//! The Debian userland provisioner: bootstrap a suite rootfs from the archive.
//!
//! [`Debian`] implements [`Provisioner`]: it fetches the
//! archive's signed release, resolves the base system plus the caller's
//! packages, downloads and extracts them, and — for a full bootstrap —
//! configures them by running dpkg inside a [`Cage`](crate::Cage) rooted at
//! the staging tree. No external tool is invoked; the archive is spoken to
//! directly over a pluggable [`Fetch`] transport, and its signature is
//! verified against an embedded keyring.
//!
//! The read half is reachable on its own. [`Debian::resolve`] reports the
//! resolved package set without downloading, for previewing a bootstrap or
//! keying a build cache on it, and [`Debian::available`] reports the names the
//! configured archives offer at all — the question a resolve cannot answer,
//! since it reports a closure rather than a catalogue. Beyond the read half,
//! [`DebianBuilder::pre_configure_overlay`] lays caller configuration into the
//! rootfs before its maintainer scripts run, and [`Pool`] writes a local
//! trusted pool a later bootstrap resolves against.
//!
//! No `.deb` is ever held in memory. A download is written to a staging file as
//! it arrives and digested on the way through, and published with a rename only
//! once the digest matches; installing reads it back the same way, streaming the
//! `data.tar` through the decompressor into the extractor; and [`Pool`] reaches a
//! control member by seeking to it. So a 90 MB kernel package costs what a shell
//! script costs, whichever direction it is moving in.
//!
//! # Example
//!
//! ```no_run
//! use ferroday_cage::provision::{self, debian::Debian};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut debian = Debian::builder("trixie")
//!     .include(["build-essential"])
//!     .build()?;
//! provision::ensure("/var/lib/machines/trixie", &mut debian)?;
//! # Ok(())
//! # }
//! ```

mod arch;
mod available;
mod bootstrap;
mod deb;
mod index;
mod layer;
mod pin;
mod plan;
mod pool;
mod release;
mod repository;
mod resolve;
mod version;

use layer::InstalledSet;
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub use arch::{Interpreter, foreign_interpreter, host_architecture};
pub use available::Available;
pub use index::{ParsePriorityError, Priority, build_depend_names};
pub use pin::{UnheldPin, UnheldReason};
pub use plan::{Plan, PlannedPackage, ResolvedArchive};
pub use pool::Pool;
pub use repository::{Repository, RepositoryBuilder};

use super::coordinate::{self, Nesting};
use super::digest::{self, Algorithm};
use super::document::Carried;
use super::extract::{Extraction, Placement};
use super::{
    BuildLayer, Delegate, Failover, Fetch, FetchError, FetchJob, FetchRequest, HttpFetch,
    LimitedWriter, PackageCache, ProvisionError, ProvisionEvent, ProvisionRequest, Provisioner,
    Stream, mirror_url, staging_path, walk_mirrors,
};
use crate::IdentityMap;
use crate::failure::path_io_error;
use crate::status::ExitStatus;
use bootstrap::{Installable, StatOverride};
use index::{Index, Package};
use pin::Pins;

/// The suffix a run-owned `.deb` cache takes on the tree it is building.
const DEB_CACHE: &str = ".fcage-debs";
use crate::provision::openpgp::Keyring;
use release::Release;

/// The mode a bootstrapped rootfs's own root directory takes.
///
/// The mode `base-files` ships `/` as, applied to the tree being assembled
/// rather than read off whichever package was extracted last; see
/// [`extract_packages`].
const ROOTFS_ROOT_MODE: u32 = 0o755;

/// The Debian archive keyring shipped with the crate, the binary
/// `debian-archive-keyring`. A caller can substitute their own with
/// [`DebianBuilder::keyring`].
///
/// Visible to the crate because the verification apparatus is tested against it:
/// a real archive keyring exercises the subkey walk and the expiry arithmetic in
/// ways a synthesized certificate cannot.
pub(crate) const EMBEDDED_KEYRING: &[u8] = include_bytes!("keyring/debian-archive-keyring.gpg");

/// The default mirror: the Debian content-delivery front end.
const DEFAULT_MIRROR: &str = "http://deb.debian.org/debian";

/// A Debian userland provisioner.
///
/// Built with [`Debian::builder`] and run through
/// [`ensure`](super::ensure). See the module documentation for the pipeline.
///
/// A `Debian` is `Send`, so a caller may build one on a coordinating thread and
/// provision on a worker. It is not `Sync`: every operation takes `&mut self`,
/// so a shared reference cannot do anything with one. [`Fetch`] carries the
/// same bound for this reason.
pub struct Debian<'a> {
    suite: String,
    architecture: String,
    base_priority: Priority,
    includes: Vec<String>,
    excludes: Vec<String>,
    extract_only: bool,
    identity_map: IdentityMap,
    cache_dir: Option<PathBuf>,
    overlay: Option<PathBuf>,
    /// The pristine base a layered build stages its increment over, set by
    /// [`DebianBuilder::base_layer`]. `None` for a full bootstrap; required by
    /// [`Debian::stage_layer`] and [`Debian::resolve_layer`].
    base_layer: Option<PathBuf>,
    /// A plan to install verbatim in place of resolving, set by
    /// [`DebianBuilder::plan`]. `None` for an ordinary bootstrap, which
    /// resolves against the archives.
    plan: Option<Plan>,
    /// The versions a resolution is held to, set by [`DebianBuilder::pin`].
    /// Empty for a resolution free to take whatever the archives now offer.
    pin: Pins,
    /// The archive sources, the primary at index zero followed by any
    /// additional repositories, merged into one resolution.
    repositories: Vec<Repository>,
    fetcher: Box<dyn Fetch + 'a>,
}

/// The builder's configuration, borrowed apart from its transport.
///
/// Every step of a bootstrap reads some of this and none of it reads all, so
/// the steps took it as positional arguments and re-threaded it through each
/// other -- fourteen of them at the widest, with `includes` beside `excludes`
/// and `cache_dir` beside `overlay`, either pair transposable without a
/// compiler complaint and producing a wrong bootstrap. Gathered once here, a
/// step names what it reads and a call site cannot mis-order it.
///
/// The transport and the observer are not part of it. Both are used mutably,
/// both are a sink rather than a setting, and every function below takes them
/// last and in that order.
struct Bootstrap<'a> {
    /// The target architecture.
    architecture: &'a str,
    /// The archive sources, the primary at index zero.
    repositories: &'a [Repository],
    /// The priority floor the base system is seeded from.
    base_priority: Priority,
    /// Names the caller asked for beyond the base system.
    includes: &'a [String],
    /// Names the caller asked to be left out.
    excludes: &'a [String],
    /// A plan to install verbatim in place of resolving.
    plan: Option<&'a Plan>,
    /// The versions a resolution is held to.
    pin: &'a Pins,
    /// Whether to stop after unpacking, running no configure wave.
    extract_only: bool,
    /// The map the bootstrap's cages run under.
    identity_map: &'a IdentityMap,
    /// The caller's package cache, or `None` for one beside the staging tree.
    cache_dir: Option<&'a Path>,
    /// A tree laid over the staging root between the unpack and configure
    /// waves.
    overlay: Option<&'a Path>,
}

impl<'a> Debian<'a> {
    /// The configuration and the transport, borrowed apart.
    ///
    /// Two values rather than one because the transport is used mutably while
    /// the configuration is read, and a single borrow of `self` could not be
    /// both. The destructure is exhaustive, with no `..`: a field added to the
    /// builder stops this compiling until someone decides whether a bootstrap
    /// reads it.
    fn split(&mut self) -> (Bootstrap<'_>, &mut dyn Fetch) {
        let Debian {
            architecture,
            repositories,
            base_priority,
            includes,
            excludes,
            plan,
            pin,
            extract_only,
            identity_map,
            cache_dir,
            overlay,
            fetcher,
            // Read by the entry points rather than by a step: it decides which
            // of them a call is, and by the time there is a bootstrap to
            // configure the base has already been read.
            base_layer: _,
            // The suite names the release a resolution checks against, which
            // the repository at index zero already carries.
            suite: _,
        } = self;
        (
            Bootstrap {
                architecture,
                repositories,
                base_priority: *base_priority,
                includes,
                excludes,
                plan: plan.as_ref(),
                pin,
                extract_only: *extract_only,
                identity_map,
                cache_dir: cache_dir.as_deref(),
                overlay: overlay.as_deref(),
            },
            fetcher.as_mut(),
        )
    }
}

/// [`coordinate::check`], with its refusal reported as this layer's
/// configuration failure.
///
/// The check itself is shared, because a value that becomes a directory in a URL
/// is refused for the same reasons whichever archive publishes it. What is not
/// shared is the error: it reports a reason, and each layer says whose
/// configuration the reason is about.
pub(super) fn check_coordinate(
    what: &str,
    value: &str,
    nesting: Nesting,
) -> Result<(), DebianError> {
    coordinate::check(what, value, nesting).map_err(|reason| DebianError::Config { reason })
}

/// Refuses a plan handed to `plan()` that contradicts the rest of the
/// configuration.
///
/// A plan describes a resolution that already happened, so a setting shaping a
/// resolution is a contradiction rather than a refinement, and picking a silent
/// precedence between the two would produce a rootfs matching neither.
fn validate_plan(
    plan: &Plan,
    suite: &str,
    architecture: &str,
    repositories: usize,
    base_priority_set: bool,
    includes: &[String],
    excludes: &[String],
) -> Result<(), DebianError> {
    let contradiction = |reason: String| Err(DebianError::Config { reason });
    if !includes.is_empty() {
        return contradiction(
            "a plan already names every package to install, so include() has nothing to \
             add; drop one of the two"
                .to_string(),
        );
    }
    if !excludes.is_empty() {
        return contradiction(
            "a plan already names every package to install, so exclude() has nothing to \
             remove; drop one of the two"
                .to_string(),
        );
    }
    if base_priority_set {
        return contradiction(
            "a plan already names its base system, so base_priority() has no seed to \
             filter; drop one of the two"
                .to_string(),
        );
    }
    if plan.suite != suite {
        return contradiction(format!(
            "the plan resolves suite {} but the bootstrap is configured for {suite}",
            plan.suite,
        ));
    }
    if plan.architecture != architecture {
        return contradiction(format!(
            "the plan resolves architecture {} but the bootstrap is configured for \
             {architecture}",
            plan.architecture,
        ));
    }
    // Each package names the archive it came from as an index, and a verbatim
    // install fetches through the repository at that index, so a plan resolved
    // against more repositories than are configured has packages with nowhere
    // to be fetched from.
    if plan.archives.len() > repositories {
        return contradiction(format!(
            "the plan resolved against {} archives but only {repositories} repositories \
             are configured, so some of its packages name no mirror",
            plan.archives.len(),
        ));
    }
    // The archive count bounds a plan whose packages agree with its own archive
    // list, which is every plan a document produced: reading one refuses a
    // package naming an archive the document does not carry. `Plan` is public
    // and `Clone`, though, so a caller can take one from `resolve()` and edit
    // it, and the index is what a bootstrap slices the repository list with.
    // It is checked here, where the configuration is frozen, rather than left to
    // panic mid-download; `Plan::to_document` makes the same check on the way
    // out.
    for package in &plan.packages {
        if package.archive >= repositories {
            return contradiction(format!(
                "the plan's package {} names archive {} but only {repositories} repositories \
                 are configured, so it names no mirror",
                package.name, package.archive,
            ));
        }
        // A document is held to this as it is read; a `Plan` is public and
        // `Clone`, so one taken from `resolve()` and edited reaches here having
        // passed nothing.
        if let Some(reason) = package.unaddressable() {
            return contradiction(reason);
        }
    }
    Ok(())
}

/// Refuses a plan handed to `pin()` that contradicts the rest of the
/// configuration.
///
/// Far less is a contradiction here than for `plan()`. A pin constrains a
/// resolution rather than replacing one, so everything that shapes what is
/// selected — the includes, the exclusions, the base seed's priority floor —
/// composes with it, and the repository list is free to differ from the one the
/// pin was resolved against. What remains is a pin that cannot mean anything: a
/// resolution that will not happen, one for a different coordinate, or one whose
/// entries state a digest nothing an archive publishes could equal.
fn validate_pin(
    pin: &Plan,
    suite: &str,
    architecture: &str,
    plan_set: bool,
) -> Result<(), DebianError> {
    let contradiction = |reason: String| Err(DebianError::Config { reason });
    if plan_set {
        return contradiction(
            "plan() installs a resolved plan instead of resolving, so there is no resolution \
             for pin() to hold to versions; drop one of the two"
                .to_string(),
        );
    }
    if pin.suite != suite {
        return contradiction(format!(
            "the pin resolves suite {} but the bootstrap is configured for {suite}",
            pin.suite,
        ));
    }
    if pin.architecture != architecture {
        return contradiction(format!(
            "the pin resolves architecture {} but the bootstrap is configured for \
             {architecture}",
            pin.architecture,
        ));
    }
    // A pin holds a resolution to the digests it records, and `Pins::check`
    // compares them against the index with a plain `==`. A digest spelled any
    // other way could only ever mismatch, and would be reported as an archive
    // that had published past the pin rather than as the malformed entry it is.
    // The whole rule is applied, not the digest half alone: a pin is a plan
    // document, read by the same reader, and one it would refuse is worth
    // refusing here too.
    for package in &pin.packages {
        if let Some(reason) = package.unaddressable() {
            return contradiction(reason);
        }
    }
    Ok(())
}

impl fmt::Debug for Debian<'_> {
    /// Renders the bootstrap's settings and its repositories. The fetcher is a
    /// caller's trait object and renders as its presence rather than its
    /// contents; each repository names its trust anchor without dumping it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Debian")
            .field("suite", &self.suite)
            .field("architecture", &self.architecture)
            .field("base_priority", &self.base_priority)
            .field("includes", &self.includes)
            .field("excludes", &self.excludes)
            .field("plan", &self.plan)
            .field("pin", &self.pin)
            .field("extract_only", &self.extract_only)
            .field("identity_map", &self.identity_map)
            .field("cache_dir", &self.cache_dir)
            .field("overlay", &self.overlay)
            .field("base_layer", &self.base_layer)
            .field("repositories", &self.repositories)
            .field("fetcher", &Delegate("dyn Fetch"))
            .finish()
    }
}

impl<'a> Debian<'a> {
    /// Returns a builder for a bootstrap of `suite` (for example `trixie`).
    pub fn builder(suite: impl Into<String>) -> DebianBuilder<'a> {
        DebianBuilder {
            suite: suite.into(),
            architecture: None,
            mirror: None,
            mirror_fallbacks: Vec::new(),
            components: Vec::new(),
            base_priority: None,
            includes: Vec::new(),
            excludes: Vec::new(),
            plan: None,
            pin: None,
            extract_only: false,
            identity_map: IdentityMap::Single,
            cache_dir: None,
            overlay: None,
            base_layer: None,
            keyring_path: None,
            trust_unsigned: false,
            allow_stale: false,
            repositories: Vec::new(),
            fetcher: None,
        }
    }

    /// Resolves the install plan for the configured suite, downloading and
    /// unpacking nothing.
    ///
    /// This performs the read half of a bootstrap: it fetches and verifies the
    /// signed release, confirms it identifies as the requested suite, fetches
    /// and verifies the package index, and resolves the base system plus the
    /// caller's [`include`](DebianBuilder::include)s into the exact set of
    /// packages a bootstrap would install. It stops there — no package is
    /// downloaded, and no staging tree is created — and returns the resolved
    /// [`Plan`].
    ///
    /// The plan is the same closure [`provision`](super::ensure) installs: both
    /// resolve through one shared path, so a plan taken immediately before a
    /// bootstrap describes what that bootstrap lays down. Every digest in it is
    /// archive-verified, chaining back to the release signature, so the plan is
    /// a sound basis for a content-addressed build cache. Because nothing runs,
    /// `resolve` needs neither a `qemu-user` binfmt handler nor an establishable
    /// identity map, and so serves a foreign architecture the host cannot
    /// execute.
    ///
    /// # Errors
    ///
    /// Returns a [`DebianError`] for a fetch failure, a signature or freshness
    /// failure, a release that does not offer the requested suite,
    /// architecture, or components, or a caller `include` that resolves to no
    /// package.
    ///
    /// A resolution that cannot be satisfied reports every refusal it met as a
    /// [`DebianEvent::Unsatisfiable`] and then fails once with all of them
    /// named, so an install list with four mistakes in it is corrected in one
    /// pass rather than four.
    pub fn resolve(&mut self) -> Result<Plan, DebianError> {
        self.observe(&mut Silent).resolve()
    }

    /// Reports the names the configured archives offer, resolving nothing.
    ///
    /// It fetches and verifies each repository's release and index exactly as a
    /// resolve does, merges them, and returns the [`Available`] name set.
    /// Nothing is downloaded, nothing is unpacked, and no closure is computed —
    /// so it needs neither a `qemu-user` binfmt handler nor an establishable
    /// identity map, and serves a foreign architecture the host cannot execute.
    ///
    /// This is a different question from [`resolve`](Self::resolve), and the
    /// resolvers cannot stand in for it. A resolve *fails* where a name cannot
    /// be satisfied rather than answering a question about it — and it fails
    /// about a whole closure, so a name that is perfectly available appears in
    /// the failure when something else in its dependency tree is not. A resolve
    /// does name every refusal rather than the first, which makes a failed one
    /// a usable list of what to correct, but that is a list of what this
    /// particular closure could not have and not an answer about a set of
    /// names. Asking here costs one pass over the index for any number of
    /// names, where a resolve per name re-fetches and re-parses it every time.
    ///
    /// The builder's [`include`](DebianBuilder::include),
    /// [`exclude`](DebianBuilder::exclude), and
    /// [`base_priority`](DebianBuilder::base_priority) settings do not apply:
    /// they shape a resolution, and this performs none. The suite, the
    /// architecture, the repositories, and the fetcher are what it reads.
    ///
    /// # Errors
    ///
    /// Returns a [`DebianError`] for a fetch failure, a signature or freshness
    /// failure, or a release that does not offer the requested suite,
    /// architecture, or components.
    pub fn available(&mut self) -> Result<Available, DebianError> {
        self.observe(&mut Silent).available()
    }

    /// Resolves the increment a layered build would install over its base,
    /// downloading and unpacking nothing.
    ///
    /// The layered counterpart of [`resolve`](Self::resolve): it reads the base
    /// layer's already-installed set from its dpkg status database, then
    /// resolves the configured [`include`](DebianBuilder::include)s against the
    /// merged archive-and-repository index while treating that set as satisfied,
    /// returning the [`Plan`] of only the packages the base does not already
    /// carry. Requires a [`base_layer`](DebianBuilder::base_layer); every digest
    /// in the plan is archive-verified, exactly as [`resolve`](Self::resolve)
    /// reports.
    ///
    /// Like [`resolve`](Self::resolve) it downloads no package and runs nothing,
    /// so it needs neither a `qemu-user` binfmt handler nor an establishable
    /// identity map; it reads only the base's status database and the archives'
    /// release and index. Use it to preview a layer or key a build-root cache on
    /// the increment without staging it.
    ///
    /// # Errors
    ///
    /// Returns a [`DebianError`] for the same fetch, signature, and resolution
    /// failures as [`resolve`](Self::resolve), and [`DebianError::Config`] when
    /// no base layer is set or the base is not a fully configured bootstrap.
    pub fn resolve_layer(&mut self) -> Result<Plan, DebianError> {
        self.observe(&mut Silent).resolve_layer()
    }

    /// The body of [`resolve_layer`](Self::resolve_layer), reporting to
    /// `observer`.
    ///
    /// One body for the two public entry points -- the unobserved one above and
    /// [`Observed::resolve_layer`] -- rather than a body on each.
    fn resolve_layer_reporting(
        &mut self,
        observer: &mut dyn DebianObserver,
    ) -> Result<Plan, DebianError> {
        let Some(base) = self.base_layer.clone() else {
            return Err(DebianError::Config {
                reason: "resolve_layer requires a base layer set with DebianBuilder::base_layer"
                    .to_string(),
            });
        };
        // Reading the base's set is what refuses a base that is not a
        // configured bootstrap, so it runs whether or not a plan makes the
        // resolution below unnecessary.
        let assume_installed = layer::read_installed_set(&base)?;

        let suite = self.suite.clone();
        let (config, fetcher) = self.split();
        // As for a whole root: a plan is the increment, and staging installs it
        // verbatim.
        if let Some(plan) = config.plan {
            let plan = plan.clone();
            observer.progress(DebianEvent::Resolved { plan: &plan });
            return Ok(plan);
        }
        let architecture = config.architecture.to_string();
        let (packages, archives) = resolve_delta(&config, &assume_installed, fetcher, observer)?;
        Ok(Plan::project(&suite, &architecture, &packages, &archives))
    }

    /// Stages this provisioner's packages as an increment over the base layer,
    /// installing only the delta into a disposable overlay `upper`.
    ///
    /// Requires a [`base_layer`](DebianBuilder::base_layer). It resolves the
    /// increment [`resolve_layer`](Self::resolve_layer) reports, downloads it,
    /// extracts it into `upper`, and configures it by running dpkg in a cage
    /// rooted on an overlay of the pristine base (the read-only lower) and
    /// `upper` (the writable increment) — so dpkg reads the base's configured
    /// database and lands the increment's state in `upper`, the base untouched.
    /// The returned [`BuildLayer`] owns `upper`: root a build cage on
    /// [`overlay_rootfs(base, layer.path())`](crate::CageBuilder::overlay_rootfs)
    /// to build against the merged `base + increment` view, then drop the layer
    /// to discard the increment.
    ///
    /// `upper` is created if absent, along with the overlay work directory beside
    /// it. The identity map, cache directory, additional repositories, and
    /// pre-configure overlay configured on the builder all apply, exactly as to a
    /// full bootstrap; the map must match the one the base was built under.
    ///
    /// A call that fails leaves nothing behind: the upper and its work directory
    /// are disposed of exactly as dropping the returned layer would dispose of
    /// them, since a failure hands the caller no handle to drop. So is the
    /// package cache, unless the builder named a
    /// [`cache_dir`](DebianBuilder::cache_dir), which is the caller's and
    /// survives either way.
    ///
    /// # Preconditions
    ///
    /// The increment's configure wave runs the target's binaries, so a foreign
    /// architecture needs the same `qemu-user` binfmt handler a full bootstrap
    /// does, and a range identity map must be establishable — both checked before
    /// any download. It roots a cage on an unprivileged overlay, so the host must
    /// support one on `upper`'s filesystem;
    /// [`host::overlay_blocker`](crate::host::overlay_blocker) reports what is
    /// missing, and `stage_layer` refuses a host that cannot before downloading.
    ///
    /// # Errors
    ///
    /// Returns [`ProvisionError`], with a [`DebianError`] surfaced through
    /// [`ProvisionError::Other`] for a fetch, resolution, or configuration
    /// failure, an unmet host precondition, a base that is not a configured
    /// bootstrap, or no base layer set.
    pub fn stage_layer(&mut self, upper: impl AsRef<Path>) -> Result<BuildLayer, ProvisionError> {
        self.observe(&mut Silent).stage_layer(upper)
    }

    /// The body of [`stage_layer`](Self::stage_layer), reporting to `observer`.
    fn stage_layer_reporting(
        &mut self,
        upper: &Path,
        observer: &mut dyn DebianObserver,
    ) -> Result<BuildLayer, ProvisionError> {
        // A base layer is required; the increment has nothing to layer over
        // otherwise. Cloned rather than borrowed: the configuration is borrowed
        // out of the same value below, and the base is one path.
        let Some(base) = self.base_layer.clone() else {
            return Err(wrap(DebianError::Config {
                reason: "stage_layer requires a base layer set with DebianBuilder::base_layer"
                    .to_string(),
            }));
        };

        // Preflights before any download, the same fail-early posture the full
        // bootstrap takes: the increment's configure wave runs the target's
        // binaries, and a range map must be establishable.
        arch::preflight_foreign(&arch::host_architecture(), &self.architecture)
            .map_err(|reason| wrap(DebianError::Config { reason }))?;
        if !matches!(self.identity_map, IdentityMap::Single)
            && let Err(reason) = crate::idmap::resolve_default_chain(&self.identity_map)
        {
            return Err(wrap(DebianError::Config {
                reason: format!("the requested identity map is unavailable: {reason}"),
            }));
        }

        // The base's configured set seeds the resolver, and reading it refuses a
        // base that is not a configured bootstrap.
        let assume_installed = layer::read_installed_set(&base).map_err(wrap)?;

        // Create the upper and refuse a host that cannot establish an
        // unprivileged overlay on its filesystem, before any download — the
        // overlay preflight the primitive would make at cage-build time, hoisted
        // ahead of the work. The probe runs on the upper's parent, its own
        // filesystem, so its scratch files land beside the upper.
        std::fs::create_dir_all(upper)
            .map_err(|err| ProvisionError::io("creating the overlay upper", upper, err))?;
        // The handle that owns the upper is taken as soon as the upper exists,
        // not on the way out, so a failure below disposes of a partly-installed
        // increment instead of orphaning it: there is no handle in an `Err` for
        // the caller to drop.
        let layer = BuildLayer::new(upper, self.identity_map.clone());
        let scratch = upper
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if let Some(blocker) = crate::host::overlay_blocker(scratch) {
            return Err(wrap(DebianError::Config {
                reason: format!("an overlay-rooted build layer cannot be established: {blocker}"),
            }));
        }

        // The archives cache: the caller's shared one, or a sibling of the
        // upper, which goes with this frame however it ends.
        let archives = PackageCache::beside(upper, self.cache_dir.as_deref(), DEB_CACHE);

        // Resolve the increment against the base's installed set, download it,
        // extract it into the upper, and configure it through the overlay.
        // A staging run installs the increment rather than reporting it, so
        // the archive state goes to the `Resolved` event and no further.
        let (config, fetcher) = self.split();
        let wanted: Vec<Wanted> = match config.plan {
            // A plan is the resolution here as it is for a whole root: the
            // release and the index are never fetched, and what it names is
            // installed over the base. Reported as the resolved manifest so an
            // observer sees the same event either way.
            Some(plan) => {
                observer.progress(DebianEvent::Resolved { plan });
                plan.packages.iter().map(Wanted::from_planned).collect()
            }
            None => {
                let (packages, _archives) =
                    resolve_delta(&config, &assume_installed, fetcher, observer).map_err(wrap)?;
                packages.iter().map(Wanted::from_package).collect()
            }
        };
        // An empty increment — every requested package already in the base, or a
        // plan that names none — needs no download or configuration; the build
        // root is the base as it stands. Skipping here also keeps dpkg from
        // being handed an empty unpack wave, which it refuses.
        if wanted.is_empty() {
            return Ok(layer);
        }
        let installables = acquire_debs(
            fetcher,
            config.repositories,
            &wanted,
            archives.path(),
            observer,
        )?;
        let statoverride = extract_packages(
            upper,
            config.architecture,
            &installables,
            archives.path(),
            observer,
        )?;

        let env = maintainer_env();
        let wave = bootstrap::Configure {
            archives_host: archives.path(),
            installables: &installables,
            statoverride: &statoverride,
            identity_map: config.identity_map,
            env: &env,
        };
        bootstrap::configure_delta(&base, upper, &wave, config.overlay, observer).map_err(wrap)?;

        // The read-only archives bind left an empty mount point in the upper.
        let _ = std::fs::remove_dir_all(upper.join(bootstrap::ARCHIVES.trim_start_matches('/')));

        Ok(layer)
    }
}

/// Builder for a [`Debian`] provisioner.
pub struct DebianBuilder<'a> {
    suite: String,
    architecture: Option<String>,
    mirror: Option<String>,
    mirror_fallbacks: Vec<String>,
    components: Vec<String>,
    /// The base seed's priority floor; `None` until the caller sets one, so a
    /// plan can refuse an explicit floor without refusing the default.
    base_priority: Option<Priority>,
    includes: Vec<String>,
    excludes: Vec<String>,
    /// A previously resolved plan to install verbatim, in place of resolving.
    plan: Option<Plan>,
    /// A previously resolved plan to hold a resolution's versions to, rather
    /// than to install in place of one.
    pin: Option<Plan>,
    extract_only: bool,
    identity_map: IdentityMap,
    cache_dir: Option<PathBuf>,
    overlay: Option<PathBuf>,
    base_layer: Option<PathBuf>,
    keyring_path: Option<PathBuf>,
    trust_unsigned: bool,
    allow_stale: bool,
    repositories: Vec<Repository>,
    fetcher: Option<Box<dyn Fetch + 'a>>,
}

impl fmt::Debug for DebianBuilder<'_> {
    /// Renders every setting made so far, including the primary repository's,
    /// which are held separately until [`build`](Self::build) assembles them.
    /// The keyring is named by its path rather than read, and the fetcher — a
    /// caller's trait object — by its presence.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DebianBuilder")
            .field("suite", &self.suite)
            .field("architecture", &self.architecture)
            .field("mirror", &self.mirror)
            .field("mirror_fallbacks", &self.mirror_fallbacks)
            .field("components", &self.components)
            .field("base_priority", &self.base_priority)
            .field("includes", &self.includes)
            .field("excludes", &self.excludes)
            .field("plan", &self.plan)
            .field("pin", &self.pin)
            .field("extract_only", &self.extract_only)
            .field("identity_map", &self.identity_map)
            .field("cache_dir", &self.cache_dir)
            .field("overlay", &self.overlay)
            .field("base_layer", &self.base_layer)
            .field("keyring_path", &self.keyring_path)
            .field("trust_unsigned", &self.trust_unsigned)
            .field("allow_stale", &self.allow_stale)
            .field("repositories", &self.repositories)
            .field(
                "fetcher",
                &self.fetcher.as_ref().map(|_| Delegate("dyn Fetch")),
            )
            .finish()
    }
}

impl<'a> DebianBuilder<'a> {
    /// Sets the target architecture (a Debian name such as `amd64` or
    /// `arm64`). The default is the host's architecture.
    pub fn architecture(mut self, architecture: impl Into<String>) -> Self {
        self.architecture = Some(architecture.into());
        self
    }

    /// Sets the primary mirror URL. The default is the Debian CDN front end.
    ///
    /// This, along with [`components`](Self::components),
    /// [`keyring`](Self::keyring), [`trust_unsigned`](Self::trust_unsigned), and
    /// [`allow_stale_release`](Self::allow_stale_release), configures the
    /// primary repository — the one that owns the finished rootfs's
    /// `sources.list`. Additional sources are added with
    /// [`repository`](Self::repository).
    ///
    /// The default transport speaks `http://` and `file://` only, so an
    /// `https://` mirror needs a fetcher of the caller's own, set with
    /// [`fetcher`](Self::fetcher); without one the URL is refused when the solve
    /// first reaches for it. Carrying a TLS stack is the consumer's decision,
    /// not the crate's — the archive signature, not the transport, is what
    /// authenticates a package.
    pub fn mirror(mut self, mirror: impl Into<String>) -> Self {
        self.mirror = Some(mirror.into());
        self
    }

    /// Adds a backstop URL for the primary mirror, tried in order after it when
    /// a fetch reports the resource missing, fails at the transport, or is
    /// answered with an unsuccessful HTTP status.
    ///
    /// This expresses a live primary mirror with a `snapshot.debian.org`
    /// fallback for a version that has rotated off the live pool. The fallback
    /// is a fetch-time concern only: the finished rootfs's `sources.list` names
    /// the primary mirror, not the backstop. A repository whose backstop is a
    /// snapshot normally also sets
    /// [`allow_stale_release`](Self::allow_stale_release), the snapshot's
    /// release being expired by design.
    ///
    /// A backstop is fetched through the same transport as the primary, so the
    /// scheme constraint of [`mirror`](Self::mirror) applies to it too.
    pub fn mirror_fallback(mut self, url: impl Into<String>) -> Self {
        self.mirror_fallbacks.push(url.into());
        self
    }

    /// Adds a [`Repository`] merged into the resolution alongside the primary.
    ///
    /// An additional repository is a distinct source — a local trusted `.deb`
    /// pool, a signed feature repository — contributing packages to one merged
    /// closure. Resolution is highest-version-wins across every repository, so a
    /// package a feature repository ships at a higher version supersedes the
    /// primary's, and a package only one repository ships is pulled from it; an
    /// exact-version tie resolves to the earlier repository, the primary first.
    /// Each additional repository writes its own
    /// `/etc/apt/sources.list.d/<name>.list` into the finished rootfs.
    pub fn repository(mut self, repository: Repository) -> Self {
        self.repositories.push(repository);
        self
    }

    /// Sets the archive components. The default is `main`.
    pub fn components<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.components = components.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the least essential [`Priority`] band the base system seeds from.
    ///
    /// The base system is every essential package plus every package at least
    /// as essential as this floor. The default, [`Priority::Required`], is
    /// `debootstrap`'s minbase: essential and required packages only. A less
    /// essential floor such as [`Priority::Important`] additionally seeds that
    /// band — `cron`, `logrotate`, and the like — matching the corresponding
    /// bootstrap variant, so a package the archive marks that priority is
    /// present without being named in [`include`](Self::include). Floors below
    /// [`Priority::Standard`] are not meaningful for a base system: they seed
    /// the bulk of the archive.
    pub fn base_priority(mut self, priority: Priority) -> Self {
        self.base_priority = Some(priority);
        self
    }

    /// Adds packages to install beyond the base system.
    pub fn include<I, S>(mut self, packages: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.includes.extend(packages.into_iter().map(Into::into));
        self
    }

    /// Installs a previously resolved [`Plan`] verbatim, resolving nothing.
    ///
    /// The bootstrap fetches exactly the packages the plan records, by the
    /// digests it records, and never touches a release or a package index. That
    /// is the whole win: the index is around 9 MB for trixie amd64, and a
    /// reproduce mode that has already resolved once has no use for a second
    /// resolution — nor for the divergence when the archive publishes between
    /// the two.
    ///
    /// # The trust model changes
    ///
    /// Skipping the release and the index means the package digests no longer
    /// chain to an archive signature at install time. **The plan becomes the
    /// trust anchor**: it was archive-verified when it was produced, and
    /// installing from it asserts that whoever kept it kept it intact. Each
    /// `.deb` is still verified against the digest the plan records, so a
    /// tampered mirror is caught; what is no longer checked is that the plan
    /// itself still describes what the archive says.
    ///
    /// That trade is exactly what a reproduce mode wants and exactly what an
    /// ordinary build should not take, so it is opt-in by construction: a
    /// builder that sets no plan resolves as it always has, chaining every
    /// digest to a repository signature.
    ///
    /// # Refused combinations
    ///
    /// A plan describes a resolution that already happened, so anything that
    /// would shape a resolution contradicts it and is refused at
    /// [`build`](Self::build) with [`DebianError::Config`] rather than given a
    /// silent precedence: [`include`](Self::include), [`exclude`](Self::exclude),
    /// and [`base_priority`](Self::base_priority). A plan whose suite or
    /// architecture disagrees with the builder's is refused the same way, as is
    /// one naming more archives than there are repositories to fetch them from.
    /// Where the builder names no architecture the plan's is adopted, since a
    /// plan states which architecture it is for.
    ///
    /// Everything that shapes *how* rather than *what* still applies:
    /// [`cache_dir`](Self::cache_dir), [`identity_map`](Self::identity_map),
    /// [`pre_configure_overlay`](Self::pre_configure_overlay), the repositories,
    /// and the fetcher. A package is fetched from the repository its
    /// [`PlannedPackage::archive`] names, so a reproduce run may point the same
    /// plan at a snapshot mirror.
    ///
    /// [`base_layer`](Self::base_layer) applies too, and a plan set alongside
    /// one is the increment rather than the whole root: it is what
    /// [`Debian::stage_layer`] installs over the base and what
    /// [`Debian::resolve_layer`] reports, exactly as a plan without a base layer
    /// is what a whole bootstrap installs. The plan to keep for that is the one
    /// [`Debian::resolve_layer`] produced.
    pub fn plan(mut self, plan: Plan) -> Self {
        self.plan = Some(plan);
        self
    }

    /// Holds a resolution to the versions a previously resolved [`Plan`]
    /// recorded, resolving everything the plan does not name.
    ///
    /// Where [`plan`](Self::plan) replaces a resolution, this constrains one.
    /// The bootstrap fetches and verifies every release and index as it always
    /// does and computes the closure over what the archives offer now; each
    /// package the pin names is selected at the pinned version rather than at
    /// the highest offered, and its recorded digest must be the one the archive
    /// records for that version. Everything else — a package added to the
    /// closure since, a dependency the pinned version pulls in, a repository
    /// the pin says nothing about — resolves normally.
    ///
    /// # When this is the one that fits
    ///
    /// A plan covering a build whose inputs are not all archives. Where some
    /// packages are compiled by the build itself and published to a local
    /// [`Pool`], [`plan`](Self::plan) requires those compiles to be
    /// byte-reproducible, since it installs every package by a recorded digest
    /// and a compile that differs by a timestamp no longer matches. Pinning
    /// only the archive-sourced packages gives a document that fixes the half a
    /// mirror controls and leaves the locally built half to resolve at whatever
    /// the pool now holds.
    ///
    /// # The trust model does not change
    ///
    /// Unlike [`plan`](Self::plan), nothing here leaves the archive signature
    /// chain: every digest installed is still read from an index whose own
    /// digest a verified release records. The pin narrows which version is
    /// selected; it never becomes the authority for what the bytes are. A pin
    /// whose digest disagrees with the archive's for the same version is
    /// refused rather than preferred, which is how one version published twice
    /// over different bytes is caught.
    ///
    /// # Refused combinations
    ///
    /// A pin and a [`plan`](Self::plan) together are refused at
    /// [`build`](Self::build) with [`DebianError::Config`]: a plan resolves
    /// nothing, so there is no resolution for a pin to constrain. A pin whose
    /// suite or architecture disagrees with the builder's is refused the same
    /// way, as is one naming a package twice. [`include`](Self::include),
    /// [`exclude`](Self::exclude), and [`base_priority`](Self::base_priority)
    /// are *not* refused — a pin constrains the versions a selection resolves
    /// to and says nothing about what is selected, which is the whole of what
    /// separates it from a plan.
    ///
    /// # Errors at resolution
    ///
    /// A pin the archives cannot supply fails the resolve or the bootstrap with
    /// [`DebianError::Pin`], naming every package at once: the archives have
    /// published past the pinned version, dropped the package, or record
    /// different bytes for it. A snapshot mirror is what holds a pin against an
    /// archive that keeps moving.
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use ferroday_cage::provision::debian::{Debian, Plan};
    ///
    /// // The committed document: the versions the mirror served, and nothing
    /// // about the packages this build compiles for itself.
    /// let kept = Plan::parse_document(&std::fs::read_to_string("archives.plan")?)?;
    ///
    /// let mut debian = Debian::builder("trixie")
    ///     .repository(ferroday_cage::provision::debian::Repository::builder("trixie")
    ///         .mirror("file:///srv/pool")
    ///         .trust_unsigned(true)
    ///         .build()?)
    ///     .include(["build-essential", "kernel-image"])
    ///     .pin(kept)
    ///     .build()?;
    /// # let _ = &mut debian;
    /// # Ok(())
    /// # }
    /// ```
    pub fn pin(mut self, pin: Plan) -> Self {
        self.pin = Some(pin);
        self
    }

    /// Excludes packages from the resolved install closure.
    ///
    /// An excluded package is dropped from the base seed and skipped as a
    /// dependency alternative, so a group such as `network-manager |
    /// isc-dhcp-client` resolves to the other alternative rather than pulling
    /// the excluded one. This is apt's `pkgname-` deselection: a way to keep a
    /// package a broader selection would otherwise draw in. A hard dependency
    /// that only the excluded package can satisfy fails the bootstrap rather
    /// than producing a broken closure, as does excluding a package that is
    /// also an [`include`](Self::include).
    pub fn exclude<I, S>(mut self, packages: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.excludes.extend(packages.into_iter().map(Into::into));
        self
    }

    /// Stops after laying out the packages' files, without configuring them.
    ///
    /// An extract-only rootfs has no configured dpkg database and has run no
    /// maintainer scripts. It is the escape hatch for a foreign architecture
    /// with no qemu binfmt handler, where the packages' code cannot run.
    pub fn extract_only(mut self, extract_only: bool) -> Self {
        self.extract_only = extract_only;
        self
    }

    /// Selects the identity map of the cages the bootstrap's dpkg runs in,
    /// and with it the ownership the finished rootfs carries.
    ///
    /// The right map follows from what the rootfs is for. The default,
    /// [`IdentityMap::Single`], serves a build or run environment consumed
    /// back inside single-identity cages: ownership Debian would assign to
    /// system users is quietly flattened to root — reconciled by the
    /// bootstrap's ownership stubs — which such cages cannot observe, and
    /// the caller-owned output needs no extra host support to manage. A
    /// rootfs that is itself the product — deployed, exported, or run under
    /// a range map — wants [`IdentityMap::Subordinate`]: the system ids are
    /// then real, every chown a maintainer script performs genuinely
    /// happens, and no stub or override is involved. That map requires the
    /// `subid` feature and a host that can establish it; a bootstrap that
    /// cannot fails before any download, never falling back to the flattened
    /// form. Non-root ownership a subordinate-mapped bootstrap writes lands
    /// as subordinate ids on the host, and a directory so owned refuses the
    /// plain caller's removal; [`remove`](super::remove) deletes the
    /// produced rootfs either way.
    ///
    /// Extraction without configuration ([`extract_only`](Self::extract_only))
    /// runs no cage and is unaffected by the map.
    pub fn identity_map(mut self, map: IdentityMap) -> Self {
        self.identity_map = map;
        self
    }

    /// Sets a directory to cache downloaded packages in, content-addressed
    /// and reused across bootstraps. Without one, packages are downloaded to
    /// a directory beside the tree being built and discarded when the run ends,
    /// whether it succeeded or failed.
    ///
    /// A cache directory set here is the caller's and is never removed, which is
    /// what makes it a cache: it is created if absent, and both it and its
    /// contents outlive the run.
    ///
    /// Concurrent bootstraps may share one cache directory, including ones in
    /// separate processes and ones whose package sets overlap. Each entry is
    /// staged under a name unique to the writer and published with a rename,
    /// so a package two bootstraps download at once resolves to the one file
    /// they both name, and is verified against its digest before reuse.
    pub fn cache_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.cache_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Lays a directory tree into the rootfs after the packages are unpacked
    /// and before their maintainer scripts run.
    ///
    /// The source is a rootfs-shaped directory: its contents are copied into
    /// the staging root — `source/etc/locale.gen` becomes `/etc/locale.gen` —
    /// preserving file modes and symlinks, under the same kernel-enforced
    /// containment as package extraction, so nothing in the source can be
    /// written outside the root. A file replaces the package's own copy of the
    /// same path, which is how a shipped conffile is overridden; directories
    /// merge. Entries land owned by the calling user, which the identity map
    /// presents as root inside.
    ///
    /// The overlay is placed after every package is unpacked and before the
    /// configuration wave runs any maintainer script, so a script observes the
    /// injected configuration — a debconf pre-seed, a hardware-probe guard.
    /// The base system's own packages are configured earlier, so the overlay
    /// governs the configuration of the non-essential packages. It applies only
    /// to a full bootstrap; [`extract_only`](Self::extract_only) configures
    /// nothing and ignores it.
    pub fn pre_configure_overlay(mut self, source: impl AsRef<Path>) -> Self {
        self.overlay = Some(source.as_ref().to_path_buf());
        self
    }

    /// Stages this provisioner's packages as an increment over an existing base,
    /// rather than as a full bootstrap.
    ///
    /// `base` is a rootfs already provisioned the ordinary way through
    /// [`ensure`](super::ensure) — a full, configured bootstrap, not an
    /// [`extract_only`](Self::extract_only) tree. Setting it turns the built
    /// [`Debian`] into a layered provisioner: [`Debian::stage_layer`] resolves
    /// only the packages the base does not already carry and installs that
    /// increment into a disposable overlay upper, and [`Debian::resolve_layer`]
    /// previews the same increment. The base's already-installed set is read
    /// from its own dpkg status database, so the resolver treats every package
    /// the base configured — and the virtuals they provide — as satisfied and
    /// closes over only the delta.
    ///
    /// The base and its layers must share a suite and architecture, and must use
    /// the same [`identity_map`](Self::identity_map): a base configured under the
    /// single-identity map carries flattened ownership that a range-mapped layer
    /// would not agree with, and the reverse. The layer's configure wave runs the
    /// increment's maintainer scripts, so a foreign architecture needs the same
    /// `qemu-user` binfmt handler a full bootstrap does.
    ///
    /// A [`Debian`] built with a base layer is used through `stage_layer` or
    /// `resolve_layer`; it is not passed to [`ensure`](super::ensure), which
    /// performs a full bootstrap and does not consult the base.
    pub fn base_layer(mut self, base: impl AsRef<Path>) -> Self {
        self.base_layer = Some(base.as_ref().to_path_buf());
        self
    }

    /// Overrides the embedded archive keyring with one read from `path` (a
    /// binary OpenPGP keyring).
    pub fn keyring(mut self, path: impl AsRef<Path>) -> Self {
        self.keyring_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Trusts the archive without verifying its signature, fetching a plain
    /// `Release` instead of `InRelease`.
    ///
    /// This is apt's `[trusted=yes]`: appropriate for a local or `file://`
    /// mirror under the caller's control, never for a remote one. Because it
    /// drops the only authenticity check, authenticity rests on the transport
    /// alone, so [`build`](Self::build) requires one that supplies some: every
    /// mirror must be `file://` or `https://`, and any other scheme —
    /// `http://` included — is refused.
    pub fn trust_unsigned(mut self, trust: bool) -> Self {
        self.trust_unsigned = trust;
        self
    }

    /// Accepts a signed release that is past its `Valid-Until`.
    ///
    /// By default, a `Valid-Until` the release carries must be parseable and
    /// unexpired, and the archive signature must not itself have expired, so a
    /// stale but validly-signed release cannot be replayed to deliver
    /// superseded packages. (A release that omits `Valid-Until`, as the Debian
    /// stable suite does, carries no freshness bound and is accepted either
    /// way.) Setting this relaxes the freshness check entirely while still
    /// verifying the signature, for the legitimate case of pinning a
    /// historical archive state — for example a `snapshot.debian.org` suite,
    /// whose `Valid-Until` has deliberately passed. It has no effect on a
    /// [`trust_unsigned`](Self::trust_unsigned) mirror, which is never
    /// freshness-checked.
    pub fn allow_stale_release(mut self, allow: bool) -> Self {
        self.allow_stale = allow;
        self
    }

    /// Substitutes the transport. The default speaks plain HTTP and
    /// `file://`; a consumer needing HTTPS or a proxy supplies their own.
    ///
    /// [`Fetch`] requires `Send`, so the boxed transport is `Send` too and the
    /// finished [`Debian`] can be moved to another thread.
    pub fn fetcher(mut self, fetcher: Box<dyn Fetch + 'a>) -> Self {
        self.fetcher = Some(fetcher);
        self
    }

    /// Validates the configuration and freezes it into a [`Debian`].
    ///
    /// # Errors
    ///
    /// Returns [`DebianError::Config`] for a configuration that contradicts
    /// itself — a plan alongside a setting that would reshape it, a plan and a
    /// pin at once, or either resolved for a different suite or architecture —
    /// and for a suite, component, or architecture the archive cannot be
    /// addressed by: an empty value, one carrying whitespace or a control
    /// character, or one that would resolve outside the mirror root through a
    /// leading `/`, a `..` segment, or an empty or `.` segment. The suite and the component may otherwise
    /// contain slashes, since both may name a subtree; the architecture may not.
    ///
    /// Returns [`DebianError::Io`] when a keyring named by
    /// [`keyring`](Self::keyring) or by an additional repository cannot be read.
    pub fn build(self) -> Result<Debian<'a>, DebianError> {
        if self.suite.trim().is_empty() {
            return Err(DebianError::Config {
                reason: "no suite was given".to_string(),
            });
        }
        // A plan states which architecture it is for, so a builder that names
        // none adopts it: refusing a plan the caller never contradicted, over a
        // default the caller never chose, would be a confusing rejection. A pin
        // states one for the same reason and is adopted the same way.
        let stated = self.plan.as_ref().or(self.pin.as_ref());
        let architecture = match (&self.architecture, stated) {
            (Some(architecture), _) => architecture.clone(),
            (None, Some(plan)) => plan.architecture.clone(),
            (None, None) => arch::host_architecture(),
        };
        // The architecture is a path segment of every index URL and of the
        // merged-usr layout, so it passes the same check the suite and the
        // components do at repository construction. It is a single segment: the
        // archive spells it `binary-<architecture>`, one directory deep.
        check_coordinate(
            "the bootstrap's architecture",
            &architecture,
            Nesting::Single,
        )?;
        let keyring = match &self.keyring_path {
            Some(path) => {
                std::fs::read(path).map_err(DebianError::at("reading the keyring", path))?
            }
            None => EMBEDDED_KEYRING.to_vec(),
        };
        let components = if self.components.is_empty() {
            vec!["main".to_string()]
        } else {
            self.components
        };
        // The primary repository: its mirror list is the configured mirror
        // followed by any snapshot backstops, and its trust anchor is the
        // resolved keyring unless the caller trusts it unsigned. Repository
        // construction rejects an unsigned http:// mirror, the same refusal the
        // flattened configuration made.
        let primary_mirror = self.mirror.unwrap_or_else(|| DEFAULT_MIRROR.to_string());
        let mut mirrors = Vec::with_capacity(1 + self.mirror_fallbacks.len());
        mirrors.push(primary_mirror);
        mirrors.extend(self.mirror_fallbacks);
        let primary = Repository::primary(
            self.suite.clone(),
            mirrors,
            components,
            keyring,
            self.trust_unsigned,
            self.allow_stale,
        )?;

        let mut repositories = Vec::with_capacity(1 + self.repositories.len());
        repositories.push(primary);
        repositories.extend(self.repositories);
        repository::validate_distinct_entries(&repositories)?;

        if let Some(plan) = &self.plan {
            validate_plan(
                plan,
                &self.suite,
                &architecture,
                repositories.len(),
                self.base_priority.is_some(),
                &self.includes,
                &self.excludes,
            )?;
        }

        let pin = match &self.pin {
            None => Pins::none(),
            Some(pin) => {
                validate_pin(pin, &self.suite, &architecture, self.plan.is_some())?;
                Pins::of(pin)?
            }
        };

        Ok(Debian {
            suite: self.suite,
            architecture,
            base_priority: self.base_priority.unwrap_or(Priority::Required),
            includes: self.includes,
            excludes: self.excludes,
            plan: self.plan,
            pin,
            extract_only: self.extract_only,
            identity_map: self.identity_map,
            cache_dir: self.cache_dir,
            overlay: self.overlay,
            base_layer: self.base_layer,
            repositories,
            fetcher: self.fetcher.unwrap_or_else(|| Box::new(HttpFetch::new())),
        })
    }
}

impl Provisioner for Debian<'_> {
    fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
        self.provision_reporting(request.staging(), &mut RunObserver { request })
    }
}

impl<'a> Debian<'a> {
    /// Binds a [`DebianObserver`] for one run, returning a provisioner that
    /// reports to it.
    ///
    /// A closure is an observer, so a caller that only wants events writes one
    /// and never names the trait; a caller that also wants to *stop* the
    /// bootstrap implements [`DebianObserver`] and answers its
    /// [`cancelled`](DebianObserver::cancelled).
    ///
    /// The sink is borrowed for the returned value's lifetime, not the
    /// provisioner's, so a `Debian` outlives every observed run and whatever the
    /// sink borrows is free again as soon as the run ends:
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use ferroday_cage::provision::debian::{Debian, DebianEvent};
    ///
    /// let mut debian = Debian::builder("trixie").build()?;
    /// let mut log: Vec<String> = Vec::new();
    ///
    /// let mut sink = |event: DebianEvent<'_>| {
    ///     if let DebianEvent::Fetching { url, .. } = event {
    ///         log.push(url.to_string());
    ///     }
    /// };
    /// let plan = debian.observe(&mut sink).resolve()?;
    /// drop(sink);
    ///
    /// // `log` is free here, and `debian` is still usable.
    /// println!("fetched {} resources for {} packages", log.len(), plan.packages.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn observe<'o>(&'o mut self, sink: &'o mut dyn DebianObserver) -> Observed<'o, 'a> {
        Observed { debian: self, sink }
    }

    /// The body of [`Provisioner::provision`], reporting to `observer` and
    /// stopping when it answers `true` to being cancelled.
    fn provision_reporting(
        &mut self,
        staging: &Path,
        observer: &mut dyn DebianObserver,
    ) -> Result<(), ProvisionError> {
        let (config, fetcher) = self.split();
        bootstrap_suite(staging, &config, fetcher, observer)
    }
}

/// A [`Debian`] with a progress sink bound for one run.
///
/// Returned by [`Debian::observe`]. It implements [`Provisioner`], so it is what
/// a caller hands to [`provision::ensure`](crate::provision::ensure) when it
/// wants progress; and it mirrors the provisioner's own entry points so a
/// resolution or a staged layer can report too.
pub struct Observed<'o, 'a> {
    debian: &'o mut Debian<'a>,
    sink: &'o mut dyn DebianObserver,
}

impl fmt::Debug for Observed<'_, '_> {
    /// Renders the bootstrap being observed. The sink is a caller's closure, so
    /// it renders as its presence rather than its contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observed")
            .field("debian", &self.debian)
            .field("sink", &Delegate("dyn DebianObserver"))
            .finish()
    }
}

impl Observed<'_, '_> {
    /// Resolves the install plan, reporting progress. See [`Debian::resolve`].
    pub fn resolve(&mut self) -> Result<Plan, DebianError> {
        let suite = self.debian.suite.clone();
        let (config, fetcher) = self.debian.split();
        // A plan set with `plan()` *is* the resolution: a bootstrap installs it
        // verbatim and fetches no index. Resolving afresh here would answer with
        // a different closure from the one the same value installs, which is the
        // one thing this is documented not to do -- and the plan is recommended
        // as a build-cache key, where a key that does not describe what is built
        // is worse than none.
        if let Some(plan) = config.plan {
            let plan = plan.clone();
            self.sink.progress(DebianEvent::Resolved { plan: &plan });
            return Ok(plan);
        }
        let architecture = config.architecture.to_string();
        let (packages, archives) = resolve_packages(&config, fetcher, self.sink)?;
        Ok(Plan::project(&suite, &architecture, &packages, &archives))
    }

    /// Resolves a layered build's increment, reporting progress. See
    /// [`Debian::resolve_layer`].
    pub fn resolve_layer(&mut self) -> Result<Plan, DebianError> {
        self.debian.resolve_layer_reporting(self.sink)
    }

    /// Reports the names the archives offer, reporting progress. See
    /// [`Debian::available`].
    pub fn available(&mut self) -> Result<Available, DebianError> {
        // Unpinned whatever the builder holds: this reports what the archives
        // offer, and a pin describes a selection from it rather than a bound on
        // what may be asked about.
        let (config, fetcher) = self.debian.split();
        let (index, _archives) = merged_index(
            fetcher,
            config.repositories,
            config.architecture,
            &Pins::none(),
            self.sink,
        )?;
        Ok(index.into_available())
    }

    /// Stages a layered build's increment, reporting progress. See
    /// [`Debian::stage_layer`].
    pub fn stage_layer(&mut self, upper: impl AsRef<Path>) -> Result<BuildLayer, ProvisionError> {
        self.debian.stage_layer_reporting(upper.as_ref(), self.sink)
    }
}

impl Provisioner for Observed<'_, '_> {
    /// Reports to the sink bound here rather than to the run's observer: the
    /// caller chose the richer, Debian-specific channel by using
    /// [`Debian::observe`]. Cancellation still comes from the run, so a
    /// [`Provision::observe`](crate::provision::Provision::observe) observer
    /// can stop a bootstrap it is not reporting on.
    fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
        let mut observer = ObservedRun {
            sink: self.sink,
            request,
        };
        self.debian
            .provision_reporting(request.staging(), &mut observer)
    }
}

/// The whole bootstrap, as a free function over borrowed configuration.
fn bootstrap_suite(
    staging: &Path,
    config: &Bootstrap<'_>,
    fetcher: &mut dyn Fetch,
    observer: &mut dyn DebianObserver,
) -> Result<(), ProvisionError> {
    let &Bootstrap {
        architecture,
        repositories,
        plan,
        extract_only,
        identity_map,
        cache_dir,
        overlay,
        // Read by the resolution this delegates to rather than here.
        base_priority: _,
        includes: _,
        excludes: _,
        pin: _,
    } = config;
    // A full bootstrap must be able to run the target's binaries.
    if !extract_only {
        arch::preflight_foreign(&arch::host_architecture(), architecture)
            .map_err(|reason| wrap(DebianError::Config { reason }))?;

        // A range map must be establishable before anything is downloaded:
        // an unavailable map is a configuration problem, and the identity
        // posture is never quietly downgraded to the single-identity form.
        if !matches!(identity_map, IdentityMap::Single)
            && let Err(reason) = crate::idmap::resolve_default_chain(identity_map)
        {
            return Err(wrap(DebianError::Config {
                reason: format!("the requested identity map is unavailable: {reason}"),
            }));
        }
    }

    let packages = match plan {
        // A plan is the resolution: the release and the index are never
        // fetched, which is the whole of what this saves. The plan is reported
        // as the resolved manifest so an observer sees the same event either
        // way, and it is reported as it stands rather than re-projected.
        Some(plan) => {
            observer.progress(DebianEvent::Resolved { plan });
            plan.packages.iter().map(Wanted::from_planned).collect()
        }
        // A bootstrap installs the plan rather than reporting it, so the archive
        // state goes to the `Resolved` event and no further.
        None => {
            let (packages, _archives) =
                resolve_packages(config, fetcher, observer).map_err(wrap)?;
            packages
                .iter()
                .map(Wanted::from_package)
                .collect::<Vec<_>>()
        }
    };

    // The cache disposes of itself when this frame ends, on the failure paths
    // below as on the success path.
    let archives = PackageCache::beside(staging, cache_dir, DEB_CACHE);
    let installables = acquire_debs(fetcher, repositories, &packages, archives.path(), observer)?;

    let statoverride = stage_extract(
        staging,
        architecture,
        &installables,
        archives.path(),
        observer,
    )?;

    if !extract_only {
        let env = maintainer_env();
        let wave = bootstrap::Configure {
            archives_host: archives.path(),
            installables: &installables,
            statoverride: &statoverride,
            identity_map,
            env: &env,
        };
        bootstrap::configure(staging, &wave, repositories, overlay, observer).map_err(wrap)?;
        // The read-only bind mount left an empty mount point in the rootfs.
        let _ = std::fs::remove_dir_all(staging.join(bootstrap::ARCHIVES.trim_start_matches('/')));
    }

    Ok(())
}

/// Fetches and verifies every repository's release and index, merges the
/// indexes, and resolves the install closure, downloading nothing.
///
/// Shared by [`Debian::resolve`] and the full bootstrap, so the plan a caller
/// previews and the plan a bootstrap installs come from one code path and
/// cannot drift apart. Each repository's release is verified against that
/// repository's own keyring and bound to its own suite; freshness is enforced
/// per repository unless it trusts unsigned or pins a historical snapshot. The
/// per-component indexes are tagged with their repository's index and merged
/// highest-version-wins across the union, so the resolved set draws each
/// package from the repository that ships its winning version.
fn resolve_packages(
    config: &Bootstrap<'_>,
    fetcher: &mut dyn Fetch,
    observer: &mut dyn DebianObserver,
) -> Result<(Vec<Package>, Vec<ResolvedArchive>), DebianError> {
    let (index, archives) = merged_index(
        fetcher,
        config.repositories,
        config.architecture,
        config.pin,
        observer,
    )?;

    observer.progress(DebianEvent::Resolving);
    let mut base = index.base_seed(config.base_priority);
    base.push("apt".to_string());
    let (packages, refusals) = resolve::resolve(&index, &base, config.includes, config.excludes);
    report_refusals(refusals, observer)?;

    let packages = emit_resolved(
        config.repositories,
        config.architecture,
        packages,
        &archives,
        observer,
    );
    Ok((packages, archives))
}

/// Reports every refusal a resolution collected, then fails with all of them
/// named. A resolution that refused nothing returns `Ok` and reports nothing.
///
/// The two halves are both the point. The events let a caller watching progress
/// see each refusal as its own item, which is what a list a user has to correct
/// wants to be; the error carries the same set as one sentence, for the caller
/// who only ever sees the failure. Neither is a summary of the other.
fn report_refusals(
    refusals: resolve::Refusals,
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    if refusals.is_empty() {
        return Ok(());
    }
    for refusal in refusals.iter() {
        observer.progress(DebianEvent::Unsatisfiable {
            requirement: refusal.requirement(),
            required_by: refusal.required_by(),
            reason: &refusal.reason(),
        });
    }
    Err(DebianError::Resolve {
        reason: refusals.describe(),
    })
}

/// Resolves the increment a layered build installs over its base.
///
/// The caller's packages are closed against the merged index while
/// `assume_installed` — the base layer's configured set, and the virtuals it
/// provides — is treated as satisfied, so only the delta the base does not
/// already carry is selected. There is no base-system seed and no `apt`: the
/// base supplies both. This is [`resolve_packages`]'s read-merge-and-report
/// structure with the priority seed replaced by the base's installed set.
fn resolve_delta(
    config: &Bootstrap<'_>,
    assume_installed: &InstalledSet,
    fetcher: &mut dyn Fetch,
    observer: &mut dyn DebianObserver,
) -> Result<(Vec<Package>, Vec<ResolvedArchive>), DebianError> {
    let (index, archives) = merged_index(
        fetcher,
        config.repositories,
        config.architecture,
        config.pin,
        observer,
    )?;

    observer.progress(DebianEvent::Resolving);
    let (packages, refusals) = resolve::resolve_seeded(
        &index,
        &[],
        config.includes,
        config.excludes,
        assume_installed,
    );
    report_refusals(refusals, observer)?;

    let packages = emit_resolved(
        config.repositories,
        config.architecture,
        packages,
        &archives,
        observer,
    );
    Ok((packages, archives))
}

/// Fetches and verifies every repository's release and index and merges them
/// into one package set, downloading no package.
///
/// The fetch-and-merge half of a resolution, shared by the full-bootstrap
/// [`resolve_packages`] and the layered-build [`resolve_delta`] so both draw
/// from an identically built and verified index. Each repository's release is
/// verified against its own keyring and bound to its own suite; the per-component
/// indexes are tagged with their repository's index and merged
/// highest-version-wins across the union.
fn merged_index(
    fetcher: &mut dyn Fetch,
    repositories: &[Repository],
    architecture: &str,
    pins: &Pins,
    observer: &mut dyn DebianObserver,
) -> Result<(Index, Vec<ResolvedArchive>), DebianError> {
    // Each repository contributes one text block per component, tagged with the
    // repository's index so the merged index knows where each package came from.
    let mut index_inputs: Vec<(usize, String)> = Vec::new();
    // The archive state, in repository order, so a package's origin tag indexes
    // straight into it.
    let mut archives: Vec<ResolvedArchive> = Vec::new();
    for (origin, repository) in repositories.iter().enumerate() {
        let (release, served) = fetch_release(fetcher, repository, observer)?;
        release
            .check(
                &repository.suite,
                architecture,
                &repository.components,
                repository.require_fresh(),
            )
            .map_err(DebianError::from)?;
        archives.push(ResolvedArchive {
            mirror: served.mirror,
            suite: repository.suite.clone(),
            components: repository.components.clone(),
            release_sha256: release.sha256().to_string(),
            date: release.date().map(str::to_string),
            valid_until: release.valid_until().map(str::to_string),
            signed_by: served.signed_by,
            signing_key: served.signing_key,
            // A record built from a live resolution has no document behind it,
            // so there is nothing to carry.
            carried: Carried::new(),
        });
        let text = fetch_index(fetcher, repository, architecture, &release, observer)?;
        index_inputs.push((origin, text));
    }

    let index = Index::merge(
        index_inputs
            .iter()
            .map(|(origin, text)| (*origin, text.as_str())),
        architecture,
        pins,
    );
    // Before the closure is computed, so a pin the archives have moved past
    // refuses the resolution rather than being quietly resolved around.
    pins.check(&index)?;
    Ok((index, archives))
}

/// Projects a resolved package set into a [`Plan`] and reports it through the
/// [`Resolved`](DebianEvent::Resolved) event, returning the packages unchanged.
///
/// The manifest is thus observable inline, without a separate resolve pass, for
/// both a full bootstrap and a layered build. The suite named is the primary
/// repository's, the one the caller requested; it always exists, as the builder
/// seeds element zero with the primary.
fn emit_resolved(
    repositories: &[Repository],
    architecture: &str,
    packages: Vec<Package>,
    archives: &[ResolvedArchive],
    observer: &mut dyn DebianObserver,
) -> Vec<Package> {
    let suite = repositories
        .first()
        .map_or("", |repository| repository.suite.as_str());
    let plan = Plan::project(suite, architecture, &packages, archives);
    observer.progress(DebianEvent::Resolved { plan: &plan });
    packages
}

/// Fetches and verifies a repository's release, returning its parsed form.
///
/// The fetch walks the repository's mirror list in order, advancing past a URL
/// that reports the release missing or fails at the transport. On the signed
/// path the archive signature is verified against the repository's keyring;
/// `allow_stale` relaxes the check that the signature itself is unexpired, for a
/// deliberately pinned historical snapshot.
fn fetch_release(
    fetcher: &mut dyn Fetch,
    repository: &Repository,
    observer: &mut dyn DebianObserver,
) -> Result<(Release, Served), DebianError> {
    let suite = &repository.suite;
    let (body, served) = match repository.keyring() {
        None => {
            let suffix = format!("dists/{suite}/Release");
            let (bytes, mirror) =
                fetch_from_mirrors(fetcher, &repository.mirrors, &suffix, observer)?;
            let body = String::from_utf8(bytes).map_err(|_| {
                DebianError::from(release::ReleaseError::Release(
                    "Release is not UTF-8".to_string(),
                ))
            })?;
            // Nothing verified it, so no key is named. An empty list is the
            // record of that, and is not the same as an omitted repository.
            (
                body,
                Served {
                    mirror,
                    signed_by: Vec::new(),
                    signing_key: Vec::new(),
                },
            )
        }
        Some(keyring_bytes) => {
            let suffix = format!("dists/{suite}/InRelease");
            let (bytes, mirror) =
                fetch_from_mirrors(fetcher, &repository.mirrors, &suffix, observer)?;
            let keyring = Keyring::parse(keyring_bytes).map_err(release::ReleaseError::from)?;
            let verified = keyring
                .verify(&bytes, !repository.allow_stale)
                .map_err(release::ReleaseError::from)?;
            (
                verified.body,
                Served {
                    mirror,
                    signed_by: vec![verified.certificate],
                    signing_key: vec![verified.signing_key],
                },
            )
        }
    };
    let release = Release::parse(&body).map_err(DebianError::from)?;
    Ok((release, served))
}

/// How a repository's release was obtained: which mirror answered, and which
/// key verified it.
///
/// The two facts a [`ResolvedArchive`] needs that the release body does not
/// itself carry.
struct Served {
    /// The mirror that served the release.
    ///
    /// Where the release came from, and not where the packages go to: a
    /// bootstrap walks the mirrors its repositories are configured with, so this
    /// records the choice that was made rather than deciding a later one. It
    /// reaches a caller as [`ResolvedArchive::mirror`].
    mirror: String,
    /// The verifying certificate's primary-key fingerprint, or empty for a
    /// trusted-unsigned repository.
    signed_by: Vec<String>,
    /// The fingerprint of the component key within that certificate which made
    /// the signature, or empty for a trusted-unsigned repository.
    signing_key: Vec<String>,
}

/// Fetches, verifies, and decompresses a repository's package index for every
/// component, returning the concatenated text ready to merge.
///
/// Components are joined with a blank line between them, because that is what
/// separates one deb822 paragraph from the next. An index ends with the final
/// field of its last stanza rather than with a blank line — the archive's own
/// files and this crate's [`Pool`] alike — so joining them end to end would fold
/// the first stanza of each component into the last stanza of the one before it,
/// and every package that stanza named would be lost from the index without any
/// digest check noticing: each component verified against the release
/// individually, and only their concatenation was wrong.
///
/// A component whose index holds no stanzas contributes nothing and is skipped,
/// so an empty component — a pool created before the build that fills it — does
/// not introduce a stray paragraph break.
fn fetch_index(
    fetcher: &mut dyn Fetch,
    repository: &Repository,
    architecture: &str,
    release: &Release,
    observer: &mut dyn DebianObserver,
) -> Result<String, DebianError> {
    let mut merged = String::new();
    for component in &repository.components {
        let text = fetch_component_index(
            fetcher,
            repository,
            architecture,
            component,
            release,
            observer,
        )?;
        append_component(&mut merged, &text);
    }
    Ok(merged)
}

/// Appends one component's index to the merged text, separated from what is
/// already there by the blank line that ends a deb822 paragraph.
///
/// Each index is normalized to end with exactly one newline before the next is
/// joined on, so the result is well-formed whether a component's file ends with
/// its last field, with a blank line, or with several. An index holding no
/// stanzas is skipped rather than contributing an empty paragraph.
fn append_component(merged: &mut String, text: &str) {
    if text.trim().is_empty() {
        return;
    }
    if !merged.is_empty() {
        merged.push('\n');
    }
    merged.push_str(text.trim_end_matches('\n'));
    merged.push('\n');
}

/// Fetches one component's index, walking the repository's mirror list.
///
/// The candidate compressions the release lists a digest for are determined
/// once, from the release; the mirror walk then tries them in order on each
/// mirror, advancing to the next mirror when one reports the index missing. A
/// fetched index is verified against the release digest — a mismatch is fatal,
/// not a reason to try another mirror — and decompressed.
fn fetch_component_index(
    fetcher: &mut dyn Fetch,
    repository: &Repository,
    architecture: &str,
    component: &str,
    release: &Release,
    observer: &mut dyn DebianObserver,
) -> Result<String, DebianError> {
    // Prefer the smallest available index; every candidate is verified against
    // the release digest, so the choice is trust-neutral. Which compressions
    // exist is a property of the release, the same across every mirror. The
    // release states each index's length beside its digest, and that length
    // travels with the fetch as its ceiling: it is signed, it is free, and it
    // bounds what a mirror can spend before the digest check runs.
    let candidates: Vec<(String, u64, &str)> = ["Packages.xz", "Packages.gz", "Packages"]
        .iter()
        .filter_map(|suffix| {
            let rel = format!("{component}/binary-{architecture}/{suffix}");
            release
                .digest(&rel)
                .map(|(size, digest)| (rel, size, digest))
        })
        .collect();
    if candidates.is_empty() {
        return Err(DebianError::Index {
            reason: format!("the release lists no index for component {component}"),
        });
    }

    let suite = &repository.suite;
    // Two walks, one inside the other: the encodings within one mirror, and the
    // mirrors. A mirror that serves none of the encodings has failed over as
    // surely as one that answered nothing, so the inner walk's last failure is
    // what advances the outer one -- and the inner `exhausted` is unreachable,
    // the empty candidate list having been refused above.
    walk_mirrors(
        &repository.mirrors,
        |mirror| {
            walk_mirrors(
                &candidates,
                |(rel, size, digest)| {
                    let url = if release.acquire_by_hash() {
                        mirror_url(
                            mirror,
                            &format!(
                                "dists/{suite}/{component}/binary-{architecture}/by-hash/SHA256/\
                                 {digest}"
                            ),
                        )
                    } else {
                        mirror_url(mirror, &format!("dists/{suite}/{rel}"))
                    };
                    observer.progress(DebianEvent::Fetching { url: &url });
                    let bytes = fetch_bytes(fetcher, &url, Some(*size))?;
                    verify_digest(rel, &bytes, digest)?;
                    decompress_index(rel, &bytes)
                },
                || DebianError::Index {
                    reason: format!("the release lists no index for component {component}"),
                },
            )
        },
        || DebianError::Index {
            reason: format!("no mirror served an index for component {component}"),
        },
    )
}

/// Fetches `suffix` (a mirror-relative path) from the first mirror that serves
/// it, advancing past a mirror that reports the resource missing or fails at
/// the transport, and returning the last such error when every mirror is
/// exhausted.
///
/// No size travels with these: this fetches a release file, which is the trust
/// root and so has nothing signed to declare its length. The fetcher's own
/// ceiling is the bound there, which is the right one — a release is small, and
/// the alternative would be a ceiling of this module's invention.
fn fetch_from_mirrors(
    fetcher: &mut dyn Fetch,
    mirrors: &[String],
    suffix: &str,
    observer: &mut dyn DebianObserver,
) -> Result<(Vec<u8>, String), DebianError> {
    walk_mirrors(
        mirrors,
        |mirror| {
            let url = mirror_url(mirror, suffix);
            observer.progress(DebianEvent::Fetching { url: &url });
            // The mirror that answered, not the whole list: a repository with a
            // snapshot backstop resolves against whichever one served, and a
            // record naming the list would describe a choice rather than the
            // choice made.
            fetch_bytes(fetcher, &url, None).map(|bytes| (bytes, mirror.clone()))
        },
        || {
            DebianError::Fetch(FetchError::NotFound {
                url: suffix.to_string(),
            })
        },
    )
}

impl Failover for DebianError {
    /// Reaches through the wrapper this layer carries a transport failure in.
    /// A failure that is not a `Fetch` one at all — a digest or signature
    /// mismatch over bytes that did arrive — never advances a walk, and falls
    /// out of the same match.
    fn is_failover(&self) -> bool {
        matches!(self, DebianError::Fetch(fetch) if fetch.is_failover())
    }
}

/// Downloads (or reuses from cache) and verifies every selected package.
///
/// Each package's bytes are fetched from its own repository's mirrors — the
/// repository the merged index retained its winning version from — walking that
/// mirror list on a missing or failed URL, so a version that has rotated off a
/// live pool is served by the repository's snapshot backstop.
///
/// What is *missing* from the cache is fetched in batches first, through
/// [`Fetch::fetch_all`], so a transport that can overlap several requests does.
/// That step is an optimization and nothing more: a package it does not deliver
/// is downloaded by the walk below exactly as though the batch had not run, and
/// the walk is still what decides that a package arrived, verified.
fn acquire_debs(
    fetcher: &mut dyn Fetch,
    repositories: &[Repository],
    packages: &[Wanted],
    archives_host: &Path,
    observer: &mut dyn DebianObserver,
) -> Result<Vec<Installable>, ProvisionError> {
    std::fs::create_dir_all(archives_host).map_err(|source| {
        wrap(DebianError::io(
            "creating the package directory",
            archives_host,
            source,
        ))
    })?;

    // The cache pass and the announcement, before anything is fetched: what a
    // caller is told it is downloading is what a batch and the walk between
    // them go on to fetch, in the order the plan names them.
    let mut missing = Vec::new();
    for (position, package) in packages.iter().enumerate() {
        if observer.cancelled() {
            return Err(ProvisionError::Cancelled);
        }
        let dest = archives_host.join(format!("{}.deb", package.sha256));
        // Whether the cache entry is intact, decided by streaming its digest:
        // validating a cached kernel package costs the memory of validating a
        // shell script, which is the property every read and write of a `.deb`
        // in this crate keeps. A corrupt or truncated entry is simply
        // re-downloaded.
        let cached = std::fs::File::open(&dest)
            .and_then(|mut file| digest::stream(Algorithm::Sha256, &mut file))
            .is_ok_and(|(digest, _)| digest == package.sha256);
        if !cached {
            observer.progress(DebianEvent::Downloading {
                package: &package.name,
                index: position + 1,
                total: packages.len(),
            });
            missing.push((package, dest));
        }
    }

    prefetch_debs(fetcher, repositories, &missing, observer)?;

    for (package, dest) in &missing {
        // A package boundary: whatever has been downloaded is complete, and
        // the staging tree is untouched, so stopping here costs nothing.
        if observer.cancelled() {
            return Err(ProvisionError::Cancelled);
        }
        if dest.is_file() {
            continue;
        }
        let mirrors = &repositories[package.origin].mirrors;
        download_deb(fetcher, mirrors, package, dest, observer).map_err(wrap)?;
    }

    Ok(packages
        .iter()
        .map(|package| Installable {
            name: package.name.clone(),
            deb_path: format!("{}/{}.deb", bootstrap::ARCHIVES, package.sha256),
            sha256: package.sha256.clone(),
        })
        .collect())
}

/// How many packages one batch asks for.
///
/// Each job holds an open staging file for as long as the batch runs, so this
/// is a bound on descriptors rather than on the transport, which decides for
/// itself how many of a batch to have in flight. It is also the granularity a
/// cancelled bootstrap stops at, which is the reason it is not larger.
const BATCH: usize = 32;

/// Fills the cache with the packages a bootstrap is about to install, several
/// at a time.
///
/// Every job asks the package's own repository's first mirror, which is the one
/// the walk would ask first too. A job that does not arrive, or arrives and does
/// not verify, simply leaves the cache without that package, and the walk that
/// follows downloads it with every mirror available to it. Nothing here decides
/// that a package is present: the rename is, and it happens only over bytes
/// whose digest matched.
fn prefetch_debs(
    fetcher: &mut dyn Fetch,
    repositories: &[Repository],
    missing: &[(&Wanted, PathBuf)],
    observer: &mut dyn DebianObserver,
) -> Result<(), ProvisionError> {
    for batch in missing.chunks(BATCH) {
        if observer.cancelled() {
            return Err(ProvisionError::Cancelled);
        }
        let mut staged = Vec::with_capacity(batch.len());
        for (package, dest) in batch {
            let Some(mirror) = repositories[package.origin].mirrors.first() else {
                continue;
            };
            let url = mirror_url(mirror, &package.filename);
            observer.progress(DebianEvent::Fetching { url: &url });
            let path = staging_path(dest);
            // Created exclusively, which establishes that the name is this
            // call's alone and refuses a symlink pre-planted at it rather than
            // writing through it.
            let Ok(file) = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            else {
                continue;
            };
            // Capped as the per-package download is, and for the same reason:
            // the size travels with the request, but a transport is free to
            // ignore it, and the sink is the one place the bound cannot be.
            let sink = digest::DigestWriter::new(Algorithm::Sha256, file);
            let cap = package.size.unwrap_or(u64::MAX);
            staged.push((*package, dest, url, path, LimitedWriter::new(sink, cap)));
        }

        let outcomes = {
            let mut jobs: Vec<FetchJob<'_>> = staged
                .iter_mut()
                .map(|(package, _dest, url, _path, sink)| {
                    let request = FetchRequest::new(url);
                    let request = match package.size {
                        Some(size) => request.sized(size),
                        None => request,
                    };
                    FetchJob::new(request, sink)
                })
                .collect();
            fetcher.fetch_all(&mut jobs)
        };

        for ((package, dest, _url, path, sink), outcome) in staged.into_iter().zip(outcomes) {
            let published = outcome.is_ok()
                && sink
                    .into_inner()
                    .finish()
                    .is_ok_and(|(actual, _size)| actual == package.sha256)
                && std::fs::rename(&path, dest).is_ok();
            if !published {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    Ok(())
}

/// Downloads one package into the cache, walking its repository's mirrors.
///
/// The walk is [`fetch_from_mirrors`]'s: a mirror that reports the package
/// missing or fails at the transport advances to the next, and the last such
/// failure is reported once none is left. A digest mismatch is not one of those
/// — it says the bytes are wrong rather than absent — so it fails the download
/// where it happens, as it does everywhere else in the module.
fn download_deb(
    fetcher: &mut dyn Fetch,
    mirrors: &[String],
    package: &Wanted,
    dest: &Path,
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    walk_mirrors(
        mirrors,
        |mirror| {
            let url = mirror_url(mirror, &package.filename);
            observer.progress(DebianEvent::Fetching { url: &url });
            fetch_verified(fetcher, &url, &package.sha256, package.size, dest)
        },
        || {
            DebianError::Fetch(FetchError::NotFound {
                url: package.filename.clone(),
            })
        },
    )
}

/// Fetches `url` into `dest`, verified and atomically.
///
/// The body is written to a staging file beside the destination as it arrives,
/// digested on the way through, and renamed onto the destination only once the
/// digest is `expected`. Two things fall out of doing it in that order. A `.deb`
/// never exists in memory as one buffer, so downloading a 90 MB kernel package
/// costs what downloading a shell script costs — the property the cache check
/// above and [`Pool::publish`] are both written for. And nothing unverified is
/// ever visible at the destination, because the rename is what puts it there;
/// the staging name is unique to this call, so a concurrent download of the same
/// package publishes its own file rather than consuming this one.
///
/// The staging file is not synced before the rename, for the reason
/// [`write_atomically`] gives: what is read back is verified against a digest,
/// so an entry left short by a crash is rejected and fetched again, which is
/// cheaper than syncing every download against a failure that costs only a
/// repeat.
///
/// `size` is the length the index recorded for the package, where one is known.
/// It travels with the request and bounds the staging file, so a mirror that
/// answers a request for a two-megabyte `.deb` with an endless body fills no
/// more disk than the package weighs. The digest still decides whether the
/// bytes are the package; this only decides how many of them are read.
///
/// Anything that fails takes the staging file with it, so a mirror that dies
/// mid-body leaves nothing for the next one to trip over.
fn fetch_verified(
    fetcher: &mut dyn Fetch,
    url: &str,
    expected: &str,
    size: Option<u64>,
    dest: &Path,
) -> Result<(), DebianError> {
    let staged = staging_path(dest);

    // Created exclusively, which establishes that the name is this call's alone
    // and refuses a symlink pre-planted at it rather than writing through it.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(DebianError::at("staging a package", &staged))?;

    let mut sink = digest::DigestWriter::new(Algorithm::Sha256, file);
    let request = FetchRequest::new(url);
    let fetched = match size {
        Some(size) => {
            let mut capped = super::LimitedWriter::new(&mut sink, size);
            fetcher.fetch(&request.sized(size), &mut capped)
        }
        None => fetcher.fetch(&request, &mut sink),
    };
    let digested = sink
        .finish()
        .map_err(DebianError::at("writing a package", &staged));

    let published = fetched
        .map_err(DebianError::Fetch)
        .and(digested)
        .and_then(|(actual, _size)| {
            if actual == expected {
                Ok(())
            } else {
                Err(DebianError::HashMismatch {
                    path: url.to_string(),
                    expected: expected.to_string(),
                    actual,
                })
            }
        })
        .and_then(|()| {
            std::fs::rename(&staged, dest).map_err(DebianError::at("publishing a package", dest))
        });

    if published.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    published
}

/// One `.deb` to acquire: what the download needs and nothing else.
///
/// The two sources of an install set project onto this — a fresh resolution's
/// [`Package`], and a [`Plan`]'s [`PlannedPackage`] — so the download,
/// the digest check, and the cache reuse are one path whichever produced it.
struct Wanted {
    /// The package name, for the progress report and the dpkg install order.
    name: String,
    /// The archive-recorded SHA-256, which is both the cache key and the check
    /// the download is held to.
    sha256: String,
    /// The pool path, relative to the mirror root.
    filename: String,
    /// The archive-recorded length of the `.deb`, which bounds what the
    /// download may spend. `None` where nothing states it.
    size: Option<u64>,
    /// Which repository serves it, as an index into the configured list.
    origin: usize,
}

impl Wanted {
    /// Projects a freshly resolved package.
    fn from_package(package: &Package) -> Wanted {
        Wanted {
            name: package.name.clone(),
            sha256: package.sha256.clone(),
            filename: package.filename.clone(),
            size: package.size,
            origin: package.origin,
        }
    }

    /// Projects a package a plan names.
    ///
    /// The plan's archive index is the repository index, which is what
    /// [`validate_plan`] holds the configuration to.
    ///
    /// A plan carries no size, because installing from one fetches no index to
    /// read it from — that omission is the whole of what a plan saves. Such a
    /// download is bounded by the fetcher's own ceiling instead, and verified
    /// against the plan's digest exactly as any other is.
    fn from_planned(package: &PlannedPackage) -> Wanted {
        Wanted {
            name: package.name.clone(),
            sha256: package.sha256.clone(),
            filename: package.filename.clone(),
            size: None,
            origin: package.archive,
        }
    }
}

/// Stage one: lay out the merged-usr farm and every package's files, and
/// initialize the dpkg database.
///
/// Returns the derived [`StatOverride`] — one record per file a package ships
/// with non-root ownership. The file is not written here: dpkg rejects a
/// statoverride naming `root` until `base-passwd` has created `/etc/passwd`, so
/// configuration writes it after the base-passwd wave. An extract-only rootfs,
/// which never configures, does not carry it.
fn stage_extract(
    staging: &Path,
    architecture: &str,
    installables: &[Installable],
    archives_host: &Path,
    observer: &mut dyn DebianObserver,
) -> Result<StatOverride, ProvisionError> {
    let statoverride =
        extract_packages(staging, architecture, installables, archives_host, observer)?;
    init_dpkg_database(staging)?;
    Ok(statoverride)
}

/// Lays out the merged-usr farm and every package's files into `staging`,
/// returning the derived [`StatOverride`].
///
/// The extraction half of [`stage_extract`], without the dpkg database
/// initialization. A layered build reuses it to extract an increment into an
/// overlay upper: the merged-usr symlinks are created there so a package
/// shipping a legacy top-level path resolves into `usr`, exactly as for a full
/// bootstrap, while the base's own dpkg database — seen through the overlay —
/// is left untouched, so no empty database is written over it.
fn extract_packages(
    staging: &Path,
    architecture: &str,
    installables: &[Installable],
    archives_host: &Path,
    observer: &mut dyn DebianObserver,
) -> Result<StatOverride, ProvisionError> {
    create_merged_usr(staging, architecture)?;

    // Every `.deb` ships a `./` entry, so the tree being assembled would
    // otherwise take the mode and modification time of whichever package
    // happened to be extracted last. A rootfs root is `0755`, the mode
    // `base-files` itself ships, and stating it keeps the published directory
    // independent of both the package set and the caller's umask.
    let mut extraction = Extraction::new(staging)?.root_mode(ROOTFS_ROOT_MODE);
    let mut statoverride = StatOverride::default();
    // A statoverride record is one newline-terminated line; a path component
    // carrying an embedded newline would split into a second, forged record
    // (a setuid grant on an unrelated path, say). A conforming .deb never
    // ships such a path, and the signed digest chain keeps a mirror from
    // forging one, so this is defense in depth for an unreachable case: reject
    // rather than emit a line the framing cannot be trusted to contain.
    let mut malformed: Option<Vec<Vec<u8>>> = None;
    for installable in installables {
        // A package boundary again: the staging tree is discarded wholesale by
        // `ensure` when this returns an error, so a partial layout is not a
        // hazard.
        if observer.cancelled() {
            return Err(ProvisionError::Cancelled);
        }
        observer.progress(DebianEvent::Extracting {
            package: &installable.name,
        });
        let filename = installable
            .deb_path
            .rsplit('/')
            .next()
            .expect("the deb path has a file name");
        let path = archives_host.join(filename);
        let mut file = std::fs::File::open(&path)
            .map_err(|err| ProvisionError::io("reading the package", &path, err))?;
        // Re-verify against the digest the package was acquired under, rather
        // than trust the bytes on disk: the download and this read are separate
        // steps, and the cache may share a filesystem with untrusted writers.
        //
        // Streamed, and the extraction that follows streams too, so installing a
        // kernel package costs the memory of installing a shell script — the
        // property the download and `Pool::publish` both keep, held to here as
        // well. `extract_deb` rewinds before it seeks to the data member, so the
        // digest pass leaving the file at its end costs nothing.
        let (actual, _) = digest::stream(Algorithm::Sha256, &mut file)
            .map_err(|err| ProvisionError::io("reading the package", &path, err))?;
        if actual != installable.sha256 {
            return Err(wrap(DebianError::HashMismatch {
                path: filename.to_string(),
                expected: installable.sha256.clone(),
                actual,
            }));
        }
        deb::extract_deb(
            &installable.name,
            &mut file,
            &mut extraction,
            &mut |entry, components| {
                if entry.uid != 0 || entry.gid != 0 {
                    if components
                        .iter()
                        .any(|component| component.contains(&b'\n'))
                    {
                        malformed.get_or_insert_with(|| components.to_vec());
                        return Ok(Placement::Write);
                    }
                    statoverride.record(entry.mode, absolute_path(components));
                }
                // A `.deb`'s files are dpkg's to arbitrate, and this hook only
                // records ownership as they go past, so every entry is written.
                Ok(Placement::Write)
            },
        )?;
    }
    if let Some(components) = malformed {
        return Err(wrap(DebianError::MalformedEntry {
            path: absolute_path(&components),
        }));
    }
    extraction.finalize(staging)?;
    Ok(statoverride)
}

/// Creates the merged-usr symlink farm for `architecture` in `staging`.
fn create_merged_usr(staging: &Path, architecture: &str) -> Result<(), ProvisionError> {
    for dir in arch::merged_usr_dirs(architecture) {
        let target = staging.join("usr").join(dir);
        std::fs::create_dir_all(&target)
            .map_err(|err| ProvisionError::io("creating", &target, err))?;
        let link = staging.join(dir);
        if !arch::exists(&link) {
            std::os::unix::fs::symlink(format!("usr/{dir}"), &link)
                .map_err(|err| ProvisionError::io("linking", &link, err))?;
        }
    }
    Ok(())
}

/// Initializes the dpkg database: empty `status` and `available`, and the
/// working directories dpkg expects.
fn init_dpkg_database(staging: &Path) -> Result<(), ProvisionError> {
    let dpkg = staging.join("var/lib/dpkg");
    for dir in ["", "info", "updates"] {
        let path = dpkg.join(dir);
        std::fs::create_dir_all(&path).map_err(|err| ProvisionError::io("creating", &path, err))?;
    }
    for file in ["status", "available"] {
        let path = dpkg.join(file);
        if !path.exists() {
            std::fs::write(&path, "").map_err(|err| ProvisionError::io("writing", &path, err))?;
        }
    }
    Ok(())
}

/// The maintainer-script environment: non-interactive, deterministic locale
/// and timezone.
fn maintainer_env() -> Vec<(String, String)> {
    [
        ("DEBIAN_FRONTEND", "noninteractive"),
        ("DEBCONF_NONINTERACTIVE_SEEN", "true"),
        ("LC_ALL", "C.UTF-8"),
        ("TZ", "UTC"),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .collect()
}

/// Fetches a URL fully into memory, bounded by the size a verified source
/// declares for it where there is one.
///
/// The declared size travels with the request, so a transport that honours it
/// refuses an oversized framing before reading a byte, *and* bounds the sink
/// here, because a caller-supplied [`Fetch`] is free to ignore the request and
/// the sink is the one place the bound cannot be ignored. Without it the only
/// bound is the built-in fetcher's own `MAX_BODY` — two gigabytes — or nothing
/// at all for a transport of the caller's, while the release that named the
/// resource says it is a few megabytes. The digest check that follows catches
/// the substitution either way, but only after the memory has been spent.
fn fetch_bytes(
    fetcher: &mut dyn Fetch,
    url: &str,
    size: Option<u64>,
) -> Result<Vec<u8>, DebianError> {
    let mut bytes = Vec::new();
    let request = FetchRequest::new(url);
    let result = match size {
        Some(size) => {
            let mut sink = super::LimitedWriter::new(&mut bytes, size);
            fetcher.fetch(&request.sized(size), &mut sink)
        }
        None => fetcher.fetch(&request, &mut bytes),
    };
    result?;
    Ok(bytes)
}

/// Verifies bytes against an expected SHA-256, naming the resource on
/// mismatch.
fn verify_digest(path: &str, bytes: &[u8], expected: &str) -> Result<(), DebianError> {
    let actual = Algorithm::Sha256.hex_of(bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(DebianError::HashMismatch {
            path: path.to_string(),
            expected: expected.to_string(),
            actual,
        })
    }
}

/// Decompresses a fetched index into text.
fn decompress_index(path: &str, bytes: &[u8]) -> Result<String, DebianError> {
    let mut cursor = io::Cursor::new(bytes);
    let head = super::compress::sniff_head(&mut cursor)
        .map_err(DebianError::at("reading the index", path))?;
    let mut reader =
        super::compress::decompress(&head, cursor).map_err(|_| DebianError::Index {
            reason: format!("{path} is not a valid index"),
        })?;
    let mut text = String::new();
    reader
        .read_to_string(&mut text)
        .map_err(DebianError::at("decompressing the index", path))?;
    Ok(text)
}

/// Joins path components into an absolute path for a statoverride line.
///
/// Components are lossily decoded as UTF-8. Debian policy requires package
/// paths to be UTF-8, so a conforming archive round-trips exactly; a
/// non-UTF-8 path would be mangled here, which dpkg then rejects at
/// configuration rather than mis-applying an override.
fn absolute_path(components: &[Vec<u8>]) -> String {
    let mut path = String::from("/");
    for (i, component) in components.iter().enumerate() {
        if i > 0 {
            path.push('/');
        }
        path.push_str(&String::from_utf8_lossy(component));
    }
    path
}

/// Boxes a [`DebianError`] into [`ProvisionError::Other`], the way a
/// provisioner outside the core surfaces its own failures.
fn wrap(error: DebianError) -> ProvisionError {
    ProvisionError::other(error)
}

/// A progress and cancellation sink for a Debian bootstrap.
///
/// Attached with [`Debian::observe`], and shaped like
/// [`ProvisionObserver`](crate::provision::ProvisionObserver): one method for
/// events, one for cancellation, both with default bodies, so an observer
/// implements only the half it wants and a plain
/// `FnMut(DebianEvent<'_>)` closure is an observer that reports and never
/// cancels.
///
/// Cancelling is what the trait adds over the closure: a bootstrap fetches and
/// verifies indexes, downloads a hundred packages, and runs several `dpkg`
/// waves in a cage, and a caller that wants to stop it part-way could not
/// before.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicBool, Ordering};
///
/// use ferroday_cage::provision::debian::{Debian, DebianEvent, DebianObserver};
///
/// struct Progress {
///     stop: Arc<AtomicBool>,
/// }
///
/// impl DebianObserver for Progress {
///     fn progress(&mut self, event: DebianEvent<'_>) {
///         if let DebianEvent::Downloading { package, index, total, .. } = event {
///             eprintln!("{package} ({index}/{total})");
///         }
///     }
///
///     fn cancelled(&mut self) -> bool {
///         self.stop.load(Ordering::Relaxed)
///     }
/// }
///
/// let stop = Arc::new(AtomicBool::new(false));
/// let mut debian = Debian::builder("trixie").build()?;
/// let plan = debian.observe(&mut Progress { stop: Arc::clone(&stop) }).resolve()?;
/// # let _ = plan;
/// # Ok(())
/// # }
/// ```
///
/// # Stability
///
/// Every method added to this trait in a later release will carry a default
/// body, so an existing implementation keeps compiling.
pub trait DebianObserver {
    /// Receives one progress event.
    fn progress(&mut self, event: DebianEvent<'_>) {
        let _ = event;
    }

    /// Whether the bootstrap should stop.
    ///
    /// Consulted at the points where stopping is clean — a package boundary, an
    /// extraction boundary. Returning `true` aborts with
    /// [`ProvisionError::Cancelled`],
    /// and a run driven through [`provision::ensure`](crate::provision::ensure)
    /// then removes the staging tree, so a cancelled bootstrap leaves no
    /// destination behind.
    ///
    /// The default is `false`: a bootstrap that is never cancelled.
    ///
    /// [`ProvisionError::Cancelled`]: crate::provision::ProvisionError::Cancelled
    fn cancelled(&mut self) -> bool {
        false
    }
}

/// A closure is an observer that reports and never cancels.
impl<F: FnMut(DebianEvent<'_>)> DebianObserver for F {
    fn progress(&mut self, event: DebianEvent<'_>) {
        self(event)
    }
}

/// An observer that reports nowhere and never cancels: what an entry point the
/// caller did not attach a sink to uses.
struct Silent;

impl DebianObserver for Silent {}

/// An observer that reports nowhere and takes its cancellation from the
/// provisioning run: what an unobserved [`Debian`] used as a [`Provisioner`].
///
/// The events still reach the run's own observer, wrapped in the shared
/// vocabulary — that is the one channel every provisioner reports through.
struct RunObserver<'a, 'r> {
    request: &'a ProvisionRequest<'r>,
}

impl DebianObserver for RunObserver<'_, '_> {
    fn progress(&mut self, event: DebianEvent<'_>) {
        self.request.report(ProvisionEvent::Debian(&event));
    }

    fn cancelled(&mut self) -> bool {
        self.request.cancelled()
    }
}

/// An observer that reports to a sink the caller bound with [`Debian::observe`]
/// and takes its cancellation from the provisioning run.
///
/// The caller chose the richer, Debian-specific channel for events; a
/// [`Provision::observe`](crate::provision::Provision::observe) observer can
/// still stop a bootstrap it is not reporting on.
struct ObservedRun<'a, 'r, 'o> {
    sink: &'o mut dyn DebianObserver,
    request: &'a ProvisionRequest<'r>,
}

impl DebianObserver for ObservedRun<'_, '_, '_> {
    fn progress(&mut self, event: DebianEvent<'_>) {
        self.sink.progress(event);
    }

    fn cancelled(&mut self) -> bool {
        self.request.cancelled()
    }
}

/// A progress event from a Debian bootstrap.
#[derive(Debug)]
#[non_exhaustive]
pub enum DebianEvent<'a> {
    /// A URL is about to be fetched.
    ///
    /// The event announces an intent, not a transfer in flight. Where several
    /// resources are fetched at once, every URL in a batch is announced before
    /// any of them is asked for, so the order is the order they were queued in
    /// rather than the order they arrive.
    #[non_exhaustive]
    Fetching {
        /// The URL.
        url: &'a str,
    },
    /// The dependency closure is being resolved.
    Resolving,
    /// A dependency the resolver could not satisfy: a name no configured
    /// archive carries, a name it carries only at a version the constraint
    /// rules out, or one an exclusion removed that a hard dependency needed.
    ///
    /// Reported for every such refusal before the run fails, so a caller fixing
    /// an install list sees the whole list rather than the first entry of it.
    /// The failure that follows carries the same set as one sentence.
    #[non_exhaustive]
    Unsatisfiable {
        /// What could not be supplied: the dependency group as the archive
        /// declares it, alternatives included, or the package name where the
        /// caller named one directly.
        requirement: &'a str,
        /// Who asked for it: the selected package whose dependency it was, or
        /// the install list.
        required_by: &'a str,
        /// What the wall was, as the clause following "and": that the name is
        /// absent, that it is excluded, or what is available instead of what
        /// the constraint asked for.
        reason: &'a str,
    },
    /// The dependency closure has been resolved, carrying the plan the
    /// bootstrap will install.
    ///
    /// Emitted mid-bootstrap once resolution completes and before the first
    /// download, so a consumer observes the exact, archive-verified manifest a
    /// full [`provision`](super::ensure) installs without a separate
    /// [`Debian::resolve`] pass. Every digest in the plan chains back to the
    /// release signature, the same as [`Debian::resolve`] reports.
    #[non_exhaustive]
    Resolved {
        /// The plan the bootstrap will install.
        plan: &'a Plan,
    },
    /// A package is being downloaded.
    #[non_exhaustive]
    Downloading {
        /// The package name.
        package: &'a str,
        /// Its position in the download, from 1.
        index: usize,
        /// The total number of packages.
        total: usize,
    },
    /// A package's files are being extracted.
    #[non_exhaustive]
    Extracting {
        /// The package name.
        package: &'a str,
    },
    /// Output from a dpkg wave running inside the cage.
    #[non_exhaustive]
    CommandOutput {
        /// Which standard stream the bytes came from.
        stream: Stream,
        /// The raw output bytes; not line-buffered, not guaranteed UTF-8.
        bytes: &'a [u8],
    },
}

/// An error from bootstrapping a Debian userland.
///
/// Surfaces through [`ProvisionError::Other`]; downcast to inspect it.
#[derive(Debug)]
#[non_exhaustive]
pub enum DebianError {
    /// The provisioner was misconfigured, or a host precondition (a foreign
    /// architecture's binfmt handler) is unmet.
    #[non_exhaustive]
    Config {
        /// What is wrong with the configuration.
        reason: String,
    },
    /// Fetching a resource failed.
    Fetch(FetchError),
    /// The archive signature was not accepted: it did not verify against the
    /// keyring, or the key or signature was refused on its own terms.
    #[non_exhaustive]
    Signature {
        /// Why the signature was not accepted.
        reason: String,
    },
    /// The release is malformed, expired, or does not offer what was asked.
    #[non_exhaustive]
    Release {
        /// What is wrong with the release.
        reason: String,
    },
    /// A package index is malformed or absent.
    #[non_exhaustive]
    Index {
        /// What is wrong with the index.
        reason: String,
    },
    /// A package shipped an entry whose path cannot be represented safely in
    /// the dpkg metadata derived from it.
    #[non_exhaustive]
    MalformedEntry {
        /// The offending path, lossily decoded.
        path: String,
    },
    /// The dependency closure could not be resolved.
    #[non_exhaustive]
    Resolve {
        /// Why the closure could not be resolved.
        reason: String,
    },
    /// A fetched resource did not match its recorded digest.
    #[non_exhaustive]
    HashMismatch {
        /// The resource path.
        path: String,
        /// The digest the release recorded.
        expected: String,
        /// The digest of what was fetched.
        actual: String,
    },
    /// A dpkg wave exited unsuccessfully.
    #[non_exhaustive]
    Configure {
        /// Which wave failed.
        wave: &'static str,
        /// dpkg's exit status.
        status: ExitStatus,
    },
    /// Packages were not left in the installed state after configuration.
    #[non_exhaustive]
    NotConfigured {
        /// The packages that did not reach `install ok installed`.
        packages: Vec<String>,
    },
    /// Launching a cage for a configuration wave failed.
    Launch(crate::Error),
    /// The pre-configure overlay could not be laid into the staging tree.
    Overlay(ProvisionError),
    /// A `.deb` presented to [`Pool::publish`] could not be read, or does not
    /// belong in the pool being written.
    #[non_exhaustive]
    Deb {
        /// The `.deb` file concerned.
        path: PathBuf,
        /// What was wrong with it.
        reason: String,
    },
    /// The archives could not supply what a
    /// [`pin`](DebianBuilder::pin) holds the resolution to.
    #[non_exhaustive]
    Pin {
        /// Every package the pin could not be held to, in name order, each
        /// carrying what the archives offer instead.
        unheld: Vec<UnheldPin>,
    },
    /// A [`Plan`] document could not be read, or a [`Plan`] could not be
    /// written as one.
    #[non_exhaustive]
    PlanDocument {
        /// What is wrong with the document, or with the plan that could not be
        /// rendered as one.
        reason: String,
    },
    /// A host I/O operation failed.
    #[non_exhaustive]
    Io {
        /// What the operation was doing.
        op: &'static str,
        /// The path concerned.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
}

impl DebianError {}

path_io_error! {
    DebianError,
    /// This is the form the bootstrap's host-side steps use, where the path is
    /// composed from a contained tree and the operation is known before the
    /// call that might fail.
}

impl fmt::Display for DebianError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DebianError::Config { reason } => {
                write!(f, "the Debian bootstrap is misconfigured: {reason}")
            }
            DebianError::Fetch(err) => {
                write!(f, "the Debian bootstrap could not fetch a resource: {err}")
            }
            DebianError::Signature { reason } => {
                write!(f, "the archive signature was not accepted: {reason}")
            }
            DebianError::Release { reason } => write!(f, "the release file is unusable: {reason}"),
            DebianError::Index { reason } => write!(f, "a package index is unusable: {reason}"),
            DebianError::MalformedEntry { path } => {
                write!(f, "a package entry has an unrepresentable path: {path}",)
            }
            DebianError::Resolve { reason } => write!(f, "dependency resolution failed: {reason}"),
            DebianError::HashMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "{path} did not match its recorded digest (expected {expected}, got {actual})",
            ),
            DebianError::Configure { wave, status } => {
                write!(f, "the dpkg {wave} step exited with {status}")
            }
            DebianError::NotConfigured { packages } => write!(
                f,
                "these packages were not configured: {}",
                packages.join(", "),
            ),
            DebianError::Launch(err) => write!(f, "a configuration step could not launch: {err}"),
            DebianError::Overlay(err) => {
                write!(f, "the pre-configure overlay could not be applied: {err}")
            }
            DebianError::Deb { path, reason } => {
                write!(
                    f,
                    "the .deb {} cannot be published: {reason}",
                    path.display()
                )
            }
            DebianError::Pin { unheld } => {
                let held = unheld
                    .iter()
                    .map(UnheldPin::to_string)
                    .collect::<Vec<_>>()
                    .join("; ");
                write!(f, "the archives cannot hold the pin: {held}")
            }
            DebianError::PlanDocument { reason } => {
                write!(f, "the install plan document is not usable: {reason}")
            }
            DebianError::Io { op, path, source } => {
                write!(
                    f,
                    "a Debian bootstrap step failed while {op} {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for DebianError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DebianError::Fetch(err) => Some(err),
            DebianError::Launch(err) => Some(err),
            DebianError::Overlay(err) => Some(err),
            DebianError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<FetchError> for DebianError {
    fn from(err: FetchError) -> Self {
        DebianError::Fetch(err)
    }
}

impl From<release::ReleaseError> for DebianError {
    fn from(err: release::ReleaseError) -> Self {
        match err {
            release::ReleaseError::OpenPgp(err) => DebianError::Signature {
                reason: err.to_string(),
            },
            release::ReleaseError::Release(reason) => DebianError::Release { reason },
        }
    }
}

impl From<crate::Error> for DebianError {
    fn from(err: crate::Error) -> Self {
        DebianError::Launch(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    /// A transport that refuses the first mirror with a fixed error and serves
    /// a body from any other, recording every URL it was asked for.
    struct Failing {
        primary: String,
        refusal: fn(&str) -> FetchError,
        asked: Vec<String>,
    }

    impl Fetch for Failing {
        fn fetch(
            &mut self,
            request: &FetchRequest<'_>,
            sink: &mut dyn std::io::Write,
        ) -> Result<(), FetchError> {
            self.asked.push(request.url().to_string());
            if request.url().starts_with(&self.primary) {
                return Err((self.refusal)(request.url()));
            }
            sink.write_all(b"from the backstop")
                .map_err(|err| FetchError::io("writing the body", request.url(), err))
        }
    }

    /// A transport that serves one fixed body to whatever it is asked for.
    struct Canned(&'static [u8]);

    impl Fetch for Canned {
        fn fetch(
            &mut self,
            request: &FetchRequest<'_>,
            sink: &mut dyn std::io::Write,
        ) -> Result<(), FetchError> {
            sink.write_all(self.0)
                .map_err(|err| FetchError::io("writing the body", request.url(), err))
        }
    }

    /// A transport that answers each URL from a table, counting every call.
    ///
    /// The count is what the acquisition tests are about: whether a package the
    /// batch delivered is asked for a second time by the walk behind it.
    struct Table {
        bodies: std::collections::HashMap<String, Vec<u8>>,
        asked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl Fetch for Table {
        fn fetch(
            &mut self,
            request: &FetchRequest<'_>,
            sink: &mut dyn std::io::Write,
        ) -> Result<(), FetchError> {
            self.asked
                .lock()
                .expect("the record is not poisoned")
                .push(request.url().to_string());
            match self.bodies.get(request.url()) {
                Some(body) => sink
                    .write_all(body)
                    .map_err(|err| FetchError::io("writing the body", request.url(), err)),
                None => Err(FetchError::not_found(request.url())),
            }
        }
    }

    /// One package to acquire, and what the mirror will answer for it.
    fn wanted(name: &str, body: &[u8]) -> Wanted {
        Wanted {
            name: name.to_string(),
            sha256: Algorithm::Sha256.hex_of(body),
            filename: format!("pool/{name}.deb"),
            size: Some(body.len() as u64),
            origin: 0,
        }
    }

    /// Acquires `packages` against a transport answering `bodies`, and reports
    /// every URL it was asked for.
    fn acquire(
        packages: &[Wanted],
        bodies: &[(String, Vec<u8>)],
        archives: &Path,
    ) -> (Result<Vec<Installable>, ProvisionError>, Vec<String>) {
        let repositories = vec![
            Repository::builder("trixie")
                // Acquisition takes a repository only for its mirror list, and
                // never reads its release; the scheme is what lets the builder
                // accept an unsigned one.
                .mirror("https://mirror.example/debian")
                .trust_unsigned(true)
                .build()
                .expect("the repository builds"),
        ];
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut fetcher = Table {
            bodies: bodies.iter().cloned().collect(),
            asked: std::sync::Arc::clone(&asked),
        };
        let outcome = acquire_debs(&mut fetcher, &repositories, packages, archives, &mut Silent);
        let urls = asked.lock().expect("the record is not poisoned").clone();
        (outcome, urls)
    }

    #[test]
    fn a_package_the_batch_delivered_is_not_asked_for_again() {
        // The batch is an optimization over the walk, not a replacement for it,
        // so the two must not both fetch the same package: the walk asks only
        // for what is not in the cache when it runs.
        let scratch = Scratch::new("acquire-batched");
        let one = b"the first package".to_vec();
        let two = b"the second package".to_vec();
        let packages = vec![wanted("one", &one), wanted("two", &two)];
        let bodies = vec![
            (
                "https://mirror.example/debian/pool/one.deb".to_string(),
                one,
            ),
            (
                "https://mirror.example/debian/pool/two.deb".to_string(),
                two,
            ),
        ];

        let (installables, asked) = acquire(&packages, &bodies, scratch.as_ref());
        let installables = installables.expect("both packages arrive");
        assert_eq!(installables.len(), 2);
        assert_eq!(asked.len(), 2, "each package was fetched once: {asked:?}");
        for package in &packages {
            assert!(
                scratch.join(format!("{}.deb", package.sha256)).is_file(),
                "{} should be in the cache",
                package.name,
            );
        }
    }

    #[test]
    fn a_package_the_batch_could_not_deliver_falls_to_the_walk() {
        // Nothing about the batch decides that a package is present. A job that
        // does not arrive leaves the cache without it, and the walk behind --
        // which has every mirror rather than the first -- fetches it as though
        // the batch had not run.
        let scratch = Scratch::new("acquire-batch-miss");
        let one = b"the first package".to_vec();
        let two = b"the second package".to_vec();
        let packages = vec![wanted("one", &one), wanted("two", &two)];
        // The transport answers `one` and knows nothing of `two`, so the batch
        // delivers one of the two and the walk asks again for the other.
        let bodies = vec![(
            "https://mirror.example/debian/pool/one.deb".to_string(),
            one.clone(),
        )];

        let (outcome, asked) = acquire(&packages, &bodies, scratch.as_ref());
        assert!(outcome.is_err(), "no mirror serves the second package");
        assert_eq!(
            asked.iter().filter(|url| url.ends_with("/two.deb")).count(),
            2,
            "the batch asked once and the walk asked again: {asked:?}",
        );
        assert!(
            scratch
                .join(format!("{}.deb", packages[0].sha256))
                .is_file()
        );
    }

    #[test]
    fn bytes_the_batch_could_not_verify_are_not_published() {
        // The rename is what decides a package is in the cache, and it happens
        // only over bytes whose digest matched. A mirror that serves the wrong
        // body through the batch therefore leaves nothing behind, and the walk
        // refuses it for the same reason.
        let scratch = Scratch::new("acquire-batch-wrong");
        let package = wanted("one", b"the package the index named");
        let bodies = vec![(
            "https://mirror.example/debian/pool/one.deb".to_string(),
            b"something else entirely".to_vec(),
        )];

        let (outcome, asked) = acquire(std::slice::from_ref(&package), &bodies, scratch.as_ref());
        assert!(outcome.is_err(), "the bytes are not the package");
        assert!(
            !scratch.join(format!("{}.deb", package.sha256)).is_file(),
            "nothing unverified reaches the cache",
        );
        // Nothing is left staged either.
        let leftovers: Vec<_> = std::fs::read_dir(scratch.as_ref())
            .expect("the cache directory is readable")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
        assert_eq!(asked.len(), 2, "the batch asked, then the walk did");
    }

    #[test]
    fn a_verified_release_reports_the_mirror_the_digest_and_the_signing_key() {
        // The three facts a plan's archive record carries that the release body
        // does not itself state, checked against a real Debian release signed by
        // the embedded keyring. The hermetic repository fixtures are unsigned,
        // so this is where the signed branch's wiring is proven.
        const INRELEASE: &[u8] =
            include_bytes!("../../../tests/fixtures/debian-archive/forky-InRelease");
        // The repository builder takes a keyring by path, so the embedded one
        // goes to a file the test owns.
        let scratch = Scratch::new("release-provenance");
        let keyring_path = scratch.join("archive-keyring.gpg");
        std::fs::write(&keyring_path, EMBEDDED_KEYRING).expect("the keyring is writable");

        let repository = Repository::builder("forky")
            .mirror("https://deb.example/debian")
            .keyring(&keyring_path)
            // The fixture is a real release with a real expiry, long past.
            .allow_stale_release(true)
            .build()
            .expect("the repository validates");

        let (release, served) = fetch_release(&mut Canned(INRELEASE), &repository, &mut Silent)
            .expect("the embedded keyring verifies a real Debian release");

        assert_eq!(served.mirror, "https://deb.example/debian");
        assert_eq!(served.signed_by.len(), 1, "{:?}", served.signed_by);
        assert_eq!(served.signed_by[0].len(), 40, "{:?}", served.signed_by);

        // The digest is over the bytes the signature covered, which is not the
        // InRelease the transport delivered: the armor and the signature are
        // around what was verified rather than part of it.
        let (message, _) = pgp::composed::CleartextSignedMessage::from_armor(INRELEASE)
            .expect("the fixture is a cleartext-signed document");
        assert_eq!(
            release.sha256(),
            Algorithm::Sha256.hex_of(message.signed_text().as_bytes()),
        );
        assert_ne!(release.sha256(), Algorithm::Sha256.hex_of(INRELEASE));

        // And it is a property of those bytes rather than of the fetch, so a
        // second pass over the same release records the same digest.
        let (again, _) = fetch_release(&mut Canned(INRELEASE), &repository, &mut Silent)
            .expect("the same release verifies again");
        assert_eq!(release.sha256(), again.sha256());

        assert_eq!(release.date(), Some("Tue, 21 Jul 2026 14:11:47 UTC"));
        assert_eq!(release.valid_until(), Some("Tue, 28 Jul 2026 14:11:47 UTC"));
    }

    /// What a mirror walk produced: the body, and the mirror that served it.
    type Walked = Result<(Vec<u8>, String), DebianError>;

    /// Walks a two-mirror list whose primary answers with `refusal`, returning
    /// the outcome and the URLs the walk asked for.
    fn walk_past(refusal: fn(&str) -> FetchError) -> (Walked, Vec<String>) {
        let mut fetcher = Failing {
            primary: "https://primary.example".to_string(),
            refusal,
            asked: Vec::new(),
        };
        let mirrors = [
            "https://primary.example/debian".to_string(),
            "https://snapshot.example/debian".to_string(),
        ];
        let result =
            fetch_from_mirrors(&mut fetcher, &mirrors, "dists/stable/Release", &mut Silent);
        (result, fetcher.asked)
    }

    #[test]
    fn the_mirror_walk_advances_past_a_failing_mirror() {
        // Every way a mirror can decline to serve is a reason to try the next
        // one: the backstop exists for precisely the outage a 5xx reports, and
        // a CDN answers an absent object with 403 as readily as with 404.
        for refusal in [
            |url: &str| FetchError::not_found(url),
            |url: &str| FetchError::status(url, 503),
            |url: &str| FetchError::status(url, 403),
            |url: &str| {
                FetchError::io(
                    "connecting",
                    url,
                    std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
                )
            },
        ] {
            let (result, asked) = walk_past(refusal);
            let (bytes, mirror) = result.expect("the backstop answers");
            assert_eq!(bytes, b"from the backstop", "{asked:?}");
            // And the walk reports the mirror that served, not the one that was
            // asked first: a plan resolved this way records which mirror
            // answered, which is the provenance a reader of the plan wants and
            // not a decision about where the packages are later fetched from.
            assert_eq!(mirror, "https://snapshot.example/debian", "{asked:?}");
            assert_eq!(asked.len(), 2, "both mirrors were tried: {asked:?}");
        }
    }

    #[test]
    fn the_mirror_walk_stops_at_a_malformed_url() {
        // A URL the transport cannot parse is the caller's configuration, not
        // the mirror's state; trying the next mirror would bury the mistake.
        let (result, asked) = walk_past(|url| FetchError::url(url, "unsupported scheme"));
        assert!(
            matches!(result, Err(DebianError::Fetch(FetchError::Url { .. }))),
            "{asked:?}",
        );
        assert_eq!(asked.len(), 1, "the walk stopped at the first mirror");
        // And it is reported against the mirror that carries the bad URL rather
        // than against the backstop, which is the whole reason a `Url` failure
        // does not advance the walk.
        let reason = result.unwrap_err().to_string();
        assert!(reason.contains("primary.example"), "{reason}");
        assert!(!reason.contains("snapshot.example"), "{reason}");
    }

    #[test]
    fn an_exhausted_walk_is_reported_against_the_mirror_it_asked_last() {
        // The other attribution: with every mirror declining, the answer names
        // the one the walk ended on. Keeping the last failure is what makes the
        // diagnostic survive a walk, and reporting the first would point at a
        // mirror that may be perfectly healthy.
        let mut fetcher = Failing {
            // Every mirror below starts with this, so all of them refuse.
            primary: "https://".to_string(),
            refusal: |url: &str| FetchError::status(url, 503),
            asked: Vec::new(),
        };
        let mirrors = [
            "https://first.example/debian".to_string(),
            "https://last.example/debian".to_string(),
        ];
        let result =
            fetch_from_mirrors(&mut fetcher, &mirrors, "dists/stable/Release", &mut Silent);
        assert_eq!(fetcher.asked.len(), 2, "{:?}", fetcher.asked);
        let reason = result.unwrap_err().to_string();
        assert!(reason.contains("last.example"), "{reason}");
        assert!(!reason.contains("first.example"), "{reason}");
    }

    #[test]
    fn the_embedded_keyring_parses() {
        // The vendored keyring must be a valid binary OpenPGP keyring that
        // rPGP can read; parsing succeeds only with at least one usable
        // (unrevoked) key.
        Keyring::parse(EMBEDDED_KEYRING).expect("the embedded keyring parses");
    }

    #[test]
    fn unsigned_input_does_not_verify() {
        // A release body with no cleartext signature is refused, not accepted
        // as if unsigned content were trusted.
        let keyring = Keyring::parse(EMBEDDED_KEYRING).unwrap();
        assert!(
            keyring
                .verify(b"Suite: trixie\nComponents: main\n", true)
                .is_err()
        );
    }

    #[test]
    fn the_builder_requires_a_suite() {
        // A whitespace-only suite is rejected. `Debian` is not `Debug`
        // (it holds trait objects), so this matches rather than unwraps.
        assert!(matches!(
            Debian::builder("  ").build(),
            Err(DebianError::Config { .. })
        ));
    }

    #[test]
    fn the_builder_defaults_are_applied() {
        let debian = Debian::builder("trixie").build().unwrap();
        // A single-mirror bootstrap has exactly the primary repository, carrying
        // the default mirror, components, suite, and a signed trust anchor.
        assert_eq!(debian.repositories.len(), 1);
        let primary = &debian.repositories[0];
        assert_eq!(primary.mirrors, [DEFAULT_MIRROR]);
        assert_eq!(primary.components, ["main"]);
        assert_eq!(primary.suite, "trixie");
        assert!(!primary.trust_unsigned());
        assert!(!debian.architecture.is_empty());
    }

    #[test]
    fn the_builder_carries_the_base_priority_and_excludes() {
        // The base priority defaults to required and the exclude list to empty;
        // both builder methods carry their values through to the provisioner.
        let default = Debian::builder("trixie").build().unwrap();
        assert_eq!(default.base_priority, Priority::Required);
        assert!(default.excludes.is_empty());

        let configured = Debian::builder("trixie")
            .base_priority(Priority::Important)
            .exclude(["isc-dhcp-client", "dhcpcd-base"])
            .build()
            .unwrap();
        assert_eq!(configured.base_priority, Priority::Important);
        assert_eq!(configured.excludes, ["isc-dhcp-client", "dhcpcd-base"]);
    }

    #[test]
    fn an_unsigned_http_primary_is_refused() {
        // The primary repository enforces the same unsigned-over-http refusal
        // the flattened configuration did.
        assert!(matches!(
            Debian::builder("trixie")
                .mirror("http://deb.debian.org/debian")
                .trust_unsigned(true)
                .build(),
            Err(DebianError::Config { .. })
        ));
    }

    #[test]
    fn an_additional_repository_follows_the_primary() {
        let extra = Repository::builder("trixie")
            .mirror("file:///srv/local-debs")
            .trust_unsigned(true)
            .name("local")
            .build()
            .expect("the repository validates");
        let debian = Debian::builder("trixie")
            .repository(extra)
            .build()
            .expect("the builder validates");
        assert_eq!(debian.repositories.len(), 2);
        // The primary is element zero; the additional repository follows.
        assert_eq!(debian.repositories[0].mirrors, [DEFAULT_MIRROR]);
        assert_eq!(debian.repositories[1].name.as_deref(), Some("local"));
    }

    #[test]
    fn components_join_with_a_paragraph_break_between_them() {
        // An index ends with the last field of its last stanza, not with a
        // blank line, so joining two components end to end would fold the
        // second's first stanza into the first's last one. Nothing downstream
        // would report it: each component verifies against the release on its
        // own, and only the concatenation is wrong, so the packages that stanza
        // named simply stop existing.
        let mut merged = String::new();
        append_component(&mut merged, "Package: a\nVersion: 1\n");
        append_component(&mut merged, "Package: b\nVersion: 2\n");
        assert_eq!(merged, "Package: a\nVersion: 1\n\nPackage: b\nVersion: 2\n");
        let stanzas = crate::provision::document::parse(&merged);
        let names: Vec<_> = stanzas
            .iter()
            .filter_map(|stanza| stanza.get("Package"))
            .collect();
        assert_eq!(names, ["a", "b"], "a component's stanza was absorbed");

        // The join is the same however a component's own file terminates, so a
        // producer that does end its index with a blank line -- or with several
        // -- does not open a gap in the merged text.
        let mut spaced = String::new();
        append_component(&mut spaced, "Package: a\nVersion: 1\n\n\n");
        append_component(&mut spaced, "Package: b\nVersion: 2");
        assert_eq!(spaced, merged);

        // An empty component contributes nothing, and does not leave a stray
        // paragraph break behind: a pool declared before the build that fills
        // it is published empty, and is a component like any other.
        let mut with_empty = String::new();
        append_component(&mut with_empty, "");
        append_component(&mut with_empty, "Package: a\nVersion: 1\n");
        append_component(&mut with_empty, "   \n");
        assert_eq!(with_empty, "Package: a\nVersion: 1\n");
    }

    /// An uncompressed tar of `(path, mode, uid, gid)` entries: the shape of a
    /// `.deb`'s `data.tar`. A path ending in `/` is a directory, which is how
    /// the oldest writers marked one and how the parser reads it — so the
    /// entries are written as regular files and the trailing slash is what the
    /// reader keys on.
    fn data_tar(entries: &[(&str, u32, u32, u32)]) -> Vec<u8> {
        let mut tar = ferroday_cage_testkit::tar::Tar::new();
        for (path, mode, uid, gid) in entries {
            tar.file_owned(path, *mode, *uid, *gid, b"");
        }
        tar.finish()
    }

    /// A `.deb` around a `data.tar`, with the `debian-binary` member that
    /// precedes it. No control member: extraction never reads one.
    fn deb_of(data: &[u8]) -> Vec<u8> {
        ferroday_cage_testkit::deb::ar(&[("debian-binary", b"2.0\n"), ("data.tar", data)])
    }

    /// Writes each `.deb` into `archives` under its digest, as the download
    /// does, and returns the install set naming them.
    fn installables(archives: &Path, debs: &[(&str, Vec<u8>)]) -> Vec<Installable> {
        std::fs::create_dir_all(archives).expect("the archive directory is creatable");
        debs.iter()
            .map(|(name, bytes)| {
                let sha256 = Algorithm::Sha256.hex_of(bytes);
                std::fs::write(archives.join(format!("{sha256}.deb")), bytes)
                    .expect("the package is writable");
                Installable {
                    name: (*name).to_string(),
                    deb_path: format!("{}/{sha256}.deb", bootstrap::ARCHIVES),
                    sha256,
                }
            })
            .collect()
    }

    #[test]
    fn two_packages_shipping_one_owned_path_derive_one_statoverride_record() {
        // dpkg treats two records for one path as an unrecoverable fatal error,
        // and a closure reaches that honestly: the resolver reads no Conflicts,
        // so two packages that a real archive expects never to be unpacked
        // together can both be selected, and tar permits one data.tar to list a
        // path twice besides. Both shapes are here, and both have to collapse.
        let dir = Scratch::new("statoverride-duplicate");
        let archives = dir.join("archives");
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).expect("the staging tree is creatable");

        let first = deb_of(&data_tar(&[("./usr/sbin/helper", 0o2755, 0, 42)]));
        let second = deb_of(&data_tar(&[
            // The same path a second package already shipped, at another mode.
            ("./usr/sbin/helper", 0o4755, 0, 42),
            // And a path this one lists twice within its own data member.
            ("./usr/bin/tool", 0o2755, 0, 42),
            ("./usr/bin/tool", 0o755, 0, 42),
        ]));
        let install = installables(&archives, &[("first", first), ("second", second)]);

        let overrides = extract_packages(&staging, "amd64", &install, &archives, &mut Silent)
            .expect("both packages extract");

        // One record per path, each carrying the mode of the file that survived
        // — the last entry to describe it, which is the extraction's own rule.
        assert_eq!(
            overrides.render(),
            "root root 755 /usr/bin/tool\nroot root 4755 /usr/sbin/helper\n",
        );
    }

    #[test]
    fn the_rootfs_root_takes_the_bootstrap_s_mode_and_not_a_package_s() {
        // Every `.deb` ships a `./` entry, so a tree assembled from several
        // would otherwise take the mode of whichever was extracted last — an
        // arbitrary choice among packages that describe their own contents and
        // say nothing about the tree being assembled from them. A package
        // shipping `./` as 0700 would leave a rootfs the caller has to chmod
        // before anything can traverse it.
        use std::os::unix::fs::PermissionsExt;

        let dir = Scratch::new("rootfs-root-mode");
        let archives = dir.join("archives");
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).expect("the staging tree is creatable");

        let closed = deb_of(&data_tar(&[
            ("./", 0o700, 0, 0),
            ("./usr/bin/x", 0o755, 0, 0),
        ]));
        let install = installables(&archives, &[("closed", closed)]);
        extract_packages(&staging, "amd64", &install, &archives, &mut Silent)
            .expect("the package extracts");

        let mode = std::fs::metadata(&staging).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, ROOTFS_ROOT_MODE, "the package chose the root's mode");
    }

    /// The names a directory holds, sorted.
    fn entries_of(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("the directory is readable")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_download_publishes_only_what_matches_the_recorded_digest() {
        // The bytes are written to a staging file as they arrive and digested on
        // the way through, so nothing is held in memory and nothing unverified
        // is ever visible at the destination: the rename is what puts it there.
        let dir = Scratch::new("download-verified");
        let dest = dir.join("package.deb");

        let err = fetch_verified(
            &mut Canned(b"not what the archive recorded"),
            "file:///ignored-by-the-canned-transport",
            &Algorithm::Sha256.hex_of(b"the recorded bytes"),
            None,
            &dest,
        )
        .expect_err("a mismatched download is refused");
        assert!(matches!(err, DebianError::HashMismatch { .. }), "{err}");
        assert!(!dest.exists(), "unverified bytes were published");
        assert!(
            entries_of(&dir).is_empty(),
            "a failed download left its staging file behind: {:?}",
            entries_of(&dir),
        );

        fetch_verified(
            &mut Canned(b"the recorded bytes"),
            "file:///ignored-by-the-canned-transport",
            &Algorithm::Sha256.hex_of(b"the recorded bytes"),
            Some(b"the recorded bytes".len() as u64),
            &dest,
        )
        .expect("a matching download publishes");
        assert_eq!(std::fs::read(&dest).unwrap(), b"the recorded bytes");
        assert_eq!(entries_of(&dir), ["package.deb"]);
    }

    #[test]
    fn a_download_stops_at_the_size_the_index_recorded() {
        // The index records what the package weighs, so a mirror answering with
        // more is answering with something else. A transport of the caller's is
        // free to ignore the size the request declares, so the bound is applied
        // at the sink too — which is the one place it cannot be ignored — and
        // the disk it would have filled is never written.
        let dir = Scratch::new("download-capped");
        let dest = dir.join("package.deb");

        let err = fetch_verified(
            &mut Canned(&[b'x'; 4096]),
            "file:///ignored-by-the-canned-transport",
            &Algorithm::Sha256.hex_of(&[b'x'; 4096]),
            Some(16),
            &dest,
        )
        .expect_err("a body over the recorded size is refused");
        assert!(
            matches!(err, DebianError::Fetch(FetchError::Io { .. })),
            "{err}"
        );
        assert!(!dest.exists(), "an oversized download was published");
        assert!(
            entries_of(&dir).is_empty(),
            "a refused download left its staging file behind: {:?}",
            entries_of(&dir),
        );
    }
}
