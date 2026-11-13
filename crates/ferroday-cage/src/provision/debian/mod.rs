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
//! rootfs before the configure wave runs, and [`Pool`] writes a local
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
mod bootstrap;
mod deb;
mod digests;
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
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use arch::{Interpreter, foreign_interpreter, host_architecture};
pub use index::{ParsePriorityError, Priority, build_depend_names};
pub use pin::{UnheldPin, UnheldReason};
pub use plan::{Plan, PlannedPackage, ResolvedArchive};
pub use pool::Pool;
pub use repository::{Repository, RepositoryBuilder};

use super::cache;
use super::coordinate::{self, Nesting};
use super::document::Carried;
use super::extract::{Extraction, Placement};
use super::identity::Ownership;
use super::layer::Staging;
use super::rooted::Rooted;
use super::{
    Available, BuildLayer, Delegate, Failover, Fetch, FetchError, FetchRequest, HttpFetch,
    LimitedWriter, PackageCache, ProvisionError, ProvisionEvent, ProvisionRequest, Provisioner,
    Staged, Stream, mirror_url, walk_mirrors,
};
use crate::failure::path_io_error;
use crate::provision::digest::{Algorithm, Digest};
use crate::status::ExitStatus;
use crate::{ErrorChain, IdMapper, IdentityMap};
use bootstrap::{Installable, StatOverride};
use digests::Digests;
use index::{Index, Package};
use pin::Pins;

/// The suffix a run-owned `.deb` cache takes on the tree it is building.
const DEB_CACHE: &str = ".fcage-debs";
use crate::provision::openpgp::{Keyring, MAX_SIGNED_DOCUMENT_BYTES};
use release::{Release, ReleasePriority};

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
pub struct Debian {
    suite: String,
    architecture: String,
    base_priority: Priority,
    includes: Vec<String>,
    excludes: Vec<String>,
    extract_only: bool,
    identity_map: IdentityMap,
    cache_dir: Option<PathBuf>,
    overlay: Option<PathBuf>,
    /// The `SOURCE_DATE_EPOCH` every maintainer script is given, set by
    /// [`DebianBuilder::source_date_epoch`]. `None` gives them none.
    source_date_epoch: Option<i64>,
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
    fetcher: Box<dyn Fetch>,
    /// The caller's identity-map delegate, set by [`DebianBuilder::id_mapper`];
    /// `None` resolves a range map through the bundled chain.
    id_mapper: Option<Arc<dyn IdMapper>>,
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
    /// The delegate a range map is established through, where the caller
    /// supplied one.
    id_mapper: Option<&'a Arc<dyn IdMapper>>,
    /// The caller's package cache, or `None` for one beside the staging tree.
    cache_dir: Option<&'a Path>,
    /// A tree laid over the staging root between the unpack and configure
    /// waves.
    overlay: Option<&'a Path>,
    /// The `SOURCE_DATE_EPOCH` the maintainer scripts are given.
    source_date_epoch: Option<i64>,
}

impl Debian {
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
            id_mapper,
            cache_dir,
            overlay,
            source_date_epoch,
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
                id_mapper: id_mapper.as_ref(),
                cache_dir: cache_dir.as_deref(),
                overlay: overlay.as_deref(),
                source_date_epoch: *source_date_epoch,
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

/// Refuses an install list entry naming a release no repository publishes,
/// and an exclusion naming a release at all.
///
/// An entry written `name/release` asks for the name from the repository
/// configured with that suite, so a release none is configured with is a
/// mistake the configuration already shows, refused before anything is
/// fetched. An exclusion removes a name from the closure whichever release
/// would have supplied it, so a release in one would be read as part of a name
/// no package has, and would quietly exclude nothing.
fn validate_selection(
    includes: &[String],
    excludes: &[String],
    repositories: &[Repository],
) -> Result<(), DebianError> {
    for entry in includes {
        let (name, release) = resolve::split_release(entry);
        let Some(release) = release else {
            continue;
        };
        if name.is_empty()
            || !repositories
                .iter()
                .any(|repository| repository.suite == release)
        {
            return Err(DebianError::Config {
                reason: format!(
                    "the include {entry:?} asks for a package from the release {release:?}, and \
                     no configured repository publishes that suite"
                ),
            });
        }
    }
    if let Some(entry) = excludes.iter().find(|entry| entry.contains('/')) {
        return Err(DebianError::Config {
            reason: format!(
                "the exclude {entry:?} names a release, and an exclusion removes a package \
                 whichever release would supply it; name the package alone"
            ),
        });
    }
    Ok(())
}

/// Refuses a plan handed to `plan()` that contradicts the rest of the
/// configuration.
///
/// A plan describes a resolution that already happened, so a setting shaping a
/// resolution is a contradiction rather than a refinement, and picking a silent
/// precedence between the two would produce a rootfs matching neither.
///
/// A refusal quotes the suite and the architecture the plan states with `{:?}`:
/// a document is a file the caller may have taken from elsewhere, and nothing
/// holds its header to an alphabet. The configured suite and architecture have
/// passed [`coordinate::check`], and are named bare. [`validate_pin`] quotes a
/// pin's the same way.
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
            "the plan resolves suite {:?} but the bootstrap is configured for {suite}",
            plan.suite,
        ));
    }
    if plan.architecture != architecture {
        return contradiction(format!(
            "the plan resolves architecture {:?} but the bootstrap is configured for \
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
        // A document is held to this as it is read; a `Plan` is public and
        // `Clone`, so one taken from `resolve()` and edited reaches here having
        // passed nothing. First, because it is what admits the name the
        // refusal below names.
        if let Some(reason) = package.unaddressable() {
            return contradiction(reason);
        }
        if package.archive >= repositories {
            return contradiction(format!(
                "the plan's package {} names archive {} but only {repositories} repositories \
                 are configured, so it names no mirror",
                package.name, package.archive,
            ));
        }
    }
    // Installed twice, a package's files would be extracted twice, the later
    // version's over the earlier's, into a root whose database records one
    // package of each name.
    if let Some((first, again)) = plan.named_twice() {
        return contradiction(format!(
            "the plan names the package {} twice, at {} and at {}, and a root holds one package \
             of each name",
            again.name, first.version, again.version,
        ));
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
/// entries a plan document's reader would refuse.
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
            "the pin resolves suite {:?} but the bootstrap is configured for {suite}",
            pin.suite,
        ));
    }
    if pin.architecture != architecture {
        return contradiction(format!(
            "the pin resolves architecture {:?} but the bootstrap is configured for \
             {architecture}",
            pin.architecture,
        ));
    }
    // A pin is a plan document, read by the same reader, and an entry it would
    // refuse is worth refusing here too. Its digest needs no check: a `Digest`
    // is held to its algorithm's shape when it is made, so one spelled any other
    // way, which could only ever mismatch, never reaches a pin.
    for package in &pin.packages {
        if let Some(reason) = package.unaddressable() {
            return contradiction(reason);
        }
    }
    Ok(())
}

impl fmt::Debug for Debian {
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
            .field("source_date_epoch", &self.source_date_epoch)
            .field("base_layer", &self.base_layer)
            .field("repositories", &self.repositories)
            .field("fetcher", &Delegate("dyn Fetch"))
            .field(
                "id_mapper",
                &self.id_mapper.as_ref().map(|_| Delegate("dyn IdMapper")),
            )
            .finish()
    }
}

impl Debian {
    /// Returns a builder for a bootstrap of `suite` (for example `trixie`).
    pub fn builder(suite: impl Into<String>) -> DebianBuilder {
        DebianBuilder {
            suite: suite.into(),
            architecture: None,
            mirror: None,
            mirror_fallbacks: Vec::new(),
            snapshot_fallbacks: Vec::new(),
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
            source_date_epoch: None,
            base_layer: None,
            keyring_path: None,
            trust_unsigned: false,
            allow_stale: false,
            repositories: Vec::new(),
            fetcher: None,
            id_mapper: None,
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
    /// pass rather than four. Where the [`pin`](DebianBuilder::pin) is among
    /// what it refused, the failure is [`DebianError::Pin`], naming every
    /// package the pin could not be held to.
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
    /// A base package the increment upgrades is replaced, along with every name
    /// the replaced version supplied, and the plan is held to every hard
    /// dependency of the root it produces: those of the packages it installs,
    /// and those of the packages the base keeps. A package the base keeps
    /// whose dependency an upgrade breaks is upgraded with it where apt would
    /// upgrade it. What is still unmet is refused, reported as a
    /// [`DebianEvent::Unsatisfiable`] like any other refusal, since a layer
    /// removes nothing from its base.
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
    /// A call that fails and created `upper` leaves nothing behind: the upper
    /// and its work directory are disposed of exactly as dropping the returned
    /// layer would dispose of them, since a failure hands the caller no handle
    /// to drop. An `upper` that already existed is the caller's, and a failure
    /// leaves it in place, holding whatever the call wrote into it. The package
    /// cache goes with the call either way, unless the builder named a
    /// [`cache_dir`](DebianBuilder::cache_dir), which is the caller's and
    /// survives.
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
        crate::provision::layer::network_filter_preflight()
            .map_err(|reason| wrap(DebianError::Config { reason }))?;
        crate::idmap::establishable(&self.identity_map, self.id_mapper.as_ref()).map_err(
            |refusal| {
                wrap(DebianError::Config {
                    reason: ErrorChain::new(&refusal).to_string(),
                })
            },
        )?;

        // The base's configured set seeds the resolver, and reading it refuses a
        // base that is not a configured bootstrap.
        let assume_installed = layer::read_installed_set(&base).map_err(wrap)?;

        // Create the upper and refuse a host that cannot establish an
        // unprivileged overlay on its filesystem, before any download — the
        // overlay preflight the primitive would make at cage-build time, hoisted
        // ahead of the work. The probe runs on the upper's parent, its own
        // filesystem, so its scratch files land beside the upper.
        // The guard is taken as the upper is created, not on the way out, so a
        // failure below disposes of a partly-installed increment instead of
        // orphaning it: there is no handle in an `Err` for the caller to drop.
        // It disposes only of an upper this call created; one that was already
        // there is the caller's.
        let staging = Staging::begin(upper, self.identity_map.clone(), self.id_mapper.clone())?;
        let scratch = crate::path::parent_of(upper);
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
        // plan that names none — needs no download and no dpkg wave, which
        // also keeps dpkg from being handed an empty unpack, which it refuses.
        // The pre-configure overlay is still the caller's configuration of the
        // build root, and is laid exactly where a wave would have found it:
        // whether the packages asked for were already in the base is no reason
        // for the root to differ.
        if wanted.is_empty() {
            if let Some(source) = config.overlay {
                let ownership = Ownership::new(config.identity_map, config.id_mapper);
                super::extract::overlay_tree(upper, source, Some((&base, &ownership)))
                    .map_err(|err| wrap(DebianError::Overlay(err)))?;
            }
            return Ok(staging.finish());
        }
        let installables = acquire_debs(
            fetcher,
            config.repositories,
            &wanted,
            archives.path(),
            observer,
        )?;
        let private = private_copy(upper, config.cache_dir, &installables)?;
        let installing = private.as_ref().unwrap_or(&archives).path();
        let statoverride = extract_packages(
            upper,
            Some((&base, Ownership::new(config.identity_map, config.id_mapper))),
            config.architecture,
            &installables,
            installing,
            observer,
        )?;

        let env = maintainer_env(config.source_date_epoch);
        let wave = bootstrap::Configure {
            archives_host: installing,
            installables: &installables,
            statoverride: &statoverride,
            identity_map: config.identity_map,
            id_mapper: config.id_mapper,
            env: &env,
            source_date_epoch: config.source_date_epoch,
        };
        bootstrap::configure_delta(&base, upper, &wave, config.overlay, observer).map_err(wrap)?;

        // The read-only archives bind left an empty mount point in the upper.
        // Removed as the empty directory it is: anything else at the name is
        // not the launch's to take.
        let _ = std::fs::remove_dir(upper.join(bootstrap::ARCHIVES.trim_start_matches('/')));

        Ok(staging.finish())
    }
}

/// Builder for a [`Debian`] provisioner.
pub struct DebianBuilder {
    suite: String,
    architecture: Option<String>,
    mirror: Option<String>,
    mirror_fallbacks: Vec<String>,
    /// The backstops among `mirror_fallbacks` that serve a past state of the
    /// archive.
    snapshot_fallbacks: Vec<String>,
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
    source_date_epoch: Option<i64>,
    base_layer: Option<PathBuf>,
    keyring_path: Option<PathBuf>,
    trust_unsigned: bool,
    allow_stale: bool,
    repositories: Vec<Repository>,
    fetcher: Option<Box<dyn Fetch>>,
    id_mapper: Option<Arc<dyn IdMapper>>,
}

impl fmt::Debug for DebianBuilder {
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
            .field("snapshot_fallbacks", &self.snapshot_fallbacks)
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
            .field("source_date_epoch", &self.source_date_epoch)
            .field("base_layer", &self.base_layer)
            .field("keyring_path", &self.keyring_path)
            .field("trust_unsigned", &self.trust_unsigned)
            .field("allow_stale", &self.allow_stale)
            .field("repositories", &self.repositories)
            .field(
                "fetcher",
                &self.fetcher.as_ref().map(|_| Delegate("dyn Fetch")),
            )
            .field(
                "id_mapper",
                &self.id_mapper.as_ref().map(|_| Delegate("dyn IdMapper")),
            )
            .finish()
    }
}

impl DebianBuilder {
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
    /// A backstop serves the same suite through a second URL, and its release
    /// is held to the freshness the primary's is. One serving a past state of
    /// the archive, such as a `snapshot.debian.org` timestamp, is added with
    /// [`snapshot_fallback`](Self::snapshot_fallback) instead. A backstop is a
    /// fetch-time concern only: the finished rootfs's `sources.list` names the
    /// primary mirror, not the backstop.
    ///
    /// A backstop is fetched through the same transport as the primary, so the
    /// scheme constraint of [`mirror`](Self::mirror) applies to it too.
    pub fn mirror_fallback(mut self, url: impl Into<String>) -> Self {
        self.mirror_fallbacks.push(url.into());
        self
    }

    /// Adds a backstop URL for the primary mirror that serves a past state of
    /// the archive, tried in order with the
    /// [`mirror_fallback`](Self::mirror_fallback) backstops.
    ///
    /// This expresses a live primary mirror with a `snapshot.debian.org`
    /// fallback for a version that has rotated off the live pool. A snapshot's
    /// release is past its `Valid-Until` by design, so a release this backstop
    /// serves is accepted as [`allow_stale_release`](Self::allow_stale_release)
    /// accepts one, the signature still verified, while a release the live
    /// mirror serves is still held to its freshness. That keeps the live
    /// mirror, or whatever answers in its place, from delivering an expired
    /// release.
    pub fn snapshot_fallback(mut self, url: impl Into<String>) -> Self {
        let url = url.into();
        self.snapshot_fallbacks.push(url.clone());
        self.mirror_fallbacks.push(url);
        self
    }

    /// Adds a [`Repository`] merged into the resolution alongside the primary.
    ///
    /// An additional repository is a distinct source — a local trusted `.deb`
    /// pool, a signed feature repository, a backports suite — contributing
    /// packages to one merged closure. Each name resolves to one version across
    /// every repository, chosen as apt chooses one by default. Each release
    /// ranks its own versions: one marked `NotAutomatic`, as `experimental` is,
    /// ranks lowest, and one also marked `ButAutomaticUpgrades`, as a backports
    /// suite is, ranks above that and below every other release. A version from
    /// a higher-ranked release is taken over one from a lower-ranked release
    /// whatever the versions are, so adding `experimental` to reach one package
    /// changes nothing else. Between releases of one rank the higher version
    /// wins, so a package a feature repository ships at a higher version
    /// supersedes the primary's. An exact tie resolves to the earlier
    /// repository, the primary first. A package only one repository ships is
    /// pulled from it, whatever its rank. To take a package from a
    /// lower-ranked release, name it with the release in
    /// [`include`](Self::include).
    ///
    /// The base system is seeded from the primary alone: a repository marking
    /// a package essential or required adds nothing to the seed, though a
    /// seeded name resolves to whichever repository's version wins.
    ///
    /// Every configured repository is trusted with the whole root. Each
    /// release is verified against its own repository's anchor, but the names
    /// are shared: any repository that wins a name supplies that package,
    /// `debian-archive-keyring` included, and with it the keys the primary's
    /// source in the finished rootfs trusts.
    ///
    /// Each additional repository writes its own
    /// `/etc/apt/sources.list.d/<name>.list` into the finished rootfs, unless
    /// its mirror is a `file://` URL: that names a host path the finished root
    /// cannot see, so no source is written for it.
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
    /// as essential as this floor, as the primary repository marks them. The
    /// default, [`Priority::Required`], is
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
    ///
    /// A name resolves to the version the repositories rank first, as
    /// [`repository`](Self::repository) describes. An entry written
    /// `name/release` asks for the name from the repository configured with the
    /// suite `release`, apt's own `name/release` request: that repository's
    /// highest version of the name is installed, whatever its rank. Each
    /// versioned dependency of it that the base, the selection, and the
    /// candidates cannot meet is taken from the same release where that release
    /// meets it, and that version's dependencies likewise. This is how a
    /// package is taken from a release ranked below the rest, such as
    /// `linux-image-amd64/trixie-backports`, without the release supplying
    /// anything nothing asked of it.
    ///
    /// An entry naming a release no repository is configured with is refused
    /// at [`build`](Self::build) with [`DebianError::Config`], and one naming a
    /// package the release does not carry fails the resolution.
    ///
    /// A name a [`pin`](Self::pin) holds is taken at its pinned version by
    /// every route, a release's included. An entry naming a release that
    /// offers the name only at another version, or a versioned dependency the
    /// pinned version does not meet, fails the resolution with
    /// [`DebianError::Pin`].
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
    /// one naming more archives than there are repositories to fetch them from,
    /// and one naming a package twice, since a root holds one package of a
    /// name. Where the builder names no architecture the plan's is adopted,
    /// since a plan states which architecture it is for.
    ///
    /// Everything that shapes *how* rather than *what* still applies:
    /// [`cache_dir`](Self::cache_dir), [`identity_map`](Self::identity_map),
    /// [`pre_configure_overlay`](Self::pre_configure_overlay),
    /// [`source_date_epoch`](Self::source_date_epoch), the repositories, and
    /// the fetcher. A package is fetched from the repository its
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
    /// The pinned version is the one selected by every route a resolution
    /// takes to a version: the candidate, an [`include`](Self::include) entry
    /// written `name/release`, a versioned dependency such an entry takes from
    /// its release, and an upgrade of a name a [`base_layer`](Self::base_layer)
    /// holds. An upgrade takes the pinned version wherever it is above the
    /// installed one, whatever the rank of its release. A name the base layer
    /// supplies and nothing upgrades keeps the base's version, since the pin
    /// constrains what the resolution selects and the base is not selected.
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
    /// A pin the resolution cannot be held to fails it the same way, after the
    /// closure is computed, naming each package with what was asked of it. An
    /// install list entry asks for a pinned name from a release that offers it
    /// only at another version, or a selected package needs a version of a
    /// pinned name that the pinned one does not meet. The resolution does not
    /// take another version in either case, so the pin or the install list has
    /// to change.
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
    ///
    /// An exclusion names a package alone. One written with a release is
    /// refused at [`build`](Self::build) with [`DebianError::Config`], since an
    /// exclusion removes the package whichever release would supply it.
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
    /// An extract-only rootfs has run no maintainer scripts. It holds the
    /// packages' files and an empty dpkg database, which records none of them
    /// as installed. It is the escape hatch for a foreign architecture with no
    /// qemu binfmt handler, where the packages' code cannot run.
    ///
    /// It applies to a whole bootstrap only. Alongside a
    /// [`base_layer`](Self::base_layer) it is refused at [`build`](Self::build)
    /// with [`DebianError::Config`]: an increment is registered in the base's
    /// dpkg database only by running dpkg over the merged view, so an
    /// extract-only one would leave files in the merged root that no database
    /// records.
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

    /// Supplies the delegate that establishes a range
    /// [`identity_map`](Self::identity_map), replacing the bundled fallback
    /// chain, as [`CageBuilder::id_mapper`] does for one sandbox.
    ///
    /// Every cage the bootstrap's dpkg runs in is launched through it, and so
    /// is the removal of a [`stage_layer`](Debian::stage_layer) increment. The
    /// preflight that refuses an unavailable map before any download asks it
    /// too. A tree a site-specific delegate established ownership in is
    /// exported, copied into, and removed through that same delegate:
    /// [`Export::id_mapper`](super::Export::id_mapper),
    /// [`CopyIn::id_mapper`](super::CopyIn::id_mapper), and
    /// [`Remove::id_mapper`](super::Remove::id_mapper). The delegate is taken by
    /// value and kept; [`CageBuilder::id_mapper`] says why.
    ///
    /// [`CageBuilder::id_mapper`]: crate::CageBuilder::id_mapper
    pub fn id_mapper(mut self, mapper: impl IdMapper + 'static) -> Self {
        self.id_mapper = Some(Arc::new(mapper));
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
    /// and before the configure wave runs their configuration scripts.
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
    /// The overlay is placed once every package is unpacked and before the one
    /// wave that configures them, so their `postinst` scripts observe the
    /// injected configuration — a debconf pre-seed, a hardware-probe guard —
    /// essential packages' included. Two kinds of script run earlier and do not
    /// see it. Unpacking runs every package's `preinst`. A full bootstrap also
    /// installs and configures its core packages first, one at a time:
    /// `base-passwd`, `base-files`, `dpkg`, `libc6`, `perl-base`, and `mawk`.
    ///
    /// A layered build lays the overlay into its increment the same way, after
    /// the increment is unpacked and before it is configured, and lays it even
    /// when the increment installs nothing, so the build root does not depend
    /// on whether the base already held what was asked for.
    /// [`extract_only`](Self::extract_only) configures nothing and ignores it.
    pub fn pre_configure_overlay(mut self, source: impl AsRef<Path>) -> Self {
        self.overlay = Some(source.as_ref().to_path_buf());
        self
    }

    /// Gives every maintainer script `SOURCE_DATE_EPOCH`, set to `epoch` in
    /// Unix seconds, so the tools they run date what they write from it rather
    /// than from the clock.
    ///
    /// In a bootstrap those tools are the ones that create accounts. `useradd`,
    /// `pwconv`, and `systemd-sysusers` record the day of each account's last
    /// password change in `/etc/shadow`. Without an epoch that day is the one
    /// the bootstrap ran on, so one plan installed on two different days gives
    /// two different roots.
    ///
    /// An epoch in the first day of 1970 records an empty field, as `useradd`
    /// and `pwconv` write it, because `/etc/shadow` reads a day of zero as a
    /// demand for a new password at the next login. `systemd-sysusers` writes
    /// the zero, and the bootstrap empties each one its run wrote, in
    /// `/etc/shadow` and in `/etc/shadow-`, once the scripts have run.
    ///
    /// The value is a plain timestamp rather than something read from the
    /// environment, so a pipeline that pins a build date passes the same number
    /// here and to [`Export::clamp_mtime`](crate::provision::Export::clamp_mtime).
    /// The epoch dates what the scripts write, and the clamp caps the
    /// modification times the archive records; a byte-reproducible archive
    /// takes both. The records of a run that no epoch dates, dpkg's own log
    /// among them, are removed from every bootstrap, with or without one.
    ///
    /// Unset, the maintainer environment carries no time. A layered build
    /// passes the epoch to the increment's scripts as a full bootstrap does,
    /// and [`extract_only`](Self::extract_only) runs no script and ignores it.
    ///
    /// The epoch is a moment already past, as the convention has it: the time
    /// of the source's last change. shadow's tools refuse one later than the
    /// build host's clock and date from the clock instead, while
    /// `systemd-sysusers` takes it, so a future epoch leaves the accounts dated
    /// two ways.
    ///
    /// # Refused values
    ///
    /// A negative epoch is refused at [`build`](Self::build) with
    /// [`DebianError::Config`]. The account tools read the variable as an
    /// unsigned count and date from the clock when it is negative, which is the
    /// date this setting exists to replace. `clamp_mtime` accepts one, because
    /// a ceiling before 1970 is still a ceiling.
    pub fn source_date_epoch(mut self, epoch: i64) -> Self {
        self.source_date_epoch = Some(epoch);
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
    /// closes over only the delta, holding what the base keeps to working
    /// beside it.
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
    /// performs a full bootstrap and does not consult the base. An increment is
    /// always configured, so [`extract_only`](Self::extract_only) alongside a
    /// base layer is refused at [`build`](Self::build).
    pub fn base_layer(mut self, base: impl AsRef<Path>) -> Self {
        self.base_layer = Some(base.as_ref().to_path_buf());
        self
    }

    /// Overrides the embedded archive keyring with one read from `path` (a
    /// binary OpenPGP keyring).
    ///
    /// A keyring alongside [`trust_unsigned`](Self::trust_unsigned) is refused
    /// at [`build`](Self::build) with [`DebianError::Config`]: one asks for the
    /// release to be verified and the other for it not to be.
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
    /// `http://` included — is refused. So is a [`keyring`](Self::keyring)
    /// named alongside it.
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
    /// way.) Setting this relaxes the freshness check for every mirror while
    /// still verifying the signature, for the legitimate case of pinning a
    /// historical archive state — for example a primary mirror that is a
    /// `snapshot.debian.org` suite, whose `Valid-Until` has deliberately
    /// passed. A live mirror with a snapshot backstop relaxes it for the
    /// backstop alone, with [`snapshot_fallback`](Self::snapshot_fallback). The
    /// key that made the signature must still be in force: a state signed
    /// only by keys that have since expired is refused. It has no effect on a
    /// [`trust_unsigned`](Self::trust_unsigned) mirror, which is never
    /// freshness-checked.
    ///
    /// The finished rootfs's source for the repository carries the same
    /// posture, `check-valid-until=no`, so the root's `apt` reads the release
    /// the root was built from.
    pub fn allow_stale_release(mut self, allow: bool) -> Self {
        self.allow_stale = allow;
        self
    }

    /// Substitutes the transport. The default speaks plain HTTP and
    /// `file://`; a consumer needing HTTPS or a proxy supplies their own.
    ///
    /// The transport is taken by value and kept for the provisioner's whole
    /// life, so the finished [`Debian`] can be moved to another thread with
    /// it; [`Fetch`] says why.
    pub fn fetcher(mut self, fetcher: impl Fetch + 'static) -> Self {
        self.fetcher = Some(Box::new(fetcher));
        self
    }

    /// Validates the configuration and freezes it into a [`Debian`].
    ///
    /// # Errors
    ///
    /// Returns [`DebianError::Config`] for a configuration that contradicts
    /// itself — a plan alongside a setting that would reshape it, a plan and a
    /// pin at once, either resolved for a different suite or architecture, or
    /// [`extract_only`](Self::extract_only) over a
    /// [`base_layer`](Self::base_layer) — for a negative
    /// [`source_date_epoch`](Self::source_date_epoch), and for a suite,
    /// component, or architecture the archive cannot be addressed by: an empty
    /// value, one carrying whitespace, a control character, or another
    /// character a URL path cannot carry as written (such as `%`, `?`, `#`, or
    /// one outside ASCII), or one that would resolve outside the mirror root
    /// through a leading `/`, a `..` segment, or an empty or `.` segment. The
    /// suite and the component may otherwise contain slashes, since both may
    /// name a subtree; the architecture may not.
    ///
    /// The same refusal covers a keyring named by [`keyring`](Self::keyring)
    /// that is not an OpenPGP keyring holding a usable key, a keyring named
    /// alongside [`trust_unsigned`](Self::trust_unsigned), a mirror URL
    /// carrying whitespace or a control character, an
    /// [`include`](Self::include) naming a release no repository publishes,
    /// and an [`exclude`](Self::exclude) naming a release at all.
    ///
    /// Returns [`DebianError::Io`] when a keyring named by
    /// [`keyring`](Self::keyring) cannot be read.
    pub fn build(self) -> Result<Debian, DebianError> {
        if self.suite.trim().is_empty() {
            return Err(DebianError::Config {
                reason: "no suite was given".to_string(),
            });
        }
        if self.extract_only && self.base_layer.is_some() {
            return Err(DebianError::Config {
                reason: "extract_only runs no dpkg, and a layered build registers its increment \
                         in the base's dpkg database only by running it, so the increment's files \
                         would be in the merged root and in no database; drop one of the two"
                    .to_string(),
            });
        }
        if let Some(epoch) = self.source_date_epoch
            && epoch < 0
        {
            return Err(DebianError::Config {
                reason: format!(
                    "the source date epoch {epoch} is negative, and the tools that read \
                     SOURCE_DATE_EPOCH date from the clock instead"
                ),
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
        // The primary's anchor: the caller's keyring, the decision to trust it
        // unsigned, or the embedded archive keyring where the caller named
        // neither. Naming both is refused before the keyring is read.
        let trust = repository::trust_anchor(
            self.keyring_path.as_deref(),
            self.trust_unsigned,
            "reading the keyring",
            || Ok(repository::Trust::Archive),
        )?;
        let components = if self.components.is_empty() {
            vec!["main".to_string()]
        } else {
            self.components
        };
        // The primary repository: its mirror list is the configured mirror
        // followed by any snapshot backstops, and its trust anchor is the one
        // settled above. Repository construction rejects an unsigned http://
        // mirror, the same refusal the flattened configuration made.
        let primary_mirror = self.mirror.unwrap_or_else(|| DEFAULT_MIRROR.to_string());
        let mut mirrors = Vec::with_capacity(1 + self.mirror_fallbacks.len());
        mirrors.push(primary_mirror);
        mirrors.extend(self.mirror_fallbacks);
        let primary = Repository::primary(
            self.suite.clone(),
            mirrors,
            self.snapshot_fallbacks,
            components,
            trust,
            self.allow_stale,
        )?;

        let mut repositories = Vec::with_capacity(1 + self.repositories.len());
        repositories.push(primary);
        repositories.extend(self.repositories);
        repository::validate_distinct_entries(&repositories)?;
        validate_selection(&self.includes, &self.excludes, &repositories)?;

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
            source_date_epoch: self.source_date_epoch,
            base_layer: self.base_layer,
            repositories,
            fetcher: self.fetcher.unwrap_or_else(|| Box::new(HttpFetch::new())),
            id_mapper: self.id_mapper,
        })
    }
}

impl Provisioner for Debian {
    fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
        self.provision_reporting(request.staging(), &mut RunObserver { request })
    }
}

impl Debian {
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
    pub fn observe<'o>(&'o mut self, sink: &'o mut dyn DebianObserver) -> Observed<'o> {
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
pub struct Observed<'o> {
    debian: &'o mut Debian,
    sink: &'o mut dyn DebianObserver,
}

impl fmt::Debug for Observed<'_> {
    /// Renders the bootstrap being observed. The sink is a caller's closure, so
    /// it renders as its presence rather than its contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observed")
            .field("debian", &self.debian)
            .field("sink", &Delegate("dyn DebianObserver"))
            .finish()
    }
}

impl Observed<'_> {
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

impl Provisioner for Observed<'_> {
    /// Reports to the sink bound here rather than to the run's observer: the
    /// caller chose the richer, Debian-specific channel by using
    /// [`Debian::observe`]. Either can stop the bootstrap: the sink through
    /// its own [`cancelled`](DebianObserver::cancelled), and a
    /// [`Provision::observe`](crate::provision::Provision::observe) observer
    /// that is not reporting on it through the run.
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
        id_mapper,
        cache_dir,
        overlay,
        source_date_epoch,
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
        crate::provision::layer::network_filter_preflight()
            .map_err(|reason| wrap(DebianError::Config { reason }))?;

        // A range map must be establishable before anything is downloaded:
        // an unavailable map is a configuration problem, and the identity
        // posture is never quietly downgraded to the single-identity form.
        crate::idmap::establishable(identity_map, id_mapper).map_err(|refusal| {
            wrap(DebianError::Config {
                reason: ErrorChain::new(&refusal).to_string(),
            })
        })?;
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
    // below as on the success path, and so does a private copy taken from it.
    let archives = PackageCache::beside(staging, cache_dir, DEB_CACHE);
    let installables = acquire_debs(fetcher, repositories, &packages, archives.path(), observer)?;
    let private = private_copy(staging, cache_dir, &installables)?;
    let installing = private.as_ref().unwrap_or(&archives).path();

    let statoverride = stage_extract(staging, architecture, &installables, installing, observer)?;

    if !extract_only {
        let env = maintainer_env(source_date_epoch);
        let wave = bootstrap::Configure {
            archives_host: installing,
            installables: &installables,
            statoverride: &statoverride,
            identity_map,
            id_mapper,
            env: &env,
            source_date_epoch,
        };
        bootstrap::configure(staging, &wave, repositories, overlay, observer).map_err(wrap)?;
        // The read-only bind mount left an empty mount point in the rootfs.
        // Removed as the empty directory it is: anything else at the name is
        // not the launch's to take.
        let _ = std::fs::remove_dir(staging.join(bootstrap::ARCHIVES.trim_start_matches('/')));
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
/// on each release unless its repository trusts unsigned, waives it, or the
/// release came from one of its snapshot backstops. The
/// per-component indexes are tagged with their repository's index and merged,
/// each name ranked across the union as [`Index::merge`] ranks it, so the
/// resolved set draws each package from the repository that ships its winning
/// version. The base system is seeded from the primary's index alone.
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
///
/// A resolution that refused the pin fails with [`DebianError::Pin`] instead,
/// naming every package the pin could not be held to, as a pin the archives
/// cannot supply fails before the resolution starts. Every refusal, the pin's
/// and the rest, is still reported as an event.
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
    let unheld = refusals.unheld();
    if !unheld.is_empty() {
        return Err(DebianError::Pin { unheld });
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
/// already carry is selected, and the root base and delta make together is
/// held to every dependency it carries, as [`resolve::resolve_seeded`]
/// describes. There is no base-system seed and no `apt`: the base supplies
/// both. This is [`resolve_packages`]'s read-merge-and-report structure with
/// the priority seed replaced by the base's installed set.
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
/// indexes are tagged with their repository's index and the rank its release
/// marks itself with, and merged into one ranked set.
fn merged_index(
    fetcher: &mut dyn Fetch,
    repositories: &[Repository],
    architecture: &str,
    pins: &Pins,
    observer: &mut dyn DebianObserver,
) -> Result<(Index, Vec<ResolvedArchive>), DebianError> {
    // Each repository contributes one text block per component, tagged with the
    // repository's index so the merged index knows where each package came from,
    // and with how its release ranks its versions.
    let mut index_inputs: Vec<(usize, ReleasePriority, String)> = Vec::new();
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
                repository.require_fresh(&served.mirror),
            )
            .map_err(|reason| DebianError::Release {
                subject: served.url.clone(),
                reason,
            })?;
        let text = fetch_index(
            fetcher,
            repository,
            architecture,
            &release,
            &served,
            observer,
        )?;
        let Served {
            mirror,
            sha256,
            signed_by,
            signing_key,
            ..
        } = served;
        archives.push(ResolvedArchive {
            mirror,
            suite: repository.suite.clone(),
            components: repository.components.clone(),
            release_sha256: sha256,
            date: release.date().map(str::to_string),
            valid_until: release.valid_until().map(str::to_string),
            signed_by,
            signing_key,
            // A record built from a live resolution has no document behind it,
            // so there is nothing to carry.
            carried: Carried::new(),
        });
        index_inputs.push((origin, release.priority(), text));
    }

    let index = Index::merge(
        index_inputs
            .iter()
            .map(|(origin, priority, text)| index::Source {
                origin: *origin,
                suite: &repositories[*origin].suite,
                priority: *priority,
                text,
            }),
        architecture,
        pins,
    );
    observer.progress(DebianEvent::Index {
        packages: index.package_count(),
        skipped: index.skipped(),
    });
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
/// path the archive signature is verified against the repository's keyring,
/// and held to be unexpired where [`Repository::require_fresh`] holds the
/// mirror that served it to freshness.
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
            let url = mirror_url(&mirror, &suffix);
            let sha256 = Digest::of(Algorithm::Sha256, &bytes);
            let Ok(body) = String::from_utf8(bytes) else {
                return Err(DebianError::Release {
                    subject: url,
                    reason: "it is not UTF-8".to_string(),
                });
            };
            // Nothing verified it, so no key is named. An empty list is the
            // record of that, and is not the same as an omitted repository.
            (
                body,
                Served {
                    url,
                    mirror,
                    sha256,
                    signed_by: Vec::new(),
                    signing_key: Vec::new(),
                },
            )
        }
        Some(keyring_bytes) => {
            let suffix = format!("dists/{suite}/InRelease");
            let (bytes, mirror) =
                fetch_from_mirrors(fetcher, &repository.mirrors, &suffix, observer)?;
            let url = mirror_url(&mirror, &suffix);
            let sha256 = Digest::of(Algorithm::Sha256, &bytes);
            // The keyring parsed when the repository was built, so this is a
            // second parse of the same bytes rather than a new question; a
            // refusal is reported against the release it was to verify.
            let verified = Keyring::parse(keyring_bytes)
                .and_then(|keyring| keyring.verify(&bytes, repository.require_fresh(&mirror)))
                .map_err(|err| DebianError::Signature {
                    subject: url.clone(),
                    reason: err.to_string(),
                })?;
            (
                verified.body,
                Served {
                    url,
                    mirror,
                    sha256,
                    signed_by: vec![verified.certificate],
                    signing_key: vec![verified.signing_key],
                },
            )
        }
    };
    let release = Release::parse(&body).map_err(|reason| DebianError::Release {
        subject: served.url.clone(),
        reason,
    })?;
    Ok((release, served))
}

/// How a repository's release was obtained: where it came from, and which key
/// verified it.
///
/// The facts a [`ResolvedArchive`] and a failure report need that the release
/// body does not itself carry.
struct Served {
    /// The URL the release was fetched from, which every failure reading it
    /// names as its subject.
    url: String,
    /// The mirror that served the release.
    ///
    /// The first mirror the release's indexes are asked of, since they are
    /// held to what this release records; see [`served_first`]. It is not where
    /// the packages go to: a bootstrap walks the mirrors its repositories are
    /// configured with, so this records the choice that was made rather than
    /// deciding a later one. It reaches a caller as
    /// [`ResolvedArchive::mirror`].
    mirror: String,
    /// The SHA-256 of the release file as the mirror served it: the
    /// `InRelease`, signature and all, or the `Release` of a repository trusted
    /// unsigned. It reaches a caller as [`ResolvedArchive::release_sha256`].
    sha256: Digest,
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
///
/// `served` is where `release` came from: its URL, which a release that lists
/// no index for a component is reported against, and the mirror that served
/// it, which every component's walk asks first.
fn fetch_index(
    fetcher: &mut dyn Fetch,
    repository: &Repository,
    architecture: &str,
    release: &Release,
    served: &Served,
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
            served,
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

/// Fetches one component's index, walking the repository's mirror list from
/// the mirror that served the release.
///
/// The candidate compressions the release lists a digest for are determined
/// once, from the release; the mirror walk then tries them in order on each
/// mirror, advancing to the next mirror when one reports the index missing. A
/// fetched index is verified against the release digest — a mismatch is fatal,
/// not a reason to try another mirror — and decompressed.
///
/// The walk starts at the mirror that served the release and goes on through
/// the rest in the order they are configured; see [`served_first`] for why.
///
/// Where the release declares `Acquire-By-Hash`, each compression is asked for
/// by its digest first and by its name second, the order apt queues the two
/// in. A partial mirror or a caching proxy may carry the named index and not
/// the by-hash copies, and it serves the index all the same. The name is asked
/// only when the digest path failed to serve: bytes that arrived and do not
/// match the digest stop the walk there, as they do everywhere else.
///
/// `served` is where `release` came from, as [`fetch_index`] takes it.
fn fetch_component_index(
    fetcher: &mut dyn Fetch,
    repository: &Repository,
    architecture: &str,
    component: &str,
    release: &Release,
    served: &Served,
    observer: &mut dyn DebianObserver,
) -> Result<String, DebianError> {
    // Prefer the smallest available index; every candidate is verified against
    // the release digest, so the choice is trust-neutral. Which compressions
    // exist is a property of the release, the same across every mirror. The
    // release states each index's length beside its digest, and that length
    // travels with the fetch as its ceiling: it is signed, it is free, and it
    // bounds what a mirror can spend before the digest check runs.
    let candidates: Vec<(String, u64, &Digests)> = ["Packages.xz", "Packages.gz", "Packages"]
        .iter()
        .filter_map(|suffix| {
            let rel = format!("{component}/binary-{architecture}/{suffix}");
            release
                .digest(&rel)
                .map(|(size, digests)| (rel, size, digests))
        })
        .collect();
    if candidates.is_empty() {
        return Err(DebianError::Release {
            subject: served.url.clone(),
            reason: format!("it lists no index for component {component} on {architecture}"),
        });
    }
    // The release states the uncompressed index's length too, whether or not a
    // mirror serves that file, and it bounds the decompression the way the
    // compressed length bounds the fetch: a few megabytes of xz may expand into
    // gigabytes, and the digest says nothing about what they expand into.
    let expanded = release
        .digest(&format!("{component}/binary-{architecture}/Packages"))
        .map_or(MAX_UNSIZED_INDEX, |(size, _)| size);

    let suite = &repository.suite;
    // What an exhausted walk reports, as `fetch_from_mirrors` reports one: the
    // resource below the mirror rather than a URL on any one of them.
    let unserved = format!("dists/{suite}/{component}/binary-{architecture}/Packages");
    // Three walks, each inside the next: the locations of one encoding (its
    // by-hash path, then its name), the encodings within one mirror, and the
    // mirrors. A walk that ends without an answer has failed over as surely as
    // a fetch that answered nothing, so its last failure is what advances the
    // walk around it -- and every `exhausted` closure is unreachable, a
    // location list never being empty, the empty candidate list having been
    // refused above, and a repository with no mirror at construction.
    let not_served = || DebianError::Fetch(FetchError::not_found(&unserved));
    walk_mirrors(
        &served_first(&repository.mirrors, &served.mirror),
        |mirror| {
            // A mirror boundary: nothing is half-read, so stopping here costs
            // nothing, and a resolve stops between one mirror and the next
            // rather than only once the whole list has answered.
            if observer.cancelled() {
                return Err(DebianError::Cancelled);
            }
            walk_mirrors(
                &candidates,
                |(rel, size, digests)| {
                    let mut locations = Vec::with_capacity(2);
                    // Under the strongest digest the release records, as apt
                    // asks: an archive recording SHA-512 alone publishes its
                    // `by-hash` copies under that algorithm alone.
                    if release.acquire_by_hash() {
                        let (algorithm, digest) = digests.strongest();
                        locations.push(mirror_url(
                            mirror,
                            &format!(
                                "dists/{suite}/{component}/binary-{architecture}/by-hash/\
                                 {algorithm}/{}",
                                digest.hex()
                            ),
                        ));
                    }
                    locations.push(mirror_url(mirror, &format!("dists/{suite}/{rel}")));
                    walk_mirrors(
                        &locations,
                        |url| {
                            observer.progress(DebianEvent::Fetching { url });
                            let bytes = fetch_bytes(fetcher, url, Some(*size))?;
                            verify_digest(url, &bytes, digests)?;
                            decompress_index(url, &bytes, expanded)
                        },
                        not_served,
                    )
                },
                not_served,
            )
        },
        not_served,
    )
}

/// The mirrors an index walk asks, in order: `served`, the mirror that served
/// the release the index is held to, then the rest of `mirrors` as configured.
///
/// The release records the digest every index is held to, and the mirrors of
/// one repository need not publish the same state at one moment: a snapshot
/// backstop publishes the state of its date, and a live mirror today's. A walk
/// from the first mirror would ask the live mirror for the index of a release
/// the snapshot served, and the live mirror's index, published under the same
/// name, is not the one that release records. A digest mismatch ends a walk
/// rather than advancing it, so the run would fail as though a mirror had
/// tampered with the index, over a transient failure that had sent the release
/// to the backstop.
fn served_first<'m>(mirrors: &'m [String], served: &'m str) -> Vec<&'m str> {
    std::iter::once(served)
        .chain(
            mirrors
                .iter()
                .map(String::as_str)
                .filter(|mirror| *mirror != served),
        )
        .collect()
}

/// Fetches `suffix` (a mirror-relative path) from the first mirror that serves
/// it, advancing past a mirror that reports the resource missing or fails at
/// the transport, and returning the last such error when every mirror is
/// exhausted.
///
/// A release file is the trust root, so nothing signed declares its length. It
/// is fetched under [`MAX_SIGNED_DOCUMENT_BYTES`], the ceiling every layer holds
/// an unsized signed document to and the most that verifying one reads. The
/// unsigned `Release` a trusted local mirror serves is held to the same
/// ceiling: it is the same document without its armor.
fn fetch_from_mirrors(
    fetcher: &mut dyn Fetch,
    mirrors: &[String],
    suffix: &str,
    observer: &mut dyn DebianObserver,
) -> Result<(Vec<u8>, String), DebianError> {
    walk_mirrors(
        mirrors,
        |mirror| {
            // A mirror boundary, and the first point of every resolve: nothing
            // has been read, so stopping costs nothing.
            if observer.cancelled() {
                return Err(DebianError::Cancelled);
            }
            let url = mirror_url(mirror, suffix);
            observer.progress(DebianEvent::Fetching { url: &url });
            // The mirror that answered, not the whole list: a repository with a
            // snapshot backstop resolves against whichever one served, and a
            // record naming the list would describe a choice rather than the
            // choice made.
            fetch_bytes(fetcher, &url, Some(MAX_SIGNED_DOCUMENT_BYTES))
                .map(|bytes| (bytes, mirror.clone()))
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
/// [`cache::prefetch`], so a transport that can overlap several requests does.
/// That step is an optimization and nothing more: a package it does not deliver
/// is downloaded by the walk below exactly as though the batch had not run.
/// Either way a download is published only once its digest has matched
/// ([`verify_deb`]), so the cache never holds a `.deb` that was not checked.
///
/// The cache pass asks [`is_cached`] rather than whether a file exists. An
/// entry left short by a crash, or altered since, is therefore downloaded again,
/// and a package the batch could not deliver reaches every mirror rather than
/// stopping at a corrupt entry.
fn acquire_debs(
    fetcher: &mut dyn Fetch,
    repositories: &[Repository],
    packages: &[Wanted],
    archives_host: &Path,
    observer: &mut dyn DebianObserver,
) -> Result<Vec<Installable>, ProvisionError> {
    cache::create(archives_host)?;

    // The cache pass, before anything is fetched: what a caller is told it is
    // downloading is what a batch and the walk between them go on to fetch, in
    // the order the plan names them.
    let mut missing = Vec::new();
    for package in packages {
        if observer.cancelled() {
            return Err(ProvisionError::Cancelled);
        }
        let dest = archives_host.join(cache_name(&package.digests));
        if !is_cached(&dest, &package.digests) {
            missing.push((package, dest));
        }
    }

    // Announced over what is actually being fetched, once the cache has been
    // asked about every package: a position among the plan's packages counts
    // the ones already cached, so an observer reporting `index` of `total` would
    // show a fetch of three packages as reaching nine of ten. The announcement
    // precedes the batch because the batch fetches several at once, which is
    // the shape a fetch event has throughout this crate.
    for (position, (package, _)) in missing.iter().enumerate() {
        observer.progress(DebianEvent::Downloading {
            package: &package.name,
            index: position + 1,
            total: missing.len(),
        });
    }

    // Every job asks the package's own repository's first mirror, which is the
    // one the walk would ask first too.
    let (batched, jobs): (Vec<usize>, Vec<cache::Job<'_>>) = missing
        .iter()
        .enumerate()
        .filter_map(|(at, (package, dest))| {
            let mirror = repositories[package.origin].mirrors.first()?;
            let job = cache::Job {
                url: mirror_url(mirror, &package.filename),
                entry: cache::Entry {
                    path: dest,
                    size: package.size,
                },
            };
            Some((at, job))
        })
        .unzip();
    let delivered = cache::prefetch(fetcher, &jobs, observer, |job, mut file| {
        let (package, dest) = &missing[batched[job]];
        verify_deb(&mut file, dest, &jobs[job].url, &package.digests)
    })
    .map_err(|failure| failure.into_provision(wrap))?;
    let mut acquired = vec![false; missing.len()];
    for (at, delivered) in batched.into_iter().zip(delivered) {
        acquired[at] = delivered.is_some();
    }

    for ((package, dest), acquired) in missing.iter().zip(acquired) {
        if acquired {
            continue;
        }
        // The walk asks the observer at each mirror and on every write of the
        // body, so a cancelled run stops within one package's worth of bytes,
        // and what has been published by then is complete and verified.
        cache::download(
            fetcher,
            &repositories[package.origin].mirrors,
            |mirror| mirror_url(mirror, &package.filename),
            cache::Entry {
                path: dest,
                size: package.size,
            },
            observer,
            |mut file, url, _| verify_deb(&mut file, dest, url, &package.digests),
            || FetchError::not_found(&package.filename),
        )
        .map_err(|failure| failure.into_provision(wrap))?;
    }

    Ok(packages
        .iter()
        .map(|package| Installable {
            name: package.name.clone(),
            deb_path: format!("{}/{}", bootstrap::ARCHIVES, cache_name(&package.digests)),
            digests: package.digests.clone(),
        })
        .collect())
}

/// The name a package with `digests` is cached under: its SHA-256 where the
/// archive records one, so an entry an earlier run cached keeps its name, and
/// otherwise its SHA-512, whose width keeps the two apart.
fn cache_name(digests: &Digests) -> String {
    format!("{}.deb", digests.planned().hex())
}

/// Whether the cache entry at `dest` holds the package whose digests are
/// `digests`, decided by streaming them.
///
/// Validating a cached kernel package costs the memory of validating a shell
/// script, which is the property every read and write of a `.deb` in this
/// crate keeps. An entry that is absent, unreadable, not a regular file,
/// truncated, or altered answers `false`, and a download replaces it: a rename
/// onto the name is what publishes the replacement.
fn is_cached(dest: &Path, digests: &Digests) -> bool {
    cache::open_entry(dest).is_ok_and(|mut file| {
        verify_deb(&mut file, dest, &dest.display().to_string(), digests).is_ok()
    })
}

/// Holds a `.deb` to every digest its index recorded, reading `file` once from
/// its start.
///
/// The one check a package is held to, whichever produced the file: a cache
/// hit, a download before it is published, and the copy a run installs from.
/// `entry` is where the package is or is about to be, for a read that fails;
/// `subject` names the bytes in a refusal, the URL they were fetched from or the
/// path they were read at.
fn verify_deb(
    file: &mut File,
    entry: &Path,
    subject: &str,
    digests: &Digests,
) -> Result<(), DebianError> {
    digests
        .check_stream(file)
        .map_err(DebianError::at("reading the package", entry))?
        .map_err(|mismatch| DebianError::Digest {
            subject: subject.to_string(),
            expected: mismatch.expected.clone(),
            actual: mismatch.actual,
        })
}

/// Copies the packages a run installs out of a cache the caller named, into a
/// directory only this run writes, returning that directory; `None` where the
/// packages were downloaded into such a directory in the first place.
///
/// The host verifies each package as it extracts it, and `dpkg` reads the same
/// `.deb` again minutes later, by path, through a read-only bind. A cache the
/// caller named outlives the run and may be shared, with other runs and with
/// other writers, so a package replaced there between the two reads would be
/// installed unverified. The copy closes that gap: the extraction verifies the
/// copy, and every `dpkg` wave reads the copy, which nothing else can replace.
///
/// The directory is the one a run without a cache of its own downloads into,
/// beside the tree being built, and it goes with the run however the run ends.
/// A caller who named that very directory as their cache is the one case left
/// alone: it is theirs to keep, and the run treats it as its own already. That
/// is asked of the directory, whatever path names it, since a copy into the
/// caller's cache under another spelling would remove the cache with the copy.
fn private_copy(
    tree: &Path,
    cache_dir: Option<&Path>,
    installables: &[Installable],
) -> Result<Option<PackageCache>, ProvisionError> {
    let Some(cache_dir) = cache_dir else {
        return Ok(None);
    };
    if PackageCache::is_derived(tree, DEB_CACHE, cache_dir) {
        return Ok(None);
    }
    let private = PackageCache::beside(tree, None, DEB_CACHE);
    cache::create(private.path())?;
    for installable in installables {
        let name = cache_name(&installable.digests);
        let from = cache_dir.join(&name);
        copy_package(&from, &private.path().join(&name))
            .map_err(|source| ProvisionError::io("copying a package to install", &from, source))?;
    }
    Ok(Some(private))
}

/// Copies one package to `to`, through a [`Staged`] file beside it, so a copy
/// left over from an earlier run is replaced rather than trusted.
fn copy_package(from: &Path, to: &Path) -> io::Result<()> {
    let mut source = cache::open_entry(from)?;
    let (staged, mut copy) = Staged::beside(to)?;
    io::copy(&mut source, &mut copy)?;
    drop(copy);
    staged.publish()
}

/// One `.deb` to acquire: what the download needs and nothing else.
///
/// The two sources of an install set project onto this — a fresh resolution's
/// [`Package`], and a [`Plan`]'s [`PlannedPackage`] — so the download,
/// the digest check, and the cache reuse are one path whichever produced it.
struct Wanted {
    /// The package name, for the progress report and the dpkg install order.
    name: String,
    /// The archive-recorded digests, which name the cache entry and are the
    /// check the download is held to.
    digests: Digests,
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
            digests: package.digests.clone(),
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
    /// Installing from a plan fetches no index, so the length that bounds the
    /// download is the one the plan recorded from the index it was resolved
    /// against. A plan that recorded none leaves the download bounded by the
    /// fetcher's own ceiling, and verified against the plan's digest exactly as
    /// any other is.
    fn from_planned(package: &PlannedPackage) -> Wanted {
        Wanted {
            name: package.name.clone(),
            digests: Digests::from(package.digest.clone()),
            filename: package.filename.clone(),
            size: package.size,
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
    let statoverride = extract_packages(
        staging,
        None,
        architecture,
        installables,
        archives_host,
        observer,
    )?;
    init_dpkg_database(staging)?;
    Ok(statoverride)
}

/// Lays every package's files into `staging`, returning the derived
/// [`StatOverride`]. A whole root gets the merged-usr farm first.
///
/// The extraction half of [`stage_extract`], without the dpkg database
/// initialization. A layered build reuses it to extract an increment into an
/// overlay upper, where the base's own dpkg database, seen through the overlay,
/// is left untouched, so no empty database is written over it. `over` is that
/// base, and the base decides the layout: every entry is placed through it
/// ([`Extraction::over`]), so a package shipping a legacy top-level path lands
/// in `usr` exactly where the base's merged-usr links send it, and no farm is
/// laid into the upper. A farm there would shadow whatever the base holds at
/// those names, a base that keeps `/bin` a directory included. The base comes
/// with the identity map the upper is owned through, which a directory the
/// extraction carries up from it is given the base's ownership through.
fn extract_packages(
    staging: &Path,
    over: Option<(&Path, Ownership)>,
    architecture: &str,
    installables: &[Installable],
    archives_host: &Path,
    observer: &mut dyn DebianObserver,
) -> Result<StatOverride, ProvisionError> {
    if over.is_none() {
        create_merged_usr(staging, architecture)?;
    }
    let (over, ownership) = over.unzip();

    // Every `.deb` ships a `./` entry, so the tree being assembled would
    // otherwise take the mode and modification time of whichever package
    // happened to be extracted last. A rootfs root is `0755`, the mode
    // `base-files` itself ships, and stating it keeps the published directory
    // independent of both the package set and the caller's umask.
    let mut extraction = Extraction::new(staging)?
        .root_mode(ROOTFS_ROOT_MODE)
        .over(over)?
        .owned_through(ownership.unwrap_or_default());
    let mut statoverride = StatOverride::default();
    // A statoverride record is one newline-terminated line; a path component
    // carrying an embedded newline would split into a second, forged record
    // (a setuid grant on an unrelated path, say). A conforming .deb never
    // ships such a path, and the signed digest chain keeps a mirror from
    // forging one, so this is defense in depth for an unreachable case: reject
    // rather than emit a line the framing cannot be trusted to contain.
    let mut malformed: Option<(&str, Vec<Vec<u8>>)> = None;
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
        let mut file = cache::open_entry(&path)
            .map_err(|err| ProvisionError::io("reading the package", &path, err))?;
        // Re-verify against the digest the package was acquired under, rather
        // than trust the bytes on disk: the download and this read are separate
        // steps. The file read here is the one every dpkg wave reads later,
        // in a directory only this run writes (see `private_copy`), so this is
        // also the check that covers dpkg's read.
        //
        // Streamed, and the extraction that follows streams too, so installing a
        // kernel package costs the memory of installing a shell script — the
        // property the download and `Pool::publish` both keep, held to here as
        // well. `extract_deb` rewinds before it seeks to the data member, so the
        // digest pass leaving the file at its end costs nothing.
        verify_deb(
            &mut file,
            &path,
            &path.display().to_string(),
            &installable.digests,
        )
        .map_err(wrap)?;
        deb::extract_deb(
            &path,
            &mut file,
            &mut extraction,
            &mut |entry, components| {
                if entry.uid != 0 || entry.gid != 0 {
                    if components
                        .iter()
                        .any(|component| component.contains(&b'\n'))
                    {
                        malformed.get_or_insert_with(|| (&installable.name, components.to_vec()));
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
    if let Some((package, components)) = malformed {
        return Err(wrap(DebianError::MalformedEntry {
            package: package.to_string(),
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
///
/// It runs after every package's files are laid down, so a package is free to
/// have shipped any of these paths, a symbolic link out of the tree among
/// them. Every step therefore goes through [`Rooted`]:
/// a link resolves inside the tree, as it does for dpkg reading it from inside
/// the sandbox, and a name already taken is left as the package laid it.
fn init_dpkg_database(staging: &Path) -> Result<(), ProvisionError> {
    let tree = Rooted::open(staging)
        .map_err(|err| ProvisionError::io("opening the tree", staging, err))?;
    for dir in ["var/lib/dpkg/info", "var/lib/dpkg/updates"] {
        tree.create_dir_all(dir)
            .map_err(|err| ProvisionError::io("creating", tree.path(dir), err))?;
    }
    for file in ["var/lib/dpkg/status", "var/lib/dpkg/available"] {
        let taken = tree
            .exists(file)
            .map_err(|err| ProvisionError::io("inspecting", tree.path(file), err))?;
        if !taken {
            tree.write(file, b"")
                .map_err(|err| ProvisionError::io("writing", tree.path(file), err))?;
        }
    }
    Ok(())
}

/// The maintainer-script environment: non-interactive, deterministic locale
/// and timezone, and the caller's `SOURCE_DATE_EPOCH` where one was set.
fn maintainer_env(source_date_epoch: Option<i64>) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = [
        ("DEBIAN_FRONTEND", "noninteractive"),
        ("DEBCONF_NONINTERACTIVE_SEEN", "true"),
        ("LC_ALL", "C.UTF-8"),
        ("TZ", "UTC"),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .collect();
    if let Some(epoch) = source_date_epoch {
        env.push(("SOURCE_DATE_EPOCH".to_string(), epoch.to_string()));
    }
    env
}

/// Fetches a URL fully into memory, bounded by the size a verified source
/// declares for it, or by the ceiling for a document nothing declares a size
/// for.
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
            let mut sink = LimitedWriter::new(&mut bytes, size);
            fetcher.fetch(&request.sized(size), &mut sink)
        }
        None => fetcher.fetch(&request, &mut bytes),
    };
    result?;
    Ok(bytes)
}

/// Verifies bytes against every digest the release records for them, naming
/// the URL they were fetched from on a mismatch.
fn verify_digest(url: &str, bytes: &[u8], digests: &Digests) -> Result<(), DebianError> {
    digests
        .check_bytes(bytes)
        .map_err(|mismatch| DebianError::Digest {
            subject: url.to_string(),
            expected: mismatch.expected.clone(),
            actual: mismatch.actual,
        })
}

/// The most an index may expand to when its release states no uncompressed
/// length for it.
///
/// The Debian archive states one for every index, and so does [`Pool`]; a
/// third-party archive need not. A merged unstable index is under a hundred
/// megabytes of text, so this leaves room for any real archive while keeping
/// a few megabytes of compressed input from expanding without bound.
///
/// A [`Pool`] publish holds the index it merges into to the same bound, since
/// that index is read before any release has recorded a length for it.
const MAX_UNSIZED_INDEX: u64 = 256 * 1024 * 1024;

/// Decompresses a fetched index into text, refusing one that expands past
/// `limit` bytes rather than reading a truncated prefix of it.
///
/// `limit` is the uncompressed length the release states, or
/// [`MAX_UNSIZED_INDEX`] where it states none. Every failure is the index's,
/// named by the URL it was fetched from: the bytes are already in memory and
/// verified, so nothing here is a host I/O operation.
///
/// A stream the decoder refuses and a stream that decodes past `limit` are told
/// apart. The decoder's own failure is the cause of the first, carried as the
/// error's source; the second has no cause beyond the length. The decoder is
/// therefore read one byte past the limit rather than through a writer that
/// fails at it, since a writer's refusal and a decoder's arrive as the same
/// kind of error.
fn decompress_index(url: &str, bytes: &[u8], limit: u64) -> Result<String, DebianError> {
    let unusable = |reason: &str, source: Option<io::Error>| DebianError::Index {
        subject: url.to_string(),
        reason: reason.to_string(),
        source,
    };
    let (_, reader) = super::compress::decoder(bytes)
        .map_err(|err| unusable("its header cannot be read", Some(err)))?;
    let mut text = Vec::new();
    io::Read::read_to_end(
        &mut io::Read::take(reader, limit.saturating_add(1)),
        &mut text,
    )
    .map_err(|err| unusable("it does not decompress", Some(err)))?;
    if text.len() as u64 > limit {
        return Err(unusable(
            &format!("it expands past the {limit} bytes it may expand to"),
            None,
        ));
    }
    String::from_utf8(text).map_err(|_| unusable("it is not UTF-8 text", None))
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

/// Surfaces a [`DebianError`] through the shared provisioning error.
///
/// A cancellation is the run's own outcome rather than a layer failure, so it
/// becomes the shared [`ProvisionError::Cancelled`] a caller matches on
/// whichever provisioner they drove; everything else is boxed into
/// [`ProvisionError::Other`], the way a provisioner outside the core surfaces
/// its own failures.
fn wrap(error: DebianError) -> ProvisionError {
    match error {
        DebianError::Cancelled => ProvisionError::Cancelled,
        other => ProvisionError::other(other),
    }
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
/// waves in a cage, and a caller that wants to stop it part-way answers
/// [`cancelled`](Self::cancelled).
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

    /// Whether the work should stop.
    ///
    /// Consulted at the points where stopping is clean: each mirror a release,
    /// an index or a package walk asks, each batch of downloads, each write of
    /// a package's body as it downloads, each package extracted, and the start
    /// of each `dpkg` wave. So a [`resolve`](Observed::resolve) or an
    /// [`available`](Observed::available) stops on its way through the
    /// archives, and a bootstrap between two waves, between two packages, or
    /// part way through a download.
    ///
    /// Returning `true` aborts with [`DebianError::Cancelled`], which a
    /// provisioning run reports as [`ProvisionError::Cancelled`]. A run driven
    /// through [`provision::ensure`](crate::provision::ensure) then removes the
    /// staging tree, and a [`stage_layer`](Observed::stage_layer) its upper,
    /// so a cancelled bootstrap leaves nothing behind.
    ///
    /// The default is `false`: work that is never cancelled.
    ///
    /// [`ProvisionError::Cancelled`]: crate::provision::ProvisionError::Cancelled
    fn cancelled(&mut self) -> bool {
        false
    }
}

/// A download's view of the observer: the layer's own fetch event, and its
/// answer to whether the run should stop.
impl cache::Watch for dyn DebianObserver + '_ {
    fn fetching(&mut self, url: &str) {
        self.progress(DebianEvent::Fetching { url });
    }

    fn cancelled(&mut self) -> bool {
        DebianObserver::cancelled(self)
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
/// and stops when either that sink or the provisioning run asks it to.
///
/// The caller chose the richer, Debian-specific channel for events, and the
/// sink's own [`cancelled`](DebianObserver::cancelled) is the one its trait
/// documents, so it stops a bootstrap as it stops a resolve or a layered build.
/// A [`Provision::observe`](crate::provision::Provision::observe) observer can
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
        self.sink.cancelled() || self.request.cancelled()
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
    /// rules out, one an exclusion removed that a hard dependency needed, one a
    /// [`pin`](DebianBuilder::pin) holds at a version that cannot answer what
    /// was asked of it, or, in a layered build, one that nothing the base keeps
    /// and nothing the increment installs satisfies.
    ///
    /// Reported for every such refusal before the run fails, so a caller fixing
    /// an install list sees the whole list rather than the first entry of it.
    /// The failure that follows carries the same set as one sentence.
    #[non_exhaustive]
    Unsatisfiable {
        /// What could not be supplied: the dependency group as the archive,
        /// or a layered build's base, declares it, alternatives included, or
        /// the package name where the caller named one directly.
        requirement: &'a str,
        /// Who asked for it: the selected package whose dependency it was, a
        /// package a layered build's base keeps, or the install list.
        required_by: &'a str,
        /// What the wall was, as the clause following "and": that the name is
        /// absent, that it is excluded, what is available instead of what
        /// the constraint asked for, the version the pin holds it at, or the
        /// upgrade that replaced what satisfied it.
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
    /// Every configured repository's index has been read and merged into the
    /// package set a resolution draws from.
    ///
    /// Reported once per resolution, before the closure is computed. Installing
    /// a [`plan`](DebianBuilder::plan) reads no index and reports none.
    #[non_exhaustive]
    Index {
        /// How many packages the merged index offers, each name counted once.
        packages: usize,
        /// How many stanzas were read and not kept, because this layer cannot
        /// act on them: a stanza missing its package's name, version,
        /// architecture, or pool path, one stating its package's name or
        /// version outside the alphabet Debian policy gives each, one stating
        /// neither a SHA-256 nor a SHA-512, or either other than as lowercase
        /// hex of its width, or one whose pool path would leave the mirror. A
        /// package left out this way is one a resolution cannot select. A live
        /// archive reports zero.
        skipped: usize,
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
        /// The URL of the release whose signature was checked.
        subject: String,
        /// Why the signature was not accepted.
        reason: String,
    },
    /// The release is malformed, expired, or does not offer what was asked: an
    /// architecture, a component, or an index for one of them.
    #[non_exhaustive]
    Release {
        /// The URL the release was fetched from.
        subject: String,
        /// What is wrong with the release.
        reason: String,
    },
    /// A package index could not be read: it does not decompress, it is not
    /// text, or it expands past the length the release states for it.
    #[non_exhaustive]
    Index {
        /// The URL the index was fetched from.
        subject: String,
        /// What is wrong with the index.
        reason: String,
        /// The decoder's own failure, where the index is a stream it refused.
        /// `None` where nothing beneath the reason failed: an index that
        /// decodes past its stated length, or decodes to something other than
        /// text.
        source: Option<io::Error>,
    },
    /// A package shipped an entry whose path cannot be represented safely in
    /// the dpkg metadata derived from it.
    ///
    /// The message quotes the path with `{:?}`: it is the package's own
    /// spelling, and one holding a newline is what this refuses.
    #[non_exhaustive]
    MalformedEntry {
        /// The package that shipped it, by the name its index states.
        package: String,
        /// The offending path, lossily decoded.
        path: String,
    },
    /// The dependency closure could not be resolved.
    #[non_exhaustive]
    Resolve {
        /// Why the closure could not be resolved.
        reason: String,
    },
    /// Bytes did not have the digest the archive recorded for them.
    ///
    /// Either a mirror served something other than the resource the release or
    /// the index named, or a cached package no longer holds the bytes it was
    /// acquired under.
    ///
    /// The bytes are held to every digest the archive recorded, SHA-256 and
    /// SHA-512 alike, and the first that differs, SHA-256 first, is the one
    /// named.
    #[non_exhaustive]
    Digest {
        /// What was checked: the URL a resource was fetched from, or the path
        /// of a cached package read back to be installed.
        subject: String,
        /// The digest the archive recorded.
        expected: Digest,
        /// The digest the bytes actually have, under the same algorithm.
        actual: Digest,
    },
    /// The bootstrap's observer asked it to stop.
    ///
    /// A provisioning run surfaces it as [`ProvisionError::Cancelled`];
    /// [`Debian::resolve`] and [`Debian::available`] return it as it is.
    Cancelled,
    /// A dpkg wave exited unsuccessfully.
    #[non_exhaustive]
    Configure {
        /// Which wave failed.
        wave: &'static str,
        /// dpkg's exit status.
        status: ExitStatus,
        /// The packages dpkg named under `Errors were encountered while
        /// processing`, in the order it listed them.
        ///
        /// Empty when dpkg failed without naming any: it exits non-zero for
        /// reasons no package owns, and an empty list says only that the wave's
        /// output held no such list. Why each package failed is not here — dpkg
        /// writes that alongside the list, and it reaches a
        /// [`DebianObserver`] as
        /// [`DebianEvent::CommandOutput`].
        ///
        /// The names are on the error, rather than in the observer's stream
        /// alone, because the observer is optional: a caller that takes no
        /// progress events, or renders them only under a verbosity flag, still
        /// has to be told which package failed.
        ///
        /// Each is as the list spelled it. A maintainer script writes to the
        /// same stream, so a name here is the sandbox's text rather than one
        /// the index vouched for, and the error's message quotes each one.
        packages: Vec<String>,
    },
    /// Packages were not left in the installed state after configuration.
    #[non_exhaustive]
    NotConfigured {
        /// The packages the status database does not record as installed and
        /// configured: in a state short of `installed`, or flagged in error.
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
    /// The resolution could not be held to a [`pin`](DebianBuilder::pin): the
    /// archives cannot supply a pinned package at its version and bytes, or the
    /// resolution asks for one from a release, or at a version, the pinned
    /// entry cannot answer. Each package's [`UnheldReason`] says which.
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
            DebianError::Fetch(_) => f.write_str("the Debian bootstrap could not fetch a resource"),
            DebianError::Signature { subject, reason } => {
                write!(f, "the signature over {subject} was not accepted: {reason}")
            }
            DebianError::Release { subject, reason } => {
                write!(f, "the release {subject} is unusable: {reason}")
            }
            DebianError::Index {
                subject, reason, ..
            } => {
                write!(f, "the index {subject} is unusable: {reason}")
            }
            DebianError::MalformedEntry { package, path } => {
                write!(
                    f,
                    "the package {package} ships an unrepresentable path: {path:?}"
                )
            }
            DebianError::Resolve { reason } => write!(f, "dependency resolution failed: {reason}"),
            DebianError::Digest {
                subject,
                expected,
                actual,
            } => write!(
                f,
                "{subject} does not have the {} digest the archive recorded for it: \
                 expected {}, got {}",
                expected.algorithm().name(),
                expected.hex(),
                actual.hex(),
            ),
            DebianError::Cancelled => f.write_str("the bootstrap was cancelled"),
            DebianError::Configure {
                wave,
                status,
                packages,
            } => {
                write!(f, "the dpkg {wave} step exited with {status}")?;
                // Each name is quoted with `{:?}`: the list is read from what
                // the wave wrote to its stderr, which a maintainer script
                // writes too, so a control character in it is escaped rather
                // than handed to the terminal the error is printed on.
                for (at, package) in packages.iter().enumerate() {
                    let lead = if at == 0 { ", processing " } else { ", " };
                    write!(f, "{lead}{package:?}")?;
                }
                Ok(())
            }
            DebianError::NotConfigured { packages } => write!(
                f,
                "these packages were not configured: {}",
                packages.join(", "),
            ),
            DebianError::Launch(_) => f.write_str("a configuration step could not launch"),
            DebianError::Overlay(_) => {
                f.write_str("the pre-configure overlay could not be applied")
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
                write!(f, "the resolution cannot be held to the pin: {held}")
            }
            DebianError::PlanDocument { reason } => {
                write!(f, "the install plan document is not usable: {reason}")
            }
            DebianError::Io { op, path, .. } => write!(
                f,
                "a Debian bootstrap step failed while {op} {}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for DebianError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DebianError::Fetch(err) => Some(err),
            DebianError::Index {
                source: Some(source),
                ..
            } => Some(source),
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

impl From<crate::Error> for DebianError {
    fn from(err: crate::Error) -> Self {
        DebianError::Launch(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    #[test]
    fn a_failed_wave_reads_as_the_step_and_the_packages() {
        // The names are the whole point of carrying them, so the rendering is
        // asserted rather than left to the Display arm's own care.
        let named = DebianError::Configure {
            wave: "configure",
            status: ExitStatus::exited(1),
            packages: vec!["systemd".to_string(), "udev".to_string()],
        };
        assert_eq!(
            named.to_string(),
            "the dpkg configure step exited with exit code 1, processing \"systemd\", \"udev\"",
        );
        let unnamed = DebianError::Configure {
            wave: "unpack",
            status: ExitStatus::exited(2),
            packages: Vec::new(),
        };
        assert_eq!(
            unnamed.to_string(),
            "the dpkg unpack step exited with exit code 2",
        );
    }

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
            digests: Digests::new(Some(Algorithm::Sha256.hex_of(body)), None).unwrap(),
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
                scratch.join(cache_name(&package.digests)).is_file(),
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
        assert!(scratch.join(cache_name(&packages[0].digests)).is_file());
    }

    #[test]
    fn a_package_is_cached_under_its_sha256_where_there_is_one_and_held_to_every_digest() {
        let body = b"the package the index named".to_vec();
        let sha256 = Algorithm::Sha256.hex_of(&body);
        let sha512 = Algorithm::Sha512.hex_of(&body);
        let served = vec![(
            "https://mirror.example/debian/pool/one.deb".to_string(),
            body.clone(),
        )];
        let with = |sha256: Option<String>, sha512: Option<String>| Wanted {
            digests: Digests::new(sha256, sha512).unwrap(),
            ..wanted("one", &body)
        };

        // A SHA-512 alone names the entry, and a SHA-256 does where there is
        // one, so an entry an earlier run cached keeps its name.
        for (package, stem) in [
            (with(None, Some(sha512.clone())), &sha512),
            (with(Some(sha256.clone()), Some(sha512.clone())), &sha256),
        ] {
            let scratch = Scratch::new("acquire-digests");
            let (outcome, _) = acquire(std::slice::from_ref(&package), &served, scratch.as_ref());
            outcome.expect("the bytes are the package");
            assert!(scratch.join(format!("{stem}.deb")).is_file());
        }

        // Either digest differing refuses the bytes, and nothing is published.
        for package in [
            with(Some(sha256.clone()), Some("0".repeat(128))),
            with(Some("0".repeat(64)), Some(sha512.clone())),
        ] {
            let scratch = Scratch::new("acquire-digests-wrong");
            let (outcome, _) = acquire(std::slice::from_ref(&package), &served, scratch.as_ref());
            assert!(outcome.is_err(), "one digest differs");
            assert!(!scratch.join(cache_name(&package.digests)).is_file());
        }
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
            !scratch.join(cache_name(&package.digests)).is_file(),
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
    fn a_corrupt_cache_entry_the_batch_misses_is_fetched_from_another_mirror() {
        // An entry left short by a crash is a download waiting to happen, and
        // the walk behind the batch is what has every mirror. Asked only whether
        // the entry exists, the walk would skip it, never ask the backstop, and
        // leave every later run to fail extracting the same corrupt file.
        let scratch = Scratch::new("acquire-corrupt-entry");
        let body = b"the real package".to_vec();
        let package = wanted("one", &body);
        let dest = scratch.join(cache_name(&package.digests));
        std::fs::write(&dest, b"short").expect("the corrupt entry is writable");
        let repositories = vec![
            Repository::builder("trixie")
                .mirror("https://live.example/debian")
                .mirror_fallback("https://snapshot.example/debian")
                .trust_unsigned(true)
                .build()
                .expect("the repository builds"),
        ];
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        // The live mirror has rotated the version out, so the batch, which asks
        // the first mirror only, does not deliver it.
        let mut fetcher = Table {
            bodies: [(
                "https://snapshot.example/debian/pool/one.deb".to_string(),
                body.clone(),
            )]
            .into_iter()
            .collect(),
            asked: std::sync::Arc::clone(&asked),
        };

        acquire_debs(
            &mut fetcher,
            &repositories,
            std::slice::from_ref(&package),
            scratch.as_ref(),
            &mut Silent,
        )
        .expect("the backstop serves the package");

        assert_eq!(
            std::fs::read(&dest).unwrap(),
            body,
            "the entry was replaced"
        );
        let asked = asked.lock().unwrap().clone();
        assert_eq!(
            asked,
            [
                "https://live.example/debian/pool/one.deb",
                "https://live.example/debian/pool/one.deb",
                "https://snapshot.example/debian/pool/one.deb",
            ],
            "the batch, then the walk over every mirror",
        );
    }

    #[test]
    fn a_download_is_announced_over_what_is_being_downloaded() {
        // The event fires for a cache miss and only for one, so counting the
        // plan's packages would report a fetch of one package out of two as
        // reaching two of two. `index` of `total` counts the downloads.
        let scratch = Scratch::new("acquire-download-count");
        let one = b"the first package".to_vec();
        let two = b"the second package".to_vec();
        let packages = vec![wanted("one", &one), wanted("two", &two)];
        // The first is cached already, the everyday state of a second run.
        std::fs::write(scratch.join(cache_name(&packages[0].digests)), &one)
            .expect("the cached package is writable");
        let repositories = vec![
            Repository::builder("trixie")
                .mirror("https://mirror.example/debian")
                .trust_unsigned(true)
                .build()
                .expect("the repository builds"),
        ];
        let mut fetcher = Table {
            bodies: [(
                "https://mirror.example/debian/pool/two.deb".to_string(),
                two,
            )]
            .into_iter()
            .collect(),
            asked: std::sync::Arc::default(),
        };

        let mut announced: Vec<(String, usize, usize)> = Vec::new();
        let mut sink = |event: DebianEvent<'_>| {
            if let DebianEvent::Downloading {
                package,
                index,
                total,
            } = event
            {
                announced.push((package.to_string(), index, total));
            }
        };
        acquire_debs(
            &mut fetcher,
            &repositories,
            &packages,
            scratch.as_ref(),
            &mut sink,
        )
        .expect("both packages are acquired");
        assert_eq!(announced, [("two".to_string(), 1, 1)]);
    }

    /// An observer that lets `allowed` checks pass and cancels from then on,
    /// counting how many times it was asked.
    struct CancelAfter {
        allowed: usize,
        asked: usize,
    }

    impl DebianObserver for CancelAfter {
        fn cancelled(&mut self) -> bool {
            self.asked += 1;
            self.asked > self.allowed
        }
    }

    /// A release for `trixie` on amd64 whose one index is `index`, served
    /// uncompressed, and the transport answering both from one mirror.
    fn unsigned_archive(index: &[u8]) -> (Debian, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let release = format!(
            "Suite: trixie\nArchitectures: amd64\nComponents: main\nSHA256:\n {} {} \
             main/binary-amd64/Packages\n",
            Algorithm::Sha256.hex_of(index),
            index.len(),
        );
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fetcher = Table {
            bodies: [
                (
                    "https://mirror.example/debian/dists/trixie/Release".to_string(),
                    release.into_bytes(),
                ),
                (
                    "https://mirror.example/debian/dists/trixie/main/binary-amd64/Packages"
                        .to_string(),
                    index.to_vec(),
                ),
            ]
            .into_iter()
            .collect(),
            asked: std::sync::Arc::clone(&asked),
        };
        let debian = Debian::builder("trixie")
            .architecture("amd64")
            .mirror("https://mirror.example/debian")
            .trust_unsigned(true)
            .fetcher(fetcher)
            .build()
            .expect("the builder validates");
        (debian, asked)
    }

    #[test]
    fn the_merged_index_reports_what_it_offers_and_what_it_left_out() {
        /// Records every `Index` event as its two counts.
        struct Counts(Vec<(usize, usize)>);
        impl DebianObserver for Counts {
            fn progress(&mut self, event: DebianEvent<'_>) {
                if let DebianEvent::Index { packages, skipped } = event {
                    self.0.push((packages, skipped));
                }
            }
        }

        let digest = "0".repeat(64);
        let stanza = |name: &str, architecture: &str, filename: &str, sha256: &str| {
            format!(
                "Package: {name}\nVersion: 1\nArchitecture: {architecture}\n\
                 Filename: {filename}\nSHA256: {sha256}\n\n"
            )
        };
        let index = [
            stanza("kept", "amd64", "pool/kept.deb", &digest),
            stanza("also-kept", "all", "pool/also-kept.deb", &digest),
            // Another architecture's is not this bootstrap's, and not counted.
            stanza("foreign", "arm64", "pool/foreign.deb", &digest),
            // Each of these is one this layer cannot act on.
            stanza("escaping", "amd64", "../../etc/passwd", &digest),
            stanza("undigested", "amd64", "pool/undigested.deb", "not-a-digest"),
            "Version: 1\nArchitecture: amd64\n\n".to_string(),
            stanza("Shouted", "amd64", "pool/shouted.deb", &digest),
            stanza("unversioned", "amd64", "pool/unversioned.deb", &digest)
                .replace("Version: 1", "Version: 1_0"),
        ]
        .concat();
        let (mut debian, _) = unsigned_archive(index.as_bytes());
        let mut counts = Counts(Vec::new());
        let available = debian
            .observe(&mut counts)
            .available()
            .expect("the index is read");
        assert!(available.contains("kept") && available.contains("also-kept"));
        assert_eq!(counts.0, [(2, 5)]);
    }

    #[test]
    fn a_release_s_indexes_are_asked_of_the_mirror_that_served_it_first() {
        // A live mirror and a backstop, each publishing its own state under the
        // same names and at the same length. The live one serves no release, so
        // the backstop's is the one read, and the index it records is the
        // backstop's: the live mirror's, asked for first, would fail the digest
        // check, which ends a walk rather than advancing it.
        let dir = Scratch::new("index-from-the-serving-mirror");
        let stanza = |name: &str| {
            format!(
                "Package: {name}\nVersion: 1\nArchitecture: amd64\nFilename: pool/{name}.deb\n\
                 SHA256: {}\n",
                "0".repeat(64),
            )
        };
        let packages = "dists/trixie/main/binary-amd64/Packages";
        let live = dir.join("live");
        let backstop = dir.join("backstop");
        for (mirror, index) in [(&live, stanza("fresh")), (&backstop, stanza("stale"))] {
            let path = mirror.join(packages);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a mirror tree");
            std::fs::write(path, index).expect("the index is written");
        }
        let recorded = stanza("stale");
        std::fs::write(
            backstop.join("dists/trixie/Release"),
            format!(
                "Suite: trixie\nArchitectures: amd64\nComponents: main\nSHA256:\n {} {} \
                 main/binary-amd64/Packages\n",
                Algorithm::Sha256.hex_of(recorded.as_bytes()),
                recorded.len(),
            ),
        )
        .expect("the release is written");

        let mut debian = Debian::builder("trixie")
            .architecture("amd64")
            .mirror(crate::provision::file_url(&live).expect("a file:// URL"))
            .mirror_fallback(crate::provision::file_url(&backstop).expect("a file:// URL"))
            .trust_unsigned(true)
            .build()
            .expect("the builder validates");
        let available = debian
            .available()
            .expect("the index the backstop's release records is read");
        assert!(available.contains("stale"));
        assert!(!available.contains("fresh"));
    }

    #[test]
    fn a_resolve_and_an_availability_query_stop_at_the_first_mirror_boundary() {
        // Neither runs inside a provisioning run, so the sink is the only thing
        // that can stop them, and the release walk is the first place it is
        // asked: nothing has been fetched yet.
        let (mut debian, asked) = unsigned_archive(b"");
        let mut stop = CancelAfter {
            allowed: 0,
            asked: 0,
        };
        assert!(matches!(
            debian.observe(&mut stop).resolve(),
            Err(DebianError::Cancelled)
        ));
        assert!(matches!(
            debian.observe(&mut stop).available(),
            Err(DebianError::Cancelled)
        ));
        assert!(
            asked.lock().unwrap().is_empty(),
            "{:?}",
            asked.lock().unwrap()
        );
    }

    #[test]
    fn a_resolve_stops_between_the_release_and_the_index() {
        // The index walk asks at each mirror too, so a resolve stopped once the
        // release has arrived fetches no index.
        let (mut debian, asked) = unsigned_archive(b"Package: p\n");
        let mut stop = CancelAfter {
            allowed: 1,
            asked: 0,
        };
        assert!(matches!(
            debian.observe(&mut stop).resolve(),
            Err(DebianError::Cancelled)
        ));
        assert_eq!(
            *asked.lock().unwrap(),
            ["https://mirror.example/debian/dists/trixie/Release"],
        );
    }

    #[test]
    fn a_bound_sink_cancels_a_provisioning_run() {
        // The sink's `cancelled` is the one its trait documents, so a run that
        // reports to it stops when it says so, as a resolve does; the run's own
        // observer is not the only one asked.
        let scratch = Scratch::new("debian-sink-cancels");
        let (mut debian, asked) = unsigned_archive(b"");
        let mut stop = CancelAfter {
            allowed: 0,
            asked: 0,
        };
        let outcome =
            crate::provision::ensure(scratch.join("root"), &mut debian.observe(&mut stop));
        assert!(
            matches!(outcome, Err(ProvisionError::Cancelled)),
            "{outcome:?}",
        );
        assert!(
            asked.lock().unwrap().is_empty(),
            "{:?}",
            asked.lock().unwrap()
        );
        assert!(
            !scratch.join("root").exists(),
            "a cancelled run publishes nothing"
        );
    }

    #[test]
    fn an_index_that_expands_past_its_stated_length_is_refused() {
        // The release states the uncompressed index's length, and that bounds
        // the decompression the way the compressed length bounds the fetch: a
        // few megabytes of xz may expand into gigabytes the digest says nothing
        // about. Refused, not truncated, so no prefix of it is ever parsed.
        use std::io::Write as _;
        let text = b"Package: p\nVersion: 1\n".repeat(64);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&text).unwrap();
        let compressed = encoder.finish().unwrap();
        let url = "https://mirror.example/debian/dists/trixie/main/binary-amd64/Packages.gz";

        let err = decompress_index(url, &compressed, text.len() as u64 - 1)
            .expect_err("an index longer than stated is refused");
        // Nothing failed beneath the length, so there is no cause to carry.
        assert!(
            matches!(&err, DebianError::Index { subject, reason, source: None }
                if subject == url && reason.contains("expands past")),
            "{err}",
        );
        assert_eq!(
            decompress_index(url, &compressed, text.len() as u64)
                .unwrap()
                .as_bytes(),
            &text[..],
        );
    }

    /// A release declaring `Acquire-By-Hash` whose one index is `index`, and a
    /// transport answering the release and whatever `serve` adds.
    fn by_hash_archive(
        index: &[u8],
        serve: &[(String, Vec<u8>)],
    ) -> (Debian, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let release = format!(
            "Suite: trixie\nArchitectures: amd64\nComponents: main\nAcquire-By-Hash: yes\n\
             SHA256:\n {} {} main/binary-amd64/Packages\n",
            Algorithm::Sha256.hex_of(index),
            index.len(),
        );
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut bodies: std::collections::HashMap<String, Vec<u8>> =
            serve.iter().cloned().collect();
        bodies.insert(
            "https://mirror.example/debian/dists/trixie/Release".to_string(),
            release.into_bytes(),
        );
        let fetcher = Table {
            bodies,
            asked: std::sync::Arc::clone(&asked),
        };
        let debian = Debian::builder("trixie")
            .architecture("amd64")
            .mirror("https://mirror.example/debian")
            .trust_unsigned(true)
            .fetcher(fetcher)
            .build()
            .expect("the builder validates");
        (debian, asked)
    }

    /// A release whose one index is `index`, listed under `sections` (each
    /// `"SHA256"` or `"SHA512"`, with the digest it states for the index), with
    /// `Acquire-By-Hash`, and a transport answering the release and `serve`.
    fn sectioned_archive(
        index: &[u8],
        sections: &[(&str, String)],
        serve: &[(String, Vec<u8>)],
    ) -> (Debian, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let mut release = "Suite: trixie\nArchitectures: amd64\nComponents: main\n\
                           Acquire-By-Hash: yes\n"
            .to_string();
        for (section, digest) in sections {
            release.push_str(&format!(
                "{section}:\n {digest} {} main/binary-amd64/Packages\n",
                index.len()
            ));
        }
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut bodies: std::collections::HashMap<String, Vec<u8>> =
            serve.iter().cloned().collect();
        bodies.insert(
            "https://mirror.example/debian/dists/trixie/Release".to_string(),
            release.into_bytes(),
        );
        let fetcher = Table {
            bodies,
            asked: std::sync::Arc::clone(&asked),
        };
        let debian = Debian::builder("trixie")
            .architecture("amd64")
            .mirror("https://mirror.example/debian")
            .trust_unsigned(true)
            .fetcher(fetcher)
            .build()
            .expect("the builder validates");
        (debian, asked)
    }

    #[test]
    fn an_index_is_held_to_every_digest_its_release_records() {
        let index = format!(
            "Package: pp\nVersion: 1\nArchitecture: amd64\nFilename: pool/p.deb\nSHA512: {}\n",
            "0".repeat(128)
        );
        let index = index.as_bytes();
        let sha256 = Algorithm::Sha256.hex_of(index);
        let sha512 = Algorithm::Sha512.hex_of(index);
        let base = "https://mirror.example/debian/dists/trixie/main/binary-amd64";
        let named = format!("{base}/Packages");

        // Listed under SHA512 alone, as Ubuntu's development series lists its
        // indexes: asked for by that digest, and its package read by its own.
        let by_sha512 = format!("{base}/by-hash/SHA512/{sha512}");
        let (mut debian, asked) = sectioned_archive(
            index,
            &[("SHA512", sha512.clone())],
            &[(by_sha512.clone(), index.to_vec())],
        );
        let available = debian
            .available()
            .expect("the index is read by its SHA-512");
        assert!(available.contains("pp"));
        assert_eq!(asked.lock().unwrap()[1..], [by_sha512]);

        // Listed under both, it is asked for by the stronger, and refused if
        // either digest differs, as apt refuses it, naming the one that does.
        for (stated256, stated512, differs) in [
            (sha256.clone(), "0".repeat(128), Algorithm::Sha512),
            ("0".repeat(64), sha512.clone(), Algorithm::Sha256),
        ] {
            let (mut debian, asked) = sectioned_archive(
                index,
                &[("SHA256", stated256), ("SHA512", stated512.clone())],
                &[
                    (format!("{base}/by-hash/SHA512/{stated512}"), index.to_vec()),
                    (named.clone(), index.to_vec()),
                ],
            );
            let err = debian.available().expect_err("one digest differs");
            match &err {
                DebianError::Digest {
                    expected, actual, ..
                } => {
                    assert_eq!(expected.algorithm(), differs);
                    assert_eq!(*actual, Digest::of(differs, index));
                    let rendered = err.to_string();
                    let named = format!("the {} digest", differs.name());
                    assert!(rendered.contains(&named), "{rendered}");
                }
                other => panic!("expected a digest refusal, got {other}"),
            }
            assert!(
                asked.lock().unwrap()[1].contains("/by-hash/SHA512/"),
                "{:?}",
                asked.lock().unwrap()
            );
        }
    }

    #[test]
    fn a_mirror_without_the_by_hash_copies_serves_the_index_by_name() {
        // A partial mirror or a caching proxy carries the named index and not
        // the by-hash copies. apt asks for the digest first and the name last,
        // and so does this.
        let index = b"Package: pp\nVersion: 1\nArchitecture: amd64\nFilename: pool/p.deb\n\
                      SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n";
        let named = "https://mirror.example/debian/dists/trixie/main/binary-amd64/Packages";
        let by_hash = format!(
            "https://mirror.example/debian/dists/trixie/main/binary-amd64/by-hash/SHA256/{}",
            Algorithm::Sha256.hex_of(index),
        );
        let (mut debian, asked) = by_hash_archive(index, &[(named.to_string(), index.to_vec())]);
        let available = debian.available().expect("the index is served by name");
        assert!(available.contains("pp"));
        assert_eq!(
            asked.lock().unwrap()[1..],
            [by_hash.clone(), named.to_string()],
            "the digest path first, the name last",
        );

        // Bytes that arrive at the digest path and do not match it are a
        // refusal, not a reason to ask elsewhere: the name is never asked.
        let (mut debian, asked) = by_hash_archive(
            index,
            &[
                (by_hash.clone(), b"something else".to_vec()),
                (named.to_string(), index.to_vec()),
            ],
        );
        let err = debian.available().expect_err("the by-hash bytes are wrong");
        assert!(matches!(err, DebianError::Digest { .. }), "{err}");
        assert!(
            !asked.lock().unwrap().iter().any(|url| url == named),
            "{:?}",
            asked.lock().unwrap(),
        );
    }

    /// One index stanza for `name` at `version`, its digest standing in for a
    /// package nothing downloads, with `extra` fields.
    fn index_stanza(name: &str, version: &str, extra: &str) -> String {
        format!(
            "Package: {name}\nVersion: {version}\nArchitecture: amd64\n\
             Filename: pool/{name}_{version}.deb\nSHA256: {}\n{extra}\n",
            Algorithm::Sha256.hex_of(format!("{name}{version}").as_bytes()),
        )
    }

    /// The release body of `suite`, offering one uncompressed index `index`,
    /// with `extra` fields.
    fn release_of(suite: &str, extra: &str, index: &str) -> String {
        format!(
            "Suite: {suite}\nArchitectures: amd64\nComponents: main\n{extra}SHA256:\n \
             {} {} main/binary-amd64/Packages\n",
            Algorithm::Sha256.hex_of(index.as_bytes()),
            index.len(),
        )
    }

    /// A trixie primary, and an `experimental` repository whose release is
    /// signed by a key of the test's and marked as `experimental` is marked.
    fn trixie_with_experimental(scratch: &Scratch) -> DebianBuilder {
        use crate::provision::openpgp::fixture;
        let primary = format!(
            "{}{}",
            index_stanza("base-files", "13.8", "Priority: required\n"),
            index_stanza("libc6", "2.41", "Priority: required\n"),
        );
        let experimental = format!(
            "{}{}{}",
            index_stanza("libc6", "2.43", "Priority: required\n"),
            index_stanza("tool", "2.0", "Depends: libc6 (>= 2.43)\n"),
            index_stanza("vendor-required", "1.0", "Priority: required\n"),
        );
        let key = fixture::signing_key("experimental <archive@test.invalid>");
        let keyring = scratch.join("experimental.gpg");
        std::fs::write(&keyring, fixture::binary([key.to_public_key()]))
            .expect("the keyring is writable");
        let signed = fixture::clearsign(
            &key,
            &release_of("experimental", "NotAutomatic: yes\n", &experimental),
        );
        let fetcher = Table {
            bodies: [
                (
                    "https://deb.example/debian/dists/trixie/Release".to_string(),
                    release_of("trixie", "", &primary).into_bytes(),
                ),
                (
                    "https://deb.example/debian/dists/trixie/main/binary-amd64/Packages"
                        .to_string(),
                    primary.into_bytes(),
                ),
                (
                    "https://exp.example/debian/dists/experimental/InRelease".to_string(),
                    signed.into_bytes(),
                ),
                (
                    "https://exp.example/debian/dists/experimental/main/binary-amd64/Packages"
                        .to_string(),
                    experimental.into_bytes(),
                ),
            ]
            .into_iter()
            .collect(),
            asked: std::sync::Arc::default(),
        };
        Debian::builder("trixie")
            .architecture("amd64")
            .mirror("https://deb.example/debian")
            .trust_unsigned(true)
            .repository(
                Repository::builder("experimental")
                    .mirror("https://exp.example/debian")
                    .keyring(&keyring)
                    .build()
                    .expect("the repository builds"),
            )
            .fetcher(fetcher)
    }

    /// Each planned package's name, version, and the archive it came from.
    fn planned(plan: &Plan) -> Vec<(String, String, usize)> {
        plan.packages
            .iter()
            .map(|p| (p.name.clone(), p.version.clone(), p.archive))
            .collect()
    }

    #[test]
    fn a_release_marked_not_automatic_supplies_only_what_it_is_asked_for() {
        // experimental carries a newer libc6 and marks a package of its own
        // required. Named alongside the primary, it supplies neither: its
        // marking ranks it below trixie, and the base is seeded from the
        // primary alone.
        let scratch = Scratch::new("debian-not-automatic");
        let plan = trixie_with_experimental(&scratch)
            .build()
            .expect("the builder validates")
            .resolve()
            .expect("the merged plan resolves");
        assert_eq!(
            planned(&plan),
            [
                ("base-files".into(), "13.8".into(), 0),
                ("libc6".into(), "2.41".into(), 0)
            ],
        );

        // Asked for by release, experimental supplies the package and the
        // libc6 it needs, which trixie's cannot satisfy.
        let plan = trixie_with_experimental(&scratch)
            .include(["tool/experimental"])
            .build()
            .expect("the builder validates")
            .resolve()
            .expect("the merged plan resolves");
        assert_eq!(
            planned(&plan),
            [
                ("base-files".into(), "13.8".into(), 0),
                ("libc6".into(), "2.43".into(), 1),
                ("tool".into(), "2.0".into(), 1),
            ],
        );
    }

    #[test]
    fn a_release_the_selection_names_must_be_one_a_repository_publishes() {
        let scratch = Scratch::new("debian-named-release");
        let refused = trixie_with_experimental(&scratch)
            .include(["tool/sid"])
            .build();
        assert!(
            matches!(&refused, Err(DebianError::Config { reason }) if reason.contains("\"sid\"")),
            "{refused:?}",
        );
        let refused = trixie_with_experimental(&scratch)
            .exclude(["libc6/experimental"])
            .build();
        assert!(
            matches!(&refused, Err(DebianError::Config { reason }) if reason.contains("exclude")),
            "{refused:?}",
        );
    }

    #[test]
    fn a_stream_the_decoder_refuses_is_not_reported_as_too_long() {
        // A corrupt stream and an over-long one are different faults with
        // different remedies, so they read differently, and the decoder's own
        // refusal is the cause rather than a string folded into the reason.
        use std::io::Write as _;
        let text = b"Package: p\nVersion: 1\n".repeat(64);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&text).unwrap();
        let mut corrupt = encoder.finish().unwrap();
        // Past the ten-byte header, inside the deflate stream.
        for byte in &mut corrupt[12..20] {
            *byte ^= 0xff;
        }
        let url = "https://mirror.example/debian/dists/trixie/main/binary-amd64/Packages.gz";

        let err = decompress_index(url, &corrupt, MAX_UNSIZED_INDEX)
            .expect_err("a corrupt stream is refused");
        match &err {
            DebianError::Index {
                reason,
                source: Some(_),
                ..
            } => assert!(!reason.contains("expands past"), "{err}"),
            other => panic!("expected the decoder's refusal as the cause, got {other:?}"),
        }
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn a_release_that_states_the_uncompressed_length_bounds_the_index() {
        // End to end: the release lists the compressed index the mirror serves
        // and an uncompressed length shorter than what it expands to.
        use std::io::Write as _;
        let text = b"Package: p\nVersion: 1\nArchitecture: amd64\n".repeat(16);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&text).unwrap();
        let compressed = encoder.finish().unwrap();
        let release = format!(
            "Suite: trixie\nArchitectures: amd64\nComponents: main\nSHA256:\n {} {} \
             main/binary-amd64/Packages.gz\n {} {} main/binary-amd64/Packages\n",
            Algorithm::Sha256.hex_of(&compressed),
            compressed.len(),
            Algorithm::Sha256.hex_of(&text),
            text.len() / 2,
        );
        let fetcher = Table {
            bodies: [
                (
                    "https://mirror.example/debian/dists/trixie/Release".to_string(),
                    release.into_bytes(),
                ),
                (
                    "https://mirror.example/debian/dists/trixie/main/binary-amd64/Packages.gz"
                        .to_string(),
                    compressed,
                ),
            ]
            .into_iter()
            .collect(),
            asked: std::sync::Arc::default(),
        };
        let mut debian = Debian::builder("trixie")
            .architecture("amd64")
            .mirror("https://mirror.example/debian")
            .trust_unsigned(true)
            .fetcher(fetcher)
            .build()
            .expect("the builder validates");
        let err = debian
            .available()
            .expect_err("the index is longer than stated");
        assert!(
            matches!(&err, DebianError::Index { subject, .. } if subject.ends_with("Packages.gz")),
            "{err}",
        );
    }

    #[test]
    fn a_release_listing_no_index_for_a_component_is_reported_against_the_release() {
        // The release offers the component and states no index for it, which is
        // the release not offering what was asked rather than an index failing.
        let release = "Suite: trixie\nArchitectures: amd64\nComponents: main\nSHA256:\n";
        let fetcher = Table {
            bodies: [(
                "https://mirror.example/debian/dists/trixie/Release".to_string(),
                release.as_bytes().to_vec(),
            )]
            .into_iter()
            .collect(),
            asked: std::sync::Arc::default(),
        };
        let mut debian = Debian::builder("trixie")
            .architecture("amd64")
            .mirror("https://mirror.example/debian")
            .trust_unsigned(true)
            .fetcher(fetcher)
            .build()
            .expect("the builder validates");
        let err = debian.available().expect_err("the release lists no index");
        assert!(
            matches!(&err, DebianError::Release { subject, reason }
                if subject == "https://mirror.example/debian/dists/trixie/Release"
                    && reason.contains("no index for component main")),
            "{err}",
        );
    }

    #[test]
    fn a_release_listing_no_architectures_or_components_is_held_to_its_digests() {
        // A release naming only its codename, as `apt-ftparchive release`
        // writes one configured with nothing else. It offers every
        // architecture and component, and serves only the indexes it lists.
        let index = index_stanza("tool", "1.0", "");
        let release = format!(
            "Codename: local\nSHA256:\n {} {} main/binary-amd64/Packages\n",
            Algorithm::Sha256.hex_of(index.as_bytes()),
            index.len(),
        );
        let archive = |components: &[&str]| {
            let fetcher = Table {
                bodies: [
                    (
                        "https://mirror.example/debian/dists/local/Release".to_string(),
                        release.clone().into_bytes(),
                    ),
                    (
                        "https://mirror.example/debian/dists/local/main/binary-amd64/Packages"
                            .to_string(),
                        index.clone().into_bytes(),
                    ),
                ]
                .into_iter()
                .collect(),
                asked: std::sync::Arc::default(),
            };
            Debian::builder("local")
                .architecture("amd64")
                .components(components.iter().copied())
                .mirror("https://mirror.example/debian")
                .trust_unsigned(true)
                .fetcher(fetcher)
                .build()
                .expect("the builder validates")
        };
        let available = archive(&["main"])
            .available()
            .expect("the listed index is read");
        assert!(available.contains("tool"));
        let err = archive(&["main", "contrib"])
            .available()
            .expect_err("the release lists no index for contrib");
        assert!(
            matches!(&err, DebianError::Release { reason, .. }
                if reason.contains("no index for component contrib")),
            "{err}",
        );
    }

    #[test]
    fn a_release_is_accepted_expired_only_from_a_snapshot_backstop() {
        // A real release with a real expiry, long past, signed by the embedded
        // keyring. Served by the live mirror it is refused, however the
        // backstops are configured; served by a snapshot backstop it is
        // accepted, and the run goes on to ask for the index, which nothing
        // serves here. A plain backstop is held to freshness as the live
        // mirror is.
        const INRELEASE: &[u8] =
            include_bytes!("../../../tests/fixtures/debian-archive/forky-InRelease");
        const LIVE: &str = "http://live.example/debian";
        const SNAPSHOT: &str = "http://snapshot.example/debian/20260721T000000Z";
        let answering = |mirror: &str, snapshot: bool| {
            let fetcher = Table {
                bodies: [(
                    format!("{mirror}/dists/forky/InRelease"),
                    INRELEASE.to_vec(),
                )]
                .into_iter()
                .collect(),
                asked: std::sync::Arc::default(),
            };
            let builder = Debian::builder("forky")
                .architecture("amd64")
                .mirror(LIVE)
                .fetcher(fetcher);
            let builder = if snapshot {
                builder.snapshot_fallback(SNAPSHOT)
            } else {
                builder.mirror_fallback(SNAPSHOT)
            };
            builder
                .build()
                .expect("the builder validates")
                .available()
                .expect_err("nothing serves the index")
        };

        for snapshot in [true, false] {
            let refused = answering(LIVE, snapshot);
            assert!(
                matches!(&refused, DebianError::Release { reason, .. } if reason.contains("expired")),
                "{refused:?}",
            );
        }
        let held = answering(SNAPSHOT, false);
        assert!(
            matches!(&held, DebianError::Release { reason, .. } if reason.contains("expired")),
            "{held:?}",
        );
        let accepted = answering(SNAPSHOT, true);
        assert!(
            matches!(&accepted, DebianError::Fetch(FetchError::NotFound { url }) if url.contains("Packages")),
            "{accepted:?}",
        );
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

        // The digest is of the file the mirror served, signature included, so
        // `sha256sum` over the InRelease gives it.
        assert_eq!(served.sha256.hex(), Algorithm::Sha256.hex_of(INRELEASE));

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
        let reason = ErrorChain::new(&result.unwrap_err()).to_string();
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
        let reason = ErrorChain::new(&result.unwrap_err()).to_string();
        assert!(reason.contains("last.example"), "{reason}");
        assert!(!reason.contains("first.example"), "{reason}");
    }

    #[test]
    fn a_release_past_the_signed_document_ceiling_is_refused_as_it_arrives() {
        // A release is the trust root, so nothing signed declares its length,
        // and a transport is free to ignore the size a request states. The
        // ceiling travels with the request for a transport that honours it, and
        // the sink holds it for one that does not, so an oversized release is
        // refused before it is held rather than after.
        struct Serving {
            body: Vec<u8>,
            asked: Option<u64>,
        }
        impl Fetch for Serving {
            fn fetch(
                &mut self,
                request: &FetchRequest<'_>,
                sink: &mut dyn std::io::Write,
            ) -> Result<(), FetchError> {
                self.asked = request.size();
                sink.write_all(&self.body)
                    .map_err(|err| FetchError::io("writing the body", request.url(), err))
            }
        }
        let ceiling = usize::try_from(MAX_SIGNED_DOCUMENT_BYTES).unwrap();
        let mirrors = ["http://mirror.example/debian".to_string()];
        let fetch = |len: usize| {
            let mut fetcher = Serving {
                body: vec![b'x'; len],
                asked: None,
            };
            let result = fetch_from_mirrors(
                &mut fetcher,
                &mirrors,
                "dists/stable/InRelease",
                &mut Silent,
            );
            assert_eq!(fetcher.asked, Some(MAX_SIGNED_DOCUMENT_BYTES));
            result
        };
        let (bytes, _) = fetch(ceiling).expect("a release at the ceiling is fetched");
        assert_eq!(bytes.len(), ceiling);
        assert!(
            matches!(
                fetch(ceiling + 1),
                Err(DebianError::Fetch(FetchError::Io { .. }))
            ),
            "a release past the ceiling is refused",
        );
    }

    #[test]
    fn the_embedded_keyring_parses() {
        // The vendored keyring must be a valid binary OpenPGP keyring that
        // irongall reads; parsing succeeds only with at least one key whose
        // signatures can be verified.
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
    fn the_primary_anchor_records_whose_keyring_it_is() {
        // The finished root names the keyring package's file for the embedded
        // keyring and writes a caller's at a stem of its own, so the primary
        // has to remember which of the two verified it, whatever the bytes.
        let default = Debian::builder("trixie").build().unwrap();
        assert!(matches!(
            default.repositories[0].trust,
            repository::Trust::Archive
        ));

        let scratch = Scratch::new("primary-anchor-provenance");
        let path = scratch.join("caller.gpg");
        // The embedded keyring's own bytes, named by the caller: still the
        // caller's to keep current.
        std::fs::write(&path, EMBEDDED_KEYRING).unwrap();
        let named = Debian::builder("trixie").keyring(&path).build().unwrap();
        assert!(matches!(
            &named.repositories[0].trust,
            repository::Trust::Signed(bytes) if bytes == EMBEDDED_KEYRING
        ));
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
    fn a_source_date_epoch_reaches_the_maintainer_scripts_only_when_set() {
        let named = |env: &[(String, String)]| {
            env.iter()
                .find(|(name, _)| name == "SOURCE_DATE_EPOCH")
                .map(|(_, value)| value.clone())
        };
        assert_eq!(named(&maintainer_env(None)), None);
        assert_eq!(
            named(&maintainer_env(Some(1_700_000_000))).as_deref(),
            Some("1700000000"),
        );

        let mut debian = Debian::builder("trixie")
            .source_date_epoch(1_700_000_000)
            .build()
            .expect("the builder validates");
        let (config, _) = debian.split();
        assert_eq!(config.source_date_epoch, Some(1_700_000_000));
    }

    #[test]
    fn an_extract_only_increment_is_refused() {
        // A layered build registers its increment by running dpkg over the
        // merged view, which an extract-only run never does.
        let refused = Debian::builder("trixie")
            .base_layer("/var/cache/build/base")
            .extract_only(true)
            .build();
        assert!(
            matches!(&refused, Err(DebianError::Config { reason }) if reason.contains("extract_only")),
            "{refused:?}",
        );
        // Either alone is a configuration.
        assert!(
            Debian::builder("trixie")
                .base_layer("/var/cache/build/base")
                .build()
                .is_ok()
        );
        assert!(Debian::builder("trixie").extract_only(true).build().is_ok());
    }

    #[test]
    fn a_keyring_named_for_a_primary_trusted_unsigned_is_refused() {
        // One setting asks for the release to be verified and the other for it
        // not to be, and neither may quietly win. The keyring is not read: the
        // path named here does not exist, and the refusal is the contradiction
        // rather than the missing file.
        let refused = Debian::builder("trixie")
            .mirror("file:///srv/debs")
            .keyring("/nonexistent/keyring.gpg")
            .trust_unsigned(true)
            .build();
        assert!(
            matches!(&refused, Err(DebianError::Config { reason })
                if reason.contains("trust_unsigned") && reason.contains("keyring.gpg")),
            "{refused:?}",
        );
        // Either alone is a configuration.
        assert!(
            Debian::builder("trixie")
                .mirror("file:///srv/debs")
                .trust_unsigned(true)
                .build()
                .is_ok()
        );
        let scratch = Scratch::new("debian-primary-keyring");
        let keyring = scratch.join("archive-keyring.gpg");
        std::fs::write(&keyring, EMBEDDED_KEYRING).expect("the keyring is writable");
        let mut debian = Debian::builder("trixie")
            .keyring(&keyring)
            .build()
            .expect("a keyring alone is a configuration");
        let (config, _) = debian.split();
        assert!(matches!(
            config.repositories[0].trust,
            repository::Trust::Signed(_)
        ));
    }

    #[test]
    fn a_negative_source_date_epoch_is_refused() {
        // The account tools read the variable as unsigned and date from the
        // clock when it is negative, so the setting would silently do nothing.
        // Zero is 1970 and is a date they accept.
        let refused = Debian::builder("trixie").source_date_epoch(-1).build();
        assert!(
            matches!(&refused, Err(DebianError::Config { reason }) if reason.contains("negative")),
            "{refused:?}",
        );
        assert!(
            Debian::builder("trixie")
                .source_date_epoch(0)
                .build()
                .is_ok()
        );
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
        let names: Vec<_> = crate::provision::document::parse(&merged)
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
                    digests: Digests::new(Some(sha256), None).unwrap(),
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

        let overrides = extract_packages(&staging, None, "amd64", &install, &archives, &mut Silent)
            .expect("both packages extract");

        // One record per path, each carrying the mode of the file that survived
        // — the last entry to describe it, which is the extraction's own rule.
        assert_eq!(
            overrides.render(),
            "root root 755 /usr/bin/tool\nroot root 4755 /usr/sbin/helper\n",
        );
    }

    #[test]
    fn an_unrepresentable_path_is_refused_naming_its_package_with_its_control_characters_escaped() {
        // The path is the package's own spelling, and the newline that makes
        // it unrepresentable in a statoverride record is a control character
        // the refusal would otherwise write to the terminal raw, beside
        // whatever else the path carries.
        let hostile = crate::failure::hostile::TEXT;
        let dir = Scratch::new("malformed-entry");
        let archives = dir.join("archives");
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).expect("the staging tree is creatable");
        let path = format!("./usr/sbin/{hostile}\nhelper");
        let shipped = deb_of(&data_tar(&[(path.as_str(), 0o4755, 0, 42)]));
        let install = installables(&archives, &[("shipper", shipped)]);

        let Err(ProvisionError::Other { source }) =
            extract_packages(&staging, None, "amd64", &install, &archives, &mut Silent)
        else {
            panic!("the path is refused");
        };
        let refused = source
            .downcast_ref::<DebianError>()
            .expect("the refusal is the layer's own");
        assert!(
            matches!(refused, DebianError::MalformedEntry { package, .. } if package == "shipper"),
            "{refused:?}",
        );
        crate::failure::hostile::assert_escaped(&crate::ErrorChain::new(refused).to_string());
    }

    #[test]
    fn an_increment_takes_its_layout_from_the_base_it_is_staged_over() {
        // A whole root is given the merged-usr farm; an increment is not, since
        // its base already decides what `/bin` is. Over a merged-usr base the
        // package's `bin/` entry goes through the base's link, carried up into
        // the upper. Over a base that keeps `/bin` a directory, it merges with
        // that directory, where a farm in the upper would have hidden it behind
        // a link.
        let dir = Scratch::new("layered-layout");
        let archives = dir.join("archives");
        let tool = deb_of(&data_tar(&[("./bin/tool", 0o755, 0, 0)]));
        let install = installables(&archives, &[("tool", tool)]);

        let merged = dir.join("merged-base");
        std::fs::create_dir_all(merged.join("usr/bin")).expect("the base is laid out");
        std::os::unix::fs::symlink("usr/bin", merged.join("bin")).expect("a link");
        let upper = dir.join("upper-merged");
        std::fs::create_dir_all(&upper).expect("the upper is creatable");
        extract_packages(
            &upper,
            Some((&merged, Ownership::default())),
            "amd64",
            &install,
            &archives,
            &mut Silent,
        )
        .expect("the increment extracts");
        assert!(upper.join("usr/bin/tool").is_file());
        assert_eq!(
            std::fs::read_link(upper.join("bin")).expect("the base's link is carried up"),
            Path::new("usr/bin"),
        );
        assert!(
            std::fs::symlink_metadata(upper.join("lib")).is_err(),
            "no farm is laid into the upper",
        );

        let split = dir.join("split-base");
        std::fs::create_dir_all(split.join("bin")).expect("the base is laid out");
        std::fs::create_dir_all(split.join("usr/bin")).expect("the base is laid out");
        let upper = dir.join("upper-split");
        std::fs::create_dir_all(&upper).expect("the upper is creatable");
        extract_packages(
            &upper,
            Some((&split, Ownership::default())),
            "amd64",
            &install,
            &archives,
            &mut Silent,
        )
        .expect("the increment extracts");
        assert!(
            std::fs::symlink_metadata(upper.join("bin"))
                .expect("the upper holds the directory")
                .is_dir(),
            "a directory that merges with the base's own",
        );
        assert!(upper.join("bin/tool").is_file());
        assert!(!upper.join("usr/bin/tool").exists());
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
        extract_packages(&staging, None, "amd64", &install, &archives, &mut Silent)
            .expect("the package extracts");

        let mode = std::fs::metadata(&staging).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, ROOTFS_ROOT_MODE, "the package chose the root's mode");
    }

    #[test]
    fn a_package_cannot_redirect_the_dpkg_database_out_of_the_tree() {
        // The database is initialized after every package's files are down, so
        // a package is free to have shipped its paths, a link out of the tree
        // among them. Both shapes: the status file itself, and the directory
        // the database lives in.
        let dir = Scratch::new("dpkg-database-links");
        let outside = dir.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let target = outside.join("created-by-the-bootstrap");

        let mut status = ferroday_cage_testkit::tar::Tar::new();
        status
            .dir("./var/", 0o755)
            .dir("./var/lib/", 0o755)
            .dir("./var/lib/dpkg/", 0o755)
            .symlink("./var/lib/dpkg/status", target.to_str().unwrap());
        let mut database = ferroday_cage_testkit::tar::Tar::new();
        database
            .dir("./var/", 0o755)
            .dir("./var/lib/", 0o755)
            .symlink("./var/lib/dpkg", outside.to_str().unwrap());

        let stage = |tag: &str, data: &[u8]| {
            let archives = dir.join(format!("{tag}-archives"));
            let staging = dir.join(format!("{tag}-staging"));
            std::fs::create_dir_all(&staging).unwrap();
            let install = installables(&archives, &[("hostile", deb_of(data))]);
            let outcome = stage_extract(&staging, "amd64", &install, &archives, &mut Silent);
            assert!(
                entries_of(&outside).is_empty(),
                "{tag}: the bootstrap wrote outside the tree: {:?}",
                entries_of(&outside),
            );
            (staging, outcome)
        };

        // A name the package took is left as the package laid it: the link
        // resolves inside the tree, which is what it means to dpkg reading it
        // from inside the sandbox, and nothing is written through it.
        let (staging, outcome) = stage("status", &status.finish());
        outcome.expect("the tree is staged");
        assert!(
            std::fs::symlink_metadata(staging.join("var/lib/dpkg/status"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(staging.join("var/lib/dpkg/available").is_file());

        // A database directory that resolves, inside the tree, to nothing is a
        // tree dpkg could not use either, and the staging fails rather than
        // creating the directory anywhere else.
        let (_, outcome) = stage("database", &database.finish());
        assert!(outcome.is_err(), "the dangling database is refused");
    }

    #[test]
    fn packages_from_a_callers_cache_are_installed_from_a_private_copy() {
        // dpkg reads each package again minutes after the extraction verified
        // it, by path. From a cache that outlives the run and may be shared,
        // that read is of a file anything with access to the cache can
        // replace, so both read a copy only this run writes.
        let dir = Scratch::new("debian-private-copy");
        let cache = dir.join("cache");
        let tree = dir.join("tree");
        let install = installables(&cache, &[("one", deb_of(&data_tar(&[])))]);
        let name = cache_name(&install[0].digests);

        let private = private_copy(&tree, Some(&cache), &install)
            .expect("the packages are copied")
            .expect("a caller's cache is copied from");
        assert_eq!(private.path(), PackageCache::derived(&tree, DEB_CACHE));
        assert_eq!(
            std::fs::read(private.path().join(&name)).unwrap(),
            std::fs::read(cache.join(&name)).unwrap(),
        );
        // A different file, rather than another name for the same one.
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            std::fs::metadata(private.path().join(&name)).unwrap().ino(),
            std::fs::metadata(cache.join(&name)).unwrap().ino(),
        );
        let copied = private.path().to_path_buf();
        drop(private);
        assert!(!copied.exists(), "the copy goes with the run");
        assert!(cache.join(&name).is_file(), "the caller's cache stays");

        // Without a cache of the caller's, the run downloaded into its own
        // directory already, and nothing is copied.
        assert!(private_copy(&tree, None, &install).unwrap().is_none());
        // Nor when the caller named that very directory, which stays theirs.
        // The download has created it by the time the copy is asked about.
        let own = PackageCache::derived(&tree, DEB_CACHE);
        let in_own = installables(&own, &[("one", deb_of(&data_tar(&[])))]);
        assert!(private_copy(&tree, Some(&own), &in_own).unwrap().is_none());
        // The same directory spelled another way is the same directory: taken
        // for a copy of the run's own, it would go with the run, and the
        // caller's cache with it.
        std::os::unix::fs::symlink(".", dir.join("via")).expect("the link is creatable");
        let aliased = dir.join(format!("via/tree{DEB_CACHE}"));
        assert_ne!(aliased, own, "the spellings differ");
        assert!(
            private_copy(&tree, Some(&aliased), &in_own)
                .unwrap()
                .is_none()
        );
        assert!(own.join(&name).is_file(), "the caller's cache stays");
    }

    #[test]
    fn a_plan_naming_one_package_twice_is_refused() {
        // Two versions of one name would both be extracted, the later one's
        // files over the earlier's, into a root that registers one of them.
        let mut plan = one_package_plan(&"0".repeat(64), None);
        let mut again = plan.packages[0].clone();
        again.version = "2".to_string();
        again.filename = "pool/one-2.deb".to_string();
        plan.packages.push(again);
        let refused = Debian::builder("trixie")
            .architecture("amd64")
            .mirror("https://mirror.example/debian")
            .trust_unsigned(true)
            .plan(plan)
            .build();
        assert!(
            matches!(&refused, Err(DebianError::Config { reason })
                if reason.contains("names the package one twice, at 1 and at 2")),
            "{refused:?}",
        );
    }

    /// A plan installing one package, `pool/one.deb` at `sha256`, from one
    /// unsigned mirror, stating `size` for it where given.
    fn one_package_plan(sha256: &str, size: Option<usize>) -> Plan {
        let size = size
            .map(|size| format!("Size: {size}\n"))
            .unwrap_or_default();
        Plan::parse_document(&format!(
            "Format: ferroday-cage-plan 2\nSuite: trixie\nArchitecture: amd64\n\n\
             Archive: 0\nMirror: https://mirror.example/debian\nSuite: trixie\n\
             Components: main\nRelease-SHA256: {}\nSigned-By:\nSigning-Key:\n\n\
             Package: one\nVersion: 1\nArchitecture: amd64\nSHA256: {sha256}\n\
             Filename: pool/one.deb\nArchive: 0\n{size}",
            "0".repeat(64),
        ))
        .expect("the plan document reads")
    }

    /// An extract-only bootstrap of `plan`, from a mirror serving `deb` as its
    /// one package, with `cache` as the caller's cache.
    fn plan_bootstrap(plan: Plan, deb: Vec<u8>, cache: &Path) -> Debian {
        Debian::builder("trixie")
            .architecture("amd64")
            .mirror("https://mirror.example/debian")
            .trust_unsigned(true)
            .plan(plan)
            .extract_only(true)
            .cache_dir(cache)
            .fetcher(Table {
                bodies: [(
                    "https://mirror.example/debian/pool/one.deb".to_string(),
                    deb,
                )]
                .into_iter()
                .collect(),
                asked: std::sync::Arc::default(),
            })
            .build()
            .expect("the builder validates")
    }

    #[test]
    fn a_package_replaced_in_the_cache_after_it_was_acquired_is_not_installed() {
        // The run installs from a copy only it writes, so replacing the cache
        // entry once the package has been acquired changes nothing the run
        // reads: the extraction verifies the copy, and dpkg would read it too.
        let dir = Scratch::new("debian-cache-swap");
        let cache = dir.join("cache");
        let deb = deb_of(&data_tar(&[("./etc/marker", 0o644, 0, 0)]));
        let sha256 = Algorithm::Sha256.hex_of(&deb);
        let mut debian = plan_bootstrap(one_package_plan(&sha256, None), deb, &cache);

        let entry = cache.join(format!("{sha256}.deb"));
        let mut swap = |event: DebianEvent<'_>| {
            if let DebianEvent::Extracting { .. } = event {
                // Another writer to the shared cache, replacing the entry by
                // a rename, as anything publishing into a cache does.
                let planted = cache.join("planted");
                std::fs::write(&planted, b"not the package").unwrap();
                std::fs::rename(&planted, &entry).unwrap();
            }
        };
        crate::provision::ensure(dir.join("root"), &mut debian.observe(&mut swap))
            .expect("the run installs what it acquired");
        assert!(dir.join("root/etc/marker").is_file());
        assert_eq!(std::fs::read(&entry).unwrap(), b"not the package");
    }

    #[test]
    fn a_plan_s_size_bounds_its_download() {
        // Installing a plan fetches no index, so the length the plan recorded is
        // the one the download is held to: a mirror answering with more is
        // refused before the bytes are spent, even where they would verify.
        let dir = Scratch::new("debian-plan-size");
        let deb = deb_of(&data_tar(&[("./etc/marker", 0o644, 0, 0)]));
        let sha256 = Algorithm::Sha256.hex_of(&deb);
        let mut debian = plan_bootstrap(
            one_package_plan(&sha256, Some(deb.len() - 1)),
            deb.clone(),
            &dir.join("cache"),
        );
        let outcome = crate::provision::ensure(dir.join("root"), &mut debian);
        assert!(outcome.is_err(), "a body past the plan's Size is refused");
        assert!(!dir.join("cache").join(format!("{sha256}.deb")).exists());

        // The exact length is accepted.
        let mut debian = plan_bootstrap(
            one_package_plan(&sha256, Some(deb.len())),
            deb,
            &dir.join("cache"),
        );
        crate::provision::ensure(dir.join("root"), &mut debian).expect("the plan installs");
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
}
