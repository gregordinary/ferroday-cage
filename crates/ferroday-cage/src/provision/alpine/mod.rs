//! The Alpine userland provisioner: bootstrap a release rootfs from an apk
//! repository.
//!
//! The layer talks to the repository directly over the shared
//! [`Fetch`] transport, as the Debian layer does, and verifies
//! what it fetches against a [`KeySet`] of RSA public keys — the crate's bundle
//! for Alpine and postmarketOS, or a caller's own. No `apk` binary is invoked.
//!
//! # What binds an apk repository together
//!
//! Both formats this layer reads are the same container: independent gzip
//! segments laid end to end, each holding a tar archive. A package is three of
//! them — the signature, the control segment, and the file tree — and an index
//! is two, the signature and the records.
//!
//! Every digest the format defines is taken over *compressed* bytes: the RSA
//! signature covers the raw bytes of the segment after it, an index record's
//! `C:` field is a SHA-1 over the package's control segment as it lies in the
//! file, and `.PKGINFO`'s `datahash` is a SHA-256 over the data segment as it
//! lies in the file. So the chain from a signing key to a file on disk runs
//! RSA-4096 over SHA-1, then SHA-1 again, then SHA-256 — and the layer verifies
//! exactly that, because the published format offers nothing stronger and
//! verifying less than `apk` does would be worse rather than safer.
//!
//! # Example
//!
//! ```no_run
//! use ferroday_cage::provision::alpine::Alpine;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut alpine = Alpine::builder("v3.23")
//!     .components(["main", "community"])
//!     .build()?;
//! assert!(alpine.available()?.contains("busybox"));
//! # Ok(())
//! # }
//! ```

mod apk;
mod bootstrap;
mod index;
mod installed;
mod keyring;
mod layer;
mod pin;
mod pkginfo;
mod plan;
mod repository;
mod resolve;
mod sign;
mod version;

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Seek as _};
use std::path::{Path, PathBuf};

pub use index::Available;
pub use keyring::KeySet;
pub use pin::{UnheldPin, UnheldReason};
pub use plan::{Plan, PlannedPackage, ResolvedIndex};
pub use repository::{Repository, RepositoryBuilder};

use super::binfmt;
use super::coordinate::{self, Nesting};
use super::extract::{Extraction, Placement};
// `super::layer` is the shared one; this module has a `layer` of its own, which
// reads a provisioned base rather than describing how a cage is rooted on it.
use super::layer::Rooting;
use super::rooted::Rooted;
use super::tar::TarReader;
use super::{
    BuildLayer, Fetch, FetchError, FetchRequest, HttpFetch, LimitedWriter, PackageCache,
    ProvisionError, ProvisionRequest, Provisioner, Stream, digest,
};
use crate::IdentityMap;
use bootstrap::ScriptSubject;
use index::{Index, Record};
use installed::{Carried, Claim, Database};
use pin::Pins;

/// The default mirror: the Alpine content-delivery front end.
const DEFAULT_MIRROR: &str = "http://dl-cdn.alpinelinux.org/alpine";

/// The ceiling on an index as it arrives, compressed.
///
/// Nothing in an apk repository declares an index's size — there is no signed
/// release above it to record one — so this is the layer's own number rather
/// than an archive's, and it is why it is not stated through
/// [`FetchRequest::sized`], which is for a length a verified source declared.
/// Alpine's largest published index is `edge/community/x86_64` at around 2.5 MB,
/// so this is generous by a factor of twenty-five and still the reason a hostile
/// mirror cannot stream forever.
const MAX_INDEX_FETCH: u64 = 64 * 1024 * 1024;

/// The ceiling on an index's records, decompressed.
///
/// The bound the fetch ceiling above cannot give: gzip is a compression format,
/// so 2.5 MB on the wire can be gigabytes in hand. Alpine's largest index
/// decompresses to around 11 MB today.
const MAX_INDEX_RECORDS: u64 = 128 * 1024 * 1024;

/// The suffix a run-owned package cache takes on the tree it is building.
const APK_CACHE: &str = ".fcage-apks";

/// The mode a bootstrapped rootfs's own root directory takes.
///
/// Alpine's packages ship no entry for the root, so nothing in the closure
/// states it; `0755` is what `alpine-baselayout` gives every top-level directory
/// and what the published minirootfs unpacks to. Stating it keeps the published
/// directory independent of the caller's umask.
const ROOTFS_ROOT_MODE: u32 = 0o755;

/// The ceiling on a package's control segment, decompressed and compressed
/// alike.
///
/// `.PKGINFO` and a handful of shell scripts: the largest across the
/// `alpine-base` closure is 11 KB, from a kilobyte and a half on the wire. The
/// bound is here because gzip is a compression format and this segment is read
/// before anything about the package has been authenticated.
const MAX_CONTROL_SEGMENT: u64 = 16 * 1024 * 1024;

/// The Alpine architecture name for the host.
///
/// This is what [`AlpineBuilder::architecture`] defaults to when a caller names
/// none, and it is exposed so a caller composing its own defaults — a cache key,
/// an artifact record — reaches the same answer the bootstrap will.
///
/// The name comes from `uname` rather than from `std::env::consts::ARCH`, as the
/// Debian layer's does and for the same reason: `ARCH` reports the architecture
/// the *calling binary* was compiled for, and reports `arm` for both the ARMv6
/// and ARMv7 userlands that Alpine publishes as `armhf` and `armv7`.
///
/// Returns the raw machine name when it is not one this table knows, so a caller
/// on an unusual host can still proceed by naming the architecture explicitly.
///
/// # Example
///
/// ```no_run
/// use ferroday_cage::provision::alpine::{Alpine, host_architecture};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let architecture = host_architecture();
/// let alpine = Alpine::builder("v3.23").architecture(&architecture).build()?;
/// # let _ = alpine;
/// # Ok(())
/// # }
/// ```
pub fn host_architecture() -> String {
    let uname = rustix::system::uname();
    let machine = uname.machine().to_string_lossy();
    match machine.as_ref() {
        "armv7l" => "armv7",
        "armv6l" => "armhf",
        "i686" | "i586" | "i386" => "x86",
        other => other,
    }
    .to_string()
}

/// Checks one archive coordinate, reporting a refusal as this layer's
/// configuration failure.
///
/// The rule is [`coordinate::check`]'s and is shared with every other layer;
/// only whose configuration the refusal is about belongs here.
pub(super) fn check_coordinate(
    what: &str,
    value: &str,
    nesting: Nesting,
) -> Result<(), AlpineError> {
    coordinate::check(what, value, nesting).map_err(|reason| AlpineError::Config { reason })
}

/// An Alpine userland provisioner.
///
/// Built with [`Alpine::builder`]. [`available`](Self::available) reports the
/// names the configured repositories offer, reading and verifying each index
/// without downloading a package.
pub struct Alpine {
    /// The architecture every index is read for, and the one `noarch` joins.
    architecture: String,
    /// The repositories, the primary first, in the order a merge applies them.
    repositories: Vec<Repository>,
    /// The packages the caller asked for, which is the whole seed of a
    /// resolution.
    world: Vec<String>,
    /// The packages that are never selected.
    excludes: Vec<String>,
    /// The versions a resolution is held to, empty where none was given.
    pins: Pins,
    /// A plan to install instead of resolving one, where the caller gave one.
    plan: Option<Plan>,
    /// Whether to lay the files out and run nothing.
    extract_only: bool,
    /// The map the script cages run under.
    identity_map: IdentityMap,
    /// Where downloaded packages are kept across runs, where the caller named a
    /// place.
    cache_dir: Option<PathBuf>,
    /// A tree laid over the unpacked closure before the scripts run.
    overlay: Option<PathBuf>,
    /// The pristine base a layered build stages its increment over, set by
    /// [`AlpineBuilder::base_layer`]. `None` for a full bootstrap; required by
    /// [`Alpine::stage_layer`] and [`Alpine::resolve_layer`].
    base_layer: Option<PathBuf>,
    /// The transport every fetch goes through.
    fetcher: Box<dyn Fetch>,
}

impl fmt::Debug for Alpine {
    /// Renders the configuration. The transport is named by neither its type
    /// nor its state, since a `Fetch` is a caller's value and this crate knows
    /// nothing renderable about one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Alpine")
            .field("architecture", &self.architecture)
            .field("repositories", &self.repositories)
            .field("world", &self.world)
            .field("excludes", &self.excludes)
            .field("extract_only", &self.extract_only)
            .field("identity_map", &self.identity_map)
            .field("cache_dir", &self.cache_dir)
            .field("overlay", &self.overlay)
            .field("base_layer", &self.base_layer)
            .finish_non_exhaustive()
    }
}

impl Alpine {
    /// Returns a builder for a bootstrap of `release` — `v3.23`, `edge`, or
    /// postmarketOS's `v26.06`.
    pub fn builder(release: impl Into<String>) -> AlpineBuilder {
        AlpineBuilder {
            release: release.into(),
            architecture: None,
            mirror: None,
            fallbacks: Vec::new(),
            components: None,
            keys: None,
            includes: Vec::new(),
            excludes: Vec::new(),
            pin: None,
            plan: None,
            extract_only: false,
            identity_map: IdentityMap::Single,
            cache_dir: None,
            overlay: None,
            base_layer: None,
            repositories: Vec::new(),
            fetcher: None,
        }
    }

    /// Resolves the install plan for the configured release, downloading and
    /// unpacking nothing.
    ///
    /// This performs the read half of a bootstrap: it fetches each repository's
    /// index, verifies its signature against that repository's keys, merges
    /// them, and resolves the caller's [`include`](AlpineBuilder::include)s into
    /// the exact set of packages a bootstrap would install. It stops there — no
    /// package is downloaded, and no staging tree is created — and returns the
    /// resolved [`Plan`].
    ///
    /// Because nothing runs, `resolve` needs neither a `qemu-user` binfmt
    /// handler nor an establishable identity map, and so serves an architecture
    /// the host cannot execute.
    ///
    /// # What seeds a resolution
    ///
    /// The included set, and nothing else. apk publishes no priority field and
    /// no essential flag, so unlike a Debian bootstrap there is no band of
    /// packages the archive itself nominates as the base — a closure holds what
    /// was asked for and what that requires. `alpine-base` is the conventional
    /// minimal set and is a package like any other; name it to get it.
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Config`] when nothing was included,
    /// [`AlpineError::Fetch`], [`AlpineError::Container`],
    /// [`AlpineError::Signature`] or [`AlpineError::Index`] for a repository
    /// that cannot be read or verified, and [`AlpineError::Resolve`] for a
    /// closure the repositories cannot supply.
    pub fn resolve(&mut self) -> Result<Plan, AlpineError> {
        self.resolve_reporting(&mut Silent)
    }

    /// The resolution, with an observer already chosen.
    ///
    /// Shared by [`resolve`](Self::resolve) and the bootstrap, so the plan a
    /// caller previews and the plan a bootstrap installs come from one code path
    /// and cannot drift apart.
    fn resolve_reporting(
        &mut self,
        observer: &mut dyn AlpineObserver,
    ) -> Result<Plan, AlpineError> {
        self.resolve_over(None, observer)
    }

    /// The resolution, over a base layer where there is one.
    ///
    /// One body for the whole-root and the layered cases, so the two cannot
    /// resolve differently: a base contributes packages the closure treats as
    /// already answered, and nothing else about the resolution changes.
    fn resolve_over(
        &mut self,
        base: Option<&layer::Base>,
        observer: &mut dyn AlpineObserver,
    ) -> Result<Plan, AlpineError> {
        if self.world.is_empty() {
            return Err(AlpineError::Config {
                reason: "a resolution installs the packages named with include(), and none were \
                         named; apk has no priority field, so there is no set the repositories \
                         nominate on the caller's behalf"
                    .to_string(),
            });
        }
        let (records, indexes) = self.read_indexes()?;
        observer.progress(AlpineEvent::Resolving);
        let merged = Index::merge(records, &self.architecture, &self.pins);
        // Before the closure, so a pin the repositories have moved past refuses
        // the resolution rather than quietly resolving to something else.
        self.pins.check(&merged)?;
        let carried = base.into_iter().flat_map(layer::Base::records);
        let packages = resolve::resolve(&merged, &self.world, &self.excludes, carried)?;
        Ok(Plan::project(
            self.release(),
            &self.architecture,
            &packages,
            &indexes,
        ))
    }

    /// Resolves the increment a layered build would install over its base,
    /// downloading and unpacking nothing.
    ///
    /// The layered counterpart of [`resolve`](Self::resolve): it reads the base
    /// layer's `lib/apk/db/installed` database, then resolves the configured
    /// [`include`](AlpineBuilder::include)s against the merged repository index
    /// while treating everything the base records as already answered, returning
    /// the [`Plan`] of only the packages the base does not carry. Requires a
    /// [`base_layer`](AlpineBuilder::base_layer).
    ///
    /// The base answers at its recorded versions rather than merely by name, so
    /// a dependency the base's version is too old for is reported rather than
    /// quietly skipped. That is the one thing a layered resolution cannot do
    /// about: an increment installs over a base, and a package the base already
    /// carries cannot be replaced by a newer one without rebuilding the base.
    ///
    /// Like [`resolve`](Self::resolve) it downloads no package and runs nothing,
    /// so it needs neither a `qemu-user` binfmt handler nor an establishable
    /// identity map. Use it to preview a layer or to key a build-root cache on
    /// the increment without staging it.
    ///
    /// # Errors
    ///
    /// Returns an [`AlpineError`] for the same fetch, signature, and resolution
    /// failures as [`resolve`](Self::resolve), and [`AlpineError::Config`] when
    /// no base layer is set or the base is not a provisioned Alpine root of this
    /// architecture.
    pub fn resolve_layer(&mut self) -> Result<Plan, AlpineError> {
        self.resolve_layer_reporting(&mut Silent)
    }

    /// The body of [`resolve_layer`](Self::resolve_layer), reporting to
    /// `observer`.
    fn resolve_layer_reporting(
        &mut self,
        observer: &mut dyn AlpineObserver,
    ) -> Result<Plan, AlpineError> {
        let base = self.read_base_layer("resolve_layer")?;
        self.resolve_over(Some(&base), observer)
    }

    /// Reads the configured base layer, refusing a provisioner that has none.
    ///
    /// `entry` names the method that needs one, so the refusal says which call
    /// was made rather than only that something was missing.
    fn read_base_layer(&self, entry: &str) -> Result<layer::Base, AlpineError> {
        let Some(base) = self.base_layer.as_deref() else {
            return Err(AlpineError::Config {
                reason: format!(
                    "{entry} stages over a base root, and none was set with \
                     AlpineBuilder::base_layer",
                ),
            });
        };
        layer::Base::read(base, &self.architecture)
    }

    /// The release the primary repository publishes, which is the one the
    /// builder was opened on.
    fn release(&self) -> &str {
        self.repositories
            .first()
            .expect("a provisioner always holds its primary repository")
            .release()
    }

    /// Fetches, verifies and parses every configured index.
    ///
    /// The two halves travel together because they are the same walk: the
    /// records a resolution reads and the record of what was read are produced
    /// by one pass, and a plan that named an index it had not verified would be
    /// describing something other than what it resolved against.
    fn read_indexes(&mut self) -> Result<(Vec<Vec<Record>>, Vec<ResolvedIndex>), AlpineError> {
        let mut records = Vec::new();
        let mut indexes = Vec::new();
        for repository in &self.repositories {
            for (component, path) in repository.indexes(&self.architecture) {
                let from = indexes.len();
                let (read, resolved) =
                    read_index(&mut *self.fetcher, repository, component, &path, from)?;
                records.push(read);
                indexes.push(resolved);
            }
        }
        Ok((records, indexes))
    }

    /// The package names the configured repositories offer.
    ///
    /// This is the question a resolve cannot answer, since a resolve reports a
    /// closure rather than a catalogue. Every index is fetched and its signature
    /// verified, so this is as authenticated as a bootstrap; no package is
    /// downloaded.
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Fetch`] when no mirror of a repository serves its
    /// index, [`AlpineError::Container`] or [`AlpineError::Signature`] when what
    /// one serves is not a signed apk container this key set accepts, and
    /// [`AlpineError::Index`] when the records it carries are not the ones the
    /// format defines.
    pub fn available(&mut self) -> Result<Available, AlpineError> {
        // Unpinned whatever the builder holds: this reports what the
        // repositories offer, and a pin describes a selection from it rather
        // than a bound on what may be asked about.
        let (records, _indexes) = self.read_indexes()?;
        Ok(Index::merge(records, &self.architecture, &Pins::none()).into_available())
    }

    /// Stages this provisioner's packages as an increment over the base layer,
    /// installing only what the base does not carry into a disposable overlay
    /// `upper`.
    ///
    /// Requires a [`base_layer`](AlpineBuilder::base_layer). It resolves the
    /// increment [`resolve_layer`](Self::resolve_layer) reports, downloads it,
    /// extracts it into `upper`, and runs its install scripts in a cage rooted
    /// on an overlay of the pristine base (the read-only lower) and `upper` (the
    /// writable increment) — so a script reads the base's shell and the base's
    /// accounts, and everything it writes lands in `upper`, the base untouched.
    /// The returned [`BuildLayer`] owns `upper`: root a build cage on
    /// [`overlay_rootfs(base, layer.path())`](crate::CageBuilder::overlay_rootfs)
    /// to build against the merged `base + increment` view, then drop the layer
    /// to discard the increment.
    ///
    /// `upper` is created if absent, along with the overlay work directory
    /// beside it. The identity map, cache directory, additional repositories and
    /// pre-configure overlay configured on the builder all apply exactly as to a
    /// full bootstrap, and [`extract_only`](AlpineBuilder::extract_only) stages
    /// the increment's files and registers them without running a script.
    ///
    /// A call that fails leaves nothing behind: the upper and its work directory
    /// are disposed of exactly as dropping the returned layer would dispose of
    /// them, since a failure hands the caller no handle to drop. So is the
    /// package cache, unless the builder named a
    /// [`cache_dir`](AlpineBuilder::cache_dir), which is the caller's and
    /// survives either way.
    ///
    /// # What the merged root records
    ///
    /// An overlay unions files, so the `lib/apk/db/installed` written into
    /// `upper` shadows the base's outright. It is therefore written to describe
    /// the whole merged root: the base's records are carried through byte for
    /// byte and the increment's are sorted in among them, and the same holds for
    /// the trigger list, the archived scripts, `/etc/apk/world` and
    /// `/etc/apk/repositories`. An `apk` run inside the build root reads one
    /// coherent database.
    ///
    /// One thing the merged root does not reproduce: a file the increment ships
    /// over one the base owns shadows it rather than being refused. The base is
    /// read-only and the shadow lives in the disposable upper, so the collision
    /// is confined to the layer and reverted with it. A collision *within* the
    /// increment is refused exactly as a full bootstrap refuses one.
    ///
    /// # Preconditions
    ///
    /// The increment's scripts run the target's binaries, so a foreign
    /// architecture needs the same `qemu-user` binfmt handler a full bootstrap
    /// does, and a range identity map must be establishable — both checked
    /// before any download. It roots a cage on an unprivileged overlay, so the
    /// host must support one on `upper`'s filesystem;
    /// [`host::overlay_blocker`](crate::host::overlay_blocker) reports what is
    /// missing, and `stage_layer` refuses a host that cannot before downloading.
    ///
    /// # Errors
    ///
    /// Returns [`ProvisionError`], with an [`AlpineError`] surfaced through
    /// [`ProvisionError::Other`] for a fetch, resolution, or script failure, an
    /// unmet host precondition, a base that is not a provisioned Alpine root, or
    /// no base layer set.
    pub fn stage_layer(&mut self, upper: impl AsRef<Path>) -> Result<BuildLayer, ProvisionError> {
        self.stage_layer_reporting(upper.as_ref(), &mut Silent)
    }

    /// The body of [`stage_layer`](Self::stage_layer), reporting to `observer`.
    fn stage_layer_reporting(
        &mut self,
        upper: &Path,
        observer: &mut dyn AlpineObserver,
    ) -> Result<BuildLayer, ProvisionError> {
        // The same fail-early posture the full bootstrap takes, and then the
        // base itself: reading it refuses a tree that is not a provisioned root
        // before anything is created or downloaded.
        preflight(self).map_err(wrap)?;
        let base = self.read_base_layer("stage_layer").map_err(wrap)?;

        std::fs::create_dir_all(upper)
            .map_err(|err| ProvisionError::io("creating the overlay upper", upper, err))?;
        // The handle that owns the upper is taken as soon as the upper exists,
        // not on the way out, so a failure below disposes of a partly-installed
        // increment instead of orphaning it: there is no handle in an `Err` for
        // the caller to drop.
        let layer = BuildLayer::new(upper, self.identity_map.clone());
        // Refuse a host that cannot establish an unprivileged overlay on the
        // upper's filesystem before any download — the preflight the primitive
        // would make at cage-build time, hoisted ahead of the work. The probe
        // runs on the upper's parent, its own filesystem, so its scratch files
        // land beside the upper.
        //
        // Not for an extract-only staging, which runs nothing and so roots no
        // cage of its own, for the same reason `preflight` skips the identity
        // map and the interpreter there. A caller who goes on to root a build
        // cage on the result meets the primitive's own check.
        let scratch = upper
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !self.extract_only
            && let Some(blocker) = crate::host::overlay_blocker(scratch)
        {
            return Err(wrap(AlpineError::Config {
                reason: format!("an overlay-rooted build layer cannot be established: {blocker}"),
            }));
        }

        install(self, upper, Some(&base), observer)?;
        Ok(layer)
    }
}

/// Builder for an [`Alpine`] provisioner.
///
/// The setters configure the primary repository — its mirrors, components and
/// keys — and [`repository`](Self::repository) adds further ones after it.
pub struct AlpineBuilder {
    release: String,
    architecture: Option<String>,
    mirror: Option<String>,
    fallbacks: Vec<String>,
    /// `None` where the caller never named any, which is what the default
    /// applies to; an empty list they named is the componentless layout.
    components: Option<Vec<String>>,
    keys: Option<KeySet>,
    includes: Vec<String>,
    excludes: Vec<String>,
    pin: Option<Plan>,
    plan: Option<Plan>,
    extract_only: bool,
    identity_map: IdentityMap,
    cache_dir: Option<PathBuf>,
    overlay: Option<PathBuf>,
    base_layer: Option<PathBuf>,
    repositories: Vec<Repository>,
    fetcher: Option<Box<dyn Fetch>>,
}

impl fmt::Debug for AlpineBuilder {
    /// Renders the configuration, naming the keys rather than holding them and
    /// leaving the transport out, as [`Alpine`]'s own rendering does.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlpineBuilder")
            .field("release", &self.release)
            .field("architecture", &self.architecture)
            .field("mirror", &self.mirror)
            .field("fallbacks", &self.fallbacks)
            .field("components", &self.components)
            .field("keys", &self.keys)
            .field("includes", &self.includes)
            .field("excludes", &self.excludes)
            .field("pin", &self.pin)
            .field("plan", &self.plan)
            .field("extract_only", &self.extract_only)
            .field("identity_map", &self.identity_map)
            .field("cache_dir", &self.cache_dir)
            .field("overlay", &self.overlay)
            .field("base_layer", &self.base_layer)
            .field("repositories", &self.repositories)
            .finish_non_exhaustive()
    }
}

impl AlpineBuilder {
    /// Sets the architecture to bootstrap. The default is
    /// [`host_architecture`].
    pub fn architecture(mut self, architecture: impl Into<String>) -> Self {
        self.architecture = Some(architecture.into());
        self
    }

    /// Sets the primary repository's mirror URL, the archive root rather than
    /// the release directory. The default is Alpine's content-delivery front
    /// end.
    pub fn mirror(mut self, url: impl Into<String>) -> Self {
        self.mirror = Some(url.into());
        self
    }

    /// Adds a backstop mirror for the primary repository, tried in order after
    /// it when a fetch reports the index missing or fails at the transport.
    pub fn mirror_fallback(mut self, url: impl Into<String>) -> Self {
        self.fallbacks.push(url.into());
        self
    }

    /// Sets the primary repository's components. The default is `main`.
    ///
    /// An empty list is not the default but the other layout: a repository with
    /// no components is addressed as `<release>/<architecture>`, which is what
    /// postmarketOS publishes.
    pub fn components<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.components = Some(components.into_iter().map(Into::into).collect());
        self
    }

    /// Verifies the primary repository against `keys` instead of the bundled
    /// Alpine keys for the architecture being bootstrapped.
    ///
    /// The route for a repository of the caller's own is usually to extend the
    /// bundle rather than replace it: [`KeySet::alpine`] then
    /// [`KeySet::insert`].
    pub fn keys(mut self, keys: KeySet) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Adds packages to install, which is the whole seed of a resolution.
    ///
    /// apk publishes no priority field and no essential flag, so nothing is
    /// installed that was not named here or required by something that was.
    /// `alpine-base` is the conventional minimal set and is an ordinary package;
    /// name it to get it.
    ///
    /// This is the set written to `/etc/apk/world` in the finished rootfs — what
    /// the root asked for, as against the closure it resolved to.
    ///
    /// # Errors
    ///
    /// A name carrying a version operator is refused at [`build`](Self::build)
    /// with [`AlpineError::Config`]. A resolution takes the highest version each
    /// repository offers; holding one to a version is what [`pin`](Self::pin)
    /// is for, and reading `busybox>=1.37` as a package name would otherwise
    /// fail as a package nothing offers.
    pub fn include<I, S>(mut self, packages: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.includes.extend(packages.into_iter().map(Into::into));
        self
    }

    /// Excludes packages from the resolved install closure.
    ///
    /// An excluded package is never selected: it is skipped when a name is
    /// answered, so a dependency on a name several packages provide resolves
    /// through one of the others. apk has no alternative groups, so a dependency
    /// that only the excluded package could have satisfied fails the resolution
    /// rather than producing a broken closure, as does excluding a package that
    /// is also an [`include`](Self::include).
    pub fn exclude<I, S>(mut self, packages: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.excludes.extend(packages.into_iter().map(Into::into));
        self
    }

    /// Holds a resolution to the versions a previously resolved [`Plan`]
    /// recorded, resolving everything the plan does not name.
    ///
    /// The resolution runs as it always does — every index fetched and verified,
    /// the closure computed over what the repositories offer now — and each
    /// package the pin names is selected at the pinned version rather than at the
    /// highest offered. Everything else, including a package added to the closure
    /// since and a dependency the pinned version pulls in, resolves normally.
    ///
    /// # The trust model does not change
    ///
    /// Nothing here leaves the repository signature chain: every control
    /// identity is still read from an index whose own signature was verified.
    /// The pin narrows which version is selected; it never becomes the authority
    /// for what the bytes are. A pin whose control identity disagrees with the
    /// index's for the same version is refused rather than preferred, which is
    /// how one version published twice over different bytes is caught.
    ///
    /// # Errors
    ///
    /// A plan naming one package twice is refused at [`build`](Self::build) with
    /// [`AlpineError::Config`]: a pin is keyed by name, so two entries state two
    /// versions to hold it at.
    ///
    /// A pin the repositories cannot supply fails the resolution with
    /// [`AlpineError::Pin`], naming every package at once — the repositories
    /// have published past the pinned version, dropped the package, or record a
    /// different control segment for it. Alpine keeps one version of each
    /// package per release, so a pin outlives a publication only where the
    /// caller keeps a mirror that does.
    pub fn pin(mut self, pin: Plan) -> Self {
        self.pin = Some(pin);
        self
    }

    /// Installs the packages a previously resolved [`Plan`] names, resolving
    /// nothing.
    ///
    /// No index is fetched and no closure is computed: the plan *is* the
    /// resolution, and that omission is the whole of what it saves. Each package
    /// is still fetched from the index directory the plan records, and each is
    /// still bound to that plan by the control identity recomputed over what
    /// arrives, so the trust chain is the plan's rather than a fresh
    /// repository's.
    ///
    /// [`pin`](Self::pin) is the other half of the same pair and answers a
    /// different question: a pin holds a *resolution* to recorded versions while
    /// still computing one, and so still needs the repositories to agree.
    ///
    /// # Errors
    ///
    /// A plan whose architecture is not the one being bootstrapped, or that
    /// names an index it does not carry, is refused at [`build`](Self::build)
    /// with [`AlpineError::Config`].
    pub fn plan(mut self, plan: Plan) -> Self {
        self.plan = Some(plan);
        self
    }

    /// Lays the packages' files out and runs nothing.
    ///
    /// No script runs and no trigger fires, so the tree is what the packages
    /// ship and nothing a script would have derived from it: no `busybox` applet
    /// links, no accounts a `.pre-install` would have added. Because nothing
    /// executes, this serves an architecture the host cannot run.
    ///
    /// # This still registers what it installed
    ///
    /// Unlike the Debian layer's extract-only, which leaves an empty `dpkg`
    /// database because registering a package there *means running `dpkg`*, this
    /// writes the full `/lib/apk/db` and `/etc/apk` state. An apk installed
    /// record is a file format rather than a program's output, so registration
    /// costs nothing and needs nothing executed — and a root that knows what it
    /// holds is worth more than one that does not.
    pub fn extract_only(mut self, extract_only: bool) -> Self {
        self.extract_only = extract_only;
        self
    }

    /// Runs the install scripts under `map` rather than under the default
    /// single-identity map.
    ///
    /// Alpine's packages are entirely root-owned — every entry of every package
    /// in the `alpine-base` closure is uid 0, gid 0 — so unlike a Debian
    /// bootstrap the extraction itself needs nothing from a wider map. What a
    /// wider map buys is the scripts: `alpine-baselayout`'s `.post-install`
    /// assigns `/etc/shadow` to the `shadow` group, which the single-identity
    /// map cannot represent. That call fails under `apk` in the same situation,
    /// and Alpine's scripts tolerate it, so the default is a working bootstrap
    /// with the group ownership flattened to root.
    pub fn identity_map(mut self, map: IdentityMap) -> Self {
        self.identity_map = map;
        self
    }

    /// Keeps downloaded packages in `dir` across runs.
    ///
    /// Without one, packages are downloaded into a directory beside the rootfs
    /// being built and removed with it, so a repeated bootstrap re-downloads
    /// everything. A cache directory is the caller's: this layer only ever adds
    /// to it, and never removes an entry it did not just write.
    ///
    /// An entry is used only when it reads back as the package the plan names —
    /// its signature verifies, its control identity matches, and its file tree
    /// digests to what its own metadata says — so a truncated or substituted
    /// entry is downloaded again rather than trusted.
    pub fn cache_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.cache_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Copies the tree at `source` over the unpacked packages before their
    /// scripts run.
    ///
    /// The window is the one that matters: after every package's files are down,
    /// so this overwrites what they shipped, and before any script runs, so a
    /// script reads the injected values. A configuration file placed here is the
    /// one `busybox`'s applet install or a `.post-install` sees.
    ///
    /// It is laid under [`extract_only`](Self::extract_only) too. The tree is
    /// still assembled there; what does not happen is the scripts that would
    /// have read it.
    pub fn pre_configure_overlay(mut self, source: impl AsRef<Path>) -> Self {
        self.overlay = Some(source.as_ref().to_path_buf());
        self
    }

    /// Stages over the provisioned root at `base` rather than bootstrapping a
    /// whole one.
    ///
    /// This turns the [`Alpine`] into a layered provisioner:
    /// [`Alpine::stage_layer`] resolves only what `base` does not already carry
    /// and installs that increment into a disposable overlay upper, and
    /// [`Alpine::resolve_layer`] reports the increment without installing it.
    ///
    /// `base` is a root this crate or `apk` provisioned — it is read for its
    /// `lib/apk/db/installed` database, and refused if it holds none. Unlike the
    /// Debian layer, an [`extract_only`](Self::extract_only) base is a usable
    /// one: an apk registration is a file format rather than a program's output,
    /// so a root laid out without running anything still records exactly what it
    /// holds.
    ///
    /// An [`Alpine`] built with a base layer is used through `stage_layer` or
    /// `resolve_layer`; it is not passed to [`ensure`](super::ensure), which
    /// bootstraps a whole root and would ignore the base.
    pub fn base_layer(mut self, base: impl AsRef<Path>) -> Self {
        self.base_layer = Some(base.as_ref().to_path_buf());
        self
    }

    /// Adds a repository after the primary.
    ///
    /// Order is meaning: a repository added later shadows an earlier one where
    /// both offer a name at the same version, which is what makes postmarketOS's
    /// repositories an overlay on Alpine's rather than a rival to them. A higher
    /// version wins wherever it comes from.
    pub fn repository(mut self, repository: Repository) -> Self {
        self.repositories.push(repository);
        self
    }

    /// Fetches through `fetcher` rather than through the built-in transport.
    ///
    /// The built-in [`HttpFetch`] speaks `http://` and `file://`. Every archive
    /// this layer is written against serves plain HTTP, so a caller needs this
    /// for a mirror behind TLS, behind a proxy, or on a transport of their own.
    pub fn fetcher(mut self, fetcher: Box<dyn Fetch>) -> Self {
        self.fetcher = Some(fetcher);
        self
    }

    /// Validates the configuration and freezes it into an [`Alpine`].
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Config`] when the architecture is not one a
    /// repository can be addressed by, when the bundle holds no keys for it and
    /// none were given, or when the primary repository's release or a component
    /// is not addressable.
    pub fn build(self) -> Result<Alpine, AlpineError> {
        let architecture = match self.architecture {
            Some(architecture) => architecture,
            None => host_architecture(),
        };
        check_coordinate(
            "the bootstrap's architecture",
            &architecture,
            Nesting::Single,
        )?;

        let keys = match self.keys {
            Some(keys) => keys,
            None => KeySet::alpine(&architecture)?,
        };
        let mut mirrors = Vec::with_capacity(1 + self.fallbacks.len());
        mirrors.push(self.mirror.unwrap_or_else(|| DEFAULT_MIRROR.to_string()));
        mirrors.extend(self.fallbacks);
        let components = self.components.unwrap_or_else(|| vec!["main".to_string()]);

        for name in self.includes.iter().chain(&self.excludes) {
            if name.contains(['<', '>', '=', '~']) {
                return Err(AlpineError::Config {
                    reason: format!(
                        "{name:?} names a package and a version, and include() and exclude() \
                         name packages; hold a resolution to a version with pin() instead",
                    ),
                });
            }
        }

        let mut repositories = Vec::with_capacity(1 + self.repositories.len());
        repositories.push(Repository::primary(
            self.release,
            mirrors,
            components,
            keys,
        )?);
        repositories.extend(self.repositories);

        Ok(Alpine {
            architecture,
            repositories,
            world: self.includes,
            excludes: self.excludes,
            pins: match &self.pin {
                Some(plan) => Pins::of(plan)?,
                None => Pins::none(),
            },
            plan: self.plan,
            extract_only: self.extract_only,
            identity_map: self.identity_map,
            cache_dir: self.cache_dir,
            overlay: self.overlay,
            base_layer: self.base_layer,
            fetcher: self
                .fetcher
                .unwrap_or_else(|| Box::new(HttpFetch::new()) as Box<dyn Fetch>),
        })
    }
}

/// Fetches, verifies and parses one repository index.
///
/// `path` is mirror-relative. The mirror list is walked in order, advancing past
/// one that [could not serve the index](FetchError::is_failover); a mirror that
/// serves something that does not verify is fatal rather than a reason to try
/// the next, since what it served was answered for by the URL that was asked
/// for. A URL the transport will not accept is fatal for the same reason it is
/// everywhere else: it is the configuration rather than the mirror, and walking
/// past it would report the failure against a mirror that was spelled fine.
fn read_index(
    fetcher: &mut dyn Fetch,
    repository: &Repository,
    component: Option<&str>,
    path: &str,
    from: usize,
) -> Result<(Vec<Record>, ResolvedIndex), AlpineError> {
    let mut last_missing = None;
    for mirror in &repository.mirrors {
        let url = format!("{}/{path}", mirror.trim_end_matches('/'));
        let mut bytes = Vec::new();
        let request = FetchRequest::new(&url);
        match fetcher.fetch(
            &request,
            &mut LimitedWriter::new(&mut bytes, MAX_INDEX_FETCH),
        ) {
            Ok(()) => {
                let (records, signed_by, description) =
                    parse_index(&url, &bytes, repository, from)?;
                return Ok((
                    records,
                    ResolvedIndex::resolved(
                        mirror.clone(),
                        repository.release().to_string(),
                        component.map(str::to_string),
                        // Over the container as it arrived, signature segment
                        // included, so the value names the exact bytes whose
                        // signature was checked.
                        digest::sha256_hex(&bytes),
                        signed_by,
                        description,
                    ),
                ));
            }
            Err(err) if err.is_failover() => last_missing = Some(err),
            Err(err) => return Err(AlpineError::Fetch(err)),
        }
    }
    Err(AlpineError::Fetch(
        last_missing.unwrap_or_else(|| FetchError::not_found(path.to_string())),
    ))
}

/// Verifies an index container and reads the records it carries.
///
/// `url` names where it came from, for the errors.
#[allow(clippy::type_complexity)]
fn parse_index(
    url: &str,
    bytes: &[u8],
    repository: &Repository,
    from: usize,
) -> Result<(Vec<Record>, String, Option<String>), AlpineError> {
    let mut segments = apk::Segments::new(bytes);
    // An index is the trust root: nothing above it vouches for it, so its own
    // signature is what is verified, against this repository's keys and no
    // other's.
    let metadata = apk::read_metadata(
        url,
        &mut segments,
        apk::Anchor::Signature(&repository.keys),
        MAX_INDEX_RECORDS,
    )?;
    // Nothing in an index follows its records, and a trailing segment is
    // covered by no digest the format defines, so it is a refusal rather than a
    // curiosity.
    if !segments
        .at_end()
        .map_err(|err| AlpineError::container(url, format!("its end is unreadable: {err}")))?
    {
        return Err(AlpineError::container(
            url,
            "a segment follows its records, which nothing signed accounts for",
        ));
    }
    let records = metadata
        .member("APKINDEX")
        .ok_or_else(|| AlpineError::index(url, "its signed segment carries no APKINDEX member"))?;
    let text = std::str::from_utf8(&records.data)
        .map_err(|err| AlpineError::index(url, format!("its records are not UTF-8: {err}")))?;
    // Whatever the repository chose to write there, kept as a fact about the
    // publication rather than read for meaning: Alpine writes a build string and
    // postmarketOS a timestamp, and the format defines neither.
    let description = metadata
        .member("DESCRIPTION")
        .map(|member| String::from_utf8_lossy(&member.data).trim().to_string())
        .filter(|description| !description.is_empty());
    Ok((
        index::parse(url, text, from)?,
        metadata.signed_by,
        description,
    ))
}

/// An observer of an Alpine bootstrap's progress.
///
/// Attached with [`Alpine::observe`]. Every method has a default body, so an
/// implementation takes only the events it cares about — and every method added
/// in a later release will carry one too, so an existing implementation keeps
/// compiling.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use ferroday_cage::provision::alpine::{Alpine, AlpineEvent, AlpineObserver};
///
/// struct Progress;
///
/// impl AlpineObserver for Progress {
///     fn progress(&mut self, event: AlpineEvent<'_>) {
///         if let AlpineEvent::Downloading { package, index, total, .. } = event {
///             eprintln!("{package} ({index}/{total})");
///         }
///     }
/// }
///
/// let mut alpine = Alpine::builder("v3.23").include(["alpine-base"]).build()?;
/// let plan = alpine.observe(&mut Progress).resolve()?;
/// # let _ = plan;
/// # Ok(())
/// # }
/// ```
pub trait AlpineObserver {
    /// Receives one progress event.
    fn progress(&mut self, event: AlpineEvent<'_>) {
        let _ = event;
    }

    /// Whether the bootstrap should stop.
    ///
    /// Consulted where stopping is clean — a package boundary, a script
    /// boundary. Returning `true` aborts with [`ProvisionError::Cancelled`],
    /// and a run driven through [`provision::ensure`](super::ensure) then
    /// removes the staging tree, so a cancelled bootstrap leaves no destination
    /// behind.
    ///
    /// [`ProvisionError::Cancelled`]: super::ProvisionError::Cancelled
    fn cancelled(&mut self) -> bool {
        false
    }
}

/// A closure is an observer that reports and never cancels.
impl<F: FnMut(AlpineEvent<'_>)> AlpineObserver for F {
    fn progress(&mut self, event: AlpineEvent<'_>) {
        self(event);
    }
}

/// A progress event from an Alpine bootstrap.
#[derive(Debug)]
#[non_exhaustive]
pub enum AlpineEvent<'a> {
    /// A URL is being fetched.
    #[non_exhaustive]
    Fetching {
        /// The URL.
        url: &'a str,
    },
    /// The dependency closure is being resolved.
    Resolving,
    /// The closure has been resolved, carrying the plan the bootstrap will
    /// install.
    ///
    /// Emitted mid-bootstrap, once every index has been verified and before the
    /// first package is downloaded, so a consumer sees the exact manifest a
    /// [`provision::ensure`](super::ensure) installs without a separate
    /// [`Alpine::resolve`] pass.
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
    /// A package's files are being laid down.
    #[non_exhaustive]
    Extracting {
        /// The package name.
        package: &'a str,
    },
    /// One of a package's scripts is about to run.
    #[non_exhaustive]
    Script {
        /// The package the script belongs to.
        package: &'a str,
        /// Which script it is: `pre-install`, `post-install` or `trigger`.
        script: &'static str,
    },
    /// Output from a script running inside the cage.
    #[non_exhaustive]
    CommandOutput {
        /// Which standard stream the bytes came from.
        stream: Stream,
        /// The raw output bytes; not line-buffered, not guaranteed UTF-8.
        bytes: &'a [u8],
    },
}

impl Provisioner for Alpine {
    /// Bootstraps the configured release into the request's staging directory.
    ///
    /// Reached through [`provision::ensure`](super::ensure), which publishes the
    /// finished tree atomically and removes it on any failure.
    fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
        let mut observer = RunObserver { request };
        self.provision_reporting(request.staging(), &mut observer)
    }
}

impl Alpine {
    /// Reports this bootstrap's progress to `sink`, which sees every
    /// [`AlpineEvent`] and can stop the run.
    ///
    /// The returned value is a [`Provisioner`] and carries the read entry points
    /// too, so one attachment covers a resolve and the bootstrap that follows
    /// it.
    pub fn observe<'o>(&'o mut self, sink: &'o mut dyn AlpineObserver) -> Observed<'o> {
        Observed { alpine: self, sink }
    }

    /// The bootstrap, with an observer already chosen.
    fn provision_reporting(
        &mut self,
        staging: &Path,
        observer: &mut dyn AlpineObserver,
    ) -> Result<(), ProvisionError> {
        bootstrap_release(self, staging, observer)
    }
}

/// An [`Alpine`] with an observer attached, from [`Alpine::observe`].
pub struct Observed<'o> {
    alpine: &'o mut Alpine,
    sink: &'o mut dyn AlpineObserver,
}

impl fmt::Debug for Observed<'_> {
    /// Renders the provisioner. The sink is the caller's value, with nothing
    /// renderable about one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observed")
            .field("alpine", &self.alpine)
            .finish_non_exhaustive()
    }
}

impl Observed<'_> {
    /// [`Alpine::resolve`], reporting to the attached sink.
    pub fn resolve(&mut self) -> Result<Plan, AlpineError> {
        self.alpine.resolve_reporting(self.sink)
    }

    /// [`Alpine::available`], reporting to the attached sink.
    pub fn available(&mut self) -> Result<Available, AlpineError> {
        self.alpine.available()
    }

    /// [`Alpine::resolve_layer`], reporting to the attached sink.
    pub fn resolve_layer(&mut self) -> Result<Plan, AlpineError> {
        self.alpine.resolve_layer_reporting(self.sink)
    }

    /// [`Alpine::stage_layer`], reporting to the attached sink.
    ///
    /// The sink sees the increment's downloads and the output of every script
    /// run in the overlay-rooted cage, which is the whole of what a layered
    /// build has to report.
    pub fn stage_layer(&mut self, upper: impl AsRef<Path>) -> Result<BuildLayer, ProvisionError> {
        self.alpine.stage_layer_reporting(upper.as_ref(), self.sink)
    }
}

impl Provisioner for Observed<'_> {
    /// Bootstraps as [`Alpine`] does, reporting to the attached sink rather than
    /// through the run's shared vocabulary.
    fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
        let mut observer = ObservedRun {
            sink: self.sink,
            request,
        };
        self.alpine
            .provision_reporting(request.staging(), &mut observer)
    }
}

/// An observer that reports through the run's shared vocabulary and takes its
/// cancellation from the run: what an unobserved [`Alpine`] uses.
struct RunObserver<'a, 'r> {
    request: &'a ProvisionRequest<'r>,
}

impl AlpineObserver for RunObserver<'_, '_> {
    fn progress(&mut self, event: AlpineEvent<'_>) {
        self.request.report(super::ProvisionEvent::Alpine(&event));
    }

    fn cancelled(&mut self) -> bool {
        self.request.cancelled()
    }
}

/// An observer that reports to a sink the caller bound with [`Alpine::observe`]
/// and takes its cancellation from the run.
struct ObservedRun<'a, 'r, 'o> {
    sink: &'o mut dyn AlpineObserver,
    request: &'a ProvisionRequest<'r>,
}

impl AlpineObserver for ObservedRun<'_, '_, '_> {
    fn progress(&mut self, event: AlpineEvent<'_>) {
        self.sink.progress(event);
    }

    fn cancelled(&mut self) -> bool {
        self.request.cancelled()
    }
}

/// An observer that reports nowhere and never cancels: what an entry point the
/// caller attached no sink to uses.
struct Silent;

impl AlpineObserver for Silent {}

/// One package acquired and verified, waiting to be laid down.
#[derive(Debug)]
struct Acquired {
    /// The plan entry it answers, which is where its name, version and
    /// architecture are checked against what arrived.
    planned: PlannedPackage,
    /// What the container says about itself, and where its file tree begins.
    package: apk::Package,
    /// The cached file, to be read a second time for the extraction.
    path: PathBuf,
    /// The file's length, which the record states as `S:`.
    size: u64,
}

/// What must hold before anything is downloaded.
///
/// An unavailable identity map or an unrunnable architecture is a configuration
/// problem, and both are cheaper to report now than after a closure has been
/// fetched. Neither applies to an extract-only run, which executes nothing.
fn preflight(alpine: &Alpine) -> Result<(), AlpineError> {
    if alpine.extract_only {
        return Ok(());
    }
    preflight_foreign(&host_architecture(), &alpine.architecture)?;
    // The identity posture is never quietly downgraded to the single-identity
    // form.
    if !matches!(alpine.identity_map, IdentityMap::Single)
        && let Err(reason) = crate::idmap::resolve_default_chain(&alpine.identity_map)
    {
        return Err(AlpineError::Config {
            reason: format!("the requested identity map is unavailable: {reason}"),
        });
    }
    Ok(())
}

/// The whole bootstrap: preflight, then install into the staging tree.
fn bootstrap_release(
    alpine: &mut Alpine,
    staging: &Path,
    observer: &mut dyn AlpineObserver,
) -> Result<(), ProvisionError> {
    // A provisioner configured with a base layer is a layered one, and this
    // would quietly bootstrap a whole root into a directory the caller meant as
    // an increment over that base.
    if alpine.base_layer.is_some() {
        return Err(wrap(AlpineError::Config {
            reason: "a provisioner with a base layer stages an increment, and is used through \
                     Alpine::stage_layer rather than through provision::ensure"
                .to_string(),
        }));
    }
    preflight(alpine).map_err(wrap)?;
    install(alpine, staging, None, observer)
}

/// Resolve or read the plan, fetch and verify every package, lay the closure
/// down, and configure it.
///
/// `into` is the tree being written — a whole root for a bootstrap, the overlay
/// upper for a layered build — and `base` is the provisioned root beneath it
/// where there is one. One body serves both so that a layered build differs from
/// a bootstrap in what it resolves against and where its scripts are rooted, and
/// in nothing else.
fn install(
    alpine: &mut Alpine,
    into: &Path,
    base: Option<&layer::Base>,
    observer: &mut dyn AlpineObserver,
) -> Result<(), ProvisionError> {
    // A plan is the resolution: no index is fetched, which is the whole of what
    // installing from one saves. It is reported as it stands rather than
    // re-projected, so an observer sees the same event either way.
    let plan = match alpine.plan.clone() {
        Some(plan) => plan,
        None => alpine.resolve_over(base, observer).map_err(wrap)?,
    };
    observer.progress(AlpineEvent::Resolved { plan: &plan });

    if let Some(base) = base {
        // The resolver reports this as the upgrade it is, with the dependency
        // that forced it; a plan reaches here without having been resolved
        // against this base at all, so the check is made against the plan rather
        // than only inside the resolution.
        let carried: Vec<&str> = base.records().map(|record| record.name.as_str()).collect();
        let doubled: Vec<&str> = plan
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .filter(|name| carried.contains(name))
            .collect();
        if !doubled.is_empty() {
            return Err(wrap(AlpineError::Config {
                reason: format!(
                    "the increment would install {}, which the base layer already carries; an \
                     increment installs over a base rather than replacing part of it",
                    doubled.join(", "),
                ),
            }));
        }
        // An increment with nothing in it needs no download and no script; the
        // build root is the base as it stands.
        if plan.packages.is_empty() {
            return Ok(());
        }
    }

    // The cache disposes of itself when this frame ends, on the failure paths
    // below as on the success path.
    let cache = PackageCache::beside(into, alpine.cache_dir.as_deref(), APK_CACHE);
    let acquired = acquire(
        &mut *alpine.fetcher,
        &plan,
        &alpine.architecture,
        cache.path(),
        observer,
    )?;

    let order = install_order(&acquired);
    let carried = base.map(layer::Base::carried).unwrap_or_default();
    let (database, subjects) = lay_down(into, carried, &acquired, &order, observer)?;

    // After every package's files are down, so this overwrites what they
    // shipped, and before any script runs, so a script reads what was injected.
    if let Some(overlay) = &alpine.overlay {
        super::extract::overlay_tree(into, overlay)?;
    }

    // The base's own state is carried forward rather than replaced: the files
    // written here shadow the base's copies through the overlay, so each has to
    // describe the merged root.
    let world = joined(
        base.map_or(&[], layer::Base::world),
        alpine.world.iter().cloned(),
    );
    let sources = joined(
        base.map_or(&[], layer::Base::repositories),
        alpine
            .repositories
            .iter()
            .flat_map(super::alpine::Repository::sources),
    );
    let beneath = base
        .map(|base| {
            Rooted::open(base.path()).map_err(AlpineError::at("opening the base", base.path()))
        })
        .transpose()
        .map_err(wrap)?;
    let state = bootstrap::State {
        world: &world,
        architecture: &alpine.architecture,
        sources: &sources,
        repositories: &alpine.repositories,
        beneath: beneath.as_ref(),
    };

    if alpine.extract_only {
        // Registration is a file format here rather than a program's output, so
        // an extract-only root still knows what it holds.
        return bootstrap::register(into, &database, &state).map_err(wrap);
    }
    // A base's own trigger-watching packages fire for the directories this
    // install created, which is what `apk` does: a trigger belongs to the root
    // rather than to the transaction.
    let watching = match base {
        Some(base) => base.trigger_subjects().map_err(wrap)?,
        None => Vec::new(),
    };
    bootstrap::configure(
        into,
        Rooting::over(base.map(layer::Base::path)),
        &database,
        &subjects,
        &watching,
        &state,
        &alpine.identity_map,
        observer,
    )
    .map_err(wrap)
}

/// A base layer's lines and this run's, in that order and without a repeat.
///
/// The base's order is kept because `apk` reads `/etc/apk/repositories` top to
/// bottom, and a line the base already records is not written twice.
fn joined(carried: &[String], mine: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut all = carried.to_vec();
    for one in mine {
        if !all.contains(&one) {
            all.push(one);
        }
    }
    all
}

/// Fetches every package the plan names into the cache and verifies it there.
///
/// A cached entry is used only when it reads back as the package the plan names.
/// That is a stronger check than a Debian pool's, and it has to be: an apk index
/// publishes no digest of the whole file, so what identifies a package is its
/// signature, the control identity the index recorded, and the `datahash`
/// binding its file tree — all of which this reads anyway.
fn acquire(
    fetcher: &mut dyn Fetch,
    plan: &Plan,
    architecture: &str,
    cache: &Path,
    observer: &mut dyn AlpineObserver,
) -> Result<Vec<Acquired>, ProvisionError> {
    std::fs::create_dir_all(cache)
        .map_err(|err| ProvisionError::io("creating the package directory", cache, err))?;

    let mut acquired = Vec::with_capacity(plan.packages.len());
    for (position, planned) in plan.packages.iter().enumerate() {
        // A package boundary: whatever has been downloaded is complete and the
        // staging tree is untouched, so stopping here costs nothing.
        if observer.cancelled() {
            return Err(ProvisionError::Cancelled);
        }
        let index = plan.indexes.get(planned.index).ok_or_else(|| {
            wrap(AlpineError::Config {
                reason: format!(
                    "the plan attributes {} to index {}, and records {}",
                    planned.name,
                    planned.index,
                    plan.indexes.len(),
                ),
            })
        })?;
        let path = cache.join(planned.file_name());

        // A cached entry that does not read back as this package is not an
        // error; it is a download waiting to happen.
        let held = match read_acquired(&path, planned, architecture) {
            Ok(held) => held,
            Err(_) => {
                observer.progress(AlpineEvent::Downloading {
                    package: &planned.name,
                    index: position + 1,
                    total: plan.packages.len(),
                });
                let url = format!(
                    "{}/{architecture}/{}",
                    index.directory(),
                    planned.file_name()
                );
                observer.progress(AlpineEvent::Fetching { url: &url });
                download(fetcher, &url, planned, &path).map_err(wrap)?;
                read_acquired(&path, planned, architecture).map_err(wrap)?
            }
        };
        acquired.push(held);
    }
    Ok(acquired)
}

/// Reads a cached `.apk` and holds it to the plan entry it answers.
///
/// This is the index-to-package binding, and it is the whole of what
/// authenticates a package: the control identity is recomputed over the bytes
/// that arrived and compared to the one the plan records — which came out of a
/// verified index, or out of a plan a caller kept — and the package's own name,
/// version and architecture are compared to the plan's.
///
/// The binding is what a signature alone cannot do. A signature says that *some*
/// package was signed; without the binding a mirror answers a request for
/// `musl-1.2.5-r23` with a validly signed `musl-1.2.5-r0` and nothing notices.
/// The package's own signature, meanwhile, adds nothing the identity has not
/// already fixed, and [`apk::Anchor`] records why it is read rather than
/// verified.
fn read_acquired(
    path: &Path,
    planned: &PlannedPackage,
    architecture: &str,
) -> Result<Acquired, AlpineError> {
    let subject = planned.file_name();
    let mut file = std::fs::File::open(path).map_err(AlpineError::at("reading a package", path))?;
    let size = file
        .metadata()
        .map_err(AlpineError::at("measuring a package", path))?
        .len();
    let package = apk::read_package(
        &subject,
        &mut apk::Segments::new(&mut file),
        MAX_CONTROL_SEGMENT,
    )?;

    if package.control_identity != planned.control_identity {
        return Err(AlpineError::Digest {
            subject,
            expected: planned.control_identity.clone(),
            actual: package.control_identity,
        });
    }
    // The identity above already fixes the control segment's bytes, so these
    // cannot disagree with it unless the plan itself does. They are checked
    // because a plan is a document a caller may have edited, and a plan whose
    // fields contradict the package it names should be refused rather than
    // silently overruled by the digest.
    let stated = |what: &str, want: &str, got: &str| AlpineError::Config {
        reason: format!(
            "the plan names {} at {what} {want:?}, and the package it identifies states \
                 {got:?}",
            planned.name,
        ),
    };
    if package.info.name != planned.name {
        return Err(stated("package", &planned.name, &package.info.name));
    }
    if package.info.version != planned.version {
        return Err(stated("version", &planned.version, &package.info.version));
    }
    if !package.info.is_noarch() && package.info.architecture != architecture {
        return Err(stated(
            "architecture",
            architecture,
            &package.info.architecture,
        ));
    }

    Ok(Acquired {
        planned: planned.clone(),
        package,
        path: path.to_path_buf(),
        size,
    })
}

/// Downloads one package into the cache, atomically.
///
/// The body is written to a staging file beside the destination and renamed onto
/// it, so nothing unverified is ever visible at the cache path and a concurrent
/// download of the same package publishes its own file rather than consuming
/// this one. The verification happens on the read that follows, which is the
/// same read a cache hit goes through — one code path, whichever produced the
/// file.
///
/// The index's `S:` bounds what the download may spend. It is a length a
/// verified source declared, so it travels as [`FetchRequest::sized`] as well as
/// capping the writer; an index that states none leaves the download bounded by
/// the fetcher's own ceiling, which is weaker rather than wrong.
fn download(
    fetcher: &mut dyn Fetch,
    url: &str,
    planned: &PlannedPackage,
    dest: &Path,
) -> Result<(), AlpineError> {
    let staged = super::staging_path(dest);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(AlpineError::at("staging a package", &staged))?;

    let request = FetchRequest::new(url);
    let fetched = match planned.size {
        Some(size) => fetcher.fetch(
            &request.sized(size),
            &mut LimitedWriter::new(&mut std::io::BufWriter::new(file), size),
        ),
        None => fetcher.fetch(&request, &mut std::io::BufWriter::new(file)),
    };
    let published = fetched.map_err(AlpineError::Fetch).and_then(|()| {
        std::fs::rename(&staged, dest).map_err(AlpineError::at("publishing a package", dest))
    });
    if published.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    published
}

/// The order the closure is laid down and configured in: a package after
/// everything it needs.
fn install_order(acquired: &[Acquired]) -> Vec<usize> {
    let mut provides: HashMap<String, Vec<usize>> = HashMap::new();
    for (at, held) in acquired.iter().enumerate() {
        provides
            .entry(held.package.info.name.clone())
            .or_default()
            .push(at);
        for entry in &held.package.info.provides {
            // A `p:` entry may state a version; the name is what a dependency
            // names it by.
            let name = entry
                .split_once(['=', '<', '>', '~'])
                .map_or(entry.as_str(), |(name, _)| name);
            provides.entry(name.to_string()).or_default().push(at);
        }
    }
    let depends: Vec<Vec<String>> = acquired
        .iter()
        .map(|held| {
            held.package
                .info
                .depends
                .iter()
                .filter(|entry| !entry.starts_with('!'))
                .map(|entry| {
                    entry
                        .split_once(['=', '<', '>', '~'])
                        .map_or(entry.clone(), |(name, _)| name.to_string())
                })
                .collect()
        })
        .collect();
    bootstrap::dependency_order(&depends, &provides)
}

/// Lays every package's file tree into the staging tree, building the installed
/// database as it goes.
///
/// One pass per package, in `order`, and the second read of each cached file:
/// the first established that the bytes are the package, and this one decodes
/// the file tree it already digested.
fn lay_down(
    staging: &Path,
    carried: Carried,
    acquired: &[Acquired],
    order: &[usize],
    observer: &mut dyn AlpineObserver,
) -> Result<(Database, Vec<ScriptSubject>), ProvisionError> {
    let mut extraction = Extraction::new(staging)?.root_mode(ROOTFS_ROOT_MODE);
    let mut database = Database::carrying(carried);
    let mut subjects = Vec::with_capacity(order.len());

    for at in order {
        let held = &acquired[*at];
        // A package boundary again: the staging tree is discarded wholesale by
        // `ensure` when this returns an error, so a partial layout is no hazard.
        if observer.cancelled() {
            return Err(ProvisionError::Cancelled);
        }
        observer.progress(AlpineEvent::Extracting {
            package: &held.package.info.name,
        });

        let record = installed::Record::open(
            &held.package.info,
            // The plan's rather than `.PKGINFO`'s, since a package built for
            // every architecture says `noarch` where the index — and so the
            // record apk writes — says the repository's.
            &held.planned.architecture,
            held.size,
            held.package.control_identity.clone(),
            held.package.control_identity_hex.clone(),
        )
        .with_scripts(held.package.scripts.clone());
        let at = database.add(record);

        let mut file = std::fs::File::open(&held.path)
            .map_err(|err| ProvisionError::io("reading the package", &held.path, err))?;
        file.seek(std::io::SeekFrom::Start(held.package.data_at))
            .map_err(|err| ProvisionError::io("reading the package", &held.path, err))?;
        let mut archive = TarReader::new(apk::data_reader(file));

        let mut collision = None;
        extraction.extract(&mut archive, &mut |entry, components| {
            record_entry(&mut database, at, entry, components, &mut collision)
        })?;
        if let Some(collision) = collision {
            return Err(wrap(collision));
        }

        subjects.push(ScriptSubject {
            name: held.package.info.name.clone(),
            version: held.package.info.version.clone(),
            scripts: held.package.scripts.clone(),
            triggers: held.package.info.triggers.clone(),
        });
    }

    extraction.finalize(staging)?;
    Ok((database, subjects))
}

/// Records one archive entry against the package laying it down, and decides
/// whether it may.
///
/// A kept claim skips the entry rather than failing it: returning an error would
/// abandon the package, and what the policy says is that *this file* stays as the
/// earlier package left it. The extractor is told so through [`Placement::Skip`],
/// which is the only way to say it — the record and the tree have to agree, and a
/// record saying the earlier package still owns the path while the later
/// package's bytes sat on disk would leave the finished root disagreeing with its
/// own `Z:` digest.
///
/// A contested claim is stashed rather than returned for the same reason it
/// cannot be an error here, and reported by the caller once the entry boundary
/// has passed.
fn record_entry(
    database: &mut Database,
    at: usize,
    entry: &crate::provision::tar::Entry,
    components: &[Vec<u8>],
    collision: &mut Option<AlpineError>,
) -> Result<Placement, ProvisionError> {
    let path = components.join(&b'/');
    if entry.typeflag == b'5' {
        // Directories are shared by construction — every package ships the ones
        // it writes into — so they are recorded rather than contested.
        database
            .record(at)
            .directory(&path, entry.uid, entry.gid, entry.mode);
        return Ok(Placement::Write);
    }

    match database.claim(at, &path) {
        Claim::Free | Claim::Replaces => {}
        Claim::Kept => return Ok(Placement::Skip),
        Claim::Contested { owner } => {
            collision.get_or_insert(AlpineError::Collision {
                owner,
                claimant: database.record(at).name.clone(),
                path: String::from_utf8_lossy(&path).into_owned(),
            });
            return Ok(Placement::Skip);
        }
    }

    database
        .record(at)
        .file(&path, entry.uid, entry.gid, entry.mode, entry.checksum_sha1);
    Ok(Placement::Write)
}

/// Checks that a full bootstrap for `target` can execute on `host`.
///
/// A bootstrap the host runs natively needs nothing. A foreign one runs the
/// target's `busybox` and install scripts through a `qemu-user` binfmt handler,
/// which is the kernel-side question [`binfmt::ready`] answers; the names here
/// are Alpine's, and the mapping onto qemu's is this layer's own because each
/// distribution spells its architectures differently.
fn preflight_foreign(host: &str, target: &str) -> Result<(), AlpineError> {
    // Identical architectures always run. Beyond that, an x86_64 host runs x86
    // binaries through the near-universal IA-32 compatibility mode, and the
    // relation is directional. Other nominally-compatible pairs — aarch64
    // running armv7 — depend on optional kernel support that is absent on many
    // hosts, so they are treated as foreign.
    if host == target || (host == "x86_64" && target == "x86") {
        return Ok(());
    }
    let interpreter = match target {
        "x86_64" => "x86_64",
        "x86" => "i386",
        "aarch64" => "aarch64",
        "armv7" | "armhf" => "arm",
        "ppc64le" => "ppc64le",
        "s390x" => "s390x",
        "riscv64" => "riscv64",
        "loongarch64" => "loongarch64",
        _ => {
            return Err(AlpineError::Config {
                reason: format!(
                    "a full bootstrap for {target} on a {host} host needs a qemu-user binfmt \
                     handler, and {target} is not a known qemu target; use extract_only instead"
                ),
            });
        }
    };
    binfmt::ready(interpreter).map_err(|missing| AlpineError::Config {
        reason: match missing {
            binfmt::Missing::Unregistered => format!(
                "a full bootstrap for {target} on a {host} host needs the qemu-{interpreter} \
                 binfmt handler registered (install qemu-user-static and binfmt support); use \
                 extract_only to lay out the rootfs without running target binaries"
            ),
            binfmt::Missing::Unusable(reason) => format!(
                "the qemu-{interpreter} binfmt handler is registered but {reason}; a foreign \
                 bootstrap needs it enabled and registered with the fix-binary (F) flag"
            ),
        },
    })
}

/// Surfaces a layer failure through the shared provisioning error.
fn wrap(error: AlpineError) -> ProvisionError {
    match error {
        AlpineError::Cancelled => ProvisionError::Cancelled,
        other => ProvisionError::other(other),
    }
}

/// A failure provisioning an Alpine rootfs.
#[derive(Debug)]
#[non_exhaustive]
pub enum AlpineError {
    /// The configuration cannot be provisioned from as it stands.
    #[non_exhaustive]
    Config {
        /// What is wrong with it, and what to do instead.
        reason: String,
    },
    /// An apk container is malformed, truncated, or carries something the
    /// reader refuses.
    #[non_exhaustive]
    Container {
        /// What was being read: a package's path, or the URL of an index.
        subject: String,
        /// What was wrong with it.
        reason: String,
    },
    /// A signature was not accepted: it did not verify against the key set, or
    /// the signature member was refused on its own terms.
    #[non_exhaustive]
    Signature {
        /// What was being verified: a package's path, or the URL of an index.
        subject: String,
        /// Why the signature was not accepted.
        reason: String,
    },
    /// Bytes did not have the digest the archive recorded for them.
    ///
    /// The container held together; what it carries is not what something that
    /// vouched for it said it would be. Either a mirror served a package that
    /// is not the one the index named, or the package's own file tree is not
    /// the one its metadata names.
    #[non_exhaustive]
    Digest {
        /// What was being checked: a package's file name, or the identity of
        /// its control segment.
        subject: String,
        /// The digest that was expected, as the archive spells it.
        expected: String,
        /// The digest the bytes actually have.
        actual: String,
    },
    /// An index's records are not the ones the format defines.
    ///
    /// The container held together and its signature verified; what it carries
    /// is not a readable set of records.
    #[non_exhaustive]
    Index {
        /// The URL of the index.
        subject: String,
        /// What was wrong with it.
        reason: String,
    },
    /// A pin could not be held: the repositories no longer supply a package at
    /// the version and with the bytes a plan recorded.
    #[non_exhaustive]
    Pin {
        /// Every package that could not be held, in name order.
        unheld: Vec<UnheldPin>,
    },
    /// A plan document could not be read, or a plan could not be written as
    /// one.
    #[non_exhaustive]
    PlanDocument {
        /// What was wrong with it.
        reason: String,
    },
    /// The closure the repositories offer is not one that can be installed.
    #[non_exhaustive]
    Resolve {
        /// What could not be resolved, and what the repositories offer instead.
        reason: String,
    },
    /// Two packages ship the same path and neither says it may take it from
    /// the other.
    ///
    /// `apk` warns, skips the file, and records the package as broken. A root
    /// is something a caller goes on to build on, so this layer refuses instead
    /// rather than publish a tree whose contents depend on which package was
    /// unpacked first.
    #[non_exhaustive]
    Collision {
        /// The package that laid the path down.
        owner: String,
        /// The package that would have overwritten it.
        claimant: String,
        /// The path both ship.
        path: String,
    },
    /// An install script did not succeed.
    #[non_exhaustive]
    Script {
        /// The package whose script it was.
        package: String,
        /// Which script it was: `pre-install`, `post-install` or `trigger`.
        script: &'static str,
        /// How it ended.
        status: crate::ExitStatus,
    },
    /// A cage could not be built or run.
    Launch(crate::Error),
    /// The bootstrap's observer asked it to stop.
    ///
    /// Surfaces to a caller as [`super::ProvisionError::Cancelled`].
    Cancelled,
    /// Fetching from the archive failed.
    Fetch(FetchError),
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

impl AlpineError {
    /// A host I/O failure, naming what the operation was doing and the path it
    /// concerned.
    ///
    /// Arguments run operation, then locator, then cause, which is the order
    /// every constructor in the crate takes them in.
    pub fn io(op: &'static str, path: impl Into<PathBuf>, source: io::Error) -> AlpineError {
        AlpineError::Io {
            op,
            path: path.into(),
            source,
        }
    }

    /// The same failure as a [`map_err`](Result::map_err) argument: names the
    /// operation and the path now, and takes the cause when it arrives.
    pub fn at(op: &'static str, path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> AlpineError {
        let path = path.into();
        move |source| AlpineError::Io { op, path, source }
    }

    /// A malformed container, naming what was being read and what was wrong.
    pub(crate) fn container(subject: impl Into<String>, reason: impl Into<String>) -> AlpineError {
        AlpineError::Container {
            subject: subject.into(),
            reason: reason.into(),
        }
    }

    /// A signature that was not accepted, naming what it covered and why.
    pub(crate) fn signature(subject: impl Into<String>, reason: impl Into<String>) -> AlpineError {
        AlpineError::Signature {
            subject: subject.into(),
            reason: reason.into(),
        }
    }

    /// An index whose records could not be read, naming which and why.
    pub(crate) fn index(subject: impl Into<String>, reason: impl Into<String>) -> AlpineError {
        AlpineError::Index {
            subject: subject.into(),
            reason: reason.into(),
        }
    }
}

impl From<FetchError> for AlpineError {
    fn from(err: FetchError) -> AlpineError {
        AlpineError::Fetch(err)
    }
}

impl From<resolve::ResolveError> for AlpineError {
    fn from(err: resolve::ResolveError) -> AlpineError {
        AlpineError::Resolve {
            reason: err.to_string(),
        }
    }
}

impl fmt::Display for AlpineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlpineError::Config { reason } => {
                write!(f, "the Alpine bootstrap is misconfigured: {reason}")
            }
            AlpineError::Container { subject, reason } => {
                write!(f, "the apk container {subject} is unusable: {reason}")
            }
            AlpineError::Signature { subject, reason } => {
                write!(f, "the signature over {subject} was not accepted: {reason}")
            }
            AlpineError::Digest {
                subject,
                expected,
                actual,
            } => write!(
                f,
                "{subject} does not have the digest the archive recorded for it: \
                 expected {expected}, got {actual}",
            ),
            AlpineError::Index { subject, reason } => {
                write!(f, "the index {subject} is unusable: {reason}")
            }
            AlpineError::Pin { unheld } => {
                write!(f, "the resolution could not be held to its pin: ")?;
                for (at, one) in unheld.iter().enumerate() {
                    if at > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{one}")?;
                }
                Ok(())
            }
            AlpineError::PlanDocument { reason } => {
                write!(f, "the Alpine plan document is unusable: {reason}")
            }
            AlpineError::Resolve { reason } => {
                write!(f, "dependency resolution failed: {reason}")
            }
            AlpineError::Collision {
                owner,
                claimant,
                path,
            } => write!(
                f,
                "{claimant} and {owner} both ship {path}, and neither declares that it replaces \
                 the other",
            ),
            AlpineError::Script {
                package,
                script,
                status,
            } => write!(f, "the {package} {script} script {status}"),
            AlpineError::Launch(err) => write!(f, "{err}"),
            AlpineError::Cancelled => f.write_str("the bootstrap was cancelled"),
            AlpineError::Fetch(err) => write!(f, "{err}"),
            AlpineError::Io { op, path, source } => write!(
                f,
                "an Alpine bootstrap step failed while {op} {}: {source}",
                path.display(),
            ),
        }
    }
}

impl std::error::Error for AlpineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AlpineError::Fetch(err) => Some(err),
            AlpineError::Launch(err) => Some(err),
            AlpineError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Containers a repository actually published, for the tests that read them.
///
/// The reader is held to bytes an archive served rather than to bytes this crate
/// wrote: a writer that agrees with its own reader proves nothing about either.
/// `tests/fixtures/alpine-archive/README.md` records where each came from and
/// what it was chosen for, and the crate manifest excludes the directory from
/// the packaged tarball.
#[cfg(test)]
pub(super) mod fixtures {
    /// 1320 bytes, and its data segment is an empty tar: the degenerate case a
    /// reader that treats an empty third segment as a missing one fails on.
    pub(super) const ALPINE_BASE: &[u8] =
        include_bytes!("../../../tests/fixtures/alpine-archive/alpine-base-3.23.5-r0.apk");

    /// A data segment of directories and regular files, and `arch = x86_64`
    /// rather than `noarch`.
    pub(super) const ALPINE_KEYS: &[u8] =
        include_bytes!("../../../tests/fixtures/alpine-archive/alpine-keys-2.6-r0.apk");

    /// Carries a symbolic link, and is large enough that its data segment spans
    /// many decoder buffers — the case that catches a reader which hashes the
    /// wrong bytes or loses a boundary.
    pub(super) const MUSL: &[u8] =
        include_bytes!("../../../tests/fixtures/alpine-archive/musl-1.2.5-r23.apk");

    /// Four install scripts, a `replaces` with a priority, and a file tree deep
    /// enough to exercise every line an installed record can carry.
    pub(super) const ALPINE_BASELAYOUT: &[u8] =
        include_bytes!("../../../tests/fixtures/alpine-archive/alpine-baselayout-3.7.2-r0.apk");

    /// The `installed` records `apk` itself wrote for `alpine-baselayout` and
    /// `musl`, lifted from Alpine's own published minirootfs.
    ///
    /// The database writer is measured against these rather than against its
    /// own output: they are what the tool this layer has to agree with produced,
    /// for two of the packages committed here.
    pub(super) const MINIROOTFS_INSTALLED: &[u8] =
        include_bytes!("../../../tests/fixtures/alpine-archive/minirootfs-installed");

    /// Alpine's `v3.23/main/x86_64` index.
    pub(super) const INDEX: &[u8] =
        include_bytes!("../../../tests/fixtures/alpine-archive/APKINDEX.tar.gz");

    /// postmarketOS's `v26.06/x86_64` index: the same container, a different
    /// key, a path one level shallower.
    pub(super) const POSTMARKETOS_INDEX: &[u8] =
        include_bytes!("../../../tests/fixtures/alpine-archive/pmos-APKINDEX.tar.gz");

    /// A published postmarketOS package, signed by a key no trust anchor holds.
    ///
    /// Its index is signed by `build.postmarketos.org` and the package by
    /// `pmos@local-6a50011b`, which varies from one postmarketOS package to the
    /// next. So it is the case that decides how a package is authenticated.
    pub(super) const POSTMARKETOS_BASELAYOUT: &[u8] =
        include_bytes!("../../../tests/fixtures/alpine-archive/pmos-baselayout-62-r0.apk");

    /// The name of the key that signs every Alpine x86_64 fixture here.
    pub(super) const ALPINE_KEY_NAME: &str = "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub";
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;

    use super::*;
    use crate::scratch::Scratch;

    /// A transport serving a fixed set of URLs and nothing else.
    struct Canned(HashMap<String, Vec<u8>>);

    impl Fetch for Canned {
        fn fetch(
            &mut self,
            request: &FetchRequest<'_>,
            sink: &mut dyn Write,
        ) -> Result<(), FetchError> {
            match self.0.get(request.url()) {
                Some(body) => sink
                    .write_all(body)
                    .map_err(FetchError::at("writing the body", request.url())),
                None => Err(FetchError::not_found(request.url())),
            }
        }
    }

    /// A transport that refuses one mirror's URLs the way the built-in client
    /// refuses one it cannot parse or whose scheme it does not speak, and
    /// delegates everything else.
    struct Unusable {
        refuse: &'static str,
        rest: Box<dyn Fetch>,
    }

    impl Fetch for Unusable {
        fn fetch(
            &mut self,
            request: &FetchRequest<'_>,
            sink: &mut dyn Write,
        ) -> Result<(), FetchError> {
            if request.url().starts_with(self.refuse) {
                return Err(FetchError::url(request.url(), "unsupported scheme"));
            }
            self.rest.fetch(request, sink)
        }
    }

    /// A transport serving the two published index fixtures at the paths their
    /// repositories publish them under.
    fn canned() -> Box<dyn Fetch> {
        Box::new(Canned(HashMap::from([
            (
                "http://mirror.invalid/alpine/v3.23/main/x86_64/APKINDEX.tar.gz".to_string(),
                fixtures::INDEX.to_vec(),
            ),
            (
                "http://mirror.invalid/pmos/v26.06/x86_64/APKINDEX.tar.gz".to_string(),
                fixtures::POSTMARKETOS_INDEX.to_vec(),
            ),
        ])))
    }

    /// The postmarketOS repository, as a caller configures one.
    fn postmarketos() -> Repository {
        Repository::builder("v26.06")
            .mirror("http://mirror.invalid/pmos")
            .keys(KeySet::postmarketos())
            .build()
            .expect("the repository validates")
    }

    #[test]
    fn a_published_index_is_read_through_the_transport_and_verified() {
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        let available = alpine.available().expect("the published index verifies");
        assert!(available.contains("busybox"));
        assert!(available.contains("alpine-base"));
        assert!(
            !available.contains("systemd"),
            "and nothing Alpine does not publish"
        );
        assert!(
            available.contains("so:libc.musl-x86_64.so.1"),
            "a virtual name the index provides",
        );
        assert!(
            available
                .providers("so:libc.musl-x86_64.so.1")
                .any(|name| name == "musl"),
            "and the package that provides it",
        );
    }

    #[test]
    fn a_local_repository_is_read_through_the_built_in_transport() {
        // The canned transport above proves the reader; this proves the URL a
        // repository formats and the bundled transport that fetches it, by
        // laying the published index out at the path Alpine publishes it under
        // and reading it back through `file://`.
        let scratch = Scratch::new("alpine-repository");
        let component = scratch.join("v3.23/main/x86_64");
        std::fs::create_dir_all(&component).expect("the repository tree is creatable");
        std::fs::write(component.join("APKINDEX.tar.gz"), fixtures::INDEX)
            .expect("the index is writable");

        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(crate::provision::file_url(scratch.path()).expect("the path is nameable"))
            .build()
            .expect("the bootstrap configures");
        assert!(
            alpine
                .available()
                .expect("the local index verifies")
                .contains("busybox"),
        );
    }

    #[test]
    fn two_repositories_merge_in_the_order_they_were_configured() {
        // postmarketOS is Alpine's repositories plus its own, on a path one
        // level shallower and under a key of its own. Nothing here is
        // postmarketOS-specific but the fixture.
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .repository(postmarketos())
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        let available = alpine.available().expect("both indexes verify");
        assert!(available.contains("alpine-base"), "from Alpine");
        assert!(available.contains("postmarketos-base"), "from postmarketOS",);
    }

    #[test]
    fn a_repository_verified_against_the_wrong_keys_is_refused() {
        // The postmarketOS index under Alpine's keys: the same format, a key
        // the set does not hold.
        let wrong = Repository::builder("v26.06")
            .mirror("http://mirror.invalid/pmos")
            .keys(KeySet::alpine("x86_64").expect("x86_64 is in the bundle"))
            .build()
            .expect("the repository validates");
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .repository(wrong)
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        let err = alpine
            .available()
            .expect_err("postmarketOS does not sign with Alpine's key");
        assert!(matches!(err, AlpineError::Signature { .. }), "{err}");
    }

    #[test]
    fn a_mirror_that_does_not_serve_the_index_is_walked_past() {
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://empty.invalid/alpine")
            .mirror_fallback("http://mirror.invalid/alpine")
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        assert!(
            alpine
                .available()
                .expect("the backstop serves it")
                .contains("busybox"),
        );
    }

    #[test]
    fn a_mirror_the_transport_will_not_accept_stops_the_walk() {
        // A `Url` failure is the caller's configuration rather than the
        // mirror's state, so it is reported against the mirror that carries it
        // instead of advancing. The backstop here does serve the index, which is
        // what makes the difference observable: a walk that advanced past the
        // refusal would succeed and say nothing about the unusable URL.
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://unusable.invalid/alpine")
            .mirror_fallback("http://mirror.invalid/alpine")
            .fetcher(Box::new(Unusable {
                refuse: "http://unusable.invalid/",
                rest: canned(),
            }))
            .build()
            .expect("the bootstrap configures");
        let err = alpine
            .available()
            .expect_err("the primary's URL is not one the transport accepts");
        assert!(
            matches!(err, AlpineError::Fetch(FetchError::Url { .. })),
            "{err}",
        );
    }

    #[test]
    fn no_mirror_serving_the_index_is_reported_as_the_fetch_failure_it_is() {
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://empty.invalid/alpine")
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        let err = alpine.available().expect_err("no mirror serves it");
        assert!(matches!(err, AlpineError::Fetch(_)), "{err}");
        // And it names the mirror that was asked, not the path alone: the walk
        // keeps the last failure so the diagnostic survives the walk.
        let reason = err.to_string();
        assert!(reason.contains("http://empty.invalid/alpine"), "{reason}");
    }

    #[test]
    fn an_exhausted_walk_is_reported_against_the_mirror_it_asked_last() {
        // Attribution, which is the whole value of keeping the last failure:
        // three mirrors, none serving, and the answer has to name the one the
        // walk ended on rather than the one it started with.
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://empty.invalid/first")
            .mirror_fallback("http://empty.invalid/second")
            .mirror_fallback("http://empty.invalid/last")
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        let reason = alpine
            .available()
            .expect_err("no mirror serves it")
            .to_string();
        assert!(reason.contains("http://empty.invalid/last"), "{reason}");
        assert!(!reason.contains("/first"), "{reason}");
    }

    #[test]
    fn an_architecture_the_bundle_has_no_keys_for_needs_keys_of_its_own() {
        let err = Alpine::builder("v3.23")
            .architecture("sparc64")
            .build()
            .expect_err("the bundle has no sparc64 keys");
        assert!(matches!(err, AlpineError::Config { .. }), "{err}");
        // And naming them is the whole remedy: the architecture itself is not
        // refused, since a mirror may serve one this crate has never heard of.
        let mut keys = KeySet::new();
        keys.insert(
            fixtures::ALPINE_KEY_NAME,
            include_str!("keyring/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"),
        )
        .expect("the key parses");
        Alpine::builder("v3.23")
            .architecture("sparc64")
            .keys(keys)
            .build()
            .expect("a key set of the caller's own is enough");
    }

    #[test]
    fn an_architecture_that_is_not_one_path_segment_is_refused() {
        for architecture in ["../etc", "x86_64/sub", "", "  ", "x86 64"] {
            let err = Alpine::builder("v3.23")
                .architecture(architecture)
                .build()
                .expect_err("the architecture is not addressable");
            assert!(
                matches!(err, AlpineError::Config { .. }),
                "{architecture:?}: {err}",
            );
        }
    }

    #[test]
    fn the_primary_defaults_to_main_and_an_empty_list_is_the_other_layout() {
        let default = Alpine::builder("v3.23")
            .architecture("x86_64")
            .build()
            .expect("the bootstrap configures");
        assert_eq!(
            default.repositories[0].indexes("x86_64"),
            [(
                Some("main"),
                "v3.23/main/x86_64/APKINDEX.tar.gz".to_string()
            )],
        );
        let shallow = Alpine::builder("v26.06")
            .architecture("x86_64")
            .components::<[&str; 0], &str>([])
            .build()
            .expect("the bootstrap configures");
        assert_eq!(
            shallow.repositories[0].indexes("x86_64"),
            [(None, "v26.06/x86_64/APKINDEX.tar.gz".to_string())],
        );
    }

    #[test]
    fn a_published_index_resolves_a_closure_and_records_what_it_resolved_against() {
        // The whole read half against 5,869 records an archive actually
        // published: the grammar, the merge, and the provider ranking all meet
        // real data here rather than the shapes a test writes.
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .include(["alpine-base"])
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        let plan = alpine.resolve().expect("alpine-base resolves");

        assert_eq!(plan.release, "v3.23");
        assert_eq!(plan.architecture, "x86_64");
        let names: Vec<&str> = plan
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect();
        assert!(names.contains(&"alpine-base"), "{names:?}");
        assert!(names.contains(&"busybox"), "pulled through the closure");
        assert!(
            names.contains(&"musl"),
            "and so is the provider of so:libc.musl-x86_64.so.1",
        );
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]), "{names:?}");

        let busybox = plan
            .packages
            .iter()
            .find(|package| package.name == "busybox")
            .expect("busybox is in the closure");
        assert!(busybox.control_identity.starts_with("Q1"));
        assert!(busybox.size.is_some_and(|size| size > 0));
        assert_eq!(
            busybox.file_name(),
            format!("busybox-{}.apk", busybox.version),
        );
        assert_eq!(busybox.index, 0);

        let [index] = &plan.indexes[..] else {
            panic!("one component was configured: {:?}", plan.indexes);
        };
        assert_eq!(index.mirror, "http://mirror.invalid/alpine");
        assert_eq!(index.component.as_deref(), Some("main"));
        assert_eq!(index.signed_by, fixtures::ALPINE_KEY_NAME);
        assert_eq!(
            index.sha256,
            crate::provision::digest::sha256_hex(fixtures::INDEX),
        );
        assert!(
            index
                .description
                .as_deref()
                .is_some_and(|built| built.starts_with("v3.23")),
            "{:?}",
            index.description,
        );
    }

    #[test]
    fn a_package_is_attributed_to_the_index_that_offered_it() {
        // With two repositories configured, the plan's index number is the only
        // thing that says where a package's bytes will be fetched from — and an
        // apk package is addressed relative to its own index's directory.
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .repository(postmarketos())
            // Not `postmarketos-base`: its closure reaches Alpine's
            // `community`, which these two fixtures do not carry. The overlay
            // is a real overlay, so most of what it publishes needs more of
            // Alpine than one component.
            .include(["postmarketos-baselayout"])
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        let plan = alpine.resolve().expect("the closure resolves");

        let base = plan
            .packages
            .iter()
            .find(|package| package.name == "postmarketos-baselayout")
            .expect("it was asked for");
        assert_eq!(base.index, 1, "the second index is postmarketOS's");
        assert_eq!(plan.indexes[1].component, None, "the shallower layout");
        assert!(
            plan.indexes[1].signed_by.contains("postmarketos"),
            "{}",
            plan.indexes[1].signed_by,
        );
        // And what it needs from Alpine is attributed to Alpine's.
        assert!(
            plan.packages
                .iter()
                .any(|package| package.name == "musl" && package.index == 0),
            "musl comes from Alpine's main",
        );
    }

    /// Lays `index` out at `path` under `root`, as an archive publishes it.
    fn publish_index(root: &std::path::Path, path: &str, index: &[u8]) {
        let directory = root.join(path);
        std::fs::create_dir_all(&directory).expect("the repository tree is creatable");
        std::fs::write(directory.join("APKINDEX.tar.gz"), index).expect("the index is writable");
    }

    #[test]
    fn an_overlay_repository_is_read_from_the_layout_it_publishes() {
        // The whole of what postmarketOS costs this layer, end to end and over
        // the bundled transport rather than a canned one: two archives, each at
        // the path it really publishes -- Alpine's
        // <release>/<component>/<architecture> and postmarketOS's
        // <release>/<architecture> -- each verified against its own keys, merged
        // into one closure.
        let scratch = Scratch::new("alpine-overlay");
        let alpine_mirror = scratch.join("alpine");
        let overlay_mirror = scratch.join("pmos");
        publish_index(&alpine_mirror, "v3.23/main/x86_64", fixtures::INDEX);
        publish_index(
            &overlay_mirror,
            "v26.06/x86_64",
            fixtures::POSTMARKETOS_INDEX,
        );

        let overlay = Repository::builder("v26.06")
            .mirror(crate::provision::file_url(&overlay_mirror).expect("the path is nameable"))
            .keys(KeySet::postmarketos())
            .build()
            .expect("the repository validates");
        let plan = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(crate::provision::file_url(&alpine_mirror).expect("the path is nameable"))
            .repository(overlay)
            // `akms` is one of the two names both archives publish, and the only
            // one whose closure both together can supply.
            .include(["akms"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("both indexes verify and the closure resolves");

        let akms = plan
            .packages
            .iter()
            .find(|package| package.name == "akms")
            .expect("it was asked for");
        assert_eq!(akms.index, 1, "the overlay's version is the one selected");
        assert_eq!(akms.version, "99990.3.0-r1");
        assert!(
            plan.packages
                .iter()
                .any(|package| package.name == "bubblewrap" && package.index == 0),
            "and what it needs from Alpine comes from Alpine",
        );

        // The two layouts, recorded as the plan saw them.
        assert_eq!(plan.indexes[0].component.as_deref(), Some("main"));
        assert_eq!(plan.indexes[0].signed_by, fixtures::ALPINE_KEY_NAME);
        assert_eq!(plan.indexes[1].component, None);
        assert_eq!(plan.indexes[1].signed_by, "build.postmarketos.org.rsa.pub");
    }

    #[test]
    fn an_overlay_can_answer_a_name_by_providing_it() {
        // postmarketOS's second way of overriding an Alpine package, and the
        // reason a postmarketOS root is not assembled by naming `alpine-base`:
        // `postmarketos-base` provides that name at `1000-r0`, a version no
        // Alpine release reaches, so the provider answers it. `apk` resolves the
        // two repositories the same way, down to which dependencies it then
        // cannot find.
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .repository(postmarketos())
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        let available = alpine.available().expect("both indexes verify");
        assert!(
            available
                .providers("alpine-base")
                .any(|name| name == "postmarketos-base"),
            "the overlay provides the name Alpine publishes as a package",
        );
    }

    #[test]
    fn an_overlay_package_is_bound_to_the_index_that_resolved_it() {
        // The chain closed over two archives, from bytes each of them published:
        // the postmarketOS index verifies against postmarketOS's key, the plan
        // records the `C:` that index carries, and the package the mirror serves
        // is accepted because it recomputes to that identity. Nothing here
        // consults the package's own signature, which is made by a builder key
        // no anchor holds.
        let scratch = Scratch::new("alpine-overlay-binding");
        let alpine_mirror = scratch.join("alpine");
        let overlay_mirror = scratch.join("pmos");
        publish_index(&alpine_mirror, "v3.23/main/x86_64", fixtures::INDEX);
        publish_index(
            &overlay_mirror,
            "v26.06/x86_64",
            fixtures::POSTMARKETOS_INDEX,
        );

        let overlay = Repository::builder("v26.06")
            .mirror(crate::provision::file_url(&overlay_mirror).expect("the path is nameable"))
            .keys(KeySet::postmarketos())
            .build()
            .expect("the repository validates");
        let plan = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(crate::provision::file_url(&alpine_mirror).expect("the path is nameable"))
            .repository(overlay)
            .include(["postmarketos-baselayout"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("the closure resolves");

        let planned = plan
            .packages
            .iter()
            .find(|package| package.name == "postmarketos-baselayout")
            .expect("it was asked for");
        let path = scratch.join(planned.file_name());
        std::fs::write(&path, fixtures::POSTMARKETOS_BASELAYOUT).expect("the package is writable");
        let held = read_acquired(&path, planned, "x86_64")
            .expect("the served package is the one the index named");
        assert_eq!(held.package.info.name, "postmarketos-baselayout");

        // And the binding is doing real work: the same file refused where the
        // plan names another version of it.
        let mut moved = planned.clone();
        moved.version = "61-r0".to_string();
        let err = read_acquired(&path, &moved, "x86_64")
            .expect_err("the mirror served a package the plan did not name");
        assert!(matches!(err, AlpineError::Config { .. }), "{err}");
    }

    #[test]
    fn an_overlay_overrides_by_version_rather_than_by_position() {
        // How postmarketOS actually overrides an Alpine package: it republishes
        // it at a version no Alpine release will reach -- `akms` at
        // `99990.3.0-r1` against Alpine's `0.3.0-r0` -- rather than relying on
        // being configured second. So the same package is selected with the
        // repositories in either order, and the equal-version shadowing rule
        // (proven over `Index::merge`) is not what the published archives lean
        // on.
        let scratch = Scratch::new("alpine-overlay-order");
        let alpine_mirror = scratch.join("alpine");
        let overlay_mirror = scratch.join("pmos");
        publish_index(&alpine_mirror, "v3.23/main/x86_64", fixtures::INDEX);
        publish_index(
            &overlay_mirror,
            "v26.06/x86_64",
            fixtures::POSTMARKETOS_INDEX,
        );
        let alpine_url = crate::provision::file_url(&alpine_mirror).expect("the path is nameable");
        let overlay_url =
            crate::provision::file_url(&overlay_mirror).expect("the path is nameable");

        // The overlay as the primary, with Alpine merged in after it.
        let alpine = Repository::builder("v3.23")
            .mirror(&alpine_url)
            .components(["main"])
            .keys(KeySet::alpine("x86_64").expect("x86_64 is in the bundle"))
            .build()
            .expect("the repository validates");
        let plan = Alpine::builder("v26.06")
            .architecture("x86_64")
            .mirror(&overlay_url)
            .components::<[&str; 0], &str>([])
            .keys(KeySet::postmarketos())
            .repository(alpine)
            .include(["akms"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("both indexes verify and the closure resolves");

        let akms = plan
            .packages
            .iter()
            .find(|package| package.name == "akms")
            .expect("it was asked for");
        assert_eq!(akms.version, "99990.3.0-r1");
        assert_eq!(akms.index, 0, "the overlay is the primary here");
    }

    /// A provisioner over the published Alpine fixture, installing `world`.
    fn provisioner(world: &[&str]) -> AlpineBuilder {
        Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .include(world.iter().copied())
            .fetcher(canned())
    }

    #[test]
    fn a_plan_pins_the_resolution_it_came_from() {
        // The round trip a reproduce case is: resolve, keep the plan, and
        // resolve again holding to it. Nothing has moved, so the closure is the
        // same one -- and it went through the whole check rather than round the
        // side of it.
        let plan = provisioner(&["alpine-base"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("alpine-base resolves");
        let again = provisioner(&["alpine-base"])
            .pin(plan.clone())
            .build()
            .expect("the pin is read")
            .resolve()
            .expect("the repositories still supply it");
        assert_eq!(again, plan);
    }

    #[test]
    fn a_pin_the_repositories_have_moved_past_is_refused_naming_every_package() {
        // A publish moves many packages together, so the failure reports them
        // all at once rather than one rebuild at a time.
        let mut plan = provisioner(&["alpine-base"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("alpine-base resolves");
        for package in &mut plan.packages {
            package.version = format!("{}9", package.version);
        }
        let err = provisioner(&["alpine-base"])
            .pin(plan.clone())
            .build()
            .expect("the pin is read")
            .resolve()
            .expect_err("the repositories offer none of those versions");
        match &err {
            AlpineError::Pin { unheld } => {
                assert_eq!(unheld.len(), plan.packages.len());
                let names: Vec<&str> = unheld.iter().map(|one| one.package.as_str()).collect();
                assert!(names.windows(2).all(|pair| pair[0] < pair[1]), "{names:?}");
                assert!(
                    unheld
                        .iter()
                        .all(|one| matches!(one.reason, UnheldReason::Version { .. })),
                    "{unheld:?}",
                );
            }
            other => panic!("expected a pin refusal, got {other}"),
        }
    }

    #[test]
    fn a_version_republished_over_different_bytes_is_refused() {
        // The event a recorded control identity exists to catch, and the one a
        // version comparison alone cannot see.
        let mut plan = provisioner(&["busybox"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("busybox resolves");
        plan.packages[0].control_identity = "Q1".to_string() + &"a".repeat(27) + "=";
        let err = provisioner(&["busybox"])
            .pin(plan)
            .build()
            .expect("the pin is read")
            .resolve()
            .expect_err("the index records other bytes for that version");
        assert!(
            matches!(&err, AlpineError::Pin { unheld }
                if matches!(unheld[0].reason, UnheldReason::Identity { .. })),
            "{err}",
        );
    }

    #[test]
    fn a_pin_naming_one_package_twice_is_refused_where_it_is_given() {
        let mut plan = provisioner(&["busybox"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("busybox resolves");
        let first = plan.packages[0].clone();
        plan.packages.push(first);
        let err = provisioner(&["busybox"])
            .pin(plan)
            .build()
            .expect_err("there is no version to hold it at");
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains("twice")),
            "{err}",
        );
    }

    #[test]
    fn a_resolution_with_nothing_included_is_refused() {
        // apk publishes no priority field, so there is no set the repositories
        // nominate on the caller's behalf and an empty world is an empty root.
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        let err = alpine.resolve().expect_err("nothing was included");
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains("include()")),
            "{err}",
        );
    }

    #[test]
    fn a_requested_name_the_repositories_do_not_offer_is_refused() {
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .include(["systemd"])
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        let err = alpine.resolve().expect_err("Alpine publishes no systemd");
        assert!(
            matches!(&err, AlpineError::Resolve { reason } if reason.contains("systemd")),
            "{err}",
        );
    }

    #[test]
    fn a_requested_name_carrying_a_version_is_refused_where_it_is_named() {
        // Rather than at the resolution, as a package nothing offers: the
        // caller wrote a constraint where a name goes, and the message that
        // says so belongs at the setter.
        for name in ["busybox>=1.37", "musl=1.2.5-r23", "python3~3.12"] {
            let err = Alpine::builder("v3.23")
                .architecture("x86_64")
                .include([name])
                .build()
                .expect_err("a constraint is not a package name");
            assert!(matches!(err, AlpineError::Config { .. }), "{name}: {err}");
        }
    }

    /// A plan entry for a committed package, read out of the package itself.
    ///
    /// The identity is recomputed rather than written down so the plan is one
    /// the binding accepts; what the test is about is the record, and a
    /// hand-typed digest would only ever prove that it was typed correctly.
    fn planned_from(container: &[u8], architecture: &str) -> PlannedPackage {
        let read = apk::read_package(
            "the fixture",
            &mut apk::Segments::new(container),
            MAX_CONTROL_SEGMENT,
        )
        .expect("the fixture reads");
        PlannedPackage::resolved(
            read.info.name.clone(),
            read.info.version.clone(),
            architecture.to_string(),
            read.control_identity,
            Some(container.len() as u64),
            read.info.installed_size,
            read.info.origin.clone(),
            0,
        )
    }

    #[test]
    fn the_database_written_is_the_one_apk_writes() {
        // The whole point of the writer, measured against the tool it has to
        // agree with: these are the records `apk` itself produced for two of
        // the committed packages, lifted out of Alpine's published minirootfs.
        // Every field, every file line, every digest and every mode has to come
        // back the same, in the same order.
        let scratch = Scratch::new("alpine-database");
        let cache = scratch.join("cache");
        std::fs::create_dir_all(&cache).expect("the cache is creatable");
        let staging = scratch.join("root");
        std::fs::create_dir_all(&staging).expect("the staging tree is creatable");

        let mut acquired = Vec::new();
        for container in [fixtures::ALPINE_BASELAYOUT, fixtures::MUSL] {
            let planned = planned_from(container, "x86_64");
            let path = cache.join(planned.file_name());
            std::fs::write(&path, container).expect("the package is writable");
            acquired.push(
                read_acquired(&path, &planned, "x86_64")
                    .expect("the package answers the plan entry"),
            );
        }

        let order: Vec<usize> = (0..acquired.len()).collect();
        let (database, subjects) =
            lay_down(&staging, Carried::default(), &acquired, &order, &mut Silent)
                .expect("the closure lays down");

        assert_eq!(
            String::from_utf8(database.installed()).expect("the database is text"),
            String::from_utf8(fixtures::MINIROOTFS_INSTALLED.to_vec())
                .expect("the fixture is text"),
        );

        // And the tree it laid down is the one the records describe.
        assert!(staging.join("lib/ld-musl-x86_64.so.1").is_file());
        assert_eq!(
            std::fs::read_link(staging.join("lib/libc.musl-x86_64.so.1"))
                .expect("musl ships the link"),
            std::path::Path::new("ld-musl-x86_64.so.1"),
        );
        assert!(staging.join("etc/profile.d/README").is_file());

        // The scripts travelled with it, in the order they are archived.
        let baselayout = subjects
            .iter()
            .find(|subject| subject.name == "alpine-baselayout")
            .expect("it was laid down");
        let carried: Vec<&str> = baselayout
            .scripts
            .iter()
            .map(|(kind, _)| kind.name())
            .collect();
        assert_eq!(
            carried,
            ["pre-install", "post-install", "pre-upgrade", "post-upgrade"],
        );
    }

    #[test]
    fn a_package_that_is_not_the_one_the_plan_names_is_refused() {
        // The index-to-package binding, which is what makes a per-package
        // signature worth checking: this package is validly signed by a key the
        // repository publishes, and it is still not the one that was asked for.
        let scratch = Scratch::new("alpine-binding");
        let path = scratch.join("musl-1.2.5-r23.apk");
        std::fs::write(&path, fixtures::MUSL).expect("the package is writable");

        let mut planned = planned_from(fixtures::ALPINE_BASELAYOUT, "x86_64");
        planned.name = "musl".to_string();
        planned.version = "1.2.5-r23".to_string();
        let err = read_acquired(&path, &planned, "x86_64")
            .expect_err("the served package is not the one the plan identified");
        assert!(matches!(err, AlpineError::Digest { .. }), "{err}");

        // And a plan whose own fields contradict the package it identifies.
        let mut planned = planned_from(fixtures::MUSL, "x86_64");
        planned.name = "not-musl".to_string();
        let err = read_acquired(&path, &planned, "x86_64")
            .expect_err("the plan names a package the container does not");
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains("not-musl")),
            "{err}",
        );
    }

    #[test]
    fn a_package_from_an_unpublished_architecture_is_refused() {
        let scratch = Scratch::new("alpine-architecture");
        let path = scratch.join("musl-1.2.5-r23.apk");
        std::fs::write(&path, fixtures::MUSL).expect("the package is writable");
        let planned = planned_from(fixtures::MUSL, "aarch64");
        let err = read_acquired(&path, &planned, "aarch64")
            .expect_err("an x86_64 package is not an aarch64 one");
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains("architecture")),
            "{err}",
        );
    }

    #[test]
    fn a_local_repository_bootstraps_a_root_that_records_what_it_holds() {
        // The whole layer end to end and entirely offline: a repository laid
        // out at the paths Alpine publishes, read through the bundled
        // `file://` transport, resolved, verified, unpacked, and registered.
        // Extract-only because the committed fixtures are chosen for their
        // container shapes rather than for making a runnable root — there is no
        // `busybox` here to interpret a script.
        let scratch = Scratch::new("alpine-bootstrap");
        let component = scratch.join("v3.23/main/x86_64");
        std::fs::create_dir_all(&component).expect("the repository tree is creatable");
        std::fs::write(component.join("APKINDEX.tar.gz"), fixtures::INDEX)
            .expect("the index is writable");
        std::fs::write(component.join("musl-1.2.5-r23.apk"), fixtures::MUSL)
            .expect("the package is writable");

        let root = scratch.join("root");
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(crate::provision::file_url(scratch.path()).expect("the path is nameable"))
            .include(["musl"])
            .extract_only(true)
            .build()
            .expect("the bootstrap configures");
        assert_eq!(
            crate::provision::ensure(&root, &mut alpine).expect("the root is provisioned"),
            crate::provision::Provisioned::Created,
        );

        // The files the package ships, including the link that makes it a C
        // library rather than a directory of objects.
        assert!(root.join("lib/ld-musl-x86_64.so.1").is_file());
        assert_eq!(
            std::fs::read_link(root.join("lib/libc.musl-x86_64.so.1")).expect("the link is there"),
            std::path::Path::new("ld-musl-x86_64.so.1"),
        );

        // And the state that makes it a root apk recognizes rather than a
        // directory of files.
        let installed = std::fs::read_to_string(root.join("lib/apk/db/installed"))
            .expect("the database is written");
        assert!(installed.contains("\nP:musl\n"), "{installed}");
        assert!(
            installed.ends_with("\n\n"),
            "a record ends with a blank line"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("etc/apk/world")).expect("the world is written"),
            "musl\n",
            "what was asked for, not the closure",
        );
        assert_eq!(
            std::fs::read_to_string(root.join("etc/apk/arch")).expect("the arch is written"),
            "x86_64\n",
        );
        let sources = std::fs::read_to_string(root.join("etc/apk/repositories"))
            .expect("the repositories are written");
        assert!(sources.trim_end().ends_with("/v3.23/main"), "{sources}");
        assert!(
            !sources.contains("x86_64"),
            "apk appends the architecture itself: {sources}",
        );

        // The trust anchor, written because nothing in this closure ships one.
        assert!(
            root.join("etc/apk/keys")
                .join(fixtures::ALPINE_KEY_NAME)
                .is_file(),
        );
        // Nothing ran, so nothing was left behind by a script.
        assert!(!root.join("lib/apk/exec").exists());
        assert_eq!(
            std::fs::read(root.join("lib/apk/db/triggers")).expect("the file is written"),
            b"",
            "musl watches nothing",
        );
    }

    /// A repository laid out at the paths Alpine publishes, serving the index
    /// and each named fixture, and the `file://` URL of its root.
    fn published(scratch: &Scratch, packages: &[(&str, &[u8])]) -> String {
        let component = scratch.join("v3.23/main/x86_64");
        std::fs::create_dir_all(&component).expect("the repository tree is creatable");
        std::fs::write(component.join("APKINDEX.tar.gz"), fixtures::INDEX)
            .expect("the index is writable");
        for (name, body) in packages {
            std::fs::write(component.join(name), body).expect("the package is writable");
        }
        crate::provision::file_url(scratch.path()).expect("the path is nameable")
    }

    /// A base root holding `world`, provisioned offline from `mirror`.
    ///
    /// Extract-only because the committed fixtures are chosen for their
    /// container shapes rather than for making a runnable root: there is no
    /// `busybox` here to interpret a script. Everything a layered build reads
    /// off a base is written either way, which is the point of registration
    /// being a file format.
    fn provisioned_base(mirror: &str, at: &Path, world: &[&str]) -> PathBuf {
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(mirror)
            .include(world.iter().copied())
            .extract_only(true)
            .build()
            .expect("the bootstrap configures");
        crate::provision::ensure(at, &mut alpine).expect("the base is provisioned");
        at.to_path_buf()
    }

    /// A hand-written base database holding one package at one version, for the
    /// resolution cases a committed fixture cannot express.
    fn base_recording(scratch: &Scratch, tag: &str, records: &[(&str, &str, &str)]) -> PathBuf {
        let base = scratch.join(tag);
        std::fs::create_dir_all(base.join("lib/apk/db")).expect("the tree is creatable");
        let mut database = String::new();
        let alphabet = "abcdefghijklmnopqrstuvwxyz".repeat(2);
        for (at, (name, version, fields)) in records.iter().enumerate() {
            // A distinct well-formed control identity per record, which the
            // reader checks the shape of and nothing here reads.
            let identity = format!("Q1{}=", &alphabet[at..at + 27]);
            database.push_str(&format!(
                "C:{identity}\nP:{name}\nV:{version}\nA:x86_64\nS:1024\nI:2048\n{fields}\n",
            ));
        }
        std::fs::write(base.join("lib/apk/db/installed"), database)
            .expect("the database is writable");
        base
    }

    #[test]
    fn an_increment_resolves_only_what_the_base_does_not_carry() {
        // The layered read half: the base answers for what it holds, so the
        // closure that comes back is the delta and nothing else.
        let scratch = Scratch::new("alpine-resolve-layer");
        let mirror = published(&scratch, &[("musl-1.2.5-r23.apk", fixtures::MUSL)]);
        let base = provisioned_base(&mirror, &scratch.join("base"), &["musl"]);

        let plan = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .base_layer(&base)
            .include(["busybox", "musl"])
            .build()
            .expect("the bootstrap configures")
            .resolve_layer()
            .expect("the increment resolves");
        let names: Vec<&str> = plan
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["busybox"],
            "musl is in the base, and so is the so: name busybox needs",
        );

        // And the whole-root resolution of the same request, for contrast: the
        // base is the only difference between them.
        let whole = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .include(["busybox", "musl"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("the closure resolves");
        let names: Vec<&str> = whole
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect();
        assert_eq!(names, ["busybox", "musl"]);
    }

    #[test]
    fn an_increment_that_would_replace_a_base_package_is_refused() {
        // The base answers at the version it records rather than merely by name,
        // so a dependency its version cannot meet is reported as the upgrade it
        // would be. `alpine-baselayout` needs its data package at exactly its own
        // version, and this base carries an older one.
        let scratch = Scratch::new("alpine-upgrade");
        let mirror = published(&scratch, &[]);
        let base = base_recording(
            &scratch,
            "base",
            &[
                ("alpine-baselayout-data", "3.7.0-r0", ""),
                ("busybox", "1.37.0-r30", "p:/bin/sh"),
            ],
        );

        let err = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .base_layer(&base)
            .include(["alpine-baselayout"])
            .build()
            .expect("the bootstrap configures")
            .resolve_layer()
            .expect_err("the base carries an older alpine-baselayout-data");
        assert!(
            matches!(&err, AlpineError::Resolve { reason }
                if reason.contains("3.7.0-r0") && reason.contains("alpine-baselayout-data")),
            "{err}",
        );

        // The same base, with the data package at the version the closure needs:
        // now the increment is `alpine-baselayout` alone.
        let base = base_recording(
            &scratch,
            "current",
            &[
                ("alpine-baselayout-data", "3.7.2-r0", ""),
                ("busybox", "1.37.0-r30", "p:/bin/sh"),
            ],
        );
        let plan = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .base_layer(&base)
            .include(["alpine-baselayout"])
            .build()
            .expect("the bootstrap configures")
            .resolve_layer()
            .expect("the base answers both of its dependencies");
        let names: Vec<&str> = plan
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect();
        assert_eq!(names, ["alpine-baselayout"]);
    }

    #[test]
    fn a_layered_entry_point_without_a_base_is_refused_where_it_is_called() {
        let scratch = Scratch::new("alpine-no-base");
        let mirror = published(&scratch, &[("musl-1.2.5-r23.apk", fixtures::MUSL)]);
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .include(["musl"])
            .build()
            .expect("the bootstrap configures");
        let err = alpine.resolve_layer().expect_err("no base layer was set");
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains("resolve_layer")),
            "{err}",
        );
        let Err(err) = alpine.stage_layer(scratch.join("upper")) else {
            panic!("no base layer was set");
        };
        assert!(err.to_string().contains("stage_layer"), "{err}");

        // And the other way round: a provisioner that has a base is a layered
        // one, and bootstrapping a whole root into the caller's directory would
        // be answering a question they did not ask.
        let base = provisioned_base(&mirror, &scratch.join("base"), &["musl"]);
        let mut layered = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .base_layer(&base)
            .include(["musl"])
            .extract_only(true)
            .build()
            .expect("the bootstrap configures");
        let Err(err) = crate::provision::ensure(scratch.join("whole"), &mut layered) else {
            panic!("a base layer was set");
        };
        assert!(err.to_string().contains("stage_layer"), "{err}");
    }

    #[test]
    fn an_increment_stages_into_the_upper_and_records_the_merged_root() {
        // The layered write half, entirely offline. The base is provisioned
        // first, then an increment is staged over it: the increment's files land
        // in the upper, the base is not written to, and the database the upper
        // carries describes both.
        let scratch = Scratch::new("alpine-stage-layer");
        let mirror = published(
            &scratch,
            &[
                ("musl-1.2.5-r23.apk", fixtures::MUSL),
                ("alpine-keys-2.6-r0.apk", fixtures::ALPINE_KEYS),
            ],
        );
        let base = provisioned_base(&mirror, &scratch.join("base"), &["alpine-keys"]);
        let upper = scratch.join("upper");

        {
            let layer = Alpine::builder("v3.23")
                .architecture("x86_64")
                .mirror(&mirror)
                .base_layer(&base)
                .include(["musl", "alpine-keys"])
                .extract_only(true)
                .build()
                .expect("the bootstrap configures")
                .stage_layer(&upper)
                .expect("the increment stages");
            assert_eq!(layer.path(), upper.as_path());

            // The increment's files are in the upper and the base is untouched.
            assert!(upper.join("lib/ld-musl-x86_64.so.1").is_file());
            assert!(
                !base.join("lib/ld-musl-x86_64.so.1").exists(),
                "the base is the read-only lower and is never written to",
            );
            // `alpine-keys` was already in the base, so it is not staged again.
            assert!(!upper.join("usr/share/apk/keys").exists());

            // The database the upper carries describes the merged root: the
            // base's record byte for byte, and the increment's sorted in among
            // them.
            let installed = std::fs::read_to_string(upper.join("lib/apk/db/installed"))
                .expect("the database is written");
            let names: Vec<&str> = installed
                .lines()
                .filter_map(|line| line.strip_prefix("P:"))
                .collect();
            assert_eq!(names, ["alpine-keys", "musl"]);
            let carried = std::fs::read_to_string(base.join("lib/apk/db/installed"))
                .expect("the base's database is there");
            assert!(
                installed.contains(carried.trim_end_matches('\n')),
                "the base's record is carried through unchanged",
            );

            // And so does the rest of the state.
            assert_eq!(
                std::fs::read_to_string(upper.join("etc/apk/world")).expect("the world is written"),
                "alpine-keys\nmusl\n",
                "what the base asked for and what the increment asked for",
            );
            // The base already holds the trust anchor and the overlay makes it
            // visible, so writing one here would shadow a file rather than add
            // one.
            assert!(!upper.join("etc/apk/keys").exists());
            let sources = std::fs::read_to_string(upper.join("etc/apk/repositories"))
                .expect("the repositories are written");
            assert_eq!(sources.lines().count(), 1, "not written twice: {sources}");
        }

        // Dropping the layer discards the increment and leaves the base.
        assert!(!upper.exists(), "the upper went with the handle");
        assert!(base.join("lib/apk/db/installed").is_file());
    }

    #[test]
    fn an_increment_the_base_already_satisfies_stages_nothing() {
        // Every requested package is in the base, so there is nothing to
        // download and nothing to run; the build root is the base as it stands.
        let scratch = Scratch::new("alpine-empty-increment");
        let mirror = published(&scratch, &[("musl-1.2.5-r23.apk", fixtures::MUSL)]);
        let base = provisioned_base(&mirror, &scratch.join("base"), &["musl"]);
        let upper = scratch.join("upper");

        let layer = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .base_layer(&base)
            .include(["musl"])
            .extract_only(true)
            .build()
            .expect("the bootstrap configures")
            .stage_layer(&upper)
            .expect("the increment stages");
        assert!(layer.path().is_dir(), "the upper exists and is empty");
        assert_eq!(
            std::fs::read_dir(&upper)
                .expect("the upper is readable")
                .count(),
            0,
        );
    }

    #[test]
    fn a_failed_staging_disposes_of_the_upper_it_created() {
        // The upper is created before the increment resolves, and a failure
        // hands the caller no handle to drop — so the failure path has to
        // dispose of it.
        let scratch = Scratch::new("alpine-failed-staging");
        let mirror = published(&scratch, &[("musl-1.2.5-r23.apk", fixtures::MUSL)]);
        let base = provisioned_base(&mirror, &scratch.join("base"), &["musl"]);
        let upper = scratch.join("upper");

        let Err(err) = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .base_layer(&base)
            .include(["systemd"])
            .extract_only(true)
            .build()
            .expect("the bootstrap configures")
            .stage_layer(&upper)
        else {
            panic!("Alpine publishes no systemd");
        };
        assert!(err.to_string().contains("systemd"), "{err}");
        assert!(
            !upper.exists(),
            "the upper it created went with the failure"
        );
    }

    #[test]
    fn a_bootstrap_reports_what_it_is_doing_and_can_be_stopped() {
        let scratch = Scratch::new("alpine-observed");
        let component = scratch.join("v3.23/main/x86_64");
        std::fs::create_dir_all(&component).expect("the repository tree is creatable");
        std::fs::write(component.join("APKINDEX.tar.gz"), fixtures::INDEX)
            .expect("the index is writable");
        std::fs::write(component.join("musl-1.2.5-r23.apk"), fixtures::MUSL)
            .expect("the package is writable");

        /// Records the events it sees, and stops once it has seen a download.
        struct Watch {
            seen: Vec<String>,
            stop: bool,
        }

        impl AlpineObserver for Watch {
            fn progress(&mut self, event: AlpineEvent<'_>) {
                match event {
                    AlpineEvent::Resolving => self.seen.push("resolving".to_string()),
                    AlpineEvent::Resolved { plan } => {
                        self.seen.push(format!("resolved {}", plan.packages.len()));
                    }
                    AlpineEvent::Downloading { package, .. } => {
                        self.seen.push(format!("downloading {package}"));
                    }
                    AlpineEvent::Extracting { package } => {
                        self.seen.push(format!("extracting {package}"));
                    }
                    _ => {}
                }
            }

            fn cancelled(&mut self) -> bool {
                // Once the closure is known, which is the first boundary a
                // caller watching the plan would decide at.
                self.stop && self.seen.iter().any(|seen| seen.starts_with("resolved"))
            }
        }

        let mirror = crate::provision::file_url(scratch.path()).expect("the path is nameable");
        let mut watch = Watch {
            seen: Vec::new(),
            stop: false,
        };
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .include(["musl"])
            .extract_only(true)
            .build()
            .expect("the bootstrap configures");
        crate::provision::ensure(scratch.join("root"), &mut alpine.observe(&mut watch))
            .expect("the root is provisioned");
        assert_eq!(
            watch.seen,
            [
                "resolving",
                "resolved 1",
                "downloading musl",
                "extracting musl",
            ],
        );

        // And stopping. A sink bound with `observe` reports; what stops a run
        // is the run's own observer, which is the one a caller driving several
        // provisioners shares — so that is where the cancellation comes from,
        // and the Alpine events still reach it through the shared vocabulary.
        struct StopOnResolve {
            resolved: bool,
        }

        impl crate::provision::ProvisionObserver for StopOnResolve {
            fn progress(&mut self, event: crate::provision::ProvisionEvent<'_>) {
                if let crate::provision::ProvisionEvent::Alpine(AlpineEvent::Resolved { .. }) =
                    event
                {
                    self.resolved = true;
                }
            }

            fn cancelled(&mut self) -> bool {
                self.resolved
            }
        }

        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .include(["musl"])
            .extract_only(true)
            .build()
            .expect("the bootstrap configures");
        let stopped = scratch.join("stopped");
        let mut stop = StopOnResolve { resolved: false };
        let err = crate::provision::Provision::new(&stopped)
            .observe(&mut stop)
            .run(&mut alpine)
            .expect_err("the observer asked it to stop");
        assert!(
            matches!(err, crate::provision::ProvisionError::Cancelled),
            "{err}",
        );
        assert!(
            stop.resolved,
            "the Alpine events reached the run's observer"
        );
        assert!(!stopped.exists());
    }

    #[test]
    fn a_plan_installs_without_reading_an_index() {
        // What installing from a plan saves is the resolution, and this is the
        // proof: the repository serves the package and no index at all.
        let scratch = Scratch::new("alpine-planned");
        let component = scratch.join("v3.23/main/x86_64");
        std::fs::create_dir_all(&component).expect("the repository tree is creatable");
        std::fs::write(component.join("APKINDEX.tar.gz"), fixtures::INDEX)
            .expect("the index is writable");
        std::fs::write(component.join("musl-1.2.5-r23.apk"), fixtures::MUSL)
            .expect("the package is writable");
        let mirror = crate::provision::file_url(scratch.path()).expect("the path is nameable");

        let plan = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .include(["musl"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("musl resolves");

        // Round-tripped through the document, which is how a plan actually
        // travels between the machine that resolved it and the one that
        // installs it.
        let document = plan.to_document().expect("the plan is writable");
        let kept = Plan::parse_document(&document).expect("the document reads back");
        assert_eq!(kept, plan);

        std::fs::remove_file(component.join("APKINDEX.tar.gz")).expect("the index is removable");
        let root = scratch.join("root");
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .plan(kept)
            .extract_only(true)
            .build()
            .expect("the bootstrap configures");
        crate::provision::ensure(&root, &mut alpine).expect("the plan installs");
        assert!(root.join("lib/ld-musl-x86_64.so.1").is_file());
        let installed = std::fs::read_to_string(root.join("lib/apk/db/installed"))
            .expect("the database is written");
        assert!(installed.contains("\nP:musl\n"), "{installed}");
    }

    /// A one-entry uncompressed tar holding `path` with `contents`, as a
    /// package's data segment lays a file down.
    fn one_file_archive(path: &str, contents: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(
            &crate::provision::tar::ustar_block(
                path.as_bytes(),
                b"",
                0o644,
                0,
                0,
                contents.len() as u64,
                0,
                b'0',
                b"",
            )
            .expect("the header fields fit"),
        );
        out.extend_from_slice(contents);
        crate::provision::tar::pad(&mut out, contents.len() as u64).expect("padding a vector");
        // The two zero blocks that end an archive.
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    /// A record for a package named `name` that carries the extra `.PKGINFO`
    /// lines in `extra` — `replaces` and `replaces_priority`, for the collision
    /// policy.
    fn record_of(name: &str, extra: &str) -> installed::Record {
        let info = pkginfo::PkgInfo::parse(
            name,
            format!("pkgname = {name}\npkgver = 1.0-r0\narch = x86_64\n{extra}").as_bytes(),
        )
        .expect("the .PKGINFO reads");
        installed::Record::open(&info, "x86_64", 1024, format!("Q1{name}"), name.to_string())
    }

    /// Lays `packages` — each a name, its extra `.PKGINFO` lines, and the
    /// contents it ships at `CONTESTED` — down in order into a fresh tree, and
    /// returns that tree with the database written over it.
    ///
    /// Drives the real [`Extraction`] and the real [`record_entry`], which is
    /// the pairing the collision policy lives in: `claim` alone cannot say
    /// whether the tree agrees with the record of it.
    fn lay_contested(packages: &[(&str, &str, &[u8])]) -> (Scratch, Database) {
        const CONTESTED: &str = "usr/bin/tool";
        let scratch = Scratch::new("alpine-collision");
        let staging = scratch.join("root");
        std::fs::create_dir_all(&staging).expect("the staging tree is creatable");

        let mut extraction = Extraction::new(&staging).expect("the root opens");
        let mut database = Database::default();
        for (name, extra, contents) in packages {
            let at = database.add(record_of(name, extra));
            let archive = one_file_archive(CONTESTED, contents);
            let mut reader = TarReader::new(&archive[..]);
            let mut collision = None;
            extraction
                .extract(&mut reader, &mut |entry, components| {
                    record_entry(&mut database, at, entry, components, &mut collision)
                })
                .expect("the archive extracts");
            assert!(collision.is_none(), "{name}: {collision:?}");
        }
        extraction.finalize(&staging).expect("the metadata applies");
        (scratch, database)
    }

    #[test]
    fn a_kept_claim_leaves_the_earlier_package_s_file_on_disk() {
        // The record says the earlier package still owns the path, so the
        // earlier package's bytes have to be what is there. Without a way to
        // tell the extractor to skip the entry, the later package's bytes
        // overwrote them and the finished root disagreed with its own `Z:`
        // digest — which `apk audit` reports as a modified file.
        let (scratch, database) = lay_contested(&[
            (
                "aaa-earlier",
                "replaces = zzz-later\nreplaces_priority = 1\n",
                b"earlier",
            ),
            ("zzz-later", "", b"later"),
        ]);
        assert_eq!(
            std::fs::read(scratch.join("root/usr/bin/tool")).expect("the file is there"),
            b"earlier",
        );
        let installed = String::from_utf8(database.installed()).expect("the database is text");
        assert_eq!(installed.matches("R:tool").count(), 1, "{installed}");
    }

    #[test]
    fn a_replacing_claim_leaves_one_owner_whichever_way_the_names_sort() {
        // The replacer taking the path over has to take the file line with it.
        // Alpine's own case has the replacer sorting after the replaced, which
        // hides a stale earlier line: `apk` reads records in name order, so the
        // replacer's digest survives and matches the disk by luck. Reversing the
        // sort is what exposes it.
        for (earlier, later) in [
            ("aaa-replaced", "zzz-replacer"),
            ("zzz-replaced", "aaa-replacer"),
        ] {
            let (scratch, database) = lay_contested(&[
                (earlier, "", b"earlier"),
                (later, &format!("replaces = {earlier}\n"), b"later"),
            ]);
            assert_eq!(
                std::fs::read(scratch.join("root/usr/bin/tool")).expect("the file is there"),
                b"later",
                "{later} replaces {earlier}",
            );
            // One owner, and it is the one whose bytes are on disk.
            let installed = String::from_utf8(database.installed()).expect("the database is text");
            assert_eq!(
                installed.matches("R:tool").count(),
                1,
                "{earlier} then {later}:\n{installed}",
            );
            let owner = installed
                .split("\n\n")
                .find(|record| record.contains("R:tool"))
                .expect("some record holds it");
            assert!(owner.contains(&format!("P:{later}")), "{owner}");
        }
    }

    #[test]
    fn a_rendering_reports_the_configuration_and_not_the_transport() {
        let alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .build()
            .expect("the bootstrap configures");
        let rendering = format!("{alpine:?}");
        assert!(rendering.contains("x86_64"), "{rendering}");
        assert!(rendering.contains("v3.23"), "{rendering}");
        assert!(rendering.contains(fixtures::ALPINE_KEY_NAME), "{rendering}");
        assert!(!rendering.contains("BEGIN PUBLIC KEY"), "{rendering}");
    }
}
