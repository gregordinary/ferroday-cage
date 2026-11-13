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
//! RSA over SHA-1, then SHA-1 again, then SHA-256 — and the layer verifies
//! exactly that, because the published format offers nothing stronger and
//! verifying less than `apk` does would be worse rather than safer. Alpine's
//! current signing keys are 4096-bit; the older ones it still ships, mips64's
//! only key among them, are 2048-bit.
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
mod base64;
mod bootstrap;
mod index;
mod installed;
mod keyring;
mod layer;
mod pin;
mod pkginfo;
mod plan;
mod release;
mod repository;
mod resolve;
mod sign;
mod version;

use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{self, Seek as _};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use keyring::KeySet;
pub use pin::{UnheldPin, UnheldReason};
pub use plan::{Plan, PlannedPackage, ResolvedIndex};
pub use repository::{Repository, RepositoryBuilder};

use super::binfmt;
use super::cache;
use super::coordinate::{self, Nesting};
use super::digest::{Algorithm, Digest};
use super::extract::{Extraction, Placement};
use super::identity::Ownership;
// `super::layer` is the shared one; this module has a `layer` of its own, which
// reads a provisioned base rather than describing how a cage is rooted on it.
use super::layer::{Rooting, Staging};
use super::rooted::Rooted;
use super::tar::TarReader;
use super::{
    Available, BuildLayer, Delegate, Failover, Fetch, FetchError, FetchRequest, HttpFetch,
    LimitedWriter, PackageCache, ProvisionError, ProvisionRequest, Provisioner, Stream, mirror_url,
    walk_mirrors,
};
use crate::failure::path_io_error;
use crate::{ErrorChain, IdMapper, IdentityMap};
use bootstrap::{Declared, ScriptSubject};
use index::{Index, Record};
use installed::{Carried, Claim, Database, Shape};
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
    /// resolution: sorted and without a repeat, since it is a set.
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
    /// The delegate that map is established through, set by
    /// [`AlpineBuilder::id_mapper`]; `None` resolves a range map through the
    /// bundled chain.
    id_mapper: Option<Arc<dyn IdMapper>>,
    /// Where downloaded packages are kept across runs, where the caller named a
    /// place.
    cache_dir: Option<PathBuf>,
    /// A tree laid over the unpacked closure before the scripts run.
    overlay: Option<PathBuf>,
    /// The date the scripts are given and the accounts they create are
    /// recorded at, set by [`AlpineBuilder::source_date_epoch`].
    source_date_epoch: Option<i64>,
    /// The pristine base a layered build stages its increment over, set by
    /// [`AlpineBuilder::base_layer`]. `None` for a full bootstrap; required by
    /// [`Alpine::stage_layer`] and [`Alpine::resolve_layer`].
    base_layer: Option<PathBuf>,
    /// The transport every fetch goes through.
    fetcher: Box<dyn Fetch>,
}

impl fmt::Debug for Alpine {
    /// Renders the configuration, and the transport and the identity-map
    /// delegate by their presence rather than their contents: both are a
    /// caller's code, with nothing useful to show.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Alpine")
            .field("architecture", &self.architecture)
            .field("repositories", &self.repositories)
            .field("world", &self.world)
            .field("excludes", &self.excludes)
            .field("pins", &self.pins)
            .field("plan", &self.plan)
            .field("extract_only", &self.extract_only)
            .field("identity_map", &self.identity_map)
            .field(
                "id_mapper",
                &self.id_mapper.as_ref().map(|_| Delegate("dyn IdMapper")),
            )
            .field("cache_dir", &self.cache_dir)
            .field("overlay", &self.overlay)
            .field("source_date_epoch", &self.source_date_epoch)
            .field("base_layer", &self.base_layer)
            .field("fetcher", &Delegate("dyn Fetch"))
            .finish()
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
            id_mapper: None,
            cache_dir: None,
            overlay: None,
            source_date_epoch: None,
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
    /// Returns [`AlpineError::Config`] when nothing was included or when a
    /// [`base_layer`](AlpineBuilder::base_layer) is set — such a provisioner
    /// stages an increment, and [`resolve_layer`](Self::resolve_layer) is its
    /// read half — [`AlpineError::Fetch`], [`AlpineError::Container`],
    /// [`AlpineError::Signature`] or [`AlpineError::Index`] for a repository
    /// that cannot be read or verified, and [`AlpineError::Resolve`] for a
    /// closure the repositories cannot supply.
    pub fn resolve(&mut self) -> Result<Plan, AlpineError> {
        self.observe(&mut Silent).resolve()
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
        let (records, indexes) = self.read_indexes(observer)?;
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
        self.observe(&mut Silent).resolve_layer()
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
    fn read_indexes(
        &mut self,
        observer: &mut dyn AlpineObserver,
    ) -> Result<(Vec<Vec<Record>>, Vec<ResolvedIndex>), AlpineError> {
        let mut records = Vec::new();
        let mut indexes = Vec::new();
        for repository in &self.repositories {
            for (component, path) in repository.indexes(&self.architecture) {
                let from = indexes.len();
                let (read, resolved) = read_index(
                    &mut *self.fetcher,
                    repository,
                    component,
                    &path,
                    from,
                    observer,
                )?;
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
        self.observe(&mut Silent).available()
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
    /// A call that fails and created `upper` leaves nothing behind: the upper
    /// and its work directory are disposed of exactly as dropping the returned
    /// layer would dispose of them, since a failure hands the caller no handle
    /// to drop. An `upper` that already existed is the caller's, and a failure
    /// leaves it in place, holding whatever the call wrote into it. The package
    /// cache goes with the call either way, unless the builder named a
    /// [`cache_dir`](AlpineBuilder::cache_dir), which is the caller's and
    /// survives.
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
        self.observe(&mut Silent).stage_layer(upper)
    }

    /// The body of [`stage_layer`](Self::stage_layer), reporting to `observer`.
    ///
    /// One body for the two public entry points -- the unobserved one above and
    /// [`Observed::stage_layer`] -- rather than a body on each.
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

        // The guard is taken as the upper is created, not on the way out, so a
        // failure below disposes of a partly-installed increment instead of
        // orphaning it: there is no handle in an `Err` for the caller to drop.
        // It disposes only of an upper this call created; one that was already
        // there is the caller's.
        let staging = Staging::begin(upper, self.identity_map.clone(), self.id_mapper.clone())?;
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
        let scratch = crate::path::parent_of(upper);
        if !self.extract_only
            && let Some(blocker) = crate::host::overlay_blocker(scratch)
        {
            return Err(wrap(AlpineError::Config {
                reason: format!("an overlay-rooted build layer cannot be established: {blocker}"),
            }));
        }

        install(self, upper, Some(&base), observer)?;
        Ok(staging.finish())
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
    id_mapper: Option<Arc<dyn IdMapper>>,
    cache_dir: Option<PathBuf>,
    overlay: Option<PathBuf>,
    source_date_epoch: Option<i64>,
    base_layer: Option<PathBuf>,
    repositories: Vec<Repository>,
    fetcher: Option<Box<dyn Fetch>>,
}

impl fmt::Debug for AlpineBuilder {
    /// Renders every setting made so far, naming the keys rather than holding
    /// them, and the transport and the identity-map delegate by their
    /// presence, as [`Alpine`]'s own rendering does.
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
            .field(
                "id_mapper",
                &self.id_mapper.as_ref().map(|_| Delegate("dyn IdMapper")),
            )
            .field("cache_dir", &self.cache_dir)
            .field("overlay", &self.overlay)
            .field("source_date_epoch", &self.source_date_epoch)
            .field("base_layer", &self.base_layer)
            .field("repositories", &self.repositories)
            .field(
                "fetcher",
                &self.fetcher.as_ref().map(|_| Delegate("dyn Fetch")),
            )
            .finish()
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
    /// it when a fetch reports the resource missing or fails at the transport.
    ///
    /// It backs the packages as well as the index, so a package rebuilt to a
    /// higher `-r` — which removes its predecessor from a live mirror — is
    /// served by the backstop for as long as a plan naming the predecessor is
    /// still being installed.
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
    /// the root asked for, as against the closure it resolved to. It is a set:
    /// the order packages are named in changes neither the closure nor the
    /// file, which lists them sorted, as `apk` writes it.
    ///
    /// # Errors
    ///
    /// A name carrying a version operator is refused at [`build`](Self::build)
    /// with [`AlpineError::Config`]. A resolution takes the highest version each
    /// repository offers; holding one to a version is what [`pin`](Self::pin)
    /// is for, and reading `busybox>=1.37` as a package name would otherwise
    /// fail as a package nothing offers.
    ///
    /// So is a name carrying an apk repository tag, such as `busybox@edge`. A
    /// [`Repository`] carries no tag, and every name resolves against every
    /// configured repository.
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
    /// The merged index keeps one record for each name, the pinned one where
    /// the pin names it, and every route to a package goes through it: a
    /// dependency, a provided name, and an `install_if` condition alike. A name
    /// a [`base_layer`](Self::base_layer) carries keeps the base's version,
    /// since a layered build never upgrades its base.
    ///
    /// # The trust model does not change
    ///
    /// Nothing here leaves the repository signature chain: every control
    /// identity is still read from an index whose own signature was verified.
    /// The pin narrows which version is selected; it never becomes the authority
    /// for what the bytes are. Where two repositories offer the pinned version,
    /// the one recording the pinned control identity is selected, wherever it
    /// sits in the order. A pin whose control identity no repository records
    /// for that version is refused rather than preferred, which is how one
    /// version published twice over different bytes is caught.
    ///
    /// # Errors
    ///
    /// [`build`](Self::build) refuses a pin with [`AlpineError::Config`] when it
    /// names one package twice — a pin is keyed by name, so two entries state
    /// two versions to hold it at — when it resolves another architecture, or
    /// when an entry states a version this grammar cannot compare.
    ///
    /// A pin the repositories cannot supply fails the resolution with
    /// [`AlpineError::Pin`], naming every package at once — the repositories
    /// have published past the pinned version, dropped the package, or record a
    /// different control segment for it. Alpine keeps one version of each
    /// package per release, so a pin outlives a publication only where the
    /// caller keeps a mirror that does. So does a dependency the pinned version
    /// does not meet where nothing else answers it, naming the requirement.
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
    /// [`build`](Self::build) refuses a plan the configuration cannot install,
    /// with [`AlpineError::Config`]: one resolved for another architecture; one
    /// naming an index it does not itself carry, or more indexes than the
    /// configured repositories publish, or an index whose release and component
    /// are not what the repository in that slot publishes; and one stating a
    /// package no index for its architecture could publish: by a name or a
    /// version outside the format, with a malformed control identity, or for
    /// an architecture other than the plan's or `noarch`; and one naming a
    /// package twice, which a root cannot hold. It also refuses the
    /// combinations that would silently drop half of what was asked for —
    /// [`include`](Self::include), [`exclude`](Self::exclude) and
    /// [`pin`](Self::pin) all describe a resolution, and a plan is one already.
    pub fn plan(mut self, plan: Plan) -> Self {
        self.plan = Some(plan);
        self
    }

    /// Lays the packages' files out and runs nothing.
    ///
    /// No script runs and no trigger fires, so the tree is what the packages
    /// ship and nothing a script would have derived from it: no `busybox` applet
    /// links, no accounts a `.pre-install` would have added. Because nothing
    /// executes, this serves an architecture the host cannot run. With no
    /// accounts to name them by, the entries a package states another owner for
    /// stay root's, as under the single-identity map; see
    /// [`identity_map`](Self::identity_map).
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

    /// Builds the root under `map` rather than under the default
    /// single-identity map: the install scripts run under it, and the entries
    /// a package states another owner for are given that owner through it.
    ///
    /// Under the single-identity map only root exists, so every entry of the
    /// finished root is owned by root, and the installed database records
    /// that. Most of Alpine is root-owned throughout — every entry of every
    /// package in the `alpine-base` closure is — so for most roots that is no
    /// change at all. What it flattens is two things. `alpine-baselayout`'s
    /// `.post-install` assigns `/etc/shadow` to the `shadow` group, which fails
    /// there as it fails under `apk` in the same situation, and Alpine's scripts
    /// tolerate it. And a package's own non-root entries, such as
    /// `dbus-daemon-launch-helper`, which is `root:messagebus` and setuid, land
    /// as root.
    ///
    /// Under a range map such as [`IdentityMap::Subordinate`] the system ids
    /// exist. The scripts' calls succeed, and each entry a package states
    /// another owner for is given it as `apk` gives it: by the names its
    /// archive records, looked up in the root's own `/etc/passwd` and
    /// `/etc/group` once the package's `.pre-install` has created the accounts,
    /// and by the archive's ids where the root has no such names. The installed
    /// database records the ids given. An id the map does not hold fails the
    /// bootstrap with [`AlpineError::Ownership`] rather than flattening the
    /// entry.
    ///
    /// [`extract_only`](Self::extract_only) runs no `.pre-install`, so it gives
    /// no owner under either map.
    pub fn identity_map(mut self, map: IdentityMap) -> Self {
        self.identity_map = map;
        self
    }

    /// Supplies the delegate that establishes a range
    /// [`identity_map`](Self::identity_map), replacing the bundled fallback
    /// chain, as [`CageBuilder::id_mapper`] does for one sandbox.
    ///
    /// Every cage an install script runs in is launched through it, and so is
    /// the removal of a [`stage_layer`](Alpine::stage_layer) increment. The
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

    /// Keeps downloaded packages in `dir` across runs.
    ///
    /// Without one, packages are downloaded into a directory beside the rootfs
    /// being built and removed with it, so a repeated bootstrap re-downloads
    /// everything. A cache directory is the caller's: this layer only ever adds
    /// to it. An entry is named for the package's control identity as well as
    /// its file name, so packages that share a file name and differ in
    /// architecture or content, such as one architecture's build and another's
    /// or a postmarketOS republish of an Alpine package, are kept side by side
    /// rather than replacing each other. The one entry a download replaces is
    /// one at that name that does not read back as the package.
    ///
    /// An entry is used only when it reads back as the package the plan names —
    /// its control identity matches, and its file tree digests to what its own
    /// metadata says — so a truncated or substituted entry is downloaded again
    /// rather than trusted. Its own signature is read and not verified, as for a
    /// fresh download: the control identity already fixes the bytes it covers.
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

    /// Dates what the install scripts write by `epoch`, in Unix seconds, rather
    /// than by the clock.
    ///
    /// Every script is given `SOURCE_DATE_EPOCH`, for the tools that read it.
    /// The ones a bootstrap reaches create accounts, and busybox's `adduser`,
    /// which Alpine's scripts call, is not among them: it records the day it
    /// ran as each new account's last password change in `/etc/shadow`, and in
    /// the previous version of the file it leaves beside it. So once the
    /// scripts have run, every such day the run wrote is rewritten as the
    /// epoch's. The days a package shipped are kept. Without an epoch, one plan
    /// installed on two different days gives two different roots.
    ///
    /// An epoch in the first day of 1970 records no day at all, which disables
    /// password aging for those accounts. `/etc/shadow` reads a last change on
    /// day zero as a demand for a new password at the next login, so
    /// shadow-utils' `useradd` writes the same empty field for that epoch.
    ///
    /// The value is a plain timestamp, so a pipeline that pins a build date
    /// passes the same number here and to
    /// [`Export::clamp_mtime`](crate::provision::Export::clamp_mtime), and a
    /// byte-reproducible archive takes both. A layered build dates the accounts
    /// its increment creates as a full bootstrap does, and
    /// [`extract_only`](Self::extract_only) runs no script and ignores it.
    ///
    /// # Refused values
    ///
    /// A negative epoch is refused at [`build`](Self::build) with
    /// [`AlpineError::Config`]: `/etc/shadow` counts days from 1970 and has no
    /// way to record one before it.
    pub fn source_date_epoch(mut self, epoch: i64) -> Self {
        self.source_date_epoch = Some(epoch);
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
    ///
    /// The transport is taken by value and kept for the provisioner's whole
    /// life; [`Fetch`] says why.
    pub fn fetcher(mut self, fetcher: impl Fetch + 'static) -> Self {
        self.fetcher = Some(Box::new(fetcher));
        self
    }

    /// Validates the configuration and freezes it into an [`Alpine`].
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Config`] when the architecture is not one a
    /// repository can be addressed by, when the bundle holds no keys for it and
    /// none were given, when the primary repository's release or a component is
    /// not addressable, when a [`plan`](Self::plan) does not describe
    /// something this configuration could install, or when the
    /// [`source_date_epoch`](Self::source_date_epoch) is negative.
    pub fn build(self) -> Result<Alpine, AlpineError> {
        if let Some(epoch) = self.source_date_epoch
            && epoch < 0
        {
            return Err(AlpineError::Config {
                reason: format!(
                    "the source date epoch {epoch} is negative, and /etc/shadow records days \
                     since 1970"
                ),
            });
        }
        // A plan states which architecture it is for, so a builder that names
        // none adopts it: refusing a plan the caller never contradicted, over a
        // default the caller never chose, would be a confusing rejection. A pin
        // states one for the same reason and is adopted the same way. This is
        // the Debian builder's rule, and it has to be the same rule, because it
        // is what decides whether the check below ever fires for a caller who
        // simply did not say.
        let stated = self.plan.as_ref().or(self.pin.as_ref());
        let architecture = match (&self.architecture, stated) {
            (Some(architecture), _) => architecture.clone(),
            (None, Some(plan)) => plan.architecture.clone(),
            (None, None) => host_architecture(),
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
            // Before the version operators, so `foo@edge>=1` is reported for
            // the tag, which is the part with no remedy here.
            if name.contains('@') {
                return Err(AlpineError::Config {
                    reason: format!(
                        "{name:?} names a repository tag, and the repositories configured here \
                         carry none; a name resolves against every configured repository, the \
                         highest version winning",
                    ),
                });
            }
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

        if let Some(plan) = &self.plan {
            validate_plan(
                plan,
                &architecture,
                &index_slots(&repositories, &architecture),
                self.pin.is_some(),
                &self.includes,
                &self.excludes,
            )?;
        }
        if let Some(pin) = &self.pin {
            validate_pin(pin, &architecture)?;
        }
        let mut world = self.includes;
        world.sort();
        world.dedup();

        Ok(Alpine {
            architecture,
            repositories,
            world,
            excludes: self.excludes,
            pins: match &self.pin {
                Some(plan) => Pins::of(plan)?,
                None => Pins::none(),
            },
            plan: self.plan,
            extract_only: self.extract_only,
            identity_map: self.identity_map,
            id_mapper: self.id_mapper,
            cache_dir: self.cache_dir,
            overlay: self.overlay,
            source_date_epoch: self.source_date_epoch,
            base_layer: self.base_layer,
            fetcher: self
                .fetcher
                .unwrap_or_else(|| Box::new(HttpFetch::new()) as Box<dyn Fetch>),
        })
    }
}

/// One slot of the index walk: which repository publishes it, and what it
/// publishes there.
struct IndexSlot<'a> {
    /// Which of the configured repositories serves it, as an index into them.
    origin: usize,
    /// The release, as that repository requested it.
    release: &'a str,
    /// The component published there, or `None` for a repository that publishes
    /// none — the `<release>/<architecture>` layout.
    component: Option<&'a str>,
}

/// The index slots a configuration publishes, in the order they are read.
///
/// The slots are the walk [`Alpine::read_indexes`] makes — every repository, and
/// within it every component it publishes — so slot *i* of a plan is the one
/// described at *i* here. The correspondence is positional, which is what
/// [`validate_plan`] holds a caller-supplied plan to and what lets a package
/// reach the mirror list it is fetched over.
fn index_slots<'a>(repositories: &'a [Repository], architecture: &str) -> Vec<IndexSlot<'a>> {
    let mut slots = Vec::new();
    for (origin, repository) in repositories.iter().enumerate() {
        for (component, _) in repository.indexes(architecture) {
            slots.push(IndexSlot {
                origin,
                release: repository.release(),
                component,
            });
        }
    }
    slots
}

/// What must hold of a [`Plan`] used as a pin.
///
/// A pin is read as constraints rather than as a manifest, so it needs less of
/// the plan than [`validate_plan`] does: no index is consulted and nothing is
/// fetched by name. What it does need is that every entry states a version this
/// grammar can compare, because a version it cannot parse compares equal to
/// nothing and would be reported as a repository that had published past the pin
/// rather than as the malformed entry it is.
///
/// A refusal quotes the architecture the pin states, as [`validate_plan`] quotes
/// a plan's.
fn validate_pin(pin: &Plan, architecture: &str) -> Result<(), AlpineError> {
    let contradiction = |reason: String| Err(AlpineError::Config { reason });
    if pin.architecture != architecture {
        return contradiction(format!(
            "the pin resolves architecture {:?} but the bootstrap is configured for \
             {architecture}",
            pin.architecture,
        ));
    }
    for package in &pin.packages {
        if let Some(reason) = package.unaddressable() {
            return contradiction(reason);
        }
    }
    Ok(())
}

/// What must hold of a caller-supplied [`Plan`] before a bootstrap is built from
/// it.
///
/// A plan reaches a bootstrap without having been resolved by it, so nothing the
/// resolution guarantees can be assumed: not that the packages are the
/// configuration's architecture, not that their names are ones a repository
/// could publish, and not that the indexes they name are ones the configuration
/// walks. Every one of those is cheaper to refuse here, where the configuration
/// is frozen, than partway through a download — which is where each of them
/// would otherwise surface.
///
/// The counterpart of the Debian layer's `validate_plan`, and it answers the
/// same questions in the same order.
///
/// A refusal quotes the architecture, the release and the component the plan
/// states with `{:?}`: a document is a file the caller may have taken from
/// elsewhere, and nothing holds its header or its index stanzas to an alphabet.
/// The configured architecture, releases and components have passed
/// [`check_coordinate`], and are named bare. A package is named bare once
/// [`PlannedPackage::unaddressable`] has admitted its name, which is the first
/// thing asked of it.
fn validate_plan(
    plan: &Plan,
    architecture: &str,
    slots: &[IndexSlot<'_>],
    pin_set: bool,
    includes: &[String],
    excludes: &[String],
) -> Result<(), AlpineError> {
    let contradiction = |reason: String| Err(AlpineError::Config { reason });
    if !includes.is_empty() {
        return contradiction(
            "a plan already names every package to install, so include() has nothing to add; \
             drop one of the two"
                .to_string(),
        );
    }
    if !excludes.is_empty() {
        return contradiction(
            "a plan already names every package to install, so exclude() has nothing to remove; \
             drop one of the two"
                .to_string(),
        );
    }
    if pin_set {
        return contradiction(
            "plan() installs a resolved plan instead of resolving, so there is no resolution for \
             pin() to hold to versions; drop one of the two"
                .to_string(),
        );
    }
    if plan.architecture != architecture {
        return contradiction(format!(
            "the plan resolves architecture {:?} but the bootstrap is configured for \
             {architecture}",
            plan.architecture,
        ));
    }
    // Each package names the index it came from, and a bootstrap fetches it
    // through the repository that serves that index, so a plan resolved against
    // more indexes than the configuration publishes has packages with no mirror
    // to walk.
    if plan.indexes.len() > slots.len() {
        return contradiction(format!(
            "the plan resolved against {} indexes but the configured repositories publish {}, so \
             some of its packages name no mirror",
            plan.indexes.len(),
            slots.len(),
        ));
    }
    // The correspondence is positional, and a package's URL is composed from the
    // configured mirror and the plan's own release and component. Two
    // configurations that publish the same number of indexes in a different
    // order therefore compose URLs no mirror serves, and the walk that follows
    // would blame every mirror for a directory none of them was ever asked to
    // publish. The mirrors themselves are deliberately not compared: a plan
    // carried to a different configuration fetches from that configuration's
    // mirrors, which is what makes it portable.
    for (at, (index, slot)) in plan.indexes.iter().zip(slots).enumerate() {
        let describe = |release: &str, component: Option<&str>| match component {
            Some(component) => format!("{release}/{component}"),
            None => release.to_string(),
        };
        if index.release != slot.release || index.component.as_deref() != slot.component {
            return contradiction(format!(
                "the plan's index {at} is {:?} and the configured repository publishes {} there, \
                 so its packages would be fetched from a directory that repository does not serve",
                describe(&index.release, index.component.as_deref()),
                describe(slot.release, slot.component),
            ));
        }
    }
    for package in &plan.packages {
        // A document is held to this as it is read; a `Plan` is public and
        // `Clone`, so one taken from `resolve()` and edited reaches here having
        // passed nothing. First, because it is what admits the name the
        // refusal below names.
        if let Some(reason) = package
            .unaddressable()
            .or_else(|| package.foreign_to(&plan.architecture))
        {
            return contradiction(reason);
        }
        if package.index >= plan.indexes.len() {
            return contradiction(format!(
                "the plan's package {} names index {} but the plan records {}, so it names no \
                 mirror",
                package.name,
                package.index,
                plan.indexes.len(),
            ));
        }
    }
    // Installed twice, a package would be recorded twice and its scripts run
    // twice, into a root that can only hold it once.
    if let Some((first, again)) = plan.named_twice() {
        return contradiction(format!(
            "the plan names the package {} twice, at {} and at {}, and a root holds one package \
             of each name",
            again.name, first.version, again.version,
        ));
    }
    Ok(())
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
    observer: &mut dyn AlpineObserver,
) -> Result<(Vec<Record>, ResolvedIndex), AlpineError> {
    walk_mirrors(
        &repository.mirrors,
        |mirror| {
            let url = mirror_url(mirror, path);
            // Reported for the same reason a package fetch is: this walk spends
            // one mirror timeout per unreachable mirror, and it is the slowest
            // part of a resolve. An observer that saw only `Resolving` would
            // watch a bootstrap that looks stopped.
            observer.progress(AlpineEvent::Fetching { url: &url });
            let mut bytes = Vec::new();
            let request = FetchRequest::new(&url);
            fetcher.fetch(
                &request,
                &mut LimitedWriter::new(&mut bytes, MAX_INDEX_FETCH),
            )?;
            let (records, signed_by, description) = parse_index(&url, &bytes, repository, from)?;
            Ok((
                records,
                ResolvedIndex {
                    mirror: mirror.clone(),
                    release: repository.release().to_string(),
                    component: component.map(str::to_string),
                    // Over the container as it arrived, signature segment
                    // included, so the value names the exact bytes whose
                    // signature was checked.
                    sha256: Digest::of(Algorithm::Sha256, &bytes),
                    signed_by,
                    description,
                    // A record built from a live resolution has no document
                    // behind it, so there is nothing to carry. Qualified: this
                    // module's own `Carried` is the installed database's, a
                    // different question with the same name.
                    carried: super::document::Carried::new(),
                },
            ))
        },
        || AlpineError::Fetch(FetchError::not_found(path.to_string())),
    )
}

/// Verifies an index container, holds it to the release it was fetched as, and
/// reads the records it carries.
///
/// `url` names where it came from, for the errors.
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
        .map_err(|err| AlpineError::unreadable(url, "its end is unreadable", err))?
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
    // Whatever the repository chose to write there: Alpine writes `git
    // describe` of the tree the index was built from, postmarketOS a timestamp,
    // and the format defines neither. Alpine's is what binds the index to the
    // release it was fetched as, since one key signs many releases; the record
    // keeps whatever was written.
    let description = metadata
        .member("DESCRIPTION")
        .map(|member| String::from_utf8_lossy(&member.data).trim().to_string())
        .filter(|description| !description.is_empty());
    release::check(
        url,
        repository.release(),
        &metadata.signed_by,
        description.as_deref(),
    )?;
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
    /// Consulted where stopping is clean — a package boundary, a mirror a
    /// download walks, a batch of downloads, a script boundary — and on each
    /// write of a package's body as it downloads. Returning `true` aborts with
    /// [`ProvisionError::Cancelled`], and a run driven through
    /// [`provision::ensure`](super::ensure) then removes the staging tree, so a
    /// cancelled bootstrap leaves no destination behind.
    ///
    /// [`ProvisionError::Cancelled`]: super::ProvisionError::Cancelled
    fn cancelled(&mut self) -> bool {
        false
    }
}

/// A download's view of the observer: the layer's own fetch event, and its
/// answer to whether the run should stop.
impl cache::Watch for dyn AlpineObserver + '_ {
    fn fetching(&mut self, url: &str) {
        self.progress(AlpineEvent::Fetching { url });
    }

    fn cancelled(&mut self) -> bool {
        AlpineObserver::cancelled(self)
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
        /// Its position among the packages being downloaded, from 1.
        index: usize,
        /// How many packages are being downloaded, which is the plan's total
        /// less whatever the cache already held.
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
        // A provisioner with a base layer stages an increment, which
        // `provision::ensure` refuses outright for the same value. Reporting the
        // whole-root closure here would answer a question this provisioner never
        // asks -- hundreds of packages the base already carries — and read as
        // the plan it would install. `resolve_layer` is its read half.
        if self.alpine.base_layer.is_some() {
            return Err(AlpineError::Config {
                reason: "a provisioner with a base layer resolves an increment, and is read \
                         through Alpine::resolve_layer rather than through Alpine::resolve"
                    .to_string(),
            });
        }
        self.alpine.resolve_over(None, self.sink)
    }

    /// [`Alpine::available`], reporting to the attached sink.
    ///
    /// The sink sees one [`Fetching`](AlpineEvent::Fetching) per index, which is
    /// the whole of what this call does.
    pub fn available(&mut self) -> Result<Available, AlpineError> {
        // Unpinned whatever the builder holds: this reports what the
        // repositories offer, and a pin describes a selection from it rather
        // than a bound on what may be asked about.
        let (records, _indexes) = self.alpine.read_indexes(self.sink)?;
        Ok(Index::merge(records, &self.alpine.architecture, &Pins::none()).into_available())
    }

    /// [`Alpine::resolve_layer`], reporting to the attached sink.
    pub fn resolve_layer(&mut self) -> Result<Plan, AlpineError> {
        let base = self.alpine.read_base_layer("resolve_layer")?;
        self.alpine.resolve_over(Some(&base), self.sink)
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
/// and stops when either that sink or the provisioning run asks it to.
///
/// The caller chose the richer, Alpine-specific channel for events, and a sink
/// that answers [`cancelled`](AlpineObserver::cancelled) stops the bootstrap
/// it watches, as it does a layered build it is handed directly. A
/// [`Provision::observe`](crate::provision::Provision::observe) observer can
/// still stop a bootstrap it is not reporting on.
struct ObservedRun<'a, 'r, 'o> {
    sink: &'o mut dyn AlpineObserver,
    request: &'a ProvisionRequest<'r>,
}

impl AlpineObserver for ObservedRun<'_, '_, '_> {
    fn progress(&mut self, event: AlpineEvent<'_>) {
        self.sink.progress(event);
    }

    fn cancelled(&mut self) -> bool {
        self.sink.cancelled() || self.request.cancelled()
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
    /// The verified file itself, still open, to be seeked to the file tree the
    /// verification already digested.
    ///
    /// The descriptor rather than the path, and that is the whole point: a cache
    /// directory is the caller's and its atomic publish is written for concurrent
    /// writers, so re-opening the path would extract whatever is there by then
    /// rather than what was verified. Nothing can be swapped underneath an open
    /// descriptor — a replacement publishes a new inode and this one keeps
    /// reading the old.
    file: std::fs::File,
    /// Where that file is, for the errors, which name a path rather than a
    /// descriptor.
    path: PathBuf,
    /// The file's length, which the record states as `S:`.
    size: u64,
}

/// What must hold before anything is downloaded.
///
/// An unavailable identity map, an unrunnable architecture, or a host that
/// cannot install the network filter the scripts' sandboxes carry is a
/// configuration problem, and each is cheaper to report now than after a
/// closure has been fetched. None applies to an extract-only run, which
/// executes nothing, so such a run reaches none of this.
///
/// A caller-supplied plan is not checked here: it is checked by
/// [`validate_plan`] at `build()`, where the configuration is frozen and where
/// the refusal reaches a caller who never provisions at all.
fn preflight(alpine: &Alpine) -> Result<(), AlpineError> {
    if alpine.extract_only {
        return Ok(());
    }
    preflight_foreign(&host_architecture(), &alpine.architecture)?;
    crate::provision::layer::network_filter_preflight()
        .map_err(|reason| AlpineError::Config { reason })?;
    // The identity posture is never quietly downgraded to the single-identity
    // form.
    crate::idmap::establishable(&alpine.identity_map, alpine.id_mapper.as_ref()).map_err(
        |refusal| AlpineError::Config {
            reason: ErrorChain::new(&refusal).to_string(),
        },
    )
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

    // The state the finished root carries, composed before anything is
    // downloaded so that an increment with nothing in it still writes it. The
    // base's own is carried forward rather than replaced: these files shadow
    // the base's copies through the overlay, so each has to describe the merged
    // root.
    //
    // A plan names every package rather than the seeds a resolution closed over,
    // and `plan()` forbids `include()` — so the configured world is empty and
    // the plan's own names are what the root wants. Written as world, they pin
    // the closure for a later `apk`: an empty file says nothing is wanted, which
    // is what `apk fix` acts on.
    let wanted: Vec<String> = match &alpine.plan {
        Some(plan) => plan.packages.iter().map(|p| p.name.clone()).collect(),
        None => alpine.world.clone(),
    };
    // Sorted as `apk` writes it, so the merged root's file is one list rather
    // than the base's followed by the increment's.
    let mut world = joined(base.map_or(&[], layer::Base::world), wanted);
    world.sort();
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
    // What a directory the host side carries up from the base is re-owned
    // through: the map the install scripts run under.
    let ownership = Ownership::new(&alpine.identity_map, alpine.id_mapper.as_ref());
    let state = bootstrap::State {
        world: &world,
        architecture: &alpine.architecture,
        sources: &sources,
        repositories: &alpine.repositories,
        beneath: beneath.as_ref(),
        ownership: &ownership,
    };

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
        // An increment with nothing in it needs no download and no script — but
        // it still writes its state, so what a caller reads back from the
        // merged view does not depend on whether the delta happened to be
        // empty. Registration is a file format rather than a program's output,
        // so writing it runs nothing.
        if plan.packages.is_empty() {
            let database = installed::Database::carrying(base.carried());
            return bootstrap::register(into, &database, &state).map_err(wrap);
        }
    }

    // The cache disposes of itself when this frame ends, on the failure paths
    // below as on the success path.
    let cache = PackageCache::beside(into, alpine.cache_dir.as_deref(), APK_CACHE);
    let mut acquired = acquire(
        &mut *alpine.fetcher,
        &plan,
        &alpine.repositories,
        &alpine.architecture,
        cache.path(),
        observer,
    )?;

    let order = install_order(&acquired);
    let carried = base.map(layer::Base::carried).unwrap_or_default();
    let (mut database, subjects) = lay_down(
        into,
        base.map(|base| (base.path(), ownership.clone())),
        carried,
        &mut acquired,
        &order,
        observer,
    )?;

    // After every package's files are down, so this overwrites what they
    // shipped, and before any script runs, so a script reads what was injected.
    if let Some(overlay) = &alpine.overlay {
        super::extract::overlay_tree(into, overlay, base.map(|base| (base.path(), &ownership)))?;
    }

    if alpine.extract_only {
        // Registration is a file format here rather than a program's output, so
        // an extract-only root still knows what it holds.
        return bootstrap::register(into, &database, &state).map_err(wrap);
    }
    // A base's own trigger-watching packages fire for the directories this
    // install created, which is what `apk` does: a trigger belongs to the root
    // rather than to the transaction. Their scripts are read out of the base's
    // archive once, and each subject borrows its own.
    let archived = match base {
        Some(base) => base.trigger_scripts().map_err(wrap)?,
        None => Vec::new(),
    };
    let watching = match base {
        Some(base) => base.trigger_subjects(&archived).map_err(wrap)?,
        None => Vec::new(),
    };
    bootstrap::configure(
        bootstrap::Site {
            staging: into,
            rooting: Rooting::over(base.map(layer::Base::path)),
            identity_map: &alpine.identity_map,
            id_mapper: alpine.id_mapper.as_ref(),
            source_date_epoch: alpine.source_date_epoch,
        },
        &mut database,
        &subjects,
        &watching,
        &state,
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
///
/// A download is held to the same read ([`read_acquired`]) before it is
/// published, so the cache never holds a package that was not checked, and the
/// [`Acquired`] that check produced is the one the root is laid down from. Each
/// package is read once, whichever produced it.
///
/// Each package is fetched over the mirrors of the repository that serves the
/// index it came from, walked in configured order, so a package that has rotated
/// off a live mirror is served by that repository's backstop. The plan's own
/// record of which mirror served the index is provenance rather than a fetch
/// instruction; it is the configuration that says where to fetch from.
fn acquire(
    fetcher: &mut dyn Fetch,
    plan: &Plan,
    repositories: &[Repository],
    architecture: &str,
    cache: &Path,
    observer: &mut dyn AlpineObserver,
) -> Result<Vec<Acquired>, ProvisionError> {
    cache::create(cache)?;

    // Positional, and `validate_plan` has already held the plan to it, so a slot
    // a package names is one this resolves.
    let slots = index_slots(repositories, architecture);

    // The cache pass and the announcement, before anything is fetched: what a
    // caller is told it is downloading is what the batch and the walk between
    // them go on to fetch, in the order the plan names them.
    let mut acquired: Vec<Option<Acquired>> = Vec::with_capacity(plan.packages.len());
    let mut missing: Vec<Missing<'_>> = Vec::new();
    for (at, planned) in plan.packages.iter().enumerate() {
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
        let mirrors = slots
            .get(planned.index)
            .map(|slot| repositories[slot.origin].mirrors.as_slice())
            .ok_or_else(|| {
                wrap(AlpineError::Config {
                    reason: format!(
                        "the plan attributes {} to index {}, and the configured repositories \
                         publish {}",
                        planned.name,
                        planned.index,
                        slots.len(),
                    ),
                })
            })?;
        let name = planned.cache_name().ok_or_else(|| {
            wrap(AlpineError::Config {
                reason: format!(
                    "the plan states {:?} with the control identity {:?}, which names no cache \
                     entry",
                    planned.name, planned.control_identity,
                ),
            })
        })?;
        let path = cache.join(name);

        // A cached entry that does not read back as this package is not an
        // error; it is a download waiting to happen.
        let held = cache::open_entry(&path)
            .map_err(AlpineError::at("reading a package", &path))
            .and_then(|file| read_acquired(file, &path, planned, architecture));
        if held.is_err() {
            missing.push(Missing {
                at,
                planned,
                index,
                mirrors,
                path,
            });
        }
        acquired.push(held.ok());
    }

    // Announced over what is actually being fetched, once the cache has been
    // asked about every package: a position among the plan's packages counts
    // the ones already cached, so an observer reporting `index` of `total` would
    // show a fetch of three packages as reaching nine of ten. The announcement
    // precedes the batch because the batch fetches several at once, which is
    // the shape a fetch event has throughout this crate.
    for (position, entry) in missing.iter().enumerate() {
        observer.progress(AlpineEvent::Downloading {
            package: &entry.planned.name,
            index: position + 1,
            total: missing.len(),
        });
    }

    // Every job asks the package's own first mirror, which is the one the walk
    // would ask first too.
    let (batched, jobs): (Vec<&Missing<'_>>, Vec<cache::Job<'_>>) = missing
        .iter()
        .filter_map(|entry| {
            let mirror = entry.mirrors.first()?;
            let job = cache::Job {
                url: entry.url(mirror, architecture),
                entry: entry.cache_entry(),
            };
            Some((entry, job))
        })
        .unzip();
    let delivered = cache::prefetch(fetcher, &jobs, observer, |job, file| {
        let entry = batched[job];
        read_acquired(file, &entry.path, entry.planned, architecture)
    })
    .map_err(|failure| failure.into_provision(wrap))?;
    for (entry, held) in batched.iter().zip(delivered) {
        if held.is_some() {
            acquired[entry.at] = held;
        }
    }

    for entry in &missing {
        if acquired[entry.at].is_some() {
            continue;
        }
        // The walk asks the observer at each mirror and on every write of the
        // body, so a cancelled run stops within one package's worth of bytes,
        // and what has been published by then is complete and verified.
        let held = cache::download(
            fetcher,
            entry.mirrors,
            |mirror| entry.url(mirror, architecture),
            entry.cache_entry(),
            observer,
            |file, _, _| read_acquired(file, &entry.path, entry.planned, architecture),
            || FetchError::not_found(entry.planned.file_name()),
        )
        .map_err(|failure| failure.into_provision(wrap))?;
        acquired[entry.at] = Some(held);
    }

    Ok(acquired
        .into_iter()
        .map(|held| held.expect("the cache, the batch or the walk acquired every package"))
        .collect())
}

/// A package the cache does not hold, and where to fetch it from.
struct Missing<'a> {
    /// Its position in the plan.
    at: usize,
    planned: &'a PlannedPackage,
    index: &'a ResolvedIndex,
    mirrors: &'a [String],
    /// Its entry in the cache.
    path: PathBuf,
}

impl Missing<'_> {
    /// The package's URL on `mirror`.
    fn url(&self, mirror: &str, architecture: &str) -> String {
        mirror_url(
            &self.index.directory_under(mirror),
            &format!("{architecture}/{}", self.planned.file_name()),
        )
    }

    /// The cache entry the download fills, held to the index's `S:`.
    ///
    /// A length a verified source declared, so it travels with the request as
    /// well as capping the writer; an index that states none leaves the download
    /// bounded by the fetcher's own ceiling, which is weaker rather than wrong.
    fn cache_entry(&self) -> cache::Entry<'_> {
        cache::Entry {
            path: &self.path,
            size: self.planned.size,
        }
    }
}

/// Reads a cached `.apk` and holds it to the plan entry it answers.
///
/// This is the index-to-package binding, and it is the whole of what
/// authenticates a package: the control identity is recomputed over the bytes
/// that arrived and compared to the one the plan records — which came out of a
/// verified index, or out of a plan a caller kept — and the package's own name,
/// version and architecture are compared to the plan's.
///
/// `file` is the package, read from its start, and `path` its entry in the
/// cache, for the errors. The file the checks were made against is carried out
/// in the [`Acquired`], rather than the path being opened again where the tree
/// is laid down: the two opens would be two files, and only the first of them
/// was verified.
///
/// The binding is what a signature alone cannot do. A signature says that *some*
/// package was signed; without the binding a mirror answers a request for
/// `musl-1.2.5-r23` with a validly signed `musl-1.2.5-r0` and nothing notices.
/// The package's own signature, meanwhile, adds nothing the identity has not
/// already fixed, and [`apk::Anchor`] records why it is read rather than
/// verified.
fn read_acquired(
    mut file: File,
    path: &Path,
    planned: &PlannedPackage,
    architecture: &str,
) -> Result<Acquired, AlpineError> {
    let subject = planned.file_name();
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
        file,
        path: path.to_path_buf(),
        size,
    })
}

/// The order the closure is laid down and configured in: a package after
/// everything it needs, and a package its `install_if` brought in after the
/// packages that condition names.
///
/// The second is `apk`'s order too: it adds an `install_if` package to a
/// transaction only once everything the condition names is in it. It matters
/// where the package's entries are owned by an account the other's
/// pre-install creates. `dbus-daemon-launch-helper` needs nothing of `dbus`,
/// and is owned by the `messagebus` group `dbus`'s pre-install adds.
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
            provides
                .entry(version::name_of(entry).to_string())
                .or_default()
                .push(at);
        }
    }
    let depends: Vec<Vec<String>> = acquired
        .iter()
        .map(|held| {
            let info = &held.package.info;
            info.depends
                .iter()
                .chain(&info.install_if)
                // A `!` entry states what must *not* be installed. The
                // resolution already settled that; an install order has no edge
                // to draw from it.
                .filter(|entry| !entry.starts_with('!'))
                .map(|entry| version::name_of(entry).to_string())
                .collect()
        })
        .collect();
    bootstrap::dependency_order(&depends, &provides)
}

/// Lays every package's file tree into the staging tree, building the installed
/// database as it goes.
///
/// One pass per package, in `order`, and the second read of each acquired file:
/// the first established that the bytes are the package, and this one decodes
/// the file tree it already digested. It is the same open file both times, which
/// is what makes "already digested" true of the bytes this reads.
///
/// `over` is the base a layered build's staging tree is an overlay upper over,
/// which the extraction places every entry through ([`Extraction::over`]), so a
/// link the base holds is never hidden by a directory of the increment's. It
/// comes with the identity map the staging tree is owned through, which a
/// directory carried up from the base is given the base's ownership through.
/// The database records each path as the package spells it, as `apk` does.
///
/// Every entry is laid down as the calling user, whom the root's identity map
/// presents as root, and the database records root as each one's owner. An
/// entry whose package states another owner is returned among its subject's
/// [`declared`](ScriptSubject::declared), with the device and inode it was laid
/// down as, for the configure wave to give it that owner once the package's
/// pre-install has run.
fn lay_down(
    staging: &Path,
    over: Option<(&Path, Ownership)>,
    carried: Carried,
    acquired: &mut [Acquired],
    order: &[usize],
    observer: &mut dyn AlpineObserver,
) -> Result<(Database, Vec<ScriptSubject<'static>>), ProvisionError> {
    let (over, ownership) = over.unzip();
    let mut extraction = Extraction::new(staging)?
        .root_mode(ROOTFS_ROOT_MODE)
        .over(over)?
        .owned_through(ownership.unwrap_or_default());
    let mut database = Database::carrying(carried);
    let mut subjects = Vec::with_capacity(order.len());
    // The entries that state an owner other than root, by path: the last entry
    // written at a path is the one on disk, so it is the one whose owner holds,
    // and an entry stating root clears an earlier one's.
    let mut stated: HashMap<Vec<u8>, Declared> = HashMap::new();
    let tree = Rooted::open(staging).map_err(|err| ProvisionError::io("opening", staging, err))?;

    for at in order {
        let held = &mut acquired[*at];
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

        // Rewound rather than reopened: the verification left this descriptor at
        // the end of the file it authenticated.
        held.file
            .seek(std::io::SeekFrom::Start(held.package.data_at))
            .map_err(|err| ProvisionError::io("reading the package", &held.path, err))?;
        let mut archive = TarReader::new(apk::data_reader(&mut held.file), &held.path);
        lay_package(
            &mut extraction,
            &tree,
            &mut database,
            at,
            &mut archive,
            &mut |entry, path| {
                match stated_owner(at, entry, &path) {
                    Some(declared) => stated.insert(path, declared),
                    None => stated.remove(&path),
                };
            },
        )?;

        subjects.push(ScriptSubject {
            name: held.package.info.name.clone(),
            version: held.package.info.version.clone(),
            scripts: held
                .package
                .scripts
                .iter()
                .map(|(kind, body)| (*kind, Cow::Owned(body.clone())))
                .collect(),
            triggers: held
                .package
                .info
                .triggers
                .iter()
                .cloned()
                .map(Cow::Owned)
                .collect(),
            declared: Vec::new(),
        });
    }

    extraction.finalize(staging)?;

    // Each entry's device and inode as it was laid down, read through the same
    // in-root resolution the extraction placed it by. They are what the
    // configure wave tells the entry apart from a replacement by.
    let mut stated: Vec<Declared> = stated.into_values().collect();
    stated.sort_by(|a, b| a.path.cmp(&b.path));
    for mut declared in stated {
        let relative = Path::new(OsStr::from_bytes(&declared.path));
        let Some(stat) = tree
            .stat(relative)
            .map_err(|err| ProvisionError::io("inspecting", tree.path(relative), err))?
        else {
            continue;
        };
        declared.dev = stat.st_dev;
        declared.ino = stat.st_ino;
        // A subject was pushed for every record added, in the same pass, so a
        // record's number is its subject's place.
        subjects[declared.record].declared.push(declared);
    }
    Ok((database, subjects))
}

/// The owner `entry` states, where it is anyone but root, as a [`Declared`]
/// for the record numbered `at`, its device and inode still to be read.
///
/// An owner is root where its name is `root` or absent and its id is 0, which
/// is how nearly every entry of every package is owned. The name `root` is not
/// looked up: a root whose `/etc/passwd` gave it another id would be no root.
fn stated_owner(at: usize, entry: &crate::provision::tar::Entry, path: &[u8]) -> Option<Declared> {
    let root = |name: &[u8], id: u32| (name.is_empty() || name == b"root") && id == 0;
    if root(&entry.uname, entry.uid) && root(&entry.gname, entry.gid) {
        return None;
    }
    Some(Declared {
        record: at,
        path: path.to_vec(),
        directory: entry.typeflag == b'5',
        uname: entry.uname.clone(),
        gname: entry.gname.clone(),
        uid: entry.uid,
        gid: entry.gid,
        dev: 0,
        ino: 0,
    })
}

/// Lays one package's file tree into `tree` through the collision policy,
/// recording each entry against the package numbered `at`.
///
/// `written` hears each entry the extraction writes, with its root-relative
/// path, after the record has it.
///
/// A directory laid where an earlier package's link is
/// ([`Claim::Through`]) is the one claim the record cannot settle alone,
/// because whether the link resolves to a directory is a fact about the tree.
/// The extraction keeps a link that does and replaces one that does not, so
/// once the package is laid down a path that holds a real directory where a
/// link was is a link replaced, and refused as `apk` refuses it. Asking the
/// tree afterwards rather than resolving the link here keeps that rule in one
/// place, the extraction's.
fn lay_package<R: std::io::Read>(
    extraction: &mut Extraction,
    tree: &Rooted,
    database: &mut Database,
    at: usize,
    archive: &mut TarReader<R>,
    written: &mut dyn FnMut(&crate::provision::tar::Entry, Vec<u8>),
) -> Result<(), ProvisionError> {
    let mut through = Vec::new();
    extraction.extract(archive, &mut |entry, components| {
        let placement = record_entry(database, at, entry, components, &mut through)?;
        if placement == Placement::Write {
            written(entry, components.join(&b'/'));
        }
        Ok(placement)
    })?;
    for (path, owner) in through {
        let relative = Path::new(OsStr::from_bytes(&path));
        let stat = tree
            .stat(relative)
            .map_err(|err| ProvisionError::io("inspecting", tree.path(relative), err))?;
        if stat.is_some_and(|stat| rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir()) {
            let claimant = database.record(at).name.clone();
            return Err(wrap(AlpineError::Collision {
                owner,
                directory: Some(claimant.clone()),
                claimant,
                path: String::from_utf8_lossy(&path).into_owned(),
            }));
        }
    }
    Ok(())
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
/// A contested claim is a collision, returned before the entry is written, so
/// the extraction stops at the entry boundary and nothing of it reaches the
/// tree. A directory over an earlier package's link is pushed onto `through`,
/// with the package that laid the link, for [`lay_package`] to settle against
/// the tree.
fn record_entry(
    database: &mut Database,
    at: usize,
    entry: &crate::provision::tar::Entry,
    components: &[Vec<u8>],
    through: &mut Vec<(Vec<u8>, String)>,
) -> Result<Placement, ProvisionError> {
    let path = components.join(&b'/');
    // Root, which is what the extraction leaves every entry owned by. An entry
    // whose package states another owner is given it, and the record told so,
    // in the configure wave.
    let (uid, gid) = (0, 0);
    let shape = match entry.typeflag {
        b'5' => Shape::Directory,
        b'2' => Shape::Link,
        _ => Shape::File,
    };
    let collision = |database: &mut Database, owner, directory| {
        wrap(AlpineError::Collision {
            owner,
            claimant: database.record(at).name.clone(),
            path: String::from_utf8_lossy(&path).into_owned(),
            directory,
        })
    };

    match database.claim(at, &path, shape) {
        Claim::Free | Claim::Replaces => {}
        Claim::Kept => return Ok(Placement::Skip),
        Claim::Through { owner } => through.push((path.clone(), owner)),
        Claim::Contested { owner } => return Err(collision(database, owner, None)),
        Claim::Unlike { owner, directory } => {
            return Err(collision(database, owner, Some(directory)));
        }
    }

    match shape {
        // Directories are shared by construction — every package ships the
        // ones it writes into — so every package that ships one records it.
        Shape::Directory => database.record(at).directory(&path, uid, gid, entry.mode),
        Shape::Link | Shape::File => {
            database
                .record(at)
                .file(&path, uid, gid, entry.mode, entry.checksum_sha1);
        }
    }
    Ok(Placement::Write)
}

/// Checks that a full bootstrap for `target` can execute on `host`.
///
/// A bootstrap the host runs natively needs nothing. A foreign one runs the
/// target's `busybox` and install scripts through a `qemu-user` binfmt handler,
/// which is the kernel-side question [`binfmt::preflight`] answers and words for
/// every layer. The names here are Alpine's, and the mapping onto qemu's is this
/// layer's own because each distribution spells its architectures differently.
fn preflight_foreign(host: &str, target: &str) -> Result<(), AlpineError> {
    // Identical architectures always run. Beyond that, an x86_64 host runs x86
    // binaries through the near-universal IA-32 compatibility mode, and the
    // relation is directional. Other nominally-compatible pairs — aarch64
    // running armv7 — depend on optional kernel support that is absent on many
    // hosts, so they are treated as foreign.
    if host == target || (host == "x86_64" && target == "x86") {
        return Ok(());
    }
    binfmt::preflight(host, target, qemu_interpreter(target)).map_err(|refusal| {
        refusal.into_error(|reason| AlpineError::Config { reason }, AlpineError::io)
    })
}

/// The `qemu-user` interpreter that runs `architecture`'s binaries, by the name
/// its binfmt handler is registered under, or `None` where qemu has none.
fn qemu_interpreter(architecture: &str) -> Option<&'static str> {
    Some(match architecture {
        "x86_64" => "x86_64",
        "x86" => "i386",
        "aarch64" => "aarch64",
        "armv7" | "armhf" => "arm",
        "ppc64le" => "ppc64le",
        "s390x" => "s390x",
        "riscv64" => "riscv64",
        "loongarch64" => "loongarch64",
        _ => return None,
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
        /// The read that failed, where the container could not be read rather
        /// than read as something this reader refuses: a gzip stream that does
        /// not decode, a segment past its ceiling, or the file itself.
        source: Option<io::Error>,
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
    ///
    /// The digests are text rather than a [`Digest`], for the first case: what
    /// an index names a package by is its control identity, `Q1` and the
    /// base64 of a SHA-1, which is not one. The second is the SHA-256 the
    /// package's `.PKGINFO` states, as it spells it.
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
    /// An index is not one a resolution can read: its records are not the ones
    /// the format defines, or it is not an index of the release it was fetched
    /// as.
    ///
    /// The container held together and its signature verified; what it carries
    /// is not a readable set of records, or its signed `DESCRIPTION` names
    /// another release. Alpine signs every release of an architecture with one
    /// key, so the description is what tells a requested release from another
    /// one a mirror served in its place.
    #[non_exhaustive]
    Index {
        /// The URL of the index.
        subject: String,
        /// What was wrong with it.
        reason: String,
    },
    /// A pin could not be held: the repositories no longer supply a package at
    /// the version and with the bytes a plan recorded, or the resolution
    /// requires a pinned package at a version other than the pinned one.
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
    /// the other, or one ships it as a directory and the other as an entry that
    /// is not one.
    ///
    /// For two files, `apk` warns, skips the file, and records the package as
    /// broken. A root is something a caller goes on to build on, so this layer
    /// refuses instead rather than publish a tree whose contents depend on
    /// which package was unpacked first. A directory and an entry that is not
    /// one are refused whichever comes first and whatever either package's
    /// `replaces` says, as `apk` fails to lay the second of them down: no
    /// package can take a directory another one's files lie in. A link that
    /// resolves to a directory satisfies a later directory entry, which is not
    /// a collision.
    #[non_exhaustive]
    Collision {
        /// The package that laid the path down.
        owner: String,
        /// The package that would have overwritten it.
        claimant: String,
        /// The path both ship.
        path: String,
        /// Where the two ship the path as different kinds of entry, whichever
        /// of them ships it as a directory; `None` where neither does. The two
        /// may be one package, shipping the path both ways.
        directory: Option<String>,
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
    /// An entry could not be given the owner its package states.
    ///
    /// Carries what the child entered into the root's identity map reported,
    /// such as an id the map has no room for.
    Ownership(ProvisionError),
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
    /// A malformed container, naming what was being read and what was wrong.
    pub(crate) fn container(subject: impl Into<String>, reason: impl Into<String>) -> AlpineError {
        AlpineError::Container {
            subject: subject.into(),
            reason: reason.into(),
            source: None,
        }
    }

    /// A container that could not be read, naming what was being read, the
    /// part of it the read was in, and the read's own failure.
    ///
    /// The failure is the cause rather than part of the reason, so a rendered
    /// chain states it once.
    pub(crate) fn unreadable(
        subject: impl Into<String>,
        reason: impl Into<String>,
        source: io::Error,
    ) -> AlpineError {
        AlpineError::Container {
            subject: subject.into(),
            reason: reason.into(),
            source: Some(source),
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

path_io_error!(AlpineError);

impl Failover for AlpineError {
    /// Reaches through the wrapper this layer carries a transport failure in.
    /// A failure that is not a `Fetch` one at all — a signature or digest
    /// mismatch over bytes that did arrive — never advances a walk.
    fn is_failover(&self) -> bool {
        matches!(self, AlpineError::Fetch(fetch) if fetch.is_failover())
    }
}

impl From<FetchError> for AlpineError {
    fn from(err: FetchError) -> AlpineError {
        AlpineError::Fetch(err)
    }
}

impl From<resolve::ResolveError> for AlpineError {
    fn from(err: resolve::ResolveError) -> AlpineError {
        match err {
            resolve::ResolveError::Pinned { unheld } => AlpineError::Pin {
                unheld: vec![unheld],
            },
            err => AlpineError::Resolve {
                reason: err.to_string(),
            },
        }
    }
}

impl fmt::Display for AlpineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlpineError::Config { reason } => {
                write!(f, "the Alpine bootstrap is misconfigured: {reason}")
            }
            AlpineError::Container {
                subject, reason, ..
            } => {
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
                directory: None,
            } => write!(
                f,
                "{claimant} and {owner} both ship {path:?}, and neither declares that it \
                 replaces the other",
            ),
            AlpineError::Collision {
                owner,
                claimant,
                path,
                directory: Some(_),
            } if owner == claimant => write!(
                f,
                "{claimant} ships {path:?} both as a directory and as an entry that is not one",
            ),
            AlpineError::Collision {
                owner,
                claimant,
                path,
                directory: Some(directory),
            } => {
                let other = if directory == owner { claimant } else { owner };
                write!(
                    f,
                    "{directory} ships {path:?} as a directory and {other} as an entry that is \
                     not one, which no replaces settles",
                )
            }
            AlpineError::Script {
                package,
                script,
                status,
            } => write!(f, "the {package} {script} script {status}"),
            AlpineError::Launch(_) => f.write_str("an install script could not launch"),
            AlpineError::Ownership(_) => {
                f.write_str("an entry could not be given the owner its package states")
            }
            AlpineError::Cancelled => f.write_str("the bootstrap was cancelled"),
            AlpineError::Fetch(_) => f.write_str("the Alpine bootstrap could not fetch a resource"),
            AlpineError::Io { op, path, .. } => write!(
                f,
                "an Alpine bootstrap step failed while {op} {}",
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
            AlpineError::Ownership(err) => Some(err),
            AlpineError::Io { source, .. } => Some(source),
            AlpineError::Container {
                source: Some(source),
                ..
            } => Some(source),
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
        rest: Canned,
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
    fn canned() -> Canned {
        Canned(HashMap::from([
            (
                "http://mirror.invalid/alpine/v3.23/main/x86_64/APKINDEX.tar.gz".to_string(),
                fixtures::INDEX.to_vec(),
            ),
            (
                "http://mirror.invalid/pmos/v26.06/x86_64/APKINDEX.tar.gz".to_string(),
                fixtures::POSTMARKETOS_INDEX.to_vec(),
            ),
        ]))
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
    fn a_negative_source_date_epoch_is_refused() {
        // /etc/shadow counts days from 1970. Zero is 1970 itself, which is a
        // valid epoch: its accounts are recorded with no day rather than day
        // zero, which `dated` covers.
        let refused = Alpine::builder("v3.23").source_date_epoch(-1).build();
        assert!(
            matches!(&refused, Err(AlpineError::Config { reason }) if reason.contains("negative")),
            "{refused:?}",
        );
        let built = Alpine::builder("v3.23")
            .source_date_epoch(0)
            .build()
            .expect("the builder validates");
        assert_eq!(built.source_date_epoch, Some(0));
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
    fn an_observed_catalogue_reports_the_index_it_is_fetching() {
        // The call is nothing but the index walk, which spends one mirror
        // timeout per unreachable mirror, so an observed caller has no other
        // way to learn what a long silence is waiting on.
        struct Sink(Vec<String>);
        impl AlpineObserver for Sink {
            fn progress(&mut self, event: AlpineEvent<'_>) {
                if let AlpineEvent::Fetching { url } = event {
                    self.0.push(url.to_string());
                }
            }
        }

        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .repository(postmarketos())
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures");
        let mut sink = Sink(Vec::new());
        alpine
            .observe(&mut sink)
            .available()
            .expect("both indexes verify");
        assert_eq!(
            sink.0,
            [
                "http://mirror.invalid/alpine/v3.23/main/x86_64/APKINDEX.tar.gz",
                "http://mirror.invalid/pmos/v26.06/x86_64/APKINDEX.tar.gz",
            ],
        );
    }

    /// A transport serving `index` at `release`'s `main` index and nothing else.
    fn serving(release: &str, index: &[u8]) -> Canned {
        Canned(HashMap::from([(
            format!("http://mirror.invalid/alpine/{release}/main/x86_64/APKINDEX.tar.gz"),
            index.to_vec(),
        )]))
    }

    #[test]
    fn a_genuine_index_of_another_release_is_refused() {
        // Alpine's v3.23 index, verified by the key that signs every release
        // since v3.15, served where another release was asked for. Its signature
        // verifies; its own DESCRIPTION is what says it is not that release.
        for release in ["v3.22", "v3.24", "edge"] {
            let mut alpine = Alpine::builder(release)
                .architecture("x86_64")
                .mirror("http://mirror.invalid/alpine")
                .fetcher(serving(release, fixtures::INDEX))
                .build()
                .expect("the bootstrap configures");
            let err = alpine
                .available()
                .expect_err("the index is not this release's");
            let AlpineError::Index { subject, reason } = &err else {
                panic!("{release}: expected an index refusal, got {err:?}");
            };
            assert!(subject.contains(&format!("/{release}/main/")), "{subject}");
            assert!(reason.contains("v3.23.5-112-gd78b27bd62b"), "{reason}");
            assert!(reason.contains(release), "{reason}");
        }

        // The same bytes as the release they are, and as the name the archive
        // also publishes its newest stable release under.
        for release in ["v3.23", "latest-stable"] {
            let mut alpine = Alpine::builder(release)
                .architecture("x86_64")
                .mirror("http://mirror.invalid/alpine")
                .fetcher(serving(release, fixtures::INDEX))
                .build()
                .expect("the bootstrap configures");
            let available = alpine.available().expect("the index is this release's");
            assert!(available.contains("busybox"), "{release}");
        }
    }

    #[test]
    fn a_postmarketos_index_is_not_bound_to_a_release() {
        // postmarketOS describes an index by the time it was built, which names
        // no release, so its v26.06 index verifies wherever it is served. This
        // is the gap an `https://` transport closes, and the test records it.
        let elsewhere = Repository::builder("v25.12")
            .mirror("http://mirror.invalid/pmos")
            .keys(KeySet::postmarketos())
            .build()
            .expect("the repository validates");
        let mut fetcher = canned();
        fetcher.0.insert(
            "http://mirror.invalid/pmos/v25.12/x86_64/APKINDEX.tar.gz".to_string(),
            fixtures::POSTMARKETOS_INDEX.to_vec(),
        );
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .repository(elsewhere)
            .fetcher(fetcher)
            .build()
            .expect("the bootstrap configures");
        assert!(
            alpine
                .available()
                .expect("nothing binds a postmarketOS index")
                .contains("postmarketos-baselayout"),
        );
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
            .fetcher(Unusable {
                refuse: "http://unusable.invalid/",
                rest: canned(),
            })
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
        let reason = ErrorChain::new(&err).to_string();
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
        let err = alpine.available().expect_err("no mirror serves it");
        let reason = ErrorChain::new(&err).to_string();
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
            index.sha256.hex(),
            Algorithm::Sha256.hex_of(fixtures::INDEX)
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
        let held = read_acquired(
            File::open(&path).expect("the package opens"),
            &path,
            planned,
            "x86_64",
        )
        .expect("the served package is the one the index named");
        assert_eq!(held.package.info.name, "postmarketos-baselayout");

        // And the binding is doing real work: the same file refused where the
        // plan names another version of it.
        let mut moved = planned.clone();
        moved.version = "61-r0".to_string();
        let err = read_acquired(
            File::open(&path).expect("the package opens"),
            &path,
            &moved,
            "x86_64",
        )
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
        plan.packages[0].control_identity = sign::identity_for_test("other bytes");
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
    fn the_order_include_names_packages_in_changes_nothing() {
        // Against Alpine's published index: one plan, and one world, whichever
        // order the packages were named in.
        let forward = ["alpine-base", "build-base", "musl"];
        let mut backward = forward;
        backward.reverse();
        let plan = |world: &[&str]| {
            provisioner(world)
                .build()
                .expect("the bootstrap configures")
                .resolve()
                .expect("the closure resolves")
                .to_document()
                .expect("the plan renders")
        };
        assert_eq!(plan(&forward), plan(&backward));

        let built = provisioner(&["musl", "alpine-base", "musl"])
            .build()
            .expect("the bootstrap configures");
        assert_eq!(
            built.world,
            ["alpine-base", "musl"],
            "what /etc/apk/world lists"
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

    #[test]
    fn a_requested_name_carrying_a_repository_tag_is_refused_where_it_is_named() {
        // apk's world spells a tagged repository `name@tag`. No repository here
        // carries a tag, so the name would otherwise reach the resolution and
        // fail late as a package nothing offers.
        for (include, exclude) in [
            (&["busybox@edge"][..], &[][..]),
            (&["busybox@edge>=1.37"][..], &[][..]),
            (&["busybox"][..], &["musl@testing"][..]),
        ] {
            let err = Alpine::builder("v3.23")
                .architecture("x86_64")
                .include(include.iter().copied())
                .exclude(exclude.iter().copied())
                .build()
                .expect_err("a tag names no configured repository");
            assert!(
                matches!(&err, AlpineError::Config { reason } if reason.contains("repository tag")),
                "{include:?} {exclude:?}: {err}",
            );
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
        PlannedPackage {
            name: read.info.name.clone(),
            version: read.info.version.clone(),
            architecture: architecture.to_string(),
            control_identity: read.control_identity,
            size: Some(container.len() as u64),
            installed_size: read.info.installed_size,
            origin: read.info.origin.clone(),
            index: 0,
            carried: crate::provision::document::Carried::new(),
        }
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

        let mut acquired: Vec<Acquired> = Vec::new();
        for container in [fixtures::ALPINE_BASELAYOUT, fixtures::MUSL] {
            let planned = planned_from(container, "x86_64");
            let path = cache.join(planned.file_name());
            std::fs::write(&path, container).expect("the package is writable");
            acquired.push(
                read_acquired(
                    File::open(&path).expect("the package opens"),
                    &path,
                    &planned,
                    "x86_64",
                )
                .expect("the package answers the plan entry"),
            );
        }

        let order: Vec<usize> = (0..acquired.len()).collect();
        let (database, subjects) = lay_down(
            &staging,
            None,
            Carried::default(),
            &mut acquired,
            &order,
            &mut Silent,
        )
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

    /// An apk container of a package stating `pkginfo`, whose file tree is
    /// `tree`: a signature segment no anchor holds, the control segment, and
    /// the data segment the control segment's `datahash` binds.
    fn container_of(pkginfo: &str, tree: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let gzip = |tar: &[u8]| {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(tar).expect("the segment compresses");
            encoder.finish().expect("the segment closes")
        };
        let data = gzip(tree);
        let pkginfo = format!(
            "{pkginfo}datahash = {}\n",
            crate::provision::digest::Algorithm::Sha256.hex_of(&data),
        );
        let control = gzip(
            &ferroday_cage_testkit::tar::Tar::new()
                .file(".PKGINFO", 0o644, pkginfo.as_bytes())
                .finish(),
        );
        let signature = gzip(
            &ferroday_cage_testkit::tar::Tar::new()
                .file(".SIGN.RSA.nobody.rsa.pub", 0o644, &[0; 512])
                .finish(),
        );
        [signature, control, data].concat()
    }

    /// `container`, acquired through the cache entry `cache` holds for it.
    fn acquired_from(cache: &Path, container: &[u8]) -> Acquired {
        let planned = planned_from(container, "x86_64");
        let path = cache.join(planned.file_name());
        std::fs::write(&path, container).expect("the package is writable");
        read_acquired(
            File::open(&path).expect("the package opens"),
            &path,
            &planned,
            "x86_64",
        )
        .expect("the package answers the plan entry")
    }

    #[test]
    fn a_package_its_install_if_brought_in_is_installed_after_the_condition() {
        // apk adds an `install_if` package to a transaction only once what the
        // condition names is in it. The launch helper needs nothing of `dbus`,
        // and its group is the one `dbus`'s pre-install creates, so ordered by
        // its dependencies alone it would be given its owner before the group
        // exists.
        let scratch = Scratch::new("alpine-install-if-order");
        let empty = ferroday_cage_testkit::tar::Tar::new().finish();
        let acquired = [
            acquired_from(
                &scratch,
                &container_of(
                    "pkgname = dbus-daemon-launch-helper\npkgver = 1-r0\narch = x86_64\n\
                     size = 1\ninstall_if = dbus=1-r0\n",
                    &empty,
                ),
            ),
            acquired_from(
                &scratch,
                &container_of(
                    "pkgname = dbus\npkgver = 1-r0\narch = x86_64\nsize = 1\n",
                    &empty,
                ),
            ),
        ];
        let names: Vec<&str> = install_order(&acquired)
            .into_iter()
            .map(|at| acquired[at].package.info.name.as_str())
            .collect();
        assert_eq!(names, ["dbus", "dbus-daemon-launch-helper"]);
    }

    #[test]
    fn an_entry_stating_another_owner_is_laid_down_as_root_and_declared() {
        // `dbus-daemon-launch-helper` as Alpine ships it: the archive's gid is
        // 0, and only its group name says `messagebus`. The extraction lays it
        // down as the calling user, the database records the root that is, and
        // the entry is handed on, as it lies on disk, for the configure wave to
        // give the owner the name resolves to.
        let scratch = Scratch::new("alpine-declared");
        let cache = scratch.join("cache");
        std::fs::create_dir_all(&cache).expect("the cache is creatable");
        let staging = scratch.join("root");
        std::fs::create_dir_all(&staging).expect("the staging tree is creatable");

        let mut tree = ferroday_cage_testkit::tar::Tar::new();
        tree.dir("usr", 0o755).dir("usr/libexec", 0o755);
        tree.file("usr/libexec/plain", 0o755, b"#!/bin/sh\n");
        tree.owner_names("root", "messagebus");
        tree.file("usr/libexec/helper", 0o4750, b"#!/bin/sh\n");
        tree.owner_names("messagebus", "messagebus");
        tree.dir_owned("var", 0o755, 0, 0);
        tree.owner_names("root", "root");
        tree.dir_owned("var/numeric", 0o750, 100, 101);
        let container = container_of(
            "pkgname = dbus-daemon-launch-helper\npkgver = 1.16.2-r1\narch = x86_64\n\
             size = 1\norigin = dbus\n",
            &tree.finish(),
        );
        let planned = planned_from(&container, "x86_64");
        let path = cache.join(planned.file_name());
        std::fs::write(&path, &container).expect("the package is writable");
        let mut acquired = vec![
            read_acquired(
                File::open(&path).expect("the package opens"),
                &path,
                &planned,
                "x86_64",
            )
            .expect("the package answers the plan entry"),
        ];
        let (database, subjects) = lay_down(
            &staging,
            None,
            Carried::default(),
            &mut acquired,
            &[0],
            &mut Silent,
        )
        .expect("the package lays down");

        let installed = String::from_utf8(database.installed()).expect("the database is text");
        assert!(installed.contains("R:helper\na:0:0:4750\n"), "{installed}");
        assert!(
            installed.contains("F:var/numeric\nM:0:0:750\n"),
            "{installed}"
        );

        let [subject] = &subjects[..] else {
            panic!("one package, one subject");
        };
        // Each as `path user:group uid:gid`, and a directory marked by its
        // trailing slash.
        let declared: Vec<String> = subject
            .declared
            .iter()
            .map(|entry| {
                format!(
                    "{}{} {}:{} {}:{}",
                    String::from_utf8_lossy(&entry.path),
                    if entry.directory { "/" } else { "" },
                    String::from_utf8_lossy(&entry.uname),
                    String::from_utf8_lossy(&entry.gname),
                    entry.uid,
                    entry.gid,
                )
            })
            .collect();
        assert_eq!(
            declared,
            [
                "usr/libexec/helper root:messagebus 0:0",
                "var/ messagebus:messagebus 0:0",
                "var/numeric/ root:root 100:101",
            ],
            "in path order, and none for an entry root owns",
        );
        let helper = &subject.declared[0];
        let on_disk = std::fs::symlink_metadata(staging.join("usr/libexec/helper"))
            .expect("the helper is laid down");
        assert!(
            std::os::unix::fs::MetadataExt::ino(&on_disk) == helper.ino
                && std::os::unix::fs::MetadataExt::dev(&on_disk) == helper.dev,
            "the entry is named as it lies on disk",
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
        let err = read_acquired(
            File::open(&path).expect("the package opens"),
            &path,
            &planned,
            "x86_64",
        )
        .expect_err("the served package is not the one the plan identified");
        assert!(matches!(err, AlpineError::Digest { .. }), "{err}");

        // And a plan whose own fields contradict the package it identifies.
        let mut planned = planned_from(fixtures::MUSL, "x86_64");
        planned.name = "not-musl".to_string();
        let err = read_acquired(
            File::open(&path).expect("the package opens"),
            &path,
            &planned,
            "x86_64",
        )
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
        let err = read_acquired(
            File::open(&path).expect("the package opens"),
            &path,
            &planned,
            "aarch64",
        )
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
        for (at, (name, version, fields)) in records.iter().enumerate() {
            // A distinct well-formed control identity per record, which the
            // reader checks the shape of and nothing here reads.
            let identity = sign::identity_for_test(&format!("{at} {name}"));
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
        assert!(
            ErrorChain::new(&err).to_string().contains("stage_layer"),
            "{err}"
        );

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
        assert!(
            ErrorChain::new(&err).to_string().contains("stage_layer"),
            "{err}"
        );
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
    fn a_download_is_announced_over_what_is_being_downloaded() {
        // The event is emitted for a cache miss and only for one, so counting
        // the plan's packages reports a fetch of one package as reaching two of
        // two. What `index` of `total` means has to be the downloads.
        let scratch = Scratch::new("alpine-download-count");
        let mirror = published(
            &scratch,
            &[
                ("musl-1.2.5-r23.apk", fixtures::MUSL),
                ("alpine-keys-2.6-r0.apk", fixtures::ALPINE_KEYS),
            ],
        );
        let cache = scratch.join("cache");
        std::fs::create_dir_all(&cache).expect("the cache is creatable");
        // One of the two already in the cache, which is the everyday state of a
        // second run, under the name its control identity gives it.
        std::fs::write(
            cache.join("musl-1.2.5-r23.1b6c50426d3c0656e9c5a567a5a59601c7f4307a.apk"),
            fixtures::MUSL,
        )
        .expect("the cached package is writable");

        #[derive(Default)]
        struct Counting(Vec<(String, usize, usize)>);
        impl AlpineObserver for Counting {
            fn progress(&mut self, event: AlpineEvent<'_>) {
                if let AlpineEvent::Downloading {
                    package,
                    index,
                    total,
                } = event
                {
                    self.0.push((package.to_string(), index, total));
                }
            }
        }

        let mut counting = Counting::default();
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .include(["musl", "alpine-keys"])
            .cache_dir(&cache)
            .extract_only(true)
            .build()
            .expect("the bootstrap configures");
        crate::provision::ensure(scratch.join("root"), &mut alpine.observe(&mut counting))
            .expect("the bootstrap runs");

        assert_eq!(
            counting.0,
            vec![("alpine-keys".to_string(), 1, 1)],
            "one package is downloaded, and it is the first of one",
        );
    }

    #[test]
    fn a_layered_provisioner_is_read_through_resolve_layer() {
        // `provision::ensure` refuses a provisioner with a base layer, and the
        // read half has to agree: reporting the whole-root closure answers a
        // question this provisioner never asks, and reads as the plan it would
        // install.
        let scratch = Scratch::new("alpine-layered-resolve");
        let mirror = published(&scratch, &[("musl-1.2.5-r23.apk", fixtures::MUSL)]);
        let base = provisioned_base(&mirror, &scratch.join("base"), &["musl"]);
        let err = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .base_layer(&base)
            .include(["musl"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect_err("a layered provisioner is not read this way");
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains("resolve_layer")),
            "{err}",
        );
    }

    #[test]
    fn an_increment_the_base_already_satisfies_still_says_what_it_wants() {
        // Every requested package is in the base, so there is nothing to
        // download and no script to run -- but the increment's own state is
        // still written. What a caller reads back from the merged view cannot
        // depend on whether the delta happened to be empty, and a base holding
        // a package says nothing about whether its world names one: every
        // package a resolution pulled in as a dependency is installed and
        // unwanted.
        let scratch = Scratch::new("alpine-empty-increment");
        let mirror = published(&scratch, &[("musl-1.2.5-r23.apk", fixtures::MUSL)]);
        let base = provisioned_base(&mirror, &scratch.join("base"), &["musl"]);
        std::fs::write(base.join("etc/apk/world"), b"").expect("the base's world is writable");
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
        assert!(layer.path().is_dir());
        assert_eq!(
            std::fs::read_to_string(upper.join("etc/apk/world")).expect("the world is written"),
            "musl\n",
            "the increment's request reaches the merged view",
        );
        // Nothing was downloaded and nothing ran, which is still true.
        assert!(!upper.join("lib/apk/exec").exists());
        assert!(!upper.join("lib/ld-musl-x86_64.so.1").exists());
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
        assert!(
            ErrorChain::new(&err).to_string().contains("systemd"),
            "{err}"
        );
        assert!(
            !upper.exists(),
            "the upper it created went with the failure"
        );

        // An upper that was already there is the caller's, and a failure
        // leaves it, and the earlier work it holds, in place.
        std::fs::create_dir_all(upper.join("usr/bin")).expect("the upper is laid out");
        std::fs::write(upper.join("usr/bin/earlier"), b"earlier work").expect("written");
        Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .base_layer(&base)
            .include(["systemd"])
            .extract_only(true)
            .build()
            .expect("the bootstrap configures")
            .stage_layer(&upper)
            .expect_err("Alpine publishes no systemd");
        assert_eq!(
            std::fs::read(upper.join("usr/bin/earlier")).expect("the caller's upper survives"),
            b"earlier work",
        );
    }

    #[test]
    fn the_preflight_asks_the_callers_delegate_for_a_range_map() {
        // A map only a site-specific delegate can establish is one the bundled
        // chain cannot, so the refusal that stops a bootstrap before any
        // download has to come from the delegate the caller supplied.
        #[derive(Debug, Clone, Default)]
        struct Refusing {
            asked: Arc<std::sync::Mutex<usize>>,
        }
        impl IdMapper for Refusing {
            fn resolve(
                &self,
                _request: &IdentityMap,
            ) -> Result<crate::ResolvedMap, crate::IdMapError> {
                *self.asked.lock().unwrap() += 1;
                Err(crate::IdMapError::unsatisfiable(
                    "the caller's delegate refuses",
                ))
            }
            fn apply(&self, _pid: u32, _map: &crate::ResolvedMap) -> Result<(), crate::IdMapError> {
                unreachable!("a refused map is never applied")
            }
        }

        let delegate = Refusing::default();
        let alpine = Alpine::builder("v3.23")
            .architecture(host_architecture())
            .identity_map(IdentityMap::Subordinate)
            .id_mapper(delegate.clone())
            .build()
            .expect("the bootstrap configures");
        let err = preflight(&alpine).expect_err("the delegate refuses the map");
        assert!(
            matches!(&err, AlpineError::Config { reason, .. } if reason.contains("the caller's delegate refuses")),
            "{err}",
        );
        assert_eq!(*delegate.asked.lock().unwrap(), 1);
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

        // And stopping, from the sink bound with `observe`: the same watch,
        // told to stop, stops the run once the closure is known, and the
        // staging tree goes with it.
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .include(["musl"])
            .extract_only(true)
            .build()
            .expect("the bootstrap configures");
        let mut watch = Watch {
            seen: Vec::new(),
            stop: true,
        };
        let watched = scratch.join("watched");
        let err = crate::provision::ensure(&watched, &mut alpine.observe(&mut watch))
            .expect_err("the sink asked it to stop");
        assert!(
            matches!(err, crate::provision::ProvisionError::Cancelled),
            "{err}",
        );
        assert_eq!(watch.seen, ["resolving", "resolved 1"]);
        assert!(!watched.exists());

        // And from the run's own observer, which is the one a caller driving
        // several provisioners shares. The Alpine events reach it through the
        // shared vocabulary.
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

    #[test]
    fn a_download_that_is_not_the_package_never_reaches_the_cache() {
        // A download is checked as a cache hit is, before it is renamed into
        // the cache, so a mirror serving another package under the planned
        // package's name leaves nothing at the cache path for a later run, or
        // another run sharing the cache, to meet.
        let scratch = Scratch::new("alpine-download-checked");
        let repository = scratch.join("mirror/v3.23/main/x86_64");
        std::fs::create_dir_all(&repository).expect("the repository tree is creatable");
        std::fs::write(repository.join("APKINDEX.tar.gz"), fixtures::INDEX)
            .expect("the index is writable");
        std::fs::write(repository.join("musl-1.2.5-r23.apk"), fixtures::MUSL)
            .expect("the package is writable");
        let mirror =
            crate::provision::file_url(&scratch.join("mirror")).expect("the path is nameable");
        let plan = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .include(["musl"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("musl resolves");

        // The mirror now answers for musl with a validly signed package that is
        // not musl.
        std::fs::write(
            repository.join("musl-1.2.5-r23.apk"),
            fixtures::ALPINE_BASELAYOUT,
        )
        .expect("the package is writable");
        let cache = scratch.join("cache");
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .plan(plan)
            .extract_only(true)
            .cache_dir(&cache)
            .build()
            .expect("the bootstrap configures");
        let err = crate::provision::ensure(scratch.join("root"), &mut alpine)
            .expect_err("the package served is not the one planned");
        assert!(ErrorChain::new(&err).to_string().contains("musl"), "{err}");
        let held: Vec<_> = std::fs::read_dir(&cache)
            .expect("the cache was created")
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(held.is_empty(), "the cache holds {held:?}");
    }

    #[test]
    fn a_package_missing_from_the_primary_is_served_by_the_backstop() {
        // The plan records the mirror that served the index, and a package is
        // fetched over the configured mirror list rather than that record. The
        // primary keeps the index the plan resolved from and loses the package,
        // which is what a rebuild does to a live mirror; a walk that stopped at
        // the recorded mirror could not recover from it.
        let scratch = Scratch::new("alpine-package-backstop");
        let primary = scratch.join("primary/v3.23/main/x86_64");
        let backstop = scratch.join("backstop/v3.23/main/x86_64");
        for tree in [&primary, &backstop] {
            std::fs::create_dir_all(tree).expect("the repository tree is creatable");
        }
        std::fs::write(primary.join("APKINDEX.tar.gz"), fixtures::INDEX)
            .expect("the index is writable");
        std::fs::write(primary.join("musl-1.2.5-r23.apk"), fixtures::MUSL)
            .expect("the package is writable");

        let primary_url =
            crate::provision::file_url(&scratch.join("primary")).expect("the path is nameable");
        let backstop_url =
            crate::provision::file_url(&scratch.join("backstop")).expect("the path is nameable");

        let plan = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&primary_url)
            .include(["musl"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("musl resolves");

        // The package rotates off the primary onto the backstop. The index it
        // was resolved from stays exactly where it was.
        std::fs::rename(
            primary.join("musl-1.2.5-r23.apk"),
            backstop.join("musl-1.2.5-r23.apk"),
        )
        .expect("the package is movable");

        // Without a backstop there is nowhere else to look, which is what makes
        // the success below the walk's doing rather than the primary's.
        let mut alone = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&primary_url)
            .plan(plan.clone())
            .extract_only(true)
            .build()
            .expect("the bootstrap configures");
        crate::provision::ensure(scratch.join("alone"), &mut alone)
            .expect_err("the primary no longer serves the package");

        let root = scratch.join("root");
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&primary_url)
            .mirror_fallback(&backstop_url)
            .plan(plan)
            .extract_only(true)
            .build()
            .expect("the bootstrap configures");
        crate::provision::ensure(&root, &mut alpine).expect("the backstop serves the package");
        assert!(root.join("lib/ld-musl-x86_64.so.1").is_file());
    }

    #[test]
    fn a_plan_pins_the_closure_it_installed() {
        // `plan()` forbids `include()`, so the configured world is empty and an
        // empty `/etc/apk/world` is what a plan-based root carried: apk reads
        // that as nothing being wanted, and acts on it. A plan names every
        // package rather than the seeds a resolution closed over, so its names
        // are what the root wants.
        let scratch = Scratch::for_test("alpine", "plan-world");
        let mirror = published(&scratch, &[("musl-1.2.5-r23.apk", fixtures::MUSL)]);
        let plan = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .include(["musl"])
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("musl resolves");
        let mut names: Vec<String> = plan
            .packages
            .iter()
            .map(|package| package.name.clone())
            .collect();
        assert!(names.iter().any(|name| name == "musl"), "{names:?}");
        names.sort();

        let root = scratch.join("planned");
        let mut alpine = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .plan(plan)
            .extract_only(true)
            .build()
            .expect("the bootstrap configures");
        crate::provision::ensure(&root, &mut alpine).expect("the plan installs");
        let world =
            std::fs::read_to_string(root.join("etc/apk/world")).expect("a world is written");
        let mut wanted: Vec<String> = world.lines().map(str::to_string).collect();
        wanted.sort();
        assert_eq!(wanted, names, "the plan's packages are what the root wants");
    }

    #[test]
    fn a_plan_resolved_against_more_indexes_than_are_configured_is_refused() {
        // A package names the index it came from, and the mirrors it is fetched
        // over are the ones the repository publishing that index is configured
        // with. A plan the configuration cannot account for therefore names no
        // mirror, and says so before anything is downloaded.
        let plan = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .repository(postmarketos())
            .include(["busybox"])
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("busybox resolves");
        assert_eq!(plan.indexes.len(), 2, "one index from each repository");

        let err = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .plan(plan)
            .extract_only(true)
            .fetcher(canned())
            .build()
            .expect_err("the second repository is not configured");
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains("name no mirror")),
            "{err}",
        );
    }

    /// A one-entry uncompressed tar holding `path` with `contents`, as a
    /// package's data segment lays a file down.
    fn one_file_archive(path: &str, contents: &[u8]) -> Vec<u8> {
        ferroday_cage_testkit::tar::Tar::new()
            .file(path, 0o644, contents)
            .finish()
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

    /// Lays `packages` — each a name, its extra `.PKGINFO` lines, and its data
    /// segment — down in order into a fresh tree, and returns that tree with
    /// the database written over it, or the failure that stopped it.
    ///
    /// Drives the real [`Extraction`] through the real [`lay_package`], which
    /// is the pairing the collision policy lives in: `claim` alone cannot say
    /// whether the tree agrees with the record of it.
    fn lay(packages: &[(&str, &str, Vec<u8>)]) -> (Scratch, Result<Database, ProvisionError>) {
        let scratch = Scratch::new("alpine-collision");
        let staging = scratch.join("root");
        std::fs::create_dir_all(&staging).expect("the staging tree is creatable");

        let mut extraction = Extraction::new(&staging).expect("the root opens");
        let tree = Rooted::open(&staging).expect("the root opens");
        let mut database = Database::default();
        for (name, extra, archive) in packages {
            let at = database.add(record_of(name, extra));
            let mut reader = TarReader::in_memory(&archive[..]);
            if let Err(err) = lay_package(
                &mut extraction,
                &tree,
                &mut database,
                at,
                &mut reader,
                &mut |_, _| {},
            ) {
                return (scratch, Err(err));
            }
        }
        extraction.finalize(&staging).expect("the metadata applies");
        (scratch, Ok(database))
    }

    /// Lays `packages` — each a name, its extra `.PKGINFO` lines, and the
    /// contents it ships at `usr/bin/tool` — down in order, none of them
    /// colliding.
    fn lay_contested(packages: &[(&str, &str, &[u8])]) -> (Scratch, Database) {
        let packages: Vec<(&str, &str, Vec<u8>)> = packages
            .iter()
            .map(|(name, extra, contents)| {
                (*name, *extra, one_file_archive("usr/bin/tool", contents))
            })
            .collect();
        let (scratch, laid) = lay(&packages);
        (scratch, laid.expect("nothing collides"))
    }

    /// The collision that stopped `laid`, as its owner, claimant, and the
    /// package that ships the path as a directory.
    fn collision_of(laid: Result<Database, ProvisionError>) -> (String, String, Option<String>) {
        let err = laid.err().expect("the two collide");
        let Some(AlpineError::Collision {
            owner,
            claimant,
            directory,
            path,
        }) = std::error::Error::source(&err).and_then(|source| source.downcast_ref())
        else {
            panic!("expected a collision, got {err:?}");
        };
        assert_eq!(path, "usr/lib/thing", "{err}");
        (owner.clone(), claimant.clone(), directory.clone())
    }

    /// A package shipping `usr/lib/thing` as a file.
    fn as_file() -> Vec<u8> {
        ferroday_cage_testkit::tar::Tar::new()
            .dir("usr", 0o755)
            .dir("usr/lib", 0o755)
            .file("usr/lib/thing", 0o644, b"a file")
            .finish()
    }

    /// A package shipping `usr/lib/thing` as a directory, holding `inside` where
    /// it is given.
    fn as_directory(inside: Option<&str>) -> Vec<u8> {
        let mut tar = ferroday_cage_testkit::tar::Tar::new();
        tar.dir("usr", 0o755)
            .dir("usr/lib", 0o755)
            .dir("usr/lib/thing", 0o755);
        if let Some(name) = inside {
            tar.file(&format!("usr/lib/thing/{name}"), 0o644, b"inside");
        }
        tar.finish()
    }

    /// A package shipping `usr/lib/thing` as a link to `target`, and
    /// `usr/lib/real` as a directory.
    fn as_link(target: &str) -> Vec<u8> {
        ferroday_cage_testkit::tar::Tar::new()
            .dir("usr", 0o755)
            .dir("usr/lib", 0o755)
            .dir("usr/lib/real", 0o755)
            .symlink("usr/lib/thing", target)
            .finish()
    }

    #[test]
    fn a_directory_and_a_file_at_one_path_collide_whichever_is_laid_first() {
        // The extraction alone would let the later one win, silently: a
        // directory entry replaces a file, and a file replaces an empty
        // directory. Which survived depended on the unpack order, and the
        // earlier package's record went on describing what was gone.
        // `replaces` does not settle it, as it does not for apk.
        for replaces in ["", "replaces = file\nreplaces = directory\n"] {
            for inside in [Some("child"), None] {
                let (_, laid) = lay(&[
                    ("file", replaces, as_file()),
                    ("directory", replaces, as_directory(inside)),
                ]);
                assert_eq!(
                    collision_of(laid),
                    (
                        "file".to_string(),
                        "directory".to_string(),
                        Some("directory".to_string())
                    ),
                    "the file first, {inside:?}, {replaces:?}",
                );
                let (_, laid) = lay(&[
                    ("directory", replaces, as_directory(inside)),
                    ("file", replaces, as_file()),
                ]);
                assert_eq!(
                    collision_of(laid),
                    (
                        "directory".to_string(),
                        "file".to_string(),
                        Some("directory".to_string())
                    ),
                    "the directory first, {inside:?}, {replaces:?}",
                );
            }
        }
    }

    #[test]
    fn a_link_to_a_directory_satisfies_a_later_directory_entry() {
        // The merged-usr shape, and `var/run -> ../run`: the later package's
        // files land through the link, which stays the earlier package's.
        let (scratch, laid) = lay(&[
            ("link", "", as_link("real")),
            ("directory", "", as_directory(Some("child"))),
        ]);
        laid.expect("a link to a directory is not a collision");
        let thing = scratch.join("root/usr/lib/thing");
        assert!(
            std::fs::symlink_metadata(&thing)
                .expect("the link is there")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read(scratch.join("root/usr/lib/real/child")).expect("the file landed"),
            b"inside",
        );
    }

    #[test]
    fn a_link_that_is_not_to_a_directory_collides_with_a_directory_either_way() {
        // A dangling link is replaced by the extraction, which the tree shows
        // afterwards. A link laid where a directory is collides at once.
        let (_, laid) = lay(&[
            ("link", "", as_link("nowhere")),
            ("directory", "", as_directory(Some("child"))),
        ]);
        assert_eq!(
            collision_of(laid),
            (
                "link".to_string(),
                "directory".to_string(),
                Some("directory".to_string())
            ),
        );
        let (_, laid) = lay(&[
            ("directory", "", as_directory(Some("child"))),
            ("link", "", as_link("real")),
        ]);
        assert_eq!(
            collision_of(laid),
            (
                "directory".to_string(),
                "link".to_string(),
                Some("directory".to_string())
            ),
        );
    }

    #[test]
    fn a_collision_reads_as_what_it_is() {
        let file = AlpineError::Collision {
            owner: "one".to_string(),
            claimant: "two".to_string(),
            path: "usr/bin/tool".to_string(),
            directory: None,
        };
        assert!(file.to_string().contains("neither declares"), "{file}");
        let kinds = AlpineError::Collision {
            owner: "one".to_string(),
            claimant: "two".to_string(),
            path: "usr/lib/thing".to_string(),
            directory: Some("two".to_string()),
        };
        assert_eq!(
            kinds.to_string(),
            "two ships \"usr/lib/thing\" as a directory and one as an entry that is not one, \
             which no replaces settles",
        );
        let itself = AlpineError::Collision {
            owner: "one".to_string(),
            claimant: "one".to_string(),
            path: "usr/lib/thing".to_string(),
            directory: Some("one".to_string()),
        };
        assert_eq!(
            itself.to_string(),
            "one ships \"usr/lib/thing\" both as a directory and as an entry that is not one",
        );
    }

    #[test]
    fn a_collision_quotes_the_path_its_archives_named() {
        // The path is an archive entry's name, which nothing vouches for, so a
        // control character in it reaches the rendering escaped.
        let path = format!("usr/lib/{}", crate::failure::hostile::TEXT);
        // Two files, two kinds of entry, and one package shipping both kinds:
        // each of the three renderings.
        for (claimant, directory) in [("two", None), ("two", Some("two")), ("one", Some("one"))] {
            let collision = AlpineError::Collision {
                owner: "one".to_string(),
                claimant: claimant.to_string(),
                path: path.clone(),
                directory: directory.map(str::to_string),
            };
            crate::failure::hostile::assert_escaped(&collision.to_string());
        }
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

    /// A plan the canned repository would resolve, for the refusals below to
    /// start from something valid.
    #[cfg(test)]
    fn resolved_plan() -> Plan {
        Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .include(["busybox"])
            .fetcher(canned())
            .build()
            .expect("the bootstrap configures")
            .resolve()
            .expect("busybox resolves")
    }

    /// The refusal `build()` gives for `plan`, under `configure`.
    fn refuses_plan(plan: Plan, configure: impl FnOnce(AlpineBuilder) -> AlpineBuilder) -> String {
        let builder = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .extract_only(true)
            .fetcher(canned())
            .plan(plan);
        match configure(builder).build() {
            Err(AlpineError::Config { reason }) => reason,
            other => panic!("expected a configuration refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_plan_resolved_for_another_architecture_is_refused_at_build() {
        // Refused where the configuration is frozen, rather than after the
        // first package has downloaded, as a per-package "states architecture"
        // error the run would otherwise end in.
        let mut plan = resolved_plan();
        plan.architecture = "aarch64".to_string();
        let reason = refuses_plan(plan, |builder| builder);
        assert!(reason.contains("aarch64"), "{reason}");
        assert!(reason.contains("x86_64"), "{reason}");
    }

    #[test]
    fn what_a_plan_or_a_pin_states_reaches_a_refusal_with_its_control_characters_escaped() {
        // A plan document is a file the caller may have taken from elsewhere,
        // and nothing holds its header or its index stanzas to an alphabet.
        use crate::failure::hostile::{TEXT as HOSTILE, assert_escaped};
        let mut plan = resolved_plan();
        plan.architecture = HOSTILE.to_string();
        let reason = refuses_plan(plan.clone(), |builder| builder);
        assert!(
            reason.contains("the plan resolves architecture"),
            "{reason}"
        );
        assert_escaped(&reason);
        let pinned = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .fetcher(canned())
            .pin(plan)
            .build();
        match pinned {
            Err(AlpineError::Config { reason }) => {
                assert!(reason.contains("the pin resolves architecture"), "{reason}");
                assert_escaped(&reason);
            }
            other => panic!("expected the pin refused, got {other:?}"),
        }

        for (release, component) in [(HOSTILE, Some("main")), ("v3.23", Some(HOSTILE))] {
            let mut plan = resolved_plan();
            plan.indexes[0].release = release.to_string();
            plan.indexes[0].component = component.map(str::to_string);
            let reason = refuses_plan(plan, |builder| builder);
            assert!(reason.contains("the plan's index 0"), "{reason}");
            assert_escaped(&reason);
        }

        // A package's name is admitted before a refusal names it bare, so one
        // that names no index the plan records is refused for its name first.
        let mut plan = resolved_plan();
        plan.packages[0].name = HOSTILE.to_string();
        plan.packages[0].index = plan.indexes.len();
        let reason = refuses_plan(plan, |builder| builder);
        assert!(reason.contains("addressed by"), "{reason}");
        assert_escaped(&reason);
    }

    #[test]
    fn a_plan_naming_one_package_twice_is_refused_at_build() {
        // A root holds one package of a name. Installed, the second entry would
        // write a second installed record, archive its scripts twice and run
        // them twice; the refusal is the one a pin naming a package twice gets.
        let mut plan = resolved_plan();
        let mut again = plan.packages[0].clone();
        again.version = "0.1-r0".to_string();
        plan.packages.push(again);
        let reason = refuses_plan(plan.clone(), |builder| builder);
        assert!(reason.contains("twice"), "{reason}");
        assert!(reason.contains(&plan.packages[0].name), "{reason}");

        // Identical entries are no less a duplicate.
        let mut plan = resolved_plan();
        let first = plan.packages[0].clone();
        plan.packages.push(first);
        let reason = refuses_plan(plan, |builder| builder);
        assert!(reason.contains("twice"), "{reason}");
    }

    #[test]
    fn a_builder_naming_no_architecture_adopts_the_plans() {
        // The other half of the check above, and the reason it is not a trap: a
        // plan states which architecture it is for, so refusing one the caller
        // never contradicted — over a host default they never chose — would be a
        // confusing rejection. The Debian builder adopts a plan's architecture
        // for exactly this reason, and a pin's the same way.
        let mut plan = resolved_plan();
        plan.architecture = "aarch64".to_string();
        for package in &mut plan.packages {
            package.architecture = "aarch64".to_string();
        }
        let alpine = Alpine::builder("v3.23")
            .mirror("http://mirror.invalid/alpine")
            .extract_only(true)
            .fetcher(canned())
            .plan(plan)
            .build()
            .expect("the plan states the architecture");
        assert_eq!(alpine.architecture, "aarch64");
    }

    #[test]
    fn a_plan_whose_index_is_not_the_one_configured_in_that_slot_is_refused() {
        // The correspondence is positional and a package's URL is composed from
        // the configured mirror with the plan's own release and component, so a
        // mismatched slot composes a directory no mirror serves. Without this
        // the whole mirror walk 404s and blames mirrors that were never asked
        // for that directory.
        let mut plan = resolved_plan();
        plan.indexes[0].component = Some("community".to_string());
        let reason = refuses_plan(plan, |builder| builder);
        assert!(reason.contains("v3.23/community"), "{reason}");
        assert!(reason.contains("v3.23/main"), "{reason}");

        // The mirror is deliberately not compared: a plan carried to another
        // configuration fetches from that configuration's mirrors, which is
        // what makes it portable.
        let mut moved = resolved_plan();
        moved.indexes[0].mirror = "http://elsewhere.invalid/alpine".to_string();
        Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .extract_only(true)
            .fetcher(canned())
            .plan(moved)
            .build()
            .expect("a plan resolved elsewhere still installs here");
    }

    #[test]
    fn a_plan_naming_a_package_by_a_path_is_refused_at_build() {
        // `Plan` is public and `Clone`, so a plan taken from `resolve()` and
        // edited reaches `build()` without having passed the index's gate. The
        // name composes the cache path the downloaded bytes are published at,
        // before anything has checked what they are.
        let mut plan = resolved_plan();
        plan.packages[0].name = "../../escaped".to_string();
        let reason = refuses_plan(plan, |builder| builder);
        assert!(reason.contains("addressed by"), "{reason}");
    }

    #[test]
    fn a_plan_entry_no_index_could_have_published_is_refused_at_build() {
        // The same gates a document passes as it is read, for a `Plan` edited
        // in code: an entry's architecture is written into the installed
        // database as it stands, and its identity is compared exactly.
        let mut plan = resolved_plan();
        plan.packages[0].architecture = "aarch64".to_string();
        let reason = refuses_plan(plan, |builder| builder);
        assert!(reason.contains("aarch64"), "{reason}");

        let mut plan = resolved_plan();
        plan.packages[0].architecture = "noarch".to_string();
        Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror("http://mirror.invalid/alpine")
            .extract_only(true)
            .fetcher(canned())
            .plan(plan)
            .build()
            .expect("noarch belongs to every architecture");

        let mut plan = resolved_plan();
        plan.packages[0].control_identity = "Q1short=".to_string();
        let reason = refuses_plan(plan, |builder| builder);
        assert!(reason.contains("control identity"), "{reason}");
    }

    #[test]
    fn a_plan_beside_a_resolution_of_its_own_is_refused() {
        // Each of these describes a resolution, and a plan is one already; the
        // bootstrap would install the plan and silently drop the rest.
        for (what, configure) in [
            (
                "include",
                Box::new(|builder: AlpineBuilder| builder.include(["busybox"]))
                    as Box<dyn FnOnce(AlpineBuilder) -> AlpineBuilder>,
            ),
            (
                "exclude",
                Box::new(|builder: AlpineBuilder| builder.exclude(["busybox"])),
            ),
            (
                "pin",
                Box::new(|builder: AlpineBuilder| builder.pin(resolved_plan())),
            ),
        ] {
            let reason = refuses_plan(resolved_plan(), configure);
            assert!(reason.contains(what), "{what}: {reason}");
            assert!(reason.contains("drop one of the two"), "{what}: {reason}");
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

    /// A base recording busybox, laid out merged-usr: its `lib`, the
    /// database's directory among it, is a link to `usr/lib`.
    fn merged_usr_base(scratch: &Scratch) -> PathBuf {
        let base = base_recording(scratch, "base", &[("busybox", "1.37.0-r30", "p:/bin/sh")]);
        std::fs::create_dir(base.join("usr")).expect("the base is laid out");
        std::fs::rename(base.join("lib"), base.join("usr/lib")).expect("the base is laid out");
        std::os::unix::fs::symlink("usr/lib", base.join("lib")).expect("a link");
        base
    }

    #[test]
    fn an_increment_over_a_merged_usr_base_keeps_the_bases_links() {
        // musl ships `lib/ld-musl-x86_64.so.1`. Over a base whose `lib` is a
        // link to `usr/lib`, as a merged-usr root's is, the loader belongs at
        // `usr/lib` in the upper, and so does the database `apk` reads at
        // `lib/apk/db`; a real `lib` directory in the upper would hide the
        // base's link, and everything else the base keeps under `usr/lib`,
        // from the merged view.
        let scratch = Scratch::new("alpine-layered-merged-usr");
        let mirror = published(&scratch, &[("musl-1.2.5-r23.apk", fixtures::MUSL)]);
        let base = merged_usr_base(&scratch);
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

        assert_eq!(
            std::fs::read_link(upper.join("lib")).expect("the base's link is kept"),
            Path::new("usr/lib"),
        );
        assert!(upper.join("usr/lib/ld-musl-x86_64.so.1").is_file());
        assert_eq!(
            std::fs::read_link(upper.join("usr/lib/libc.musl-x86_64.so.1"))
                .expect("musl's own link"),
            Path::new("ld-musl-x86_64.so.1"),
        );
        // The database records the path as the package spells it, and is
        // written where the merged view reads it.
        let installed = std::fs::read_to_string(upper.join("usr/lib/apk/db/installed"))
            .expect("the merged database is written through the link");
        assert!(installed.contains("\nP:musl\n"), "{installed}");
        assert!(
            installed.contains("\nF:lib\nR:ld-musl-x86_64.so.1\n"),
            "{installed}"
        );
        assert!(installed.contains("P:busybox\n"), "{installed}");
        // The base was only read.
        assert!(!base.join("usr/lib/ld-musl-x86_64.so.1").exists());
        drop(layer);
    }

    #[test]
    fn an_increment_that_ships_nothing_under_lib_writes_its_database_through_the_link() {
        // alpine-keys ships under `etc` and `usr/share` alone, so no entry of
        // the increment's carries the base's `lib` link up. The database
        // written afterwards still goes where the merged view reads it.
        let scratch = Scratch::new("alpine-layered-database");
        let mirror = published(
            &scratch,
            &[("alpine-keys-2.6-r0.apk", fixtures::ALPINE_KEYS)],
        );
        let base = merged_usr_base(&scratch);
        let upper = scratch.join("upper");

        let layer = Alpine::builder("v3.23")
            .architecture("x86_64")
            .mirror(&mirror)
            .base_layer(&base)
            .include(["alpine-keys"])
            .extract_only(true)
            .build()
            .expect("the bootstrap configures")
            .stage_layer(&upper)
            .expect("the increment stages");

        assert_eq!(
            std::fs::read_link(upper.join("lib")).expect("the base's link is kept"),
            Path::new("usr/lib"),
        );
        let installed = std::fs::read_to_string(upper.join("usr/lib/apk/db/installed"))
            .expect("the merged database is written through the link");
        assert!(installed.contains("\nP:alpine-keys\n"), "{installed}");
        drop(layer);
    }
}
