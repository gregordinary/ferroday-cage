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
//! [`Debian::resolve`] reports the resolved package set without downloading,
//! for previewing a bootstrap or keying a build cache on it,
//! [`DebianBuilder::pre_configure_overlay`] lays caller configuration into the
//! rootfs before its maintainer scripts run, and [`Pool`] writes a local
//! trusted pool a later bootstrap resolves against.
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
mod fetch;
mod http;
mod index;
mod layer;
mod plan;
mod pool;
mod release;
mod repository;
mod resolve;
mod version;

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub use fetch::{Fetch, FetchError, FetchRequest};
pub use http::HttpFetch;
pub use index::{Priority, build_depend_names};
pub use layer::BuildLayer;
pub use plan::{Plan, PlannedPackage};
pub use pool::Pool;
pub use repository::{Repository, RepositoryBuilder};

use super::extract::Extraction;
use super::{ProvisionError, ProvisionEvent, ProvisionRequest, Provisioner, io_error};
use crate::IdentityMap;
use crate::status::ExitStatus;
use bootstrap::Installable;
use index::{Index, Package};
use release::{Keyring, Release};

/// The Debian archive keyring shipped with the crate, the binary
/// `debian-archive-keyring`. A caller can substitute their own with
/// [`DebianBuilder::keyring`].
const EMBEDDED_KEYRING: &[u8] = include_bytes!("keyring/debian-archive-keyring.gpg");

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
    /// The archive sources, the primary at index zero followed by any
    /// additional repositories, merged into one resolution.
    repositories: Vec<Repository>,
    fetcher: Box<dyn Fetch + 'a>,
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
            base_priority: Priority::Required,
            includes: Vec::new(),
            excludes: Vec::new(),
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
    pub fn resolve(&mut self) -> Result<Plan, DebianError> {
        self.resolve_reporting(&mut |_| {})
    }

    /// The body of [`resolve`](Self::resolve), reporting to `progress`.
    fn resolve_reporting(
        &mut self,
        progress: &mut dyn FnMut(DebianEvent<'_>),
    ) -> Result<Plan, DebianError> {
        let packages = resolve_packages(
            self.fetcher.as_mut(),
            &self.repositories,
            &self.architecture,
            self.base_priority,
            &self.includes,
            &self.excludes,
            progress,
        )?;
        Ok(Plan::project(&self.suite, &self.architecture, &packages))
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
        self.resolve_layer_reporting(&mut |_| {})
    }

    /// The body of [`resolve_layer`](Self::resolve_layer), reporting to
    /// `progress`.
    fn resolve_layer_reporting(
        &mut self,
        progress: &mut dyn FnMut(DebianEvent<'_>),
    ) -> Result<Plan, DebianError> {
        let Some(base) = self.base_layer.as_deref() else {
            return Err(DebianError::Config {
                reason: "resolve_layer requires a base layer set with DebianBuilder::base_layer"
                    .to_string(),
            });
        };
        let assume_installed = layer::read_installed_set(base)?;

        let packages = resolve_delta(
            self.fetcher.as_mut(),
            &self.repositories,
            &self.architecture,
            &self.includes,
            &self.excludes,
            &assume_installed,
            progress,
        )?;
        Ok(Plan::project(&self.suite, &self.architecture, &packages))
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
        self.stage_layer_reporting(upper.as_ref(), &mut |_| {}, &mut || false)
    }

    /// The body of [`stage_layer`](Self::stage_layer), reporting to `progress`.
    fn stage_layer_reporting(
        &mut self,
        upper: &Path,
        progress: &mut dyn FnMut(DebianEvent<'_>),
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<BuildLayer, ProvisionError> {
        // A base layer is required; the increment has nothing to layer over
        // otherwise.
        let Some(base) = self.base_layer.as_deref() else {
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
        let assume_installed = layer::read_installed_set(base).map_err(wrap)?;

        // Create the upper and refuse a host that cannot establish an
        // unprivileged overlay on its filesystem, before any download — the
        // overlay preflight the primitive would make at cage-build time, hoisted
        // ahead of the work. The probe runs on the upper's parent, its own
        // filesystem, so its scratch files land beside the upper.
        std::fs::create_dir_all(upper)
            .map_err(|err| io_error("creating the overlay upper", upper, err))?;
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
        // upper. A sibling, not a child: an extracted package's entries land
        // under the upper, so a cache beneath it could be overwritten before it
        // is read.
        let archives_host = match self.cache_dir.as_deref() {
            Some(dir) => dir.to_path_buf(),
            None => {
                let mut sibling = upper.as_os_str().to_os_string();
                sibling.push(".fcage-debs");
                PathBuf::from(sibling)
            }
        };

        // Resolve the increment against the base's installed set, download it,
        // extract it into the upper, and configure it through the overlay.
        let packages = resolve_delta(
            self.fetcher.as_mut(),
            &self.repositories,
            &self.architecture,
            &self.includes,
            &self.excludes,
            &assume_installed,
            progress,
        )
        .map_err(wrap)?;
        // An empty increment — every requested package already in the base —
        // needs no download or configuration; the build root is the base as it
        // stands. Skipping here also keeps dpkg from being handed an empty
        // unpack wave, which it refuses.
        if packages.is_empty() {
            return Ok(BuildLayer::new(upper, self.identity_map.clone()));
        }
        let installables = acquire_debs(
            self.fetcher.as_mut(),
            &self.repositories,
            &packages,
            &archives_host,
            progress,
            cancelled,
        )?;
        let statoverride = extract_packages(
            upper,
            &self.architecture,
            &installables,
            &archives_host,
            progress,
            cancelled,
        )?;

        let env = maintainer_env();
        bootstrap::configure_delta(
            base,
            upper,
            &archives_host,
            &installables,
            &statoverride,
            &self.identity_map,
            &env,
            self.overlay.as_deref(),
            progress,
        )
        .map_err(wrap)?;

        // The read-only archives bind left an empty mount point in the upper.
        let _ = std::fs::remove_dir_all(upper.join(bootstrap::ARCHIVES.trim_start_matches('/')));
        if self.cache_dir.is_none() {
            let _ = std::fs::remove_dir_all(&archives_host);
        }

        Ok(BuildLayer::new(upper, self.identity_map.clone()))
    }
}

/// Builder for a [`Debian`] provisioner.
pub struct DebianBuilder<'a> {
    suite: String,
    architecture: Option<String>,
    mirror: Option<String>,
    mirror_fallbacks: Vec<String>,
    components: Vec<String>,
    base_priority: Priority,
    includes: Vec<String>,
    excludes: Vec<String>,
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
    pub fn mirror(mut self, mirror: impl Into<String>) -> Self {
        self.mirror = Some(mirror.into());
        self
    }

    /// Adds a backstop URL for the primary mirror, tried in order after it when
    /// a fetch reports the resource missing or fails at the transport.
    ///
    /// This expresses a live primary mirror with a `snapshot.debian.org`
    /// fallback for a version that has rotated off the live pool. The fallback
    /// is a fetch-time concern only: the finished rootfs's `sources.list` names
    /// the primary mirror, not the backstop. A repository whose backstop is a
    /// snapshot normally also sets
    /// [`allow_stale_release`](Self::allow_stale_release), the snapshot's
    /// release being expired by design.
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
        self.base_priority = priority;
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
    /// a temporary directory and discarded.
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
    /// drops the only authenticity check, [`build`](Self::build) refuses it
    /// against an `http://` mirror, whose transport offers no authenticity in
    /// its place.
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
    pub fn build(self) -> Result<Debian<'a>, DebianError> {
        if self.suite.trim().is_empty() {
            return Err(DebianError::Config {
                reason: "no suite was given".to_string(),
            });
        }
        let architecture = self.architecture.unwrap_or_else(arch::host_architecture);
        let keyring = match &self.keyring_path {
            Some(path) => std::fs::read(path).map_err(|source| DebianError::Io {
                op: "reading the keyring",
                path: path.clone(),
                source,
            })?,
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

        Ok(Debian {
            suite: self.suite,
            architecture,
            base_priority: self.base_priority,
            includes: self.includes,
            excludes: self.excludes,
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
        // Every event goes to the run's observer, wrapped in the shared
        // vocabulary, and cancellation comes from the same place — the one
        // channel every provisioner reports through.
        self.provision_reporting(
            request.staging(),
            &mut |event| request.report(ProvisionEvent::Debian(&event)),
            &mut || request.cancelled(),
        )
    }
}

impl<'a> Debian<'a> {
    /// Binds a progress sink for one run, returning a provisioner that reports
    /// to it.
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
    pub fn observe<'o>(&'o mut self, sink: &'o mut dyn FnMut(DebianEvent<'_>)) -> Observed<'o, 'a> {
        Observed { debian: self, sink }
    }

    /// The body of [`Provisioner::provision`], reporting to `progress` and
    /// stopping when `cancelled` answers `true`.
    fn provision_reporting(
        &mut self,
        staging: &Path,
        progress: &mut dyn FnMut(DebianEvent<'_>),
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<(), ProvisionError> {
        bootstrap_suite(
            staging,
            &self.architecture,
            &self.repositories,
            self.base_priority,
            &self.includes,
            &self.excludes,
            self.extract_only,
            &self.identity_map,
            self.cache_dir.as_deref(),
            self.overlay.as_deref(),
            self.fetcher.as_mut(),
            progress,
            cancelled,
        )
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
    sink: &'o mut dyn FnMut(DebianEvent<'_>),
}

impl Observed<'_, '_> {
    /// Resolves the install plan, reporting progress. See [`Debian::resolve`].
    pub fn resolve(&mut self) -> Result<Plan, DebianError> {
        self.debian.resolve_reporting(&mut *self.sink)
    }

    /// Resolves a layered build's increment, reporting progress. See
    /// [`Debian::resolve_layer`].
    pub fn resolve_layer(&mut self) -> Result<Plan, DebianError> {
        self.debian.resolve_layer_reporting(&mut *self.sink)
    }

    /// Stages a layered build's increment, reporting progress. See
    /// [`Debian::stage_layer`].
    pub fn stage_layer(&mut self, upper: impl AsRef<Path>) -> Result<BuildLayer, ProvisionError> {
        self.debian
            .stage_layer_reporting(upper.as_ref(), &mut *self.sink, &mut || false)
    }
}

impl Provisioner for Observed<'_, '_> {
    /// Reports to the sink bound here rather than to the run's observer: the
    /// caller chose the richer, Debian-specific channel by using
    /// [`Debian::observe`]. Cancellation still comes from the run, so a
    /// [`Provision::observe`](crate::provision::Provision::observe) observer
    /// can stop a bootstrap it is not reporting on.
    fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
        self.debian
            .provision_reporting(request.staging(), &mut *self.sink, &mut || {
                request.cancelled()
            })
    }
}

/// The whole bootstrap, as a free function over borrowed configuration.
#[allow(clippy::too_many_arguments)]
fn bootstrap_suite(
    staging: &Path,
    architecture: &str,
    repositories: &[Repository],
    base_priority: Priority,
    includes: &[String],
    excludes: &[String],
    extract_only: bool,
    identity_map: &IdentityMap,
    cache_dir: Option<&Path>,
    overlay: Option<&Path>,
    fetcher: &mut dyn Fetch,
    progress: &mut dyn FnMut(DebianEvent<'_>),
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<(), ProvisionError> {
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

    let packages = resolve_packages(
        fetcher,
        repositories,
        architecture,
        base_priority,
        includes,
        excludes,
        progress,
    )
    .map_err(wrap)?;

    let archives_host = match cache_dir {
        Some(dir) => dir.to_path_buf(),
        // A sibling of the staging root, not a child of it: an extracted
        // package's entries land under `staging`, so a cache beneath `staging`
        // could be overwritten before it is read, but a sibling is out of the
        // extraction's contained reach.
        None => {
            let mut sibling = staging.as_os_str().to_os_string();
            sibling.push(".fcage-debs");
            PathBuf::from(sibling)
        }
    };
    let installables = acquire_debs(
        fetcher,
        repositories,
        &packages,
        &archives_host,
        progress,
        cancelled,
    )?;

    let statoverride = stage_extract(
        staging,
        architecture,
        &installables,
        &archives_host,
        progress,
        cancelled,
    )?;

    if !extract_only {
        let env = maintainer_env();
        bootstrap::configure(
            staging,
            &archives_host,
            &installables,
            &statoverride,
            identity_map,
            &env,
            repositories,
            overlay,
            progress,
        )
        .map_err(wrap)?;
        // The read-only bind mount left an empty mount point in the rootfs.
        let _ = std::fs::remove_dir_all(staging.join(bootstrap::ARCHIVES.trim_start_matches('/')));
    }

    if cache_dir.is_none() {
        let _ = std::fs::remove_dir_all(&archives_host);
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
#[allow(clippy::too_many_arguments)]
fn resolve_packages(
    fetcher: &mut dyn Fetch,
    repositories: &[Repository],
    architecture: &str,
    base_priority: Priority,
    includes: &[String],
    excludes: &[String],
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<Vec<Package>, DebianError> {
    let index = merged_index(fetcher, repositories, architecture, progress)?;

    progress(DebianEvent::Resolving);
    let mut base = index.base_seed(base_priority);
    base.push("apt".to_string());
    let packages =
        resolve::resolve(&index, &base, includes, excludes).map_err(DebianError::from)?;

    Ok(emit_resolved(
        repositories,
        architecture,
        packages,
        progress,
    ))
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
    fetcher: &mut dyn Fetch,
    repositories: &[Repository],
    architecture: &str,
    includes: &[String],
    excludes: &[String],
    assume_installed: &HashSet<String>,
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<Vec<Package>, DebianError> {
    let index = merged_index(fetcher, repositories, architecture, progress)?;

    progress(DebianEvent::Resolving);
    let packages = resolve::resolve_seeded(&index, &[], includes, excludes, assume_installed)
        .map_err(DebianError::from)?;

    Ok(emit_resolved(
        repositories,
        architecture,
        packages,
        progress,
    ))
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
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<Index, DebianError> {
    // Each repository contributes one text block per component, tagged with the
    // repository's index so the merged index knows where each package came from.
    let mut index_inputs: Vec<(usize, String)> = Vec::new();
    for (origin, repository) in repositories.iter().enumerate() {
        let release = fetch_release(fetcher, repository, progress)?;
        release
            .check(
                &repository.suite,
                architecture,
                &repository.components,
                repository.require_fresh(),
            )
            .map_err(DebianError::from)?;
        let text = fetch_index(fetcher, repository, architecture, &release, progress)?;
        index_inputs.push((origin, text));
    }

    Ok(Index::merge(
        index_inputs
            .iter()
            .map(|(origin, text)| (*origin, text.as_str())),
        architecture,
    ))
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
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Vec<Package> {
    let suite = repositories
        .first()
        .map_or("", |repository| repository.suite.as_str());
    let plan = Plan::project(suite, architecture, &packages);
    progress(DebianEvent::Resolved { plan: &plan });
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
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<Release, DebianError> {
    let suite = &repository.suite;
    let body = match repository.keyring() {
        None => {
            let suffix = format!("dists/{suite}/Release");
            let bytes = fetch_from_mirrors(fetcher, &repository.mirrors, &suffix, progress)?;
            String::from_utf8(bytes).map_err(|_| {
                DebianError::from(release::ReleaseError::Release(
                    "Release is not UTF-8".to_string(),
                ))
            })?
        }
        Some(keyring_bytes) => {
            let suffix = format!("dists/{suite}/InRelease");
            let bytes = fetch_from_mirrors(fetcher, &repository.mirrors, &suffix, progress)?;
            let keyring = Keyring::parse(keyring_bytes).map_err(DebianError::from)?;
            keyring
                .verify(&bytes, !repository.allow_stale)
                .map_err(DebianError::from)?
        }
    };
    Release::parse(&body).map_err(DebianError::from)
}

/// Fetches, verifies, and decompresses a repository's package index for every
/// component, returning the concatenated text ready to merge.
fn fetch_index(
    fetcher: &mut dyn Fetch,
    repository: &Repository,
    architecture: &str,
    release: &Release,
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<String, DebianError> {
    let mut merged = String::new();
    for component in &repository.components {
        let text = fetch_component_index(
            fetcher,
            repository,
            architecture,
            component,
            release,
            progress,
        )?;
        merged.push_str(&text);
        if !merged.ends_with('\n') {
            merged.push('\n');
        }
    }
    Ok(merged)
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
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<String, DebianError> {
    // Prefer the smallest available index; every candidate is verified against
    // the release digest, so the choice is trust-neutral. Which compressions
    // exist is a property of the release, the same across every mirror.
    let candidates: Vec<(String, &str)> = ["Packages.xz", "Packages.gz", "Packages"]
        .iter()
        .filter_map(|suffix| {
            let rel = format!("{component}/binary-{architecture}/{suffix}");
            release.digest(&rel).map(|(_, digest)| (rel, digest))
        })
        .collect();
    if candidates.is_empty() {
        return Err(DebianError::Index {
            reason: format!("the release lists no index for component {component}"),
        });
    }

    let suite = &repository.suite;
    let mut last_missing = None;
    for mirror in &repository.mirrors {
        for (rel, digest) in &candidates {
            let url = if release.acquire_by_hash() {
                format!(
                    "{}/dists/{suite}/{component}/binary-{architecture}/by-hash/SHA256/{digest}",
                    mirror.trim_end_matches('/'),
                )
            } else {
                format!("{}/dists/{suite}/{rel}", mirror.trim_end_matches('/'))
            };
            progress(DebianEvent::Fetching { url: &url });
            match fetch_bytes(fetcher, &url) {
                Ok(bytes) => {
                    verify_digest(rel, &bytes, digest)?;
                    return decompress_index(rel, &bytes);
                }
                Err(err) if is_failover(&err) => {
                    last_missing = Some(err);
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
    }
    Err(last_missing.unwrap_or_else(|| DebianError::Index {
        reason: format!("no mirror served an index for component {component}"),
    }))
}

/// Fetches `suffix` (a mirror-relative path) from the first mirror that serves
/// it, advancing past a mirror that reports the resource missing or fails at
/// the transport, and returning the last such error when every mirror is
/// exhausted.
fn fetch_from_mirrors(
    fetcher: &mut dyn Fetch,
    mirrors: &[String],
    suffix: &str,
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<Vec<u8>, DebianError> {
    let mut last_missing = None;
    for mirror in mirrors {
        let url = format!(
            "{}/{}",
            mirror.trim_end_matches('/'),
            suffix.trim_start_matches('/'),
        );
        progress(DebianEvent::Fetching { url: &url });
        match fetch_bytes(fetcher, &url) {
            Ok(bytes) => return Ok(bytes),
            Err(err) if is_failover(&err) => {
                last_missing = Some(err);
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_missing.unwrap_or_else(|| {
        DebianError::Fetch(FetchError::NotFound {
            url: suffix.to_string(),
        })
    }))
}

/// Whether an error is one the mirror walk advances past: a missing resource,
/// or a transport failure. A digest or signature failure is not — it signals
/// corruption or tampering and stops the bootstrap.
fn is_failover(err: &DebianError) -> bool {
    matches!(
        err,
        DebianError::Fetch(FetchError::NotFound { .. } | FetchError::Io { .. })
    )
}

/// Downloads (or reuses from cache) and verifies every selected package.
///
/// Each package's bytes are fetched from its own repository's mirrors — the
/// repository the merged index retained its winning version from — walking that
/// mirror list on a missing or failed URL, so a version that has rotated off a
/// live pool is served by the repository's snapshot backstop.
fn acquire_debs(
    fetcher: &mut dyn Fetch,
    repositories: &[Repository],
    packages: &[Package],
    archives_host: &Path,
    progress: &mut dyn FnMut(DebianEvent<'_>),
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<Vec<Installable>, ProvisionError> {
    std::fs::create_dir_all(archives_host).map_err(|source| {
        wrap(DebianError::Io {
            op: "creating the package directory",
            path: archives_host.to_path_buf(),
            source,
        })
    })?;

    let mut installables = Vec::with_capacity(packages.len());
    for (position, package) in packages.iter().enumerate() {
        // A package boundary: whatever has been downloaded is complete, and
        // the staging tree is untouched, so stopping here costs nothing.
        if cancelled() {
            return Err(ProvisionError::Cancelled);
        }
        let filename = format!("{}.deb", package.sha256);
        let dest = archives_host.join(&filename);

        // Whether the cache entry is intact, decided by streaming its digest:
        // validating a cached kernel package costs the memory of validating a
        // shell script, the same property `Pool::publish` was reworked for. A
        // corrupt or truncated entry is simply re-downloaded.
        let cached = std::fs::File::open(&dest)
            .and_then(|mut file| deb::sha256_stream(&mut file))
            .is_ok_and(|(digest, _)| digest == package.sha256);
        if !cached {
            progress(DebianEvent::Downloading {
                package: &package.name,
                index: position + 1,
                total: packages.len(),
            });
            let mirrors = &repositories[package.origin].mirrors;
            let bytes =
                fetch_from_mirrors(fetcher, mirrors, &package.filename, progress).map_err(wrap)?;
            verify_digest(&package.filename, &bytes, &package.sha256).map_err(wrap)?;
            write_atomically(&dest, &bytes).map_err(|source| {
                wrap(DebianError::Io {
                    op: "writing a package",
                    path: dest.clone(),
                    source,
                })
            })?;
        }

        installables.push(Installable {
            name: package.name.clone(),
            deb_path: format!("{}/{filename}", bootstrap::ARCHIVES),
            sha256: package.sha256.clone(),
        });
    }
    Ok(installables)
}

/// Stage one: lay out the merged-usr farm and every package's files, and
/// initialize the dpkg database.
///
/// Returns the derived statoverride content — one `root root <mode> <path>`
/// line per file a package ships with non-root ownership. The file is not
/// written here: dpkg rejects a statoverride naming `root` until
/// `base-passwd` has created `/etc/passwd`, so configuration writes it after
/// the base-passwd wave. An extract-only rootfs, which never configures,
/// does not carry it.
fn stage_extract(
    staging: &Path,
    architecture: &str,
    installables: &[Installable],
    archives_host: &Path,
    progress: &mut dyn FnMut(DebianEvent<'_>),
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<String, ProvisionError> {
    let statoverride = extract_packages(
        staging,
        architecture,
        installables,
        archives_host,
        progress,
        cancelled,
    )?;
    init_dpkg_database(staging)?;
    Ok(statoverride)
}

/// Lays out the merged-usr farm and every package's files into `staging`,
/// returning the derived statoverride content.
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
    progress: &mut dyn FnMut(DebianEvent<'_>),
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<String, ProvisionError> {
    create_merged_usr(staging, architecture)?;

    let mut extraction = Extraction::new(staging)?;
    let mut statoverride = String::new();
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
        if cancelled() {
            return Err(ProvisionError::Cancelled);
        }
        progress(DebianEvent::Extracting {
            package: &installable.name,
        });
        let filename = installable
            .deb_path
            .rsplit('/')
            .next()
            .expect("the deb path has a file name");
        let deb = std::fs::read(archives_host.join(filename))
            .map_err(|err| io_error("reading the package", &archives_host.join(filename), err))?;
        // Re-verify against the digest the package was acquired under, rather
        // than trust the bytes on disk: the download and this read are separate
        // steps, and the cache may share a filesystem with untrusted writers.
        let actual = deb::sha256_hex(&deb);
        if actual != installable.sha256 {
            return Err(wrap(DebianError::HashMismatch {
                path: filename.to_string(),
                expected: installable.sha256.clone(),
                actual,
            }));
        }
        deb::extract_deb(
            &installable.name,
            &deb,
            &mut extraction,
            &mut |entry, components| {
                if entry.uid != 0 || entry.gid != 0 {
                    if components
                        .iter()
                        .any(|component| component.contains(&b'\n'))
                    {
                        malformed.get_or_insert_with(|| components.to_vec());
                        return Ok(());
                    }
                    statoverride.push_str(&format!(
                        "root root {:o} {}\n",
                        entry.mode,
                        absolute_path(components),
                    ));
                }
                Ok(())
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
        std::fs::create_dir_all(&target).map_err(|err| io_error("creating", &target, err))?;
        let link = staging.join(dir);
        if !arch::exists(&link) {
            std::os::unix::fs::symlink(format!("usr/{dir}"), &link)
                .map_err(|err| io_error("linking", &link, err))?;
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
        std::fs::create_dir_all(&path).map_err(|err| io_error("creating", &path, err))?;
    }
    for file in ["status", "available"] {
        let path = dpkg.join(file);
        if !path.exists() {
            std::fs::write(&path, "").map_err(|err| io_error("writing", &path, err))?;
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

/// Fetches a URL fully into memory.
fn fetch_bytes(fetcher: &mut dyn Fetch, url: &str) -> Result<Vec<u8>, DebianError> {
    let mut bytes = Vec::new();
    fetcher.fetch(&FetchRequest::new(url), &mut bytes)?;
    Ok(bytes)
}

/// Verifies bytes against an expected SHA-256, naming the resource on
/// mismatch.
fn verify_digest(path: &str, bytes: &[u8], expected: &str) -> Result<(), DebianError> {
    let actual = deb::sha256_hex(bytes);
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
    let head = super::compress::sniff_head(&mut cursor).map_err(|source| DebianError::Io {
        op: "reading the index",
        path: PathBuf::from(path),
        source,
    })?;
    let mut reader =
        super::compress::decompress(&head, cursor).map_err(|_| DebianError::Index {
            reason: format!("{path} is not a valid index"),
        })?;
    let mut text = String::new();
    reader
        .read_to_string(&mut text)
        .map_err(|source| DebianError::Io {
            op: "decompressing the index",
            path: PathBuf::from(path),
            source,
        })?;
    Ok(text)
}

/// The path of a staging file for `dest`: a hidden name beside it, unique to
/// the call that asked for it.
///
/// The name is unique so that concurrent writers of one destination — provisions
/// sharing a package cache, publishers sharing a pool — each stage their own
/// file and each publish it with a rename. A staging name shared between them
/// would let one writer's rename consume the other's file, failing the second
/// with `ENOENT`.
///
/// The staging file is a sibling of the destination, so the rename that
/// publishes it stays within one directory and one filesystem.
fn staging_path(dest: &Path) -> PathBuf {
    let dir = dest.parent().unwrap_or(Path::new("."));
    let name = dest.file_name().unwrap_or(dest.as_os_str());
    let mut staging = std::ffi::OsString::from(".");
    staging.push(name);
    staging.push(format!(".{}.partial", crate::host::unique_hex()));
    dir.join(staging)
}

/// Writes bytes to `dest` atomically, via a staging file in its directory and a
/// rename onto the destination.
///
/// The staging file is created exclusively, which establishes that the name is
/// this call's alone and refuses a symlink pre-planted at it rather than writing
/// through it. [`staging_path`] describes why the name is unique per call.
///
/// The staging file is not synced before the rename. Both callers verify what
/// they read against a digest, so an entry left short by a crash is rejected
/// and written again, which is cheaper than syncing every write against a
/// failure that costs only a repeat.
///
/// Errors name the staging file only when the failure is the staging file's
/// own; the caller wraps them against the destination it asked for.
pub(super) fn write_atomically(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = staging_path(dest);

    // Only a failure after this point removes the staging file: the exclusive
    // create is what establishes that the name is this call's alone, so a
    // cleanup ahead of it could delete a file the caller does not own.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;

    // Leaving a staging file behind would accumulate in a directory that
    // outlives the call, since no later one reuses the name.
    if let Err(err) = file.write_all(bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    drop(file);

    std::fs::rename(&tmp, dest).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
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

/// A progress event from a Debian bootstrap.
#[derive(Debug)]
#[non_exhaustive]
pub enum DebianEvent<'a> {
    /// A URL is being fetched.
    #[non_exhaustive]
    Fetching {
        /// The URL.
        url: &'a str,
    },
    /// The dependency closure is being resolved.
    Resolving,
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

/// A standard stream of an in-cage command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
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
    /// The archive signature did not verify.
    #[non_exhaustive]
    Signature {
        /// Why verification failed.
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
                write!(f, "the archive signature did not verify: {reason}")
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

impl From<resolve::ResolveError> for DebianError {
    fn from(err: resolve::ResolveError) -> Self {
        DebianError::Resolve {
            reason: err.to_string(),
        }
    }
}

impl From<release::ReleaseError> for DebianError {
    fn from(err: release::ReleaseError) -> Self {
        match err {
            release::ReleaseError::Keyring(reason) | release::ReleaseError::Signature(reason) => {
                DebianError::Signature { reason }
            }
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

    fn tempdir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ferroday-cage-debian-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn concurrent_writes_of_one_cache_entry_all_succeed() {
        // The shared-cache race: several provisions download the same package
        // at once and publish it under the same content-addressed name. Every
        // writer must succeed, and the published bytes must be the package.
        let dir = tempdir("cache-race");
        let bytes = vec![0xab; 64 * 1024];
        let writers: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.clone();
                let bytes = bytes.clone();
                std::thread::spawn(move || write_atomically(&dir.join("entry.deb"), &bytes))
            })
            .collect();
        for writer in writers {
            writer.join().unwrap().expect("a concurrent write succeeds");
        }
        assert_eq!(std::fs::read(dir.join("entry.deb")).unwrap(), bytes);

        // Nothing is left staged: the cache holds the published entry alone.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "entry.deb")
            .collect();
        assert!(leftovers.is_empty(), "staging files remain: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_publish_leaves_nothing_staged() {
        // Staging names are unique per call, so a failure that left one behind
        // would accumulate in a cache directory rather than being reused. The
        // publishing rename is made to fail by occupying the destination with
        // a non-empty directory.
        let dir = tempdir("cache-publish-failure");
        std::fs::create_dir(dir.join("entry.deb")).unwrap();
        std::fs::write(dir.join("entry.deb").join("occupant"), b"").unwrap();
        assert!(write_atomically(&dir.join("entry.deb"), b"payload").is_err());
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "entry.deb")
            .collect();
        assert!(leftovers.is_empty(), "staging files remain: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
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
}
