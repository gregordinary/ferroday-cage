//! Stage two: configuring the unpacked packages by running dpkg in the cage.
//!
//! With every package's files laid out in the staging tree, the packages
//! still have to be registered and configured — their maintainer scripts run
//! — for the rootfs to hold a consistent dpkg database. That is what dpkg
//! does, and this library is an unprivileged chroot, so dpkg runs inside a
//! [`Cage`] whose root is the staging tree. The wave sequence follows
//! `debootstrap`'s second stage.
//!
//! The configured identity map decides how Debian's ownership expectations
//! are met. Under a range map the system ids are real: every `chown` a
//! maintainer script or a compiled tool performs genuinely happens, and the
//! cages need no accompaniment. Under the default single-identity map no id
//! but root exists, so the host-side preparation between waves reconciles
//! the difference — a statoverride seed, ownership stubs, and shadow-file
//! pre-creation, each documented where it happens — at the cost of
//! flattening the affected ownership to root in the finished tree.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::index::parse_stanzas;
use super::repository::{Repository, Trust};
use super::{DebianError, DebianEvent, Stream};
use crate::{Cage, CageBuilder, IdentityMap, Observer, Stdio};

/// The core packages configured before the rest, in dependency order, so the
/// base system (accounts, directories, the C library, dpkg itself) is in
/// place before other packages' maintainer scripts run. `mawk` is installed
/// last, on its own, once the temporary `awk` symlink is removed.
const CORE_ORDER: [&str; 5] = ["base-passwd", "base-files", "dpkg", "libc6", "perl-base"];

/// The commands whose direct invocation the single-identity map breaks: a
/// maintainer script's `chown root:mail` names a group that is not mapped and
/// fails. They are replaced with a stub that succeeds while packages
/// configure, and restored afterward. A range map leaves the real tools in
/// place, because the chowns genuinely work there.
const OWNERSHIP_TOOLS: [&str; 2] = ["chown", "chgrp"];

/// The body of an ownership-tool stub: a shell script that succeeds and does
/// nothing. Also the marker that identifies a stub as one this bootstrap
/// wrote, so the restore can delete a stub it has no real tool to put back.
const OWNERSHIP_STUB: &str = "#!/bin/sh\nexit 0\n";

/// Where the primary repository's trust anchor is written in the finished
/// rootfs, and the `signed-by` its [`sources.list`](write_repository_sources)
/// references. A binary OpenPGP keyring here lets an in-rootfs `apt-get update`
/// verify the release without the `debian-archive-keyring` package, which the
/// base closure does not pull in.
pub(crate) const TRUST_ANCHOR: &str = "/usr/share/keyrings/debian-archive-keyring.gpg";

/// The mount point the downloaded packages are bound to inside the cage.
///
/// Deliberately not `/var/cache/apt/archives`: the `apt` package ships and
/// writes to that directory during its own unpack, and a read-only bind there
/// would block it. A neutral path keeps the archive cache a normal, writable
/// part of the rootfs.
pub(crate) const ARCHIVES: &str = "/fcage-debs";

/// A package to install: its name, the path to its `.deb` inside the cage, and
/// the SHA-256 the `.deb` was verified against, for re-verification on read.
pub(crate) struct Installable {
    pub name: String,
    pub deb_path: String,
    pub sha256: String,
}

/// The dpkg statoverride a bootstrap derives: one `<user> <group> <mode>
/// <path>` record per path a package ships with non-root ownership.
///
/// Records are keyed on the path, because dpkg treats two records for one path
/// as an unrecoverable fatal error: `dpkg-statoverride --list` aborts on the
/// duplicate, and so does every dpkg invocation the bootstrap makes after the
/// file is written, with a message that says nothing about which package
/// produced it. A closure reaches a duplicate honestly — two selected packages
/// shipping one path, since the resolver reads `Depends` and `Provides` and
/// never `Conflicts` or `Replaces`; a `data.tar` listing a path twice, which tar
/// permits; or an increment re-shipping a path its base already overrode — so
/// the duplicate is collapsed here rather than handed to dpkg.
///
/// The last record for a path wins, which is the extraction's own rule: a later
/// entry supersedes an earlier one, so the surviving record describes the file
/// that survived.
///
/// A record is held as its whole line, so one read back from a file dpkg or a
/// maintainer script wrote keeps the owner it names; only the derived ones are
/// `root root`. Rendering is in path order, so the file a bootstrap writes is a
/// function of what it extracted rather than of the order it extracted in.
#[derive(Default)]
pub(crate) struct StatOverride {
    records: BTreeMap<String, String>,
}

impl StatOverride {
    /// Records `path` as root-owned at `mode`, replacing any record already held
    /// for that path.
    pub(super) fn record(&mut self, mode: u32, path: String) {
        self.records
            .insert(path.clone(), format!("root root {mode:o} {path}"));
    }

    /// Reads the records an existing statoverride file holds.
    ///
    /// A line that is not a record — blank, or missing one of the four fields —
    /// is dropped rather than carried forward, since it is not something dpkg
    /// would read either.
    fn read(text: &str) -> StatOverride {
        let mut overrides = StatOverride::default();
        for line in text.lines() {
            if let Some(path) = record_path(line) {
                overrides.records.insert(path.to_string(), line.to_string());
            }
        }
        overrides
    }

    /// Lays `later`'s records over these, `later` winning wherever both name a
    /// path.
    fn layer(&mut self, later: &StatOverride) {
        for (path, record) in &later.records {
            self.records.insert(path.clone(), record.clone());
        }
    }

    /// The file's content: one newline-terminated record per line, in path
    /// order. Empty when nothing was recorded.
    pub(super) fn render(&self) -> String {
        let mut text = String::new();
        for record in self.records.values() {
            text.push_str(record);
            text.push('\n');
        }
        text
    }
}

/// The path a statoverride record names: everything after the user, group, and
/// mode fields, so a path containing a space survives.
///
/// Returns `None` for a line that does not carry all four fields.
fn record_path(line: &str) -> Option<&str> {
    let mut rest = line;
    for _ in 0..3 {
        rest = rest.split_once(' ')?.1;
    }
    (!rest.is_empty()).then_some(rest)
}

/// Configures every unpacked package, leaving a consistent dpkg database.
///
/// `env` is the maintainer-script environment; `repositories` compose the
/// `sources.list` and `sources.list.d` entries written into the finished
/// rootfs, each signed repository's keyring written there as its `signed-by`
/// trust anchor so the sources verify. `identity_map` is the map the cages run
/// under, deciding whether the single-identity ownership reconciliation happens
/// at all. `progress` receives dpkg's output.
#[allow(clippy::too_many_arguments)]
pub(crate) fn configure(
    staging: &Path,
    archives_host: &Path,
    installables: &[Installable],
    statoverride: &StatOverride,
    identity_map: &IdentityMap,
    env: &[(String, String)],
    repositories: &[Repository],
    overlay: Option<&Path>,
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<(), DebianError> {
    // Under a range map every id Debian assigns is real and every chown
    // works; the reconciliation below exists solely for the single-identity
    // map, where no id but root can be represented.
    let single = matches!(identity_map, IdentityMap::Single);

    // Suppress daemon startup and, under the single-identity map, neutralize
    // direct chown/chgrp for the whole configuration, before any maintainer
    // script runs.
    write_policy_rc_d(staging)?;
    if single {
        install_ownership_stubs(staging)?;
    }
    symlink_awk(staging)?;

    // base-passwd is configured first: it creates /etc/passwd, so the
    // statoverride can name `root` when it is written, which dpkg reads on
    // every subsequent invocation. A range map wants the packages' own
    // ownership and modes, so no override is seeded and the shadow files are
    // left for pwconv to create with their real root:shadow ownership.
    core_install(
        installables,
        "base-passwd",
        staging,
        archives_host,
        identity_map,
        env,
        progress,
    )?;
    if single {
        write_statoverride(staging, statoverride)?;
        precreate_shadow(staging)?;
    }

    // The rest of the base system.
    for name in &CORE_ORDER[1..] {
        core_install(
            installables,
            name,
            staging,
            archives_host,
            identity_map,
            env,
            progress,
        )?;
    }
    // The real mawk replaces the temporary awk symlink.
    remove_awk_symlink(staging)?;
    core_install(
        installables,
        "mawk",
        staging,
        archives_host,
        identity_map,
        env,
        progress,
    )?;

    // Unpack registers every package in the database and lays its files;
    // this re-lays coreutils, so the ownership stubs are reinstalled before
    // configuration runs the maintainer scripts.
    write_dselect_method(staging)?;
    let mut unpack: Vec<&str> = vec!["--force-depends", "--unpack"];
    unpack.extend(installables.iter().map(|p| p.deb_path.as_str()));
    run_dpkg(
        "unpack",
        staging,
        archives_host,
        identity_map,
        env,
        &unpack,
        progress,
    )?;

    if single {
        install_ownership_stubs(staging)?;
    }

    // Every package is now unpacked and no maintainer script has run. Lay the
    // caller's pre-configure overlay here, so it overwrites the packages' just-
    // unpacked files — a shipped conffile among them — and the configuration
    // wave's scripts read the injected values. Placing it before the unpack
    // wave instead would leave the files for dpkg to treat as conffile
    // conflicts; placing it after configuration would be too late to steer it.
    if let Some(overlay) = overlay {
        super::super::extract::overlay_tree(staging, overlay).map_err(DebianError::Overlay)?;
    }

    run_dpkg(
        "configure",
        staging,
        archives_host,
        identity_map,
        env,
        &[
            "--configure",
            "--pending",
            "--force-configure-any",
            "--force-depends",
        ],
        progress,
    )?;

    // Restore the real tools and remove the bootstrap-only files, then write
    // the finished rootfs's apt sources.
    if single {
        restore_ownership_stubs(staging)?;
    }
    remove_policy_rc_d(staging)?;
    write_repository_sources(staging, repositories)?;
    if single {
        write_apt_sandbox_user(staging)?;
    }

    verify_installed(
        staging,
        &installables
            .iter()
            .map(|p| p.name.clone())
            .collect::<Vec<_>>(),
    )
}

/// Configures the increment of a layered build over its base, leaving a
/// consistent merged dpkg database.
///
/// The increment's files are already extracted into `upper`; this registers and
/// configures its packages by running dpkg in a cage rooted on an overlay of the
/// pristine base (`lower`) and the increment (`upper`), so dpkg reads the base's
/// configured database — its installed set, its `base-passwd` accounts — and
/// lands the increment's state in the disposable upper, the base untouched.
///
/// It is the full bootstrap's [`configure`] restricted to the increment: no
/// base-system priming (base-passwd first, the awk shim, shadow pre-creation),
/// since the base already supplies all of it. Under the single-identity map it
/// still neutralizes `chown`/`chgrp` and seeds a merged statoverride, so a
/// maintainer script that assigns an id the map cannot represent succeeds; those
/// shims shadow the base's real tools through the overlay and are removed
/// afterward. `overlay_source` is the caller's pre-configure overlay, laid over
/// the upper between the unpack and configure waves exactly as for a full
/// bootstrap.
#[allow(clippy::too_many_arguments)]
pub(crate) fn configure_delta(
    lower: &Path,
    upper: &Path,
    archives_host: &Path,
    installables: &[Installable],
    statoverride: &StatOverride,
    identity_map: &IdentityMap,
    env: &[(String, String)],
    overlay_source: Option<&Path>,
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<(), DebianError> {
    let single = matches!(identity_map, IdentityMap::Single);

    // Suppress daemon startup and, under the single-identity map, neutralize
    // direct chown/chgrp and seed the merged statoverride, before any maintainer
    // script runs. The base's own base-passwd is already configured, so `root`
    // resolves from the start; no shadow pre-creation or awk shim is needed.
    write_policy_rc_d(upper)?;
    if single {
        install_delta_ownership_stubs(upper)?;
        write_delta_statoverride(lower, upper, statoverride)?;
    }

    // Register the increment against the base's database, seen through the
    // overlay. The files are already laid in the upper; the unpack wave records
    // the packages in the database and, honoring the statoverride, keeps their
    // ownership representable.
    let mut unpack: Vec<&str> = vec!["--force-depends", "--unpack"];
    unpack.extend(installables.iter().map(|p| p.deb_path.as_str()));
    run_dpkg_overlay(
        "unpack",
        lower,
        upper,
        archives_host,
        identity_map,
        env,
        &unpack,
        progress,
    )?;

    // The caller's pre-configure overlay, after unpack so it overwrites the
    // just-unpacked files — a shipped conffile among them — and before configure
    // so the maintainer scripts read the injected values.
    if let Some(source) = overlay_source {
        super::super::extract::overlay_tree(upper, source).map_err(DebianError::Overlay)?;
    }

    run_dpkg_overlay(
        "configure",
        lower,
        upper,
        archives_host,
        identity_map,
        env,
        &[
            "--configure",
            "--pending",
            "--force-configure-any",
            "--force-depends",
        ],
        progress,
    )?;

    // Reveal the base's real ownership tools through the overlay again and drop
    // the daemon-startup policy from the increment.
    if single {
        restore_delta_ownership_stubs(upper)?;
    }
    remove_policy_rc_d(upper)?;

    // dpkg copied the base's status database up into the upper on its first
    // write, so the merged database — base plus increment — is read from the
    // upper. Verify the increment's own packages reached the installed state.
    verify_installed(
        upper,
        &installables
            .iter()
            .map(|p| p.name.clone())
            .collect::<Vec<_>>(),
    )
}

/// Shadows the base's ownership tools with success stubs in the upper.
///
/// A delta package's maintainer script that `chown`s to an id the
/// single-identity map cannot represent would fail; the stub makes it succeed
/// for the duration of the increment's configuration. Unlike the full
/// bootstrap's stubs, which move the real tool aside, these merely shadow the
/// base's real tools through the overlay — [`restore_delta_ownership_stubs`]
/// removes the shadow to reveal them again, since the base's copies persist in
/// the read-only lower.
fn install_delta_ownership_stubs(upper: &Path) -> Result<(), DebianError> {
    for tool in OWNERSHIP_TOOLS {
        write_script(&upper.join(format!("usr/bin/{tool}")), OWNERSHIP_STUB)?;
    }
    Ok(())
}

/// Removes the ownership-tool stubs from the upper, revealing the base's real
/// tools through the overlay again.
fn restore_delta_ownership_stubs(upper: &Path) -> Result<(), DebianError> {
    for tool in OWNERSHIP_TOOLS {
        remove_if_present(&upper.join(format!("usr/bin/{tool}")))?;
    }
    Ok(())
}

/// Writes the increment's statoverride into the upper, carrying the base's
/// records as well.
///
/// The upper's statoverride shadows the base's copy in the lower through the
/// overlay, so it must hold the base's records as well as the increment's or the
/// merged view would lose the base's overrides. The base's file is read (an
/// absent one is treated as empty) and the increment's records laid over it, so
/// a path both describe carries the increment's mode — the mode of the file the
/// upper now shadows the base's with — and carries it once, which is the only
/// count dpkg accepts.
fn write_delta_statoverride(
    lower: &Path,
    upper: &Path,
    delta: &StatOverride,
) -> Result<(), DebianError> {
    let base_path = lower.join("var/lib/dpkg/statoverride");
    let base = match fs::read_to_string(&base_path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(source) => {
            return Err(DebianError::Io {
                op: "reading the base statoverride",
                path: base_path,
                source,
            });
        }
    };
    let mut merged = StatOverride::read(&base);
    merged.layer(delta);
    let path = upper.join("var/lib/dpkg/statoverride");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io("creating", parent))?;
    }
    fs::write(&path, merged.render()).map_err(io("writing", &path))
}

/// Forwards a wave's dpkg output to the progress callback.
struct DpkgOutput<'a> {
    emit: &'a mut dyn FnMut(DebianEvent<'_>),
}

impl Observer for DpkgOutput<'_> {
    fn stdout(&mut self, chunk: &[u8]) {
        (self.emit)(DebianEvent::CommandOutput {
            stream: Stream::Stdout,
            bytes: chunk,
        });
    }
    fn stderr(&mut self, chunk: &[u8]) {
        (self.emit)(DebianEvent::CommandOutput {
            stream: Stream::Stderr,
            bytes: chunk,
        });
    }
}

/// Installs one core package by name, if it is in the selection.
#[allow(clippy::too_many_arguments)]
fn core_install(
    installables: &[Installable],
    name: &str,
    staging: &Path,
    archives_host: &Path,
    identity_map: &IdentityMap,
    env: &[(String, String)],
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<(), DebianError> {
    if let Some(package) = installables.iter().find(|p| p.name == name) {
        run_dpkg(
            "core install",
            staging,
            archives_host,
            identity_map,
            env,
            &["--force-depends", "--install", &package.deb_path],
            progress,
        )?;
    }
    Ok(())
}

/// Writes the derived dpkg statoverride. Called after base-passwd so `root`
/// resolves.
fn write_statoverride(staging: &Path, overrides: &StatOverride) -> Result<(), DebianError> {
    let path = staging.join("var/lib/dpkg/statoverride");
    fs::write(&path, overrides.render()).map_err(io("writing", &path))
}

/// Pre-creates `/etc/shadow` and `/etc/gshadow` as empty root-owned files,
/// for the single-identity map only.
///
/// The `passwd` package configures with `pwconv`/`grpconv`, compiled tools
/// that create these files owned `root:shadow` — a group the single-identity
/// map leaves unmapped, so the create-and-chown fails, and being compiled the
/// tools bypass the chown stubs. Shadow-utils copies an existing file's
/// ownership onto its replacement, so seeding the files root-owned makes
/// those tools preserve root ownership and succeed.
///
/// A range identity map retires this seeding along with the stubs: the
/// `shadow` gid is real there, and the create-and-chown genuinely happens.
/// What a range map still cannot cover is an id outside the caller's
/// delegated allocation; making those succeed would take a syscall-level
/// ownership fake — one that records the intended ownership rather than
/// enacting it — which is complementary future work, not this mechanism.
fn precreate_shadow(staging: &Path) -> Result<(), DebianError> {
    for file in ["etc/shadow", "etc/gshadow"] {
        let path = staging.join(file);
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(io("creating", parent))?;
            }
            fs::write(&path, "").map_err(io("writing", &path))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
                .map_err(io("setting the mode of", &path))?;
        }
    }
    Ok(())
}

/// Runs one dpkg wave in a cage rooted at the staging tree, under the
/// bootstrap's identity map.
#[allow(clippy::too_many_arguments)]
fn run_dpkg(
    wave: &'static str,
    staging: &Path,
    archives_host: &Path,
    identity_map: &IdentityMap,
    env: &[(String, String)],
    args: &[&str],
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<(), DebianError> {
    run_dpkg_in(
        wave,
        Cage::builder().rootfs(staging),
        archives_host,
        identity_map,
        env,
        args,
        progress,
    )
}

/// Runs one dpkg wave in a cage rooted on an overlay of `lower` with writes in
/// `upper`, under the layer's identity map.
///
/// The layered build's configure waves run here: dpkg sees the merged view of
/// the pristine base (`lower`) and the increment (`upper`), reads the base's
/// configured database, and lands its writes in the disposable upper.
#[allow(clippy::too_many_arguments)]
fn run_dpkg_overlay(
    wave: &'static str,
    lower: &Path,
    upper: &Path,
    archives_host: &Path,
    identity_map: &IdentityMap,
    env: &[(String, String)],
    args: &[&str],
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<(), DebianError> {
    run_dpkg_in(
        wave,
        Cage::builder().overlay_rootfs(lower, upper),
        archives_host,
        identity_map,
        env,
        args,
        progress,
    )
}

/// Runs one dpkg wave in a cage built from `root`, which already carries the
/// rooting choice (a plain rootfs or an overlay). Shared by the full bootstrap's
/// plain-rooted waves and the layered build's overlay-rooted ones.
#[allow(clippy::too_many_arguments)]
fn run_dpkg_in(
    wave: &'static str,
    root: CageBuilder,
    archives_host: &Path,
    identity_map: &IdentityMap,
    env: &[(String, String)],
    args: &[&str],
    progress: &mut dyn FnMut(DebianEvent<'_>),
) -> Result<(), DebianError> {
    let cage = root
        .command("/usr/bin/dpkg")
        .args(args)
        .bind_ro(archives_host, ARCHIVES)
        .stdin(Stdio::Null)
        // The wave exists only to serve this bootstrap. Tie it to the caller so
        // that a caller killed mid-bootstrap does not leave dpkg writing into a
        // staging tree that `provision::ensure`'s error path is removing.
        .stop_with_caller(true)
        .identity_map(identity_map.clone())
        .envs(
            env.iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )
        .build()
        .map_err(DebianError::Launch)?;
    let mut observer = DpkgOutput { emit: progress };
    let status = cage.run_with(&mut observer).map_err(DebianError::Launch)?;
    if status.success() {
        Ok(())
    } else {
        Err(DebianError::Configure { wave, status })
    }
}

/// Verifies every selected package reached `install ok installed`.
fn verify_installed(staging: &Path, selected: &[String]) -> Result<(), DebianError> {
    let path = staging.join("var/lib/dpkg/status");
    let text = fs::read_to_string(&path).map_err(|source| DebianError::Io {
        op: "reading the dpkg status database",
        path: path.clone(),
        source,
    })?;
    let mut installed = HashSet::new();
    for stanza in parse_stanzas(&text) {
        if let (Some(name), Some(status)) = (stanza.get("Package"), stanza.get("Status"))
            && status == "install ok installed"
        {
            installed.insert(name.to_string());
        }
    }
    let mut missing: Vec<String> = selected
        .iter()
        .filter(|name| !installed.contains(*name))
        .cloned()
        .collect();
    missing.sort();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(DebianError::NotConfigured { packages: missing })
    }
}

/// Writes `/usr/sbin/policy-rc.d` returning 101, so package installation does
/// not start services in the half-built rootfs.
fn write_policy_rc_d(staging: &Path) -> Result<(), DebianError> {
    let path = staging.join("usr/sbin/policy-rc.d");
    write_script(&path, "#!/bin/sh\nexit 101\n")
}

/// Removes the daemon-startup policy after configuration.
fn remove_policy_rc_d(staging: &Path) -> Result<(), DebianError> {
    remove_if_present(&staging.join("usr/sbin/policy-rc.d"))
}

/// Replaces the ownership tools with stubs that succeed.
///
/// The real tool is preserved beside the stub on first call; a second call
/// (after an unpack wave re-lays the real tool) only rewrites the stub.
fn install_ownership_stubs(staging: &Path) -> Result<(), DebianError> {
    for tool in OWNERSHIP_TOOLS {
        let path = staging.join(format!("usr/bin/{tool}"));
        let saved = staging.join(format!("usr/bin/{tool}.fcage-real"));
        if path.exists() && !saved.exists() {
            fs::rename(&path, &saved).map_err(io("moving aside", &path))?;
        }
        write_script(&path, OWNERSHIP_STUB)?;
    }
    Ok(())
}

/// Restores the real ownership tools and removes the bootstrap-only copies.
///
/// A tool the rootfs never carried has nothing to restore, so its stub is
/// deleted rather than left behind: a `chown` that silently succeeds is a
/// worse outcome in a finished rootfs than no `chown` at all. The deletion is
/// conditional on the file still holding the stub body, so a real tool that
/// arrived after the last stub was written survives.
fn restore_ownership_stubs(staging: &Path) -> Result<(), DebianError> {
    for tool in OWNERSHIP_TOOLS {
        let path = staging.join(format!("usr/bin/{tool}"));
        let saved = staging.join(format!("usr/bin/{tool}.fcage-real"));
        if saved.exists() {
            fs::rename(&saved, &path).map_err(io("restoring", &path))?;
        } else if fs::read(&path).is_ok_and(|body| body == OWNERSHIP_STUB.as_bytes()) {
            remove_if_present(&path)?;
        }
    }
    Ok(())
}

/// Points `/usr/bin/awk` at mawk for the core install, so the base packages'
/// dependency on the virtual `awk` is satisfiable before mawk is configured.
fn symlink_awk(staging: &Path) -> Result<(), DebianError> {
    let path = staging.join("usr/bin/awk");
    remove_if_present(&path)?;
    std::os::unix::fs::symlink("mawk", &path).map_err(io("linking", &path))
}

/// Removes the temporary awk symlink before the real mawk is installed.
fn remove_awk_symlink(staging: &Path) -> Result<(), DebianError> {
    remove_if_present(&staging.join("usr/bin/awk"))
}

/// Selects apt as dpkg's access method, as `debootstrap` does.
fn write_dselect_method(staging: &Path) -> Result<(), DebianError> {
    let path = staging.join("var/lib/dpkg/cmethopt");
    fs::write(&path, "apt apt\n").map_err(io("writing", &path))
}

/// Writes every repository's apt source into the finished rootfs.
///
/// The primary repository (index zero) owns `/etc/apt/sources.list` and, when
/// signed, the canonical [`TRUST_ANCHOR`] keyring path. Each additional
/// repository writes `/etc/apt/sources.list.d/<name>.list` and, when signed,
/// its own `/usr/share/keyrings/<name>.gpg`, referenced by a `signed-by` so an
/// in-rootfs `apt-get update` verifies it against that keyring without the
/// `debian-archive-keyring` package the base closure does not install. An
/// unsigned repository writes a `[trusted=yes]` line and no keyring, apt's own
/// posture for a source under the caller's control. Each source names the
/// repository's primary mirror; a snapshot backstop is a fetch-time concern and
/// is not written into the installed system.
fn write_repository_sources(
    staging: &Path,
    repositories: &[Repository],
) -> Result<(), DebianError> {
    for (index, repository) in repositories.iter().enumerate() {
        let (list_path, keyring_path) = if index == 0 {
            ("etc/apt/sources.list".to_string(), TRUST_ANCHOR.to_string())
        } else {
            // Distinct across the set: the configuration refuses two additional
            // repositories that would write the same pair of files.
            let stem = repository.entry_stem(index);
            (
                format!("etc/apt/sources.list.d/{stem}.list"),
                format!("/usr/share/keyrings/{stem}.gpg"),
            )
        };

        let options = match &repository.trust {
            Trust::Signed(keyring) => {
                write_keyring(staging, &keyring_path, keyring)?;
                format!("[signed-by={keyring_path}]")
            }
            Trust::Unsigned => "[trusted=yes]".to_string(),
        };

        // The primary mirror; a snapshot backstop is not carried into the
        // installed system's apt configuration.
        let mirror = &repository.mirrors[0];
        let line = format!(
            "deb {options} {mirror} {} {}\n",
            repository.suite,
            repository.components.join(" "),
        );
        write_sources_file(staging, &list_path, &line)?;
    }
    Ok(())
}

/// Writes a keyring into the finished rootfs at an absolute in-rootfs path,
/// creating the keyrings directory as needed.
fn write_keyring(staging: &Path, rootfs_path: &str, keyring: &[u8]) -> Result<(), DebianError> {
    let path = staging.join(rootfs_path.trim_start_matches('/'));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io("creating", parent))?;
    }
    fs::write(&path, keyring).map_err(io("writing", &path))
}

/// Configures apt to run its download methods as root, for the single-identity
/// map only.
///
/// apt drops privileges to the `_apt` user before fetching, to sandbox the
/// download. Under the single-identity map that user does not exist — the one
/// mapped id is root — so the drop fails with `EINVAL` and `apt-get update`
/// cannot fetch. Because every id in that map is the same underlying caller
/// uid, the drop would isolate nothing anyway, so disabling it costs no
/// separation. A range map maps `_apt` to a real id, keeps the sandbox, and
/// needs no such file.
fn write_apt_sandbox_user(staging: &Path) -> Result<(), DebianError> {
    let path = staging.join("etc/apt/apt.conf.d/00fcage-single-identity");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io("creating", parent))?;
    }
    fs::write(&path, "APT::Sandbox::User \"root\";\n").map_err(io("writing", &path))
}

/// Writes a single apt sources file (`sources.list` or a `sources.list.d`
/// entry) at a rootfs-relative path, creating its parent directory as needed.
fn write_sources_file(staging: &Path, rootfs_path: &str, line: &str) -> Result<(), DebianError> {
    let path = staging.join(rootfs_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io("creating", parent))?;
    }
    fs::write(&path, line).map_err(io("writing", &path))
}

/// Writes an executable script.
fn write_script(path: &Path, contents: &str) -> Result<(), DebianError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io("creating", parent))?;
    }
    fs::write(path, contents).map_err(io("writing", path))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(io("setting the mode of", path))
}

/// Removes a path if it exists, treating an already-absent path as success.
fn remove_if_present(path: &Path) -> Result<(), DebianError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DebianError::Io {
            op: "removing",
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Builds an I/O error closure for a host-side step.
fn io(op: &'static str, path: &Path) -> impl FnOnce(std::io::Error) -> DebianError {
    let path = path.to_path_buf();
    move |source| DebianError::Io { op, path, source }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> crate::scratch::Scratch {
        crate::scratch::Scratch::new(&format!("bootstrap-{tag}"))
    }

    /// A signed repository over the given mirror, suite, and components.
    fn signed_repo(
        mirror: &str,
        suite: &str,
        components: &[&str],
        keyring: &[u8],
        name: Option<&str>,
    ) -> Repository {
        Repository {
            mirrors: vec![mirror.to_string()],
            suite: suite.to_string(),
            components: components.iter().map(|c| c.to_string()).collect(),
            trust: Trust::Signed(keyring.to_vec()),
            allow_stale: false,
            name: name.map(str::to_string),
        }
    }

    #[test]
    fn the_primary_sources_list_is_signed_by_the_trust_anchor() {
        // The primary owns sources.list and the canonical keyring path; the deb
        // line must carry a signed-by naming it, or apt would reject the release
        // for want of a trusted keyring.
        let staging = tempdir("sources-list");
        let primary = signed_repo(
            "http://deb.debian.org/debian",
            "trixie",
            &["main", "contrib"],
            b"keyring-bytes",
            None,
        );
        write_repository_sources(&staging, &[primary]).expect("the sources are written");

        // The keyring lands at the canonical anchor path.
        let anchor = staging.join(TRUST_ANCHOR.trim_start_matches('/'));
        assert_eq!(
            fs::read(&anchor).expect("the anchor exists"),
            b"keyring-bytes",
        );
        let sources = fs::read_to_string(staging.join("etc/apt/sources.list"))
            .expect("the sources.list exists");
        assert_eq!(
            sources,
            format!(
                "deb [signed-by={TRUST_ANCHOR}] http://deb.debian.org/debian trixie main contrib\n"
            ),
        );
    }

    #[test]
    fn an_additional_signed_repository_writes_its_own_entry_and_anchor() {
        // The second repository writes a named sources.list.d entry signed by
        // its own keyring, distinct from the primary's anchor.
        let staging = tempdir("sources-additional");
        let primary = signed_repo(
            "http://deb.debian.org/debian",
            "trixie",
            &["main"],
            b"archive-keyring",
            None,
        );
        let feature = signed_repo(
            "https://features.example/debian",
            "trixie",
            &["main"],
            b"feature-keyring",
            Some("features"),
        );
        write_repository_sources(&staging, &[primary, feature]).expect("the sources are written");

        let entry = fs::read_to_string(staging.join("etc/apt/sources.list.d/features.list"))
            .expect("the additional entry exists");
        assert_eq!(
            entry,
            "deb [signed-by=/usr/share/keyrings/features.gpg] \
             https://features.example/debian trixie main\n",
        );
        assert_eq!(
            fs::read(staging.join("usr/share/keyrings/features.gpg")).expect("the keyring exists"),
            b"feature-keyring",
        );
    }

    #[test]
    fn an_unsigned_repository_writes_a_trusted_line_and_no_keyring() {
        // A trust_unsigned repository writes [trusted=yes] and lays down no
        // keyring, apt's posture for a source under the caller's control.
        let staging = tempdir("sources-unsigned");
        let primary = signed_repo(
            "http://deb.debian.org/debian",
            "trixie",
            &["main"],
            b"archive-keyring",
            None,
        );
        let local = Repository {
            mirrors: vec!["file:///srv/local-debs".to_string()],
            suite: "trixie".to_string(),
            components: vec!["main".to_string()],
            trust: Trust::Unsigned,
            allow_stale: false,
            name: Some("local".to_string()),
        };
        write_repository_sources(&staging, &[primary, local]).expect("the sources are written");

        let entry = fs::read_to_string(staging.join("etc/apt/sources.list.d/local.list"))
            .expect("the local entry exists");
        assert_eq!(
            entry,
            "deb [trusted=yes] file:///srv/local-debs trixie main\n",
        );
        assert!(
            !staging.join("usr/share/keyrings/local.gpg").exists(),
            "an unsigned repository writes no keyring",
        );
    }

    #[test]
    fn the_single_identity_apt_config_runs_methods_as_root() {
        // Under the single-identity map apt cannot drop to _apt, so the
        // written config points its sandbox user at root instead.
        let staging = tempdir("apt-sandbox-user");
        write_apt_sandbox_user(&staging).expect("the apt config is written");

        let conf = fs::read_to_string(staging.join("etc/apt/apt.conf.d/00fcage-single-identity"))
            .expect("the apt config exists");
        assert_eq!(conf, "APT::Sandbox::User \"root\";\n");
    }

    #[test]
    fn a_path_recorded_twice_produces_one_record() {
        // dpkg treats two records for one path as an unrecoverable fatal error:
        // `dpkg-statoverride --list` aborts, and with it every dpkg wave that
        // follows the file being written. Two packages shipping one path, or one
        // data.tar listing it twice, is reachable without anything malformed, so
        // the second record supersedes the first rather than joining it — the
        // extraction's own last-wins rule, describing the file that survived.
        let mut overrides = StatOverride::default();
        overrides.record(0o2755, "/usr/bin/x".to_string());
        overrides.record(0o4755, "/usr/bin/x".to_string());
        assert_eq!(overrides.render(), "root root 4755 /usr/bin/x\n");
    }

    #[test]
    fn records_are_rendered_in_path_order() {
        // The file is then a function of what was extracted rather than of the
        // order it was extracted in.
        let mut overrides = StatOverride::default();
        for path in ["/var/log/x", "/usr/bin/a", "/etc/z"] {
            overrides.record(0o2755, path.to_string());
        }
        assert_eq!(
            overrides.render(),
            "root root 2755 /etc/z\nroot root 2755 /usr/bin/a\nroot root 2755 /var/log/x\n",
        );
        // Nothing recorded is an empty file, not a blank line.
        assert_eq!(StatOverride::default().render(), "");
    }

    #[test]
    fn a_base_statoverride_is_carried_and_the_increment_wins() {
        // The upper's file shadows the base's through the overlay, so it has to
        // hold the base's records too. Where both name a path the increment's
        // record is the one that describes what the merged view shows — and it
        // has to appear once, whatever the base said.
        let base = "root root 2755 /usr/bin/shared\n\
                    games games 2755 /usr/games/keep\n\
                    \n\
                    not-a-record\n";
        let mut delta = StatOverride::default();
        delta.record(0o4755, "/usr/bin/shared".to_string());
        delta.record(0o2755, "/usr/bin/new".to_string());

        let mut merged = StatOverride::read(base);
        merged.layer(&delta);
        assert_eq!(
            merged.render(),
            "root root 2755 /usr/bin/new\n\
             root root 4755 /usr/bin/shared\n\
             games games 2755 /usr/games/keep\n",
        );
    }

    #[test]
    fn a_record_path_may_carry_a_space() {
        // dpkg's fourth field runs to the end of the line, so a path with a
        // space in it is one record and not a malformed two.
        assert_eq!(
            record_path("root root 2755 /usr/lib/my tool"),
            Some("/usr/lib/my tool"),
        );
        assert_eq!(record_path("root root 2755"), None);
        assert_eq!(record_path(""), None);
    }
}
