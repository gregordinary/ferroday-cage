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
//!
//! Every host-side step goes through [`Rooted`] rather than through a path
//! composed with the tree's own. The steps interleave with the waves, so most
//! of them run after arbitrary maintainer scripts have executed inside a cage
//! rooted at the tree, as root of its namespace; a script that leaves a
//! symbolic link where a step is about to write would otherwise redirect that
//! write out of the tree, resolved against the host's root and performed as the
//! calling user. Anchored to a descriptor for the tree, the same link resolves
//! within the tree — which is what it means to dpkg reading it from inside the
//! cage — and the write lands there.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::Path;

use super::index::parse_stanzas;
use super::repository::{Repository, Trust};
use super::{DebianError, DebianEvent, DebianObserver, Stream};
use crate::provision::rooted::Rooted;
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

/// The dpkg statoverride: one record per path whose ownership or mode differs
/// from what its package shipped.
const STATOVERRIDE: &str = "var/lib/dpkg/statoverride";

/// The dpkg status database, which records what is installed and configured.
pub(super) const STATUS: &str = "var/lib/dpkg/status";

/// dpkg's access-method selection.
const CMETHOPT: &str = "var/lib/dpkg/cmethopt";

/// The daemon-startup policy that suppresses service starts while the rootfs is
/// half-built.
const POLICY_RC_D: &str = "usr/sbin/policy-rc.d";

/// The temporary `awk` the core install resolves the virtual dependency
/// through, before the real mawk is configured.
const AWK: &str = "usr/bin/awk";

/// The apt configuration the single-identity map needs.
const APT_SANDBOX_USER: &str = "etc/apt/apt.conf.d/00fcage-single-identity";

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
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    // Under a range map every id Debian assigns is real and every chown
    // works; the reconciliation below exists solely for the single-identity
    // map, where no id but root can be represented.
    let single = matches!(identity_map, IdentityMap::Single);

    // Every host-side step below is anchored to this descriptor, so a symbolic
    // link a maintainer script leaves behind cannot redirect one out of the
    // tree. The cages are rooted by path, which the kernel resolves once, at
    // the pivot.
    let tree = open_tree(staging)?;

    // Suppress daemon startup and, under the single-identity map, neutralize
    // direct chown/chgrp for the whole configuration, before any maintainer
    // script runs.
    write_policy_rc_d(&tree)?;
    if single {
        install_ownership_stubs(&tree)?;
    }
    symlink_awk(&tree)?;

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
        observer,
    )?;
    if single {
        write_statoverride(&tree, statoverride)?;
        precreate_shadow(&tree)?;
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
            observer,
        )?;
    }
    // The real mawk replaces the temporary awk symlink.
    remove_awk_symlink(&tree)?;
    core_install(
        installables,
        "mawk",
        staging,
        archives_host,
        identity_map,
        env,
        observer,
    )?;

    // Unpack registers every package in the database and lays its files;
    // this re-lays coreutils, so the ownership stubs are reinstalled before
    // configuration runs the maintainer scripts.
    write_dselect_method(&tree)?;
    let mut unpack: Vec<&str> = vec!["--force-depends", "--unpack"];
    unpack.extend(installables.iter().map(|p| p.deb_path.as_str()));
    run_dpkg(
        "unpack",
        staging,
        archives_host,
        identity_map,
        env,
        &unpack,
        observer,
    )?;

    if single {
        install_ownership_stubs(&tree)?;
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
        observer,
    )?;

    // Restore the real tools and remove the bootstrap-only files, then write
    // the finished rootfs's apt sources.
    if single {
        restore_ownership_stubs(&tree)?;
    }
    remove_policy_rc_d(&tree)?;
    write_repository_sources(&tree, repositories)?;
    if single {
        write_apt_sandbox_user(&tree)?;
    }

    verify_installed(
        &tree,
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
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    let single = matches!(identity_map, IdentityMap::Single);

    // The increment's own tree, which every host-side step below is anchored
    // to; the base is opened where it is read.
    let tree = open_tree(upper)?;

    // Suppress daemon startup and, under the single-identity map, neutralize
    // direct chown/chgrp and seed the merged statoverride, before any maintainer
    // script runs. The base's own base-passwd is already configured, so `root`
    // resolves from the start; no shadow pre-creation or awk shim is needed.
    write_policy_rc_d(&tree)?;
    if single {
        install_delta_ownership_stubs(&tree)?;
        write_delta_statoverride(lower, &tree, statoverride)?;
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
        observer,
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
        observer,
    )?;

    // Reveal the base's real ownership tools through the overlay again and drop
    // the daemon-startup policy from the increment.
    if single {
        restore_delta_ownership_stubs(&tree)?;
    }
    remove_policy_rc_d(&tree)?;

    // dpkg copied the base's status database up into the upper on its first
    // write, so the merged database — base plus increment — is read from the
    // upper. Verify the increment's own packages reached the installed state.
    verify_installed(
        &tree,
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
fn install_delta_ownership_stubs(upper: &Rooted) -> Result<(), DebianError> {
    for tool in OWNERSHIP_TOOLS {
        write_script(upper, &format!("usr/bin/{tool}"), OWNERSHIP_STUB)?;
    }
    Ok(())
}

/// Removes the ownership-tool stubs from the upper, revealing the base's real
/// tools through the overlay again.
fn restore_delta_ownership_stubs(upper: &Rooted) -> Result<(), DebianError> {
    for tool in OWNERSHIP_TOOLS {
        remove_if_present(upper, &format!("usr/bin/{tool}"))?;
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
    upper: &Rooted,
    delta: &StatOverride,
) -> Result<(), DebianError> {
    // The base is a caller-supplied tree, so its statoverride is read through a
    // descriptor for it: a symbolic link at that path would otherwise make this
    // an arbitrary host-file read whose contents are written into the tree the
    // caller goes on to export.
    let base_tree = open_tree(lower)?;
    let base = match read_text(&base_tree, STATOVERRIDE) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
        Err(source) => {
            return Err(DebianError::io(
                "reading the base statoverride",
                base_tree.path(STATOVERRIDE),
                source,
            ));
        }
    };
    let mut merged = StatOverride::read(&base);
    merged.layer(delta);
    upper
        .write(STATOVERRIDE, merged.render().as_bytes())
        .map_err(at("writing", upper, STATOVERRIDE))
}

/// Forwards a wave's dpkg output to the bootstrap's observer.
struct DpkgOutput<'a> {
    emit: &'a mut dyn DebianObserver,
}

impl Observer for DpkgOutput<'_> {
    fn stdout(&mut self, chunk: &[u8]) {
        self.emit.progress(DebianEvent::CommandOutput {
            stream: Stream::Stdout,
            bytes: chunk,
        });
    }
    fn stderr(&mut self, chunk: &[u8]) {
        self.emit.progress(DebianEvent::CommandOutput {
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
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    if let Some(package) = installables.iter().find(|p| p.name == name) {
        run_dpkg(
            "core install",
            staging,
            archives_host,
            identity_map,
            env,
            &["--force-depends", "--install", &package.deb_path],
            observer,
        )?;
    }
    Ok(())
}

/// Writes the derived dpkg statoverride. Called after base-passwd so `root`
/// resolves.
fn write_statoverride(tree: &Rooted, overrides: &StatOverride) -> Result<(), DebianError> {
    tree.write(STATOVERRIDE, overrides.render().as_bytes())
        .map_err(at("writing", tree, STATOVERRIDE))
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
fn precreate_shadow(tree: &Rooted) -> Result<(), DebianError> {
    for file in ["etc/shadow", "etc/gshadow"] {
        if !tree.exists(file).map_err(at("inspecting", tree, file))? {
            tree.write_mode(file, b"", 0o640)
                .map_err(at("writing", tree, file))?;
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
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    run_dpkg_in(
        wave,
        Cage::builder().rootfs(staging),
        archives_host,
        identity_map,
        env,
        args,
        observer,
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
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    run_dpkg_in(
        wave,
        Cage::builder().overlay_rootfs(lower, upper),
        archives_host,
        identity_map,
        env,
        args,
        observer,
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
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    let cage = root
        .command("/usr/bin/dpkg")
        .args(args)
        // Read-only so a wave cannot rewrite the caller's package cache, in the
        // ordinary course of unpacking or otherwise. The command enters a nested
        // user namespace before it execs, which locks the flag, so this holds
        // even though dpkg runs as namespace root — as a maintainer script needs
        // it to. See `CageBuilder::bind_ro`.
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
    let mut output = DpkgOutput { emit: observer };
    let status = cage.run_with(&mut output).map_err(DebianError::Launch)?;
    if status.success() {
        Ok(())
    } else {
        Err(DebianError::Configure { wave, status })
    }
}

/// Verifies every selected package reached `install ok installed`.
fn verify_installed(tree: &Rooted, selected: &[String]) -> Result<(), DebianError> {
    let text =
        read_text(tree, STATUS).map_err(at("reading the dpkg status database", tree, STATUS))?;
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
fn write_policy_rc_d(tree: &Rooted) -> Result<(), DebianError> {
    write_script(tree, POLICY_RC_D, "#!/bin/sh\nexit 101\n")
}

/// Removes the daemon-startup policy after configuration.
fn remove_policy_rc_d(tree: &Rooted) -> Result<(), DebianError> {
    remove_if_present(tree, POLICY_RC_D)
}

/// Replaces the ownership tools with stubs that succeed.
///
/// The real tool is preserved beside the stub on first call; a second call
/// (after an unpack wave re-lays the real tool) only rewrites the stub.
///
/// Presence is asked of the name rather than of what it resolves to, so a
/// symbolic link occupying either path counts as the tool being there and is
/// moved aside as one, never followed.
fn install_ownership_stubs(tree: &Rooted) -> Result<(), DebianError> {
    for tool in OWNERSHIP_TOOLS {
        let path = format!("usr/bin/{tool}");
        let saved = format!("{path}.fcage-real");
        if tree.exists(&path).map_err(at("inspecting", tree, &path))?
            && !tree
                .exists(&saved)
                .map_err(at("inspecting", tree, &saved))?
        {
            tree.rename(&path, &saved)
                .map_err(at("moving aside", tree, &path))?;
        }
        write_script(tree, &path, OWNERSHIP_STUB)?;
    }
    Ok(())
}

/// Restores the real ownership tools and removes the bootstrap-only copies.
///
/// A tool the rootfs never carried has nothing to restore, so its stub is
/// deleted rather than left behind: a `chown` that silently succeeds is a
/// worse outcome in a finished rootfs than no `chown` at all. The deletion is
/// conditional on the file still holding the stub body, so a real tool that
/// arrived after the last stub was written survives — as does anything the read
/// refuses to follow, a symbolic link at the path among them.
fn restore_ownership_stubs(tree: &Rooted) -> Result<(), DebianError> {
    for tool in OWNERSHIP_TOOLS {
        let path = format!("usr/bin/{tool}");
        let saved = format!("{path}.fcage-real");
        if tree
            .exists(&saved)
            .map_err(at("inspecting", tree, &saved))?
        {
            tree.rename(&saved, &path)
                .map_err(at("restoring", tree, &path))?;
        } else if tree
            .read(&path)
            .is_ok_and(|body| body == OWNERSHIP_STUB.as_bytes())
        {
            remove_if_present(tree, &path)?;
        }
    }
    Ok(())
}

/// Points `/usr/bin/awk` at mawk for the core install, so the base packages'
/// dependency on the virtual `awk` is satisfiable before mawk is configured.
fn symlink_awk(tree: &Rooted) -> Result<(), DebianError> {
    tree.symlink("mawk", AWK).map_err(at("linking", tree, AWK))
}

/// Removes the temporary awk symlink before the real mawk is installed.
fn remove_awk_symlink(tree: &Rooted) -> Result<(), DebianError> {
    remove_if_present(tree, AWK)
}

/// Selects apt as dpkg's access method, as `debootstrap` does.
fn write_dselect_method(tree: &Rooted) -> Result<(), DebianError> {
    tree.write(CMETHOPT, b"apt apt\n")
        .map_err(at("writing", tree, CMETHOPT))
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
fn write_repository_sources(tree: &Rooted, repositories: &[Repository]) -> Result<(), DebianError> {
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
                write_keyring(tree, &keyring_path, keyring)?;
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
        write_sources_file(tree, &list_path, &line)?;
    }
    Ok(())
}

/// Writes a keyring into the finished rootfs at an absolute in-rootfs path,
/// creating the keyrings directory as needed.
fn write_keyring(tree: &Rooted, rootfs_path: &str, keyring: &[u8]) -> Result<(), DebianError> {
    tree.write(rootfs_path, keyring)
        .map_err(at("writing", tree, rootfs_path))
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
fn write_apt_sandbox_user(tree: &Rooted) -> Result<(), DebianError> {
    tree.write(APT_SANDBOX_USER, b"APT::Sandbox::User \"root\";\n")
        .map_err(at("writing", tree, APT_SANDBOX_USER))
}

/// Writes a single apt sources file (`sources.list` or a `sources.list.d`
/// entry) at a rootfs-relative path, creating its parent directory as needed.
fn write_sources_file(tree: &Rooted, rootfs_path: &str, line: &str) -> Result<(), DebianError> {
    tree.write(rootfs_path, line.as_bytes())
        .map_err(at("writing", tree, rootfs_path))
}

/// Writes an executable script.
fn write_script(tree: &Rooted, rootfs_path: &str, contents: &str) -> Result<(), DebianError> {
    tree.write_mode(rootfs_path, contents.as_bytes(), 0o755)
        .map_err(at("writing", tree, rootfs_path))
}

/// Removes a path if it exists, treating an already-absent path as success.
fn remove_if_present(tree: &Rooted, rootfs_path: &str) -> Result<(), DebianError> {
    tree.remove(rootfs_path)
        .map_err(at("removing", tree, rootfs_path))
}

/// Reads the dpkg status database of a caller-supplied base tree, anchored to
/// that tree so nothing in it can redirect the read.
///
/// The failure is the raw one, so the layered build can tell an absent database
/// — which it reports as a misconfigured base — from a read that failed.
pub(super) fn read_base_status(base: &Path) -> io::Result<String> {
    read_text(&Rooted::open(base)?, STATUS)
}

/// Opens a tree for the host-side steps that read and write inside it.
fn open_tree(root: &Path) -> Result<Rooted, DebianError> {
    Rooted::open(root).map_err(DebianError::at("opening the tree", root))
}

/// Reads a file of the tree as text, as [`std::fs::read_to_string`] would:
/// invalid UTF-8 is an `InvalidData` failure rather than lossily decoded.
fn read_text(tree: &Rooted, rootfs_path: &str) -> io::Result<String> {
    let bytes = tree.read(rootfs_path)?;
    String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        )
    })
}

/// Builds an I/O error closure for a host-side step, naming the host path the
/// tree-relative one would compose to.
///
/// [`DebianError::at`] with the path composition every host-side step here
/// needs: the operation is asked for by its tree-relative name, and only the
/// error message names a host path.
fn at(op: &'static str, tree: &Rooted, rootfs_path: &str) -> impl FnOnce(io::Error) -> DebianError {
    DebianError::at(op, tree.path(rootfs_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;
    use std::fs;

    /// A scratch tree, and a [`Rooted`] anchored to it.
    fn rooted_tree(tag: &str) -> (Scratch, Rooted) {
        let scratch = Scratch::for_test("bootstrap", tag);
        let tree = open_tree(&scratch).expect("the scratch tree opens");
        (scratch, tree)
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
        let (staging, tree) = rooted_tree("sources-list");
        let primary = signed_repo(
            "http://deb.debian.org/debian",
            "trixie",
            &["main", "contrib"],
            b"keyring-bytes",
            None,
        );
        write_repository_sources(&tree, &[primary]).expect("the sources are written");

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
        let (staging, tree) = rooted_tree("sources-additional");
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
        write_repository_sources(&tree, &[primary, feature]).expect("the sources are written");

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
        let (staging, tree) = rooted_tree("sources-unsigned");
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
        write_repository_sources(&tree, &[primary, local]).expect("the sources are written");

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
        let (staging, tree) = rooted_tree("apt-sandbox-user");
        write_apt_sandbox_user(&tree).expect("the apt config is written");

        let conf = fs::read_to_string(staging.join("etc/apt/apt.conf.d/00fcage-single-identity"))
            .expect("the apt config exists");
        assert_eq!(conf, "APT::Sandbox::User \"root\";\n");
    }

    #[test]
    fn a_planted_link_cannot_redirect_a_host_side_step_out_of_the_tree() {
        // Most host-side steps run after a wave has executed every selected
        // package's maintainer scripts inside a cage rooted at the tree, so a
        // script is free to leave an absolute link where one of them writes.
        // The write must land in the tree, and the host file it names must be
        // untouched.
        let (staging, tree) = rooted_tree("planted-link");
        let victim = staging.join("victim");
        fs::write(&victim, b"host contents\n").unwrap();
        for path in [
            "etc/apt/sources.list",
            "usr/sbin/policy-rc.d",
            "usr/bin/awk",
        ] {
            let planted = staging.join(path);
            fs::create_dir_all(planted.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&victim, &planted).unwrap();
        }

        let primary = signed_repo("file:///srv/pool", "trixie", &["main"], b"anchor", None);
        write_repository_sources(&tree, &[primary]).expect("the sources are written");
        symlink_awk(&tree).expect("the awk shim is linked");
        remove_policy_rc_d(&tree).expect("the policy is removed");

        assert_eq!(
            fs::read(&victim).unwrap(),
            b"host contents\n",
            "a step wrote through the planted link",
        );
        let sources = staging.join("etc/apt/sources.list");
        assert!(
            !fs::symlink_metadata(&sources)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(&sources).unwrap(),
            format!("deb [signed-by={TRUST_ANCHOR}] file:///srv/pool trixie main\n"),
        );
        assert_eq!(
            fs::read_link(staging.join("usr/bin/awk")).unwrap(),
            Path::new("mawk"),
        );
        assert!(fs::symlink_metadata(staging.join("usr/sbin/policy-rc.d")).is_err());
    }

    #[test]
    fn a_link_in_the_base_cannot_leak_a_host_file_into_the_increment() {
        // The base of a layered build is a caller-supplied tree whose
        // statoverride is read and carried into the upper. A link there would
        // otherwise make the read an arbitrary host-file read, published in the
        // tree the caller exports.
        let (base, _) = rooted_tree("delta-base");
        let (upper, upper_tree) = rooted_tree("delta-upper");
        let secret = base.join("secret");
        fs::write(&secret, b"root root 4755 /host/secret\n").unwrap();
        fs::create_dir_all(base.join("var/lib/dpkg")).unwrap();
        std::os::unix::fs::symlink(&secret, base.join(STATOVERRIDE)).unwrap();

        let mut delta = StatOverride::default();
        delta.record(0o2755, "/usr/bin/new".to_string());
        let err = write_delta_statoverride(&base, &upper_tree, &delta)
            .expect_err("a link at the base's statoverride is not read through");
        assert!(matches!(err, DebianError::Io { .. }));
        assert!(!upper.join(STATOVERRIDE).exists());
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
