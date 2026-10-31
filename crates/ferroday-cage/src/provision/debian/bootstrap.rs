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

use super::repository::{Repository, Trust};
use super::{DebianError, DebianEvent, DebianObserver};
use crate::provision::Stream;
use crate::provision::accounts;
use crate::provision::document;
use crate::provision::layer::Rooting;
use crate::provision::rooted::Rooted;
use crate::{IdentityMap, Observer, Stdio};

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
///
/// Substituting a command covers only a script that runs one. A compiled helper
/// calls `fchownat()` itself and is unreachable from here — see
/// [`precreate_shadow`], which exists because `pwconv` is one — as is a POSIX
/// ACL, which goes through `acl_set_file()` and has no dpkg record besides.
/// `setfacl` is deliberately not on this list: the stub is only honest because
/// [`StatOverride`] keeps the ownership the rootfs intends, and there is no
/// such record for an ACL to keep, so stubbing it would discard the intent
/// instead of deferring it. The coverage is documented for callers on
/// [`IdentityMap::Single`].
const OWNERSHIP_TOOLS: [&str; 2] = ["chown", "chgrp"];

/// The body of an ownership-tool stub: a shell script that succeeds and does
/// nothing. Also the marker that identifies a stub as one this bootstrap
/// wrote, so the restore can delete a stub it has no real tool to put back.
const OWNERSHIP_STUB: &str = "#!/bin/sh\nexit 0\n";

/// The file-name stem a trust anchor the bootstrap writes for the primary
/// repository takes in the finished rootfs, and so a name an additional
/// repository may not claim: [`repository::validate_distinct_entries`] refuses
/// a set that would write a second keyring here.
///
/// A stem no package ships, so nothing the root goes on to upgrade replaces
/// what is written here. It holds a caller's keyring, which the caller keeps
/// current, or the embedded archive keyring where the root has no
/// `debian-archive-keyring` package to name instead; see
/// [`write_repository_sources`].
///
/// [`repository::validate_distinct_entries`]: super::repository::validate_distinct_entries
pub(crate) const TRUST_ANCHOR_STEM: &str = "fcage-archive-keyring";

/// The package that ships Debian's archive keyring. `apt` depends on it, so
/// every root with `apt` holds it, and its upgrades are how a root learns the
/// keys the archive rotates to.
pub(crate) const ARCHIVE_KEYRING_PACKAGE: &str = "debian-archive-keyring";

/// The file-name stem of the keyring [`ARCHIVE_KEYRING_PACKAGE`] installs,
/// which no repository's anchor may take: the package's upgrades replace the
/// file, and a default primary's `sources.list` names it.
pub(crate) const PACKAGE_KEYRING_STEM: &str = "debian-archive-keyring";

/// Where a repository's keyring is in the finished rootfs, and the `signed-by`
/// its [sources file](write_repository_sources) references.
///
/// The primary's stem is [`PACKAGE_KEYRING_STEM`] where it names the package's
/// keyring, and [`TRUST_ANCHOR_STEM`] where the bootstrap writes one; an
/// additional repository's is its [`entry_stem`](Repository::entry_stem). All
/// of them land in this one directory, which is why they share one collision
/// set rather than two.
pub(crate) fn keyring_path(stem: &str) -> String {
    format!("/usr/share/keyrings/{stem}.gpg")
}

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

/// What the configure waves record of their own run, which a finished root
/// does not keep.
///
/// Each describes the run rather than the root. dpkg's log and
/// `update-alternatives`' log time-stamp every action the waves took, and
/// `ldconfig`'s auxiliary cache records the inode and change time of every
/// library it read, which differ between two trees holding the same files.
/// Nothing needs them: the logs are history, and `ldconfig` rebuilds its cache
/// on its next run. The list is `mmdebstrap`'s, less the apt logs a bootstrap
/// that drives dpkg directly never writes.
const RUN_RECORDS: [&str; 3] = [
    "var/log/dpkg.log",
    "var/log/alternatives.log",
    "var/cache/ldconfig/aux-cache",
];

/// The system's machine id.
///
/// `systemd`'s configuration writes a random one, which every machine a root is
/// deployed to would then share. `machine-id(5)` asks a generic image to carry
/// the file missing or empty, and `systemd` generates a fresh id at boot from
/// either. Empty is the state kept, as `mmdebstrap` keeps it. A missing file
/// also makes that boot a first boot, which runs the first-boot units and
/// presets, and whether a root's first boot does that is the deployment's
/// decision rather than the bootstrap's.
const MACHINE_ID: &str = "etc/machine-id";

/// The most of the dpkg status database a host-side step reads.
///
/// The database records a stanza of about a kilobyte per installed package:
/// a desktop's two thousand packages come to under three megabytes. This is far
/// past a root holding every package an archive publishes, and it is what a
/// maintainer script that grew the file without writing to it meets first.
const MAX_STATUS: u64 = 256 * 1024 * 1024;

/// The most of a statoverride database a host-side step reads: a line of a few
/// dozen bytes per overridden path, for a few paths a root.
const MAX_STATOVERRIDE: u64 = 16 * 1024 * 1024;

/// The most of one package's dpkg file list a host-side step reads: a line per
/// path the package installed, which for the largest packages is tens of
/// thousands of lines and a few megabytes.
const MAX_FILE_LIST: u64 = 64 * 1024 * 1024;

/// D-Bus's own copy of the machine id, which its configuration copies from
/// [`MACHINE_ID`] or generates. Removed rather than emptied, as `mmdebstrap`
/// removes it: D-Bus reads the system's id when its own is absent.
const DBUS_MACHINE_ID: &str = "var/lib/dbus/machine-id";

/// The mount point the downloaded packages are bound to inside the cage.
///
/// Deliberately not `/var/cache/apt/archives`: the `apt` package ships and
/// writes to that directory during its own unpack, and a read-only bind there
/// would block it. A neutral path keeps the archive cache a normal, writable
/// part of the rootfs.
pub(crate) const ARCHIVES: &str = "/fcage-debs";

/// A package to install: its name, the path to its `.deb` inside the cage, and
/// the SHA-256 the `.deb` was acquired under, which the extraction verifies the
/// file `dpkg` goes on to read against.
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

/// What a configure wave installs, and the environment it installs it in.
///
/// The same values travel from a bootstrap down through `configure`,
/// `core_install` and `run_dpkg`, and were threaded through each positionally.
/// Gathered here, a step names what it reads.
pub(crate) struct Configure<'a> {
    /// The host directory the `.deb` files are installed from, bound read-only
    /// into each dpkg cage: one only this run writes, so what `dpkg` reads is
    /// what the extraction verified.
    pub(crate) archives_host: &'a Path,
    /// The packages to install, in the order they were resolved.
    pub(crate) installables: &'a [Installable],
    /// The ownership and mode records dpkg is seeded with.
    pub(crate) statoverride: &'a StatOverride,
    /// The map the wave's cages run under, deciding whether the
    /// single-identity ownership reconciliation happens at all.
    pub(crate) identity_map: &'a IdentityMap,
    /// The maintainer-script environment.
    pub(crate) env: &'a [(String, String)],
    /// The `SOURCE_DATE_EPOCH` that environment carries, if any, by which the
    /// accounts the scripts create are [dated](date_accounts).
    pub(crate) source_date_epoch: Option<i64>,
}

/// Configures every unpacked package, leaving a consistent dpkg database.
///
/// `wave` carries the packages, the maintainer-script environment, and the
/// identity map the cages run under, which decides whether the single-identity
/// ownership reconciliation happens at all. `repositories` compose the
/// `sources.list` and `sources.list.d` entries written into the finished
/// rootfs, each signed repository's keyring written there as its `signed-by`
/// trust anchor so the sources verify. `observer` receives dpkg's output.
///
/// Once the last wave has run, what it recorded of its own run is
/// [cleared](clear_run_state), so the finished rootfs carries no log of the
/// bootstrap and no machine identity it generated. With an epoch, the accounts
/// the scripts created are [dated](date_accounts) by it.
///
/// Under the single-identity map the reconciliation neutralizes the
/// [`chown`/`chgrp` commands](OWNERSHIP_TOOLS), so a maintainer script that
/// shells out to one to assign an id the map cannot represent succeeds. That is
/// the whole of the coverage: a script reaching `fchownat()` through a compiled
/// helper, or setting a POSIX ACL, fails with `EINVAL`, and a package that does
/// so cannot be configured under this map at all.
pub(crate) fn configure(
    staging: &Path,
    wave: &Configure<'_>,
    repositories: &[Repository],
    overlay: Option<&Path>,
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    let &Configure {
        installables,
        statoverride,
        identity_map,
        source_date_epoch,
        // Read by the dpkg waves this hands the gathered value down to.
        archives_host: _,
        env: _,
    } = wave;
    // Under a range map every id Debian assigns is real and every chown
    // works; the reconciliation below exists solely for the single-identity
    // map, where no id but root can be represented.
    let single = matches!(identity_map, IdentityMap::Single);

    // Every host-side step below is anchored to this descriptor, so a symbolic
    // link a maintainer script leaves behind cannot redirect one out of the
    // tree. The cages are rooted by path, which the kernel resolves once, at
    // the pivot.
    let tree = open_tree(staging)?;
    // What the accounts' dates were before any script ran, so that afterwards
    // the ones the run wrote can be told from the ones it found.
    let found = found_dates(source_date_epoch, &tree, None)?;

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
    core_install("base-passwd", staging, wave, observer)?;
    if single {
        write_statoverride(&tree, statoverride)?;
        precreate_shadow(&tree)?;
    }

    // The rest of the base system.
    for name in &CORE_ORDER[1..] {
        core_install(name, staging, wave, observer)?;
    }
    // The real mawk replaces the temporary awk symlink.
    remove_awk_symlink(&tree)?;
    core_install("mawk", staging, wave, observer)?;

    // Unpack registers every package in the database and lays its files;
    // this re-lays coreutils, so the ownership stubs are reinstalled before
    // configuration runs the maintainer scripts.
    write_dselect_method(&tree)?;
    let mut unpack: Vec<&str> = vec!["--force-depends", "--unpack"];
    unpack.extend(installables.iter().map(|p| p.deb_path.as_str()));
    run_dpkg("unpack", staging, Rooting::Whole, &unpack, wave, observer)?;

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
        super::super::extract::overlay_tree(staging, overlay, None)
            .map_err(DebianError::Overlay)?;
    }

    run_dpkg(
        "configure",
        staging,
        Rooting::Whole,
        &[
            "--configure",
            "--pending",
            "--force-configure-any",
            "--force-depends",
        ],
        wave,
        observer,
    )?;

    // Restore the real tools, remove the bootstrap-only files and what the
    // waves recorded of the run, then write the finished rootfs's apt sources.
    if single {
        restore_ownership_stubs(&tree)?;
    }
    remove_policy_rc_d(&tree)?;
    clear_run_state(&tree)?;
    if let (Some(epoch), Some(found)) = (source_date_epoch, &found) {
        date_accounts(&tree, found, epoch)?;
    }
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
/// maintainer script that shells out to one of those commands to assign an id
/// the map cannot represent succeeds; those shims shadow the base's real tools
/// through the overlay and are removed afterward. The coverage stops exactly
/// where [`configure`]'s does — a compiled helper or a POSIX ACL still fails —
/// and the overlay is not the variable: an increment runs under the map of the
/// base it increments, so a package needing real ids fails here for the same
/// reason it fails in a full bootstrap. What the increment's waves record of
/// their run is [cleared](clear_run_state) from the upper as a full bootstrap
/// clears it from the rootfs, and with an epoch the accounts they created are
/// [dated](date_accounts) there.
///
/// `overlay_source` is the caller's pre-configure overlay, laid over the upper
/// between the unpack and configure waves exactly as for a full bootstrap.
pub(crate) fn configure_delta(
    lower: &Path,
    upper: &Path,
    wave: &Configure<'_>,
    overlay_source: Option<&Path>,
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    let &Configure {
        installables,
        statoverride,
        identity_map,
        source_date_epoch,
        // Read by the dpkg waves this hands the gathered value down to.
        archives_host: _,
        env: _,
    } = wave;
    let single = matches!(identity_map, IdentityMap::Single);

    // The increment's own tree, which every host-side step below is anchored
    // to, over the base so a directory a step creates never hides a link the
    // base holds; the base is otherwise opened where it is read.
    let base = open_tree(lower)?;
    let tree = open_tree(upper)?
        .over(Some(&base))
        .map_err(DebianError::at("opening the tree", upper))?;
    // The accounts' dates before any script runs, the base's where the upper
    // holds no file of its own yet.
    let found = found_dates(source_date_epoch, &tree, Some(&base))?;

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
    run_dpkg(
        "unpack",
        upper,
        Rooting::Over(lower),
        &unpack,
        wave,
        observer,
    )?;

    // The caller's pre-configure overlay, after unpack so it overwrites the
    // just-unpacked files — a shipped conffile among them — and before configure
    // so the maintainer scripts read the injected values.
    if let Some(source) = overlay_source {
        super::super::extract::overlay_tree(upper, source, Some(lower))
            .map_err(DebianError::Overlay)?;
    }

    run_dpkg(
        "configure",
        upper,
        Rooting::Over(lower),
        &[
            "--configure",
            "--pending",
            "--force-configure-any",
            "--force-depends",
        ],
        wave,
        observer,
    )?;

    // Reveal the base's real ownership tools through the overlay again, and drop
    // the daemon-startup policy and what the increment's waves recorded of their
    // run. Removing a record from the upper reveals whatever copy the base holds
    // at that path, which is the base's own; a base this library bootstrapped
    // holds none.
    if single {
        restore_delta_ownership_stubs(&tree)?;
    }
    remove_policy_rc_d(&tree)?;
    clear_run_state(&tree)?;
    if let (Some(epoch), Some(found)) = (source_date_epoch, &found) {
        date_accounts(&tree, found, epoch)?;
    }

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
///
/// Conditional on the file still holding the stub body, for the reason
/// [`restore_ownership_stubs`]'s deletion is: the increment's own unpack wave
/// runs after the stubs are written, so a package it installs — or the caller's
/// pre-configure overlay — may have laid a real tool over one. Removing that
/// would delete a file the merged database says the increment installed, and
/// reveal the base's older copy in its place. Anything the read refuses to
/// follow, a symbolic link at the path among them, survives for the same
/// reason.
fn restore_delta_ownership_stubs(upper: &Rooted) -> Result<(), DebianError> {
    for tool in OWNERSHIP_TOOLS {
        let path = format!("usr/bin/{tool}");
        if is_ownership_stub(upper, &path) {
            remove_if_present(upper, &path)?;
        }
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
    let base = match read_text_if_present(&base_tree, STATOVERRIDE, MAX_STATOVERRIDE) {
        Ok(text) => text.unwrap_or_default(),
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

/// Forwards a wave's dpkg output to the bootstrap's observer, keeping enough of
/// stderr that a failing wave can name the packages dpkg reported.
struct DpkgOutput<'a> {
    emit: &'a mut dyn DebianObserver,
    /// The tail of dpkg's stderr, bounded at [`DPKG_STDERR_KEPT`] and discarded
    /// from the front: the list [`failed_packages`] reads is the last thing
    /// dpkg writes, so what a bound drops is the unpack output ahead of it.
    stderr_tail: Vec<u8>,
}

/// How much of a wave's stderr is kept to read its failure list out of. The
/// whole of it is unbounded — a line per package acted on, plus whatever the
/// maintainer scripts write — while the list sits at its end.
const DPKG_STDERR_KEPT: usize = 64 * 1024;

/// The line dpkg prints before listing the packages a wave failed on. Each name
/// follows on its own line, indented by one space.
///
/// dpkg translates this message, so reading it is sound only because the wave's
/// locale is this library's to set rather than a caller's: [`maintainer_env`]
/// pins `LC_ALL=C.UTF-8` and is internal, so no caller can put dpkg into a
/// locale that renders the line otherwise.
///
/// [`maintainer_env`]: super::maintainer_env
const DPKG_ERROR_LIST: &str = "Errors were encountered while processing:";

/// The packages dpkg named under [`DPKG_ERROR_LIST`], in the order it listed
/// them.
///
/// Empty when the output holds no such list, which is every wave that failed
/// for a reason no package owns. The last list wins: a maintainer script is
/// free to run dpkg itself, and that dpkg writes to the stderr it inherited —
/// so its summary can precede the one the wave itself ends with.
fn failed_packages(stderr: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(stderr);
    let Some((_, list)) = text.rsplit_once(DPKG_ERROR_LIST) else {
        return Vec::new();
    };
    list.lines()
        .skip(1)
        .take_while(|line| line.starts_with(' ') && !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect()
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
        self.stderr_tail.extend_from_slice(chunk);
        if self.stderr_tail.len() > DPKG_STDERR_KEPT {
            let excess = self.stderr_tail.len() - DPKG_STDERR_KEPT;
            self.stderr_tail.drain(..excess);
        }
    }
}

/// Installs one core package by name, if it is in the selection.
fn core_install(
    name: &str,
    staging: &Path,
    wave: &Configure<'_>,
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    let installables = wave.installables;
    if let Some(package) = installables.iter().find(|p| p.name == name) {
        run_dpkg(
            "core install",
            staging,
            // The core waves are the full bootstrap's alone: a layered build
            // installs no base system, since its base already carries one.
            Rooting::Whole,
            &["--force-depends", "--install", &package.deb_path],
            wave,
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

/// Runs one dpkg wave in a cage rooted for `staging`, under the bootstrap's
/// identity map.
///
/// `rooting` decides what the wave sees. A full bootstrap roots on the staging
/// tree alone; a layered build roots on an overlay of the pristine base and the
/// increment's upper, so dpkg reads the base's configured database and lands its
/// writes in the disposable upper.
///
/// The observer is asked whether to stop before the wave starts. A wave runs
/// for minutes and is not interrupted once begun, so the boundary between two
/// waves is where a cancelled bootstrap stops; the tree it leaves is discarded
/// whole, so a half-configured database is not a hazard.
fn run_dpkg(
    name: &'static str,
    staging: &Path,
    rooting: Rooting<'_>,
    args: &[&str],
    wave: &Configure<'_>,
    observer: &mut dyn DebianObserver,
) -> Result<(), DebianError> {
    if observer.cancelled() {
        return Err(DebianError::Cancelled);
    }
    let &Configure {
        archives_host,
        identity_map,
        env,
        // The wave's own selection is spelled out in `args` by the caller,
        // which is what dpkg is told to act on.
        installables: _,
        statoverride: _,
        // The scripts read it from `env`; the dates are the caller's to fix.
        source_date_epoch: _,
    } = wave;
    let cage = rooting
        .builder(staging)
        .command("/usr/bin/dpkg")
        .args(args)
        // Read-only so a wave cannot rewrite the packages it installs, in the
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
    let mut output = DpkgOutput {
        emit: observer,
        stderr_tail: Vec::new(),
    };
    let status = cage.run_with(&mut output).map_err(DebianError::Launch)?;
    if status.success() {
        Ok(())
    } else {
        Err(DebianError::Configure {
            wave: name,
            status,
            packages: failed_packages(&output.stderr_tail),
        })
    }
}

/// The packages the tree's dpkg status database records as `install ok
/// installed`.
fn installed_packages(tree: &Rooted) -> Result<HashSet<String>, DebianError> {
    let text = read_text(tree, STATUS, MAX_STATUS).map_err(at(
        "reading the dpkg status database",
        tree,
        STATUS,
    ))?;
    let mut installed = HashSet::new();
    for stanza in document::parse(&text) {
        if let (Some(name), Some(status)) = (stanza.get("Package"), stanza.get("Status"))
            && status == "install ok installed"
        {
            installed.insert(name.to_string());
        }
    }
    Ok(installed)
}

/// Verifies every selected package reached `install ok installed`.
fn verify_installed(tree: &Rooted, selected: &[String]) -> Result<(), DebianError> {
    let installed = installed_packages(tree)?;
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

/// Each account's last-change day before the scripts run, where an epoch is
/// given; see [`accounts::account_dates`]. `beneath` is a layered build's
/// base.
fn found_dates(
    epoch: Option<i64>,
    tree: &Rooted,
    beneath: Option<&Rooted>,
) -> Result<Option<accounts::Dates>, DebianError> {
    epoch
        .map(|_| accounts::account_dates(tree, beneath).map_err(accounts_failure))
        .transpose()
}

/// Records the epoch's day where `systemd-sysusers` wrote 1970's first day as
/// a zero.
///
/// The tools a Debian bootstrap creates accounts with all date them by
/// `SOURCE_DATE_EPOCH`, and they disagree about one day. shadow's `useradd`
/// and `pwconv` leave the field empty for an epoch in 1970's first day, since
/// a zero demands a new password at the next login. `systemd-sysusers` writes
/// the epoch's day as it is, zero included. So under such an epoch, a zero the
/// run wrote is that day, and it is recorded as
/// [`last_change_day`](accounts::last_change_day) records it. Only the fields
/// the run wrote are touched, as [`accounts::redate`] describes. Under a later
/// epoch every tool wrote the day itself, and nothing is rewritten.
fn date_accounts(tree: &Rooted, found: &accounts::Dates, epoch: i64) -> Result<(), DebianError> {
    if epoch / accounts::SECONDS_PER_DAY != 0 {
        return Ok(());
    }
    let day = accounts::last_change_day(epoch);
    accounts::redate(tree, found, day.as_bytes(), |field| field == b"0").map_err(accounts_failure)
}

/// An accounts step's failure, reported as this layer's own.
fn accounts_failure(failure: accounts::Failure) -> DebianError {
    DebianError::io(failure.op, failure.path, failure.source)
}

/// Removes what the configure waves leave that belongs to their run rather
/// than to the root: the [run records](RUN_RECORDS) and the machine identity a
/// maintainer script generated.
///
/// Each step looks at what holds the path before it acts, without following
/// it. A record is removed whatever it is, a symbolic link as the name it is,
/// except for an overlay whiteout: in a layered build's upper that is the run
/// having deleted the base's copy, and removing it would bring the base's copy
/// back.
///
/// The machine id is emptied only where a script wrote one: a regular file
/// with something in it, emptied in place, so the owner and mode the script
/// gave it are the ones it keeps. A root without `systemd` carries no file, and
/// creating one would add state no package asked for. An empty file, a
/// symbolic link, and a whiteout are none of them an id this run generated,
/// and are left as they are.
///
/// The mechanism is Alpine's `clear_run_state` and the policy is not: an
/// Alpine root boots without `systemd`, and removes the id where this one
/// empties it.
fn clear_run_state(tree: &Rooted) -> Result<(), DebianError> {
    for path in RUN_RECORDS.into_iter().chain([DBUS_MACHINE_ID]) {
        tree.remove_if(path, |stat| !Rooted::is_whiteout(stat))
            .map_err(at("removing", tree, path))?;
    }
    tree.truncate_if(MACHINE_ID, Rooted::is_file_with_content)
        .map_err(at("emptying", tree, MACHINE_ID))
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
        } else if is_ownership_stub(tree, &path) {
            remove_if_present(tree, &path)?;
        }
    }
    Ok(())
}

/// Whether the file at `path` still holds the ownership stub's body.
///
/// Read no further than the stub's own length: a file longer than that is not
/// the stub, whatever it holds, and the read refuses it rather than holding it.
/// Anything the read refuses, a symbolic link at the path among them, is not
/// the stub either.
fn is_ownership_stub(tree: &Rooted, path: &str) -> bool {
    tree.read(path, OWNERSHIP_STUB.len() as u64)
        .is_ok_and(|body| body == OWNERSHIP_STUB.as_bytes())
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
/// The primary repository (index zero) owns `/etc/apt/sources.list`. Each
/// additional repository writes `/etc/apt/sources.list.d/<name>.list` and, when
/// signed, its own `/usr/share/keyrings/<name>.gpg`, referenced by a
/// `signed-by` so an in-rootfs `apt-get update` verifies it against the keyring
/// the bootstrap verified it against. An unsigned repository writes a
/// `[trusted=yes]` line and no keyring, apt's own posture for a source under
/// the caller's control. Each source names the repository's primary mirror; a
/// snapshot backstop is a fetch-time concern and is not written into the
/// installed system.
///
/// The primary's keyring depends on where it came from. A keyring of the
/// caller's is written at [`TRUST_ANCHOR_STEM`], a path no package ships, so
/// it stays the caller's to rotate. Where the bootstrap verified against the
/// embedded archive keyring, the line names the keyring the
/// `debian-archive-keyring` package installed instead, and writes nothing: the
/// package carries the same keys and its upgrades deliver the ones the archive
/// rotates to, which a copy written now would never learn. A root that does
/// not hold the package, which is one without `apt`, gets the embedded keyring
/// at [`TRUST_ANCHOR_STEM`], so its line still verifies.
fn write_repository_sources(tree: &Rooted, repositories: &[Repository]) -> Result<(), DebianError> {
    for (index, repository) in repositories.iter().enumerate() {
        let (list_path, anchor_path) = if index == 0 {
            (
                "etc/apt/sources.list".to_string(),
                keyring_path(TRUST_ANCHOR_STEM),
            )
        } else {
            // Distinct across the set, the primary's anchor included: the
            // configuration refuses two repositories that would write the same
            // keyring or the same sources file.
            let stem = repository.entry_stem(index);
            (
                format!("etc/apt/sources.list.d/{stem}.list"),
                keyring_path(&stem),
            )
        };

        let options = match &repository.trust {
            Trust::Archive if ships_archive_keyring(tree)? => {
                format!("[signed-by={}]", keyring_path(PACKAGE_KEYRING_STEM))
            }
            Trust::Archive => {
                write_keyring(tree, &anchor_path, super::EMBEDDED_KEYRING)?;
                format!("[signed-by={anchor_path}]")
            }
            Trust::Signed(keyring) => {
                write_keyring(tree, &anchor_path, keyring)?;
                format!("[signed-by={anchor_path}]")
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

/// Whether the tree holds the archive keyring [`ARCHIVE_KEYRING_PACKAGE`]
/// ships, at the path a sources line names it by.
///
/// Asked of dpkg's own records rather than of the file. The status database
/// says whether the package is installed, and the package's file list says
/// whether it owns the path: a file a script left there, or one a later
/// release of the package stops shipping, is not one an upgrade keeps current.
fn ships_archive_keyring(tree: &Rooted) -> Result<bool, DebianError> {
    if !installed_packages(tree)?.contains(ARCHIVE_KEYRING_PACKAGE) {
        return Ok(false);
    }
    let list = format!("var/lib/dpkg/info/{ARCHIVE_KEYRING_PACKAGE}.list");
    let files = match read_text_if_present(tree, &list, MAX_FILE_LIST) {
        Ok(Some(files)) => files,
        Ok(None) => return Ok(false),
        Err(source) => return Err(at("reading the package's file list", tree, &list)(source)),
    };
    let keyring = keyring_path(PACKAGE_KEYRING_STEM);
    Ok(files.lines().any(|line| line == keyring))
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
    read_text(&Rooted::open(base)?, STATUS, MAX_STATUS)
}

/// Opens a tree for the host-side steps that read and write inside it.
fn open_tree(root: &Path) -> Result<Rooted, DebianError> {
    Rooted::open(root).map_err(DebianError::at("opening the tree", root))
}

/// Reads a file of the tree as text, as [`std::fs::read_to_string`] would:
/// invalid UTF-8 is an `InvalidData` failure rather than lossily decoded. A
/// file past `limit` bytes is refused, as [`Rooted::read`] refuses it.
fn read_text(tree: &Rooted, rootfs_path: &str, limit: u64) -> io::Result<String> {
    text(tree.read(rootfs_path, limit)?)
}

/// [`read_text`], with `None` where the tree holds no file at the path, as
/// [`Rooted::read_if_present`] answers it.
fn read_text_if_present(
    tree: &Rooted,
    rootfs_path: &str,
    limit: u64,
) -> io::Result<Option<String>> {
    tree.read_if_present(rootfs_path, limit)?
        .map(text)
        .transpose()
}

/// `bytes` as text, refusing invalid UTF-8 as [`std::fs::read_to_string`]
/// does.
fn text(bytes: Vec<u8>) -> io::Result<String> {
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
    fn a_delta_restores_only_the_stubs_it_wrote() {
        // The increment's unpack wave runs after the stubs are written, so a
        // package it installs can lay a real tool over one. Removing that would
        // delete a file the merged database says is installed and reveal the
        // base's older copy through the overlay in its place.
        let (upper, tree) = rooted_tree("delta-ownership-stubs");
        install_delta_ownership_stubs(&tree).expect("the stubs are written");
        // What an unpack of a real coreutils leaves behind.
        let real = b"\x7fELF real chown\n";
        tree.write("usr/bin/chown", real)
            .expect("the real tool lands");

        restore_delta_ownership_stubs(&tree).expect("the stubs are restored");

        assert_eq!(
            fs::read(upper.join("usr/bin/chown")).expect("the real tool survives"),
            real,
        );
        assert!(
            !upper.join("usr/bin/chgrp").exists(),
            "an untouched stub is still removed, revealing the base's tool",
        );
    }

    #[test]
    fn a_cancelled_bootstrap_stops_before_the_next_wave() {
        // A wave runs for minutes and is not interrupted once begun, so the
        // boundary before one is where a cancelled bootstrap stops, and it stops
        // before a sandbox is built for the wave.
        struct Stop;
        impl DebianObserver for Stop {
            fn cancelled(&mut self) -> bool {
                true
            }
        }
        let scratch = Scratch::for_test("bootstrap", "cancelled-wave");
        let wave = Configure {
            archives_host: &scratch.join("archives"),
            installables: &[],
            statoverride: &StatOverride::default(),
            identity_map: &IdentityMap::Single,
            env: &[],
            source_date_epoch: None,
        };
        let outcome = run_dpkg(
            "configure",
            &scratch.join("no-such-tree"),
            Rooting::Whole,
            &["--configure", "--pending"],
            &wave,
            &mut Stop,
        );
        assert!(
            matches!(outcome, Err(DebianError::Cancelled)),
            "{outcome:?}"
        );
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
        let anchor = staging.join(keyring_path(TRUST_ANCHOR_STEM).trim_start_matches('/'));
        assert_eq!(
            fs::read(&anchor).expect("the anchor exists"),
            b"keyring-bytes",
        );
        let sources = fs::read_to_string(staging.join("etc/apt/sources.list"))
            .expect("the sources.list exists");
        assert_eq!(
            sources,
            format!(
                "deb [signed-by={}] http://deb.debian.org/debian trixie main contrib\n",
                keyring_path(TRUST_ANCHOR_STEM)
            ),
        );
    }

    /// A primary verified against the embedded archive keyring, the default.
    fn archive_repo() -> Repository {
        Repository {
            mirrors: vec!["http://deb.debian.org/debian".to_string()],
            suite: "trixie".to_string(),
            components: vec!["main".to_string()],
            trust: Trust::Archive,
            allow_stale: false,
            name: None,
        }
    }

    /// Records the keyring package in the tree's dpkg database at `status`,
    /// owning `owns`, and lays its keyring where it ships one.
    fn record_keyring_package(tree: &Rooted, status: &str, owns: &[&str]) {
        tree.write(
            STATUS,
            format!(
                "Package: base-files\nStatus: install ok installed\nVersion: 13.8\n\n\
                 Package: {ARCHIVE_KEYRING_PACKAGE}\nStatus: {status}\nVersion: 2025.1\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let mut list = String::from("/.\n/usr/share/keyrings\n");
        for path in owns {
            list.push_str(path);
            list.push('\n');
        }
        tree.write(
            format!("var/lib/dpkg/info/{ARCHIVE_KEYRING_PACKAGE}.list"),
            list.as_bytes(),
        )
        .unwrap();
        tree.write(
            keyring_path(PACKAGE_KEYRING_STEM),
            b"the keys the package keeps current",
        )
        .unwrap();
    }

    #[test]
    fn a_default_primary_names_the_keyring_its_package_keeps_current() {
        // The archive rotates its signing keys and delivers new ones through
        // the keyring package's upgrades, so a root verified against the
        // embedded keyring names the package's file rather than a copy that
        // would never learn them, and writes nothing over it.
        let (staging, tree) = rooted_tree("sources-archive-keyring");
        record_keyring_package(
            &tree,
            "install ok installed",
            &[&keyring_path(PACKAGE_KEYRING_STEM)],
        );

        write_repository_sources(&tree, &[archive_repo()]).expect("the sources are written");

        assert_eq!(
            fs::read_to_string(staging.join("etc/apt/sources.list")).unwrap(),
            format!(
                "deb [signed-by={}] http://deb.debian.org/debian trixie main\n",
                keyring_path(PACKAGE_KEYRING_STEM)
            ),
        );
        assert_eq!(
            fs::read(staging.join(keyring_path(PACKAGE_KEYRING_STEM).trim_start_matches('/')))
                .unwrap(),
            b"the keys the package keeps current",
            "the package's keyring is the package's",
        );
        assert!(
            fs::symlink_metadata(
                staging.join(keyring_path(TRUST_ANCHOR_STEM).trim_start_matches('/'))
            )
            .is_err(),
            "no copy of the keys is written",
        );
    }

    #[test]
    fn a_default_primary_without_the_keyring_package_gets_the_embedded_keyring() {
        // A root without apt holds no keyring package, or dpkg's records do not
        // say it ships the file a line would name. The embedded keyring is then
        // written at the private stem, so the line still verifies.
        let anchor = keyring_path(TRUST_ANCHOR_STEM);
        for (tag, status, owns) in [
            ("absent", None, &[][..]),
            (
                "unpacked",
                Some("install ok unpacked"),
                &[&*keyring_path(PACKAGE_KEYRING_STEM)][..],
            ),
            (
                "unowned",
                Some("install ok installed"),
                &["/usr/share/keyrings/other.pgp"][..],
            ),
        ] {
            let (staging, tree) = rooted_tree(&format!("sources-archive-{tag}"));
            match status {
                Some(status) => record_keyring_package(&tree, status, owns),
                None => tree
                    .write(
                        STATUS,
                        b"Package: base-files\nStatus: install ok installed\n",
                    )
                    .unwrap(),
            }

            write_repository_sources(&tree, &[archive_repo()]).expect("the sources are written");

            assert_eq!(
                fs::read_to_string(staging.join("etc/apt/sources.list")).unwrap(),
                format!("deb [signed-by={anchor}] http://deb.debian.org/debian trixie main\n"),
                "{tag}",
            );
            assert_eq!(
                fs::read(staging.join(anchor.trim_start_matches('/'))).unwrap(),
                super::super::EMBEDDED_KEYRING,
                "{tag}",
            );
        }
    }

    #[test]
    fn a_callers_keyring_stays_at_the_private_stem_beside_the_package() {
        // A caller's keyring is the caller's to rotate, and the package's
        // upgrades must not replace it, so it is written where no package
        // writes even when the keyring package is installed.
        let (staging, tree) = rooted_tree("sources-caller-keyring");
        record_keyring_package(
            &tree,
            "install ok installed",
            &[&keyring_path(PACKAGE_KEYRING_STEM)],
        );
        let primary = signed_repo(
            "http://deb.debian.org/debian",
            "trixie",
            &["main"],
            b"the caller's keys",
            None,
        );

        write_repository_sources(&tree, &[primary]).expect("the sources are written");

        let anchor = keyring_path(TRUST_ANCHOR_STEM);
        assert_eq!(
            fs::read_to_string(staging.join("etc/apt/sources.list")).unwrap(),
            format!("deb [signed-by={anchor}] http://deb.debian.org/debian trixie main\n"),
        );
        assert_eq!(
            fs::read(staging.join(anchor.trim_start_matches('/'))).unwrap(),
            b"the caller's keys",
        );
        assert_eq!(
            fs::read(staging.join(keyring_path(PACKAGE_KEYRING_STEM).trim_start_matches('/')))
                .unwrap(),
            b"the keys the package keeps current",
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
            format!(
                "deb [signed-by={}] file:///srv/pool trixie main\n",
                keyring_path(TRUST_ANCHOR_STEM)
            ),
        );
        assert_eq!(
            fs::read_link(staging.join("usr/bin/awk")).unwrap(),
            Path::new("mawk"),
        );
        assert!(fs::symlink_metadata(staging.join("usr/sbin/policy-rc.d")).is_err());
    }

    /// What `systemd-sysusers` writes for an account it creates under an epoch
    /// in 1970's first day, beside what shadow's `useradd` writes for one, and
    /// a package's own account that ships with no date.
    const DAY_ZERO_SHADOW: &[u8] = b"root:*::0:99999:7:::\n\
        systemd-network:!*:0::::::\n\
        _apt:!::0:99999:7:::\n";

    #[test]
    fn the_first_day_of_1970_is_recorded_as_no_date_whatever_wrote_it() {
        // A zero demands a new password at the next login, which is not what
        // the epoch meant; useradd leaves the field empty for the same day.
        for epoch in [0, 86_399] {
            let (staging, tree) = rooted_tree("day-zero");
            for path in accounts::SHADOW {
                tree.write_mode(path, DAY_ZERO_SHADOW, 0o640).unwrap();
            }
            date_accounts(&tree, &accounts::Dates::new(), epoch).expect("the accounts are dated");
            for path in accounts::SHADOW {
                assert_eq!(
                    fs::read(staging.join(path)).unwrap(),
                    b"root:*::0:99999:7:::\nsystemd-network:!*:::::::\n_apt:!::0:99999:7:::\n",
                    "{path} under {epoch}",
                );
            }
        }
    }

    #[test]
    fn a_zero_is_a_date_only_under_the_epoch_whose_day_it_is() {
        // Under any later epoch every tool wrote that day itself, so a zero
        // the run wrote is a script's demand for a new password, and is kept.
        let (staging, tree) = rooted_tree("day-zero-later-epoch");
        tree.write_mode("etc/shadow", DAY_ZERO_SHADOW, 0o640)
            .unwrap();
        date_accounts(&tree, &accounts::Dates::new(), 86_400).expect("nothing to date");
        assert_eq!(
            fs::read(staging.join("etc/shadow")).unwrap(),
            DAY_ZERO_SHADOW
        );

        // And a zero the run found, in a layered build's base, is the base's
        // own whatever the epoch.
        let (_base_dir, base) = rooted_tree("day-zero-base");
        base.write("etc/shadow", b"root:*:0:0:99999:7:::\n")
            .unwrap();
        let (upper_dir, upper) = rooted_tree("day-zero-upper");
        let found = found_dates(Some(0), &upper, Some(&base))
            .expect("the accounts read")
            .expect("an epoch was given");
        upper
            .write(
                "etc/shadow",
                b"root:*:0:0:99999:7:::\nsystemd-network:!*:0::::::\n",
            )
            .unwrap();
        date_accounts(&upper, &found, 0).expect("the accounts are dated");
        assert_eq!(
            fs::read(upper_dir.join("etc/shadow")).unwrap(),
            b"root:*:0:0:99999:7:::\nsystemd-network:!*:::::::\n",
        );
        assert_eq!(found_dates(None, &upper, Some(&base)).unwrap(), None);
    }

    #[test]
    fn the_run_state_is_cleared_and_the_machine_id_emptied() {
        // What the waves left of their own run: two logs, the ldconfig cache,
        // and the two copies of a machine id the scripts generated.
        let (staging, tree) = rooted_tree("run-state");
        let id = b"bab73fe9c7e4506ef70334906ab8378f\n";
        for path in RUN_RECORDS {
            tree.write(path, b"recorded during the run\n").unwrap();
        }
        tree.write(DBUS_MACHINE_ID, id).unwrap();
        tree.write_mode(MACHINE_ID, id, 0o444).unwrap();
        let written = fs::metadata(staging.join(MACHINE_ID)).unwrap();

        clear_run_state(&tree).expect("the run state is cleared");

        for path in RUN_RECORDS.into_iter().chain([DBUS_MACHINE_ID]) {
            assert!(
                fs::symlink_metadata(staging.join(path)).is_err(),
                "{path} is removed",
            );
        }
        // The system's id is kept as a file, empty, so the machine the root is
        // deployed to generates its own. It is the file the script wrote,
        // emptied in place: read-only, as `systemd` writes it, and the same
        // inode, so its owner and group are the ones the script left.
        let machine_id = staging.join(MACHINE_ID);
        assert_eq!(fs::read(&machine_id).unwrap(), b"");
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let emptied = fs::metadata(&machine_id).unwrap();
        assert_eq!(emptied.permissions().mode() & 0o7777, 0o444);
        assert_eq!(emptied.ino(), written.ino());
    }

    #[test]
    fn a_machine_id_grown_without_writing_is_emptied_without_being_read() {
        // A script can make the id enormous for nothing, since a sparse file
        // takes no space. Emptying asks the file's size, never its contents.
        let (staging, tree) = rooted_tree("machine-id-sparse");
        tree.write_mode(MACHINE_ID, b"", 0o444).unwrap();
        let machine_id = staging.join(MACHINE_ID);
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&machine_id, fs::Permissions::from_mode(0o644)).unwrap();
        fs::File::options()
            .write(true)
            .open(&machine_id)
            .unwrap()
            .set_len(1 << 40)
            .unwrap();

        clear_run_state(&tree).expect("the run state is cleared");

        assert_eq!(fs::metadata(&machine_id).unwrap().len(), 0);
    }

    #[test]
    fn a_layered_upper_keeps_the_whiteouts_its_run_left() {
        // In an overlay upper, a whiteout is the run having deleted the base's
        // copy. Removing it, or emptying through it, would bring the base's
        // copy back through the overlay.
        let (staging, tree) = rooted_tree("run-state-whiteouts");
        let mut whiteouts = Vec::new();
        for path in RUN_RECORDS.into_iter().chain([DBUS_MACHINE_ID, MACHINE_ID]) {
            let at = staging.join(path);
            fs::create_dir_all(at.parent().unwrap()).unwrap();
            match rustix::fs::mknodat(
                rustix::fs::CWD,
                &at,
                rustix::fs::FileType::CharacterDevice,
                rustix::fs::Mode::empty(),
                0,
            ) {
                Ok(()) => whiteouts.push(at),
                Err(rustix::io::Errno::PERM) => {
                    eprintln!("skipping: this kernel refuses an unprivileged whiteout");
                    return;
                }
                Err(errno) => panic!("making a whiteout: {errno}"),
            }
        }

        clear_run_state(&tree).expect("the run state is cleared");

        for at in whiteouts {
            let kept = fs::symlink_metadata(&at).expect("the whiteout is kept");
            assert!(
                std::os::unix::fs::FileTypeExt::is_char_device(&kept.file_type()),
                "{}",
                at.display(),
            );
        }
    }

    #[test]
    fn a_root_without_a_machine_id_is_not_given_one() {
        // A root without systemd carries no machine id, and clearing the run's
        // state creates none; an already-empty one is not rewritten.
        let (staging, tree) = rooted_tree("no-machine-id");
        clear_run_state(&tree).expect("an absent state clears");
        assert!(fs::symlink_metadata(staging.join(MACHINE_ID)).is_err());

        tree.write_mode(MACHINE_ID, b"", 0o644).unwrap();
        clear_run_state(&tree).expect("an empty id clears");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(staging.join(MACHINE_ID))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o644,
            "an empty id is left as it stands",
        );
    }

    #[test]
    fn a_link_at_a_run_record_cannot_reach_out_of_the_tree() {
        // The cleanup runs after every maintainer script, so a script can leave
        // a link at any of the paths it clears. A link at a record is removed as
        // the name it is; a link at the machine id is not an id the run
        // generated, and the file it names is not emptied through it.
        let (staging, tree) = rooted_tree("run-state-links");
        let victim = staging.join("victim");
        fs::write(&victim, b"host contents\n").unwrap();
        for path in ["var/log/dpkg.log", MACHINE_ID] {
            let planted = staging.join(path);
            fs::create_dir_all(planted.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&victim, &planted).unwrap();
        }

        clear_run_state(&tree).expect("the run state is cleared");

        assert_eq!(fs::read(&victim).unwrap(), b"host contents\n");
        assert!(fs::symlink_metadata(staging.join("var/log/dpkg.log")).is_err());
        assert_eq!(fs::read_link(staging.join(MACHINE_ID)).unwrap(), victim);
    }

    #[test]
    fn a_named_pipe_at_the_machine_id_does_not_stall_the_cleanup() {
        // The cleanup reads the machine id after every maintainer script has
        // run, and a script can leave a named pipe there, which a plain open
        // for reading waits on for a writer. The cleanup answers at once and
        // leaves the pipe alone, as it leaves anything that is not an id.
        let (staging, tree) = rooted_tree("machine-id-fifo");
        let pipe = staging.join(MACHINE_ID);
        fs::create_dir_all(pipe.parent().unwrap()).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &pipe,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();

        let (answer, answered) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = answer.send(clear_run_state(&tree).is_ok());
        });
        assert!(
            answered
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("the cleanup answers rather than waiting for a writer"),
            "the cleanup succeeds",
        );
        use std::os::unix::fs::FileTypeExt;
        assert!(fs::symlink_metadata(&pipe).unwrap().file_type().is_fifo());
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
    fn a_failing_wave_names_the_packages_dpkg_listed() {
        // The shape dpkg writes to stderr when a wave fails: the per-package
        // error, then the summary list the name comes out of.
        let stderr = "dpkg: error processing package systemd (--configure):\n \
             installed systemd package post-installation script subprocess \
             returned error exit status 73\n\
             Errors were encountered while processing:\n \
             systemd\n udev\n initramfs-tools-core\n";
        assert_eq!(
            failed_packages(stderr.as_bytes()),
            ["systemd", "udev", "initramfs-tools-core"],
        );
    }

    #[test]
    fn a_wave_that_named_no_package_reports_none() {
        // dpkg exits non-zero for reasons no package owns, and an empty list is
        // the honest answer rather than a guess at one.
        assert!(failed_packages(b"dpkg: error: cannot access archives\n").is_empty());
        assert!(failed_packages(b"").is_empty());
    }

    #[test]
    fn the_last_list_wins_over_one_a_nested_dpkg_left() {
        // A maintainer script may run dpkg itself, on the stderr it inherited,
        // so a summary can precede the one the wave ends with. The wave's own
        // is the later one.
        let stderr = "Errors were encountered while processing:\n nested\n\
             Setting up udev ...\n\
             Errors were encountered while processing:\n udev\n";
        assert_eq!(failed_packages(stderr.as_bytes()), ["udev"]);
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
