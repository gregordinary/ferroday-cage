//! Host support probing for unprivileged user namespaces.
//!
//! The sandbox is built from unprivileged user namespaces, and several common
//! host configurations disable them. [`userns_blocker`] inspects the host for
//! the known ones, so that a denial surfaces as an explanation rather than a
//! raw `EPERM`, and so that test suites can skip sandbox tests explicitly on
//! hosts that cannot run them. [`range_map_blocker`] does the same for
//! uid/gid range maps, whose availability depends on the caller's privilege
//! and, for the delegated tier, on the shadow suite's helpers.

use std::ffi::CString;
use std::fmt;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Mode, OFlags, XattrFlags};
use rustix::io::Errno;
use rustix::rand::GetRandomFlags;

/// A host configuration known to block unprivileged user namespace creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UsernsBlocker {
    /// The `kernel.unprivileged_userns_clone` sysctl is `0`.
    ///
    /// This out-of-tree sysctl appears on Debian-derived kernels; `0` denies
    /// user namespace creation to unprivileged processes.
    UnprivilegedUsernsCloneDisabled,
    /// The `user.max_user_namespaces` sysctl is `0`.
    ///
    /// A limit of zero denies user namespace creation outright.
    MaxUserNamespacesIsZero,
    /// The `user.max_user_namespaces` sysctl is `1`, and a launch needs two.
    ///
    /// The sandbox creates one user namespace, and the command enters a nested
    /// one before it hardens — which is what locks the flags of the mounts the
    /// sandbox established. A namespace is charged against the sysctl at every
    /// level up to the initial namespace, so a ceiling of one admits the first
    /// and refuses the second.
    ///
    /// The condition is necessary and not sufficient, as every blocker here is:
    /// a host whose ceiling is four with three namespaces already live fails
    /// the same way, and only the launch can know that. It surfaces there as
    /// [`Error::NamespaceLimitReached`](crate::Error::NamespaceLimitReached).
    MaxUserNamespacesBelowNesting,
    /// The `kernel.apparmor_restrict_unprivileged_userns` sysctl is `1`.
    ///
    /// On Ubuntu-derived systems this restricts user namespace creation to
    /// programs granted the capability by an AppArmor profile.
    ApparmorRestrictsUnprivilegedUserns,
}

impl fmt::Display for UsernsBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UsernsBlocker::UnprivilegedUsernsCloneDisabled => {
                "the kernel.unprivileged_userns_clone sysctl is 0; set it to 1 to permit \
                 unprivileged user namespace creation"
            }
            UsernsBlocker::MaxUserNamespacesIsZero => {
                "the user.max_user_namespaces sysctl is 0; raise it to permit user \
                 namespace creation"
            }
            UsernsBlocker::MaxUserNamespacesBelowNesting => {
                "the user.max_user_namespaces sysctl is 1, and every launch holds two user \
                 namespaces: the sandbox's own, and the nested one its command enters to \
                 lock the sandbox's mount flags. Raise the sysctl to at least 2"
            }
            UsernsBlocker::ApparmorRestrictsUnprivilegedUserns => {
                "the kernel.apparmor_restrict_unprivileged_userns sysctl is 1; set it to 0, \
                 or grant this program an AppArmor profile that permits user namespace \
                 creation"
            }
        })
    }
}

/// Probes the host for configurations that block unprivileged user namespace
/// creation, returning the first one identified.
///
/// The probe is best-effort and read-only: it inspects sysctl values and
/// creates no namespaces. `None` means no known blocker was found, not a
/// guarantee that namespace creation succeeds — a seccomp filter or an LSM
/// policy can still deny it. The blockers describe creation by unprivileged
/// processes; a privileged process may be exempt from some of them.
pub fn userns_blocker() -> Option<UsernsBlocker> {
    if sysctl_value("/proc/sys/kernel/unprivileged_userns_clone") == Some(0) {
        return Some(UsernsBlocker::UnprivilegedUsernsCloneDisabled);
    }
    // The budget, not merely its presence: a launch holds two user namespaces,
    // so a ceiling of one admits the sandbox's and refuses the nested one the
    // command enters. Reporting that here turns a launch-time `ENOSPC` into a
    // condition a caller can check for before it starts.
    match sysctl_value("/proc/sys/user/max_user_namespaces") {
        Some(0) => return Some(UsernsBlocker::MaxUserNamespacesIsZero),
        Some(1) => return Some(UsernsBlocker::MaxUserNamespacesBelowNesting),
        _ => {}
    }
    if sysctl_value("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == Some(1) {
        return Some(UsernsBlocker::ApparmorRestrictsUnprivilegedUserns);
    }
    None
}

/// The supported Landlock ABI version, or `None` when the running kernel
/// offers no Landlock security module.
///
/// The version rises as the kernel gains filesystem and network access
/// rights; [`CageBuilder::landlock_fs`] enforces best-effort down to it. A
/// `None` result means a Landlock request is refused rather than applied: at
/// build where Landlock is its only boundary, and at launch otherwise.
///
/// [`CageBuilder::landlock_fs`]: crate::CageBuilder::landlock_fs
#[cfg(feature = "hardening")]
pub fn landlock_abi() -> Option<i32> {
    crate::mechanism::probe_landlock_abi()
}

/// Whether the running kernel's Landlock enforces every right in `access`.
///
/// A right is enforced where the kernel governs it, so a grant of it is applied
/// rather than narrowed away: [`FsAccess::READ`], [`FsAccess::WRITE`] and
/// [`FsAccess::EXECUTE`] on every kernel that offers Landlock (ABI 1), and
/// [`FsAccess::RESOLVE_UNIX`] from Landlock ABI 9. Two parts of a right arrive
/// after the right itself and are not weighed here: truncation, part of
/// `WRITE`, is governed from ABI 3, and device `ioctl` from ABI 5. `false`
/// without Landlock.
///
/// A build asks the same question of a right nothing else bounds, and refuses
/// one this answers `false` for, such as
/// [`landlock_resolve_unix`](crate::CageBuilder::landlock_resolve_unix) on a
/// kernel below ABI 9. A caller asks it first to choose a posture the kernel
/// enforces:
///
/// ```no_run
/// use ferroday_cage::{Cage, FsAccess, host};
///
/// # fn main() -> ferroday_cage::Result<()> {
/// let cage = Cage::builder()
///     .host_rootfs()
///     .landlock_resolve_unix(host::landlock_enforces_fs(FsAccess::RESOLVE_UNIX))
///     .command("/usr/bin/make")
///     .build()?;
/// # let _ = cage;
/// # Ok(())
/// # }
/// ```
///
/// [`FsAccess::READ`]: crate::FsAccess::READ
/// [`FsAccess::WRITE`]: crate::FsAccess::WRITE
/// [`FsAccess::EXECUTE`]: crate::FsAccess::EXECUTE
/// [`FsAccess::RESOLVE_UNIX`]: crate::FsAccess::RESOLVE_UNIX
#[cfg(feature = "hardening")]
pub fn landlock_enforces_fs(access: crate::FsAccess) -> bool {
    crate::hardening::fs_enforced(access, landlock_abi())
}

/// Whether the running kernel's Landlock enforces every right in `access`:
/// from Landlock ABI 4 (Linux 6.7), and `false` without Landlock.
///
/// Below it a network grant is narrowed away where a network namespace bounds
/// the command, and refused where the grant is the only bound, as under
/// [`Network::Host`](crate::Network::Host); see
/// [`CageBuilder::landlock_net`](crate::CageBuilder::landlock_net).
#[cfg(feature = "hardening")]
pub fn landlock_enforces_net(access: crate::NetAccess) -> bool {
    crate::hardening::net_enforced(access, landlock_abi())
}

/// Whether the running kernel's Landlock enforces `scope`: from Landlock ABI 6
/// (Linux 6.12), and `false` without Landlock.
///
/// Below it a scope is narrowed away where a namespace also bounds its reach,
/// and refused where nothing else does; see
/// [`CageBuilder::landlock_scope`](crate::CageBuilder::landlock_scope).
#[cfg(feature = "hardening")]
pub fn landlock_enforces_scope(scope: crate::LandlockScope) -> bool {
    crate::hardening::scope_enforced(scope, landlock_abi())
}

/// Whether this process can install a seccomp filter.
///
/// `false` on a kernel built without `CONFIG_SECCOMP_FILTER`, and where a
/// seccomp policy the caller already runs under refuses the `seccomp` syscall,
/// as a container runtime's profile can. A sandbox with a network namespace of
/// its own, [`Network::Isolated`] or [`Network::None`], then fails to launch,
/// since the filter that closes the routes out such a namespace does not cover
/// cannot be installed. A seccomp policy of the hardening layer would fail to
/// install too. [`Network::Host`] needs no filter.
///
/// The probe forks a short-lived child that installs the filter a launch
/// installs and exits, so it answers what a launch would meet rather than what
/// the kernel was configured with. It changes nothing in the calling process.
/// A fork that fails answers `false`.
///
/// [`Network::Isolated`]: crate::Network::Isolated
/// [`Network::None`]: crate::Network::None
/// [`Network::Host`]: crate::Network::Host
pub fn seccomp_available() -> bool {
    crate::mechanism::seccomp::installable()
}

/// Why a sandbox with a PID namespace of its own cannot mount the fresh procfs
/// that namespace needs.
///
/// The kernel lets a process inside a user namespace mount a procfs only where
/// its mount namespace already holds one that is fully visible: a procfs
/// mounted at its own root, with no mount lying on any of its entries except
/// the permanently empty directories the kernel keeps for mounting on, such as
/// `/proc/sys/fs/binfmt_misc`. A container runtime masks entries of the
/// container's procfs by mounting over them, `/proc/kcore` and `/proc/sys`
/// among them, and a sandbox's user namespace locks those mounts in place, so
/// inside a container started with the runtime's defaults no procfs qualifies,
/// whatever the sandbox does. The mount fails with `EPERM`, which a launch
/// reports as [`Error::ProcfsRefused`](crate::Error::ProcfsRefused).
///
/// Two remedies exist, in the order to consider them. The first is unmasking
/// the runtime's procfs: Docker's `--security-opt systempaths=unconfined`, or
/// Kubernetes' `procMount: Unmasked`, which needs `hostUsers: false`. The
/// second is sharing the caller's PID namespace, with
/// [`CageBuilder::pid_namespace(false)`](crate::CageBuilder::pid_namespace). The managed
/// profile then binds the existing procfs, masks included, and needs no fresh
/// one; the command can then see and signal the processes of the caller's PID
/// namespace that run as the same user, which the `hardening` feature's
/// `LandlockScope::Signal` refuses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProcfsBlocker {
    /// Mounts lie on entries of every procfs the mount namespace holds.
    #[non_exhaustive]
    Covered {
        /// Where each such mount is mounted, in the order the mount table
        /// lists them.
        mounts: Vec<PathBuf>,
    },
    /// The kernel refused the mount, and no mount lies on the procfs.
    ///
    /// The rule weighs the existing procfs's own flags as well: a procfs
    /// mounted read-only, or with access-time settings other than the default,
    /// does not count. A security module's policy or a seccomp filter can
    /// refuse the mount too.
    Refused,
}

impl fmt::Display for ProcfsBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcfsBlocker::Covered { mounts } => {
                f.write_str(
                    "the kernel mounts a fresh procfs only where an existing one is fully \
                     visible, and mounts cover entries of the one this process runs under, as a \
                     container runtime's masks do: ",
                )?;
                for (at, mount) in mounts.iter().enumerate() {
                    let lead = if at == 0 { "" } else { ", " };
                    write!(f, "{lead}{}", mount.display())?;
                }
                f.write_str(
                    "; unmask the procfs, with Docker's --security-opt systempaths=unconfined or \
                     Kubernetes' procMount: Unmasked, or share the caller's PID namespace with \
                     pid_namespace(false)",
                )
            }
            ProcfsBlocker::Refused => f.write_str(
                "the kernel refused a fresh procfs although no mount covers the existing one; \
                 its read-only or access-time flags, a security module's policy, or a seccomp \
                 filter can refuse it, and sharing the caller's PID namespace with \
                 pid_namespace(false) needs no fresh procfs",
            ),
        }
    }
}

/// Probes whether a sandbox with a PID namespace of its own can mount the
/// fresh procfs it needs, returning why not where it cannot.
///
/// The probe forks a short-lived child that creates a user, a mount and a PID
/// namespace and mounts a procfs inside them, as a launch does, so it answers
/// what a launch would meet, including the conditions no file reports. It then
/// reads this process's mount table to say why: [`ProcfsBlocker::Covered`]
/// names the mounts lying on the procfs.
///
/// `None` means the procfs mounted, or that the probe could not create the
/// namespaces to try it in. The second leaves the diagnosis to
/// [`userns_blocker`], the boundary that owns it, as [`overlay_blocker`] does.
/// The probe changes nothing in the calling process, and its mount goes away
/// with the child's namespaces.
pub fn procfs_blocker() -> Option<ProcfsBlocker> {
    match crate::mechanism::probe_procfs_mount() {
        crate::mechanism::ProcfsProbe::Refused => Some(procfs_refusal()),
        crate::mechanism::ProcfsProbe::Mounted | crate::mechanism::ProcfsProbe::Inconclusive => {
            None
        }
    }
}

/// Why the kernel refused a fresh procfs, read from this process's mount table:
/// the mounts covering every procfs it holds, or [`ProcfsBlocker::Refused`]
/// where the table shows a procfs nothing covers or cannot be read.
///
/// Asked once a refusal is known, by the probe and by a launch whose procfs
/// mount failed. The mount table is the one the sandbox's mount namespace was
/// copied from.
pub(crate) fn procfs_refusal() -> ProcfsBlocker {
    std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|table| procfs_covers(&table))
        .map_or(ProcfsBlocker::Refused, |mounts| ProcfsBlocker::Covered {
            mounts,
        })
}

/// Probes whether a launch with a cgroup of its own beneath `parent`, holding
/// the tree to `limits`, would be refused its cgroup, returning why where it
/// would.
///
/// It answers what [`CageBuilder::cgroup_parent`] and
/// [`CageBuilder::cgroup_limit`] meet at launch, by the launch's own steps
/// rather than a reading of the parent's files: it creates a cgroup and its
/// leaf beneath `parent` as a launch does, enabling the controllers the limits
/// need and writing the limits, forks a short-lived child that moves itself
/// into the leaf as the launch stage moves, and removes both once the child
/// has exited. The
/// [`CgroupRefusal`] it returns is the one the launch would fail with, as
/// [`Error::CgroupRefused`](crate::Error::CgroupRefused). That covers a parent
/// that does not exist, one outside a cgroup v2 hierarchy or on a read-only
/// one, one not delegated to this process, a missing controller, a parent
/// holding processes, a limit's file the kernel lacks, and a caller in a cgroup
/// the launch cannot move out of into the parent's subtree.
///
/// `None` means a launch would be given its cgroup. It also means a step failed
/// for a reason of the host's that no refusal names, such as running out of
/// descriptors, which a launch reports as
/// [`Error::Cgroup`](crate::Error::Cgroup), or that a value the build
/// refuses, such as a relative `parent`, stopped the probe before it began.
///
/// The probe changes the parent as a launch does, and as a launch leaves it:
/// the controllers the limits need, and the `memory` and `pids` controllers a
/// launch accounts with where the parent offers them, stay enabled in its
/// `cgroup.subtree_control`. A parent holding processes refuses before
/// anything is changed.
///
/// [`CageBuilder::cgroup_parent`]: crate::CageBuilder::cgroup_parent
/// [`CageBuilder::cgroup_limit`]: crate::CageBuilder::cgroup_limit
/// [`CgroupRefusal`]: crate::CgroupRefusal
pub fn cgroup_blocker(
    parent: impl AsRef<Path>,
    limits: &[crate::CgroupLimit],
) -> Option<crate::CgroupRefusal> {
    crate::cgroup::probe(parent.as_ref(), limits)
}

/// The directory of the cgroup v2 hierarchy that this process runs in, as
/// this process's mount table places it: `/sys/fs/cgroup/user.slice/…` on a
/// host that mounts the hierarchy at `/sys/fs/cgroup`.
///
/// `None` where this process is in no cgroup v2 hierarchy, or where none its
/// mount table shows holds its cgroup, as inside a cgroup namespace whose
/// hierarchy was mounted from outside it.
///
/// A caller that runs in a delegated cgroup names it with
/// [`CageBuilder::cgroup_parent`] once it has moved itself into a leaf beside
/// the sandboxes' cgroups, since a cgroup holding processes cannot enable a
/// controller for its children. The move is the caller's to make: the library
/// moves no process of the caller's. [`cgroup_blocker`] then answers whether
/// the cgroup can hold a launch's.
///
/// A process moves with its threads, except a thread already exiting, which
/// the kernel leaves in the cgroup until its exit completes. Until then the
/// cgroup cannot enable a controller for its children, and a launch whose
/// limits need one is refused with [`CgroupRefusal::ParentHoldsProcesses`],
/// although `cgroup.procs`, which lists only each process's leader, may list
/// nothing. A caller whose threads can be ending as it moves waits for the
/// cgroup's `cgroup.threads` to list none.
///
/// [`CageBuilder::cgroup_parent`]: crate::CageBuilder::cgroup_parent
/// [`CgroupRefusal::ParentHoldsProcesses`]: crate::CgroupRefusal::ParentHoldsProcesses
pub fn own_cgroup() -> Option<PathBuf> {
    let membership = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    cgroup_directory(&membership, &mountinfo)
}

/// Where the cgroup `membership`, a `/proc/self/cgroup`, names in the cgroup
/// v2 hierarchy lies in `mountinfo`, a `/proc/self/mountinfo` table: beneath
/// the first cgroup v2 mount whose root holds it.
fn cgroup_directory(membership: &str, mountinfo: &str) -> Option<PathBuf> {
    // The unified hierarchy's line has hierarchy id 0 and no controller list.
    let own = Path::new(
        membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))?,
    );
    cgroup2_mounts(mountinfo).find_map(|entry| {
        let beneath = own.strip_prefix(&entry.root).ok()?;
        Some(match beneath.as_os_str().is_empty() {
            true => entry.mount_point,
            false => entry.mount_point.join(beneath),
        })
    })
}

/// The procfs entries the kernel keeps as permanently empty directories for
/// other filesystems to mount on, relative to the procfs's root. A mount on
/// one leaves the procfs fully visible.
const PROCFS_MOUNT_POINTS: [&str; 2] = ["sys/fs/binfmt_misc", "fs/nfsd"];

/// The mounts lying on entries of every procfs in `mountinfo`, a
/// `/proc/self/mountinfo` table, or `None` where the table holds no procfs, or
/// holds one no mount covers.
///
/// A procfs counts where it is mounted at its own root, which a bind of one of
/// its subdirectories is not. What covers it is every mount whose parent it is,
/// except one on a [permanently empty directory](PROCFS_MOUNT_POINTS). A mount
/// stacked on such a mount covers that mount and not the procfs.
fn procfs_covers(mountinfo: &str) -> Option<Vec<PathBuf>> {
    let mounts: Vec<MountEntry> = mountinfo.lines().filter_map(MountEntry::parse).collect();
    let mut covering = Vec::new();
    let mut found = false;
    for procfs in mounts
        .iter()
        .filter(|entry| entry.fstype == "proc" && entry.root == Path::new("/"))
    {
        found = true;
        let covers: Vec<&PathBuf> = mounts
            .iter()
            .filter(|entry| entry.parent == procfs.id && entry.id != procfs.id)
            .filter(|entry| {
                entry
                    .mount_point
                    .strip_prefix(&procfs.mount_point)
                    .is_ok_and(|beneath| {
                        !PROCFS_MOUNT_POINTS
                            .iter()
                            .any(|empty| beneath == Path::new(empty))
                    })
            })
            .map(|entry| &entry.mount_point)
            .collect();
        if covers.is_empty() {
            return None;
        }
        covering.extend(covers.into_iter().cloned());
    }
    found.then_some(covering)
}

/// The mounts of the cgroup v2 hierarchy in `mountinfo`, a
/// `/proc/self/mountinfo` table, in the table's order: the hierarchy's own
/// mount and every bind of a directory of it.
pub(crate) fn cgroup2_mounts(mountinfo: &str) -> impl Iterator<Item = MountEntry> + '_ {
    mountinfo
        .lines()
        .filter_map(MountEntry::parse)
        .filter(|entry| entry.fstype == "cgroup2")
}

/// One line of a `/proc/self/mountinfo` table: the fields of it the crate
/// reads.
pub(crate) struct MountEntry {
    /// The mount's id.
    id: u64,
    /// The id of the mount it is mounted on.
    parent: u64,
    /// The directory of its filesystem that the mount presents.
    root: PathBuf,
    /// Where it is mounted.
    pub(crate) mount_point: PathBuf,
    /// Its filesystem type.
    fstype: String,
}

impl MountEntry {
    /// Reads one line, or `None` where it is not one the kernel writes.
    ///
    /// The fields are space-separated, with optional fields before a lone `-`
    /// and the filesystem type after it. A path is written with a space, a tab,
    /// a newline and a backslash as three-digit octal escapes.
    fn parse(line: &str) -> Option<MountEntry> {
        let mut fields = line.split(' ');
        let id = fields.next()?.parse().ok()?;
        let parent = fields.next()?.parse().ok()?;
        let _device = fields.next()?;
        let root = unescape_mount_path(fields.next()?)?;
        let mount_point = unescape_mount_path(fields.next()?)?;
        let fstype = fields.skip_while(|field| *field != "-").nth(1)?.to_string();
        Some(MountEntry {
            id,
            parent,
            root,
            mount_point,
            fstype,
        })
    }
}

/// A mount table path with its octal escapes decoded, or `None` where an
/// escape is malformed.
///
/// The kernel writes an escape as a backslash and three octal digits, and a
/// backslash in a path as such an escape itself, so the three bytes after a
/// backslash it wrote are octal digits. The leading `+` `from_str_radix` would
/// also take is not something the kernel writes there.
fn unescape_mount_path(field: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let bytes = field.as_bytes();
    let mut path = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\' {
            let digits = bytes.get(at + 1..at + 4)?;
            let text = std::str::from_utf8(digits).ok()?;
            path.push(u8::from_str_radix(text, 8).ok()?);
            at += 4;
        } else {
            path.push(bytes[at]);
            at += 1;
        }
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(path)))
}

/// Reads a sysctl file and parses its leading integer value.
///
/// Returns `None` when the file does not exist, cannot be read, or does not
/// parse; an absent sysctl is simply not part of this host's configuration.
fn sysctl_value(path: &str) -> Option<i64> {
    let contents = std::fs::read_to_string(path).ok()?;
    contents.split_whitespace().next()?.parse().ok()
}

/// The ids the kernel presents an owner or a group as to a user namespace whose
/// map does not hold it: the overflow uid and gid, `nobody` and `nogroup`.
///
/// Read from `/proc/sys/kernel/overflowuid` and `overflowgid`, which a host may
/// set, and 65534 each, the kernel's default, where either cannot be read.
#[cfg(feature = "tarball")]
pub(crate) fn overflow_ids() -> (u32, u32) {
    let read = |path| {
        sysctl_value(path)
            .and_then(|id| u32::try_from(id).ok())
            .unwrap_or(65534)
    };
    (
        read("/proc/sys/kernel/overflowuid"),
        read("/proc/sys/kernel/overflowgid"),
    )
}

/// A host condition known to make a uid/gid range map unavailable.
///
/// The single-identity map needs none of this; the conditions concern the
/// range tiers: writing a map directly requires capabilities over the parent
/// user namespace, and delegating to the shadow suite requires working,
/// privileged helpers and a subordinate allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RangeMapBlocker {
    /// The library was built without the `subid` feature, and the caller
    /// holds no capabilities over its user namespace.
    ///
    /// Without the feature the only bundled delegate writes maps directly,
    /// which requires `CAP_SETUID` and `CAP_SETGID` — running as root, or
    /// inside an already range-mapped namespace.
    SubidFeatureDisabled,
    /// The calling process runs under `no_new_privs`, so the shadow suite's
    /// helpers run without their privilege.
    ///
    /// A helper holds its privilege as a setuid bit or a file capability, and
    /// an exec under `no_new_privs` honours neither, so every map it is asked to
    /// write fails with `EPERM`. The flag is inherited and cannot be cleared:
    /// a process started under a service manager's `NoNewPrivileges=` setting,
    /// or by a launcher that set it, has it for good. The remedy is to start
    /// the caller without it.
    NoNewPrivileges,
    /// A shadow suite helper is not on `PATH`.
    ///
    /// The commonest cause is a container runtime installed without its
    /// recommended packages. The helpers ship with the shadow suite's
    /// subordinate-id tools: `uidmap` on Debian, Devuan, and Ubuntu,
    /// `shadow-subids` on Alpine, `shadow` elsewhere.
    #[non_exhaustive]
    HelperMissing {
        /// The missing helper, `newuidmap` or `newgidmap`.
        helper: &'static str,
    },
    /// A helper exists but holds no privilege.
    ///
    /// A working helper is either setuid-root or carries the needed
    /// capability as a file capability; this one is neither. openSUSE's
    /// `shadow.paranoid` permissions profile ships the helpers this way,
    /// and a copy that did not preserve `security.*` extended attributes
    /// loses a file capability while leaving the file looking intact.
    #[non_exhaustive]
    HelperUnprivileged {
        /// The unprivileged helper.
        path: PathBuf,
    },
    /// A subordinate file is a symbolic link, which the helpers refuse.
    ///
    /// `newuidmap` opens the file with `O_NOFOLLOW` and reports the
    /// refusal as a missing-privilege error, obscuring the real cause.
    #[non_exhaustive]
    SubordinateFileSymlink {
        /// The offending file, `/etc/subuid` or `/etc/subgid`.
        path: &'static str,
    },
    /// The calling user has no subordinate id allocation.
    NoSubordinateAllocation,
    /// The caller's subordinate allocation could not be determined at all.
    ///
    /// Distinct from [`NoSubordinateAllocation`](Self::NoSubordinateAllocation),
    /// which is the query answering that there is none. This is the query
    /// failing to answer: `getsubids` exists but did not report, or
    /// `nsswitch.conf` sources subordinate ids from a module beyond `files` and
    /// `getsubids` — the only tool that consults it — is not installed. On such
    /// a host the subordinate files are not the authority, so the remedy is to
    /// install `getsubids`, not to add entries to them.
    #[non_exhaustive]
    SubordinateAllocationUnknown {
        /// What the query could not do, and what would let it.
        reason: String,
    },
}

impl fmt::Display for RangeMapBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RangeMapBlocker::SubidFeatureDisabled => f.write_str(
                "the caller holds no CAP_SETUID/CAP_SETGID over its user namespace, and the \
                 library was built without the `subid` feature, so no delegate can establish \
                 a range map; enable the feature, or run with those capabilities",
            ),
            RangeMapBlocker::NoNewPrivileges => f.write_str(
                "the calling process runs under no_new_privs, so newuidmap and newgidmap run \
                 without the setuid bit or file capability that is their privilege; start the \
                 caller without the flag",
            ),
            RangeMapBlocker::HelperMissing { helper } => write!(
                f,
                "{helper} was not found on PATH; install the shadow suite's subordinate-id \
                 helpers (packaged as uidmap on Debian and Ubuntu, shadow-subids on Alpine, \
                 and shadow on most other distributions)",
            ),
            RangeMapBlocker::HelperUnprivileged { path } => write!(
                f,
                "{} is neither setuid-root nor granted a file capability, so it cannot \
                 establish maps; reinstall the shadow suite's subordinate-id helpers or \
                 restore the packaged privilege",
                path.display(),
            ),
            RangeMapBlocker::SubordinateFileSymlink { path } => write!(
                f,
                "{path} is a symbolic link, which the shadow helpers refuse to follow; make \
                 it a regular file",
            ),
            RangeMapBlocker::NoSubordinateAllocation => f.write_str(
                "the calling user has no subordinate id allocation; grant one with \
                 usermod --add-subuids and --add-subgids, or entries in /etc/subuid and \
                 /etc/subgid",
            ),
            RangeMapBlocker::SubordinateAllocationUnknown { reason } => write!(
                f,
                "the calling user's subordinate id allocation could not be determined: {reason}",
            ),
        }
    }
}

/// A host condition known to prevent an unprivileged overlay-rooted cage.
///
/// A cage rooted on an overlay ([`CageBuilder::overlay_rootfs`]) mounts an
/// overlay from inside its user namespace. Two host properties gate that, and
/// each maps to a variant here.
///
/// [`CageBuilder::overlay_rootfs`]: crate::CageBuilder::overlay_rootfs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OverlayBlocker {
    /// An unprivileged overlay mount was refused.
    ///
    /// The running kernel predates unprivileged overlay in a user namespace
    /// (before Linux 5.11), or the overlay filesystem is otherwise unavailable.
    Unsupported,
    /// The upper layer's filesystem does not support the `user.*` extended-
    /// attribute namespace.
    ///
    /// An unprivileged overlay records its metadata — whiteouts and opaque
    /// markers — in `user.*` xattrs. tmpfs gained support for them only in
    /// Linux 6.6; an on-disk filesystem (ext4, xfs, btrfs) supports them
    /// throughout. Place the overlay's upper layer on such a filesystem, or use
    /// a newer kernel.
    UpperUnsupported,
}

impl fmt::Display for OverlayBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OverlayBlocker::Unsupported => {
                "the kernel refused an unprivileged overlay mount; overlay in a user namespace \
                 needs Linux 5.11 or later"
            }
            OverlayBlocker::UpperUnsupported => {
                "the upper layer's filesystem does not support user.* extended attributes, which \
                 an unprivileged overlay records its metadata in; put the upper on an on-disk \
                 filesystem such as ext4, xfs, or btrfs, or use Linux 6.6 or later for a tmpfs \
                 upper"
            }
        })
    }
}

/// Probes the host for a condition that prevents an unprivileged overlay-rooted
/// cage whose upper layer sits on the filesystem hosting `scratch_dir`.
///
/// `scratch_dir` is a directory on the filesystem the overlay's upper layer
/// will live on; the probe tests that filesystem for `user.*` xattr support and
/// forks a throwaway child that attempts an unprivileged overlay mount. It
/// returns the first blocker found, or `None` when an overlay-rooted cage should
/// be establishable.
///
/// The probe is best-effort. It creates and removes temporary files and
/// directories under `scratch_dir` and forks a short-lived child, but changes no
/// durable state; `None` is the absence of a known blocker, not a guarantee.
/// When the probe cannot set up a user namespace to test in — because
/// unprivileged user namespaces are themselves unavailable — it returns `None`
/// and leaves that diagnosis to [`userns_blocker`], the boundary that owns it.
/// Test suites use it to skip overlay tests explicitly on hosts that cannot run
/// them, as they use [`userns_blocker`] and [`range_map_blocker`].
pub fn overlay_blocker(scratch_dir: impl AsRef<Path>) -> Option<OverlayBlocker> {
    let scratch_dir = scratch_dir.as_ref();
    // The upper-filesystem gate first: it is a direct, fork-free xattr write on
    // the target filesystem, and it identifies the specific "upper cannot record
    // metadata" case a bare mount test would miss (a pre-6.6 tmpfs mounts but
    // cannot record whiteouts).
    if upper_lacks_user_xattr(scratch_dir) {
        return Some(OverlayBlocker::UpperUnsupported);
    }
    // The mount gate: can an unprivileged overlay mount at all on this kernel?
    if overlay_mount_refused(scratch_dir) {
        return Some(OverlayBlocker::Unsupported);
    }
    None
}

/// Opens `dir` as a directory descriptor for the work below to anchor against.
///
/// `dir` is the caller's to name, so reaching it through a symlink is the
/// caller's business; what the descriptor buys is that every entry created,
/// inspected, or removed within it resolves relative to one directory, with no
/// path walk another user of a shared directory can step into.
fn open_dir(dir: &Path) -> rustix::io::Result<OwnedFd> {
    rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// A probe entry name: `prefix` followed by 16 hex digits of kernel entropy.
///
/// Every probe entry is created exclusively — `O_EXCL` for the xattr probe's
/// file, `mkdirat` for the mount probe's directory — so an unpredictable name is
/// not what makes the probe safe against a hostile neighbour. It is what keeps
/// one from parking a squatter at a name the probe is bound to choose and
/// turning the preflight into a standing denial of service.
fn probe_name(prefix: &str) -> String {
    format!("{prefix}{}", unique_hex())
}

/// Sixteen hex digits distinguishing one call from every other, for naming a
/// filesystem entry no concurrent caller may collide with.
///
/// The kernel's randomness is combined with, rather than substituted for, a seed
/// that is already unique per call: the process id in the high half distinguishes
/// concurrent processes, and a process-wide counter in the low half distinguishes
/// calls within one process, which threads sharing a pid would not be. Combining
/// the two by exclusive-or keeps the claim in the first sentence true on a host
/// where `getrandom` fails: the outcome is then the seed combined with whatever
/// [`fill_random`] managed, still unique.
///
/// Uniqueness is not what makes the naming safe in any case: every caller
/// creates its entry with `O_EXCL` or `mkdirat` and treats a collision as a
/// failure. What it buys is that a neighbour cannot park a squatter at a name
/// this is bound to choose.
pub(crate) fn unique_hex() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Distinguishes calls within one process, where the pid cannot.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut random = [0u8; 8];
    // A failure is tolerated: the seed alone keeps the name unique, and the
    // randomness only makes it unpredictable.
    let _ = fill_random(&mut random);
    let seed = (u64::from(std::process::id()) << 32)
        | (COUNTER.fetch_add(1, Ordering::Relaxed) & u64::from(u32::MAX));
    format!("{:016x}", seed ^ u64::from_ne_bytes(random))
}

/// Fills `buf` from the kernel's randomness.
///
/// A short read is resumed where it stopped, and `EINTR` is retried. A read of
/// nothing into a buffer with room left is not an answer `getrandom` documents,
/// so it is reported as `EIO` rather than retried, which would spin. What a
/// failure leaves filled stays in `buf`.
///
/// What a failure means is the caller's to decide. [`unique_hex`] carries on
/// without the randomness, since its seed is unique already, while the network
/// stack refuses to start without the entropy its TCP sequence numbers need.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), Errno> {
    fill_from(buf, |rest| {
        // The call `clippy.toml` sends every other site here for: this is that
        // answer.
        #[expect(clippy::disallowed_methods)]
        rustix::rand::getrandom(rest, GetRandomFlags::empty())
    })
}

/// The body of [`fill_random`], with each read made by `read`.
///
/// Split so the answers the kernel rarely gives, a short read, an
/// interruption, and a read of nothing, are reachable from a test.
fn fill_from(
    buf: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> Result<usize, Errno>,
) -> Result<(), Errno> {
    let mut filled = 0;
    while filled < buf.len() {
        match read(&mut buf[filled..]) {
            Ok(0) => return Err(Errno::IO),
            Ok(read) => filled += read,
            Err(Errno::INTR) => {}
            Err(errno) => return Err(errno),
        }
    }
    Ok(())
}

/// Whether the filesystem hosting `dir` refuses a `user.*` extended attribute,
/// the condition that makes it unable to back an unprivileged overlay.
///
/// A write that succeeds, or fails for any reason other than the namespace being
/// unsupported (a full disk, a permission quirk), is not treated as a blocker:
/// the probe reports only the specific unsupported-namespace signal.
fn upper_lacks_user_xattr(dir: &Path) -> bool {
    let Ok(parent) = open_dir(dir) else {
        // Cannot even open the directory: inconclusive, not a blocker.
        return false;
    };
    let name = probe_name(".fcage-xattr-probe-");
    let Ok(probe) = create_probe_file(&parent, &name) else {
        // Cannot write here at all: inconclusive, not a blocker.
        return false;
    };
    // The attribute goes on the descriptor rather than the name, so the write
    // cannot land anywhere the exclusive create did not reach.
    let result = rustix::fs::fsetxattr(&probe, "user.fcage.probe", b"1", XattrFlags::empty());
    drop(probe);
    let _ = rustix::fs::unlinkat(&parent, name.as_str(), AtFlags::empty());
    matches!(result, Err(errno) if crate::mechanism::xattr_unsupported(errno))
}

/// Creates the xattr probe's file at `name` under `parent`, refusing anything
/// already there.
///
/// `O_EXCL | O_NOFOLLOW`: the scratch directory may be shared with other local
/// users, so the probe must only ever hold a file it created itself. Anything
/// already at the name — a regular file, or a symlink aimed at a file the caller
/// can write — fails the create with `EEXIST` instead of being truncated and
/// written through.
fn create_probe_file(parent: &OwnedFd, name: &str) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
}

/// Whether an unprivileged overlay mount is refused on this host, tested by
/// mounting a throwaway overlay under `scratch_dir` in a forked child.
///
/// Returns `false` when the mount succeeds and when the probe is inconclusive —
/// it could not lay out the test directories, or could not create a user
/// namespace to test in — so only a genuine mount refusal reads as a blocker.
fn overlay_mount_refused(scratch_dir: &Path) -> bool {
    let Ok(parent) = open_dir(scratch_dir) else {
        return false;
    };
    let name = probe_name(".fcage-overlay-probe-");
    // `mkdirat` refuses a name that already exists — including one another user
    // planted as a symlink — so, like the xattr probe's `O_EXCL` create, the
    // probe works only inside a directory it created itself. Mode `0700` keeps
    // the layer directories laid out below out of a neighbour's reach.
    if rustix::fs::mkdirat(&parent, name.as_str(), Mode::RWXU).is_err() {
        return false;
    }

    // The probe child opens its layers by path, as the launch does; that is
    // safe because this base directory is fresh, private, and unpredictably
    // named.
    let base = scratch_dir.join(&name);
    let outcome = overlay_mount_probe(&base);
    // The mount leaves a mode-`0` directory in its work area. Empty, it goes
    // as the calling user; anything left inside it is what the single-map
    // escalation clears. Best effort: the verdict does not depend on it.
    let _ = crate::provision::remove_tree(&base, &crate::IdentityMap::Single, None);
    matches!(outcome, Some(crate::mechanism::OverlayProbe::MountFailed))
}

/// Lays out the probe's lower, upper, and work directories under `base` and
/// runs the fork-based mount test, returning its outcome or `None` when the
/// layout could not be prepared.
///
/// `base` was just created empty and private by [`overlay_mount_refused`], so
/// each layer directory is created outright: a name already taken is a surprise
/// worth failing on, not something to reuse. The child opens each layer without
/// following a link, as the launch does, so it is named by its canonical path.
fn overlay_mount_probe(base: &Path) -> Option<crate::mechanism::OverlayProbe> {
    let base = std::fs::canonicalize(base).ok()?;
    let dir = |name: &str| {
        let path = base.join(name);
        std::fs::create_dir(&path).ok()?;
        CString::new(path.into_os_string().into_vec()).ok()
    };
    let lower = dir("lower")?;
    let upper = dir("upper")?;
    let work = dir("work")?;
    Some(crate::mechanism::probe_overlay_mount(&lower, &upper, &work))
}

/// Probes the host for conditions that make a uid/gid range map unavailable,
/// returning the first one identified.
///
/// Returns `None` when a range map should be establishable: the caller holds
/// `CAP_SETUID` and `CAP_SETGID` in its effective set (enough to write a map
/// directly), or (with the `subid` feature) the shadow suite's helpers are
/// present, privileged, and backed by an allocation.
///
/// The capability check reflects the effective set only. The direct tier and
/// the kernel's map write both require the capabilities effective and do not
/// raise them from the permitted set, so a caller that has parked them in
/// `permitted` — after a privilege-lowering wrapper, say — reads as needing
/// the delegate until it raises them into effective itself.
///
/// A map naming the parent namespace's uid 0 among its outside ids needs
/// `CAP_SETFCAP` as well. That is a property of the request, which the probe
/// does not know: for a direct write the build judges it. Only a root caller's
/// own uid is outside uid 0, so an unprivileged caller's delegated map never
/// names it. A root caller's exec of a helper grants every capability in its
/// bounding set, whatever capabilities the helper's file carries, unless the
/// caller set `SECBIT_NOROOT`. shadow's helpers keep `CAP_SETFCAP` for such a
/// map since shadow 4.9. So a helper's own file capabilities do not decide it,
/// and the probe does not read them for it.
///
/// The probe is best-effort and read-only; `None` is an absence of known
/// blockers, not a guarantee.
pub fn range_map_blocker() -> Option<RangeMapBlocker> {
    // A caller that can write a map directly needs nothing else, and has no
    // blocker: no refusal of a direct write is `None` here too. The map's
    // outside ids are the request's, which the probe does not know, so it asks
    // about none of them.
    crate::idmap::direct_write_refusal(&[], crate::idmap::effective_capabilities())?;

    #[cfg(not(feature = "subid"))]
    {
        Some(RangeMapBlocker::SubidFeatureDisabled)
    }
    #[cfg(feature = "subid")]
    {
        delegated_blocker()
    }
}

/// The delegated-tier checks behind [`range_map_blocker`]: whatever stops the
/// helpers themselves, then the allocation.
#[cfg(feature = "subid")]
fn delegated_blocker() -> Option<RangeMapBlocker> {
    if let Some(blocker) = helper_blocker() {
        return Some(blocker);
    }

    match crate::idmap::probe_allocation() {
        None => {}
        Some((_, crate::idmap::AllocationUnusable::Empty)) => {
            return Some(RangeMapBlocker::NoSubordinateAllocation);
        }
        // The query could not answer, which is a different diagnosis from an
        // empty allocation and has a different remedy — most often "install
        // getsubids", on a host whose subordinate ids come from a directory
        // service rather than from the files. Reporting the empty-allocation
        // blocker here would advise adding /etc/subuid entries, which on such a
        // host is wrong twice over: the user may well have an allocation, and
        // the files are not the authority.
        Some((kind, unusable)) => {
            return Some(RangeMapBlocker::SubordinateAllocationUnknown {
                reason: unusable.to_string(kind),
            });
        }
    }

    None
}

/// Why the shadow suite's helpers cannot establish a map on this host, or
/// `None` when nothing known stands in their way.
///
/// The conditions are the caller's own `no_new_privs`, a helper absent from
/// `PATH` or holding no privilege, and a subordinate file the helpers refuse to
/// open. Each one fails every map the helpers are asked to write, whatever the
/// request and whatever the allocation.
///
/// The one answer to whether the helpers can work here.
/// [`SubidMapper`](crate::SubidMapper)'s `resolve` asks it before it reports a
/// map, so a build and a provisioner's preflight refuse a host the launch would
/// fail on. [`range_map_blocker`] asks it before the allocation, so the probe
/// and the delegate name the same condition. A helper is judged at the path
/// [`find_on_path`] resolves, which is the path the delegate executes.
#[cfg(feature = "subid")]
pub(crate) fn helper_blocker() -> Option<RangeMapBlocker> {
    use rustix::thread::CapabilitySet;

    // First, since it defeats every helper whatever the helper's own state.
    if crate::idmap::no_new_privs() {
        return Some(RangeMapBlocker::NoNewPrivileges);
    }

    for (helper, capability) in [
        ("newuidmap", CapabilitySet::SETUID),
        ("newgidmap", CapabilitySet::SETGID),
    ] {
        let Some(path) = find_on_path(helper) else {
            return Some(RangeMapBlocker::HelperMissing { helper });
        };
        if helper_privilege(&path, capability) == HelperPrivilege::None {
            return Some(RangeMapBlocker::HelperUnprivileged { path });
        }
    }

    for path in ["/etc/subuid", "/etc/subgid"] {
        if std::fs::symlink_metadata(path)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Some(RangeMapBlocker::SubordinateFileSymlink { path });
        }
    }

    None
}

/// How a shadow helper holds its privilege, if at all.
///
/// A file-capability helper needs only the one capability its map file asks
/// for. `CAP_SETFCAP` matters only to a map naming the parent namespace's uid 0,
/// which is a root caller's, and a root caller's exec does not take its
/// capabilities from the file; see [`range_map_blocker`].
#[cfg(feature = "subid")]
#[derive(Debug, PartialEq, Eq)]
enum HelperPrivilege {
    /// Setuid-root: full privilege when run.
    SetuidRoot,
    /// File capabilities carrying the needed `CAP_SETUID`/`CAP_SETGID`.
    FileCaps,
    /// Neither: the helper cannot work.
    None,
}

/// The `VFS_CAP_FLAGS_EFFECTIVE` bit of a `security.capability` attribute's
/// magic word: the file's capabilities are raised in the effective set at exec,
/// rather than merely permitted for a program that raises them itself.
#[cfg(feature = "subid")]
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;

/// Determines a helper's privilege: the setuid bit, or the needed capability
/// in its `security.capability` extended attribute. Podman's probe accepts
/// either, and so does this one; a mode check alone would misreport
/// capability-based installations (Alpine's, for one) as unprivileged.
#[cfg(feature = "subid")]
fn helper_privilege(
    path: &std::path::Path,
    capability: rustix::thread::CapabilitySet,
) -> HelperPrivilege {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if let Ok(meta) = std::fs::metadata(path)
        && meta.uid() == 0
        && meta.permissions().mode() & 0o4000 != 0
    {
        return HelperPrivilege::SetuidRoot;
    }

    let mut buf = [0u8; 40];
    let Ok(len) = rustix::fs::getxattr(path, "security.capability", &mut buf[..]) else {
        return HelperPrivilege::None;
    };
    file_capability_privilege(&buf[..len], capability)
}

/// What a helper's `security.capability` attribute grants it, for a helper
/// that needs `capability`.
///
/// The attribute is a little-endian magic/version word, then per-word
/// permitted and inheritable masks. `CAP_SETUID` and `CAP_SETGID` both live in
/// the low word, the attribute's second `u32`.
#[cfg(feature = "subid")]
fn file_capability_privilege(
    attribute: &[u8],
    capability: rustix::thread::CapabilitySet,
) -> HelperPrivilege {
    let (Some(magic), Some(permitted_low)) = (attribute.get(0..4), attribute.get(4..8)) else {
        return HelperPrivilege::None;
    };
    let magic = u32::from_le_bytes(magic.try_into().expect("slice length is 4"));
    // The effective bit rides in the magic word. Without it the capability is
    // permitted but not raised at exec, so a helper that is not itself
    // capability-aware — and `newuidmap` is not — runs without it and fails.
    // Reporting such a helper as privileged would have the probe name no
    // blocker where there is one.
    if magic & VFS_CAP_FLAGS_EFFECTIVE == 0 {
        return HelperPrivilege::None;
    }
    let permitted_low = u32::from_le_bytes(permitted_low.try_into().expect("slice length is 4"));
    if u64::from(permitted_low) & capability.bits() == 0 {
        return HelperPrivilege::None;
    }
    HelperPrivilege::FileCaps
}

/// Finds an executable on `PATH`, returning its absolute path.
///
/// Shared by the probe above and by the delegate that executes the helper, so
/// the binary whose privilege the probe judged is the one chosen by the same
/// rules — a probe describing a different binary from the one that runs is a
/// verdict about nothing.
///
/// Only absolute `PATH` entries are searched. An empty or relative entry names
/// the process's working directory, and resolving a privileged helper against
/// whatever directory the process happens to be in is not a lookup this should
/// perform; [`spec::search_candidates`](crate::spec) takes the same position for
/// the sandbox's own path lookup, for the same reason.
#[cfg(feature = "subid")]
pub(crate) fn find_on_path(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if !dir.is_absolute() {
            continue;
        }
        let candidate = dir.join(name);
        if let Ok(meta) = std::fs::metadata(&candidate)
            && meta.is_file()
            && meta.permissions().mode() & 0o111 != 0
        {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    #[test]
    fn a_process_s_cgroup_lies_beneath_the_cgroup2_mount_that_holds_it() {
        let table = "24 30 0:22 / /sys rw,nosuid - sysfs sysfs rw\n\
                     31 24 0:27 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw\n";
        let at = |membership: &str, table: &str| cgroup_directory(membership, table);
        assert_eq!(
            at("0::/user.slice/run-r1.scope\n", table),
            Some(PathBuf::from("/sys/fs/cgroup/user.slice/run-r1.scope"))
        );
        assert_eq!(at("0::/\n", table), Some(PathBuf::from("/sys/fs/cgroup")));
        // A v1 hierarchy's line names no cgroup of the unified one.
        assert_eq!(at("1:name=systemd:/user.slice\n", table), None);
        assert_eq!(
            at("0::/a\n", "24 30 0:22 / /sys rw - sysfs sysfs rw\n"),
            None
        );
        // A mount presenting a subtree holds only what lies beneath its root.
        let subtree = "40 30 0:27 /machine/ct /mnt/cgroup rw - cgroup2 cgroup2 rw\n";
        assert_eq!(at("0::/elsewhere\n", subtree), None);
        assert_eq!(
            at("0::/machine/ct/leaf\n", subtree),
            Some(PathBuf::from("/mnt/cgroup/leaf"))
        );
    }

    #[test]
    fn probe_runs_without_panicking() {
        // The result is host-dependent; the probe itself must always be safe
        // to call.
        let _ = userns_blocker();
        let _ = procfs_blocker();
    }

    /// The procfs and its masks as a container runtime with its defaults lays
    /// them out: subdirectories bound read-only onto themselves, files covered
    /// with a bind of `/dev/null`, and a directory with an empty tmpfs.
    const CONTAINER_MOUNTINFO: &str = "\
600 599 0:45 / / rw,relatime master:1 - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w
601 600 0:48 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
602 600 0:49 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
640 601 0:48 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
643 601 0:48 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
645 601 0:53 / /proc/acpi ro,relatime - tmpfs tmpfs ro
646 601 0:49 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
647 601 0:49 /null /proc/key\\040list rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
";

    /// A host's procfs, with systemd's `binfmt_misc` automount and the
    /// filesystem it mounts on top.
    const HOST_MOUNTINFO: &str = "\
28 1 259:2 / / rw,relatime shared:1 - ext4 /dev/root rw
22 28 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
41 22 0:36 / /proc/sys/fs/binfmt_misc rw,relatime shared:13 - autofs systemd-1 rw,fd=32
826 41 0:68 / /proc/sys/fs/binfmt_misc rw,nosuid,nodev,noexec,relatime shared:383 - binfmt_misc binfmt_misc rw
";

    #[test]
    fn a_runtimes_masks_cover_its_procfs() {
        assert_eq!(
            procfs_covers(CONTAINER_MOUNTINFO),
            Some(
                [
                    "/proc/bus",
                    "/proc/sys",
                    "/proc/acpi",
                    "/proc/kcore",
                    "/proc/key list",
                ]
                .map(PathBuf::from)
                .to_vec()
            ),
            "every mount on the procfs is named, a bound subdirectory included, \
             and a path's octal escape is decoded",
        );
    }

    #[test]
    fn a_mount_on_a_permanently_empty_directory_covers_nothing() {
        // The automount sits on a directory the kernel keeps empty for it, and
        // the filesystem on top of that is the automount's child, not the
        // procfs's.
        assert_eq!(procfs_covers(HOST_MOUNTINFO), None);
    }

    #[test]
    fn one_procfs_nothing_covers_leaves_the_rule_met() {
        // The kernel accepts a new procfs where any one already mounted is
        // fully visible, so a masked one beside a clear one explains nothing.
        let both = format!(
            "{CONTAINER_MOUNTINFO}700 600 0:48 / /host-proc rw,nosuid,nodev,noexec,relatime - \
             proc proc rw\n"
        );
        assert_eq!(procfs_covers(&both), None);
        // A bind of a procfs subdirectory is no procfs root of its own.
        let bound = "\
1 0 0:1 / / rw - tmpfs tmpfs rw
2 1 0:48 /sys /proc rw,nosuid - proc proc rw
";
        assert_eq!(
            procfs_covers(bound),
            None,
            "no procfs is mounted at its root"
        );
        assert_eq!(procfs_covers(""), None);
    }

    #[test]
    fn a_covered_procfs_names_its_mounts_and_the_remedies() {
        let blocker = ProcfsBlocker::Covered {
            mounts: vec![PathBuf::from("/proc/kcore"), PathBuf::from("/proc/acpi")],
        };
        let rendered = blocker.to_string();
        assert!(
            rendered.contains(": /proc/kcore, /proc/acpi;"),
            "{rendered}"
        );
        assert!(rendered.contains("systempaths=unconfined"), "{rendered}");
        assert!(rendered.contains("pid_namespace(false)"), "{rendered}");
    }

    /// A `security.capability` attribute of the second revision: the magic
    /// word with the effective flag where asked for, then the permitted and
    /// inheritable masks of the low and high words.
    #[cfg(feature = "subid")]
    fn capability_attribute(effective: bool, permitted_low: u32) -> Vec<u8> {
        const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
        let flags = if effective {
            VFS_CAP_FLAGS_EFFECTIVE
        } else {
            0
        };
        let magic = VFS_CAP_REVISION_2 | flags;
        [magic, permitted_low, 0, 0, 0]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    /// shadow installs `newuidmap` with `cap_setuid+ep` and nothing else, and
    /// that helper writes every map an unprivileged caller can ask for: only a
    /// map naming the parent's uid 0 needs `CAP_SETFCAP`, and that map is a
    /// root caller's, whose exec does not take its capabilities from the file.
    #[cfg(feature = "subid")]
    #[test]
    fn a_helper_granted_only_its_own_capability_is_a_working_one() {
        use rustix::thread::CapabilitySet;

        let setuid = u32::try_from(CapabilitySet::SETUID.bits()).expect("a low-word capability");
        let setgid = u32::try_from(CapabilitySet::SETGID.bits()).expect("a low-word capability");
        assert_eq!(
            file_capability_privilege(&capability_attribute(true, setuid), CapabilitySet::SETUID),
            HelperPrivilege::FileCaps,
        );
        assert_eq!(
            file_capability_privilege(&capability_attribute(true, setgid), CapabilitySet::SETGID),
            HelperPrivilege::FileCaps,
        );

        // The capability the map file asks for is the one that counts.
        assert_eq!(
            file_capability_privilege(&capability_attribute(true, setgid), CapabilitySet::SETUID),
            HelperPrivilege::None,
        );
        // Permitted but not raised at exec, which `newuidmap` does not do itself.
        assert_eq!(
            file_capability_privilege(&capability_attribute(false, setuid), CapabilitySet::SETUID),
            HelperPrivilege::None,
        );
        // An attribute too short to carry a permitted mask grants nothing.
        assert_eq!(
            file_capability_privilege(
                &capability_attribute(true, setuid)[..6],
                CapabilitySet::SETUID
            ),
            HelperPrivilege::None,
        );
    }

    #[test]
    fn overlay_probe_runs_without_panicking_and_cleans_up() {
        // The result is host-dependent, but the probe — which forks a child and
        // creates temporary files and directories — must always be safe to call
        // and must leave nothing behind under the scratch directory.
        let dir = Scratch::new("overlay-probe");
        let _ = overlay_blocker(&dir);
        // No probe residue remains in the scratch directory.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(
            leftovers.is_empty(),
            "the overlay probe left {} entries behind",
            leftovers.len(),
        );
    }

    #[test]
    fn unique_hex_distinguishes_calls_within_one_process() {
        // The doc comment promises a name no concurrent caller collides with,
        // and the promise has to hold when `getrandom` is unavailable — where
        // the entropy is the seed alone. A pid seed cannot distinguish two calls
        // in one process, so the process-wide counter is what makes this true
        // rather than the randomness.
        let names: std::collections::HashSet<String> = (0..1000).map(|_| unique_hex()).collect();
        assert_eq!(names.len(), 1000, "unique_hex repeated a name");
        assert!(names.iter().all(|name| name.len() == 16));
    }

    #[test]
    fn a_fill_resumes_a_short_read_where_it_stopped() {
        // Three bytes at a time, counting up, so a fill that restarted rather
        // than resumed would overwrite what it had and leave the tail zero.
        let mut next = 1u8;
        let mut buf = [0u8; 8];
        fill_from(&mut buf, |rest| {
            let take = rest.len().min(3);
            for byte in &mut rest[..take] {
                *byte = next;
                next += 1;
            }
            Ok(take)
        })
        .expect("the fill completes");
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn a_fill_retries_an_interruption_and_reports_a_failure() {
        let mut interrupted = false;
        let mut buf = [0u8; 4];
        fill_from(&mut buf, |rest| match interrupted {
            false => {
                interrupted = true;
                Err(Errno::INTR)
            }
            true => {
                rest.fill(7);
                Ok(rest.len())
            }
        })
        .expect("an interruption is retried");
        assert_eq!(buf, [7; 4]);

        assert_eq!(
            fill_from(&mut buf, |_| Err(Errno::NOSYS)),
            Err(Errno::NOSYS),
            "any other failure is the caller's to judge",
        );
    }

    #[test]
    fn a_read_of_nothing_ends_the_fill_rather_than_spinning() {
        let mut reads = 0;
        let mut buf = [0u8; 8];
        let outcome = fill_from(&mut buf, |_| {
            reads += 1;
            assert!(reads < 100, "the fill spun on a read of nothing");
            Ok(0)
        });
        assert_eq!(outcome, Err(Errno::IO));
        assert_eq!(reads, 1);
    }

    #[test]
    fn the_kernels_randomness_fills_a_buffer() {
        let mut buf = [0u8; 64];
        fill_random(&mut buf).expect("the kernel's randomness is available");
        assert!(buf.iter().any(|&byte| byte != 0));
        // An empty buffer asks nothing of the kernel.
        fill_random(&mut []).expect("nothing to fill");
    }

    #[test]
    fn probe_names_differ_between_calls() {
        // The names carry kernel entropy, not just a pid, so a neighbour in a
        // shared scratch directory cannot predict — and squat on — the next one.
        let first = probe_name(".fcage-probe-");
        let second = probe_name(".fcage-probe-");
        assert!(first.starts_with(".fcage-probe-"));
        assert_ne!(first, second);
    }

    #[test]
    fn the_xattr_probe_refuses_a_planted_name() {
        // A neighbour who guesses the probe's name must not have the probe write
        // through what it finds there. Both plants are refused outright, and the
        // symlink's target survives intact.
        let dir = Scratch::new("plant");
        std::fs::write(dir.join("victim"), b"intact").unwrap();
        std::os::unix::fs::symlink("victim", dir.join("link")).unwrap();
        std::fs::write(dir.join("regular"), b"mine").unwrap();

        let parent = open_dir(&dir).unwrap();
        for name in ["link", "regular"] {
            assert_eq!(
                create_probe_file(&parent, name).map(|_| ()),
                Err(rustix::io::Errno::EXIST),
                "the probe created {name} over a planted entry",
            );
        }
        assert_eq!(std::fs::read(dir.join("victim")).unwrap(), b"intact");

        // The mount probe's directory is created the same way, and `mkdirat`
        // refuses a planted name for the same reason.
        assert_eq!(
            rustix::fs::mkdirat(&parent, "link", Mode::RWXU),
            Err(rustix::io::Errno::EXIST),
        );
    }

    #[test]
    fn sysctl_value_parses_a_leading_integer() {
        // max_user_namespaces exists on any modern kernel and holds a
        // non-negative integer.
        if let Some(value) = sysctl_value("/proc/sys/user/max_user_namespaces") {
            assert!(value >= 0);
        }
    }

    #[test]
    fn sysctl_value_is_none_for_missing_files() {
        assert_eq!(sysctl_value("/proc/sys/ferroday/cage/does_not_exist"), None);
    }
}
