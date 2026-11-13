//! An out-of-band probe for a fresh procfs.
//!
//! A sandbox with a PID namespace of its own mounts a procfs for that
//! namespace, and the kernel lets a process in a user namespace mount one only
//! where its mount namespace already holds a procfs that is fully visible: one
//! with no mount on any of its entries except the permanently empty
//! directories the kernel keeps for mounting on. A container runtime's masks
//! are such mounts, so inside a default container the mount is refused with
//! `EPERM` whatever the sandbox does. The rule also weighs the existing
//! procfs's own read-only and access-time flags, which no file reports.
//!
//! So whether a launch's procfs mounts is a mount to attempt rather than a
//! table to read. This forks a throwaway child that unshares a user, a mount
//! and a PID namespace, single-identity-maps itself, and forks once more so
//! that the grandchild is the new PID namespace's first process. That process
//! mounts a procfs as the launch's [`MountAction::Procfs`] step does, with the
//! launch's flags. The children keep the post-fork discipline the launch
//! stages keep (see [`child`](super::child)).
//!
//! [`MountAction::Procfs`]: super::MountAction::Procfs

use rustix::io::Errno;
use rustix::mount::{self, MountFlags, MountPropagationFlags};
use rustix::thread::UnshareFlags;

use super::child::{MapDuty, MapPaths, enter_mapped_namespace};
use super::sys;

/// The outcome of the procfs probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcfsProbe {
    /// A fresh procfs mounted.
    Mounted,
    /// The kernel refused the mount.
    Refused,
    /// The probe could not set up the namespaces to test in, so it says nothing
    /// about the procfs: the caller defers to the user-namespace diagnosis.
    Inconclusive,
}

/// The flags a fresh procfs is mounted with, by a launch and by the probe
/// alike: the rule the kernel applies weighs a new mount's flags against the
/// existing procfs's, so the probe asks with the launch's own.
pub(super) const FRESH_PROCFS_FLAGS: MountFlags = MountFlags::NOSUID
    .union(MountFlags::NODEV)
    .union(MountFlags::NOEXEC);

/// The grandchild mounted the procfs.
const EXIT_MOUNTED: i32 = 0;
/// The grandchild reached the mount and it was refused.
const EXIT_REFUSED: i32 = 1;
/// A child could not establish what the mount is tried in.
const EXIT_SETUP_FAILED: i32 = 2;

/// Forks a child that mounts a fresh procfs in namespaces of its own, as a
/// launch with a PID namespace does, and reports whether the kernel allowed it.
///
/// Nothing is mounted anywhere the caller can see: the mount is made in the
/// grandchild's private mount namespace, which goes away when it exits.
pub(crate) fn probe_procfs_mount() -> ProcfsProbe {
    let (uid_line, gid_line) = crate::idmap::single_identity_lines();

    // SAFETY: `probe_child` makes only raw syscalls over the data formatted
    // above, with no allocation, no lock, no libc and no panic.
    match unsafe { sys::probe(|| probe_child(&uid_line, &gid_line)) } {
        Ok(code) => classify(code),
        Err(_) => ProcfsProbe::Inconclusive,
    }
}

/// Maps a child's exit code, `None` where a signal ended it, onto the probe
/// outcome.
fn classify(code: Option<i32>) -> ProcfsProbe {
    match code {
        Some(EXIT_MOUNTED) => ProcfsProbe::Mounted,
        Some(EXIT_REFUSED) => ProcfsProbe::Refused,
        // EXIT_SETUP_FAILED, a signal, or anything else: the test never reached
        // the mount.
        _ => ProcfsProbe::Inconclusive,
    }
}

/// The probe child: unshares the three namespaces, maps itself, and forks the
/// grandchild that tries the mount, answering with the grandchild's code.
///
/// Runs under the post-fork constraints of [`child`](super::child).
fn probe_child(uid_line: &[u8], gid_line: &[u8]) -> i32 {
    // A procfs belongs to the PID namespace of the process that mounts it, and
    // mounting one takes `CAP_SYS_ADMIN` over that namespace's owner. Only a
    // PID namespace this user namespace owns grants it, so the mount is made by
    // a process inside one, which `unshare` gives the next child alone. The
    // probe keeps no descriptor.
    let duty = MapDuty::Write {
        paths: MapPaths::SELF,
        uid_line,
        gid_line,
    };
    let also = UnshareFlags::NEWNS | UnshareFlags::NEWPID;
    if enter_mapped_namespace(&[], also, duty, None).is_err() {
        return EXIT_SETUP_FAILED;
    }
    // SAFETY: `mount_in_namespace` keeps the same discipline as this child.
    match unsafe { sys::probe(mount_in_namespace) } {
        Ok(Some(code)) => code,
        Ok(None) | Err(_) => EXIT_SETUP_FAILED,
    }
}

/// The grandchild, the new PID namespace's first process: privatizes its mount
/// tree and mounts a procfs over `/proc`.
///
/// `/proc` is a target the probe's caller already has, and in this private
/// mount namespace a procfs stacked on it changes nothing outside. The kernel
/// weighs every procfs the namespace holds rather than the one under the
/// target, so the target does not decide the answer.
fn mount_in_namespace() -> i32 {
    if mount::mount_change(
        c"/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .is_err()
    {
        return EXIT_SETUP_FAILED;
    }
    match mount::mount(c"proc", c"/proc", c"proc", FRESH_PROCFS_FLAGS, c"") {
        Ok(()) => EXIT_MOUNTED,
        // A target the caller lacks says nothing about the rule.
        Err(Errno::NOENT | Errno::NOTDIR) => EXIT_SETUP_FAILED,
        Err(_) => EXIT_REFUSED,
    }
}
