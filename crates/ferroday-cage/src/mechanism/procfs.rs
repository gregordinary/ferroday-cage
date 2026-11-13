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
use rustix::thread::{self, UnshareFlags};

use super::sys::{self, PidfdFork};

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

    // SAFETY: the child branch runs only raw syscalls over the data formatted
    // above, with no allocation, no lock and no libc, and always ends in
    // `exit_group`. `sys::fork_with_pidfd` is the launch's own fork primitive.
    match unsafe { sys::fork_with_pidfd() } {
        Err(_) => ProcfsProbe::Inconclusive,
        Ok(PidfdFork::Child) => sys::exit_group(probe_child(&uid_line, &gid_line)),
        Ok(PidfdFork::ParentOf(child)) => match child.reap() {
            Ok(code) => classify(code),
            Err(_) => ProcfsProbe::Inconclusive,
        },
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
    if super::child::reset_signals(&sys::SigSet::empty()).is_err() {
        return EXIT_SETUP_FAILED;
    }
    // The caller's descriptors are closed for every forked child's reason,
    // which `sweep_fds_keeping` states, and the probe needs none of them.
    if super::child::sweep_fds_keeping(&[]).is_err() {
        return EXIT_SETUP_FAILED;
    }
    // A procfs belongs to the PID namespace of the process that mounts it, and
    // mounting one takes `CAP_SYS_ADMIN` over that namespace's owner. Only a
    // PID namespace this user namespace owns grants it, so the mount is made by
    // a process inside one, which `unshare` gives the next child alone.
    let flags = UnshareFlags::NEWUSER | UnshareFlags::NEWNS | UnshareFlags::NEWPID;
    // SAFETY: `unshare_unsafe` is unsafe only because `UnshareFlags::FILES`
    // could invalidate descriptors other threads observe; these flags omit it,
    // and this is a freshly forked single-threaded child besides.
    if unsafe { thread::unshare_unsafe(flags) }.is_err() {
        return EXIT_SETUP_FAILED;
    }
    if super::child::write_file(c"/proc/self/setgroups", b"deny").is_err()
        || super::child::write_file(c"/proc/self/gid_map", gid_line).is_err()
        || super::child::write_file(c"/proc/self/uid_map", uid_line).is_err()
    {
        return EXIT_SETUP_FAILED;
    }
    // SAFETY: as for the fork above; the grandchild runs `mount_in_namespace`,
    // which keeps the same discipline, and ends in `exit_group`. Reaping it
    // through its pidfd is one raw syscall.
    match unsafe { sys::fork_with_pidfd() } {
        Err(_) => EXIT_SETUP_FAILED,
        Ok(PidfdFork::Child) => sys::exit_group(mount_in_namespace()),
        Ok(PidfdFork::ParentOf(grandchild)) => match grandchild.reap() {
            Ok(code) => code.unwrap_or(EXIT_SETUP_FAILED),
            Err(_) => EXIT_SETUP_FAILED,
        },
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
