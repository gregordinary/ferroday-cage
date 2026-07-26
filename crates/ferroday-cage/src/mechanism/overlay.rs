//! An out-of-band probe for unprivileged overlay support.
//!
//! Rooting a cage on an overlay needs a kernel that lets an unprivileged
//! process mount `overlay` inside a user namespace (Linux 5.11). Whether that
//! holds is not a sysctl to read but a mount to attempt, so this forks a
//! throwaway child that unshares a user and mount namespace, single-identity-
//! maps it, and tries the mount — exactly the sequence the real launch runs,
//! reduced to its overlay step. The child touches no allocator or lock and
//! only issues raw syscalls before it exits, the same discipline the launch
//! stages keep (see [`child`](super::child)).
//!
//! This answers only the mount question. Whether the upper layer's filesystem
//! can record an overlay's metadata — the `user.*` xattr support tmpfs gained
//! in Linux 6.6 — is a separate, fork-free check the [`host`](crate::host)
//! module makes directly on the target filesystem.

#![allow(unsafe_code)]

use std::ffi::CStr;

use rustix::io::Errno;
use rustix::mount::{self, MountFlags, MountPropagationFlags};
use rustix::process::{self, WaitStatus};
use rustix::runtime::{self, Fork};
use rustix::thread::{self, UnshareFlags};

/// The outcome of the overlay mount probe.
pub(crate) enum OverlayProbe {
    /// An unprivileged overlay mounted: the host supports overlay-rooted cages.
    Mounted,
    /// The kernel refused the overlay mount.
    MountFailed,
    /// The probe could not set up a user namespace to test in, so it says
    /// nothing about overlay support — the caller defers to the user-namespace
    /// diagnosis instead.
    Inconclusive,
}

/// The child exited having mounted the overlay.
const EXIT_MOUNTED: i32 = 0;
/// The child reached the mount and it was refused.
const EXIT_MOUNT_FAILED: i32 = 1;
/// The child could not establish the namespace to test in.
const EXIT_SETUP_FAILED: i32 = 2;

/// Forks a child that attempts an unprivileged overlay mount at `merged` with
/// `options`, and reports whether it succeeded.
///
/// `merged` is an existing empty directory to mount over, and `options` the
/// preformatted `lowerdir=…,upperdir=…,workdir=…,userxattr` string. Both name
/// directories on the host, resolved by the child before it swaps nothing —
/// there is no pivot here, only the mount, undone when the child's mount
/// namespace is torn down at exit.
pub(crate) fn probe_overlay_mount(merged: &CStr, options: &CStr) -> OverlayProbe {
    // The single-identity map lines, formatted before the fork where geteuid
    // still answers with the caller's id — the same constraint the launch
    // marshals its map lines under.
    let uid_line = format!("0 {} 1\n", process::geteuid().as_raw()).into_bytes();
    let gid_line = format!("0 {} 1\n", process::getegid().as_raw()).into_bytes();

    // SAFETY: the child branch runs only raw rustix syscalls over the data
    // frozen above — no allocation, no locking, no libc — and never returns:
    // it always ends in `exit_group`. `kernel_fork` is the launch's own
    // fork primitive.
    match unsafe { runtime::kernel_fork() } {
        Err(_) => OverlayProbe::Inconclusive,
        Ok(Fork::Child(_)) => {
            let code = probe_child(merged, options, &uid_line, &gid_line);
            runtime::exit_group(code)
        }
        Ok(Fork::ParentOf(child)) => match super::wait_for_exit(child) {
            Ok(status) => classify(status),
            Err(_) => OverlayProbe::Inconclusive,
        },
    }
}

/// Maps the child's wait status onto the probe outcome.
fn classify(status: WaitStatus) -> OverlayProbe {
    match status.exit_status() {
        Some(EXIT_MOUNTED) => OverlayProbe::Mounted,
        Some(EXIT_MOUNT_FAILED) => OverlayProbe::MountFailed,
        // EXIT_SETUP_FAILED, a signal, or anything else: the test never reached
        // a verdict on the mount.
        _ => OverlayProbe::Inconclusive,
    }
}

/// The probe child: unshare a user and mount namespace, single-identity-map it,
/// and attempt the overlay mount. Returns the exit code the parent classifies.
///
/// Runs under the post-fork constraints of [`child`](super::child): raw
/// syscalls over frozen data, no allocation, no panic.
fn probe_child(merged: &CStr, options: &CStr, uid_line: &[u8], gid_line: &[u8]) -> i32 {
    // Scrub inherited signal dispositions: an inherited handler must not run
    // inside this no-allocation child.
    if super::child::reset_signals().is_err() {
        return EXIT_SETUP_FAILED;
    }

    // SAFETY: `unshare_unsafe` is unsafe only because `UnshareFlags::FILES`
    // could invalidate descriptors observed by other threads; these flags omit
    // it, and this is a freshly forked single-threaded child besides.
    if unsafe { thread::unshare_unsafe(UnshareFlags::NEWUSER | UnshareFlags::NEWNS) }.is_err() {
        return EXIT_SETUP_FAILED;
    }

    // The single-identity map: deny setgroups so an unprivileged process may
    // write its own gid map, then the gid and uid lines. Root inside is the
    // caller outside — enough credential to mount overlay in the new namespace.
    if super::child::write_file(c"/proc/self/setgroups", b"deny").is_err()
        || super::child::write_file(c"/proc/self/gid_map", gid_line).is_err()
        || super::child::write_file(c"/proc/self/uid_map", uid_line).is_err()
    {
        return EXIT_SETUP_FAILED;
    }

    // Privatize the mount tree, as the real setup does, so the mount is
    // contained and cannot propagate.
    if mount::mount_change(
        c"/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .is_err()
    {
        return EXIT_SETUP_FAILED;
    }

    match mount::mount(c"overlay", merged, c"overlay", MountFlags::empty(), options) {
        Ok(()) => EXIT_MOUNTED,
        Err(_) => EXIT_MOUNT_FAILED,
    }
}

/// Whether an errno from a `user.*` xattr write means the filesystem does not
/// support that namespace, the condition that distinguishes an overlay-capable
/// upper from one (a pre-6.6 tmpfs) that cannot record overlay metadata.
///
/// Lives here beside the mount probe so the two halves of the overlay
/// preflight share one crate home; the caller in [`host`](crate::host) applies
/// it to a direct `setxattr` on the target filesystem.
pub(crate) fn xattr_unsupported(errno: Errno) -> bool {
    errno == Errno::NOTSUP
}
