//! An out-of-band probe for joining a cgroup.
//!
//! The launch stage moves itself into the sandbox's leaf cgroup by writing `0`
//! to the leaf's `cgroup.procs`, and whether the kernel allows that depends on
//! where the writer runs as much as on the cgroup: the writer must be able to
//! write the `cgroup.procs` of the nearest cgroup its own and the destination
//! share, and both must lie inside its cgroup namespace. No file reports that,
//! so whether a launch could join is a move to attempt. This forks a throwaway
//! child of the caller, in the caller's cgroup as a launch stage is, that makes
//! the same write and exits. The child keeps the post-fork discipline the
//! launch stages keep (see [`child`](super::child)).

use std::os::fd::{AsRawFd, BorrowedFd};

use rustix::io::Errno;

use super::sys;

/// The outcome of the join probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JoinProbe {
    /// The child moved itself into the cgroup.
    Joined,
    /// The kernel refused the move with this errno.
    Refused(Errno),
    /// The probe could not fork or collect its child, so it says nothing about
    /// the move.
    Inconclusive,
}

/// The child moved itself in.
const EXIT_JOINED: i32 = 0;
/// The child could not prepare to try the move.
const EXIT_SETUP_FAILED: i32 = 255;

/// Forks a child that moves itself into the cgroup whose `cgroup.procs` is
/// `procs`, the sandbox's leaf as the launch stage joins it, and reports
/// whether the kernel allowed it.
///
/// The child exits at once, so the cgroup holds nothing once the probe returns
/// and can be removed.
pub(crate) fn probe_cgroup_join(procs: BorrowedFd<'_>) -> JoinProbe {
    // SAFETY: `join_child` makes only raw syscalls, with no allocation, no
    // lock, no libc and no panic.
    match unsafe { sys::probe(|| join_child(procs)) } {
        Ok(Some(EXIT_JOINED)) => JoinProbe::Joined,
        Ok(Some(code)) if code != EXIT_SETUP_FAILED => {
            JoinProbe::Refused(Errno::from_raw_os_error(code))
        }
        _ => JoinProbe::Inconclusive,
    }
}

/// The probe child: the launch stage's write, answered as an exit code, the
/// errno where the kernel refused it. Every errno fits in the code's eight
/// bits.
///
/// Runs under the post-fork constraints of [`child`](super::child).
fn join_child(procs: BorrowedFd<'_>) -> i32 {
    // A handler of the caller's must not run in this copy of it.
    if super::child::reset_signals(&sys::SigSet::empty()).is_err() {
        return EXIT_SETUP_FAILED;
    }
    // The caller's descriptors are closed for every forked child's reason,
    // which `sweep_fds_keeping` states; the probe needs only the cgroup's.
    if super::child::sweep_fds_keeping(&[procs.as_raw_fd()]).is_err() {
        return EXIT_SETUP_FAILED;
    }
    match rustix::io::write(procs, b"0") {
        Ok(_) => EXIT_JOINED,
        Err(errno) => errno.raw_os_error(),
    }
}
