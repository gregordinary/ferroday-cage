//! Descriptors a test waits on.

use std::os::fd::AsFd;
use std::time::Instant;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;

/// Waits until `fd` is readable, and reports whether it became so before
/// `deadline`.
///
/// A test that waits on a descriptor waits against a deadline, so a channel
/// that never becomes ready fails the test rather than hanging the run. An
/// interrupted wait is resumed with what remains of the deadline.
///
/// # Panics
///
/// Where the wait fails for any reason but an interruption, which is a broken
/// test rather than an answer.
pub fn readable_by(fd: impl AsFd, deadline: Instant) -> bool {
    let fd = fd.as_fd();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(remaining.subsec_nanos()),
        };
        let mut slots = [PollFd::new(&fd, PollFlags::IN)];
        match poll(&mut slots, Some(&timeout)) {
            Ok(0) => return false,
            Ok(_) => return true,
            Err(Errno::INTR) => {}
            Err(errno) => panic!("waiting on a descriptor failed: {errno}"),
        }
    }
}
