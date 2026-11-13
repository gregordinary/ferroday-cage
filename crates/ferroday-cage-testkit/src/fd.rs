//! Descriptors a test waits on, and the standard descriptors a probe closes.

use std::os::fd::{AsFd, RawFd};
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

/// Runs `run` with the standard descriptors `closed` closed in this process,
/// and puts them back before returning what `run` returned.
///
/// For a probe running as a process of its own, a copy of its test binary
/// started for the purpose: a standard descriptor is the whole process's, and
/// closing one in the test harness's process would take the harness's output
/// and every test running beside it. `run` asserts nothing and prints nothing,
/// since a failed assertion reports through standard error, so it returns what
/// it found for the probe to assert once the streams are back.
///
/// The one other `unsafe` block in this crate, beside
/// `pty::spawn_controlled`'s.
///
/// # Panics
///
/// Where `closed` names a descriptor other than 0, 1 and 2, or one of them
/// cannot be copied aside or put back.
#[expect(unsafe_code)]
pub fn with_standard_streams_closed<T>(closed: &[RawFd], run: impl FnOnce() -> T) -> T {
    let saved = [
        rustix::stdio::stdin(),
        rustix::stdio::stdout(),
        rustix::stdio::stderr(),
    ]
    .map(|fd| rustix::io::fcntl_dupfd_cloexec(fd, 3).expect("a standard descriptor copies"));
    for &fd in closed {
        assert!((0..3).contains(&fd), "{fd} is not a standard descriptor");
        // SAFETY: a standard descriptor is held by no owned descriptor in this
        // process, and nothing reads or writes it until a copy from `saved` is
        // back in its place.
        unsafe { rustix::io::close(fd) };
    }
    let found = run();
    rustix::stdio::dup2_stdin(&saved[0]).expect("standard input is put back");
    rustix::stdio::dup2_stdout(&saved[1]).expect("standard output is put back");
    rustix::stdio::dup2_stderr(&saved[2]).expect("standard error is put back");
    found
}

/// Whether `fd` is open in this process, asked without opening a descriptor
/// that could take a closed number: `lstat` of its `/proc/self/fd` entry.
pub fn is_open(fd: RawFd) -> bool {
    std::fs::symlink_metadata(format!("/proc/self/fd/{fd}")).is_ok()
}
