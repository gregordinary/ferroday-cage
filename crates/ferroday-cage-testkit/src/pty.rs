//! Reading a pseudoterminal until it goes quiet.

use std::os::fd::AsFd;
use std::time::Instant;

/// Reads whatever `primary` has ready, waiting no later than `deadline`, and
/// appends it to `into`.
///
/// Returns whether the session is still producing: `false` at end of file, at
/// the hangup a pseudoterminal primary reports as `EIO`, or once the deadline
/// has passed.
///
/// Polled rather than read outright, so a deadline is a deadline: a blocking
/// read on a quiet session would ignore it and hang the whole run. `EINTR` and
/// `EAGAIN` both mean "nothing yet, ask again" and neither ends the session.
pub fn drain_until(primary: impl AsFd, deadline: Instant, into: &mut String) -> bool {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::io::Errno;

    let primary = primary.as_fd();
    let remaining = deadline.saturating_duration_since(Instant::now());
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(remaining.subsec_nanos()),
    };
    let mut slots = [PollFd::new(&primary, PollFlags::IN)];
    match poll(&mut slots, Some(&timeout)) {
        Ok(0) => return false,
        Ok(_) => {}
        Err(Errno::INTR) => return true,
        Err(errno) => panic!("waiting on the session failed: {errno}"),
    }
    let mut buf = [0u8; 4096];
    match rustix::io::read(primary, &mut buf) {
        Ok(0) | Err(Errno::IO) => false,
        Ok(read) => {
            into.push_str(&String::from_utf8_lossy(&buf[..read]));
            true
        }
        Err(Errno::INTR | Errno::AGAIN) => true,
        Err(errno) => panic!("reading the session failed: {errno}"),
    }
}
