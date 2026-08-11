//! The `poll` discipline: how a loop states its timeout, and how it stops
//! watching a channel it is finished with.
//!
//! Both answers are subtle enough to be worth stating once. The supervisor
//! loop and the network stack's pump each block in `poll` with a deadline and
//! each retire channels as they close, and the `fcage` binary's terminal relay
//! does the same a crate away.

use std::os::fd::OwnedFd;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec};

/// Converts a remaining duration into a `poll` timeout.
///
/// `Duration` counts seconds as a `u64` and `Timespec` as an `i64`, so a
/// duration beyond the `i64` range has no faithful timeout. It saturates to the
/// longest one expressible rather than wrapping: a caller that asks to wait
/// roughly three hundred billion years is asking to wait indefinitely, and
/// answering with a short — or negative — timeout would turn that into a busy
/// loop.
pub(crate) fn timeout(duration: Duration) -> Timespec {
    Timespec {
        tv_sec: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(duration.subsec_nanos()),
    }
}

/// Builds the poll entry for a channel: the channel's descriptor when it is
/// live, and otherwise `placeholder` with no requested events.
///
/// # Why a placeholder rather than a muted descriptor
///
/// A loop that has finished with a channel has three ways to stop watching its
/// slot, and only two of them work:
///
/// - Substitute a *different*, live descriptor with `PollFlags::empty()`, as
///   this does. The slot stays quiet because the substitute can neither hang up
///   nor be invalid for as long as the loop holds it.
/// - Shorten the polled slice so the slot is not passed at all, which needs the
///   retiring channel to be last.
/// - Mute the *real* descriptor with `PollFlags::empty()`. This does not work.
///   `poll` reports `POLLHUP`, `POLLERR`, and `POLLNVAL` whatever the requested
///   events are, so a muted slot on a closed or hung-up descriptor is ready on
///   every pass and the loop spins at full CPU without ever blocking.
///
/// The placeholder here is the supervisor's own pidfd, which the loop owns for
/// its whole life, so the first technique holds. A loop whose retiring channel
/// is naturally last — the terminal relay's standard input — uses the second.
pub(crate) fn slot<'fd>(fd: &'fd Option<OwnedFd>, placeholder: &'fd OwnedFd) -> PollFd<'fd> {
    match fd {
        Some(fd) => PollFd::new(fd, PollFlags::IN),
        None => PollFd::new(placeholder, PollFlags::empty()),
    }
}
