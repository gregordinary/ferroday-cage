//! The `poll` discipline: how a loop states its timeout, and how it stops
//! watching a channel it is finished with.
//!
//! Both answers are subtle enough to be worth stating once. The running
//! handle's pump, the supervisor loop, the network stack's pump, and the
//! terminal relay each block in `poll` with a deadline and each retire channels
//! as they close.
//!
//! # A retired channel leaves the polled slice
//!
//! A loop that has finished with a channel stops watching it by not passing
//! it to `poll` at all. `poll` reports `POLLHUP`, `POLLERR`, and `POLLNVAL`
//! whatever events were requested, so a slot left in the slice with no events
//! asked of it is not quiet. On a closed or hung-up descriptor it is ready on
//! every pass, and the loop spins at full CPU without ever blocking.
//!
//! Substituting another descriptor in the retired slot fails the same way
//! unless that descriptor can never hang up, which is a property of its kind
//! rather than of who holds it. A pidfd is the trap here: the loop holds it
//! for its whole life and it stays valid, yet it reports `POLLHUP` once its
//! process has been reaped. So no slot holds a placeholder. The running
//! handle's pump gathers its live channels to the front of a fixed array and
//! polls only those. The supervisor loop has one retiring channel, the control
//! socket, and the terminal relay one, the caller's input; each sits at one end
//! of its array, so retiring it shortens the slice.

use std::time::Duration;

use rustix::event::Timespec;

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
