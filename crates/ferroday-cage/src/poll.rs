//! The `poll` discipline: how a loop states its timeout, and how it stops
//! watching a channel it is finished with.
//!
//! Both answers are subtle enough to be worth stating once. The supervisor
//! loop, the network stack's pump, and the terminal relay each block in `poll`
//! with a deadline and each retire channels as they close.
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
//! process has been reaped. So no slot holds a placeholder. The supervisor
//! loop gathers its live channels to the front of a fixed array and polls only
//! those. The terminal relay's one retiring channel, the caller's input, is
//! last, so it shortens the slice.

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

/// The processor time the thread `tid` of this process has used, in clock
/// ticks: what a test holding a loop to blocking measures it by.
///
/// A loop that blocks uses next to none over a window it waits through, and
/// one that spins uses the whole window. The user and system times are fields
/// 14 and 15 of the thread's `stat`. They are counted from the state, field 3,
/// which follows the parenthesised name, since the name may hold spaces.
#[cfg(test)]
pub(crate) fn thread_ticks(tid: i32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat"))
        .expect("a thread's statistics are readable");
    let fields: Vec<&str> = stat[stat.rfind(')').expect("a name") + 2..]
        .split_whitespace()
        .collect();
    let field = |at: usize| fields[at].parse::<u64>().expect("a tick count");
    field(11) + field(12)
}
