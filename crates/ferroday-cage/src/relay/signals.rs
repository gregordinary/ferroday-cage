//! The relay's signals: blocked process-wide, and read back as data.
//!
//! # `unsafe`
//!
//! Two calls, and rustix offers no safe wrapper for either: `kernel_sigprocmask`
//! is in its low-level `runtime` module, and `signalfd` it does not wrap at all,
//! so that one goes through the `syscalls` conduit the crate already carries for
//! `mount_setattr` and the seccomp install. Both are of the shape "pass a
//! pointer to a live local of matching size", and neither creates, frees, or
//! aliases anything.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};

use rustix::fs::OFlags;
use rustix::io::Errno;
use rustix::process::Signal;
use rustix::runtime::{How, KernelSigSet};
use syscalls::Sysno;

use super::RelayError;

/// The signals a relay reads as data rather than letting the kernel act on.
///
/// Blocking them is what makes them readable from the descriptor instead of
/// delivered to a handler. `SIGQUIT` earns its place by being blocked alone: its
/// default action would dump core and take the process down with the caller's
/// terminal still in raw mode.
///
/// `SIGTTOU` is blocked for the effect of blocking it rather than for anything
/// read back. A `tcsetattr` from a background process group raises it, and its
/// default action stops the process — so a relay put into the background would
/// stop while entering raw mode or, worse, while restoring, leaving the caller's
/// terminal raw with nothing left to fix it. Blocked, the call succeeds instead,
/// and the restoration discipline holds from the background as it does from the
/// foreground. `SIGTTIN` is deliberately *not* blocked: a backgrounded relay
/// stopping when it tries to read the terminal is the conventional behavior, and
/// the one the caller's shell reports.
pub(super) const RELAYED: [Signal; 8] = [
    Signal::WINCH,
    Signal::INT,
    Signal::TERM,
    Signal::HUP,
    Signal::QUIT,
    Signal::TSTP,
    Signal::CONT,
    Signal::TTOU,
];

/// The size of one `struct signalfd_siginfo`, whose first field is the signal
/// number as a `__u32` in the host's own byte order. The struct is padded to a
/// fixed size the kernel promises not to change.
const SIGINFO_LEN: usize = 128;

/// `SFD_CLOEXEC`, so no exec'd descendant inherits the signal descriptor.
///
/// `signalfd4` takes the `O_*` bits under other names: `SFD_CLOEXEC` is
/// `O_CLOEXEC` and `SFD_NONBLOCK` is `O_NONBLOCK`. Those values differ by
/// architecture, so both are read from rustix's per-target table rather than
/// written out here.
const SFD_CLOEXEC: usize = OFlags::CLOEXEC.bits() as usize;
/// `SFD_NONBLOCK`, so draining the descriptor never blocks the loop.
const SFD_NONBLOCK: usize = OFlags::NONBLOCK.bits() as usize;

/// The relay's signals, blocked process-wide and readable as a descriptor.
///
/// A relay handles `SIGWINCH`, `SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT`,
/// `SIGTSTP`, `SIGCONT`, and `SIGTTOU` as one channel of its poll loop. Blocking
/// them is what makes that possible: no library code runs in signal context,
/// there are no handlers, no async-signal-safety reasoning, and no shared flags
/// — a signal is a poll event handled by ordinary code.
///
/// # Call this first
///
/// [`install`](Self::install) is the one process-global thing the relay does,
/// and it is the caller's explicit call rather than a side effect of relaying.
/// Call it **on the main thread, before building the sandbox and before
/// creating any thread**: a thread inherits the creating thread's mask, so
/// blocking first is what keeps a process-directed `SIGINT` from being delivered
/// to some other thread and killing the process behind the relay's back. The
/// library starts exactly one thread of its own — the native network stack's
/// pump, with the `netstack` feature — so a program composing a relay with a
/// stack installs this before it attaches one.
///
/// The blocked set stays blocked for the process's life. That is deliberate: a
/// relay that restored the mask on the way out would leave a window in which the
/// signals it exists to handle were fatal again, and a program that relays one
/// session usually relays another.
///
/// # What it costs
///
/// Nothing the standard library depends on. It installs handlers only for
/// `SIGPIPE` and the stack-overflow `SIGSEGV`, neither of which is in the set. A
/// program that has signal handling of its own for one of the eight should not
/// install this, because the block is process-wide and the descriptor is where
/// those signals go instead.
///
/// ```no_run
/// use ferroday_cage::relay::Signals;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Before the sandbox, and before anything that might start a thread.
/// let signals = Signals::install()?;
/// # let _ = signals;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Signals {
    /// The `signalfd`. Non-blocking, so draining it never stalls the loop.
    fd: OwnedFd,
}

impl Signals {
    /// Blocks the relayed signals and opens the descriptor they arrive on.
    ///
    /// Idempotent in effect but not in resources: a second call blocks an
    /// already-blocked set and opens a second descriptor, and two descriptors in
    /// one process race for a process-directed signal — whichever reads first
    /// consumes it. One per process is the shape to build.
    pub fn install() -> Result<Signals, RelayError> {
        let mut blocked = KernelSigSet::empty();
        let mut mask = 0u64;
        for signal in RELAYED {
            blocked.insert(signal);
            // The kernel's `sigset_t` numbers signals from zero, so signal `n`
            // is bit `n - 1`. Every relayed signal is well under 64.
            mask |= 1u64 << (signal.as_raw() - 1);
        }
        // SAFETY: `blocked` is a live local of exactly the type the call takes.
        // Blocking the relayed set interferes with nothing in the process: the
        // standard library installs handlers only for SIGPIPE and the
        // stack-overflow SIGSEGV, neither of which is in it.
        unsafe { rustix::runtime::kernel_sigprocmask(How::BLOCK, Some(&blocked)) }
            .map_err(RelayError::at("blocking the relayed signals"))?;

        // SAFETY: `mask` is a live local `u64`, whose size is passed alongside
        // it and matches the kernel's `sigset_t` on every architecture this
        // crate builds for. The first argument, -1, asks for a new descriptor
        // rather than modifying an existing one, and the call returns an owned
        // file descriptor on success.
        let fd = unsafe {
            syscalls::syscall!(
                Sysno::signalfd4,
                -1i32,
                &mask as *const u64,
                size_of::<u64>(),
                SFD_CLOEXEC | SFD_NONBLOCK
            )
        }
        .map_err(|err| {
            RelayError::io(
                "opening the signal descriptor",
                io::Error::from_raw_os_error(err.into_raw()),
            )
        })?;
        // SAFETY: the syscall returned a fresh, owned file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        Ok(Signals { fd })
    }

    /// The descriptor, for the relay's poll set.
    pub(super) fn as_fd(&self) -> rustix::fd::BorrowedFd<'_> {
        rustix::fd::AsFd::as_fd(&self.fd)
    }

    /// Reads one pending signal, or `None` when none is pending.
    ///
    /// The descriptor is non-blocking, so this is safe to call until it answers
    /// `None` — which is what drains a wake that carried several at once.
    ///
    /// A record naming a number this build has no name for is skipped rather
    /// than answered with `None`: `None` means "the descriptor is drained" to
    /// the loop, so returning it for an unrecognized record would leave
    /// everything queued behind that record waiting for the next wake — which,
    /// with nothing else ready, is however long the deadline is. Unreachable
    /// today, since only the blocked set can arrive and all of it is named.
    pub(super) fn next(&self) -> Result<Option<Signal>, RelayError> {
        let mut record = [0u8; SIGINFO_LEN];
        loop {
            match rustix::io::read(&self.fd, &mut record) {
                Ok(0) => return Ok(None),
                Ok(_) => {
                    // `ssi_signo` is a `__u32` the kernel fills in the host's
                    // own byte order, so the decode is native-endian.
                    let number = i32::from_ne_bytes(
                        record[0..4]
                            .try_into()
                            .expect("a four-byte slice converts to an array"),
                    );
                    if let Some(signal) = Signal::from_named_raw(number) {
                        return Ok(Some(signal));
                    }
                }
                Err(Errno::AGAIN | Errno::INTR) => return Ok(None),
                Err(errno) => {
                    return Err(RelayError::at("reading the signal descriptor")(errno));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Raises `signal` at *this* thread.
    ///
    /// Thread-directed rather than process-directed, because a test binary runs
    /// its tests on threads of their own and only this one has the relayed set
    /// blocked. A process-directed signal is delivered to any thread that has
    /// not blocked it, so it would be taken by some other test's thread and
    /// acted on — which for `SIGWINCH` means silently discarded, and for the
    /// rest means the run ends.
    fn raise_here(signal: Signal) {
        let tid = rustix::thread::gettid();
        // SAFETY: the signal is one this thread has blocked, so it is made
        // pending rather than delivered, and nothing runs in signal context.
        // The thread id is this thread's own and cannot have been recycled
        // while this thread is the one asking for it.
        unsafe { rustix::runtime::tkill(tid, signal) }.expect("the signal is deliverable");
    }

    #[test]
    fn a_blocked_signal_arrives_on_the_descriptor_rather_than_being_acted_on() {
        let signals = Signals::install().expect("the signal descriptor opens");
        assert_eq!(
            signals.next().expect("a drained descriptor reads"),
            None,
            "nothing has been raised yet",
        );

        raise_here(Signal::WINCH);
        assert_eq!(
            signals.next().expect("the descriptor reads"),
            Some(Signal::WINCH),
        );
        assert_eq!(
            signals.next().expect("the descriptor reads"),
            None,
            "one record was queued and one was read",
        );
    }

    #[test]
    fn a_wake_carrying_several_signals_drains_to_none() {
        let signals = Signals::install().expect("the signal descriptor opens");
        // Two distinct signals, since identical ones coalesce while pending.
        raise_here(Signal::WINCH);
        raise_here(Signal::CONT);

        let mut read = Vec::new();
        while let Some(signal) = signals.next().expect("the descriptor reads") {
            read.push(signal);
        }
        read.sort_by_key(|signal| signal.as_raw());
        let mut expected = vec![Signal::WINCH, Signal::CONT];
        expected.sort_by_key(|signal| signal.as_raw());
        assert_eq!(read, expected);
    }
}
