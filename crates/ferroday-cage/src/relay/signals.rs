//! Signals blocked and read back as data: the relay's, blocked process-wide,
//! and the `SIGINT` a provisioning run's [`Interrupt`] holds while it works.
//!
//! # `unsafe`
//!
//! One call, the signal mask, which rustix offers a program like this one no
//! safe wrapper for. It is set through the launch mechanism's
//! [`sys::sigprocmask`], whose shape is "pass a pointer to a live local of
//! matching size", and it creates, frees, or aliases nothing. The descriptor
//! the signals are read from is the mechanism's [`sys::signalfd`].

#![allow(unsafe_code)]

use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use rustix::event::{EventfdFlags, PollFd, PollFlags};
use rustix::io::Errno;
use rustix::process::Signal;

use super::RelayError;
use crate::mechanism::sys::{self, How, SigSet};

/// The signals a relay reads as data rather than letting the kernel act on.
///
/// Blocking them is what makes them readable from the descriptor instead of
/// delivered to a handler. `SIGQUIT` earns its place by being blocked alone: its
/// default action would dump core and take the process down with the caller's
/// terminal still in raw mode.
///
/// `SIGTTOU` is blocked for the effect of blocking it rather than for anything
/// read back. A `tcsetattr` from a background process group raises it, and its
/// default action stops the process — so a relay put into the background while
/// raw would stop while restoring, leaving the caller's terminal raw with
/// nothing left to fix it. Blocked, the call succeeds instead, and the
/// restoration discipline holds from the background as it does from the
/// foreground. The same block would let a session *started* in the background
/// rewrite the terminal of the shell that holds it, which is why raw mode is
/// entered only from the foreground. `SIGTTIN` is not blocked, and the relay
/// does not raise it: it leaves the caller's input unread while it is in the
/// background, for the reason the relay's own module documentation gives.
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
/// to some other thread and killing the process behind the relay's back.
///
/// The library starts threads in three places, and each inherits the mask of the
/// thread that calls into it. A held [`Interrupt`] watches for `SIGINT` from a
/// thread of its own until it drops, which a program holds before it installs
/// this or after its relay is done. `NetStack::attach`, with the `netstack` feature,
/// starts the native network stack's pump, which runs for as long as the stack
/// is attached; a program composing a relay with a stack installs this before
/// it attaches one. `HttpFetch::fetch_all`, which a provisioner's downloads
/// reach, runs a batch on scoped workers and joins every one before it returns.
/// Those cannot outlive the call, so the order matters for them only where a
/// provisioner runs while a session is being relayed.
///
/// The blocked set stays blocked for the process's life. That is deliberate: a
/// relay that restored the mask on the way out would leave a window in which the
/// signals it exists to handle were fatal again, and a program that relays one
/// session usually relays another.
///
/// # Keep the handle for as long as the program should answer a signal
///
/// Dropping it closes the descriptor and does not unblock anything, because
/// nothing here restores the mask. From that point the eight signals are
/// blocked with nowhere to be read from, so the process ignores them entirely:
/// a shell's `^C` and a supervisor's `SIGTERM` both do nothing, and `SIGKILL` is
/// what is left.
///
/// For a program whose whole job is one session — `fcage --terminal` is the
/// worked example — the handle lives to process exit and the question does not
/// arise. For a library consumer relaying a session inside a longer-lived
/// program, which is the consumer this module was extracted for, holding the
/// handle for the program's life is the shape to build: it is the same handle
/// every later session needs, and one process wants exactly one.
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
    ///
    /// # Errors
    ///
    /// [`RelayError::Io`] where the mask cannot be set, or where the descriptor
    /// cannot be opened — descriptor exhaustion, or a seccomp policy that
    /// refuses `signalfd4`. A failed call leaves the caller's signal mask
    /// exactly as it found it: the permanent block described above is what a
    /// *successful* install establishes, and holding it with no descriptor to
    /// drain it would leave the process unable to answer `SIGINT` or `SIGTERM`
    /// at all.
    pub fn install() -> Result<Signals, RelayError> {
        Signals::install_with(sys::signalfd)
    }

    /// The body of [`install`](Self::install), with the descriptor opened by
    /// `open`.
    ///
    /// Split so the failure path is reachable from a test. `signalfd4` fails on
    /// descriptor exhaustion or a seccomp refusal, and a test can arrange
    /// neither without perturbing the whole test binary; what the failure path
    /// has to get right — the mask this call leaves behind — is independent of
    /// which of them it was.
    fn install_with(
        open: impl FnOnce(&SigSet) -> Result<OwnedFd, Errno>,
    ) -> Result<Signals, RelayError> {
        let blocked = SigSet::of(&RELAYED);
        // SAFETY: `blocked` is a live local of exactly the type the call takes.
        // Blocking the relayed set interferes with nothing in the process: the
        // standard library installs handlers only for SIGPIPE and the
        // stack-overflow SIGSEGV, neither of which is in it.
        let previous = unsafe { sys::sigprocmask(How::Block, Some(&blocked)) }
            .map_err(RelayError::at("blocking the relayed signals"))?;

        let fd = open(&blocked).map_err(|errno| {
            // No descriptor came back, so nothing will drain what was just
            // blocked. Left blocked, SIGINT and SIGTERM would do nothing to a
            // caller that logged this failure and carried on -- a service made
            // resistant to ordinary shutdown by the very call that reported it
            // could not relay. The permanent block is a property of a
            // *successful* install, where a descriptor exists to answer on it.
            //
            // Restoring the exact prior mask, rather than unblocking the
            // relayed set, is what keeps a signal the caller had blocked for its
            // own reasons blocked.
            //
            // SAFETY: `previous` is a live local of exactly the type the call
            // takes, and is the mask this same thread was running under a few
            // instructions ago.
            let _ = unsafe { sys::sigprocmask(How::SetMask, Some(&previous)) };
            RelayError::io("opening the signal descriptor", io::Error::from(errno))
        })?;
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
        let mut record = [0u8; sys::SIGINFO_LEN];
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

/// `SIGINT`, held back from ending the process while a provisioning run works,
/// and read as a request to stop the run.
///
/// [`ProvisionObserver::cancelled`] is how a run is stopped, and a program that
/// stops one on `^C` has to learn of the `SIGINT` without a handler of its own.
/// While this is held, the thread that holds it blocks `SIGINT`, and a thread
/// of the hold's own reads it from a descriptor instead of the kernel ending
/// the process. [`requested`](Self::requested) then answers `true`, an
/// observer answers `cancelled` from it, and the run stops at its next clean
/// point, removing what it staged.
///
/// The first `SIGINT` is all the hold takes. The next one acts as `SIGINT` does,
/// ending the process unless it has a handler of its own, so a second `^C` ends
/// a run that a stalled download keeps from its next clean point. Dropping the
/// hold puts the holding thread's mask back, and a `SIGINT` that arrived after
/// the hold's thread last looked is then delivered as it would have been
/// without the hold.
///
/// Where the process ignores `SIGINT`, as a shell leaves it for a command it
/// runs in the background, nothing is held and `requested` answers `false`
/// throughout: an ignored signal stops nothing.
///
/// # Hold it first
///
/// A signal mask is a thread's own, and the kernel delivers a `SIGINT` sent to
/// the process to any thread that does not block it. Hold this on the thread
/// that runs the provisioner, before the program creates any other thread. A
/// thread created while it is held, as a batch of downloads creates its
/// workers, inherits the block; one created before would take the signal and
/// end the process. A thread that already blocks `SIGINT`, as one with
/// [`Signals`] installed does, keeps it blocked when the hold ends, and the two
/// descriptors then race for each `SIGINT`: hold one or the other.
///
/// Neither `Send` nor `Sync`, since the block is the holding thread's own.
///
/// ```no_run
/// use ferroday_cage::provision::{Interrupt, Provision, ProvisionObserver};
///
/// struct StopOnInterrupt(Interrupt);
///
/// impl ProvisionObserver for StopOnInterrupt {
///     fn cancelled(&mut self) -> bool {
///         self.0.requested()
///     }
/// }
///
/// # #[cfg(feature = "tarball")]
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use ferroday_cage::provision::Tarball;
/// // Before the program starts any thread of its own.
/// let mut observer = StopOnInterrupt(Interrupt::hold()?);
/// Provision::new("/var/cache/myapp/alpine-rootfs")
///     .observe(&mut observer)
///     .run(&mut Tarball::new("alpine-minirootfs-3.24.1-x86_64.tar.gz"))?;
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "tarball"))]
/// # fn main() {}
/// ```
///
/// [`ProvisionObserver::cancelled`]: crate::provision::ProvisionObserver::cancelled
#[derive(Debug)]
pub struct Interrupt {
    /// The hold, or `None` where the process ignores `SIGINT`.
    held: Option<Held>,
}

/// A hold on `SIGINT`: the holding thread's block, and the thread that reads
/// what the block queues.
#[derive(Debug)]
struct Held {
    /// Whether a `SIGINT` has arrived, which the watching thread sets.
    requested: Arc<AtomicBool>,
    /// The eventfd that stops the watching thread when written.
    stop: OwnedFd,
    /// The watching thread, joined when the hold ends.
    watcher: Option<JoinHandle<()>>,
    /// Whether the holding thread blocked `SIGINT` before the hold, in which
    /// case ending the hold leaves it blocked.
    was_blocked: bool,
    /// Neither `Send` nor `Sync`: the block is the holding thread's, and only
    /// that thread can end it.
    _thread: PhantomData<*const ()>,
}

impl Interrupt {
    /// Holds `SIGINT` on the calling thread until this drops, or does nothing
    /// where the process ignores it.
    ///
    /// # Errors
    ///
    /// The OS error where the disposition cannot be read, the mask cannot be
    /// set, or the descriptor, the eventfd, or the watching thread cannot be
    /// made: descriptor exhaustion, or a seccomp policy that refuses one of the
    /// calls. A failed call leaves the thread's mask as it found it, and
    /// `SIGINT` then acts as it did before.
    pub fn hold() -> io::Result<Interrupt> {
        if sys::is_ignored(Signal::INT)? {
            return Ok(Interrupt { held: None });
        }
        let interrupt = SigSet::of(&[Signal::INT]);
        // SAFETY: `interrupt` is a live local of exactly the type the call
        // takes, and blocking a signal runs nothing.
        let previous = unsafe { sys::sigprocmask(How::Block, Some(&interrupt)) }?;
        let was_blocked = previous.without(&[Signal::INT]) != previous;
        match Interrupt::watch(&interrupt, was_blocked) {
            Ok(held) => Ok(Interrupt { held: Some(held) }),
            Err(error) => {
                if !was_blocked {
                    unblock_interrupt();
                }
                Err(error)
            }
        }
    }

    /// Whether a `SIGINT` has arrived since the hold began.
    pub fn requested(&self) -> bool {
        self.held
            .as_ref()
            .is_some_and(|held| held.requested.load(Ordering::Acquire))
    }

    /// Opens the descriptor `interrupt` arrives on, and starts the thread that
    /// reads it.
    fn watch(interrupt: &SigSet, was_blocked: bool) -> io::Result<Held> {
        let signals = sys::signalfd(interrupt)?;
        let stop = rustix::event::eventfd(0, EventfdFlags::CLOEXEC)?;
        let stopped = stop.try_clone()?;
        let requested = Arc::new(AtomicBool::new(false));
        let watcher = std::thread::Builder::new()
            .name("interrupt".to_string())
            .spawn({
                let requested = Arc::clone(&requested);
                move || watch_for_interrupt(&signals, &stopped, &requested, was_blocked)
            })?;
        Ok(Held {
            requested,
            stop,
            watcher: Some(watcher),
            was_blocked,
            _thread: PhantomData,
        })
    }
}

impl Drop for Interrupt {
    fn drop(&mut self) {
        let Some(held) = &mut self.held else {
            return;
        };
        // An eventfd write fails only on an overflow a single write cannot
        // reach.
        let _ = rustix::io::write(&held.stop, &1u64.to_ne_bytes());
        if let Some(watcher) = held.watcher.take() {
            let _ = watcher.join();
        }
        if !held.was_blocked {
            unblock_interrupt();
        }
    }
}

/// The watching thread's body: waits for the first `SIGINT` on `signals`, or
/// for `stop`, records the first in `requested`, and from then on leaves
/// `SIGINT` unblocked on this thread so the next acts as `SIGINT` does.
///
/// Where the holding thread blocked `SIGINT` before the hold, this thread
/// leaves it blocked as well: the block is the caller's own, and taking it
/// away from the process would undo it.
fn watch_for_interrupt(signals: &OwnedFd, stop: &OwnedFd, requested: &AtomicBool, keep: bool) {
    loop {
        let watching = !requested.load(Ordering::Relaxed);
        let mut fds = [
            PollFd::new(stop, PollFlags::IN),
            PollFd::new(signals, PollFlags::IN),
        ];
        let polled = if watching {
            &mut fds[..]
        } else {
            &mut fds[..1]
        };
        match rustix::event::poll(polled, None) {
            Ok(_) | Err(Errno::INTR) => {}
            Err(_) => return,
        }
        if !fds[0].revents().is_empty() {
            return;
        }
        if watching && !fds[1].revents().is_empty() && read_one(signals) {
            requested.store(true, Ordering::Release);
            if !keep {
                unblock_interrupt();
            }
        }
    }
}

/// Reads one record from a signal descriptor, answering whether there was one.
fn read_one(signals: &OwnedFd) -> bool {
    let mut record = [0u8; sys::SIGINFO_LEN];
    matches!(rustix::io::read(signals.as_fd(), &mut record), Ok(read) if read > 0)
}

/// Unblocks `SIGINT` on the calling thread, and nothing else.
fn unblock_interrupt() {
    // SAFETY: `None` asks only for the current mask, and nothing is set.
    let Ok(current) = (unsafe { sys::sigprocmask(How::Block, None) }) else {
        return;
    };
    // SAFETY: the set is a live local of exactly the type the call takes. Only
    // `SIGINT` is unblocked, on a thread that blocked it for a hold alone, so
    // it then does what the process's disposition for it says, as it would
    // have without the hold.
    let _ = unsafe { sys::sigprocmask(How::SetMask, Some(&current.without(&[Signal::INT]))) };
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
        unsafe { sys::tkill(tid, signal) }.expect("the signal is deliverable");
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

    /// This thread's current signal mask, read without changing it.
    fn mask_here() -> SigSet {
        // SAFETY: `None` asks only for the current mask; `how` is then ignored
        // and nothing is set.
        unsafe { sys::sigprocmask(How::Block, None) }
            .expect("reading a thread's own mask cannot fail")
    }

    /// Applies `how` with `set` to this thread's mask.
    fn set_mask_here(how: How, set: &SigSet) {
        // SAFETY: `set` is a live reference of exactly the type the call takes.
        unsafe { sys::sigprocmask(how, Some(set)) }
            .expect("setting a thread's own mask cannot fail");
    }

    #[test]
    fn a_failed_install_leaves_the_mask_exactly_as_it_found_it() {
        // Without the rollback, a caller that logs this failure and carries on
        // runs with SIGINT and SIGTERM blocked and no descriptor draining them:
        // the process stops answering ^C and an ordinary shutdown request,
        // having just reported that it could not relay. Restoring the prior mask
        // rather than unblocking the relayed set is what this pins -- a signal
        // the caller had blocked for its own reasons stays blocked.
        let mut mine = SigSet::empty();
        mine.insert(Signal::INT);
        set_mask_here(How::Block, &mine);
        assert!(!mask_here().contains(Signal::TERM), "the test's premise");

        let err = Signals::install_with(|_| Err(Errno::MFILE))
            .expect_err("the descriptor cannot be opened");
        assert!(
            err.to_string().contains("signal descriptor"),
            "{err}, expected the descriptor's own failure",
        );

        let after = mask_here();
        assert!(
            after.contains(Signal::INT),
            "a signal the caller had blocked was unblocked by a failed install",
        );
        for signal in RELAYED {
            if signal != Signal::INT {
                assert!(
                    !after.contains(signal),
                    "{signal:?} was left blocked with no descriptor to drain it",
                );
            }
        }

        set_mask_here(How::Unblock, &mine);
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
