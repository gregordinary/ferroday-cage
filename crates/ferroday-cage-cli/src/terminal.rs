//! The terminal relay: `fcage`'s side of `--terminal`.
//!
//! A terminal launch gives the sandbox a pseudoterminal of its own. What is
//! left is the caller side: putting `fcage`'s own terminal into raw mode so
//! keystrokes pass through unbuffered, moving bytes between it and the
//! sandbox's terminal, and restoring it afterwards on every exit the process
//! can observe. That is deliberately not in the library — a library that can
//! leave the user's shell unusable is a worse failure than the one the terminal
//! feature started from — so it lives here, where process-global state is
//! legitimately ownable.
//!
//! The guide reproduces this module as the reference implementation for a
//! consumer building the same thing.
//!
//! # Signals are data
//!
//! The relay blocks the signals it cares about before anything else starts and
//! reads them as one channel of its poll loop, from a `signalfd`. No `fcage`
//! code runs in signal context: there are no handlers, no async-signal-safety
//! reasoning, and no shared flags — a signal is a poll event handled by
//! ordinary code.
//!
//! # `unsafe`
//!
//! This is the one module of `fcage` that needs it, and it needs exactly two
//! calls. rustix offers no safe wrapper for either: `kernel_sigprocmask` is in
//! its low-level `runtime` module, and `signalfd` it does not wrap at all, so
//! that one goes through the `syscalls` conduit the binary already carries for
//! seccomp names — the same route the library takes for `mount_setattr`. Both
//! are of the shape "pass a pointer to a live local of matching size", and
//! neither creates, frees, or aliases anything.

#![allow(unsafe_code)]

use std::io::{self, Write as _};
use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ferroday_cage::{ExitStatus, Pty, Running, Terminal};
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::OFlags;
use rustix::io::Errno;
use rustix::process::Signal;
use rustix::runtime::{How, KernelSigSet};
use rustix::termios::{self, OptionalActions, SpecialCodeIndex, Termios};
use syscalls::Sysno;

/// The signals the relay reads as data rather than letting the kernel act on.
///
/// Blocking them is what makes them readable from the descriptor instead of
/// delivered to a handler. `SIGQUIT` earns its place by being blocked alone: its
/// default action would dump core and take the process down with the caller's
/// terminal still in raw mode.
const RELAYED: [Signal; 7] = [
    Signal::WINCH,
    Signal::INT,
    Signal::TERM,
    Signal::HUP,
    Signal::QUIT,
    Signal::TSTP,
    Signal::CONT,
];

/// The size of one `struct signalfd_siginfo`, whose first field is the signal
/// number as a little-endian `u32`. The struct is padded to a fixed size the
/// kernel promises not to change.
const SIGINFO_LEN: usize = 128;

/// The relay's read buffer, per direction and per wake.
const RELAY_BUF: usize = 8192;

/// The caller's termios as it was before raw mode, saved once.
///
/// A `OnceLock` rather than a mutex: [`restore`] is called from a panic hook,
/// where a mutex the panicking thread already held would deadlock or answer
/// with a poisoned lock. Written once before raw mode is entered and never
/// mutated, so a lock-free read is always correct.
static ORIGINAL: OnceLock<Termios> = OnceLock::new();

/// Installs the panic hook that restores the caller's terminal, once per
/// process.
static PANIC_HOOK: OnceLock<()> = OnceLock::new();

/// A relay failure: the library's, or the relay's own I/O.
#[derive(Debug)]
pub enum RelayError {
    /// The sandbox handle failed — signalling it, or collecting its outcome.
    Cage(ferroday_cage::Error),
    /// The relay's own plumbing failed: the signal descriptor, the poll, or a
    /// read or write of one of the three channels.
    Io(io::Error),
}

impl From<ferroday_cage::Error> for RelayError {
    fn from(error: ferroday_cage::Error) -> RelayError {
        RelayError::Cage(error)
    }
}

impl From<Errno> for RelayError {
    fn from(errno: Errno) -> RelayError {
        RelayError::Io(errno.into())
    }
}

impl From<io::Error> for RelayError {
    fn from(error: io::Error) -> RelayError {
        RelayError::Io(error)
    }
}

/// The blocked signals, readable as a descriptor.
///
/// Created before the sandbox is built, and before any thread the run may start:
/// a thread inherits the creating thread's signal mask, so blocking first is
/// what keeps a process-directed `SIGINT` from being delivered to, say, the
/// network stack's pump thread and killing the process behind the relay's back.
pub struct Signals {
    fd: OwnedFd,
}

impl Signals {
    /// Blocks the relayed signals and opens the descriptor they arrive on.
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
        // Blocking these seven interferes with nothing in the process: the
        // standard library installs handlers only for SIGPIPE and the
        // stack-overflow SIGSEGV, neither of which is in the set.
        unsafe { rustix::runtime::kernel_sigprocmask(How::BLOCK, Some(&blocked)) }?;

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
        .map_err(|err| io::Error::from_raw_os_error(err.into_raw()))?;
        // SAFETY: the syscall returned a fresh, owned file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        Ok(Signals { fd })
    }

    /// Reads one pending signal, or `None` when none is pending.
    ///
    /// The descriptor is non-blocking, so this is safe to call until it answers
    /// `None` — which is what drains a wake that carried several at once.
    fn next(&self) -> Result<Option<Signal>, RelayError> {
        let mut record = [0u8; SIGINFO_LEN];
        match rustix::io::read(&self.fd, &mut record) {
            Ok(0) => Ok(None),
            Ok(_) => {
                let number = i32::from_le_bytes(
                    record[0..4]
                        .try_into()
                        .expect("a four-byte slice converts to an array"),
                );
                // `from_named_raw` refuses a number this build has no name for,
                // which is exactly right here: only the blocked set can arrive,
                // and anything else is a record to ignore rather than act on.
                Ok(Signal::from_named_raw(number))
            }
            Err(Errno::AGAIN | Errno::INTR) => Ok(None),
            Err(errno) => Err(errno.into()),
        }
    }
}

/// `SFD_CLOEXEC`, so no exec'd descendant inherits the signal descriptor.
///
/// `signalfd4` takes the `O_*` bits under other names: `SFD_CLOEXEC` is
/// `O_CLOEXEC` and `SFD_NONBLOCK` is `O_NONBLOCK`. Those values differ by
/// architecture, so both are read from rustix's per-target table rather than
/// written out here.
const SFD_CLOEXEC: usize = OFlags::CLOEXEC.bits() as usize;
/// `SFD_NONBLOCK`, so draining the descriptor never blocks the loop.
const SFD_NONBLOCK: usize = OFlags::NONBLOCK.bits() as usize;

/// Whether `fcage`'s own standard input is a terminal.
///
/// Decides raw mode and the restoration that follows it, and nothing else. A
/// run whose input is a pipe still relays; it simply has no terminal of its own
/// to put into raw mode or restore.
fn caller_is_terminal() -> bool {
    termios::tcgetattr(rustix::stdio::stdin()).is_ok()
}

/// The caller terminal's current size, or `None` when it has none to report.
///
/// The ambient read the library refuses to make. It is legitimate here: a binary
/// may read the terminal it was started from, and the caller that owns the relay
/// owns the size.
///
/// A zero in either dimension is `None` rather than a size. That is what a
/// terminal reports when its size is *unknown* — a pseudoterminal nobody has
/// sized, which is what a terminal multiplexer or `script(1)` hands on when it
/// was itself started without one — and passing it through would give the
/// sandbox a terminal that answers "no size" to everything that asks. Programs
/// treat that as an error rather than as a default: `stty size` refuses it
/// outright, and a full-screen program has nothing to draw into.
pub fn caller_size() -> Option<(u16, u16)> {
    let size = termios::tcgetwinsize(rustix::stdio::stdin()).ok()?;
    (size.ws_row != 0 && size.ws_col != 0).then_some((size.ws_row, size.ws_col))
}

/// The terminal to allocate for the sandbox: the caller's own size where there
/// is one, and the stated default otherwise.
///
/// A `--terminal` run from a script degrades to a plain byte relay around a
/// sandbox that still has a real terminal of its own, at 80x24.
pub fn terminal_for_caller() -> Terminal {
    match caller_size() {
        Some((rows, cols)) => Terminal::new().size(rows, cols),
        None => Terminal::new(),
    }
}

/// Restores the caller's terminal to the settings saved before raw mode.
///
/// Idempotent and lock-free, so every exit path may call it without
/// coordination, including the panic hook. A no-op before raw mode was entered,
/// which is what makes every failure before that point leave the terminal
/// untouched.
///
/// The flush is deliberate: input pending at restoration is raw bytes typed at a
/// session that no longer exists, and discarding them beats letting half an
/// escape sequence land at the caller's prompt.
fn restore() {
    if let Some(original) = ORIGINAL.get() {
        let _ = termios::tcsetattr(rustix::stdio::stdin(), OptionalActions::Flush, original);
    }
}

/// Puts the caller's terminal into raw mode, saving the original the first time.
///
/// Raw mode is what makes the session behave: keystrokes pass through
/// unbuffered, and the *sandbox's* line discipline — not the caller's — turns a
/// typed `^C` into a `SIGINT` for the sandbox's own foreground process group.
fn enter_raw() -> Result<(), RelayError> {
    let current = termios::tcgetattr(rustix::stdio::stdin())?;
    // The first call records the terminal as the caller had it. A later one —
    // re-entering after a stop — must not overwrite that with the raw settings
    // it is restoring from.
    let original = ORIGINAL.get_or_init(|| current.clone());
    let mut raw = original.clone();
    raw.make_raw();
    termios::tcsetattr(rustix::stdio::stdin(), OptionalActions::Now, &raw)?;
    Ok(())
}

/// Installs the panic hook that restores before the default hook prints.
///
/// The ordering is the reason this exists rather than a guard alone: with
/// `OPOST` off a backtrace prints stair-stepped down the screen, so restoration
/// has to precede the message, and a drop runs after the hook.
fn install_panic_hook() {
    PANIC_HOOK.get_or_init(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            default(info);
        }));
    });
}

/// Restores the caller's terminal when it goes out of scope, however it does:
/// normal exit, an early return, or a panic unwinding through the relay's frame.
struct RawMode;

impl Drop for RawMode {
    fn drop(&mut self) {
        restore();
    }
}

/// Which channel a poll slot watches. The order is fixed so a slot's index is
/// stable whether or not the channel behind it is still live.
const STDIN: usize = 0;
const PRIMARY: usize = 1;
const SIGNALS: usize = 2;

/// How far the timeout escalation has gone.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Escalation {
    /// Running normally; the deadline is the caller's `--timeout`.
    Running,
    /// Terminated once; the deadline is the `--kill-after` grace.
    Terminated,
    /// Killed; no deadline remains.
    Killed,
}

/// Drives an interactive session to its end and returns the command's outcome.
///
/// `Ok(None)` means the timeout expired, whatever became of the command
/// afterwards — the same convention the non-terminal path follows.
///
/// The order on the way in is: everything fallible first, then raw mode
/// immediately before the loop, so every failure before that point leaves the
/// caller's terminal untouched. On the way out it reverses: the loop ends, the
/// terminal is restored, and only then is the outcome collected and reported.
pub fn relay(
    mut running: Running<'_>,
    pty: Pty,
    signals: Signals,
    timeout: Option<Duration>,
    kill_after: Duration,
) -> Result<Option<ExitStatus>, RelayError> {
    // A large paste must not stall the loop, so the primary is non-blocking and
    // what does not fit waits behind POLLOUT.
    let flags = rustix::fs::fcntl_getfl(&pty)?;
    rustix::fs::fcntl_setfl(&pty, flags | OFlags::NONBLOCK)?;

    let interactive = caller_is_terminal();
    if interactive {
        install_panic_hook();
        enter_raw()?;
    }
    // Dropped at every exit from here on, so the terminal is restored before
    // anything is printed or collected. Held even when the caller's standard
    // input is not a terminal, where restoring is a no-op.
    let _raw = RawMode;

    let outcome = pump(
        &mut running,
        &pty,
        &signals,
        interactive,
        timeout,
        kill_after,
    );
    drop(_raw);
    let expired = outcome?;

    // The wait is prompt: the loop ended at end-of-file on the primary, which
    // means every replica is closed and the command is already gone.
    let status = running.wait()?;
    Ok(if expired { None } else { Some(status) })
}

/// The loop proper. Returns whether the timeout expired.
fn pump(
    running: &mut Running<'_>,
    pty: &Pty,
    signals: &Signals,
    interactive: bool,
    timeout: Option<Duration>,
    kill_after: Duration,
) -> Result<bool, RelayError> {
    let stdin = rustix::stdio::stdin();
    let mut stdin_open = true;
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; RELAY_BUF];
    let mut escalation = Escalation::Running;
    let mut expired = false;
    let mut deadline = timeout.map(|timeout| Instant::now() + timeout);
    // A second interrupt escalates; the first is a request.
    let mut interrupted = false;

    loop {
        // Standard input is watched only while there is room to put what it
        // produces: with a full pending buffer, reading more would grow it
        // without bound.
        let watch_stdin = stdin_open && pending.is_empty();
        let mut primary_events = PollFlags::IN;
        if !pending.is_empty() {
            primary_events |= PollFlags::OUT;
        }
        let mut slots = [
            PollFd::new(
                &stdin,
                if watch_stdin {
                    PollFlags::IN
                } else {
                    PollFlags::empty()
                },
            ),
            PollFd::new(pty, primary_events),
            PollFd::new(&signals.fd, PollFlags::IN),
        ];

        let wait = deadline.map(timespec_until);
        match rustix::event::poll(&mut slots, wait.as_ref()) {
            Ok(0) => {
                // The deadline passed. Escalate, and keep relaying: the
                // sandbox's exit closes the replicas, end-of-file ends the loop,
                // and restoration happens on the normal path.
                expired = true;
                match escalation {
                    Escalation::Running => {
                        running.terminate()?;
                        escalation = Escalation::Terminated;
                        deadline = Some(Instant::now() + kill_after);
                    }
                    Escalation::Terminated => {
                        running.kill()?;
                        escalation = Escalation::Killed;
                        deadline = None;
                    }
                    Escalation::Killed => deadline = None,
                }
                continue;
            }
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(errno.into()),
        }

        let ready: [PollFlags; 3] = std::array::from_fn(|index| slots[index].revents());

        if ready[SIGNALS].intersects(PollFlags::IN) {
            while let Some(signal) = signals.next()? {
                match signal {
                    // The caller's terminal changed size; the sandbox's follows.
                    Signal::WINCH => {
                        if let Some((rows, cols)) = caller_size() {
                            pty.resize(rows, cols)?;
                        }
                    }
                    // These arrive only from outside: in raw mode a typed `^C`
                    // is a byte the relay forwards, which the sandbox's own line
                    // discipline turns into the sandbox's own SIGINT. Forwarding
                    // them is what keeps the caller's shell managing `fcage` as
                    // one job and `fcage` passing that on.
                    Signal::INT | Signal::TERM | Signal::HUP | Signal::QUIT => {
                        if interrupted {
                            running.kill()?;
                        } else {
                            running.terminate()?;
                            interrupted = true;
                        }
                    }
                    // Restore before stopping, so the shell that resumes finds
                    // its terminal as it left it. The self-directed SIGSTOP
                    // returns once something continues this process, and the
                    // SIGCONT that did so is pending on the descriptor.
                    Signal::TSTP => {
                        restore();
                        rustix::process::kill_process(rustix::process::getpid(), Signal::STOP)
                            .map_err(RelayError::from)?;
                    }
                    // Continued: re-enter raw mode and re-read the size, which
                    // may have changed while stopped. The discipline `less`
                    // follows.
                    Signal::CONT if interactive => {
                        enter_raw()?;
                        if let Some((rows, cols)) = caller_size() {
                            pty.resize(rows, cols)?;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Drain whatever the primary can take of the pending buffer, then
        // whatever standard input has produced since.
        if ready[PRIMARY].intersects(PollFlags::OUT) {
            flush_pending(pty, &mut pending)?;
        }
        if watch_stdin && ready[STDIN].intersects(PollFlags::IN | PollFlags::HUP) {
            match rustix::io::read(stdin, &mut buf) {
                Ok(0) => {
                    // End-of-input. There is no way to close a pseudoterminal's
                    // write side, so this is sent as the replica's own VEOF
                    // character, and the channel retires.
                    let veof = replica_veof(pty);
                    pending.push(veof);
                    flush_pending(pty, &mut pending)?;
                    stdin_open = false;
                }
                Ok(read) => {
                    pending.extend_from_slice(&buf[..read]);
                    flush_pending(pty, &mut pending)?;
                }
                Err(Errno::INTR | Errno::AGAIN) => {}
                Err(errno) => return Err(errno.into()),
            }
        }

        if ready[PRIMARY].intersects(PollFlags::IN | PollFlags::HUP) {
            match rustix::io::read(pty, &mut buf) {
                // End-of-file on the primary is the session-over signal.
                Ok(0) => return Ok(expired),
                Ok(read) => {
                    let mut out = io::stdout();
                    out.write_all(&buf[..read])?;
                    out.flush()?;
                }
                Err(Errno::INTR | Errno::AGAIN) => {}
                // Hangup on a pseudoterminal primary is EIO, and it is the same
                // end of session.
                Err(Errno::IO) => return Ok(expired),
                Err(errno) => return Err(errno.into()),
            }
        }
    }
}

/// Writes as much of `pending` to the primary as it will take, keeping the rest.
fn flush_pending(pty: &Pty, pending: &mut Vec<u8>) -> Result<(), RelayError> {
    while !pending.is_empty() {
        match rustix::io::write(pty, pending) {
            Ok(0) => return Ok(()),
            Ok(written) => {
                pending.drain(..written);
            }
            Err(Errno::AGAIN | Errno::INTR) => return Ok(()),
            // The session is over; what is left has nowhere to go, and the
            // primary's own read reports the end.
            Err(Errno::IO) => {
                pending.clear();
                return Ok(());
            }
            Err(errno) => return Err(errno.into()),
        }
    }
    Ok(())
}

/// The replica's current end-of-file character.
///
/// Read rather than assumed: Linux redirects a termios query on a
/// pseudoterminal primary to the replica, so this is what the sandbox's line
/// discipline calls end-of-file *now*, which a program inside is free to have
/// changed. The baseline's `^D` is the fallback for a query that fails.
fn replica_veof(pty: &Pty) -> u8 {
    termios::tcgetattr(pty)
        .map(|settings| settings.special_codes[SpecialCodeIndex::VEOF])
        .unwrap_or(0o004)
}

/// The time remaining until `deadline`, as a poll timeout; zero once it has
/// passed, which polls without blocking and reports the expiry.
fn timespec_until(deadline: Instant) -> Timespec {
    let remaining = deadline.saturating_duration_since(Instant::now());
    Timespec {
        tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(remaining.subsec_nanos()),
    }
}
