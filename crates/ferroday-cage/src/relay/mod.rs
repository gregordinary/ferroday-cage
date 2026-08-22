//! Driving an interactive terminal session from the caller's own terminal.
//!
//! A terminal launch gives the sandbox a pseudoterminal of its own. What is left
//! is the caller side: moving bytes between the caller's terminal and the
//! sandbox's, putting the caller's into raw mode so keystrokes pass through
//! unbuffered, and restoring it afterwards on every exit the process can
//! observe. [`Relay`] is that loop, and `fcage --terminal` is nothing but a
//! configuration of it.
//!
//! ```no_run
//! use std::os::fd::AsFd as _;
//!
//! use ferroday_cage::relay::{Relay, Signals, install_panic_restore};
//! use ferroday_cage::{Cage, Terminal};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // First, before the sandbox and before anything that might start a thread.
//! let signals = Signals::install()?;
//! // Restores the terminal before a backtrace prints, which a guard cannot.
//! install_panic_restore();
//!
//! let cage = Cage::builder()
//!     .rootfs("/srv/rootfs/alpine")
//!     .command("/bin/sh")
//!     .env("TERM", "xterm-256color")
//!     .build()?;
//! let (mut running, pty) = cage.spawn_terminal(&Terminal::new().size(24, 80))?;
//!
//! let stdin = std::io::stdin();
//! let stdout = std::io::stdout();
//! let outcome = Relay::new(stdin.as_fd(), stdout.as_fd())
//!     .raw(true)
//!     .run(&mut running, &pty, &signals)?;
//! # let _ = outcome;
//! # Ok(())
//! # }
//! ```
//!
//! # What stays the caller's
//!
//! The relay does nothing process-global as a side effect, and reads nothing
//! from the environment. Four decisions are therefore the caller's to make, and
//! a program driving a session makes all four:
//!
//! - **Install [`Signals`]** — early, on the main thread. Blocking the relayed
//!   set is process-wide, so it is an explicit call rather than something
//!   [`Relay::run`] does on the way past.
//! - **Decide raw mode.** [`Relay::raw`] is off unless asked; whether the
//!   caller's standard input is a terminal at all is the caller's reading, not
//!   the relay's.
//! - **Decide the panic hook.** [`install_panic_restore`] is one call, or a
//!   program with a hook of its own calls [`restore_terminal`] from it.
//! - **Decide the sandbox's terminal.** [`Terminal`](crate::Terminal) is a
//!   stated size; a caller that wants its own window's size reads it and passes
//!   it, because the library reads nothing of the host.
//!
//! # Signals are data
//!
//! The relay reads the signals it handles as one channel of its poll loop, from
//! the descriptor [`Signals::install`] opened. No library code runs in signal
//! context: there are no handlers, no async-signal-safety reasoning, and no
//! shared flags — a signal is a poll event handled by ordinary code.
//!
//! - **`SIGWINCH`** — read the size the *supplied* input descriptor reports and
//!   call [`Pty::resize`], which is how a full-screen program inside learns to
//!   redraw.
//! - **`SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT`** — forward: terminate the
//!   sandbox and keep relaying. The sandbox's exit closes the replicas,
//!   end-of-file ends the loop, and restoration happens on the normal path. A
//!   second such signal escalates to a kill. These arrive only from *outside*:
//!   in raw mode a typed `^C` is a byte the relay forwards, which the sandbox's
//!   own line discipline turns into the sandbox's own `SIGINT`, delivered to the
//!   sandbox's own foreground process group. Forwarding the four from outside is
//!   what keeps the caller's shell managing the relaying process as one job and
//!   that process passing the management on.
//! - **`SIGTSTP`** — restore the terminal, then stop with a self-directed
//!   `SIGSTOP`.
//! - **`SIGCONT`** — re-enter raw mode and re-read the window size, which may
//!   have changed while stopped. The discipline `less` follows.
//! - **`SIGTTOU`** — blocked for the effect of blocking it, and otherwise
//!   ignored; see [`Signals`].
//!
//! # The two directions are not symmetric
//!
//! The sandbox-bound direction cannot stall the loop: the primary is set
//! non-blocking and what it will not take waits in a pending buffer behind
//! `POLLOUT`, so a command that stops reading its terminal never blocks the
//! signal channel. The caller-bound direction is a plain blocking write, outside
//! the poll, and that is deliberate.
//!
//! The symmetric treatment would need `O_NONBLOCK` on the output descriptor.
//! That flag lives on the open file description, not on the descriptor, so
//! setting it sets it for everything sharing that description — the caller's
//! shell, and every other process in the pipeline the caller was started from,
//! which would begin seeing `EAGAIN` from writes they have no reason to expect
//! it on, and would keep seeing it if the process exited without restoring the
//! flag. That is a worse failure than the one it prevents, and it is a failure
//! in someone else's process.
//!
//! What is given up: with the output on a pipe whose reader has stopped, a write
//! blocks the whole loop, so a `SIGINT` or a deadline is not observed until the
//! reader drains. `ssh` has the same shape for the same reason. For the
//! interactive session this exists for, the output is the caller's terminal,
//! which does not stop reading.
//!
//! # One restorer, three triggers
//!
//! Raw mode is entered last — everything fallible happens first, so a failure
//! before the loop leaves the caller's terminal untouched — and undone by three
//! things between them covering every exit the process can observe: a guard in
//! [`Relay::run`]'s own frame, dropped on normal exit, on error, and on a panic
//! unwinding through it; the optional panic hook, which restores *before* the
//! default hook prints, because with `OPOST` off a backtrace prints
//! stair-stepped and a drop runs after the hook; and the stop path, which
//! restores before the process stops and re-enters raw mode when it continues.
//! [`restore_terminal`] states what restoration does and does not promise.

mod escalation;
mod raw;
mod signals;

use std::io;
use std::os::fd::BorrowedFd;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags};
use rustix::fs::OFlags;
use rustix::io::Errno;
use rustix::process::Signal;
use rustix::termios::{self, SpecialCodeIndex};

use crate::error::Error;
use crate::mechanism::frame;
use crate::poll;
use crate::running::Running;
use crate::status::ExitStatus;
use crate::terminal::Pty;
use raw::RawMode;

pub use escalation::Escalation;
pub use raw::{install_panic_restore, restore_terminal};
pub use signals::Signals;

/// The relay's read buffer, per direction and per wake.
const RELAY_BUF: usize = 8192;

/// Which channel a poll slot watches.
///
/// The caller's input is last because it is the one channel that retires: a
/// retired slot is dropped from the polled slice rather than muted, which is
/// what keeps the loop from spinning. `poll` reports `POLLHUP`, `POLLERR`, and
/// `POLLNVAL` whatever the requested events are, so a muted slot on a hung-up
/// pipe — `producer | relaying-program ...` after the producer exits — is ready
/// on every pass and the loop never blocks again. [`poll::slot`] states the
/// other technique that works, for the loops whose retiring channel is not last.
///
/// The other two indices stay stable across the change, and an unpolled slot's
/// `revents` stays as `PollFd::new` left it: empty.
const PRIMARY: usize = 0;
const SIGNALS: usize = 1;
const INPUT: usize = 2;

/// A byte loop between the caller's terminal and the sandbox's.
///
/// Built around two descriptors the caller supplies and driven by
/// [`run`](Self::run), which returns when the session ends. Nothing here is read
/// from the environment: the terminal whose size a `SIGWINCH` follows is the
/// supplied input descriptor, which is the caller's statement about what its
/// terminal is rather than an ambient reading of the process's.
///
/// # What it changes
///
/// Two things, both stated:
///
/// - The caller's input descriptor enters raw mode for the loop's duration when
///   [`raw`](Self::raw) asked for it, and is restored on every exit from
///   [`run`](Self::run), a panic unwinding through it included.
/// - The [`Pty`] is left non-blocking. A large paste must not stall the loop, so
///   the primary is `O_NONBLOCK` and what it will not take waits behind
///   `POLLOUT`. The flag is not undone: the session is over by then, and the
///   `Pty` is the caller's to drop.
///
/// The output descriptor must be blocking; see the module's asymmetry section
/// for why it is not given the treatment the primary gets.
#[derive(Debug)]
pub struct Relay<'fd> {
    /// What the caller types.
    input: BorrowedFd<'fd>,
    /// Where the sandbox's bytes go.
    output: BorrowedFd<'fd>,
    /// Whether the input is put into raw mode for the loop's duration.
    raw: bool,
    /// The bounded stop, or `None` for a session bounded only by the command.
    escalation: Option<Escalation>,
}

impl<'fd> Relay<'fd> {
    /// A relay between `input` — what the caller types — and `output`, where the
    /// sandbox's bytes go.
    ///
    /// For an interactive session both are the same terminal. Either may be a
    /// pipe, and the relay still relays: a session driven from a script has no
    /// terminal of its own to put into raw mode, and needs none.
    pub fn new(input: BorrowedFd<'fd>, output: BorrowedFd<'fd>) -> Relay<'fd> {
        Relay {
            input,
            output,
            raw: false,
            escalation: None,
        }
    }

    /// Puts `input` into raw mode for the loop's duration.
    ///
    /// Off by default: the relay never touches termios unasked. Raw mode is what
    /// makes an interactive session behave — keystrokes pass through unbuffered,
    /// and the sandbox's own line discipline turns a typed `^C` into a `SIGINT`
    /// for the sandbox's own foreground process group.
    ///
    /// Asking for it on an input that is not a terminal fails the run rather
    /// than being ignored, because a caller that says so has said something the
    /// descriptor cannot do. Whether the caller's own input *is* a terminal is
    /// the caller's reading to make.
    pub fn raw(mut self, raw: bool) -> Relay<'fd> {
        self.raw = raw;
        self
    }

    /// Bounds the session: the `timeout(1)` policy [`Escalation`] states.
    ///
    /// Without one the session runs until the command ends. The deadline runs
    /// from where the [`Escalation`] was built, so build it where the run
    /// begins.
    pub fn escalation(mut self, escalation: Escalation) -> Relay<'fd> {
        self.escalation = Some(escalation);
        self
    }

    /// Drives the session to end-of-file on the primary, restores what it
    /// changed, and collects the outcome.
    ///
    /// `Ok(None)` means a deadline passed, whatever became of the command
    /// afterwards — [`Escalation::outcome`]'s convention. Returns as soon as the
    /// session ends: end-of-file on the primary means every replica is closed
    /// and the command is already gone, so the [`wait`](Running::wait) this
    /// finishes with does not block.
    ///
    /// The order on the way in is everything fallible first, then raw mode
    /// immediately before the loop, so every failure before that point leaves
    /// the caller's terminal untouched. On the way out it reverses: the loop
    /// ends, the terminal is restored, and only then is the outcome collected —
    /// which is what keeps a diagnostic from printing stair-stepped down a
    /// screen still in raw mode.
    pub fn run(
        mut self,
        running: &mut Running<'_>,
        pty: &Pty,
        signals: &Signals,
    ) -> Result<Option<ExitStatus>, RelayError> {
        // A large paste must not stall the loop, so the primary is non-blocking
        // and what does not fit waits behind POLLOUT.
        let flags = rustix::fs::fcntl_getfl(pty)
            .map_err(RelayError::at("reading the primary's descriptor flags"))?;
        rustix::fs::fcntl_setfl(pty, flags | OFlags::NONBLOCK)
            .map_err(RelayError::at("setting the primary non-blocking"))?;

        // Entered last, and dropped at every exit from here on, so the terminal
        // is restored before anything is printed or collected.
        let guard = match self.raw {
            true => Some(RawMode::enter(self.input)?),
            false => None,
        };

        // No escalation is one with no deadline: nothing ever expires, so the
        // grace it carries is never consulted.
        let mut escalation = self
            .escalation
            .take()
            .unwrap_or_else(|| Escalation::new(None, Duration::ZERO));
        let outcome = self.pump(running, pty, signals, guard.as_ref(), &mut escalation);
        drop(guard);
        outcome?;

        // The wait is prompt: the loop ended at end-of-file on the primary,
        // which means every replica is closed and the command is already gone.
        let status = running.wait()?;
        Ok(escalation.outcome(status))
    }

    /// The loop proper.
    fn pump(
        &self,
        running: &mut Running<'_>,
        pty: &Pty,
        signals: &Signals,
        guard: Option<&RawMode<'_>>,
        escalation: &mut Escalation,
    ) -> Result<(), RelayError> {
        let signal_fd = signals.as_fd();
        let mut input_open = true;
        let mut pending: Vec<u8> = Vec::new();
        let mut buf = [0u8; RELAY_BUF];
        // A second interrupt escalates; the first is a request.
        let mut interrupted = false;

        loop {
            // The caller's input is watched only while there is room to put what
            // it produces: with a full pending buffer, reading more would grow
            // it without bound.
            let watch_input = input_open && pending.is_empty();
            let mut primary_events = PollFlags::IN;
            if !pending.is_empty() {
                primary_events |= PollFlags::OUT;
            }
            let mut slots = [
                PollFd::new(pty, primary_events),
                PollFd::new(&signal_fd, PollFlags::IN),
                PollFd::new(&self.input, PollFlags::IN),
            ];
            // The retired input slot leaves the polled slice rather than being
            // muted; see the slot constants for why muting does not work.
            let watched = match watch_input {
                true => &mut slots[..],
                false => &mut slots[..INPUT],
            };

            let wait = escalation
                .deadline()
                .map(|deadline| poll::timeout(deadline.saturating_duration_since(Instant::now())));
            match rustix::event::poll(watched, wait.as_ref()) {
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(errno) => return Err(RelayError::at("waiting on the session")(errno)),
            }

            // Asked on every wakeup, not only on the one `poll` timed out on.
            // Once the deadline is behind the loop the poll timeout is zero, so
            // a descriptor with something to say answers `Ok(n > 0)` first and a
            // sandbox printing without pause would postpone the escalation for
            // as long as it kept winning that race. Consulting the clock instead
            // makes the expiry a consequence of the clock.
            if escalation.passed() {
                // Escalate, and keep relaying: the sandbox's exit closes the
                // replicas, end-of-file ends the loop, and restoration happens
                // on the normal path.
                escalation.expire(running)?;
            }

            let ready: [PollFlags; 3] = std::array::from_fn(|index| slots[index].revents());

            if ready[SIGNALS].intersects(PollFlags::IN) {
                self.handle_signals(running, pty, signals, guard, &mut interrupted)?;
            }

            // Drain whatever the primary can take of the pending buffer, then
            // whatever the caller's input has produced since.
            if ready[PRIMARY].intersects(PollFlags::OUT) {
                flush_pending(pty, &mut pending)?;
            }
            // Every way the slot can be ready leads into the read: readable,
            // hung up, in error, or naming no open description at all. The last
            // is a caller started with its input closed, which reports
            // `POLLNVAL` and would otherwise be ready forever without anything
            // acting on it.
            if ready[INPUT]
                .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
            {
                match rustix::io::read(self.input, &mut buf) {
                    // End of input. There is no way to close a
                    // pseudoterminal's write side, so this is sent as the
                    // replica's own VEOF character, and the channel retires.
                    //
                    // An invalid input takes the same path: there is nothing to
                    // relay and never will be, which is the same thing end of
                    // input says, and the session continues on the caller-bound
                    // direction alone.
                    Ok(0) | Err(Errno::BADF) => {
                        pending.push(replica_veof(pty));
                        flush_pending(pty, &mut pending)?;
                        input_open = false;
                    }
                    Ok(read) => {
                        pending.extend_from_slice(&buf[..read]);
                        flush_pending(pty, &mut pending)?;
                    }
                    Err(Errno::INTR | Errno::AGAIN) => {}
                    Err(errno) => {
                        return Err(RelayError::at("reading the caller's input")(errno));
                    }
                }
            }

            if ready[PRIMARY].intersects(PollFlags::IN | PollFlags::HUP) {
                match rustix::io::read(pty, &mut buf) {
                    // End-of-file on the primary is the session-over signal.
                    Ok(0) => return Ok(()),
                    // Blocking, and outside the poll; see the module's "The two
                    // directions are not symmetric".
                    Ok(read) => write_all(self.output, &buf[..read])?,
                    Err(Errno::INTR | Errno::AGAIN) => {}
                    // Hangup on a pseudoterminal primary is EIO, and it is the
                    // same end of session.
                    Err(Errno::IO) => return Ok(()),
                    Err(errno) => {
                        return Err(RelayError::at("reading the sandbox's terminal")(errno));
                    }
                }
            }
        }
    }

    /// Drains the signal descriptor and acts on everything it carried.
    fn handle_signals(
        &self,
        running: &mut Running<'_>,
        pty: &Pty,
        signals: &Signals,
        guard: Option<&RawMode<'_>>,
        interrupted: &mut bool,
    ) -> Result<(), RelayError> {
        while let Some(signal) = signals.next()? {
            match signal {
                // The caller's terminal changed size; the sandbox's follows.
                Signal::WINCH => self.follow_size(pty)?,
                // These arrive only from outside: in raw mode a typed `^C` is a
                // byte the relay forwards, which the sandbox's own line
                // discipline turns into the sandbox's own SIGINT.
                Signal::INT | Signal::TERM | Signal::HUP | Signal::QUIT => match interrupted {
                    true => running.kill()?,
                    false => {
                        running.terminate()?;
                        *interrupted = true;
                    }
                },
                // Restore before stopping, so the shell that resumes finds its
                // terminal as it left it. The self-directed SIGSTOP returns once
                // something continues this process, and the SIGCONT that did so
                // is pending on the descriptor.
                Signal::TSTP => {
                    if let Some(guard) = guard {
                        guard.restore_for_stop();
                    }
                    rustix::process::kill_process(rustix::process::getpid(), Signal::STOP)
                        .map_err(RelayError::at("stopping the relaying process"))?;
                }
                // Continued: re-enter raw mode and re-read the size, which may
                // have changed while stopped. The discipline `less` follows.
                Signal::CONT => {
                    if let Some(guard) = guard {
                        guard.reenter()?;
                        self.follow_size(pty)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Sets the sandbox's terminal to the size the caller's input reports, where
    /// it reports one.
    fn follow_size(&self, pty: &Pty) -> Result<(), RelayError> {
        if let Some((rows, cols)) = raw::window_size(self.input) {
            pty.resize(rows, cols)?;
        }
        Ok(())
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
            Err(errno) => return Err(RelayError::at("writing to the sandbox's terminal")(errno)),
        }
    }
    Ok(())
}

/// Writes the whole of `bytes` to the caller-bound descriptor.
///
/// Blocking, and outside the poll. A descriptor the caller has made
/// non-blocking fails the session with `EAGAIN` rather than being spun on: the
/// relay states that this direction blocks, and a caller that arranged otherwise
/// has arranged something the loop cannot honour.
///
/// The loop over short writes is [`frame::write_full`]'s, which is where this
/// crate answers "write all of these bytes to a descriptor, retrying `EINTR`".
/// All that is left here is the step this failure names.
fn write_all(output: BorrowedFd<'_>, bytes: &[u8]) -> Result<(), RelayError> {
    frame::write_full(output, bytes).map_err(RelayError::at("writing to the caller's terminal"))
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

/// A relay failure: the sandbox's, or the relay's own plumbing.
#[derive(Debug)]
#[non_exhaustive]
pub enum RelayError {
    /// The sandbox failed: signalling it, resizing its terminal, or collecting
    /// its outcome.
    Cage(Error),
    /// The relay's own plumbing failed: the signal descriptor, the poll, the
    /// caller's terminal settings, or a read or write of one of its channels.
    #[non_exhaustive]
    Io {
        /// What the relay was doing.
        op: &'static str,
        /// The underlying error.
        source: io::Error,
    },
}

impl RelayError {
    /// A plumbing failure, naming what the relay was doing.
    ///
    /// Arguments run operation, then cause, which is the order every constructor
    /// in the crate takes them in; the relay's channels are the caller's own
    /// descriptors, so there is no locator between them to name.
    pub(crate) fn io(op: &'static str, source: io::Error) -> RelayError {
        RelayError::Io { op, source }
    }

    /// The same failure as a [`map_err`](Result::map_err) argument.
    ///
    /// Takes the `Errno` a rustix call fails with rather than the `io::Error`
    /// the crate's other `at` constructors take: every syscall this module makes
    /// goes through rustix, so folding the conversion in here states it once
    /// instead of at each of the loop's call sites.
    pub(crate) fn at(op: &'static str) -> impl FnOnce(Errno) -> RelayError {
        move |errno| RelayError::Io {
            op,
            source: errno.into(),
        }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Cage(error) => write!(f, "the relayed sandbox failed: {error}"),
            RelayError::Io { op, source } => {
                write!(f, "the terminal relay failed while {op}: {source}")
            }
        }
    }
}

impl std::error::Error for RelayError {
    /// The failure underneath: the library's own error, or the OS error the
    /// relay's plumbing reported.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RelayError::Cage(error) => Some(error),
            RelayError::Io { source, .. } => Some(source),
        }
    }
}

impl From<Error> for RelayError {
    fn from(error: Error) -> RelayError {
        RelayError::Cage(error)
    }
}
