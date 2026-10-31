//! Raw mode, and undoing it on every exit the process can observe.
//!
//! Whoever sets raw mode must restore it on normal exit, on error, on panic, on
//! `SIGINT`/`SIGTERM`/`SIGQUIT`, and on a stop — a relay that leaves the user's
//! shell unusable is a worse failure than the one the terminal feature started
//! from. This module is the whole of that discipline: a guard for the loop's
//! frame, a process-global save for the panic hook, and one restorer all of them
//! call.

use std::cell::{Cell, RefCell};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::OnceLock;

use rustix::termios::{self, OptionalActions, Termios};

use super::RelayError;

/// The first raw session's terminal, and its settings before that session.
struct Saved {
    /// A duplicate of the descriptor raw mode was entered on.
    ///
    /// Duplicated rather than borrowed because the hook outlives the relay: the
    /// caller's own descriptor may be closed by the time a panic unwinds, and a
    /// closed descriptor's number is one the process may have reallocated to a
    /// file. The duplicate is held for the process's life, so it names the same
    /// open file description for as long as anything could ask.
    fd: OwnedFd,
    /// The settings to replay.
    original: Termios,
}

/// The first raw session's terminal, saved for [`restore_terminal`].
///
/// A `OnceLock` rather than a mutex: [`restore_terminal`] is called from a panic
/// hook, where a mutex the panicking thread already held would deadlock or
/// answer with a poisoned lock. Written once, before the first raw session's
/// loop begins, and never mutated, so a lock-free read is always correct.
static SAVED: OnceLock<Saved> = OnceLock::new();

/// Installs the panic hook once per process.
static PANIC_HOOK: OnceLock<()> = OnceLock::new();

/// Restores the terminal of the first raw session this process entered.
///
/// Idempotent and lock-free, so every exit path may call it without
/// coordination, including a panic hook. A no-op before any relay has entered
/// raw mode, which is what leaves a failure before that point with the caller's
/// terminal untouched.
///
/// The flush is deliberate: input pending at restoration is raw bytes typed at a
/// session that no longer exists, and discarding them beats letting half an
/// escape sequence land at the caller's prompt.
///
/// # What it reaches
///
/// The *first* terminal a raw session was entered on, which is what a hook with
/// no argument can name. Sequential sessions on the same terminal — the real
/// case — restore correctly, and so does every session's own exit, because
/// [`Relay::run`](super::Relay::run) restores the terminal it was given from a
/// guard in its own frame rather than through this. A process that relays raw
/// sessions on *different* terminals over its lifetime is the case this does not
/// cover: a panic during the second session restores the first one's terminal.
///
/// Restoration means *termios*. `SIGKILL` and `SIGSTOP` are uncatchable and out
/// of scope, with the same honesty a leaked handle gets: the remedy is `stty
/// sane`, and no process can promise otherwise. Screen contents — an alternate
/// screen left active, a hidden cursor — were written by the sandboxed program
/// through the relay verbatim and belong to it, exactly as `ssh` treats them.
pub fn restore_terminal() {
    if let Some(saved) = SAVED.get() {
        let _ = termios::tcsetattr(&saved.fd, OptionalActions::Flush, &saved.original);
    }
}

/// Installs a panic hook that calls [`restore_terminal`] before the hook it
/// replaces prints, once per process.
///
/// Explicit and optional, because installing a hook is process-global and the
/// library does nothing process-global a caller did not ask for. A program with
/// a hook of its own calls [`restore_terminal`] from it instead and does not
/// call this; a second call here does nothing.
///
/// # Why a hook rather than the guard alone
///
/// Ordering. With `OPOST` off a backtrace prints stair-stepped down the screen,
/// so restoration has to precede the message — and a guard's drop runs *after*
/// the hook has printed. A relay whose caller installs no hook still restores on
/// unwind, from the guard; what it loses is a readable panic message.
pub fn install_panic_restore() {
    PANIC_HOOK.get_or_init(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            default(info);
        }));
    });
}

/// A terminal in raw mode, restored when the guard goes out of scope however it
/// does: normal exit, an early return, or a panic unwinding through the relay's
/// frame.
///
/// Holds the settings it found, so it restores *its own* terminal rather than
/// the process-global save [`restore_terminal`] replays.
///
/// # Only from the foreground
///
/// The guard changes the terminal only while this process is in the
/// terminal's foreground process group. The relay blocks `SIGTTOU`, so a
/// `tcsetattr` from the background succeeds rather than stopping the process,
/// and would rewrite the settings of the shell that holds the terminal. A
/// session started in the background therefore holds a guard that has not yet
/// entered raw mode, and enters it on the first [`reenter`](Self::reenter)
/// that finds the process in the foreground. Restoration follows the same
/// rule from the other side: it writes only where raw mode is in force, so a
/// guard never hands a terminal settings it did not take from it.
pub(super) struct RawMode<'fd> {
    /// The terminal this guard puts into raw mode.
    fd: BorrowedFd<'fd>,
    /// Its settings before raw mode was first entered, which every restore
    /// replays. `None` until the first entry, which a session started in the
    /// background defers.
    original: RefCell<Option<Termios>>,
    /// Whether this guard's raw settings are in force now.
    raw: Cell<bool>,
}

impl<'fd> RawMode<'fd> {
    /// Takes charge of `fd` for a session, putting it into raw mode now if this
    /// process is in its foreground.
    ///
    /// Raw mode is what makes a session behave: keystrokes pass through
    /// unbuffered, and the *sandbox's* line discipline — not the caller's —
    /// turns a typed `^C` into a `SIGINT` for the sandbox's own foreground
    /// process group.
    ///
    /// A descriptor that is not a terminal is refused here, whether or not raw
    /// mode would be entered yet, so the refusal does not depend on where the
    /// session was started. Everything fallible happens before the terminal is
    /// touched, so a failure here leaves it exactly as it was.
    pub(super) fn enter(fd: BorrowedFd<'fd>) -> Result<RawMode<'fd>, RelayError> {
        termios::tcgetattr(fd).map_err(RelayError::at("reading the caller's terminal settings"))?;
        let guard = RawMode {
            fd,
            original: RefCell::new(None),
            raw: Cell::new(false),
        };
        guard.enter_in_foreground("putting the caller's terminal into raw mode")?;
        Ok(guard)
    }

    /// Restores this guard's terminal, discarding what was typed at the session
    /// that is ending.
    ///
    /// Idempotent: the stop path restores before stopping and the drop restores
    /// again, and a restore with raw mode not in force writes nothing.
    pub(super) fn restore(&self) {
        self.write_original(OptionalActions::Flush);
    }

    /// Restores this guard's terminal for a stop, keeping what was typed.
    ///
    /// The two restores differ in what they do with input already in the queue,
    /// because the sessions they end are not the same. A session that is over
    /// leaves keystrokes aimed at something that no longer exists, and
    /// discarding them beats letting half an escape sequence land at the
    /// caller's prompt. A stopped session is not over: what was typed ahead of
    /// `^Z` was typed at the session `fg` resumes, so it waits there instead.
    /// Draining is what `ssh` and `less` do across a stop for the same reason.
    pub(super) fn restore_for_stop(&self) {
        self.write_original(OptionalActions::Drain);
    }

    /// Re-enters raw mode after a continue, from the settings this guard saved,
    /// if the continue left this process in the foreground.
    ///
    /// Derived from the original rather than from what the terminal carries now,
    /// so a shell that changed something while this process was stopped does not
    /// become the baseline the session is later restored to. A continue from
    /// `bg` leaves the process in the background and re-enters nothing; the one
    /// from a later `fg` does. For a session started in the background, the
    /// first entry happens here, and it is then that the original is read.
    pub(super) fn reenter(&self) -> Result<(), RelayError> {
        self.enter_in_foreground("entering raw mode after a continue")
    }

    /// Puts the terminal into raw mode if this process is in its foreground and
    /// raw mode is not already in force.
    fn enter_in_foreground(&self, op: &'static str) -> Result<(), RelayError> {
        if self.raw.get() || !in_foreground(self.fd) {
            return Ok(());
        }
        let saved = self.original.borrow().clone();
        let original = match saved {
            Some(original) => original,
            None => self.first_entry()?,
        };
        let mut raw = original;
        raw.make_raw();
        termios::tcsetattr(self.fd, OptionalActions::Now, &raw).map_err(RelayError::at(op))?;
        self.raw.set(true);
        Ok(())
    }

    /// Reads the settings the first entry finds and records them, for this
    /// guard and for the panic hook.
    fn first_entry(&self) -> Result<Termios, RelayError> {
        let original = termios::tcgetattr(self.fd)
            .map_err(RelayError::at("reading the caller's terminal settings"))?;
        // Duplicated before anything is changed, so the process-global save
        // below cannot fail once the terminal is raw. Wasted where a raw session
        // has already been recorded, which costs one descriptor for the length
        // of this call.
        let duplicate = rustix::io::fcntl_dupfd_cloexec(self.fd, 0).map_err(RelayError::at(
            "duplicating the caller's terminal descriptor",
        ))?;
        // Recorded for the panic hook's reach. The first raw session in the
        // process wins; a later one is already covered for its own frame by
        // this guard.
        let _ = SAVED.set(Saved {
            fd: duplicate,
            original: original.clone(),
        });
        *self.original.borrow_mut() = Some(original.clone());
        Ok(original)
    }

    /// Writes the saved settings back, where raw mode is in force.
    fn write_original(&self, when: OptionalActions) {
        if !self.raw.replace(false) {
            return;
        }
        if let Some(original) = self.original.borrow().as_ref() {
            let _ = termios::tcsetattr(self.fd, when, original);
        }
    }
}

impl Drop for RawMode<'_> {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Whether this process may change `fd`'s terminal settings without taking
/// them from a foreground job: it is in the terminal's foreground process
/// group, or the terminal is not its controlling terminal at all.
///
/// The second case is a terminal no job control governs. A pseudoterminal a
/// program opened for itself is one, and so is a terminal reached from another
/// session. The kernel answers `ENOTTY` for those, and no `SIGTTOU` would ever
/// apply to a write, so there is no foreground to defer to. The same reading
/// covers a controlling terminal whose foreground group has gone, which the
/// kernel lets anyone in the session write.
fn in_foreground(fd: BorrowedFd<'_>) -> bool {
    match termios::tcgetpgrp(fd) {
        Ok(foreground) => foreground == rustix::process::getpgrp(),
        Err(_) => true,
    }
}

/// The window size `fd`'s terminal reports, or `None` where it reports none.
///
/// A zero in either dimension is `None` rather than a size. That is what a
/// terminal reports when its size is *unknown* — a pseudoterminal nobody has
/// sized, which is what a terminal multiplexer or `script(1)` hands on when it
/// was itself started without one — and passing it through would give the
/// sandbox a terminal that answers "no size" to everything that asks. Programs
/// treat that as an error rather than as a default: `stty size` refuses it
/// outright, and a full-screen program has nothing to draw into.
///
/// [`Terminal::size`](crate::Terminal::size) takes the same position, so a
/// launch would be sound either way; this answers `None` so that a `SIGWINCH`
/// carrying a zero resizes nothing.
pub(super) fn window_size(fd: BorrowedFd<'_>) -> Option<(u16, u16)> {
    let size = termios::tcgetwinsize(fd).ok()?;
    (size.ws_row != 0 && size.ws_col != 0).then_some((size.ws_row, size.ws_col))
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;

    use std::time::Duration;

    use rustix::termios::{LocalModes, SpecialCodeIndex};

    use super::*;
    use crate::terminal::{Terminal, allocate};

    /// A pseudoterminal pair: the caller's end and the terminal it drives.
    ///
    /// The replica stands in for the caller's own terminal, so raw mode is
    /// entered on something this test owns; the primary is the other end, from
    /// which the settings read back — Linux redirects a termios query on a
    /// primary to its replica.
    fn pair() -> (OwnedFd, OwnedFd) {
        allocate(&Terminal::new().size(24, 80)).expect("a pseudoterminal is allocatable")
    }

    #[test]
    fn raw_mode_is_visible_from_the_other_end_and_undone_on_drop() {
        let (primary, replica) = pair();
        let before = termios::tcgetattr(&primary).expect("the settings are readable");
        assert!(
            before
                .local_modes
                .contains(LocalModes::ICANON | LocalModes::ECHO),
            "the baseline is a cooked terminal",
        );

        {
            let _raw = RawMode::enter(replica.as_fd()).expect("raw mode is enterable");
            let during = termios::tcgetattr(&primary).expect("the settings are readable");
            assert!(
                !during
                    .local_modes
                    .intersects(LocalModes::ICANON | LocalModes::ECHO),
                "raw mode turns the line discipline off",
            );
        }

        let after = termios::tcgetattr(&primary).expect("the settings are readable");
        assert_eq!(after.local_modes, before.local_modes);
        assert_eq!(after.input_modes, before.input_modes);
        assert_eq!(after.output_modes, before.output_modes);
        assert_eq!(after.control_modes, before.control_modes);
    }

    #[test]
    fn a_stop_restores_and_a_continue_re_enters() {
        let (primary, replica) = pair();
        let cooked = termios::tcgetattr(&primary).expect("the settings are readable");

        let raw = RawMode::enter(replica.as_fd()).expect("raw mode is enterable");
        // What the stop path does before it stops the process.
        raw.restore_for_stop();
        assert_eq!(
            termios::tcgetattr(&primary)
                .expect("the settings are readable")
                .local_modes,
            cooked.local_modes,
            "the terminal is the caller's again while the process is stopped",
        );

        // And what the continue path does when something resumes it.
        raw.reenter().expect("raw mode is re-enterable");
        assert!(
            !termios::tcgetattr(&primary)
                .expect("the settings are readable")
                .local_modes
                .intersects(LocalModes::ICANON | LocalModes::ECHO),
        );
    }

    #[test]
    fn a_stop_keeps_the_type_ahead_that_an_ending_session_discards() {
        // The two restores differ only in what they do with input already in
        // the queue, so the terminal here is one whose baseline is already
        // non-canonical: a read then answers from the queue directly, and the
        // canonical line discipline's own rules about a line that arrived while
        // it was off are not what is being measured.
        let (primary, replica) = pair();
        let mut baseline = termios::tcgetattr(&replica).expect("the settings are readable");
        baseline
            .local_modes
            .remove(LocalModes::ICANON | LocalModes::ECHO);
        // A read answers with whatever is queued rather than waiting for a byte
        // that a discarded queue will never bring.
        baseline.special_codes[SpecialCodeIndex::VMIN] = 0;
        baseline.special_codes[SpecialCodeIndex::VTIME] = 0;
        termios::tcsetattr(&replica, OptionalActions::Now, &baseline)
            .expect("the baseline is settable");

        let raw = RawMode::enter(replica.as_fd()).expect("raw mode is enterable");
        let queued = |restore: &dyn Fn()| {
            rustix::io::write(&primary, b"ahead").expect("the terminal takes input");
            // The kernel hands a pseudoterminal's input to the line discipline
            // from a thread of its own, so the queue is waited for rather than
            // assumed: what a restore does to a *filled* queue is the question,
            // and a flush that ran first would answer a different one.
            let mut watched = [rustix::event::PollFd::new(
                &replica,
                rustix::event::PollFlags::IN,
            )];
            let wait = crate::poll::timeout(Duration::from_secs(5));
            let ready =
                rustix::event::poll(&mut watched, Some(&wait)).expect("the queue is pollable");
            assert_eq!(ready, 1, "the input reached the line discipline");

            restore();
            let mut buffer = [0u8; 16];
            let read = rustix::io::read(&replica, &mut buffer).expect("the queue is readable");
            buffer[..read].to_vec()
        };

        assert_eq!(
            queued(&|| raw.restore_for_stop()),
            b"ahead",
            "what was typed ahead of a stop was typed at the session that resumes",
        );
        // Resumed, so the session's own restore has raw mode to undo.
        raw.reenter().expect("raw mode is re-enterable");
        assert!(
            queued(&|| raw.restore()).is_empty(),
            "what was typed at a session that is over goes nowhere",
        );
    }

    #[test]
    fn restoring_replays_the_first_settings_rather_than_the_last() {
        // A second guard on an already-raw terminal would save raw as its
        // original if it read the terminal at that moment. The guard the loop
        // holds is entered once per session, so this pins the property the
        // session's own exit depends on: what is restored is what the caller
        // had.
        let (primary, replica) = pair();
        let cooked = termios::tcgetattr(&primary).expect("the settings are readable");
        let outer = RawMode::enter(replica.as_fd()).expect("raw mode is enterable");
        outer.reenter().expect("re-entry is idempotent");
        drop(outer);
        assert_eq!(
            termios::tcgetattr(&primary)
                .expect("the settings are readable")
                .local_modes,
            cooked.local_modes,
        );
    }

    #[test]
    fn a_restore_writes_only_where_raw_mode_is_in_force() {
        // Once the session has restored the terminal, its settings are the
        // shell's again, and a later restore, the guard's drop among them,
        // must not replay what the session found over what the shell has
        // since set.
        let (primary, replica) = pair();
        let raw = RawMode::enter(replica.as_fd()).expect("raw mode is enterable");
        raw.restore_for_stop();

        let mut shells = termios::tcgetattr(&primary).expect("the settings are readable");
        shells.local_modes.remove(LocalModes::ECHO);
        termios::tcsetattr(&primary, OptionalActions::Now, &shells)
            .expect("the settings are settable");
        drop(raw);

        assert!(
            !termios::tcgetattr(&primary)
                .expect("the settings are readable")
                .local_modes
                .contains(LocalModes::ECHO),
            "a guard with raw mode not in force wrote the terminal anyway",
        );
    }

    #[test]
    fn a_terminal_reporting_no_size_reports_none() {
        // Zero is what a terminal says when its size is unknown, and a SIGWINCH
        // carrying it must resize nothing.
        let (primary, replica) = pair();
        assert_eq!(window_size(replica.as_fd()), Some((24, 80)));
        termios::tcsetwinsize(
            &primary,
            rustix::termios::Winsize {
                ws_row: 0,
                ws_col: 0,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .expect("the size is settable");
        assert_eq!(window_size(replica.as_fd()), None);
    }

    #[test]
    fn raw_mode_on_something_that_is_not_a_terminal_is_refused() {
        // A caller that asks for raw mode on a pipe has asked for something the
        // descriptor cannot do, and hears so rather than being quietly ignored.
        let (reader, _writer) = rustix::pipe::pipe().expect("a pipe");
        let refused = RawMode::enter(reader.as_fd());
        assert!(
            matches!(refused, Err(RelayError::Io { .. })),
            "a pipe has no termios to save"
        );
    }
}
