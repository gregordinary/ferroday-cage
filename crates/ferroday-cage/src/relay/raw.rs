//! Raw mode, and undoing it on every exit the process can observe.
//!
//! Whoever sets raw mode must restore it on normal exit, on error, on panic, on
//! `SIGINT`/`SIGTERM`/`SIGQUIT`, and on a stop — a relay that leaves the user's
//! shell unusable is a worse failure than the one the terminal feature started
//! from. This module is the whole of that discipline: a guard for the loop's
//! frame, a process-global record of the raw session in force for the panic
//! hook, and one restorer all of them call.

use std::cell::{Cell, RefCell};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, TryLockError};

use rustix::termios::{self, OptionalActions, Termios};

use super::RelayError;

/// The raw session in force: its terminal, and the settings it found there.
struct Saved {
    /// A duplicate of the descriptor raw mode was entered on.
    ///
    /// Duplicated rather than borrowed because the hook may run on another
    /// thread than the relay, at any point in the session: the caller's own
    /// descriptor is the caller's to close, and a closed descriptor's number is
    /// one the process may have reallocated to a file. The duplicate names the
    /// same open file description for as long as the record holds it.
    fd: OwnedFd,
    /// The settings to replay.
    original: Termios,
    /// The guard that recorded it, so a guard retires its own record and no
    /// other.
    session: u64,
}

/// The raw session in force, for [`restore_terminal`]: `None` whenever no
/// guard holds a terminal in raw mode.
///
/// A guard records its session immediately before it puts the terminal into raw
/// mode, and retires the record as it restores. So the record exists exactly
/// while raw mode is in force, and the hook restores nothing outside a session.
///
/// A mutex, which [`restore_terminal`] only ever tries. The hook runs from
/// wherever a panic happens, and blocking there could deadlock. The lock is
/// held for the length of a record's update and no longer, and nothing inside
/// it can panic.
static SESSION: Mutex<Option<Saved>> = Mutex::new(None);

/// The identity the next guard takes, which is what [`Saved::session`] holds.
static NEXT_SESSION: AtomicU64 = AtomicU64::new(0);

/// Installs the panic hook once per process.
static PANIC_HOOK: OnceLock<()> = OnceLock::new();

/// Takes the session record, blocking, for a guard's update.
///
/// A poisoned lock is taken anyway. No update can panic while it holds the
/// lock, and the record is whole whatever another thread did.
fn session() -> MutexGuard<'static, Option<Saved>> {
    SESSION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Restores the terminal of the raw session in force, where this process is in
/// that terminal's foreground.
///
/// Idempotent, and never blocks, so every exit path may call it without
/// coordination, a panic hook included. It does nothing before a relay has
/// entered raw mode, which leaves a failure before that point with the caller's
/// terminal untouched. It does nothing after the session has restored the
/// terminal either. The settings are then the shell's again, and replaying the
/// session's would overwrite whatever the shell has set since.
///
/// The flush is deliberate: input pending at restoration is raw bytes typed at a
/// session that no longer exists, and discarding them beats letting half an
/// escape sequence land at the caller's prompt.
///
/// # What it reaches
///
/// The terminal of the session that holds one in raw mode now, with the
/// settings that session found there. Sequential sessions are each covered, on
/// one terminal or on several.
///
/// Only from the foreground. A process put into the background with a session
/// in force has had its terminal taken by the job now in the foreground. A
/// job-control shell reinstates its own settings when it takes the terminal
/// back, so replaying the session's would overwrite them and discard the
/// shell's type-ahead. The session's own guard still restores it when the
/// session ends, a panic unwinding through [`Relay::run`](super::Relay::run)
/// included, by the rule [`Signals`](super::Signals) describes.
///
/// A call that finds the record busy does nothing. A guard holds it only while
/// it records or retires a session, and that guard is the one about to restore
/// the terminal or to enter raw mode on it.
///
/// Restoration means *termios*. `SIGKILL` and `SIGSTOP` are uncatchable and out
/// of scope, with the same honesty a leaked handle gets: the remedy is `stty
/// sane`, and no process can promise otherwise. Screen contents — an alternate
/// screen left active, a hidden cursor — were written by the sandboxed program
/// through the relay verbatim and belong to it, exactly as `ssh` treats them.
pub fn restore_terminal() {
    let mut record = match SESSION.try_lock() {
        Ok(record) => record,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => return,
    };
    let Some(saved) = record.as_ref() else {
        return;
    };
    if !in_foreground(saved.fd.as_fd()) {
        return;
    }
    let _ = termios::tcsetattr(&saved.fd, OptionalActions::Flush, &saved.original);
    *record = None;
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
/// Holds the settings it found, so it restores *its own* terminal. It also
/// records them for [`restore_terminal`] for as long as raw mode is in force.
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
    /// This guard's identity in the process-global record.
    session: u64,
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
            session: NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
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
    ///
    /// The session is recorded for [`restore_terminal`] before the terminal
    /// changes, so the hook never finds raw mode in force without the settings
    /// to undo it. Everything that can fail happens before that, so a failure
    /// here leaves the terminal as it was.
    fn enter_in_foreground(&self, op: &'static str) -> Result<(), RelayError> {
        if self.raw.get() || !in_foreground(self.fd) {
            return Ok(());
        }
        let saved = self.original.borrow().clone();
        let original = match saved {
            Some(original) => original,
            None => self.first_entry()?,
        };
        let duplicate = rustix::io::fcntl_dupfd_cloexec(self.fd, 0).map_err(RelayError::at(
            "duplicating the caller's terminal descriptor",
        ))?;
        let mut raw = original.clone();
        raw.make_raw();
        *session() = Some(Saved {
            fd: duplicate,
            original,
            session: self.session,
        });
        if let Err(errno) = termios::tcsetattr(self.fd, OptionalActions::Now, &raw) {
            self.retire();
            return Err(RelayError::at(op)(errno));
        }
        self.raw.set(true);
        Ok(())
    }

    /// Reads the settings the first entry finds, which every later restore of
    /// this guard's replays.
    fn first_entry(&self) -> Result<Termios, RelayError> {
        let original = termios::tcgetattr(self.fd)
            .map_err(RelayError::at("reading the caller's terminal settings"))?;
        *self.original.borrow_mut() = Some(original.clone());
        Ok(original)
    }

    /// Writes the saved settings back, where raw mode is in force.
    ///
    /// The session's record is retired first, so a panic hook that runs from
    /// here on finds nothing to replay.
    fn write_original(&self, when: OptionalActions) {
        if !self.raw.replace(false) {
            return;
        }
        self.retire();
        if let Some(original) = self.original.borrow().as_ref() {
            let _ = termios::tcsetattr(self.fd, when, original);
        }
    }

    /// Removes this guard's session from the process-global record, where it is
    /// still there.
    ///
    /// The panic hook may have taken it already, and only a record of this
    /// guard's own is removed.
    fn retire(&self) {
        let mut record = session();
        if record
            .as_ref()
            .is_some_and(|saved| saved.session == self.session)
        {
            *record = None;
        }
    }
}

impl Drop for RawMode<'_> {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Whether this process may change `fd`'s terminal settings, or read from it,
/// without taking it from a foreground job: it is in the terminal's foreground
/// process group, or `fd` is not its controlling terminal at all.
///
/// The second case is a terminal no job control governs. A pseudoterminal a
/// program opened for itself is one, and so is a terminal reached from another
/// session. The kernel answers `ENOTTY` for those, as it does for a descriptor
/// that is no terminal, and no `SIGTTOU` or `SIGTTIN` would ever apply, so
/// there is no foreground to defer to. The same reading covers a controlling
/// terminal whose foreground group has gone, which the kernel lets anyone in
/// the session write.
pub(super) fn in_foreground(fd: BorrowedFd<'_>) -> bool {
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

    /// One guard at a time across these tests.
    ///
    /// The record the panic hook reads is process-global, and the hook restores
    /// whichever session it holds. A test that calls the hook while another
    /// test's session is in force would restore that session's terminal under
    /// it.
    static GUARDS: Mutex<()> = Mutex::new(());

    /// Takes [`GUARDS`], ignoring a poisoning left by a failed test: the lock
    /// orders the tests and guards no state of its own.
    fn serially() -> MutexGuard<'static, ()> {
        GUARDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The settings `primary`'s terminal carries now.
    fn settings(primary: &OwnedFd) -> Termios {
        termios::tcgetattr(primary).expect("the settings are readable")
    }

    /// Plays the shell between sessions: turns echo off on `primary`'s
    /// terminal, a setting no session's original carries.
    fn shell_turns_echo_off(primary: &OwnedFd) {
        let mut shells = settings(primary);
        shells.local_modes.remove(LocalModes::ECHO);
        termios::tcsetattr(primary, OptionalActions::Now, &shells)
            .expect("the settings are settable");
    }

    #[test]
    fn raw_mode_is_visible_from_the_other_end_and_undone_on_drop() {
        let _serial = serially();
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
        let _serial = serially();
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
        let _serial = serially();
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
        let _serial = serially();
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
        let _serial = serially();
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

    #[test]
    fn the_panic_restore_undoes_the_session_in_force() {
        let _serial = serially();
        let (primary, replica) = pair();
        let cooked = settings(&primary);
        let raw = RawMode::enter(replica.as_fd()).expect("raw mode is enterable");
        restore_terminal();
        assert_eq!(
            settings(&primary).local_modes,
            cooked.local_modes,
            "the hook left the session's terminal raw",
        );
        drop(raw);
    }

    #[test]
    fn the_panic_restore_leaves_a_terminal_whose_session_has_ended() {
        // Once the session has restored the terminal, its settings are the
        // shell's again. A panic later in the process must not replay the
        // session's over whatever the shell has set since.
        let _serial = serially();
        let (primary, replica) = pair();
        drop(RawMode::enter(replica.as_fd()).expect("raw mode is enterable"));
        shell_turns_echo_off(&primary);
        restore_terminal();
        assert!(
            !settings(&primary).local_modes.contains(LocalModes::ECHO),
            "the hook rewrote a terminal no session held",
        );
    }

    #[test]
    fn the_panic_restore_reaches_the_session_in_force_on_another_terminal() {
        // A program relaying sessions on two terminals in turn: the hook
        // restores the one in force, with the settings it found, and leaves
        // the first alone.
        let _serial = serially();
        let (first, first_replica) = pair();
        drop(RawMode::enter(first_replica.as_fd()).expect("raw mode is enterable"));
        shell_turns_echo_off(&first);

        let (second, second_replica) = pair();
        let cooked = settings(&second);
        let raw = RawMode::enter(second_replica.as_fd()).expect("raw mode is enterable");
        restore_terminal();
        assert!(
            !settings(&first).local_modes.contains(LocalModes::ECHO),
            "the hook rewrote the first session's terminal",
        );
        assert_eq!(
            settings(&second).local_modes,
            cooked.local_modes,
            "the hook left the session in force raw",
        );
        drop(raw);
    }

    /// Names the role this test binary plays when it runs itself as the child
    /// process of [`the_panic_restore_leaves_a_terminal_its_session_lost_to_the_foreground`].
    const BACKGROUND_HELPER: &str = "FERRODAY_CAGE_TEST_BACKGROUND_RESTORE";

    /// A session moved to the background has lost its terminal to the job in
    /// the foreground, and the hook leaves that job's settings alone.
    ///
    /// Only a process with the terminal as its controlling terminal has a
    /// foreground to be out of, which this test process cannot become without
    /// taking every other test with it. So it runs this test binary as a child
    /// process in a session of its own, on a fresh pseudoterminal, and the
    /// child plays both the session and the shell; see
    /// [`helper_restore_in_the_background`].
    #[test]
    fn the_panic_restore_leaves_a_terminal_its_session_lost_to_the_foreground() {
        let (primary, replica) = pair();
        let exe = std::env::current_exe().expect("the test binary has a path");
        let mut command = std::process::Command::new(exe);
        command
            .args([
                "--exact",
                "relay::raw::tests::helper_restore_in_the_background",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(BACKGROUND_HELPER, "1");
        let mut child = ferroday_cage_testkit::pty::spawn_controlled(&mut command, &replica);
        drop(replica);

        // Drained throughout, so the child's report cannot fill the terminal.
        let mut seen = String::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().expect("the helper can be waited for") {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the helper did not finish; it printed:\n{seen}");
            }
            ferroday_cage_testkit::pty::drain_until(
                &primary,
                std::time::Instant::now() + Duration::from_millis(50),
                &mut seen,
            );
        };
        while ferroday_cage_testkit::pty::drain_until(
            &primary,
            std::time::Instant::now() + Duration::from_millis(100),
            &mut seen,
        ) {}
        assert!(status.success(), "the helper failed; it printed:\n{seen}");
        assert!(
            seen.contains("1 passed"),
            "the helper ran no test; it printed:\n{seen}",
        );
    }

    /// Not a test of its own: when [`BACKGROUND_HELPER`] is set, this plays a
    /// session that the shell moves to the background, and the shell that
    /// takes the terminal back. Without the variable it does nothing.
    #[test]
    fn helper_restore_in_the_background() {
        use std::os::unix::process::CommandExt as _;

        if std::env::var_os(BACKGROUND_HELPER).is_none() {
            return;
        }
        // Blocked, as a relay blocks it, so a write to the terminal from the
        // background succeeds rather than stopping this process: the shell
        // this plays writes from there, and so would the hook.
        let _signals = crate::relay::Signals::install().expect("the relay's signals install");
        let terminal = rustix::stdio::stdin();
        let raw = RawMode::enter(terminal).expect("raw mode is enterable");
        let original = raw
            .original
            .borrow()
            .clone()
            .expect("the session entered raw mode in the foreground");

        // The shell takes the foreground and reinstates settings of its own.
        let mut shell = std::process::Command::new("sleep")
            .arg("60")
            .process_group(0)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("a process to hold the foreground starts");
        let shell_group =
            rustix::process::Pid::from_raw(i32::try_from(shell.id()).expect("a process id fits"))
                .expect("a live process id");
        termios::tcsetpgrp(terminal, shell_group).expect("the foreground moves to the shell");
        let mut shells = original.clone();
        shells.local_modes.remove(LocalModes::ECHO);
        termios::tcsetattr(terminal, OptionalActions::Now, &shells)
            .expect("the shell's settings are settable");

        restore_terminal();
        let in_the_background = termios::tcgetattr(terminal).expect("the settings are readable");

        // Back in the foreground, with the session's raw mode still its own.
        termios::tcsetpgrp(terminal, rustix::process::getpgrp())
            .expect("the foreground returns to the session");
        restore_terminal();
        let in_the_foreground = termios::tcgetattr(terminal).expect("the settings are readable");

        let _ = shell.kill();
        let _ = shell.wait();
        drop(raw);

        assert!(
            !in_the_background.local_modes.contains(LocalModes::ECHO),
            "the hook rewrote the settings of the job in the foreground",
        );
        assert_eq!(
            in_the_foreground.local_modes, original.local_modes,
            "the hook did not restore the session's terminal in the foreground",
        );
    }
}
