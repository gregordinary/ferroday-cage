//! `fcage`'s side of `--terminal`: the decisions a binary makes and a library
//! does not.
//!
//! The relay is [`ferroday_cage::relay`]. What is left here is what it
//! deliberately will not do on a caller's behalf: read the terminal `fcage` was
//! started from, decide whether that terminal is one at all, and install the
//! panic hook that restores it. All three are ambient readings of the process,
//! which a binary may make and a library may not.

use std::os::fd::AsFd as _;
use std::time::Duration;

use ferroday_cage::relay::{Escalation, Relay, RelayError, Signals, install_panic_restore};
use ferroday_cage::{ExitStatus, Pty, Running, Terminal};
use rustix::termios;

/// Whether `fcage`'s own standard input is a terminal.
///
/// Decides raw mode and the restoration that follows it, and nothing else. A run
/// whose input is a pipe still relays; it simply has no terminal of its own to
/// put into raw mode or restore.
fn caller_is_terminal() -> bool {
    termios::tcgetattr(rustix::stdio::stdin()).is_ok()
}

/// The terminal to allocate for the sandbox: the caller's own size where there
/// is one, and the stated default otherwise.
///
/// The ambient read the library refuses to make. It is legitimate here: a binary
/// may read the terminal it was started from.
///
/// A dimension the caller's terminal reports as zero lands on
/// [`Terminal`]'s default, which is where the rule that zero means *unknown*
/// rather than *empty* is stated. A `--terminal` run from a script, where there
/// is no terminal to ask, degrades to a plain byte relay around a sandbox that
/// still has a real terminal of its own, at 80x24.
pub fn terminal_for_caller() -> Terminal {
    match termios::tcgetwinsize(rustix::stdio::stdin()) {
        Ok(size) => Terminal::new().size(size.ws_row, size.ws_col),
        Err(_) => Terminal::new(),
    }
}

/// The relay's signals, installed for a run's one session and given back to
/// the process when this drops.
///
/// The library blocks the relayed signals for as long as the process lives,
/// and a dropped handle leaves them blocked with nothing reading them, so
/// `fcage` winding down after its session, or failing before it, would ignore
/// a `^C` and a `SIGTERM`. `fcage` relays one session, so it gives them back
/// as soon as that session is over, or will not happen.
pub struct HeldSignals(Option<Signals>);

impl HeldSignals {
    /// Installs the relay's signals; see [`Signals::install`].
    pub fn install() -> Result<HeldSignals, RelayError> {
        Signals::install().map(|signals| HeldSignals(Some(signals)))
    }
}

impl Drop for HeldSignals {
    fn drop(&mut self) {
        if let Some(signals) = self.0.take() {
            // Left blocked where the mask cannot be restored, as a dropped
            // handle leaves them; there is nothing else to do about it.
            let _ = signals.release();
        }
    }
}

/// Drives an interactive session to its end and returns the command's outcome.
///
/// `Ok(None)` means the timeout expired, whatever became of the command
/// afterwards — the same convention the non-terminal path follows, because both
/// drive the same [`Escalation`].
pub fn relay(
    mut running: Running<'_>,
    pty: Pty,
    signals: HeldSignals,
    timeout: Option<Duration>,
    kill_after: Duration,
) -> Result<Option<ExitStatus>, RelayError> {
    let held = signals
        .0
        .as_ref()
        .expect("installed signals are held until dropped");
    let interactive = caller_is_terminal();
    if interactive {
        // The hook is the binary's to install: setting one is process-global,
        // and what it buys — restoration before a backtrace prints, which a
        // guard's drop cannot arrange — only matters to a program that prints
        // one.
        install_panic_restore();
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    // Lines `fcage` writes while the relay runs, a network stack's or a
    // forward's reports among them, go to a terminal in raw mode where standard
    // error is one.
    let raw_stderr = interactive && termios::tcgetattr(rustix::stdio::stderr()).is_ok();
    let _lines = crate::output::RawLines::hold(raw_stderr);
    Relay::new(stdin.as_fd(), stdout.as_fd())
        .raw(interactive)
        .escalation(Escalation::new(timeout, kill_after))
        .run(&mut running, &pty, held)
}
