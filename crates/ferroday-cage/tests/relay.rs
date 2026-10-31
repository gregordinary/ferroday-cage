//! In-process integration tests for the terminal relay.
//!
//! The relay is parameterized on the descriptors it drives, so a test can hand
//! it a pseudoterminal of the test's own and play the user at the other end.
//! That is what makes raw mode, restoration, `VEOF` forwarding, a window
//! change, an interrupt from outside, and an expired deadline assertable here
//! rather than only through a built binary driving a real terminal.
//!
//! # The shape
//!
//! Each session runs the relay on the test's own thread and the driver — the
//! user — on a thread of its own. That way round because the relay's signals are
//! blocked per thread: the thread that calls [`Signals::install`] is the thread
//! whose pending signals its descriptor reads, so the relay must run where the
//! set was blocked. The driver raises signals *at that thread* rather than at
//! the process, since a process-directed signal is delivered to any thread that
//! has not blocked it, which in a test binary is every other test's.
//!
//! The sessions hold a lock for the same reason. Two relays in flight would each
//! own a signal descriptor, and two descriptors in one process race for a
//! process-directed signal — whichever reads first consumes it. Nothing here
//! raises one, but a suite that depended on that would be depending on a
//! subtlety rather than on the documented rule.
//!
//! Every test launches a real sandbox, so it skips explicitly, on stderr, where
//! the host cannot create unprivileged user namespaces;
//! `FERRODAY_CAGE_REQUIRE_USERNS` turns each skip into a failure. The
//! exceptions are the restriction cases, which run a host binary and need
//! none.

#![allow(unsafe_code)]

mod common;

use common::pty;

use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ferroday_cage::relay::{Escalation, Relay, RelayError, Signals, restore_terminal};
use ferroday_cage::{Cage, ExitStatus, Pty, Running, Terminal};
use rustix::process::{Pid, Signal};
use rustix::termios::{self, LocalModes, Termios};

/// One relay at a time; see the module documentation.
static SERIAL: Mutex<()> = Mutex::new(());

/// How long a driven session may take before the test gives up on it. Generous:
/// the assertion that matters is what the session did, not how fast.
const PATIENCE: Duration = Duration::from_secs(30);

/// The relay's own read buffer, which a paste has to exceed several times over
/// to be sure it met the pending path rather than passing through in one write.
const RELAY_BUF: usize = 8192;

/// How long a driver waits for something the session is about to print.
const PROMPTLY: Duration = Duration::from_secs(5);

/// Takes the session lock, ignoring a poisoning left by a failed test: the lock
/// orders the sessions and guards no state a panic could have left inconsistent.
fn serially() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// -- The harness --------------------------------------------------------------

/// How the caller's side of a session is wired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wiring {
    /// Input and output are one terminal: the interactive shape, with or
    /// without raw mode.
    Terminal { raw: bool },
    /// Input is a pipe the driver closes and output is the terminal. The
    /// scripted shape, and the only one in which the input channel can reach
    /// end of file.
    PipeInput,
}

/// What a driven session left behind.
struct Session {
    /// What the relay returned.
    outcome: Result<Option<ExitStatus>, RelayError>,
    /// The caller terminal's settings before the session.
    before: Termios,
    /// And after it, which is what restoration is asserted on.
    after: Termios,
    /// Everything the user's end read.
    seen: String,
}

impl Session {
    /// The status the session reported, failing the test if it did not report
    /// one.
    fn status(&self) -> ExitStatus {
        match &self.outcome {
            Ok(Some(status)) => *status,
            Ok(None) => panic!("the session reported an expired deadline: {}", self.seen),
            Err(error) => panic!("the session failed: {error}\n{}", self.seen),
        }
    }

    /// Asserts the caller's terminal came back field for field as it went in.
    ///
    /// Compared rather than eyeballed, because "looks interactive again" is not
    /// the promise the relay makes.
    fn assert_restored(&self) {
        pty::assert_restored(&self.before, &self.after);
    }
}

/// Runs one relayed session: the relay on this thread, `drive` on another
/// playing the user.
fn relayed(
    wiring: Wiring,
    size: (u16, u16),
    bound: Option<(Duration, Duration)>,
    launch: impl FnOnce(&Terminal) -> Result<(Running<'static>, Pty), ferroday_cage::Error>,
    drive: impl FnOnce(&mut Caller) + Send,
) -> Session {
    let _serial = serially();
    let signals = Signals::install().expect("the relay's signals install");
    let relay_thread = rustix::thread::gettid();

    let (primary, replica) = pty::pair(size.0, size.1);
    let before = termios::tcgetattr(&primary).expect("the caller terminal reports its settings");

    let (mut running, pty) = launch(&Terminal::new().size(size.0, size.1))
        .expect("the command starts on a terminal of its own");

    // Only the piped shape has an input the driver can close; the interactive
    // one types at the terminal it also reads.
    let (pipe_reader, pipe_writer) = match wiring {
        Wiring::PipeInput => {
            let (reader, writer) = rustix::pipe::pipe().expect("a pipe is available");
            (Some(reader), Some(writer))
        }
        Wiring::Terminal { .. } => (None, None),
    };
    let input = pipe_reader.as_ref().map_or(replica.as_fd(), OwnedFd::as_fd);

    let mut relay = Relay::new(input, replica.as_fd());
    if let Wiring::Terminal { raw: true } = wiring {
        relay = relay.raw(true);
    }
    // Built here rather than by the caller: an `Escalation`'s deadline runs
    // from where it was built, and building one before the launch would spend
    // the timeout on starting the sandbox.
    if let Some((timeout, kill_after)) = bound {
        relay = relay.escalation(Escalation::new(Some(timeout), kill_after));
    }

    let mut caller = Caller {
        primary,
        input: pipe_writer,
        relay: relay_thread,
        seen: String::new(),
    };
    let done = AtomicBool::new(false);
    let outcome = {
        let caller = &mut caller;
        let done = &done;
        std::thread::scope(move |scope| {
            scope.spawn(move || {
                drive(caller);
                // Kept draining until the relay says the session is over: a
                // command that writes more than the caller terminal holds would
                // otherwise stall the relay's blocking write and hang the run.
                caller.drain_until_done(done);
            });
            let outcome = relay.run(&mut running, &pty, &signals);
            done.store(true, Ordering::Release);
            outcome
        })
    };

    let after =
        termios::tcgetattr(&caller.primary).expect("the caller terminal reports its settings");
    Session {
        outcome,
        before,
        after,
        seen: caller.seen,
    }
}

/// The user at the other end of the relayed terminal.
struct Caller {
    /// The user's end of the caller terminal: what the session wrote is
    /// readable here, and what is written here the session reads as typed.
    primary: OwnedFd,
    /// The write end of the relay's input, where that input is a pipe.
    input: Option<OwnedFd>,
    /// The thread the relay runs on, which is the thread its signals are
    /// pending for.
    relay: Pid,
    /// Everything read from the terminal so far, for the assertions to search.
    seen: String,
}

impl Caller {
    /// Types `text` at the session.
    fn send(&mut self, text: &str) {
        let fd = self
            .input
            .as_ref()
            .map_or(self.primary.as_fd(), OwnedFd::as_fd);
        pty::send(fd, text);
    }

    /// Closes the relay's input, which is end of input where it is a pipe.
    fn close_input(&mut self) {
        self.input = None;
    }

    /// Reads until `needle` appears or the patience runs out, and reports
    /// whether it appeared.
    ///
    /// Everything is accumulated rather than searched per read, because the
    /// session's echo and the command's output arrive interleaved and in
    /// whatever chunks the line discipline chose.
    fn read_until(&mut self, needle: &str, patience: Duration) -> bool {
        let deadline = Instant::now() + patience;
        pty::read_until(&self.primary, needle, deadline, &mut self.seen)
    }

    /// Reads until `needle` appears, failing the test if it does not.
    fn expect(&mut self, needle: &str) {
        assert!(
            self.read_until(needle, PROMPTLY),
            "the session never printed {needle:?}; it printed:\n{}",
            self.seen,
        );
    }

    /// Keeps reading for `how_long`, so the relay has room to act on what it
    /// was just sent.
    fn settle(&mut self, how_long: Duration) {
        let deadline = Instant::now() + how_long;
        while Instant::now() < deadline && pty::drain_until(&self.primary, deadline, &mut self.seen)
        {
        }
    }

    /// Keeps reading until the relay reports the session over.
    fn drain_until_done(&mut self, done: &AtomicBool) {
        let deadline = Instant::now() + PATIENCE;
        while !done.load(Ordering::Acquire) && Instant::now() < deadline {
            let step = Instant::now() + Duration::from_millis(50);
            pty::drain_until(&self.primary, step, &mut self.seen);
        }
    }

    /// The caller terminal's current settings, which is what raw mode changes.
    ///
    /// Read from the primary: Linux redirects a termios query there to the
    /// replica, which is the descriptor the relay was given.
    fn settings(&self) -> Termios {
        termios::tcgetattr(&self.primary).expect("the settings are readable")
    }

    /// Waits until the caller's terminal is out of raw mode, failing the test
    /// if it does not come out promptly.
    ///
    /// The relay restores the caller's terminal the moment it stops relaying,
    /// before it waits for the command, so this is the relay's own report that
    /// the session's terminal has closed.
    fn expect_restored(&mut self) {
        let deadline = Instant::now() + PROMPTLY;
        while pty::is_raw(&self.settings()) {
            assert!(
                Instant::now() < deadline,
                "the relay never stopped relaying; it printed:\n{}",
                self.seen,
            );
            self.settle(Duration::from_millis(50));
        }
    }

    /// Resizes the caller's terminal. Does not itself signal the relay.
    fn resize(&self, rows: u16, cols: u16) {
        termios::tcsetwinsize(&self.primary, pty::winsize(rows, cols))
            .expect("the size is settable");
    }

    /// Raises `signal` at the relay's thread.
    fn signal(&self, signal: Signal) {
        // SAFETY: the relay's thread has this signal blocked, so it is made
        // pending on that thread's signal descriptor rather than delivered, and
        // nothing runs in signal context. The thread id is the relay's, taken
        // before this driver existed and live for as long as the relay is.
        unsafe {
            syscalls::syscall!(
                syscalls::Sysno::tkill,
                self.relay.as_raw_nonzero().get(),
                signal.as_raw()
            )
        }
        .expect("the signal is deliverable");
    }
}

/// A cage running `/bin/sh -c script` against the fixture rootfs.
fn shell(rootfs: &std::path::Path, script: &str) -> Cage {
    Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
}

// -- The interactive shape ----------------------------------------------------

/// A typed line reaches the sandbox, its output comes back, and the caller's
/// terminal is restored byte for byte on the way out.
///
/// The restoration is the assertion that matters most: the relay puts the
/// caller's terminal into raw mode, and one that returns without undoing that
/// leaves the user's shell unusable.
#[test]
fn a_session_relays_a_typed_line_and_restores_the_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .build()
        .expect("a valid sandbox configuration");

    let session = relayed(
        Wiring::Terminal { raw: true },
        (24, 80),
        None,
        |terminal| cage.spawn_terminal(terminal),
        |caller| {
            caller.send("echo marker-from-inside\n");
            caller.expect("marker-from-inside");
            // Raw mode is observable from the other end while the session runs,
            // which is the whole reason this shape can be driven in process.
            assert!(
                !caller
                    .settings()
                    .local_modes
                    .intersects(LocalModes::ICANON | LocalModes::ECHO),
                "the caller's terminal is raw for the session's duration",
            );
            caller.send("exit 7\n");
        },
    );

    assert_eq!(session.status().code(), Some(7), "{}", session.seen);
    assert!(
        session.seen.contains("marker-from-inside"),
        "{}",
        session.seen
    );
    session.assert_restored();
}

/// A relay that was not asked for raw mode does not touch the caller's termios,
/// which is what makes the default posture safe for a library.
#[test]
fn a_relay_that_was_not_asked_for_raw_mode_leaves_the_terminal_alone() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = shell(rootfs, "echo marker-from-inside");
    let session = relayed(
        Wiring::Terminal { raw: false },
        (24, 80),
        None,
        |terminal| cage.spawn_terminal(terminal),
        |caller| {
            caller.expect("marker-from-inside");
            assert!(
                caller
                    .settings()
                    .local_modes
                    .contains(LocalModes::ICANON | LocalModes::ECHO),
                "the caller's terminal is still the caller's",
            );
        },
    );

    assert!(session.status().success(), "{}", session.seen);
    session.assert_restored();
}

/// A window change resizes the sandbox's terminal, which is how a full-screen
/// program inside learns to redraw.
///
/// The size the relay follows is the one the *supplied* descriptor reports, not
/// the process's own terminal: this test process has whatever terminal the test
/// runner gave it, and the session follows the pseudoterminal the test made.
#[test]
fn a_window_change_resizes_the_sandboxs_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Announces itself, then answers the window change with the new size. The
    // wait is a bounded sequence of short sleeps, so a run where the signal
    // never arrives ends rather than hanging.
    let cage = shell(
        rootfs,
        "trap 'stty size; exit 0' WINCH; echo ready; \
         i=0; while [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done",
    );
    let session = relayed(
        Wiring::Terminal { raw: true },
        (30, 100),
        None,
        |terminal| cage.spawn_terminal(terminal),
        |caller| {
            caller.expect("ready");
            caller.resize(45, 132);
            caller.signal(Signal::WINCH);
            caller.expect("45 132");
        },
    );

    assert!(session.status().success(), "{}", session.seen);
    assert!(session.seen.contains("45 132"), "{}", session.seen);
    session.assert_restored();
}

/// An interrupt from outside is forwarded as a termination request rather than
/// acted on locally, and the terminal is still restored on the way out.
///
/// A typed `^C` is a different thing entirely — in raw mode it is a byte the
/// sandbox's own line discipline acts on — which is why this raises the signal
/// rather than writing the character.
#[test]
fn an_interrupt_from_outside_ends_the_session_and_restores_the_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = shell(rootfs, "echo ready; sleep 30");
    let session = relayed(
        Wiring::Terminal { raw: true },
        (24, 80),
        None,
        |terminal| cage.spawn_terminal(terminal),
        |caller| {
            caller.expect("ready");
            caller.signal(Signal::INT);
        },
    );

    assert!(
        !session.status().success(),
        "an interrupted session should not report success: {:?}",
        session.outcome,
    );
    session.assert_restored();
}

/// A second interrupt kills what the first only asked to stop.
///
/// The command ignores `SIGTERM`, so the termination request the first
/// interrupt sends leaves it running and only the kill ends the session.
#[test]
fn a_second_interrupt_kills_a_command_that_ignored_the_first() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = shell(rootfs, "trap '' TERM; echo ready; sleep 30");
    let session = relayed(
        Wiring::Terminal { raw: true },
        (24, 80),
        None,
        |terminal| cage.spawn_terminal(terminal),
        |caller| {
            caller.expect("ready");
            caller.signal(Signal::INT);
            // Long enough for the relay to read the first and act on it:
            // identical signals coalesce while pending, so a second raised
            // before the first was read would be the same one.
            caller.settle(Duration::from_millis(500));
            caller.signal(Signal::INT);
        },
    );

    assert!(
        !session.status().success(),
        "the killed session should not report success: {:?}",
        session.outcome,
    );
    session.assert_restored();
}

// -- The scripted shape -------------------------------------------------------

/// End of input on a pipe is relayed as the sandbox's own `VEOF`, since a
/// pseudoterminal's write side cannot be closed. The command inside sees end of
/// file and exits on its own terms, which is what carries the status back.
///
/// `cat` rather than a shell, deliberately: an interactive shell installs a line
/// editor that puts the terminal into raw mode and interprets `^D` itself, so it
/// would be testing the shell's reading of the character rather than the relay's
/// delivery of it.
#[test]
fn end_of_input_reaches_the_sandbox_as_end_of_file() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/cat")
        .build()
        .expect("a valid sandbox configuration");
    let session = relayed(
        Wiring::PipeInput,
        (24, 80),
        None,
        |terminal| cage.spawn_terminal(terminal),
        |caller| {
            caller.send("marker-in-sandbox\n");
            caller.expect("marker-in-sandbox");
            // The channel retires here: the relay sends the replica's own VEOF
            // and stops watching the slot, which is what lets `cat` end.
            caller.close_input();
        },
    );

    assert!(session.status().success(), "{}", session.seen);
    assert!(
        session.seen.contains("marker-in-sandbox"),
        "{}",
        session.seen
    );
}

/// A paste larger than the sandbox's terminal will take is buffered and drained
/// rather than dropped or spun on.
///
/// The relay's defence against exactly that: the primary is non-blocking, so a
/// write that only takes part of what was read leaves the rest in a pending
/// buffer behind `POLLOUT`, and the caller's input leaves the poll set while
/// that buffer is occupied — reading more would grow it without bound. A loop
/// that dropped the short write's remainder would deliver a truncated paste,
/// and one that kept reading would grow the buffer for as long as the caller
/// kept typing.
///
/// The payload is far larger than a pseudoterminal's own buffer, which is a few
/// kilobytes, so the path is entered many times over rather than at a boundary
/// the test would have to hit exactly.
#[test]
fn a_paste_larger_than_the_sandboxs_terminal_arrives_whole() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Nothing reads the sandbox's terminal for the first second, so its input
    // queue -- a few kilobytes -- fills and the primary stops accepting long
    // before the paste has been delivered. That is what puts the loop on the
    // pending path deterministically rather than depending on `cat` losing a
    // race it usually wins.
    let cage = shell(rootfs, "sleep 1; exec /bin/cat");
    // Line-shaped, since the sandbox's own line discipline is canonical and
    // delivers a line only when it ends. Thirty-two kilobytes: many times the
    // terminal's own buffer and many times the relay's read buffer, and well
    // inside the pipe the driver writes it to, so the driver is never blocked
    // in the write while the relay waits for it to drain the other direction.
    const LINES: usize = 4096;
    let paste: String = (0..LINES).map(|at| format!("line-{at:04}\n")).collect();
    assert!(
        paste.len() > 4 * RELAY_BUF && paste.len() < 64 * 1024,
        "{}",
        paste.len()
    );

    let session = relayed(
        Wiring::PipeInput,
        (24, 80),
        None,
        |terminal| cage.spawn_terminal(terminal),
        {
            let paste = paste.clone();
            move |caller| {
                caller.send(&paste);
                // The last line is the one that can only arrive after every
                // pending buffer before it has drained. The patience covers the
                // sandbox's first second of not reading.
                assert!(
                    caller.read_until(&format!("line-{:04}", LINES - 1), PATIENCE),
                    "the paste's last line never came back:\n{}",
                    caller.seen,
                );
                caller.close_input();
            }
        },
    );

    assert!(session.status().success(), "{}", session.seen);
    // Every line, in order, and each of them once. `cat` writes what it read
    // and the replica echoes it, so each appears twice; what is asserted is
    // that none went missing.
    for at in 0..LINES {
        assert!(
            session.seen.contains(&format!("line-{at:04}")),
            "line {at} of the paste never arrived",
        );
    }
}

/// An expired deadline is reported as no status at all, whatever became of the
/// command.
#[test]
fn an_expired_deadline_reports_no_status() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = shell(rootfs, "echo ready; sleep 60");
    let started = Instant::now();
    let session = relayed(
        Wiring::Terminal { raw: false },
        (24, 80),
        Some((Duration::from_secs(2), Duration::from_secs(1))),
        |terminal| cage.spawn_terminal(terminal),
        |caller| caller.expect("ready"),
    );

    assert!(
        matches!(session.outcome, Ok(None)),
        "the deadline passed, so no status is reported: {:?}",
        session.outcome,
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the deadline did not end the session promptly",
    );
}

/// The same expiry against a command that never stops printing.
///
/// The quiet case above leaves the relay asleep in a `poll` whose only wakeup is
/// the deadline, so it cannot tell an expiry the clock decided from one the
/// absence of traffic decided. A command flooding the pseudoterminal keeps the
/// primary readable, so every `poll` returns on a descriptor rather than on the
/// timeout — and a relay that acted on the deadline only when `poll` reported
/// nothing else would go on relaying instead of escalating.
#[test]
fn an_expired_deadline_reports_no_status_against_a_command_that_never_stops_printing() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Three writers, so the relay is refilled while it drains.
    let cage = shell(rootfs, "yes flooding & yes flooding & yes flooding");
    let started = Instant::now();
    let session = relayed(
        Wiring::Terminal { raw: false },
        (24, 80),
        Some((Duration::from_secs(2), Duration::from_secs(1))),
        |terminal| cage.spawn_terminal(terminal),
        |caller| caller.expect("flooding"),
    );

    assert!(
        matches!(session.outcome, Ok(None)),
        "the deadline passed, so no status is reported: {:?}",
        session.outcome,
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the deadline did not end the session promptly",
    );
    assert!(
        !session.seen.is_empty(),
        "the relay kept relaying while the deadline ran out",
    );
}

// -- A command that outlives its terminal -------------------------------------

/// A command that closes its standard streams and keeps running. Closing them
/// closes the last replica, which ends the relaying; `exec` keeps the sleep the
/// command process itself, so a termination request reaches it directly.
const CLOSES_ITS_TERMINAL: &str = "echo ready; exec 0<&- 1>&- 2>&-; exec sleep 60";

/// End-of-file on the sandbox's terminal ends the relaying, not the command,
/// and the deadline still stops the command.
#[test]
fn a_deadline_stops_a_command_that_closed_its_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = shell(rootfs, CLOSES_ITS_TERMINAL);
    let started = Instant::now();
    let session = relayed(
        Wiring::Terminal { raw: true },
        (24, 80),
        Some((Duration::from_secs(2), Duration::from_secs(1))),
        |terminal| cage.spawn_terminal(terminal),
        |caller| caller.expect("ready"),
    );

    assert!(
        matches!(session.outcome, Ok(None)),
        "the deadline passed, so no status is reported: {:?}",
        session.outcome,
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the deadline did not stop the command once its terminal closed",
    );
    session.assert_restored();
}

/// A signal from outside still reaches a command whose terminal has closed.
///
/// Raised only once the relay has restored the caller's terminal, which it does
/// as it stops relaying, so the signal is answered by the wait for the
/// command's exit rather than by the loop before it.
#[test]
fn a_termination_request_reaches_a_command_that_closed_its_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = shell(rootfs, CLOSES_ITS_TERMINAL);
    let started = Instant::now();
    let session = relayed(
        Wiring::Terminal { raw: true },
        (24, 80),
        None,
        |terminal| cage.spawn_terminal(terminal),
        |caller| {
            caller.expect("ready");
            caller.expect_restored();
            caller.signal(Signal::TERM);
        },
    );

    assert_eq!(
        session.status().signal(),
        Some(Signal::TERM.as_raw()),
        "the command was ended by the forwarded request: {:?}",
        session.outcome,
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the request did not reach the command once its terminal closed",
    );
    session.assert_restored();
}

/// An interrupt raised while the session was relayed counts toward the kill
/// that a second one sends after the terminal has closed.
///
/// The command ignores `SIGTERM`, so the first interrupt's request leaves it
/// running and only the kill ends it. The ignored disposition survives the
/// `exec`, which keeps the sleep deaf to the request too. The command closes
/// its terminal only once it reads a line, so the first interrupt is answered
/// while the session is still relayed.
#[test]
fn an_interrupt_before_the_terminal_closed_counts_toward_the_kill() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = shell(
        rootfs,
        "trap '' TERM; echo ready; read line; exec 0<&- 1>&- 2>&-; exec sleep 60",
    );
    let started = Instant::now();
    let session = relayed(
        Wiring::Terminal { raw: true },
        (24, 80),
        None,
        |terminal| cage.spawn_terminal(terminal),
        |caller| {
            caller.expect("ready");
            caller.signal(Signal::INT);
            // Long enough for the relay to read the first and act on it:
            // identical signals coalesce while pending.
            caller.settle(Duration::from_millis(500));
            caller.send("go\n");
            caller.expect_restored();
            caller.signal(Signal::INT);
        },
    );

    assert_eq!(
        session.status().signal(),
        Some(Signal::KILL.as_raw()),
        "only the kill ends a command that ignores the request: {:?}",
        session.outcome,
    );
    assert!(started.elapsed() < Duration::from_secs(20));
}

// -- The other launch paths ---------------------------------------------------

/// The network seam's terminal launch relays the same way, and its wait is as
/// prompt: the gate is released before the loop starts, so the loop still ends
/// at end-of-file on the primary.
#[test]
fn a_session_held_at_the_network_seam_relays_once_it_proceeds() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = shell(rootfs, "echo marker-from-inside");
    let session = relayed(
        Wiring::Terminal { raw: true },
        (24, 80),
        None,
        |terminal| {
            let (pending, pty) = cage.spawn_pending_terminal(terminal)?;
            // Where a caller would attach a network stack to the sandbox's
            // namespace; the seam itself is what this exercises.
            let running = pending.proceed()?;
            Ok((running, pty))
        },
        |caller| caller.expect("marker-from-inside"),
    );

    assert!(session.status().success(), "{}", session.seen);
    session.assert_restored();
}

/// The restriction fallback's terminal launch relays the same way.
#[cfg(feature = "hardening")]
#[test]
fn a_restricted_session_relays() {
    let Some(restriction) = restricted_shell("echo marker-from-inside") else {
        return;
    };
    let session = relayed(
        Wiring::Terminal { raw: true },
        (24, 80),
        None,
        |terminal| restriction.spawn_terminal(terminal),
        |caller| caller.expect("marker-from-inside"),
    );

    assert!(session.status().success(), "{}", session.seen);
    session.assert_restored();
}

/// The restriction fallback's command is bounded by the deadline once its
/// terminal has closed, as a sandbox's is.
#[cfg(feature = "hardening")]
#[test]
fn a_deadline_stops_a_restricted_command_that_closed_its_terminal() {
    let Some(restriction) = restricted_shell(CLOSES_ITS_TERMINAL) else {
        return;
    };
    let started = Instant::now();
    let session = relayed(
        Wiring::Terminal { raw: true },
        (24, 80),
        Some((Duration::from_secs(2), Duration::from_secs(1))),
        |terminal| restriction.spawn_terminal(terminal),
        |caller| caller.expect("ready"),
    );

    assert!(
        matches!(session.outcome, Ok(None)),
        "the deadline passed, so no status is reported: {:?}",
        session.outcome,
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the deadline did not stop the command once its terminal closed",
    );
    session.assert_restored();
}

/// A restriction running `/bin/sh -c script` from the host's system trees, or
/// `None`, with the skip reported, where the kernel offers no Landlock.
///
/// It runs a host binary rather than a sandboxed one, so it needs no user
/// namespace and no rootfs fixture. It does need the confinement a restriction
/// exists to apply, and `FERRODAY_CAGE_REQUIRE_LANDLOCK` turns the skip into a
/// failure.
#[cfg(feature = "hardening")]
fn restricted_shell(script: &str) -> Option<ferroday_cage::Restriction> {
    if !common::landlock() {
        return None;
    }
    // The command runs from the system trees, so they are what it is granted;
    // the pseudoterminal arrives as descriptors and needs no path at all.
    let mut builder = ferroday_cage::Restriction::builder()
        .command("/bin/sh")
        .args(["-c", script]);
    for tree in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
        if std::path::Path::new(tree).exists() {
            builder = builder.landlock_fs(
                ferroday_cage::FsAccess::READ | ferroday_cage::FsAccess::EXECUTE,
                tree,
            );
        }
    }
    Some(builder.build().expect("a valid restriction configuration"))
}

// -- Raw mode and the foreground ----------------------------------------------

/// Names the role this test binary plays when it runs itself as the child of
/// [`a_session_started_in_the_background_leaves_the_terminal_to_its_shell`].
const BACKGROUND_HELPER: &str = "FERRODAY_CAGE_TEST_BACKGROUND_RELAY";

/// A relay started in the background leaves the terminal's settings to the
/// shell in the foreground, and enters raw mode once `fg` brings it forward.
///
/// The relay blocks `SIGTTOU`, so a `tcsetattr` from the background succeeds
/// rather than stopping it, and only the relay's own check keeps it from
/// rewriting a terminal it does not hold. That needs a session with job
/// control, which this test process cannot become without taking every other
/// test with it. So it runs this test binary as a child process in a session of
/// its own, with a fresh pseudoterminal as its controlling terminal, and the
/// child plays both the shell and the job; see
/// [`helper_relay_started_in_the_background`].
#[test]
fn a_session_started_in_the_background_leaves_the_terminal_to_its_shell() {
    use std::process::Command;

    let Some(_) = common::fixture_rootfs() else {
        return;
    };
    let (primary, replica) = pty::pair(24, 80);
    let exe = std::env::current_exe().expect("the test binary has a path");
    let mut command = Command::new(exe);
    command
        .args([
            "--exact",
            "helper_relay_started_in_the_background",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(BACKGROUND_HELPER, "1");
    let mut child = pty::spawn_controlled(&mut command, &replica);
    // The test's own copy goes, so the helper's exit hangs the primary up.
    drop(replica);

    // Drained throughout, so neither the helper's report nor the sandbox's
    // output can fill the terminal and stall the helper.
    let mut seen = String::new();
    let deadline = Instant::now() + PATIENCE;
    let status = loop {
        if let Some(status) = child.try_wait().expect("the helper can be waited for") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the helper did not finish; it printed:\n{seen}");
        }
        pty::drain_until(
            &primary,
            Instant::now() + Duration::from_millis(50),
            &mut seen,
        );
    };
    while pty::drain_until(
        &primary,
        Instant::now() + Duration::from_millis(100),
        &mut seen,
    ) {}
    assert!(status.success(), "the helper failed; it printed:\n{seen}");
}

/// Not a test of its own: when [`BACKGROUND_HELPER`] is set, this plays a shell
/// starting a relayed session with `&` and then bringing it to the foreground.
/// Without the variable it does nothing.
///
/// Its process is a session leader whose controlling terminal is its standard
/// input. The shell's part is a process group of its own that holds the
/// foreground, which is what `&` leaves behind. The relay runs on this thread,
/// and a driver thread plays the shell's `bg` and `fg`. Each continue goes to
/// the relay's thread rather than to the process, for the reason the module
/// documentation gives.
#[test]
fn helper_relay_started_in_the_background() {
    use std::os::unix::process::CommandExt as _;

    if std::env::var_os(BACKGROUND_HELPER).is_none() {
        return;
    }
    let rootfs =
        common::fixture_rootfs().expect("the parent runs the helper only where sandboxes launch");
    let signals = Signals::install().expect("the relay's signals install");
    let relay_thread = rustix::thread::gettid();
    let terminal = rustix::stdio::stdin();
    assert!(
        !pty::is_raw(&termios::tcgetattr(terminal).expect("the terminal reports its settings")),
        "the helper's premise: a cooked terminal",
    );

    // The shell's process group takes the foreground, leaving this one in the
    // background, as `&` does.
    let mut foreground = std::process::Command::new("sleep")
        .arg("60")
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("a process to hold the foreground starts");
    let shell_group = Pid::from_raw(foreground.id() as i32).expect("a live process id");
    termios::tcsetpgrp(terminal, shell_group).expect("the foreground moves to the shell's group");

    let cage = shell(rootfs, "echo ready; sleep 60");
    let (mut running, pty) = cage
        .spawn_terminal(&Terminal::new())
        .expect("the command starts on a terminal of its own");
    let raised = |signal: Signal| {
        // SAFETY: the relay's thread has this signal blocked, so it is made
        // pending on that thread's signal descriptor rather than delivered.
        // The thread id is the relay's, live for as long as the relay is.
        unsafe {
            syscalls::syscall!(
                syscalls::Sysno::tkill,
                relay_thread.as_raw_nonzero().get(),
                signal.as_raw()
            )
        }
        .is_ok()
    };
    let raw_now = || termios::tcgetattr(terminal).is_ok_and(|settings| pty::is_raw(&settings));

    let (outcome, report) = std::thread::scope(|scope| {
        // The driver records what it saw and always ends the session, so a
        // failed observation is reported rather than left as a relay that
        // never returns.
        let driver = scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(500));
            let at_start = raw_now();
            // `bg`: a continue that leaves the session in the background.
            raised(Signal::CONT);
            std::thread::sleep(Duration::from_millis(300));
            let after_bg = raw_now();
            // `fg`: the foreground moves to the session's group, then the
            // continue. This thread inherited the relay's blocked SIGTTOU,
            // which is what lets a background group take the foreground.
            let moved = termios::tcsetpgrp(terminal, rustix::process::getpgrp()).is_ok();
            raised(Signal::CONT);
            let deadline = Instant::now() + PROMPTLY;
            let mut after_fg = raw_now();
            while !after_fg && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
                after_fg = raw_now();
            }
            raised(Signal::TERM);
            (at_start, after_bg, moved, after_fg)
        });
        let outcome = Relay::new(terminal, rustix::stdio::stdout()).raw(true).run(
            &mut running,
            &pty,
            &signals,
        );
        (outcome, driver.join().expect("the driver completes"))
    });
    let _ = foreground.kill();
    let _ = foreground.wait();

    let (at_start, after_bg, moved, after_fg) = report;
    assert!(
        !at_start,
        "a session started in the background put the shell's terminal into raw mode",
    );
    assert!(
        !after_bg,
        "a continue that left the session in the background entered raw mode",
    );
    assert!(moved, "the session's group could not take the foreground");
    assert!(
        after_fg,
        "brought to the foreground, the session stayed cooked"
    );
    assert!(
        !raw_now(),
        "the terminal was not restored when the session ended",
    );
    assert!(
        matches!(outcome, Ok(Some(_))),
        "the session ended on the termination request: {outcome:?}",
    );
}

// -- Restoration outside a session --------------------------------------------

/// `restore_terminal` reaches the first raw session's terminal and nothing else,
/// so a terminal no relay has touched is left exactly as it is.
///
/// Order-independent by construction: whatever earlier test may already have
/// recorded a raw session, this terminal is not it.
#[test]
fn restoring_leaves_a_terminal_no_session_touched_alone() {
    let (primary, _replica) = pty::pair(24, 80);
    let before = termios::tcgetattr(&primary).expect("the settings are readable");
    restore_terminal();
    restore_terminal();
    let after = termios::tcgetattr(&primary).expect("the settings are readable");
    assert_eq!(before.local_modes, after.local_modes);
    assert_eq!(before.input_modes, after.input_modes);
    assert_eq!(before.output_modes, after.output_modes);
    assert_eq!(before.control_modes, after.control_modes);
}
