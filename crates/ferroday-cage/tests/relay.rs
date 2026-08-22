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
//! `FERRODAY_CAGE_REQUIRE_USERNS` turns each skip into a failure. The one
//! exception is the restriction case, which runs a host binary and needs none.

#![allow(unsafe_code)]

mod common;

use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ferroday_cage::relay::{Escalation, Relay, RelayError, Signals, restore_terminal};
use ferroday_cage::{Cage, ExitStatus, Pty, Running, Terminal};
use rustix::process::{Pid, Signal};
use rustix::pty::OpenptFlags;
use rustix::termios::{self, LocalModes, SpecialCodeIndex, Termios, Winsize};

/// One relay at a time; see the module documentation.
static SERIAL: Mutex<()> = Mutex::new(());

/// How long a driven session may take before the test gives up on it. Generous:
/// the assertion that matters is what the session did, not how fast.
const PATIENCE: Duration = Duration::from_secs(30);

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
        assert_eq!(
            self.before.input_modes, self.after.input_modes,
            "the input modes were not restored",
        );
        assert_eq!(
            self.before.output_modes, self.after.output_modes,
            "the output modes were not restored",
        );
        assert_eq!(
            self.before.control_modes, self.after.control_modes,
            "the control modes were not restored",
        );
        assert_eq!(
            self.before.local_modes, self.after.local_modes,
            "the local modes were not restored",
        );
        // `SpecialCodes` carries no equality of its own, and `make_raw` clears
        // VMIN and VTIME and leaves the rest, so a restoration that missed any
        // of them would show here.
        for (name, index) in [
            ("VINTR", SpecialCodeIndex::VINTR),
            ("VQUIT", SpecialCodeIndex::VQUIT),
            ("VERASE", SpecialCodeIndex::VERASE),
            ("VKILL", SpecialCodeIndex::VKILL),
            ("VEOF", SpecialCodeIndex::VEOF),
            ("VTIME", SpecialCodeIndex::VTIME),
            ("VMIN", SpecialCodeIndex::VMIN),
            ("VSTART", SpecialCodeIndex::VSTART),
            ("VSTOP", SpecialCodeIndex::VSTOP),
            ("VSUSP", SpecialCodeIndex::VSUSP),
            ("VEOL", SpecialCodeIndex::VEOL),
            ("VREPRINT", SpecialCodeIndex::VREPRINT),
            ("VDISCARD", SpecialCodeIndex::VDISCARD),
            ("VWERASE", SpecialCodeIndex::VWERASE),
            ("VLNEXT", SpecialCodeIndex::VLNEXT),
            ("VEOL2", SpecialCodeIndex::VEOL2),
        ] {
            assert_eq!(
                self.before.special_codes[index], self.after.special_codes[index],
                "{name} was not restored",
            );
        }
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

    let (primary, replica) = caller_terminal(size);
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
        let mut written = 0;
        while written < text.len() {
            written += rustix::io::write(fd, &text.as_bytes()[written..]).expect("the write lands");
        }
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
        while !self.seen.contains(needle) {
            if !common::drain_until(&self.primary, deadline, &mut self.seen) {
                break;
            }
        }
        self.seen.contains(needle)
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
        while Instant::now() < deadline
            && common::drain_until(&self.primary, deadline, &mut self.seen)
        {}
    }

    /// Keeps reading until the relay reports the session over.
    fn drain_until_done(&mut self, done: &AtomicBool) {
        let deadline = Instant::now() + PATIENCE;
        while !done.load(Ordering::Acquire) && Instant::now() < deadline {
            let step = Instant::now() + Duration::from_millis(50);
            common::drain_until(&self.primary, step, &mut self.seen);
        }
    }

    /// The caller terminal's current settings, which is what raw mode changes.
    ///
    /// Read from the primary: Linux redirects a termios query there to the
    /// replica, which is the descriptor the relay was given.
    fn settings(&self) -> Termios {
        termios::tcgetattr(&self.primary).expect("the settings are readable")
    }

    /// Resizes the caller's terminal. Does not itself signal the relay.
    fn resize(&self, rows: u16, cols: u16) {
        termios::tcsetwinsize(&self.primary, winsize(rows, cols)).expect("the size is settable");
    }

    /// Raises `signal` at the relay's thread.
    fn signal(&self, signal: Signal) {
        // SAFETY: the relay's thread has this signal blocked, so it is made
        // pending on that thread's signal descriptor rather than delivered, and
        // nothing runs in signal context. The thread id is the relay's, taken
        // before this driver existed and live for as long as the relay is.
        unsafe { rustix::runtime::tkill(self.relay, signal) }.expect("the signal is deliverable");
    }
}

/// A pseudoterminal pair standing in for the caller's own terminal: the user's
/// end, and the end the relay is given.
fn caller_terminal(size: (u16, u16)) -> (OwnedFd, OwnedFd) {
    let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
    let primary = rustix::pty::openpt(flags).expect("a pseudoterminal is available");
    rustix::pty::unlockpt(&primary).expect("the replica unlocks");
    let replica = rustix::pty::ioctl_tiocgptpeer(&primary, flags).expect("the replica opens");
    termios::tcsetwinsize(&primary, winsize(size.0, size.1)).expect("the size is settable");
    (primary, replica)
}

/// A window size in rows and columns.
fn winsize(rows: u16, cols: u16) -> Winsize {
    Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
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
///
/// It runs a host binary rather than a sandboxed one, so it needs no user
/// namespace and no rootfs fixture — but it does need the confinement a
/// restriction exists to apply, so it skips where the kernel offers no
/// Landlock. `FERRODAY_CAGE_REQUIRE_LANDLOCK` turns that skip into a failure.
#[cfg(feature = "hardening")]
#[test]
fn a_restricted_session_relays() {
    if ferroday_cage::host::landlock_abi().is_none() {
        assert!(
            std::env::var_os("FERRODAY_CAGE_REQUIRE_LANDLOCK").is_none(),
            "Landlock is required but the kernel offers none",
        );
        eprintln!("skipping: the kernel offers no Landlock support");
        return;
    }
    // The command runs from the system trees, so they are what it is granted;
    // the pseudoterminal arrives as descriptors and needs no path at all.
    let mut builder = ferroday_cage::Restriction::builder()
        .command("/bin/sh")
        .args(["-c", "echo marker-from-inside"]);
    for tree in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
        if std::path::Path::new(tree).exists() {
            builder = builder.landlock_fs(
                ferroday_cage::FsAccess::READ | ferroday_cage::FsAccess::EXECUTE,
                tree,
            );
        }
    }
    let restriction = builder.build().expect("a valid restriction configuration");
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

// -- Restoration outside a session --------------------------------------------

/// `restore_terminal` reaches the first raw session's terminal and nothing else,
/// so a terminal no relay has touched is left exactly as it is.
///
/// Order-independent by construction: whatever earlier test may already have
/// recorded a raw session, this terminal is not it.
#[test]
fn restoring_leaves_a_terminal_no_session_touched_alone() {
    let (primary, _replica) = caller_terminal((24, 80));
    let before = termios::tcgetattr(&primary).expect("the settings are readable");
    restore_terminal();
    restore_terminal();
    let after = termios::tcgetattr(&primary).expect("the settings are readable");
    assert_eq!(before.local_modes, after.local_modes);
    assert_eq!(before.input_modes, after.input_modes);
    assert_eq!(before.output_modes, after.output_modes);
    assert_eq!(before.control_modes, after.control_modes);
}
