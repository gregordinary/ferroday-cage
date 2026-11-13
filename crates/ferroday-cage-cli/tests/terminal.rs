//! Integration tests for `fcage --terminal`: the relay, driven end to end.
//!
//! The relay owns process-global state — the caller's termios, a panic hook, a
//! blocked signal set — so it cannot be exercised in process alongside anything
//! else. Every test here runs the built binary instead, which is also what a
//! user runs.
//!
//! Two shapes appear below. The non-interactive one gives `fcage` an ordinary
//! pipe or `/dev/null` for its standard input, which is the scripted posture the
//! flag advertises. The interactive one allocates a pseudoterminal of the test's
//! own, puts `fcage` in a session of its own with the replica on all three
//! standard descriptors, and drives it as a user would — which is the only way
//! to reach raw mode, the size copy, `SIGWINCH`, and the restoration. Job
//! control takes one more process: the session is led by this test binary,
//! playing the shell, and `fcage` runs in it as a job.
//!
//! Every test skips explicitly, on stderr, on a host that cannot create
//! unprivileged user namespaces; `FERRODAY_CAGE_REQUIRE_USERNS` turns each skip
//! into a failure so a runner can assert they really ran.

mod common;

use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::pty;
use rustix::termios::{self, Winsize};

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// How long a driven session may take before the test gives up on it. Generous:
/// the assertion that matters is what the session did, not how fast.
const PATIENCE: Duration = Duration::from_secs(30);

// -- The non-interactive shape ------------------------------------------------

/// The regression this file exists for.
///
/// With `fcage`'s own standard input on a pipe whose writer has closed, the
/// relay's standard-input channel retires. A retired channel that stayed in the
/// poll set with an empty events mask would be reported ready on every pass —
/// `poll` reports `POLLHUP` whatever the requested events are — and the loop
/// would spin at 100% CPU for the rest of the session. The channel leaves the
/// polled set instead, so the loop blocks as it should.
///
/// Measured rather than reasoned about: the relay's own CPU time over a session
/// it spends entirely idle.
#[test]
fn a_retired_standard_input_does_not_spin() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut child = common::spawn_grouped(
        Command::new(FCAGE)
            .args(["--rootfs", rootfs.to_str().unwrap(), "--terminal"])
            .args(["--", "/bin/sleep", "3"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    );
    // Closing the write end hangs the pipe up, which is the trigger.
    drop(child.stdin.take());

    std::thread::sleep(Duration::from_millis(1500));
    let ticks = common::cpu_ticks(child.id()).expect("the relay is still running");
    let status = common::finish_bounded(child, PATIENCE).status;

    // The kernel counts in 10ms ticks on every configuration this runs on, so
    // an idle 1.5 seconds is a handful of them and a spinning one is ~150.
    assert!(
        ticks < 25,
        "the relay used {ticks} clock ticks over 1.5 idle seconds, which is a spin",
    );
    assert!(status.success(), "{status}");
}

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
    let output = run_with_input(rootfs, &["/bin/cat"], "marker-in-sandbox\n");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("marker-in-sandbox"), "{text}");
    assert!(output.status.success(), "{}\n{text}", output.status);
}

/// The command's exit status is the relay's, unchanged.
#[test]
fn the_commands_exit_status_passes_through() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let output = run_with_input(rootfs, &["/bin/sh", "-c", "exit 42"], "");
    assert_eq!(output.status.code(), Some(42), "{}", output.status);
}

/// `--timeout` is the poll deadline, and its expiry is exit 124 whatever the
/// command was doing.
#[test]
fn an_expired_timeout_exits_124() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let started = Instant::now();
    let output = common::run_bounded(
        Command::new(FCAGE)
            .args(["--rootfs", rootfs.to_str().unwrap(), "--terminal"])
            .args(["--timeout", "1", "--kill-after", "1"])
            .args(["--", "/bin/sleep", "60"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        PATIENCE,
    );
    assert_eq!(output.status.code(), Some(124), "{}", output.status);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the timeout did not end the session promptly",
    );
}

/// The same expiry against a command that never stops printing.
///
/// The silent case above leaves the relay asleep in a `poll` whose only wakeup
/// is the deadline, so it cannot tell an expiry the clock decided from one the
/// absence of traffic decided. A command flooding the pseudoterminal keeps the
/// primary readable, so every `poll` returns on a descriptor rather than on the
/// timeout — and a relay that acted on the deadline only when `poll` reported
/// nothing else would go on relaying instead of escalating.
#[test]
fn an_expired_timeout_exits_124_against_a_command_that_never_stops_printing() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let started = Instant::now();
    let output = common::run_bounded(
        Command::new(FCAGE)
            .args(["--rootfs", rootfs.to_str().unwrap(), "--terminal"])
            .args(["--timeout", "2", "--kill-after", "1"])
            // Three writers, so the relay is refilled while it drains.
            .args([
                "--",
                "/bin/sh",
                "-c",
                "yes flooding & yes flooding & yes flooding",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        PATIENCE,
    );
    assert_eq!(output.status.code(), Some(124), "{}", output.status);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the timeout did not end the session promptly",
    );
    assert!(
        !output.stdout.is_empty(),
        "the relay kept relaying while the deadline ran out",
    );
}

// -- The interactive shape ----------------------------------------------------

/// A typed line reaches the sandbox, its output comes back, and the caller's
/// terminal is restored byte for byte on the way out.
///
/// The restoration is the assertion that matters most: the relay puts the
/// caller's terminal into raw mode, and a relay that exits without undoing that
/// leaves the user's shell unusable. Compared field for field, because "looks
/// interactive again" is not the promise the module makes.
#[test]
fn a_session_relays_a_typed_line_and_restores_the_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut session = Session::start(rootfs, &["/bin/sh"], pty::winsize(24, 80));
    let before = session.settings();

    session.send("echo marker-from-inside\n");
    let seen = session.read_until("marker-from-inside", 2);
    assert!(seen.contains("marker-from-inside"), "{seen}");

    session.send("exit 7\n");
    let status = session.finish();
    assert_eq!(status.code(), Some(7), "{status}");

    let after = session.settings();
    pty::assert_restored(&before, &after);
}

/// The caller's window size is copied into the sandbox at launch, so a
/// full-screen program inside has the caller's dimensions from its first draw.
#[test]
fn the_callers_size_is_copied_into_the_sandbox() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let size = pty::winsize(30, 100);
    let mut session = Session::start(rootfs, &["/bin/sh", "-c", "stty size"], size);
    let seen = session.read_until("30 100", 2);
    let status = session.finish();
    assert!(seen.contains("30 100"), "{seen}");
    assert!(status.success(), "{status}");
}

/// A caller terminal that reports no size — zero in either dimension, which is
/// what an unsized pseudoterminal says — falls back to the stated default
/// rather than handing the sandbox a terminal that answers "no size".
#[test]
fn an_unsized_caller_terminal_falls_back_to_the_default() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut session = Session::start(
        rootfs,
        &["/bin/sh", "-c", "stty size"],
        // A pseudoterminal nobody has sized.
        pty::winsize(0, 0),
    );
    let seen = session.read_until("24 80", 2);
    let status = session.finish();
    assert!(seen.contains("24 80"), "{seen}");
    assert!(status.success(), "{status}");
}

/// Resizing the caller's terminal and signalling the relay resizes the
/// sandbox's, which is how a full-screen program inside learns to redraw.
#[test]
fn a_sigwinch_resizes_the_sandboxs_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut session = Session::start(rootfs, &["/bin/sh"], pty::winsize(30, 100));
    session.send("stty size\n");
    assert!(session.read_until("30 100", 2).contains("30 100"));

    session.resize(45, 132);
    session.signal(rustix::process::Signal::WINCH);
    // The relay reads the caller's size on the SIGWINCH and sets it on the
    // sandbox's terminal; asking again is what proves it landed.
    session.send("stty size\n");
    let seen = session.read_until("45 132", 2);
    session.send("exit 0\n");
    let status = session.finish();
    assert!(seen.contains("45 132"), "{seen}");
    assert!(status.success(), "{status}");
}

/// An interrupt from outside is forwarded as a terminate request rather than
/// acted on locally, and the relay still restores the caller's terminal on the
/// way out. A typed `^C` is a different thing entirely — in raw mode it is a
/// byte the sandbox's own line discipline acts on — which is why this test
/// signals the process rather than writing the character.
#[test]
fn an_external_interrupt_ends_the_session_and_restores_the_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A non-interactive shell running `sleep`, not an interactive one: an
    // interactive shell ignores SIGTERM, so the termination request the relay
    // forwards would leave it running and the session would never end. That is
    // what a *second* interrupt is for, and it is not what this test is about.
    let mut session = Session::start(
        rootfs,
        &["/bin/sh", "-c", "echo ready; sleep 30"],
        pty::winsize(24, 80),
    );
    let before = session.settings();
    // The marker comes from inside -- nothing is typed here, so the caller's
    // own line discipline cannot have echoed it -- which is what says the
    // sandbox is up and the signal cannot race the launch.
    assert!(session.read_until("ready", 5).contains("ready"));

    session.signal(rustix::process::Signal::INT);
    let status = session.finish();
    assert!(
        !status.success(),
        "an interrupted session should not report success: {status}",
    );
    pty::assert_restored(&before, &session.settings());
}

/// A stop restores the caller's terminal before the process stops, and a
/// continue re-enters raw mode from the settings the relay saved.
///
/// The branch whose failure is the worst of any here: a relay that stopped
/// without restoring would leave the shell that resumes with a terminal in raw
/// mode and nothing left running to fix it, and one that never re-entered would
/// hand the resumed session a cooked terminal the sandbox is not expecting.
///
/// Driven against the built binary because the relay stops the *process*: a
/// `SIGSTOP` stops every thread, so an in-process test would stop the test
/// harness alongside it with nothing left to continue either.
#[test]
fn a_stop_restores_the_terminal_and_a_continue_re_enters_raw_mode() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut session = Session::start(rootfs, &["/bin/sh"], pty::winsize(24, 80));
    let cooked = session.settings();
    session.await_sandbox("ready");
    assert!(
        pty::is_raw(&session.settings()),
        "the session's terminal is raw"
    );

    session.signal(rustix::process::Signal::TSTP);
    session.await_state('T');
    // Restored *before* the process stopped, which is the whole discipline: the
    // shell that gets the terminal back gets it as it left it.
    pty::assert_restored(&cooked, &session.settings());

    // Continued, and relaying again: the marker can only have come from inside
    // the sandbox, so seeing it says the loop is back in the poll. Signals are
    // handled ahead of the input in one pass of that loop, so the re-entry has
    // happened by the time the marker comes back.
    session.signal(rustix::process::Signal::CONT);
    session.await_sandbox("continued");
    assert!(
        pty::is_raw(&session.settings()),
        "the continued session re-enters raw mode",
    );

    session.send("exit 0\n");
    let status = session.finish();
    assert!(status.success(), "{status}");
    pty::assert_restored(&cooked, &session.settings());
}

/// Names the role this test binary plays when it runs itself as the shell of
/// [`a_session_in_the_background_leaves_the_input_to_its_shell`].
const BACKGROUND_SHELL: &str = "FERRODAY_CAGE_TEST_BACKGROUND_SHELL";

/// What the background session's command prints, through the relay, once it
/// runs.
const BACKGROUND_READY: &str = "background-session-ready";

/// A session in the background leaves the terminal's input to the shell in the
/// foreground, and relays again once `fg` brings it forward.
///
/// A read of the terminal from the background raises `SIGTTIN`, which stops the
/// session. The `fg` that continues it restarts that read before the relay sees
/// the continue, in a terminal still cooked and emptied of the line by the
/// shell, so the session would sit in the read with nothing relayed and a
/// `SIGTERM` unanswered.
///
/// Job control needs a shell, and a job whose shell is in its session: a read
/// from a process group with no parent in its session, the orphaned group a
/// session leader's job would be, gets `EIO` instead of the stop. So this test
/// binary runs itself as that shell, in a session of its own on a fresh
/// pseudoterminal, and starts `fcage` as a background job of its own; see
/// [`helper_shell_with_a_background_session`]. This test plays the user, and
/// types a line at the shell while the session is in the background.
#[test]
fn a_session_in_the_background_leaves_the_input_to_its_shell() {
    let Some(_) = common::fixture_rootfs() else {
        return;
    };
    let (primary, replica) = pty::pair(24, 80);
    let mut command = common::rerun("helper_shell_with_a_background_session");
    command.env(BACKGROUND_SHELL, "1");
    let mut child = pty::spawn_controlled(&mut command, &replica);
    // The test's own copy goes, so the helper's exit hangs the primary up.
    drop(replica);

    // The marker is the sandbox's, relayed from the background; nothing has
    // been typed that the terminal could have echoed instead.
    let mut seen = String::new();
    let ready = pty::read_until(
        &primary,
        BACKGROUND_READY,
        Instant::now() + Duration::from_secs(10),
        &mut seen,
    );
    if ready {
        pty::send(&primary, "typed at the shell\n");
    }

    // Drained throughout, so neither the helper's report nor the session's
    // output can fill the terminal and stall the helper.
    let deadline = Instant::now() + PATIENCE;
    let status = loop {
        if let Some(status) = child.try_wait().expect("the helper can be waited for") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the helper did not finish; the terminal showed:\n{seen}");
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
    assert!(
        ready,
        "the background session never ran; the terminal showed:\n{seen}"
    );
    assert!(
        status.success(),
        "the helper failed; the terminal showed:\n{seen}"
    );
}

/// Not a test of its own: when [`BACKGROUND_SHELL`] is set, this plays a shell
/// that starts `fcage --terminal` as a background job, reads a line typed while
/// the job is in the background, brings the job forward with `fg`, and then
/// ends it with a `SIGTERM`. Without the variable it does nothing.
///
/// Its process leads a session whose controlling terminal is its standard
/// input, and holds the terminal's foreground, as an interactive shell does.
/// The job is a process group of its own, started by this process, so a stop is
/// reported to this process as the job's parent, as a shell learns of one.
#[test]
fn helper_shell_with_a_background_session() {
    use std::os::unix::process::CommandExt as _;

    use rustix::process::{Pid, Signal, WaitOptions};

    if std::env::var_os(BACKGROUND_SHELL).is_none() {
        return;
    }
    let rootfs =
        common::fixture_rootfs().expect("the parent runs the helper only where sandboxes launch");
    let terminal = rustix::stdio::stdin();
    let mut job = Command::new(FCAGE)
        .args(["--rootfs", rootfs.to_str().unwrap(), "--terminal", "--"])
        .args([
            "/bin/sh",
            "-c",
            &format!("echo {BACKGROUND_READY}; exec sleep 60"),
        ])
        .process_group(0)
        .spawn()
        .expect("the job starts");
    let pid = Pid::from_raw(job.id() as i32).expect("a live pid");

    // The user types a line at the shell. In canonical mode a line counts as
    // queued once it is whole.
    let typed_by = Instant::now() + PATIENCE;
    while rustix::io::ioctl_fionread(terminal).expect("the terminal reports its queue") == 0 {
        assert!(Instant::now() < typed_by, "nothing was typed at the shell");
        std::thread::sleep(Duration::from_millis(20));
    }

    // The line waits in the terminal while the session is in the background. A
    // session that read it would stop on SIGTTIN. Asked of `waitpid` directly,
    // since the handle cannot report a stop, and a stop report reaps nothing.
    let mut stopped = false;
    let window = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < window {
        if let Some((_, status)) =
            rustix::process::waitpid(Some(pid), WaitOptions::UNTRACED | WaitOptions::NOHANG)
                .expect("the job can be waited for")
        {
            assert!(
                status.stopped(),
                "the session ended in the background: {status:?}"
            );
            stopped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // The shell reads its line, then `fg`: the foreground moves to the job's
    // group, then the continue.
    let mut line = [0u8; 64];
    let read = rustix::io::read(terminal, &mut line).expect("the shell reads its line");
    termios::tcsetpgrp(terminal, pid).expect("the job's group takes the foreground");
    rustix::process::kill_process(pid, Signal::CONT).expect("the job is continued");
    let raw_by = Instant::now() + Duration::from_secs(5);
    let mut raw = false;
    while !raw && Instant::now() < raw_by {
        raw = termios::tcgetattr(terminal).is_ok_and(|settings| pty::is_raw(&settings));
        std::thread::sleep(Duration::from_millis(20));
    }

    // An interrupt from outside ends the session.
    rustix::process::kill_process(pid, Signal::TERM).expect("the job is signalled");
    let end_by = Instant::now() + Duration::from_secs(10);
    let mut ended = job.try_wait().expect("the job can be waited for");
    while ended.is_none() && Instant::now() < end_by {
        std::thread::sleep(Duration::from_millis(20));
        ended = job.try_wait().expect("the job can be waited for");
    }
    if ended.is_none() {
        let _ = job.kill();
        let _ = job.wait();
    }

    assert!(
        !stopped,
        "the session read the terminal from the background and stopped on SIGTTIN",
    );
    assert_eq!(
        &line[..read],
        b"typed at the shell\n",
        "the shell read the line typed at it",
    );
    assert!(
        raw,
        "brought to the foreground, the session never entered raw mode"
    );
    assert!(
        ended.is_some(),
        "the session did not end on the termination request"
    );
}

// -- Helpers ------------------------------------------------------------------

/// Runs `fcage --terminal` over a pipe carrying `input`, and collects the
/// result. The pipe is closed after the write, which retires the relay's
/// standard-input channel.
///
/// A session that outlasts the patience is killed and the test fails, rather
/// than hanging the run: libtest has no per-test deadline of its own, and a
/// relay that never finishes is exactly the failure these tests exist to catch.
fn run_with_input(rootfs: &Path, command: &[&str], input: &str) -> std::process::Output {
    let mut child = common::spawn_grouped(
        Command::new(FCAGE)
            .args(["--rootfs", rootfs.to_str().unwrap(), "--terminal", "--"])
            .args(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    {
        let mut stdin = child.stdin.take().expect("the pipe is there");
        stdin.write_all(input.as_bytes()).expect("the write lands");
    }
    common::finish_bounded(child, PATIENCE)
}

/// A driven `fcage --terminal` session: a pseudoterminal of the test's own,
/// with `fcage` in a session of its own on the replica.
///
/// This is what makes `fcage`'s standard input a terminal, which is the
/// condition for raw mode, the size copy, and the restoration. The test holds
/// the primary and plays the user.
struct Session {
    /// The primary. Reads what the session wrote; writes what it reads as typed
    /// input. Also the handle for the size and for the replica's termios, both
    /// of which the kernel redirects to the replica.
    primary: OwnedFd,
    /// The running `fcage`.
    child: std::process::Child,
    /// Everything read from the primary so far, for the assertions to search.
    seen: String,
}

impl Session {
    /// Starts `fcage --terminal` on a fresh pseudoterminal sized `size`, in a
    /// session of its own with the replica as its controlling terminal.
    fn start(rootfs: &Path, command: &[&str], size: Winsize) -> Session {
        let (primary, replica) = pty::pair(size.ws_row, size.ws_col);
        let mut command_line = Command::new(FCAGE);
        command_line
            .args(["--rootfs", rootfs.to_str().unwrap(), "--terminal", "--"])
            .args(command);
        let child = pty::spawn_controlled(&mut command_line, &replica);
        // The test's own copy goes, so end of file on the primary means the
        // session is over rather than that this handle is still open.
        drop(replica);

        Session {
            primary,
            child,
            seen: String::new(),
        }
    }

    /// The replica's current termios, which is what the relay puts into raw
    /// mode and restores. Linux redirects a termios query on the primary to the
    /// replica, so this reads the settings `fcage` itself sees on descriptor 0.
    fn settings(&self) -> termios::Termios {
        termios::tcgetattr(&self.primary).expect("the settings are readable")
    }

    /// Types `text` at the session.
    fn send(&mut self, text: &str) {
        pty::send(&self.primary, text);
    }

    /// Resizes the caller's terminal. Does not itself signal the relay.
    fn resize(&self, rows: u16, cols: u16) {
        termios::tcsetwinsize(&self.primary, pty::winsize(rows, cols))
            .expect("the size is settable");
    }

    /// Sends `signal` to the relay.
    fn signal(&self, signal: rustix::process::Signal) {
        let pid = rustix::process::Pid::from_raw(self.child.id() as i32).expect("a live pid");
        rustix::process::kill_process(pid, signal).expect("the signal is deliverable");
    }

    /// Reads from the primary until `needle` appears or `seconds` elapse, and
    /// returns everything read so far.
    ///
    /// Everything is accumulated rather than searched per read, because the
    /// session's echo and the command's output arrive interleaved and in
    /// whatever chunks the line discipline chose.
    fn read_until(&mut self, needle: &str, seconds: u64) -> String {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        pty::read_until(&self.primary, needle, deadline, &mut self.seen);
        self.seen.clone()
    }

    /// Types a command whose output the caller's own line discipline cannot
    /// have produced, and waits for that output.
    ///
    /// The distinction matters for every assertion about raw mode. A cooked
    /// caller terminal echoes what is typed at it, so a marker typed literally
    /// comes back whether or not the session is relaying — and a test that
    /// waited for one would be reading its own echo and asserting against a
    /// relay that had not started yet. The shell inside is the only thing that
    /// can do the arithmetic.
    fn await_sandbox(&mut self, marker: &str) {
        self.send(&format!("echo {marker}-$((20 + 2))\n"));
        let wanted = format!("{marker}-22");
        let seen = self.read_until(&wanted, 5);
        assert!(
            seen.contains(&wanted),
            "the sandbox never printed {wanted:?}: {seen}"
        );
    }

    /// Waits until the relay's process reaches `state` -- `T` stopped, `S`
    /// sleeping -- failing the test if it does not.
    ///
    /// Read from `/proc/<pid>/stat` rather than waited for with `WUNTRACED`,
    /// because this test is not the child's parent for signal purposes and a
    /// stop it consumed would be a stop the harness could not then continue
    /// from.
    fn await_state(&mut self, state: char) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if common::process_state(self.child.id()) == Some(state) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "the relay never reached state {state}; it is in {:?}",
            common::process_state(self.child.id()),
        );
    }

    /// Reads whatever the primary has ready, waiting no later than `deadline`.
    ///
    /// Returns whether the session is still producing: `false` at end of file,
    /// at the hangup a pseudoterminal primary reports as `EIO`, or once the
    /// deadline has passed. Polled rather than read outright, so a deadline is
    /// a deadline — a blocking read on a quiet session would ignore it and hang
    /// the whole run.
    fn drain(&mut self, deadline: Instant) -> bool {
        pty::drain_until(&self.primary, deadline, &mut self.seen)
    }

    /// Waits for the session to end and returns its status, failing the test if
    /// it outlasts the patience.
    ///
    /// Keeps draining while it waits, so a session that fills the
    /// pseudoterminal's buffer is not blocked by this test's failure to read it.
    fn finish(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + PATIENCE;
        loop {
            if let Some(status) = self.child.try_wait().expect("the child is waitable") {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("the session did not end within {PATIENCE:?}");
            }
            if !self.drain(Instant::now() + Duration::from_millis(50)) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // A test that failed mid-session must not leave a sandbox behind.
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
