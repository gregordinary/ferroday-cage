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
//! to reach raw mode, the size copy, `SIGWINCH`, and the restoration.
//!
//! Every test skips explicitly, on stderr, on a host that cannot create
//! unprivileged user namespaces; `FERRODAY_CAGE_REQUIRE_USERNS` turns each skip
//! into a failure so a runner can assert they really ran.

#![allow(unsafe_code)]

mod common;

use std::io::Write as _;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustix::termios::{self, SpecialCodeIndex, Winsize};

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
    let mut child = Command::new(FCAGE)
        .args(["--rootfs", rootfs.to_str().unwrap(), "--terminal"])
        .args(["--", "/bin/sleep", "3"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("fcage starts");
    // Closing the write end hangs the pipe up, which is the trigger.
    drop(child.stdin.take());

    std::thread::sleep(Duration::from_millis(1500));
    let ticks = cpu_ticks(child.id()).expect("the relay is still running");
    let status = child.wait().expect("the relay exits");

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
    let output = Command::new(FCAGE)
        .args(["--rootfs", rootfs.to_str().unwrap(), "--terminal"])
        .args(["--timeout", "1", "--kill-after", "1"])
        .args(["--", "/bin/sleep", "60"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("fcage runs");
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
    let output = Command::new(FCAGE)
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
        .stderr(Stdio::piped())
        .output()
        .expect("fcage runs");
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
    let mut session = Session::start(rootfs, &["/bin/sh"], winsize(24, 80));
    let before = session.settings();

    session.send("echo marker-from-inside\n");
    let seen = session.read_until("marker-from-inside", 2);
    assert!(seen.contains("marker-from-inside"), "{seen}");

    session.send("exit 7\n");
    let status = session.finish();
    assert_eq!(status.code(), Some(7), "{status}");

    let after = session.settings();
    assert_termios_eq(&before, &after);
}

/// The caller's window size is copied into the sandbox at launch, so a
/// full-screen program inside has the caller's dimensions from its first draw.
#[test]
fn the_callers_size_is_copied_into_the_sandbox() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let size = winsize(30, 100);
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
        winsize(0, 0),
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
    let mut session = Session::start(rootfs, &["/bin/sh"], winsize(30, 100));
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
        winsize(24, 80),
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
    assert_termios_eq(&before, &session.settings());
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
    let mut session = Session::start(rootfs, &["/bin/sh"], winsize(24, 80));
    let cooked = session.settings();
    session.await_sandbox("ready");
    assert!(is_raw(&session.settings()), "the session's terminal is raw");

    session.signal(rustix::process::Signal::TSTP);
    session.await_state(b'T');
    // Restored *before* the process stopped, which is the whole discipline: the
    // shell that gets the terminal back gets it as it left it.
    assert_termios_eq(&cooked, &session.settings());

    // Continued, and relaying again: the marker can only have come from inside
    // the sandbox, so seeing it says the loop is back in the poll. Signals are
    // handled ahead of the input in one pass of that loop, so the re-entry has
    // happened by the time the marker comes back.
    session.signal(rustix::process::Signal::CONT);
    session.await_sandbox("continued");
    assert!(
        is_raw(&session.settings()),
        "the continued session re-enters raw mode",
    );

    session.send("exit 0\n");
    let status = session.finish();
    assert!(status.success(), "{status}");
    assert_termios_eq(&cooked, &session.settings());
}

/// A caller started with its standard input closed relays the session's output
/// and ends on the command's own terms.
///
/// `fcage --terminal ... 0<&-` is the shape: descriptor 0 names no open file
/// description at all, so `poll` answers `POLLNVAL` and a read answers `EBADF`.
/// Both take the retiring path end-of-input takes -- there is nothing to relay
/// and never will be -- and the caller-bound direction carries on alone. A loop
/// that treated `POLLNVAL` as nothing to act on would spin on a slot that is
/// ready forever.
#[test]
fn a_caller_with_no_standard_input_at_all_still_relays() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // `sh -c` with the descriptor closed by the shell, since `Command` has no
    // way to spawn a child with a descriptor absent rather than redirected.
    let script = format!(
        "exec {} --rootfs {} --terminal -- /bin/sh -c 'echo marker-from-inside; exit 3' 0<&-",
        shell_quote(FCAGE),
        shell_quote(rootfs.to_str().expect("a UTF-8 rootfs path")),
    );
    let started = Instant::now();
    let output = Command::new("/bin/sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("fcage starts");
    let seen = String::from_utf8_lossy(&output.stdout);
    assert!(
        seen.contains("marker-from-inside"),
        "{seen}{}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    // A spin would still have produced the right answer; that it produced one
    // promptly is what says the closed slot was retired rather than polled.
    assert!(started.elapsed() < PATIENCE, "{:?}", started.elapsed());
}

// -- Helpers ------------------------------------------------------------------

/// Quotes `text` for a single-quoted shell word.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Runs `fcage --terminal` over a pipe carrying `input`, and collects the
/// result. The pipe is closed after the write, which retires the relay's
/// standard-input channel.
///
/// A session that outlasts the patience is killed and the test fails, rather
/// than hanging the run: libtest has no per-test deadline of its own, and a
/// relay that never finishes is exactly the failure these tests exist to catch.
fn run_with_input(rootfs: &Path, command: &[&str], input: &str) -> std::process::Output {
    let mut child = Command::new(FCAGE)
        .args(["--rootfs", rootfs.to_str().unwrap(), "--terminal", "--"])
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("fcage starts");
    {
        let mut stdin = child.stdin.take().expect("the pipe is there");
        stdin.write_all(input.as_bytes()).expect("the write lands");
    }
    let deadline = Instant::now() + PATIENCE;
    let mut overran = false;
    while child.try_wait().expect("the child is waitable").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            overran = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().expect("fcage finishes");
    assert!(!overran, "the session did not end within {PATIENCE:?}");
    output
}

/// The process's own CPU time in clock ticks: `utime + stime` from
/// `/proc/<pid>/stat`. `None` once the process is gone.
///
/// The two fields sit after the command name, which is parenthesized and may
/// itself contain spaces and parentheses, so the split starts after the last
/// `)` rather than at the second field.
fn cpu_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // `rest` starts at the state field, which is field 3 of the record, so
    // utime (14) and stime (15) are indices 11 and 12 here.
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
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

/// Asserts two termios records are identical field for field.
fn assert_termios_eq(before: &termios::Termios, after: &termios::Termios) {
    assert_eq!(
        before.input_modes, after.input_modes,
        "the input modes were not restored",
    );
    assert_eq!(
        before.output_modes, after.output_modes,
        "the output modes were not restored",
    );
    assert_eq!(
        before.control_modes, after.control_modes,
        "the control modes were not restored",
    );
    assert_eq!(
        before.local_modes, after.local_modes,
        "the local modes were not restored",
    );
    // `SpecialCodes` carries no equality of its own, so the characters raw mode
    // changes are compared one by one. `make_raw` clears VMIN/VTIME and leaves
    // the rest, so a restoration that missed any of these would show here.
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
            before.special_codes[index], after.special_codes[index],
            "{name} was not restored",
        );
    }
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
    /// Starts `fcage --terminal` on a fresh pseudoterminal sized `size`.
    fn start(rootfs: &Path, command: &[&str], size: Winsize) -> Session {
        use std::os::unix::process::CommandExt as _;

        let primary =
            rustix::pty::openpt(rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY)
                .expect("a pseudoterminal is available");
        rustix::pty::unlockpt(&primary).expect("the replica unlocks");
        // Sized before the fork, so the size the relay copies is this one and
        // there is no race with the launch.
        termios::tcsetwinsize(&primary, size).expect("the size is settable");
        let replica = rustix::pty::ioctl_tiocgptpeer(
            &primary,
            rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY,
        )
        .expect("the replica opens");

        let mut command_line = Command::new(FCAGE);
        command_line
            .args(["--rootfs", rootfs.to_str().unwrap(), "--terminal", "--"])
            .args(command)
            .stdin(Stdio::from(
                replica.try_clone().expect("the replica clones"),
            ))
            .stdout(Stdio::from(
                replica.try_clone().expect("the replica clones"),
            ))
            .stderr(Stdio::from(
                replica.try_clone().expect("the replica clones"),
            ));
        // SAFETY: between fork and exec the child calls only `setsid` and one
        // ioctl, both async-signal-safe, and allocates nothing. A session of
        // its own is what makes the replica the child's controlling terminal,
        // which is what `fcage` needs its standard input to be.
        unsafe {
            command_line.pre_exec(|| {
                rustix::process::setsid()?;
                set_controlling_terminal(rustix::stdio::stdin())?;
                Ok(())
            });
        }
        let child = command_line.spawn().expect("fcage starts");
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
        let mut written = 0;
        while written < text.len() {
            written += rustix::io::write(&self.primary, &text.as_bytes()[written..])
                .expect("the write lands");
        }
    }

    /// Resizes the caller's terminal. Does not itself signal the relay.
    fn resize(&self, rows: u16, cols: u16) {
        termios::tcsetwinsize(&self.primary, winsize(rows, cols)).expect("the size is settable");
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
        while Instant::now() < deadline {
            if self.seen.contains(needle) {
                break;
            }
            if !self.drain(deadline) {
                break;
            }
        }
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
    /// from. The field is the third, after the comm in parentheses, which is
    /// the only field that can itself contain one.
    fn await_state(&mut self, state: u8) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if process_state(self.child.id()) == Some(state) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "the relay never reached state {}; it is in {:?}",
            state as char,
            process_state(self.child.id()).map(|held| held as char),
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
        common::drain_until(&self.primary, deadline, &mut self.seen)
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

/// Whether `settings` describe a terminal in raw mode.
///
/// Canonical input and echo are the two `make_raw` clears that a user would
/// notice immediately, and the two the relay's whole reason for entering raw
/// mode rests on.
fn is_raw(settings: &termios::Termios) -> bool {
    !settings
        .local_modes
        .intersects(termios::LocalModes::ICANON | termios::LocalModes::ECHO)
}

/// The process state `pid` is in, from `/proc/<pid>/stat`.
///
/// The third field, and the parse starts after the last `)` because the second
/// is the executable name in parentheses and is the one field that can contain
/// one.
fn process_state(pid: u32) -> Option<u8> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 1..];
    after_comm.split_whitespace().next()?.bytes().next()
}

/// `TIOCSCTTY`: make the terminal on `fd` this session's controlling terminal.
const TIOCSCTTY: rustix::ioctl::Opcode = 0x540E;

/// Makes `fd`'s terminal the calling session's controlling terminal.
///
/// Called between fork and exec, where rustix's own wrapper is not available:
/// the ioctl takes an integer argument rather than a struct, and zero is the
/// "do not steal it from another session" form, which is the only one wanted
/// here.
fn set_controlling_terminal(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    // SAFETY: TIOCSCTTY takes its argument by value rather than by pointer, so
    // there is no buffer for the kernel to read or write. `NoArg` states
    // exactly that.
    let request = unsafe { rustix::ioctl::NoArg::<TIOCSCTTY>::new() };
    // SAFETY: the descriptor is this process's standard input, which the
    // spawn wired to the pseudoterminal replica.
    unsafe { rustix::ioctl::ioctl(fd.as_fd(), request) }.map_err(std::io::Error::from)
}
