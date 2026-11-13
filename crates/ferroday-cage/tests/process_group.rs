//! Integration tests for the process group a sandbox that keeps the caller's
//! session runs in, and the caller's terminal it borrows.
//!
//! A signal sent to a process group reaches every member of it, and a sandbox
//! left in the caller's group could signal the caller and everything beside
//! it. These tests launch from a caller that stands where a shell's foreground
//! job stands: in a pseudoterminal's session, in a process group of its own
//! that holds the terminal's foreground, with a sibling in that group. The
//! caller is this test binary, run again; so is the shell that starts it, the
//! session's leader, which hands it the foreground as a shell does and reports
//! how it ended. The test plays the user at the pseudoterminal.
//!
//! Each command signals its own process group with `USR1` and `TERM`,
//! ignoring both itself. A signal that reached the caller's group would end
//! the caller and the sibling, whose dispositions are the defaults.

mod common;

use std::process::{Command, Stdio as HostStdio};
use std::time::{Duration, Instant};

use ferroday_cage::Cage;
use rustix::process::{Pid, WaitOptions};

/// Which part this test binary plays, when it is run again: `shell` or
/// `caller`.
const ROLE: &str = "FERRODAY_CAGE_TEST_GROUP_ROLE";

/// What the caller launches and how it stands: `interrupt`, `suspend`,
/// `suspend-subreaper`, `inner-job`, or `pipe`.
const SCENARIO: &str = "FERRODAY_CAGE_TEST_GROUP_SCENARIO";

/// The command every scenario runs: it signals its own process group, which
/// it ignores the signals of, and on a terminal says it is ready and sleeps
/// until the user interrupts it.
///
/// In `inner-job` the command is a shell with job control, which runs the sleep
/// as a job of its own: in a process group of its own, which it gives the
/// terminal's foreground.
fn script(scenario: &str) -> &'static str {
    match scenario {
        "pipe" => "trap '' USR1 TERM; kill -USR1 0; kill -TERM 0",
        "inner-job" => {
            "trap '' USR1 TERM; kill -USR1 0; kill -TERM 0; set -m; echo ready; sleep 30; exit 0"
        }
        _ => "trap '' USR1 TERM; kill -USR1 0; kill -TERM 0; echo ready; exec sleep 30",
    }
}

/// A command line running this test binary's `test` alone, in `role`.
fn rerun(test: &str, role: &str, scenario: &str) -> Command {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let mut command = Command::new(exe);
    command
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(ROLE, role)
        .env(SCENARIO, scenario);
    command
}

/// This run's scenario, when it is a run of `role`.
fn playing(role: &str) -> Option<String> {
    if std::env::var(ROLE).ok()? != role {
        return None;
    }
    // The harness has printed `test <name> ... ` without ending the line.
    println!();
    std::env::var(SCENARIO).ok()
}

/// The shell: starts the caller in a process group of its own, gives that
/// group the terminal's foreground, and reports how the caller ended, a stop
/// included.
#[test]
fn helper_shell() {
    let Some(scenario) = playing("shell") else {
        return;
    };
    let caller = {
        use std::os::unix::process::CommandExt as _;
        rerun("helper_caller", "caller", &scenario)
            .process_group(0)
            .spawn()
            .expect("the caller starts")
    };
    let pid = Pid::from_raw(i32::try_from(caller.id()).expect("a pid fits"))
        .expect("a child's pid is positive");
    println!("shell-caller-group={}", caller.id());
    // The shell's group holds the foreground, so handing it on raises nothing.
    rustix::termios::tcsetpgrp(rustix::stdio::stdin(), pid)
        .expect("the caller's group takes the foreground");
    let (_, status) = rustix::process::waitpid(Some(pid), WaitOptions::UNTRACED)
        .expect("the caller is waited for")
        .expect("the caller reports a status");
    let ended = if let Some(code) = status.exit_status() {
        format!("exited({code})")
    } else if let Some(signal) = status.terminating_signal() {
        format!("signaled({signal})")
    } else {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        let _ = rustix::process::waitpid(Some(pid), WaitOptions::empty());
        format!("stopped({:?})", status.stopping_signal())
    };
    println!("shell-report caller={ended}");
}

/// The caller: waits until its group holds the terminal's foreground, starts
/// a sibling in its own group, runs the scenario's sandbox with the caller's
/// standard input, and reports the outcome, whether the sibling survived, and
/// whether the foreground came back.
#[test]
fn helper_caller() {
    let Some(scenario) = playing("caller") else {
        return;
    };
    let rootfs = common::fixture_rootfs().expect("the fixture root is provisioned");
    let terminal = scenario != "pipe";
    if terminal {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !in_foreground() {
            assert!(
                Instant::now() < deadline,
                "the shell never gave the caller the foreground"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if scenario == "suspend-subreaper" {
        // The launch stage's children reparent here once it exits: a reaper
        // in the session, so the sandbox's group is not orphaned.
        rustix::process::set_child_subreaper(Some(rustix::process::getpid()))
            .expect("the caller becomes a subreaper");
    }
    let mut sibling = Command::new("sleep")
        .arg("60")
        .stdin(HostStdio::null())
        .stdout(HostStdio::null())
        .stderr(HostStdio::null())
        .spawn()
        .expect("the sibling starts");
    // Tied to the caller, so a run that fails and ends the caller does not
    // leave the sandbox behind.
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script(&scenario)])
        .stop_with_caller(true)
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    let sibling_alive = sibling
        .try_wait()
        .expect("the sibling is waited for")
        .is_none();
    let foreground = !terminal || in_foreground();
    let _ = sibling.kill();
    let _ = sibling.wait();
    println!(
        "caller-report code={:?} signal={:?} sibling-alive={sibling_alive} foreground={foreground}",
        status.code(),
        status.signal(),
    );
}

/// Whether this process's group holds its terminal's foreground.
fn in_foreground() -> bool {
    rustix::termios::tcgetpgrp(rustix::stdio::stdin()) == Ok(rustix::process::getpgrp())
}

/// Runs `scenario` under a pseudoterminal: waits for the command to be ready,
/// types each of `keys` with a pause after it, and returns everything the
/// session wrote, its reports included, once every process in it has ended.
fn session(scenario: &str, keys: &[&str]) -> String {
    let (primary, replica) = common::pty::pair(24, 80);
    let shell =
        common::pty::spawn_controlled(&mut rerun("helper_shell", "shell", scenario), &replica);
    drop(replica);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut seen = String::new();
    let ready = common::pty::read_until(&primary, "ready", deadline, &mut seen);
    if ready {
        for key in keys {
            common::pty::send(&primary, key);
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    let reported = ready && common::pty::read_until(&primary, "shell-report", deadline, &mut seen);
    if !reported {
        end_caller(&seen);
    }
    // The shell leads a process group of its own, as a session leader does.
    let ended = common::finish_bounded(shell, Duration::from_secs(30));
    // The rest of the report lines: the session hangs up once the last process
    // holding its terminal has ended.
    while common::pty::drain_until(&primary, Instant::now() + Duration::from_secs(5), &mut seen) {}
    assert!(reported, "the session did not run to its report:\n{seen}");
    assert!(ended.status.success(), "the shell failed:\n{seen}");
    seen
}

/// Ends the caller's process group, which the shell named in `seen`, for a run
/// that is failing with the caller still running.
fn end_caller(seen: &str) {
    let group = seen
        .split("shell-caller-group=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|pid| pid.parse().ok())
        .and_then(Pid::from_raw);
    if let Some(group) = group {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    }
}

/// Asserts the session's reports: the command ended by `^C`, the caller and
/// its sibling survived what the command sent its group, and the caller's
/// group holds the foreground again.
fn assert_contained(seen: &str) {
    assert!(
        seen.contains("caller-report code=None signal=Some(2) sibling-alive=true foreground=true"),
        "{seen}"
    );
    assert!(seen.contains("shell-report caller=exited(0)"), "{seen}");
}

#[test]
fn a_command_on_the_callers_terminal_signals_only_its_own_group() {
    if common::fixture_rootfs().is_none() {
        return;
    }
    // The command signals its group; the caller and its sibling survive. A
    // `^C` typed at the terminal still reaches the command, whose group holds
    // the foreground, and the caller has it back once the wait returns.
    assert_contained(&session("interrupt", &["\x03"]));
}

#[test]
fn a_suspend_typed_at_the_terminal_leaves_the_command_running() {
    if common::fixture_rootfs().is_none() {
        return;
    }
    // Once the launch stage exits, the sandbox's group has no member whose
    // parent is in another group of the session, and the kernel discards the
    // terminal's stop signals for it. The `^C` after the `^Z` ends a command
    // that is still running.
    assert_contained(&session("suspend", &["\x1a", "\x03"]));
}

#[test]
fn a_suspend_under_a_reaper_in_the_session_is_continued() {
    if common::fixture_rootfs().is_none() {
        return;
    }
    // A subreaper in the caller's session becomes the init's parent, so the
    // sandbox's group is not orphaned and `^Z` stops the command. The init
    // continues it, and the `^C` after it ends the command rather than
    // waiting on a stopped one.
    assert_contained(&session("suspend-subreaper", &["\x1a", "\x03"]));
}

#[test]
fn the_terminal_comes_back_from_a_job_a_shell_inside_ran() {
    if common::fixture_rootfs().is_none() {
        return;
    }
    // A shell with job control inside the sandbox gives a job of its own the
    // terminal, and the `^C` reaches that job; busybox's shell then ends itself
    // with the job's signal. The terminal is left on the job's group, which is
    // gone by the time the wait returns, and the caller takes it back from
    // there too.
    let seen = session("inner-job", &["\x03"]);
    assert!(
        seen.contains("caller-report code=None signal=Some(2) sibling-alive=true foreground=true"),
        "{seen}"
    );
    assert!(seen.contains("shell-report caller=exited(0)"), "{seen}");
}

#[test]
fn a_command_whose_input_is_a_pipe_signals_only_its_own_group() {
    if common::fixture_rootfs().is_none() {
        return;
    }
    // Standard input inherited from the caller keeps the caller's session
    // whether it is a terminal or not, and the sandbox's own process group
    // keeps the caller's out of reach either way.
    let output = common::finish_bounded(
        common::spawn_grouped(
            rerun("helper_caller", "caller", "pipe")
                .stdin(HostStdio::piped())
                .stdout(HostStdio::piped())
                .stderr(HostStdio::piped()),
        ),
        Duration::from_secs(60),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the caller did not survive: {:?}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        stdout
            .contains("caller-report code=Some(0) signal=None sibling-alive=true foreground=true"),
        "{stdout}"
    );
}
