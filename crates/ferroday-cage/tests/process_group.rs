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
/// `suspend-subreaper`, `inner-job`, `pipeline`, or `pipe`.
const SCENARIO: &str = "FERRODAY_CAGE_TEST_GROUP_SCENARIO";

/// The command every scenario runs: it signals its own process group, which
/// it ignores the signals of, and on a terminal says it is ready and sleeps
/// until the user interrupts it.
///
/// In `inner-job` the command is a shell with job control, which runs the sleep
/// as a job of its own: in a process group of its own, which it gives the
/// terminal's foreground.
///
/// In `pipeline` the command's output is a pipe, so it says it has signalled
/// its group on standard error, which is still the terminal.
fn script(scenario: &str) -> &'static str {
    match scenario {
        "pipe" => "trap '' USR1 TERM; kill -USR1 0; kill -TERM 0",
        "pipeline" => {
            "trap '' USR1 TERM; kill -USR1 0; kill -TERM 0; echo signalled >&2; exec sleep 30"
        }
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

/// The reader at a pipeline's far end, in `pipeline`: it reads the caller's
/// output until the caller says the sandbox is running, then reads a line typed
/// at the terminal, says what it read, and passes the rest of the caller's
/// output through.
const READER: &str = "while IFS= read -r line; do [ \"$line\" = launched ] && break; done; \
     echo sibling-reading; IFS= read -r typed </dev/tty; echo \"sibling-read=$typed\"; exec cat";

/// The shell: starts the caller in a process group of its own, gives that
/// group the terminal's foreground, and reports how the caller ended, a stop
/// included. In `pipeline` the caller's output is piped to [`READER`], which
/// the shell starts in the caller's group, as a shell starts a pipeline's
/// members in one job.
#[test]
fn helper_shell() {
    use std::os::unix::process::CommandExt as _;

    let Some(scenario) = playing("shell") else {
        return;
    };
    let pipeline = scenario == "pipeline";
    let mut caller = rerun("helper_caller", "caller", &scenario);
    caller.process_group(0);
    if pipeline {
        caller.stdout(HostStdio::piped());
    }
    // Collected below through `waitpid`, which reports a stop as well as an
    // exit, where `Child::wait` reports exits alone.
    #[expect(clippy::zombie_processes)]
    let mut caller = caller.spawn().expect("the caller starts");
    let pid = Pid::from_raw(i32::try_from(caller.id()).expect("a pid fits"))
        .expect("a child's pid is positive");
    println!("shell-caller-group={}", caller.id());
    let reader = caller.stdout.take().map(|output| {
        Command::new("/bin/sh")
            .args(["-c", READER])
            .stdin(output)
            .process_group(pid.as_raw_nonzero().get())
            .spawn()
            .expect("the reader starts")
    });
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
    if let Some(mut reader) = reader {
        let _ = reader.wait();
    }
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
    let mut running = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script(&scenario)])
        .stop_with_caller(true)
        .build()
        .expect("a valid sandbox configuration")
        .spawn()
        .expect("the sandbox launches");
    // Whether the launch kept the terminal's foreground with the caller, read
    // once the command runs; the reader of a pipeline waits for the word.
    // One write, so the command's own output cannot land inside the line.
    let launched = format!(
        "caller-launched foreground={}\n",
        terminal && in_foreground()
    );
    std::io::Write::write_all(&mut std::io::stderr(), launched.as_bytes())
        .expect("the line is written");
    println!("launched");
    let status = running.wait().expect("the outcome is collected");
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

/// One step of playing the user at a session.
enum Step<'a> {
    /// Wait for the session to write this.
    Expect(&'a str),
    /// Type this, and pause.
    Type(&'a str),
}

/// Runs `scenario` under a pseudoterminal, taking `steps` in order, and
/// returns everything the session wrote, its reports included, once every
/// process in it has ended.
fn session(scenario: &str, steps: &[Step<'_>]) -> String {
    let (primary, replica) = common::pty::pair(24, 80);
    let shell =
        common::pty::spawn_controlled(&mut rerun("helper_shell", "shell", scenario), &replica);
    drop(replica);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut seen = String::new();
    let mut ran = true;
    for step in steps {
        ran = match step {
            Step::Expect(text) => common::pty::read_until(&primary, text, deadline, &mut seen),
            Step::Type(keys) => {
                common::pty::send(&primary, keys);
                std::thread::sleep(Duration::from_millis(300));
                true
            }
        };
        if !ran {
            break;
        }
    }
    let reported = ran && common::pty::read_until(&primary, "shell-report", deadline, &mut seen);
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

/// Asserts the session's reports: the sandbox held the foreground while it
/// ran, the command ended by `^C`, the caller and its sibling survived what
/// the command sent its group, and the caller's group holds the foreground
/// again.
fn assert_contained(seen: &str) {
    assert!(seen.contains("caller-launched foreground=false"), "{seen}");
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
    assert_contained(&session(
        "interrupt",
        &[Step::Expect("ready"), Step::Type("\x03")],
    ));
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
    assert_contained(&session(
        "suspend",
        &[
            Step::Expect("ready"),
            Step::Type("\x1a"),
            Step::Type("\x03"),
        ],
    ));
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
    assert_contained(&session(
        "suspend-subreaper",
        &[
            Step::Expect("ready"),
            Step::Type("\x1a"),
            Step::Type("\x03"),
        ],
    ));
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
    let seen = session("inner-job", &[Step::Expect("ready"), Step::Type("\x03")]);
    assert!(seen.contains("caller-launched foreground=false"), "{seen}");
    assert!(
        seen.contains("caller-report code=None signal=Some(2) sibling-alive=true foreground=true"),
        "{seen}"
    );
    assert!(seen.contains("shell-report caller=exited(0)"), "{seen}");
}

#[test]
fn a_pipelines_far_end_keeps_the_terminal_while_the_sandbox_runs() {
    if common::fixture_rootfs().is_none() {
        return;
    }
    // The caller's output is a pipe into a reader in the caller's own job, as
    // in `fcage -- cmd | less`. The caller lends nothing, so its job keeps the
    // terminal: the reader's read of it succeeds while the sandbox runs, where
    // a background read would stop it. The sandbox still has its own process
    // group, and what the command sends its group reaches neither the caller
    // nor the reader. The `^C` reaches the caller's job, which it ends, and
    // the sandbox ends with the caller it is tied to.
    let seen = session(
        "pipeline",
        &[
            Step::Expect("signalled"),
            Step::Expect("sibling-reading"),
            Step::Type("typed-line\n"),
            Step::Expect("sibling-read=typed-line"),
            Step::Type("\x03"),
        ],
    );
    assert!(seen.contains("caller-launched foreground=true"), "{seen}");
    assert!(seen.contains("shell-report caller=signaled(2)"), "{seen}");
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
