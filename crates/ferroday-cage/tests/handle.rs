//! Integration tests for the running-sandbox handle: deadlines, kill,
//! terminate, cross-thread signaling, and the stop-with-caller tie.

mod common;

use common::{Collect, process_exists, wait_gone};

use std::path::Path;
use std::time::{Duration, Instant};

use ferroday_cage::{Cage, Stdio};

/// Builds a cage running `/bin/sh -c <script>` in the fixture rootfs.
fn sh(rootfs: &Path, script: &str) -> Cage {
    Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
}

#[test]
fn a_deadline_expires_and_a_kill_ends_the_sandbox() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut running = sh(rootfs, "sleep 30")
        .spawn()
        .expect("the sandbox launches");
    assert!(running.pid() > 0);
    // An already-expired deadline pumps nothing and reports expiry.
    let expired = running
        .wait_timeout(Duration::ZERO)
        .expect("the wait survives an expired deadline");
    assert_eq!(expired, None);
    assert_eq!(running.usage(), None, "no usage before the outcome");
    let outcome = running
        .wait_timeout(Duration::from_millis(200))
        .expect("the deadline wait completes");
    assert_eq!(outcome, None, "the command must still be running");
    running.kill().expect("the kill is delivered");
    let status = running.wait().expect("the wait completes after a kill");
    assert_eq!(status.signal(), Some(9), "expected termination by SIGKILL");
    // The kill ended the init, which would have reported it.
    assert_eq!(running.usage(), None, "a killed namespace reports no usage");
}

#[test]
fn a_kill_without_a_pid_namespace_reports_the_observed_status() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut running = Cage::builder()
        .rootfs(rootfs)
        .pid_namespace(false)
        .command("/bin/sh")
        .args(["-c", "sleep 30"])
        .build()
        .expect("a valid sandbox configuration")
        .spawn()
        .expect("the sandbox launches");
    running.kill().expect("the kill is delivered");
    let status = running.wait().expect("the wait completes after a kill");
    assert_eq!(status.signal(), Some(9), "expected termination by SIGKILL");
    // The kill ended only the command; the launch stage collected it.
    assert!(running.usage().is_some(), "the observed kill carries usage");
}

/// A busybox shell loop costing a third of a second of processor time on an
/// ordinary host, and never less than [`LOOP_FLOOR`].
const CPU_LOOP: &str = "i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done";

/// The processor time [`CPU_LOOP`] is held to: well under what it costs, so a
/// loaded host still passes, and well over what the rest of a script costs.
const LOOP_FLOOR: Duration = Duration::from_millis(150);

/// The processor time a process's usage reports, user and system together.
fn cpu(usage: ferroday_cage::ResourceUsage) -> Duration {
    usage.user_time + usage.system_time
}

#[test]
fn the_usage_reports_processor_time_and_peak_memory() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // `dd` reads into a buffer of its block size, so the whole buffer is
    // resident; it runs as a child the shell waits for.
    let script = format!("{CPU_LOOP}; dd if=/dev/zero of=/dev/null bs=64M count=1 2>/dev/null");
    let output = sh(rootfs, &script)
        .output()
        .expect("the sandbox runs to completion");
    assert!(output.status.success(), "{output:?}");
    let usage = output.usage.expect("the init reports the usage");
    assert!(cpu(usage) >= LOOP_FLOOR, "{usage:?}");
    assert!(usage.peak_rss_bytes >= 64 << 20, "{usage:?}");
    assert_eq!(usage.peak_rss_bytes % 1024, 0, "{usage:?}");

    // The handle reports the same figure once its wait has returned.
    let mut running = sh(rootfs, CPU_LOOP).spawn().expect("the sandbox launches");
    let status = running.wait().expect("the wait completes");
    assert!(status.success());
    let usage = running.usage().expect("the init reports the usage");
    assert!(cpu(usage) >= LOOP_FLOOR, "{usage:?}");
}

/// A script whose processor time is spent in an orphan: the loop runs in a
/// process whose parent exits at once, and the command waits for the loop's
/// marker without waiting for the process.
const ORPHAN: &str = "(sh -c 'LOOP; touch /tmp/done' &); \
     while [ ! -e /tmp/done ]; do sleep 0.1; done; sleep 0.2";

#[test]
fn an_orphan_counts_under_a_pid_namespace_and_not_without_one() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let script = ORPHAN.replace("LOOP", CPU_LOOP);

    // The orphan reparents to the init, which collects it.
    let output = sh(rootfs, &script)
        .output()
        .expect("the sandbox runs to completion");
    assert!(output.status.success(), "{output:?}");
    let usage = output.usage.expect("the init reports the usage");
    assert!(
        cpu(usage) >= LOOP_FLOOR,
        "the orphan was not counted: {usage:?}"
    );

    // Without a PID namespace the orphan reparents outside the sandbox, so
    // only the command's own polling counts.
    let output = Cage::builder()
        .rootfs(rootfs)
        .pid_namespace(false)
        .command("/bin/sh")
        .args(["-c", &script])
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox runs to completion");
    assert!(output.status.success(), "{output:?}");
    let usage = output.usage.expect("the launch stage reports the usage");
    assert!(cpu(usage) < LOOP_FLOOR, "the orphan was counted: {usage:?}");
}

#[test]
fn terminate_is_trappable_for_a_graceful_exit() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The trap can only fire while the shell is interruptible, hence
    // sleep-in-background plus `wait`.
    let mut running = sh(rootfs, "trap 'exit 7' TERM; sleep 30 & wait $!")
        .spawn()
        .expect("the sandbox launches");
    let outcome = running
        .wait_timeout(Duration::from_millis(200))
        .expect("the deadline wait completes");
    assert_eq!(outcome, None, "the command must still be running");
    running
        .terminate()
        .expect("the termination request is sent");
    let status = running.wait().expect("the wait completes");
    assert_eq!(status.code(), Some(7), "expected the TERM trap's exit code");
}

#[test]
fn waits_are_fused_and_late_signals_are_not_errors() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut running = sh(rootfs, "exit 5").spawn().expect("the sandbox launches");
    let first = running.wait().expect("the first wait completes");
    assert_eq!(first.code(), Some(5));
    let second = running.wait().expect("a repeated wait returns the fuse");
    assert_eq!(second.code(), Some(5));
    let deadline = running
        .wait_deadline(Instant::now())
        .expect("a fused deadline wait succeeds");
    assert_eq!(deadline, Some(first));
    running
        .kill()
        .expect("killing an exited sandbox is a no-op");
    running
        .terminate()
        .expect("terminating an exited sandbox is a no-op");
}

#[test]
fn a_kill_handle_unblocks_a_waiting_thread() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut running = sh(rootfs, "sleep 30")
        .spawn()
        .expect("the sandbox launches");
    let handle = running.kill_handle().expect("a kill handle is available");
    let killer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        handle.kill().expect("the kill is delivered");
    });
    let status = running.wait().expect("the wait completes after the kill");
    assert_eq!(status.signal(), Some(9));
    killer.join().expect("the killer thread completes");
}

#[test]
fn output_produced_before_a_kill_is_drained_by_the_wait_after_it() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut observer = Collect::default();
    let cage = sh(rootfs, "echo before-kill; sleep 30");
    let mut running = cage
        .spawn_with(&mut observer)
        .expect("the sandbox launches");
    let outcome = running
        .wait_timeout(Duration::from_millis(500))
        .expect("the deadline wait completes");
    assert_eq!(outcome, None, "the command must still be running");
    running.kill().expect("the kill is delivered");
    let status = running.wait().expect("the wait completes");
    assert_eq!(status.signal(), Some(9));
    assert_eq!(observer.stdout, b"before-kill\n");
}

/// Not a test of its own: when `FERRODAY_CAGE_TEST_HELPER` is set, this
/// spawns a long-running sandbox, writes its supervisor pid to the file
/// named by `FERRODAY_CAGE_TEST_PIDFILE`, and exits without waiting — the
/// subject of the stop-with-caller tests, which run this test binary as a
/// child process. Without the variable it does nothing.
#[test]
fn helper_spawn_and_abandon() {
    let Ok(mode) = std::env::var("FERRODAY_CAGE_TEST_HELPER") else {
        return;
    };
    let pidfile =
        std::env::var("FERRODAY_CAGE_TEST_PIDFILE").expect("the helper is given a pid file path");
    let Some(rootfs) = common::fixture_rootfs() else {
        panic!("the helper requires user namespaces");
    };
    let running = Cage::builder()
        .rootfs(rootfs)
        .stop_with_caller(mode == "stop")
        .stdin(Stdio::Null)
        .command("/bin/sleep")
        .arg("86399")
        .build()
        .expect("a valid sandbox configuration")
        .spawn()
        .expect("the sandbox launches");
    std::fs::write(pidfile, running.pid().to_string()).expect("the pid file is writable");
    // Exiting with the handle intact: the process exit severs the tie the
    // way a crashed caller would.
    std::mem::forget(running);
}

/// Runs this test binary as a child executing only the helper above, and
/// returns the supervisor pid it recorded.
///
/// The helper runs with null standard streams: the abandoned sandbox
/// inherits the helper's stdio, so a pipe there would be held open by the
/// sandboxed command — for the surviving-sandbox case, forever. The pid
/// travels through a file instead.
fn spawn_abandoning_caller(mode: &str) -> u32 {
    let pidfile = common::scratch_dir(&format!("stop-with-caller-{mode}")).join("supervisor.pid");
    let exe = std::env::current_exe().expect("the test binary has a path");
    let status = std::process::Command::new(exe)
        .args(["--exact", "helper_spawn_and_abandon", "--nocapture"])
        .env("FERRODAY_CAGE_TEST_HELPER", mode)
        .env("FERRODAY_CAGE_TEST_PIDFILE", &pidfile)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("the helper process runs");
    assert!(status.success(), "the helper process failed");
    std::fs::read_to_string(&pidfile)
        .expect("the helper recorded the supervisor pid")
        .trim()
        .parse()
        .expect("the supervisor pid parses")
}

#[test]
fn stop_with_caller_ends_the_sandbox_when_the_caller_exits() {
    let Some(_) = common::fixture_rootfs() else {
        return;
    };
    let supervisor = spawn_abandoning_caller("stop");
    // The tie is a socket hangup; give the supervisor a moment to observe
    // it, polling rather than sleeping a fixed eternity.
    assert!(
        wait_gone(supervisor, Duration::from_secs(5)),
        "the sandbox outlived its caller despite stop_with_caller",
    );
}

#[test]
fn without_stop_with_caller_the_sandbox_survives_the_caller() {
    let Some(_) = common::fixture_rootfs() else {
        return;
    };
    let supervisor = spawn_abandoning_caller("keep");
    // The caller is gone; the sandbox must still be running well past any
    // teardown latency.
    std::thread::sleep(Duration::from_millis(600));
    assert!(
        process_exists(supervisor),
        "the sandbox stopped with its caller despite stop_with_caller being off"
    );
    // Clean up: killing the init tears the namespace down.
    let killed = std::process::Command::new("kill")
        .args(["-9", &supervisor.to_string()])
        .status()
        .expect("kill runs");
    assert!(killed.success(), "the cleanup kill failed");
}
