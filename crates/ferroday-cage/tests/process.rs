//! Integration tests for the process model: the PID namespace, the library
//! init, and the scrubbed process state the command starts with.
//!
//! The traced-exit tests need a call no tool in the fixture root makes, so
//! their command is this test binary, run again inside a sandbox on an empty
//! root holding the host's own userland, as a probe.

mod common;

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::Stdio as HostStdio;
use std::time::{Duration, Instant};

use ferroday_cage::{Cage, ConfigError, Error, Limit, Resource, Stdio};
use rustix::process::Pid;

/// Set inside the sandbox, and in the probe's own child, to make a probe test
/// probe rather than return. Its value names the probe's part.
const PROBE: &str = "FERRODAY_CAGE_TEST_PROCESS_PROBE";

/// How long the tracer probe holds the command's exit, in milliseconds.
const HOLD: &str = "FERRODAY_CAGE_TEST_PROCESS_HOLD_MS";

/// The pid the tracer probe seizes.
const TRACEE: &str = "FERRODAY_CAGE_TEST_PROCESS_TRACEE";

/// Where this test binary is bound inside the sandbox.
const PROBE_PATH: &str = "/probe";

/// The exit code of the traced command, which the outcome must carry.
const TRACED_EXIT: i32 = 7;

#[test]
fn the_command_is_pid_2_under_the_library_init() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The shell is PID 2; its parent, the init, is PID 1.
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            r#"[ "$$" = 2 ] && [ "$(grep '^PPid:' /proc/$$/status | cut -f2)" = 1 ]"#,
        ])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the command at PID 2 under init");
}

#[test]
fn the_fresh_procfs_shows_only_the_sandbox() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The test process exists on the host; a procfs presenting the
    // sandbox's PID namespace cannot contain it. PID 1 (the init) must be
    // present.
    let status = Cage::builder()
        .rootfs(rootfs)
        .env("HOST_PID", std::process::id().to_string())
        .command("/bin/sh")
        .args(["-c", "test -d /proc/1 && test ! -e /proc/$HOST_PID"])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected a sandbox-only procfs");
}

#[test]
fn without_a_pid_namespace_proc_shows_the_host() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = Cage::builder()
        .rootfs(rootfs)
        .pid_namespace(false)
        .env("HOST_PID", std::process::id().to_string())
        .command("/bin/sh")
        .args(["-c", "test -e /proc/$HOST_PID"])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the host's procfs bind");
}

#[test]
fn exit_codes_round_trip_without_a_pid_namespace() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = Cage::builder()
        .rootfs(rootfs)
        .pid_namespace(false)
        .command("/bin/sh")
        .args(["-c", "exit 42"])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert_eq!(status.code(), Some(42));
}

#[test]
fn orphaned_descendants_are_reaped_while_the_command_runs() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A subshell backgrounds a child and exits, orphaning the child onto
    // the init, where its exit leaves a zombie. The init must collect it while
    // the command still runs — not at command exit — so after a grace period,
    // no process in the namespace may be in the zombie state.
    let script = r#"
        (: &)
        sleep 1
        ! grep -l ') Z ' /proc/[0-9]*/stat 2>/dev/null
    "#;
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected no zombies after the reap tick");
}

#[test]
fn sigpipe_is_reset_to_the_default_disposition() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A Rust caller ignores SIGPIPE, and exec preserves ignored
    // dispositions; the launch resets them, so bit 13 of SigIgn must be
    // clear inside (mask 0x1000).
    let script = r#"
        ignored=$(grep '^SigIgn:' /proc/$$/status | cut -f2)
        [ $(( 0x$ignored & 4096 )) = 0 ]
    "#;
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected SIGPIPE at SIG_DFL inside");
}

#[test]
fn the_command_starts_with_no_signal_blocked_or_ignored() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Every process of a launch is forked with every signal blocked, and the
    // launch stage keeps most of them blocked for as long as it lives and
    // ignores them while it supervises. None of that may reach the command: an inherited block or an inherited ignore both survive
    // `execve`. The command is the reader itself, so no shell's own signal
    // handling is in the picture.
    for pid_namespace in [true, false] {
        let output = Cage::builder()
            .rootfs(rootfs)
            .pid_namespace(pid_namespace)
            .command("/bin/busybox")
            .args(["grep", "-E", "^Sig(Blk|Ign):", "/proc/self/status"])
            .build()
            .expect("a valid sandbox configuration")
            .output()
            .expect("the sandbox launches");
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            text, "SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\n",
            "pid_namespace = {pid_namespace}",
        );
    }
}

#[test]
fn the_launch_stage_outside_the_sandbox_outlives_the_signals_sent_to_its_group() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Without a PID namespace the launch stage supervises the command from
    // outside, as an ordinary member of the caller's process group, where a
    // terminal's interrupt and a shell's `kill %1` reach it alike. Had one of
    // them ended it, the outcome would be lost and a command in a session of
    // its own would run on unsupervised. Sent straight to the launch stage,
    // each must leave the outcome to be collected, as each would leave the
    // init of a PID namespace.
    let mut running = Cage::builder()
        .rootfs(rootfs)
        .pid_namespace(false)
        .command("/bin/sh")
        .args(["-c", "sleep 1; exit 7"])
        .build()
        .expect("a valid sandbox configuration")
        .spawn()
        .expect("the sandbox launches");
    let launch_stage = parent_of(running.pid());
    for signal in common::GROUP_SIGNALS {
        rustix::process::kill_process(launch_stage, signal)
            .expect("the launch stage is alive to be signalled");
    }
    match running.wait_timeout(Duration::from_secs(30)) {
        Ok(Some(status)) => assert_eq!(status.code(), Some(7)),
        other => {
            let _ = running.kill();
            panic!("the outcome was not collected: {other:?}");
        }
    }
}

/// The parent of the host process `pid`, read from its procfs status.
fn parent_of(pid: u32) -> Pid {
    let status =
        std::fs::read_to_string(format!("/proc/{pid}/status")).expect("the process is alive");
    let parent = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .expect("a status names its parent")
        .trim()
        .parse()
        .expect("a parent is a number");
    Pid::from_raw(parent).expect("a living process has a parent")
}

#[test]
fn the_command_shares_the_inits_process_group_under_a_pid_namespace() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A command that inherits the caller's standard input keeps the caller's
    // session. Under a PID namespace it is in the init's process group, which
    // the init made its own: the pgrp field of /proc/self/stat reads the
    // init's pid, 1. A command left in the caller's group would read 0 there,
    // since an outside group has no mapping in the namespace.
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", r#"[ "$(cut -d' ' -f5 /proc/$$/stat)" = 1 ]"#])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the init's process group");

    // Without a PID namespace the command shares the caller's PID space, and
    // its process group with it.
    let caller = rustix::process::getpgrp().as_raw_nonzero().get();
    let status = Cage::builder()
        .rootfs(rootfs)
        .pid_namespace(false)
        .command("/bin/sh")
        .args([
            "-c",
            &format!(r#"[ "$(cut -d' ' -f5 /proc/$$/stat)" = {caller} ]"#),
        ])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the caller's process group");
}

#[test]
fn the_command_starts_with_a_clean_descriptor_table() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Only the standard streams survive into the command; every launch
    // channel and caller descriptor is closed or close-on-exec. Builtins
    // and path checks only: a forked helper or a command substitution
    // would add pipe descriptors to the very table being examined, and
    // even a glob briefly opens the directory it enumerates.
    let script = r#"
        [ -e /proc/$$/fd/0 ] && [ -e /proc/$$/fd/1 ] && [ -e /proc/$$/fd/2 ] || exit 1
        for fd in 3 4 5 6 7 8 9 10 11 12 13 14 15; do
            [ ! -e /proc/$$/fd/$fd ] || exit 1
        done
    "#;
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected only fds 0, 1, 2 inside");
}

#[test]
fn a_resource_limit_reaches_the_command() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The command reads its own limits from procfs. Without a configured
    // limit the caller's is inherited; with one, the sandbox's value is what
    // the command sees.
    let read_limit = |cage: Cage| -> String {
        let output = cage.output().expect("the sandbox launches");
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let builder = || {
        Cage::builder()
            .rootfs(rootfs)
            .command("/bin/sh")
            .args(["-c", "grep '^Max processes' /proc/self/limits"])
    };

    let unlimited = read_limit(builder().build().expect("a valid configuration"));
    assert!(
        !unlimited.contains(" 64 "),
        "the fixture host is unlikely to cap processes at 64: {unlimited:?}"
    );

    let limited = read_limit(
        builder()
            .rlimit(Resource::Processes, 64, 64)
            .build()
            .expect("a valid configuration"),
    );
    let fields: Vec<&str> = limited.split_whitespace().collect();
    // "Max processes  <soft>  <hard>  processes"
    assert_eq!(
        &fields[fields.len() - 3..fields.len() - 1],
        ["64", "64"],
        "the configured limit must reach the command: {limited:?}"
    );
}

#[test]
fn a_resource_limit_binds_the_commands_descendants() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A limit is a process attribute, inherited across fork and exec, so a
    // process the command starts sees it too.
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "/bin/busybox sh -c \"grep '^Max file size' /proc/self/limits\"",
        ])
        .rlimit(Resource::FileSize, 4096, 4096)
        .build()
        .expect("a valid configuration")
        .output()
        .expect("the sandbox launches");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("4096"), "{text:?}");
}

#[test]
fn a_file_size_limit_stops_a_runaway_write() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The limit is enforced by the kernel, not merely reported: a write past
    // it raises SIGXFSZ, which the shell reports as a failed command. The
    // tmpfs `/tmp` the sandbox mounts is the target, so nothing on the host
    // is touched.
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "head -c 65536 /dev/zero > /tmp/probe 2>/dev/null; \
             /bin/busybox stat -c %s /tmp/probe",
        ])
        .rlimit(Resource::FileSize, 4096, 4096)
        .build()
        .expect("a valid configuration")
        .output()
        .expect("the sandbox launches");
    let size: u64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("stat reports a size");
    assert_eq!(size, 4096, "the write must be cut off at the limit");
}

#[test]
fn a_soft_limit_above_its_hard_limit_is_a_config_error() {
    let err = Cage::builder()
        .rootfs("/")
        .command("/bin/sh")
        .rlimit(Resource::Processes, 64, 32)
        .build()
        .unwrap_err();
    match &err {
        Error::Config(config @ ConfigError::RlimitInvalid { resource, .. }) => {
            assert_eq!(*resource, Resource::Processes);
            assert!(config.to_string().contains("RLIMIT_NPROC"), "{config}");
        }
        other => panic!("expected RlimitInvalid, got {other:?}"),
    }
}

#[test]
fn an_unlimited_soft_limit_needs_an_unlimited_hard_limit() {
    let err = Cage::builder()
        .rootfs("/")
        .command("/bin/sh")
        .rlimit(Resource::CpuTime, Limit::UNLIMITED, 10)
        .build()
        .unwrap_err();
    assert!(
        matches!(err, Error::Config(ConfigError::RlimitInvalid { .. })),
        "{err:?}"
    );
}

#[test]
fn a_command_that_leaves_the_supervisors_process_group_is_still_waited_for() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A sandboxed command is free to start a session of its own, which takes it
    // out of the supervisor's process group. The supervisor's reaping wait must
    // be for any child, not for any child of its own group: a group-scoped wait
    // answers ECHILD for a child sitting there exited, and the supervisor then
    // exits without a status record, which the caller reads as a lost
    // supervisor rather than the exit code the command actually produced.
    //
    // Both process shapes are checked: with a PID namespace the supervisor is
    // the in-namespace init, and without one it is the launch stage outside.
    for pid_namespace in [true, false] {
        let status = Cage::builder()
            .rootfs(rootfs)
            .pid_namespace(pid_namespace)
            .command("/bin/busybox")
            .args(["setsid", "/bin/busybox", "sh", "-c", "exit 7"])
            .build()
            .expect("a valid sandbox configuration")
            .run()
            .expect("the sandbox launches");
        assert_eq!(
            status.code(),
            Some(7),
            "the command's own session must not hide its outcome \
             (pid_namespace = {pid_namespace})",
        );
    }
}

/// The probe's command: starts a tracer of itself, waits until the tracer has
/// seized it, and exits with [`TRACED_EXIT`], leaving its exit held by the
/// tracer.
#[test]
fn probe_traced_command() {
    if std::env::var(PROBE).as_deref() != Ok("command") {
        return;
    }
    let me = std::process::id();
    let mut tracer = std::process::Command::new(PROBE_PATH)
        .args(["--exact", "probe_tracer", "--nocapture", "--test-threads=1"])
        .env(PROBE, "tracer")
        .env(TRACEE, me.to_string())
        .stdin(HostStdio::piped())
        .stdout(HostStdio::null())
        .stderr(HostStdio::piped())
        .spawn()
        .expect("the tracer starts");
    let tracer_pid = Pid::from_raw(i32::try_from(tracer.id()).expect("a pid fits"))
        .expect("a child's pid is positive");
    // The tracer is no ancestor of this process, so Yama's relational scope
    // admits it only by name.
    rustix::process::set_ptracer(rustix::process::PTracer::ProcessID(tracer_pid))
        .expect("the tracer is named");
    let mut go = tracer.stdin.take().expect("the tracer's input is piped");
    go.write_all(b"go\n").expect("the tracer is told to seize");
    // The report is on the tracer's standard error, where its harness writes
    // nothing of its own unless it fails.
    let report = BufReader::new(tracer.stderr.take().expect("the tracer's errors are piped"));
    let seized = report
        .lines()
        .map(|line| line.expect("the tracer's report reads"))
        .any(|line| line == "seized");
    assert!(seized, "the tracer did not seize this process");
    std::process::exit(TRACED_EXIT);
}

/// The probe's tracer: seizes the command once told to, says so on its
/// standard error, and holds it for [`HOLD`] milliseconds.
#[test]
#[expect(unsafe_code)]
fn probe_tracer() {
    if std::env::var(PROBE).as_deref() != Ok("tracer") {
        return;
    }
    let tracee: libc::pid_t = std::env::var(TRACEE)
        .expect("the tracee is named")
        .parse()
        .expect("a pid");
    let hold: u64 = std::env::var(HOLD)
        .expect("the hold is set")
        .parse()
        .expect("a duration");
    let mut go = String::new();
    std::io::stdin()
        .read_line(&mut go)
        .expect("the command says when");
    // SAFETY: `PTRACE_SEIZE` takes the pid and two null arguments, and reads
    // or writes no memory of this process.
    let seized = unsafe {
        libc::ptrace(
            libc::PTRACE_SEIZE,
            tracee,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    assert_eq!(seized, 0, "{}", std::io::Error::last_os_error());
    eprintln!("seized");
    std::thread::sleep(Duration::from_millis(hold));
}

/// A sandbox whose command exits with its exit held by a tracer it started,
/// which holds it for `hold`.
fn traced_exit(pid_namespace: bool, hold: Duration) -> Cage {
    let exe = std::env::current_exe().expect("the test binary has a path");
    common::host_userland()
        .pid_namespace(pid_namespace)
        .command(PROBE_PATH)
        .args([
            "--exact",
            "probe_traced_command",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE, "command")
        .env(HOLD, hold.as_millis().to_string())
        .bind_ro(&exe, PROBE_PATH)
        .resolv_conf(false)
        .stdin(Stdio::Null)
        .stdout(Stdio::Null)
        .build()
        .expect("a valid sandbox configuration")
}

#[test]
fn a_tracer_holding_the_commands_exit_does_not_hold_the_outcome() {
    if !common::require::userns() {
        return;
    }
    // A process tracing the command holds its exit, which its parent's wait
    // then cannot see, and with a held exit the init cannot report. The init
    // ends the namespace's other processes once the command's pidfd says it
    // has exited, as its own exit would have a moment later, and the tracer
    // goes with them. A tracer holding on for a minute must not hold the
    // outcome for any of it.
    let mut running = traced_exit(true, Duration::from_secs(60))
        .spawn()
        .expect("the sandbox launches");
    match running.wait_timeout(Duration::from_secs(30)) {
        Ok(Some(status)) => assert_eq!(status.code(), Some(TRACED_EXIT), "{status}"),
        other => {
            let _ = running.kill();
            panic!("the traced command's outcome was not reported: {other:?}");
        }
    }
}

/// How many clock ticks the launch stage may use over the second it is watched
/// below. One spinning on a readable pidfd uses the whole second, a hundred
/// ticks.
const IDLE_TICKS: u64 = 20;

#[test]
fn without_a_pid_namespace_the_launch_stage_sleeps_while_a_tracer_holds_the_exit() {
    if !common::require::userns() {
        return;
    }
    // Without a PID namespace the launch stage collects the command's outcome
    // from outside, and the tracer is a host process the launch does not
    // govern, so the stage waits for it to let go. The command's pidfd turns
    // readable at its exit and stays so; polled on, it would wake the stage on
    // every pass of its loop for as long as the tracer holds.
    let mut running = traced_exit(false, Duration::from_secs(5))
        .spawn()
        .expect("the sandbox launches");
    let command = running.pid();
    let launch_stage = parent_of(command);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !is_zombie(command) {
        if Instant::now() >= deadline {
            let _ = running.kill();
            panic!("the command never exited under its tracer");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let launch_stage = u32::try_from(launch_stage.as_raw_nonzero().get()).expect("a pid fits");
    let before = common::cpu_ticks(launch_stage).expect("the launch stage is alive");
    std::thread::sleep(Duration::from_secs(1));
    let after = common::cpu_ticks(launch_stage).expect("the launch stage is alive");
    assert!(
        after - before < IDLE_TICKS,
        "the launch stage spun: {} ticks while the tracer held the exit",
        after - before,
    );
    match running.wait_timeout(Duration::from_secs(30)) {
        Ok(Some(status)) => assert_eq!(status.code(), Some(TRACED_EXIT), "{status}"),
        other => {
            let _ = running.kill();
            panic!("the outcome was not reported once the tracer let go: {other:?}");
        }
    }
}

/// Whether the host process `pid` is a zombie: exited, and not yet collected.
fn is_zombie(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let (_, rest) = stat.rsplit_once(')')?;
            rest.split_whitespace().next().map(|state| state == "Z")
        })
        .unwrap_or(false)
}
