//! Integration tests for the process model: the PID namespace, the library
//! init, and the scrubbed process state the command starts with.
//!
//! The traced-exit tests need a call no tool in the fixture root makes, so
//! their command is this test binary, run again inside a sandbox on an empty
//! root holding the host's own userland, as a probe.

mod common;

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::process::Stdio as HostStdio;
use std::time::{Duration, Instant};

use ferroday_cage::{
    Cage, ConfigError, Error, ExitStatus, Limit, Output, Pending, Pty, Resource, Running,
    SetupStep, Stdio, Terminal,
};
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
    let status = common::shell(rootfs, script)
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
    let status = common::shell(rootfs, script)
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
    let status = common::outcome_within(&mut running, Duration::from_secs(30));
    assert_eq!(status.code(), Some(7));
}

/// The parent of the host process `pid`.
fn parent_of(pid: u32) -> Pid {
    let parent = common::process_parent(pid).expect("the process is alive");
    Pid::from_raw(i32::try_from(parent).expect("a pid fits an i32"))
        .expect("a living process has a parent")
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
    let status = common::shell(rootfs, script)
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
        .args(common::rerun_args("probe_tracer"))
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
        .args(common::rerun_args("probe_traced_command"))
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
    let status = common::outcome_within(&mut running, Duration::from_secs(30));
    assert_eq!(status.code(), Some(TRACED_EXIT), "{status}");
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
    let status = common::outcome_within(&mut running, Duration::from_secs(30));
    assert_eq!(status.code(), Some(TRACED_EXIT), "{status}");
}

/// Whether the host process `pid` is a zombie: exited, and not yet collected.
fn is_zombie(pid: u32) -> bool {
    common::process_state(pid) == Some('Z')
}

// -- A caller's closed standard streams ---------------------------------------

/// Set in a copy of this test binary that [`run_closed_stream_probes`] starts,
/// to have [`probe_closed_streams`] close the standard descriptors its value
/// names and launch with them closed. The value is the confinement, `sandbox`
/// or `restriction`, then the numbers: `sandbox 0 1 2`.
const CLOSED: &str = "FERRODAY_CAGE_TEST_PROCESS_CLOSED";

/// The sets of standard descriptors a caller has closed that the launches are
/// tried under, each in a process of its own.
const CLOSED_SETS: [&str; 4] = ["0", "1", "2", "0 1 2"];

/// A command that is nowhere, so its launch fails at the exec.
const ABSENT: &str = "/usr/bin/ferroday-cage-absent-command";

/// How long one launch of the probe may take to finish.
const PATIENCE: Duration = Duration::from_secs(30);

/// Sets `fds` to the word `fds` and then every descriptor number below 64 the
/// shell holds.
///
/// Builtins and path checks only, as in
/// [`the_command_starts_with_a_clean_descriptor_table`]: a forked helper or a
/// command substitution would add descriptors to the very table it examines.
const LIST_FDS: &str = "fds=fds; fd=0; while [ $fd -lt 64 ]; do \
     [ -e /proc/$$/fd/$fd ] && fds=\"$fds $fd\"; fd=$((fd+1)); done";

#[test]
fn a_sandbox_launch_leaves_the_callers_closed_streams_closed() {
    if common::fixture_rootfs().is_none() {
        return;
    }
    run_closed_stream_probes("sandbox");
}

#[cfg(feature = "hardening")]
#[test]
fn a_restriction_launch_leaves_the_callers_closed_streams_closed() {
    if !common::landlock() {
        return;
    }
    run_closed_stream_probes("restriction");
}

/// Runs [`probe_closed_streams`] for `confinement` under each of
/// [`CLOSED_SETS`], in a copy of this test binary of its own for each, and
/// fails on the first whose probe does not pass.
///
/// A process apart, because closing a standard descriptor is process-wide: in
/// the harness's own process it would take the harness's output, and every
/// test running beside it would launch with the descriptor closed.
fn run_closed_stream_probes(confinement: &str) {
    for closed in CLOSED_SETS {
        let output = common::run_bounded(
            common::rerun("probe_closed_streams").env(CLOSED, format!("{confinement} {closed}")),
            Duration::from_secs(300),
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("probe done"),
            "a {confinement} launch with {closed} closed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

/// The probe [`run_closed_stream_probes`] starts: closes the standard
/// descriptors [`CLOSED`] names, launches with them closed in every way the
/// confinement offers, and reports what it found once they are open again.
#[test]
fn probe_closed_streams() {
    let Ok(spec) = std::env::var(CLOSED) else {
        return;
    };
    let mut words = spec.split(' ');
    let confinement = words.next().expect("the probe names its confinement");
    let closed: Vec<RawFd> = words
        .map(|word| word.parse().expect("a descriptor number"))
        .collect();
    let launchers = Launchers::new(confinement, &spec.replace(' ', "-"));

    let mut findings = common::with_standard_streams_closed(&closed, || launchers.run(&closed));

    // The reports the uncaptured launches wrote, read now that reading a file
    // cannot take one of the closed numbers.
    let left_open = listing((0..3).filter(|fd| !closed.contains(fd)));
    for name in launchers.reports() {
        let written =
            std::fs::read_to_string(launchers.report.join(name)).expect("the report file reads");
        if written.trim_end() != left_open {
            findings.push(format!(
                "a {name} launch held {written:?} where it inherited {left_open:?}"
            ));
        }
    }
    assert!(findings.is_empty(), "{}", findings.join("\n"));
    println!("probe done");
}

/// The descriptor listing [`LIST_FDS`] makes of a table holding `numbers`.
fn listing(numbers: impl IntoIterator<Item = RawFd>) -> String {
    numbers
        .into_iter()
        .fold(String::from("fds"), |listing, fd| format!("{listing} {fd}"))
}

/// Whether `err` is the exec step failing to find the command.
fn exec_absent(err: &Error) -> bool {
    matches!(
        err,
        Error::Setup { step: SetupStep::Exec, source, .. }
            if source.kind() == std::io::ErrorKind::NotFound
    )
}

/// Waits for `running` within [`PATIENCE`], killing it past that, and returns
/// its outcome, keeping in `findings` what went wrong.
fn settle(running: &mut Running<'_>, what: &str, findings: &mut Vec<String>) -> Option<ExitStatus> {
    match running.wait_timeout(PATIENCE) {
        Ok(Some(status)) => Some(status),
        Ok(None) => {
            findings.push(format!("{what}: the command did not finish"));
            let _ = running.kill();
            let _ = running.wait_timeout(PATIENCE);
            None
        }
        Err(err) => {
            findings.push(format!("{what}: the wait failed: {err:?}"));
            None
        }
    }
}

/// What the probe asks of a cage and of a restriction alike.
trait Launch {
    fn output(&self) -> Result<Output, Error>;
    fn spawn(&self) -> Result<Running<'static>, Error>;
    fn spawn_terminal(&self) -> Result<(Running<'static>, Pty), Error>;
    /// A launch held at its gate, or `None` where the confinement has none.
    fn spawn_pending(&self) -> Option<Result<Pending<'static>, Error>>;
}

impl Launch for Cage {
    fn output(&self) -> Result<Output, Error> {
        Cage::output(self)
    }

    fn spawn(&self) -> Result<Running<'static>, Error> {
        Cage::spawn(self)
    }

    fn spawn_terminal(&self) -> Result<(Running<'static>, Pty), Error> {
        Cage::spawn_terminal(self, &Terminal::new())
    }

    fn spawn_pending(&self) -> Option<Result<Pending<'static>, Error>> {
        Some(Cage::spawn_pending(self))
    }
}

#[cfg(feature = "hardening")]
impl Launch for ferroday_cage::Restriction {
    fn output(&self) -> Result<Output, Error> {
        ferroday_cage::Restriction::output(self)
    }

    fn spawn(&self) -> Result<Running<'static>, Error> {
        ferroday_cage::Restriction::spawn(self)
    }

    fn spawn_terminal(&self) -> Result<(Running<'static>, Pty), Error> {
        ferroday_cage::Restriction::spawn_terminal(self, &Terminal::new())
    }

    fn spawn_pending(&self) -> Option<Result<Pending<'static>, Error>> {
        None
    }
}

/// The launches [`probe_closed_streams`] makes, built before it closes
/// anything.
///
/// Each stops with the probe, so the bound [`run_closed_stream_probes`] holds
/// the probe to also bounds a launch whose own wait takes none, as `output`
/// does.
struct Launchers {
    /// Lists its descriptors on standard output and writes `err` to standard
    /// error, for a capturing launch.
    capture: Box<dyn Launch>,
    /// Lists its descriptors into the report file `spawn`, leaving every
    /// stream inherited.
    spawn: Box<dyn Launch>,
    /// Lists its descriptors into the report file `pending`, leaving every
    /// stream inherited.
    pending: Box<dyn Launch>,
    /// Lists its descriptors on its terminal.
    terminal: Box<dyn Launch>,
    /// Runs [`ABSENT`].
    absent: Box<dyn Launch>,
    /// The directory the report files are in.
    report: PathBuf,
    /// Whether the confinement has a gate, and so writes a `pending` report.
    gated: bool,
}

impl Launchers {
    /// The launches for `confinement`, reporting into a scratch directory named
    /// for `tag`.
    fn new(confinement: &str, tag: &str) -> Launchers {
        let report = common::scratch_dir(&format!("closed-streams-{tag}"));
        for name in ["spawn", "pending"] {
            std::fs::write(report.join(name), "").expect("the report file is created");
        }
        // Where the command names the report directory: bound at `/mnt` in a
        // sandbox, and the host path itself under a restriction.
        let (inside, gated) = match confinement {
            "sandbox" => ("/mnt".to_string(), true),
            _ => (
                report.to_str().expect("a UTF-8 scratch path").to_string(),
                false,
            ),
        };
        let build = |script: Option<&str>| -> Box<dyn Launch> {
            match confinement {
                "sandbox" => {
                    let builder = Cage::builder()
                        .rootfs(common::fixture_rootfs().expect("the fixture root"))
                        .bind(&report, "/mnt")
                        .stop_with_caller(true);
                    let builder = match script {
                        Some(script) => builder.command("/bin/sh").args(["-c", script]),
                        None => builder.command(ABSENT),
                    };
                    Box::new(builder.build().expect("a valid sandbox configuration"))
                }
                #[cfg(feature = "hardening")]
                "restriction" => {
                    let builder = common::grant_system_trees(ferroday_cage::Restriction::builder())
                        .landlock_fs(
                            ferroday_cage::FsAccess::READ | ferroday_cage::FsAccess::WRITE,
                            &report,
                        )
                        .stop_with_caller(true);
                    let builder = match script {
                        Some(script) => builder.command("/bin/sh").args(["-c", script]),
                        None => builder.command(ABSENT),
                    };
                    Box::new(builder.build().expect("a valid restriction configuration"))
                }
                other => panic!("no confinement {other:?}"),
            }
        };
        Launchers {
            capture: build(Some(&format!("{LIST_FDS}; echo \"$fds\"; echo err >&2"))),
            spawn: build(Some(&format!(
                "{LIST_FDS}; echo \"$fds\" >> '{inside}/spawn'"
            ))),
            pending: build(Some(&format!(
                "{LIST_FDS}; echo \"$fds\" >> '{inside}/pending'"
            ))),
            terminal: build(Some(&format!("{LIST_FDS}; echo \"$fds\""))),
            absent: build(None),
            report,
            gated,
        }
    }

    /// The report files the launches write.
    fn reports(&self) -> &'static [&'static str] {
        if self.gated {
            &["spawn", "pending"]
        } else {
            &["spawn"]
        }
    }

    /// Launches each way with the standard descriptors `closed` closed, and
    /// returns what went wrong.
    fn run(&self, closed: &[RawFd]) -> Vec<String> {
        let mut findings = Vec::new();
        // The caller's closed numbers stay closed whatever the launch holds.
        let still_closed = |when: &str, findings: &mut Vec<String>| {
            for &fd in closed {
                if common::is_open(fd) {
                    findings.push(format!("{when}, the caller's descriptor {fd} is open"));
                }
            }
        };

        match self.capture.output() {
            Ok(output) => {
                let held = listing((0..3).filter(|&fd| fd != 0 || !closed.contains(&0)));
                if output.stdout != format!("{held}\n").as_bytes()
                    || output.stderr != b"err\n"
                    || !output.status.success()
                {
                    findings.push(format!(
                        "a capturing launch wrote {:?} and {:?} where it held {held:?}, and \
                         ended {}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr),
                        output.status,
                    ));
                }
            }
            Err(err) => findings.push(format!("a capturing launch failed: {err:?}")),
        }
        still_closed("after a capturing launch", &mut findings);
        match self.absent.output() {
            Err(err) if exec_absent(&err) => {}
            other => findings.push(format!(
                "a capturing launch of an absent command answered {other:?}"
            )),
        }
        still_closed("after a failed capturing launch", &mut findings);

        match self.spawn.spawn() {
            Ok(mut running) => {
                still_closed("while a launch runs", &mut findings);
                if let Some(status) = settle(&mut running, "a launch", &mut findings)
                    && !status.success()
                {
                    findings.push(format!("a launch ended {status}"));
                }
            }
            Err(err) => findings.push(format!("a launch failed: {err:?}")),
        }
        still_closed("after a launch", &mut findings);
        match self.absent.spawn() {
            Err(err) if exec_absent(&err) => {}
            Err(err) => findings.push(format!("a launch of an absent command failed: {err:?}")),
            Ok(mut running) => {
                let status = settle(&mut running, "an absent command", &mut findings);
                findings.push(format!(
                    "a launch of an absent command ran, ending {status:?}"
                ));
            }
        }
        still_closed("after a failed launch", &mut findings);

        if let Some(pending) = self.pending.spawn_pending() {
            match pending {
                Ok(pending) => {
                    still_closed("while a launch is held", &mut findings);
                    match pending.proceed() {
                        Ok(mut running) => {
                            if let Some(status) =
                                settle(&mut running, "a held launch", &mut findings)
                                && !status.success()
                            {
                                findings.push(format!("a held launch ended {status}"));
                            }
                        }
                        Err(err) => findings.push(format!("a held launch failed: {err:?}")),
                    }
                }
                Err(err) => findings.push(format!("a held launch failed: {err:?}")),
            }
            still_closed("after a held launch", &mut findings);
            match self
                .absent
                .spawn_pending()
                .map(|held| held.and_then(Pending::proceed))
            {
                Some(Err(err)) if exec_absent(&err) => {}
                Some(Ok(mut running)) => {
                    let status = settle(&mut running, "an absent command", &mut findings);
                    findings.push(format!(
                        "a held launch of an absent command ran, ending {status:?}"
                    ));
                }
                other => findings.push(format!(
                    "a held launch of an absent command answered {:?}",
                    other.map(|held| held.map(drop)),
                )),
            }
            still_closed("after a failed held launch", &mut findings);
        }

        match self.terminal.spawn_terminal() {
            Ok((mut running, pty)) => {
                still_closed("while a terminal launch runs", &mut findings);
                let deadline = Instant::now() + PATIENCE;
                let mut written = String::new();
                while common::pty::drain_until(&pty, deadline, &mut written) {}
                settle(&mut running, "a terminal launch", &mut findings);
                if !written.lines().any(|line| line.trim_end() == "fds 0 1 2") {
                    findings.push(format!("a terminal launch wrote {written:?}"));
                }
            }
            Err(err) => findings.push(format!("a terminal launch failed: {err:?}")),
        }
        still_closed("after a terminal launch", &mut findings);
        match self.absent.spawn_terminal() {
            Err(err) if exec_absent(&err) => {}
            Err(err) => findings.push(format!(
                "a terminal launch of an absent command failed: {err:?}"
            )),
            Ok((mut running, _pty)) => {
                let status = settle(&mut running, "an absent command", &mut findings);
                findings.push(format!(
                    "a terminal launch of an absent command ran, ending {status:?}"
                ));
            }
        }
        still_closed("after a failed terminal launch", &mut findings);
        findings
    }
}

/// The launch [`probe_unreceived_supervisor`] makes, as `<entry> <pid
/// namespace>`: `spawn` or `pending`, then `true` or `false`.
const UNRECEIVED: &str = "FERRODAY_CAGE_TEST_PROCESS_UNRECEIVED";

/// A launch whose supervisor's pidfd cannot reach the caller ends with
/// `Error::SupervisorUnreceived`, promptly, and leaves no process running.
///
/// The kernel delivers a message without the descriptor it carries where the
/// receiver has no descriptor number free. The probe takes every free number
/// in the window between the identity map and the receive, from inside the
/// delegate that applies the map, which is the one point a caller's code runs
/// there. Each launch shape is a process apart, since a full descriptor table
/// is process-wide, and each is bounded twice: the launch by the probe, and the
/// probe by this test.
#[test]
fn a_supervisor_whose_pidfd_cannot_be_received_ends_the_launch() {
    if !common::require::userns() {
        return;
    }
    let mut cases = vec![("spawn", false), ("pending", false)];
    match ferroday_cage::host::procfs_blocker() {
        None => cases.extend([("spawn", true), ("pending", true)]),
        Some(blocker) => common::require::premise_unmet(format!(
            "this host cannot mount a PID namespace's procfs: {blocker}"
        )),
    }
    for (entry, pid_namespace) in cases {
        let output = common::run_bounded(
            common::rerun("probe_unreceived_supervisor")
                .env(UNRECEIVED, format!("{entry} {pid_namespace}")),
            Duration::from_secs(120),
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("probe done"),
            "{entry}, pid_namespace = {pid_namespace}:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

/// The probe [`a_supervisor_whose_pidfd_cannot_be_received_ends_the_launch`]
/// starts: launches as [`UNRECEIVED`] says with no descriptor number free at the
/// receive, holds the error to `SupervisorUnreceived`, and waits for every
/// process the launch started to be gone.
#[test]
fn probe_unreceived_supervisor() {
    use std::os::fd::OwnedFd;
    use std::sync::mpsc;

    let Ok(spec) = std::env::var(UNRECEIVED) else {
        return;
    };
    let (entry, pid_namespace) = spec.split_once(' ').expect("an entry and a flag");
    let pid_namespace: bool = pid_namespace.parse().expect("a flag");

    // Every process the launch leaves behind reparents here, where the wait
    // below finds it, rather than to the host's init.
    rustix::process::set_child_subreaper(Some(rustix::process::getpid()))
        .expect("the probe becomes a subreaper");
    // A small table, so filling it is quick.
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    let soft = limit.current.map_or(256, |current| current.min(256));
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(soft),
            maximum: limit.maximum,
        },
    )
    .expect("the soft limit comes down");

    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let map = |outside| {
        vec![ferroday_cage::IdRange {
            inside: 0,
            outside,
            count: 1,
        }]
    };
    let taken = std::sync::Arc::new(std::sync::Mutex::new(Vec::<OwnedFd>::new()));
    let cage = common::host_userland()
        .command("/bin/sleep")
        .args(["60"])
        .pid_namespace(pid_namespace)
        .resolv_conf(false)
        .stdin(Stdio::Null)
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
        .identity_map(ferroday_cage::IdentityMap::ranges(map(uid), map(gid)))
        .id_mapper(TakesEveryNumber {
            taken: std::sync::Arc::clone(&taken),
        })
        .build()
        .expect("a valid sandbox configuration");

    // The launch runs on a thread of its own, so a launch that does not return
    // fails here rather than holding the probe until its bound.
    let (sent, outcome) = mpsc::channel();
    let launch = std::thread::spawn({
        let entry = entry.to_string();
        move || {
            let err = match entry.as_str() {
                "spawn" => cage.spawn().map(drop).err(),
                _ => cage.spawn_pending().map(drop).err(),
            };
            let _ = sent.send(err);
        }
    });
    let err = outcome
        .recv_timeout(PATIENCE)
        .expect("the launch returns promptly");
    launch.join().expect("the launch thread ends");
    taken.lock().expect("the taken numbers").clear();
    assert!(
        matches!(err, Some(Error::SupervisorUnreceived)),
        "the launch ends with SupervisorUnreceived: {err:?}",
    );

    // Every process of the launch is this probe's child or reparented to it,
    // so its end is no child left.
    let deadline = Instant::now() + PATIENCE;
    loop {
        match rustix::process::waitid(
            rustix::process::WaitId::All,
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
        ) {
            Err(rustix::io::Errno::CHILD) => break,
            Ok(Some(_)) => continue,
            Ok(None) => {
                assert!(
                    Instant::now() < deadline,
                    "a process of the launch is still running"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(errno) => panic!("the wait failed: {errno}"),
        }
    }
    println!("probe done");
}

/// A delegate that writes the single-identity map from outside, as a range
/// map's delegate writes any map, and then takes every descriptor number free
/// in the caller, keeping them in `taken`.
#[derive(Debug)]
struct TakesEveryNumber {
    taken: std::sync::Arc<std::sync::Mutex<Vec<std::os::fd::OwnedFd>>>,
}

impl ferroday_cage::IdMapper for TakesEveryNumber {
    fn resolve(
        &self,
        request: &ferroday_cage::IdentityMap,
    ) -> Result<ferroday_cage::ResolvedMap, ferroday_cage::IdMapError> {
        match request {
            ferroday_cage::IdentityMap::Ranges { uid, gid, .. } => {
                Ok(ferroday_cage::ResolvedMap::new(uid.clone(), gid.clone()))
            }
            _ => Err(ferroday_cage::IdMapError::unsatisfiable(
                "only an explicit map",
            )),
        }
    }

    fn apply(
        &self,
        pid: u32,
        _map: &ferroday_cage::ResolvedMap,
    ) -> Result<(), ferroday_cage::IdMapError> {
        let write = |which: &'static str, line: String| {
            std::fs::write(format!("/proc/{pid}/{which}"), line)
                .map_err(|err| ferroday_cage::IdMapError::map_write(which, err))
        };
        write("setgroups", "deny".to_string())?;
        write(
            "gid_map",
            format!("0 {} 1", rustix::process::getgid().as_raw()),
        )?;
        write(
            "uid_map",
            format!("0 {} 1", rustix::process::getuid().as_raw()),
        )?;
        let mut taken = self.taken.lock().expect("the taken numbers");
        loop {
            match rustix::io::fcntl_dupfd_cloexec(rustix::stdio::stderr(), 0) {
                Ok(fd) => taken.push(fd),
                Err(rustix::io::Errno::MFILE) => return Ok(()),
                Err(errno) => {
                    return Err(ferroday_cage::IdMapError::map_write(
                        "a descriptor",
                        errno.into(),
                    ));
                }
            }
        }
    }
}
