//! Integration tests for `fcage --events`: the run's events, and a standard
//! error left to the command.
//!
//! Each run writes its events to a file in a scratch directory, or to a pipe
//! named as `/dev/fd/3`, and the test reads them back as JSON lines. The
//! sandbox tests skip explicitly, on stderr, on a host that cannot create
//! unprivileged user namespaces, and the report tests on a host without the
//! facility the report needs. Every run is bounded, so a launch that never
//! finishes fails its test rather than hanging the suite.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use serde_json::Value;

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// How long one run may take before its test fails.
const PATIENCE: Duration = Duration::from_secs(60);

/// Runs `fcage` with `args`, its events written to `events`, standard input
/// empty, and both outputs kept.
fn run(args: &[&str], events: &Path) -> Output {
    common::run_bounded(
        Command::new(FCAGE)
            .arg("--events")
            .arg(events)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        PATIENCE,
    )
}

/// The events in `path`, one JSON object per line.
fn events_in(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path).expect("the events are readable");
    parse(&text)
}

/// The events `text` holds, checking each line is one JSON object.
fn parse(text: &str) -> Vec<Value> {
    text.lines()
        .map(|line| {
            let event: Value = serde_json::from_str(line).expect("each line is JSON");
            assert!(
                event["event"].is_string(),
                "an event names its kind: {line}"
            );
            event
        })
        .collect()
}

/// The kinds of `events`, in order.
fn kinds(events: &[Value]) -> Vec<&str> {
    events
        .iter()
        .map(|event| event["event"].as_str().expect("a kind"))
        .collect()
}

/// A fresh file path for a test's events, in a scratch directory of its own.
fn events_path(test: &str) -> PathBuf {
    common::scratch_dir(test).join("events.jsonl")
}

#[test]
fn a_launch_writes_its_events_and_leaves_standard_error_to_the_command() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    let path = events_path("fcage-events-launch");
    let output = run(
        &[
            "--rootfs",
            rootfs,
            "--",
            "/bin/sh",
            "-c",
            "echo out; echo err >&2; exit 3",
        ],
        &path,
    );
    assert_eq!(output.status.code(), Some(3), "{}", output.status);
    assert_eq!(output.stdout, b"out\n");
    assert_eq!(
        output.stderr, b"err\n",
        "standard error is the command's alone"
    );

    let events = events_in(&path);
    assert_eq!(kinds(&events), ["hello", "started", "exited"], "{events:?}");
    assert_eq!(events[0]["protocol"], 1);
    assert_eq!(events[0]["fcage"], env!("CARGO_PKG_VERSION"));
    assert!(events[1]["pid"].as_u64().is_some_and(|pid| pid > 1));
    let exited = &events[2];
    assert_eq!(exited["code"], 3);
    assert_eq!(exited["shell-code"], 3);
    assert_eq!(exited["timed-out"], false);
    assert_eq!(exited["core-dumped"], false);
    assert!(exited.get("signal").is_none(), "{exited}");
    assert!(
        exited["usage"]["peak-rss-bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0),
        "{exited}"
    );
}

#[test]
fn a_pipe_named_as_a_descriptor_carries_the_events() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    // The shell hands fcage its own standard output, a pipe, as descriptor 3,
    // and fcage's standard output goes nowhere: what arrives is the events.
    let script =
        format!("exec {FCAGE} --events /dev/fd/3 --rootfs {rootfs} -- /bin/true 3>&1 >/dev/null");
    let output = common::run_bounded(
        Command::new("/bin/sh")
            .args(["-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        PATIENCE,
    );
    assert!(output.status.success(), "{}", output.status);
    assert!(
        output.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events = parse(&String::from_utf8(output.stdout).expect("UTF-8"));
    assert_eq!(kinds(&events), ["hello", "started", "exited"], "{events:?}");
}

#[test]
fn a_failed_setup_step_is_named_with_its_errno() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    let path = events_path("fcage-events-failed-step");
    let output = run(&["--rootfs", rootfs, "--", "/bin/absent"], &path);
    assert_eq!(output.status.code(), Some(127), "{}", output.status);
    assert!(
        output.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = events_in(&path);
    assert_eq!(kinds(&events), ["hello", "failed"], "{events:?}");
    let failed = &events[1];
    assert_eq!(failed["error"], "setup");
    assert_eq!(failed["step"], "exec");
    assert_eq!(failed["errno"], "ENOENT");
    assert_eq!(failed["shell-code"], 127);
    assert!(
        failed["text"]
            .as_str()
            .is_some_and(|text| text.starts_with("fcage: ") && text.contains("/bin/absent")),
        "{failed}"
    );
}

#[test]
fn an_expired_timeout_is_an_exit_that_timed_out() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    let path = events_path("fcage-events-timeout");
    let output = run(
        &[
            "--rootfs",
            rootfs,
            "--timeout",
            "0.2",
            "--",
            "/bin/sleep",
            "30",
        ],
        &path,
    );
    assert_eq!(output.status.code(), Some(124), "{}", output.status);

    let events = events_in(&path);
    let exited = events.last().expect("an event");
    assert_eq!(exited["event"], "exited");
    assert_eq!(exited["timed-out"], true);
    assert_eq!(exited["shell-code"], 124);
    assert!(
        exited.get("code").is_none() && exited.get("signal").is_none(),
        "{exited}"
    );
}

#[test]
fn a_warning_is_an_event_and_not_a_line() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    let path = events_path("fcage-events-warning");
    let output = run(
        &[
            "--rootfs",
            rootfs,
            "--cgroup",
            "pids-max=64",
            "--no-cgroup-required",
            "--",
            "/bin/true",
        ],
        &path,
    );
    assert!(output.status.success(), "{}", output.status);
    assert!(
        output.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = events_in(&path);
    assert_eq!(
        kinds(&events),
        ["hello", "warning", "started", "exited"],
        "{events:?}"
    );
    assert!(
        events[1]["text"]
            .as_str()
            .is_some_and(|text| text.starts_with("fcage: the cgroup limits are not applied")),
        "{}",
        events[1]
    );
}

#[test]
fn a_usage_error_found_once_the_stream_is_open_is_an_event() {
    let dir = common::scratch_dir("fcage-events-usage");
    let profile = dir.join("profile.toml");
    std::fs::write(&profile, "network = \"host\"\n").expect("the profile is writable");
    let path = dir.join("events.jsonl");
    let output = run(
        &[
            "--profile",
            profile.to_str().expect("UTF-8"),
            "--host-rootfs",
            "--netstack",
            "--",
            "/bin/true",
        ],
        &path,
    );
    assert_eq!(output.status.code(), Some(2), "{}", output.status);
    assert!(
        output.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = events_in(&path);
    assert_eq!(kinds(&events), ["hello", "failed"], "{events:?}");
    assert_eq!(events[1]["error"], "usage");
    assert_eq!(events[1]["shell-code"], 2);
}

#[test]
fn a_stream_that_cannot_be_opened_is_said_on_standard_error() {
    let dir = common::scratch_dir("fcage-events-unopened");
    let fifo = dir.join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .expect("the named pipe is made");
    for (case, path, said) in [
        (
            "a named pipe nothing reads",
            fifo.as_path(),
            "nothing reads it",
        ),
        ("a directory", dir.as_path(), "Is a directory"),
    ] {
        let output = run(&["--host-rootfs", "--", "/bin/true"], path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(125), "{case}: {stderr}");
        assert!(
            stderr.starts_with("fcage: opening ") && stderr.contains(said),
            "{case}: {stderr:?}"
        );
    }
}

#[test]
fn a_seccomp_refusal_is_an_event() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::seccomp() {
        return;
    }
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    let path = events_path("fcage-events-seccomp");
    let output = run(
        &[
            "--rootfs",
            rootfs,
            "--seccomp",
            "curated",
            "--seccomp-reports",
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "mkdir -p /mnt; mount -t tmpfs none /mnt",
        ],
        &path,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("fcage:"), "{stderr:?}");

    let events = events_in(&path);
    let refusal = events
        .iter()
        .find(|event| event["event"] == "seccomp")
        .unwrap_or_else(|| panic!("a seccomp event: {events:?}"));
    assert_eq!(refusal["report"], "denied");
    assert_eq!(refusal["syscall"], "mount");
    assert_eq!(refusal["errno"], "EPERM");
    assert_eq!(
        refusal["arguments"].as_array().map(Vec::len),
        Some(6),
        "{refusal}"
    );
    assert_eq!(events.last().expect("an event")["event"], "exited");
}

#[test]
fn the_network_stacks_refusals_and_publications_are_events() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    let path = events_path("fcage-events-network");
    // 198.51.100.7 is a documentation address no allow rule admits, so the
    // stack refuses the connection at once.
    let output = run(
        &[
            "--rootfs",
            rootfs,
            "--no-resolv-conf",
            "--netstack",
            "--netstack-allow",
            "192.0.2.1:443",
            "--netstack-publish",
            "127.0.0.1:0",
            "8080",
            "--",
            "/bin/sh",
            "-c",
            "nc -w 1 198.51.100.7 80 </dev/null; true",
        ],
        &path,
    );
    assert!(output.status.success(), "{}", output.status);
    assert!(
        output.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = events_in(&path);
    let published = events
        .iter()
        .find(|event| event["event"] == "published")
        .unwrap_or_else(|| panic!("a publication: {events:?}"));
    assert_eq!(published["guest-port"], 8080);
    assert!(
        published["address"]
            .as_str()
            .is_some_and(|address| address.starts_with("127.0.0.1:") && !address.ends_with(":0")),
        "{published}"
    );
    let refused = events
        .iter()
        .find(|event| event["event"] == "network")
        .unwrap_or_else(|| panic!("a refusal: {events:?}"));
    assert_eq!(refused["report"], "flow-refused");
    assert_eq!(refused["transport"], "tcp");
    assert_eq!(refused["destination"], "198.51.100.7:80");
    assert_eq!(refused["refusal"], "not-allowed");
    // The publication is bound before the command is released.
    let at = |kind: &str| events.iter().position(|event| event["event"] == kind);
    assert!(at("published") < at("started"), "{events:?}");
}

#[test]
fn a_restriction_writes_its_events_too() {
    if !(common::require::seccomp()
        && common::require::landlock(ferroday_cage::host::landlock_abi()))
    {
        return;
    }
    let path = events_path("fcage-events-restriction");
    let output = run(
        &[
            "--restrict",
            "--landlock-ro",
            "/",
            "--",
            "/bin/sh",
            "-c",
            "exit 4",
        ],
        &path,
    );
    assert_eq!(output.status.code(), Some(4), "{}", output.status);
    let events = events_in(&path);
    assert_eq!(kinds(&events), ["hello", "started", "exited"], "{events:?}");
    assert_eq!(events[2]["code"], 4);
}

#[test]
fn a_relay_that_fails_after_the_command_ended_is_the_last_event() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    let dir = common::scratch_dir("fcage-events-relay");
    std::fs::write(dir.join("input"), "unread\n").expect("the input is writable");
    let path = dir.join("events.jsonl");
    // Standard input is a file opened for writing only, so fcage relays it and
    // the relay's first read is refused: the command ends well, and the run
    // fails after it.
    let input = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("input"))
        .expect("the input opens");
    let output = common::run_bounded(
        Command::new(FCAGE)
            .arg("--events")
            .arg(&path)
            .args(["--rootfs", rootfs, "--", "/bin/sh", "-c", "cat; exit 0"])
            .stdin(input)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        PATIENCE,
    );
    assert_eq!(output.status.code(), Some(125), "{}", output.status);
    assert!(
        output.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = events_in(&path);
    assert_eq!(
        kinds(&events),
        ["hello", "started", "exited", "failed"],
        "{events:?}"
    );
    assert_eq!(events[2]["shell-code"], 0);
    assert_eq!(events[3]["error"], "relay");
    assert_eq!(events[3]["shell-code"], 125);
    assert!(
        events[3]["text"]
            .as_str()
            .is_some_and(|text| text.starts_with("fcage: relaying the command's standard input: ")),
        "{}",
        events[3]
    );
}
