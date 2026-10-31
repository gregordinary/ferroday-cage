//! Integration tests for `fcage`'s relay of a standard stream that is a file.
//!
//! A sandboxed command handed a file as a standard stream could reopen it
//! through `/proc/self/fd/N` with more access than the stream was opened with.
//! `fcage` gives the command a pipe instead and copies between the two, so each
//! test hands the built binary a file on one stream, has the command try the
//! reopen, and checks the file afterwards.
//!
//! The cage tests skip explicitly, on stderr, on a host that cannot create
//! unprivileged user namespaces, and the restriction tests on a kernel that
//! offers no seccomp.

mod common;

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// `fcage --rootfs <fixture> -- /bin/sh -c <script>`.
fn cage_sh(rootfs: &Path, script: &str) -> Command {
    let mut command = Command::new(FCAGE);
    command
        .args(["--rootfs", rootfs.to_str().expect("a UTF-8 fixture path")])
        .args(["--", "/bin/sh", "-c", script]);
    command
}

/// `fcage --restrict --seccomp curated -- /bin/sh -c <script>`, when the
/// kernel offers seccomp to confine it with.
fn restricted_sh(script: &str) -> Option<Command> {
    if !ferroday_cage::host::seccomp_available() {
        assert!(
            std::env::var_os("FERRODAY_CAGE_REQUIRE_SECCOMP").is_none(),
            "seccomp is required but the kernel offers none",
        );
        eprintln!("skipping: the kernel offers no seccomp support");
        return None;
    }
    let mut command = Command::new(FCAGE);
    command
        .args(["--restrict", "--seccomp", "curated"])
        .args(["--", "/bin/sh", "-c", script]);
    Some(command)
}

/// The reopen that rewrites a standard input handed over as a file.
const REWRITE_STDIN: &str = "echo rewritten > /proc/self/fd/0; cat";

/// Runs `command` with `input` as its standard input and returns what it wrote
/// to standard output, after checking it exited successfully.
fn run_with_input(mut command: Command, input: &Path) -> String {
    let output = command
        .stdin(File::open(input).expect("the input opens"))
        .stderr(Stdio::inherit())
        .output()
        .expect("fcage runs");
    assert!(output.status.success(), "{}", output.status);
    String::from_utf8(output.stdout).expect("UTF-8 output")
}

#[test]
fn a_file_on_standard_input_cannot_be_rewritten_by_a_cage() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("fcage-stdin-file");
    let input = dir.join("input");
    std::fs::write(&input, "the original\n").expect("the input is writable");

    let read = run_with_input(cage_sh(rootfs, REWRITE_STDIN), &input);

    assert_eq!(
        std::fs::read_to_string(&input).expect("the input is readable"),
        "the original\n",
        "the command reached the file behind its standard input",
    );
    // The input still arrived: the command read the file's bytes through the
    // pipe that stood in for it. The reopen landed in that pipe, which is what
    // a reopen of a pipe reaches, so the command reads its own write after them.
    assert_eq!(read, "the original\nrewritten\n");
}

#[test]
fn a_file_on_standard_output_cannot_be_truncated_by_a_cage() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("fcage-stdout-file");
    let log = dir.join("log");
    std::fs::write(&log, "written before the run\n").expect("the log is writable");

    // The log is opened for appending, the way a shell's `>>` opens it. The
    // reopen for writing truncates whatever it reaches, and a relayed stream
    // reaches a pipe, where truncation means nothing.
    let status = cage_sh(rootfs, ": > /proc/$$/fd/1; echo written by the command")
        .stdin(Stdio::null())
        .stdout(
            OpenOptions::new()
                .append(true)
                .open(&log)
                .expect("the log opens"),
        )
        .status()
        .expect("fcage runs");
    assert!(status.success(), "{status}");

    assert_eq!(
        std::fs::read_to_string(&log).expect("the log is readable"),
        "written before the run\nwritten by the command\n",
    );
}

#[test]
fn output_larger_than_a_pipe_arrives_whole() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("fcage-stdout-large");
    let out = dir.join("out");

    // Far past a pipe's 64 KiB, so the relay has to keep draining while the
    // command runs rather than collect everything at the end.
    let status = cage_sh(rootfs, "seq 1 200000")
        .stdin(Stdio::null())
        .stdout(File::create(&out).expect("the output file is creatable"))
        .status()
        .expect("fcage runs");
    assert!(status.success(), "{status}");

    let written = std::fs::read_to_string(&out).expect("the output is readable");
    assert_eq!(written.lines().count(), 200_000);
    assert_eq!(written.lines().last(), Some("200000"));
}

#[test]
fn a_file_on_standard_input_cannot_be_rewritten_by_a_restriction() {
    let Some(command) = restricted_sh(REWRITE_STDIN) else {
        return;
    };
    let dir = common::scratch_dir("fcage-restrict-stdin-file");
    let input = dir.join("input");
    std::fs::write(&input, "the original\n").expect("the input is writable");

    // A seccomp-only restriction enrolls no Landlock grant, so nothing but the
    // relay stands between the command and the file.
    let read = run_with_input(command, &input);

    assert_eq!(
        std::fs::read_to_string(&input).expect("the input is readable"),
        "the original\n",
        "the command reached the file behind its standard input",
    );
    assert_eq!(read, "the original\nrewritten\n");
}

#[test]
fn a_process_that_outlives_the_command_does_not_hold_the_run_open() {
    // A restriction has no PID namespace, so a background process the command
    // started survives it and keeps the relay's pipe open. The run still ends
    // with the command, carrying what the command wrote.
    let Some(mut command) = restricted_sh("sleep 60 & echo from the command") else {
        return;
    };
    let dir = common::scratch_dir("fcage-restrict-survivor");
    let out = dir.join("out");

    let started = Instant::now();
    let status = command
        .stdin(Stdio::null())
        .stdout(File::create(&out).expect("the output file is creatable"))
        .status()
        .expect("fcage runs");
    let took = started.elapsed();

    assert!(status.success(), "{status}");
    assert!(
        took < Duration::from_secs(30),
        "the run waited {took:?} on a process that outlived the command",
    );
    assert_eq!(
        std::fs::read_to_string(&out).expect("the output is readable"),
        "from the command\n",
    );
}
