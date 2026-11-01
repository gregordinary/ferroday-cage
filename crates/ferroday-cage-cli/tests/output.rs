//! Integration tests for `fcage`'s own writes when their reader has gone.
//!
//! Rust ignores `SIGPIPE`, so a write to a pipe nobody reads fails with `EPIPE`
//! rather than ending the process. Each test hands the built binary a pipe
//! whose read end is already closed, on the stream the case writes to, and
//! checks the exit code a shell reads: 141 where the write was what the run was
//! for or work remained, and the outcome's own code where the line only
//! reported it. Never 101, the code of a panic.

mod common;

use std::process::{Command, Output, Stdio};
use std::time::Duration;

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// How long one run may take before its test fails.
const PATIENCE: Duration = Duration::from_secs(60);

/// What a process `SIGPIPE` killed exits with, as a shell reports it.
const READER_GONE: i32 = 141;

/// The write end of a pipe whose reader has already gone.
fn closed_pipe() -> Stdio {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    Stdio::from(writer)
}

/// Runs `fcage` with `args`, standard output on `stdout` and standard error on
/// `stderr`.
fn fcage(args: &[&str], stdout: Stdio, stderr: Stdio) -> Output {
    common::run_bounded(
        Command::new(FCAGE)
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr),
        PATIENCE,
    )
}

#[test]
fn the_help_and_the_version_end_quietly_when_their_reader_has_gone() {
    // `(sleep .2; fcage --help) | true` is the shape: the reader is gone
    // before the first write.
    for flag in ["--help", "--version"] {
        let output = fcage(&[flag], closed_pipe(), Stdio::piped());
        assert_eq!(output.status.code(), Some(READER_GONE), "{flag}");
        assert!(
            output.stderr.is_empty(),
            "{flag}: {}",
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn a_report_of_how_the_run_ended_keeps_its_code_without_a_reader() {
    // A usage error is still one when nobody reads why.
    let output = fcage(&["--no-such-flag"], Stdio::null(), closed_pipe());
    assert_eq!(output.status.code(), Some(2));
    // And so is a failure of fcage's own: no tree at the path to export.
    let missing = common::scratch_dir("fcage-output-missing").join("absent");
    let output = fcage(
        &[
            "--export-rootfs",
            missing.to_str().expect("a UTF-8 scratch path"),
            "--export-to",
            "/dev/null",
        ],
        Stdio::null(),
        closed_pipe(),
    );
    assert_eq!(output.status.code(), Some(125));
}

#[test]
fn a_line_before_the_launch_with_no_reader_stops_the_launch() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // A publication on port 0 reports the port the kernel chose before the
    // command is released. With nobody to read it the run stops there, and the
    // command, which would leave a mark in a directory the test can see, never
    // runs.
    let marks = common::scratch_dir("fcage-output-launch");
    let output = fcage(
        &[
            "--rootfs",
            rootfs.to_str().expect("a UTF-8 fixture path"),
            "--netstack",
            "--no-resolv-conf",
            "--netstack-publish",
            "0",
            "8080",
            "--bind",
            marks.to_str().expect("a UTF-8 scratch path"),
            "/mnt",
            "--",
            "/bin/touch",
            "/mnt/ran",
        ],
        Stdio::piped(),
        closed_pipe(),
    );
    assert_eq!(output.status.code(), Some(READER_GONE), "{output:?}");
    assert!(
        !marks.join("ran").exists(),
        "the command ran with nobody reading the port it was published on",
    );
}

#[test]
fn a_terminal_session_whose_reader_has_gone_ends_with_it() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The relay copies the session's output to fcage's standard output. With
    // nobody reading it, the session ends at the first copy rather than at the
    // command's leisure, and the run reports the reader gone.
    let output = fcage(
        &[
            "--rootfs",
            rootfs.to_str().expect("a UTF-8 fixture path"),
            "--terminal",
            "--",
            "/bin/sh",
            "-c",
            "echo marker; sleep 30",
        ],
        closed_pipe(),
        Stdio::piped(),
    );
    assert_eq!(output.status.code(), Some(READER_GONE), "{output:?}");
}
