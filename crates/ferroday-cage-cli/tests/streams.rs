//! Integration tests for `fcage`'s relay of a standard stream that is a file.
//!
//! A sandboxed command handed a file as a standard stream could reopen it
//! through `/proc/self/fd/N` with more access than the stream was opened with.
//! `fcage` gives the command a pipe instead and copies between the two, so most
//! tests here hand the built binary a file on one stream, have the command try
//! the reopen, and check the file afterwards. The rest hold the relay to the
//! stream's other contracts: the order the command wrote in, the input it did
//! not read, and the kinds of stream it refuses.
//!
//! The sandbox tests skip explicitly, on stderr, on a host that cannot create
//! unprivileged user namespaces, and the restriction tests on a kernel that
//! offers no seccomp. Every run is bounded, so a relay that never finishes
//! fails its test rather than hanging the suite.

mod common;

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// How long one run may take before its test fails. Far beyond what any run
/// here needs; it exists so a relay that never finishes is a failure.
const PATIENCE: Duration = Duration::from_secs(60);

/// Runs `command` to its end, with its streams as configured, and returns what
/// it wrote to those that are piped. Fails the test if the run outlasts
/// [`PATIENCE`].
fn run_bounded(mut command: Command) -> Output {
    common::run_bounded(&mut command, PATIENCE)
}

/// `fcage --rootfs <fixture> [extra] -- /bin/sh -c <script>`.
fn cage_sh(rootfs: &Path, extra: &[&str], script: &str) -> Command {
    let mut command = Command::new(FCAGE);
    command
        .args(["--rootfs", rootfs.to_str().expect("a UTF-8 fixture path")])
        .args(extra)
        .args(["--", "/bin/sh", "-c", script]);
    command
}

/// `fcage --restrict --seccomp curated -- /bin/sh -c <script>`, when the
/// kernel offers seccomp to confine it with.
fn restricted_sh(script: &str) -> Option<Command> {
    if !common::require::seccomp(ferroday_cage::host::seccomp_available()) {
        return None;
    }
    let mut command = Command::new(FCAGE);
    command
        .args(["--restrict", "--seccomp", "curated"])
        .args(["--", "/bin/sh", "-c", script]);
    Some(command)
}

/// The reopen that rewrites a standard input handed over as a file, tried
/// through every descriptor that could still name the file: the command's own,
/// and `fcage`'s, and those of the launch's processes between the two.
///
/// The walk climbs the command's ancestors for as long as they are `fcage` or a
/// process forked from it, which carry its name, and stops at the first that is
/// not, so the test reaches nothing of the harness that runs it. A reopen
/// `fcage` refuses fails with `EACCES`, which the loop does not report.
const REWRITE_STDIN: &str = r#"
p=$$
while :; do
    p=$(awk '/^PPid:/ { print $2 }' /proc/$p/status)
    [ "$(cat /proc/$p/comm 2>/dev/null)" = fcage ] || break
    echo rewritten > /proc/$p/fd/0
done 2>/dev/null
echo rewritten > /proc/self/fd/0
cat
"#;

/// Runs `command` with `input` as its standard input and returns what it wrote
/// to standard output, after checking it exited successfully.
fn run_with_input(mut command: Command, input: &Path) -> String {
    command
        .stdin(File::open(input).expect("the input opens"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_bounded(command);
    assert!(
        output.status.success(),
        "{}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("UTF-8 output")
}

/// Writes `contents` to a file named `name` in a scratch directory of its own.
fn scratch_file(dir: &str, name: &str, contents: &str) -> std::path::PathBuf {
    let path = common::scratch_dir(dir).join(name);
    std::fs::write(&path, contents).expect("the scratch file is writable");
    path
}

#[test]
fn a_file_on_standard_input_cannot_be_rewritten_by_a_cage() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Without a PID namespace the command sees `fcage` and the launch stage on
    // the host's procfs, so the walk reaches their descriptors. The user
    // namespace between them is what refuses the reopen there.
    for extra in [&[][..], &["--share-pid"][..]] {
        let input = scratch_file("fcage-stdin-file", "input", "the original\n");

        let read = run_with_input(cage_sh(rootfs, extra, REWRITE_STDIN), &input);

        assert_eq!(
            std::fs::read_to_string(&input).expect("the input is readable"),
            "the original\n",
            "the command reached the file behind its standard input ({extra:?})",
        );
        // The input still arrived: the command read the file's bytes through
        // the pipe that stood in for it. The reopen landed in that pipe, which
        // is what a reopen of a pipe reaches, so the command reads its own
        // write after them.
        assert_eq!(read, "the original\nrewritten\n", "{extra:?}");
    }
}

#[test]
fn a_file_on_standard_input_cannot_be_rewritten_by_a_restriction() {
    let Some(command) = restricted_sh(REWRITE_STDIN) else {
        return;
    };
    let input = scratch_file("fcage-restrict-stdin-file", "input", "the original\n");

    // A seccomp-only restriction enrolls no Landlock grant, and it shares the
    // host's namespaces with `fcage`, so the reopen through `fcage`'s own
    // descriptor is refused only because `fcage` is not dumpable.
    let read = run_with_input(command, &input);

    assert_eq!(
        std::fs::read_to_string(&input).expect("the input is readable"),
        "the original\n",
        "the command reached the file behind its standard input",
    );
    assert_eq!(read, "the original\nrewritten\n");
}

#[test]
fn a_file_on_standard_output_cannot_be_truncated_by_a_cage() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let log = scratch_file("fcage-stdout-file", "log", "written before the run\n");

    // The log is opened for appending, the way a shell's `>>` opens it. The
    // reopen for writing truncates whatever it reaches, and a relayed stream
    // reaches a pipe, where truncation means nothing.
    let mut command = cage_sh(
        rootfs,
        &[],
        ": > /proc/$$/fd/1; echo written by the command",
    );
    command.stdin(Stdio::null()).stdout(
        OpenOptions::new()
            .append(true)
            .open(&log)
            .expect("the log opens"),
    );
    let output = run_bounded(command);
    assert!(output.status.success(), "{}", output.status);

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
    let out = common::scratch_dir("fcage-stdout-large").join("out");

    // Far past a pipe's 64 KiB, so the relay has to keep draining while the
    // command runs rather than collect everything at the end.
    let mut command = cage_sh(rootfs, &[], "seq 1 200000");
    command
        .stdin(Stdio::null())
        .stdout(File::create(&out).expect("the output file is creatable"));
    let output = run_bounded(command);
    assert!(output.status.success(), "{}", output.status);

    let written = std::fs::read_to_string(&out).expect("the output is readable");
    assert_eq!(written.lines().count(), 200_000);
    assert_eq!(written.lines().last(), Some("200000"));
}

#[test]
fn both_output_streams_on_one_file_keep_the_order_they_were_written_in() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("fcage-output-order");
    let script = "i=0; while [ $i -lt 200 ]; do echo out $i; echo err $i >&2; i=$((i+1)); done";
    let expected: String = (0..200).map(|i| format!("out {i}\nerr {i}\n")).collect();

    // `> log 2>&1`, one open shared by both streams; and `>> log 2>> log`, two
    // opens of one file. Either way two pipes would deliver each stream's
    // writes in order but not the two streams' writes relative to each other.
    let shared = File::create(dir.join("shared")).expect("the log is creatable");
    let appended = || {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("appended"))
            .expect("the log opens")
    };
    for (log, stdout, stderr) in [
        (
            "shared",
            shared.try_clone().expect("the log duplicates"),
            shared,
        ),
        ("appended", appended(), appended()),
    ] {
        let mut command = cage_sh(rootfs, &[], script);
        command.stdin(Stdio::null()).stdout(stdout).stderr(stderr);
        let output = run_bounded(command);
        assert!(output.status.success(), "{}", output.status);
        assert_eq!(
            std::fs::read_to_string(dir.join(log)).expect("the log is readable"),
            expected,
            "the {log} log lost the order the command wrote in",
        );
    }
}

#[test]
fn input_a_command_did_not_read_is_left_for_the_next_reader() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let input = scratch_file("fcage-stdin-unread", "hosts", "alpha\nbeta\ngamma\n");
    let shell = |script: &str| {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script])
            .env("FCAGE", FCAGE)
            .env("ROOTFS", rootfs)
            .env("INPUT", &input)
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        String::from_utf8(run_bounded(command).stdout).expect("UTF-8 output")
    };

    // The loop reads one line, and each fcage it runs must leave the rest:
    // a relay that read ahead and kept what it read ends the loop after the
    // first line.
    assert_eq!(
        shell(
            r#"while read -r h; do "$FCAGE" --rootfs "$ROOTFS" -- /bin/echo "processing $h"; done < "$INPUT""#
        ),
        "processing alpha\nprocessing beta\nprocessing gamma\n",
    );
    // A command that reads part of its input leaves the next reader exactly
    // where it stopped.
    assert_eq!(
        shell(
            r#"{ "$FCAGE" --rootfs "$ROOTFS" -- /bin/sh -c 'read x; echo "the command read $x"'; cat; } < "$INPUT""#
        ),
        "the command read alpha\nbeta\ngamma\n",
    );
    // A launch that fails, at the exec or before the sandbox is built, read
    // nothing of it.
    for launch in [
        r#""$FCAGE" --rootfs "$ROOTFS" -- /nonexistent"#,
        r#""$FCAGE" --rootfs "$INPUT.missing" -- /bin/true"#,
    ] {
        assert_eq!(
            shell(&format!(r#"{{ {launch} 2>/dev/null; cat; }} < "$INPUT""#)),
            "alpha\nbeta\ngamma\n",
            "after {launch}",
        );
    }
}

#[test]
fn an_input_the_relay_cannot_read_fails_the_run_after_the_commands_output() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("fcage-stdin-unreadable");
    std::fs::write(dir.join("input"), "unread\n").expect("the input is writable");
    let log = dir.join("log");

    // Opened for writing only, so the relay's first read is refused. The
    // command sees its input end there, and the run reports what it lost, after
    // everything the command wrote to the same relayed stream.
    let mut command = cage_sh(rootfs, &[], "cat; echo the command finished >&2");
    command
        .stdin(
            OpenOptions::new()
                .write(true)
                .open(dir.join("input"))
                .expect("the input opens"),
        )
        .stderr(File::create(&log).expect("the log is creatable"));
    let output = run_bounded(command);
    assert_eq!(output.status.code(), Some(125), "{}", output.status);
    assert!(output.stdout.is_empty());
    let logged = std::fs::read_to_string(&log).expect("the log is readable");
    let (first, rest) = logged.split_once('\n').expect("the log holds two lines");
    assert_eq!(first, "the command finished");
    assert!(
        rest.starts_with("fcage: relaying the command's standard input: "),
        "{logged:?}",
    );
}

#[test]
fn a_directory_is_refused_on_any_standard_stream() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("fcage-stream-directory");
    std::fs::write(dir.join("secret"), "host secret\n").expect("the secret is writable");
    let probe = "ls /proc/self/fd/0/ /proc/self/fd/1/; cat /proc/self/fd/0/secret";

    let mut launches = vec![("a sandbox", cage_sh(rootfs, &[], probe))];
    if let Some(restricted) = restricted_sh(probe) {
        launches.push(("a restriction", restricted));
    }
    for (launch, mut command) in launches {
        command
            .stdin(File::open(&dir).expect("the directory opens"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = run_bounded(command);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(125), "{launch}: {stderr}");
        assert!(output.stdout.is_empty(), "{launch} ran the command");
        assert!(
            stderr.contains("standard input is a directory"),
            "{launch}: {stderr}",
        );
    }

    // The output pair is judged the same way.
    let mut command = cage_sh(rootfs, &[], probe);
    command
        .stdin(Stdio::null())
        .stdout(File::open(&dir).expect("the directory opens"))
        .stderr(Stdio::piped());
    let output = run_bounded(command);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(125), "{stderr}");
    assert!(
        stderr.contains("standard output is a directory"),
        "{stderr}"
    );

    // A directory that is not handed over is no concern of the relay's.
    let mut command = cage_sh(rootfs, &["--stdin", "null"], "true");
    command.stdin(File::open(&dir).expect("the directory opens"));
    let output = run_bounded(command);
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn a_process_that_outlives_the_command_does_not_hold_the_run_open() {
    // A restriction has no PID namespace, so a background process the command
    // started survives it and keeps the relay's pipe open. The run still ends
    // with the command, carrying what the command wrote.
    let Some(mut command) = restricted_sh("sleep 60 & echo from the command") else {
        return;
    };
    let out = common::scratch_dir("fcage-restrict-survivor").join("out");

    let started = Instant::now();
    command
        .stdin(Stdio::null())
        .stdout(File::create(&out).expect("the output file is creatable"));
    let output = run_bounded(command);
    let took = started.elapsed();

    assert!(output.status.success(), "{}", output.status);
    assert!(
        took < Duration::from_secs(30),
        "the run waited {took:?} on a process that outlived the command",
    );
    assert_eq!(
        std::fs::read_to_string(&out).expect("the output is readable"),
        "from the command\n",
    );
}
