//! Integration tests for output streaming and the stream dispositions.

mod common;

use std::io::Write;
use std::os::fd::RawFd;

use ferroday_cage::{Cage, Observer, Progress, Stdio};

/// Collects the launch milestones for assertions. The command's own output is
/// what `Cage::output` returns, so only the milestones need an observer.
#[derive(Default)]
struct Milestones {
    progress: Vec<Progress>,
}

impl Observer for Milestones {
    fn progress(&mut self, event: Progress) {
        self.progress.push(event);
    }
}

#[test]
fn stdout_and_stderr_arrive_separately() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let output = common::shell(rootfs, "echo to-stdout; echo to-stderr >&2")
        .output()
        .expect("the sandbox launches");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"to-stdout\n");
    assert_eq!(output.stderr, b"to-stderr\n");
}

#[test]
fn output_beyond_the_pipe_buffer_streams_without_deadlock() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // One megabyte per stream, interleaved: far beyond the kernel's pipe
    // buffer, so the command can only finish if the pump keeps draining
    // both pipes.
    let script = "\
        head -c 500000 /dev/zero; head -c 500000 /dev/zero >&2; \
        head -c 500000 /dev/zero; head -c 500000 /dev/zero >&2";
    let output = common::shell(rootfs, script)
        .output()
        .expect("the sandbox launches");
    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 1_000_000);
    assert_eq!(output.stderr.len(), 1_000_000);
    assert!(output.stdout.iter().all(|byte| *byte == 0));
}

#[test]
fn output_from_the_commands_children_is_captured() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "echo direct; ( echo from-subshell ); /bin/busybox echo from-exec",
        ])
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"direct\nfrom-subshell\nfrom-exec\n");
}

#[test]
fn spawned_output_flows_during_the_handle_wait() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut observer = common::Collect::default();
    let cage = common::shell(rootfs, "echo spawned");
    let mut running = cage
        .spawn_with(&mut observer)
        .expect("the sandbox launches");
    let status = running.wait().expect("the wait completes");
    assert!(status.success());
    assert_eq!(observer.stdout, b"spawned\n");
}

#[test]
fn launch_progress_milestones_arrive_in_order() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut observer = Milestones::default();
    let status = common::shell(rootfs, "true")
        .run_with(&mut observer)
        .expect("the sandbox launches");
    assert!(status.success());
    assert_eq!(
        observer.progress,
        [
            Progress::Launching,
            Progress::Supervised,
            Progress::Executing,
        ],
    );
}

#[test]
fn a_cloned_cage_launches_independently() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = common::shell(rootfs, "echo cloned");
    // The clone launches its own sandbox; the original still launches too.
    let clone = cage.clone();
    let first = clone.output().expect("the clone launches");
    assert!(first.status.success());
    assert_eq!(first.stdout, b"cloned\n");
    let second = cage.output().expect("the original launches");
    assert!(second.status.success());
    assert_eq!(second.stdout, b"cloned\n");
}

#[test]
fn a_null_stdin_reads_immediate_end_of_file() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let output = Cage::builder()
        .rootfs(rootfs)
        .stdin(Stdio::Null)
        .command("/bin/sh")
        .args(["-c", "wc -c"])
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"0\n", "expected zero bytes from stdin");
}

#[test]
fn a_descriptor_stdin_feeds_the_command() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let (reader, mut writer) = std::io::pipe().expect("a pipe");
    let cage = Cage::builder()
        .rootfs(rootfs)
        .stdin(Stdio::from_fd(reader.into()))
        .command("/bin/sh")
        .args(["-c", "cat"])
        .build()
        .expect("a valid sandbox configuration");
    // Write the whole input and close the write end before waiting: the
    // command reads to end-of-file, and the caller is not competing with the
    // output pump for its own thread.
    writer.write_all(b"fed through the descriptor\n").unwrap();
    drop(writer);

    let output = cage.output().expect("the sandbox launches");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"fed through the descriptor\n");
}

#[test]
fn a_descriptor_stdin_survives_the_descriptor_sweep() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Hold several descriptors open before the launch so the pipe read end
    // lands well above the standard-stream numbers, where the sweep would
    // close it unless it is explicitly kept.
    let _padding: Vec<std::fs::File> = (0..8)
        .map(|_| std::fs::File::open("/dev/null").expect("an open descriptor"))
        .collect();
    let (reader, mut writer) = std::io::pipe().expect("a pipe");
    let cage = Cage::builder()
        .rootfs(rootfs)
        .stdin(Stdio::from_fd(reader.into()))
        .command("/bin/sh")
        .args(["-c", "wc -c"])
        .build()
        .expect("a valid sandbox configuration");
    writer.write_all(b"0123456789").unwrap();
    drop(writer);

    let output = cage.output().expect("the sandbox launches");
    assert!(output.status.success());
    assert_eq!(output.stdout.trim_ascii(), b"10");
}

/// Duplicates `fd` onto a number at or above `floor`, leaving close-on-exec
/// clear.
///
/// Clear is `dup`'s own behaviour, and the state a descriptor is in when a
/// caller placed it by hand — `dup2`d onto a fixed number, or inherited from
/// its own parent. A descriptor `std` opened carries close-on-exec already, so
/// it could not show whether the launch closes what it was handed. The number
/// is pushed clear of the low ones so that nothing the command opens for itself
/// can land on it.
fn duplicate_above(fd: std::os::fd::BorrowedFd<'_>, floor: RawFd) -> std::os::fd::OwnedFd {
    use std::os::fd::AsRawFd;
    let mut ladder = Vec::new();
    loop {
        // `dup` rather than the close-on-exec duplicate the library takes:
        // the flag left clear is the state this helper exists to produce.
        #[expect(clippy::disallowed_methods)]
        let duplicate = rustix::io::dup(fd).expect("the descriptor duplicates");
        if duplicate.as_raw_fd() >= floor {
            return duplicate;
        }
        ladder.push(duplicate);
    }
}

#[test]
fn a_caller_descriptor_does_not_survive_the_exec_at_its_own_number() {
    use std::os::fd::{AsFd, AsRawFd};

    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The sweep keeps a caller's descriptor so the command stage can copy it
    // onto a standard stream, and the caller holds it at whatever number it
    // has. Left as it was it would survive the exec there, handing the command
    // a second handle to the caller's file — one it keeps after closing and
    // reopening the standard stream — where the contract is a descriptor table
    // holding only the standard streams.
    let (reader, mut writer) = std::io::pipe().expect("a pipe");
    let (out_reader, out_writer) = std::io::pipe().expect("a pipe");
    // Each duplicate replaces its original outright, so the cage holds the only
    // copy of the write end and the read below ends when the cage is dropped.
    let reader = duplicate_above(reader.as_fd(), 20);
    let out_writer = {
        let duplicate = duplicate_above(out_writer.as_fd(), 20);
        drop(out_writer);
        duplicate
    };
    let (stdin_number, stdout_number) = (reader.as_raw_fd(), out_writer.as_raw_fd());
    let cage = Cage::builder()
        .rootfs(rootfs)
        .stdin(Stdio::from_fd(reader))
        .stdout(Stdio::from_fd(out_writer))
        .command("/bin/sh")
        // The listing goes to the caller's own pipe through standard output,
        // which is a descriptor the command was given and is meant to hold.
        .args(["-c", "ls /proc/self/fd"])
        .build()
        .expect("a valid sandbox configuration");
    writer.write_all(b"unread\n").unwrap();
    drop(writer);

    let status = cage.run().expect("the sandbox launches");
    assert!(status.success());
    // The cage holds the only remaining copies of the write end, so the read
    // below sees end-of-file once it is gone.
    drop(cage);
    let mut listing = String::new();
    std::io::Read::read_to_string(&mut { out_reader }, &mut listing).expect("the listing arrives");
    let held: Vec<RawFd> = listing
        .split_ascii_whitespace()
        .filter_map(|entry| entry.parse().ok())
        .collect();
    for number in [stdin_number, stdout_number] {
        assert!(
            !held.contains(&number),
            "the caller's descriptor {number} survived the exec: {listing:?}",
        );
    }
    // `ls` opens the listed directory itself, so one entry above the standard
    // streams is its own and anything more is a leak.
    assert!(
        held.iter().filter(|number| **number > 2).count() <= 1,
        "a descriptor beyond the standard streams survived the exec: {listing:?}",
    );
}

#[test]
fn a_shared_stdin_descriptor_serves_repeated_launches() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A cage is a frozen plan that can launch many times, so the descriptor is
    // shared rather than consumed: the second launch resumes where the first
    // left off. `dd bs=1` reads a byte at a time, so the first command takes
    // exactly what it asks for rather than buffering the rest away. This
    // documents the sharing rather than recommending it.
    let (reader, mut writer) = std::io::pipe().expect("a pipe");
    let cage = Cage::builder()
        .rootfs(rootfs)
        .stdin(Stdio::from_fd(reader.into()))
        .command("/bin/sh")
        .args(["-c", "dd bs=1 count=5 2>/dev/null"])
        .build()
        .expect("a valid sandbox configuration");
    writer.write_all(b"firstsecond").unwrap();
    drop(writer);

    let first = cage.output().expect("the first launch");
    assert_eq!(first.stdout, b"first");
    let second = cage.output().expect("the second launch");
    assert_eq!(second.stdout, b"secon");
}

/// The controlling-terminal number from `/proc/self/stat`: field 7, read from
/// after the closing parenthesis so a `comm` holding spaces cannot shift it.
/// The remainder opens with a separator, so `tty_nr` is the sixth `cut` field
/// of it. Zero means the process has no controlling terminal.
const TTY_NR: &str = "cut -d')' -f2- /proc/self/stat | cut -d' ' -f6";

#[test]
fn a_sandbox_that_inherits_stdin_keeps_the_callers_controlling_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The test process is the caller here. Under `cargo test` it usually has no
    // controlling terminal of its own, in which case there is nothing for the
    // sandbox to inherit and the assertion below would hold vacuously; skip
    // rather than pretend to have proved something.
    let Some(caller_tty) = common::controlling_terminal(std::process::id()) else {
        common::require::premise_unmet("the test process has no controlling terminal to share");
        return;
    };
    let caller_tty = caller_tty.to_string();

    // Inheriting standard input hands the sandbox the caller's terminal, so it
    // stays in the caller's session and keeps that terminal.
    let output = Cage::builder()
        .rootfs(rootfs)
        .stdin(Stdio::Inherit)
        .command("/bin/sh")
        .args(["-c", TTY_NR])
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    assert_eq!(
        output.stdout.trim_ascii(),
        caller_tty.as_bytes(),
        "an inheriting sandbox shares the caller's controlling terminal",
    );
}

#[test]
fn a_sandbox_that_does_not_inherit_stdin_has_no_controlling_terminal() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A command the caller has not handed its standard input to runs in a
    // session of its own, where there is no controlling terminal to reach: no
    // `/dev/tty` to open, and no terminal `TIOCSTI` is granted for. This holds
    // whether or not the caller has a terminal at all, so it needs no skip.
    for stdin in [Stdio::Null, Stdio::from_fd(open_null())] {
        let output = Cage::builder()
            .rootfs(rootfs)
            .stdin(stdin)
            .command("/bin/sh")
            .args(["-c", TTY_NR])
            .build()
            .expect("a valid sandbox configuration")
            .output()
            .expect("the sandbox launches");
        assert_eq!(
            output.stdout.trim_ascii(),
            b"0",
            "a sandbox in its own session has no controlling terminal",
        );
    }
}

#[test]
fn a_sandbox_in_its_own_session_cannot_open_dev_tty() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // `/dev/tty` is still bound — it is the magic device 5:0, which conveys no
    // terminal of its own — and opening it now fails, because the sandbox's
    // session has no controlling terminal for it to resolve to.
    let output = Cage::builder()
        .rootfs(rootfs)
        .stdin(Stdio::Null)
        .command("/bin/sh")
        .args(["-c", "exec 3</dev/tty"])
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    assert!(
        !output.status.success(),
        "opening /dev/tty must fail without a controlling terminal",
    );
}

/// An owned descriptor for `/dev/null`, for the caller-supplied stdin case.
fn open_null() -> std::os::fd::OwnedFd {
    std::fs::File::open("/dev/null")
        .expect("/dev/null is openable")
        .into()
}

#[test]
fn a_null_output_stream_is_discarded() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Each output stream is directed on its own, so a sandbox can discard its
    // results and keep its diagnostics. The command reports what its standard
    // output was wired to — `/proc/self/fd` resolves a redirected stream to the
    // file behind it — and writes a line of its own; both go to standard error,
    // which the caller supplies as a pipe.
    let (mut reader, writer) = std::io::pipe().expect("a pipe");
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        // Standard output is saved onto file descriptor 3 first: `>&2` on the
        // `readlink` itself would put the pipe on file descriptor 1 for the
        // duration of that command, and the link read back would name the pipe.
        .args([
            "-c",
            "exec 3>&1; readlink /proc/self/fd/3 >&2; echo err >&2",
        ])
        .stdout(Stdio::Null)
        .stderr(Stdio::from_fd(writer.into()))
        .build()
        .expect("a valid sandbox configuration");
    let status = cage.run().expect("the sandbox launches");
    assert!(status.success());
    // The plan holds the caller's descriptor for its whole life, so the write
    // end closes only once the cage is gone — which is what lets the read below
    // reach end-of-file rather than block.
    drop(cage);

    let mut captured = String::new();
    std::io::Read::read_to_string(&mut reader, &mut captured)
        .expect("the pipe reads to end-of-file");
    let mut lines = captured.lines();
    assert_eq!(
        lines.next(),
        Some("/dev/null"),
        "a null standard output resolves to the null device: {captured:?}",
    );
    assert_eq!(
        lines.next(),
        Some("err"),
        "the descriptor disposition carries what the command wrote: {captured:?}",
    );
}

#[test]
fn a_directed_output_stream_refuses_a_capturing_launch() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Capture supplies a pipe for each output stream, so a sandbox that already
    // directs one somewhere is a contradiction the launch refuses rather than
    // resolves. Standard input is untouched by capture and so never conflicts.
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "echo out"])
        .stdout(Stdio::Null)
        .build()
        .expect("a valid sandbox configuration");
    let err = cage.output().expect_err("a capturing launch is refused");
    assert!(
        matches!(
            err,
            ferroday_cage::Error::Config(
                ferroday_cage::ConfigError::StreamAttachmentConflict { .. }
            )
        ),
        "{err:?}",
    );
    // The same sandbox launches through an entry point that attaches nothing.
    let status = cage.run().expect("a non-capturing launch is not refused");
    assert!(status.success());
}

#[test]
fn a_directory_on_a_standard_stream_is_refused_before_the_launch() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A directory descriptor walks the host's filesystem by path, past the
    // pivoted root, so a command handed one as a stream could reach anything
    // the caller can. The launch refuses it on whichever stream it would land.
    let dir = common::scratch_dir("stream-directory");
    for expected in ["standard input", "standard output", "standard error"] {
        let directory = Stdio::from_fd(
            std::fs::File::open(&dir)
                .expect("the scratch directory opens")
                .into(),
        );
        let builder = Cage::builder().rootfs(rootfs).command("/bin/true");
        let cage = match expected {
            "standard input" => builder.stdin(directory),
            "standard output" => builder.stdout(directory),
            _ => builder.stderr(directory),
        }
        .build()
        .expect("a stream is judged at the launch, not at build");
        match cage.run() {
            Err(ferroday_cage::Error::StreamIsDirectory { stream, .. }) => {
                assert_eq!(stream, expected);
            }
            other => panic!("a directory on the {expected} was not refused: {other:?}"),
        }
    }
}

#[test]
fn the_resolved_record_reports_each_stream_by_kind() {
    use ferroday_cage::ResolvedStdio;

    let cage = Cage::builder()
        .rootfs("/tmp")
        .command("/bin/sh")
        .stdin(Stdio::from_fd(open_null()))
        .stderr(Stdio::Null)
        .build()
        .expect("a valid sandbox configuration");
    let streams = cage.resolved_inputs().streams;
    assert_eq!(streams.stdin, ResolvedStdio::Fd);
    assert_eq!(streams.stdout, ResolvedStdio::Inherit);
    assert_eq!(streams.stderr, ResolvedStdio::Null);
}
