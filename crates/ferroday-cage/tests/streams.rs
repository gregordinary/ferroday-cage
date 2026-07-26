//! Integration tests for output streaming and the stdin disposition.

mod common;

use std::io::Write;

use ferroday_cage::{Cage, Observer, Progress, Stdin};

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
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "echo to-stdout; echo to-stderr >&2"])
        .build()
        .expect("a valid sandbox configuration")
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
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
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
    /// A whole-stream collector, for the handle path where `output` — which
    /// runs the command to completion — does not apply.
    #[derive(Default)]
    struct Stdout(Vec<u8>);

    impl Observer for Stdout {
        fn stdout(&mut self, chunk: &[u8]) {
            self.0.extend_from_slice(chunk);
        }
    }

    let mut observer = Stdout::default();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "echo spawned"])
        .build()
        .expect("a valid sandbox configuration");
    let mut running = cage
        .spawn_with(&mut observer)
        .expect("the sandbox launches");
    let status = running.wait().expect("the wait completes");
    assert!(status.success());
    assert_eq!(observer.0, b"spawned\n");
}

#[test]
fn launch_progress_milestones_arrive_in_order() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut observer = Milestones::default();
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "true"])
        .build()
        .expect("a valid sandbox configuration")
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
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "echo cloned"])
        .build()
        .expect("a valid sandbox configuration");
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
        .stdin(Stdin::Null)
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
        .stdin(Stdin::from_fd(reader.into()))
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
        .stdin(Stdin::from_fd(reader.into()))
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
        .stdin(Stdin::from_fd(reader.into()))
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
