//! Integration tests for an interrupted provisioning run.
//!
//! A run provisions from a tarball the test writes into a named pipe, so the
//! test decides where the run stands when its `SIGINT` arrives: past the
//! archive's first entry, with the rest not yet written. The interrupt asks the
//! run to stop at its next clean point, which removes what it staged, and
//! `fcage` then ends by the signal, as a process `^C` ends does.
//!
//! Nothing here builds a sandbox, so nothing skips. Every run is bounded, so a
//! run that never finishes fails its test rather than hanging the suite.

mod common;

use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal};

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// How long one run may take before its test fails. Far beyond what any run
/// here needs; it exists so a run that never finishes is a failure.
const PATIENCE: Duration = Duration::from_secs(60);

/// The tar block, the unit a header and an entry's data are written in.
const BLOCK: usize = 512;

/// A provisioning run fed through a named pipe the test writes.
struct Run {
    /// Where the run publishes its root.
    root: PathBuf,
    /// The staging tree a run fills beside the root before it publishes.
    staging: PathBuf,
    fcage: Child,
    /// The pipe's writing end, once the run has opened its reading end.
    archive: File,
    /// The rest of the archive, written by [`Run::write_rest`].
    rest: Vec<u8>,
}

impl Run {
    /// Starts `fcage --provision-tar` from a named pipe, under `shell` where
    /// one is given, and writes the archive's first entry once the run has
    /// opened the pipe.
    fn start(name: &str, shell: Option<&str>) -> Run {
        let dir = common::scratch_dir(name);
        let pipe = dir.join("root.tar");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &pipe,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .expect("the pipe is made");
        let root = dir.join("root");
        let archive = common::Tar::new()
            .dir("etc", 0o755)
            .file("etc/hostname", 0o644, b"interrupted\n")
            .file("etc/motd", 0o644, b"never published\n")
            .finish();
        let mut command = match shell {
            Some(script) => {
                let mut command = Command::new("/bin/sh");
                command.args(["-c", script, FCAGE]);
                command
            }
            None => Command::new(FCAGE),
        };
        command
            .arg("--rootfs")
            .arg(&root)
            .arg("--provision-tar")
            .arg(&pipe)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let fcage = common::spawn_grouped(&mut command);
        let mut archive_end = open_when_read(&pipe);
        // The first entry alone, a directory's header, which the run extracts
        // into its staging tree before it waits for the next.
        archive_end
            .write_all(&archive[..BLOCK])
            .expect("the first entry is written");
        Run {
            staging: dir.join(".root.staging"),
            root,
            fcage,
            archive: archive_end,
            rest: archive[BLOCK..].to_vec(),
        }
    }

    /// Waits until the run has extracted the first entry into its staging
    /// tree, so it is part way through the archive.
    fn await_first_entry(&self) {
        let deadline = Instant::now() + PATIENCE;
        while !self.staging.join("etc").is_dir() {
            assert!(
                Instant::now() < deadline,
                "the run never extracted its first entry",
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Sends the run `SIGINT`.
    fn interrupt(&self) {
        let pid = i32::try_from(self.fcage.id()).expect("a pid fits an i32");
        let pid = Pid::from_raw(pid).expect("a pid is positive");
        rustix::process::kill_process(pid, Signal::INT).expect("the run is signalled");
    }

    /// Waits until the run has taken the interrupt, which its hold's thread,
    /// named `interrupt`, records before it unblocks `SIGINT` on itself.
    ///
    /// The run reads the interrupt at its next clean point, and the rest of
    /// the archive is what brings it to one, so it is written only once the
    /// interrupt is known to be there to read.
    fn await_interrupt_taken(&self) {
        let deadline = Instant::now() + PATIENCE;
        while !self.interrupt_taken() {
            assert!(
                Instant::now() < deadline,
                "the run never took its interrupt"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Whether the run's `interrupt` thread no longer blocks `SIGINT`.
    fn interrupt_taken(&self) -> bool {
        let tasks = format!("/proc/{}/task", self.fcage.id());
        let Ok(tasks) = std::fs::read_dir(tasks) else {
            return false;
        };
        tasks.flatten().any(|task| {
            let named = std::fs::read_to_string(task.path().join("comm"))
                .is_ok_and(|comm| comm.trim_end() == "interrupt");
            named
                && std::fs::read_to_string(task.path().join("status")).is_ok_and(|status| {
                    status
                        .lines()
                        .find_map(|line| line.strip_prefix("SigBlk:"))
                        .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
                        .is_some_and(|mask| mask & (1 << (Signal::INT.as_raw() - 1)) == 0)
                })
        })
    }

    /// Writes the rest of the archive. A run that has stopped reading has
    /// closed the pipe, and the write then fails, which is the run's to
    /// report rather than this.
    fn write_rest(&mut self) {
        let _ = self.archive.write_all(&self.rest);
    }

    /// Closes the pipe and waits for the run to end.
    fn finish(self) -> (Output, PathBuf, PathBuf) {
        drop(self.archive);
        let output = common::finish_bounded(self.fcage, PATIENCE);
        (output, self.root, self.staging)
    }
}

/// Opens `pipe` for writing once a reader has opened it, failing the test
/// past [`PATIENCE`] rather than waiting on a run that never opens it.
fn open_when_read(pipe: &Path) -> File {
    let deadline = Instant::now() + PATIENCE;
    loop {
        // Without a reader, a non-blocking open of a pipe for writing fails
        // with `ENXIO` rather than waiting for one.
        match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(pipe)
        {
            Ok(file) => return file,
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::NXIO.raw_os_error()) => {
                assert!(
                    Instant::now() < deadline,
                    "the run never opened its archive"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("the pipe opens for writing: {error}"),
        }
    }
}

#[test]
fn an_interrupted_run_removes_what_it_staged_and_ends_by_the_signal() {
    let mut run = Run::start("fcage-provision-interrupted", None);
    run.await_first_entry();
    run.interrupt();
    run.await_interrupt_taken();
    // The next entry is the run's next clean point, where it reads the
    // interrupt and stops.
    run.write_rest();
    let (output, root, staging) = run.finish();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.signal(),
        Some(Signal::INT.as_raw()),
        "{stderr}"
    );
    assert!(
        !staging.exists(),
        "the interrupted run left its staging tree"
    );
    assert!(!root.exists(), "the interrupted run published a root");
}

#[test]
fn a_second_interrupt_ends_a_run_that_has_not_reached_a_clean_point() {
    // The run waits on the pipe for its next entry, which never comes, so it
    // never reaches the point where it would stop. The second interrupt ends
    // it as an interrupt ends a process.
    let run = Run::start("fcage-provision-interrupted-twice", None);
    run.await_first_entry();
    run.interrupt();
    run.interrupt();
    let deadline = Instant::now() + PATIENCE;
    // The first is read before the second arrives, by a thread that watches
    // for it, so the second has the signal's own effect. Until the first is
    // read both are held, and the run is sent another until it ends.
    while !ended(&run.fcage) {
        assert!(Instant::now() < deadline, "the run outlived two interrupts");
        std::thread::sleep(Duration::from_millis(50));
        run.interrupt();
    }
    let (output, _, _) = run.finish();
    assert_eq!(output.status.signal(), Some(Signal::INT.as_raw()));
}

#[test]
fn a_run_that_ignores_interrupts_is_not_stopped_by_one() {
    // A shell gives a command it runs in the background an ignored SIGINT,
    // and an ignored signal stops nothing.
    let mut run = Run::start(
        "fcage-provision-ignoring",
        Some("trap '' INT; exec \"$0\" \"$@\""),
    );
    run.await_first_entry();
    run.interrupt();
    run.write_rest();
    let (output, root, staging) = run.finish();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{}: {stderr}", output.status);
    assert!(root.join("etc/motd").is_file(), "the run did not publish");
    assert!(!staging.exists());
}

/// Whether `child` has exited, read from its `/proc` record without reaping
/// it.
fn ended(child: &Child) -> bool {
    std::fs::read_to_string(format!("/proc/{}/stat", child.id())).map_or(true, |stat| {
        stat[stat.rfind(')').map_or(0, |end| end + 1)..]
            .split_whitespace()
            .next()
            == Some("Z")
    })
}
