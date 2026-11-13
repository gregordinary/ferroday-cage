//! Host processes a test starts or watches: whether one still exists, waiting
//! for one to go, what its `stat` record says of it, running one with a bound
//! on how long it may take, and running one test of the test binary again as a
//! process of its own.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use rustix::process::Pid;

/// Whether a process with this pid exists on the host.
pub fn process_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Waits up to `within` for the process `pid` to be gone, and reports whether
/// it went.
///
/// Polled rather than slept for a fixed time, so a test waits only as long as
/// the process takes.
pub fn wait_gone(pid: u32, within: Duration) -> bool {
    let deadline = Instant::now().checked_add(within);
    while process_exists(pid) {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

/// The processor time the process `pid` has used, in clock ticks, or `None`
/// once it is gone.
///
/// What a test holding a loop to blocking measures it by: a loop that blocks
/// uses next to none over a window it waits through, and one that spins uses
/// the whole window.
pub fn cpu_ticks(pid: u32) -> Option<u64> {
    ticks_of(&Stat::of(&format!("/proc/{pid}/stat"))?)
}

/// The processor time the thread `tid` of this process has used, in clock
/// ticks, as [`cpu_ticks`] reads a process's.
pub fn thread_ticks(tid: i32) -> u64 {
    let stat = Stat::of(&format!("/proc/self/task/{tid}/stat"))
        .expect("a thread's statistics are readable");
    ticks_of(&stat).expect("a thread's statistics hold its times")
}

/// The user and system times a `stat` record holds, fields 14 and 15, summed.
fn ticks_of(stat: &Stat) -> Option<u64> {
    Some(stat.number(14)? + stat.number(15)?)
}

/// The state the process `pid` is in, the letter `ps` shows for it: `R`
/// running, `S` sleeping, `T` stopped, `Z` exited and not yet collected, and
/// the rest proc(5) lists. `None` once it is gone.
pub fn process_state(pid: u32) -> Option<char> {
    Stat::of(&format!("/proc/{pid}/stat"))?
        .field(3)?
        .chars()
        .next()
}

/// The parent of the process `pid`, or `None` once it is gone.
pub fn process_parent(pid: u32) -> Option<u32> {
    Stat::of(&format!("/proc/{pid}/stat"))?
        .number(4)?
        .try_into()
        .ok()
}

/// The device number of the process `pid`'s controlling terminal, or `None`
/// where it has none or is gone.
pub fn controlling_terminal(pid: u32) -> Option<u64> {
    Stat::of(&format!("/proc/{pid}/stat"))?
        .number(7)
        .filter(|&tty| tty != 0)
}

/// The value of the field `name` in `status`, the text of a process's `status`
/// record, as a command inside a sandbox reads its own and prints it: what
/// follows `name:` on its line, trimmed.
pub fn status_field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        let (field, value) = line.split_once(':')?;
        (field == name).then_some(value.trim())
    })
}

/// A process's or a thread's `stat` record.
struct Stat(String);

impl Stat {
    /// The record at `path`, or `None` where it cannot be read, as once its
    /// process is gone.
    fn of(path: &str) -> Option<Stat> {
        std::fs::read_to_string(path).ok().map(Stat)
    }

    /// Field `number` of the record, numbered from 1 as proc(5) numbers them.
    ///
    /// The second field is the process's name in parentheses, which may itself
    /// hold spaces and parentheses, so every field after it is counted from
    /// past the last `)`. The first two are not read.
    fn field(&self, number: usize) -> Option<&str> {
        let after_name = &self.0[self.0.rfind(')')? + 1..];
        after_name.split_whitespace().nth(number.checked_sub(3)?)
    }

    /// Field `number` of the record, read as a number.
    fn number(&self, number: usize) -> Option<u64> {
        self.field(number)?.parse().ok()
    }
}

/// The arguments that run one test of a test binary alone: `test` by its exact
/// name, as the harness lists it, on one thread, with what it prints left
/// uncaptured for the process that started it to read.
///
/// For a test binary started where [`rerun`] cannot start it, such as inside a
/// sandbox, as the command a launch executes.
pub fn rerun_args(test: &str) -> [&str; 4] {
    ["--exact", test, "--nocapture", "--test-threads=1"]
}

/// A command that runs this test binary again, for `test` alone, with
/// [`rerun_args`]: a test that changes what is process-wide, or that must stand
/// where a test process cannot, runs its part as a process of its own.
///
/// Its standard input is null and its output is piped, for [`run_bounded`], or
/// [`spawn_grouped`] then [`finish_bounded`], to collect. A test that wants
/// other streams sets them before starting it, and starts it through one of
/// those, or through the pseudoterminal harness's `spawn_controlled` with a
/// deadline of its own, so a run that never ends fails its test rather than
/// hanging the suite.
pub fn rerun(test: &str) -> Command {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let mut command = Command::new(exe);
    command
        .args(rerun_args(test))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Runs `command` to its end and returns what it wrote to whichever of its
/// streams are piped, failing the test if the run outlasts `patience`.
///
/// libtest has no per-test deadline of its own, and a run that never finishes
/// is exactly the failure a relay's tests exist to catch, so it is killed and
/// reported rather than left to hang the suite. The command starts as the
/// leader of a process group of its own, through [`spawn_grouped`], so that
/// what it started dies with it.
#[track_caller]
pub fn run_bounded(command: &mut Command, patience: Duration) -> Output {
    finish_bounded(spawn_grouped(command), patience)
}

/// Starts `command` as the leader of a process group of its own, which is
/// what [`finish_bounded`] needs of the child it bounds.
///
/// A run that outlasts its patience is ended by its group, so whatever it
/// started goes with it, and a process the run left behind holding one of its
/// streams is killed rather than waited on.
#[track_caller]
pub fn spawn_grouped(command: &mut Command) -> Child {
    use std::os::unix::process::CommandExt as _;

    command
        .process_group(0)
        .spawn()
        .expect("the command starts")
}

/// Waits for `child` to end and returns what it wrote to its piped streams,
/// failing the test if the whole of that outlasts `patience`.
///
/// For a test that writes to the child's input first. Its input, where it is
/// piped and the test still holds it, is closed before the wait, so a child
/// reading its input to the end reaches it. `child` leads a process group of
/// its own, as [`spawn_grouped`] starts one. The piped streams are read on
/// threads of their own while the wait runs, so a child whose output fills its
/// pipe is collected rather than mistaken for a hang.
///
/// The patience covers the streams as well as the exit. A stream ends only when
/// every process holding it has gone, and a process the child left behind can
/// hold one open long after the child exited; past the patience, the child's
/// group is killed and the test fails, naming the stream. The child is not
/// reaped until then, so its pid, which names the group, cannot have been
/// reused by the time the group is signalled.
#[track_caller]
pub fn finish_bounded(mut child: Child, patience: Duration) -> Output {
    let pid = pid_of(&child);
    assert_eq!(
        rustix::process::getpgid(Some(pid)),
        Ok(pid),
        "a bounded run is ended by its process group, so the child must lead one; start it \
         with spawn_grouped",
    );
    drop(child.stdin.take());
    let stdout = child.stdout.take().map(collect);
    let stderr = child.stderr.take().map(collect);
    let deadline = Instant::now().checked_add(patience);
    let past = || deadline.is_some_and(|deadline| Instant::now() >= deadline);

    while !exited(pid) {
        if past() {
            end_group(pid, &mut child);
            panic!("the run did not finish within {patience:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut drained = |stream: Option<Receiver<Vec<u8>>>, name: &str| {
        let Some(stream) = stream else {
            return Vec::new();
        };
        let received = match deadline {
            Some(deadline) => {
                stream.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            }
            None => stream.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match received {
            Ok(bytes) => bytes,
            Err(RecvTimeoutError::Timeout) => {
                end_group(pid, &mut child);
                panic!(
                    "the run exited, but its {name} was still open {patience:?} after it \
                     began: a process the run left behind holds it"
                );
            }
            Err(RecvTimeoutError::Disconnected) => panic!("the reader of the run's {name} failed"),
        }
    };
    let stdout = drained(stdout, "standard output");
    let stderr = drained(stderr, "standard error");
    let status = child.wait().expect("the child can be reaped");
    Output {
        status,
        stdout,
        stderr,
    }
}

/// Whether the process `pid`, a child of this one, has exited, without reaping
/// it: its pid stays its own, and the group it names stays signallable.
fn exited(pid: Pid) -> bool {
    use rustix::process::{WaitId, WaitIdOptions};

    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    rustix::process::waitid(WaitId::Pid(pid), options)
        .expect("the child can be waited for")
        .is_some()
}

/// Kills the process group `pid` leads, and reaps its leader, `child`.
fn end_group(pid: Pid, child: &mut Child) {
    // The group may already be empty but for its unreaped leader.
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    let _ = child.wait();
}

/// The pid of a child process, as rustix names one.
fn pid_of(child: &Child) -> Pid {
    let raw = i32::try_from(child.id()).expect("a pid fits an i32");
    Pid::from_raw(raw).expect("a child's pid is positive")
}

/// Reads `stream` to its end on a thread of its own, and hands over what it
/// read.
fn collect(mut stream: impl Read + Send + 'static) -> Receiver<Vec<u8>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .expect("the stream is readable");
        // The receiver is gone only when the test already failed.
        let _ = sender.send(bytes);
    });
    receiver
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shell running `script`, with both output streams piped.
    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        command
    }

    /// The pid a script recorded in `file`.
    fn recorded_pid(file: &Path) -> u32 {
        std::fs::read_to_string(file)
            .expect("the script recorded a pid")
            .trim()
            .parse()
            .expect("a pid")
    }

    #[test]
    fn a_childs_stat_record_names_its_parent_and_its_end() {
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("the child starts");
        assert_eq!(process_parent(child.id()), Some(std::process::id()));
        child.kill().expect("the child is killed");
        let pid = pid_of(&child);
        let deadline = Instant::now() + Duration::from_secs(30);
        while !exited(pid) {
            assert!(Instant::now() < deadline, "the child outlived its kill");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Exited and not yet collected, its record is still there to read.
        assert_eq!(process_state(child.id()), Some('Z'));
        child.wait().expect("the child is collected");
        assert_eq!(process_state(child.id()), None);
    }

    #[test]
    fn a_bounded_run_returns_its_status_and_its_streams() {
        let output = run_bounded(
            &mut shell("echo out; echo err >&2; exit 3"),
            Duration::from_secs(30),
        );
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout, b"out\n");
        assert_eq!(output.stderr, b"err\n");
    }

    #[test]
    fn a_child_reading_its_input_to_the_end_is_handed_the_end() {
        // The input is piped and still held here: a child that reads it to the
        // end would wait forever on a test that forgot to close it.
        let mut command = shell("cat; echo read");
        command.stdin(std::process::Stdio::piped());
        let mut child = spawn_grouped(&mut command);
        std::io::Write::write_all(
            child.stdin.as_mut().expect("the input is piped"),
            b"typed\n",
        )
        .expect("the input takes a line");
        let output = finish_bounded(child, Duration::from_secs(30));
        assert!(output.status.success(), "{:?}", output.status);
        assert_eq!(output.stdout, b"typed\nread\n");
    }

    #[test]
    fn a_stream_a_leftover_process_holds_open_fails_the_run_in_time() {
        // The shell exits at once, and the `sleep` it leaves behind holds its
        // standard output for half a minute. Reading that stream to its end
        // would wait the half minute out; the run's patience bounds it instead.
        let dir = crate::scratch::scratch_dir("testkit-leftover-stream");
        let pid_file = dir.join("pid");
        let script = format!(
            "sleep 30 & echo $! > '{}'; echo started",
            pid_file.display()
        );
        let started = Instant::now();
        let ended =
            std::panic::catch_unwind(|| run_bounded(&mut shell(&script), Duration::from_secs(2)));
        let message = *ended
            .expect_err("a held stream fails the run")
            .downcast::<String>()
            .expect("a formatted message");
        assert!(message.contains("standard output"), "{message}");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        // The leftover was in the run's process group, and went with it.
        assert!(wait_gone(recorded_pid(&pid_file), Duration::from_secs(10)));
    }

    #[test]
    fn a_run_past_its_patience_is_ended_with_its_process_group() {
        let dir = crate::scratch::scratch_dir("testkit-group-timeout");
        let pid_file = dir.join("pid");
        let script = format!("sleep 30 & echo $! > '{}'; sleep 30", pid_file.display());
        let ended =
            std::panic::catch_unwind(|| run_bounded(&mut shell(&script), Duration::from_secs(2)));
        let message = *ended
            .expect_err("a run past its patience fails")
            .downcast::<String>()
            .expect("a formatted message");
        assert!(message.contains("did not finish"), "{message}");
        assert!(wait_gone(recorded_pid(&pid_file), Duration::from_secs(10)));
    }

    #[test]
    fn a_child_outside_a_group_of_its_own_is_refused() {
        // Ending such a child's group would signal the group of the test
        // itself, so the runner asks for one it can end instead.
        let child = shell("exit 0").spawn().expect("the shell starts");
        let ended = std::panic::catch_unwind(|| finish_bounded(child, Duration::from_secs(30)));
        let message = *ended
            .expect_err("a child sharing the test's group is refused")
            .downcast::<String>()
            .expect("a formatted message");
        assert!(message.contains("spawn_grouped"), "{message}");
    }
}
