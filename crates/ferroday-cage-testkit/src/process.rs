//! Host processes a test starts or watches: whether one still exists, waiting
//! for one to go, how much processor time one has used, and running one with a
//! bound on how long it may take.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Output};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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
    ticks_of(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// The processor time the thread `tid` of this process has used, in clock
/// ticks, as [`cpu_ticks`] reads a process's.
pub fn thread_ticks(tid: i32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat"))
        .expect("a thread's statistics are readable");
    ticks_of(&stat).expect("a thread's statistics hold its times")
}

/// The user and system times a `stat` record holds, summed.
///
/// They are fields 14 and 15. They are counted from the state, field 3, which
/// follows the parenthesised name: the name may hold spaces and parentheses, so
/// the split starts after the last `)`.
fn ticks_of(stat: &str) -> Option<u64> {
    let fields: Vec<&str> = stat[stat.rfind(')')? + 1..].split_whitespace().collect();
    let field = |at: usize| fields.get(at)?.parse::<u64>().ok();
    Some(field(11)? + field(12)?)
}

/// Runs `command` to its end and returns what it wrote to whichever of its
/// streams are piped, failing the test if the run outlasts `patience`.
///
/// libtest has no per-test deadline of its own, and a run that never finishes
/// is exactly the failure a relay's tests exist to catch, so it is killed and
/// reported rather than left to hang the suite.
#[track_caller]
pub fn run_bounded(command: &mut Command, patience: Duration) -> Output {
    let child = command.spawn().expect("the command starts");
    finish_bounded(child, patience)
}

/// Waits for `child` to end and returns what it wrote to its piped streams,
/// killing it and failing the test if it outlasts `patience`.
///
/// For a test that writes to the child's input first. The piped streams are
/// read on threads of their own while the wait runs, so a child whose output
/// fills its pipe is collected rather than mistaken for a hang.
#[track_caller]
pub fn finish_bounded(mut child: Child, patience: Duration) -> Output {
    let stdout = child.stdout.take().map(collect);
    let stderr = child.stderr.take().map(collect);
    let deadline = Instant::now().checked_add(patience);
    let status = loop {
        if let Some(status) = child.try_wait().expect("the child can be waited for") {
            break status;
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the run did not finish within {patience:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: stdout.map(joined).unwrap_or_default(),
        stderr: stderr.map(joined).unwrap_or_default(),
    }
}

/// Reads `stream` to its end on a thread of its own.
fn collect(mut stream: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .expect("the stream is readable");
        bytes
    })
}

/// What a collecting thread read.
fn joined(reader: JoinHandle<Vec<u8>>) -> Vec<u8> {
    reader.join().expect("the stream's reader finished")
}
