//! Integration tests for `fcage --forward-loopback`: a port on the sandbox's
//! loopback whose connections arrive at a target on the host.
//!
//! The tests skip explicitly, on stderr, on a host that cannot create
//! unprivileged user namespaces. Every run is bounded, so a launch that never
//! finishes fails its test rather than hanging the suite.

mod common;

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// How long one run may take before its test fails. Far beyond what any run
/// here needs; it exists so a launch that never finishes is a failure.
const PATIENCE: Duration = Duration::from_secs(60);

/// How long a run may take to end once its command has, while its forward
/// holds a connection the target never takes.
///
/// Shorter than the 30 seconds a forward gives a connection to the target, so a
/// run that waited for that connection fails here, and far beyond what ending a
/// run needs.
const PROMPTLY: Duration = Duration::from_secs(20);

/// The most connections a forward holds at once, as `--forward-loopback`
/// documents it.
const BUDGET: usize = 128;

/// Answers one connection on a thread of its own: reads a line, and replies
/// with that line uppercased. Returns the line it read.
fn answer_one<S>(
    accept: impl FnOnce() -> std::io::Result<S> + Send + 'static,
) -> std::thread::JoinHandle<String>
where
    S: std::io::Read + Write + Send + 'static,
{
    std::thread::spawn(move || {
        let connection = accept().expect("the forward connects to the target");
        let mut reader = BufReader::new(connection);
        let mut line = String::new();
        reader.read_line(&mut line).expect("the request arrives");
        let mut connection = reader.into_inner();
        connection
            .write_all(line.to_uppercase().as_bytes())
            .expect("the reply is sent");
        line
    })
}

/// A path to `leaf` in `dir` short enough for a socket address, through this
/// process's descriptor for `dir`, which the returned file holds open.
///
/// The fixture cache can sit deeper than the 108 bytes a socket's path may
/// take, and `/proc/<pid>/fd/<n>` names the directory whatever its depth, to
/// this process and to the `fcage` it runs alike.
fn short_socket_path(dir: &std::path::Path, leaf: &str) -> (std::fs::File, String) {
    use std::os::fd::AsRawFd as _;

    let handle = std::fs::File::open(dir).expect("the scratch directory opens");
    let path = format!(
        "/proc/{}/fd/{}/{leaf}",
        std::process::id(),
        handle.as_raw_fd()
    );
    (handle, path)
}

/// Runs `fcage` with one forward from the sandbox's loopback port 4100 to
/// `target`, where the command sends a line with `nc` and prints the reply.
fn run_forward(rootfs: &std::path::Path, target: &str) -> std::process::Output {
    let mut command = Command::new(FCAGE);
    command
        .args(["--rootfs", rootfs.to_str().expect("a UTF-8 fixture path")])
        .args(["--forward-loopback", "4100", target])
        .args([
            "--",
            "/bin/sh",
            "-c",
            "echo from-the-sandbox | nc 127.0.0.1 4100",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    common::run_bounded(&mut command, PATIENCE)
}

/// A unix socket listening at `path` whose accept queue is full, and the
/// connection that fills it.
///
/// A backlog of 0 queues one connection. A further non-blocking connect then
/// fails with `EAGAIN` at once, which is checked here, since it is what the
/// forward meets.
fn full_unix_target(path: &str) -> (OwnedFd, UnixStream) {
    let address = SocketAddrUnix::new(path).expect("the path fits a socket address");
    let listener = stream_socket(AddressFamily::UNIX, SocketFlags::CLOEXEC);
    rustix::net::bind(&listener, &address).expect("the target socket binds");
    rustix::net::listen(&listener, 0).expect("the target socket listens");
    let filler = UnixStream::connect(path).expect("the first connection is queued");
    let probe = stream_socket(
        AddressFamily::UNIX,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
    );
    assert_eq!(
        rustix::net::connect(&probe, &address),
        Err(Errno::AGAIN),
        "a connection past a full queue is refused for now"
    );
    (listener, filler)
}

/// A TCP listener on the loopback whose accept queue is full, the connection
/// that fills it, and its address.
///
/// With a backlog of 0, the first connection fills the queue, and the kernel
/// drops the SYN of any further one, SYN cookies or not, so a connect to it
/// stays in progress until the queue has room. That is checked here: a further
/// connect is still in progress after a wait a refusal or an acceptance would
/// have ended, since either arrives within microseconds on the loopback.
fn full_tcp_target() -> (OwnedFd, TcpStream, SocketAddr) {
    let listener = stream_socket(AddressFamily::INET, SocketFlags::CLOEXEC);
    let any: SocketAddr = "127.0.0.1:0".parse().expect("a socket address");
    rustix::net::bind(&listener, &any).expect("the target listener binds");
    rustix::net::listen(&listener, 0).expect("the target listener listens");
    let address = match rustix::net::getsockname(&listener).map(SocketAddr::try_from) {
        Ok(Ok(address)) => address,
        other => panic!("the target listener has no address: {other:?}"),
    };
    let filler = TcpStream::connect(address).expect("the first connection is made");
    let probe = stream_socket(
        AddressFamily::INET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
    );
    assert_eq!(
        rustix::net::connect(&probe, &address),
        Err(Errno::INPROGRESS)
    );
    let quarter = Timespec {
        tv_sec: 0,
        tv_nsec: 250_000_000,
    };
    let mut fds = [PollFd::new(&probe, PollFlags::OUT)];
    let answered = loop {
        match rustix::event::poll(&mut fds, Some(&quarter)) {
            Err(Errno::INTR) => {}
            other => break other.expect("the probe can be polled"),
        }
    };
    assert_eq!(
        answered,
        0,
        "a connection past a full TCP queue stays in progress, here {:?}",
        fds[0].revents()
    );
    (listener, filler, address)
}

/// A new stream socket of `family`.
fn stream_socket(family: AddressFamily, flags: SocketFlags) -> OwnedFd {
    rustix::net::socket_with(family, SocketType::STREAM, flags, None).expect("a socket opens")
}

/// A run of `fcage` with one forward from the sandbox's loopback port 4100,
/// whose command the test talks to: it reads the lines the command prints and
/// writes lines to its input.
///
/// A test that fails partway kills the run's process group rather than leaving
/// a sandbox behind.
struct Session {
    /// The run, until it is finished.
    child: Option<Child>,
    /// The command's input, until the run is finished.
    input: Option<ChildStdin>,
    /// The lines the command prints, as they arrive.
    lines: Receiver<String>,
    /// The run's process id.
    pid: u32,
}

impl Session {
    /// Starts `fcage` with `flags`, a forward to `target`, and `script` as the
    /// command's shell script.
    fn start(rootfs: &std::path::Path, flags: &[&str], target: &str, script: &str) -> Session {
        Session::start_with_stderr(rootfs, flags, target, script, Stdio::piped())
    }

    /// [`start`](Self::start), with `fcage`'s standard error on `stderr`.
    fn start_with_stderr(
        rootfs: &std::path::Path,
        flags: &[&str],
        target: &str,
        script: &str,
        stderr: Stdio,
    ) -> Session {
        let mut command = Command::new(FCAGE);
        command
            .args(["--rootfs", rootfs.to_str().expect("a UTF-8 fixture path")])
            .args(flags)
            .args(["--forward-loopback", "4100", target])
            .args(["--", "/bin/sh", "-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr);
        let mut child = common::spawn_grouped(&mut command);
        let input = child.stdin.take();
        let output = child.stdout.take().expect("the output is piped");
        let (sender, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { return };
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        Session {
            pid: child.id(),
            child: Some(child),
            input,
            lines,
        }
    }

    /// Waits for the command's next line, and checks that it is `wanted`.
    fn expect_line(&self, wanted: &str) {
        match self.lines.recv_timeout(PATIENCE) {
            Ok(line) => assert_eq!(line, wanted),
            Err(error) => panic!("the command never printed {wanted:?}: {error}"),
        }
    }

    /// Writes `line` to the command's input.
    fn send(&mut self, line: &str) {
        let input = self.input.as_mut().expect("the run is not finished");
        writeln!(input, "{line}").expect("the command's input takes a line");
    }

    /// How many threads `fcage` runs.
    fn threads(&self) -> usize {
        std::fs::read_dir(format!("/proc/{}/task", self.pid))
            .expect("the run's process can be read")
            .count()
    }

    /// The sockets `fcage` holds, each named as `/proc/<pid>/fd` links it, by
    /// its inode.
    ///
    /// A socket keeps its name for as long as it is open and no other takes it,
    /// so one in this set and not in an earlier one was opened in between,
    /// whatever else was closed meanwhile. That is what a count of every
    /// descriptor cannot tell: the command can run before the launch has closed
    /// all of its own, and those it closes later would hide those the forward
    /// opens.
    fn sockets(&self) -> BTreeSet<String> {
        std::fs::read_dir(format!("/proc/{}/fd", self.pid))
            .expect("the run's process can be read")
            .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
            .filter_map(|link| link.to_str()?.strip_prefix("socket:").map(str::to_owned))
            .collect()
    }

    /// Whether `fcage` has exited. It is not reaped until the run is
    /// finished, so its process stays readable.
    fn exited(&self) -> bool {
        common::process_state(self.pid) == Some('Z')
    }

    /// Waits until `fcage` holds at least `wanted` sockets that are not among
    /// `before`, failing the test past [`PATIENCE`]; or, with `or_exit`, until
    /// it has exited.
    fn await_new_sockets(&self, before: &BTreeSet<String>, wanted: usize, or_exit: bool) {
        let deadline = Instant::now() + PATIENCE;
        loop {
            if or_exit && self.exited() {
                return;
            }
            let new = self.sockets().difference(before).count();
            if new >= wanted {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "fcage opened {new} sockets, not {wanted}, in {PATIENCE:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Closes the command's input, waits for the run to end within
    /// `patience`, and returns what it did. Its output is what the command
    /// printed past the lines already read.
    fn finish(mut self, patience: Duration) -> Output {
        drop(self.input.take());
        let child = self.child.take().expect("the run is finished once");
        let mut output = common::finish_bounded(child, patience);
        let deadline = Instant::now() + patience;
        loop {
            match self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(line) => {
                    output.stdout.extend_from_slice(line.as_bytes());
                    output.stdout.push(b'\n');
                }
                Err(RecvTimeoutError::Disconnected) => return output,
                Err(RecvTimeoutError::Timeout) => {
                    panic!("the run's output was still open {patience:?} after it ended")
                }
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let pid = i32::try_from(self.pid).expect("a pid fits an i32");
            if let Some(group) = rustix::process::Pid::from_raw(pid) {
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            }
            let _ = child.wait();
        }
    }
}

/// Runs a command that connects to the forward, holds its connection until the
/// forward has accepted it and opened a socket toward `target`, and then ends.
/// Returns what the run did, failing the test if the run outlasts
/// [`PROMPTLY`] from the command's end.
///
/// `fcage` holds two sockets more once the forward has accepted the
/// connection and opened the socket that connects to the target, which it does
/// in the same step, before it next waits.
fn connect_and_end(rootfs: &std::path::Path, target: &str) -> Output {
    let mut session = Session::start(
        rootfs,
        &[],
        target,
        "echo ready; read go; nc 127.0.0.1 4100 </dev/null & read end; echo marker",
    );
    session.expect_line("ready");
    let before = session.sockets();
    session.send("go");
    session.await_new_sockets(&before, 2, false);
    session.send("end");
    session.finish(PROMPTLY)
}

#[test]
fn a_forward_carries_the_command_s_connection_to_a_unix_socket() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("fcage-forward-unix");
    let (_dir, socket) = short_socket_path(&dir, "target.sock");
    let listener = UnixListener::bind(&socket).expect("the target socket binds");
    let answered = answer_one(move || listener.accept().map(|(connection, _)| connection));

    let output = run_forward(rootfs, &socket);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{}: {stderr}", output.status);
    assert_eq!(
        answered.join().expect("the target thread finishes"),
        "from-the-sandbox\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "FROM-THE-SANDBOX\n"
    );
}

#[test]
fn a_forward_carries_the_command_s_connection_to_a_tcp_address() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("the target listener binds");
    let target = listener
        .local_addr()
        .expect("the target has an address")
        .to_string();
    let answered = answer_one(move || listener.accept().map(|(connection, _)| connection));

    let output = run_forward(rootfs, &target);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{}: {stderr}", output.status);
    assert_eq!(
        answered.join().expect("the target thread finishes"),
        "from-the-sandbox\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "FROM-THE-SANDBOX\n"
    );
}

#[test]
fn a_target_that_refuses_is_reported_and_the_run_still_ends() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Nothing listens at the target, so the forward reports the refused
    // connection, and the command's `nc` sees its connection closed and ends.
    let dir = common::scratch_dir("fcage-forward-refused");
    let (_dir, socket) = short_socket_path(&dir, "nobody.sock");
    let output = run_forward(rootfs, &socket);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("connecting to the target"),
        "the refused target is reported: {stderr}"
    );
}

#[test]
fn a_target_that_keeps_refusing_is_reported_once() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Nothing listens at the target, so each of the command's three
    // connections is refused, and only the first refusal is reported.
    let dir = common::scratch_dir("fcage-forward-refused-again");
    let (_dir, socket) = short_socket_path(&dir, "nobody.sock");
    let mut command = Command::new(FCAGE);
    command
        .args(["--rootfs", rootfs.to_str().expect("a UTF-8 fixture path")])
        .args(["--forward-loopback", "4100", &socket])
        .args([
            "--",
            "/bin/sh",
            "-c",
            "for i in 1 2 3; do nc 127.0.0.1 4100 </dev/null; done",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = common::run_bounded(&mut command, PATIENCE);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{}: {stderr}", output.status);
    assert_eq!(
        stderr.matches("connecting to the target").count(),
        1,
        "a run of refusals is reported once: {stderr}"
    );
}

#[test]
fn a_target_that_resets_resets_the_command_s_connection() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The target reads the command's request and resets the connection. The
    // command's `wget` reads a reset as one, and an end of stream as a reply
    // that ended, so what it reports says which arrived.
    //
    // The reset comes before any reply on purpose. A reset behind bytes the
    // command has yet to read reaches it in the read that returns them, which
    // wget's buffered reader can take for an end of stream, so whether it
    // reports one would depend on the timing of its reads.
    let listener = TcpListener::bind("127.0.0.1:0").expect("the target listener binds");
    let target = listener
        .local_addr()
        .expect("the target has an address")
        .to_string();
    let replied = std::thread::spawn(move || {
        let (mut connection, _) = listener.accept().expect("the forward connects");
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.windows(4).any(|end| end == b"\r\n\r\n") {
            let read = connection.read(&mut buf).expect("the request arrives");
            assert!(read > 0, "the request ended early");
            request.extend_from_slice(&buf[..read]);
        }
        let connection = OwnedFd::from(connection);
        rustix::net::sockopt::set_socket_linger(&connection, Some(Duration::ZERO))
            .expect("the target's close can be a reset");
    });

    let mut command = Command::new(FCAGE);
    command
        .args(["--rootfs", rootfs.to_str().expect("a UTF-8 fixture path")])
        .args(["--forward-loopback", "4100", &target])
        .args([
            "--",
            "/bin/sh",
            "-c",
            "wget -q -O /dev/null http://127.0.0.1:4100/",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = common::run_bounded(&mut command, PATIENCE);
    replied.join().expect("the target thread finishes");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "wget fetched nothing: {stderr}");
    assert!(
        stderr.contains("Connection reset by peer"),
        "the command read an end of stream where the target reset: {stderr}"
    );
}

#[test]
fn a_forward_carries_a_megabyte_each_way_and_passes_each_end_on() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The target reads to the end of what the command sends before it answers
    // a byte, then sends it all back and closes. So the command's end has to
    // reach the target while the other direction stays open, and the target's
    // end has to reach the command, whose `nc` ends only then. A megabyte is
    // many times what the forward holds of either direction at once.
    let listener = TcpListener::bind("127.0.0.1:0").expect("the target listener binds");
    let target = listener
        .local_addr()
        .expect("the target has an address")
        .to_string();
    let echoed = std::thread::spawn(move || {
        let (mut connection, _) = listener.accept().expect("the forward connects");
        let mut received = Vec::new();
        connection
            .read_to_end(&mut received)
            .expect("the command's bytes arrive, then its end");
        connection
            .write_all(&received)
            .expect("the bytes go back while the command still reads");
        received.len()
    });

    let mut command = Command::new(FCAGE);
    command
        .args(["--rootfs", rootfs.to_str().expect("a UTF-8 fixture path")])
        .args(["--forward-loopback", "4100", &target])
        .args([
            "--",
            "/bin/sh",
            "-c",
            "head -c 1048576 /dev/urandom > /tmp/sent && \
             nc 127.0.0.1 4100 < /tmp/sent > /tmp/received && \
             cmp /tmp/sent /tmp/received && echo identical",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = common::run_bounded(&mut command, PATIENCE);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{}: {stderr}", output.status);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "identical\n");
    assert_eq!(
        echoed.join().expect("the target thread finishes"),
        1_048_576
    );
}

#[test]
fn a_run_ends_while_a_unix_target_s_queue_stays_full() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("fcage-forward-full-unix");
    let (_dir, socket) = short_socket_path(&dir, "full.sock");
    let _target = full_unix_target(&socket);

    let output = connect_and_end(rootfs, &socket);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{}: {stderr}", output.status);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "marker\n");
}

#[test]
fn a_run_ends_while_a_tcp_target_never_answers() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let (_target, _filler, address) = full_tcp_target();

    let output = connect_and_end(rootfs, &address.to_string());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{}: {stderr}", output.status);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "marker\n");
}

#[test]
fn a_run_its_timeout_ends_does_not_wait_for_a_target_with_a_full_queue() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("fcage-forward-full-timeout");
    let (_dir, socket) = short_socket_path(&dir, "full.sock");
    let _target = full_unix_target(&socket);

    let mut session = Session::start(
        rootfs,
        &["--timeout", "3", "--kill-after", "1"],
        &socket,
        "echo ready; read go; nc 127.0.0.1 4100 </dev/null & exec sleep 60",
    );
    session.expect_line("ready");
    let before = session.sockets();
    session.send("go");
    // The timeout counts from the launch and does not wait for this test, so
    // a run it has already ended is as good as a forward that has accepted.
    session.await_new_sockets(&before, 2, true);
    let output = session.finish(PROMPTLY);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(124),
        "{}: {stderr}",
        output.status
    );
}

#[test]
fn a_unix_target_whose_queue_was_full_takes_the_connection_once_it_has_room() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("fcage-forward-room");
    let (_dir, socket) = short_socket_path(&dir, "room.sock");
    let (target, filler) = full_unix_target(&socket);

    let mut session = Session::start(
        rootfs,
        &[],
        &socket,
        "echo ready; read go; echo from-the-sandbox | nc 127.0.0.1 4100",
    );
    session.expect_line("ready");
    let before = session.sockets();
    session.send("go");
    // The forward has accepted the command's connection and met the full
    // queue. Taking the connection that fills it makes room, and the forward's
    // next attempt is queued behind it.
    session.await_new_sockets(&before, 2, false);
    let queued = rustix::net::accept_with(&target, SocketFlags::CLOEXEC)
        .expect("the filling connection is accepted");
    drop((queued, filler));
    let listener = UnixListener::from(target);
    let answered = answer_one(move || listener.accept().map(|(connection, _)| connection));

    let output = session.finish(PATIENCE);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{}: {stderr}", output.status);
    assert_eq!(
        answered.join().expect("the target thread finishes"),
        "from-the-sandbox\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "FROM-THE-SANDBOX\n"
    );
}

#[test]
fn a_forward_holds_its_budget_on_one_thread_and_resets_what_is_past_it() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("fcage-forward-budget");
    let (_dir, socket) = short_socket_path(&dir, "budget.sock");
    let listener = UnixListener::bind(&socket).expect("the target socket binds");
    listener
        .set_nonblocking(true)
        .expect("the target socket is non-blocking");

    // One connection past the budget, each held open: `nc` sends its end at
    // once and then waits for the connection's, which the target never sends.
    // The one the forward resets is the one whose `nc` ends, and it records
    // its number.
    let script = format!(
        "echo ready; read go; i=0; \
         while [ $i -lt {} ]; do \
           i=$((i + 1)); \
           (nc 127.0.0.1 4100 </dev/null >/dev/null 2>&1; echo $i >> /tmp/closed) & \
         done; \
         while [ ! -s /tmp/closed ]; do sleep 0.05; done; echo refused; \
         read end; wc -l < /tmp/closed",
        BUDGET + 1
    );
    let mut session = Session::start(rootfs, &[], &socket, &script);
    session.expect_line("ready");
    let (threads, before) = (session.threads(), session.sockets());
    session.send("go");

    // The target takes every connection the forward makes and holds it,
    // neither reading nor closing it.
    let deadline = Instant::now() + PATIENCE;
    let mut held = Vec::new();
    while held.len() < BUDGET {
        assert!(
            ferroday_cage_testkit::fd::readable_by(&listener, deadline),
            "the target had {} of the forward's connections after {PATIENCE:?}",
            held.len()
        );
        match listener.accept() {
            Ok((connection, _)) => held.push(connection),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("the target cannot accept: {error}"),
        }
    }
    session.expect_line("refused");
    // A unix connect is queued at the target when it is made, so one the
    // forward made past its budget would be waiting there by now.
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("the target was sent a connection past the budget: {other:?}"),
    }

    // Measured while every connection is held: one thread whatever the
    // count, and two sockets for each connection the forward carries. The
    // threads are bounded rather than matched, for the reason the sockets are
    // counted by name: the launch may still have been ending one of its own
    // when the command said it was ready.
    let now = session.threads();
    assert!(
        now <= threads,
        "the forward's threads grew with its connections, from {threads} to {now}"
    );
    let opened = session.sockets().difference(&before).count();
    assert!(
        opened <= 2 * BUDGET,
        "fcage opened {opened} sockets for {BUDGET} connections"
    );

    session.send("end");
    let output = session.finish(PROMPTLY);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{}: {stderr}", output.status);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "1",
        "one connection is reset past the budget"
    );
    assert_eq!(
        stderr.matches("past the budget of 128").count(),
        1,
        "the budget is reported once: {stderr}"
    );
    drop(held);
}

#[test]
fn a_forward_carries_connections_while_nothing_reads_its_reports() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // `fcage`'s standard error is a pipe already full, which nothing reads
    // until the run is over. Nothing listens at the target at first, so the
    // forward reports the command's first connection refused. The target then
    // comes up, and the command's second connection is carried while that
    // report still waits for a reader.
    let dir = common::scratch_dir("fcage-forward-unread-reports");
    let (_dir, socket) = short_socket_path(&dir, "late.sock");
    let (unread, stderr) = std::io::pipe().expect("a pipe for standard error");
    rustix::io::ioctl_fionbio(&stderr, true).expect("the pipe can be filled");
    let mut filled = 0;
    while let Ok(written) = (&stderr).write(&[b'.'; 4096]) {
        filled += written;
    }
    while (&stderr).write(b".").is_ok() {
        filled += 1;
    }
    rustix::io::ioctl_fionbio(&stderr, false).expect("the pipe blocks again");

    let mut session = Session::start_with_stderr(
        rootfs,
        &[],
        &socket,
        "echo ready; read go; nc 127.0.0.1 4100 </dev/null; echo refused; read again; \
         echo from-the-sandbox | nc 127.0.0.1 4100",
        Stdio::from(stderr),
    );
    session.expect_line("ready");
    session.send("go");
    session.expect_line("refused");
    let listener = UnixListener::bind(&socket).expect("the target socket binds");
    let answered = answer_one(move || listener.accept().map(|(connection, _)| connection));
    session.send("again");
    session.expect_line("FROM-THE-SANDBOX");
    assert_eq!(
        answered.join().expect("the target thread finishes"),
        "from-the-sandbox\n"
    );

    // The run ends once its report is written, which takes a reader.
    let reader = std::thread::spawn(move || {
        let mut written = Vec::new();
        (&unread)
            .read_to_end(&mut written)
            .expect("standard error reads to its end");
        written
    });
    let output = session.finish(PATIENCE);
    let written = reader.join().expect("the reader finishes");
    let stderr = String::from_utf8_lossy(&written[filled..]);
    assert!(output.status.success(), "{}: {stderr}", output.status);
    assert!(
        stderr.contains("connecting to the target"),
        "the refused target is reported: {stderr}"
    );
}
