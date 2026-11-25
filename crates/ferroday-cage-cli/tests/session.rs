//! Integration tests for `fcage --serve`: a session's socket, who may use it,
//! and the protocol a program speaks to it.
//!
//! Each test starts a server on the host's own root, its events on its
//! standard output, and drives it through a client of the protocol written
//! here: requests as lines of JSON, descriptors attached to a request's first
//! byte. The tests skip explicitly, on stderr, on a host that cannot create
//! unprivileged user namespaces. Every wait is bounded, so a server that never
//! answers fails its test rather than hanging the suite.

mod common;

use std::fs::File;
use std::io::{BufRead as _, BufReader, IoSlice, Read as _, Write as _};
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
use serde_json::{Value, json};

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// How long a test waits for any one thing the server does.
const PATIENCE: Duration = Duration::from_secs(30);

/// A server under test.
struct Server {
    /// The `fcage --serve` process, leading a process group of its own,
    /// until [`finish`](Self::finish) collects it.
    child: Option<Child>,
    /// Its events, read on a thread of their own.
    events: Receiver<Value>,
    /// Every event read so far, in order.
    seen: Vec<Value>,
    /// The socket's path.
    socket: PathBuf,
    /// The socket's directory, held open so a client reaches a path longer
    /// than a socket's address through it.
    directory: File,
    /// The sandbox's init, from `serving`.
    init: u32,
}

/// A directory for a test's socket, empty, writable by its owner alone.
fn socket_directory(test: &str) -> PathBuf {
    let directory = common::scratch_dir(test);
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("the scratch directory's mode is set");
    directory
}

/// `fcage` with `args`, its events on its standard output and its standard
/// error kept, started as the leader of a process group of its own.
fn spawn(args: &[&str]) -> Child {
    common::spawn_grouped(
        Command::new(FCAGE)
            .args(["--events", "/dev/stdout"])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
}

/// The events `child` writes on its standard output, one JSON value each, read
/// on a thread of their own.
fn events_of(child: &mut Child) -> Receiver<Value> {
    let stdout = child.stdout.take().expect("the events are piped");
    let (sender, events) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            let event = serde_json::from_str(&line).expect("each event is JSON");
            if sender.send(event).is_err() {
                return;
            }
        }
    });
    events
}

impl Server {
    /// Starts a server on the host's root with `args` besides, its socket in
    /// a directory of `test`'s own, and waits until it serves. `None` where the
    /// host cannot make a sandbox, the skip said.
    fn start(test: &str, args: &[&str]) -> Option<Server> {
        Server::start_with(test, args, spawn)
    }

    /// [`start`](Self::start), with `fcage` started by `run`, which is handed
    /// the whole argument list.
    fn start_with(test: &str, args: &[&str], run: impl FnOnce(&[&str]) -> Child) -> Option<Server> {
        if !common::require::userns() {
            return None;
        }
        let directory_path = socket_directory(test);
        let socket = directory_path.join("s.sock");
        let socket_arg = socket.to_str().expect("a UTF-8 scratch path").to_string();
        let mut all = vec!["--serve", socket_arg.as_str(), "--host-rootfs"];
        all.extend(args);
        let mut child = run(&all);
        let events = events_of(&mut child);
        let directory = File::open(&directory_path).expect("the socket's directory opens");
        let mut server = Server {
            child: Some(child),
            events,
            seen: Vec::new(),
            socket,
            directory,
            init: 0,
        };
        let serving = server.wait_for("serving");
        assert_eq!(serving["socket"], socket_arg, "{serving}");
        server.init = serving["pid"].as_u64().expect("the init's pid") as u32;
        Some(server)
    }

    /// The next event of `kind`, failing the test past [`PATIENCE`].
    fn wait_for(&mut self, kind: &str) -> Value {
        loop {
            let event = self.events.recv_timeout(PATIENCE).unwrap_or_else(|_| {
                panic!("no {kind} event within {PATIENCE:?}; seen {:?}", self.seen)
            });
            self.seen.push(event.clone());
            if event["event"] == kind {
                return event;
            }
        }
    }

    /// The socket's path as this process reaches it: through the directory's
    /// descriptor, however long the scratch path is.
    fn reachable(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd())).join("s.sock")
    }

    /// A client connected to the server.
    fn connect(&self) -> Client {
        let stream = UnixStream::connect(self.reachable()).expect("the client connects");
        stream
            .set_read_timeout(Some(PATIENCE))
            .expect("a read timeout");
        Client {
            reader: BufReader::new(stream.try_clone().expect("the stream clones")),
            stream,
        }
    }

    /// Waits for the server to exit, and returns its status, its standard
    /// error, and every event it wrote.
    fn finish(mut self) -> (ExitStatus, String, Vec<Value>) {
        let child = self
            .child
            .take()
            .expect("the server runs until it is finished");
        let output = common::finish_bounded(child, PATIENCE);
        while let Ok(event) = self.events.recv_timeout(PATIENCE) {
            self.seen.push(event);
        }
        (
            output.status,
            String::from_utf8_lossy(&output.stderr).into_owned(),
            std::mem::take(&mut self.seen),
        )
    }

    /// Sends the server `signal`.
    fn signal(&self, signal: rustix::process::Signal) {
        let child = self.child.as_ref().expect("the server runs");
        let pid = rustix::process::Pid::from_raw(child.id() as i32).expect("a pid");
        rustix::process::kill_process(pid, signal).expect("the server is signalled");
    }
}

/// A client of a session.
struct Client {
    /// Where requests are written.
    stream: UnixStream,
    /// Where messages are read.
    reader: BufReader<UnixStream>,
}

impl Client {
    /// Sends `request` as a line.
    fn send(&mut self, request: &Value) {
        let mut line = serde_json::to_vec(request).expect("JSON");
        line.push(b'\n');
        self.stream.write_all(&line).expect("the request is sent");
    }

    /// Sends `request` with `fds` attached to its first byte, in one message.
    fn send_with(&mut self, request: &Value, fds: &[BorrowedFd<'_>]) {
        let mut line = serde_json::to_vec(request).expect("JSON");
        line.push(b'\n');
        send_fds(&self.stream, &line, fds);
    }

    /// The next message, or `None` at the end of the connection.
    fn next(&mut self) -> Option<Value> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => Some(serde_json::from_str(&line).expect("each message is JSON")),
            Err(error) => panic!("no message within {PATIENCE:?}: {error}"),
        }
    }

    /// Reads up to the response to request `id`, and returns it with the
    /// events before it.
    fn response(&mut self, id: u64) -> (Vec<Value>, Value) {
        let mut events = Vec::new();
        loop {
            let message = self
                .next()
                .unwrap_or_else(|| panic!("the connection closed before answering {id}"));
            if message.get("event").is_some() {
                events.push(message);
            } else {
                assert_eq!(
                    message["id"], id,
                    "a response to another request: {message}"
                );
                return (events, message);
            }
        }
    }

    /// Sends `request` and returns its response, with the events before it.
    fn call(&mut self, request: &Value) -> (Vec<Value>, Value) {
        self.send(request);
        self.response(request["id"].as_u64().expect("a numeric id"))
    }
}

/// Sends `bytes` on `stream` in one message, with `fds` attached.
fn send_fds(stream: &UnixStream, bytes: &[u8], fds: &[BorrowedFd<'_>]) {
    let mut space = [std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() {
        assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
    }
    let sent = rustix::net::sendmsg(
        stream,
        &[IoSlice::new(bytes)],
        &mut control,
        SendFlags::empty(),
    )
    .expect("the message is sent");
    assert_eq!(sent, bytes.len(), "one message is sent whole");
}

/// A pipe, as its read and write ends.
fn pipe() -> (OwnedFd, OwnedFd) {
    rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).expect("a pipe")
}

/// Everything `read_end` holds until every writer has closed it.
fn read_all(read_end: OwnedFd) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::from(read_end)
        .read_to_end(&mut bytes)
        .expect("the pipe reads");
    bytes
}

/// The kinds of `events`, in order.
fn kinds(events: &[Value]) -> Vec<&str> {
    events
        .iter()
        .map(|event| event["event"].as_str().expect("a kind"))
        .collect()
}

#[test]
fn a_session_serves_an_exec_and_ends_on_a_stop() {
    let Some(server) = Server::start("fcage-session-exec", &[]) else {
        return;
    };
    let mut client = server.connect();

    let (events, hello) = client.call(&json!({"id": 1, "method": "hello"}));
    assert!(events.is_empty(), "{events:?}");
    assert_eq!(
        hello["result"],
        json!({"protocol": 1, "fcage": env!("CARGO_PKG_VERSION")})
    );

    // The command's two outputs go to the client's own pipe, which the
    // command writes directly: nothing is relayed.
    let (read_end, write_end) = pipe();
    let request = json!({"id": 2, "method": "exec", "params": {
        "command": "/bin/sh",
        "args": ["-c", "echo out; echo err >&2; exit 3"],
        "stdout": "passed",
        "stderr": "passed",
    }});
    client.send_with(&request, &[write_end.as_fd(), write_end.as_fd()]);
    drop(write_end);
    let (events, response) = client.response(2);
    assert_eq!(kinds(&events), ["started"], "{events:?}");
    assert_eq!(events[0]["exec"], 2);
    assert!(events[0]["pid"].as_u64().is_some_and(|pid| pid > 1));
    let result = &response["result"];
    assert_eq!(result["code"], 3, "{response}");
    assert_eq!(result["shell-code"], 3);
    assert_eq!(result["timed-out"], false);
    assert!(result.get("signal").is_none(), "{result}");
    assert_eq!(read_all(read_end), b"out\nerr\n");

    let (_, stopped) = client.call(&json!({"id": 3, "method": "stop"}));
    assert_eq!(stopped["result"], json!({}), "{stopped}");
    assert_eq!(
        client.next(),
        None,
        "the connection closes once the session ends"
    );

    let socket = server.socket.clone();
    let (status, stderr, events) = server.finish();
    assert_eq!(status.code(), Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(kinds(&events), ["hello", "serving", "ended"], "{events:?}");
    assert_eq!(events[2]["reason"], "stop");
    assert_eq!(events[2]["shell-code"], 0);
    assert!(!socket.exists(), "the socket is removed");
}

#[test]
fn an_execs_settings_reach_the_command_in_either_spelling() {
    let Some(server) = Server::start("fcage-session-settings", &["--chdir", "/tmp"]) else {
        return;
    };
    let mut client = server.connect();
    // A value that is not UTF-8 travels as base64, a bare name is looked up
    // on PATH, the working directory is the session's unless the exec names
    // its own, and the input is the client's pipe.
    let (read_end, write_end) = pipe();
    let (input, feed) = pipe();
    rustix::io::write(&feed, b"fed\n").expect("the input is written");
    drop(feed);
    let script = r#"printf '%s|' "$A" "$1" "$(pwd)"; cat"#;
    let request = json!({"id": 1, "method": "exec", "params": {
        "command": "sh",
        "path-lookup": true,
        "args": ["-c", script, "sh", {"base64": "/w=="}],
        "env": [["A", "first"], ["A", {"base64": "3q2+7w=="}]],
        "stdin": "passed",
        "stdout": "passed",
    }});
    client.send_with(&request, &[input.as_fd(), write_end.as_fd()]);
    drop((input, write_end));
    let (_, response) = client.response(1);
    assert_eq!(response["result"]["code"], 0, "{response}");
    assert_eq!(read_all(read_end), b"\xde\xad\xbe\xef|\xff|/tmp|fed\n");

    let (read_end, write_end) = pipe();
    let request = json!({"id": 2, "method": "exec", "params": {
        "command": "/bin/pwd", "cwd": "/", "stdout": "passed",
    }});
    client.send_with(&request, &[write_end.as_fd()]);
    drop(write_end);
    let (_, response) = client.response(2);
    assert_eq!(response["result"]["code"], 0, "{response}");
    assert_eq!(read_all(read_end), b"/\n");
}

#[test]
fn requests_the_session_cannot_serve_are_answered_with_errors() {
    let Some(server) = Server::start("fcage-session-errors", &[]) else {
        return;
    };
    let mut client = server.connect();
    let code = |response: &Value| response["error"]["code"].as_str().map(str::to_string);

    client.stream.write_all(b"not json\n").expect("sent");
    let parse = client.next().expect("an answer");
    assert_eq!(code(&parse).as_deref(), Some("parse"), "{parse}");
    assert_eq!(parse["id"], Value::Null);

    for (request, expected) in [
        (json!({"method": "hello"}), "invalid-request"),
        (
            json!({"id": 1, "method": "hello", "extra": 1}),
            "invalid-request",
        ),
        (json!({"id": 2, "method": "teleport"}), "method-not-found"),
        (
            json!({"id": 3, "method": "hello", "params": {"a": 1}}),
            "invalid-params",
        ),
        (
            json!({"id": 4, "method": "exec", "params": {"command": "/bin/true", "colour": 1}}),
            "invalid-params",
        ),
        (
            json!({"id": 5, "method": "exec", "params": {"command": "/bin/true", "stdout": "passed"}}),
            "invalid-params",
        ),
        (
            json!({"id": 6, "method": "exec", "params": {"command": "/bin/true", "timeout": -1}}),
            "invalid-params",
        ),
    ] {
        client.send(&request);
        let answer = client.next().expect("an answer");
        assert_eq!(
            code(&answer).as_deref(),
            Some(expected),
            "{request}: {answer}"
        );
        assert!(answer["error"]["text"].is_string(), "{answer}");
    }

    // A command that does not exist fails as a launch fails, typed.
    let (_, missing) =
        client.call(&json!({"id": 7, "method": "exec", "params": {"command": "/no/such/command"}}));
    let error = &missing["error"];
    assert_eq!(error["code"], "setup", "{missing}");
    assert_eq!(error["step"], "exec");
    assert_eq!(error["errno"], "ENOENT");
    assert_eq!(error["shell-code"], 127);

    // A file is refused as a stream: the command could reopen it with more
    // access than the descriptor carries.
    let file = File::open("/etc/hostname")
        .or_else(|_| File::open("/etc/passwd"))
        .expect("a file");
    let request =
        json!({"id": 8, "method": "exec", "params": {"command": "/bin/true", "stdin": "passed"}});
    client.send_with(&request, &[file.as_fd()]);
    let (_, refused) = client.response(8);
    assert_eq!(refused["error"]["code"], "stream-refused", "{refused}");
    assert_eq!(refused["error"]["stream"], "stdin");

    // One exec at a time on a connection.
    let (read_end, write_end) = pipe();
    let request =
        json!({"id": 9, "method": "exec", "params": {"command": "/bin/cat", "stdin": "passed"}});
    client.send_with(&request, &[read_end.as_fd()]);
    drop(read_end);
    let started = client.next().expect("the exec starts");
    assert_eq!(started["event"], "started", "{started}");
    let (_, busy) =
        client.call(&json!({"id": 10, "method": "exec", "params": {"command": "/bin/true"}}));
    assert_eq!(busy["error"]["code"], "busy", "{busy}");
    drop(write_end);
    let (_, done) = client.response(9);
    assert_eq!(done["result"]["code"], 0, "{done}");
}

#[test]
fn a_signal_reaches_the_connections_exec() {
    let Some(server) = Server::start("fcage-session-exec-signal", &[]) else {
        return;
    };
    let mut client = server.connect();
    let (read_end, write_end) = pipe();
    let request = json!({"id": 1, "method": "exec", "params": {
        "command": "/bin/sh",
        "args": ["-c", "trap 'kill $!; exit 3' INT; echo ready; sleep 30 & wait $!"],
        "stdout": "passed",
    }});
    client.send_with(&request, &[write_end.as_fd()]);
    drop(write_end);
    // Once the shell has said so, its trap is set.
    assert!(
        common::readable_by(&read_end, std::time::Instant::now() + PATIENCE),
        "the command never said it was ready"
    );

    // A signal names the exec it is for, by the request that started it, and
    // a signal by a number the kernel names.
    let signal = |id: u64, exec: u64, number: i32| json!({"id": id, "method": "signal", "params": {"exec": exec, "signal": number}});
    let (_, other) = client.call(&signal(2, 7, 2));
    assert_eq!(other["error"]["code"], "no-such-exec", "{other}");
    let (_, unnamed) = client.call(&signal(3, 1, 40));
    assert_eq!(unnamed["error"]["code"], "invalid-params", "{unnamed}");
    let (_, sent) = client.call(&signal(4, 1, 2));
    assert_eq!(sent["result"], json!({}), "{sent}");
    let (_, ended) = client.response(1);
    assert_eq!(ended["result"]["code"], 3, "{ended}");
    assert_eq!(read_all(read_end), b"ready\n");

    // Once it has ended, the exec is no longer the connection's.
    let (_, late) = client.call(&signal(5, 1, 2));
    assert_eq!(late["error"]["code"], "no-such-exec", "{late}");
}

#[test]
fn two_connections_run_their_execs_at_once() {
    let Some(server) = Server::start("fcage-session-concurrent", &[]) else {
        return;
    };
    // The first waits for a line the test holds back, and the second runs
    // and ends meanwhile.
    let mut first = server.connect();
    let (input, feed) = pipe();
    let (output, write_end) = pipe();
    let request = json!({"id": 1, "method": "exec", "params": {
        "command": "/bin/sh", "args": ["-c", "read line; echo \"got $line\""],
        "stdin": "passed", "stdout": "passed",
    }});
    first.send_with(&request, &[input.as_fd(), write_end.as_fd()]);
    drop((input, write_end));
    assert_eq!(first.next().expect("started")["event"], "started");

    let mut second = server.connect();
    let (_, response) =
        second.call(&json!({"id": 1, "method": "exec", "params": {"command": "/bin/true"}}));
    assert_eq!(response["result"]["code"], 0, "{response}");

    rustix::io::write(&feed, b"late\n").expect("the line is written");
    drop(feed);
    let (_, response) = first.response(1);
    assert_eq!(response["result"]["code"], 0, "{response}");
    assert_eq!(read_all(output), b"got late\n");
}

#[test]
fn a_closed_connection_ends_its_exec() {
    let Some(server) = Server::start("fcage-session-closed", &[]) else {
        return;
    };
    let mut client = server.connect();
    client.send(
        &json!({"id": 1, "method": "exec", "params": {"command": "/bin/sleep", "args": ["1000"]}}),
    );
    let started = client.next().expect("started");
    let pid = started["pid"].as_u64().expect("a pid") as u32;
    assert!(ferroday_cage_testkit::process::process_exists(pid));
    drop(client);
    assert!(
        ferroday_cage_testkit::process::wait_gone(pid, PATIENCE),
        "the exec ends with its connection"
    );
    // The session goes on serving.
    let (_, hello) = server.connect().call(&json!({"id": 1, "method": "hello"}));
    assert_eq!(hello["result"]["protocol"], 1, "{hello}");
}

#[test]
fn a_stop_ends_the_execs_in_flight_and_answers_once_the_sandbox_has_ended() {
    let Some(server) = Server::start("fcage-session-stop", &[]) else {
        return;
    };
    let mut running = server.connect();
    running.send(
        &json!({"id": 1, "method": "exec", "params": {"command": "/bin/sleep", "args": ["1000"]}}),
    );
    assert_eq!(running.next().expect("started")["event"], "started");

    let mut stopping = server.connect();
    stopping.send(&json!({"id": 7, "method": "stop"}));
    // The sandbox's end sends SIGTERM to every process of it.
    let (_, ended) = running.response(1);
    assert_eq!(ended["result"]["signal"], 15, "{ended}");
    assert_eq!(ended["result"]["shell-code"], 143);
    let (_, stopped) = stopping.response(7);
    assert_eq!(stopped["result"], json!({}), "{stopped}");

    let (status, stderr, events) = server.finish();
    assert_eq!(status.code(), Some(0), "{stderr}");
    assert_eq!(
        events.last().expect("an event")["reason"],
        "stop",
        "{events:?}"
    );
}

#[test]
fn the_sandboxs_own_end_ends_the_session() {
    let Some(server) = Server::start("fcage-session-sandbox-ended", &[]) else {
        return;
    };
    let mut client = server.connect();
    client.send(
        &json!({"id": 1, "method": "exec", "params": {"command": "/bin/sleep", "args": ["1000"]}}),
    );
    assert_eq!(client.next().expect("started")["event"], "started");

    let init = rustix::process::Pid::from_raw(server.init as i32).expect("a pid");
    rustix::process::kill_process(init, rustix::process::Signal::KILL).expect("the init is killed");
    let (_, ended) = client.response(1);
    assert_eq!(ended["result"]["signal"], 9, "{ended}");
    assert_eq!(
        client.next(),
        None,
        "the connection closes with the session"
    );

    let socket = server.socket.clone();
    let (status, stderr, events) = server.finish();
    assert_eq!(status.code(), Some(137), "{stderr}");
    let last = events.last().expect("an event");
    assert_eq!(last["event"], "ended", "{events:?}");
    assert_eq!(last["reason"], "sandbox-ended");
    assert_eq!(last["signal"], 9);
    assert!(
        last["text"]
            .as_str()
            .is_some_and(|text| text.contains("signal 9"))
    );
    assert!(!socket.exists(), "the socket is removed");
}

#[test]
fn a_signal_ends_the_session() {
    let Some(server) = Server::start("fcage-session-signal", &[]) else {
        return;
    };
    server.signal(rustix::process::Signal::TERM);
    let socket = server.socket.clone();
    let (status, stderr, events) = server.finish();
    assert_eq!(status.code(), Some(0), "{stderr}");
    let last = events.last().expect("an event");
    assert_eq!(last["reason"], "signal", "{events:?}");
    assert_eq!(last["signal"], 15);
    assert!(!socket.exists(), "the socket is removed");
}

#[test]
fn the_end_of_the_input_it_watches_ends_the_session() {
    // The shell hands fcage its own standard input, a pipe the test holds the
    // writing end of, as descriptor 3, and gives fcage none.
    let mut feed = None;
    let started = Server::start_with(
        "fcage-session-until-closed",
        &["--serve-until-closed", "/dev/fd/3"],
        |args| {
            let mut script = format!("exec {FCAGE} --events /dev/stdout");
            for arg in args {
                script.push(' ');
                script.push_str(arg);
            }
            script.push_str(" 3<&0 </dev/null");
            let mut child = common::spawn_grouped(
                Command::new("/bin/sh")
                    .args(["-c", &script])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped()),
            );
            feed = child.stdin.take();
            child
        },
    );
    let Some(server) = started else {
        return;
    };
    let (_, hello) = server.connect().call(&json!({"id": 1, "method": "hello"}));
    assert_eq!(hello["result"]["protocol"], 1, "{hello}");
    drop(feed);
    let (status, stderr, events) = server.finish();
    assert_eq!(status.code(), Some(0), "{stderr}");
    assert_eq!(
        events.last().expect("an event")["reason"],
        "closed",
        "{events:?}"
    );
}

#[test]
fn an_exec_past_its_timeout_reports_that_it_timed_out() {
    let Some(server) = Server::start("fcage-session-timeout", &[]) else {
        return;
    };
    let (_, response) = server
        .connect()
        .call(&json!({"id": 1, "method": "exec", "params": {
            "command": "/bin/sleep", "args": ["1000"], "timeout": 0.2, "kill-after": 0.2,
        }}));
    let result = &response["result"];
    assert_eq!(result["timed-out"], true, "{response}");
    assert_eq!(result["shell-code"], 124);
}

#[test]
fn descriptors_inside_a_message_close_the_connection() {
    let Some(server) = Server::start("fcage-session-descriptors", &[]) else {
        return;
    };
    let mut client = server.connect();
    // The message's first part goes alone, and a descriptor comes with its
    // second: not with the message's first byte.
    client.stream.write_all(br#"{"id": 1, "#).expect("sent");
    std::thread::sleep(Duration::from_millis(50));
    let (_read_end, write_end) = pipe();
    send_fds(
        &client.stream,
        b"\"method\": \"hello\"}\n",
        &[write_end.as_fd()],
    );
    let refused = client.next().expect("an answer");
    assert_eq!(refused["error"]["code"], "protocol", "{refused}");
    assert_eq!(client.next(), None, "the connection is closed");
}

#[test]
fn an_unsafe_directory_and_an_existing_path_are_refused() {
    let directory = socket_directory("fcage-session-placement");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777))
        .expect("the directory is opened to everyone");
    let socket = directory.join("s.sock");
    let output = common::run_bounded(
        Command::new(FCAGE)
            .args(["--host-rootfs", "--serve"])
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        PATIENCE,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(125), "{stderr}");
    assert!(
        stderr.contains("writable by its group or by others"),
        "{stderr}"
    );
    assert!(!socket.exists(), "nothing is left behind");

    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("the directory is the owner's again");
    std::fs::write(&socket, b"").expect("something holds the path");
    let output = common::run_bounded(
        Command::new(FCAGE)
            .args(["--host-rootfs", "--serve"])
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        PATIENCE,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(125), "{stderr}");
    assert!(stderr.contains("the path exists"), "{stderr}");
    assert!(socket.is_file(), "what held the path is left as it was");
}

/// Set inside the sandbox to make [`probe_session_peer`] connect rather than
/// return: the socket's path there.
const PROBE: &str = "FCAGE_TEST_SESSION_PEER";

/// Inside the sandbox: connects to the session's socket, asks it `hello`, and
/// prints what came back, or `closed`.
#[test]
fn probe_session_peer() {
    let Some(path) = std::env::var_os(PROBE) else {
        return;
    };
    println!();
    let mut stream = match UnixStream::connect(Path::new(&path)) {
        Ok(stream) => stream,
        Err(error) => {
            println!("probe connect failed: {error}");
            return;
        }
    };
    stream
        .set_read_timeout(Some(PATIENCE))
        .expect("a read timeout");
    let _ = stream.write_all(b"{\"id\": 1, \"method\": \"hello\"}\n");
    let mut answer = String::new();
    let _ = BufReader::new(&stream).read_line(&mut answer);
    match answer.trim() {
        "" => println!("probe answer closed"),
        answer => println!("probe answer {answer}"),
    }
}

#[test]
fn a_peer_inside_a_sandbox_is_refused() {
    let Some(mut server) = Server::start("fcage-session-peer", &[]) else {
        return;
    };
    // The socket's directory is bound into another sandbox, whose Landlock
    // rules are lifted so its command can reach the socket at all: the peer
    // check is all that is left to refuse it.
    let exe = std::env::current_exe().expect("the test binary has a path");
    let directory = server.socket.parent().expect("a directory").to_path_buf();
    let output = common::run_bounded(
        Command::new(FCAGE)
            .args(["--host-rootfs", "--no-landlock-resolve-unix", "--bind"])
            .arg(&directory)
            .arg("/tmp/s")
            .arg("--ro-bind")
            .arg(&exe)
            .arg("/tmp/probe")
            .args(["--setenv", PROBE, "/tmp/s/s.sock", "--", "/tmp/probe"])
            .args(common::rerun_args("probe_session_peer"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        PATIENCE,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let answer = stdout
        .lines()
        .find_map(|line| line.strip_prefix("probe answer "))
        .unwrap_or_else(|| {
            panic!(
                "the probe did not report:\n{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    let answer: Value = serde_json::from_str(answer).expect("the refusal is JSON");
    assert_eq!(answer["error"]["code"], "peer-refused", "{answer}");
    let warning = server.wait_for("warning");
    assert!(
        warning["text"]
            .as_str()
            .is_some_and(|text| text.contains("refused a connection")),
        "{warning}"
    );
    // A client of the caller's own is served all the same.
    let (_, hello) = server.connect().call(&json!({"id": 1, "method": "hello"}));
    assert_eq!(hello["result"]["protocol"], 1, "{hello}");
}

/// A server a test is done with and did not finish: asked to end, as a signal
/// asks it, and collected, so no session outlives its test.
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take()
            && let Ok(None) = child.try_wait()
        {
            let pid = rustix::process::Pid::from_raw(child.id() as i32).expect("a pid");
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            let _ = child.wait();
        }
    }
}
