//! Integration tests for `fcage --forward-loopback`: a port on the sandbox's
//! loopback whose connections arrive at a target on the host.
//!
//! The tests skip explicitly, on stderr, on a host that cannot create
//! unprivileged user namespaces. Every run is bounded, so a launch that never
//! finishes fails its test rather than hanging the suite.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::Duration;

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// How long one run may take before its test fails. Far beyond what any run
/// here needs; it exists so a launch that never finishes is a failure.
const PATIENCE: Duration = Duration::from_secs(60);

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
