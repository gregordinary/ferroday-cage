//! Integration tests for the userspace-network seam: the pending launch, the
//! network-namespace target it exposes, the gate that holds the command until
//! the caller proceeds, the listener it makes on the sandbox's loopback, and
//! the teardown when a pending launch is abandoned.

mod common;

use common::{Collect, process_exists, sleeper, wait_gone};

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use ferroday_cage::{
    Cage, CageBuilder, Error, ListenRefusal, Network, PresentedIdentity, SetupStep,
};

/// The network namespace a process is in, as the `net:[...]` symlink target
/// under `/proc/<pid>/ns/net`.
fn network_namespace(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{pid}/ns/net"))
        .expect("the process has a network namespace")
        .to_string_lossy()
        .into_owned()
}

#[test]
fn netns_pid_names_a_private_network_namespace() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let pending = sleeper(rootfs)
        .spawn_pending()
        .expect("the pending sandbox launches");
    let pid = pending.netns_pid();
    assert!(pid > 0, "the netns pid is a real process");
    // The exposed pid is a valid target for /proc/<pid>/ns/net, and its
    // network namespace is the sandbox's own — a stack attaches to this.
    assert_ne!(
        network_namespace(pid),
        network_namespace(std::process::id()),
        "the sandbox must have its own network namespace",
    );
    let mut running = pending.proceed().expect("the command is released");
    running.kill().expect("the kill is delivered");
    let status = running.wait().expect("the wait completes after a kill");
    assert_eq!(status.signal(), Some(9));
}

#[test]
fn a_denied_network_still_offers_a_private_netns() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Network::None creates the namespace but brings up no interface; the seam
    // still exposes it, for a caller's stack to configure from scratch.
    let pending = Cage::builder()
        .rootfs(rootfs)
        .network(Network::None)
        .command("/bin/sleep")
        .arg("86399")
        .build()
        .expect("a valid sandbox configuration")
        .spawn_pending()
        .expect("the pending sandbox launches");
    let pid = pending.netns_pid();
    assert_ne!(
        network_namespace(pid),
        network_namespace(std::process::id()),
        "a denied network is still a private namespace",
    );
    let mut running = pending.proceed().expect("the command is released");
    running.kill().expect("the kill is delivered");
    assert_eq!(
        running.wait().expect("the wait completes").signal(),
        Some(9)
    );
}

#[test]
fn the_command_is_held_until_proceed() {
    let Some(rootfs) = common::scratch_rootfs("network-seam-gate") else {
        return;
    };
    let out = common::scratch_dir("network-seam-gate-out");
    let marker = out.join("marker");
    let cage = Cage::builder()
        .rootfs(&rootfs)
        .bind(&out, "/out")
        .command("/bin/sh")
        .args(["-c", "echo ran > /out/marker"])
        .build()
        .expect("a valid sandbox configuration");

    let pending = cage.spawn_pending().expect("the pending sandbox launches");
    // The command is gated before exec. A broken gate would let it run now;
    // the delay gives it the chance, so a still-absent marker is meaningful.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !marker.exists(),
        "the command ran before the caller proceeded",
    );

    let mut running = pending.proceed().expect("the command is released");
    let status = running.wait().expect("the wait completes");
    assert!(status.success(), "the released command exits cleanly");
    assert!(
        marker.exists(),
        "the command did not run after the caller proceeded",
    );
}

#[test]
fn proceed_streams_the_command_output() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut observer = Collect::default();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "echo hello from the seam"])
        .build()
        .expect("a valid sandbox configuration");
    let pending = cage
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let mut running = pending.proceed().expect("the command is released");
    let status = running.wait().expect("the wait completes");
    assert!(status.success());
    assert_eq!(observer.stdout, b"hello from the seam\n");
}

#[test]
fn abandoning_a_pending_launch_tears_the_sandbox_down() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let pending = sleeper(rootfs)
        .spawn_pending()
        .expect("the pending sandbox launches");
    let pid = pending.netns_pid();
    assert!(
        process_exists(pid),
        "the supervisor is running while pending"
    );
    // Dropping without proceeding must not leak the sandbox.
    drop(pending);
    assert!(
        wait_gone(pid, Duration::from_secs(5)),
        "the abandoned sandbox outlived its pending handle",
    );
}

#[test]
fn a_setup_step_that_fails_before_the_gate_fails_the_pending_launch() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // With a PID namespace the init sets the sandbox up after it is published,
    // so a pending launch is handed out only once the command reports itself
    // at the gate. A working directory the root lacks fails the setup there,
    // and the process `netns_pid` would have named is gone; the launch reports
    // the step rather than a handle naming a process that has exited.
    for pid_namespace in [true, false] {
        let result = Cage::builder()
            .rootfs(rootfs)
            .pid_namespace(pid_namespace)
            .current_dir("/no/such/directory")
            .command("/bin/true")
            .build()
            .expect("a valid sandbox configuration")
            .spawn_pending();
        match result {
            Err(Error::Setup {
                step: SetupStep::ChdirWorkdir,
                ..
            }) => {}
            Err(other) => panic!("pid_namespace = {pid_namespace}: {other:?}"),
            Ok(pending) => panic!(
                "pid_namespace = {pid_namespace}: a pending launch over a failed setup, naming \
                 {} (alive: {})",
                pending.netns_pid(),
                process_exists(pending.netns_pid()),
            ),
        }
    }
}

/// Accepts one connection on `listener`, or gives up at `within`: a command
/// that never connects fails the test rather than hanging it.
fn accept_within(listener: &TcpListener, within: Duration) -> Option<TcpStream> {
    listener
        .set_nonblocking(true)
        .expect("the listener turns non-blocking");
    let deadline = Instant::now().checked_add(within)?;
    loop {
        match listener.accept() {
            Ok((connection, _)) => {
                connection
                    .set_nonblocking(false)
                    .expect("the connection turns blocking");
                return Some(connection);
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => panic!("the accept fails: {err}"),
        }
    }
}

/// Runs `builder`'s sandbox with a listener at `address` on its loopback,
/// where the command sends a request with `nc` and prints the reply, and
/// returns what the caller read and what the command printed, its errors
/// included.
fn round_trip(builder: CageBuilder, address: SocketAddr, connect_to: &str) -> (String, String) {
    let mut observer = Collect::default();
    let cage = builder
        .command("/bin/sh")
        .args([
            "-c",
            &format!(
                "echo request-from-the-sandbox | nc {connect_to} {}",
                address.port()
            ),
        ])
        .build()
        .expect("a valid sandbox configuration");
    let pending = cage
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let listener = pending.listen(address).expect("the listener is made");
    let mut running = pending.proceed().expect("the command is released");
    let Some(mut connection) = accept_within(&listener, Duration::from_secs(30)) else {
        let _ = running.kill();
        let status = running.wait();
        drop(running);
        panic!(
            "the command never connected ({status:?}): {}",
            String::from_utf8_lossy(&observer.stdout)
        );
    };
    let mut request = [0u8; "request-from-the-sandbox\n".len()];
    connection
        .read_exact(&mut request)
        .expect("the request arrives");
    connection
        .write_all(b"reply-from-the-caller\n")
        .expect("the reply is sent");
    drop(connection);
    let status = running.wait().expect("the wait completes");
    drop(listener);
    assert!(status.success(), "the command exits cleanly: {status:?}");
    (
        String::from_utf8_lossy(&request).into_owned(),
        String::from_utf8_lossy(&observer.stdout).into_owned(),
    )
}

#[test]
fn a_command_s_connection_to_its_loopback_reaches_the_caller() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Port 80 is privileged: the helper binds it holding the sandbox's
    // CAP_NET_BIND_SERVICE, which the caller does not hold on the host.
    let (request, printed) = round_trip(
        Cage::builder().rootfs(rootfs),
        "127.0.0.1:80".parse().unwrap(),
        "127.0.0.1",
    );
    assert_eq!(request, "request-from-the-sandbox\n");
    assert_eq!(printed, "reply-from-the-caller\n");
}

#[test]
fn a_listener_serves_the_ipv6_loopback() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let (request, printed) = round_trip(
        Cage::builder().rootfs(rootfs),
        "[::1]:4100".parse().unwrap(),
        "::1",
    );
    assert_eq!(request, "request-from-the-sandbox\n");
    assert_eq!(printed, "reply-from-the-caller\n");
}

#[test]
fn a_listener_serves_a_presented_identity() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let (_, printed) = round_trip(
        Cage::builder()
            .rootfs(rootfs)
            .present_as(PresentedIdentity::Own),
        "127.0.0.1:4100".parse().unwrap(),
        "127.0.0.1",
    );
    assert_eq!(printed, "reply-from-the-caller\n");
}

#[cfg(feature = "hardening")]
#[test]
fn a_listener_serves_a_command_whose_landlock_grant_names_its_port() {
    use ferroday_cage::{FsAccess, NetAccess};

    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::landlock_net() {
        return;
    }
    // busybox `nc` binds its ephemeral source port explicitly, which a network
    // grant governs as a bind on port 0.
    let (_, printed) = round_trip(
        Cage::builder()
            .rootfs(rootfs)
            .landlock_fs(FsAccess::all(), "/")
            .landlock_net(NetAccess::BIND, 0)
            .landlock_net(NetAccess::CONNECT, 4100),
        "127.0.0.1:4100".parse().unwrap(),
        "127.0.0.1",
    );
    assert_eq!(printed, "reply-from-the-caller\n");
}

#[test]
fn a_second_listener_at_one_address_is_refused_with_the_bind_s_errno() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let pending = sleeper(rootfs)
        .spawn_pending()
        .expect("the pending sandbox launches");
    let address: SocketAddr = "127.0.0.1:4100".parse().unwrap();
    let first = pending.listen(address).expect("the first listener is made");
    match pending.listen(address) {
        Err(Error::Listen {
            address: at,
            source: Some(source),
            ..
        }) => {
            assert_eq!(at, address);
            assert_eq!(source.raw_os_error(), Some(98), "EADDRINUSE: {source}");
        }
        other => panic!("a second listener at one address: {other:?}"),
    }
    drop(first);
    drop(pending);
}

#[test]
fn a_listener_is_refused_off_the_loopback_and_without_one() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let refused = |network: Network, address: &str| {
        let pending = Cage::builder()
            .rootfs(rootfs)
            .network(network)
            .command("/bin/true")
            .build()
            .expect("a valid sandbox configuration")
            .spawn_pending()
            .expect("the pending sandbox launches");
        let address: SocketAddr = address.parse().unwrap();
        match pending.listen(address) {
            Err(Error::ListenRefused {
                address: at,
                reason,
                ..
            }) => {
                assert_eq!(at, address);
                reason
            }
            other => panic!("{network:?} at {address}: {other:?}"),
        }
    };
    assert_eq!(
        refused(Network::Isolated, "10.0.2.15:80"),
        ListenRefusal::NotLoopback
    );
    assert_eq!(
        refused(Network::Isolated, "[::ffff:127.0.0.1]:80"),
        ListenRefusal::NotLoopback
    );
    assert_eq!(
        refused(Network::None, "127.0.0.1:80"),
        ListenRefusal::LoopbackDown
    );
    assert_eq!(
        refused(Network::Host, "127.0.0.1:80"),
        ListenRefusal::SharedNamespace
    );
}
