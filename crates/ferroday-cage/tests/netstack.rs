//! Integration tests for the native network stack: tap creation inside the
//! sandbox's namespace, the shared-namespace refusal, and the independence
//! of the handle's and the sandbox's lifetimes.

mod common;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ferroday_cage::{Cage, NetStack, NetStackError, Network, Observer, RawMount};

/// Builds a cage running a long sleep in the fixture rootfs — a command that
/// stays alive so the attachment can be exercised around it.
fn sleeper(rootfs: &Path) -> Cage {
    Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sleep")
        .arg("86399")
        .build()
        .expect("a valid sandbox configuration")
}

/// Whether a process with this pid exists on the host.
fn process_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[derive(Default)]
struct Collect {
    stdout: Vec<u8>,
}

impl Observer for Collect {
    fn stdout(&mut self, chunk: &[u8]) {
        self.stdout.extend_from_slice(chunk);
    }
}

#[test]
fn attach_creates_the_guest_interface() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::tun_available() {
        return;
    }
    // A sysfs instance scoped to the sandbox's namespaces lists its network
    // interfaces; the guest reports what it sees.
    let mut observer = Collect::default();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .raw_mount(RawMount::new("/sys").fstype("sysfs"))
        .command("/bin/ls")
        .arg("/sys/class/net")
        .build()
        .expect("a valid sandbox configuration");
    let pending = cage
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");

    let handle = NetStack::default()
        .attach(&pending)
        .expect("the stack attaches");
    assert!(handle.is_running(), "the pump serves the attachment");

    let mut running = pending.proceed().expect("the command is released");
    let status = running.wait().expect("the wait completes");
    assert!(status.success(), "listing the interfaces succeeds");
    handle.stop().expect("the stack stops cleanly");

    let listing = String::from_utf8_lossy(&observer.stdout).into_owned();
    assert!(listing.lines().any(|line| line == "tap0"), "{listing}");
    assert!(listing.lines().any(|line| line == "lo"), "{listing}");
}

#[test]
fn attach_refuses_a_host_network_sandbox() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let pending = Cage::builder()
        .rootfs(rootfs)
        .network(Network::Host)
        .command("/bin/sleep")
        .arg("86399")
        .build()
        .expect("a valid sandbox configuration")
        .spawn_pending()
        .expect("the pending sandbox launches");
    // A host-network sandbox shares the caller's namespace; attaching there
    // would put a tap on the host network, so it is refused outright, and
    // no tun support is needed to decide that.
    let err = NetStack::default()
        .attach(&pending)
        .expect_err("a shared namespace is refused");
    assert!(matches!(err, NetStackError::SharedNamespace), "{err}");
    drop(pending);
}

#[test]
fn dropping_the_handle_does_not_kill_the_sandbox() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::tun_available() {
        return;
    }
    let pending = sleeper(rootfs)
        .spawn_pending()
        .expect("the pending sandbox launches");
    let handle = NetStack::default()
        .attach(&pending)
        .expect("the stack attaches");
    let mut running = pending.proceed().expect("the command is released");

    // The stack is an attachment, not a lifeline: discarding it leaves the
    // sandbox running, merely without connectivity.
    drop(handle);
    assert!(
        running
            .wait_timeout(Duration::from_millis(300))
            .expect("the wait completes")
            .is_none(),
        "the sandbox must survive its stack",
    );

    running.kill().expect("the kill is delivered");
    let status = running.wait().expect("the wait completes after a kill");
    assert_eq!(status.signal(), Some(9));
}

#[test]
fn abandoning_the_pending_launch_after_attach() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::tun_available() {
        return;
    }
    let pending = sleeper(rootfs)
        .spawn_pending()
        .expect("the pending sandbox launches");
    let pid = pending.netns_pid();
    let handle = NetStack::default()
        .attach(&pending)
        .expect("the stack attaches");

    // Dropping the pending launch tears the sandbox down as usual; the
    // attachment does not keep it alive.
    drop(pending);
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_exists(pid) {
        assert!(
            Instant::now() < deadline,
            "the abandoned sandbox outlived its pending handle",
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // The pump holds the namespace open past the sandbox's death, so the
    // stack still stops in an orderly way.
    assert!(handle.is_running(), "the pump outlives the sandbox");
    handle.stop().expect("the stack stops cleanly");
}

/// A host TCP listener bound to loopback that answers one connection with a
/// banner and echoes a line back. Returns its port and a receiver that
/// yields whatever the peer sent.
fn banner_listener(banner: &'static [u8]) -> (u16, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback listener binds");
    let port = listener
        .local_addr()
        .expect("the listener has an address")
        .port();
    let (send, recv) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(banner);
            let mut received = Vec::new();
            let mut buf = [0u8; 256];
            // Read until the peer half-closes or a short idle passes.
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("the read timeout is set");
            while let Ok(read) = stream.read(&mut buf) {
                if read == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..read]);
                if received.contains(&b'\n') {
                    break;
                }
            }
            let _ = send.send(received);
        }
    });
    (port, recv)
}

#[test]
fn tcp_connects_to_a_host_listener_through_the_stack() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::tun_available() {
        return;
    }
    let (port, received) = banner_listener(b"hello from the host\n");

    // The guest reaches the host listener through the gateway address,
    // which host_loopback maps to 127.0.0.1. nc sends a line and prints
    // the banner it receives.
    let mut observer = Collect::default();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            &format!("echo ping | /usr/bin/nc -w 3 10.0.2.2 {port}"),
        ])
        .build()
        .expect("a valid sandbox configuration");
    let pending = cage
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let handle = NetStack::builder()
        .host_loopback(true)
        .build()
        .expect("a valid stack configuration")
        .attach(&pending)
        .expect("the stack attaches");
    let mut running = pending.proceed().expect("the command is released");
    let status = running
        .wait_timeout(Duration::from_secs(10))
        .expect("the wait completes")
        .expect("the command exits before the deadline");
    handle.stop().expect("the stack stops cleanly");

    assert!(status.success(), "nc connected and exchanged data");
    assert_eq!(
        String::from_utf8_lossy(&observer.stdout).trim(),
        "hello from the host",
        "the guest received the host's banner",
    );
    let from_guest = received
        .recv_timeout(Duration::from_secs(2))
        .expect("the host listener received the guest's line");
    assert_eq!(String::from_utf8_lossy(&from_guest).trim(), "ping");
}

/// A host TCP listener that answers one connection with `bytes` of payload and
/// closes immediately, the shape of a `Connection: close` response. Returns its
/// port.
fn bulk_listener(bytes: usize) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback listener binds");
    let port = listener
        .local_addr()
        .expect("the listener has an address")
        .port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Read the guest's request out first. Closing a socket with data
            // still unread makes the kernel send a reset instead of the FIN
            // this fixture is about.
            let mut request = Vec::new();
            let _ = stream.read_to_end(&mut request);
            let _ = stream.write_all(&vec![b'x'; bytes]);
            // Dropping the stream here is the point of the fixture: the peer's
            // FIN reaches the stack while the tail of the transfer is still
            // buffered on both sides of it.
        }
    });
    port
}

#[test]
fn tcp_delivers_a_bulk_transfer_that_ends_in_a_prompt_close() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::tun_available() {
        return;
    }
    // Comfortably past the stack's 64 KiB transmit buffer, so the buffer is
    // full — and the host descriptor still holds unread bytes — when the host's
    // hangup is reported. Delivering every byte regardless is what separates
    // an end-of-stream from a reset.
    const PAYLOAD: usize = 1024 * 1024;
    let port = bulk_listener(PAYLOAD);

    let mut observer = Collect::default();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            &format!("echo ping | /usr/bin/nc -w 10 10.0.2.2 {port} | wc -c"),
        ])
        .build()
        .expect("a valid sandbox configuration");
    let pending = cage
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let handle = NetStack::builder()
        .host_loopback(true)
        .build()
        .expect("a valid stack configuration")
        .attach(&pending)
        .expect("the stack attaches");
    let mut running = pending.proceed().expect("the command is released");
    let status = running
        .wait_timeout(Duration::from_secs(60))
        .expect("the wait completes")
        .expect("the command exits before the deadline");
    handle.stop().expect("the stack stops cleanly");

    assert!(status.success(), "the guest read the transfer to its end");
    assert_eq!(
        String::from_utf8_lossy(&observer.stdout).trim(),
        PAYLOAD.to_string(),
        "every byte of the transfer reached the guest",
    );
}

#[test]
fn the_default_policy_blocks_a_host_local_service() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::tun_available() {
        return;
    }
    let (port, _received) = banner_listener(b"unreachable\n");

    // Without host_loopback the gateway address is not mapped to loopback,
    // so the connection is refused (reset) and nc exits nonzero.
    let mut observer = Collect::default();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            &format!("/usr/bin/nc -w 3 10.0.2.2 {port} < /dev/null"),
        ])
        .build()
        .expect("a valid sandbox configuration");
    let pending = cage
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let handle = NetStack::default()
        .attach(&pending)
        .expect("the stack attaches");
    let mut running = pending.proceed().expect("the command is released");
    let status = running
        .wait_timeout(Duration::from_secs(10))
        .expect("the wait completes")
        .expect("the command exits before the deadline");
    handle.stop().expect("the stack stops cleanly");

    assert!(
        !status.success(),
        "the default policy must refuse the host-local service",
    );
    // The decisive check: nc exits nonzero for many reasons, but the banner's
    // absence proves the connection never reached the host listener.
    let stdout = String::from_utf8_lossy(&observer.stdout);
    assert!(
        !stdout.contains("unreachable"),
        "the guest must not receive the host banner: {stdout:?}",
    );
}

/// A host UDP socket that echoes the first datagram back to its sender and
/// reports what it received. Returns its port and the receiver.
fn udp_echo() -> (u16, mpsc::Receiver<Vec<u8>>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback UDP socket binds");
    let port = socket
        .local_addr()
        .expect("the socket has an address")
        .port();
    let (send, recv) = mpsc::channel();
    std::thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("the read timeout is set");
        let mut buf = [0u8; 512];
        if let Ok((len, peer)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..len], peer);
            let _ = send.send(buf[..len].to_vec());
        }
    });
    (port, recv)
}

#[test]
fn udp_reaches_a_host_socket() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::tun_available() {
        return;
    }
    let (port, received) = udp_echo();

    // The guest sends a datagram through the gateway address, which
    // host_loopback maps to 127.0.0.1, and reads the echo back. busybox nc
    // -u sends the line and prints whatever comes back.
    let mut observer = Collect::default();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            &format!("echo datagram | /usr/bin/nc -u -w 3 10.0.2.2 {port}"),
        ])
        .build()
        .expect("a valid sandbox configuration");
    let pending = cage
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let handle = NetStack::builder()
        .host_loopback(true)
        .build()
        .expect("a valid stack configuration")
        .attach(&pending)
        .expect("the stack attaches");
    let mut running = pending.proceed().expect("the command is released");
    let _ = running.wait_timeout(Duration::from_secs(10));
    running.kill().ok();
    running.wait().ok();
    handle.stop().expect("the stack stops cleanly");

    let from_guest = received
        .recv_timeout(Duration::from_secs(2))
        .expect("the host socket received the guest's datagram");
    assert_eq!(String::from_utf8_lossy(&from_guest).trim(), "datagram");
    assert_eq!(
        String::from_utf8_lossy(&observer.stdout).trim(),
        "datagram",
        "the guest received the echoed datagram",
    );
}

#[test]
fn stopping_after_the_sandbox_exits_is_clean() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::tun_available() {
        return;
    }
    // A short-lived command: the sandbox exits well before the stack is
    // stopped, exercising the pump holding the dead namespace open.
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/true")
        .build()
        .expect("a valid sandbox configuration");
    let pending = cage.spawn_pending().expect("the pending sandbox launches");
    let handle = NetStack::default()
        .attach(&pending)
        .expect("the stack attaches");
    let mut running = pending.proceed().expect("the command is released");
    let status = running.wait().expect("the wait completes");
    assert!(status.success());

    // Give the pump a moment to notice nothing (it must not exit on its
    // own), then stop it.
    std::thread::sleep(Duration::from_millis(200));
    assert!(handle.is_running(), "the pump does not stop by itself");
    handle
        .stop()
        .expect("the stack stops cleanly after the sandbox");
}
