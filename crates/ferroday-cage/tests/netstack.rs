//! Integration tests for the native network stack: tap creation inside the
//! sandbox's namespace, the shared-namespace refusal, the independence of the
//! handle's and the sandbox's lifetimes, and the flows the stack carries in
//! each direction.

mod common;

use common::dns::{KNOWN_NAME, Record, Resolver};
use common::{Collect, sleeper, wait_gone};

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ferroday_cage::{
    Cage, CageBuilder, FlowAdmission, FlowRefusal, NetStack, NetStackError, NetStackReport,
    Network, RawMount, Transport,
};

#[test]
fn attach_creates_the_guest_interface() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
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

/// Set inside a restriction to make [`probe_attach_where_landlock_is_absent`]
/// probe rather than return.
#[cfg(feature = "hardening")]
const NO_LANDLOCK_PROBE: &str = "FERRODAY_CAGE_TEST_NETSTACK_NO_LANDLOCK";

/// An attachment that would carry the command's connections past a network
/// grant the kernel does not enforce is refused.
///
/// The host's kernel enforces network grants, so the probe is this test binary
/// run again under a restriction whose seccomp policy answers
/// `landlock_create_ruleset` with `ENOSYS`, which is how a kernel without the
/// LSM answers. Below ABI 4 the same refusal is the unit tests'.
#[cfg(feature = "hardening")]
#[test]
fn attach_refuses_a_network_grant_the_kernel_cannot_enforce() {
    use ferroday_cage::{Restriction, SeccompPolicy, SeccompRules};

    let Some(_) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::seccomp() {
        return;
    }
    let landlock =
        SeccompRules::syscall("landlock_create_ruleset").expect("a syscall of this host");
    let enosys = SeccompRules::errno("ENOSYS").expect("an errno name");
    let exe = std::env::current_exe().expect("the test binary has a path");
    let output = Restriction::builder()
        .command(&exe)
        .args(common::rerun_args("probe_attach_where_landlock_is_absent"))
        .env(NO_LANDLOCK_PROBE, "1")
        .seccomp(SeccompPolicy::Rules(
            SeccompRules::denying([]).errno_for(landlock, enosys),
        ))
        .build()
        .expect("a valid restriction configuration")
        .output()
        .expect("the probe runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("probe refused"),
        "the probe did not report the refusal:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Not a test of its own: with [`NO_LANDLOCK_PROBE`] set, attaches a stack to
/// a sandbox carrying a network grant where Landlock answers as absent, and
/// reports the refusal. Without the variable it does nothing.
#[cfg(feature = "hardening")]
#[test]
fn probe_attach_where_landlock_is_absent() {
    use ferroday_cage::NetAccess;

    if std::env::var_os(NO_LANDLOCK_PROBE).is_none() {
        return;
    }
    let rootfs =
        common::fixture_rootfs().expect("the parent runs the probe only where sandboxes launch");
    assert_eq!(
        ferroday_cage::host::landlock_abi(),
        None,
        "the probe's premise: Landlock answers as absent",
    );
    let pending = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/true")
        .landlock_net(NetAccess::CONNECT, 443)
        .build()
        .expect("an isolated sandbox's grant is the namespace's to bound at build")
        .spawn_pending()
        .expect("the pending sandbox launches");
    let err = NetStack::default()
        .attach(&pending)
        .expect_err("a grant the kernel cannot enforce is refused");
    assert!(
        matches!(
            err,
            NetStackError::LandlockNetUnenforceable { abi: None, .. }
        ),
        "{err:?}",
    );
    println!("probe refused");
}

#[test]
fn dropping_the_handle_does_not_kill_the_sandbox() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
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
    if !common::require::tun() {
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
    assert!(
        wait_gone(pid, Duration::from_secs(5)),
        "the abandoned sandbox outlived its pending handle",
    );

    // The pump holds the namespace open past the sandbox's death, so the
    // stack still stops in an orderly way.
    assert!(handle.is_running(), "the pump outlives the sandbox");
    handle.stop().expect("the stack stops cleanly");
}

/// A host TCP listener bound to loopback that answers one connection with a
/// banner and echoes a line back. Returns its port and a receiver that
/// yields whatever the peer sent.
fn banner_listener(banner: &'static [u8]) -> (u16, mpsc::Receiver<Vec<u8>>) {
    banner_listener_on(Ipv4Addr::LOCALHOST, banner)
}

/// [`banner_listener`], bound to `address`.
fn banner_listener_on(address: Ipv4Addr, banner: &'static [u8]) -> (u16, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind((address, 0)).expect("a host listener binds");
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
    if !common::require::tun() {
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
    let status = common::outcome_within(&mut running, Duration::from_secs(10));
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
    if !common::require::tun() {
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
    let status = common::outcome_within(&mut running, Duration::from_secs(60));
    handle.stop().expect("the stack stops cleanly");

    assert!(status.success(), "the guest read the transfer to its end");
    assert_eq!(
        String::from_utf8_lossy(&observer.stdout).trim(),
        PAYLOAD.to_string(),
        "every byte of the transfer reached the guest",
    );
}

/// A host listener that answers each connection the way a `Connection: close`
/// server does — read the request, write a short response, close — and serves
/// `connections` of them one after another. Returns its port.
///
/// The close comes from the host, which is the point of the fixture: the stack
/// forwards it as the first FIN, so each finished exchange leaves the stack's
/// guest-facing socket in TIME_WAIT.
fn closing_listener(connections: usize) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback listener binds");
    let port = listener
        .local_addr()
        .expect("the listener has an address")
        .port();
    std::thread::spawn(move || {
        for _ in 0..connections {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            // Read the request out first: closing with the peer's bytes still
            // unread makes the kernel send a reset instead of the FIN this
            // fixture is about.
            let mut request = Vec::new();
            let mut buf = [0u8; 256];
            while let Ok(read) = stream.read(&mut buf) {
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|end| end == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
            // Dropping the stream closes the connection from the host side.
        }
    });
    port
}

#[test]
fn back_to_back_connections_are_not_capped_by_finished_ones() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // Comfortably more than the stack's 128 flow slots, so a stack that held a
    // slot for each finished exchange would run out. smoltcp keeps a closed
    // socket in TIME_WAIT for ten seconds, which would put the ceiling at
    // 12.8 connections a second; the guest below runs far faster than that, and
    // reports how many it completed either way.
    const CONNECTIONS: usize = 160;
    let port = closing_listener(CONNECTIONS);

    // wget is the client because it does not half-close before reading the
    // response: the host closes first, which is the shape that ends in
    // TIME_WAIT. nc would half-close as soon as its stdin ended, and the guest
    // closing first never reaches that state.
    let mut observer = Collect::default();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            &format!(
                "i=0; while [ $i -lt {CONNECTIONS} ]; do \
                 /usr/bin/wget -q -O /dev/null http://10.0.2.2:{port}/ || break; \
                 i=$((i+1)); done; echo $i"
            ),
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
    let status = common::outcome_within(&mut running, Duration::from_secs(120));
    handle.stop().expect("the stack stops cleanly");

    assert!(status.success(), "the guest's loop ran to completion");
    assert_eq!(
        String::from_utf8_lossy(&observer.stdout).trim(),
        CONNECTIONS.to_string(),
        "every connection was admitted; a lower count is the flow table \
         filling with exchanges that are already over",
    );
}

#[test]
fn the_default_policy_blocks_a_host_local_service() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
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
    let status = common::outcome_within(&mut running, Duration::from_secs(10));
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
    udp_echo_on(Ipv4Addr::LOCALHOST)
}

/// [`udp_echo`], bound to `address`.
fn udp_echo_on(address: Ipv4Addr) -> (u16, mpsc::Receiver<Vec<u8>>) {
    let socket = UdpSocket::bind((address, 0)).expect("a host UDP socket binds");
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

/// Sends one datagram from the guest to the gateway's `port`, through a stack
/// built by `stack`, and asserts that the host echo on that port received it
/// and that the guest received the echo.
///
/// busybox `nc -u` sends the line and prints whatever comes back.
fn udp_round_trip(rootfs: &Path, port: u16, received: mpsc::Receiver<Vec<u8>>, stack: NetStack) {
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
    let handle = stack.attach(&pending).expect("the stack attaches");
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
fn udp_reaches_a_host_socket() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // The gateway address, which host_loopback maps to 127.0.0.1 on every
    // port.
    let (port, received) = udp_echo();
    let stack = NetStack::builder()
        .host_loopback(true)
        .build()
        .expect("a valid stack configuration");
    udp_round_trip(rootfs, port, received, stack);
}

#[test]
fn udp_reaches_a_host_socket_through_a_named_port() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // The narrower grant maps UDP as it maps TCP: the one port it names.
    let (port, received) = udp_echo();
    let stack = NetStack::builder()
        .host_loopback_port(port)
        .build()
        .expect("a valid stack configuration");
    udp_round_trip(rootfs, port, received, stack);
}

// -- Destination rules -----------------------------------------------------
//
// The rules decide only what the stack would otherwise carry, which loopback
// never is, so the servers these tests reach listen on the host's own routable
// address.

/// The host's own routable IPv4 address, where these tests' servers listen, or
/// `None`, with the skip reported, where the host has none the stack carries
/// flows to.
fn routable() -> Option<Ipv4Addr> {
    let address = common::require::routable_v4()?;
    // A host whose own address falls in the guest's network would see every
    // flow to it refused as the guest's on-link traffic, rules or none.
    let carried = NetStack::default().forwards(Transport::Tcp, (address, 80).into());
    common::require::TUN
        .holds(
            carried,
            format!("the stack refuses the host's own address {address}"),
        )
        .then_some(address)
}

/// A stack with `allow` and `deny` rules, given as text, over `builder`.
fn ruled(builder: ferroday_cage::NetStackBuilder, allow: &[String], deny: &[String]) -> NetStack {
    let builder = allow.iter().fold(builder, |builder, rule| {
        builder.allow(rule.parse().expect("an allow rule"))
    });
    deny.iter()
        .fold(builder, |builder, rule| {
            builder.deny(rule.parse().expect("a deny rule"))
        })
        .build()
        .expect("address rules build")
}

/// Runs `script` in a sandbox with `stack` attached, for at most ten seconds,
/// and returns whether it exited successfully in that time and what it
/// printed. One still running then is killed.
fn run_under(rootfs: &Path, stack: &NetStack, script: &str) -> (bool, String) {
    let (ok, stdout, _) = run_reporting(rootfs, stack, script);
    (ok, stdout)
}

/// [`run_under`], returning the stack's reports too, each as [`summary`]
/// writes it.
fn run_reporting(rootfs: &Path, stack: &NetStack, script: &str) -> (bool, String, Vec<Summary>) {
    let mut observer = Collect::default();
    let pending = common::shell(rootfs, script)
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let mut handle = stack.attach(&pending).expect("the stack attaches");
    let reports = handle
        .take_reports()
        .expect("a fresh handle holds its reports");
    let mut running = pending.proceed().expect("the command is released");
    let status = running.wait_timeout(Duration::from_secs(10)).ok().flatten();
    if status.is_none() {
        let _ = running.kill();
        let _ = running.wait();
    }
    drop(running);
    handle.stop().expect("the stack stops cleanly");
    let summaries = std::iter::from_fn(|| reports.recv().ok())
        .map(|report| summary(&report))
        .collect();
    (
        status.is_some_and(|status| status.success()),
        String::from_utf8_lossy(&observer.stdout).into_owned(),
        summaries,
    )
}

/// What a report says of a flow: its transport, its destination, and the
/// decision, naming the rule that took it where one did.
type Summary = (Transport, SocketAddr, String);

/// A report as a test compares it. The guest's port is left out, since the
/// guest's kernel chooses it; its address is the guest's own.
fn summary(report: &NetStackReport) -> Summary {
    let (transport, guest, destination, decision) = match report {
        NetStackReport::FlowAdmitted {
            transport,
            guest,
            destination,
            admission,
            ..
        } => (transport, guest, destination, admitted_as(admission)),
        NetStackReport::FlowRefused {
            transport,
            guest,
            destination,
            refusal,
            ..
        } => (transport, guest, destination, refused_as(refusal)),
        other => panic!("a report of something other than a flow: {other}"),
    };
    assert_eq!(guest.ip(), IpAddr::from([10, 0, 2, 15]), "{report}");
    (*transport, *destination, decision)
}

/// What admitted a flow or a question, as a test compares it, naming the rule
/// where one decided.
fn admitted_as(admission: &FlowAdmission) -> String {
    match admission {
        FlowAdmission::Allowed { rule, .. } => format!("allowed by {rule}"),
        other => format!("carried as {other:?}"),
    }
}

/// Why a flow or a question was refused, as a test compares it, naming the
/// rule where one decided.
fn refused_as(refusal: &FlowRefusal) -> String {
    match refusal {
        FlowRefusal::Denied { rule, .. } => format!("denied by {rule}"),
        FlowRefusal::PrivateBehindName { rule, .. } => format!("private behind {rule}"),
        FlowRefusal::NameOverUdp { rule, .. } => format!("over udp under {rule}"),
        other => format!("refused as {other:?}"),
    }
}

/// The summary of a flow over TCP to `destination`.
fn tcp(destination: impl Into<SocketAddr>, decision: impl Into<String>) -> Summary {
    (Transport::Tcp, destination.into(), decision.into())
}

/// Whether a host server's receiver stays empty: the guest never reached it.
fn never_reached(received: &mpsc::Receiver<Vec<u8>>) -> bool {
    received.recv_timeout(Duration::from_millis(500)).is_err()
}

#[test]
fn an_allow_rule_carries_its_range_and_refuses_the_rest() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let Some(host) = routable() else {
        return;
    };
    let connect = |port| format!("echo ping | /usr/bin/nc -w 3 {host} {port}");

    let (port, received) = banner_listener_on(host, b"admitted\n");
    let stack = ruled(NetStack::builder(), &[format!("{host}/32:{port}")], &[]);
    let (ok, stdout, reports) = run_reporting(rootfs, &stack, &connect(port));
    assert!(ok && stdout.contains("admitted"), "{stdout}");
    assert_eq!(
        reports,
        [tcp((host, port), format!("allowed by {host}:{port}"))]
    );
    let from_guest = received
        .recv_timeout(Duration::from_secs(2))
        .expect("the host's server heard from the guest");
    assert_eq!(String::from_utf8_lossy(&from_guest).trim(), "ping");

    // An allow rule that leaves the host out refuses it, as one admitting the
    // host on another port does.
    for allow in ["192.0.2.0/24".to_string(), format!("{host}:1")] {
        let (port, received) = banner_listener_on(host, b"refused\n");
        let stack = ruled(NetStack::builder(), std::slice::from_ref(&allow), &[]);
        let (ok, stdout, reports) = run_reporting(rootfs, &stack, &connect(port));
        assert!(!ok && !stdout.contains("refused"), "{allow}: {stdout}");
        assert!(never_reached(&received), "{allow}");
        assert_eq!(reports, [tcp((host, port), "refused as NotAllowed")]);
    }
}

#[test]
fn a_deny_rule_refuses_what_an_allow_rule_admits_and_alone_admits_the_rest() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let Some(host) = routable() else {
        return;
    };
    let both = |denied: u16, carried: u16| {
        format!(
            "/usr/bin/nc -w 3 {host} {denied} < /dev/null; \
             echo ping | /usr/bin/nc -w 3 {host} {carried}"
        )
    };
    for allow in [vec![format!("{host}/32")], vec![]] {
        let (denied, denied_received) = banner_listener_on(host, b"denied\n");
        let (carried, carried_received) = banner_listener_on(host, b"carried\n");
        let stack = ruled(
            NetStack::builder(),
            &allow,
            &[format!("tcp:{host}:{denied}")],
        );
        let (_, stdout, reports) = run_reporting(rootfs, &stack, &both(denied, carried));
        assert!(
            !stdout.contains("denied") && stdout.contains("carried"),
            "under {allow:?}: {stdout}"
        );
        let admitted = match allow.is_empty() {
            true => "carried as Default".to_string(),
            false => format!("allowed by {host}"),
        };
        assert_eq!(
            reports,
            [
                tcp((host, denied), format!("denied by tcp:{host}:{denied}")),
                tcp((host, carried), admitted),
            ],
            "under {allow:?}"
        );
        assert!(never_reached(&denied_received), "under {allow:?}");
        carried_received
            .recv_timeout(Duration::from_secs(2))
            .expect("the carried port's server heard from the guest");
    }
}

#[test]
fn a_transport_rule_carries_its_own_transport_alone() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let Some(host) = routable() else {
        return;
    };
    let send = |port| format!("echo datagram | /usr/bin/nc -u -w 2 {host} {port}");

    let (port, received) = udp_echo_on(host);
    let stack = ruled(NetStack::builder(), &[format!("udp:{host}")], &[]);
    let (_, stdout) = run_under(rootfs, &stack, &send(port));
    let from_guest = received
        .recv_timeout(Duration::from_secs(2))
        .expect("the host's socket received the guest's datagram");
    assert_eq!(String::from_utf8_lossy(&from_guest).trim(), "datagram");
    assert_eq!(stdout.trim(), "datagram", "the echo reached the guest");

    let (port, received) = udp_echo_on(host);
    let stack = ruled(NetStack::builder(), &[format!("tcp:{host}")], &[]);
    let (_, stdout) = run_under(rootfs, &stack, &send(port));
    assert!(never_reached(&received), "a TCP rule carried a datagram");
    assert!(stdout.trim().is_empty(), "{stdout}");
}

#[test]
fn rules_that_admit_nothing_leave_the_stacks_own_grants() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let everything = ["0.0.0.0/0".to_string(), "::/0".to_string()];

    // The gateway's loopback mapping and the nameserver, under a deny over
    // both families whole.
    let (port, received) = banner_listener(b"mapped\n");
    let resolver = Resolver::new(1);
    let stack = ruled(
        NetStack::builder()
            .host_loopback_port(port)
            .upstream(resolver.address()),
        &[],
        &everything,
    );
    let mut observer = Collect::default();
    let pending = Cage::builder()
        .rootfs(rootfs)
        .nameservers(stack.nameservers())
        .command("/bin/sh")
        .args([
            "-c",
            &format!("echo ping | /usr/bin/nc -w 3 10.0.2.2 {port}; getent hosts {KNOWN_NAME}"),
        ])
        .build()
        .expect("a valid sandbox configuration")
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let handle = stack.attach(&pending).expect("the stack attaches");
    let mut running = pending.proceed().expect("the command is released");
    common::outcome_within(&mut running, Duration::from_secs(30));
    drop(running);
    handle.stop().expect("the stack stops cleanly");
    let printed = String::from_utf8_lossy(&observer.stdout);
    assert!(printed.contains("mapped"), "{printed}");
    assert!(
        printed.contains("192.0.2.1"),
        "the name resolved: {printed}"
    );
    received
        .recv_timeout(Duration::from_secs(2))
        .expect("the mapped port's server heard from the guest");

    // A published port, under the same deny.
    let mut observer = Collect::default();
    let pending = common::shell(rootfs, "echo hello from the guest | /usr/bin/nc -l -p 8000")
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let stack = ruled(
        NetStack::builder().publish((Ipv4Addr::LOCALHOST, 0).into(), 8000),
        &[],
        &everything,
    );
    let handle = stack.attach(&pending).expect("the stack attaches");
    let address = handle.published()[0];
    let mut running = pending.proceed().expect("the command is released");
    let (stream, greeting) = connect_published(address);
    assert_eq!(greeting, "hello from the guest\n");
    stream
        .shutdown(std::net::Shutdown::Both)
        .expect("the host closes");
    common::outcome_within(&mut running, Duration::from_secs(10));
    drop(running);
    handle.stop().expect("the stack stops cleanly");
}

// Each flow the stack decides is reported, carried or refused, to the queue the
// handle hands out. The destinations here are refused before anything leaves
// the host, or carried to a listener on the host's loopback, so no test needs a
// route outward.

#[test]
fn each_refusal_arrives_as_its_report() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let (mapped, received) = banner_listener(b"mapped\n");
    let stack = ruled(
        NetStack::builder().host_loopback_port(mapped),
        &["tcp:198.51.100.0/24:443".to_string()],
        &["tcp:198.51.100.66".to_string()],
    );
    // A refused connection is reset, so each `nc` ends at once. The datagrams
    // are three from one socket, one flow.
    let script = format!(
        "echo ping | /usr/bin/nc -w 3 10.0.2.2 {mapped}; \
         for target in '192.0.2.1 443' '198.51.100.66 443' '169.254.169.254 80' \
             '10.0.2.2 9' '10.0.2.3 80'; do \
             /usr/bin/nc -w 3 $target < /dev/null; \
         done; \
         (echo a; sleep 0.2; echo b; sleep 0.2; echo c) | /usr/bin/nc -u -w 1 192.0.2.1 53; \
         true"
    );
    let (_, stdout, reports) = run_reporting(rootfs, &stack, &script);
    assert!(stdout.contains("mapped"), "{stdout}");
    received
        .recv_timeout(Duration::from_secs(2))
        .expect("the mapped port's server heard from the guest");
    assert_eq!(
        reports,
        [
            tcp(
                (Ipv4Addr::new(10, 0, 2, 2), mapped),
                "carried as HostLoopback"
            ),
            tcp(([192, 0, 2, 1], 443), "refused as NotAllowed"),
            tcp(([198, 51, 100, 66], 443), "denied by tcp:198.51.100.66"),
            tcp(([169, 254, 169, 254], 80), "refused as LinkLocal"),
            tcp(([10, 0, 2, 2], 9), "refused as GatewayUnmapped"),
            tcp(([10, 0, 2, 3], 80), "refused as GuestNetwork"),
            (
                Transport::Udp,
                ([192, 0, 2, 1], 53).into(),
                "refused as NotAllowed".to_string()
            ),
        ]
    );
}

#[test]
fn a_reader_that_never_reads_costs_reports_and_never_a_flow() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // More refused connections than the queue holds, then one the stack
    // carries, while nothing reads the reports.
    const REFUSED: usize = 1100;
    const QUEUED: usize = 1024;
    let (mapped, received) = banner_listener(b"carried past the full queue\n");
    let script = format!(
        "i=0; while [ $i -lt {REFUSED} ]; do \
             /usr/bin/nc -w 1 10.0.2.2 9 < /dev/null 2> /dev/null; i=$((i + 1)); \
         done; \
         echo ping | /usr/bin/nc -w 3 10.0.2.2 {mapped}"
    );
    let mut observer = Collect::default();
    let pending = common::shell(rootfs, &script)
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let stack = NetStack::builder()
        .host_loopback_port(mapped)
        .build()
        .expect("a valid stack configuration");
    let mut handle = stack.attach(&pending).expect("the stack attaches");
    let reports = handle
        .take_reports()
        .expect("a fresh handle holds its reports");
    let mut running = pending.proceed().expect("the command is released");
    let status = common::outcome_within(&mut running, Duration::from_secs(60));
    drop(running);
    handle.stop().expect("the stack stops cleanly");

    assert!(status.success(), "{status:?}");
    assert!(
        String::from_utf8_lossy(&observer.stdout).contains("carried past the full queue"),
        "the last connection was carried"
    );
    received
        .recv_timeout(Duration::from_secs(2))
        .expect("the mapped port's server heard from the guest");

    // The queue kept the first reports it was offered, and counted the rest,
    // the carried connection's among them.
    let kept: Vec<NetStackReport> = std::iter::from_fn(|| reports.recv().ok()).collect();
    assert_eq!(kept.len(), QUEUED);
    assert!(
        kept.iter()
            .all(|report| summary(report) == tcp(([10, 0, 2, 2], 9), "refused as GatewayUnmapped")),
        "{kept:?}"
    );
    assert_eq!(
        reports.dropped(),
        u64::try_from(REFUSED + 1 - QUEUED).unwrap()
    );
}

#[test]
fn the_stack_resolves_only_for_the_gateway() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // The interface accepts every destination so that routed traffic reaches
    // the flows' sockets. That switch would also have it answer address
    // resolution for the whole of the guest's link, which would make the stack
    // claim to be every address on it — and would leave the guest with a
    // resolved neighbour for a host that does not exist. Both families resolve:
    // ARP for IPv4, neighbor discovery for IPv6.
    let mut observer = Collect::default();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            // The routed addresses resolve the gateway on their way out; the
            // on-link ones are asked after directly. `fd00::1:2` shares the
            // gateway's low sixteen bits, which is all smoltcp's own
            // solicited-node check compares.
            "/usr/bin/nc -w 2 203.0.113.9 80 </dev/null; \
             /usr/bin/nc -w 2 10.0.2.99 80 </dev/null; \
             /usr/bin/nc -w 2 2001:db8::9 80 </dev/null; \
             /usr/bin/nc -w 2 fd00::1:2 80 </dev/null; \
             cat /proc/net/arp; \
             /sbin/ip -6 neigh show",
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
    common::outcome_within(&mut running, Duration::from_secs(30));
    handle.stop().expect("the stack stops cleanly");

    // A completed ARP entry carries flags 0x2; one the guest asked after and
    // never heard back about stays at 0x0, or is absent entirely.
    let table = String::from_utf8_lossy(&observer.stdout);
    let resolved = |address: &str| {
        table
            .lines()
            .filter(|line| line.split_whitespace().next() == Some(address))
            .any(|line| line.split_whitespace().nth(2) == Some("0x2"))
    };
    assert!(
        resolved("10.0.2.2"),
        "the gateway is the stack, and answers for itself: {table}",
    );
    assert!(
        !resolved("10.0.2.99"),
        "nothing holds an on-link address other than the gateway: {table}",
    );

    // A resolved IPv6 neighbour carries the hardware address it resolved to;
    // a failed or incomplete one carries none.
    let resolved_v6 = |address: &str| {
        table
            .lines()
            .filter(|line| line.split_whitespace().next() == Some(address))
            .any(|line| line.split_whitespace().any(|field| field == "lladdr"))
    };
    assert!(
        resolved_v6("fd00::2"),
        "the gateway is the stack, and answers for itself: {table}",
    );
    assert!(
        !resolved_v6("fd00::1:2"),
        "nothing holds an on-link address other than the gateway: {table}",
    );
}

#[test]
fn stopping_after_the_sandbox_exits_is_clean() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
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

#[test]
fn a_named_loopback_port_is_the_only_one_mapped() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let (granted, _) = banner_listener(b"through the granted port\n");
    let (withheld, withheld_received) = banner_listener(b"through the withheld port\n");

    // Only `granted` maps onto the host's loopback. The guest tries both, and
    // reports what each gave it.
    let mut observer = Collect::default();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            &format!(
                "echo ping | /usr/bin/nc -w 3 10.0.2.2 {granted}; \
                 /usr/bin/nc -w 3 10.0.2.2 {withheld} < /dev/null; true"
            ),
        ])
        .build()
        .expect("a valid sandbox configuration");
    let pending = cage
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let handle = NetStack::builder()
        .host_loopback_port(granted)
        .build()
        .expect("a valid stack configuration")
        .attach(&pending)
        .expect("the stack attaches");
    let mut running = pending.proceed().expect("the command is released");
    common::outcome_within(&mut running, Duration::from_secs(15));
    handle.stop().expect("the stack stops cleanly");

    let stdout = String::from_utf8_lossy(&observer.stdout);
    assert!(
        stdout.contains("through the granted port"),
        "the named port reaches the host service: {stdout:?}",
    );
    assert!(
        !stdout.contains("through the withheld port"),
        "a port not named is refused: {stdout:?}",
    );
    assert!(
        withheld_received
            .recv_timeout(Duration::from_millis(200))
            .is_err(),
        "the withheld service never saw a connection",
    );
}

/// Connects to a published port until the guest's server answers, returning
/// the connected stream and the first line it sent.
///
/// The host listener accepts at once, but the guest's server may not be
/// listening yet, and a connection the guest refuses is reset on the host side
/// before anything arrives. So each attempt reads, and one that ends empty is
/// retried.
fn connect_published(address: std::net::SocketAddr) -> (std::net::TcpStream, String) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            Instant::now() < deadline,
            "the guest's server never answered on {address}",
        );
        if let Ok(mut stream) = std::net::TcpStream::connect(address) {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("the read timeout is set");
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while let Ok(1) = stream.read(&mut byte) {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            if !line.is_empty() {
                return (stream, String::from_utf8_lossy(&line).into_owned());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_published_port_reaches_a_server_in_the_guest() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // The guest serves one connection on its port 8000: it greets, then prints
    // whatever it is sent. The host reaches it through a port the kernel picks.
    let mut observer = Collect::default();
    let cage = common::shell(rootfs, "echo hello from the guest | /usr/bin/nc -l -p 8000");
    let pending = cage
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let handle = NetStack::builder()
        .publish((Ipv4Addr::LOCALHOST, 0).into(), 8000)
        .build()
        .expect("a valid stack configuration")
        .attach(&pending)
        .expect("the stack attaches");
    let address = handle.published()[0];
    assert_ne!(
        address.port(),
        0,
        "the handle reports the port the kernel chose"
    );
    let mut running = pending.proceed().expect("the command is released");

    let (mut stream, greeting) = connect_published(address);
    assert_eq!(greeting, "hello from the guest\n");
    stream.write_all(b"ping\n").expect("the host writes");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("the host half-closes");
    let status = common::outcome_within(&mut running, Duration::from_secs(10));
    handle.stop().expect("the stack stops cleanly");

    assert!(status.success(), "the guest's server ran to completion");
    assert_eq!(
        String::from_utf8_lossy(&observer.stdout).trim(),
        "ping",
        "the host's line reached the guest",
    );
}

#[test]
fn a_published_port_already_in_use_is_refused_at_attach() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback listener binds");
    let address = taken.local_addr().expect("the listener has an address");
    let cage = sleeper(rootfs);
    let pending = cage.spawn_pending().expect("the pending sandbox launches");
    let err = NetStack::builder()
        .publish(address, 80)
        .build()
        .expect("a valid stack configuration")
        .attach(&pending)
        .expect_err("the address is held by another listener");
    assert!(
        matches!(&err, NetStackError::Publish { host, .. } if *host == address),
        "{err:?}",
    );
}

#[test]
fn a_published_connection_the_guest_refuses_is_reset_on_the_host() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // Nothing in the guest listens on the published port. The host listener
    // accepts regardless, so the guest's refusal, its kernel's reset, reaches
    // the host as a reset before any byte, never as an end of stream.
    let pending = sleeper(rootfs)
        .spawn_pending()
        .expect("the pending sandbox launches");
    let handle = NetStack::builder()
        .publish((Ipv4Addr::LOCALHOST, 0).into(), 8000)
        .build()
        .expect("a valid stack configuration")
        .attach(&pending)
        .expect("the stack attaches");
    let address = handle.published()[0];
    let mut running = pending.proceed().expect("the command is released");

    let mut stream = std::net::TcpStream::connect(address).expect("the host listener accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("the read timeout is set");
    let mut buf = [0u8; 16];
    let outcome = stream.read(&mut buf);
    running.kill().expect("the kill is delivered");
    running.wait().expect("the wait completes after a kill");
    handle.stop().expect("the stack stops cleanly");

    assert!(
        matches!(&outcome, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
        "the refused connection was not reset on the host side: {outcome:?}",
    );
}

#[test]
fn a_published_port_reaches_a_server_in_the_guest_over_ipv6() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    if !common::require::TUN.holds(
        TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).is_ok(),
        "the host has no IPv6 loopback",
    ) {
        return;
    }
    // An IPv6 listener carries its connections to the guest's IPv6 address,
    // from the gateway's.
    let mut observer = Collect::default();
    let cage = common::shell(rootfs, "echo hello over ipv6 | /usr/bin/nc -l -p 8000");
    let pending = cage
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let handle = NetStack::builder()
        .publish((Ipv6Addr::LOCALHOST, 0).into(), 8000)
        .build()
        .expect("a valid stack configuration")
        .attach(&pending)
        .expect("the stack attaches");
    let address = handle.published()[0];
    assert!(address.is_ipv6(), "{address}");
    let mut running = pending.proceed().expect("the command is released");

    let (mut stream, greeting) = connect_published(address);
    assert_eq!(greeting, "hello over ipv6\n");
    stream.write_all(b"ping\n").expect("the host writes");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("the host half-closes");
    let status = common::outcome_within(&mut running, Duration::from_secs(10));
    handle.stop().expect("the stack stops cleanly");

    assert!(status.success(), "the guest's server ran to completion");
    assert_eq!(String::from_utf8_lossy(&observer.stdout).trim(), "ping");
}

/// Runs `script` in a sandbox whose `resolv.conf` names `nameservers`, with a
/// stack whose nameserver asks `resolver`, and returns what it printed.
fn resolve_in_guest(
    rootfs: &Path,
    resolver: &Resolver,
    nameservers: &[&str],
    script: &str,
) -> String {
    let mut observer = Collect::default();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .nameservers(nameservers.iter().map(|address| address.parse().unwrap()))
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration");
    let pending = cage
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let handle = NetStack::builder()
        .upstream(resolver.address())
        .build()
        .expect("a stack asking the stand-in resolver")
        .attach(&pending)
        .expect("the stack attaches");
    let mut running = pending.proceed().expect("the command is released");
    common::outcome_within(&mut running, Duration::from_secs(60));
    handle.stop().expect("the stack stops cleanly");
    String::from_utf8_lossy(&observer.stdout).into_owned()
}

#[test]
fn the_nameserver_answers_the_guest_from_its_upstream() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // musl's resolver, through `getent`: a name the upstream knows, and one
    // it answers NXDOMAIN for, which reaches the guest as such.
    let resolver = Resolver::new(1);
    let printed = resolve_in_guest(
        rootfs,
        &resolver,
        &["10.0.2.3"],
        &format!(
            "getent hosts {KNOWN_NAME}; echo known=$?; \
             getent hosts missing.example; echo missing=$?"
        ),
    );
    assert!(printed.contains("192.0.2.1"), "{printed}");
    assert!(printed.contains(KNOWN_NAME), "{printed}");
    assert!(printed.contains("known=0"), "{printed}");
    assert!(
        printed.contains("missing=2"),
        "the name does not resolve: {printed}"
    );
    let (udp, tcp) = resolver.asked();
    assert!(udp > 0, "the queries went upstream over UDP");
    assert_eq!(tcp, 0, "nothing needed TCP");
}

#[test]
fn an_answer_too_long_for_one_packet_reaches_the_guest_over_tcp() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // A hundred and twenty addresses make an answer of nearly 2,000 bytes,
    // past what one 1,500-byte packet carries. The nameserver answers the
    // datagram truncated, and the guest's resolver asks again over TCP, where
    // the whole answer goes.
    let resolver = Resolver::new(120);
    let printed = resolve_in_guest(
        rootfs,
        &resolver,
        &["10.0.2.3"],
        &format!("getent hosts {KNOWN_NAME}; echo known=$?"),
    );
    assert!(
        printed.contains("known=0"),
        "{printed} {:?}",
        resolver.asked()
    );
    assert!(printed.contains("192.0.2."), "{printed}");
    let (_, tcp) = resolver.asked();
    assert!(tcp > 0, "the guest asked again over TCP: {printed}");
}

#[test]
fn the_nameserver_answers_on_its_ipv6_address() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let resolver = Resolver::new(1);
    let printed = resolve_in_guest(
        rootfs,
        &resolver,
        &["fd00::3"],
        &format!("getent hosts {KNOWN_NAME}; echo known=$?"),
    );
    assert!(printed.contains("known=0"), "{printed}");
    assert!(printed.contains("192.0.2.1"), "{printed}");
}

#[test]
fn a_tcp_connection_to_the_nameserver_carries_each_of_its_queries() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // Two queries for the known name, ids 0x1234 and 0x1235, each with its
    // length prefix, sent back to back on one connection, which the guest then
    // closes. Each answer comes back framed, under its own id.
    let query = |id: &str| {
        format!(
            "\\000\\042{id}\\001\\000\\000\\001\\000\\000\\000\\000\\000\\000\\010resolver\\007example\\000\\000\\001\\000\\001"
        )
    };
    let resolver = Resolver::new(1);
    let printed = resolve_in_guest(
        rootfs,
        &resolver,
        &["10.0.2.3"],
        &format!(
            "printf '{}{}' | nc -w 5 10.0.2.3 53 | od -An -v -tx1 | tr -s ' \\n' ' '",
            query("\\022\\064"),
            query("\\022\\065"),
        ),
    );
    // The answer is 50 bytes: the 34-byte query, as a response, and one A
    // record of 16.
    let answer = |id: &str| format!("00 32 12 {id} 81 80 00 01 00 01 00 00 00 00 ");
    assert!(printed.contains(&answer("34")), "{printed}");
    assert!(printed.contains(&answer("35")), "{printed}");
    assert!(
        printed.contains("c0 0c 00 01 00 01 00 00 00 3c 00 04 c0 00 02 01"),
        "{printed}"
    );
    assert_eq!(
        resolver.asked(),
        (0, 2),
        "each query went upstream over TCP"
    );
}

// Name rules: the nameserver holds each question to the rules, and a flow is
// admitted by the names its answers resolved. The addresses are documentation
// ones, which a carried flow's host connect starts toward and nothing answers,
// so these tests need the host's route outward that `routable` reports.

/// What the name-rule tests' zone resolves its names to.
const ADMITTED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const REFUSED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);
const EDGE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);
const STRAY: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const PRIVATE: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 1);

/// The stand-in resolver the name-rule tests ask, with records of a second's
/// life.
fn naming_resolver() -> Resolver {
    Resolver::serving(
        vec![
            (
                "admitted.example",
                vec![
                    ("admitted.example", Record::A(ADMITTED)),
                    ("admitted.example", Record::Https),
                ],
            ),
            (
                "refused.example",
                vec![("refused.example", Record::A(REFUSED))],
            ),
            (
                "alias.example",
                vec![
                    ("alias.example", Record::Cname("edge.cdn.example")),
                    ("edge.cdn.example", Record::A(EDGE)),
                    ("stray.example", Record::A(STRAY)),
                ],
            ),
            (
                "private.example",
                vec![("private.example", Record::A(PRIVATE))],
            ),
        ],
        1,
    )
}

/// A stack asking `resolver`, with `allow` and `deny` rules given as text.
fn naming(resolver: &Resolver, allow: &[&str], deny: &[&str]) -> NetStack {
    let text = |rules: &[&str]| -> Vec<String> { rules.iter().map(ToString::to_string).collect() };
    ruled(
        NetStack::builder().upstream(resolver.address()),
        &text(allow),
        &text(deny),
    )
}

/// Runs `script` in the sandbox `cage` builds, its `resolv.conf` naming the
/// stack's nameserver, with `stack` attached, and returns what it printed,
/// every report the stack made, and how long the command ran.
fn run_naming(
    cage: CageBuilder,
    stack: &NetStack,
    script: &str,
) -> (String, Vec<NetStackReport>, Duration) {
    let mut observer = Collect::default();
    let pending = cage
        .nameservers(stack.nameservers())
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
        .spawn_pending_with(&mut observer)
        .expect("the pending sandbox launches");
    let mut handle = stack.attach(&pending).expect("the stack attaches");
    let reports = handle
        .take_reports()
        .expect("a fresh handle holds its reports");
    let started = Instant::now();
    let mut running = pending.proceed().expect("the command is released");
    common::outcome_within(&mut running, Duration::from_secs(30));
    let took = started.elapsed();
    drop(running);
    handle.stop().expect("the stack stops cleanly");
    (
        String::from_utf8_lossy(&observer.stdout).into_owned(),
        std::iter::from_fn(|| reports.recv().ok()).collect(),
        took,
    )
}

/// The question reports among `reports`, each as its name and its decision:
/// relayed by default or by a named rule, refused for a reason, or withheld.
fn questions(reports: &[NetStackReport]) -> Vec<(String, String)> {
    reports
        .iter()
        .filter_map(|report| match report {
            NetStackReport::QuestionRelayed {
                name, admission, ..
            } => Some((name.clone(), admitted_as(admission))),
            NetStackReport::QuestionRefused { name, refusal, .. } => {
                Some((name.clone(), refused_as(refusal)))
            }
            NetStackReport::QuestionWithheld { name, .. } => {
                Some((name.clone(), "withheld".to_string()))
            }
            _ => None,
        })
        .collect()
}

/// The flow reports among `reports`, each as its transport, its destination,
/// the name resolved to it, and its decision.
fn flows(reports: &[NetStackReport]) -> Vec<(Transport, SocketAddr, Option<String>, String)> {
    reports
        .iter()
        .filter_map(|report| match report {
            NetStackReport::FlowAdmitted {
                transport,
                destination,
                name,
                admission,
                ..
            } => Some((
                *transport,
                *destination,
                name.clone(),
                admitted_as(admission),
            )),
            NetStackReport::FlowRefused {
                transport,
                destination,
                name,
                refusal,
                ..
            } => Some((*transport, *destination, name.clone(), refused_as(refusal))),
            _ => None,
        })
        .collect()
}

#[test]
fn a_name_the_rules_refuse_does_not_resolve_and_fails_at_once() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    // musl's resolver from the fixture's root, and glibc's from the host's,
    // where the host has one.
    let mut libraries = vec![("musl", Cage::builder().rootfs(rootfs))];
    if Path::new("/usr/bin/getent").exists() {
        libraries.push(("glibc", Cage::builder().host_rootfs()));
    }
    for (library, cage) in libraries {
        for (allow, deny) in [
            (&["admitted.example"][..], &[][..]),
            (&[], &["refused.example"]),
        ] {
            let resolver = naming_resolver();
            let stack = naming(&resolver, allow, deny);
            let (printed, reports, _) = run_naming(
                cage.clone(),
                &stack,
                "getent hosts admitted.example; echo admitted=$?; \
                 getent hosts refused.example; echo refused=$?",
            );
            let under = format!("{library} under allow {allow:?}, deny {deny:?}");
            assert!(printed.contains("198.51.100.7"), "{under}: {printed}");
            assert!(printed.contains("admitted=0"), "{under}: {printed}");
            assert!(printed.contains("refused=2"), "{under}: {printed}");
            assert!(!printed.contains("198.51.100.8"), "{under}: {printed}");
            assert_eq!(resolver.asked_for("refused.example"), 0, "{under}");
            assert!(resolver.asked_for("admitted.example") > 0, "{under}");
            let (relayed, refused) = match allow.is_empty() {
                true => ("carried as Default", "denied by refused.example"),
                false => ("allowed by admitted.example", "refused as NotAllowed"),
            };
            let asked = questions(&reports);
            assert!(!asked.is_empty(), "{under}");
            for (name, decision) in asked {
                let expected = match name.as_str() {
                    "admitted.example" => relayed,
                    "refused.example" => refused,
                    other => panic!("{under}: a question for {other}"),
                };
                assert_eq!(decision, expected, "{under}: {name}");
            }

            // A refused name ends the lookup at once, where a refusal of
            // another kind would cost the resolver its timeout.
            let (printed, _, took) = run_naming(
                cage.clone(),
                &stack,
                "getent hosts refused.example; echo refused=$?",
            );
            assert!(printed.contains("refused=2"), "{under}: {printed}");
            assert!(took < Duration::from_secs(3), "{under}: {took:?}");
        }
    }
}

#[test]
fn a_name_rule_admits_tcp_to_what_its_answers_resolved_for_the_sandboxs_life() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    if routable().is_none() {
        return;
    }
    // The answer reaches its address through an alias, beside a record for a
    // name off its chain, and lives a second; the connections come after two.
    let resolver = naming_resolver();
    let stack = naming(&resolver, &["alias.example"], &[]);
    let (printed, reports, _) = run_naming(
        Cage::builder().rootfs(rootfs),
        &stack,
        &format!(
            "getent hosts alias.example; sleep 2; \
             /usr/bin/nc -w 1 {EDGE} 443 < /dev/null; \
             /usr/bin/nc -w 1 {STRAY} 443 < /dev/null; \
             echo datagram | /usr/bin/nc -u -w 1 {EDGE} 443; true"
        ),
    );
    assert!(printed.contains("198.51.100.9"), "{printed}");
    let alias = || Some("alias.example".to_string());
    assert_eq!(
        flows(&reports),
        [
            (
                Transport::Tcp,
                (EDGE, 443).into(),
                alias(),
                "allowed by alias.example".to_string()
            ),
            (
                Transport::Tcp,
                (STRAY, 443).into(),
                None,
                "refused as NotResolved".to_string()
            ),
            (
                Transport::Udp,
                (EDGE, 443).into(),
                alias(),
                "over udp under alias.example".to_string()
            ),
        ]
    );
}

#[test]
fn a_name_rule_admits_no_private_address_and_an_address_rule_does() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    if routable().is_none() {
        return;
    }
    let script =
        format!("getent hosts private.example; /usr/bin/nc -w 1 {PRIVATE} 443 < /dev/null; true");
    let named = || Some("private.example".to_string());
    for (allow, decision) in [
        (&["private.example"][..], "private behind private.example"),
        (
            &["private.example", "10.255.255.1"],
            "allowed by 10.255.255.1",
        ),
    ] {
        let resolver = naming_resolver();
        let stack = naming(&resolver, allow, &[]);
        let (printed, reports, _) = run_naming(Cage::builder().rootfs(rootfs), &stack, &script);
        assert!(printed.contains("10.255.255.1"), "{allow:?}: {printed}");
        assert_eq!(
            flows(&reports),
            [(
                Transport::Tcp,
                (PRIVATE, 443).into(),
                named(),
                decision.to_string()
            )],
            "{allow:?}"
        );
    }
}

/// A shell `printf` format writing `bytes`, each as an octal escape.
fn printf_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\{byte:03o}")).collect()
}

/// A query under `id` for `name`'s records of `record_type`, with recursion
/// desired, and an OPT record where `edns` says.
fn raw_query(id: u16, name: &str, record_type: u16, edns: bool) -> Vec<u8> {
    let mut query = id.to_be_bytes().to_vec();
    query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, u8::from(edns)]);
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).expect("a label's length"));
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&[0, 1]);
    if edns {
        query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    }
    query
}

/// Lowercase hex, a space after each byte, as `od -An -tx1` writes it once
/// `tr` joins its lines.
fn spaced_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x} ")).collect()
}

#[test]
fn the_nameserver_gives_its_reason_and_withholds_service_bindings() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let resolver = naming_resolver();
    let stack = naming(&resolver, &["admitted.example"], &[]);
    let ask = |query: Vec<u8>| {
        format!(
            "printf '{}' | /usr/bin/nc -u -w 2 10.0.2.3 53 | od -An -v -tx1 | tr -s ' \\n' ' '; \
             echo",
            printf_bytes(&query)
        )
    };
    let script = [
        ask(raw_query(0x1234, "refused.example", 1, true)),
        ask(raw_query(0x1235, "refused.example", 1, false)),
        ask(raw_query(0x1236, "admitted.example", 65, true)),
    ]
    .join("; ");
    let (printed, reports, _) = run_naming(Cage::builder().rootfs(rootfs), &stack, &script);
    let lines: Vec<&str> = printed.lines().map(str::trim).collect();
    assert_eq!(lines.len(), 3, "{printed}");

    // NXDOMAIN, with Extended DNS Error 15 and the reason where the query reads
    // EDNS, and the code alone where it does not.
    let reason = "no allow rule admits it";
    assert!(
        lines[0].starts_with("12 34 81 83 00 01 00 00 00 00 00 01"),
        "{}",
        lines[0]
    );
    let mut option = vec![0, 15];
    option.extend_from_slice(&u16::try_from(2 + reason.len()).unwrap().to_be_bytes());
    option.extend_from_slice(&[0, 15]);
    option.extend_from_slice(reason.as_bytes());
    assert!(
        lines[0].ends_with(spaced_hex(&option).trim_end()),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("12 35 81 83 00 01 00 00 00 00 00 00"),
        "{}",
        lines[1]
    );
    // An admitted name's HTTPS records: none, and none asked for upstream.
    assert!(
        lines[2].starts_with("12 36 81 80 00 01 00 00 00 00 00 01"),
        "{}",
        lines[2]
    );
    assert_eq!(resolver.asked(), (0, 0), "nothing was relayed");
    assert_eq!(
        questions(&reports),
        [
            (
                "refused.example".to_string(),
                "refused as NotAllowed".to_string()
            ),
            (
                "refused.example".to_string(),
                "refused as NotAllowed".to_string()
            ),
            ("admitted.example".to_string(), "withheld".to_string()),
        ]
    );
}
