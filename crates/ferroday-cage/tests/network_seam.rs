//! Integration tests for the userspace-network seam: the pending launch, the
//! network-namespace target it exposes, the gate that holds the command until
//! the caller proceeds, and the teardown when a pending launch is abandoned.

mod common;

use common::{Collect, process_exists, sleeper, wait_gone};

use std::time::Duration;

use ferroday_cage::{Cage, Network};

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
