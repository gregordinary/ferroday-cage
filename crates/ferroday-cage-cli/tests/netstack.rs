//! Integration tests for `fcage --netstack`: what the built binary refuses
//! before a native network stack carries a sandbox's traffic.
//!
//! The tests skip explicitly, on stderr, on a host that cannot create
//! unprivileged user namespaces or offers no seccomp. Every run is bounded, so
//! a launch that never finishes fails its test rather than hanging the suite.

mod common;

use std::process::{Command, Stdio};
use std::time::Duration;

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// How long one run may take before its test fails. Far beyond what any run
/// here needs; it exists so a launch that never finishes is a failure.
const PATIENCE: Duration = Duration::from_secs(60);

/// A Landlock network grant is the only bound on the ports a sandbox reaches
/// through an attached stack, so `--netstack` refuses one the kernel does not
/// enforce, and the command never runs.
///
/// The host's kernel enforces network grants, so the inner `fcage` runs under
/// an outer `fcage --restrict` whose seccomp policy answers
/// `landlock_create_ruleset` with `ENOSYS`, which is how a kernel without the
/// LSM answers.
#[test]
fn a_network_grant_the_kernel_cannot_enforce_refuses_the_stack() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() || !common::require::seccomp() {
        return;
    }
    let mut command = Command::new(FCAGE);
    command
        .args([
            "--restrict",
            "--seccomp-errno",
            "landlock_create_ruleset=ENOSYS",
        ])
        .args(["--", FCAGE])
        .args(["--rootfs", rootfs.to_str().expect("a UTF-8 fixture path")])
        .args([
            "--netstack",
            "--no-resolv-conf",
            "--landlock-connect",
            "443",
        ])
        .args(["--", "/bin/echo", "the command ran"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = common::run_bounded(&mut command, PATIENCE);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stdout.contains("the command ran"),
        "the command ran past a grant the kernel cannot enforce: {stderr}",
    );
    assert!(
        stderr.contains("offers no Landlock LSM")
            && stderr.contains("an attached network stack would carry its connections"),
        "the stack was not refused for the grant: {stderr}",
    );
    assert!(!output.status.success(), "{}", output.status);
}
