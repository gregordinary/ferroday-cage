//! Integration tests for what `fcage` says about a launch before it starts it.
//!
//! `fcage` starts a launch five ways: a sandbox plainly, on a terminal, or held
//! at the pending seam for a network stack, and a restriction plainly or on a
//! terminal. What a build leaves unapplied is said on standard error whichever
//! of them a run takes, so each is driven here with cgroup limits it cannot
//! apply and is not required to.
//!
//! The sandbox tests skip explicitly, on stderr, on a host that cannot create
//! unprivileged user namespaces, the restriction tests on a kernel that offers
//! no seccomp or no Landlock, and the network stack's on a host without
//! `/dev/net/tun`. Every
//! run is bounded, so a launch that never finishes fails its test rather than
//! hanging the suite.

mod common;

use std::process::{Command, Stdio};
use std::time::Duration;

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// How long one run may take before its test fails. Far beyond what any run
/// here needs; it exists so a launch that never finishes is a failure.
const PATIENCE: Duration = Duration::from_secs(60);

/// Limits with no `--cgroup-parent` to apply them beneath, which a launch runs
/// without because they are not required.
const UNAPPLIED: [&str; 3] = ["--cgroup", "pids-max=64", "--no-cgroup-required"];

/// What `fcage` says of them.
const NOTICE: &str = "the cgroup limits are not applied";

/// Runs `fcage` with `args` and the limits above, then `-- /bin/true`, and
/// checks the run succeeded and said once that the limits are not applied.
fn assert_notice(case: &str, args: &[&str]) {
    let mut command = Command::new(FCAGE);
    command
        .args(args)
        .args(UNAPPLIED)
        .args(["--", "/bin/true"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = common::run_bounded(&mut command, PATIENCE);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{case}: {}: {stderr}",
        output.status
    );
    assert_eq!(
        stderr.matches(NOTICE).count(),
        1,
        "{case}: the unapplied limits were not said once: {stderr:?}",
    );
}

#[test]
fn a_sandbox_says_its_limits_are_not_applied_however_it_starts() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    assert_notice("plain", &["--rootfs", rootfs]);
    assert_notice("terminal", &["--rootfs", rootfs, "--terminal"]);
    if common::require::tun() {
        assert_notice(
            "pending",
            &["--rootfs", rootfs, "--netstack", "--no-resolv-conf"],
        );
    }
}

#[test]
fn a_restriction_says_its_limits_are_not_applied_however_it_starts() {
    if !(common::require::seccomp()
        && common::require::landlock(ferroday_cage::host::landlock_abi()))
    {
        return;
    }
    // A restriction with cgroup limits builds only where its command can
    // neither write the cgroup's files nor call clone3, required or not.
    let restricted = ["--restrict", "--landlock-ro", "/", "--seccomp", "curated"];
    assert_notice("plain", &restricted);
    assert_notice("terminal", &[&restricted[..], &["--terminal"]].concat());
}

#[test]
fn the_resolved_inputs_name_what_fcage_adds_around_the_sandbox() {
    // The library's resolved inputs record the sandbox; the stack, a forward,
    // the timeout and the relays are fcage's, printed as a table of its own.
    let output = common::run_bounded(
        Command::new(FCAGE)
            .args([
                "--print-resolved",
                "--host-rootfs",
                "--netstack",
                "--netstack-allow",
                "example.com:443",
                "--forward-loopback",
                "8080",
                "127.0.0.1:9",
                "--timeout",
                "30",
                "--",
                "/bin/true",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        PATIENCE,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed: toml::Table = String::from_utf8_lossy(&output.stdout)
        .parse()
        .expect("the inputs are TOML");
    let fcage = printed["fcage"].as_table().expect("an [fcage] table");
    assert_eq!(fcage["terminal"].as_bool(), Some(false));
    assert_eq!(fcage["timeout"].as_float(), Some(30.0));
    let forward = fcage["forwards"][0].as_table().expect("the forward");
    assert_eq!(forward["listen"].as_str(), Some("127.0.0.1:8080"));
    assert_eq!(forward["target"].as_str(), Some("127.0.0.1:9"));
    let allow = fcage["netstack"]["allow"]
        .as_array()
        .expect("the stack's rules");
    assert_eq!(allow[0].as_str(), Some("example.com:443"));
    // Standard input is null and the other two are pipes, so nothing is
    // relayed.
    assert_eq!(fcage["relayed"].as_array().map(Vec::len), Some(0));
}
