//! Integration tests for `fcage --netstack`: what the built binary refuses
//! before a native network stack carries a sandbox's traffic, the names a
//! sandbox resolves through the stack's nameserver, and the stack's reports it
//! writes on standard error.
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

/// Runs `fcage` with `args`, then `--netstack`, the stand-in resolver as the
/// stack's upstream, and `getent hosts` for the name it knows, and returns
/// whether it succeeded, what it printed, and what it said on stderr.
fn resolve_known_name(args: &[&str], getent: &str) -> (bool, String, String) {
    let resolver = common::dns::Resolver::new(1);
    let upstream = resolver.address().to_string();
    let mut command = Command::new(FCAGE);
    command
        .args(args)
        .args(["--netstack", "--netstack-upstream", &upstream])
        .args(["--", getent, "hosts", common::dns::KNOWN_NAME])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = common::run_bounded(&mut command, PATIENCE);
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// `--netstack` names the stack's nameserver in the sandbox's `resolv.conf`,
/// so the sandbox resolves through the stack, here from a resolver on the
/// host's loopback, which the sandbox's own traffic never reaches.
#[test]
fn netstack_resolves_through_the_stack_s_nameserver() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    let (ok, stdout, stderr) = resolve_known_name(&["--rootfs", rootfs], "/usr/bin/getent");
    assert!(ok, "{stderr}");
    assert!(stdout.contains("192.0.2.1"), "{stdout}\n{stderr}");
}

/// Under the host's own root the host's C library resolves, and the sandbox's
/// `resolv.conf` is the host's, commonly a link into the hidden `/run`. The
/// stack's nameserver is named where it leads.
#[test]
fn netstack_resolves_through_the_stack_s_nameserver_under_the_host_root() {
    if !common::require::tun() {
        return;
    }
    let getent = "/usr/bin/getent";
    if !std::path::Path::new(getent).is_file() {
        common::require::premise_unmet("the host has no /usr/bin/getent to resolve with");
        return;
    }
    if std::fs::canonicalize("/etc/resolv.conf").is_err() {
        common::require::premise_unmet("the host has no /etc/resolv.conf to read through");
        return;
    }
    let (ok, stdout, stderr) = resolve_known_name(&["--host-rootfs"], getent);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("192.0.2.1"), "{stdout}\n{stderr}");
}

/// Runs `fcage --rootfs ROOTFS --netstack` with `args`, then `/bin/sh -c
/// script`, and returns what it said on stderr.
fn stderr_of(rootfs: &str, args: &[&str], script: &str) -> String {
    let mut command = Command::new(FCAGE);
    command
        .args(["--rootfs", rootfs, "--netstack"])
        .args(args)
        .args(["--", "/bin/sh", "-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = common::run_bounded(&mut command, PATIENCE);
    assert!(output.status.success(), "{}", output.status);
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The lines `fcage` wrote of the network stack's reports, each with the
/// guest's port, which the guest's kernel chooses, left out. The guest is
/// `10.0.2.15`, or `fd00::15` where it wrote from its IPv6 address, as musl's
/// resolver does in asking each nameserver at once.
fn stack_lines(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|line| line.starts_with("fcage: the network stack "))
        .map(|line| {
            let (before, guest, after) = ["10.0.2.15", "fd00::15"]
                .into_iter()
                .find_map(|guest| {
                    let endpoint = match guest.contains(':') {
                        true => format!("from [{guest}]:"),
                        false => format!("from {guest}:"),
                    };
                    let (before, after) = line.split_once(&endpoint)?;
                    Some((before, guest, after))
                })
                .unwrap_or_else(|| panic!("a report names the guest: {line}"));
            let after = after.trim_start_matches(|c: char| c.is_ascii_digit());
            format!("{before}from {guest}{after}")
        })
        .collect()
}

/// Under destination rules each refusal is written on standard error, saying
/// why, and a flow the stack carries is not.
#[test]
fn refusals_are_written_under_destination_rules() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    let mapped = std::net::TcpListener::bind("127.0.0.1:0").expect("a host listener binds");
    let port = mapped.local_addr().expect("an address").port().to_string();
    let stderr = stderr_of(
        rootfs,
        &[
            "--netstack-host-port",
            &port,
            "--netstack-allow",
            "tcp:198.51.100.0/24:443",
        ],
        &format!(
            "/usr/bin/nc -w 1 10.0.2.2 {port} < /dev/null; \
             /usr/bin/nc -w 1 192.0.2.1 443 < /dev/null; \
             /usr/bin/nc -w 1 169.254.169.254 80 < /dev/null; true"
        ),
    );
    assert_eq!(
        stack_lines(&stderr),
        [
            "fcage: the network stack refused tcp from 10.0.2.15 to 192.0.2.1:443: no allow rule \
             admits it",
            "fcage: the network stack refused tcp from 10.0.2.15 to 169.254.169.254:80: a \
             link-local address, where the cloud metadata services answer, is always refused",
        ],
        "{stderr}"
    );
}

/// Under a name rule a lookup the rules refuse is written as the question the
/// stack's nameserver refused, and the lookup it admits is not.
#[test]
fn a_refused_question_is_written_under_name_rules() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    let resolver = common::dns::Resolver::new(1);
    let upstream = resolver.address().to_string();
    let stderr = stderr_of(
        rootfs,
        &[
            "--netstack-upstream",
            &upstream,
            "--netstack-allow",
            common::dns::KNOWN_NAME,
        ],
        &format!(
            "/usr/bin/getent hosts {} > /dev/null; /usr/bin/getent hosts other.example; true",
            common::dns::KNOWN_NAME
        ),
    );
    let lines = stack_lines(&stderr);
    assert!(!lines.is_empty(), "{stderr}");
    for line in lines {
        let (start, end) = line
            .split_once(" question ")
            .unwrap_or_else(|| panic!("a question: {line}"));
        assert!(
            start.starts_with("fcage: the network stack refused the "),
            "{line}"
        );
        let guest = end
            .strip_prefix("for other.example from ")
            .and_then(|end| end.strip_suffix(": no allow rule admits it"));
        assert!(matches!(guest, Some("10.0.2.15" | "fd00::15")), "{stderr}");
    }
}

/// Without rules nothing is written, and `--netstack-log` writes every flow,
/// carried or refused.
#[test]
fn the_log_writes_every_flow_and_nothing_is_written_without_it() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::tun() {
        return;
    }
    let rootfs = rootfs.to_str().expect("a UTF-8 fixture path");
    let mapped = std::net::TcpListener::bind("127.0.0.1:0").expect("a host listener binds");
    let port = mapped.local_addr().expect("an address").port().to_string();
    let script = format!(
        "/usr/bin/nc -w 1 10.0.2.2 {port} < /dev/null; \
         /usr/bin/nc -w 1 10.0.2.2 9 < /dev/null; true"
    );

    let quiet = stderr_of(rootfs, &["--netstack-host-port", &port], &script);
    assert_eq!(stack_lines(&quiet), Vec::<String>::new(), "{quiet}");

    let logged = stderr_of(
        rootfs,
        &["--netstack-host-port", &port, "--netstack-log"],
        &script,
    );
    assert_eq!(
        stack_lines(&logged),
        [
            format!(
                "fcage: the network stack carried tcp from 10.0.2.15 to 10.0.2.2:{port}: the \
                 gateway's port is mapped to the host's loopback"
            ),
            "fcage: the network stack refused tcp from 10.0.2.15 to 10.0.2.2:9: the gateway's \
             port is not mapped to the host's loopback"
                .to_string(),
        ],
        "{logged}"
    );
}
