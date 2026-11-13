//! Integration tests for a launch under a procfs whose entries are masked, as
//! inside a container a runtime started with its defaults.
//!
//! The container is a sandbox: an empty root holding the host's own userland,
//! with the managed fresh procfs and `/dev/null` bound over one of its entries,
//! as a runtime masks `/proc/keys`. The probe is this test binary, run again
//! inside it, and it launches sandboxes of its own and reports what each did.

mod common;

use ferroday_cage::host::{self, ProcfsBlocker};
use ferroday_cage::{Error, ErrorChain};

/// Set inside the outer sandbox to make the probe test probe rather than
/// return.
const PROBE: &str = "FERRODAY_CAGE_TEST_PROCFS_PROBE";

/// Where the test binary is bound inside the outer sandbox.
const PROBE_PATH: &str = "/probe";

/// The procfs entry the outer sandbox masks.
const MASKED: &str = "/proc/keys";

/// Launches sandboxes from inside the masked one and reports each outcome on a
/// line of its own: the host check, a launch with a PID namespace of its own,
/// and one sharing the caller's.
#[test]
fn probe_launches() {
    if std::env::var_os(PROBE).is_none() {
        return;
    }
    // Under `--nocapture` the harness has printed `test <name> ... ` without
    // ending the line.
    println!();
    println!("blocker {}", described(host::procfs_blocker().as_ref()));
    let fresh = common::host_userland()
        .command("/bin/true")
        .build()
        .expect("a valid sandbox configuration")
        .run();
    match fresh {
        Err(err) => match &err {
            Error::ProcfsRefused { blocker, .. } => {
                println!("fresh refused {}", described(Some(blocker)));
                println!("fresh message {}", ErrorChain::new(&err));
            }
            _ => println!("fresh {}", ErrorChain::new(&err)),
        },
        Ok(status) => println!("fresh {status:?}"),
    }
    let shared = common::host_userland()
        .pid_namespace(false)
        .command("/bin/sh")
        .args(["-c", &format!("test -c {MASKED}")])
        .build()
        .expect("a valid sandbox configuration")
        .run();
    match shared {
        Ok(status) => println!("shared {}", status.code().unwrap_or(-1)),
        Err(err) => println!("shared {}", ErrorChain::new(&err)),
    }
    println!("probe done");
}

/// A blocker as one token the outer test can compare: the covering mounts
/// joined with commas, `refused`, or `none`.
fn described(blocker: Option<&ProcfsBlocker>) -> String {
    match blocker {
        None => "none".to_string(),
        Some(ProcfsBlocker::Covered { mounts, .. }) => mounts
            .iter()
            .map(|mount| mount.display().to_string())
            .collect::<Vec<_>>()
            .join(","),
        Some(ProcfsBlocker::Refused) => "refused".to_string(),
        Some(other) => format!("{other:?}"),
    }
}

#[test]
fn a_masked_procfs_refuses_a_fresh_one_and_a_shared_pid_namespace_launches() {
    if !common::require::userns() {
        return;
    }
    // The outer sandbox mounts a fresh procfs itself, which a host that is
    // already a masked container refuses.
    if let Some(blocker) = host::procfs_blocker() {
        common::require::premise_unmet(format!(
            "this host cannot mount a fresh procfs to mask: {blocker}"
        ));
        return;
    }
    let exe = std::env::current_exe().expect("the test binary has a path");
    let output = common::host_userland()
        .command(PROBE_PATH)
        .args([
            "--exact",
            "probe_launches",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE, "1")
        .bind_ro(&exe, PROBE_PATH)
        .bind_ro("/dev/null", MASKED)
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the outer sandbox launches");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("probe done"),
        "the probe did not finish:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    let reported = |key: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(' '))
            .unwrap_or_else(|| panic!("the probe reported no {key}:\n{stdout}"))
            .to_string()
    };
    assert_eq!(reported("blocker"), MASKED, "the host check names the mask");
    assert_eq!(
        reported("fresh refused"),
        MASKED,
        "a launch with a PID namespace of its own is refused, naming the mask",
    );
    let message = reported("fresh message");
    for remedy in ["systempaths=unconfined", "pid_namespace(false)"] {
        assert!(
            message.contains(remedy),
            "the refusal names {remedy}: {message}"
        );
    }
    assert_eq!(
        reported("shared"),
        "0",
        "sharing the PID namespace binds the masked procfs, mask included",
    );
}
