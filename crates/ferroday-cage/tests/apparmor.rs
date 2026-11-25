//! Integration tests for a launch under an AppArmor profile that refuses a mount
//! the launch makes, as a container runtime's default profile refuses every
//! one.
//!
//! The probe is this test binary, run again under the profile through
//! `aa-exec`. [`PROFILE`] names the profile, which is loaded beforehand:
//! `tests/fixtures/apparmor/refuses-mounts`, as CI loads it, or any profile in
//! enforce mode that allows a user namespace and refuses a mount a launch
//! makes.

mod common;

use std::process::Command;
use std::time::Duration;

use ferroday_cage::host::Confinement;
use ferroday_cage::{Error, ErrorChain};

/// Names the loaded profile the probe runs under.
const PROFILE: &str = "FERRODAY_CAGE_APPARMOR_PROFILE";

/// Set under the profile to make the probe test probe rather than return.
const PROBE: &str = "FERRODAY_CAGE_TEST_APPARMOR_PROBE";

/// How long the probe may take: one launch that fails during its setup.
const PATIENCE: Duration = Duration::from_secs(60);

/// Launches a sandbox under the profile and reports what the launch did, on
/// lines the outer test reads: the refusal's fields, and its message.
#[test]
fn probe_launch() {
    if std::env::var_os(PROBE).is_none() {
        return;
    }
    // Under `--nocapture` the harness has printed `test <name> ... ` without
    // ending the line.
    println!();
    let outcome = common::host_userland()
        .command("/bin/true")
        .build()
        .expect("a valid sandbox configuration")
        .run();
    match outcome {
        Err(err) => {
            if let Error::MountRefused {
                step, confinement, ..
            } = &err
            {
                match confinement {
                    Confinement::AppArmor { profile, mode, .. } => {
                        println!("refused {step:?} {profile} {mode}");
                    }
                    other => println!("refused {step:?} {other:?}"),
                }
            }
            println!("message {}", ErrorChain::new(&err));
        }
        Ok(status) => println!("ran {status:?}"),
    }
    println!("probe done");
}

/// A launch under a profile that refuses one of its mounts fails naming the
/// profile and its mode, in place of a bare `EACCES` at the step.
#[test]
fn a_mount_the_confining_profile_refuses_names_the_profile() {
    let Some(profile) = std::env::var(PROFILE).ok().filter(|name| !name.is_empty()) else {
        common::require::APPARMOR.skip(format!("{PROFILE} names no loaded AppArmor profile"));
        return;
    };
    if !common::require::userns() {
        return;
    }
    let exe = std::env::current_exe().expect("the test binary has a path");
    let mut command = Command::new("aa-exec");
    command
        .args(["-p", &profile, "--"])
        .arg(exe)
        .args(common::rerun_args("probe_launch"))
        .env(PROBE, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let output = common::run_bounded(&mut command, PATIENCE);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("probe done"),
        "the probe did not finish under {profile:?}:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    let reported = |key: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(' '))
            .unwrap_or_else(|| panic!("the probe reported no {key}:\n{stdout}"))
            .to_string()
    };
    let refused = reported("refused");
    let (step, named) = refused
        .split_once(' ')
        .unwrap_or_else(|| panic!("a refusal names its step: {refused}"));
    let (label, mode) = named
        .rsplit_once(' ')
        .unwrap_or_else(|| panic!("a refusal names a mode: {named}"));
    // The label is the profile, or a stack holding it where the process that
    // ran the probe was confined already, as a CI runner's job can be: the
    // kernel joins a stack's names with `//&`, and the refusal names the label
    // as the kernel writes it.
    assert!(
        label.split("//&").any(|name| name == profile),
        "the refusal names the profile the launch ran under, at {step}: {label}",
    );
    assert_eq!(mode, "enforce", "at {step}");
    let message = reported("message");
    assert!(
        message.contains(&format!("the AppArmor profile {label:?} in enforce mode")),
        "{message}"
    );
    assert!(
        message.ends_with("Permission denied (os error 13)"),
        "the kernel's EACCES is the cause: {message}"
    );
}
