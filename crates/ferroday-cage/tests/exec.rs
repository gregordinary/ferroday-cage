//! Integration tests for a further command run in a running sandbox: what it
//! shares with the first command and what is its own, how it ends, and the
//! sandbox's end seen from it.

mod common;

use common::Collect;

use std::time::Duration;

use std::io::Read as _;

use ferroday_cage::{Cage, ConfigError, Error, Exec, IdentityMap, Running, Stdio, Terminal};

/// How long a test waits for an outcome it expects promptly.
const PATIENCE: Duration = Duration::from_secs(30);

/// A sandbox on the fixture root whose first command writes its own pid to
/// `/tmp/first` and then sleeps, with `hostname` set: something running for a
/// further command to find.
///
/// Every sandbox these tests leave running ends with its handle, so a test that
/// fails mid-way leaves none behind holding the harness's output open.
fn running_sandbox(rootfs: &std::path::Path, pid_namespace: bool) -> Running<'static> {
    Cage::builder()
        .rootfs(rootfs)
        .stop_with_caller(true)
        .hostname("joined")
        .pid_namespace(pid_namespace)
        .command("/bin/sh")
        .args(["-c", "echo $$ > /tmp/first; exec sleep 86399"])
        .build()
        .expect("a valid sandbox configuration")
        .spawn()
        .expect("the sandbox launches")
}

/// Runs `script` under the fixture's shell as a further command of `sandbox`,
/// and returns its outcome and what it wrote to standard output.
fn exec_script(sandbox: &Running<'_>, script: &str) -> (ferroday_cage::ExitStatus, String) {
    let mut collected = Collect::default();
    let status = {
        let mut running = sandbox
            .exec_with(&Exec::new("/bin/sh").args(["-c", script]), &mut collected)
            .expect("the further command launches");
        common::outcome_within(&mut running, PATIENCE)
    };
    (
        status,
        String::from_utf8_lossy(&collected.stdout).into_owned(),
    )
}

/// The script line that waits until the first command has written its pid.
const AWAIT_FIRST: &str = "while [ ! -s /tmp/first ]; do sleep 0.01; done";

#[test]
fn a_further_command_runs_beside_the_first_in_its_sandbox() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut sandbox = running_sandbox(rootfs, true);
    let (status, out) = exec_script(
        &sandbox,
        &format!(
            "{AWAIT_FIRST}; echo first=$(cat /tmp/first); echo host=$(hostname); \
             echo self=$$; grep PPid /proc/$$/status; \
             kill -0 $(cat /tmp/first) && echo signalled"
        ),
    );
    assert!(status.success(), "{status:?}: {out}");
    // The first command is the sandbox's PID 2, under its init.
    assert!(out.contains("first=2\n"), "{out}");
    assert!(out.contains("host=joined\n"), "{out}");
    assert!(
        !out.contains("self=2\n") && !out.contains("self=1\n"),
        "{out}"
    );
    // Its parent is the launch stage, outside the sandbox's PID namespace.
    assert!(out.contains("PPid:\t0\n"), "{out}");
    assert!(out.contains("signalled\n"), "{out}");
    // The sandbox outlives the further command.
    assert_eq!(sandbox.try_wait().expect("the handle polls"), None);
    sandbox.kill().expect("the kill is delivered");
    sandbox.wait().expect("the outcome is collected");
}

#[test]
fn a_further_command_is_held_to_the_sandboxs_read_only_binds() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let host = common::scratch_dir("exec-read-only");
    std::fs::write(host.join("kept"), b"host's").expect("the scratch file is written");
    let mut sandbox = Cage::builder()
        .rootfs(rootfs)
        .stop_with_caller(true)
        .bind_ro(&host, "/mnt")
        .command("/bin/sleep")
        .arg("86399")
        .build()
        .expect("a valid sandbox configuration")
        .spawn()
        .expect("the sandbox launches");
    // Root of its own nested namespace, the further command cannot remount the
    // bind writable: the flags it inherited are locked.
    let (status, out) = exec_script(
        &sandbox,
        "echo x > /mnt/kept 2>/dev/null; echo write=$?; \
         mount -o remount,rw /mnt 2>/dev/null; echo remount=$?; \
         echo y > /mnt/kept 2>/dev/null; echo again=$?",
    );
    assert!(status.success(), "{status:?}: {out}");
    assert!(out.contains("write=1\n"), "{out}");
    assert!(!out.contains("remount=0\n"), "{out}");
    assert!(out.contains("again=1\n"), "{out}");
    assert_eq!(
        std::fs::read(host.join("kept")).expect("the scratch file reads"),
        b"host's"
    );
    sandbox.kill().expect("the kill is delivered");
    sandbox.wait().expect("the outcome is collected");
}

#[test]
fn a_mount_the_first_command_makes_is_not_a_further_commands() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The first command is root of its own nested namespace and mounts a tmpfs
    // there. A further command enters a copy of the sandbox's setup, not of the
    // first command's namespace, so it finds the directory as the setup left it.
    for pid_namespace in [true, false] {
        let mut sandbox = Cage::builder()
            .rootfs(rootfs)
            .stop_with_caller(true)
            .pid_namespace(pid_namespace)
            .command("/bin/sh")
            .args([
                "-c",
                "mount -t tmpfs none /mnt && touch /mnt/first && echo 1 > /tmp/first; \
                 exec sleep 86399",
            ])
            .build()
            .expect("a valid sandbox configuration")
            .spawn()
            .expect("the sandbox launches");
        let (status, out) = exec_script(
            &sandbox,
            &format!("{AWAIT_FIRST}; ls /mnt; grep -c ' /mnt ' /proc/self/mounts"),
        );
        assert_eq!(out, "0\n", "pid namespace {pid_namespace}: {status:?}");
        sandbox.kill().expect("the kill is delivered");
        sandbox.wait().expect("the outcome is collected");
    }
}

#[test]
fn a_further_command_ends_alone_and_the_sandbox_runs_on() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    for pid_namespace in [true, false] {
        let mut sandbox = running_sandbox(rootfs, pid_namespace);
        let sleep = Exec::new("/bin/sleep").arg("86399").stop_with_caller(true);

        let mut killed = sandbox.exec(&sleep).expect("the further command launches");
        killed.kill().expect("the kill is delivered");
        let status = common::outcome_within(&mut killed, PATIENCE);
        assert_eq!(status.signal(), Some(9), "pid namespace {pid_namespace}");

        let mut terminated = sandbox.exec(&sleep).expect("the further command launches");
        terminated
            .terminate()
            .expect("the termination is delivered");
        let status = common::outcome_within(&mut terminated, PATIENCE);
        assert_eq!(status.signal(), Some(15), "pid namespace {pid_namespace}");
        assert!(terminated.usage().is_some(), "its stage collected it");

        assert_eq!(
            sandbox.try_wait().expect("the handle polls"),
            None,
            "pid namespace {pid_namespace}: the sandbox runs on"
        );
        let (status, out) = exec_script(&sandbox, "echo again");
        assert!(status.success() && out == "again\n", "{status:?}: {out}");
        sandbox.kill().expect("the kill is delivered");
        sandbox.wait().expect("the outcome is collected");
    }
}

#[test]
fn a_further_commands_handle_runs_further_commands() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut sandbox = running_sandbox(rootfs, true);
    let mut middle = sandbox
        .exec(&Exec::new("/bin/sleep").arg("86399").stop_with_caller(true))
        .expect("the further command launches");
    let (status, out) = exec_script(&middle, &format!("{AWAIT_FIRST}; hostname"));
    assert!(status.success() && out == "joined\n", "{status:?}: {out}");
    middle.kill().expect("the kill is delivered");
    common::outcome_within(&mut middle, PATIENCE);
    sandbox.kill().expect("the kill is delivered");
    sandbox.wait().expect("the outcome is collected");
}

#[test]
fn the_sandboxs_end_ends_a_further_command_with_a_pid_namespace() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut sandbox = running_sandbox(rootfs, true);
    let mut further = sandbox
        .exec(&Exec::new("/bin/sleep").arg("86399").stop_with_caller(true))
        .expect("the further command launches");
    sandbox.kill().expect("the kill is delivered");
    sandbox.wait().expect("the outcome is collected");
    let status = common::outcome_within(&mut further, PATIENCE);
    assert_eq!(status.signal(), Some(9), "{status:?}");
}

#[test]
fn a_further_command_after_the_sandbox_ended_is_refused() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    for pid_namespace in [true, false] {
        let mut sandbox = Cage::builder()
            .rootfs(rootfs)
            .pid_namespace(pid_namespace)
            .command("/bin/true")
            .build()
            .expect("a valid sandbox configuration")
            .spawn()
            .expect("the sandbox launches");
        sandbox.wait().expect("the outcome is collected");
        let refused = sandbox.exec(&Exec::new("/bin/true"));
        assert!(
            matches!(refused, Err(Error::SandboxEnded)),
            "pid namespace {pid_namespace}: {refused:?}"
        );
    }
}

#[test]
fn a_further_command_racing_the_sandboxs_end_is_refused_as_its_end() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The first command ends at once, so the joins below meet a sandbox that is
    // running, ending, or ended. Whichever they meet, a refusal is the end.
    for _ in 0..20 {
        let mut sandbox = Cage::builder()
            .rootfs(rootfs)
            .command("/bin/true")
            .build()
            .expect("a valid sandbox configuration")
            .spawn()
            .expect("the sandbox launches");
        loop {
            match sandbox.exec(&Exec::new("/bin/true")) {
                Ok(mut further) => {
                    common::outcome_within(&mut further, PATIENCE);
                }
                Err(Error::SandboxEnded) => break,
                Err(other) => panic!("a refusal other than the sandbox's end: {other:?}"),
            }
        }
        sandbox.wait().expect("the outcome is collected");
    }
}

#[test]
fn a_further_command_states_its_own_command_line_and_inherits_the_rest() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut sandbox = Cage::builder()
        .rootfs(rootfs)
        .stop_with_caller(true)
        .env("KEPT", "launch")
        .env("REPLACED", "launch")
        .current_dir("/tmp")
        .command("/bin/sleep")
        .arg("86399")
        .build()
        .expect("a valid sandbox configuration")
        .spawn()
        .expect("the sandbox launches");
    let mut collected = Collect::default();
    {
        let exec = Exec::new("sh")
            .path_lookup(true)
            .args(["-c", "echo $KEPT $REPLACED $ADDED $(pwd)"])
            .env("REPLACED", "exec")
            .env("ADDED", "exec");
        let mut running = sandbox
            .exec_with(&exec, &mut collected)
            .expect("the further command launches");
        assert!(common::outcome_within(&mut running, PATIENCE).success());
    }
    assert_eq!(
        String::from_utf8_lossy(&collected.stdout),
        "launch exec exec /tmp\n"
    );
    let mut collected = Collect::default();
    {
        let exec = Exec::new("/bin/pwd").current_dir("/etc");
        let mut running = sandbox
            .exec_with(&exec, &mut collected)
            .expect("the further command launches");
        assert!(common::outcome_within(&mut running, PATIENCE).success());
    }
    assert_eq!(String::from_utf8_lossy(&collected.stdout), "/etc\n");
    // A relative command without lookup is refused as at build.
    assert!(matches!(
        sandbox.exec(&Exec::new("sh")),
        Err(Error::Config(ConfigError::CommandNotAbsolute { .. }))
    ));
    sandbox.kill().expect("the kill is delivered");
    sandbox.wait().expect("the outcome is collected");
}

#[test]
fn a_further_command_takes_a_process_group_of_its_own() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Left in the caller's process group, a command in the sandbox could signal
    // the caller with a signal sent to its own group.
    let mut sandbox = running_sandbox(rootfs, true);
    let mut further = sandbox
        .exec(
            &Exec::new("/bin/sleep")
                .arg("86399")
                .stop_with_caller(true)
                .stdout(Stdio::Null),
        )
        .expect("the further command launches");
    let ours = rustix::process::getpgrp().as_raw_nonzero().get();
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", further.pid()))
        .expect("the further command's stat reads");
    // The process group is the fifth field, the first after the name's close.
    let after_name = &stat[stat.rfind(')').expect("a stat record names its process") + 2..];
    let group: i32 = after_name
        .split(' ')
        .nth(2)
        .and_then(|field| field.parse().ok())
        .expect("a process group");
    assert_ne!(group, ours, "{stat}");
    further.kill().expect("the kill is delivered");
    common::outcome_within(&mut further, PATIENCE);
    sandbox.kill().expect("the kill is delivered");
    sandbox.wait().expect("the outcome is collected");
}

#[test]
fn a_further_command_on_a_terminal_leads_a_session_on_it() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The first command runs on the test's own streams; the further command
    // gets a terminal of its own, which is its controlling terminal, and leads
    // the session that terminal belongs to.
    let mut sandbox = running_sandbox(rootfs, true);
    let (mut further, mut pty) = sandbox
        .exec_terminal(
            &Exec::new("/bin/sh").args([
                "-c",
                "for fd in 0 1 2; do [ -t $fd ] || exit 1; done; \
                 stat=$(cut -d')' -f2- /proc/$$/stat); \
                 echo pid=$$ sid=$(echo $stat | cut -d' ' -f4) \
                 tty=$(echo $stat | cut -d' ' -f5)",
            ]),
            &Terminal::new(),
        )
        .expect("the further command launches on a terminal");
    let mut written = Vec::new();
    pty.read_to_end(&mut written)
        .expect("the primary drains to end-of-file");
    let written = String::from_utf8_lossy(&written).into_owned();
    let status = common::outcome_within(&mut further, PATIENCE);
    assert!(status.success(), "every stream is the terminal: {written}");
    let field = |name: &str| {
        written
            .split_whitespace()
            .find_map(|word| word.strip_prefix(name))
            .unwrap_or_else(|| panic!("no {name} in {written:?}"))
            .to_owned()
    };
    assert_eq!(field("pid="), field("sid="), "{written}");
    assert_ne!(field("tty="), "0", "{written}");
    sandbox.kill().expect("the kill is delivered");
    sandbox.wait().expect("the outcome is collected");
}

#[test]
fn a_further_command_on_a_terminal_names_no_stream_of_its_own() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut sandbox = running_sandbox(rootfs, true);
    let refused = sandbox.exec_terminal(
        &Exec::new("/bin/true").stdout(Stdio::Null),
        &Terminal::new(),
    );
    assert!(
        matches!(
            refused,
            Err(Error::Config(ConfigError::StreamAttachmentConflict { .. }))
        ),
        "{:?}",
        refused.err()
    );
    sandbox.kill().expect("the kill is delivered");
    sandbox.wait().expect("the outcome is collected");
}

/// A cage on the fixture root with no command of its own, tied to its handles.
fn session(rootfs: &std::path::Path) -> Cage {
    Cage::builder()
        .rootfs(rootfs)
        .stop_with_caller(true)
        .hostname("session")
        .build()
        .expect("a cage without a command builds")
}

#[test]
fn a_started_sandbox_runs_no_command_and_holds_for_further_ones() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut sandbox = session(rootfs).start().expect("the sandbox starts");
    // The init forks nothing: the further command is the first process of the
    // sandbox after it.
    let (status, out) = exec_script(&sandbox, "hostname; echo self=$$");
    assert!(status.success(), "{status:?}: {out}");
    assert_eq!(out, "session\nself=2\n");
    // Between further commands, the sandbox holds.
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(sandbox.try_wait().expect("the handle polls"), None);
    let (status, out) = exec_script(&sandbox, "echo again");
    assert!(status.success() && out == "again\n", "{status:?}: {out}");
    sandbox.kill().expect("the kill is delivered");
    let status = sandbox.wait().expect("the outcome is collected");
    assert_eq!(status.signal(), Some(9));
}

#[test]
fn a_started_sandbox_collects_what_further_commands_leave() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut sandbox = session(rootfs).start().expect("the sandbox starts");
    let (status, _) = exec_script(&sandbox, "sleep 0.2 & exit 0");
    assert!(status.success());
    std::thread::sleep(Duration::from_millis(600));
    // The sleep was reparented to the init when its shell exited, and the init
    // collected it when it exited in turn: no zombie is left.
    let (status, out) = exec_script(
        &sandbox,
        "grep -l ') Z ' /proc/[0-9]*/stat 2>/dev/null | wc -l",
    );
    assert!(status.success() && out == "0\n", "{status:?}: {out}");
    sandbox.kill().expect("the kill is delivered");
    sandbox.wait().expect("the outcome is collected");
}

#[test]
fn terminating_a_started_sandbox_ends_it_once_nothing_is_left() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut sandbox = session(rootfs).start().expect("the sandbox starts");
    let mut further = sandbox
        .exec(&Exec::new("/bin/sleep").arg("86399").stop_with_caller(true))
        .expect("the further command launches");
    sandbox.terminate().expect("the termination is delivered");
    let status = common::outcome_within(&mut further, PATIENCE);
    assert_eq!(status.signal(), Some(15), "every process is sent SIGTERM");
    let status = common::outcome_within(&mut sandbox, PATIENCE);
    assert_eq!(status.code(), Some(0), "{status:?}");

    // A process that ignores the request keeps the sandbox up until a kill.
    let mut sandbox = session(rootfs).start().expect("the sandbox starts");
    let mut stubborn = sandbox
        .exec(
            &Exec::new("/bin/sh")
                .args([
                    "-c",
                    "trap '' TERM; echo ready > /tmp/ready; while :; do sleep 1; done",
                ])
                .stop_with_caller(true),
        )
        .expect("the further command launches");
    let (status, _) = exec_script(&sandbox, "while [ ! -s /tmp/ready ]; do sleep 0.01; done");
    assert!(status.success());
    sandbox.terminate().expect("the termination is delivered");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(sandbox.try_wait().expect("the handle polls"), None);
    sandbox.kill().expect("the kill is delivered");
    assert_eq!(
        sandbox.wait().expect("the outcome is collected").signal(),
        Some(9)
    );
    let status = common::outcome_within(&mut stubborn, PATIENCE);
    assert_eq!(status.signal(), Some(9), "{status:?}");
}

#[test]
fn dropping_a_tied_started_sandboxs_handle_ends_it() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let sandbox = session(rootfs).start().expect("the sandbox starts");
    let mut further = sandbox
        .exec(&Exec::new("/bin/sleep").arg("86399").stop_with_caller(true))
        .expect("the further command launches");
    drop(sandbox);
    let status = common::outcome_within(&mut further, PATIENCE);
    assert_eq!(status.signal(), Some(9), "{status:?}");
}

#[test]
fn a_started_sandbox_held_at_the_gate_proceeds_to_its_handle() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let pending = session(rootfs)
        .start_pending()
        .expect("the sandbox starts held");
    assert!(pending.netns_pid() > 0);
    let mut sandbox = pending.proceed().expect("the sandbox proceeds");
    let (status, out) = exec_script(&sandbox, "hostname");
    assert!(status.success() && out == "session\n", "{status:?}: {out}");
    sandbox.kill().expect("the kill is delivered");
    sandbox.wait().expect("the outcome is collected");
}

#[test]
fn a_range_map_reaches_a_further_command() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::range_map() {
        return;
    }
    let mut sandbox = Cage::builder()
        .rootfs(rootfs)
        .stop_with_caller(true)
        .identity_map(IdentityMap::Subordinate)
        .command("/bin/sleep")
        .arg("86399")
        .build()
        .expect("a valid sandbox configuration")
        .spawn()
        .expect("the sandbox launches");
    let (status, out) = exec_script(
        &sandbox,
        "touch /tmp/owned && chown 5:5 /tmp/owned && stat -c %u:%g /tmp/owned; \
         cat /proc/self/uid_map",
    );
    assert!(status.success(), "{status:?}: {out}");
    assert!(out.starts_with("5:5\n"), "{out}");
    sandbox.kill().expect("the kill is delivered");
    sandbox.wait().expect("the outcome is collected");
}

#[cfg(feature = "hardening")]
mod hardening {
    use super::*;

    use ferroday_cage::{Restriction, SeccompPolicy, SeccompRules};

    #[test]
    fn a_further_command_is_refused_what_the_first_is() {
        let Some(rootfs) = common::fixture_rootfs() else {
            return;
        };
        if !common::require::seccomp() {
            return;
        }
        // Root in its own nested namespace, a further command mounts a tmpfs
        // unfiltered; the launch's curated roster refuses it the mount.
        let script = "mkdir -p /mnt; mount -t tmpfs none /mnt 2>/dev/null; echo mount=$?";
        for curated in [false, true] {
            let mut builder = Cage::builder()
                .rootfs(rootfs)
                .stop_with_caller(true)
                .command("/bin/sleep")
                .arg("86399");
            if curated {
                builder = builder.seccomp(SeccompPolicy::Rules(SeccompRules::curated()));
            }
            let mut sandbox = builder
                .build()
                .expect("a valid sandbox configuration")
                .spawn()
                .expect("the sandbox launches");
            let (status, out) = exec_script(&sandbox, script);
            assert!(status.success(), "{status:?}: {out}");
            let expected = if curated { "mount=1\n" } else { "mount=0\n" };
            assert_eq!(out, expected, "curated {curated}");
            sandbox.kill().expect("the kill is delivered");
            sandbox.wait().expect("the outcome is collected");
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn a_further_commands_refusals_are_reported_on_its_own_handle() {
        let Some(rootfs) = common::fixture_rootfs() else {
            return;
        };
        if !common::require::seccomp() {
            return;
        }
        let mut sandbox = Cage::builder()
            .rootfs(rootfs)
            .stop_with_caller(true)
            .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
            .seccomp_reports(true)
            .command("/bin/sleep")
            .arg("86399")
            .build()
            .expect("a valid sandbox configuration")
            .spawn()
            .expect("the sandbox launches");
        let first = sandbox
            .take_seccomp_reports()
            .expect("the first command's reports are made");
        let mut further = sandbox
            .exec(
                &Exec::new("/bin/sh")
                    .args(["-c", "mkdir -p /mnt; mount -t tmpfs none /mnt 2>/dev/null"]),
            )
            .expect("the further command launches");
        let reports = further
            .take_seccomp_reports()
            .expect("the further command's reports are made");
        let status = common::outcome_within(&mut further, PATIENCE);
        assert!(!status.success(), "{status:?}");
        drop(further);
        let denied = reports
            .recv_timeout(Duration::from_secs(10))
            .expect("the further command's refusal is reported");
        assert!(
            matches!(
                denied,
                ferroday_cage::SeccompReport::Denied {
                    name: Some("mount"),
                    ..
                }
            ),
            "{denied:?}"
        );
        assert!(
            first.try_recv().is_err(),
            "the first command's queue holds nothing of the further command's"
        );
        sandbox.kill().expect("the kill is delivered");
        sandbox.wait().expect("the outcome is collected");
    }

    #[test]
    fn a_restriction_has_nothing_to_join() {
        let mut running = Restriction::builder()
            .stop_with_caller(true)
            .command("/bin/sleep")
            .arg("86399")
            .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
            .build()
            .expect("a valid restriction")
            .spawn()
            .expect("the command launches");
        let refused = running.exec(&Exec::new("/bin/true"));
        assert!(
            matches!(
                refused,
                Err(Error::Config(ConfigError::ExecIntoRestriction))
            ),
            "{refused:?}"
        );
        running.kill().expect("the kill is delivered");
        running.wait().expect("the outcome is collected");
    }
}
