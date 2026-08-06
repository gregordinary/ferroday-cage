//! Integration tests for the process model: the PID namespace, the library
//! init, and the scrubbed process state the command starts with.

mod common;

use ferroday_cage::{Cage, ConfigError, Error, Limit, Resource};

#[test]
fn the_command_is_pid_2_under_the_library_init() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The shell is PID 2; its parent, the init, is PID 1.
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            r#"[ "$$" = 2 ] && [ "$(grep '^PPid:' /proc/$$/status | cut -f2)" = 1 ]"#,
        ])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the command at PID 2 under init");
}

#[test]
fn the_fresh_procfs_shows_only_the_sandbox() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The test process exists on the host; a procfs presenting the
    // sandbox's PID namespace cannot contain it. PID 1 (the init) must be
    // present.
    let status = Cage::builder()
        .rootfs(rootfs)
        .env("HOST_PID", std::process::id().to_string())
        .command("/bin/sh")
        .args(["-c", "test -d /proc/1 && test ! -e /proc/$HOST_PID"])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected a sandbox-only procfs");
}

#[test]
fn without_a_pid_namespace_proc_shows_the_host() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = Cage::builder()
        .rootfs(rootfs)
        .pid_namespace(false)
        .env("HOST_PID", std::process::id().to_string())
        .command("/bin/sh")
        .args(["-c", "test -e /proc/$HOST_PID"])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the host's procfs bind");
}

#[test]
fn exit_codes_round_trip_without_a_pid_namespace() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = Cage::builder()
        .rootfs(rootfs)
        .pid_namespace(false)
        .command("/bin/sh")
        .args(["-c", "exit 42"])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert_eq!(status.code(), Some(42));
}

#[test]
fn orphaned_descendants_are_reaped_within_the_tick() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A subshell backgrounds a child and exits, orphaning the child onto
    // the init, where its exit leaves a zombie. The init's reaping tick
    // must collect it while the command still runs — not at command exit —
    // so after a grace period longer than the tick, no process in the
    // namespace may be in the zombie state.
    let script = r#"
        (: &)
        sleep 2
        ! grep -l ') Z ' /proc/[0-9]*/stat 2>/dev/null
    "#;
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected no zombies after the reap tick");
}

#[test]
fn sigpipe_is_reset_to_the_default_disposition() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A Rust caller ignores SIGPIPE, and exec preserves ignored
    // dispositions; the launch resets them, so bit 13 of SigIgn must be
    // clear inside (mask 0x1000).
    let script = r#"
        ignored=$(grep '^SigIgn:' /proc/$$/status | cut -f2)
        [ $(( 0x$ignored & 4096 )) = 0 ]
    "#;
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected SIGPIPE at SIG_DFL inside");
}

#[test]
fn the_command_keeps_the_callers_process_group() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The command stays in the caller's process group and session, which is
    // what routes a terminal ^C to it. From inside the PID namespace an
    // outside process group has no mapping, so the pgrp field of
    // /proc/self/stat reads 0 — a group of the sandbox's own would read as
    // a namespace-local pid instead.
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", r#"[ "$(cut -d' ' -f5 /proc/$$/stat)" = 0 ]"#])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the caller's process group");
}

#[test]
fn the_command_starts_with_a_clean_descriptor_table() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Only the standard streams survive into the command; every launch
    // channel and caller descriptor is closed or close-on-exec. Builtins
    // and path checks only: a forked helper or a command substitution
    // would add pipe descriptors to the very table being examined, and
    // even a glob briefly opens the directory it enumerates.
    let script = r#"
        [ -e /proc/$$/fd/0 ] && [ -e /proc/$$/fd/1 ] && [ -e /proc/$$/fd/2 ] || exit 1
        for fd in 3 4 5 6 7 8 9 10 11 12 13 14 15; do
            [ ! -e /proc/$$/fd/$fd ] || exit 1
        done
    "#;
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected only fds 0, 1, 2 inside");
}

#[test]
fn a_resource_limit_reaches_the_command() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The command reads its own limits from procfs. Without a configured
    // limit the caller's is inherited; with one, the sandbox's value is what
    // the command sees.
    let read_limit = |cage: Cage| -> String {
        let output = cage.output().expect("the sandbox launches");
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let builder = || {
        Cage::builder()
            .rootfs(rootfs)
            .command("/bin/sh")
            .args(["-c", "grep '^Max processes' /proc/self/limits"])
    };

    let unlimited = read_limit(builder().build().expect("a valid configuration"));
    assert!(
        !unlimited.contains(" 64 "),
        "the fixture host is unlikely to cap processes at 64: {unlimited:?}"
    );

    let limited = read_limit(
        builder()
            .rlimit(Resource::Processes, 64, 64)
            .build()
            .expect("a valid configuration"),
    );
    let fields: Vec<&str> = limited.split_whitespace().collect();
    // "Max processes  <soft>  <hard>  processes"
    assert_eq!(
        &fields[fields.len() - 3..fields.len() - 1],
        ["64", "64"],
        "the configured limit must reach the command: {limited:?}"
    );
}

#[test]
fn a_resource_limit_binds_the_commands_descendants() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A limit is a process attribute, inherited across fork and exec, so a
    // process the command starts sees it too.
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "/bin/busybox sh -c \"grep '^Max file size' /proc/self/limits\"",
        ])
        .rlimit(Resource::FileSize, 4096, 4096)
        .build()
        .expect("a valid configuration")
        .output()
        .expect("the sandbox launches");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("4096"), "{text:?}");
}

#[test]
fn a_file_size_limit_stops_a_runaway_write() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The limit is enforced by the kernel, not merely reported: a write past
    // it raises SIGXFSZ, which the shell reports as a failed command. The
    // tmpfs `/tmp` the sandbox mounts is the target, so nothing on the host
    // is touched.
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "head -c 65536 /dev/zero > /tmp/probe 2>/dev/null; \
             /bin/busybox stat -c %s /tmp/probe",
        ])
        .rlimit(Resource::FileSize, 4096, 4096)
        .build()
        .expect("a valid configuration")
        .output()
        .expect("the sandbox launches");
    let size: u64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("stat reports a size");
    assert_eq!(size, 4096, "the write must be cut off at the limit");
}

#[test]
fn a_soft_limit_above_its_hard_limit_is_a_config_error() {
    let err = Cage::builder()
        .rootfs("/")
        .command("/bin/sh")
        .rlimit(Resource::Processes, 64, 32)
        .build()
        .unwrap_err();
    match err {
        Error::Config(ConfigError::RlimitInvalid { resource, .. }) => {
            assert_eq!(resource, Resource::Processes);
            assert!(err.to_string().contains("RLIMIT_NPROC"), "{err}");
        }
        other => panic!("expected RlimitInvalid, got {other:?}"),
    }
}

#[test]
fn an_unlimited_soft_limit_needs_an_unlimited_hard_limit() {
    let err = Cage::builder()
        .rootfs("/")
        .command("/bin/sh")
        .rlimit(Resource::CpuTime, Limit::UNLIMITED, 10)
        .build()
        .unwrap_err();
    assert!(
        matches!(err, Error::Config(ConfigError::RlimitInvalid { .. })),
        "{err:?}"
    );
}

#[test]
fn a_command_that_leaves_the_supervisors_process_group_is_still_waited_for() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A sandboxed command is free to start a session of its own, which takes it
    // out of the supervisor's process group. The supervisor's reaping wait must
    // be for any child, not for any child of its own group: a group-scoped wait
    // answers ECHILD for a child sitting there exited, and the supervisor then
    // exits without a status record, which the caller reads as a lost
    // supervisor rather than the exit code the command actually produced.
    //
    // Both process shapes are checked: with a PID namespace the supervisor is
    // the in-namespace init, and without one it is the launch stage outside.
    for pid_namespace in [true, false] {
        let status = Cage::builder()
            .rootfs(rootfs)
            .pid_namespace(pid_namespace)
            .command("/bin/busybox")
            .args(["setsid", "/bin/busybox", "sh", "-c", "exit 7"])
            .build()
            .expect("a valid sandbox configuration")
            .run()
            .expect("the sandbox launches");
        assert_eq!(
            status.code(),
            Some(7),
            "the command's own session must not hide its outcome \
             (pid_namespace = {pid_namespace})",
        );
    }
}
