//! Integration tests that build real sandboxes and observe the isolation.
//!
//! These tests require a Linux host with unprivileged user namespaces; when
//! they are unavailable the tests skip explicitly (see [`common`]). The
//! rootfs fixture is a pinned Alpine minirootfs, shared across tests and
//! treated as read-only; tests only run commands that do not modify it.

mod common;

use std::path::Path;

use ferroday_cage::{
    Cage, ConfigError, Error, ExitStatus, Network, RawMount, ResolvedMount, SetupStep,
};
use rustix::io::Errno;

/// Builds a cage that runs `/bin/sh -c <script>` in the given rootfs.
fn sh(rootfs: &Path, script: &str) -> Cage {
    Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
}

/// Runs `/bin/sh -c <script>` in the fixture rootfs.
fn run_sh(rootfs: &Path, script: &str) -> ExitStatus {
    sh(rootfs, script).run().expect("the sandbox launches")
}

#[test]
fn a_command_runs_to_successful_exit() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .arg("true")
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success());
    assert_eq!(status.code(), Some(0));
    assert_eq!(status.signal(), None);
}

#[test]
fn exit_codes_round_trip() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = run_sh(rootfs, "exit 42");
    assert!(!status.success());
    assert_eq!(status.code(), Some(42));
    assert_eq!(status.signal(), None);
}

#[test]
fn fatal_signals_round_trip() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = run_sh(rootfs, "kill -9 $$");
    assert!(!status.success());
    assert_eq!(status.code(), None);
    assert_eq!(status.signal(), Some(9));
}

#[test]
fn the_calling_user_is_root_inside() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = run_sh(rootfs, r#"[ "$(/bin/busybox id -u)" = 0 ]"#);
    assert!(status.success(), "expected uid 0 inside the sandbox");
}

#[test]
fn the_visible_root_is_the_rootfs() {
    let Some(rootfs) = common::scratch_rootfs("visible-root") else {
        return;
    };
    // A marker only this rootfs carries: `/etc/alpine-release` would also be
    // there on a host that happens to run Alpine, and the discriminator has to
    // be one no host root can satisfy.
    std::fs::write(rootfs.join("this-rootfs-and-no-other"), b"").expect("the marker is writable");
    let status = Cage::builder()
        .rootfs(&rootfs)
        .command("/bin/sh")
        .args(["-c", "test -f /this-rootfs-and-no-other"])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the named rootfs at /");
}

#[test]
fn the_working_directory_is_the_new_root() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = run_sh(rootfs, r#"[ "$PWD" = / ]"#);
    assert!(status.success(), "expected the working directory to be /");
}

#[test]
fn a_cage_launches_repeatedly() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = sh(rootfs, "exit 7");
    for _ in 0..2 {
        let status = cage.run().expect("the sandbox launches");
        assert_eq!(status.code(), Some(7));
    }
}

#[test]
fn a_nonexistent_rootfs_is_a_config_error() {
    // Configuration validation happens at build time and needs no
    // namespaces: this test runs everywhere.
    let err = Cage::builder()
        .rootfs("/ferroday-cage/no/such/rootfs")
        .command("/bin/sh")
        .build()
        .unwrap_err();
    match err {
        Error::Config(ConfigError::RootfsUnusable { errno, .. }) => {
            assert_eq!(errno, Errno::NOENT.raw_os_error());
        }
        other => panic!("expected RootfsUnusable, got {other:?}"),
    }
}

#[test]
fn a_missing_command_is_a_typed_exec_error() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let err = Cage::builder()
        .rootfs(rootfs)
        .command("/does/not/exist")
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .unwrap_err();
    match err {
        Error::Setup {
            step,
            errno,
            ref detail,
            ..
        } => {
            assert_eq!(step, SetupStep::Exec);
            assert_eq!(errno, Errno::NOENT.raw_os_error());
            // The command that could not be executed is named, so a typo in
            // the path appears in the message reporting it.
            assert_eq!(detail.as_deref(), Some("/does/not/exist"));
            assert!(err.to_string().contains("/does/not/exist"), "{err}");
        }
        other => panic!("expected a Setup error at the exec step, got {other:?}"),
    }
}

#[test]
fn path_lookup_runs_a_bare_command_from_the_sandbox_path() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // With path lookup on, a bare `sh` resolves against the sandbox's PATH to
    // /bin/sh inside the fixture and runs, without the caller naming the path.
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("sh")
        .args(["-c", "exit 0"])
        .path_lookup(true)
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the bare command resolves and runs");
    assert!(status.success());
    assert_eq!(status.code(), Some(0));
}

#[test]
fn path_lookup_of_an_unresolvable_command_is_a_typed_exec_error() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A bare name matched by no PATH directory exhausts the search and reports
    // the exec step with ENOENT, the same typed error a missing absolute
    // command gives.
    let err = Cage::builder()
        .rootfs(rootfs)
        .command("not-a-real-command-xyz")
        .path_lookup(true)
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .unwrap_err();
    match err {
        Error::Setup {
            step,
            errno,
            ref detail,
            ..
        } => {
            assert_eq!(step, SetupStep::Exec);
            assert_eq!(errno, Errno::NOENT.raw_os_error());
            // A search reports the bare name and every candidate it tried, so
            // the message shows which PATH directories were consulted.
            let detail = detail.as_deref().expect("the exec step names its subject");
            assert!(
                detail.starts_with("not-a-real-command-xyz, searched "),
                "{detail}"
            );
            assert!(detail.contains("/bin/not-a-real-command-xyz"), "{detail}");
        }
        other => panic!("expected a Setup error at the exec step, got {other:?}"),
    }
}

#[test]
fn path_lookup_reports_a_denial_ahead_of_a_later_miss() {
    use std::os::unix::fs::PermissionsExt;

    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // One directory on PATH, holding a runnable script and a matching name that
    // is not executable.
    let host_dir = common::scratch_dir("path-lookup-denial");
    for (name, mode) in [("runnable", 0o755), ("blocked", 0o644)] {
        let path = host_dir.join(name);
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    let search = |command: &str| {
        Cage::builder()
            .rootfs(rootfs)
            .bind(&host_dir, "/candidates")
            .command(command)
            .path_lookup(true)
            .env("PATH", "/candidates:/nowhere")
            .build()
            .expect("a valid sandbox configuration")
            .run()
    };

    // The bind itself carries no noexec, so a denial below is about the file's
    // mode and nothing else.
    assert!(
        search("runnable")
            .expect("the runnable candidate runs")
            .success()
    );

    // execvp's rule: the EACCES from the first directory outranks the ENOENT
    // from the second. "Found it, may not run it" is the useful diagnosis.
    match search("blocked").unwrap_err() {
        Error::Setup { step, errno, .. } => {
            assert_eq!(step, SetupStep::Exec);
            assert_eq!(errno, Errno::ACCESS.raw_os_error());
        }
        other => panic!("expected a Setup error at the exec step, got {other:?}"),
    }
}

#[test]
fn a_non_executable_command_is_a_typed_exec_error() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let err = Cage::builder()
        .rootfs(rootfs)
        .command("/etc/alpine-release")
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .unwrap_err();
    match err {
        Error::Setup { step, errno, .. } => {
            assert_eq!(step, SetupStep::Exec);
            assert_eq!(errno, Errno::ACCESS.raw_os_error());
        }
        other => panic!("expected a Setup error at the exec step, got {other:?}"),
    }
}

#[test]
fn proc_is_mounted_and_readable() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = run_sh(rootfs, "grep -q '^Name:' /proc/self/status");
    assert!(status.success(), "expected a readable procfs at /proc");
}

#[test]
fn dev_is_assembled() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let script = "\
        test -c /dev/null && echo discard > /dev/null && \
        [ \"$(head -c 4 /dev/urandom | wc -c)\" = 4 ] && \
        test -c /dev/zero && test -c /dev/full && \
        test -c /dev/random && test -c /dev/tty && \
        test -L /dev/stdin && test -L /dev/stdout && test -L /dev/stderr && \
        test -L /dev/fd && test -L /dev/ptmx && \
        test -c /dev/pts/ptmx && \
        test -d /dev/shm && touch /dev/shm/scribble";
    let status = run_sh(rootfs, script);
    assert!(status.success(), "expected the minimal /dev profile");
}

#[test]
fn tmp_is_a_fresh_writable_tmpfs() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let script = "\
        grep -q ' /tmp tmpfs ' /proc/mounts && \
        [ -z \"$(ls -A /tmp)\" ] && touch /tmp/scribble";
    let status = run_sh(rootfs, script);
    assert!(status.success(), "expected an empty tmpfs at /tmp");
}

#[test]
fn profile_toggles_remove_the_mounts() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // /proc stays mounted so the script can consult /proc/mounts; the
    // fixture's own /dev and /tmp are empty directories with nothing
    // mounted over them.
    let status = Cage::builder()
        .rootfs(rootfs)
        .mount_dev(false)
        .mount_tmp(false)
        .command("/bin/sh")
        .args([
            "-c",
            "! grep -q ' /tmp ' /proc/mounts && ! grep -q ' /dev ' /proc/mounts \
             && [ -z \"$(ls -A /dev)\" ]",
        ])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected /dev and /tmp untouched");
}

#[test]
fn a_consumer_can_rebuild_the_managed_dev_by_hand() {
    // The remedy the stability chapter names for a consumer that needs an
    // exact mount set: disable the managed profile and declare an equivalent.
    // It requires a tmpfs on /dev followed by the binds that populate it, so
    // it is only expressible because both kinds share one ordered sequence.
    // With binds forced ahead of raw mounts this configuration produced a /dev
    // holding nothing but pts and shm, and still exited zero.
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let mut builder = Cage::builder()
        .rootfs(rootfs)
        .mount_dev(false)
        // MS_NOSUID. Deliberately not MS_NODEV: the tmpfs has to carry the
        // device nodes bound in below, which MS_NODEV would render inoperable.
        .raw_mount(
            RawMount::new("/dev")
                .fstype("tmpfs")
                .flags(0x2)
                .data("mode=0755"),
        );
    for device in ["null", "zero", "full", "random", "urandom", "tty"] {
        builder = builder.bind(format!("/dev/{device}"), format!("/dev/{device}"));
    }
    let status = builder
        .raw_mount(
            RawMount::new("/dev/pts")
                .fstype("devpts")
                .data("newinstance,ptmxmode=0666,mode=0620"),
        )
        // MS_NOSUID | MS_NODEV
        .raw_mount(
            RawMount::new("/dev/shm")
                .fstype("tmpfs")
                .flags(0x6)
                .data("mode=1777"),
        )
        .command("/bin/sh")
        .args([
            "-c",
            "for node in null zero full random urandom tty; do \
               [ -c \"/dev/$node\" ] || exit 1; \
             done; \
             [ -e /dev/pts/ptmx ] || exit 1; \
             grep -q ' /dev tmpfs ' /proc/mounts || exit 1; \
             grep -q ' /dev/shm tmpfs ' /proc/mounts || exit 1",
        ])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(
        status.success(),
        "a hand-declared /dev must carry every device node the managed one does",
    );
}

#[test]
fn a_read_write_bind_round_trips() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let host_dir = common::scratch_dir("rw-bind");
    std::fs::write(host_dir.join("outside"), "from the host\n").unwrap();
    let status = Cage::builder()
        .rootfs(rootfs)
        .bind(&host_dir, "/mnt")
        .command("/bin/sh")
        .args([
            "-c",
            "test -f /mnt/outside && echo made inside > /mnt/inside",
        ])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the bind visible inside");
    let inside = std::fs::read_to_string(host_dir.join("inside")).unwrap();
    assert_eq!(inside, "made inside\n");
}

#[test]
fn a_read_only_bind_refuses_writes() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let host_dir = common::scratch_dir("ro-bind");
    std::fs::write(host_dir.join("marker"), "present\n").unwrap();
    let status = Cage::builder()
        .rootfs(rootfs)
        .bind_ro(&host_dir, "/mnt")
        .command("/bin/sh")
        .args([
            "-c",
            "test -f /mnt/marker && ! touch /mnt/scribble 2> /dev/null",
        ])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(
        status.success(),
        "expected the bind readable but not writable"
    );
    assert!(!host_dir.join("scribble").exists());
}

#[test]
fn a_read_only_bind_cannot_be_remounted_read_write() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The boundary the nested user namespace exists for. A read-only bind is
    // established by the sandbox setup inside the user namespace that setup
    // created, and root of the namespace that owns a mount may lift any
    // restriction on it — so without the nested entry the command remounts its
    // own read-only bind read-write and writes through to the host. Entering a
    // nested user namespace has the kernel copy the mount tree and lock every
    // restriction it carries: the remount answers EPERM, and a write to the
    // still-read-only mount answers EROFS.
    let host_dir = common::scratch_dir("ro-bind-locked");
    std::fs::write(host_dir.join("marker"), "present\n").unwrap();
    let status = Cage::builder()
        .rootfs(rootfs)
        .bind_ro(&host_dir, "/mnt")
        .command("/bin/sh")
        .args([
            "-c",
            "! /bin/busybox mount -o remount,bind,rw /mnt 2>/dev/null && \
             ! echo scribbled > /mnt/marker 2>/dev/null",
        ])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(
        status.success(),
        "expected the read-only bind to be locked against the sandbox's own root",
    );
    assert_eq!(
        std::fs::read_to_string(host_dir.join("marker")).unwrap(),
        "present\n",
        "the sandbox wrote through a read-only bind",
    );
}

#[test]
fn the_root_mount_is_nosuid_and_locked() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // The root is bound from a host tree and inherits that mount's flags, and
    // the provisioners apply a tree's permission bits verbatim, so a rootfs
    // ships set-user-ID binaries owned by in-namespace uid 0. `nosuid` is what
    // makes them inert — and the nested user namespace is what makes `nosuid`
    // worth setting, since without the lock the command could clear it as
    // readily as it could clear a read-only bind.
    let script = "\
        grep -q ' / .*[ ,]nosuid[ ,]' /proc/self/mountinfo || exit 1; \
        ! /bin/busybox mount -o remount,bind,suid / 2>/dev/null || exit 2; \
        grep -q ' / .*[ ,]nosuid[ ,]' /proc/self/mountinfo || exit 3";
    let status = run_sh(rootfs, script);
    assert!(
        status.success(),
        "expected the root mount nosuid, and locked against the sandbox's own root",
    );
}

#[test]
fn the_command_runs_one_user_namespace_deeper_than_the_sandbox() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A map file states its outside ids in the *parent* namespace's terms, so
    // the command's own map is the discriminator: the sandbox's map is root
    // inside to the calling user outside and never reads `0 0 1`, while the
    // nested map — the reflection of that inside id onto itself — always does.
    //
    // The second check is the kernel's own account of the same fact. Reading
    // another process's `ns/user` link needs either the same user namespace or
    // `CAP_SYS_PTRACE` over that process's namespace, and a child namespace
    // holds no capability over its parent's; the init, which never nests, is
    // therefore out of reach in a way it was not before.
    //
    // The rest asserts what does *not* change: the command is still root
    // inside, and the root filesystem is still its own.
    let script = "\
        set -- $(cat /proc/self/uid_map); [ \"$1 $2 $3\" = \"0 0 1\" ] || exit 1; \
        /bin/busybox readlink /proc/self/ns/user >/dev/null || exit 2; \
        /bin/busybox readlink /proc/1/ns/user >/dev/null 2>&1 && exit 3; \
        [ \"$(/bin/busybox id -u)\" = 0 ] || exit 4; \
        [ -O / ] || exit 5";
    let status = run_sh(rootfs, script);
    assert!(
        status.success(),
        "expected the command one namespace deeper, and otherwise unchanged",
    );
}

#[test]
fn a_missing_bind_target_is_created_in_the_rootfs() {
    let Some(rootfs) = common::scratch_rootfs("bind-target") else {
        return;
    };
    let host_dir = common::scratch_dir("bind-target-source");
    std::fs::write(host_dir.join("marker"), "present\n").unwrap();
    let status = Cage::builder()
        .rootfs(&rootfs)
        .bind(&host_dir, "/brand/new/place")
        .command("/bin/sh")
        .args(["-c", "test -f /brand/new/place/marker"])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the created target usable");
    // The created mount-point chain persists in the rootfs directory.
    assert!(rootfs.join("brand/new/place").is_dir());
}

#[test]
fn a_file_bind_target_the_rootfs_ships_as_a_symlink_creates_nothing() {
    let Some(rootfs) = common::scratch_rootfs("linked-bind-target") else {
        return;
    };
    // A rootfs shipping its target as a symbolic link to a path it does not
    // have — the shape a resolver's `/etc/resolv.conf` takes on a systemd host.
    std::fs::create_dir_all(rootfs.join("var")).unwrap();
    std::os::unix::fs::symlink("../var/absent", rootfs.join("etc/linked")).unwrap();
    let source = common::scratch_dir("linked-bind-source").join("file");
    std::fs::write(&source, b"caller content\n").unwrap();

    // The launch creates a bind target only where the rootfs has nothing, and
    // only at the path the caller side recorded for removal. Creating one
    // through the link would leave the rootfs holding a file it never shipped,
    // at a path nothing takes away.
    let err = Cage::builder()
        .rootfs(&rootfs)
        .bind_ro(&source, "/etc/linked")
        .command("/bin/sh")
        .args(["-c", "true"])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect_err("a bind onto a link that resolves to nothing has no target");
    match err {
        Error::Setup {
            step,
            detail: Some(detail),
            ..
        } => {
            assert_eq!(step, SetupStep::OpenMountTarget);
            assert!(detail.contains("/etc/linked"), "{detail}");
        }
        other => panic!("expected a detailed Setup error, got {other:?}"),
    }
    assert!(
        !rootfs.join("var/absent").exists(),
        "a file was created through the link"
    );
    assert!(
        std::fs::symlink_metadata(rootfs.join("etc/linked"))
            .expect("the link is still there")
            .is_symlink(),
        "the rootfs's own symbolic link was replaced"
    );
}

#[test]
fn a_failed_mount_op_names_the_mount() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let host_dir = common::scratch_dir("bind-detail");
    // The target chain crosses a file, so creating it must fail, and the
    // error must name this bind.
    let err = Cage::builder()
        .rootfs(rootfs)
        .bind(&host_dir, "/etc/alpine-release/impossible")
        .command("/bin/sh")
        .arg("-c")
        .arg("true")
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .unwrap_err();
    match err {
        Error::Setup {
            step,
            detail: Some(detail),
            ..
        } => {
            assert_eq!(step, SetupStep::CreateMountTarget);
            assert!(
                detail.contains("/etc/alpine-release/impossible"),
                "{detail}"
            );
        }
        other => panic!("expected a detailed Setup error, got {other:?}"),
    }
}

#[test]
fn a_raw_mount_reaches_the_kernel_verbatim() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A tmpfs expressed through the escape hatch: MS_NOSUID | MS_NODEV,
    // with a data string. The mount must appear with its options and be
    // usable, at an auto-created target.
    let status = Cage::builder()
        .rootfs(rootfs)
        .raw_mount(
            RawMount::new("/raw/scratch")
                .fstype("tmpfs")
                .flags(0x6)
                .data("mode=0777"),
        )
        .command("/bin/sh")
        .args([
            "-c",
            "grep -q ' /raw/scratch tmpfs rw,nosuid,nodev' /proc/mounts \
             && touch /raw/scratch/scribble",
        ])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(
        status.success(),
        "expected the raw tmpfs mounted and usable"
    );
}

#[test]
fn a_refused_raw_mount_names_the_mount() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let err = Cage::builder()
        .rootfs(rootfs)
        .raw_mount(RawMount::new("/raw").fstype("ferroday-no-such-fs"))
        .command("/bin/sh")
        .arg("-c")
        .arg("true")
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .unwrap_err();
    match err {
        Error::Setup {
            step,
            detail: Some(detail),
            ..
        } => {
            assert_eq!(step, SetupStep::MountRaw);
            assert!(detail.contains("raw mount at /raw"), "{detail}");
        }
        other => panic!("expected a detailed raw-mount error, got {other:?}"),
    }
}

/// A shell script that starts a loopback listener and connects to it, exiting
/// zero only when the connection is carried.
///
/// Loopback connectivity is proven over TCP rather than with `ping`, because
/// ICMP needs `CAP_NET_RAW` over the network namespace and the command holds no
/// capability over a namespace its own user namespace does not own; see
/// [`the_nested_namespace_costs_the_command_its_network_capabilities`].
const LOOPBACK_TCP: &str = "\
    busybox nc -l -p 9000 -e /bin/true >/dev/null 2>&1 & \
    sleep 1; \
    busybox nc -w 2 127.0.0.1 9000 </dev/null >/dev/null 2>&1";

#[test]
fn the_isolated_network_has_only_a_working_loopback() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // /proc/net/dev lists interfaces from line 3 on; loopback must be the
    // only one, and it must be up to carry the connection.
    let script = format!(
        "[ \"$(sed -n '3,$p' /proc/net/dev | wc -l)\" = 1 ] && \
         grep -q 'lo:' /proc/net/dev && {LOOPBACK_TCP}",
    );
    let status = run_sh(rootfs, &script);
    assert!(
        status.success(),
        "expected an isolated loopback-only network"
    );
}

#[test]
fn the_denied_network_has_no_loopback_connectivity() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // Unlike the isolated network, loopback is left down, so even 127.0.0.1
    // is unreachable.
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", LOOPBACK_TCP])
        .network(Network::None)
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(!status.success(), "a denied network cannot reach loopback");
}

#[test]
fn the_nested_namespace_costs_the_command_its_network_capabilities() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    // A capability is held over a namespace only by a process whose user
    // namespace owns it, or an ancestor of that one. The sandbox's network
    // namespace is owned by the sandbox's user namespace, and the command
    // enters a *child* of that namespace before it execs, so it holds no
    // capability over the network namespace it runs in.
    //
    // The consequence is worth pinning rather than leaving to be discovered:
    // ICMP (CAP_NET_RAW) and binding a port below 1024 (CAP_NET_BIND_SERVICE)
    // are both refused inside, where before the nested entry they were not.
    // Ordinary sockets are unaffected, which the loopback tests above assert.
    let script = "\
        busybox ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; \
        [ $? -ne 0 ] || exit 1; \
        busybox nc -l -p 80 -e /bin/true >/dev/null 2>&1; \
        [ $? -ne 0 ] || exit 2; \
        exit 0";
    let status = run_sh(rootfs, script);
    assert!(
        status.success(),
        "expected the command to hold no capability over its network namespace",
    );
}

#[test]
fn the_host_network_shows_the_host_interfaces() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let host_ifaces = std::fs::read_to_string("/proc/net/dev").unwrap();
    let checks: Vec<String> = host_ifaces
        .lines()
        .skip(2)
        .filter_map(|line| line.split(':').next())
        .map(|name| format!("grep -q '{}:' /proc/net/dev", name.trim()))
        .collect();
    assert!(!checks.is_empty(), "the host has network interfaces");
    let status = Cage::builder()
        .rootfs(rootfs)
        .network(Network::Host)
        .resolv_conf(false)
        .command("/bin/sh")
        .args(["-c", &checks.join(" && ")])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the host interfaces visible");
}

#[test]
fn the_hostname_is_inherited_by_default() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    let status = Cage::builder()
        .rootfs(rootfs)
        .env("EXPECTED", host.trim_end())
        .command("/bin/sh")
        .args(["-c", r#"[ "$(hostname)" = "$EXPECTED" ]"#])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the host hostname inside");
}

#[test]
fn a_configured_hostname_is_set() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = Cage::builder()
        .rootfs(rootfs)
        .hostname("cage-test")
        .command("/bin/sh")
        .args(["-c", r#"[ "$(hostname)" = cage-test ]"#])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the configured hostname inside");
    // The host is untouched: the change happened in a new UTS namespace.
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    assert_ne!(host.trim_end(), "cage-test");
}

#[test]
fn the_environment_is_exactly_the_composed_one() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let expected = "FERRODAY=cage\n\
                    HOME=/override\n\
                    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    // The shell exports PWD and SHLVL into its children; everything else
    // must be exactly the composed environment.
    let script = format!(r#"[ "$(env | grep -v -e ^PWD= -e ^SHLVL= | sort)" = "{expected}" ]"#);
    let status = Cage::builder()
        .rootfs(rootfs)
        .env("FERRODAY", "cage")
        .env("HOME", "/override")
        .command("/bin/sh")
        .args(["-c", &script])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(
        status.success(),
        "expected exactly the composed environment"
    );
}

#[test]
fn the_resolved_environment_is_the_one_the_command_sees() {
    // The record is only worth stamping into provenance if it matches reality,
    // so it is checked against the command's own `env` rather than against the
    // builder's inputs — which would only restate what was asked for.
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = Cage::builder()
        .rootfs(rootfs)
        .env("FERRODAY", "cage")
        .env("HOME", "/override")
        .command("/bin/sh")
        .args(["-c", "env | grep -v -e ^PWD= -e ^SHLVL= | sort"])
        .build()
        .expect("a valid sandbox configuration");

    let recorded: Vec<String> = cage
        .resolved_inputs()
        .env
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                name.to_str().expect("a UTF-8 name"),
                value.to_str().expect("a UTF-8 value")
            )
        })
        .collect();

    let output = cage.output().expect("the sandbox launches");
    let observed: Vec<String> = String::from_utf8(output.stdout)
        .expect("UTF-8 output")
        .lines()
        .map(str::to_string)
        .collect();

    assert_eq!(recorded, observed, "the record must match the environment");
    // And it is the composed environment, not just the caller's additions:
    // the base's PATH is in there, and the caller's HOME overrode the base's.
    assert!(recorded.iter().any(|entry| entry.starts_with("PATH=")));
    assert!(recorded.iter().any(|entry| entry == "HOME=/override"));
}

#[test]
fn the_resolved_mounts_are_the_ones_the_sandbox_establishes() {
    // Same principle for the mount half: every recorded mount and symlink is
    // checked against what the command can actually see inside the sandbox.
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "cat /proc/mounts; ls -l /dev"])
        .build()
        .expect("a valid sandbox configuration");

    let inputs = cage.resolved_inputs();
    let output = cage.output().expect("the sandbox launches");
    let seen = String::from_utf8_lossy(&output.stdout).into_owned();

    // The default profile: /proc, the /dev tmpfs with its six nodes and five
    // symlinks, /dev/pts, /dev/shm, and /tmp.
    assert!(
        inputs.mounts.len() >= 5,
        "expected the managed profile, got {:?}",
        inputs.mounts,
    );
    for mount in &inputs.mounts {
        let target = mount.get_target().display().to_string();
        match mount {
            ResolvedMount::Symlink { path, .. } => {
                let name = path.file_name().expect("a symlink leaf").to_string_lossy();
                assert!(
                    seen.contains(&format!("{name} ->")),
                    "missing symlink {name}"
                );
            }
            ResolvedMount::Bind { .. } => {
                let leaf = mount.get_target().file_name().expect("a bind leaf");
                assert!(
                    seen.contains(&leaf.to_string_lossy().into_owned()),
                    "missing bind {target}",
                );
            }
            _ => assert!(
                seen.contains(&format!(" {target} ")),
                "missing mount {target}",
            ),
        }
    }
    // The five /dev symlinks are reported, which is the part no other accessor
    // could tell a consumer.
    let symlinks = inputs
        .mounts
        .iter()
        .filter(|mount| matches!(mount, ResolvedMount::Symlink { .. }))
        .count();
    assert_eq!(symlinks, 5, "expected the five /dev symlinks");
}

#[test]
fn the_resolved_inputs_follow_the_opt_outs() {
    // With both opt-outs set the record is exactly what the consumer declared,
    // which is the combination a reproducibility-focused consumer runs.
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let inputs = Cage::builder()
        .rootfs(rootfs)
        .managed_mounts(false)
        .base_env(false)
        .env("ONLY", "this")
        // The one mount even an opted-out profile declares for itself: the
        // nested user namespace that locks the sandbox's mount flags
        // establishes its identity map through a procfs, so a profile that
        // suppresses the managed one supplies its own.
        .bind("/proc", "/proc")
        .bind("/etc", "/host-etc")
        .command("/bin/true")
        .build()
        .expect("a valid sandbox configuration")
        .resolved_inputs();

    assert_eq!(
        inputs.env,
        [(
            std::ffi::OsString::from("ONLY"),
            std::ffi::OsString::from("this"),
        )],
    );
    assert_eq!(inputs.mounts.len(), 2);
    assert!(matches!(
        &inputs.mounts[1],
        ResolvedMount::Bind { target, .. } if target == Path::new("/host-etc")
    ));
}

#[test]
fn an_exact_environment_carries_nothing_of_the_librarys() {
    // With the base opted out of, the command's environment is the caller's
    // pairs and nothing else — no PATH, no HOME. This is what a consumer whose
    // build output depends on the environment needs: overriding a variable
    // requires knowing its name, and only an exact environment excludes one a
    // later release might add to the base.
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let script = r#"[ "$(env | grep -v -e ^PWD= -e ^SHLVL= | sort)" = "FERRODAY=cage" ]"#;
    let status = Cage::builder()
        .rootfs(rootfs)
        .base_env(false)
        .env("FERRODAY", "cage")
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected only the caller's own variable");
}

#[test]
fn opting_out_of_the_managed_mounts_leaves_only_the_callers() {
    // Nothing of the library's is established: no /proc, no /dev, no /tmp.
    // The command reads /proc/self/mountinfo rather than /proc/mounts, since
    // there is no /proc inside to consult — the bind below is how it sees one.
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = Cage::builder()
        .rootfs(rootfs)
        .managed_mounts(false)
        .bind("/proc", "/proc")
        .command("/bin/sh")
        .args([
            "-c",
            "! grep -q ' /tmp ' /proc/self/mountinfo \
             && [ -z \"$(ls -A /dev)\" ] \
             && [ -n \"$(ls -A /proc)\" ]",
        ])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(
        status.success(),
        "expected only the caller's own mount to be established",
    );
}

#[test]
fn the_working_directory_is_applied() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let status = Cage::builder()
        .rootfs(rootfs)
        .current_dir("/etc")
        .command("/bin/sh")
        .args(["-c", r#"[ "$PWD" = /etc ]"#])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected /etc as the working directory");
}

#[test]
fn a_missing_working_directory_is_a_typed_error() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let err = Cage::builder()
        .rootfs(rootfs)
        .current_dir("/no/such/directory")
        .command("/bin/sh")
        .arg("-c")
        .arg("true")
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .unwrap_err();
    match err {
        Error::Setup { step, errno, .. } => {
            assert_eq!(step, SetupStep::ChdirWorkdir);
            assert_eq!(errno, Errno::NOENT.raw_os_error());
        }
        other => panic!("expected a Setup error at the workdir step, got {other:?}"),
    }
}

#[test]
fn the_host_resolv_conf_is_bound_read_only_with_the_host_network() {
    let Some(rootfs) = common::scratch_rootfs("resolv-conf") else {
        return;
    };
    let Ok(source) = std::fs::canonicalize("/etc/resolv.conf") else {
        eprintln!("skipping: the host has no resolv.conf");
        return;
    };
    let expected = std::fs::read_to_string(source).unwrap();
    let status = Cage::builder()
        .rootfs(&rootfs)
        .network(Network::Host)
        .env("EXPECTED", expected.trim_end())
        .command("/bin/sh")
        .args([
            "-c",
            r#"[ "$(cat /etc/resolv.conf)" = "$EXPECTED" ] && \
               ! { echo scribble >> /etc/resolv.conf; } 2> /dev/null"#,
        ])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "expected the host resolv.conf, read-only");
}

#[test]
fn a_builder_reads_back_what_it_was_given() {
    // The inspection path a profile-driven consumer takes before launching
    // configuration it did not write.
    let builder = Cage::builder()
        .rootfs("/srv/rootfs/alpine")
        .command("/usr/bin/make")
        .args(["-j", "4"])
        .bind("/home/user/project", "/build")
        // Declared between the two binds, to pin that the order survives.
        .raw_mount(RawMount::new("/sys").fstype("sysfs").flags(0xE))
        .bind_ro("/home/user/cache", "/cache")
        .env("CARGO_HOME", "/cache/cargo")
        .network(Network::Host)
        .hostname("builder")
        .current_dir("/build")
        .pid_namespace(false);

    assert_eq!(builder.get_rootfs(), Some(Path::new("/srv/rootfs/alpine")));
    assert!(builder.get_overlay().is_none());
    assert_eq!(builder.get_command(), Some(Path::new("/usr/bin/make")));
    assert_eq!(builder.get_args(), ["-j", "4"]);
    assert_eq!(builder.get_network(), Network::Host);
    assert!(!builder.get_pid_namespace());
    assert_eq!(
        builder.get_hostname(),
        Some(std::ffi::OsStr::new("builder"))
    );
    assert_eq!(builder.get_current_dir(), Some(Path::new("/build")));

    let binds: Vec<_> = builder.get_binds().collect();
    assert_eq!(binds.len(), 2);
    assert_eq!(binds[0].get_source(), Path::new("/home/user/project"));
    assert_eq!(binds[0].get_target(), Path::new("/build"));
    assert!(!binds[0].is_read_only());
    assert!(binds[1].is_read_only());

    let raw: Vec<_> = builder.get_raw_mounts().collect();
    assert_eq!(raw.len(), 1);
    assert_eq!(raw[0].get_target(), Path::new("/sys"));
    assert_eq!(raw[0].get_fstype(), Some("sysfs"));
    assert_eq!(raw[0].get_flags(), 0xE);

    // The unified accessor keeps the relative order the kind-specific ones
    // cannot report: the raw mount was declared between the two binds.
    let targets: Vec<_> = builder
        .get_mounts()
        .iter()
        .map(|mount| mount.get_target())
        .collect();
    assert_eq!(
        targets,
        [Path::new("/build"), Path::new("/sys"), Path::new("/cache")],
    );

    let envs: Vec<_> = builder.get_envs().collect();
    assert_eq!(
        envs,
        [(
            std::ffi::OsStr::new("CARGO_HOME"),
            std::ffi::OsStr::new("/cache/cargo"),
        )]
    );
}

#[test]
fn an_overlay_root_reads_back_through_the_overlay_accessor() {
    let builder = Cage::builder()
        .overlay_rootfs("/srv/base", "/srv/scratch/run-1")
        .command("/bin/sh");
    assert!(builder.get_rootfs().is_none());
    let overlay = builder.get_overlay().expect("an overlay root is set");
    assert_eq!(overlay.get_lowers(), [Path::new("/srv/base")]);
    assert_eq!(overlay.get_upper(), Some(Path::new("/srv/scratch/run-1")));
    assert_eq!(overlay.get_work(), None);
}

#[test]
fn a_launch_that_fails_after_the_mounts_leaves_no_placeholder_behind() {
    let Some(rootfs) = common::scratch_rootfs("failed-launch-residue") else {
        return;
    };
    let source = common::scratch_dir("failed-launch-source").join("file");
    std::fs::write(&source, b"caller content\n").unwrap();

    // A working directory that does not exist inside the sandbox fails the
    // launch at ChdirWorkdir — after every mount op has run, so the bind's
    // target file has already been created in the rootfs. That empty file is
    // exactly the residue the placeholder mechanism exists to prevent, and a
    // failed launch is the case a caller getting a configuration right hits
    // repeatedly.
    let err = Cage::builder()
        .rootfs(&rootfs)
        .bind_ro(&source, "/etc/created")
        .current_dir("/no/such/directory")
        .command("/bin/sh")
        .args(["-c", "true"])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect_err("a missing working directory fails the launch");
    assert!(
        matches!(
            err,
            Error::Setup {
                step: SetupStep::ChdirWorkdir,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(
        !rootfs.join("etc/created").exists(),
        "a failed launch left its bind target behind",
    );
}
