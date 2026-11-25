//! Integration tests for the hardening layer: Landlock filesystem rules,
//! seccomp syscall filters, capability drops, and the denied network.
//!
//! Each test builds a real sandbox on Linux and observes the restriction
//! taking effect. Tests skip explicitly when the host lacks the facility they
//! exercise — unprivileged user namespaces, the Landlock LSM, or seccomp —
//! rather than passing silently.
//!
//! A test that names a syscall by libc's number builds for a 64-bit target
//! alone. libc's numbers are the `i64` a rule takes only there, and a seccomp
//! policy compiles for a 64-bit host alone.

mod common;

use std::path::Path;

use ferroday_cage::{
    Cage, Capability, ConfigError, Error, FsAccess, LandlockScope, NetAccess, Network,
    SeccompPolicy, SeccompRules,
};
#[cfg(target_pointer_width = "64")]
use ferroday_cage::{Restriction, SeccompAction};

/// The fixture rootfs, or `None` when the sandbox tests should skip.
fn rootfs() -> Option<&'static Path> {
    common::fixture_rootfs()
}

/// A busybox TCP round trip over loopback: a listener binds a fixed port and
/// sends a token, then a client connects and prints what it receives. The token
/// reaches stdout only when the listener's bind, the client's connect, and the
/// client's ephemeral source-port bind are all permitted, so a crossed token is
/// evidence that every one of them was.
///
/// busybox `sh` redirects a backgrounded job's stdin from `/dev/null`, so the
/// tests grant `/dev`; the client binds its ephemeral source port explicitly,
/// so they grant `NetAccess::BIND` on port 0.
const NET_ROUNDTRIP: &str = "echo cage-net-ok | nc -l -p 50505 & sleep 1; nc -w 3 127.0.0.1 50505";
/// The token the round trip carries when the connection is permitted.
const NET_TOKEN: &str = "cage-net-ok";
/// The fixed TCP port the round trip's listener binds.
const NET_PORT: u16 = 50505;

/// The same round trip on two ports at once, each listener carrying its own
/// token.
///
/// The deny test grants `CONNECT` on one port and not the other, so the two
/// halves differ in nothing but that grant. The granted half is the test's
/// positive control: an absent token means the round trip itself did not work
/// — a busybox without the `nc` applet, a port already bound, a loaded runner
/// outrunning the `sleep` — which would otherwise make the denied half's empty
/// stdout pass for enforcement.
const NET_TWO_PORT_ROUNDTRIP: &str = "echo cage-net-granted | nc -l -p 50505 & \
     echo cage-net-ungranted | nc -l -p 50506 & \
     sleep 1; nc -w 3 127.0.0.1 50505; nc -w 3 127.0.0.1 50506";
/// The token carried on the port the deny test grants `CONNECT` on.
const NET_GRANTED_TOKEN: &str = "cage-net-granted";
/// The token carried on the port it does not.
const NET_UNGRANTED_TOKEN: &str = "cage-net-ungranted";
/// The second listener's port, bound but never granted `CONNECT`.
const NET_UNGRANTED_PORT: u16 = 50506;

#[test]
fn landlock_denies_a_path_outside_the_grants() {
    let Some(rootfs) = rootfs() else { return };
    if !common::landlock() {
        return;
    }
    // The command may execute from /bin and load libraries from /lib, but is
    // granted nothing under /etc. Reading a file there is denied, so busybox
    // cat exits non-zero.
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["cat", "/etc/passwd"])
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/bin")
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(
        !status.success(),
        "reading an ungranted path must be denied"
    );
}

#[test]
fn landlock_allows_a_granted_path() {
    let Some(rootfs) = rootfs() else { return };
    if !common::landlock() {
        return;
    }
    // The same command, now granted read access under /etc, succeeds. This
    // path is a tmpfs-free rootfs directory, but the same grant mechanism
    // covers the mounted view.
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["cat", "/etc/passwd"])
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/bin")
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
        .landlock_fs(FsAccess::READ, "/etc")
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "reading a granted path must succeed");
}

#[test]
fn landlock_covers_a_tmpfs_mount_in_the_pivoted_view() {
    let Some(rootfs) = rootfs() else { return };
    if !common::landlock() {
        return;
    }
    // /tmp is a tmpfs mounted after the pivot — a filesystem object that does
    // not exist at build time. A read-write grant on it proves the rules bind
    // the mounted view, not just host-inode paths.
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["sh", "-c", "echo hi > /tmp/probe && cat /tmp/probe"])
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/bin")
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
        .landlock_fs(FsAccess::READ | FsAccess::WRITE, "/tmp")
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "a granted tmpfs must be writable");
}

#[test]
fn landlock_grants_a_single_file_and_a_device_node() {
    let Some(rootfs) = rootfs() else { return };
    if !common::landlock() {
        return;
    }
    // A grant on a file and a grant on a device node, rather than on the
    // directories that hold them. `READ` and `WRITE` each lower to rights that
    // act on a directory's entries, which the kernel refuses on anything else;
    // the grant narrows to the rights a file accepts instead. The command reads
    // the one granted file, writes the one granted device, and is still denied
    // the file's neighbour.
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args([
            "sh",
            "-c",
            "cat /etc/passwd >/dev/null && echo written >/dev/null && ! cat /etc/group",
        ])
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/bin")
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
        .landlock_fs(FsAccess::READ, "/etc/passwd")
        .landlock_fs(FsAccess::READ | FsAccess::WRITE, "/dev/null")
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    assert!(
        output.status.success(),
        "the granted file and device are reachable and nothing beside them is: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn a_landlock_rule_that_fails_names_its_grant() {
    let Some(rootfs) = rootfs() else { return };
    if !common::landlock() {
        return;
    }
    // The grant's path is a sandbox path, resolved only after the pivot, so a
    // missing one fails the launch rather than the build. The failure names the
    // grant, not merely the step.
    let error = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["true"])
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/bin")
        .landlock_fs(FsAccess::READ, "/no/such/grant")
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect_err("a grant on a missing path fails the launch");
    match error {
        ferroday_cage::Error::Setup {
            step: ferroday_cage::SetupStep::LandlockAddRule,
            detail,
            source,
            ..
        } => {
            assert_eq!(detail.as_deref(), Some("r on /no/such/grant"));
            assert_eq!(source.raw_os_error(), Some(2), "{source}");
        }
        other => panic!("expected a Landlock rule failure, got {other:?}"),
    }
}

#[test]
fn the_signal_scope_confines_a_sandbox_sharing_the_host_pid_space() {
    let Some(rootfs) = rootfs() else { return };
    if !common::landlock_scope() {
        return;
    }
    // Without a PID namespace the command sees the calling user's processes,
    // and as the same user outside the namespace it may signal them. The probe
    // is signal 0, which asks the kernel for the permission check alone.
    let mut victim = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a process to signal");
    let probe = format!("kill -0 {}", victim.id());
    let launch = |scoped: bool| {
        let builder = Cage::builder()
            .rootfs(rootfs)
            .command("/bin/busybox")
            .args(["sh", "-c", probe.as_str()])
            .pid_namespace(false);
        let builder = if scoped {
            builder.landlock_scope([LandlockScope::Signal])
        } else {
            builder
        };
        builder
            .build()
            .expect("a valid sandbox configuration")
            .run()
            .expect("the sandbox launches")
    };
    let unscoped = launch(false);
    let scoped = launch(true);
    let _ = victim.kill();
    let _ = victim.wait();
    assert!(
        unscoped.success(),
        "an unscoped command reaches the caller's process"
    );
    assert!(
        !scoped.success(),
        "a scoped command cannot signal a process outside its domain"
    );
}

#[test]
fn a_scope_no_namespace_bounds_builds_only_where_the_kernel_enforces_it() {
    // A build alone, so this needs neither the fixture nor user namespaces. On a
    // kernel with scopes both sandboxes build; on one without, the scope that
    // is the only bound on its reach refuses the build rather than vanish.
    let abi = ferroday_cage::host::landlock_abi();
    let enforced = ferroday_cage::host::landlock_enforces_scope(LandlockScope::Signal);
    let base = || {
        Cage::builder()
            .rootfs(common::scratch_dir("unbounded-scope"))
            .command("/bin/sh")
    };
    for (builder, expected) in [
        (
            base()
                .pid_namespace(false)
                .landlock_scope([LandlockScope::Signal]),
            "signal",
        ),
        (
            base()
                .network(Network::Host)
                .resolv_conf(false)
                .landlock_scope([LandlockScope::AbstractUnixSocket]),
            "abstract-unix-socket",
        ),
    ] {
        match builder.build() {
            Ok(_) => assert!(enforced, "{expected} built at Landlock ABI {abi:?}"),
            Err(Error::Config(ConfigError::LandlockScopeUnenforceable {
                scope,
                abi: reported,
                ..
            })) => {
                assert!(!enforced, "{expected} was refused at Landlock ABI {abi:?}");
                assert_eq!((scope, reported), (expected, abi));
            }
            Err(other) => panic!("{expected}: {other}"),
        }
    }
    // Behind the namespaces a default sandbox has, the same scopes are
    // additive, and build on any kernel.
    base()
        .landlock_scope(LandlockScope::ALL.iter().copied())
        .build()
        .expect("a scope a namespace also bounds is not refused");
}

#[test]
fn a_landlock_grant_through_a_link_fails_rather_than_follow_it() {
    let Some(rootfs) = common::scratch_rootfs("landlock-through-a-link") else {
        return;
    };
    if !common::landlock() {
        return;
    }
    // Links a root could ship or an earlier run could plant, both pointing at
    // the whole sandbox: one at the end of a grant's path, one on the way to
    // it. Followed, either grant would cover every path in the sandbox, and
    // the command would read /etc/passwd. Neither is followed, so the launch
    // fails and names the grant.
    std::os::unix::fs::symlink("/", rootfs.join("etc/everything")).unwrap();
    std::os::unix::fs::symlink("/", rootfs.join("srv/app")).unwrap();
    for grant in ["/etc/everything", "/srv/app/etc"] {
        let error = Cage::builder()
            .rootfs(&rootfs)
            .command("/bin/busybox")
            .args(["cat", "/etc/passwd"])
            .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/bin")
            .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
            .landlock_fs(FsAccess::READ, grant)
            .build()
            .expect("a valid sandbox configuration")
            .run()
            .expect_err("a grant through a link fails the launch");
        match error {
            Error::Setup {
                step: ferroday_cage::SetupStep::LandlockAddRule,
                detail,
                source,
                ..
            } => {
                assert_eq!(detail.as_deref(), Some(format!("r on {grant}").as_str()));
                assert_eq!(source.raw_os_error(), Some(libc::ELOOP), "{source}");
            }
            other => panic!("{grant}: expected a Landlock rule failure, got {other:?}"),
        }
    }
}

#[test]
fn landlock_request_without_the_lsm_is_a_setup_error() {
    let Some(rootfs) = rootfs() else { return };
    // Only meaningful where Landlock is absent: a requested restriction that
    // cannot apply must surface as an error, never silently succeed.
    if ferroday_cage::host::landlock_abi().is_some() {
        common::require::premise_unmet("the kernel supports Landlock");
        return;
    }
    let result = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["true"])
        .landlock_fs(FsAccess::READ, "/bin")
        .build()
        .expect("a valid sandbox configuration")
        .run();
    assert!(matches!(result, Err(ferroday_cage::Error::Setup { .. })));
}

#[test]
fn landlock_net_allows_a_granted_bind_and_connect() {
    let Some(rootfs) = rootfs() else { return };
    if !common::landlock_net() {
        return;
    }
    // Every bind and connect the round trip needs is granted, so the token
    // completes the round trip and reaches the client's stdout: the listener
    // binds NET_PORT, the client binds an ephemeral source port (port 0), and
    // the client connects to NET_PORT.
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["sh", "-c", NET_ROUNDTRIP])
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/bin")
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
        .landlock_fs(FsAccess::READ, "/dev")
        .landlock_net(NetAccess::BIND, NET_PORT)
        .landlock_net(NetAccess::BIND, 0)
        .landlock_net(NetAccess::CONNECT, NET_PORT)
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    assert!(
        output.status.success(),
        "a permitted round trip must succeed"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(NET_TOKEN),
        "the token must cross a permitted connection"
    );
}

#[test]
fn landlock_net_denies_a_connect_outside_the_grant() {
    let Some(rootfs) = rootfs() else { return };
    if !common::landlock_net() {
        return;
    }
    // Two round trips in one run, differing in nothing but the CONNECT grant:
    // every bind is granted, so both listeners and the client's ephemeral
    // source port bind, and CONNECT is granted on the first port only.
    // Enrolling any network grant makes CONNECT handled and denied everywhere
    // it is not granted, so the second connect is refused by Landlock and its
    // token never crosses — while the first token proves the round trip works
    // here, which is what makes the second's absence enforcement rather than
    // an unrelated failure. busybox nc reports nothing on a refused connect,
    // so this control is the only positive evidence available.
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["sh", "-c", NET_TWO_PORT_ROUNDTRIP])
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/bin")
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
        .landlock_fs(FsAccess::READ, "/dev")
        .landlock_net(NetAccess::BIND, NET_PORT)
        .landlock_net(NetAccess::BIND, NET_UNGRANTED_PORT)
        .landlock_net(NetAccess::BIND, 0)
        .landlock_net(NetAccess::CONNECT, NET_PORT)
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(NET_GRANTED_TOKEN),
        "the granted round trip must work, or the denial below proves nothing: \
         stdout was {stdout:?}, stderr was {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !stdout.contains(NET_UNGRANTED_TOKEN),
        "a connect outside the grant must be denied: stdout was {stdout:?}"
    );
}

#[test]
fn landlock_net_denies_an_ungranted_bind() {
    let Some(rootfs) = rootfs() else { return };
    if !common::landlock_net() {
        return;
    }
    // Only CONNECT is granted, which still enrolls BIND handling. busybox nc
    // binds its ephemeral source port explicitly before connecting, and that
    // bind is not granted (no BIND on port 0), so Landlock refuses it: nc
    // reports the denied bind and never reaches the connect. This is the
    // deny-by-default counterpart of the allow test's granted binds.
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["nc", "-w", "1", "127.0.0.1", "50505"])
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/bin")
        .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
        .landlock_net(NetAccess::CONNECT, NET_PORT)
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bind") && stderr.contains("denied"),
        "an ungranted bind must be denied: stderr was {stderr:?}"
    );
}

#[test]
fn curated_seccomp_allows_an_ordinary_command() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::seccomp() {
        return;
    }
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["true"])
        .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert!(
        status.success(),
        "the curated profile must not break an ordinary command"
    );
}

#[test]
#[cfg(target_pointer_width = "64")]
fn a_rule_added_to_the_curated_roster_refuses_its_syscall_beside_the_roster() {
    let Some(rootfs) = rootfs() else {
        return;
    };
    if !common::require::seccomp() {
        return;
    }
    // Lowering one's own priority needs no privilege, and the roster leaves
    // `setpriority` alone, so the added rule is what refuses it. `mount` is
    // the roster's own entry, refused either way.
    let script = "nice -n 1 true 2>/dev/null; echo nice=$?; \
                  mkdir -p /mnt && mount -t tmpfs none /mnt 2>/dev/null; echo mount=$?";
    let run = |rules: SeccompRules| -> String {
        let output = Cage::builder()
            .rootfs(rootfs)
            .command("/bin/busybox")
            .args(["sh", "-c", script])
            .seccomp(SeccompPolicy::Rules(rules))
            .build()
            .expect("a valid sandbox configuration")
            .output()
            .expect("the sandbox launches");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    assert_eq!(run(SeccompRules::curated()), "nice=0\nmount=1\n");
    assert_eq!(
        run(SeccompRules::curated().rule(libc::SYS_setpriority, [])),
        "nice=1\nmount=1\n"
    );
}

#[test]
fn curated_seccomp_denies_a_listed_syscall() {
    let Some(rootfs) = rootfs() else {
        return;
    };
    if !common::require::seccomp() {
        return;
    }
    // mount is on the curated denylist, denied with EPERM. The cage command is
    // root inside its namespaces, so a tmpfs mount succeeds unfiltered; running
    // it both ways isolates the filter from any other cause, and asserts the
    // curated profile's shipped content actually blocks, not just that it
    // leaves an ordinary command alone.
    let script = "mkdir -p /mnt && mount -t tmpfs none /mnt 2>&1; echo rc=$?";
    let run = |curated: bool| -> String {
        let mut builder = Cage::builder()
            .rootfs(rootfs)
            .command("/bin/busybox")
            .args(["sh", "-c", script]);
        if curated {
            builder = builder.seccomp(SeccompPolicy::Rules(SeccompRules::curated()));
        }
        let output = builder
            .build()
            .expect("a valid sandbox configuration")
            .output()
            .expect("the sandbox launches");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let unfiltered = run(false);
    assert!(
        unfiltered.contains("rc=0"),
        "the mount should succeed without the filter: {unfiltered:?}"
    );
    let filtered = run(true);
    // busybox renders the mount syscall's EPERM as a permission-denied message;
    // the rc=1-versus-rc=0 flip is what pins the denial to the filter.
    let denied = filtered.to_lowercase();
    assert!(
        filtered.contains("rc=1")
            && !filtered.contains("rc=0")
            && (denied.contains("permission denied") || denied.contains("not permitted")),
        "the curated profile must deny the mount syscall with EPERM: {filtered:?}"
    );
}

#[test]
fn curated_seccomp_denies_creating_a_namespace() {
    let Some(rootfs) = rootfs() else {
        return;
    };
    if !common::require::seccomp() {
        return;
    }
    // The command is root in its own user namespace, so a new user namespace
    // and a new network namespace are both its to create unfiltered. Running
    // the script both ways isolates the filter from any other cause. Every
    // command the shell runs is a process it started, so the filtered run
    // reaching its last line is the evidence that processes still start.
    let script = "unshare -U true 2>&1; echo user=$?; unshare -n true 2>&1; echo net=$?";
    let run = |curated: bool| -> String {
        let mut builder = Cage::builder()
            .rootfs(rootfs)
            .command("/bin/busybox")
            .args(["sh", "-c", script]);
        if curated {
            builder = builder.seccomp(SeccompPolicy::Rules(SeccompRules::curated()));
        }
        let output = builder
            .build()
            .expect("a valid sandbox configuration")
            .output()
            .expect("the sandbox launches");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let unfiltered = run(false);
    assert!(
        unfiltered.contains("user=0") && unfiltered.contains("net=0"),
        "both namespaces should be created without the filter: {unfiltered:?}"
    );
    let filtered = run(true);
    assert!(
        filtered.contains("user=1")
            && filtered.contains("net=1")
            && filtered.to_lowercase().contains("not permitted"),
        "the curated profile must deny both namespaces with EPERM: {filtered:?}"
    );
}

#[test]
#[cfg(target_pointer_width = "64")]
fn a_relaxed_roster_lets_a_command_create_namespaces_and_refuses_the_rest() {
    let Some(rootfs) = rootfs() else {
        return;
    };
    if !common::require::seccomp() {
        return;
    }
    // The roster less its namespace entries, for a command that builds a
    // sandbox of its own: the namespaces are created, and the mount the roster
    // still refuses is refused.
    let rules = SeccompRules::curated()
        .relax(libc::SYS_unshare)
        .relax(libc::SYS_clone);
    let script = "unshare -U true 2>&1; echo user=$?; mkdir -p /mnt; \
                  mount -t tmpfs none /mnt 2>&1; echo mount=$?";
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["sh", "-c", script])
        .seccomp(SeccompPolicy::Rules(rules))
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("user=0") && stdout.contains("mount=1"),
        "{stdout:?}"
    );
}

#[test]
#[cfg(target_pointer_width = "64")]
fn an_errno_no_failed_syscall_reports_is_refused_at_build() {
    // A build alone, so this needs neither the fixture nor seccomp in the
    // kernel. Zero would hand `getpid` a pid of 0 and tell a `clone3` caller it
    // is the child; past 4095 the C library reads the answer as a value.
    let policies = |errno: u16| {
        [
            SeccompRules::denying([]).errno_for(libc::SYS_getpid, errno),
            SeccompRules::denying([libc::SYS_getpid]).listed_action(SeccompAction::Errno(errno)),
            SeccompRules::allowing([libc::SYS_exit_group])
                .default_action(SeccompAction::Errno(errno)),
        ]
    };
    let builds = |rules: SeccompRules| {
        let sandbox = Cage::builder()
            .rootfs(common::scratch_dir("errno-range"))
            .command("/bin/sh")
            .seccomp(SeccompPolicy::Rules(rules.clone()))
            .build()
            .map(drop);
        let restriction = Restriction::builder()
            .command("/bin/true")
            .seccomp(SeccompPolicy::Rules(rules))
            .build()
            .map(drop);
        [sandbox, restriction]
    };
    for errno in [0, 4096, u16::MAX] {
        for rules in policies(errno) {
            for built in builds(rules) {
                match built {
                    Err(Error::Config(ConfigError::SeccompInvalid { reason, .. })) => {
                        assert!(reason.contains(&format!("errno {errno},")), "{reason}");
                    }
                    other => panic!("errno {errno} is refused: {other:?}"),
                }
            }
        }
    }
    for errno in [1, 4095] {
        for rules in policies(errno) {
            for built in builds(rules) {
                built.unwrap_or_else(|err| panic!("errno {errno} builds: {err}"));
            }
        }
    }
}

#[test]
#[cfg(target_pointer_width = "64")]
fn a_denied_syscall_kills_the_command() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::seccomp() {
        return;
    }
    // Denying write with a process kill: the command dies with SIGSYS the
    // moment it writes, proving the filter is live.
    // SYS_write is c_long, which is i64 on the 64-bit seccomp-supported
    // architectures this test runs on.
    let policy = SeccompRules::denying([libc::SYS_write])
        .listed_action(ferroday_cage::SeccompAction::KillProcess);
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["echo", "hello"])
        .seccomp(SeccompPolicy::Rules(policy))
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "a killed command reports termination by SIGSYS"
    );
}

/// A full capability drop leaves every set empty, bounding set included.
///
/// This is also the guard on where the nested user namespace is entered.
/// Entering one has the kernel re-derive the credential: the bounding set comes
/// back full, the inheritable and ambient sets are cleared, and the securebits
/// go back to the default with the locked bit among them. A drop applied before
/// the entry would therefore be undone without a word, and `CapBnd` would read
/// back full — so this assertion fails the moment the entry moves after the
/// hardening layer.
#[test]
fn dropping_capabilities_empties_every_set() {
    let Some(rootfs) = rootfs() else { return };
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["cat", "/proc/self/status"])
        .drop_all_capabilities()
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    for set in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let value =
            common::status_field(&text, set).unwrap_or_else(|| panic!("the status reports {set}"));
        assert_eq!(
            value, "0000000000000000",
            "a full capability drop must empty {set}",
        );
    }
}

#[test]
fn keeping_a_capability_retains_only_it() {
    let Some(rootfs) = rootfs() else { return };
    let output = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["cat", "/proc/self/status"])
        .keep_capabilities([Capability::NetBindService])
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    let effective =
        common::status_field(&text, "CapEff").expect("the status reports an effective set");
    // CAP_NET_BIND_SERVICE is bit 10, so the effective set is exactly 1 << 10.
    let bits = u64::from_str_radix(effective, 16).expect("a hex capability mask");
    assert_eq!(bits, 1 << 10, "only the kept capability remains");
}

// ---------------------------------------------------------------------------
// Seccomp reports: each call the filter refuses, answered by the caller.
// ---------------------------------------------------------------------------

/// Collects the command's standard output.
#[derive(Default)]
struct Collected(Vec<u8>);

impl ferroday_cage::Observer for Collected {
    fn stdout(&mut self, chunk: &[u8]) {
        self.0.extend_from_slice(chunk);
    }
}

/// Every report a stream holds, read to its end, which comes once no process
/// the filter governs is left; a stream that has not ended within ten seconds
/// fails the test.
fn drained(
    reports: ferroday_cage::Reports<ferroday_cage::SeccompReport>,
) -> Vec<ferroday_cage::SeccompReport> {
    let mut read = Vec::new();
    loop {
        match reports.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(report) => read.push(report),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return read,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("the reports did not end; read so far: {read:?}")
            }
        }
    }
}

/// The syscall a report names, and the errno it answered.
fn named(report: &ferroday_cage::SeccompReport) -> (Option<&'static str>, u16) {
    match report {
        ferroday_cage::SeccompReport::Denied { name, errno, .. } => (*name, *errno),
        other => panic!("not a denial: {other:?}"),
    }
}

/// How a test launches its sandbox: spawned, or held at the gate and released.
#[derive(Debug, Clone, Copy)]
enum Launch {
    Spawned,
    Released,
}

/// Runs `script` under the fixture's busybox with `policy`, its refusals
/// reported where `reports` says so, and returns its standard output and the
/// reports read to their end.
fn reported_run(
    rootfs: &Path,
    script: &str,
    policy: SeccompRules,
    reports: bool,
    pid_namespace: bool,
    launch: Launch,
) -> (String, Vec<ferroday_cage::SeccompReport>) {
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["sh", "-c", script])
        .pid_namespace(pid_namespace)
        .seccomp(SeccompPolicy::Rules(policy))
        .seccomp_reports(reports)
        .build()
        .expect("a valid sandbox configuration");
    let mut collected = Collected::default();
    let mut running = match launch {
        Launch::Spawned => cage.spawn_with(&mut collected),
        Launch::Released => cage
            .spawn_pending_with(&mut collected)
            .and_then(|pending| pending.proceed()),
    }
    .expect("the sandbox launches");
    let stream = running.take_seccomp_reports();
    assert_eq!(
        stream.is_some(),
        reports,
        "reports are made exactly where asked for"
    );
    assert!(
        running.take_seccomp_reports().is_none(),
        "the reports are taken once"
    );
    running.wait().expect("the outcome is collected");
    drop(running);
    let read = stream.map(drained).unwrap_or_default();
    (String::from_utf8_lossy(&collected.0).into_owned(), read)
}

#[test]
#[cfg(target_pointer_width = "64")]
fn a_refused_call_is_reported_and_answered_as_it_is_without_reports() {
    let Some(rootfs) = rootfs() else {
        return;
    };
    if !common::require::seccomp() {
        return;
    }
    // Two refusals of the curated roster's, each run where the command is root
    // in its own namespaces and would succeed unfiltered. The command sees the
    // same failure with reports as without: the listener answers with the
    // roster's errno.
    let script = "mkdir -p /mnt; mount -t tmpfs none /mnt 2>&1; echo mount=$?; \
                  unshare -U true 2>&1; echo unshare=$?";
    for pid_namespace in [true, false] {
        for launch in [Launch::Spawned, Launch::Released] {
            let context = format!("pid namespace {pid_namespace}, {launch:?}");
            let (plain, none) = reported_run(
                rootfs,
                script,
                SeccompRules::curated(),
                false,
                pid_namespace,
                launch,
            );
            assert!(none.is_empty());
            assert!(
                plain.contains("mount=1") && plain.contains("unshare=1"),
                "{context}: {plain:?}"
            );
            let (reported_output, reports) = reported_run(
                rootfs,
                script,
                SeccompRules::curated(),
                true,
                pid_namespace,
                launch,
            );
            assert_eq!(reported_output, plain, "{context}");
            let names: Vec<_> = reports.iter().map(named).collect();
            assert!(
                names.contains(&(Some("mount"), 1)),
                "{context}: {reports:?}"
            );
            assert!(
                names.contains(&(Some("unshare"), 1)),
                "{context}: {reports:?}"
            );
            // Every report names a thread and what it ran.
            for report in &reports {
                let ferroday_cage::SeccompReport::Denied {
                    thread, command, ..
                } = report
                else {
                    unreachable!()
                };
                assert!(*thread > 0 && command.is_some(), "{context}: {report:?}");
            }
        }
    }
}

#[test]
#[cfg(target_pointer_width = "64")]
fn a_report_carries_the_arguments_its_refusal_was_judged_on() {
    let Some(rootfs) = rootfs() else {
        return;
    };
    if !common::require::seccomp() {
        return;
    }
    // The roster refuses `unshare` by its flags, and the report holds them.
    let (_, reports) = reported_run(
        rootfs,
        "unshare -n true",
        SeccompRules::curated(),
        true,
        true,
        Launch::Spawned,
    );
    let flags = reports.iter().find_map(|report| match report {
        ferroday_cage::SeccompReport::Denied {
            name: Some("unshare"),
            arguments,
            ..
        } => Some(arguments[0]),
        _ => None,
    });
    let new_net = libc::CLONE_NEWNET as u64;
    assert!(
        flags.is_some_and(|flags| flags & new_net != 0),
        "{reports:?}"
    );
}

#[test]
#[cfg(target_pointer_width = "64")]
fn an_answer_of_absence_is_answered_and_not_reported() {
    let Some(rootfs) = rootfs() else {
        return;
    };
    if !common::require::seccomp() {
        return;
    }
    // `sethostname` answered ENOSYS, as a kernel without it would, beside the
    // roster's own refusals: the command sees the errno, and nothing reports
    // it. The mount is the positive control that reports flow at all.
    let rules = SeccompRules::curated().errno_for(libc::SYS_sethostname, libc::ENOSYS as u16);
    let (output, reports) = reported_run(
        rootfs,
        "hostname elsewhere 2>&1; echo hostname=$?; mkdir -p /mnt; mount -t tmpfs none /mnt 2>/dev/null",
        rules,
        true,
        true,
        Launch::Spawned,
    );
    assert!(output.contains("hostname=1"), "{output:?}");
    let names: Vec<_> = reports.iter().map(named).collect();
    assert!(names.contains(&(Some("mount"), 1)), "{reports:?}");
    assert!(
        !names.iter().any(|(name, _)| *name == Some("sethostname")),
        "{reports:?}"
    );
}

#[test]
#[cfg(target_pointer_width = "64")]
fn a_restricted_commands_refusals_are_reported() {
    if !common::require::seccomp() {
        return;
    }
    let unshare = Path::new("/usr/bin/unshare");
    if !unshare.exists() {
        eprintln!("skipping: no {} on this host", unshare.display());
        return;
    }
    let restriction = Restriction::builder()
        .command(unshare)
        .args(["--user", "true"])
        .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
        .seccomp_reports(true)
        .build()
        .expect("a valid restriction");
    let mut running = restriction.spawn().expect("the command launches");
    let stream = running
        .take_seccomp_reports()
        .expect("the reports are made");
    let status = running.wait().expect("the outcome is collected");
    assert!(!status.success(), "{status:?}");
    drop(running);
    let reports = drained(stream);
    assert!(
        reports
            .iter()
            .map(named)
            .any(|named| named == (Some("unshare"), 1)),
        "{reports:?}"
    );
}

#[test]
#[cfg(target_pointer_width = "64")]
#[allow(unsafe_code)]
fn a_caller_already_under_a_listener_cannot_have_reports() {
    let Some(rootfs) = rootfs() else {
        return;
    };
    if !common::require::seccomp() {
        return;
    }
    let cage = move |reports: bool| {
        Cage::builder()
            .rootfs(rootfs)
            .command("/bin/true")
            .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
            .seccomp_reports(reports)
            .build()
            .expect("a valid sandbox configuration")
    };
    assert!(
        ferroday_cage::host::seccomp_listener_available(),
        "nothing holds a listener on this process yet"
    );
    // A thread of its own takes a filter with a listener, as a runtime that
    // intercepts syscalls installs one: a filter binds only the thread that
    // installs it, and this one ends with the thread.
    std::thread::spawn(move || {
        let allow = libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        };
        let program = libc::sock_fprog {
            len: 1,
            filter: (&raw const allow).cast_mut(),
        };
        // SAFETY: a flag on the calling thread, which ends with the test.
        let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        assert_eq!(no_new_privs, 0);
        // SAFETY: the kernel copies the one-instruction program, which outlives
        // the call, and answers with a listener this thread owns.
        let listener = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &raw const program,
            )
        };
        assert!(listener >= 0, "{}", std::io::Error::last_os_error());
        // The host's probe says so before a launch does.
        assert!(!ferroday_cage::host::seccomp_listener_available());
        let held = cage(true).spawn();
        assert!(
            matches!(held, Err(Error::SeccompListenerHeld { .. })),
            "{:?}",
            held.map(|_| ())
        );
        // The same launch without reports installs its filter as usual.
        assert!(cage(false).run().expect("the sandbox runs").success());
        // SAFETY: the listener is this thread's, closed once.
        unsafe { libc::close(listener as libc::c_int) };
    })
    .join()
    .expect("the thread's assertions hold");
}
