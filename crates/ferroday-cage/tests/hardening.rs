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
