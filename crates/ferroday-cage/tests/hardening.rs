//! Integration tests for the hardening layer: Landlock filesystem rules,
//! seccomp syscall filters, capability drops, and the denied network.
//!
//! Each test builds a real sandbox on Linux and observes the restriction
//! taking effect. Tests skip explicitly when the host lacks the facility they
//! exercise — unprivileged user namespaces, the Landlock LSM, or seccomp —
//! rather than passing silently.

mod common;

use std::path::Path;

use ferroday_cage::{Cage, Capability, FsAccess, NetAccess, SeccompPolicy, SeccompRules};

/// The fixture rootfs, or `None` when the sandbox tests should skip.
fn rootfs() -> Option<&'static Path> {
    common::fixture_rootfs()
}

/// Skips a Landlock test when the kernel offers no Landlock LSM.
///
/// The skip is explicit, and `FERRODAY_CAGE_REQUIRE_LANDLOCK` turns it into a
/// failure so CI can assert the Landlock enforcement tests actually ran.
fn landlock_supported() -> bool {
    match ferroday_cage::host::landlock_abi() {
        Some(_) => true,
        None => {
            assert!(
                std::env::var_os("FERRODAY_CAGE_REQUIRE_LANDLOCK").is_none(),
                "Landlock is required but the kernel offers none",
            );
            eprintln!("skipping: the kernel offers no Landlock support");
            false
        }
    }
}

/// Skips a Landlock network test when the kernel's Landlock ABI predates the
/// network rights, which arrive in ABI 4.
///
/// As with [`landlock_supported`], `FERRODAY_CAGE_REQUIRE_LANDLOCK` turns the
/// skip into a failure: a runner CI marks Landlock-capable is expected to reach
/// ABI 4.
fn landlock_net_supported() -> bool {
    match ferroday_cage::host::landlock_abi() {
        Some(abi) if abi >= 4 => true,
        Some(abi) => {
            assert!(
                std::env::var_os("FERRODAY_CAGE_REQUIRE_LANDLOCK").is_none(),
                "Landlock network rights are required but the kernel's ABI is {abi} (needs 4)",
            );
            eprintln!("skipping: Landlock ABI {abi} predates network rights (needs 4)");
            false
        }
        None => {
            assert!(
                std::env::var_os("FERRODAY_CAGE_REQUIRE_LANDLOCK").is_none(),
                "Landlock is required but the kernel offers none",
            );
            eprintln!("skipping: the kernel offers no Landlock support");
            false
        }
    }
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

/// Skips a seccomp test when the kernel offers no seccomp filtering.
///
/// The skip is explicit, and `FERRODAY_CAGE_REQUIRE_SECCOMP` turns it into a
/// failure so CI can assert the seccomp enforcement tests actually ran.
fn seccomp_supported() -> bool {
    if ferroday_cage::host::seccomp_available() {
        true
    } else {
        assert!(
            std::env::var_os("FERRODAY_CAGE_REQUIRE_SECCOMP").is_none(),
            "seccomp is required but the kernel offers none",
        );
        eprintln!("skipping: the kernel offers no seccomp support");
        false
    }
}

#[test]
fn landlock_denies_a_path_outside_the_grants() {
    let Some(rootfs) = rootfs() else { return };
    if !landlock_supported() {
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
    if !landlock_supported() {
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
    if !landlock_supported() {
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
fn landlock_request_without_the_lsm_is_a_setup_error() {
    let Some(rootfs) = rootfs() else { return };
    // Only meaningful where Landlock is absent: a requested restriction that
    // cannot apply must surface as an error, never silently succeed.
    if ferroday_cage::host::landlock_abi().is_some() {
        eprintln!("skipping: the kernel supports Landlock");
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
    if !landlock_net_supported() {
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
    if !landlock_net_supported() {
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
    if !landlock_net_supported() {
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
    if !seccomp_supported() {
        return;
    }
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/busybox")
        .args(["true"])
        .seccomp(SeccompPolicy::Curated)
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
fn curated_seccomp_denies_a_listed_syscall() {
    let Some(rootfs) = rootfs() else {
        return;
    };
    if !seccomp_supported() {
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
            builder = builder.seccomp(SeccompPolicy::Curated);
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
fn a_denied_syscall_kills_the_command() {
    let Some(rootfs) = rootfs() else { return };
    if !seccomp_supported() {
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
        let value = text
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{set}:")))
            .map(str::trim)
            .unwrap_or_else(|| panic!("the status reports {set}"));
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
    let effective = text
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim)
        .expect("the status reports an effective set");
    // CAP_NET_BIND_SERVICE is bit 10, so the effective set is exactly 1 << 10.
    let bits = u64::from_str_radix(effective, 16).expect("a hex capability mask");
    assert_eq!(bits, 1 << 10, "only the kept capability remains");
}
