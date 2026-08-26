//! Integration tests for the restriction fallback: Landlock and seccomp
//! confinement of a plain spawned command, without user namespaces.
//!
//! Unlike the sandbox tests, these need neither unprivileged user namespaces
//! nor the rootfs fixture — a restriction runs host binaries — so they
//! exercise on hosts where every cage test skips. Tests skip explicitly when
//! the kernel lacks the facility they use, Landlock or seccomp, rather than
//! passing silently.

use std::path::Path;
use std::time::Duration;

mod common;

use common::scratch_dir as scratch;
use ferroday_cage::{
    Error, FsAccess, NetAccess, Restriction, RestrictionBuilder, SeccompAction, SeccompArg,
    SeccompPolicy, SeccompRules, SetupStep, Stdio, Terminal,
};

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

/// Adds the grants that make a dynamically linked host binary runnable:
/// read and execute beneath the standard system trees, granting only the
/// ones this host has.
fn grant_system_trees(mut builder: RestrictionBuilder) -> RestrictionBuilder {
    for tree in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
        if Path::new(tree).exists() {
            builder = builder.landlock_fs(FsAccess::READ | FsAccess::EXECUTE, tree);
        }
    }
    builder
}

#[test]
fn landlock_allows_a_granted_path_and_denies_the_rest() {
    if !landlock_supported() {
        return;
    }
    let granted = scratch("restrict-granted");
    let denied = scratch("restrict-denied");
    std::fs::write(granted.join("file"), "granted contents\n").unwrap();
    std::fs::write(denied.join("file"), "denied contents\n").unwrap();

    // The command may run from the system trees and read the granted
    // directory; reading beneath it succeeds and delivers the contents.
    let output = grant_system_trees(Restriction::builder())
        .command("/bin/cat")
        .arg(granted.join("file"))
        .landlock_fs(FsAccess::READ, &granted)
        .build()
        .expect("a valid restriction configuration")
        .output()
        .expect("the restriction launches");
    assert!(
        output.status.success(),
        "reading a granted path must succeed"
    );
    assert_eq!(output.stdout, b"granted contents\n");

    // The same command against the ungranted directory is denied by the
    // ruleset, so cat exits non-zero.
    let status = grant_system_trees(Restriction::builder())
        .command("/bin/cat")
        .arg(denied.join("file"))
        .landlock_fs(FsAccess::READ, &granted)
        .build()
        .expect("a valid restriction configuration")
        .run()
        .expect("the restriction launches");
    assert!(
        !status.success(),
        "reading an ungranted path must be denied"
    );
}

/// Skips a Landlock network test when the kernel's ABI predates network
/// rights, which arrived in ABI 4.
fn landlock_net_supported() -> bool {
    match ferroday_cage::host::landlock_abi() {
        Some(abi) if abi >= 4 => true,
        _ => {
            assert!(
                std::env::var_os("FERRODAY_CAGE_REQUIRE_LANDLOCK_NET").is_none(),
                "Landlock network rights are required but the kernel offers none",
            );
            eprintln!("skipping: the kernel's Landlock ABI predates network rights");
            false
        }
    }
}

#[test]
fn landlock_net_gates_a_tcp_connection() {
    if !landlock_supported() || !landlock_net_supported() {
        return;
    }
    // A host listener the command is asked to reach. The port is granted in
    // one run and not in the other; nothing else differs.
    let listener =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("a listener binds");
    let port = listener.local_addr().expect("an address").port();
    std::thread::spawn(move || {
        // Accept whatever arrives for the duration of the test.
        while listener.accept().is_ok() {}
    });

    let Some(nc) = ["/usr/bin/nc", "/bin/nc", "/usr/bin/ncat"]
        .into_iter()
        .find(|path| Path::new(path).exists())
    else {
        eprintln!("skipping: no nc on this host to make the connection with");
        return;
    };

    let connect = |granted: u16| {
        grant_system_trees(Restriction::builder())
            .command(nc)
            .args(["-w", "2", "127.0.0.1", &port.to_string()])
            .landlock_net(NetAccess::CONNECT, granted)
            .stdin(Stdio::Null)
            .build()
            .expect("a valid restriction configuration")
            .run()
            .expect("the restriction launches")
    };

    assert!(
        connect(port).success(),
        "a granted port must remain connectable",
    );
    // Enrolling any grant denies everything ungranted, so granting a different
    // port denies this one. The grant is what is being tested, so the run is
    // otherwise identical.
    assert!(
        !connect(port.wrapping_add(1).max(1)).success(),
        "an ungranted port must be denied",
    );
}

#[test]
fn an_empty_landlock_grant_is_refused() {
    // An empty access set reads as "grant nothing here" and behaves as "deny
    // the whole class": the enrollment denies everything ungranted, and the
    // kernel skips a rule that permits nothing. A restriction built that way
    // fails at `execve` with nothing pointing at the cause, so the build
    // refuses it instead. No kernel support is needed to decide this.
    let err = Restriction::builder()
        .command("/bin/true")
        .landlock_fs(FsAccess::empty(), "/usr")
        .build()
        .expect_err("an empty filesystem grant is refused");
    assert!(
        matches!(
            err,
            Error::Config(ferroday_cage::ConfigError::LandlockGrantEmpty { .. })
        ),
        "{err}"
    );

    let err = Restriction::builder()
        .command("/bin/true")
        .landlock_net(NetAccess::empty(), 443)
        .build()
        .expect_err("an empty network grant is refused");
    assert!(
        matches!(
            err,
            Error::Config(ferroday_cage::ConfigError::LandlockGrantEmpty { .. })
        ),
        "{err}"
    );
}

#[test]
fn landlock_write_grant_gates_file_creation() {
    if !landlock_supported() {
        return;
    }
    let writable = scratch("restrict-writable");
    let read_only = scratch("restrict-read-only");

    // touch(1) creates a file where the grant allows writing...
    let status = grant_system_trees(Restriction::builder())
        .command("/bin/touch")
        .arg(writable.join("created"))
        .landlock_fs(FsAccess::READ | FsAccess::WRITE, &writable)
        .landlock_fs(FsAccess::READ, &read_only)
        .build()
        .expect("a valid restriction configuration")
        .run()
        .expect("the restriction launches");
    assert!(
        status.success(),
        "creating in a writable grant must succeed"
    );
    assert!(writable.join("created").exists());

    // ...and fails where the grant is read-only.
    let status = grant_system_trees(Restriction::builder())
        .command("/bin/touch")
        .arg(read_only.join("created"))
        .landlock_fs(FsAccess::READ | FsAccess::WRITE, &writable)
        .landlock_fs(FsAccess::READ, &read_only)
        .build()
        .expect("a valid restriction configuration")
        .run()
        .expect("the restriction launches");
    assert!(
        !status.success(),
        "creating under a read-only grant must be denied"
    );
    assert!(!read_only.join("created").exists());
}

#[test]
fn curated_seccomp_allows_an_ordinary_command() {
    if !seccomp_supported() {
        return;
    }
    let status = Restriction::builder()
        .command("/bin/true")
        .seccomp(SeccompPolicy::Curated)
        .build()
        .expect("a valid restriction configuration")
        .run()
        .expect("the restriction launches");
    assert!(
        status.success(),
        "the curated profile must not break an ordinary command"
    );
}

#[test]
fn a_denied_syscall_kills_the_command() {
    if !seccomp_supported() {
        return;
    }
    // Denying write with a process kill: the command dies with SIGSYS the
    // moment it writes, proving the filter binds the host process.
    let policy = SeccompRules::denying([libc::SYS_write]).listed_action(SeccompAction::KillProcess);
    let status = Restriction::builder()
        .command("/bin/echo")
        .arg("hello")
        .seccomp(SeccompPolicy::Rules(policy))
        .build()
        .expect("a valid restriction configuration")
        .run()
        .expect("the restriction launches");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "a killed command reports termination by SIGSYS"
    );
}

#[test]
fn an_argument_condition_kills_only_a_matching_call() {
    if !seccomp_supported() {
        return;
    }
    // Kill write only when its first argument, the file descriptor, is 1.
    // echo writes its output to descriptor 1, so it triggers the kill.
    let policy = SeccompRules::denying([])
        .rule(libc::SYS_write, [SeccompArg::eq_dword(0, 1)])
        .listed_action(SeccompAction::KillProcess);
    let status = Restriction::builder()
        .command("/bin/echo")
        .arg("hello")
        .seccomp(SeccompPolicy::Rules(policy))
        .build()
        .expect("a valid restriction configuration")
        .run()
        .expect("the restriction launches");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "writing to the matched descriptor is killed"
    );
}

#[test]
fn an_argument_condition_spares_a_nonmatching_call() {
    if !seccomp_supported() {
        return;
    }
    // The same policy, but conditioned on descriptor 2. echo writes to
    // descriptor 1, which does not match, so the command runs to completion.
    let policy = SeccompRules::denying([])
        .rule(libc::SYS_write, [SeccompArg::eq_dword(0, 2)])
        .listed_action(SeccompAction::KillProcess);
    let status = Restriction::builder()
        .command("/bin/echo")
        .arg("hello")
        .seccomp(SeccompPolicy::Rules(policy))
        .build()
        .expect("a valid restriction configuration")
        .run()
        .expect("the restriction launches");
    assert!(
        status.success(),
        "writing to an unmatched descriptor is allowed"
    );
}

#[test]
fn no_new_privileges_is_always_set() {
    if !seccomp_supported() {
        return;
    }
    // A seccomp-only restriction leaves the filesystem unrestricted, so the
    // command can read its own status and show the flag the restriction
    // always sets.
    let output = Restriction::builder()
        .command("/bin/cat")
        .arg("/proc/self/status")
        .seccomp(SeccompPolicy::Curated)
        .build()
        .expect("a valid restriction configuration")
        .output()
        .expect("the restriction launches");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    let no_new_privs = text
        .lines()
        .find_map(|line| line.strip_prefix("NoNewPrivs:"))
        .map(str::trim)
        .expect("the status reports the no-new-privileges flag");
    assert_eq!(no_new_privs, "1");
}

#[test]
fn capabilities_are_dropped() {
    if !seccomp_supported() {
        return;
    }
    // A restriction always drops to the empty capability set. The command
    // reads its own status: the effective and permitted sets must be empty,
    // so a privileged caller's capabilities are not carried into the command.
    // (An unprivileged runner already starts empty, which still exercises the
    // drop path and proves it neither errors nor leaves a stray capability.)
    let output = Restriction::builder()
        .command("/bin/cat")
        .arg("/proc/self/status")
        .seccomp(SeccompPolicy::Curated)
        .build()
        .expect("a valid restriction configuration")
        .output()
        .expect("the restriction launches");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
            .unwrap_or_else(|| panic!("the status reports {name}"))
            .to_string()
    };
    assert_eq!(
        field("CapEff:"),
        "0000000000000000",
        "no effective capability"
    );
    assert_eq!(
        field("CapPrm:"),
        "0000000000000000",
        "no permitted capability"
    );
}

#[test]
fn the_environment_is_the_base_plus_overrides() {
    if !seccomp_supported() {
        return;
    }
    let output = Restriction::builder()
        .command("/usr/bin/env")
        .env("PROBE", "value")
        .seccomp(SeccompPolicy::Curated)
        .build()
        .expect("a valid restriction configuration")
        .output()
        .expect("the restriction launches");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort_unstable();
    // Exactly the deterministic base plus the override: nothing leaks in
    // from the host environment, and no HOME is invented.
    assert_eq!(
        lines,
        [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PROBE=value",
        ]
    );
}

#[test]
fn the_working_directory_applies() {
    if !seccomp_supported() {
        return;
    }
    let output = Restriction::builder()
        .command("/bin/pwd")
        .current_dir("/usr")
        .seccomp(SeccompPolicy::Curated)
        .build()
        .expect("a valid restriction configuration")
        .output()
        .expect("the restriction launches");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"/usr\n");
}

#[test]
fn the_working_directory_defaults_to_the_root() {
    if !seccomp_supported() {
        return;
    }
    // The default is `/`, not whatever directory the caller happened to be in:
    // a restriction that inherited one would run the same command differently
    // depending on where it was launched from, and a relative path the command
    // resolves would name a different file each time.
    let output = Restriction::builder()
        .command("/bin/pwd")
        .seccomp(SeccompPolicy::Curated)
        .build()
        .expect("a valid restriction configuration")
        .output()
        .expect("the restriction launches");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"/\n");
}

#[test]
fn the_handle_kills_a_running_command() {
    if !seccomp_supported() {
        return;
    }
    let restriction = Restriction::builder()
        .command("/bin/sleep")
        .arg("30")
        .seccomp(SeccompPolicy::Curated)
        .build()
        .expect("a valid restriction configuration");
    let mut running = restriction.spawn().expect("the restriction launches");
    assert!(
        running
            .wait_timeout(Duration::from_millis(200))
            .expect("the deadline wait works")
            .is_none(),
        "the command outlives the deadline"
    );
    running.kill().expect("the kill is delivered");
    let status = running.wait().expect("the outcome is collected");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}

#[test]
fn a_missing_command_is_an_exec_setup_error() {
    if !seccomp_supported() {
        return;
    }
    let result = Restriction::builder()
        .command("/ferroday-cage/no/such/binary")
        .seccomp(SeccompPolicy::Curated)
        .build()
        .expect("a valid restriction configuration")
        .run();
    match result {
        Err(Error::Setup { step, .. }) => assert_eq!(step, SetupStep::Exec),
        other => panic!("expected an exec setup error, got {other:?}"),
    }
}

#[test]
fn a_restriction_directs_its_output_streams() {
    if !seccomp_supported() {
        return;
    }
    // A restriction's command inherits the caller's descriptors exactly as a
    // cage's does, so closing the caller's terminal to it takes the output pair
    // as well as standard input. Standard output is discarded and standard
    // error goes to a pipe the caller supplies; the command reports what each
    // was wired to, taking a copy of standard output onto file descriptor 3
    // first so the redirection cannot answer for it.
    let Some(shell) = ["/bin/sh", "/usr/bin/sh"]
        .into_iter()
        .find(|path| Path::new(path).exists())
    else {
        eprintln!("skipping: no shell on this host");
        return;
    };
    let (mut reader, writer) = std::io::pipe().expect("a pipe");
    let restriction = grant_system_trees(Restriction::builder())
        .landlock_fs(FsAccess::READ, "/proc")
        .command(shell)
        .args([
            "-c",
            "exec 3>&1; readlink /proc/self/fd/3 >&2; echo err >&2",
        ])
        .stdin(Stdio::Null)
        .stdout(Stdio::Null)
        .stderr(Stdio::from_fd(writer.into()))
        .build()
        .expect("a valid restriction configuration");
    let status = restriction.run().expect("the restriction launches");
    assert!(status.success());
    // The plan shares the caller's descriptor for its whole life, so the write
    // end closes only once the restriction is gone.
    drop(restriction);

    let mut captured = String::new();
    std::io::Read::read_to_string(&mut reader, &mut captured)
        .expect("the pipe reads to end-of-file");
    let mut lines = captured.lines();
    assert_eq!(
        lines.next(),
        Some("/dev/null"),
        "a null standard output resolves to the null device: {captured:?}",
    );
    assert_eq!(
        lines.next(),
        Some("err"),
        "the descriptor disposition carries what the command wrote: {captured:?}",
    );
}

#[test]
fn a_restriction_runs_on_a_terminal_of_its_own() {
    if !seccomp_supported() {
        return;
    }
    // A host-allocated pseudoterminal needs no devpts instance, so the fallback
    // gets the same interactive story a cage does: isatty holds on all three
    // streams, the command has a controlling terminal, and it is not the
    // caller's. The command process is the session leader here, there being no
    // PID namespace and so no init above it.
    let Some(shell) = ["/bin/sh", "/usr/bin/sh"]
        .into_iter()
        .find(|path| Path::new(path).exists())
    else {
        eprintln!("skipping: no shell on this host");
        return;
    };
    let restriction = grant_system_trees(Restriction::builder())
        .landlock_fs(FsAccess::READ, "/proc")
        .command(shell)
        .args([
            "-c",
            "for fd in 0 1 2; do [ -t $fd ] || exit 1; done; stty size",
        ])
        .build()
        .expect("a valid restriction configuration");
    let (mut running, mut pty) = restriction
        .spawn_terminal(&Terminal::new().size(30, 100))
        .expect("the restriction launches on a terminal");

    let mut written = Vec::new();
    std::io::Read::read_to_end(&mut pty, &mut written).expect("the primary drains to end-of-file");
    let status = running.wait().expect("the outcome is collected");
    let written = String::from_utf8_lossy(&written);
    assert!(status.success(), "isatty must hold on all three: {written}");
    assert!(
        written.contains("30 100"),
        "the command sees the stated size: {written}",
    );
}

#[test]
fn a_restricted_terminal_launch_is_refused_against_a_directed_stream() {
    if !seccomp_supported() {
        return;
    }
    let restriction = Restriction::builder()
        .command("/bin/true")
        .seccomp(SeccompPolicy::Curated)
        .stdin(Stdio::Null)
        .build()
        .expect("the restriction itself is valid");
    let err = restriction
        .spawn_terminal(&Terminal::new())
        .expect_err("a terminal launch is refused");
    assert!(
        matches!(
            err,
            Error::Config(ferroday_cage::ConfigError::StreamAttachmentConflict { .. })
        ),
        "{err:?}",
    );
}
