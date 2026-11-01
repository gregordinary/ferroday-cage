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
    Error, FsAccess, LandlockScope, NetAccess, Restriction, RestrictionBuilder, SeccompAction,
    SeccompArg, SeccompPolicy, SeccompRules, SetupStep, Stdio, Terminal,
};

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
fn a_directory_on_a_standard_stream_is_refused() {
    if !common::seccomp() {
        return;
    }
    // A restriction swaps no root, but a directory descriptor still hands the
    // command a directory it could list whatever Landlock grants, so every
    // launch refuses one, as a sandbox's does.
    let dir = scratch("restrict-stream-directory");
    let directory = std::fs::File::open(&dir).expect("the scratch directory opens");
    let restriction = Restriction::builder()
        .command("/bin/true")
        .seccomp(SeccompPolicy::Curated)
        .stdin(Stdio::from_fd(directory.into()))
        .build()
        .expect("a stream is judged at the launch, not at build");
    match restriction.run() {
        Err(Error::StreamIsDirectory { stream, .. }) => assert_eq!(stream, "standard input"),
        other => panic!("a directory on standard input was not refused: {other:?}"),
    }
}

#[test]
fn landlock_allows_a_granted_path_and_denies_the_rest() {
    if !common::landlock() {
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

#[test]
fn a_restriction_grant_follows_a_host_link() {
    if !common::landlock() {
        return;
    }
    // A restriction's grants are host paths, resolved as the host resolves
    // them: a grant naming a link covers what the link points at, as a grant on
    // a merged-/usr host's `/lib` covers `/usr/lib`.
    let tree = scratch("restrict-link");
    std::fs::create_dir(tree.join("real")).unwrap();
    std::fs::write(tree.join("real/file"), "through the link\n").unwrap();
    std::os::unix::fs::symlink("real", tree.join("link")).unwrap();
    let output = grant_system_trees(Restriction::builder())
        .command("/bin/cat")
        .arg(tree.join("real/file"))
        .landlock_fs(FsAccess::READ, tree.join("link"))
        .build()
        .expect("a valid restriction configuration")
        .output()
        .expect("the restriction launches");
    assert!(
        output.status.success(),
        "a grant through a host link must cover its target: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"through the link\n");
}

#[test]
fn landlock_net_gates_a_tcp_connection() {
    if !common::landlock_net() {
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
        common::require::LANDLOCK.skip("no nc on this host to make the connection with");
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
    if !common::landlock() {
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
    if !common::seccomp() {
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
    if !common::seccomp() {
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
    if !common::seccomp() {
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
    if !common::seccomp() {
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
    if !common::seccomp() {
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
    if !common::seccomp() {
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
    if !common::seccomp() {
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
    if !common::seccomp() {
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
    if !common::seccomp() {
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
    if !common::seccomp() {
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
fn the_restrictions_supervisor_outlives_the_signals_sent_to_its_group() {
    if !common::seccomp() {
        return;
    }
    // A restriction's command is supervised from outside by the launch stage,
    // an ordinary member of the caller's process group, where a terminal's
    // interrupt and a shell's `kill %1` reach it alike. None of them may end
    // it: the outcome would be lost, and a command in a session of its own
    // would run on unsupervised.
    let mut running = Restriction::builder()
        .command("/bin/sh")
        .args(["-c", "sleep 1; exit 7"])
        .seccomp(SeccompPolicy::Curated)
        .stdin(Stdio::Null)
        .build()
        .expect("a valid restriction configuration")
        .spawn()
        .expect("the restriction launches");
    let status = std::fs::read_to_string(format!("/proc/{}/status", running.pid()))
        .expect("the command is alive");
    let launch_stage = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|parent| parent.trim().parse().ok())
        .and_then(rustix::process::Pid::from_raw)
        .expect("the command has a parent");
    for signal in common::GROUP_SIGNALS {
        rustix::process::kill_process(launch_stage, signal)
            .expect("the launch stage is alive to be signalled");
    }
    match running.wait_timeout(Duration::from_secs(30)) {
        Ok(Some(status)) => assert_eq!(status.code(), Some(7)),
        other => {
            let _ = running.kill();
            panic!("the outcome was not collected: {other:?}");
        }
    }
}

#[test]
fn landlock_grants_a_single_file_and_a_device_node() {
    if !common::landlock() {
        return;
    }
    // A grant on a file and a grant on a device node, rather than on the
    // directories that hold them: `--landlock-ro` on one file and
    // `--landlock-rw /dev/null`. Each lowers to rights that act on a
    // directory's entries as well, which the kernel refuses on anything else,
    // so the grant narrows to the rights a file accepts.
    let dir = scratch("restrict-file-grant");
    let (granted, neighbour) = (dir.join("granted"), dir.join("neighbour"));
    std::fs::write(&granted, "granted contents\n").unwrap();
    std::fs::write(&neighbour, "neighbour contents\n").unwrap();
    let output = grant_system_trees(Restriction::builder())
        .command("/bin/sh")
        .args([
            "-c",
            r#"cat "$1" && echo written >/dev/null && ! cat "$2" 2>/dev/null"#,
            "sh",
        ])
        .arg(&granted)
        .arg(&neighbour)
        .landlock_fs(FsAccess::READ, &granted)
        .landlock_fs(FsAccess::READ | FsAccess::WRITE, "/dev/null")
        .build()
        .expect("a valid restriction configuration")
        .output()
        .expect("the restriction launches");
    assert!(
        output.status.success(),
        "the granted file and device are reachable and nothing beside them is: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(output.stdout, b"granted contents\n");
}

#[test]
fn a_landlock_rule_that_fails_names_its_grant() {
    if !common::landlock() {
        return;
    }
    // Nothing checks a grant's path at build, so a missing one fails the launch.
    // The failure names the grant rather than only the step that refused it.
    let result = grant_system_trees(Restriction::builder())
        .command("/bin/true")
        .landlock_fs(
            FsAccess::READ | FsAccess::WRITE,
            "/ferroday-cage/no/such/grant",
        )
        .build()
        .expect("a valid restriction configuration")
        .run();
    match result {
        Err(Error::Setup {
            step: SetupStep::LandlockAddRule,
            detail,
            source,
            ..
        }) => {
            assert_eq!(
                detail.as_deref(),
                Some("rw on /ferroday-cage/no/such/grant")
            );
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound, "{source}");
        }
        other => panic!("expected a Landlock rule failure, got {other:?}"),
    }
}

/// Runs `script` under `/bin/sh` in a restriction confined by the curated
/// seccomp policy alone, with `scopes` in place of the default, and reports
/// whether it succeeded.
///
/// No Landlock grant is made, so any Landlock domain the command runs in is the
/// one its scopes alone create.
fn run_scoped(script: &str, scopes: Option<&[LandlockScope]>) -> bool {
    let builder = Restriction::builder()
        .command("/bin/sh")
        .args(["-c", script])
        .seccomp(SeccompPolicy::Curated);
    let builder = match scopes {
        Some(scopes) => builder.landlock_scope(scopes.iter().copied()),
        None => builder,
    };
    builder
        .build()
        .expect("a valid restriction configuration")
        .run()
        .expect("the restriction launches")
        .success()
}

#[test]
fn a_restriction_cannot_signal_a_process_outside_it() {
    if !common::seccomp() || !common::landlock_scope() {
        return;
    }
    // A restriction shares the host's PID space and runs as the calling user,
    // so without the signal scope it may signal every process that user owns.
    // The probe is signal 0, which asks the kernel for the permission check
    // alone.
    let mut victim = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a process to signal");
    let probe = format!("kill -0 {}", victim.id());
    let by_default = run_scoped(&probe, None);
    let unscoped = run_scoped(&probe, Some(&[]));
    let _ = victim.kill();
    let _ = victim.wait();
    assert!(
        !by_default,
        "the default scopes deny signalling the caller's process"
    );
    assert!(unscoped, "without the scope the same probe reaches it");
}

#[test]
fn a_restriction_cannot_reach_an_abstract_socket_outside_it() {
    if !common::seccomp() || !common::landlock_scope() {
        return;
    }
    let Some(python) = ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| Path::new(path).exists())
    else {
        common::require::LANDLOCK_SCOPE.skip("no python3 on this host to make the connection with");
        return;
    };
    // An abstract socket belongs to the network namespace, not the filesystem,
    // and a restriction shares the caller's. The listener is this test's, so it
    // is outside the restriction's domain.
    use std::os::linux::net::SocketAddrExt;
    let name = format!("ferroday-cage-scope-{}", std::process::id());
    let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
        .expect("an abstract address");
    let _listener =
        std::os::unix::net::UnixListener::bind_addr(&address).expect("an abstract listener");
    let probe = format!(
        "{python} -c 'import socket; socket.socket(socket.AF_UNIX).connect(\"\\0{name}\")'"
    );
    assert!(
        !run_scoped(&probe, None),
        "the default scopes deny connecting to the caller's abstract socket"
    );
    assert!(
        run_scoped(&probe, Some(&[])),
        "without the scope the same connect reaches it"
    );
}

#[test]
fn a_scoped_restriction_cannot_read_an_outside_process_environment() {
    if !common::seccomp() || !common::landlock_scope() {
        return;
    }
    // Any Landlock domain refuses the ptrace access checks on a process outside
    // it, and reading another process's environment is one. On a kernel with
    // scopes, a restriction always has a domain, even when it makes no grant.
    let probe = format!("cat /proc/{}/environ >/dev/null", std::process::id());
    assert!(
        !run_scoped(&probe, None),
        "the scoped restriction is refused the caller's environment"
    );
    assert!(
        run_scoped(&probe, Some(&[])),
        "a restriction with no Landlock domain reads it"
    );
}

#[test]
fn a_syscall_answered_with_its_own_errno_reports_it() {
    if !common::seccomp() {
        return;
    }
    let Some(python) = ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| Path::new(path).exists())
    else {
        common::require::SECCOMP.skip("no python3 on this host to make the calls with");
        return;
    };
    // `clone3` answered `ENOSYS` beside a denylist whose listed action is
    // `EPERM`. Each call is made raw and reports the errno it got: `clone3`
    // with no arguments would be `EINVAL` from the kernel itself, so `ENOSYS`
    // can only be the filter's. A thread then starts all the same, because the
    // C library reads `ENOSYS` from `clone3` as an older kernel and falls back
    // to `clone`.
    let script = format!(
        "import ctypes, threading; libc = ctypes.CDLL(None, use_errno=True); \
         libc.syscall({clone3}, 0, 0); print(ctypes.get_errno()); \
         libc.syscall({acct}, 0); print(ctypes.get_errno()); \
         t = threading.Thread(target=int); t.start(); t.join(); print('thread')",
        clone3 = libc::SYS_clone3,
        acct = libc::SYS_acct,
    );
    let rules =
        SeccompRules::denying([libc::SYS_acct]).errno_for(libc::SYS_clone3, libc::ENOSYS as u16);
    let output = Restriction::builder()
        .command(python)
        .args(["-c", &script])
        .seccomp(SeccompPolicy::Rules(rules))
        .build()
        .expect("a valid restriction configuration")
        .output()
        .expect("the restriction launches");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{}\n{}\nthread\n", libc::ENOSYS, libc::EPERM),
    );
}

#[test]
fn the_curated_policy_denies_a_namespace_and_starts_threads_and_processes() {
    if !common::seccomp() {
        return;
    }
    let Some(python) = ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| Path::new(path).exists())
    else {
        common::require::SECCOMP.skip("no python3 on this host to make the calls with");
        return;
    };
    // A host binary linked against the host's C library, which starts a thread
    // with `clone3` and falls back to `clone` on `ENOSYS`. Each `unshare`
    // reports the errno it got, and so does a raw `clone3`, which the kernel
    // itself answers `EINVAL` for its empty arguments. The thread and the
    // forked process report that they ran. Unsharing the descriptor table is
    // not a namespace, so it stays allowed.
    let script = format!(
        "import ctypes, os, threading; libc = ctypes.CDLL(None, use_errno=True); \
         print(ctypes.get_errno() if libc.unshare({newuser}) else 0); \
         print(ctypes.get_errno() if libc.unshare({files}) else 0); \
         libc.syscall({clone3}, 0, 0); print(ctypes.get_errno()); \
         t = threading.Thread(target=int); t.start(); t.join(); print('thread'); \
         pid = os.fork(); pid or os._exit(0); os.waitpid(pid, 0); print('fork')",
        newuser = libc::CLONE_NEWUSER,
        files = libc::CLONE_FILES,
        clone3 = libc::SYS_clone3,
    );
    let run = |policy: SeccompPolicy| {
        let output = Restriction::builder()
            .command(python)
            .args(["-c", &script])
            .seccomp(policy)
            .build()
            .expect("a valid restriction configuration")
            .output()
            .expect("the restriction launches");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    assert_eq!(
        run(SeccompPolicy::Curated),
        format!("{}\n0\n{}\nthread\nfork\n", libc::EPERM, libc::ENOSYS),
    );
    // Where the host lets an unprivileged process create a user namespace, the
    // same script under a policy without the rules creates one, which pins the
    // refusals above on the curated policy rather than on the host.
    if common::require::userns() {
        let control = SeccompRules::denying([libc::SYS_acct]);
        assert_eq!(
            run(SeccompPolicy::Rules(control)),
            format!("0\n0\n{}\nthread\nfork\n", libc::EINVAL),
        );
    }
}

#[test]
fn a_missing_command_is_an_exec_setup_error() {
    if !common::seccomp() {
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
    if !common::seccomp() {
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
        common::require::SECCOMP.skip("no shell on this host");
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
    if !common::seccomp() {
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
        common::require::SECCOMP.skip("no shell on this host");
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
    if !common::seccomp() {
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
