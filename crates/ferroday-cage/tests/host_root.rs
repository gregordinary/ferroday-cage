//! Integration tests for the host's own root: the host's tree, read-only, with
//! the paths it hides by default, and the two mount kinds that take something
//! away on any root, a hidden path and a path made read-only.
//!
//! The command is the host's own `/bin/sh`, so no fixture root is needed.

mod common;

use common::Collect;

use std::path::Path;

use ferroday_cage::{Cage, CageBuilder, ConfigError, Error, ResolvedMount, ResolvedRoot};

/// Runs `script` under `builder`'s sandbox with `/bin/sh`, its errors folded
/// into its output, and returns whether it exited cleanly and what it printed.
fn run(builder: CageBuilder, script: &str) -> (bool, String) {
    let mut observer = Collect::default();
    let status = builder
        .command("/bin/sh")
        .args(["-c", &format!("exec 2>&1; {script}")])
        .build()
        .expect("a valid sandbox configuration")
        .run_with(&mut observer)
        .expect("the sandbox runs");
    (
        status.success(),
        String::from_utf8_lossy(&observer.stdout).into_owned(),
    )
}

#[test]
fn the_host_s_files_are_read_and_written_nowhere_but_the_sandbox_s_own() {
    if !common::require::userns() {
        return;
    }
    let work = common::scratch_dir("host-root-writes");
    let place = work.to_str().expect("a UTF-8 scratch path");
    let (ok, printed) = run(
        Cage::builder().host_rootfs().bind(&work, &work),
        &format!(
            "test -r /etc/passwd && echo read; \
             touch /etc/written || echo etc refused; \
             touch /usr/written || echo usr refused; \
             touch /tmp/written && echo tmp written; \
             touch {place}/written && echo bind written"
        ),
    );
    assert!(ok, "{printed}");
    for line in [
        "read",
        "etc refused",
        "usr refused",
        "tmp written",
        "bind written",
    ] {
        assert!(printed.contains(line), "{line:?} missing from {printed}");
    }
    assert!(
        printed.contains("Read-only file system"),
        "a write to the host's tree is EROFS: {printed}"
    );
    assert!(work.join("written").is_file(), "the bind is writable");
    assert!(!Path::new("/etc/written").exists());
}

#[test]
fn the_default_hides_leave_the_host_s_homes_and_sockets_out() {
    if !common::require::userns() {
        return;
    }
    let (ok, printed) = run(
        Cage::builder().host_rootfs(),
        "for path in /home /root /run /var/tmp; do \
             echo \"$path: $(ls -A $path | wc -l)\"; \
         done; \
         touch /run/written || echo run refused",
    );
    assert!(ok, "{printed}");
    for path in ["/home", "/root", "/run", "/var/tmp"] {
        assert!(
            printed.contains(&format!("{path}: 0")),
            "{path} is not empty: {printed}"
        );
    }
    assert!(printed.contains("run refused"), "{printed}");

    // The session bus, where the host has one, is among what /run held.
    if let Some(bus) = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|dir| Path::new(&dir).join("bus"))
        .filter(|bus| bus.exists())
    {
        let bus = bus.to_str().expect("a UTF-8 bus path").to_owned();
        let (ok, printed) = run(
            Cage::builder().host_rootfs(),
            &format!("test -e {bus} && echo bus visible || echo bus hidden"),
        );
        assert!(ok, "{printed}");
        assert!(printed.contains("bus hidden"), "{printed}");
    }
}

#[test]
fn a_default_hide_is_listed_and_one_taken_back_shows_the_host_s_own() {
    if !common::require::userns() {
        return;
    }
    let hides = |builder: CageBuilder| -> Vec<String> {
        builder
            .command("/bin/true")
            .build()
            .expect("a valid sandbox configuration")
            .resolved_inputs()
            .mounts
            .into_iter()
            .filter_map(|mount| match mount {
                ResolvedMount::Hide { target, .. } => Some(target.display().to_string()),
                _ => None,
            })
            .collect()
    };
    assert_eq!(
        hides(Cage::builder().host_rootfs()),
        ["/home", "/root", "/run", "/var/run", "/var/tmp"]
    );
    assert_eq!(
        hides(Cage::builder().host_rootfs().reveal("/var/tmp")),
        ["/home", "/root", "/run", "/var/run"]
    );
    // Opting out of the managed profile takes them with it; the procfs the
    // command's nested namespace needs is then the profile's own.
    assert!(
        hides(
            Cage::builder()
                .host_rootfs()
                .managed_mounts(false)
                .raw_mount(ferroday_cage::RawMount::new("/proc").fstype("proc"))
        )
        .is_empty()
    );
    assert_eq!(
        Cage::builder()
            .host_rootfs()
            .command("/bin/true")
            .build()
            .expect("a valid sandbox configuration")
            .resolved_inputs()
            .root,
        ResolvedRoot::HostReadOnly
    );

    let (ok, printed) = run(
        Cage::builder().host_rootfs().reveal("/var/tmp"),
        "ls -A /var/tmp | wc -l",
    );
    assert!(ok, "{printed}");
    let host = std::fs::read_dir("/var/tmp").map_or(0, |entries| entries.count());
    assert_eq!(printed.trim(), host.to_string());
}

#[test]
fn a_path_not_hidden_by_default_is_not_taken_back() {
    for builder in [
        Cage::builder().host_rootfs().reveal("/etc"),
        Cage::builder().empty_rootfs().reveal("/run"),
    ] {
        match builder.command("/bin/true").build() {
            Err(Error::Config(ConfigError::RevealUnhidden { .. })) => {}
            other => panic!("a reveal of nothing hidden: {other:?}"),
        }
    }
}

#[test]
fn a_missing_mount_target_is_refused_at_build_and_nothing_is_created() {
    // A target outside every filesystem the sandbox mounts: a scratch
    // directory would not do, since it sits under `/tmp` or `/home`.
    let work = common::scratch_dir("host-root-missing");
    let target = Path::new("/etc/ferroday-cage-test/missing").to_path_buf();
    match Cage::builder()
        .host_rootfs()
        .bind(&work, &target)
        .command("/bin/true")
        .build()
    {
        Err(Error::Config(ConfigError::MountTargetMissing { target: at, .. })) => {
            assert_eq!(at, target);
        }
        other => panic!("a missing bind target on the host's root: {other:?}"),
    }
    assert!(!target.exists());
    // Beneath a filesystem the sandbox mounts, the same target is created
    // there, and nothing reaches the host.
    if !common::require::userns() {
        return;
    }
    let (ok, printed) = run(
        Cage::builder()
            .host_rootfs()
            .bind(&work, "/tmp/made/for/the/bind"),
        "test -d /tmp/made/for/the/bind && echo made",
    );
    assert!(ok && printed.contains("made"), "{printed}");
}

#[test]
fn a_hidden_directory_is_empty_and_read_only_and_a_mount_still_lands_beneath_it() {
    if !common::require::userns() {
        return;
    }
    let work = common::scratch_dir("host-root-hide-dir");
    let secrets = work.join("secrets");
    std::fs::create_dir_all(secrets.join("deep")).unwrap();
    std::fs::write(secrets.join("token"), b"secret\n").unwrap();
    let kept = common::scratch_dir("host-root-hide-dir-kept");
    std::fs::write(kept.join("note"), b"kept\n").unwrap();
    let place = secrets.to_str().expect("a UTF-8 scratch path");
    let (ok, printed) = run(
        Cage::builder()
            .host_rootfs()
            .bind(&work, &work)
            .hide(&secrets)
            .bind(&kept, secrets.join("kept")),
        &format!("ls -A {place}; touch {place}/written || echo refused; cat {place}/kept/note"),
    );
    assert!(ok, "{printed}");
    assert!(
        !printed.contains("token") && !printed.contains("deep"),
        "{printed}"
    );
    assert!(printed.contains("refused"), "{printed}");
    assert!(printed.contains("kept"), "{printed}");
    assert!(
        secrets.join("token").is_file(),
        "the host's file is untouched"
    );
}

#[test]
fn a_hidden_file_reads_empty_and_refuses_a_write_with_erofs() {
    if !common::require::userns() {
        return;
    }
    let work = common::scratch_dir("host-root-hide-file");
    let env = work.join(".env");
    std::fs::write(&env, b"API_KEY=secret\n").unwrap();
    let place = env.to_str().expect("a UTF-8 scratch path");
    for builder in [
        Cage::builder().host_rootfs().bind(&work, &work),
        common::host_userland().bind(&work, &work),
    ] {
        let (ok, printed) = run(
            builder.hide(&env),
            &format!(
                "test -f {place} && echo regular; \
                 echo \"size $(wc -c < {place})\"; \
                 echo overwritten > {place} || echo refused"
            ),
        );
        assert!(ok, "{printed}");
        assert!(printed.contains("regular"), "{printed}");
        assert!(printed.contains("size 0"), "{printed}");
        assert!(printed.contains("Read-only file system"), "{printed}");
        assert_eq!(std::fs::read(&env).unwrap(), b"API_KEY=secret\n");
    }
}

#[test]
fn a_missing_hidden_path_hides_nothing() {
    if !common::require::userns() {
        return;
    }
    let (ok, printed) = run(
        Cage::builder().host_rootfs().hide("/no/such/path/anywhere"),
        "echo ran",
    );
    assert!(ok && printed.contains("ran"), "{printed}");
}

#[test]
fn a_read_only_path_refuses_writes_inside_a_writable_bind() {
    if !common::require::userns() {
        return;
    }
    let work = common::scratch_dir("host-root-read-only");
    std::fs::create_dir_all(work.join(".git/hooks")).unwrap();
    let place = work.to_str().expect("a UTF-8 scratch path");
    for builder in [Cage::builder().host_rootfs(), common::host_userland()] {
        let (ok, printed) = run(
            builder
                .bind(&work, &work)
                .read_only(work.join(".git/hooks")),
            &format!(
                "touch {place}/.git/hooks/pre-commit || echo hooks refused; \
                 touch {place}/written && echo tree written"
            ),
        );
        assert!(ok, "{printed}");
        assert!(printed.contains("hooks refused"), "{printed}");
        assert!(printed.contains("tree written"), "{printed}");
        assert!(!work.join(".git/hooks/pre-commit").exists());
    }

    // A path made read-only that is not there fails the launch, rather than
    // leaving a path the command could create.
    let result = Cage::builder()
        .host_rootfs()
        .bind(&work, &work)
        .read_only(work.join("absent"))
        .command("/bin/true")
        .build()
        .expect("a valid sandbox configuration")
        .run();
    assert!(
        matches!(
            result,
            Err(Error::Setup {
                step: ferroday_cage::SetupStep::OpenMountTarget,
                ..
            })
        ),
        "{result:?}"
    );
}

/// Set inside the sandbox to make [`probe_unix_connect`] connect rather than
/// return: the socket paths to connect to, joined as a `PATH` is.
#[cfg(feature = "hardening")]
const PROBE: &str = "FERRODAY_CAGE_TEST_UNIX_SOCKET_PROBE";

/// Where the test binary is bound inside the sandbox: inside the managed
/// `/tmp`, where the host's own root lets a target be made.
#[cfg(feature = "hardening")]
const PROBE_PATH: &str = "/tmp/probe";

/// Inside the sandbox: connects to each socket the outer test named, then to
/// one this process created itself, and prints what each connection met.
#[cfg(feature = "hardening")]
#[test]
fn probe_unix_connect() {
    use std::os::unix::net::{UnixListener, UnixStream};

    let Some(paths) = std::env::var_os(PROBE) else {
        return;
    };
    println!();
    let outcome = |path: &Path| match UnixStream::connect(path) {
        Ok(_) => "ok".to_string(),
        Err(err) => format!("errno {}", err.raw_os_error().unwrap_or(0)),
    };
    for path in std::env::split_paths(&paths) {
        println!("connect {} {}", path.display(), outcome(&path));
    }
    let own = Path::new("/tmp/own.sock");
    let _listener = UnixListener::bind(own).expect("the probe's own socket binds");
    println!("connect own {}", outcome(own));
    println!("probe done");
}

/// Runs [`probe_unix_connect`] in `builder`'s sandbox, which binds `sockets`
/// at `/tmp/s`, and returns each connection's outcome, by the path inside the
/// sandbox, or `own` for the probe's own socket.
#[cfg(feature = "hardening")]
fn probe_connections(
    builder: CageBuilder,
    sockets: &Path,
) -> std::collections::BTreeMap<String, String> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let output = builder
        .bind(sockets, "/tmp/s")
        .bind_ro(&exe, PROBE_PATH)
        .command(PROBE_PATH)
        .args([
            "--exact",
            "probe_unix_connect",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE, "/tmp/s/granted/sock:/tmp/s/other/sock")
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("probe done"),
        "the probe did not report:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("connect "))
        .map(|line| {
            let (path, outcome) = line.split_once(' ').expect("a path and an outcome");
            (path.to_string(), outcome.to_string())
        })
        .collect()
}

/// A scratch directory holding a listening socket in `granted/` and another in
/// `other/`, made through this process's descriptor for the directory so the
/// sockets' paths fit a socket address however deep the fixture cache sits.
#[cfg(feature = "hardening")]
fn listening_sockets(
    name: &str,
) -> (
    std::path::PathBuf,
    std::fs::File,
    [std::os::unix::net::UnixListener; 2],
) {
    use std::os::fd::AsRawFd as _;

    let dir = common::scratch_dir(name);
    let handle = std::fs::File::open(&dir).expect("the scratch directory opens");
    let listen = |sub: &str| {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
        let short = format!("/proc/self/fd/{}/{sub}/sock", handle.as_raw_fd());
        std::os::unix::net::UnixListener::bind(short).expect("the socket binds")
    };
    let listeners = [listen("granted"), listen("other")];
    (dir, handle, listeners)
}

/// Whether the kernel's Landlock ABI has the unix-socket right, reporting the
/// skip where it does not. No variable governs it: CI's kernels predate it.
#[cfg(feature = "hardening")]
fn landlock_resolve_unix() -> bool {
    let abi = ferroday_cage::host::landlock_abi();
    let present = abi.is_some_and(|abi| abi >= 9);
    if !present {
        common::require::premise_unmet(format_args!(
            "the unix-socket restriction needs Landlock ABI 9, and the kernel offers {abi:?}"
        ));
    }
    present
}

#[cfg(feature = "hardening")]
#[test]
fn the_unix_socket_restriction_refuses_a_host_socket_and_admits_a_granted_one() {
    use ferroday_cage::FsAccess;

    if !common::require::userns() || !landlock_resolve_unix() {
        return;
    }
    let (dir, _handle, _listeners) = listening_sockets("host-root-unix-sockets");
    // On by default under the host's own root, asked for on an empty root.
    for builder in [
        Cage::builder().host_rootfs(),
        common::host_userland().landlock_resolve_unix(true),
    ] {
        let seen = probe_connections(
            builder.landlock_fs(FsAccess::RESOLVE_UNIX, "/tmp/s/granted"),
            &dir,
        );
        assert_eq!(seen["/tmp/s/granted/sock"], "ok", "{seen:?}");
        assert_eq!(seen["/tmp/s/other/sock"], "errno 13", "{seen:?}");
        assert_eq!(seen["own"], "ok", "{seen:?}");
    }
    // Turned off, every socket in view answers.
    let seen = probe_connections(
        Cage::builder().host_rootfs().landlock_resolve_unix(false),
        &dir,
    );
    assert_eq!(seen["/tmp/s/other/sock"], "ok", "{seen:?}");
    let report = Cage::builder()
        .host_rootfs()
        .command("/bin/true")
        .build()
        .expect("a valid sandbox configuration")
        .resolved_inputs()
        .hardening;
    assert!(
        matches!(
            report,
            ferroday_cage::ResolvedHardening::Applied {
                landlock_resolve_unix: true,
                ..
            }
        ),
        "{report:?}"
    );
}
