//! Integration tests for identity maps, the run-as identity, and the presented
//! identity.
//!
//! The tests assert the observable consequence rather than the mechanism:
//! under a range map, `chown` to a non-root id succeeds where the
//! single-identity map answers `EINVAL`, a run-as identity is what `id`
//! reports from inside, and a presented identity is what the command sees of
//! itself while the host still sees the caller. Range-map tests skip explicitly on hosts where
//! no delegate is available, as the network-stack tests do for
//! `/dev/net/tun`; the nested direct-tier test additionally needs a host
//! `unshare` that can establish a subordinate-backed namespace to nest in.
//!
//! Every range-map skip here goes through `require::SUBID`, whatever its
//! cause: no delegate at all, an allocation the files do not state, one too
//! small to carry the map a test needs, or a util-linux without `--map-users`.
//! `FERRODAY_CAGE_REQUIRE_SUBID` turns each of them into a failure, not only
//! the first: a runner whose allocation is a single 65536-id block satisfies
//! the delegate check and still cannot nest, so gating only that one would let
//! tests quietly stop running while the guarded run stayed green.

mod common;

use std::path::Path;

use ferroday_cage::{Cage, Identity, Output, PresentedIdentity, Terminal};
// Identity maps and the run-as identity are exercised only by the range-map
// tests, all of which are gated on the `subid` delegate.
#[cfg(feature = "subid")]
use ferroday_cage::{IdRange, IdentityMap};

/// The fixture rootfs, or `None` when the sandbox tests should skip.
fn rootfs() -> Option<&'static Path> {
    common::fixture_rootfs()
}

/// The size of the caller's subordinate uid allocation, when `/etc/subuid`
/// states it plainly.
///
/// Used only to decide whether a nested test can fit inside the allocation,
/// never to build a map: `unshare --map-auto` reads the allocation itself,
/// through the same NSS-aware path the shadow helpers use. This is the
/// cheaper question of whether the allocation is large enough to bother
/// trying, so an allocation this cannot see — one a directory service
/// provides rather than the file — returns `None` and the caller proceeds
/// rather than skipping.
#[cfg(feature = "subid")]
fn subordinate_uid_count() -> Option<u32> {
    subordinate_allocation("/etc/subuid").map(|(_start, count)| count)
}

/// The caller's first subordinate allocation in `path`, as `(start, count)`.
///
/// Reads the file directly, which is enough for a test to compose a request
/// the delegate will then accept on its own terms. An allocation the file does
/// not state — one a directory service provides — returns `None`, and the
/// caller skips rather than guessing at ids it has no claim to.
#[cfg(feature = "subid")]
fn subordinate_allocation(path: &str) -> Option<(u32, u32)> {
    let id = rustix::process::getuid().as_raw().to_string();
    let name = std::env::var("USER").ok();
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|line| {
        let mut fields = line.trim().splitn(3, ':');
        let owner = fields.next()?;
        let start = fields.next()?.parse().ok()?;
        let count = fields.next()?.parse().ok()?;
        let mine = owner == id || name.as_deref().is_some_and(|name| owner == name);
        mine.then_some((start, count))
    })
}

/// Runs a shell script in the cage, capturing its output.
fn run_script(cage: &Cage) -> Output {
    cage.output().expect("the sandbox should launch")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The whitespace-separated fields after `prefix`, on the first line of
/// `stdout` that starts with it. `/proc/self/status` lines and the
/// `label value...` lines a test script echoes both read this way.
fn fields<'a>(stdout: &'a str, prefix: &str) -> Vec<&'a str> {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .map(|rest| rest.split_whitespace().collect())
        .unwrap_or_default()
}

/// A presented identity, in the ids the tests below expect to read back. The
/// uid and gid differ, so a swap between them shows.
const PRESENTED: PresentedIdentity = PresentedIdentity::ids(1000, 100);

/// A presented identity is what the command observes of itself, and the one
/// extent its namespace maps is the caller as that identity. Nothing maps 0.
#[test]
fn a_presented_identity_is_what_the_command_observes() {
    let Some(rootfs) = rootfs() else { return };
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "grep -E '^(Uid|Gid):' /proc/self/status; \
             echo uid_map $(cat /proc/self/uid_map); \
             echo gid_map $(cat /proc/self/gid_map)",
        ])
        .present_as(PRESENTED)
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    assert_eq!(fields(&stdout, "Uid:"), ["1000"; 4], "{stdout}");
    assert_eq!(fields(&stdout, "Gid:"), ["100"; 4], "{stdout}");
    assert_eq!(fields(&stdout, "uid_map"), ["1000", "0", "1"], "{stdout}");
    assert_eq!(fields(&stdout, "gid_map"), ["100", "0", "1"], "{stdout}");
}

/// The command holds no capability across its `execve`, with no-new-privileges
/// set, though nothing but the presented identity was asked for.
#[test]
fn a_presented_identity_holds_no_capability() {
    let Some(rootfs) = rootfs() else { return };
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "grep -E '^(CapEff|CapPrm|CapAmb|NoNewPrivs):' /proc/self/status",
        ])
        .present_as(PRESENTED)
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    for prefix in ["CapEff:", "CapPrm:", "CapAmb:"] {
        let value = fields(&stdout, prefix).first().copied().unwrap_or("");
        assert_eq!(
            u64::from_str_radix(value, 16).unwrap_or(u64::MAX),
            0,
            "{prefix} should be empty: {stdout}"
        );
    }
    assert_eq!(fields(&stdout, "NoNewPrivs:"), ["1"], "{stdout}");
}

/// The presentation changes the command's view, not who it is: a directory the
/// caller owns reads as the presented identity's, and what the command writes
/// there is the caller's on the host.
#[test]
fn a_presented_identity_owns_and_writes_as_the_caller() {
    use std::os::unix::fs::MetadataExt;

    let Some(rootfs) = rootfs() else { return };
    let out = common::scratch_dir("identity-presented-out");
    let cage = Cage::builder()
        .rootfs(rootfs)
        .bind(&out, "/out")
        .command("/bin/sh")
        .args([
            "-c",
            "echo owner $(stat -c '%u %g' /out); touch /out/written",
        ])
        .present_as(PRESENTED)
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    assert_eq!(fields(&stdout, "owner"), ["1000", "100"], "{stdout}");
    let written = std::fs::metadata(out.join("written")).expect("the command wrote the file");
    assert_eq!(written.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(written.gid(), rustix::process::getegid().as_raw());
}

/// `own` presents the caller as the ids the host knows it by.
#[test]
fn own_presents_the_callers_host_ids() {
    let Some(rootfs) = rootfs() else { return };
    if rustix::process::geteuid().is_root() {
        // The build refuses a presented uid of 0, which the unit tests cover.
        common::require::premise_unmet("the caller is root, whose own uid is never presented");
        return;
    }
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "grep -E '^(Uid|Gid):' /proc/self/status"])
        .present_as(PresentedIdentity::Own)
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    let uid = rustix::process::geteuid().as_raw().to_string();
    let gid = rustix::process::getegid().as_raw().to_string();
    assert_eq!(fields(&stdout, "Uid:"), [uid.as_str(); 4], "{stdout}");
    assert_eq!(fields(&stdout, "Gid:"), [gid.as_str(); 4], "{stdout}");
}

/// A run-as identity naming the presented identity launches, and switches
/// nothing: the command is that identity either way.
#[test]
fn run_as_the_presented_identity_launches() {
    let Some(rootfs) = rootfs() else { return };
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "grep -E '^(Uid|Gid):' /proc/self/status"])
        .present_as(PRESENTED)
        .run_as(Identity::new(1000, 100))
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    assert_eq!(fields(&stdout, "Uid:"), ["1000"; 4], "{stdout}");
    assert_eq!(fields(&stdout, "Gid:"), ["100"; 4], "{stdout}");
}

/// The same combination on a terminal of the sandbox's own. The replica is the
/// command's without a change of owner: the sandbox's namespace maps no id but
/// its root, which the replica belongs to, and the command's map presents that
/// root as the presented identity.
#[test]
fn run_as_the_presented_identity_launches_on_a_terminal() {
    use std::io::Read as _;

    let Some(rootfs) = rootfs() else { return };
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "grep -E '^(Uid|Gid):' /proc/self/status; echo tty $(stat -c '%u %g' $(tty))",
        ])
        .present_as(PRESENTED)
        .run_as(Identity::new(1000, 100))
        .build()
        .expect("the sandbox should build");
    let (mut running, mut pty) = cage
        .spawn_terminal(&Terminal::new())
        .expect("the sandbox should launch on a terminal");
    let mut written = Vec::new();
    pty.read_to_end(&mut written)
        .expect("the terminal drains to its end");
    let status = running.wait().expect("the outcome is collected");
    let stdout = String::from_utf8_lossy(&written);
    assert!(status.success(), "{status}: {stdout}");
    assert_eq!(fields(&stdout, "Uid:"), ["1000"; 4], "{stdout}");
    assert_eq!(fields(&stdout, "Gid:"), ["100"; 4], "{stdout}");
    assert_eq!(fields(&stdout, "tty"), ["1000", "100"], "{stdout}");
}

/// A keep set carries its capabilities across the `execve` of a presented
/// identity, which runs non-root with no switch for the securebits to span:
/// the kept set is raised into the ambient set, which is what an exec of a
/// non-root command keeps.
#[cfg(feature = "hardening")]
#[test]
fn a_kept_capability_survives_a_presented_identitys_exec() {
    use ferroday_cage::Capability;

    let Some(rootfs) = rootfs() else { return };
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "grep -E '^(Uid|CapEff|CapAmb):' /proc/self/status"])
        .present_as(PRESENTED)
        .keep_capabilities([Capability::NetRaw])
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    assert_eq!(fields(&stdout, "Uid:"), ["1000"; 4], "{stdout}");
    // CAP_NET_RAW is capability 13.
    for prefix in ["CapEff:", "CapAmb:"] {
        let value = fields(&stdout, prefix).first().copied().unwrap_or("");
        assert_eq!(
            u64::from_str_radix(value, 16).unwrap_or(u64::MAX),
            1 << 13,
            "{prefix} should hold exactly CAP_NET_RAW: {stdout}"
        );
    }
}

/// The boundary the range map removes, asserted first: under the
/// single-identity map, `chown` to any other id cannot succeed, because the
/// namespace cannot represent the id.
#[test]
fn the_single_map_cannot_chown_to_another_id() {
    let Some(rootfs) = rootfs() else { return };
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "touch /tmp/probe; chown 250:250 /tmp/probe 2>/dev/null; echo rc=$?",
        ])
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("rc=1"),
        "chown unexpectedly succeeded: {stdout}"
    );
}

/// The motivating consequence: under a subordinate range map the same
/// `chown` genuinely succeeds, and the file's ownership reads back as the
/// non-root id.
#[cfg(feature = "subid")]
#[test]
fn a_range_map_makes_chown_to_a_nonroot_id_real() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "touch /tmp/probe && chown 250:250 /tmp/probe && stat -c %u:%g /tmp/probe",
        ])
        .identity_map(IdentityMap::Subordinate)
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(
        output.status.success(),
        "chown failed under the range map: {stdout} {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(stdout.contains("250:250"), "{stdout}");
}

/// Under a range map the sandbox holds a whole id space: ids beyond the
/// allocation still do not exist, and the failure stays typed.
#[cfg(feature = "subid")]
#[test]
fn ids_outside_the_allocation_stay_unrepresentable() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "touch /tmp/probe; chown 999999999:999999999 /tmp/probe 2>/dev/null; echo rc=$?",
        ])
        .identity_map(IdentityMap::Subordinate)
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("rc=1"), "{stdout}");
}

/// The run-as identity is what the command observes itself to be, groups
/// included, from its first instruction.
#[cfg(feature = "subid")]
#[test]
fn run_as_is_the_identity_the_command_observes() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "echo \"$(id -u) $(id -g) $(id -G)\""])
        .identity_map(IdentityMap::Subordinate)
        .run_as(Identity::new(250, 250).groups([250, 100]))
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    assert_eq!(stdout.trim(), "250 250 250 100", "{stdout}");
}

/// `HOME` follows the identity the command runs as: `/root` for root inside,
/// none from the library for a presented or a non-root run-as identity, and
/// the caller's own wherever the caller sets one.
#[test]
fn home_follows_the_identity_the_command_runs_as() {
    let Some(rootfs) = rootfs() else { return };
    let home = |builder: ferroday_cage::CageBuilder| {
        let cage = builder
            .rootfs(rootfs)
            .command("/bin/sh")
            .args(["-c", "echo \"home=${HOME-unset}\""])
            .build()
            .expect("the sandbox should build");
        let output = run_script(&cage);
        let stdout = stdout_of(&output);
        assert!(output.status.success(), "{stdout}");
        stdout.trim().to_string()
    };
    assert_eq!(home(Cage::builder()), "home=/root");
    assert_eq!(home(Cage::builder().present_as(PRESENTED)), "home=unset");
    assert_eq!(
        home(
            Cage::builder()
                .present_as(PRESENTED)
                .env("HOME", "/home/user")
        ),
        "home=/home/user"
    );
    #[cfg(feature = "subid")]
    if common::require::range_map() {
        assert_eq!(
            home(
                Cage::builder()
                    .identity_map(IdentityMap::Subordinate)
                    .run_as(Identity::new(250, 250))
            ),
            "home=unset"
        );
    }
}

/// The nested user namespace's map under the range tier: the whole of the
/// sandbox's map, reflected onto its own inside ids.
///
/// The command cannot write this for itself — the kernel's one-id exception
/// covers a single extent of the writer's own id and nothing richer — and
/// neither can the host caller, which owns the sandbox's user namespace but is
/// not inside it. It is written by the process that forked the command, which
/// is root of the namespace the nested one is a child of. That a run-as
/// identity with supplementary groups still works is the other half of the
/// assertion: a delegated map leaves `setgroups` at `allow`, where the
/// single-identity tier has to deny it.
#[cfg(feature = "subid")]
#[test]
fn a_delegated_nested_map_reflects_the_sandbox_map() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "cat /proc/self/uid_map | tr -s ' ' | tr '\\n' ';'; echo; id -u; id -G",
        ])
        .identity_map(IdentityMap::Subordinate)
        .run_as(Identity::new(250, 250).groups([250, 100]))
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    let mut lines = stdout.lines();
    let map = lines.next().unwrap_or_default();
    // The subordinate map is root plus the allocation, so its reflection is
    // `0 0 1` followed by one extent per allocated range, each naming its
    // inside ids on both sides. The allocation's own extents are the host's to
    // decide, so only the first is asserted exactly.
    assert!(
        map.starts_with(" 0 0 1;") && map.matches(';').count() >= 2,
        "expected a reflected multi-extent map, got {map:?}",
    );
    for extent in map.split(';').filter(|extent| !extent.trim().is_empty()) {
        let fields: Vec<&str> = extent.split_whitespace().collect();
        assert_eq!(
            fields.first(),
            fields.get(1),
            "an extent names different ids on the two sides: {extent:?}",
        );
    }
    assert_eq!(lines.next(), Some("250"), "{stdout}");
    assert_eq!(lines.next(), Some("250 100"), "{stdout}");
}

/// The lock a delegated nested map buys, which is the whole point of entering
/// the namespace: a read-only bind cannot be remounted read-write by the
/// sandbox's own root, and a write to it answers `EROFS`.
#[cfg(feature = "subid")]
#[test]
fn a_delegated_nested_map_locks_a_read_only_bind() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let host_dir = common::scratch_dir("ro-bind-locked-ranged");
    std::fs::write(host_dir.join("marker"), "present\n").unwrap();
    let cage = Cage::builder()
        .rootfs(rootfs)
        .bind_ro(&host_dir, "/mnt")
        .command("/bin/sh")
        .args([
            "-c",
            "! /bin/busybox mount -o remount,bind,rw /mnt 2>/dev/null && \
             ! echo scribbled > /mnt/marker 2>/dev/null",
        ])
        .identity_map(IdentityMap::Subordinate)
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    assert!(output.status.success(), "{}", stdout_of(&output));
    assert_eq!(
        std::fs::read_to_string(host_dir.join("marker")).unwrap(),
        "present\n",
        "the sandbox wrote through a read-only bind",
    );
}

/// Without a PID namespace the delegate is the launch stage rather than the
/// sandbox init, and it reaches the command's map files through the host's own
/// procfs; the two shapes must reach the same place.
#[cfg(feature = "subid")]
#[test]
fn a_delegated_nested_map_works_without_a_pid_namespace() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let cage = Cage::builder()
        .rootfs(rootfs)
        .pid_namespace(false)
        .command("/bin/sh")
        .args(["-c", "head -1 /proc/self/uid_map | tr -s ' '; id -u"])
        .identity_map(IdentityMap::Subordinate)
        .run_as(Identity::new(250, 250))
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    assert_eq!(stdout.lines().next(), Some(" 0 0 1"), "{stdout}");
    assert_eq!(stdout.lines().nth(1), Some("250"), "{stdout}");
}

/// A set-user-ID binary in the rootfs confers nothing, while still executing.
///
/// `nosuid` on the root is what does it, and the contrast is drawn against the
/// same inode reached through a caller's own bind, which keeps its source's
/// flags: a caller who binds a host tree in order to run what is in it is
/// entitled to a different answer than the rootfs gets.
///
/// The command runs as root inside with no hardening, so no-new-privileges is
/// clear and the mount flag is the only thing that can account for the
/// difference. The same flag suppresses file capabilities, which cannot be
/// observed the same way: a root-inside command already holds every capability,
/// and every shape that reduces them sets no-new-privileges, which suppresses
/// file capabilities on its own.
#[cfg(feature = "subid")]
#[test]
fn a_set_user_id_binary_in_the_rootfs_confers_nothing() {
    let Some(rootfs) = common::scratch_rootfs("nosuid-rootfs") else {
        return;
    };
    if !common::require::range_map() {
        return;
    }
    // The binary is owned by a mapped non-root id, which only a process inside
    // the range map can arrange: root inside executing it would gain uid 250
    // were the mount to allow it.
    let source = common::scratch_dir("nosuid-source");
    let prepare = Cage::builder()
        .rootfs(&rootfs)
        .identity_map(IdentityMap::Subordinate)
        .bind(&source, "/source")
        .command("/bin/sh")
        .args([
            "-c",
            "mkdir -p /suid && for dir in /suid /source; do \
               cp /bin/busybox $dir/id && chown 250:250 $dir/id && chmod 4755 $dir/id; \
             done",
        ])
        .build()
        .expect("the sandbox should build");
    let output = run_script(&prepare);
    assert!(
        output.status.success(),
        "preparing the set-user-ID binaries failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let cage = Cage::builder()
        .rootfs(&rootfs)
        .identity_map(IdentityMap::Subordinate)
        .bind(&source, "/bound")
        .command("/bin/sh")
        .args(["-c", "/suid/id -u; /bound/id -u"])
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some("0"),
        "a set-user-ID binary in the rootfs conferred its owner's id: {stdout}",
    );
    assert_eq!(
        lines.next(),
        Some("250"),
        "the same binary under a caller's bind should still confer it: {stdout}",
    );
}

/// A command that dies before it reaches the gate leaves the delegate at a
/// read that answers end-of-file, not at one that blocks forever.
///
/// The gate is created by the delegate immediately before it forks the command,
/// inside the sandbox and after the descriptor sweep, so it has exactly two
/// holders and end-of-file means what it says. The failure is induced one step
/// above the nested entry, where raising a hard resource limit the caller does
/// not hold answers `EPERM`: what must come back is that typed error rather
/// than a launch that never returns.
#[test]
fn a_command_that_dies_before_the_gate_does_not_hang_the_delegate() {
    use ferroday_cage::{Error, Limit, Resource, SetupStep};

    let Some(rootfs) = rootfs() else { return };
    let hard = rustix::process::getrlimit(rustix::process::Resource::Nofile)
        .maximum
        .unwrap_or(u64::MAX);
    if hard == u64::MAX {
        common::require::premise_unmet(
            "the caller's file-descriptor hard limit is already unlimited",
        );
        return;
    }
    let err = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/true")
        .rlimit(
            Resource::OpenFiles,
            Limit::of(hard + 1),
            Limit::of(hard + 1),
        )
        .build()
        .expect("the sandbox should build")
        .run()
        .expect_err("raising a hard limit the caller does not hold is refused");
    assert!(
        matches!(
            err,
            Error::Setup {
                step: SetupStep::SetRlimit,
                ..
            }
        ),
        "expected the rlimit step to be reported, got {err:?}",
    );
}

/// A non-root identity writes where its ids permit and nowhere else: root's
/// files inside the sandbox refuse it.
#[cfg(feature = "subid")]
#[test]
fn run_as_cannot_write_what_root_owns() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            // /etc is root-owned rootfs content; /tmp is the sandbox tmpfs,
            // world-writable with the sticky bit.
            "touch /etc/probe 2>/dev/null; echo etc=$?; touch /tmp/probe 2>/dev/null; echo tmp=$?",
        ])
        .identity_map(IdentityMap::Subordinate)
        .run_as(Identity::new(250, 250))
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("etc=1"), "{stdout}");
    assert!(stdout.contains("tmp=0"), "{stdout}");
}

/// Without a keep request, the identity switch clears the command's
/// capabilities: the kernel's fixup is the boundary a non-root identity
/// draws.
#[cfg(feature = "subid")]
#[test]
fn run_as_without_kept_caps_holds_no_capabilities() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "grep -E '^Cap(Eff|Prm|Amb)' /proc/self/status"])
        .identity_map(IdentityMap::Subordinate)
        .run_as(Identity::new(250, 250))
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    for line in stdout.lines() {
        let value = line.split_whitespace().nth(1).unwrap_or("");
        assert_eq!(
            u64::from_str_radix(value, 16).unwrap_or(u64::MAX),
            0,
            "expected empty capability sets: {stdout}"
        );
    }
}

/// A run-as identity sets no-new-privileges, with nothing else configured.
///
/// The cleared capability set is only half of the boundary a non-root identity
/// draws. The rootfs bind inherits the host mount's flags rather than adding
/// `nosuid`, and the provisioners apply a tree's permission bits verbatim, so
/// the sandbox holds set-user-ID binaries owned by in-namespace uid 0; without
/// the flag the non-root command executes them and is root inside again. This
/// test deliberately asks for a run-as identity and no hardening at all,
/// because that is the combination where the flag has no other reason to be
/// set.
#[cfg(feature = "subid")]
#[test]
fn run_as_alone_sets_no_new_privileges() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "grep '^NoNewPrivs' /proc/self/status"])
        .identity_map(IdentityMap::Subordinate)
        .run_as(Identity::new(250, 250))
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    assert_eq!(fields(&stdout, "NoNewPrivs:"), ["1"], "{stdout}");
}

/// Without a run-as identity the flag stays clear, so the assertion above is
/// about the switch rather than about something the launch always does.
#[test]
fn a_launch_without_a_run_as_identity_leaves_no_new_privileges_clear() {
    let Some(rootfs) = rootfs() else { return };
    let cage = common::shell(rootfs, "grep '^NoNewPrivs' /proc/self/status");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    assert_eq!(fields(&stdout, "NoNewPrivs:"), ["0"], "{stdout}");
}

/// The securebits path, asserted through the command's own view: a kept
/// capability survives the switch to a non-root identity, in the ambient
/// and effective sets, while the rest are gone. Without the securebits the
/// transition would clear everything, so this is the test that keeps the
/// feature from silently regressing into the behavior it exists to prevent.
#[cfg(all(feature = "subid", feature = "hardening"))]
#[test]
fn a_kept_capability_survives_the_identity_switch() {
    use ferroday_cage::Capability;

    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "echo \"uid=$(id -u)\"; grep -E '^Cap(Eff|Amb)' /proc/self/status",
        ])
        .identity_map(IdentityMap::Subordinate)
        .run_as(Identity::new(250, 250))
        .keep_capabilities([Capability::NetRaw])
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("uid=250"), "{stdout}");
    // CAP_NET_RAW is capability 13.
    let expected = 1u64 << 13;
    for prefix in ["CapEff:", "CapAmb:"] {
        let value = *fields(&stdout, prefix)
            .first()
            .unwrap_or_else(|| panic!("missing {prefix}: {stdout}"));
        assert_eq!(
            u64::from_str_radix(value, 16).expect("a hex mask"),
            expected,
            "{prefix} should hold exactly CAP_NET_RAW: {stdout}"
        );
    }
}

/// An explicit range request whose ids sit inside the caller's allocation,
/// exercising the explicit-`Ranges` path end to end.
///
/// The request is composed from the caller's own allocation rather than
/// delegated to `Subordinate`, so it is the `Ranges` arm of the delegate — and
/// its containment check — that is exercised, not the composition the
/// subordinate arm performs for itself.
#[cfg(feature = "subid")]
#[test]
fn an_explicit_range_request_launches() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let (Some((uid_start, uid_count)), Some((gid_start, gid_count))) = (
        subordinate_allocation("/etc/subuid"),
        subordinate_allocation("/etc/subgid"),
    ) else {
        common::require::SUBID.skip("the subordinate allocation is not stated in the files");
        return;
    };
    // Inside id 0 is the caller, as every map must have; inside 1 onward covers
    // the allocation, far enough to hold the id the chown below names.
    let span = 1_000.min(uid_count).min(gid_count);
    if span <= 250 {
        common::require::SUBID.skip("the subordinate allocation is too small to map id 250");
        return;
    }
    let uid = vec![
        IdRange {
            inside: 0,
            outside: rustix::process::geteuid().as_raw(),
            count: 1,
        },
        IdRange {
            inside: 1,
            outside: uid_start,
            count: span,
        },
    ];
    let gid = vec![
        IdRange {
            inside: 0,
            outside: rustix::process::getegid().as_raw(),
            count: 1,
        },
        IdRange {
            inside: 1,
            outside: gid_start,
            count: span,
        },
    ];
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "touch /tmp/probe; chown 250:250 /tmp/probe;              cat /proc/self/uid_map | wc -l",
        ])
        .identity_map(IdentityMap::ranges(uid, gid))
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    let extents: u32 = stdout.trim().parse().expect("an extent count");
    assert_eq!(extents, 2, "the requested extents are the map: {stdout}");
}

/// A range map whose gid list is the caller's own gid alone, which
/// `newgidmap` writes by denying `setgroups`: a non-root run-as identity
/// launches under it and keeps the group list it inherited, where a call
/// clearing that list would fail the launch.
#[cfg(feature = "subid")]
#[test]
fn run_as_launches_under_the_callers_own_gid_alone() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    let Some((uid_start, uid_count)) = subordinate_allocation("/etc/subuid") else {
        common::require::SUBID.skip("the subordinate allocation is not stated in the files");
        return;
    };
    let span = 1_000.min(uid_count);
    if span <= 250 {
        common::require::SUBID.skip("the subordinate allocation is too small to map id 250");
        return;
    }
    let uid = vec![
        IdRange {
            inside: 0,
            outside: rustix::process::geteuid().as_raw(),
            count: 1,
        },
        IdRange {
            inside: 1,
            outside: uid_start,
            count: span,
        },
    ];
    let gid = vec![IdRange {
        inside: 0,
        outside: rustix::process::getegid().as_raw(),
        count: 1,
    }];
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "echo \"$(id -u) $(id -g)\""])
        .identity_map(IdentityMap::ranges(uid, gid))
        .run_as(Identity::new(250, 0))
        .build()
        .expect("the sandbox should build");
    let output = cage.output().expect("the sandbox should launch");
    let stdout = stdout_of(&output);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout.trim(), "250 0", "{stdout}");
}

/// An explicit range request for ids the caller has no claim to is refused at
/// build time, with the offending extent named.
#[cfg(feature = "subid")]
#[test]
fn an_out_of_allocation_range_request_is_refused() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }
    // The top of the id space: no subordinate allocation reaches it, and no
    // parent map the direct tier could read contains it either, so both
    // delegates refuse and the build reports why rather than failing at launch.
    let far = u32::MAX - 10;
    let err = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/true")
        .identity_map(IdentityMap::ranges(
            vec![
                IdRange {
                    inside: 0,
                    outside: rustix::process::geteuid().as_raw(),
                    count: 1,
                },
                IdRange {
                    inside: 1,
                    outside: far,
                    count: 4,
                },
            ],
            vec![IdRange {
                inside: 0,
                outside: rustix::process::getegid().as_raw(),
                count: 1,
            }],
        ))
        .build()
        .expect_err("ids outside the allocation cannot be mapped");
    assert!(
        matches!(
            err,
            ferroday_cage::Error::Config(ferroday_cage::ConfigError::IdentityMapUnavailable { .. })
        ),
        "{err}"
    );
}

/// The removal that real ownership requires: a tree a range-mapped sandbox
/// chowned resists the plain caller, and `provision::remove` deletes it by
/// re-entering the map.
#[cfg(feature = "subid")]
#[test]
fn provision_remove_deletes_a_subordinate_owned_tree() {
    let Some(rootfs) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }

    // A host directory the sandbox fills with subordinate-owned content.
    let scratch = common::ranged_scratch("identity-remove");
    let tree = scratch.join("tree");
    std::fs::create_dir_all(&tree).expect("the scratch tree is created");

    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args([
            "-c",
            "mkdir -p /work/sub && touch /work/sub/file && chown -R 250:250 /work/sub",
        ])
        .bind(&tree, "/work")
        .identity_map(IdentityMap::Subordinate)
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    assert!(
        output.status.success(),
        "the sandbox populated the tree: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    // The plain caller is refused; the library's removal is not.
    #[expect(clippy::disallowed_methods)]
    let plain = std::fs::remove_dir_all(&*scratch);
    assert!(
        plain.is_err(),
        "a subordinate-owned tree resists plain removal"
    );
    ferroday_cage::provision::remove(&*scratch).expect("the map-assisted removal succeeds");
    assert!(!scratch.exists());
}

/// The nested direct tier: inside a range-mapped user namespace, the cage
/// writes a child range map itself, with no delegate — the pure-Rust path a
/// cage inside a rootless container uses.
///
/// The outer namespace is established with the host's `unshare
/// --map-users`, which delegates to `newuidmap` exactly as the subordinate
/// tier does; the test re-runs itself inside it with an environment marker.
/// Skips when the host `unshare` cannot build the outer namespace.
#[cfg(feature = "subid")]
#[test]
fn a_nested_cage_writes_its_own_range_map() {
    use std::os::unix::process::CommandExt as _;
    use std::process::Command;

    // The inner run: already inside the range-mapped outer namespace, where
    // the caller holds CAP_SETUID/CAP_SETGID over its own namespace and the
    // direct mapper needs no delegate.
    if std::env::var_os("FERRODAY_CAGE_NESTED_INNER").is_some() {
        let Some(rootfs) = rootfs() else { return };
        let ranges = |top: u32| {
            vec![
                ferroday_cage::IdRange {
                    inside: 0,
                    outside: 0,
                    count: 1,
                },
                ferroday_cage::IdRange {
                    inside: 1,
                    outside: 1,
                    count: top,
                },
            ]
        };
        let cage = Cage::builder()
            .rootfs(rootfs)
            .command("/bin/sh")
            .args([
                "-c",
                "touch /tmp/probe && chown 250:250 /tmp/probe && stat -c %u:%g /tmp/probe",
            ])
            .identity_map(IdentityMap::ranges(ranges(65535), ranges(65535)))
            .build()
            .expect("the nested sandbox should build");
        let output = run_script(&cage);
        let stdout = stdout_of(&output);
        assert!(output.status.success(), "{stdout}");
        assert!(stdout.contains("250:250"), "{stdout}");
        return;
    }

    let Some(_) = rootfs() else { return };
    if !common::require::range_map() {
        return;
    }

    // The outer namespace: this test binary re-run under the host unshare,
    // with the caller's own id at 0 and the subordinate allocation behind it.
    // An unshare without --map-auto support skips.
    //
    // --map-auto rather than an explicit --map-users, because the range a
    // host delegates is a host detail: useradd hands out 65536-wide blocks
    // marching up from SUB_UID_MIN, so which one a user holds depends on how
    // many users preceded it, and a directory service may supply it instead
    // of the file. Naming a range here would assert one machine's answer.
    // The inner run maps 65535 ids above root, so an allocation known to be
    // smaller cannot carry it and the test says so rather than failing.
    if subordinate_uid_count().is_some_and(|count| count < 65536) {
        common::require::SUBID
            .skip("the caller's subordinate allocation is too small to nest inside");
        return;
    }
    let exe = std::env::current_exe().expect("the test binary path");
    let started = Command::new("unshare")
        .args([
            "--setgroups",
            "allow",
            "--map-user=0",
            "--map-group=0",
            "--map-auto",
            "--",
        ])
        .arg(&exe)
        .args(common::rerun_args("a_nested_cage_writes_its_own_range_map"))
        .env("FERRODAY_CAGE_NESTED_INNER", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn();
    let output = match started {
        Ok(child) => common::finish_bounded(child, std::time::Duration::from_secs(120)),
        Err(err) => {
            common::require::SUBID.skip(format!("the host unshare could not run: {err}"));
            return;
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // An old util-linux without --map-users is a skip; an assertion
        // failure inside the nested run is a real failure.
        if stderr.contains("unrecognized option") || stderr.contains("bad usage") {
            common::require::SUBID.skip("the host unshare does not support --map-users");
            return;
        }
        panic!(
            "the nested run failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            stderr,
        );
    }
}
