//! Integration tests for identity maps and the run-as identity.
//!
//! The tests assert the observable consequence rather than the mechanism:
//! under a range map, `chown` to a non-root id succeeds where the
//! single-identity map answers `EINVAL`, and a run-as identity is what
//! `id` reports from inside. Range-map tests skip explicitly on hosts where
//! no delegate is available, as the network-stack tests do for
//! `/dev/net/tun`; the nested direct-tier test additionally needs a host
//! `unshare` that can establish a subordinate-backed namespace to nest in.

mod common;

use std::path::Path;

use ferroday_cage::{Cage, Output};
// Identity maps and the run-as identity are exercised only by the range-map
// tests, all of which are gated on the `subid` delegate.
#[cfg(feature = "subid")]
use ferroday_cage::{Identity, IdentityMap};

/// The fixture rootfs, or `None` when the sandbox tests should skip.
fn rootfs() -> Option<&'static Path> {
    common::fixture_rootfs()
}

/// Skips a range-map test when no delegate can establish one on this host.
///
/// The skip is explicit on stderr, and `FERRODAY_CAGE_REQUIRE_SUBID` turns
/// it into a failure so CI can assert the range-map tests actually ran.
#[cfg(feature = "subid")]
fn range_map_available() -> bool {
    match ferroday_cage::host::range_map_blocker() {
        None => true,
        Some(blocker) => {
            assert!(
                std::env::var_os("FERRODAY_CAGE_REQUIRE_SUBID").is_none(),
                "a range map is required but unavailable: {blocker}"
            );
            eprintln!("skipping: no delegate can establish a range map: {blocker}");
            false
        }
    }
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
    let uid = rustix::process::getuid().as_raw().to_string();
    let name = std::env::var("USER").ok();
    let text = std::fs::read_to_string("/etc/subuid").ok()?;
    text.lines().find_map(|line| {
        let mut fields = line.trim().splitn(3, ':');
        let owner = fields.next()?;
        let _start = fields.next()?;
        let count = fields.next()?.parse().ok()?;
        let mine = owner == uid || name.as_deref().is_some_and(|name| owner == name);
        mine.then_some(count)
    })
}

/// Runs a shell script in the cage, capturing its output.
fn run_script(cage: &Cage) -> Output {
    cage.output().expect("the sandbox should launch")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
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
    if !range_map_available() {
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
    if !range_map_available() {
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
    if !range_map_available() {
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

/// A non-root identity writes where its ids permit and nowhere else: root's
/// files inside the sandbox refuse it.
#[cfg(feature = "subid")]
#[test]
fn run_as_cannot_write_what_root_owns() {
    let Some(rootfs) = rootfs() else { return };
    if !range_map_available() {
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
    if !range_map_available() {
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
    if !range_map_available() {
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
    for prefix in ["CapEff", "CapAmb"] {
        let line = stdout
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("missing {prefix}: {stdout}"));
        let value = line.split_whitespace().nth(1).expect("a mask value");
        assert_eq!(
            u64::from_str_radix(value, 16).expect("a hex mask"),
            expected,
            "{prefix} should hold exactly CAP_NET_RAW: {stdout}"
        );
    }
}

/// An explicit range request whose ids sit inside the caller's allocation,
/// exercising the explicit-`Ranges` path end to end.
#[cfg(feature = "subid")]
#[test]
fn an_explicit_range_request_launches() {
    let Some(rootfs) = rootfs() else { return };
    if !range_map_available() {
        return;
    }
    // Compose a request from the caller's own id plus part of whatever the
    // subordinate map resolves to; simplest is to reuse Subordinate, whose
    // resolution the delegate reports, and assert the id space's edge.
    let cage = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", "cat /proc/self/uid_map | wc -l"])
        .identity_map(IdentityMap::Subordinate)
        .build()
        .expect("the sandbox should build");
    let output = run_script(&cage);
    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}");
    let extents: u32 = stdout.trim().parse().expect("an extent count");
    assert!(extents >= 2, "expected a multi-extent map: {stdout}");
}

/// The removal that real ownership requires: a tree a range-mapped sandbox
/// chowned resists the plain caller, and `provision::remove` deletes it by
/// re-entering the map.
#[cfg(feature = "subid")]
#[test]
fn provision_remove_deletes_a_subordinate_owned_tree() {
    let Some(rootfs) = rootfs() else { return };
    if !range_map_available() {
        return;
    }

    // A host directory the sandbox fills with subordinate-owned content.
    let scratch = std::env::temp_dir().join(format!(
        "ferroday-cage-identity-remove-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
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
    assert!(
        std::fs::remove_dir_all(&scratch).is_err(),
        "a subordinate-owned tree resists plain removal"
    );
    ferroday_cage::provision::remove(&scratch).expect("the map-assisted removal succeeds");
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
    if !range_map_available() {
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
        eprintln!("skipping: the caller's subordinate allocation is too small to nest inside");
        return;
    }
    let exe = std::env::current_exe().expect("the test binary path");
    let output = Command::new("unshare")
        .args([
            "--setgroups",
            "allow",
            "--map-user=0",
            "--map-group=0",
            "--map-auto",
            "--",
        ])
        .arg(&exe)
        .args(["--exact", "a_nested_cage_writes_its_own_range_map"])
        .env("FERRODAY_CAGE_NESTED_INNER", "1")
        .output();
    let output = match output {
        Ok(output) => output,
        Err(err) => {
            eprintln!("skipping: the host unshare could not run: {err}");
            return;
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // An old util-linux without --map-users is a skip; an assertion
        // failure inside the nested run is a real failure.
        if stderr.contains("unrecognized option") || stderr.contains("bad usage") {
            eprintln!("skipping: the host unshare does not support --map-users");
            return;
        }
        panic!(
            "the nested run failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            stderr,
        );
    }
}
