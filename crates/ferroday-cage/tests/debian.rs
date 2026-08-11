//! Integration tests for the Debian userland provisioner.

mod common;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use common::deb_repo::{Pkg, Tar, ar, deb, write_repo};
use ferroday_cage::provision::debian::{Debian, DebianEvent, Plan, Pool, Repository};
use ferroday_cage::provision::{self, ProvisionError, Provisioned};

/// The pool the pool tests publish into: a fixed suite, component, and
/// architecture, so each test names only what it is varying.
fn trixie_pool(dir: &Path) -> Pool {
    Pool::at(dir)
        .suite("trixie")
        .component("main")
        .architecture("amd64")
}

/// Builds a `.deb` carrying a real `./control` member, which [`deb`] omits.
/// `Pool::publish` reads the control stanza to synthesize the pool index, so its
/// tests need a control-bearing package.
fn deb_with_control(control: &str, data_tar: &[u8]) -> Vec<u8> {
    let control_tar = Tar::new()
        .file("./control", 0o644, control.as_bytes())
        .finish();
    ar(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar", &control_tar),
        ("data.tar", data_tar),
    ])
}

/// The environment variable that opts into the network-dependent bootstrap
/// tests. They fetch from a live Debian mirror and are off by default, so a
/// plain `cargo test --all-features` — including CI — does not reach the
/// network.
const NETWORK_GATE: &str = "FERRODAY_CAGE_DEBIAN_NETWORK_TEST";

/// The variable that asserts these tests ran, in the crate's usual shape: a
/// skip stays a skip by default, and this turns it into a failure so a release
/// check cannot come back green having exercised no repository at all.
const REQUIRE_GATE: &str = "FERRODAY_CAGE_REQUIRE_NETWORK_TEST";

/// Returns `false` and prints a skip note when the network tests are not
/// enabled.
fn network_enabled() -> bool {
    if std::env::var_os(NETWORK_GATE).is_some() {
        return true;
    }
    assert!(
        std::env::var_os(REQUIRE_GATE).is_none(),
        "{REQUIRE_GATE} is set and {NETWORK_GATE} is not, so the Debian bootstrap tests \
         would have been skipped",
    );
    eprintln!("skipping: set {NETWORK_GATE}=1 to run the Debian bootstrap tests");
    false
}

/// A cache directory for downloaded packages, persistent across runs so the
/// tests do not re-download the base system each time.
fn deb_cache() -> std::path::PathBuf {
    let base = std::env::var_os("FERRODAY_CAGE_FIXTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let cache = base.join("ferroday-cage-debian-cache");
    std::fs::create_dir_all(&cache).unwrap();
    cache
}

#[test]
fn hermetic_extract_only_bootstrap() {
    // A self-contained file:// repository, no network and no signature, so
    // the whole acquisition and extraction pipeline runs in CI.
    let dir = common::scratch_dir("debian-hermetic");
    let base = Tar::new()
        .dir("./usr", 0o755)
        .dir("./usr/bin", 0o755)
        .dir("./usr/sbin", 0o755)
        .file("./usr/bin/hello", 0o755, b"#!/bin/true\n")
        // A setgid helper owned by a non-root group, as the base set's
        // shadow helpers are: it extracts root-owned, keeping its mode.
        .file_owned("./usr/sbin/helper", 0o2755, 0, 42, b"x\n")
        .symlink("./bin", "usr/bin")
        .finish();
    let dependency = Tar::new()
        .dir("./usr", 0o755)
        .dir("./usr/lib", 0o755)
        .file("./usr/lib/libdep.so", 0o644, b"lib\n")
        .finish();
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", deb(&base), "libdep"),
            Pkg::ordinary("libdep", deb(&dependency)),
        ],
    );

    let rootfs = dir.join("rootfs");
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .build()
        .expect("the builder validates");
    assert_eq!(
        provision::ensure(&rootfs, &mut debian).expect("the hermetic bootstrap runs"),
        Provisioned::Created,
    );

    assert!(rootfs.join("usr/bin/hello").is_file());
    // The dependency was resolved from the base package's Depends and
    // extracted, and the merged-usr symlink is in place.
    assert!(rootfs.join("usr/lib/libdep.so").is_file());
    assert!(rootfs.join("bin").is_symlink());
    let mode = std::fs::symlink_metadata(rootfs.join("usr/sbin/helper"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o2755, "the setgid bit is preserved");
}

#[test]
fn hermetic_resolve_reports_the_plan_without_downloading() {
    // resolve() fetches and verifies the release and index and resolves the
    // closure, but downloads no package. Proven by deleting the pool .debs
    // after building the repository: resolve() must still succeed, reading only
    // the release and the index, and report the archive's recorded digests.
    let dir = common::scratch_dir("debian-resolve");
    let repo = dir.join("repo");
    let base = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let dependency = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/lib/libdep.so", 0o644, b"lib\n")
        .finish();
    let base_deb = deb(&base);
    let mirror = write_repo(
        &repo,
        "trixie",
        "amd64",
        &[
            Pkg::required("base", base_deb.clone(), "libdep"),
            Pkg::ordinary("libdep", deb(&dependency)),
        ],
    );
    // Remove the pool so any download would fail; resolve() must not need it.
    std::fs::remove_file(repo.join("pool/base_1.0_amd64.deb")).unwrap();
    std::fs::remove_file(repo.join("pool/libdep_1.0_amd64.deb")).unwrap();

    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .build()
        .expect("the builder validates");
    let plan = debian
        .resolve()
        .expect("resolve reads only the release and index");

    assert_eq!(plan.suite, "trixie");
    assert_eq!(plan.architecture, "amd64");
    // The required base package pulls its dependency; the plan is sorted by name.
    let names: Vec<_> = plan.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["base", "libdep"]);

    let base_plan = plan
        .packages
        .iter()
        .find(|p| p.name == "base")
        .expect("base is in the plan");
    assert_eq!(base_plan.version, "1.0");
    assert_eq!(base_plan.architecture, "amd64");
    assert_eq!(base_plan.filename, "pool/base_1.0_amd64.deb");
    // The reported digest is the archive's, chained from the verified index.
    assert_eq!(base_plan.sha256, common::deb_repo::sha256_hex(&base_deb));

    // Resolution is deterministic: a second call yields an identical plan.
    assert_eq!(debian.resolve().expect("resolve again"), plan);
}

#[test]
fn hermetic_two_repositories_merge_and_fetch_origin_correctly() {
    // A primary mirror plus an additional trusted file:// repository shipping a
    // custom package. The custom package lives only in the second repository's
    // pool and depends on a library that lives only in the primary; a full
    // extraction succeeds only if each package is fetched from its own
    // repository's mirror, proving origin-correct acquisition and a merged
    // resolution that closes the custom package's dependency against the mirror.
    let dir = common::scratch_dir("debian-two-repos");

    let base = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let library = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/lib/libdep.so", 0o644, b"lib\n")
        .finish();
    let primary = write_repo(
        &dir.join("primary"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", deb(&base), "libdep"),
            Pkg::ordinary("libdep", deb(&library)),
        ],
    );

    let custom_tar = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/custom", 0o755, b"#!/bin/true\n")
        .finish();
    // An ordinary package that depends on the primary's library, so resolving
    // it exercises a cross-repository dependency closure.
    let custom = Pkg::ordinary("custom", deb(&custom_tar)).depending_on("libdep");
    let feature = write_repo(&dir.join("feature"), "trixie", "amd64", &[custom]);

    let feature_repo = ferroday_cage::provision::debian::Repository::builder("trixie")
        .mirror(feature)
        .trust_unsigned(true)
        .name("feature")
        .build()
        .expect("the feature repository validates");

    let rootfs = dir.join("rootfs");
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(primary)
        .trust_unsigned(true)
        .include(["custom"])
        .repository(feature_repo)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .build()
        .expect("the builder validates");

    // The plan draws from both repositories: the base and its library from the
    // primary, the custom package from the feature repository.
    let plan = debian.resolve().expect("the merged plan resolves");
    let mut names: Vec<_> = plan.packages.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["base", "custom", "libdep"]);

    assert_eq!(
        provision::ensure(&rootfs, &mut debian).expect("the two-repository bootstrap runs"),
        Provisioned::Created,
    );
    // Every package's files are present: the custom package could only have been
    // fetched from the feature repository, its dependency and the base only from
    // the primary.
    assert!(rootfs.join("usr/bin/custom").is_file());
    assert!(rootfs.join("usr/lib/libdep.so").is_file());
    assert!(rootfs.join("usr/bin/x").is_file());
}

#[test]
fn hermetic_resolved_event_reports_the_bootstrap_plan() {
    // A full bootstrap emits DebianEvent::Resolved once the closure is resolved
    // and before the first download, carrying the same plan a standalone
    // resolve() reports. Captured through a progress sink over an extract-only
    // bootstrap, so no configuration wave is needed.
    let dir = common::scratch_dir("debian-resolved-event");
    let base = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let dependency = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/lib/libdep.so", 0o644, b"lib\n")
        .finish();
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", deb(&base), "libdep"),
            Pkg::ordinary("libdep", deb(&dependency)),
        ],
    );

    // The sink borrows `reported` for the run; the block scopes that borrow so
    // the plan can be read out afterward.
    let reported: std::cell::RefCell<Option<Plan>> = std::cell::RefCell::new(None);
    let rootfs = dir.join("rootfs");
    {
        let mut sink = |event: DebianEvent<'_>| {
            if let DebianEvent::Resolved { plan, .. } = event {
                *reported.borrow_mut() = Some(plan.clone());
            }
        };
        let mut debian = Debian::builder("trixie")
            .architecture("amd64")
            .mirror(mirror)
            .trust_unsigned(true)
            .cache_dir(dir.join("cache"))
            .extract_only(true)
            .build()
            .expect("the builder validates");
        provision::ensure(&rootfs, &mut debian.observe(&mut sink)).expect("the bootstrap runs");
    }

    let plan = reported
        .into_inner()
        .expect("a Resolved event carried the plan");
    assert_eq!(plan.suite, "trixie");
    assert_eq!(plan.architecture, "amd64");
    let names: Vec<_> = plan.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["base", "libdep"]);
}

#[test]
fn hermetic_published_pool_is_consumable_by_the_provisioner() {
    // Pool::publish writes a dists/-structured trusted pool from a freshly-built
    // .deb; the provisioner then resolves and extracts against it as an
    // additional repository. The round-trip proves the writer's output parses
    // through the reader, and the pool's bytes are fetchable and extractable.
    let dir = common::scratch_dir("debian-pool-writer");

    let base = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let library = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/lib/libdep.so", 0o644, b"lib\n")
        .finish();
    let primary = write_repo(
        &dir.join("primary"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", deb(&base), "libdep"),
            Pkg::ordinary("libdep", deb(&library)),
        ],
    );

    // A freshly-built custom package that depends on the primary's library.
    let custom_data = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/custom", 0o755, b"#!/bin/true\n")
        .finish();
    let custom_deb = deb_with_control(
        "Package: custom\nVersion: 1.0\nArchitecture: amd64\nMaintainer: test\n\
         Depends: libdep\nDescription: a custom package\n",
        &custom_data,
    );
    let deb_path = dir.join("custom_1.0_amd64.deb");
    std::fs::write(&deb_path, &custom_deb).unwrap();

    let pool = dir.join("pool");
    trixie_pool(&pool)
        .publish([&deb_path])
        .expect("the pool publishes");

    let pool_repo = Repository::builder("trixie")
        .mirror(format!("file://{}", pool.display()))
        .trust_unsigned(true)
        .name("localpool")
        .build()
        .expect("the pool repository validates");

    let rootfs = dir.join("rootfs");
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(primary)
        .trust_unsigned(true)
        .include(["custom"])
        .repository(pool_repo)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .build()
        .expect("the builder validates");

    let plan = debian
        .resolve()
        .expect("resolves against the published pool");
    let mut names: Vec<_> = plan.packages.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["base", "custom", "libdep"]);

    // The custom entry carries the pool path the writer chose and the archive
    // digest of the .deb published there — read from its control member and
    // computed over its bytes.
    let custom = plan
        .packages
        .iter()
        .find(|p| p.name == "custom")
        .expect("the custom package resolved from the pool");
    assert_eq!(custom.version, "1.0");
    assert_eq!(custom.filename, "pool/main/c/custom/custom_1.0_amd64.deb");
    assert_eq!(custom.sha256, common::deb_repo::sha256_hex(&custom_deb));

    assert_eq!(
        provision::ensure(&rootfs, &mut debian).expect("the bootstrap runs"),
        Provisioned::Created,
    );
    assert!(rootfs.join("usr/bin/custom").is_file());
}

#[test]
fn hermetic_a_second_component_does_not_retire_the_first() {
    // A pool's release names the sections a reader may resolve, and a reader
    // consults it before it knows which digests to ask for. So publishing a
    // second component into one suite has to leave the first named: the index
    // an earlier publish wrote survives on disk either way, but a section the
    // release does not name cannot be resolved, and the by-hash copies are no
    // escape from that. The proof is the provisioner drawing a package out of
    // each component after both have been published.
    let dir = common::scratch_dir("debian-pool-two-components");

    let base = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let primary = write_repo(
        &dir.join("primary"),
        "trixie",
        "amd64",
        &[Pkg::required("base", deb(&base), "")],
    );

    // One package per component, each with contents of its own, so the two
    // indexes differ and a digest carried across a publish is meaningful.
    let build = |name: &str| {
        let data = Tar::new()
            .dir("./usr", 0o755)
            .file(&format!("./usr/bin/{name}"), 0o755, b"#!/bin/true\n")
            .finish();
        let bytes = deb_with_control(
            &format!(
                "Package: {name}\nVersion: 1.0\nArchitecture: amd64\nMaintainer: test\n\
                 Description: the {name} package\n"
            ),
            &data,
        );
        let path = dir.join(format!("{name}_1.0_amd64.deb"));
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let in_main = build("mainpkg");
    let in_contrib = build("contribpkg");

    let pool = dir.join("pool");
    let publish = |component: &str, package: &Path| {
        Pool::at(&pool)
            .suite("trixie")
            .architecture("amd64")
            .component(component)
            .publish([package])
            .unwrap_or_else(|err| panic!("publishing into {component}: {err}"));
    };
    publish("main", &in_main);
    publish("contrib", &in_contrib);

    let release_text = || std::fs::read_to_string(pool.join("dists/trixie/Release")).unwrap();
    let release = release_text();
    assert!(
        release.contains("Components: contrib main\n"),
        "the second publish retired the first component: {release}",
    );

    // The digest a section is recorded under is what a reader verifies its
    // fetch against, so republishing one component must leave the other's
    // exactly as it was. Anything else breaks a reader that is midway through
    // resolving a component this publish has nothing to do with.
    let digest_of = |release: &str, section: &str| -> String {
        release
            .lines()
            .find(|line| line.ends_with(section))
            .unwrap_or_else(|| panic!("the release does not name {section}: {release}"))
            .split_whitespace()
            .next()
            .expect("a section line begins with its digest")
            .to_string()
    };
    let contrib_before = digest_of(&release, "contrib/binary-amd64/Packages");
    publish("main", &in_main);
    assert_eq!(
        digest_of(&release_text(), "contrib/binary-amd64/Packages"),
        contrib_before,
        "republishing main changed the digest contrib's index is recorded under",
    );

    // Reachability, end to end: resolution verifies each index it fetches
    // against the digest the release records, so drawing a package out of both
    // components is only possible if the release names both sections.
    let pool_repo = Repository::builder("trixie")
        .mirror(format!("file://{}", pool.display()))
        .components(["main", "contrib"])
        .trust_unsigned(true)
        .name("localpool")
        .build()
        .expect("the pool repository validates");

    let rootfs = dir.join("rootfs");
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(primary)
        .trust_unsigned(true)
        .include(["mainpkg", "contribpkg"])
        .repository(pool_repo)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .build()
        .expect("the builder validates");

    let plan = debian
        .resolve()
        .expect("both components resolve out of one pool");
    let mut names: Vec<_> = plan.packages.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["base", "contribpkg", "mainpkg"]);

    assert_eq!(
        provision::ensure(&rootfs, &mut debian).expect("the bootstrap runs"),
        Provisioned::Created,
    );
    // Each package came from its own component's pool directory.
    assert!(rootfs.join("usr/bin/mainpkg").is_file());
    assert!(rootfs.join("usr/bin/contribpkg").is_file());
}

#[test]
fn hermetic_empty_published_pool_is_a_valid_repository() {
    // A pool published with no .debs is a valid, empty repository: its Release
    // declares the architecture and component, so the provisioner's release
    // check passes and the empty package set contributes nothing. This is the
    // create-the-pool-up-front case before the first component has built.
    let dir = common::scratch_dir("debian-empty-pool");
    let base = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let primary = write_repo(
        &dir.join("primary"),
        "trixie",
        "amd64",
        &[Pkg::required("base", deb(&base), "")],
    );

    let pool = dir.join("pool");
    trixie_pool(&pool)
        .publish::<&Path>([])
        .expect("an empty pool publishes");

    let pool_repo = Repository::builder("trixie")
        .mirror(format!("file://{}", pool.display()))
        .trust_unsigned(true)
        .name("empty")
        .build()
        .expect("the empty pool repository validates");

    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(primary)
        .trust_unsigned(true)
        .repository(pool_repo)
        .build()
        .expect("the builder validates");
    let plan = debian
        .resolve()
        .expect("resolution succeeds with an empty pool declared");
    let names: Vec<_> = plan.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["base"], "the empty pool contributes nothing");
}

#[test]
fn hermetic_published_pool_keeps_the_highest_version_across_calls() {
    // Pool::publish is incremental and idempotent: publishing a higher version
    // supersedes a lower one, and re-publishing the lower one afterward does not
    // regress the index. The resolver draws the highest version, matching the
    // pool's own dedupe.
    let dir = common::scratch_dir("debian-pool-dedupe");
    let base = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let primary = write_repo(
        &dir.join("primary"),
        "trixie",
        "amd64",
        &[Pkg::required("base", deb(&base), "")],
    );

    let data = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/tool", 0o755, b"v\n")
        .finish();
    let v1 = deb_with_control(
        "Package: tool\nVersion: 1.0\nArchitecture: amd64\nDescription: a tool\n",
        &data,
    );
    let v2 = deb_with_control(
        "Package: tool\nVersion: 2.0\nArchitecture: amd64\nDescription: a tool\n",
        &data,
    );
    let p1 = dir.join("tool_1.0.deb");
    let p2 = dir.join("tool_2.0.deb");
    std::fs::write(&p1, &v1).unwrap();
    std::fs::write(&p2, &v2).unwrap();

    let pool = dir.join("pool");
    trixie_pool(&pool).publish([&p1]).unwrap();
    trixie_pool(&pool).publish([&p2]).unwrap();
    // Re-publishing the older version must not win over the newer one.
    trixie_pool(&pool).publish([&p1]).unwrap();

    let pool_repo = Repository::builder("trixie")
        .mirror(format!("file://{}", pool.display()))
        .trust_unsigned(true)
        .name("pool")
        .build()
        .unwrap();
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(primary)
        .trust_unsigned(true)
        .include(["tool"])
        .repository(pool_repo)
        .build()
        .unwrap();
    let plan = debian.resolve().expect("resolves");
    let tool = plan
        .packages
        .iter()
        .find(|p| p.name == "tool")
        .expect("the tool resolved from the pool");
    assert_eq!(
        tool.version, "2.0",
        "the highest version wins across publish calls",
    );
}

#[test]
fn hermetic_concurrent_publishes_keep_every_package() {
    // Publishing rebuilds the index from what the pool already holds, so
    // concurrent publishes that each started from the same prior index would
    // silently drop each other's packages. Every package a publish reported as
    // written must be in the final index.
    let dir = common::scratch_dir("debian-pool-concurrent");
    let data = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/tool", 0o755, b"v\n")
        .finish();

    // One .deb per publisher, each a distinct package name, so a lost update
    // shows up as a missing name rather than a version regression.
    let names: Vec<String> = (0..8).map(|i| format!("component{i}")).collect();
    let paths: Vec<std::path::PathBuf> = names
        .iter()
        .map(|name| {
            let bytes = deb_with_control(
                &format!(
                    "Package: {name}\nVersion: 1.0\nArchitecture: amd64\nDescription: a part\n"
                ),
                &data,
            );
            let path = dir.join(format!("{name}.deb"));
            std::fs::write(&path, &bytes).unwrap();
            path
        })
        .collect();

    let pool = dir.join("pool");
    let publishers: Vec<_> = paths
        .into_iter()
        .map(|path| {
            let pool = pool.clone();
            std::thread::spawn(move || trixie_pool(&pool).publish([&path]))
        })
        .collect();
    for publisher in publishers {
        publisher
            .join()
            .unwrap()
            .expect("a concurrent publish succeeds");
    }

    let packages =
        std::fs::read_to_string(pool.join("dists/trixie/main/binary-amd64/Packages")).unwrap();
    for name in &names {
        assert!(
            packages.contains(&format!("Package: {name}\n")),
            "{name} was dropped from the index by a concurrent publish",
        );
    }
}

#[test]
fn hermetic_a_published_release_keeps_resolving_after_later_publishes() {
    // The property that lets a pipeline resolve against the pool while other
    // components publish into it: a reader holding a Release resolves the
    // indexes that Release described, however many publishes land afterward.
    // The Release declares Acquire-By-Hash, and the by-hash copies it names are
    // never rewritten or removed.
    let dir = common::scratch_dir("debian-pool-by-hash");
    let data = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/tool", 0o755, b"v\n")
        .finish();
    let write_deb = |name: &str| {
        let bytes = deb_with_control(
            &format!("Package: {name}\nVersion: 1.0\nArchitecture: amd64\nDescription: a part\n"),
            &data,
        );
        let path = dir.join(format!("{name}.deb"));
        std::fs::write(&path, &bytes).unwrap();
        path
    };

    let pool = dir.join("pool");
    trixie_pool(&pool).publish([write_deb("first")]).unwrap();

    // What a reader would have read before the later publishes.
    let release_path = pool.join("dists/trixie/Release");
    let captured = std::fs::read_to_string(&release_path).unwrap();
    assert!(
        captured.contains("Acquire-By-Hash: yes"),
        "the release must direct readers at the immutable index copies",
    );
    let digests: Vec<String> = captured
        .lines()
        .filter(|line| line.starts_with(' '))
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect();
    assert_eq!(
        digests.len(),
        2,
        "the release names Packages and Packages.gz"
    );

    for name in ["second", "third", "fourth"] {
        trixie_pool(&pool).publish([write_deb(name)]).unwrap();
    }

    // The captured Release is now stale, but everything it named still resolves
    // to the bytes it described.
    let by_hash = pool.join("dists/trixie/main/binary-amd64/by-hash/SHA256");
    for digest in &digests {
        let body = std::fs::read(by_hash.join(digest)).unwrap_or_else(|err| {
            panic!("the index {digest} named by a read Release is gone: {err}")
        });
        assert_eq!(
            common::deb_repo::sha256_hex(&body),
            *digest,
            "a by-hash index must hold the bytes its name claims",
        );
    }

    // And the current Release names the current index, which has everything.
    let packages =
        std::fs::read_to_string(pool.join("dists/trixie/main/binary-amd64/Packages")).unwrap();
    for name in ["first", "second", "third", "fourth"] {
        assert!(
            packages.contains(&format!("Package: {name}\n")),
            "{name} missing"
        );
    }
}

#[test]
fn hermetic_republishing_identical_bytes_does_not_rewrite_the_pool_file() {
    // Copying identical bytes over themselves would be the only routine rewrite
    // of a file a reader may be fetching, so an unchanged .deb is left alone.
    let dir = common::scratch_dir("debian-pool-idempotent");
    let data = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/tool", 0o755, b"v\n")
        .finish();
    let bytes = deb_with_control(
        "Package: tool\nVersion: 1.0\nArchitecture: amd64\nDescription: a tool\n",
        &data,
    );
    let source = dir.join("tool.deb");
    std::fs::write(&source, &bytes).unwrap();

    let pool = dir.join("pool");
    trixie_pool(&pool).publish([&source]).unwrap();

    let published = pool.join("pool/main/t/tool/tool_1.0_amd64.deb");
    let first = std::fs::metadata(&published).unwrap();

    trixie_pool(&pool).publish([&source]).unwrap();

    let second = std::fs::metadata(&published).unwrap();
    assert_eq!(
        (first.ino(), first.modified().unwrap()),
        (second.ino(), second.modified().unwrap()),
        "republishing identical bytes replaced the pool file",
    );
    assert_eq!(std::fs::read(&published).unwrap(), bytes);
}

/// The `Filename`, `Size`, and `SHA256` the published index records for
/// `package`.
fn published_fields(pool: &Path, package: &str) -> (String, u64, String) {
    let packages =
        std::fs::read_to_string(pool.join("dists/trixie/main/binary-amd64/Packages")).unwrap();
    let stanza = packages
        .split("\n\n")
        .find(|block| {
            block
                .lines()
                .any(|line| line == format!("Package: {package}"))
        })
        .unwrap_or_else(|| panic!("{package} is not in the published index"));
    let field = |name: &str| {
        stanza
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .unwrap_or_else(|| panic!("the {package} stanza has no {name}"))
            .to_string()
    };
    (
        field("Filename"),
        field("Size").parse().expect("Size is a number"),
        field("SHA256"),
    )
}

#[test]
fn hermetic_rewriting_a_source_deb_does_not_change_the_pool() {
    // The pool's copy is its own inode, never an alias of the caller's file. A
    // clone shares storage and nothing else, and the streamed fallback shares
    // nothing at all, so a caller that rewrites its .deb in place cannot change
    // bytes a reader is resolving against. A hard link into the pool would be
    // cheaper still and would break exactly this.
    let dir = common::scratch_dir("debian-pool-independent");
    let bytes = deb_with_control(
        "Package: tool\nVersion: 1.0\nArchitecture: amd64\nDescription: a tool\n",
        &Tar::new()
            .dir("./usr", 0o755)
            .file("./usr/bin/tool", 0o755, b"v1\n")
            .finish(),
    );
    let source = dir.join("tool.deb");
    std::fs::write(&source, &bytes).unwrap();

    let pool = dir.join("pool");
    trixie_pool(&pool).publish([&source]).unwrap();

    let published = pool.join("pool/main/t/tool/tool_1.0_amd64.deb");
    assert_ne!(
        std::fs::metadata(&published).unwrap().ino(),
        std::fs::metadata(&source).unwrap().ino(),
        "the pool must hold its own inode, not an alias of the caller's",
    );

    // Rewrite the caller's .deb in place at a different length, then at the
    // same length: a shared inode would carry either straight into the pool.
    let rebuilt = deb_with_control(
        "Package: tool\nVersion: 1.0\nArchitecture: amd64\nDescription: a rebuilt tool\n",
        &Tar::new()
            .dir("./usr", 0o755)
            // Enough to span more tar blocks than the original, so the rewrite
            // genuinely changes the file's length.
            .file("./usr/bin/tool", 0o755, &vec![b'v'; 4096])
            .finish(),
    );
    assert_ne!(rebuilt.len(), bytes.len(), "the rewrite must change length");
    std::fs::write(&source, &rebuilt).unwrap();
    assert_eq!(
        std::fs::read(&published).unwrap(),
        bytes,
        "rewriting the source at a new length changed the pool's copy",
    );

    let mut flipped = bytes.clone();
    *flipped.last_mut().unwrap() ^= 0xff;
    std::fs::write(&source, &flipped).unwrap();
    assert_eq!(
        std::fs::read(&published).unwrap(),
        bytes,
        "rewriting the source in place changed the pool's copy",
    );

    // And the index still describes the file the pool holds.
    let (filename, size, digest) = published_fields(&pool, "tool");
    assert_eq!(filename, "pool/main/t/tool/tool_1.0_amd64.deb");
    assert_eq!(size, bytes.len() as u64);
    assert_eq!(digest, common::deb_repo::sha256_hex(&bytes));
}

#[test]
fn hermetic_republishing_changed_bytes_replaces_the_file_and_its_digest() {
    // The documented republish case: the archive layout stores one version at
    // one path, so different bytes at the same version replace what is there.
    // The index must follow the file rather than go on describing what the file
    // used to be — the recorded digest and the stored bytes are one claim.
    let dir = common::scratch_dir("debian-pool-republish-changed");
    let control = "Package: tool\nVersion: 1.0\nArchitecture: amd64\nDescription: a tool\n";
    let first = deb_with_control(
        control,
        &Tar::new()
            .dir("./usr", 0o755)
            .file("./usr/bin/tool", 0o755, b"v1\n")
            .finish(),
    );
    // Both payloads fit the same number of tar blocks, so the two .debs are the
    // same length and only their content differs. That is deliberate: it takes
    // the comparison past the length check and onto the digests, the path a
    // rebuild of one component actually takes.
    let second = deb_with_control(
        control,
        &Tar::new()
            .dir("./usr", 0o755)
            .file("./usr/bin/tool", 0o755, b"v2\n")
            .finish(),
    );

    let source = dir.join("tool.deb");
    let pool = dir.join("pool");
    std::fs::write(&source, &first).unwrap();
    trixie_pool(&pool).publish([&source]).unwrap();
    std::fs::write(&source, &second).unwrap();
    trixie_pool(&pool).publish([&source]).unwrap();

    let published = pool.join("pool/main/t/tool/tool_1.0_amd64.deb");
    assert_eq!(
        std::fs::read(&published).unwrap(),
        second,
        "the pool must hold the bytes most recently published",
    );
    let (_, size, digest) = published_fields(&pool, "tool");
    assert_eq!(size, second.len() as u64);
    assert_eq!(digest, common::deb_repo::sha256_hex(&second));
}

#[test]
fn hermetic_resolve_layer_omits_the_base_packages() {
    // A layered resolution treats the base's configured set as satisfied and
    // returns only the increment. The base's dpkg status lists `base` and
    // `libdep` installed; resolving an include that depends on `libdep` yields
    // just the include, while a full resolution of the same repository draws in
    // the base packages it stands on. The contrast is the whole point of the
    // assume-installed seed.
    let dir = common::scratch_dir("debian-resolve-layer");

    let base_data = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let libdep_data = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/lib/libdep.so", 0o644, b"lib\n")
        .finish();
    let tool_data = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/tool", 0o755, b"#!/bin/true\n")
        .finish();
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", deb(&base_data), "libdep"),
            Pkg::ordinary("libdep", deb(&libdep_data)),
            Pkg::ordinary("tool", deb(&tool_data)).depending_on("libdep"),
        ],
    );

    // A base whose dpkg status database records the base packages configured.
    let base_dir = dir.join("base");
    let dpkg = base_dir.join("var/lib/dpkg");
    std::fs::create_dir_all(&dpkg).unwrap();
    std::fs::write(
        dpkg.join("status"),
        "Package: base\nStatus: install ok installed\nVersion: 1.0\n\n\
         Package: libdep\nStatus: install ok installed\nVersion: 1.0\n",
    )
    .unwrap();

    let mut layered = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror.clone())
        .trust_unsigned(true)
        .base_layer(&base_dir)
        .include(["tool"])
        .build()
        .expect("the builder validates");
    let plan = layered.resolve_layer().expect("the layer resolves");
    let names: Vec<_> = plan.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        ["tool"],
        "the increment is the include alone; the base's `libdep` dependency and \
         seed packages are assumed satisfied",
    );

    // The same repository resolved as a full bootstrap draws in the base seed and
    // the dependency the layer left to the base.
    let mut full = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .include(["tool"])
        .build()
        .expect("the builder validates");
    let mut full_names: Vec<_> = full
        .resolve()
        .expect("the full plan resolves")
        .packages
        .iter()
        .map(|p| p.name.clone())
        .collect();
    full_names.sort();
    assert_eq!(
        full_names,
        ["base", "libdep", "tool"],
        "a full bootstrap installs the base seed and the shared dependency",
    );
}

#[test]
fn hermetic_resolve_layer_requires_a_configured_base() {
    // A base layer that is not a configured bootstrap — no status database, or an
    // empty one from an extract-only tree — is refused rather than treated as an
    // empty base, which would draw the whole base system into the increment.
    let dir = common::scratch_dir("debian-layer-base-check");
    let base_data = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[Pkg::required("base", deb(&base_data), "")],
    );

    // No status database at all.
    let missing = dir.join("no-base");
    std::fs::create_dir_all(&missing).unwrap();
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .base_layer(&missing)
        .include(["base"])
        .build()
        .expect("the builder validates");
    assert!(
        debian.resolve_layer().is_err(),
        "a base with no dpkg status database is refused",
    );
}

#[test]
fn hermetic_stage_layer_empty_increment_stages_without_configuring() {
    // When every requested package is already in the base, the increment is
    // empty: stage_layer installs nothing, launches no dpkg wave, and returns a
    // build layer over an empty upper. This exercises the empty-increment path
    // hermetically — it runs no cage — so it needs no network or real dpkg; it
    // skips only where the overlay preflight reports the host cannot overlay.
    let dir = common::scratch_dir("debian-empty-layer");
    if let Some(blocker) = ferroday_cage::host::overlay_blocker(&dir) {
        eprintln!("skipping: overlay-rooted cages are unavailable: {blocker}");
        return;
    }
    let base_data = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[Pkg::required("base", deb(&base_data), "")],
    );

    // A configured base carrying `base`, the only package the layer requests.
    let base_dir = dir.join("base");
    let dpkg = base_dir.join("var/lib/dpkg");
    std::fs::create_dir_all(&dpkg).unwrap();
    std::fs::write(
        dpkg.join("status"),
        "Package: base\nStatus: install ok installed\nVersion: 1.0\n",
    )
    .unwrap();

    let upper = dir.join("upper");
    let layer = {
        let mut debian = Debian::builder("trixie")
            .architecture("amd64")
            .mirror(mirror)
            .trust_unsigned(true)
            .base_layer(&base_dir)
            .include(["base"])
            .build()
            .expect("the builder validates");
        debian
            .stage_layer(&upper)
            .expect("an empty increment stages without configuring")
    };
    assert_eq!(layer.path(), upper.as_path());
    assert!(
        upper.is_dir(),
        "the upper exists even for an empty increment"
    );
    drop(layer);
    assert!(
        !upper.exists(),
        "the empty layer's upper is removed on drop"
    );
}

#[test]
fn hermetic_a_failed_stage_layer_disposes_of_the_upper_it_created() {
    // stage_layer creates the upper before it resolves, and a failure hands the
    // caller no BuildLayer to drop — so the upper it created has to go with the
    // failure, or a partly-installed increment (and the download cache beside
    // it) is orphaned with nothing that knows to remove it.
    //
    // The failure is an include the archive does not carry, which is refused
    // after the upper exists and before anything is downloaded.
    let dir = common::scratch_dir("debian-failed-layer");
    if let Some(blocker) = ferroday_cage::host::overlay_blocker(&dir) {
        eprintln!("skipping: overlay-rooted cages are unavailable: {blocker}");
        return;
    }
    let base_data = Tar::new().file("./usr/bin/x", 0o755, b"ok\n").finish();
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[Pkg::required("base", deb(&base_data), "")],
    );

    let base_dir = dir.join("base");
    let dpkg = base_dir.join("var/lib/dpkg");
    std::fs::create_dir_all(&dpkg).unwrap();
    std::fs::write(
        dpkg.join("status"),
        "Package: base\nStatus: install ok installed\nVersion: 1.0\n",
    )
    .unwrap();

    let upper = dir.join("upper");
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .base_layer(&base_dir)
        .include(["nonesuch"])
        .build()
        .expect("the builder validates");
    debian
        .stage_layer(&upper)
        .expect_err("an unknown include fails the staging");

    assert!(!upper.exists(), "a failed staging left its upper behind");
    assert!(
        !dir.join("upper.fcage-debs").exists(),
        "a failed staging left its package cache behind",
    );
    let mut left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, ["base", "repo"]);
}

#[test]
fn hermetic_mirror_fallback_serves_a_missing_primary() {
    // The primary mirror points at a directory that does not exist, so every
    // fetch 404s there and falls through to the backstop, which serves the whole
    // repository. A successful bootstrap proves the ordered-URL failover.
    let dir = common::scratch_dir("debian-fallback");
    let payload = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let backstop = write_repo(
        &dir.join("backstop"),
        "trixie",
        "amd64",
        &[Pkg::required("base", deb(&payload), "")],
    );
    // A file:// URL to a path that was never created: every resource under it is
    // reported missing, the signal the mirror walk advances past.
    let missing = format!("file://{}", dir.join("does-not-exist").display());

    let rootfs = dir.join("rootfs");
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(missing)
        .mirror_fallback(backstop)
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .build()
        .expect("the builder validates");
    assert_eq!(
        provision::ensure(&rootfs, &mut debian).expect("the fallback bootstrap runs"),
        Provisioned::Created,
    );
    assert!(rootfs.join("usr/bin/x").is_file());
}

#[test]
fn an_archive_coordinate_the_repository_cannot_be_addressed_by_is_refused() {
    // The suite, the components, and the architecture become path segments of
    // every URL a repository is fetched through, and words of the `deb` line
    // written into the finished rootfs. A `..` segment climbs out of the mirror
    // root — for a file:// mirror, a local read — and a control character splits
    // the request line the value is interpolated into, or adds a source line the
    // caller never wrote. They pass the same check the pool holds its own
    // coordinates to, so an archive this crate writes and one it reads agree on
    // what an archive may be called.
    let refused = |what: &str, build: Result<Debian<'_>, _>| match build {
        Err(ferroday_cage::provision::debian::DebianError::Config { reason, .. }) => {
            assert!(reason.contains(what), "{what}: {reason}");
        }
        other => panic!("{what} should be refused, got {other:?}"),
    };
    let base = || {
        Debian::builder("trixie")
            .mirror("file:///srv/debs")
            .trust_unsigned(true)
    };

    for suite in ["../../etc", "/etc", "a//b", "with space", "a\r\nX: 1"] {
        refused(
            "suite",
            Debian::builder(suite)
                .mirror("file:///srv/debs")
                .trust_unsigned(true)
                .build(),
        );
    }
    refused(
        "component",
        base().components(["main", "../../etc"]).build(),
    );
    refused("architecture", base().architecture("../../etc").build());
    // An architecture is one directory name; the other two may name a subtree.
    refused("architecture", base().architecture("linux/amd64").build());
    Debian::builder("buster/updates")
        .mirror("file:///srv/debs")
        .trust_unsigned(true)
        .components(["main/debian-installer"])
        .build()
        .expect("a slashed suite and component are real layouts");

    // An additional repository is held to the same rule, at its own build.
    assert!(
        Repository::builder("../../etc")
            .mirror("file:///srv/debs")
            .trust_unsigned(true)
            .build()
            .is_err(),
        "an additional repository's suite is unchecked",
    );
}

#[test]
fn the_unsigned_path_is_refused_without_trust_unsigned() {
    // The same unsigned file:// repository, but without trust_unsigned: the
    // default path requires a signed InRelease, which the repository does not
    // carry, so provisioning fails rather than silently trusting the plain
    // Release. This is the default-secure property the other hermetic tests,
    // which all pass trust_unsigned(true), do not exercise.
    let dir = common::scratch_dir("debian-unsigned-default");
    let base = Tar::new()
        .dir("./usr", 0o755)
        .file("./usr/bin/x", 0o755, b"ok\n")
        .finish();
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[Pkg::required("base", deb(&base), "")],
    );
    let rootfs = dir.join("rootfs");
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        // No trust_unsigned: the archive signature must be present and verify.
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .build()
        .expect("the builder validates");
    assert!(
        provision::ensure(&rootfs, &mut debian).is_err(),
        "an unsigned repository must not provision without trust_unsigned",
    );
    assert!(!rootfs.exists(), "a refused bootstrap publishes nothing");
}

#[test]
fn hermetic_rejects_an_escaping_deb_entry() {
    // A package whose data.tar tries to write outside the root is refused by
    // the hardened extractor, and nothing is published.
    let dir = common::scratch_dir("debian-hostile");
    let evil = Tar::new().file("../escape", 0o644, b"pwned\n").finish();
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[Pkg::required("evil", deb(&evil), "")],
    );
    let rootfs = dir.join("rootfs");
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .build()
        .expect("the builder validates");
    let err = provision::ensure(&rootfs, &mut debian).unwrap_err();
    assert!(
        matches!(err, ProvisionError::EntryUnsafe { .. }),
        "an escaping entry is rejected: {err:?}"
    );
    assert!(!rootfs.exists(), "a failed bootstrap publishes nothing");
}

/// A control stanza for `name` at `version`, with the fields every `.deb`
/// carries and nothing else.
fn control_of(name: &str, version: &str) -> String {
    format!(
        "Package: {name}\nVersion: {version}\nArchitecture: amd64\nMaintainer: test\n\
         Description: a test package\n",
    )
}

/// The names of every file under `dir`, recursively, in no particular order.
fn files_under(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            found.extend(files_under(&entry.path()));
        } else {
            found.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    found
}

#[test]
fn hermetic_a_deb_cannot_choose_where_in_the_pool_it_is_written() {
    // The pool path a `.deb` is stored at is derived from the package's own
    // control stanza, and `Path::join` does not normalize: a `..` in the name
    // survives into the syscall and the kernel resolves it, so a publish would
    // create directories and write a file outside the pool root, as the
    // publishing user. The version reaches the same path through the file-name
    // component. Both are held to the alphabet Debian policy gives them before
    // any path is built from them.
    //
    // The pool is nested several levels inside the scratch directory so that a
    // regression here writes there rather than somewhere a test has no business
    // touching.
    let dir = common::scratch_dir("debian-pool-traversal");
    let pool = dir.join("a/b/c/d/e/pool");
    let data = Tar::new().file("./usr/bin/x", 0o755, b"ok\n").finish();

    let refused = |control: String, note: &str| {
        let path = dir.join("candidate.deb");
        std::fs::write(&path, deb_with_control(&control, &data)).unwrap();
        let reason = trixie_pool(&pool)
            .publish([&path])
            .expect_err(note)
            .to_string();
        assert!(
            reason.contains("Debian policy permits"),
            "{note} was refused for the wrong reason: {reason}",
        );
    };

    refused(control_of("../../../../escaped", "1.0"), "a climbing name");
    refused(control_of("..", "1.0"), "a name that is `..`");
    refused(control_of(".", "1.0"), "a name that is `.`");
    refused(control_of("evil/../../x", "1.0"), "a name with a separator");
    refused(control_of("Evil", "1.0"), "an upper-case name");
    refused(control_of("x", "1.0"), "a one-character name");
    refused(control_of("-lead", "1.0"), "a name starting with a dash");
    refused(control_of("tool", "1.0/../../evil"), "a slashed version");
    refused(control_of("tool", "1.0 2.0"), "a spaced version");
    refused(control_of("tool", ""), "an empty version");

    // Nothing was created along the way to any of those paths: the pool tree a
    // published package lives in was never opened.
    assert!(
        !pool.join("pool").exists(),
        "a refused publish created a pool tree",
    );
    let stray: Vec<String> = files_under(&dir)
        .into_iter()
        .filter(|name| name.contains("escaped") || name.contains("evil"))
        .collect();
    assert!(stray.is_empty(), "a refused publish wrote {stray:?}");

    // An ordinary package still publishes, epoch and all: the check is of the
    // alphabet, not of the punctuation a real version uses.
    let path = dir.join("ok.deb");
    let control = control_of("tool", "2:1.3-1~bpo12+1");
    std::fs::write(&path, deb_with_control(&control, &data)).unwrap();
    trixie_pool(&pool)
        .publish([&path])
        .expect("an ordinary package publishes");
    assert!(
        pool.join("pool/main/t/tool/tool_1.3-1~bpo12+1_amd64.deb")
            .is_file(),
        "the published file is not where the archive convention puts it",
    );
}

#[test]
fn hermetic_a_deb_cannot_write_its_own_index_entry() {
    // A pool entry is the control file verbatim with Filename, Size, and SHA256
    // appended, and a deb822 reader resolves a field by its first occurrence. A
    // control file carrying one of those would shadow the archive's value: the
    // recorded digest would be one the package chose rather than one taken from
    // the bytes on disk, and the recorded Filename could name another package's
    // file in the same pool.
    //
    // A control file of several paragraphs reaches the same place by another
    // route: the appended fields land on the last, which is then the paragraph
    // that reads back as the entry — under whatever name and version it
    // declares, while the dedupe that placed it keyed on the first. A pool is
    // consumed as [trusted=yes] and resolution is highest-version-wins across
    // repositories, so an entry a package wrote for itself supersedes the
    // primary archive's.
    let dir = common::scratch_dir("debian-pool-shadowing");
    let pool = dir.join("pool");
    let data = Tar::new().file("./usr/bin/x", 0o755, b"ok\n").finish();

    let refused = |control: String, expected: &str, note: &str| {
        let path = dir.join("candidate.deb");
        std::fs::write(&path, deb_with_control(&control, &data)).unwrap();
        let reason = trixie_pool(&pool)
            .publish([&path])
            .expect_err(note)
            .to_string();
        assert!(
            reason.contains(expected),
            "{note} was refused for the wrong reason: {reason}",
        );
    };

    for field in ["Filename", "Size", "SHA256"] {
        refused(
            format!(
                "{}{field}: pool/main/o/other/other_1.0_amd64.deb\n",
                control_of("tool", "1.0")
            ),
            field,
            &format!("a control file carrying {field}"),
        );
    }
    refused(
        format!(
            "{}\n{}",
            control_of("tool", "1.0"),
            control_of("libc6", "99.0"),
        ),
        "paragraphs",
        "a control file of two paragraphs",
    );

    assert!(
        !pool.join("pool").exists(),
        "a refused publish created a pool tree",
    );

    // The well-formed case still publishes, and the index it writes carries the
    // archive's own values: the digest of the bytes in the pool, and the path
    // the pool chose.
    let path = dir.join("ok.deb");
    let deb = deb_with_control(&control_of("tool", "1.0"), &data);
    std::fs::write(&path, &deb).unwrap();
    trixie_pool(&pool)
        .publish([&path])
        .expect("a well-formed package publishes");
    let index =
        std::fs::read_to_string(pool.join("dists/trixie/main/binary-amd64/Packages")).unwrap();
    assert!(
        index.contains(&format!("SHA256: {}", common::deb_repo::sha256_hex(&deb))),
        "the index does not record the digest of the published bytes: {index}",
    );
    assert!(
        index.contains("Filename: pool/main/t/tool/tool_1.0_amd64.deb"),
        "the index does not record the path the pool chose: {index}",
    );
}

#[test]
fn hermetic_a_failed_bootstrap_leaves_no_package_cache_behind() {
    // Without a cache directory the packages are downloaded into a sibling of
    // the staging tree — a sibling because an extracted package's entries land
    // under the staging root, so a cache beneath it could be overwritten before
    // it is read. Nothing else clears that sibling: the publication's own
    // cleanup removes the staging tree, and provision::remove removes the
    // destination and its lock. So a failure partway has to take it, or a failed
    // bootstrap leaves a base system's worth of .debs beside a rootfs that was
    // never published.
    //
    // The failure is an escaping archive entry, which happens after the download
    // has populated the cache.
    let dir = common::scratch_dir("debian-failed-cache");
    let evil = Tar::new().file("../escape", 0o644, b"pwned\n").finish();
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[Pkg::required("evil", deb(&evil), "")],
    );

    let rootfs = dir.join("rootfs");
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .extract_only(true)
        .build()
        .expect("the builder validates");
    provision::ensure(&rootfs, &mut debian).expect_err("an escaping entry fails the bootstrap");

    assert!(!rootfs.exists(), "a failed bootstrap publishes nothing");
    // The staging tree and the cache beside it, by the names the run derives.
    assert!(!dir.join(".rootfs.staging").exists(), "the staging tree");
    assert!(
        !dir.join(".rootfs.staging.fcage-debs").exists(),
        "the package cache",
    );
    // And nothing else either: what is left is the repository the test wrote
    // and the publication lock, which `provision::remove` clears.
    let mut left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, ["repo", "rootfs.lock"]);
}

#[test]
fn hermetic_rejects_a_digest_mismatch() {
    // The index records a digest; a package whose bytes do not match it is
    // rejected rather than installed.
    let dir = common::scratch_dir("debian-mismatch");
    let repo = dir.join("repo");
    let good = Tar::new().file("./usr/bin/x", 0o755, b"ok\n").finish();
    write_repo(
        &repo,
        "trixie",
        "amd64",
        &[Pkg::required("base", deb(&good), "")],
    );
    // Corrupt the published package so its bytes no longer match the index,
    // without changing its length: the download is bounded by the size the
    // index records, and a longer body would be refused at that bound before
    // the digest was reached. This is the digest's own test.
    let pool_deb = repo.join("pool/base_1.0_amd64.deb");
    let mut bytes = std::fs::read(&pool_deb).unwrap();
    *bytes.last_mut().unwrap() ^= 0xff;
    std::fs::write(&pool_deb, &bytes).unwrap();

    let rootfs = dir.join("rootfs");
    let mirror = format!("file://{}", repo.display());
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .build()
        .expect("the builder validates");
    let err = provision::ensure(&rootfs, &mut debian).unwrap_err();
    let ProvisionError::Other { source: inner, .. } = &err else {
        panic!("expected a boxed Debian error, got {err:?}");
    };
    assert!(
        inner.to_string().contains("digest"),
        "a digest mismatch is reported: {inner}"
    );
    assert!(!rootfs.exists());
}

#[test]
fn hermetic_stops_a_package_at_the_size_the_index_recorded() {
    // The index records what the package weighs, so a mirror serving more is
    // serving something else. The download stops at that bound rather than
    // spending disk on the whole of it and discovering the substitution at the
    // digest afterward.
    let dir = common::scratch_dir("debian-oversized");
    let repo = dir.join("repo");
    let good = Tar::new().file("./usr/bin/x", 0o755, b"ok\n").finish();
    write_repo(
        &repo,
        "trixie",
        "amd64",
        &[Pkg::required("base", deb(&good), "")],
    );
    // Grow the published package well past its recorded size.
    let pool_deb = repo.join("pool/base_1.0_amd64.deb");
    let mut bytes = std::fs::read(&pool_deb).unwrap();
    bytes.resize(bytes.len() + 4 * 1024 * 1024, b'x');
    std::fs::write(&pool_deb, &bytes).unwrap();

    let rootfs = dir.join("rootfs");
    let cache = dir.join("cache");
    let mirror = format!("file://{}", repo.display());
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .cache_dir(&cache)
        .extract_only(true)
        .build()
        .expect("the builder validates");
    let err = provision::ensure(&rootfs, &mut debian).unwrap_err();
    let ProvisionError::Other { source: inner, .. } = &err else {
        panic!("expected a boxed Debian error, got {err:?}");
    };
    assert!(
        inner.to_string().contains("maximum size"),
        "the oversized body is refused at the bound: {inner}"
    );
    assert!(!rootfs.exists());
    // Nothing oversized was left in the cache, and nothing was published there.
    let cached: u64 = std::fs::read_dir(&cache)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.metadata().unwrap().len())
        .sum();
    assert!(
        cached < bytes.len() as u64,
        "the whole oversized body reached the cache",
    );
}

#[test]
fn extract_only_bootstraps_a_trixie_tree() {
    if !network_enabled() {
        return;
    }
    let rootfs = common::scratch_dir("debian-extract").join("rootfs");
    let mut debian = Debian::builder("trixie")
        .cache_dir(deb_cache())
        .extract_only(true)
        .build()
        .expect("the builder validates");

    let outcome = provision::ensure(&rootfs, &mut debian).expect("the extract-only bootstrap runs");
    assert_eq!(outcome, Provisioned::Created);

    // The base system's files are laid out, merged-usr is in place, and the
    // dpkg database is initialized — but nothing is configured.
    assert!(rootfs.join("usr/bin/dpkg").is_file(), "dpkg is extracted");
    assert!(
        rootfs.join("bin").is_symlink(),
        "merged-usr /bin is a symlink"
    );
    assert!(
        Path::new(&rootfs.join("usr/bin/sh")).is_symlink(),
        "dash provides /usr/bin/sh"
    );
    // The dpkg database is initialized but empty: extract-only runs no
    // maintainer scripts, so nothing is configured.
    assert!(
        rootfs.join("var/lib/dpkg/status").is_file(),
        "the dpkg status database is initialized"
    );
    assert_eq!(
        std::fs::read_to_string(rootfs.join("var/lib/dpkg/status")).unwrap(),
        "",
        "extract-only leaves the status database empty"
    );
    // The setgid shadow helper is laid out (root-owned, as everything is
    // under the single-identity map) but not configured.
    assert!(rootfs.join("usr/sbin/unix_chkpwd").is_file());
}

#[test]
fn full_bootstrap_configures_a_runnable_trixie() {
    if !network_enabled() {
        return;
    }
    let Some(_) = common::fixture_rootfs() else {
        // The full bootstrap runs dpkg inside a cage, which needs user
        // namespaces; the fixture probe reports the skip.
        return;
    };
    let rootfs = common::scratch_dir("debian-full").join("rootfs");
    // The provisioner borrows the progress sink, so both are scoped and
    // dropped before the finished rootfs is exercised.
    {
        let mut progress = |event: DebianEvent<'_>| {
            if let DebianEvent::CommandOutput { bytes, .. } = event {
                use std::io::Write;
                let _ = std::io::stderr().write_all(bytes);
            }
        };
        let mut debian = Debian::builder("trixie")
            .cache_dir(deb_cache())
            .build()
            .expect("the builder validates");
        provision::ensure(&rootfs, &mut debian.observe(&mut progress))
            .expect("the full bootstrap runs");
    }

    // The finished rootfs is apt-usable: the archive keyring is written as the
    // signed-by trust anchor, and the sources.list references it. The base
    // closure does not install debian-archive-keyring, so without this the
    // apt-get update below would have no key to verify the release against.
    let anchor = std::fs::read(rootfs.join("usr/share/keyrings/debian-archive-keyring.gpg"))
        .expect("the trust anchor is written");
    assert!(
        !anchor.is_empty(),
        "the trust anchor holds the archive keyring the release was verified against",
    );
    let sources = std::fs::read_to_string(rootfs.join("etc/apt/sources.list"))
        .expect("the sources.list is written");
    assert!(
        sources.contains("[signed-by=/usr/share/keyrings/debian-archive-keyring.gpg]"),
        "the sources.list is signed-by the trust anchor: {sources:?}"
    );

    // Every base package reached the installed state; run dpkg in the cage
    // to prove the userland is configured and executable.
    let status = ferroday_cage::Cage::builder()
        .rootfs(&rootfs)
        .command("/usr/bin/dpkg")
        .args(["--list"])
        .build()
        .expect("the cage builds")
        .run()
        .expect("dpkg runs in the finished rootfs");
    assert!(
        status.success(),
        "dpkg --list succeeds in the bootstrapped rootfs"
    );

    // The real proof of the trust anchor: apt-get update verifies the release
    // from inside the rootfs against the signed-by keyring. A missing or
    // untrusted anchor makes apt exit non-zero here.
    let status = ferroday_cage::Cage::builder()
        .rootfs(&rootfs)
        .network(ferroday_cage::Network::Host)
        .command("/usr/bin/apt-get")
        .args(["update"])
        .build()
        .expect("the cage builds")
        .run()
        .expect("apt-get runs in the finished rootfs");
    assert!(
        status.success(),
        "apt-get update verifies the release against the signed-by trust anchor"
    );
}

#[test]
fn full_bootstrap_applies_a_pre_configure_overlay() {
    if !network_enabled() {
        return;
    }
    let Some(_) = common::fixture_rootfs() else {
        return;
    };
    let scratch = common::scratch_dir("debian-overlay");

    // A rootfs-shaped overlay carrying one configuration file at a path no
    // package owns, so it survives configuration untouched and its presence
    // proves the overlay was laid during the bootstrap.
    let overlay = scratch.join("overlay");
    std::fs::create_dir_all(overlay.join("etc")).unwrap();
    std::fs::write(overlay.join("etc/fcage-overlay.conf"), b"laid-by-overlay\n").unwrap();

    let rootfs = scratch.join("rootfs");
    {
        let mut debian = Debian::builder("trixie")
            .cache_dir(deb_cache())
            .pre_configure_overlay(&overlay)
            .build()
            .expect("the builder validates");
        provision::ensure(&rootfs, &mut debian).expect("the bootstrap with an overlay runs");
    }

    assert_eq!(
        std::fs::read_to_string(rootfs.join("etc/fcage-overlay.conf")).unwrap(),
        "laid-by-overlay\n",
        "the overlay file is present in the finished rootfs",
    );
}

/// The layered build: a base provisioned once, a component's increment staged
/// over it into a disposable overlay upper, and the base left pristine.
#[test]
fn layered_build_stages_only_the_increment_over_a_pristine_base() {
    if !network_enabled() {
        return;
    }
    let Some(_) = common::fixture_rootfs() else {
        // stage_layer runs dpkg in a cage, which needs user namespaces.
        return;
    };
    let scratch = common::scratch_dir("debian-layer");
    if let Some(blocker) = ferroday_cage::host::overlay_blocker(&scratch) {
        eprintln!("skipping: overlay-rooted cages are unavailable: {blocker}");
        return;
    }

    // Provision the shared base once, the ordinary way: a configured minbase.
    let base = scratch.join("base");
    {
        let mut debian = Debian::builder("trixie")
            .cache_dir(deb_cache())
            .build()
            .expect("the builder validates");
        provision::ensure(&base, &mut debian).expect("the base bootstrap runs");
    }

    // Stage `hello` as an increment. Its only dependency, libc6, is in the base,
    // so the increment is `hello` alone.
    let upper = scratch.join("upper");
    let reported: std::cell::RefCell<Option<Plan>> = std::cell::RefCell::new(None);
    let layer = {
        let mut sink = |event: DebianEvent<'_>| match event {
            DebianEvent::Resolved { plan, .. } => *reported.borrow_mut() = Some(plan.clone()),
            DebianEvent::CommandOutput { bytes, .. } => {
                use std::io::Write;
                let _ = std::io::stderr().write_all(bytes);
            }
            _ => {}
        };
        let mut debian = Debian::builder("trixie")
            .base_layer(&base)
            .include(["hello"])
            .cache_dir(deb_cache())
            .build()
            .expect("the builder validates");
        debian
            .observe(&mut sink)
            .stage_layer(&upper)
            .expect("the increment stages")
    };

    // The increment omits the base's packages: `hello` is present, and the
    // `libc6` it depends on — configured in the base — is not re-resolved.
    let plan = reported
        .into_inner()
        .expect("a Resolved event carried the plan");
    let names: Vec<_> = plan.packages.iter().map(|p| p.name.as_str()).collect();
    assert!(
        names.contains(&"hello"),
        "the increment installs hello: {names:?}"
    );
    assert!(
        !names.contains(&"libc6"),
        "the base's libc6 is assumed satisfied, not re-resolved: {names:?}",
    );

    // The upper holds only the increment's files and dpkg state. `hello`'s binary
    // landed there; the base's own files stayed in the read-only lower.
    assert!(
        upper.join("usr/bin/hello").is_file(),
        "the increment's binary is in the upper",
    );
    assert!(
        !upper.join("usr/bin/dpkg").exists(),
        "the base's files stay in the lower, not copied into the upper",
    );
    // The base's database is unchanged; the merged database dpkg copied up into
    // the upper records the increment installed.
    assert!(
        !std::fs::read_to_string(base.join("var/lib/dpkg/status"))
            .unwrap()
            .contains("Package: hello"),
        "the base's dpkg database is untouched",
    );
    assert!(
        std::fs::read_to_string(upper.join("var/lib/dpkg/status"))
            .unwrap()
            .contains("Package: hello"),
        "the increment's dpkg state landed in the upper",
    );

    // Build against the merged view: `hello` runs, proving the overlay root joins
    // the base's C library and the increment's binary into one view.
    let status = ferroday_cage::Cage::builder()
        .overlay_rootfs(&base, layer.path())
        .command("/usr/bin/hello")
        .build()
        .expect("the overlay build cage builds")
        .run()
        .expect("hello runs in the build root");
    assert!(
        status.success(),
        "hello runs against the merged base-plus-increment view",
    );

    // Dropping the layer discards the increment; the base stays runnable.
    drop(layer);
    assert!(!upper.exists(), "the layer's upper is removed on drop");
    assert!(
        base.join("usr/bin/dpkg").is_file(),
        "the base is left pristine and intact",
    );
}

/// The range-mapped layered build: the increment is configured under the same
/// subordinate map as its base, and disposal escalates through the map to remove
/// the subordinate-owned upper and the mode-`0` overlay work directory.
#[cfg(feature = "subid")]
#[test]
fn layered_build_under_a_range_map_disposes_of_a_subordinate_owned_upper() {
    if !network_enabled() {
        return;
    }
    let Some(_) = common::fixture_rootfs() else {
        return;
    };
    let scratch = common::scratch_dir("debian-layer-ranged");
    if let Some(blocker) = ferroday_cage::host::overlay_blocker(&scratch) {
        eprintln!("skipping: overlay-rooted cages are unavailable: {blocker}");
        return;
    }
    if ferroday_cage::host::range_map_blocker().is_some() {
        eprintln!("skipping: no delegate can establish a range map");
        return;
    }

    // The base and its layer share the subordinate identity map, as they must.
    let base = scratch.join("base");
    {
        let mut debian = Debian::builder("trixie")
            .identity_map(ferroday_cage::IdentityMap::Subordinate)
            .cache_dir(deb_cache())
            .build()
            .expect("the builder validates");
        provision::ensure(&base, &mut debian).expect("the range-mapped base bootstrap runs");
    }

    let upper = scratch.join("upper");
    let layer = {
        let mut progress = |event: DebianEvent<'_>| {
            if let DebianEvent::CommandOutput { bytes, .. } = event {
                use std::io::Write;
                let _ = std::io::stderr().write_all(bytes);
            }
        };
        let mut debian = Debian::builder("trixie")
            .identity_map(ferroday_cage::IdentityMap::Subordinate)
            .base_layer(&base)
            .include(["hello"])
            .cache_dir(deb_cache())
            .build()
            .expect("the builder validates");
        debian
            .observe(&mut progress)
            .stage_layer(&upper)
            .expect("the range-mapped increment stages")
    };

    // The increment configured under the map: hello's binary is in the upper,
    // owned by a real mapped id rather than the flattened caller id.
    assert!(
        upper.join("usr/bin/hello").is_file(),
        "the increment is in the upper"
    );

    // The build runs under the same map, seeing the merged view.
    let status = ferroday_cage::Cage::builder()
        .overlay_rootfs(&base, layer.path())
        .identity_map(ferroday_cage::IdentityMap::Subordinate)
        .command("/usr/bin/hello")
        .build()
        .expect("the overlay build cage builds")
        .run()
        .expect("hello runs in the range-mapped build root");
    assert!(
        status.success(),
        "hello runs in the range-mapped build root"
    );

    // Disposal escalates through the map: the subordinate-owned upper and the
    // mode-`0` overlay work directory beside it are both removed, where a plain
    // caller-side delete could touch neither.
    drop(layer);
    assert!(
        !upper.exists(),
        "the subordinate-owned upper is removed on drop through the identity map",
    );
    assert!(base.join("usr/bin/dpkg").is_file(), "the base is intact");
}

/// The range-mapped bootstrap: real ownership, no reconciliation artifacts,
/// and a rootfs that needs — and gets — the map-assisted removal.
#[cfg(feature = "subid")]
#[test]
fn full_bootstrap_under_a_range_map_carries_real_ownership() {
    if !network_enabled() {
        return;
    }
    let Some(_) = common::fixture_rootfs() else {
        return;
    };
    if ferroday_cage::host::range_map_blocker().is_some() {
        eprintln!("skipping: no delegate can establish a range map");
        return;
    }
    let scratch = common::scratch_dir("debian-full-ranged");
    let rootfs = scratch.join("rootfs");
    {
        let mut progress = |event: DebianEvent<'_>| {
            if let DebianEvent::CommandOutput { bytes, .. } = event {
                use std::io::Write;
                let _ = std::io::stderr().write_all(bytes);
            }
        };
        let mut debian = Debian::builder("trixie")
            .identity_map(ferroday_cage::IdentityMap::Subordinate)
            .cache_dir(deb_cache())
            .build()
            .expect("the builder validates");
        provision::ensure(&rootfs, &mut debian.observe(&mut progress))
            .expect("the range-mapped bootstrap runs");
    }

    // No single-identity reconciliation happened: the statoverride seed is
    // absent, and base-passwd's shadow helper carries its real non-root
    // group — the base gid mapped through the subordinate allocation —
    // rather than the flattened root.
    assert!(
        !rootfs.join("var/lib/dpkg/statoverride").exists(),
        "a range-mapped bootstrap seeds no statoverride"
    );
    let meta = std::fs::metadata(rootfs.join("usr/sbin/unix_chkpwd"))
        .expect("the shadow helper is laid out");
    use std::os::unix::fs::MetadataExt;
    // Flattened ownership would leave the file with the caller's own gid;
    // the real shadow gid lands inside the subordinate allocation instead.
    assert_ne!(
        meta.gid(),
        rustix::process::getegid().as_raw(),
        "the shadow helper's group is a real mapped id, not the flattened caller gid",
    );

    // The finished rootfs is runnable under the same map.
    let status = ferroday_cage::Cage::builder()
        .rootfs(&rootfs)
        .command("/usr/bin/dpkg")
        .args(["--list"])
        .identity_map(ferroday_cage::IdentityMap::Subordinate)
        .build()
        .expect("the cage builds")
        .run()
        .expect("dpkg runs in the finished rootfs");
    assert!(status.success());

    // Real ownership can put parts of a tree beyond the plain caller — a
    // directory owned by a mapped non-root id refuses the unlinks inside
    // it. The base system's directories are root-owned, so this tree may
    // remove plainly; `provision::remove` covers either case, and the
    // escalated path itself is exercised by the identity tests.
    provision::remove(&rootfs).expect("the removal succeeds");
    assert!(!rootfs.exists());
}

/// A payload for a fixture package: one file under `/usr/bin` named for it.
fn payload(name: &str) -> Vec<u8> {
    deb(&Tar::new()
        .dir("./usr", 0o755)
        .dir("./usr/bin", 0o755)
        .file(&format!("./usr/bin/{name}"), 0o755, b"#!/bin/true\n")
        .finish())
}

#[test]
fn available_reports_the_names_the_archive_carries() {
    // The question a resolve cannot answer. A top-level include naming nothing
    // fails the whole resolve, so asking that way tells a caller whether every
    // name was there and never which were not.
    let dir = common::scratch_dir("debian-available");
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", payload("base"), ""),
            Pkg::ordinary("libdep", payload("libdep")),
        ],
    );

    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .build()
        .expect("the builder validates");
    let available = debian.available().expect("the index is read");

    assert!(available.contains("base"));
    assert!(available.contains("libdep"));
    assert!(!available.contains("not-in-this-archive"));
    // A real package is not a provider of itself.
    assert_eq!(available.providers("libdep").count(), 0);
}

#[test]
fn available_reports_a_virtual_name_nothing_is_named_for() {
    // The case that is the reason for the whole query: `awk` is no package's
    // name, so a resolve's closure can only say something satisfied it, and a
    // caller reporting on a package list wants to know the name resolves and
    // what satisfies it.
    let dir = common::scratch_dir("debian-available-virtual");
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", payload("base"), ""),
            Pkg::ordinary("mawk", payload("mawk")).providing("awk"),
            Pkg::ordinary("gawk", payload("gawk")).providing("awk"),
        ],
    );

    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .build()
        .expect("the builder validates");
    let available = debian.available().expect("the index is read");

    assert!(available.contains("awk"), "the virtual name resolves");
    let providers: Vec<&str> = available.providers("awk").collect();
    assert_eq!(
        providers,
        ["gawk", "mawk"],
        "sorted, so the order is stable"
    );
}

#[test]
fn available_merges_every_configured_repository() {
    let dir = common::scratch_dir("debian-available-merge");
    let primary = write_repo(
        &dir.join("primary"),
        "trixie",
        "amd64",
        &[Pkg::required("base", payload("base"), "")],
    );
    let extra = write_repo(
        &dir.join("extra"),
        "trixie",
        "amd64",
        &[Pkg::ordinary("only-here", payload("only-here"))],
    );

    let extra_repo = Repository::builder("trixie")
        .mirror(extra)
        .trust_unsigned(true)
        .name("extra")
        .build()
        .expect("the extra repository validates");
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(primary)
        .trust_unsigned(true)
        .repository(extra_repo)
        .build()
        .expect("the builder validates");
    let available = debian.available().expect("the indexes are read and merged");

    assert!(available.contains("base"), "the primary's package");
    assert!(available.contains("only-here"), "the second's package");
}

#[test]
fn available_applies_the_architecture_filter() {
    // The query answers availability for the architecture that was asked for.
    // A package published only for another one cannot be installed here, so
    // reporting it as available would be a wrong answer rather than a generous
    // one; an `all` package is installable everywhere and is reported.
    let dir = common::scratch_dir("debian-available-arch");
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", payload("base"), ""),
            Pkg::ordinary("elsewhere", payload("elsewhere")).for_architecture("riscv64"),
            Pkg::ordinary("everywhere", payload("everywhere")).for_architecture("all"),
        ],
    );

    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .build()
        .expect("the builder validates");
    let available = debian.available().expect("the index is read");

    assert!(available.contains("base"));
    assert!(
        available.contains("everywhere"),
        "an `all` package installs here"
    );
    assert!(
        !available.contains("elsewhere"),
        "another architecture's does not"
    );
}

#[test]
fn available_and_resolve_agree_on_one_index() {
    // The two read the same merged index through the same path, so every name
    // a resolve selects has to be a name the query reports. Pinning it keeps
    // the projection from drifting away from what the resolver sees.
    let dir = common::scratch_dir("debian-available-agrees");
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", payload("base"), "libdep"),
            Pkg::ordinary("libdep", payload("libdep")),
            Pkg::ordinary("tool", payload("tool")).depending_on("libdep"),
        ],
    );

    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror.clone())
        .trust_unsigned(true)
        .include(["tool"])
        .build()
        .expect("the builder validates");
    let plan = debian.resolve().expect("the plan resolves");

    // A fresh builder, since `available` ignores the include set rather than
    // consuming it, and reading through the same one would prove less.
    let mut query = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .build()
        .expect("the builder validates");
    let available = query.available().expect("the index is read");

    assert!(
        !plan.packages.is_empty(),
        "the fixture resolves to something"
    );
    for package in &plan.packages {
        assert!(
            available.contains(&package.name),
            "{} is in the plan but not reported available",
            package.name,
        );
    }
}

#[test]
fn a_plan_records_the_archive_state_it_resolved_against() {
    // A plan naming a package set says what was selected and not what it was
    // selected from, and the same suite resolves to different versions a week
    // apart. The archive record is what makes the plan a description of a
    // moment in an archive's life.
    let dir = common::scratch_dir("debian-plan-archives");
    let repo = dir.join("repo");
    let mirror = write_repo(
        &repo,
        "trixie",
        "amd64",
        &[
            Pkg::required("base", payload("base"), "libdep"),
            Pkg::ordinary("libdep", payload("libdep")),
        ],
    );

    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror.clone())
        .trust_unsigned(true)
        .build()
        .expect("the builder validates");
    let plan = debian.resolve().expect("the plan resolves");

    assert_eq!(plan.archives.len(), 1);
    let archive = &plan.archives[0];
    assert_eq!(archive.mirror, mirror);
    assert_eq!(archive.suite, "trixie");
    assert_eq!(archive.components, ["main"]);
    // The digest is of the release body that was read, which for an unsigned
    // repository is the Release file itself.
    let release = std::fs::read(repo.join("dists/trixie/Release")).unwrap();
    assert_eq!(
        archive.release_sha256,
        common::deb_repo::sha256_hex(&release)
    );
    // Nothing verified it, so no key is named. An empty list is the record of
    // that, not an omission.
    assert!(archive.signed_by.is_empty(), "{:?}", archive.signed_by);
    // Every package resolved from the only archive there is.
    assert!(plan.packages.iter().all(|package| package.archive == 0));
}

#[test]
fn a_plan_records_the_mirror_that_served_rather_than_the_one_configured_first() {
    // A repository with a snapshot backstop resolves against whichever URL
    // answered. Recording the configured list would describe a choice rather
    // than the choice made, and a caller replaying the plan would go to a
    // mirror that never served it.
    let dir = common::scratch_dir("debian-plan-backstop");
    let backstop = write_repo(
        &dir.join("backstop"),
        "trixie",
        "amd64",
        &[Pkg::required("base", payload("base"), "")],
    );
    let missing = format!("file://{}", dir.join("does-not-exist").display());

    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(missing.clone())
        .mirror_fallback(backstop.clone())
        .trust_unsigned(true)
        .build()
        .expect("the builder validates");
    let plan = debian.resolve().expect("the backstop serves the resolve");

    assert_eq!(plan.archives.len(), 1);
    assert_eq!(plan.archives[0].mirror, backstop);
    assert_ne!(plan.archives[0].mirror, missing);
}

#[test]
fn a_plan_indexes_each_package_to_the_archive_its_version_came_from() {
    // Resolution is highest-version-wins across the merged repositories, so
    // with more than one configured the archive index is the only thing that
    // says where a package will actually be fetched from.
    let dir = common::scratch_dir("debian-plan-multirepo");
    let primary = write_repo(
        &dir.join("primary"),
        "trixie",
        "amd64",
        &[Pkg::required("base", payload("base"), "")],
    );
    let feature = write_repo(
        &dir.join("feature"),
        "trixie",
        "amd64",
        &[Pkg::ordinary("custom", payload("custom"))],
    );
    let feature_repo = Repository::builder("trixie")
        .mirror(feature.clone())
        .trust_unsigned(true)
        .name("feature")
        .build()
        .expect("the feature repository validates");

    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(primary.clone())
        .trust_unsigned(true)
        .include(["custom"])
        .repository(feature_repo)
        .build()
        .expect("the builder validates");
    let plan = debian.resolve().expect("the plan resolves");

    assert_eq!(plan.archives.len(), 2, "one record per repository");
    assert_eq!(plan.archives[0].mirror, primary, "the primary leads");
    assert_eq!(plan.archives[1].mirror, feature);

    let index_of = |name: &str| {
        plan.packages
            .iter()
            .find(|package| package.name == name)
            .unwrap_or_else(|| panic!("{name} is in the plan"))
            .archive
    };
    assert_eq!(index_of("base"), 0, "the primary's package");
    assert_eq!(index_of("custom"), 1, "the second repository's package");
    // And the index names a real archive, so a caller can follow it to a URL.
    assert_eq!(plan.archives[index_of("custom")].mirror, feature);
}

/// A fetcher that records every URL it is asked for and otherwise reads from
/// the `file://` mirrors the hermetic fixtures write.
///
/// The `.deb` fetch has to work for a pinned install to finish, so this wraps
/// the ordinary transport rather than replacing it: the assertion is about what
/// was *not* asked for.
#[derive(Default)]
struct Watching {
    asked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl ferroday_cage::provision::Fetch for Watching {
    fn fetch(
        &mut self,
        request: &ferroday_cage::provision::FetchRequest<'_>,
        sink: &mut dyn std::io::Write,
    ) -> Result<(), ferroday_cage::provision::FetchError> {
        self.asked
            .lock()
            .expect("the URL log is not poisoned")
            .push(request.url().to_string());
        ferroday_cage::provision::HttpFetch::new().fetch(request, sink)
    }
}

/// Builds a two-package hermetic repository and returns its scratch directory,
/// its mirror URL, and the plan a resolve against it produces.
fn resolved_fixture(name: &str) -> (std::path::PathBuf, String, Plan) {
    let dir = common::scratch_dir(name);
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", payload("base"), "libdep"),
            Pkg::ordinary("libdep", payload("libdep")),
        ],
    );
    let plan = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror.clone())
        .trust_unsigned(true)
        .build()
        .expect("the builder validates")
        .resolve()
        .expect("the plan resolves");
    (dir, mirror, plan)
}

#[test]
fn a_pinned_plan_installs_the_tree_the_resolve_that_made_it_would_have() {
    // The primitive a reproduce mode is missing: resolve once, install from
    // that, and get what the inline resolution would have laid down.
    let (dir, mirror, plan) = resolved_fixture("debian-pinned-same-tree");

    let inline_rootfs = dir.join("inline");
    let mut inline = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror.clone())
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .build()
        .expect("the builder validates");
    provision::ensure(&inline_rootfs, &mut inline).expect("the inline bootstrap runs");

    let pinned_rootfs = dir.join("pinned");
    let mut pinned = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .plan(plan)
        .build()
        .expect("the pinned builder validates");
    provision::ensure(&pinned_rootfs, &mut pinned).expect("the pinned bootstrap runs");

    for entry in ["usr/bin/base", "usr/bin/libdep"] {
        assert!(
            pinned_rootfs.join(entry).is_file(),
            "{entry} is missing from the pinned tree",
        );
        assert_eq!(
            std::fs::read(inline_rootfs.join(entry)).unwrap(),
            std::fs::read(pinned_rootfs.join(entry)).unwrap(),
            "{entry} differs between the two trees",
        );
    }
}

#[test]
fn a_plan_kept_as_a_document_installs_what_the_plan_it_came_from_would_have() {
    // The reproduce case the same-process handoff does not cover: resolve on
    // one machine, keep the plan on disk, and replay it later. The document is
    // the whole interchange — nothing else travels — so a plan that survives it
    // must install byte for byte what the plan it was written from would have.
    let (dir, mirror, plan) = resolved_fixture("debian-plan-document");

    let kept = dir.join("trixie.plan");
    std::fs::write(&kept, plan.to_document().expect("the plan renders")).unwrap();
    let read = ferroday_cage::provision::debian::Plan::parse_document(
        &std::fs::read_to_string(&kept).unwrap(),
    )
    .expect("the kept document reads");
    assert_eq!(read, plan, "the document did not carry the plan intact");

    let inline_rootfs = dir.join("inline");
    let mut inline = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror.clone())
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .plan(plan)
        .build()
        .expect("the builder validates");
    provision::ensure(&inline_rootfs, &mut inline).expect("the in-process plan installs");

    let replayed_rootfs = dir.join("replayed");
    let mut replayed = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .plan(read)
        .build()
        .expect("the replayed builder validates");
    provision::ensure(&replayed_rootfs, &mut replayed).expect("the kept plan installs");

    for entry in ["usr/bin/base", "usr/bin/libdep"] {
        assert_eq!(
            std::fs::read(inline_rootfs.join(entry)).unwrap(),
            std::fs::read(replayed_rootfs.join(entry)).unwrap(),
            "{entry} differs between the in-process plan and the kept one",
        );
    }
}

/// The guide prints a sample plan document. It is only worth printing if it is
/// what the library actually emits, so it is parsed and re-rendered here rather
/// than trusted: a change to the format that nobody carried into the guide
/// leaves a sample that reads plausibly and is wrong.
///
/// A locked-down sample only covers the cases it contains, so the sample is
/// itself checked for the ones this test exists to catch. The rendering of an
/// empty field is the first of them: `Signed-By: ` with a trailing space was
/// the defect that made this a test rather than a one-off check, and a sample
/// whose every archive is signed would have rendered identically before and
/// after that fix.
#[test]
fn the_guides_sample_document_is_what_the_library_emits() {
    const GUIDE: &str = include_str!("../../../docs/src/debian.md");

    let start = GUIDE
        .find("### Keeping a plan")
        .expect("the guide still has the plan-document section");
    let block = GUIDE[start..]
        .split_once("```text\n")
        .expect("the section still prints a sample")
        .1
        .split_once("```")
        .expect("the sample is fenced")
        .0;

    // An empty field, so the bare-colon rendering is exercised rather than
    // only described in the prose beside it.
    assert!(
        block.contains("\nSigned-By:\n"),
        "the sample has no unsigned archive, so it does not cover the empty-field \
         rendering this test was written for:\n{block}",
    );
    // And an archive a package actually refers to by index, so the sample
    // covers a plan with more than one repository.
    assert!(block.contains("\nArchive: 1\n"), "{block}");

    let plan = ferroday_cage::provision::debian::Plan::parse_document(block)
        .expect("the guide's sample reads");
    let rendered = plan.to_document().expect("and renders");
    // Every stanza ends in a blank line, so a document ends in two newlines. A
    // fenced block cannot show that last blank line, so it is the one
    // difference the comparison allows.
    assert_eq!(
        rendered.trim_end_matches('\n'),
        block.trim_end_matches('\n'),
        "the guide's sample is not what the library emits",
    );
    assert!(rendered.ends_with("\n\n"), "{rendered:?}");
}

#[test]
fn a_pinned_install_fetches_no_release_and_no_index() {
    // The whole win, asserted through the fetcher seam: skipping the release
    // and the index is what removes a 9 MB download from a reproduce run, and
    // it is checkable without a network.
    let (dir, mirror, plan) = resolved_fixture("debian-pinned-no-index");

    let watcher = Watching::default();
    let asked = std::sync::Arc::clone(&watcher.asked);
    let mut pinned = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .plan(plan)
        .fetcher(Box::new(watcher))
        .build()
        .expect("the pinned builder validates");
    provision::ensure(dir.join("rootfs"), &mut pinned).expect("the pinned bootstrap runs");

    let urls = asked.lock().unwrap().clone();
    assert!(!urls.is_empty(), "the packages were still fetched");
    for url in &urls {
        assert!(
            !url.contains("/dists/"),
            "a pinned install touched archive metadata: {url}",
        );
        assert!(url.contains("/pool/"), "only packages are fetched: {url}");
    }
}

#[test]
fn a_pinned_install_survives_an_archive_that_has_moved_on() {
    // The point of pinning. The repository republishes with a newer version
    // and without the one the plan names; the plan still installs its own
    // versions, because it never consults the index that no longer offers them.
    let dir = common::scratch_dir("debian-pinned-moved-on");
    let repo = dir.join("repo");
    let mirror = write_repo(
        &repo,
        "trixie",
        "amd64",
        &[Pkg::required("base", payload("base"), "")],
    );
    let plan = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror.clone())
        .trust_unsigned(true)
        .build()
        .expect("the builder validates")
        .resolve()
        .expect("the plan resolves");
    let pinned_version = plan.packages[0].version.clone();

    // The archive publishes on: a new version, and the index no longer names
    // the old one. The pool file the plan points at is left in place, as a real
    // archive leaves a superseded .deb until it is culled.
    let mut newer = Pkg::required("base", payload("base-2"), "");
    newer.version = "2.0".to_string();
    write_repo(&repo, "trixie", "amd64", &[newer]);

    let rootfs = dir.join("rootfs");
    let mut pinned = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .plan(plan)
        .build()
        .expect("the pinned builder validates");
    provision::ensure(&rootfs, &mut pinned).expect("the pinned bootstrap runs");

    assert_eq!(pinned_version, "1.0");
    assert!(rootfs.join("usr/bin/base").is_file());
}

#[test]
fn a_pinned_install_whose_package_is_gone_fails_naming_the_package() {
    // The failure a caller has to be able to read: the plan is intact and the
    // archive no longer holds what it names, which is a different problem from
    // a resolution that found nothing.
    let (dir, mirror, plan) = resolved_fixture("debian-pinned-missing-deb");
    let gone = plan.packages[0].filename.clone();
    std::fs::remove_file(dir.join("repo").join(&gone)).expect("the pool file is removable");

    let mut pinned = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .plan(plan)
        .build()
        .expect("the pinned builder validates");
    let err = provision::ensure(dir.join("rootfs"), &mut pinned).unwrap_err();
    let ProvisionError::Other { source: inner, .. } = &err else {
        panic!("expected a boxed Debian error, got {err:?}");
    };
    let message = inner.to_string();
    assert!(
        message.contains(&gone),
        "the report names the package: {message}"
    );
}

#[test]
fn a_pinned_install_refuses_a_digest_mismatch_without_trying_elsewhere() {
    // The plan is the trust anchor, so the digest it records is the whole of
    // what a fetched .deb is held to. A mismatch means the bytes are not the
    // ones the plan was made from; another mirror cannot make that true.
    let (dir, mirror, plan) = resolved_fixture("debian-pinned-mismatch");
    let pool_deb = dir.join("repo").join(&plan.packages[0].filename);
    let mut bytes = std::fs::read(&pool_deb).unwrap();
    bytes.extend_from_slice(b"tampered");
    std::fs::write(&pool_deb, &bytes).unwrap();

    let mut pinned = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        // A backstop that would serve, so this proves the failure is terminal
        // rather than merely unrecoverable for want of an alternative.
        .mirror_fallback(format!("file://{}", dir.join("repo").display()))
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .plan(plan)
        .build()
        .expect("the pinned builder validates");
    let err = provision::ensure(dir.join("rootfs"), &mut pinned).unwrap_err();
    let ProvisionError::Other { source: inner, .. } = &err else {
        panic!("expected a boxed Debian error, got {err:?}");
    };
    assert!(
        inner.to_string().contains("digest"),
        "a digest mismatch is reported: {inner}",
    );
}

#[test]
fn a_plan_refuses_every_setting_that_would_shape_a_resolution() {
    // Each refusal names what conflicts, rather than the build picking a silent
    // precedence between a plan and a setting that contradicts it.
    let (_dir, mirror, plan) = resolved_fixture("debian-pinned-conflicts");

    let base = |plan: Plan| {
        Debian::builder("trixie")
            .architecture("amd64")
            .mirror(mirror.clone())
            .trust_unsigned(true)
            .plan(plan)
    };
    let refusal =
        |builder: ferroday_cage::provision::debian::DebianBuilder<'_>| match builder.build() {
            Err(ferroday_cage::provision::debian::DebianError::Config { reason, .. }) => reason,
            other => panic!("expected a configuration refusal, got {other:?}"),
        };

    assert!(refusal(base(plan.clone()).include(["git"])).contains("include()"));
    assert!(refusal(base(plan.clone()).exclude(["git"])).contains("exclude()"));
    assert!(
        refusal(
            base(plan.clone()).base_priority(ferroday_cage::provision::debian::Priority::Important)
        )
        .contains("base_priority()"),
    );

    // A plan for another suite or architecture describes a different tree.
    let mut elsewhere = plan.clone();
    elsewhere.suite = "bookworm".to_string();
    assert!(refusal(base(elsewhere)).contains("bookworm"));
    let mut foreign = plan.clone();
    foreign.architecture = "riscv64".to_string();
    assert!(refusal(base(foreign)).contains("riscv64"));

    // And a plan resolved against more archives than there are repositories has
    // packages naming a mirror that is not configured.
    let mut wider = plan.clone();
    let extra = wider.archives[0].clone();
    wider.archives.push(extra);
    assert!(refusal(base(wider)).contains("2 archives"));

    // The archive count bounds a plan whose packages agree with its own archive
    // list, which is every plan a document produced. `Plan` is public and
    // `Clone`, though, so a caller can take one from `resolve()` and edit a
    // package's archive index past the end — and the index is what a bootstrap
    // slices the repository list with, so an unchecked one is a panic partway
    // through a download rather than a refusal at build time.
    let mut edited = plan.clone();
    edited.packages[0].archive = 7;
    let reason = refusal(base(edited));
    assert!(reason.contains("archive 7"), "{reason}");

    // Same route, and the fields that become a URL rather than an index. The
    // pool path is interpolated verbatim into the fetch URL, so an edited one
    // could ask a mirror for something above its root; the digest is compared
    // with a plain `==`, so one spelled any other way could only ever mismatch.
    let mut traversing = plan.clone();
    traversing.packages[0].filename = "../../../etc/passwd".to_string();
    let reason = refusal(base(traversing));
    assert!(reason.contains("asked for"), "{reason}");

    let mut shouted = plan;
    shouted.packages[0].sha256 = shouted.packages[0].sha256.to_uppercase();
    let reason = refusal(base(shouted));
    assert!(reason.contains("lowercase hex"), "{reason}");
}

/// A package at an explicit version, which [`Pkg::ordinary`] fixes at `1.0`.
fn at_version(name: &str, version: &str, deb: Vec<u8>) -> Pkg {
    Pkg {
        version: version.to_string(),
        ..Pkg::ordinary(name, deb)
    }
}

/// A payload at a fixed path carrying the given bytes, so two builds of one
/// package are told apart by what they installed rather than by where.
fn payload_holding(contents: &[u8]) -> Vec<u8> {
    deb(&Tar::new()
        .dir("./usr", 0o755)
        .dir("./usr/bin", 0o755)
        .file("./usr/bin/x", 0o755, contents)
        .finish())
}

#[test]
fn hermetic_a_pin_selects_its_version_where_the_archive_offers_a_higher_one() {
    // What a pin is for: the archive has published since the plan was taken and
    // still offers both versions, as a snapshot mirror does. The unpinned
    // resolution takes the newer one and the pinned resolution does not, from
    // the same archive in the same test.
    let dir = common::scratch_dir("debian-pin-selects");
    let repo = dir.join("repo");
    let old = payload_holding(b"one\n");
    let new = payload_holding(b"two\n");
    let mirror = write_repo(
        &repo,
        "trixie",
        "amd64",
        &[
            Pkg {
                priority: "required".to_string(),
                ..at_version("base", "1.0", old.clone())
            },
            Pkg {
                priority: "required".to_string(),
                ..at_version("base", "2.0", new)
            },
        ],
    );

    let build = || {
        Debian::builder("trixie")
            .architecture("amd64")
            .mirror(mirror.clone())
            .trust_unsigned(true)
            .cache_dir(dir.join("cache"))
            .extract_only(true)
    };

    // Unpinned, the archive's newest wins.
    let live = build().build().expect("the builder validates");
    let live = live_resolve(live);
    assert_eq!(live.packages[0].version, "2.0");

    // Pinned to the older one, the resolution holds there — and reports the
    // digest of the version it held to, not the one it passed over.
    let mut pin = live.clone();
    pin.packages[0].version = "1.0".to_string();
    pin.packages[0].sha256 = common::deb_repo::sha256_hex(&old);
    pin.packages[0].filename = "pool/base_1.0_amd64.deb".to_string();

    let mut debian = build().pin(pin).build().expect("the pin validates");
    let held = debian.resolve().expect("the pinned version is offered");
    assert_eq!(held.packages[0].version, "1.0");
    assert_eq!(held.packages[0].sha256, common::deb_repo::sha256_hex(&old));

    // And the bootstrap installs what the pin held to, not what the archive
    // would have chosen.
    let rootfs = dir.join("rootfs");
    assert_eq!(
        provision::ensure(&rootfs, &mut debian).expect("the pinned bootstrap runs"),
        Provisioned::Created,
    );
    assert_eq!(std::fs::read(rootfs.join("usr/bin/x")).unwrap(), b"one\n");
}

/// Resolves a bootstrap, taking it by value so a builder chain reads in one
/// expression.
fn live_resolve(mut debian: Debian<'_>) -> Plan {
    debian.resolve().expect("the resolution runs")
}

#[test]
fn hermetic_a_pin_the_archive_has_moved_past_names_what_it_offers() {
    // The archive replaced the version rather than keeping both, which is what
    // an ordinary suite does. The pin cannot be held, and the refusal says what
    // is there instead rather than only that something is missing.
    let dir = common::scratch_dir("debian-pin-moved");
    let repo = dir.join("repo");
    let mirror = write_repo(
        &repo,
        "trixie",
        "amd64",
        &[Pkg {
            priority: "required".to_string(),
            ..at_version("base", "1.0", payload_holding(b"one\n"))
        }],
    );
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror.clone())
        .trust_unsigned(true)
        .build()
        .expect("the builder validates");
    let pin = debian.resolve().expect("the first resolution runs");

    // The archive publishes 2.0 over 1.0, and drops the package `gone`
    // entirely — the two failures a pin distinguishes.
    write_repo(
        &repo,
        "trixie",
        "amd64",
        &[Pkg {
            priority: "required".to_string(),
            ..at_version("base", "2.0", payload_holding(b"two\n"))
        }],
    );

    let mut dropped = pin.clone();
    let mut gone = dropped.packages[0].clone();
    gone.name = "gone".to_string();
    dropped.packages.push(gone);

    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .pin(dropped)
        .build()
        .expect("the pin validates against the configuration");

    let refusal = debian.resolve().expect_err("the pin cannot be held");
    let rendered = refusal.to_string();
    assert!(rendered.contains("base is pinned to 1.0"), "{rendered}");
    assert!(rendered.contains("offer 2.0"), "{rendered}");
    assert!(
        rendered.contains("gone is pinned to 1.0 and the archives offer no version of it"),
        "{rendered}",
    );
    // Reported in name order, so a diff across two archive publishes is stable.
    assert!(
        rendered.find("base is pinned").unwrap() < rendered.find("gone is pinned").unwrap(),
        "{rendered}",
    );
}

#[test]
fn hermetic_a_pin_holds_the_archive_half_and_lets_a_local_build_float() {
    // The shape a pin exists for. The archive half of a build is fixed by a
    // committed document; the half the build compiles for itself is published
    // to a local repository and pinned by nothing, because a compile that is
    // not byte-reproducible produces a different digest each time. Handing the
    // whole plan to plan() refuses that build; pinning only the archive half
    // resolves it.
    let dir = common::scratch_dir("debian-pin-local");
    let archive = write_repo(
        &dir.join("archive"),
        "trixie",
        "amd64",
        &[Pkg::required("base", payload_holding(b"base\n"), "")],
    );
    let local = dir.join("local");
    let built = write_repo(
        &local,
        "trixie",
        "amd64",
        &[at_version(
            "kernel",
            "6.12",
            payload_holding(b"first compile\n"),
        )],
    );

    let local_repo = Repository::builder("trixie")
        .mirror(built.clone())
        .trust_unsigned(true)
        .name("local")
        .build()
        .expect("the local repository validates");
    // A plan names every package to install, so the replay below composes with
    // no include(); the selecting builds carry one and the replay does not.
    let base = |repo: Repository| {
        Debian::builder("trixie")
            .architecture("amd64")
            .mirror(archive.clone())
            .trust_unsigned(true)
            .repository(repo)
            .cache_dir(dir.join("cache"))
            .extract_only(true)
    };
    let build = |repo: Repository| base(repo).include(["kernel"]);

    let mut debian = build(local_repo.clone())
        .build()
        .expect("the builder validates");
    let plan = debian.resolve().expect("the first resolution runs");
    assert_eq!(plan.packages.len(), 2, "{plan:?}");

    // The kernel is compiled again and differs in a byte, as a build that is
    // not byte-reproducible does.
    write_repo(
        &local,
        "trixie",
        "amd64",
        &[at_version(
            "kernel",
            "6.12",
            payload_holding(b"second compile\n"),
        )],
    );

    // The whole plan replayed verbatim fetches by the digest of the first
    // compile, which nothing now serves.
    let mut verbatim = base(local_repo.clone())
        .plan(plan.clone())
        .build()
        .expect("the plan validates against the configuration");
    let rootfs = dir.join("replayed");
    let refusal = provision::ensure(&rootfs, &mut verbatim)
        .expect_err("the recompiled kernel does not match the recorded digest");
    assert!(refusal.to_string().contains("recorded digest"), "{refusal}",);

    // The same plan with the locally built half dropped holds the archive and
    // resolves the kernel at whatever the local repository now serves.
    let mut pin = plan;
    pin.packages.retain(|package| package.name != "kernel");
    let mut debian = build(local_repo)
        .pin(pin)
        .build()
        .expect("the pin validates against the configuration");
    let rootfs = dir.join("pinned");
    assert_eq!(
        provision::ensure(&rootfs, &mut debian).expect("the pinned bootstrap runs"),
        Provisioned::Created,
    );
    assert_eq!(
        std::fs::read(rootfs.join("usr/bin/x")).unwrap(),
        b"second compile\n",
    );
}

#[test]
fn hermetic_one_version_published_twice_over_different_bytes_is_refused() {
    // The version matches and the bytes do not, which is the event a recorded
    // digest exists to catch. Nothing else in the resolution notices: the
    // archive's own index is internally consistent and its release signs it.
    let dir = common::scratch_dir("debian-pin-rebuilt");
    let repo = dir.join("repo");
    let mirror = write_repo(
        &repo,
        "trixie",
        "amd64",
        &[Pkg::required("base", payload_holding(b"one\n"), "")],
    );
    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror.clone())
        .trust_unsigned(true)
        .build()
        .expect("the builder validates");
    let pin = debian.resolve().expect("the first resolution runs");

    // Republished at the same version over different bytes.
    write_repo(
        &repo,
        "trixie",
        "amd64",
        &[Pkg::required("base", payload_holding(b"two\n"), "")],
    );

    let mut debian = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .pin(pin)
        .build()
        .expect("the pin validates against the configuration");
    let refusal = debian
        .resolve()
        .expect_err("the archive records other bytes for the pinned version")
        .to_string();
    assert!(
        refusal.contains("base 1.0 is pinned to the digest"),
        "{refusal}"
    );
}

#[test]
fn hermetic_a_pin_composes_with_the_selection_a_plan_contradicts() {
    // The whole of what separates a pin from a plan: a plan names every package
    // to install, so include() has nothing to add and is refused; a pin names
    // the versions a selection resolves to and says nothing about what is
    // selected, so the same include() composes with it.
    let dir = common::scratch_dir("debian-pin-composes");
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", payload_holding(b"base\n"), ""),
            Pkg::ordinary("extra", payload_holding(b"extra\n")),
        ],
    );
    let build = || {
        Debian::builder("trixie")
            .architecture("amd64")
            .mirror(mirror.clone())
            .trust_unsigned(true)
    };
    let mut debian = build().build().expect("the builder validates");
    let plan = debian.resolve().expect("the base resolution runs");

    // The same plan, the same include, and opposite outcomes.
    let refusal = build()
        .include(["extra"])
        .plan(plan.clone())
        .build()
        .expect_err("a plan and an include contradict")
        .to_string();
    assert!(refusal.contains("include()"), "{refusal}");

    let mut debian = build()
        .include(["extra"])
        .pin(plan.clone())
        .build()
        .expect("a pin and an include compose");
    let resolved = debian.resolve().expect("the pinned resolution runs");
    let names: Vec<_> = resolved.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["base", "extra"]);

    // A plan and a pin at once are refused: a plan resolves nothing, so there
    // is no resolution left for a pin to hold.
    let refusal = build()
        .plan(plan.clone())
        .pin(plan.clone())
        .build()
        .expect_err("a plan and a pin contradict")
        .to_string();
    assert!(refusal.contains("drop one of the two"), "{refusal}");

    // A pin resolved for another coordinate is refused where it cannot mean
    // anything, exactly as a plan is.
    let mut foreign = plan;
    foreign.architecture = "riscv64".to_string();
    let refusal = build()
        .pin(foreign)
        .build()
        .expect_err("a pin for another architecture is refused")
        .to_string();
    assert!(refusal.contains("riscv64"), "{refusal}");
}
