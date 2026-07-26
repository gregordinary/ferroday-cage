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

/// Returns `false` and prints a skip note when the network tests are not
/// enabled.
fn network_enabled() -> bool {
    if std::env::var_os(NETWORK_GATE).is_some() {
        return true;
    }
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
    let custom = Pkg {
        name: "custom".to_string(),
        version: "1.0".to_string(),
        deb: deb(&custom_tar),
        depends: "libdep".to_string(),
        priority: String::new(),
        essential: false,
    };
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
            Pkg {
                name: "tool".to_string(),
                version: "1.0".to_string(),
                deb: deb(&tool_data),
                depends: "libdep".to_string(),
                priority: String::new(),
                essential: false,
            },
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
    // Corrupt the published package so its bytes no longer match the index.
    let pool_deb = repo.join("pool/base_1.0_amd64.deb");
    let mut bytes = std::fs::read(&pool_deb).unwrap();
    bytes.extend_from_slice(b"tampered");
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
