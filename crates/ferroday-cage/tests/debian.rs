//! Integration tests for the Debian userland provisioner.

mod common;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use common::deb_repo::{Pkg, Tar, deb, deb_with_control, write_repo};
use ferroday_cage::provision::debian::{
    Debian, DebianError, DebianEvent, Plan, Pool, Repository, UnheldReason,
};
use ferroday_cage::provision::{self, ProvisionError, Provisioned};

/// The pool the pool tests publish into: a fixed suite, component, and
/// architecture, so each test names only what it is varying.
fn trixie_pool(dir: &Path) -> Pool {
    Pool::at(dir)
        .suite("trixie")
        .component("main")
        .architecture("amd64")
}

/// The environment variable that opts into the network-dependent bootstrap
/// tests. They fetch from a live Debian mirror and are off by default, so a
/// plain `cargo test --all-features` — including CI — does not reach the
/// network.
const NETWORK_GATE: &str = "FERRODAY_CAGE_DEBIAN_NETWORK_TEST";

/// Whether the network-dependent tests run: [`NETWORK_GATE`] opts in, and
/// `FERRODAY_CAGE_REQUIRE_NETWORK_TEST` turns not opting in into a failure.
fn network_enabled() -> bool {
    common::require::network_suite(NETWORK_GATE, "the Debian bootstrap tests")
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

/// An identity-map delegate a test supplies: it records what it is asked, and
/// resolves every request to the caller alone, or refuses it, and refuses to
/// apply what it resolved.
#[derive(Debug, Clone, Default)]
struct Delegate {
    /// Whether `resolve` refuses.
    refuses: bool,
    /// What it was asked, in order: `resolve` and `apply`.
    asked: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
}

impl ferroday_cage::IdMapper for Delegate {
    fn resolve(
        &self,
        _request: &ferroday_cage::IdentityMap,
    ) -> Result<ferroday_cage::ResolvedMap, ferroday_cage::IdMapError> {
        self.asked.lock().unwrap().push("resolve");
        if self.refuses {
            return Err(ferroday_cage::IdMapError::unsatisfiable(
                "the caller's delegate refuses",
            ));
        }
        let caller = |outside: u32| ferroday_cage::IdRange {
            inside: 0,
            outside,
            count: 1,
        };
        Ok(ferroday_cage::ResolvedMap::new(
            vec![caller(rustix::process::getuid().as_raw())],
            vec![caller(rustix::process::getgid().as_raw())],
        ))
    }

    fn apply(
        &self,
        _pid: u32,
        _map: &ferroday_cage::ResolvedMap,
    ) -> Result<(), ferroday_cage::IdMapError> {
        self.asked.lock().unwrap().push("apply");
        Err(ferroday_cage::IdMapError::unsatisfiable(
            "the caller's delegate will not apply",
        ))
    }
}

#[test]
fn hermetic_a_bootstrap_establishes_its_map_through_the_callers_delegate() {
    // A range map only a site-specific delegate can establish is one the
    // bundled chain cannot, so every place a bootstrap establishes the map has
    // to ask the caller's delegate: the preflight before any download, and the
    // cage each dpkg wave runs in.
    let dir = common::scratch_dir("debian-delegate");
    let base = Tar::new()
        .dir("./usr", 0o755)
        .dir("./usr/bin", 0o755)
        .file("./usr/bin/hello", 0o755, b"#!/bin/true\n")
        .finish();
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[Pkg::required("base", deb(&base), "")],
    );
    let bootstrap = |delegate: &Delegate, at: &str| {
        let mut debian = Debian::builder("trixie")
            .architecture("amd64")
            .mirror(mirror.clone())
            .trust_unsigned(true)
            .cache_dir(dir.join(format!("{at}-cache")))
            .identity_map(ferroday_cage::IdentityMap::Subordinate)
            .id_mapper(delegate.clone())
            .build()
            .expect("the builder validates");
        let err = provision::ensure(dir.join(at), &mut debian)
            .expect_err("the delegate fails the bootstrap");
        let ProvisionError::Other { source, .. } = err else {
            panic!("expected a Debian error, got {err:?}");
        };
        *source
            .downcast::<ferroday_cage::provision::debian::DebianError>()
            .expect("a Debian error")
    };

    // The preflight asks the delegate, and its refusal stops the bootstrap
    // before a package is downloaded.
    let refusing = Delegate {
        refuses: true,
        ..Delegate::default()
    };
    match bootstrap(&refusing, "refused") {
        ferroday_cage::provision::debian::DebianError::Config { reason, .. } => {
            assert!(reason.contains("the caller's delegate refuses"), "{reason}");
        }
        other => panic!("a refused map is a configuration refusal: {other:?}"),
    }
    assert_eq!(*refusing.asked.lock().unwrap(), ["resolve"]);
    let downloaded = std::fs::read_dir(dir.join("refused-cache"))
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(downloaded, 0, "a package was downloaded before the refusal");

    // So does staging a layer, before it reads the base.
    let refusing = Delegate {
        refuses: true,
        ..Delegate::default()
    };
    let mut layered = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror.clone())
        .trust_unsigned(true)
        .base_layer(dir.join("no-base"))
        .identity_map(ferroday_cage::IdentityMap::Subordinate)
        .id_mapper(refusing.clone())
        .build()
        .expect("the builder validates");
    let err = layered
        .stage_layer(dir.join("upper"))
        .expect_err("the delegate refuses the layer's map");
    let message = ferroday_cage::ErrorChain::new(&err).to_string();
    assert!(
        message.contains("the caller's delegate refuses"),
        "{message}"
    );
    assert_eq!(*refusing.asked.lock().unwrap(), ["resolve"]);

    // The dpkg wave's cage is launched through it too. Launching one needs a
    // user namespace, which is where the delegate is asked to apply the map.
    if !common::require::userns() {
        return;
    }
    let obliging = Delegate::default();
    match bootstrap(&obliging, "launched") {
        ferroday_cage::provision::debian::DebianError::Launch(
            ferroday_cage::Error::IdentityMap(refusal),
        ) => {
            assert!(refusal.to_string().contains("will not apply"), "{refusal}");
        }
        other => panic!("the wave's launch fails at the delegate: {other:?}"),
    }
    let asked = obliging.asked.lock().unwrap().clone();
    assert_eq!(
        asked.last(),
        Some(&"apply"),
        "the wave's cage was not launched through the delegate: {asked:?}",
    );
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
        .mirror(provision::file_url(&pool).expect("a file:// URL"))
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
        .mirror(provision::file_url(&pool).expect("a file:// URL"))
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
        .mirror(provision::file_url(&pool).expect("a file:// URL"))
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
        .mirror(provision::file_url(&pool).expect("a file:// URL"))
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

/// Makes a named pipe at `path`.
fn make_fifo(path: &Path) {
    use rustix::fs::{CWD, FileType, Mode, mknodat};
    mknodat(CWD, path, FileType::Fifo, Mode::from_raw_mode(0o644), 0)
        .unwrap_or_else(|errno| panic!("a named pipe at {}: {errno}", path.display()));
}

/// Publishes `debs` into `pool` on a thread of its own, failing the test if the
/// publish has not returned within a deadline rather than waiting on it.
///
/// An open of a named pipe waits for a writer that never comes, so a publish
/// that opened one would never return. The thread is left behind if it does
/// not, which ends with the test process.
fn publish_within_deadline(
    pool: &Path,
    debs: Vec<std::path::PathBuf>,
) -> Result<(), ferroday_cage::provision::debian::DebianError> {
    let pool = pool.to_path_buf();
    let (done, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || done.send(trixie_pool(&pool).publish(debs)));
    outcome
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the publish returned rather than waiting on a named pipe")
}

#[test]
fn hermetic_a_pipe_or_link_at_a_pool_file_is_replaced_rather_than_read() {
    // A republish reads the file the pool already holds at a package's name,
    // and the copy of each index it already holds under its digest, to decide
    // whether to write them again. Neither name is the pool's to trust blindly:
    // a named pipe there would stall the publish on its open, and a link would
    // be followed out of the pool and its target's bytes taken as the pool's.
    // Each is replaced by the file the publish writes instead.
    let dir = common::scratch_dir("debian-pool-planted");
    let bytes = deb_with_control(
        "Package: tool\nVersion: 1.0\nArchitecture: amd64\nDescription: a tool\n",
        &Tar::new()
            .dir("./usr", 0o755)
            .file("./usr/bin/tool", 0o755, b"v\n")
            .finish(),
    );
    let source = dir.join("tool.deb");
    std::fs::write(&source, &bytes).unwrap();
    let pool = dir.join("pool");
    trixie_pool(&pool).publish([&source]).unwrap();

    let published = pool.join("pool/main/t/tool/tool_1.0_amd64.deb");
    let by_hash = pool.join("dists/trixie/main/binary-amd64/by-hash/SHA256");
    let index_digest = common::deb_repo::sha256_hex(
        &std::fs::read(pool.join("dists/trixie/main/binary-amd64/Packages")).unwrap(),
    );
    let index_copy = by_hash.join(&index_digest);
    let is_file = |path: &Path| {
        std::fs::symlink_metadata(path)
            .unwrap()
            .file_type()
            .is_file()
    };
    assert!(is_file(&published) && is_file(&index_copy));

    // A pipe at both names: the republish returns, and each name holds the file
    // the pool wrote.
    for planted in [&published, &index_copy] {
        std::fs::remove_file(planted).unwrap();
        make_fifo(planted);
    }
    publish_within_deadline(&pool, vec![source.clone()]).expect("the republish succeeds");
    assert!(is_file(&published), "the pipe at the package was replaced");
    assert_eq!(std::fs::read(&published).unwrap(), bytes);
    assert!(
        is_file(&index_copy),
        "the pipe at the index copy was replaced"
    );

    // A link to the same bytes outside the pool reads as already published
    // when it is followed, which would leave the pool serving a file it does
    // not hold. It is replaced with the pool's own copy instead.
    let outside = dir.join("outside.deb");
    std::fs::write(&outside, &bytes).unwrap();
    std::fs::remove_file(&published).unwrap();
    std::os::unix::fs::symlink(&outside, &published).unwrap();
    publish_within_deadline(&pool, vec![source]).expect("the republish succeeds");
    assert!(is_file(&published), "the link at the package was replaced");
    assert_eq!(std::fs::read(&published).unwrap(), bytes);
}

#[test]
fn hermetic_a_pipe_at_the_index_a_publish_merges_into_fails_it_promptly() {
    // A publish merges into the index the pool already holds, so it cannot go on
    // without reading it: one it skipped would drop every package published
    // before. A named pipe there fails the publish, naming the index, instead of
    // stalling it on the open.
    let dir = common::scratch_dir("debian-pool-planted-index");
    let pool = dir.join("pool");
    trixie_pool(&pool).publish::<&Path>([]).unwrap();
    let index = pool.join("dists/trixie/main/binary-amd64/Packages");
    std::fs::remove_file(&index).unwrap();
    make_fifo(&index);

    match publish_within_deadline(&pool, Vec::new()) {
        Err(ferroday_cage::provision::debian::DebianError::Io { path, .. }) => {
            assert_eq!(path, index, "the failure names the index");
        }
        other => panic!("a pipe at the index is a host failure naming it: {other:?}"),
    }
}

#[test]
fn hermetic_a_pipe_or_link_offered_as_a_deb_is_refused_without_being_read() {
    // A pipeline publishes what its build sandbox left in a directory the
    // sandbox could write. A named pipe there called `x.deb` would hold the
    // publish forever on its open, and a link called `x.deb` would have the
    // host read a file the sandbox chose and copy it into the pool. Each is
    // refused, promptly, naming the path, and the pool gains nothing.
    let dir = common::scratch_dir("debian-pool-planted-input");
    let pool = dir.join("pool");
    trixie_pool(&pool).publish::<&Path>([]).unwrap();
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();

    let pipe = out.join("pipe.deb");
    make_fifo(&pipe);
    let outside = dir.join("outside.deb");
    std::fs::write(
        &outside,
        deb_with_control(
            "Package: planted\nVersion: 1.0\nArchitecture: amd64\nDescription: chosen\n",
            &Tar::new().dir("./usr", 0o755).finish(),
        ),
    )
    .unwrap();
    let link = out.join("link.deb");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    for planted in [pipe, link] {
        match publish_within_deadline(&pool, vec![planted.clone()]) {
            Err(ferroday_cage::provision::debian::DebianError::Io { path, .. }) => {
                assert_eq!(path, planted, "the failure names the path offered");
            }
            other => panic!(
                "{} is refused as a host failure: {other:?}",
                planted.display()
            ),
        }
    }
    assert!(
        !pool.join("pool/main/p").exists(),
        "nothing the link named was copied into the pool",
    );
}

#[test]
fn hermetic_a_link_at_another_components_index_is_not_named() {
    // Each publish rescans the suite and names every index it holds, so the
    // scan reads indexes this publish did not write. A link at one of them is
    // looked at rather than followed: the release names only the files the
    // pool holds, and a link to bytes elsewhere is not one.
    let dir = common::scratch_dir("debian-pool-linked-index");
    let pool = dir.join("pool");
    trixie_pool(&pool).publish::<&Path>([]).unwrap();
    let contrib = pool.join("dists/trixie/contrib/binary-amd64");
    std::fs::create_dir_all(&contrib).unwrap();
    let outside = dir.join("Packages");
    std::fs::write(&outside, b"").unwrap();
    std::os::unix::fs::symlink(&outside, contrib.join("Packages")).unwrap();
    make_fifo(&contrib.join("Packages.gz"));

    publish_within_deadline(&pool, Vec::new()).expect("the publish succeeds");
    let release = std::fs::read_to_string(pool.join("dists/trixie/Release")).unwrap();
    assert!(
        !release.contains("contrib/"),
        "a link or a pipe was named as an index: {release}",
    );
    assert!(
        release.contains("main/binary-amd64/Packages\n"),
        "{release}"
    );
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
    // build layer whose upper holds only the pre-configure overlay. This
    // exercises the empty-increment path hermetically — it runs no cage — so it
    // needs no network or real dpkg; it skips only where the overlay preflight
    // reports the host cannot overlay.
    let dir = common::scratch_dir("debian-empty-layer");
    if !common::require::overlay(&dir) {
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

    // The caller's configuration of the build root, which applies whether or
    // not anything needed installing.
    let overlay = dir.join("overlay");
    std::fs::create_dir_all(overlay.join("etc")).unwrap();
    std::fs::write(overlay.join("etc/build.conf"), b"jobs=4\n").unwrap();

    let upper = dir.join("upper");
    let layer = {
        let mut debian = Debian::builder("trixie")
            .architecture("amd64")
            .mirror(mirror)
            .trust_unsigned(true)
            .base_layer(&base_dir)
            .include(["base"])
            .pre_configure_overlay(&overlay)
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
    assert_eq!(
        std::fs::read(upper.join("etc/build.conf")).unwrap(),
        b"jobs=4\n",
        "the overlay is laid into an empty increment as into any other",
    );
    // Nothing a wave writes is there: no package was installed.
    assert!(!upper.join("var/lib/dpkg").exists());
    drop(layer);
    assert!(
        !upper.exists(),
        "the empty layer's upper is removed on drop"
    );
}

#[test]
fn hermetic_a_plan_is_the_increment_a_layered_build_installs() {
    // A plan set alongside a base layer describes the increment. The layered
    // path read no plan at all and `plan()` forbids `include()`, so the seed was
    // empty: `stage_layer` returned a build layer over an empty upper having
    // installed nothing, and `resolve_layer` reported that same empty closure.
    let dir = common::scratch_dir("debian-layer-plan");
    if !common::require::overlay(&dir) {
        return;
    }
    let mirror = write_repo(
        &dir.join("repo"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", payload("base"), ""),
            Pkg::ordinary("extra", payload("extra")),
        ],
    );

    // A configured base carrying only `base`.
    let base_dir = dir.join("base");
    let dpkg = base_dir.join("var/lib/dpkg");
    std::fs::create_dir_all(&dpkg).unwrap();
    std::fs::write(
        dpkg.join("status"),
        "Package: base\nStatus: install ok installed\nVersion: 1.0\n",
    )
    .unwrap();

    let layered = |plan: Option<Plan>| {
        let mut builder = Debian::builder("trixie")
            .architecture("amd64")
            .mirror(mirror.clone())
            .trust_unsigned(true)
            .cache_dir(dir.join("cache"))
            .base_layer(&base_dir);
        builder = match plan {
            Some(plan) => builder.plan(plan),
            None => builder.include(["extra"]),
        };
        builder.build().expect("the builder validates")
    };

    let plan = layered(None)
        .resolve_layer()
        .expect("the increment resolves");
    assert_eq!(
        plan.packages
            .iter()
            .map(|package| package.name.clone())
            .collect::<Vec<_>>(),
        ["extra"],
        "the base already carries `base`, so the increment is `extra` alone",
    );

    // The plan is what the layered resolve answers with, rather than a closure
    // resolved from an empty seed.
    let answered = layered(Some(plan.clone()))
        .resolve_layer()
        .expect("a configured plan needs no archive to answer");
    assert_eq!(
        answered
            .packages
            .iter()
            .map(|package| package.name.clone())
            .collect::<Vec<_>>(),
        ["extra"],
    );

    // And it is what staging installs. The configure wave needs a real dpkg in
    // the base, which this fixture has none of, so the call fails there -- what
    // this asserts is that the increment's package was fetched, which an empty
    // layer would not have done.
    let watcher = Watching::default();
    let asked = std::sync::Arc::clone(&watcher.asked);
    let mut staging = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .base_layer(&base_dir)
        .plan(plan)
        .fetcher(watcher)
        .build()
        .expect("the builder validates");
    let _ = staging.stage_layer(dir.join("upper"));
    let urls = asked.lock().unwrap().clone();
    assert!(
        urls.iter()
            .any(|url| url.contains("/pool/") && url.contains("extra")),
        "the plan's package was never fetched: {urls:?}",
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
    if !common::require::overlay(&dir) {
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
    let missing = provision::file_url(&dir.join("does-not-exist")).expect("a file:// URL");

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
    let refused = |what: &str, build: Result<Debian, _>| match build {
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
    // consumed as [trusted=yes] and ranks alongside the primary archive, where
    // the higher version wins, so an entry a package wrote for itself
    // supersedes the primary archive's.
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
    let mirror = provision::file_url(&repo).expect("a file:// URL");
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
    let mirror = provision::file_url(&repo).expect("a file:// URL");
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
    let reported = ferroday_cage::ErrorChain::new(&**inner).to_string();
    assert!(
        reported.contains("maximum size"),
        "the oversized body is refused at the bound: {reported}"
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
        .cache_dir(common::download_cache("debian"))
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
fn backports_supplies_only_what_is_asked_of_it_by_release() {
    // The real archive's own markings: trixie-backports is NotAutomatic and
    // ButAutomaticUpgrades, so beside trixie it supplies nothing a resolution
    // does not ask of it by name and release, as apt resolves the pair.
    if !network_enabled() {
        return;
    }
    let keyring = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/provision/debian/keyring/debian-archive-keyring.gpg"
    );
    let backports = || {
        Repository::builder("trixie-backports")
            .mirror("http://deb.debian.org/debian")
            .keyring(keyring)
            .name("backports")
            .build()
            .expect("the backports repository validates")
    };

    // A package trixie carries that backports carries too: the kernel's
    // metapackage, or one of the long-lived backports otherwise.
    let offered = Debian::builder("trixie-backports")
        .build()
        .expect("the builder validates")
        .available()
        .expect("the backports index is read");
    let kernel = format!(
        "linux-image-{}",
        ferroday_cage::provision::debian::host_architecture()
    );
    let name = [
        kernel.as_str(),
        "systemd",
        "git",
        "curl",
        "cockpit",
        "golang-go",
    ]
    .into_iter()
    .find(|name| offered.contains(name))
    .expect("trixie-backports carries one of the usual backports");

    let plan = Debian::builder("trixie")
        .repository(backports())
        .include([name])
        .build()
        .expect("the builder validates")
        .resolve()
        .expect("the merged plan resolves");
    let from_backports: Vec<&str> = plan
        .packages
        .iter()
        .filter(|package| package.archive == 1)
        .map(|package| package.name.as_str())
        .collect();
    assert!(
        from_backports.is_empty(),
        "backports supplied what nothing asked of it: {from_backports:?}",
    );

    let plan = Debian::builder("trixie")
        .repository(backports())
        .include([format!("{name}/trixie-backports")])
        .build()
        .expect("the builder validates")
        .resolve()
        .expect("the merged plan resolves");
    let asked = plan
        .packages
        .iter()
        .find(|package| package.name == name)
        .expect("the package asked for is in the plan");
    assert_eq!(asked.archive, 1, "{name} comes from backports");
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
            .cache_dir(common::download_cache("debian"))
            .build()
            .expect("the builder validates");
        provision::ensure(&rootfs, &mut debian.observe(&mut progress))
            .expect("the full bootstrap runs");
    }

    // The finished rootfs is apt-usable. The release was verified against the
    // embedded archive keyring, and apt depends on debian-archive-keyring, so
    // the sources.list names the keyring that package installed: its upgrades
    // deliver the keys the archive rotates to. No copy is written beside it.
    let sources = std::fs::read_to_string(rootfs.join("etc/apt/sources.list"))
        .expect("the sources.list is written");
    assert!(
        sources.contains("[signed-by=/usr/share/keyrings/debian-archive-keyring.gpg]"),
        "the sources.list names the package's keyring: {sources:?}"
    );
    assert!(
        std::fs::symlink_metadata(rootfs.join("usr/share/keyrings/fcage-archive-keyring.gpg"))
            .is_err(),
        "a default bootstrap writes no keyring of its own",
    );

    // The files the keyring package ships are its own: nothing the bootstrap
    // wrote went over them, so the package's next upgrade has nothing to put
    // back.
    let verify = ferroday_cage::Cage::builder()
        .rootfs(&rootfs)
        .command("/usr/bin/dpkg")
        .args(["--verify", "debian-archive-keyring"])
        .build()
        .expect("the cage builds")
        .output()
        .expect("dpkg runs in the finished rootfs");
    assert!(
        verify.status.success() && verify.stdout.is_empty(),
        "debian-archive-keyring's files are the package's own: {}",
        String::from_utf8_lossy(&verify.stdout),
    );

    // The daemon launcher was a stand-in while packages configured, and the
    // real one is back: dpkg finds its own file unchanged, and no stand-in or
    // saved copy is left.
    let verify = ferroday_cage::Cage::builder()
        .rootfs(&rootfs)
        .command("/usr/bin/dpkg")
        .args(["--verify", "dpkg"])
        .build()
        .expect("the cage builds")
        .output()
        .expect("dpkg runs in the finished rootfs");
    assert!(
        verify.status.success() && verify.stdout.is_empty(),
        "dpkg's files, start-stop-daemon among them, are the package's own: {}",
        String::from_utf8_lossy(&verify.stdout),
    );
    assert!(
        std::fs::symlink_metadata(rootfs.join("usr/sbin/start-stop-daemon.fcage-real")).is_err(),
        "no saved copy of the launcher is left",
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

    // The real proof of the anchor: apt-get update verifies the release from
    // inside the rootfs against the signed-by keyring. A missing or untrusted
    // keyring makes apt exit non-zero here.
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
            .cache_dir(common::download_cache("debian"))
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
    if !common::require::overlay(&scratch) {
        return;
    }

    // Provision the shared base once, the ordinary way: a configured minbase.
    let base = scratch.join("base");
    {
        let mut debian = Debian::builder("trixie")
            .cache_dir(common::download_cache("debian"))
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
            .cache_dir(common::download_cache("debian"))
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
    // Neither the base's bootstrap nor the increment's waves keep dpkg's log of
    // their run.
    assert!(!base.join("var/log/dpkg.log").exists());
    assert!(!upper.join("var/log/dpkg.log").exists());

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
    if !common::require::overlay(&scratch) {
        return;
    }
    if !common::require::range_map() {
        return;
    }

    // The base and its layer share the subordinate identity map, as they must.
    let base = scratch.join("base");
    {
        let mut debian = Debian::builder("trixie")
            .identity_map(ferroday_cage::IdentityMap::Subordinate)
            .cache_dir(common::download_cache("debian"))
            .build()
            .expect("the builder validates");
        provision::ensure(&base, &mut debian).expect("the range-mapped base bootstrap runs");
    }

    // The caller's overlay writes beneath `/var/mail`, which the base holds at
    // `root:mail` with the set-group-ID bit, so the upper has to carry that
    // directory up to hold the file.
    let overlay = scratch.join("overlay");
    std::fs::create_dir_all(overlay.join("var/mail")).unwrap();
    std::fs::write(overlay.join("var/mail/note"), b"from the overlay\n").unwrap();

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
            .pre_configure_overlay(&overlay)
            .cache_dir(common::download_cache("debian"))
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

    // The directory the overlay was carried beneath keeps the owner, group and
    // mode the base holds it at, in the merged view, as the overlay's own
    // copy-up would have kept them.
    assert!(
        upper.join("var/mail/note").is_file(),
        "carried into the upper"
    );
    let mail = |cage: ferroday_cage::CageBuilder| {
        let output = cage
            .identity_map(ferroday_cage::IdentityMap::Subordinate)
            .command("/usr/bin/stat")
            .args(["-c", "%U:%G %a", "/var/mail"])
            .build()
            .expect("the cage builds")
            .output()
            .expect("stat runs");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let held = mail(ferroday_cage::Cage::builder().rootfs(&base));
    assert_eq!(held, "root:mail 2775\n", "the base's own /var/mail");
    assert_eq!(
        mail(ferroday_cage::Cage::builder().overlay_rootfs(&base, layer.path())),
        held,
        "the merged view's /var/mail is the base's",
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
    if !common::require::range_map() {
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
            .cache_dir(common::download_cache("debian"))
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

/// A dated bootstrap: the accounts its scripts create carry the epoch's day,
/// and the root keeps no record of the run and no machine id it generated.
///
/// Range-mapped because `systemd`, which writes the machine id and creates
/// accounts with `systemd-sysusers`, assigns ownership the single-identity map
/// cannot represent.
#[cfg(feature = "subid")]
#[test]
fn a_dated_bootstrap_keeps_the_epoch_and_no_record_of_its_run() {
    if !network_enabled() {
        return;
    }
    let Some(_) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::range_map() {
        return;
    }
    const EPOCH: i64 = 1_700_000_000;
    let scratch = common::scratch_dir("debian-dated");
    let rootfs = scratch.join("rootfs");
    {
        let mut debian = Debian::builder("trixie")
            .include(["systemd", "dbus"])
            .identity_map(ferroday_cage::IdentityMap::Subordinate)
            .source_date_epoch(EPOCH)
            .cache_dir(common::download_cache("debian"))
            .build()
            .expect("the builder validates");
        provision::ensure(&rootfs, &mut debian).expect("the dated bootstrap runs");
    }

    // Every account records its last password change as the epoch's day:
    // those `pwconv` converts, those `useradd` creates, and those
    // `systemd-sysusers` creates alike. Without the epoch each is the build day.
    let shadow = std::fs::read_to_string(rootfs.join("etc/shadow")).expect("the shadow file reads");
    let day = (EPOCH / 86_400).to_string();
    let accounts: Vec<&str> = shadow.lines().collect();
    assert!(
        accounts.len() > 10,
        "the base system created its accounts: {shadow}"
    );
    for account in accounts {
        assert_eq!(
            account.split(':').nth(2),
            Some(day.as_str()),
            "{account} is dated by the epoch",
        );
    }

    // What the waves recorded of their run is gone, and the machine id a script
    // generated is left empty for the machine the root is deployed to.
    for record in [
        "var/log/dpkg.log",
        "var/log/alternatives.log",
        "var/cache/ldconfig/aux-cache",
        "var/lib/dbus/machine-id",
    ] {
        assert!(
            std::fs::symlink_metadata(rootfs.join(record)).is_err(),
            "{record} is not kept",
        );
    }
    assert_eq!(
        std::fs::read(rootfs.join("etc/machine-id")).expect("systemd's machine id file is kept"),
        b"",
    );

    provision::remove(&rootfs).expect("the removal succeeds");
}

/// A bootstrap dated in 1970's first day, `SOURCE_DATE_EPOCH=0` being a common
/// pipeline value: no account demands a new password at its next login.
///
/// shadow's tools leave the last-change field empty for that day, and
/// `systemd-sysusers` writes it as a zero, which `shadow(5)` reads as that
/// demand. The bootstrap records every one of them as `useradd` does.
#[cfg(feature = "subid")]
#[test]
fn a_bootstrap_dated_in_the_first_day_of_1970_records_no_date() {
    if !network_enabled() {
        return;
    }
    let Some(_) = common::fixture_rootfs() else {
        return;
    };
    if !common::require::range_map() {
        return;
    }
    let scratch = common::scratch_dir("debian-dated-day-zero");
    let rootfs = scratch.join("rootfs");
    {
        let mut debian = Debian::builder("trixie")
            .include(["systemd", "dbus"])
            .identity_map(ferroday_cage::IdentityMap::Subordinate)
            .source_date_epoch(0)
            .cache_dir(common::download_cache("debian"))
            .build()
            .expect("the builder validates");
        provision::ensure(&rootfs, &mut debian).expect("the dated bootstrap runs");
    }

    let shadow = std::fs::read_to_string(rootfs.join("etc/shadow")).expect("the shadow file reads");
    assert!(
        shadow
            .lines()
            .any(|line| line.starts_with("systemd-network:")),
        "systemd-sysusers created its accounts: {shadow}"
    );
    for account in shadow.lines() {
        assert_eq!(
            account.split(':').nth(2),
            Some(""),
            "{account} records no date"
        );
    }

    provision::remove(&rootfs).expect("the removal succeeds");
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
    let missing = provision::file_url(&dir.join("does-not-exist")).expect("a file:// URL");

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
    // Each name resolves to one version across the merged repositories, so
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
fn a_configured_plan_is_what_resolve_answers_with() {
    // `resolve` and `ensure` are documented as one code path, and the plan is
    // recommended as a build-cache key. Resolving afresh on a provisioner that
    // already carries a plan answered with a whole fresh closure while `ensure`
    // on the same value installed the plan's, so the key described a rootfs
    // nothing built.
    let (dir, mirror, plan) = resolved_fixture("debian-plan-resolve-agrees");
    let mut trimmed = plan.clone();
    trimmed.packages.truncate(1);

    let answered = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        .trust_unsigned(true)
        .cache_dir(dir.join("cache"))
        .extract_only(true)
        .plan(trimmed.clone())
        .build()
        .expect("the builder validates")
        .resolve()
        .expect("a configured plan needs no archive to answer");
    assert_eq!(
        answered
            .packages
            .iter()
            .map(|package| package.name.clone())
            .collect::<Vec<_>>(),
        trimmed
            .packages
            .iter()
            .map(|package| package.name.clone())
            .collect::<Vec<_>>(),
        "resolve answered with a closure the same value would not install",
    );
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
        .fetcher(watcher)
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
    let message = ferroday_cage::ErrorChain::new(&**inner).to_string();
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
    // Altered in place rather than extended: the plan records the length too,
    // and a body longer than that is refused before its digest is taken.
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&pool_deb, &bytes).unwrap();

    let mut pinned = Debian::builder("trixie")
        .architecture("amd64")
        .mirror(mirror)
        // A backstop that would serve, so this proves the failure is terminal
        // rather than merely unrecoverable for want of an alternative.
        .mirror_fallback(provision::file_url(&dir.join("repo")).expect("a file:// URL"))
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
    let refusal = |builder: ferroday_cage::provision::debian::DebianBuilder| match builder.build() {
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
fn live_resolve(mut debian: Debian) -> Plan {
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
    let reported = ferroday_cage::ErrorChain::new(&refusal).to_string();
    assert!(
        reported.contains("digest the archive recorded"),
        "{reported}",
    );

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

/// Writes a repository for `suite` into `dir` that ranks itself as a backports
/// suite does, `NotAutomatic` and `ButAutomaticUpgrades`, and declares it.
fn backports_repository(dir: &Path, suite: &str, packages: &[Pkg]) -> Repository {
    let mirror = write_repo(dir, suite, "amd64", packages);
    let release = dir.join(format!("dists/{suite}/Release"));
    let mut text = std::fs::read_to_string(&release).unwrap();
    text.push_str("NotAutomatic: yes\nButAutomaticUpgrades: yes\n");
    std::fs::write(&release, text).unwrap();
    Repository::builder(suite)
        .mirror(mirror)
        .trust_unsigned(true)
        .name("backports")
        .build()
        .expect("the backports repository validates")
}

#[test]
fn hermetic_a_pin_refuses_a_release_that_does_not_offer_the_pinned_version() {
    // The pin holds the kernel at the version trixie offers, and the install
    // list asks for it from backports, which offers a newer one. Taking
    // backports' version would resolve the kernel around its pin, and taking
    // trixie's would ignore the release the entry names, so the pin refuses.
    let dir = common::scratch_dir("debian-pin-release");
    let archive = write_repo(
        &dir.join("archive"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", payload_holding(b"base\n"), ""),
            at_version("kernel", "6.12", payload_holding(b"6.12\n")),
        ],
    );
    let backports = backports_repository(
        &dir.join("backports"),
        "trixie-backports",
        &[at_version("kernel", "6.16~bpo", payload_holding(b"6.16\n"))],
    );
    let build = || {
        Debian::builder("trixie")
            .architecture("amd64")
            .mirror(archive.clone())
            .trust_unsigned(true)
            .repository(backports.clone())
    };
    let pin = live_resolve(build().include(["kernel"]).build().unwrap());
    let kernel = pin.packages.iter().find(|p| p.name == "kernel").unwrap();
    assert_eq!((kernel.version.as_str(), kernel.archive), ("6.12", 0));

    let mut debian = build()
        .include(["kernel/trixie-backports"])
        .pin(pin)
        .build()
        .expect("the pin validates against the configuration");
    match debian.resolve() {
        Err(DebianError::Pin { unheld, .. }) => {
            assert_eq!(unheld.len(), 1, "{unheld:?}");
            assert_eq!(
                (unheld[0].package.as_str(), unheld[0].version.as_str()),
                ("kernel", "6.12"),
            );
            assert!(
                matches!(
                    &unheld[0].reason,
                    UnheldReason::Release { release, archive, .. }
                        if release == "trixie-backports" && archive == "6.16~bpo"
                ),
                "{:?}",
                unheld[0],
            );
        }
        other => panic!("expected the pin refused, got {other:?}"),
    }
}

#[test]
fn hermetic_a_pin_holds_a_dependency_a_release_switches() {
    // `app/trixie-backports` needs a libfoo only backports offers, which the
    // switch to the release would take. The pin holds libfoo at trixie's
    // version, so the resolution refuses the pin, naming who needed what.
    let dir = common::scratch_dir("debian-pin-switch");
    let archive = write_repo(
        &dir.join("archive"),
        "trixie",
        "amd64",
        &[
            Pkg::required("base", payload_holding(b"base\n"), ""),
            at_version("libfoo", "1.0", payload_holding(b"libfoo 1\n")),
            at_version("app", "1.0", payload_holding(b"app 1\n")).depending_on("libfoo"),
        ],
    );
    let backports = backports_repository(
        &dir.join("backports"),
        "trixie-backports",
        &[
            at_version("libfoo", "2.0~bpo", payload_holding(b"libfoo 2\n")),
            at_version("app", "2.0~bpo", payload_holding(b"app 2\n"))
                .depending_on("libfoo (>= 2.0~bpo)"),
        ],
    );
    let build = || {
        Debian::builder("trixie")
            .architecture("amd64")
            .mirror(archive.clone())
            .trust_unsigned(true)
            .repository(backports.clone())
    };
    // The pin holds what trixie supplied, and leaves the entry's own name to
    // float, so the only thing in the way is the dependency.
    let mut pin = live_resolve(build().include(["app"]).build().unwrap());
    pin.packages.retain(|package| package.name != "app");
    let libfoo = pin.packages.iter().find(|p| p.name == "libfoo").unwrap();
    assert_eq!(libfoo.version, "1.0");

    let mut debian = build()
        .include(["app/trixie-backports"])
        .pin(pin)
        .build()
        .expect("the pin validates against the configuration");
    match debian.resolve() {
        Err(DebianError::Pin { unheld, .. }) => {
            assert_eq!(unheld.len(), 1, "{unheld:?}");
            assert_eq!(
                (unheld[0].package.as_str(), unheld[0].version.as_str()),
                ("libfoo", "1.0"),
            );
            assert!(
                matches!(
                    &unheld[0].reason,
                    UnheldReason::Requirement { requirement, required_by, .. }
                        if requirement == "libfoo (>= 2.0~bpo)" && required_by == "app"
                ),
                "{:?}",
                unheld[0],
            );
        }
        other => panic!("expected the pin refused, got {other:?}"),
    }
}

#[test]
fn hermetic_a_pin_holds_what_a_layer_upgrades_over_its_base() {
    // The base holds libfoo1 1.0-1, the pin holds trixie's 1.0-2, and a
    // security release ranked like trixie offers 1.0-2+deb13u1. An increment
    // needing 1.0-2 or newer upgrades libfoo1, and the upgrade is the pinned
    // version rather than the newest one.
    let dir = common::scratch_dir("debian-pin-layer");
    let archive = write_repo(
        &dir.join("archive"),
        "trixie",
        "amd64",
        &[
            at_version("libfoo1", "1.0-2", payload_holding(b"1.0-2\n")),
            at_version("app", "1.0", payload_holding(b"app\n")).depending_on("libfoo1 (>= 1.0-2)"),
        ],
    );
    let security_mirror = write_repo(
        &dir.join("security"),
        "trixie-security",
        "amd64",
        &[at_version(
            "libfoo1",
            "1.0-2+deb13u1",
            payload_holding(b"1.0-2+deb13u1\n"),
        )],
    );
    let security = Repository::builder("trixie-security")
        .mirror(security_mirror)
        .trust_unsigned(true)
        .name("security")
        .build()
        .expect("the security repository validates");

    let base_dir = dir.join("base");
    let dpkg = base_dir.join("var/lib/dpkg");
    std::fs::create_dir_all(&dpkg).unwrap();
    std::fs::write(
        dpkg.join("status"),
        "Package: libfoo1\nStatus: install ok installed\nVersion: 1.0-1\n",
    )
    .unwrap();

    let build = || {
        Debian::builder("trixie")
            .architecture("amd64")
            .mirror(archive.clone())
            .trust_unsigned(true)
    };
    let pin = live_resolve(build().include(["libfoo1"]).build().unwrap());
    assert_eq!(pin.packages.len(), 1, "{pin:?}");

    let layered = || {
        build()
            .repository(security.clone())
            .base_layer(&base_dir)
            .include(["app"])
    };
    let upgrade = |plan: &Plan| {
        let libfoo1 = plan.packages.iter().find(|p| p.name == "libfoo1").unwrap();
        (libfoo1.version.clone(), libfoo1.archive)
    };
    let unpinned = layered()
        .build()
        .unwrap()
        .resolve_layer()
        .expect("the unpinned layer resolves");
    assert_eq!(upgrade(&unpinned), ("1.0-2+deb13u1".to_string(), 1));

    let pinned = layered()
        .pin(pin)
        .build()
        .expect("the pin validates against the configuration")
        .resolve_layer()
        .expect("the pinned layer resolves");
    assert_eq!(upgrade(&pinned), ("1.0-2".to_string(), 0));
}
