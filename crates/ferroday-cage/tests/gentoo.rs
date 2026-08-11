//! Integration tests for the Gentoo userland provisioner.
//!
//! The hermetic tests live beside the code they exercise, over documents signed
//! by a key the test generates: that is where the refusals are, because an
//! archive publishes nothing that fails its own trust chain. What is here is
//! what needs the live archive — that Gentoo still publishes the shape this
//! layer reads, and that a real signed stage3 produces a root Gentoo's own
//! files agree with.
//!
//! Nothing here pins a build. The archive keeps about five weeks of them and
//! publishes no snapshot service, so a pinned id would age out into a permanent
//! failure — and what these tests are for is noticing the archive changing
//! shape, which a pin would hide.

mod common;

use ferroday_cage::provision::gentoo::Gentoo;
use ferroday_cage::provision::{self, Provisioned};

/// The environment variable that opts into the network-dependent tests. They
/// read a live archive and download a half-gigabyte tarball, and are off by
/// default, so a plain `cargo test --all-features` — CI included — reaches no
/// archive.
const NETWORK_GATE: &str = "FERRODAY_CAGE_GENTOO_NETWORK_TEST";

/// The variable that asserts these tests ran, in the crate's usual shape: a
/// skip stays a skip by default, and this turns it into a failure so a release
/// check cannot come back green having exercised no archive at all.
const REQUIRE_GATE: &str = "FERRODAY_CAGE_REQUIRE_NETWORK_TEST";

/// The architecture the live tests read, and the variant they install: the
/// smallest ordinary root the archive publishes for it.
const ARCHITECTURE: &str = "amd64";
const VARIANT: &str = "amd64-openrc";

/// Returns `false` and prints a skip note when the network tests are not
/// enabled.
fn network_enabled() -> bool {
    if std::env::var_os(NETWORK_GATE).is_some() {
        return true;
    }
    assert!(
        std::env::var_os(REQUIRE_GATE).is_none(),
        "{REQUIRE_GATE} is set and {NETWORK_GATE} is not, so the Gentoo tests would have \
         been skipped",
    );
    eprintln!("skipping: set {NETWORK_GATE}=1 to run the Gentoo archive tests");
    false
}

#[test]
fn the_archive_publishes_the_enumeration_this_layer_reads() {
    if !network_enabled() {
        return;
    }
    let mut gentoo = Gentoo::builder(ARCHITECTURE)
        .build()
        .expect("the architecture and the vendored keyring are usable");
    let available = gentoo
        .available()
        .expect("the archive serves a pointer this layer can verify and read");

    // The variant the tests install, spelled as the whole compound the document
    // publishes. If this stops holding, the archive has renamed what it offers.
    assert!(
        available.contains(VARIANT),
        "{ARCHITECTURE} publishes {VARIANT}; it offers {:?}",
        available.variants().collect::<Vec<_>>(),
    );
    // A sub-architecture is a sibling in the same document rather than a
    // variant of the one it was fetched under. This is the finding the variant
    // spelling rests on, so it is worth catching upstream changing its mind.
    assert!(
        available
            .variants()
            .any(|variant| variant.starts_with("x32-")),
        "amd64's document lists x32 variants as siblings: {:?}",
        available.variants().collect::<Vec<_>>(),
    );

    // The build id belongs to the entry rather than to the document: the x32
    // entries are routinely months older than the rest.
    let build = available
        .build_id(VARIANT)
        .expect("the variant it just reported");
    assert_eq!(build.len(), 16, "a build id is a timestamp: {build}");
    assert!(
        available.size(VARIANT).is_some_and(|size| size > 1 << 26),
        "a stage3 is hundreds of megabytes",
    );
    // The regeneration timestamp is the only freshness bound there is, and a
    // resolve refuses without it.
    assert!(available.published().is_some(), "the pointer states its ts");
}

#[test]
fn a_resolution_names_a_build_and_the_digest_it_is_held_to() {
    if !network_enabled() {
        return;
    }
    let mut gentoo = Gentoo::builder(ARCHITECTURE)
        .variant(VARIANT)
        .build()
        .expect("the builder accepts an ordinary configuration");
    let stage3 = gentoo
        .resolve()
        .expect("the archive serves a pointer and a digest document that verify");

    assert_eq!(stage3.variant(), VARIANT);
    assert_eq!(
        stage3.path(),
        format!(
            "{}/stage3-{VARIANT}-{}.tar.xz",
            stage3.build_id(),
            stage3.build_id()
        ),
    );
    assert_eq!(stage3.sha512().len(), 128, "{}", stage3.sha512());
    // The releng key is what signs the release documents, and it is the
    // identity a policy pinning this archive would pin. A rotation to another
    // certificate in the keyring is a thing to notice rather than to absorb.
    assert_eq!(
        stage3.certificate(),
        "13EBBDBEDE7A12775DFDB1BABB572E0E2D182910",
        "the Automated Weekly Release Key vouches for the digests",
    );
}

#[test]
fn a_bootstrap_produces_a_root_gentoo_recognizes() {
    if !network_enabled() {
        return;
    }
    let root = common::scratch_dir("gentoo-bootstrap").join("rootfs");
    let mut gentoo = Gentoo::builder(ARCHITECTURE)
        .variant(VARIANT)
        .cache_dir(common::download_cache("gentoo"))
        .build()
        .expect("the builder accepts an ordinary configuration");
    assert_eq!(
        provision::ensure(&root, &mut gentoo).expect("the stage3 verifies and extracts"),
        Provisioned::Created,
    );

    // What Gentoo's own files say about the tree, rather than what this crate
    // says about what it wrote.
    let release = std::fs::read_to_string(root.join("etc/gentoo-release"))
        .expect("a stage3 lays down /etc/gentoo-release");
    assert!(release.contains("Gentoo"), "{release}");
    let os_release = std::fs::read_to_string(root.join("etc/os-release"))
        .expect("a stage3 lays down /etc/os-release");
    // Gentoo quotes every value in this file, which is worth matching rather
    // than matching around: the assertion is about the file it publishes.
    assert!(os_release.contains("ID='gentoo'"), "{os_release}");
    // The pieces a build in this root would reach for: portage's own tooling,
    // its configuration, and a shell.
    for path in [
        "usr/lib/portage",
        "etc/portage",
        "bin/bash",
        "usr/bin/emerge",
    ] {
        assert!(
            root.join(path).exists(),
            "a stage3 holds {path}: {}",
            root.display(),
        );
    }

    // A second publication reuses the tree rather than downloading again.
    assert_eq!(
        provision::ensure(&root, &mut gentoo).expect("the published root is reused"),
        Provisioned::Existing,
    );
    provision::remove(&root).expect("the root removes");
}
