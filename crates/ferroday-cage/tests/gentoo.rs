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

/// The architecture the live tests read, and the variant they install: the
/// smallest ordinary root the archive publishes for it.
const ARCHITECTURE: &str = "amd64";
const VARIANT: &str = "amd64-openrc";

/// The binary-package tree that goes with them.
const BINHOST: &str = "x86-64";

/// Whether the network-dependent tests run: [`NETWORK_GATE`] opts in, and
/// `FERRODAY_CAGE_REQUIRE_NETWORK_TEST` turns not opting in into a failure.
fn network_enabled() -> bool {
    common::require::network_suite(NETWORK_GATE, "the Gentoo archive tests")
}

#[test]
fn the_archive_publishes_the_enumeration_this_layer_reads() {
    if !network_enabled() {
        return;
    }
    let mut gentoo = Gentoo::builder(ARCHITECTURE)
        .build()
        .expect("the architecture and the vendored keyring are usable");
    let variants = gentoo
        .variants()
        .expect("the archive serves a pointer this layer can verify and read");

    // The variant the tests install, spelled as the whole compound the document
    // publishes. If this stops holding, the archive has renamed what it offers.
    assert!(
        variants.contains(VARIANT),
        "{ARCHITECTURE} publishes {VARIANT}; it offers {:?}",
        variants.names().collect::<Vec<_>>(),
    );
    // A sub-architecture is a sibling in the same document rather than a
    // variant of the one it was fetched under. This is the finding the variant
    // spelling rests on, so it is worth catching upstream changing its mind.
    assert!(
        variants.names().any(|variant| variant.starts_with("x32-")),
        "amd64's document lists x32 variants as siblings: {:?}",
        variants.names().collect::<Vec<_>>(),
    );

    // The build id belongs to the entry rather than to the document: the x32
    // entries are routinely months older than the rest.
    let build = variants
        .build_id(VARIANT)
        .expect("the variant it just reported");
    assert_eq!(build.len(), 16, "a build id is a timestamp: {build}");
    assert!(
        variants.size(VARIANT).is_some_and(|size| size > 1 << 26),
        "a stage3 is hundreds of megabytes",
    );
    // The regeneration timestamp is the only freshness bound there is, and a
    // resolve refuses without it.
    assert!(variants.published().is_some(), "the pointer states its ts");
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

#[test]
fn the_binhost_publishes_the_index_this_layer_reads() {
    if !network_enabled() {
        return;
    }
    let mut gentoo = Gentoo::builder(ARCHITECTURE)
        .binhost(BINHOST)
        .build()
        .expect("the architecture and the binhost are usable coordinates");
    let catalogue = gentoo
        .packages()
        .expect("the archive serves an index this layer can read");

    // The shape rather than a number: the archive moves, and what would be
    // worth noticing is it stopping being a package set at all.
    assert!(
        catalogue.len() > 5_000,
        "the binhost publishes thousands of packages, not {}",
        catalogue.len(),
    );
    // More builds than names, because a version is published more than once --
    // which is the finding the whole selection rule rests on.
    assert!(
        catalogue.builds() > catalogue.len(),
        "{} builds over {} names",
        catalogue.builds(),
        catalogue.len(),
    );
    assert!(
        catalogue.contains("dev-vcs/git"),
        "the binhost publishes git"
    );
    assert!(
        catalogue.versions("dev-vcs/git").next().is_some(),
        "git is published in some version",
    );
    // The coverage statement, held to: the binhost installs most things and
    // not everything, and this is one of the ones it does not.
    assert!(
        !catalogue.contains("app-misc/jq"),
        "the binhost has begun publishing app-misc/jq, so the guide's coverage \
         example needs a different package",
    );
    // The preamble's own target triple, which is the one field of it that
    // tracks the packages rather than the machine that generated the index.
    assert_eq!(catalogue.chost(), Some("x86_64-pc-linux-gnu"));
}

#[test]
fn an_install_wave_merges_packages_portage_reads_back() {
    if !network_enabled() {
        return;
    }
    let root = common::scratch_dir("gentoo-binhost").join("rootfs");
    let mut gentoo = Gentoo::builder(ARCHITECTURE)
        .variant(VARIANT)
        .binhost(BINHOST)
        // Small, and it exercises the shapes that matter: a closure of several
        // packages, a file and a symbolic link in each image, and a dependency
        // the stage3 already answers.
        .install(["app-editors/vim"])
        .cache_dir(common::download_cache("gentoo"))
        .build()
        .expect("the builder accepts an ordinary configuration");
    assert_eq!(
        provision::ensure(&root, &mut gentoo).expect("the stage3 and the packages install"),
        Provisioned::Created,
    );

    // The files landed, with the image archive's own wrapper directory
    // stripped rather than laid down.
    assert!(root.join("usr/bin/vim").exists(), "vim is merged");
    assert!(!root.join("image").exists(), "the wrapper is not a path");

    // And the database describes them. Read back through this layer's own
    // reader, which is the same one a later resolution against this root would
    // use -- so what this asserts is that a second run would see the packages
    // as installed rather than install them again.
    let installed = ferroday_cage::provision::gentoo::installed(&root).expect("the database reads");
    let vim = installed
        .packages()
        .find(|package| package.name() == "app-editors/vim")
        .expect("vim is registered");
    assert!(!vim.version().is_empty());
    assert!(!vim.slot().is_empty());

    // A stage3 arrives with 296 entries, so the merged set is larger than what
    // was asked for and much larger than what was installed.
    assert!(
        installed.len() > 296,
        "the stage3's own packages are still registered: {}",
        installed.len(),
    );

    // The entry carries what portage computes at merge as well as what the
    // container shipped, which is the whole of what makes it an entry.
    let entry = root.join("var/db/pkg/app-editors").join(format!(
        "{}-{}",
        vim.name().rsplit('/').next().expect("a package name"),
        vim.version(),
    ));
    for file in [
        "CONTENTS",
        "COUNTER",
        "BINPKGMD5",
        "SLOT",
        "USE",
        "CATEGORY",
    ] {
        assert!(entry.join(file).exists(), "the entry holds {file}");
    }
    // Every CONTENTS line names a path that is actually there, which is what
    // portage's own `qcheck` walks the file to do.
    let contents = std::fs::read_to_string(entry.join("CONTENTS")).expect("CONTENTS reads");
    assert!(!contents.is_empty());
    for line in contents.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(kind), Some(path)) = (fields.next(), fields.next()) else {
            panic!("a CONTENTS line names no path: {line}");
        };
        assert!(
            matches!(kind, "dir" | "obj" | "sym"),
            "an unknown CONTENTS entry kind: {line}",
        );
        let path = root.join(path.trim_start_matches('/'));
        assert!(
            path.symlink_metadata().is_ok(),
            "CONTENTS names {} and it is not there",
            path.display(),
        );
    }
    // The merge ordinal continued the stage3's own sequence rather than
    // starting again, so no two entries share one.
    let counter: u64 = std::fs::read_to_string(entry.join("COUNTER"))
        .expect("COUNTER reads")
        .trim()
        .parse()
        .expect("COUNTER is a number");
    assert!(counter > 1, "the ordinal continues the stage3's: {counter}");

    provision::remove(&root).expect("the root removes");
}

#[test]
fn a_plan_replays_what_a_resolution_chose() {
    if !network_enabled() {
        return;
    }
    // A resolution needs a root to start from, so this reuses the bootstrap's
    // shape: provision a stage3, then ask what installing into it would do.
    let root = common::scratch_dir("gentoo-plan").join("rootfs");
    let mut stage3 = Gentoo::builder(ARCHITECTURE)
        .variant(VARIANT)
        .cache_dir(common::download_cache("gentoo"))
        .build()
        .expect("the builder accepts an ordinary configuration");
    provision::ensure(&root, &mut stage3).expect("the stage3 verifies and extracts");

    let mut gentoo = Gentoo::builder(ARCHITECTURE)
        .binhost(BINHOST)
        .install(["dev-vcs/git"])
        .build()
        .expect("the builder accepts an ordinary configuration");
    let plan = gentoo
        .resolve_packages(&root)
        .expect("the binhost can satisfy git against a stage3");
    assert!(!plan.packages.is_empty());
    assert_eq!(plan.binhost, BINHOST);

    // The measured shape: a stage3 answers most of git's closure, so what is
    // left is a dozen packages rather than a hundred.
    assert!(
        plan.packages.len() < 40,
        "resolution starts from the root: {} packages",
        plan.packages.len(),
    );
    // git merges last, because everything else is what it needs.
    assert_eq!(plan.packages.last().expect("a package").name, "dev-vcs/git",);

    // And the plan round-trips through its document, which is what makes it a
    // pin worth committing.
    let document = plan.to_document().expect("the plan renders");
    let kept = ferroday_cage::provision::gentoo::Plan::parse_document(&document)
        .expect("the document reads back");
    assert_eq!(kept, plan);

    // Replayed as an increment over the root it was resolved against, the plan
    // installs what it names: every container verifies, and the slots and
    // blockers its own metadata states agree with the root it lands in.
    let upper = root.with_file_name("upper");
    let mut replay = Gentoo::builder(ARCHITECTURE)
        .binhost(BINHOST)
        .plan(kept)
        .base_layer(&root)
        .cache_dir(common::download_cache("gentoo"))
        .build()
        .expect("the builder accepts the plan it resolved");
    let layer = replay
        .stage_layer(&upper)
        .expect("the plan replays over the root it was resolved against");
    let git = plan.packages.last().expect("a package");
    assert!(
        upper
            .join(format!("var/db/pkg/{}-{}", git.name, git.version))
            .is_dir(),
        "the replay registers what it merged",
    );
    // Over a view that already holds every package it names, the same plan
    // installs nothing.
    let again = replay
        .stage_layer(&upper)
        .expect("a plan the root already holds replays as nothing");
    drop(again);
    drop(layer);

    provision::remove(&root).expect("the root removes");
}

#[test]
fn an_atom_the_binhost_cannot_satisfy_says_which_wall_it_hit() {
    if !network_enabled() {
        return;
    }
    // Against an empty root rather than a stage3, which is a real answer as
    // well as a cheap one: with nothing installed, git's closure reaches an
    // `app-crypt/pinentry` the binhost publishes in no version, and that is the
    // finding the whole root-first design rests on.
    let root = common::scratch_dir("gentoo-unsatisfiable").join("empty");
    std::fs::create_dir_all(&root).expect("the directory is created");
    let mut gentoo = Gentoo::builder(ARCHITECTURE)
        .binhost(BINHOST)
        .install(["app-misc/jq"])
        .build()
        .expect("the builder accepts an ordinary configuration");
    let error = gentoo
        .resolve_packages(&root)
        .expect_err("the binhost publishes no app-misc/jq");
    let message = error.to_string();
    assert!(
        message.contains("app-misc/jq") && message.contains("published by this binhost"),
        "the refusal names the atom and the wall: {message}",
    );
}

/// An increment staged over a stage3 leaves the base's merged-usr links in
/// place, in the merged view a build sandbox is rooted on.
///
/// A stage3 holds `lib64` and `sbin` as links into `usr`, and the binhost's
/// lvm2 ships `lib64/libdevmapper.so.1.02` and `sbin/dmsetup`. Merged into a
/// bare upper those become directories, which the overlay shows over the
/// links: the merged `/lib64` then holds libdevmapper alone, and no dynamically
/// linked program finds its loader.
#[test]
fn an_increment_over_a_stage3_keeps_its_merged_usr_links() {
    if !network_enabled() {
        return;
    }
    // The merged view is read through a sandbox, which needs user namespaces;
    // the fixture probe reports the skip.
    let Some(_) = common::fixture_rootfs() else {
        return;
    };
    let scratch = common::scratch_dir("gentoo-layered");
    if !common::require::overlay(&scratch) {
        return;
    }
    let base = scratch.join("base");
    let mut stage3 = Gentoo::builder(ARCHITECTURE)
        .variant(VARIANT)
        .cache_dir(common::download_cache("gentoo"))
        .build()
        .expect("the builder accepts an ordinary configuration");
    provision::ensure(&base, &mut stage3).expect("the stage3 verifies and extracts");
    for link in ["lib64", "sbin"] {
        assert!(
            base.join(link)
                .symlink_metadata()
                .expect("the stage3 holds it")
                .is_symlink(),
            "the stage3 is merged-usr at {link}",
        );
    }

    let upper = scratch.join("upper");
    let mut increment = Gentoo::builder(ARCHITECTURE)
        .binhost(BINHOST)
        .install(["sys-fs/lvm2"])
        .base_layer(&base)
        .cache_dir(common::download_cache("gentoo"))
        .build()
        .expect("the builder accepts an ordinary configuration");
    let layer = increment
        .stage_layer(&upper)
        .expect("lvm2 stages over the stage3");

    // Whatever lvm2 ships under `lib64/` and `sbin/` went through the links:
    // the upper holds no directory at either name.
    for name in ["lib64", "sbin"] {
        if let Ok(found) = upper.join(name).symlink_metadata() {
            assert!(!found.is_dir(), "the upper hides the base's {name}");
        }
    }
    // And the merged view agrees, read by the shell the stage3 ships, which
    // itself execs only while `/lib64` reaches the loader.
    let status = ferroday_cage::Cage::builder()
        .overlay_rootfs(&base, layer.path())
        .command("/bin/bash")
        .args([
            "-c",
            "test -L /lib64 && test -L /sbin && test -e /lib64/libdevmapper.so.1.02 \
             && test -x /sbin/dmsetup",
        ])
        .build()
        .expect("the build sandbox is valid")
        .run()
        .expect("the build sandbox runs");
    assert!(status.success(), "the merged view keeps the base's links");

    drop(layer);
    provision::remove(&base).expect("the base removes");
}
