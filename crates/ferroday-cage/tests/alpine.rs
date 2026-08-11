//! Integration tests for the Alpine userland provisioner.
//!
//! The hermetic tests live beside the code they exercise, where the committed
//! archive fixtures are. What is here is what needs a live repository: a
//! bootstrap of the real `alpine-base` closure, and the proof that the root it
//! produces is one `apk` and `busybox` agree with.

mod common;

use ferroday_cage::provision::alpine::{Alpine, AlpineEvent, KeySet, Repository};
use ferroday_cage::provision::{self, Provisioned};

/// The environment variable that opts into the network-dependent bootstrap
/// tests. They fetch from a live Alpine mirror and are off by default, so a
/// plain `cargo test --all-features` — CI included — does not reach the
/// network.
const NETWORK_GATE: &str = "FERRODAY_CAGE_ALPINE_NETWORK_TEST";

/// Returns `false` and prints a skip note when the network tests are not
/// enabled.
fn network_enabled() -> bool {
    if std::env::var_os(NETWORK_GATE).is_some() {
        return true;
    }
    eprintln!("skipping: set {NETWORK_GATE}=1 to run the Alpine bootstrap tests");
    false
}

/// A cache directory for downloaded packages, kept across runs so the tests do
/// not re-download the base system each time.
fn apk_cache() -> std::path::PathBuf {
    let base = std::env::var_os("FERRODAY_CAGE_FIXTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let cache = base.join("ferroday-cage-alpine-cache");
    std::fs::create_dir_all(&cache).unwrap();
    cache
}

/// The release the live tests bootstrap.
const RELEASE: &str = "v3.23";

#[test]
fn full_bootstrap_configures_a_runnable_alpine() {
    if !network_enabled() {
        return;
    }
    let Some(_) = common::fixture_rootfs() else {
        // The scripts run inside a cage, which needs user namespaces; the
        // fixture probe reports the skip.
        return;
    };
    let rootfs = common::scratch_dir("alpine-full").join("rootfs");
    {
        let mut progress = |event: AlpineEvent<'_>| {
            if let AlpineEvent::CommandOutput { bytes, .. } = event {
                use std::io::Write;
                let _ = std::io::stderr().write_all(bytes);
            }
        };
        let mut alpine = Alpine::builder(RELEASE)
            .include(["alpine-base"])
            .cache_dir(apk_cache())
            .build()
            .expect("the builder validates");
        assert_eq!(
            provision::ensure(&rootfs, &mut alpine.observe(&mut progress))
                .expect("the full bootstrap runs"),
            Provisioned::Created,
        );
    }

    // `busybox`'s post-install ran: `/bin/busybox --install -s` is what creates
    // every applet link, and nothing else in the closure ships one.
    assert!(
        rootfs.join("bin/busybox").is_file(),
        "the package's own binary",
    );
    let ls = rootfs.join("bin/ls");
    assert_eq!(
        std::fs::read_link(&ls).expect("the applet link was created by a script"),
        std::path::Path::new("/bin/busybox"),
    );

    // `alpine-baselayout`'s pre-install ran, and ran late enough to find the
    // `addgroup` applet the link above provides. Running the scripts in name
    // order rather than dependency order loses exactly this.
    let group = std::fs::read_to_string(rootfs.join("etc/group")).expect("the file is there");
    assert!(
        group.lines().any(|line| line.starts_with("shadow:")),
        "the pre-install added the shadow group: {group}",
    );

    // The state a later apk reads back.
    assert_eq!(
        std::fs::read_to_string(rootfs.join("etc/apk/world")).expect("the world is written"),
        "alpine-base\n",
    );
    let sources =
        std::fs::read_to_string(rootfs.join("etc/apk/repositories")).expect("it is written");
    assert!(sources.trim_end().ends_with("/v3.23/main"), "{sources}");

    // The finished root runs its own userland.
    let status = ferroday_cage::Cage::builder()
        .rootfs(&rootfs)
        .command("/bin/busybox")
        .args(["true"])
        .build()
        .expect("the cage builds")
        .run()
        .expect("busybox runs in the finished rootfs");
    assert!(status.success(), "the bootstrapped userland executes");

    // And apk inside it agrees with the database this bootstrap wrote: `apk
    // info` reads `installed`, and every unknown field there is fatal to the
    // whole file rather than skipped, so a record this layer got wrong makes
    // this fail rather than merely differ.
    let status = ferroday_cage::Cage::builder()
        .rootfs(&rootfs)
        .command("/sbin/apk")
        .args(["info", "-e", "alpine-base"])
        .build()
        .expect("the cage builds")
        .run()
        .expect("apk runs in the finished rootfs");
    assert!(
        status.success(),
        "apk reads back the database the bootstrap wrote",
    );

    // The stronger form of the same question: `apk audit` walks every file the
    // database records and compares it to what is on disk, so it fails on a
    // digest, a mode, or a path this layer recorded wrongly.
    let status = ferroday_cage::Cage::builder()
        .rootfs(&rootfs)
        .command("/sbin/apk")
        .args(["audit", "--system", "--quiet"])
        .build()
        .expect("the cage builds")
        .run()
        .expect("apk audit runs in the finished rootfs");
    assert!(
        status.success(),
        "every file the database records is the file on disk",
    );
}

/// A root provisioned from Alpine's `main` and postmarketOS's repository at
/// once.
///
/// postmarketOS is the layer's test of whether repository handling is plural in
/// the right places: its archive is byte-identical apk on a path one level
/// shallower, under a key of its own, and it is an overlay rather than a
/// distribution — a postmarketOS root is Alpine's repositories plus these. So
/// what this asserts is not that a file arrived but that the finished root
/// records two archives, trusts two keys, and audits as one system.
#[test]
fn a_root_provisions_from_alpine_and_postmarketos_together() {
    if !network_enabled() {
        return;
    }
    let Some(_) = common::fixture_rootfs() else {
        // The scripts run inside a cage, which needs user namespaces.
        return;
    };
    let rootfs = common::scratch_dir("alpine-postmarketos").join("rootfs");

    let overlay = Repository::builder("v26.06")
        .mirror("http://mirror.postmarketos.org/postmarketos")
        .keys(KeySet::postmarketos())
        .build()
        .expect("the repository validates");
    // Deliberately not `alpine-base`. postmarketOS overrides that package by
    // *providing* it — `postmarketos-base` carries `p:alpine-base=1000-r0`, a
    // version no Alpine release reaches — so naming it here would resolve the
    // whole postmarketOS base system, whose closure reaches Alpine's
    // `community`. `apk` does the same thing with the same two repositories
    // configured, down to failing on the same missing names. What this test is
    // about is two archives in one root, so it names the packages that make one.
    let mut alpine = Alpine::builder(RELEASE)
        .repository(overlay)
        .include([
            "apk-tools",
            "busybox",
            "alpine-baselayout",
            "alpine-keys",
            "postmarketos-baselayout",
        ])
        .cache_dir(apk_cache())
        .build()
        .expect("the builder validates");
    provision::ensure(&rootfs, &mut alpine).expect("the two-repository bootstrap runs");

    // A file only the overlay publishes, laid over the one Alpine's own
    // `alpine-baselayout` ships at the same path — which `postmarketos-baselayout`
    // is allowed to take because it names that package in `replaces`.
    let motd = std::fs::read_to_string(rootfs.join("etc/motd")).expect("the overlay ships one");
    assert!(motd.contains("postmarketOS"), "{motd}");

    // Both archives are recorded, each at the depth it publishes: Alpine names a
    // component and postmarketOS does not, and neither names an architecture.
    let sources =
        std::fs::read_to_string(rootfs.join("etc/apk/repositories")).expect("it is written");
    let lines: Vec<&str> = sources.lines().collect();
    assert_eq!(
        lines,
        [
            "http://dl-cdn.alpinelinux.org/alpine/v3.23/main",
            "http://mirror.postmarketos.org/postmarketos/v26.06",
        ],
        "{sources}",
    );

    // And both trust anchors reached the root. Alpine's arrive as files of the
    // `alpine-keys` package the closure installs; postmarketOS's is written by
    // the bootstrap, since nothing in this closure carries it.
    let keys = rootfs.join("etc/apk/keys");
    assert!(keys.join("build.postmarketos.org.rsa.pub").is_file());
    assert!(
        keys.join("alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub")
            .is_file(),
    );

    // The database describes the merged closure, and apk agrees with it: `audit`
    // walks every file recorded and compares it to what is on disk, so a package
    // taken from the wrong archive, or a collision settled the wrong way, fails
    // here rather than merely differing.
    for args in [
        &["info", "-e", "postmarketos-baselayout"][..],
        &["audit", "--system", "--quiet"][..],
    ] {
        let status = ferroday_cage::Cage::builder()
            .rootfs(&rootfs)
            .command("/sbin/apk")
            .args(args)
            .build()
            .expect("the cage builds")
            .run()
            .expect("apk runs in the finished rootfs");
        assert!(status.success(), "apk {args:?} in the merged root");
    }
}

#[test]
fn extract_only_bootstrap_registers_without_running_anything() {
    if !network_enabled() {
        return;
    }
    let rootfs = common::scratch_dir("alpine-extract-only").join("rootfs");
    let mut alpine = Alpine::builder(RELEASE)
        .include(["alpine-base"])
        .extract_only(true)
        .cache_dir(apk_cache())
        .build()
        .expect("the builder validates");
    provision::ensure(&rootfs, &mut alpine).expect("the extract-only bootstrap runs");

    // The files are laid out and the database is written — apk registration is
    // a file format rather than a program's output, so it costs nothing here.
    assert!(rootfs.join("bin/busybox").is_file());
    let installed =
        std::fs::read_to_string(rootfs.join("lib/apk/db/installed")).expect("it is written");
    assert!(installed.contains("\nP:alpine-base\n"), "{installed}");

    // What did not happen is everything a script would have done.
    assert!(
        !rootfs.join("bin/ls").exists(),
        "no script ran, so no applet link was created",
    );
    // `apk-tools` ships this directory, so its presence says nothing; what says
    // no script ran is that it holds none. A script is written there to be
    // executed and removed once it has been.
    assert_eq!(
        std::fs::read_dir(rootfs.join("lib/apk/exec"))
            .expect("apk-tools ships the directory")
            .count(),
        0,
    );
}

/// The layered build: a base provisioned once, an increment staged over it into
/// a disposable overlay upper, and the base left pristine.
#[test]
fn a_layered_build_stages_an_increment_and_fires_the_bases_triggers() {
    if !network_enabled() {
        return;
    }
    let Some(_) = common::fixture_rootfs() else {
        // The increment's scripts run in a cage, which needs user namespaces.
        return;
    };
    let scratch = common::scratch_dir("alpine-layer");
    if let Some(blocker) = ferroday_cage::host::overlay_blocker(&scratch) {
        eprintln!("skipping: overlay-rooted cages are unavailable: {blocker}");
        return;
    }

    // The shared base, provisioned the ordinary way.
    let base = scratch.join("base");
    {
        let mut alpine = Alpine::builder(RELEASE)
            .include(["alpine-base"])
            .cache_dir(apk_cache())
            .build()
            .expect("the builder validates");
        provision::ensure(&base, &mut alpine).expect("the base bootstrap runs");
    }

    // `su-exec` ships one binary into `/sbin` and needs only musl, which the
    // base already carries — so the increment is that package alone, and the
    // directory it creates is one the base's `busybox` watches.
    let upper = scratch.join("upper");
    let ran: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
    let staged: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
    {
        let mut sink = |event: AlpineEvent<'_>| match event {
            AlpineEvent::Resolved { plan, .. } => {
                *staged.borrow_mut() = plan
                    .packages
                    .iter()
                    .map(|package| package.name.clone())
                    .collect();
            }
            AlpineEvent::Script {
                package, script, ..
            } => {
                ran.borrow_mut().push(format!("{package} {script}"));
            }
            AlpineEvent::CommandOutput { bytes, .. } => {
                use std::io::Write;
                let _ = std::io::stderr().write_all(bytes);
            }
            _ => {}
        };
        let mut alpine = Alpine::builder(RELEASE)
            .base_layer(&base)
            .include(["su-exec"])
            .cache_dir(apk_cache())
            .build()
            .expect("the builder validates");
        let layer = alpine
            .observe(&mut sink)
            .stage_layer(&upper)
            .expect("the increment stages");
        assert_eq!(layer.path(), upper.as_path());

        // The increment holds what the base does not, and nothing else.
        assert_eq!(staged.borrow().as_slice(), ["su-exec"]);

        // The base's own trigger fired for a directory the increment created.
        // `busybox` is not in the increment: this is the base's package, run
        // because the root it belongs to changed, which is what apk does.
        assert!(
            ran.borrow().iter().any(|one| one == "busybox trigger"),
            "the base's busybox watches /sbin, and the increment created it: {:?}",
            ran.borrow(),
        );

        // The files landed in the upper, and the base was not written to.
        assert!(upper.join("sbin/su-exec").is_file());
        assert!(
            !base.join("sbin/su-exec").exists(),
            "the base is the read-only lower",
        );

        // The database in the upper describes the merged root, so an apk inside
        // the build root sees one coherent state rather than the increment
        // alone.
        let installed = std::fs::read_to_string(upper.join("lib/apk/db/installed"))
            .expect("the merged database is written");
        assert!(installed.contains("\nP:su-exec\n"), "the increment");
        assert!(installed.contains("\nP:busybox\n"), "and the base");
        assert_eq!(
            std::fs::read_to_string(upper.join("etc/apk/world")).expect("the world is written"),
            "alpine-base\nsu-exec\n",
        );

        // And apk agrees, read through the merged view the caller builds in.
        for args in [
            &["info", "-e", "su-exec"][..],
            &["info", "-e", "alpine-base"][..],
            &["audit", "--system", "--quiet"][..],
        ] {
            let status = ferroday_cage::Cage::builder()
                .overlay_rootfs(&base, layer.path())
                .command("/sbin/apk")
                .args(args)
                .build()
                .expect("the build cage builds")
                .run()
                .expect("apk runs in the merged root");
            assert!(status.success(), "apk {args:?} in the merged root");
        }
    }

    // Dropping the layer discarded the increment; the base is ready for the
    // next component unchanged.
    assert!(!upper.exists(), "the upper went with the handle");
    assert!(base.join("bin/busybox").is_file());
}

/// Layering over a root `apk` itself wrote, rather than one this layer did.
///
/// The pinned minirootfs is Alpine's own published image: its scripts are
/// archived under `scripts.tar.gz` rather than the plain name this layer writes,
/// and its records are `apk`'s. So this is the proof that a base is read as the
/// format defines it and not as this layer happens to write it.
#[test]
fn an_increment_layers_over_a_root_apk_wrote() {
    if !network_enabled() {
        return;
    }
    let Some(base) = common::fixture_rootfs() else {
        return;
    };
    let scratch = common::scratch_dir("alpine-layer-published");
    if let Some(blocker) = ferroday_cage::host::overlay_blocker(&scratch) {
        eprintln!("skipping: overlay-rooted cages are unavailable: {blocker}");
        return;
    }

    let upper = scratch.join("upper");
    let ran: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
    {
        let mut sink = |event: AlpineEvent<'_>| {
            if let AlpineEvent::Script {
                package, script, ..
            } = event
            {
                ran.borrow_mut().push(format!("{package} {script}"));
            }
        };
        let mut alpine = Alpine::builder(RELEASE)
            .base_layer(base)
            .include(["su-exec"])
            .cache_dir(apk_cache())
            .build()
            .expect("the builder validates");
        let layer = alpine
            .observe(&mut sink)
            .stage_layer(&upper)
            .expect("the increment stages over Alpine's own root");

        assert!(upper.join("sbin/su-exec").is_file());
        assert!(
            !base.join("sbin/su-exec").exists(),
            "the fixture is shared and read-only",
        );
        // The base's trigger came out of its `scripts.tar.gz`, which no root this
        // layer writes carries.
        assert!(
            ran.borrow().iter().any(|one| one == "busybox trigger"),
            "{:?}",
            ran.borrow(),
        );
        // apk reads the merged database back, and audits every file in it
        // against the merged tree.
        let status = ferroday_cage::Cage::builder()
            .overlay_rootfs(base, layer.path())
            .command("/sbin/apk")
            .args(["audit", "--system", "--quiet"])
            .build()
            .expect("the build cage builds")
            .run()
            .expect("apk audits the merged root");
        assert!(status.success(), "the merged database describes the tree");
    }
    assert!(!upper.exists());
}

#[test]
fn a_resolved_plan_installs_the_same_root_it_described() {
    if !network_enabled() {
        return;
    }
    let scratch = common::scratch_dir("alpine-plan");
    let plan = Alpine::builder(RELEASE)
        .include(["musl", "busybox"])
        .cache_dir(apk_cache())
        .build()
        .expect("the builder validates")
        .resolve()
        .expect("the closure resolves against the live archive");
    let document = plan.to_document().expect("the plan is writable");

    let from_plan = scratch.join("from-plan");
    let mut alpine = Alpine::builder(RELEASE)
        .plan(
            ferroday_cage::provision::alpine::Plan::parse_document(&document)
                .expect("the document reads back"),
        )
        .extract_only(true)
        .cache_dir(apk_cache())
        .build()
        .expect("the builder validates");
    provision::ensure(&from_plan, &mut alpine).expect("the plan installs");

    let from_resolve = scratch.join("from-resolve");
    let mut alpine = Alpine::builder(RELEASE)
        .include(["musl", "busybox"])
        .extract_only(true)
        .cache_dir(apk_cache())
        .build()
        .expect("the builder validates");
    provision::ensure(&from_resolve, &mut alpine).expect("the resolution installs");

    // The two modes read their records from different places — one from an
    // index it fetched, one from a document — so the databases agreeing is what
    // says a plan reproduces a root rather than merely naming one.
    assert_eq!(
        std::fs::read(from_plan.join("lib/apk/db/installed")).expect("it is written"),
        std::fs::read(from_resolve.join("lib/apk/db/installed")).expect("it is written"),
    );
}
