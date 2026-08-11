//! What the provisioning types show when they are formatted.
//!
//! Each of these holds something that must not be printed — a caller's trait
//! object, which has nothing useful to show, or a repository's trust anchor,
//! which is bulky and says nothing a reader can act on. A rendering is the
//! easiest place for either to escape into a log, so what each one puts there
//! is asserted from outside the crate, as a consumer sees it.
//!
//! The types live behind different features, so this file gates each test on
//! the feature its subject needs rather than declaring `required-features` on
//! the target: the publication and removal renderings are part of a featureless
//! build's public API, and gating the whole binary would stop covering them.

#[cfg(feature = "debian")]
use std::path::Path;

use ferroday_cage::DirectMapper;
use ferroday_cage::provision::{Provision, ProvisionEvent, ProvisionObserver, Remove};

#[cfg(feature = "tarball")]
use ferroday_cage::IdentityMap;
#[cfg(feature = "tarball")]
use ferroday_cage::provision::Export;

#[cfg(feature = "debian")]
use ferroday_cage::provision::debian::{Debian, Pool, Repository};

/// A recognizable stand-in for a keyring, so a test can look for its bytes in
/// a rendering. `build` reads the file without parsing it, which is what lets
/// this be plain text.
#[cfg(feature = "debian")]
const ANCHOR: &[u8] = b"NOT-A-REAL-KEYRING-BUT-DISTINCTIVE-ENOUGH-TO-FIND";

/// Writes the stand-in anchor to a file of its own, in a directory that is
/// removed when the returned guard drops.
#[cfg(feature = "debian")]
fn anchor_file(tag: &str) -> Anchor {
    let dir =
        std::env::temp_dir().join(format!("ferroday-cage-debug-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
    let file = dir.join("keyring.gpg");
    std::fs::write(&file, ANCHOR).expect("the anchor is writable");
    Anchor { dir, file }
}

/// The anchor file and the scratch directory holding it, which is removed when
/// the guard drops.
///
/// Dereferences to the anchor file's path, so it stands in for one at a call
/// site.
#[cfg(feature = "debian")]
struct Anchor {
    dir: std::path::PathBuf,
    file: std::path::PathBuf,
}

#[cfg(feature = "debian")]
impl std::ops::Deref for Anchor {
    type Target = std::path::Path;

    fn deref(&self) -> &std::path::Path {
        &self.file
    }
}

#[cfg(feature = "debian")]
impl AsRef<std::path::Path> for Anchor {
    fn as_ref(&self) -> &std::path::Path {
        &self.file
    }
}

#[cfg(feature = "debian")]
impl Drop for Anchor {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An observer that does nothing, for the builders that take one.
struct Silent;

impl ProvisionObserver for Silent {
    fn progress(&mut self, _: ProvisionEvent<'_>) {}
}

#[cfg(feature = "debian")]
#[test]
fn a_builder_shows_its_settings_and_names_its_delegate() {
    // A builder is configured across many calls and then handed off, so a
    // rendering of one is how a caller checks what it actually assembled. Every
    // setting has to be in it, or the rendering answers a different question
    // than the one being asked.
    let mut sink = |_event: ferroday_cage::provision::debian::DebianEvent<'_>| {};
    let builder = Debian::builder("trixie")
        .architecture("arm64")
        .mirror("https://example.invalid/debian")
        .include(["curl"])
        .exclude(["systemd"])
        .cache_dir("/var/cache/build")
        .trust_unsigned(true);

    // The builder holds the primary's settings separately until `build`
    // assembles them, so its rendering is the only place they can be read.
    let rendering = format!("{builder:?}");
    for expected in [
        "mirror: Some(\"https://example.invalid/debian\")",
        "trust_unsigned: true",
        // No fetcher was substituted, so the default is still to be resolved.
        "fetcher: None",
    ] {
        assert!(
            rendering.contains(expected),
            "the builder's rendering does not carry {expected:?}: {rendering}",
        );
    }

    let mut debian = builder.build().expect("the builder validates");

    let rendering = format!("{debian:?}");
    for expected in [
        "trixie",
        "arm64",
        "curl",
        "systemd",
        "/var/cache/build",
        // The fetcher is a trait object, named rather than shown.
        "fetcher: <dyn Fetch>",
    ] {
        assert!(
            rendering.contains(expected),
            "the rendering does not carry {expected:?}: {rendering}",
        );
    }

    // Observing wraps the bootstrap; the rendering carries it and names the
    // sink, which is a caller's own observer and has nothing to show.
    let observed = debian.observe(&mut sink);
    let rendering = format!("{observed:?}");
    assert!(
        rendering.contains("sink: <dyn DebianObserver>"),
        "{rendering}"
    );
    assert!(rendering.contains("trixie"), "{rendering}");
}

#[test]
fn an_absent_delegate_renders_as_absent_and_a_present_one_as_present() {
    // The one thing a rendering is asked about a delegate is whether it is
    // there, so the two cases have to look different.
    let mapper = DirectMapper::new();
    let bare = Remove::new("/srv/rootfs");
    assert!(format!("{bare:?}").contains("mapper: None"), "{bare:?}");

    let removal = Remove::new("/srv/rootfs").mapper(&mapper);
    assert!(
        format!("{removal:?}").contains("mapper: Some(<dyn IdMapper>)"),
        "{removal:?}",
    );

    // And on a publication, whose delegate is an observer rather than a mapper.
    let mut observer = Silent;
    let quiet = format!("{:?}", Provision::new("/srv/rootfs"));
    assert!(quiet.contains("observer: None"), "{quiet}");
    let watched = Provision::new("/srv/rootfs").observe(&mut observer);
    assert!(
        format!("{watched:?}").contains("observer: Some(<dyn ProvisionObserver>)"),
        "{watched:?}",
    );
}

#[cfg(feature = "tarball")]
#[test]
fn an_export_shows_whether_it_has_a_mapper() {
    // The export takes the same delegate as the removal above, and answers the
    // same question about it: present or absent, told apart at a glance.
    let without = format!("{:?}", Export::new("/srv/rootfs"));
    assert!(without.contains("mapper: None"), "{without}");

    let mapper = DirectMapper::new();
    let with = format!("{:?}", Export::new("/srv/rootfs").mapper(&mapper));
    assert!(with.contains("mapper: Some(<dyn IdMapper>)"), "{with}");
}

#[cfg(feature = "tarball")]
#[test]
fn an_export_carries_the_settings_that_decide_its_output() {
    // An export's bytes are a function of these three, so a caller comparing
    // two archives that should have matched reads them off the rendering.
    let mapper = DirectMapper::new();
    let export = Export::new("/srv/rootfs")
        .map(IdentityMap::Subordinate)
        .mapper(&mapper)
        .clamp_mtime(1_700_000_000);
    let rendering = format!("{export:?}");
    for expected in [
        "/srv/rootfs",
        "Subordinate",
        "clamp_mtime: Some(1700000000)",
    ] {
        assert!(
            rendering.contains(expected),
            "{expected:?} missing: {rendering}"
        );
    }
}

#[cfg(feature = "debian")]
#[test]
fn no_trust_anchor_bytes_reach_a_rendering() {
    // A keyring is the one thing in this family that is both large and
    // uninformative, and a repository is routinely logged while a bootstrap is
    // being debugged. Its length is kept, because an empty or truncated
    // keyring is a real misconfiguration and looks identical to a whole one
    // otherwise.
    let path = anchor_file("anchor");
    let repository = Repository::builder("trixie")
        .mirror("https://example.invalid/debian")
        .keyring(&path)
        .name("extra")
        .build()
        .expect("the repository validates");

    let rendering = format!("{repository:?}");
    assert!(
        !rendering.contains("NOT-A-REAL-KEYRING"),
        "the anchor bytes reached the rendering: {rendering}",
    );
    assert!(
        rendering.contains(&format!("Signed({} bytes)", ANCHOR.len())),
        "the rendering does not name the anchor: {rendering}",
    );

    // A repository builder holds the anchor as the path it will be read from,
    // so it names the trust anchor without ever having held it.
    let unbuilt = Repository::builder("trixie")
        .mirror("https://example.invalid/debian")
        .keyring(&path);
    let rendering = format!("{unbuilt:?}");
    assert!(
        !rendering.contains("NOT-A-REAL-KEYRING"),
        "the builder read the anchor into its rendering: {rendering}",
    );
    assert!(
        rendering.contains("keyring.gpg"),
        "the builder's rendering does not name the anchor's path: {rendering}",
    );

    // An unsigned repository says so, rather than showing an empty anchor.
    let unsigned = Repository::builder("trixie")
        .mirror("file:///srv/pool")
        .trust_unsigned(true)
        .build()
        .expect("the repository validates");
    assert!(format!("{unsigned:?}").contains("Unsigned"), "{unsigned:?}");

    // The primary carries the embedded archive keyring, which is the largest
    // anchor the crate ever holds and the one a default bootstrap has without
    // the caller doing anything. A rendering of the bootstrap stays small.
    let default = Debian::builder("trixie")
        .build()
        .expect("the builder validates");
    let rendering = format!("{default:?}");
    assert!(
        rendering.len() < 2000,
        "a bootstrap rendered {} characters, which is a dumped keyring: {rendering}",
        rendering.len(),
    );
    assert!(rendering.contains("Signed("), "{rendering}");
}

#[cfg(feature = "debian")]
#[test]
fn a_pool_names_the_layout_it_would_write() {
    // Everything that decides where a publish lands and what its release says,
    // which is what a caller checks when a pool wrote somewhere unexpected.
    let pool = Pool::at("/srv/pool")
        .suite("trixie")
        .component("contrib")
        .architecture("riscv64")
        .date(1_700_000_000);
    let rendering = format!("{pool:?}");
    for expected in ["/srv/pool", "trixie", "contrib", "riscv64", "1700000000"] {
        assert!(
            rendering.contains(expected),
            "{expected:?} missing: {rendering}"
        );
    }

    // A pool left at its defaults says so rather than showing a resolved value
    // it has not chosen yet: the architecture is settled at publish time.
    let bare = format!("{:?}", Pool::at(Path::new("/srv/pool")));
    assert!(bare.contains("architecture: None"), "{bare}");
    assert!(bare.contains("date: None"), "{bare}");
}
