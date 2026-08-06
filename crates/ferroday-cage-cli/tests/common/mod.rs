//! Shared helpers for the `fcage` integration tests.
//!
//! Compiled into each integration-test binary; not every binary uses every
//! helper.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Returns the Alpine minirootfs fixture, or `None` when the host cannot
/// create unprivileged user namespaces and the sandbox tests should skip.
///
/// A skip is always explicit: it is reported on stderr, and setting
/// `FERRODAY_CAGE_REQUIRE_USERNS` turns it into a failure so that CI can
/// assert the sandbox tests actually ran. The same rule and the same
/// environment variable as the library's own integration tests.
pub fn fixture_rootfs() -> Option<&'static Path> {
    if let Some(blocker) = ferroday_cage::host::userns_blocker() {
        assert!(
            std::env::var_os("FERRODAY_CAGE_REQUIRE_USERNS").is_none(),
            "unprivileged user namespaces are required but unavailable: {blocker}"
        );
        eprintln!("skipping: unprivileged user namespaces are unavailable: {blocker}");
        return None;
    }
    Some(fixture())
}

/// Fetches the fixture once per process and returns the cached rootfs.
///
/// The library crate owns the fixture script and the cache directory, and this
/// crate reuses both rather than keeping a second copy: the tarball is a pinned,
/// verified download, and one copy per workspace is enough. The rootfs is
/// provisioned through the library's own tarball provisioner, and is shared by
/// every test — treat it as read-only.
fn fixture() -> &'static Path {
    static ROOTFS: OnceLock<PathBuf> = OnceLock::new();
    ROOTFS.get_or_init(|| {
        let script = library_crate().join("tests/fixtures/alpine-minirootfs.sh");
        let output = Command::new("sh")
            .arg(&script)
            .arg(cache_dir())
            .output()
            .expect("failed to run the fixture script");
        assert!(
            output.status.success(),
            "the fixture script failed:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        let path = String::from_utf8(output.stdout).expect("the fixture path is UTF-8");
        let tarball = PathBuf::from(path.trim());
        let name = tarball
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".tar.gz"))
            .expect("the fixture tarball is named *.tar.gz");
        let rootfs = tarball.with_file_name(name);
        ferroday_cage::provision::ensure(
            &rootfs,
            &mut ferroday_cage::provision::Tarball::new(&tarball),
        )
        .expect("the fixture rootfs is provisionable");
        rootfs
    })
}

/// The library crate's directory, which carries the fixture script.
fn library_crate() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate sits under crates/")
        .join("ferroday-cage")
}

/// The fixture cache, shared with the library's tests so the pinned tarball is
/// downloaded and extracted once for the whole workspace.
fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("FERRODAY_CAGE_FIXTURE_DIR") {
        return PathBuf::from(dir);
    }
    // The test binary lives at target/<profile>/deps/<name>; the fixture
    // cache sits beside the profile directories.
    let exe = std::env::current_exe().expect("the test binary has a path");
    exe.ancestors()
        .nth(3)
        .expect("the test binary lives under target/")
        .join("test-fixtures")
}
