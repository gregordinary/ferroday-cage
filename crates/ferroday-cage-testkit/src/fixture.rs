//! The pinned Alpine minirootfs every sandbox test launches against.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use crate::scratch::{cache_dir, scratch_dir};

/// Returns the Alpine minirootfs fixture, or `None` when the host cannot create
/// unprivileged user namespaces and the sandbox tests should skip.
///
/// A skip is always explicit: it is reported on stderr, and setting
/// `FERRODAY_CAGE_REQUIRE_USERNS` turns it into a failure so that CI can assert
/// the sandbox tests actually ran.
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
/// The fixture script downloads and verifies the pinned minirootfs tarball; the
/// rootfs is then provisioned from it through the library's own tarball
/// provisioner, so every integration test also exercises the extraction path.
/// The fixture is shared by every test in the workspace and must be treated as
/// read-only.
fn fixture() -> &'static Path {
    static ROOTFS: OnceLock<PathBuf> = OnceLock::new();
    ROOTFS.get_or_init(|| {
        let output = Command::new("sh")
            .arg(fixture_script())
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

/// The fixture script, which lives with the library crate that pins the
/// tarball's URL and digest.
///
/// Reached from this crate's own manifest directory, which sits beside the
/// library's under `crates/`.
fn fixture_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate sits under crates/")
        .join("ferroday-cage/tests/fixtures/alpine-minirootfs.sh")
}

/// Copies the fixture rootfs into a scratch directory, for tests whose
/// sandboxes write into the rootfs (the shared fixture is read-only). Returns
/// `None` when the sandbox tests should skip.
pub fn scratch_rootfs(name: &str) -> Option<PathBuf> {
    let fixture = fixture_rootfs()?;
    let rootfs = scratch_dir(name).join("rootfs");
    let status = Command::new("cp")
        .arg("-a")
        .arg(fixture)
        .arg(&rootfs)
        .status()
        .expect("failed to run cp");
    assert!(status.success(), "copying the fixture rootfs failed");
    Some(rootfs)
}
