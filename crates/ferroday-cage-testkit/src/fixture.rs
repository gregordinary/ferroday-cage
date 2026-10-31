//! The pinned Alpine minirootfs every sandbox test launches against.
//!
//! The tarball is fetched and verified here, and provisioned into a root
//! filesystem by the caller. Provisioning takes the library's tarball
//! provisioner, which is behind its `tarball` feature, and this crate enables no
//! library feature (see the crate documentation). So each suite's `common`
//! module, and a unit test that needs the root, hands in the provisioning as a
//! closure: `|tarball, root| provision::ensure(root, &mut Tarball::new(tarball))`.
//! Every test that launches against the fixture therefore also exercises the
//! extraction path.

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use crate::scratch::{cache_dir, scratch_dir};

/// Returns the Alpine minirootfs fixture, provisioned from its tarball by
/// `provision`, or `None` when the host cannot create unprivileged user
/// namespaces and the sandbox tests should skip.
///
/// The skip goes through [`require::userns`](crate::require::userns), so
/// `FERRODAY_CAGE_REQUIRE_USERNS` turns it into a failure.
///
/// `provision` runs at most once per process, the first time any test asks; it
/// is handed the verified tarball and the directory to publish the root at.
#[track_caller]
pub fn fixture_rootfs<T, E: Display>(
    provision: impl FnOnce(&Path, &Path) -> Result<T, E>,
) -> Option<&'static Path> {
    if !crate::require::userns() {
        return None;
    }
    Some(fixture(provision))
}

/// Fetches the fixture once per process and returns the provisioned root.
///
/// The fixture script downloads and verifies the pinned minirootfs tarball.
/// The fixture is shared by every test in the workspace and must be treated as
/// read-only.
fn fixture<T, E: Display>(provision: impl FnOnce(&Path, &Path) -> Result<T, E>) -> &'static Path {
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
        if let Err(err) = provision(&tarball, &rootfs) {
            panic!("the fixture rootfs is provisionable: {err}");
        }
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
///
/// `provision` is [`fixture_rootfs`]'s.
#[track_caller]
pub fn scratch_rootfs<T, E: Display>(
    name: &str,
    provision: impl FnOnce(&Path, &Path) -> Result<T, E>,
) -> Option<PathBuf> {
    let fixture = fixture_rootfs(provision)?;
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
