//! Scratch directories that clear themselves, and the fixture cache they sit
//! beside.

use std::path::{Path, PathBuf};

/// The fixture cache directory: `FERRODAY_CAGE_FIXTURE_DIR` when set, otherwise
/// a directory inside `target` so `cargo clean` clears it.
///
/// Shared by both crates' suites, so the pinned tarball is downloaded and
/// extracted once for the whole workspace.
pub fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("FERRODAY_CAGE_FIXTURE_DIR") {
        return PathBuf::from(dir);
    }
    // The test binary lives at target/<profile>/deps/<name>; the fixture cache
    // sits beside the profile directories.
    let exe = std::env::current_exe().expect("the test binary has a path");
    exe.ancestors()
        .nth(3)
        .expect("the test binary lives under target/")
        .join("test-fixtures")
}

/// The download cache one network suite keeps across runs, named for the suite:
/// `download_cache("gentoo")` is where `tests/gentoo.rs` keeps its stage3.
///
/// `FERRODAY_CAGE_FIXTURE_DIR` when set, and otherwise the system temporary
/// directory rather than a place under `target`, which is the one thing it does
/// differently from every other directory here. What these hold is up to half a
/// gigabyte fetched from a live archive; a `cargo clean` that cost that much to
/// undo would be a reason not to run the network suites at all. It is one fixed
/// directory per suite either way, so nothing accumulates run over run.
pub fn download_cache(suite: &str) -> PathBuf {
    let base = std::env::var_os("FERRODAY_CAGE_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let cache = base.join(format!("ferroday-cage-{suite}-cache"));
    std::fs::create_dir_all(&cache).expect("the download cache is creatable");
    cache
}

/// Creates an empty scratch directory for one test, under `target` so
/// `cargo clean` clears it. Any previous run's directory is removed first.
pub fn scratch_dir(name: &str) -> PathBuf {
    let dir = cache_dir().join(format!("scratch-{name}"));
    if dir.exists() {
        force_remove_dir_all(&dir);
        assert!(!dir.exists(), "the previous scratch directory is removable");
    }
    std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
    dir
}

/// Removes a directory tree, restoring traversable permissions as it descends.
///
/// An overlay-rooted cage leaves a mode-`0` `work/work` directory in its work
/// area, which a plain recursive removal cannot read into; a scratch directory
/// that hosted one is otherwise unremovable on the next run. Every entry was
/// created by the test process, so making each directory traversable first lets
/// the removal complete.
pub fn force_remove_dir_all(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                force_remove_dir_all(&entry.path());
            }
        }
        let _ = std::fs::remove_dir(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

/// Whether `/dev/net/tun` is present and openable, the additional host
/// requirement of the native network stack; the tests that need it skip when it
/// is unavailable.
///
/// The skip is always explicit: it is reported on stderr, and setting
/// `FERRODAY_CAGE_REQUIRE_TUN` turns it into a failure so that CI can assert
/// the network-stack tests actually ran.
pub fn tun_available() -> bool {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
    {
        Ok(_) => true,
        Err(err) => {
            assert!(
                std::env::var_os("FERRODAY_CAGE_REQUIRE_TUN").is_none(),
                "/dev/net/tun is required but unavailable: {err}"
            );
            eprintln!("skipping: /dev/net/tun is unavailable: {err}");
            false
        }
    }
}
