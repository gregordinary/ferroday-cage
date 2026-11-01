//! Scratch directories that clear themselves, and the fixture cache they sit
//! beside.

use std::path::{Path, PathBuf};

use ferroday_cage::IdentityMap;
use ferroday_cage::provision::Remove;

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

/// Creates an empty scratch directory for one test, in the fixture cache
/// [`cache_dir`] names, and returns its path.
///
/// No guard removes it: the tree outlives the test, and the next call with the
/// same `name` removes it before creating it again. One fixed name per test is
/// what keeps that from accumulating. The cache sits under `target`, so
/// `cargo clean` clears it, unless `FERRODAY_CAGE_FIXTURE_DIR` moves it.
pub fn scratch_dir(name: &str) -> PathBuf {
    let dir = cache_dir().join(format!("scratch-{name}"));
    if dir.exists() {
        force_remove_dir_all(&dir);
        assert!(!dir.exists(), "the previous scratch directory is removable");
    }
    std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
    dir
}

/// Removes a directory tree the way the library removes one, best effort.
///
/// This is [`Remove`] under the single-identity map, declining the lock, which
/// a scratch tree has none of. The calling user removes what it can. An
/// overlay-rooted cage can leave a mode-`0` directory in its work area with
/// something inside it, and the map's escalation clears that. The walk is the
/// library's own, so a tree a test nested deep is removed like a shallow one.
///
/// A tree holding subordinate-owned entries resists this, as it resists any
/// removal by the calling user; such a tree is a [`ranged_scratch`].
pub fn force_remove_dir_all(path: &Path) {
    let _ = Remove::new(path)
        .identity_map(IdentityMap::Single)
        .remove_lock(false)
        .run();
}

/// A scratch tree for one test that holds subordinate-owned entries, removed
/// through [`Remove`] under the subordinate map when it drops.
///
/// Such a tree resists any removal by the calling user, [`scratch_dir`]'s
/// clearing of a previous run's tree included. So it lives in the system
/// temporary directory rather than under `target`, where a tree that outlived
/// its guard would make `cargo clean` fail, and it is named for the process, so
/// two runs never share one. It is removed before use too, in case the process
/// id was reused. A scratch tree is not a published root, so no publication
/// lock takes part.
pub fn ranged_scratch(tag: &str) -> RangedScratch {
    let path = std::env::temp_dir().join(format!("ferroday-cage-{tag}-{}", std::process::id()));
    remove_ranged(&path);
    std::fs::create_dir_all(&path).expect("the scratch tree is creatable");
    RangedScratch { path }
}

/// Removes a tree that may hold subordinate-owned entries, best effort.
fn remove_ranged(path: &Path) {
    let _ = Remove::new(path)
        .identity_map(IdentityMap::Subordinate)
        .remove_lock(false)
        .run();
}

/// The guard [`ranged_scratch`] returns.
///
/// Dereferences to its [`Path`], so it stands in for one at a call site.
#[derive(Debug)]
pub struct RangedScratch {
    path: PathBuf,
}

impl std::ops::Deref for RangedScratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for RangedScratch {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for RangedScratch {
    /// Best effort: a test that has already failed should report its own
    /// assertion, not a cleanup failure raised while it unwinds.
    fn drop(&mut self) {
        remove_ranged(&self.path);
    }
}
