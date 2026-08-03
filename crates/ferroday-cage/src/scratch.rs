//! A self-removing scratch directory for the crate's own unit tests.
//!
//! Every test that needs a real filesystem tree builds one here rather than
//! composing a path under the system temporary directory by hand. The guard
//! removes the tree when it drops, so a test suite run leaves nothing behind:
//! an ad-hoc directory that only clears itself on the *next* run accumulates
//! one tree per run forever, which a long-lived machine notices.
//!
//! Integration tests use `tests/common::scratch_dir`, which places its trees
//! under `target` for the same reason.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Distinguishes two scratch directories made in one process, so tests that
/// share a tag — or run in parallel threads — never collide.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// An empty directory that removes itself and everything under it when
/// dropped.
///
/// Dereferences to its [`Path`], so it substitutes for one at a call site:
/// `scratch.join("pool")` and a `&scratch` passed where `&Path` is expected
/// both work.
pub(crate) struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// Creates an empty scratch directory named after `tag`.
    ///
    /// Panics if the directory cannot be created: a test that cannot lay out
    /// its tree has nothing left to assert.
    pub(crate) fn new(tag: &str) -> Scratch {
        let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ferroday-cage-test-{tag}-{}-{serial}",
            std::process::id()
        ));
        // A previous run that was killed rather than unwound leaves its tree
        // behind, and the name is only unique per process id.
        crate::host::force_remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the scratch directory is creatable");
        Scratch { path }
    }

    /// The directory's path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for Scratch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Scratch").field(&self.path).finish()
    }
}

impl Drop for Scratch {
    /// Removes the tree, restoring traversable permissions as it descends: a
    /// test that mounted an overlay here leaves a mode-`0` work directory that
    /// a plain recursive removal cannot read into.
    ///
    /// Best effort. A test that has already failed should report its own
    /// assertion rather than a cleanup failure raised while it unwinds.
    fn drop(&mut self) {
        crate::host::force_remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_scratch_takes_its_tree_with_it() {
        let path = {
            let scratch = Scratch::new("self");
            std::fs::create_dir_all(scratch.join("a/b")).unwrap();
            std::fs::write(scratch.join("a/b/file"), b"contents").unwrap();
            scratch.path().to_path_buf()
        };
        assert!(
            !path.exists(),
            "the scratch tree outlived its guard: {}",
            path.display(),
        );
    }

    #[test]
    fn two_scratches_with_one_tag_do_not_collide() {
        let first = Scratch::new("shared");
        let second = Scratch::new("shared");
        assert_ne!(
            first.path(),
            second.path(),
            "two scratch directories share a path, so one clears the other",
        );
    }
}
