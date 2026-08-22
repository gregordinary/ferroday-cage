//! The disposable overlay upper a layered build installs its increment into.
//!
//! A build pipeline provisions a base system once, then per component stages
//! only that component's build dependencies over it — resolving against the base
//! as already-installed, extracting the increment into an overlay upper, and
//! configuring it in a cage rooted on an overlay of the pristine base. The base
//! is never mutated; the increment lives in the upper, which the [`BuildLayer`]
//! below removes when dropped.
//!
//! The handle is here rather than in a userland layer because nothing about it
//! is one userland's: an upper directory, the work directory beside it, and the
//! identity map that decides how both are removed. What differs between layers
//! is how a base's already-installed set is read and how an increment is
//! configured, and those stay with the layer that knows the archive.
//!
//! [`Rooting`] is here for the same reason. Whether a wave's cage is rooted on
//! the tree being built or on an overlay of a base and that tree is a property
//! of whether the build is layered, not of the archive it installs from.

use std::path::{Path, PathBuf};

use crate::{Cage, CageBuilder, IdentityMap};

/// Where a wave of a provisioning run is rooted.
///
/// A full bootstrap roots its waves on the tree it is building. A layered build
/// roots them on an overlay of the pristine base and that tree, which is the
/// increment's writable upper: the command reads the base's own interpreter, its
/// accounts and its package database through the merged view, and everything it
/// writes lands in the upper, so the base comes out of the build untouched.
///
/// Only a layer that runs something in a cage during a bootstrap needs this —
/// Debian's `dpkg` waves and Alpine's install scripts. The Gentoo layer runs
/// nothing: a stage3 is extracted, and a binary package is merged and
/// registered without its phase functions, so a `gentoo`-only build reaches
/// [`BuildLayer`] and no further.
#[cfg_attr(
    not(any(feature = "debian", feature = "alpine")),
    allow(
        dead_code,
        reason = "the Gentoo layer roots no cage during a bootstrap"
    )
)]
#[derive(Clone, Copy)]
pub(crate) enum Rooting<'a> {
    /// The tree being built is the whole root.
    Whole,
    /// The tree being built is an increment over the base at this path.
    Over(&'a Path),
}

impl<'a> Rooting<'a> {
    /// The rooting a build with `base` runs under: over it when a base was
    /// configured, on the tree alone when none was.
    ///
    /// The Debian layer names the two cases where it decides them and reaches
    /// for [`Rooting`] already made; only the Alpine layer carries an
    /// `Option<&Path>` this far, so a build without that feature has no caller.
    #[cfg_attr(not(feature = "alpine"), allow(dead_code))]
    pub(crate) fn over(base: Option<&'a Path>) -> Rooting<'a> {
        match base {
            Some(base) => Rooting::Over(base),
            None => Rooting::Whole,
        }
    }

    /// A cage builder rooted for the tree at `staging`, which is the whole root
    /// or the increment's upper according to which rooting this is.
    pub(crate) fn builder(self, staging: &Path) -> CageBuilder {
        match self {
            Rooting::Whole => Cage::builder().rootfs(staging),
            // The base is the read-only lower and the tree being built is the
            // writable upper, so the command sees the merged root and writes
            // only into the upper.
            Rooting::Over(base) => Cage::builder().overlay_rootfs(base, staging),
        }
    }
}

/// A staged build layer: the disposable overlay upper an increment was installed
/// into, removed when the handle is dropped.
///
// Which provisioners return one depends on the userland features built, and a
// link to a layer that is not compiled does not resolve. The sentence is
// therefore written per feature combination, as is each link's definition below.
#[cfg_attr(feature = "debian", doc = "Returned by [`Debian::stage_layer`].")]
#[cfg_attr(feature = "alpine", doc = "Returned by [`Alpine::stage_layer`].")]
#[cfg_attr(feature = "gentoo", doc = "Returned by [`Gentoo::stage_layer`].")]
///
/// The upper it owns is the writable layer of a build root — the caller roots a
/// cage on
/// [`overlay_rootfs(base, layer.path())`](crate::CageBuilder::overlay_rootfs)
/// to build against the merged `base + increment` view. Dropping the handle
/// removes the upper and the overlay's work directory beside it, reverting the
/// increment and leaving the base pristine; the base is a separate directory
/// the handle never touches.
///
/// Keep the handle alive for as long as the build root is in use, and drop it to
/// dispose of the increment. The removal is best-effort at drop time — a drop
/// cannot report an error — so a caller that must observe a disposal failure
/// removes the upper directory explicitly through
/// [`provision::remove`](crate::provision::remove) before dropping the handle,
/// which then finds nothing to remove.
///
#[cfg_attr(
    feature = "debian",
    doc = "[`Debian::stage_layer`]: crate::provision::debian::Debian::stage_layer"
)]
#[cfg_attr(
    feature = "alpine",
    doc = "[`Alpine::stage_layer`]: crate::provision::alpine::Alpine::stage_layer"
)]
#[cfg_attr(
    feature = "gentoo",
    doc = "[`Gentoo::stage_layer`]: crate::provision::gentoo::Gentoo::stage_layer"
)]
#[derive(Debug)]
pub struct BuildLayer {
    /// The overlay upper the increment was installed into: the build root's
    /// writable layer.
    upper: PathBuf,
    /// The overlay work directory beside the upper. The kernel leaves a mode-`0`
    /// directory here that a plain recursive delete cannot descend, so disposal
    /// treats it specially.
    work: PathBuf,
    /// The identity map the increment was configured under, which decides how the
    /// upper and work directory are removed.
    identity_map: IdentityMap,
}

impl BuildLayer {
    /// Builds a layer handle over a staged `upper`, computing the sibling work
    /// directory the overlay-rooted cage manages so disposal removes both.
    pub(crate) fn new(upper: &Path, identity_map: IdentityMap) -> BuildLayer {
        // The work directory is the same sibling an overlay-rooted cage derives
        // from this upper; a canonical upper always has a parent and file name,
        // so the fallback to the upper itself is unreachable in practice and
        // simply makes disposal a no-op rather than panicking.
        let work = crate::spec::overlay_work_dir(upper).unwrap_or_else(|| upper.to_path_buf());
        BuildLayer {
            upper: upper.to_path_buf(),
            work,
            identity_map,
        }
    }

    /// The overlay upper directory, the build root's writable layer.
    ///
    /// Pass it as the upper of
    /// [`CageBuilder::overlay_rootfs`](crate::CageBuilder::overlay_rootfs), with
    /// the base as the lower, to root a build cage on the merged view.
    pub fn path(&self) -> &Path {
        &self.upper
    }
}

impl Drop for BuildLayer {
    fn drop(&mut self) {
        // Under the single-identity map every entry is the caller's own, but the
        // overlay leaves a mode-`0` work directory a plain delete cannot descend;
        // a chmod-aware removal restores traversable permissions as it goes.
        // Under a range map the increment and the work directory hold
        // subordinate-owned entries the caller cannot chmod, so the removal
        // escalates through the identity map, where root inside it owns them.
        if matches!(self.identity_map, IdentityMap::Single) {
            crate::host::force_remove_dir_all(&self.upper);
            crate::host::force_remove_dir_all(&self.work);
        } else {
            let _ = crate::provision::remove(&self.upper);
            let _ = crate::provision::remove(&self.work);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    #[test]
    fn a_single_map_layer_drop_removes_the_upper_and_work_tree() {
        // A single-identity layer disposes of its upper and the overlay work
        // directory, including a mode-`0` work/work directory a plain recursive
        // delete cannot descend — the artifact an overlay mount leaves behind.
        use std::os::unix::fs::PermissionsExt;

        let dir = Scratch::for_test("layer", "dispose-single");
        let upper = dir.join("upper");
        std::fs::create_dir_all(upper.join("usr/bin")).unwrap();
        std::fs::write(upper.join("usr/bin/tool"), b"x").unwrap();

        let work = crate::spec::overlay_work_dir(&upper).unwrap();
        std::fs::create_dir_all(work.join("work")).unwrap();
        std::fs::write(work.join("index"), b"i").unwrap();
        // The overlay artifact: a directory with no permissions at all.
        std::fs::set_permissions(work.join("work"), std::fs::Permissions::from_mode(0o000))
            .unwrap();

        let layer = BuildLayer::new(&upper, IdentityMap::Single);
        assert_eq!(layer.path(), upper.as_path());
        drop(layer);

        assert!(!upper.exists(), "the upper is removed");
        assert!(
            !work.exists(),
            "the work directory is removed despite mode-0"
        );
    }
}
