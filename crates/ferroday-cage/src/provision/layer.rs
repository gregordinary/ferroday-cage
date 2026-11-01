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

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{Delegate, ProvisionError};
use crate::{Cage, CageBuilder, IdMapper, IdentityMap};

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
    ///
    /// The type's own allowance covers its variants and not this: an inherent
    /// method is not the enum. It is dead in the same builds and for the same
    /// reason — a `gentoo`-only build roots no cage during a bootstrap.
    #[cfg_attr(
        not(any(feature = "debian", feature = "alpine")),
        allow(
            dead_code,
            reason = "the Gentoo layer roots no cage during a bootstrap"
        )
    )]
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
/// The increment's files are written into the upper on the host, as the calling
/// user, where the mounted overlay would place them. A directory of the base's
/// that one lands beneath is carried into the upper first, keeping what the
/// overlay's own copy-up keeps: the base's extended attributes, POSIX access
/// control lists among them, its mode and modification time, and its owner and
/// group. The ownership is given from inside the identity map the increment is
/// staged under. Under the single-identity map, a base directory held at an id
/// other than the caller's is carried owned by root, since that map has no other
/// id. A base directory the calling user cannot list carries no attributes up.
///
/// Keep the handle alive for as long as the build root is in use, and drop it to
/// dispose of the increment. The removal is best-effort at drop time — a drop
/// cannot report an error — so a caller that must observe a disposal failure
/// removes the layer explicitly before dropping the handle, which then finds
/// nothing to remove. That is
/// [`Remove::overlay_upper`](crate::provision::Remove::overlay_upper) on
/// [`path`](Self::path), with the identity map the layer was staged under:
/// the drop's own removal.
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
pub struct BuildLayer {
    /// The overlay upper the increment was installed into: the build root's
    /// writable layer.
    upper: PathBuf,
    /// The identity map the increment was configured under, which decides how the
    /// upper and the work directory beside it are removed.
    identity_map: IdentityMap,
    /// The delegate that map was established through, where the provisioner's
    /// caller supplied one, so the removal re-enters the same map.
    id_mapper: Option<Arc<dyn IdMapper>>,
}

impl fmt::Debug for BuildLayer {
    /// Renders the upper and the map, and the delegate by its presence rather
    /// than its contents: it is a caller's trait object.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BuildLayer")
            .field("upper", &self.upper)
            .field("identity_map", &self.identity_map)
            .field(
                "id_mapper",
                &self.id_mapper.as_ref().map(|_| Delegate("dyn IdMapper")),
            )
            .finish()
    }
}

impl BuildLayer {
    /// Builds a layer handle over a staged `upper`, which disposal removes with
    /// the work directory the overlay-rooted cage manages beside it, through the
    /// map and the delegate the increment was staged under.
    pub(crate) fn new(
        upper: &Path,
        identity_map: IdentityMap,
        id_mapper: Option<Arc<dyn IdMapper>>,
    ) -> BuildLayer {
        BuildLayer {
            upper: upper.to_path_buf(),
            identity_map,
            id_mapper,
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
    /// Removes the upper and the overlay work directory beside it, through the
    /// map the increment was staged under and the delegate that established it.
    fn drop(&mut self) {
        dispose(&self.upper, &self.identity_map, self.id_mapper.as_ref());
    }
}

/// Removes `upper` and the overlay work directory beside it, through
/// `identity_map` and the delegate that established it.
///
/// That map rather than the subordinate default: an explicit range map
/// allocates ids the bundled chain would not, and a removal the calling user is
/// refused has to re-enter the map the tree's ownership was written in, through
/// the delegate that wrote it. Under the single map the ids are the caller's
/// own, and the escalation is for the mode-`0` directory the overlay leaves in
/// its work area, should anything be left inside it.
///
/// The publication lock is not touched: an upper is a directory a caller named
/// as a build layer, not a published root filesystem, so `<upper>.lock` is a
/// path this never created and may not delete.
///
/// Best-effort, since both callers are drops and a drop cannot report an
/// error.
fn dispose(upper: &Path, identity_map: &IdentityMap, id_mapper: Option<&Arc<dyn IdMapper>>) {
    let _ = crate::provision::Remove::overlay_upper(upper)
        .identity_map(identity_map.clone())
        .shared_id_mapper(id_mapper.cloned())
        .run();
}

/// An increment being staged into an overlay upper, and what a failure leaves
/// of the upper.
///
/// A staging that fails hands its caller no [`BuildLayer`] to drop, so this is
/// what disposes of the upper instead. It disposes only of an upper the staging
/// itself created. An upper that was already there is the caller's and may hold
/// earlier work, so a failure leaves it in place, holding whatever the staging
/// wrote into it before failing.
///
/// [`finish`](Self::finish) hands the upper to the [`BuildLayer`] a staging
/// returns, which owns it whichever way it arrived.
pub(crate) struct Staging {
    /// The upper the increment is installed into.
    upper: PathBuf,
    /// The identity map the increment is configured under.
    identity_map: IdentityMap,
    /// The delegate that map is established through, where the caller
    /// supplied one.
    id_mapper: Option<Arc<dyn IdMapper>>,
    /// Whether this staging created the upper, which is what makes removing
    /// it on failure its own to do.
    created: bool,
    /// Whether the staging finished, handing the upper to a [`BuildLayer`].
    finished: bool,
}

impl Staging {
    /// Begins staging into `upper`, creating it and its missing parents where
    /// nothing holds its name.
    ///
    /// # Errors
    ///
    /// Returns [`ProvisionError::Io`] where `upper` or a parent cannot be
    /// created, or where `upper` names something other than a directory.
    pub(crate) fn begin(
        upper: &Path,
        identity_map: IdentityMap,
        id_mapper: Option<Arc<dyn IdMapper>>,
    ) -> Result<Staging, ProvisionError> {
        let creating = |err| ProvisionError::io("creating the overlay upper", upper, err);
        std::fs::create_dir_all(crate::path::parent_of(upper)).map_err(creating)?;
        // Created here or found there, decided by the one call that would
        // create it: a name another process takes between a check and a
        // creation is then the other process's, and is left alone.
        let created = match std::fs::create_dir(upper) {
            Ok(()) => true,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists && upper.is_dir() => false,
            Err(err) => return Err(creating(err)),
        };
        Ok(Staging {
            upper: upper.to_path_buf(),
            identity_map,
            id_mapper,
            created,
            finished: false,
        })
    }

    /// Ends a staging that succeeded, handing the upper to the layer that owns
    /// it from here on.
    pub(crate) fn finish(mut self) -> BuildLayer {
        self.finished = true;
        BuildLayer::new(
            &self.upper,
            self.identity_map.clone(),
            self.id_mapper.clone(),
        )
    }
}

impl Drop for Staging {
    /// Disposes of an upper this staging created, where it did not finish.
    fn drop(&mut self) {
        if self.created && !self.finished {
            dispose(&self.upper, &self.identity_map, self.id_mapper.as_ref());
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

        let layer = BuildLayer::new(&upper, IdentityMap::Single, None);
        assert_eq!(layer.path(), upper.as_path());
        drop(layer);

        assert!(!upper.exists(), "the upper is removed");
        assert!(
            !work.exists(),
            "the work directory is removed despite mode-0"
        );
    }

    #[test]
    fn a_layer_drop_leaves_a_lock_sibling_it_never_created() {
        // An upper is a directory a caller named as a build layer, not a
        // published rootfs -- `ensure` wrote no lock beside it, so `<upper>.lock`
        // is an unrelated path, and deleting it is a removal outside the tree
        // the layer owns. A build root and its layers routinely sit beside the
        // published trees a cache holds.
        let dir = Scratch::for_test("layer", "dispose-lock");
        let upper = dir.join("upper");
        std::fs::create_dir_all(&upper).unwrap();
        let sibling = dir.join("upper.lock");
        std::fs::write(&sibling, b"someone else's").unwrap();

        // Asserted for the single-identity map, whose removal never touched the
        // sibling, and for the escalating one, which did.
        for map in [IdentityMap::Single, IdentityMap::Subordinate] {
            std::fs::create_dir_all(&upper).unwrap();
            drop(BuildLayer::new(&upper, map, None));
            assert!(!upper.exists(), "the upper is removed");
            assert!(
                sibling.exists(),
                "a lock the layer never created went with it",
            );
        }
        assert_eq!(std::fs::read(&sibling).unwrap(), b"someone else's");
    }

    #[test]
    fn a_failed_staging_removes_an_upper_it_created_and_nothing_else() {
        // A staging that fails hands back no layer, so its own guard is what
        // disposes of the upper -- and only of one it created. An upper the
        // caller already had may hold an earlier increment, and losing it to a
        // failure in a later one would be the failure destroying work it never
        // did.
        let dir = Scratch::for_test("layer", "staging-failed");

        let fresh = dir.join("nested/fresh");
        let staging =
            Staging::begin(&fresh, IdentityMap::Single, None).expect("the upper is created");
        assert!(fresh.is_dir(), "the upper and its parents are created");
        std::fs::write(fresh.join("partial"), b"x").unwrap();
        drop(staging);
        assert!(!fresh.exists(), "an upper the staging created is removed");

        let kept = dir.join("kept");
        std::fs::create_dir_all(kept.join("usr/bin")).unwrap();
        std::fs::write(kept.join("usr/bin/earlier"), b"earlier work").unwrap();
        let staging = Staging::begin(&kept, IdentityMap::Single, None).expect("the upper is found");
        std::fs::write(kept.join("partial"), b"x").unwrap();
        drop(staging);
        assert_eq!(
            std::fs::read(kept.join("usr/bin/earlier")).expect("the earlier work survives"),
            b"earlier work",
        );
        assert!(
            kept.join("partial").exists(),
            "what the failed staging wrote stays in the caller's upper",
        );
    }

    #[test]
    fn a_finished_staging_hands_the_upper_to_the_layer_however_it_arrived() {
        let dir = Scratch::for_test("layer", "staging-finished");
        for (name, existing) in [("fresh", false), ("kept", true)] {
            let upper = dir.join(name);
            if existing {
                std::fs::create_dir_all(&upper).unwrap();
            }
            let staging = Staging::begin(&upper, IdentityMap::Single, None).expect("staged");
            let layer = staging.finish();
            assert!(upper.is_dir(), "{name}: finishing removes nothing");
            assert_eq!(layer.path(), upper.as_path());
            drop(layer);
            assert!(!upper.exists(), "{name}: the layer owns the upper");
        }
    }

    #[test]
    fn a_staging_refuses_an_upper_that_is_not_a_directory() {
        let dir = Scratch::for_test("layer", "staging-file");
        let upper = dir.join("upper");
        std::fs::write(&upper, b"a file").unwrap();
        assert!(Staging::begin(&upper, IdentityMap::Single, None).is_err());
        assert_eq!(std::fs::read(&upper).unwrap(), b"a file", "left alone");
    }

    /// A delegate that records the map it is asked for and refuses it.
    #[derive(Debug, Default)]
    struct Recording {
        asked: std::sync::Mutex<Vec<IdentityMap>>,
    }

    impl IdMapper for Recording {
        fn resolve(&self, request: &IdentityMap) -> Result<crate::ResolvedMap, crate::IdMapError> {
            self.asked.lock().unwrap().push(request.clone());
            Err(crate::IdMapError::unsatisfiable(
                "the test's delegate refuses",
            ))
        }

        fn apply(&self, _pid: u32, _map: &crate::ResolvedMap) -> Result<(), crate::IdMapError> {
            unreachable!("a refused map is never applied")
        }
    }

    #[test]
    fn a_layer_drop_escalates_through_the_delegate_it_was_staged_with() {
        // A removal the caller is refused re-enters the map the layer was
        // staged under. Where the provisioner's caller supplied the delegate
        // that established that map, the bundled chain may not be able to
        // establish it at all, so the drop has to ask the same delegate.
        use std::os::unix::fs::PermissionsExt;

        if rustix::process::geteuid().is_root() {
            ferroday_cage_testkit::require::premise_unmet(
                "root removes a mode-0 directory without escalating",
            );
            return;
        }
        let dir = Scratch::for_test("layer", "dispose-delegate");
        let upper = dir.join("upper");
        let sealed = upper.join("sealed");
        std::fs::create_dir_all(sealed.join("inside")).unwrap();
        // A directory the caller cannot search, so the plain removal is
        // refused and the escalation is what is left.
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();

        let delegate = Arc::new(Recording::default());
        let layer = BuildLayer::new(
            &upper,
            IdentityMap::Subordinate,
            Some(Arc::clone(&delegate) as Arc<dyn IdMapper>),
        );
        drop(layer);

        assert_eq!(
            *delegate.asked.lock().unwrap(),
            [IdentityMap::Subordinate],
            "the escalation did not ask the layer's delegate",
        );
        assert!(upper.exists(), "the refused escalation removed nothing");
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}
