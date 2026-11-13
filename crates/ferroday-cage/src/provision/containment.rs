//! Opening a directory the kernel keeps inside a tree.
//!
//! Both halves of provisioning walk a tree they do not trust — the extractor
//! writes an archive's entries into one, the host-side steps read and write a
//! rootfs that untrusted code has already run in — and both walk it the same
//! way: `openat2` against a descriptor for the tree's root, with a resolve flag
//! that makes the kernel, not a text inspection of the path, the thing that
//! keeps the walk inside.
//!
//! [`open_dir`] is that call. What each caller decides is the containment flag
//! and the access the descriptor is for; everything else about the call is the
//! same wherever it is made, and is stated here once. [`create_dirs`] is the
//! same walk for a chain whose missing links are to be made.
//!
//! # The two containment flags
//!
//! `RESOLVE_IN_ROOT` re-anchors an absolute symbolic link at the tree's root,
//! which is what such a link means to a tree that is a root filesystem: `/lib
//! -> /usr/lib` inside a rootfs names the rootfs's own `/usr/lib`, both to the
//! sandbox that pivots into it and to the host-side step writing to it
//! beforehand. Every tree provisioning writes is one, so the extractor and the
//! host-side steps both resolve this way. `RESOLVE_BENEATH` refuses every
//! absolute link instead, including one whose target would land back inside
//! the tree; it suits a walk that follows no link at all, where the two agree.
//!
//! Either way the walk cannot leave the tree. The flags differ only in what
//! they do with a link that names a path from a root.
//!
//! # Creating over what is already there
//!
//! [`replacing`] is here for the same reason [`open_dir`] is. Both halves of
//! provisioning create entries in a tree that may already hold something at the
//! name, and so does the copy-in child laying a host tree into a root. All of
//! them answer it the same way: remove whatever is there, an empty directory
//! included, and create again. What differs between them is only what a failure
//! is called — the extractor reports a `ProvisionError` naming the archive
//! entry, the host-side steps an errno the operation's own error carries, the
//! child a step and an errno — so the errno-level algorithm is stated once and
//! each caller says what its failures are.
//!
//! # Opening what a walk found or made
//!
//! A walk that inspects a name and then opens it can find something else
//! there by the time it opens it. [`open_typed_file`] opens a regular file the
//! caller has just looked at, and [`open_created_fifo`] a named pipe it has
//! just made. Neither waits on whatever has taken the name, and each refuses
//! anything but the entry the caller meant. Both allocate nothing, so the
//! mechanism's post-fork walks use them as the host-side steps do.
//!
//! # A tree staged over a lower layer
//!
//! A layered build writes into an overlay upper, and the overlay shows that
//! upper over a read-only base. The kernel merges a directory only with a
//! directory, so a directory the upper creates where the base holds a symbolic
//! link to one hides the link: a base whose `/lib64` is `usr/lib64` loses its
//! dynamic linker the moment an increment's `lib64/` becomes a real directory in
//! the upper. [`copy_up`] is the answer. Before a chain is created in the upper,
//! it walks the chain through the merged view and makes the upper hold what
//! that view holds along it, so the kernel's own resolution in the upper then
//! goes where it would go in the mounted overlay.
//!
//! A directory it carries up keeps what the overlay's own copy-up keeps: the
//! extended attributes, which the walk gives it, and the mode, time, owner and
//! group, which the caller states. Ownership is the one part the calling user
//! cannot give, so the caller hands what is [`owed`] to the copy-in child,
//! which sets it from inside the tree's identity map.

use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat};
use rustix::io::Errno;

use crate::mechanism::resolve;

/// How many times a create is retried when something already occupies the name.
///
/// One replacement always suffices; the bound exists so a pathological
/// filesystem state — an entry something else keeps putting back — cannot loop
/// forever.
const REPLACE_ATTEMPTS: u32 = 3;

/// The mode a directory is created with before its caller states the one it
/// keeps.
///
/// Owner-only, so a directory never sits at a permissive mode in the window
/// before its own; and owner-writable, so the chain beneath it can be created.
const CREATION_MODE: u32 = 0o700;

/// The components joined with `/` into one path, `.` for none.
///
/// The one place a chain of components becomes the string a `*at` call takes.
/// A component holding a NUL cannot be named to the kernel at all, and is
/// `EINVAL`.
fn joined<C: AsRef<[u8]>>(components: &[C]) -> Result<CString, Errno> {
    if components.is_empty() {
        return Ok(c".".to_owned());
    }
    let mut path = Vec::new();
    for (at, component) in components.iter().enumerate() {
        if at > 0 {
            path.push(b'/');
        }
        path.extend_from_slice(component.as_ref());
    }
    CString::new(path).map_err(|_| Errno::INVAL)
}

/// Opens `components` as a directory, resolved against `anchor` under
/// `containment`. No components names the anchor itself.
///
/// `access` is what the descriptor is for: `O_PATH` where it is only ever the
/// anchor of a later `*at` call, and `O_RDONLY` where something is done to the
/// directory itself — an `O_PATH` descriptor does not accept `fchmod`. A caller
/// that must not follow a symbolic link at the final component adds
/// `O_NOFOLLOW`, which the containment flag does not cover: either flag keeps
/// a follow inside the tree, and staying inside the tree is not the same as
/// landing on the entry that was named.
///
/// `O_DIRECTORY` and `O_CLOEXEC` are unconditional: every caller wants a
/// directory, and a descriptor that outlived an exec would be one the sandbox
/// could inherit. `RESOLVE_NO_MAGICLINKS` is unconditional for the same kind of
/// reason — a `/proc/*/fd/*` entry re-opens whatever it names, from anywhere on
/// the host, and no path in a tree being provisioned has a use for one.
///
/// The lookup goes through [`resolve::openat2`], so the `EAGAIN` the kernel
/// answers when a rename raced the walk is retried rather than reported. A
/// caller that took it for a failure would report a root filesystem as unwritable
/// because something moved underneath it.
pub(crate) fn open_dir<C: AsRef<[u8]>>(
    anchor: BorrowedFd<'_>,
    components: &[C],
    access: OFlags,
    containment: ResolveFlags,
) -> Result<OwnedFd, Errno> {
    open_dir_path(anchor, &joined(components)?, access, containment)
}

/// [`open_dir`] for a path already joined and terminated, with everything that
/// function states.
///
/// The one form that allocates nothing, so the copy-in child calls it after
/// the fork: it takes no lock and cannot panic either, and the child assembles
/// the path from the destination's root in a fixed buffer of its own.
pub(crate) fn open_dir_path(
    anchor: BorrowedFd<'_>,
    path: &CStr,
    access: OFlags,
    containment: ResolveFlags,
) -> Result<OwnedFd, Errno> {
    resolve::openat2(
        anchor,
        path,
        access | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        containment | ResolveFlags::NO_MAGICLINKS,
    )
}

/// A directory a chain walk made, handed to the caller so it can state the
/// directory's mode.
pub(super) struct Made<'a> {
    /// Where the directory is, as a slash-joined path from the anchor.
    // Read by an extraction alone, for its deferred pass: the host-side steps
    // state each mode at once.
    #[cfg_attr(not(feature = "tarball"), allow(dead_code))]
    pub(super) path: &'a [u8],
    /// The directory itself, opened `O_RDONLY | O_NOFOLLOW`, so a mode applied
    /// through it lands on the directory the walk made and on nothing a racer
    /// put at the name since.
    pub(super) dir: BorrowedFd<'a>,
    /// The lower layer's directory this one stands in for, where [`copy_up`]
    /// made it to carry one up. Its mode, modification time, owner, and group
    /// are the ones the merged view showed before the upper held anything
    /// there. The walk has already given the new directory the lower one's
    /// extended attributes; the rest are the caller's to state, the ownership
    /// through [`owed`].
    pub(super) copied: Option<&'a Stat>,
}

/// Opens `components` beneath `anchor` as a directory, creating the missing
/// links of the chain.
///
/// Each prefix is resolved from the anchor rather than descended into, so an
/// in-tree symbolic link mid-path — a merged-usr alias — keeps working under
/// either containment flag, and each `mkdirat` is anchored to the descriptor
/// the resolve before it returned.
///
/// Every directory this creates is made at [`CREATION_MODE`] and handed to
/// `made`, which is where the caller states the mode it keeps: applied through
/// the descriptor at once, or recorded for a pass after the chain's contents
/// are written. Nothing here sets a mode by name, so no symbolic link a racer
/// leaves at the name can redirect one.
///
/// A name in the chain held by something that does not resolve to a directory
/// — a file, or a link that dangles — fails with `ENOTDIR`, whatever the kernel
/// said about the link: the `mkdirat` that found the name taken is what shows
/// it, and the caller reports a path it cannot create a directory at rather
/// than the detail of why. A link the containment flag refuses fails as the
/// kernel refused it, `EXDEV` or `ELOOP`, before anything is created.
pub(super) fn create_dirs<C: AsRef<[u8]>>(
    anchor: BorrowedFd<'_>,
    components: &[C],
    containment: ResolveFlags,
    made: &mut dyn FnMut(Made<'_>) -> Result<(), Errno>,
) -> Result<OwnedFd, Errno> {
    match open_dir(anchor, components, OFlags::PATH, containment) {
        Ok(fd) => return Ok(fd),
        Err(Errno::NOENT) => {}
        Err(errno) => return Err(errno),
    }
    for depth in 1..=components.len() {
        match open_dir(anchor, &components[..depth], OFlags::PATH, containment) {
            Ok(_) => continue,
            Err(Errno::NOENT) => {}
            Err(errno) => return Err(errno),
        }
        let above = open_dir(anchor, &components[..depth - 1], OFlags::PATH, containment)?;
        let leaf = joined(&components[depth - 1..depth])?;
        match make_dir(above.as_fd(), &leaf) {
            Ok(dir) => {
                let path = joined(&components[..depth])?;
                made(Made {
                    path: path.as_bytes(),
                    dir: dir.as_fd(),
                    copied: None,
                })?;
            }
            // Something already holds the name. A directory that arrived since
            // the resolve above is taken as it stands; anything else did not
            // resolve to a directory there and still does not.
            Err(Errno::EXIST) => {
                if open_dir(anchor, &components[..depth], OFlags::PATH, containment).is_err() {
                    return Err(Errno::NOTDIR);
                }
            }
            Err(errno) => return Err(errno),
        }
    }
    open_dir(anchor, components, OFlags::PATH, containment)
}

/// Creates the directory `leaf` in `parent` at [`CREATION_MODE`] and opens the
/// directory it created.
///
/// `O_NOFOLLOW` refuses a leaf replaced by a symbolic link in between, and
/// `O_DIRECTORY` one replaced by anything else, so the descriptor is the
/// directory this made or the call fails.
fn make_dir(parent: BorrowedFd<'_>, leaf: &CStr) -> Result<OwnedFd, Errno> {
    rustix::fs::mkdirat(parent, leaf, Mode::from_raw_mode(CREATION_MODE))?;
    open_child_dir(parent, leaf, OFlags::RDONLY)
}

/// Opens the directory `leaf` of `parent` itself, never through a link.
///
/// One component from a descriptor the caller already holds inside the tree,
/// so there is nothing for a resolve flag to contain: `O_NOFOLLOW` keeps the
/// open on the entry that is there.
fn open_child_dir(parent: BorrowedFd<'_>, leaf: &CStr, access: OFlags) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(
        parent,
        leaf,
        access | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Whether `stat` describes an overlay whiteout: a character device numbered
/// `0:0`, which the overlay shows as nothing at all, hiding whatever a lower
/// layer holds at the name.
///
/// The one definition. [`Rooted::is_whiteout`](super::rooted::Rooted::is_whiteout)
/// is its predicate form for the host-side steps, the launch's placeholder
/// checks among them, which reach `provision` only through `Rooted`.
pub(super) fn is_whiteout(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::CharacterDevice && stat.st_rdev == 0
}

/// The extended attribute an overlay marks an opaque directory with.
///
/// Every overlay this library mounts carries `userxattr`, which keeps the
/// overlay's own attributes in the `user.overlay.` namespace rather than
/// `trusted.overlay.`, where an unprivileged process could neither read nor
/// write them.
pub(super) const OPAQUE: &CStr = c"user.overlay.opaque";

/// Whether the directory `dir` carries the overlay's opaque marker, so the
/// overlay shows nothing of a lower layer beneath it.
///
/// The marker is the value `y`. The overlay gives the attribute one other
/// value, `x`, which says a directory holds whiteouts of another form and is
/// not opaque. A directory without the attribute, or on a filesystem without
/// `user.` attributes, carries no marker; any other failure to read it is the
/// caller's to report. `dir` must be open for reading: an `O_PATH` descriptor
/// cannot be asked for an attribute.
///
/// The one answer to the question: the layered walk ([`copy_up`]), the Gentoo
/// layer's reading of what an upper hides, and the launch's placeholder checks
/// through [`Rooted::is_opaque`](super::rooted::Rooted::is_opaque) all ask it
/// here.
pub(super) fn is_opaque(dir: BorrowedFd<'_>) -> Result<bool, Errno> {
    let mut value = [0u8; 1];
    match rustix::fs::fgetxattr(dir, OPAQUE, &mut value) {
        Ok(read) => Ok(value[..read] == *b"y"),
        Err(Errno::NODATA | Errno::NOTSUP | Errno::RANGE) => Ok(false),
        Err(errno) => Err(errno),
    }
}

#[cfg(feature = "tarball")]
pub(super) use layered::{Reached, copy_up, mark_opaque, modified, owed};

/// Whether an extended attribute is one the host holding a tree assigns, rather
/// than one the tree carries.
///
/// A security module labels the files it sees: SELinux as `security.selinux`,
/// Smack as `security.SMACK64` and its relatives, AppArmor as
/// `security.apparmor`. The integrity subsystem records a measurement or a
/// signature as `security.ima` and `security.evm`. Overlayfs keeps its own
/// bookkeeping on an upper's files as `user.overlay.*` and `trusted.overlay.*`.
/// None of it is the tree's. It describes the host the tree sat on and that
/// host's policy, and it differs between two hosts holding the same tree.
///
/// The one answer to the question. An export leaves these out of the archive,
/// so one tree's archive is the same from any host, and a layered build's
/// carry leaves them off the upper's copy of a base directory, as the overlay's
/// own copy-up does.
///
/// Most of these an unprivileged sandbox cannot set at all. A `user.overlay.`
/// one is the exception: on a root filesystem that is a plain directory, a
/// sandbox owns the files it writes and can set it. It is left out all the
/// same, since an overlay mounted with `userxattr`, as every one this library
/// mounts is, reads that namespace as its own bookkeeping. A carried
/// `user.overlay.opaque` would hide a lower layer's directory there.
#[cfg(feature = "tarball")]
pub(super) fn host_assigned_xattr(name: &[u8]) -> bool {
    matches!(
        name,
        b"security.selinux" | b"security.apparmor" | b"security.ima" | b"security.evm"
    ) || name.starts_with(b"security.SMACK64")
        || name.starts_with(b"user.overlay.")
        || name.starts_with(b"trusted.overlay.")
}

/// The walk through an overlay's merged view, which only a layered build makes,
/// and so only a build with a provisioner in it: the increment's extraction and
/// the host-side steps after it both write the upper through this walk.
#[cfg(feature = "tarball")]
mod layered {
    use std::collections::VecDeque;
    use std::ffi::{CStr, CString};
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

    use rustix::fs::{
        AtFlags, FileType, OFlags, ResolveFlags, Stat, Timespec, Timestamps, XattrFlags,
    };
    use rustix::io::Errno;

    use super::{
        Made, OPAQUE, host_assigned_xattr, is_opaque, is_whiteout, make_dir, open_child_dir,
        open_dir,
    };
    use crate::provision::copyin::{Owed, Owner};

    /// The extended attributes that hold a POSIX access control list: one for
    /// the directory itself, and the default its new entries inherit.
    const ACLS: [&CStr; 2] = [c"system.posix_acl_access", c"system.posix_acl_default"];

    /// How many times a listing or a value is read again after it grew between
    /// asking its size and reading it.
    const XATTR_ATTEMPTS: u32 = 3;

    /// How many symbolic links one [`copy_up`] walk follows before it leaves the
    /// rest to the kernel, which refuses the loop itself. The kernel's own bound,
    /// so the walk gives up exactly where the resolution it stands in for would.
    const MAX_FOLLOWS: u32 = 40;

    /// Marks the directory `dir` opaque, so the overlay shows nothing of a lower
    /// layer beneath it.
    pub(in crate::provision) fn mark_opaque(dir: BorrowedFd<'_>) -> Result<(), Errno> {
        rustix::fs::fsetxattr(dir, OPAQUE, b"y", rustix::fs::XattrFlags::empty())
    }

    /// What [`copy_up`] found at the end of the chain it walked.
    pub(in crate::provision) enum Reached {
        /// Every component resolved to a directory of the merged view, and the
        /// upper now holds each one. Carries the lower layer's own directory at
        /// the end of the chain, where the overlay shows the lower through there.
        Directory(Option<OwnedFd>),
        /// The walk stopped before the end of the chain: at a name the merged view
        /// does not hold, which the caller creates, or at a link only the kernel's
        /// own resolution can rule on. The upper holds the link, so that
        /// resolution reaches the same verdict through it.
        Short,
    }

    /// One directory on a [`copy_up`] walk's path.
    struct Level {
        /// The directory's name, empty for the anchor.
        name: Vec<u8>,
        /// The upper's directory, read-only where it can be opened so, since an
        /// opaque marker is read through it.
        upper: OwnedFd,
        /// The lower layer's directory at the same path, where the overlay shows
        /// the lower through: absent beneath an opaque upper directory, a
        /// whiteout, or anything in the lower that is not a directory.
        lower: Option<OwnedFd>,
    }

    /// Makes `upper` hold, along `components`, what an overlay of `upper` over
    /// `lower` shows there.
    ///
    /// The walk goes through the merged view one name at a time: an entry the
    /// upper holds is the one the overlay shows, and where it holds none, the
    /// lower's is. A directory only the lower holds is created in the upper,
    /// given the lower one's extended attributes ([`carry_xattrs`]), and handed
    /// to `made` with the lower's own [`Stat`], so the caller can give it the
    /// mode, time, and ownership the merged view showed. A symbolic link only
    /// the lower holds is copied into the upper verbatim, with the lower's
    /// modification time, and followed; a link the upper holds is followed as
    /// it stands. Following one splices its target into the rest of the walk,
    /// as path resolution does.
    ///
    /// After the walk the upper resolves the chain, by itself, to where the merged
    /// view does, so the caller's own kernel-contained resolution and
    /// [`create_dirs`] then do in the upper what they would do in the mounted
    /// overlay: an entry under `lib64/`, where the lower holds `lib64 ->
    /// usr/lib64`, is created at `usr/lib64` in the upper, and the upper's copy of
    /// the link keeps the merged `/lib64` a link.
    ///
    /// The walk honours the overlay's own markers. A whiteout in either layer is
    /// nothing, and one in the upper hides the lower beneath it too; an opaque
    /// directory in the upper hides the lower beneath it. A whiteout in the upper
    /// on the chain is replaced by an opaque directory, which is what the overlay
    /// itself makes when a directory is created over one: the name held nothing in
    /// the merged view, so the directory starts empty there. The lower's own
    /// opaque markers mean nothing to an overlay with one lower layer, and are not
    /// read.
    ///
    /// `containment` is the flag the caller resolves the tree under, and the walk
    /// keeps to it rather than ruling on a link itself. Under `RESOLVE_BENEATH` an
    /// absolute link, or a `..` climbing out of the tree, stops the walk with the
    /// link in place, and the caller's own resolution refuses it exactly as it
    /// refuses one the tree held all along; under `RESOLVE_IN_ROOT` an absolute
    /// link restarts at the root and `..` stops there. A walk past
    /// [`MAX_FOLLOWS`] links stops the same way, for the kernel to refuse the loop.
    ///
    /// The lower is only ever read. Every directory of it is opened with
    /// `O_NOFOLLOW` from the one above, starting from a descriptor contained under
    /// `containment`, so a link in the lower is only ever read as a link, never
    /// followed by the kernel.
    ///
    /// # Errors
    ///
    /// `ENOTDIR` where the merged view holds something other than a directory at a
    /// name on the chain, which no caller can create a directory beneath. Any
    /// other failure is the errno of the call that made it.
    pub(in crate::provision) fn copy_up<C: AsRef<[u8]>>(
        upper: BorrowedFd<'_>,
        lower: BorrowedFd<'_>,
        components: &[C],
        containment: ResolveFlags,
        made: &mut dyn FnMut(Made<'_>) -> Result<(), Errno>,
    ) -> Result<Reached, Errno> {
        let mut stack = vec![Level {
            name: Vec::new(),
            upper: open_dir(upper, &[] as &[&[u8]], OFlags::RDONLY, containment)?,
            lower: Some(open_dir(lower, &[] as &[&[u8]], OFlags::PATH, containment)?),
        }];
        let mut pending: VecDeque<Vec<u8>> = components
            .iter()
            .map(|component| component.as_ref().to_vec())
            .collect();
        let mut follows = 0u32;

        while let Some(name) = pending.pop_front() {
            match name.as_slice() {
                b"" | b"." => continue,
                b".." => {
                    if stack.len() > 1 {
                        stack.pop();
                    } else if containment.contains(ResolveFlags::BENEATH) {
                        return Ok(Reached::Short);
                    }
                    continue;
                }
                _ => {}
            }
            let leaf = CString::new(name.clone()).map_err(|_| Errno::INVAL)?;
            let top = stack.last().expect("the anchor's level is never popped");

            // What the upper holds at the name is what the overlay shows there.
            let target = match lookup(top.upper.as_fd(), &leaf)? {
                Some(stat) => match FileType::from_raw_mode(stat.st_mode) {
                    FileType::Directory => {
                        let level = descend_upper(top, name, &leaf)?;
                        stack.push(level);
                        continue;
                    }
                    FileType::Symlink => {
                        rustix::fs::readlinkat(top.upper.as_fd(), &leaf, Vec::new())?
                    }
                    _ if is_whiteout(&stat) => {
                        let level = replace_whiteout(&stack, name, &leaf, made)?;
                        stack.push(level);
                        continue;
                    }
                    _ => return Err(Errno::NOTDIR),
                },
                // Nothing in the upper: the lower's entry, where the overlay shows
                // the lower here at all.
                None => {
                    let Some(below) = top.lower.as_ref() else {
                        return Ok(Reached::Short);
                    };
                    let Some(stat) = lookup(below.as_fd(), &leaf)? else {
                        return Ok(Reached::Short);
                    };
                    match FileType::from_raw_mode(stat.st_mode) {
                        FileType::Directory => {
                            let level = carry_dir(&stack, name, &leaf, &stat, made)?;
                            stack.push(level);
                            continue;
                        }
                        FileType::Symlink => carry_link(top, &leaf, &stat)?,
                        _ if is_whiteout(&stat) => return Ok(Reached::Short),
                        _ => return Err(Errno::NOTDIR),
                    }
                }
            };

            follows += 1;
            if follows > MAX_FOLLOWS {
                return Ok(Reached::Short);
            }
            let target = target.as_bytes();
            if target.first() == Some(&b'/') {
                if containment.contains(ResolveFlags::BENEATH) {
                    return Ok(Reached::Short);
                }
                stack.truncate(1);
            }
            for component in target.split(|byte| *byte == b'/').rev() {
                pending.push_front(component.to_vec());
            }
        }
        Ok(Reached::Directory(
            stack.pop().and_then(|level| level.lower),
        ))
    }

    /// The entry at `leaf` in `dir`, without following it; `None` where there is
    /// none.
    fn lookup(dir: BorrowedFd<'_>, leaf: &CStr) -> Result<Option<Stat>, Errno> {
        match rustix::fs::statat(dir, leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(stat)),
            Err(Errno::NOENT) => Ok(None),
            Err(errno) => Err(errno),
        }
    }

    /// The level for a directory the upper already holds at `leaf`.
    fn descend_upper(top: &Level, name: Vec<u8>, leaf: &CStr) -> Result<Level, Errno> {
        // Read-only, so the opaque marker can be read through it; a directory its
        // owner cannot read is still walked, and is read as carrying no marker,
        // since nothing unprivileged can ask it for one.
        let (upper, readable) = match open_child_dir(top.upper.as_fd(), leaf, OFlags::RDONLY) {
            Err(Errno::ACCESS) => (
                open_child_dir(top.upper.as_fd(), leaf, OFlags::PATH)?,
                false,
            ),
            opened => (opened?, true),
        };
        let opaque = readable && is_opaque(upper.as_fd())?;
        let lower = match &top.lower {
            Some(below) if !opaque => lower_dir(below.as_fd(), leaf)?,
            _ => None,
        };
        Ok(Level { name, upper, lower })
    }

    /// The lower's directory at `leaf`, or `None` where the lower holds no
    /// directory there for the overlay to merge with.
    fn lower_dir(below: BorrowedFd<'_>, leaf: &CStr) -> Result<Option<OwnedFd>, Errno> {
        match open_child_dir(below, leaf, OFlags::PATH) {
            Ok(dir) => Ok(Some(dir)),
            Err(Errno::NOENT | Errno::NOTDIR | Errno::LOOP) => Ok(None),
            Err(errno) => Err(errno),
        }
    }

    /// Replaces the upper's whiteout at `leaf` with an opaque directory, and
    /// returns its level.
    fn replace_whiteout(
        stack: &[Level],
        name: Vec<u8>,
        leaf: &CStr,
        made: &mut dyn FnMut(Made<'_>) -> Result<(), Errno>,
    ) -> Result<Level, Errno> {
        let top = stack.last().expect("the anchor's level is never popped");
        rustix::fs::unlinkat(top.upper.as_fd(), leaf, AtFlags::empty())?;
        let dir = make_dir(top.upper.as_fd(), leaf)?;
        mark_opaque(dir.as_fd())?;
        let path = level_path(stack, &name);
        made(Made {
            path: &path,
            dir: dir.as_fd(),
            copied: None,
        })?;
        Ok(Level {
            name,
            upper: dir,
            lower: None,
        })
    }

    /// Creates in the upper the directory only the lower holds at `leaf`, and
    /// returns its level.
    fn carry_dir(
        stack: &[Level],
        name: Vec<u8>,
        leaf: &CStr,
        stat: &Stat,
        made: &mut dyn FnMut(Made<'_>) -> Result<(), Errno>,
    ) -> Result<Level, Errno> {
        let top = stack.last().expect("the anchor's level is never popped");
        let below = top
            .lower
            .as_ref()
            .expect("a directory is carried up only from a lower the overlay shows");
        let lower = lower_dir(below.as_fd(), leaf)?;
        let dir = make_dir(top.upper.as_fd(), leaf)?;
        carry_xattrs(below.as_fd(), leaf, dir.as_fd())?;
        let path = level_path(stack, &name);
        made(Made {
            path: &path,
            dir: dir.as_fd(),
            copied: Some(stat),
        })?;
        Ok(Level {
            name,
            upper: dir,
            lower,
        })
    }

    /// Gives the upper's new directory `upper` the extended attributes of the
    /// lower's directory `leaf` of `below`, as the overlay's own copy-up gives
    /// the copy it makes.
    ///
    /// Every attribute the tree carries is copied, POSIX access control lists
    /// and `user.` attributes among them. What the host assigns rather than the
    /// tree carries is not ([`host_assigned_xattr`]): the overlay's own
    /// bookkeeping would mean something else in the upper, and a security
    /// module labels the new directory as it creates it. A `trusted.` attribute
    /// is never listed for an unprivileged caller, and the overlay a sandbox
    /// mounts cannot read one either.
    ///
    /// An access control list the new directory inherited from a default on its
    /// parent, where the lower's directory carries none, is removed: the copy
    /// holds what the lower's directory holds and nothing more. A failure to set
    /// a `user.` attribute the upper's filesystem does not support is passed
    /// over, as the overlay passes it over; one to set an access control list is
    /// the caller's to report, since the copy would grant other access than the
    /// base does.
    ///
    /// A lower directory the caller cannot open for reading cannot be asked for
    /// its attributes at all, unprivileged, and its copy carries none. The walk
    /// through such a directory needs only search permission, so it can carry
    /// one up: a directory another id owns and only that id may list.
    fn carry_xattrs(
        below: BorrowedFd<'_>,
        leaf: &CStr,
        upper: BorrowedFd<'_>,
    ) -> Result<(), Errno> {
        let lower = match open_child_dir(below, leaf, OFlags::RDONLY) {
            Ok(lower) => lower,
            Err(Errno::ACCESS) => return Ok(()),
            Err(errno) => return Err(errno),
        };
        let listing = read_sized(
            || rustix::fs::flistxattr_query(&lower),
            |buffer| rustix::fs::flistxattr(&lower, buffer),
        )?;
        let mut carried = [false; ACLS.len()];
        for name in listing.split(|byte| *byte == 0) {
            if name.is_empty() || host_assigned_xattr(name) {
                continue;
            }
            let Ok(name) = CString::new(name) else {
                continue;
            };
            let value = match read_sized(
                || rustix::fs::fgetxattr_query(&lower, &name),
                |buffer| rustix::fs::fgetxattr(&lower, &name, buffer),
            ) {
                Ok(value) => value,
                // Removed since the listing: there is nothing to carry.
                Err(Errno::NODATA) => continue,
                Err(errno) => return Err(errno),
            };
            let acl = ACLS.iter().position(|acl| *acl == name.as_c_str());
            match rustix::fs::fsetxattr(upper, &name, &value, XattrFlags::empty()) {
                Ok(()) => {}
                Err(Errno::NOTSUP) if acl.is_none() => continue,
                Err(errno) => return Err(errno),
            }
            if let Some(at) = acl {
                carried[at] = true;
            }
        }
        for (acl, carried) in ACLS.iter().zip(carried) {
            if carried {
                continue;
            }
            match rustix::fs::fremovexattr(upper, *acl) {
                Ok(()) | Err(Errno::NODATA | Errno::NOTSUP) => {}
                Err(errno) => return Err(errno),
            }
        }
        Ok(())
    }

    /// Reads a listing or a value whose length `query` answers, through `read`,
    /// which fills the buffer it is given and answers the length it filled.
    ///
    /// The length can change between the asking and the reading, which the
    /// read answers with `ERANGE`; it is asked again a few times before that is
    /// reported. A filesystem without extended attributes has none to read.
    fn read_sized(
        mut query: impl FnMut() -> Result<usize, Errno>,
        mut read: impl FnMut(&mut [u8]) -> Result<usize, Errno>,
    ) -> Result<Vec<u8>, Errno> {
        for _ in 0..XATTR_ATTEMPTS {
            let size = match query() {
                Ok(size) => size,
                Err(Errno::NOTSUP) => return Ok(Vec::new()),
                Err(errno) => return Err(errno),
            };
            let mut buffer = vec![0u8; size];
            match read(&mut buffer) {
                Ok(read) => {
                    buffer.truncate(read);
                    return Ok(buffer);
                }
                Err(Errno::RANGE) => continue,
                Err(errno) => return Err(errno),
            }
        }
        Err(Errno::RANGE)
    }

    /// The ownership the directory a carry made is owed, where the lower's
    /// directory it stands in for is held at an owner or a group the new one
    /// was not given.
    ///
    /// The carry is the calling user's, so the new directory belongs to the
    /// caller's own ids, or to its parent's group where the parent is
    /// set-group-ID. A lower directory at the same two ids is owed nothing, and
    /// that is every directory of a base built under the single-identity map.
    /// The record names the new directory by its device and inode too, so the
    /// owner reaches it and nothing that takes its name before it is given.
    pub(in crate::provision) fn owed(made: &Made<'_>) -> Result<Option<Owed>, Errno> {
        let Some(lower) = made.copied else {
            return Ok(None);
        };
        let upper = rustix::fs::fstat(made.dir)?;
        if (upper.st_uid, upper.st_gid) == (lower.st_uid, lower.st_gid) {
            return Ok(None);
        }
        Ok(Some(Owed {
            path: made.path.to_vec(),
            owner: Owner::Host {
                uid: lower.st_uid,
                gid: lower.st_gid,
            },
            dev: upper.st_dev,
            ino: upper.st_ino,
        }))
    }

    /// Copies the lower's symbolic link at `leaf` into the upper, and returns its
    /// target.
    fn carry_link(top: &Level, leaf: &CStr, stat: &Stat) -> Result<CString, Errno> {
        let below = top
            .lower
            .as_ref()
            .expect("a link is carried up only from a lower the overlay shows");
        let target = rustix::fs::readlinkat(below.as_fd(), leaf, Vec::new())?;
        rustix::fs::symlinkat(&target, top.upper.as_fd(), leaf)?;
        let modified = modified(stat);
        rustix::fs::utimensat(
            top.upper.as_fd(),
            leaf,
            &Timestamps {
                last_access: modified,
                last_modification: modified,
            },
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        Ok(target)
    }

    /// The modification time `stat` records.
    ///
    /// The fields are the architecture's own `stat`, unsigned on x86_64 and signed
    /// on aarch64, so the cast is the identity on some targets and a conversion on
    /// others. `allow` is the attribute that holds on both, as the export walk's
    /// own conversions say.
    #[allow(clippy::unnecessary_cast)]
    pub(in crate::provision) fn modified(stat: &Stat) -> Timespec {
        Timespec {
            tv_sec: stat.st_mtime as i64,
            tv_nsec: stat.st_mtime_nsec as i64,
        }
    }

    /// The slash-joined path from the anchor to `name` beneath the top of `stack`.
    fn level_path(stack: &[Level], name: &[u8]) -> Vec<u8> {
        let mut path = Vec::new();
        for level in &stack[1..] {
            path.extend_from_slice(&level.name);
            path.push(b'/');
        }
        path.extend_from_slice(name);
        path
    }
}

/// Opens `name` under `dir` for `access` as the regular file `typed` describes,
/// refusing whatever has taken the name since.
///
/// The one answer to opening a file a walk has just inspected. `typed` is the
/// `stat` the caller took of the name, without following a link, to decide that
/// it was a regular file worth opening. Between that and the open, anything can
/// take the name. The open therefore waits on nothing: a named pipe put there
/// would hold a blocking open until something opened its other end, and
/// `O_NOCTTY` keeps a terminal from becoming the caller's. The descriptor is
/// then checked against `typed` by kind, device, and inode, so what is read or
/// written is the file the walk looked at. Anything else is `ESTALE`, which
/// each caller reports as the tree having changed underneath it. A regular file
/// ignores the `O_NONBLOCK` the descriptor keeps.
///
/// It allocates nothing, so the export's post-fork walk calls it as the
/// copy-in's host-side walk and `rooted::Rooted` do.
pub(crate) fn open_typed_file(
    dir: BorrowedFd<'_>,
    name: &CStr,
    typed: &Stat,
    access: OFlags,
) -> Result<OwnedFd, Errno> {
    let file = rustix::fs::openat(
        dir,
        name,
        access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let opened = rustix::fs::fstat(&file)?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
        || opened.st_dev != typed.st_dev
        || opened.st_ino != typed.st_ino
    {
        return Err(Errno::STALE);
    }
    Ok(file)
}

/// Opens the named pipe `name` the caller just created in `dir`, so its
/// metadata can be applied through a descriptor rather than by name.
///
/// `O_RDONLY | O_NONBLOCK` opens a pipe at once, whether or not anything holds
/// its other end. `O_NOFOLLOW` refuses a name a racer replaced with a symbolic
/// link since the `mknodat`, and `O_NOCTTY` keeps a terminal put there from
/// becoming the caller's controlling one before the check below refuses it.
/// Anything that is not a pipe is `EEXIST`: the name no longer holds the entry
/// the caller created.
///
/// It allocates nothing, so the copy-in child calls it after the fork as the
/// extractor does in process.
pub(crate) fn open_created_fifo(dir: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd, Errno> {
    let fifo = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if FileType::from_raw_mode(rustix::fs::fstat(&fifo)?.st_mode) != FileType::Fifo {
        return Err(Errno::EXIST);
    }
    Ok(fifo)
}

/// Runs `create`, unlinking whatever occupies `leaf` in `parent` and trying
/// again on `EEXIST`.
///
/// `EEXIST` is the only failure acted on: every other errno is the caller's to
/// report, and so is the `EEXIST` that survives [`REPLACE_ATTEMPTS`] rounds.
///
/// `parent` is a descriptor for the directory holding the name, so the unlink
/// and the create act on the same entry the kernel already resolved — nothing
/// here re-walks a path, and the containment that got the caller its descriptor
/// is what keeps this inside the tree.
///
/// It allocates nothing, so the copy-in child replaces what holds a name after
/// the fork as the extractor and the host-side steps do in process. A `create`
/// that allocates nothing keeps it that way.
pub(crate) fn replacing<T>(
    parent: impl AsFd,
    leaf: &CStr,
    mut create: impl FnMut() -> Result<T, Errno>,
) -> Result<T, Errno> {
    for _ in 0..REPLACE_ATTEMPTS {
        match create() {
            Ok(value) => return Ok(value),
            Err(Errno::EXIST) => remove_at(parent.as_fd(), leaf)?,
            Err(errno) => return Err(errno),
        }
    }
    Err(Errno::EXIST)
}

/// Makes `leaf` in `parent` another name for the entry `target_leaf` of
/// `target_dir`, replacing whatever else holds the name as [`replacing`] does.
///
/// A name that already holds that entry is already done. It is the same rule
/// GNU tar applies, and the replacement cannot apply it for itself: what it
/// would unlink to make room is a name of the very file the link is to, and
/// where the two names are one, a link whose target is its own name or a name
/// reached through a directory alias such as merged-usr's `bin -> usr/bin`,
/// the unlink removes the file and the link after it fails with `ENOENT`. GNU
/// tar writes such an entry wherever it lists a multiply-linked path twice.
///
/// The two are compared by device and inode, without following a link at
/// either name, once the link has been refused for the name being taken.
/// Neither final component is followed by the link either: `linkat` without
/// `AT_SYMLINK_FOLLOW` links a symbolic link as itself.
///
/// It allocates nothing, so the copy-in child links after the fork as the
/// extractor does in process.
pub(crate) fn link_replacing(
    target_dir: BorrowedFd<'_>,
    target_leaf: &CStr,
    parent: BorrowedFd<'_>,
    leaf: &CStr,
) -> Result<(), Errno> {
    replacing(parent, leaf, || {
        match rustix::fs::linkat(target_dir, target_leaf, parent, leaf, AtFlags::empty()) {
            Err(Errno::EXIST) if same_entry(target_dir, target_leaf, parent, leaf)? => Ok(()),
            linked => linked,
        }
    })
}

/// Whether `leaf_a` of `dir_a` and `leaf_b` of `dir_b` name one entry, by
/// device and inode, following a link at neither.
fn same_entry(
    dir_a: BorrowedFd<'_>,
    leaf_a: &CStr,
    dir_b: BorrowedFd<'_>,
    leaf_b: &CStr,
) -> Result<bool, Errno> {
    let a = rustix::fs::statat(dir_a, leaf_a, AtFlags::SYMLINK_NOFOLLOW)?;
    let b = rustix::fs::statat(dir_b, leaf_b, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(a.st_dev == b.st_dev && a.st_ino == b.st_ino)
}

/// Removes the entry at `leaf` in `parent`, whichever kind it is.
///
/// An empty directory is removed; a non-empty one keeps the `ENOTEMPTY` the
/// kernel gave, which is what every caller wants to report — a tar entry does
/// not supersede a directory that still holds entries, and neither does a
/// host-side write or an entry a copy lays in.
pub(crate) fn remove_at(parent: impl AsFd, leaf: &CStr) -> Result<(), Errno> {
    let parent = parent.as_fd();
    match rustix::fs::unlinkat(parent, leaf, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(Errno::ISDIR) => rustix::fs::unlinkat(parent, leaf, AtFlags::REMOVEDIR),
        Err(errno) => Err(errno),
    }
}
