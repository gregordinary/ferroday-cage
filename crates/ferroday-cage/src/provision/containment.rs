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
//! same wherever it is made, and is stated here once.
//!
//! # The two containment flags
//!
//! `RESOLVE_IN_ROOT` re-anchors an absolute symbolic link at the tree's root,
//! which is what such a link means to a tree that is a root filesystem: `/lib
//! -> /usr/lib` inside a rootfs names the rootfs's own `/usr/lib`, both to the
//! sandbox that pivots into it and to the host-side step writing to it
//! beforehand. `RESOLVE_BENEATH` refuses every absolute link instead, including
//! one whose target would land back inside the tree, and is what a caller uses
//! when the tree is a plain host directory that nothing ever re-roots — an
//! extraction destination, where an absolute link points at the host and
//! honouring it would write there.
//!
//! Either way the walk cannot leave the tree. The flags differ only in what
//! they do with a link that names a path from a root.
//!
//! # Creating over what is already there
//!
//! [`replacing`] is here for the same reason [`open_dir`] is. Both halves of
//! provisioning create entries in a tree that may already hold something at the
//! name, and both answer it the same way: unlink whatever is there and create
//! again. What differs between them is only what a failure is called — the
//! extractor reports a `ProvisionError` naming the archive entry, the host-side
//! steps an errno the operation's own error carries — so the errno-level
//! algorithm is stated once and each caller says what its failures are.

use std::ffi::{CStr, CString};
use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

/// How many times a create is retried when something already occupies the name.
///
/// One replacement always suffices; the bound exists so a pathological
/// filesystem state — an entry something else keeps putting back — cannot loop
/// forever.
const REPLACE_ATTEMPTS: u32 = 3;

/// How many times a resolution is retried when a rename raced it.
///
/// Each attempt re-resolves from the anchor, so a genuine race is lost once and
/// won next; consecutive losses are what a tree being rewritten underneath the
/// walk produces, and sixteen of them is far past anything an ordinary one
/// reaches. The bound exists for the same reason [`REPLACE_ATTEMPTS`] does:
/// neither half of provisioning walks a tree this crate trusts, and a
/// pathological state must not be able to loop forever.
const RESOLVE_ATTEMPTS: u32 = 16;

/// Opens `path` as a directory, resolved against `anchor` under `containment`.
///
/// `access` is what the descriptor is for: `O_PATH` where it is only ever the
/// anchor of a later `*at` call, and `O_RDONLY` where something is done to the
/// directory itself — an `O_PATH` descriptor does not accept `fchmod`. A caller
/// that must not follow a symbolic link at the final component adds
/// `O_NOFOLLOW`, which the containment flag does not cover: `RESOLVE_BENEATH`
/// keeps a follow inside the tree, and staying inside the tree is not the same
/// as landing on the entry that was named.
///
/// `O_DIRECTORY` and `O_CLOEXEC` are unconditional: every caller wants a
/// directory, and a descriptor that outlived an exec would be one the sandbox
/// could inherit. `RESOLVE_NO_MAGICLINKS` is unconditional for the same kind of
/// reason — a `/proc/*/fd/*` entry re-opens whatever it names, from anywhere on
/// the host, and no path in a tree being provisioned has a use for one.
///
/// `EAGAIN` is retried rather than returned, up to [`RESOLVE_ATTEMPTS`] times.
/// The kernel answers with it when a rename raced the walk, meaning "ask
/// again", and a caller that took it for a failure would report a rootfs as
/// unwritable because something moved underneath it. The bound is the same
/// reasoning [`replacing`] applies to its own retry: a tree being provisioned
/// is not one this crate trusts, and something renaming components in a loop
/// must not be able to spin the walk forever. An exhausted retry returns the
/// `EAGAIN` it kept receiving, which is the accurate answer — the resolution
/// really was raced every time — and the caller reports it against whatever it
/// was opening.
pub(super) fn open_dir(
    anchor: BorrowedFd<'_>,
    path: &CStr,
    access: OFlags,
    containment: ResolveFlags,
) -> Result<OwnedFd, Errno> {
    for _ in 0..RESOLVE_ATTEMPTS {
        // The call `clippy.toml` sends every other site here for: this is that
        // answer.
        #[expect(clippy::disallowed_methods)]
        let opened = rustix::fs::openat2(
            anchor,
            path,
            access | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            containment | ResolveFlags::NO_MAGICLINKS,
        );
        match opened {
            Err(Errno::AGAIN) => continue,
            result => return result,
        }
    }
    Err(Errno::AGAIN)
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
pub(super) fn replacing<T>(
    parent: &OwnedFd,
    leaf: &CString,
    mut create: impl FnMut() -> Result<T, Errno>,
) -> Result<T, Errno> {
    for _ in 0..REPLACE_ATTEMPTS {
        match create() {
            Ok(value) => return Ok(value),
            Err(Errno::EXIST) => remove_at(parent, leaf)?,
            Err(errno) => return Err(errno),
        }
    }
    Err(Errno::EXIST)
}

/// Removes the entry at `leaf` in `parent`, whichever kind it is.
///
/// An empty directory is removed; a non-empty one keeps the `ENOTEMPTY` the
/// kernel gave, which is what both callers want to report — a tar entry does not
/// supersede a directory that still holds entries, and neither does a host-side
/// write.
pub(super) fn remove_at(parent: &OwnedFd, leaf: &CString) -> Result<(), Errno> {
    match rustix::fs::unlinkat(parent, leaf, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(Errno::ISDIR) => rustix::fs::unlinkat(parent, leaf, AtFlags::REMOVEDIR),
        Err(errno) => Err(errno),
    }
}
