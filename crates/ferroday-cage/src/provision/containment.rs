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

use std::ffi::CStr;
use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::fs::{Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

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
/// `EAGAIN` is retried rather than returned. The kernel answers with it when a
/// rename raced the walk, meaning "ask again", and a caller that took it for a
/// failure would report a rootfs as unwritable because something moved
/// underneath it.
pub(super) fn open_dir(
    anchor: BorrowedFd<'_>,
    path: &CStr,
    access: OFlags,
    containment: ResolveFlags,
) -> Result<OwnedFd, Errno> {
    loop {
        // The call `clippy.toml` sends every other site here for: this is that
        // answer.
        #[allow(clippy::disallowed_methods)]
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
}
