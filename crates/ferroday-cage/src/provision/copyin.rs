//! Copying a host tree into a rootfs at the ownership the rootfs intends.
//!
//! The caller-facing half of [`mechanism::copyin`](crate::mechanism): this side
//! walks the host source with an allocator and a heap, and streams frames to
//! the in-map child that creates each entry. See that module for the frame
//! protocol and the post-fork discipline the child works under.
//!
//! Three things live here rather than in the child because they need a heap.
//! The hardlink table recognizes that two names are one file and emits the
//! second as a link onto the first, so a tree keeps the sharing it was written
//! with — the same table, and the same reason, as the export's. Each entry's
//! extended attributes are read and judged here, and the ones the sandbox's
//! root can set are restated for the map. And the skip report names every
//! entry the copy could not create and every attribute it could not give, so a
//! rootfs that ends up missing something says so.
//!
//! The same child also gives an owner to entries a tree already holds, for a
//! provisioner that laid them down as the calling user: [`reown`], which a
//! layered build gives the directories it carried up from its base, and the
//! Alpine layer the entries a package states another owner for.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{self, AtFlags, OFlags};

use super::containment;
use super::identity::{Ownership, compose_child_map};
use super::xattr::{self, Acl, Holder, Named, Restated};
use super::{Delegate, ProvisionError};
use crate::IdentityMap;
use crate::failure::ErrorChain;
use crate::idmap::{IdMapper, IdRange};
use crate::mechanism::bounds::{LINK_BUF, MAX_DEPTH, NAME_MAX, XATTR_NAME_MAX, XATTR_SIZE_MAX};
use crate::mechanism::frame::{self, Holes, StreamFailure};
use crate::mechanism::{
    COPY_DIR, COPY_END, COPY_FIFO, COPY_FILE, COPY_LEAVE, COPY_LINK, COPY_OWN, COPY_SYMLINK,
    ChildMap, CopyFailure, start_copy_in,
};
use crate::path;

/// Copies a host directory tree into a rootfs, with each entry created under
/// the identity map the rootfs is owned through.
///
// The paragraph links a feature-gated item, so its doc text is gated on the
// feature: present in the canonical all-features build, absent — link and all —
// from a no-feature `cargo doc`.
#[cfg_attr(
    feature = "tarball",
    doc = "
The mirror image of [`Export`](super::Export). An export forks a child into
the map to *read* a tree at the ownership it intends; this forks one to
*write* one.

The mirroring is of the mechanism, not of the entry types. An export
describes a rootfs the cage built, for a runtime that will supply its own
device nodes and pipes; a copy lays down a tree the caller wrote by hand,
where every entry is there because someone put it there. So the copy creates
everything it can create — a named pipe included — and names the rest.

"
)]
/// A source entry's host ownership is read back through the map to the id it
/// means inside the rootfs. So a tree an earlier mapped sandbox produced copies
/// in owned as it was written, and a tree the caller staged as themselves lands
/// as whatever id the map gives the calling user — root, under a
/// [`Single`](IdentityMap::Single) map.
///
/// That is the thing a plain `cp` structurally cannot do. `cp` runs as the
/// calling user, which can create a file owned by nobody else, so a tree laid
/// into a rootfs by hand arrives owned by the caller's own host id, whatever the
/// source intended — an id a range-mapped rootfs has no name for at all.
///
/// The destination must already exist, and entries are added to it. A directory
/// the rootfs already carries is kept as it stands, and the copy descends into
/// it without setting its owner, mode, or modification time. So is a symbolic
/// link that resolves inside the rootfs to a directory, such as merged-usr's
/// `bin -> usr/bin`: the copy lands through it, resolving it from the rootfs's
/// root as the sandbox would. Anything else at a directory's name is replaced,
/// and a file, symlink, or named pipe replaces whatever is at its own, an empty
/// directory included. A directory with something in it is not replaced, and
/// fails the copy.
///
/// Directories, regular files, symbolic links, and named pipes are copied.
/// Several names for one file are copied as hard links, so a tree keeps the
/// sharing it was written with. Character and block devices and sockets cannot
/// be copied and are named in the [`CopyReport`] the run returns; see
/// [`SkippedKind`] for why each is left out.
///
/// A sparse file is copied sparse. Its data is found with `SEEK_DATA` and
/// `SEEK_HOLE`, and each hole is left a hole in the copy, so a file that cost
/// whoever wrote it nothing to make long costs the copy its data rather than
/// its length: `truncate -s 16T` writes no data, and a copy that wrote what such
/// a file reads as would fill the destination's disk with zeros. A source
/// filesystem that cannot report where a file's holes are has the file copied
/// as the zeros it reads as.
///
/// Extended attributes are copied where the sandbox's root can set them:
/// `user.` attributes, POSIX access control lists, and a file's capabilities.
/// An access control list's named users and groups, and the user a capability
/// is rooted at, are read through the map as the entry's owner is, so the list
/// names in the rootfs whom it named in the source. A capability the source
/// holds in its plain form lands in the namespaced form, rooted at the
/// rootfs's root, which is the most a user namespace's root can grant. Each
/// attribute the copy cannot give is named in the report; see
/// [`AttributeSkip`]. The attributes a host assigns rather than a tree carries,
/// a security module's label among them, are left for the destination's host
/// to assign, as an export leaves them out.
///
/// An access control list that cannot be copied is not dropped as though it
/// were never there. Where a list has a mask, the group bits of the entry's
/// mode are the mask, so the mode alone would give the owning group what the
/// mask allows. The entry is given the list's own narrowing instead: the owning
/// group keeps what the list allowed it, and the named users and groups lose
/// what they were given. A directory's default list is narrowed the same way.
///
/// # Example
///
/// ```no_run
/// use ferroday_cage::IdentityMap;
/// use ferroday_cage::provision::CopyIn;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let report = CopyIn::new("./overlay", "/srv/images/trixie")
///     .identity_map(IdentityMap::Subordinate)
///     .run()?;
///
/// for entry in &report.skipped {
///     eprintln!("not copied: {} ({})", entry.path.display(), entry.kind);
/// }
/// for attribute in &report.attributes {
///     eprintln!(
///         "not given: {} on {} ({})",
///         attribute.name.display(),
///         attribute.path.display(),
///         attribute.reason,
///     );
/// }
/// # Ok(())
/// # }
/// ```
pub struct CopyIn {
    source: PathBuf,
    rootfs: PathBuf,
    identity_map: IdentityMap,
    id_mapper: Option<Arc<dyn IdMapper>>,
}

impl fmt::Debug for CopyIn {
    /// Renders every setting, and the mapper by its presence rather than its
    /// contents: it is a caller's trait object, with nothing useful to show.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CopyIn")
            .field("source", &self.source)
            .field("rootfs", &self.rootfs)
            .field("identity_map", &self.identity_map)
            .field(
                "id_mapper",
                &self.id_mapper.as_ref().map(|_| Delegate("dyn IdMapper")),
            )
            .finish()
    }
}

impl CopyIn {
    /// Returns a copy of the tree at `source` into the rootfs at `rootfs`.
    ///
    /// A symbolic link at `source` itself is followed, as one at any other
    /// component of a caller's path is. No link inside the tree is
    /// followed: each is copied as the link it is.
    ///
    /// The identity map defaults to [`IdentityMap::Single`], under which the
    /// in-map child writes its own one-id map and every entry lands as root —
    /// what a single-mapped sandbox sees, and what such a sandbox could have
    /// written itself.
    ///
    /// That is a sandbox's own default, because a copy writes every owner
    /// through the map: it has to be the map the root was built under, and a
    /// root built with every default was built under this one. A [`Remove`]
    /// defaults to the subordinate map instead, because a removal writes no
    /// ownership.
    ///
    /// [`Remove`]: super::Remove
    pub fn new(source: impl AsRef<Path>, rootfs: impl AsRef<Path>) -> CopyIn {
        CopyIn {
            source: source.as_ref().to_path_buf(),
            rootfs: rootfs.as_ref().to_path_buf(),
            identity_map: IdentityMap::Single,
            id_mapper: None,
        }
    }

    /// Sets the identity map the rootfs is owned through.
    ///
    /// It must be the map the rootfs was built under, for the reason an export
    /// must name the same one: the ids on the host are the rootfs's ids offset
    /// by the map, so a copy made through a different map writes ownership the
    /// rootfs will not read back as intended.
    pub fn identity_map(mut self, map: IdentityMap) -> CopyIn {
        self.identity_map = map;
        self
    }

    /// Copies through a caller-supplied identity-map delegate, for a rootfs
    /// built under [`CageBuilder::id_mapper`].
    ///
    /// Without one, the copy resolves the bundled delegate chain, which covers
    /// a [`Subordinate`](IdentityMap::Subordinate) rootfs and a
    /// bundled-delegate [`Ranges`](IdentityMap::Ranges) one. A
    /// [`Single`](IdentityMap::Single) map self-establishes and ignores the
    /// mapper, as the launch does.
    ///
    /// The delegate is taken by value and kept, as every builder that takes one
    /// keeps it; [`CageBuilder::id_mapper`] says why.
    ///
    /// [`CageBuilder::id_mapper`]: crate::CageBuilder::id_mapper
    pub fn id_mapper(mut self, mapper: impl IdMapper + 'static) -> CopyIn {
        self.id_mapper = Some(Arc::new(mapper));
        self
    }

    /// Performs the copy, reporting what it could not copy.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::CopyUnprivileged`] when the rootfs needs a range map
    /// and no delegate can establish one; [`ProvisionError::EntryRefused`] for a
    /// source entry the copy cannot carry — a tree deeper than the walk
    /// descends, a name or a link target longer than a frame holds, or an
    /// ownership the rootfs's identity map has no id for;
    /// [`ProvisionError::SourceChanged`] for a file that changed size while it
    /// was being read, or whose name stopped holding it between the walk
    /// inspecting it and opening it; and [`ProvisionError::Io`] for a failure of
    /// the copy machinery, of the walk, or of the in-map writer. A destination
    /// whose filesystem refuses an extended attribute the copy gives, one
    /// without `user.` attributes or access control lists, is such a failure,
    /// naming the step, rather than an attribute passed over in silence.
    pub fn run(self) -> Result<CopyReport, ProvisionError> {
        copy_in_inner(
            &self.source,
            &self.rootfs,
            &self.identity_map,
            self.id_mapper.as_ref(),
        )
    }
}

/// What a [`CopyIn`] run left out.
///
/// A copy that silently dropped an entry, or an attribute of one, would produce
/// a rootfs that differs from the tree the caller wrote, with nothing to say
/// so. Every source entry the copy did not create, and every extended
/// attribute it did not give an entry it copied, is named here instead, so a
/// caller can treat the omission as a warning, as an error, or as expected.
///
/// When [`skipped`](Self::skipped) and [`attributes`](Self::attributes) are
/// both empty, the destination holds everything the source did, but for the
/// attributes a host assigns to whatever it holds, which the destination's host
/// assigns afresh; see [`CopyIn`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CopyReport {
    /// Every source entry the copy did not create, in the order the walk
    /// reached them.
    pub skipped: Vec<SkippedEntry>,
    /// Every extended attribute the copy did not give an entry it created, in
    /// the order the walk reached them.
    pub attributes: Vec<SkippedAttribute>,
}

/// One source entry a [`CopyIn`] run did not create.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkippedEntry {
    /// The entry's path in the source tree, as the walk reached it.
    pub path: PathBuf,
    /// What the entry is, which is why it was left out.
    pub kind: SkippedKind,
}

/// The kind of source entry a copy cannot create.
///
/// Every other kind — a directory, a regular file, a symbolic link, a named
/// pipe, and a second name for a file already copied — is copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkippedKind {
    /// A character device.
    ///
    /// Creating a device node needs `CAP_MKNOD` in the *initial* user
    /// namespace, which the copy child does not hold however it is mapped, so
    /// this is a limit of the mechanism rather than a choice. A rootfs's
    /// runtime supplies its own device nodes.
    CharacterDevice,
    /// A block device, for the reason a character device is skipped.
    BlockDevice,
    /// A unix-domain socket.
    ///
    /// A socket's inode is created by the process that binds it and is
    /// meaningless without that process; copying the inode would produce a
    /// path that looks connectable and is not.
    Socket,
}

/// An extended attribute a [`CopyIn`] run did not give the entry it copied.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkippedAttribute {
    /// The entry's path in the source tree, as the walk reached it.
    pub path: PathBuf,
    /// The attribute's name, as the source lists it.
    pub name: OsString,
    /// Why the attribute was left off.
    pub reason: AttributeSkip,
}

/// Why a copy left an extended attribute off the entry it copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttributeSkip {
    /// The sandbox's root cannot set it.
    ///
    /// The copy writes from inside the rootfs's user namespace, whose root is
    /// root only of what the map gives it. A `trusted.` attribute needs the
    /// host's own administrator, and so does a `security.` attribute other than
    /// a capability and a `system.` attribute other than an access control
    /// list. A symbolic link holds no attribute anything unprivileged can set,
    /// and a value the kernel would not store, such as a capability of the
    /// obsolete first revision, is not set either.
    Unsettable,
    /// It names an id the identity map has no id inside the rootfs for: a user
    /// or a group an access control list names, or the user a capability is
    /// rooted at.
    ///
    /// An access control list left off for this reason is narrowed rather than
    /// dropped; see [`CopyIn`].
    UnmappedId,
}

impl fmt::Display for AttributeSkip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let described = match self {
            AttributeSkip::Unsettable => {
                "an attribute the rootfs's root cannot set, which needs the host's own \
                 administrator or an entry that can hold it"
            }
            AttributeSkip::UnmappedId => {
                "an attribute naming an id the identity map has no id inside the rootfs for"
            }
        };
        f.write_str(described)
    }
}

impl fmt::Display for SkippedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let described = match self {
            SkippedKind::CharacterDevice => {
                "a character device, which needs a privilege the copy does not hold"
            }
            SkippedKind::BlockDevice => {
                "a block device, which needs a privilege the copy does not hold"
            }
            SkippedKind::Socket => "a socket, which only the process that binds it can create",
        };
        f.write_str(described)
    }
}

/// Copies `source` into `rootfs`, resolving a range map through `mapper` when
/// given and the bundled delegate chain otherwise.
fn copy_in_inner(
    source: &Path,
    rootfs: &Path,
    map: &IdentityMap,
    mapper: Option<&Arc<dyn IdMapper>>,
) -> Result<CopyReport, ProvisionError> {
    let rootfs_c = CString::new(rootfs.as_os_str().as_bytes()).map_err(|_| {
        ProvisionError::io(
            "copying into",
            rootfs,
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;
    let source_root = open_source(source)?;

    let map_source =
        compose_child_map(map, mapper).map_err(|reason| ProvisionError::CopyUnprivileged {
            path: rootfs.to_path_buf(),
            reason,
        })?;
    let child_map = map_source.child_map();

    // The extents the source's ids are read through, as host-to-inside pairs.
    // See `Translation`.
    let translation = Translation::of(&child_map);

    let child = start_copy_in(&rootfs_c, child_map).map_err(|err| failure(err, rootfs))?;

    // The walk writes to the child's stream. A failure part-way leaves the
    // child mid-tree, so it is killed rather than left to read an input that
    // will never end.
    //
    // The child's own account comes first where it left one. The walk's most
    // common failure is a frame write, and a frame write fails only because the
    // child has already died — of a step this side cannot see, an id the map
    // refuses or an entry the destination will not take — so this side's broken
    // pipe would name the symptom and drop the cause.
    let report = match walk(child.stream(), source_root, source, &translation) {
        Ok(report) => report,
        Err(err) => {
            return Err(match child.abandon() {
                Some(reported) => failure(reported, rootfs),
                None => err,
            });
        }
    };
    child.finish().map_err(|err| failure(err, rootfs))?;
    Ok(report)
}

/// An entry a tree already holds, and the owner it is owed: what [`reown`]
/// gives it.
///
/// A provisioner lays a tree down as the calling user, who can create an entry
/// owned by nobody else, so an owner only the tree's identity map can express is
/// recorded here and given afterwards. Two steps owe one. A layered build
/// carries a base's directory up into its upper, where the base holds it at the
/// owner its packages and scripts gave it, as the overlay's own copy-up would
/// have kept. And the Alpine layer gives an entry a package states another
/// owner for that owner, once the package's pre-install has created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Owed {
    /// Where the entry is, slash-joined from the tree's root, which the in-map
    /// child resolves as the root does, following every link but the last.
    pub(crate) path: Vec<u8>,
    /// The owner and group it is owed.
    pub(crate) owner: Owner,
    /// The device the entry was on when it was recorded.
    pub(crate) dev: u64,
    /// Its inode number then. With [`dev`](Self::dev), what tells the entry
    /// apart from anything that has taken its name since, which [`reown`]
    /// leaves alone.
    pub(crate) ino: u64,
}

/// The ids an [`Owed`] entry is owed, and the side of the tree's identity map
/// they are stated on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owner {
    /// As the host stores them, which is how a carried directory's base holds
    /// it. Read back through the map to the ids they mean inside the tree, as a
    /// copy reads a source tree's (see [`Translation`]). An id the map has no
    /// inside id for cannot be set from inside it either, so the entry keeps
    /// the owner it has: under the single-identity map, that is every id but
    /// the caller's own.
    #[cfg_attr(
        not(feature = "tarball"),
        allow(
            dead_code,
            reason = "only a layered build carries a base's directory up, and only a build with \
                      a provisioner makes one"
        )
    )]
    Host {
        /// The owner.
        uid: u32,
        /// The group.
        gid: u32,
    },
    /// As the tree means them, which is how a package names its owner through
    /// the root's own accounts. An id the map does not hold is refused, naming
    /// the entry, since nothing else could give the entry the owner it states.
    #[cfg_attr(
        not(feature = "alpine"),
        allow(
            dead_code,
            reason = "only the Alpine layer names an owner through the root's own accounts"
        )
    )]
    Tree {
        /// The owner.
        uid: u32,
        /// The group.
        gid: u32,
    },
}

/// Gives each entry `owed` names inside the tree at `root` the owner recorded
/// for it, from a child re-entered into the map the tree is owned through.
///
/// The counterpart of a copy for a tree laid down already: nothing is created,
/// and an entry is given the ids its owner names as the tree means them, which
/// a process outside the map cannot do for the reason a copy cannot create such
/// an entry. The child resolves each path from the root, changes nothing but
/// the entry's owner and group, and leaves alone a name that no longer holds
/// the entry recorded; see the copy-in child's `COPY_OWN` frame. Nothing is
/// forked when nothing is left to give.
///
/// # Errors
///
/// [`ProvisionError::CopyUnprivileged`] where the map cannot be established,
/// [`ProvisionError::EntryRefused`] for a path longer than a frame carries, and
/// [`ProvisionError::Io`] for a failure of the child, naming `root`. A
/// [`Owner::Tree`] id the map does not hold is an
/// [`EntryRefused`](ProvisionError::EntryRefused) naming the entry.
pub(crate) fn reown(
    root: &Path,
    owed: &[Owed],
    ownership: &Ownership,
) -> Result<(), ProvisionError> {
    if owed.is_empty() {
        return Ok(());
    }
    let map_source = ownership
        .child_map()
        .map_err(|reason| ProvisionError::CopyUnprivileged {
            path: root.to_path_buf(),
            reason,
        })?;
    let child_map = map_source.child_map();
    let translation = Translation::of(&child_map);

    let mut owing = Vec::new();
    for record in owed {
        let path = root.join(OsStr::from_bytes(&record.path));
        let (uid, gid) = match record.owner {
            Owner::Host { uid, gid } => {
                let (Some(uid), Some(gid)) = (translation.maps_uid(uid), translation.maps_gid(gid))
                else {
                    continue;
                };
                (uid, gid)
            }
            Owner::Tree { uid, gid } => {
                if !translation.holds_uid(uid) || !translation.holds_gid(gid) {
                    return Err(ProvisionError::EntryRefused {
                        path,
                        reason: format!(
                            "its owner {uid}:{gid} is an id the identity map does not hold"
                        ),
                    });
                }
                (uid, gid)
            }
        };
        // The child resolves the path into a fixed buffer, as it does a hard
        // link's anchor.
        if record.path.len() > LINK_BUF {
            return Err(ProvisionError::EntryRefused {
                path,
                reason: "the path of an entry to own is longer than a frame can carry".to_string(),
            });
        }
        owing.push((record, uid, gid));
    }
    if owing.is_empty() {
        return Ok(());
    }

    let root_c = CString::new(root.as_os_str().as_bytes()).map_err(|_| {
        ProvisionError::io(
            "re-owning in",
            root,
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;
    let child = start_copy_in(&root_c, child_map).map_err(|err| failure(err, root))?;
    let stream = child.stream();
    let sent = owing
        .iter()
        .try_for_each(|(record, uid, gid)| {
            put(stream, &[COPY_OWN], root)?;
            put_bytes_u16(stream, &record.path, root)?;
            for field in [uid.to_le_bytes(), gid.to_le_bytes()] {
                put(stream, &field, root)?;
            }
            for field in [record.dev.to_le_bytes(), record.ino.to_le_bytes()] {
                put(stream, &field, root)?;
            }
            Ok(())
        })
        .and_then(|()| put(stream, &[COPY_END], root));
    if let Err(err) = sent {
        return Err(match child.abandon() {
            Some(reported) => failure(reported, root),
            None => err,
        });
    }
    child.finish().map_err(|err| failure(err, root))
}

/// Turns a child-side failure into the caller's error.
fn failure(err: CopyFailure, rootfs: &Path) -> ProvisionError {
    match err {
        CopyFailure::Map(err) => ProvisionError::CopyUnprivileged {
            path: rootfs.to_path_buf(),
            reason: ErrorChain::new(&err).to_string(),
        },
        CopyFailure::Step { step, errno } => ProvisionError::Io {
            op: step.describe(),
            path: rootfs.to_path_buf(),
            source: io::Error::from_raw_os_error(errno),
        },
        CopyFailure::Malformed => ProvisionError::Io {
            op: "reading the copy process's outcome",
            path: rootfs.to_path_buf(),
            source: io::Error::from_raw_os_error(rustix::io::Errno::PROTO.raw_os_error()),
        },
    }
}

/// Walks the source tree opened as `root` and streams its contents as frames.
///
/// The source root itself is not emitted: its contents land directly in the
/// destination, so a copy of `./overlay` into a rootfs puts `./overlay/etc` at
/// `/etc`. That matches what a caller means by laying a tree in, and it means
/// the destination's own mode and ownership are never rewritten by a copy.
///
/// The whole walk is relative to that descriptor: every step resolves a name
/// against a directory the walk holds open rather than against a path, so what
/// was typed is what is read. See `Walk::dir`. `source` names the tree in
/// diagnostics and in the report.
fn walk(
    stream: BorrowedFd<'_>,
    root: OwnedFd,
    source: &Path,
    ids: &Translation,
) -> Result<CopyReport, ProvisionError> {
    let mut walk = Walk {
        ids,
        links: HashMap::new(),
        prefix: Vec::new(),
        report: CopyReport::default(),
    };
    walk.dir(stream, root.as_fd(), source, 0)?;
    put(stream, &[COPY_END], source)?;
    Ok(walk.report)
}

/// The state one walk carries: the id translation, the hardlink table, the
/// path of the directory currently being emitted, and what has been skipped.
struct Walk<'a> {
    /// The map, read backwards, applied to every entry's ownership.
    ids: &'a Translation,
    /// The first name emitted for each multiply-linked inode, keyed by device
    /// and inode number and held as a path relative to the destination root.
    ///
    /// The parent keeps this for the same reason the export does: the child
    /// has no heap and no path assembly, so recognizing that two names are one
    /// file is work only this side can do.
    links: HashMap<(u64, u64), Vec<u8>>,
    /// The current directory's path relative to the destination root, with a
    /// trailing separator, so appending a name gives that entry's own path.
    /// Empty at the top of the tree.
    prefix: Vec<u8>,
    /// What the walk could not copy.
    report: CopyReport,
}

impl Walk<'_> {
    /// Emits every entry of `dir`, descending into subdirectories.
    ///
    /// `dir` is a descriptor, and every step resolves its name against that
    /// descriptor rather than against a path: the entry that is typed is the
    /// entry that is then read, opened, or descended into. A path-based walk
    /// resolves each name afresh at every step, so an entry swapped for a
    /// symbolic link between being typed and being acted on is followed — a
    /// directory descended out of the source, or worse, a file streamed from
    /// wherever the link points. `path` is carried alongside for diagnostics
    /// and for the report, and names nothing this resolves.
    ///
    /// A symbolic link is therefore copied as a symbolic link and never
    /// traversed, whatever it points at. The child holds its own side to the
    /// same rule: the one link it follows is a destination alias of a
    /// directory, resolved from the destination's root.
    ///
    /// Entries are sorted by name, so a copy of one tree is one sequence of
    /// frames whatever order the filesystem hands them back — the same reason
    /// the export sorts its own walk. Sorting also fixes which name of a
    /// multiply-linked file carries the data and which become links, so two
    /// copies of one tree produce the same frames.
    fn dir(
        &mut self,
        stream: BorrowedFd<'_>,
        dir: BorrowedFd<'_>,
        path: &Path,
        depth: usize,
    ) -> Result<(), ProvisionError> {
        if depth >= MAX_DEPTH {
            return Err(ProvisionError::EntryRefused {
                path: path.to_path_buf(),
                reason: format!("the source tree is deeper than {MAX_DEPTH} levels"),
            });
        }
        let mut entries = read_names(dir, path)?;
        entries.sort();

        for name in entries {
            let entry = path.join(OsStr::from_bytes(&name));
            // The child refuses anything that is not a single ordinary
            // component, and refusing here names the host path that carries it
            // rather than leaving the child to report a name with no context.
            if !path::is_ordinary_component(&name) {
                return Err(ProvisionError::EntryRefused {
                    path: entry,
                    reason: "the entry name is not a single path component".to_string(),
                });
            }
            if name.len() > NAME_MAX {
                return Err(ProvisionError::EntryRefused {
                    path: entry,
                    reason: "the entry name is longer than NAME_MAX".to_string(),
                });
            }
            let leaf = leaf_cstring(&name, &entry)?;

            // `AT_SYMLINK_NOFOLLOW`, so a symlink is typed as a symlink rather
            // than as whatever it points at.
            let meta = fs::statat(dir, &leaf, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|errno| ProvisionError::io("reading", &entry, errno.into()))?;
            let kind = fs::FileType::from_raw_mode(meta.st_mode);
            if kind == fs::FileType::Directory {
                // `O_NOFOLLOW` as well as `O_DIRECTORY`: an entry that became a
                // symlink between the stat above and this open is refused here
                // rather than descended through. Opened before the frame, so
                // the attributes it announces are the directory's own.
                let child = openat_nofollow(dir, &leaf, OFlags::DIRECTORY, &entry)?;
                let attributes = self.attributes(Holder::Fd(child.as_fd()), kind, &meta, &entry)?;
                self.emit_named(stream, COPY_DIR, &name, &meta, attributes.mode, &entry)?;
                let restore = self.prefix.len();
                self.prefix.extend_from_slice(&name);
                self.prefix.push(b'/');
                self.dir(stream, child.as_fd(), &entry, depth + 1)?;
                self.prefix.truncate(restore);
                put(stream, &[COPY_LEAVE], &entry)?;
                put_attributes(stream, &attributes.carried, &entry)?;
            } else if kind == fs::FileType::RegularFile {
                if self.emit_link(stream, &name, &meta, &entry)? {
                    continue;
                }
                // Opened before the length is announced, so the descriptor the
                // bytes and the attributes come from is the file that was typed.
                let file = open_typed_file(dir, &leaf, &meta, &entry)?;
                let attributes = self.attributes(Holder::Fd(file.as_fd()), kind, &meta, &entry)?;
                let size = meta.st_size as u64;
                self.emit_named(stream, COPY_FILE, &name, &meta, attributes.mode, &entry)?;
                put(stream, &size.to_le_bytes(), &entry)?;
                stream_file(stream, file, &entry, size)?;
                put_attributes(stream, &attributes.carried, &entry)?;
            } else if kind == fs::FileType::Symlink {
                let mut buffer = [0u8; LINK_BUF];
                let read = fs::readlinkat_raw(dir, &leaf, &mut buffer[..])
                    .map_err(|errno| ProvisionError::io("reading", &entry, errno.into()))?;
                // `readlinkat` truncates a target too long for the buffer and
                // reports the truncated length as a success, so a full buffer is
                // the only signal there is: a target that fills it is refused
                // rather than copied as a link pointing somewhere else.
                if read == buffer.len() {
                    return Err(ProvisionError::EntryRefused {
                        path: entry,
                        reason: "the symlink target is longer than a frame can carry".to_string(),
                    });
                }
                let target = &buffer[..read];
                // Nothing a link holds can be carried; this names what it held.
                let path = by_path(dir, &name, &entry)?;
                self.attributes(Holder::Path(&path), kind, &meta, &entry)?;
                self.emit_named(stream, COPY_SYMLINK, &name, &meta, None, &entry)?;
                put_bytes_u16(stream, target, &entry)?;
            } else if kind == fs::FileType::Fifo {
                // A named pipe is an ordinary unprivileged creation, so the
                // copy makes one rather than dropping it: a tree that ships a
                // FIFO meant to ship it. Its attributes are read by name, since
                // opening it would wake a writer waiting on its other end.
                let path = by_path(dir, &name, &entry)?;
                let attributes = self.attributes(Holder::Path(&path), kind, &meta, &entry)?;
                self.emit_named(stream, COPY_FIFO, &name, &meta, attributes.mode, &entry)?;
                put_attributes(stream, &attributes.carried, &entry)?;
            } else {
                let skipped = match kind {
                    fs::FileType::CharacterDevice => SkippedKind::CharacterDevice,
                    fs::FileType::BlockDevice => SkippedKind::BlockDevice,
                    _ => SkippedKind::Socket,
                };
                self.report.skipped.push(SkippedEntry {
                    path: entry,
                    kind: skipped,
                });
            }
        }
        Ok(())
    }

    /// Emits a [`COPY_LINK`] frame when this file has already been copied
    /// under another name, and reports whether it did.
    ///
    /// A file with one link is never recorded: the table would then hold every
    /// regular file in the tree to answer a question that can only be no.
    ///
    /// The device and inode widths are the architecture's; see
    /// [`emit_named`](Self::emit_named).
    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    fn emit_link(
        &mut self,
        stream: BorrowedFd<'_>,
        name: &[u8],
        meta: &fs::Stat,
        path: &Path,
    ) -> Result<bool, ProvisionError> {
        if meta.st_nlink <= 1 {
            return Ok(false);
        }
        let key = (meta.st_dev as u64, meta.st_ino as u64);
        if let Some(anchor) = self.links.get(&key) {
            put(stream, &[COPY_LINK], path)?;
            put_bytes_u16(stream, name, path)?;
            put_bytes_u16(stream, anchor, path)?;
            return Ok(true);
        }

        let mut anchor = self.prefix.clone();
        anchor.extend_from_slice(name);
        // The child resolves the anchor into a fixed buffer, so a path it
        // could not hold is refused here, with the path that carries it.
        if anchor.len() > LINK_BUF {
            return Err(ProvisionError::EntryRefused {
                path: path.to_path_buf(),
                reason: "the path of a multiply-linked file is longer than a frame can carry"
                    .to_string(),
            });
        }
        self.links.insert(key, anchor);
        Ok(false)
    }

    /// Reads the attributes of the entry `holder` reaches, a `kind` typed as
    /// `meta`, and judges them ([`judge`]), adding what is left off to the
    /// report.
    fn attributes(
        &mut self,
        holder: Holder<'_>,
        kind: fs::FileType,
        meta: &fs::Stat,
        path: &Path,
    ) -> Result<Attributes, ProvisionError> {
        let read = xattr::read_all(holder).map_err(|errno| {
            ProvisionError::io("reading the extended attributes of", path, errno.into())
        })?;
        let (attributes, skipped) = judge(read, kind, meta.st_mode & 0o7777, self.ids);
        self.report
            .attributes
            .extend(skipped.into_iter().map(|(name, reason)| SkippedAttribute {
                path: path.to_path_buf(),
                name: OsString::from_vec(name),
                reason,
            }));
        Ok(attributes)
    }

    /// Emits a frame's tag, name, and metadata block, with `mode` in place of
    /// the entry's own where one is given.
    ///
    /// A `stat`'s field widths are the architecture's own — `st_nlink` is 32
    /// bits on some and 64 on others, and the time fields likewise — so the
    /// conversions to the frame's fixed widths are the identity on one target
    /// and a widening on another. `allow` rather than `expect`, for the reason
    /// the export's link count carries: an expectation of either lint is
    /// fulfilled on some targets and not others, and an unfulfilled one fails
    /// the clippy job there.
    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    fn emit_named(
        &self,
        stream: BorrowedFd<'_>,
        tag: u8,
        name: &[u8],
        meta: &fs::Stat,
        mode: Option<u32>,
        path: &Path,
    ) -> Result<(), ProvisionError> {
        let mode = mode.unwrap_or(meta.st_mode as u32);
        put(stream, &[tag], path)?;
        put_bytes_u16(stream, name, path)?;
        put(stream, &mode.to_le_bytes(), path)?;
        put(
            stream,
            &self.ids.uid(meta.st_uid, path)?.to_le_bytes(),
            path,
        )?;
        put(
            stream,
            &self.ids.gid(meta.st_gid, path)?.to_le_bytes(),
            path,
        )?;
        put(stream, &(meta.st_mtime as i64).to_le_bytes(), path)
    }
}

/// What an entry's extended attributes come to in the copy.
struct Attributes {
    /// The attributes the child gives the entry, by name and in name order,
    /// each restated for the map.
    carried: Named,
    /// The permission bits to give the entry in place of its own, where its
    /// access control list could not be carried and its narrowing stands in.
    mode: Option<u32>,
}

/// Judges each attribute `read` off an entry of `kind` at `mode`: given to the
/// copy, restated for the map `ids` where it names an id, or left off, with
/// the reason, in the second list.
///
/// What is given is the attributes the sandbox's root can set: `user.` ones,
/// access control lists, and a capability, which only the kinds that can hold
/// them carry. One the host assigned is left out unreported, as an export
/// leaves it out ([`containment::host_assigned_xattr`]). Everything else is
/// [`AttributeSkip::Unsettable`]. A list or a capability naming an id the map
/// has no inside id for is [`AttributeSkip::UnmappedId`]; such an access list
/// narrows the mode the entry is given instead, and such a default list is
/// replaced by its narrowing, so nothing lands more open than the source.
fn judge(
    read: Named,
    kind: fs::FileType,
    mode: u32,
    ids: &Translation,
) -> (Attributes, Vec<(Vec<u8>, AttributeSkip)>) {
    let mut attributes = Attributes {
        carried: Vec::new(),
        mode: None,
    };
    let mut skipped = Vec::new();
    for (name, value) in read {
        if containment::host_assigned_xattr(&name) {
            continue;
        }
        let is = |known: &CStr| name == known.to_bytes();
        let fate = if kind == fs::FileType::Symlink
            || name.len() > XATTR_NAME_MAX
            || value.len() > XATTR_SIZE_MAX
        {
            Err(AttributeSkip::Unsettable)
        } else if name.starts_with(b"user.") {
            Ok(value)
        } else if is(xattr::ACCESS_ACL) || is(xattr::DEFAULT_ACL) {
            match Acl::parse(&value) {
                None => Err(AttributeSkip::Unsettable),
                Some(acl) => match acl.mapped(|id| ids.maps_uid(id), |id| ids.maps_gid(id)) {
                    Some(mapped) => Ok(mapped.encode()),
                    None => {
                        let narrowed = acl.narrowed();
                        if is(xattr::ACCESS_ACL) {
                            attributes.mode = Some(narrowed.mode_of(mode));
                        } else {
                            attributes.carried.push((name.clone(), narrowed.encode()));
                        }
                        Err(AttributeSkip::UnmappedId)
                    }
                },
            }
        } else if is(xattr::CAPABILITY) {
            match xattr::capability_mapped(&value, |id| ids.maps_uid(id)) {
                Restated::Value(value) => Ok(value),
                Restated::Unmapped => Err(AttributeSkip::UnmappedId),
                Restated::Malformed => Err(AttributeSkip::Unsettable),
            }
        } else {
            Err(AttributeSkip::Unsettable)
        };
        match fate {
            Ok(value) => attributes.carried.push((name, value)),
            Err(reason) => skipped.push((name, reason)),
        }
    }
    attributes.carried.sort();
    (attributes, skipped)
}

/// Writes an attribute block: the count, then each name and value, each led by
/// its length. See the copy-in child's frame protocol.
fn put_attributes(
    stream: BorrowedFd<'_>,
    attributes: &[(Vec<u8>, Vec<u8>)],
    path: &Path,
) -> Result<(), ProvisionError> {
    let count = u16::try_from(attributes.len()).map_err(|_| ProvisionError::EntryRefused {
        path: path.to_path_buf(),
        reason: "the entry carries more extended attributes than a frame can".to_string(),
    })?;
    put(stream, &count.to_le_bytes(), path)?;
    for (name, value) in attributes {
        put_bytes_u16(stream, name, path)?;
        put(stream, &(value.len() as u32).to_le_bytes(), path)?;
        put(stream, value, path)?;
    }
    Ok(())
}

/// The path that names the entry `name` of `dir` without following a link at
/// it, for a call that takes a path where the walk holds a descriptor: the
/// `proc` entry for the directory's descriptor, then the name.
///
/// The directory is the one the walk holds open, whatever its own path is now,
/// and the name is resolved in it as every other step of the walk resolves
/// one. It is how a symbolic link's or a named pipe's attributes are asked
/// for, since neither can be opened to be asked through a descriptor.
fn by_path(dir: BorrowedFd<'_>, name: &[u8], subject: &Path) -> Result<CString, ProvisionError> {
    let mut path = format!("/proc/self/fd/{}/", dir.as_raw_fd()).into_bytes();
    path.extend_from_slice(name);
    CString::new(path).map_err(|_| ProvisionError::EntryRefused {
        path: subject.to_path_buf(),
        reason: "the entry name carries a NUL".to_string(),
    })
}

/// The map, read backwards: host id to the id inside the rootfs.
///
/// The source tree's ownership is read through the identity map, which is what
/// makes a copy the exact mirror of an export. An export forks a child into the
/// map so a file the host stores at `100000 + 42` reads as uid 42, the id the
/// tree means; a copy takes the id the tree means and stores it back at the
/// host id the map puts it at. So a tree an earlier mapped sandbox produced
/// copies into a rootfs owned through the same map with its ownership intact —
/// which is what a caller wants from a copy and what `cp` running outside the
/// map cannot do.
///
/// Reading the host id as an *inside* id instead would make the common cases
/// wrong in both directions: a subordinate tree's `100042` is not an id any
/// rootfs holds, and a caller's own tree could never name a system id at all,
/// since an unprivileged process cannot create a file owned by one.
///
/// The single map falls out of the same rule rather than needing a case of its
/// own: it maps inside 0 to the calling user, so a caller-owned source lands as
/// root — what a single-mapped sandbox sees, and what it could have written
/// itself.
///
/// The extractor reads it forwards, with `host_uid` and `host_gid`: an access
/// control list an export wrote names the ids the root means, and the
/// extraction writes as the calling user outside the map.
pub(super) struct Translation {
    uid: Vec<IdRange>,
    gid: Vec<IdRange>,
}

impl Translation {
    /// The extents the map `ownership` names establishes, or why they cannot be
    /// resolved.
    #[cfg(feature = "tarball")]
    pub(super) fn of_ownership(ownership: &Ownership) -> Result<Translation, String> {
        Ok(Translation::of(&ownership.child_map()?.child_map()))
    }

    /// The extents the child's map establishes.
    pub(super) fn of(map: &ChildMap<'_>) -> Translation {
        match map {
            // The one-id map the child writes itself: the calling user is root
            // inside and nothing else is mapped.
            ChildMap::SelfMap { .. } => {
                let one = |outside| {
                    vec![IdRange {
                        inside: 0,
                        outside,
                        count: 1,
                    }]
                };
                Translation {
                    uid: one(rustix::process::geteuid().as_raw()),
                    gid: one(rustix::process::getegid().as_raw()),
                }
            }
            ChildMap::Delegated { map, .. } => Translation {
                uid: map.uid().to_vec(),
                gid: map.gid().to_vec(),
            },
        }
    }

    /// The inside uid a host uid stands for.
    fn uid(&self, host: u32, path: &Path) -> Result<u32, ProvisionError> {
        inside(&self.uid, host, "uid", path)
    }

    /// The inside gid a host gid stands for.
    fn gid(&self, host: u32, path: &Path) -> Result<u32, ProvisionError> {
        inside(&self.gid, host, "gid", path)
    }

    /// The inside uid a host uid stands for, where the map has one.
    fn maps_uid(&self, host: u32) -> Option<u32> {
        located(&self.uid, host).and_then(|mapped| u32::try_from(mapped).ok())
    }

    /// The inside gid a host gid stands for, where the map has one.
    fn maps_gid(&self, host: u32) -> Option<u32> {
        located(&self.gid, host).and_then(|mapped| u32::try_from(mapped).ok())
    }

    /// Whether the map holds the inside uid `inside`.
    pub(super) fn holds_uid(&self, inside: u32) -> bool {
        holds(&self.uid, inside)
    }

    /// The host uid the inside uid `inside` is, where the map holds it.
    #[cfg(feature = "tarball")]
    pub(super) fn host_uid(&self, inside: u32) -> Option<u32> {
        on_host(&self.uid, inside)
    }

    /// The host gid the inside gid `inside` is, where the map holds it.
    #[cfg(feature = "tarball")]
    pub(super) fn host_gid(&self, inside: u32) -> Option<u32> {
        on_host(&self.gid, inside)
    }

    /// Whether the map holds the inside gid `inside`.
    pub(super) fn holds_gid(&self, inside: u32) -> bool {
        holds(&self.gid, inside)
    }
}

/// The inside id the extent covering `host` maps it to, widened so it cannot
/// wrap; `None` where no extent covers it.
fn located(extents: &[IdRange], host: u32) -> Option<u64> {
    extents.iter().find_map(|extent| {
        let outside = u64::from(extent.outside);
        let end = outside + u64::from(extent.count);
        (u64::from(host) >= outside && u64::from(host) < end)
            .then(|| u64::from(extent.inside) + (u64::from(host) - outside))
    })
}

/// The host id the extent covering the inside id `inside` maps it to, `None`
/// where no extent covers it or the id it maps to is past what the kernel
/// names.
#[cfg(feature = "tarball")]
fn on_host(extents: &[IdRange], inside: u32) -> Option<u32> {
    extents.iter().find_map(|extent| {
        let start = u64::from(extent.inside);
        let id = u64::from(inside);
        (start..start + u64::from(extent.count))
            .contains(&id)
            .then(|| u64::from(extent.outside) + (id - start))
            .and_then(|host| u32::try_from(host).ok())
    })
}

/// Whether an extent maps the inside id `inside` to a host id, so that a
/// `chown` to it from inside the map can succeed.
fn holds(extents: &[IdRange], inside: u32) -> bool {
    extents.iter().any(|extent| {
        let start = u64::from(extent.inside);
        (start..start + u64::from(extent.count)).contains(&u64::from(inside))
    })
}

/// Finds the inside id `host` falls to, refusing one no extent covers.
///
/// A host id outside every extent is one the rootfs cannot hold, and the copy
/// says so with the path that carries it rather than letting the child fail
/// with an `EINVAL` naming nothing.
///
/// The whole calculation runs in `u64`. An extent is three `u32`s, so both the
/// containment test and the id it produces can pass `u32::MAX` — a wrapped id in
/// a release build, a panic in a debug one — and an id is only an id once it
/// fits back in the width the kernel names it in.
fn inside(extents: &[IdRange], host: u32, which: &str, path: &Path) -> Result<u32, ProvisionError> {
    let refuse = |reason: String| {
        Err(ProvisionError::EntryRefused {
            path: path.to_path_buf(),
            reason,
        })
    };
    match located(extents, host) {
        Some(mapped) => match u32::try_from(mapped) {
            Ok(inside) => Ok(inside),
            Err(_) => refuse(format!(
                "the source entry's {which} {host} maps to {mapped}, which is past the largest \
                 id the kernel names",
            )),
        },
        None => refuse(format!(
            "the source entry's {which} {host} is outside the identity map, so the rootfs \
             has no id for it",
        )),
    }
}

/// Opens the source tree's root as the directory the walk reads from.
///
/// The path is the caller's own, so a symbolic link at its final component is
/// followed, as one at any earlier component is: a source named through a link
/// copies the directory the link names. No link *inside* the tree is followed;
/// every entry below is resolved against a directory the walk holds open.
///
/// The open is also the check that the source is a directory, made before
/// anything is forked. It is one resolution, so the directory checked is the
/// directory read.
fn open_source(source: &Path) -> Result<OwnedFd, ProvisionError> {
    fs::open(
        source,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        fs::Mode::empty(),
    )
    .map_err(|errno| ProvisionError::io("copying", source, errno.into()))
}

/// Opens the regular file `name` under `dir` that the walk typed as `typed`,
/// through [`containment::open_typed_file`]: without waiting, and refusing a
/// name that no longer holds that file as a source that changed underneath the
/// copy.
fn open_typed_file(
    dir: BorrowedFd<'_>,
    name: &CStr,
    typed: &fs::Stat,
    subject: &Path,
) -> Result<OwnedFd, ProvisionError> {
    containment::open_typed_file(dir, name, typed, OFlags::RDONLY).map_err(|errno| match errno {
        rustix::io::Errno::STALE => ProvisionError::SourceChanged {
            path: subject.to_path_buf(),
            recorded: typed.st_size as u64,
        },
        errno => ProvisionError::io("reading", subject, errno.into()),
    })
}

/// Opens `name` under `dir`, following no symbolic link at it.
///
/// `extra` carries `O_DIRECTORY` where a directory is what was typed, so an
/// entry that has since become something else is refused by the kernel rather
/// than read as whatever it now is.
fn openat_nofollow(
    dir: BorrowedFd<'_>,
    name: &CStr,
    extra: OFlags,
    subject: &Path,
) -> Result<OwnedFd, ProvisionError> {
    fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | extra,
        fs::Mode::empty(),
    )
    .map_err(|errno| ProvisionError::io("reading", subject, errno.into()))
}

/// Every entry name `dir` holds, `.` and `..` left out.
///
/// Read from a descriptor rather than from a path, so the directory listed is
/// the directory the walk holds open. `subject` names it in a failure. The
/// pre-configure overlay's walk lists its source directories through this too.
pub(super) fn read_names(
    dir: BorrowedFd<'_>,
    subject: &Path,
) -> Result<Vec<Vec<u8>>, ProvisionError> {
    // A `Dir` consumes its descriptor's offset, so it is handed one of its own,
    // `.` opened relative to the walk's: the caller goes on resolving every
    // entry against the descriptor it already holds.
    let handle = openat_nofollow(dir, c".", OFlags::DIRECTORY, subject)?;
    let mut names = Vec::new();
    for entry in fs::Dir::new(handle)
        .map_err(|errno| ProvisionError::io("reading", subject, errno.into()))?
    {
        let entry = entry.map_err(|errno| ProvisionError::io("reading", subject, errno.into()))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push(name.to_vec());
    }
    Ok(names)
}

/// An entry's name as a `CStr`, for the `*at` calls that resolve it.
///
/// The component check above has already refused a name carrying a NUL, so this
/// is the boundary the bytes cross rather than the rule they are held to.
fn leaf_cstring(name: &[u8], subject: &Path) -> Result<CString, ProvisionError> {
    CString::new(name).map_err(|_| ProvisionError::EntryRefused {
        path: subject.to_path_buf(),
        reason: "the entry name carries a NUL".to_string(),
    })
}

/// Streams exactly `size` bytes of `path` to the child, and refuses to call a
/// file that changed underneath it copied.
///
/// The frame's declared length is committed before any data is read, so a file
/// that grew or shrank in between cannot be sent faithfully. The frame is
/// finished either way, by [`frame::stream_exact`], and only then is the
/// mismatch reported.
///
/// The frame is honored and the copy still fails, because those are answers to
/// different questions. Keeping the stream in step is what lets the failure be
/// reported at all rather than as a desynchronized child; it is not a reason to
/// hand back a rootfs holding a zero-padded binary and call it a copy.
fn stream_file(
    stream: BorrowedFd<'_>,
    file: OwnedFd,
    path: &Path,
    size: u64,
) -> Result<(), ProvisionError> {
    let changed =
        frame::stream_exact(file.as_fd(), stream, size, Holes::Runs).map_err(|failure| {
            match failure {
                StreamFailure::File(errno) => ProvisionError::io("reading", path, errno.into()),
                StreamFailure::Stream(errno) => ProvisionError::io("copying", path, errno.into()),
            }
        })?;
    if changed {
        return Err(ProvisionError::SourceChanged {
            path: path.to_path_buf(),
            recorded: size,
        });
    }
    Ok(())
}

/// Writes `data` in full to the child's stream, blaming `path` for a failure.
///
/// The child is the only thing that can end the write early, and its outcome
/// record says why; this reports the broken pipe and lets `finish` supply the
/// reason.
fn put(stream: BorrowedFd<'_>, data: &[u8], path: &Path) -> Result<(), ProvisionError> {
    frame::write_full(stream, data)
        .map_err(|errno| ProvisionError::io("copying", path, errno.into()))
}

/// Writes a `u16`-length-prefixed byte string to the child's stream, through
/// [`frame::write_bytes_u16`], blaming `path` for a failure.
///
/// Every caller has refused already what a frame cannot carry, so a string too
/// long for its prefix does not reach here. Were one to, it would be refused
/// with `ERANGE` rather than sent under a length cut to fit, which would
/// declare a different string and leave every later frame out of step.
fn put_bytes_u16(stream: BorrowedFd<'_>, data: &[u8], path: &Path) -> Result<(), ProvisionError> {
    frame::write_bytes_u16(stream, data)
        .map_err(|errno| ProvisionError::io("copying", path, errno.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    /// Streams `path` at a declared `size` into a throwaway pipe and reports
    /// what the copy made of it.
    ///
    /// The declared size is what the frame committed, so passing one that does
    /// not match the file reproduces exactly the race the walk loses — a source
    /// that changed between the stat and the read — without having to win it.
    /// The sizes stay well under a pipe's capacity, so nothing has to drain the
    /// read end.
    fn stream_at(path: &Path, size: u64) -> Result<(), ProvisionError> {
        let (read, write) = rustix::pipe::pipe().expect("a pipe is creatable");
        // Opened as the walk opens one: the descriptor is what the data comes
        // from, so the file streamed is the file that was typed.
        let file = std::fs::File::open(path).expect("the fixture opens");
        let outcome = stream_file(write.as_fd(), OwnedFd::from(file), path, size);
        drop((read, write));
        outcome
    }

    #[test]
    fn an_entry_is_resolved_against_its_directory_and_never_through_a_symlink() {
        // The walk types an entry and then reads, opens, or descends into it.
        // Resolving the name afresh at each step follows whatever is at the
        // path by then, so an entry swapped for a symlink between the two is
        // traversed -- a directory descended out of the source, or a file
        // streamed from wherever the link points. Every step resolves against
        // the descriptor of the directory holding the name instead, and refuses
        // a symlink at it.
        let dir = Scratch::new("copyin-nofollow");
        std::fs::create_dir_all(dir.join("outside")).unwrap();
        std::fs::write(dir.join("outside/secret"), b"not the source's").unwrap();
        std::fs::create_dir_all(dir.join("source")).unwrap();
        std::fs::write(dir.join("source/own"), b"the source's own").unwrap();
        std::os::unix::fs::symlink(dir.join("outside"), dir.join("source/as-dir")).unwrap();
        std::os::unix::fs::symlink(dir.join("outside/secret"), dir.join("source/as-file")).unwrap();

        let source = open_source(&dir.join("source")).expect("the source opens");
        for (name, extra) in [
            (c"as-dir", OFlags::DIRECTORY),
            (c"as-file", OFlags::empty()),
        ] {
            assert!(
                openat_nofollow(source.as_fd(), name, extra, &dir).is_err(),
                "{name:?} was opened through a symlink",
            );
        }
        // What is not a symlink still opens, so the refusal is the link's doing.
        openat_nofollow(source.as_fd(), c"own", OFlags::empty(), &dir)
            .expect("an ordinary file opens");

        // And the listing comes from the descriptor: a source directory
        // replaced by a symlink after it was opened is not what gets listed.
        let mut names = read_names(source.as_fd(), &dir).expect("the source lists");
        names.sort();
        assert_eq!(
            names,
            [b"as-dir".to_vec(), b"as-file".to_vec(), b"own".to_vec()]
        );
        std::fs::remove_file(dir.join("source/own")).unwrap();
        std::fs::remove_file(dir.join("source/as-dir")).unwrap();
        std::fs::remove_file(dir.join("source/as-file")).unwrap();
        std::fs::remove_dir(dir.join("source")).unwrap();
        std::os::unix::fs::symlink(dir.join("outside"), dir.join("source")).unwrap();
        assert_eq!(
            read_names(source.as_fd(), &dir).expect("the held directory still lists"),
            Vec::<Vec<u8>>::new(),
            "the descriptor lists the directory it opened, not the path's new target",
        );
    }

    #[test]
    fn the_source_root_is_followed_and_the_tree_below_it_is_not() {
        // The source path is the caller's own, so a link naming it is followed
        // to the directory it names; a file is refused at the same open, before
        // anything is forked.
        let dir = Scratch::new("copyin-source-root");
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::fs::write(dir.join("real/entry"), b"x").unwrap();
        std::os::unix::fs::symlink("real", dir.join("named-through")).unwrap();
        std::fs::write(dir.join("a-file"), b"not a tree").unwrap();

        let root = open_source(&dir.join("named-through")).expect("the link is followed");
        assert_eq!(
            read_names(root.as_fd(), &dir).expect("the source lists"),
            [b"entry".to_vec()],
        );
        let err = open_source(&dir.join("a-file")).expect_err("a file is not a source tree");
        assert!(
            matches!(&err, ProvisionError::Io { source, .. }
                if source.raw_os_error() == Some(rustix::io::Errno::NOTDIR.raw_os_error())),
            "{err}",
        );
    }

    #[test]
    fn a_name_that_stopped_holding_the_file_typed_is_refused_without_waiting() {
        // The walk types an entry, then opens it to stream it. A named pipe put
        // at the name in between would hold a blocking open until something
        // wrote to it, and another file would be streamed under the first one's
        // metadata. Both are refused at once as a source that changed.
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = Scratch::new("copyin-typed");
        let source = open_source(&dir).expect("the scratch directory opens");
        let typed = |name: &CStr| {
            fs::statat(source.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW).expect("the entry stats")
        };

        std::fs::write(dir.join("intact"), b"x").unwrap();
        let intact = typed(c"intact");
        open_typed_file(source.as_fd(), c"intact", &intact, &dir).expect("the file opens");

        std::fs::write(dir.join("piped"), b"x").unwrap();
        let piped = typed(c"piped");
        std::fs::remove_file(dir.join("piped")).unwrap();
        fs::mknodat(
            source.as_fd(),
            c"piped",
            fs::FileType::Fifo,
            fs::Mode::RUSR,
            0,
        )
        .unwrap();
        let (sent, received) = mpsc::channel();
        let pipe_dir = dir.to_path_buf();
        std::thread::spawn(move || {
            let source = open_source(&pipe_dir).expect("the scratch directory opens");
            let _ = sent.send(open_typed_file(source.as_fd(), c"piped", &piped, &pipe_dir));
        });
        let outcome = received
            .recv_timeout(Duration::from_secs(10))
            .expect("the open waited on the named pipe");
        assert!(
            matches!(outcome, Err(ProvisionError::SourceChanged { .. })),
            "{outcome:?}",
        );

        // The replacement exists before the original goes, so it cannot be
        // given the original's freed inode number.
        std::fs::write(dir.join("swapped"), b"x").unwrap();
        let swapped = typed(c"swapped");
        std::fs::write(dir.join("replacement"), b"another file").unwrap();
        std::fs::rename(dir.join("replacement"), dir.join("swapped")).unwrap();
        assert!(
            matches!(
                open_typed_file(source.as_fd(), c"swapped", &swapped, &dir),
                Err(ProvisionError::SourceChanged { .. })
            ),
            "a different file was opened under the typed one's metadata",
        );
    }

    #[test]
    fn a_file_matching_its_recorded_size_streams_cleanly() {
        let dir = Scratch::new("copyin-intact");
        let path = dir.join("file");
        std::fs::write(&path, b"exactly this").unwrap();
        stream_at(&path, 12).expect("an unchanged file copies");
    }

    #[test]
    fn a_file_shorter_than_its_recorded_size_is_padded_and_refused() {
        // The padding keeps the frame the length the child is counting on, and
        // the refusal is what stops a zero-padded binary being reported as a
        // copy. Both, not either.
        let dir = Scratch::new("copyin-short");
        let path = dir.join("file");
        std::fs::write(&path, b"short").unwrap();
        match stream_at(&path, 4096) {
            Err(ProvisionError::SourceChanged {
                path: changed,
                recorded,
            }) => {
                assert_eq!(changed, path);
                assert_eq!(recorded, 4096, "the frame's committed length is reported");
            }
            other => panic!("expected a source-changed refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_file_longer_than_its_recorded_size_is_refused_too() {
        // The grown case truncates rather than pads, and was the quieter of the
        // two: the loop simply stops at the declared length with nothing to
        // notice. One read past the end is what notices.
        let dir = Scratch::new("copyin-grown");
        let path = dir.join("file");
        std::fs::write(&path, b"much more than was recorded").unwrap();
        match stream_at(&path, 4) {
            Err(ProvisionError::SourceChanged { recorded, .. }) => assert_eq!(recorded, 4),
            other => panic!("expected a source-changed refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_owner_the_map_cannot_express_is_passed_over_or_refused_by_where_it_came_from() {
        // Under the single-identity map only root exists. A base's host id the
        // map has no inside id for leaves the entry as its carry left it, which
        // is that map's documented limit; an id a package states for the tree
        // is refused, naming the entry, since nothing else could give it. Both
        // are settled before anything is forked.
        let root = Scratch::new("copyin-reown-unheld");
        let owed = |owner| Owed {
            path: b"usr/libexec/helper".to_vec(),
            owner,
            dev: 0,
            ino: 0,
        };
        let host = owed(Owner::Host {
            uid: u32::MAX - 1,
            gid: u32::MAX - 1,
        });
        assert!(reown(&root, &[host], &Ownership::default()).is_ok());

        let tree = owed(Owner::Tree { uid: 0, gid: 101 });
        match reown(&root, &[tree], &Ownership::default()) {
            Err(ProvisionError::EntryRefused { path, reason }) => {
                assert_eq!(path, root.join("usr/libexec/helper"));
                assert!(reason.contains("0:101"), "{reason}");
            }
            other => panic!("expected the entry refused, got {other:?}"),
        }
    }

    #[test]
    fn a_host_id_maps_back_through_the_extent_that_covers_it() {
        // The ordinary reading: a subordinate tree's 100042 is uid 42 inside,
        // and a host id no extent covers is one the rootfs has no name for.
        let extents = [IdRange {
            inside: 0,
            outside: 100_000,
            count: 65_536,
        }];
        let path = Path::new("/src/file");
        assert_eq!(inside(&extents, 100_042, "uid", path).unwrap(), 42);
        assert_eq!(inside(&extents, 100_000, "uid", path).unwrap(), 0);
        // The extent is half-open: its last id maps, the one past it does not.
        assert_eq!(inside(&extents, 165_535, "uid", path).unwrap(), 65_535);
        let err = inside(&extents, 165_536, "uid", path).unwrap_err();
        assert!(
            err.to_string().contains("outside the identity map"),
            "{err}"
        );
    }

    #[test]
    fn a_mapped_id_that_would_not_fit_a_u32_is_refused_rather_than_wrapped() {
        // An extent is three `u32`s, so `inside + count` can pass `u32::MAX`.
        // Computed in `u32` the sum wraps in a release build and panics in a
        // debug one; computed in `u64` it is simply an id the kernel cannot
        // name, and the copy says so with the path that carries it.
        let extents = [IdRange {
            inside: u32::MAX - 1,
            outside: 1_000,
            count: 10,
        }];
        let path = Path::new("/src/file");
        // Still within `u32`: the last id that fits maps.
        assert_eq!(inside(&extents, 1_001, "uid", path).unwrap(), u32::MAX);
        let err = inside(&extents, 1_002, "gid", path).unwrap_err();
        assert!(
            err.to_string().contains("largest id the kernel names"),
            "{err}",
        );
    }

    /// An access control list value from `(tag, perm, id)` triples.
    fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut value = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            value.extend_from_slice(&tag.to_le_bytes());
            value.extend_from_slice(&perm.to_le_bytes());
            value.extend_from_slice(&id.to_le_bytes());
        }
        value
    }

    /// A capability value of `revision` granting `CAP_NET_RAW`, rooted at
    /// `root` where the revision names one.
    fn capability(revision: u8, root: Option<u32>) -> Vec<u8> {
        let mut value = vec![1, 0, 0, revision];
        value.extend_from_slice(&[0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        if let Some(root) = root {
            value.extend_from_slice(&root.to_le_bytes());
        }
        value
    }

    #[test]
    fn each_attribute_is_carried_restated_or_reported() {
        // A subordinate map: inside 0 is host 100000.
        let extent = vec![IdRange {
            inside: 0,
            outside: 100_000,
            count: 65_536,
        }];
        let ids = Translation {
            uid: extent.clone(),
            gid: extent,
        };
        const NONE: u32 = u32::MAX;
        let masked = |named: u32| {
            acl(&[
                (0x01, 6, NONE),
                (0x02, 6, named),
                (0x04, 0, NONE),
                (0x10, 6, NONE),
                (0x20, 0, NONE),
            ])
        };
        let read: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (
                b"security.selinux".to_vec(),
                b"system_u:object_r:etc_t:s0".to_vec(),
            ),
            (b"user.overlay.opaque".to_vec(), b"y".to_vec()),
            (b"user.comment".to_vec(), b"kept".to_vec()),
            (b"trusted.md5".to_vec(), b"x".to_vec()),
            (b"security.SMACK64".to_vec(), b"_".to_vec()),
            (b"security.other".to_vec(), b"x".to_vec()),
            (b"system.nfs4_acl".to_vec(), b"x".to_vec()),
            (b"system.posix_acl_access".to_vec(), masked(5)),
            (
                b"security.capability".to_vec(),
                capability(3, Some(100_000)),
            ),
        ];
        let (attributes, skipped) = judge(read, fs::FileType::RegularFile, 0o4660, &ids);

        // The user attribute as it stands, and the capability rooted at the
        // map's root inside. The host's own labels and the overlay's
        // bookkeeping are left out unreported.
        assert_eq!(
            attributes.carried,
            vec![
                (b"security.capability".to_vec(), capability(3, Some(0))),
                (b"user.comment".to_vec(), b"kept".to_vec()),
            ],
        );
        // The access list names host uid 5, which the map has no inside id
        // for. It is reported, and the owning group keeps the `---` the list
        // gave it rather than the mask the mode shows.
        assert_eq!(attributes.mode, Some(0o4600));
        let reasons: Vec<(&[u8], AttributeSkip)> = skipped
            .iter()
            .map(|(name, reason)| (name.as_slice(), *reason))
            .collect();
        assert_eq!(
            reasons,
            vec![
                (&b"trusted.md5"[..], AttributeSkip::Unsettable),
                (b"security.other", AttributeSkip::Unsettable),
                (b"system.nfs4_acl", AttributeSkip::Unsettable),
                (b"system.posix_acl_access", AttributeSkip::UnmappedId),
            ],
        );

        // A list the map can name lands naming the inside id.
        let (attributes, skipped) = judge(
            vec![
                (b"system.posix_acl_access".to_vec(), masked(100_042)),
                (b"system.posix_acl_default".to_vec(), masked(100_042)),
            ],
            fs::FileType::Directory,
            0o770,
            &ids,
        );
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(attributes.mode, None);
        assert_eq!(
            attributes.carried,
            vec![
                (b"system.posix_acl_access".to_vec(), masked(42)),
                (b"system.posix_acl_default".to_vec(), masked(42)),
            ],
        );

        // A default list the map cannot name is replaced by its narrowing, so
        // what the directory's new entries inherit is no more open than it
        // was; a capability rooted outside the map, or of a revision the
        // kernel will not store, is left off.
        let (attributes, skipped) = judge(
            vec![
                (b"security.capability".to_vec(), capability(3, Some(7))),
                (b"system.posix_acl_default".to_vec(), masked(5)),
            ],
            fs::FileType::Directory,
            0o770,
            &ids,
        );
        assert_eq!(
            attributes.carried,
            vec![(
                b"system.posix_acl_default".to_vec(),
                acl(&[(0x01, 6, NONE), (0x04, 0, NONE), (0x20, 0, NONE)]),
            )],
        );
        assert_eq!(
            skipped,
            vec![
                (b"security.capability".to_vec(), AttributeSkip::UnmappedId),
                (
                    b"system.posix_acl_default".to_vec(),
                    AttributeSkip::UnmappedId
                ),
            ],
        );
        let (_, skipped) = judge(
            vec![(b"security.capability".to_vec(), capability(1, None))],
            fs::FileType::RegularFile,
            0o755,
            &ids,
        );
        assert_eq!(
            skipped,
            vec![(b"security.capability".to_vec(), AttributeSkip::Unsettable)]
        );

        // A link holds nothing anything unprivileged can set.
        let (attributes, skipped) = judge(
            vec![(b"trusted.link".to_vec(), b"x".to_vec())],
            fs::FileType::Symlink,
            0o777,
            &ids,
        );
        assert!(attributes.carried.is_empty());
        assert_eq!(
            skipped,
            vec![(b"trusted.link".to_vec(), AttributeSkip::Unsettable)]
        );
    }

    #[test]
    fn a_file_capability_is_copied_rooted_at_the_rootfs_root() {
        // Nothing unprivileged can give a file a capability outside a user
        // namespace, so the source is staged by the copy's own child, as the
        // namespace's root: the plain form it is handed lands rooted at the
        // namespace's root, the caller. A copy of that tree into another rootfs
        // reads the root across the map and lands it at the same place.
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        let dir = Scratch::new("copyin-capability");
        let staged = dir.join("staged");
        let rootfs = dir.join("rootfs");
        std::fs::create_dir_all(&staged).unwrap();
        std::fs::create_dir_all(&rootfs).unwrap();

        let mut frames = vec![COPY_FILE];
        frames.extend_from_slice(&4u16.to_le_bytes());
        frames.extend_from_slice(b"ping");
        frames.extend_from_slice(&0o755u32.to_le_bytes());
        frames.extend_from_slice(&0u32.to_le_bytes());
        frames.extend_from_slice(&0u32.to_le_bytes());
        frames.extend_from_slice(&0i64.to_le_bytes());
        frames.extend_from_slice(&3u64.to_le_bytes());
        frames.push(frame::RUN_DATA);
        frames.extend_from_slice(&3u64.to_le_bytes());
        frames.extend_from_slice(b"elf");
        let plain = capability(2, None);
        frames.extend_from_slice(&1u16.to_le_bytes());
        frames.extend_from_slice(&(xattr::CAPABILITY.to_bytes().len() as u16).to_le_bytes());
        frames.extend_from_slice(xattr::CAPABILITY.to_bytes());
        frames.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        frames.extend_from_slice(&plain);
        frames.push(COPY_END);
        let map = compose_child_map(&IdentityMap::Single, None).expect("the single map");
        let staged_c = CString::new(staged.as_os_str().as_bytes()).unwrap();
        let child = start_copy_in(&staged_c, map.child_map()).expect("the child starts");
        put(child.stream(), &frames, &staged).expect("the frames are sent");
        child.finish().expect("the child gives the capability");

        let held = |path: &Path| {
            let mut value = vec![0u8; 64];
            let read = rustix::fs::lgetxattr(path, xattr::CAPABILITY, &mut value[..])
                .expect("the file holds a capability");
            value.truncate(read);
            value
        };
        let caller = rustix::process::geteuid().as_raw();
        let staged_capability = held(&staged.join("ping"));
        assert_eq!(
            staged_capability,
            capability(3, Some(caller)),
            "a capability set inside a namespace is rooted at its root",
        );

        let report = CopyIn::new(&staged, &rootfs)
            .run()
            .expect("the copy succeeds");
        assert_eq!(report, CopyReport::default());
        assert_eq!(held(&rootfs.join("ping")), staged_capability);
    }

    #[test]
    fn a_sparse_file_is_copied_sparse() {
        // A sandbox makes a file eight tebibytes long with `truncate -s 8T`
        // and no data; ext4 holds a file up to a block short of sixteen.
        // Copied as the zeros it reads as, it would fill the destination's
        // disk; copied as runs, it costs its data.
        use std::os::unix::fs::{FileExt, MetadataExt};

        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        const SIZE: u64 = 8 << 40;
        let dir = Scratch::new("copyin-sparse");
        let (source, rootfs) = (dir.join("source"), dir.join("rootfs"));
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&rootfs).unwrap();
        let file = std::fs::File::create(source.join("big")).unwrap();
        file.set_len(SIZE).unwrap();
        for (at, data) in [(0, &b"head"[..]), (1 << 30, b"middle"), (SIZE - 4, b"tail")] {
            file.write_all_at(data, at).unwrap();
        }
        drop(file);
        let held = std::fs::metadata(source.join("big")).unwrap();
        if held.blocks() * 512 >= 1 << 30 {
            ferroday_cage_testkit::require::premise_unmet(
                "this filesystem keeps no holes in a sparse file",
            );
            return;
        }

        let report = CopyIn::new(&source, &rootfs)
            .run()
            .expect("the sparse file copies");
        assert_eq!(report, CopyReport::default());
        let copied = std::fs::File::open(rootfs.join("big")).unwrap();
        let meta = copied.metadata().unwrap();
        assert_eq!(meta.len(), SIZE);
        assert!(
            meta.blocks() <= held.blocks() * 2,
            "the copy holds {} blocks where the source holds {}",
            meta.blocks(),
            held.blocks(),
        );
        // Whatever either file holds as data, both read the same there; the
        // rest of each is a hole, and reads as zeros.
        let source = std::fs::File::open(source.join("big")).unwrap();
        for file in [&source, &copied] {
            let mut at = 0;
            while let Ok(start) = rustix::fs::seek(file, rustix::fs::SeekFrom::Data(at)) {
                let end = rustix::fs::seek(file, rustix::fs::SeekFrom::Hole(start)).unwrap();
                let len = usize::try_from(end - start).unwrap();
                let (mut want, mut got) = (vec![0u8; len], vec![0u8; len]);
                source.read_exact_at(&mut want, start).unwrap();
                copied.read_exact_at(&mut got, start).unwrap();
                assert!(got == want, "the bytes from {start} to {end} differ");
                at = end;
            }
        }
    }

    #[test]
    fn an_empty_file_recorded_as_empty_is_not_a_change() {
        // The zero-length case reads nothing and must not look like a file that
        // vanished: the check past the end is what tells them apart.
        let dir = Scratch::new("copyin-empty");
        let path = dir.join("file");
        std::fs::write(&path, b"").unwrap();
        stream_at(&path, 0).expect("an empty file copies");
    }
}
