//! Copying a host tree into a rootfs at the ownership the rootfs intends.
//!
//! The caller-facing half of [`mechanism::copyin`](crate::mechanism): this side
//! walks the host source with an allocator and a heap, and streams frames to
//! the in-map child that creates each entry. See that module for the frame
//! protocol and the post-fork discipline the child works under.
//!
//! Two things live here rather than in the child because they need a heap. The
//! hardlink table recognizes that two names are one file and emits the second
//! as a link onto the first, so a tree keeps the sharing it was written with —
//! the same table, and the same reason, as the export's. And the skip report
//! names every entry the copy could not create, so a rootfs that ends up
//! missing something says so.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::io::{self, Read};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{self, AtFlags, OFlags};

use super::containment;
use super::identity::compose_child_map;
use super::{Delegate, ProvisionError};
use crate::IdentityMap;
use crate::failure::ErrorChain;
use crate::idmap::{IdMapper, IdRange};
use crate::mechanism::bounds::{DATA_BUF, LINK_BUF, MAX_DEPTH, NAME_MAX};
use crate::mechanism::frame;
use crate::mechanism::{
    COPY_DIR, COPY_END, COPY_FIFO, COPY_FILE, COPY_LEAVE, COPY_LINK, COPY_SYMLINK, ChildMap,
    CopyFailure, start_copy_in,
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
/// and a file, symlink, or named pipe replaces whatever is at its own.
///
/// Directories, regular files, symbolic links, and named pipes are copied.
/// Several names for one file are copied as hard links, so a tree keeps the
/// sharing it was written with. Character and block devices and sockets cannot
/// be copied and are named in the [`CopyReport`] the run returns; see
/// [`SkippedKind`] for why each is left out.
///
/// # Example
///
/// ```no_run
/// use ferroday_cage::IdentityMap;
/// use ferroday_cage::provision::CopyIn;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let report = CopyIn::new("./overlay", "/srv/images/trixie")
///     .map(IdentityMap::Subordinate)
///     .run()?;
///
/// for entry in &report.skipped {
///     eprintln!("not copied: {} ({})", entry.path.display(), entry.kind);
/// }
/// # Ok(())
/// # }
/// ```
pub struct CopyIn {
    source: PathBuf,
    rootfs: PathBuf,
    map: IdentityMap,
    mapper: Option<Arc<dyn IdMapper>>,
}

impl fmt::Debug for CopyIn {
    /// Renders every setting, and the mapper by its presence rather than its
    /// contents: it is a caller's trait object, with nothing useful to show.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CopyIn")
            .field("source", &self.source)
            .field("rootfs", &self.rootfs)
            .field("map", &self.map)
            .field(
                "mapper",
                &self.mapper.as_ref().map(|_| Delegate("dyn IdMapper")),
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
            map: IdentityMap::Single,
            mapper: None,
        }
    }

    /// Sets the identity map the rootfs is owned through.
    ///
    /// It must be the map the rootfs was built under, for the reason an export
    /// must name the same one: the ids on the host are the rootfs's ids offset
    /// by the map, so a copy made through a different map writes ownership the
    /// rootfs will not read back as intended.
    pub fn map(mut self, map: IdentityMap) -> CopyIn {
        self.map = map;
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
    pub fn mapper(mut self, mapper: impl IdMapper + 'static) -> CopyIn {
        self.mapper = Some(Arc::new(mapper));
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
    /// the copy machinery, of the walk, or of the in-map writer.
    pub fn run(self) -> Result<CopyReport, ProvisionError> {
        copy_in_inner(&self.source, &self.rootfs, &self.map, self.mapper.as_ref())
    }
}

/// What a [`CopyIn`] run left out.
///
/// A copy that silently dropped an entry would produce a rootfs that differs
/// from the tree the caller wrote, with nothing to say so. Every source entry
/// the copy did not create is named here instead, so a caller can treat the
/// omission as a warning, as an error, or as expected.
///
/// An empty [`skipped`](Self::skipped) means the destination now holds
/// everything the source did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CopyReport {
    /// Every source entry the copy did not create, in the order the walk
    /// reached them.
    pub skipped: Vec<SkippedEntry>,
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
                self.emit_named(stream, COPY_DIR, &name, &meta, &entry)?;
                let restore = self.prefix.len();
                self.prefix.extend_from_slice(&name);
                self.prefix.push(b'/');
                // `O_NOFOLLOW` as well as `O_DIRECTORY`: an entry that became a
                // symlink between the stat above and this open is refused here
                // rather than descended through.
                let child = openat_nofollow(dir, &leaf, OFlags::DIRECTORY, &entry)?;
                self.dir(stream, child.as_fd(), &entry, depth + 1)?;
                self.prefix.truncate(restore);
                put(stream, &[COPY_LEAVE], &entry)?;
            } else if kind == fs::FileType::RegularFile {
                if self.emit_link(stream, &name, &meta, &entry)? {
                    continue;
                }
                // Opened before the length is announced, so the descriptor the
                // bytes come from is the file that was typed.
                let file = open_typed_file(dir, &leaf, &meta, &entry)?;
                let size = meta.st_size as u64;
                self.emit_named(stream, COPY_FILE, &name, &meta, &entry)?;
                put(stream, &size.to_le_bytes(), &entry)?;
                stream_file(stream, file, &entry, size)?;
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
                self.emit_named(stream, COPY_SYMLINK, &name, &meta, &entry)?;
                put(stream, &(target.len() as u16).to_le_bytes(), &entry)?;
                put(stream, target, &entry)?;
            } else if kind == fs::FileType::Fifo {
                // A named pipe is an ordinary unprivileged creation, so the
                // copy makes one rather than dropping it: a tree that ships a
                // FIFO meant to ship it.
                self.emit_named(stream, COPY_FIFO, &name, &meta, &entry)?;
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
            put(stream, &(name.len() as u16).to_le_bytes(), path)?;
            put(stream, name, path)?;
            put(stream, &(anchor.len() as u16).to_le_bytes(), path)?;
            put(stream, anchor, path)?;
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

    /// Emits a frame's tag, name, and metadata block.
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
        path: &Path,
    ) -> Result<(), ProvisionError> {
        put(stream, &[tag], path)?;
        put(stream, &(name.len() as u16).to_le_bytes(), path)?;
        put(stream, name, path)?;
        put(stream, &(meta.st_mode as u32).to_le_bytes(), path)?;
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
struct Translation {
    uid: Vec<IdRange>,
    gid: Vec<IdRange>,
}

impl Translation {
    /// The extents the child's map establishes.
    fn of(map: &ChildMap<'_>) -> Translation {
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
    for extent in extents {
        let outside = u64::from(extent.outside);
        let end = outside + u64::from(extent.count);
        if u64::from(host) >= outside && u64::from(host) < end {
            let mapped = u64::from(extent.inside) + (u64::from(host) - outside);
            return match u32::try_from(mapped) {
                Ok(inside) => Ok(inside),
                Err(_) => refuse(format!(
                    "the source entry's {which} {host} maps to {mapped}, which is past the \
                     largest id the kernel names",
                )),
            };
        }
    }
    refuse(format!(
        "the source entry's {which} {host} is outside the identity map, so the rootfs \
         has no id for it",
    ))
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
/// the directory the walk holds open. `subject` names it in a failure.
fn read_names(dir: BorrowedFd<'_>, subject: &Path) -> Result<Vec<Vec<u8>>, ProvisionError> {
    // A `Dir` takes a descriptor of its own and consumes its offset, so this
    // opens `.` relative to the walk's: the caller goes on resolving every
    // entry against the descriptor it already holds.
    let handle = openat_nofollow(dir, c".", OFlags::DIRECTORY, subject)?;
    let mut names = Vec::new();
    for entry in fs::Dir::read_from(&handle)
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
/// that grew or shrank in between cannot be sent faithfully: the child is
/// counting bytes, and a frame that lied about its length would leave every
/// later frame misaligned. So the frame is finished either way — a short file
/// padded with zeroes, a grown one cut at the declared length — and only then
/// is the mismatch reported.
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
    let mut file = std::fs::File::from(file);
    let mut buf = [0u8; DATA_BUF];
    let mut left = size;
    let mut changed = false;
    while left > 0 {
        let want = usize::try_from(left.min(DATA_BUF as u64)).unwrap_or(DATA_BUF);
        let read = file
            .read(&mut buf[..want])
            .map_err(|err| ProvisionError::io("reading", path, err))?;
        if read == 0 {
            // The file is shorter than its stat said.
            changed = true;
            buf[..want].fill(0);
            put(stream, &buf[..want], path)?;
            left -= want as u64;
            continue;
        }
        put(stream, &buf[..read], path)?;
        left -= read as u64;
    }

    // One byte past the declared length says whether the file grew. Nothing is
    // sent: the frame is complete, and this only decides what to report.
    if !changed {
        let mut past = [0u8; 1];
        changed = file
            .read(&mut past)
            .map_err(|err| ProvisionError::io("reading", path, err))?
            != 0;
    }
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
