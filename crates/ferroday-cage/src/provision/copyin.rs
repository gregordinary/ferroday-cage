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
use std::ffi::CString;
use std::fs;
use std::io::{self, Read};
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use super::{Delegate, ProvisionError, io_error};
use crate::IdentityMap;
use crate::idmap::{IdMapper, IdRange};
use crate::mechanism::{
    COPY_DIR, COPY_END, COPY_FIFO, COPY_FILE, COPY_LEAVE, COPY_LINK, COPY_SYMLINK, ChildMap,
    CopyFailure, LINK_BUF, start_copy_in,
};

/// How deep the walk descends, matching the child's own bound.
const MAX_DEPTH: usize = 128;
/// The file-data streaming buffer, matching the child's.
const DATA_BUF: usize = 65536;

/// Copies a host directory tree into a rootfs, with each entry created under
/// the identity map the rootfs is owned through.
///
// The paragraph links a feature-gated item, so its doc text is gated on the
// feature: present in the canonical all-features build, absent — link and all —
// from a no-feature `cargo doc`.
#[cfg_attr(
    feature = "tarball",
    doc = "The mirror image of [`Export`](super::Export). An export forks a child into"
)]
#[cfg_attr(
    feature = "tarball",
    doc = "the map to *read* a tree at the ownership it intends; this forks one to"
)]
#[cfg_attr(
    feature = "tarball",
    doc = "*write* one. The source tree's ids are interpreted as in-rootfs ids, which"
)]
#[cfg_attr(
    feature = "tarball",
    doc = "is what a tar extraction does and what lets a tree ship a file owned by a"
)]
#[cfg_attr(feature = "tarball", doc = "target uid.")]
#[cfg_attr(feature = "tarball", doc = "")]
#[cfg_attr(
    feature = "tarball",
    doc = "The mirroring is of the mechanism, not of the entry types. An export"
)]
#[cfg_attr(
    feature = "tarball",
    doc = "describes a rootfs the cage built, for a runtime that will supply its own"
)]
#[cfg_attr(
    feature = "tarball",
    doc = "device nodes and pipes; a copy lays down a tree the caller wrote by hand,"
)]
#[cfg_attr(
    feature = "tarball",
    doc = "where every entry is there because someone put it there. So the copy creates"
)]
#[cfg_attr(
    feature = "tarball",
    doc = "everything it can create — a named pipe included — and names the rest."
)]
#[cfg_attr(feature = "tarball", doc = "")]
/// That is the thing a plain `cp` structurally cannot do. `cp` runs as the
/// calling user, which can create a file owned by nobody else, so a tree laid
/// into a rootfs by hand arrives owned by the caller — and under a range map
/// that reads as root inside, whatever the source intended.
///
/// The destination must already exist. Entries are added to it: a directory the
/// rootfs already carries is kept and descended into, and a file, symlink, or
/// named pipe is replaced.
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
pub struct CopyIn<'a> {
    source: PathBuf,
    rootfs: PathBuf,
    map: IdentityMap,
    mapper: Option<&'a dyn IdMapper>,
}

impl std::fmt::Debug for CopyIn<'_> {
    /// Renders every setting, and the mapper by its presence rather than its
    /// contents: it is a caller's trait object, with nothing useful to show.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl<'a> CopyIn<'a> {
    /// Returns a copy of the tree at `source` into the rootfs at `rootfs`.
    ///
    /// The identity map defaults to [`IdentityMap::Single`], under which the
    /// in-map child writes its own one-id map and every entry lands as root —
    /// what a single-mapped sandbox sees, and what such a sandbox could have
    /// written itself.
    pub fn new(source: impl AsRef<Path>, rootfs: impl AsRef<Path>) -> CopyIn<'a> {
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
    pub fn map(mut self, map: IdentityMap) -> CopyIn<'a> {
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
    /// [`CageBuilder::id_mapper`]: crate::CageBuilder::id_mapper
    pub fn mapper(mut self, mapper: &'a dyn IdMapper) -> CopyIn<'a> {
        self.mapper = Some(mapper);
        self
    }

    /// Performs the copy, reporting what it could not copy.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::CopyUnprivileged`] when the rootfs needs a range map
    /// and no delegate can establish one; [`ProvisionError::EntryUnsafe`] for a
    /// source entry that cannot be represented as a contained rootfs entry;
    /// [`ProvisionError::SourceChanged`] for a file that changed size while it
    /// was being read; and [`ProvisionError::Io`] for a failure of the copy
    /// machinery, of the walk, or of the in-map writer.
    pub fn run(self) -> Result<CopyReport, ProvisionError> {
        copy_in_inner(&self.source, &self.rootfs, &self.map, self.mapper)
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

impl std::fmt::Display for SkippedKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    mapper: Option<&dyn IdMapper>,
) -> Result<CopyReport, ProvisionError> {
    let rootfs_c = CString::new(rootfs.as_os_str().as_bytes()).map_err(|_| {
        io_error(
            "copying into",
            rootfs,
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;
    if !source.is_dir() {
        return Err(io_error(
            "copying",
            source,
            io::Error::from(io::ErrorKind::NotADirectory),
        ));
    }

    // Compose the child's map, exactly as the export composes its own: the
    // single map it writes itself, a range map a delegate applies.
    let uid_line;
    let gid_line;
    let default_chain;
    let resolved;
    let child_map = match map {
        IdentityMap::Single => {
            let euid = rustix::process::geteuid().as_raw();
            let egid = rustix::process::getegid().as_raw();
            uid_line = format!("0 {euid} 1\n").into_bytes();
            gid_line = format!("0 {egid} 1\n").into_bytes();
            ChildMap::SelfMap {
                uid_line: &uid_line,
                gid_line: &gid_line,
            }
        }
        IdentityMap::Ranges { .. } | IdentityMap::Subordinate => {
            let unprivileged = |reason: String| ProvisionError::CopyUnprivileged {
                path: rootfs.to_path_buf(),
                reason,
            };
            match mapper {
                Some(mapper) => {
                    resolved = mapper
                        .resolve(map)
                        .map_err(|err| unprivileged(err.to_string()))?;
                    ChildMap::Delegated {
                        mapper,
                        map: &resolved,
                    }
                }
                None => {
                    default_chain =
                        crate::idmap::resolve_default_chain(map).map_err(unprivileged)?;
                    ChildMap::Delegated {
                        mapper: default_chain.0.as_ref(),
                        map: &default_chain.1,
                    }
                }
            }
        }
    };

    // The extents the source's ids are read through, as host-to-inside pairs.
    // See `Translation`.
    let translation = Translation::of(&child_map);

    let child = start_copy_in(&rootfs_c, child_map).map_err(|err| failure(err, rootfs))?;

    // The walk writes to the child's stream. A failure part-way leaves the
    // child mid-tree, so it is killed rather than left to read an input that
    // will never end.
    let report = match walk(child.stream(), source, &translation) {
        Ok(report) => report,
        Err(err) => {
            child.abandon();
            return Err(err);
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
            reason: err.to_string(),
        },
        CopyFailure::Step { step, errno } => ProvisionError::Io {
            op: step.describe(),
            path: rootfs.to_path_buf(),
            source: io::Error::from_raw_os_error(errno),
        },
    }
}

/// Walks `source` and streams its contents as frames.
///
/// The source root itself is not emitted: its contents land directly in the
/// destination, so a copy of `./overlay` into a rootfs puts `./overlay/etc` at
/// `/etc`. That matches what a caller means by laying a tree in, and it means
/// the destination's own mode and ownership are never rewritten by a copy.
fn walk(
    stream: BorrowedFd<'_>,
    source: &Path,
    ids: &Translation,
) -> Result<CopyReport, ProvisionError> {
    let mut walk = Walk {
        ids,
        links: HashMap::new(),
        prefix: Vec::new(),
        report: CopyReport::default(),
    };
    walk.dir(stream, source, 0)?;
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
    /// Entries are sorted by name, so a copy of one tree is one sequence of
    /// frames whatever order the filesystem hands them back — the same reason
    /// the export sorts its own walk. Sorting also fixes which name of a
    /// multiply-linked file carries the data and which become links, so two
    /// copies of one tree produce the same frames.
    fn dir(
        &mut self,
        stream: BorrowedFd<'_>,
        dir: &Path,
        depth: usize,
    ) -> Result<(), ProvisionError> {
        if depth >= MAX_DEPTH {
            return Err(ProvisionError::EntryUnsafe {
                path: dir.to_path_buf(),
                reason: format!("the source tree is deeper than {MAX_DEPTH} levels"),
            });
        }
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .map_err(|err| io_error("reading", dir, err))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<_, _>>()
            .map_err(|err| io_error("reading", dir, err))?;
        entries.sort();

        for path in entries {
            let name = path
                .file_name()
                .ok_or_else(|| ProvisionError::EntryUnsafe {
                    path: path.clone(),
                    reason: "the entry has no final component".to_string(),
                })?
                .as_bytes()
                .to_vec();
            // The child refuses anything that is not a single ordinary
            // component, but refusing here too means the caller gets a path in
            // the message rather than an errno from a forked process.
            if name.is_empty() || name.contains(&b'/') || name.contains(&0) {
                return Err(ProvisionError::EntryUnsafe {
                    path: path.clone(),
                    reason: "the entry name is not a single path component".to_string(),
                });
            }
            if name.len() > u16::from(u8::MAX) as usize {
                return Err(ProvisionError::EntryUnsafe {
                    path: path.clone(),
                    reason: "the entry name is longer than NAME_MAX".to_string(),
                });
            }

            // `symlink_metadata`, so a symlink is copied as a symlink rather
            // than followed. A symlink pointing out of the source is therefore
            // recreated as a symlink inside the destination, and never
            // traversed: the walk does not descend through one, and the child
            // opens each directory with `O_NOFOLLOW`.
            let meta =
                fs::symlink_metadata(&path).map_err(|err| io_error("reading", &path, err))?;
            let kind = meta.file_type();
            if kind.is_dir() {
                self.emit_named(stream, COPY_DIR, &name, &meta, &path)?;
                let restore = self.prefix.len();
                self.prefix.extend_from_slice(&name);
                self.prefix.push(b'/');
                self.dir(stream, &path, depth + 1)?;
                self.prefix.truncate(restore);
                put(stream, &[COPY_LEAVE], &path)?;
            } else if kind.is_file() {
                if self.emit_link(stream, &name, &meta, &path)? {
                    continue;
                }
                self.emit_named(stream, COPY_FILE, &name, &meta, &path)?;
                put(stream, &meta.len().to_le_bytes(), &path)?;
                stream_file(stream, &path, meta.len())?;
            } else if kind.is_symlink() {
                let target = fs::read_link(&path).map_err(|err| io_error("reading", &path, err))?;
                let target = target.as_os_str().as_bytes();
                if target.len() > u16::MAX as usize {
                    return Err(ProvisionError::EntryUnsafe {
                        path: path.clone(),
                        reason: "the symlink target is longer than a frame can carry".to_string(),
                    });
                }
                self.emit_named(stream, COPY_SYMLINK, &name, &meta, &path)?;
                put(stream, &(target.len() as u16).to_le_bytes(), &path)?;
                put(stream, target, &path)?;
            } else if kind.is_fifo() {
                // A named pipe is an ordinary unprivileged creation, so the
                // copy makes one rather than dropping it: a tree that ships a
                // FIFO meant to ship it.
                self.emit_named(stream, COPY_FIFO, &name, &meta, &path)?;
            } else {
                let skipped = if kind.is_char_device() {
                    SkippedKind::CharacterDevice
                } else if kind.is_block_device() {
                    SkippedKind::BlockDevice
                } else {
                    SkippedKind::Socket
                };
                self.report.skipped.push(SkippedEntry {
                    path: path.clone(),
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
    fn emit_link(
        &mut self,
        stream: BorrowedFd<'_>,
        name: &[u8],
        meta: &fs::Metadata,
        path: &Path,
    ) -> Result<bool, ProvisionError> {
        if meta.nlink() <= 1 {
            return Ok(false);
        }
        let key = (meta.dev(), meta.ino());
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
            return Err(ProvisionError::EntryUnsafe {
                path: path.to_path_buf(),
                reason: "the path of a multiply-linked file is longer than a frame can carry"
                    .to_string(),
            });
        }
        self.links.insert(key, anchor);
        Ok(false)
    }

    /// Emits a frame's tag, name, and metadata block.
    fn emit_named(
        &self,
        stream: BorrowedFd<'_>,
        tag: u8,
        name: &[u8],
        meta: &fs::Metadata,
        path: &Path,
    ) -> Result<(), ProvisionError> {
        put(stream, &[tag], path)?;
        put(stream, &(name.len() as u16).to_le_bytes(), path)?;
        put(stream, name, path)?;
        put(stream, &meta.mode().to_le_bytes(), path)?;
        put(stream, &self.ids.uid(meta.uid(), path)?.to_le_bytes(), path)?;
        put(stream, &self.ids.gid(meta.gid(), path)?.to_le_bytes(), path)?;
        put(stream, &meta.mtime().to_le_bytes(), path)
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
fn inside(extents: &[IdRange], host: u32, which: &str, path: &Path) -> Result<u32, ProvisionError> {
    for extent in extents {
        let end = u64::from(extent.outside) + u64::from(extent.count);
        if u64::from(host) >= u64::from(extent.outside) && u64::from(host) < end {
            return Ok(extent.inside + (host - extent.outside));
        }
    }
    Err(ProvisionError::EntryUnsafe {
        path: path.to_path_buf(),
        reason: format!(
            "the source entry's {which} {host} is outside the identity map, so the rootfs \
             has no id for it"
        ),
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
fn stream_file(stream: BorrowedFd<'_>, path: &Path, size: u64) -> Result<(), ProvisionError> {
    let mut file = fs::File::open(path).map_err(|err| io_error("reading", path, err))?;
    let mut buf = [0u8; DATA_BUF];
    let mut left = size;
    let mut changed = false;
    while left > 0 {
        let want = usize::try_from(left.min(DATA_BUF as u64)).unwrap_or(DATA_BUF);
        let read = file
            .read(&mut buf[..want])
            .map_err(|err| io_error("reading", path, err))?;
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
            .map_err(|err| io_error("reading", path, err))?
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

/// Writes `data` in full to the child's stream.
fn put(stream: BorrowedFd<'_>, data: &[u8], path: &Path) -> Result<(), ProvisionError> {
    let mut written = 0;
    while written < data.len() {
        match rustix::io::write(stream, &data[written..]) {
            Ok(0) => {
                return Err(io_error(
                    "copying",
                    path,
                    io::Error::from(io::ErrorKind::WriteZero),
                ));
            }
            Ok(n) => written += n,
            Err(rustix::io::Errno::INTR) => continue,
            // The child is gone. Its outcome record says why, so this reports a
            // broken pipe and lets `finish` supply the reason.
            Err(errno) => return Err(io_error("copying", path, errno.into())),
        }
    }
    Ok(())
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
        use std::os::fd::AsFd;

        let (read, write) = rustix::pipe::pipe().expect("a pipe is creatable");
        let outcome = stream_file(write.as_fd(), path, size);
        drop((read, write));
        outcome
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
    fn an_empty_file_recorded_as_empty_is_not_a_change() {
        // The zero-length case reads nothing and must not look like a file that
        // vanished: the check past the end is what tells them apart.
        let dir = Scratch::new("copyin-empty");
        let path = dir.join("file");
        std::fs::write(&path, b"").unwrap();
        stream_at(&path, 0).expect("an empty file copies");
    }
}
