//! Ownership-preserving rootfs export: write a provisioned tree to a POSIX/pax
//! tar whose entries carry the ownership the rootfs intends.
//!
//! A range-mapped sandbox writes real ownership, so the finished tree holds
//! files stored on the host at offset subordinate ids: a file the rootfs means
//! as uid 42 is owned `100000 + 42`. A host-side `tar` would record the offset
//! id, and could not read the `security.*` xattrs a setcap'd binary carries at
//! all. [`export_tar`] instead re-enters the identity map the tree was built
//! under — the machinery [`provision::remove`](super::remove) already runs —
//! so a forked child reads every entry as root of the mapped namespace, where
//! the ids and xattrs are its own.
//!
//! The child ([`mechanism::export`](crate::mechanism)) does only the
//! privileged, in-map reads and streams a flat frame protocol to this module,
//! which runs in ordinary `std` context. Here the frames are reassembled into
//! paths, hardlinks are coalesced by `(device, inode)`, and the pax/ustar
//! archive is encoded — all the heap-bearing work the post-fork child cannot
//! do. A caller's [`Export::filter`] is consulted here for the same reason:
//! the child holds no path to offer one and could not call a caller's code
//! post-fork, so an excluded subtree is walked and dropped on this side. The
//! encoder is hand-rolled, symmetric with the [reader](super::tar), and adds no
//! tar dependency.

use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::containment;
use super::identity::compose_child_map;
use super::tar::{
    BLOCK, MAX_USTAR_ID, MAX_USTAR_MTIME, MAX_USTAR_NAME, MAX_USTAR_PREFIX, MAX_USTAR_SIZE, pad,
    ustar_block, xattr_keyword,
};
use super::{Delegate, ProvisionError};
use crate::failure::ErrorChain;
use crate::mechanism::{
    ExportStep, FRAME_DIR, FRAME_END, FRAME_ERROR, FRAME_FILE, FRAME_LEAVE, FRAME_SYMLINK,
    StartError, kill_export, start_export,
};
use crate::{IdMapper, IdentityMap};

/// An ownership-preserving rootfs export, configured then written.
///
/// The archive is the range-map-correct equivalent of `tar -C rootfs .` run
/// inside the sandbox's user namespace: a file a subordinate-mapped bootstrap
/// chowned to a system id appears at that id, not the host subordinate id it is
/// stored as, and a setcap'd binary's `security.capability` xattr survives.
/// Regular files, directories, symlinks, and hardlinks are emitted, with their
/// mode, ownership, and modification time. Extended attributes are emitted for
/// everything but symlinks — ACLs and file capabilities included — since the
/// kernel confines a symlink's attributes to the `security` and `trusted`
/// namespaces, which an unprivileged export can neither read in full nor an
/// unprivileged extraction restore. Each is a `SCHILY.xattr.` pax record, its
/// name spelled as GNU tar spells it where it holds an `=` or a `%`, so GNU tar
/// restores it whole. The attributes the host assigns rather than
/// the tree carries are left out: security-module labels, integrity
/// measurements, and overlayfs's own bookkeeping. Character and block devices,
/// FIFOs, and sockets are skipped, as a deployed image's runtime provides its
/// own.
///
/// [`filter`](Self::filter) narrows that to a subset the caller names, so a
/// tree that holds more than the artifact should — a build cache, a mount
/// point a runtime fills in for itself — is exported without being edited
/// first.
///
/// Entries are emitted in sorted order — directory children by name, extended
/// attributes by name — so the output does not depend on the order the source
/// filesystem stores entries in. With [`clamp_mtime`](Self::clamp_mtime) set,
/// the archive is byte-reproducible given the tree. A directory is sorted in
/// memory the export sets aside before it starts reading, sized for several
/// hundred thousand entries among the directories it is inside at once; a
/// tree that needs more fails the export rather than being written out of
/// order.
///
/// A file that grows or shrinks while it is read fails the export with
/// [`ProvisionError::SourceChanged`], naming the file: the archive would
/// otherwise carry it cut or zero-padded. A name that stops holding the file
/// the walk inspected, before the walk opens it, fails the export too.
///
/// A file is archived at its length, a sparse file's holes as the zeros they
/// read as, and the export holds the archive to no ceiling. A tree untrusted
/// code wrote can hold a file that cost it nothing to make long: `truncate -s
/// 16T` writes no data. An export of such a tree bounds its sink, which
/// [`write_to`](Self::write_to) takes as any `Write`: one that refuses past a
/// ceiling fails the export there.
///
/// [`write_to_path`](Self::write_to_path) names a file, which the archive is
/// staged beside and renamed over, so the destination appears complete or not
/// at all; [`write_to`](Self::write_to) takes any `Write` sink, for a pipe, a
/// compressor, or a buffer in memory. [`export_tar`] is the shorthand for the
/// common case.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
/// use ferroday_cage::IdentityMap;
/// use ferroday_cage::provision::Export;
///
/// let mut archive = Vec::new();
/// Export::new("/var/lib/myapp/rootfs")
///     .identity_map(IdentityMap::Subordinate)
///     .clamp_mtime(1_700_000_000)
///     .write_to(&mut archive)?;
/// # Ok(())
/// # }
/// ```
pub struct Export<'a> {
    rootfs: PathBuf,
    identity_map: IdentityMap,
    id_mapper: Option<Arc<dyn IdMapper>>,
    clamp_mtime: Option<i64>,
    filter: Option<Box<EntryPredicate<'a>>>,
}

/// The predicate an [`Export::filter`] holds: owned by the builder, borrowed by
/// the encoder.
///
/// `Send + Sync` because [`Export`] is: a configured export can be moved to
/// another thread or shared, and a caller's predicate is the only part of it
/// that could withdraw either.
type EntryPredicate<'a> = dyn Fn(&ExportEntry<'_>) -> bool + Send + Sync + 'a;

impl fmt::Debug for Export<'_> {
    /// Renders every setting, and the mapper and the filter by their presence
    /// rather than their contents: both are a caller's code, with nothing
    /// useful to show.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Export")
            .field("rootfs", &self.rootfs)
            .field("identity_map", &self.identity_map)
            .field(
                "id_mapper",
                &self.id_mapper.as_ref().map(|_| Delegate("dyn IdMapper")),
            )
            .field("clamp_mtime", &self.clamp_mtime)
            .field("filter", &self.filter.as_ref().map(|_| Delegate("dyn Fn")))
            .finish()
    }
}

impl<'a> Export<'a> {
    /// Returns an export of the finished rootfs at `rootfs`.
    ///
    /// The identity map defaults to [`IdentityMap::Single`], under which the
    /// in-map child writes its own one-id map and every entry is recorded as
    /// root — the identity a single-mapped sandbox ran everything as.
    ///
    /// That is a sandbox's own default, because an export records every owner
    /// through the map: it has to be the map the tree was built under, and a
    /// tree built with every default was built under this one. A [`Remove`]
    /// defaults to the subordinate map instead, because a removal records no
    /// ownership.
    ///
    /// [`Remove`]: super::Remove
    pub fn new(rootfs: impl AsRef<Path>) -> Export<'a> {
        Export {
            rootfs: rootfs.as_ref().to_path_buf(),
            identity_map: IdentityMap::Single,
            id_mapper: None,
            clamp_mtime: None,
            filter: None,
        }
    }

    /// Sets the identity map the tree was built under.
    ///
    /// It must be the map the tree was built under. Naming it, rather than
    /// resolving the subordinate chain internally, is deliberate: a bootstrap
    /// done under an explicit [`IdentityMap::Ranges`] must be exported through
    /// the identical map, or the host subordinate ids will not round-trip to
    /// the ids the tree was built with.
    pub fn identity_map(mut self, map: IdentityMap) -> Export<'a> {
        self.identity_map = map;
        self
    }

    /// Exports through a caller-supplied identity-map delegate, for a tree
    /// built under [`CageBuilder::id_mapper`].
    ///
    /// Without one, the export resolves the bundled delegate chain, which
    /// covers a [`Subordinate`](IdentityMap::Subordinate) tree and a
    /// bundled-delegate [`Ranges`](IdentityMap::Ranges) one. A tree whose
    /// ownership a site-specific mapper established — one allocating ids the
    /// bundled delegates would not — must be exported through that same mapper,
    /// so its ids round-trip. The mapper and the
    /// [`identity_map`](Self::identity_map) must be the pair the tree was built
    /// under; a [`Single`](IdentityMap::Single) map self-establishes and
    /// ignores the mapper, as the launch does.
    ///
    /// The delegate is taken by value and kept, as every builder that takes one
    /// keeps it; [`CageBuilder::id_mapper`] says why.
    ///
    /// [`CageBuilder::id_mapper`]: crate::CageBuilder::id_mapper
    pub fn id_mapper(mut self, mapper: impl IdMapper + 'static) -> Export<'a> {
        self.id_mapper = Some(Arc::new(mapper));
        self
    }

    /// Caps every recorded modification time at `epoch`, a `SOURCE_DATE_EPOCH`
    /// ceiling in Unix seconds.
    ///
    /// Each entry's time is recorded as `min(mtime, epoch)`, pulling a
    /// bootstrap's wall-clock stamps down to the epoch while preserving any
    /// intrinsically earlier time. Unset, the real time is recorded and the
    /// archive is not byte-reproducible across runs.
    pub fn clamp_mtime(mut self, epoch: i64) -> Export<'a> {
        self.clamp_mtime = Some(epoch);
        self
    }

    /// Writes only the entries `keep` answers `true` for.
    ///
    /// The predicate is consulted once per entry, in the order the archive is
    /// written, and is the export's own statement of what the tree holds that
    /// the artifact should not — a build cache, a resolver's package lists, the
    /// contents of a directory a runtime fills in for itself. Without one every
    /// entry the walk reaches is written.
    ///
    /// **Excluding a directory excludes everything under it.** Its descendants
    /// are dropped without the predicate being consulted about them, so a rule
    /// naming the top of a subtree does not have to be restated for its
    /// contents. The tree's own root is an entry like any other and is offered
    /// too, as `/`; excluding it produces an empty archive.
    ///
    /// A hardlink is offered as [`ExportKind::File`]. Which of an inode's names
    /// carries the data is the encoder's choice rather than a property of the
    /// entry, so excluding the first name seen does not lose the file: the next
    /// kept name is written in full, and later ones link onto it.
    ///
    /// The archive stays byte-reproducible as long as the predicate is a pure
    /// function of the entry it is given — every input it has is already
    /// determined by the tree.
    ///
    /// The predicate runs on this side of the export rather than in the walking
    /// child, which is a post-fork reader that can neither call a caller's code
    /// nor assemble a path to offer it. An excluded subtree is therefore read
    /// from the tree and dropped here, not left unvisited: the archive is what
    /// the filter says, and the walk is not made cheaper by it.
    ///
    /// A closure rather than a named seam, which is the second answer to a
    /// question [`IdMapper`] answers with a trait. Its `Debug` supertrait is
    /// what a trait buys, and it buys nothing here: a filter renders by its
    /// presence either way, exactly as the identity-map delegate beside it
    /// does. That leaves a trait costing a type definition per rule for a
    /// predicate whose body is usually one comparison. `Send + Sync` is not
    /// optional, though — it is what keeps [`Export`] itself both.
    ///
    /// # Example
    ///
    /// A rootfs's `/dev` is a mount point the deployed runtime fills, so the
    /// archive carries the directory and nothing under it:
    ///
    /// ```no_run
    /// # fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
    /// use std::path::Path;
    /// use ferroday_cage::IdentityMap;
    /// use ferroday_cage::provision::Export;
    ///
    /// let dev = Path::new("/dev");
    /// Export::new("/var/lib/myapp/rootfs")
    ///     .identity_map(IdentityMap::Subordinate)
    ///     .filter(move |entry| entry.path() == dev || !entry.path().starts_with(dev))
    ///     .write_to_path("/var/lib/myapp/rootfs.tar")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn filter(
        mut self,
        keep: impl Fn(&ExportEntry<'_>) -> bool + Send + Sync + 'a,
    ) -> Export<'a> {
        self.filter = Some(Box::new(keep));
        self
    }

    /// Writes the archive to `writer`.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::ExportUnprivileged`] when the tree needs a range map
    /// and no delegate can establish one; [`ProvisionError::SourceChanged`] for
    /// a file that grew or shrank while it was read; and
    /// [`ProvisionError::Io`] for a failure of the export machinery, of the
    /// in-map reader, or of `writer`.
    pub fn write_to<W: Write>(self, writer: W) -> Result<(), ProvisionError> {
        export_inner(
            &self.rootfs,
            writer,
            &self.identity_map,
            self.id_mapper.as_ref(),
            self.clamp_mtime,
            self.filter.as_deref(),
        )
    }

    /// Writes the archive to the file at `path`, which appears complete or not
    /// at all.
    ///
    /// The bytes go to a staging file beside `path`, which is synced and then
    /// renamed over it. A failure — an unreadable source entry, an identity map
    /// no delegate can establish, a full filesystem — removes the staging file
    /// and leaves whatever was already at `path` untouched, and a crash
    /// mid-write cannot leave a truncated archive behind a completed rename.
    /// Writing to the destination directly would instead destroy a previous
    /// archive to make a partial one, before the export had established that it
    /// could produce anything at all.
    ///
    /// The staging file is created afresh, so `path`'s own inode is replaced
    /// rather than rewritten: a hard link to the previous archive keeps it, and
    /// a symlink at `path` is replaced by the archive rather than followed. Its
    /// permissions are the ones an ordinary shell redirection produces, `0o666`
    /// less the process umask, and `path`'s previous mode does not carry over.
    ///
    /// [`write_to`](Self::write_to) remains the call for a sink that is not a
    /// file — a pipe, a socket, a buffer in memory, a compressor.
    ///
    /// # Errors
    ///
    /// As [`write_to`](Self::write_to), plus
    /// [`ProvisionError::ExportDestInside`] where `path` lies inside the tree
    /// being exported, which would make the archive a member of itself, and
    /// [`ProvisionError::Io`] for a failure of the staging file, the sync, or
    /// the rename.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
    /// use ferroday_cage::IdentityMap;
    /// use ferroday_cage::provision::Export;
    ///
    /// Export::new("/var/lib/myapp/rootfs")
    ///     .identity_map(IdentityMap::Subordinate)
    ///     .write_to_path("/var/lib/myapp/rootfs.tar")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_to_path(self, path: impl AsRef<Path>) -> Result<(), ProvisionError> {
        let path = path.as_ref();
        let parent = crate::path::parent_of(path);
        refuse_dest_inside(&self.rootfs, path, parent)?;

        // Unique to this call, so two exports to one destination -- two
        // threads of one process included -- stage separately and the later
        // rename wins, which is what two shell redirections to one path do.
        let (staged, file) = super::Staged::beside(path)
            .map_err(|err| ProvisionError::io("creating the staging file for", path, err))?;

        export_inner(
            &self.rootfs,
            &file,
            &self.identity_map,
            self.id_mapper.as_ref(),
            self.clamp_mtime,
            self.filter.as_deref(),
        )?;
        file.sync_all()
            .map_err(|err| ProvisionError::io("syncing", staged.path(), err))?;
        drop(file);

        staged
            .publish()
            .map_err(|err| ProvisionError::io("publishing", path, err))?;
        // The rename is durable only once the directory entry is, which is what
        // keeps a crash from resurrecting the destination the rename replaced.
        let parent_dir =
            fs::File::open(parent).map_err(|err| ProvisionError::io("opening", parent, err))?;
        parent_dir
            .sync_all()
            .map_err(|err| ProvisionError::io("syncing", parent, err))
    }
}

/// Refuses a destination that lies inside the tree being exported.
///
/// The comparison is between the tree and the *directory the archive would be
/// written into*, both canonicalized, so it is about where the kernel would
/// resolve to rather than about how the two paths were spelled: a symlinked
/// directory, a relative source, and a `..` in either all reduce to the same
/// answer. The destination file itself is not canonicalized, since it need not
/// exist yet; the directory holding it must, because the staging file goes
/// there.
///
/// Where either side cannot be canonicalized the check abstains -- a missing
/// rootfs or a missing parent directory is a failure the export itself reports
/// a moment later, with the operation that met it named.
fn refuse_dest_inside(rootfs: &Path, dest: &Path, parent: &Path) -> Result<(), ProvisionError> {
    let (Ok(rootfs_real), Ok(parent_real)) = (fs::canonicalize(rootfs), fs::canonicalize(parent))
    else {
        return Ok(());
    };
    if parent_real.starts_with(&rootfs_real) {
        return Err(ProvisionError::ExportDestInside {
            path: dest.to_path_buf(),
            rootfs: rootfs.to_path_buf(),
        });
    }
    Ok(())
}

/// Writes the finished rootfs at `rootfs` to `writer` as a POSIX/pax tar whose
/// entries carry the ownership the rootfs intends, read from inside the
/// identity `map` that produced it.
///
/// The shorthand for [`Export`], carrying only the inputs every export needs.
/// Reach for the builder to clamp modification times, to filter what the
/// archive holds, or to name a caller-supplied identity-map delegate.
///
/// # Errors
///
/// As [`Export::write_to`].
pub fn export_tar<W: Write>(
    rootfs: impl AsRef<Path>,
    writer: W,
    map: IdentityMap,
) -> Result<(), ProvisionError> {
    Export::new(rootfs).identity_map(map).write_to(writer)
}

/// Exports `rootfs`, resolving a range map through `mapper` when given and the
/// bundled delegate chain otherwise.
fn export_inner<W: Write>(
    rootfs: &Path,
    writer: W,
    map: &IdentityMap,
    mapper: Option<&Arc<dyn IdMapper>>,
    clamp_mtime: Option<i64>,
    filter: Option<&EntryPredicate<'_>>,
) -> Result<(), ProvisionError> {
    let rootfs_c = CString::new(rootfs.as_os_str().as_bytes()).map_err(|_| {
        ProvisionError::io(
            "exporting",
            rootfs,
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;

    let source =
        compose_child_map(map, mapper).map_err(|reason| ProvisionError::ExportUnprivileged {
            path: rootfs.to_path_buf(),
            reason,
        })?;

    let child = match start_export(&rootfs_c, source.child_map()) {
        Ok(child) => child,
        Err(StartError::Spawn(errno)) => {
            return Err(ProvisionError::io("exporting", rootfs, errno.into()));
        }
        // The child's own account of what stopped it, reported exactly as the
        // same failure arriving mid-walk as a `FRAME_ERROR` would be.
        Err(StartError::Reported { step, errno }) => {
            return Err(ProvisionError::io(step.describe(), rootfs, errno.into()));
        }
        Err(StartError::Map(err)) => {
            return Err(ProvisionError::ExportUnprivileged {
                path: rootfs.to_path_buf(),
                reason: ErrorChain::new(&err).to_string(),
            });
        }
    };

    let result = drive(child.stream(), writer, rootfs, clamp_mtime, filter);

    // Reap the child regardless. A walk failure already surfaced as a frame; a
    // failure to reap is not worth masking the export's own outcome.
    if result.is_err() {
        kill_export(&child);
    }
    let _ = child.finish();
    result
}

/// Reads the child's frame stream and encodes the archive into `writer`.
fn drive<W: Write>(
    stream: BorrowedFd<'_>,
    writer: W,
    rootfs: &Path,
    clamp_mtime: Option<i64>,
    filter: Option<&EntryPredicate<'_>>,
) -> Result<(), ProvisionError> {
    // The stream is duplicated so it can be owned by a buffered reader while the
    // child retains its own descriptor for reaping. Close-on-exec like the
    // original, so a process the caller spawns while the export runs does not
    // hold the stream open.
    let dup = rustix::io::fcntl_dupfd_cloexec(stream, 0)
        .map_err(|errno| ProvisionError::io("exporting", rootfs, errno.into()))?;
    let mut reader = BufReader::new(std::fs::File::from(dup));
    let mut tar = TarWriter::new(BufWriter::new(writer), clamp_mtime, filter);

    let read_err = |e: io::Error| ProvisionError::io("reading the exported tree", rootfs, e);
    let write_err = |e: io::Error| ProvisionError::io("writing the archive", rootfs, e);

    loop {
        let tag = match read_u8(&mut reader) {
            Ok(tag) => tag,
            Err(e) => return Err(read_err(e)),
        };
        match tag {
            FRAME_DIR => {
                let meta = read_meta(&mut reader, false).map_err(read_err)?;
                tar.enter_dir(&meta).map_err(write_err)?;
            }
            FRAME_FILE => {
                let meta = read_meta(&mut reader, true).map_err(read_err)?;
                let written = tar
                    .file(&meta, &mut reader)
                    .map_err(|e| classify(e, read_err, write_err))?;
                // The child's word on whether the file held what it recorded.
                // It matters only for data that went into the archive: an
                // excluded file, or a later name of one already written, adds
                // none of what was read.
                let changed = read_u8(&mut reader).map_err(read_err)? != 0;
                if changed && written {
                    return Err(ProvisionError::SourceChanged {
                        path: tar.host_path(rootfs, &meta.name),
                        recorded: meta.size,
                    });
                }
            }
            FRAME_SYMLINK => {
                let meta = read_symlink(&mut reader).map_err(read_err)?;
                tar.symlink(&meta).map_err(write_err)?;
            }
            FRAME_LEAVE => tar.leave_dir(),
            FRAME_END => {
                tar.finish().map_err(write_err)?;
                return Ok(());
            }
            FRAME_ERROR => {
                let (step, errno) = read_error(&mut reader).map_err(read_err)?;
                let Some(step) = ExportStep::from_wire(step) else {
                    // The child is this same build, so a step it does not
                    // carry means the stream is malformed rather than newer.
                    return Err(read_err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected export failure step {step}"),
                    )));
                };
                return Err(ProvisionError::io(
                    step.describe(),
                    rootfs,
                    io::Error::from_raw_os_error(errno),
                ));
            }
            other => {
                return Err(read_err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected export frame tag {other}"),
                )));
            }
        }
    }
}

/// Distinguishes a read failure (the stream half of a file copy) from a write
/// failure (the archive half), so each is attributed correctly.
fn classify(
    e: CopyError,
    read_err: impl Fn(io::Error) -> ProvisionError,
    write_err: impl Fn(io::Error) -> ProvisionError,
) -> ProvisionError {
    match e {
        CopyError::Read(e) => read_err(e),
        CopyError::Write(e) => write_err(e),
    }
}

/// What one entry offered to an [`Export::filter`] is.
///
/// Only the three kinds an export writes. Character and block devices, FIFOs,
/// and sockets are never offered: the export skips them before any filter is
/// consulted, since a deployed image's runtime provides its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExportKind {
    /// A directory. Excluding one excludes everything under it.
    Directory,
    /// A regular file, or a second name for one — see
    /// [`Export::filter`] for why a hardlink is not a kind of its own.
    File,
    /// A symbolic link.
    Symlink,
}

/// One entry an [`Export`] is about to write, as its
/// [`filter`](Export::filter) sees it.
///
/// The path is where the entry sits *inside the tree*, spelled absolutely —
/// `/etc/hostname`, and `/` for the tree itself — which is how a mount target
/// and a Landlock grant name a location inside a tree too. Because it is a
/// [`Path`], [`starts_with`](Path::starts_with) compares whole components, so
/// `/dev` does not match `/devices`.
///
/// It is deliberately not the member name the archive carries. That name is
/// `./`-prefixed and gives a directory a trailing slash, and a leading `./` is
/// the one relative component [`Path::components`] does not normalize away — so
/// a rule written the way a rootfs is otherwise spoken about, `/dev`, would
/// silently match nothing.
///
/// The ownership is what the *rootfs* intends rather than what the host stores,
/// which is the whole point of exporting through the identity map: a file a
/// subordinate-mapped bootstrap chowned to uid 42 is offered as uid 42.
///
/// The modification time is the entry's own, before
/// [`clamp_mtime`](Export::clamp_mtime) applies — filtering decides what the
/// archive holds, and clamping decides how what it holds is recorded.
#[derive(Debug, Clone, Copy)]
pub struct ExportEntry<'a> {
    path: &'a Path,
    kind: ExportKind,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: i64,
}

impl ExportEntry<'_> {
    /// Where the entry sits inside the tree, spelled absolutely.
    pub fn path(&self) -> &Path {
        self.path
    }

    /// What the entry is.
    pub fn kind(&self) -> ExportKind {
        self.kind
    }

    /// The permission and set-id bits, without the type bits
    /// [`kind`](Self::kind) already answers for.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// The owning user id, as the rootfs intends it.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The owning group id, as the rootfs intends it.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// The file's length in bytes; zero for a directory or a symbolic link.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The modification time in Unix seconds, before any
    /// [`clamp_mtime`](Export::clamp_mtime).
    pub fn mtime(&self) -> i64 {
        self.mtime
    }
}

/// One entry's metadata, decoded from a frame.
struct Meta {
    name: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    size: u64,
    dev: u64,
    ino: u64,
    nlink: u64,
    link_target: Vec<u8>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Encodes the frame stream into a tar, maintaining the path stack and the
/// hardlink table the post-fork child could not.
struct TarWriter<'f, W: Write> {
    out: W,
    /// Directory name components from the root to the current directory.
    ///
    /// A pruned directory is not pushed, so the stack always describes a path
    /// that is being written and `child_path` is only ever asked for one.
    stack: Vec<Vec<u8>>,
    /// The recorded path of the first link seen for each `(device, inode)` with
    /// more than one link, so a later link coalesces onto it.
    ///
    /// A filtered-out link is not recorded, so the first *kept* name of an
    /// inode is the one that carries the data.
    hardlinks: HashMap<(u64, u64), Vec<u8>>,
    /// A `SOURCE_DATE_EPOCH` ceiling in Unix seconds. An entry's modification
    /// time is recorded as `min(mtime, epoch)`; `None` records the real time.
    epoch: Option<i64>,
    /// The caller's entry filter, consulted once per entry; `None` keeps every
    /// entry the walk reaches.
    filter: Option<&'f EntryPredicate<'f>>,
    /// How many directory levels of an excluded subtree the walk is inside.
    ///
    /// The child walks the whole tree whatever the filter says — it is a
    /// post-fork reader with no channel back — so exclusion is a state this end
    /// holds: nonzero means every frame until the matching `FRAME_LEAVE`s is
    /// dropped, and a file's data is read off the stream and discarded so the
    /// next frame starts where it should.
    pruned: u32,
}

impl<'f, W: Write> TarWriter<'f, W> {
    fn new(out: W, epoch: Option<i64>, filter: Option<&'f EntryPredicate<'f>>) -> TarWriter<'f, W> {
        TarWriter {
            out,
            stack: Vec::new(),
            hardlinks: HashMap::new(),
            epoch,
            filter,
            pruned: 0,
        }
    }

    /// Whether the caller's filter keeps the entry named `name` in the current
    /// directory.
    ///
    /// `true` with no filter configured, so an unfiltered export pays one
    /// branch and builds neither the path nor the entry.
    fn keeps(&self, name: &[u8], kind: ExportKind, meta: &Meta) -> bool {
        let Some(filter) = self.filter else {
            return true;
        };
        let path = self.child_tree_path(name);
        filter(&ExportEntry {
            path: Path::new(OsStr::from_bytes(&path)),
            kind,
            // The type bits are what `kind` already answers for, and leaving
            // them in would make a mode comparison at the call site wrong in a
            // way that reads right.
            mode: meta.mode & 0o7777,
            uid: meta.uid,
            gid: meta.gid,
            size: meta.size,
            mtime: meta.mtime,
        })
    }

    /// Clamps a modification time to the configured epoch: the
    /// reproducible-builds `SOURCE_DATE_EPOCH` rule, a ceiling that leaves a time
    /// already at or before the epoch untouched.
    fn clamp(&self, mtime: i64) -> i64 {
        match self.epoch {
            Some(epoch) => mtime.min(epoch),
            None => mtime,
        }
    }

    /// The archive member name of a child named `name` in the current
    /// directory.
    fn child_path(&self, name: &[u8]) -> Vec<u8> {
        if self.stack.is_empty() {
            return name.to_vec();
        }
        let mut path = self.stack.join(&b'/');
        path.push(b'/');
        path.extend_from_slice(name);
        path
    }

    /// Where a child named `name` in the current directory sits inside the
    /// tree, spelled absolutely: what an [`Export::filter`] is offered.
    ///
    /// The walk's root frame is named `.` and no entry the walk reaches can be,
    /// so dropping that component is what turns the archive's `./etc/hostname`
    /// into the `/etc/hostname` a caller's rule is written against, and the
    /// tree's own root into `/`.
    fn child_tree_path(&self, name: &[u8]) -> Vec<u8> {
        let mut path = Vec::new();
        for component in self.stack.iter().map(Vec::as_slice).chain([name]) {
            if component == b"." {
                continue;
            }
            path.push(b'/');
            path.extend_from_slice(component);
        }
        if path.is_empty() {
            path.push(b'/');
        }
        path
    }

    /// Emits a directory entry and descends: later frames name its children
    /// until the matching [`leave_dir`](Self::leave_dir).
    ///
    /// A directory the filter excludes takes its whole subtree with it, which
    /// is what makes one rule enough to drop a build cache or a mount point's
    /// contents.
    fn enter_dir(&mut self, meta: &Meta) -> io::Result<()> {
        if self.pruned > 0 {
            self.pruned += 1;
            return Ok(());
        }
        if !self.keeps(&meta.name, ExportKind::Directory, meta) {
            self.pruned = 1;
            return Ok(());
        }
        let mut path = self.child_path(&meta.name);
        self.stack.push(meta.name.clone());
        path.push(b'/');
        self.write_entry(&path, b'5', meta, 0, &[], &meta.xattrs)
    }

    /// Ascends out of the current directory, or out of one level of an excluded
    /// subtree — the stack holds only directories that were written.
    fn leave_dir(&mut self) {
        if self.pruned > 0 {
            self.pruned -= 1;
        } else {
            self.stack.pop();
        }
    }

    /// Emits a file entry: a full regular file the first time its inode is
    /// seen, a hardlink onto the first path afterward. The `size` bytes of data
    /// the child streams are copied to the archive for a regular file and
    /// discarded for a coalesced hardlink, so the stream stays in step either
    /// way.
    ///
    /// Reports whether the data went into the archive, which is when a change
    /// to the file while it was read matters.
    fn file(&mut self, meta: &Meta, reader: &mut impl Read) -> Result<bool, CopyError> {
        if self.pruned > 0 || !self.keeps(&meta.name, ExportKind::File, meta) {
            discard(reader, meta.size)?;
            return Ok(false);
        }
        let path = self.child_path(&meta.name);
        if meta.nlink > 1 {
            if let Some(first) = self.hardlinks.get(&(meta.dev, meta.ino)) {
                let first = first.clone();
                self.write_entry(&path, b'1', meta, 0, &first, &meta.xattrs)
                    .map_err(CopyError::Write)?;
                discard(reader, meta.size)?;
                return Ok(false);
            }
            self.hardlinks.insert((meta.dev, meta.ino), path.clone());
        }
        self.write_entry(&path, b'0', meta, meta.size, &[], &meta.xattrs)
            .map_err(CopyError::Write)?;
        copy_data(reader, &mut self.out, meta.size)?;
        pad(&mut self.out, meta.size).map_err(CopyError::Write)?;
        Ok(true)
    }

    /// The host path of a child named `name` in the current directory, for an
    /// error that names the file it is about.
    fn host_path(&self, rootfs: &Path, name: &[u8]) -> PathBuf {
        let mut path = rootfs.to_path_buf();
        for component in self.stack.iter().map(Vec::as_slice).chain([name]) {
            if component != b"." {
                path.push(OsStr::from_bytes(component));
            }
        }
        path
    }

    /// Emits a symlink entry.
    fn symlink(&mut self, meta: &Meta) -> io::Result<()> {
        if self.pruned > 0 || !self.keeps(&meta.name, ExportKind::Symlink, meta) {
            return Ok(());
        }
        let path = self.child_path(&meta.name);
        self.write_entry(&path, b'2', meta, 0, &meta.link_target, &meta.xattrs)
    }

    /// Writes two zero blocks: the archive terminator.
    fn finish(&mut self) -> io::Result<()> {
        self.out.write_all(&[0u8; BLOCK as usize * 2])?;
        self.out.flush()
    }

    /// Writes an entry's header(s): a pax extended header when the ustar fields
    /// cannot hold the path, link target, size, modification time, owner,
    /// group, or any extended attribute, then the ustar header itself.
    fn write_entry(
        &mut self,
        path: &[u8],
        typeflag: u8,
        meta: &Meta,
        size: u64,
        linkname: &[u8],
        xattrs: &[(Vec<u8>, Vec<u8>)],
    ) -> io::Result<()> {
        let mtime = self.clamp(meta.mtime);
        let split = split_name(path);
        let link_fits = linkname.len() <= 100;
        let size_fits = size <= MAX_USTAR_SIZE;
        let mtime_fits = (0..=MAX_USTAR_MTIME).contains(&mtime);

        // Assemble any pax records the ustar header cannot express.
        let mut pax = Vec::new();
        if split.is_none() {
            pax.extend_from_slice(&pax_record(b"path", path));
        }
        if !link_fits {
            pax.extend_from_slice(&pax_record(b"linkpath", linkname));
        }
        if !size_fits {
            pax.extend_from_slice(&pax_record(b"size", size.to_string().as_bytes()));
        }
        if !mtime_fits {
            // A pre-1970 or far-future time the ustar field cannot hold: record
            // the real seconds-since-epoch, negative or large, rather than
            // clamp it silently or abort the whole export on one exotic stamp.
            pax.extend_from_slice(&pax_record(b"mtime", mtime.to_string().as_bytes()));
        }
        // An id past the octal field's seven digits: a range map whose extents
        // reach that far, or an explicit `Ranges` one. Recorded exactly, as GNU
        // tar records it and as this crate's reader reads it back.
        if meta.uid > MAX_USTAR_ID {
            pax.extend_from_slice(&pax_record(b"uid", meta.uid.to_string().as_bytes()));
        }
        if meta.gid > MAX_USTAR_ID {
            pax.extend_from_slice(&pax_record(b"gid", meta.gid.to_string().as_bytes()));
        }
        for (name, value) in xattrs {
            pax.extend_from_slice(&pax_record(&xattr_keyword(name), value));
        }

        if !pax.is_empty() {
            self.write_pax_header(path, mtime, pax.len())?;
            self.out.write_all(&pax)?;
            pad(&mut self.out, pax.len() as u64)?;
        }

        // The ustar header. When a pax record overrides a field, the ustar
        // field holds a truncated form the reader ignores. An id is clamped
        // rather than zeroed, so a reader that ignores pax records takes the
        // entry for an unprivileged owner's rather than for root's.
        let (name_field, prefix_field) =
            split.unwrap_or((&path[..path.len().min(MAX_USTAR_NAME)], &[][..]));
        let ustar_size = if size_fits { size } else { 0 };
        let link_field = &linkname[..linkname.len().min(MAX_USTAR_NAME)];
        let block = ustar_block(
            name_field,
            prefix_field,
            meta.mode,
            meta.uid.min(MAX_USTAR_ID),
            meta.gid.min(MAX_USTAR_ID),
            ustar_size,
            mtime,
            typeflag,
            link_field,
        )?;
        self.out.write_all(&block)
    }

    /// Writes the header of a pax extended-header entry (typeflag `x`).
    fn write_pax_header(&mut self, path: &[u8], mtime: i64, size: usize) -> io::Result<()> {
        // The name is cosmetic — the reader keys on the typeflag — but a
        // path-derived one keeps `tar tvf` legible.
        let mut name = b"PaxHeaders/".to_vec();
        name.extend_from_slice(path);
        let name = &name[..name.len().min(MAX_USTAR_NAME)];
        let block = ustar_block(name, &[], 0o644, 0, 0, size as u64, mtime, b'x', &[])?;
        self.out.write_all(&block)
    }
}

/// A failed file-data copy, tagged with which side failed.
#[derive(Debug)]
enum CopyError {
    Read(io::Error),
    Write(io::Error),
}

/// Copies exactly `n` bytes from the stream to the archive.
fn copy_data(reader: &mut impl Read, out: &mut impl Write, n: u64) -> Result<(), CopyError> {
    let mut remaining = n;
    let mut buf = [0u8; 1 << 16];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        reader
            .read_exact(&mut buf[..want])
            .map_err(CopyError::Read)?;
        out.write_all(&buf[..want]).map_err(CopyError::Write)?;
        remaining -= want as u64;
    }
    Ok(())
}

/// Reads and discards exactly `n` bytes from the stream (a coalesced
/// hardlink's data).
fn discard(reader: &mut impl Read, n: u64) -> Result<(), CopyError> {
    let mut remaining = n;
    let mut buf = [0u8; 1 << 16];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        reader
            .read_exact(&mut buf[..want])
            .map_err(CopyError::Read)?;
        remaining -= want as u64;
    }
    Ok(())
}

/// Splits a path into the ustar `name` and `prefix` fields, joined by an
/// implicit `/`, or `None` when no split fits and a pax `path` record is needed.
fn split_name(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.len() <= MAX_USTAR_NAME {
        return Some((path, &[]));
    }
    // name = path[i+1..] must fit `name`, so i >= len-(MAX_USTAR_NAME+1);
    // prefix = path[..i] must fit `prefix`, so i <= MAX_USTAR_PREFIX. Prefer the
    // largest such split point.
    let lo = path.len().saturating_sub(MAX_USTAR_NAME + 1);
    let hi = path.len().saturating_sub(1).min(MAX_USTAR_PREFIX);
    for i in (lo..=hi).rev() {
        if path[i] == b'/' {
            let (prefix, rest) = (&path[..i], &path[i + 1..]);
            if !rest.is_empty() && rest.len() <= MAX_USTAR_NAME && prefix.len() <= MAX_USTAR_PREFIX
            {
                return Some((rest, prefix));
            }
        }
    }
    None
}

/// Builds a pax extended-header record: `"<len> key=value\n"`, where `len`
/// counts the whole record including its own digits.
fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
    // Everything but the leading length digits: a space, the key, `=`, the
    // value, and a newline.
    let content = 1 + key.len() + 1 + value.len() + 1;
    let mut len = content + 1;
    loop {
        let total = decimal_len(len) + content;
        if total == len {
            break;
        }
        len = total;
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(len.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(key);
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

/// The number of decimal digits in `n`.
fn decimal_len(n: usize) -> usize {
    let mut digits = 1;
    let mut v = n;
    while v >= 10 {
        v /= 10;
        digits += 1;
    }
    digits
}

// Frame decoding: the little-endian shapes the child emits.

fn read_u8(reader: &mut impl Read) -> io::Result<u8> {
    let mut b = [0u8; 1];
    reader.read_exact(&mut b)?;
    Ok(b[0])
}

fn read_u16(reader: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    reader.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    reader.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_i32(reader: &mut impl Read) -> io::Result<i32> {
    let mut b = [0u8; 4];
    reader.read_exact(&mut b)?;
    Ok(i32::from_le_bytes(b))
}

fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    let mut b = [0u8; 8];
    reader.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn read_i64(reader: &mut impl Read) -> io::Result<i64> {
    let mut b = [0u8; 8];
    reader.read_exact(&mut b)?;
    Ok(i64::from_le_bytes(b))
}

/// Reads a `u16`-length-prefixed byte string.
///
/// Named for the shape rather than for this side of the pipe, so it matches the
/// child's `frame::read_bytes_u16` that wrote it. The `Read` bound is what
/// keeps these separate from the child's descriptor-based readers: the archive
/// writer is fed from a reader in the tests as well as from the child's pipe.
fn read_bytes_u16(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let len = read_u16(reader)? as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Reads the xattr block — a count, then each name and its value — and sorts it
/// by name so the emitted `SCHILY.xattr.*` records do not depend on the order
/// the source filesystem lists attributes in.
///
/// An attribute the host assigns rather than the tree carries is read off the
/// stream and dropped; see [`containment::host_assigned_xattr`].
fn read_xattrs(reader: &mut impl Read) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let count = read_u16(reader)? as usize;
    let mut xattrs = Vec::with_capacity(count);
    for _ in 0..count {
        let name = read_bytes_u16(reader)?;
        let value_len = read_u32(reader)? as usize;
        let mut value = vec![0u8; value_len];
        reader.read_exact(&mut value)?;
        if !containment::host_assigned_xattr(&name) {
            xattrs.push((name, value));
        }
    }
    xattrs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(xattrs)
}

/// Reads a directory or file metadata frame (the tag already consumed).
fn read_meta(reader: &mut impl Read, is_file: bool) -> io::Result<Meta> {
    let name = read_bytes_u16(reader)?;
    let mode = read_u32(reader)?;
    let uid = read_u32(reader)?;
    let gid = read_u32(reader)?;
    let mtime = read_i64(reader)?;
    let (size, dev, ino, nlink) = if is_file {
        (
            read_u64(reader)?,
            read_u64(reader)?,
            read_u64(reader)?,
            read_u64(reader)?,
        )
    } else {
        (0, 0, 0, 0)
    };
    let xattrs = read_xattrs(reader)?;
    Ok(Meta {
        name,
        mode,
        uid,
        gid,
        mtime,
        size,
        dev,
        ino,
        nlink,
        link_target: Vec::new(),
        xattrs,
    })
}

/// Reads a symlink metadata frame (the tag already consumed).
fn read_symlink(reader: &mut impl Read) -> io::Result<Meta> {
    let name = read_bytes_u16(reader)?;
    let mode = read_u32(reader)?;
    let uid = read_u32(reader)?;
    let gid = read_u32(reader)?;
    let mtime = read_i64(reader)?;
    let link_target = read_bytes_u16(reader)?;
    Ok(Meta {
        name,
        mode,
        uid,
        gid,
        mtime,
        size: 0,
        dev: 0,
        ino: 0,
        nlink: 0,
        link_target,
        // A symlink frame carries no attribute block; the child emits none for
        // the reason `Export`'s documentation gives.
        xattrs: Vec::new(),
    })
}

/// Reads an error frame: a step discriminant and an errno.
fn read_error(reader: &mut impl Read) -> io::Result<(u32, i32)> {
    let step = read_u32(reader)?;
    let errno = read_i32(reader)?;
    Ok((step, errno))
}

#[cfg(test)]
mod tests {
    use super::super::tar::TarReader;
    use super::*;

    /// Encodes one entry through a `TarWriter` and parses it back with the
    /// crate's own reader, so the writer is checked against the reader it is
    /// symmetric with.
    fn meta(name: &str, mode: u32, uid: u32, gid: u32) -> Meta {
        Meta {
            name: name.as_bytes().to_vec(),
            mode,
            uid,
            gid,
            mtime: 1_700_000_000,
            size: 0,
            dev: 0,
            ino: 0,
            nlink: 0,
            link_target: Vec::new(),
            xattrs: Vec::new(),
        }
    }

    #[test]
    fn ownership_and_mode_round_trip() {
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None, None);
            let m = meta("etc", 0o755, 0, 0);
            tar.enter_dir(&m).unwrap();
            let mut f = meta("shadow", 0o640, 0, 42);
            f.size = 5;
            f.nlink = 1;
            tar.file(&f, &mut &b"1234\n"[..]).unwrap();
            tar.leave_dir();
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        let dir = reader.next_entry().unwrap().unwrap();
        assert_eq!(dir.path, b"etc/");
        assert_eq!(dir.typeflag, b'5');
        let file = reader.next_entry().unwrap().unwrap();
        assert_eq!(file.path, b"etc/shadow");
        assert_eq!(file.uid, 0);
        assert_eq!(file.gid, 42);
        assert_eq!(file.mode, 0o640);
        assert_eq!(file.size, 5);
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn an_id_past_the_octal_field_survives_through_a_pax_record() {
        // A range map's extents can reach past the seven octal digits a ustar
        // header has for an id. Such an id is carried in a pax record, and the
        // header's own field holds a placeholder that is not root's.
        let large = MAX_USTAR_ID + 1;
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None, None);
            let mut f = meta("f", 0o644, large, u32::MAX);
            f.nlink = 1;
            tar.file(&f, &mut &b""[..]).unwrap();
            let mut g = meta("g", 0o644, MAX_USTAR_ID, 7);
            g.nlink = 1;
            tar.file(&g, &mut &b""[..]).unwrap();
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        let file = reader.next_entry().unwrap().unwrap();
        assert_eq!((file.uid, file.gid), (large, u32::MAX));
        let within = reader.next_entry().unwrap().unwrap();
        assert_eq!((within.uid, within.gid), (MAX_USTAR_ID, 7));
        assert!(reader.next_entry().unwrap().is_none());

        // The header block of the first entry, after its pax header and data,
        // holds the clamped placeholder.
        let header = &buf[2 * BLOCK as usize..3 * BLOCK as usize];
        assert_eq!(&header[108..116], b"7777777\0", "the clamped uid field");
    }

    #[test]
    fn a_symlink_round_trips_its_target() {
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None, None);
            let mut m = meta("sh", 0o777, 0, 0);
            m.link_target = b"bin/busybox".to_vec();
            tar.symlink(&m).unwrap();
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        let link = reader.next_entry().unwrap().unwrap();
        assert_eq!(link.path, b"sh");
        assert_eq!(link.typeflag, b'2');
        assert_eq!(link.link_target, b"bin/busybox");
    }

    #[test]
    fn a_second_link_becomes_a_hardlink() {
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None, None);
            let mut a = meta("a", 0o644, 0, 0);
            a.size = 3;
            a.dev = 7;
            a.ino = 99;
            a.nlink = 2;
            tar.file(&a, &mut &b"abc"[..]).unwrap();
            let mut b = meta("b", 0o644, 0, 0);
            b.size = 3;
            b.dev = 7;
            b.ino = 99;
            b.nlink = 2;
            tar.file(&b, &mut &b"abc"[..]).unwrap();
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        let first = reader.next_entry().unwrap().unwrap();
        assert_eq!(first.path, b"a");
        assert_eq!(first.typeflag, b'0');
        let second = reader.next_entry().unwrap().unwrap();
        assert_eq!(second.path, b"b");
        assert_eq!(second.typeflag, b'1');
        assert_eq!(second.link_target, b"a");
    }

    #[test]
    fn a_long_path_round_trips_through_a_pax_record() {
        let long = format!("{}/leaf", "d".repeat(200));
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None, None);
            let mut f = meta("leaf", 0o644, 0, 0);
            // Bypass the stack to force a path longer than the ustar fields.
            f.name = long.as_bytes().to_vec();
            f.size = 0;
            f.nlink = 1;
            tar.write_entry(long.as_bytes(), b'0', &f, 0, &[], &[])
                .unwrap();
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        let entry = reader.next_entry().unwrap().unwrap();
        assert_eq!(entry.path, long.as_bytes());
    }

    #[test]
    fn pax_record_length_is_self_counting() {
        // "SCHILY.xattr.security.capability" = 32-byte value, per the spec's
        // self-referential length.
        let record = pax_record(b"path", b"x");
        // "9 path=x\n" — the 9 counts the whole record, itself included.
        assert_eq!(record, b"9 path=x\n");
        // A record whose length crosses a digit boundary still self-counts.
        let value = "y".repeat(90);
        let record = pax_record(b"path", value.as_bytes());
        let space = record.iter().position(|b| *b == b' ').unwrap();
        let declared: usize = std::str::from_utf8(&record[..space])
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(declared, record.len());
    }

    #[test]
    fn split_name_prefers_a_fitting_split() {
        let short = b"etc/passwd";
        assert_eq!(split_name(short), Some((&short[..], &[][..])));
        let long = format!("{}/{}", "a".repeat(120), "b".repeat(50));
        let (name, prefix) = split_name(long.as_bytes()).unwrap();
        assert_eq!(prefix.len(), 120);
        assert_eq!(name.len(), 50);
        // No interior slash within reach: no split.
        let unsplittable = "c".repeat(160);
        assert!(split_name(unsplittable.as_bytes()).is_none());
    }

    #[test]
    fn mtime_clamps_to_the_epoch() {
        // A modification time later than the epoch is pulled down to it; an
        // earlier one is preserved; no epoch records the real time.
        fn exported_mtime(entry_mtime: i64, epoch: Option<i64>) -> i64 {
            let mut buf = Vec::new();
            {
                let mut tar = TarWriter::new(&mut buf, epoch, None);
                let mut f = meta("f", 0o644, 0, 0);
                f.mtime = entry_mtime;
                f.nlink = 1;
                tar.file(&f, &mut &b""[..]).unwrap();
                tar.finish().unwrap();
            }
            TarReader::new(&buf[..])
                .next_entry()
                .unwrap()
                .unwrap()
                .mtime
        }
        let epoch = 1_600_000_000;
        assert_eq!(exported_mtime(1_700_000_000, Some(epoch)), epoch);
        assert_eq!(exported_mtime(1_500_000_000, Some(epoch)), 1_500_000_000);
        assert_eq!(exported_mtime(1_700_000_000, None), 1_700_000_000);
    }

    #[test]
    fn an_out_of_range_mtime_survives_through_a_pax_record() {
        // A time the ustar field cannot hold — far past 2242, or pre-1970 and
        // negative — is carried in a pax `mtime` record rather than aborting the
        // export or silently clamping to the epoch.
        fn exported_mtime(entry_mtime: i64) -> i64 {
            let mut buf = Vec::new();
            {
                let mut tar = TarWriter::new(&mut buf, None, None);
                let mut f = meta("f", 0o644, 0, 0);
                f.mtime = entry_mtime;
                f.nlink = 1;
                tar.file(&f, &mut &b""[..]).unwrap();
                tar.finish().unwrap();
            }
            TarReader::new(&buf[..])
                .next_entry()
                .unwrap()
                .unwrap()
                .mtime
        }
        let far_future = MAX_USTAR_MTIME + 1_000;
        assert_eq!(exported_mtime(far_future), far_future);
        assert_eq!(exported_mtime(-100_000), -100_000);
        // A time exactly at the field ceiling still fits the ustar header.
        assert_eq!(exported_mtime(MAX_USTAR_MTIME), MAX_USTAR_MTIME);
    }

    #[test]
    fn xattrs_decode_in_sorted_order() {
        // The child lists attributes in the filesystem's order; the decoder
        // sorts them by name so the emitted records are deterministic.
        let mut frame = Vec::new();
        frame.extend_from_slice(&2u16.to_le_bytes());
        for (name, value) in [(&b"user.zzz"[..], &b"1"[..]), (b"user.aaa", b"2")] {
            frame.extend_from_slice(&(name.len() as u16).to_le_bytes());
            frame.extend_from_slice(name);
            frame.extend_from_slice(&(value.len() as u32).to_le_bytes());
            frame.extend_from_slice(value);
        }
        let xattrs = read_xattrs(&mut &frame[..]).unwrap();
        let names: Vec<&[u8]> = xattrs.iter().map(|(n, _)| n.as_slice()).collect();
        assert_eq!(names, [&b"user.aaa"[..], &b"user.zzz"[..]]);
    }

    #[test]
    fn attributes_the_host_assigns_are_left_out() {
        // A label, a measurement, and an overlay's bookkeeping describe the
        // host the tree sat on; a capability and an ACL are the tree's own.
        let mut frame = Vec::new();
        let attributes: [(&[u8], &[u8]); 7] = [
            (b"security.selinux", b"system_u:object_r:usr_t:s0"),
            (b"security.SMACK64", b"_"),
            (b"security.ima", b"\x04\x04"),
            (b"user.overlay.origin", b"\x00\xfb"),
            (b"security.capability", b"\x01\x00\x00\x02"),
            (b"system.posix_acl_access", b"\x02\x00"),
            (b"user.mime_type", b"text/plain"),
        ];
        frame.extend_from_slice(&(attributes.len() as u16).to_le_bytes());
        for (name, value) in attributes {
            frame.extend_from_slice(&(name.len() as u16).to_le_bytes());
            frame.extend_from_slice(name);
            frame.extend_from_slice(&(value.len() as u32).to_le_bytes());
            frame.extend_from_slice(value);
        }
        // A trailing byte, so a drop that misread the stream shows up as one
        // left unread.
        frame.push(0xee);
        let mut reader = &frame[..];
        let xattrs = read_xattrs(&mut reader).unwrap();
        let names: Vec<&[u8]> = xattrs.iter().map(|(n, _)| n.as_slice()).collect();
        assert_eq!(
            names,
            [
                &b"security.capability"[..],
                b"system.posix_acl_access",
                b"user.mime_type"
            ]
        );
        assert_eq!(
            reader,
            [0xee],
            "the dropped attributes were not read off the stream"
        );
    }

    #[test]
    fn a_filter_drops_the_entries_it_refuses() {
        // The dropped file carries data, so this also pins that the frame
        // stream stays in step: the entry after it decodes correctly.
        let keep = |entry: &ExportEntry<'_>| entry.path() != Path::new("/etc/secret");
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None, Some(&keep));
            tar.enter_dir(&meta("etc", 0o755, 0, 0)).unwrap();
            let mut secret = meta("secret", 0o600, 0, 0);
            secret.size = 6;
            secret.nlink = 1;
            tar.file(&secret, &mut &b"hunter"[..]).unwrap();
            let mut kept = meta("hostname", 0o644, 0, 0);
            kept.size = 3;
            kept.nlink = 1;
            tar.file(&kept, &mut &b"box"[..]).unwrap();
            tar.leave_dir();
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        assert_eq!(reader.next_entry().unwrap().unwrap().path, b"etc/");
        let file = reader.next_entry().unwrap().unwrap();
        assert_eq!(file.path, b"etc/hostname");
        assert_eq!(file.size, 3);
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn excluding_a_directory_excludes_its_subtree_unasked() {
        // The whole point of the prune: one rule names the top of a subtree and
        // nothing under it is offered, so the rule does not have to be restated
        // for every descendant.
        let seen = std::sync::Mutex::new(Vec::new());
        let keep = |entry: &ExportEntry<'_>| {
            seen.lock()
                .unwrap()
                .push(entry.path().display().to_string());
            entry.path() != Path::new("/var/cache")
        };
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None, Some(&keep));
            tar.enter_dir(&meta("var", 0o755, 0, 0)).unwrap();
            tar.enter_dir(&meta("cache", 0o755, 0, 0)).unwrap();
            tar.enter_dir(&meta("apt", 0o755, 0, 0)).unwrap();
            let mut deb = meta("a.deb", 0o644, 0, 0);
            deb.size = 4;
            deb.nlink = 1;
            tar.file(&deb, &mut &b"data"[..]).unwrap();
            tar.leave_dir();
            let mut link = meta("latest", 0o777, 0, 0);
            link.link_target = b"apt"[..].to_vec();
            tar.symlink(&link).unwrap();
            tar.leave_dir();
            tar.enter_dir(&meta("lib", 0o755, 0, 0)).unwrap();
            tar.leave_dir();
            tar.leave_dir();
            tar.finish().unwrap();
        }
        // Consulted about the two directories it reached and the one it kept
        // descending into -- never about anything under the excluded one.
        assert_eq!(
            *seen.lock().unwrap(),
            ["/var", "/var/cache", "/var/lib"],
            "descendants of an excluded directory must not be offered"
        );
        let mut reader = TarReader::new(&buf[..]);
        let paths: Vec<Vec<u8>> = std::iter::from_fn(|| reader.next_entry().unwrap())
            .map(|e| e.path)
            .collect();
        assert_eq!(paths, [b"var/".to_vec(), b"var/lib/".to_vec()]);
    }

    #[test]
    fn a_filtered_first_link_leaves_the_next_carrying_the_data() {
        // A hardlink is offered as a file, and the encoder's choice of which
        // name carries the bytes follows the filter: dropping the first name
        // must not leave the second pointing at a member that is not there.
        let keep = |entry: &ExportEntry<'_>| entry.path() != Path::new("/a");
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None, Some(&keep));
            for name in ["a", "b", "c"] {
                let mut m = meta(name, 0o644, 0, 0);
                m.size = 3;
                m.dev = 7;
                m.ino = 99;
                m.nlink = 3;
                tar.file(&m, &mut &b"abc"[..]).unwrap();
            }
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        let first = reader.next_entry().unwrap().unwrap();
        assert_eq!(first.path, b"b");
        assert_eq!(first.typeflag, b'0', "the first kept name carries the data");
        let second = reader.next_entry().unwrap().unwrap();
        assert_eq!(second.path, b"c");
        assert_eq!(second.typeflag, b'1');
        assert_eq!(second.link_target, b"b");
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn the_filter_sees_the_entry_the_rootfs_intends() {
        // The ownership is the in-map one, the mode carries no type bits (which
        // `kind` answers for), and the time is the entry's own rather than the
        // clamped one -- filtering decides what the archive holds, clamping
        // decides how it is recorded.
        let seen = std::sync::Mutex::new(Vec::new());
        let keep = |entry: &ExportEntry<'_>| {
            seen.lock().unwrap().push((
                entry.path().display().to_string(),
                entry.kind(),
                entry.mode(),
                entry.uid(),
                entry.gid(),
                entry.size(),
                entry.mtime(),
            ));
            true
        };
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, Some(1_600_000_000), Some(&keep));
            let mut dir = meta("etc", 0o755, 0, 0);
            dir.mode |= 0o040_000;
            tar.enter_dir(&dir).unwrap();
            let mut file = meta("shadow", 0o640, 0, 42);
            file.mode |= 0o100_000;
            file.size = 5;
            file.nlink = 1;
            tar.file(&file, &mut &b"1234\n"[..]).unwrap();
            let mut link = meta("sh", 0o777, 0, 0);
            link.mode |= 0o120_000;
            link.link_target = b"bin/busybox"[..].to_vec();
            tar.symlink(&link).unwrap();
            tar.leave_dir();
            tar.finish().unwrap();
        }
        assert_eq!(
            *seen.lock().unwrap(),
            [
                (
                    "/etc".to_string(),
                    ExportKind::Directory,
                    0o755,
                    0,
                    0,
                    0,
                    1_700_000_000
                ),
                (
                    "/etc/shadow".to_string(),
                    ExportKind::File,
                    0o640,
                    0,
                    42,
                    5,
                    1_700_000_000
                ),
                (
                    "/etc/sh".to_string(),
                    ExportKind::Symlink,
                    0o777,
                    0,
                    0,
                    0,
                    1_700_000_000
                ),
            ]
        );
    }

    #[test]
    fn an_unfiltered_export_writes_what_it_always_did() {
        // The default must be untouched: the filter is an addition, and an
        // export that names none pays nothing.
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None, None);
            tar.enter_dir(&meta("etc", 0o755, 0, 0)).unwrap();
            let mut f = meta("hostname", 0o644, 0, 0);
            f.size = 3;
            f.nlink = 1;
            tar.file(&f, &mut &b"box"[..]).unwrap();
            tar.leave_dir();
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        assert_eq!(reader.next_entry().unwrap().unwrap().path, b"etc/");
        assert_eq!(reader.next_entry().unwrap().unwrap().path, b"etc/hostname");
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn the_tree_is_spelled_absolutely_and_the_archive_is_not() {
        // The walk opens with a directory frame named `.` for the rootfs root,
        // which the archive carries as `./`. The filter is offered the same
        // entries spelled as locations inside the tree, so a rule reads the way
        // a mount target does and never has to know how tar spells a member.
        let seen = std::sync::Mutex::new(Vec::new());
        let keep = |entry: &ExportEntry<'_>| {
            seen.lock()
                .unwrap()
                .push(entry.path().display().to_string());
            true
        };
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None, Some(&keep));
            tar.enter_dir(&meta(".", 0o755, 0, 0)).unwrap();
            tar.enter_dir(&meta("etc", 0o755, 0, 0)).unwrap();
            tar.leave_dir();
            tar.leave_dir();
            tar.finish().unwrap();
        }
        assert_eq!(*seen.lock().unwrap(), ["/", "/etc"]);
        let mut reader = TarReader::new(&buf[..]);
        assert_eq!(reader.next_entry().unwrap().unwrap().path, b"./");
        assert_eq!(reader.next_entry().unwrap().unwrap().path, b"./etc/");
    }

    #[test]
    fn an_excluded_root_produces_an_empty_archive() {
        // Documented rather than special-cased: the root is an entry like any
        // other, so a filter that refuses everything refuses it too.
        let keep = |_: &ExportEntry<'_>| false;
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None, Some(&keep));
            tar.enter_dir(&meta(".", 0o755, 0, 0)).unwrap();
            tar.enter_dir(&meta("etc", 0o755, 0, 0)).unwrap();
            let mut f = meta("hostname", 0o644, 0, 0);
            f.size = 3;
            f.nlink = 1;
            tar.file(&f, &mut &b"box"[..]).unwrap();
            tar.leave_dir();
            tar.leave_dir();
            tar.finish().unwrap();
        }
        assert!(TarReader::new(&buf[..]).next_entry().unwrap().is_none());
    }

    /// A metadata frame for a regular file named `name` holding `data`,
    /// followed by the data and the child's status byte.
    fn file_frame(name: &[u8], data: &[u8], status: u8) -> Vec<u8> {
        let mut frame = vec![FRAME_FILE];
        frame.extend_from_slice(&(name.len() as u16).to_le_bytes());
        frame.extend_from_slice(name);
        frame.extend_from_slice(&0o100_644u32.to_le_bytes());
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame.extend_from_slice(&1_700_000_000i64.to_le_bytes());
        frame.extend_from_slice(&(data.len() as u64).to_le_bytes());
        frame.extend_from_slice(&7u64.to_le_bytes());
        frame.extend_from_slice(&99u64.to_le_bytes());
        frame.extend_from_slice(&1u64.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(data);
        frame.push(status);
        frame
    }

    /// Runs `frames`, opened by the root's own directory frame, through the
    /// encoder as the child's stream.
    fn drive_frames(
        frames: &[u8],
        filter: Option<&EntryPredicate<'_>>,
    ) -> Result<(), ProvisionError> {
        let mut stream = vec![FRAME_DIR];
        stream.extend_from_slice(&1u16.to_le_bytes());
        stream.push(b'.');
        stream.extend_from_slice(&0o40_755u32.to_le_bytes());
        stream.extend_from_slice(&[0; 8]);
        stream.extend_from_slice(&1_700_000_000i64.to_le_bytes());
        stream.extend_from_slice(&0u16.to_le_bytes());
        stream.extend_from_slice(frames);
        stream.push(FRAME_LEAVE);
        stream.push(FRAME_END);
        let (read, write) = rustix::pipe::pipe().expect("a pipe is creatable");
        rustix::io::write(&write, &stream).expect("the frames fit the pipe");
        drop(write);
        drive(
            std::os::fd::AsFd::as_fd(&read),
            io::sink(),
            Path::new("/srv/rootfs"),
            None,
            filter,
        )
    }

    #[test]
    fn a_file_the_child_saw_change_fails_the_export_naming_it() {
        // The child streams the size it recorded whatever the file held, so the
        // archive would carry a cut or padded file; its status byte is what
        // says so, and the export reports the file rather than the archive.
        drive_frames(&file_frame(b"intact", b"abc", 0), None).expect("an intact file exports");
        match drive_frames(&file_frame(b"grew", b"abc", 1), None) {
            Err(ProvisionError::SourceChanged { path, recorded }) => {
                assert_eq!(path, Path::new("/srv/rootfs/grew"));
                assert_eq!(recorded, 3);
            }
            other => panic!("expected a changed source, got {other:?}"),
        }
        // An excluded file adds nothing to the archive, so its change does not
        // matter to it.
        let keep = |entry: &ExportEntry<'_>| entry.path() != Path::new("/grew");
        drive_frames(&file_frame(b"grew", b"abc", 1), Some(&keep))
            .expect("an excluded file's change is not the archive's");
    }

    #[test]
    fn the_filter_renders_in_the_debug_by_its_presence() {
        // A caller's closure has nothing to show, so it is rendered the way the
        // identity-map delegate beside it is: present or absent.
        let plain = format!("{:?}", Export::new("/tmp/rootfs"));
        assert!(plain.contains("filter: None"), "{plain}");
        let filtered = format!("{:?}", Export::new("/tmp/rootfs").filter(|_| true));
        assert!(filtered.contains("filter: Some(<dyn Fn>)"), "{filtered}");
    }
}
