//! What a run wrote through an overlay, read from its upper as a list of
//! changes against its lowers.
//!
//! An overlay keeps the lowers as they were and records every write in the
//! upper: a new or changed entry whole, a deletion as a whiteout, a directory
//! that replaced what the lowers held as an opaque one. [`ChangeSet::read`]
//! turns that record back into what changed, path by path, by asking the
//! lowers what each path held before the run.
//!
//! The upper is written by the command a sandbox confined, so the reader
//! treats it as a tree nothing vouches for. It is walked by descriptor, each
//! name resolved against the directory that holds it and never through a
//! symbolic link, as [`CopyIn`](super::CopyIn) walks a source. The lowers are
//! descended the same way, in step with the upper.

mod apply;
mod fork;

pub use apply::{Apply, ApplyRefusal, ApplyRefusalReason, ApplyReport, Protected};

use std::ffi::{CStr, CString, OsStr};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rustix::fs::{self, AtFlags, FileType, OFlags, Stat};
use rustix::io::Errno;

use super::ProvisionError;
use super::containment;
use super::copyin::{by_path, read_names};
use super::xattr::{self, Holder};
use crate::mechanism::bounds::LINK_BUF;
use crate::mechanism::frame;
use crate::{Overlay, OverlayLayer};

/// What a run wrote through an overlay: each path its upper changed, against
/// what the overlay's lowers held there.
///
/// Read from an [`Overlay`] with [`read`](Self::read). The list holds one
/// [`Change`] per path the merged view shows differently from the lowers
/// alone, sorted by path:
///
/// - **added**: no lower shows an entry at the path;
/// - **modified**: a lower shows an entry of the same type, and the run's
///   differs from it in content, mode, owner, or extended attributes, each of
///   which the change names;
/// - **removed**: the run deleted what a lower shows. A removed directory is
///   one change, its contents with it;
/// - **replaced**: the entry's type changed, a file become a directory, or a
///   directory a symbolic link.
///
/// An entry beneath an added or replaced directory is a change of its own,
/// added. A directory the overlay copied up only because something beneath it
/// changed is not a change, nor is a file rewritten with the bytes it had, nor
/// a change of times alone: the merged view shows each as the lowers do.
///
/// # What is compared
///
/// Content is a file's bytes, compared only where the sizes match, and a
/// symbolic link's target. The mode is the permission and set-id bits. The
/// owner is the uid and gid as the host stores them. The extended attributes
/// are compared without those the host assigns rather than the tree carries,
/// which include the overlay's own bookkeeping: an attribute a command named
/// `user.overlay.` is one the overlay keeps under another name, and is never a
/// difference.
///
/// # What the reader refuses
///
/// No overlay this library mounts records a renamed directory as a redirect, a
/// change of metadata alone as a metadata-only copy, or a deletion as anything
/// but a character device numbered 0:0: it mounts with `userxattr`, under which
/// the kernel creates none of them. A layer holding one came from elsewhere, and
/// the reader would read it otherwise than the kernel does, so
/// [`read`](Self::read) refuses it with [`ProvisionError::EntryRefused`],
/// naming the entry and the record.
///
/// # What the reader cannot read
///
/// The run can leave an entry the caller cannot read, such as a file of mode
/// `000`. Such an entry is listed with what the reader could learn, and
/// [`Change::is_readable`] says it is incomplete: a file's content compared as
/// differing, a directory's entries unlisted.
///
/// # When to read it
///
/// The list is what the upper holds when it is read. Reading an upper while a
/// sandbox has its overlay mounted is sound, so the changes of a session can be
/// read between its commands; while a command is writing, they are the changes
/// of a tree in motion.
///
/// [`Remove::overlay_upper`](super::Remove::overlay_upper) discards a change
/// set, with the upper and the work directory beside it.
///
/// # Example
///
/// ```no_run
/// use ferroday_cage::Overlay;
/// use ferroday_cage::provision::ChangeSet;
///
/// # fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
/// let overlay = Overlay::new()
///     .lower("/home/user/project")
///     .upper("/home/user/.cache/runs/1/upper");
/// for change in ChangeSet::read(&overlay)?.changes() {
///     println!("{:?} {}", change.kind(), change.path().display());
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ChangeSet {
    upper: PathBuf,
    lowers: Vec<PathBuf>,
    changes: Vec<Change>,
    /// When the upper was created, where its filesystem records it: the
    /// default reference an apply holds the target's changes to.
    born: Option<SystemTime>,
}

impl ChangeSet {
    /// Reads what `overlay`'s upper changed against its lowers.
    ///
    /// The overlay names at least one lower and an upper, as one a sandbox
    /// mounts does; one that names neither is refused with
    /// [`ProvisionError::OverlayLayerMissing`]. Every layer must be a directory
    /// the caller can open.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::OverlayLayerMissing`] for a layer the overlay does not
    /// name, [`ProvisionError::EntryRefused`] for a layer holding a record the
    /// reader would read otherwise than the kernel, and
    /// [`ProvisionError::Io`] for a layer or an entry the walk could not read
    /// where it had to.
    pub fn read(overlay: &Overlay) -> Result<ChangeSet, ProvisionError> {
        let upper = overlay
            .get_upper()
            .ok_or(ProvisionError::OverlayLayerMissing {
                layer: OverlayLayer::Upper,
            })?;
        if overlay.get_lowers().is_empty() {
            return Err(ProvisionError::OverlayLayerMissing {
                layer: OverlayLayer::Lower,
            });
        }
        let upper_fd = open_layer(upper)?;
        let born = birth_time(upper_fd.as_fd())
            .map_err(|errno| ProvisionError::io("reading", upper, errno.into()))?;
        // The lowers in the order the kernel consults them: the last stacked
        // first, the base last.
        let lower_fds = overlay
            .get_lowers()
            .iter()
            .rev()
            .map(|lower| open_layer(lower).map(|fd| Lower { fd, layer: lower }))
            .collect::<Result<Vec<_>, _>>()?;
        let mut reader = Reader {
            changes: Vec::new(),
        };
        reader.walk(upper_fd, lower_fds)?;
        Ok(ChangeSet {
            upper: upper.to_path_buf(),
            lowers: overlay.get_lowers().to_vec(),
            changes: reader.changes,
            born,
        })
    }

    /// The changes, sorted by path.
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }

    /// Whether the run changed nothing the merged view shows.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The upper the changes were read from, as the overlay named it.
    pub fn get_upper(&self) -> &Path {
        &self.upper
    }

    /// The lowers the changes were read against, base first, as the overlay
    /// named them.
    pub fn get_lowers(&self) -> &[PathBuf] {
        &self.lowers
    }
}

/// One path a run changed, as a [`ChangeSet`] lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    path: PathBuf,
    before: Option<EntryKind>,
    now: Option<EntryKind>,
    size: Option<u64>,
    differs: Differs,
    readable: bool,
    /// The upper's entry as the reader found it, for an entry the merged view
    /// holds now: what an apply holds the upper to, so it writes what was
    /// read and not what a run went on to write.
    upper: Option<UpperEntry>,
    /// The target of the symbolic link the merged view holds now, as the reader
    /// read it: what an apply judges, and writes, while the upper still holds
    /// the link it was read from.
    link: Option<Vec<u8>>,
}

/// An upper entry as the reader found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpperEntry {
    /// Its device and inode, which tell two names of one file apart from two
    /// files.
    dev: u64,
    ino: u64,
    /// Its link count.
    nlink: u64,
    /// Its permission and set-id bits.
    mode: u32,
    /// Its change time, seconds and nanoseconds, which any write to it moves.
    ctime: (i64, i64),
}

impl UpperEntry {
    fn of(stat: &Stat) -> UpperEntry {
        // `st_nlink` is 32 bits on some architectures and 64 on others, so the
        // conversion is a widening on one and the identity on the other. `allow`
        // rather than `expect`, for the reason the export's link count gives.
        #[allow(clippy::useless_conversion)]
        let nlink = u64::from(stat.st_nlink);
        UpperEntry {
            dev: stat.st_dev,
            ino: stat.st_ino,
            nlink,
            mode: stat.st_mode & 0o7777,
            ctime: (stat.st_ctime, stat.st_ctime_nsec as i64),
        }
    }

    /// Whether `stat` is still this entry, unchanged since it was read.
    fn holds(&self, stat: &Stat) -> bool {
        let now = UpperEntry::of(stat);
        (now.dev, now.ino, now.ctime) == (self.dev, self.ino, self.ctime)
    }
}

impl Change {
    /// Where the change is, relative to the top of the overlay: `src/main.rs`
    /// for a file the overlay shows at `src/main.rs` beneath its target.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What kind of change it is.
    pub fn kind(&self) -> ChangeKind {
        match (self.before, self.now) {
            (None, _) => ChangeKind::Added,
            (_, None) => ChangeKind::Removed,
            (Some(before), Some(now)) if before == now => ChangeKind::Modified,
            (Some(_), Some(_)) => ChangeKind::Replaced,
        }
    }

    /// What the lowers held at the path, or `None` for an added entry.
    pub fn before(&self) -> Option<EntryKind> {
        self.before
    }

    /// What the merged view holds at the path now, or `None` for a removed
    /// entry.
    pub fn now(&self) -> Option<EntryKind> {
        self.now
    }

    /// The size of the file the merged view holds now, or `None` where it holds
    /// no file. A sparse file's size is its length, holes included.
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Whether a modified entry's content differs: a file's bytes, or a
    /// symbolic link's target. `false` for every other kind of change.
    pub fn content_differs(&self) -> bool {
        self.differs.content
    }

    /// Whether a modified entry's permission or set-id bits differ.
    pub fn mode_differs(&self) -> bool {
        self.differs.mode
    }

    /// Whether a modified entry's uid or gid differs.
    pub fn owner_differs(&self) -> bool {
        self.differs.owner
    }

    /// Whether a modified entry's extended attributes differ, those the host
    /// assigns left out.
    pub fn attributes_differ(&self) -> bool {
        self.differs.attributes
    }

    /// Whether the reader read everything the change rests on.
    ///
    /// `false` where the run left something the caller cannot read: a file
    /// whose content is then counted as differing, a directory whose entries
    /// are not listed, or attributes not compared.
    pub fn is_readable(&self) -> bool {
        self.readable
    }

    /// The target of the symbolic link the merged view holds now, as the
    /// reader read it, or `None` where it holds no link.
    pub(super) fn link(&self) -> Option<&[u8]> {
        self.link.as_deref()
    }
}

/// The kind of a [`Change`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChangeKind {
    /// No lower shows an entry at the path.
    Added,
    /// A lower shows an entry of the same type, and the run's differs from it.
    Modified,
    /// The run deleted what a lower shows.
    Removed,
    /// The entry's type changed.
    Replaced,
}

/// The type of an entry a [`Change`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A named pipe, a socket, or a device.
    Other,
}

impl EntryKind {
    /// The kind of the entry `stat` describes.
    fn of(stat: &Stat) -> EntryKind {
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => EntryKind::File,
            FileType::Directory => EntryKind::Directory,
            FileType::Symlink => EntryKind::Symlink,
            _ => EntryKind::Other,
        }
    }
}

/// What a modified entry differs from the lowers' in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Differs {
    content: bool,
    mode: bool,
    owner: bool,
    attributes: bool,
}

impl Differs {
    fn any(&self) -> bool {
        self.content || self.mode || self.owner || self.attributes
    }
}

/// One lower layer the walk descends: a directory of it, and the layer's path,
/// which names it in a failure.
struct Lower<'a> {
    fd: OwnedFd,
    layer: &'a Path,
}

/// One directory of the upper the walk is inside.
struct Level<'a> {
    /// The upper's directory.
    upper: OwnedFd,
    /// The lowers' directories at the same path, in the order the kernel
    /// consults them, as the lowers alone show the path: each lower holding a
    /// directory there that no lower above it hides.
    lowers: Vec<Lower<'a>>,
    /// The path, relative to the top of the overlay.
    path: PathBuf,
    /// Whether the merged view shows nothing of the lowers here: the upper's
    /// directory, or one above it, is opaque.
    opaque: bool,
    /// The names still to visit, sorted.
    items: std::vec::IntoIter<Item>,
}

/// One name a directory of the walk holds.
enum Item {
    /// A name the upper holds.
    Upper(Vec<u8>),
    /// A name only the lowers hold, beneath an opaque directory of the upper,
    /// where the merged view no longer shows it.
    Hidden(Vec<u8>, EntryKind),
}

impl Item {
    fn name(&self) -> &[u8] {
        match self {
            Item::Upper(name) | Item::Hidden(name, _) => name,
        }
    }
}

/// What the lowers alone show at a name, and the layer holding it.
struct Before {
    /// The entry's own `stat`.
    stat: Stat,
    /// Its index among the level's lowers.
    at: usize,
}

/// The state one read carries.
struct Reader {
    changes: Vec<Change>,
}

impl Reader {
    /// Walks the upper from its top, `upper`, against the lowers' tops,
    /// `lowers`.
    ///
    /// The walk carries its own stack rather than recursing, so an arbitrarily
    /// deep upper costs heap rather than call frames, and a run cannot make
    /// its changes unreadable by nesting directories deeply.
    fn walk<'a>(&mut self, upper: OwnedFd, lowers: Vec<Lower<'a>>) -> Result<(), ProvisionError> {
        let top = Path::new("");
        refuse_records(upper.as_fd(), top, Layer::Upper)?;
        for lower in &lowers {
            refuse_records(lower.fd.as_fd(), Path::new(""), Layer::Lower(lower.layer))?;
        }
        let opaque = containment::is_opaque(upper.as_fd())
            .map_err(|errno| ProvisionError::io("reading", top, errno.into()))?;
        let mut stack = vec![open_level(upper, lowers, PathBuf::new(), opaque)?];
        while let Some(at) = stack.len().checked_sub(1) {
            let Some(item) = stack[at].items.next() else {
                stack.pop();
                continue;
            };
            let level = &stack[at];
            let path = level.path.join(OsStr::from_bytes(item.name()));
            let name = CString::new(item.name()).map_err(|_| ProvisionError::EntryRefused {
                path: path.clone(),
                reason: "the entry name carries a NUL".to_string(),
            })?;
            let entry = match item {
                Item::Hidden(_, kind) => {
                    self.removed(path, kind);
                    continue;
                }
                Item::Upper(_) => level,
            };
            if let Some(next) = self.entry(entry, &name, path)? {
                stack.push(next);
            }
        }
        Ok(())
    }

    /// Lists what the upper holds at `name` in `level`, against what the lowers
    /// hold there, and returns the level to descend into where it is a
    /// directory whose entries the walk reads.
    fn entry<'a>(
        &mut self,
        level: &Level<'a>,
        name: &CStr,
        path: PathBuf,
    ) -> Result<Option<Level<'a>>, ProvisionError> {
        let stat = fs::statat(&level.upper, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|errno| ProvisionError::io("reading", &path, errno.into()))?;
        let before = lookup(&level.lowers, name, &path)?;
        if containment::is_whiteout(&stat) {
            if let Some(before) = before {
                self.removed(path, EntryKind::of(&before.stat));
            }
            return Ok(None);
        }
        let now = EntryKind::of(&stat);
        let mut change = Change {
            path,
            before: before.as_ref().map(|before| EntryKind::of(&before.stat)),
            now: Some(now),
            size: (now == EntryKind::File).then_some(stat.st_size as u64),
            differs: Differs::default(),
            readable: true,
            upper: Some(UpperEntry::of(&stat)),
            link: None,
        };

        // A directory is opened before anything else is asked of it, so the
        // directory compared and descended into is the one typed. One the
        // caller cannot both list and search is not descended into at all,
        // since its entries could be named and not read.
        let dir = match now {
            EntryKind::Directory if listable(level.upper.as_fd(), name) => Some(
                containment::open_child_dir(&level.upper, name, OFlags::RDONLY)
                    .map_err(|errno| ProvisionError::io("reading", &change.path, errno.into()))?,
            ),
            EntryKind::Directory => {
                change.readable = false;
                None
            }
            _ => None,
        };
        let held = Held {
            dir: level.upper.as_fd(),
            name,
            stat: &stat,
            opened: dir.as_ref().map(AsFd::as_fd),
        };
        let attributes = held.attributes(&change.path, Layer::Upper)?;
        if now == EntryKind::Symlink {
            change.link = Some(link_target(&held, &change.path)?);
        }
        let opaque = match &dir {
            Some(dir) => {
                level.opaque
                    || containment::is_opaque(dir.as_fd()).map_err(|errno| {
                        ProvisionError::io("reading", &change.path, errno.into())
                    })?
            }
            None => false,
        };

        match &before {
            Some(before) if change.before == change.now => {
                let lower = &level.lowers[before.at];
                let theirs = Held {
                    dir: lower.fd.as_fd(),
                    name,
                    stat: &before.stat,
                    opened: None,
                };
                let lower_attributes =
                    theirs.attributes(&change.path, Layer::Lower(lower.layer))?;
                // `None` where the caller could not read what the comparison
                // needs.
                let content = match now {
                    EntryKind::File if stat.st_size != before.stat.st_size => Some(true),
                    EntryKind::File => {
                        same_bytes(&held, &theirs, &change.path, lower.layer)?.map(|same| !same)
                    }
                    EntryKind::Symlink => Some(
                        change.link.as_deref()
                            != Some(&*link_target(&theirs, &lower.layer.join(&change.path))?),
                    ),
                    EntryKind::Directory | EntryKind::Other => Some(false),
                };
                let attributes_differ = match (&attributes, &lower_attributes) {
                    (Some(ours), Some(theirs)) => Some(ours != theirs),
                    _ => None,
                };
                change.readable &= content.is_some() && attributes_differ.is_some();
                change.differs = Differs {
                    // Content that could not be compared is counted as
                    // differing: what it holds is not known to match.
                    content: content.unwrap_or(true),
                    mode: stat.st_mode & 0o7777 != before.stat.st_mode & 0o7777,
                    owner: (stat.st_uid, stat.st_gid) != (before.stat.st_uid, before.stat.st_gid),
                    attributes: attributes_differ.unwrap_or(false),
                };
            }
            _ => change.readable &= attributes.is_some(),
        }

        let next = match dir {
            Some(dir) => {
                let lowers = match &before {
                    Some(before) if change.before == change.now => {
                        descend(&level.lowers, before.at, name, &change.path)?
                    }
                    _ => Vec::new(),
                };
                Some(open_level(dir, lowers, change.path.clone(), opaque)?)
            }
            None => None,
        };
        if change.before.is_none()
            || change.before != change.now
            || change.differs.any()
            || !change.readable
        {
            self.changes.push(change);
        }
        Ok(next)
    }

    /// Lists the removal of what the lowers held at `path`.
    fn removed(&mut self, path: PathBuf, before: EntryKind) {
        self.changes.push(Change {
            path,
            before: Some(before),
            now: None,
            size: None,
            differs: Differs::default(),
            readable: true,
            upper: None,
            link: None,
        });
    }
}

/// The level for the upper's directory `upper` at `path`: the names it holds,
/// and beneath an opaque directory the names only the lowers hold, sorted
/// together.
fn open_level<'a>(
    upper: OwnedFd,
    lowers: Vec<Lower<'a>>,
    path: PathBuf,
    opaque: bool,
) -> Result<Level<'a>, ProvisionError> {
    let mut names = read_names(upper.as_fd(), &path)?;
    names.sort();
    let mut items: Vec<Item> = Vec::with_capacity(names.len());
    if opaque && !lowers.is_empty() {
        let hidden: Vec<(Vec<u8>, EntryKind)> = lower_names(&lowers, &path)?
            .into_iter()
            .filter(|(name, _)| names.binary_search(name).is_err())
            .collect();
        let mut hidden = hidden.into_iter().peekable();
        for name in names {
            while let Some((other, kind)) = hidden.next_if(|(other, _)| *other < name) {
                items.push(Item::Hidden(other, kind));
            }
            items.push(Item::Upper(name));
        }
        items.extend(hidden.map(|(name, kind)| Item::Hidden(name, kind)));
    } else {
        items.extend(names.into_iter().map(Item::Upper));
    }
    Ok(Level {
        upper,
        lowers,
        path,
        opaque,
        items: items.into_iter(),
    })
}

/// Every name the lowers alone show in the directory they hold at `path`, with
/// its kind, sorted: the first lower holding a name decides it, and a whiteout
/// there hides it from those below.
fn lower_names(
    lowers: &[Lower<'_>],
    path: &Path,
) -> Result<Vec<(Vec<u8>, EntryKind)>, ProvisionError> {
    let mut seen: std::collections::BTreeMap<Vec<u8>, Option<EntryKind>> =
        std::collections::BTreeMap::new();
    for lower in lowers {
        for name in read_names(lower.fd.as_fd(), path)? {
            if seen.contains_key(&name) {
                continue;
            }
            let entry = path.join(OsStr::from_bytes(&name));
            let leaf = CString::new(name.clone()).map_err(|_| ProvisionError::EntryRefused {
                path: entry.clone(),
                reason: "the entry name carries a NUL".to_string(),
            })?;
            let stat =
                fs::statat(&lower.fd, &leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|errno| {
                    ProvisionError::io("reading", lower.layer.join(&entry), errno.into())
                })?;
            let kind = (!containment::is_whiteout(&stat)).then(|| EntryKind::of(&stat));
            seen.insert(name, kind);
        }
    }
    Ok(seen
        .into_iter()
        .filter_map(|(name, kind)| kind.map(|kind| (name, kind)))
        .collect())
}

/// What the lowers alone show at `name` in their directories `lowers`: the
/// first lower holding an entry there decides, a whiteout hiding it, or `None`
/// where none holds one.
///
/// The question [`merged_lookup`](super::rooted::merged_lookup) answers for a
/// path, answered here for one name in directories the walk holds open. That
/// lookup resolves the path's directories through `Rooted`, which follows a
/// symbolic link inside a layer; the merged view resolves a name, and the
/// reader descends each layer only through the directories it holds, so a
/// lower's link at a directory's name is a link, as it is to the kernel's
/// lookup, and not the directory it points at.
fn lookup(
    lowers: &[Lower<'_>],
    name: &CStr,
    path: &Path,
) -> Result<Option<Before>, ProvisionError> {
    for (at, lower) in lowers.iter().enumerate() {
        match fs::statat(&lower.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if containment::is_whiteout(&stat) => return Ok(None),
            Ok(stat) => return Ok(Some(Before { stat, at })),
            Err(Errno::NOENT) => {}
            Err(errno) => {
                return Err(ProvisionError::io(
                    "reading",
                    lower.layer.join(path),
                    errno.into(),
                ));
            }
        }
    }
    Ok(None)
}

/// The lowers' directories at `name`, from the lower at `from`, which holds
/// the directory the lowers show there, down through each lower below it that
/// also holds a directory there, stopping at an opaque one, a whiteout, or an
/// entry of another kind, as the kernel merges a directory.
fn descend<'a>(
    lowers: &[Lower<'a>],
    from: usize,
    name: &CStr,
    path: &Path,
) -> Result<Vec<Lower<'a>>, ProvisionError> {
    let mut found = Vec::new();
    for lower in &lowers[from..] {
        let fd = match containment::open_child_dir(&lower.fd, name, OFlags::RDONLY) {
            Ok(fd) => fd,
            Err(Errno::NOENT) if !found.is_empty() => continue,
            // A whiteout, a file, or a link holding the name: the lowers below
            // do not show through.
            Err(Errno::NOTDIR | Errno::LOOP | Errno::NXIO) if !found.is_empty() => break,
            Err(errno) => {
                return Err(ProvisionError::io(
                    "reading",
                    lower.layer.join(path),
                    errno.into(),
                ));
            }
        };
        refuse_records(fd.as_fd(), path, Layer::Lower(lower.layer))?;
        let opaque = containment::is_opaque(fd.as_fd())
            .map_err(|errno| ProvisionError::io("reading", lower.layer.join(path), errno.into()))?;
        found.push(Lower {
            fd,
            layer: lower.layer,
        });
        if opaque {
            break;
        }
    }
    Ok(found)
}

/// Which layer an entry the reader examines belongs to, for its failures.
#[derive(Clone, Copy)]
enum Layer<'a> {
    /// The upper, whose entries are named by their path in the overlay.
    Upper,
    /// A lower at this path, whose entries are named by their host path.
    Lower(&'a Path),
}

impl Layer<'_> {
    /// The path a failure names an entry at `path` by.
    fn name(&self, path: &Path) -> PathBuf {
        match self {
            Layer::Upper => path.to_path_buf(),
            Layer::Lower(layer) => layer.join(path),
        }
    }
}

/// An entry a layer holds: its directory, its name there, the `stat` the walk
/// took of it, and, for a directory, the descriptor the walk opened.
struct Held<'a> {
    dir: BorrowedFd<'a>,
    name: &'a CStr,
    stat: &'a Stat,
    opened: Option<BorrowedFd<'a>>,
}

impl Held<'_> {
    /// The entry's extended attributes, those the host assigns left out, or
    /// `None` where the caller cannot read them. Refuses an entry carrying a
    /// record the reader would read otherwise than the kernel.
    fn attributes(
        &self,
        path: &Path,
        layer: Layer<'_>,
    ) -> Result<Option<xattr::Named>, ProvisionError> {
        let read = match EntryKind::of(self.stat) {
            EntryKind::Directory => match self.opened {
                Some(dir) => xattr::read_all(Holder::Fd(dir)),
                None => match containment::open_child_dir(self.dir, self.name, OFlags::RDONLY) {
                    Ok(dir) => xattr::read_all(Holder::Fd(dir.as_fd())),
                    Err(errno) => Err(errno),
                },
            },
            EntryKind::File => {
                match containment::open_typed_file(self.dir, self.name, self.stat, OFlags::RDONLY) {
                    Ok(file) => xattr::read_all(Holder::Fd(file.as_fd())),
                    Err(errno) => Err(errno),
                }
            }
            // A link, a pipe, a socket or a device is asked by path, without
            // following the link or opening the pipe.
            EntryKind::Symlink | EntryKind::Other => {
                let named = by_path(self.dir, self.name.to_bytes(), &layer.name(path))?;
                xattr::read_all(Holder::Path(&named))
            }
        };
        let named = match read {
            Ok(named) => named,
            Err(Errno::ACCESS) => return Ok(None),
            Err(Errno::STALE) => {
                return Err(ProvisionError::SourceChanged {
                    path: layer.name(path),
                    recorded: self.stat.st_size as u64,
                });
            }
            Err(errno) => {
                return Err(ProvisionError::io(
                    "reading",
                    layer.name(path),
                    errno.into(),
                ));
            }
        };
        if let Some(record) = named
            .iter()
            .find_map(|(name, value)| misread_record(name, value))
        {
            return Err(ProvisionError::EntryRefused {
                path: layer.name(path),
                reason: format!(
                    "it carries the overlay record {record}, which no overlay this library \
                     mounts writes, and which the reader would read otherwise than the kernel"
                ),
            });
        }
        Ok(Some(
            named
                .into_iter()
                .filter(|(name, _)| !containment::host_assigned_xattr(name))
                .collect(),
        ))
    }
}

/// Refuses a layer's directory `dir`, at `path`, carrying a record the reader
/// would read otherwise than the kernel. A directory the caller cannot read the
/// attributes of is left to the walk, which reports it unreadable.
fn refuse_records(
    dir: BorrowedFd<'_>,
    path: &Path,
    layer: Layer<'_>,
) -> Result<(), ProvisionError> {
    let named = match xattr::read_all(Holder::Fd(dir)) {
        Ok(named) => named,
        Err(Errno::ACCESS) => return Ok(()),
        Err(errno) => {
            return Err(ProvisionError::io(
                "reading",
                layer.name(path),
                errno.into(),
            ));
        }
    };
    match named
        .iter()
        .find_map(|(name, value)| misread_record(name, value))
    {
        Some(record) => Err(ProvisionError::EntryRefused {
            path: layer.name(path),
            reason: format!(
                "it carries the overlay record {record}, which no overlay this library mounts \
                 writes, and which the reader would read otherwise than the kernel"
            ),
        }),
        None => Ok(()),
    }
}

/// The overlay record an attribute named `name` with `value` is, where the
/// reader would read it otherwise than the kernel: a redirect, a metadata-only
/// copy, a whiteout of the attribute form, or a directory marked as holding
/// such whiteouts.
///
/// Matched by exact name: an attribute a command sets named `user.overlay.`
/// is kept escaped, as `user.overlay.overlay.`, and is none of these.
fn misread_record(name: &[u8], value: &[u8]) -> Option<&'static str> {
    match name {
        b"user.overlay.redirect" => Some("user.overlay.redirect"),
        b"user.overlay.metacopy" => Some("user.overlay.metacopy"),
        b"user.overlay.whiteout" => Some("user.overlay.whiteout"),
        b"user.overlay.opaque" if value != b"y" => Some("user.overlay.opaque other than \"y\""),
        _ => None,
    }
}

/// Whether the caller can both list the directory `name` in `dir` and search
/// it, which reading the entries beneath it takes.
fn listable(dir: BorrowedFd<'_>, name: &CStr) -> bool {
    fs::accessat(
        dir,
        name,
        fs::Access::READ_OK | fs::Access::EXEC_OK,
        AtFlags::EACCESS | AtFlags::SYMLINK_NOFOLLOW,
    )
    .is_ok()
}

/// The target of the symbolic link `held`, refusing one too long to read whole.
fn link_target(held: &Held<'_>, path: &Path) -> Result<Vec<u8>, ProvisionError> {
    let mut buffer = [0u8; LINK_BUF];
    let read = fs::readlinkat_raw(held.dir, held.name, &mut buffer[..])
        .map_err(|errno| ProvisionError::io("reading", path, errno.into()))?;
    if read == buffer.len() {
        return Err(ProvisionError::EntryRefused {
            path: path.to_path_buf(),
            reason: "the symlink target is longer than the reader reads".to_string(),
        });
    }
    Ok(buffer[..read].to_vec())
}

/// Whether the files `ours` and `theirs`, of one length, hold the same bytes,
/// or `None` where the caller cannot read one of them.
fn same_bytes(
    ours: &Held<'_>,
    theirs: &Held<'_>,
    path: &Path,
    lower: &Path,
) -> Result<Option<bool>, ProvisionError> {
    let open = |held: &Held<'_>, named: PathBuf| match containment::open_typed_file(
        held.dir,
        held.name,
        held.stat,
        OFlags::RDONLY,
    ) {
        Ok(file) => Ok(Some(file)),
        Err(Errno::ACCESS) => Ok(None),
        Err(Errno::STALE) => Err(ProvisionError::SourceChanged {
            path: named,
            recorded: held.stat.st_size as u64,
        }),
        Err(errno) => Err(ProvisionError::io("reading", named, errno.into())),
    };
    let (Some(a), Some(b)) = (
        open(ours, path.to_path_buf())?,
        open(theirs, lower.join(path))?,
    ) else {
        return Ok(None);
    };
    let mut left = vec![0u8; COMPARE_CHUNK];
    let mut right = vec![0u8; COMPARE_CHUNK];
    loop {
        let read_a = frame::read_full_or_short(a.as_fd(), &mut left)
            .map_err(|errno| ProvisionError::io("reading", path, errno.into()))?;
        let read_b = frame::read_full_or_short(b.as_fd(), &mut right)
            .map_err(|errno| ProvisionError::io("reading", lower.join(path), errno.into()))?;
        if read_a != read_b || left[..read_a] != right[..read_b] {
            return Ok(Some(false));
        }
        if read_a < COMPARE_CHUNK {
            return Ok(Some(true));
        }
    }
}

/// How much of each file [`same_bytes`] compares at a time.
const COMPARE_CHUNK: usize = 64 * 1024;

/// When the directory `dir` was created, or `None` where its filesystem does
/// not record it.
fn birth_time(dir: BorrowedFd<'_>) -> Result<Option<SystemTime>, Errno> {
    let statx = fs::statx(dir, c"", AtFlags::EMPTY_PATH, fs::StatxFlags::BTIME)?;
    if statx.stx_mask & fs::StatxFlags::BTIME.bits() == 0 {
        return Ok(None);
    }
    let since_epoch = Duration::new(
        u64::try_from(statx.stx_btime.tv_sec).unwrap_or(0),
        statx.stx_btime.tv_nsec,
    );
    Ok(SystemTime::UNIX_EPOCH.checked_add(since_epoch))
}

/// Opens a layer's top directory, following the path the caller named.
fn open_layer(layer: &Path) -> Result<OwnedFd, ProvisionError> {
    fs::open(
        layer,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        fs::Mode::empty(),
    )
    .map_err(|errno| ProvisionError::io("reading", layer, errno.into()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use ferroday_cage_testkit::{overlay, xattr};

    use super::*;
    use crate::scratch::Scratch;

    /// A scratch tree with an upper and the lowers named, each created empty,
    /// and the overlay of them, base first.
    fn layers(name: &str, lowers: &[&str]) -> (Scratch, Overlay) {
        let scratch = Scratch::new(name);
        let mut overlay = Overlay::new();
        for lower in lowers {
            std::fs::create_dir(scratch.join(lower)).unwrap();
            overlay = overlay.lower(scratch.join(lower));
        }
        std::fs::create_dir(scratch.join("upper")).unwrap();
        let overlay = overlay.upper(scratch.join("upper"));
        (scratch, overlay)
    }

    /// The changes, as their paths and kinds.
    fn listed(overlay: &Overlay) -> Vec<(String, ChangeKind)> {
        ChangeSet::read(overlay)
            .expect("the change set reads")
            .changes()
            .iter()
            .map(|change| (change.path().display().to_string(), change.kind()))
            .collect()
    }

    fn write(path: PathBuf, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// A lower stacked over the base hides what its own whiteouts and opaque
    /// directories hide, and the lowers together are what a run's change is
    /// against.
    #[test]
    fn stacked_lowers_are_read_as_the_kernel_stacks_them() {
        let (scratch, overlay) = layers("changes-stacked", &["base", "patch"]);
        write(scratch.join("base/gone-in-patch"), "base\n");
        write(scratch.join("base/dir/hidden"), "base\n");
        write(scratch.join("base/dir/kept"), "base\n");
        write(scratch.join("base/shown"), "base\n");
        if !overlay::whiteout(&scratch.join("patch/gone-in-patch")) {
            return;
        }
        std::fs::create_dir(scratch.join("patch/dir")).unwrap();
        assert!(xattr::set(
            &scratch.join("patch/dir"),
            "user.overlay.opaque",
            b"y"
        ));
        write(scratch.join("patch/dir/patched"), "patch\n");

        // The run writes the name the patch had deleted, deletes the patch's
        // file, writes the name the patch's opaque directory hid, and deletes
        // a base file the patch left showing.
        write(scratch.join("upper/gone-in-patch"), "run\n");
        std::fs::create_dir(scratch.join("upper/dir")).unwrap();
        assert!(overlay::whiteout(&scratch.join("upper/dir/patched")));
        write(scratch.join("upper/dir/hidden"), "run\n");
        assert!(overlay::whiteout(&scratch.join("upper/shown")));
        // A whiteout of a name no lower shows is no change.
        assert!(overlay::whiteout(&scratch.join("upper/dir/kept")));

        assert_eq!(
            listed(&overlay),
            [
                ("dir/hidden".to_string(), ChangeKind::Added),
                ("dir/patched".to_string(), ChangeKind::Removed),
                ("gone-in-patch".to_string(), ChangeKind::Added),
                ("shown".to_string(), ChangeKind::Removed),
            ]
        );
    }

    /// An opaque directory removes each name the lowers held beneath it that
    /// the upper does not hold again, down through directories the upper holds
    /// again, and the removals are listed in path order among the rest.
    #[test]
    fn an_opaque_directory_lists_what_it_removed() {
        let (scratch, overlay) = layers("changes-opaque", &["base"]);
        for path in ["d/a", "d/c", "d/sub/x", "d/sub/y", "d/zz/deep"] {
            write(scratch.join("base").join(path), "base\n");
        }
        std::fs::create_dir_all(scratch.join("upper/d/sub")).unwrap();
        assert!(xattr::set(
            &scratch.join("upper/d"),
            "user.overlay.opaque",
            b"y"
        ));
        write(scratch.join("upper/d/b"), "run\n");
        write(scratch.join("upper/d/sub/x"), "base\n");
        let base = std::fs::metadata(scratch.join("base/d")).unwrap();
        std::fs::set_permissions(scratch.join("upper/d"), base.permissions()).unwrap();
        let sub = std::fs::metadata(scratch.join("base/d/sub")).unwrap();
        std::fs::set_permissions(scratch.join("upper/d/sub"), sub.permissions()).unwrap();

        assert_eq!(
            listed(&overlay),
            [
                ("d/a".to_string(), ChangeKind::Removed),
                ("d/b".to_string(), ChangeKind::Added),
                ("d/c".to_string(), ChangeKind::Removed),
                ("d/sub/y".to_string(), ChangeKind::Removed),
                ("d/zz".to_string(), ChangeKind::Removed),
            ]
        );
    }

    /// A record no overlay the library mounts writes is refused, on an upper
    /// entry or a lower directory, while a command's own attribute the overlay
    /// kept escaped is neither a record nor a difference.
    #[test]
    fn a_record_the_kernel_would_read_otherwise_is_refused() {
        for (record, value) in [
            ("user.overlay.redirect", &b"/elsewhere"[..]),
            ("user.overlay.metacopy", b""),
            ("user.overlay.whiteout", b""),
            ("user.overlay.opaque", b"x"),
        ] {
            let (scratch, overlay) = layers("changes-record", &["base"]);
            std::fs::create_dir(scratch.join("upper/d")).unwrap();
            if !xattr::set(&scratch.join("upper/d"), record, value) {
                return;
            }
            match ChangeSet::read(&overlay) {
                Err(ProvisionError::EntryRefused { path, reason }) => {
                    assert_eq!(path, Path::new("d"));
                    assert!(reason.contains(record), "{reason}");
                }
                other => panic!("{record}: {other:?}"),
            }
        }

        let (scratch, overlay) = layers("changes-record-lower", &["base"]);
        std::fs::create_dir(scratch.join("base/d")).unwrap();
        std::fs::create_dir(scratch.join("upper/d")).unwrap();
        write(scratch.join("upper/d/f"), "run\n");
        assert!(xattr::set(
            &scratch.join("base/d"),
            "user.overlay.opaque",
            b"x"
        ));
        assert!(matches!(
            ChangeSet::read(&overlay),
            Err(ProvisionError::EntryRefused { path, .. }) if path == scratch.join("base/d")
        ));

        let (scratch, overlay) = layers("changes-escaped", &["base"]);
        write(scratch.join("base/f"), "same\n");
        write(scratch.join("upper/f"), "same\n");
        assert!(xattr::set(
            &scratch.join("upper/f"),
            "user.overlay.overlay.opaque",
            b"y"
        ));
        assert!(listed(&overlay).is_empty(), "an escaped attribute is none");
    }

    /// A link is read as a link wherever it stands, in the upper or a lower,
    /// and nothing beneath one is looked through it.
    #[test]
    fn a_link_is_never_followed() {
        let (scratch, overlay) = layers("changes-links", &["base"]);
        write(scratch.join("base/real/f"), "base\n");
        std::os::unix::fs::symlink("real", scratch.join("base/link")).unwrap();
        write(scratch.join("base/dir/f"), "base\n");
        // The run replaced the lower's link with a directory holding a file
        // the link's target also holds, and the lower's directory with a link
        // to a host directory.
        std::fs::create_dir(scratch.join("upper/link")).unwrap();
        write(scratch.join("upper/link/f"), "base\n");
        std::os::unix::fs::symlink("/etc", scratch.join("upper/dir")).unwrap();

        let changes = ChangeSet::read(&overlay).unwrap();
        let listed: Vec<_> = changes
            .changes()
            .iter()
            .map(|change| {
                (
                    change.path().display().to_string(),
                    change.before(),
                    change.now(),
                )
            })
            .collect();
        assert_eq!(
            listed,
            [
                (
                    "dir".to_string(),
                    Some(EntryKind::Directory),
                    Some(EntryKind::Symlink)
                ),
                (
                    "link".to_string(),
                    Some(EntryKind::Symlink),
                    Some(EntryKind::Directory)
                ),
                ("link/f".to_string(), None, Some(EntryKind::File)),
            ]
        );
    }

    /// A file the run left unreadable to the caller is listed, its content
    /// counted as differing, and the change says it is incomplete.
    #[test]
    fn an_unreadable_entry_is_listed_as_incomplete() {
        if rustix::process::geteuid().is_root() {
            ferroday_cage_testkit::require::premise_unmet(
                "root reads a file of mode 000, so nothing is unreadable to it",
            );
            return;
        }
        let (scratch, overlay) = layers("changes-unreadable", &["base"]);
        write(scratch.join("base/f"), "same\n");
        write(scratch.join("upper/f"), "same\n");
        std::fs::create_dir(scratch.join("upper/d")).unwrap();
        write(scratch.join("upper/d/inside"), "run\n");
        for path in ["upper/f", "upper/d"] {
            std::fs::set_permissions(scratch.join(path), std::fs::Permissions::from_mode(0o000))
                .unwrap();
        }
        let changes = ChangeSet::read(&overlay).unwrap();
        for path in ["upper/f", "upper/d"] {
            std::fs::set_permissions(scratch.join(path), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let listed: Vec<_> = changes
            .changes()
            .iter()
            .map(|change| {
                (
                    change.path().display().to_string(),
                    change.kind(),
                    change.content_differs(),
                    change.is_readable(),
                )
            })
            .collect();
        assert_eq!(
            listed,
            [
                ("d".to_string(), ChangeKind::Added, false, false),
                ("f".to_string(), ChangeKind::Modified, true, false),
            ]
        );
    }

    /// Nesting carries no limit of the reader's own.
    #[test]
    fn a_deep_upper_reads_whole() {
        let (scratch, overlay) = layers("changes-deep", &["base"]);
        let mut deep = scratch.join("upper");
        for _ in 0..300 {
            deep.push("d");
        }
        write(deep.join("f"), "deep\n");
        let changes = ChangeSet::read(&overlay).unwrap();
        assert_eq!(changes.changes().len(), 301);
        assert!(
            changes
                .changes()
                .windows(2)
                .all(|pair| pair[0].path() < pair[1].path())
        );
    }

    #[test]
    fn an_overlay_without_an_upper_or_a_lower_is_refused() {
        assert!(matches!(
            ChangeSet::read(&Overlay::new().lower("/srv/base")),
            Err(ProvisionError::OverlayLayerMissing {
                layer: OverlayLayer::Upper
            })
        ));
        assert!(matches!(
            ChangeSet::read(&Overlay::new().upper("/srv/upper")),
            Err(ProvisionError::OverlayLayerMissing {
                layer: OverlayLayer::Lower
            })
        ));
    }
}
