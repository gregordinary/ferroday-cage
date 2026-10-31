//! Hardened extraction of a tar stream into a directory.
//!
//! Containment is enforced by the kernel, not by inspecting path text: every
//! parent directory is resolved with `openat2` and `RESOLVE_IN_ROOT`, anchored
//! at the extraction root, so no entry is written outside it however its path
//! or a link chain is spelled. An entry's own path is held to more than that:
//! one that is absolute, or climbs with `..`, is refused outright as an escape
//! attempt, since a name an archive gives has no business being either.
//!
//! A symbolic link in the tree is a link of the root filesystem the tree is,
//! and resolves as that root resolves it once it is in use. A relative link
//! resolves normally, so a merged-usr archive whose `bin` is a link to
//! `usr/bin` extracts correctly. An absolute one re-anchors at the extraction
//! root: `var/run -> /run`, which Debian's `base-files` ships, carries an entry
//! under `var/run/` to the tree's own `run/`, which is where `dpkg` or `apk`
//! inside the finished sandbox would put it. A `..` in a link's target stops at
//! the root, as it does there. Nothing resolves outside the tree, and a magic
//! link is refused.
//!
//! Extraction is unprivileged by design: entries become owned by the
//! calling user (whom the sandbox's identity map presents as root),
//! permission bits apply verbatim, and entry types that cannot be created
//! without privilege — character and block devices — are skipped, as the
//! sandbox assembles its own `/dev`. (A tar archive has no socket entry
//! type; GNU volume labels, archive metadata, are skipped too.)
//!
//! A layered build extracts into an overlay upper over a base it never
//! writes, and [`Extraction::over`] names that base: every entry is then
//! placed as it would be in the mounted overlay, so a directory of the
//! increment's never hides a link of the base's. [`overlay_tree`] takes the
//! base the same way.

use std::collections::HashMap;
use std::ffi::CString;
#[cfg(any(feature = "debian", feature = "alpine"))]
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::Timespec;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, Timestamps, UTIME_OMIT};
use rustix::io::Errno;

use crate::path::{self, LeadingSlash, Refused};

use super::ProvisionError;
use super::containment::{self, Made, Reached};
use super::tar::{Entry, TarReader};

/// How every path an extraction writes through is resolved: inside the root,
/// with an absolute link re-anchored there, as the root filesystem resolves it
/// once it is in use. `RESOLVE_NO_MAGICLINKS` comes with every resolve
/// [`containment::open_dir`] makes.
const CONTAINMENT: ResolveFlags = ResolveFlags::IN_ROOT;

/// The mode of a directory the extraction implies but no entry names.
///
/// An archive that carries `usr/lib/x` without an entry for `usr/lib` leaves
/// the mode of that directory unstated; the conventional `0755` is the only
/// answer available, and it is the one every other extractor gives.
const IMPLIED_DIR_MODE: u32 = 0o755;

/// The mode a named pipe is created with, before the one its entry states.
///
/// Owner-only, so the pipe never sits at a permissive mode in the window before
/// its own, and readable by its owner, since its mode is applied through a
/// descriptor that opening it for reading gives.
const FIFO_CREATION_MODE: u32 = 0o600;

/// The per-entry hook the extractor calls before writing each entry.
///
/// Receives the entry's header and its validated path components, and answers
/// whether the entry is written. Its error abandons the extraction at an entry
/// boundary, which is what a cancellation check needs.
pub(crate) type OnEntry<'f> =
    dyn FnMut(&Entry, &[Vec<u8>]) -> Result<Placement, ProvisionError> + 'f;

/// Whether an entry is written, as the per-entry hook decides.
///
/// The channel exists because a hook that keeps a record of the tree may know
/// that an entry must *not* be laid down — an apk package whose file an earlier
/// package keeps — and an error is the wrong way to say so: it would abandon the
/// whole archive rather than one entry. Without it a hook could record the
/// decision and the extractor would write the file anyway, leaving the tree
/// disagreeing with the record of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Write the entry, which is what a hook that only observes always answers.
    Write,
    /// Leave the entry unwritten and the tree as it is. The archive is read past
    /// it either way, so the entries after it are unaffected.
    #[cfg_attr(not(feature = "alpine"), allow(dead_code))]
    Skip,
}

/// Metadata of a directory entry, applied after all entries have been
/// extracted so that a read-only directory cannot block the extraction of
/// its own contents.
struct DirMeta {
    mode: u32,
    mtime: Option<i64>,
}

/// The tree entries are written into: the extraction root, and the base it is
/// an overlay upper over, where it is one.
#[derive(Clone, Copy)]
struct Tree<'a> {
    /// The extraction root; every write resolves beneath it.
    root: BorrowedFd<'a>,
    /// The base, read and never written. See [`Extraction::over`].
    lower: Option<BorrowedFd<'a>>,
}

/// An extraction into one root directory, across one or more archives.
///
/// A single [`Extraction`] holds the extraction root and the deferred
/// directory metadata, so several archives can extract into the same root
/// with one shared metadata pass. The directory modes and times are applied
/// once, by [`finalize`](Self::finalize), after the last archive: a
/// read-only directory shipped by an early archive is not locked before a
/// later archive writes into it. The single-archive case
/// ([`extract_archive`]) is this used once.
pub(crate) struct Extraction {
    /// The extraction root, opened once; every operation resolves beneath it.
    root_fd: OwnedFd,
    /// The base the root is an overlay upper over, where it is one.
    lower_fd: Option<OwnedFd>,
    /// Deferred directory metadata, keyed by slash-joined path. Implied
    /// directories (created for a child before their own entry appears, or
    /// never described at all) default to 0755 with their creation time. A
    /// later directory entry for a path replaces an earlier one, so the
    /// last archive to describe a directory wins.
    dir_meta: HashMap<Vec<u8>, DirMeta>,
    /// The root directory's own metadata, applied by [`finalize`](Self::finalize)
    /// once every entry is written. `None` until something states it.
    root_meta: Option<DirMeta>,
    /// Whether [`root_mode`](Self::root_mode) stated it, in which case a `./`
    /// entry does not replace it.
    root_mode_fixed: bool,
    /// The directory inside the archive that stands for the extraction root,
    /// where the archive wraps its tree in one.
    under: Option<Vec<u8>>,
}

impl Extraction {
    /// Opens `root` for extraction.
    pub(crate) fn new(root: &Path) -> Result<Extraction, ProvisionError> {
        Ok(Extraction {
            root_fd: open_root(root)?,
            lower_fd: None,
            dir_meta: HashMap::new(),
            root_meta: None,
            root_mode_fixed: false,
            under: None,
        })
    }

    /// Treats the extraction root as an overlay upper over `lower`, where one
    /// is named.
    ///
    /// A layered build writes its increment into an upper the kernel shows
    /// over the base, and the kernel merges a directory only with a directory.
    /// An entry under `lib64/`, extracted into a bare upper, would make
    /// `lib64` a real directory there, and over a base whose `lib64` is a link
    /// to `usr/lib64` that directory hides the link: the merged `/lib64` holds
    /// the increment's files and nothing else, the dynamic linker among what
    /// it lost. So each entry's chain is first walked through the merged view,
    /// with the upper made to hold what the view holds along it
    /// ([`containment::copy_up`]), and the entry lands where it would in the
    /// mounted overlay: at `usr/lib64` in the upper, beside the upper's copy
    /// of the base's link.
    ///
    /// The rules are the ones a whole root is extracted by, applied to the
    /// merged view. A link to a directory satisfies a directory entry, an
    /// absolute link of the base's resolves inside the root as the root
    /// resolves it, and a later entry supersedes what holds its name. The base
    /// is never written, so a directory of its own is
    /// one an entry that is not a directory cannot supersede, and such an entry
    /// is refused. A directory the base holds and the archive only implies
    /// keeps the base's mode and modification time, as the overlay's own copy
    /// carries them up.
    ///
    /// What the per-entry hook sees is unchanged: the entry's path as the
    /// archive spells it, which is the path a package database records —
    /// portage's `CONTENTS` and apk's `installed` alike name `/lib64/x`, and
    /// the root resolves it.
    #[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
    pub(crate) fn over(mut self, lower: Option<&Path>) -> Result<Extraction, ProvisionError> {
        if let Some(lower) = lower {
            self.lower_fd = Some(open_root(lower)?);
        }
        Ok(self)
    }

    /// Fixes the extraction root's own mode, in place of taking it from a `./`
    /// entry.
    ///
    /// An archive that describes the whole tree it is unpacked into describes
    /// the root as well, and its `./` entry is that description; by default it
    /// is applied, which is what `tar -C dir -x` does. Several archives unpacked
    /// into one root each carry their own, so the root would take the mode and
    /// modification time of whichever was extracted last — a choice among
    /// archives that say nothing about the tree being assembled from them, and
    /// one nothing in the result records.
    ///
    /// A caller assembling such a root states the mode instead. `./` entries are
    /// then ignored, and the root's modification time is left as the filesystem
    /// set it.
    #[cfg(any(feature = "debian", feature = "alpine"))]
    pub(crate) fn root_mode(mut self, mode: u32) -> Extraction {
        self.root_meta = Some(DirMeta { mode, mtime: None });
        self.root_mode_fixed = true;
        self
    }

    /// Treats `prefix` inside the archive as the extraction root.
    ///
    /// An archive that wraps the tree it describes in a directory needs this: a
    /// Gentoo binary package's image archive holds `image/usr/bin/git`, and
    /// what belongs at the root is `usr/bin/git`. Entries outside the prefix
    /// are not extracted, so the wrapper's own entry — and anything a container
    /// put beside it — lands nowhere.
    ///
    /// The prefix is stripped before the path is validated, so what the
    /// containment rules see is the path as it will be written, and an entry
    /// that escapes the prefix is refused by the same check that refuses one
    /// escaping the root.
    #[cfg(feature = "gentoo")]
    pub(crate) fn under(mut self, prefix: &[u8]) -> Extraction {
        self.under = Some(prefix.to_vec());
        self
    }

    /// Extracts every entry of `archive` into the root.
    ///
    /// `on_entry` is called for each entry that is extracted, with its
    /// metadata and validated path components, before the entry is written;
    /// skipped entries (character and block devices, volume labels) and the `./` root
    /// entry do not call it. It lets a caller act on entry metadata the
    /// extractor itself ignores — recording non-root ownership, reporting
    /// progress — without a second pass over the archive. It also decides
    /// whether the entry is written at all ([`Placement`]), so a caller that
    /// keeps a record of the tree can hold the tree to it; and its error
    /// abandons the extraction at an entry boundary, which is what a
    /// cancellation check needs.
    pub(crate) fn extract<R: Read>(
        &mut self,
        archive: &mut TarReader<R>,
        on_entry: &mut OnEntry<'_>,
    ) -> Result<(), ProvisionError> {
        let tree = Tree {
            root: self.root_fd.as_fd(),
            lower: self.lower_fd.as_ref().map(AsFd::as_fd),
        };
        while let Some(mut entry) = archive.next_entry()? {
            match entry.typeflag {
                // Unextractable without privilege; the sandbox provides its
                // own /dev. GNU volume labels are archive metadata.
                b'3' | b'4' | b'V' => continue,
                // Sparse and multi-volume members are not supported.
                b'S' | b'M' => {
                    return Err(ProvisionError::EntryUnsupported {
                        path: bytes_to_path(&entry.path),
                        kind: entry.typeflag,
                    });
                }
                _ => {}
            }

            // A prefixed archive names the extraction root by a directory of
            // its own, so what is validated and written is the path below it.
            let path = match &self.under {
                None => entry.path.as_slice(),
                Some(prefix) => match strip_prefix(&entry.path, prefix) {
                    // The wrapper's own entry. It strips to the empty path,
                    // which the `./` arm below reads as the extraction root --
                    // and the root is the caller's, not something the wrapper
                    // describes, so applying its mode and modification time
                    // there would rewrite the root every archive is unpacked
                    // into. `under` says the wrapper lands nowhere.
                    Some([]) => continue,
                    Some(rest) => rest,
                    // Anything outside the wrapper. The archive is read past
                    // it, so what follows is unaffected.
                    None => continue,
                },
            };
            let components = validate_path(path, &entry.path, "path")?;
            // A hardlink names another entry of the same archive, so its target
            // carries the wrapper too and has to lose it the same way. One that
            // does not is naming something the archive is not laying down, and
            // resolving it against the root would point it at whatever happens
            // to be there.
            if entry.typeflag == b'1'
                && let Some(prefix) = &self.under
            {
                match strip_prefix(&entry.link_target, prefix) {
                    Some(rest) => entry.link_target = rest.to_vec(),
                    None => {
                        return Err(entry_unsafe(
                            &entry.path,
                            "the hardlink target is outside the archive's own root directory",
                        ));
                    }
                }
            }
            if components.is_empty() {
                // The `./` entry: metadata for the extraction root itself,
                // unless the caller fixed the root's mode instead.
                if entry.typeflag == b'5' {
                    if !self.root_mode_fixed {
                        self.root_meta = Some(DirMeta {
                            mode: entry.mode,
                            mtime: Some(entry.mtime),
                        });
                    }
                    continue;
                }
                return Err(entry_refused(&entry.path, "the entry path is empty"));
            }

            if on_entry(&entry, &components)? == Placement::Skip {
                // Nothing is created and nothing is resolved: the entry's data
                // is drained by the next `next_entry`, so a skip costs the read
                // and no more.
                continue;
            }

            match entry.typeflag {
                b'5' => extract_dir(tree, &entry, &components, &mut self.dir_meta)?,
                b'2' => extract_symlink(tree, &entry, &components, &mut self.dir_meta)?,
                b'1' => extract_hardlink(tree, &entry, &components, &mut self.dir_meta)?,
                b'6' => extract_fifo(tree, &entry, &components, &mut self.dir_meta)?,
                // Regular files, and unknown typeflags, which POSIX says to
                // treat as regular files.
                _ => extract_file(tree, archive, &entry, &components, &mut self.dir_meta)?,
            }
        }
        Ok(())
    }

    /// Applies the deferred directory metadata and consumes the extraction.
    ///
    /// `root` names the extraction root for error reporting only.
    pub(crate) fn finalize(self, root: &Path) -> Result<(), ProvisionError> {
        apply_dir_meta(self.root_fd.as_fd(), self.dir_meta)?;
        if let Some(meta) = self.root_meta {
            apply_meta_fd(self.root_fd.as_fd(), &meta)
                .map_err(|errno| ProvisionError::io("finalizing", root, errno.into()))?;
        }
        Ok(())
    }
}

/// Extracts every entry of `archive` into the directory at `root`, reporting
/// each entry through `on_entry`.
pub(crate) fn extract_archive<R: Read>(
    archive: &mut TarReader<R>,
    root: &Path,
    on_entry: &mut OnEntry<'_>,
) -> Result<(), ProvisionError> {
    let mut extraction = Extraction::new(root)?;
    extraction.extract(archive, on_entry)?;
    extraction.finalize(root)
}

/// Opens the directory at `path`, a tree an extraction writes into or reads
/// as a base, as the anchor every resolve beneath it starts from.
fn open_root(path: &Path) -> Result<OwnedFd, ProvisionError> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| ProvisionError::io("opening", path, errno.into()))
}

/// The part of `path` below `prefix`, or `None` where it is not under it.
///
/// The prefix names a directory, so a path that merely begins with those bytes
/// is not under it: `image2/x` is not inside `image/`. The prefix's own entry
/// — `image/`, or `image` — yields the empty path, which the caller tells from
/// a path below the prefix and skips: the wrapper describes the extraction root
/// it was unpacked into, and that root is the caller's.
fn strip_prefix<'p>(path: &'p [u8], prefix: &[u8]) -> Option<&'p [u8]> {
    let prefix = prefix.strip_suffix(b"/").unwrap_or(prefix);
    let rest = path.strip_prefix(prefix)?;
    match rest.first() {
        None => Some(rest),
        Some(b'/') => Some(&rest[1..]),
        Some(_) => None,
    }
}

/// Splits and validates an entry path: relative, no `..`, no NUL.
///
/// [`path::tree_components`] is the split, with an absolute path refused rather
/// than read as naming the destination's own root. A link in the tree is the
/// root's to resolve as the root resolves it, but an archive names its own
/// entries relative to the root it describes, and one that names a path from
/// `/` is aiming at the host whatever the resolution would make of it. `.`
/// components and empty segments are dropped, so `./` normalizes to an empty
/// list, which is the entry describing the extraction root.
///
/// `context` names the entry in errors (for a hardlink target, the entry it
/// belongs to) and `noun` names which of the two the refusal is about, so the
/// message says whether the entry or its link target was the problem.
fn validate_path(raw: &[u8], context: &[u8], noun: &str) -> Result<Vec<Vec<u8>>, ProvisionError> {
    match path::tree_components(raw, LeadingSlash::Refused) {
        Ok(components) => Ok(components.into_iter().map(<[u8]>::to_vec).collect()),
        Err(Refused::Nul) => Err(entry_unsafe(
            context,
            format!("the {noun} contains a NUL byte"),
        )),
        Err(Refused::Absolute) => Err(entry_unsafe(context, format!("the {noun} is absolute"))),
        Err(Refused::Traversal) => Err(entry_unsafe(
            context,
            format!("the {noun} contains a `..` component"),
        )),
    }
}

/// An entry's parent directory, opened beneath the extraction root.
struct Parent {
    /// The directory itself, in the extraction root.
    dir: OwnedFd,
    /// The base's own directory at the same path, where the extraction is
    /// layered and the overlay shows the base there. What an entry that is not
    /// a directory consults before superseding the name; see
    /// [`refuse_superseding_a_base_directory`].
    lower: Option<OwnedFd>,
}

/// Opens an entry's parent directory beneath the root, creating missing
/// intermediate directories.
///
/// Resolution is kernel-scoped to the root ([`CONTAINMENT`]): a link in the
/// chain, absolute or climbing with `..`, resolves inside the root as the root
/// itself resolves it, and nothing resolves outside. Where the tree is layered, the
/// chain is first walked through the merged view with the root made to hold
/// what that view holds along it ([`containment::copy_up`]), so the kernel's
/// resolution then goes where the mounted overlay would.
///
/// A directory created here is a parent the archive implied but never named,
/// and gets the conventional `0755`, or, where it stands in for one of the
/// base's, the base's own mode and modification time. `dir_meta` is the
/// deferred-metadata map of a caller that applies directory modes in a later
/// pass, which records the metadata rather than applying it: an implied
/// parent's contents are still to be created, and it is created `0700` until
/// they are. A caller with no such pass passes `None` and has the mode applied
/// at once, through the descriptor of the directory just made, so an implied
/// parent is never left at the creation mode.
fn open_parent(
    tree: Tree<'_>,
    components: &[Vec<u8>],
    entry_path: &[u8],
    mut dir_meta: Option<&mut HashMap<Vec<u8>, DirMeta>>,
) -> Result<Parent, ProvisionError> {
    let parent = &components[..components.len() - 1];
    let mut lower = None;
    if let Some(base) = tree.lower {
        let walked = containment::copy_up(tree.root, base, parent, CONTAINMENT, &mut |made| {
            place_made(made, dir_meta.as_deref_mut())
        });
        match walked {
            Ok(Reached::Directory(found)) => lower = found,
            Ok(Reached::Short) => {}
            Err(errno) => return Err(parent_error(errno, entry_path)),
        }
    }
    let dir = containment::create_dirs(tree.root, parent, CONTAINMENT, &mut |made| {
        place_made(made, dir_meta.as_deref_mut())
    })
    .map_err(|errno| parent_error(errno, entry_path))?;
    Ok(Parent { dir, lower })
}

/// States the mode of a directory a chain walk made: recorded for the
/// deferred pass where the caller keeps one, applied through the directory's
/// own descriptor at once where it does not.
///
/// An implied directory gets [`IMPLIED_DIR_MODE`]. One carried up from a
/// layered extraction's base keeps the base's mode and modification time,
/// which is what the merged view showed before the root held it; only the
/// deferred pass restores the time, since a directory's time moves as its
/// contents are written.
fn place_made(
    made: Made<'_>,
    dir_meta: Option<&mut HashMap<Vec<u8>, DirMeta>>,
) -> Result<(), Errno> {
    let meta = match made.copied {
        Some(stat) => DirMeta {
            mode: stat.st_mode & 0o7777,
            mtime: Some(containment::modified(stat).tv_sec),
        },
        None => DirMeta {
            mode: IMPLIED_DIR_MODE,
            mtime: None,
        },
    };
    match dir_meta {
        Some(dir_meta) => {
            dir_meta.entry(made.path.to_vec()).or_insert(meta);
            Ok(())
        }
        None => rustix::fs::fchmod(made.dir, Mode::from_raw_mode(meta.mode)),
    }
}

/// Maps a failure to open or create an entry's parent chain onto the typed
/// error surface.
///
/// [`resolve_error`]'s mapping, with every other errno reported as the
/// creation it interrupted: the chain is resolved, created, and given its
/// modes in one walk, and what the caller can act on is the entry whose
/// parents could not be made.
fn parent_error(errno: Errno, entry_path: &[u8]) -> ProvisionError {
    match errno {
        Errno::XDEV | Errno::LOOP | Errno::NOTDIR => resolve_error(errno, entry_path),
        errno => ProvisionError::io(
            "creating the parent directories of",
            bytes_to_path(entry_path),
            errno.into(),
        ),
    }
}

/// Resolves `components` beneath the root as a directory, without following
/// magic links and without leaving the root.
///
/// `O_PATH`: the descriptor is only ever the anchor of a later `*at` call.
fn open_dir_at(root: BorrowedFd<'_>, components: &[Vec<u8>]) -> Result<OwnedFd, Errno> {
    containment::open_dir(root, components, OFlags::PATH, CONTAINMENT)
}

/// Prepares a layered extraction to write the directory `components` names.
///
/// Where the tree is layered, the whole chain, the directory's own name
/// included, is walked through the merged view first, so the root holds what
/// the view holds there and the classification that follows sees it: a link
/// of the base's to a directory is an alias exactly as one of the root's own
/// is. A name the view holds as something else is the classification's to
/// replace, so a walk that ends there is not a failure here; one that ends
/// above it already failed the parent's own walk.
fn prepare_dir(
    tree: Tree<'_>,
    components: &[Vec<u8>],
    entry_path: &[u8],
    mut dir_meta: Option<&mut HashMap<Vec<u8>, DirMeta>>,
) -> Result<(), ProvisionError> {
    let Some(base) = tree.lower else {
        return Ok(());
    };
    match containment::copy_up(tree.root, base, components, CONTAINMENT, &mut |made| {
        place_made(made, dir_meta.as_deref_mut())
    }) {
        Ok(_) | Err(Errno::NOTDIR) => Ok(()),
        Err(errno) => Err(parent_error(errno, entry_path)),
    }
}

/// Creates the directory `leaf` in `parent` where something else held the
/// name, which the caller has just removed.
///
/// In a layered extraction the new directory is marked opaque. The name held
/// something other than a directory in the merged view, so the directory
/// starts empty there; without the marker the overlay would merge it with a
/// directory of the base's that the removed entry had been hiding.
fn make_replacement_dir(
    tree: Tree<'_>,
    parent: &OwnedFd,
    leaf: &CString,
    entry_path: &[u8],
) -> Result<(), ProvisionError> {
    let creating =
        |errno: Errno| ProvisionError::io("creating", bytes_to_path(entry_path), errno.into());
    rustix::fs::mkdirat(parent, leaf, Mode::from_raw_mode(0o700)).map_err(creating)?;
    if tree.lower.is_some() {
        let dir = rustix::fs::openat(
            parent,
            leaf,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(creating)?;
        containment::mark_opaque(dir.as_fd()).map_err(creating)?;
    }
    Ok(())
}

/// Refuses an entry that is not a directory where a layered extraction's base
/// holds a directory at its name that the overlay would show.
///
/// A later entry supersedes what holds its name, and in a whole root that
/// stops at a directory with something in it, which cannot be removed to make
/// room. A base's directory cannot be removed at all, since the base is never
/// written; an entry laid over it would hide the base's whole directory
/// instead, and the files the base's own database records there with it. A
/// name the root already holds as something other than a directory, or as an
/// opaque directory, hides the base's entry already, and is the root's to
/// replace as it stands.
fn refuse_superseding_a_base_directory(
    parent: &Parent,
    leaf: &CString,
    entry_path: &[u8],
) -> Result<(), ProvisionError> {
    let Some(below) = &parent.lower else {
        return Ok(());
    };
    let inspecting =
        |errno: Errno| ProvisionError::io("inspecting", bytes_to_path(entry_path), errno.into());
    match rustix::fs::statat(&parent.dir, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) != FileType::Directory => return Ok(()),
        Ok(_) => {
            let own = rustix::fs::openat(
                &parent.dir,
                leaf,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(inspecting)?;
            if containment::is_opaque(own.as_fd()).map_err(inspecting)? {
                return Ok(());
            }
        }
        Err(Errno::NOENT) => {}
        Err(errno) => return Err(inspecting(errno)),
    }
    match rustix::fs::statat(below, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Directory => {
            Err(entry_refused(
                entry_path,
                "the base layer holds a directory at this path, which an entry that is not a \
                 directory cannot replace",
            ))
        }
        Ok(_) | Err(Errno::NOENT) => Ok(()),
        Err(errno) => Err(inspecting(errno)),
    }
}

/// What already occupies a name where a directory is about to be created.
enum DirClash {
    /// A real directory: kept, and its metadata recorded or merged into.
    Directory,
    /// A symlink that resolves within the tree to a directory — a merged-usr
    /// alias such as `/lib -> usr/lib`. Kept untouched: the directory is
    /// present through the alias, and the entry's children resolve through it
    /// exactly as a file entry's parent does. No metadata is applied, which
    /// would otherwise fall on the symlink or its target.
    AliasedDirectory,
    /// A file, a symlink to a non-directory, or a dangling symlink: replaced,
    /// per the tar convention that a later entry supersedes an earlier one.
    Replace,
}

/// Classifies the existing `leaf` under `parent` when a directory entry lands
/// on a name that is already taken (`mkdirat` returned `EEXIST`).
///
/// The merged-usr case is the reason this is not a plain is-a-directory test.
/// A usrmerged rootfs ships `/lib`, `/bin`, `/sbin` (and their multilib
/// siblings) as symlinks into `/usr`; the dynamic linker is reachable only
/// through them. A package's own bare directory entry for such a path — a
/// kernel image's `./lib/` for `/lib/modules`, say — must not replace the
/// symlink with a real directory, or the linker at `/usr/lib/.../ld-linux-*`
/// stops resolving as `/lib/ld-linux-*` and nothing dynamically linked can run.
/// `dpkg` applies the same aliasing. The rule is general — a symlink resolving
/// to a directory is satisfied — so it covers every aliased path without naming
/// any. `root` anchors the contained follow that recognizes the alias, and an
/// absolute alias (`bin -> /usr/bin`) is one as much as a relative one.
fn classify_existing_dir(
    root: BorrowedFd<'_>,
    parent: &OwnedFd,
    leaf: &CString,
    components: &[Vec<u8>],
    entry_path: &[u8],
) -> Result<DirClash, ProvisionError> {
    let stat = rustix::fs::statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|errno| {
        ProvisionError::io("inspecting", bytes_to_path(entry_path), errno.into())
    })?;
    let file_type = FileType::from_raw_mode(stat.st_mode);
    if file_type.is_dir() {
        Ok(DirClash::Directory)
    } else if file_type.is_symlink() && open_dir_at(root, components).is_ok() {
        // The symlink resolves, following in-tree, to a directory: an alias.
        Ok(DirClash::AliasedDirectory)
    } else {
        Ok(DirClash::Replace)
    }
}

/// Maps a parent-resolution failure onto the typed error surface.
///
/// `EXDEV` and `ELOOP` are the kernel refusing a resolution: the first is a
/// rename racing the walk out of the root, the second a magic link or a loop,
/// and the errno does not distinguish those two. Both are containment
/// failures. A link naming a place outside the tree is not one, since it
/// resolves inside the root, and a link to nothing there is `ENOTDIR` from the
/// creation that found its name taken. `ENOTDIR` is not either: an archive that
/// ships `foo` as a file and `foo/bar` after it is an ordinary malformed
/// archive, and calling that an escape attempt would tell a caller something
/// untrue about their input.
fn resolve_error(errno: Errno, entry_path: &[u8]) -> ProvisionError {
    match errno {
        Errno::XDEV => entry_unsafe(entry_path, "the path resolves outside the extraction root"),
        Errno::LOOP => entry_unsafe(
            entry_path,
            "the path resolves through a symlink loop or a magic link",
        ),
        Errno::NOTDIR => entry_refused(entry_path, "a parent component is not a directory"),
        errno => ProvisionError::io("resolving", bytes_to_path(entry_path), errno.into()),
    }
}

/// Extracts a regular file, streaming its data from the archive.
fn extract_file<R: Read>(
    tree: Tree<'_>,
    archive: &mut TarReader<R>,
    entry: &Entry,
    components: &[Vec<u8>],
    dir_meta: &mut HashMap<Vec<u8>, DirMeta>,
) -> Result<(), ProvisionError> {
    let parent = open_parent(tree, components, &entry.path, Some(dir_meta))?;
    let leaf = component_cstr(components.last().expect("non-empty"), &entry.path)?;
    refuse_superseding_a_base_directory(&parent, &leaf, &entry.path)?;

    let fd = create_replacing(
        &entry.path,
        || {
            rustix::fs::openat(
                &parent.dir,
                &leaf,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
        },
        &parent.dir,
        &leaf,
    )?;

    let mut file = File::from(fd);
    let mut buf = [0u8; 65536];
    loop {
        let got = archive.read_data(&mut buf)?;
        if got == 0 {
            break;
        }
        file.write_all(&buf[..got])
            .map_err(|err| ProvisionError::io("writing", bytes_to_path(&entry.path), err))?;
    }

    rustix::fs::fchmod(&file, Mode::from_raw_mode(entry.mode)).map_err(|errno| {
        ProvisionError::io(
            "setting the mode of",
            bytes_to_path(&entry.path),
            errno.into(),
        )
    })?;
    rustix::fs::futimens(&file, &timestamps(entry.mtime)).map_err(|errno| {
        ProvisionError::io(
            "setting the times of",
            bytes_to_path(&entry.path),
            errno.into(),
        )
    })?;
    Ok(())
}

/// Extracts a directory entry; its mode and mtime are recorded for the
/// deferred pass.
fn extract_dir(
    tree: Tree<'_>,
    entry: &Entry,
    components: &[Vec<u8>],
    dir_meta: &mut HashMap<Vec<u8>, DirMeta>,
) -> Result<(), ProvisionError> {
    let parent = open_parent(tree, components, &entry.path, Some(dir_meta))?;
    let leaf = component_cstr(components.last().expect("non-empty"), &entry.path)?;
    prepare_dir(tree, components, &entry.path, Some(dir_meta))?;

    match rustix::fs::mkdirat(&parent.dir, &leaf, Mode::from_raw_mode(0o700)) {
        Ok(()) => {}
        Err(Errno::EXIST) => {
            // A directory already in place (created implied, or a duplicate
            // entry) is kept; a merged-usr alias is left untouched, its
            // directory already present through the symlink; anything else is
            // replaced.
            match classify_existing_dir(tree.root, &parent.dir, &leaf, components, &entry.path)? {
                DirClash::Directory => {}
                // No metadata is recorded for an alias: the deferred pass opens
                // no-follow and would drop it, and the target owns its own.
                DirClash::AliasedDirectory => return Ok(()),
                DirClash::Replace => {
                    remove_at(&parent.dir, &leaf, &entry.path)?;
                    make_replacement_dir(tree, &parent.dir, &leaf, &entry.path)?;
                }
            }
        }
        Err(errno) => {
            return Err(ProvisionError::io(
                "creating",
                bytes_to_path(&entry.path),
                errno.into(),
            ));
        }
    }

    dir_meta.insert(
        join(components),
        DirMeta {
            mode: entry.mode,
            mtime: Some(entry.mtime),
        },
    );
    Ok(())
}

/// Extracts a symlink; the target is stored verbatim and never resolved.
fn extract_symlink(
    tree: Tree<'_>,
    entry: &Entry,
    components: &[Vec<u8>],
    dir_meta: &mut HashMap<Vec<u8>, DirMeta>,
) -> Result<(), ProvisionError> {
    if entry.link_target.is_empty() {
        return Err(entry_refused(&entry.path, "the symlink target is empty"));
    }
    let target = CString::new(entry.link_target.clone())
        .map_err(|_| entry_unsafe(&entry.path, "the symlink target contains a NUL byte"))?;
    let parent = open_parent(tree, components, &entry.path, Some(dir_meta))?;
    let leaf = component_cstr(components.last().expect("non-empty"), &entry.path)?;
    refuse_superseding_a_base_directory(&parent, &leaf, &entry.path)?;

    create_replacing(
        &entry.path,
        || rustix::fs::symlinkat(&target, &parent.dir, &leaf),
        &parent.dir,
        &leaf,
    )?;

    rustix::fs::utimensat(
        &parent.dir,
        &leaf,
        &timestamps(entry.mtime),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|errno| {
        ProvisionError::io(
            "setting the times of",
            bytes_to_path(&entry.path),
            errno.into(),
        )
    })?;
    Ok(())
}

/// Extracts a hardlink to an already-extracted entry. The link target is
/// validated and resolved under the same containment as entry paths.
///
/// The target is an entry this extraction wrote, so in a layered one its chain
/// is already in the root: its own entry put it there.
fn extract_hardlink(
    tree: Tree<'_>,
    entry: &Entry,
    components: &[Vec<u8>],
    dir_meta: &mut HashMap<Vec<u8>, DirMeta>,
) -> Result<(), ProvisionError> {
    // The context is the entry's own path — the archive member at fault — while
    // the noun names which of its two paths was rejected.
    let target_components = validate_path(&entry.link_target, &entry.path, "hardlink target")?;
    if target_components.is_empty() {
        return Err(entry_unsafe(&entry.path, "the hardlink target is empty"));
    }
    let target_parent = open_dir_at(tree.root, &target_components[..target_components.len() - 1])
        .map_err(|errno| resolve_error(errno, &entry.path))?;
    let target_leaf = component_cstr(target_components.last().expect("non-empty"), &entry.path)?;

    let parent = open_parent(tree, components, &entry.path, Some(dir_meta))?;
    let leaf = component_cstr(components.last().expect("non-empty"), &entry.path)?;
    refuse_superseding_a_base_directory(&parent, &leaf, &entry.path)?;

    create_replacing(
        &entry.path,
        || {
            rustix::fs::linkat(
                &target_parent,
                &target_leaf,
                &parent.dir,
                &leaf,
                AtFlags::empty(),
            )
        },
        &parent.dir,
        &leaf,
    )?;
    Ok(())
}

/// Extracts a FIFO.
///
/// Created at [`FIFO_CREATION_MODE`], since `mknodat` narrows a mode by the
/// umask, and then given its entry's mode and time through a descriptor for
/// the pipe itself. Opening a pipe for reading with `O_NONBLOCK` returns at
/// once, with no writer needed; `O_NOFOLLOW` refuses a leaf a racer replaced
/// with a link since the `mknodat`, and the kind is checked again on what
/// opened, so the mode an archive states lands on the pipe this created and on
/// nothing else.
fn extract_fifo(
    tree: Tree<'_>,
    entry: &Entry,
    components: &[Vec<u8>],
    dir_meta: &mut HashMap<Vec<u8>, DirMeta>,
) -> Result<(), ProvisionError> {
    let parent = open_parent(tree, components, &entry.path, Some(dir_meta))?;
    let leaf = component_cstr(components.last().expect("non-empty"), &entry.path)?;
    refuse_superseding_a_base_directory(&parent, &leaf, &entry.path)?;

    create_replacing(
        &entry.path,
        || {
            rustix::fs::mknodat(
                &parent.dir,
                &leaf,
                FileType::Fifo,
                Mode::from_raw_mode(FIFO_CREATION_MODE),
                0,
            )
        },
        &parent.dir,
        &leaf,
    )?;

    let pipe = containment::open_created_fifo(parent.dir.as_fd(), &leaf)
        .map_err(|errno| ProvisionError::io("opening", bytes_to_path(&entry.path), errno.into()))?;
    rustix::fs::fchmod(&pipe, Mode::from_raw_mode(entry.mode)).map_err(|errno| {
        ProvisionError::io(
            "setting the mode of",
            bytes_to_path(&entry.path),
            errno.into(),
        )
    })?;
    rustix::fs::futimens(&pipe, &timestamps(entry.mtime)).map_err(|errno| {
        ProvisionError::io(
            "setting the times of",
            bytes_to_path(&entry.path),
            errno.into(),
        )
    })?;
    Ok(())
}

/// Runs `create`, replacing whatever occupies the name on `EEXIST`: the
/// tar convention that a later entry supersedes an earlier one.
///
/// [`containment::replacing`] is the algorithm; what is here is this side's
/// vocabulary for its failures, which names the archive entry a caller can act
/// on rather than the errno the kernel gave. An `EEXIST` that survives the
/// retries is reported as its own thing: it is not a name that could not be
/// created but a name that could not be *replaced*, which is what a non-empty
/// directory standing where a file belongs looks like.
fn create_replacing<T>(
    entry_path: &[u8],
    create: impl FnMut() -> Result<T, Errno>,
    parent: &OwnedFd,
    leaf: &CString,
) -> Result<T, ProvisionError> {
    containment::replacing(parent, leaf, create).map_err(|errno| {
        if errno == Errno::EXIST {
            ProvisionError::io(
                "creating",
                bytes_to_path(entry_path),
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the name could not be replaced",
                ),
            )
        } else {
            ProvisionError::io("creating", bytes_to_path(entry_path), errno.into())
        }
    })
}

/// [`containment::remove_at`], reported as this side's failure: naming the
/// archive entry a caller can act on rather than the errno the kernel gave.
fn remove_at(parent: &OwnedFd, leaf: &CString, entry_path: &[u8]) -> Result<(), ProvisionError> {
    containment::remove_at(parent, leaf)
        .map_err(|errno| ProvisionError::io("replacing", bytes_to_path(entry_path), errno.into()))
}

/// Applies the deferred directory metadata, deepest first, so a parent's
/// mtime is not disturbed by touching its children, and a read-only mode
/// lands only after the directory's contents are complete.
fn apply_dir_meta(
    root: BorrowedFd<'_>,
    dir_meta: HashMap<Vec<u8>, DirMeta>,
) -> Result<(), ProvisionError> {
    let mut entries: Vec<(Vec<u8>, DirMeta)> = dir_meta.into_iter().collect();
    entries.sort_by_key(|(path, _)| std::cmp::Reverse(depth(path)));
    for (path, meta) in entries {
        let components: Vec<&[u8]> = path.split(|b| *b == b'/').collect();
        let fd = match open_dir_meta_fd(root, &components) {
            Ok(fd) => fd,
            // The directory was removed by a later entry (NOENT), replaced by a
            // non-directory (NOTDIR), or replaced by a symlink where a
            // directory stood (LOOP, from the no-follow open). In every case the
            // directory this metadata described is gone, so there is nothing to
            // describe; applying it to whatever took its place would let the
            // archive retarget an unrelated in-tree entry.
            Err(Errno::NOENT | Errno::NOTDIR | Errno::LOOP) => continue,
            Err(errno) => {
                return Err(ProvisionError::io(
                    "finalizing",
                    bytes_to_path(&path),
                    errno.into(),
                ));
            }
        };
        apply_meta_fd(fd.as_fd(), &meta).map_err(|errno| {
            ProvisionError::io("finalizing", bytes_to_path(&path), errno.into())
        })?;
    }
    Ok(())
}

/// Opens a directory for metadata application. `O_PATH` fds do not accept
/// `fchmod`, so this open is `O_RDONLY` — which works because directories
/// still hold their writable creation mode at this point.
///
/// `O_NOFOLLOW` refuses a leaf that a later archive entry turned into a
/// symlink: the containment would keep the follow in-tree, but following it
/// would apply this directory's archive mode and mtime to whatever the symlink
/// names, so the leaf must be the directory itself or the metadata is dropped.
/// This matches the `O_NOFOLLOW` discipline the extraction leaves use.
fn open_dir_meta_fd(root: BorrowedFd<'_>, components: &[&[u8]]) -> Result<OwnedFd, Errno> {
    containment::open_dir(
        root,
        components,
        OFlags::RDONLY | OFlags::NOFOLLOW,
        CONTAINMENT,
    )
}

/// Applies a directory's deferred mode and mtime through its fd.
fn apply_meta_fd(fd: BorrowedFd<'_>, meta: &DirMeta) -> Result<(), Errno> {
    rustix::fs::fchmod(fd, Mode::from_raw_mode(meta.mode))?;
    if let Some(mtime) = meta.mtime {
        rustix::fs::futimens(fd, &timestamps(mtime))?;
    }
    Ok(())
}

/// Timestamps that set the modification time and leave the access time
/// untouched.
fn timestamps(mtime: i64) -> Timestamps {
    Timestamps {
        last_access: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        last_modification: Timespec {
            tv_sec: mtime,
            tv_nsec: 0,
        },
    }
}

/// Joins path components with `/`.
fn join(components: &[Vec<u8>]) -> Vec<u8> {
    components.join(&b'/')
}

/// The number of components in a joined path.
fn depth(path: &[u8]) -> usize {
    path.iter().filter(|b| **b == b'/').count() + 1
}

/// A single path component as a `CString` (components are pre-validated,
/// so a NUL cannot occur; the error path is defensive).
fn component_cstr(component: &[u8], entry_path: &[u8]) -> Result<CString, ProvisionError> {
    CString::new(component.to_vec())
        .map_err(|_| entry_unsafe(entry_path, "the path contains a NUL byte"))
}

/// Builds [`ProvisionError::EntryUnsafe`], for an entry that tried to reach
/// outside the extraction root.
fn entry_unsafe(path: &[u8], reason: impl Into<String>) -> ProvisionError {
    ProvisionError::EntryUnsafe {
        path: bytes_to_path(path),
        reason: reason.into(),
    }
}

/// Builds [`ProvisionError::EntryRefused`], for an entry the extractor cannot
/// write for a reason that is not a containment failure — a malformed archive,
/// rather than one reaching for the host.
fn entry_refused(path: &[u8], reason: impl Into<String>) -> ProvisionError {
    ProvisionError::EntryRefused {
        path: bytes_to_path(path),
        reason: reason.into(),
    }
}

/// An archive path, as bytes, for error display.
fn bytes_to_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
}

/// Copies the directory tree at `source` into the directory at `root`, with the
/// same kernel-enforced containment as archive extraction.
///
/// Every parent is resolved inside `root` with `openat2` and [`CONTAINMENT`],
/// and every leaf is created `O_NOFOLLOW`, so nothing in `source` — nor a
/// symlink already in `root` — can cause a write outside `root`. The contents
/// of `source` are laid at the root: `source/etc/hosts` becomes
/// `<root>/etc/hosts`. A regular file or symlink replaces whatever occupies its
/// name, the way a later archive entry supersedes an earlier one, so the
/// overlay overrides a file a package already unpacked; directories merge.
/// File modes are preserved and symlink targets are stored verbatim; entries
/// are written by the calling user, whom the sandbox's identity map presents as
/// root inside. A link the root already holds is followed as the root follows
/// it, an absolute one included: an overlay's `var/run/` lands in `run/` where
/// the root links `var/run` to `/run`, and the link stays a link.
///
/// `over` is the base `root` is an overlay upper over, in a layered build, and
/// is consulted as [`Extraction::over`] consults it: an overlay directory where
/// the base links to a directory merges through the link rather than hiding
/// it.
///
/// This backs the Debian and Alpine provisioners' pre-configure overlay, which
/// lays a caller's configuration into the root after the packages are unpacked
/// and before their scripts run. Entry kinds that have no place in a
/// configuration overlay — device nodes, FIFOs, sockets — are skipped.
///
/// It is the second answer to laying a host tree into a root, beside
/// [`CopyIn`](super::CopyIn), and the two share one policy for what the root
/// already holds. An existing directory is merged into, and neither sets its
/// owner, mode, or modification time. A symbolic link resolving inside the root
/// to a directory, an absolute one included, is merged through and never
/// replaced. Anything else at a directory's name is replaced, as a file
/// replaces what occupies its own name.
///
/// Where they differ, the job differs. This runs in the provisioner's own
/// process between two dpkg or apk waves, writing as the calling user, whom the
/// bootstrap's identity map already presents as root, so it needs no child
/// re-entered into the map. It can lay into an upper over a base, which a
/// `CopyIn` never writes into. It stamps what it writes with the time of
/// writing, as the rest of a bootstrap does; an export's `clamp_mtime` is what
/// makes the root reproducible, where a `CopyIn` carries the source's times
/// because it mirrors an export. And it lays only what configuration for the
/// scripts that run next consists of, with no report of the rest, where a
/// `CopyIn` copies any tree and names what it leaves out.
#[cfg(any(feature = "debian", feature = "alpine"))]
pub(crate) fn overlay_tree(
    root: &Path,
    source: &Path,
    over: Option<&Path>,
) -> Result<(), ProvisionError> {
    let root_fd = open_root(root)?;
    let lower_fd = over.map(open_root).transpose()?;
    let tree = Tree {
        root: root_fd.as_fd(),
        lower: lower_fd.as_ref().map(AsFd::as_fd),
    };
    overlay_dir(tree, source)
}

/// One item of the overlay walk's stack.
#[cfg(any(feature = "debian", feature = "alpine"))]
enum OverlayStep {
    /// Copy this source entry in beneath the current destination directory.
    Visit(PathBuf),
    /// The children pushed above this marker are done: step back out of their
    /// directory.
    Leave,
}

/// Copies the entries of `source_dir` into the tree.
///
/// A directory is created before it is descended into, so a parent is always
/// in place when a child beneath it is written, and the deferred-metadata pass
/// the archive extractor needs is unnecessary: each directory's mode is set as
/// it is created.
///
/// The walk carries its own stack rather than recursing, so an arbitrarily deep
/// source tree costs heap rather than call frames. `components` names the
/// destination directory relative to the root, empty at the top; each directory
/// pushes a [`OverlayStep::Leave`] marker beneath its children, which pops that
/// name back off once they are all done.
#[cfg(any(feature = "debian", feature = "alpine"))]
fn overlay_dir(tree: Tree<'_>, source_dir: &Path) -> Result<(), ProvisionError> {
    let mut components: Vec<Vec<u8>> = Vec::new();
    let mut pending = Vec::new();
    push_children(source_dir, &mut pending)?;

    while let Some(step) = pending.pop() {
        let OverlayStep::Visit(source_path) = step else {
            components.pop();
            continue;
        };
        let kind = fs::symlink_metadata(&source_path)
            .map_err(|err| ProvisionError::io("inspecting the overlay entry", &source_path, err))?
            .file_type();

        // read_dir never yields `.` or `..`, and a name is a single component,
        // so the pushed component is always a safe leaf.
        let name = source_path.file_name().expect("an entry of a directory");
        components.push(name.as_bytes().to_vec());
        if kind.is_symlink() {
            overlay_symlink(tree, &source_path, &components)?;
        } else if kind.is_dir() {
            overlay_mkdir(tree, &source_path, &components)?;
            // The marker goes on first, so it resurfaces only once every child
            // pushed above it has been visited.
            pending.push(OverlayStep::Leave);
            push_children(&source_path, &mut pending)?;
            continue;
        } else if kind.is_file() {
            overlay_file(tree, &source_path, &components)?;
        }
        components.pop();
    }
    Ok(())
}

/// Pushes the entries of `dir` onto the overlay walk's stack.
///
/// They go on in reverse so they pop in name order: `read_dir` order is
/// filesystem-dependent, and the walk must be deterministic.
#[cfg(any(feature = "debian", feature = "alpine"))]
fn push_children(dir: &Path, pending: &mut Vec<OverlayStep>) -> Result<(), ProvisionError> {
    let read = |err| ProvisionError::io("reading the overlay directory", dir, err);
    let mut children: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(read)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()
        .map_err(read)?;
    children.sort();
    pending.extend(children.into_iter().rev().map(OverlayStep::Visit));
    Ok(())
}

/// Creates the overlay directory named by `components`, or merges into one
/// already present, replacing a non-directory in the way.
#[cfg(any(feature = "debian", feature = "alpine"))]
fn overlay_mkdir(
    tree: Tree<'_>,
    source_path: &Path,
    components: &[Vec<u8>],
) -> Result<(), ProvisionError> {
    let path = join(components);
    let parent = open_parent(tree, components, &path, None)?;
    let leaf = component_cstr(components.last().expect("non-empty"), &path)?;
    let mode = source_mode(source_path)?;
    prepare_dir(tree, components, &path, None)?;

    // A newly created directory gets its mode set explicitly, since mkdirat
    // honors the umask; an existing directory is merged into and keeps its own
    // mode, since the overlay describes the files it carries, not the modes of
    // directories a package already created. A merged-usr alias (`/lib ->
    // usr/lib`) is treated as an existing directory too — merged through,
    // never replaced — so an overlay directory cannot orphan the linker any
    // more than a package entry can.
    let created = match rustix::fs::mkdirat(&parent.dir, &leaf, Mode::from_raw_mode(0o700)) {
        Ok(()) => true,
        Err(Errno::EXIST) => {
            match classify_existing_dir(tree.root, &parent.dir, &leaf, components, &path)? {
                DirClash::Directory | DirClash::AliasedDirectory => false,
                DirClash::Replace => {
                    remove_at(&parent.dir, &leaf, &path)?;
                    make_replacement_dir(tree, &parent.dir, &leaf, &path)?;
                    true
                }
            }
        }
        Err(errno) => {
            return Err(ProvisionError::io(
                "creating",
                bytes_to_path(&path),
                errno.into(),
            ));
        }
    };
    if created {
        // Through a descriptor for the directory just made: `O_NOFOLLOW` and
        // `O_DIRECTORY` refuse whatever a racer put at the name since.
        let setting = |errno: Errno| {
            ProvisionError::io("setting the mode of", bytes_to_path(&path), errno.into())
        };
        let dir = rustix::fs::openat(
            &parent.dir,
            &leaf,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(setting)?;
        rustix::fs::fchmod(&dir, Mode::from_raw_mode(mode)).map_err(setting)?;
    }
    Ok(())
}

/// Copies the overlay file named by `components`, replacing whatever occupies
/// the name; the leaf is created `O_NOFOLLOW`, so a symlink in the way is
/// replaced rather than written through.
#[cfg(any(feature = "debian", feature = "alpine"))]
fn overlay_file(
    tree: Tree<'_>,
    source_path: &Path,
    components: &[Vec<u8>],
) -> Result<(), ProvisionError> {
    let path = join(components);
    let parent = open_parent(tree, components, &path, None)?;
    let leaf = component_cstr(components.last().expect("non-empty"), &path)?;
    let mode = source_mode(source_path)?;
    refuse_superseding_a_base_directory(&parent, &leaf, &path)?;

    let fd = create_replacing(
        &path,
        || {
            rustix::fs::openat(
                &parent.dir,
                &leaf,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
        },
        &parent.dir,
        &leaf,
    )?;

    let mut source = File::open(source_path)
        .map_err(|err| ProvisionError::io("reading the overlay file", source_path, err))?;
    let mut dest = File::from(fd);
    io::copy(&mut source, &mut dest)
        .map_err(|err| ProvisionError::io("writing", bytes_to_path(&path), err))?;
    rustix::fs::fchmod(&dest, Mode::from_raw_mode(mode)).map_err(|errno| {
        ProvisionError::io("setting the mode of", bytes_to_path(&path), errno.into())
    })?;
    Ok(())
}

/// Recreates the overlay symlink named by `components`, its target stored
/// verbatim and never resolved, replacing whatever occupies the name.
#[cfg(any(feature = "debian", feature = "alpine"))]
fn overlay_symlink(
    tree: Tree<'_>,
    source_path: &Path,
    components: &[Vec<u8>],
) -> Result<(), ProvisionError> {
    let path = join(components);
    let target = fs::read_link(source_path)
        .map_err(|err| ProvisionError::io("reading the overlay symlink", source_path, err))?;
    let target = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| entry_unsafe(&path, "the symlink target contains a NUL byte"))?;
    let parent = open_parent(tree, components, &path, None)?;
    let leaf = component_cstr(components.last().expect("non-empty"), &path)?;
    refuse_superseding_a_base_directory(&parent, &leaf, &path)?;

    create_replacing(
        &path,
        || rustix::fs::symlinkat(&target, &parent.dir, &leaf),
        &parent.dir,
        &leaf,
    )?;
    Ok(())
}

/// The permission bits of `path`, without following a final symlink.
#[cfg(any(feature = "debian", feature = "alpine"))]
fn source_mode(path: &Path) -> Result<u32, ProvisionError> {
    let stat = rustix::fs::statat(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|errno| ProvisionError::io("inspecting the overlay entry", path, errno.into()))?;
    Ok(stat.st_mode & 0o7777)
}

// The overlay tests exercise the Debian pre-configure overlay, which only
// exists with that feature.
#[cfg(all(test, feature = "debian"))]
mod tests {
    use super::*;
    use crate::scratch::Scratch;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn overlay_lays_files_and_dirs_and_preserves_modes() {
        // A nested directory and file are created, an existing directory is
        // merged into, and file modes are preserved.
        let base = Scratch::for_test("overlay", "basic");
        let root = base.join("root");
        let source = base.join("source");
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(source.join("etc/depthcharge-tools")).unwrap();
        fs::write(source.join("etc/locale.gen"), b"en_US.UTF-8 UTF-8\n").unwrap();
        let guard = source.join("etc/depthcharge-tools/config");
        fs::write(&guard, b"board=x\n").unwrap();
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o640)).unwrap();

        overlay_tree(&root, &source, None).expect("the overlay applies");

        assert_eq!(
            fs::read(root.join("etc/locale.gen")).unwrap(),
            b"en_US.UTF-8 UTF-8\n"
        );
        assert!(root.join("etc/depthcharge-tools").is_dir());
        assert_eq!(
            fs::read(root.join("etc/depthcharge-tools/config")).unwrap(),
            b"board=x\n"
        );
        let mode = fs::symlink_metadata(root.join("etc/depthcharge-tools/config"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o640, "the file mode is preserved");
    }

    #[test]
    fn an_implied_parent_is_traversable_without_a_deferred_mode_pass() {
        // `open_parent` creates a missing directory 0700 and leaves widening it
        // to the caller's later mode pass. A caller with no such pass — the
        // overlay walk — asks for the mode at once instead, or the directory
        // would keep a mode that only its owner can traverse.
        let base = Scratch::for_test("overlay", "implied-parent");
        let root = base.join("root");
        fs::create_dir_all(&root).unwrap();
        let fd = rustix::fs::open(
            &root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();

        let components: Vec<Vec<u8>> = [&b"usr"[..], b"lib", b"file"]
            .iter()
            .map(|name| name.to_vec())
            .collect();
        let tree = Tree {
            root: fd.as_fd(),
            lower: None,
        };
        open_parent(tree, &components, b"usr/lib/file", None)
            .expect("the implied parents are created");

        for path in ["usr", "usr/lib"] {
            let mode = fs::symlink_metadata(root.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(mode, 0o755, "{path} kept its creation mode");
        }
    }

    #[test]
    fn an_overlay_directory_merges_through_an_absolute_link_the_root_holds() {
        // The root links `var/run` to `/run`, as Debian's base-files does. An
        // overlay that carries `var/run/` merges into the root's `run`, and the
        // link stays a link rather than being replaced by a directory.
        let base = Scratch::for_test("overlay", "absolute-link");
        let root = base.join("root");
        let source = base.join("source");
        fs::create_dir_all(root.join("run")).unwrap();
        fs::create_dir_all(root.join("var")).unwrap();
        std::os::unix::fs::symlink("/run", root.join("var/run")).unwrap();
        fs::create_dir_all(source.join("var/run/app")).unwrap();
        fs::write(source.join("var/run/app/state"), b"ready\n").unwrap();

        overlay_tree(&root, &source, None).expect("the overlay applies");

        assert_eq!(
            fs::read_link(root.join("var/run")).unwrap(),
            Path::new("/run")
        );
        assert_eq!(fs::read(root.join("run/app/state")).unwrap(), b"ready\n");
    }

    #[test]
    fn overlay_replaces_a_package_conffile() {
        // A file a package already unpacked is overwritten by the overlay's,
        // which is how a shipped conffile is overridden.
        let base = Scratch::for_test("overlay", "conffile");
        let root = base.join("root");
        let source = base.join("source");
        fs::create_dir_all(root.join("etc/default")).unwrap();
        fs::write(root.join("etc/default/keyboard"), b"XKBLAYOUT=us\n").unwrap();
        fs::create_dir_all(source.join("etc/default")).unwrap();
        fs::write(source.join("etc/default/keyboard"), b"XKBLAYOUT=de\n").unwrap();

        overlay_tree(&root, &source, None).expect("the overlay applies");

        assert_eq!(
            fs::read(root.join("etc/default/keyboard")).unwrap(),
            b"XKBLAYOUT=de\n",
        );
    }

    #[test]
    fn overlay_stores_symlinks_verbatim_without_following_them() {
        // A relative in-tree link is stored as itself; an absolute link out of
        // the tree is stored as a link, never followed to write at its target.
        let base = Scratch::for_test("overlay", "symlink");
        let root = base.join("root");
        let source = base.join("source");
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(source.join("etc")).unwrap();
        std::os::unix::fs::symlink("../usr/share/zoneinfo/UTC", source.join("etc/localtime"))
            .unwrap();
        let escape = base.join("escape-target");
        std::os::unix::fs::symlink(&escape, source.join("etc/escape")).unwrap();

        overlay_tree(&root, &source, None).expect("the overlay applies");

        assert!(
            fs::symlink_metadata(root.join("etc/localtime"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_link(root.join("etc/localtime")).unwrap(),
            Path::new("../usr/share/zoneinfo/UTC"),
        );
        assert!(
            fs::symlink_metadata(root.join("etc/escape"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            !escape.exists(),
            "the escaping symlink was not followed to write outside the root",
        );
    }

    #[test]
    fn overlay_contains_a_write_through_a_planted_root_symlink() {
        // A symlink already in the root pointing outside must not become a path
        // a file is written through: the leaf is created O_NOFOLLOW, so the
        // symlink is replaced by the file rather than followed.
        let base = Scratch::for_test("overlay", "contain");
        let root = base.join("root");
        let source = base.join("source");
        fs::create_dir_all(&root).unwrap();
        let outside = base.join("outside");
        fs::write(&outside, b"original\n").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("passwd")).unwrap();
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("passwd"), b"overlaid\n").unwrap();

        overlay_tree(&root, &source, None).expect("the overlay applies");

        assert_eq!(fs::read(root.join("passwd")).unwrap(), b"overlaid\n");
        assert!(
            !fs::symlink_metadata(root.join("passwd"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the planted symlink was replaced, not followed",
        );
        assert_eq!(
            fs::read(&outside).unwrap(),
            b"original\n",
            "the outside target was not written through",
        );
    }
}

// The prefix strip serves the Gentoo layer's image archives, which wrap the
// tree they describe in a directory. It sits apart from the overlay tests above
// because those need the Debian feature and this needs none.
#[cfg(test)]
mod prefix_tests {
    use super::strip_prefix;
    #[cfg(feature = "gentoo")]
    use super::{Extraction, Placement, TarReader};
    #[cfg(feature = "gentoo")]
    use crate::scratch::Scratch;
    #[cfg(feature = "gentoo")]
    use std::fs;
    #[cfg(feature = "gentoo")]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(feature = "gentoo")]
    #[test]
    fn a_wrapper_directory_does_not_become_the_extraction_roots_metadata() {
        // The wrapper describes the directory the archive was built in, not the
        // root it is unpacked into -- and the root belongs to the caller, who
        // may be merging a hundred containers into it. Reading the wrapper as
        // the `./` entry rewrote that root's mode and modification time once
        // per container.
        let root = Scratch::for_test("extract", "wrapper-root-mode");
        fs::set_permissions(&*root, fs::Permissions::from_mode(0o755)).unwrap();

        let mut tar = ferroday_cage_testkit::tar::Tar::new();
        tar.dir("image/", 0o700)
            .file("image/usr/bin/git", 0o755, b"binary\n");
        let archive = tar.finish();

        let mut extraction = Extraction::new(&root)
            .expect("the root opens")
            .under(b"image");
        extraction
            .extract(&mut TarReader::new(&archive[..]), &mut |_, _| {
                Ok(Placement::Write)
            })
            .expect("the image extracts");
        extraction
            .finalize(&root)
            .expect("the extraction finalizes");

        assert_eq!(
            fs::symlink_metadata(&*root).unwrap().permissions().mode() & 0o7777,
            0o755,
            "the wrapper's own mode must not reach the extraction root",
        );
        assert!(root.join("usr/bin/git").exists(), "the image still lands");
    }

    #[test]
    fn a_wrapper_prefix_is_stripped_only_from_paths_actually_under_it() {
        // The prefix names a directory, so a path that merely begins with those
        // bytes is not inside it. Reading `image2/x` as under `image/` would
        // write one package's files into another's tree.
        for prefix in [&b"image/"[..], b"image"] {
            assert_eq!(
                strip_prefix(b"image/usr/bin/git", prefix),
                Some(&b"usr/bin/git"[..]),
            );
            // The wrapper's own entry, either way it is spelled, names the
            // extraction root.
            assert_eq!(strip_prefix(b"image/", prefix), Some(&b""[..]));
            assert_eq!(strip_prefix(b"image", prefix), Some(&b""[..]));
            for outside in [&b"image2/x"[..], b"images", b"other/x", b"", b"/image/x"] {
                assert_eq!(strip_prefix(outside, prefix), None, "{outside:?}");
            }
        }
    }
}

// The entry kinds whose mode is set after they are created, which every build
// with an extractor writes.
#[cfg(test)]
mod mode_tests {
    use super::{Placement, TarReader, extract_archive};
    use crate::scratch::Scratch;
    use ferroday_cage_testkit::tar::Tar;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    #[test]
    fn a_named_pipe_takes_its_entrys_mode_even_one_its_owner_cannot_read() {
        // The pipe is created owner-only and given its own mode through a
        // descriptor opened for reading, without waiting for a writer, so a
        // mode that denies its owner reading still lands on it, and a mode
        // wider than the creation mode does too.
        let root = Scratch::for_test("extract", "fifo-modes");
        let mut tar = Tar::new();
        tar.entry("write-only", b'6', 0o220, 0, 0, "", b"")
            .entry("shared", b'6', 0o666, 0, 0, "", b"");
        extract_archive(
            &mut TarReader::new(&tar.finish()[..]),
            &root,
            &mut |_, _| Ok(Placement::Write),
        )
        .expect("the pipes extract");

        for (name, mode) in [("write-only", 0o220), ("shared", 0o666)] {
            let found = std::fs::symlink_metadata(root.join(name)).expect("the pipe is laid");
            assert!(found.file_type().is_fifo(), "{name}");
            assert_eq!(found.permissions().mode() & 0o7777, mode, "{name}");
        }
    }
}

// A layered extraction is what the Debian, Alpine and Gentoo layers stage an
// increment with, and `Extraction::over` exists only where one of them does.
#[cfg(all(test, any(feature = "debian", feature = "alpine", feature = "gentoo")))]
mod layered_tests {
    use super::{Extraction, Placement, TarReader};
    use crate::scratch::Scratch;
    use ferroday_cage_testkit::tar::Tar;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::Path;

    /// Extracts `archive` into `upper` as an overlay upper over `base`,
    /// returning every path the hook was shown.
    fn extract_over(
        upper: &Path,
        base: &Path,
        archive: &[u8],
    ) -> Result<Vec<String>, crate::provision::ProvisionError> {
        let mut seen = Vec::new();
        let mut extraction = Extraction::new(upper)?.over(Some(base))?;
        extraction.extract(&mut TarReader::new(archive), &mut |_, components| {
            seen.push(String::from_utf8(components.join(&b'/')).unwrap());
            Ok(Placement::Write)
        })?;
        extraction.finalize(upper)?;
        Ok(seen)
    }

    /// A merged-usr base, as a Gentoo stage3 lays it out: `lib64` and `sbin`
    /// are links into `usr`, and `usr/sbin` is a link beside `usr/bin`.
    fn merged_usr_base(scratch: &Scratch) -> std::path::PathBuf {
        let base = scratch.join("base");
        fs::create_dir_all(base.join("usr/lib64")).unwrap();
        fs::create_dir_all(base.join("usr/bin")).unwrap();
        fs::write(base.join("usr/lib64/ld-linux-x86-64.so.2"), b"loader").unwrap();
        fs::write(base.join("usr/bin/sh"), b"shell").unwrap();
        symlink("usr/lib64", base.join("lib64")).unwrap();
        symlink("usr/bin", base.join("sbin")).unwrap();
        symlink("bin", base.join("usr/sbin")).unwrap();
        fs::set_permissions(base.join("usr/lib64"), fs::Permissions::from_mode(0o750)).unwrap();
        base
    }

    /// The paths under `dir`, recursively, without following a link.
    fn listing(dir: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(at) = pending.pop() {
            for entry in fs::read_dir(&at).unwrap() {
                let path = entry.unwrap().path();
                found.push(path.strip_prefix(dir).unwrap().display().to_string());
                if fs::symlink_metadata(&path).unwrap().is_dir() {
                    pending.push(path);
                }
            }
        }
        found.sort();
        found
    }

    #[test]
    fn an_increment_lands_through_the_bases_merged_usr_links() {
        // The binhost's lvm2 ships `lib64/libdevmapper.so.1.02` and
        // `sbin/dmsetup`. In a bare upper those become real directories, and
        // the overlay shows a real directory over the base's link, so the
        // merged `/lib64` would hold libdevmapper and lose the loader.
        let scratch = Scratch::for_test("extract-layered", "merged-usr");
        let base = merged_usr_base(&scratch);
        let before = listing(&base);
        let upper = scratch.join("upper");
        fs::create_dir(&upper).unwrap();

        let mut tar = Tar::new();
        tar.dir("lib64/", 0o755)
            .file("lib64/libdevmapper.so.1.02", 0o755, b"library")
            .symlink("lib64/libdevmapper.so", "libdevmapper.so.1.02")
            .dir("sbin/", 0o755)
            .file("sbin/dmsetup", 0o755, b"tool")
            .file("usr/sbin/lvm", 0o755, b"lvm");
        let seen = extract_over(&upper, &base, &tar.finish()).expect("the increment extracts");

        // Each entry landed where the base's links point, inside the upper.
        assert_eq!(
            fs::read(upper.join("usr/lib64/libdevmapper.so.1.02")).unwrap(),
            b"library"
        );
        assert_eq!(
            fs::read_link(upper.join("usr/lib64/libdevmapper.so")).unwrap(),
            Path::new("libdevmapper.so.1.02"),
        );
        assert_eq!(fs::read(upper.join("usr/bin/dmsetup")).unwrap(), b"tool");
        assert_eq!(fs::read(upper.join("usr/bin/lvm")).unwrap(), b"lvm");
        // The links the walk passed through are the upper's now too, as the
        // base spells them, so the merged view keeps them links.
        for (link, target) in [
            ("lib64", "usr/lib64"),
            ("sbin", "usr/bin"),
            ("usr/sbin", "bin"),
        ] {
            assert_eq!(
                fs::read_link(upper.join(link)).unwrap(),
                Path::new(target),
                "{link}",
            );
        }
        // A directory carried up from the base keeps the base's mode.
        assert_eq!(
            fs::metadata(upper.join("usr/lib64")).unwrap().mode() & 0o7777,
            0o750,
        );
        // What a package database records is the archive's own path.
        assert_eq!(
            seen,
            [
                "lib64",
                "lib64/libdevmapper.so.1.02",
                "lib64/libdevmapper.so",
                "sbin",
                "sbin/dmsetup",
                "usr/sbin/lvm",
            ],
        );
        // And the base was only read.
        assert_eq!(listing(&base), before);
    }

    #[test]
    fn a_link_the_increment_ships_over_the_bases_own_is_the_increments() {
        // The increment's own entry supersedes the base's at the name, and
        // what it ships beneath resolves through the increment's link.
        let scratch = Scratch::for_test("extract-layered", "own-link");
        let base = merged_usr_base(&scratch);
        let upper = scratch.join("upper");
        fs::create_dir(&upper).unwrap();

        let mut tar = Tar::new();
        tar.symlink("lib64", "usr/lib64")
            .file("lib64/libz.so.1", 0o755, b"zlib");
        extract_over(&upper, &base, &tar.finish()).expect("the increment extracts");

        assert_eq!(
            fs::read_link(upper.join("lib64")).unwrap(),
            Path::new("usr/lib64")
        );
        assert_eq!(
            fs::read(upper.join("usr/lib64/libz.so.1")).unwrap(),
            b"zlib"
        );
    }

    #[test]
    fn an_absolute_link_of_the_bases_resolves_inside_the_root() {
        // Debian's base-files ships `var/run -> /run`, and an Alpine root
        // carries `etc/ssl1.1/certs -> /etc/ssl/certs`. Inside the finished
        // sandbox each names the root's own directory, and that is where an
        // entry beneath one lands: in the upper's `run`, with the base's link
        // copied up beside it.
        let scratch = Scratch::for_test("extract-layered", "absolute");
        let base = scratch.join("base");
        fs::create_dir_all(base.join("run")).unwrap();
        fs::create_dir_all(base.join("var")).unwrap();
        symlink("/run", base.join("var/run")).unwrap();
        let upper = scratch.join("upper");
        fs::create_dir(&upper).unwrap();

        let mut tar = Tar::new();
        tar.dir("var/run/", 0o755)
            .file("var/run/daemon/pid", 0o644, b"1\n");
        let seen = extract_over(&upper, &base, &tar.finish()).expect("the increment extracts");

        assert_eq!(fs::read(upper.join("run/daemon/pid")).unwrap(), b"1\n");
        assert_eq!(
            fs::read_link(upper.join("var/run")).unwrap(),
            Path::new("/run"),
            "the base's link stays a link in the merged view",
        );
        assert_eq!(seen, ["var/run", "var/run/daemon/pid"]);
        assert!(!base.join("run/daemon").exists(), "the base is only read");
    }

    #[test]
    fn a_base_link_naming_a_host_path_is_never_followed_out() {
        // A link naming a path outside the tree, absolutely or by climbing,
        // names the root's own path of that name. Where the root holds nothing
        // there the link dangles, and an entry beneath it is refused as one
        // beneath any dangling link is; nothing is written outside.
        let scratch = Scratch::for_test("extract-layered", "host-path");
        let base = scratch.join("base");
        let outside = scratch.join("outside");
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, base.join("absolute")).unwrap();
        symlink("../outside", base.join("climbing")).unwrap();

        for name in ["absolute", "climbing"] {
            let upper = scratch.join(format!("upper-{name}"));
            fs::create_dir(&upper).unwrap();
            let mut tar = Tar::new();
            tar.file(&format!("{name}/payload"), 0o644, b"x");
            let err = extract_over(&upper, &base, &tar.finish())
                .expect_err("an entry beneath a dangling link is refused");
            assert!(
                matches!(err, crate::provision::ProvisionError::EntryRefused { .. }),
                "{name}: {err:?}",
            );
        }
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
    }

    #[test]
    fn an_entry_that_is_not_a_directory_cannot_replace_one_of_the_bases() {
        // The base is never written, so its directory cannot be removed to make
        // room; a file over it would hide the base's whole directory instead.
        let scratch = Scratch::for_test("extract-layered", "file-over-dir");
        let base = scratch.join("base");
        fs::create_dir_all(base.join("etc/conf.d")).unwrap();
        fs::write(base.join("etc/conf.d/net"), b"base").unwrap();
        let upper = scratch.join("upper");
        fs::create_dir(&upper).unwrap();

        let mut tar = Tar::new();
        tar.file("etc/conf.d", 0o644, b"a file");
        let err = extract_over(&upper, &base, &tar.finish())
            .expect_err("the base's directory is not superseded");
        assert!(
            matches!(err, crate::provision::ProvisionError::EntryRefused { .. }),
            "{err:?}",
        );
    }

    /// Whether this filesystem holds the `user.` attributes an overlay upper
    /// needs, so the opaque cases can run; a skip says so.
    fn holds_user_xattrs(dir: &Path) -> bool {
        let probe = dir.join("xattr-probe");
        fs::create_dir(&probe).unwrap();
        let opened = fs::File::open(&probe).unwrap();
        let held =
            rustix::fs::fsetxattr(&opened, "user.probe", b"1", rustix::fs::XattrFlags::empty())
                .is_ok();
        fs::remove_dir(&probe).unwrap();
        ferroday_cage_testkit::require::OVERLAY
            .holds(held, "this filesystem holds no user. attributes")
    }

    /// Makes an overlay whiteout at `path`, or answers `false` where the
    /// kernel refuses an unprivileged one.
    fn whiteout(path: &Path) -> bool {
        match rustix::fs::mknodat(
            rustix::fs::CWD,
            path,
            rustix::fs::FileType::CharacterDevice,
            rustix::fs::Mode::empty(),
            0,
        ) {
            Ok(()) => true,
            Err(rustix::io::Errno::PERM) => {
                ferroday_cage_testkit::require::OVERLAY
                    .skip("this kernel refuses an unprivileged whiteout");
                false
            }
            Err(errno) => panic!("making a whiteout: {errno}"),
        }
    }

    /// The opaque marker on `dir`, if any.
    fn opaque(dir: &Path) -> bool {
        let opened = fs::File::open(dir).unwrap();
        let mut value = [0u8; 2];
        matches!(
            rustix::fs::fgetxattr(&opened, "user.overlay.opaque", &mut value),
            Ok(1) if value[0] == b'y'
        )
    }

    #[test]
    fn the_overlays_own_markers_decide_what_the_base_shows() {
        let scratch = Scratch::for_test("extract-layered", "markers");
        if !holds_user_xattrs(&scratch) {
            return;
        }
        let base = scratch.join("base");
        let upper = scratch.join("upper");
        fs::create_dir_all(base.join("usr/share/doc/base-files")).unwrap();
        fs::create_dir_all(base.join("opt/vendor")).unwrap();
        symlink("vendor", base.join("opt/current")).unwrap();
        fs::create_dir_all(upper.join("usr/share")).unwrap();
        fs::create_dir_all(upper.join("opt")).unwrap();

        // A whiteout in the upper is a deletion the merged view shows: the
        // directory a later entry needs there starts empty, so it is marked
        // opaque rather than merged with the base's again.
        if !whiteout(&upper.join("usr/share/doc")) {
            return;
        }
        // An opaque directory hides the base beneath it, links included.
        rustix::fs::fsetxattr(
            fs::File::open(upper.join("opt")).unwrap(),
            "user.overlay.opaque",
            b"y",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        // A whiteout in the base is nothing at all.
        if !whiteout(&base.join("srv")) {
            return;
        }

        let mut tar = Tar::new();
        tar.file("usr/share/doc/fresh/README", 0o644, b"new")
            .file("opt/current/tool", 0o755, b"tool")
            .file("srv/www/index", 0o644, b"index");
        extract_over(&upper, &base, &tar.finish()).expect("the increment extracts");

        let doc = upper.join("usr/share/doc");
        assert!(fs::symlink_metadata(&doc).unwrap().is_dir());
        assert!(opaque(&doc), "the replaced whiteout starts empty");
        assert_eq!(fs::read(doc.join("fresh/README")).unwrap(), b"new");

        let current = upper.join("opt/current");
        assert!(
            fs::symlink_metadata(&current).unwrap().is_dir(),
            "the base's link beneath an opaque directory is not shown, so not copied",
        );
        assert!(!upper.join("opt/vendor").exists());

        assert!(fs::symlink_metadata(upper.join("srv")).unwrap().is_dir());
        assert_eq!(fs::read(upper.join("srv/www/index")).unwrap(), b"index");
    }

    #[test]
    fn the_merged_view_keeps_the_bases_links_and_shows_the_increment_through_them() {
        // The proof the kernel gives: the base and the upper mounted as the
        // overlay a build sandbox is rooted on.
        let Some(fixture) = ferroday_cage_testkit::fixture::fixture_rootfs(|tarball, root| {
            crate::provision::ensure(root, &mut crate::provision::Tarball::new(tarball))
        }) else {
            return;
        };
        let scratch = Scratch::for_test("extract-layered", "merged-view");
        if !ferroday_cage_testkit::require::overlay(&scratch) {
            return;
        }
        // The pinned minirootfs, made merged-usr where a stage3 is: `lib64`
        // into `usr/lib64`, and `sbin`'s contents moved into `usr/bin` with
        // `sbin` a link to it.
        let base = scratch.join("base");
        let copied = std::process::Command::new("cp")
            .arg("-a")
            .arg(fixture)
            .arg(&base)
            .status()
            .expect("cp runs");
        assert!(copied.success());
        fs::create_dir(base.join("usr/lib64")).unwrap();
        fs::write(base.join("usr/lib64/marker"), b"the base's own\n").unwrap();
        symlink("usr/lib64", base.join("lib64")).unwrap();
        for entry in fs::read_dir(base.join("sbin")).unwrap() {
            let entry = entry.unwrap();
            let moved = base.join("usr/bin").join(entry.file_name());
            if fs::symlink_metadata(&moved).is_err() {
                fs::rename(entry.path(), moved).unwrap();
            }
        }
        crate::provision::remove_tree(&base.join("sbin"), &crate::IdentityMap::Single, None)
            .expect("the copied sbin is removable");
        symlink("usr/bin", base.join("sbin")).unwrap();

        let upper = scratch.join("upper");
        fs::create_dir(&upper).unwrap();
        let mut tar = Tar::new();
        tar.dir("lib64/", 0o755)
            .file("lib64/libdevmapper.so.1.02", 0o644, b"library\n")
            .dir("sbin/", 0o755)
            .file("sbin/dmsetup", 0o755, b"#!/bin/sh\necho dmsetup\n");
        extract_over(&upper, &base, &tar.finish()).expect("the increment extracts");

        let output = crate::Cage::builder()
            .overlay_rootfs(&base, &upper)
            .command("/bin/sh")
            .args([
                "-c",
                "test -L /lib64 && test \"$(readlink /lib64)\" = usr/lib64 \
                 && test -L /sbin && test \"$(readlink /sbin)\" = usr/bin \
                 && cat /lib64/marker /usr/lib64/libdevmapper.so.1.02 \
                 && test -x /sbin/apk && /sbin/dmsetup",
            ])
            .build()
            .expect("the sandbox configuration is valid")
            .output()
            .expect("the sandbox runs");
        assert!(
            output.status.success(),
            "the merged view: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "the base's own\nlibrary\ndmsetup\n",
        );
    }
}
