//! Hardened extraction of a tar stream into a directory.
//!
//! Containment is enforced by the kernel, not by inspecting path text:
//! every parent directory is resolved with `openat2` and
//! `RESOLVE_BENEATH`, so an entry whose path or link chain escapes the
//! extraction root is refused by the kernel no matter how it is spelled.
//! In-tree relative symlinks resolve normally — a merged-usr archive
//! whose `bin` is a symlink to `usr/bin` extracts correctly — while
//! dotdot components, absolute paths, and symlinks leading outside the
//! root are rejected.
//!
//! `RESOLVE_BENEATH` refuses every absolute symlink, including one whose
//! target would land back inside the tree; `RESOLVE_IN_ROOT` would accept
//! it by re-anchoring the target at the extraction root. The stricter
//! flag is deliberate: the sandbox's mount setup resolves inside a rootfs
//! it is about to pivot into, where in-root re-anchoring is the correct
//! reading of an absolute link, but extraction writes to a plain host
//! directory that nothing ever re-roots, so an absolute link is treated
//! as pointing at the host and refused. The practical cost is that an
//! archive using the absolute form of a merged-usr link (`bin ->
//! /usr/bin`) and shipping entries through it does not extract; real
//! rootfs archives use the relative form and place entries under the
//! link's target.
//!
//! Extraction is unprivileged by design: entries become owned by the
//! calling user (whom the sandbox's identity map presents as root),
//! permission bits apply verbatim, and entry types that cannot be created
//! without privilege — character and block devices — are skipped, as the
//! sandbox assembles its own `/dev`. (A tar archive has no socket entry
//! type; GNU volume labels, archive metadata, are skipped too.)

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
use super::containment;
use super::tar::{Entry, TarReader};

/// The mode of a directory the extraction implies but no entry names.
///
/// An archive that carries `usr/lib/x` without an entry for `usr/lib` leaves
/// the mode of that directory unstated; the conventional `0755` is the only
/// answer available, and it is the one every other extractor gives.
const IMPLIED_DIR_MODE: u32 = 0o755;

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
}

impl Extraction {
    /// Opens `root` for extraction.
    pub(crate) fn new(root: &Path) -> Result<Extraction, ProvisionError> {
        let root_fd = rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| ProvisionError::io("opening", root, errno.into()))?;
        Ok(Extraction {
            root_fd,
            dir_meta: HashMap::new(),
            root_meta: None,
            root_mode_fixed: false,
        })
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
        let root = self.root_fd.as_fd();
        while let Some(entry) = archive.next_entry()? {
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

            let components = validate_path(&entry.path, &entry.path, "path")?;
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
                b'5' => extract_dir(root, &entry, &components, &mut self.dir_meta)?,
                b'2' => extract_symlink(root, &entry, &components, &mut self.dir_meta)?,
                b'1' => extract_hardlink(root, &entry, &components, &mut self.dir_meta)?,
                b'6' => extract_fifo(root, &entry, &components, &mut self.dir_meta)?,
                // Regular files, and unknown typeflags, which POSIX says to
                // treat as regular files.
                _ => extract_file(root, archive, &entry, &components, &mut self.dir_meta)?,
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

/// Splits and validates an entry path: relative, no `..`, no NUL.
///
/// [`path::tree_components`] is the split, with an absolute path refused rather
/// than read as naming the destination's own root: the destination is a plain
/// host directory that nothing re-roots, so a leading `/` names the host.
/// `.` components and empty segments are dropped, so `./` normalizes to an
/// empty list, which is the entry describing the extraction root.
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

/// Opens an entry's parent directory beneath `root`, creating missing
/// intermediate directories.
///
/// Resolution is kernel-scoped to `root` (`RESOLVE_BENEATH`); a parent
/// path that escapes — through `..` in a symlink, an absolute symlink
/// target, or any other route — is refused.
///
/// A directory created here is a parent the archive implied but never named,
/// and gets the conventional `0755`. `dir_meta` is the deferred-metadata map of
/// a caller that applies directory modes in a later pass, which records the
/// mode rather than applying it: an implied parent's contents are still to be
/// created, and it is created `0700` until they are. A caller with no such pass
/// passes `None` and has the mode applied at once, so an implied parent is
/// never left at the creation mode.
fn open_parent(
    root: BorrowedFd<'_>,
    components: &[Vec<u8>],
    entry_path: &[u8],
    mut dir_meta: Option<&mut HashMap<Vec<u8>, DirMeta>>,
) -> Result<OwnedFd, ProvisionError> {
    let parent = &components[..components.len() - 1];
    match open_dir_at(root, parent) {
        Ok(fd) => return Ok(fd),
        Err(Errno::NOENT) => {}
        Err(errno) => return Err(resolve_error(errno, entry_path)),
    }

    // Create the missing links of the chain, resolving each prefix from
    // the root so in-tree symlinks keep working mid-path.
    for depth in 1..=parent.len() {
        match open_dir_at(root, &parent[..depth]) {
            Ok(_) => continue,
            Err(Errno::NOENT) => {}
            Err(errno) => return Err(resolve_error(errno, entry_path)),
        }
        let above = open_dir_at(root, &parent[..depth - 1])
            .map_err(|errno| resolve_error(errno, entry_path))?;
        let leaf = component_cstr(&parent[depth - 1], entry_path)?;
        match rustix::fs::mkdirat(&above, &leaf, Mode::from_raw_mode(0o700)) {
            Ok(()) => match dir_meta.as_deref_mut() {
                Some(dir_meta) => {
                    dir_meta.entry(join(&parent[..depth])).or_insert(DirMeta {
                        mode: IMPLIED_DIR_MODE,
                        mtime: None,
                    });
                }
                None => {
                    rustix::fs::chmodat(
                        &above,
                        &leaf,
                        Mode::from_raw_mode(IMPLIED_DIR_MODE),
                        AtFlags::empty(),
                    )
                    .map_err(|errno| {
                        ProvisionError::io(
                            "setting the mode of a parent directory for",
                            bytes_to_path(entry_path),
                            errno.into(),
                        )
                    })?;
                }
            },
            // A concurrent creation cannot happen (the staging tree is
            // private); EEXIST here means a dangling symlink or another
            // non-directory in the way, which the re-resolve below turns
            // into a typed error.
            Err(Errno::EXIST) => {}
            Err(errno) => {
                return Err(ProvisionError::io(
                    "creating a parent directory for",
                    bytes_to_path(entry_path),
                    errno.into(),
                ));
            }
        }
        if open_dir_at(root, &parent[..depth]).is_err() {
            return Err(entry_refused(
                entry_path,
                "a parent component is not a directory",
            ));
        }
    }

    open_dir_at(root, parent).map_err(|errno| resolve_error(errno, entry_path))
}

/// Resolves `components` beneath `root` as a directory, without following
/// magic links and without leaving `root`.
///
/// `O_PATH`: the descriptor is only ever the anchor of a later `*at` call.
fn open_dir_at(root: BorrowedFd<'_>, components: &[Vec<u8>]) -> Result<OwnedFd, Errno> {
    let path = if components.is_empty() {
        CString::new(".").expect("no NUL")
    } else {
        CString::new(join(components)).map_err(|_| Errno::INVAL)?
    };
    containment::open_dir(root, &path, OFlags::PATH, ResolveFlags::BENEATH)
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
/// any. `root` anchors the `RESOLVE_BENEATH` follow that recognizes the alias.
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
/// `EXDEV` and `ELOOP` are the kernel refusing to leave the root — the second
/// covers a magic link as well as a loop, and the errno does not distinguish
/// them — so both are containment failures. `ENOTDIR` is not: an archive that
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
    root: BorrowedFd<'_>,
    archive: &mut TarReader<R>,
    entry: &Entry,
    components: &[Vec<u8>],
    dir_meta: &mut HashMap<Vec<u8>, DirMeta>,
) -> Result<(), ProvisionError> {
    let parent = open_parent(root, components, &entry.path, Some(dir_meta))?;
    let leaf = component_cstr(components.last().expect("non-empty"), &entry.path)?;

    let fd = create_replacing(
        &entry.path,
        || {
            rustix::fs::openat(
                &parent,
                &leaf,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
        },
        &parent,
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
    root: BorrowedFd<'_>,
    entry: &Entry,
    components: &[Vec<u8>],
    dir_meta: &mut HashMap<Vec<u8>, DirMeta>,
) -> Result<(), ProvisionError> {
    let parent = open_parent(root, components, &entry.path, Some(dir_meta))?;
    let leaf = component_cstr(components.last().expect("non-empty"), &entry.path)?;

    match rustix::fs::mkdirat(&parent, &leaf, Mode::from_raw_mode(0o700)) {
        Ok(()) => {}
        Err(Errno::EXIST) => {
            // A directory already in place (created implied, or a duplicate
            // entry) is kept; a merged-usr alias is left untouched, its
            // directory already present through the symlink; anything else is
            // replaced.
            match classify_existing_dir(root, &parent, &leaf, components, &entry.path)? {
                DirClash::Directory => {}
                // No metadata is recorded for an alias: the deferred pass opens
                // no-follow and would drop it, and the target owns its own.
                DirClash::AliasedDirectory => return Ok(()),
                DirClash::Replace => {
                    remove_at(&parent, &leaf, &entry.path)?;
                    rustix::fs::mkdirat(&parent, &leaf, Mode::from_raw_mode(0o700)).map_err(
                        |errno| {
                            ProvisionError::io("creating", bytes_to_path(&entry.path), errno.into())
                        },
                    )?;
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
    root: BorrowedFd<'_>,
    entry: &Entry,
    components: &[Vec<u8>],
    dir_meta: &mut HashMap<Vec<u8>, DirMeta>,
) -> Result<(), ProvisionError> {
    if entry.link_target.is_empty() {
        return Err(entry_refused(&entry.path, "the symlink target is empty"));
    }
    let target = CString::new(entry.link_target.clone())
        .map_err(|_| entry_unsafe(&entry.path, "the symlink target contains a NUL byte"))?;
    let parent = open_parent(root, components, &entry.path, Some(dir_meta))?;
    let leaf = component_cstr(components.last().expect("non-empty"), &entry.path)?;

    create_replacing(
        &entry.path,
        || rustix::fs::symlinkat(&target, &parent, &leaf),
        &parent,
        &leaf,
    )?;

    rustix::fs::utimensat(
        &parent,
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
fn extract_hardlink(
    root: BorrowedFd<'_>,
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
    let target_parent = open_dir_at(root, &target_components[..target_components.len() - 1])
        .map_err(|errno| resolve_error(errno, &entry.path))?;
    let target_leaf = component_cstr(target_components.last().expect("non-empty"), &entry.path)?;

    let parent = open_parent(root, components, &entry.path, Some(dir_meta))?;
    let leaf = component_cstr(components.last().expect("non-empty"), &entry.path)?;

    create_replacing(
        &entry.path,
        || {
            rustix::fs::linkat(
                &target_parent,
                &target_leaf,
                &parent,
                &leaf,
                AtFlags::empty(),
            )
        },
        &parent,
        &leaf,
    )?;
    Ok(())
}

/// Extracts a FIFO. `mknodat` honors the umask, so the mode is corrected
/// afterward.
fn extract_fifo(
    root: BorrowedFd<'_>,
    entry: &Entry,
    components: &[Vec<u8>],
    dir_meta: &mut HashMap<Vec<u8>, DirMeta>,
) -> Result<(), ProvisionError> {
    let parent = open_parent(root, components, &entry.path, Some(dir_meta))?;
    let leaf = component_cstr(components.last().expect("non-empty"), &entry.path)?;

    create_replacing(
        &entry.path,
        || {
            rustix::fs::mknodat(
                &parent,
                &leaf,
                FileType::Fifo,
                Mode::from_raw_mode(entry.mode),
                0,
            )
        },
        &parent,
        &leaf,
    )?;

    rustix::fs::chmodat(
        &parent,
        &leaf,
        Mode::from_raw_mode(entry.mode),
        AtFlags::empty(),
    )
    .map_err(|errno| {
        ProvisionError::io(
            "setting the mode of",
            bytes_to_path(&entry.path),
            errno.into(),
        )
    })?;
    rustix::fs::utimensat(
        &parent,
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
        let components: Vec<Vec<u8>> = path.split(|b| *b == b'/').map(<[u8]>::to_vec).collect();
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
/// symlink: `RESOLVE_BENEATH` would keep the follow in-tree, but following it
/// would apply this directory's archive mode and mtime to whatever the symlink
/// names, so the leaf must be the directory itself or the metadata is dropped.
/// This matches the `O_NOFOLLOW` discipline the extraction leaves use.
fn open_dir_meta_fd(root: BorrowedFd<'_>, components: &[Vec<u8>]) -> Result<OwnedFd, Errno> {
    let path = CString::new(join(components)).map_err(|_| Errno::INVAL)?;
    containment::open_dir(
        root,
        &path,
        OFlags::RDONLY | OFlags::NOFOLLOW,
        ResolveFlags::BENEATH,
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
/// Every parent is resolved beneath `root` with `openat2`/`RESOLVE_BENEATH`,
/// and every leaf is created `O_NOFOLLOW`, so nothing in `source` — nor a
/// symlink already in `root` — can cause a write outside `root`. The contents
/// of `source` are laid at the root: `source/etc/hosts` becomes
/// `<root>/etc/hosts`. A regular file or symlink replaces whatever occupies its
/// name, the way a later archive entry supersedes an earlier one, so the
/// overlay overrides a file a package already unpacked; directories merge.
/// File modes are preserved and symlink targets are stored verbatim; entries
/// are written by the calling user, whom the sandbox's identity map presents as
/// root inside.
///
/// This backs the Debian provisioner's pre-configure overlay, which lays a
/// caller's configuration into the rootfs after the packages are unpacked and
/// before their maintainer scripts run. Directory kinds it cannot create
/// unprivileged, and that have no place in a configuration overlay — device
/// nodes, FIFOs, sockets — are skipped, as archive extraction skips device
/// nodes.
#[cfg(any(feature = "debian", feature = "alpine"))]
pub(crate) fn overlay_tree(root: &Path, source: &Path) -> Result<(), ProvisionError> {
    let root_fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| ProvisionError::io("opening", root, errno.into()))?;
    overlay_dir(root_fd.as_fd(), source)
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

/// Copies the entries of `source_dir` into `root`.
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
fn overlay_dir(root: BorrowedFd<'_>, source_dir: &Path) -> Result<(), ProvisionError> {
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
            overlay_symlink(root, &source_path, &components)?;
        } else if kind.is_dir() {
            overlay_mkdir(root, &source_path, &components)?;
            // The marker goes on first, so it resurfaces only once every child
            // pushed above it has been visited.
            pending.push(OverlayStep::Leave);
            push_children(&source_path, &mut pending)?;
            continue;
        } else if kind.is_file() {
            overlay_file(root, &source_path, &components)?;
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
    root: BorrowedFd<'_>,
    source_path: &Path,
    components: &[Vec<u8>],
) -> Result<(), ProvisionError> {
    let path = join(components);
    let parent = open_parent(root, components, &path, None)?;
    let leaf = component_cstr(components.last().expect("non-empty"), &path)?;
    let mode = source_mode(source_path)?;

    // A newly created directory gets its mode set explicitly, since mkdirat
    // honors the umask; an existing directory is merged into and keeps its own
    // mode, since the overlay describes the files it carries, not the modes of
    // directories a package already created. A merged-usr alias (`/lib ->
    // usr/lib`) is treated as an existing directory too — merged through,
    // never replaced — so an overlay directory cannot orphan the linker any
    // more than a package entry can.
    let created = match rustix::fs::mkdirat(&parent, &leaf, Mode::from_raw_mode(0o700)) {
        Ok(()) => true,
        Err(Errno::EXIST) => {
            match classify_existing_dir(root, &parent, &leaf, components, &path)? {
                DirClash::Directory | DirClash::AliasedDirectory => false,
                DirClash::Replace => {
                    remove_at(&parent, &leaf, &path)?;
                    rustix::fs::mkdirat(&parent, &leaf, Mode::from_raw_mode(0o700)).map_err(
                        |errno| ProvisionError::io("creating", bytes_to_path(&path), errno.into()),
                    )?;
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
        rustix::fs::chmodat(&parent, &leaf, Mode::from_raw_mode(mode), AtFlags::empty()).map_err(
            |errno| ProvisionError::io("setting the mode of", bytes_to_path(&path), errno.into()),
        )?;
    }
    Ok(())
}

/// Copies the overlay file named by `components`, replacing whatever occupies
/// the name; the leaf is created `O_NOFOLLOW`, so a symlink in the way is
/// replaced rather than written through.
#[cfg(any(feature = "debian", feature = "alpine"))]
fn overlay_file(
    root: BorrowedFd<'_>,
    source_path: &Path,
    components: &[Vec<u8>],
) -> Result<(), ProvisionError> {
    let path = join(components);
    let parent = open_parent(root, components, &path, None)?;
    let leaf = component_cstr(components.last().expect("non-empty"), &path)?;
    let mode = source_mode(source_path)?;

    let fd = create_replacing(
        &path,
        || {
            rustix::fs::openat(
                &parent,
                &leaf,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
        },
        &parent,
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
    root: BorrowedFd<'_>,
    source_path: &Path,
    components: &[Vec<u8>],
) -> Result<(), ProvisionError> {
    let path = join(components);
    let target = fs::read_link(source_path)
        .map_err(|err| ProvisionError::io("reading the overlay symlink", source_path, err))?;
    let target = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| entry_unsafe(&path, "the symlink target contains a NUL byte"))?;
    let parent = open_parent(root, components, &path, None)?;
    let leaf = component_cstr(components.last().expect("non-empty"), &path)?;

    create_replacing(
        &path,
        || rustix::fs::symlinkat(&target, &parent, &leaf),
        &parent,
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

        overlay_tree(&root, &source).expect("the overlay applies");

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
        open_parent(fd.as_fd(), &components, b"usr/lib/file", None)
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

        overlay_tree(&root, &source).expect("the overlay applies");

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

        overlay_tree(&root, &source).expect("the overlay applies");

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

        overlay_tree(&root, &source).expect("the overlay applies");

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
