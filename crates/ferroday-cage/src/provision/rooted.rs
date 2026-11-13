//! Host-side file operations on a tree, contained to that tree.
//!
//! The host side of a run reads and writes inside a tree that untrusted code
//! has already run in: the Debian bootstrap seeds a statoverride, swaps
//! ownership stubs, and writes the finished rootfs's apt sources between dpkg
//! waves, and by then every selected package's maintainer scripts have run
//! inside a cage rooted at that tree, as root of its namespace; a launch's
//! teardown removes the mount-point placeholders it created in the rootfs the
//! command has just finished running against. Such a command, or such a script,
//! is entitled to leave a symbolic link at any of those paths.
//!
//! Composing a host path with [`Path::join`] and handing it to [`std::fs`]
//! resolves that link against the *host's* root, so a link left at
//! `etc/apt/sources.list` redirects the write that follows out of the tree
//! entirely, performed as the calling user. It is the hazard the launch side
//! already answers for the placeholders it removes, and the extractor for every
//! entry it writes.
//!
//! [`Rooted`] answers it here. It holds a descriptor for the tree and resolves
//! every path against it with `openat2` and `RESOLVE_IN_ROOT`, the discipline
//! the sandbox's mount setup gives every mount target: an absolute symbolic
//! link inside the tree resolves *within* the tree — which is what it means to
//! the rootfs the tree is about to be, and what the same link means to dpkg
//! running inside the cage — and nothing resolves outside it. Leaves are opened
//! `O_NOFOLLOW`, so a link occupying a name is replaced rather than written
//! through, which is what the extractor's leaves do.
//!
//! A script can as easily leave a named pipe where the host side expects a
//! file, and opening one for reading waits for a writer that never comes. A
//! read therefore looks at what holds the name before opening it, opens only a
//! regular file, and opens that without waiting, so a tree can fail a read but
//! cannot stall one. Nor can it make one exhaust the host: a file costs a
//! script nothing to make enormous, since `truncate -s 1T` writes no data and
//! takes no space, so every read states the most it will hold and refuses a
//! file past it.
//!
//! Paths are tree-relative and may be written with a leading `/`, since the
//! tree is a root filesystem and its own files name themselves that way. A `..`
//! component is refused outright rather than resolved: the kernel would contain
//! it, but no path this is asked for has one, and a path that does is a
//! composition bug rather than a traversal to honour. The tree's host path is
//! held only to name it in an error; nothing resolves through it.
//!
//! A path is anything [`Path`]-shaped rather than a `&str`, because a mount
//! target comes from a caller's profile and a filesystem path is bytes: a
//! target that is not UTF-8 is unusual but not invalid, and it must not be the
//! one path that skips the containment.

// Every provisioner's host-side steps go through this module, and the Debian
// bootstrap's use nearly all of it. A build without that feature reaches only
// the part Alpine's or Gentoo's steps use, and a build with no provisioner only
// `remove_if`, for the launch teardown's mount-point placeholders. The rest is
// dead code there, and saying so once is clearer than gating each method on
// the combination of features that reaches it. The few that Debian does not
// reach carry their own allowance.
#![cfg_attr(not(feature = "debian"), allow(dead_code))]

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat};
use rustix::io::Errno;

use crate::path::{self, LeadingSlash};

use super::containment;
use super::copyin::{Owed, reown};
use super::identity::Ownership;

/// The mode an intermediate directory is left at.
///
/// Applied through the descriptor of the directory just made rather than left
/// to `mkdirat`, which narrows it by the umask: a rootfs whose directory modes
/// followed the caller's umask would differ between two runs of the same build.
const DIR_MODE: u32 = 0o755;

/// The mode a file is left at where the caller states none — the mode
/// `fs::write` produces under the conventional umask, applied explicitly for
/// the same reason as [`DIR_MODE`].
const FILE_MODE: u32 = 0o644;

/// A directory tree that host-side steps read and write through, with every
/// path resolved by the kernel against the tree's own root.
pub(crate) struct Rooted {
    /// The tree's root. `O_PATH`: it is only ever the anchor of an `openat2`,
    /// so it needs no read access to the directory itself.
    fd: OwnedFd,
    /// The base the tree is an overlay upper over, where it is one: read, and
    /// never written. See [`over`](Self::over).
    #[cfg(feature = "tarball")]
    lower: Option<OwnedFd>,
    /// The identity map the tree is owned through, which a directory carried
    /// up from the base is given its ownership through. See
    /// [`owned_through`](Self::owned_through).
    ownership: Ownership,
    /// The tree's host path, for error reporting, and for the child that
    /// re-owns a carried directory, which opens the tree afresh by it. Nothing
    /// in this process resolves through it.
    root: PathBuf,
}

impl Rooted {
    /// Opens `root` as a contained tree.
    pub(crate) fn open(root: &Path) -> io::Result<Rooted> {
        let fd = rustix::fs::open(
            root,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Rooted {
            fd,
            #[cfg(feature = "tarball")]
            lower: None,
            ownership: Ownership::default(),
            root: root.to_path_buf(),
        })
    }

    /// Treats the tree as an overlay upper over `lower`, where one is given.
    ///
    /// A layered build's host-side steps write into the upper, and a directory
    /// one creates there where the base holds a link to a directory hides the
    /// link in the merged view, exactly as an extraction's would. Over a base,
    /// the parents a write creates are first walked through the merged view,
    /// with the upper made to hold what the view holds along them
    /// ([`containment::copy_up`]). `lib/apk/db/installed`, over a base whose
    /// `lib` is `usr/lib`, then lands in the upper's `usr/lib` beside a copy
    /// of the link. A directory carried up from the base keeps what an
    /// extraction's carry keeps: the base's extended attributes, its mode, and
    /// its owner and group. The ownership is given from inside the map
    /// [`owned_through`](Self::owned_through) names, once the write that carried
    /// the directory has landed beneath it.
    ///
    /// Only creation consults the base. Every read, and every write to a path
    /// whose parents are already there, is the upper's own, as it always was.
    #[cfg(feature = "tarball")]
    pub(crate) fn over(mut self, lower: Option<&Rooted>) -> io::Result<Rooted> {
        if let Some(lower) = lower {
            self.lower = Some(rustix::io::fcntl_dupfd_cloexec(&lower.fd, 0)?);
        }
        Ok(self)
    }

    /// Names the identity map the tree is owned through, which a directory a
    /// write carries up from the base is given its ownership through.
    ///
    /// Unset, the single-identity map, which is what a layer that runs nothing
    /// in a sandbox writes under. Only a tree [`over`](Self::over) a base
    /// carries anything up, so it is only there that this matters.
    #[cfg(any(feature = "debian", feature = "alpine"))]
    pub(crate) fn owned_through(mut self, ownership: Ownership) -> Rooted {
        self.ownership = ownership;
        self
    }

    /// The host path `relative` names, for an error message. Nothing resolves
    /// through it.
    ///
    /// Composed from the components the module's own split produces rather than
    /// by joining the path as written. [`Path::join`] discards the root it is
    /// joined to whenever the argument is absolute, so trimming a single leading
    /// slash would leave `//etc/x` absolute and report the *host's* `/etc/x` as
    /// the path inside the tree — the one place in the module where a path would
    /// be composed by `std`'s rules instead of by the rules everything else here
    /// resolves under.
    pub(crate) fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        let relative = relative.as_ref();
        let bytes = relative.as_os_str().as_bytes();
        let Ok(components) = path::tree_components(bytes, LeadingSlash::TreeRoot) else {
            // A path the split refuses names nothing inside the tree, and this
            // is only ever an error message: the tree's own root is the nearest
            // true thing to say.
            return self.root.clone();
        };
        let mut host = self.root.clone();
        for component in components {
            host.push(std::ffi::OsStr::from_bytes(component));
        }
        host
    }

    /// Writes `contents` to `relative` at the default mode, creating missing
    /// parent directories.
    pub(crate) fn write(&self, relative: impl AsRef<Path>, contents: &[u8]) -> io::Result<()> {
        self.create(relative.as_ref(), contents, FILE_MODE)
    }

    /// Writes `contents` to `relative` at `mode`, creating missing parent
    /// directories.
    pub(crate) fn write_mode(
        &self,
        relative: impl AsRef<Path>,
        contents: &[u8],
        mode: u32,
    ) -> io::Result<()> {
        self.create(relative.as_ref(), contents, mode)
    }

    /// Creates the directory `relative` and every missing directory above it,
    /// each at the default directory mode. A directory already there, or an
    /// in-tree link to one, is left as it is.
    ///
    /// Every link of the chain resolves inside the tree, the leaf included, so
    /// a symbolic link a package shipped in place of one of them names a
    /// directory of the tree rather than of the host.
    pub(crate) fn create_dir_all(&self, relative: impl AsRef<Path>) -> io::Result<()> {
        let mut made = Chain::default();
        self.create_dirs(&components(relative.as_ref())?, &mut made)?;
        self.settle(made)
    }

    /// Reads the file at `relative`, refusing one that holds more than `limit`
    /// bytes.
    ///
    /// The ceiling is the caller's, since only the caller knows what it is
    /// reading: a counter is a few digits, and a package database is megabytes.
    /// A file past it fails the read with an error naming the path and the
    /// ceiling, whatever its size claims, since the bound is on what is read
    /// rather than on what a `stat` said a moment earlier.
    ///
    /// `O_NOFOLLOW`: a symbolic link at the leaf fails the read rather than
    /// being followed, so a link planted where a file is expected cannot turn
    /// this into a read of something else. Anything else that is not a regular
    /// file is refused as [`reader`](Self::reader) refuses it.
    pub(crate) fn read(&self, relative: impl AsRef<Path>, limit: u64) -> io::Result<Vec<u8>> {
        let relative = relative.as_ref();
        let mut contents = Vec::new();
        self.reader(relative)?
            .take(limit.saturating_add(1))
            .read_to_end(&mut contents)?;
        if contents.len() as u64 > limit {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                format!(
                    "{} holds more than the {limit} bytes accepted for it",
                    self.path(relative).display(),
                ),
            ));
        }
        Ok(contents)
    }

    /// Reads the file at `relative` as [`read`](Self::read) does, answering
    /// `None` where there is none.
    ///
    /// None is the name being free — an absent leaf, a parent that is absent or
    /// is not a directory, or an overlay whiteout, which is how a layered
    /// build's upper says the file is gone. Anything else that is not a regular
    /// file is still refused: a directory or a named pipe at the path is not a
    /// file that is missing.
    pub(crate) fn read_if_present(
        &self,
        relative: impl AsRef<Path>,
        limit: u64,
    ) -> io::Result<Option<Vec<u8>>> {
        match self.read(relative, limit) {
            Ok(contents) => Ok(Some(contents)),
            Err(err)
                if err.kind() == io::ErrorKind::NotFound
                    || err.raw_os_error() == Some(Errno::NOTDIR.raw_os_error()) =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Opens the file at `relative` for reading, contained as every path here
    /// is.
    ///
    /// What [`read`](Self::read) is built on, and what a caller that must not
    /// hold the whole file uses instead: a merged package's own database entry
    /// records a digest per installed file, and a hundred-megabyte binary is
    /// one of them.
    ///
    /// Only a regular file is opened. Anything else is refused without being
    /// opened at all, a named pipe included; see
    /// [`regular_stat`](Self::regular_stat).
    pub(crate) fn reader(&self, relative: impl AsRef<Path>) -> io::Result<File> {
        let relative = relative.as_ref();
        let (parent, leaf) = self.parent_of(relative, Parents::Require)?;
        let typed = self.regular_stat(&parent, &leaf, relative)?;
        self.open_regular(&parent, &leaf, relative, &typed, OFlags::RDONLY)
    }

    /// Replaces the contents of the regular file at `relative` in place.
    ///
    /// Where [`write`](Self::write) replaces the file, this keeps it: the inode,
    /// and with it the owner, the group, and the mode, are the ones the file
    /// already had. That is the difference for a file whose ownership a script
    /// set, which a replacement written by the calling user would lose. The
    /// file must exist, and anything that is not a regular file is refused as
    /// [`reader`](Self::reader) refuses it, before anything is truncated.
    #[cfg_attr(not(feature = "alpine"), allow(dead_code))]
    pub(crate) fn overwrite(&self, relative: impl AsRef<Path>, contents: &[u8]) -> io::Result<()> {
        let relative = relative.as_ref();
        let (parent, leaf) = self.parent_of(relative, Parents::Require)?;
        let typed = self.regular_stat(&parent, &leaf, relative)?;
        let mut file = self.open_in_place(&parent, &leaf, relative, &typed)?;
        file.set_len(0)?;
        file.write_all(contents)
    }

    /// Empties the regular file at `relative` in place if it exists and
    /// `accept` approves what is there, leaving it alone otherwise.
    ///
    /// The stat-gated counterpart of [`remove_if`](Self::remove_if), for a
    /// file a root keeps but should not keep the contents of. The predicate
    /// sees the leaf's own `stat`, taken without following it, and nothing is
    /// opened until it has approved; anything that is not a regular file is
    /// left alone whatever it says, so a link, a named pipe, or a layered
    /// build's whiteout is never emptied through.
    ///
    /// In place, as [`overwrite`](Self::overwrite) rewrites: the inode, owner,
    /// group, and mode stay the ones a script gave the file. An absent leaf,
    /// or an absent parent, is already done.
    ///
    /// What is emptied is the file the predicate approved. The open is held to
    /// that `stat`, so a file renamed onto the name after the look, regular or
    /// not, fails the call rather than being emptied unseen.
    pub(crate) fn truncate_if(
        &self,
        relative: impl AsRef<Path>,
        accept: impl FnOnce(&Stat) -> bool,
    ) -> io::Result<()> {
        let relative = relative.as_ref();
        let (parent, leaf) = match self.parent_of(relative, Parents::Require) {
            Ok(found) => found,
            Err(Errno::NOENT | Errno::NOTDIR) => return Ok(()),
            Err(errno) => return Err(errno.into()),
        };
        let approved = match rustix::fs::statat(&parent, &leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat)
                if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                    && accept(&stat) =>
            {
                stat
            }
            Ok(_) | Err(Errno::NOENT | Errno::NOTDIR) => return Ok(()),
            Err(errno) => return Err(errno.into()),
        };
        self.open_in_place(&parent, &leaf, relative, &approved)?
            .set_len(0)
    }

    /// Opens the regular file `leaf` of `parent`, which `typed` describes, for
    /// rewriting in place.
    ///
    /// A file whose mode denies its owner writing is still the owner's to
    /// rewrite, since the owner may change its mode: `systemd` writes the
    /// machine id `0444`. Such a file is held open for reading, given its
    /// owner's write bit through that descriptor for as long as the open for
    /// writing takes, and given its own mode back before anything is written,
    /// since a descriptor keeps the access it was opened with. Every open is
    /// held to `typed`, so all of them reach the file the caller looked at, or
    /// nothing is written: the name is not trusted to hold still between them.
    fn open_in_place(
        &self,
        parent: &OwnedFd,
        leaf: &CString,
        relative: &Path,
        typed: &Stat,
    ) -> io::Result<File> {
        match self.open_regular(parent, leaf, relative, typed, OFlags::WRONLY) {
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {}
            opened => return opened,
        }
        let held = self.open_regular(parent, leaf, relative, typed, OFlags::RDONLY)?;
        let mode = Mode::from_raw_mode(rustix::fs::fstat(&held)?.st_mode & 0o7777);
        rustix::fs::fchmod(&held, mode | Mode::WUSR)?;
        let opened = self.open_regular(parent, leaf, relative, typed, OFlags::WRONLY);
        rustix::fs::fchmod(&held, mode)?;
        opened
    }

    /// What holds `leaf` of `parent`, without following it, where it is a
    /// regular file, refusing anything else without opening it.
    ///
    /// Looking first is what keeps anything but a regular file from ever being
    /// opened: a named pipe, which an ordinary open would wait on until
    /// something opened its other end, and a device node, whose open can act on
    /// the device, are refused before either happens. An overlay whiteout is a
    /// file that is gone, and reads as absent. `relative` names the file in a
    /// refusal.
    fn regular_stat(&self, parent: &OwnedFd, leaf: &CString, relative: &Path) -> io::Result<Stat> {
        let stat = rustix::fs::statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)?;
        if containment::is_whiteout(&stat) {
            return Err(Errno::NOENT.into());
        }
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", self.path(relative).display()),
            ));
        }
        Ok(stat)
    }

    /// Opens the regular file `leaf` of `parent` that `typed` describes, for
    /// `access`.
    ///
    /// `typed` is the [`regular_stat`](Self::regular_stat) the caller took, or
    /// the one it approved. The open itself is
    /// [`containment::open_typed_file`]'s: `O_NONBLOCK` and `O_NOCTTY` all the
    /// same, and refusing a name that no longer holds that file, since the name
    /// can be replaced between the look and the open. A regular file ignores
    /// `O_NONBLOCK`, and the flag is cleared before the descriptor is handed
    /// back all the same.
    fn open_regular(
        &self,
        parent: &OwnedFd,
        leaf: &CString,
        relative: &Path,
        typed: &Stat,
        access: OFlags,
    ) -> io::Result<File> {
        let fd =
            containment::open_typed_file(parent.as_fd(), leaf, typed, access).map_err(|errno| {
                match errno {
                    Errno::STALE => io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "{} was replaced while it was being opened",
                            self.path(relative).display(),
                        ),
                    ),
                    errno => errno.into(),
                }
            })?;
        rustix::fs::fcntl_setfl(&fd, rustix::fs::fcntl_getfl(&fd)? - OFlags::NONBLOCK)?;
        Ok(File::from(fd))
    }

    /// The names of the subdirectories of `relative`, sorted.
    ///
    /// The tree is one untrusted code has run in, so this resolves as every
    /// other operation here does and reads through the descriptor the kernel
    /// returned rather than re-walking a host path. `.` and `..` are not
    /// entries, and neither is anything that is not a directory: the callers
    /// that ask this are walking a directory *of* directories — a package
    /// database's categories, and the entries under each — and a stray file
    /// beside them is not one of the things being enumerated.
    ///
    /// Sorted, so a walk over a tree is the same walk twice. Readdir order is
    /// the filesystem's and differs between two roots holding the same entries,
    /// which would make an install order, and anything derived from one,
    /// unreproducible.
    ///
    /// An absent directory is an empty listing rather than a failure: the
    /// question these callers ask is what is there, and nothing is a legitimate
    /// answer to it.
    ///
    /// Enumerating a tree is the Gentoo layer's alone — its package database is
    /// a directory of directories, where Debian's and Alpine's are files whose
    /// names the layer already knows — so a build without that feature has no
    /// caller. The module's own blanket allowance does not cover it, since it
    /// is dead under `debian` as well.
    #[cfg_attr(not(feature = "gentoo"), allow(dead_code))]
    pub(crate) fn directories(&self, relative: impl AsRef<Path>) -> io::Result<Vec<Vec<u8>>> {
        let components = components(relative.as_ref())?;
        let dir = match self.open_read_dir(&components) {
            Ok(dir) => dir,
            Err(Errno::NOENT | Errno::NOTDIR) => return Ok(Vec::new()),
            Err(errno) => return Err(errno.into()),
        };
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::read_from(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            // `DT_UNKNOWN` is what a filesystem answers when it does not carry
            // the type in the directory entry, so the kind is confirmed with a
            // `stat` against the same descriptor rather than assumed either way.
            let is_dir = match entry.file_type() {
                FileType::Directory => true,
                FileType::Unknown => {
                    rustix::fs::statat(&dir, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
                        .is_ok_and(|stat| {
                            FileType::from_raw_mode(stat.st_mode) == FileType::Directory
                        })
                }
                _ => false,
            };
            if is_dir {
                names.push(name.to_vec());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Whether anything occupies `relative` — a file, a directory, or a
    /// symbolic link, dangling or not. The question is whether the name is
    /// taken, so nothing is followed.
    pub(crate) fn exists(&self, relative: impl AsRef<Path>) -> io::Result<bool> {
        Ok(self.stat(relative)?.is_some())
    }

    /// What occupies `relative`: the leaf's own `stat`, taken without following
    /// a symbolic link, or `None` where nothing does.
    ///
    /// For a caller that must tell the kinds of entry apart before acting on
    /// one, as [`is_whiteout`](Self::is_whiteout) tells an entry the merged
    /// root does not hold from one it does.
    pub(crate) fn stat(&self, relative: impl AsRef<Path>) -> io::Result<Option<Stat>> {
        let (parent, leaf) = match self.parent_of(relative.as_ref(), Parents::Require) {
            Ok(found) => found,
            Err(Errno::NOENT | Errno::NOTDIR) => return Ok(None),
            Err(errno) => return Err(errno.into()),
        };
        match rustix::fs::statat(&parent, &leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(stat)),
            Err(Errno::NOENT | Errno::NOTDIR) => Ok(None),
            Err(errno) => Err(errno.into()),
        }
    }

    /// Whether the directory at `relative` carries the overlay's opaque marker,
    /// so a tree that is an overlay's upper shows nothing of the layers beneath
    /// it there.
    ///
    /// [`containment::is_opaque`] is the answer; this resolves the directory as
    /// every path here is resolved and asks it through a descriptor opened for
    /// reading, since an `O_PATH` one cannot be asked for an attribute. A
    /// directory is the one kind opened, so nothing here can wait on a named
    /// pipe.
    pub(crate) fn is_opaque(&self, relative: impl AsRef<Path>) -> io::Result<bool> {
        let components = components(relative.as_ref())?;
        let dir = self.open_read_dir(&components)?;
        Ok(containment::is_opaque(dir.as_fd())?)
    }

    /// Creates an overlay whiteout at `relative`: a character device numbered
    /// 0:0, which hides the name from every layer below the one holding it.
    ///
    /// The kernel lets an unprivileged process create this one device. A name
    /// already taken is refused rather than replaced.
    pub(crate) fn whiteout(&self, relative: impl AsRef<Path>) -> io::Result<()> {
        let (parent, leaf) = self.parent_of(relative.as_ref(), Parents::Require)?;
        rustix::fs::mknodat(&parent, &leaf, FileType::CharacterDevice, Mode::empty(), 0)?;
        Ok(())
    }

    /// Removes `relative` if it exists, treating an already-absent path — and
    /// an absent parent — as success. `unlinkat` never follows the leaf, so a
    /// symbolic link is removed rather than its target.
    pub(crate) fn remove(&self, relative: impl AsRef<Path>) -> io::Result<()> {
        self.remove_if(relative, |_| true)
    }

    /// Removes `relative` if it exists and `accept` approves what is there,
    /// leaving it alone otherwise.
    ///
    /// The predicate sees the leaf's own `stat`, taken with `AT_SYMLINK_NOFOLLOW`
    /// against the same directory descriptor the unlink uses, so neither call
    /// follows a link, out of the tree or anywhere else. They are two calls on
    /// one name, though, not one on one entry: something that renames another
    /// entry onto the name between them has that entry removed in its place.
    /// The predicate tells what the tree is expected to hold from what it is
    /// not; it does not hold the name still against a process racing it.
    ///
    /// This is what a launch's teardown removes its mount-point placeholders
    /// through: a placeholder is an empty regular file for its whole life, so
    /// anything with content, or anything that is no longer a plain file,
    /// arrived from elsewhere and belongs to whoever put it there.
    pub(crate) fn remove_if(
        &self,
        relative: impl AsRef<Path>,
        accept: impl FnOnce(&Stat) -> bool,
    ) -> io::Result<()> {
        let (parent, leaf) = match self.parent_of(relative.as_ref(), Parents::Require) {
            Ok(found) => found,
            Err(Errno::NOENT | Errno::NOTDIR) => return Ok(()),
            Err(errno) => return Err(errno.into()),
        };
        match rustix::fs::statat(&parent, &leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if !accept(&stat) => return Ok(()),
            Ok(_) => {}
            Err(Errno::NOENT | Errno::NOTDIR) => return Ok(()),
            Err(errno) => return Err(errno.into()),
        }
        match rustix::fs::unlinkat(&parent, &leaf, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(errno) => Err(errno.into()),
        }
    }

    /// Whether `stat` describes an empty regular file — the shape a launch's
    /// mount-point placeholder has, and keeps, for its whole life.
    pub(crate) fn is_empty_file(stat: &Stat) -> bool {
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile && stat.st_size == 0
    }

    /// Whether `stat` describes a regular file with something in it — the
    /// shape an identifier a script generated has, as against an empty file, a
    /// symbolic link, or an overlay whiteout.
    pub(crate) fn is_file_with_content(stat: &Stat) -> bool {
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile && stat.st_size > 0
    }

    /// Whether `stat` describes an overlay whiteout: a character device
    /// numbered 0:0, which is how an overlay upper records that the merged root
    /// no longer holds what a lower layer has at that name.
    ///
    /// A whiteout in a tree that is an overlay's upper is an absent entry to
    /// every reader of the merged root. Opening one for reading fails with
    /// `ENXIO`, since no driver backs the device. The predicate form of
    /// [`containment::is_whiteout`], which is the definition, for the callers
    /// that hold a `Stat` from [`stat`](Self::stat) or [`remove_if`](Self::remove_if).
    pub(crate) fn is_whiteout(stat: &Stat) -> bool {
        containment::is_whiteout(stat)
    }

    /// Renames `from` to `to` within the tree, replacing whatever occupies the
    /// destination. Both paths resolve against the tree's root.
    pub(crate) fn rename(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
        let mut made = Chain::default();
        let (from_parent, from_leaf) = self.parent_of(from.as_ref(), Parents::Require)?;
        let (to_parent, to_leaf) = self.parent_of(to.as_ref(), Parents::Create(&mut made))?;
        rustix::fs::renameat(&from_parent, &from_leaf, &to_parent, &to_leaf)?;
        self.settle(made)
    }

    /// Creates a symbolic link at `relative` holding `target` verbatim,
    /// replacing whatever occupies the name.
    ///
    /// `target` is stored as written and never resolved here; it is read by
    /// whatever later follows the link, inside the tree.
    pub(crate) fn symlink(&self, target: &str, relative: impl AsRef<Path>) -> io::Result<()> {
        let target = CString::new(target).map_err(|_| Errno::INVAL)?;
        let mut made = Chain::default();
        let (parent, leaf) = self.parent_of(relative.as_ref(), Parents::Create(&mut made))?;
        containment::replacing(&parent, &leaf, || {
            rustix::fs::symlinkat(&target, &parent, &leaf)
        })?;
        self.settle(made)
    }

    /// Creates the file at `relative` holding `contents`, at `mode`.
    ///
    /// The leaf is created `O_EXCL | O_NOFOLLOW` and, on a name already taken,
    /// unlinked and created again: a symbolic link occupying it is replaced by
    /// the file rather than written through, which is the extractor's rule for
    /// its own leaves. The mode is applied through the descriptor, so it lands
    /// on the file this created and on nothing else.
    fn create(&self, relative: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
        let mut made = Chain::default();
        let (parent, leaf) = self.parent_of(relative, Parents::Create(&mut made))?;
        let fd = containment::replacing(&parent, &leaf, || {
            rustix::fs::openat(
                &parent,
                &leaf,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
        })?;
        let mut file = File::from(fd);
        file.write_all(contents)?;
        rustix::fs::fchmod(&file, Mode::from_raw_mode(mode))?;
        self.settle(made)
    }

    /// Gives each directory a write created its mode, deepest first, and then
    /// each one it carried up from the base the ownership the base holds it at,
    /// through the map the tree is owned through.
    ///
    /// Called once the write has landed, as an extraction applies both once
    /// every entry has: a mode denying the owner write or search, `0555` from a
    /// base's directory, would refuse the calling user the write beneath it,
    /// and so would a directory given to another id. The modes go first, while
    /// the calling user still owns every directory and may set one.
    fn settle(&self, made: Chain) -> io::Result<()> {
        for (dir, mode) in made.modes.iter().rev() {
            rustix::fs::fchmod(dir, Mode::from_raw_mode(*mode))?;
        }
        reown(&self.root, &made.owed, &self.ownership).map_err(io::Error::other)
    }

    /// Opens the parent directory of `relative` and returns it with the leaf
    /// name, creating the missing links of the chain where asked to.
    fn parent_of(
        &self,
        relative: &Path,
        parents: Parents<'_>,
    ) -> Result<(OwnedFd, CString), Errno> {
        let components = components(relative)?;
        let (leaf, parent) = components.split_last().expect("validated non-empty");
        let leaf = CString::new(*leaf).map_err(|_| Errno::INVAL)?;
        let parent = match parents {
            Parents::Require => self.open_dir(parent)?,
            Parents::Create(chain) => self.create_dirs(parent, chain)?,
        };
        Ok((parent, leaf))
    }

    /// Resolves `components` inside the tree as a directory.
    ///
    /// `RESOLVE_IN_ROOT`, so an absolute symbolic link in the chain resolves
    /// within the tree, which is what such a link means to the root filesystem
    /// the tree is. `O_PATH`: the descriptor is only ever the anchor of an
    /// `*at` call.
    fn open_dir(&self, components: &[&[u8]]) -> Result<OwnedFd, Errno> {
        containment::open_dir(
            self.fd.as_fd(),
            components,
            OFlags::PATH,
            ResolveFlags::IN_ROOT,
        )
    }

    /// Resolves `components` inside the tree as a directory that will be read.
    ///
    /// `O_RDONLY` where [`open_dir`](Self::open_dir) takes `O_PATH`: an
    /// `O_PATH` descriptor anchors an `*at` call and cannot be handed to
    /// `getdents` or asked for an extended attribute.
    fn open_read_dir(&self, components: &[&[u8]]) -> Result<OwnedFd, Errno> {
        containment::open_dir(
            self.fd.as_fd(),
            components,
            OFlags::RDONLY,
            ResolveFlags::IN_ROOT,
        )
    }

    /// Opens `components` as a directory, creating the missing links of the
    /// chain at [`DIR_MODE`], or at the base's own mode for a directory carried
    /// up from it.
    ///
    /// [`containment::create_dirs`] is the walk, preceded over a base by
    /// [`containment::copy_up`]; what is here is the mode this side leaves a
    /// directory at. It is recorded in `chain` with a descriptor of the
    /// directory just made, as is the ownership a directory carried up from the
    /// base is owed, for the caller to [`settle`](Self::settle) once its write
    /// is in.
    fn create_dirs(&self, components: &[&[u8]], chain: &mut Chain) -> Result<OwnedFd, Errno> {
        let mut made = |made: containment::Made<'_>| {
            #[cfg(feature = "tarball")]
            if let Some(record) = containment::owed(&made)? {
                chain.owed.push(record);
            }
            let mode = made.copied.map_or(DIR_MODE, |below| below.st_mode & 0o7777);
            chain
                .modes
                .push((rustix::io::fcntl_dupfd_cloexec(made.dir, 0)?, mode));
            Ok(())
        };
        #[cfg(feature = "tarball")]
        if let Some(lower) = &self.lower {
            containment::copy_up(
                self.fd.as_fd(),
                lower.as_fd(),
                components,
                ResolveFlags::IN_ROOT,
                &mut made,
            )?;
        }
        containment::create_dirs(
            self.fd.as_fd(),
            components,
            ResolveFlags::IN_ROOT,
            &mut made,
        )
    }
}

/// Whether a missing parent directory is created or is a failure.
enum Parents<'o> {
    /// Create the missing links of the chain, recording in the [`Chain`] what
    /// each directory it made is owed.
    Create(&'o mut Chain),
    /// Fail with the kernel's own `ENOENT`.
    Require,
}

/// What the directories a write created are owed once the write has landed:
/// their modes and, for one carried up from a base, its ownership. See
/// [`Rooted::settle`].
#[derive(Default)]
struct Chain {
    /// Each directory made, in the order it was made, held open read-only
    /// without following a link, with the mode it keeps.
    modes: Vec<(OwnedFd, u32)>,
    /// The ownership the directories carried up from a base are owed.
    owed: Vec<Owed>,
}

/// Splits a tree-relative path into its components.
///
/// [`path::tree_components`] is the split, with a leading `/` naming the tree's
/// own root: the tree is a root filesystem, and its files name themselves that
/// way. Every refusal it reports becomes `EINVAL`, since this side has an errno
/// to answer with and nothing finer; the caller's path is in the error the
/// operation returns.
///
/// A path naming nothing at all — `/`, `.`, the empty path — is refused on top
/// of what the split refuses. Every operation here acts on a leaf inside the
/// tree, and the tree itself is not one.
fn components(relative: &Path) -> Result<Vec<&[u8]>, Errno> {
    let components = path::tree_components(relative.as_os_str().as_bytes(), LeadingSlash::TreeRoot)
        .map_err(|_| Errno::INVAL)?;
    if components.is_empty() {
        return Err(Errno::INVAL);
    }
    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;
    use std::os::unix::fs::PermissionsExt;

    fn tree(tag: &str) -> (Scratch, Rooted) {
        let scratch = Scratch::new(&format!("rooted-{tag}"));
        let root = scratch.join("tree");
        std::fs::create_dir(&root).unwrap();
        let rooted = Rooted::open(&root).unwrap();
        (scratch, rooted)
    }

    #[test]
    fn a_named_pipe_is_refused_rather_than_waited_on() {
        // Opening a FIFO for reading waits for a writer, and a script can leave
        // one where the host side reads a file. The read answers at once. It
        // runs on a thread of its own, so a regression fails here on the
        // deadline rather than hanging the test run.
        let (scratch, tree) = tree("fifo");
        let pipe = scratch.join("tree/machine-id");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &pipe,
            FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();

        let (answer, answered) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = answer.send(tree.read("machine-id", 64).map(|_| ()));
        });
        let outcome = answered
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the read answers rather than waiting for a writer");
        let err = outcome.expect_err("a named pipe is not read");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("not a regular file"), "{err}");
    }

    #[test]
    fn a_regular_file_reads_through_an_ordinary_descriptor() {
        // The open is non-blocking so that a pipe cannot stall it; what is
        // handed back for a regular file carries no trace of that.
        let (_scratch, tree) = tree("regular");
        tree.write("etc/os-release", b"ID=test\n").unwrap();
        let file = tree.reader("etc/os-release").unwrap();
        assert!(
            !rustix::fs::fcntl_getfl(&file)
                .unwrap()
                .contains(OFlags::NONBLOCK)
        );
        assert_eq!(tree.read("etc/os-release", 64).unwrap(), b"ID=test\n");
    }

    #[test]
    fn an_overwrite_keeps_the_file_it_rewrites() {
        // The inode, and so the owner, group, and mode a script gave the file,
        // survive the rewrite; only the contents change.
        let (scratch, tree) = tree("overwrite");
        tree.write_mode("etc/shadow", b"root:*:19000:0:::::\n", 0o640)
            .unwrap();
        let path = scratch.join("tree/etc/shadow");
        let before = std::fs::metadata(&path).unwrap();

        tree.overwrite("etc/shadow", b"root:*:1:0:::::\n").unwrap();

        use std::os::unix::fs::MetadataExt;
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"root:*:1:0:::::\n");
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.permissions().mode() & 0o7777, 0o640);

        // A file that is not there is not created, and a link is not written
        // through.
        assert!(tree.overwrite("etc/absent", b"x").is_err());
        std::os::unix::fs::symlink(&path, scratch.join("tree/etc/link")).unwrap();
        assert!(tree.overwrite("etc/link", b"x").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"root:*:1:0:::::\n");
    }

    #[test]
    fn a_reported_host_path_stays_inside_the_tree_however_it_is_spelled() {
        // Error text only, but the failure it would report is the wrong one:
        // `Path::join` discards the root whenever what it is joined to is
        // absolute, so a leading run of slashes trimmed one at a time would name
        // the *host's* path and read as a write that escaped the tree.
        let (scratch, tree) = tree("path");
        let root = scratch.join("tree");
        for spelling in ["/etc/x", "etc/x", "//etc/x", "/etc//./x"] {
            assert_eq!(tree.path(spelling), root.join("etc/x"), "{spelling:?}");
        }
        // A path naming nothing inside the tree names the tree.
        for spelling in ["/", "", "."] {
            assert_eq!(tree.path(spelling), root, "{spelling:?}");
        }
    }

    #[test]
    fn a_directory_listing_reports_the_subdirectories_sorted_and_nothing_else() {
        let (scratch, tree) = tree("directories");
        let root = scratch.join("tree");
        for name in ["sys-libs", "app-crypt", "dev-vcs"] {
            std::fs::create_dir_all(root.join("var/db/pkg").join(name)).unwrap();
        }
        // A file beside them is not one of the things being enumerated, and
        // neither is a symbolic link to a directory: what these callers walk is
        // a directory of directories.
        std::fs::write(root.join("var/db/pkg/README"), b"").unwrap();
        std::os::unix::fs::symlink("sys-libs", root.join("var/db/pkg/alias")).unwrap();

        assert_eq!(
            tree.directories("/var/db/pkg").unwrap(),
            [
                b"app-crypt".to_vec(),
                b"dev-vcs".to_vec(),
                b"sys-libs".to_vec()
            ],
        );
        // Absent is an empty listing rather than a failure: the question is
        // what is there, and nothing is an answer to it.
        assert!(tree.directories("/var/db/nothing").unwrap().is_empty());
        assert!(tree.directories("/var/db/pkg/README").unwrap().is_empty());
    }

    #[test]
    fn a_directory_listing_stays_inside_the_tree() {
        // The containment the whole module exists for, applied to the walk: an
        // absolute link inside the tree names something inside the tree, which
        // is what it means to the root filesystem the tree is.
        let (scratch, tree) = tree("directories-contained");
        let root = scratch.join("tree");
        std::fs::create_dir_all(root.join("etc/portage")).unwrap();
        std::fs::create_dir_all(scratch.join("outside/secret")).unwrap();
        std::os::unix::fs::symlink("/etc", root.join("var")).unwrap();
        std::os::unix::fs::symlink(scratch.join("outside"), root.join("escape")).unwrap();

        // The in-tree absolute link resolves within the tree.
        assert_eq!(tree.directories("/var").unwrap(), [b"portage".to_vec()]);
        // The one pointing at the host resolves to nothing at all.
        assert!(tree.directories("/escape").unwrap().is_empty());
    }

    #[test]
    fn a_write_creates_its_parents_and_states_its_mode() {
        let (scratch, tree) = tree("write");
        tree.write("/etc/apt/sources.list", b"deb file:///pool x main\n")
            .unwrap();
        tree.write_mode("etc/shadow", b"", 0o640).unwrap();

        let root = scratch.join("tree");
        assert_eq!(
            std::fs::read(root.join("etc/apt/sources.list")).unwrap(),
            b"deb file:///pool x main\n",
        );
        let mode = |path: &str| {
            std::fs::symlink_metadata(root.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(
            mode("etc/apt"),
            DIR_MODE,
            "an implied parent states its mode"
        );
        assert_eq!(mode("etc/apt/sources.list"), FILE_MODE);
        assert_eq!(mode("etc/shadow"), 0o640);
    }

    #[cfg(feature = "tarball")]
    #[test]
    fn a_base_directory_its_owner_cannot_write_is_carried_up_and_written_beneath() {
        // A write over a base carries the base's directories up first, and a
        // carried directory keeps the base's mode, 0555 here. Given that mode
        // as it is carried, the directory refuses the write the carry was for,
        // so it is given once the write has landed.
        if rustix::process::geteuid().is_root() {
            ferroday_cage_testkit::require::premise_unmet(
                "the test needs a caller other than root, whom a directory's mode does not bind",
            );
            return;
        }
        let (scratch, upper) = tree("read-only-base");
        let base = scratch.join("base");
        std::fs::create_dir_all(base.join("srv/www")).unwrap();
        std::fs::set_permissions(base.join("srv"), std::fs::Permissions::from_mode(0o555)).unwrap();
        let below = Rooted::open(&base).unwrap();
        let written = upper
            .over(Some(&below))
            .unwrap()
            .write("srv/www/index", b"served\n");
        std::fs::set_permissions(base.join("srv"), std::fs::Permissions::from_mode(0o755)).unwrap();
        written.expect("the write lands");

        let root = scratch.join("tree");
        let mode = |path: &str| {
            std::fs::symlink_metadata(root.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(
            mode("srv"),
            0o555,
            "the carried directory keeps the base's mode"
        );
        assert_eq!(
            std::fs::read(root.join("srv/www/index")).unwrap(),
            b"served\n"
        );
        std::fs::set_permissions(root.join("srv"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn a_planted_symlink_at_a_leaf_is_replaced_not_written_through() {
        // The hazard this type exists for: a maintainer script leaves an
        // absolute link where a host-side step is about to write. The write
        // must land in the tree, and the file outside must be untouched.
        let (scratch, tree) = tree("leaf");
        let outside = scratch.join("victim");
        std::fs::write(&outside, b"original\n").unwrap();
        let root = scratch.join("tree");
        std::fs::create_dir_all(root.join("etc/apt")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("etc/apt/sources.list")).unwrap();

        tree.write("etc/apt/sources.list", b"replaced\n").unwrap();

        assert_eq!(std::fs::read(&outside).unwrap(), b"original\n");
        assert_eq!(
            std::fs::read(root.join("etc/apt/sources.list")).unwrap(),
            b"replaced\n",
        );
        assert!(
            !std::fs::symlink_metadata(root.join("etc/apt/sources.list"))
                .unwrap()
                .file_type()
                .is_symlink(),
        );
    }

    #[test]
    fn an_absolute_link_in_a_parent_resolves_inside_the_tree() {
        // An absolute link in a directory component means what it means to the
        // rootfs it names itself from: a path inside the tree.
        let (scratch, tree) = tree("parent");
        let root = scratch.join("tree");
        std::fs::create_dir(root.join("real-usr")).unwrap();
        std::os::unix::fs::symlink("/real-usr", root.join("usr")).unwrap();

        tree.write("/usr/share/keyrings/archive.gpg", b"keyring")
            .unwrap();

        assert_eq!(
            std::fs::read(root.join("real-usr/share/keyrings/archive.gpg")).unwrap(),
            b"keyring",
        );
        assert!(
            !Path::new("/real-usr").exists(),
            "the host's own root was never reached",
        );

        // A link naming a host path re-anchors onto a path inside the tree,
        // which does not exist, so the write fails rather than landing outside.
        std::fs::create_dir(scratch.join("outside")).unwrap();
        std::os::unix::fs::symlink(scratch.join("outside"), root.join("etc")).unwrap();
        assert!(tree.write("/etc/hosts", b"x").is_err());
        assert!(!scratch.join("outside/hosts").exists());
    }

    #[test]
    fn a_read_refuses_to_follow_a_planted_link() {
        let (scratch, tree) = tree("read");
        let outside = scratch.join("secret");
        std::fs::write(&outside, b"host secret\n").unwrap();
        let root = scratch.join("tree");
        std::fs::create_dir_all(root.join("var/lib/dpkg")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("var/lib/dpkg/status")).unwrap();

        assert!(
            tree.read("var/lib/dpkg/status", 64).is_err(),
            "a link at the leaf must not be read through",
        );
        tree.write("var/lib/dpkg/status", b"Package: x\n").unwrap();
        assert_eq!(
            tree.read("var/lib/dpkg/status", 64).unwrap(),
            b"Package: x\n".to_vec(),
        );
    }

    #[test]
    fn presence_removal_and_rename_stay_in_the_tree() {
        let (scratch, tree) = tree("moves");
        let root = scratch.join("tree");
        let outside = scratch.join("tool");
        std::fs::write(&outside, b"real\n").unwrap();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("usr/bin/chown")).unwrap();

        // A dangling or escaping link still occupies the name.
        assert!(tree.exists("usr/bin/chown").unwrap());
        assert!(!tree.exists("usr/bin/absent").unwrap());
        assert!(!tree.exists("no/such/parent").unwrap());

        // The rename moves the link itself, never its target.
        tree.rename("usr/bin/chown", "usr/bin/chown.saved").unwrap();
        assert!(tree.exists("usr/bin/chown.saved").unwrap());
        assert!(std::fs::symlink_metadata(&outside).is_ok());

        // The removal unlinks the link, not the file it names.
        tree.remove("usr/bin/chown.saved").unwrap();
        assert!(!tree.exists("usr/bin/chown.saved").unwrap());
        assert_eq!(std::fs::read(&outside).unwrap(), b"real\n");
        // An absent path, and an absent parent, are both already done.
        tree.remove("usr/bin/chown.saved").unwrap();
        tree.remove("no/such/parent").unwrap();
    }

    #[test]
    fn a_symlink_replaces_what_occupies_its_name() {
        let (scratch, tree) = tree("symlink");
        let root = scratch.join("tree");
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/awk"), b"not a link\n").unwrap();

        tree.symlink("mawk", "usr/bin/awk").unwrap();

        assert_eq!(
            std::fs::read_link(root.join("usr/bin/awk")).unwrap(),
            Path::new("mawk"),
        );
    }

    #[test]
    fn a_traversal_component_is_refused_rather_than_resolved() {
        let (_scratch, tree) = tree("traversal");
        for path in ["../escape", "etc/../../escape", "", "/", "."] {
            assert!(
                tree.write(path, b"x").is_err(),
                "{path} should not be writable",
            );
        }
    }

    /// Makes an overlay whiteout at `path`, or answers `false` on a kernel that
    /// refuses an unprivileged one (they are allowed from Linux 5.8).
    fn whiteout(path: &Path) -> bool {
        match rustix::fs::mknodat(
            rustix::fs::CWD,
            path,
            FileType::CharacterDevice,
            Mode::empty(),
            0,
        ) {
            Ok(()) => true,
            Err(Errno::PERM) => {
                ferroday_cage_testkit::require::OVERLAY
                    .skip("this kernel refuses an unprivileged whiteout");
                false
            }
            Err(errno) => panic!("making a whiteout: {errno}"),
        }
    }

    #[test]
    fn a_read_past_its_ceiling_is_refused_naming_the_path_and_the_ceiling() {
        // A script makes a file enormous for nothing: the length is a number in
        // an inode, and a sparse file takes no space. What the read holds is
        // bounded by the caller's ceiling, not by what the file claims.
        let (scratch, tree) = tree("ceiling");
        tree.write("etc/machine-id", b"0123456789abcdef\n").unwrap();
        assert_eq!(
            tree.read("etc/machine-id", 17).unwrap(),
            b"0123456789abcdef\n",
            "a file of exactly the ceiling is read whole",
        );
        let err = tree
            .read("etc/machine-id", 16)
            .expect_err("one byte over is refused");
        assert_eq!(err.kind(), io::ErrorKind::FileTooLarge);
        let message = err.to_string();
        assert!(message.contains("etc/machine-id"), "{message}");
        assert!(message.contains("16 bytes"), "{message}");

        let sparse = std::fs::File::options()
            .write(true)
            .open(scratch.join("tree/etc/machine-id"))
            .unwrap();
        sparse.set_len(1 << 36).unwrap();
        let err = tree
            .read("etc/machine-id", 4096)
            .expect_err("a sparse file the size of a disk is refused");
        assert_eq!(err.kind(), io::ErrorKind::FileTooLarge);
    }

    #[test]
    fn a_name_that_holds_no_file_reads_as_none() {
        // Absent is a leaf that is not there, a parent that is not there or is
        // not a directory, and a whiteout, which is how a layered build's upper
        // records a file its run deleted.
        let (scratch, tree) = tree("if-present");
        tree.write("etc/shadow", b"root:*:1:0:::::\n").unwrap();
        assert_eq!(
            tree.read_if_present("etc/shadow", 64).unwrap().as_deref(),
            Some(&b"root:*:1:0:::::\n"[..]),
        );
        for absent in ["etc/absent", "absent/shadow", "etc/shadow/below"] {
            assert_eq!(tree.read_if_present(absent, 64).unwrap(), None, "{absent}");
        }
        if whiteout(&scratch.join("tree/etc/gone")) {
            assert_eq!(tree.read_if_present("etc/gone", 64).unwrap(), None);
        }
        // Something that is there and is not a file is not a missing file.
        std::fs::create_dir(scratch.join("tree/etc/dir")).unwrap();
        assert!(tree.read_if_present("etc/dir", 64).is_err());
        // And the ceiling holds here as well.
        assert!(tree.read_if_present("etc/shadow", 4).is_err());
    }

    #[test]
    fn a_truncation_empties_only_an_approved_file_and_keeps_it() {
        use std::os::unix::fs::MetadataExt;
        let (scratch, tree) = tree("truncate");
        let root = scratch.join("tree");

        // `systemd` writes the machine id read-only. It is emptied all the
        // same, in place: the inode, and with it the owner and the mode, are
        // the ones the script left.
        tree.write_mode("etc/machine-id", b"0123456789abcdef\n", 0o444)
            .unwrap();
        let before = std::fs::metadata(root.join("etc/machine-id")).unwrap();
        tree.truncate_if("etc/machine-id", Rooted::is_file_with_content)
            .unwrap();
        let after = std::fs::metadata(root.join("etc/machine-id")).unwrap();
        assert_eq!(after.len(), 0);
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.permissions().mode() & 0o7777, 0o444);

        // A file the predicate turns down keeps its contents.
        tree.write("etc/hostname", b"kept\n").unwrap();
        tree.truncate_if("etc/hostname", |_| false).unwrap();
        assert_eq!(std::fs::read(root.join("etc/hostname")).unwrap(), b"kept\n");

        // Nothing that is not a regular file is emptied, whatever the
        // predicate says: not through a link, and not a named pipe, which is
        // never opened.
        let outside = scratch.join("outside");
        std::fs::write(&outside, b"host contents\n").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("etc/link")).unwrap();
        tree.truncate_if("etc/link", |_| true).unwrap();
        assert_eq!(std::fs::read(&outside).unwrap(), b"host contents\n");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            root.join("etc/pipe"),
            FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        tree.truncate_if("etc/pipe", |_| true).unwrap();
        if whiteout(&root.join("etc/gone")) {
            tree.truncate_if("etc/gone", |_| true).unwrap();
            assert!(std::fs::symlink_metadata(root.join("etc/gone")).is_ok());
        }

        // An absent file, or an absent parent, is already done.
        tree.truncate_if("etc/absent", |_| true).unwrap();
        tree.truncate_if("absent/file", |_| true).unwrap();
    }

    #[test]
    fn a_truncation_empties_the_file_it_approved_or_nothing() {
        // The predicate approves one file, and a regular file renamed onto the
        // name before the open is not that file. It is left as it is and the
        // call says the name changed, rather than emptying what nobody looked
        // at. The rename runs inside the predicate, which is exactly the
        // window between the look and the open.
        let (scratch, tree) = tree("truncate-raced");
        let root = scratch.join("tree");
        tree.write("etc/machine-id", b"approved\n").unwrap();
        tree.write("etc/other", b"unseen\n").unwrap();
        let err = tree
            .truncate_if("etc/machine-id", |_| {
                std::fs::rename(root.join("etc/other"), root.join("etc/machine-id")).unwrap();
                true
            })
            .expect_err("the name no longer holds the approved file");
        assert!(err.to_string().contains("was replaced"), "{err}");
        assert_eq!(
            std::fs::read(root.join("etc/machine-id")).unwrap(),
            b"unseen\n",
        );
    }

    #[test]
    fn a_removal_can_leave_a_whiteout_in_place() {
        // A layered build's upper records a file its run deleted as a whiteout,
        // and removing that would bring the base's copy back through the
        // overlay.
        let (scratch, tree) = tree("whiteout");
        let root = scratch.join("tree");
        std::fs::create_dir(root.join("log")).unwrap();
        tree.write("log/dpkg.log", b"recorded\n").unwrap();
        tree.remove_if("log/dpkg.log", |stat| !Rooted::is_whiteout(stat))
            .unwrap();
        assert!(std::fs::symlink_metadata(root.join("log/dpkg.log")).is_err());
        if whiteout(&root.join("log/alternatives.log")) {
            tree.remove_if("log/alternatives.log", |stat| !Rooted::is_whiteout(stat))
                .unwrap();
            assert!(std::fs::symlink_metadata(root.join("log/alternatives.log")).is_ok());
        }
    }
}
