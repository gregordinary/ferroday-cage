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
//! read therefore opens without waiting and refuses whatever it opened that is
//! not a regular file, so a tree can fail a read but cannot stall one.
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

// Most of this module serves the Debian bootstrap's host-side steps; a build
// without that feature reaches it only through `remove_if`, for the launch
// teardown's mount-point placeholders. The rest is dead code there, and saying
// so once is clearer than gating a dozen methods one by one.
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

/// The mode an intermediate directory is created with.
///
/// `mkdirat` honours the umask, so the mode is applied explicitly afterward:
/// a rootfs whose directory modes followed the caller's umask would differ
/// between two runs of the same build.
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
    /// The tree's host path, for error reporting only.
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
            root: root.to_path_buf(),
        })
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

    /// Reads the file at `relative`.
    ///
    /// `O_NOFOLLOW`: a symbolic link at the leaf fails the read rather than
    /// being followed, so a link planted where a file is expected cannot turn
    /// this into a read of something else. Anything else that is not a regular
    /// file is refused as [`reader`](Self::reader) refuses it.
    pub(crate) fn read(&self, relative: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        let mut contents = Vec::new();
        self.reader(relative)?.read_to_end(&mut contents)?;
        Ok(contents)
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
    /// waited on, a named pipe included; see
    /// [`open_regular`](Self::open_regular).
    pub(crate) fn reader(&self, relative: impl AsRef<Path>) -> io::Result<File> {
        self.open_regular(relative.as_ref(), OFlags::RDONLY)
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
        let mut file = self.open_regular(relative.as_ref(), OFlags::WRONLY)?;
        file.set_len(0)?;
        file.write_all(contents)
    }

    /// Opens the regular file at `relative` for `access`, refusing anything
    /// else without waiting on it.
    ///
    /// The open is `O_NONBLOCK`, so a named pipe at the leaf, which an ordinary
    /// open would wait on until something opened its other end, returns at
    /// once, and is then refused as a directory, a socket, or a device node is.
    /// `O_NOCTTY` keeps a terminal from becoming the caller's controlling
    /// terminal in the moment before its refusal. A regular file ignores
    /// `O_NONBLOCK`, and the flag is cleared before the descriptor is handed
    /// back all the same.
    fn open_regular(&self, relative: &Path, access: OFlags) -> io::Result<File> {
        let (parent, leaf) = self.parent_of(relative, Parents::Require)?;
        let fd = rustix::fs::openat(
            &parent,
            &leaf,
            access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) != FileType::RegularFile {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", self.path(relative).display()),
            ));
        }
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
    /// caller, and neither has [`open_read_dir`](Self::open_read_dir) below it.
    /// The module's own blanket allowance does not cover the pair, since they
    /// are dead under `debian` as well.
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
        let (parent, leaf) = match self.parent_of(relative.as_ref(), Parents::Require) {
            Ok(found) => found,
            Err(Errno::NOENT | Errno::NOTDIR) => return Ok(false),
            Err(errno) => return Err(errno.into()),
        };
        match rustix::fs::statat(&parent, &leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT | Errno::NOTDIR) => Ok(false),
            Err(errno) => Err(errno.into()),
        }
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
    /// against the same directory descriptor the unlink uses, so the entry
    /// inspected and the entry removed are one and the same and neither follows
    /// a link out of the tree.
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
    #[cfg_attr(not(feature = "alpine"), allow(dead_code))]
    pub(crate) fn is_file_with_content(stat: &Stat) -> bool {
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile && stat.st_size > 0
    }

    /// Renames `from` to `to` within the tree, replacing whatever occupies the
    /// destination. Both paths resolve against the tree's root.
    pub(crate) fn rename(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
        let (from_parent, from_leaf) = self.parent_of(from.as_ref(), Parents::Require)?;
        let (to_parent, to_leaf) = self.parent_of(to.as_ref(), Parents::Create)?;
        rustix::fs::renameat(&from_parent, &from_leaf, &to_parent, &to_leaf)?;
        Ok(())
    }

    /// Creates a symbolic link at `relative` holding `target` verbatim,
    /// replacing whatever occupies the name.
    ///
    /// `target` is stored as written and never resolved here; it is read by
    /// whatever later follows the link, inside the tree.
    pub(crate) fn symlink(&self, target: &str, relative: impl AsRef<Path>) -> io::Result<()> {
        let target = CString::new(target).map_err(|_| Errno::INVAL)?;
        let (parent, leaf) = self.parent_of(relative.as_ref(), Parents::Create)?;
        containment::replacing(&parent, &leaf, || {
            rustix::fs::symlinkat(&target, &parent, &leaf)
        })?;
        Ok(())
    }

    /// Creates the file at `relative` holding `contents`, at `mode`.
    ///
    /// The leaf is created `O_EXCL | O_NOFOLLOW` and, on a name already taken,
    /// unlinked and created again: a symbolic link occupying it is replaced by
    /// the file rather than written through, which is the extractor's rule for
    /// its own leaves. The mode is applied through the descriptor, so it lands
    /// on the file this created and on nothing else.
    fn create(&self, relative: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
        let (parent, leaf) = self.parent_of(relative, Parents::Create)?;
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
        Ok(())
    }

    /// Opens the parent directory of `relative` and returns it with the leaf
    /// name, creating the missing links of the chain where asked to.
    fn parent_of(&self, relative: &Path, parents: Parents) -> Result<(OwnedFd, CString), Errno> {
        let components = components(relative)?;
        let (leaf, parent) = components.split_last().expect("validated non-empty");
        let leaf = CString::new(*leaf).map_err(|_| Errno::INVAL)?;
        let parent = match parents {
            Parents::Require => self.open_dir(parent)?,
            Parents::Create => self.create_dirs(parent)?,
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
        let path = if components.is_empty() {
            CString::new(&b"."[..])
        } else {
            CString::new(components.join(&b'/'))
        }
        .map_err(|_| Errno::INVAL)?;
        containment::open_dir(self.fd.as_fd(), &path, OFlags::PATH, ResolveFlags::IN_ROOT)
    }

    /// Resolves `components` inside the tree as a directory that will be read.
    ///
    /// `O_RDONLY` where [`open_dir`](Self::open_dir) takes `O_PATH`: an
    /// `O_PATH` descriptor anchors an `*at` call and cannot be handed to
    /// `getdents`.
    ///
    /// [`directories`](Self::directories) is its only caller, so it is dead in
    /// the same builds and gated the same way.
    #[cfg_attr(not(feature = "gentoo"), allow(dead_code))]
    fn open_read_dir(&self, components: &[&[u8]]) -> Result<OwnedFd, Errno> {
        let path = if components.is_empty() {
            CString::new(&b"."[..])
        } else {
            CString::new(components.join(&b'/'))
        }
        .map_err(|_| Errno::INVAL)?;
        containment::open_dir(
            self.fd.as_fd(),
            &path,
            OFlags::RDONLY,
            ResolveFlags::IN_ROOT,
        )
    }

    /// Opens `components` as a directory, creating the missing links of the
    /// chain.
    ///
    /// Each prefix is resolved from the root rather than descended into, so an
    /// in-tree symbolic link mid-path — a merged-usr alias — keeps working, and
    /// each `mkdirat` is anchored to the descriptor the previous resolve
    /// returned.
    fn create_dirs(&self, components: &[&[u8]]) -> Result<OwnedFd, Errno> {
        match self.open_dir(components) {
            Ok(fd) => return Ok(fd),
            Err(Errno::NOENT) => {}
            Err(errno) => return Err(errno),
        }
        for depth in 1..=components.len() {
            match self.open_dir(&components[..depth]) {
                Ok(_) => continue,
                Err(Errno::NOENT) => {}
                Err(errno) => return Err(errno),
            }
            let above = self.open_dir(&components[..depth - 1])?;
            let leaf = CString::new(components[depth - 1]).map_err(|_| Errno::INVAL)?;
            match rustix::fs::mkdirat(&above, &leaf, Mode::from_raw_mode(DIR_MODE)) {
                // `mkdirat` honours the umask, so the mode is stated again.
                Ok(()) => rustix::fs::chmodat(
                    &above,
                    &leaf,
                    Mode::from_raw_mode(DIR_MODE),
                    AtFlags::empty(),
                )?,
                // Something is already at the name. If it is a directory, or an
                // in-tree link to one, the resolve at the top of the next round
                // finds it; if it is not, that resolve fails with `ENOTDIR` and
                // says so.
                Err(Errno::EXIST) => {}
                Err(errno) => return Err(errno),
            }
        }
        self.open_dir(components)
    }
}

/// Whether a missing parent directory is created or is a failure.
#[derive(Clone, Copy)]
enum Parents {
    /// Create the missing links of the chain.
    Create,
    /// Fail with the kernel's own `ENOENT`.
    Require,
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
            let _ = answer.send(tree.read("machine-id").map(|_| ()));
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
        assert_eq!(tree.read("etc/os-release").unwrap(), b"ID=test\n");
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
            tree.read("var/lib/dpkg/status").is_err(),
            "a link at the leaf must not be read through",
        );
        tree.write("var/lib/dpkg/status", b"Package: x\n").unwrap();
        assert_eq!(
            tree.read("var/lib/dpkg/status").unwrap(),
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
}
