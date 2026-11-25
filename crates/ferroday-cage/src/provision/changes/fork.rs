//! Copying an upper to a new upper, so a session continues from one point
//! twice.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat, Timespec, Timestamps};
use rustix::io::Errno;

use super::super::ProvisionError;
use super::super::containment;
use super::super::copyin::{by_path, read_names};
use super::super::xattr::{self, Holder};
use super::apply::{carries, copy_data, resolve, split};
use super::{ChangeSet, misread_record};
use crate::Overlay;
use crate::mechanism::bounds::LINK_BUF;
use crate::mechanism::delete_tree;

impl ChangeSet {
    /// Copies the upper these changes were read from to `to`, a new upper over
    /// the same lowers, and returns the overlay of them.
    ///
    /// Two sessions then continue from one point, each over an upper of its
    /// own. The copy is the upper as it stands when it is copied, whiteouts
    /// and opaque markers included, and an attribute a command named
    /// `user.overlay.` kept as the overlay keeps it. Its files keep their
    /// holes, names that share an inode stay one file, and every entry keeps
    /// its mode and its times. The overlay's other bookkeeping is left behind,
    /// for the kernel to write afresh. A named pipe and a socket are made
    /// again; a device other than a whiteout cannot be, and is refused.
    ///
    /// `to` must not exist, and its parent must. Copy an upper no sandbox is
    /// writing: a copy of a tree in motion is of no one moment of it. The
    /// returned overlay names no work directory, so a sandbox mounting it gets
    /// one of its own beside `to`.
    ///
    /// It is the second answer to laying a tree into another, beside
    /// [`CopyIn`](super::super::CopyIn). A copy-in lays a tree into a root
    /// through the identity map the root is owned through, and leaves the
    /// overlay's records out, since a root is no upper. A fork copies an upper
    /// of the caller's own, the single-identity map's, into another, and the
    /// records are what it exists to keep.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::Io`] where `to` exists, its parent does not, or an
    /// entry cannot be read or made, and [`ProvisionError::EntryRefused`] for
    /// a record the reader refuses or a device. Either way, what the fork made
    /// is removed.
    pub fn fork(&self, to: impl AsRef<Path>) -> Result<Overlay, ProvisionError> {
        let to = to.as_ref();
        let made = |errno: Errno| ProvisionError::io("forking into", to, errno.into());
        let (_, name) = split(to).map_err(made)?;
        let parent_fd = fs::open(
            crate::path::parent_of(to),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(made)?;
        let source = fs::open(
            &self.upper,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| ProvisionError::io("reading", &self.upper, errno.into()))?;
        fs::mkdirat(&parent_fd, &name, Mode::from_raw_mode(0o700)).map_err(made)?;
        let copied = containment::open_child_dir(&parent_fd, &name, OFlags::RDONLY)
            .map_err(made)
            .and_then(|dest| {
                Fork {
                    from: &self.upper,
                    dest: &dest,
                    links: HashMap::new(),
                    directories: Vec::new(),
                }
                .copy(source)
            });
        if let Err(err) = copied {
            let _ = delete_tree(parent_fd.as_fd(), &name);
            return Err(err);
        }
        let mut overlay = Overlay::new();
        for lower in &self.lowers {
            overlay = overlay.lower(lower);
        }
        Ok(overlay.upper(to))
    }
}

/// The state one fork carries.
struct Fork<'a> {
    /// The upper copied from, which names an entry in a failure.
    from: &'a Path,
    /// The copy's top.
    dest: &'a OwnedFd,
    /// The first copy made of each file with several names, by the source's
    /// device and inode, as its path in the copy.
    links: HashMap<(u64, u64), PathBuf>,
    /// Each directory copied, its path and the source's `stat`, in the order
    /// made, whose mode and times are set once nothing more is made in it.
    directories: Vec<(PathBuf, Stat)>,
}

/// One directory of the source the walk is inside, and its copy.
struct Level {
    source: OwnedFd,
    dest: OwnedFd,
    path: PathBuf,
    names: std::vec::IntoIter<Vec<u8>>,
}

impl Fork<'_> {
    /// Copies the source's top, `source`, into the copy's top, and every entry
    /// beneath it.
    ///
    /// The walk carries its own stack, as the reader's does, and holds open
    /// only the directories from the top to where it is.
    fn copy(mut self, source: OwnedFd) -> Result<(), ProvisionError> {
        let top = Path::new("");
        let stat = fs::fstat(&source).map_err(|errno| self.io(top, errno))?;
        let dest = containment::open_child_dir(self.dest, c".", OFlags::RDONLY)
            .map_err(|errno| self.io(top, errno))?;
        self.attributes(Holder::Fd(source.as_fd()), Holder::Fd(dest.as_fd()), top)?;
        self.directories.push((PathBuf::new(), stat));
        let mut stack = vec![self.level(source, dest, PathBuf::new())?];
        while let Some(at) = stack.len().checked_sub(1) {
            let Some(name) = stack[at].names.next() else {
                stack.pop();
                continue;
            };
            let level = &stack[at];
            let path = level.path.join(OsStr::from_bytes(&name));
            let name = CString::new(name).map_err(|_| self.io(&path, Errno::INVAL))?;
            if let Some((source, dest)) =
                self.entry(level.source.as_fd(), level.dest.as_fd(), &name, &path)?
            {
                let next = self.level(source, dest, path)?;
                stack.push(next);
            }
        }
        // Deepest first, and each directory's times after its mode, since
        // every entry made in a directory moves them.
        for (path, stat) in self.directories.iter().rev() {
            let dir = match split(path) {
                Ok((parent, leaf)) => resolve(self.dest.as_fd(), parent)
                    .and_then(|parent| containment::open_child_dir(&parent, &leaf, OFlags::RDONLY)),
                Err(_) => containment::open_child_dir(self.dest, c".", OFlags::RDONLY),
            }
            .map_err(|errno| self.io(path, errno))?;
            fs::fchmod(&dir, Mode::from_raw_mode(stat.st_mode & 0o7777))
                .map_err(|errno| self.io(path, errno))?;
            fs::futimens(&dir, &times(stat)).map_err(|errno| self.io(path, errno))?;
        }
        Ok(())
    }

    /// The level for the source's directory `source` at `path` and its copy
    /// `dest`, its names sorted, so two forks of one upper make the same tree
    /// in the same order.
    fn level(
        &self,
        source: OwnedFd,
        dest: OwnedFd,
        path: PathBuf,
    ) -> Result<Level, ProvisionError> {
        let mut names = read_names(source.as_fd(), &self.from.join(&path))?;
        names.sort();
        Ok(Level {
            source,
            dest,
            path,
            names: names.into_iter(),
        })
    }

    /// Copies the entry `name` of `source` into `dest`, at `path`, and
    /// returns the source's directory and its copy where it is one.
    fn entry(
        &mut self,
        source: BorrowedFd<'_>,
        dest: BorrowedFd<'_>,
        name: &CStr,
        path: &Path,
    ) -> Result<Option<(OwnedFd, OwnedFd)>, ProvisionError> {
        let io = |errno: Errno| self.io(path, errno);
        let stat = fs::statat(source, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
        let mode = Mode::from_raw_mode(stat.st_mode & 0o7777);
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                let from = containment::open_child_dir(source, name, OFlags::RDONLY).map_err(io)?;
                fs::mkdirat(dest, name, Mode::from_raw_mode(0o700)).map_err(io)?;
                let to = containment::open_child_dir(dest, name, OFlags::RDONLY).map_err(io)?;
                self.attributes(Holder::Fd(from.as_fd()), Holder::Fd(to.as_fd()), path)?;
                self.directories.push((path.to_path_buf(), stat));
                return Ok(Some((from, to)));
            }
            FileType::RegularFile => {
                let key = (stat.st_dev, stat.st_ino);
                if stat.st_nlink > 1
                    && let Some(first) = self.links.get(&key)
                {
                    let (parent, leaf) = split(first).map_err(io)?;
                    let parent = resolve(self.dest.as_fd(), parent).map_err(io)?;
                    fs::linkat(&parent, &leaf, dest, name, AtFlags::empty()).map_err(io)?;
                    return Ok(None);
                }
                let from = containment::open_typed_file(source, name, &stat, OFlags::RDONLY)
                    .map_err(|errno| match errno {
                        Errno::STALE => ProvisionError::SourceChanged {
                            path: self.from.join(path),
                            recorded: stat.st_size as u64,
                        },
                        errno => self.io(path, errno),
                    })?;
                let to = fs::openat(
                    dest,
                    name,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(io)?;
                copy_data(from.as_fd(), to.as_fd(), stat.st_size as u64).map_err(io)?;
                self.attributes(Holder::Fd(from.as_fd()), Holder::Fd(to.as_fd()), path)?;
                fs::fchmod(&to, mode).map_err(io)?;
                fs::futimens(&to, &times(&stat)).map_err(io)?;
                if stat.st_nlink > 1 {
                    self.links.insert(key, path.to_path_buf());
                }
                return Ok(None);
            }
            FileType::Symlink => {
                let mut buffer = [0u8; LINK_BUF];
                let read = fs::readlinkat_raw(source, name, &mut buffer[..]).map_err(io)?;
                if read == buffer.len() {
                    return Err(ProvisionError::EntryRefused {
                        path: self.from.join(path),
                        reason: "the symlink target is longer than the fork reads".to_string(),
                    });
                }
                fs::symlinkat(OsStr::from_bytes(&buffer[..read]), dest, name).map_err(io)?;
            }
            // A whiteout, which the kernel lets an unprivileged process make.
            FileType::CharacterDevice if containment::is_whiteout(&stat) => {
                fs::mknodat(dest, name, FileType::CharacterDevice, mode, 0).map_err(io)?;
            }
            kind @ (FileType::Fifo | FileType::Socket) => {
                fs::mknodat(dest, name, kind, mode, 0).map_err(io)?;
                let from = by_path(source, name.to_bytes(), &self.from.join(path))?;
                let to = by_path(dest, name.to_bytes(), &self.from.join(path))?;
                self.attributes(Holder::Path(&from), Holder::Path(&to), path)?;
            }
            _ => {
                return Err(ProvisionError::EntryRefused {
                    path: self.from.join(path),
                    reason: "a device other than a whiteout, which an unprivileged copy cannot \
                             make"
                        .to_string(),
                });
            }
        }
        // A link, a whiteout, a pipe or a socket: its mode was given at its
        // making, and its times are set by name, not following a link.
        fs::utimensat(dest, name, &times(&stat), AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
        Ok(None)
    }

    /// Copies the attributes of `from` that a fork keeps onto `to`: those an
    /// apply carries, the opaque marker, and an attribute a command named
    /// `user.overlay.`, which the overlay keeps escaped. Refuses a record the
    /// reader would read otherwise than the kernel.
    fn attributes(
        &self,
        from: Holder<'_>,
        to: Holder<'_>,
        path: &Path,
    ) -> Result<(), ProvisionError> {
        let io = |errno: Errno| self.io(path, errno);
        for (name, value) in xattr::read_all(from).map_err(io)? {
            if let Some(record) = misread_record(&name, &value) {
                return Err(ProvisionError::EntryRefused {
                    path: self.from.join(path),
                    reason: format!(
                        "it carries the overlay record {record}, which no overlay this library \
                         mounts writes, and which the reader would read otherwise than the kernel"
                    ),
                });
            }
            let kept = carries(&name)
                || name == b"user.overlay.opaque"
                || name.starts_with(b"user.overlay.overlay.");
            if !kept {
                continue;
            }
            let name = CString::new(name).map_err(|_| io(Errno::INVAL))?;
            match &to {
                Holder::Fd(fd) => fs::fsetxattr(fd, &name, &value, fs::XattrFlags::empty()),
                Holder::Path(path) => fs::lsetxattr(*path, &name, &value, fs::XattrFlags::empty()),
            }
            .map_err(io)?;
        }
        Ok(())
    }

    /// The failure of reading or making `path`.
    fn io(&self, path: &Path, errno: Errno) -> ProvisionError {
        ProvisionError::io("forking", self.from.join(path), errno.into())
    }
}

/// An entry's access and modification times, to set on its copy.
fn times(stat: &Stat) -> Timestamps {
    Timestamps {
        last_access: Timespec {
            tv_sec: stat.st_atime,
            tv_nsec: stat.st_atime_nsec as _,
        },
        last_modification: Timespec {
            tv_sec: stat.st_mtime,
            tv_nsec: stat.st_mtime_nsec as _,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    use ferroday_cage_testkit::{overlay, xattr as test_xattr};

    use super::*;
    use crate::scratch::Scratch;

    fn write(path: PathBuf, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// What a change set lists, without the upper's own identities.
    fn listed(overlay: &Overlay) -> Vec<(PathBuf, ChangeKindAndKinds)> {
        ChangeSet::read(overlay)
            .unwrap()
            .changes()
            .iter()
            .map(|change| {
                (
                    change.path().to_path_buf(),
                    (
                        change.kind(),
                        change.before(),
                        change.now(),
                        change.content_differs(),
                        change.mode_differs(),
                    ),
                )
            })
            .collect()
    }

    type ChangeKindAndKinds = (
        super::super::ChangeKind,
        Option<super::super::EntryKind>,
        Option<super::super::EntryKind>,
        bool,
        bool,
    );

    #[test]
    fn a_fork_keeps_what_an_upper_records() {
        let scratch = Scratch::new("fork");
        let (lower, upper) = (scratch.join("lower"), scratch.join("upper"));
        for path in ["gone", "dir/old", "kept"] {
            write(lower.join(path), "lower\n");
        }
        std::fs::create_dir(&upper).unwrap();
        if !overlay::whiteout(&upper.join("gone")) {
            return;
        }
        std::fs::create_dir(upper.join("dir")).unwrap();
        assert!(test_xattr::set(
            &upper.join("dir"),
            "user.overlay.opaque",
            b"y"
        ));
        write(upper.join("dir/new"), "upper\n");
        write(upper.join("kept"), "upper\n");
        assert!(test_xattr::set(
            &upper.join("kept"),
            "user.overlay.origin",
            b""
        ));
        assert!(test_xattr::set(
            &upper.join("kept"),
            "user.overlay.overlay.mine",
            b"escaped"
        ));
        assert!(test_xattr::set(&upper.join("kept"), "user.note", b"kept"));
        std::fs::set_permissions(upper.join("kept"), PermissionsExt::from_mode(0o4750)).unwrap();
        std::fs::hard_link(upper.join("kept"), upper.join("second")).unwrap();
        std::os::unix::fs::symlink("kept", upper.join("link")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            upper.join("fifo"),
            FileType::Fifo,
            Mode::from_raw_mode(0o640),
            0,
        )
        .unwrap();
        let sparse = std::fs::File::create(upper.join("sparse")).unwrap();
        sparse.set_len(1 << 30).unwrap();
        drop(sparse);

        let original = Overlay::new().lower(&lower).upper(&upper);
        let forked = ChangeSet::read(&original)
            .unwrap()
            .fork(scratch.join("fork"))
            .unwrap();
        assert_eq!(forked.get_lowers(), original.get_lowers());
        let fork = scratch.join("fork");
        assert_eq!(forked.get_upper(), Some(fork.as_path()));
        assert_eq!(listed(&forked), listed(&original));

        assert!(overlay::is_whiteout(&fork.join("gone")));
        assert_eq!(
            test_xattr::get(&fork.join("dir"), "user.overlay.opaque").as_deref(),
            Some(&b"y"[..])
        );
        assert_eq!(
            test_xattr::get(&fork.join("kept"), "user.overlay.origin"),
            None
        );
        assert_eq!(
            test_xattr::get(&fork.join("kept"), "user.overlay.overlay.mine").as_deref(),
            Some(&b"escaped"[..])
        );
        assert_eq!(
            test_xattr::get(&fork.join("kept"), "user.note").as_deref(),
            Some(&b"kept"[..])
        );
        let (kept, second) = (
            std::fs::metadata(fork.join("kept")).unwrap(),
            std::fs::metadata(fork.join("second")).unwrap(),
        );
        assert_eq!(kept.ino(), second.ino());
        assert_eq!(kept.mode() & 0o7777, 0o4750);
        let source = std::fs::metadata(upper.join("kept")).unwrap();
        assert_eq!(
            (kept.mtime(), kept.mtime_nsec()),
            (source.mtime(), source.mtime_nsec())
        );
        assert_eq!(
            std::fs::read_link(fork.join("link")).unwrap(),
            Path::new("kept")
        );
        assert!(
            std::fs::symlink_metadata(fork.join("fifo"))
                .unwrap()
                .file_type()
                .is_fifo()
        );
        let sparse = std::fs::metadata(fork.join("sparse")).unwrap();
        assert_eq!(sparse.len(), 1 << 30);
        assert!(sparse.blocks() * 512 < 1 << 20);

        // A fork never lands on an existing directory.
        assert!(matches!(
            ChangeSet::read(&original).unwrap().fork(&fork),
            Err(ProvisionError::Io { .. })
        ));
    }

    /// A refused fork removes what it made.
    #[test]
    fn a_refused_fork_leaves_nothing() {
        let scratch = Scratch::new("fork-refused");
        let (lower, upper) = (scratch.join("lower"), scratch.join("upper"));
        std::fs::create_dir(&lower).unwrap();
        write(upper.join("a/b"), "upper\n");
        let overlay = Overlay::new().lower(&lower).upper(&upper);
        let changes = ChangeSet::read(&overlay).unwrap();
        if !test_xattr::set(&upper.join("a/b"), "user.overlay.metacopy", b"") {
            return;
        }
        assert!(matches!(
            changes.fork(scratch.join("fork")),
            Err(ProvisionError::EntryRefused { .. })
        ));
        assert!(!scratch.join("fork").exists());
    }
}
