//! Host-side file operations on a tree, contained to that tree.
//!
//! A provisioner's host side reads and writes inside a tree that untrusted
//! code has already run in: the Debian bootstrap seeds a statoverride, swaps
//! ownership stubs, and writes the finished rootfs's apt sources between dpkg
//! waves, and by then every selected package's maintainer scripts have run
//! inside a cage rooted at that tree, as root of its namespace. Such a script
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
//! Paths are tree-relative and may be written with a leading `/`, since the
//! tree is a root filesystem and its own files name themselves that way. A `..`
//! component is refused outright rather than resolved: the kernel would contain
//! it, but no path this is asked for has one, and a path that does is a
//! composition bug rather than a traversal to honour. The tree's host path is
//! held only to name it in an error; nothing resolves through it.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

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

/// How many times a create is retried when something already occupies the
/// name. One replacement always suffices; the bound exists so a pathological
/// filesystem state cannot loop forever.
const REPLACE_ATTEMPTS: u32 = 3;

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
    pub(crate) fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative.trim_start_matches('/'))
    }

    /// Writes `contents` to `relative` at the default mode, creating missing
    /// parent directories.
    pub(crate) fn write(&self, relative: &str, contents: &[u8]) -> io::Result<()> {
        self.create(relative, contents, FILE_MODE)
    }

    /// Writes `contents` to `relative` at `mode`, creating missing parent
    /// directories.
    pub(crate) fn write_mode(&self, relative: &str, contents: &[u8], mode: u32) -> io::Result<()> {
        self.create(relative, contents, mode)
    }

    /// Reads the file at `relative`.
    ///
    /// `O_NOFOLLOW`: a symbolic link at the leaf fails the read rather than
    /// being followed, so a link planted where a file is expected cannot turn
    /// this into a read of something else.
    pub(crate) fn read(&self, relative: &str) -> io::Result<Vec<u8>> {
        let (parent, leaf) = self.parent_of(relative, Parents::Require)?;
        let fd = rustix::fs::openat(
            &parent,
            &leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut contents = Vec::new();
        File::from(fd).read_to_end(&mut contents)?;
        Ok(contents)
    }

    /// Whether anything occupies `relative` — a file, a directory, or a
    /// symbolic link, dangling or not. The question is whether the name is
    /// taken, so nothing is followed.
    pub(crate) fn exists(&self, relative: &str) -> io::Result<bool> {
        let (parent, leaf) = match self.parent_of(relative, Parents::Require) {
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
    pub(crate) fn remove(&self, relative: &str) -> io::Result<()> {
        let (parent, leaf) = match self.parent_of(relative, Parents::Require) {
            Ok(found) => found,
            Err(Errno::NOENT | Errno::NOTDIR) => return Ok(()),
            Err(errno) => return Err(errno.into()),
        };
        match rustix::fs::unlinkat(&parent, &leaf, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(errno) => Err(errno.into()),
        }
    }

    /// Renames `from` to `to` within the tree, replacing whatever occupies the
    /// destination. Both paths resolve against the tree's root.
    pub(crate) fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (from_parent, from_leaf) = self.parent_of(from, Parents::Require)?;
        let (to_parent, to_leaf) = self.parent_of(to, Parents::Create)?;
        rustix::fs::renameat(&from_parent, &from_leaf, &to_parent, &to_leaf)?;
        Ok(())
    }

    /// Creates a symbolic link at `relative` holding `target` verbatim,
    /// replacing whatever occupies the name.
    ///
    /// `target` is stored as written and never resolved here; it is read by
    /// whatever later follows the link, inside the tree.
    pub(crate) fn symlink(&self, target: &str, relative: &str) -> io::Result<()> {
        let target = CString::new(target).map_err(|_| Errno::INVAL)?;
        let (parent, leaf) = self.parent_of(relative, Parents::Create)?;
        replacing(&parent, &leaf, || {
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
    fn create(&self, relative: &str, contents: &[u8], mode: u32) -> io::Result<()> {
        let (parent, leaf) = self.parent_of(relative, Parents::Create)?;
        let fd = replacing(&parent, &leaf, || {
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
    fn parent_of(&self, relative: &str, parents: Parents) -> Result<(OwnedFd, CString), Errno> {
        let components = components(relative)?;
        let (leaf, parent) = components.split_last().expect("validated non-empty");
        let leaf = CString::new(*leaf).map_err(|_| Errno::INVAL)?;
        let parent = match parents {
            Parents::Require => self.open_dir(parent)?,
            Parents::Create => self.create_dirs(parent)?,
        };
        Ok((parent, leaf))
    }

    /// Resolves `components` beneath the tree as a directory.
    fn open_dir(&self, components: &[&str]) -> Result<OwnedFd, Errno> {
        let path = if components.is_empty() {
            CString::new(".")
        } else {
            CString::new(components.join("/"))
        }
        .map_err(|_| Errno::INVAL)?;
        loop {
            match rustix::fs::openat2(
                self.fd.as_fd(),
                &path,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
            ) {
                // The kernel asks for a retry when a rename raced the walk.
                Err(Errno::AGAIN) => continue,
                result => return result,
            }
        }
    }

    /// Opens `components` as a directory, creating the missing links of the
    /// chain.
    ///
    /// Each prefix is resolved from the root rather than descended into, so an
    /// in-tree symbolic link mid-path — a merged-usr alias — keeps working, and
    /// each `mkdirat` is anchored to the descriptor the previous resolve
    /// returned.
    fn create_dirs(&self, components: &[&str]) -> Result<OwnedFd, Errno> {
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

/// Runs `create`, unlinking whatever occupies the name and trying again on
/// `EEXIST`.
fn replacing<T>(
    parent: &OwnedFd,
    leaf: &CString,
    mut create: impl FnMut() -> Result<T, Errno>,
) -> Result<T, Errno> {
    for _ in 0..REPLACE_ATTEMPTS {
        match create() {
            Ok(value) => return Ok(value),
            Err(Errno::EXIST) => remove_at(parent, leaf)?,
            Err(errno) => return Err(errno),
        }
    }
    Err(Errno::EXIST)
}

/// Removes the entry at `leaf`, whichever kind it is. An empty directory is
/// removed; a non-empty one keeps the `ENOTEMPTY` the kernel gave.
fn remove_at(parent: &OwnedFd, leaf: &CString) -> Result<(), Errno> {
    match rustix::fs::unlinkat(parent, leaf, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(Errno::ISDIR) => rustix::fs::unlinkat(parent, leaf, AtFlags::REMOVEDIR),
        Err(errno) => Err(errno),
    }
}

/// Splits a tree-relative path into its components.
///
/// A leading `/` is accepted and names the tree's own root, since the tree is a
/// root filesystem whose files name themselves that way. Empty and `.`
/// components are dropped; a `..` component, a NUL, and a path naming nothing
/// are refused with `EINVAL` — none is a path a caller composes by accident,
/// and refusing here keeps the shape of what reaches the kernel obvious.
fn components(relative: &str) -> Result<Vec<&str>, Errno> {
    if relative.contains('\0') {
        return Err(Errno::INVAL);
    }
    let mut components = Vec::new();
    for component in relative.split('/') {
        match component {
            "" | "." => continue,
            ".." => return Err(Errno::INVAL),
            _ => components.push(component),
        }
    }
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
