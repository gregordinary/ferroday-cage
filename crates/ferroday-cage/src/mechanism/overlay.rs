//! Mounting an overlay from layers opened by descriptor, and an out-of-band
//! probe for unprivileged overlay support.
//!
//! [`mount_overlay`] is the one place an overlay is mounted. The launch mounts
//! an overlay-rooted cage's root with it, and the probe mounts a throwaway
//! overlay with it, so the probe tests the sequence the launch runs.
//!
//! Every layer is opened as a descriptor, without following a link, and the
//! kernel is handed the descriptor rather than the path. The build froze each
//! layer as a canonical path, which holds no link, so a link met at launch was
//! put in place since, by whatever can write a directory the path runs
//! through. Followed, it would mount whatever it names as a lower, or land the
//! sandbox's writes, or the overlay's work, wherever it points. The open
//! refuses it with `ELOOP` instead, and nothing resolves the path again once it
//! is open.
//!
//! Rooting a cage on an overlay needs a kernel that lets an unprivileged
//! process mount `overlay` inside a user namespace (Linux 5.11). Whether that
//! holds is not a sysctl to read but a mount to attempt, so the probe forks a
//! throwaway child that unshares a user and mount namespace, single-identity-
//! maps it, and mounts. The child touches no allocator or lock and only issues
//! raw syscalls before it exits, the same discipline the launch stages keep
//! (see [`child`](super::child)).
//!
//! The probe answers only the mount question. Whether the upper layer's
//! filesystem can record an overlay's metadata — the `user.*` xattr support
//! tmpfs gained in Linux 6.6 — is a separate, fork-free check the
//! [`host`](crate::host) module makes directly on the target filesystem.

use std::ffi::CStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::{self, Mode, OFlags};
use rustix::io::Errno;
use rustix::mount::{self, MountFlags, MountPropagationFlags, UnmountFlags};
use rustix::thread::UnshareFlags;

use super::child::{
    MapDuty, MapPaths, StackBuf, attach_over_root, empty_tmpfs, enter_mapped_namespace, fd_path,
    open_frozen,
};
use super::sys;

/// The outcome of the overlay mount probe.
pub(crate) enum OverlayProbe {
    /// An unprivileged overlay mounted: the host supports overlay-rooted cages.
    Mounted,
    /// The kernel refused the overlay mount.
    MountFailed,
    /// The probe could not set up a user namespace to test in, so it says
    /// nothing about overlay support — the caller defers to the user-namespace
    /// diagnosis instead.
    Inconclusive,
}

/// The child exited having mounted the overlay.
const EXIT_MOUNTED: i32 = 0;
/// The child reached the mount and it was refused.
const EXIT_MOUNT_FAILED: i32 = 1;
/// The child could not establish the namespace to test in.
const EXIT_SETUP_FAILED: i32 = 2;

/// Forks a child that mounts an unprivileged overlay of `lower`, writing into
/// `upper` with `work` beside it, and reports whether it succeeded.
///
/// Each is the canonical path of an existing directory on the host, opened by
/// the child as the launch opens a layer. The mount is never attached, and goes
/// with the child.
pub(crate) fn probe_overlay_mount(lower: &CStr, upper: &CStr, work: &CStr) -> OverlayProbe {
    // The single-identity map lines, formatted before the fork as the launch
    // formats its own.
    let (uid_line, gid_line) = crate::idmap::single_identity_lines();

    // SAFETY: `probe_child` makes only raw syscalls over the data frozen above,
    // with no allocation, no lock, no libc and no panic.
    match unsafe { sys::probe(|| probe_child(lower, upper, work, &uid_line, &gid_line)) } {
        Ok(code) => classify(code),
        Err(_) => OverlayProbe::Inconclusive,
    }
}

/// Maps the child's exit code, `None` where a signal ended it, onto the probe
/// outcome.
fn classify(code: Option<i32>) -> OverlayProbe {
    match code {
        Some(EXIT_MOUNTED) => OverlayProbe::Mounted,
        Some(EXIT_MOUNT_FAILED) => OverlayProbe::MountFailed,
        // EXIT_SETUP_FAILED, a signal, or anything else: the test never reached
        // a verdict on the mount.
        _ => OverlayProbe::Inconclusive,
    }
}

/// The probe child: unshare a user and mount namespace, single-identity-map it,
/// and mount the overlay. Returns the exit code the parent classifies.
///
/// Runs under the post-fork constraints of [`child`](super::child): raw
/// syscalls over frozen data, no allocation, no panic.
fn probe_child(lower: &CStr, upper: &CStr, work: &CStr, uid_line: &[u8], gid_line: &[u8]) -> i32 {
    // A user and mount namespace of the child's own under the single-identity
    // map, keeping no descriptor: the probe needs only the paths frozen above.
    // Root inside is the caller outside, which is credential enough to mount an
    // overlay in the new namespace.
    let duty = MapDuty::Write {
        paths: MapPaths::SELF,
        uid_line,
        gid_line,
    };
    if enter_mapped_namespace(&[], UnshareFlags::NEWNS, duty, None).is_err() {
        return EXIT_SETUP_FAILED;
    }

    // Privatize the mount tree, as the real setup does, so the mount is
    // contained and cannot propagate.
    if mount::mount_change(
        c"/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .is_err()
    {
        return EXIT_SETUP_FAILED;
    }

    let Ok(lower) = open_frozen(lower, OFlags::DIRECTORY) else {
        return EXIT_SETUP_FAILED;
    };
    let layers = OverlayLayers {
        base: lower.as_fd(),
        stacked: &[],
        upper,
        work,
    };
    match mount_overlay(&layers) {
        Ok(_) => EXIT_MOUNTED,
        Err(_) => EXIT_MOUNT_FAILED,
    }
}

/// Whether an errno from a `user.*` xattr write means the filesystem does not
/// support that namespace, the condition that distinguishes an overlay-capable
/// upper from one (a pre-6.6 tmpfs) that cannot record overlay metadata.
///
/// Lives here beside the mount probe so the two halves of the overlay
/// preflight share one crate home; the caller in [`host`](crate::host) applies
/// it to a direct `setxattr` on the target filesystem.
pub(crate) fn xattr_unsupported(errno: Errno) -> bool {
    errno == Errno::NOTSUP
}

/// The layers of one overlay, as [`mount_overlay`] takes them.
pub(crate) struct OverlayLayers<'a> {
    /// The lowest lower, already open: an overlay-rooted cage's base, which
    /// the launch also mounts the overlay over.
    pub(crate) base: BorrowedFd<'a>,
    /// The lowers stacked over the base, lowest first: the order
    /// [`Overlay`](crate::Overlay) keeps.
    pub(crate) stacked: &'a [std::ffi::CString],
    /// The upper, where the overlay's writes land.
    pub(crate) upper: &'a CStr,
    /// The work directory beside the upper.
    pub(crate) work: &'a CStr,
}

/// The most lowers an overlay may stack, its base included.
///
/// Before Linux 6.13 the layers reach the kernel as `/proc/self/fd` paths in
/// one option string (see [`mount_overlay`]), which `mount(2)` passes on whole
/// only up to [`MOUNT_DATA_MAX`] bytes. Each layer's path is at most
/// [`FD_PATH_MAX`] bytes, whatever descriptor it names, so this many lowers
/// always fit. The kernel's own ceiling, 500 lowers, is above it.
pub(crate) const MAX_LOWERS: usize =
    (MOUNT_DATA_MAX - OPTIONS_FIXED - 2 * FD_PATH_MAX + 1) / (FD_PATH_MAX + 1);

// The longest string the fallback can compose fits, and one more lower would
// not: every lower, the upper and the work directory named by the longest
// descriptor path, with a `:` between each lower.
const _: () = {
    let longest = OPTIONS_FIXED + (MAX_LOWERS + 2) * FD_PATH_MAX + (MAX_LOWERS - 1);
    assert!(longest <= MOUNT_DATA_MAX);
    assert!(longest + FD_PATH_MAX + 1 > MOUNT_DATA_MAX);
    assert!(MAX_LOWERS <= 500, "the kernel's own ceiling");
};

/// The longest data string `mount(2)` passes to a filesystem whole.
///
/// The kernel copies one page of mount data and overwrites the page's last byte
/// with a NUL, so a longer string is cut short rather than refused. The bound
/// is a 4 KiB page, the smallest any supported architecture runs with.
const MOUNT_DATA_MAX: usize = 4095;

/// The longest `/proc/self/fd` path: a descriptor of ten decimal digits.
const FD_PATH_MAX: usize = "/proc/self/fd/".len() + 10;

/// The bytes of the option string that name no layer.
const OPTIONS_FIXED: usize = "lowerdir=,upperdir=,workdir=,userxattr".len();

/// Mounts an overlay of `layers` and returns a descriptor of it, attached
/// nowhere.
///
/// Every layer but the base, which the caller opened, is opened here with
/// [`open_frozen`], and handed to the kernel as that descriptor, so the
/// overlay is made of exactly the directories opened. Linux 6.13 takes a layer
/// as a descriptor through `fsconfig`, which is how it is mounted where the
/// kernel can. An earlier kernel refuses a descriptor for a layer with
/// `EINVAL`, whether its overlay predates the mount API, knows no `lowerdir+`
/// (before 6.8), or takes one only as a string. There the layers
/// are named instead by the `/proc/self/fd` path of each descriptor, a magic
/// link the overlay's own lookup follows to the directory the descriptor holds
/// open, whatever has been renamed or replaced at its path since.
///
/// `nosuid` either way. An overlay-rooted cage's base ships set-user-ID
/// binaries; see the launch stage's `nosuid_root`.
pub(crate) fn mount_overlay(layers: &OverlayLayers<'_>) -> Result<OwnedFd, Errno> {
    match mount_by_descriptor(layers) {
        Err(Handoff::Unsupported) => mount_by_fd_path(layers),
        Err(Handoff::Failed(errno)) => Err(errno),
        Ok(mount) => Ok(mount),
    }
}

/// Why [`mount_by_descriptor`] did not mount.
enum Handoff {
    /// The kernel takes no layer as a descriptor.
    Unsupported,
    /// The mount failed.
    Failed(Errno),
}

/// Mounts the overlay through `fsconfig`, each layer as a descriptor.
///
/// The first layer handed over decides whether the kernel takes descriptors at
/// all: its `EINVAL` is [`Handoff::Unsupported`]. A later refusal is the
/// mount's own failure. A kernel that takes descriptors and refuses the first
/// layer itself with `EINVAL` refuses it again through the fallback, so the
/// launch fails either way.
fn mount_by_descriptor(layers: &OverlayLayers<'_>) -> Result<OwnedFd, Handoff> {
    let context =
        mount::fsopen(c"overlay", mount::FsOpenFlags::FSOPEN_CLOEXEC).map_err(Handoff::Failed)?;
    let mut first = true;
    let mut hand = |key: &CStr, layer: BorrowedFd<'_>| {
        let handed = mount::fsconfig_set_fd(&context, key, layer);
        match handed {
            Err(Errno::INVAL) if first => Err(Handoff::Unsupported),
            handed => {
                first = false;
                handed.map_err(Handoff::Failed)
            }
        }
    };
    // `lowerdir+` appends a lower beneath those already given, so the stack is
    // handed over highest first and the base last. Each descriptor goes once
    // it is handed over: the mount context keeps the layer itself.
    for lower in layers.stacked.iter().rev() {
        let lower = open_frozen(lower, OFlags::DIRECTORY).map_err(Handoff::Failed)?;
        hand(c"lowerdir+", lower.as_fd())?;
    }
    hand(c"lowerdir+", layers.base)?;
    let upper = open_frozen(layers.upper, OFlags::DIRECTORY).map_err(Handoff::Failed)?;
    hand(c"upperdir", upper.as_fd())?;
    let work = open_frozen(layers.work, OFlags::DIRECTORY).map_err(Handoff::Failed)?;
    hand(c"workdir", work.as_fd())?;
    let configured = mount::fsconfig_set_flag(&context, c"userxattr")
        .and_then(|()| mount::fsconfig_set_string(&context, c"source", c"overlay"))
        .and_then(|()| mount::fsconfig_create(&context))
        .and_then(|()| {
            mount::fsmount(
                &context,
                mount::FsMountFlags::FSMOUNT_CLOEXEC,
                mount::MountAttrFlags::MOUNT_ATTR_NOSUID,
            )
        });
    configured.map_err(Handoff::Failed)
}

/// The directory, in a tmpfs of the sandbox's own, that [`mount_by_fd_path`]
/// mounts an overlay on before it clones it.
const OVERLAY_MOUNT_POINT: &CStr = c"overlay";

/// The option string [`mount_by_fd_path`] composes: [`MOUNT_DATA_MAX`] bytes
/// and the terminating NUL.
type Options = StackBuf<{ MOUNT_DATA_MAX + 1 }>;

/// Mounts the overlay through `mount(2)`, each layer named by the
/// `/proc/self/fd` path of a descriptor of it.
///
/// Every descriptor is held until the mount is made, in a slot for each of the
/// [`MAX_LOWERS`] lowers the build allows, since nothing here may allocate. A
/// stack the slots or the option string cannot hold whole fails with `E2BIG`
/// rather than mounting what part of it fits.
///
/// `mount(2)` mounts only onto a path. The path here is a directory in a tmpfs
/// of the sandbox's own, attached for the moment on top of `/`, where no lookup
/// crosses it (see the launch stage's `mount_empty_root`), so nothing outside
/// this process can reach it or replace it. The overlay is cloned from there,
/// the clone keeping its flags, and the tmpfs is detached again with the
/// original in it.
fn mount_by_fd_path(layers: &OverlayLayers<'_>) -> Result<OwnedFd, Errno> {
    let mut held: [Option<OwnedFd>; MAX_LOWERS] = [const { None }; MAX_LOWERS];
    // The base takes no slot, so a stack the build allows has one to spare.
    if layers.stacked.len() >= held.len() {
        return Err(Errno::TOOBIG);
    }
    let mut options = Options::new();
    options.push(b"lowerdir=");
    for (lower, slot) in layers.stacked.iter().rev().zip(held.iter_mut()) {
        let lower = open_frozen(lower, OFlags::DIRECTORY)?;
        options.push_fd_path(lower.as_fd());
        options.push(b":");
        *slot = Some(lower);
    }
    options.push_fd_path(layers.base);
    let upper = open_frozen(layers.upper, OFlags::DIRECTORY)?;
    options.push(b",upperdir=");
    options.push_fd_path(upper.as_fd());
    let work = open_frozen(layers.work, OFlags::DIRECTORY)?;
    options.push(b",workdir=");
    options.push_fd_path(work.as_fd());
    options.push(b",userxattr");
    if options.dropped() {
        return Err(Errno::TOOBIG);
    }

    let scratch = empty_tmpfs(
        mount::MountAttrFlags::MOUNT_ATTR_NOSUID
            | mount::MountAttrFlags::MOUNT_ATTR_NODEV
            | mount::MountAttrFlags::MOUNT_ATTR_NOEXEC,
    )?;
    fs::mkdirat(&scratch, OVERLAY_MOUNT_POINT, Mode::from_raw_mode(0o700))?;
    attach_over_root(scratch.as_fd())?;
    let clone = fs::openat(
        &scratch,
        OVERLAY_MOUNT_POINT,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .and_then(|at| {
        mount::mount(
            c"overlay",
            fd_path(&at).as_cstr(),
            c"overlay",
            MountFlags::NOSUID,
            options.as_cstr(),
        )
    })
    .and_then(|()| {
        mount::open_tree(
            &scratch,
            OVERLAY_MOUNT_POINT,
            mount::OpenTreeFlags::OPEN_TREE_CLONE | mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
        )
    });
    let detached = mount::unmount(fd_path(&scratch).as_cstr(), UnmountFlags::DETACH);
    let clone = clone?;
    detached?;
    Ok(clone)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::*;
    use crate::scratch::Scratch;

    /// How a probe mounts the overlay it is given.
    #[derive(Clone, Copy)]
    enum Mechanism {
        /// [`mount_overlay`], as the launch does.
        Either,
        /// [`mount_by_fd_path`], the fallback, whatever the kernel takes.
        FdPath,
    }

    /// What a probe puts at `layers` once it has opened the base.
    #[derive(Clone, Copy)]
    enum Replacement {
        /// A link to `elsewhere`.
        Link,
        /// `elsewhere` itself, renamed into place.
        Directory,
    }

    /// A tree whose base one probe opens, then replaces, then mounts an
    /// overlay over.
    struct Swap {
        scratch: Scratch,
    }

    impl Swap {
        /// Lays out `layers/{base,stacked,upper,work}` and an `elsewhere` tree
        /// of the same names. Each lower holds a file naming its tree: `which`
        /// in the base, `stacked` in the stacked lower.
        fn new(name: &str) -> Swap {
            let scratch = Scratch::new(name);
            for tree in ["layers", "elsewhere"] {
                for layer in ["base", "stacked", "upper", "work"] {
                    std::fs::create_dir_all(scratch.join(tree).join(layer)).unwrap();
                }
                std::fs::write(scratch.join(tree).join("base/which"), tree).unwrap();
                std::fs::write(scratch.join(tree).join("stacked/stacked"), tree).unwrap();
            }
            Swap { scratch }
        }

        fn path(&self, relative: &str) -> CString {
            let canonical = std::fs::canonicalize(&*self.scratch).unwrap();
            CString::new(canonical.join(relative).as_os_str().as_bytes()).unwrap()
        }

        /// Forks a probe that opens the base, moves `layers` aside and puts
        /// `replacement` in its place, mounts the overlay through `mechanism`,
        /// reads both lowers' files through it, and writes `written` into it.
        /// The exit code is `0` where the base reads `layers` and the stacked
        /// lower `stacked`, and says what differed otherwise.
        fn run(
            &self,
            mechanism: Mechanism,
            replacement: Replacement,
            stacked_reads: &'static [u8],
        ) -> Option<i32> {
            let base = self.path("layers/base");
            let stacked = [self.path("layers/stacked")];
            let (upper, work) = (self.path("layers/upper"), self.path("layers/work"));
            let (layers, moved, elsewhere) = (
                self.path("layers"),
                self.path("layers.moved"),
                self.path("elsewhere"),
            );
            let (uid_line, gid_line) = crate::idmap::single_identity_lines();
            let probe = || {
                let duty = MapDuty::Write {
                    paths: MapPaths::SELF,
                    uid_line: &uid_line,
                    gid_line: &gid_line,
                };
                if enter_mapped_namespace(&[], UnshareFlags::NEWNS, duty, None).is_err()
                    || mount::mount_change(
                        c"/",
                        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
                    )
                    .is_err()
                {
                    return 10;
                }
                let Ok(base) = open_frozen(&base, OFlags::DIRECTORY) else {
                    return 11;
                };
                let replaced = fs::rename(&layers, &moved).and_then(|()| match replacement {
                    Replacement::Link => fs::symlink(&elsewhere, &layers),
                    Replacement::Directory => fs::rename(&elsewhere, &layers),
                });
                if replaced.is_err() {
                    return 12;
                }
                let layers = OverlayLayers {
                    base: base.as_fd(),
                    stacked: &stacked,
                    upper: &upper,
                    work: &work,
                };
                let mounted = match mechanism {
                    Mechanism::Either => mount_overlay(&layers),
                    Mechanism::FdPath => mount_by_fd_path(&layers),
                };
                match mounted {
                    Ok(merged) => read_and_write(merged.as_fd(), stacked_reads),
                    Err(errno) if errno == Errno::LOOP => 20,
                    Err(_) => 21,
                }
            };
            // SAFETY: the probe makes raw syscalls over paths formatted before
            // the fork, with no allocation, no lock and no panic.
            unsafe { sys::probe(probe) }.ok().flatten()
        }
    }

    /// Reads the base's `which` and the stacked lower's `stacked` through the
    /// overlay `merged`, and writes `written` into it. `0` where the base reads
    /// `layers` and the stacked lower `stacked_reads`.
    fn read_and_write(merged: BorrowedFd<'_>, stacked_reads: &[u8]) -> i32 {
        for (file, expected, code) in [
            (c"which", &b"layers"[..], 30),
            (c"stacked", stacked_reads, 31),
        ] {
            let mut content = [0u8; 16];
            let read = fs::openat(
                merged,
                file,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .and_then(|fd| rustix::io::read(&fd, &mut content));
            match read {
                Ok(len) if &content[..len] == expected => {}
                Ok(_) => return code,
                Err(_) => return code + 10,
            }
        }
        match fs::openat(
            merged,
            c"written",
            OFlags::WRONLY | OFlags::CREATE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        ) {
            Ok(_) => 0,
            Err(_) => 50,
        }
    }

    fn overlay_available(scratch: &Path) -> bool {
        match crate::host::overlay_blocker(scratch) {
            None => true,
            Some(blocker) => {
                ferroday_cage_testkit::require::OVERLAY.skip(format!(
                    "an unprivileged overlay is unavailable here: {blocker}"
                ));
                false
            }
        }
    }

    #[test]
    fn a_layer_reached_through_a_link_is_refused() {
        // The build froze each layer link-free, so a link at a layer's path,
        // or at a directory above it, was put there since. The mount fails
        // rather than take what the link names, and nothing is written.
        for mechanism in [Mechanism::Either, Mechanism::FdPath] {
            let swap = Swap::new("overlay-link");
            if !overlay_available(&swap.scratch) {
                return;
            }
            assert_eq!(swap.run(mechanism, Replacement::Link, b""), Some(20));
            for tree in ["layers.moved", "elsewhere"] {
                assert!(!swap.scratch.join(tree).join("upper/written").exists());
            }
        }
    }

    #[test]
    fn an_open_layer_is_mounted_whatever_has_taken_its_path_since() {
        // The base is opened before a directory replaces the tree it is in,
        // and the overlay is made of the directory opened, through either
        // mechanism. The layers opened after the replacement are those now at
        // their paths, and the sandbox's write lands in that upper.
        for mechanism in [Mechanism::Either, Mechanism::FdPath] {
            let swap = Swap::new("overlay-open");
            if !overlay_available(&swap.scratch) {
                return;
            }
            assert_eq!(
                swap.run(mechanism, Replacement::Directory, b"elsewhere"),
                Some(0)
            );
            assert!(swap.scratch.join("layers/upper/written").exists());
            assert!(!swap.scratch.join("layers.moved/upper/written").exists());
        }
    }
}
