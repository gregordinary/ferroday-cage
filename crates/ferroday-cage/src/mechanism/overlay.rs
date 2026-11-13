//! An out-of-band probe for unprivileged overlay support.
//!
//! Rooting a cage on an overlay needs a kernel that lets an unprivileged
//! process mount `overlay` inside a user namespace (Linux 5.11). Whether that
//! holds is not a sysctl to read but a mount to attempt, so this forks a
//! throwaway child that unshares a user and mount namespace, single-identity-
//! maps it, and tries the mount — exactly the sequence the real launch runs,
//! reduced to its overlay step. The child touches no allocator or lock and
//! only issues raw syscalls before it exits, the same discipline the launch
//! stages keep (see [`child`](super::child)).
//!
//! This answers only the mount question. Whether the upper layer's filesystem
//! can record an overlay's metadata — the `user.*` xattr support tmpfs gained
//! in Linux 6.6 — is a separate, fork-free check the [`host`](crate::host)
//! module makes directly on the target filesystem.
//!
//! The probe and the launch both hand `mount(2)` an option string naming the
//! layers, and [`overlay_options`] is the one place that string is composed.

use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::io::Errno;
use rustix::mount::{self, MountFlags, MountPropagationFlags};
use rustix::thread::UnshareFlags;

use super::child::{MapDuty, MapPaths, enter_mapped_namespace};
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

/// Forks a child that attempts an unprivileged overlay mount at `merged` with
/// `options`, and reports whether it succeeded.
///
/// `merged` is an existing empty directory to mount over, and `options` the
/// preformatted `lowerdir=…,upperdir=…,workdir=…,userxattr` string. Both name
/// directories on the host, resolved by the child before it swaps nothing —
/// there is no pivot here, only the mount, undone when the child's mount
/// namespace is torn down at exit.
pub(crate) fn probe_overlay_mount(merged: &CStr, options: &CStr) -> OverlayProbe {
    // The single-identity map lines, formatted before the fork as the launch
    // formats its own.
    let (uid_line, gid_line) = crate::idmap::single_identity_lines();

    // SAFETY: `probe_child` makes only raw syscalls over the data frozen above,
    // with no allocation, no lock, no libc and no panic.
    match unsafe { sys::probe(|| probe_child(merged, options, &uid_line, &gid_line)) } {
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
/// and attempt the overlay mount. Returns the exit code the parent classifies.
///
/// Runs under the post-fork constraints of [`child`](super::child): raw
/// syscalls over frozen data, no allocation, no panic.
fn probe_child(merged: &CStr, options: &CStr, uid_line: &[u8], gid_line: &[u8]) -> i32 {
    // A user and mount namespace of the child's own under the single-identity
    // map, keeping no descriptor: the probe needs only the two paths frozen
    // above. Root inside is the caller outside, which is credential enough to
    // mount an overlay in the new namespace.
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

    match mount::mount(c"overlay", merged, c"overlay", MountFlags::empty(), options) {
        Ok(()) => EXIT_MOUNTED,
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

/// The longest data string `mount(2)` passes to a filesystem whole.
///
/// The kernel copies one page of mount data and overwrites the page's last byte
/// with a NUL, so a longer string is cut short rather than refused. A cut overlay
/// option string still mounts whenever the prefix it leaves names directories
/// that exist: a shorter work directory than the one asked for, without
/// `userxattr`. The bound is a 4 KiB page, the smallest any supported
/// architecture runs with.
const MOUNT_DATA_MAX: usize = 4095;

/// Why a layer stack cannot be written as overlay mount options.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OverlayOptionsError {
    /// A layer path holds a byte the option string cannot carry: a `,` or a
    /// NUL.
    Unrepresentable(PathBuf),
    /// The composed string, of this many bytes, is longer than `mount(2)`
    /// passes on whole.
    TooLong(usize),
}

/// Composes the mount options of an overlay over `lowers`, writing into `upper`
/// with `work` beside it: `lowerdir=…,upperdir=…,workdir=…,userxattr`.
///
/// `lowers` is base first, the order [`Overlay`](crate::Overlay) keeps.
/// `lowerdir=` is highest-precedence first, so the stack is emitted reversed.
///
/// Every layer path is escaped as overlayfs unescapes it: `\` as `\\`, and `:`
/// as `\:`. Overlayfs unescapes each path it is given, so a backslash written
/// verbatim disappears and the kernel mounts a different directory from the one
/// the caller's checks were made on, while an unescaped colon splits a lower in
/// two.
///
/// A `,` is refused rather than escaped. Overlayfs honours `\,`, but a security
/// module that reads its own options out of the same string, as SELinux and
/// Smack do, splits it at every comma first and drops the pieces it recognizes.
/// The escape is therefore not one every reader of the string respects.
pub(crate) fn overlay_options(
    lowers: &[PathBuf],
    upper: &Path,
    work: &Path,
) -> Result<CString, OverlayOptionsError> {
    let mut options = b"lowerdir=".to_vec();
    for (index, lower) in lowers.iter().rev().enumerate() {
        if index > 0 {
            options.push(b':');
        }
        push_layer(&mut options, lower)?;
    }
    options.extend_from_slice(b",upperdir=");
    push_layer(&mut options, upper)?;
    options.extend_from_slice(b",workdir=");
    push_layer(&mut options, work)?;
    options.extend_from_slice(b",userxattr");
    if options.len() > MOUNT_DATA_MAX {
        return Err(OverlayOptionsError::TooLong(options.len()));
    }
    Ok(CString::new(options).expect("a layer holding a NUL is refused above"))
}

/// Appends one layer path to an overlay option string, escaped as
/// [`overlay_options`] describes.
fn push_layer(options: &mut Vec<u8>, layer: &Path) -> Result<(), OverlayOptionsError> {
    for &byte in layer.as_os_str().as_bytes() {
        match byte {
            b',' | 0 => return Err(OverlayOptionsError::Unrepresentable(layer.to_path_buf())),
            b'\\' | b':' => options.extend_from_slice(&[b'\\', byte]),
            _ => options.push(byte),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(lowers: &[&str], upper: &str, work: &str) -> Result<String, OverlayOptionsError> {
        let lowers: Vec<PathBuf> = lowers.iter().map(PathBuf::from).collect();
        overlay_options(&lowers, Path::new(upper), Path::new(work))
            .map(|options| options.into_string().expect("the test paths are UTF-8"))
    }

    #[test]
    fn the_lower_stack_is_emitted_highest_precedence_first() {
        assert_eq!(
            options(&["/srv/base", "/srv/patches"], "/srv/up", "/srv/.up.work").unwrap(),
            "lowerdir=/srv/patches:/srv/base,upperdir=/srv/up,workdir=/srv/.up.work,userxattr",
        );
    }

    #[test]
    fn a_backslash_and_a_colon_are_escaped_in_every_layer() {
        // Overlayfs unescapes every layer it is given. A backslash written
        // verbatim is dropped, so `up\x` would mount `upx`; a colon written
        // verbatim splits a lower in two.
        assert_eq!(
            options(&[r"/srv/ba\se", "/srv/pa:tch"], r"/srv/up\x", "/srv/w:k").unwrap(),
            r"lowerdir=/srv/pa\:tch:/srv/ba\\se,upperdir=/srv/up\\x,workdir=/srv/w\:k,userxattr",
        );
    }

    #[test]
    fn a_comma_or_a_nul_in_any_layer_is_refused() {
        for (lower, upper, work, refused) in [
            ("/srv/a,b", "/srv/up", "/srv/work", "/srv/a,b"),
            ("/srv/base", "/srv/u,p", "/srv/work", "/srv/u,p"),
            ("/srv/base", "/srv/up", "/srv/w,k", "/srv/w,k"),
            ("/srv/base", "/srv/u\0p", "/srv/work", "/srv/u\0p"),
        ] {
            assert_eq!(
                options(&[lower], upper, work),
                Err(OverlayOptionsError::Unrepresentable(PathBuf::from(refused))),
            );
        }
    }

    #[test]
    fn options_longer_than_a_page_are_refused_rather_than_cut() {
        // The kernel would cut the string at the page and mount whatever the
        // prefix names. A string that just fits is passed on.
        let fixed = "lowerdir=,upperdir=/u,workdir=/w,userxattr".len();
        let fits = format!("/{}", "l".repeat(MOUNT_DATA_MAX - fixed - 1));
        assert_eq!(options(&[&fits], "/u", "/w").unwrap().len(), MOUNT_DATA_MAX);
        let over = format!("{fits}l");
        assert_eq!(
            options(&[&over], "/u", "/w"),
            Err(OverlayOptionsError::TooLong(MOUNT_DATA_MAX + 1)),
        );
        // An escape counts at its escaped length.
        let escaped = format!("/{}:", "l".repeat(MOUNT_DATA_MAX - fixed - 2));
        assert_eq!(
            options(&[&escaped], "/u", "/w"),
            Err(OverlayOptionsError::TooLong(MOUNT_DATA_MAX + 1)),
        );
    }
}
