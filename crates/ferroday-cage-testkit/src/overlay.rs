//! Overlay markers a test lays into an upper by hand.

use std::path::Path;

use crate::require;

/// Makes an overlay whiteout at `path`, a character device numbered 0:0, and
/// answers whether it did.
///
/// A kernel before Linux 5.8 refuses an unprivileged caller one, and there
/// the skip [`require::OVERLAY`] governs is reported and the answer is
/// `false`.
///
/// # Panics
///
/// Where the whiteout cannot be made for any other reason, or where
/// [`require::OVERLAY`] demands the test run.
#[track_caller]
pub fn whiteout(path: &Path) -> bool {
    use rustix::fs::{CWD, FileType, Mode, mknodat};

    match mknodat(CWD, path, FileType::CharacterDevice, Mode::empty(), 0) {
        Ok(()) => true,
        Err(rustix::io::Errno::PERM) => {
            require::OVERLAY.skip("this kernel refuses an unprivileged whiteout");
            false
        }
        Err(errno) => panic!("making a whiteout at {}: {errno}", path.display()),
    }
}

/// Whether `path` holds an overlay whiteout, a character device numbered 0:0,
/// without following a link: how a test reads what a run deleted out of an
/// upper.
///
/// # Panics
///
/// Where nothing is at `path`, or it cannot be read.
#[track_caller]
pub fn is_whiteout(path: &Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = std::fs::symlink_metadata(path)
        .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
    metadata.file_type().is_char_device() && metadata.rdev() == 0
}
