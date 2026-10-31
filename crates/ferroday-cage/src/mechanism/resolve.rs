//! Resolving a path the kernel keeps inside a tree.
//!
//! Every lookup the crate confines to a tree is an `openat2` with
//! `RESOLVE_IN_ROOT` or `RESOLVE_BENEATH`: the sandbox stage resolving a mount
//! target against the new root, the caller side asking whether a launch created
//! one, and provisioning walking a tree it does not trust. A scoped lookup has
//! one answer no other open has. When a rename or a mount anywhere on the host
//! races a `..` step of the walk, the kernel cannot prove the walk stayed
//! inside, and answers `EAGAIN`: ask again. [`openat2`] is that call with the
//! retry folded in, so no caller takes the request for a failure.
//!
//! The race is ordinary. A root ships `etc/resolv.conf ->
//! ../run/systemd/resolve/stub-resolv.conf`, and resolving it while another
//! thread renames unrelated files fails a few percent of the time on the first
//! attempt. Concurrent launches on one host are exactly that.
//!
//! # Post-fork
//!
//! The sandbox stage resolves its mount targets after the fork, so nothing here
//! allocates, locks, or panics: a bounded loop over one raw syscall.

use std::ffi::CStr;
use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::fs::{Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

/// How many times a resolution is attempted when the kernel keeps asking for
/// another.
///
/// Each attempt re-resolves from the anchor, so a genuine race is usually lost
/// once and won next. Losses come in runs only when the walk itself is slowed,
/// on a host whose processors are oversubscribed, while renames or mounts
/// elsewhere keep coming. The longest run measured, with six namespaces
/// mounting in tight loops beside a renamer, was five. Sixty-four leaves a
/// loaded host far more room than that. The bound exists because the trees
/// resolved here are not ones this crate trusts: something renaming
/// components in a loop must not be able to spin the walk forever.
const RESOLVE_ATTEMPTS: u32 = 64;

/// Opens `path` against `anchor` with `openat2`, retrying the kernel's
/// `EAGAIN` up to [`RESOLVE_ATTEMPTS`] times.
///
/// The flags are the caller's, passed through unchanged: which containment
/// flag, whether to follow a link at the leaf, and what the descriptor is for
/// are each caller's own decision. The retry is the one thing every scoped
/// lookup needs alike.
///
/// Retrying is sound for a create as much as for an open. The kernel answers
/// `EAGAIN` from the walk, before it reaches the final component, so an
/// attempt that asks again has created nothing.
///
/// An exhausted retry returns the `EAGAIN` it kept receiving. That is the
/// accurate answer, since the resolution really was raced every time, and the
/// caller reports it against whatever it was opening.
pub(crate) fn openat2(
    anchor: BorrowedFd<'_>,
    path: &CStr,
    oflags: OFlags,
    mode: Mode,
    resolve: ResolveFlags,
) -> Result<OwnedFd, Errno> {
    for _ in 0..RESOLVE_ATTEMPTS {
        // The call `clippy.toml` sends every other site here for: this is that
        // answer.
        #[expect(clippy::disallowed_methods)]
        let opened = rustix::fs::openat2(anchor, path, oflags, mode, resolve);
        match opened {
            Err(Errno::AGAIN) => continue,
            result => return result,
        }
    }
    Err(Errno::AGAIN)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::scratch::Scratch;

    /// A scoped lookup through a `..` link survives renames racing it.
    ///
    /// A thread renames an unrelated file back and forth for the whole run.
    /// Every rename bumps the sequence count a scoped walk checks at a `..`
    /// step, so a bare `openat2` on this path answers `EAGAIN` a few percent
    /// of the time. Through the retry, none of those reaches the caller.
    #[test]
    fn a_scoped_lookup_retries_a_raced_walk() {
        let scratch = Scratch::for_test("resolve", "eagain");
        let root = scratch.join("root");
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("usr/lib/os-release"), b"").unwrap();
        std::os::unix::fs::symlink("../usr/lib/os-release", root.join("etc/os-release")).unwrap();
        let churn = scratch.join("churn");
        std::fs::create_dir(&churn).unwrap();
        std::fs::write(churn.join("a"), b"").unwrap();

        let anchor = rustix::fs::open(
            &root,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let renamer = {
            let stop = Arc::clone(&stop);
            let (a, b) = (churn.join("a"), churn.join("b"));
            std::thread::spawn(move || {
                let mut flip = false;
                while !stop.load(Ordering::Relaxed) {
                    let (from, to) = if flip { (&b, &a) } else { (&a, &b) };
                    let _ = std::fs::rename(from, to);
                    flip = !flip;
                }
            })
        };

        let mut raced = 0;
        for _ in 0..200_000 {
            match openat2(
                anchor.as_fd(),
                c"etc/os-release",
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::IN_ROOT,
            ) {
                Ok(_) => {}
                Err(Errno::AGAIN) => raced += 1,
                Err(errno) => panic!("the lookup failed outright: {errno}"),
            }
        }
        stop.store(true, Ordering::Relaxed);
        renamer.join().unwrap();
        assert_eq!(raced, 0, "{raced} lookups surfaced the kernel's EAGAIN");
    }
}
