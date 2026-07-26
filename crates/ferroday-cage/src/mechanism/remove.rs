//! Map-assisted tree removal: delete a tree whose files a range-mapped
//! sandbox chowned to subordinate ids.
//!
//! A range-mapped sandbox writes real ownership, so a rootfs it built can
//! hold files the plain calling user cannot delete. From inside the same
//! map, though, those ids are the caller's own: this module forks a child
//! that unshares a user namespace, holds it at the map gate while the caller
//! applies the identity map — the same protocol the launch uses — and then
//! removes the tree as root of the mapped namespace, where `CAP_FOWNER` and
//! `CAP_DACL_OVERRIDE` cover every mapped id. No rootfs, no mounts, no
//! `execve`: the child performs the deletion itself, in the post-fork
//! discipline this module already enforces (no allocation, no locks, no
//! panic, rustix syscalls only).
//!
//! The deletion walks the tree with one open descriptor and constant
//! memory: entries are unlinked from a rescanning pass, a non-empty
//! directory is descended into, an emptied one is left by re-opening `..`
//! and removed when its parent's next pass reaches it. Symlinks are never
//! followed, descents refuse to cross them, and the walk never leaves the
//! tree it was pointed at.

use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::{self, AtFlags, Mode, OFlags, RawDir, SeekFrom};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use rustix::process::{Pid, Signal};
use rustix::runtime::{self, Fork};
use rustix::thread::UnshareFlags;

use crate::idmap::{IdMapError, IdMapper, ResolvedMap};

/// What a failed map-assisted removal was doing, for the caller's error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoveStep {
    /// Forking the removal process or speaking to it.
    Spawn,
    /// The child could not unshare its user namespace.
    Unshare,
    /// The child died or was abandoned at the map gate.
    AwaitMap,
    /// The deletion itself failed inside the mapped namespace.
    Delete,
}

impl RemoveStep {
    /// The step as launch-error prose: what the failure was doing.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            RemoveStep::Spawn => "spawning the removal process",
            RemoveStep::Unshare => "unsharing the removal namespace",
            RemoveStep::AwaitMap => "establishing the removal identity map",
            RemoveStep::Delete => "deleting the tree inside the mapped namespace",
        }
    }
}

/// A failed map-assisted removal: the step, and the errno when the failure
/// carried one.
#[derive(Debug)]
pub(crate) enum RemoveFailure {
    /// A step failed with an OS error.
    Step {
        /// What the removal was doing.
        step: RemoveStep,
        /// The raw OS error.
        errno: i32,
    },
    /// The delegate failed to apply the map; its own error is the
    /// diagnostic.
    Map(IdMapError),
}

/// The wire values of the child's result record: the step discriminants.
const WIRE_UNSHARE: u32 = 1;
const WIRE_AWAIT: u32 = 2;
const WIRE_DELETE: u32 = 3;

/// Removes `leaf` under the directory `parent`, as root of a freshly
/// mapped user namespace.
///
/// `map` is applied to the child through `mapper`, exactly as a launch
/// applies a sandbox's; the child then deletes the tree with the mapped
/// ids as its own. Both paths must be NUL-terminated; the caller resolves
/// and freezes them before the fork.
pub(crate) fn remove_tree_mapped(
    parent: &CStr,
    leaf: &CStr,
    mapper: &dyn IdMapper,
    map: &ResolvedMap,
) -> Result<(), RemoveFailure> {
    let spawn_failure = |errno: Errno| RemoveFailure::Step {
        step: RemoveStep::Spawn,
        errno: errno.raw_os_error(),
    };

    // One seqpacket pair carries the whole conversation: ready out, go
    // back, then the 8-byte result record.
    let (caller, child_end) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(spawn_failure)?;

    // SAFETY: the child branch runs `removal_child`, which performs raw
    // rustix syscalls over the frozen paths and descriptors — no
    // allocation, no locking, no panic — and never returns: every path
    // ends in `exit_group`.
    match unsafe { runtime::kernel_fork() } {
        Err(errno) => Err(spawn_failure(errno)),
        Ok(Fork::Child(_)) => {
            // The fork duplicated the caller's end of the gate into this
            // process; close it, so this child pins nothing it does not use.
            // Closing an owned descriptor is a bare `close`, which the
            // post-fork discipline permits.
            drop(caller);
            removal_child(child_end.as_fd(), parent, leaf)
        }
        Ok(Fork::ParentOf(child)) => {
            drop(child_end);
            // `drive_removal` owns the gate, so returning closes the caller's
            // end before the wait below, and it signals the child before
            // giving up on it. The wait is therefore always reachable.
            let result = drive_removal(caller, child, mapper, map);
            let _ = super::wait_for_exit(child);
            result
        }
    }
}

/// The caller's half: waits for ready, applies the map, sends go, and reads
/// the child's result record.
///
/// Takes the gate by value so that returning closes it, and signals the child
/// on every path that gives up on it. The child blocks on the gate until the
/// go byte arrives, and a caller that simply stopped writing would strand it
/// there and hang the wait that follows.
///
/// Closing the gate is not enough on its own to release it. `kernel_fork`
/// copies the whole descriptor table, so a sibling process this caller forked
/// concurrently — another removal or export child — holds its own copy of this
/// gate's caller end and keeps the peer open however promptly this one closes.
/// The signal does not depend on any other process's descriptor table.
fn drive_removal(
    gate: OwnedFd,
    child: Pid,
    mapper: &dyn IdMapper,
    map: &ResolvedMap,
) -> Result<(), RemoveFailure> {
    let io_failure = |step: RemoveStep, errno: Errno| RemoveFailure::Step {
        step,
        errno: errno.raw_os_error(),
    };

    // Ready, or the child's early failure record, or end-of-file.
    let mut record = [0u8; 8];
    let first = loop {
        match rustix::io::read(&gate, &mut record) {
            Ok(n) => break n,
            Err(Errno::INTR) => continue,
            Err(errno) => {
                let _ = rustix::process::kill_process(child, Signal::KILL);
                return Err(io_failure(RemoveStep::Spawn, errno));
            }
        }
    };
    match first {
        // The ready byte: the namespace exists and the child is blocked.
        1 => {}
        // An 8-byte record before ready is the unshare failure.
        8 => return Err(decode_record(record)),
        // End-of-file or a corrupt message: the child is gone.
        _ => {
            let _ = rustix::process::kill_process(child, Signal::KILL);
            return Err(io_failure(RemoveStep::Spawn, Errno::PROTO));
        }
    }

    let pid = child.as_raw_nonzero().get() as u32;
    if let Err(err) = mapper.apply(pid, map) {
        // The child is blocked at the gate in an unmapped namespace with
        // nothing left to do. It has touched no tree and holds no resource
        // but its own descriptors, so killing it is a clean end.
        let _ = rustix::process::kill_process(child, Signal::KILL);
        return Err(RemoveFailure::Map(err));
    }
    loop {
        match rustix::io::write(&gate, &[super::MAP_GO_BYTE]) {
            Ok(_) => break,
            Err(Errno::INTR) => continue,
            Err(errno) => {
                let _ = rustix::process::kill_process(child, Signal::KILL);
                return Err(io_failure(RemoveStep::AwaitMap, errno));
            }
        }
    }

    // The result record: all zeros is success. Past the go byte the child is
    // deleting rather than waiting, and it exits when it is done either way,
    // so a failure here needs no signal: the wait still returns.
    let mut len = 0;
    while len < record.len() {
        match rustix::io::read(&gate, &mut record[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(io_failure(RemoveStep::Delete, errno)),
        }
    }
    if len != record.len() {
        return Err(io_failure(RemoveStep::Delete, Errno::PROTO));
    }
    if record == [0u8; 8] {
        Ok(())
    } else {
        Err(decode_record(record))
    }
}

/// Decodes the child's 8-byte record: step discriminant then errno, both
/// little-endian.
fn decode_record(record: [u8; 8]) -> RemoveFailure {
    let wire = u32::from_le_bytes(record[0..4].try_into().expect("slice length is 4"));
    let errno = i32::from_le_bytes(record[4..8].try_into().expect("slice length is 4"));
    let step = match wire {
        WIRE_UNSHARE => RemoveStep::Unshare,
        WIRE_AWAIT => RemoveStep::AwaitMap,
        _ => RemoveStep::Delete,
    };
    RemoveFailure::Step { step, errno }
}

/// The child: unshare, gate, delete, report. Never returns.
fn removal_child(gate: BorrowedFd<'_>, parent: &CStr, leaf: &CStr) -> ! {
    let report = |wire: u32, errno: Errno| {
        let mut record = [0u8; 8];
        record[0..4].copy_from_slice(&wire.to_le_bytes());
        record[4..8].copy_from_slice(&errno.raw_os_error().to_le_bytes());
        let _ = rustix::io::write(gate, &record);
    };

    // A caller signal handler must never run in this constrained copy; the
    // scrub is the same one every launch performs first.
    if let Err(errno) = super::child::reset_signals() {
        report(WIRE_UNSHARE, errno);
        runtime::exit_group(127)
    }

    // The user namespace alone: the deletion works on the caller's own
    // mount view, through real paths.
    // SAFETY: the flags never include the descriptor table, and this
    // process is a freshly forked single-threaded child besides.
    if let Err(errno) = unsafe { rustix::thread::unshare_unsafe(UnshareFlags::NEWUSER) } {
        report(WIRE_UNSHARE, errno);
        runtime::exit_group(127)
    }

    // Ready; then block until the caller's delegate has written the map.
    loop {
        match rustix::io::write(gate, &[super::MAP_READY_BYTE]) {
            Ok(_) => break,
            Err(Errno::INTR) => continue,
            Err(errno) => {
                report(WIRE_AWAIT, errno);
                runtime::exit_group(127)
            }
        }
    }
    let mut byte = [0u8; 1];
    loop {
        match rustix::io::read(gate, &mut byte) {
            Ok(0) => runtime::exit_group(127),
            Ok(_) => break,
            Err(Errno::INTR) => continue,
            Err(errno) => {
                report(WIRE_AWAIT, errno);
                runtime::exit_group(127)
            }
        }
    }

    match delete_tree(parent, leaf) {
        Ok(()) => {
            let _ = rustix::io::write(gate, &[0u8; 8]);
            runtime::exit_group(0)
        }
        Err(errno) => {
            report(WIRE_DELETE, errno);
            runtime::exit_group(127)
        }
    }
}

/// Deletes `leaf` under `parent`, holding one directory descriptor and
/// constant memory.
///
/// Each pass over a directory unlinks what it can; a non-empty
/// subdirectory is descended into and the pass restarts there, and an
/// emptied directory is left through `..` — its parent's next pass removes
/// it with `AT_REMOVEDIR`. The walk therefore needs no name stack: the
/// only state is the current descriptor and the identity of the starting
/// directory, remembered by device and inode so the ascent knows where to
/// stop.
fn delete_tree(parent: &CStr, leaf: &CStr) -> Result<(), Errno> {
    let parent_fd = fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;

    // A plain entry (file or symlink) needs no walk at all. Linux reports the
    // attempt to unlink a directory as EISDIR; POSIX permits EPERM, so accept
    // both as "this is a directory".
    match fs::unlinkat(&parent_fd, leaf, AtFlags::empty()) {
        Ok(()) => return Ok(()),
        Err(Errno::ISDIR | Errno::PERM) => {}
        Err(errno) => return Err(errno),
    }

    let start = fs::openat(
        &parent_fd,
        leaf,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let start_stat = fs::fstat(&start)?;
    let mut current = start;

    'walk: loop {
        // Rescan the current directory from the top; unlinking during
        // getdents iteration is safe, but a fresh pass keeps the logic
        // simple and the state constant.
        fs::seek(&current, SeekFrom::Start(0))?;
        let mut buf = [MaybeUninit::uninit(); 2048];
        let mut entries = RawDir::new(&current, &mut buf);
        let mut removed = false;
        while let Some(entry) = entries.next() {
            let entry = entry?;
            let name = entry.file_name();
            if name == c"." || name == c".." {
                continue;
            }
            match fs::unlinkat(&current, name, AtFlags::empty()) {
                Ok(()) => {
                    removed = true;
                }
                // EISDIR on Linux, EPERM where POSIX allows it: a directory.
                Err(Errno::ISDIR | Errno::PERM) => {
                    match fs::unlinkat(&current, name, AtFlags::REMOVEDIR) {
                        Ok(()) => {
                            removed = true;
                        }
                        // Not empty: descend and restart the walk there.
                        Err(Errno::NOTEMPTY | Errno::EXIST) => {
                            let child = fs::openat(
                                &current,
                                name,
                                OFlags::RDONLY
                                    | OFlags::DIRECTORY
                                    | OFlags::NOFOLLOW
                                    | OFlags::CLOEXEC,
                                Mode::empty(),
                            )?;
                            current = child;
                            continue 'walk;
                        }
                        Err(errno) => return Err(errno),
                    }
                }
                Err(errno) => return Err(errno),
            }
        }

        if removed {
            // Something went; the directory may be empty now. Rescan.
            continue;
        }

        // An empty directory. The start is removed from its parent and the
        // walk is done; anything deeper is left through `..`, for its
        // parent's next pass to remove.
        let here = fs::fstat(&current)?;
        if here.st_dev == start_stat.st_dev && here.st_ino == start_stat.st_ino {
            fs::unlinkat(&parent_fd, leaf, AtFlags::REMOVEDIR)?;
            return Ok(());
        }
        let up = fs::openat(
            &current,
            c"..",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        current = up;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use crate::idmap::{IdRange, IdentityMap};

    use super::*;

    /// A delegate that resolves the map, forks a bystander process, and then
    /// refuses to apply.
    ///
    /// The bystander stands in for a sibling this caller forked concurrently —
    /// another removal or export child. `kernel_fork` copies the whole
    /// descriptor table, so the bystander holds its own copy of the caller's
    /// end of the removal gate and keeps the peer open no matter how promptly
    /// the caller closes its own. A caller that abandoned the removal child by
    /// closing the gate alone would therefore leave it blocked forever.
    #[derive(Debug, Default)]
    struct ForksThenRefuses {
        /// The bystander's pid, for the test to collect.
        bystander: Mutex<Option<Pid>>,
    }

    impl IdMapper for ForksThenRefuses {
        fn resolve(&self, _request: &IdentityMap) -> Result<ResolvedMap, IdMapError> {
            let uid = rustix::process::getuid().as_raw();
            let gid = rustix::process::getgid().as_raw();
            Ok(ResolvedMap::new(
                vec![IdRange {
                    inside: 0,
                    outside: uid,
                    count: 1,
                }],
                vec![IdRange {
                    inside: 0,
                    outside: gid,
                    count: 1,
                }],
            ))
        }

        fn apply(&self, _pid: u32, _map: &ResolvedMap) -> Result<(), IdMapError> {
            // SAFETY: the child branch sleeps through one rustix syscall and
            // then exits — no allocation, no locking, no panic — and never
            // returns.
            match unsafe { runtime::kernel_fork() } {
                Ok(Fork::Child(_)) => {
                    // Outlast the caller's abandonment; the test collects this
                    // process rather than waiting the sleep out.
                    let _ = rustix::thread::nanosleep(&rustix::thread::Timespec {
                        tv_sec: 300,
                        tv_nsec: 0,
                    });
                    runtime::exit_group(0)
                }
                Ok(Fork::ParentOf(pid)) => {
                    *self
                        .bystander
                        .lock()
                        .expect("the test holds no poisoned lock") = Some(pid);
                }
                Err(_) => {}
            }
            Err(IdMapError::unsatisfiable(
                "refused after forking a bystander",
            ))
        }
    }

    impl ForksThenRefuses {
        /// Collects the bystander, so the test leaves no process behind.
        fn collect(&self) {
            if let Some(pid) = *self
                .bystander
                .lock()
                .expect("the test holds no poisoned lock")
            {
                let _ = rustix::process::kill_process(pid, Signal::KILL);
                let _ = super::super::wait_for_exit(pid);
            }
        }
    }

    /// A delegate that fails to apply the map releases the removal child, even
    /// while a sibling process holds the gate open.
    ///
    /// This test hangs rather than fails if the release regresses to closing
    /// the gate and waiting for the child to notice: the bystander's inherited
    /// copy means the end-of-file never arrives.
    #[test]
    fn an_abandoned_child_is_released_while_a_sibling_holds_the_gate() {
        if let Some(blocker) = crate::host::userns_blocker() {
            // Without a user namespace the child fails before reaching the
            // gate, so there would be nothing to abandon.
            eprintln!("skipping: unprivileged user namespaces are unavailable: {blocker}");
            return;
        }

        // A real directory, so a regression in the other direction — the
        // removal proceeding without a map — has somewhere harmless to land.
        let dir = std::env::temp_dir().join(format!(
            "ferroday-cage-abandon-{}",
            rustix::process::getpid().as_raw_nonzero()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tree")).expect("the scratch tree is creatable");
        let parent = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
        let leaf = c"tree";

        let delegate = ForksThenRefuses::default();
        let map = delegate
            .resolve(&IdentityMap::Single)
            .expect("the stub resolves");
        let result = remove_tree_mapped(&parent, leaf, &delegate, &map);

        delegate.collect();
        assert!(
            matches!(result, Err(RemoveFailure::Map(_))),
            "the delegate's own error is the diagnostic: {result:?}"
        );
        assert!(dir.join("tree").is_dir(), "nothing was removed");
        std::fs::remove_dir_all(&dir).expect("the scratch tree is removable");
    }
}
