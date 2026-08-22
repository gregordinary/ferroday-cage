//! Map-assisted tree removal: delete a tree whose files a range-mapped
//! sandbox chowned to subordinate ids.
//!
//! A range-mapped sandbox writes real ownership, so a rootfs it built can
//! hold files the plain calling user cannot delete. From inside the same
//! map, though, those ids are the caller's own: this module forks a child
//! that unshares a user namespace, establishes the identity map — the same
//! protocol the launch uses, the child writing a single map itself and
//! holding at the gate for a range map the caller applies — and then removes
//! the tree as root of the mapped namespace, where `CAP_FOWNER` and
//! `CAP_DACL_OVERRIDE` cover every mapped id. Those capabilities are why even
//! a single-identity map is worth re-entering: the ids are the caller's own
//! either way, but a directory whose mode denies the search or write the
//! deletion needs yields to them. No rootfs, no mounts, no `execve`: the
//! child performs the deletion itself, in the post-fork discipline this
//! module already enforces (no allocation, no locks, no panic, rustix
//! syscalls only).
//!
//! The deletion walks the tree with one open descriptor and constant
//! memory: entries are unlinked from a rescanning pass, a non-empty
//! directory is descended into, an emptied one is left by re-opening `..`
//! and removed when its parent's next pass reaches it. Symlinks are never
//! followed and descents refuse to cross them, so nothing the tree itself
//! holds can redirect the walk out of it.
//!
//! The ascent is the one step that does not open a name the pass just read: it
//! re-opens `..` and stops at the directory the caller pointed it at, identified
//! by device and inode and re-checked at every level. That bounds it against the
//! tree's own contents and against nothing else. A concurrent writer that
//! renames a directory the walk is currently inside to somewhere outside the
//! tree breaks the chain of `..` leading back to the start, and the ascent then
//! climbs past where it should have stopped — as root of the mapped namespace,
//! unlinking as it goes. The copy-in side carries the same exposure to a
//! concurrent writer, and one bound covers both: the tree is one the caller owns
//! and is finished with.

use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{self, AtFlags, Mode, OFlags, RawDir, SeekFrom};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use rustix::process::Pid;
use rustix::runtime::{self, Fork};

use super::ChildMap;
use super::child::{MapDuty, MapFailure};
use crate::idmap::IdMapError;
use crate::wire::wire_enum;

wire_enum! {
    /// What a failed map-assisted removal was doing, for the caller's error.
    ///
    /// The explicit discriminants are the result record's wire encoding, which
    /// both ends of a single build write and read; zero is not among them,
    /// since the all-zero record is the success record. They are not a stable
    /// protocol and they are not declaration order: a step added in a later
    /// release takes the next free value rather than renumbering the ones it
    /// was declared among.
    pub(crate) enum RemoveStep {
        map {
            ResetSignals = 1 => "resetting the removal process's signal dispositions",
            SweepFds = 2 => "closing the removal process's inherited descriptors",
            Unshare = 3 => "unsharing the removal namespace",
            DenySetgroups = 7 => "denying setgroups in the removal namespace",
            WriteGidMap = 8 => "writing the removal gid map",
            WriteUidMap = 9 => "writing the removal uid map",
            AwaitMap = 4 => "establishing the removal identity map",
        }
        /// Forking the removal process or speaking to it. Reported by the
        /// caller alone: the child has no channel to report it on.
        Spawn = 6 => "spawning the removal process",
        /// The deletion itself failed inside the mapped namespace.
        Delete = 5 => "deleting the tree inside the mapped namespace",
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
    /// The child's result record named no step this build carries, so the
    /// record is malformed.
    Malformed,
}

/// Removes `leaf` under the directory `parent`, as root of a freshly
/// mapped user namespace.
///
/// The map is established exactly as a launch establishes a sandbox's — the
/// child writes a single-identity map itself, and a range map is applied from
/// outside while it holds at the gate — and the child then deletes the tree
/// with the mapped ids as its own. Both paths must be NUL-terminated; the
/// caller resolves and freezes them before the fork.
pub(crate) fn remove_tree_mapped(
    parent: &CStr,
    leaf: &CStr,
    map: ChildMap<'_>,
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
            removal_child(child_end.as_fd(), parent, leaf, map.duty())
        }
        Ok(Fork::ParentOf(child)) => {
            drop(child_end);
            // `drive_removal` owns the gate, so returning closes the caller's
            // end before the wait below, and it signals the child before
            // giving up on it. The wait is therefore always reachable — and it
            // is this child's only one, on every path through `drive_removal`,
            // which is why the one that gives up kills without reaping.
            let result = drive_removal(caller, child, &map);
            let _ = super::wait_for_exit(child);
            result
        }
    }
}

/// The caller's half: for a delegated map, waits for ready, applies the map
/// and sends go; then reads the child's result record either way.
///
/// A child that writes its own single-identity map needs nothing from this
/// side and never signals ready, so there is no handshake to drive: the gate
/// carries the result record alone.
///
/// Takes the gate by value so that returning closes it. The child blocks on the
/// gate until the go byte arrives, and a caller that simply stopped writing
/// would strand it there and hang the wait that follows — which is why a caller
/// that gives up on the child kills it rather than closing the gate, as
/// [`abandon_gated_child`](super::abandon_gated_child) explains.
///
/// The result record that follows the go byte is this removal's own: past the
/// gate the child is deleting rather than waiting, and it exits when it is done
/// either way, so a failure reading it needs no signal — the wait still
/// returns.
fn drive_removal(gate: OwnedFd, child: Pid, map: &ChildMap<'_>) -> Result<(), RemoveFailure> {
    let io_failure = |step: RemoveStep, errno: Errno| RemoveFailure::Step {
        step,
        errno: errno.raw_os_error(),
    };

    if let ChildMap::Delegated { mapper, map } = map {
        let failure = match super::drive_map_gate(gate.as_fd(), child, *mapper, map) {
            Ok(super::Gated::Released) => None,
            // A record before ready is the failure the child hit on the way to
            // the gate: it names the step it reached, and no kill is owed to a
            // child that has already exited reporting it.
            Ok(super::Gated::EarlyRecord(record)) => return Err(decode_record(record)),
            Ok(super::Gated::ChildLost) => Some(io_failure(RemoveStep::Spawn, Errno::PROTO)),
            Err(super::GateFailure::Io(errno)) => Some(io_failure(RemoveStep::Spawn, errno)),
            Err(super::GateFailure::Map(err)) => Some(RemoveFailure::Map(err)),
        };
        if let Some(failure) = failure {
            // Killed but not reaped: the caller waits on this child whatever
            // this function returns, and that wait is its one reap. Collecting
            // the status here as well would leave the caller's wait blocking on
            // a pid the kernel is free to have given to something else.
            super::kill_gated_child(child);
            return Err(failure);
        }
    }

    let mut record = [0u8; super::RECORD_LEN];
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
    if record == [0u8; super::RECORD_LEN] {
        Ok(())
    } else {
        Err(decode_record(record))
    }
}

/// Decodes the child's 8-byte record: step discriminant then errno, both
/// little-endian.
fn decode_record(record: [u8; super::RECORD_LEN]) -> RemoveFailure {
    let wire = u32::from_le_bytes(record[0..4].try_into().expect("slice length is 4"));
    let errno = i32::from_le_bytes(record[4..8].try_into().expect("slice length is 4"));
    match RemoveStep::from_wire(wire) {
        Some(step) => RemoveFailure::Step { step, errno },
        None => RemoveFailure::Malformed,
    }
}

/// The child: unshare, map, delete, report. Never returns.
fn removal_child(gate: BorrowedFd<'_>, parent: &CStr, leaf: &CStr, duty: MapDuty<'_>) -> ! {
    let report = |wire: u32, errno: Errno| {
        let mut record = [0u8; 8];
        record[0..4].copy_from_slice(&wire.to_le_bytes());
        record[4..8].copy_from_slice(&errno.raw_os_error().to_le_bytes());
        let _ = rustix::io::write(gate, &record);
    };

    // The gate is kept: the outcome record travels back on it.
    if let Err(failure) =
        super::child::enter_mapped_namespace(&[gate.as_raw_fd()], duty, Some(gate))
    {
        match failure {
            // The caller left without applying the map; its own error is the
            // diagnostic, and the gate a report would travel on is closed.
            MapFailure::Abandoned => runtime::exit_group(127),
            MapFailure::Step(step, errno) => {
                report(RemoveStep::from(step).wire(), errno);
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
            report(RemoveStep::Delete.wire(), errno);
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
    let refused = match fs::unlinkat(&parent_fd, leaf, AtFlags::empty()) {
        Ok(()) => return Ok(()),
        Err(errno @ (Errno::ISDIR | Errno::PERM)) => errno,
        Err(errno) => return Err(errno),
    };

    // EPERM is only a guess at "directory": an immutable file is refused the
    // same way. Where the open proves it was not one, the first refusal is the
    // honest diagnostic, not the ENOTDIR that disproved the guess.
    let start = fs::openat(
        &parent_fd,
        leaf,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| {
        if errno == Errno::NOTDIR {
            refused
        } else {
            errno
        }
    })?;
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
                Err(refused @ (Errno::ISDIR | Errno::PERM)) => {
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
                        // Not a directory after all, so the EPERM that
                        // suggested one — an immutable file, say — is the
                        // failure worth reporting.
                        Err(Errno::NOTDIR) => return Err(refused),
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

    use crate::idmap::{IdMapper, IdRange, IdentityMap, ResolvedMap};

    use super::*;
    use crate::scratch::Scratch;

    /// Every step decodes back to itself, and every step names itself in prose.
    ///
    /// The round trip is structural now — the decoder's match arms are the same
    /// literals the variants are declared with, so a value used twice is a
    /// duplicate discriminant and a duplicate pattern, both of which the
    /// compiler refuses. What this still checks is that the list of steps and
    /// the encoding agree about which values exist, and that no step was left
    /// without a description.
    #[test]
    fn remove_step_wire_round_trip() {
        for &step in RemoveStep::ALL {
            assert_eq!(RemoveStep::from_wire(step.wire()), Some(step));
            assert!(!step.describe().is_empty(), "{step:?} describes itself");
        }
    }

    /// Zero is the success record, so no step may claim it; nothing past the
    /// last step is a step either.
    #[test]
    fn unknown_wire_values_are_rejected() {
        assert_eq!(RemoveStep::from_wire(0), None);
        assert_eq!(RemoveStep::from_wire(RemoveStep::past_the_last()), None);
        assert_eq!(RemoveStep::from_wire(u32::MAX), None);
        assert!(matches!(
            decode_record([0xFFu8; 8]),
            RemoveFailure::Malformed
        ));
    }

    /// A delegate that resolves the map, forks a bystander process, and then
    /// refuses to apply.
    ///
    /// The bystander stands in for any process this caller forked concurrently
    /// — one of the library's own children before it has swept, or one the
    /// consumer forked and that never sweeps at all. `kernel_fork` copies the
    /// whole descriptor table, so the bystander holds its own copy of the
    /// caller's end of the removal gate and keeps the peer open no matter how
    /// promptly the caller closes its own. A caller that abandoned the removal
    /// child by closing the gate alone would therefore leave it blocked for as
    /// long as the bystander lives.
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
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
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
        let dir = Scratch::new("abandon");
        std::fs::create_dir_all(dir.join("tree")).expect("the scratch tree is creatable");
        let parent = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
        let leaf = c"tree";

        let delegate = ForksThenRefuses::default();
        let map = delegate
            .resolve(&IdentityMap::Single)
            .expect("the stub resolves");
        let result = remove_tree_mapped(
            &parent,
            leaf,
            ChildMap::Delegated {
                mapper: &delegate,
                map: &map,
            },
        );

        delegate.collect();
        assert!(
            matches!(result, Err(RemoveFailure::Map(_))),
            "the delegate's own error is the diagnostic: {result:?}"
        );
        assert!(dir.join("tree").is_dir(), "nothing was removed");
        std::fs::remove_dir_all(&dir).expect("the scratch tree is removable");
    }
}
