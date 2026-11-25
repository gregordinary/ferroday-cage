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
//! `CAP_DAC_OVERRIDE` cover every mapped id. Those capabilities are why even
//! a single-identity map is worth re-entering: the ids are the caller's own
//! either way, but a directory whose mode denies the search or write the
//! deletion needs yields to them. No rootfs, no mounts, no `execve`: the
//! child performs the deletion itself, in the post-fork discipline this
//! module already enforces (no allocation, no locks, no panic, rustix
//! syscalls only).
//!
//! The deletion walks the tree with a few open descriptors and constant
//! memory, and never climbs: entries are unlinked from a rescanning pass over
//! the top of the tree, a non-empty directory there is emptied in place, and a
//! non-empty directory inside that one is renamed up to the top, for a later
//! pass to reach. Symlinks are never followed and the walk refuses to open one
//! as a directory, so nothing the tree itself holds can redirect the walk out
//! of it, and every directory the walk acts on is the top or one it opened by
//! name from there, so a concurrent writer renaming a directory out of the tree
//! takes none of the walk's reach with it. [`delete_tree`] is that walk, and the
//! caller's own first attempt at a removal runs it too, in process, before
//! anything here is forked.

use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{self, AtFlags, Mode, OFlags, RawDir, SeekFrom};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketFlags, SocketType};

use super::child::{MapDuty, MapFailure, StackBuf};
use super::frame;
use super::sys::{self, PidfdFork};
use super::{ChildMap, Forked};
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
    match unsafe { sys::fork_with_pidfd() } {
        Err(errno) => Err(spawn_failure(errno)),
        Ok(PidfdFork::Child) => sys::in_child(|| {
            // The fork duplicated the caller's end of the gate into this
            // process; close it, so this child pins nothing it does not use.
            // Closing an owned descriptor is a bare `close`, which the
            // post-fork discipline permits.
            drop(caller);
            removal_child(child_end.as_fd(), parent, leaf, map.duty())
        }),
        Ok(PidfdFork::ParentOf(child)) => {
            drop(child_end);
            // `drive_removal` owns the gate, so returning closes the caller's
            // end before the reap below, and it ends the child before giving
            // up on it. The reap is therefore always reachable.
            let result = drive_removal(caller, &child, &map);
            let _ = child.reap();
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
/// either way, so a failure reading it needs no signal: the reap still
/// returns.
fn drive_removal(gate: OwnedFd, child: &Forked, map: &ChildMap<'_>) -> Result<(), RemoveFailure> {
    let io_failure = |step: RemoveStep, errno: Errno| RemoveFailure::Step {
        step,
        errno: errno.raw_os_error(),
    };

    if let ChildMap::Delegated { mapper, map } = map {
        let failure = match super::drive_map_gate(gate.as_fd(), child.pid(), *mapper, map) {
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
            super::abandon_gated_child(child);
            return Err(failure);
        }
    }

    let record = frame::read_record(gate.as_fd())
        .map_err(|errno| io_failure(RemoveStep::Delete, errno))?
        .ok_or_else(|| io_failure(RemoveStep::Delete, Errno::PROTO))?;
    match frame::decode_record(record) {
        (frame::RECORD_DONE, _) => Ok(()),
        _ => Err(decode_record(record)),
    }
}

/// Names the failure the child's outcome record reports.
fn decode_record(record: [u8; frame::RECORD_LEN]) -> RemoveFailure {
    let (wire, errno) = frame::decode_record(record);
    match RemoveStep::from_wire(wire) {
        Some(step) => RemoveFailure::Step { step, errno },
        None => RemoveFailure::Malformed,
    }
}

/// The child: unshare, map, delete, report. Never returns.
fn removal_child(gate: BorrowedFd<'_>, parent: &CStr, leaf: &CStr, duty: MapDuty<'_>) -> ! {
    let report = |wire: u32, errno: Errno| {
        let _ = rustix::io::write(gate, &frame::encode_record(wire, errno.raw_os_error()));
    };

    // The gate is kept: the outcome record travels back on it.
    if let Err(failure) = super::child::enter_mapped_namespace(
        &[gate.as_raw_fd()],
        rustix::thread::UnshareFlags::empty(),
        duty,
        Some(gate),
    ) {
        match failure {
            // The caller left without applying the map; its own error is the
            // diagnostic, and the gate a report would travel on is closed.
            MapFailure::Abandoned => sys::exit_group(127),
            MapFailure::Step(step, errno) => {
                report(RemoveStep::from(step).wire(), errno);
                sys::exit_group(127)
            }
        }
    }

    let deleted = fs::open(
        parent,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .and_then(|parent| delete_tree(parent.as_fd(), leaf));
    match deleted {
        Ok(()) => {
            let _ = rustix::io::write(gate, &frame::encode_record(frame::RECORD_DONE, 0));
            sys::exit_group(0)
        }
        Err(errno) => {
            report(RemoveStep::Delete.wire(), errno);
            sys::exit_group(127)
        }
    }
}

/// Deletes `leaf` under the directory `parent`, whatever kind of entry it is,
/// holding at most three descriptors and constant memory.
///
/// Each pass over the start, the directory `leaf` names, unlinks what it can.
/// A non-empty directory in it is emptied in place: its own entries are
/// unlinked, and each non-empty directory among them is renamed up into the
/// start under a name of the walk's own, for a later pass to empty in turn. The
/// next pass removes the emptied one with `AT_REMOVEDIR`. Every directory is
/// renamed at most once, so a tree nested a hundred thousand levels deep costs
/// what a wide one of as many directories does, where a recursive removal holds
/// a descriptor and a stack frame per level and runs out of one or the other.
///
/// The walk never climbs. Every directory it acts on is the start, which it
/// holds open, or one it opened by name from the start, so a concurrent writer
/// that renames a directory the walk is in somewhere outside the tree takes
/// nothing of the walk out with it: the walk empties that directory where it
/// now is, as it is the tree's, and never reaches the directory it was moved
/// into. A walk that climbed back through `..` would follow such a directory
/// out and unlink in its new parent, with whatever privilege the walk holds.
///
/// It is the one walk every removal of a tree takes. The map-assisted child
/// runs it under the post-fork discipline, which it meets: it allocates
/// nothing, takes no lock, and cannot panic on what it reads. The caller's own
/// first attempt runs it in process, as the calling user. A removal that fails
/// partway leaves the tree partly removed, with directories from deeper in it
/// standing in the start under the walk's names.
///
/// A symbolic link is never followed: one at `leaf` is removed as a link, and
/// one inside the tree is unlinked like any other entry. An entry that is
/// already gone — `leaf` itself, or a name another process removed while a
/// pass was reading its directory — is the outcome asked for, not a failure.
pub(crate) fn delete_tree(parent: BorrowedFd<'_>, leaf: &CStr) -> Result<(), Errno> {
    // A plain entry (file or symlink) needs no walk at all. Linux reports the
    // attempt to unlink a directory as EISDIR; POSIX permits EPERM, so accept
    // both as "this is a directory".
    let refused = match fs::unlinkat(parent, leaf, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => return Ok(()),
        Err(errno @ (Errno::ISDIR | Errno::PERM)) => errno,
        Err(errno) => return Err(errno),
    };

    // EPERM is only a guess at "directory": an immutable file is refused the
    // same way. Where the open proves it was not one, the first refusal is the
    // honest diagnostic, not the ENOTDIR that disproved the guess.
    let start = match crate::provision::containment::open_child_dir(parent, leaf, OFlags::RDONLY) {
        Ok(start) => start,
        Err(Errno::NOENT) => return Ok(()),
        Err(Errno::NOTDIR) => return Err(refused),
        Err(errno) => return Err(errno),
    };
    let mut hoisted = 0;
    loop {
        // A fresh pass from the top each time: unlinking or renaming entries
        // while `getdents` reads the directory is safe, and an entry added
        // meanwhile is found by a later pass if not by this one.
        fs::seek(&start, SeekFrom::Start(0))?;
        let mut changed = false;
        let mut buf = [MaybeUninit::uninit(); 2048];
        let mut entries = RawDir::new(&start, &mut buf);
        while let Some(entry) = entries.next() {
            let entry = entry?;
            let name = entry.file_name();
            if name == c"." || name == c".." {
                continue;
            }
            match remove_entry(start.as_fd(), name)? {
                Removal::Removed => changed = true,
                Removal::Gone => {}
                Removal::NotEmpty => {
                    let child = match crate::provision::containment::open_child_dir(
                        start.as_fd(),
                        name,
                        OFlags::RDONLY,
                    ) {
                        Ok(child) => child,
                        // Removed, or renamed away, since the pass found it.
                        Err(Errno::NOENT) => continue,
                        Err(errno) => return Err(errno),
                    };
                    empty_into(child.as_fd(), start.as_fd(), &mut hoisted)?;
                    changed = true;
                }
            }
        }
        if !changed {
            // Nothing was left to remove: the start is empty.
            return match fs::unlinkat(parent, leaf, AtFlags::REMOVEDIR) {
                Ok(()) | Err(Errno::NOENT) => Ok(()),
                Err(errno) => Err(errno),
            };
        }
    }
}

/// Empties `dir`, a directory in `start`: unlinks every entry it can, and
/// renames each non-empty directory in it up into `start`, for the walk to
/// empty from there. Returns once a pass over `dir` finds nothing left.
fn empty_into(dir: BorrowedFd<'_>, start: BorrowedFd<'_>, hoisted: &mut u32) -> Result<(), Errno> {
    loop {
        fs::seek(dir, SeekFrom::Start(0))?;
        let mut changed = false;
        let mut buf = [MaybeUninit::uninit(); 2048];
        let mut entries = RawDir::new(dir, &mut buf);
        while let Some(entry) = entries.next() {
            let entry = entry?;
            let name = entry.file_name();
            if name == c"." || name == c".." {
                continue;
            }
            match remove_entry(dir, name)? {
                Removal::Removed => changed = true,
                Removal::Gone => {}
                Removal::NotEmpty => {
                    hoist(dir, name, start, hoisted)?;
                    changed = true;
                }
            }
        }
        if !changed {
            return Ok(());
        }
    }
}

/// What [`remove_entry`] did with an entry.
enum Removal {
    /// It is removed.
    Removed,
    /// Something else removed it first; nothing is owed here.
    Gone,
    /// It is a directory with entries of its own.
    NotEmpty,
}

/// Removes the entry `name` in `dir` where it is a file, a link, or an empty
/// directory, or reports it as a directory with entries of its own.
fn remove_entry(dir: BorrowedFd<'_>, name: &CStr) -> Result<Removal, Errno> {
    match fs::unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) => Ok(Removal::Removed),
        Err(Errno::NOENT) => Ok(Removal::Gone),
        // EISDIR on Linux, EPERM where POSIX allows it: a directory.
        Err(refused @ (Errno::ISDIR | Errno::PERM)) => {
            match fs::unlinkat(dir, name, AtFlags::REMOVEDIR) {
                Ok(()) => Ok(Removal::Removed),
                Err(Errno::NOENT) => Ok(Removal::Gone),
                Err(Errno::NOTEMPTY | Errno::EXIST) => Ok(Removal::NotEmpty),
                // Not a directory after all, so the EPERM that suggested one —
                // an immutable file, say — is the failure worth reporting.
                Err(Errno::NOTDIR) => Err(refused),
                Err(errno) => Err(errno),
            }
        }
        Err(errno) => Err(errno),
    }
}

/// Renames the directory `name` in `dir` up into `start`, under the first name
/// of the walk's own that `start` does not hold.
///
/// The names count up from `hoisted`, which keeps the count across the walk. A
/// name already taken, by an entry of the tree or by a concurrent writer, is
/// passed over: `RENAME_NOREPLACE` refuses it. A filesystem without that flag
/// has the name looked up first and the rename made plainly, which replaces
/// at most an empty directory that took the name in between.
fn hoist(
    dir: BorrowedFd<'_>,
    name: &CStr,
    start: BorrowedFd<'_>,
    hoisted: &mut u32,
) -> Result<(), Errno> {
    loop {
        *hoisted = hoisted.wrapping_add(1);
        let mut new = StackBuf::<HOIST_NAME_LEN>::new();
        new.push(HOIST_PREFIX);
        new.push_decimal(*hoisted);
        let new = new.as_cstr();
        let renamed = match fs::renameat_with(dir, name, start, new, fs::RenameFlags::NOREPLACE) {
            Err(Errno::INVAL) => match fs::statat(start, new, AtFlags::SYMLINK_NOFOLLOW) {
                Err(Errno::NOENT) => fs::renameat(dir, name, start, new),
                Ok(_) => Err(Errno::EXIST),
                Err(errno) => Err(errno),
            },
            renamed => renamed,
        };
        match renamed {
            Ok(()) => return Ok(()),
            // Removed meanwhile: nothing left to hoist.
            Err(Errno::NOENT) => return Ok(()),
            Err(Errno::EXIST | Errno::NOTEMPTY | Errno::NOTDIR | Errno::ISDIR) => continue,
            Err(errno) => return Err(errno),
        }
    }
}

/// The start of every name the walk gives a directory it renames up into the
/// start.
const HOIST_PREFIX: &[u8] = b".removing-";

/// A buffer that holds [`HOIST_PREFIX`] and the decimal digits of any `u32`.
const HOIST_NAME_LEN: usize = 32;

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

    /// No step may claim `frame::RECORD_DONE`, the finished record's wire
    /// value; zero and anything past the last step are not steps either.
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

    /// A tree with directories nested several deep, each holding a file, and
    /// one of them at the top a writer can move.
    fn nested_tree(tree: &std::path::Path, depth: usize) {
        let mut level = tree.join("moved");
        for _ in 0..depth {
            std::fs::create_dir_all(&level).expect("a level is creatable");
            std::fs::write(level.join("file"), b"").expect("a file is writable");
            level = level.join("level");
        }
    }

    #[test]
    fn a_tree_nested_deep_and_wide_is_removed_without_climbing() {
        let dir = Scratch::new("remove-hoist");
        let tree = dir.join("tree");
        nested_tree(&tree, 40);
        for wide in 0..40 {
            std::fs::create_dir_all(tree.join(format!("wide/{wide}/inner"))).unwrap();
            std::fs::write(tree.join(format!("wide/{wide}/inner/file")), b"").unwrap();
        }
        // A name the walk would give a directory it renames up is taken
        // already, and is passed over.
        std::fs::create_dir_all(tree.join(".removing-1/kept")).unwrap();
        let parent = rustix::fs::open(
            dir.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();

        delete_tree(parent.as_fd(), c"tree").expect("the tree is removed");
        assert!(!tree.exists());
    }

    #[test]
    fn a_directory_renamed_out_of_the_tree_takes_the_walk_nowhere() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // A writer moves a directory of the tree out of it and back, over and
        // over, while the walk removes the tree. Beside the tree, where the
        // directory goes, nothing is touched: the walk empties the directory
        // wherever it is, and never follows it to its new parent.
        for round in 0..10 {
            let dir = Scratch::new("remove-renamed");
            let (tree, outside) = (dir.join("tree"), dir.join("outside"));
            nested_tree(&tree, 32);
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("sentinel"), b"").unwrap();

            let stop = Arc::new(AtomicBool::new(false));
            let writer = {
                let stop = Arc::clone(&stop);
                let (inside, away) = (tree.join("moved"), outside.join("moved"));
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let _ = std::fs::rename(&inside, &away);
                        let _ = std::fs::rename(&away, &inside);
                    }
                })
            };
            let parent = rustix::fs::open(
                dir.path(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let removed = delete_tree(parent.as_fd(), c"tree");
            stop.store(true, Ordering::Relaxed);
            writer.join().unwrap();

            assert!(
                outside.join("sentinel").exists(),
                "round {round}: the walk reached beside the tree ({removed:?})",
            );
        }
    }

    /// A delegate that resolves the map, forks a bystander process, and then
    /// refuses to apply.
    ///
    /// The bystander stands in for any process this caller forked concurrently
    /// — one of the library's own children before it has swept, or one the
    /// consumer forked and that never sweeps at all. A fork copies the
    /// whole descriptor table, so the bystander holds its own copy of the
    /// caller's end of the removal gate and keeps the peer open no matter how
    /// promptly the caller closes its own. A caller that abandoned the removal
    /// child by closing the gate alone would therefore leave it blocked for as
    /// long as the bystander lives.
    #[derive(Debug, Default)]
    struct ForksThenRefuses {
        /// The bystander, for the test to collect.
        bystander: Mutex<Option<Forked>>,
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
            match unsafe { sys::fork_with_pidfd() } {
                Ok(PidfdFork::Child) => sys::in_child(|| {
                    // Outlast the caller's abandonment; the test collects this
                    // process rather than waiting the sleep out.
                    let _ = rustix::thread::nanosleep(&rustix::thread::Timespec {
                        tv_sec: 300,
                        tv_nsec: 0,
                    });
                    sys::exit_group(0)
                }),
                Ok(PidfdFork::ParentOf(bystander)) => {
                    *self
                        .bystander
                        .lock()
                        .expect("the test holds no poisoned lock") = Some(bystander);
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
            if let Some(bystander) = self
                .bystander
                .lock()
                .expect("the test holds no poisoned lock")
                .take()
            {
                bystander.kill();
                let _ = bystander.reap();
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
        if !ferroday_cage_testkit::require::userns() {
            // Without a user namespace the child fails before reaching the
            // gate, so there would be nothing to abandon.
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
    }
}
