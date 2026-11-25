//! Map-assisted rootfs export: read a tree whose files a range-mapped sandbox
//! chowned to subordinate ids, at the ownership the tree intends.
//!
//! A range-mapped sandbox writes real ownership, so a file the rootfs means as
//! uid 42 is stored on the host as `100000 + 42`. Only a process re-entered
//! into the same identity map, as root of the mapped namespace, sees that file
//! as uid 42 again — and only such a process can read the `security.*` xattrs a
//! setcap'd binary carries. This module forks a child that unshares a user
//! namespace and either writes its own single-identity map or holds at a gate
//! while the caller's delegate establishes a range map, then walks the tree as
//! root of the mapped namespace and streams every entry's metadata and data to
//! the parent.
//!
//! The division of labor is deliberate. The child does only the privileged,
//! must-be-in-map work — `statat`, `flistxattr`/`fgetxattr`, `readlinkat`, and
//! reading file data — under the post-fork discipline this module enforces (no
//! allocation, no locks, no panic, rustix syscalls only). Its memory is a stack
//! frame per level of the tree and two arenas its caller allocates before the
//! fork, which hold the names of the directories it is inside while it sorts
//! them. It never assembles a path, tracks hardlinks, or formats a tar header:
//! those want a heap. It emits a flat stream of [frames](#frame-protocol)
//! instead, and the parent — in ordinary `std` context, with an allocator —
//! reassembles paths, coalesces hardlinks, and encodes the archive (see
//! [`provision::export`](crate::provision)).
//!
//! # Frame protocol
//!
//! The child writes little-endian frames to a stream pipe, each led by a
//! one-byte tag:
//!
//! - [`FRAME_DIR`]: a directory is entered. Its metadata and xattrs follow; the
//!   parent pushes its name and every later frame is a descendant until the
//!   matching [`FRAME_LEAVE`]. The walk opens with one such frame for the
//!   rootfs root itself, named `.`, so the archive equals `tar -C rootfs .`:
//!   every member is `./`-prefixed (see [`Walker::walk_root`]).
//! - [`FRAME_LEAVE`]: the current directory is finished; the parent pops it.
//! - [`FRAME_FILE`]: a regular file. Its metadata, xattrs, exactly `size` bytes
//!   of data, and a status byte follow. The status is zero when the file read
//!   back exactly `size` bytes, and one when it grew or shrank while it was
//!   read, the data then cut or zero-padded to keep the stream in step.
//! - [`FRAME_SYMLINK`]: a symbolic link. Its metadata and link target follow.
//! - [`FRAME_END`]: the walk finished cleanly.
//! - [`FRAME_ERROR`]: a syscall failed; a step discriminant and errno follow,
//!   then the name of the entry it failed on in the current directory, as a
//!   `u16`-prefixed string, empty where it failed on the current directory
//!   itself, and the child exits.
//!
//! Character and block devices, FIFOs, and sockets are skipped: a deployed OS
//! image carries none that a runtime does not provide, and the tar reader on
//! the other end drops them regardless.
//!
//! # Replies
//!
//! The parent answers some frames on a second pipe, one byte each:
//! [`REPLY_SEND`] or [`REPLY_SKIP`]. A file's data, and a directory's
//! contents, cross the stream only where the parent writes them into the
//! archive. A filtered export is asked of every directory and every file, and
//! an unfiltered one of every file with more than one link, whose later names
//! the archive records as hard links rather than as their data. The child
//! waits for the answer after the entry's metadata. On [`REPLY_SKIP`] a file
//! frame ends there, without data or a status byte, and a directory frame is
//! followed by its [`FRAME_LEAVE`] alone. Without this, every name of a file
//! and every file of an excluded subtree crossed the stream in full and was
//! discarded, which nothing the archive was written to could bound: a sparse
//! file of terabytes, linked a thousand times, cost its writer nothing.

use std::cell::Cell;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RawDir};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketFlags, SocketType};

use super::bounds::{LINK_BUF, MAX_DEPTH, NAME_MAX, XATTR_SIZE_MAX};
use super::child::MapFailure;
use super::frame::{self, Holes, StreamFailure};
use super::sys::{self, PidfdFork};
use super::{ChildMap, Forked};
use crate::idmap::IdMapError;
use crate::provision::containment;
use crate::wire::wire_enum;

/// Frame tag: a directory is entered.
pub(crate) const FRAME_DIR: u8 = 1;
/// Frame tag: the current directory is finished.
pub(crate) const FRAME_LEAVE: u8 = 2;
/// Frame tag: a regular file, followed by its data.
pub(crate) const FRAME_FILE: u8 = 3;
/// Frame tag: a symbolic link, followed by its target.
pub(crate) const FRAME_SYMLINK: u8 = 4;
/// Frame tag: the walk finished cleanly.
pub(crate) const FRAME_END: u8 = 5;
/// Frame tag: a syscall failed; a step discriminant and errno follow.
pub(crate) const FRAME_ERROR: u8 = 6;

/// Reply: the parent writes this entry into the archive, so the child streams
/// its data, or walks its contents.
pub(crate) const REPLY_SEND: u8 = 1;
/// Reply: the parent writes nothing of this entry's data or contents, so the
/// child sends none.
pub(crate) const REPLY_SKIP: u8 = 0;

/// Whether the child asks the parent before streaming a file's data: always
/// where the export is `filtered`, and otherwise for a file with more than
/// `nlink` one. Both ends ask this, so they agree on which frames are
/// answered.
pub(crate) fn asks_for_file(filtered: bool, nlink: u64) -> bool {
    filtered || nlink > 1
}

wire_enum! {
    /// What the export child was doing when a syscall failed, carried in a
    /// [`FRAME_ERROR`] frame and by [`StartError`].
    ///
    /// The explicit discriminants are the frame's wire encoding, which both
    /// ends of a single build write and read. They are not a stable protocol: a
    /// step inserted in a later release may renumber the ones after it.
    pub(crate) enum ExportStep {
        map {
            ResetSignals = 1 => "resetting the export process's signal dispositions",
            SweepFds = 2 => "closing the export process's inherited descriptors",
            Unshare = 3 => "unsharing the export namespace",
            DenySetgroups = 4 => "denying setgroups in the export namespace",
            WriteGidMap = 14 => "writing the export gid map",
            WriteUidMap = 15 => "writing the export uid map",
            AwaitMap = 5 => "establishing the export identity map",
        }
        /// Forking the export process or speaking to it. Reported by the caller
        /// alone: the child has no channel to report it on.
        Spawn = 0 => "spawning the export process",
        /// Reading a directory's entries failed.
        ReadDir = 6 => "reading a directory in the exported tree",
        /// Stat-ing an entry failed.
        Stat = 7 => "inspecting an entry in the exported tree",
        /// Opening an entry failed.
        Open = 8 => "opening an entry in the exported tree",
        /// Reading a symlink target failed.
        ReadLink = 9 => "reading a symlink in the exported tree",
        /// Reading an entry's extended attributes failed.
        Xattr = 10 => "reading extended attributes in the exported tree",
        /// Reading a file's data failed.
        ReadData = 11 => "reading file data in the exported tree",
        /// The tree is nested deeper than the export walks.
        Depth = 12 => "walking the exported tree, which nests too deeply",
        /// Streaming a frame to the parent failed; the parent is gone.
        Stream = 13 => "streaming the exported tree to the archiver",
        /// The entry opened was not the regular file the walk had inspected:
        /// another process changed the tree while it was being exported.
        Changed = 16 => "reading an entry in the exported tree, which changed while it was being read",
        /// A directory held more entries than the export can sort.
        Crowded = 17 => "sorting a directory in the exported tree, which holds more entries than the export can order",
    }
}

/// A failure to start the export before the child began streaming.
pub(crate) enum StartError {
    /// A syscall of the spawn machinery failed.
    Spawn(Errno),
    /// The child failed before it reached the map gate and named the step on
    /// the stream, where this caller read it back rather than reporting the
    /// lost child it looked like from the gate's side.
    Reported {
        /// What the child was doing.
        step: ExportStep,
        /// What the kernel answered it with.
        errno: Errno,
    },
    /// The delegate failed to apply the map; its own error is the diagnostic.
    Map(IdMapError),
}

/// A running export child: the parent reads [`stream`](Self::stream) to
/// completion, then calls [`finish`](Self::finish) to reap it.
pub(crate) struct ExportChild {
    /// The child process.
    child: Forked,
    /// The read end of the frame stream.
    stream: OwnedFd,
    /// The write end of the replies.
    replies: OwnedFd,
}

impl ExportChild {
    /// The frame stream to read to [`FRAME_END`] or [`FRAME_ERROR`].
    pub(crate) fn stream(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }

    /// Where the parent writes its [replies](self#replies).
    pub(crate) fn replies(&self) -> BorrowedFd<'_> {
        self.replies.as_fd()
    }

    /// Reaps the child once its stream is drained, reporting only whether the
    /// wait itself succeeded.
    ///
    /// The wait status is deliberately not judged. What the child made of the
    /// tree is carried by the stream — [`FRAME_END`] for a completed walk,
    /// [`FRAME_ERROR`] for a failed one — and the parent has already read it by
    /// the time this is called. A status is the weaker evidence besides: the
    /// terminator is written before `exit_group`, so a child signalled between
    /// the two produced a complete archive and would be reported as a failure,
    /// while a child killed mid-walk truncated the stream and is reported by the
    /// reader that ran into the end of it.
    pub(crate) fn finish(self) -> Result<(), Errno> {
        drop(self.stream);
        drop(self.replies);
        self.child.reap().map(|_| ())
    }
}

/// Forks the export child and establishes its identity map.
///
/// On return the child is walking `rootfs` and streaming frames; the caller
/// reads [`ExportChild::stream`] to [`FRAME_END`] or [`FRAME_ERROR`], answering
/// on [`ExportChild::replies`] what the [replies](self#replies) say it is asked
/// where the export is `filtered`, then calls [`ExportChild::finish`]. A
/// child-side walk failure surfaces in the stream as [`FRAME_ERROR`], not here;
/// this returns only spawn failures and, for a delegated map, the delegate's own
/// apply failure.
pub(crate) fn start_export(
    rootfs: &CStr,
    map: ChildMap<'_>,
    filtered: bool,
) -> Result<ExportChild, StartError> {
    let (stream_read, stream_write) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(StartError::Spawn)?;
    let (replies_read, replies_write) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(StartError::Spawn)?;

    // The arenas the child sorts each directory's names in, allocated here
    // because the child cannot allocate. Zeroed, so the pages are the kernel's
    // own until the child writes to them, and this caller never does.
    let mut names = vec![0u8; NAMES_ARENA];
    let mut order = vec![0u32; ORDER_ARENA];

    // The gate exists only for a delegated map; a self-mapped child needs no
    // handshake.
    let gate = match map {
        ChildMap::Delegated { .. } => Some(
            rustix::net::socketpair(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )
            .map_err(StartError::Spawn)?,
        ),
        ChildMap::SelfMap { .. } => None,
    };

    // SAFETY: the child branch runs `export_child`, which performs raw rustix
    // syscalls over the frozen paths and descriptors — no allocation, no
    // locking, no panic — and never returns: every path ends in `exit_group`.
    match unsafe { sys::fork_with_pidfd() } {
        Err(errno) => Err(StartError::Spawn(errno)),
        Ok(PidfdFork::Child) => {
            // The fork duplicated the caller's ends into this process; close
            // what this child does not use, so it pins nothing of the caller's.
            // The read end of its own frame pipe matters most: holding it would
            // make `write` on the stream succeed forever, so a child orphaned
            // by the caller's death would fill the pipe and block in `write`
            // rather than fail with `EPIPE` and exit. Closing an owned
            // descriptor is a bare `close`, which the post-fork discipline
            // permits; everything else the caller had open is closed by the
            // sweep inside `export_child`.
            drop(stream_read);
            drop(replies_write);
            let gate_child = gate.map(|(caller, child)| {
                drop(caller);
                child
            });
            let arena = Arena {
                names: &mut names,
                order: &mut order,
            };
            let ends = Ends {
                stream: stream_write.as_fd(),
                replies: replies_read.as_fd(),
                filtered,
            };
            export_child(ends, gate_child, rootfs, &map, arena)
        }
        Ok(PidfdFork::ParentOf(child)) => {
            drop(stream_write);
            drop(replies_read);
            // The child has its own copy of the arenas; this side's is unused.
            drop((names, order));
            if let (Some((caller, child_end)), ChildMap::Delegated { mapper, map }) = (gate, &map) {
                drop(child_end);
                let driven = super::drive_map_gate(caller.as_fd(), child.pid(), *mapper, map);
                // Anything but a released child leaves one blocked at the gate
                // in an unmapped namespace, having read nothing and written
                // nothing the caller will read.
                let failure = match driven {
                    Ok(super::Gated::Released) => None,
                    // The export child reports its failures on the stream, not
                    // on the gate, so a record here is a malfunction rather
                    // than a step it named. Both read as a lost child.
                    Ok(super::Gated::EarlyRecord(_) | super::Gated::ChildLost) => {
                        Some(StartError::Spawn(Errno::PROTO))
                    }
                    Err(super::GateFailure::Io(errno)) => Some(StartError::Spawn(errno)),
                    Err(super::GateFailure::Map(err)) => Some(StartError::Map(err)),
                };
                if let Some(err) = failure {
                    drop(caller);
                    super::abandon_gated_child(&child);
                    // A child that failed on its way to the gate reported on
                    // the stream, as it reports every other failure — and this
                    // caller was blocked on the gate, so it has not read it.
                    // Reading it now is what turns "the child is gone" into the
                    // step it went on; the copy-in path preserves its child's
                    // diagnostic the same way, through `Gated::EarlyRecord`.
                    return Err(early_report(stream_read.as_fd()).unwrap_or(err));
                }
            }
            Ok(ExportChild {
                child,
                stream: stream_read,
                replies: replies_write,
            })
        }
    }
}

/// The child's ends of its two pipes, and whether the export is filtered.
struct Ends<'a> {
    stream: BorrowedFd<'a>,
    replies: BorrowedFd<'a>,
    filtered: bool,
}

/// The child: unshare, establish the map, walk, and stream. Never returns.
///
/// Takes the gate by value so the handshake can close it: past the go byte the
/// gate has nothing left to say, and the walk that follows is long.
fn export_child(
    ends: Ends<'_>,
    gate: Option<OwnedFd>,
    rootfs: &CStr,
    map: &ChildMap<'_>,
    arena: Arena<'_>,
) -> ! {
    let stream = ends.stream;
    let fail = |step: ExportStep, errno: Errno| -> ! {
        emit_error(stream, step, errno, &[]);
        sys::exit_group(1)
    };

    let keep = [
        stream.as_raw_fd(),
        ends.replies.as_raw_fd(),
        gate.as_ref().map_or(-1 as RawFd, |gate| gate.as_raw_fd()),
    ];
    if let Err(failure) = super::child::enter_mapped_namespace(
        &keep,
        rustix::thread::UnshareFlags::empty(),
        map.duty(),
        gate.as_ref().map(OwnedFd::as_fd),
    ) {
        match failure {
            // The caller left without applying the map; its own error is the
            // diagnostic, and it is no longer reading the stream a report
            // would travel on.
            MapFailure::Abandoned => sys::exit_group(1),
            MapFailure::Step(step, errno) => fail(step.into(), errno),
        }
    }
    // The map is in force and the gate has served its purpose; the walk below
    // carries the rest of the conversation on the stream, and it is long.
    drop(gate);

    let root = match fs::open(
        rootfs,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(errno) => fail(ExportStep::Open, errno),
    };

    let walker = Walker::new(stream, ends.replies, ends.filtered);
    match walker.walk_root(root.as_fd(), arena) {
        Ok(()) => {
            emit_tag(stream, FRAME_END);
            sys::exit_group(0)
        }
        Err((step, errno)) => {
            let (name, len) = walker.blamed();
            emit_error(stream, step, errno, &name[..len]);
            sys::exit_group(1)
        }
    }
}

/// The directory-iteration buffer, one per open level.
const DIRENTS_BUF: usize = 2048;
/// The bytes of entry names the walk can hold at once: those of every
/// directory it is inside, since each is read whole and sorted before its
/// entries are visited.
///
/// Each name costs its length and two bytes. Sixteen MiB holds several hundred
/// thousand names of an ordinary length; a rootfs directory with five figures
/// of entries uses a few percent of it.
const NAMES_ARENA: usize = 16 << 20;
/// How many entries the walk can hold at once, across the directories it is
/// inside, and so the most one directory may have.
const ORDER_ARENA: usize = 1 << 20;

// A stored name's length is one byte.
const _: () = assert!(NAME_MAX <= u8::MAX as usize);

/// Where the walk keeps the names of the directories it is inside, for sorting.
///
/// Allocated by the caller before the fork, since the child cannot allocate,
/// and split as the walk descends: a directory takes what its own names need
/// from the front and hands the rest to the directories below it. A tree whose
/// open directories together need more than the arenas hold fails the export
/// with [`ExportStep::Crowded`] rather than being walked out of order.
struct Arena<'a> {
    /// Each name as a length byte, the name, and a NUL, back to back.
    names: &'a mut [u8],
    /// The offset in `names` of each entry, sorted in place by the name there.
    order: &'a mut [u32],
}

/// Carries the frame stream through the recursive walk. Holds no growing
/// state: the per-level memory is the directory-iteration buffer and the part
/// of the [`Arena`] the level's own names take, and the large metadata buffers
/// live in the leaf helpers so they never span a recursive call.
struct Walker<'a> {
    stream: BorrowedFd<'a>,
    /// Where the parent's [replies](self#replies) arrive.
    replies: BorrowedFd<'a>,
    /// Whether the export is filtered, so every entry is asked of.
    filtered: bool,
    /// The name, in the directory the parent holds as current, of the entry a
    /// failure was met on, and its length: set by [`blame`](Self::blame) where
    /// one was, and empty where the walk failed on that directory itself.
    blamed: Cell<([u8; NAME_MAX], usize)>,
}

impl<'a> Walker<'a> {
    /// A walk streaming to `stream` and reading the parent's replies from
    /// `replies`, asking of every entry where `filtered`.
    fn new(stream: BorrowedFd<'a>, replies: BorrowedFd<'a>, filtered: bool) -> Walker<'a> {
        Walker {
            stream,
            replies,
            filtered,
            blamed: Cell::new(([0; NAME_MAX], 0)),
        }
    }

    /// Records that the failure about to be returned was met on `name`, an
    /// entry of the directory the parent holds as current, and hands it back.
    fn blame(&self, name: &CStr, failure: (ExportStep, Errno)) -> (ExportStep, Errno) {
        let name = name.to_bytes();
        let mut held = [0; NAME_MAX];
        let len = name.len().min(NAME_MAX);
        held[..len].copy_from_slice(&name[..len]);
        self.blamed.set((held, len));
        failure
    }

    /// The name [`blame`](Self::blame) recorded, empty where none was.
    fn blamed(&self) -> ([u8; NAME_MAX], usize) {
        self.blamed.get()
    }

    /// Walks the export root, emitting it as a `.` directory entry — the
    /// rootfs's own mode, ownership, mtime, and xattrs — then its contents,
    /// then a leave.
    ///
    /// The root frame is what makes the archive equal `tar -C rootfs .`: the
    /// parent's path stack starts at `.`, so the first member is `./` and every
    /// child is `./`-prefixed (`./boot/`, `./boot/vmlinuz`). Without it the
    /// stack starts empty, top-level entries get bare names (`boot`,
    /// `boot/vmlinuz`), and the tar diverges from the `tar -C rootfs .`
    /// convention consumers select members against.
    fn walk_root(&self, root: BorrowedFd<'_>, arena: Arena<'_>) -> Result<(), (ExportStep, Errno)> {
        let stat = fs::fstat(root).map_err(|e| (ExportStep::Stat, e))?;
        self.emit_meta(FRAME_DIR, c".", &stat, Some(root))?;
        if !self.filtered || self.sent()? {
            self.walk_dir(root, 0, arena)?;
        }
        emit_tag_checked(self.stream, FRAME_LEAVE)
    }

    /// Walks `dir` in sorted name order, emitting a frame per entry and
    /// descending into subdirectories. Symlinks are never followed and the walk
    /// never leaves the tree: every step opens a single component from the
    /// current descriptor.
    ///
    /// The order is deterministic so the archive is byte-reproducible, and it is
    /// produced without the heap the post-fork child cannot use. The directory
    /// is read once, its names copied into the front of the [`Arena`], and their
    /// offsets sorted in place by the name each one locates — an unstable sort
    /// over a slice, which allocates nothing. A directory's names are unique,
    /// so the order is total. The cost is a directory's size times its
    /// logarithm, however large it is, until the arena runs out.
    ///
    /// The walk recurses once per level, through this and
    /// [`visit_entry`](Self::visit_entry), and refuses a tree deeper than
    /// [`MAX_DEPTH`]. That bounds the stack it takes, since nothing larger than
    /// the directory-iteration buffer is in either frame: the helpers holding
    /// the large buffers, the attributes' two of `XATTR_SIZE_MAX`, a link
    /// target's and a file's data, are kept out of line, so their buffers are
    /// on the stack only while one runs and never once per level. At
    /// [`MAX_DEPTH`] levels of a few kilobytes each, the walk stays well inside
    /// the stack of the thread that forked it.
    fn walk_dir(
        &self,
        dir: BorrowedFd<'_>,
        depth: u32,
        arena: Arena<'_>,
    ) -> Result<(), (ExportStep, Errno)> {
        if depth as usize >= MAX_DEPTH {
            return Err((ExportStep::Depth, Errno::LOOP));
        }
        let Arena { names, order } = arena;
        let crowded = (ExportStep::Crowded, Errno::NOBUFS);
        let mut used = 0;
        let mut count = 0;
        // From the first entry, whatever the descriptor has already read.
        fs::seek(dir, fs::SeekFrom::Start(0)).map_err(|e| (ExportStep::ReadDir, e))?;
        let mut buf = [MaybeUninit::uninit(); DIRENTS_BUF];
        let mut entries = RawDir::new(dir, &mut buf);
        while let Some(entry) = entries.next() {
            let entry = entry.map_err(|e| (ExportStep::ReadDir, e))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if name.len() > NAME_MAX {
                return Err((ExportStep::ReadDir, Errno::NAMETOOLONG));
            }
            let end = used + name.len() + 2;
            if end > names.len() || count == order.len() {
                return Err(crowded);
            }
            names[used] = name.len() as u8;
            names[used + 1..end - 1].copy_from_slice(name);
            names[end - 1] = 0;
            order[count] = u32::try_from(used).map_err(|_| crowded)?;
            used = end;
            count += 1;
        }

        let (mine, names) = names.split_at_mut(used);
        let (sorted, order) = order.split_at_mut(count);
        let mine: &[u8] = mine;
        sorted.sort_unstable_by(|a, b| stored_name(mine, *a).cmp(stored_name(mine, *b)));
        for &at in sorted.iter() {
            let name = stored_cstr(mine, at).ok_or((ExportStep::ReadDir, Errno::INVAL))?;
            let below = Arena {
                names: &mut *names,
                order: &mut *order,
            };
            self.visit_entry(dir, name, depth, below)?;
        }
        Ok(())
    }

    /// Emits one entry: a directory, descending into it and closing with a
    /// leave; a regular file, followed by its data; or a symlink. Character and
    /// block devices, FIFOs, and sockets are dropped, as a deployed image's
    /// runtime provides its own.
    ///
    /// A regular file is opened through
    /// [`containment::open_typed_file`](crate::provision::containment::open_typed_file):
    /// without waiting, and checked against what was inspected before it is
    /// read. A named pipe put in its place between the two would otherwise hold
    /// the walk forever on a blocking open, and a different file would be read
    /// under the first one's metadata.
    ///
    /// A failure on the entry itself is [blamed](Self::blame) on its name. One
    /// met inside a directory it descends into is that directory's walk's,
    /// which the parent holds as current by then, and is left as it is.
    fn visit_entry(
        &self,
        dir: BorrowedFd<'_>,
        name: &CStr,
        depth: u32,
        arena: Arena<'_>,
    ) -> Result<(), (ExportStep, Errno)> {
        let on_entry = |failure| self.blame(name, failure);
        let stat = fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| on_entry((ExportStep::Stat, e)))?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                let child =
                    crate::provision::containment::open_child_dir(dir, name, OFlags::RDONLY)
                        .map_err(|e| on_entry((ExportStep::Open, e)))?;
                // Emit the directory (with its xattrs) before descending; the
                // 64 KiB xattr buffers are freed on return, so they never
                // overlap the recursion's stack.
                self.emit_meta(FRAME_DIR, name, &stat, Some(child.as_fd()))
                    .map_err(on_entry)?;
                if !self.filtered || self.sent()? {
                    self.walk_dir(child.as_fd(), depth + 1, arena)?;
                }
                emit_tag_checked(self.stream, FRAME_LEAVE)
            }
            FileType::RegularFile => {
                let file = containment::open_typed_file(dir, name, &stat, OFlags::RDONLY).map_err(
                    |e| match e {
                        Errno::STALE => on_entry((ExportStep::Changed, e)),
                        e => on_entry((ExportStep::Open, e)),
                    },
                )?;
                self.emit_meta(FRAME_FILE, name, &stat, Some(file.as_fd()))
                    .map_err(on_entry)?;
                // Widened as `emit_meta` widens it; see there.
                #[allow(clippy::useless_conversion)]
                let nlink = u64::from(stat.st_nlink);
                if asks_for_file(self.filtered, nlink) && !self.sent().map_err(on_entry)? {
                    return Ok(());
                }
                self.stream_data(file.as_fd(), stat.st_size as u64)
                    .map_err(on_entry)
            }
            FileType::Symlink => self.emit_symlink(dir, name, &stat).map_err(on_entry),
            _ => Ok(()),
        }
    }

    /// Emits a directory or file metadata frame: tag, name, mode, ownership,
    /// mtime, the file-only size/dev/ino/nlink block, and the xattrs read from
    /// `fd`.
    fn emit_meta(
        &self,
        tag: u8,
        name: &CStr,
        stat: &fs::Stat,
        fd: Option<BorrowedFd<'_>>,
    ) -> Result<(), (ExportStep, Errno)> {
        let stream = self.stream;
        put(stream, &[tag])?;
        put_bytes_u16(stream, name.to_bytes())?;
        put(stream, &stat.st_mode.to_le_bytes())?;
        put(stream, &stat.st_uid.to_le_bytes())?;
        put(stream, &stat.st_gid.to_le_bytes())?;
        put(stream, &stat.st_mtime.to_le_bytes())?;
        if tag == FRAME_FILE {
            put(stream, &(stat.st_size as u64).to_le_bytes())?;
            put(stream, &stat.st_dev.to_le_bytes())?;
            put(stream, &stat.st_ino.to_le_bytes())?;
            // `st_nlink` is u32 or u64 depending on the architecture's `stat`;
            // normalize to the 8-byte field the parent decodes.
            //
            // `allow` rather than `expect`, and a conversion rather than a
            // cast, because either lint fires on some targets and not others:
            // the conversion is the identity where the field is already 64 bits
            // and a widening where it is 32, so an expectation of one is
            // unfulfilled on the targets the other applies to — which fails the
            // clippy job there. `allow` is the attribute that holds either way.
            #[allow(clippy::useless_conversion)]
            let nlink = u64::from(stat.st_nlink);
            put(stream, &nlink.to_le_bytes())?;
        }
        match fd {
            Some(fd) => self.emit_xattrs(fd),
            None => put(stream, &0u16.to_le_bytes()),
        }
    }

    /// Emits the xattr block: a count, then each name and value. Reads the name
    /// list and each value into bounded stack buffers, the kernel's 64 KiB cap
    /// on both keeping them finite. A filesystem or entry with no xattr support
    /// emits an empty block.
    ///
    /// Kept out of line, so its buffers are never in a level of the walk's
    /// frame; see [`walk_dir`](Self::walk_dir).
    #[inline(never)]
    fn emit_xattrs(&self, fd: BorrowedFd<'_>) -> Result<(), (ExportStep, Errno)> {
        let stream = self.stream;
        let mut names = [0u8; XATTR_SIZE_MAX];
        let list_len = match fs::flistxattr(fd, &mut names[..]) {
            Ok(len) => len,
            Err(Errno::NOTSUP) | Err(Errno::NODATA) => 0,
            Err(e) => return Err((ExportStep::Xattr, e)),
        };
        let list = &names[..list_len];

        // Count the NUL-terminated names first, so the count leads the block.
        let count = list.iter().filter(|b| **b == 0).count();
        let count = u16::try_from(count).map_err(|_| (ExportStep::Xattr, Errno::RANGE))?;
        put(stream, &count.to_le_bytes())?;

        let mut value = [0u8; XATTR_SIZE_MAX];
        let mut start = 0;
        for (i, byte) in list.iter().enumerate() {
            if *byte != 0 {
                continue;
            }
            // The name including its terminator is a valid C string.
            let name = CStr::from_bytes_with_nul(&list[start..=i])
                .map_err(|_| (ExportStep::Xattr, Errno::INVAL))?;
            start = i + 1;
            let value_len = match fs::fgetxattr(fd, name, &mut value[..]) {
                Ok(len) => len,
                // The attribute vanished between listing and reading; emit it
                // empty rather than fail the whole export.
                Err(Errno::NODATA) => 0,
                Err(e) => return Err((ExportStep::Xattr, e)),
            };
            put_bytes_u16(stream, name.to_bytes())?;
            put(stream, &(value_len as u32).to_le_bytes())?;
            put(stream, &value[..value_len])?;
        }
        Ok(())
    }

    /// Emits a symlink frame: metadata then the link target, and no attribute
    /// block.
    ///
    /// The kernel confines a symlink's extended attributes to the `security`
    /// and `trusted` namespaces — the `user` namespace is refused on anything
    /// but a regular file or a directory — and neither is one an unprivileged
    /// export can read in full or an unprivileged extraction restore. Reading
    /// them would also mean an `O_PATH` descriptor and a `/proc/self/fd` detour,
    /// since `flistxattr` refuses one; the frame format leaves the door open by
    /// simply having no block here.
    ///
    /// Kept out of line for the reason [`emit_xattrs`](Self::emit_xattrs) is.
    #[inline(never)]
    fn emit_symlink(
        &self,
        dir: BorrowedFd<'_>,
        name: &CStr,
        stat: &fs::Stat,
    ) -> Result<(), (ExportStep, Errno)> {
        let mut target = [0u8; LINK_BUF];
        let len = fs::readlinkat_raw(dir, name, &mut target[..])
            .map_err(|e| (ExportStep::ReadLink, e))?;
        // `readlinkat` truncates a target too long for the buffer and reports
        // the truncated length as success, so a full buffer is the only signal
        // there is and one that exactly fills it cannot be told from one that
        // did not fit. Refused rather than exported, because a truncated target
        // extracts as a link pointing somewhere else entirely. Linux caps a
        // symlink's target at `PATH_MAX - 1`, one byte short of this buffer, so
        // what this guards is a filesystem that answers for a longer one.
        if len == target.len() {
            return Err((ExportStep::ReadLink, Errno::NAMETOOLONG));
        }
        let stream = self.stream;
        put(stream, &[FRAME_SYMLINK])?;
        put_bytes_u16(stream, name.to_bytes())?;
        put(stream, &stat.st_mode.to_le_bytes())?;
        put(stream, &stat.st_uid.to_le_bytes())?;
        put(stream, &stat.st_gid.to_le_bytes())?;
        put(stream, &stat.st_mtime.to_le_bytes())?;
        put_bytes_u16(stream, &target[..len])
    }

    /// Waits for the parent's [reply](self#replies) to the entry just emitted:
    /// whether it writes the entry's data or contents into the archive.
    ///
    /// A parent gone, or a byte that is neither reply, ends the walk as a
    /// failed stream.
    fn sent(&self) -> Result<bool, (ExportStep, Errno)> {
        let mut reply = [0u8; 1];
        frame::read_full(self.replies, &mut reply).map_err(|e| (ExportStep::Stream, e))?;
        match reply[0] {
            REPLY_SEND => Ok(true),
            REPLY_SKIP => Ok(false),
            _ => Err((ExportStep::Stream, Errno::PROTO)),
        }
    }

    /// Streams exactly `size` bytes of a file's data, then the status byte
    /// saying whether the file still held exactly that many.
    ///
    /// [`frame::stream_exact`] keeps the parent's framing in step with a file
    /// that a live writer grew or shrank, which a quiesced rootfs does not.
    /// The status is what keeps the parent from calling the result an archive
    /// of the file: it reports the change for an entry it keeps, as a copy into
    /// a rootfs does.
    ///
    /// A sparse file's holes read as zeros and are streamed as data. Nothing
    /// here bounds a file's length, so the bound on an archive is its sink's,
    /// as the `Export` documentation says: a file's data is streamed only
    /// where the parent writes it there, which its [reply](self#replies) says
    /// where it might not.
    fn stream_data(&self, fd: BorrowedFd<'_>, size: u64) -> Result<(), (ExportStep, Errno)> {
        let changed =
            frame::stream_exact(fd, self.stream, size, Holes::Zeros).map_err(|failure| {
                match failure {
                    StreamFailure::File(errno) => (ExportStep::ReadData, errno),
                    StreamFailure::Stream(errno) => (ExportStep::Stream, errno),
                }
            })?;
        put(self.stream, &[u8::from(changed)])
    }
}

/// A name [`Walker::walk_dir`] stored at `at` in its arena: the bytes after
/// the length byte, without the terminator.
fn stored_name(names: &[u8], at: u32) -> &[u8] {
    let at = at as usize;
    let len = names.get(at).copied().unwrap_or(0) as usize;
    names.get(at + 1..at + 1 + len).unwrap_or(&[])
}

/// A name [`Walker::walk_dir`] stored at `at`, with its terminator, for the
/// `*at` calls that resolve it.
fn stored_cstr(names: &[u8], at: u32) -> Option<&CStr> {
    let at = at as usize;
    let len = *names.get(at)? as usize;
    CStr::from_bytes_with_nul(names.get(at + 1..=at + 1 + len)?).ok()
}

/// Writes `data` in full to the frame stream, retrying short writes and
/// interruptions. A stream failure is a gone parent, reported as
/// [`ExportStep::Stream`].
fn put(stream: BorrowedFd<'_>, data: &[u8]) -> Result<(), (ExportStep, Errno)> {
    frame::write_full(stream, data).map_err(|e| (ExportStep::Stream, e))
}

/// Writes a `u16` length prefix and the bytes it counts.
fn put_bytes_u16(stream: BorrowedFd<'_>, data: &[u8]) -> Result<(), (ExportStep, Errno)> {
    frame::write_bytes_u16(stream, data).map_err(|e| (ExportStep::Stream, e))
}

/// Emits a lone tag byte (a directory-leave or the terminator), checked.
fn emit_tag_checked(stream: BorrowedFd<'_>, tag: u8) -> Result<(), (ExportStep, Errno)> {
    put(stream, &[tag])
}

/// The failure an export child put on the stream before it reached the gate, or
/// `None` where it put nothing there.
///
/// Read without blocking, because neither a frame nor an end of input is
/// guaranteed to arrive: a sibling process the caller forked concurrently holds
/// its own copy of the child's write end — a fork copies the whole
/// descriptor table — so even a dead child's end-of-file can be held off
/// indefinitely. The child is already dead by the time this runs, so whatever it
/// wrote is queued in full: an error frame is one write of at most
/// [`ERROR_FRAME_MAX`] bytes, well under `PIPE_BUF`, and a pipe write that
/// small is atomic.
///
/// Only an error frame is read back, and one naming no entry, since a child
/// that has not reached the gate has not reached the tree either. A child past
/// the gate is walking rather than reporting, and this runs only for one that
/// never got there.
fn early_report(stream: BorrowedFd<'_>) -> Option<StartError> {
    // The descriptor belongs to a `start_export` that is on its way to
    // returning an error, so it is dropped rather than restored to blocking.
    fs::fcntl_setfl(stream, OFlags::NONBLOCK).ok()?;
    let mut error = [0u8; 1 + frame::RECORD_LEN + 2];
    let read = frame::retry_on_intr!(rustix::io::read(stream, &mut error)).ok()?;
    let [tag, rest @ ..] = error;
    let (record, unnamed) = rest.split_at(frame::RECORD_LEN);
    if read != error.len() || tag != FRAME_ERROR || unnamed != [0, 0] {
        return None;
    }
    let (wire, errno) = frame::decode_record(record.try_into().ok()?);
    Some(StartError::Reported {
        step: ExportStep::from_wire(wire)?,
        errno: Errno::from_raw_os_error(errno),
    })
}

/// Emits a lone tag byte, best-effort (the terminator, where a gone parent is
/// already the caller's problem).
fn emit_tag(stream: BorrowedFd<'_>, tag: u8) {
    let _ = frame::write_full(stream, &[tag]);
}

/// The most bytes an error frame takes: the tag, the outcome record, and a
/// name of [`NAME_MAX`] behind its two length bytes.
const ERROR_FRAME_MAX: usize = 1 + frame::RECORD_LEN + 2 + NAME_MAX;

/// Emits an error frame: the tag, the outcome record naming the step and the
/// errno, and `name`, the entry it was met on, empty where none was.
///
/// One write, of at most [`ERROR_FRAME_MAX`] bytes, which is under `PIPE_BUF`,
/// so the frame arrives whole or not at all.
fn emit_error(stream: BorrowedFd<'_>, step: ExportStep, errno: Errno, name: &[u8]) {
    let name = &name[..name.len().min(NAME_MAX)];
    let mut error = [0u8; ERROR_FRAME_MAX];
    error[0] = FRAME_ERROR;
    error[1..=frame::RECORD_LEN]
        .copy_from_slice(&frame::encode_record(step.wire(), errno.raw_os_error()));
    let at = 1 + frame::RECORD_LEN;
    error[at..at + 2].copy_from_slice(&(name.len() as u16).to_le_bytes());
    error[at + 2..at + 2 + name.len()].copy_from_slice(name);
    let _ = frame::write_full(stream, &error[..at + 2 + name.len()]);
}

/// Sends a signal to the export child, used to tear it down when the parent
/// abandons the archive early.
pub(crate) fn kill_export(export: &ExportChild) {
    export.child.kill();
}

#[cfg(test)]
mod tests {
    use std::io::Read;

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
    fn export_step_wire_round_trip() {
        for &step in ExportStep::ALL {
            assert_eq!(ExportStep::from_wire(step.wire()), Some(step));
            assert!(!step.describe().is_empty(), "{step:?} describes itself");
        }
    }

    #[test]
    fn export_step_unknown_wire_value_is_rejected() {
        assert_eq!(ExportStep::from_wire(ExportStep::past_the_last()), None);
        assert_eq!(ExportStep::from_wire(u32::MAX), None);
    }

    /// A frame stream into a scratch file, which no reader has to drain.
    fn stream_into(dir: &std::path::Path) -> OwnedFd {
        fs::open(
            dir.join("stream"),
            OFlags::CREATE | OFlags::RDWR | OFlags::TRUNC | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("the stream file opens")
    }

    /// What was written to a stream from `stream_into`.
    fn written(dir: &std::path::Path) -> Vec<u8> {
        std::fs::read(dir.join("stream")).expect("the stream file reads")
    }

    /// A file or a directory the parent skips crosses the stream as its
    /// metadata alone, and one it keeps with its data or its contents.
    #[test]
    fn what_the_parent_skips_does_not_cross_the_stream() {
        let dir = Scratch::new("export-replies");
        std::fs::create_dir_all(dir.join("tree/sub")).unwrap();
        std::fs::write(dir.join("tree/file"), b"data").unwrap();
        std::fs::write(dir.join("tree/sub/inner"), b"inner").unwrap();
        let tree = fs::open(
            dir.join("tree"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let visited = |name: &CStr, replies: &[u8]| {
            let stream = stream_into(&dir);
            let (read, write) = rustix::pipe::pipe().unwrap();
            frame::write_full(write.as_fd(), replies).unwrap();
            let walker = Walker::new(stream.as_fd(), read.as_fd(), true);
            let (mut names, mut order) = (vec![0u8; 4096], vec![0u32; 16]);
            let arena = Arena {
                names: &mut names,
                order: &mut order,
            };
            walker
                .visit_entry(tree.as_fd(), name, 0, arena)
                .expect("the entry is visited");
            written(&dir)
        };
        let ends_with = |stream: &[u8], tail: &[u8]| stream.ends_with(tail);

        let sent = visited(c"file", &[REPLY_SEND]);
        assert!(ends_with(&sent, b"data\0"), "{sent:?}");
        let skipped = visited(c"file", &[REPLY_SKIP]);
        assert_eq!(skipped.len(), sent.len() - b"data\0".len());
        assert_eq!(skipped, sent[..skipped.len()]);

        // A directory kept is walked, its file asked of in turn.
        let walked = visited(c"sub", &[REPLY_SEND, REPLY_SEND]);
        assert!(ends_with(
            &walked,
            &[b'i', b'n', b'n', b'e', b'r', 0, FRAME_LEAVE]
        ));
        // One skipped is its own frame and its leave, with nothing between.
        let pruned = visited(c"sub", &[REPLY_SKIP]);
        let (leave, meta) = pruned.split_last().expect("the directory is emitted");
        assert_eq!(*leave, FRAME_LEAVE);
        assert_eq!(meta, &walked[..meta.len()]);
        assert_eq!(walked[meta.len()], FRAME_FILE);
    }

    /// A file streams exactly its declared size whatever it holds, and the
    /// status byte after the data says whether that was all of it.
    #[test]
    fn a_file_that_changed_size_is_flagged_after_its_data() {
        let dir = Scratch::new("export-status");
        std::fs::write(dir.join("file"), b"12345").unwrap();
        for (declared, data, status) in [
            (5, &b"12345"[..], 0),
            (8, b"12345\0\0\0", 1),
            (3, b"123", 1),
        ] {
            let stream = stream_into(&dir);
            let file = fs::open(
                dir.join("file"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let (replies, _) = rustix::pipe::pipe().unwrap();
            Walker::new(stream.as_fd(), replies.as_fd(), false)
                .stream_data(file.as_fd(), declared)
                .expect("the data streams");
            let mut expected = data.to_vec();
            expected.push(status);
            assert_eq!(written(&dir), expected, "declared {declared}");
        }
    }

    /// A directory with more entries than the arena holds is refused before
    /// anything of it is emitted, rather than walked out of order.
    #[test]
    fn a_directory_the_arena_cannot_hold_is_refused() {
        let dir = Scratch::new("export-crowded");
        std::fs::create_dir(dir.join("tree")).unwrap();
        // Created out of order, so neither the order a filesystem lists them
        // in by creation nor its reverse is the sorted one.
        for name in ["entry-c", "entry-a", "entry-e", "entry-b", "entry-d"] {
            std::fs::write(dir.join("tree").join(name), b"x").unwrap();
        }
        let tree = fs::open(
            dir.join("tree"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let stream = stream_into(&dir);
        let (replies, _) = rustix::pipe::pipe().unwrap();
        let walker = Walker::new(stream.as_fd(), replies.as_fd(), false);

        let (mut names, mut order) = (vec![0u8; 4096], vec![0u32; 4]);
        let arena = Arena {
            names: &mut names,
            order: &mut order,
        };
        assert_eq!(
            walker.walk_dir(tree.as_fd(), 0, arena),
            Err((ExportStep::Crowded, Errno::NOBUFS)),
        );
        let (mut names, mut order) = (vec![0u8; 8], vec![0u32; 16]);
        let arena = Arena {
            names: &mut names,
            order: &mut order,
        };
        assert_eq!(
            walker.walk_dir(tree.as_fd(), 0, arena),
            Err((ExportStep::Crowded, Errno::NOBUFS)),
        );
        assert!(
            written(&dir).is_empty(),
            "the walk emitted part of a directory"
        );

        // With room, the same directory walks, in name order.
        let (mut names, mut order) = (vec![0u8; 4096], vec![0u32; 16]);
        let arena = Arena {
            names: &mut names,
            order: &mut order,
        };
        walker
            .walk_dir(tree.as_fd(), 0, arena)
            .expect("the directory walks");
        let frames = written(&dir);
        let mut seen = Vec::new();
        for name in ["entry-a", "entry-b", "entry-c", "entry-d", "entry-e"] {
            let at = frames
                .windows(name.len())
                .position(|window| window == name.as_bytes())
                .expect("every entry is emitted");
            seen.push(at);
        }
        assert!(
            seen.is_sorted(),
            "the entries are not in name order: {seen:?}"
        );
    }

    /// A failure on an entry names it, and one met inside a directory the
    /// walk descended into names nothing more: the parent holds that directory
    /// as current by then. The error frame carries the name.
    #[test]
    fn a_failure_names_the_entry_it_was_met_on() {
        let dir = Scratch::new("export-blame");
        std::fs::create_dir_all(dir.join("tree/crowded")).unwrap();
        for name in ["a", "b", "c"] {
            std::fs::write(dir.join("tree/crowded").join(name), b"x").unwrap();
        }
        let tree = fs::open(
            dir.join("tree"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let stream = stream_into(&dir);
        let (replies, _) = rustix::pipe::pipe().unwrap();
        let visit = |name: &CStr, order: usize| {
            let walker = Walker::new(stream.as_fd(), replies.as_fd(), false);
            let (mut names, mut order) = (vec![0u8; 4096], vec![0u32; order]);
            let arena = Arena {
                names: &mut names,
                order: &mut order,
            };
            let failed = walker.visit_entry(tree.as_fd(), name, 0, arena);
            let (blamed, len) = walker.blamed();
            (failed, blamed[..len].to_vec())
        };

        let (failed, blamed) = visit(c"absent", 16);
        assert_eq!(failed, Err((ExportStep::Stat, Errno::NOENT)));
        assert_eq!(blamed, b"absent");
        let (failed, blamed) = visit(c"crowded", 2);
        assert_eq!(failed, Err((ExportStep::Crowded, Errno::NOBUFS)));
        assert_eq!(blamed, b"", "the directory's own walk failed");

        // The frame: the tag, the record, and the name behind its length.
        let stream = stream_into(&dir);
        emit_error(stream.as_fd(), ExportStep::Stat, Errno::NOENT, b"absent");
        let frame = written(&dir);
        let at = 1 + frame::RECORD_LEN;
        assert_eq!(frame[0], FRAME_ERROR);
        assert_eq!(&frame[at..at + 2], &6u16.to_le_bytes());
        assert_eq!(&frame[at + 2..], b"absent");
    }

    /// The export child closes every descriptor it inherited but its own two.
    ///
    /// The consequence is the point: a caller that exports while a sandbox runs
    /// has a copy of that sandbox's control socket in the fork, and the
    /// supervisor's hangup detection — the whole of `stop_with_caller` — waits
    /// on the last copy closing. A pipe stands in for the socket here; once the
    /// caller drops its own end, the read end reaches end of stream only if the
    /// child has let go of its copy too.
    #[test]
    fn the_export_child_sweeps_the_descriptors_it_inherited() {
        if !ferroday_cage_testkit::require::userns() {
            // The child maps itself before it walks; without a user namespace
            // it fails before the sweep could matter.
            return;
        }

        let dir = Scratch::new("export-sweep");
        // Larger than a pipe's capacity, so the child is still blocked writing
        // frames while the check below runs. A tree the child could finish
        // streaming would close its inherited copy by exiting, and the check
        // would pass whether or not it ever swept.
        std::fs::write(dir.join("file"), vec![b'x'; 256 * 1024])
            .expect("the scratch file is writable");
        let rootfs = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();

        let (bystander_read, bystander_write) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).expect("a pipe is creatable");

        let (uid_line, gid_line) = crate::idmap::single_identity_lines();
        let child = start_export(
            &rootfs,
            ChildMap::SelfMap {
                uid_line: &uid_line,
                gid_line: &gid_line,
            },
            false,
        )
        .unwrap_or_else(|_| panic!("the export child starts"));

        // The caller's own copy goes; the child's is all that could keep the
        // pipe open now.
        drop(bystander_write);
        assert!(
            ferroday_cage_testkit::fd::readable_by(
                &bystander_read,
                std::time::Instant::now() + std::time::Duration::from_secs(10),
            ),
            "the export child still holds the caller's descriptor",
        );
        let mut byte = [0u8; 1];
        assert_eq!(
            rustix::io::read(&bystander_read, &mut byte),
            Ok(0),
            "the pipe reached end of stream, so no copy of the write end remains",
        );

        // Drain the stream so the blocked child reaches its end and can be
        // reaped.
        let mut frames = Vec::new();
        std::fs::File::from(
            child
                .stream()
                .try_clone_to_owned()
                .expect("the stream is cloneable"),
        )
        .read_to_end(&mut frames)
        .expect("the frame stream reads to its end");
        assert_eq!(frames.last(), Some(&FRAME_END), "the walk finished cleanly");
        child.finish().expect("the export child is reaped");
    }
}
