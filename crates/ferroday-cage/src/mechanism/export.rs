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
//! allocation, no locks, no panic, rustix syscalls only), and constant memory
//! besides the tree's own depth. It never assembles a path, tracks hardlinks,
//! or formats a tar header: those want a heap. It emits a flat stream of
//! [frames](#frame-protocol) instead, and the parent — in ordinary `std`
//! context, with an allocator — reassembles paths, coalesces hardlinks, and
//! encodes the archive (see [`provision::export`](crate::provision)).
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
//! - [`FRAME_FILE`]: a regular file. Its metadata, xattrs, and then exactly
//!   `size` bytes of data follow.
//! - [`FRAME_SYMLINK`]: a symbolic link. Its metadata and link target follow.
//! - [`FRAME_END`]: the walk finished cleanly.
//! - [`FRAME_ERROR`]: a syscall failed; a step discriminant and errno follow,
//!   and the child exits.
//!
//! Character and block devices, FIFOs, and sockets are skipped: a deployed OS
//! image carries none that a runtime does not provide, and the tar reader on
//! the other end drops them regardless.

use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RawDir};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use rustix::process::{Pid, Signal};
use rustix::runtime::{self, Fork};

use super::ChildMap;
use super::bounds::{DATA_BUF, LINK_BUF, MAX_DEPTH, NAME_MAX};
use super::child::MapFailure;
use super::frame;
use crate::idmap::IdMapError;
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
    pid: Pid,
    /// The read end of the frame stream.
    stream: OwnedFd,
}

impl ExportChild {
    /// The frame stream to read to [`FRAME_END`] or [`FRAME_ERROR`].
    pub(crate) fn stream(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
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
        super::wait_for_exit(self.pid).map(|_| ())
    }
}

/// Forks the export child and establishes its identity map.
///
/// On return the child is walking `rootfs` and streaming frames; the caller
/// reads [`ExportChild::stream`] to [`FRAME_END`] or [`FRAME_ERROR`], then
/// calls [`ExportChild::finish`]. A child-side walk failure surfaces in the
/// stream as [`FRAME_ERROR`], not here; this returns only spawn failures and, for
/// a delegated map, the delegate's own apply failure.
pub(crate) fn start_export(rootfs: &CStr, map: ChildMap<'_>) -> Result<ExportChild, StartError> {
    let (stream_read, stream_write) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(StartError::Spawn)?;

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
    match unsafe { runtime::kernel_fork() } {
        Err(errno) => Err(StartError::Spawn(errno)),
        Ok(Fork::Child(_)) => {
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
            let gate_child = gate.map(|(caller, child)| {
                drop(caller);
                child
            });
            export_child(stream_write.as_fd(), gate_child, rootfs, &map)
        }
        Ok(Fork::ParentOf(pid)) => {
            drop(stream_write);
            if let (Some((caller, child_end)), ChildMap::Delegated { mapper, map }) = (gate, &map) {
                drop(child_end);
                let driven = super::drive_map_gate(caller.as_fd(), pid, *mapper, map);
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
                    super::abandon_gated_child(pid);
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
                pid,
                stream: stream_read,
            })
        }
    }
}

/// The child: unshare, establish the map, walk, and stream. Never returns.
///
/// Takes the gate by value so the handshake can close it: past the go byte the
/// gate has nothing left to say, and the walk that follows is long.
fn export_child(
    stream: BorrowedFd<'_>,
    gate: Option<OwnedFd>,
    rootfs: &CStr,
    map: &ChildMap<'_>,
) -> ! {
    let fail = |step: ExportStep, errno: Errno| -> ! {
        emit_error(stream, step, errno);
        runtime::exit_group(1)
    };

    let keep = [
        stream.as_raw_fd(),
        gate.as_ref().map_or(-1 as RawFd, |gate| gate.as_raw_fd()),
    ];
    if let Err(failure) =
        super::child::enter_mapped_namespace(&keep, map.duty(), gate.as_ref().map(OwnedFd::as_fd))
    {
        match failure {
            // The caller left without applying the map; its own error is the
            // diagnostic, and it is no longer reading the stream a report
            // would travel on.
            MapFailure::Abandoned => runtime::exit_group(1),
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

    let walker = Walker { stream };
    match walker.walk_root(root.as_fd()) {
        Ok(()) => {
            emit_tag(stream, FRAME_END);
            runtime::exit_group(0)
        }
        Err((step, errno)) => fail(step, errno),
    }
}

/// The directory-iteration buffer, one per open level.
const DIRENTS_BUF: usize = 2048;
/// The bound on an extended-attribute name list and on a single value, both
/// capped by the kernel at 64 KiB.
const XATTR_BUF: usize = 65536;
/// How many successive names one scan of a directory collects.
///
/// A scan costs a full pass over the directory whatever it yields, so
/// collecting a batch divides the number of scans by this factor: a directory
/// of `n` entries costs `ceil(n / SUCCESSOR_BATCH)` scans rather than `n`. The
/// bound is stack, not correctness — the batch is
/// `SUCCESSOR_BATCH * (NAME_MAX + 1)` bytes live in every frame of a walk that
/// may recurse to [`MAX_DEPTH`] — so it stays modest.
const SUCCESSOR_BATCH: usize = 8;

/// Carries the frame stream through the recursive walk. Holds no growing
/// state: the only per-level memory is the directory-iteration buffer, and the
/// large metadata buffers live in the leaf helpers so they never span a
/// recursive call.
struct Walker<'a> {
    stream: BorrowedFd<'a>,
}

impl Walker<'_> {
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
    fn walk_root(&self, root: BorrowedFd<'_>) -> Result<(), (ExportStep, Errno)> {
        let stat = fs::fstat(root).map_err(|e| (ExportStep::Stat, e))?;
        self.emit_meta(FRAME_DIR, c".", &stat, Some(root))?;
        self.walk_dir(root, 0)?;
        emit_tag_checked(self.stream, FRAME_LEAVE)
    }

    /// Walks `dir` in sorted name order, emitting a frame per entry and
    /// descending into subdirectories. Symlinks are never followed and the walk
    /// never leaves the tree: every step opens a single component from the
    /// current descriptor.
    ///
    /// The order is deterministic so the archive is byte-reproducible, and it is
    /// produced without the heap the post-fork child cannot use (see the module
    /// docs). Rather than read a directory into a buffer and sort it, the walk
    /// visits entries by *successor scan*: it keeps the last name it emitted
    /// and, each pass, rescans the directory for the next
    /// [`SUCCESSOR_BATCH`] names strictly greater than it, in order. A
    /// directory's names are unique, so this is a total order and every entry is
    /// visited once.
    ///
    /// The cost is quadratic in a single directory's entry count — `n` entries
    /// cost `ceil(n / SUCCESSOR_BATCH)` passes over all `n` — which the batch
    /// reduces by a constant factor but does not remove. It is the price of a
    /// sorted walk in constant memory. A rootfs directory holding five figures
    /// of entries, such as a fully populated `/usr/share/man/man3`, is where it
    /// is felt.
    fn walk_dir(&self, dir: BorrowedFd<'_>, depth: u32) -> Result<(), (ExportStep, Errno)> {
        if depth as usize >= MAX_DEPTH {
            return Err((ExportStep::Depth, Errno::LOOP));
        }
        let mut buf = [MaybeUninit::uninit(); DIRENTS_BUF];
        // The last name emitted, and the batch of successors the current pass
        // collects: fixed buffers, so the walk allocates nothing.
        let mut last = [0u8; NAME_MAX + 1];
        let mut last_len = 0;
        let mut have_last = false;
        let mut batch = [[0u8; NAME_MAX + 1]; SUCCESSOR_BATCH];
        let mut lens = [0usize; SUCCESSOR_BATCH];
        loop {
            // Rewind, then scan for the smallest names strictly greater than
            // the last one emitted, keeping the batch sorted as it fills.
            let mut filled = 0;
            fs::seek(dir, fs::SeekFrom::Start(0)).map_err(|e| (ExportStep::ReadDir, e))?;
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
                if have_last && name <= &last[..last_len] {
                    continue;
                }
                // Past the batch's largest, with the batch full: not a
                // candidate for this pass.
                if filled == SUCCESSOR_BATCH && name >= &batch[filled - 1][..lens[filled - 1]] {
                    continue;
                }
                // Insertion sort into the batch. A full batch drops its
                // largest, which a later pass collects.
                let mut at = filled.min(SUCCESSOR_BATCH - 1);
                while at > 0 && name < &batch[at - 1][..lens[at - 1]] {
                    batch[at] = batch[at - 1];
                    lens[at] = lens[at - 1];
                    at -= 1;
                }
                batch[at][..name.len()].copy_from_slice(name);
                lens[at] = name.len();
                filled = (filled + 1).min(SUCCESSOR_BATCH);
            }
            if filled == 0 {
                return Ok(());
            }
            for slot in 0..filled {
                let len = lens[slot];
                // NUL-terminated for the `statat`/`openat` that follow.
                batch[slot][len] = 0;
                let name = CStr::from_bytes_with_nul(&batch[slot][..=len])
                    .map_err(|_| (ExportStep::ReadDir, Errno::INVAL))?;
                self.visit_entry(dir, name, depth)?;
            }
            // The batch's largest is the next pass's floor.
            last_len = lens[filled - 1];
            last[..last_len].copy_from_slice(&batch[filled - 1][..last_len]);
            have_last = true;
        }
    }

    /// Emits one entry: a directory, descending into it and closing with a
    /// leave; a regular file, followed by its data; or a symlink. Character and
    /// block devices, FIFOs, and sockets are dropped, as a deployed image's
    /// runtime provides its own.
    fn visit_entry(
        &self,
        dir: BorrowedFd<'_>,
        name: &CStr,
        depth: u32,
    ) -> Result<(), (ExportStep, Errno)> {
        let stat =
            fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| (ExportStep::Stat, e))?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                let child = fs::openat(
                    dir,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| (ExportStep::Open, e))?;
                // Emit the directory (with its xattrs) before descending; the
                // 64 KiB xattr buffers are freed on return, so they never
                // overlap the recursion's stack.
                self.emit_meta(FRAME_DIR, name, &stat, Some(child.as_fd()))?;
                self.walk_dir(child.as_fd(), depth + 1)?;
                emit_tag_checked(self.stream, FRAME_LEAVE)
            }
            FileType::RegularFile => {
                let file = fs::openat(
                    dir,
                    name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| (ExportStep::Open, e))?;
                self.emit_meta(FRAME_FILE, name, &stat, Some(file.as_fd()))?;
                self.stream_data(file.as_fd(), stat.st_size as u64)
            }
            FileType::Symlink => self.emit_symlink(dir, name, &stat),
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
            // `st_nlink` is u32 or u64 depending on rustix's `Stat` backing;
            // normalize to the 8-byte field the parent decodes.
            #[expect(clippy::useless_conversion)]
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
    fn emit_xattrs(&self, fd: BorrowedFd<'_>) -> Result<(), (ExportStep, Errno)> {
        let stream = self.stream;
        let mut names = [0u8; XATTR_BUF];
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

        let mut value = [0u8; XATTR_BUF];
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
    fn emit_symlink(
        &self,
        dir: BorrowedFd<'_>,
        name: &CStr,
        stat: &fs::Stat,
    ) -> Result<(), (ExportStep, Errno)> {
        let mut target = [0u8; LINK_BUF];
        let len = fs::readlinkat_raw(dir, name, &mut target[..]).map_err(|e| {
            let e = if e == Errno::RANGE {
                Errno::NAMETOOLONG
            } else {
                e
            };
            (ExportStep::ReadLink, e)
        })?;
        let stream = self.stream;
        put(stream, &[FRAME_SYMLINK])?;
        put_bytes_u16(stream, name.to_bytes())?;
        put(stream, &stat.st_mode.to_le_bytes())?;
        put(stream, &stat.st_uid.to_le_bytes())?;
        put(stream, &stat.st_gid.to_le_bytes())?;
        put(stream, &stat.st_mtime.to_le_bytes())?;
        put_bytes_u16(stream, &target[..len])
    }

    /// Streams exactly `size` bytes of a file's data. A file that reads short
    /// (a race against a live writer, which a quiesced rootfs is not) is
    /// zero-padded to the declared size, so the parent's framing stays in
    /// step.
    fn stream_data(&self, fd: BorrowedFd<'_>, size: u64) -> Result<(), (ExportStep, Errno)> {
        let stream = self.stream;
        let mut buf = [0u8; DATA_BUF];
        let mut remaining = size;
        while remaining > 0 {
            let want = remaining.min(DATA_BUF as u64) as usize;
            let got = loop {
                match rustix::io::read(fd, &mut buf[..want]) {
                    Ok(got) => break got,
                    Err(Errno::INTR) => continue,
                    Err(e) => return Err((ExportStep::ReadData, e)),
                }
            };
            if got == 0 {
                break;
            }
            put(stream, &buf[..got])?;
            remaining -= got as u64;
        }
        let zeros = [0u8; DATA_BUF];
        while remaining > 0 {
            let want = remaining.min(DATA_BUF as u64) as usize;
            put(stream, &zeros[..want])?;
            remaining -= want as u64;
        }
        Ok(())
    }
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
/// its own copy of the child's write end — `kernel_fork` copies the whole
/// descriptor table — so even a dead child's end-of-file can be held off
/// indefinitely. The child is already dead by the time this runs, so whatever it
/// wrote is queued in full: an error frame is nine bytes, well under `PIPE_BUF`,
/// and a pipe write that small is atomic.
///
/// Only an error frame is read back. A child past the gate is walking rather
/// than reporting, and this runs only for one that never got there.
fn early_report(stream: BorrowedFd<'_>) -> Option<StartError> {
    // The descriptor belongs to a `start_export` that is on its way to
    // returning an error, so it is dropped rather than restored to blocking.
    fs::fcntl_setfl(stream, OFlags::NONBLOCK).ok()?;
    let mut record = [0u8; 9];
    let read = frame::retry_on_intr!(rustix::io::read(stream, &mut record)).ok()?;
    if read != record.len() || record[0] != FRAME_ERROR {
        return None;
    }
    let wire = u32::from_le_bytes(record[1..5].try_into().expect("slice length is 4"));
    let errno = i32::from_le_bytes(record[5..9].try_into().expect("slice length is 4"));
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

/// Emits an error frame: the tag, the step discriminant, and the errno.
fn emit_error(stream: BorrowedFd<'_>, step: ExportStep, errno: Errno) {
    let mut record = [0u8; 9];
    record[0] = FRAME_ERROR;
    record[1..5].copy_from_slice(&step.wire().to_le_bytes());
    record[5..9].copy_from_slice(&errno.raw_os_error().to_le_bytes());
    let _ = frame::write_full(stream, &record);
}

/// Sends a signal to the export child, used to tear it down when the parent
/// abandons the archive early.
pub(crate) fn kill_export(child: &ExportChild) {
    let _ = rustix::process::kill_process(child.pid, Signal::KILL);
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use rustix::event::{PollFd, PollFlags, Timespec};

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
        if let Some(blocker) = crate::host::userns_blocker() {
            // The child maps itself before it walks; without a user namespace
            // it fails before the sweep could matter.
            eprintln!("skipping: unprivileged user namespaces are unavailable: {blocker}");
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

        let euid = rustix::process::geteuid().as_raw();
        let egid = rustix::process::getegid().as_raw();
        let uid_line = format!("0 {euid} 1\n").into_bytes();
        let gid_line = format!("0 {egid} 1\n").into_bytes();
        let child = start_export(
            &rootfs,
            ChildMap::SelfMap {
                uid_line: &uid_line,
                gid_line: &gid_line,
            },
        )
        .unwrap_or_else(|_| panic!("the export child starts"));

        // The caller's own copy goes; the child's is all that could keep the
        // pipe open now.
        drop(bystander_write);
        let mut fds = [PollFd::new(&bystander_read, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: 10,
            tv_nsec: 0,
        };
        rustix::event::poll(&mut fds, Some(&timeout)).expect("the poll completes");
        assert!(
            !fds[0].revents().is_empty(),
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
