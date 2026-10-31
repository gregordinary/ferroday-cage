//! Map-assisted copy into a rootfs: write a tree whose entries carry the
//! ownership the rootfs intends, not the ownership the calling user can set.
//!
//! The mirror image of [`export`](super::export). That module forks a child
//! into an identity map, walks a tree as root of the mapped namespace, and
//! streams frames *out* to a parent that reassembles paths and encodes tar.
//! This reverses the direction: the parent walks the host source — its own
//! tree, read unprivileged — and streams frames *in*, and the child creates
//! each entry with the ownership the frame names.
//!
//! The reason is the one `cp` cannot answer. A caller running as an ordinary
//! user cannot create a file owned by anyone else, so laying a tree into a
//! rootfs leaves every entry owned by the caller — which a range map then
//! presents as root inside. A tree that is meant to ship a file owned by a
//! target uid has no way to say so. A child re-entered into the map is root of
//! that namespace and can, exactly as the export child can *read* such a file.
//!
//! The division of labor is the export's, unchanged. The child does only the
//! privileged, must-be-in-map work — `mkdirat`, `openat`, `symlinkat`,
//! `mknodat`, `linkat`, `fchownat`, and writing file data — under the post-fork
//! discipline (no allocation, no locks, no panic, rustix syscalls only), and
//! constant memory besides the tree's own depth. It never assembles a path,
//! resolves a symlink, or decides what to copy: those want a heap, and they are
//! the parent's.
//!
//! # Frame protocol
//!
//! The parent writes little-endian frames to a stream pipe, each led by a
//! one-byte tag. Every frame names its own entry as a single path component,
//! never a path, which is most of the containment argument: the child creates
//! each entry with an `*at` call relative to the directory it currently holds
//! open, so there is no path for a `..` or a leading `/` to appear in.
//!
//! - [`COPY_DIR`]: enter a directory. Its name and metadata follow; the child
//!   creates it, opens it with `O_NOFOLLOW`, and every later frame lands inside
//!   it until the matching [`COPY_LEAVE`].
//! - [`COPY_LEAVE`]: the current directory is finished. The child applies its
//!   deferred ownership, mode, and modification time and closes it.
//! - [`COPY_FILE`]: a regular file. Its name, metadata, and then exactly `size`
//!   bytes of data follow.
//! - [`COPY_SYMLINK`]: a symbolic link. Its name, metadata, and target follow.
//!   The child applies the ownership and the modification time; the mode goes
//!   unused, since the kernel fixes a symlink's own at 0777.
//! - [`COPY_FIFO`]: a named pipe. Its name and metadata follow, and the child
//!   applies them through a descriptor for the pipe it created, opened without
//!   waiting for a peer that a copy has no reason to expect.
//! - [`COPY_LINK`]: a second or later name for a file already created. Its own
//!   name and the first name's path, relative to the destination root, follow.
//!   Metadata is the inode's and is already applied, so none is sent.
//! - [`COPY_END`]: the tree is finished.
//!
//! [`COPY_LINK`] is the one frame that carries a path rather than a single
//! component, because a hard link's two names may sit in different directories
//! and only the parent's walk knows where the first one was. Containment there
//! rests on three things together, and none of them suffices alone:
//!
//! 1. The child refuses an absolute anchor and any component that is empty,
//!    `.`, or `..`, so the path cannot be written to climb.
//! 2. The link is made without `AT_SYMLINK_FOLLOW`, so the *final* component is
//!    never traversed.
//! 3. `linkat` still resolves the anchor's *intermediate* components, and every
//!    directory along that path was created and opened by this same walk with
//!    `O_NOFOLLOW` — so none of them is a symlink, and the resolution cannot
//!    leave the tree part way along.
//!
//! The third is the load-bearing one for intermediate components, and it is a
//! property of the walk rather than of the frame: a change that let the child
//! link against a path it did not itself create would lose it while the first
//! two still appeared to hold.
//!
//! What remains is a concurrent writer inside the destination: nothing stops a
//! separate process replacing one of those directories with a symlink between
//! the walk creating it and the link being made. The whole copy shares that
//! exposure — the file path unlinks and recreates by name too — and it is
//! bounded by the destination being a tree the caller owns and is building.
//!
//! The child reports its outcome as an 8-byte record on the gate — the step it
//! failed at and the errno — exactly as the removal child does, rather than as
//! a frame: the data pipe runs the other way, so there is nothing to write a
//! frame to.

use std::ffi::CStr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{self, AtFlags, Mode, OFlags, Timestamps};
use rustix::io::Errno;
use rustix::net::{AddressFamily, RecvFlags, SocketFlags, SocketType};
use rustix::process::{Pid, Signal};

use super::ChildMap;
use super::bounds::{DATA_BUF, LINK_BUF, MAX_DEPTH, NAME_MAX};
use super::child::MapFailure;
use super::frame;
use super::sys::{self, Fork};
use crate::idmap::IdMapError;
use crate::path;
use crate::wire::wire_enum;

/// Frame tag: enter a directory.
pub(crate) const COPY_DIR: u8 = 1;
/// Frame tag: the current directory is finished.
pub(crate) const COPY_LEAVE: u8 = 2;
/// Frame tag: a regular file, followed by its data.
pub(crate) const COPY_FILE: u8 = 3;
/// Frame tag: a symbolic link, followed by its target.
pub(crate) const COPY_SYMLINK: u8 = 4;
/// Frame tag: the tree is finished.
pub(crate) const COPY_END: u8 = 5;
/// Frame tag: a named pipe.
pub(crate) const COPY_FIFO: u8 = 6;
/// Frame tag: another name for a file already created, followed by the first
/// name's path relative to the destination root.
pub(crate) const COPY_LINK: u8 = 7;

wire_enum! {
    /// What the copy child was doing when a syscall failed.
    ///
    /// The explicit discriminants are the outcome record's wire encoding, which
    /// both ends of a single build write and read. They are not a stable
    /// protocol and they are not declaration order: a step added in a later
    /// release takes the next free value rather than renumbering the ones it
    /// was declared among.
    pub(crate) enum CopyStep {
        map {
            ResetSignals = 1 => "resetting the copy process's signal dispositions",
            SweepFds = 2 => "closing the copy process's inherited descriptors",
            Unshare = 3 => "unsharing the copy process's user namespace",
            DenySetgroups = 4 => "denying setgroups in the copy process's user namespace",
            WriteGidMap = 19 => "writing the copy process's gid map",
            WriteUidMap = 20 => "writing the copy process's uid map",
            AwaitMap = 5 => "waiting for the identity map to be applied",
        }
        /// Forking the copy process or speaking to it. Reported by the caller
        /// alone: the child has no channel to report it on.
        Spawn = 0 => "forking the copy process",
        /// The destination rootfs could not be opened.
        OpenRoot = 6 => "opening the destination rootfs",
        /// A frame could not be read from the parent.
        ReadFrame = 7 => "reading the tree to copy",
        /// A directory could not be created.
        Mkdir = 8 => "creating a directory",
        /// A directory could not be opened after creation.
        OpenDir = 9 => "opening a directory just created",
        /// A file could not be created.
        Create = 10 => "creating a file",
        /// A file's data could not be written.
        Write = 11 => "writing a file's contents",
        /// A symbolic link could not be created.
        Symlink = 12 => "creating a symbolic link",
        /// A named pipe could not be created.
        Fifo = 17 => "creating a named pipe",
        /// A second name for an already-created file could not be linked.
        Link = 18 => "linking a second name onto a file already copied",
        /// An entry's ownership could not be applied.
        Chown = 16 => "setting an entry's ownership, which an id the identity map cannot express refuses",
        /// An entry's mode or modification time could not be applied.
        Metadata = 13 => "applying an entry's mode or modification time",
        /// The tree is deeper than the copy descends.
        TooDeep = 14 => "descending into the source tree",
        /// A frame named something that is not a single path component.
        BadName = 15 => "reading an entry's name",
    }
}

/// Why a copy failed.
#[derive(Debug)]
pub(crate) enum CopyFailure {
    /// A step failed with an OS error.
    Step {
        /// What the copy was doing.
        step: CopyStep,
        /// The raw OS error.
        errno: i32,
    },
    /// The identity map could not be applied by the delegate.
    Map(IdMapError),
    /// The child's outcome record named no step this build carries, so the
    /// record is malformed.
    Malformed,
}

/// The started copy child: the frame stream to write, and the gate its outcome
/// arrives on.
pub(crate) struct CopyChild {
    /// The child process.
    pid: Pid,
    /// The write end of the frame stream.
    stream: OwnedFd,
    /// The caller's end of the control socket.
    gate: OwnedFd,
}

impl CopyChild {
    /// The frame stream to write the tree to.
    pub(crate) fn stream(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }

    /// Closes the frame stream, which is what tells the child the tree is over,
    /// then reads the child's outcome and reaps it.
    ///
    /// Called once, after the last frame. The stream must close before the
    /// outcome is read: the child is reading frames until end of input, so a
    /// held-open stream would deadlock both sides.
    pub(crate) fn finish(self) -> Result<(), CopyFailure> {
        let CopyChild { pid, stream, gate } = self;
        drop(stream);

        let mut record = [0u8; super::RECORD_LEN];
        let read = loop {
            match rustix::io::read(&gate, &mut record) {
                Ok(n) => break n,
                Err(Errno::INTR) => continue,
                Err(errno) => {
                    let _ = super::wait_for_exit(pid);
                    return Err(CopyFailure::Step {
                        step: CopyStep::Spawn,
                        errno: errno.raw_os_error(),
                    });
                }
            }
        };
        let outcome = super::wait_for_exit(pid);
        if read != record.len() {
            // The child died without reporting, or reported something that is
            // not a record. Its exit status is all there is to go on either
            // way: a clean exit here would mean it finished the tree and lost
            // only the record, which is not something to claim. The length is
            // checked rather than only the end of input because this is a
            // seqpacket — a short message is delivered whole and would
            // otherwise decode against the zero-filled rest of the buffer as a
            // step this child never reached, with errno 0. The gate's other two
            // readers hold the same line.
            let _ = outcome;
            return Err(CopyFailure::Step {
                step: CopyStep::Spawn,
                errno: Errno::PIPE.raw_os_error(),
            });
        }
        decode_record(record)
    }

    /// Kills and reaps the child, for a parent abandoning the copy part-way,
    /// handing back the outcome the child had already reported.
    ///
    /// A parent abandons for one of two disjoint reasons, and the useful
    /// diagnostic differs between them. When a frame write failed, the child is
    /// already gone — a write fails only once the child has closed the stream,
    /// which it does by exiting, and it reports before it exits — so the record
    /// names the step that actually failed where the parent's own `EPIPE` names
    /// nothing. When the parent's walk failed on its own terms, the child is
    /// alive and mid-tree with nothing to report, and the parent's error is the
    /// whole story.
    ///
    /// The read below tells them apart without waiting on either.
    pub(crate) fn abandon(self) -> Option<CopyFailure> {
        let CopyChild { pid, stream, gate } = self;
        let reported = reported_outcome(gate.as_fd());
        let _ = rustix::process::kill_process(pid, Signal::KILL);
        drop(stream);
        drop(gate);
        let _ = super::wait_for_exit(pid);
        reported
    }
}

/// Takes an outcome record the child has already sent, without waiting for one.
///
/// `MSG_DONTWAIT` rather than a blocking read, because neither a record nor an
/// end of input is guaranteed to arrive: a child killed part-way through the
/// tree may never report, and a sibling process this caller forked concurrently
/// holds its own copy of the child's gate end — a fork copies the whole
/// descriptor table — so even a dead child's end-of-file can be held off
/// indefinitely.
///
/// A record that decodes to success cannot arise here: the child writes one only
/// after a `COPY_END` frame, which a parent that is abandoning the copy never
/// sent. It is reported as no outcome rather than treated as a case of its own.
fn reported_outcome(gate: BorrowedFd<'_>) -> Option<CopyFailure> {
    let mut record = [0u8; super::RECORD_LEN];
    // `EAGAIN`: nothing is queued, so the child has reported nothing.
    let (received, _) = frame::retry_on_intr!(rustix::net::recv(
        gate,
        &mut record[..],
        RecvFlags::DONTWAIT
    ))
    .ok()?;
    if received != record.len() {
        return None;
    }
    decode_record(record).err()
}

/// Reads an 8-byte outcome record: a step discriminant and an errno, with a
/// zero step meaning success.
fn decode_record(record: [u8; super::RECORD_LEN]) -> Result<(), CopyFailure> {
    let wire = u32::from_le_bytes(record[0..4].try_into().expect("slice length is 4"));
    let errno = i32::from_le_bytes(record[4..8].try_into().expect("slice length is 4"));
    if wire == OUTCOME_OK {
        return Ok(());
    }
    let Some(step) = CopyStep::from_wire(wire) else {
        return Err(CopyFailure::Malformed);
    };
    Err(CopyFailure::Step { step, errno })
}

/// The outcome discriminant that means the copy finished: distinct from every
/// step's wire value, which start at zero.
const OUTCOME_OK: u32 = u32::MAX;

/// Forks the copy child into `map` and returns the handle to stream a tree to.
///
/// `rootfs` is the destination, which must already exist. The child holds it
/// open as a directory and creates every entry beneath it relative to that
/// descriptor.
pub(crate) fn start_copy_in(rootfs: &CStr, map: ChildMap<'_>) -> Result<CopyChild, CopyFailure> {
    let spawn_failure = |errno: Errno| CopyFailure::Step {
        step: CopyStep::Spawn,
        errno: errno.raw_os_error(),
    };

    let (stream_read, stream_write) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(spawn_failure)?;
    // One seqpacket pair carries the control conversation: ready out and go back
    // for a delegated map, then the outcome record either way. Unlike the
    // export's gate this is always created, since the outcome has nowhere else
    // to go — the data pipe runs the other way.
    let (gate_caller, gate_child) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(spawn_failure)?;

    // SAFETY: the child branch runs `copy_child`, which performs raw rustix
    // syscalls over the frozen paths and descriptors — no allocation, no
    // locking, no panic — and never returns: every path ends in `exit_group`.
    match unsafe { sys::fork() } {
        Err(errno) => Err(spawn_failure(errno)),
        Ok(Fork::Child) => {
            // The fork duplicated the caller's ends into this process. Closing
            // the write end of its own frame pipe is what lets the child see
            // end of input when the parent is done; holding it would make the
            // read block forever. Closing an owned descriptor is a bare
            // `close`, which the post-fork discipline permits; everything else
            // the caller had open is closed by the sweep inside `copy_child`.
            drop(stream_write);
            drop(gate_caller);
            copy_child(stream_read.as_fd(), gate_child.as_fd(), rootfs, &map)
        }
        Ok(Fork::ParentOf(pid)) => {
            drop(stream_read);
            drop(gate_child);
            if let ChildMap::Delegated { mapper, map } = &map {
                let driven = super::drive_map_gate(gate_caller.as_fd(), pid, *mapper, map);
                // Anything but a released child leaves one blocked at the gate
                // in an unmapped namespace, having created nothing.
                let failure = match driven {
                    Ok(super::Gated::Released) => None,
                    // A record before ready is a failure the child hit on the
                    // way to the gate — its sweep, or its unshare — and it
                    // names the step it reached. Decoding it here is what keeps
                    // that diagnostic rather than reporting a child that
                    // vanished.
                    Ok(super::Gated::EarlyRecord(record)) => {
                        // A success record before ready is not something a
                        // child sends; it is a malformed conversation.
                        Some(
                            decode_record(record)
                                .err()
                                .unwrap_or(CopyFailure::Malformed),
                        )
                    }
                    Ok(super::Gated::ChildLost) => Some(CopyFailure::Step {
                        step: CopyStep::AwaitMap,
                        errno: Errno::PROTO.raw_os_error(),
                    }),
                    Err(super::GateFailure::Io(errno)) => Some(CopyFailure::Step {
                        step: CopyStep::AwaitMap,
                        errno: errno.raw_os_error(),
                    }),
                    Err(super::GateFailure::Map(err)) => Some(CopyFailure::Map(err)),
                };
                if let Some(err) = failure {
                    drop(gate_caller);
                    drop(stream_write);
                    super::abandon_gated_child(pid);
                    return Err(err);
                }
            }
            Ok(CopyChild {
                pid,
                stream: stream_write,
                gate: gate_caller,
            })
        }
    }
}

/// The child: unshare, gate, create, report. Never returns.
fn copy_child(
    stream: BorrowedFd<'_>,
    gate: BorrowedFd<'_>,
    rootfs: &CStr,
    map: &ChildMap<'_>,
) -> ! {
    let fail = |step: CopyStep, errno: Errno| -> ! {
        report(gate, step.wire(), errno.raw_os_error());
        sys::exit_group(1)
    };

    // The gate is kept: unlike the export's, it is also the channel the
    // outcome record goes back on.
    let keep = [stream.as_raw_fd(), gate.as_raw_fd()];
    if let Err(failure) = super::child::enter_mapped_namespace(&keep, map.duty(), Some(gate)) {
        match failure {
            // The caller left without applying the map; its own error is the
            // diagnostic, and the gate a report would travel on is closed.
            MapFailure::Abandoned => sys::exit_group(1),
            MapFailure::Step(step, errno) => fail(step.into(), errno),
        }
    }

    let root = match fs::open(
        rootfs,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(errno) => fail(CopyStep::OpenRoot, errno),
    };

    match consume(stream, root) {
        Ok(()) => {
            report(gate, OUTCOME_OK, 0);
            sys::exit_group(0)
        }
        Err((step, errno)) => fail(step, errno),
    }
}

/// Reads frames until end of input and creates what they name.
///
/// The directory stack is the only state that grows, and it is bounded by
/// [`MAX_DEPTH`]. Deferred metadata rides alongside each open directory: a
/// directory's own mode is applied on the way out, because a mode denying write
/// would otherwise stop its contents being created, and its modification time
/// last of all, because creating those contents changes it.
///
/// The root descriptor is duplicated before the walk begins. Every other
/// descriptor moves onto the stack as the walk descends, but a [`COPY_LINK`]
/// resolves its anchor from the root, so one copy has to stay put for the
/// whole tree.
fn consume(stream: BorrowedFd<'_>, root: OwnedFd) -> Result<(), (CopyStep, Errno)> {
    let anchor_root = rustix::io::dup(&root).map_err(|errno| (CopyStep::OpenRoot, errno))?;
    let mut stack: [Option<Level>; MAX_DEPTH] = [const { None }; MAX_DEPTH];
    let mut depth: usize = 0;
    let mut current = root;

    loop {
        let mut tag = [0u8; 1];
        match frame::read_full_or_eof(stream, &mut tag) {
            Ok(true) => {}
            // End of input with no COPY_END: the parent died. Report it rather
            // than claiming the tree was copied.
            Ok(false) => return Err((CopyStep::ReadFrame, Errno::PIPE)),
            Err(errno) => return Err((CopyStep::ReadFrame, errno)),
        }
        match tag[0] {
            COPY_END => {
                // The stream ends where it began. A COPY_END with directories
                // still open would leave every one of them at its creation
                // mode 0700 with no ownership or modification time applied,
                // reported to the caller as a complete copy — the one
                // malformed shape in this loop that could pass for success.
                if depth != 0 {
                    return Err((CopyStep::ReadFrame, Errno::INVAL));
                }
                return Ok(());
            }
            COPY_DIR => {
                let (name, meta) = read_named(stream)?;
                if depth >= MAX_DEPTH {
                    return Err((CopyStep::TooDeep, Errno::NAMETOOLONG));
                }
                let name = name.component()?;
                // Created 0700 and widened on the way out: a directory whose
                // final mode denies the owner write cannot have its contents
                // created under it.
                match fs::mkdirat(&current, name, Mode::from_bits_truncate(0o700)) {
                    Ok(()) => {}
                    // An entry the destination already carries is kept, as the
                    // extraction path keeps one: the copy adds to a rootfs
                    // rather than replacing it.
                    Err(Errno::EXIST) => {}
                    Err(errno) => return Err((CopyStep::Mkdir, errno)),
                }
                // O_NOFOLLOW is the containment: an existing symlink here is
                // refused rather than followed out of the tree.
                let opened = fs::openat(
                    &current,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|errno| (CopyStep::OpenDir, errno))?;
                stack[depth] = Some(Level {
                    parent: std::mem::replace(&mut current, opened),
                    meta,
                });
                depth += 1;
            }
            COPY_LEAVE => {
                if depth == 0 {
                    return Err((CopyStep::ReadFrame, Errno::INVAL));
                }
                depth -= 1;
                let level = stack[depth]
                    .take()
                    .ok_or((CopyStep::ReadFrame, Errno::INVAL))?;
                apply_meta(current.as_fd(), &level.meta)?;
                current = level.parent;
            }
            COPY_FILE => {
                let (name, meta) = read_named(stream)?;
                let mut size = [0u8; 8];
                read_full(stream, &mut size)?;
                let size = u64::from_le_bytes(size);
                let name = name.component()?;
                // O_EXCL after an unlink, rather than O_TRUNC: an existing
                // entry may be a symlink, and truncating through one would
                // write outside the tree.
                match fs::unlinkat(&current, name, AtFlags::empty()) {
                    Ok(()) | Err(Errno::NOENT) => {}
                    Err(errno) => return Err((CopyStep::Create, errno)),
                }
                let file = fs::openat(
                    &current,
                    name,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(0o600),
                )
                .map_err(|errno| (CopyStep::Create, errno))?;
                copy_data(stream, file.as_fd(), size)?;
                apply_meta(file.as_fd(), &meta)?;
            }
            COPY_SYMLINK => {
                let (name, meta) = read_named(stream)?;
                let mut raw = [0u8; LINK_BUF];
                let len = read_bytes_u16(stream, &mut raw)?.len();
                let mut terminated = [0u8; LINK_BUF + 1];
                let target = cstr_in(&mut terminated, &raw[..len])?;
                let name = name.component()?;
                match fs::unlinkat(&current, name, AtFlags::empty()) {
                    Ok(()) | Err(Errno::NOENT) => {}
                    Err(errno) => return Err((CopyStep::Symlink, errno)),
                }
                fs::symlinkat(target, &current, name)
                    .map_err(|errno| (CopyStep::Symlink, errno))?;
                // A symlink carries ownership and a modification time but no
                // mode: the kernel fixes a symlink's mode at 0777 and ignores an
                // attempt to change it. Both calls resolve the name without
                // following it, so they act on the link rather than on whatever
                // it points at.
                fs::chownat(
                    &current,
                    name,
                    Some(rustix::fs::Uid::from_raw(meta.uid)),
                    Some(rustix::fs::Gid::from_raw(meta.gid)),
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(|errno| (CopyStep::Chown, errno))?;
                set_times_at(&current, name, meta.mtime)?;
            }
            COPY_FIFO => {
                let (name, meta) = read_named(stream)?;
                let name = name.component()?;
                match fs::unlinkat(&current, name, AtFlags::empty()) {
                    Ok(()) | Err(Errno::NOENT) => {}
                    Err(errno) => return Err((CopyStep::Fifo, errno)),
                }
                // Created 0600 and widened below, for the reason a directory
                // is: the copy owns the window between creation and the final
                // mode, and a permissive one should not exist inside it.
                fs::mknodat(
                    &current,
                    name,
                    rustix::fs::FileType::Fifo,
                    Mode::from_bits_truncate(0o600),
                    0,
                )
                .map_err(|errno| (CopyStep::Fifo, errno))?;
                // Applied through a descriptor, as every other entry's is, so
                // a source-chosen mode lands on this pipe and on nothing a
                // racer put at the name since.
                let fifo = open_created_fifo(&current, name)?;
                apply_meta(fifo.as_fd(), &meta)?;
            }
            COPY_LINK => {
                let name = read_bare_name(stream)?;
                let mut raw = [0u8; LINK_BUF + 1];
                let len = read_bytes_u16(stream, &mut raw[..LINK_BUF])?.len();
                raw[len] = 0;
                let anchor = contained_path(&raw[..=len])?;
                let name = name.component()?;
                match fs::unlinkat(&current, name, AtFlags::empty()) {
                    Ok(()) | Err(Errno::NOENT) => {}
                    Err(errno) => return Err((CopyStep::Link, errno)),
                }
                // No `AT_SYMLINK_FOLLOW`, so the final component is not
                // traversed. The intermediate ones are, by `linkat` itself —
                // they are safe because this same walk created each of those
                // directories and opened it with `O_NOFOLLOW`, not because the
                // anchor was checked. See the module doc.
                //
                // The link shares the anchor's inode, so it carries the
                // ownership, mode, and modification time already applied to
                // it — there is nothing further to set, which is the whole
                // point of recording it as a link.
                fs::linkat(&anchor_root, anchor, &current, name, AtFlags::empty())
                    .map_err(|errno| (CopyStep::Link, errno))?;
            }
            _ => return Err((CopyStep::ReadFrame, Errno::INVAL)),
        }
    }
}

/// One open directory on the stack: the parent it was opened from, and the
/// metadata to apply when it is left.
struct Level {
    parent: OwnedFd,
    meta: Meta,
}

/// An entry's ownership, mode, and modification time, as a frame carries them.
#[derive(Clone, Copy)]
struct Meta {
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
}

/// Applies ownership, then mode, then modification time to an open entry.
///
/// Ownership first: a `chown` clears the setuid and setgid bits, so applying
/// the mode afterwards is what keeps a setgid helper setgid.
fn apply_meta(fd: BorrowedFd<'_>, meta: &Meta) -> Result<(), (CopyStep, Errno)> {
    // The ids come from the source tree's own metadata and mean whatever the
    // rootfs means by them, which is the point: inside the map this process is
    // root and may set any of them.
    fs::fchown(
        fd,
        Some(rustix::fs::Uid::from_raw(meta.uid)),
        Some(rustix::fs::Gid::from_raw(meta.gid)),
    )
    .map_err(|errno| (CopyStep::Chown, errno))?;
    fs::fchmod(fd, Mode::from_bits_truncate(meta.mode & 0o7777))
        .map_err(|errno| (CopyStep::Metadata, errno))?;
    let stamp = rustix::fs::Timespec {
        tv_sec: meta.mtime,
        tv_nsec: 0,
    };
    fs::futimens(
        fd,
        &Timestamps {
            last_access: stamp,
            last_modification: stamp,
        },
    )
    .map_err(|errno| (CopyStep::Metadata, errno))
}

/// Opens the named pipe `name` this walk just created in `dir`, so its
/// metadata can be applied through a descriptor.
///
/// `O_RDONLY | O_NONBLOCK` opens a pipe at once, whether or not anything holds
/// its other end. `O_NOFOLLOW` refuses a name a racer replaced with a symbolic
/// link since the `mknodat`, and `O_NOCTTY` keeps a terminal put there from
/// becoming this process's controlling one before the check below refuses it.
/// Anything that is not a pipe is `EEXIST`: the name no longer holds the entry
/// this created.
fn open_created_fifo(dir: &OwnedFd, name: &CStr) -> Result<OwnedFd, (CopyStep, Errno)> {
    let fifo = fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| (CopyStep::Fifo, errno))?;
    let stat = fs::fstat(&fifo).map_err(|errno| (CopyStep::Fifo, errno))?;
    if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::Fifo {
        return Err((CopyStep::Fifo, Errno::EXIST));
    }
    Ok(fifo)
}

/// Applies a modification time to an entry named relative to an open directory,
/// without following a symbolic link.
///
/// The access time is set alongside it, to the same value: a copy has no access
/// time of its own to carry, and leaving it at the moment of the copy would make
/// the destination differ from run to run.
fn set_times_at(dir: &OwnedFd, name: &CStr, mtime: i64) -> Result<(), (CopyStep, Errno)> {
    let stamp = rustix::fs::Timespec {
        tv_sec: mtime,
        tv_nsec: 0,
    };
    fs::utimensat(
        dir,
        name,
        &Timestamps {
            last_access: stamp,
            last_modification: stamp,
        },
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|errno| (CopyStep::Metadata, errno))
}

/// Reads a frame's name alone, for a frame that carries no metadata block.
fn read_bare_name(stream: BorrowedFd<'_>) -> Result<Name, (CopyStep, Errno)> {
    let mut buf = [0u8; NAME_MAX + 1];
    let len = read_bytes_u16(stream, &mut buf[..NAME_MAX])?.len();
    buf[len] = 0;
    Ok(Name { buf, len })
}

/// Reads a frame's name and metadata block.
fn read_named(stream: BorrowedFd<'_>) -> Result<(Name, Meta), (CopyStep, Errno)> {
    let name = read_bare_name(stream)?;
    let mut fields = [0u8; 20];
    read_full(stream, &mut fields)?;
    Ok((
        name,
        Meta {
            mode: u32::from_le_bytes(fields[0..4].try_into().expect("slice length is 4")),
            uid: u32::from_le_bytes(fields[4..8].try_into().expect("slice length is 4")),
            gid: u32::from_le_bytes(fields[8..12].try_into().expect("slice length is 4")),
            mtime: i64::from_le_bytes(fields[12..20].try_into().expect("slice length is 8")),
        },
    ))
}

/// Reads a `u16`-prefixed byte string into `buf`, refusing one that does not
/// fit.
fn read_bytes_u16<'b>(
    stream: BorrowedFd<'_>,
    buf: &'b mut [u8],
) -> Result<&'b [u8], (CopyStep, Errno)> {
    frame::read_bytes_u16(stream, buf).map_err(|errno| match errno {
        // A declared length past the buffer is a name this build cannot hold,
        // which is the frame's fault rather than the stream's.
        Errno::NAMETOOLONG => (CopyStep::BadName, errno),
        errno => (CopyStep::ReadFrame, errno),
    })
}

/// A frame's name: the bytes the frame carried, terminated for the `*at` calls,
/// and the length the frame declared for them.
///
/// The length is kept rather than recovered from the terminator, because the
/// two disagree exactly when a frame names something with a NUL inside it — and
/// [`Name::component`] refuses such a name rather than accept the prefix.
struct Name {
    /// The name, followed by its terminator.
    buf: [u8; NAME_MAX + 1],
    /// The declared length, excluding the terminator.
    len: usize,
}

impl Name {
    /// The name as a `CStr`, refusing anything that is not a single, ordinary
    /// path component.
    ///
    /// This is where a hostile stream is stopped. Every entry is created with an
    /// `*at` call relative to the directory currently held open, so a name that
    /// is a single component cannot reach outside the destination however the
    /// source tree is shaped: `..`, `.`, an embedded separator, an embedded NUL,
    /// and an empty name are all refused rather than resolved.
    /// [`path::is_ordinary_component`] is that rule, and the walk's host side
    /// refuses the same shapes before sending a frame at all.
    ///
    /// The NUL is refused for the reason the rest are, one step earlier. A name
    /// carrying one is not a name any filesystem can hold, so a frame naming
    /// `a\0b` is a stream this walk does not understand; taking the `a` it
    /// happens to begin with would create an entry the source does not have and
    /// call the tree copied.
    fn component(&self) -> Result<&CStr, (CopyStep, Errno)> {
        let bytes = self
            .buf
            .get(..self.len)
            .ok_or((CopyStep::BadName, Errno::INVAL))?;
        if !path::is_ordinary_component(bytes) {
            return Err((CopyStep::BadName, Errno::INVAL));
        }
        CStr::from_bytes_with_nul(&self.buf[..=self.len])
            .map_err(|_| (CopyStep::BadName, Errno::INVAL))
    }
}

/// Turns a hardlink anchor's bytes into a `CStr`, refusing any path that is
/// written to climb.
///
/// One of the three premises the module doc sets out, and only one: it stops a
/// path from *naming* somewhere outside the destination. An absolute path would
/// restart at the host's root, so it is refused here rather than resolved, and
/// every component must be an ordinary one — which refuses a `..` that would
/// climb out, and an empty component, a `.`, and an embedded NUL besides. None
/// of those is anything an anchor the walk records can be, so refusing them
/// costs nothing and closes the shape.
///
/// The per-component rule is [`path::is_ordinary_component`], the one the
/// walk's frames are held to; nothing is dropped or normalized on the way, so a
/// path that merely *reduces* to something ordinary is refused too. An anchor
/// is a path this walk itself emitted, and it emits neither.
///
/// It does not by itself keep the *resolution* inside the tree, since `linkat`
/// follows the anchor's intermediate components. What does is that this walk
/// created every directory on that path and opened each with `O_NOFOLLOW`, so
/// none is a symlink.
///
/// `bytes` is the anchor followed by its null terminator.
fn contained_path(bytes: &[u8]) -> Result<&CStr, (CopyStep, Errno)> {
    let anchor = bytes
        .split_last()
        .filter(|(last, _)| **last == 0)
        .map(|(_, rest)| rest)
        .ok_or((CopyStep::BadName, Errno::INVAL))?;
    if anchor.is_empty() || anchor[0] == b'/' {
        return Err((CopyStep::BadName, Errno::INVAL));
    }
    if !anchor
        .split(|byte| *byte == b'/')
        .all(path::is_ordinary_component)
    {
        return Err((CopyStep::BadName, Errno::INVAL));
    }
    CStr::from_bytes_with_nul(bytes).map_err(|_| (CopyStep::BadName, Errno::INVAL))
}

/// Copies exactly `size` bytes from the frame stream into `file`.
fn copy_data(
    stream: BorrowedFd<'_>,
    file: BorrowedFd<'_>,
    size: u64,
) -> Result<(), (CopyStep, Errno)> {
    let mut buf = [0u8; DATA_BUF];
    let mut left = size;
    while left > 0 {
        let want = usize::try_from(left.min(DATA_BUF as u64)).unwrap_or(DATA_BUF);
        read_full(stream, &mut buf[..want])?;
        frame::write_full(file, &buf[..want]).map_err(|errno| (CopyStep::Write, errno))?;
        left -= want as u64;
    }
    Ok(())
}

/// Fills `buf` completely, treating a short stream as a truncated frame.
fn read_full(stream: BorrowedFd<'_>, buf: &mut [u8]) -> Result<(), (CopyStep, Errno)> {
    frame::read_full(stream, buf).map_err(|errno| (CopyStep::ReadFrame, errno))
}

/// Writes a null-terminated copy of `bytes` into `buf` and returns it as a
/// `CStr`.
fn cstr_in<'b>(buf: &'b mut [u8], bytes: &[u8]) -> Result<&'b CStr, (CopyStep, Errno)> {
    if bytes.len() + 1 > buf.len() || bytes.contains(&0) {
        return Err((CopyStep::BadName, Errno::INVAL));
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;
    CStr::from_bytes_with_nul(&buf[..=bytes.len()]).map_err(|_| (CopyStep::BadName, Errno::INVAL))
}

/// Writes the outcome record to the gate, best effort.
fn report(gate: BorrowedFd<'_>, wire: u32, errno: i32) {
    let mut record = [0u8; super::RECORD_LEN];
    record[0..4].copy_from_slice(&wire.to_le_bytes());
    record[4..8].copy_from_slice(&errno.to_le_bytes());
    let _ = rustix::io::write(gate, &record);
}

#[cfg(test)]
mod tests {
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
    fn copy_step_wire_round_trip() {
        for &step in CopyStep::ALL {
            assert_eq!(CopyStep::from_wire(step.wire()), Some(step));
            assert!(!step.describe().is_empty(), "{step:?} describes itself");
        }
    }

    #[test]
    fn copy_step_unknown_wire_value_is_rejected() {
        assert_eq!(CopyStep::from_wire(CopyStep::past_the_last()), None);
        assert_eq!(CopyStep::from_wire(OUTCOME_OK), None);
    }

    /// A record naming no step at all is not read as a step: the success
    /// record decodes as success, and anything else as a malformed record.
    #[test]
    fn an_outcome_record_naming_no_step_is_malformed() {
        let record = |wire: u32| {
            let mut record = [0u8; crate::mechanism::RECORD_LEN];
            record[0..4].copy_from_slice(&wire.to_le_bytes());
            record
        };
        assert!(decode_record(record(OUTCOME_OK)).is_ok());
        assert!(matches!(
            decode_record(record(CopyStep::ALL.len() as u32)),
            Err(CopyFailure::Malformed),
        ));
    }

    /// The anchor path is the one thing a frame carries that is not a single
    /// component, so it is the one place a hostile or broken stream could aim
    /// a link outside the destination. Every shape that could is refused
    /// before it reaches `linkat`.
    #[test]
    fn a_hardlink_anchor_that_could_leave_the_tree_is_refused() {
        let refused = |bytes: &[u8]| {
            let mut buf = bytes.to_vec();
            buf.push(0);
            assert!(
                contained_path(&buf).is_err(),
                "{:?} was accepted as an anchor",
                String::from_utf8_lossy(bytes),
            );
        };

        refused(b"/etc/shadow");
        refused(b"..");
        refused(b"../outside");
        refused(b"usr/../../outside");
        refused(b"usr//bin/tool");
        refused(b".");
        refused(b"usr/./bin");
        refused(b"");
        refused(b"trailing/");
    }

    /// An ordinary in-tree path is accepted whole, including the dotted names
    /// that only look like traversal.
    #[test]
    fn an_in_tree_hardlink_anchor_is_accepted() {
        let accepted = |bytes: &[u8]| {
            let mut buf = bytes.to_vec();
            buf.push(0);
            let path = contained_path(&buf).unwrap_or_else(|err| {
                panic!("{:?} was refused: {err:?}", String::from_utf8_lossy(bytes))
            });
            assert_eq!(path.to_bytes(), bytes);
        };

        accepted(b"busybox");
        accepted(b"usr/bin/busybox");
        accepted(b"usr/lib/.build-id/ab/cdef");
        // Three dots is a legal file name; two is the one that climbs.
        accepted(b"usr/.../odd");
    }

    /// A missing terminator is a malformed frame, not a path to resolve.
    #[test]
    fn an_unterminated_hardlink_anchor_is_refused() {
        assert!(contained_path(b"usr/bin/tool").is_err());
    }

    /// One `COPY_DIR` frame for `name`, with the caller's own ownership so the
    /// `fchown` of a matching `COPY_LEAVE` is permitted outside a map.
    fn dir_frame(name: &[u8], mode: u32) -> Vec<u8> {
        let mut frame = vec![COPY_DIR];
        frame.extend_from_slice(&(name.len() as u16).to_le_bytes());
        frame.extend_from_slice(name);
        frame.extend_from_slice(&mode.to_le_bytes());
        frame.extend_from_slice(&rustix::process::getuid().as_raw().to_le_bytes());
        frame.extend_from_slice(&rustix::process::getgid().as_raw().to_le_bytes());
        frame.extend_from_slice(&0i64.to_le_bytes());
        frame
    }

    /// One `COPY_SYMLINK` frame: name, metadata, and target. The ownership is
    /// the caller's own, so the `chownat` is permitted outside a map.
    fn symlink_frame(name: &[u8], target: &[u8], mtime: i64) -> Vec<u8> {
        let mut frame = vec![COPY_SYMLINK];
        frame.extend_from_slice(&(name.len() as u16).to_le_bytes());
        frame.extend_from_slice(name);
        frame.extend_from_slice(&0o777u32.to_le_bytes());
        frame.extend_from_slice(&rustix::process::getuid().as_raw().to_le_bytes());
        frame.extend_from_slice(&rustix::process::getgid().as_raw().to_le_bytes());
        frame.extend_from_slice(&mtime.to_le_bytes());
        frame.extend_from_slice(&(target.len() as u16).to_le_bytes());
        frame.extend_from_slice(target);
        frame
    }

    /// Runs `frames` through the consuming walk against `dir`.
    fn consume_frames_in(dir: &std::path::Path, frames: &[u8]) -> Result<(), (CopyStep, Errno)> {
        let (read, write) = rustix::pipe::pipe().expect("a pipe");
        rustix::io::write(&write, frames).expect("the frames fit the pipe buffer");
        drop(write);
        let root = fs::open(
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("the destination opens");
        consume(read.as_fd(), root)
    }

    /// Runs `frames` through the consuming walk against a fresh destination.
    fn consume_frames(tag: &str, frames: &[u8]) -> Result<(), (CopyStep, Errno)> {
        let dir = Scratch::new(tag);
        consume_frames_in(dir.path(), frames)
    }

    /// A stream that ends with directories still open is malformed: every one
    /// of them would keep its creation mode 0700 with no ownership or
    /// modification time applied, and the caller would be told the copy was
    /// complete. Every other malformed shape in the walk is refused, and this
    /// is the one whose consequence is silent.
    #[test]
    fn a_copy_end_at_a_non_zero_depth_is_refused() {
        let mut frames = dir_frame(b"sub", 0o755);
        frames.push(COPY_END);
        assert_eq!(
            consume_frames("copyin-unbalanced", &frames),
            Err((CopyStep::ReadFrame, Errno::INVAL))
        );

        // The balanced stream the writer actually produces is accepted.
        let mut frames = dir_frame(b"sub", 0o755);
        frames.push(COPY_LEAVE);
        frames.push(COPY_END);
        assert_eq!(consume_frames("copyin-balanced", &frames), Ok(()));
    }

    /// A name with a NUL inside it is refused, not read as the prefix before
    /// it.
    ///
    /// No filesystem holds such a name, so a frame carrying one is a stream the
    /// walk does not understand. Creating the prefix would put an entry in the
    /// destination that the source does not have, under a name the caller never
    /// asked for, and report the tree copied.
    #[test]
    fn a_name_carrying_an_embedded_nul_is_refused() {
        let dir = Scratch::new("copyin-embedded-nul");
        let mut frames = dir_frame(b"a\0b", 0o755);
        frames.push(COPY_END);
        assert_eq!(
            consume_frames_in(dir.path(), &frames),
            Err((CopyStep::BadName, Errno::INVAL))
        );
        assert_eq!(
            std::fs::read_dir(dir.path())
                .expect("the destination is readable")
                .count(),
            0,
            "the name was truncated at the NUL and its prefix created",
        );
    }

    /// A symbolic link carries the modification time its frame names.
    ///
    /// The link's own, not its target's: the copy is the mirror of an export
    /// that records one, and a tree that copies in with every link stamped at
    /// the moment of the copy is not the tree that was copied.
    #[test]
    fn a_symlink_carries_the_modification_time_its_frame_names() {
        use std::os::unix::fs::MetadataExt;

        let dir = Scratch::new("copyin-symlink-mtime");
        let mut frames = symlink_frame(b"link", b"target", 1_000_000_000);
        frames.push(COPY_END);
        assert_eq!(consume_frames_in(dir.path(), &frames), Ok(()));

        let meta = std::fs::symlink_metadata(dir.join("link")).expect("the link was created");
        assert!(meta.is_symlink(), "the entry is not a symbolic link");
        assert_eq!(meta.mtime(), 1_000_000_000);
    }
}
