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
//!   creates it, or adopts the directory or in-root alias of one the root
//!   already has there, and every later frame lands inside it until the
//!   matching [`COPY_LEAVE`].
//! - [`COPY_LEAVE`]: the current directory is finished. Its attribute block
//!   follows. The child applies the deferred ownership, mode, and modification
//!   time, and then the attributes, if it created the directory; it reads the
//!   block past for one it adopted. Then it closes the directory.
//! - [`COPY_FILE`]: a regular file. Its name, metadata, its size, its data as
//!   the runs [`frame::receive_runs`] reads, and its attribute block follow. A
//!   hole in the source is a run of its own that carries no bytes, and the
//!   child leaves it a hole, so a sparse file costs the copy its data rather
//!   than its length.
//! - [`COPY_SYMLINK`]: a symbolic link. Its name, metadata, and target follow.
//!   The child applies the ownership and the modification time; the mode goes
//!   unused, since the kernel fixes a symlink's own at 0777.
//! - [`COPY_FIFO`]: a named pipe. Its name, metadata, and attribute block
//!   follow, and the child applies them through a descriptor for the pipe it
//!   created, opened without waiting for a peer that a copy has no reason to
//!   expect.
//! - [`COPY_LINK`]: a second or later name for a file already created. Its own
//!   name and the first name's path, relative to the destination root, follow.
//!   Metadata is the inode's and is already applied, so none is sent.
//! - [`COPY_OWN`]: an entry the root already holds, to be given an owner and a
//!   group. Its path from the destination root, the two ids, and the device and
//!   inode it must still be follow. Nothing is created. A provisioner that laid
//!   entries down as the calling user names here the owners only the map can
//!   give them: a layered build, the base's owner for each directory it carried
//!   up into the upper; the Alpine layer, the owner each package states.
//! - [`COPY_END`]: the tree is finished.
//!
//! An attribute block is a count, then each extended attribute as its name and
//! its value, each led by its length: the name's in two bytes, held to
//! `XATTR_NAME_MAX`, the value's in four, held to `XATTR_SIZE_MAX`
//! ([`bounds`](super::bounds)). The child gives each to the entry through the
//! descriptor it holds, after the ownership and the mode, so a capability is
//! set after the `chown` that would clear it. What the block holds is the
//! parent's decision: the attributes the sandbox's root can set, each restated
//! for the map (see `provision::xattr`). A directory's comes when it is left,
//! once everything inside it is created, so a default access control list it
//! carries is not inherited by the entries the copy creates there.
//!
//! [`COPY_LINK`] and [`COPY_OWN`] are the frames that carry a path rather than
//! a single component. A hard link's two names may sit in different
//! directories and only the parent's walk knows where the first one was, and
//! an entry to own is named by where it sits in the root. Containment there
//! rests on two things:
//!
//! 1. The path's directory part is resolved from the destination root with
//!    `RESOLVE_IN_ROOT`, so whatever its components are — a merged-usr alias
//!    the walk adopted, an absolute link, something a concurrent writer put
//!    there — the resolution cannot leave the root.
//! 2. The final component is never traversed: a link is made without
//!    `AT_SYMLINK_FOLLOW`, and an entry to own is opened with `O_NOFOLLOW`.
//!
//! The child also refuses an absolute path and any component that is empty,
//! `.`, or `..`. None of those is anything the parent records, so a frame
//! naming one is a stream the child does not understand.
//!
//! A directory the root already has is resolved the same way when it is a
//! symbolic link: an alias such as `bin -> usr/bin` is followed from the root
//! with `RESOLVE_IN_ROOT`, and the walk lands through it. Every other step is
//! an `*at` call on a single component, relative to a directory the walk holds
//! open, and none follows a symbolic link at its leaf.
//!
//! The child reports its outcome as an 8-byte record on the gate — the step it
//! failed at and the errno — exactly as the removal child does, rather than as
//! a frame: the data pipe runs the other way, so there is nothing to write a
//! frame to.

use std::ffi::CStr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags, Timestamps};
use rustix::io::Errno;
use rustix::net::{AddressFamily, RecvFlags, SocketFlags, SocketType};

use super::bounds::{LINK_BUF, MAX_DEPTH, NAME_MAX, XATTR_NAME_MAX, XATTR_SIZE_MAX};
use super::child::MapFailure;
use super::frame::{self, StreamFailure};
use super::sys::{self, PidfdFork};
use super::{ChildMap, Forked};
use crate::idmap::IdMapError;
use crate::path;
use crate::provision::containment;
use crate::wire::wire_enum;

/// Frame tag: enter a directory.
pub(crate) const COPY_DIR: u8 = 1;
/// Frame tag: the current directory is finished, followed by its attribute
/// block.
pub(crate) const COPY_LEAVE: u8 = 2;
/// Frame tag: a regular file, followed by its data and its attribute block.
pub(crate) const COPY_FILE: u8 = 3;
/// Frame tag: a symbolic link, followed by its target.
pub(crate) const COPY_SYMLINK: u8 = 4;
/// Frame tag: the tree is finished.
pub(crate) const COPY_END: u8 = 5;
/// Frame tag: a named pipe, followed by its attribute block.
pub(crate) const COPY_FIFO: u8 = 6;
/// Frame tag: another name for a file already created, followed by the first
/// name's path relative to the destination root.
pub(crate) const COPY_LINK: u8 = 7;
/// Frame tag: an entry the root already holds, followed by its path relative to
/// the destination root, the uid and gid to give it, and the device and inode
/// it must still be. See [`own_at`].
pub(crate) const COPY_OWN: u8 = 8;

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
        /// An entry the root already holds could not be reached to be given
        /// its owner.
        Own = 21 => "opening an entry the root already holds, to give it its owner",
        /// An extended attribute could not be given to an entry the copy
        /// created.
        Xattr = 22 => "giving an entry an extended attribute, which the destination's filesystem may not hold",
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
    child: Forked,
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
        let CopyChild {
            child,
            stream,
            gate,
        } = self;
        drop(stream);

        let read = match frame::read_record(gate.as_fd()) {
            Ok(read) => read,
            Err(errno) => {
                let _ = child.reap();
                return Err(CopyFailure::Step {
                    step: CopyStep::Spawn,
                    errno: errno.raw_os_error(),
                });
            }
        };
        let outcome = child.reap();
        let Some(record) = read else {
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
        };
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
        let CopyChild {
            child,
            stream,
            gate,
        } = self;
        let reported = reported_outcome(gate.as_fd());
        child.kill();
        drop(stream);
        drop(gate);
        let _ = child.reap();
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
    let mut record = [0u8; frame::RECORD_LEN];
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

/// Reads the child's outcome record: the copy finished, or the step that
/// failed and its errno.
fn decode_record(record: [u8; frame::RECORD_LEN]) -> Result<(), CopyFailure> {
    let (wire, errno) = frame::decode_record(record);
    if wire == frame::RECORD_DONE {
        return Ok(());
    }
    let Some(step) = CopyStep::from_wire(wire) else {
        return Err(CopyFailure::Malformed);
    };
    Err(CopyFailure::Step { step, errno })
}

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
    match unsafe { sys::fork_with_pidfd() } {
        Err(errno) => Err(spawn_failure(errno)),
        Ok(PidfdFork::Child) => {
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
        Ok(PidfdFork::ParentOf(child)) => {
            drop(stream_read);
            drop(gate_child);
            if let ChildMap::Delegated { mapper, map } = &map {
                let driven = super::drive_map_gate(gate_caller.as_fd(), child.pid(), *mapper, map);
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
                    super::abandon_gated_child(&child);
                    return Err(err);
                }
            }
            Ok(CopyChild {
                child,
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
    if let Err(failure) = super::child::enter_mapped_namespace(
        &keep,
        rustix::thread::UnshareFlags::empty(),
        map.duty(),
        Some(gate),
    ) {
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
            report(gate, frame::RECORD_DONE, 0);
            sys::exit_group(0)
        }
        Err((step, errno)) => fail(step, errno),
    }
}

/// Reads frames until end of input and creates what they name.
///
/// The directory stack is the only state that grows, and it is bounded by
/// [`MAX_DEPTH`]. Deferred metadata rides alongside each open directory this
/// walk created: a directory's own mode is applied on the way out, because a
/// mode denying write would otherwise stop its contents being created, and its
/// modification time last of all, because creating those contents changes it. A
/// directory the root already had is left as it is; see [`enter_dir`].
///
/// The root descriptor is duplicated before the walk begins. Every other
/// descriptor moves onto the stack as the walk descends, but an alias and a
/// [`COPY_LINK`] anchor both resolve from the root, so one copy has to stay put
/// for the whole tree. The [`Trail`] is the current directory's path from it.
fn consume(stream: BorrowedFd<'_>, root: OwnedFd) -> Result<(), (CopyStep, Errno)> {
    let anchor_root =
        rustix::io::fcntl_dupfd_cloexec(&root, 0).map_err(|errno| (CopyStep::OpenRoot, errno))?;
    let mut stack: [Option<Level>; MAX_DEPTH] = [const { None }; MAX_DEPTH];
    let mut depth: usize = 0;
    let mut current = root;
    let mut trail = Trail::new();

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
                let (opened, created) = enter_dir(&anchor_root, &current, &mut trail, name)?;
                stack[depth] = Some(Level {
                    parent: std::mem::replace(&mut current, opened),
                    meta,
                    created,
                    trail: trail.mark(),
                });
                trail.push(name);
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
                if level.created {
                    apply_meta(current.as_fd(), &level.meta)?;
                    apply_xattrs(stream, Some(current.as_fd()))?;
                } else {
                    apply_xattrs(stream, None)?;
                }
                current = level.parent;
                trail.restore(level.trail);
            }
            COPY_FILE => {
                let (name, meta) = read_named(stream)?;
                let mut size = [0u8; 8];
                read_full(stream, &mut size)?;
                let size = u64::from_le_bytes(size);
                let name = name.component()?;
                // O_EXCL, replacing what holds the name, rather than O_TRUNC:
                // an existing entry may be a symlink, and truncating through
                // one would write outside the tree.
                let file = containment::replacing(&current, name, || {
                    fs::openat(
                        &current,
                        name,
                        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                        Mode::from_bits_truncate(0o600),
                    )
                })
                .map_err(|errno| (CopyStep::Create, errno))?;
                frame::receive_runs(stream, file.as_fd(), size).map_err(
                    |failure| match failure {
                        StreamFailure::Stream(errno) => (CopyStep::ReadFrame, errno),
                        StreamFailure::File(errno) => (CopyStep::Write, errno),
                    },
                )?;
                apply_meta(file.as_fd(), &meta)?;
                apply_xattrs(stream, Some(file.as_fd()))?;
            }
            COPY_SYMLINK => {
                let (name, meta) = read_named(stream)?;
                let mut raw = [0u8; LINK_BUF];
                let len = read_bytes_u16(stream, &mut raw)?.len();
                let mut terminated = [0u8; LINK_BUF + 1];
                let target = cstr_in(&mut terminated, &raw[..len])?;
                let name = name.component()?;
                containment::replacing(&current, name, || fs::symlinkat(target, &current, name))
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
                // Created 0600 and widened below, for the reason a directory
                // is: the copy owns the window between creation and the final
                // mode, and a permissive one should not exist inside it.
                containment::replacing(&current, name, || {
                    fs::mknodat(
                        &current,
                        name,
                        rustix::fs::FileType::Fifo,
                        Mode::from_bits_truncate(0o600),
                        0,
                    )
                })
                .map_err(|errno| (CopyStep::Fifo, errno))?;
                // Applied through a descriptor, as every other entry's is, so
                // a source-chosen mode lands on this pipe and on nothing a
                // racer put at the name since.
                let fifo = containment::open_created_fifo(current.as_fd(), name)
                    .map_err(|errno| (CopyStep::Fifo, errno))?;
                apply_meta(fifo.as_fd(), &meta)?;
                apply_xattrs(stream, Some(fifo.as_fd()))?;
            }
            COPY_LINK => {
                let name = read_bare_name(stream)?;
                let mut raw = [0u8; LINK_BUF + 1];
                let len = read_bytes_u16(stream, &mut raw[..LINK_BUF])?.len();
                raw[len] = 0;
                contained_path(&raw[..=len])?;
                let name = name.component()?;
                // The link shares the anchor's inode, so it carries the
                // ownership, mode, and modification time already applied to
                // it — there is nothing further to set, which is the whole
                // point of recording it as a link.
                link_to_anchor(&anchor_root, &mut raw[..=len], &current, name)?;
            }
            COPY_OWN => {
                let mut raw = [0u8; LINK_BUF + 1];
                let len = read_bytes_u16(stream, &mut raw[..LINK_BUF])?.len();
                raw[len] = 0;
                contained_path(&raw[..=len])?;
                let mut fields = [0u8; 24];
                read_full(stream, &mut fields)?;
                let owner = OwnFrame {
                    uid: u32::from_le_bytes(fields[0..4].try_into().expect("slice length is 4")),
                    gid: u32::from_le_bytes(fields[4..8].try_into().expect("slice length is 4")),
                    dev: u64::from_le_bytes(fields[8..16].try_into().expect("slice length is 8")),
                    ino: u64::from_le_bytes(fields[16..24].try_into().expect("slice length is 8")),
                };
                own_at(&anchor_root, &mut raw[..=len], &owner)?;
            }
            _ => return Err((CopyStep::ReadFrame, Errno::INVAL)),
        }
    }
}

/// One open directory on the stack: the parent it was opened from, the
/// metadata to apply when it is left, and what to restore on leaving it.
struct Level {
    parent: OwnedFd,
    meta: Meta,
    /// Whether this walk created the directory, and so owes it the metadata.
    /// A directory the root already had is adopted as it stands.
    created: bool,
    /// The [`Trail`]'s length before the directory's name was pushed.
    trail: Option<usize>,
}

/// Opens the directory `name` names under `current`, creating it where nothing
/// is there, and reports whether this walk created it.
///
/// A copy adds to a root filesystem rather than rebuilding it, so an entry the
/// root already has at the name is used as it stands where it can be:
///
/// - A directory is adopted, and its owner, mode and modification time are not
///   set from the frame.
///   The source's directory says where its contents go, not what the root's
///   `/etc` should be: a source staged under umask 077 would otherwise leave the
///   root's `/etc` at `0700`, and a file under a home directory would re-own the
///   home.
/// - A symbolic link that resolves inside the root to a directory is an alias,
///   merged-usr's `bin -> usr/bin` among them, and is adopted the same way. The
///   link is resolved from the root with `RESOLVE_IN_ROOT`, so an absolute
///   target means the root's own path, as it does to the sandbox, and nothing
///   resolves outside the root.
/// - Anything else is replaced by a directory, as a file entry replaces what
///   occupies its name.
///
/// `provision::extract::overlay_tree`, the other way a host tree is laid into
/// a root, follows the same policy, and its documentation states where it
/// differs and why.
///
/// A directory this walk creates is created `0700` and widened on the way out:
/// one whose final mode denies the owner write cannot have its contents created
/// under it. `O_NOFOLLOW` on each open is what keeps a symbolic link from being
/// taken for a directory anywhere but the alias step.
fn enter_dir(
    root: &OwnedFd,
    current: &OwnedFd,
    trail: &mut Trail,
    name: &CStr,
) -> Result<(OwnedFd, bool), (CopyStep, Errno)> {
    let open = || {
        fs::openat(
            current,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| (CopyStep::OpenDir, errno))
    };
    let create = || {
        fs::mkdirat(current, name, Mode::from_bits_truncate(0o700))
            .map_err(|errno| (CopyStep::Mkdir, errno))
    };
    match create() {
        Ok(()) => return Ok((open()?, true)),
        Err((_, Errno::EXIST)) => {}
        Err(err) => return Err(err),
    }
    match open() {
        Ok(fd) => return Ok((fd, false)),
        // A symbolic link answers ENOTDIR (ELOOP on older kernels), and so does
        // anything else that is not a directory.
        Err((_, Errno::NOTDIR | Errno::LOOP)) => {}
        Err(err) => return Err(err),
    }
    let path = trail
        .with(name)
        .map_err(|errno| (CopyStep::OpenDir, errno))?;
    match containment::open_dir_path(root.as_fd(), path, OFlags::RDONLY, ResolveFlags::IN_ROOT) {
        Ok(fd) => return Ok((fd, false)),
        // Dangling, a link to something that is not a directory, or a loop:
        // not an alias, and replaced like any other entry in the way.
        Err(Errno::NOENT | Errno::NOTDIR | Errno::LOOP) => {}
        Err(errno) => return Err((CopyStep::OpenDir, errno)),
    }
    fs::unlinkat(current, name, AtFlags::empty()).map_err(|errno| (CopyStep::Mkdir, errno))?;
    create()?;
    Ok((open()?, true))
}

/// Links `name` under `current` onto the file at `anchor`, a path from the
/// destination root that [`contained_path`] has already admitted, replacing
/// what holds `name` as every other entry the copy lays in does.
///
/// A `name` that already holds the anchor's file is already done, through
/// [`containment::link_replacing`]. A source tree whose `bin/x` and
/// `usr/bin/x` are one file copies into a merged-usr root, where `bin` is a
/// link to `usr/bin`, as one name reached twice, and replacing it would remove
/// the file the link is to.
///
/// `anchor` is the path followed by its terminator. The directory part is
/// resolved from the root with `RESOLVE_IN_ROOT`, so no component of it — an
/// alias [`enter_dir`] adopted included — can take the resolution out of the
/// root. The final component is linked without `AT_SYMLINK_FOLLOW`, so it is
/// never traversed. The separator before it is overwritten with a terminator
/// to split the two in place, once, before any link is tried.
fn link_to_anchor(
    root: &OwnedFd,
    anchor: &mut [u8],
    current: &OwnedFd,
    name: &CStr,
) -> Result<(), (CopyStep, Errno)> {
    let (dir, leaf) = parent_in_root(root, anchor, CopyStep::Link)?;
    let dir = dir.as_ref().map_or(root.as_fd(), AsFd::as_fd);
    containment::link_replacing(dir, leaf, current.as_fd(), name)
        .map_err(|errno| (CopyStep::Link, errno))
}

/// Splits `path`, a path from the destination root that [`contained_path`] has
/// already admitted followed by its terminator, into the directory holding its
/// final component and that component.
///
/// The directory is resolved from the root with `RESOLVE_IN_ROOT`, so no
/// component of it — an alias [`enter_dir`] adopted included — can take the
/// resolution out of the root. `None` is the root itself, for a path of one
/// component. The final component is only named, for an `*at` call that does
/// not follow it. The separator before it is overwritten with a terminator to
/// split the two in place, once, before anything acts on either. `step` is what
/// a failed resolution reports.
fn parent_in_root<'p>(
    root: &OwnedFd,
    path: &'p mut [u8],
    step: CopyStep,
) -> Result<(Option<OwnedFd>, &'p CStr), (CopyStep, Errno)> {
    let malformed = |_| (CopyStep::BadName, Errno::INVAL);
    let Some(split) = path.iter().rposition(|byte| *byte == b'/') else {
        return Ok((None, CStr::from_bytes_with_nul(path).map_err(malformed)?));
    };
    path[split] = 0;
    let (dir, leaf) = path.split_at(split + 1);
    let dir = CStr::from_bytes_with_nul(dir).map_err(malformed)?;
    let leaf = CStr::from_bytes_with_nul(leaf).map_err(malformed)?;
    let dir = containment::open_dir_path(root.as_fd(), dir, OFlags::PATH, ResolveFlags::IN_ROOT)
        .map_err(|errno| (step, errno))?;
    Ok((Some(dir), leaf))
}

/// What a [`COPY_OWN`] frame states: the owner to give an entry, and the entry
/// it must still be.
struct OwnFrame {
    uid: u32,
    gid: u32,
    /// The device the entry was on when the parent recorded it.
    dev: u64,
    /// Its inode number then.
    ino: u64,
}

/// Gives the entry at `path` — a path from the destination root, as
/// [`parent_in_root`] takes one — the owner `owner` names, where it is still
/// the entry `owner` identifies.
///
/// The parent records an entry's device and inode when it lays the entry down
/// or carries it up from a base, and names it here later, after other writers
/// have had the tree: the rest of an extraction, a caller's files laid over
/// it, a script. A name that holds anything else by then, or nothing, is left
/// as it is. The entry the owner was stated for is gone, and giving its owner
/// to whatever took the name would re-own an unrelated entry.
///
/// The final component is never followed. A symbolic link is given its owner
/// as the link it is, through a descriptor of the link. Anything else is opened
/// without following and without waiting — a named pipe opens as readily as a
/// file — and given its owner through that descriptor. Its mode is then put
/// back as it was. A `chown` clears a file's setuid and setgid bits, and a
/// setuid or setgid helper is the commonest file an owner is stated for. The
/// kernel keeps a directory's set-group-ID bit, but a filesystem that cleared
/// it would change what new entries beneath the directory inherit.
fn own_at(root: &OwnedFd, path: &mut [u8], owner: &OwnFrame) -> Result<(), (CopyStep, Errno)> {
    let (dir, leaf) = parent_in_root(root, path, CopyStep::Own)?;
    let dir = dir.as_ref().map_or(root.as_fd(), AsFd::as_fd);
    let uid = Some(rustix::fs::Uid::from_raw(owner.uid));
    let gid = Some(rustix::fs::Gid::from_raw(owner.gid));
    let opened = fs::openat(
        dir,
        leaf,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    );
    match opened {
        Ok(entry) => {
            let stat = fs::fstat(&entry).map_err(|errno| (CopyStep::Own, errno))?;
            if !is_entry(&stat, owner) {
                return Ok(());
            }
            fs::fchown(&entry, uid, gid).map_err(|errno| (CopyStep::Chown, errno))?;
            fs::fchmod(&entry, Mode::from_bits_truncate(stat.st_mode & 0o7777))
                .map_err(|errno| (CopyStep::Metadata, errno))
        }
        // What `O_NOFOLLOW` answers for a symbolic link.
        Err(Errno::LOOP) => {
            let link = fs::openat(
                dir,
                leaf,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|errno| (CopyStep::Own, errno))?;
            let stat = fs::fstat(&link).map_err(|errno| (CopyStep::Own, errno))?;
            if !is_entry(&stat, owner) {
                return Ok(());
            }
            fs::chownat(&link, c"", uid, gid, AtFlags::EMPTY_PATH)
                .map_err(|errno| (CopyStep::Chown, errno))
        }
        Err(Errno::NOENT | Errno::NOTDIR) => Ok(()),
        Err(errno) => Err((CopyStep::Own, errno)),
    }
}

/// Whether `stat` is the entry `owner` was recorded for.
fn is_entry(stat: &fs::Stat, owner: &OwnFrame) -> bool {
    stat.st_dev == owner.dev && stat.st_ino == owner.ino
}

/// The path from the destination root to the directory the walk holds open,
/// for the resolutions that start at the root rather than at that directory.
///
/// Held in a fixed buffer, since the child cannot allocate one, as each name
/// followed by a separator. A path that outgrows the buffer is longer than
/// `PATH_MAX`, which `openat2` refuses anyway, so it is recorded as lost rather
/// than truncated, and a resolution that needs it fails with `ENAMETOOLONG`.
/// The walk itself goes on: only an alias deeper than that cannot be resolved.
struct Trail {
    buf: [u8; LINK_BUF],
    /// Bytes in use, or `None` once a push did not fit.
    len: Option<usize>,
}

impl Trail {
    /// The root's own trail: empty.
    fn new() -> Trail {
        Trail {
            buf: [0; LINK_BUF],
            len: Some(0),
        }
    }

    /// The length to [`restore`](Self::restore) on leaving the directory about
    /// to be entered.
    fn mark(&self) -> Option<usize> {
        self.len
    }

    /// Returns to a length [`mark`](Self::mark) recorded.
    fn restore(&mut self, mark: Option<usize>) {
        self.len = mark;
    }

    /// Appends a directory the walk has entered.
    fn push(&mut self, name: &CStr) {
        let Some(len) = self.len else {
            return;
        };
        let name = name.to_bytes();
        let end = len + name.len() + 1;
        // Room is kept for the terminator `with` writes after the separator.
        if end >= self.buf.len() {
            self.len = None;
            return;
        }
        self.buf[len..end - 1].copy_from_slice(name);
        self.buf[end - 1] = b'/';
        self.len = Some(end);
    }

    /// `name` in the current directory, as a terminated path from the root.
    fn with(&mut self, name: &CStr) -> Result<&CStr, Errno> {
        let len = self.len.ok_or(Errno::NAMETOOLONG)?;
        let name = name.to_bytes_with_nul();
        let end = len + name.len();
        if end > self.buf.len() {
            return Err(Errno::NAMETOOLONG);
        }
        self.buf[len..end].copy_from_slice(name);
        CStr::from_bytes_with_nul(&self.buf[..end]).map_err(|_| Errno::INVAL)
    }
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

/// Reads an attribute block from the stream and gives each attribute to the
/// entry `fd` holds, or reads the block past where there is no entry to give
/// it to: a directory the copy adopted rather than created.
///
/// The value is read into a buffer of [`XATTR_SIZE_MAX`], the kernel's own
/// bound, so a frame declaring more is a stream the child does not understand.
/// So is a name that is empty or carries a NUL. A failure to set one is the
/// copy's failure: the parent sends only attributes the sandbox's root can set,
/// so one the destination refuses is a filesystem that cannot hold what the
/// source does, which is not something to pass over in silence.
///
/// Kept out of line, so its buffer is on the stack only while a block is read.
#[inline(never)]
fn apply_xattrs(
    stream: BorrowedFd<'_>,
    fd: Option<BorrowedFd<'_>>,
) -> Result<(), (CopyStep, Errno)> {
    let mut count = [0u8; 2];
    read_full(stream, &mut count)?;
    let mut value = [0u8; XATTR_SIZE_MAX];
    for _ in 0..u16::from_le_bytes(count) {
        let mut raw = [0u8; XATTR_NAME_MAX];
        let len = read_bytes_u16(stream, &mut raw)?.len();
        if len == 0 {
            return Err((CopyStep::BadName, Errno::INVAL));
        }
        let mut terminated = [0u8; XATTR_NAME_MAX + 1];
        let name = cstr_in(&mut terminated, &raw[..len])?;
        let mut size = [0u8; 4];
        read_full(stream, &mut size)?;
        let size = usize::try_from(u32::from_le_bytes(size)).unwrap_or(usize::MAX);
        if size > value.len() {
            return Err((CopyStep::ReadFrame, Errno::TOOBIG));
        }
        read_full(stream, &mut value[..size])?;
        if let Some(fd) = fd {
            fs::fsetxattr(fd, name, &value[..size], fs::XattrFlags::empty())
                .map_err(|errno| (CopyStep::Xattr, errno))?;
        }
    }
    Ok(())
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
/// It stops a path from *naming* somewhere outside the destination. An
/// absolute path is refused here rather than resolved, and every component must
/// be an ordinary one — which refuses a `..`, an empty component, a `.`, and an
/// embedded NUL. None of those is anything an anchor the walk records can be,
/// so a frame carrying one is malformed, and refusing it costs nothing.
///
/// The per-component rule is [`path::is_ordinary_component`], the one the
/// walk's frames are held to; nothing is dropped or normalized on the way, so a
/// path that merely *reduces* to something ordinary is refused too. An anchor
/// is a path this walk itself emitted, and it emits neither.
///
/// It does not by itself keep the *resolution* inside the tree. What does is
/// [`link_to_anchor`] resolving the anchor's directory with `RESOLVE_IN_ROOT`.
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
    let _ = rustix::io::write(gate, &frame::encode_record(wire, errno));
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
        assert_eq!(CopyStep::from_wire(frame::RECORD_DONE), None);
    }

    /// A record naming no step at all is not read as a step: the success
    /// record decodes as success, and anything else as a malformed record.
    #[test]
    fn an_outcome_record_naming_no_step_is_malformed() {
        let record = |wire: u32| frame::encode_record(wire, 0);
        assert!(decode_record(record(frame::RECORD_DONE)).is_ok());
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

    /// A `COPY_LEAVE` frame with an empty attribute block.
    const LEAVE: [u8; 3] = [COPY_LEAVE, 0, 0];

    /// One `COPY_FILE` frame holding `data`, owned by the caller, with no
    /// attributes.
    fn file_frame(name: &[u8], mode: u32, data: &[u8]) -> Vec<u8> {
        file_frame_with(name, mode, data, &[])
    }

    /// One `COPY_FILE` frame holding `data` and the attributes `xattrs`.
    fn file_frame_with(name: &[u8], mode: u32, data: &[u8], xattrs: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut frame = vec![COPY_FILE];
        frame.extend_from_slice(&(name.len() as u16).to_le_bytes());
        frame.extend_from_slice(name);
        frame.extend_from_slice(&mode.to_le_bytes());
        frame.extend_from_slice(&rustix::process::getuid().as_raw().to_le_bytes());
        frame.extend_from_slice(&rustix::process::getgid().as_raw().to_le_bytes());
        frame.extend_from_slice(&0i64.to_le_bytes());
        frame.extend_from_slice(&(data.len() as u64).to_le_bytes());
        if !data.is_empty() {
            frame.push(frame::RUN_DATA);
            frame.extend_from_slice(&(data.len() as u64).to_le_bytes());
            frame.extend_from_slice(data);
        }
        frame.extend(attribute_block(xattrs));
        frame
    }

    /// An attribute block holding `xattrs`.
    fn attribute_block(xattrs: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut block = (xattrs.len() as u16).to_le_bytes().to_vec();
        for (name, value) in xattrs {
            block.extend_from_slice(&(name.len() as u16).to_le_bytes());
            block.extend_from_slice(name);
            block.extend_from_slice(&(value.len() as u32).to_le_bytes());
            block.extend_from_slice(value);
        }
        block
    }

    /// One `COPY_LINK` frame: `name` as a second name for the file at `anchor`.
    fn link_frame(name: &[u8], anchor: &[u8]) -> Vec<u8> {
        let mut frame = vec![COPY_LINK];
        frame.extend_from_slice(&(name.len() as u16).to_le_bytes());
        frame.extend_from_slice(name);
        frame.extend_from_slice(&(anchor.len() as u16).to_le_bytes());
        frame.extend_from_slice(anchor);
        frame
    }

    /// A [`COPY_OWN`] frame naming `path`, to be given `uid` and `gid` where
    /// it is still the entry `path_on_disk` is now.
    fn own_frame(path: &[u8], uid: u32, gid: u32, path_on_disk: &std::path::Path) -> Vec<u8> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path_on_disk).expect("the entry exists");
        own_frame_at(path, uid, gid, meta.dev(), meta.ino())
    }

    /// A [`COPY_OWN`] frame naming `path` as the entry `dev` and `ino` name.
    fn own_frame_at(path: &[u8], uid: u32, gid: u32, dev: u64, ino: u64) -> Vec<u8> {
        let mut frame = vec![COPY_OWN];
        frame.extend_from_slice(&(path.len() as u16).to_le_bytes());
        frame.extend_from_slice(path);
        frame.extend_from_slice(&uid.to_le_bytes());
        frame.extend_from_slice(&gid.to_le_bytes());
        frame.extend_from_slice(&dev.to_le_bytes());
        frame.extend_from_slice(&ino.to_le_bytes());
        frame
    }

    /// The caller's own ids, which an unprivileged process may give a file it
    /// owns, where root is one it may not.
    fn own_ids() -> (u32, u32) {
        (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        )
    }

    #[test]
    fn an_owned_entry_keeps_its_setuid_bit() {
        // A `chown` clears the setuid and setgid bits of a file, and a helper
        // that is given an owner is the entry that most needs them. Giving a
        // file to its own owner clears them for an unprivileged caller all the
        // same, which is what makes this observable without privilege.
        use std::os::unix::fs::PermissionsExt;
        let dir = Scratch::new("copyin-own-setuid");
        std::fs::create_dir_all(dir.join("usr/libexec")).unwrap();
        let helper = dir.join("usr/libexec/helper");
        std::fs::write(&helper, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o4750)).unwrap();
        let (uid, gid) = own_ids();

        let mut frames = own_frame(b"usr/libexec/helper", uid, gid, &helper);
        frames.push(COPY_END);
        assert_eq!(consume_frames_in(dir.path(), &frames), Ok(()));
        assert_eq!(mode_and_mtime(&helper).0, 0o4750);
    }

    #[test]
    fn an_entry_whose_name_holds_something_else_is_left_alone() {
        // Root is an owner an unprivileged caller cannot give, so an attempt
        // fails, and an entry left alone is one with no attempt made.
        if rustix::process::getuid().is_root() {
            ferroday_cage_testkit::require::premise_unmet(
                "the test needs a caller other than root, to whom a chown to root is refused",
            );
            return;
        }
        let dir = Scratch::new("copyin-own-replaced");
        std::fs::write(dir.join("file"), b"laid down\n").unwrap();
        let frame = own_frame(b"file", 0, 0, &dir.join("file"));

        // Replaced since: another inode at the name. The original is kept
        // elsewhere, so its inode number is not the one the replacement takes.
        std::fs::rename(dir.join("file"), dir.join("kept")).unwrap();
        std::fs::write(dir.join("file"), b"a replacement\n").unwrap();
        let mut frames = frame.clone();
        frames.extend(own_frame_at(b"gone", 0, 0, 1, 1));
        frames.push(COPY_END);
        assert_eq!(consume_frames_in(dir.path(), &frames), Ok(()));

        // The entry itself is acted on, which is the refusal.
        let mut frames = own_frame(b"file", 0, 0, &dir.join("file"));
        frames.push(COPY_END);
        assert_eq!(
            consume_frames_in(dir.path(), &frames),
            Err((CopyStep::Chown, Errno::PERM)),
        );
    }

    #[test]
    fn an_owned_symbolic_link_is_owned_as_itself() {
        // The link is never followed: a frame naming the link acts on the
        // link, and an outside target is neither opened nor changed.
        if rustix::process::getuid().is_root() {
            ferroday_cage_testkit::require::premise_unmet(
                "the test needs a caller other than root, to whom a chown to root is refused",
            );
            return;
        }
        let dir = Scratch::new("copyin-own-link");
        let outside = Scratch::new("copyin-own-link-outside");
        let target = outside.join("target");
        std::fs::write(&target, b"outside\n").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("link")).unwrap();

        let mut frames = own_frame(b"link", 0, 0, &dir.join("link"));
        frames.push(COPY_END);
        assert_eq!(
            consume_frames_in(dir.path(), &frames),
            Err((CopyStep::Chown, Errno::PERM)),
            "the link itself is what the owner is given to",
        );

        // Named by the target's identity, the link is not the entry, and the
        // target is not reached through it.
        let mut frames = own_frame(b"link", 0, 0, &target);
        frames.push(COPY_END);
        assert_eq!(consume_frames_in(dir.path(), &frames), Ok(()));
    }

    #[test]
    fn an_entry_to_own_is_named_inside_the_root() {
        // The directory part resolves in the root, an absolute link included,
        // and a path that climbs out is a frame the child does not understand.
        let dir = Scratch::new("copyin-own-in-root");
        std::fs::create_dir_all(dir.join("run")).unwrap();
        std::fs::create_dir_all(dir.join("var")).unwrap();
        std::os::unix::fs::symlink("/run", dir.join("var/run")).unwrap();
        std::fs::write(dir.join("run/socketdir"), b"").unwrap();
        let (uid, gid) = own_ids();

        let mut frames = own_frame(b"var/run/socketdir", uid, gid, &dir.join("run/socketdir"));
        frames.push(COPY_END);
        assert_eq!(consume_frames_in(dir.path(), &frames), Ok(()));

        for path in [&b"../escape"[..], b"/etc/passwd", b"a//b", b"a/./b"] {
            let mut frames = own_frame_at(path, uid, gid, 0, 0);
            frames.push(COPY_END);
            assert_eq!(
                consume_frames_in(dir.path(), &frames),
                Err((CopyStep::BadName, Errno::INVAL)),
                "{}",
                String::from_utf8_lossy(path),
            );
        }
    }

    /// The permission bits and modification time of `path`, without following
    /// a symbolic link at it.
    fn mode_and_mtime(path: &std::path::Path) -> (u32, i64) {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path).expect("the entry exists");
        (meta.mode() & 0o7777, meta.mtime())
    }

    /// A directory the root already has is adopted as it stands, and one the
    /// copy creates takes the frame's metadata.
    ///
    /// The source's directory says where its contents go, not what the root's
    /// own directory should be: a source staged under umask 077 would otherwise
    /// leave the root's `/etc` at `0700`.
    #[test]
    fn a_directory_the_root_already_has_keeps_its_own_metadata() {
        use std::os::unix::fs::PermissionsExt;

        let dir = Scratch::new("copyin-adopt");
        std::fs::create_dir(dir.join("etc")).unwrap();
        std::fs::set_permissions(dir.join("etc"), PermissionsExt::from_mode(0o755)).unwrap();
        let stamp = rustix::fs::Timespec {
            tv_sec: 1_000_000_000,
            tv_nsec: 0,
        };
        fs::utimensat(
            fs::CWD,
            dir.join("etc"),
            &Timestamps {
                last_access: stamp,
                last_modification: stamp,
            },
            AtFlags::empty(),
        )
        .unwrap();

        let mut frames = dir_frame(b"etc", 0o700);
        frames.extend(LEAVE);
        frames.extend(dir_frame(b"new", 0o750));
        frames.extend(LEAVE);
        frames.push(COPY_END);
        assert_eq!(consume_frames_in(dir.path(), &frames), Ok(()));

        assert_eq!(
            mode_and_mtime(&dir.join("etc")),
            (0o755, 1_000_000_000),
            "the root's own directory was rewritten",
        );
        assert_eq!(mode_and_mtime(&dir.join("new")), (0o750, 0));
    }

    /// A directory entry lands through a symbolic link the root has at its
    /// name when the link resolves inside the root to a directory, and the link
    /// stays a link.
    ///
    /// Merged-usr's `bin -> usr/bin` is the relative case. `var/run -> /run`
    /// is the absolute one: it names the root's own `/run`, as it does to the
    /// sandbox, and resolving it anywhere else would write outside the root.
    #[test]
    fn a_directory_lands_through_an_alias_the_root_resolves() {
        let dir = Scratch::new("copyin-alias");
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::fs::create_dir_all(dir.join("run")).unwrap();
        std::fs::create_dir_all(dir.join("var")).unwrap();
        std::os::unix::fs::symlink("usr/bin", dir.join("bin")).unwrap();
        std::os::unix::fs::symlink("/run", dir.join("var/run")).unwrap();

        let mut frames = dir_frame(b"bin", 0o755);
        frames.extend(file_frame(b"tool", 0o755, b"#!/bin/sh\n"));
        frames.extend(LEAVE);
        frames.extend(dir_frame(b"var", 0o755));
        frames.extend(dir_frame(b"run", 0o755));
        frames.extend(file_frame(b"marker", 0o644, b"in the root's /run\n"));
        frames.extend(LEAVE);
        frames.extend(LEAVE);
        frames.push(COPY_END);
        assert_eq!(consume_frames_in(dir.path(), &frames), Ok(()));

        assert_eq!(
            std::fs::read(dir.join("usr/bin/tool")).unwrap(),
            b"#!/bin/sh\n"
        );
        assert_eq!(
            std::fs::read(dir.join("run/marker")).unwrap(),
            b"in the root's /run\n",
        );
        for alias in ["bin", "var/run"] {
            assert!(
                std::fs::symlink_metadata(dir.join(alias))
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "{alias} was replaced rather than laid through",
            );
        }
    }

    /// A hard link's anchor resolves from the root, so a path through an
    /// absolute alias names the root's own file rather than the host's.
    #[test]
    fn a_hardlink_anchor_resolves_inside_the_root() {
        use std::os::unix::fs::MetadataExt;

        let dir = Scratch::new("copyin-anchor");
        std::fs::create_dir_all(dir.join("run")).unwrap();
        std::fs::create_dir_all(dir.join("var")).unwrap();
        std::os::unix::fs::symlink("/run", dir.join("var/run")).unwrap();

        let mut frames = dir_frame(b"var", 0o755);
        frames.extend(dir_frame(b"run", 0o755));
        frames.extend(file_frame(b"first", 0o644, b"shared\n"));
        frames.extend(LEAVE);
        frames.extend(LEAVE);
        frames.extend(link_frame(b"second", b"var/run/first"));
        frames.push(COPY_END);
        assert_eq!(consume_frames_in(dir.path(), &frames), Ok(()));

        let ino = |path: &str| std::fs::symlink_metadata(dir.join(path)).unwrap().ino();
        assert_eq!(
            ino("second"),
            ino("run/first"),
            "the link is not onto the root's file"
        );
    }

    /// An attribute block gives a file its attributes after its data and
    /// metadata, gives a directory the copy created its own once it is left,
    /// and is read past for a directory the root already had, which keeps
    /// what it holds.
    #[test]
    fn an_attribute_block_lands_on_the_entry_the_copy_created() {
        let dir = Scratch::new("copyin-attributes");
        if !ferroday_cage_testkit::xattr::holds_user_attributes(dir.path()) {
            ferroday_cage_testkit::require::premise_unmet(
                "this filesystem holds no user extended attributes",
            );
            return;
        }
        std::fs::create_dir(dir.join("kept")).unwrap();
        let block = |value: &[u8]| attribute_block(&[(b"user.origin", value)]);

        let mut frames = dir_frame(b"made", 0o755);
        frames.extend(file_frame_with(
            b"file",
            0o644,
            b"contents\n",
            &[(b"user.origin", b"the file")],
        ));
        frames.push(COPY_LEAVE);
        frames.extend(block(b"the directory"));
        frames.extend(dir_frame(b"kept", 0o700));
        frames.push(COPY_LEAVE);
        frames.extend(block(b"not the root's"));
        frames.push(COPY_END);
        assert_eq!(consume_frames_in(dir.path(), &frames), Ok(()));

        assert_eq!(
            ferroday_cage_testkit::xattr::get(&dir.join("made/file"), "user.origin").as_deref(),
            Some(&b"the file"[..]),
        );
        assert_eq!(std::fs::read(dir.join("made/file")).unwrap(), b"contents\n");
        assert_eq!(
            ferroday_cage_testkit::xattr::get(&dir.join("made"), "user.origin").as_deref(),
            Some(&b"the directory"[..]),
        );
        assert_eq!(
            ferroday_cage_testkit::xattr::get(&dir.join("kept"), "user.origin"),
            None
        );
    }

    /// A block declaring a value past the kernel's own bound, or a name that is
    /// empty, is a stream the child does not understand.
    #[test]
    fn an_attribute_block_past_its_bounds_is_refused() {
        let mut frames = file_frame(b"file", 0o644, b"");
        frames.truncate(frames.len() - 2);
        frames.extend_from_slice(&1u16.to_le_bytes());
        frames.extend_from_slice(&6u16.to_le_bytes());
        frames.extend_from_slice(b"user.x");
        frames.extend_from_slice(&(XATTR_SIZE_MAX as u32 + 1).to_le_bytes());
        assert_eq!(
            consume_frames("copyin-attribute-oversized", &frames),
            Err((CopyStep::ReadFrame, Errno::TOOBIG)),
        );

        let mut frames = file_frame(b"file", 0o644, b"");
        frames.truncate(frames.len() - 2);
        frames.extend_from_slice(&1u16.to_le_bytes());
        frames.extend_from_slice(&0u16.to_le_bytes());
        frames.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            consume_frames("copyin-attribute-unnamed", &frames),
            Err((CopyStep::BadName, Errno::INVAL)),
        );
    }

    /// A link onto a name that already holds the anchor's file is already
    /// done: `bin/x` and `usr/bin/x` are one name where `bin` is a link to
    /// `usr/bin`, and replacing the name would remove the file.
    #[test]
    fn a_link_onto_a_name_already_holding_the_file_is_already_done() {
        let dir = Scratch::new("copyin-link-same");
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::os::unix::fs::symlink("usr/bin", dir.join("bin")).unwrap();

        let mut frames = dir_frame(b"bin", 0o755);
        frames.extend(file_frame(b"x", 0o755, b"#!/bin/sh\n"));
        frames.extend(LEAVE);
        frames.extend(dir_frame(b"usr", 0o755));
        frames.extend(dir_frame(b"bin", 0o755));
        frames.extend(link_frame(b"x", b"bin/x"));
        frames.extend(LEAVE);
        frames.extend(LEAVE);
        // And a link naming itself.
        frames.extend(file_frame(b"self", 0o644, b"once\n"));
        frames.extend(link_frame(b"self", b"self"));
        frames.push(COPY_END);
        assert_eq!(consume_frames_in(dir.path(), &frames), Ok(()));
        assert_eq!(
            std::fs::read(dir.join("usr/bin/x")).unwrap(),
            b"#!/bin/sh\n"
        );
        assert_eq!(std::fs::read(dir.join("self")).unwrap(), b"once\n");
    }

    /// Anything else at a directory's name is replaced, as a file entry
    /// replaces what occupies its own: a file, and a link that resolves to
    /// nothing.
    #[test]
    fn a_non_directory_in_the_way_of_a_directory_is_replaced() {
        let dir = Scratch::new("copyin-replace");
        std::fs::write(dir.join("was-a-file"), b"in the way\n").unwrap();
        std::os::unix::fs::symlink("nowhere", dir.join("was-dangling")).unwrap();

        let mut frames = Vec::new();
        for name in [&b"was-a-file"[..], b"was-dangling"] {
            frames.extend(dir_frame(name, 0o755));
            frames.extend(LEAVE);
        }
        frames.push(COPY_END);
        assert_eq!(consume_frames_in(dir.path(), &frames), Ok(()));

        for name in ["was-a-file", "was-dangling"] {
            assert!(
                std::fs::symlink_metadata(dir.join(name))
                    .unwrap()
                    .file_type()
                    .is_dir(),
                "{name} is not a directory",
            );
        }
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
        frames.extend(LEAVE);
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
