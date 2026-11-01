//! The framed byte protocol the helper children speak.
//!
//! The copy-in and export children each hold one conversation with the caller
//! over a pipe: little-endian scalars, `u16`-length-prefixed byte strings, and
//! tag bytes. Producer and consumer of each are in different modules — one runs
//! post-fork, one on the host — so the primitives live here and both ends read
//! them from one place.
//!
//! Everything here returns [`Errno`] and nothing here names a step. The step
//! vocabulary belongs to the caller, which adds it at the edge:
//!
//! ```ignore
//! frame::read_full(stream, &mut buf).map_err(|errno| (CopyStep::ReadFrame, errno))?;
//! ```
//!
//! # Post-fork
//!
//! Half the callers are post-fork children, so nothing here allocates, locks,
//! or panics, and every call is a bare `rustix` syscall.
//!
//! # Names
//!
//! End of input is the only axis on which the readers differ, so it is the only
//! thing their names say: [`read_full`] treats a short read as a truncated
//! frame, [`read_full_or_eof`] reports it, and [`read_full_or_short`] reports
//! how far the read got before it. The host side of the export reads through a
//! `std::io::Read` rather than a descriptor and keeps its own readers, but uses
//! these names for the shapes they share.

use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::io::Errno;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

/// Writes `data` in full, looping over short writes and retrying `EINTR`.
///
/// A write that reports zero bytes on a descriptor that is neither full nor
/// closed is an anomaly with no progress to make, so it is reported as `EIO`
/// rather than looped on forever.
pub(crate) fn write_full(fd: BorrowedFd<'_>, data: &[u8]) -> Result<(), Errno> {
    let mut written = 0;
    while written < data.len() {
        match rustix::io::write(fd, &data[written..]) {
            Ok(0) => return Err(Errno::IO),
            Ok(n) => written += n,
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(errno),
        }
    }
    Ok(())
}

/// Writes `data` in one `write`, for a file that takes its content whole or not
/// at all, retrying `EINTR`.
///
/// An identity-map file is one: the kernel parses the map from a single write
/// and refuses a second, so the partial progress [`write_full`] would resume
/// from cannot exist. A write that reports fewer bytes than `data` holds is
/// therefore not an errno the kernel gave, and `EMSGSIZE` is the one that says
/// what happened: the write did not carry the whole content. `EIO` would send a
/// reader looking for a device fault.
pub(crate) fn write_whole(fd: BorrowedFd<'_>, data: &[u8]) -> Result<(), Errno> {
    match retry_on_intr!(rustix::io::write(fd, data))? {
        written if written == data.len() => Ok(()),
        _ => Err(Errno::MSGSIZE),
    }
}

/// Fills `buf`, retrying `EINTR`, and treats end of input as a truncated frame.
///
/// The peer committed to the bytes when it wrote the frame that declared them,
/// so falling short is a conversation cut off part-way: `EPIPE`.
pub(crate) fn read_full(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<(), Errno> {
    match read_full_or_eof(fd, buf)? {
        true => Ok(()),
        false => Err(Errno::PIPE),
    }
}

/// Fills `buf`, retrying `EINTR`, and reports end of input rather than
/// failing on it.
///
/// `false` means the peer stopped writing before `buf` was full. That is the
/// right answer only where end of input is a legitimate ending — reading the
/// tag that begins a frame, where the peer may simply have nothing more to say.
/// Anywhere inside a frame, [`read_full`] is the reader that wants.
pub(crate) fn read_full_or_eof(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<bool, Errno> {
    Ok(read_full_or_short(fd, buf)? == buf.len())
}

/// Fills `buf`, retrying `EINTR`, and returns how much of it was filled: all
/// of it, or less where input ended first.
///
/// For a reader to whom end of input means one thing before a frame and
/// another inside one: nothing at all is an ending, and part of a frame is a
/// conversation cut off. [`read_full_or_eof`] answers both with `false`.
pub(crate) fn read_full_or_short(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<usize, Errno> {
    let mut read = 0;
    while read < buf.len() {
        match rustix::io::read(fd, &mut buf[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(errno),
        }
    }
    Ok(read)
}

/// The length of a helper child's outcome record: a step's wire value then an
/// errno, both little-endian.
///
/// The copy-in, export, and removal children each report how their work ended
/// in one. The launch stages' own report carries a detail index besides, and
/// is a record of its own.
pub(crate) const RECORD_LEN: usize = 8;

/// The wire value a record carries for a child that finished: above every
/// step's, which [`wire_enum`](crate::wire::wire_enum) numbers from zero
/// upward and so never reaches it.
pub(crate) const RECORD_DONE: u32 = u32::MAX;

/// Encodes an outcome record: `wire`, the failed step's wire value or
/// [`RECORD_DONE`], then `errno`.
pub(crate) fn encode_record(wire: u32, errno: i32) -> [u8; RECORD_LEN] {
    let mut record = [0u8; RECORD_LEN];
    record[0..4].copy_from_slice(&wire.to_le_bytes());
    record[4..8].copy_from_slice(&errno.to_le_bytes());
    record
}

/// Decodes an outcome record into the wire value and the errno it carries.
///
/// The wire value is the caller's to name a step from, since only the caller
/// knows which helper's steps it numbers.
pub(crate) fn decode_record(record: [u8; RECORD_LEN]) -> (u32, i32) {
    let [w0, w1, w2, w3, e0, e1, e2, e3] = record;
    (
        u32::from_le_bytes([w0, w1, w2, w3]),
        i32::from_le_bytes([e0, e1, e2, e3]),
    )
}

/// Reads one outcome record from a helper child's seqpacket gate, retrying
/// `EINTR`.
///
/// One read is one message on a seqpacket, so a record arrives whole or not at
/// all, and `None` is a message of any other length, end of input included:
/// what a child that exited without reporting leaves behind. A short message is
/// delivered whole, so reading it into the buffer and decoding would name a
/// step from the zeros after it. A reader that filled the buffer across reads
/// would instead join two messages into one record.
pub(crate) fn read_record(gate: BorrowedFd<'_>) -> Result<Option<[u8; RECORD_LEN]>, Errno> {
    let mut record = [0u8; RECORD_LEN];
    let received = retry_on_intr!(rustix::io::read(gate, &mut record))?;
    Ok((received == RECORD_LEN).then_some(record))
}

/// Writes a `u16` length prefix and the bytes it counts.
///
/// A byte string longer than a `u16` counts is `ERANGE`: the frame has no way
/// to declare it, and truncating the length would declare a different string.
///
/// The export child is its only caller, so a build without the `tarball`
/// feature has none.
#[cfg_attr(not(feature = "tarball"), allow(dead_code))]
pub(crate) fn write_bytes_u16(fd: BorrowedFd<'_>, data: &[u8]) -> Result<(), Errno> {
    let len = u16::try_from(data.len()).map_err(|_| Errno::RANGE)?;
    write_full(fd, &len.to_le_bytes())?;
    write_full(fd, data)
}

/// Reads a `u16`-length-prefixed byte string into `buf` and returns the part
/// of it that was filled.
///
/// A declared length larger than `buf` is `ENAMETOOLONG`. The bytes are not
/// consumed in that case: the conversation is already lost, and the caller ends
/// it rather than resynchronizing.
pub(crate) fn read_bytes_u16<'b>(fd: BorrowedFd<'_>, buf: &'b mut [u8]) -> Result<&'b [u8], Errno> {
    let mut len = [0u8; 2];
    read_full(fd, &mut len)?;
    let len = usize::from(u16::from_le_bytes(len));
    if len > buf.len() {
        return Err(Errno::NAMETOOLONG);
    }
    read_full(fd, &mut buf[..len])?;
    Ok(&buf[..len])
}

/// Retries a `rustix` call that was interrupted by a signal.
///
/// The expression is evaluated again on `EINTR` and its result returned
/// otherwise, which is the whole of the idiom:
///
/// ```ignore
/// let received = retry_on_intr!(rustix::io::read(gate, &mut record))?;
/// ```
///
/// A call whose partial progress must be accounted for — a short read, a short
/// write — needs more than a retry and belongs in one of the readers and
/// writers above instead.
macro_rules! retry_on_intr {
    ($call:expr) => {
        loop {
            match $call {
                Err(::rustix::io::Errno::INTR) => continue,
                other => break other,
            }
        }
    };
}

pub(crate) use retry_on_intr;

/// Sends `payload` as one message on a socket, with `fd` attached as
/// `SCM_RIGHTS`, retrying `EINTR`.
///
/// How a child hands the caller a descriptor it opened: the supervisor's pidfd,
/// the network stack's tap, the sandbox's pseudoterminal. Each rides on a
/// payload of its own protocol, which is the caller's to decide, and the
/// message is sent whole or not at all. A seqpacket socket keeps the payload
/// and its descriptor one unit on the receiving side, which is what every
/// caller here uses.
///
/// `SIGPIPE` is suppressed, so a peer that has gone is an `EPIPE` to report
/// rather than a signal to die of.
///
/// Post-fork safe: the control-message buffer is on the stack.
pub(crate) fn send_with_fd(
    socket: BorrowedFd<'_>,
    payload: &[u8],
    fd: BorrowedFd<'_>,
) -> Result<(), Errno> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let fds = [fd];
    ancillary.push(SendAncillaryMessage::ScmRights(&fds));
    retry_on_intr!(rustix::net::sendmsg(
        socket,
        &[std::io::IoSlice::new(payload)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    ))
    .map(|_| ())
}

/// Receives one message into `payload`, returning how many bytes arrived and
/// the descriptor attached to it, if one was, retrying `EINTR`.
///
/// The other end of [`send_with_fd`]. The descriptor arrives close-on-exec. A
/// message carrying more than one has the first returned and the rest closed,
/// and one carrying none, or a hangup reported as zero bytes, returns `None`
/// for it. Each caller judges the byte count against its own protocol, since
/// only it knows what a short message means.
pub(crate) fn recv_with_fd(
    socket: BorrowedFd<'_>,
    payload: &mut [u8],
) -> Result<(usize, Option<OwnedFd>), Errno> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = retry_on_intr!(rustix::net::recvmsg(
        socket,
        &mut [std::io::IoSliceMut::new(payload)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    ))?;
    let mut fd = None;
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(mut fds) = message
            && fd.is_none()
        {
            fd = fds.next();
        }
    }
    Ok((received.bytes, fd))
}
