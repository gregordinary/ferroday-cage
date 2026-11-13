//! The framed byte protocol the helper children speak.
//!
//! The copy-in and export children each hold one conversation with the caller
//! over a pipe: little-endian scalars, `u16`-length-prefixed byte strings, tag
//! bytes, and the bytes of a file. Producer and consumer of each are in
//! different modules — one runs post-fork, one on the host — so the primitives
//! live here and both ends read them from one place.
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

use super::bounds::DATA_BUF;

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

/// Which end of [`stream_exact`] or [`receive_runs`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamFailure {
    /// The file could not be read, or written.
    File(Errno),
    /// The stream could not be written, which is a peer that has gone; or read,
    /// which is a peer that stopped part-way or sent runs that do not add up.
    Stream(Errno),
}

/// How [`stream_exact`] sends a file's holes.
///
/// A hole is a range of a sparse file that holds no data and reads as zeros. A
/// file costs its writer nothing to make long that way: `truncate -s 16T`
/// writes no data and takes no space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Holes {
    /// As the zeros they read as, so the stream is exactly the file's bytes.
    #[cfg_attr(
        not(feature = "tarball"),
        allow(
            dead_code,
            reason = "only an export streams holes as zeros, and only a build with the tarball \
                      feature exports"
        )
    )]
    Zeros,
    /// As runs, which [`receive_runs`] writes back: each a tag, [`RUN_DATA`]
    /// or [`RUN_HOLE`], then its length as a little-endian `u64`, and a data
    /// run's bytes after that. A hole costs the stream nine bytes whatever its
    /// length. The file's data is found with `SEEK_DATA` and `SEEK_HOLE`, and
    /// a filesystem that cannot report where a file's holes are has the whole
    /// file sent as data.
    Runs,
}

/// Run tag: that many bytes of the file's data follow.
pub(crate) const RUN_DATA: u8 = 1;

/// Run tag: a hole that many bytes long, which carries no bytes.
pub(crate) const RUN_HOLE: u8 = 2;

/// Streams exactly `size` bytes of the regular file `file`, from its start, to
/// `stream`, and answers whether the file held a different number of bytes.
///
/// `size` is what a frame declared before any byte was read, and the peer is
/// counting on it, so the stream carries exactly that many whatever the file
/// does: one that ends early is padded with zeros, and one that grew is cut.
/// `true` says the file changed while it was read. The caller reports that,
/// since a file padded or cut to fit its frame is not a copy of the file; the
/// framing is kept so that the report can be made at all, rather than by a
/// peer reading the next frame out of the middle of this one. The file's
/// length once its bytes are sent is what notices one that grew, or one that
/// shrank into what was sent as a hole.
///
/// `holes` says whether a hole goes as zeros or as a run the peer skips.
///
/// The reads are positioned, so the file's offset is not what is read from.
/// `EINTR` is retried on both ends.
///
/// Kept out of line, so its buffer is on the stack only while a file streams
/// rather than in the frame of every level of the walk that calls it.
#[inline(never)]
pub(crate) fn stream_exact(
    file: BorrowedFd<'_>,
    stream: BorrowedFd<'_>,
    size: u64,
    holes: Holes,
) -> Result<bool, StreamFailure> {
    let mut buf = [0u8; DATA_BUF];
    let short = match holes {
        Holes::Zeros => send_range(file, stream, 0, size, &mut buf)?,
        Holes::Runs => send_runs(file, stream, size, &mut buf)?,
    };
    let length = rustix::fs::fstat(file)
        .map_err(StreamFailure::File)?
        .st_size;
    Ok(short || u64::try_from(length).ok() != Some(size))
}

/// Sends the first `size` bytes of `file` as runs, and answers whether a data
/// run read short.
fn send_runs(
    file: BorrowedFd<'_>,
    stream: BorrowedFd<'_>,
    size: u64,
    buf: &mut [u8],
) -> Result<bool, StreamFailure> {
    let mut short = false;
    let mut at = 0;
    while at < size {
        let (start, end) = data_extent(file, at, size)?;
        if start > at {
            send_run(stream, RUN_HOLE, start - at)?;
        }
        if end > start {
            send_run(stream, RUN_DATA, end - start)?;
            short |= send_range(file, stream, start, end - start, buf)?;
        }
        at = end;
    }
    Ok(short)
}

/// The next extent of data in the first `size` bytes of `file`, at or after
/// `at`: where it starts and where the hole after it does, both held to
/// `size`. A start at `size` is no data left, and the rest a hole.
///
/// An extent is never empty unless it is that one, so a walk over them always
/// moves on. A file that changed between the two seeks has what is left sent
/// as data, which [`send_range`] pads where the file has since ended.
fn data_extent(file: BorrowedFd<'_>, at: u64, size: u64) -> Result<(u64, u64), StreamFailure> {
    let start = match rustix::fs::seek(file, rustix::fs::SeekFrom::Data(at)) {
        Ok(start) => start.min(size),
        // No data at or past `at`: a hole runs to the end, or the file ended.
        Err(Errno::NXIO) => size,
        // A filesystem that cannot report its holes: all of it is data.
        Err(Errno::INVAL) => return Ok((at, size)),
        Err(errno) => return Err(StreamFailure::File(errno)),
    };
    if start == size {
        return Ok((size, size));
    }
    let end = match rustix::fs::seek(file, rustix::fs::SeekFrom::Hole(start)) {
        Ok(end) if end > start => end.min(size),
        Ok(_) | Err(Errno::NXIO) => size,
        Err(errno) => return Err(StreamFailure::File(errno)),
    };
    Ok((start, end))
}

/// Writes a run's tag and length.
fn send_run(stream: BorrowedFd<'_>, tag: u8, len: u64) -> Result<(), StreamFailure> {
    let mut run = [tag; 9];
    run[1..].copy_from_slice(&len.to_le_bytes());
    write_full(stream, &run).map_err(StreamFailure::Stream)
}

/// Sends `len` bytes of `file` from the offset `at`, padding with zeros where
/// the file ends first, and answers whether it did.
fn send_range(
    file: BorrowedFd<'_>,
    stream: BorrowedFd<'_>,
    at: u64,
    len: u64,
    buf: &mut [u8],
) -> Result<bool, StreamFailure> {
    let cap = buf.len();
    let chunk = |sent: u64| usize::try_from(len - sent).map_or(cap, |left| left.min(cap));
    let mut sent = 0;
    while sent < len {
        let want = chunk(sent);
        let read = retry_on_intr!(rustix::io::pread(
            file,
            &mut buf[..want],
            at.saturating_add(sent)
        ))
        .map_err(StreamFailure::File)?;
        if read == 0 {
            break;
        }
        write_full(stream, &buf[..read]).map_err(StreamFailure::Stream)?;
        sent += read as u64;
    }
    if sent == len {
        return Ok(false);
    }
    buf.fill(0);
    while sent < len {
        let want = chunk(sent);
        write_full(stream, &buf[..want]).map_err(StreamFailure::Stream)?;
        sent += want as u64;
    }
    Ok(true)
}

/// Reads the runs [`stream_exact`] sends with [`Holes::Runs`] from `stream`
/// into `file`, a file just created and empty, until they make up `size`
/// bytes.
///
/// A data run's bytes are written where the run begins, and a hole is passed
/// over, so the file holds no blocks for it. The length is set to `size` at
/// the end, which is what makes a hole at the end of the file. A run that is
/// empty, that reaches past `size`, or whose tag is neither is a stream this
/// does not understand, `EINVAL` on the stream's side.
///
/// Kept out of line for the reason [`stream_exact`] is.
#[inline(never)]
pub(crate) fn receive_runs(
    stream: BorrowedFd<'_>,
    file: BorrowedFd<'_>,
    size: u64,
) -> Result<(), StreamFailure> {
    let mut buf = [0u8; DATA_BUF];
    let mut at = 0;
    while at < size {
        let mut run = [0u8; 9];
        read_full(stream, &mut run).map_err(StreamFailure::Stream)?;
        let [tag, len @ ..] = run;
        let len = u64::from_le_bytes(len);
        if len == 0 || len > size - at {
            return Err(StreamFailure::Stream(Errno::INVAL));
        }
        match tag {
            RUN_DATA => {
                rustix::fs::seek(file, rustix::fs::SeekFrom::Start(at))
                    .map_err(StreamFailure::File)?;
                let mut left = len;
                while left > 0 {
                    let want = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
                    read_full(stream, &mut buf[..want]).map_err(StreamFailure::Stream)?;
                    write_full(file, &buf[..want]).map_err(StreamFailure::File)?;
                    left -= want as u64;
                }
            }
            RUN_HOLE => {}
            _ => return Err(StreamFailure::Stream(Errno::INVAL)),
        }
        at += len;
    }
    rustix::fs::ftruncate(file, size).map_err(StreamFailure::File)
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

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::os::unix::fs::{FileExt, MetadataExt};

    use super::*;
    use crate::scratch::Scratch;

    /// A sparse file `size` bytes long holding `data` at each offset given.
    fn sparse(path: &std::path::Path, size: u64, data: &[(u64, &[u8])]) -> std::fs::File {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .expect("the file is creatable");
        file.set_len(size).expect("the file is extendable");
        for (at, bytes) in data {
            file.write_all_at(bytes, *at).expect("the data is writable");
        }
        file
    }

    /// Whether `file` reports a hole at its start, which is what a filesystem
    /// that keeps sparse files does for one whose data starts later.
    fn reports_holes(file: &std::fs::File) -> bool {
        rustix::fs::seek(file, rustix::fs::SeekFrom::Data(0)).is_ok_and(|data| data > 0)
    }

    /// What `stream_exact` sends of `file` at a declared `size`, and whether
    /// it reports the file changed, through a scratch file no reader drains.
    fn streamed(dir: &Scratch, file: &std::fs::File, size: u64, holes: Holes) -> (Vec<u8>, bool) {
        let stream = std::fs::File::create(dir.join("stream")).expect("the stream file opens");
        let changed =
            stream_exact(file.as_fd(), stream.as_fd(), size, holes).expect("the file streams");
        (
            std::fs::read(dir.join("stream")).expect("the stream reads"),
            changed,
        )
    }

    /// A run's tag and length.
    fn run(tag: u8, len: u64) -> Vec<u8> {
        let mut run = vec![tag];
        run.extend_from_slice(&len.to_le_bytes());
        run
    }

    /// A sparse file goes as runs whose holes carry no bytes, and comes back
    /// as a file of the same length, holding the same bytes, and as sparse.
    #[test]
    fn a_sparse_file_crosses_the_stream_as_runs_and_lands_sparse() {
        let dir = Scratch::new("frame-runs");
        // A tebibyte: streamed as its zeros, it would not fit the disk.
        const SIZE: u64 = 1 << 40;
        let source = sparse(
            &dir.join("source"),
            SIZE,
            &[(1 << 30, b"middle"), (SIZE - 4, b"tail")],
        );
        if !reports_holes(&source) {
            ferroday_cage_testkit::require::premise_unmet(
                "this filesystem reports no holes in a sparse file",
            );
            return;
        }

        let (runs, changed) = streamed(&dir, &source, SIZE, Holes::Runs);
        assert!(!changed, "an unchanged file was reported changed");
        assert!(
            runs.len() < 64 * 1024,
            "the holes cost the stream {} bytes",
            runs.len()
        );
        assert_eq!(&runs[..9], run(RUN_HOLE, 1 << 30).as_slice());

        let landed = sparse(&dir.join("landed"), 0, &[]);
        let stream = std::fs::File::open(dir.join("stream")).expect("the stream opens");
        receive_runs(stream.as_fd(), landed.as_fd(), SIZE).expect("the runs land");
        let meta = landed.metadata().expect("the copy stats");
        assert_eq!(meta.len(), SIZE);
        assert!(
            meta.blocks() < 1024,
            "the copy holds {} blocks for its holes",
            meta.blocks()
        );
        for (at, len) in [(0, 16), ((1 << 30) - 8, 32), (SIZE - 16, 16)] {
            let (mut want, mut got) = (vec![0u8; len], vec![0u8; len]);
            source.read_exact_at(&mut want, at).unwrap();
            landed.read_exact_at(&mut got, at).unwrap();
            assert_eq!(got, want, "the bytes at {at} differ");
        }
    }

    /// A file streamed as runs keeps its framing and reports the change where
    /// it shrank into what was sent as a hole, or grew past what was declared;
    /// one with no holes goes as a single data run, exactly as zeros would.
    #[test]
    fn runs_keep_their_framing_and_report_a_changed_file() {
        let dir = Scratch::new("frame-runs-changed");
        let plain = sparse(&dir.join("plain"), 0, &[(0, b"12345")]);

        let (runs, changed) = streamed(&dir, &plain, 5, Holes::Runs);
        let mut expected = run(RUN_DATA, 5);
        expected.extend_from_slice(b"12345");
        assert_eq!((runs, changed), (expected, false));
        assert_eq!(
            streamed(&dir, &plain, 5, Holes::Zeros),
            (b"12345".to_vec(), false)
        );

        // Declared longer than the file: the rest goes as a hole, and the
        // length says the file is not what was declared.
        let (runs, changed) = streamed(&dir, &plain, 8, Holes::Runs);
        let mut expected = run(RUN_DATA, 5);
        expected.extend_from_slice(b"12345");
        expected.extend(run(RUN_HOLE, 3));
        assert_eq!((runs, changed), (expected, true));

        // Declared shorter: cut at the declared length.
        let (runs, changed) = streamed(&dir, &plain, 3, Holes::Runs);
        let mut expected = run(RUN_DATA, 3);
        expected.extend_from_slice(b"123");
        assert_eq!((runs, changed), (expected, true));

        // An empty file is no runs at all.
        let empty = sparse(&dir.join("empty"), 0, &[]);
        assert_eq!(streamed(&dir, &empty, 0, Holes::Runs), (Vec::new(), false));
    }

    /// Runs that do not add up to the declared size, or that name no kind of
    /// run, are a stream the reader does not understand.
    #[test]
    fn runs_that_do_not_add_up_are_refused() {
        let dir = Scratch::new("frame-runs-malformed");
        let mut past = run(RUN_DATA, 4);
        past.extend_from_slice(b"1234");
        for (tag, runs) in [
            ("empty", run(RUN_HOLE, 0)),
            ("past", past),
            ("unknown", run(9, 1)),
        ] {
            std::fs::write(dir.join("stream"), &runs).unwrap();
            let stream = std::fs::File::open(dir.join("stream")).unwrap();
            let landed = sparse(&dir.join(tag), 0, &[]);
            assert_eq!(
                receive_runs(stream.as_fd(), landed.as_fd(), 2),
                Err(StreamFailure::Stream(Errno::INVAL)),
                "{tag}",
            );
        }
        // A stream that ends inside a run is a peer that stopped part-way.
        std::fs::write(dir.join("stream"), run(RUN_DATA, 2)).unwrap();
        let stream = std::fs::File::open(dir.join("stream")).unwrap();
        let landed = sparse(&dir.join("cut"), 0, &[]);
        assert_eq!(
            receive_runs(stream.as_fd(), landed.as_fd(), 2),
            Err(StreamFailure::Stream(Errno::PIPE)),
        );
    }
}
