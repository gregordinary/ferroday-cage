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
//! frame, and [`read_full_or_eof`] reports it. The host side of the export
//! reads through a `std::io::Read` rather than a descriptor and keeps its own
//! readers, but uses these names for the shapes they share.

use std::os::fd::BorrowedFd;

use rustix::io::Errno;

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
    let mut read = 0;
    while read < buf.len() {
        match rustix::io::read(fd, &mut buf[read..]) {
            Ok(0) => return Ok(false),
            Ok(n) => read += n,
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(errno),
        }
    }
    Ok(true)
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
