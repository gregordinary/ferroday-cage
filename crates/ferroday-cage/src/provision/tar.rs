//! A read-only tar parser for POSIX ustar, GNU, pax, and pre-POSIX v7
//! archives.
//!
//! The parser yields entry metadata and streams entry data; it interprets
//! GNU long-name (`L`)/long-link (`K`) entries and pax extended headers
//! (`x` per-entry, and `g` global, whose per-file keywords are read past)
//! internally, so a consumer only ever sees
//! concrete file entries with their effective path, link target, size, and
//! times. Header checksums are verified.
//!
//! The writing side is here too, as [`ustar_block`]: one header block, its
//! checksum, and the padding that follows an entry's data. It is the whole of
//! what a writer shares with a reader, and keeping the two in one module is
//! what stops the field offsets being written down twice.
//!
//! v7 is a subset rather than a separate format: the first 257 bytes of a
//! header are laid out identically, and what v7 lacks is everything after them
//! — the magic, the version, `uname`/`gname`, the device numbers, and the
//! `prefix`. A v7 header is therefore read as a ustar one whose fields beyond
//! 257 are absent. It is worth reading because the archives a caller hands this
//! parser are no longer only rootfs tarballs, which contemporary tooling
//! produces: an upstream release tarball was produced by whoever released the
//! software, on whatever machine, in whatever year.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use super::ProvisionError;
use super::compress::{Refusal, read_fully};

/// The size of a tar block, and of a tar header.
pub(crate) const BLOCK: u64 = 512;

/// The largest metadata entry (GNU long name, pax header) accepted.
///
/// Real metadata entries are at most a few kilobytes; a huge one is a
/// malformed or hostile archive, not a rootfs.
const METADATA_LIMIT: u64 = 1 << 20;

/// One entry's effective metadata.
///
/// Paths and link targets are byte strings as recorded in the archive; the
/// extractor validates and interprets them.
#[derive(Debug)]
pub(crate) struct Entry {
    /// The entry's path bytes, after long-name and pax resolution.
    pub path: Vec<u8>,
    /// The link target for symlink and hardlink entries.
    pub link_target: Vec<u8>,
    /// The tar typeflag byte.
    ///
    /// `S` for a GNU sparse member, whichever of GNU's formats wrote it. The
    /// old GNU format marks one with that typeflag. The pax formats (0.0, 0.1
    /// and 1.0) write a regular file's `0` and describe the sparseness only in
    /// `GNU.sparse.*` records, so the member's data is a packed form of the
    /// file, or a map and the packed form, rather than its contents. Reading
    /// one as the `0` it claims would yield a file other than the one archived,
    /// so the reader reports the type the member is.
    pub typeflag: u8,
    /// The permission bits, as stored (may include setuid/setgid/sticky).
    pub mode: u32,
    /// The owning user id, as stored. The extractor does not apply it; it
    /// is read so a consumer can act on non-root ownership (a `.deb`'s
    /// setgid helpers, for instance). The only such consumer today is the
    /// Debian provisioner, so a build without that feature parses the field
    /// but reads no further.
    #[cfg_attr(not(feature = "debian"), allow(dead_code))]
    pub uid: u32,
    /// The owning group id, as stored. Not applied by the extractor; read
    /// only by the Debian provisioner, as [`uid`](Self::uid) is.
    #[cfg_attr(not(feature = "debian"), allow(dead_code))]
    pub gid: u32,
    /// The owning user's name, as stored: the ustar header's `uname`, or a pax
    /// `uname` record. Empty where the archive states none, as a v7 header
    /// cannot.
    ///
    /// Read for the Alpine layer, which gives a package's entries their owner
    /// as `apk` does: by this name, looked up in the root being built, with
    /// [`uid`](Self::uid) where the root has no such account.
    #[cfg_attr(not(feature = "alpine"), allow(dead_code))]
    pub uname: Vec<u8>,
    /// The owning group's name, as stored, and read for the same reason as
    /// [`uname`](Self::uname).
    #[cfg_attr(not(feature = "alpine"), allow(dead_code))]
    pub gname: Vec<u8>,
    /// The data size in bytes.
    pub size: u64,
    /// Modification time, seconds since the epoch.
    pub mtime: i64,
    /// The SHA-1 an `APK-TOOLS.checksum.SHA1` pax record states for this
    /// entry, where it carries one.
    ///
    /// A vendor record, read for the same reason [`uid`](Self::uid) is: one
    /// layer needs it and the reader is the only place it can be seen. apk
    /// writes it for every file and symbolic link of a package's data segment
    /// — over the contents of a file, over the target of a link — and it is
    /// what an installed-database record carries as its `Z:` field, so the
    /// Alpine layer reads it here rather than digesting a tree it has just
    /// written.
    #[cfg_attr(not(feature = "alpine"), allow(dead_code))]
    pub checksum_sha1: Option<[u8; 20]>,
    /// The POSIX access control list a `SCHILY.xattr.system.posix_acl_access`
    /// record states for this entry, as the attribute's own value: the kernel's
    /// binary form, its named ids as the archive's writer read them.
    ///
    /// An [`Export`](super::Export) writes one for every entry that carries a
    /// list. It is read for the extractor, which gives the entry the list
    /// rather than the mode alone: where a list has a mask, the mode's group
    /// bits are the mask, and the mode alone would give the owning group what
    /// the mask allows.
    pub acl_access: Option<Vec<u8>>,
    /// The default list a `SCHILY.xattr.system.posix_acl_default` record states
    /// for a directory, in the same form, read for the same reason.
    pub acl_default: Option<Vec<u8>>,
}

/// Whether entries of type `typeflag` carry a data stream.
///
/// Hardlinks, symlinks, devices, directories, and FIFOs have none;
/// everything else — including unknown typeflags, which POSIX says to
/// treat as regular files — is followed by `size` bytes of data.
fn has_data(typeflag: u8) -> bool {
    !matches!(typeflag, b'1' | b'2' | b'3' | b'4' | b'5' | b'6')
}

/// Pax keys collected from an `x` or `g` header.
#[derive(Debug, Default, Clone)]
struct PaxRecords {
    path: Option<Vec<u8>>,
    link_target: Option<Vec<u8>>,
    size: Option<u64>,
    mtime: Option<i64>,
    uid: Option<u32>,
    gid: Option<u32>,
    uname: Option<Vec<u8>>,
    gname: Option<Vec<u8>>,
    checksum_sha1: Option<[u8; 20]>,
    acl_access: Option<Vec<u8>>,
    acl_default: Option<Vec<u8>>,
    /// Whether any `GNU.sparse.*` record was present, which makes the entry a
    /// GNU sparse member in one of the pax formats.
    gnu_sparse: bool,
}

impl PaxRecords {
    /// Overlays `other` on top of `self`, `other` winning where both are set:
    /// a pax header may be split across several `x` entries, and the later one
    /// states the attribute.
    fn overlaid(&self, other: &PaxRecords) -> PaxRecords {
        PaxRecords {
            path: other.path.clone().or_else(|| self.path.clone()),
            link_target: other
                .link_target
                .clone()
                .or_else(|| self.link_target.clone()),
            size: other.size.or(self.size),
            mtime: other.mtime.or(self.mtime),
            uid: other.uid.or(self.uid),
            gid: other.gid.or(self.gid),
            uname: other.uname.clone().or_else(|| self.uname.clone()),
            gname: other.gname.clone().or_else(|| self.gname.clone()),
            checksum_sha1: other.checksum_sha1.or(self.checksum_sha1),
            acl_access: other.acl_access.clone().or_else(|| self.acl_access.clone()),
            acl_default: other
                .acl_default
                .clone()
                .or_else(|| self.acl_default.clone()),
            gnu_sparse: other.gnu_sparse || self.gnu_sparse,
        }
    }
}

/// Reasons a header block is rejected.
#[derive(Debug, PartialEq, Eq)]
enum HeaderFlaw {
    NotATarHeader,
    Checksum,
    Numeric,
}

impl HeaderFlaw {
    fn describe(&self) -> &'static str {
        match self {
            HeaderFlaw::NotATarHeader => {
                "the block is not a tar header: it carries no ustar or GNU magic \
                 and its checksum does not match"
            }
            HeaderFlaw::Checksum => "the header checksum does not match",
            HeaderFlaw::Numeric => "a numeric header field is not octal or base-256",
        }
    }
}

/// A streaming tar reader over any byte source.
///
/// A read of the source that fails is reported as what it is
/// ([`read_failure`]): the source failing, an OS error or a transport's, as
/// [`ProvisionError::Io`] naming the archive, and a decoder beneath refusing
/// the stream as [`ProvisionError::Archive`] with the decoder's failure as its
/// cause. Every other failure is the archive's, a refusal of what it declares.
pub(crate) struct TarReader<R: Read> {
    inner: R,
    /// The archive, as a failure to read it names it.
    path: PathBuf,
    /// Whether the stream turned out not to be a tar archive at all. Read by
    /// [`not_a_tar`](Self::not_a_tar).
    not_a_tar: bool,
    /// Bytes consumed from the (uncompressed) stream, for error offsets.
    offset: u64,
    /// Unread data bytes of the current entry.
    data_remaining: u64,
    /// Block-padding bytes following the current entry's data.
    padding: u64,
    /// Set once the archive terminator or EOF was seen.
    finished: bool,
}

impl<'a> TarReader<&'a [u8]> {
    /// A reader over an archive held in memory.
    ///
    /// No read of a slice fails, so nothing names the archive.
    #[cfg_attr(not(feature = "alpine"), allow(dead_code))]
    pub(crate) fn in_memory(archive: &'a [u8]) -> Self {
        TarReader::new(archive, PathBuf::new())
    }
}

impl<R: Read> TarReader<R> {
    /// A reader over `inner`, which holds the archive at `path`.
    ///
    /// `path` is what a failure to read `inner` names: the file, or, for a
    /// stream that has none, what the caller calls it.
    pub(crate) fn new(inner: R, path: impl Into<PathBuf>) -> Self {
        TarReader {
            inner,
            path: path.into(),
            not_a_tar: false,
            offset: 0,
            data_remaining: 0,
            padding: 0,
            finished: false,
        }
    }

    /// Whether the failure was that this is not a tar archive at all.
    ///
    /// Meaningful only after [`next_entry`](Self::next_entry) returned an
    /// error; a caller reports "not a tar archive" rather than "corrupt
    /// archive" on it. True in exactly three cases: the stream ended before
    /// its first byte, it ended inside its first block, or that block is no
    /// header. The last is a block carrying neither magic whose checksum does
    /// not match either, which with v7 accepted is what any other format's
    /// first 512 bytes look like.
    ///
    /// Every other failure keeps its own reason, however early it came. A first
    /// block carrying the magic with a checksum that does not match is a
    /// corrupt tar header, and one the reader refuses for what it declares is a
    /// malformed archive. A read that *failed* is the reader underneath: the
    /// source, or a decompressor whose refusal (a dictionary over the bound, a
    /// truncated stream, a frame it will not decode) is a diagnostic with a
    /// reason in it. Calling any of these "not a tar archive" would replace the
    /// reason with a guess about the format.
    pub fn not_a_tar(&self) -> bool {
        self.not_a_tar
    }

    /// Advances to the next file entry, returning `None` at the end of the
    /// archive.
    ///
    /// Any unread data of the previous entry is drained first. Metadata
    /// entries (GNU long names, pax headers) are consumed internally and
    /// folded into the entry they describe.
    pub fn next_entry(&mut self) -> Result<Option<Entry>, ProvisionError> {
        if self.finished {
            return Ok(None);
        }
        self.drain_current()?;

        // Metadata accumulated for the upcoming file entry.
        let mut gnu_longname: Option<Vec<u8>> = None;
        let mut gnu_longlink: Option<Vec<u8>> = None;
        let mut pax_entry: Option<PaxRecords> = None;

        loop {
            let header_offset = self.offset;
            let mut block = [0u8; BLOCK as usize];
            if !self.read_block(&mut block)? {
                // EOF before the first header block: there is no archive here.
                // The tolerance below is for an archive that ran out of
                // terminator, which presupposes an archive; a stream that
                // ended before its first header is a file of some other
                // format, or an empty one, and calling it a complete archive
                // of nothing publishes an empty rootfs as a finished tree.
                if header_offset == 0 {
                    self.not_a_tar = true;
                    return Err(malformed(0, "the stream holds no archive"));
                }
                // EOF at a later header boundary. GNU tar tolerates a missing
                // two-block terminator, and so do we — unless metadata was
                // left dangling.
                if gnu_longname.is_some() || gnu_longlink.is_some() || pax_entry.is_some() {
                    return Err(malformed(
                        header_offset,
                        "the archive ends after a metadata entry",
                    ));
                }
                self.finished = true;
                return Ok(None);
            }

            if block.iter().all(|b| *b == 0) {
                // The terminator. The second zero block is not insisted on.
                // Metadata waiting for an entry it never got is refused here as
                // it is at the end of the stream: the two are one archive
                // ending in one place, spelled with and without its marker.
                if gnu_longname.is_some() || gnu_longlink.is_some() || pax_entry.is_some() {
                    return Err(malformed(
                        header_offset,
                        "the archive ends after a metadata entry",
                    ));
                }
                self.finished = true;
                return Ok(None);
            }

            let mut entry = match parse_header(&block) {
                Ok(entry) => entry,
                Err(flaw) => {
                    self.not_a_tar = header_offset == 0 && flaw == HeaderFlaw::NotATarHeader;
                    return Err(malformed(header_offset, flaw.describe()));
                }
            };
            self.set_current(&entry);

            match entry.typeflag {
                // GNU long name / long link: the data names the next entry.
                b'L' => {
                    gnu_longname = Some(self.read_metadata()?);
                    trim_trailing_nuls(gnu_longname.as_mut().expect("just set"));
                }
                b'K' => {
                    gnu_longlink = Some(self.read_metadata()?);
                    trim_trailing_nuls(gnu_longlink.as_mut().expect("just set"));
                }
                // Pax extended headers.
                b'x' => {
                    let data = self.read_metadata()?;
                    let records =
                        parse_pax(&data).map_err(|reason| malformed(header_offset, reason))?;
                    pax_entry = Some(match pax_entry {
                        Some(prior) => prior.overlaid(&records),
                        None => records,
                    });
                }
                b'g' => {
                    // A global extended header states attributes for every
                    // entry after it, and every keyword this reader
                    // understands is a per-file one: a path, a size, an
                    // owner, a digest. Taking them from here would let one
                    // record at the head of an archive rename every member —
                    // or, with a `size` the entry's own header contradicts,
                    // split one member into two, since the bytes past the
                    // declared size are read as the next header. That is a
                    // member set no other reader agrees with, which is the
                    // shape a tar parser differential takes. GNU tar decodes
                    // no per-file keyword from a global header either.
                    //
                    // The records are still parsed, so a malformed global
                    // header is a malformed archive rather than a block read
                    // past without looking.
                    let data = self.read_metadata()?;
                    parse_pax(&data).map_err(|reason| malformed(header_offset, reason))?;
                }
                _ => {
                    // A concrete file entry: fold in the accumulated
                    // metadata, per-entry pax beating GNU long names.
                    let pax = pax_entry.unwrap_or_default();
                    if let Some(path) = pax.path {
                        entry.path = path;
                    } else if let Some(longname) = gnu_longname {
                        entry.path = longname;
                    }
                    if let Some(link) = pax.link_target {
                        entry.link_target = link;
                    } else if let Some(longlink) = gnu_longlink {
                        entry.link_target = longlink;
                    }
                    if let Some(size) = pax.size {
                        entry.size = size;
                    }
                    if let Some(mtime) = pax.mtime {
                        entry.mtime = mtime;
                    }
                    if let Some(uid) = pax.uid {
                        entry.uid = uid;
                    }
                    if let Some(gid) = pax.gid {
                        entry.gid = gid;
                    }
                    if let Some(uname) = pax.uname {
                        entry.uname = uname;
                    }
                    if let Some(gname) = pax.gname {
                        entry.gname = gname;
                    }
                    entry.checksum_sha1 = pax.checksum_sha1;
                    entry.acl_access = pax.acl_access;
                    entry.acl_default = pax.acl_default;
                    // A pax sparse member says `0` in its header; see
                    // `Entry::typeflag`. Its size is still the stored length,
                    // so the reader reads past it as it would any member.
                    if pax.gnu_sparse {
                        entry.typeflag = b'S';
                    }
                    // A trailing slash marks a directory, whatever the typeflag
                    // says. The oldest archives predate a reliably-set typeflag
                    // and mark a directory this way and no other.
                    //
                    // Read from the *resolved* path rather than from the
                    // header's own name field, which is what a long name or a
                    // pax record has just replaced. A header's name field holds
                    // at most 100 bytes, so for such an entry it is a truncation
                    // of the real path -- and a truncation that happens to land
                    // just after a separator would otherwise turn a regular file
                    // into a directory. That is not a cosmetic misreading: a
                    // directory carries no data, so the file's bytes would be
                    // read as the next header, and the rest of the archive with
                    // them. A real Gentoo stage3 is where that was found.
                    if entry.typeflag == b'0' && entry.path.last() == Some(&b'/') {
                        // Unless it declares data, which no directory has. Such
                        // an entry says two incompatible things about itself,
                        // and a reader that resolved the contradiction would
                        // pick one of two archives: taking the name drops the
                        // bytes it declared and reads them as the next header,
                        // and taking the size writes a file at a directory's
                        // name. Refusing is what keeps two readers of these
                        // bytes from disagreeing, which is the shape a tar
                        // parser differential takes.
                        if entry.size != 0 {
                            return Err(malformed(
                                header_offset,
                                "an entry names a directory and declares data",
                            ));
                        }
                        entry.typeflag = b'5';
                    }
                    // The size and the type recorded when the header was parsed
                    // may both have changed since; the data bookkeeping follows
                    // the entry as it finally reads.
                    self.set_current(&entry);
                    return Ok(Some(entry));
                }
            }
        }
    }

    /// Reads from the current entry's data, returning `Ok(0)` when the
    /// data is exhausted.
    ///
    /// The buffer is filled as far as the entry's remaining data reaches, through
    /// [`read_fully`], which retries a read a signal interrupted: the archive may
    /// arrive over a pipe or a socket, in a process whose signal handlers do not
    /// restart the calls they interrupt, and one `EINTR` is not a broken archive.
    /// Every byte asked for is one the entry declares, so a fill that ends short
    /// is an archive that ends inside the entry.
    pub fn read_data(&mut self, buf: &mut [u8]) -> Result<usize, ProvisionError> {
        if self.data_remaining == 0 {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.data_remaining).unwrap_or(usize::MAX));
        let got = read_fully(&mut self.inner, &mut buf[..want]).map_err(|err| self.failure(err))?;
        self.offset += got as u64;
        self.data_remaining -= got as u64;
        if got < want {
            return Err(malformed(
                self.offset,
                "the archive ends inside an entry's data",
            ));
        }
        Ok(got)
    }

    /// Records the data and padding lengths for `entry`.
    ///
    /// The padded length always fits: header sizes are bounded to `i64` by
    /// [`parse_header`], and pax sizes are validated by [`parse_pax`].
    fn set_current(&mut self, entry: &Entry) {
        let size = if has_data(entry.typeflag) {
            entry.size
        } else {
            0
        };
        self.data_remaining = size;
        self.padding = size.next_multiple_of(BLOCK) - size;
    }

    /// Skips whatever remains of the current entry: unread data, then the
    /// block padding.
    ///
    /// Read through [`read_fully`], so an interrupted read is retried rather
    /// than reported, as [`read_data`](Self::read_data) retries one.
    fn drain_current(&mut self) -> Result<(), ProvisionError> {
        let mut skip = self.data_remaining + self.padding;
        self.data_remaining = 0;
        self.padding = 0;
        let mut scratch = [0u8; 4096];
        while skip > 0 {
            let want = scratch
                .len()
                .min(usize::try_from(skip).unwrap_or(usize::MAX));
            let got = read_fully(&mut self.inner, &mut scratch[..want])
                .map_err(|err| self.failure(err))?;
            self.offset += got as u64;
            if got < want {
                return Err(malformed(self.offset, "the archive ends inside an entry"));
            }
            skip -= got as u64;
        }
        Ok(())
    }

    /// Reads one full block. Returns `false` on clean EOF at the block
    /// boundary; a partial block is an error.
    fn read_block(&mut self, block: &mut [u8; BLOCK as usize]) -> Result<bool, ProvisionError> {
        let first = self.offset == 0;
        let filled = read_fully(&mut self.inner, block).map_err(|err| self.failure(err))?;
        self.offset += filled as u64;
        match filled {
            0 => Ok(false),
            filled if filled == block.len() => Ok(true),
            _ => {
                // Fewer bytes than one header holds: no archive, if these were
                // all the stream had.
                self.not_a_tar = first;
                Err(malformed(
                    self.offset,
                    "the archive ends inside a header block",
                ))
            }
        }
    }

    /// Reads the stream on past the end-of-archive marker to its end, refusing
    /// more than `limit` bytes of it.
    ///
    /// A tar archive ends at its marker, and nothing after it is part of the
    /// archive. The stream the archive is read from may not end there: the
    /// rest of the last record is padding, and a compressed stream closes with
    /// the check over the last block it decoded, which covers the marker and
    /// the entries before it. Stopping at the marker leaves that check unread,
    /// so a corrupt final block would be extracted as though it were sound.
    /// Reading on to the end is what has the decoder compare it.
    ///
    /// For an archive whose bytes are verified against a digest before it is
    /// read, the decoder's check adds nothing, and a caller reading one need not
    /// finish it. For one nothing else vouches for, the check is the only
    /// thing that would say the stream is damaged.
    ///
    /// What follows the marker is decoded only to be discarded, so `limit`
    /// bounds what a stream can make that cost: a few mebibytes of input can
    /// decompress to far more than any record padding.
    pub(crate) fn finish(&mut self, limit: u64) -> Result<(), ProvisionError> {
        let mut remaining = limit;
        let mut scratch = [0u8; 4096];
        loop {
            let got = match self.inner.read(&mut scratch) {
                Ok(0) => return Ok(()),
                Ok(got) => got as u64,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(self.failure(err)),
            };
            self.offset += got;
            remaining = remaining.checked_sub(got).ok_or_else(|| {
                malformed(
                    self.offset,
                    &format!("more than {limit} bytes follow the end of the archive"),
                )
            })?;
        }
    }

    /// Reads what is left of the current entry's data into memory, refusing an
    /// entry that holds more than `limit` bytes.
    ///
    /// The one way an entry is held whole, for the members a reader acts on as
    /// a unit: a control file, a package's metadata, a GNU long name. The
    /// ceiling is the caller's, since only the caller knows what the entry is.
    ///
    /// The refusal is made on the length the header declares, before a byte of
    /// the data is read, and is never a truncation: [`read_data`](Self::read_data)
    /// delivers exactly the declared length or fails, so what is returned is
    /// the whole entry. A declared length is still the archive's own claim
    /// until the bytes arrive, so the reservation made up front is the smaller
    /// of it and [`RESERVE`], and the buffer grows from there with what the
    /// archive actually holds. A header claiming the whole ceiling for an entry
    /// that stops short of it costs the reservation, not the ceiling.
    pub(crate) fn read_entry(&mut self, limit: u64) -> Result<Vec<u8>, ProvisionError> {
        let declared = self.data_remaining;
        if declared > limit {
            return Err(malformed(
                self.offset,
                &format!("an entry of {declared} bytes is more than the {limit} accepted for it"),
            ));
        }
        let reserve = usize::try_from(declared).map_or(RESERVE, |declared| declared.min(RESERVE));
        let mut data = Vec::with_capacity(reserve);
        let mut chunk = [0u8; 8192];
        loop {
            let got = self.read_data(&mut chunk)?;
            if got == 0 {
                return Ok(data);
            }
            data.extend_from_slice(&chunk[..got]);
        }
    }

    /// Reads the current (metadata) entry's data in full, under
    /// [`METADATA_LIMIT`], and drains its padding.
    fn read_metadata(&mut self) -> Result<Vec<u8>, ProvisionError> {
        let data = self.read_entry(METADATA_LIMIT)?;
        self.drain_current()?;
        Ok(data)
    }

    /// `err`, a failed read of the source, as this archive reports it.
    fn failure(&self, err: io::Error) -> ProvisionError {
        read_failure(&self.path, self.offset, err)
    }
}

/// A failed read beneath the archive at `path`, `offset` bytes into it, as the
/// failure it is.
///
/// A decoder's [`Refusal`] is the archive's: [`ProvisionError::Archive`], the
/// decoder's own failure its cause. A failure [`into_io`] carried through a
/// `Read` is the reader's that failed, returned as it was. Anything else is the
/// source failing to deliver what it holds, an OS error or a transport's, and
/// is [`ProvisionError::Io`] naming the archive: a caller that retries such a
/// failure can tell it from a malformed archive, which a retry will not mend.
pub(crate) fn read_failure(path: &Path, offset: u64, err: io::Error) -> ProvisionError {
    if err.get_ref().is_some_and(|inner| inner.is::<Carried>()) {
        let carried = err
            .into_inner()
            .expect("a carried error carries its failure");
        return carried
            .downcast::<Carried>()
            .expect("the carried failure was checked for")
            .0;
    }
    match Refusal::of(err) {
        Ok(refusal) => ProvisionError::Archive {
            offset,
            reason: refusal.what().to_string(),
            source: Some(refusal.into_cause()),
        },
        Err(err) => ProvisionError::io("reading", path, err),
    }
}

/// `err`, a failure of a [`TarReader`], as the `io::Error` a `Read` over an
/// entry's data returns, so a reader of that data reports it as
/// [`read_failure`] does.
///
/// An OS failure is returned as the OS returned it, which is what a reader above
/// takes it for; it names the archive again by its own path, the archive that
/// holds the entry. Any other failure is carried whole, and a reader above
/// returns it as it stands rather than as a failure of its own.
#[cfg_attr(not(feature = "gentoo"), allow(dead_code))]
pub(crate) fn into_io(err: ProvisionError) -> io::Error {
    match err {
        ProvisionError::Io { source, .. } => source,
        other => io::Error::new(io::ErrorKind::InvalidData, Carried(other)),
    }
}

/// A [`TarReader`]'s failure carried through `Read` by [`into_io`].
///
/// [`read_failure`] unwraps one, so this is rendered only where a carried
/// failure reaches something other than a reader of the archive, as the layer
/// above the reader's own failure.
#[cfg_attr(not(feature = "gentoo"), allow(dead_code))]
#[derive(Debug)]
struct Carried(ProvisionError);

impl fmt::Display for Carried {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the archive the data is read from failed")
    }
}

impl std::error::Error for Carried {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// The most [`TarReader::read_entry`] reserves before an entry's data arrives.
///
/// Every entry read whole is a few kilobytes in practice, so this covers the
/// real ones in one allocation, and a larger one grows past it as it is read.
const RESERVE: usize = 64 * 1024;

/// Builds [`ProvisionError::Archive`] for a refusal of what the archive
/// declares, which nothing beneath it caused.
fn malformed(offset: u64, reason: &str) -> ProvisionError {
    ProvisionError::Archive {
        offset,
        reason: reason.to_string(),
        source: None,
    }
}

/// Removes trailing NUL bytes (long-name data is NUL-terminated).
fn trim_trailing_nuls(bytes: &mut Vec<u8>) {
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
}

/// Parses a 512-byte header block into an [`Entry`].
fn parse_header(block: &[u8; BLOCK as usize]) -> Result<Entry, HeaderFlaw> {
    // Magic: POSIX writes "ustar\0" + version "00"; GNU writes "ustar " +
    // " \0". A v7 header has neither, those bytes being part of its unused
    // tail, so the magic no longer decides whether a block is accepted — it
    // decides only whether the fields beyond byte 257 are there to read.
    let posix = &block[257..263] == b"ustar\0";
    let gnu = &block[257..263] == b"ustar ";

    // The checksum runs first, and with v7 accepted it is the only thing
    // separating a header from arbitrary bytes. That makes the two failures
    // worth telling apart: magic present and checksum wrong is a corrupt tar
    // header, while neither present is a file that is very likely not a tar at
    // all — a diagnostic worth keeping, since it is the one a caller who
    // pointed the parser at the wrong file needs.
    if verify_checksum(block).is_err() {
        return Err(if posix || gnu {
            HeaderFlaw::Checksum
        } else {
            HeaderFlaw::NotATarHeader
        });
    }

    let mut path = field_bytes(&block[0..100]).to_vec();
    // The POSIX prefix field extends the name; GNU reuses those bytes for
    // other purposes, and v7 has no such field at all.
    if posix {
        let prefix = field_bytes(&block[345..500]);
        if !prefix.is_empty() {
            let mut joined = prefix.to_vec();
            joined.push(b'/');
            joined.extend_from_slice(&path);
            path = joined;
        }
    }

    // A mode and an id are both unsigned. The base-256 form is two's complement
    // and can carry a negative value, which a cast would wrap into a
    // plausible-looking permission set — the setuid, setgid, and sticky bits
    // included — or into an unrelated id; refusing it keeps a malformed header
    // from silently deciding either.
    let mode = unsigned_field(&block[100..108])?;
    let uid = unsigned_field(&block[108..116])?;
    let gid = unsigned_field(&block[116..124])?;
    let size = u64::try_from(numeric_field(&block[124..136])?).map_err(|_| HeaderFlaw::Numeric)?;
    let mtime = numeric_field(&block[136..148])?;
    let typeflag = match block[156] {
        // An old (v7-style) NUL typeflag is a regular file.
        0 => b'0',
        flag => flag,
    };
    let link_target = field_bytes(&block[157..257]).to_vec();
    // Past byte 257, so a v7 header has neither; it names its owner by id
    // alone.
    let (uname, gname) = if posix || gnu {
        (
            field_bytes(&block[265..297]).to_vec(),
            field_bytes(&block[297..329]).to_vec(),
        )
    } else {
        (Vec::new(), Vec::new())
    };

    Ok(Entry {
        path,
        link_target,
        typeflag,
        mode: mode & 0o7777,
        uid,
        gid,
        uname,
        gname,
        size,
        mtime,
        // Stated by a pax record only; a ustar header has no field for it.
        checksum_sha1: None,
        acl_access: None,
        acl_default: None,
    })
}

/// Verifies the header checksum: the sum of all header bytes with the
/// checksum field read as spaces. The unsigned sum is authoritative; the
/// signed sum is accepted as a fallback, as GNU tar documents for archives
/// from historical implementations.
fn verify_checksum(block: &[u8; BLOCK as usize]) -> Result<(), HeaderFlaw> {
    let stored = numeric_field(&block[148..156]).map_err(|_| HeaderFlaw::Checksum)?;
    let mut unsigned: i64 = 0;
    let mut signed: i64 = 0;
    for (i, byte) in block.iter().enumerate() {
        let byte = if (148..156).contains(&i) { b' ' } else { *byte };
        unsigned += i64::from(byte);
        signed += i64::from(byte as i8);
    }
    if stored == unsigned || stored == signed {
        Ok(())
    } else {
        Err(HeaderFlaw::Checksum)
    }
}

/// A header text field: the bytes up to the first NUL.
fn field_bytes(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    &field[..end]
}

/// Parses a numeric header field: octal ASCII, or GNU base-256 when the
/// first byte has its high bit set.
fn numeric_field(field: &[u8]) -> Result<i64, HeaderFlaw> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        return base256_field(field);
    }
    let mut value: i64 = 0;
    let mut seen_digit = false;
    for byte in field {
        match byte {
            b'0'..=b'7' => {
                value = value
                    .checked_mul(8)
                    .and_then(|v| v.checked_add(i64::from(byte - b'0')))
                    .ok_or(HeaderFlaw::Numeric)?;
                seen_digit = true;
            }
            b' ' if !seen_digit => continue,
            b' ' | 0 => break,
            _ => return Err(HeaderFlaw::Numeric),
        }
    }
    // An all-blank field decodes as zero, as GNU tar treats it.
    Ok(value)
}

/// Decodes a numeric header field that cannot be negative — a mode, a user id, a
/// group id: the same decoding as [`numeric_field`], refusing a negative value
/// rather than wrapping it into an unrelated one.
///
/// No capability is lost by refusing: an archive that means `0o7777`, or uid
/// 4294967295, spells it in octal or in the positive base-256 form directly.
fn unsigned_field(field: &[u8]) -> Result<u32, HeaderFlaw> {
    u32::try_from(numeric_field(field)?).map_err(|_| HeaderFlaw::Numeric)
}

/// Decodes a GNU base-256 numeric field: big-endian two's complement with
/// the top bit of the first byte as the format flag.
fn base256_field(field: &[u8]) -> Result<i64, HeaderFlaw> {
    // The top bit of the first byte is the format marker; the remaining
    // bits begin the two's-complement value, sign-extended from bit 6.
    let mut value = i64::from(field[0] & 0x7f);
    if field[0] & 0x40 != 0 {
        value -= 0x80;
    }
    for byte in &field[1..] {
        value = value
            .checked_mul(256)
            .and_then(|v| v.checked_add(i64::from(*byte)))
            .ok_or(HeaderFlaw::Numeric)?;
    }
    Ok(value)
}

/// A pax record's decimal number: one or more ASCII digits, and nothing else.
///
/// Rust's integer parsers also accept a leading `+`, which no pax writer emits.
/// The record length is framing, deciding where the next record begins, and a
/// reader more lenient than the format is one that reads an archive
/// differently from the tools that wrote it.
fn pax_decimal<T: std::str::FromStr>(text: &[u8]) -> Option<T> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// Parses a pax header body: a sequence of `"%d key=value\n"` records,
/// where the decimal length counts the whole record. Unknown keys are
/// ignored.
fn parse_pax(data: &[u8]) -> Result<PaxRecords, &'static str> {
    let mut records = PaxRecords::default();
    let mut rest = data;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|b| *b == b' ')
            .ok_or("a pax record has no length delimiter")?;
        let length: usize =
            pax_decimal(&rest[..space]).ok_or("a pax record length is not decimal")?;
        if length <= space + 1 || length > rest.len() {
            return Err("a pax record length is out of bounds");
        }
        let record = &rest[space + 1..length];
        rest = &rest[length..];
        let record = record
            .strip_suffix(b"\n")
            .ok_or("a pax record does not end in a newline")?;
        let eq = record
            .iter()
            .position(|b| *b == b'=')
            .ok_or("a pax record has no '='")?;
        let (key, value) = (&record[..eq], &record[eq + 1..]);
        match key {
            b"path" => records.path = Some(value.to_vec()),
            b"linkpath" => records.link_target = Some(value.to_vec()),
            b"size" => {
                let size: u64 = pax_decimal(value).ok_or("a pax size record is not decimal")?;
                // A size whose block-padded length does not fit in u64
                // cannot describe real entry data; rejecting it here keeps
                // the reader's data and padding arithmetic overflow-free.
                if size.checked_next_multiple_of(BLOCK).is_none() {
                    return Err("a pax size record is implausibly large");
                }
                records.size = Some(size);
            }
            // GNU tar writes these whenever an id will not fit the header's
            // octal field, so an archive of a tree with high ids carries its
            // ownership here and nowhere else. Ignoring them while reporting
            // the header's ids as meaningful yields silently wrong ownership.
            b"uid" | b"gid" => {
                let id: u32 =
                    pax_decimal(value).ok_or("a pax uid or gid record is not a decimal id")?;
                if key == b"uid" {
                    records.uid = Some(id);
                } else {
                    records.gid = Some(id);
                }
            }
            // The names a header's 32-byte fields cannot hold.
            b"uname" => records.uname = Some(value.to_vec()),
            b"gname" => records.gname = Some(value.to_vec()),
            // apk writes one of these for every file and symbolic link of a
            // package. A record naming a digest this reader does not know is
            // not an error: the key is namespaced to a vendor, and a reader
            // that refused an unfamiliar one would refuse an archive apk
            // itself reads.
            b"APK-TOOLS.checksum.SHA1" => {
                let mut digest = [0u8; 20];
                if value.len() != 2 * digest.len() {
                    return Err("an apk file checksum record is not a SHA-1");
                }
                // The length check above is what leaves no remainder to drop.
                let (pairs, _) = value.as_chunks::<2>();
                for (byte, pair) in digest.iter_mut().zip(pairs) {
                    *byte = std::str::from_utf8(pair)
                        .ok()
                        .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                        .ok_or("an apk file checksum record is not hexadecimal")?;
                }
                records.checksum_sha1 = Some(digest);
            }
            b"mtime" => {
                // Pax times may carry fractional seconds; whole seconds are
                // what extraction applies. The fraction floors rather than
                // truncates toward zero, as GNU tar does: `-1.5` is the instant
                // between `-2` and `-1`, so the second containing it is `-2`.
                let (whole, fraction) = match value.iter().position(|byte| *byte == b'.') {
                    Some(dot) => (&value[..dot], &value[dot + 1..]),
                    None => (value, &[][..]),
                };
                let (negative, magnitude) = match whole.strip_prefix(b"-") {
                    Some(magnitude) => (true, magnitude),
                    None => (false, whole),
                };
                if !fraction.iter().all(u8::is_ascii_digit) {
                    return Err("a pax mtime record is not numeric");
                }
                let magnitude: u64 =
                    pax_decimal(magnitude).ok_or("a pax mtime record is not numeric")?;
                let seconds = if negative {
                    0i64.checked_sub_unsigned(magnitude)
                } else {
                    i64::try_from(magnitude).ok()
                }
                .ok_or("a pax mtime record is out of range")?;
                let negative_fraction = negative && fraction.iter().any(|b| *b != b'0');
                let mtime = if negative_fraction {
                    seconds
                        .checked_sub(1)
                        .ok_or("a pax mtime record is out of range")?
                } else {
                    seconds
                };
                records.mtime = Some(mtime);
            }
            // GNU's pax sparse formats describe the holes in these, and the
            // member's data is not the file's contents without them. Only the
            // presence is recorded: the member is refused rather than
            // reassembled, so the map's values are never read.
            _ if key.starts_with(b"GNU.sparse.") => records.gnu_sparse = true,
            // An extended attribute, its name spelled as GNU tar spells it in a
            // keyword. Only the two access control lists are read; every other
            // attribute is one the extractor does not apply.
            _ if key.starts_with(XATTR_KEYWORD) => {
                let name = xattr_name(&key[XATTR_KEYWORD.len()..]);
                if name == b"system.posix_acl_access" {
                    records.acl_access = Some(value.to_vec());
                } else if name == b"system.posix_acl_default" {
                    records.acl_default = Some(value.to_vec());
                }
            }
            _ => {}
        }
    }
    Ok(records)
}

// The writing side of the same format. The reader above and these share the
// block size, the field offsets, and the octal encoding, so they are one
// module: two files describing one header layout drift, and a header this
// crate writes is one this crate reads back in `export_tar`'s round trip.

/// The prefix of the pax keyword that records an extended attribute, the name
/// following it.
pub(crate) const XATTR_KEYWORD: &[u8] = b"SCHILY.xattr.";

/// The pax keyword recording the extended attribute `name`, spelled as GNU tar
/// spells it.
///
/// A pax record's keyword ends at its first `=`, so a name holding one cannot
/// be written as it stands: the record would read back as a shorter name with
/// the rest of the name in its value. GNU tar writes `=` as `%3D` and, so that
/// the escape is unambiguous, `%` as `%25`, and reads both back. Spelling a name
/// the same way means GNU tar and this crate's reader ([`xattr_name`]) restore
/// it exactly.
pub(crate) fn xattr_keyword(name: &[u8]) -> Vec<u8> {
    let mut keyword = XATTR_KEYWORD.to_vec();
    for &byte in name {
        match byte {
            b'%' => keyword.extend_from_slice(b"%25"),
            b'=' => keyword.extend_from_slice(b"%3D"),
            byte => keyword.push(byte),
        }
    }
    keyword
}

/// The attribute name a `SCHILY.xattr.` keyword's remainder spells, its
/// `%3D` and `%25` read back as GNU tar reads them ([`xattr_keyword`]). Any
/// other `%` stands for itself.
fn xattr_name(spelled: &[u8]) -> Vec<u8> {
    let mut name = Vec::with_capacity(spelled.len());
    let mut at = 0;
    while at < spelled.len() {
        match &spelled[at..] {
            [b'%', b'3', b'D', ..] => {
                name.push(b'=');
                at += 3;
            }
            [b'%', b'2', b'5', ..] => {
                name.push(b'%');
                at += 3;
            }
            [byte, ..] => {
                name.push(*byte);
                at += 1;
            }
            [] => break,
        }
    }
    name
}

/// The largest size the ustar octal `size` field holds (`8^11 - 1`); a larger
/// file needs a pax `size` record.
pub(crate) const MAX_USTAR_SIZE: u64 = (1 << 33) - 1;
/// The length of the ustar `name` field. A longer path is split into `prefix`
/// and `name` at a separator, or carried in a pax `path` record when it does not
/// split; a name with no separator in it fits or it does not.
pub(crate) const MAX_USTAR_NAME: usize = 100;
/// The length of the ustar `prefix` field, the other half of that split.
pub(crate) const MAX_USTAR_PREFIX: usize = 155;
/// The modification-time range the ustar octal `mtime` field holds: zero
/// through `8^11 - 1` seconds since the epoch, about the year 2242. A time
/// outside it — a pre-1970 negative time, or one further out than 2242 — is
/// carried in a pax `mtime` record instead, the ustar field holding a clamped
/// placeholder the reader ignores, the way an oversized path or file does.
pub(crate) const MAX_USTAR_MTIME: i64 = (1 << 33) - 1;
/// The largest value the ustar octal `uid`/`gid` field holds (`8^7 - 1`). A
/// larger id is carried in a pax `uid` or `gid` record, the ustar field holding
/// a clamped placeholder the reader ignores, the way an out-of-range time does.
pub(crate) const MAX_USTAR_ID: u32 = (1 << 21) - 1;

/// Writes the zero padding after `size` bytes of data, up to the next block.
pub(crate) fn pad(out: &mut impl Write, size: u64) -> io::Result<()> {
    let rem = (size % BLOCK) as usize;
    if rem != 0 {
        out.write_all(&[0u8; BLOCK as usize][..BLOCK as usize - rem])?;
    }
    Ok(())
}

/// Assembles a 512-byte ustar header block with its checksum.
///
/// The parameters are the header's own fields, in the header's own order, so
/// they are a record rather than a bundle threaded down through call levels:
/// gathering them into a struct would put a copy of the ustar header beside the
/// ustar header. The suppression stays for that reason.
#[expect(clippy::too_many_arguments)]
pub(crate) fn ustar_block(
    name: &[u8],
    prefix: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: i64,
    typeflag: u8,
    linkname: &[u8],
) -> io::Result<[u8; BLOCK as usize]> {
    let mut block = [0u8; BLOCK as usize];
    let name = &name[..name.len().min(MAX_USTAR_NAME)];
    block[0..name.len()].copy_from_slice(name);
    octal(&mut block[100..108], u64::from(mode & 0o7777))?;
    octal(&mut block[108..116], u64::from(uid))?;
    octal(&mut block[116..124], u64::from(gid))?;
    octal(&mut block[124..136], size)?;
    // Clamp into the field's range: a time outside it is carried in a pax
    // `mtime` record, so this placeholder is what the reader ignores. Clamping
    // (rather than failing) keeps one out-of-range stamp from aborting the
    // export.
    octal(&mut block[136..148], mtime.clamp(0, MAX_USTAR_MTIME) as u64)?;
    block[156] = typeflag;
    let linkname = &linkname[..linkname.len().min(MAX_USTAR_NAME)];
    block[157..157 + linkname.len()].copy_from_slice(linkname);
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    octal(&mut block[329..337], 0)?;
    octal(&mut block[337..345], 0)?;
    let prefix = &prefix[..prefix.len().min(MAX_USTAR_PREFIX)];
    block[345..345 + prefix.len()].copy_from_slice(prefix);

    // The checksum: the sum of every byte with the field read as spaces,
    // written as six octal digits, a NUL, and a space. The field is six full
    // octal digits (not the NUL-terminated form `octal` produces), so it is
    // formatted directly.
    for byte in &mut block[148..156] {
        *byte = b' ';
    }
    let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
    let mut v = sum;
    for slot in block[148..154].iter_mut().rev() {
        *slot = b'0' + (v & 0o7) as u8;
        v >>= 3;
    }
    block[154] = 0;
    block[155] = b' ';
    Ok(block)
}

/// Formats `value` right-justified as NUL-terminated octal ASCII into `field`,
/// erroring when it does not fit.
fn octal(field: &mut [u8], value: u64) -> io::Result<()> {
    let digits = field.len() - 1;
    let max = if digits >= 22 {
        u64::MAX
    } else {
        (1u64 << (3 * digits)) - 1
    };
    if value > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a tar header field does not fit an octal value",
        ));
    }
    let mut v = value;
    for slot in field[..digits].iter_mut().rev() {
        *slot = b'0' + (v & 0o7) as u8;
        v >>= 3;
    }
    field[digits] = 0;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octal_rejects_an_overlong_value() {
        let mut field = [0u8; 8];
        assert!(octal(&mut field, u64::from(MAX_USTAR_ID)).is_ok());
        assert!(octal(&mut field, u64::from(MAX_USTAR_ID) + 1).is_err());
    }

    #[test]
    fn octal_fields_decode() {
        assert_eq!(numeric_field(b"0000755\0").unwrap(), 0o755);
        assert_eq!(numeric_field(b"   755 \0").unwrap(), 0o755);
        assert_eq!(numeric_field(b"        ").unwrap(), 0);
        assert_eq!(numeric_field(b"\0\0\0\0").unwrap(), 0);
    }

    #[test]
    fn octal_fields_reject_non_octal() {
        assert!(numeric_field(b"12x4\0").is_err());
        assert!(numeric_field(b"0008\0").is_err());
    }

    #[test]
    fn base256_fields_decode() {
        // 8 GiB + 1, too large for the 12-byte octal size field.
        let mut field = [0u8; 12];
        field[0] = 0x80;
        field[7] = 0x02;
        field[11] = 0x01;
        assert_eq!(numeric_field(&field).unwrap(), (2i64 << 32) + 1);

        // -1 in two's complement.
        let field = [0xffu8; 12];
        assert_eq!(numeric_field(&field).unwrap(), -1);
    }

    #[test]
    fn pax_records_parse() {
        let data = b"28 path=some/long/file/name\n19 size=1234567890\n23 mtime=1720000000.25\n";
        let records = parse_pax(data).unwrap();
        assert_eq!(records.path.as_deref(), Some(&b"some/long/file/name"[..]));
        assert_eq!(records.size, Some(1234567890));
        assert_eq!(records.mtime, Some(1720000000));
    }

    #[test]
    fn an_attribute_name_holding_an_equals_sign_survives_its_keyword() {
        // A keyword ends at the first `=`, so a name holding one is spelled as
        // GNU tar spells it, and read back the same way.
        for name in [&b"user.a=b"[..], b"user.100%", b"user.%3D", b"user.plain"] {
            let keyword = xattr_keyword(name);
            assert!(!keyword.contains(&b'='), "{keyword:?}");
            assert_eq!(xattr_name(&keyword[XATTR_KEYWORD.len()..]), name);
        }
        assert_eq!(xattr_keyword(b"user.a=b%c"), b"SCHILY.xattr.user.a%3Db%25c");
    }

    #[test]
    fn the_access_control_list_records_are_read_and_no_other_attribute() {
        let mut data = Vec::new();
        for (key, value) in [
            (
                &b"SCHILY.xattr.system.posix_acl_access"[..],
                &b"\x02\0\0\0list"[..],
            ),
            (
                b"SCHILY.xattr.system.posix_acl_default",
                b"\x02\0\0\0default",
            ),
            (b"SCHILY.xattr.user.comment", b"ignored"),
        ] {
            let mut record = key.to_vec();
            record.push(b'=');
            record.extend_from_slice(value);
            record.push(b'\n');
            let mut length = record.len() + 3;
            if length.to_string().len() + 1 + record.len() != length {
                length += 1;
            }
            data.extend_from_slice(format!("{length} ").as_bytes());
            data.extend_from_slice(&record);
        }
        let records = parse_pax(&data).unwrap();
        assert_eq!(records.acl_access.as_deref(), Some(&b"\x02\0\0\0list"[..]));
        assert_eq!(
            records.acl_default.as_deref(),
            Some(&b"\x02\0\0\0default"[..])
        );
    }

    #[test]
    fn pax_unknown_keys_are_ignored() {
        // A record length that overruns the data is rejected.
        let data_bad = b"22 uid=1000\n23 gname=abc\n";
        let data_ok = b"12 uid=1000\n15 gname=users\n19 SCHILY.fflags=x\n";
        assert!(parse_pax(data_bad).is_err());
        let records = parse_pax(data_ok).unwrap();
        assert!(records.path.is_none());
        assert!(records.size.is_none());
        assert_eq!(records.uid, Some(1000));
        assert_eq!(records.gname.as_deref(), Some(&b"users"[..]));
    }

    #[test]
    fn an_owner_is_read_by_name_as_well_as_by_id() {
        // The header's own fields, and a pax record past them, the record
        // winning as it does for every attribute it states. A v7 header has no
        // field for a name, so it names no one.
        let mut archive = ferroday_cage_testkit::tar::Tar::new();
        archive.owner_names("root", "messagebus");
        archive.entry("helper", b'0', 0o4750, 0, 101, "", b"x");
        let record = ferroday_cage_testkit::tar::pax_record(
            "gname",
            "a-group-name-longer-than-the-header-field",
        );
        archive.entry("PaxHeaders/next", b'x', 0o644, 0, 0, "", record.as_bytes());
        archive.entry("next", b'0', 0o644, 0, 0, "", b"y");
        let tar = archive.finish();
        let mut reader = TarReader::in_memory(&tar[..]);
        let helper = reader.next_entry().unwrap().expect("an entry");
        assert_eq!(
            (&helper.uname[..], &helper.gname[..], helper.gid),
            (&b"root"[..], &b"messagebus"[..], 101),
        );
        let next = reader.next_entry().unwrap().expect("an entry");
        assert_eq!(next.gname, b"a-group-name-longer-than-the-header-field");
        assert_eq!(next.uname, b"root");

        let mut v7 = ferroday_cage_testkit::tar::Tar::new().v7();
        v7.file("old", 0o644, b"z");
        let tar = v7.finish();
        let old = TarReader::in_memory(&tar[..])
            .next_entry()
            .unwrap()
            .expect("an entry");
        assert!(old.uname.is_empty() && old.gname.is_empty());
    }

    #[test]
    fn a_fractional_pax_mtime_floors() {
        // Whole seconds are what extraction applies, and the fraction floors as
        // GNU tar's does: `-1.5` names an instant inside the second `-2`, not
        // inside `-1`.
        assert_eq!(
            parse_pax(b"23 mtime=1720000000.25\n").unwrap().mtime,
            Some(1_720_000_000)
        );
        assert_eq!(parse_pax(b"14 mtime=-1.5\n").unwrap().mtime, Some(-2));
        // A zero fraction is not a fraction, in either direction.
        assert_eq!(parse_pax(b"14 mtime=-1.0\n").unwrap().mtime, Some(-1));
        assert_eq!(parse_pax(b"12 mtime=-1\n").unwrap().mtime, Some(-1));
    }

    #[test]
    fn a_pax_number_is_digits_and_nothing_else() {
        // An integer parser also takes a leading `+`, which no pax writer
        // emits. The record length decides where the next record begins, so a
        // reader more lenient than the format reads an archive differently
        // from the tools that wrote it.
        assert!(parse_pax(b"+12 uid=1000\n").is_err());
        assert!(parse_pax(b"14 size=+1234\n").is_err());
        assert!(parse_pax(b"13 uid=+1000\n").is_err());
        assert!(parse_pax(b"15 mtime=+1000\n").is_err());
        assert!(parse_pax(b"17 mtime=1000.+5\n").is_err());
        assert!(parse_pax(b"8 size=\n").is_err());
        // The forms the format does have still read.
        assert_eq!(parse_pax(b"13 size=1234\n").unwrap().size, Some(1234));
        assert_eq!(
            parse_pax(b"30 mtime=-9223372036854775808\n").unwrap().mtime,
            Some(i64::MIN)
        );
        assert!(parse_pax(b"29 mtime=9223372036854775808\n").is_err());
    }

    #[test]
    fn pax_ownership_records_are_read() {
        // GNU tar writes these whenever an id will not fit the header's octal
        // field, so an archive of a tree with high ids carries its ownership
        // here and nowhere else.
        let records = parse_pax(b"14 uid=888888\n14 gid=999999\n").unwrap();
        assert_eq!(records.uid, Some(888_888));
        assert_eq!(records.gid, Some(999_999));
        // An id that is not a plain decimal is a malformed archive, not a
        // record to skip: skipping would fall back on the header's octal field,
        // which is exactly the value the record exists to correct.
        assert!(parse_pax(b"13 uid=-1000\n").is_err());
        assert!(parse_pax(b"12 gid=zzzz\n").is_err());
    }

    #[test]
    fn an_apk_file_checksum_record_decodes_to_the_digest_it_states() {
        // apk writes one of these for every file and symbolic link, and the
        // Alpine layer verifies an extracted file against it. A record that
        // decoded to the wrong bytes would fail every file it covers, so the
        // decoding is pinned here rather than only through that layer.
        let hex = b"000102030405060708090a0b0c0d0e0f10111213";
        let mut data = Vec::from(&b"68 APK-TOOLS.checksum.SHA1="[..]);
        data.extend_from_slice(hex);
        data.push(b'\n');
        let records = parse_pax(&data).unwrap();
        assert_eq!(
            records.checksum_sha1,
            Some(std::array::from_fn(|index| index as u8)),
        );

        // A value that is not twenty bytes of hexadecimal is a malformed
        // record, not one to skip: skipping would leave the file unverified
        // while the archive claimed to state a digest for it.
        let mut short = Vec::from(&b"66 APK-TOOLS.checksum.SHA1="[..]);
        short.extend_from_slice(&hex[2..]);
        short.push(b'\n');
        assert!(parse_pax(&short).is_err());

        let mut not_hex = Vec::from(&b"68 APK-TOOLS.checksum.SHA1="[..]);
        not_hex.extend_from_slice(b"g00102030405060708090a0b0c0d0e0f10111213");
        not_hex.push(b'\n');
        assert!(parse_pax(&not_hex).is_err());
    }

    #[test]
    fn a_negative_unsigned_field_is_refused_rather_than_wrapped() {
        // The base-256 form is two's complement. Casting a negative value to
        // `u32` would produce a plausible-looking id — `-1` becomes 4294967295,
        // the kernel's overflow id — and assign ownership from a malformed
        // header without a word.
        let field = [0xffu8; 8];
        assert_eq!(numeric_field(&field).unwrap(), -1);
        assert!(unsigned_field(&field).is_err());
        // The ordinary octal form still decodes.
        assert_eq!(unsigned_field(b"0001750\0").unwrap(), 0o1750);
    }

    #[test]
    fn a_negative_mode_is_refused_alongside_the_ids_it_sits_beside() {
        // The mode takes the same decoding as the ids beside it, so a negative
        // base-256 value is refused there too. Wrapped, `-1 as u32 & 0o7777`
        // would be `0o7777`: every permission bit plus setuid, setgid, and
        // sticky, granted by a header no archive can have meant.
        let mut block = ustar_header(b"file.txt", b"");
        block[100..108].copy_from_slice(&[0xffu8; 8]);
        checksum(&mut block);
        assert_eq!(parse_header(&block).unwrap_err(), HeaderFlaw::Numeric);

        // The same header with an ordinary octal mode parses, so what is refused
        // is the sign and not the field.
        assert_eq!(
            parse_header(&ustar_header(b"file.txt", b"")).unwrap().mode,
            0o644,
        );
    }

    #[test]
    fn pax_sizes_that_cannot_be_block_padded_are_rejected() {
        // The largest acceptable size is the last exact block multiple
        // (u64::MAX - 511); anything above it would overflow the padded
        // length.
        let ok = parse_pax(b"29 size=18446744073709551104\n").unwrap();
        assert_eq!(ok.size, Some(u64::MAX - 511));
        assert!(parse_pax(b"29 size=18446744073709551615\n").is_err());
    }

    #[test]
    fn pax_bad_lengths_are_rejected() {
        assert!(parse_pax(b"999 path=x\n").is_err());
        assert!(parse_pax(b"3 path=x\n").is_err());
        assert!(parse_pax(b"path=x\n").is_err());
    }

    /// Writes the header checksum over `block`, in the six-octal-digits, NUL,
    /// space form tar writes.
    fn checksum(block: &mut [u8; BLOCK as usize]) {
        block[148..156].copy_from_slice(b"        ");
        let sum: u32 = block.iter().map(|byte| u32::from(*byte)).sum();
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }

    /// A minimal POSIX `ustar` header block for a regular file, with `name` in
    /// the 100-byte name field and `prefix` in the 155-byte prefix field.
    fn ustar_header(name: &[u8], prefix: &[u8]) -> [u8; BLOCK as usize] {
        let mut block = [0u8; BLOCK as usize];
        block[..name.len()].copy_from_slice(name);
        block[100..108].copy_from_slice(b"0000644\0");
        block[108..116].copy_from_slice(b"0000000\0");
        block[116..124].copy_from_slice(b"0000000\0");
        block[124..136].copy_from_slice(b"00000000000\0");
        block[136..148].copy_from_slice(b"00000000000\0");
        block[156] = b'0';
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        block[345..345 + prefix.len()].copy_from_slice(prefix);
        checksum(&mut block);
        block
    }

    /// A ustar header block for a file of `size` bytes with `typeflag`, with
    /// `name` in the 100-byte name field.
    fn sized_header(name: &[u8], size: u64, typeflag: u8) -> [u8; BLOCK as usize] {
        let mut block = ustar_header(&name[..name.len().min(MAX_USTAR_NAME)], b"");
        block[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        block[156] = typeflag;
        checksum(&mut block);
        block
    }

    #[test]
    fn a_long_name_truncated_after_a_separator_is_still_the_file_it_is() {
        // The defect a real Gentoo stage3 found. A GNU long name puts the real
        // path in an `L` entry, and what the file's own header carries is the
        // first hundred bytes of it. When that truncation happens to land just
        // after a separator, a rule reading the header's name would take a
        // regular file for a directory -- and a directory carries no data, so
        // the file's bytes would be read as the next header and the rest of the
        // archive lost with them.
        //
        // A hundred bytes of directory, then the file: the name field holds
        // exactly the directory part, trailing separator and all.
        let long_name = format!("./{}/deep.hpp", "d".repeat(97));
        assert_eq!(long_name.as_bytes()[MAX_USTAR_NAME - 1], b'/');
        let body = b"the contents of a file that is not a directory\n";

        let mut archive = Vec::new();
        // The `L` entry naming it, its data NUL-terminated as GNU writes it.
        archive.extend_from_slice(&sized_header(
            b"././@LongLink",
            long_name.len() as u64 + 1,
            b'L',
        ));
        archive.extend_from_slice(long_name.as_bytes());
        archive.push(0);
        pad(&mut archive, long_name.len() as u64 + 1).unwrap();
        // The file itself, its own name field truncated to the directory part.
        archive.extend_from_slice(&sized_header(long_name.as_bytes(), body.len() as u64, b'0'));
        archive.extend_from_slice(body);
        pad(&mut archive, body.len() as u64).unwrap();
        // A second entry, which is only reachable if the first was skipped by
        // the right number of bytes.
        archive.extend_from_slice(&sized_header(b"after.txt", 0, b'0'));
        archive.extend_from_slice(&[0u8; 2 * BLOCK as usize]);

        let mut reader = TarReader::in_memory(&archive[..]);
        let entry = reader.next_entry().unwrap().expect("the long-named entry");
        assert_eq!(entry.path, long_name.as_bytes());
        assert_eq!(entry.typeflag, b'0', "a regular file, not a directory");
        assert_eq!(entry.size, body.len() as u64);
        let mut read = vec![0u8; body.len()];
        let mut filled = 0;
        while filled < read.len() {
            let got = reader.read_data(&mut read[filled..]).unwrap();
            assert_ne!(got, 0, "the data is the file's own");
            filled += got;
        }
        assert_eq!(read, body);

        let next = reader.next_entry().unwrap().expect("the entry after it");
        assert_eq!(next.path, &b"after.txt"[..]);
        assert!(reader.next_entry().unwrap().is_none(), "the archive ends");
    }

    #[test]
    fn an_entry_that_names_a_directory_and_declares_data_is_refused() {
        // The other side of the rule above. An entry whose resolved name ends
        // in a separator is a directory, and a directory carries no data, so
        // one that declares some says two incompatible things about itself. No
        // real writer emits that shape; a reader that resolved the
        // contradiction rather than refusing it would be picking one of two
        // archives, which is what a parser differential is made of.
        let mut archive = Vec::new();
        archive.extend_from_slice(&sized_header(b"dir/", 512, b'0'));
        archive.extend_from_slice(&[b'x'; 512]);
        archive.extend_from_slice(&sized_header(b"after.txt", 0, b'0'));
        archive.extend_from_slice(&[0u8; 2 * BLOCK as usize]);

        let mut reader = TarReader::in_memory(&archive[..]);
        let err = reader
            .next_entry()
            .expect_err("the entry contradicts itself");
        assert!(
            err.to_string()
                .contains("names a directory and declares data"),
            "{err}",
        );

        // A directory entry declaring nothing is the ordinary old-style shape
        // and is read as the directory it names.
        let mut plain = Vec::new();
        plain.extend_from_slice(&sized_header(b"dir/", 0, b'0'));
        plain.extend_from_slice(&[0u8; 2 * BLOCK as usize]);
        let entry = TarReader::in_memory(&plain[..])
            .next_entry()
            .unwrap()
            .expect("the directory entry");
        assert_eq!(entry.typeflag, b'5');
    }

    #[test]
    fn a_posix_prefix_joins_onto_the_name() {
        // A ustar path too long for the 100-byte name field splits across the
        // prefix and name fields, rejoined with a separator.
        let entry = parse_header(&ustar_header(b"file.txt", b"a/very/long/directory")).unwrap();
        assert_eq!(entry.path, &b"a/very/long/directory/file.txt"[..]);
    }

    #[test]
    fn an_empty_posix_prefix_leaves_the_name_alone() {
        // No separator is prepended: the prefix field is unset, not empty.
        let entry = parse_header(&ustar_header(b"file.txt", b"")).unwrap();
        assert_eq!(entry.path, &b"file.txt"[..]);
    }

    #[test]
    fn a_gnu_header_never_joins_its_prefix_bytes() {
        // GNU reuses the bytes POSIX gives the prefix for other fields, so
        // whatever they hold must not reach the path.
        let mut block = ustar_header(b"file.txt", b"not-a-prefix");
        block[257..263].copy_from_slice(b"ustar ");
        block[263..265].copy_from_slice(b" \0");
        checksum(&mut block);
        let entry = parse_header(&block).unwrap();
        assert_eq!(entry.path, &b"file.txt"[..]);
    }

    /// A v7 header block: the ustar one with everything past byte 257 cleared,
    /// which is exactly what the format is.
    fn v7_header(name: &[u8]) -> [u8; BLOCK as usize] {
        let mut block = ustar_header(name, b"");
        block[257..].fill(0);
        checksum(&mut block);
        block
    }

    #[test]
    fn a_v7_header_parses_without_magic() {
        let entry = parse_header(&v7_header(b"file.txt")).unwrap();
        assert_eq!(entry.path, &b"file.txt"[..]);
        assert_eq!(entry.typeflag, b'0');
        assert_eq!(entry.mode, 0o644);
    }

    #[test]
    fn a_v7_header_never_reads_a_prefix() {
        // The bytes a ustar header gives the prefix are not a field in v7 at
        // all. Whatever an old writer left in them stays out of the path.
        let mut block = v7_header(b"file.txt");
        block[345..357].copy_from_slice(b"not-a-prefix");
        checksum(&mut block);
        let entry = parse_header(&block).unwrap();
        assert_eq!(entry.path, &b"file.txt"[..]);
    }

    /// A pax metadata entry — `x` per-entry or `g` global — carrying `records`,
    /// followed by the blocks its data occupies.
    fn pax_block(typeflag: u8, records: &[u8]) -> Vec<u8> {
        let mut out = sized_header(b"PaxHeaders/entry", records.len() as u64, typeflag).to_vec();
        let mut data = records.to_vec();
        data.resize(data.len().next_multiple_of(BLOCK as usize), 0);
        out.extend_from_slice(&data);
        out
    }

    /// A source that fails every read with `err`.
    struct Failing(fn() -> std::io::Error);

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err((self.0)())
        }
    }

    #[test]
    fn a_reader_that_fails_is_not_a_file_of_another_format() {
        // The reader under the parser is a decompressor, and its refusals carry
        // reasons -- a dictionary over the bound, a frame it will not decode.
        // Reported as "not a tar archive" those reasons are gone, replaced by a
        // guess about the format, and the guard that produced them exists for
        // nothing.
        let mut reader = TarReader::new(
            Failing(|| {
                Refusal::mark(
                    "the xz stream does not decode",
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "the dictionary is larger than the bound",
                    ),
                )
            }),
            "/srv/rootfs.tar.xz",
        );
        let err = reader.next_entry().expect_err("the decoder refuses");
        assert!(
            matches!(
                &err,
                ProvisionError::Archive {
                    source: Some(_),
                    ..
                }
            ),
            "{err:?}",
        );
        assert_eq!(
            crate::ErrorChain::new(&err).to_string(),
            "malformed archive at offset 0: the xz stream does not decode: the dictionary is \
             larger than the bound",
        );
        assert!(
            !reader.not_a_tar(),
            "a reader that failed said nothing about the format",
        );

        // What the classification is for: bytes that arrived and are not a tar
        // header, however few of them there were.
        let mut reader = TarReader::in_memory(&b"not a tar archive at all"[..]);
        assert!(reader.next_entry().is_err());
        assert!(reader.not_a_tar());
        let mut reader = TarReader::in_memory(&[b'X'; BLOCK as usize][..]);
        assert!(reader.next_entry().is_err());
        assert!(reader.not_a_tar());
    }

    #[test]
    fn a_source_that_fails_is_the_hosts_failure_naming_the_archive() {
        // A read the source itself failed, a file's error or a stream's reset,
        // is no refusal of the archive: a caller that retries a transport
        // failure has to be able to see one. It names the archive, and the
        // OS's failure is its cause, whether it comes at the first block or
        // part way through an entry.
        let reset = || std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let mut reader = TarReader::new(Failing(reset), "/srv/rootfs.tar");
        let err = reader.next_entry().expect_err("the source fails");
        assert!(!reader.not_a_tar());

        let archive = one_file(3000, &[b'x'; 3000]);
        let mut reader =
            TarReader::new((&archive[..1024]).chain(Failing(reset)), "/srv/rootfs.tar");
        reader
            .next_entry()
            .unwrap()
            .expect("the first header reads");
        let later = reader
            .read_entry(1 << 20)
            .expect_err("the source fails inside the entry");

        for err in [err, later] {
            match &err {
                ProvisionError::Io { path, source, .. } => {
                    assert_eq!(path, Path::new("/srv/rootfs.tar"));
                    assert_eq!(source.kind(), std::io::ErrorKind::ConnectionReset);
                }
                other => panic!("expected the host's failure, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_failure_carried_through_a_read_returns_as_it_was() {
        // A member of one archive read as the source of another: the outer
        // reader's refusal is the outer archive's, and a reader above reports it
        // as such rather than as a source of its own that failed.
        let outer = || {
            into_io(ProvisionError::Archive {
                offset: 9216,
                reason: "the archive ends inside an entry's data".to_string(),
                source: None,
            })
        };
        let err = TarReader::new(Failing(outer), "/srv/package.gpkg.tar")
            .next_entry()
            .expect_err("the outer archive fails");
        assert!(
            matches!(err, ProvisionError::Archive { offset: 9216, .. }),
            "{err:?}",
        );
    }

    #[test]
    fn a_first_header_refused_for_what_it_says_is_not_a_file_of_another_format() {
        // The magic says these bytes were meant to be a tar header, so a
        // checksum that does not match is a corrupt archive, with that reason,
        // however early in the stream it came.
        let mut corrupt = ustar_header(b"file.txt", b"").to_vec();
        corrupt[0] = b'X';
        corrupt.extend_from_slice(&[0u8; 2 * BLOCK as usize]);
        let mut reader = TarReader::in_memory(&corrupt[..]);
        let err = reader
            .next_entry()
            .expect_err("the checksum does not match");
        assert!(err.to_string().contains("checksum"), "{err}");
        assert!(
            !reader.not_a_tar(),
            "a corrupt header is still a tar header"
        );

        // A first header that parses, for an entry the reader refuses, is a
        // malformed archive too: the whole stream past it has not been read,
        // and nothing about it says it is some other format.
        let mut contradictory = sized_header(b"dir/", 512, b'0').to_vec();
        contradictory.extend_from_slice(&[b'x'; BLOCK as usize]);
        contradictory.extend_from_slice(&[0u8; 2 * BLOCK as usize]);
        let mut reader = TarReader::in_memory(&contradictory[..]);
        reader
            .next_entry()
            .expect_err("the entry contradicts itself");
        assert!(!reader.not_a_tar());
    }

    #[test]
    fn a_global_header_states_nothing_about_a_later_entry() {
        // A `g` header applies to every entry after it, and every keyword this
        // reader understands is a per-file one. Taking a `size` from one splits
        // a member in two: the bytes past the declared size are read as the
        // next header, so this reader's member set differs from that of every
        // reader that ignores it -- a tar parser differential of exactly the
        // kind the rest of this module refuses. A `path` from one renames every
        // member of the archive at once.
        let payload = b"0123456789abcdef";
        let mut archive = pax_block(b'g', b"9 size=0\n16 path=renamed\n");
        archive.extend_from_slice(&sized_header(b"real.txt", payload.len() as u64, b'0'));
        let mut data = [0u8; BLOCK as usize];
        data[..payload.len()].copy_from_slice(payload);
        archive.extend_from_slice(&data);
        archive.extend_from_slice(&[0u8; 2 * BLOCK as usize]);

        let mut reader = TarReader::in_memory(&archive[..]);
        let entry = reader.next_entry().unwrap().expect("the file entry");
        assert_eq!(
            entry.path,
            &b"real.txt"[..],
            "the global path is not the entry's",
        );
        assert_eq!(
            entry.size,
            payload.len() as u64,
            "the global size is not the entry's",
        );
        let mut body = vec![0u8; payload.len()];
        let got = reader.read_data(&mut body).expect("the body reads");
        assert_eq!(&body[..got], payload);
        assert!(
            reader.next_entry().unwrap().is_none(),
            "the archive holds one member, not two",
        );
    }

    #[test]
    fn a_v7_name_ending_in_a_separator_is_a_directory() {
        // The convention the oldest writers used in place of a typeflag. GNU
        // tar's own `--format=v7` output sets `5` as well, so this is the
        // belt to that archive's braces.
        //
        // Read by the reader rather than by the header parse, which knows only
        // the header's own name field: for an entry whose real path arrived in
        // a long-name or pax record, that field is a truncation, and a rule
        // applied to it would take a truncated regular file for a directory.
        let mut archive = v7_header(b"olddir/").to_vec();
        archive.extend_from_slice(&[0u8; 2 * BLOCK as usize]);
        let mut reader = TarReader::in_memory(&archive[..]);
        let entry = reader.next_entry().unwrap().expect("the directory");
        assert_eq!(entry.typeflag, b'5');
    }

    #[test]
    fn a_block_with_neither_magic_nor_a_valid_checksum_is_not_a_tar_header() {
        // With v7 accepted the checksum is the only thing separating a header
        // from arbitrary bytes, and the diagnostic has to stay useful to
        // whoever pointed the parser at the wrong file.
        let mut block = v7_header(b"file.txt");
        block[0] = b'X'; // after the checksum was written, so it no longer matches
        assert_eq!(parse_header(&block).unwrap_err(), HeaderFlaw::NotATarHeader);
    }

    #[test]
    fn a_corrupt_ustar_header_reads_as_corrupt_rather_than_as_not_a_tar() {
        // Magic present says this was meant to be a tar header, so the report
        // is about the header rather than about the file.
        let mut block = ustar_header(b"file.txt", b"");
        block[0] = b'X';
        assert_eq!(parse_header(&block).unwrap_err(), HeaderFlaw::Checksum);
    }

    #[test]
    fn a_stream_that_ends_before_its_first_header_holds_no_archive() {
        // The missing-terminator tolerance below presupposes an archive. A
        // stream that ended before its first header is a file of some other
        // format or an empty one, and answering `None` here would report a
        // complete archive of nothing -- which a publication then publishes as
        // a finished, empty rootfs that every later run trusts without
        // reconsulting the source.
        let mut reader = TarReader::in_memory(&b""[..]);
        let err = reader
            .next_entry()
            .expect_err("an empty stream is no archive");
        assert!(
            reader.not_a_tar(),
            "{err}, expected a format classification",
        );
    }

    #[test]
    fn a_terminated_empty_archive_holds_no_entries_and_is_not_an_error() {
        // Two zero blocks are what `tar cf empty.tar --files-from /dev/null`
        // writes, and it is a valid archive of nothing -- the case the rejection
        // above must not take with it.
        let archive = [0u8; 2 * BLOCK as usize];
        let mut reader = TarReader::in_memory(&archive[..]);
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn an_archive_missing_only_its_terminator_still_reads() {
        // GNU tar tolerates a truncated two-block terminator and so does this
        // reader, once at least one header has been consumed.
        let archive = v7_header(b"file.txt").to_vec();
        let mut reader = TarReader::in_memory(&archive[..]);
        let entry = reader.next_entry().unwrap().expect("the file");
        assert_eq!(entry.path, b"file.txt");
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn metadata_with_no_entry_after_it_is_refused_with_or_without_a_terminator() {
        // A pax header or a GNU long name describes the entry after it. One the
        // archive ends after describes nothing, and whether the end is spelled
        // with the two zero blocks or by the stream running out, it is one
        // archive refused one way.
        let mut long_name = sized_header(b"././@LongLink", 4, b'L').to_vec();
        long_name.extend_from_slice(b"name");
        long_name.resize(long_name.len().next_multiple_of(BLOCK as usize), 0);
        for (kind, metadata) in [
            ("a pax header", pax_block(b'x', b"16 path=renamed\n")),
            ("a long name", long_name),
        ] {
            for terminated in [false, true] {
                let mut archive = metadata.clone();
                if terminated {
                    archive.extend_from_slice(&[0u8; 2 * BLOCK as usize]);
                }
                let err = TarReader::in_memory(&archive[..])
                    .next_entry()
                    .expect_err("metadata describing nothing is refused");
                assert!(
                    err.to_string().contains("ends after a metadata entry"),
                    "{kind}, terminated {terminated}: {err}",
                );
            }
        }
    }

    /// An archive of one regular file holding `body`, with a header declaring
    /// `declared` bytes for it.
    fn one_file(declared: u64, body: &[u8]) -> Vec<u8> {
        let mut archive = sized_header(b"entry", declared, b'0').to_vec();
        archive.extend_from_slice(body);
        archive.resize(archive.len().next_multiple_of(BLOCK as usize), 0);
        archive.extend_from_slice(&[0u8; 2 * BLOCK as usize]);
        archive
    }

    #[test]
    fn an_entry_is_read_whole_up_to_its_ceiling_and_refused_past_it() {
        let body = vec![b'x'; 3000];

        // At the ceiling exactly, the entry is the whole of it, and the reader
        // goes on to the next entry from where it ends.
        let archive = one_file(body.len() as u64, &body);
        let mut reader = TarReader::in_memory(&archive[..]);
        reader.next_entry().unwrap().expect("the file");
        assert_eq!(reader.read_entry(body.len() as u64).unwrap(), body);
        assert!(reader.next_entry().unwrap().is_none());

        // One byte under it, the entry is refused on its declared length rather
        // than read as far as the ceiling and handed back cut short.
        let mut reader = TarReader::in_memory(&archive[..]);
        reader.next_entry().unwrap().expect("the file");
        let err = reader
            .read_entry(body.len() as u64 - 1)
            .expect_err("an entry past its ceiling is refused");
        assert!(
            err.to_string()
                .contains("of 3000 bytes is more than the 2999"),
            "{err}",
        );
    }

    #[test]
    fn an_entry_declaring_more_than_the_archive_holds_is_not_returned_short() {
        // The declared length is inside the ceiling, so it is believed until the
        // bytes run out, and then the read fails: what comes back is a whole
        // entry or nothing.
        let mut archive = sized_header(b"entry", 1 << 20, b'0').to_vec();
        archive.extend_from_slice(&[b'x'; 700]);
        let mut reader = TarReader::in_memory(&archive[..]);
        reader.next_entry().unwrap().expect("the file");
        let err = reader
            .read_entry(1 << 30)
            .expect_err("an entry the archive does not hold is refused");
        assert!(
            err.to_string().contains("ends inside an entry's data"),
            "{err}",
        );
    }

    /// A reader that answers every other read with `EINTR`, as a pipe or a
    /// socket does in a process whose signal handlers do not restart the call.
    struct Interrupting<R> {
        inner: R,
        interrupt: bool,
    }

    impl<R: Read> Read for Interrupting<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            // A short read as well, so a fill has to come back for the rest.
            let short = buf.len().min(100);
            self.inner.read(&mut buf[..short])
        }
    }

    #[test]
    fn an_interrupted_read_is_retried_rather_than_reported() {
        // The entry's data is read once and drained once, and the headers on
        // either side are read too: every read the reader makes meets the
        // interruption.
        let body = vec![b'x'; 3000];
        let mut archive = one_file(body.len() as u64, &body);
        let terminator = archive.split_off(archive.len() - 2 * BLOCK as usize);
        let second = sized_header(b"second", 600, b'0');
        archive.extend_from_slice(&second);
        archive.extend_from_slice(&[b'y'; 600]);
        archive.resize(archive.len().next_multiple_of(BLOCK as usize), 0);
        archive.extend_from_slice(&terminator);

        let mut reader = TarReader::new(
            Interrupting {
                inner: &archive[..],
                interrupt: false,
            },
            "archive.tar",
        );
        reader.next_entry().unwrap().expect("the first file");
        let mut read = Vec::new();
        let mut chunk = [0u8; 1000];
        loop {
            let got = reader
                .read_data(&mut chunk)
                .expect("an interruption is retried");
            if got == 0 {
                break;
            }
            read.extend_from_slice(&chunk[..got]);
        }
        assert_eq!(read, body);
        let second = reader.next_entry().unwrap().expect("the second file");
        assert_eq!(second.path, b"second");
        // The second entry's data is left unread, so the reader drains it.
        assert!(
            reader
                .next_entry()
                .expect("the drain retries too")
                .is_none()
        );
    }

    #[test]
    fn a_metadata_entry_is_held_to_its_ceiling() {
        // A GNU long name past the metadata ceiling is refused, through the same
        // read every whole-entry reader in the crate goes through.
        let mut archive = sized_header(b"././@LongLink", METADATA_LIMIT + 1, b'L').to_vec();
        archive.extend_from_slice(&[0u8; BLOCK as usize]);
        let err = TarReader::in_memory(&archive[..])
            .next_entry()
            .expect_err("a long name past the ceiling is refused");
        assert!(err.to_string().contains("more than the"), "{err}");
    }
}
