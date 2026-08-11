//! A read-only tar parser for POSIX ustar, GNU, pax, and pre-POSIX v7
//! archives.
//!
//! The parser yields entry metadata and streams entry data; it interprets
//! GNU long-name (`L`)/long-link (`K`) entries and pax extended headers
//! (`x` per-entry, `g` global) internally, so a consumer only ever sees
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

use std::io::{self, Read, Write};

use super::ProvisionError;

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
    checksum_sha1: Option<[u8; 20]>,
}

impl PaxRecords {
    /// Overlays `other` on top of `self`, `other` winning where both are
    /// set (per-entry records override globals).
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
            checksum_sha1: other.checksum_sha1.or(self.checksum_sha1),
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
pub(crate) struct TarReader<R: Read> {
    inner: R,
    /// Bytes consumed from the (uncompressed) stream, for error offsets.
    offset: u64,
    /// Unread data bytes of the current entry.
    data_remaining: u64,
    /// Block-padding bytes following the current entry's data.
    padding: u64,
    /// Global pax records (`g` headers), applying to all later entries.
    globals: PaxRecords,
    /// Set once the archive terminator or EOF was seen.
    finished: bool,
}

impl<R: Read> TarReader<R> {
    pub fn new(inner: R) -> Self {
        TarReader {
            inner,
            offset: 0,
            data_remaining: 0,
            padding: 0,
            globals: PaxRecords::default(),
            finished: false,
        }
    }

    /// Whether parsing failed on the very first block.
    ///
    /// Meaningful only after [`next_entry`](Self::next_entry) returned an
    /// error; used to report "not a tar archive" rather than "corrupt
    /// archive".
    pub fn rejected_at_start(&self) -> bool {
        self.offset <= BLOCK
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
                // EOF at a header boundary. GNU tar tolerates a missing
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
                self.finished = true;
                return Ok(None);
            }

            let mut entry =
                parse_header(&block).map_err(|flaw| malformed(header_offset, flaw.describe()))?;
            self.set_current(&entry);

            match entry.typeflag {
                // GNU long name / long link: the data names the next entry.
                b'L' => {
                    gnu_longname = Some(self.read_metadata(header_offset)?);
                    trim_trailing_nuls(gnu_longname.as_mut().expect("just set"));
                }
                b'K' => {
                    gnu_longlink = Some(self.read_metadata(header_offset)?);
                    trim_trailing_nuls(gnu_longlink.as_mut().expect("just set"));
                }
                // Pax extended headers.
                b'x' => {
                    let data = self.read_metadata(header_offset)?;
                    let records =
                        parse_pax(&data).map_err(|reason| malformed(header_offset, reason))?;
                    pax_entry = Some(match pax_entry {
                        Some(prior) => prior.overlaid(&records),
                        None => records,
                    });
                }
                b'g' => {
                    let data = self.read_metadata(header_offset)?;
                    let records =
                        parse_pax(&data).map_err(|reason| malformed(header_offset, reason))?;
                    self.globals = self.globals.overlaid(&records);
                }
                _ => {
                    // A concrete file entry: fold in the accumulated
                    // metadata, per-entry pax beating GNU long names.
                    let pax = match pax_entry {
                        Some(records) => self.globals.overlaid(&records),
                        None => self.globals.clone(),
                    };
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
                        self.set_current(&entry);
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
                    entry.checksum_sha1 = pax.checksum_sha1;
                    return Ok(Some(entry));
                }
            }
        }
    }

    /// Reads from the current entry's data, returning `Ok(0)` when the
    /// data is exhausted.
    pub fn read_data(&mut self, buf: &mut [u8]) -> Result<usize, ProvisionError> {
        if self.data_remaining == 0 {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.data_remaining).unwrap_or(usize::MAX));
        let got = self
            .inner
            .read(&mut buf[..want])
            .map_err(|err| malformed(self.offset, &format!("cannot read entry data: {err}")))?;
        if got == 0 {
            return Err(malformed(
                self.offset,
                "the archive ends inside an entry's data",
            ));
        }
        self.offset += got as u64;
        self.data_remaining -= got as u64;
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
    fn drain_current(&mut self) -> Result<(), ProvisionError> {
        let mut skip = self.data_remaining + self.padding;
        self.data_remaining = 0;
        self.padding = 0;
        let mut scratch = [0u8; 4096];
        while skip > 0 {
            let want = scratch
                .len()
                .min(usize::try_from(skip).unwrap_or(usize::MAX));
            let got = self.inner.read(&mut scratch[..want]).map_err(|err| {
                malformed(self.offset, &format!("cannot read the archive: {err}"))
            })?;
            if got == 0 {
                return Err(malformed(self.offset, "the archive ends inside an entry"));
            }
            self.offset += got as u64;
            skip -= got as u64;
        }
        Ok(())
    }

    /// Reads one full block. Returns `false` on clean EOF at the block
    /// boundary; a partial block is an error.
    fn read_block(&mut self, block: &mut [u8; BLOCK as usize]) -> Result<bool, ProvisionError> {
        let mut filled = 0;
        while filled < block.len() {
            let got = self.inner.read(&mut block[filled..]).map_err(|err| {
                malformed(self.offset, &format!("cannot read the archive: {err}"))
            })?;
            if got == 0 {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(malformed(
                    self.offset,
                    "the archive ends inside a header block",
                ));
            }
            filled += got;
            self.offset += got as u64;
        }
        Ok(true)
    }

    /// Reads the current (metadata) entry's data in full, with a sanity
    /// cap, and drains its padding.
    fn read_metadata(&mut self, header_offset: u64) -> Result<Vec<u8>, ProvisionError> {
        if self.data_remaining > METADATA_LIMIT {
            return Err(malformed(
                header_offset,
                "a metadata entry is implausibly large",
            ));
        }
        let mut data = Vec::with_capacity(usize::try_from(self.data_remaining).expect("capped"));
        let mut chunk = [0u8; 4096];
        loop {
            let got = self.read_data(&mut chunk)?;
            if got == 0 {
                break;
            }
            data.extend_from_slice(&chunk[..got]);
        }
        self.drain_current()?;
        Ok(data)
    }
}

/// Builds [`ProvisionError::Archive`].
fn malformed(offset: u64, reason: &str) -> ProvisionError {
    ProvisionError::Archive {
        offset,
        reason: reason.to_string(),
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
    let mut typeflag = match block[156] {
        // An old (v7-style) NUL typeflag is a regular file.
        0 => b'0',
        flag => flag,
    };
    // A trailing slash marks a directory, whatever the typeflag says. The
    // oldest archives predate a reliably-set typeflag and mark a directory this
    // way and no other; both GNU tar's own `--format=v7` output and the archive
    // that prompted this do set `5`, so it may never fire. It is safe to apply
    // to every format, a regular file having no business with a name that ends
    // in a separator.
    if typeflag == b'0' && path.last() == Some(&b'/') {
        typeflag = b'5';
    }
    let link_target = field_bytes(&block[157..257]).to_vec();

    Ok(Entry {
        path,
        link_target,
        typeflag,
        mode: mode & 0o7777,
        uid,
        gid,
        size,
        mtime,
        // Stated by a pax record only; a ustar header has no field for it.
        checksum_sha1: None,
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
        let length: usize = std::str::from_utf8(&rest[..space])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or("a pax record length is not decimal")?;
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
                let size: u64 = std::str::from_utf8(value)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or("a pax size record is not decimal")?;
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
                let id: u32 = std::str::from_utf8(value)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or("a pax uid or gid record is not a decimal id")?;
                if key == b"uid" {
                    records.uid = Some(id);
                } else {
                    records.gid = Some(id);
                }
            }
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
                for (byte, pair) in digest.iter_mut().zip(value.chunks_exact(2)) {
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
                let text =
                    std::str::from_utf8(value).map_err(|_| "a pax mtime record is not ASCII")?;
                let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
                let seconds: i64 = whole
                    .parse()
                    .map_err(|_| "a pax mtime record is not numeric")?;
                let negative_fraction =
                    whole.starts_with('-') && fraction.bytes().any(|b| b != b'0');
                let mtime = if negative_fraction {
                    seconds
                        .checked_sub(1)
                        .ok_or("a pax mtime record is out of range")?
                } else {
                    seconds
                };
                records.mtime = Some(mtime);
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
/// The largest value the ustar octal `uid`/`gid` field holds (`8^7 - 1`).
const MAX_ID: u64 = (1 << 21) - 1;

/// Writes the zero padding after `size` bytes of data, up to the next block.
pub(crate) fn pad(out: &mut impl Write, size: u64) -> io::Result<()> {
    let rem = (size % BLOCK) as usize;
    if rem != 0 {
        out.write_all(&[0u8; BLOCK as usize][..BLOCK as usize - rem])?;
    }
    Ok(())
}

/// Assembles a 512-byte ustar header block with its checksum.
#[allow(clippy::too_many_arguments)]
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
    octal_id(&mut block[108..116], u64::from(uid))?;
    octal_id(&mut block[116..124], u64::from(gid))?;
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

/// Formats a uid or gid, erroring past the ustar octal field's reach. The
/// exported ids are in-map system ids, well under the limit; a larger id was
/// never established at provision time (see the module docs of
/// [`bootstrap::configure`](crate::provision) on the ownership boundary).
fn octal_id(field: &mut [u8], value: u64) -> io::Result<()> {
    if value > MAX_ID {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "an owner id is too large for the tar header",
        ));
    }
    octal(field, value)
}

#[cfg(test)]
mod tests {

    #[test]
    fn octal_rejects_an_overlong_value() {
        let mut field = [0u8; 8];
        assert!(octal(&mut field, MAX_ID).is_ok());
        assert!(octal(&mut field, MAX_ID + 1).is_err());
    }
    use super::*;

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
    fn pax_unknown_keys_are_ignored() {
        // A record length that overruns the data is rejected.
        let data_bad = b"22 uid=1000\n23 gname=abc\n";
        let data_ok = b"12 uid=1000\n15 gname=users\n";
        assert!(parse_pax(data_bad).is_err());
        let records = parse_pax(data_ok).unwrap();
        assert!(records.path.is_none());
        assert!(records.size.is_none());
        // `gname` is not ownership the extractor can act on; `uid` is.
        assert_eq!(records.uid, Some(1000));
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

    #[test]
    fn a_v7_name_ending_in_a_separator_is_a_directory() {
        // The convention the oldest writers used in place of a typeflag. GNU
        // tar's own `--format=v7` output sets `5` as well, so this is the
        // belt to that archive's braces.
        let entry = parse_header(&v7_header(b"olddir/")).unwrap();
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
}
