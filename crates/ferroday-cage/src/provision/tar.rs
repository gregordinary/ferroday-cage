//! A read-only tar parser for the formats rootfs tarballs use: POSIX ustar,
//! GNU, and pax.
//!
//! The parser yields entry metadata and streams entry data; it interprets
//! GNU long-name (`L`)/long-link (`K`) entries and pax extended headers
//! (`x` per-entry, `g` global) internally, so a consumer only ever sees
//! concrete file entries with their effective path, link target, size, and
//! times. Header checksums are verified. Writing is out of scope.

use std::io::Read;

use super::ProvisionError;

/// The size of a tar block, and of a tar header.
const BLOCK: u64 = 512;

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
        }
    }
}

/// Reasons a header block is rejected.
#[derive(Debug, PartialEq, Eq)]
enum HeaderFlaw {
    Magic,
    Checksum,
    Numeric,
}

impl HeaderFlaw {
    fn describe(&self) -> &'static str {
        match self {
            HeaderFlaw::Magic => "the header magic is neither ustar nor GNU",
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
    // Magic: POSIX writes "ustar\0" + version "00"; GNU writes
    // "ustar " + " \0". Anything else — including pre-POSIX v7 archives,
    // which have no magic — is rejected.
    let posix = &block[257..263] == b"ustar\0";
    let gnu = &block[257..263] == b"ustar ";
    if !posix && !gnu {
        return Err(HeaderFlaw::Magic);
    }

    verify_checksum(block)?;

    let mut path = field_bytes(&block[0..100]).to_vec();
    // The POSIX prefix field extends the name; GNU reuses those bytes for
    // other purposes.
    if posix {
        let prefix = field_bytes(&block[345..500]);
        if !prefix.is_empty() {
            let mut joined = prefix.to_vec();
            joined.push(b'/');
            joined.extend_from_slice(&path);
            path = joined;
        }
    }

    let mode = numeric_field(&block[100..108])? as u32;
    let uid = numeric_field(&block[108..116])? as u32;
    let gid = numeric_field(&block[116..124])? as u32;
    let size = u64::try_from(numeric_field(&block[124..136])?).map_err(|_| HeaderFlaw::Numeric)?;
    let mtime = numeric_field(&block[136..148])?;
    let typeflag = match block[156] {
        // An old (v7-style) NUL typeflag is a regular file.
        0 => b'0',
        flag => flag,
    };
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
            b"mtime" => {
                // Pax times may carry fractional seconds; the integer part
                // is what extraction applies.
                let text =
                    std::str::from_utf8(value).map_err(|_| "a pax mtime record is not ASCII")?;
                let whole = text.split('.').next().unwrap_or(text);
                let mtime = whole
                    .parse()
                    .map_err(|_| "a pax mtime record is not numeric")?;
                records.mtime = Some(mtime);
            }
            _ => {}
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
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
}
