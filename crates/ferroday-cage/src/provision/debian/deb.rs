//! Reading a `.deb`: the `ar` container and its `data.tar` member.
//!
//! A `.deb` is a Unix `ar` archive of three members — `debian-binary`, a
//! `control.tar`, and a `data.tar` — the last carrying the files to install.
//! The `data.tar` is a tar stream compressed like any rootfs tarball, so it
//! extracts through the same hardened extractor once unwrapped from the `ar`
//! container.
//!
//! Nothing here holds a `.deb`. Every read reaches its member by seeking on the
//! container's declared sizes, so the members before the one wanted are stepped
//! over and the members after it are never touched: [`extract_deb`] streams the
//! `data.tar` through the decompressor into the extractor, and
//! [`read_control_from`] reads only the control member. Digests are taken in
//! chunks on the way past — [`sha256_stream`] on a read, [`DigestWriter`] on a
//! write. So installing or publishing a 90 MB kernel package costs what a shell
//! script costs.

use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use super::super::compress;
use super::super::extract::{Extraction, OnEntry};
use super::super::tar::TarReader;
use super::super::{ProvisionError, io_error};

/// The 8-byte `ar` global header.
const AR_MAGIC: &[u8] = b"!<arch>\n";
/// The size of one `ar` member header.
const AR_HEADER: usize = 60;

/// The chunk size the streaming reads work in.
const CHUNK: usize = 64 * 1024;

/// The largest `control.tar` member [`read_control_from`] will hold in memory.
///
/// A control member carries the control stanza, the maintainer scripts, and
/// `md5sums`, which together run to a few megabytes even for the largest
/// packages in the archive. The cap is what makes the bound unconditional: it
/// stops a `.deb` that declares an implausible member size from being read into
/// memory just because its header said so.
const CONTROL_MEMBER_LIMIT: u64 = 16 * 1024 * 1024;

/// The lowercase hex SHA-256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The lowercase hex SHA-256 of everything `reader` yields, with the number of
/// bytes it yielded.
///
/// The digest is taken in fixed-size chunks, so it costs the same memory for a
/// kernel package as for a shell script. The size is counted from what was
/// actually read rather than taken from a stat, so it describes the same bytes
/// the digest does.
pub(crate) fn sha256_stream(reader: &mut impl Read) -> io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(got) => {
                hasher.update(&chunk[..got]);
                size += got as u64;
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok((hex(&hasher.finalize()), size))
}

/// A writer that digests everything written through it on its way to `inner`.
///
/// The write-side counterpart of [`sha256_stream`]. A [`Fetch`](super::Fetch)
/// writes a resource to a sink as it arrives, so a download that digests at the
/// sink learns what it received without holding it: the bytes go to their file
/// and to the hasher in one pass, and the caller decides whether to publish the
/// file only after the digest is known.
pub(crate) struct DigestWriter<W> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> DigestWriter<W> {
    /// Wraps `inner`, digesting what passes through.
    pub(crate) fn new(inner: W) -> DigestWriter<W> {
        DigestWriter {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }

    /// Flushes the wrapped writer and reports the lowercase hex digest of
    /// everything written through it, with the number of bytes that was.
    ///
    /// The count comes from what was actually written rather than from a stat,
    /// so it describes the same bytes the digest does.
    pub(crate) fn finish(mut self) -> io::Result<(String, u64)> {
        self.inner.flush()?;
        Ok((hex(&self.hasher.finalize()), self.written))
    }
}

impl<W: Write> Write for DigestWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Only what the inner writer accepted is digested, so a short write
        // cannot put the digest and the file out of step.
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Formats a digest as lowercase hex.
fn hex(digest: &[u8]) -> String {
    let mut text = String::with_capacity(digest.len() * 2);
    for byte in digest {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// Extracts a `.deb`'s `data.tar` member into an ongoing extraction.
///
/// `on_entry` is forwarded to the extractor for every extracted entry, so
/// the caller can record ownership for the dpkg statoverride. Extraction
/// shares the caller's [`Extraction`], so directory metadata is applied once
/// across every package rather than per package.
///
/// The member is streamed rather than buffered: the container is seeked to it,
/// and the decompressor and the tar reader are stacked directly on the file. So
/// unpacking a package costs the extractor's own buffers whatever the package
/// weighs, which is the property the whole module keeps.
pub(crate) fn extract_deb<R: Read + Seek>(
    package: &str,
    deb: &mut R,
    extraction: &mut Extraction,
    on_entry: &mut OnEntry<'_>,
) -> Result<(), ProvisionError> {
    let size = seek_to_member(deb, "data.tar", None, &|reason: String| {
        deb_error(package, &reason)
    })?;
    // Bounded by the member's declared size, so the tar stream ends where the
    // member ends instead of running on into the container's next header.
    let mut member = deb.take(size);
    let head = compress::sniff_head(&mut member)
        .map_err(|err| io_error("reading the data member of", Path::new(package), err))?;
    let decoded = compress::decompress(&head, member)?;
    let mut archive = TarReader::new(decoded);
    extraction.extract(&mut archive, on_entry)
}

/// Positions `deb` at the data of its first member whose name begins with
/// `member`, and returns that member's declared size.
///
/// The name is matched as a prefix because a `.deb`'s compressed members carry
/// the compression as a suffix — `control.tar.xz`, `data.tar.zst` — and which
/// one a package used is not the caller's concern.
///
/// The `ar` container records each member's size in its header, so the members
/// before the one wanted are seeked over rather than read, and the members after
/// it are never touched. Seeking rather than scanning also keeps the read
/// indifferent to member order, which a reader that stopped at the first member
/// it streamed past would not be.
///
/// `limit` bounds what the member may declare, for a caller that will read it
/// into memory rather than stream it. It is checked against the declared size
/// before that size is used for anything, so a header claiming more than any
/// real member holds is refused rather than acted on.
///
/// A structural problem is reported through `bad`, which names the `.deb` the
/// caller is reading; an I/O failure is reported against the member being sought.
fn seek_to_member<R: Read + Seek>(
    deb: &mut R,
    member: &str,
    limit: Option<u64>,
    bad: &dyn Fn(String) -> ProvisionError,
) -> Result<u64, ProvisionError> {
    let io = |err: io::Error| io_error("reading a member of the package", Path::new(member), err);

    // The end offset bounds every member size, so a header claiming more than
    // the file holds is refused before anything is read on its word.
    let length = deb.seek(SeekFrom::End(0)).map_err(io)?;
    deb.rewind().map_err(io)?;

    let mut magic = [0u8; AR_MAGIC.len()];
    deb.read_exact(&mut magic)
        .map_err(|_| bad("not an ar archive (bad magic)".to_string()))?;
    if magic != AR_MAGIC {
        return Err(bad("not an ar archive (bad magic)".to_string()));
    }

    let mut offset = AR_MAGIC.len() as u64;
    while offset < length {
        // A trailing newline padding byte between the last member and the
        // end of the archive is tolerated.
        let remaining = length - offset;
        if remaining < AR_HEADER as u64 {
            let mut tail = vec![0u8; remaining as usize];
            deb.read_exact(&mut tail).map_err(io)?;
            if tail.iter().all(|byte| *byte == b'\n') {
                break;
            }
            return Err(bad("a truncated member header".to_string()));
        }

        let mut header = [0u8; AR_HEADER];
        deb.read_exact(&mut header).map_err(io)?;
        if &header[58..60] != b"`\n" {
            return Err(bad("a member header lacks its magic".to_string()));
        }
        let name = ar_name(&header[0..16]);
        let size: u64 = ascii_field(&header[48..58])
            .parse()
            .map_err(|_| bad("a member size is not a number".to_string()))?;

        let wanted = name.starts_with(member);
        if wanted && limit.is_some_and(|limit| size > limit) {
            return Err(bad(format!("the {member} member is implausibly large")));
        }
        let end = (offset + AR_HEADER as u64)
            .checked_add(size)
            .filter(|end| *end <= length)
            .ok_or_else(|| bad("a member size runs past the archive".to_string()))?;

        if wanted {
            return Ok(size);
        }

        // Members are padded to an even offset with a single newline.
        offset = end + (size & 1);
        deb.seek(SeekFrom::Start(offset)).map_err(io)?;
    }
    Err(bad(format!("no {member} member")))
}

/// Reads a `.deb`'s control stanza: the `control` member of its `control.tar`.
///
/// A `.deb`'s `control.tar` holds the package's control file — the deb822 stanza
/// carrying `Package`, `Version`, `Architecture`, the dependency relations, and
/// the rest — alongside its maintainer scripts and `md5sums`. This unwraps the
/// `control.tar` from the `ar` container, decompresses it through the same
/// hardened path as a `data.tar`, and returns the `./control` entry's text. It is
/// the read a pool writer needs to synthesize a `Packages` stanza from a built
/// `.deb`.
///
/// The returned text is the control file verbatim, so a caller can emit it into a
/// `Packages` index without reconstructing deb822 folding, appending only the
/// archive-supplied `Filename`, `Size`, and `SHA256`.
///
/// Only the control member is read, and [`seek_to_member`] describes what that
/// costs: reaching it is proportional to the members before it — a few hundred
/// bytes — rather than to the `.deb`, which for a kernel package is four orders
/// of magnitude larger.
pub(crate) fn read_control_from<R: Read + Seek>(deb: &mut R) -> Result<String, ProvisionError> {
    let size = seek_to_member(
        deb,
        "control.tar",
        Some(CONTROL_MEMBER_LIMIT),
        &|reason: String| control_error(&reason),
    )?;
    let mut member = vec![0u8; size as usize];
    deb.read_exact(&mut member).map_err(|err| {
        io_error(
            "reading the control member of the package",
            Path::new("control.tar"),
            err,
        )
    })?;
    control_from_tar(&member)
}

/// Reads the `control` entry out of a `.deb`'s `control.tar` member.
fn control_from_tar(member: &[u8]) -> Result<String, ProvisionError> {
    let mut cursor = Cursor::new(member);
    let head = compress::sniff_head(&mut cursor).map_err(|err| {
        io_error(
            "reading the control member of the package",
            Path::new("control.tar"),
            err,
        )
    })?;
    let decoded = compress::decompress(&head, cursor)?;
    let mut archive = TarReader::new(decoded);
    while let Some(entry) = archive.next_entry()? {
        // The control file is `./control` in a conforming `.deb`; tolerate a
        // bare `control` as well.
        let name = entry
            .path
            .strip_prefix(b"./".as_slice())
            .unwrap_or(&entry.path);
        if name != b"control" {
            continue;
        }
        // The reserve is a hint taken from the entry header, so it is capped:
        // the vector grows to whatever the entry actually holds, and a header
        // claiming more than it carries does not get to ask for it up front.
        let claimed = usize::try_from(entry.size).unwrap_or(0);
        let mut bytes = Vec::with_capacity(claimed.min(CHUNK));
        let mut chunk = [0u8; 4096];
        loop {
            let got = archive.read_data(&mut chunk)?;
            if got == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..got]);
        }
        return String::from_utf8(bytes)
            .map_err(|_| control_error("the control file is not UTF-8"));
    }
    Err(control_error("the control.tar has no control member"))
}

/// Builds an error for a malformed `.deb` presented to [`read_control_from`].
fn control_error(reason: &str) -> ProvisionError {
    ProvisionError::other(format!("the .deb control member is unreadable: {reason}"))
}

/// Trims an `ar` member name: trailing spaces and the GNU terminator slash.
///
/// Only the fixed-name short form is handled, which is all a `.deb` uses; the
/// GNU long-name table and BSD extensions are not needed and are not
/// implemented.
fn ar_name(field: &[u8]) -> String {
    let text = String::from_utf8_lossy(field);
    text.trim_end().trim_end_matches('/').to_string()
}

/// Reads a space-padded ASCII `ar` header field.
fn ascii_field(field: &[u8]) -> String {
    String::from_utf8_lossy(field).trim().to_string()
}

/// Builds a package-scoped extraction error.
fn deb_error(package: &str, reason: &str) -> ProvisionError {
    ProvisionError::other(format!("the .deb for {package} is malformed: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Appends one `ar` member to `archive`.
    fn ar_member(archive: &mut Vec<u8>, name: &str, data: &[u8]) {
        let mut header = [b' '; AR_HEADER];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = data.len().to_string();
        header[48..48 + size.len()].copy_from_slice(size.as_bytes());
        header[58] = b'`';
        header[59] = b'\n';
        archive.extend_from_slice(&header);
        archive.extend_from_slice(data);
        if data.len() % 2 == 1 {
            archive.push(b'\n');
        }
    }

    #[test]
    fn sha256_of_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Seeks to `member`, reporting the reason rather than a typed error, and
    /// returns it with the bytes the member holds.
    fn member_of(archive: &[u8], member: &str) -> Result<Vec<u8>, String> {
        let mut cursor = Cursor::new(archive);
        let size = seek_to_member(&mut cursor, member, None, &|reason: String| {
            ProvisionError::other(reason)
        })
        .map_err(|err| err.to_string())?;
        let mut bytes = vec![0u8; size as usize];
        cursor
            .read_exact(&mut bytes)
            .map_err(|err| err.to_string())?;
        Ok(bytes)
    }

    #[test]
    fn a_member_is_reached_across_the_padding_before_it() {
        // An odd-length member is followed by a padding byte, so a walk that
        // did not step over it would find the next header one byte late.
        let mut archive = AR_MAGIC.to_vec();
        ar_member(&mut archive, "debian-binary", b"2.0\n");
        ar_member(&mut archive, "control.tar.gz", b"odd");
        ar_member(&mut archive, "data.tar.xz", b"payload!");
        assert_eq!(member_of(&archive, "control.tar").unwrap(), b"odd");
        assert_eq!(member_of(&archive, "data.tar").unwrap(), b"payload!");
        // The name is matched as a prefix, because the compression suffix is
        // the package's choice and not the reader's concern.
        assert_eq!(member_of(&archive, "debian-binary").unwrap(), b"2.0\n");
    }

    #[test]
    fn a_member_the_archive_does_not_carry_is_reported_by_name() {
        let mut archive = AR_MAGIC.to_vec();
        ar_member(&mut archive, "debian-binary", b"2.0\n");
        let reason = member_of(&archive, "data.tar").unwrap_err();
        assert!(reason.contains("no data.tar member"), "{reason}");
    }

    #[test]
    fn a_non_ar_input_is_rejected() {
        let reason = member_of(b"not an ar archive at all", "data.tar").unwrap_err();
        assert!(reason.contains("bad magic"), "{reason}");
    }

    #[test]
    fn a_member_size_running_past_the_archive_is_rejected() {
        // The container's own end bounds every declared size, so a header
        // claiming more than the file holds is refused before anything is read
        // or allocated on its word.
        let mut archive = AR_MAGIC.to_vec();
        let mut header = [b' '; AR_HEADER];
        header[.."data.tar".len()].copy_from_slice(b"data.tar");
        header[48..58].copy_from_slice(b"9999999999");
        header[58] = b'`';
        header[59] = b'\n';
        archive.extend_from_slice(&header);
        let reason = member_of(&archive, "data.tar").unwrap_err();
        assert!(reason.contains("runs past the archive"), "{reason}");
    }

    /// Writes an octal header field: digits padded to the field width, NUL
    /// terminated, as a ustar header carries them.
    fn octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        field[..width].copy_from_slice(format!("{value:0width$o}").as_bytes());
        field[width] = 0;
    }

    /// A single-entry uncompressed tar holding `./control`, the shape of a
    /// `.deb`'s control member once decompressed.
    fn control_tar(body: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..b"./control".len()].copy_from_slice(b"./control");
        octal(&mut header[100..108], 0o644);
        octal(&mut header[108..116], 0);
        octal(&mut header[116..124], 0);
        octal(&mut header[124..136], body.len() as u64);
        octal(&mut header[136..148], 0);
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        // The checksum is taken over the header with its own field blanked.
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());

        let mut tar = header.to_vec();
        tar.extend_from_slice(body);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
        // The two zero blocks that terminate the archive.
        tar.extend_from_slice(&[0u8; 1024]);
        tar
    }

    /// A `.deb` whose data member is `data_size` bytes, with its members in the
    /// given order.
    fn deb(control: &[u8], data_size: usize, control_last: bool) -> Vec<u8> {
        let mut archive = AR_MAGIC.to_vec();
        ar_member(&mut archive, "debian-binary", b"2.0\n");
        if control_last {
            ar_member(&mut archive, "data.tar", &vec![0u8; data_size]);
            ar_member(&mut archive, "control.tar", &control_tar(control));
        } else {
            ar_member(&mut archive, "control.tar", &control_tar(control));
            ar_member(&mut archive, "data.tar", &vec![0u8; data_size]);
        }
        archive
    }

    /// A reader that tallies the bytes actually read through it, so a test can
    /// assert what a read did not touch.
    struct Counting<R> {
        inner: R,
        read: u64,
    }

    impl<R: Read> Read for Counting<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let got = self.inner.read(buf)?;
            self.read += got as u64;
            Ok(got)
        }
    }

    impl<R: Seek> Seek for Counting<R> {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    #[test]
    fn the_control_member_is_read_without_touching_the_payload() {
        // The property the pool writer depends on: reading a package's control
        // stanza costs its control member, not its size. A 4 MiB payload must
        // be seeked over, never read.
        let stanza = b"Package: tool\nVersion: 1.0\nArchitecture: amd64\n";
        let archive = deb(stanza, 4 * 1024 * 1024, false);
        let mut counting = Counting {
            inner: Cursor::new(&archive),
            read: 0,
        };

        let control = read_control_from(&mut counting).expect("the control member is read");
        assert_eq!(control, String::from_utf8_lossy(stanza));
        assert!(
            counting.read < 64 * 1024,
            "reading the control member read {} bytes of a {} byte archive",
            counting.read,
            archive.len(),
        );
    }

    #[test]
    fn the_control_member_is_found_after_the_payload() {
        // Members are located by seeking on their declared sizes, so a .deb
        // that orders its members unconventionally reads the same. A reader
        // that streamed until it met a control member would too, but would
        // have paid for the payload to get there.
        let stanza = b"Package: tool\nVersion: 2.0\nArchitecture: all\n";
        let archive = deb(stanza, 8192, true);
        let control =
            read_control_from(&mut Cursor::new(&archive)).expect("the control member is read");
        assert_eq!(control, String::from_utf8_lossy(stanza));
    }

    #[test]
    fn a_deb_without_a_control_member_is_rejected() {
        let mut archive = AR_MAGIC.to_vec();
        ar_member(&mut archive, "debian-binary", b"2.0\n");
        ar_member(&mut archive, "data.tar", b"payload!");
        let err = read_control_from(&mut Cursor::new(&archive))
            .expect_err("a .deb with no control member is rejected");
        assert!(err.to_string().contains("no control.tar member"), "{err}");
    }

    #[test]
    fn an_implausible_control_member_size_is_refused() {
        // The cap is read off the declared size, before it is used to size an
        // allocation, so a header claiming more than any real control member
        // costs nothing to refuse.
        let mut archive = AR_MAGIC.to_vec();
        ar_member(&mut archive, "debian-binary", b"2.0\n");
        let mut header = [b' '; AR_HEADER];
        header[.."control.tar.gz".len()].copy_from_slice(b"control.tar.gz");
        let size = (CONTROL_MEMBER_LIMIT + 1).to_string();
        header[48..48 + size.len()].copy_from_slice(size.as_bytes());
        header[58] = b'`';
        header[59] = b'\n';
        archive.extend_from_slice(&header);

        let err = read_control_from(&mut Cursor::new(&archive))
            .expect_err("an implausible control member is refused");
        assert!(err.to_string().contains("implausibly large"), "{err}");
    }

    #[test]
    fn a_streamed_digest_matches_the_buffered_one() {
        // The streaming digest spans several chunks, so the chunk boundaries
        // are exercised rather than assumed away by a small input.
        let bytes: Vec<u8> = (0..CHUNK * 3 + 17).map(|i| (i % 251) as u8).collect();
        let (digest, size) =
            sha256_stream(&mut Cursor::new(&bytes)).expect("the stream is digested");
        assert_eq!(digest, sha256_hex(&bytes));
        assert_eq!(size, bytes.len() as u64);

        // An empty stream is the empty digest, not a failure.
        let (digest, size) = sha256_stream(&mut Cursor::new(Vec::new())).expect("empty digests");
        assert_eq!(digest, sha256_hex(b""));
        assert_eq!(size, 0);
    }
}
