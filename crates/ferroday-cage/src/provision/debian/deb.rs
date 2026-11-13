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
//! chunks on the way past — [`digest::stream`](crate::provision::digest::stream)
//! on a read, [`DigestWriter`](crate::provision::digest::DigestWriter) on a
//! write. So installing or publishing a 90 MB kernel package costs what a shell
//! script costs.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use super::super::ProvisionError;
use super::super::compress;
use super::super::extract::{Extraction, OnEntry};
use super::super::tar::{self, TarReader};

/// The 8-byte `ar` global header.
const AR_MAGIC: &[u8] = b"!<arch>\n";
/// The size of one `ar` member header.
const AR_HEADER: usize = 60;

/// The largest `control.tar` member [`read_control_from`] will read, compressed
/// and decompressed alike.
///
/// A control member carries the control stanza, the maintainer scripts, and
/// `md5sums`, which together run to a few megabytes even for the largest
/// packages in the archive. The cap is what makes the bound unconditional: it
/// stops a `.deb` that declares an implausible member size from being read into
/// memory just because its header said so.
///
/// Both sides matter, and for the reason the Alpine layer bounds its own control
/// segment both ways: the member is a compression format, so one comfortably
/// inside the wire bound decompresses to as much `./control` as its author
/// chose. It is also read before anything about the package has been
/// authenticated. Applied to the decompressed stream the bound covers the time
/// as well as the memory, since an entry the reader skips past is decompressed
/// too, and a `./control` declaring more than it is refused before it is read.
const CONTROL_MEMBER_LIMIT: u64 = 16 * 1024 * 1024;

/// Extracts the `data.tar` member of the `.deb` at `path`, which `deb` reads,
/// into an ongoing extraction.
///
/// `path` names the package in a failure and is not opened. `on_entry` is
/// forwarded to the extractor for every extracted entry, so the caller can
/// record ownership for the dpkg statoverride. Extraction shares the caller's
/// [`Extraction`], so directory metadata is applied once across every package
/// rather than per package.
///
/// The member is streamed rather than buffered: the container is seeked to it,
/// and the decompressor and the tar reader are stacked directly on the file. So
/// unpacking a package costs the extractor's own buffers whatever the package
/// weighs, which is the property the whole module keeps.
pub(crate) fn extract_deb<R: Read + Seek>(
    path: &Path,
    deb: &mut R,
    extraction: &mut Extraction,
    on_entry: &mut OnEntry<'_>,
) -> Result<(), ProvisionError> {
    let (_, size) = seek_to_member(path, deb, "data.tar", None)?;
    // Bounded by the member's declared size, so the tar stream ends where the
    // member ends instead of running on into the container's next header.
    let member = deb.take(size);
    let (_, decoded) = compress::decoder(member).map_err(|err| tar::read_failure(path, 0, err))?;
    let mut archive = TarReader::new(decoded, path);
    extraction.extract(&mut archive, on_entry)
}

/// Positions `deb`, which reads the `.deb` at `path`, at the data of its first
/// member whose name begins with `member`, and returns where in the `.deb` that
/// data begins and the size the member declares.
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
/// A container the reader refuses is [`ProvisionError::Archive`], at the offset
/// in the `.deb` where what it refuses begins. A read that fails is
/// [`ProvisionError::Io`] naming `path`.
fn seek_to_member<R: Read + Seek>(
    path: &Path,
    deb: &mut R,
    member: &str,
    limit: Option<u64>,
) -> Result<(u64, u64), ProvisionError> {
    let io = |err: io::Error| ProvisionError::io("reading", path, err);

    // The end offset bounds every member size, so a header claiming more than
    // the file holds is refused before anything is read on its word.
    let length = deb.seek(SeekFrom::End(0)).map_err(io)?;
    deb.rewind().map_err(io)?;

    let mut magic = [0u8; AR_MAGIC.len()];
    deb.read_exact(&mut magic).map_err(|err| match err.kind() {
        io::ErrorKind::UnexpectedEof => {
            refused(0, "the .deb is shorter than an ar archive's magic")
        }
        _ => io(err),
    })?;
    if magic != AR_MAGIC {
        return Err(refused(
            0,
            "the .deb is not an ar archive: its magic is wrong",
        ));
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
            return Err(refused(
                offset,
                "the .deb's ar container ends inside a member header",
            ));
        }

        let mut header = [0u8; AR_HEADER];
        deb.read_exact(&mut header).map_err(io)?;
        if &header[58..60] != b"`\n" {
            return Err(refused(
                offset,
                "a member header of the .deb's ar container lacks its magic",
            ));
        }
        let name = ar_name(&header[0..16]);
        let size: u64 = ascii_field(&header[48..58]).parse().map_err(|_| {
            refused(
                offset,
                "a member size in the .deb's ar container is not a number",
            )
        })?;

        let wanted = name.starts_with(member);
        if let Some(limit) = limit.filter(|limit| wanted && size > *limit) {
            return Err(refused(
                offset,
                format!(
                    "the .deb's {member} member declares {size} bytes, more than the {limit} \
                     accepted for it"
                ),
            ));
        }
        let data = offset + AR_HEADER as u64;
        let end = data
            .checked_add(size)
            .filter(|end| *end <= length)
            .ok_or_else(|| {
                refused(
                    offset,
                    "a member of the .deb's ar container runs past its end",
                )
            })?;

        if wanted {
            return Ok((data, size));
        }

        // Members are padded to an even offset with a single newline.
        offset = end + (size & 1);
        deb.seek(SeekFrom::Start(offset)).map_err(io)?;
    }
    Err(refused(length, format!("the .deb has no {member} member")))
}

/// Builds [`ProvisionError::Archive`] for a `.deb` refused for what it
/// declares, `offset` bytes into it.
fn refused(offset: u64, reason: impl Into<String>) -> ProvisionError {
    ProvisionError::Archive {
        offset,
        reason: reason.into(),
        source: None,
    }
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
///
/// `deb` reads the `.deb` at `path`, which names it in a failure and is not
/// opened.
pub(crate) fn read_control_from<R: Read + Seek>(
    path: &Path,
    deb: &mut R,
) -> Result<String, ProvisionError> {
    let (at, size) = seek_to_member(path, deb, "control.tar", Some(CONTROL_MEMBER_LIMIT))?;
    let mut member = vec![0u8; size as usize];
    deb.read_exact(&mut member)
        .map_err(|err| ProvisionError::io("reading", path, err))?;
    control_from_tar(path, at, &member)
}

/// Reads the `control` entry out of the `control.tar` member of the `.deb` at
/// `path`, held in memory, which begins `at` bytes into the `.deb`.
fn control_from_tar(path: &Path, at: u64, member: &[u8]) -> Result<String, ProvisionError> {
    let (_, decoded) = compress::decoder(member).map_err(|err| tar::read_failure(path, 0, err))?;
    let mut archive = TarReader::new(decoded.take(CONTROL_MEMBER_LIMIT), path);
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
        let bytes = archive.read_entry(CONTROL_MEMBER_LIMIT)?;
        return String::from_utf8(bytes)
            .map_err(|_| refused(at, "the .deb's control file is not UTF-8"));
    }
    Err(refused(at, "the .deb's control.tar has no control file"))
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::ErrorChain;

    /// Seeks to `member`, reporting the reason rather than a typed error, and
    /// returns it with the bytes the member holds.
    fn member_of(archive: &[u8], member: &str) -> Result<Vec<u8>, String> {
        let mut cursor = Cursor::new(archive);
        let (_, size) = seek_to_member(Path::new("tool.deb"), &mut cursor, member, None)
            .map_err(|err| ErrorChain::new(&err).to_string())?;
        let mut bytes = vec![0u8; size as usize];
        cursor
            .read_exact(&mut bytes)
            .map_err(|err| ErrorChain::new(&err).to_string())?;
        Ok(bytes)
    }

    #[test]
    fn a_member_is_reached_across_the_padding_before_it() {
        // An odd-length member is followed by a padding byte, so a walk that
        // did not step over it would find the next header one byte late.
        let archive = ferroday_cage_testkit::deb::ar(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", b"odd"),
            ("data.tar.xz", b"payload!"),
        ]);
        assert_eq!(member_of(&archive, "control.tar").unwrap(), b"odd");
        assert_eq!(member_of(&archive, "data.tar").unwrap(), b"payload!");
        // The name is matched as a prefix, because the compression suffix is
        // the package's choice and not the reader's concern.
        assert_eq!(member_of(&archive, "debian-binary").unwrap(), b"2.0\n");
    }

    /// A `.deb` on a medium that fails every read past its first `good`
    /// bytes, as a file on a failing disk does.
    struct FailingPast {
        inner: Cursor<Vec<u8>>,
        good: u64,
    }

    impl Read for FailingPast {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let left = self.good.saturating_sub(self.inner.position());
            if left == 0 {
                return Err(io::Error::from_raw_os_error(5));
            }
            let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            self.inner.read(&mut buf[..want])
        }
    }

    impl Seek for FailingPast {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    #[test]
    fn a_read_that_fails_is_the_hosts_failure_naming_the_deb() {
        // Before the container's magic, and inside the control member: either
        // way the failure is the file's, not the package's, and it names the
        // file rather than a member of it.
        let archive = deb(b"Package: tool\n", 4096, false);
        for good in [0, 100] {
            let mut failing = FailingPast {
                inner: Cursor::new(archive.clone()),
                good,
            };
            match read_control_from(Path::new("/pool/tool.deb"), &mut failing) {
                Err(ProvisionError::Io { path, source, .. }) => {
                    assert_eq!(path, Path::new("/pool/tool.deb"), "{good}");
                    assert_eq!(source.raw_os_error(), Some(5), "{good}");
                }
                other => panic!("{good}: expected the host's failure, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_member_the_archive_does_not_carry_is_reported_by_name() {
        let archive = ferroday_cage_testkit::deb::ar(&[("debian-binary", b"2.0\n")]);
        let reason = member_of(&archive, "data.tar").unwrap_err();
        assert!(reason.contains("no data.tar member"), "{reason}");
    }

    #[test]
    fn a_non_ar_input_is_rejected() {
        let reason = member_of(b"not an ar archive at all", "data.tar").unwrap_err();
        assert!(reason.contains("its magic is wrong"), "{reason}");
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
        assert!(reason.contains("runs past its end"), "{reason}");
    }

    /// A single-entry uncompressed tar holding `./control`, the shape of a
    /// `.deb`'s control member once decompressed.
    fn control_tar(body: &[u8]) -> Vec<u8> {
        ferroday_cage_testkit::tar::Tar::new()
            .file("./control", 0o644, body)
            .finish()
    }

    /// A `.deb` whose data member is `data_size` bytes, with its members in the
    /// given order.
    fn deb(control: &[u8], data_size: usize, control_last: bool) -> Vec<u8> {
        let data = vec![0u8; data_size];
        let control = control_tar(control);
        let mut members: [(&str, &[u8]); 3] = [
            ("debian-binary", b"2.0\n"),
            ("control.tar", &control),
            ("data.tar", &data),
        ];
        if control_last {
            members.swap(1, 2);
        }
        ferroday_cage_testkit::deb::ar(&members)
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

        let control = read_control_from(Path::new("tool.deb"), &mut counting)
            .expect("the control member is read");
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
        let control = read_control_from(Path::new("tool.deb"), &mut Cursor::new(&archive))
            .expect("the control member is read");
        assert_eq!(control, String::from_utf8_lossy(stanza));
    }

    #[test]
    fn a_deb_without_a_control_member_is_rejected() {
        let archive = ferroday_cage_testkit::deb::ar(&[
            ("debian-binary", b"2.0\n"),
            ("data.tar", b"payload!"),
        ]);
        let err = read_control_from(Path::new("tool.deb"), &mut Cursor::new(&archive))
            .expect_err("a .deb with no control member is rejected");
        assert!(
            ErrorChain::new(&err)
                .to_string()
                .contains("no control.tar member"),
            "{err}"
        );
    }

    /// A `.deb` whose control member is `tar`, gzipped, asserting that the
    /// compressed member is inside the wire bound so the decompressed one is
    /// what a refusal answers.
    fn gzipped_control(tar: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let compressed = {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            encoder.write_all(tar).expect("the bomb compresses");
            encoder.finish().expect("the encoder finishes")
        };
        assert!(
            (compressed.len() as u64) < CONTROL_MEMBER_LIMIT,
            "the fixture must be inside the wire bound to test the other one",
        );
        ferroday_cage_testkit::deb::ar(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", &compressed),
        ])
    }

    #[test]
    fn a_control_member_that_decompresses_past_the_ceiling_is_refused() {
        // The wire bound holds the compressed member, and the member is a
        // compression format: one comfortably inside it decompresses to as much
        // `./control` as its author chose. Read before anything about the
        // package is authenticated, so it is refused rather than accumulated,
        // on the length its header declares.
        let archive = gzipped_control(&control_tar(&vec![b'x'; CONTROL_MEMBER_LIMIT as usize + 1]));
        let err = read_control_from(Path::new("tool.deb"), &mut Cursor::new(&archive))
            .expect_err("a control file past the ceiling is refused");
        assert!(err.to_string().contains("more than the"), "{err}");

        // An entry ahead of `./control` is decompressed to be skipped, so the
        // ceiling holds the stream as well as the file it is after.
        let skipped = ferroday_cage_testkit::tar::Tar::new()
            .file(
                "./postinst",
                0o755,
                &vec![b'x'; CONTROL_MEMBER_LIMIT as usize + 1],
            )
            .file("./control", 0o644, b"Package: tool\n")
            .finish();
        let err = read_control_from(
            Path::new("tool.deb"),
            &mut Cursor::new(&gzipped_control(&skipped)),
        )
        .expect_err("a control archive past the ceiling is refused");
        assert!(err.to_string().contains("ends inside an entry"), "{err}",);
    }

    #[test]
    fn an_implausible_control_member_size_is_refused() {
        // The cap is read off the declared size, before it is used to size an
        // allocation, so a header claiming more than any real control member
        // costs nothing to refuse.
        let mut archive = ferroday_cage_testkit::deb::ar(&[("debian-binary", b"2.0\n")]);
        let mut header = [b' '; AR_HEADER];
        header[.."control.tar.gz".len()].copy_from_slice(b"control.tar.gz");
        let size = (CONTROL_MEMBER_LIMIT + 1).to_string();
        header[48..48 + size.len()].copy_from_slice(size.as_bytes());
        header[58] = b'`';
        header[59] = b'\n';
        archive.extend_from_slice(&header);

        let err = read_control_from(Path::new("tool.deb"), &mut Cursor::new(&archive))
            .expect_err("an implausible control member is refused");
        assert!(
            ErrorChain::new(&err)
                .to_string()
                .contains("more than the 16777216 accepted"),
            "{err}"
        );
    }
}
