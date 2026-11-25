//! Where the provisioners' tar archives meet ferrotape, which reads and writes
//! them.
//!
//! ferrotape reads POSIX ustar and pax, GNU, and pre-POSIX v7 archives, folds
//! long names and pax records into the member they describe, and refuses an
//! archive that GNU tar, bsdtar, Go's `archive/tar` and Python's `tarfile`
//! read differently from one another. A reader here starts at its
//! [`Level::Strict`], which also counts the Rust tar crates among those
//! readers, and is read with its default for a global extended header, which
//! refuses one that would change a member. The packages and stage3s the
//! userland layers verify are read at Strict; a caller's own archive, through
//! [`Tarball`](super::Tarball), at [`Level::Compatible`]
//! ([`with_level`](TarReader::with_level)).
//!
//! [`TarReader`] is that reader with the archive's name beside it, so a
//! failure is reported as a [`ProvisionError`] naming the archive it belongs
//! to: a refusal of what the archive declares as [`ProvisionError::Archive`],
//! a source that failed as [`ProvisionError::Io`] ([`read_failure`]). Its
//! members are ferrotape's [`Entry`] values. [`into_io`] carries a failure
//! through a `Read`, for an archive read from another archive's member.
//!
//! Writing goes through ferrotape's `Header` and `Writer` directly: nothing
//! about a header's encoding is decided in this crate.

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use ferrotape::{Entry, ErrorKind, Level, Reader};

use super::ProvisionError;
use super::compress::Refusal;

/// A tar reader over any byte source, with the archive's name for its
/// failures.
///
/// A read of the source that fails is reported as what it is
/// ([`read_failure`]): the source failing, an OS error or a transport's, as
/// [`ProvisionError::Io`] naming the archive, and a decoder beneath refusing
/// the stream as [`ProvisionError::Archive`] with the decoder's failure as its
/// cause. Every other failure is the archive's, a refusal of what it declares,
/// with ferrotape's account of the rule it breaks as the reason.
pub(crate) struct TarReader<R: Read> {
    inner: Reader<R>,
    /// The archive, as a failure to read it names it.
    path: PathBuf,
    /// Whether the stream turned out not to be a tar archive at all. Read by
    /// [`not_a_tar`](Self::not_a_tar).
    not_a_tar: bool,
    /// Where in the stream the current member's data has been read to, for a
    /// source that fails while it is read. ferrotape reports the offset of
    /// every failure but one: a source's own, which reaches a `Read` of a
    /// member's data as the source's error and nothing else. A sparse
    /// member's holes are no bytes of the stream, so only its stored data
    /// counts toward it.
    data_at: u64,
    /// Whether the current member is sparse, its file holding more than the
    /// archive stores.
    sparse: bool,
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
    /// A reader over `inner`, which holds the archive at `path`, at
    /// [`Level::Strict`].
    ///
    /// `path` is what a failure to read `inner` names: the file, or, for a
    /// stream that has none, what the caller calls it.
    pub(crate) fn new(inner: R, path: impl Into<PathBuf>) -> Self {
        TarReader {
            inner: Reader::new(inner).with_level(Level::Strict),
            path: path.into(),
            not_a_tar: false,
            data_at: 0,
            sparse: false,
        }
    }

    /// The reader, reading at `level`, before anything is read.
    pub(crate) fn with_level(self, level: Level) -> Self {
        TarReader {
            inner: self.inner.with_level(level),
            ..self
        }
    }

    /// Whether the failure was that this is not a tar archive at all.
    ///
    /// Meaningful only after [`next_entry`](Self::next_entry) returned an
    /// error; a caller reports "not a tar archive" rather than "corrupt
    /// archive" on it. True where ferrotape found no archive
    /// ([`ErrorKind::NotATar`]): the stream ended before its first block was
    /// whole, or that block carries neither magic nor a checksum that
    /// matches, which with v7 read is what any other format's first 512 bytes
    /// look like.
    ///
    /// Every other failure keeps its own reason, however early it came. A first
    /// block carrying the magic with a checksum that does not match is a
    /// corrupt tar header, and one refused for what it declares is a malformed
    /// archive. A read that *failed* is the reader underneath: the source, or a
    /// decompressor whose refusal (a dictionary over the bound, a truncated
    /// stream, a frame it will not decode) is a diagnostic with a reason in it.
    /// Calling any of these "not a tar archive" would replace the reason with a
    /// guess about the format.
    pub fn not_a_tar(&self) -> bool {
        self.not_a_tar
    }

    /// Advances to the next member, returning `None` at the end of the
    /// archive.
    ///
    /// Any unread data of the previous member is passed over first. Long names
    /// and pax records are folded into the member they describe, and members
    /// that describe the archive rather than a file (a global header holding
    /// only a `comment`) are passed over.
    ///
    /// A sparse member is refused with [`ProvisionError::EntryRefused`],
    /// whichever of GNU's formats wrote it: the old `S` type, or a pax format
    /// whose header claims a regular file. Its data, as
    /// [`read_data`](Self::read_data) reads it, is the file it stands for, up
    /// to 2^60 bytes of it, and its [`Entry::size`] that file's length, so a
    /// reader that sizes a read from the entry, as one hashing or holding a
    /// member does, must never meet one. Only the extractor reads sparse
    /// members, through
    /// [`next_entry_with_sparse`](Self::next_entry_with_sparse). The Debian,
    /// Alpine and Gentoo layers are this method's callers, so a build with
    /// none of them has none.
    #[cfg_attr(
        not(any(feature = "debian", feature = "alpine", feature = "gentoo")),
        allow(dead_code)
    )]
    pub fn next_entry(&mut self) -> Result<Option<Entry>, ProvisionError> {
        let entry = self.next_entry_with_sparse()?;
        if let Some(entry) = &entry
            && entry.sparse().is_some()
        {
            return Err(ProvisionError::EntryRefused {
                path: PathBuf::from(OsStr::from_bytes(entry.path())),
                reason: "it is a sparse member, which only an extraction reads".to_string(),
            });
        }
        Ok(entry)
    }

    /// Advances to the next member as [`next_entry`](Self::next_entry) does,
    /// yielding a sparse member rather than refusing it.
    ///
    /// For the extractor, which writes a sparse member's file with its holes:
    /// its map is the member's [`Entry::sparse`], and
    /// [`read_stored`](Self::read_stored) reads the regions it stores. A
    /// sparse member is read in every form the reader's level reads.
    pub(crate) fn next_entry_with_sparse(&mut self) -> Result<Option<Entry>, ProvisionError> {
        let entry = self.inner.next_entry().map_err(|err| self.failure(err))?;
        if let Some(entry) = &entry {
            self.data_at = entry.data_offset();
            self.sparse = entry.sparse().is_some();
        }
        Ok(entry)
    }

    /// Reads the current member's data into `buf`, returning 0 once it is all
    /// read.
    ///
    /// The buffer is filled as far as the member's remaining data reaches, a
    /// read that a signal interrupted retried: the archive may arrive over a
    /// pipe or a socket, in a process whose signal handlers do not restart the
    /// calls they interrupt. Every byte asked for is one the member declares,
    /// so a fill that ends short is an archive that ends inside the member.
    ///
    /// A sparse member's data is the file it stands for, its holes as zeros.
    pub fn read_data(&mut self, buf: &mut [u8]) -> Result<usize, ProvisionError> {
        let read = self.inner.data().read(buf);
        self.counted(read, false)
    }

    /// Reads the current member's data as the archive stores it into `buf`,
    /// returning 0 once it is all read: for a sparse member, its regions'
    /// bytes alone, in the map's order, and for any other, its data as
    /// [`read_data`](Self::read_data) reads it.
    ///
    /// What the holes of a sparse member hold is never read, so passing over
    /// a member through this costs what the archive holds, where its file
    /// can be up to 2^60 bytes long.
    pub fn read_stored(&mut self, buf: &mut [u8]) -> Result<usize, ProvisionError> {
        let read = self.inner.stored_data().read(buf);
        self.counted(read, true)
    }

    /// A read of the member's data, `stored` where it read what the archive
    /// holds, counted toward where the stream has reached.
    fn counted(&mut self, read: io::Result<usize>, stored: bool) -> Result<usize, ProvisionError> {
        match read {
            Ok(got) => {
                // A sparse member's file, read whole, holds bytes of its holes,
                // which are the reader's rather than the stream's.
                if stored || !self.sparse {
                    self.data_at += got as u64;
                }
                Ok(got)
            }
            // A refusal of the archive, carried in the `io::Error` a `Read`
            // returns, or the source's own failure as the source returned it.
            Err(err) => match err.downcast::<ferrotape::Error>() {
                Ok(err) => Err(self.failure(err)),
                Err(err) => Err(read_failure(&self.path, self.data_at, err)),
            },
        }
    }

    /// Reads the rest of the archive, then the stream on past the archive's
    /// end to the stream's end, refusing more than `limit` bytes there, and
    /// anything there but zeros.
    ///
    /// A tar archive ends at its end marker, and nothing after it is part of
    /// the archive. The stream the archive is read from may not end there: the
    /// rest of the last record is padding, and a compressed stream closes with
    /// the check over the last block it decoded, which covers the marker and
    /// the members before it. Stopping at the marker leaves that check unread,
    /// so a corrupt final block would be extracted as though it were sound.
    /// Reading on to the end is what has the decoder compare it.
    ///
    /// For an archive whose bytes are verified against a digest before it is
    /// read, the decoder's check adds nothing, and a caller reading one need
    /// not finish it. For one nothing else vouches for, the check is the only
    /// thing that would say the stream is damaged.
    ///
    /// What follows the marker is decoded only to be checked, so `limit`
    /// bounds what a stream can make that cost: a few mebibytes of input can
    /// decompress to far more than any record padding.
    pub(crate) fn finish(&mut self, limit: u64) -> Result<(), ProvisionError> {
        self.inner.finish(limit).map_err(|err| self.failure(err))
    }

    /// Reads what is left of the current member's data into memory, refusing a
    /// member that holds more than `limit` bytes.
    ///
    /// The one way a member is held whole, for the members a reader acts on as
    /// a unit: a control file, a package's metadata. The ceiling is the
    /// caller's, since only the caller knows what the member is. The refusal
    /// is made on the length the header declares, before a byte of the data is
    /// read, and is never a truncation: what is returned is the whole member,
    /// and an archive that ends inside it is refused.
    #[cfg_attr(
        not(any(feature = "debian", feature = "alpine", feature = "gentoo")),
        allow(dead_code)
    )]
    pub(crate) fn read_entry(&mut self, limit: u64) -> Result<Vec<u8>, ProvisionError> {
        match self.inner.read_entry(limit) {
            Ok(data) => {
                self.data_at += data.len() as u64;
                Ok(data)
            }
            Err(err) => Err(self.failure(err)),
        }
    }

    /// `err`, a failure of the reader, as this archive reports it.
    fn failure(&mut self, err: ferrotape::Error) -> ProvisionError {
        let offset = err.offset();
        match err.kind() {
            // The source failed: converting the error hands its failure back.
            ErrorKind::Io => read_failure(&self.path, offset, io::Error::from(err)),
            kind => {
                self.not_a_tar = *kind == ErrorKind::NotATar;
                ProvisionError::Archive {
                    path: self.path.clone(),
                    offset,
                    reason: kind.to_string(),
                    source: None,
                }
            }
        }
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
            path: path.to_path_buf(),
            offset,
            reason: refusal.what().to_string(),
            source: Some(refusal.into_cause()),
        },
        Err(err) => ProvisionError::io("reading", path, err),
    }
}

/// `err`, a failure of a [`TarReader`], as the `io::Error` a `Read` over a
/// member's data returns, so a reader of that data reports it as
/// [`read_failure`] does.
///
/// An OS failure is returned as the OS returned it, which is what a reader above
/// takes it for; it names the archive again by its own path, the archive that
/// holds the member. Any other failure is carried whole, and a reader above
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

#[cfg(test)]
mod tests {
    use super::*;
    use ferroday_cage_testkit::tar::Tar;

    /// A source that fails every read with `err`.
    struct Failing(fn() -> io::Error);

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err((self.0)())
        }
    }

    /// An archive of one regular file holding `body`, with a header declaring
    /// `declared` bytes for it.
    fn one_file(declared: u64, body: &[u8]) -> Vec<u8> {
        Tar::new()
            .header(b"entry", b'0', 0o644, declared, 0, b"")
            .body(body)
            .finish()
    }

    #[test]
    fn a_reader_that_fails_is_not_a_file_of_another_format() {
        // The reader under the parser is a decompressor, and its refusals carry
        // reasons -- a dictionary over the bound, a frame it will not decode.
        // Reported as "not a tar archive" those reasons are gone, replaced by a
        // guess about the format.
        let mut reader = TarReader::new(
            Failing(|| {
                Refusal::mark(
                    "the xz stream does not decode",
                    io::Error::new(
                        io::ErrorKind::InvalidData,
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
            "malformed archive \"/srv/rootfs.tar.xz\" at offset 0: the xz stream does not \
             decode: the dictionary is larger than the bound",
        );
        assert!(
            !reader.not_a_tar(),
            "a reader that failed said nothing about the format",
        );

        // What the classification is for: bytes that arrived and are not a tar
        // header, however few of them there were, or none.
        for bytes in [&b"not a tar archive at all"[..], &[b'X'; 512][..], &b""[..]] {
            let mut reader = TarReader::in_memory(bytes);
            assert!(reader.next_entry().is_err());
            assert!(reader.not_a_tar(), "{bytes:?}");
        }
    }

    #[test]
    fn a_source_that_fails_is_the_hosts_failure_naming_the_archive() {
        // A read the source itself failed, a file's error or a stream's reset,
        // is no refusal of the archive: a caller that retries a transport
        // failure has to be able to see one. It names the archive, and the
        // OS's failure is its cause, whether it comes at the first block or
        // part way through a member, read whole or a buffer at a time.
        let reset = || io::Error::from(io::ErrorKind::ConnectionReset);
        let mut reader = TarReader::new(Failing(reset), "/srv/rootfs.tar");
        let first = reader.next_entry().expect_err("the source fails");
        assert!(!reader.not_a_tar());

        let archive = one_file(3000, &[b'x'; 3000]);
        let cut = || TarReader::new((&archive[..1024]).chain(Failing(reset)), "/srv/rootfs.tar");
        let mut reader = cut();
        reader
            .next_entry()
            .unwrap()
            .expect("the first header reads");
        let whole = reader
            .read_entry(1 << 20)
            .expect_err("the source fails inside the member");
        let mut reader = cut();
        reader
            .next_entry()
            .unwrap()
            .expect("the first header reads");
        let mut buf = [0u8; 4096];
        let piece = reader
            .read_data(&mut buf)
            .expect_err("the source fails inside the member");

        for err in [first, whole, piece] {
            match &err {
                ProvisionError::Io { path, source, .. } => {
                    assert_eq!(path, Path::new("/srv/rootfs.tar"));
                    assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);
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
                path: PathBuf::from("/srv/package.gpkg.tar"),
                offset: 9216,
                reason: "the archive ends inside a member's data".to_string(),
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
        let mut corrupt = Tar::new().file("file.txt", 0o644, b"").finish();
        corrupt[0] = b'X';
        let mut reader = TarReader::in_memory(&corrupt[..]);
        let err = reader
            .next_entry()
            .expect_err("the checksum does not match");
        assert!(
            matches!(&err, ProvisionError::Archive { reason, .. } if *reason == ErrorKind::Checksum.to_string()),
            "{err:?}"
        );
        assert!(
            !reader.not_a_tar(),
            "a corrupt header is still a tar header"
        );

        // A first header that reads, for a member the reader refuses, is a
        // malformed archive too: nothing about it says it is some other format.
        let contradictory = Tar::new()
            .header(b"dir/", b'0', 0o755, 512, 0, b"")
            .body(&[b'x'; 512])
            .finish();
        let mut reader = TarReader::in_memory(&contradictory[..]);
        let err = reader
            .next_entry()
            .expect_err("the member contradicts itself");
        assert!(
            matches!(&err, ProvisionError::Archive { offset: 0, .. }),
            "{err:?}"
        );
        assert!(!reader.not_a_tar());
    }

    #[test]
    fn a_sparse_member_is_refused_where_nothing_extracts_it() {
        // Read through `next_entry`, a sparse member's size and data are the
        // file it stands for, which a reader sizing a read from the entry
        // would hash or hold whole: a member of 2^50 bytes in an archive of a
        // few blocks.
        let mut tar = Tar::new();
        tar.gnu_sparse_file("holes", 0o644, &[(4096, b"data")], 1 << 50);
        tar.file("after", 0o644, b"x");
        let err = TarReader::in_memory(&tar.finish())
            .next_entry()
            .expect_err("the sparse member is refused");
        assert!(
            matches!(&err, ProvisionError::EntryRefused { path, .. } if path == Path::new("holes")),
            "{err:?}",
        );
    }

    #[test]
    fn a_sparse_member_is_read_with_its_map() {
        // GNU's old form, which the strict level reads: its map is the
        // member's, its stored regions are read alone, and its file is read
        // whole with its holes as zeros.
        let mut tar = Tar::new();
        tar.gnu_sparse_file("holes", 0o644, &[(4096, b"data"), (8192, b"more")], 1 << 20);
        tar.file("after", 0o644, b"x");
        let archive = tar.finish();

        let mut reader = TarReader::in_memory(&archive);
        let entry = reader
            .next_entry_with_sparse()
            .expect("it reads")
            .expect("a member");
        let map: Vec<(u64, u64)> = entry
            .sparse()
            .expect("a sparse member")
            .regions()
            .iter()
            .map(|region| (region.offset(), region.length()))
            .collect();
        assert_eq!(map, [(4096, 4), (8192, 4), (1 << 20, 0)]);
        assert_eq!(entry.size(), 1 << 20);
        let mut stored = Vec::new();
        let mut buf = [0u8; 3];
        loop {
            let got = reader.read_stored(&mut buf).expect("the regions read");
            if got == 0 {
                break;
            }
            stored.extend_from_slice(&buf[..got]);
        }
        assert_eq!(stored, b"datamore");
        let after = reader.next_entry().expect("it reads").expect("a member");
        assert_eq!(after.path(), b"after");

        let mut reader = TarReader::in_memory(&archive);
        reader.next_entry_with_sparse().expect("it reads");
        let mut file = Vec::new();
        let mut buf = vec![0u8; 65536];
        loop {
            let got = reader.read_data(&mut buf).expect("the file reads");
            if got == 0 {
                break;
            }
            file.extend_from_slice(&buf[..got]);
        }
        assert_eq!(file.len(), 1 << 20);
        assert_eq!(&file[4096..4100], b"data");
        assert_eq!(&file[8192..8196], b"more");
        assert_eq!(file.iter().filter(|byte| **byte != 0).count(), 8);
    }

    #[test]
    fn a_sparse_map_the_readers_extract_otherwise_is_refused() {
        // Regions out of order: GNU tar and Python extract different files,
        // and bsdtar and Go fail. The refusal names the rule.
        let mut tar = Tar::new();
        tar.gnu_sparse_file("holes", 0o644, &[(8192, b"more"), (4096, b"data")], 1 << 20);
        let err = TarReader::in_memory(&tar.finish())
            .next_entry_with_sparse()
            .expect_err("the map is refused");
        let order = ErrorKind::Sparse(ferrotape::SparseFlaw::Order);
        assert!(
            matches!(&err, ProvisionError::Archive { reason, .. } if *reason == order.to_string()),
            "{err:?}",
        );
    }

    #[test]
    fn a_pax_size_on_an_entry_without_data_is_refused() {
        // GNU tar skips the bytes the record counts, and bsdtar and Python
        // read them as the next header, finding the member `hidden` that GNU
        // tar never sees. Read either way, it is two archives.
        for typeflag in *b"123456" {
            let record = ferroday_cage_testkit::tar::pax_record(b"size", b"1024");
            let mut tar = Tar::new();
            tar.header(b"PaxHeader/entry", b'x', 0o644, record.len() as u64, 0, b"")
                .body(&record)
                .header(b"entry", typeflag, 0o644, 0, 0, b"target")
                .header(b"hidden", b'0', 0o644, 512, 0, b"")
                .body(&[b'h'; 512]);
            let err = TarReader::in_memory(&tar.finish())
                .next_entry()
                .expect_err("the entry contradicts itself");
            assert!(
                matches!(&err, ProvisionError::Archive { offset: 1024, .. }),
                "{}: {err:?}",
                typeflag as char,
            );
        }
        // A pax size of zero states what the type does, and reads.
        let record = ferroday_cage_testkit::tar::pax_record(b"size", b"0");
        let mut tar = Tar::new();
        tar.header(b"PaxHeader/dir", b'x', 0o644, record.len() as u64, 0, b"")
            .body(&record)
            .header(b"dir/", b'5', 0o755, 0, 0, b"");
        let entry = TarReader::in_memory(&tar.finish())
            .next_entry()
            .expect("it reads")
            .expect("a member");
        assert_eq!(entry.path(), b"dir/");
    }

    #[test]
    fn a_terminated_empty_archive_holds_no_entries_and_is_not_an_error() {
        // Two zero blocks are what `tar cf empty.tar --files-from /dev/null`
        // writes, and it is a valid archive of nothing, where a stream that
        // ends before its first block is none.
        let archive = Tar::new().finish();
        let mut reader = TarReader::in_memory(&archive[..]);
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn a_member_is_read_whole_up_to_its_ceiling_and_refused_past_it() {
        let body = vec![b'x'; 3000];
        // At the ceiling exactly, the member is the whole of it, and the reader
        // goes on to the next member from where it ends.
        let archive = one_file(body.len() as u64, &body);
        let mut reader = TarReader::in_memory(&archive[..]);
        reader.next_entry().unwrap().expect("the file");
        assert_eq!(reader.read_entry(body.len() as u64).unwrap(), body);
        assert!(reader.next_entry().unwrap().is_none());
        // One byte under it, the member is refused on its declared length
        // rather than read as far as the ceiling and handed back cut short.
        let mut reader = TarReader::in_memory(&archive[..]);
        reader.next_entry().unwrap().expect("the file");
        let err = reader
            .read_entry(body.len() as u64 - 1)
            .expect_err("a member past its ceiling is refused");
        let past = ErrorKind::EntryLimit {
            size: 3000,
            limit: 2999,
        };
        assert!(
            matches!(&err, ProvisionError::Archive { reason, .. } if *reason == past.to_string()),
            "{err:?}",
        );

        // Declaring more than the archive holds, within the ceiling, the
        // declared length is believed until the bytes run out, and then the
        // read fails: what comes back is a whole member or nothing.
        let mut cut = one_file(1 << 20, &[b'x'; 700]);
        cut.truncate(512 + 700);
        let mut reader = TarReader::in_memory(&cut[..]);
        reader.next_entry().unwrap().expect("the file");
        let err = reader
            .read_entry(1 << 30)
            .expect_err("a member the archive does not hold is refused");
        assert!(
            matches!(&err, ProvisionError::Archive { source: None, .. }),
            "{err:?}"
        );
    }

    /// A reader that answers every other read with `EINTR`, as a pipe or a
    /// socket does in a process whose signal handlers do not restart the call.
    struct Interrupting<R> {
        inner: R,
        interrupt: bool,
    }

    impl<R: Read> Read for Interrupting<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }
            // A short read as well, so a fill has to come back for the rest.
            let short = buf.len().min(100);
            self.inner.read(&mut buf[..short])
        }
    }

    #[test]
    fn an_interrupted_read_is_retried_rather_than_reported() {
        // The member's data is read once and passed over once, and the headers
        // on either side are read too: every read meets the interruption.
        let body = vec![b'x'; 3000];
        let archive = Tar::new()
            .file("entry", 0o644, &body)
            .file("second", 0o644, &[b'y'; 600])
            .finish();
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
        assert_eq!(second.path(), b"second");
        // The second member's data is left unread, so the reader passes over
        // it.
        assert!(
            reader
                .next_entry()
                .expect("passing over retries too")
                .is_none()
        );
        // The end marker's second block is all that follows its first.
        reader
            .finish(512)
            .expect("nothing more follows the archive");
    }
}
