//! The tarball provisioner: a rootfs from a tar archive.

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::extract::{Placement, extract_archive};
use super::tar::TarReader;
use super::{ProvisionError, ProvisionEvent, ProvisionRequest, Provisioner, compress};

/// How often the byte counter reports progress: once per mebibyte consumed.
///
/// Fine enough for a progress bar on a 250 MB stage3 and coarse enough that a
/// small archive reports a handful of times rather than thousands.
const REPORT_EVERY: u64 = 1 << 20;

/// Where a [`Tarball`]'s archive comes from.
enum Source {
    /// A file on the host, opened afresh for each provisioning run.
    Path(PathBuf),
    /// A caller-supplied stream, taken by the first run that uses it.
    Reader(Option<Box<dyn Read + Send>>),
}

/// A rootfs provisioner that extracts a tar archive.
///
/// The archive may be uncompressed or compressed with gzip, xz, or zstd;
/// the format is detected from the stream's content, never a file name. The
/// supported archive dialects are POSIX ustar, GNU, and pax.
///
/// The archive comes either from a path ([`new`](Self::new)) or from any
/// reader ([`from_reader`](Self::from_reader)), so a rootfs fetched over the
/// network is provisioned as it arrives rather than being written to disk
/// first — the mirror image of [`export_tar`](super::export_tar), which writes
/// to any `Write`.
///
/// # Progress and cancellation
///
/// Extraction reports an [`Entry`](ProvisionEvent::Entry) per extracted entry
/// and a [`Read`](ProvisionEvent::Read) as it consumes the source, and it
/// consults the run's cancellation check at each entry boundary. Both reach it
/// through the [`ProvisionRequest`], so they are configured on the publication
/// with [`Provision::observe`](super::Provision::observe) rather than on the
/// provisioner. Byte progress counts the *source* stream, so for a compressed
/// archive it is progress through the compressed bytes; `total` is the file's
/// size for a path source and `None` for a reader, whose length is unknown.
///
/// # Extraction semantics
///
/// Extraction is unprivileged and containment is kernel-enforced: entry
/// paths and hardlink targets resolve strictly beneath the destination
/// (in-tree relative symlinks included), and an entry that reaches outside
/// it — absolute paths, `..`, a symlink chain leading out — fails with
/// [`ProvisionError::EntryUnsafe`] rather than being written.
///
/// - Every extracted entry is owned by the calling user; ownership
///   recorded in the archive is not applied. Inside a sandbox the calling
///   user is mapped to root, so extracted files appear root-owned there.
/// - Permission bits apply verbatim, including setuid, setgid, and sticky
///   bits. Modification times apply from the archive; directory times are
///   applied after their contents so they survive extraction. Because
///   extraction never changes ownership, a preserved setuid or setgid bit
///   grants only the calling user's own authority. The exception is a caller
///   that runs [`ensure`](crate::provision::ensure) as real root and
///   publishes to a location other host users can reach: there a setuid bit
///   from an untrusted archive becomes a setuid-root binary on the host.
///   Extract untrusted archives as an unprivileged user.
/// - Character and block devices are skipped: they cannot be created without
///   privilege, and the sandbox assembles its own minimal `/dev`. FIFOs are
///   extracted; a tar archive has no socket entry type. GNU volume labels,
///   which are archive metadata, are skipped. Extended attributes are not
///   applied.
/// - A later entry for the same path replaces the earlier one, as with
///   tar itself. Sparse and multi-volume members are unsupported and fail
///   with [`ProvisionError::EntryUnsupported`].
///
/// Extraction imposes no size or entry-count quota, so a caller extracting
/// untrusted archives should bound disk usage externally. Decoder memory is
/// bounded, however: a zstd frame declaring a window larger than 128 MiB is
/// refused before decoding, so a compression bomb cannot exhaust memory, and
/// the xz decoder sizes its dictionary fallibly.
pub struct Tarball {
    source: Source,
}

impl Tarball {
    /// A provisioner for the archive at `path`.
    ///
    /// The file is opened afresh on each provisioning run, so one `Tarball`
    /// can provision more than one destination.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Tarball {
            source: Source::Path(path.as_ref().to_path_buf()),
        }
    }

    /// A provisioner for an archive read from `reader`.
    ///
    /// For a rootfs that arrives as a stream — an HTTP response body, a
    /// decompressor, a pipe — so the fetch-and-provision path stays a stream
    /// end to end with no intermediate file. Buffering is the provisioner's:
    /// the reader is wrapped before the format is sniffed, so an unbuffered
    /// source needs no `BufReader` of its own. The reader is bounded `Send`,
    /// because a `Tarball` stores it and so must stay movable between threads.
    ///
    /// A stream can be read only once, so the reader is consumed by the first
    /// run; a second run against the same `Tarball` fails rather than
    /// provisioning an empty rootfs. Use [`new`](Self::new) for a source that
    /// provisions repeatedly.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use ferroday_cage::provision::{self, Tarball};
    ///
    /// # fn fetch(url: &str) -> std::io::Result<std::fs::File> { unimplemented!() }
    /// let body = fetch("https://example.invalid/alpine-minirootfs.tar.gz")?;
    /// provision::ensure("/var/cache/myapp/alpine", &mut Tarball::from_reader(body))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_reader(reader: impl Read + Send + 'static) -> Self {
        Tarball {
            source: Source::Reader(Some(Box::new(reader))),
        }
    }
}

impl fmt::Debug for Tarball {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Tarball");
        match &self.source {
            Source::Path(path) => debug.field("path", path),
            Source::Reader(reader) => debug.field("reader", &reader.is_some()),
        }
        .finish()
    }
}

impl Provisioner for Tarball {
    fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
        // The name a failure is reported against: the archive's path, or a
        // stand-in for a stream that has none.
        let subject: PathBuf = match &self.source {
            Source::Path(path) => path.clone(),
            Source::Reader(_) => PathBuf::from("<reader>"),
        };

        let (reader, total): (Box<dyn Read + Send>, Option<u64>) = match &mut self.source {
            Source::Path(path) => {
                let file =
                    File::open(&*path).map_err(|err| ProvisionError::io("opening", &*path, err))?;
                let total = file.metadata().ok().map(|meta| meta.len());
                (Box::new(file), total)
            }
            Source::Reader(reader) => {
                let reader = reader.take().ok_or_else(|| {
                    ProvisionError::other(
                        "this Tarball's reader was consumed by an earlier provisioning run; \
                         a stream can be extracted only once",
                    )
                })?;
                (reader, None)
            }
        };

        let counted = Counting {
            inner: reader,
            request,
            total,
            done: 0,
            reported: 0,
        };
        let mut source = BufReader::with_capacity(64 * 1024, counted);

        // Sniff the compression from the leading magic bytes, then hand the
        // full stream (head included) to the chosen decoder.
        let head = compress::sniff_head(&mut source)
            .map_err(|err| ProvisionError::io("reading", &subject, err))?;
        let decoded = compress::decompress(&head, source)?;

        let mut archive = TarReader::new(BufReader::with_capacity(64 * 1024, decoded));
        let outcome = extract_archive(&mut archive, request.staging(), &mut |_, components| {
            // An entry boundary: what has been written is complete, and
            // `ensure` discards the staging tree wholesale, so stopping here
            // leaves nothing half-extracted behind.
            if request.cancelled() {
                return Err(ProvisionError::Cancelled);
            }
            let mut path = PathBuf::new();
            for component in components {
                path.push(OsStr::from_bytes(component));
            }
            request.report(ProvisionEvent::Entry { path: &path });
            // A tarball provisioner unpacks what the archive holds and keeps no
            // record to hold it to, so every entry is written.
            Ok(Placement::Write)
        });
        match outcome {
            Ok(()) => Ok(()),
            // A stream whose very first block is not a tar header is not
            // a tar archive at all.
            Err(ProvisionError::Archive { .. }) if archive.rejected_at_start() => {
                Err(ProvisionError::FormatUnrecognized { path: subject })
            }
            Err(err) => Err(err),
        }
    }
}

/// A reader that counts what passes through it and reports progress.
///
/// Wrapped around the *source* stream rather than the decoded one, so the
/// count is progress through the archive as it exists on disk or on the wire —
/// the number a caller can compare against a known total.
struct Counting<'a, 'r> {
    inner: Box<dyn Read + Send>,
    request: &'a ProvisionRequest<'r>,
    total: Option<u64>,
    done: u64,
    /// The count at the last report, so reporting stays coarse.
    reported: u64,
}

impl Counting<'_, '_> {
    /// Reports the current count, unless it has already been reported.
    fn flush(&mut self) {
        if self.done != self.reported {
            self.reported = self.done;
            self.request.report(ProvisionEvent::Read {
                done: self.done,
                total: self.total,
            });
        }
    }
}

impl Read for Counting<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.done += read as u64;
        if self.done - self.reported >= REPORT_EVERY {
            self.flush();
        }
        Ok(read)
    }
}

impl Drop for Counting<'_, '_> {
    /// The final report. A tar stream ends at its end-of-archive marker rather
    /// than at end-of-file, so the last read is often never issued and the
    /// tail of the count would otherwise go unreported; dropping the reader is
    /// the one moment that always arrives, on a completed extraction and a
    /// failed one alike.
    fn drop(&mut self) {
        self.flush();
    }
}
