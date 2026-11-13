//! The package cache: where a run's downloads land, how they arrive there, and
//! how they are read back.
//!
//! Every archive layer keeps what it downloads in a directory that may outlive
//! the run and may be shared with other runs: the `cache_dir` a caller names on
//! the layer's builder, or a sibling of the tree being built ([`PackageCache`]). What is in such a directory is bytes on
//! a disk this crate does not own, so the three layers keep one discipline over
//! it, and this module is that discipline stated once.
//!
//! # Filling it
//!
//! [`download`] fetches one entry from the first of a list of mirrors that
//! serves it, and [`prefetch`] fetches several at once where the transport can.
//! Both stream the body into a [`Staged`] file beside the entry, so nothing is
//! ever held whole in memory and nothing incomplete is ever visible at the
//! entry's name. A staging file a killed run left behind is removed the next
//! time the cache is [created](create). The body is held to the size the entry may hold, where one is
//! known, as it arrives. Once it is complete, the caller's own check reads it
//! back through the descriptor that wrote it, and only a body the check accepts
//! is published by the rename. Nothing unverified is ever at an entry's name,
//! so another run reading the cache never meets bytes this one has not checked.
//!
//! The check is the layer's, and is the same one a cache hit goes through: a
//! digest against the index for a `.deb` or a stage3, the control identity and
//! the package's own fields for an `.apk`, the signed Manifest and the identity
//! inside for a binary package. Whichever produced a file, a download or an
//! earlier run, one check decides whether it is the package.
//!
//! # Reading it back
//!
//! [`open_entry`] opens what the cache holds at a name without following a
//! symbolic link there and without waiting on a named pipe, and refuses anything
//! that is not a regular file. An entry held below directories of the cache's
//! own has that chain made by `create_within`, which refuses a link at any
//! directory of it, so a link planted at one is refused rather than followed out
//! of the cache too. A cache is a tree that is not fully trusted, so
//! its entries are opened as [`Rooted`] opens any such tree's files.
//!
//! # Failing
//!
//! A download fails in one of four ways, which [`Failure`] keeps apart: the
//! mirror could not serve it, the check refused what arrived, the run was
//! cancelled, or a host operation on the cache failed. Only the first advances
//! a walk over mirrors. The last is [`ProvisionError::Io`] whichever layer asked,
//! as is a cache directory that cannot be created ([`create`]): neither is about
//! a format, so neither is a layer's error.

use std::fs::{self, File};
use std::io::{self, BufWriter, Seek, Write};
use std::path::{Path, PathBuf};

use super::fetch::Watch;
use super::rooted::Rooted;
use super::{
    Failover, Fetch, FetchError, FetchJob, FetchRequest, LimitedWriter, ProvisionError, Staged,
    remove_tree, walk_mirrors,
};

/// The directory a run downloads its packages into, and whether the run owns it.
///
/// A caller that names a cache directory owns it: it survives the run, which is
/// the whole point of naming one. A run that names none downloads into a derived
/// sibling of the tree it is building, and that directory is the run's own.
///
/// A derived cache is removed when the value is dropped rather than at the end
/// of the successful path, so a failure disposes of it exactly as a success
/// does. Every `?` between creating the cache and finishing the bootstrap would
/// otherwise leave a base system's worth of packages beside a rootfs that was
/// never published, and nothing later clears it: the publication's own cleanup
/// removes the staging tree, and [`remove`](super::remove) removes the
/// destination and its lock, neither of which this is.
pub(crate) struct PackageCache {
    path: PathBuf,
    owned: bool,
}

impl PackageCache {
    /// The cache for a run building `tree`: the caller's, or a sibling of the
    /// tree named after it with `suffix`.
    ///
    /// A sibling, not a child: an extracted package's entries land under the
    /// tree, so a cache beneath it could be overwritten before it is read, but a
    /// sibling is out of the extraction's contained reach.
    ///
    /// The suffix is the layer's, so two provisioners building one destination
    /// do not each dispose of the other's downloads.
    pub(crate) fn beside(tree: &Path, cache_dir: Option<&Path>, suffix: &str) -> PackageCache {
        match cache_dir {
            Some(dir) => PackageCache {
                path: dir.to_path_buf(),
                owned: false,
            },
            None => PackageCache {
                path: PackageCache::derived(tree, suffix),
                owned: true,
            },
        }
    }

    /// The directory a run building `tree` derives for itself, and removes,
    /// when the caller names none: the sibling of the tree named after it with
    /// `suffix`.
    ///
    /// Composed from the tree's parent and its final component, as an overlay
    /// upper's work directory is (`spec::overlay_work_dir`), rather than by
    /// appending to the path as it was spelled: `/srv/upper/` names the tree
    /// `/srv/upper`, and appending would derive `/srv/upper/.fcage-debs`, a
    /// directory inside it. A tree spelled with no final component, such as
    /// `.`, is named by its canonical path. The root directory has no sibling,
    /// and its cache is the root followed by the suffix.
    ///
    /// Answered on its own so a caller can tell whether a directory it was
    /// handed is that one, which the run would remove as its own; see
    /// `is_derived`, which asks it of the directory rather than of a spelling.
    pub(crate) fn derived(tree: &Path, suffix: &str) -> PathBuf {
        let sibling = |tree: &Path| {
            let (parent, name) = (tree.parent()?, tree.file_name()?);
            let mut name = name.to_os_string();
            name.push(suffix);
            Some(parent.join(name))
        };
        sibling(tree)
            .or_else(|| fs::canonicalize(tree).ok().as_deref().and_then(sibling))
            .unwrap_or_else(|| {
                let mut inside = tree.as_os_str().to_os_string();
                inside.push(suffix);
                PathBuf::from(inside)
            })
    }

    /// Whether `dir` is the directory [`derived`](Self::derived) names for
    /// `tree`, the one a run would remove as its own.
    ///
    /// Asked of the directories rather than of their spellings, by device and
    /// inode: `./root.fcage-debs` and `root.fcage-debs` name one directory, as
    /// does a path through a symbolic link, and a comparison of the paths calls
    /// them two. A run that took a caller's cache for a directory of its own
    /// would remove it. Where either does not exist they are not one directory.
    ///
    /// Only the Debian layer copies out of a caller's cache, so only it asks.
    #[cfg(feature = "debian")]
    pub(crate) fn is_derived(tree: &Path, suffix: &str, dir: &Path) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        match (
            fs::metadata(PackageCache::derived(tree, suffix)),
            fs::metadata(dir),
        ) {
            (Ok(own), Ok(dir)) => own.dev() == dir.dev() && own.ino() == dir.ino(),
            _ => false,
        }
    }

    /// The directory itself, to download into and to read back from.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PackageCache {
    fn drop(&mut self) {
        if self.owned {
            // Best effort, as a drop must be. The cache holds what the run
            // downloaded, all of it the calling user's own.
            let _ = remove_tree(&self.path, &crate::IdentityMap::Single, None);
        }
    }
}

/// Creates the cache directory `path`, and any directory above it that is
/// missing, and sweeps it of the staging files nothing is writing.
///
/// A run killed outright leaves the download it was writing as a hidden
/// staging file beside the entry, and the next run to use the cache is the one
/// that can tell it is nobody's: [`Staged::sweep`].
///
/// # Errors
///
/// Returns [`ProvisionError::Io`] naming the directory. A cache that cannot be
/// created is a host failure whichever layer's cache it is.
pub(crate) fn create(path: &Path) -> Result<(), ProvisionError> {
    fs::create_dir_all(path)
        .map_err(|err| ProvisionError::io("creating the package cache", path, err))?;
    Staged::sweep(path);
    Ok(())
}

/// The mode a directory [`create_within`] makes is left at, stated rather than
/// left to the umask, as a tree's own directories are.
#[cfg(feature = "gentoo")]
const DIR_MODE: u32 = 0o755;

/// Creates the directory `dir` below the package cache `cache`, and every
/// directory between them that is missing, refusing a symbolic link at any of
/// them; and sweeps `dir` as [`create`] sweeps a cache. The cache itself is
/// created where it is missing, as [`create`] creates it.
///
/// For an entry a cache holds below directories of its own: a Gentoo binary
/// package, under the binhost's path. The cache is the caller's, and may be
/// reached through a link. Nothing below it is, so a link at a directory of
/// the chain fails the call, rather than being followed out of the cache by
/// the download into it and the read back out of it. The chain is resolved
/// from a descriptor of the cache, with every link refused.
///
/// # Errors
///
/// Returns [`ProvisionError::Io`] naming `dir`: for a link in the chain,
/// `ELOOP`, and for a `dir` that is not below `cache`, `EINVAL`.
#[cfg(feature = "gentoo")]
pub(crate) fn create_within(cache: &Path, dir: &Path) -> Result<(), ProvisionError> {
    use std::os::fd::AsFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    use rustix::fs::{Mode, OFlags, ResolveFlags};
    use rustix::io::Errno;

    let fail = |errno: Errno| ProvisionError::io("creating the package cache", dir, errno.into());
    let components = dir
        .strip_prefix(cache)
        .ok()
        .and_then(|below| {
            crate::path::tree_components(
                below.as_os_str().as_bytes(),
                crate::path::LeadingSlash::Refused,
            )
            .ok()
        })
        .ok_or_else(|| fail(Errno::INVAL))?;
    fs::create_dir_all(cache)
        .map_err(|err| ProvisionError::io("creating the package cache", cache, err))?;
    let root = rustix::fs::open(
        cache,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(fail)?;
    super::containment::create_dirs(
        root.as_fd(),
        &components,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        &mut |made| rustix::fs::fchmod(made.dir, Mode::from_raw_mode(DIR_MODE)),
    )
    .map_err(fail)?;
    Staged::sweep(dir);
    Ok(())
}

/// Opens the cache entry at `path` for reading.
///
/// The entry is looked at before it is opened, without following it, and only
/// a regular file is opened: a symbolic link planted at the name is refused
/// rather than followed out of the cache, and a named pipe, which an ordinary
/// open would wait on until something opened its other end, is refused without
/// being opened at all. The open is [`Rooted::reader`]'s, with the cache
/// directory as the tree, so this is the same answer every host-side read of a
/// tree that is not fully trusted gets.
///
/// # Errors
///
/// An entry that is absent is [`io::ErrorKind::NotFound`]; anything that is not
/// a regular file, or that was replaced between the look and the open, is
/// refused with an error naming it.
pub(crate) fn open_entry(path: &Path) -> io::Result<File> {
    let Some(name) = path.file_name() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} names no cache entry", path.display()),
        ));
    };
    Rooted::open(crate::path::parent_of(path))?.reader(name)
}

/// A cache entry a download fills: where it is published, and the most its body
/// may hold.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry<'a> {
    /// The entry's path in the cache.
    pub(crate) path: &'a Path,
    /// The size a verified source stated for the body, or the layer's own
    /// ceiling for it; `None` where nothing bounds it but the transport.
    ///
    /// It travels with the request, so a transport that honours it refuses an
    /// oversized framing before reading a byte, and it bounds the sink, because
    /// a transport of the caller's is free to ignore the request and the sink is
    /// the one place the bound cannot be ignored.
    pub(crate) size: Option<u64>,
}

/// Why a download did not publish its entry.
#[derive(Debug)]
pub(crate) enum Failure<E> {
    /// The mirror could not serve the body. The one failure a walk over
    /// mirrors advances past, where [`FetchError::is_failover`] says so.
    Fetch(FetchError),
    /// The body arrived and the layer's check refused it.
    Refused(E),
    /// The run was cancelled while the download was under way.
    Cancelled,
    /// A host operation on the cache failed: staging the body, writing it,
    /// reading it back, or publishing it.
    Io(ProvisionError),
}

impl<E> Failover for Failure<E> {
    /// Only a transport failure the transport calls the mirror's state. A body
    /// that arrived and was refused, a cancellation, and a failure on this
    /// host's own disk are each the same whichever mirror is asked next.
    fn is_failover(&self) -> bool {
        matches!(self, Failure::Fetch(err) if err.is_failover())
    }
}

impl<E: From<FetchError>> Failure<E> {
    /// The failure as the provisioning error a caller is shown, `wrap`
    /// surfacing the layer's own.
    ///
    /// A cancellation is the run's own outcome, and a host failure on the
    /// cache is the shared [`ProvisionError::Io`]; the other two are the
    /// layer's, a transport failure included, since a layer reports the mirror
    /// it was walking in its own terms.
    pub(crate) fn into_provision(self, wrap: impl FnOnce(E) -> ProvisionError) -> ProvisionError {
        match self {
            Failure::Fetch(err) => wrap(E::from(err)),
            Failure::Refused(err) => wrap(err),
            Failure::Cancelled => ProvisionError::Cancelled,
            Failure::Io(err) => err,
        }
    }
}

/// How large a buffer a body is written through.
///
/// A transport writes whatever its own reads deliver, which for a socket is
/// often a few kilobytes at a time; this turns those into fewer, larger writes
/// to the staging file.
const WRITE_BUFFER: usize = 64 * 1024;

/// The sink a body is written into: held to its size, then the staging file's
/// failures recorded, then buffered onto the staging file.
type Sink<'f> = LimitedWriter<Recording<BufWriter<&'f mut File>>>;

/// The sink a body is written into: buffered onto the staging file, keeping the
/// first failure the file reports, and failing the write that would carry it
/// past `size`.
fn sink(file: &mut File, size: Option<u64>) -> Sink<'_> {
    LimitedWriter::new(
        Recording {
            inner: BufWriter::with_capacity(WRITE_BUFFER, file),
            failed: None,
        },
        size.unwrap_or(u64::MAX),
    )
}

/// The staging file's writer, keeping the first failure it reports.
///
/// A body's writes run inside the transport, which meets a failure to write the
/// staging file as one more write failure and reports it as its own. That is a
/// [`FetchError`], which a walk over mirrors advances past: a full disk would be
/// asked of every mirror in turn, each downloading as much as fits, and the
/// failure reported would blame the last of them. What the disk said is
/// therefore recorded here, as it happens, for the reason [`Stoppable`]
/// records a cancellation, and reported as the host failure it is.
///
/// It sits beneath the [`LimitedWriter`], which refuses a body past its size
/// before the bytes reach here. That refusal is the mirror's, and stays a
/// transport failure.
struct Recording<W> {
    inner: W,
    /// The first failure the writer beneath reported.
    failed: Option<io::Error>,
}

impl<W> Recording<W> {
    /// Keeps `err` as the file's failure, if it is the first, and answers the
    /// copy the transport is handed in its place.
    ///
    /// `Interrupted` is not kept. It asks for the write to be made again, which
    /// `write_all` and `io::copy` do, so it is not a failure of the file.
    fn record(&mut self, err: io::Error) -> io::Error {
        if err.kind() == io::ErrorKind::Interrupted {
            return err;
        }
        let copy = match err.raw_os_error() {
            Some(code) => io::Error::from_raw_os_error(code),
            None => io::Error::new(err.kind(), err.to_string()),
        };
        self.failed.get_or_insert(err);
        copy
    }
}

impl<W: Write> Write for Recording<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf).map_err(|err| self.record(err))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().map_err(|err| self.record(err))
    }
}

/// What the staging file made of a body once the transport has finished with
/// it: the first write the file refused while the body arrived, or, for a body
/// that `arrived` whole, the outcome of writing what is still buffered.
///
/// The buffered tail is discarded rather than written where the file has
/// already refused a write, or where the body did not arrive. Neither is
/// published, and the staging file goes with it.
fn finish(sink: Sink<'_>, arrived: bool) -> io::Result<()> {
    let Recording { inner, failed } = sink.into_inner();
    match failed {
        Some(failed) => {
            drop(inner.into_parts());
            Err(failed)
        }
        None if arrived => flush(inner),
        None => {
            drop(inner.into_parts());
            Ok(())
        }
    }
}

/// A request for `url`, stating `size` where one is known.
fn request(url: &str, size: Option<u64>) -> FetchRequest<'_> {
    let request = FetchRequest::new(url);
    match size {
        Some(size) => request.sized(size),
        None => request,
    }
}

/// Writes what is still buffered, reporting a failure the buffer's own `Drop`
/// would swallow.
///
/// A body whose tail never reached the disk would otherwise be checked as a
/// short file and refused as the wrong package: an authenticity answer to a
/// local write failure, which is the wrong thing to tell a caller and the wrong
/// thing for them to act on.
fn flush(buffered: BufWriter<&mut File>) -> io::Result<()> {
    buffered
        .into_inner()
        .map(|_| ())
        .map_err(io::IntoInnerError::into_error)
}

/// A sink that stops accepting bytes once the run has been cancelled.
///
/// A download is where a run spends its time, and a stage3 is a single file of
/// several hundred megabytes, so a check made only between mirrors or between
/// packages would answer a caller who asked to stop once the whole body had
/// arrived. Asking on every write is what stops one part way.
///
/// The stop is recorded here rather than read back out of the [`io::Error`] the
/// transport returns: a [`Fetch`] implementation is a caller's own and may
/// report a failed write however it likes, and a stop is something this crate
/// knows first-hand. So is a failure of the staging file, which [`Recording`]
/// keeps the same way.
struct Stoppable<'a, S, W: ?Sized> {
    inner: S,
    watch: &'a mut W,
    stopped: bool,
}

impl<S: Write, W: Watch + ?Sized> Write for Stoppable<'_, S, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.watch.cancelled() {
            self.stopped = true;
            // Not `Interrupted`, which `io::copy` and `write_all` retry: a
            // cancellation is the one write failure that must not be retried.
            return Err(io::Error::other("the run was cancelled"));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Downloads `entry` from the first of `mirrors` that serves it, publishing
/// what `verify` accepts.
///
/// `url_of` composes each mirror's URL for the entry. A mirror that
/// [could not serve it](FetchError::is_failover) advances the walk, and the last
/// such failure is reported once none is left; `unserved` supplies the failure
/// for a list with no mirror in it. Nothing else advances the walk: a body that
/// arrives and is refused was answered for by the URL that was asked for, and
/// asking elsewhere would hide that.
///
/// `watch` is asked at every mirror and on every write of the body, so a
/// cancelled run stops part way through it, and the partial body goes with the
/// staging file. It hears each URL as it is fetched.
///
/// `verify` is the layer's check, handed the complete body rewound to its
/// start, with the URL it came from and the watch. What it returns is what the
/// call returns once the entry is published: the descriptor it read through,
/// typically, so the caller reads on from the bytes that were checked rather
/// than opening the name again.
///
/// # Errors
///
/// Returns [`Failure`] for whichever step failed. On every failure the staging
/// file is removed and the entry is left as it was.
pub(crate) fn download<M, T, E, W: Watch + ?Sized>(
    fetcher: &mut dyn Fetch,
    mirrors: &[M],
    url_of: impl Fn(&M) -> String,
    entry: Entry<'_>,
    watch: &mut W,
    mut verify: impl FnMut(File, &str, &mut W) -> Result<T, E>,
    unserved: impl FnOnce() -> FetchError,
) -> Result<T, Failure<E>> {
    walk_mirrors(
        mirrors,
        |mirror| {
            if watch.cancelled() {
                return Err(Failure::Cancelled);
            }
            let url = url_of(mirror);
            watch.fetching(&url);
            fetch(fetcher, &url, entry, watch, |file, watch| {
                verify(file, &url, watch)
            })
        },
        || Failure::Fetch(unserved()),
    )
}

/// Downloads one URL into `entry`, publishing what `verify` accepts.
fn fetch<T, E, W: Watch + ?Sized>(
    fetcher: &mut dyn Fetch,
    url: &str,
    entry: Entry<'_>,
    watch: &mut W,
    verify: impl FnOnce(File, &mut W) -> Result<T, E>,
) -> Result<T, Failure<E>> {
    let (staged, mut file) = Staged::beside(entry.path)
        .map_err(|err| Failure::Io(ProvisionError::io("staging a download of", entry.path, err)))?;

    let (fetched, stopped, written) = {
        let mut body = Stoppable {
            inner: sink(&mut file, entry.size),
            watch: &mut *watch,
            stopped: false,
        };
        let fetched = fetcher.fetch(&request(url, entry.size), &mut body);
        let written = finish(body.inner, fetched.is_ok());
        (fetched, body.stopped, written)
    };

    // A stopped write reaches the transport as a write failure, which is what
    // the sink has to answer it with. What it means is the run's own outcome,
    // and reporting it as a transport failure would send a walk to the next
    // mirror to do the same thing again.
    if stopped {
        return Err(Failure::Cancelled);
    }
    // The same holds for a write the staging file refused, which comes back
    // from the transport as the transport's failure: it is this host's disk,
    // and the next mirror would meet it too. So it is answered before the
    // transport's outcome is.
    written.map_err(|err| {
        Failure::Io(ProvisionError::io(
            "writing a download to",
            staged.path(),
            err,
        ))
    })?;
    fetched.map_err(Failure::Fetch)?;
    file.rewind().map_err(|err| {
        Failure::Io(ProvisionError::io(
            "reading back a download at",
            staged.path(),
            err,
        ))
    })?;
    let verified = verify(file, watch).map_err(Failure::Refused)?;
    staged.publish().map_err(|err| {
        Failure::Io(ProvisionError::io(
            "publishing a download at",
            entry.path,
            err,
        ))
    })?;
    Ok(verified)
}

/// How many downloads one batch asks for.
///
/// Each job holds its staging file open for as long as the batch runs, through
/// two descriptors: the one its body is written through, and the one its lock
/// is held on ([`Staged`]). So this is a bound on descriptors, at twice its
/// value, rather than on the transport, which decides for itself how many of a
/// batch to have in flight. It is also the granularity a cancelled run stops at
/// within a batch's downloads, which is the reason it is not larger.
const BATCH: usize = 16;

/// One download of a batch: the URL to fetch, and the entry it fills.
#[derive(Debug)]
pub(crate) struct Job<'a> {
    /// The URL, on the first mirror that would be asked for the entry.
    pub(crate) url: String,
    /// The entry the body fills.
    pub(crate) entry: Entry<'a>,
}

/// Fills the cache with `jobs`, [`BATCH`] at a time, through
/// [`Fetch::fetch_all`], publishing each body `verify` accepts.
///
/// Answers, per job and in order, what `verify` made of it, or `None` where the
/// job did not arrive or did not verify. Neither fails the call: this is an
/// optimization over [`download`] and nothing more, and a job it does not
/// deliver is the walk's, which has every mirror rather than the first. What is
/// published is exactly what the walk would have published, a body that arrived
/// complete within its size and that `verify` accepted; `verify` is handed it
/// rewound, with the job's index.
///
/// A host operation on the cache that fails ends the call instead: creating a
/// job's staging file, writing it, reading it back, or publishing it. Each is
/// this host's disk, the same whichever mirror the walk asks, so leaving the
/// job to the walk would only meet the failure again there. A full disk would
/// download as much of every job as fits and fail anyway, and a staging file
/// the host cannot create would be reported against a package rather than as
/// what it is.
///
/// `watch` hears each URL as its job is staged, and is asked before each batch.
/// It is not asked while a batch's bodies arrive: a transport that fetches
/// several at once writes each body from a thread of its own, and a watch is a
/// layer's observer, which only the thread that called into the provisioner
/// may ask. A cancelled run therefore stops at a batch boundary, which
/// [`BATCH`] bounds, and a body that arrived is still checked before it is
/// published.
///
/// # Errors
///
/// Returns [`Failure::Cancelled`] where the run was cancelled before a batch.
/// Returns [`Failure::Io`] where a job's staging file refused a write, once the
/// batch it was in has finished, and nothing of that batch is published; and
/// where a job's staging file could not be created, read back, or published, as
/// it fails.
pub(crate) fn prefetch<T, E, W: Watch + ?Sized>(
    fetcher: &mut dyn Fetch,
    jobs: &[Job<'_>],
    watch: &mut W,
    mut verify: impl FnMut(usize, File) -> Result<T, E>,
) -> Result<Vec<Option<T>>, Failure<E>> {
    let mut verified = Vec::with_capacity(jobs.len());
    for batch in jobs.chunks(BATCH) {
        if watch.cancelled() {
            return Err(Failure::Cancelled);
        }
        let mut staged: Vec<(Staged, File)> = Vec::with_capacity(batch.len());
        for job in batch {
            watch.fetching(&job.url);
            staged.push(Staged::beside(job.entry.path).map_err(|err| {
                Failure::Io(ProvisionError::io(
                    "staging a download of",
                    job.entry.path,
                    err,
                ))
            })?);
        }

        // Whether each job's body arrived whole and reached the disk, and the
        // first job whose staging file refused a write.
        let mut arrived = vec![false; batch.len()];
        let mut refused = None;
        {
            let mut sinks: Vec<(usize, Sink<'_>)> = staged
                .iter_mut()
                .enumerate()
                .map(|(at, (_, file))| (at, sink(file, batch[at].entry.size)))
                .collect();
            let outcomes = {
                let mut fetching: Vec<FetchJob<'_>> = sinks
                    .iter_mut()
                    .map(|(at, sink)| {
                        let job = &batch[*at];
                        FetchJob::new(request(&job.url, job.entry.size), sink)
                    })
                    .collect();
                fetcher.fetch_all(&mut fetching)
            };
            for ((at, sink), outcome) in sinks.into_iter().zip(outcomes) {
                match finish(sink, outcome.is_ok()) {
                    Ok(()) => arrived[at] = outcome.is_ok(),
                    Err(err) => {
                        refused.get_or_insert((at, err));
                    }
                }
            }
        }

        // A write the staging file refused is this host's disk rather than
        // the job's mirror, so the walk would meet it at its first mirror. The
        // batch stops here rather than leaving each job to find that out, and
        // every staging file of the batch goes unpublished.
        if let Some((at, err)) = refused {
            return Err(Failure::Io(ProvisionError::io(
                "writing a download to",
                staged[at].0.path(),
                err,
            )));
        }

        // A job that did not arrive, or that its check refuses, drops its
        // staging file here, unpublished.
        let first = verified.len();
        for ((at, (staged, mut file)), arrived) in staged.into_iter().enumerate().zip(arrived) {
            if !arrived {
                verified.push(None);
                continue;
            }
            file.rewind().map_err(|err| {
                Failure::Io(ProvisionError::io(
                    "reading back a download at",
                    staged.path(),
                    err,
                ))
            })?;
            let Ok(checked) = verify(first + at, file) else {
                verified.push(None);
                continue;
            };
            staged.publish().map_err(|err| {
                Failure::Io(ProvisionError::io(
                    "publishing a download at",
                    batch[at].entry.path,
                    err,
                ))
            })?;
            verified.push(Some(checked));
        }
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    use crate::scratch::Scratch;

    /// A transport that serves one fixed body to whatever it is asked for, in
    /// writes of `chunk` bytes, counting what it was asked for.
    struct Canned {
        body: Vec<u8>,
        chunk: usize,
        asked: Vec<String>,
    }

    impl Canned {
        fn new(body: &[u8]) -> Canned {
            Canned {
                body: body.to_vec(),
                chunk: usize::MAX,
                asked: Vec::new(),
            }
        }
    }

    impl Fetch for Canned {
        fn fetch(
            &mut self,
            request: &FetchRequest<'_>,
            sink: &mut dyn Write,
        ) -> Result<(), FetchError> {
            self.asked.push(request.url().to_string());
            if request.url().contains("missing") {
                return Err(FetchError::not_found(request.url()));
            }
            for chunk in self.body.chunks(self.chunk.max(1)) {
                sink.write_all(chunk)
                    .map_err(|err| FetchError::io("writing the body", request.url(), err))?;
            }
            Ok(())
        }
    }

    /// A watch that records what it heard and cancels once asked `allowed`
    /// times.
    struct Watching {
        fetched: Vec<String>,
        asked: usize,
        allowed: usize,
    }

    impl Watching {
        fn patient() -> Watching {
            Watching {
                fetched: Vec::new(),
                asked: 0,
                allowed: usize::MAX,
            }
        }
    }

    impl Watch for Watching {
        fn fetching(&mut self, url: &str) {
            self.fetched.push(url.to_string());
        }

        fn cancelled(&mut self) -> bool {
            self.asked += 1;
            self.asked > self.allowed
        }
    }

    /// A check that accepts a body equal to `want`, handing back its bytes.
    fn holding(want: &[u8]) -> impl FnMut(File, &str, &mut Watching) -> Result<Vec<u8>, String> {
        let want = want.to_vec();
        move |mut file, _url, _watch| {
            let mut held = Vec::new();
            file.read_to_end(&mut held).map_err(|err| err.to_string())?;
            if held == want {
                Ok(held)
            } else {
                Err("not the package".to_string())
            }
        }
    }

    /// The names a directory holds, sorted.
    fn entries_of(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("the directory is readable")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn mirrors() -> Vec<String> {
        vec![
            "http://missing.example".to_string(),
            "http://serves.example".to_string(),
        ]
    }

    /// Two mirrors that both serve the entry, so a walk that reaches the second
    /// shows it advanced past the first.
    fn serving_mirrors() -> Vec<String> {
        vec![
            "http://first.example".to_string(),
            "http://second.example".to_string(),
        ]
    }

    fn unserved() -> FetchError {
        FetchError::not_found("the entry")
    }

    #[test]
    fn a_download_publishes_only_what_its_check_accepts() {
        // The body is written to a staging file as it arrives and checked
        // through that file's descriptor, so nothing unverified is ever visible
        // at the entry: the rename is what puts it there, and it follows the
        // check.
        let dir = Scratch::new("cache-verified");
        let path = dir.join("package");
        let entry = Entry {
            path: &path,
            size: None,
        };

        let mut fetcher = Canned::new(b"not what the archive recorded");
        let refused = download(
            &mut fetcher,
            &mirrors(),
            |mirror| format!("{mirror}/package"),
            entry,
            &mut Watching::patient(),
            holding(b"the recorded bytes"),
            unserved,
        )
        .expect_err("a body the check refuses is not published");
        assert!(matches!(refused, Failure::Refused(_)), "{refused:?}");
        assert!(
            entries_of(&dir).is_empty(),
            "left behind: {:?}",
            entries_of(&dir)
        );
        // The first mirror did not serve it and the second served the wrong
        // bytes; the walk advanced past the first and stopped at the second.
        assert_eq!(
            fetcher.asked,
            [
                "http://missing.example/package",
                "http://serves.example/package"
            ],
        );

        let mut watch = Watching::patient();
        let held = download(
            &mut Canned::new(b"the recorded bytes"),
            &mirrors(),
            |mirror| format!("{mirror}/package"),
            entry,
            &mut watch,
            holding(b"the recorded bytes"),
            unserved,
        )
        .expect("a body the check accepts is published");
        assert_eq!(held, b"the recorded bytes");
        assert_eq!(fs::read(&path).unwrap(), b"the recorded bytes");
        assert_eq!(entries_of(&dir), ["package"]);
        assert_eq!(
            watch.fetched,
            [
                "http://missing.example/package",
                "http://serves.example/package"
            ],
        );
    }

    #[test]
    fn a_download_stops_at_the_size_its_entry_may_hold() {
        // The size travels with the request, and a transport is free to ignore
        // it, so it bounds the sink as well: a body past it is refused as it
        // arrives, as a transport failure, and the disk it would have filled is
        // never written.
        let dir = Scratch::new("cache-capped");
        let path = dir.join("package");
        let body = [b'x'; 4096];
        let mut fetcher = Canned::new(&body);
        let err = download(
            &mut fetcher,
            &serving_mirrors(),
            |mirror| format!("{mirror}/package"),
            Entry {
                path: &path,
                size: Some(16),
            },
            &mut Watching::patient(),
            holding(&body),
            unserved,
        )
        .expect_err("a body over the size is refused");
        assert!(
            matches!(&err, Failure::Fetch(FetchError::Io { .. })),
            "{err:?}"
        );
        // A body past its size is what that mirror served, so the walk asks
        // the next one.
        assert_eq!(fetcher.asked.len(), 2, "{:?}", fetcher.asked);
        assert!(
            entries_of(&dir).is_empty(),
            "left behind: {:?}",
            entries_of(&dir)
        );

        // At the size exactly, it is accepted.
        download(
            &mut Canned::new(&body),
            &["http://serves.example".to_string()],
            |mirror| format!("{mirror}/package"),
            Entry {
                path: &path,
                size: Some(body.len() as u64),
            },
            &mut Watching::patient(),
            holding(&body),
            unserved,
        )
        .expect("a body at its size is published");
    }

    #[test]
    fn a_cancelled_download_stops_part_way_through_the_body() {
        // The watch is asked at the mirror and on every write, so a run
        // cancelled while the body arrives stops there rather than once all of
        // it has, and leaves neither the partial body nor an entry.
        let dir = Scratch::new("cache-cancelled");
        let path = dir.join("package");
        let mut fetcher = Canned::new(&[b'x'; 64 * 1024]);
        fetcher.chunk = 512;
        let mut watch = Watching {
            fetched: Vec::new(),
            asked: 0,
            // The mirror boundary, and three writes.
            allowed: 4,
        };
        let err = download(
            &mut fetcher,
            &["http://serves.example".to_string()],
            |mirror| format!("{mirror}/package"),
            Entry {
                path: &path,
                size: None,
            },
            &mut watch,
            holding(b""),
            unserved,
        )
        .expect_err("the run was cancelled");
        assert!(matches!(err, Failure::Cancelled), "{err:?}");
        assert_eq!(watch.asked, 5, "the body itself asked, and stopped at once");
        assert!(
            entries_of(&dir).is_empty(),
            "left behind: {:?}",
            entries_of(&dir)
        );
    }

    /// The marker the file-size test's child process finds its cache by.
    const FILE_SIZE_LIMITED: &str = "FERRODAY_CAGE_TEST_CACHE_FILE_SIZE";

    /// The file size the child process is limited to, well under one write
    /// buffer, so the staging file refuses a write part way through a body.
    const FILE_SIZE_LIMIT: u64 = 4096;

    #[test]
    fn a_staging_file_that_refuses_a_write_is_a_host_failure() {
        // The body's writes run inside the transport, which reports a write the
        // disk refused as its own failure. Read that way, a full disk sends the
        // walk to every mirror in turn and blames the last. The refusal here is
        // the kernel's own: the child process runs under a file-size limit, a
        // real write failure that, unlike a full disk, a test can arrange
        // without a filesystem of its own. The limit is the child's, so no
        // other test's writes are held to it.
        if let Some(dir) = std::env::var_os(FILE_SIZE_LIMITED) {
            // A write past the limit raises `SIGXFSZ`, which ends the process
            // by default; ignored, the write fails with `EFBIG` instead.
            crate::mechanism::sys::set_disposition(
                rustix::process::Signal::XFSZ,
                crate::mechanism::sys::Disposition::Ignore,
            )
            .expect("SIGXFSZ can be ignored");
            let limit = rustix::process::Rlimit {
                current: Some(FILE_SIZE_LIMIT),
                maximum: Some(FILE_SIZE_LIMIT),
            };
            rustix::process::setrlimit(rustix::process::Resource::Fsize, limit)
                .expect("the file-size limit lowers");
            refused_writes_stop_the_download(Path::new(&dir));
            fs::write(Path::new(&dir).join("done"), b"").expect("the marker is written");
            return;
        }

        let dir = Scratch::new("cache-refused-write");
        // The child's output goes to pipes, which the limit does not cover. An
        // inherited standard output may be a file already past it, and the
        // harness's own report would then fail to be written.
        let child = std::process::Command::new(
            std::env::current_exe().expect("the test binary has a path"),
        )
        .args([
            "--exact",
            "provision::cache::tests::a_staging_file_that_refuses_a_write_is_a_host_failure",
            "--test-threads=1",
        ])
        .env(FILE_SIZE_LIMITED, dir.path())
        .output()
        .expect("the child test process runs");
        assert!(
            child.status.success(),
            "the child process failed: {}\n{}{}",
            child.status,
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr),
        );
        // A child that matched no test would succeed having asserted nothing.
        assert_eq!(entries_of(&dir), ["done"], "the child ran the test");
    }

    /// The child's half of the file-size test, in a cache under `dir`.
    fn refused_writes_stop_the_download(dir: &Path) {
        // Several write buffers' worth, in pieces, so the staging file is
        // written while the body is still arriving rather than only once it
        // has.
        let body = vec![b'x'; 4 * WRITE_BUFFER];
        let file_too_large = Some(rustix::io::Errno::FBIG.raw_os_error());

        let path = dir.join("package");
        let mut fetcher = Canned::new(&body);
        fetcher.chunk = 4096;
        let err = download(
            &mut fetcher,
            &serving_mirrors(),
            |mirror| format!("{mirror}/package"),
            Entry {
                path: &path,
                size: None,
            },
            &mut Watching::patient(),
            holding(&body),
            unserved,
        )
        .expect_err("the staging file refuses the body");
        let Failure::Io(ProvisionError::Io { source, .. }) = &err else {
            panic!("a refused write is a host failure: {err:?}");
        };
        assert_eq!(source.raw_os_error(), file_too_large, "{source}");
        assert_eq!(
            fetcher.asked,
            ["http://first.example/package"],
            "the walk stops at the first mirror",
        );
        assert!(entries_of(dir).is_empty(), "left: {:?}", entries_of(dir));

        // A batch stops at the same failure rather than leaving each job to
        // the walk, which would meet it again.
        let paths = [dir.join("one"), dir.join("two")];
        let jobs: Vec<Job<'_>> = paths
            .iter()
            .map(|path| Job {
                url: "http://first.example/package".to_string(),
                entry: Entry { path, size: None },
            })
            .collect();
        let mut fetcher = Canned::new(&body);
        fetcher.chunk = 4096;
        let outcome = prefetch(&mut fetcher, &jobs, &mut Watching::patient(), |_, _| {
            Ok::<(), ()>(())
        });
        let Err(Failure::Io(ProvisionError::Io { source, .. })) = &outcome else {
            panic!("a refused write ends the batch: {outcome:?}");
        };
        assert_eq!(source.raw_os_error(), file_too_large, "{source}");
        assert!(entries_of(dir).is_empty(), "left: {:?}", entries_of(dir));
    }

    #[test]
    fn a_batch_publishes_what_arrived_and_verified_and_leaves_the_rest() {
        // A job that does not arrive, or arrives and is refused, is left for the
        // walk; nothing about it is published, and nothing of it is left staged.
        let dir = Scratch::new("cache-batch");
        let paths: Vec<PathBuf> = ["good", "refused", "missing"]
            .iter()
            .map(|name| dir.join(name))
            .collect();
        let jobs: Vec<Job<'_>> = ["good", "refused", "missing"]
            .iter()
            .zip(&paths)
            .map(|(name, path)| Job {
                url: format!("http://mirror.example/{name}"),
                entry: Entry { path, size: None },
            })
            .collect();
        let mut watch = Watching::patient();
        let verified = prefetch(
            &mut Canned::new(b"a body"),
            &jobs,
            &mut watch,
            |at, mut file| {
                let mut held = String::new();
                file.read_to_string(&mut held)
                    .map_err(|err| err.to_string())?;
                if at == 1 {
                    return Err("refused".to_string());
                }
                Ok((at, held))
            },
        )
        .unwrap_or_else(|_| panic!("nothing cancelled the batch"));
        assert_eq!(verified, [Some((0, "a body".to_string())), None, None],);
        assert_eq!(entries_of(&dir), ["good"]);
        assert_eq!(watch.fetched.len(), 3, "every job was announced");
    }

    #[test]
    fn a_batch_reports_a_staging_file_it_cannot_create() {
        // The host's failure rather than the job's: the walk would meet it at
        // its first mirror, so the batch reports it rather than leaving the job
        // to be reported against a package.
        let dir = Scratch::new("cache-batch-unstaged");
        let staged = dir.join("staged");
        let unstaged = dir.join("absent/package");
        let jobs: Vec<Job<'_>> = [&staged, &unstaged]
            .into_iter()
            .map(|path| Job {
                url: "http://mirror.example/package".to_string(),
                entry: Entry { path, size: None },
            })
            .collect();
        let mut fetcher = Canned::new(b"a body");
        let outcome = prefetch(&mut fetcher, &jobs, &mut Watching::patient(), |_, _| {
            Ok::<(), ()>(())
        });
        let Err(Failure::Io(ProvisionError::Io { path, source, .. })) = &outcome else {
            panic!("a staging file that cannot be created ends the batch: {outcome:?}");
        };
        assert_eq!(path, &unstaged);
        assert_eq!(source.kind(), io::ErrorKind::NotFound, "{source}");
        assert!(fetcher.asked.is_empty(), "nothing of the batch was fetched");
        assert!(entries_of(&dir).is_empty(), "left: {:?}", entries_of(&dir));
    }

    #[test]
    fn a_batch_stops_at_its_boundary_when_the_run_is_cancelled() {
        let dir = Scratch::new("cache-batch-cancelled");
        let path = dir.join("package");
        let jobs = [Job {
            url: "http://mirror.example/package".to_string(),
            entry: Entry {
                path: &path,
                size: None,
            },
        }];
        let mut fetcher = Canned::new(b"a body");
        let mut watch = Watching {
            fetched: Vec::new(),
            asked: 0,
            allowed: 0,
        };
        let outcome = prefetch(&mut fetcher, &jobs, &mut watch, |_, _| Ok::<(), ()>(()));
        assert!(matches!(outcome, Err(Failure::Cancelled)));
        assert!(fetcher.asked.is_empty(), "nothing was fetched");
        assert!(entries_of(&dir).is_empty());
    }

    #[test]
    fn an_entry_is_opened_only_when_it_is_a_regular_file() {
        let dir = Scratch::new("cache-open");
        let file = dir.join("file");
        fs::write(&file, b"cached").unwrap();
        let mut held = String::new();
        open_entry(&file)
            .expect("a regular file opens")
            .read_to_string(&mut held)
            .unwrap();
        assert_eq!(held, "cached");

        assert_eq!(
            open_entry(&dir.join("absent")).unwrap_err().kind(),
            io::ErrorKind::NotFound,
        );

        // A link planted at the name is refused rather than followed.
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let err = open_entry(&link).expect_err("a link is not an entry");
        assert!(err.to_string().contains("is not a regular file"), "{err}");

        // A named pipe is refused without being opened, so nothing waits on a
        // writer that never comes.
        let fifo = dir.join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .expect("a named pipe can be made");
        let (done, waited) = std::sync::mpsc::channel();
        std::thread::spawn(move || done.send(open_entry(&fifo).map(|_| ())));
        let outcome = waited
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the open returned rather than waiting on the pipe");
        let err = outcome.expect_err("a pipe is not an entry");
        assert!(err.to_string().contains("is not a regular file"), "{err}");
    }

    #[test]
    fn a_derived_cache_is_a_sibling_however_the_tree_is_spelled() {
        // A trailing slash names the same tree, and appending to the spelling
        // would put the cache inside it, where an extraction can reach it.
        for (tree, cache) in [
            ("/srv/upper", "/srv/upper.cache"),
            ("/srv/upper/", "/srv/upper.cache"),
            ("/srv/upper/.", "/srv/upper.cache"),
            ("upper/", "upper.cache"),
        ] {
            assert_eq!(
                PackageCache::derived(Path::new(tree), ".cache"),
                Path::new(cache),
                "{tree}"
            );
        }
        // A spelling with no final component is named by where it resolves.
        let dir = Scratch::new("cache-derived");
        std::fs::create_dir_all(dir.join("tree/sub")).unwrap();
        assert_eq!(
            PackageCache::derived(&dir.join("tree/sub/.."), ".cache"),
            fs::canonicalize(dir.path()).unwrap().join("tree.cache"),
        );
    }

    #[cfg(feature = "gentoo")]
    #[test]
    fn a_link_below_the_cache_is_refused_rather_than_followed() {
        // A binary package sits below the binhost's path in the cache. A link
        // planted at one of those directories would carry the download, and
        // the read back, out of the cache.
        let dir = Scratch::new("cache-within");
        let (cache, outside) = (dir.join("cache"), dir.join("outside"));
        std::fs::create_dir_all(&outside).unwrap();
        create_within(&cache, &cache.join("binhost/app-misc/hello")).expect("the chain is created");
        create_within(&cache, &cache.join("binhost/app-misc/hello"))
            .expect("a chain already there is taken as it stands");
        assert!(cache.join("binhost/app-misc/hello").is_dir());

        std::os::unix::fs::symlink(&outside, cache.join("binhost/sys-apps")).unwrap();
        let err = create_within(&cache, &cache.join("binhost/sys-apps/coreutils"))
            .expect_err("a link in the chain is refused");
        assert!(
            matches!(&err, ProvisionError::Io { source, .. }
                if source.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())),
            "{err:?}"
        );
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            0,
            "the link was followed"
        );

        // A directory that is not below the cache is not one to create there.
        assert!(create_within(&cache, &outside.join("x")).is_err());
    }
}
