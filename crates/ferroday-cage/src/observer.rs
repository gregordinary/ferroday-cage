//! Live output streaming to a caller-supplied observer, and the collected
//! whole-run form built on it.

use crate::status::{ExitStatus, ResourceUsage};

/// A milestone in a sandbox launch, reported to [`Observer::progress`].
///
/// A launch passes through these stages in order, whether it is a direct
/// [`Cage::spawn_with`] or a held [`Cage::spawn_pending_with`] released with
/// [`Pending::proceed`]. They carry no payload and are the library's own
/// progress, distinct from the command's captured output: an observer keys a
/// launch log or progress display off the variant.
///
/// The enum is `#[non_exhaustive]`, so finer milestones can be added without
/// breaking existing observers.
///
/// [`Cage::spawn_with`]: crate::Cage::spawn_with
/// [`Cage::spawn_pending_with`]: crate::Cage::spawn_pending_with
/// [`Pending::proceed`]: crate::Pending::proceed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Progress {
    /// The launch has begun, before the sandbox's channels are created and its
    /// launch stage is forked.
    Launching,
    /// The sandbox's namespaces exist and its supervisor is published. For a
    /// direct launch the command is about to be executed; for a pending
    /// launch this is the gate, where a userspace network stack can attach
    /// before the command runs.
    Supervised,
    /// The command has been executed and is now running.
    Executing,
}

/// A sink for the sandboxed command's output.
///
/// An observer is borrowed by [`Cage::run_with`] or [`Cage::spawn_with`],
/// which capture the command's standard output and standard error into
/// pipes. The library delivers the captured bytes by calling the observer
/// on the caller's own thread, from inside the calls that serve the handle —
/// [`Cage::run_with`] itself, or [`Running::wait`], its deadline variants,
/// and the non-blocking [`Running::try_wait`]. No internal thread is spawned,
/// and output flows only while one of those calls is pumping.
///
/// Chunks are delivered exactly as they are read from the pipes: they are
/// not lines, they are not UTF-8, and their boundaries carry no meaning. An
/// observer that needs lines assembles them itself.
///
/// Alongside the command's output, an observer receives the library's own
/// launch [`Progress`] milestones through [`progress`](Self::progress).
///
/// Every method has an empty default body, so an observer implements only
/// what it consumes, and new callbacks can be added without breaking
/// existing implementations.
///
/// # Example
///
/// ```
/// use ferroday_cage::Observer;
///
/// #[derive(Default)]
/// struct Collect {
///     stdout: Vec<u8>,
///     stderr: Vec<u8>,
/// }
///
/// impl Observer for Collect {
///     fn stdout(&mut self, chunk: &[u8]) {
///         self.stdout.extend_from_slice(chunk);
///     }
///     fn stderr(&mut self, chunk: &[u8]) {
///         self.stderr.extend_from_slice(chunk);
///     }
/// }
/// ```
///
/// [`Cage::run_with`]: crate::Cage::run_with
/// [`Cage::spawn_with`]: crate::Cage::spawn_with
/// [`Running::wait`]: crate::Running::wait
/// [`Running::try_wait`]: crate::Running::try_wait
pub trait Observer {
    /// Receives a chunk of the command's standard output.
    fn stdout(&mut self, chunk: &[u8]) {
        let _ = chunk;
    }

    /// Receives a chunk of the command's standard error.
    fn stderr(&mut self, chunk: &[u8]) {
        let _ = chunk;
    }

    /// Receives a launch [`Progress`] milestone.
    ///
    /// Called on the calling thread as the launch advances, before any
    /// captured output flows. Unlike [`stdout`](Self::stdout) and
    /// [`stderr`](Self::stderr), a milestone is the library's own progress,
    /// not the command's output, so an observer can drive a launch log or a
    /// progress display without parsing the command's streams.
    fn progress(&mut self, event: Progress) {
        let _ = event;
    }
}

/// A closure is an observer that watches the launch's milestones and ignores
/// the command's output.
///
/// The same blanket impl [`ProvisionObserver`] carries, so a caller that wants
/// one line per milestone writes the same thing on either side:
///
/// ```no_run
/// # fn main() -> Result<(), ferroday_cage::Error> {
/// use ferroday_cage::{Cage, Progress};
///
/// # let rootfs = "/var/cache/myapp/rootfs";
/// let cage = Cage::builder().command("/bin/true").rootfs(rootfs).build()?;
/// cage.run_with(&mut |event: Progress| eprintln!("{event:?}"))?;
/// # Ok(())
/// # }
/// ```
///
/// A closure cannot receive the command's output, because it would have no way
/// to say which stream a chunk came from. An observer that wants the output
/// implements the trait.
///
/// [`ProvisionObserver`]: crate::provision::ProvisionObserver
impl<F: FnMut(Progress)> Observer for F {
    fn progress(&mut self, event: Progress) {
        self(event)
    }
}

/// A completed command's exit status and its captured output.
///
/// Produced by [`Cage::output`], the run-it-and-give-me-everything shape of a
/// launch. [`Capped`] is its bounded counterpart, and [`Observer`] remains the
/// way to consume output as it is produced or to act on it before the command
/// finishes.
///
/// [`Cage::output`]: crate::Cage::output
// The restriction fallback is feature-gated, so the sentence naming it — and
// its intra-doc link — is gated with it, per the crate-level convention.
#[cfg_attr(
    feature = "hardening",
    doc = "
[`Restriction::output`](crate::Restriction::output) produces the same type for a
restriction.
"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Output {
    /// The command's exit status. As everywhere in this library, a non-zero
    /// exit is data rather than an error.
    pub status: ExitStatus,
    /// What the command and its descendants used of the processor and of
    /// memory, as [`Running::usage`](crate::Running::usage) reports it.
    pub usage: Option<ResourceUsage>,
    /// Everything the command wrote to standard output, concatenated in
    /// order. Raw bytes: not lines, and not guaranteed to be UTF-8.
    pub stdout: Vec<u8>,
    /// Everything the command wrote to standard error, concatenated in order.
    pub stderr: Vec<u8>,
}

/// An observer that keeps the beginning and the end of each stream the command
/// writes, within a bound, and counts what it leaves out between them.
///
/// The bounded counterpart of [`Output`], for a command whose output volume
/// the caller does not control: model-generated code, an untrusted build, a
/// test suite that may loop. The beginning says what the command set out to
/// do, and the end holds what it reported last, which is where a compiler's
/// error or a test run's summary is. The command is never stopped or failed
/// for writing more: the pump keeps draining its streams, and what falls
/// between the two ends is counted rather than kept.
///
/// What is kept is raw bytes, as the [`Observer`] receives them. The bound
/// counts bytes, so a cut can fall inside a line or inside a UTF-8 sequence,
/// and rendering an excerpt for a reader, with a marker where bytes were left
/// out, is the caller's.
///
/// ```no_run
/// use ferroday_cage::{Cage, Capped};
///
/// # fn main() -> ferroday_cage::Result<()> {
/// let cage = Cage::builder()
///     .rootfs("/srv/rootfs/alpine")
///     .command("/usr/bin/make")
///     .build()?;
/// // The first and the last 32 KiB of each stream.
/// let mut capped = Capped::new(32 * 1024, 32 * 1024);
/// let status = cage.run_with(&mut capped)?;
/// let errors = &capped.stderr;
/// eprint!("{}", String::from_utf8_lossy(errors.head()));
/// if errors.omitted() > 0 {
///     eprintln!("[{} bytes left out]", errors.omitted());
/// }
/// eprint!("{}", String::from_utf8_lossy(errors.tail()));
/// # let _ = status;
/// # Ok(())
/// # }
/// ```
///
/// Bounding the time as well is a deadline's job, and bounding what the command
/// can consume while it runs is a resource limit's.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Capped {
    /// What was kept of the command's standard output.
    pub stdout: Excerpt,
    /// What was kept of the command's standard error.
    pub stderr: Excerpt,
}

impl Capped {
    /// An observer keeping, of each stream, up to its first `head` bytes and
    /// its last `tail` bytes.
    ///
    /// A stream no longer than `head` and `tail` together is kept whole. Either
    /// may be zero, so `Capped::new(0, 4096)` keeps only the end of each stream
    /// and `Capped::new(4096, 0)` only the beginning.
    pub fn new(head: usize, tail: usize) -> Capped {
        Capped {
            stdout: Excerpt::new(head, tail),
            stderr: Excerpt::new(head, tail),
        }
    }
}

impl Observer for Capped {
    fn stdout(&mut self, chunk: &[u8]) {
        self.stdout.keep(chunk);
    }

    fn stderr(&mut self, chunk: &[u8]) {
        self.stderr.keep(chunk);
    }
}

/// What a [`Capped`] observer kept of one stream: its beginning, its end, and
/// how much it left out between them.
///
/// Where nothing was left out, [`head`](Self::head) and then
/// [`tail`](Self::tail) are the whole stream, in order. The memory one holds
/// never exceeds its head's bound and twice its tail's: the end is kept in a
/// buffer compacted as it fills, so taking it costs a copy only once per tail's
/// worth of input.
#[derive(Debug, Clone)]
pub struct Excerpt {
    /// The stream's first bytes, up to `head_limit`.
    head: Vec<u8>,
    head_limit: usize,
    /// The stream's latest bytes after the head, at most twice `tail_limit`
    /// long, whose last `tail_limit` are the tail.
    recent: Vec<u8>,
    tail_limit: usize,
    /// Every byte the stream carried.
    total: u64,
}

impl Excerpt {
    /// An empty excerpt keeping up to `head` bytes from the start and `tail`
    /// from the end.
    fn new(head: usize, tail: usize) -> Excerpt {
        Excerpt {
            head: Vec::new(),
            head_limit: head,
            recent: Vec::new(),
            tail_limit: tail,
            total: 0,
        }
    }

    /// Takes the stream's next `chunk`.
    fn keep(&mut self, chunk: &[u8]) {
        self.total = self.total.saturating_add(chunk.len() as u64);
        let room = self.head_limit.saturating_sub(self.head.len());
        let (first, rest) = chunk.split_at(chunk.len().min(room));
        self.head.extend_from_slice(first);
        if rest.len() >= self.tail_limit {
            self.recent.clear();
            self.recent
                .extend_from_slice(&rest[rest.len() - self.tail_limit..]);
            return;
        }
        self.recent.extend_from_slice(rest);
        if self.recent.len() > self.tail_limit.saturating_mul(2) {
            let excess = self.recent.len() - self.tail_limit;
            self.recent.drain(..excess);
        }
    }

    /// The stream's first bytes, up to the head's bound.
    pub fn head(&self) -> &[u8] {
        &self.head
    }

    /// The stream's last bytes after the head, up to the tail's bound.
    pub fn tail(&self) -> &[u8] {
        &self.recent[self.recent.len().saturating_sub(self.tail_limit)..]
    }

    /// How many bytes between the head and the tail were left out; zero where
    /// the stream is kept whole.
    pub fn omitted(&self) -> u64 {
        self.total - (self.head.len() + self.tail().len()) as u64
    }

    /// How many bytes the stream carried in all.
    pub fn total(&self) -> u64 {
        self.total
    }
}

/// Two excerpts are equal where they kept the same bytes of streams of the same
/// length, however the tail's buffer stands.
impl PartialEq for Excerpt {
    fn eq(&self, other: &Excerpt) -> bool {
        self.head == other.head && self.tail() == other.tail() && self.total == other.total
    }
}

impl Eq for Excerpt {}

/// The observer behind [`Output`]: accumulates both streams whole.
///
/// Unbounded by construction, which is why it is internal: a caller running
/// untrusted code reaches for [`Capped`] rather than for this.
#[derive(Default)]
pub(crate) struct Collect {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Collect {
    /// Pairs what was collected with the command's outcome and usage.
    pub(crate) fn into_output(self, status: ExitStatus, usage: Option<ResourceUsage>) -> Output {
        Output {
            status,
            usage,
            stdout: self.stdout,
            stderr: self.stderr,
        }
    }
}

impl Observer for Collect {
    fn stdout(&mut self, chunk: &[u8]) {
        self.stdout.extend_from_slice(chunk);
    }

    fn stderr(&mut self, chunk: &[u8]) {
        self.stderr.extend_from_slice(chunk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `stream` fed to an excerpt in chunks of `size` bytes.
    fn kept(head: usize, tail: usize, stream: &[u8], size: usize) -> Excerpt {
        let mut excerpt = Excerpt::new(head, tail);
        for chunk in stream.chunks(size.max(1)) {
            excerpt.keep(chunk);
            assert!(
                excerpt.recent.len() <= tail.saturating_mul(2).max(tail),
                "the tail's buffer outgrew its bound"
            );
        }
        excerpt
    }

    #[test]
    fn a_stream_within_the_bounds_is_kept_whole() {
        let stream = b"one\ntwo\nthree\n";
        for (head, tail) in [(64, 0), (0, 64), (4, 10), (14, 0), (0, 14)] {
            let excerpt = kept(head, tail, stream, 3);
            assert_eq!(excerpt.omitted(), 0, "{head}/{tail}");
            assert_eq!([excerpt.head(), excerpt.tail()].concat(), stream);
            assert_eq!(excerpt.total(), stream.len() as u64);
        }
    }

    #[test]
    fn a_longer_stream_keeps_its_ends_and_counts_its_middle() {
        let stream: Vec<u8> = (0..10_000u32).flat_map(|n| n.to_le_bytes()).collect();
        let expected = (
            stream[..100].to_vec(),
            stream[stream.len() - 300..].to_vec(),
        );
        // However the pipe happened to chunk it.
        let excerpts: Vec<Excerpt> = [1, 7, 299, 300, 301, 4096, stream.len()]
            .into_iter()
            .map(|size| kept(100, 300, &stream, size))
            .collect();
        for excerpt in &excerpts {
            assert_eq!((excerpt.head().to_vec(), excerpt.tail().to_vec()), expected);
            assert_eq!(excerpt.omitted(), stream.len() as u64 - 400);
            assert_eq!(excerpt, &excerpts[0]);
        }
    }

    #[test]
    fn either_end_can_be_left_unkept() {
        let stream = vec![b'x'; 1000];
        let only_end = kept(0, 10, &stream, 64);
        assert!(only_end.head().is_empty());
        assert_eq!(only_end.tail().len(), 10);
        assert_eq!(only_end.omitted(), 990);
        let only_start = kept(10, 0, &stream, 64);
        assert_eq!(only_start.head().len(), 10);
        assert!(only_start.tail().is_empty());
        assert_eq!(only_start.omitted(), 990);
    }

    #[test]
    fn each_stream_is_kept_apart() {
        let mut capped = Capped::new(2, 2);
        Observer::stdout(&mut capped, b"out-out-out");
        Observer::stderr(&mut capped, b"err");
        assert_eq!(
            (capped.stdout.head(), capped.stdout.tail()),
            (&b"ou"[..], &b"ut"[..])
        );
        assert_eq!(capped.stdout.omitted(), 7);
        assert_eq!(
            [capped.stderr.head(), capped.stderr.tail()].concat(),
            b"err"
        );
    }
}
