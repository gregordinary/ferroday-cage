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
/// launch. [`Observer`] remains the way to consume output as it is produced, to
/// bound what is kept, or to act on it before the command finishes.
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

/// The observer behind [`Output`]: accumulates both streams whole.
///
/// Unbounded by construction, which is why it is internal — a caller running
/// untrusted code writes an [`Observer`] that caps what it keeps rather than
/// reaching for this.
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
