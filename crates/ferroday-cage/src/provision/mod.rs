//! Rootfs provisioning: producing the root filesystem a sandbox runs in.
//!
//! A [`Provisioner`] populates a staging directory with a complete root
//! filesystem, and [`ensure`] publishes the result atomically: the
//! destination directory either does not exist or holds a fully provisioned
//! rootfs, never a partial one, even across crashes and concurrent callers.
//!
// The `Tarball` sentence links a feature-gated item, so its doc text is gated
// on the feature: present in the canonical all-features build, absent — link
// and all — from a no-feature `cargo doc`.
#![cfg_attr(
    feature = "tarball",
    doc = "With the `tarball` feature, [`Tarball`] provisions from a tar archive"
)]
#![cfg_attr(
    feature = "tarball",
    doc = "(plain, gzip, xz, or zstd, detected by content), extracting with"
)]
#![cfg_attr(
    feature = "tarball",
    doc = "kernel-enforced containment so a hostile archive cannot write outside"
)]
#![cfg_attr(feature = "tarball", doc = "the destination.")]
#![cfg_attr(feature = "tarball", doc = "")]
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "tarball")]
//! # fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
//! use ferroday_cage::provision::{self, Tarball};
//!
//! let rootfs = "/var/cache/myapp/alpine-rootfs";
//! provision::ensure(rootfs, &mut Tarball::new("alpine-minirootfs.tar.gz"))?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "tarball"))]
//! # fn main() {}
//! ```

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, Mode, OFlags};
use rustix::io::Errno;

#[cfg(feature = "tarball")]
mod compress;
mod copyin;
#[cfg(feature = "tarball")]
mod export;
#[cfg(feature = "tarball")]
mod extract;
mod identity;
#[cfg(feature = "debian")]
mod rooted;
#[cfg(feature = "tarball")]
mod tar;
#[cfg(feature = "tarball")]
mod tarball;

pub use copyin::{CopyIn, CopyReport, SkippedEntry, SkippedKind};
#[cfg(feature = "tarball")]
pub use export::{Export, export_tar};
#[cfg(feature = "tarball")]
pub use tarball::Tarball;

#[cfg(feature = "debian")]
pub mod debian;

/// Something a provisioner is doing, reported to a [`ProvisionObserver`].
///
/// Provisioning a root filesystem is the slow part of a first run — extracting
/// a 250 MB stage3, fetching and configuring a hundred packages — so a
/// provisioner reports what it is doing as it goes. The variants a given
/// provisioner emits are its own business; an observer matches the ones it
/// cares about and ignores the rest, which `#[non_exhaustive]` requires it to
/// do anyway.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProvisionEvent<'a> {
    /// An entry is about to be written into the staging tree.
    ///
    /// The path is relative to the staging directory, as the source records
    /// it.
    #[non_exhaustive]
    Entry {
        /// The entry's path within the tree being provisioned.
        path: &'a Path,
    },
    /// Progress through the provisioner's source.
    ///
    /// `total` is the source's size when the provisioner knows it — an archive
    /// read from a file — and `None` when it does not, as for an archive
    /// streamed from a reader of unknown length.
    #[non_exhaustive]
    Read {
        /// Bytes consumed from the source so far.
        done: u64,
        /// The source's total size, when known.
        total: Option<u64>,
    },
    /// A Debian bootstrap's own, richer event.
    ///
    /// The bootstrap reports fetches, resolution, downloads, and the output of
    /// the `dpkg` waves it runs in a cage — detail the shared vocabulary above
    /// has no place for. Nesting it here keeps one observer for every
    /// provisioner rather than one per provisioner.
    #[cfg(feature = "debian")]
    Debian(&'a debian::DebianEvent<'a>),
}

/// A progress and cancellation sink for a provisioning run.
///
/// Attached with [`Provision::observe`], and reached by a provisioner through
/// [`ProvisionRequest::report`] and [`ProvisionRequest::cancelled`]. Both
/// methods have a default body, so an observer implements only the half it
/// wants, and a plain `FnMut(ProvisionEvent<'_>)` closure is an observer that
/// reports and never cancels.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "tarball")]
/// # fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicBool, Ordering};
///
/// use ferroday_cage::provision::{
///     Provision, ProvisionEvent, ProvisionObserver, Tarball,
/// };
///
/// struct Progress {
///     stop: Arc<AtomicBool>,
/// }
///
/// impl ProvisionObserver for Progress {
///     fn progress(&mut self, event: ProvisionEvent<'_>) {
///         if let ProvisionEvent::Read { done, total: Some(total), .. } = event {
///             eprint!("\r{}%", done * 100 / total.max(1));
///         }
///     }
///
///     fn cancelled(&mut self) -> bool {
///         self.stop.load(Ordering::Relaxed)
///     }
/// }
///
/// let stop = Arc::new(AtomicBool::new(false));
/// Provision::new("/var/cache/myapp/alpine-rootfs")
///     .observe(&mut Progress { stop: Arc::clone(&stop) })
///     .run(&mut Tarball::new("alpine-minirootfs.tar.gz"))?;
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "tarball"))]
/// # fn main() {}
/// ```
pub trait ProvisionObserver {
    /// Receives one progress event.
    fn progress(&mut self, event: ProvisionEvent<'_>) {
        let _ = event;
    }

    /// Whether the run should stop.
    ///
    /// Consulted by a provisioner at the points where stopping is clean — an
    /// archive entry boundary, a package boundary. Returning `true` aborts the
    /// run with [`ProvisionError::Cancelled`]; [`ensure`] then removes the
    /// staging tree, so a cancelled run leaves no destination behind, exactly
    /// as a failed one does.
    ///
    /// The default is `false`: a run that is never cancelled.
    fn cancelled(&mut self) -> bool {
        false
    }
}

/// A closure is an observer that reports and never cancels.
impl<F: FnMut(ProvisionEvent<'_>)> ProvisionObserver for F {
    fn progress(&mut self, event: ProvisionEvent<'_>) {
        self(event)
    }
}

/// The observer as a provisioning run carries it: shared, so the immutable
/// [`ProvisionRequest`] every provisioner holds can still call into it.
type ObserverCell<'o> = std::cell::RefCell<&'o mut dyn ProvisionObserver>;

/// The inputs to one provisioning run.
///
/// [`Provisioner::provision`] takes its inputs as this value rather than as
/// loose parameters, so that context a provisioner comes to need can be added
/// as accessors without changing the trait method's signature.
///
/// A provisioner reads what it understands and ignores the rest.
#[derive(Clone, Copy)]
pub struct ProvisionRequest<'a> {
    staging: &'a Path,
    observer: Option<&'a ObserverCell<'a>>,
}

impl<'a> ProvisionRequest<'a> {
    /// Returns a request naming `staging` as the directory to fill, with no
    /// observer attached.
    ///
    /// [`ensure`] and [`Provision::run`] build the request a provisioner
    /// receives; this constructor is for a caller driving a [`Provisioner`]
    /// directly.
    pub fn new(staging: &'a Path) -> ProvisionRequest<'a> {
        ProvisionRequest {
            staging,
            observer: None,
        }
    }

    /// The same request with `observer` attached.
    pub(crate) fn observed(self, observer: &'a ObserverCell<'a>) -> ProvisionRequest<'a> {
        ProvisionRequest {
            observer: Some(observer),
            ..self
        }
    }

    /// The directory to fill with the root filesystem's contents.
    ///
    /// It exists and is empty. It is not the rootfs's final location:
    /// [`ensure`] renames it into place once the provisioner returns.
    pub fn staging(&self) -> &'a Path {
        self.staging
    }

    /// Reports an event to the run's observer, if one is attached.
    ///
    /// A no-op otherwise, so a provisioner reports unconditionally rather than
    /// branching on whether anyone is listening.
    pub fn report(&self, event: ProvisionEvent<'_>) {
        if let Some(observer) = self.observer {
            observer.borrow_mut().progress(event);
        }
    }

    /// Whether the run has been cancelled, and the provisioner should stop.
    ///
    /// `false` when no observer is attached. A provisioner consults this at
    /// the boundaries where stopping is clean, and returns
    /// [`ProvisionError::Cancelled`] when it is `true`.
    pub fn cancelled(&self) -> bool {
        match self.observer {
            Some(observer) => observer.borrow_mut().cancelled(),
            None => false,
        }
    }
}

impl fmt::Debug for ProvisionRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvisionRequest")
            .field("staging", &self.staging)
            .field("observed", &self.observer.is_some())
            .finish_non_exhaustive()
    }
}

/// Populates a staging directory with a complete root filesystem.
///
/// A provisioner is handed an existing, empty staging directory and fills
/// it; it must not assume the directory is the rootfs's final location.
/// [`ensure`] supplies the staging directory and publishes it atomically.
///
/// On error, the provisioner may leave the staging directory in any state;
/// the caller removes it.
///
/// The method takes `&mut self`, so a provisioner may carry mutable state
/// across the call — a fetcher's connections, a progress sink — and is
/// consumed by [`ensure`] through a `&mut` reference.
///
/// # Stability
///
/// Every method added to this trait in a later release will carry a default
/// body, so an existing implementation keeps compiling. New inputs arrive as
/// accessors on [`ProvisionRequest`] rather than as parameters, for the same
/// reason.
///
/// # Example
///
/// ```
/// use std::fs;
///
/// use ferroday_cage::provision::{ProvisionError, ProvisionRequest, Provisioner};
///
/// /// A provisioner that lays down a single marker file.
/// struct Marker;
///
/// impl Provisioner for Marker {
///     fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
///         let path = request.staging().join("marker");
///         fs::write(&path, b"provisioned")
///             .map_err(|err| ProvisionError::io("writing", path, err))
///     }
/// }
/// ```
pub trait Provisioner {
    /// Fills the request's staging directory with the root filesystem's
    /// contents.
    fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError>;
}

/// The outcome of [`ensure`]: whether the rootfs was created by this call
/// or was already present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Provisioned {
    /// The rootfs did not exist and was provisioned and published.
    Created,
    /// The rootfs already existed; the provisioner did not run.
    Existing,
}

/// An error from provisioning a rootfs.
///
/// Provisioning is a separate act from launching a sandbox, and carries its
/// own error type; it never appears inside [`Error`](crate::Error).
#[derive(Debug)]
#[non_exhaustive]
pub enum ProvisionError {
    /// The destination path cannot host a rootfs directory.
    ///
    /// The path has no final component, or something that is not a
    /// directory already exists there.
    #[non_exhaustive]
    DestUnusable {
        /// The destination as it was given.
        path: PathBuf,
    },
    /// A host I/O operation failed.
    #[non_exhaustive]
    Io {
        /// What the operation was doing.
        op: &'static str,
        /// The path the operation concerned.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
    /// The archive is malformed or truncated.
    #[non_exhaustive]
    Archive {
        /// The archive offset of the offending block, in bytes of the
        /// uncompressed stream.
        offset: u64,
        /// What was wrong.
        reason: String,
    },
    /// An archive entry attempted to reach outside the extraction root.
    ///
    /// The entry's path or link target is absolute, contains `..`, carries a
    /// NUL byte that would truncate it, or resolves through a symlink to a
    /// location outside the rootfs being extracted. Containment is enforced by
    /// the kernel during path resolution, not by inspecting the path text.
    ///
    /// This variant asserts a containment failure and nothing else. An entry
    /// refused for any other reason is [`EntryRefused`](Self::EntryRefused).
    #[non_exhaustive]
    EntryUnsafe {
        /// The entry's path as recorded in the archive.
        path: PathBuf,
        /// What was unsafe about it.
        reason: String,
    },
    /// An entry cannot be handled as it stands, for a reason that is not a
    /// containment failure.
    ///
    /// A malformed archive — a path component that is not a directory, an empty
    /// symlink target — a source tree past a limit the copy protocol can carry
    /// (its depth, an entry name, a link target), or a source id the
    /// destination's identity map has no place for.
    ///
    /// Distinct from [`EntryUnsafe`](Self::EntryUnsafe), which means an entry
    /// tried to reach outside the tree it was being written into. Nothing here
    /// did.
    #[non_exhaustive]
    EntryRefused {
        /// The entry's path: as recorded in the archive, or as it sits in the
        /// source tree.
        path: PathBuf,
        /// Why it was refused.
        reason: String,
    },
    /// An archive entry has a type the extractor does not support.
    ///
    /// Sparse and multi-volume entries are not supported. (Character and
    /// block devices and GNU volume labels are not errors; they are skipped,
    /// as documented on the `Tarball` provisioner.)
    #[non_exhaustive]
    EntryUnsupported {
        /// The entry's path as recorded in the archive.
        path: PathBuf,
        /// The entry's tar typeflag byte.
        kind: u8,
    },
    /// The file is neither a recognized compression format nor a tar
    /// archive.
    #[non_exhaustive]
    FormatUnrecognized {
        /// The file as it was given.
        path: PathBuf,
    },
    /// The run was cancelled through the observer.
    ///
    /// Reported by a provisioner whose [`ProvisionRequest::cancelled`] check
    /// answered `true`. [`ensure`] removes the staging tree, so the
    /// destination is left absent, as it is for any other failed run.
    Cancelled,
    /// A failure from a provisioner outside this crate.
    ///
    /// The stable channel through which a provisioner implemented elsewhere
    /// reports its own error type; build one with [`ProvisionError::other`].
    #[non_exhaustive]
    Other {
        /// The provisioner's own error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A tree could not be removed: it holds files owned through an
    /// identity map, and no delegate can establish that map to act on them.
    ///
    /// A range-mapped sandbox writes real ownership, so its rootfs can hold
    /// files the plain calling user cannot delete. [`remove`] escalates by
    /// re-entering the same map; this error is the escalation finding no
    /// delegate, with the reason naming what the host is missing.
    #[non_exhaustive]
    RemoveUnprivileged {
        /// The tree that could not be removed.
        path: PathBuf,
        /// The removal failure that triggered the escalation.
        source: io::Error,
        /// Why no delegate could establish the identity map.
        reason: String,
    },
    /// A tree could not be exported: it holds files owned through a range
    /// identity map, and no delegate can establish that map to read them at
    /// their intended ownership.
    ///
    /// [`export_tar`] re-enters the map the tree was built under so a file the
    /// rootfs means as a system id is read as that id, not the host
    /// subordinate id it is stored as. This error is that re-entry finding no
    /// delegate for a range map, with the reason naming what the host is
    /// missing.
    #[cfg(feature = "tarball")]
    #[non_exhaustive]
    ExportUnprivileged {
        /// The tree that could not be exported.
        path: PathBuf,
        /// Why no delegate could establish the identity map.
        reason: String,
    },
    /// A copy into a rootfs owned through a range map could not establish that
    /// map.
    ///
    /// Creating an entry owned by a mapped id needs a process inside the map,
    /// and no delegate could establish one.
    // The sentence links a feature-gated variant, so its doc text is gated on
    // the feature: present in the canonical all-features build, absent — link
    // and all — from a no-feature `cargo doc`.
    #[cfg_attr(
        feature = "tarball",
        doc = "It is the mirror of [`ExportUnprivileged`](Self::ExportUnprivileged),"
    )]
    #[cfg_attr(feature = "tarball", doc = "which arises for the same reason.")]
    #[non_exhaustive]
    CopyUnprivileged {
        /// The rootfs that could not be copied into.
        path: PathBuf,
        /// Why no delegate could establish the identity map.
        reason: String,
    },
    /// A source file changed size while a [`CopyIn`] was reading it, so the
    /// copy could not reproduce it.
    ///
    /// The copy commits a file's length before it reads the contents, and the
    /// in-map writer reads exactly that many bytes. A file that grew or shrank
    /// in between is therefore written truncated or zero-padded, and the run
    /// reports this rather than presenting the result as a copy: a source tree
    /// changing underneath a copy is something the caller would rather hear
    /// about than discover in the rootfs later.
    #[non_exhaustive]
    SourceChanged {
        /// The source file that changed.
        path: PathBuf,
        /// The length the copy recorded and wrote.
        recorded: u64,
    },
}

impl ProvisionError {
    /// Wraps a provisioner's own error.
    ///
    /// The channel for a [`Provisioner`] implemented outside this crate: its
    /// error type travels intact and is reachable through
    /// [`source`](std::error::Error::source), so a consumer can downcast to it.
    ///
    /// # Example
    ///
    /// ```
    /// use ferroday_cage::provision::ProvisionError;
    ///
    /// let err = ProvisionError::other("the mirror rejected the request");
    /// assert!(err.to_string().contains("the mirror rejected the request"));
    /// ```
    pub fn other(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> ProvisionError {
        ProvisionError::Other {
            source: source.into(),
        }
    }

    /// A host I/O failure, naming what the operation was doing and the path it
    /// concerned.
    pub fn io(op: &'static str, path: impl Into<PathBuf>, source: io::Error) -> ProvisionError {
        ProvisionError::Io {
            op,
            path: path.into(),
            source,
        }
    }
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProvisionError::DestUnusable { path } => write!(
                f,
                "cannot publish a rootfs at {}: the path has no final component or is not a directory",
                path.display(),
            ),
            ProvisionError::Io { op, path, source } => {
                write!(
                    f,
                    "provisioning failed while {op} {}: {source}",
                    path.display()
                )
            }
            ProvisionError::Archive { offset, reason } => {
                write!(f, "malformed archive at offset {offset}: {reason}")
            }
            ProvisionError::EntryUnsafe { path, reason } => write!(
                f,
                "the archive entry {} reaches outside the extraction root: {reason}",
                path.display(),
            ),
            ProvisionError::EntryRefused { path, reason } => {
                write!(f, "the entry {} was refused: {reason}", path.display())
            }
            ProvisionError::EntryUnsupported { path, kind } => write!(
                f,
                "the archive entry {} has unsupported type {:?}",
                path.display(),
                char::from(*kind),
            ),
            ProvisionError::FormatUnrecognized { path } => write!(
                f,
                "{} is neither a recognized compression format nor a tar archive",
                path.display(),
            ),
            ProvisionError::Cancelled => f.write_str("provisioning was cancelled"),
            ProvisionError::Other { source } => write!(f, "provisioning failed: {source}"),
            ProvisionError::RemoveUnprivileged {
                path,
                source,
                reason,
            } => write!(
                f,
                "cannot remove {}: {source}; the tree holds ids the caller cannot act on, \
                 and no delegate can establish the identity map to remove them ({reason})",
                path.display(),
            ),
            ProvisionError::CopyUnprivileged { path, reason } => write!(
                f,
                "cannot copy into {}: the rootfs is owned through a range identity map, \
                 and no delegate can establish the map to write it ({reason})",
                path.display(),
            ),
            ProvisionError::SourceChanged { path, recorded } => write!(
                f,
                "{} changed size while it was being copied: {recorded} bytes were recorded \
                 and written, which is no longer what the file holds",
                path.display(),
            ),
            #[cfg(feature = "tarball")]
            ProvisionError::ExportUnprivileged { path, reason } => write!(
                f,
                "cannot export {}: the tree holds ids owned through a range identity map, \
                 and no delegate can establish the map to read them ({reason})",
                path.display(),
            ),
        }
    }
}

impl std::error::Error for ProvisionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProvisionError::Io { source, .. } => Some(source),
            ProvisionError::Other { source } => Some(source.as_ref()),
            ProvisionError::RemoveUnprivileged { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Shorthand for building [`ProvisionError::Io`].
fn io_error(op: &'static str, path: &Path, source: io::Error) -> ProvisionError {
    ProvisionError::Io {
        op,
        path: path.to_path_buf(),
        source,
    }
}

/// A rootfs publication, configured then run.
///
/// The extensible form of [`ensure`]: it takes the destination, a progress and
/// cancellation observer, and future options — a lock-free mode, a staleness
/// predicate — as methods here rather than as parameters of a free function.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "tarball")]
/// # fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
/// use ferroday_cage::provision::{Provision, ProvisionEvent, Tarball};
///
/// Provision::new("/var/cache/myapp/alpine-rootfs")
///     .observe(&mut |event: ProvisionEvent<'_>| eprintln!("{event:?}"))
///     .run(&mut Tarball::new("alpine-minirootfs.tar.gz"))?;
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "tarball"))]
/// # fn main() {}
/// ```
pub struct Provision<'obs> {
    dest: PathBuf,
    observer: Option<&'obs mut dyn ProvisionObserver>,
}

/// A delegate rendered by what it stands for, for the `Debug` impls of the
/// builders that hold one.
///
/// A fetcher, an observer, and an identity mapper are all supplied by the
/// caller as code behind a trait object. What a reader of a rendering wants
/// from one is whether it is there at all, so it renders as `<dyn Fetch>`
/// rather than as its contents, and an optional one as `Some(<dyn IdMapper>)`
/// or `None`.
///
/// [`IdMapper`](crate::IdMapper) does require `Debug`, so a mapper alone could
/// render its own. It does not, for two reasons: [`Fetch`](debian::Fetch) and
/// [`ProvisionObserver`] carry no such bound, so one delegate rendering unlike
/// the other two would be an inconsistency with nothing behind it, and a
/// caller's mapper is free to render at any length in a place that should stay
/// compact.
pub(crate) struct Delegate(pub(crate) &'static str);

impl fmt::Debug for Delegate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.0)
    }
}

impl fmt::Debug for Provision<'_> {
    /// Renders the destination and whether an observer is attached. The
    /// observer itself is a caller's trait object, with nothing useful to show.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provision")
            .field("dest", &self.dest)
            .field(
                "observer",
                &self
                    .observer
                    .as_ref()
                    .map(|_| Delegate("dyn ProvisionObserver")),
            )
            .finish()
    }
}

impl<'obs> Provision<'obs> {
    /// Returns a publication targeting `dest`.
    pub fn new(dest: impl AsRef<Path>) -> Provision<'obs> {
        Provision {
            dest: dest.as_ref().to_path_buf(),
            observer: None,
        }
    }

    /// Attaches a progress and cancellation observer to the run.
    ///
    /// The observer reaches the provisioner as
    /// [`ProvisionRequest::report`] and [`ProvisionRequest::cancelled`], so
    /// every provisioner speaks to it the same way. A closure taking a
    /// [`ProvisionEvent`] is an observer that reports and never cancels.
    pub fn observe(mut self, observer: &'obs mut dyn ProvisionObserver) -> Provision<'obs> {
        self.observer = Some(observer);
        self
    }

    /// Publishes the rootfs, running `provisioner` if it is absent.
    ///
    /// # Errors
    ///
    /// As [`ensure`], plus [`ProvisionError::Cancelled`] when the observer
    /// stops the run.
    pub fn run(self, provisioner: &mut dyn Provisioner) -> Result<Provisioned, ProvisionError> {
        let Provision { dest, observer } = self;
        // Reborrowed explicitly, so the trait object's lifetime shortens to
        // this frame rather than staying pinned to the builder's.
        let mut observer = observer;
        let reborrowed: Option<&mut (dyn ProvisionObserver + '_)> = match &mut observer {
            Some(observer) => Some(&mut **observer),
            None => None,
        };
        ensure_inner(&dest, provisioner, reborrowed)
    }
}

/// A rootfs removal, configured then run.
///
/// The extensible form of [`remove`], and the one that names a caller-supplied
/// identity-map delegate.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
/// use ferroday_cage::IdentityMap;
/// use ferroday_cage::provision::Remove;
///
/// Remove::new("/var/lib/myapp/rootfs")
///     .map(IdentityMap::Subordinate)
///     .run()?;
/// # Ok(())
/// # }
/// ```
pub struct Remove<'a> {
    dest: PathBuf,
    map: crate::IdentityMap,
    mapper: Option<&'a dyn crate::idmap::IdMapper>,
}

impl fmt::Debug for Remove<'_> {
    /// Renders the tree, the map it was written under, and whether a
    /// caller-supplied mapper was given. The mapper renders by its presence
    /// rather than its contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Remove")
            .field("dest", &self.dest)
            .field("map", &self.map)
            .field(
                "mapper",
                &self.mapper.as_ref().map(|_| Delegate("dyn IdMapper")),
            )
            .finish()
    }
}

impl<'a> Remove<'a> {
    /// Returns a removal of the tree at `dest`.
    ///
    /// The identity map defaults to
    /// [`IdentityMap::Subordinate`](crate::IdentityMap::Subordinate), which is
    /// what a tree written by a bundled-delegate sandbox needs.
    pub fn new(dest: impl AsRef<Path>) -> Remove<'a> {
        Remove {
            dest: dest.as_ref().to_path_buf(),
            map: crate::IdentityMap::Subordinate,
            mapper: None,
        }
    }

    /// Sets the identity map the tree was written under.
    pub fn map(mut self, map: crate::IdentityMap) -> Remove<'a> {
        self.map = map;
        self
    }

    /// Removes through a caller-supplied identity-map delegate.
    ///
    /// Without one, the escalation resolves the bundled delegate chain. A tree
    /// whose ownership a site-specific mapper established — one allocating ids
    /// the bundled delegates would not — must be removed through that same
    /// mapper, so it can re-enter the map the tree was written under. The
    /// mapper and the [`map`](Self::map) must be the pair the tree was built
    /// under.
    pub fn mapper(mut self, mapper: &'a dyn crate::idmap::IdMapper) -> Remove<'a> {
        self.mapper = Some(mapper);
        self
    }

    /// Removes the tree.
    ///
    /// # Errors
    ///
    /// As [`remove`].
    pub fn run(self) -> Result<(), ProvisionError> {
        remove_dest(&self.dest, &self.map, self.mapper)
    }
}

/// Publishes a rootfs at `dest` atomically, provisioning it if absent.
///
/// The shorthand for [`Provision`], carrying only the inputs every publication
/// needs.
///
/// If `dest` already exists as a directory, it is taken as the previously
/// published rootfs and returned as [`Provisioned::Existing`] without
/// running the provisioner. Otherwise the provisioner fills a staging
/// directory beside `dest`, which is then renamed into place: `dest` only
/// ever appears complete, and an interrupted run cannot leave a
/// half-populated tree that a later caller would trust.
///
/// Concurrent calls — including from other processes — serialize on a
/// `<name>.lock` file beside `dest`; exactly one provisions and the rest
/// observe the published result. The lock file persists after the call, so a
/// later publication of the same destination serializes on the same inode;
/// [`remove`] deletes it along with the rootfs, and so also clears the one a
/// failed provision leaves beside no rootfs at all. Locking uses `flock`, so
/// `dest` should live on a local filesystem.
///
/// The lock, staging directory, and rename all operate on paths beside
/// `dest`, so `dest` must live under a directory the caller controls — not a
/// world-writable one such as a shared `/tmp`, where another user could
/// pre-plant those paths. The lock open refuses to follow a planted symlink,
/// and the staging cleanup removes a planted symlink rather than following it
/// into a removal of its target, but the parent's own path components are
/// trusted to be the caller's.
///
/// Before the rename, the staging tree's filesystem is synced, so a crash
/// after publication cannot leave truncated files behind the completed
/// rename.
///
/// # Errors
///
/// Returns [`ProvisionError::DestUnusable`] when `dest` cannot host a
/// rootfs directory, any error of the provisioner itself, and
/// [`ProvisionError::Io`] for failures of the publication machinery. When
/// the provisioner fails, the staging directory is removed and `dest` is
/// left absent.
///
/// The two cleanups — the failed run's staging tree, and a previous run's stale
/// one — escalate with [`IdentityMap::Subordinate`](crate::IdentityMap::Subordinate)
/// and the bundled delegate chain, since nothing here names a map. A tree
/// provisioned under a caller-supplied mapper, or under an explicit
/// [`IdentityMap::Ranges`](crate::IdentityMap::Ranges) the bundled chain cannot
/// reproduce, therefore surfaces as
/// [`ProvisionError::RemoveUnprivileged`] rather than being cleaned; remove it
/// with [`Remove`] and the same map and delegate that wrote it.
pub fn ensure(
    dest: impl AsRef<Path>,
    provisioner: &mut dyn Provisioner,
) -> Result<Provisioned, ProvisionError> {
    ensure_inner(dest.as_ref(), provisioner, None)
}

/// The body of [`ensure`] and [`Provision::run`].
fn ensure_inner(
    dest: &Path,
    provisioner: &mut dyn Provisioner,
    observer: Option<&mut dyn ProvisionObserver>,
) -> Result<Provisioned, ProvisionError> {
    // Fast path: a published rootfs needs no lock.
    match fs::symlink_metadata(dest) {
        Ok(meta) if meta.is_dir() => return Ok(Provisioned::Existing),
        Ok(_) => {
            return Err(ProvisionError::DestUnusable {
                path: dest.to_path_buf(),
            });
        }
        Err(_) => {}
    }

    let Some(name) = dest.file_name() else {
        return Err(ProvisionError::DestUnusable {
            path: dest.to_path_buf(),
        });
    };
    let parent = match dest.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent).map_err(|err| io_error("creating", parent, err))?;

    let mut lock_name = name.to_os_string();
    lock_name.push(".lock");
    let lock_path = parent.join(lock_name);
    // NOFOLLOW so a symlink pre-planted at the lock path (in a world-writable
    // parent) cannot redirect the lock, and with it a later write, elsewhere.
    // CLOEXEC so the helpers a provisioning run executes — an identity-map
    // delegate's `newuidmap`, say — do not inherit the descriptor and hold the
    // lock open past their own lifetimes.
    let lock = rustix::fs::open(
        &lock_path,
        OFlags::CREATE | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
    )
    .map_err(|errno| io_error("creating", &lock_path, errno.into()))?;
    loop {
        match rustix::fs::flock(&lock, FlockOperation::LockExclusive) {
            Ok(()) => break,
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(io_error("locking", &lock_path, errno.into())),
        }
    }

    // Re-check under the lock: another caller may have finished the work
    // while this one waited.
    match fs::symlink_metadata(dest) {
        Ok(meta) if meta.is_dir() => return Ok(Provisioned::Existing),
        Ok(_) => {
            return Err(ProvisionError::DestUnusable {
                path: dest.to_path_buf(),
            });
        }
        Err(_) => {}
    }

    let mut staging_name = OsString::from(".");
    staging_name.push(name);
    staging_name.push(".staging");
    let staging = parent.join(staging_name);

    // A leftover staging tree is a crashed prior run; the lock guarantees
    // no live owner. The removal escalates through the identity map, since
    // the crashed run may have been range-mapped and left subordinate-owned
    // files. Inspect without following symlinks: a symlink pre-planted at the
    // staging path (in a world-writable parent) is removed as a link, never
    // followed into a removal of whatever it points at.
    match fs::symlink_metadata(&staging) {
        Ok(meta) if meta.is_symlink() => {
            fs::remove_file(&staging).map_err(|err| io_error("removing", &staging, err))?;
        }
        Ok(_) => remove_tree(&staging, &crate::IdentityMap::Subordinate, None)?,
        Err(_) => {}
    }
    fs::create_dir(&staging).map_err(|err| io_error("creating", &staging, err))?;

    // The observer is wrapped in a cell local to this frame, so its lifetime
    // and the staging path's unify — which `RefCell`'s invariance needs.
    let outcome = match observer {
        Some(observer) => {
            let cell = ObserverCell::new(observer);
            provisioner.provision(&ProvisionRequest::new(&staging).observed(&cell))
        }
        None => provisioner.provision(&ProvisionRequest::new(&staging)),
    };
    if let Err(err) = outcome {
        let _ = remove_tree(&staging, &crate::IdentityMap::Subordinate, None);
        return Err(err);
    }

    // Sync the staging tree's filesystem before the rename, so the rename
    // cannot become durable ahead of the data it publishes.
    let staging_dir = fs::File::open(&staging).map_err(|err| io_error("opening", &staging, err))?;
    rustix::fs::syncfs(&staging_dir)
        .map_err(|errno| io_error("syncing", &staging, errno.into()))?;
    drop(staging_dir);

    fs::rename(&staging, dest).map_err(|err| io_error("publishing", dest, err))?;

    let parent_dir = fs::File::open(parent).map_err(|err| io_error("opening", parent, err))?;
    parent_dir
        .sync_all()
        .map_err(|err| io_error("syncing", parent, err))?;

    Ok(Provisioned::Created)
}

/// Removes a rootfs directory, including one a range-mapped sandbox has
/// written.
///
/// The shorthand for [`Remove`], carrying only the inputs every removal needs.
///
/// A sandbox under a [range identity map](crate::IdentityMap) writes real
/// ownership: files it chowned to non-root ids are owned by subordinate ids
/// on the host, which a plain `remove_dir_all` cannot delete. This removal
/// starts plain and, when it is refused, re-enters the same map — a forked
/// process unshares a user namespace, the bundled delegates establish the
/// subordinate map for it, and the tree is deleted from inside, where the
/// ids are the caller's own. The rootless container runtimes' `unshare rm`
/// pattern, as a library call.
///
/// Removing a path that does not exist is not an error, so the call is
/// idempotent; a path that is not a directory is removed as the file it is.
///
/// The `<name>.lock` file [`ensure`] leaves beside the destination goes with
/// it, so create and destroy round-trip and nothing is left behind. A
/// destination that was never published through `ensure` has no lock to
/// remove, and a removal of a destination whose provision failed clears the
/// lock that was left beside no rootfs.
///
/// # Errors
///
/// [`ProvisionError::Io`] for an ordinary removal failure, and
/// [`ProvisionError::RemoveUnprivileged`] when the tree needs the identity
/// map and no delegate can establish one — the reason names what the host
/// is missing.
///
/// The escalation resolves the bundled delegate chain for the subordinate
/// map, which covers a tree written under
/// [`IdentityMap::Subordinate`](crate::IdentityMap::Subordinate) or a
/// bundled-delegate [`IdentityMap::Ranges`](crate::IdentityMap::Ranges). For a
/// tree built under a caller-supplied delegate, use [`Remove::mapper`].
pub fn remove(dest: impl AsRef<Path>) -> Result<(), ProvisionError> {
    remove_dest(dest.as_ref(), &crate::IdentityMap::Subordinate, None)
}

/// The shared body of [`remove`] and [`Remove::run`]: dispatch a non-directory
/// or missing path, then remove a directory tree with the given resolution,
/// and finally the publication lock [`ensure`] left beside it.
fn remove_dest(
    dest: &Path,
    map: &crate::IdentityMap,
    mapper: Option<&dyn crate::idmap::IdMapper>,
) -> Result<(), ProvisionError> {
    match fs::symlink_metadata(dest) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(io_error("inspecting", dest, err)),
        Ok(meta) if !meta.is_dir() => {
            fs::remove_file(dest).map_err(|err| io_error("removing", dest, err))?;
        }
        Ok(_) => remove_tree(dest, map, mapper)?,
    }
    remove_lock(dest)
}

/// Removes the `<name>.lock` file [`ensure`] leaves beside a published rootfs,
/// so create and destroy round-trip and a failed provision leaves no orphan.
///
/// Removed after the tree, so a failure to delete the rootfs leaves the lock
/// guarding it. A destination that was never published through [`ensure`] has
/// no lock, which is not an error.
///
/// Removing the lock is safe only because a removal and a concurrent
/// publication of the same destination are already mutually exclusive: a caller
/// that deletes a rootfs another thread or process is provisioning has no
/// defined outcome, lock or no lock.
fn remove_lock(dest: &Path) -> Result<(), ProvisionError> {
    let (Some(name), Some(parent)) = (dest.file_name(), dest.parent()) else {
        return Ok(());
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let mut lock_name = name.to_os_string();
    lock_name.push(".lock");
    let lock_path = parent.join(lock_name);
    match fs::remove_file(&lock_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io_error("removing", &lock_path, err)),
    }
}

/// Removes a directory tree: plain removal first, escalated through the
/// identity map when ownership refuses the plain path.
///
/// The escalation re-enters `map`: a range map through `mapper` when one is
/// supplied and the bundled delegate chain otherwise, and a single-identity
/// map written by the removal child itself. The single map is worth
/// re-entering even though its ids are the caller's own already, because the
/// child holds `CAP_DAC_OVERRIDE` and `CAP_FOWNER` over them there: a
/// directory whose own mode denies the search or write the deletion needs
/// refuses the plain path and yields to the mapped one.
///
/// Also used by [`ensure`]'s staging cleanup, so a crashed provisioning run
/// cannot wedge the destination.
fn remove_tree(
    dest: &Path,
    map: &crate::IdentityMap,
    mapper: Option<&dyn crate::idmap::IdMapper>,
) -> Result<(), ProvisionError> {
    use std::os::unix::ffi::OsStrExt;

    let denied = match fs::remove_dir_all(dest) {
        Ok(()) => return Ok(()),
        // EACCES and EPERM are the ownership refusals; anything else is an
        // ordinary failure with nothing to escalate.
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => err,
        Err(err) => return Err(io_error("removing", dest, err)),
    };

    let unprivileged = |source: io::Error, reason: String| ProvisionError::RemoveUnprivileged {
        path: dest.to_path_buf(),
        source,
        reason,
    };

    // The map to re-enter: the single map the child writes itself, or the
    // delegate and extents a range map is applied through.
    let map_source = match identity::compose_child_map(map, mapper) {
        Ok(source) => source,
        Err(reason) => return Err(unprivileged(denied, reason)),
    };

    let parent = match dest.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Some(leaf) = dest.file_name() else {
        return Err(ProvisionError::DestUnusable {
            path: dest.to_path_buf(),
        });
    };
    let nul = |_| {
        io_error(
            "removing",
            dest,
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    };
    let parent_c = std::ffi::CString::new(parent.as_os_str().as_bytes()).map_err(nul)?;
    let leaf_c = std::ffi::CString::new(leaf.as_bytes()).map_err(nul)?;

    crate::mechanism::remove_tree_mapped(&parent_c, &leaf_c, map_source.child_map()).map_err(
        |failure| match failure {
            crate::mechanism::RemoveFailure::Step { step, errno } => {
                io_error(step.describe(), dest, io::Error::from_raw_os_error(errno))
            }
            crate::mechanism::RemoveFailure::Map(err) => unprivileged(denied, err.to_string()),
            crate::mechanism::RemoveFailure::Malformed => io_error(
                "reading the removal process's outcome",
                dest,
                io::Error::from_raw_os_error(Errno::PROTO.raw_os_error()),
            ),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    struct Touch;

    impl Provisioner for Touch {
        fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
            let staging = request.staging();
            fs::write(staging.join("marker"), b"provisioned")
                .map_err(|err| io_error("writing", staging, err))
        }
    }

    struct Fail;

    impl Provisioner for Fail {
        fn provision(&mut self, _request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
            Err(ProvisionError::other("deliberate failure"))
        }
    }

    fn tempdir(tag: &str) -> Scratch {
        Scratch::new(&format!("provision-{tag}"))
    }

    #[test]
    fn remove_is_idempotent_on_a_missing_path() {
        let dir = tempdir("remove-missing");
        remove(dir.join("never-created")).expect("removing nothing is not an error");
    }

    #[test]
    fn remove_deletes_a_plain_tree() {
        let dir = tempdir("remove-plain");
        let tree = dir.join("tree");
        fs::create_dir_all(tree.join("a/b")).unwrap();
        fs::write(tree.join("a/b/file"), b"x").unwrap();
        fs::write(tree.join("top"), b"y").unwrap();
        std::os::unix::fs::symlink("a", tree.join("link")).unwrap();
        remove(&tree).expect("a caller-owned tree removes plainly");
        assert!(!tree.exists());
    }

    #[test]
    fn remove_deletes_a_non_directory() {
        let dir = tempdir("remove-file");
        let file = dir.join("file");
        fs::write(&file, b"x").unwrap();
        remove(&file).expect("a plain file is removed as itself");
        assert!(!file.exists());
    }

    #[test]
    fn ensure_creates_then_reuses() {
        let dir = tempdir("create");
        let dest = dir.join("rootfs");
        assert_eq!(ensure(&dest, &mut Touch).unwrap(), Provisioned::Created);
        assert!(dest.join("marker").is_file());
        assert_eq!(ensure(&dest, &mut Fail).unwrap(), Provisioned::Existing);
    }

    #[test]
    fn ensure_failure_leaves_no_dest_and_no_staging() {
        let dir = tempdir("fail");
        let dest = dir.join("rootfs");
        let err = ensure(&dest, &mut Fail).unwrap_err();
        assert!(matches!(err, ProvisionError::Other { .. }), "{err}");
        assert!(!dest.exists());
        assert!(!dir.join(".rootfs.staging").exists());
    }

    #[test]
    fn remove_takes_the_publication_lock_with_the_rootfs() {
        let dir = tempdir("lock-round-trip");
        let dest = dir.join("rootfs");
        let lock = dir.join("rootfs.lock");
        assert_eq!(ensure(&dest, &mut Touch).unwrap(), Provisioned::Created);
        assert!(lock.is_file(), "ensure takes a lock beside the destination");
        remove(&dest).expect("the published rootfs is removed");
        assert!(!dest.exists());
        assert!(!lock.exists(), "the lock goes with the rootfs");
    }

    #[test]
    fn remove_clears_the_lock_a_failed_provision_left_behind() {
        let dir = tempdir("lock-orphan");
        let dest = dir.join("rootfs");
        let lock = dir.join("rootfs.lock");
        ensure(&dest, &mut Fail).unwrap_err();
        assert!(!dest.exists());
        assert!(lock.is_file(), "the failed run left its lock behind");
        // The destination is already absent, so this is the idempotent path;
        // it still clears the orphan.
        remove(&dest).expect("removing an absent rootfs is not an error");
        assert!(!lock.exists());
    }

    #[test]
    fn ensure_rejects_a_non_directory_dest() {
        let dir = tempdir("nondir");
        let dest = dir.join("rootfs");
        fs::write(&dest, b"file in the way").unwrap();
        let err = ensure(&dest, &mut Touch).unwrap_err();
        assert!(matches!(err, ProvisionError::DestUnusable { .. }), "{err}");
    }

    #[test]
    fn ensure_clears_stale_staging() {
        let dir = tempdir("stale");
        let dest = dir.join("rootfs");
        let staging = dir.join(".rootfs.staging");
        fs::create_dir_all(staging.join("leftover")).unwrap();
        assert_eq!(ensure(&dest, &mut Touch).unwrap(), Provisioned::Created);
        assert!(dest.join("marker").is_file());
        assert!(!dest.join("leftover").exists());
        assert!(!staging.exists());
    }

    #[test]
    fn ensure_serializes_concurrent_callers() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static RUNS: AtomicUsize = AtomicUsize::new(0);

        struct Counting;

        impl Provisioner for Counting {
            fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
                let staging = request.staging();
                RUNS.fetch_add(1, Ordering::SeqCst);
                // Stay in the provisioner long enough that the other
                // threads pile up on the lock.
                std::thread::sleep(std::time::Duration::from_millis(50));
                fs::write(staging.join("marker"), b"x")
                    .map_err(|err| io_error("writing", staging, err))
            }
        }

        let dir = tempdir("concurrent");
        let dest = dir.join("rootfs");
        let outcomes: Vec<Provisioned> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| ensure(&dest, &mut Counting).unwrap()))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(RUNS.load(Ordering::SeqCst), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == Provisioned::Created)
                .count(),
            1
        );
    }
}
