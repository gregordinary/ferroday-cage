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
    doc = "
With the `tarball` feature, [`Tarball`] provisions from a tar archive
(plain, gzip, xz, or zstd, detected by content), extracting with
kernel-enforced containment so a hostile archive cannot write outside
the destination.

"
)]
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

use crate::failure::path_io_error;
use crate::mechanism::frame;

#[cfg(any(feature = "debian", feature = "alpine"))]
mod binfmt;
#[cfg(feature = "tarball")]
mod compress;
pub(crate) mod containment;
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
mod coordinate;
mod copyin;
#[cfg(feature = "tarball")]
mod export;
#[cfg(feature = "tarball")]
mod extract;
// The transport seam and the digesting that verifies what it brings back serve
// every userland provisioner that talks to an archive, so they are compiled for
// each of them rather than gaining a feature of their own — a feature nothing
// could enable on purpose would only widen the powerset the `features` job
// walks. Each such gate names all three layers, and gains the next one the same
// way.
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
mod digest;
// The plan document's syntax, which every userland layer's plan is written in
// -- and, for Gentoo, the syntax its archive publishes its binary-package index
// in as well.
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
mod document;
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
mod fetch;
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
mod http;
mod identity;
// The overlay upper a layered build installs into, which is a disposal handle
// rather than anything one userland knows about.
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
mod layer;
// Establishing that a cleartext-signed document is authentic against a keyring,
// which is a question about the signature rather than about any archive that
// asks it. Alpine verifies RSA PKCS#1 over its own containers and reaches none
// of this, so the gate names the two layers whose trust chains are OpenPGP.
#[cfg(any(feature = "debian", feature = "gentoo"))]
mod openpgp;
pub(crate) mod rooted;
#[cfg(feature = "tarball")]
mod tar;
#[cfg(feature = "tarball")]
mod tarball;

pub use copyin::{CopyIn, CopyReport, SkippedEntry, SkippedKind};
#[cfg(feature = "tarball")]
pub use export::{Export, ExportEntry, ExportKind, export_tar};
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
pub(crate) use fetch::{Failover, mirror_url, walk_mirrors};
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
pub use fetch::{Fetch, FetchError, FetchJob, FetchRequest};
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
pub use http::{HttpFetch, file_url};
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
pub use layer::BuildLayer;
#[cfg(feature = "tarball")]
pub use tarball::Tarball;

#[cfg(feature = "alpine")]
pub mod alpine;
#[cfg(feature = "debian")]
pub mod debian;
#[cfg(feature = "gentoo")]
pub mod gentoo;

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
    /// An Alpine bootstrap's own, richer event.
    ///
    /// The bootstrap reports fetches, resolution, downloads, and the output of
    /// the install scripts it runs in a cage — detail the shared vocabulary
    /// above has no place for. Nesting it here keeps one observer for every
    /// provisioner rather than one per provisioner.
    #[cfg(feature = "alpine")]
    Alpine(&'a alpine::AlpineEvent<'a>),
    /// A Gentoo bootstrap's own event.
    ///
    /// The bootstrap reports the documents it fetches, what it resolved, and
    /// the verification and extraction of the tarball — detail the shared
    /// vocabulary above has no place for. Nesting it here keeps one observer for
    /// every provisioner rather than one per provisioner.
    #[cfg(feature = "gentoo")]
    Gentoo(&'a gentoo::GentooEvent<'a>),
}

/// A standard stream of a command a provisioner runs in a cage.
///
/// Every userland layer's own event carries this in its `CommandOutput` variant,
/// which is why it is here rather than in one of them: a provisioner that runs a
/// command in a cage has output to attribute to a stream whichever archive it
/// provisions from, and the attribution says nothing about the archive. The
/// events themselves stay with their layers, nested in [`ProvisionEvent`] — they
/// speak each archive's own vocabulary, and this does not.
#[cfg(any(feature = "debian", feature = "alpine"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
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
    /// The entry's path or hardlink target is absolute, contains `..`, or
    /// carries a NUL byte that would truncate it, or its path resolves through
    /// a magic link or a symlink loop. A symbolic link in the tree resolves
    /// inside the rootfs being extracted, as it does for the root itself, so it
    /// carries no entry outside: one naming a host path names the rootfs's own
    /// path of that name. Containment is enforced by the kernel during path
    /// resolution, not by inspecting the path text.
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
    /// An export's destination file lies inside the tree being exported.
    ///
    /// The archive would be a member of its own source: the walk reaches the
    /// file it is being written to, and what lands in the archive depends on
    /// how far the encoder had got when the walk arrived there. Reported by
    /// [`Export::write_to_path`], which names the destination and so can see
    /// it; [`Export::write_to`] takes a sink it cannot locate, and a caller
    /// that opens a file inside the tree itself gets the archive it asked for.
    #[cfg(feature = "tarball")]
    #[non_exhaustive]
    ExportDestInside {
        /// The destination as it was given.
        path: PathBuf,
        /// The tree it lies inside.
        rootfs: PathBuf,
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
        doc = "
It is the mirror of [`ExportUnprivileged`](Self::ExportUnprivileged),
which arises for the same reason.
"
    )]
    #[non_exhaustive]
    CopyUnprivileged {
        /// The rootfs that could not be copied into.
        path: PathBuf,
        /// Why no delegate could establish the identity map.
        reason: String,
    },
    /// A file changed while it was being read, so the result could not
    /// reproduce it.
    ///
    /// A [`CopyIn`] reports it for a file in its source, and an export for a
    /// file in the tree it archives. Both commit a file's length before they
    /// read its contents, and the far side of the walk counts exactly that many
    /// bytes. A file that grew or shrank in between is therefore written
    /// truncated or zero-padded, and the run reports this rather than
    /// presenting the result as a copy. A copy also reports a name that stopped
    /// naming the file it had inspected before it opened it. A tree changing
    /// underneath a walk is something the caller would rather hear about than
    /// discover later.
    #[non_exhaustive]
    SourceChanged {
        /// The file that changed.
        path: PathBuf,
        /// The length the walk recorded for it.
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
}

path_io_error! {
    ProvisionError,
    /// ```
    /// use std::fs;
    ///
    /// use ferroday_cage::provision::ProvisionError;
    ///
    /// # fn read(path: &std::path::Path) -> Result<Vec<u8>, ProvisionError> {
    /// fs::read(path).map_err(ProvisionError::at("reading", path))
    /// # }
    /// ```
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
                "{} changed while it was being read: {recorded} bytes were recorded for it, \
                 which is no longer what it holds",
                path.display(),
            ),
            #[cfg(feature = "tarball")]
            ProvisionError::ExportUnprivileged { path, reason } => write!(
                f,
                "cannot export {}: the tree holds ids owned through a range identity map, \
                 and no delegate can establish the map to read them ({reason})",
                path.display(),
            ),
            #[cfg(feature = "tarball")]
            ProvisionError::ExportDestInside { path, rootfs } => write!(
                f,
                "cannot write the archive to {}: it lies inside {}, the tree being exported, \
                 so the archive would be a member of itself",
                path.display(),
                rootfs.display(),
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
/// render its own. It does not, for two reasons: `Fetch` and
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
    /// The overlay work directory removed after `dest`, for a removal of an
    /// overlay upper.
    work: Option<PathBuf>,
    map: crate::IdentityMap,
    mapper: Option<&'a dyn crate::idmap::IdMapper>,
    remove_lock: bool,
}

impl fmt::Debug for Remove<'_> {
    /// Renders the tree, the overlay work directory removed with it, the map
    /// both were written under, whether a caller-supplied mapper was given, and
    /// whether the publication lock is removed with the tree. The mapper
    /// renders by its presence rather than its contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Remove")
            .field("dest", &self.dest)
            .field("work", &self.work)
            .field("map", &self.map)
            .field(
                "mapper",
                &self.mapper.as_ref().map(|_| Delegate("dyn IdMapper")),
            )
            .field("remove_lock", &self.remove_lock)
            .finish()
    }
}

impl<'a> Remove<'a> {
    /// Returns a removal of the tree at `dest`.
    ///
    /// The identity map defaults to
    /// [`IdentityMap::Subordinate`](crate::IdentityMap::Subordinate), which is
    /// what a tree written by a bundled-delegate sandbox needs.
    ///
    /// The publication lock beside `dest` is removed with the tree, matching
    /// [`remove`]; [`remove_lock(false)`](Self::remove_lock) is how a caller
    /// whose `dest` is not itself a published rootfs declines that.
    pub fn new(dest: impl AsRef<Path>) -> Remove<'a> {
        Remove {
            dest: dest.as_ref().to_path_buf(),
            work: None,
            map: crate::IdentityMap::Subordinate,
            mapper: None,
            remove_lock: true,
        }
    }

    /// Returns a removal of the upper layer of an overlay root, together with
    /// the work directory the library manages beside it.
    ///
    /// Discarding the upper is how a run on
    /// [`overlay_rootfs`](crate::CageBuilder::overlay_rootfs) is reverted. The
    /// overlay also needs a work directory on the upper's filesystem, which the
    /// library creates as a hidden sibling of the upper and the kernel fills
    /// with a directory of mode `0`. This removes both, so nothing the overlay
    /// root created outlives it.
    ///
    /// Name the identity map the sandbox ran under with [`map`](Self::map): a
    /// sandbox's own default is
    /// [`IdentityMap::Single`](crate::IdentityMap::Single), while this
    /// builder's is the subordinate map. The map decides how an entry the
    /// calling user cannot remove is removed, so a tree a range-mapped sandbox
    /// wrote needs its map, and a single-mapped one needs no subordinate ids.
    ///
    /// The publication lock is not removed: an upper is not a published rootfs,
    /// so a `<upper>.lock` beside it is a path this removal has no claim to. An
    /// overlay that names its own work directory through
    /// [`Overlay::work`](crate::Overlay::work) removes that directory with a
    /// [`Remove::new`] of its own, with the lock declined.
    pub fn overlay_upper(upper: impl AsRef<Path>) -> Remove<'a> {
        let upper = upper.as_ref();
        Remove {
            dest: upper.to_path_buf(),
            work: crate::spec::overlay_work_dir(upper),
            map: crate::IdentityMap::Subordinate,
            mapper: None,
            remove_lock: false,
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

    /// Sets whether the `<dest>.lock` sibling goes with the tree.
    ///
    /// Defaults to `true`, because [`ensure`] wrote that file and a published
    /// rootfs and its lock round-trip together. Pass `false` for a `dest` that
    /// merely *contains* published rootfs trees rather than being one — a
    /// scratch directory, a cache, a work area holding several. There
    /// `<dest>.lock` is an unrelated path that the caller never named as a
    /// target, and removing it is a deletion outside the tree the caller asked
    /// about.
    ///
    /// The distinction is the caller's to make, because only the caller knows
    /// which of the two its `dest` is: both are directories, and a containing
    /// directory that happens to have no `.lock` sibling today is
    /// indistinguishable from a published one whose lock was already cleared.
    ///
    /// The tree itself is removed identically either way; this governs the
    /// sibling file only.
    ///
    /// The lock is also what a removal holds while it runs. A removal that
    /// takes the lock waits for a publication of the same destination to
    /// finish, and a publication waits for the removal in turn, so neither
    /// sees the other half done. A removal that declines the lock takes no part
    /// in that exclusion.
    pub fn remove_lock(mut self, remove: bool) -> Remove<'a> {
        self.remove_lock = remove;
        self
    }

    /// Removes the tree, and the overlay work directory beside it for an
    /// [`overlay_upper`](Self::overlay_upper) removal.
    ///
    /// # Errors
    ///
    /// As [`remove`].
    pub fn run(self) -> Result<(), ProvisionError> {
        remove_dest(&self.dest, &self.map, self.mapper, self.remove_lock)?;
        match &self.work {
            Some(work) => remove_dest(work, &self.map, self.mapper, false),
            None => Ok(()),
        }
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
    fs::create_dir_all(parent).map_err(|err| ProvisionError::io("creating", parent, err))?;

    let lock_path = parent.join(lock_name(name));
    // Held until this function returns, on the failure paths as on success.
    let _lock =
        lock_exclusive(&lock_path).map_err(|err| ProvisionError::io("locking", &lock_path, err))?;

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
    // files. The removal never follows a symlink at the staging path: one
    // pre-planted there (in a world-writable parent) is removed as a link,
    // never followed into a removal of whatever it points at.
    match fs::symlink_metadata(&staging) {
        Ok(_) => remove_tree(&staging, &crate::IdentityMap::Subordinate, None)?,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(ProvisionError::io("inspecting", &staging, err)),
    }
    fs::create_dir(&staging).map_err(|err| ProvisionError::io("creating", &staging, err))?;

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
    let staging_dir =
        fs::File::open(&staging).map_err(|err| ProvisionError::io("opening", &staging, err))?;
    rustix::fs::syncfs(&staging_dir)
        .map_err(|errno| ProvisionError::io("syncing", &staging, errno.into()))?;
    drop(staging_dir);

    fs::rename(&staging, dest).map_err(|err| ProvisionError::io("publishing", dest, err))?;

    let parent_dir =
        fs::File::open(parent).map_err(|err| ProvisionError::io("opening", parent, err))?;
    parent_dir
        .sync_all()
        .map_err(|err| ProvisionError::io("syncing", parent, err))?;

    Ok(Provisioned::Created)
}

/// Removes a rootfs directory, including one a range-mapped sandbox has
/// written.
///
/// The shorthand for [`Remove`], carrying only the inputs every removal needs.
///
/// A sandbox under a [range identity map](crate::IdentityMap) writes real
/// ownership: files it chowned to non-root ids are owned by subordinate ids
/// on the host, which the calling user cannot delete. This removal starts as
/// the calling user and, when ownership or a directory's own mode refuses it,
/// re-enters the same map. A forked process unshares a user namespace, the
/// bundled delegates establish the subordinate map for it, and the tree is
/// deleted from inside, where the ids are the caller's own. The rootless
/// container runtimes' `unshare rm` pattern, as a library call.
///
/// Both attempts walk the tree iteratively, holding a few descriptors and no
/// stack per level, and never follow a symbolic link. A tree a sandbox nested
/// arbitrarily deep therefore costs what a shallow one does, where a recursive
/// removal would exhaust the descriptor table or the stack.
///
/// Removing a path that does not exist is not an error, so the call is
/// idempotent; a path that is not a directory is removed as the file it is.
///
/// The `<name>.lock` file [`ensure`] leaves beside the destination goes with
/// it, so create and destroy round-trip and nothing is left behind. The removal
/// holds that lock while it runs, so it waits for a publication of the same
/// destination in progress, and one that starts meanwhile waits for it. A
/// destination that was never published through `ensure` has no lock to
/// remove, and a removal of a destination whose provision failed clears the
/// lock that was left beside no rootfs. A caller whose destination *contains*
/// published trees rather than being one wants
/// [`Remove::remove_lock(false)`](Remove::remove_lock) instead, so the sibling
/// of a path it never published stays where it is.
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
    remove_dest(dest.as_ref(), &crate::IdentityMap::Subordinate, None, true)
}

/// The shared body of [`remove`] and [`Remove::run`]: take the publication lock
/// [`ensure`] keeps beside `dest`, remove whatever is at `dest` with the given
/// resolution, and delete the lock file while still holding it.
///
/// `lock` says whether the lock takes part at all. [`Remove::remove_lock`]
/// clears it, for a `dest` that holds published trees rather than being one.
///
/// The lock file is deleted after the tree, so a failure to delete the rootfs
/// leaves the lock guarding it. Deleting it while it is held is what keeps a
/// waiting publication honest: the publication is granted a lock on a file no
/// longer at the path, notices, and takes the lock again on the file a later
/// caller creates there, rather than proceeding beside it. A destination that
/// was never published through [`ensure`] has no lock until this creates one
/// to hold, which is not a way to tell a published destination from a
/// containing one: that is why [`Remove::remove_lock`] is a caller-supplied
/// flag rather than this probing for it.
fn remove_dest(
    dest: &Path,
    map: &crate::IdentityMap,
    mapper: Option<&dyn crate::idmap::IdMapper>,
    lock: bool,
) -> Result<(), ProvisionError> {
    let held = match lock_path(dest).filter(|_| lock) {
        // Nothing at either path is nothing to remove and no lock to delete,
        // so there is no publication to exclude, and no lock file to create in
        // a directory that may not take one.
        Some(path) if !occupied(dest)? && !occupied(&path)? => return Ok(()),
        Some(path) => match lock_exclusive(&path) {
            Ok(held) => Some((path, held)),
            // The destination's directory went away in between, and with it
            // anything to remove.
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(ProvisionError::io("locking", &path, err)),
        },
        None => None,
    };

    match fs::symlink_metadata(dest) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(ProvisionError::io("inspecting", dest, err)),
        Ok(_) => remove_tree(dest, map, mapper)?,
    }

    if let Some((path, _held)) = held {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(ProvisionError::io("removing", &path, err)),
        }
    }
    Ok(())
}

/// Whether anything is at `path`, a symbolic link included, without following
/// one.
fn occupied(path: &Path) -> Result<bool, ProvisionError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(ProvisionError::io("inspecting", path, err)),
    }
}

/// The name of the publication lock [`ensure`] keeps beside a destination of
/// this name: `<name>.lock`.
fn lock_name(name: &std::ffi::OsStr) -> OsString {
    let mut lock = name.to_os_string();
    lock.push(".lock");
    lock
}

/// The path of the publication lock beside `dest`, or `None` for a path with no
/// final component, which [`ensure`] refuses to publish at.
fn lock_path(dest: &Path) -> Option<PathBuf> {
    let name = dest.file_name()?;
    let parent = match dest.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Some(parent.join(lock_name(name)))
}

/// How many times [`lock_exclusive`] takes its lock again after the file it
/// locked was removed from the path while it waited.
///
/// One retry answers an ordinary removal; each further one needs another
/// removal to complete in the moment between an open and its lock. The bound
/// exists for the reason the resolution retries have one: the lock file sits
/// in a directory this crate does not control, and something deleting it in a
/// loop must not be able to hold a caller in this one forever.
const LOCK_ATTEMPTS: u32 = 16;

/// Takes an exclusive `flock` on the lock file at `path`, creating it if
/// absent, and returns the descriptor that holds it. Dropping the descriptor
/// releases the lock.
///
/// The one answer to taking a lock file, which [`ensure`] serializes
/// publications on and the Debian pool serializes its publishes on:
///
/// - `O_NOFOLLOW`, so a symbolic link pre-planted at the path cannot redirect
///   the lock, and with it the work the lock serializes, elsewhere.
/// - `O_CLOEXEC`, so a process the holder spawns does not inherit the
///   descriptor. A `flock` belongs to the open file description, so an
///   inherited copy keeps the lock held until that process exits as well,
///   whenever the holder itself lets go.
/// - Once the lock is granted, the path is checked to still name the file that
///   was locked. A removal deletes a lock file while it holds it, and a caller
///   that had opened the file before the deletion is granted a lock no later
///   caller can see. It takes the lock again on the file now at the path.
///
/// The wait for the lock is unbounded, which is what a caller that meets
/// contention wants: the work behind the lock rather than an error.
pub(crate) fn lock_exclusive(path: &Path) -> io::Result<std::os::fd::OwnedFd> {
    for _ in 0..LOCK_ATTEMPTS {
        let lock = rustix::fs::open(
            path,
            OFlags::CREATE | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
        )?;
        // The call `clippy.toml` sends every other site here for: this is
        // that answer.
        #[expect(clippy::disallowed_methods)]
        let locked = frame::retry_on_intr!(rustix::fs::flock(&lock, FlockOperation::LockExclusive));
        locked?;
        let held = rustix::fs::fstat(&lock)?;
        match rustix::fs::lstat(path) {
            Ok(named) if named.st_dev == held.st_dev && named.st_ino == held.st_ino => {
                return Ok(lock);
            }
            // Removed, or removed and created again, while this waited.
            Ok(_) | Err(Errno::NOENT) => continue,
            Err(errno) => return Err(errno.into()),
        }
    }
    Err(Errno::AGAIN.into())
}

/// Removes whatever is at `dest` — a directory tree, a file, a symbolic link —
/// as the calling user first, escalated through the identity map when
/// ownership or a directory's own mode refuses that.
///
/// Both attempts take [`delete_tree`](crate::mechanism::delete_tree)'s walk:
/// iterative, a few descriptors at any depth, never following a symbolic link.
/// It is the answer to removing a tree untrusted code may have written, where
/// `std::fs::remove_dir_all` recurses with a descriptor and a stack frame per
/// level and a sandbox can nest a tree deep enough to exhaust either.
///
/// The escalation re-enters `map`: a range map through `mapper` when one is
/// supplied and the bundled delegate chain otherwise, and a single-identity
/// map written by the removal child itself. The single map is worth
/// re-entering even though its ids are the caller's own already, because the
/// child holds `CAP_DAC_OVERRIDE` and `CAP_FOWNER` over them there: a
/// directory whose own mode denies the search or write the deletion needs
/// refuses the caller and yields to the mapped child.
///
/// Only those refusals, `EACCES` and `EPERM`, escalate. Every other failure is
/// one the mapped child would meet in the same place — a read-only filesystem,
/// a mount point in the tree — and is reported as the caller's own, rather than
/// as an escalation that a host without a delegate could not attempt.
///
/// Also used by [`ensure`]'s staging cleanup, so a crashed provisioning run
/// cannot wedge the destination.
pub(crate) fn remove_tree(
    dest: &Path,
    map: &crate::IdentityMap,
    mapper: Option<&dyn crate::idmap::IdMapper>,
) -> Result<(), ProvisionError> {
    use std::os::unix::ffi::OsStrExt;

    let (parent, leaf) = parent_and_leaf(dest)?;
    let denied = match delete_in_process(parent, &leaf) {
        Ok(()) => return Ok(()),
        Err(errno @ (Errno::ACCESS | Errno::PERM)) => io::Error::from(errno),
        Err(errno) => return Err(ProvisionError::io("removing", dest, errno.into())),
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

    let parent_c = std::ffi::CString::new(parent.as_os_str().as_bytes()).map_err(|_| {
        ProvisionError::io(
            "removing",
            dest,
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;

    crate::mechanism::remove_tree_mapped(&parent_c, &leaf, map_source.child_map()).map_err(
        |failure| match failure {
            crate::mechanism::RemoveFailure::Step { step, errno } => {
                ProvisionError::io(step.describe(), dest, io::Error::from_raw_os_error(errno))
            }
            crate::mechanism::RemoveFailure::Map(err) => unprivileged(denied, err.to_string()),
            crate::mechanism::RemoveFailure::Malformed => ProvisionError::io(
                "reading the removal process's outcome",
                dest,
                io::Error::from_raw_os_error(Errno::PROTO.raw_os_error()),
            ),
        },
    )
}

/// `dest`'s directory and final component, in the shapes the removal walk takes
/// them: a path to open and a name to resolve against it.
fn parent_and_leaf(dest: &Path) -> Result<(&Path, std::ffi::CString), ProvisionError> {
    use std::os::unix::ffi::OsStrExt;

    let Some(leaf) = dest.file_name() else {
        return Err(ProvisionError::DestUnusable {
            path: dest.to_path_buf(),
        });
    };
    let parent = match dest.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let leaf = std::ffi::CString::new(leaf.as_bytes()).map_err(|_| {
        ProvisionError::io(
            "removing",
            dest,
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;
    Ok((parent, leaf))
}

/// Deletes `leaf` under the directory at `parent` as the calling user, through
/// the walk every removal takes.
fn delete_in_process(parent: &Path, leaf: &std::ffi::CStr) -> Result<(), Errno> {
    let parent = rustix::fs::open(
        parent,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    crate::mechanism::delete_tree(std::os::fd::AsFd::as_fd(&parent), leaf)
}

/// A writer that forwards to an inner writer until a byte ceiling is crossed,
/// then fails.
///
/// It bounds what an untrusted producer can make the caller buffer, in the one
/// place the bound cannot be ignored. A mirror is free to answer a request for
/// a few megabytes with gigabytes whatever its framing claimed, and a
/// caller-supplied [`Fetch`] is free to ignore the size a request declares; a
/// gzip segment is free to expand a kilobyte into a gigabyte. In every case the
/// digest that would catch the substitution runs only after the bytes have been
/// spent, so the sink is where the ceiling belongs.
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
pub(crate) struct LimitedWriter<W> {
    inner: W,
    remaining: u64,
}

#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
impl<W: io::Write> LimitedWriter<W> {
    /// Wraps `inner`, failing the write that would carry it past `limit` bytes
    /// in total.
    ///
    /// Generic over the writer rather than fixed to a `&mut dyn Write`, because
    /// a batched fetch hands each job a sink of its own to own for the length
    /// of the batch. A borrowed writer still fits: `&mut W` is a `Write`.
    pub(crate) fn new(inner: W, limit: u64) -> LimitedWriter<W> {
        LimitedWriter {
            inner,
            remaining: limit,
        }
    }

    /// The writer back, once the cap has done its work.
    pub(crate) fn into_inner(self) -> W {
        self.inner
    }
}

#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
impl<W: io::Write> io::Write for LimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() as u64 > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the stream exceeded the maximum size accepted for it",
            ));
        }
        let written = self.inner.write(buf)?;
        self.remaining -= written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The current time as a Unix timestamp, or `None` if the clock is before
/// the epoch (which would make a freshness check meaningless).
///
/// Here rather than in any one layer because reading the wall clock is nobody's
/// question: a signature's validity window, a release's deadline, and the
/// timestamp a published pool stamps are three layers' worth of caller, and a
/// second reading of the clock is a second answer to when it is.
#[cfg(any(feature = "debian", feature = "gentoo"))]
pub(crate) fn now_epoch() -> Option<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|since| since.as_secs() as i64)
}

/// The path of a staging file for `dest`: a hidden name beside it, unique to
/// the call that asked for it.
///
/// The name is unique so that concurrent writers of one destination — provisions
/// sharing a package cache, publishers sharing a pool, two threads exporting to
/// one archive — each stage their own file and each publish it with a rename. A
/// staging name shared between them would let one writer's rename consume the
/// other's file, publishing a file still being written and failing the second
/// writer with `ENOENT`. A name keyed to the process alone is shared that way by
/// every thread in it.
///
/// The staging file is a sibling of the destination, so the rename that
/// publishes it stays within one directory and one filesystem. A caller creates
/// it exclusively, which is what establishes that the name is the caller's
/// alone; nothing already at the name is ever removed to make room.
#[cfg(feature = "tarball")]
fn staging_path(dest: &Path) -> PathBuf {
    let dir = dest.parent().unwrap_or(Path::new("."));
    let name = dest.file_name().unwrap_or(dest.as_os_str());
    let mut staging = OsString::from(".");
    staging.push(name);
    staging.push(format!(".{}.partial", crate::host::unique_hex()));
    dir.join(staging)
}

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
/// removes the staging tree, and [`remove`] removes the destination and its
/// lock, neither of which this is.
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
pub(crate) struct PackageCache {
    path: PathBuf,
    owned: bool,
}

#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
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
    /// Answered on its own so a caller can tell whether a directory it was
    /// handed is that one, which the run would remove as its own.
    pub(crate) fn derived(tree: &Path, suffix: &str) -> PathBuf {
        let mut sibling = tree.as_os_str().to_os_string();
        sibling.push(suffix);
        PathBuf::from(sibling)
    }

    /// The directory itself, to download into and to read back from.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
impl Drop for PackageCache {
    fn drop(&mut self) {
        if self.owned {
            // Best effort, as a drop must be. The cache holds what the run
            // downloaded, all of it the calling user's own.
            let _ = remove_tree(&self.path, &crate::IdentityMap::Single, None);
        }
    }
}

/// Writes bytes to `dest` atomically, via a staging file in its directory and a
/// rename onto the destination.
///
/// This is how the Debian layer publishes a cache entry — a fetched index, a
/// downloaded package, a pool file — so that two processes provisioning at once
/// cannot show each other a half-written file. The Alpine and Gentoo layers
/// stage and rename through [`staging_path`] at the point they stream a body to
/// disk instead, because what they publish arrives as a stream rather than as
/// bytes already in hand.
///
/// The staging file is created exclusively, which establishes that the name is
/// this call's alone and refuses a symlink pre-planted at it rather than writing
/// through it. [`staging_path`] describes why the name is unique per call.
///
/// The staging file is not synced before the rename. What a reader takes from
/// these files is verified against a digest, so a file left short by a crash is
/// rejected and written again, which is cheaper than syncing every write against
/// a failure that costs only a repeat.
///
/// Errors name the staging file only when the failure is the staging file's
/// own; the caller wraps them against the destination it asked for.
#[cfg(feature = "debian")]
pub(crate) fn write_atomically(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    let tmp = staging_path(dest);

    // Only a failure after this point removes the staging file: the exclusive
    // create is what establishes that the name is this call's alone, so a
    // cleanup ahead of it could delete a file the caller does not own.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;

    // Leaving a staging file behind would accumulate in a directory that
    // outlives the call, since no later one reuses the name.
    if let Err(err) = file.write_all(bytes) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    drop(file);

    fs::rename(&tmp, dest).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
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
                .map_err(|err| ProvisionError::io("writing", staging, err))
        }
    }

    struct Fail;

    impl Provisioner for Fail {
        fn provision(&mut self, _request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
            Err(ProvisionError::other("deliberate failure"))
        }
    }
    #[test]
    fn remove_is_idempotent_on_a_missing_path() {
        let dir = Scratch::for_test("provision", "remove-missing");
        remove(dir.join("never-created")).expect("removing nothing is not an error");
    }

    #[test]
    fn removing_nothing_creates_no_lock_and_needs_no_write() {
        // The removal holds the publication lock only where there is something
        // to remove or a lock to delete; with neither, it touches nothing, so a
        // directory the caller cannot write is no obstacle to removing nothing.
        use std::os::unix::fs::PermissionsExt;

        let dir = Scratch::for_test("provision", "remove-nothing");
        let sealed = dir.join("sealed");
        fs::create_dir(&sealed).unwrap();
        fs::set_permissions(&sealed, fs::Permissions::from_mode(0o555)).unwrap();
        remove(sealed.join("never-created")).expect("removing nothing is not an error");
        assert_eq!(
            fs::read_dir(&sealed).unwrap().count(),
            0,
            "the removal left a lock"
        );
        fs::set_permissions(&sealed, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn remove_deletes_a_plain_tree() {
        let dir = Scratch::for_test("provision", "remove-plain");
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
        let dir = Scratch::for_test("provision", "remove-file");
        let file = dir.join("file");
        fs::write(&file, b"x").unwrap();
        remove(&file).expect("a plain file is removed as itself");
        assert!(!file.exists());
    }

    #[test]
    fn ensure_creates_then_reuses() {
        let dir = Scratch::for_test("provision", "create");
        let dest = dir.join("rootfs");
        assert_eq!(ensure(&dest, &mut Touch).unwrap(), Provisioned::Created);
        assert!(dest.join("marker").is_file());
        assert_eq!(ensure(&dest, &mut Fail).unwrap(), Provisioned::Existing);
    }

    #[test]
    fn ensure_failure_leaves_no_dest_and_no_staging() {
        let dir = Scratch::for_test("provision", "fail");
        let dest = dir.join("rootfs");
        let err = ensure(&dest, &mut Fail).unwrap_err();
        assert!(matches!(err, ProvisionError::Other { .. }), "{err}");
        assert!(!dest.exists());
        assert!(!dir.join(".rootfs.staging").exists());
    }

    #[test]
    fn remove_takes_the_publication_lock_with_the_rootfs() {
        let dir = Scratch::for_test("provision", "lock-round-trip");
        let dest = dir.join("rootfs");
        let lock = dir.join("rootfs.lock");
        assert_eq!(ensure(&dest, &mut Touch).unwrap(), Provisioned::Created);
        assert!(lock.is_file(), "ensure takes a lock beside the destination");
        remove(&dest).expect("the published rootfs is removed");
        assert!(!dest.exists());
        assert!(!lock.exists(), "the lock goes with the rootfs");
    }

    #[test]
    fn declining_the_lock_removes_the_tree_and_leaves_the_sibling() {
        // A caller whose `dest` holds published trees rather than being one:
        // the `.lock` beside it belongs to whoever wrote it, and was never a
        // target of this removal.
        let dir = Scratch::for_test("provision", "keep-lock");
        let dest = dir.join("work");
        let sibling = dir.join("work.lock");
        assert_eq!(ensure(&dest, &mut Touch).unwrap(), Provisioned::Created);
        assert!(sibling.is_file());
        Remove::new(&dest)
            .remove_lock(false)
            .run()
            .expect("the tree is removed");
        assert!(!dest.exists(), "the tree itself goes either way");
        assert!(
            sibling.is_file(),
            "the sibling is not this removal's to take"
        );
    }

    #[test]
    fn a_removal_takes_the_lock_unless_asked_not_to() {
        // The builder defaults to `remove`'s behaviour, so reaching for
        // `Remove` to name a map does not silently change what is deleted.
        let dir = Scratch::for_test("provision", "builder-lock");
        let dest = dir.join("rootfs");
        let lock = dir.join("rootfs.lock");
        assert_eq!(ensure(&dest, &mut Touch).unwrap(), Provisioned::Created);
        Remove::new(&dest).run().expect("the rootfs is removed");
        assert!(!lock.exists(), "the default is the round-trip");
    }

    #[test]
    fn remove_clears_the_lock_a_failed_provision_left_behind() {
        let dir = Scratch::for_test("provision", "lock-orphan");
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
    fn a_lock_is_not_inherited_by_a_process_its_holder_spawns() {
        // A `flock` belongs to the open file description, so a child that
        // inherited the descriptor would keep the lock held after the holder
        // let go -- a publish that returned, with its destination still locked
        // for as long as something it spawned lives on.
        let dir = Scratch::for_test("provision", "lock-cloexec");
        let path = dir.join("held.lock");
        let held = lock_exclusive(&path).expect("the lock is taken");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("a process is spawned while the lock is held");
        drop(held);

        let other = rustix::fs::open(&path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())
            .expect("the lock file opens");
        // Probing the lock from outside the helper is the point of the test.
        #[expect(clippy::disallowed_methods)]
        let taken = rustix::fs::flock(&other, FlockOperation::NonBlockingLockExclusive);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(taken, Ok(()), "the spawned process kept the lock held");
    }

    #[test]
    fn a_waiter_whose_lock_file_was_removed_takes_the_lock_again() {
        // A removal deletes the lock file while it holds it. A caller already
        // queued on that file is then granted a lock on a file no later caller
        // can open, and must take the lock again on the one at the path, or two
        // publications proceed at once.
        use std::time::Duration;

        let dir = Scratch::for_test("provision", "lock-replaced");
        let path = dir.join("rootfs.lock");
        let held = lock_exclusive(&path).expect("the lock is taken");
        let waiter = std::thread::spawn({
            let path = path.clone();
            move || {
                let lock = lock_exclusive(&path).expect("the waiter takes the lock");
                let locked = rustix::fs::fstat(&lock).expect("the lock stats");
                let named = rustix::fs::lstat(&path).expect("the path names a lock file");
                (locked.st_ino, named.st_ino)
            }
        });
        // Long enough for the waiter to have opened the file and queued on it.
        std::thread::sleep(Duration::from_millis(200));
        fs::remove_file(&path).expect("the lock file is removable");
        drop(held);

        let (locked, named) = waiter.join().expect("the waiter finishes");
        assert_eq!(
            locked, named,
            "the waiter holds a lock on a file the path no longer names",
        );
    }

    #[test]
    fn a_removal_waits_for_a_publication_in_progress() {
        // `Remove` holds the publication lock, so it cannot delete a rootfs
        // out from under a provisioner still writing it, nor delete the lock
        // file that provisioner's waiters are queued on.
        use std::time::Duration;

        let dir = Scratch::for_test("provision", "remove-waits");
        let dest = dir.join("rootfs");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("marker"), b"x").unwrap();
        let held = lock_exclusive(&dir.join("rootfs.lock")).expect("the lock is taken");
        let remover = std::thread::spawn({
            let dest = dest.clone();
            move || remove(&dest)
        });
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            dest.join("marker").exists(),
            "the removal ran while a publication held the lock",
        );
        drop(held);
        remover
            .join()
            .expect("the removal finishes")
            .expect("the removal succeeds once the lock is free");
        assert!(!dest.exists());
        assert!(!dir.join("rootfs.lock").exists(), "the lock goes with it");
    }

    /// The marker the deep-tree test's child process finds its tree by.
    const DEEP_TREE: &str = "FERRODAY_CAGE_TEST_DEEP_TREE";

    /// Lays out a chain of `depth` directories under `root`, each named
    /// `level`, through relative descriptors: a chain this deep is longer than
    /// `PATH_MAX` and cannot be spelled as one path. Returns the deepest.
    fn deep_chain(root: &Path, depth: usize) -> std::os::fd::OwnedFd {
        let mut deep = rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("the root opens");
        for _ in 0..depth {
            rustix::fs::mkdirat(&deep, c"level", Mode::RWXU).expect("a level is creatable");
            deep = rustix::fs::openat(
                &deep,
                c"level",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("a level opens");
        }
        deep
    }

    #[test]
    fn a_tree_deeper_than_the_descriptor_limit_is_removed() {
        // A recursive removal holds a descriptor per level, so a tree a sandbox
        // nested deeper than the caller's descriptor limit could not be removed
        // at all -- and with a limit high enough, the recursion overflows the
        // stack instead. The removal runs in a child process of its own, so the
        // limit it lowers is its own rather than every other test's.
        if let Some(tree) = std::env::var_os(DEEP_TREE) {
            let limit = rustix::process::Rlimit {
                current: Some(32),
                maximum: Some(32),
            };
            rustix::process::setrlimit(rustix::process::Resource::Nofile, limit)
                .expect("the descriptor limit lowers");
            remove(PathBuf::from(tree)).expect("the deep tree is removed");
            return;
        }

        let dir = Scratch::for_test("provision", "deep-tree");
        let tree = dir.join("tree");
        fs::create_dir(&tree).unwrap();
        let deepest = deep_chain(&tree, 3_000);
        rustix::fs::symlinkat(c"/nowhere", &deepest, c"dangling").unwrap();
        drop(deepest);

        let status = std::process::Command::new(
            std::env::current_exe().expect("the test binary has a path"),
        )
        .args([
            "--exact",
            "provision::tests::a_tree_deeper_than_the_descriptor_limit_is_removed",
            "--test-threads=1",
        ])
        .env(DEEP_TREE, &tree)
        .status()
        .expect("the child test process runs");
        assert!(
            status.success(),
            "the removal failed in the child: {status}"
        );
        assert!(!tree.exists(), "the tree survived removal");
    }

    #[test]
    fn a_mode_locked_directory_deep_in_a_tree_yields_to_the_single_map() {
        // The caller removes everything it can, down a chain longer than
        // `PATH_MAX`, and then meets a directory whose own mode denies it the
        // read the walk needs -- what an overlay leaves in its work area, with
        // something inside it. The single-map escalation finishes the job.
        if let Some(blocker) = crate::host::userns_blocker() {
            eprintln!("skipping: unprivileged user namespaces are unavailable: {blocker}");
            return;
        }
        let dir = Scratch::for_test("provision", "deep-sealed");
        let tree = dir.join("tree");
        fs::create_dir(&tree).unwrap();
        let deepest = deep_chain(&tree, 2_000);
        rustix::fs::symlinkat(c"/nowhere", &deepest, c"dangling").unwrap();
        rustix::fs::mkdirat(&deepest, c"work", Mode::RWXU).unwrap();
        let sealed = rustix::fs::openat(
            &deepest,
            c"work",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        drop(
            rustix::fs::openat(
                &sealed,
                c"inner",
                OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC,
                Mode::RUSR,
            )
            .unwrap(),
        );
        rustix::fs::fchmod(&sealed, Mode::empty()).unwrap();
        drop((sealed, deepest));

        remove_tree(&tree, &crate::IdentityMap::Single, None).expect("the tree is removed");
        assert!(!tree.exists(), "the tree survived removal");
    }

    #[test]
    fn an_overlay_upper_goes_with_its_work_directory_and_leaves_the_lock() {
        // The work directory is the library's own creation beside the upper,
        // and goes with it, mode-`0` inner directory and all. A `.lock` beside
        // the upper was never this removal's: an upper is not a published
        // rootfs.
        use std::os::unix::fs::PermissionsExt;

        let dir = Scratch::for_test("provision", "overlay-upper");
        let upper = dir.join("upper");
        fs::create_dir_all(upper.join("etc")).unwrap();
        fs::write(upper.join("etc/hostname"), b"build\n").unwrap();
        let work = crate::spec::overlay_work_dir(&upper).expect("the upper has a parent");
        fs::create_dir_all(work.join("work")).unwrap();
        fs::set_permissions(work.join("work"), fs::Permissions::from_mode(0o000)).unwrap();
        let lock = dir.join("upper.lock");
        fs::write(&lock, b"someone else's").unwrap();

        Remove::overlay_upper(&upper)
            .map(crate::IdentityMap::Single)
            .run()
            .expect("the upper is removed");
        assert!(!upper.exists(), "the upper survived");
        assert!(!work.exists(), "the work directory survived");
        assert_eq!(fs::read(&lock).unwrap(), b"someone else's");
    }

    #[test]
    fn ensure_rejects_a_non_directory_dest() {
        let dir = Scratch::for_test("provision", "nondir");
        let dest = dir.join("rootfs");
        fs::write(&dest, b"file in the way").unwrap();
        let err = ensure(&dest, &mut Touch).unwrap_err();
        assert!(matches!(err, ProvisionError::DestUnusable { .. }), "{err}");
    }

    #[test]
    fn ensure_clears_stale_staging() {
        let dir = Scratch::for_test("provision", "stale");
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
                    .map_err(|err| ProvisionError::io("writing", staging, err))
            }
        }

        let dir = Scratch::for_test("provision", "concurrent");
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

    #[cfg(feature = "debian")]
    #[test]
    fn concurrent_writes_of_one_cache_entry_all_succeed() {
        // The shared-cache race: several provisions download the same package
        // at once and publish it under the same content-addressed name. Every
        // writer must succeed, and the published bytes must be the package.
        let dir = Scratch::for_test("provision", "cache-race");
        let bytes = vec![0xab; 64 * 1024];
        let writers: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.to_path_buf();
                let bytes = bytes.clone();
                std::thread::spawn(move || write_atomically(&dir.join("entry"), &bytes))
            })
            .collect();
        for writer in writers {
            writer.join().unwrap().expect("a concurrent write succeeds");
        }
        assert_eq!(fs::read(dir.join("entry")).unwrap(), bytes);

        // Nothing is left staged: the cache holds the published entry alone.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "entry")
            .collect();
        assert!(leftovers.is_empty(), "staging files remain: {leftovers:?}");
    }

    #[cfg(feature = "debian")]
    #[test]
    fn a_failed_publish_leaves_nothing_staged() {
        // Staging names are unique per call, so a failure that left one behind
        // would accumulate in a cache directory rather than being reused. The
        // publishing rename is made to fail by occupying the destination with
        // a non-empty directory.
        let dir = Scratch::for_test("provision", "cache-publish-failure");
        fs::create_dir(dir.join("entry")).unwrap();
        fs::write(dir.join("entry").join("occupant"), b"").unwrap();
        assert!(write_atomically(&dir.join("entry"), b"payload").is_err());
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "entry")
            .collect();
        assert!(leftovers.is_empty(), "staging files remain: {leftovers:?}");
    }
}
