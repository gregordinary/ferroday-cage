//! The transport seam: how bytes are fetched from the archive.

use std::fmt;
use std::io::{self, Write};

/// The inputs to one fetch.
///
/// [`Fetch::fetch`] takes its inputs as this value rather than as loose
/// parameters, so that per-request context an implementation comes to need — a
/// byte range, an expected digest, a conditional-request stamp, extra headers —
/// can be added as accessors without changing the trait method's signature.
///
/// A `Fetch` implementation reads what it understands and ignores the rest.
#[derive(Debug, Clone, Copy)]
pub struct FetchRequest<'a> {
    url: &'a str,
}

impl<'a> FetchRequest<'a> {
    /// Returns a request for `url`.
    pub fn new(url: &'a str) -> FetchRequest<'a> {
        FetchRequest { url }
    }

    /// The URL to fetch.
    pub fn url(&self) -> &'a str {
        self.url
    }
}

/// Fetches the contents of a URL.
///
/// The Debian provisioner fetches every index and package through a `Fetch`
/// implementation, so a consumer can substitute a transport the built-in
/// client does not provide — HTTPS, a proxy, an on-disk cache, a private
/// mirror protocol. The default is [`HttpFetch`](super::HttpFetch), which
/// speaks plain HTTP and `file://`.
///
/// A fetch writes the resource to `sink` as it arrives. A missing resource
/// must be reported as [`FetchError::not_found`] rather than a generic error,
/// so the provisioner can fall back — trying a different index compression or
/// a non-by-hash path — instead of failing.
///
/// # Threads
///
/// A transport is `Send` because [`Debian`](super::Debian) owns it: a
/// provisioner that could not cross a thread boundary would strand every value
/// built from it on the thread that built it. `Sync` is deliberately not
/// required — every operation on a `Debian` takes `&mut self`, so a shared
/// reference to one buys nothing, and demanding `Sync` would rule out a
/// transport that keeps a cache or a connection count behind a [`Cell`].
///
/// Fetches always run on the thread that called into the provisioner; the
/// requirement is on moving the transport, not on using it concurrently. A
/// transport wrapping a genuinely thread-bound handle keeps that handle in a
/// [`thread_local!`] or behind a channel to the thread that owns it.
///
/// [`Cell`]: std::cell::Cell
///
/// # Stability
///
/// Every method added to this trait in a later release will carry a default
/// body, so an existing implementation keeps compiling. New per-request inputs
/// arrive as accessors on [`FetchRequest`] rather than as parameters, for the
/// same reason.
///
/// # Example
///
/// ```
/// use std::io::Write;
///
/// use ferroday_cage::provision::debian::{Fetch, FetchError, FetchRequest};
///
/// /// A transport that serves one canned response and nothing else.
/// struct Canned(Vec<u8>);
///
/// impl Fetch for Canned {
///     fn fetch(
///         &mut self,
///         request: &FetchRequest<'_>,
///         sink: &mut dyn Write,
///     ) -> Result<(), FetchError> {
///         if request.url().ends_with("/Release") {
///             sink.write_all(&self.0)
///                 .map_err(|err| FetchError::io(request.url(), "writing the body", err))
///         } else {
///             Err(FetchError::not_found(request.url()))
///         }
///     }
/// }
/// ```
pub trait Fetch: Send {
    /// Fetches the resource `request` names, writing its body to `sink`.
    fn fetch(&mut self, request: &FetchRequest<'_>, sink: &mut dyn Write)
    -> Result<(), FetchError>;
}

/// A failure fetching a URL.
#[derive(Debug)]
#[non_exhaustive]
pub enum FetchError {
    /// The URL could not be parsed or uses an unsupported scheme.
    #[non_exhaustive]
    Url {
        /// The offending URL.
        url: String,
        /// What was wrong with it.
        reason: String,
    },
    /// The resource does not exist (HTTP 404, or a missing `file://` path).
    #[non_exhaustive]
    NotFound {
        /// The URL that was not found.
        url: String,
    },
    /// The server returned an unsuccessful status other than 404.
    #[non_exhaustive]
    Status {
        /// The URL fetched.
        url: String,
        /// The HTTP status code.
        code: u16,
    },
    /// The transport failed: connection, timeout, or a read/write error.
    #[non_exhaustive]
    Io {
        /// The URL fetched.
        url: String,
        /// What the transport was doing.
        op: String,
        /// The underlying error.
        source: io::Error,
    },
}

impl FetchError {
    /// A URL that could not be parsed, or whose scheme is unsupported.
    pub fn url(url: impl Into<String>, reason: impl Into<String>) -> FetchError {
        FetchError::Url {
            url: url.into(),
            reason: reason.into(),
        }
    }

    /// A resource the transport could not find.
    ///
    /// The provisioner treats this as a recoverable absence and falls back —
    /// to a different index compression, or a non-by-hash path — so a
    /// [`Fetch`] implementation must report a missing resource with this
    /// rather than with [`status`](Self::status) or [`io`](Self::io).
    pub fn not_found(url: impl Into<String>) -> FetchError {
        FetchError::NotFound { url: url.into() }
    }

    /// An unsuccessful transport status other than "not found".
    pub fn status(url: impl Into<String>, code: u16) -> FetchError {
        FetchError::Status {
            url: url.into(),
            code,
        }
    }

    /// A transport failure: connection, timeout, or a read/write error.
    ///
    /// `op` names what the transport was doing, for the message.
    pub fn io(url: impl Into<String>, op: impl Into<String>, source: io::Error) -> FetchError {
        FetchError::Io {
            url: url.into(),
            op: op.into(),
            source,
        }
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Url { url, reason } => write!(f, "cannot fetch {url}: {reason}"),
            FetchError::NotFound { url } => write!(f, "{url} was not found"),
            FetchError::Status { url, code } => {
                write!(f, "fetching {url} failed with HTTP status {code}")
            }
            FetchError::Io { url, op, source } => {
                write!(f, "fetching {url} failed while {op}: {source}")
            }
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FetchError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
