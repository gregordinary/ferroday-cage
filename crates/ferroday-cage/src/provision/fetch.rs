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
    size: Option<u64>,
}

impl<'a> FetchRequest<'a> {
    /// Returns a request for `url`.
    pub fn new(url: &'a str) -> FetchRequest<'a> {
        FetchRequest { url, size: None }
    }

    /// Records the size the body is expected to be, in bytes.
    ///
    /// The provisioner states it wherever a verified source declares it: the
    /// signed release records the length of every index alongside its digest,
    /// and the index records the length of every package. Both are known before
    /// the request is made and are as trustworthy as the signature they hang
    /// from.
    pub fn sized(mut self, bytes: u64) -> FetchRequest<'a> {
        self.size = Some(bytes);
        self
    }

    /// The URL to fetch.
    ///
    /// The scheme is case-insensitive (RFC 3986 §3.1); the rest of the URL is
    /// not. An implementation that routes on the scheme — handing `https://`
    /// URLs to a TLS transport and delegating the rest, say — reaches it
    /// through [`scheme`](Self::scheme) rather than by splitting this string,
    /// so that the two layers cannot disagree about which URLs name TLS.
    pub fn url(&self) -> &'a str {
        self.url
    }

    /// The scheme the URL names, or `None` for a reference that names none.
    ///
    /// This is the accessor a transport routes on. The scheme is the text
    /// before `://`, spelled `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` by
    /// RFC 3986 §3.1, so a path reference that happens to contain `://` does
    /// not read as one. `None` is a real input rather than a broken one: a
    /// caller may name a mirror by a bare path, and a transport that serves
    /// only absolute URLs answers it with [`FetchError::url`].
    ///
    /// It is returned exactly as written. Schemes are case-insensitive, so a
    /// comparison against it must be too — this crate's own client matches
    /// `HTTP://` and `http://` alike, and a transport that matched literally
    /// would refuse URLs the layer above it had already accepted.
    ///
    /// # Example
    ///
    /// Routing by scheme, compared the way the rule requires:
    ///
    /// ```
    /// use ferroday_cage::provision::FetchRequest;
    ///
    /// let request = FetchRequest::new("HTTPS://deb.debian.org/debian/Release");
    /// let scheme = request.scheme().unwrap_or_default();
    ///
    /// // `eq_ignore_ascii_case`, not `==`: the archive may be configured in
    /// // any case, and the two spellings name one transport.
    /// assert!(scheme.eq_ignore_ascii_case("https"));
    /// assert_eq!(scheme, "HTTPS", "the scheme is returned as written");
    /// ```
    pub fn scheme(&self) -> Option<&'a str> {
        scheme_of(self.url)
    }

    /// The size the body is expected to be, or `None` where nothing declares
    /// one — a release file, which is the trust root and so has no signed
    /// length of its own.
    ///
    /// An implementation that honours it refuses a body larger than the stated
    /// size, and may refuse a declared framing larger than it before reading
    /// anything: a mirror that answers a request for a few megabytes with
    /// gigabytes is not serving the resource that was asked for, and the digest
    /// check that would catch the substitution runs only after the bytes have
    /// been spent. It is a ceiling, not a promise — an implementation is free
    /// to ignore it, and the provisioner bounds its own sink regardless.
    pub fn size(&self) -> Option<u64> {
        self.size
    }
}

/// The scheme `url` names, or `None` for a reference that names none.
///
/// The scheme is the text before `://`, and RFC 3986 §3.1 spells it
/// `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` — so a path reference that
/// happens to contain `://` does not read as one. It is returned as written;
/// schemes are case-insensitive, so a comparison against it must be too.
///
/// This is the crate's one answer to the question, reached from inside by the
/// client's own routing and from outside through [`FetchRequest::scheme`].
pub(super) fn scheme_of(url: &str) -> Option<&str> {
    let (scheme, _) = url.split_once("://")?;
    let mut bytes = scheme.bytes();
    let first = bytes.next()?;
    (first.is_ascii_alphabetic()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')))
    .then_some(scheme)
}

/// Fetches the contents of a URL.
///
/// A userland provisioner fetches every index and package through a `Fetch`
/// implementation, so a consumer can substitute a transport the built-in
/// client does not provide — HTTPS, a proxy, an on-disk cache, a private
/// mirror protocol. The default is [`HttpFetch`](super::HttpFetch), which
/// speaks plain HTTP and `file://`. A substitute that routes by scheme takes
/// it from [`FetchRequest::scheme`] and compares it case-insensitively.
///
/// A fetch writes the resource to `sink` as it arrives. A missing resource
/// must be reported as [`FetchError::not_found`] rather than a generic error,
/// so the provisioner can fall back — trying a different index compression or
/// a non-by-hash path — instead of failing.
///
/// # Threads
///
/// A transport is `Send` because the provisioner owns it: a provisioner that
/// could not cross a thread boundary would strand every value built from it on
/// the thread that built it. `Sync` is deliberately not required — every
/// operation on a provisioner takes `&mut self`, so a shared reference to one
/// buys nothing, and demanding `Sync` would rule out a transport that keeps a
/// cache or a connection count behind a [`Cell`].
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
/// use ferroday_cage::provision::{Fetch, FetchError, FetchRequest};
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
///                 .map_err(|err| FetchError::io("writing the body", request.url(), err))
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
    /// The URL could not be parsed, could not be formed from what was meant to
    /// name it, or uses an unsupported scheme.
    #[non_exhaustive]
    Url {
        /// The offending URL, or the locator that could not be made into one.
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
    /// The transport failed: connection, timeout, a read/write error, or an
    /// answer it refused to read — one over the size the resource may weigh,
    /// or a redirect chain that never arrives at a body.
    #[non_exhaustive]
    Io {
        /// What the transport was doing.
        op: &'static str,
        /// The URL fetched.
        url: String,
        /// The underlying error.
        source: io::Error,
    },
}

impl FetchError {
    /// A URL that could not be parsed or formed, or whose scheme is
    /// unsupported.
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
    /// `op` names what the transport was doing, for the message. Arguments run
    /// operation, then locator, then cause, which is the order every
    /// constructor in the crate takes them in.
    pub fn io(op: &'static str, url: impl Into<String>, source: io::Error) -> FetchError {
        FetchError::Io {
            op,
            url: url.into(),
            source,
        }
    }

    /// The same failure as a [`map_err`](Result::map_err) argument: names the
    /// operation and the URL now, and takes the cause when it arrives.
    ///
    /// ```
    /// use std::io::Write;
    ///
    /// use ferroday_cage::provision::FetchError;
    ///
    /// # fn send(url: &str, sink: &mut dyn Write, body: &[u8]) -> Result<(), FetchError> {
    /// sink.write_all(body)
    ///     .map_err(FetchError::at("writing the body", url))
    /// # }
    /// ```
    pub fn at(op: &'static str, url: impl Into<String>) -> impl FnOnce(io::Error) -> FetchError {
        let url = url.into();
        move |source| FetchError::Io { op, url, source }
    }

    /// Whether this failure says that *this* source could not serve the
    /// resource, so a caller walking a list of interchangeable mirrors advances
    /// to the next one.
    ///
    /// A missing resource, a transport failure, and an unsuccessful status all
    /// qualify. The status case is the one worth naming: a 503 during an outage
    /// or a CDN's 403 for an absent object is exactly what a second mirror, or a
    /// snapshot backstop, exists to answer, and a walk that stopped there would
    /// fail without trying either. A walk keeps the last such failure and
    /// reports it when no mirror answers, so the diagnostic survives.
    ///
    /// [`Url`](Self::Url) does not qualify. A malformed or unsupported URL is
    /// the caller's configuration rather than the mirror's state, and a walk
    /// that advanced past it would report the failure against the last mirror in
    /// the list rather than the one that was spelled wrong. That is all it
    /// names: an answer over the size the resource may weigh, or a redirect
    /// chain that never arrives at one, is what a mirror did rather than how the
    /// caller spelled it, and each is carried as a transport failure so that a
    /// walk treats it as one.
    ///
    /// This asks only about the transport. A digest or signature failure is not
    /// a `FetchError` at all — it is the layer's own, raised over bytes that did
    /// arrive — and the answer to one is never to ask somewhere else.
    pub(crate) fn is_failover(&self) -> bool {
        matches!(
            self,
            FetchError::NotFound { .. } | FetchError::Io { .. } | FetchError::Status { .. }
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The accessor hands back the scheme as the URL spells it, rather than a
    /// case-folded copy.
    ///
    /// Folding here would look helpful and cost the caller the ability to
    /// report what was configured, and it would answer a question the caller
    /// has to ask anyway: a router comparing case-insensitively is correct
    /// whether or not the accessor folds, and one comparing literally is wrong
    /// either way.
    #[test]
    fn the_scheme_is_returned_as_written() {
        for (url, expected) in [
            ("http://deb.debian.org/debian/x", "http"),
            ("HTTPS://deb.debian.org/debian/x", "HTTPS"),
            ("Http://deb.debian.org/debian/x", "Http"),
            ("file:///var/cache/x", "file"),
        ] {
            let request = FetchRequest::new(url);
            assert_eq!(request.scheme(), Some(expected), "{url}");
            assert!(
                request
                    .scheme()
                    .is_some_and(|scheme| scheme.eq_ignore_ascii_case(expected)),
                "{url}: the documented comparison holds",
            );
        }
    }

    /// A reference naming no scheme is a real input, so it answers `None`
    /// rather than inventing one. A path that merely contains `://` is such a
    /// reference: the text before it is not a scheme.
    #[test]
    fn a_reference_naming_no_scheme_answers_none() {
        for url in ["/var/cache/archives/x.deb", "deb.debian.org/debian/x", ""] {
            assert_eq!(FetchRequest::new(url).scheme(), None, "{url}");
        }
    }

    #[test]
    fn a_mirror_walk_advances_past_what_this_mirror_could_not_serve() {
        // The question every layer's mirror walk asks, pinned here rather than
        // only through each walk that asks it: three failures say "ask
        // somewhere else" and one says "you asked wrongly".
        for failure in [
            FetchError::not_found("http://mirror.invalid/x"),
            FetchError::status("http://mirror.invalid/x", 503),
            FetchError::status("http://mirror.invalid/x", 403),
            FetchError::io(
                "connecting",
                "http://mirror.invalid/x",
                io::Error::from(io::ErrorKind::ConnectionRefused),
            ),
        ] {
            assert!(failure.is_failover(), "{failure}");
        }

        // A URL the transport will not accept is the caller's configuration
        // rather than the mirror's state. A walk that advanced past it would
        // report the failure against whichever mirror came last instead of
        // against the one that was spelled wrong.
        let malformed = FetchError::url("gopher://mirror.invalid/x", "unsupported scheme");
        assert!(!malformed.is_failover(), "{malformed}");
    }

    #[test]
    fn only_an_os_failure_carries_a_source() {
        let source = FetchError::io(
            "connecting",
            "http://mirror.invalid/x",
            io::Error::from(io::ErrorKind::ConnectionRefused),
        );
        assert!(std::error::Error::source(&source).is_some());
        for bare in [
            FetchError::not_found("http://mirror.invalid/x"),
            FetchError::status("http://mirror.invalid/x", 503),
            FetchError::url("gopher://mirror.invalid/x", "unsupported scheme"),
        ] {
            assert!(std::error::Error::source(&bare).is_none(), "{bare}");
        }
    }
}
