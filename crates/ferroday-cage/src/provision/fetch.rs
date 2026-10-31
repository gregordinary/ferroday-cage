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
    /// from. A signed document is the trust root, so nothing declares its
    /// length, and the provisioner states the ceiling it holds one to instead.
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

    /// The size the body is expected to be, or `None` where the provisioner
    /// states none.
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
/// For the same reason, a provisioner's builder takes its transport by value,
/// as `impl Fetch + 'static`, and the provisioner keeps it for its whole life.
/// A borrowed transport would tie the provisioner to the frame that lent it,
/// and so to that frame's thread. A transport that shares state with its
/// caller, such as a connection pool or a record of what was fetched, holds
/// that state behind an [`Arc`].
///
/// [`Cell`]: std::cell::Cell
/// [`Arc`]: std::sync::Arc
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

    /// Fetches every job in `jobs`, answering one outcome per job, in order.
    ///
    /// This is where a transport says it can do more than one at a time. The
    /// default body is [`fetch`](Self::fetch) per job in order, so an
    /// implementation that overrides nothing behaves exactly as it did before
    /// this method existed; [`HttpFetch`](super::HttpFetch) overrides it and
    /// runs several at once.
    ///
    /// The jobs are independent. One that fails does not stop the others, and
    /// the answer at index `i` is the outcome of the job at index `i` -- which
    /// is what lets a caller retry only what did not arrive.
    ///
    /// A caller batches what it can afford to have in flight together, since
    /// each job holds an open sink for as long as the batch runs. Nothing here
    /// bounds that: how many is a question about the caller's file descriptors
    /// and memory, not about the transport.
    ///
    /// # Overriding it
    ///
    /// An override answers every job in the slice; Rust offers no way to call
    /// this default body from an implementation that replaces it. A transport
    /// that speaks for only some of the jobs therefore delivers the rest
    /// itself, which is what [`FetchJob::parts`] is for.
    ///
    /// The rest need not go one at a time. [`FetchRequest`] is [`Copy`] and
    /// [`FetchJob::new`] is public, so the halves `parts` hands back rebuild a
    /// job at a shorter borrow: a subset of the slice becomes a batch of its
    /// own, and the transport behind this one still overlaps it. Keep each
    /// job's index while doing so, since the answers are read by position.
    ///
    /// # Example
    ///
    /// A transport that serves one scheme itself and passes the rest to
    /// [`HttpFetch`](super::HttpFetch) as a batch:
    ///
    /// ```
    /// use std::io::Write;
    ///
    /// use ferroday_cage::provision::{Fetch, FetchError, FetchJob, FetchRequest, HttpFetch};
    ///
    /// /// Serves `canned://` itself; every other scheme is the bundled client's.
    /// struct Routed(HttpFetch);
    ///
    /// fn is_canned(request: &FetchRequest<'_>) -> bool {
    ///     // `eq_ignore_ascii_case`, because a scheme is case-insensitive.
    ///     request
    ///         .scheme()
    ///         .is_some_and(|scheme| scheme.eq_ignore_ascii_case("canned"))
    /// }
    ///
    /// impl Fetch for Routed {
    ///     fn fetch(
    ///         &mut self,
    ///         request: &FetchRequest<'_>,
    ///         sink: &mut dyn Write,
    ///     ) -> Result<(), FetchError> {
    ///         if is_canned(request) {
    ///             sink.write_all(b"canned")
    ///                 .map_err(|err| FetchError::io("writing the body", request.url(), err))
    ///         } else {
    ///             self.0.fetch(request, sink)
    ///         }
    ///     }
    ///
    ///     fn fetch_all(&mut self, jobs: &mut [FetchJob<'_>]) -> Vec<Result<(), FetchError>> {
    ///         let mut outcomes: Vec<Option<Result<(), FetchError>>> =
    ///             jobs.iter().map(|_| None).collect();
    ///         let mut passed_on: Vec<(usize, FetchJob<'_>)> = Vec::new();
    ///
    ///         for (index, job) in jobs.iter_mut().enumerate() {
    ///             let (request, sink) = job.parts();
    ///             if is_canned(request) {
    ///                 let written = sink.write_all(b"canned").map_err(|err| {
    ///                     FetchError::io("writing the body", request.url(), err)
    ///                 });
    ///                 outcomes[index] = Some(written);
    ///             } else {
    ///                 // Rebuilt, so what is passed on is one batch rather than
    ///                 // one request at a time.
    ///                 passed_on.push((index, FetchJob::new(*request, sink)));
    ///             }
    ///         }
    ///
    ///         let (indices, mut batch): (Vec<usize>, Vec<FetchJob<'_>>) =
    ///             passed_on.into_iter().unzip();
    ///         for (index, outcome) in indices.into_iter().zip(self.0.fetch_all(&mut batch)) {
    ///             outcomes[index] = Some(outcome);
    ///         }
    ///
    ///         outcomes
    ///             .into_iter()
    ///             .map(|outcome| outcome.expect("every job was served or passed on"))
    ///             .collect()
    ///     }
    /// }
    ///
    /// let (mut served, mut absent) = (Vec::new(), Vec::new());
    /// let mut jobs = vec![
    ///     FetchJob::new(FetchRequest::new("canned://body"), &mut served),
    ///     FetchJob::new(FetchRequest::new("file:///nonexistent/body"), &mut absent),
    /// ];
    /// let outcomes = Routed(HttpFetch::new()).fetch_all(&mut jobs);
    /// drop(jobs);
    ///
    /// assert!(outcomes[0].is_ok(), "the scheme this transport speaks");
    /// assert!(outcomes[1].is_err(), "passed on, and answered at its own index");
    /// assert_eq!(served, b"canned".as_slice());
    /// ```
    fn fetch_all(&mut self, jobs: &mut [FetchJob<'_>]) -> Vec<Result<(), FetchError>> {
        jobs.iter_mut()
            .map(|job| {
                let (request, sink) = job.parts();
                self.fetch(request, sink)
            })
            .collect()
    }
}

/// One entry of a batch: what to fetch, and where its body goes.
///
/// Handed to [`Fetch::fetch_all`]. The sink is `Send` because a transport that
/// fetches several at once writes each body from a thread of its own; it is
/// borrowed rather than owned so that a caller keeps whatever it needs to
/// finish the job -- a digest to check, a staging file to rename -- and gets it
/// back when the batch ends.
pub struct FetchJob<'a> {
    request: FetchRequest<'a>,
    sink: &'a mut (dyn Write + Send),
}

impl<'a> FetchJob<'a> {
    /// A job fetching `request` into `sink`.
    pub fn new(request: FetchRequest<'a>, sink: &'a mut (dyn Write + Send)) -> FetchJob<'a> {
        FetchJob { request, sink }
    }

    /// What this job fetches.
    pub fn request(&self) -> &FetchRequest<'a> {
        &self.request
    }

    /// What to fetch and where it goes, borrowed apart.
    ///
    /// This is how a transport delivers a job it took from
    /// [`Fetch::fetch_all`]: [`request`](Self::request) alone says what was
    /// asked for, and this says where the body goes. One method rather than
    /// two, because a transport needs both at once and the request is behind
    /// the same borrow as the sink.
    ///
    /// It hands back the two halves that share one borrow, not an exhaustive
    /// view of the job. Anything a job comes to carry later arrives as an
    /// accessor of its own, or as one on [`FetchRequest`], rather than as a
    /// third element here.
    ///
    /// The sink is reborrowed from `self`, so it cannot outlive the job it came
    /// from, and the job cannot be handed to a second transport while it is
    /// out.
    pub fn parts(&mut self) -> (&FetchRequest<'a>, &mut (dyn Write + Send)) {
        (&self.request, self.sink)
    }
}

impl fmt::Debug for FetchJob<'_> {
    /// Renders the request. The sink is the caller's writer, so it renders as
    /// its presence rather than its contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchJob")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
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
    /// walk treats it as one — as is a redirect refused for leaving the host or
    /// for leading to a URL the transport cannot fetch, such as an `https://`
    /// one, since where a mirror sends a request is that mirror's arrangement.
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

/// A failure a mirror walk may advance past.
///
/// Every archive layer walks a list of mirrors the same way: try one, and on a
/// failure that says "ask somewhere else" try the next, keeping the last such
/// failure to report when none is left. What differs between the layers is the
/// error type the walk carries, and this is the one question
/// [`walk_mirrors`] has to ask of it.
///
/// The predicate itself is [`FetchError::is_failover`] in every implementation.
/// A layer that wraps a transport failure in its own error reaches through the
/// wrapper; a failure that is not a transport one at all -- a digest or
/// signature mismatch over bytes that did arrive -- never advances a walk,
/// because the answer to one is never to ask somewhere else.
pub(crate) trait Failover {
    /// Whether this failure is one to try the next mirror for.
    fn is_failover(&self) -> bool;
}

impl Failover for FetchError {
    fn is_failover(&self) -> bool {
        FetchError::is_failover(self)
    }
}

/// Tries `attempt` against each entry of `over` in turn, taking the first that
/// answers.
///
/// A failure [`Failover`] recognizes advances to the next entry and is kept;
/// any other failure ends the walk where it happened. When the list runs out,
/// the last kept failure is what is reported, so the diagnostic describes a
/// mirror rather than the walk -- and `exhausted` supplies an error only for
/// the case where nothing was tried at all, which an empty list is.
///
/// Generic over the entry rather than fixed to a mirror URL, because two of the
/// walks here are over something else: the Debian index walk tries several
/// index encodings within each mirror, which is the same rule one level down
/// and nests as one call inside another. What the entry means is the caller's;
/// what this owns is the rule for advancing past a failure and for which
/// failure is reported at the end.
pub(crate) fn walk_mirrors<Entry, T, E: Failover>(
    over: &[Entry],
    mut attempt: impl FnMut(&Entry) -> Result<T, E>,
    exhausted: impl FnOnce() -> E,
) -> Result<T, E> {
    let mut unserved = None;
    for entry in over {
        match attempt(entry) {
            Ok(answered) => return Ok(answered),
            Err(err) if err.is_failover() => unserved = Some(err),
            Err(err) => return Err(err),
        }
    }
    Err(unserved.unwrap_or_else(exhausted))
}

/// Joins a mirror-relative path onto a mirror's URL.
///
/// A configured mirror may or may not end in a slash and a composed suffix may
/// or may not begin with one, so the join owns both: `http://mirror/debian/`
/// and `http://mirror/debian` address the same archive, and a doubled or
/// missing separator addresses neither.
pub(crate) fn mirror_url(mirror: &str, suffix: &str) -> String {
    format!(
        "{}/{}",
        mirror.trim_end_matches('/'),
        suffix.trim_start_matches('/'),
    )
}

/// Decodes the percent escapes in `text`, or `None` where one is malformed: a
/// `%` not followed by two hexadecimal digits.
///
/// One pass, and only one. What the decoded bytes may hold is the caller's
/// question, because it differs with what the text is: a pool path out of a
/// Debian index is refused if decoding leaves anything a second pass could
/// decode again, and a `file://` path is refused where an escape would change
/// the path's shape rather than spell a name in it.
pub(crate) fn percent_decode(text: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(text.len());
    let mut bytes = text.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            decoded.push(byte);
            continue;
        }
        let high = hex_value(bytes.next()?)?;
        let low = hex_value(bytes.next()?)?;
        decoded.push(high << 4 | low);
    }
    Some(decoded)
}

/// The value of one hexadecimal digit, either case.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding_takes_one_pass_and_refuses_a_malformed_escape() {
        assert_eq!(
            percent_decode(b"My%20Pool/caf%C3%a9").as_deref(),
            Some("My Pool/caf\u{e9}".as_bytes()),
        );
        // A decoded `%` is not decoded again.
        assert_eq!(percent_decode(b"%252e").as_deref(), Some(&b"%2e"[..]));
        for malformed in [&b"%"[..], b"%2", b"%zz", b"x%g0"] {
            assert_eq!(percent_decode(malformed), None, "{malformed:?}");
        }
    }

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
