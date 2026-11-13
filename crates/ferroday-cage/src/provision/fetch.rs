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

    /// Records the most the body may hold, in bytes.
    ///
    /// The provisioner states it on every request whose body it bounds, and it
    /// is the bound the provisioner holds the body to itself. Where a verified
    /// source declares the body's length, that length is the bound: the signed
    /// release records the length of every index alongside its digest, and the
    /// index records the length of every package. Both are known before the
    /// request is made and are as trustworthy as the signature they hang from.
    /// Where nothing declares it, the bound is the ceiling the provisioner holds
    /// that document to: a signed document, which is the trust root, and an
    /// index nothing signed describes. A body past the bound is refused either
    /// way, so a transport that refuses an over-declared answer up front only
    /// refuses it sooner.
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
/// that state behind an [`Arc`]. A transport chosen at run time is a
/// `Box<dyn Fetch>`, which is a transport too: a box forwards every method to
/// what it holds.
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
/// A method added here is forwarded by the `Box` implementation as well,
/// defaulted ones included. A box that left one out would run the default body
/// in place of the boxed transport's own, which for [`fetch_all`](Self::fetch_all)
/// turns a transport's overlapping batch into one request at a time with
/// nothing to show for it. A test compares the two method lists.
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

/// A boxed transport is a transport, so one chosen at run time is passed
/// wherever a transport is taken.
///
/// Every method forwards to the boxed transport, the defaulted ones included,
/// so a box runs the transport's own overrides rather than the trait's default
/// bodies. A caller cannot write this for a `Box<dyn Fetch>` of its own, since
/// neither the trait nor the type is the caller's.
impl<F: Fetch + ?Sized> Fetch for Box<F> {
    fn fetch(
        &mut self,
        request: &FetchRequest<'_>,
        sink: &mut dyn Write,
    ) -> Result<(), FetchError> {
        (**self).fetch(request, sink)
    }

    fn fetch_all(&mut self, jobs: &mut [FetchJob<'_>]) -> Vec<Result<(), FetchError>> {
        (**self).fetch_all(jobs)
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
            FetchError::Io { url, op, .. } => write!(f, "fetching {url} failed while {op}"),
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

/// What a fetch reports to, and asks whether to go on.
///
/// Each layer's own observer, seen from a fetch: the event a layer reports a
/// fetch with is its own, and so is the answer to whether the run should stop.
pub(crate) trait Watch {
    /// A URL is about to be fetched.
    fn fetching(&mut self, url: &str);

    /// Whether the run has been asked to stop.
    fn cancelled(&mut self) -> bool;
}

/// Fetches `url` into memory, refusing a body past `limit` bytes.
///
/// The bound is stated twice, and this is where every in-memory fetch states
/// it. It travels with the request through [`FetchRequest::sized`], so a
/// transport that honours it refuses an over-declared answer before reading
/// it, and it bounds the sink, because a transport of the caller's is free to
/// ignore the request and the sink is the one place the bound cannot be
/// ignored. `limit` is the length a verified source declared for the body
/// where one did, and otherwise the ceiling the layer holds the document to,
/// which is the one rule `sized` documents.
pub(crate) fn fetch_bounded(
    fetcher: &mut dyn Fetch,
    url: &str,
    limit: u64,
) -> Result<Vec<u8>, FetchError> {
    let mut bytes = Vec::new();
    fetcher.fetch(
        &FetchRequest::new(url).sized(limit),
        &mut super::LimitedWriter::new(&mut bytes, limit),
    )?;
    Ok(bytes)
}

/// A document as the first mirror that served it delivered it.
#[derive(Debug)]
pub(crate) struct Fetched<'m> {
    /// The mirror that served it, as configured.
    ///
    /// The one that answered rather than the list: a plan resolved against a
    /// repository with a backstop records whichever served, and a record naming
    /// the list would describe a choice rather than the choice made. The
    /// Gentoo layer records no mirror, so a build without the other two never
    /// reads it.
    #[cfg_attr(not(any(feature = "debian", feature = "alpine")), allow(dead_code))]
    pub(crate) mirror: &'m str,
    /// The URL it arrived from, which a refusal of what arrived names.
    pub(crate) url: String,
    /// The bytes as they arrived.
    pub(crate) body: Vec<u8>,
}

/// Fetches `suffix`, a mirror-relative path, into memory from the first of
/// `mirrors` that serves it, holding it to `limit` bytes as
/// [`fetch_bounded`] does.
///
/// The walk is [`walk_mirrors`]'s: a mirror that [could not serve the
/// document](FetchError::is_failover) advances it, the last such failure is
/// what an exhausted walk reports, and a URL the transport refuses ends it,
/// since that is the configuration rather than the mirror.
///
/// `watch` is asked before each mirror, so a walk over unreachable mirrors,
/// which spends a connect timeout on each, stops between one and the next;
/// `cancelled` is the layer's error for that stop. It hears each URL as it is
/// fetched, since this walk is the slowest part of a resolve and an observer
/// that heard nothing would watch a run that looks stopped.
///
/// What arrived is the caller's to verify. A document that does not verify is
/// fatal rather than a reason to ask the next mirror, since what a mirror
/// served was answered for by the URL that was asked for, so verifying once
/// the walk has ended is the same as verifying inside it.
pub(crate) fn fetch_first<'m, E, W>(
    fetcher: &mut dyn Fetch,
    mirrors: &'m [String],
    suffix: &str,
    limit: u64,
    watch: &mut W,
    cancelled: impl Fn() -> E,
) -> Result<Fetched<'m>, E>
where
    E: From<FetchError> + Failover,
    W: Watch + ?Sized,
{
    // Walked as `&str`s borrowed from the list, so the mirror that answers is
    // handed back at the list's own lifetime rather than at the walk's.
    let mirrors: Vec<&'m str> = mirrors.iter().map(String::as_str).collect();
    walk_mirrors(
        &mirrors,
        |&mirror| {
            if watch.cancelled() {
                return Err(cancelled());
            }
            let url = mirror_url(mirror, suffix);
            watch.fetching(&url);
            let body = fetch_bounded(fetcher, &url, limit)?;
            Ok(Fetched { mirror, url, body })
        },
        || E::from(no_mirror(suffix)),
    )
}

/// The failure a mirror walk reports when it had nowhere to walk.
///
/// Unreachable as the layers are configured, since every builder composes its
/// mirror list with a primary in it. It is a configuration
/// failure rather than a missing resource, which is also what keeps it out of
/// the failover class: there is nothing to advance to.
pub(crate) fn no_mirror(suffix: &str) -> FetchError {
    FetchError::url(suffix, "no mirror is configured to fetch it from")
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
///
/// A second answer beside [`digest::unhex`](super::digest::unhex), which reads
/// lowercase alone: a digest this crate compares has one spelling, and a
/// percent escape has two, since RFC 3986 makes `%2f` and `%2F` the same octet.
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

    /// A boxed transport runs the boxed transport's own methods, its
    /// overridden batch included, rather than the trait's default bodies.
    #[test]
    fn a_boxed_transport_forwards_its_own_batch() {
        /// Records which of its two methods each request went through.
        #[derive(Default)]
        struct Batching {
            took: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
        }
        impl Fetch for Batching {
            fn fetch(
                &mut self,
                _request: &FetchRequest<'_>,
                _sink: &mut dyn Write,
            ) -> Result<(), FetchError> {
                self.took.lock().unwrap().push("fetch");
                Ok(())
            }
            fn fetch_all(&mut self, jobs: &mut [FetchJob<'_>]) -> Vec<Result<(), FetchError>> {
                self.took.lock().unwrap().push("batch");
                jobs.iter().map(|_| Ok(())).collect()
            }
        }

        let transport = Batching::default();
        let took = std::sync::Arc::clone(&transport.took);
        let mut boxed: Box<dyn Fetch> = Box::new(transport);
        let (mut first, mut second) = (Vec::new(), Vec::new());
        let mut jobs = [
            FetchJob::new(FetchRequest::new("file:///one"), &mut first),
            FetchJob::new(FetchRequest::new("file:///two"), &mut second),
        ];
        assert_eq!(boxed.fetch_all(&mut jobs).len(), 2);
        boxed
            .fetch(&FetchRequest::new("file:///three"), &mut Vec::new())
            .expect("the boxed transport serves it");

        // One batch, not one fetch per job, then the single fetch.
        assert_eq!(*took.lock().unwrap(), ["batch", "fetch"]);
    }

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

    /// A layer's error, as a walk sees one: a transport failure, or the stop.
    #[derive(Debug)]
    enum Walked {
        Fetch(FetchError),
        Cancelled,
    }

    impl From<FetchError> for Walked {
        fn from(err: FetchError) -> Walked {
            Walked::Fetch(err)
        }
    }

    impl Failover for Walked {
        fn is_failover(&self) -> bool {
            matches!(self, Walked::Fetch(err) if err.is_failover())
        }
    }

    /// A watch recording what it heard, answering "stop" once it has been
    /// asked `allowed` times.
    struct Asked {
        fetched: Vec<String>,
        asked: usize,
        allowed: usize,
    }

    impl Asked {
        fn patient() -> Asked {
            Asked::stopping_after(usize::MAX)
        }

        fn stopping_after(allowed: usize) -> Asked {
            Asked {
                fetched: Vec::new(),
                asked: 0,
                allowed,
            }
        }
    }

    impl Watch for Asked {
        fn fetching(&mut self, url: &str) {
            self.fetched.push(url.to_string());
        }

        fn cancelled(&mut self) -> bool {
            self.asked += 1;
            self.asked > self.allowed
        }
    }

    /// A transport that refuses every URL beginning with `refused` with a
    /// fixed error and serves `body` for any other, recording every URL it was
    /// asked for and the size each request stated.
    struct Failing {
        refused: &'static str,
        refusal: fn(&str) -> FetchError,
        body: Vec<u8>,
        asked: Vec<(String, Option<u64>)>,
    }

    impl Failing {
        fn refusing(refused: &'static str, refusal: fn(&str) -> FetchError) -> Failing {
            Failing {
                refused,
                refusal,
                body: b"from the backstop".to_vec(),
                asked: Vec::new(),
            }
        }
    }

    impl Fetch for Failing {
        fn fetch(
            &mut self,
            request: &FetchRequest<'_>,
            sink: &mut dyn Write,
        ) -> Result<(), FetchError> {
            self.asked.push((request.url().to_string(), request.size()));
            if request.url().starts_with(self.refused) {
                return Err((self.refusal)(request.url()));
            }
            sink.write_all(&self.body)
                .map_err(FetchError::at("writing the body", request.url()))
        }
    }

    const PRIMARY: &str = "https://primary.example/debian";
    const BACKSTOP: &str = "https://snapshot.example/debian";

    /// Walks a two-mirror list with `fetcher`.
    fn walk<'m>(
        fetcher: &mut Failing,
        mirrors: &'m [String],
        watch: &mut Asked,
    ) -> Result<Fetched<'m>, Walked> {
        fetch_first(
            fetcher,
            mirrors,
            "dists/stable/Release",
            1024,
            watch,
            || Walked::Cancelled,
        )
    }

    fn both() -> [String; 2] {
        [PRIMARY.to_string(), BACKSTOP.to_string()]
    }

    #[test]
    fn a_walk_advances_past_a_mirror_that_could_not_serve() {
        // Every way a mirror can decline to serve is a reason to try the next
        // one: the backstop exists for precisely the outage a 5xx reports, and
        // a CDN answers an absent object with 403 as readily as with 404.
        for refusal in [
            |url: &str| FetchError::not_found(url),
            |url: &str| FetchError::status(url, 503),
            |url: &str| FetchError::status(url, 403),
            |url: &str| {
                FetchError::io(
                    "connecting",
                    url,
                    io::Error::from(io::ErrorKind::ConnectionRefused),
                )
            },
        ] {
            let mut fetcher = Failing::refusing(PRIMARY, refusal);
            let mirrors = both();
            let mut watch = Asked::patient();
            let served = walk(&mut fetcher, &mirrors, &mut watch).expect("the backstop answers");
            assert_eq!(served.body, b"from the backstop");
            // The mirror that served, not the one asked first: a plan resolved
            // this way records which mirror answered.
            assert_eq!(served.mirror, BACKSTOP);
            assert_eq!(served.url, format!("{BACKSTOP}/dists/stable/Release"));
            assert_eq!(fetcher.asked.len(), 2, "{:?}", fetcher.asked);
            // Each URL is announced as it is fetched.
            assert_eq!(watch.fetched.len(), 2, "{:?}", watch.fetched);
        }
    }

    #[test]
    fn a_walk_stops_at_a_url_the_transport_refuses() {
        // A URL the transport cannot parse is the caller's configuration, not
        // the mirror's state; trying the next mirror would bury the mistake,
        // and report it against the backstop rather than the mirror that
        // carries it.
        let mut fetcher = Failing::refusing(PRIMARY, |url| FetchError::url(url, "unsupported"));
        let mirrors = both();
        let result = walk(&mut fetcher, &mirrors, &mut Asked::patient());
        assert!(
            matches!(&result, Err(Walked::Fetch(FetchError::Url { url, .. })) if url.starts_with(PRIMARY)),
            "{result:?}",
        );
        assert_eq!(
            fetcher.asked.len(),
            1,
            "the walk stopped at the first mirror"
        );
    }

    #[test]
    fn an_exhausted_walk_is_reported_against_the_mirror_it_asked_last() {
        // Keeping the last failure is what makes the diagnostic survive a
        // walk, and reporting the first would point at a mirror that may be
        // perfectly healthy.
        let mut fetcher = Failing::refusing("https://", |url| FetchError::status(url, 503));
        let mirrors = both();
        let result = walk(&mut fetcher, &mirrors, &mut Asked::patient());
        assert!(
            matches!(&result, Err(Walked::Fetch(FetchError::Status { url, .. })) if url.starts_with(BACKSTOP)),
            "{result:?}",
        );
        assert_eq!(fetcher.asked.len(), 2);
    }

    #[test]
    fn a_walk_stops_between_mirrors_once_the_run_is_cancelled() {
        // An unreachable mirror costs a connect timeout, so a list of them is
        // a step long enough to want stopping in the middle of: the watch is
        // asked before each mirror, and the stop is the layer's own error
        // rather than a failure the walk advances past.
        let mut fetcher = Failing::refusing(PRIMARY, |url| FetchError::status(url, 503));
        let mirrors = both();
        let mut watch = Asked::stopping_after(1);
        let result = walk(&mut fetcher, &mirrors, &mut watch);
        assert!(matches!(result, Err(Walked::Cancelled)), "{result:?}");
        assert_eq!(fetcher.asked.len(), 1, "the backstop was never asked");

        let mut fetcher = Failing::refusing(PRIMARY, |url| FetchError::status(url, 503));
        let result = walk(&mut fetcher, &mirrors, &mut Asked::stopping_after(0));
        assert!(matches!(result, Err(Walked::Cancelled)), "{result:?}");
        assert!(fetcher.asked.is_empty(), "nothing is fetched once stopped");
    }

    #[test]
    fn a_bounded_fetch_states_its_bound_and_holds_the_sink_to_it() {
        // The bound travels with the request for a transport that honours it,
        // and the sink holds it for one that does not, so an oversized body is
        // refused as it arrives rather than after it is held.
        let fetch = |len: usize| {
            let mut fetcher = Failing::refusing("none://", |url| FetchError::not_found(url));
            fetcher.body = vec![b'x'; len];
            let result = fetch_bounded(&mut fetcher, "http://mirror.example/x", 64);
            assert_eq!(fetcher.asked[0].1, Some(64), "the request states the bound");
            result
        };
        assert_eq!(fetch(64).expect("a body at the bound arrives").len(), 64);
        assert!(
            matches!(fetch(65), Err(FetchError::Io { .. })),
            "a body past the bound is refused",
        );
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
