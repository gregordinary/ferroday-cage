//! The default fetcher: a minimal HTTP/1.1 client plus `file://`.
//!
//! It speaks just enough HTTP to retrieve static files from a distribution
//! mirror over plain `http://` — a single `GET` for the resource's own bytes,
//! content-length or chunked bodies, capped redirects, connect and read
//! timeouts — with no dependency beyond `std::net`. Authenticity of what it fetches comes from the archive
//! signature, verified above this layer, not from the transport; a consumer
//! who needs HTTPS or a proxy supplies their own [`Fetch`]. `file://` URLs
//! read a local path, which serves local mirrors and the test suite.
//!
//! A URL's host may be a DNS name, an IPv4 literal, or a bracketed IPv6
//! literal (`http://[::1]:8080/debian`), so an IPv6-only local mirror is
//! addressable.

use std::borrow::Cow;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use rustix::fs::{FileType, Mode, OFlags};

use super::fetch::{Fetch, FetchError, FetchJob, FetchRequest};

/// The ceiling on a single response body, whatever the request states.
///
/// A request that states a size is held to that size, and to this where it
/// states more; one that states none is held to this alone. The body streams to
/// the caller's sink, which may be memory or a staging file, and its digest is
/// checked only once the bytes are spent. It sits far above any Debian index or
/// `.deb`, so it never bites a legitimate fetch, and bounds what a hostile
/// mirror can make a caller write by announcing a huge framing or never closing
/// the stream. A consumer that must fetch something larger supplies their own
/// [`Fetch`].
const MAX_BODY: u64 = 2 * 1024 * 1024 * 1024;

/// How many interim (`1xx`) responses are read past before the peer is treated
/// as never intending to send a final one. A server sends at most a handful,
/// and each costs a round trip's worth of parsing.
const MAX_INTERIM_RESPONSES: u32 = 8;

/// How much of a response's own body is read off, where the response is a
/// redirect or a refusal rather than the resource, so the connection can serve
/// the next request. Nothing here reads it, so the only question the number
/// answers is how large a page is worth keeping a connection for; a redirect
/// or error page is a few hundred bytes of HTML and this is far above any of
/// them.
const MAX_SET_ASIDE_BODY: u64 = 64 * 1024;

/// The ceiling on a single framing line — the status line, a header line, or a
/// chunk-size line. Real ones are a few hundred bytes at most; a larger one is
/// a hostile or broken mirror, not a legitimate response. Bounding each line
/// keeps a mirror from driving unbounded buffering with one enormous line,
/// which the body cap alone does not cover.
const MAX_LINE: usize = 16 * 1024;

/// The most lines a field section is read for, the blank line that ends it
/// included, so at most 255 field lines. Bounds a slowloris mirror that
/// dribbles endless headers within the per-read timeout.
const MAX_HEADERS: usize = 256;

/// How to fetch from an `https://` mirror, which this client cannot.
///
/// Named in a refusal, because a caller who has just typed a perfectly good
/// `https://` address otherwise reads the refusal as a malformed URL.
const TLS_REMEDY: &str =
    "an https:// mirror needs a Fetch implementation of your own, set with the builder's fetcher";

/// The default HTTP and `file://` fetcher.
#[derive(Debug)]
pub struct HttpFetch {
    /// How long one connection attempt may wait, or `None` for no bound of
    /// its own.
    connect_timeout: Option<Duration>,
    /// How long one read or write may wait, or `None` for no bound of its own.
    io_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    max_redirects: u32,
    cross_host_redirects: bool,
    concurrency: usize,
    /// The connection the last request left open, held for the next one.
    ///
    /// A bootstrap fetches a few hundred resources from one host, so a
    /// connection per resource is a few hundred DNS lookups, handshakes and
    /// slow-start ramps against a peer that was already answering. HTTP/1.1
    /// keeps a connection open by default and this client already does the
    /// hard part -- it reads `Content-Length` and chunked framing, which is
    /// what tells it where a response ends without waiting for the socket to
    /// close.
    ///
    /// One connection rather than a pool: `fetch` takes `&mut self` and so
    /// runs one request at a time, and [`fetch_all`](Fetch::fetch_all) gives
    /// each of its workers a fetcher of its own.
    idle: Option<Kept>,
}

/// A connection held open between requests, with whatever the reader had
/// buffered past the end of the last response.
///
/// The buffer travels with it because it must: a framed body ends where the
/// framing says, and anything the reader had already pulled from the socket
/// past that point is the next response's first bytes.
#[derive(Debug)]
struct Kept {
    host: String,
    port: u16,
    reader: BufReader<DeadlineReader>,
}

impl Clone for HttpFetch {
    /// A clone is a fetcher with the same settings and no connection: a
    /// connection belongs to whoever is using it, and two fetchers reading one
    /// socket would interleave their responses.
    fn clone(&self) -> HttpFetch {
        HttpFetch {
            connect_timeout: self.connect_timeout,
            io_timeout: self.io_timeout,
            request_timeout: self.request_timeout,
            max_redirects: self.max_redirects,
            cross_host_redirects: self.cross_host_redirects,
            concurrency: self.concurrency,
            idle: None,
        }
    }
}

impl Default for HttpFetch {
    fn default() -> Self {
        HttpFetch {
            idle: None,
            connect_timeout: Some(Duration::from_secs(30)),
            io_timeout: Some(Duration::from_secs(120)),
            // A whole-request wall-clock ceiling. The per-read timeout alone
            // does not bound total time: a mirror that trickles the body one
            // byte just under each read timeout resets the clock indefinitely.
            // One hour per file sits far above any real Debian index or `.deb`
            // fetch — each is a separate request, not a whole bootstrap — while
            // turning an endless trickle into a bounded failure.
            request_timeout: Some(Duration::from_secs(3600)),
            max_redirects: 5,
            cross_host_redirects: false,
            // Four connections hide almost all of the per-request round trip
            // against one host without asking much of a volunteer mirror.
            concurrency: 4,
        }
    }
}

impl HttpFetch {
    /// A fetcher with the default timeouts and redirect limit.
    pub fn new() -> Self {
        HttpFetch::default()
    }

    /// Sets the connection and per-read timeouts. The defaults are 30 seconds
    /// to connect and two minutes for each read or write.
    ///
    /// A timeout of zero is no timeout, as zero is for the kernel's own socket
    /// timeouts: a wait that ended before it began could never succeed, so it
    /// is not a value anything asks for on purpose. Either step is still held
    /// to the [`request_timeout`](Self::request_timeout), which bounds every
    /// connection attempt and every read whether or not a timeout of its own
    /// does.
    pub fn timeouts(mut self, connect: Duration, io: Duration) -> Self {
        self.connect_timeout = (!connect.is_zero()).then_some(connect);
        self.io_timeout = (!io.is_zero()).then_some(io);
        self
    }

    /// Sets the whole-request deadline bounding the total time one fetch may
    /// take, or `None` to remove the bound. The default is one hour per file;
    /// raise it only to fetch an unusually large artifact over a slow link.
    ///
    /// One fetch means one call, whatever it takes to answer: a redirect chain,
    /// the retry a connection reused from an earlier fetch is allowed, and the
    /// walk over the addresses a host resolves to all come out of this budget
    /// rather than starting a fresh one. The one step of an `http://` fetch it
    /// cannot bound is the address resolution itself, which the platform's
    /// resolver answers on a timeout of its own.
    ///
    /// A `file://` fetch is held to it as well. Its open never waits on what
    /// holds the path, and the deadline is checked before the open and before
    /// each read of the file. A single read the filesystem itself holds up, as a
    /// stalled network filesystem can, is the one wait it cannot cut short.
    ///
    /// A timeout beyond what the clock can express removes the bound as well:
    /// there is no faithful deadline for one, and asking to wait that long is
    /// asking to wait.
    pub fn request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Sets how many resources [`fetch_all`](Fetch::fetch_all) fetches at once
    /// (the default is 4, and 0 means 1).
    ///
    /// The ceiling is deliberately low. An archive mirror is usually somebody
    /// else's bandwidth and somebody else's connection table, and the win here
    /// is in overlapping latency rather than in saturating a link: four
    /// connections hide almost all of the per-request round trip, and more of
    /// them mostly asks a volunteer mirror for more.
    pub fn concurrency(mut self, at_once: usize) -> Self {
        self.concurrency = at_once.max(1);
        self
    }

    /// Allows a redirect to send the client to a different host.
    ///
    /// By default a redirect must stay on the same host. Authenticity comes
    /// from the archive signature, so a redirect can never substitute content;
    /// an unconstrained redirect host is nonetheless a blind, GET-only SSRF
    /// primitive, letting a hostile mirror steer the client's request at an
    /// arbitrary internal `http://` endpoint. Enable this only for a mirror
    /// that legitimately redirects to a separate CDN host.
    pub fn cross_host_redirects(mut self, allow: bool) -> Self {
        self.cross_host_redirects = allow;
        self
    }
}

impl Fetch for HttpFetch {
    fn fetch(
        &mut self,
        request: &FetchRequest<'_>,
        sink: &mut dyn Write,
    ) -> Result<(), FetchError> {
        let url = request.url();
        // The signed release states the length of every index, and the index
        // the length of every package, so most requests arrive with a ceiling
        // far below `MAX_BODY`. Where one does, it is what the body is held to:
        // a mirror that answers a request for a few megabytes with gigabytes is
        // not serving the resource that was asked for, and the digest check
        // that catches the substitution runs only after the bytes are spent.
        let cap = request.size().map_or(MAX_BODY, |size| size.min(MAX_BODY));
        // Bound the whole fetch rather than each request inside it: the
        // deadline covers the redirect chain and the one retry a reused
        // connection is allowed, so `request_timeout` is the ceiling its
        // documentation states rather than a per-attempt budget that a chain
        // multiplies by the hops it takes. A `file://` fetch is held to it too.
        //
        // A timeout the clock cannot express is a fetch without a deadline,
        // which is what a caller asking to wait some hundreds of billions of
        // years asked for; the addition would otherwise overflow and panic.
        let deadline = self
            .request_timeout
            .and_then(|timeout| Instant::now().checked_add(timeout));
        if let Some(path) = strip_scheme(url, "file://") {
            return fetch_file(url, path, sink, cap, deadline);
        }
        let mut current = url.to_string();
        for _ in 0..=self.max_redirects {
            match self.request(&current, sink, cap, deadline)? {
                Step::Done => return Ok(()),
                Step::Redirect(next) => current = next,
            }
        }
        // A chain that never arrives at a resource is this mirror's state, not
        // a URL the caller spelled wrong, so a walk over interchangeable
        // mirrors advances past it rather than failing outright.
        Err(FetchError::io(
            "following redirects",
            url,
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("more than {} redirects", self.max_redirects),
            ),
        ))
    }

    /// Fetches up to [`concurrency`](HttpFetch::concurrency) of the jobs at
    /// once, each on a connection of its own.
    ///
    /// A cold bootstrap is nearly all network: a few hundred small files from
    /// one host, each costing a round trip that nothing overlaps. Workers take
    /// the next job as they finish one, so a batch holding one large package
    /// and a hundred small ones does not wait on the large one.
    ///
    /// Each worker carries a fetcher of its own, cloned from this one, and so
    /// keeps its own connection open across the jobs it takes. This fetcher's
    /// own connection is not shared with them: one socket carrying two
    /// interleaved responses is not HTTP.
    ///
    /// A worker the host will not start a thread for is one fewer at once. The
    /// process's or the service's task limit (`RLIMIT_NPROC`, a cgroup's
    /// `pids.max`) refuses a thread with `EAGAIN`, and a batch is an
    /// optimization that has no business failing a run over it. The calling
    /// thread then takes jobs too, in the place of the workers that did not
    /// start, so a host that starts none still fetches every job, one at a
    /// time.
    fn fetch_all(&mut self, jobs: &mut [FetchJob<'_>]) -> Vec<Result<(), FetchError>> {
        let workers = self.concurrency.min(jobs.len());
        if workers <= 1 {
            return jobs
                .iter_mut()
                .map(|job| {
                    let (request, sink) = job.parts();
                    self.fetch(request, sink)
                })
                .collect();
        }

        // Each outcome is written by whichever worker took that job, so the
        // slots are handed out one per job and never shared.
        let mut outcomes: Vec<Option<Result<(), FetchError>>> =
            (0..jobs.len()).map(|_| None).collect();
        let queue = Mutex::new(
            jobs.iter_mut()
                .zip(outcomes.iter_mut())
                .collect::<Vec<_>>()
                .into_iter(),
        );

        thread::scope(|scope| {
            let mut started = 0;
            for _ in 0..workers {
                let queue = &queue;
                let mut fetcher = self.clone();
                let worker = thread::Builder::new()
                    .spawn_scoped(scope, move || take_jobs(&mut fetcher, queue));
                if worker.is_err() {
                    break;
                }
                started += 1;
            }
            if started < workers {
                take_jobs(self, &queue);
            }
        });

        outcomes
            .into_iter()
            .map(|outcome| outcome.expect("every job was taken by a worker"))
            .collect()
    }
}

/// Fetches the jobs `queue` holds with `fetcher` until none is left, recording
/// each outcome in the slot that came with its job.
///
/// What each worker of a batch runs, and the calling thread too when the host
/// would not start every worker.
fn take_jobs<'j, 'a: 'j, Q>(fetcher: &mut HttpFetch, queue: &Mutex<Q>)
where
    Q: Iterator<Item = (&'j mut FetchJob<'a>, &'j mut Option<Result<(), FetchError>>)>,
{
    loop {
        // The lock is held only long enough to take the next job, never across
        // a fetch.
        let next = queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .next();
        let Some((job, outcome)) = next else {
            return;
        };
        let (request, sink) = job.parts();
        *outcome = Some(fetcher.fetch(request, sink));
    }
}

/// The result of one request: the body was delivered, or a redirect target.
enum Step {
    Done,
    Redirect(String),
}

/// Where in an exchange a failure happened.
///
/// The distinction exists for one reason: a connection reused from a previous
/// request may have been closed by the peer while it was idle, and a peer says
/// nothing when it does. That failure is indistinguishable from a mirror that
/// closed mid-request, so a reused connection gets one fresh attempt -- but
/// only where nothing has reached the caller's sink yet, since a retry cannot
/// unwrite what was already delivered.
enum Exchange {
    /// The request was not answered, or was answered only by the `408` a
    /// closing connection sends: nothing has been written to the sink.
    BeforeBody(FetchError),
    /// The response had begun, so a retry would deliver a second copy of
    /// whatever the first attempt already wrote.
    AfterBody(FetchError),
}

impl Exchange {
    /// The failure itself, once where it happened has been acted on.
    fn into_error(self) -> FetchError {
        match self {
            Exchange::BeforeBody(err) | Exchange::AfterBody(err) => err,
        }
    }
}

/// A parsed `http://` URL.
struct HttpUrl {
    /// The host as it is resolved and compared: a DNS name, an IPv4 literal,
    /// or an IPv6 literal with its URL brackets removed.
    host: String,
    port: u16,
    path: String,
}

impl HttpUrl {
    /// The host as a URL and a `Host:` header spell it: an IPv6 literal
    /// re-bracketed, anything else unchanged.
    ///
    /// The brackets are URL syntax, present to keep the literal's colons from
    /// reading as a port separator, so they belong wherever the authority is
    /// written out and nowhere else.
    fn authority_host(&self) -> Cow<'_, str> {
        if self.host.contains(':') {
            Cow::Owned(format!("[{}]", self.host))
        } else {
            Cow::Borrowed(&self.host)
        }
    }
}

impl HttpFetch {
    /// Performs one HTTP request, streaming a 2xx body to `sink` and refusing
    /// one that runs past `cap` bytes.
    ///
    /// Reuses the connection the last request left open where it goes to the
    /// same host and port. A peer is free to close an idle connection at any
    /// time and usually says nothing when it does, so a reused connection that
    /// fails before the body has begun is retried once on a fresh one -- which
    /// is the whole of what makes reuse safe, since that failure is
    /// indistinguishable from a peer that closed while the request was in
    /// flight. A peer that does say so, with a `408` sent as it closes, is
    /// retried the same way.
    fn request(
        &mut self,
        url: &str,
        sink: &mut dyn Write,
        cap: u64,
        deadline: Option<Instant>,
    ) -> Result<Step, FetchError> {
        let parsed = parse_http_url(url).map_err(|reason| FetchError::url(url, reason))?;

        let kept = self
            .idle
            .take()
            .filter(|kept| kept.host == parsed.host && kept.port == parsed.port);
        let reused = kept.is_some();
        match self.exchange(url, &parsed, kept, sink, cap, deadline) {
            Err(Exchange::BeforeBody(_)) if reused => self
                .exchange(url, &parsed, None, sink, cap, deadline)
                .map_err(Exchange::into_error),
            outcome => outcome.map_err(Exchange::into_error),
        }
    }

    /// One request-and-response over `kept`, or over a fresh connection where
    /// there is none to reuse.
    fn exchange(
        &mut self,
        url: &str,
        parsed: &HttpUrl,
        kept: Option<Kept>,
        sink: &mut dyn Write,
        cap: u64,
        deadline: Option<Instant>,
    ) -> Result<Step, Exchange> {
        let io = |op: &'static str| FetchError::at(op, url);

        let mut reader = match kept {
            Some(mut kept) => {
                // The deadline is this fetch's, not the one the connection was
                // opened under, and the timeout is this fetcher's as it stands.
                let held = kept.reader.get_mut();
                held.deadline = deadline;
                held.io_timeout = self.io_timeout;
                kept.reader
            }
            None => {
                // The deadline bounds the whole fetch, so it is checked before
                // the work rather than only once bytes are moving. Address
                // resolution is the one step inside it that cannot be bounded
                // here: `to_socket_addrs` uses the platform's resolver, which
                // takes no deadline of its own and answers on its own timeout.
                if expired(deadline) {
                    return Err(Exchange::BeforeBody(deadline_elapsed(
                        "resolving the address",
                        url,
                    )));
                }
                let addrs = (parsed.host.as_str(), parsed.port)
                    .to_socket_addrs()
                    .map_err(io("resolving the address"))
                    .map_err(Exchange::BeforeBody)?;
                let stream = self
                    .connect(url, addrs, deadline)
                    .map_err(Exchange::BeforeBody)?;
                BufReader::new(DeadlineReader {
                    inner: stream,
                    deadline,
                    io_timeout: self.io_timeout,
                })
            }
        };
        // Each read sets its own timeout; the request's write is the one write.
        step_timeout(self.io_timeout, deadline)
            .and_then(|timeout| reader.get_ref().inner.set_write_timeout(timeout))
            .map_err(io("sending the request"))
            .map_err(Exchange::BeforeBody)?;

        let host_header = if parsed.port == 80 {
            parsed.authority_host().into_owned()
        } else {
            format!("{}:{}", parsed.authority_host(), parsed.port)
        };
        // No `Connection:` header at all, which is HTTP/1.1's own default of
        // keeping the connection open. A peer that will not is required to say
        // so, and `Headers::close` is what reads that back.
        //
        // `Accept-Encoding: identity` asks for the resource's own bytes, which
        // are what its digest is computed over. A server or a CDN left to its
        // own defaults may compress a response on the way out, and a body
        // compressed on the fly is a different sequence of bytes from the
        // resource however faithfully it decodes. A response that applies a
        // content coding regardless is refused below.
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: ferroday-cage\r\n\
             Accept: */*\r\nAccept-Encoding: identity\r\n\r\n",
            parsed.path,
        );
        (&reader.get_ref().inner)
            .write_all(request.as_bytes())
            .map_err(io("sending the request"))
            .map_err(Exchange::BeforeBody)?;

        let mut status = read_status(&mut reader)
            .map_err(io("reading the response"))
            .map_err(Exchange::BeforeBody)?;
        let mut headers = read_headers(&mut reader)
            .map_err(io("reading the response"))
            .map_err(Exchange::BeforeBody)?;

        // An interim response is not the answer to the request. RFC 9110
        // section 15.2 requires a client to read past one it never asked for,
        // which a server may send at any time — `103 Early Hints` is the one in
        // use — and a client that took the first status line for the final one
        // reports the hint as a status failure. An interim response ends at its
        // own blank line and carries no body, so reading the next status and
        // headers is the whole of skipping it.
        //
        // `101` is not interim in that sense: it says the connection has left
        // HTTP/1.1 for a protocol nothing here asked for, so it falls through
        // to the unexpected statuses below rather than being read past.
        let mut interim = 0;
        while (100..=199).contains(&status.code) && status.code != 101 {
            interim += 1;
            if interim > MAX_INTERIM_RESPONSES {
                return Err(Exchange::BeforeBody(FetchError::io(
                    "reading the response",
                    url,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("more than {MAX_INTERIM_RESPONSES} interim responses"),
                    ),
                )));
            }
            status = read_status(&mut reader)
                .map_err(io("reading the response"))
                .map_err(Exchange::BeforeBody)?;
            headers = read_headers(&mut reader)
                .map_err(io("reading the response"))
                .map_err(Exchange::BeforeBody)?;
        }

        // Whether the connection can serve another request. A response with no
        // definite framing ends at end of stream, so there is nothing after it
        // to read; a peer that said `Connection: close` is about to close; and
        // a peer speaking anything older than HTTP/1.1 promised nothing either
        // way, since a persistent connection is 1.1's own default and nothing
        // earlier's. `Connection: close` is how 1.1 departs from that default,
        // so its absence from a 1.0 response says nothing at all.
        let framed = headers.chunked || headers.content_length.is_some();
        let persistent = framed && !headers.close && status.version >= (1, 1);
        let mut keep = |reader| {
            if persistent {
                self.idle = Some(Kept {
                    host: parsed.host.clone(),
                    port: parsed.port,
                    reader,
                });
            }
        };

        match status.code {
            // A content coding this client asked not to receive and does not
            // decode: the body is not the resource's own bytes, and handed on
            // it would fail the digest check above this layer as a corrupt
            // resource, which no other mirror is asked about. It is this
            // mirror's answer instead, a transport failure a walk advances
            // past. The coding is the server's string, named with `{:?}` as
            // every server-supplied string in an error is.
            200 if headers.content_coding.is_some() => {
                let coding = headers.content_coding.take().unwrap_or_default();
                if persistent && set_aside(&mut reader, status.code, &headers) {
                    keep(reader);
                }
                return Err(Exchange::AfterBody(FetchError::io(
                    "reading the response",
                    url,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "the response applied the content coding {coding:?}, which this \
                             client asked not to receive and does not decode"
                        ),
                    ),
                )));
            }
            200 => {}
            301 | 302 | 303 | 307 | 308 => {
                let location = headers
                    .location
                    .clone()
                    .ok_or_else(|| FetchError::status(url, status.code))
                    .map_err(Exchange::AfterBody)?;
                // Its page is not held to the resource's cap: a request for a
                // signed index of a few hundred bytes would otherwise be failed
                // by the mirror's own redirect page. One past even the cap
                // `set_aside` holds it to costs the connection and nothing
                // more, and the redirect is still followed.
                if persistent && set_aside(&mut reader, status.code, &headers) {
                    keep(reader);
                }
                let next = resolve_redirect(url, &location);
                self.check_redirect(url, &next)
                    .map_err(Exchange::AfterBody)?;
                return Ok(Step::Redirect(next));
            }
            // A server closing a connection it held idle may first send a
            // `408 Request Timeout` nobody asked for (RFC 9110 section
            // 15.5.9), and a request sent down that connection reads it as its
            // answer. It says the connection went stale rather than anything
            // about the resource, and nothing has reached the sink, so it is
            // the failure a reused connection is retried for.
            408 => {
                return Err(Exchange::BeforeBody(FetchError::status(url, 408)));
            }
            // `101` says the connection has left HTTP/1.1, so nothing more is
            // asked of it.
            101 => {
                return Err(Exchange::AfterBody(FetchError::status(url, 101)));
            }
            // A refusal's page is read off as a redirect's is. A missing
            // resource is the refusal a layer answers by asking the same host
            // for another spelling of it, a by-hash path or another
            // compression, so it is the common one to keep a connection for.
            other => {
                if persistent && set_aside(&mut reader, other, &headers) {
                    keep(reader);
                }
                return Err(Exchange::AfterBody(match other {
                    404 => FetchError::not_found(url),
                    other => FetchError::status(url, other),
                }));
            }
        }

        // Every body path streams through a writer capped at what this resource
        // may weigh — the signed length where one is stated, `MAX_BODY`
        // otherwise — so a hostile mirror cannot drive unbounded buffering by
        // announcing a huge framing or never closing the connection.
        read_body(&mut reader, &headers, sink, cap)
            .map_err(io("reading the body"))
            .map_err(Exchange::AfterBody)?;
        keep(reader);
        Ok(Step::Done)
    }

    /// Connects to the first of `addrs` that accepts, in resolver order.
    ///
    /// A CDN-fronted mirror resolves to several A and AAAA records, and a host
    /// whose IPv6 egress is broken — a common CI and container condition — can
    /// reach only some of them. Trying each address in turn, and reporting the
    /// last failure only once none is left, keeps a bootstrap working there
    /// instead of making it depend on the order the resolver returned. The
    /// connect timeout applies to each attempt, as it does for every client
    /// that walks a resolved address list.
    ///
    /// The walk is held to the fetch's deadline as well, and that is what stops
    /// the two bounds from multiplying: eight black-holed addresses at the
    /// default connect timeout would otherwise wait eight times it, whatever
    /// ceiling the caller set on the fetch as a whole. Each attempt gets
    /// whichever of the two is nearer, and a deadline already reached ends the
    /// walk rather than starting an attempt that cannot finish inside it.
    fn connect(
        &self,
        url: &str,
        addrs: impl Iterator<Item = SocketAddr>,
        deadline: Option<Instant>,
    ) -> Result<TcpStream, FetchError> {
        let mut last = None;
        for addr in addrs {
            let timeout = step_timeout(self.connect_timeout, deadline)
                .map_err(FetchError::at("connecting", url))?;
            let attempt = match timeout {
                Some(timeout) => TcpStream::connect_timeout(&addr, timeout),
                None => TcpStream::connect(addr),
            };
            match attempt {
                Ok(stream) => return Ok(stream),
                Err(source) => last = Some(source),
            }
        }
        Err(match last {
            Some(source) => FetchError::io("connecting", url, source),
            None => FetchError::url(url, "the host resolved to no addresses"),
        })
    }

    /// Refuses a redirect this client will not follow: one to a URL it cannot
    /// fetch, and, unless cross-host redirects are allowed, one that leaves the
    /// host *and port* of the URL it came from. The second closes the blind,
    /// GET-only SSRF an unconstrained redirect target would otherwise allow —
    /// including the port scan a same-host, different-port redirect amounts to.
    ///
    /// Either refusal is carried as a transport failure, for the reason a
    /// redirect chain that never arrives is: where a mirror sends a request is
    /// that mirror's own arrangement rather than a URL the caller spelled
    /// wrong, so a walk over interchangeable mirrors asks the next one. One
    /// mirror redirecting to `https://`, or to a CDN, would otherwise abort the
    /// whole walk. The target is judged here rather than by the request that
    /// would follow it, which would report it as a URL the caller spelled.
    ///
    /// A refusal names `from`, the URL that was fetched, since the target never
    /// was. The target is the mirror's own string, and anyone on a plain-HTTP
    /// path can write it, so it is named the way every string a server supplies
    /// is named in an error: rendered with `{:?}`, which writes a control
    /// character as an escape rather than handing it to the terminal the error
    /// is printed on. An escape sequence there could rewrite the screen or set
    /// the clipboard.
    fn check_redirect(&self, from: &str, to: &str) -> Result<(), FetchError> {
        let refuse = |reason: String| {
            FetchError::io(
                "following a redirect",
                from,
                io::Error::new(io::ErrorKind::InvalidData, reason),
            )
        };
        if strip_scheme(to, "http://").is_none() {
            return Err(refuse(format!(
                "the redirect leads to {to:?}, and a redirect is followed only to another \
                 http:// URL; {TLS_REMEDY}"
            )));
        }
        let to_url = parse_http_url(to).map_err(|reason| {
            refuse(format!(
                "the redirect target {to:?} cannot be fetched: {reason}"
            ))
        })?;
        if self.cross_host_redirects {
            return Ok(());
        }
        let Ok(from_url) = parse_http_url(from) else {
            // Not reached: `from` is the URL the request was just made to.
            return Ok(());
        };
        if from_url.host.eq_ignore_ascii_case(&to_url.host) && from_url.port == to_url.port {
            Ok(())
        } else {
            Err(refuse(format!(
                "the redirect to {to:?} leaves for a different host ({}:{}) than {}:{}; enable \
                 cross-host redirects to follow it",
                to_url.host, to_url.port, from_url.host, from_url.port
            )))
        }
    }
}

/// The `file://` URL naming a local path — the URL form of a repository that
/// lives on this machine.
///
/// This is the construction side of what this module's own fetcher reads back,
/// and the two are stated together so a change to either is made against the
/// other.
/// A relative path is made absolute against the current directory, since a
/// `file://` URL has no way to carry one: the authority is the machine and what
/// follows it is a path from the root. The path need not exist, so the URL for
/// a repository is available before it is written.
///
/// Every byte outside the letters, the digits, `-`, `.`, `_`, `~`, and the
/// separator is written as a percent escape. A path holding a space, a newline,
/// or a byte that is not UTF-8 is therefore still one URL, and one word of the
/// apt source line a Debian root names its repository by; this module's
/// fetcher and apt both decode the escapes back into the path.
///
/// A caller reaches this for any repository that lives on this machine —
/// a Debian pool, which answers for itself through `Pool::mirror_url`, or an
/// apk repository assembled some other way; the result goes to the mirror
/// setting of whichever repository builder is being configured.
///
/// # Errors
///
/// Returns [`FetchError::Io`] when the current directory cannot be read to
/// make a relative path absolute. The failure is the transport's because the
/// locator is: a path that cannot be named is a resource that cannot be
/// addressed, whichever layer wanted to address it.
pub fn file_url(path: &Path) -> Result<String, FetchError> {
    use std::fmt::Write as _;
    use std::os::unix::ffi::OsStrExt as _;

    let absolute = std::path::absolute(path).map_err(|source| {
        FetchError::io(
            "resolving a path for its file:// URL",
            path.display().to_string(),
            source,
        )
    })?;
    let mut escaped = String::with_capacity(absolute.as_os_str().len());
    for &byte in absolute.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            escaped.push(char::from(byte));
        } else {
            // Writing to a `String` cannot fail.
            let _ = write!(escaped, "%{byte:02X}");
        }
    }
    Ok(format!("file://{escaped}"))
}

/// Reads a local file for a `file://` URL, refusing one that runs past `cap`
/// bytes, and holding the open and every read to the fetch's `deadline`.
fn fetch_file(
    url: &str,
    rest: &str,
    sink: &mut dyn Write,
    cap: u64,
    deadline: Option<Instant>,
) -> Result<(), FetchError> {
    let path = decode_file_path(url, local_file_path(url, rest)?)?;
    if expired(deadline) {
        return Err(deadline_elapsed("opening the file", url));
    }
    let file = open_local_file(&path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            FetchError::not_found(url)
        } else {
            FetchError::io("opening the file", url, source)
        }
    })?;
    let mut sink = super::LimitedWriter::new(sink, cap);
    io::copy(&mut LocalReader { file, deadline }, &mut sink)
        .map_err(FetchError::at("reading the file", url))?;
    Ok(())
}

/// Opens the regular file at `path` for a `file://` fetch, without waiting on
/// anything else that holds the path.
///
/// A local mirror is a tree an `rsync` from an upstream fills, and nothing stops
/// that upstream from leaving a named pipe where a file belongs. An ordinary open
/// of one waits until something opens its other end, and no deadline reaches a
/// wait inside `open`. So the open does not wait (`O_NONBLOCK`, with `O_NOCTTY`
/// keeping a terminal from becoming the caller's), and the descriptor is then
/// held to being a regular file. A pipe, a directory, a device, or a socket is
/// refused. `O_NONBLOCK` is cleared again once the descriptor is known to be a
/// regular file, as [`Rooted`](super::rooted::Rooted) clears it, so a filesystem
/// that does not ignore it on a file reads normally.
///
/// This is a second answer beside [`cache::open_entry`](super::cache::open_entry),
/// which refuses a symbolic link at the final component as well. A URL's path
/// is resolved as a server resolves it, links and all, and a local mirror is
/// entitled to hold a link where a file is served: a suite named by its
/// codename and by its alias, or a file shared between two of its paths. What
/// is held here is the descriptor the path reached, which is what decides
/// whether the read can wait.
fn open_local_file(path: &Path) -> io::Result<File> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) != FileType::RegularFile {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path names something other than a regular file",
        ));
    }
    rustix::fs::fcntl_setfl(&fd, rustix::fs::fcntl_getfl(&fd)? - OFlags::NONBLOCK)?;
    Ok(File::from(fd))
}

/// A local file's reader, holding each read to the fetch's deadline.
///
/// The counterpart of [`DeadlineReader`] for a `file://` fetch. A read of a
/// regular file cannot be given a timeout, so the deadline is checked before
/// each one, and a fetch that reaches it fails at the next read rather than
/// copying on to the end of the file.
struct LocalReader {
    file: File,
    deadline: Option<Instant>,
}

impl Read for LocalReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if expired(self.deadline) {
            return Err(io::Error::new(io::ErrorKind::TimedOut, DEADLINE_ELAPSED));
        }
        self.file.read(buf)
    }
}

/// The local path a `file://` URL's path spells, its percent escapes decoded.
///
/// [`file_url`] escapes every byte outside a small safe set, and this reads such
/// a path back. A component holding an escape must decode to an
/// [ordinary component](crate::path::is_ordinary_component): an escape may
/// spell any byte of a name, but not a separator the written URL does not show,
/// a NUL that would end the path, or a whole `.` or `..` that would step through
/// the tree where the written URL names an entry. Each of those is refused
/// rather than decoded, so decoding never lets a URL reach a path its written
/// form does not. A component written without an escape is taken as written.
///
/// A layer joins an index-supplied name onto a `file://` mirror as the index
/// spells it, so the name is decoded once here, as an HTTP server decodes the
/// same name in a request line. The refusal above is what keeps an escape in
/// such a name from reaching anything its written form does not.
fn decode_file_path(url: &str, path: &str) -> Result<std::path::PathBuf, FetchError> {
    use std::os::unix::ffi::OsStringExt as _;

    let refuse = |reason: &str| FetchError::url(url, reason);
    let mut decoded = Vec::with_capacity(path.len());
    for (index, component) in path.split('/').enumerate() {
        if index > 0 {
            decoded.push(b'/');
        }
        let name = super::fetch::percent_decode(component.as_bytes())
            .ok_or_else(|| refuse("the path carries a malformed percent escape"))?;
        if name != component.as_bytes() && !crate::path::is_ordinary_component(&name) {
            return Err(refuse(
                "a percent escape spells a separator, a NUL, or a `.` or `..` component, which \
                 would change the path rather than name an entry in it",
            ));
        }
        decoded.extend_from_slice(&name);
    }
    Ok(std::path::PathBuf::from(std::ffi::OsString::from_vec(
        decoded,
    )))
}

/// The local path a `file://` URL names, refusing one that names another
/// machine.
///
/// `rest` is the URL with `file://` already stripped, so it is an authority
/// followed by the path. RFC 8089 gives the authority two spellings for the
/// machine the URL is read on — empty, as in `file:///srv/pool`, and
/// `localhost`, as in `file://localhost/srv/pool` — and anything else names a
/// different host.
///
/// This library has no way to read a file from another machine, so such a URL is
/// refused rather than reinterpreted. Without the check the authority stays on
/// the front of the string and `File::open` resolves what is left relative to
/// the process's current directory, so `file://otherhost/srv/pool` would quietly
/// read `./otherhost/srv/pool` — a different file, on this machine, reported as
/// though the URL had been honoured.
///
/// The authority is split at the first `/` rather than matched by prefix, so
/// `file://localhostile/x` is the remote host `localhostile` and not the
/// relative path `ile/x`.
fn local_file_path<'a>(url: &str, rest: &'a str) -> Result<&'a str, FetchError> {
    let (authority, path) = match rest.find('/') {
        Some(at) => rest.split_at(at),
        // No separator at all: the whole of it is the authority, and the URL
        // names no path.
        None => (rest, ""),
    };
    if !authority.is_empty() && !authority.eq_ignore_ascii_case("localhost") {
        return Err(FetchError::url(
            url,
            format!(
                "the authority {authority:?} names another host, and a file:// URL this library \
                 reads names a path on this one",
            ),
        ));
    }
    if path.is_empty() {
        return Err(FetchError::url(url, "the URL names no path"));
    }
    Ok(path)
}

/// Whether `s` is an absolute URL — a scheme followed by `://` — rather than a
/// path reference. A relative `Location` has no scheme.
fn is_absolute_url(s: &str) -> bool {
    super::fetch::scheme_of(s).is_some()
}

/// Resolves a redirect `location` against the `base` URL it was returned for.
///
/// An absolute URL is returned unchanged — a non-`http` scheme is then refused
/// by [`HttpFetch::check_redirect`], so a redirect cannot escape to `file://`. A
/// network-path reference (`//host/x`, RFC 3986 section 4.2) carries an
/// authority of its own and inherits only the scheme. Any other path reference
/// resolves against the base's `http://host[:port]` origin: an absolute path
/// (`/x`) replaces the base path, a relative one (`x`) resolves against the base
/// path's directory. This resolves the target only; the same-host redirect
/// policy is applied separately by [`HttpFetch::check_redirect`], and a
/// redirected response is still checked against the signed digest, so a redirect
/// can never substitute content.
fn resolve_redirect(base: &str, location: &str) -> String {
    if is_absolute_url(location) {
        return location.to_string();
    }
    // Before the absolute-path arm below, which would otherwise read the
    // authority as the first two segments of a path and compose
    // `http://base-host//cdn.example/x` — a request to the wrong resource on
    // the base's host, which the same-host policy then has no reason to refuse.
    if let Some(authority_and_path) = location.strip_prefix("//") {
        return format!("http://{authority_and_path}");
    }
    let Ok(parsed) = parse_http_url(base) else {
        return location.to_string();
    };
    let origin = if parsed.port == 80 {
        format!("http://{}", parsed.authority_host())
    } else {
        format!("http://{}:{}", parsed.authority_host(), parsed.port)
    };
    if let Some(absolute) = location.strip_prefix('/') {
        format!("{origin}/{absolute}")
    } else {
        let dir = match parsed.path.rfind('/') {
            Some(slash) => &parsed.path[..=slash],
            None => "/",
        };
        format!("{origin}{dir}{location}")
    }
}

/// Strips `scheme` from `url`, comparing it case-insensitively.
///
/// Only the scheme is case-insensitive; the rest of the URL is returned exactly
/// as written, since a path is not.
fn strip_scheme<'u>(url: &'u str, scheme: &str) -> Option<&'u str> {
    let prefix = url.get(..scheme.len())?;
    prefix
        .eq_ignore_ascii_case(scheme)
        .then(|| &url[scheme.len()..])
}

/// Parses an `http://host[:port]/path` URL, or answers why it is not one this
/// client fetches.
///
/// The scheme is matched case-insensitively, as RFC 3986 §3.1 requires and as
/// [`scheme_of`](super::fetch::scheme_of) documents. A literal comparison would
/// let `HTTP://` be a URL one check in this crate accepts and another refuses,
/// with the second refusing it for the wrong reason.
///
/// A URL carrying anything outside printable ASCII is refused whole, and that
/// refusal is this client's request-line boundary. [`request`](HttpFetch::request)
/// interpolates the parsed path verbatim into `GET <path> HTTP/1.1`, and every
/// other URL this crate composes has already passed a check of its own —
/// `coordinate::check` for a layer's own coordinates, `is_safe_pool_path` for a
/// pool path, `Algorithm::is_hex` for a digest. `coordinate::check` holds a
/// coordinate to a subset of what this accepts, so a value it accepts reaches
/// the server as it was written. A redirect `Location` has passed none: it is
/// a hostile mirror's string, and one holding a CR or an LF would otherwise
/// write headers of its own into the follow-up request. Refusing here covers
/// the whole URL rather than the path alone, since the host reaches the
/// request line too, through the `Host:` header.
fn parse_http_url(url: &str) -> Result<HttpUrl, String> {
    let bad = |reason: &str| reason.to_string();
    if !url.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(bad(
            "the URL carries a space, a control character, or a character outside ASCII, none \
             of which a request line can hold as written",
        ));
    }
    let rest = strip_scheme(url, "http://")
        .ok_or_else(|| format!("this fetcher speaks only http:// and file://; {TLS_REMEDY}"))?;
    let (authority, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, "/"),
    };
    // An IPv6 literal is bracketed precisely so its colons cannot be read as
    // the port separator, so it is split off before the port is looked for. The
    // brackets are stripped here: they are URL syntax, and the host is carried
    // in the form that resolves and compares.
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (literal, after) = rest
            .split_once(']')
            .ok_or_else(|| bad("the bracketed host literal is unterminated"))?;
        let port = match after.strip_prefix(':') {
            Some(port) => port.parse().map_err(|_| bad("the port is not a number"))?,
            None if after.is_empty() => 80,
            None => return Err(bad("the bracketed host is followed by junk")),
        };
        if literal.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(bad("the bracketed host is not an IPv6 literal"));
        }
        (literal.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (
                host.to_string(),
                port.parse().map_err(|_| bad("the port is not a number"))?,
            ),
            None => (authority.to_string(), 80),
        }
    };
    if host.is_empty() {
        return Err(bad("the host is empty"));
    }
    Ok(HttpUrl {
        host,
        port,
        path: path.to_string(),
    })
}

/// The response headers this client acts on.
#[derive(Debug, Default)]
struct Headers {
    content_length: Option<u64>,
    chunked: bool,
    location: Option<String>,
    /// The first content coding the response applied other than `identity`,
    /// as the server spelled it, where it applied one.
    content_coding: Option<String>,
    /// Whether the peer said it will close the connection after this response.
    ///
    /// HTTP/1.1 keeps a connection open unless a response says otherwise, so
    /// this is what decides whether the connection can be held for the next
    /// request.
    close: bool,
}

/// Reads one line through its newline into `line`, capping its length at
/// [`MAX_LINE`]. Returns the bytes read, zero at end of stream. A line over the
/// cap is a hostile or broken mirror, refused rather than buffered.
///
/// A byte that is not UTF-8 is read as U+FFFD rather than refused. RFC 9110
/// permits such bytes, obs-text, in a field's value and in a status line's
/// reason phrase, and treats the value as opaque. No field this client acts on
/// can hold one and still be read as a value it acts on: a number or a coding
/// with U+FFFD in it is refused as malformed, a `Location` holding one is a URL
/// no request line can carry, and `Connection` matches `close` alone.
fn read_line_limited<R: BufRead>(reader: &mut R, line: &mut String) -> io::Result<usize> {
    // Reading one byte past the cap distinguishes a line exactly at the cap
    // from one that overruns it.
    let mut bytes = Vec::new();
    let read = reader
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut bytes)?;
    if bytes.len() > MAX_LINE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a response line exceeded the length cap",
        ));
    }
    line.push_str(&String::from_utf8_lossy(&bytes));
    Ok(read)
}

/// A response's status line.
#[derive(Debug, PartialEq, Eq)]
struct Status {
    /// Major and minor, as `HTTP/<major>.<minor>` spells them.
    version: (u8, u8),
    code: u16,
}

/// Reads and parses the status line.
///
/// The version token is parsed, not merely skipped over. Reading the second
/// word of any line that happens to parse as a number would take a mail or SSH
/// server's greeting for a response — the digest chain makes that harmless, but
/// a mirror URL pointed at the wrong port then fails somewhere further on
/// instead of saying what it found. The version itself is acted on in one
/// place: whether the connection can be held for another request.
fn read_status<R: BufRead>(reader: &mut R) -> io::Result<Status> {
    let mut line = String::new();
    read_line_limited(reader, &mut line)?;
    let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed status line");
    let mut words = line.split_whitespace();
    let version = words.next().and_then(parse_version).ok_or_else(malformed)?;
    let code = words
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(malformed)?;
    Ok(Status { version, code })
}

/// Parses an `HTTP/<major>.<minor>` version token, which RFC 9112 spells with
/// exactly one digit on each side of the dot.
fn parse_version(token: &str) -> Option<(u8, u8)> {
    // Split as bytes: the token is arbitrary input, and slicing a `str` at a
    // fixed index would panic where that index is not a character boundary.
    let (name, version) = token.as_bytes().split_at_checked(5)?;
    if !name.eq_ignore_ascii_case(b"HTTP/") {
        return None;
    }
    match version {
        [major, b'.', minor] if major.is_ascii_digit() && minor.is_ascii_digit() => {
            Some((major - b'0', minor - b'0'))
        }
        _ => None,
    }
}

/// Reads a field section, handing each field line to `field` and stopping at
/// the blank line that ends it. `section` names it in a failure.
///
/// A response has two: the headers, and the trailer section that follows a
/// chunked body. They are the same grammar and carry the same hazards, so they
/// are read the same way — all that differs is what a caller does with a line.
///
/// Only the blank separator ends a section. A stream that ends inside one is
/// a truncated response — an overloaded backend, a proxy that dropped the
/// response — and is refused rather than read as a complete section with no
/// framing, which would deliver an empty body as a successful fetch.
///
/// A line beginning with a space or a tab continues the field before it, the
/// obsolete line folding RFC 9112 section 5.2 has a recipient replace with a
/// space before reading the value. Read as a field of its own, a folded line
/// holding a colon would be a header the server did not send, framing
/// included. A field is therefore handed on only once the next line shows it
/// is not continued, and a continuation with nothing before it is refused.
fn read_field_section<R: BufRead>(
    reader: &mut R,
    section: &str,
    mut field: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    let malformed = |reason: &str| io::Error::new(io::ErrorKind::InvalidData, reason.to_string());
    // The field line read last, held until the next line shows whether it is
    // continued.
    let mut held: Option<String> = None;
    for _ in 0..MAX_HEADERS {
        let mut line = String::new();
        if read_line_limited(reader, &mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("the response ended inside the {section} section"),
            ));
        }
        let line = line.trim_end();
        if line.starts_with([' ', '\t']) {
            let Some(continued) = held.as_mut() else {
                return Err(malformed(&format!(
                    "the {section} section begins with a continuation line"
                )));
            };
            continued.push(' ');
            continued.push_str(line.trim_start());
            if continued.len() > MAX_LINE {
                return Err(malformed(&format!(
                    "a folded {section} line exceeded the length cap"
                )));
            }
            continue;
        }
        if let Some(complete) = held.take() {
            field(&complete)?;
        }
        if line.is_empty() {
            return Ok(());
        }
        held = Some(line.to_string());
    }
    // More field lines than the cap without a blank separator: a hostile or
    // broken mirror, refused rather than read on.
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the response sent more {section} lines than the cap"),
    ))
}

/// `text` as a number the framing grammar spells: one or more digits of
/// `radix`, and nothing else.
///
/// Rust's integer parsers also take a leading `+`, which neither
/// `Content-Length` (`1*DIGIT`) nor a chunk size (`1*HEXDIG`) admits. Both
/// decide where a body ends, and framing read more leniently than its grammar
/// is framing that another reader of the same bytes disagrees with.
fn framing_number(text: &str, radix: u32) -> Option<u64> {
    if text.is_empty() || !text.chars().all(|digit| digit.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(text, radix).ok()
}

/// Reads the response headers up to the blank separator line.
fn read_headers<R: BufRead>(reader: &mut R) -> io::Result<Headers> {
    let mut headers = Headers::default();
    read_field_section(reader, "header", |line| {
        if let Some((name, value)) = line.split_once(':') {
            let (name, value) = (name.trim(), value.trim());
            if name.eq_ignore_ascii_case("content-length") {
                // Content-Length is framing, not decoration: a value that does
                // not parse, or a repeat that contradicts the first, leaves the
                // body's extent unknown. Reading such a response to end of
                // stream would turn a truncation into a short, successful body,
                // so it is refused instead.
                let length = framing_number(value, 10).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed Content-Length")
                })?;
                if headers.content_length.is_some_and(|first| first != length) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the response repeated Content-Length with a different value",
                    ));
                }
                headers.content_length = Some(length);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                // A list of codings, which repeated field lines extend. This
                // client offers to read none but `chunked`, and a server may
                // apply no other unless offered. Any other coding, or `chunked`
                // twice, leaves the body unreadable here, so it is refused
                // rather than handed on as the resource. Matched by token: a
                // substring match would take `notchunked` for the one coding
                // that is understood.
                for coding in value.split(',').map(str::trim).filter(|c| !c.is_empty()) {
                    if !coding.eq_ignore_ascii_case("chunked") || headers.chunked {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "the response applied a transfer coding other than one chunked \
                             coding, which this client does not read",
                        ));
                    }
                    headers.chunked = true;
                }
            } else if name.eq_ignore_ascii_case("location") {
                headers.location = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("content-encoding") {
                // A list of codings, which repeated field lines extend. Only the
                // first one that is not `identity` is kept: one is enough to
                // say the body is not the resource's own bytes.
                if headers.content_coding.is_none() {
                    headers.content_coding = value
                        .split(',')
                        .map(str::trim)
                        .find(|coding| {
                            !coding.is_empty() && !coding.eq_ignore_ascii_case("identity")
                        })
                        .map(str::to_string);
                }
            } else if name.eq_ignore_ascii_case("connection")
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("close"))
            {
                // The peer will close after this response, so the connection is
                // not one to hold for the next request. A comma-separated list
                // is legal here and `close` may be anywhere in it.
                headers.close = true;
            }
        }
        Ok(())
    })?;
    // Two framings in one response are two answers to where the body ends.
    // This client would take the chunked one, as it is required to, but an
    // intermediary that took the other disagrees about where the *next*
    // response begins — and a connection held across that disagreement serves
    // the following request whatever the two left behind. It is the shape a
    // response-splitting attack has, and it is refused for the same reason a
    // self-contradicting Content-Length is: framing a recipient has to guess at
    // is not framing.
    if headers.chunked && headers.content_length.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the response declared both chunked framing and a Content-Length",
        ));
    }
    Ok(headers)
}

/// Reads the trailer section that ends a chunked body, discarding its fields.
///
/// The section is there even when it carries none: RFC 9112 ends it with a
/// blank line either way, so a chunked response is not fully read until that
/// line has been. Stopping at the last chunk costs nothing on a connection
/// about to be closed and poisons one held for the next request, whose status
/// line is then read from what this response left on the socket.
///
/// The fields themselves are discarded because nothing here acts on one, and
/// the fields that would matter — framing above all — are not allowed to appear
/// in a trailer.
fn read_trailers<R: BufRead>(reader: &mut R) -> io::Result<()> {
    read_field_section(reader, "trailer", |_| Ok(()))
}

/// Reads off the body of a response that is not the resource, a redirect or a
/// refusal, answering whether the connection it came on can serve the next
/// request.
///
/// Such a body is framed like any other, and the connection is reusable only
/// once it has been read: a reader left part way through a body reads the next
/// response from the middle of this one. It is neither delivered nor held to
/// the resource's cap, only to [`MAX_SET_ASIDE_BODY`], and a longer one costs
/// the connection and nothing more.
///
/// A `204` or a `304` carries no body whatever its framing headers say (RFC
/// 9112 section 6.3), so there is nothing to read. Reading the length a `304`
/// states would wait on bytes the server never sends.
fn set_aside<R: BufRead>(reader: &mut R, code: u16, headers: &Headers) -> bool {
    match code {
        204 | 304 => true,
        _ => read_body(reader, headers, &mut io::sink(), MAX_SET_ASIDE_BODY).is_ok(),
    }
}

/// Reads one response body, however it is framed, into `sink`.
///
/// `cap` is what this resource may weigh -- the signed length where one is
/// stated, `MAX_BODY` otherwise -- and every path streams through a writer held
/// to it, so a hostile mirror cannot drive unbounded buffering by announcing a
/// huge framing or never closing the connection.
fn read_body<R: BufRead>(
    reader: &mut R,
    headers: &Headers,
    sink: &mut dyn Write,
    cap: u64,
) -> io::Result<()> {
    let mut sink = super::LimitedWriter::new(sink, cap);
    if headers.chunked {
        read_chunked(reader, &mut sink)
    } else if let Some(length) = headers.content_length {
        if length > cap {
            // The refusal `LimitedWriter` makes when a body runs past the cap,
            // made here before a byte is read because this response said in
            // advance how big it was. Reported identically, so which of the two
            // a mirror meets -- and whether a walk over several of them
            // advances past it -- does not depend on the framing that mirror
            // chose.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the response is {length} bytes, over the {cap}-byte cap"),
            ));
        }
        read_sized(reader, length, &mut sink)
    } else {
        // No framing: the body runs to end of stream, which the peer's own
        // `Connection: close` is what promises.
        io::copy(reader, &mut sink).map(|_| ())
    }
}

/// Copies exactly `length` bytes from `reader` to `sink`, refusing a stream
/// that ends before them as a truncated body.
fn read_sized<R: Read>(reader: &mut R, length: u64, sink: &mut dyn Write) -> io::Result<()> {
    let copied = io::copy(&mut reader.take(length), sink)?;
    if copied != length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the body ended before Content-Length",
        ));
    }
    Ok(())
}

/// Decodes a chunked transfer-encoded body into `sink`.
fn read_chunked<R: BufRead>(reader: &mut R, sink: &mut dyn Write) -> io::Result<()> {
    loop {
        let mut line = String::new();
        read_line_limited(reader, &mut line)?;
        // The chunk size is hex, before any `;`-delimited extension.
        let size = framing_number(line.trim().split(';').next().unwrap_or("").trim(), 16)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed chunk size"))?;
        if size == 0 {
            // The last chunk is followed by the trailer section, which is part
            // of this response and not of the next one.
            return read_trailers(reader);
        }
        // Stream the chunk body in bounded pieces (`io::copy` uses a fixed
        // internal buffer) rather than allocating the whole announced size up
        // front, so a huge chunk-size line cannot force a large allocation.
        let copied = io::copy(&mut reader.take(size), sink)?;
        if copied != size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the chunk ended before its declared size",
            ));
        }
        // Each chunk body is followed by a bare CRLF. Read it through the
        // length cap, not a bare `read_line`: a hostile mirror could otherwise
        // stream unbounded data where the terminator belongs, growing this
        // buffer without limit while each read returns promptly enough that the
        // per-read timeout never fires.
        let mut terminator = String::new();
        read_line_limited(reader, &mut terminator)?;
        if !terminator.trim_end_matches(['\r', '\n']).is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a chunk was not terminated by a bare CRLF",
            ));
        }
    }
}

/// A connection's reader, holding each read to the fetch's wall-clock deadline
/// as well as to the per-read timeout.
///
/// The per-read timeout alone does not bound a response: a mirror that trickles
/// bytes just inside it keeps every read alive. So each read waits at most
/// whichever is nearer, the timeout or what is left of the deadline, and one
/// started after the deadline fails at once. Total time is therefore bounded
/// by the deadline, with or without a timeout of the read's own. `None` for
/// either removes that bound.
#[derive(Debug)]
struct DeadlineReader {
    inner: TcpStream,
    deadline: Option<Instant>,
    io_timeout: Option<Duration>,
}

impl Read for DeadlineReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = step_timeout(self.io_timeout, self.deadline)?;
        self.inner.set_read_timeout(timeout)?;
        match self.inner.read(buf) {
            // A read the deadline cut short reports the deadline, in the words
            // every other step it bounds uses, and one its own timeout ended
            // reports that, each rather than the bare `EAGAIN` a socket timeout
            // reads as. The fetch's error names the URL around either.
            Err(err) if is_timeout(&err) && expired(self.deadline) => {
                Err(io::Error::new(io::ErrorKind::TimedOut, DEADLINE_ELAPSED))
            }
            Err(err) if is_timeout(&err) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "no data arrived within the read timeout{}",
                    timeout.map_or(String::new(), |timeout| format!(" of {timeout:?}")),
                ),
            )),
            read => read,
        }
    }
}

/// Whether a socket operation failed because its timeout ran out, which Linux
/// reports as `EAGAIN` for a read and `std` may report as either kind.
fn is_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// How long one step of a fetch may wait: its own timeout or what is left of
/// the fetch's deadline, whichever is nearer, or `None` where neither bounds
/// it.
///
/// A deadline already reached fails the step before it starts, since it could
/// not finish inside it. The failure is the one [`deadline_elapsed`] reports.
fn step_timeout(own: Option<Duration>, deadline: Option<Instant>) -> io::Result<Option<Duration>> {
    match (own, remaining(deadline)) {
        (_, Some(Duration::ZERO)) => Err(io::Error::new(io::ErrorKind::TimedOut, DEADLINE_ELAPSED)),
        (Some(own), Some(left)) => Ok(Some(own.min(left))),
        (own, left) => Ok(own.or(left)),
    }
}

/// What a fetch reports when its whole-request deadline has passed. One wording
/// for every step it bounds, so a caller reads the same sentence whether the
/// deadline was reached before the connection or part way through the body.
const DEADLINE_ELAPSED: &str = "the overall fetch deadline elapsed";

/// How much of `deadline` is left, or `None` where there is no deadline at all.
/// A deadline already reached leaves [`Duration::ZERO`].
fn remaining(deadline: Option<Instant>) -> Option<Duration> {
    deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()))
}

/// Whether `deadline` is set and has passed.
fn expired(deadline: Option<Instant>) -> bool {
    remaining(deadline) == Some(Duration::ZERO)
}

/// The deadline failure, named for the step that could not be started.
///
/// A transport failure rather than a `Url` one, because a deadline reached is
/// what this exchange did rather than how the caller spelled it, and a walk over
/// interchangeable mirrors is right to ask the next.
fn deadline_elapsed(op: &'static str, url: &str) -> FetchError {
    FetchError::io(
        op,
        url,
        io::Error::new(io::ErrorKind::TimedOut, DEADLINE_ELAPSED),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure::ErrorChain;
    use crate::scratch::Scratch;

    /// Serves one canned response to each of `connections` requests on a
    /// loopback port, and answers the URL to fetch from it.
    ///
    /// The client is the thing under test, so the server does the least that
    /// keeps it honest: it reads the request through its blank separator line,
    /// so the client's write completes, and writes the bytes the test chose.
    /// The thread ends when it has served them all, which is what makes the
    /// count part of the assertion — a client that made more requests than the
    /// test expected meets a closed port.
    fn serving(connections: usize, response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a loopback listener binds");
        let url = format!(
            "http://{}/x",
            listener.local_addr().expect("the listener is bound"),
        );
        let served = std::thread::spawn(move || {
            for _ in 0..connections {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut request = BufReader::new(stream.try_clone().expect("the stream clones"));
                let mut line = String::new();
                while request.read_line(&mut line).is_ok_and(|read| read > 0) {
                    if line == "\r\n" {
                        break;
                    }
                    line.clear();
                }
                let _ = stream.write_all(&response);
            }
        });
        (url, served)
    }

    /// Serves `responses` in order down *one* connection, and reports how many
    /// connections were accepted.
    ///
    /// The count is the whole point: a client that reuses its connection
    /// accepts one, and a client that opens a fresh one per request accepts as
    /// many as it made.
    fn serving_one_connection(
        responses: Vec<Vec<u8>>,
    ) -> (
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a loopback listener binds");
        let url = format!(
            "http://{}/x",
            listener.local_addr().expect("the listener is bound"),
        );
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&accepted);
        let served = std::thread::spawn(move || {
            let mut remaining = responses.into_iter().peekable();
            'accept: while remaining.peek().is_some() {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut request = BufReader::new(stream.try_clone().expect("the stream clones"));
                loop {
                    let mut line = String::new();
                    // End of input means the client is done with this
                    // connection; whatever is left goes to the next one.
                    match request.read_line(&mut line) {
                        Ok(0) | Err(_) => continue 'accept,
                        Ok(_) => {}
                    }
                    if line != "\r\n" {
                        continue;
                    }
                    let Some(response) = remaining.next() else {
                        return;
                    };
                    if stream.write_all(&response).is_err() {
                        continue 'accept;
                    }
                    // Serving the last one ends the thread, so a test that
                    // joins it does not wait for a connection nobody will make.
                    if remaining.peek().is_none() {
                        return;
                    }
                }
            }
        });
        (url, accepted, served)
    }

    /// Serves one canned response to every request it is asked, on as many
    /// connections as the client opens, and reports how many that was.
    ///
    /// [`serving_one_connection`] cannot ask what a *failure* of reuse costs:
    /// it stops once its scripted responses run out, so a client that discards
    /// an answer and asks again meets a closed listener rather than a peer that
    /// is still there, and the test then fails on the retry's `ConnectionReset`
    /// instead of on the connection count. What a reuse failure actually costs
    /// is a second request against a peer that is still answering.
    ///
    /// Stops when it is dropped, which is why the test drops the fetcher first:
    /// a connection the client still holds is one this is still reading.
    struct Serving {
        url: String,
        port: u16,
        accepted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        served: Option<std::thread::JoinHandle<()>>,
    }

    impl Serving {
        fn new(response: Vec<u8>) -> Serving {
            Serving::answering(move |_| Some(response.clone()))
        }

        /// As [`Serving::new`], with the response chosen per request from the
        /// count of requests already answered on this listener.
        fn answering(respond: impl FnMut(usize) -> Option<Vec<u8>> + Send + 'static) -> Serving {
            let mut respond = respond;
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .expect("a loopback listener binds");
            let addr = listener.local_addr().expect("the listener is bound");
            let url = format!("http://{addr}/x");
            let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (counter, halt) = (
                std::sync::Arc::clone(&accepted),
                std::sync::Arc::clone(&stop),
            );
            let served = std::thread::spawn(move || {
                let stopping = || halt.load(std::sync::atomic::Ordering::SeqCst);
                let mut answered = 0;
                'accept: while !stopping() {
                    let Ok((mut stream, _)) = listener.accept() else {
                        return;
                    };
                    if stopping() {
                        // The connection that woke the accept, not a client's.
                        return;
                    }
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    // So a connection the client is holding idle does not park
                    // this thread past the point the test wants it to stop.
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                    let mut request =
                        BufReader::new(stream.try_clone().expect("the stream clones"));
                    loop {
                        let mut line = String::new();
                        match request.read_line(&mut line) {
                            Ok(0) => continue 'accept,
                            Ok(_) => {}
                            Err(error) if is_timeout(&error) => match stopping() {
                                true => return,
                                false => continue,
                            },
                            Err(_) => continue 'accept,
                        }
                        if line != "\r\n" {
                            continue;
                        }
                        let Some(response) = respond(answered) else {
                            return;
                        };
                        answered += 1;
                        if stream.write_all(&response).is_err() {
                            continue 'accept;
                        }
                    }
                }
            });
            Serving {
                url,
                port: addr.port(),
                accepted,
                stop,
                served: Some(served),
            }
        }

        fn connections(&self) -> usize {
            self.accepted.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Drop for Serving {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            // Wakes the thread where it is parked in `accept`; the connection
            // is never answered, and the thread counts it as none.
            let _ = std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, self.port));
            if let Some(served) = self.served.take() {
                let _ = served.join();
            }
        }
    }

    /// Fetches `url` `times` over one fetcher, asserting each answer.
    fn fetch_repeatedly(fetcher: &mut HttpFetch, url: &str, times: usize, body: &[u8]) {
        for _ in 0..times {
            let mut out = Vec::new();
            fetcher
                .fetch(&FetchRequest::new(url), &mut out)
                .expect("each fetch answers");
            assert_eq!(out, body);
        }
    }

    #[test]
    fn a_chunked_response_leaves_the_connection_reusable() {
        // A chunked body ends with a trailer section, which is empty here and
        // is still two bytes of this response. Leaving them on the socket puts
        // them where the next response's status line is read from, which costs
        // a wasted request and the reconnect it was already paying -- so a
        // mirror that chunks would be slower with reuse than without it.
        let served = Serving::new(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\nfirst\r\n0\r\n\r\n"
                .to_vec(),
        );
        let mut fetcher = HttpFetch::new();
        fetch_repeatedly(&mut fetcher, &served.url, 3, b"first");
        assert_eq!(
            served.connections(),
            1,
            "three fetches down one held connection, as a framed body already manages",
        );
        drop(fetcher);
    }

    #[test]
    fn a_chunked_trailer_leaves_the_connection_reusable() {
        // The same, for the section a mirror actually puts fields in. Nothing
        // here reads them; what matters is that they are read *off*.
        let served = Serving::new(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\nfirst\r\n0\r\nExpires: never\r\nX-Checksum: 00\r\n\r\n"
                .to_vec(),
        );
        let mut fetcher = HttpFetch::new();
        fetch_repeatedly(&mut fetcher, &served.url, 3, b"first");
        assert_eq!(served.connections(), 1, "a trailer section is read off too");
        drop(fetcher);
    }

    #[test]
    fn an_http_1_0_peer_is_not_held_open() {
        // A persistent connection is HTTP/1.1's default and nothing earlier's,
        // so a 1.0 peer that did not say `Connection: close` has still promised
        // nothing -- holding it buys a wasted request per fetch.
        let served = Serving::new(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nfirst".to_vec());
        let mut fetcher = HttpFetch::new();
        fetch_repeatedly(&mut fetcher, &served.url, 1, b"first");
        assert!(
            fetcher.idle.is_none(),
            "a peer older than HTTP/1.1 is not held open",
        );
        drop(fetcher);
    }

    #[test]
    fn a_response_framed_two_ways_is_refused() {
        // Chunked framing wins over a Content-Length by rule, but an
        // intermediary that read the other one disagrees about where the next
        // response starts. Nothing is served from a connection held across that
        // disagreement, so the response is refused instead.
        let served = Serving::new(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n\
              5\r\nfirst\r\n0\r\n\r\n"
                .to_vec(),
        );
        let mut fetcher = HttpFetch::new();
        let mut out = Vec::new();
        let err = fetcher
            .fetch(&FetchRequest::new(&served.url), &mut out)
            .expect_err("two framings in one response are refused");
        assert!(err.to_string().contains("reading the response"), "{err}");
        assert!(out.is_empty(), "nothing is delivered from it");
        drop(fetcher);
    }

    #[test]
    fn one_fetch_shares_one_deadline_with_the_redirects_it_follows() {
        // `request_timeout` is documented as the ceiling on one fetch. A
        // deadline computed per request instead would give each hop of a chain
        // a fresh budget, so a chain of them could run to several times the
        // ceiling -- five redirects being what the default allows.
        //
        // Each hop here waits, and their waits together pass the ceiling while
        // no single one comes near it.
        const HOP: Duration = Duration::from_millis(60);
        let served = Serving::answering(|answered| {
            std::thread::sleep(HOP);
            Some(
                match answered {
                    // Same host and port, which the same-origin rule requires.
                    0..=2 => format!(
                        "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: /{answered}\r\n\r\n"
                    ),
                    _ => "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst".to_string(),
                }
                .into_bytes(),
            )
        });
        let mut fetcher = HttpFetch::new().request_timeout(Some(HOP * 5 / 2));
        let mut out = Vec::new();
        let err = fetcher
            .fetch(&FetchRequest::new(&served.url), &mut out)
            .expect_err("the chain runs past the fetch's deadline");
        assert!(
            ErrorChain::new(&err).to_string().contains("deadline"),
            "{err}"
        );
        drop(fetcher);
    }

    #[test]
    fn a_zero_timeout_is_no_timeout() {
        // `std` refuses a zero socket timeout, so taken as written it failed
        // every connection, on every mirror in turn.
        let served = Serving::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst".to_vec());
        let mut fetcher = HttpFetch::new().timeouts(Duration::ZERO, Duration::ZERO);
        fetch_repeatedly(&mut fetcher, &served.url, 2, b"first");
        drop(fetcher);
    }

    #[test]
    fn a_read_with_no_timeout_of_its_own_is_held_to_the_deadline() {
        // A peer that accepts the request and never answers. With no per-read
        // timeout, the read waits on the fetch's deadline alone, which has to
        // end it: one checked only between reads would wait forever.
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a loopback listener binds");
        let url = format!(
            "http://{}/x",
            listener.local_addr().expect("the listener is bound"),
        );
        let (done, waited) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut fetcher = HttpFetch::new()
                .timeouts(Duration::ZERO, Duration::ZERO)
                .request_timeout(Some(Duration::from_millis(200)));
            let outcome = fetcher.fetch(&FetchRequest::new(&url), &mut Vec::new());
            let _ = done.send(outcome.map_err(|err| ErrorChain::new(&err).to_string()));
        });
        let outcome = waited
            .recv_timeout(Duration::from_secs(30))
            .expect("the fetch ended at its deadline rather than waiting on the peer");
        let err = outcome.expect_err("the peer never answers");
        assert!(err.contains(DEADLINE_ELAPSED), "{err}");
        drop(listener);
    }

    #[test]
    fn a_read_that_outlasts_its_own_timeout_is_reported_as_one() {
        // A peer that accepts the request and never answers, read with a
        // timeout of its own well inside the fetch's deadline. The socket
        // reports the timeout as `EAGAIN`, "Resource temporarily unavailable",
        // which says nothing of a timeout to the reader of the error.
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a loopback listener binds");
        let url = format!(
            "http://{}/x",
            listener.local_addr().expect("the listener is bound"),
        );
        let err = HttpFetch::new()
            .timeouts(Duration::from_secs(5), Duration::from_millis(100))
            .request_timeout(Some(Duration::from_secs(60)))
            .fetch(&FetchRequest::new(&url), &mut Vec::new())
            .expect_err("the peer never answers");
        let chain = ErrorChain::new(&err).to_string();
        assert!(chain.contains("read timeout of 100ms"), "{chain}");
        assert!(chain.contains(&url), "{chain}");
        assert!(!chain.contains(DEADLINE_ELAPSED), "{chain}");
        assert!(err.is_failover(), "{err}");
        drop(listener);
    }

    #[test]
    fn a_field_value_outside_utf8_is_read_as_opaque_bytes() {
        // RFC 9110 permits obs-text in a field's value and a reason phrase.
        // None of the mirrors this client is pointed at sends any, but one
        // that did would have failed every fetch on a header nothing reads.
        let mut response = b"HTTP/1.1 200 Gr\xfc\xdfe\r\nX-Note: caf\xe9\r\n".to_vec();
        response.extend_from_slice(b"Content-Length: 5\r\n\r\nfirst");
        let (url, served) = serving(1, response);
        let mut out = Vec::new();
        HttpFetch::new()
            .fetch(&FetchRequest::new(&url), &mut out)
            .expect("the response is read");
        assert_eq!(out, b"first");
        served.join().expect("the server finishes");

        // A field the client acts on is still refused where it holds one.
        for field in [
            &b"Content-Length: 5\xff"[..],
            b"Location: http://mirror.example/caf\xe9",
        ] {
            let mut response = b"HTTP/1.1 301 Moved\r\n".to_vec();
            response.extend_from_slice(field);
            response.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
            let (url, served) = serving(1, response);
            let err = HttpFetch::new()
                .fetch(&FetchRequest::new(&url), &mut Vec::new())
                .expect_err("the field is refused");
            assert!(err.is_failover(), "{err}");
            served.join().expect("the server finishes");
        }
    }

    #[test]
    fn a_second_fetch_reuses_the_connection_the_first_left_open() {
        // The win this buys: a bootstrap fetches a few hundred resources from
        // one host, and a connection per resource is a few hundred handshakes
        // and slow-start ramps against a peer that was already answering.
        let response = |body: &str| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len(),
            )
            .into_bytes()
        };
        let (url, accepted, served) =
            serving_one_connection(vec![response("first"), response("second")]);

        let mut fetcher = HttpFetch::new();
        let mut first = Vec::new();
        fetcher
            .fetch(&FetchRequest::new(&url), &mut first)
            .expect("the first fetch answers");
        let mut second = Vec::new();
        fetcher
            .fetch(&FetchRequest::new(&url), &mut second)
            .expect("the second fetch answers");

        assert_eq!(first, b"first");
        assert_eq!(second, b"second");
        assert_eq!(
            accepted.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the second request should have gone down the first connection",
        );
        drop(fetcher);
        served.join().expect("the server thread ends");
    }

    #[test]
    fn a_peer_that_says_it_will_close_is_not_held_open() {
        // `Connection: close` is the peer saying this connection serves one
        // response. Holding it would make the next request fail and retry,
        // which is correct but wasteful, so it is not held.
        let body = "only";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        )
        .into_bytes();
        let (url, served) = serving(2, response);

        let mut fetcher = HttpFetch::new();
        for _ in 0..2 {
            let mut out = Vec::new();
            fetcher
                .fetch(&FetchRequest::new(&url), &mut out)
                .expect("each fetch answers");
            assert_eq!(out, b"only");
        }
        assert!(fetcher.idle.is_none(), "a closing peer is not held open");
        served.join().expect("the server thread ends");
    }

    #[test]
    fn a_connection_the_peer_closed_while_idle_is_retried_once() {
        // The failure reuse has to survive: a peer may close an idle connection
        // at any time and says nothing when it does, so the second request goes
        // out on a socket the peer has already gone from. Nothing has reached
        // the caller's sink at that point, so one fresh attempt is safe -- and
        // it is what keeps reuse from turning a working bootstrap into a flaky
        // one.
        let body = "served";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len(),
        )
        .into_bytes();
        // Each connection serves exactly one response and is then dropped,
        // while the client believes both are reusable.
        let (url, served) = serving(2, response);

        let mut fetcher = HttpFetch::new();
        let mut first = Vec::new();
        fetcher
            .fetch(&FetchRequest::new(&url), &mut first)
            .expect("the first fetch answers");
        let mut second = Vec::new();
        fetcher
            .fetch(&FetchRequest::new(&url), &mut second)
            .expect("the retry on a fresh connection answers");
        assert_eq!(first, b"served");
        assert_eq!(second, b"served");
        served.join().expect("the server thread ends");
    }

    /// Serves `refusal` and then the resource, down whatever connection the
    /// client keeps, and asserts the client asked both of one connection.
    fn the_connection_survives(refusal: &[u8]) -> FetchError {
        let refusal = refusal.to_vec();
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst".to_vec();
        let served = Serving::answering(move |answered| {
            Some(if answered == 0 {
                refusal.clone()
            } else {
                ok.clone()
            })
        });
        // Short timeouts, so a client that waits on a body the server never
        // sends fails here in seconds rather than minutes.
        let mut fetcher = HttpFetch::new().timeouts(Duration::from_secs(5), Duration::from_secs(5));
        let err = fetcher
            .fetch(&FetchRequest::new(&served.url), &mut Vec::new())
            .expect_err("the first answer is a refusal");
        fetch_repeatedly(&mut fetcher, &served.url, 1, b"first");
        assert_eq!(served.connections(), 1, "the refusal kept its connection");
        drop(fetcher);
        err
    }

    #[test]
    fn a_refusal_with_a_framed_page_leaves_the_connection_reusable() {
        // A missing index encoding is answered by asking the same host for
        // the next one, so the connection the 404 came on is worth keeping
        // once its page has been read off.
        let err = the_connection_survives(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found",
        );
        assert!(matches!(err, FetchError::NotFound { .. }), "{err}");
        let err = the_connection_survives(
            b"HTTP/1.1 503 Service Unavailable\r\nTransfer-Encoding: chunked\r\n\r\n\
              4\r\nbusy\r\n0\r\n\r\n",
        );
        assert!(matches!(err, FetchError::Status { code: 503, .. }), "{err}");
    }

    #[test]
    fn a_304_is_read_as_carrying_no_body() {
        // The length a `304` states is its representation's, not a body that
        // follows; reading it would wait on bytes the server never sends.
        let err =
            the_connection_survives(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1234\r\n\r\n");
        assert!(matches!(err, FetchError::Status { code: 304, .. }), "{err}");
    }

    #[test]
    fn a_408_on_a_reused_connection_is_retried_on_a_fresh_one() {
        // A server closing a connection it held idle may send a `408` nobody
        // asked for, which the next request on that connection reads as its
        // answer. It is the stale connection speaking, so the request is asked
        // again on a fresh one.
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst".to_vec();
        let served = Serving::answering(move |answered| {
            Some(match answered {
                1 => b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec(),
                _ => ok.clone(),
            })
        });
        let mut fetcher = HttpFetch::new();
        fetch_repeatedly(&mut fetcher, &served.url, 2, b"first");
        assert_eq!(
            served.connections(),
            2,
            "the retry took a connection of its own"
        );

        // On a connection opened for the request, a `408` is that request's
        // answer, and it is reported as one.
        let timed_out =
            Serving::new(b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n".to_vec());
        let err = HttpFetch::new()
            .fetch(&FetchRequest::new(&timed_out.url), &mut Vec::new())
            .expect_err("a fresh connection's 408 is its answer");
        assert!(matches!(err, FetchError::Status { code: 408, .. }), "{err}");
        assert_eq!(timed_out.connections(), 1, "and is not retried");
        drop(fetcher);
    }

    #[test]
    fn a_batch_fetches_several_at_once() {
        // The property, measured rather than asserted structurally: the server
        // holds every response back until it has seen `at_once` requests, so a
        // client that fetched them one at a time would deadlock on the first
        // and this test would time out rather than fail. What it proves is that
        // several are in flight together.
        const AT_ONCE: usize = 4;
        const JOBS: usize = 8;

        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a loopback listener binds");
        let url = format!(
            "http://{}/x",
            listener.local_addr().expect("the listener is bound"),
        );
        let gate = std::sync::Arc::new((std::sync::Mutex::new(0usize), std::sync::Condvar::new()));
        let held = std::sync::Arc::clone(&gate);
        let served = std::thread::spawn(move || {
            let mut streams = Vec::new();
            for _ in 0..AT_ONCE {
                let (stream, _) = listener.accept().expect("a connection arrives");
                let mut request = BufReader::new(stream.try_clone().expect("the stream clones"));
                let mut line = String::new();
                while request.read_line(&mut line).is_ok_and(|read| read > 0) {
                    if line == "\r\n" {
                        break;
                    }
                    line.clear();
                }
                streams.push(stream);
            }
            // Every worker is now blocked on a response, which is the thing
            // being proved. Release them, then serve the rest one per request.
            {
                let (lock, notify) = &*held;
                *lock.lock().expect("the gate is not poisoned") = AT_ONCE;
                notify.notify_all();
            }
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            for mut stream in streams {
                let _ = stream.write_all(response);
            }
            for _ in AT_ONCE..JOBS {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut request = BufReader::new(stream.try_clone().expect("the stream clones"));
                let mut line = String::new();
                while request.read_line(&mut line).is_ok_and(|read| read > 0) {
                    if line == "\r\n" {
                        break;
                    }
                    line.clear();
                }
                let _ = stream.write_all(response);
            }
        });

        let mut sinks: Vec<Vec<u8>> = (0..JOBS).map(|_| Vec::new()).collect();
        let outcomes = {
            let mut jobs: Vec<FetchJob<'_>> = sinks
                .iter_mut()
                .map(|sink| FetchJob::new(FetchRequest::new(&url), sink))
                .collect();
            HttpFetch::new().concurrency(AT_ONCE).fetch_all(&mut jobs)
        };

        assert_eq!(outcomes.len(), JOBS);
        for outcome in &outcomes {
            assert!(outcome.is_ok(), "{outcome:?}");
        }
        for sink in &sinks {
            assert_eq!(sink, b"ok");
        }
        let (lock, _) = &*gate;
        assert_eq!(
            *lock.lock().expect("the gate is not poisoned"),
            AT_ONCE,
            "the server released the workers only once all four had asked",
        );
        served.join().expect("the server thread ends");
    }

    /// The marker the task-limit test's child process finds its files by.
    const TASK_LIMITED: &str = "FERRODAY_CAGE_TEST_HTTP_TASK_LIMIT";

    #[test]
    fn a_batch_the_host_starts_no_thread_for_still_fetches_every_job() {
        // A task limit refuses a new thread with `EAGAIN`. A batch is an
        // optimization, so a host that starts no worker has every job fetched
        // on the calling thread instead. The limit counts every task the user
        // runs, so it is lowered in a child process of its own, where nothing
        // else this suite runs is held to it.
        if let Some(dir) = std::env::var_os(TASK_LIMITED) {
            let dir = std::path::PathBuf::from(dir);
            let limit = rustix::process::Rlimit {
                current: Some(1),
                maximum: Some(1),
            };
            rustix::process::setrlimit(rustix::process::Resource::Nproc, limit)
                .expect("the task limit lowers");
            if std::thread::Builder::new().spawn(|| ()).is_ok() {
                ferroday_cage_testkit::require::premise_unmet(
                    "the task limit does not hold this caller, as it does not hold root",
                );
                std::fs::write(dir.join("unheld"), b"").expect("the marker is written");
                return;
            }
            let urls: Vec<String> = (0..3)
                .map(|at| file_url(&dir.join(format!("body-{at}"))).expect("the URL is built"))
                .collect();
            let mut bodies = vec![Vec::new(); urls.len()];
            let outcomes = {
                let mut jobs: Vec<FetchJob<'_>> = urls
                    .iter()
                    .zip(bodies.iter_mut())
                    .map(|(url, body)| FetchJob::new(FetchRequest::new(url), body))
                    .collect();
                HttpFetch::new().concurrency(4).fetch_all(&mut jobs)
            };
            assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
            for (at, body) in bodies.iter().enumerate() {
                assert_eq!(body, format!("body {at}").as_bytes());
            }
            std::fs::write(dir.join("done"), b"").expect("the marker is written");
            return;
        }

        let dir = Scratch::new("http-task-limit");
        for at in 0..3 {
            std::fs::write(dir.join(format!("body-{at}")), format!("body {at}")).unwrap();
        }
        let status = std::process::Command::new(
            std::env::current_exe().expect("the test binary has a path"),
        )
        .args([
            "--exact",
            "provision::http::tests::a_batch_the_host_starts_no_thread_for_still_fetches_every_job",
            "--test-threads=1",
        ])
        .env(TASK_LIMITED, dir.path())
        .status()
        .expect("the child test process runs");
        assert!(status.success(), "the child process failed: {status}");
        // A child that matched no test would succeed having asserted nothing.
        assert!(
            dir.join("done").exists() || dir.join("unheld").exists(),
            "the child ran the test",
        );
    }

    #[test]
    fn a_batch_answers_per_job_so_one_failure_does_not_take_the_rest() {
        // What the per-job answer is for: a caller retries what did not arrive
        // against the next mirror and keeps what did.
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec();
        let missing =
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
        let (found_url, found) = serving(1, ok);
        let (absent_url, absent) = serving(1, missing);

        let mut first = Vec::new();
        let mut second = Vec::new();
        let outcomes = {
            let mut jobs = vec![
                FetchJob::new(FetchRequest::new(&found_url), &mut first),
                FetchJob::new(FetchRequest::new(&absent_url), &mut second),
            ];
            // One at a time, which is the default body every other transport
            // inherits: the answer must be per job there too.
            HttpFetch::new().concurrency(1).fetch_all(&mut jobs)
        };

        assert!(outcomes[0].is_ok(), "{:?}", outcomes[0]);
        assert!(
            matches!(outcomes[1], Err(FetchError::NotFound { .. })),
            "{:?}",
            outcomes[1],
        );
        assert_eq!(first, b"ok");
        found.join().expect("the server thread ends");
        absent.join().expect("the server thread ends");
    }

    #[test]
    fn an_over_cap_answer_is_the_mirrors_state_whichever_framing_it_chose() {
        // A mirror that answers a request for sixteen bytes with four kilobytes
        // is not serving the resource that was asked for -- and that is the
        // mirror's state, so a walk over interchangeable mirrors asks the next
        // one. The two framings are the point: the declared length is refused
        // before a byte is read and a chunked body is refused as it arrives,
        // and a caller must not get a different answer depending on which the
        // mirror sent.
        let body = vec![b'x'; 4096];
        let declared = [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len(),
            )
            .into_bytes(),
            body.clone(),
        ]
        .concat();
        let chunked = [
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec(),
            format!("{:x}\r\n", body.len()).into_bytes(),
            body,
            b"\r\n0\r\n\r\n".to_vec(),
        ]
        .concat();

        for (framing, response) in [("declared", declared), ("chunked", chunked)] {
            let (url, served) = serving(1, response);
            let err = HttpFetch::new()
                .fetch(&FetchRequest::new(&url).sized(16), &mut Vec::new())
                .expect_err("the answer is over the cap");
            assert!(matches!(err, FetchError::Io { .. }), "{framing}: {err:?}");
            assert!(err.is_failover(), "{framing}: {err}");
            served.join().expect("the server thread ends");
        }
    }

    #[test]
    fn a_connect_walk_is_held_to_the_fetch_deadline() {
        // A host resolving to several addresses tried at the connect timeout
        // each waits that timeout per address, which multiplies past whatever
        // ceiling the caller put on the fetch. With the deadline already
        // reached, no attempt is started at all.
        let fetch = HttpFetch::new();
        let addrs = [
            SocketAddr::from(([192, 0, 2, 1], 80)),
            SocketAddr::from(([192, 0, 2, 2], 80)),
        ];
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("a monotonic clock a second past its start");
        let err = fetch
            .connect("http://mirror.example/x", addrs.into_iter(), Some(past))
            .expect_err("the deadline ends the walk");
        assert!(matches!(err, FetchError::Io { .. }), "{err:?}");
        assert!(
            ErrorChain::new(&err).to_string().contains(DEADLINE_ELAPSED),
            "{err}"
        );
        // The mirror walk is right to ask the next mirror about it.
        assert!(err.is_failover(), "{err}");
    }

    #[test]
    fn an_interim_response_is_read_past_rather_than_reported() {
        // A server may send `103 Early Hints` before the response it was asked
        // for, whether or not the client asked for hints. Reading the first
        // status line as the final one turned the hint into a status failure.
        let body = b"Suite: trixie\n";
        let mut response =
            b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n".to_vec();
        response.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
        response.extend_from_slice(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        );
        response.extend_from_slice(body);
        let (url, served) = serving(1, response);

        let mut out = Vec::new();
        HttpFetch::new()
            .fetch(&FetchRequest::new(&url), &mut out)
            .expect("the final response is the one delivered");
        assert_eq!(out, body);
        served.join().expect("the server thread ends");
    }

    #[test]
    fn a_peer_that_only_ever_sends_interim_responses_is_refused() {
        // A final response has to arrive. Reading past interim ones forever
        // would let a mirror hold a fetch open for the whole deadline.
        let mut response = Vec::new();
        for _ in 0..MAX_INTERIM_RESPONSES + 2 {
            response.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\n\r\n");
        }
        let (url, served) = serving(1, response);
        let err = HttpFetch::new()
            .fetch(&FetchRequest::new(&url), &mut Vec::new())
            .expect_err("a peer that never answers is refused");
        assert!(
            ErrorChain::new(&err)
                .to_string()
                .contains("interim responses"),
            "{err}, expected the interim-response refusal"
        );
        assert!(err.is_failover(), "{err}");
        served.join().expect("the server thread ends");
    }

    #[test]
    fn an_unrequested_protocol_switch_is_not_read_past() {
        // A 101 says the connection has left HTTP/1.1 for something nothing
        // here asked for, so it is a status failure rather than an interim
        // response to skip.
        let (url, served) = serving(
            1,
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".to_vec(),
        );
        let err = HttpFetch::new()
            .fetch(&FetchRequest::new(&url), &mut Vec::new())
            .expect_err("an unrequested protocol switch is refused");
        assert!(
            matches!(err, FetchError::Status { code: 101, .. }),
            "{err:?}"
        );
        served.join().expect("the server thread ends");
    }

    #[test]
    fn a_redirects_own_page_is_not_held_to_the_resources_cap() {
        // A request for a signed index states its size, and the body cap is
        // that size. A mirror answering with an HTML redirect page larger than
        // the index it points at is ordinary, and reading the page against the
        // index's cap failed the fetch before the redirect was followed.
        let page = "<html>redirecting</html>".repeat(64);
        let redirect = format!(
            "HTTP/1.1 302 Found\r\nLocation: /moved\r\nContent-Length: {}\r\n\r\n{page}",
            page.len(),
        );
        let body = b"Suite: trixie\n";
        let (url, accepted, served) = serving_one_connection(vec![
            redirect.into_bytes(),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes()
            .into_iter()
            .chain(body.iter().copied())
            .collect(),
        ]);

        let mut out = Vec::new();
        HttpFetch::new()
            .fetch(&FetchRequest::new(&url).sized(body.len() as u64), &mut out)
            .expect("the redirect is followed and the resource delivered");
        assert_eq!(out, body);
        // The page was read off, so the redirect was followed on the same
        // connection rather than a new one.
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
        served.join().expect("the server thread ends");
    }

    #[test]
    fn a_redirect_chain_with_no_end_is_the_mirrors_state_too() {
        // The same question one step earlier: a mirror that answers every
        // request with another redirect has not served the resource, and the
        // URL it was asked for was spelled fine. The default limit is five, so
        // the client makes six requests before it gives up.
        let (url, served) = serving(
            6,
            b"HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        );
        let err = HttpFetch::new()
            .fetch(&FetchRequest::new(&url), &mut Vec::new())
            .expect_err("the chain never arrives at a body");
        assert!(matches!(err, FetchError::Io { .. }), "{err:?}");
        assert!(err.is_failover(), "{err}");
        assert!(
            ErrorChain::new(&err)
                .to_string()
                .contains("more than 5 redirects"),
            "{err}"
        );
        served.join().expect("the server thread ends");
    }

    #[test]
    fn urls_parse() {
        let url = parse_http_url("http://deb.debian.org/debian/dists/trixie/InRelease").unwrap();
        assert_eq!(url.host, "deb.debian.org");
        assert_eq!(url.port, 80);
        assert_eq!(url.path, "/debian/dists/trixie/InRelease");

        let url = parse_http_url("http://localhost:8080/repo").unwrap();
        assert_eq!(url.port, 8080);
        assert_eq!(url.path, "/repo");

        // A bare host with no path fetches the root.
        assert_eq!(parse_http_url("http://host").unwrap().path, "/");
    }

    #[test]
    fn bracketed_ipv6_authorities_parse() {
        // The brackets are URL syntax keeping the literal's colons from
        // reading as a port separator; the host is carried without them, in
        // the form that resolves, and written back with them.
        let url = parse_http_url("http://[::1]:8080/repo/InRelease").unwrap();
        assert_eq!(url.host, "::1");
        assert_eq!(url.port, 8080);
        assert_eq!(url.path, "/repo/InRelease");
        assert_eq!(url.authority_host(), "[::1]");

        let url = parse_http_url("http://[2001:db8::1]/x").unwrap();
        assert_eq!(url.host, "2001:db8::1");
        assert_eq!(url.port, 80);

        // A host that needs no brackets keeps none.
        assert_eq!(
            parse_http_url("http://deb.debian.org/x")
                .unwrap()
                .authority_host(),
            "deb.debian.org"
        );
    }

    #[test]
    fn malformed_bracketed_authorities_are_rejected() {
        for url in [
            "http://[::1/x",         // unterminated
            "http://[::1]junk/x",    // junk after the literal
            "http://[::1]:notaport", // a port that is not a number
            "http://[nonsense]/x",   // not an IPv6 literal
            "http://[]/x",           // empty
        ] {
            assert!(parse_http_url(url).is_err(), "{url} should be refused");
        }
    }

    #[test]
    fn a_url_that_could_write_a_request_line_of_its_own_is_refused() {
        // The one URL source that reaches the request line having passed no
        // boundary of its own is a redirect `Location`, which is a hostile
        // mirror's string. A CRLF in one would otherwise append headers to the
        // follow-up request, turning the documented cross-host redirect into a
        // request the caller did not compose.
        for url in [
            "http://mirror.example/x\r\nX-Injected: 1",
            "http://mirror.example/x\nX-Injected: 1",
            "http://mirror.example/x HTTP/1.1",
            "http://mirror.example/x\0",
            "http://mirror.exam\rple/x",
        ] {
            assert!(parse_http_url(url).is_err(), "{url:?} should be refused");
        }
        // And a redirect carrying one is refused as the URL it resolves to,
        // rather than reaching the request line.
        let injected =
            resolve_redirect("http://mirror.example/debian/x", "/pool/y\r\nX-Injected: 1");
        assert!(parse_http_url(&injected).is_err());
    }

    #[test]
    fn a_coordinate_the_check_accepts_reaches_the_request_line_as_written() {
        // The two boundaries answer one question between them: a coordinate
        // `check` accepts is one this client writes into the request line
        // unchanged, and one this client would refuse never gets past `check`.
        use super::super::coordinate::{Nesting, check};
        let accepted = [
            "trixie",
            "buster/updates",
            "main/debian-installer",
            "extra-repos/systemd",
            "dev-libs/libsigc++/libsigc++-2.12.1-1.gpkg.tar",
            "a-b.c_d~e!f$g&h'i(j)k*l+m,n;o=p:q@r",
        ];
        for value in accepted {
            check("the archive's component", value, Nesting::Nested)
                .unwrap_or_else(|reason| panic!("{reason}"));
            let url = super::super::mirror_url("http://mirror.example/debian", value);
            let parsed = parse_http_url(&url).unwrap_or_else(|reason| panic!("{url}: {reason}"));
            assert_eq!(parsed.path, format!("/debian/{value}"));
        }
        for value in ["caf\u{e9}", "a b", "a\u{7f}"] {
            let url = super::super::mirror_url("http://mirror.example/debian", value);
            assert!(parse_http_url(&url).is_err(), "{value:?}");
            assert!(
                check("the archive's component", value, Nesting::Nested).is_err(),
                "{value:?}",
            );
        }
    }

    #[test]
    fn a_network_path_redirect_carries_its_own_authority() {
        // `//host/path` names a host of its own and inherits only the scheme,
        // where an absolute path names a path on the base's host. Reading the
        // first as the second composed a doubled-slash path on the base host,
        // which the same-host policy admits because the host never changed.
        let base = "http://mirror.example/debian/dists/trixie/Release";
        assert_eq!(
            resolve_redirect(base, "//cdn.example/x"),
            "http://cdn.example/x",
        );
        assert_eq!(
            resolve_redirect(base, "//cdn.example:8080/x"),
            "http://cdn.example:8080/x",
        );
        // And it is then a cross-host redirect, which the default policy
        // refuses rather than following.
        let refused = HttpFetch::new()
            .check_redirect(base, &resolve_redirect(base, "//cdn.example/x"))
            .expect_err("a network-path redirect leaves the host");
        assert!(refused.is_failover(), "{refused}");
    }

    #[test]
    fn a_redirect_resolves_against_a_bracketed_origin() {
        // The origin is rebuilt from the parsed host, so the brackets have to
        // come back or the next request would not parse.
        assert_eq!(
            resolve_redirect("http://[::1]:8080/a/b", "/c"),
            "http://[::1]:8080/c"
        );
        assert_eq!(
            resolve_redirect("http://[::1]/a/b", "c"),
            "http://[::1]/a/c"
        );
    }

    /// A scheme is case-insensitive (RFC 3986 §3.1), and every check in the
    /// crate agrees about that.
    ///
    /// `scheme_of` documented it and the authenticated-transport allow-list
    /// honoured it, while the parser matched `http://` literally — so
    /// `HTTP://host/x` passed the transport check and was then refused by the
    /// parser as though it were `https://`, with a message telling the caller
    /// to supply a TLS transport for a URL that names no TLS.
    #[test]
    fn the_scheme_is_matched_case_insensitively() {
        for url in [
            "HTTP://deb.debian.org/debian/x",
            "Http://deb.debian.org/debian/x",
        ] {
            let parsed = parse_http_url(url).unwrap_or_else(|err| panic!("{url}: {err}"));
            assert_eq!(parsed.host, "deb.debian.org");
            assert_eq!(parsed.path, "/debian/x");
        }
        // The path keeps its case; only the scheme is folded.
        assert_eq!(
            parse_http_url("HTTP://host/Mixed/Case").unwrap().path,
            "/Mixed/Case",
        );
    }

    #[test]
    fn non_http_schemes_are_rejected() {
        let err = HttpFetch::new()
            .fetch(&FetchRequest::new("https://host/x"), &mut Vec::new())
            .expect_err("https is not this fetcher's scheme");
        assert!(matches!(err, FetchError::Url { .. }), "{err:?}");
        // The refusal points at the transport a TLS mirror needs rather than
        // reading as a malformed URL, which is the whole of the diagnosis for a
        // caller who has just typed a perfectly good https:// address. It names
        // no one layer's builder, since every layer takes a transport the same
        // way.
        let rendered = err.to_string();
        assert!(
            rendered.contains(TLS_REMEDY),
            "the scheme refusal must name the remedy, got {rendered}",
        );
    }

    #[test]
    fn a_redirect_to_a_url_this_client_cannot_follow_is_the_mirrors_state() {
        // An http:// mirror redirecting to https:// is common, and this client
        // speaks no TLS. Where a mirror sends a request is its own arrangement
        // rather than a URL the caller spelled wrong, so the refusal is a
        // transport failure and a walk over mirrors asks the next one. Allowing
        // cross-host redirects widens where a redirect may go, not what this
        // client can fetch, so it changes nothing here.
        let moved = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://mirror.example/x\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n";
        for cross_host in [false, true] {
            let (url, served) = serving(1, moved.to_vec());
            let err = HttpFetch::new()
                .cross_host_redirects(cross_host)
                .fetch(&FetchRequest::new(&url), &mut Vec::new())
                .expect_err("an https:// target cannot be followed");
            assert!(matches!(err, FetchError::Io { .. }), "{err:?}");
            assert!(err.is_failover(), "{err}");
            assert!(
                ErrorChain::new(&err).to_string().contains(TLS_REMEDY),
                "{err}"
            );
            served.join().expect("the server thread ends");
        }

        // The same for a target that cannot be fetched at all, and for one that
        // names the local filesystem.
        let fetch = HttpFetch::new();
        for target in ["file:///etc/passwd", "http://mirror.example:port/x"] {
            let refused = fetch
                .check_redirect("http://mirror.example/x", target)
                .expect_err("the target is refused");
            assert!(matches!(refused, FetchError::Io { .. }), "{refused:?}");
            assert!(refused.is_failover(), "{refused}");
        }
    }

    #[test]
    fn a_redirect_target_reaches_an_error_with_its_control_characters_escaped() {
        // The target is the mirror's string, and anyone on a plain-HTTP path can
        // write it. An escape sequence carried into the operator's terminal
        // through an error chain could rewrite the screen or, as OSC 52 does,
        // set the clipboard, so a refusal renders it as `{:?}` renders it.
        let hostile = crate::failure::hostile::TEXT;
        let fetch = HttpFetch::new();
        for target in [
            format!("https://mirror.example/{hostile}"),
            format!("http://mirror.example/{hostile}"),
            format!("http://elsewhere.example{hostile}"),
        ] {
            let refused = fetch
                .check_redirect("http://mirror.example/x", &target)
                .expect_err("the target is refused");
            let rendered = ErrorChain::new(&refused).to_string();
            crate::failure::hostile::assert_escaped(&rendered);
            assert!(
                rendered.starts_with("fetching http://mirror.example/x failed"),
                "the refusal names the URL fetched: {rendered:?}",
            );
        }

        // And end to end, from the header a server sent.
        let moved = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: /{hostile}\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n"
        );
        let (url, served) = serving(1, moved.into_bytes());
        let err = HttpFetch::new()
            .fetch(&FetchRequest::new(&url), &mut Vec::new())
            .expect_err("the target cannot be fetched");
        let rendered = ErrorChain::new(&err).to_string();
        assert!(
            !rendered.contains(['\u{1b}', '\u{7}']),
            "a control character reached the error: {rendered:?}",
        );
        assert!(err.is_failover(), "{err}");
        served.join().expect("the server thread ends");
    }

    /// Serves one response to one request, and hands back the request's header
    /// lines.
    fn serving_and_recording(response: Vec<u8>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a loopback listener binds");
        let url = format!(
            "http://{}/x",
            listener.local_addr().expect("the listener is bound"),
        );
        let served = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("the client connects");
            let mut request = BufReader::new(stream.try_clone().expect("the stream clones"));
            let mut lines = Vec::new();
            loop {
                let mut line = String::new();
                if request.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                lines.push(line.trim_end().to_string());
            }
            let _ = stream.write_all(&response);
            lines
        });
        (url, served)
    }

    #[test]
    fn a_content_coded_body_is_refused_as_this_mirrors_failure() {
        // The request asks for the resource's own bytes, which are what its
        // digest covers. A response that compresses the body regardless is
        // refused before a byte reaches the sink, as a failure a walk over
        // mirrors advances past, rather than handed on to fail the digest.
        let coded = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\
                      Connection: close\r\n\r\nabcd";
        let (url, served) = serving_and_recording(coded.to_vec());
        let mut sink = Vec::new();
        let err = HttpFetch::new()
            .fetch(&FetchRequest::new(&url), &mut sink)
            .expect_err("a content-coded body is not the resource");
        let request = served.join().expect("the server thread ends");
        assert!(
            request
                .iter()
                .any(|line| line == "Accept-Encoding: identity"),
            "the request asked for no particular coding: {request:?}",
        );
        assert!(matches!(err, FetchError::Io { .. }), "{err:?}");
        assert!(err.is_failover(), "{err}");
        assert!(sink.is_empty(), "the coded body reached the sink");
        assert!(
            ErrorChain::new(&err).to_string().contains("\"gzip\""),
            "{}",
            ErrorChain::new(&err),
        );

        // `identity` is the resource's own bytes, however it is spelled.
        let plain = b"HTTP/1.1 200 OK\r\nContent-Encoding: Identity\r\nContent-Length: 4\r\n\
                      Connection: close\r\n\r\nabcd";
        let (url, served) = serving_and_recording(plain.to_vec());
        let mut sink = Vec::new();
        HttpFetch::new()
            .fetch(&FetchRequest::new(&url), &mut sink)
            .expect("an identity body is the resource");
        served.join().expect("the server thread ends");
        assert_eq!(sink, b"abcd");
    }

    #[test]
    fn chunked_bodies_decode() {
        let body = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let mut reader = BufReader::new(body.as_bytes());
        let mut out = Vec::new();
        read_chunked(&mut reader, &mut out).unwrap();
        assert_eq!(out, b"Wikipedia");
    }

    #[test]
    fn a_limited_writer_stops_at_its_ceiling() {
        let mut out = Vec::new();
        let mut limited = crate::provision::LimitedWriter::new(&mut out, 4);
        assert!(limited.write_all(b"12345").is_err());
    }

    #[test]
    fn an_oversized_chunk_is_capped_not_buffered() {
        // A chunk announces 16 MiB but only a little data follows. Decoding
        // fails at the sink's ceiling rather than allocating the announced
        // size, proving a hostile chunk framing cannot force a large buffer.
        let mut body = Vec::new();
        body.extend_from_slice(b"1000000\r\n"); // 0x1000000 = 16 MiB announced
        body.extend_from_slice(&[b'x'; 64]);
        let mut reader = BufReader::new(&body[..]);
        let mut out = Vec::new();
        let mut limited = crate::provision::LimitedWriter::new(&mut out, 8);
        let err = read_chunked(&mut reader, &mut limited).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(out.len() <= 8, "no more than the ceiling was buffered");
    }

    #[test]
    fn an_oversized_chunk_terminator_is_rejected() {
        // A chunk body is followed by an unbounded run of bytes where the bare
        // CRLF terminator belongs. The decoder refuses it at the line cap
        // rather than buffering without bound.
        let mut body = Vec::new();
        body.extend_from_slice(b"4\r\nWiki"); // one 4-byte chunk...
        body.extend_from_slice(&vec![b'x'; MAX_LINE + 10]); // ...then no terminator
        let mut reader = BufReader::new(&body[..]);
        let mut out = Vec::new();
        let err = read_chunked(&mut reader, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_non_crlf_chunk_terminator_is_rejected() {
        // Even within the cap, the terminator must be a bare CRLF; stray bytes
        // there signal a broken or hostile framing.
        let body = "4\r\nWikiGARBAGE\r\n0\r\n\r\n";
        let mut reader = BufReader::new(body.as_bytes());
        let mut out = Vec::new();
        let err = read_chunked(&mut reader, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn file_urls_read_local_paths() {
        let dir = Scratch::new("http");
        let path = dir.join("resource");
        std::fs::write(&path, b"contents").unwrap();
        let url = format!("file://{}", path.display());
        let mut out = Vec::new();
        HttpFetch::new()
            .fetch(&FetchRequest::new(&url), &mut out)
            .unwrap();
        assert_eq!(out, b"contents");

        let missing = format!("file://{}", dir.join("absent").display());
        assert!(matches!(
            HttpFetch::new().fetch(&FetchRequest::new(&missing), &mut Vec::new()),
            Err(FetchError::NotFound { .. })
        ));

        // The other spelling of this machine reads the same file.
        let localhost = format!("file://localhost{}", path.display());
        let mut out = Vec::new();
        HttpFetch::new()
            .fetch(&FetchRequest::new(&localhost), &mut out)
            .unwrap();
        assert_eq!(out, b"contents");
    }

    #[test]
    fn a_file_url_naming_anything_but_a_regular_file_is_refused_without_waiting() {
        // A local mirror is a tree an rsync from an upstream fills, and a named
        // pipe left where a file belongs would hold an ordinary open until
        // something opened its other end, outside any deadline. The open does
        // not wait, and the descriptor is refused for not being a file.
        use std::sync::mpsc;

        let dir = Scratch::new("http-file-fifo");
        let pipe = dir.join("Release");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &pipe,
            FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .expect("a named pipe is creatable");
        std::fs::create_dir(dir.join("a-directory")).unwrap();

        for name in ["Release", "a-directory"] {
            let url = format!("file://{}", dir.join(name).display());
            let (sent, received) = mpsc::channel();
            std::thread::spawn(move || {
                let _ =
                    sent.send(HttpFetch::new().fetch(&FetchRequest::new(&url), &mut Vec::new()));
            });
            let outcome = received
                .recv_timeout(Duration::from_secs(10))
                .unwrap_or_else(|_| panic!("the fetch of {name} waited on what holds the path"));
            let err = outcome.expect_err("only a regular file is read");
            assert!(matches!(err, FetchError::Io { .. }), "{name}: {err:?}");
            assert!(
                ErrorChain::new(&err)
                    .to_string()
                    .contains("not a regular file")
                    || ErrorChain::new(&err)
                        .to_string()
                        .contains("other than a regular file"),
                "{name}: {}",
                ErrorChain::new(&err),
            );
        }

        // A link to a file is followed, as a server follows one: a local mirror
        // may name one file by two paths.
        std::fs::write(dir.join("InRelease"), b"signed").unwrap();
        std::os::unix::fs::symlink("InRelease", dir.join("alias")).unwrap();
        let mut out = Vec::new();
        HttpFetch::new()
            .fetch(
                &FetchRequest::new(&format!("file://{}", dir.join("alias").display())),
                &mut out,
            )
            .expect("a link to a file is read through");
        assert_eq!(out, b"signed");
    }

    #[test]
    fn a_file_fetch_is_held_to_the_request_deadline() {
        // `request_timeout` bounds one fetch whatever its scheme. A deadline
        // already reached fails the open, and one reached part way through
        // fails the next read rather than copying on.
        let dir = Scratch::new("http-file-deadline");
        let path = dir.join("resource");
        std::fs::write(&path, b"contents").unwrap();
        let url = format!("file://{}", path.display());
        let err = HttpFetch::new()
            .request_timeout(Some(Duration::ZERO))
            .fetch(&FetchRequest::new(&url), &mut Vec::new())
            .expect_err("a reached deadline ends the fetch");
        assert!(
            ErrorChain::new(&err).to_string().contains(DEADLINE_ELAPSED),
            "{}",
            ErrorChain::new(&err),
        );
        assert!(err.is_failover(), "{err}");

        let mut reader = LocalReader {
            file: File::open(&path).unwrap(),
            deadline: Some(Instant::now() - Duration::from_secs(1)),
        };
        let err = reader
            .read(&mut [0u8; 8])
            .expect_err("a read past the deadline fails");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn a_built_file_url_reads_back_as_the_path_it_was_built_from() {
        // The two directions of the same scheme: what `file_url` writes is what
        // the fetcher resolves, for a path that exists and for one that does
        // not yet.
        let dir = Scratch::new("http-file-url");
        let path = dir.join("resource");
        std::fs::write(&path, b"contents").unwrap();

        let url = file_url(&path).unwrap();
        let mut out = Vec::new();
        HttpFetch::new()
            .fetch(&FetchRequest::new(&url), &mut out)
            .unwrap();
        assert_eq!(out, b"contents");

        let unwritten = file_url(&dir.join("pool")).unwrap();
        assert_eq!(
            local_file_path(&unwritten, unwritten.strip_prefix("file://").unwrap()).unwrap(),
            dir.join("pool").to_str().unwrap(),
        );
    }

    /// The local path the fetcher reads for `url`, or the refusal.
    fn read_back(url: &str) -> Result<std::path::PathBuf, FetchError> {
        let rest = strip_scheme(url, "file://").expect("a file:// URL");
        decode_file_path(url, local_file_path(url, rest)?)
    }

    #[test]
    fn a_relative_path_is_made_absolute_and_every_byte_is_nameable() {
        // A `file://` URL carries a path from a root, and carries it as text,
        // so a byte that is not text, or text a URL cannot hold as written, is
        // an escape.
        let url = file_url(Path::new("pool")).unwrap();
        let expected = std::env::current_dir().unwrap().join("pool");
        assert_eq!(read_back(&url).unwrap(), expected);

        use std::os::unix::ffi::OsStrExt as _;
        for (path, spelled) in [
            (&b"/srv/\xff\xfe"[..], "file:///srv/%FF%FE"),
            (b"/srv/My Pool/100%", "file:///srv/My%20Pool/100%25"),
            (b"/srv/a\nb", "file:///srv/a%0Ab"),
            (b"/srv/plain-name_1.0~rc", "file:///srv/plain-name_1.0~rc"),
        ] {
            let path = Path::new(std::ffi::OsStr::from_bytes(path));
            let url = file_url(path).unwrap();
            assert_eq!(url, spelled);
            assert!(!url.contains(char::is_whitespace), "{url:?}");
            assert_eq!(read_back(&url).unwrap(), path, "{url}");
        }
    }

    #[test]
    fn a_path_a_url_must_escape_is_read_through_its_url() {
        // The pool a caller names by path is the one the fetcher reads, however
        // the path is spelled.
        let dir = Scratch::new("http-file-url-escaped");
        let pool = dir.join("My Pool 100%");
        std::fs::create_dir(&pool).unwrap();
        std::fs::write(pool.join("Release"), b"contents").unwrap();

        let url = crate::provision::mirror_url(&file_url(&pool).unwrap(), "Release");
        let mut out = Vec::new();
        HttpFetch::new()
            .fetch(&FetchRequest::new(&url), &mut out)
            .unwrap();
        assert_eq!(out, b"contents");
    }

    #[test]
    fn an_escape_that_would_change_the_path_is_refused() {
        // Decoding is one pass over each component as written, and an escape
        // may spell a name but never the shape of the path: no separator the
        // written URL does not show, no NUL, and no dot segment.
        for url in [
            "file:///srv/pool/a%2F..%2F..%2Fetc/passwd",
            "file:///srv/pool/%2e%2e/%2E%2E/etc/passwd",
            "file:///srv/pool/.%2e/etc/passwd",
            "file:///srv/pool/x%00y",
            "file:///srv/pool/%zz",
            "file:///srv/pool/x%",
        ] {
            assert!(
                matches!(read_back(url), Err(FetchError::Url { .. })),
                "{url} should be refused",
            );
        }
        // A dot segment written as one is the caller's to write, as it was
        // before any escape was read: `std::path::absolute` keeps one.
        assert_eq!(
            read_back("file:///srv/pool/../other").unwrap(),
            Path::new("/srv/pool/../other"),
        );
    }

    #[test]
    fn a_file_url_naming_another_host_is_refused_rather_than_read_relative() {
        // The authority sits between `file://` and the path. Left on the front
        // of the string it is not an authority at all: `File::open` resolves
        // what remains against the process's current directory, so a URL naming
        // a remote host would quietly read a different file on this one and
        // report it as though the URL had been honoured.
        for url in [
            "file://otherhost/srv/pool/Release",
            // The `localhost` prefix is matched as a whole authority, not as a
            // prefix of one: this is the host `localhostile`, and reading it as
            // the relative path `ile/x` is exactly the confusion above.
            "file://localhostile/x",
            "file://localhost",
            "file://",
        ] {
            match HttpFetch::new().fetch(&FetchRequest::new(url), &mut Vec::new()) {
                Err(FetchError::Url { .. }) => {}
                other => panic!("{url} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_declared_size_caps_the_body_below_the_default_ceiling() {
        // The signed release states the length of every index and the index the
        // length of every package, so a request usually arrives with a ceiling
        // far below `MAX_BODY`. A source that answers with more must fail at
        // the stated length rather than at two gigabytes. The `file://` path
        // carries the same cap as the HTTP one, and is the one a unit test can
        // reach without a server.
        let dir = Scratch::new("http-cap");
        let path = dir.join("index");
        std::fs::write(&path, vec![b'x'; 4096]).unwrap();
        let url = format!("file://{}", path.display());

        let mut out = Vec::new();
        let err = HttpFetch::new()
            .fetch(&FetchRequest::new(&url).sized(16), &mut out)
            .expect_err("a body over the declared size is refused");
        assert!(matches!(err, FetchError::Io { .. }), "{err:?}");
        assert!(out.len() <= 16, "more than the ceiling was written");

        // The whole resource arrives when the declared size admits it, and a
        // request with no declared size is bounded by `MAX_BODY` alone.
        for request in [FetchRequest::new(&url).sized(4096), FetchRequest::new(&url)] {
            let mut out = Vec::new();
            HttpFetch::new().fetch(&request, &mut out).unwrap();
            assert_eq!(out.len(), 4096);
        }
    }

    #[test]
    fn an_oversized_framing_line_is_rejected() {
        // A line longer than the cap with no newline is refused rather than
        // buffered without bound.
        let long = vec![b'a'; MAX_LINE + 10];
        let mut reader = BufReader::new(&long[..]);
        let mut line = String::new();
        let err = read_line_limited(&mut reader, &mut line).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn more_headers_than_the_cap_are_rejected() {
        let mut body = String::new();
        for i in 0..=MAX_HEADERS {
            body.push_str(&format!("X-Pad-{i}: v\r\n"));
        }
        // No blank separator: the section never ends.
        let mut reader = BufReader::new(body.as_bytes());
        let err = read_headers(&mut reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn only_an_http_status_line_is_read_as_one() {
        assert_eq!(
            read_status(&mut &b"HTTP/1.1 200 OK\r\n"[..]).unwrap(),
            Status {
                version: (1, 1),
                code: 200
            },
        );
        // The name is compared case-insensitively, and the version travels with
        // the code because whether the connection may be held turns on it.
        assert_eq!(
            read_status(&mut &b"http/1.0 404 x\r\n"[..]).unwrap(),
            Status {
                version: (1, 0),
                code: 404
            },
        );
        for line in [
            // A greeting whose second word parses as a number is not a status
            // line; a mirror URL pointed at the wrong port should say so here
            // rather than fail somewhere further on.
            &b"220 587 ESMTP ready\r\n"[..],
            &b"SSH-2.0-OpenSSH_9.9\r\n"[..],
            &b"HTTP/ 200 OK\r\n"[..],
            &b"HTTP/1.1\r\n"[..],
            &b"\r\n"[..],
            // RFC 9112 spells a version with one digit on each side of the
            // dot, and this client reads the digits, so a token that is not
            // one is refused rather than read as some version or other.
            &b"HTTP/11 200 OK\r\n"[..],
            &b"HTTP/1.x 200 OK\r\n"[..],
            &b"HTTP/1.10 200 OK\r\n"[..],
            // A non-ASCII first token must be refused, not panicked on.
            "\u{e9}\u{e9}\u{e9} 200 OK\r\n".as_bytes(),
        ] {
            let err = read_status(&mut { line }).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{line:?}");
        }
    }

    #[test]
    fn a_complete_header_section_parses() {
        let body = "Content-Length: 9\r\nLocation: /elsewhere\r\n\r\nWikipedia";
        let mut reader = BufReader::new(body.as_bytes());
        let headers = read_headers(&mut reader).unwrap();
        assert_eq!(headers.content_length, Some(9));
        assert_eq!(headers.location.as_deref(), Some("/elsewhere"));
        assert!(!headers.chunked);
        // A repeat that agrees with the first is not a contradiction.
        let mut reader =
            BufReader::new("Content-Length: 9\r\nContent-Length: 9\r\n\r\n".as_bytes());
        assert_eq!(read_headers(&mut reader).unwrap().content_length, Some(9));
    }

    #[test]
    fn a_truncated_header_section_is_rejected() {
        // A mirror that sends a status line and closes cleanly must not read as
        // a complete, unframed response: that would deliver an empty body as a
        // successful fetch.
        let mut reader = BufReader::new("Server: mirror\r\n".as_bytes());
        let err = read_headers(&mut reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn an_unusable_content_length_is_rejected() {
        for body in [
            "Content-Length: abc\r\n\r\n",                     // not a number
            "Content-Length: 18446744073709551616\r\n\r\n",    // past u64
            "Content-Length: 9\r\nContent-Length: 10\r\n\r\n", // contradictory
            "Content-Length: +9\r\n\r\n",                      // a sign
            "Content-Length:\r\n\r\n",                         // empty
        ] {
            let mut reader = BufReader::new(body.as_bytes());
            let err = read_headers(&mut reader).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{body:?}");
        }
    }

    #[test]
    fn a_chunk_size_is_hex_digits_and_nothing_else() {
        // A sign is no part of `1*HEXDIG`, and the size decides where the chunk
        // ends. An extension after a `;` is still read past.
        for body in ["+4\r\nWiki\r\n0\r\n\r\n", "\r\nWiki\r\n0\r\n\r\n"] {
            let mut reader = BufReader::new(body.as_bytes());
            let err = read_chunked(&mut reader, &mut Vec::new()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{body:?}");
        }
        let mut reader = BufReader::new("4;name=value\r\nWiki\r\n0\r\n\r\n".as_bytes());
        let mut out = Vec::new();
        read_chunked(&mut reader, &mut out).unwrap();
        assert_eq!(out, b"Wiki");
    }

    #[test]
    fn transfer_codings_are_read_as_a_list_of_tokens() {
        // `chunked` is the one coding this client reads, and it is matched as
        // a token in the comma-separated list, across repeated field lines.
        for body in [
            "Transfer-Encoding: chunked\r\n\r\n",
            "Transfer-Encoding: Chunked\r\n\r\n",
            "Transfer-Encoding: , chunked\r\n\r\n",
        ] {
            let mut reader = BufReader::new(body.as_bytes());
            assert!(read_headers(&mut reader).unwrap().chunked, "{body:?}");
        }
        // A coding it does not read leaves the body unreadable, a substring is
        // not the token, and chunked twice is not a framing a sender may use.
        for body in [
            "Transfer-Encoding: gzip, chunked\r\n\r\n",
            "Transfer-Encoding: notchunked\r\n\r\n",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            "Transfer-Encoding: identity\r\n\r\n",
        ] {
            let mut reader = BufReader::new(body.as_bytes());
            let err = read_headers(&mut reader).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{body:?}");
        }
    }

    #[test]
    fn a_folded_field_line_continues_the_field_before_it() {
        // A line beginning with whitespace continues the previous field's
        // value. Read as a field of its own, this one would be a framing header
        // the server did not send.
        let body = "X-Note: first\r\n Content-Length: 99\r\n\r\n";
        let mut reader = BufReader::new(body.as_bytes());
        let headers = read_headers(&mut reader).unwrap();
        assert_eq!(headers.content_length, None);

        // A folded value is read whole, so a framing field split across lines
        // is read as one.
        let mut reader = BufReader::new("Location: /a\r\n\t/b\r\n\r\n".as_bytes());
        assert_eq!(
            read_headers(&mut reader).unwrap().location.as_deref(),
            Some("/a /b")
        );

        // A continuation with no field before it continues nothing.
        let mut reader = BufReader::new(" Content-Length: 9\r\n\r\n".as_bytes());
        let err = read_headers(&mut reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn relative_redirects_resolve_against_the_base() {
        let base = "http://mirror.example/debian/dists/trixie/InRelease";
        // An absolute path replaces the base path.
        assert_eq!(
            resolve_redirect(base, "/other/Release"),
            "http://mirror.example/other/Release"
        );
        // A relative path resolves against the base path's directory.
        assert_eq!(
            resolve_redirect(base, "Release.gpg"),
            "http://mirror.example/debian/dists/trixie/Release.gpg"
        );
        // An absolute URL is returned unchanged; a non-default port is kept.
        assert_eq!(
            resolve_redirect(base, "http://cdn.example/x"),
            "http://cdn.example/x"
        );
        assert_eq!(
            resolve_redirect("http://host:8080/a/b", "c"),
            "http://host:8080/a/c"
        );
    }

    #[test]
    fn cross_host_redirects_are_refused_by_default() {
        let fetch = HttpFetch::new();
        let from = "http://mirror.example/debian/pool/x.deb";
        // A same-host redirect (only the path changes) is allowed.
        assert!(
            fetch
                .check_redirect(from, "http://mirror.example/pool/y.deb")
                .is_ok()
        );
        // A redirect to another host is refused: it is the blind SSRF vector.
        // Carried as a transport failure, so a walk asks the next mirror rather
        // than aborting the list over where this one sends its requests.
        let refused = fetch
            .check_redirect(from, "http://169.254.169.254/latest/meta-data")
            .expect_err("a cross-host redirect is refused");
        assert!(matches!(refused, FetchError::Io { .. }), "{refused:?}");
        assert!(refused.is_failover(), "{refused}");
        // So is another port on the same host, which is the same vector aimed
        // at whatever else that host is running.
        let refused = fetch
            .check_redirect(from, "http://mirror.example:9000/pool/y.deb")
            .expect_err("a cross-port redirect is refused");
        assert!(matches!(refused, FetchError::Io { .. }), "{refused:?}");
        assert!(refused.is_failover(), "{refused}");
        // Opting in allows the cross-host CDN redirect.
        let permissive = HttpFetch::new().cross_host_redirects(true);
        assert!(
            permissive
                .check_redirect(from, "http://cdn.example/x.deb")
                .is_ok()
        );
    }

    #[test]
    fn a_passed_deadline_fails_the_read() {
        // A reader whose deadline is already in the past fails before touching
        // the inner stream, so a trickling body cannot outlast the deadline.
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a loopback listener binds");
        let stream = TcpStream::connect(listener.local_addr().expect("the listener is bound"))
            .expect("the loopback connection is made");
        let mut reader = DeadlineReader {
            inner: stream,
            deadline: Some(Instant::now() - Duration::from_secs(1)),
            io_timeout: None,
        };
        let mut buf = [0u8; 8];
        let err = reader.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn absolute_urls_are_recognized() {
        assert!(is_absolute_url("http://host/x"));
        assert!(is_absolute_url("file:///etc/passwd"));
        assert!(!is_absolute_url("/relative/path"));
        assert!(!is_absolute_url("relative"));
    }
}
