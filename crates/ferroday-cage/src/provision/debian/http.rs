//! The default fetcher: a minimal HTTP/1.1 client plus `file://`.
//!
//! It speaks just enough HTTP to retrieve static files from a Debian mirror
//! over plain `http://` — a single `GET`, content-length or chunked bodies,
//! capped redirects, connect and read timeouts — with no dependency beyond
//! `std::net`. Authenticity of what it fetches comes from the archive
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
use std::time::{Duration, Instant};

use super::fetch::{Fetch, FetchError, FetchRequest};

/// The ceiling on a single response body, buffered in memory before its digest
/// is checked. It sits far above any Debian index or `.deb`, so it never bites
/// a legitimate fetch, and bounds the memory a hostile mirror can drive a
/// caller to buffer by announcing a huge framing or never closing the stream.
/// A consumer that must fetch something larger supplies their own [`Fetch`].
const MAX_BODY: u64 = 2 * 1024 * 1024 * 1024;

/// The ceiling on a single framing line — the status line, a header line, or a
/// chunk-size line. Real ones are a few hundred bytes at most; a larger one is
/// a hostile or broken mirror, not a legitimate response. Bounding each line
/// keeps a mirror from driving unbounded buffering with one enormous line,
/// which the body cap alone does not cover.
const MAX_LINE: usize = 16 * 1024;

/// The most header lines read before the blank separator. Bounds a slowloris
/// mirror that dribbles endless headers within the per-read timeout.
const MAX_HEADERS: usize = 256;

/// The default HTTP and `file://` fetcher.
#[derive(Debug, Clone)]
pub struct HttpFetch {
    connect_timeout: Duration,
    io_timeout: Duration,
    request_timeout: Option<Duration>,
    max_redirects: u32,
    cross_host_redirects: bool,
}

impl Default for HttpFetch {
    fn default() -> Self {
        HttpFetch {
            connect_timeout: Duration::from_secs(30),
            io_timeout: Duration::from_secs(120),
            // A whole-request wall-clock ceiling. The per-read timeout alone
            // does not bound total time: a mirror that trickles the body one
            // byte just under each read timeout resets the clock indefinitely.
            // One hour per file sits far above any real Debian index or `.deb`
            // fetch — each is a separate request, not a whole bootstrap — while
            // turning an endless trickle into a bounded failure.
            request_timeout: Some(Duration::from_secs(3600)),
            max_redirects: 5,
            cross_host_redirects: false,
        }
    }
}

impl HttpFetch {
    /// A fetcher with the default timeouts and redirect limit.
    pub fn new() -> Self {
        HttpFetch::default()
    }

    /// Sets the connection and per-read timeouts.
    pub fn timeouts(mut self, connect: Duration, io: Duration) -> Self {
        self.connect_timeout = connect;
        self.io_timeout = io;
        self
    }

    /// Sets the whole-request deadline bounding the total time one fetch may
    /// take, or `None` to remove the bound. The default is one hour per file;
    /// raise it only to fetch an unusually large artifact over a slow link.
    pub fn request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_timeout = timeout;
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
        if let Some(path) = url.strip_prefix("file://") {
            return fetch_file(url, path, sink);
        }
        let mut current = url.to_string();
        for _ in 0..=self.max_redirects {
            match self.request(&current, sink)? {
                Step::Done => return Ok(()),
                Step::Redirect(next) => current = next,
            }
        }
        Err(FetchError::url(
            url,
            format!("more than {} redirects", self.max_redirects),
        ))
    }
}

/// The result of one request: the body was delivered, or a redirect target.
enum Step {
    Done,
    Redirect(String),
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
    /// Performs one HTTP request, streaming a 2xx body to `sink`.
    fn request(&self, url: &str, sink: &mut dyn Write) -> Result<Step, FetchError> {
        let parsed = parse_http_url(url)?;
        let io = |op: &'static str| move |source: io::Error| FetchError::io(url, op, source);

        let addrs = (parsed.host.as_str(), parsed.port)
            .to_socket_addrs()
            .map_err(io("resolving the address"))?;
        let stream = self.connect(url, addrs)?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(io("connecting"))?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(io("connecting"))?;

        let host_header = if parsed.port == 80 {
            parsed.authority_host().into_owned()
        } else {
            format!("{}:{}", parsed.authority_host(), parsed.port)
        };
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: ferroday-cage\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n",
            parsed.path,
        );
        (&stream)
            .write_all(request.as_bytes())
            .map_err(io("sending the request"))?;

        // Bound the whole response, not just each read: the deadline is checked
        // before every underlying read, so a mirror that trickles bytes to keep
        // the per-read timeout from firing still fails once the deadline passes.
        let deadline = self.request_timeout.map(|timeout| Instant::now() + timeout);
        let mut reader = BufReader::new(DeadlineReader {
            inner: stream,
            deadline,
        });
        let code = read_status(&mut reader).map_err(io("reading the response"))?;
        let headers = read_headers(&mut reader).map_err(io("reading the response"))?;

        match code {
            200 => {}
            301 | 302 | 303 | 307 | 308 => {
                let location = headers
                    .location
                    .ok_or_else(|| FetchError::status(url, code))?;
                let next = resolve_redirect(url, &location);
                self.check_redirect_host(url, &next)?;
                return Ok(Step::Redirect(next));
            }
            404 => {
                return Err(FetchError::not_found(url));
            }
            other => {
                return Err(FetchError::status(url, other));
            }
        }

        // Every body path streams through a writer capped at `MAX_BODY`, so a
        // hostile mirror cannot drive unbounded buffering by announcing a huge
        // framing or never closing the connection.
        let mut sink = LimitedWriter::new(sink, MAX_BODY);
        if headers.chunked {
            read_chunked(&mut reader, &mut sink).map_err(io("reading the body"))?;
        } else if let Some(length) = headers.content_length {
            if length > MAX_BODY {
                return Err(FetchError::url(
                    url,
                    format!("the response is {length} bytes, over the {MAX_BODY}-byte cap"),
                ));
            }
            read_sized(&mut reader, length, &mut sink).map_err(io("reading the body"))?;
        } else {
            // No framing: the body runs to end of stream, which Connection:
            // close guarantees.
            io::copy(&mut reader, &mut sink).map_err(io("reading the body"))?;
        }
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
    fn connect(
        &self,
        url: &str,
        addrs: impl Iterator<Item = SocketAddr>,
    ) -> Result<TcpStream, FetchError> {
        let mut last = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, self.connect_timeout) {
                Ok(stream) => return Ok(stream),
                Err(source) => last = Some(source),
            }
        }
        Err(match last {
            Some(source) => FetchError::io(url, "connecting", source),
            None => FetchError::url(url, "the host resolved to no addresses"),
        })
    }

    /// Enforces the same-origin redirect policy: unless cross-host redirects are
    /// allowed, a redirect must resolve to the same host *and port* as the URL
    /// it came from. A target that does not parse as `http://` is left to the
    /// next request, which refuses it. Closes the blind, GET-only SSRF an
    /// unconstrained redirect target would otherwise allow — including the port
    /// scan a same-host, different-port redirect amounts to.
    fn check_redirect_host(&self, from: &str, to: &str) -> Result<(), FetchError> {
        if self.cross_host_redirects {
            return Ok(());
        }
        let (Ok(from_url), Ok(to_url)) = (parse_http_url(from), parse_http_url(to)) else {
            return Ok(());
        };
        if from_url.host.eq_ignore_ascii_case(&to_url.host) && from_url.port == to_url.port {
            Ok(())
        } else {
            Err(FetchError::url(
                to,
                format!(
                    "redirect to a different host ({}:{}) than {}:{}; \
                     enable cross-host redirects to follow it",
                    to_url.host, to_url.port, from_url.host, from_url.port
                ),
            ))
        }
    }
}

/// Reads a local file for a `file://` URL.
fn fetch_file(url: &str, path: &str, sink: &mut dyn Write) -> Result<(), FetchError> {
    // file://localhost/path and file:///path both name an absolute path.
    let path = path.strip_prefix("localhost").unwrap_or(path);
    let mut file = File::open(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            FetchError::not_found(url)
        } else {
            FetchError::io(url, "opening the file", source)
        }
    })?;
    io::copy(&mut file, sink).map_err(|source| FetchError::io(url, "reading the file", source))?;
    Ok(())
}

/// Whether `s` is an absolute URL — a scheme followed by `://` — rather than a
/// path reference. A relative `Location` has no scheme.
fn is_absolute_url(s: &str) -> bool {
    match s.split_once("://") {
        Some((scheme, _)) => {
            !scheme.is_empty()
                && !scheme.contains('/')
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        }
        None => false,
    }
}

/// Resolves a redirect `location` against the `base` URL it was returned for.
///
/// An absolute URL is returned unchanged — a non-`http` scheme is then refused
/// by [`parse_http_url`], so a redirect cannot escape to `file://`. A path
/// reference resolves against the base's `http://host[:port]` origin: an
/// absolute path (`/x`) replaces the base path, a relative one (`x`) resolves
/// against the base path's directory. This resolves the target only; the
/// same-host redirect policy is applied separately by
/// [`HttpFetch::check_redirect_host`], and a redirected response is still
/// checked against the signed digest, so a redirect can never substitute
/// content.
fn resolve_redirect(base: &str, location: &str) -> String {
    if is_absolute_url(location) {
        return location.to_string();
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

/// Parses an `http://host[:port]/path` URL.
fn parse_http_url(url: &str) -> Result<HttpUrl, FetchError> {
    let bad = |reason: &str| FetchError::url(url, reason);
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| bad("only http:// and file:// URLs are supported"))?;
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
}

/// Reads one line through its newline into `line`, capping its length at
/// [`MAX_LINE`]. Returns the bytes read, zero at end of stream. A line over the
/// cap is a hostile or broken mirror, refused rather than buffered.
fn read_line_limited<R: BufRead>(reader: &mut R, line: &mut String) -> io::Result<usize> {
    // Reading one byte past the cap distinguishes a line exactly at the cap
    // from one that overruns it.
    let read = reader.take(MAX_LINE as u64 + 1).read_line(line)?;
    if line.len() > MAX_LINE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a response line exceeded the length cap",
        ));
    }
    Ok(read)
}

/// Reads and parses the status line, returning the status code.
fn read_status<R: BufRead>(reader: &mut R) -> io::Result<u16> {
    let mut line = String::new();
    read_line_limited(reader, &mut line)?;
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed status line"))
}

/// Reads headers up to the blank separator line.
///
/// Only the blank separator ends the section. A stream that ends inside it is
/// a truncated response — an overloaded backend, a proxy that dropped the
/// response — and is refused rather than read as a complete section with no
/// framing, which would deliver an empty body as a successful fetch.
fn read_headers<R: BufRead>(reader: &mut R) -> io::Result<Headers> {
    let mut headers = Headers::default();
    for _ in 0..MAX_HEADERS {
        let mut line = String::new();
        if read_line_limited(reader, &mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the response ended inside the header section",
            ));
        }
        let line = line.trim_end();
        if line.is_empty() {
            // The blank separator ends the header section.
            return Ok(headers);
        }
        if let Some((name, value)) = line.split_once(':') {
            let (name, value) = (name.trim(), value.trim());
            if name.eq_ignore_ascii_case("content-length") {
                // Content-Length is framing, not decoration: a value that does
                // not parse, or a repeat that contradicts the first, leaves the
                // body's extent unknown. Reading such a response to end of
                // stream would turn a truncation into a short, successful body,
                // so it is refused instead.
                let length: u64 = value.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed Content-Length")
                })?;
                if headers.content_length.is_some_and(|first| first != length) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the response repeated Content-Length with a different value",
                    ));
                }
                headers.content_length = Some(length);
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                headers.chunked = true;
            } else if name.eq_ignore_ascii_case("location") {
                headers.location = Some(value.to_string());
            }
        }
    }
    // More header lines than the cap without a blank separator: a hostile or
    // broken mirror, refused rather than read on.
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "the response sent more headers than the cap",
    ))
}

/// Copies exactly `length` bytes from `reader` to `sink`.
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
        let size = u64::from_str_radix(line.trim().split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed chunk size"))?;
        if size == 0 {
            break;
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
    Ok(())
}

/// A reader that fails once a wall-clock deadline passes, bounding the total
/// time a response may take regardless of how a mirror trickles bytes to keep
/// the per-read timeout from firing. The deadline is checked before each read,
/// so total time is bounded by the deadline plus one read timeout. `None`
/// removes the bound.
struct DeadlineReader<R> {
    inner: R,
    deadline: Option<Instant>,
}

impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline
            && Instant::now() >= deadline
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the overall fetch deadline elapsed",
            ));
        }
        self.inner.read(buf)
    }
}

/// A writer that forwards to an inner writer until a byte ceiling is crossed,
/// then fails. It bounds the memory a fetch buffers regardless of what the
/// server's framing claims.
struct LimitedWriter<'a> {
    inner: &'a mut dyn Write,
    remaining: u64,
}

impl<'a> LimitedWriter<'a> {
    fn new(inner: &'a mut dyn Write, limit: u64) -> LimitedWriter<'a> {
        LimitedWriter {
            inner,
            remaining: limit,
        }
    }
}

impl Write for LimitedWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() as u64 > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the response body exceeded the maximum size",
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

#[cfg(test)]
mod tests {
    use super::*;

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
            assert!(
                matches!(parse_http_url(url), Err(FetchError::Url { .. })),
                "{url} should be refused"
            );
        }
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

    #[test]
    fn non_http_schemes_are_rejected() {
        assert!(matches!(
            parse_http_url("https://host/x"),
            Err(FetchError::Url { .. })
        ));
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
        let mut limited = LimitedWriter::new(&mut out, 4);
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
        let mut limited = LimitedWriter::new(&mut out, 8);
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
        let dir = crate::scratch::Scratch::new("http");
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
        ] {
            let mut reader = BufReader::new(body.as_bytes());
            let err = read_headers(&mut reader).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{body:?}");
        }
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
                .check_redirect_host(from, "http://mirror.example/pool/y.deb")
                .is_ok()
        );
        // A redirect to another host is refused: it is the blind SSRF vector.
        assert!(matches!(
            fetch.check_redirect_host(from, "http://169.254.169.254/latest/meta-data"),
            Err(FetchError::Url { .. })
        ));
        // So is another port on the same host, which is the same vector aimed
        // at whatever else that host is running.
        assert!(matches!(
            fetch.check_redirect_host(from, "http://mirror.example:9000/pool/y.deb"),
            Err(FetchError::Url { .. })
        ));
        // Opting in allows the cross-host CDN redirect.
        let permissive = HttpFetch::new().cross_host_redirects(true);
        assert!(
            permissive
                .check_redirect_host(from, "http://cdn.example/x.deb")
                .is_ok()
        );
    }

    #[test]
    fn a_passed_deadline_fails_the_read() {
        // A reader whose deadline is already in the past fails before touching
        // the inner stream, so a trickling body cannot outlast the deadline.
        let mut reader = DeadlineReader {
            inner: &b"unused"[..],
            deadline: Some(Instant::now() - Duration::from_secs(1)),
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
