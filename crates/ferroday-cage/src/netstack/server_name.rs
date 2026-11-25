//! The server a TCP flow's first bytes ask for: the server name a TLS
//! ClientHello carries, or the host an HTTP/1 request names.
//!
//! Under name rules the stack holds the guest's first bytes on a flow until it
//! has read them ([`Hold`]). On an address that many sites share, the name the
//! client sends is what picks the site, so that name is held to the rules as
//! the name the guest resolved is. [`read`] reads the bytes the guest has sent
//! so far, the stream from its start, as one of three things:
//!
//! - **TLS**: a handshake record, `0x16` and then major version 3. Handshake
//!   records are read until the ClientHello they carry is whole, and its server
//!   name extension is taken.
//! - **HTTP/1**: a request line whose last word is an HTTP version, or a line
//!   of two words whose target is absolute, as HTTP/0.9 writes one. The head is
//!   read to the empty line that ends it, and the host of the target, where it
//!   names one, and the `Host` header are taken. Whether bytes are a request is
//!   judged as the most lenient server judges it, so bytes some server reads as
//!   one are never carried unread.
//! - **Anything else**, which the stack carries as it stands.
//!
//! The bytes come from the guest and are read in the caller's process, within
//! the stream's first [`MAX_HEAD`] bytes. Where a lenient reader could take a
//! different server from the bytes than the server does, this one refuses them
//! instead: a ClientHello naming more than one server, a record of another kind
//! inside one, a request line opened by whitespace, spaced by anything but
//! spaces and tabs, or holding a control byte, a carriage return that ends no
//! line, a header folded onto a further line, two `Host` headers, a target with
//! user information in it, and a host written as anything but a host name or
//! an address. The stack answers those as it answers a server the rules
//! refuse.
//!
//! A reading, once it is more than [`Reading::Incomplete`], does not change as
//! more of the stream arrives, so the stack decides a flow once.
//!
//! [`Hold`]: super::policy::Hold

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::dns;
use super::report::FlowRefusal;

/// The most of a stream's first bytes the stack reads for the server they ask
/// for. A ClientHello or a request head not whole within them is refused.
///
/// The clients measured send a ClientHello of 400 to 1,600 bytes, the largest
/// carrying a post-quantum key share, and a request head is commonly well
/// under a kilobyte. The bound is the most one TLS record carries, and a
/// quarter of the receive buffer the guest's bytes wait in while they are
/// read.
pub(super) const MAX_HEAD: usize = 16 * 1024;

/// The TLS record types the reader reads or writes (RFC 8446, section 5.1).
const RECORD_ALERT: u8 = 21;
const RECORD_HANDSHAKE: u8 = 22;

/// A TLS record's header: its type, its version, and its length.
const RECORD_HEADER: usize = 5;

/// The longest fragment one TLS record may carry (RFC 8446, section 5.1).
const MAX_FRAGMENT: usize = 1 << 14;

/// The handshake message a client opens with, and the length of a handshake
/// message's header: its type and a three-byte length (RFC 8446, section 4).
const CLIENT_HELLO: u8 = 1;
const HANDSHAKE_HEADER: usize = 4;

/// The server name extension, and the one kind of name it carries (RFC 6066,
/// section 3).
const EXTENSION_SERVER_NAME: u16 = 0;
const HOST_NAME: u8 = 0;

/// The alerts the stack answers refused first bytes with (RFC 8446, section
/// 6): fatal, and why.
const ALERT_FATAL: u8 = 2;
const ALERT_DECODE_ERROR: u8 = 50;
const ALERT_UNRECOGNIZED_NAME: u8 = 112;

/// The longest word the reader takes for an HTTP method. Past it, the bytes
/// are not read as a request. The longest method IANA registers is 17 bytes.
const MAX_METHOD: usize = 32;

/// The protocol a stream's first bytes begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Protocol {
    /// A TLS handshake.
    Tls,
    /// An HTTP/1 request.
    Http,
}

/// A server the first bytes ask for, as they write it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Host {
    /// A name, in the spelling of the [`dns`] module.
    Name(String),
    /// An address, which an HTTP host may be.
    Address(IpAddr),
}

/// What a stream's first bytes ask for, as far as they have arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Reading {
    /// The bytes begin a ClientHello or a request head, or may yet, and do not
    /// finish it.
    Incomplete,
    /// The bytes begin neither, and the stack carries them as they stand.
    Other,
    /// A whole ClientHello or request head, which asks for `hosts`, none where
    /// it names no server.
    Asks {
        /// The protocol the bytes begin.
        protocol: Protocol,
        /// The servers, at most one for TLS, and for HTTP the target's host
        /// and then the `Host` header's, where the two differ.
        hosts: Vec<Host>,
    },
    /// A ClientHello or a request head the stack does not read a server from.
    Unreadable {
        /// The protocol the bytes begin.
        protocol: Protocol,
        /// Why, as a clause.
        reason: &'static str,
    },
}

/// Reads `bytes`, a stream's first bytes as far as they have arrived, for the
/// server they ask for. Only the first [`MAX_HEAD`] of them are read.
pub(super) fn read(bytes: &[u8]) -> Reading {
    let bytes = &bytes[..bytes.len().min(MAX_HEAD)];
    let (protocol, reading) = match bytes {
        [] => return Reading::Incomplete,
        [RECORD_HANDSHAKE, ..] => (Protocol::Tls, read_tls(bytes)),
        _ => (Protocol::Http, read_http(bytes)),
    };
    match reading {
        Reading::Incomplete if bytes.len() == MAX_HEAD => Reading::Unreadable {
            protocol,
            reason: "it is not whole within the stream's first 16 KiB",
        },
        reading => reading,
    }
}

/// The answer the stack gives the guest in place of the server's, for first
/// bytes in `protocol` that `refusal` refuses: a fatal TLS alert, or an HTTP
/// response whose body says why.
///
/// A server the rules refuse is answered as a server answers for a name it
/// does not serve: the alert `unrecognized_name`, or `403 Forbidden`. Bytes the
/// stack cannot read are answered as a server answers bytes it cannot parse:
/// `decode_error`, or `400 Bad Request`. The alert goes out before any key is
/// agreed, so it is in the clear, as a server's own would be there.
pub(super) fn answer(protocol: Protocol, refusal: &FlowRefusal) -> Vec<u8> {
    let unreadable = matches!(refusal, FlowRefusal::ServerNameUnreadable { .. });
    match protocol {
        Protocol::Tls => {
            let description = match unreadable {
                true => ALERT_DECODE_ERROR,
                false => ALERT_UNRECOGNIZED_NAME,
            };
            vec![RECORD_ALERT, 3, 3, 0, 2, ALERT_FATAL, description]
        }
        Protocol::Http => {
            let status = match unreadable {
                true => "400 Bad Request",
                false => "403 Forbidden",
            };
            let body = format!("refused by the sandbox's network stack: {refusal}\n");
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        }
    }
}

/// The bytes of a stream read in order, each read answering `None` where
/// fewer bytes remain than it takes.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    /// The next `count` bytes.
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(taken)
    }

    /// The next byte.
    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|taken| taken[0])
    }

    /// The next two bytes, as a number in network order.
    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|taken| u16::from_be_bytes([taken[0], taken[1]]))
    }

    /// The next vector with a one-byte length (RFC 8446, section 3.4).
    fn vector8(&mut self) -> Option<&'a [u8]> {
        let length = self.byte()?;
        self.take(usize::from(length))
    }

    /// The next vector with a two-byte length.
    fn vector16(&mut self) -> Option<&'a [u8]> {
        let length = self.u16()?;
        self.take(usize::from(length))
    }

    /// Whether every byte has been read.
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Reads `bytes`, which begin a handshake record, as the records of a
/// ClientHello.
///
/// The records' fragments are joined until they hold the whole ClientHello,
/// which may span several records and need not start or end at a record's
/// boundary. Each record up to its end must be a handshake record of major
/// version 3, non-empty and no longer than TLS allows, since a server refuses
/// any other there. Records after the one that finishes the ClientHello are not
/// read.
fn read_tls(bytes: &[u8]) -> Reading {
    let unreadable = |reason| Reading::Unreadable {
        protocol: Protocol::Tls,
        reason,
    };
    // The handshake bytes the records carry so far, borrowed where one record
    // carries all of them.
    let mut handshake: Cow<'_, [u8]> = Cow::Borrowed(&[]);
    let mut at = 0;
    loop {
        if let Some(header) = handshake.get(..HANDSHAKE_HEADER) {
            if header[0] != CLIENT_HELLO {
                return unreadable("its first handshake message is not a ClientHello");
            }
            let length = u32::from_be_bytes([0, header[1], header[2], header[3]]);
            let length = usize::try_from(length).unwrap_or(usize::MAX);
            if length > MAX_HEAD {
                return unreadable("its ClientHello is longer than 16 KiB");
            }
            if let Some(hello) = handshake.get(HANDSHAKE_HEADER..HANDSHAKE_HEADER + length) {
                return match server_name(hello) {
                    Ok(host) => Reading::Asks {
                        protocol: Protocol::Tls,
                        hosts: host.into_iter().collect(),
                    },
                    Err(reason) => unreadable(reason),
                };
            }
        }
        let header = &bytes[at..bytes.len().min(at + RECORD_HEADER)];
        match header {
            [] => return Reading::Incomplete,
            [kind, ..] if *kind != RECORD_HANDSHAKE => {
                return unreadable("a record of another kind interrupts its ClientHello");
            }
            // A first byte of 0x16 alone does not make a stream TLS.
            [_, major, ..] if *major != 3 && at == 0 => return Reading::Other,
            [_, major, ..] if *major != 3 => {
                return unreadable("a record of another version interrupts its ClientHello");
            }
            _ if header.len() < RECORD_HEADER => return Reading::Incomplete,
            _ => {}
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if length == 0 || length > MAX_FRAGMENT {
            return unreadable("a handshake record is empty or longer than TLS allows");
        }
        let start = at + RECORD_HEADER;
        let Some(fragment) = bytes.get(start..start + length) else {
            return Reading::Incomplete;
        };
        if handshake.is_empty() {
            handshake = Cow::Borrowed(fragment);
        } else {
            handshake.to_mut().extend_from_slice(fragment);
        }
        at = start + length;
    }
}

/// The server a ClientHello's body names, `None` where it carries no server
/// name extension, or why it is not read.
///
/// The body must read to its end. Its server name extension must hold exactly
/// one name, a host name, as RFC 6066 has a client send. A list of several, or
/// of a kind other than a host name, is refused: servers differ on which of
/// several they take, and on whether they pass over a kind they do not know.
fn server_name(body: &[u8]) -> Result<Option<Host>, &'static str> {
    const MALFORMED: &str = "its ClientHello does not read to its end";
    const NOT_ONE: &str = "its server name extension does not hold exactly one host name";
    let mut hello = Cursor(body);
    // The legacy version and the random, then the session id, the cipher
    // suites and the compression methods.
    hello.take(2 + 32).ok_or(MALFORMED)?;
    let session = hello.vector8().ok_or(MALFORMED)?;
    let suites = hello.vector16().ok_or(MALFORMED)?;
    let compression = hello.vector8().ok_or(MALFORMED)?;
    if session.len() > 32 || suites.is_empty() || suites.len() % 2 != 0 || compression.is_empty() {
        return Err(MALFORMED);
    }
    // A ClientHello before TLS 1.2 may end here, without extensions.
    if hello.is_empty() {
        return Ok(None);
    }
    let mut extensions = Cursor(hello.vector16().ok_or(MALFORMED)?);
    if !hello.is_empty() {
        return Err(MALFORMED);
    }
    let mut named = None;
    while !extensions.is_empty() {
        let kind = extensions.u16().ok_or(MALFORMED)?;
        let data = extensions.vector16().ok_or(MALFORMED)?;
        if kind != EXTENSION_SERVER_NAME {
            continue;
        }
        if named.is_some() {
            return Err("its ClientHello carries two server name extensions");
        }
        let mut extension = Cursor(data);
        let mut list = Cursor(extension.vector16().ok_or(NOT_ONE)?);
        if !extension.is_empty() || list.byte() != Some(HOST_NAME) {
            return Err(NOT_ONE);
        }
        let name = list.vector16().ok_or(NOT_ONE)?;
        if !list.is_empty() {
            return Err(NOT_ONE);
        }
        let name = dns::host_name_text(name).ok_or("its server name is not a host name")?;
        named = Some(Host::Name(name));
    }
    Ok(named)
}

/// Whether `byte` may stand in an HTTP token, as a method or a header's name
/// is (RFC 9110, section 5.6.2).
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Whether `byte` is a control byte other than a tab, which no request line or
/// header line holds.
fn is_control(byte: u8) -> bool {
    (byte < 0x20 && byte != b'\t') || byte == 0x7f
}

/// Whether `byte` separates the words of a request line the reader reads.
/// HTTP separates them with one space, and servers commonly take a run of
/// spaces and tabs.
fn is_separator(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// Whether some server may read `byte` as whitespace in a request line, before
/// its first word or between two.
///
/// RFC 9112 (section 3) lets a recipient take a vertical tab, a form feed and
/// a carriage return that ends no line as a space, beside the space and the
/// tab. A reader that splits the line on Unicode whitespace after decoding it
/// as Latin-1, as Python's `http.server` does, also takes the four information
/// separators, `0x1c` to `0x1f`, a next-line `0x85` and a no-break space
/// `0xa0`.
fn is_lenient_space(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t' | 0x0b | 0x0c | b'\r' | 0x1c..=0x1f | 0x85 | 0xa0
    )
}

/// The words of a request line as a server splitting it on every byte of
/// [`is_lenient_space`] reads them.
fn lenient_words(line: &[u8]) -> Vec<&[u8]> {
    line.split(|&byte| is_lenient_space(byte))
        .filter(|word| !word.is_empty())
        .collect()
}

/// Whether `words` are a request line's: a last word naming an HTTP version,
/// or a method and an absolute target, as HTTP/0.9 writes one.
fn is_request_line(words: &[&[u8]]) -> bool {
    let last = words.last().copied().unwrap_or_default();
    let versioned = last
        .get(..5)
        .is_some_and(|name| name.eq_ignore_ascii_case(b"HTTP/"));
    versioned || (words.len() == 2 && absolute_authority(words[1]).is_some())
}

/// The line of `bytes` that starts at `at`, without its line feed or a
/// carriage return before it, and where the next line starts; `None` where no
/// line feed has arrived.
fn line_at(bytes: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let length = bytes[at..].iter().position(|&byte| byte == b'\n')?;
    let line = &bytes[at..at + length];
    Some((line.strip_suffix(b"\r").unwrap_or(line), at + length + 1))
}

/// Reads `bytes`, which do not begin a handshake record, as an HTTP/1 request.
///
/// Whether the bytes are a request at all is judged as the most lenient server
/// judges it, since that is the server the bytes may reach. Empty lines and
/// [lenient whitespace](is_lenient_space) before the request line are passed
/// over. The bytes are no request where they do not begin with a token and
/// lenient whitespace, or where the request line is not one in any server's
/// reading: its words, split on lenient whitespace, neither end in an HTTP
/// version nor are a method and an absolute target, and the same holds of the
/// line cut at a carriage return that ends no line, where a server ending
/// lines there would cut it.
///
/// A request in some server's reading is then read as a strict server reads
/// it, and refused where the two readings could part: whitespace before it,
/// words spaced by anything but spaces and tabs, a control byte, or a carriage
/// return that ends no line. A request line ending in an HTTP version must be
/// three words of version 1; an HTTP/2 connection without TLS sends one of
/// version 2, whose host is in compressed headers the stack does not read.
///
/// A first line holding a NUL is no request, finished or not: binary protocols
/// write one early, and HTTP admits none in a request line. Reading it so
/// even before the line ends carries such a protocol on, rather than holding
/// one that sends no line feed to the deadline.
fn read_http(bytes: &[u8]) -> Reading {
    let unreadable = |reason| Reading::Unreadable {
        protocol: Protocol::Http,
        reason,
    };
    let mut at = 0;
    let mut spaced = false;
    loop {
        match &bytes[at..] {
            [b'\n', ..] => at += 1,
            [b'\r', b'\n', ..] => at += 2,
            [] | [b'\r'] => return Reading::Incomplete,
            [byte, ..] if is_lenient_space(*byte) => {
                spaced = true;
                at += 1;
            }
            _ => break,
        }
    }
    let method = bytes[at..]
        .iter()
        .take_while(|&&byte| is_token_byte(byte))
        .count();
    if method == 0 || method > MAX_METHOD {
        return Reading::Other;
    }
    match bytes.get(at + method) {
        None => return Reading::Incomplete,
        Some(&byte) if !is_lenient_space(byte) => return Reading::Other,
        Some(_) => {}
    }
    let Some((line, head)) = line_at(bytes, at) else {
        return match bytes[at..].contains(&0) {
            true => Reading::Other,
            false => Reading::Incomplete,
        };
    };
    if line.contains(&0) {
        return Reading::Other;
    }
    let words = lenient_words(line);
    let cut_at_return = line
        .iter()
        .position(|&byte| byte == b'\r')
        .is_some_and(|cut| is_request_line(&lenient_words(&line[..cut])));
    if !is_request_line(&words) && !cut_at_return {
        return Reading::Other;
    }
    if line.contains(&b'\r') {
        return unreadable("a carriage return in its request line ends no line");
    }
    if spaced {
        return unreadable("whitespace comes before its request line");
    }
    if line
        .iter()
        .any(|&byte| is_lenient_space(byte) && !is_separator(byte))
    {
        return unreadable("its request line spaces its words with more than spaces and tabs");
    }
    if line.iter().any(|&byte| is_control(byte)) {
        return unreadable("its request line holds a control byte");
    }
    // The line is now words between spaces and tabs, which every server splits
    // as the lenient reading did.
    let last = words.last().copied().unwrap_or_default();
    let version = match last.get(..5) {
        Some(name) if name.eq_ignore_ascii_case(b"HTTP/") => &last[5..],
        // HTTP/0.9: a method and an absolute target, and no head, which the
        // lenient reading established.
        _ => {
            return match target_host(words[0], words[1]) {
                Ok(host) => Reading::Asks {
                    protocol: Protocol::Http,
                    hosts: host.into_iter().collect(),
                },
                Err(reason) => unreadable(reason),
            };
        }
    };
    if words.len() != 3 {
        return unreadable("its request line is not a method, a target and a version");
    }
    match version {
        [b'1', b'.', minor] if minor.is_ascii_digit() => read_head(bytes, head, words[0], words[1]),
        [b'2', ..] => unreadable(
            "it opens HTTP/2 without TLS, whose host is in compressed headers the stack does \
             not read",
        ),
        _ => unreadable("its HTTP version is not 1"),
    }
}

/// Reads the head of an HTTP/1 request whose request line was `method` and
/// `target`, from `at` in `bytes` to the empty line that ends it, for the
/// servers it asks for.
fn read_head(bytes: &[u8], mut at: usize, method: &[u8], target: &[u8]) -> Reading {
    let unreadable = |reason| Reading::Unreadable {
        protocol: Protocol::Http,
        reason,
    };
    let mut host_header = None;
    loop {
        let Some((line, next)) = line_at(bytes, at) else {
            return Reading::Incomplete;
        };
        at = next;
        if line.is_empty() {
            break;
        }
        if line.contains(&b'\r') {
            return unreadable("a carriage return in its head ends no line");
        }
        if line.iter().any(|&byte| is_control(byte)) {
            return unreadable("a header holds a control byte");
        }
        if is_separator(line[0]) {
            return unreadable("a header is folded onto a further line");
        }
        let name = line.split(|&byte| byte == b':').next().unwrap_or_default();
        if name.len() == line.len() || name.is_empty() || !name.iter().all(|&b| is_token_byte(b)) {
            return unreadable("a header line is not a name, a colon and a value");
        }
        if name.eq_ignore_ascii_case(b"host") {
            if host_header.is_some() {
                return unreadable("it carries more than one Host header");
            }
            host_header = Some(line[name.len() + 1..].trim_ascii());
        }
    }
    let mut hosts = Vec::new();
    match target_host(method, target) {
        Ok(host) => hosts.extend(host),
        Err(reason) => return unreadable(reason),
    }
    if let Some(value) = host_header.filter(|value| !value.is_empty()) {
        let Some(host) = authority_host(value) else {
            return unreadable("its Host header names neither a host name nor an address");
        };
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    Reading::Asks {
        protocol: Protocol::Http,
        hosts,
    }
}

/// The server a request's `target` names, for a request of `method`: the host
/// of a `CONNECT` target's authority, or of an absolute target's, and none for
/// a path or `*`.
fn target_host(method: &[u8], target: &[u8]) -> Result<Option<Host>, &'static str> {
    const NO_HOST: &str = "its request target names neither a host name nor an address";
    if method.eq_ignore_ascii_case(b"CONNECT") {
        return authority_host(target).map(Some).ok_or(NO_HOST);
    }
    match target {
        [b'/', ..] | b"*" => Ok(None),
        _ => match absolute_authority(target) {
            Some(authority) => authority_host(authority).map(Some).ok_or(NO_HOST),
            None => Err("its request target is neither a path, an absolute URI nor `*`"),
        },
    }
}

/// The authority of `target`, where it is an absolute URI: a scheme, `://`,
/// and the authority, which runs to the path, the query or the fragment.
fn absolute_authority(target: &[u8]) -> Option<&[u8]> {
    let separator = target.windows(3).position(|window| window == b"://")?;
    let scheme = &target[..separator];
    let first = *scheme.first()?;
    let schemed = first.is_ascii_alphabetic()
        && scheme
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte));
    if !schemed {
        return None;
    }
    let rest = &target[separator + 3..];
    let end = rest
        .iter()
        .position(|byte| b"/?#".contains(byte))
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The host an authority names, with any port left off: an IPv6 address in
/// brackets, an IPv4 address, or a host name; `None` for anything else, user
/// information and an empty host among it.
///
/// User information, `user@`, is refused rather than passed over: HTTP forbids
/// a sender to write it, and readers differ on which `@` ends it.
fn authority_host(authority: &[u8]) -> Option<Host> {
    if authority.contains(&b'@') {
        return None;
    }
    let (host, port) = match authority.strip_prefix(b"[") {
        Some(bracketed) => {
            let close = bracketed.iter().position(|&byte| byte == b']')?;
            let address: Ipv6Addr = std::str::from_utf8(&bracketed[..close])
                .ok()?
                .parse()
                .ok()?;
            let port = match &bracketed[close + 1..] {
                [] => &[][..],
                [b':', port @ ..] => port,
                _ => return None,
            };
            (Host::Address(IpAddr::V6(address)), port)
        }
        None => {
            let (host, port) = match authority.iter().rposition(|&byte| byte == b':') {
                Some(colon) => (&authority[..colon], &authority[colon + 1..]),
                None => (authority, &[][..]),
            };
            let address = std::str::from_utf8(host).ok()?.parse::<Ipv4Addr>();
            let host = match address {
                Ok(address) => Host::Address(IpAddr::V4(address)),
                Err(_) => Host::Name(dns::host_name_text(host)?),
            };
            (host, port)
        }
    };
    is_port(port).then_some(host)
}

/// Whether `port` is an authority's port: decimal digits, or nothing, as a URI
/// may write an authority's port (RFC 3986, section 3.2.3).
///
/// The crate's answer to whether text is a run of digits,
/// `provision::number::is_digits`, is built with the provisioners alone, and
/// the network stack builds without them, so the stack asks the question
/// itself.
fn is_port(port: &[u8]) -> bool {
    port.iter().all(u8::is_ascii_digit)
}

/// Runs the reader over `bytes`, for a fuzz target: it may not panic, a name
/// it gives is a host name's text, a reading of a shorter prefix is unfinished
/// or the same, and each answer has the shape its protocol gives one.
#[cfg(fuzzing)]
pub(super) fn exercise(bytes: &[u8]) {
    let whole = read(bytes);
    if let Reading::Asks { hosts, .. } = &whole {
        for host in hosts {
            if let Host::Name(name) = host {
                assert!(dns::host_name_flaw(name).is_none(), "{name:?}");
                assert_eq!(*name, name.to_ascii_lowercase());
            }
        }
    }
    for cut in [0, bytes.len() / 2, bytes.len().saturating_sub(1)] {
        let part = read(&bytes[..cut]);
        assert!(
            part == Reading::Incomplete || part == whole,
            "{part:?} at {cut} bytes, then {whole:?}"
        );
    }
    let refusals = [
        FlowRefusal::ServerNameNotAllowed {
            name: "example.com".to_string(),
        },
        FlowRefusal::ServerNameUnreadable { reason: "a reason" },
    ];
    for refusal in &refusals {
        assert_eq!(answer(Protocol::Tls, refusal).len(), 7);
        let response = answer(Protocol::Http, refusal);
        assert!(response.starts_with(b"HTTP/1.1 4"));
        assert!(response.ends_with(b"\n"));
    }
}

/// Runs the reader over `body` as a ClientHello's, in one record and in
/// records of the size `input`'s first byte gives, for a fuzz target: both
/// read as [`exercise`] requires, and as each other where both fit the bytes
/// the stack reads.
#[cfg(fuzzing)]
pub(super) fn exercise_client_hello(input: &[u8]) {
    let Some((&size, body)) = input.split_first() else {
        return;
    };
    let Ok(length) = u32::try_from(body.len()) else {
        return;
    };
    let mut message = vec![CLIENT_HELLO];
    message.extend_from_slice(&length.to_be_bytes()[1..]);
    message.extend_from_slice(body);
    let whole = records(&message, MAX_FRAGMENT);
    let split = records(&message, usize::from(size).max(1));
    exercise(&whole);
    exercise(&split);
    if split.len() <= MAX_HEAD {
        assert_eq!(read(&whole), read(&split));
    }
}

/// Runs the reader over `bytes` as a request head, for a fuzz target: they
/// read as [`exercise`] requires, bytes some server may read as a request are
/// never carried unread, and where they hold no carriage return, they read as
/// the same bytes with each line feed after one.
#[cfg(fuzzing)]
pub(super) fn exercise_http_head(bytes: &[u8]) {
    exercise(bytes);
    let read_bytes = &bytes[..bytes.len().min(MAX_HEAD)];
    if read(read_bytes) == Reading::Other {
        assert!(
            !a_server_may_read_a_request(read_bytes),
            "{} is carried unread",
            read_bytes.escape_ascii()
        );
    }
    if bytes.first() != Some(&RECORD_HANDSHAKE)
        && !bytes.contains(&b'\r')
        && bytes.len() < MAX_HEAD / 2
    {
        let mut crlf = Vec::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            if byte == b'\n' {
                crlf.push(b'\r');
            }
            crlf.push(byte);
        }
        assert_eq!(read(bytes), read(&crlf));
    }
}

/// Whether some server may read `bytes` as an HTTP request, stated apart from
/// [`read_http`]'s walk so a fuzz target can hold one to the other: after any
/// line feeds and lenient whitespace, a method token and lenient whitespace,
/// on a first line holding no NUL whose words are a request line's, whole or
/// cut at a carriage return. The first line must have ended, since a server
/// reads no request before it does.
#[cfg(any(test, fuzzing))]
fn a_server_may_read_a_request(bytes: &[u8]) -> bool {
    let Some(start) = bytes
        .iter()
        .position(|&byte| byte != b'\n' && !is_lenient_space(byte))
    else {
        return false;
    };
    let rest = &bytes[start..];
    let Some(end) = rest.iter().position(|&byte| byte == b'\n') else {
        return false;
    };
    let line = &rest[..end];
    let method = line.iter().take_while(|&&byte| is_token_byte(byte)).count();
    let spaced = line.get(method).is_some_and(|&byte| is_lenient_space(byte));
    if !(1..=MAX_METHOD).contains(&method) || !spaced || line.contains(&0) {
        return false;
    }
    line.split(|&byte| byte == b'\r')
        .next()
        .into_iter()
        .chain([line])
        .any(|part| is_request_line(&lenient_words(part)))
}

/// `message` in handshake records of at most `size` bytes each.
#[cfg(any(test, fuzzing))]
fn records(message: &[u8], size: usize) -> Vec<u8> {
    let mut records = Vec::new();
    for fragment in message.chunks(size.min(MAX_FRAGMENT)) {
        let length = u16::try_from(fragment.len()).expect("a fragment fits a record");
        records.extend_from_slice(&[RECORD_HANDSHAKE, 3, 1]);
        records.extend_from_slice(&length.to_be_bytes());
        records.extend_from_slice(fragment);
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ClientHellos six clients sent, each naming `example.com`, as the
    /// fixtures' README describes them.
    const FIXTURES: [(&str, &[u8]); 6] = [
        (
            "git",
            include_bytes!("../../tests/fixtures/client-hello/git-2.43-gnutls-3.8.bin"),
        ),
        (
            "curl",
            include_bytes!("../../tests/fixtures/client-hello/curl-8.5-openssl-3.0.bin"),
        ),
        (
            "python",
            include_bytes!("../../tests/fixtures/client-hello/python-3.12-openssl-3.0.bin"),
        ),
        (
            "go",
            include_bytes!("../../tests/fixtures/client-hello/go-1.27.bin"),
        ),
        (
            "openssl",
            include_bytes!("../../tests/fixtures/client-hello/openssl-3.6.4.bin"),
        ),
        (
            "node",
            include_bytes!("../../tests/fixtures/client-hello/node-24.18.bin"),
        ),
    ];

    fn asks(protocol: Protocol, hosts: &[&str]) -> Reading {
        Reading::Asks {
            protocol,
            hosts: hosts
                .iter()
                .map(|host| match host.parse() {
                    Ok(address) => Host::Address(address),
                    Err(_) => Host::Name(host.to_string()),
                })
                .collect(),
        }
    }

    fn unreadable(protocol: Protocol, reason: &'static str) -> Reading {
        Reading::Unreadable { protocol, reason }
    }

    /// Asserts that every prefix of `bytes` reads as unfinished or as `bytes`
    /// whole does, which is what lets the stack decide a flow once.
    fn settles_once(bytes: &[u8]) {
        let whole = read(bytes);
        for cut in 0..bytes.len() {
            let part = read(&bytes[..cut]);
            assert!(
                part == Reading::Incomplete || part == whole,
                "{part:?} at {cut} of {:?}, then {whole:?}",
                bytes.escape_ascii().to_string()
            );
        }
    }

    #[test]
    fn each_clients_hello_asks_for_its_server_name() {
        for (client, hello) in FIXTURES {
            assert_eq!(
                read(hello),
                asks(Protocol::Tls, &["example.com"]),
                "{client}"
            );
            // Read as it arrives: unfinished until its last byte.
            for cut in 0..hello.len() {
                assert_eq!(
                    read(&hello[..cut]),
                    Reading::Incomplete,
                    "{client} at {cut}"
                );
            }
            // What follows the ClientHello is not read.
            let mut more = hello.to_vec();
            more.extend_from_slice(&[0x17, 3, 3, 0, 1, 0]);
            assert_eq!(read(&more), read(hello), "{client}");
        }
    }

    #[test]
    fn a_hello_reads_the_same_in_records_of_any_size() {
        for (client, hello) in FIXTURES {
            // The fixtures are each one record; their handshake message is the
            // record's fragment.
            let message = &hello[RECORD_HEADER..];
            for size in [1, 3, 4, 5, 100, 1000] {
                let split = records(message, size);
                assert_eq!(
                    read(&split),
                    asks(Protocol::Tls, &["example.com"]),
                    "{client} in records of {size}"
                );
            }
            settles_once(&records(message, 7));
        }
    }

    /// A ClientHello's body: version, random, a session id, one cipher suite,
    /// null compression, and `extensions`, each its type and data, where
    /// there are any.
    fn hello_body(extensions: Option<&[(u16, Vec<u8>)]>) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0x5a; 32]);
        body.extend_from_slice(&[32]);
        body.extend_from_slice(&[0xa5; 32]);
        body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        if let Some(extensions) = extensions {
            let mut block = Vec::new();
            for (kind, data) in extensions {
                block.extend_from_slice(&kind.to_be_bytes());
                block.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
                block.extend_from_slice(data);
            }
            body.extend_from_slice(&u16::try_from(block.len()).unwrap().to_be_bytes());
            body.extend_from_slice(&block);
        }
        body
    }

    /// `body` as a ClientHello in one record.
    fn hello(body: &[u8]) -> Vec<u8> {
        let mut message = vec![CLIENT_HELLO];
        message.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        message.extend_from_slice(body);
        records(&message, MAX_FRAGMENT)
    }

    /// A server name extension's data holding `entries`, each a kind and a
    /// name.
    fn server_names(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (kind, name) in entries {
            list.push(*kind);
            list.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
            list.extend_from_slice(name);
        }
        let mut data = u16::try_from(list.len()).unwrap().to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        data
    }

    #[test]
    fn a_hello_without_a_server_name_asks_for_none() {
        // Without extensions, as before TLS 1.2, and with some but none the
        // server name's.
        assert_eq!(read(&hello(&hello_body(None))), asks(Protocol::Tls, &[]));
        let alpn = (16, b"\x00\x09\x08http/1.1".to_vec());
        assert_eq!(
            read(&hello(&hello_body(Some(&[alpn])))),
            asks(Protocol::Tls, &[])
        );
        // The name is lowered, and its trailing dot dropped.
        let named = (0, server_names(&[(HOST_NAME, b"WWW.Example.COM.")]));
        assert_eq!(
            read(&hello(&hello_body(Some(&[named])))),
            asks(Protocol::Tls, &["www.example.com"])
        );
    }

    #[test]
    fn a_hello_a_server_could_read_otherwise_is_refused() {
        let named = |entries: &[(u8, &[u8])]| (0, server_names(entries));
        let one = named(&[(HOST_NAME, b"example.com")]);
        for (extensions, reason) in [
            (
                vec![one.clone(), named(&[(HOST_NAME, b"other.example")])],
                "its ClientHello carries two server name extensions",
            ),
            (
                vec![named(&[
                    (HOST_NAME, b"example.com"),
                    (HOST_NAME, b"other.example"),
                ])],
                "its server name extension does not hold exactly one host name",
            ),
            (
                vec![named(&[(1, b"x"), (HOST_NAME, b"other.example")])],
                "its server name extension does not hold exactly one host name",
            ),
            (
                vec![(0, Vec::new())],
                "its server name extension does not hold exactly one host name",
            ),
            (
                vec![named(&[(HOST_NAME, b"other.example\0.example.com")])],
                "its server name is not a host name",
            ),
            (
                vec![named(&[(HOST_NAME, b"")])],
                "its server name is not a host name",
            ),
        ] {
            assert_eq!(
                read(&hello(&hello_body(Some(&extensions)))),
                unreadable(Protocol::Tls, reason),
                "{extensions:?}"
            );
        }
        // Bytes past the extensions, or an extension running past them.
        let mut trailing = hello_body(Some(&[one]));
        trailing.push(0);
        let mut short = hello_body(None);
        short.extend_from_slice(&[0, 9, 0, 0, 0, 20]);
        for body in [trailing, short, vec![3, 3]] {
            assert_eq!(
                read(&hello(&body)),
                unreadable(Protocol::Tls, "its ClientHello does not read to its end")
            );
        }
    }

    #[test]
    fn records_around_a_hello_are_held_to_tls() {
        let message = &FIXTURES[1].1[RECORD_HEADER..];
        let split = records(message, 100);
        // Another kind of record, or another version, before the hello is
        // whole.
        let mut interrupted = split[..105].to_vec();
        interrupted.extend_from_slice(&[RECORD_ALERT, 3, 3, 0, 2, 1, 0]);
        assert_eq!(
            read(&interrupted),
            unreadable(
                Protocol::Tls,
                "a record of another kind interrupts its ClientHello"
            )
        );
        let mut versioned = split.clone();
        versioned[106] = 2;
        assert_eq!(
            read(&versioned),
            unreadable(
                Protocol::Tls,
                "a record of another version interrupts its ClientHello"
            )
        );
        // An empty record, one longer than TLS allows, a first message other
        // than a ClientHello, and one longer than the stack reads.
        let too_long = u16::try_from(MAX_FRAGMENT + 1).unwrap().to_be_bytes();
        for (bytes, reason) in [
            (
                vec![RECORD_HANDSHAKE, 3, 1, 0, 0],
                "a handshake record is empty or longer than TLS allows",
            ),
            (
                vec![RECORD_HANDSHAKE, 3, 1, too_long[0], too_long[1]],
                "a handshake record is empty or longer than TLS allows",
            ),
            (
                records(&[2, 0, 0, 0], 4),
                "its first handshake message is not a ClientHello",
            ),
            (
                records(&[CLIENT_HELLO, 0, 0x40, 1], 4),
                "its ClientHello is longer than 16 KiB",
            ),
        ] {
            assert_eq!(read(&bytes), unreadable(Protocol::Tls, reason));
        }
        // A first byte of 0x16 alone does not make the stream TLS.
        assert_eq!(read(&[RECORD_HANDSHAKE]), Reading::Incomplete);
        assert_eq!(read(&[RECORD_HANDSHAKE, 2, 0]), Reading::Other);
        settles_once(&interrupted);
    }

    #[test]
    fn a_request_asks_for_its_host() {
        for (request, hosts) in [
            (
                &b"GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n"[..],
                &["example.com"][..],
            ),
            (
                b"GET / HTTP/1.1\r\nhost:example.com:8080 \r\n\r\n",
                &["example.com"],
            ),
            (
                b"GET / HTTP/1.1\r\nHost: 192.0.2.7:80\r\n\r\n",
                &["192.0.2.7"],
            ),
            (
                b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n",
                &["2001:db8::1"],
            ),
            // No host at all, or an empty one.
            (b"GET / HTTP/1.0\r\n\r\n", &[]),
            (b"OPTIONS * HTTP/1.1\r\nHost:\r\n\r\n", &[]),
            // An absolute target's host, beside the header's where they differ.
            (
                b"GET http://a.example/x HTTP/1.1\r\nHost: b.example\r\n\r\n",
                &["a.example", "b.example"],
            ),
            (
                b"GET https://a.example:443?q HTTP/1.1\r\nHost: a.example\r\n\r\n",
                &["a.example"],
            ),
            (b"CONNECT a.example:443 HTTP/1.1\r\n\r\n", &["a.example"]),
            // Empty lines before the request, bare line feeds, and the head's
            // other headers.
            (
                b"\r\n\nPOST /form HTTP/1.1\nUser-Agent: x\nHost: a.example\n\nbody",
                &["a.example"],
            ),
            // HTTP/0.9: a method and an absolute target, without a head.
            (b"GET http://a.example/\r\n", &["a.example"]),
        ] {
            assert_eq!(
                read(request),
                asks(Protocol::Http, hosts),
                "{}",
                request.escape_ascii()
            );
            settles_once(request);
        }
    }

    #[test]
    fn a_request_a_server_could_read_otherwise_is_refused() {
        for (request, reason) in [
            (
                &b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n"[..],
                "it carries more than one Host header",
            ),
            (
                b"GET / HTTP/1.1\r\nX: y\rHost: b.example\r\n\r\n",
                "a carriage return in its head ends no line",
            ),
            (
                b"GET / HTTP/1.1\r\nHost: a.example\r\n b.example\r\n\r\n",
                "a header is folded onto a further line",
            ),
            (
                b"GET / HTTP/1.1\r\nHost : b.example\r\n\r\n",
                "a header line is not a name, a colon and a value",
            ),
            (
                b"GET / HTTP/1.1\r\nno colon\r\n\r\n",
                "a header line is not a name, a colon and a value",
            ),
            (
                b"GET / HTTP/1.1\r\nHost: b.example\0.a.example\r\n\r\n",
                "a header holds a control byte",
            ),
            (
                b"GET / HTTP/1.1\r\nHost: %62.example\r\n\r\n",
                "its Host header names neither a host name nor an address",
            ),
            (
                b"GET http://a.example@b.example/ HTTP/1.1\r\n\r\n",
                "its request target names neither a host name nor an address",
            ),
            (
                b"GET b.example/ HTTP/1.1\r\n\r\n",
                "its request target is neither a path, an absolute URI nor `*`",
            ),
            (
                b"GET / x HTTP/1.1\r\n\r\n",
                "its request line is not a method, a target and a version",
            ),
            (
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                "it opens HTTP/2 without TLS, whose host is in compressed headers the stack \
                 does not read",
            ),
            (b"GET / HTTP/3\r\n\r\n", "its HTTP version is not 1"),
        ] {
            assert_eq!(
                read(request),
                unreadable(Protocol::Http, reason),
                "{}",
                request.escape_ascii()
            );
            settles_once(request);
        }
        // A request line or a head not whole within the bytes read.
        let mut long = b"GET /".to_vec();
        long.resize(MAX_HEAD, b'a');
        assert_eq!(
            read(&long),
            unreadable(
                Protocol::Http,
                "it is not whole within the stream's first 16 KiB"
            )
        );
        assert_eq!(read(&long[..MAX_HEAD - 1]), Reading::Incomplete);
    }

    #[test]
    fn a_request_line_a_lenient_server_reads_is_refused() {
        for (request, reason) in [
            // Whitespace before the request line, which a server may pass over
            // as it passes over an empty line.
            (
                &b" GET / HTTP/1.1\r\nHost: b.example\r\n\r\n"[..],
                "whitespace comes before its request line",
            ),
            (
                b"\r\n\tGET / HTTP/1.1\r\n\r\n",
                "whitespace comes before its request line",
            ),
            (
                b"\x0cGET http://b.example/\r\n",
                "whitespace comes before its request line",
            ),
            // Words a server may split on whitespace other than spaces and
            // tabs: RFC 9112's, and a Latin-1 reader's Unicode whitespace.
            (
                b"GET\x0b/ HTTP/1.1\r\nHost: b.example\r\n\r\n",
                "its request line spaces its words with more than spaces and tabs",
            ),
            (
                b"GET\x0c/ HTTP/1.1\r\n\r\n",
                "its request line spaces its words with more than spaces and tabs",
            ),
            (
                b"GET\x1f/ HTTP/1.1\r\n\r\n",
                "its request line spaces its words with more than spaces and tabs",
            ),
            (
                b"GET /\x85HTTP/1.1\r\n\r\n",
                "its request line spaces its words with more than spaces and tabs",
            ),
            (
                b"GET\xa0/\xa0HTTP/1.1\r\nHost: b.example\r\n\r\n",
                "its request line spaces its words with more than spaces and tabs",
            ),
            // A server ending lines at a bare carriage return reads a request
            // line, and here a Host header, that the line feed's reading does
            // not.
            (
                b"GET / HTTP/1.1\rHost: b.example\r\n\r\n",
                "a carriage return in its request line ends no line",
            ),
            (
                b"GET\rhttp://b.example/\r\n",
                "a carriage return in its request line ends no line",
            ),
            (
                b"GET / HTTP/1.1\r\r\n\r\n",
                "a carriage return in its request line ends no line",
            ),
            // A control byte a server may take as part of a word.
            (
                b"GET /\x01 HTTP/1.1\r\nHost: b.example\r\n\r\n",
                "its request line holds a control byte",
            ),
            (
                b"GET http://b.example/\x7f\r\n",
                "its request line holds a control byte",
            ),
        ] {
            assert_eq!(
                read(request),
                unreadable(Protocol::Http, reason),
                "{}",
                request.escape_ascii()
            );
            assert!(
                a_server_may_read_a_request(request),
                "{}",
                request.escape_ascii()
            );
            settles_once(request);
        }
    }

    #[test]
    fn bytes_that_begin_no_request_are_other() {
        for bytes in [
            &b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"[..],
            b"*1\r\n$4\r\nPING\r\n",
            b"PING\r\n",
            b"get key\r\n",
            b"GET /\r\n",
            b"\0\0\0\x08\x04\xd2\x16\x2f",
            b"\x80\x2e\x01\x03\x01",
            b"\r\x00",
            // Whitespace before a line that is no request line either way.
            b" hello world\r\n",
            // Cut at its carriage return, the line is no request line either.
            b"FOO bar\rbaz\r\n",
            // git's protocol: a NUL before any line feed, which HTTP admits
            // nowhere in a request line, finished or not.
            b"0032git-upload-pack /project.git\0host=example.com\0",
            b"GET /\0 HTTP/1.1\r\nHost: b.example\r\n\r\n",
        ] {
            assert_eq!(read(bytes), Reading::Other, "{}", bytes.escape_ascii());
            assert!(
                !a_server_may_read_a_request(bytes),
                "{}",
                bytes.escape_ascii()
            );
            settles_once(bytes);
        }
        let method = vec![b'A'; MAX_METHOD + 1];
        assert_eq!(read(&method), Reading::Other);
        // Until the bytes say, they may yet begin a request.
        for bytes in [
            &b""[..],
            b"\r",
            b"\r\n",
            b" ",
            b" GET",
            b"GE",
            b"GET",
            b"GET /",
            b"GET\x0b",
            b"GET /\x01",
            b"GET / HTTP/1.1\r",
            b"GET / HTTP/1.1\rHost: b.example",
        ] {
            assert_eq!(read(bytes), Reading::Incomplete, "{}", bytes.escape_ascii());
        }
        assert_eq!(read(&method[..MAX_METHOD]), Reading::Incomplete);
    }

    #[test]
    fn a_line_feed_ends_a_line_as_a_carriage_return_and_one_do() {
        for request in [
            &b"GET / HTTP/1.1\nHost: a.example\n\n"[..],
            b"GET / HTTP/1.1\nHost: a.example\nHost: b.example\n\n",
            b"GET http://a.example/\n",
            b"GET / HTTP/1.1\nHost: a.example\n",
        ] {
            let mut crlf = Vec::new();
            for &byte in request {
                if byte == b'\n' {
                    crlf.push(b'\r');
                }
                crlf.push(byte);
            }
            assert_eq!(read(request), read(&crlf), "{}", request.escape_ascii());
        }
    }

    #[test]
    fn a_refusal_is_answered_in_the_protocol_the_bytes_began() {
        let refused = FlowRefusal::ServerNameNotAllowed {
            name: "other.example".to_string(),
        };
        let unread = FlowRefusal::ServerNameUnreadable {
            reason: "it carries more than one Host header",
        };
        assert_eq!(
            answer(Protocol::Tls, &refused),
            [
                RECORD_ALERT,
                3,
                3,
                0,
                2,
                ALERT_FATAL,
                ALERT_UNRECOGNIZED_NAME
            ]
        );
        assert_eq!(
            answer(Protocol::Tls, &unread),
            [RECORD_ALERT, 3, 3, 0, 2, ALERT_FATAL, ALERT_DECODE_ERROR]
        );
        for (refusal, status) in [(&refused, "403 Forbidden"), (&unread, "400 Bad Request")] {
            let response = String::from_utf8(answer(Protocol::Http, refusal)).unwrap();
            let (head, body) = response.split_once("\r\n\r\n").unwrap();
            assert!(
                head.starts_with(&format!("HTTP/1.1 {status}\r\n")),
                "{head}"
            );
            assert!(head.contains("\r\nConnection: close"), "{head}");
            assert!(
                head.contains(&format!("\r\nContent-Length: {}", body.len())),
                "{head}"
            );
            assert_eq!(
                body,
                format!("refused by the sandbox's network stack: {refusal}\n")
            );
        }
    }
}
