//! The stack's nameserver: the guest's DNS, answered by the host's resolver.
//!
//! The nameserver answers on port 53 of host 3 of each network the stack
//! configures, `10.0.2.3` and `fd00::3` by default, over UDP and TCP. It asks
//! one resolver of the host's on the guest's behalf: the first nameserver the
//! host's `resolv.conf` names, read when the stack attaches, or the one the
//! configuration names. The stack's sockets are the host's, so a resolver on
//! the host's loopback is reached as any other: systemd-resolved's stub at
//! `127.0.0.53` is the common one, and an address the stack refuses as a guest
//! destination.
//!
//! It works in messages rather than as a port mapped onto the resolver. A query
//! is read, relayed, and its answer read back. Each query goes upstream on a
//! host socket of its own, connected to the resolver, so only that resolver's
//! answer to that query can arrive there, and it goes as the guest sent it. It
//! goes over the transport the guest asked on: a datagram for a datagram, a
//! connection of its own for a query from a TCP connection. A guest's resolver
//! moves to TCP itself when an answer comes back truncated, as it does from any
//! resolver.
//!
//! One limit is the stack's own. It does not fragment, so a datagram answer
//! longer than one packet cannot reach the guest, whatever size the guest's
//! query offered. Such an answer is replaced with a truncated one, its question
//! and flags with no records and the TC bit set, which sends the guest's
//! resolver to TCP for the whole answer.
//!
//! Everything is bounded: [`MAX_EXCHANGES`] queries in flight, each given up
//! after [`EXCHANGE_DEADLINE`]; [`MAX_SESSIONS`] guest TCP connections, each
//! closed after [`SESSION_IDLE`] without a query; and [`dns::MAX_QUERY`] bytes a
//! query. A datagram past a bound, or given up, is dropped, as a lossy network
//! would drop it, and the guest's resolver asks again. A query on a TCP
//! connection is answered with SERVFAIL instead, since its resolver waits on the
//! connection rather than asking again. A query the resolver refuses is answered
//! with SERVFAIL too, so the guest learns of it at once.
//!
//! The destination rules decide each question before it is relayed
//! ([`Policy::decide_question`]). A name they refuse is answered NXDOMAIN, with
//! the reason as an Extended DNS Error where the guest's resolver reads EDNS,
//! and nothing is relayed. Under name rules a question for a name's HTTPS or
//! SVCB records is answered with none, since those records carry the keys a
//! client would encrypt its server name with. Each question is reported, as it
//! is relayed, refused or answered with no records.
//!
//! Each answer the upstream gives, under any rules or none, is read for the
//! addresses it gives the asked name, and each is pinned to that name
//! ([`Pins`]) before the answer goes back, so the guest's first connection to
//! an address finds its name there. A pin names a flow's destination in its
//! report, and is what a name rule admits a flow by.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::event::PollFlags;
use rustix::io::Errno;
use rustix::net::{RecvFlags, SendFlags, SocketFlags, SocketType};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::IpEndpoint;

use super::dns::{self, Query, Rcode, Refusal};
use super::pins::Pins;
use super::policy::Policy;
use super::report::{NetStackReport, Reporter};
use super::udp::deliverable;
use crate::mechanism::netns::socket_for;

/// The port the nameserver answers on, and the one it asks its upstream on
/// where `resolv.conf` names the upstream, which names no port.
pub(super) const PORT: u16 = 53;

/// The most queries the nameserver relays at once, over both transports. A
/// query past it is dropped.
pub(super) const MAX_EXCHANGES: usize = 64;

/// How long a relayed query waits for its answer before it is given up: a
/// datagram dropped, and a query on a TCP connection answered with SERVFAIL.
///
/// The guest's resolver has its own timeout and asks again past it: five
/// seconds a try for glibc, with tries a second apart for musl. A query outlives
/// the first of those, so a slow answer still reaches the resolver that is
/// waiting for it.
pub(super) const EXCHANGE_DEADLINE: Duration = Duration::from_secs(5);

/// The most guest TCP connections the nameserver serves at once. A connection
/// past it is refused with a reset.
pub(super) const MAX_SESSIONS: usize = 16;

/// How long a guest TCP connection may sit with no query and no answer moving
/// before the nameserver closes it, as RFC 7766 lets a server close an idle
/// connection.
pub(super) const SESSION_IDLE: Duration = Duration::from_secs(30);

/// The most queries one guest TCP connection has in flight at once. Past it,
/// the connection's further queries wait in its receive buffer, and the guest's
/// sends then wait on its window.
const SESSION_IN_FLIGHT: usize = 8;

/// The most answer bytes one guest TCP connection holds that its transmit
/// buffer has no room for. Past it, the connection's queries are left unread
/// until the guest reads, so a guest that sends and never reads holds a bounded
/// amount.
const SESSION_BACKLOG: usize = 64 * 1024;

/// A guest TCP connection's receive buffer: one query of the longest the
/// nameserver takes, with its length prefix.
const SESSION_RX: usize = 2 + dns::MAX_QUERY;

/// A guest TCP connection's transmit buffer. An answer longer than it waits in
/// the connection's backlog and goes as the guest reads.
const SESSION_TX: usize = 16 * 1024;

/// The most datagram answers waiting for room in the port socket's transmit
/// ring. An answer past it is dropped.
const MAX_OUTBOX: usize = 64;

/// The longest message a DNS length prefix can state, and so the longest
/// answer the nameserver reads.
const MAX_MESSAGE: usize = u16::MAX as usize;

/// The resolver the host itself asks: the first nameserver its `resolv.conf`
/// names, on [`PORT`], or `127.0.0.1` where it names none, as glibc and musl
/// take a file that names none.
pub(super) fn host_upstream() -> SocketAddr {
    let named = std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|contents| first_nameserver(&contents));
    SocketAddr::new(named.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)), PORT)
}

/// The first nameserver `contents`, a `resolv.conf`, names that reads as an
/// address.
///
/// A `nameserver` line is the keyword, whitespace, and the address, and the C
/// libraries read the address as far as the next whitespace. A line that runs
/// the keyword into its value names nothing to them, so it names nothing here.
/// An address with a scope, `fe80::1%eth0`, names an interface by name, which
/// this does not resolve, so the line is passed over for the next.
pub(super) fn first_nameserver(contents: &str) -> Option<IpAddr> {
    contents.lines().find_map(|line| {
        let value = line.strip_prefix("nameserver")?;
        if !value.starts_with([' ', '\t']) {
            return None;
        }
        value.split_whitespace().next()?.parse().ok()
    })
}

/// Where a relayed query came from, and so where its answer goes.
#[derive(Debug, Clone, Copy)]
enum Origin {
    /// A datagram from `guest` to the nameserver at `server`, which the answer
    /// goes back from.
    Datagram {
        guest: IpEndpoint,
        server: IpEndpoint,
    },
    /// A query on the guest TCP connection whose socket this is.
    Session(SocketHandle),
}

/// One query relayed to the upstream, and its socket there.
struct Exchange {
    origin: Origin,
    /// The query as the guest sent it, which goes upstream as it stands and
    /// which a reply the nameserver writes itself repeats the question of.
    query: Vec<u8>,
    /// The name the query asks about, which the answer's addresses are pinned
    /// to.
    name: Arc<str>,
    /// The query's transaction id, which its answer carries.
    id: u16,
    /// The socket connected to the upstream, nonblocking.
    host: OwnedFd,
    /// The stream state of a query relayed over TCP; `None` for a datagram.
    stream: Option<Stream>,
    /// When the query is given up.
    deadline: Instant,
    /// The exchange is over, answered or failed; it is reaped.
    done: bool,
}

/// The upstream side of a query relayed over TCP.
struct Stream {
    /// The query with its length prefix.
    out: Vec<u8>,
    /// How much of `out` the socket has taken.
    written: usize,
    /// The answer as it arrives, its length prefix first.
    inbound: Vec<u8>,
}

/// One guest TCP connection to the nameserver.
struct Session {
    /// The guest-facing smoltcp socket.
    handle: SocketHandle,
    /// The guest endpoint and the nameserver endpoint it connected to, the
    /// connection's identity.
    guest: IpEndpoint,
    server: IpEndpoint,
    /// Answers, each with its length prefix, waiting for room in the socket's
    /// transmit buffer.
    backlog: Vec<u8>,
    /// When a query or an answer last moved.
    last_active: Instant,
    /// The guest has finished sending and nothing is left to answer, so the
    /// socket has been closed from this side.
    closing: bool,
    /// The connection is over; the pump reaps it with its socket.
    dead: bool,
}

/// A datagram answer waiting for room in the port socket's transmit ring.
struct Datagram {
    guest: IpEndpoint,
    server: IpEndpoint,
    message: Vec<u8>,
}

/// The nameserver's state: the queries in flight, the guest TCP connections,
/// and the datagram answers waiting to go.
pub(super) struct Nameserver {
    upstream: SocketAddr,
    /// The interface MTU, which bounds a datagram answer; see
    /// [`deliverable`].
    mtu: usize,
    exchanges: Vec<Exchange>,
    sessions: Vec<Session>,
    outbox: VecDeque<Datagram>,
    /// The names the upstream's answers resolved, by address.
    pins: Pins,
    /// The buffer every read copies through, allocated once.
    scratch: Box<[u8]>,
}

impl Nameserver {
    /// A nameserver that asks `upstream`, for an interface of `mtu`.
    pub(super) fn new(upstream: SocketAddr, mtu: u16) -> Nameserver {
        Nameserver {
            upstream,
            mtu: usize::from(mtu),
            exchanges: Vec::new(),
            sessions: Vec::new(),
            outbox: VecDeque::new(),
            pins: Pins::default(),
            scratch: vec![0; MAX_MESSAGE].into_boxed_slice(),
        }
    }

    /// The names the upstream's answers resolved, by the addresses they gave.
    pub(super) fn pins(&self) -> &Pins {
        &self.pins
    }

    /// Takes a datagram the guest at `guest` sent to the nameserver at
    /// `server`: decides a query by `policy` and relays it or answers it,
    /// reporting it to `reports`; answers a message that is not a query it
    /// relays; and drops anything else.
    pub(super) fn query_datagram(
        &mut self,
        guest: IpEndpoint,
        server: IpEndpoint,
        message: &[u8],
        policy: &Policy,
        reports: &mut Reporter,
        now: Instant,
    ) {
        let origin = Origin::Datagram { guest, server };
        match dns::read_query(message) {
            Ok(query) => self.take(origin, guest, query, policy, reports, now),
            Err(Refusal::Unanswerable) => {}
            Err(Refusal::Answer(rcode)) => {
                if let Some(reply) = dns::refusal(message, rcode) {
                    self.deliver(origin, reply);
                }
            }
        }
    }

    /// Decides `query`, from the guest at `guest` by way of `origin`, by
    /// `policy`: answers it NXDOMAIN where the rules refuse its name, with no
    /// records where name rules withhold the records it asks for, and relays it
    /// otherwise. Reports what became of it to `reports`.
    fn take(
        &mut self,
        origin: Origin,
        guest: IpEndpoint,
        query: Query<'_>,
        policy: &Policy,
        reports: &mut Reporter,
        now: Instant,
    ) {
        let name: Arc<str> = query.name().into();
        let record_type = query.record_type();
        match policy.decide_question(&name) {
            Err(refusal) => {
                self.deliver(origin, dns::blocked(&query, &refusal.to_string()));
                reports
                    .offer(|| NetStackReport::question_refused(guest, &name, record_type, refusal));
            }
            Ok(_) if policy.has_names() && dns::is_service_binding(record_type) => {
                self.deliver(origin, dns::no_records(&query));
                reports.offer(|| NetStackReport::withheld(guest, &name, record_type));
            }
            Ok(admission) => {
                if self.relay(origin, query, Arc::clone(&name), now) {
                    reports.offer(|| NetStackReport::relayed(guest, &name, record_type, admission));
                }
            }
        }
    }

    /// Opens a guest TCP connection to the nameserver at `server`: a listening
    /// socket the interface's processing of the connection's SYN lands on.
    ///
    /// Answers whether one is listening, a retransmitted SYN's included. Where
    /// none is, past [`MAX_SESSIONS`], the interface answers the SYN with a
    /// reset.
    pub(super) fn open_session(
        &mut self,
        sockets: &mut SocketSet<'static>,
        guest: IpEndpoint,
        server: IpEndpoint,
        now: Instant,
    ) -> bool {
        if self
            .sessions
            .iter()
            .any(|session| session.guest == guest && session.server == server && !session.dead)
        {
            return true;
        }
        if self.sessions.iter().filter(|session| !session.dead).count() >= MAX_SESSIONS {
            return false;
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; SESSION_RX]),
            tcp::SocketBuffer::new(vec![0; SESSION_TX]),
        );
        if socket.listen(server).is_err() {
            return false;
        }
        self.sessions.push(Session {
            handle: sockets.add(socket),
            guest,
            server,
            backlog: Vec::new(),
            last_active: now,
            closing: false,
            dead: false,
        });
        true
    }

    /// Relays `query`, already read as one and asking about `name`, from
    /// `origin`: a socket of its own toward the upstream, over the transport
    /// `origin` asked on. Answers whether it went upstream.
    ///
    /// A datagram past [`MAX_EXCHANGES`] is dropped, as a lossy network drops
    /// one, and the guest's resolver asks again. A query on a TCP connection
    /// past it is answered with SERVFAIL instead: its resolver waits on the
    /// connection rather than retrying a lost datagram. So is a query whose
    /// socket cannot be made.
    fn relay(&mut self, origin: Origin, query: Query<'_>, name: Arc<str>, now: Instant) -> bool {
        let stream = matches!(origin, Origin::Session(_));
        let full = self
            .exchanges
            .iter()
            .filter(|exchange| !exchange.done)
            .count()
            >= MAX_EXCHANGES;
        if full && !stream {
            return false;
        }
        let message = query.message();
        let opened = if full {
            Err(Errno::AGAIN)
        } else if stream {
            open_stream(self.upstream)
        } else {
            open_datagram(self.upstream, message)
        };
        let host = match opened {
            Ok(host) => host,
            Err(_) => {
                self.deliver(origin, dns::failure(&query, Rcode::ServerFailure));
                return false;
            }
        };
        let stream = stream.then(|| {
            let mut out = Vec::with_capacity(2 + message.len());
            // The query is at most `dns::MAX_QUERY` bytes, which a prefix holds.
            out.extend_from_slice(
                &u16::try_from(message.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            out.extend_from_slice(message);
            Stream {
                out,
                written: 0,
                inbound: Vec::new(),
            }
        });
        self.exchanges.push(Exchange {
            origin,
            query: message.to_vec(),
            name,
            id: query.id(),
            host,
            stream,
            deadline: now + EXCHANGE_DEADLINE,
            done: false,
        });
        true
    }

    /// How many of the TCP connection `handle`'s queries are in flight
    /// upstream.
    fn in_flight(&self, handle: SocketHandle) -> usize {
        self.exchanges
            .iter()
            .filter(|exchange| {
                !exchange.done && matches!(exchange.origin, Origin::Session(of) if of == handle)
            })
            .count()
    }

    /// Sends `message` toward `origin`: into the outbox for a datagram, which
    /// one past [`MAX_OUTBOX`] is dropped from, or into its TCP connection's
    /// backlog, with its length prefix. A message for a connection that has
    /// ended goes nowhere.
    fn deliver(&mut self, origin: Origin, message: Vec<u8>) {
        match origin {
            Origin::Datagram { guest, server } => {
                if self.outbox.len() < MAX_OUTBOX {
                    self.outbox.push_back(Datagram {
                        guest,
                        server,
                        message,
                    });
                }
            }
            Origin::Session(handle) => {
                let Some(session) = self
                    .sessions
                    .iter_mut()
                    .find(|session| session.handle == handle && !session.dead)
                else {
                    return;
                };
                // A message here is a query's answer or a reply of the
                // nameserver's own, at most `MAX_MESSAGE` bytes either way.
                let length = u16::try_from(message.len()).unwrap_or(u16::MAX);
                session.backlog.extend_from_slice(&length.to_be_bytes());
                session.backlog.extend_from_slice(&message);
            }
        }
    }

    /// The upstream sockets to wait on, with what each waits for: a stream
    /// still sending its query waits to write, and everything else to read.
    pub(super) fn interest(&self) -> impl Iterator<Item = (&OwnedFd, PollFlags)> {
        self.exchanges
            .iter()
            .filter(|exchange| !exchange.done)
            .map(|exchange| {
                let writing = exchange
                    .stream
                    .as_ref()
                    .is_some_and(|stream| stream.written < stream.out.len());
                let interest = if writing {
                    PollFlags::OUT
                } else {
                    PollFlags::IN
                };
                (&exchange.host, interest)
            })
    }

    /// How many upstream sockets [`interest`](Self::interest) can yield.
    pub(super) fn socket_count(&self) -> usize {
        self.exchanges.len()
    }

    /// Moves everything: the guest TCP connections' queries in, decided by
    /// `policy` and reported to `reports`, and their answers out, and every
    /// exchange's query up and answer back. Returns whether anything moved.
    pub(super) fn service(
        &mut self,
        sockets: &mut SocketSet<'static>,
        policy: &Policy,
        reports: &mut Reporter,
        now: Instant,
    ) -> bool {
        let mut progress = self.serve_sessions(sockets, policy, reports, now);
        progress |= self.serve_exchanges();
        // The answers just delivered to sessions go out on this pass rather
        // than waiting on the next.
        progress |= self.flush_sessions(sockets, now);
        progress
    }

    /// Reads each session's complete queries and takes them as a datagram's
    /// are taken.
    fn serve_sessions(
        &mut self,
        sockets: &mut SocketSet<'static>,
        policy: &Policy,
        reports: &mut Reporter,
        now: Instant,
    ) -> bool {
        let mut progress = false;
        let mut index = 0;
        while index < self.sessions.len() {
            let (handle, guest) = (self.sessions[index].handle, self.sessions[index].guest);
            while let Some(query) = self.next_query(index, sockets) {
                progress = true;
                self.sessions[index].last_active = now;
                let origin = Origin::Session(handle);
                match dns::read_query(&query) {
                    Ok(read) => self.take(origin, guest, read, policy, reports, now),
                    // A response, or a fragment of a header, has nothing to
                    // repeat and is passed over, as a datagram's is.
                    Err(Refusal::Unanswerable) => {}
                    Err(Refusal::Answer(rcode)) => {
                        if let Some(reply) = dns::refusal(&query, rcode) {
                            self.deliver(origin, reply);
                        }
                    }
                }
            }
            index += 1;
        }
        progress
    }

    /// The next complete query on session `index`, dequeued, or `None` where
    /// none has arrived whole or the session holds as much as it may.
    ///
    /// A length prefix of zero, or past [`dns::MAX_QUERY`], names no query the
    /// nameserver takes, and the connection is reset.
    fn next_query(&mut self, index: usize, sockets: &mut SocketSet<'static>) -> Option<Vec<u8>> {
        let in_flight = self.in_flight(self.sessions[index].handle);
        let session = &mut self.sessions[index];
        if session.dead
            || session.closing
            || in_flight >= SESSION_IN_FLIGHT
            || session.backlog.len() >= SESSION_BACKLOG
        {
            return None;
        }
        let socket = sockets.get_mut::<tcp::Socket>(session.handle);
        let mut prefix = [0u8; 2];
        if socket.peek_slice(&mut prefix).ok()? < 2 {
            return None;
        }
        let length = usize::from(u16::from_be_bytes(prefix));
        if length == 0 || length > dns::MAX_QUERY {
            socket.abort();
            session.dead = true;
            return None;
        }
        if socket.recv_queue() < 2 + length {
            return None;
        }
        let mut framed = vec![0; 2 + length];
        let read = socket.recv_slice(&mut framed).ok()?;
        debug_assert_eq!(read, framed.len(), "the queue held the whole query");
        framed.drain(..2);
        Some(framed)
    }

    /// Writes each session's backlog into its socket as far as there is room,
    /// and closes a session whose guest has finished sending once every query
    /// it sent is answered and the answers are out.
    fn flush_sessions(&mut self, sockets: &mut SocketSet<'static>, now: Instant) -> bool {
        let mut progress = false;
        for index in 0..self.sessions.len() {
            let in_flight = self.in_flight(self.sessions[index].handle);
            let session = &mut self.sessions[index];
            if session.dead {
                continue;
            }
            let socket = sockets.get_mut::<tcp::Socket>(session.handle);
            if !session.backlog.is_empty()
                && let Ok(sent) = socket.send_slice(&session.backlog)
                && sent > 0
            {
                session.backlog.drain(..sent);
                session.last_active = now;
                progress = true;
            }
            // The guest's FIN has arrived and every query before it has been
            // read: it will ask nothing more. CLOSE-WAIT is the one state that
            // says so, since this side closes only after the guest has.
            // Asking whether the socket may still receive would not do: it may
            // not before its handshake completes either.
            let finished = socket.state() == tcp::State::CloseWait && socket.recv_queue() == 0;
            if finished && !session.closing && in_flight == 0 && session.backlog.is_empty() {
                socket.close();
                session.closing = true;
                progress = true;
            }
        }
        progress
    }

    /// Moves every exchange: a stream's query up, and any answer back.
    fn serve_exchanges(&mut self) -> bool {
        let mut progress = false;
        let mut finished = Vec::new();
        for (index, exchange) in self.exchanges.iter_mut().enumerate() {
            if exchange.done {
                continue;
            }
            let outcome = match &mut exchange.stream {
                None => read_datagram(&exchange.host, exchange.id, &mut self.scratch),
                Some(stream) => {
                    advance_stream(&exchange.host, stream, exchange.id, &mut self.scratch)
                }
            };
            match outcome {
                Outcome::Waiting { moved } => progress |= moved,
                Outcome::Answered(answer) => {
                    progress = true;
                    exchange.done = true;
                    finished.push((index, Some(answer)));
                }
                Outcome::Failed => {
                    progress = true;
                    exchange.done = true;
                    finished.push((index, None));
                }
            }
        }
        for (index, answer) in finished {
            let exchange = &self.exchanges[index];
            let origin = exchange.origin;
            let Ok(query) = dns::read_query(&exchange.query) else {
                continue;
            };
            // Pinned before the answer goes, so the guest's first connection
            // to an address it gives finds the name there.
            if let Some(answer) = &answer {
                for address in dns::answer_addresses(&query, answer) {
                    self.pins.pin(address, &exchange.name);
                }
            }
            let message = match (answer, origin) {
                (Some(answer), Origin::Datagram { server, .. })
                    if answer.len() > deliverable(self.mtu, &server) =>
                {
                    dns::truncated(&query, &answer)
                }
                (Some(answer), _) => answer,
                (None, _) => dns::failure(&query, Rcode::ServerFailure),
            };
            self.deliver(origin, message);
        }
        progress
    }

    /// Sends the datagram answers waiting in the outbox through the port
    /// socket the nameserver's queries arrived on, as far as its transmit ring
    /// has room. Returns whether any went.
    pub(super) fn send_datagrams(&mut self, socket: &mut udp::Socket<'_>) -> bool {
        let mut progress = false;
        while socket.can_send() {
            let Some(datagram) = self.outbox.pop_front() else {
                break;
            };
            let meta = udp::UdpMetadata {
                endpoint: datagram.guest,
                local_address: Some(datagram.server.addr),
                meta: Default::default(),
            };
            if socket.send_slice(&datagram.message, meta).is_err() {
                // The ring had a metadata slot but not the payload bytes. It
                // drains on the next interface poll, so the answer waits.
                self.outbox.push_front(datagram);
                break;
            }
            progress = true;
        }
        progress
    }

    /// Whether answers wait in the outbox, which only the port socket can
    /// send.
    pub(super) fn has_datagrams(&self) -> bool {
        !self.outbox.is_empty()
    }

    /// The time until the nearest exchange is given up or session closed for
    /// idleness, for the pump's poll timeout.
    pub(super) fn next_deadline(&self, now: Instant) -> Option<Duration> {
        let exchanges = self
            .exchanges
            .iter()
            .filter(|exchange| !exchange.done)
            .map(|exchange| exchange.deadline.saturating_duration_since(now));
        let sessions = self
            .sessions
            .iter()
            .filter(|session| !session.dead)
            .map(|session| (session.last_active + SESSION_IDLE).saturating_duration_since(now));
        exchanges.chain(sessions).min()
    }

    /// Gives up the exchanges past their deadline, answering a TCP
    /// connection's with SERVFAIL, and resets the sessions idle past
    /// [`SESSION_IDLE`] or whose socket has ended. Returns whether any socket
    /// was aborted, since its reset then waits on the interface's next
    /// dispatch.
    pub(super) fn enforce_deadlines(
        &mut self,
        sockets: &mut SocketSet<'static>,
        now: Instant,
    ) -> bool {
        let mut failed = Vec::new();
        for exchange in &mut self.exchanges {
            if !exchange.done && now >= exchange.deadline {
                exchange.done = true;
                if matches!(exchange.origin, Origin::Session(_))
                    && let Ok(query) = dns::read_query(&exchange.query)
                {
                    failed.push((exchange.origin, dns::failure(&query, Rcode::ServerFailure)));
                }
            }
        }
        if !failed.is_empty() {
            for (origin, reply) in failed {
                self.deliver(origin, reply);
            }
            // Nothing else would wake the pump to write the replies out.
            self.flush_sessions(sockets, now);
        }
        let mut aborted = false;
        for session in &mut self.sessions {
            if session.dead {
                continue;
            }
            let socket = sockets.get_mut::<tcp::Socket>(session.handle);
            match socket.state() {
                // Closed by both sides, or reset by the guest.
                tcp::State::Closed => session.dead = true,
                // Closed from this side first. The wait guards against a late
                // segment on a path that has none, as a flow's does; see
                // `TcpFlow::leave_time_wait`.
                tcp::State::TimeWait => {
                    socket.abort();
                    session.dead = true;
                }
                _ if now >= session.last_active + SESSION_IDLE => {
                    socket.abort();
                    session.dead = true;
                    aborted = true;
                }
                _ => {}
            }
        }
        aborted
    }

    /// Removes the finished exchanges, and the ended sessions with their
    /// sockets.
    pub(super) fn reap(&mut self, sockets: &mut SocketSet<'static>) {
        self.exchanges.retain(|exchange| !exchange.done);
        self.sessions.retain(|session| {
            if session.dead {
                sockets.remove(session.handle);
            }
            !session.dead
        });
    }
}

/// What a pass over one exchange came to.
enum Outcome {
    /// No answer yet; `moved` says whether any byte went either way.
    Waiting { moved: bool },
    /// The answer, whole.
    Answered(Vec<u8>),
    /// The upstream refused the query, or its connection failed.
    Failed,
}

/// Opens a datagram socket connected to `upstream` and sends it `query`.
fn open_datagram(upstream: SocketAddr, query: &[u8]) -> Result<OwnedFd, Errno> {
    let host = socket_for(
        &upstream,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
    )?;
    rustix::net::connect(&host, &upstream)?;
    rustix::net::send(&host, query, SendFlags::NOSIGNAL)?;
    Ok(host)
}

/// Opens a stream socket toward `upstream`, its connect started and typically
/// not yet complete.
fn open_stream(upstream: SocketAddr) -> Result<OwnedFd, Errno> {
    let host = socket_for(
        &upstream,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
    )?;
    match rustix::net::connect(&host, &upstream) {
        Ok(()) | Err(Errno::INPROGRESS) => Ok(host),
        Err(errno) => Err(errno),
    }
}

/// Reads a datagram exchange's socket for the answer to the query sent under
/// `id`.
///
/// A datagram that is not that answer, one under another id, is passed over:
/// the socket is connected, so it can only be the upstream's, answering
/// something it took for this query. A refusal from the upstream's host
/// (`ECONNREFUSED`, from an ICMP port-unreachable) or any other error fails the
/// exchange.
fn read_datagram(host: &OwnedFd, id: u16, scratch: &mut [u8]) -> Outcome {
    loop {
        match rustix::net::recv(host, &mut *scratch, RecvFlags::empty()) {
            Ok((len, _)) => {
                let answer = &scratch[..len.min(scratch.len())];
                if dns::answers(answer, id) {
                    return Outcome::Answered(answer.to_vec());
                }
            }
            Err(Errno::AGAIN) => return Outcome::Waiting { moved: false },
            Err(Errno::INTR) => {}
            Err(_) => return Outcome::Failed,
        }
    }
}

/// Moves a stream exchange on: the rest of its query up, then as much of its
/// answer as has arrived.
///
/// A send that would block is a connect still in progress or a full buffer,
/// and both are waited on. A connection that fails, ends before the whole
/// answer, or answers under another id fails the exchange.
fn advance_stream(host: &OwnedFd, stream: &mut Stream, id: u16, scratch: &mut [u8]) -> Outcome {
    let mut moved = false;
    while stream.written < stream.out.len() {
        match rustix::net::send(host, &stream.out[stream.written..], SendFlags::NOSIGNAL) {
            Ok(sent) => {
                stream.written += sent;
                moved = true;
            }
            Err(Errno::AGAIN) => return Outcome::Waiting { moved },
            Err(Errno::INTR) => {}
            Err(_) => return Outcome::Failed,
        }
    }
    loop {
        // Read no further than the answer's own end, which its prefix states
        // once two bytes are in.
        let wanted = match stream.inbound.get(..2) {
            Some(prefix) => 2 + usize::from(u16::from_be_bytes([prefix[0], prefix[1]])),
            None => 2,
        };
        if stream.inbound.len() >= wanted && wanted > 2 {
            let answer = stream.inbound.split_off(2);
            return if dns::answers(&answer, id) {
                Outcome::Answered(answer)
            } else {
                Outcome::Failed
            };
        }
        let room = (wanted - stream.inbound.len()).min(scratch.len());
        match rustix::net::recv(host, &mut scratch[..room], RecvFlags::empty()) {
            // An end of stream before the answer is whole, a zero-length
            // answer's included.
            Ok((0, _)) => return Outcome::Failed,
            Ok((len, _)) => {
                stream.inbound.extend_from_slice(&scratch[..len.min(room)]);
                moved = true;
            }
            Err(Errno::AGAIN) => return Outcome::Waiting { moved },
            Err(Errno::INTR) => {}
            Err(_) => return Outcome::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_nameserver_line_that_reads_is_the_upstream() {
        let contents =
            "# generated\nsearch example.com\nnameserver 127.0.0.53\nnameserver 9.9.9.9\n";
        assert_eq!(
            first_nameserver(contents),
            Some(IpAddr::from([127, 0, 0, 53]))
        );
        // Trailing text after the address is the C libraries' to ignore.
        assert_eq!(
            first_nameserver("nameserver\t2001:db8::53  # the resolver\n"),
            Some("2001:db8::53".parse().unwrap()),
        );
        // The keyword run into its value names nothing; a scoped address names
        // an interface this does not look up.
        assert_eq!(
            first_nameserver("nameserver8.8.8.8\nnameserver fe80::1%eth0\nnameserver 192.0.2.53\n"),
            Some(IpAddr::from([192, 0, 2, 53])),
        );
        assert_eq!(first_nameserver("options edns0\n"), None);
        assert_eq!(first_nameserver(""), None);
    }

    /// A connected pair of nonblocking sockets of `kind`: the first stands in
    /// for an exchange's upstream socket, the second plays the upstream.
    fn upstream_pair(kind: SocketType) -> (OwnedFd, OwnedFd) {
        rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            kind,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket pair stands in for the upstream")
    }

    /// A query for `example.com`, type A, under `id`.
    fn query_under(id: u16) -> Vec<u8> {
        let mut message = id.to_be_bytes().to_vec();
        message.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        message.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        message
    }

    /// The answer to `query`: the same message with QR set and `extra` bytes
    /// appended.
    fn answer_to(query: &[u8], extra: usize) -> Vec<u8> {
        let mut answer = query.to_vec();
        answer[2] |= 0x80;
        answer.resize(query.len() + extra, 0);
        answer
    }

    #[test]
    fn a_datagram_exchange_takes_its_answer_and_passes_over_others() {
        let (host, upstream) = upstream_pair(SocketType::DGRAM);
        let query = query_under(0x4242);
        let mut scratch = vec![0; MAX_MESSAGE];
        assert!(matches!(
            read_datagram(&host, 0x4242, &mut scratch),
            Outcome::Waiting { moved: false }
        ));
        rustix::net::send(
            &upstream,
            &answer_to(&query_under(0x4243), 0),
            SendFlags::empty(),
        )
        .unwrap();
        let answer = answer_to(&query, 16);
        rustix::net::send(&upstream, &answer, SendFlags::empty()).unwrap();
        match read_datagram(&host, 0x4242, &mut scratch) {
            Outcome::Answered(got) => assert_eq!(got, answer),
            _ => panic!("the answer under the query's id is taken"),
        }
    }

    #[test]
    fn a_stream_exchange_sends_the_framed_query_and_reads_the_framed_answer() {
        let (host, upstream) = upstream_pair(SocketType::STREAM);
        let query = query_under(7);
        let mut stream = Stream {
            out: [&(query.len() as u16).to_be_bytes()[..], &query].concat(),
            written: 0,
            inbound: Vec::new(),
        };
        let mut scratch = vec![0; MAX_MESSAGE];
        assert!(matches!(
            advance_stream(&host, &mut stream, 7, &mut scratch),
            Outcome::Waiting { moved: true }
        ));
        let mut sent = vec![0; 2 + query.len()];
        let (len, _) = rustix::net::recv(&upstream, &mut sent[..], RecvFlags::empty()).unwrap();
        assert_eq!(&sent[..len], &stream.out[..]);

        // The answer arrives in two pieces, split inside its length prefix.
        let answer = answer_to(&query, 300);
        let framed = [&(answer.len() as u16).to_be_bytes()[..], &answer].concat();
        rustix::net::send(&upstream, &framed[..1], SendFlags::empty()).unwrap();
        assert!(matches!(
            advance_stream(&host, &mut stream, 7, &mut scratch),
            Outcome::Waiting { .. }
        ));
        rustix::net::send(&upstream, &framed[1..], SendFlags::empty()).unwrap();
        match advance_stream(&host, &mut stream, 7, &mut scratch) {
            Outcome::Answered(got) => assert_eq!(got, answer),
            _ => panic!("the whole answer is read"),
        }
    }

    #[test]
    fn a_stream_that_ends_early_fails_the_exchange() {
        for sent in [&[][..], &[0, 40, 1, 2][..], &[0, 0][..]] {
            let (host, upstream) = upstream_pair(SocketType::STREAM);
            let mut stream = Stream {
                out: Vec::new(),
                written: 0,
                inbound: Vec::new(),
            };
            rustix::net::send(&upstream, sent, SendFlags::empty()).unwrap();
            drop(upstream);
            let mut scratch = vec![0; MAX_MESSAGE];
            assert!(
                matches!(
                    advance_stream(&host, &mut stream, 7, &mut scratch),
                    Outcome::Failed
                ),
                "{sent:?}",
            );
        }
    }

    #[test]
    fn an_upstream_that_refuses_the_query_fails_the_exchange() {
        // A loopback port nothing listens on: its refusal comes back as an
        // ICMP port-unreachable, which the connected socket reports.
        let closed = {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a loopback socket");
            socket.local_addr().expect("the socket has an address")
        };
        let host = open_datagram(closed, &query_under(3)).expect("the query is sent");
        let mut scratch = vec![0; MAX_MESSAGE];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match read_datagram(&host, 3, &mut scratch) {
                Outcome::Failed => break,
                Outcome::Waiting { .. } if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => panic!("the refusal fails the exchange"),
            }
        }
    }

    #[test]
    fn a_tcp_query_given_up_is_answered_with_servfail() {
        // A session over a socket that never connected: the reply stays in
        // its backlog, where it can be read.
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64]),
            tcp::SocketBuffer::new(vec![0; 64]),
        ));
        let mut nameserver = Nameserver::new("127.0.0.1:53".parse().unwrap(), 1500);
        nameserver.sessions.push(Session {
            handle,
            guest: IpEndpoint::new(smoltcp::wire::IpAddress::v4(10, 0, 2, 15), 40000),
            server: IpEndpoint::new(smoltcp::wire::IpAddress::v4(10, 0, 2, 3), PORT),
            backlog: Vec::new(),
            last_active: Instant::now(),
            closing: false,
            dead: false,
        });
        let (host, _upstream) = upstream_pair(SocketType::STREAM);
        let query = query_under(11);
        let now = Instant::now();
        nameserver.exchanges.push(Exchange {
            origin: Origin::Session(handle),
            query: query.clone(),
            name: Arc::from("example.com"),
            id: 11,
            host,
            stream: Some(Stream {
                out: Vec::new(),
                written: 0,
                inbound: Vec::new(),
            }),
            deadline: now,
            done: false,
        });
        nameserver.enforce_deadlines(&mut sockets, now);
        let backlog = &nameserver.sessions[0].backlog;
        let length = usize::from(u16::from_be_bytes([backlog[0], backlog[1]]));
        assert_eq!(backlog.len(), 2 + length, "one framed reply");
        assert_eq!(backlog[2..4], query[..2], "under the query's id");
        assert_eq!(backlog[5] & 0x0f, Rcode::ServerFailure as u8);
        assert_eq!(
            nameserver.in_flight(handle),
            0,
            "the query is no longer in flight"
        );
    }

    #[test]
    fn a_datagram_answer_too_long_for_one_packet_is_truncated() {
        let (host, upstream) = upstream_pair(SocketType::DGRAM);
        let mut nameserver = Nameserver::new("127.0.0.1:53".parse().unwrap(), 1500);
        let query = query_under(9);
        let guest = IpEndpoint::new(smoltcp::wire::IpAddress::v4(10, 0, 2, 15), 40000);
        let server = IpEndpoint::new(smoltcp::wire::IpAddress::v4(10, 0, 2, 3), PORT);
        nameserver.exchanges.push(Exchange {
            origin: Origin::Datagram { guest, server },
            query: query.clone(),
            name: Arc::from("example.com"),
            id: 9,
            host,
            stream: None,
            deadline: Instant::now() + EXCHANGE_DEADLINE,
            done: false,
        });
        // One byte past what an IPv4 packet of 1500 carries as a UDP payload.
        let long = answer_to(&query, 1473 - query.len());
        rustix::net::send(&upstream, &long, SendFlags::empty()).unwrap();
        assert!(nameserver.serve_exchanges());
        let sent = nameserver.outbox.pop_front().expect("an answer goes back");
        assert_eq!(sent.message.len(), query.len(), "header and question only");
        assert_eq!(sent.message[2] & 0x02, 0x02, "TC is set");
        assert_eq!(sent.message[..2], query[..2]);
    }
}
