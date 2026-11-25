//! UDP datagram forwarding: guest datagrams relayed over host sockets.
//!
//! UDP has no connection to sniff and terminate the way TCP does, so the
//! stack tracks two tables. One smoltcp socket per guest-addressed
//! destination *port* receives the guest's datagrams: it binds to that
//! port on any local address, and `any_ip` lets it see datagrams sent to
//! the wider world, with each datagram's original destination address
//! recovered from its metadata. One connected host socket per (guest
//! source, original destination) endpoint pair carries the exchange out:
//! the guest's datagrams go to the policy-mapped host target, and replies
//! come back stamped with the original destination as their source so the
//! guest sees them arriving from where it sent.
//!
//! Flows carry no teardown signal, so an idle flow is expired after
//! [`IDLE_TIMEOUT`] and the whole table is capped at [`MAX_FLOWS`]. The pump
//! folds the nearest flow's expiry into its poll timeout, so an idle flow is
//! reaped when its timeout falls due rather than waiting on the next unrelated
//! wakeup. The clock is injected, so expiry is testable.
//!
//! A flow is reported once, carried or refused. A carried flow is reported
//! when it opens. A refused one has no flow to hold it, and the guest repeats
//! a refused datagram as it would any other that went unanswered, so a third
//! table remembers the flows refused lately, at most [`MAX_FLOWS`] of them: a
//! refused flow is reported at its first datagram, and again only once it has
//! sat idle for [`IDLE_TIMEOUT`], as a carried flow would have expired.
//!
//! The port sockets are indexed by port, and each counts the flows using it,
//! so a pass costs what its flows and datagrams do: a flow finds its port
//! socket in logarithmic time, and expiry removes a port socket by its count
//! rather than by searching the flows for one still using it. The guest
//! drives the passes, by sending, so a search of one table per entry of the
//! other would make each datagram cost the product of the two. A guest
//! datagram finds its flow by a search of the flow table, at most
//! [`MAX_FLOWS`] long.
//!
//! Both directions are bounded by one packet. IP fragmentation is not compiled
//! in, so a guest datagram larger than the interface MTU never arrives, and a
//! host reply larger than [`deliverable`] cannot be carried to the guest: the
//! relay drops it rather than hand the interface a packet it would discard at
//! egress with no diagnostic at all. A guest that needs larger datagrams — a
//! resolver advertising a large EDNS buffer is the usual case — needs a larger
//! MTU, which the stack's builder configures.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::net::{RecvFlags, SendFlags, SocketFlags, SocketType};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};

use super::Plan;
use super::nameserver::Nameserver;
use super::pins::Pins;
use super::policy::Transport;
use super::pump::{Carried, Refused, host_target};
use super::report::{FlowRefusal, NetStackReport, Reporter};
use crate::mechanism::netns::socket_for;

/// The most guest UDP flows tracked at once. A datagram that would open a
/// flow past the cap is dropped.
pub(super) const MAX_FLOWS: usize = 256;

/// How long a flow may sit idle before it is expired.
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// The metadata slots each port socket's receive and transmit rings hold:
/// the datagrams that may be queued in one direction at once. The pump drains
/// a ring fully on every service pass, so this need only absorb the burst that
/// one poll cycle delivers, not a backlog.
const PACKET_SLOTS: usize = 8;

/// The largest single datagram the relay copies, which bounds the drain
/// scratch buffer. A guest datagram never exceeds the interface MTU — IP
/// fragmentation is not compiled in — but a host reply is whatever the peer
/// sent, up to the protocol's own `u16` ceiling; the buffer is sized to that so
/// an oversized reply is read whole and judged, rather than truncated.
const MAX_DATAGRAM: usize = 65_535;

/// The IPv4 header the interface emits, which carries no options.
const IPV4_HEADER: usize = 20;

/// The IPv6 header the interface emits, which carries no extension headers.
const IPV6_HEADER: usize = 40;

/// The UDP header.
const UDP_HEADER: usize = 8;

/// The largest reply payload the interface can carry to the guest in one packet
/// over `destination`'s family: the MTU less that family's IP header and the
/// UDP header.
///
/// Neither IPv4 nor IPv6 fragmentation is compiled in, so this is a hard
/// ceiling rather than a preference: smoltcp discards a larger packet at egress
/// and reports nothing, so the relay refuses it here instead.
pub(super) fn deliverable(mtu: usize, destination: &IpEndpoint) -> usize {
    let ip_header = match destination.addr {
        IpAddress::Ipv4(_) => IPV4_HEADER,
        IpAddress::Ipv6(_) => IPV6_HEADER,
    };
    mtu.saturating_sub(ip_header + UDP_HEADER)
}

/// The most replies one service pass drains from a single host flow.
///
/// A host peer can send replies faster than this loop forwards them, and
/// nothing about a socket read makes it stop. Without a cap the pump would stay
/// inside the drain indefinitely, never returning to its `poll` — so a stop
/// would go unanswered and shutting the stack down would block. The cap
/// makes the drain bounded like every sibling in the pump (the tap read batch,
/// the service rounds, the TCP copies): a pass moves at most one transmit ring's
/// worth, and the next poll cycle picks up the rest.
const REPLY_BATCH: usize = PACKET_SLOTS;

/// A smoltcp socket bound to one destination port, receiving the guest's
/// datagrams to any address on it.
struct UdpPort {
    handle: SocketHandle,
    /// How many flows use the port, which keeps its socket while any does.
    flows: usize,
    /// The stack's nameserver answers on the port, which keeps its socket for
    /// the attachment's life: an answer goes out through the socket its query
    /// came in on, and a query in flight is no flow to count.
    kept: bool,
}

/// One guest UDP flow and its host side.
struct UdpFlow {
    /// The guest endpoint that originated the flow.
    guest: IpEndpoint,
    /// The destination the guest addressed; also the spoofed reply source.
    destination: IpEndpoint,
    /// The connected host socket, nonblocking.
    host: OwnedFd,
    /// When the flow last carried a datagram, for idle expiry.
    last_active: Instant,
    /// The host socket reported a hard error (a refused destination, say);
    /// the flow is torn down at the next expiry pass rather than lingering to
    /// the idle timeout.
    dead: bool,
}

/// A UDP flow the stack refused lately, remembered so its refusal is reported
/// once rather than at each datagram.
struct RefusedFlow {
    /// The guest endpoint that sent it.
    guest: IpEndpoint,
    /// The destination the guest addressed.
    destination: IpEndpoint,
    /// When the guest last sent it a datagram.
    last_seen: Instant,
}

/// The UDP forwarding tables: the per-port receive sockets and the
/// per-endpoint-pair host flows.
pub(super) struct UdpTables {
    /// The port sockets, by the port each is bound to.
    ports: BTreeMap<u16, UdpPort>,
    flows: Vec<UdpFlow>,
    /// The flows refused lately, at most [`MAX_FLOWS`] of them.
    refused: Vec<RefusedFlow>,
    /// The interface MTU, which sets the reply ceiling; see [`deliverable`].
    mtu: usize,
    /// The payload bytes each port socket's receive and transmit rings hold,
    /// sized to [`PACKET_SLOTS`] datagrams of one MTU. Fragmentation is not
    /// compiled in, so a datagram never exceeds the MTU; sizing to it rather
    /// than to the `u16` datagram ceiling keeps a 1500-byte MTU's port near
    /// 24 KB instead of the 128 KB a fixed 64 KB ring per direction cost.
    payload_bytes: usize,
    /// The scratch buffer both directions copy a datagram through, allocated
    /// once and reused. Each direction runs up to `SERVICE_ROUNDS` times per
    /// poll wake, so a stack buffer of [`MAX_DATAGRAM`] would have an idle stack
    /// zeroing half a megabyte per loop iteration.
    scratch: Box<[u8]>,
}

impl UdpTables {
    /// Builds empty tables whose port rings are sized to `mtu`. Because a
    /// datagram is at most one MTU, each ring holds [`PACKET_SLOTS`] of them.
    pub(super) fn new(mtu: u16) -> UdpTables {
        UdpTables {
            ports: BTreeMap::new(),
            flows: Vec::new(),
            refused: Vec::new(),
            mtu: usize::from(mtu),
            payload_bytes: PACKET_SLOTS * usize::from(mtu),
            scratch: vec![0u8; MAX_DATAGRAM].into_boxed_slice(),
        }
    }

    /// Ensures a receive socket is bound for `port`, so the interface has
    /// somewhere to deliver the guest's datagrams. Called when a datagram
    /// to `port` is sniffed, before the interface processes it.
    pub(super) fn ensure_port(&mut self, port: u16, sockets: &mut SocketSet<'static>) {
        if self.ports.contains_key(&port) {
            return;
        }
        let socket = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; PACKET_SLOTS],
                vec![0; self.payload_bytes],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; PACKET_SLOTS],
                vec![0; self.payload_bytes],
            ),
        );
        let handle = sockets.add(socket);
        // Bind to the port on any local address, so datagrams to any
        // destination the guest addresses on it are received.
        let socket = sockets.get_mut::<udp::Socket>(handle);
        if socket.bind(IpListenEndpoint { addr: None, port }).is_err() {
            sockets.remove(handle);
            return;
        }
        self.ports.insert(
            port,
            UdpPort {
                handle,
                flows: 0,
                kept: false,
            },
        );
    }

    /// Ensures a receive socket is bound for `port`, as
    /// [`ensure_port`](Self::ensure_port) does, and keeps it for the
    /// attachment's life: the port the stack's nameserver answers on.
    ///
    /// The nameserver has no socket of its own. smoltcp hands a datagram to
    /// the first socket bound to accept it, and the port socket accepts every
    /// address on its port, the nameserver's included, so a second socket on the
    /// nameserver's address would depend on which of the two the socket set
    /// happened to hold first.
    pub(super) fn keep_port(&mut self, port: u16, sockets: &mut SocketSet<'static>) {
        self.ensure_port(port, sockets);
        if let Some(entry) = self.ports.get_mut(&port) {
            entry.kept = true;
        }
    }

    /// The socket bound to `port`, if one is.
    pub(super) fn port_socket(&self, port: u16) -> Option<SocketHandle> {
        self.ports.get(&port).map(|entry| entry.handle)
    }

    /// How many flows the tables hold, which is the most host sockets
    /// [`reply_interest`](Self::reply_interest) yields.
    pub(super) fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// The host sockets to wait on for replies, for the pump's poll set: each
    /// flow whose port socket has room for a reply right now.
    ///
    /// The TCP flows' interest model, applied to UDP. A reply is read only when
    /// it can be queued (see [`host_to_guest`](Self::host_to_guest)), so a host
    /// socket whose port socket is full keeps its reply and stays readable.
    /// Polling it then returns at once on every pass and spins the pump until
    /// the ring drains. The ring drains on the interface's own schedule, which
    /// the pump's timeout already follows, and the service pass after that
    /// drain reads the reply.
    pub(super) fn reply_interest<'a>(
        &'a self,
        sockets: &'a SocketSet<'static>,
    ) -> impl Iterator<Item = &'a OwnedFd> {
        self.flows
            .iter()
            .filter(move |flow| {
                self.ports
                    .get(&flow.destination.port)
                    .is_some_and(|port| sockets.get::<udp::Socket>(port.handle).can_send())
            })
            .map(|flow| &flow.host)
    }

    /// Records that the stack refuses the flow from `guest` to `destination`
    /// as `refused` says, and reports it where this is the flow's first
    /// datagram, or its first since it sat idle for [`IDLE_TIMEOUT`].
    ///
    /// The table holds [`MAX_FLOWS`] refused flows. A refusal past that takes
    /// the place of the one seen longest ago, which is reported again if the
    /// guest sends it more.
    pub(super) fn refuse(
        &mut self,
        guest: IpEndpoint,
        destination: IpEndpoint,
        refused: Refused,
        now: Instant,
        reports: &mut Reporter,
    ) {
        note_refusal(&mut self.refused, guest, destination, refused, now, reports);
    }

    /// Moves both directions of every flow: the guest's datagrams out to
    /// the host, and the host's replies back to the guest. A datagram to the
    /// stack's nameserver goes to `nameserver` instead, which decides its
    /// question by the plan's rules, and a flow is decided by them and by the
    /// names `nameserver` resolved. A flow that opens, or that the stack
    /// refuses, is reported to `reports`, as a question is. Returns whether
    /// anything moved.
    pub(super) fn service(
        &mut self,
        sockets: &mut SocketSet<'static>,
        plan: &Plan,
        nameserver: Option<&mut Nameserver>,
        reports: &mut Reporter,
        now: Instant,
    ) -> bool {
        let mut progress = false;
        progress |= self.guest_to_host(sockets, plan, nameserver, reports, now);
        progress |= self.host_to_guest(sockets, now);
        progress
    }

    /// Drains each port socket's received datagrams to their host sockets,
    /// creating a host flow for a new endpoint pair, or to the stack's
    /// nameserver where one is addressed to it.
    fn guest_to_host(
        &mut self,
        sockets: &mut SocketSet<'static>,
        plan: &Plan,
        mut nameserver: Option<&mut Nameserver>,
        reports: &mut Reporter,
        now: Instant,
    ) -> bool {
        let mut progress = false;
        // The fields touched below — the port table, the flow tables, and the
        // scratch buffer — are borrowed separately, which is why `forward_out`
        // takes the flow table rather than the whole of `self`.
        let UdpTables {
            ports,
            flows,
            refused,
            scratch,
            ..
        } = self;
        for (&port, entry) in ports.iter_mut() {
            loop {
                let socket = sockets.get_mut::<udp::Socket>(entry.handle);
                let (len, meta) = match socket.recv_slice(scratch) {
                    Ok(datagram) => datagram,
                    // The ring is drained; move to the next port.
                    Err(udp::RecvError::Exhausted) => break,
                    // The scratch buffer is MAX_DATAGRAM and a datagram never
                    // exceeds the MTU without fragmentation, so this is
                    // unreachable; drop the (already dequeued) datagram rather
                    // than forward a partial one if the MTU assumption ever
                    // changes.
                    Err(udp::RecvError::Truncated) => continue,
                };
                progress = true;
                // The original destination is the address the datagram was
                // sent to, paired with the port this socket is bound to.
                // smoltcp stamps every datagram a bound socket receives with
                // the local address it arrived on; a None here would be a
                // smoltcp regression, not guest input. Assert in debug so a
                // test catches it, and drop the datagram in release rather
                // than guess its destination.
                let Some(local) = meta.local_address else {
                    debug_assert!(false, "a received UDP datagram carried no local address");
                    continue;
                };
                let destination = IpEndpoint::new(local, port);
                let guest = meta.endpoint;
                // The classifier withholds a datagram from any other source,
                // and this states the rule a second time where a flow opens.
                // The classifier parses a frame on its own, reading past the
                // extension headers smoltcp walks today and no further, so a
                // smoltcp that walked further would deliver datagrams here
                // that it never classified. Its replies would have nowhere to
                // go; see `Plan::is_guest`.
                if !plan.is_guest(guest.addr) {
                    continue;
                }
                // The nameserver's address is on the guest's subnet, which
                // `host_target` refuses, so a datagram to it opens no flow.
                if plan.serves(destination) {
                    if let Some(nameserver) = nameserver.as_deref_mut() {
                        let message = &scratch[..len];
                        nameserver.query_datagram(
                            guest,
                            destination,
                            message,
                            &plan.policy,
                            reports,
                            now,
                        );
                    }
                    continue;
                }
                let pins = nameserver.as_deref().map(Nameserver::pins);
                match forward_out(flows, guest, destination, &scratch[..len], plan, pins, now) {
                    Forwarded::Opened(carried) => {
                        entry.flows += 1;
                        reports.offer(|| {
                            let name = carried.name.as_deref();
                            let admission = carried.admission;
                            NetStackReport::admitted(
                                Transport::Udp,
                                guest,
                                destination,
                                name,
                                admission,
                            )
                        });
                    }
                    Forwarded::Refused(refusal) => {
                        note_refusal(refused, guest, destination, refusal, now, reports);
                    }
                    Forwarded::Carried | Forwarded::Lost => {}
                }
            }
        }
        progress
    }

    /// Reads each host socket's replies and sends them back to the guest,
    /// stamped with the original destination as their source.
    ///
    /// A reply is taken off the host socket only once the guest's ring has a
    /// slot for it, since `recv` consumes the datagram: judging the room
    /// afterwards would discard the one already in hand along with leaving its
    /// successors queued. The interface drains that ring on every poll, so a
    /// deferred reply waits one pass rather than being lost.
    fn host_to_guest(&mut self, sockets: &mut SocketSet<'static>, now: Instant) -> bool {
        let mut progress = false;
        let UdpTables {
            ports,
            flows,
            mtu,
            scratch,
            ..
        } = self;
        for flow in flows.iter_mut() {
            let Some(port) = ports.get(&flow.destination.port) else {
                continue;
            };
            let ceiling = deliverable(*mtu, &flow.destination);
            let socket = sockets.get_mut::<udp::Socket>(port.handle);
            for _ in 0..REPLY_BATCH {
                // Ask before taking: the guest's ring must have a metadata slot
                // free, or the datagram this pass reads would have nowhere to
                // go and be lost with it.
                if !socket.can_send() {
                    break;
                }
                // A zero-length read is a zero-length datagram, not end of
                // stream: a datagram socket has no end of stream, and the drain
                // ends on `EAGAIN` below. Forwarding it keeps the empty
                // datagram — a legitimate keep-alive in several protocols —
                // and, more to the point, keeps the replies queued behind it
                // from waiting on an unrelated wakeup.
                match rustix::net::recv(&flow.host, &mut scratch[..], RecvFlags::empty()) {
                    Ok((len, _)) => {
                        progress = true;
                        flow.last_active = now;
                        if len > ceiling {
                            // Larger than one packet, and the stack does not
                            // fragment: the interface would discard it at
                            // egress without a word. Drop it here, where the
                            // ceiling is documented, and carry on draining so
                            // it does not hold up the replies behind it.
                            continue;
                        }
                        // The reply's source is the address the guest
                        // addressed, so it appears to come from there.
                        let meta = udp::UdpMetadata {
                            endpoint: flow.guest,
                            local_address: Some(flow.destination.addr),
                            meta: Default::default(),
                        };
                        if socket.send_slice(&scratch[..len], meta).is_err() {
                            // The metadata slot checked for above was there but
                            // the ring's payload bytes were not: a large
                            // datagram can exhaust those while slots remain.
                            // The relay accepts that much loss — UDP is lossy,
                            // and the ring drains on the next interface poll.
                            // Leave the replies behind it on the host socket.
                            break;
                        }
                    }
                    Err(Errno::AGAIN | Errno::INTR) => break,
                    Err(_) => {
                        // A hard error (a refused destination surfacing as
                        // ECONNREFUSED, say) means the host side is gone; tear
                        // the flow down at the next expiry rather than hold it
                        // to the idle timeout.
                        flow.dead = true;
                        break;
                    }
                }
            }
        }
        progress
    }

    /// The time until the nearest flow must be reaped, for the pump's poll
    /// timeout, so the loop wakes to expire an idle flow rather than reaping it
    /// lazily on the next unrelated event. A flow already marked dead is due
    /// immediately; `None` when no flows are live.
    pub(super) fn next_deadline(&self, now: Instant) -> Option<Duration> {
        self.flows
            .iter()
            .map(|flow| {
                if flow.dead {
                    Duration::ZERO
                } else {
                    IDLE_TIMEOUT.saturating_sub(now.saturating_duration_since(flow.last_active))
                }
            })
            .min()
    }

    /// Reaps every flow idle past [`IDLE_TIMEOUT`] or marked dead, then removes
    /// any port socket the reaping left with no flows behind it, unless the
    /// port is [kept](Self::keep_port).
    ///
    /// A port socket outlives its flows for exactly as long as one of them is
    /// still using the port, since the interface delivers to the socket rather
    /// than to the flow: dropping it while another flow shares the port would
    /// silently stop that flow's replies.
    pub(super) fn expire(&mut self, sockets: &mut SocketSet<'static>, now: Instant) {
        let UdpTables {
            ports,
            flows,
            refused,
            ..
        } = self;
        refused.retain(|flow| now.saturating_duration_since(flow.last_seen) < IDLE_TIMEOUT);
        flows.retain(|flow| {
            let live = !flow.dead && now.saturating_duration_since(flow.last_active) < IDLE_TIMEOUT;
            if !live && let Some(port) = ports.get_mut(&flow.destination.port) {
                port.flows -= 1;
            }
            live
        });
        ports.retain(|_, port| {
            let used = port.flows > 0 || port.kept;
            if !used {
                sockets.remove(port.handle);
            }
            used
        });
    }
}

/// What became of one guest datagram [`forward_out`] was handed.
#[derive(Debug)]
enum Forwarded {
    /// It went out the flow its endpoint pair already has.
    Carried,
    /// It opened a flow for its endpoint pair, which the caller counts against
    /// the destination's port and reports, admitted as this says.
    Opened(Carried),
    /// The stack refuses its flow, as this says.
    Refused(Refused),
    /// No flow could be opened for it on the host: it is dropped, and the next
    /// datagram of the pair tries again.
    Lost,
}

/// Sends one guest datagram out its host flow, opening a flow in `flows` if the
/// endpoint pair is new and policy admits the destination, by its address and
/// the names `pins` holds at it.
///
/// Takes the flow table rather than the whole of [`UdpTables`] so its caller can
/// hold the shared scratch buffer across the call.
fn forward_out(
    flows: &mut Vec<UdpFlow>,
    guest: IpEndpoint,
    destination: IpEndpoint,
    payload: &[u8],
    plan: &Plan,
    pins: Option<&Pins>,
    now: Instant,
) -> Forwarded {
    if let Some(flow) = flows
        .iter_mut()
        .find(|flow| flow.guest == guest && flow.destination == destination)
    {
        if rustix::net::send(&flow.host, payload, SendFlags::NOSIGNAL).is_ok() {
            flow.last_active = now;
        }
        return Forwarded::Carried;
    }
    // The destination is decided before the budget, so a refused one is
    // reported for its own reason whatever the table holds.
    let carried = match host_target(Transport::Udp, destination, plan, pins) {
        Ok(carried) => carried,
        Err(refused) => return Forwarded::Refused(refused),
    };
    if flows.len() >= MAX_FLOWS {
        return Forwarded::Refused(Refused {
            refusal: FlowRefusal::TooManyFlows,
            name: carried.name,
        });
    }
    let Ok(host) = connect_host(carried.target) else {
        return Forwarded::Lost;
    };
    if rustix::net::send(&host, payload, SendFlags::NOSIGNAL).is_err() {
        return Forwarded::Lost;
    }
    flows.push(UdpFlow {
        guest,
        destination,
        host,
        last_active: now,
        dead: false,
    });
    Forwarded::Opened(carried)
}

/// Records in `refused` that the stack refuses the flow from `guest` to
/// `destination`, as `decision` says, and reports the refusal where the flow is
/// new to the table or sat idle there for [`IDLE_TIMEOUT`]; see
/// [`UdpTables::refuse`].
///
/// Takes the table rather than the whole of [`UdpTables`] for the reason
/// [`forward_out`] does.
fn note_refusal(
    refused: &mut Vec<RefusedFlow>,
    guest: IpEndpoint,
    destination: IpEndpoint,
    decision: Refused,
    now: Instant,
    reports: &mut Reporter,
) {
    let seen = refused
        .iter_mut()
        .find(|flow| flow.guest == guest && flow.destination == destination);
    let news = match seen {
        Some(flow) => {
            let idle = now.saturating_duration_since(flow.last_seen) >= IDLE_TIMEOUT;
            flow.last_seen = now;
            idle
        }
        None => {
            let flow = RefusedFlow {
                guest,
                destination,
                last_seen: now,
            };
            if refused.len() < MAX_FLOWS {
                refused.push(flow);
            } else if let Some(oldest) = refused.iter_mut().min_by_key(|flow| flow.last_seen) {
                *oldest = flow;
            }
            true
        }
    };
    if news {
        reports.offer(|| {
            let name = decision.name.as_deref();
            NetStackReport::refused(Transport::Udp, guest, destination, name, decision.refusal)
        });
    }
}

/// Opens a connected, nonblocking host UDP socket to `target`.
fn connect_host(target: SocketAddr) -> Result<OwnedFd, Errno> {
    let host = socket_for(
        &target,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
    )?;
    rustix::net::connect(&host, &target)?;
    Ok(host)
}

#[cfg(test)]
mod tests {
    use rustix::net::AddressFamily;

    use super::super::report::FlowAdmission;
    use super::*;

    /// A connected socket pair standing in for a flow's host side: the first
    /// end is the flow's, the second plays the host peer.
    fn host_pair() -> (OwnedFd, OwnedFd) {
        rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket pair stands in for the host side")
    }

    /// A flow on port 53 over `host`, the shape the reply drain reads from.
    fn flow_over(host: OwnedFd) -> UdpFlow {
        UdpFlow {
            guest: IpEndpoint::new(IpAddress::v4(10, 0, 2, 15), 40_000),
            destination: IpEndpoint::new(IpAddress::v4(10, 0, 2, 3), 53),
            host,
            last_active: Instant::now(),
            dead: false,
        }
    }

    impl UdpTables {
        /// Adds `flow` as `forward_out` opens one, counted against its port.
        fn adopt(&mut self, flow: UdpFlow) {
            self.ports
                .get_mut(&flow.destination.port)
                .expect("the flow's port has a socket")
                .flows += 1;
            self.flows.push(flow);
        }

        /// The handle of the socket bound to `port`.
        fn port(&self, port: u16) -> SocketHandle {
            self.ports.get(&port).expect("the port has a socket").handle
        }
    }

    /// Whether the flow's host socket has been drained empty.
    fn drained(flow: &UdpFlow) -> bool {
        let mut leftover = [0u8; 8];
        matches!(
            rustix::net::recv(&flow.host, &mut leftover, RecvFlags::empty()),
            Err(Errno::AGAIN)
        )
    }

    #[test]
    fn a_flow_is_expired_only_after_the_idle_timeout() {
        // Driven through `expire` rather than by restating its predicate: a
        // restatement passes whatever the predicate later becomes, which is the
        // one thing a pinned boundary is written to catch.
        let base = Instant::now();
        let at = |elapsed: Duration| {
            let mut tables = UdpTables::new(1500);
            let mut sockets = SocketSet::new(Vec::new());
            tables.ensure_port(53, &mut sockets);
            let (flow_side, _peer) = host_pair();
            let mut flow = flow_over(flow_side);
            flow.last_active = base;
            tables.adopt(flow);
            tables.expire(&mut sockets, base + elapsed);
            (tables.flows.len(), tables.ports.len())
        };

        assert_eq!(
            at(IDLE_TIMEOUT - Duration::from_millis(1)),
            (1, 1),
            "a flow one millisecond short of the timeout is still live",
        );
        // And the port socket goes with the last flow that was using it, since
        // nothing is left for the interface to deliver to it.
        assert_eq!(
            at(IDLE_TIMEOUT),
            (0, 0),
            "a flow idle for the whole timeout is reaped",
        );
    }

    #[test]
    fn a_dead_flow_is_reaped_however_recently_it_was_active() {
        // The `dead` flag is set when the host side answers a hard error, and
        // it is due immediately: holding such a flow to the idle timeout would
        // keep a slot for a peer that is already gone.
        let now = Instant::now();
        let mut tables = UdpTables::new(1500);
        let mut sockets = SocketSet::new(Vec::new());
        tables.ensure_port(53, &mut sockets);
        let (flow_side, _peer) = host_pair();
        let mut flow = flow_over(flow_side);
        flow.last_active = now;
        flow.dead = true;
        tables.adopt(flow);

        tables.expire(&mut sockets, now);
        assert!(tables.flows.is_empty());
        assert!(tables.ports.is_empty());
    }

    #[test]
    fn a_port_socket_outlives_a_reaped_flow_that_shares_it() {
        // The interface delivers to the port socket rather than to the flow, so
        // removing it while another flow is still using the port would silently
        // stop that flow's replies.
        let now = Instant::now();
        let mut tables = UdpTables::new(1500);
        let mut sockets = SocketSet::new(Vec::new());
        tables.ensure_port(53, &mut sockets);

        let (idle_side, _idle_peer) = host_pair();
        let mut idle = flow_over(idle_side);
        idle.last_active = now;
        tables.adopt(idle);

        let (live_side, _live_peer) = host_pair();
        let mut live = flow_over(live_side);
        live.guest = IpEndpoint::new(IpAddress::v4(10, 0, 2, 15), 40_001);
        live.last_active = now + IDLE_TIMEOUT;
        tables.adopt(live);

        tables.expire(&mut sockets, now + IDLE_TIMEOUT);
        assert_eq!(tables.flows.len(), 1, "only the idle flow is reaped");
        assert_eq!(tables.ports.len(), 1, "the port the survivor uses stays");
    }

    #[test]
    fn a_reply_drain_leaves_a_flooding_peer_for_the_next_pass() {
        // A host peer replying faster than the guest reads must not hold the
        // pump inside the drain: without a bound the pump never returns to its
        // poll, the stop goes unserviced, and shutdown blocks. One pass
        // takes what it can and leaves the rest on the host socket.
        let mut tables = UdpTables::new(1500);
        let mut sockets = SocketSet::new(Vec::new());
        tables.ensure_port(53, &mut sockets);

        let (flow_side, peer) = host_pair();
        for _ in 0..REPLY_BATCH * 4 {
            rustix::net::send(&peer, b"reply", SendFlags::NOSIGNAL).unwrap();
        }
        tables.adopt(flow_over(flow_side));

        assert!(tables.host_to_guest(&mut sockets, Instant::now()));
        let flow = &tables.flows[0];
        assert!(!flow.dead, "a bounded drain is not a flow error");
        assert!(
            !drained(flow),
            "the pass drained the whole flood instead of stopping",
        );
    }

    #[test]
    fn an_empty_reply_does_not_end_the_drain() {
        // A datagram socket has no end of stream, so a zero-length read is a
        // zero-length datagram — legitimate in several protocols. Reading it as
        // the end of the drain would discard it and leave every reply queued
        // behind it waiting on an unrelated wakeup.
        let mut tables = UdpTables::new(1500);
        let mut sockets = SocketSet::new(Vec::new());
        tables.ensure_port(53, &mut sockets);

        let (flow_side, peer) = host_pair();
        rustix::net::send(&peer, b"", SendFlags::NOSIGNAL).unwrap();
        rustix::net::send(&peer, b"answer", SendFlags::NOSIGNAL).unwrap();
        tables.adopt(flow_over(flow_side));

        assert!(tables.host_to_guest(&mut sockets, Instant::now()));
        assert!(drained(&tables.flows[0]), "both datagrams were taken");
        let socket = sockets.get_mut::<udp::Socket>(tables.port(53));
        assert_eq!(
            socket.send_queue(),
            b"answer".len(),
            "the reply behind the empty datagram reached the guest",
        );
    }

    #[test]
    fn a_reply_is_left_unread_while_the_guest_ring_is_full() {
        // `recv` consumes the datagram, so a drain that read first and looked
        // for room afterwards would drop the reply it had just taken. Checking
        // first leaves it on the host socket, where the next pass — after the
        // interface has drained the ring — picks it up.
        let mut tables = UdpTables::new(1500);
        let mut sockets = SocketSet::new(Vec::new());
        tables.ensure_port(53, &mut sockets);
        let (flow_side, peer) = host_pair();
        let flow = flow_over(flow_side);
        {
            let socket = sockets.get_mut::<udp::Socket>(tables.port(53));
            for _ in 0..PACKET_SLOTS {
                let meta = udp::UdpMetadata {
                    endpoint: flow.guest,
                    local_address: Some(flow.destination.addr),
                    meta: Default::default(),
                };
                socket
                    .send_slice(b"queued", meta)
                    .expect("the ring holds one datagram per slot");
            }
            assert!(!socket.can_send(), "every metadata slot is taken");
        }
        rustix::net::send(&peer, b"answer", SendFlags::NOSIGNAL).unwrap();
        let before = flow.last_active;
        tables.adopt(flow);

        assert!(
            !tables.host_to_guest(&mut sockets, Instant::now()),
            "a pass that can deliver nothing moves nothing",
        );
        assert_eq!(
            tables.flows[0].last_active, before,
            "an untouched flow is not refreshed",
        );
        assert!(
            !drained(&tables.flows[0]),
            "the reply is still on the host socket",
        );
    }

    #[test]
    fn a_flow_is_waited_on_only_while_its_port_can_take_a_reply() {
        // A reply that cannot be queued stays on the host socket, which then
        // stays readable; waiting on it would return at once on every pass.
        let mut tables = UdpTables::new(1500);
        let mut sockets = SocketSet::new(Vec::new());
        tables.ensure_port(53, &mut sockets);
        let (flow_side, _peer) = host_pair();
        let flow = flow_over(flow_side);
        let meta = udp::UdpMetadata {
            endpoint: flow.guest,
            local_address: Some(flow.destination.addr),
            meta: Default::default(),
        };
        tables.adopt(flow);
        assert_eq!(tables.reply_interest(&sockets).count(), 1);

        let socket = sockets.get_mut::<udp::Socket>(tables.port(53));
        for _ in 0..PACKET_SLOTS {
            socket
                .send_slice(b"queued", meta)
                .expect("the ring holds one datagram per slot");
        }
        assert_eq!(
            tables.reply_interest(&sockets).count(),
            0,
            "a flow whose port is full is still waited on",
        );
    }

    #[test]
    fn a_reply_past_the_ceiling_is_dropped_where_it_can_be_explained() {
        // Handing the interface a packet larger than the MTU has it discarded
        // at egress with no diagnostic, and the drain would carry on believing
        // it delivered. Dropping it here keeps the behaviour documented and
        // lets the replies behind it through.
        let mut tables = UdpTables::new(1500);
        let mut sockets = SocketSet::new(Vec::new());
        tables.ensure_port(53, &mut sockets);

        let (flow_side, peer) = host_pair();
        let oversized =
            vec![0u8; deliverable(1500, &IpEndpoint::new(IpAddress::v4(10, 0, 2, 3), 53)) + 1];
        rustix::net::send(&peer, &oversized, SendFlags::NOSIGNAL).unwrap();
        rustix::net::send(&peer, b"answer", SendFlags::NOSIGNAL).unwrap();
        tables.adopt(flow_over(flow_side));

        assert!(tables.host_to_guest(&mut sockets, Instant::now()));
        assert!(drained(&tables.flows[0]), "both datagrams were taken");
        let socket = sockets.get_mut::<udp::Socket>(tables.port(53));
        assert_eq!(
            socket.send_queue(),
            b"answer".len(),
            "only the deliverable reply was queued",
        );
    }

    #[test]
    fn the_reply_ceiling_leaves_room_for_each_familys_headers() {
        // The ceiling is what fits in one packet, so it has to account for the
        // family's IP header as well as UDP's own.
        let v4 = IpEndpoint::new(IpAddress::v4(10, 0, 2, 3), 53);
        let v6 = IpEndpoint::new(IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 3), 53);
        assert_eq!(deliverable(1500, &v4), 1500 - 20 - 8);
        assert_eq!(deliverable(1500, &v6), 1500 - 40 - 8);
        // An MTU below a bare header pair yields no room at all rather than
        // wrapping; the builder's floor keeps this out of reach in practice.
        assert_eq!(deliverable(16, &v6), 0);
    }

    /// An IPv4 endpoint.
    fn endpoint(a: u8, b: u8, c: u8, d: u8, port: u16) -> IpEndpoint {
        IpEndpoint::new(IpAddress::v4(a, b, c, d), port)
    }

    /// The guest's endpoint on `port`.
    fn guest(port: u16) -> IpEndpoint {
        endpoint(10, 0, 2, 15, port)
    }

    /// Every report queued so far.
    fn reported(reports: &crate::reports::Reports<NetStackReport>) -> Vec<NetStackReport> {
        std::iter::from_fn(|| reports.try_recv().ok()).collect()
    }

    /// A report that the flow from the guest's `port` to `destination` is
    /// refused as the gateway's unmapped port.
    fn unmapped(port: u16, destination: IpEndpoint) -> NetStackReport {
        NetStackReport::refused(
            Transport::Udp,
            guest(port),
            destination,
            None,
            FlowRefusal::GatewayUnmapped,
        )
    }

    /// The refusal of the gateway's unmapped port, to an address no name was
    /// resolved to.
    fn unnamed() -> Refused {
        Refused {
            refusal: FlowRefusal::GatewayUnmapped,
            name: None,
        }
    }

    #[test]
    fn a_refused_flow_is_reported_again_only_once_it_sat_idle() {
        let mut tables = UdpTables::new(1500);
        let (mut reporter, reports) = Reporter::new();
        let destination = endpoint(10, 0, 2, 2, 9);
        let start = Instant::now();
        let refuse = |tables: &mut UdpTables, reporter: &mut Reporter, at| {
            tables.refuse(guest(40_000), destination, unnamed(), at, reporter);
        };

        // Datagrams closer together than the idle timeout keep the flow, so
        // the refusal is reported once, however long they go on.
        for step in 0..4u32 {
            refuse(&mut tables, &mut reporter, start + IDLE_TIMEOUT / 2 * step);
        }
        assert_eq!(reported(&reports), [unmapped(40_000, destination)]);

        // Past the idle timeout since the last, the flow is a new one.
        let resumed = start + IDLE_TIMEOUT / 2 * 3 + IDLE_TIMEOUT;
        refuse(&mut tables, &mut reporter, resumed);
        assert_eq!(reported(&reports), [unmapped(40_000, destination)]);

        // Expiry forgets a refused flow idle as long, as it would a carried one.
        let sockets = &mut SocketSet::new(Vec::new());
        tables.expire(sockets, resumed + IDLE_TIMEOUT);
        assert!(tables.refused.is_empty());
    }

    #[test]
    fn the_refused_table_gives_up_the_flow_seen_longest_ago() {
        let mut tables = UdpTables::new(1500);
        let (mut reporter, reports) = Reporter::new();
        let destination = endpoint(10, 0, 2, 2, 9);
        let start = Instant::now();
        let first_port = 40_000;
        let ports = (first_port..).take(MAX_FLOWS + 1);
        for (offset, port) in ports.clone().enumerate() {
            let at = start + Duration::from_millis(u64::try_from(offset).unwrap());
            tables.refuse(guest(port), destination, unnamed(), at, &mut reporter);
        }
        assert_eq!(tables.refused.len(), MAX_FLOWS);
        assert_eq!(reported(&reports).len(), MAX_FLOWS + 1);

        // The first flow gave its place to the last, so it is news again; the
        // second is still held.
        let later = start + Duration::from_secs(1);
        for port in [first_port + 1, first_port] {
            tables.refuse(guest(port), destination, unnamed(), later, &mut reporter);
        }
        assert_eq!(reported(&reports), [unmapped(first_port, destination)]);
    }

    #[test]
    fn a_flow_past_the_budget_is_refused_for_it() {
        let peer = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a host socket binds");
        let port = peer.local_addr().expect("an address").port();
        let plan = super::super::NetStack::builder()
            .host_loopback_port(port)
            .build()
            .expect("a valid configuration")
            .plan;
        let gateway = endpoint(10, 0, 2, 2, port);
        let now = Instant::now();
        let mut flows = Vec::new();

        let first_port = 20_000;
        for guest_port in (first_port..).take(MAX_FLOWS) {
            let forwarded = forward_out(
                &mut flows,
                guest(guest_port),
                gateway,
                b"x",
                &plan,
                None,
                now,
            );
            assert!(
                matches!(
                    forwarded,
                    Forwarded::Opened(Carried {
                        admission: FlowAdmission::HostLoopback,
                        ..
                    })
                ),
                "{forwarded:?}"
            );
        }
        let again = forward_out(
            &mut flows,
            guest(first_port),
            gateway,
            b"x",
            &plan,
            None,
            now,
        );
        assert!(matches!(again, Forwarded::Carried), "{again:?}");

        // One past the budget is refused for it, and a destination refused for
        // a reason of its own is refused for that reason, budget or none.
        let past = forward_out(&mut flows, guest(30_000), gateway, b"x", &plan, None, now);
        assert!(
            matches!(
                past,
                Forwarded::Refused(Refused {
                    refusal: FlowRefusal::TooManyFlows,
                    ..
                })
            ),
            "{past:?}"
        );
        let unmapped = endpoint(10, 0, 2, 2, 9);
        let refused = forward_out(&mut flows, guest(30_000), unmapped, b"x", &plan, None, now);
        assert!(
            matches!(
                refused,
                Forwarded::Refused(Refused {
                    refusal: FlowRefusal::GatewayUnmapped,
                    ..
                })
            ),
            "{refused:?}"
        );
    }
}
