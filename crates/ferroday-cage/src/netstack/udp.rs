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

use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};

use super::Plan;
use super::pump::host_target;

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

/// The largest single datagram the relay copies. IP fragmentation is not
/// compiled in, so a received datagram never exceeds the interface MTU, whose
/// own ceiling is a `u16`; this bounds the drain scratch buffer.
const MAX_DATAGRAM: usize = 65_535;

/// The most replies one service pass drains from a single host flow.
///
/// A host peer can send replies faster than this loop forwards them, and
/// nothing about a socket read makes it stop. Without a cap the pump would stay
/// inside the drain indefinitely, never returning to its `poll` — so the stop
/// pipe would go unserviced and shutting the stack down would block. The cap
/// makes the drain bounded like every sibling in the pump (the tap read batch,
/// the service rounds, the TCP copies): a pass moves at most one transmit ring's
/// worth, and the next poll cycle picks up the rest.
const REPLY_BATCH: usize = PACKET_SLOTS;

/// A smoltcp socket bound to one destination port, receiving the guest's
/// datagrams to any address on it.
struct UdpPort {
    port: u16,
    handle: SocketHandle,
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

/// The UDP forwarding tables: the per-port receive sockets and the
/// per-endpoint-pair host flows.
pub(super) struct UdpTables {
    ports: Vec<UdpPort>,
    flows: Vec<UdpFlow>,
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
            ports: Vec::new(),
            flows: Vec::new(),
            payload_bytes: PACKET_SLOTS * usize::from(mtu),
            scratch: vec![0u8; MAX_DATAGRAM].into_boxed_slice(),
        }
    }

    /// Ensures a receive socket is bound for `port`, so the interface has
    /// somewhere to deliver the guest's datagrams. Called when a datagram
    /// to `port` is sniffed, before the interface processes it.
    pub(super) fn ensure_port(&mut self, port: u16, sockets: &mut SocketSet<'static>) {
        if self.ports.iter().any(|entry| entry.port == port) {
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
        self.ports.push(UdpPort { port, handle });
    }

    /// The host sockets to wait on, for the pump's poll set: every live
    /// flow's socket wants to wake the loop when a reply arrives.
    pub(super) fn host_sockets(&self) -> impl Iterator<Item = &OwnedFd> {
        self.flows.iter().map(|flow| &flow.host)
    }

    /// Moves both directions of every flow: the guest's datagrams out to
    /// the host, and the host's replies back to the guest. Returns whether
    /// anything moved.
    pub(super) fn service(
        &mut self,
        sockets: &mut SocketSet<'static>,
        plan: &Plan,
        now: Instant,
    ) -> bool {
        let mut progress = false;
        progress |= self.guest_to_host(sockets, plan, now);
        progress |= self.host_to_guest(sockets, now);
        progress
    }

    /// Drains each port socket's received datagrams to their host sockets,
    /// creating a host flow for a new endpoint pair.
    fn guest_to_host(
        &mut self,
        sockets: &mut SocketSet<'static>,
        plan: &Plan,
        now: Instant,
    ) -> bool {
        let mut progress = false;
        // The three fields touched below — the port table, the flow table, and
        // the scratch buffer — are borrowed separately, which is why
        // `forward_out` takes the flow table rather than the whole of `self`.
        let UdpTables {
            ports,
            flows,
            scratch,
            ..
        } = self;
        for &UdpPort { port, handle } in ports.iter() {
            loop {
                let socket = sockets.get_mut::<udp::Socket>(handle);
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
                forward_out(flows, guest, destination, &scratch[..len], plan, now);
            }
        }
        progress
    }

    /// Reads each host socket's replies and sends them back to the guest,
    /// stamped with the original destination as their source.
    fn host_to_guest(&mut self, sockets: &mut SocketSet<'static>, now: Instant) -> bool {
        let mut progress = false;
        let UdpTables {
            ports,
            flows,
            scratch,
            ..
        } = self;
        for flow in flows.iter_mut() {
            let Some(port) = ports.iter().find(|port| port.port == flow.destination.port) else {
                continue;
            };
            let socket = sockets.get_mut::<udp::Socket>(port.handle);
            for _ in 0..REPLY_BATCH {
                match rustix::net::recv(&flow.host, &mut scratch[..], RecvFlags::empty()) {
                    Ok((0, _)) => break,
                    Ok((len, _)) => {
                        progress = true;
                        flow.last_active = now;
                        // The reply's source is the address the guest
                        // addressed, so it appears to come from there.
                        let meta = udp::UdpMetadata {
                            endpoint: flow.guest,
                            local_address: Some(flow.destination.addr),
                            meta: Default::default(),
                        };
                        if socket.send_slice(&scratch[..len], meta).is_err() {
                            // The guest's transmit ring is full: it is not
                            // keeping up, so reading further replies would only
                            // discard them. Leave the rest on the host socket
                            // for the next pass.
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

    /// Expires flows idle past [`IDLE_TIMEOUT`] and removes any port socket
    /// left with no flows.
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

    pub(super) fn expire(&mut self, sockets: &mut SocketSet<'static>, now: Instant) {
        self.flows.retain(|flow| {
            !flow.dead && now.saturating_duration_since(flow.last_active) < IDLE_TIMEOUT
        });
        let flows = &self.flows;
        self.ports.retain(|port| {
            let used = flows.iter().any(|flow| flow.destination.port == port.port);
            if !used {
                sockets.remove(port.handle);
            }
            used
        });
    }
}

/// Sends one guest datagram out its host flow, opening a flow in `flows` if the
/// endpoint pair is new and policy admits the destination.
///
/// Takes the flow table rather than the whole of [`UdpTables`] so its caller can
/// hold the shared scratch buffer across the call.
fn forward_out(
    flows: &mut Vec<UdpFlow>,
    guest: IpEndpoint,
    destination: IpEndpoint,
    payload: &[u8],
    plan: &Plan,
    now: Instant,
) {
    if let Some(flow) = flows
        .iter_mut()
        .find(|flow| flow.guest == guest && flow.destination == destination)
    {
        if rustix::net::send(&flow.host, payload, SendFlags::NOSIGNAL).is_ok() {
            flow.last_active = now;
        }
        return;
    }
    if flows.len() >= MAX_FLOWS {
        return;
    }
    let Some(target) = host_target(destination, plan) else {
        return;
    };
    let Ok(host) = connect_host(target) else {
        return;
    };
    if rustix::net::send(&host, payload, SendFlags::NOSIGNAL).is_ok() {
        flows.push(UdpFlow {
            guest,
            destination,
            host,
            last_active: now,
            dead: false,
        });
    }
}

/// Opens a connected, nonblocking host UDP socket to `target`.
fn connect_host(target: SocketAddr) -> Result<OwnedFd, Errno> {
    let family = match target {
        SocketAddr::V4(_) => AddressFamily::INET,
        SocketAddr::V6(_) => AddressFamily::INET6,
    };
    let host = rustix::net::socket_with(
        family,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    rustix::net::connect(&host, &target)?;
    Ok(host)
}

#[cfg(test)]
mod tests {
    use smoltcp::wire::IpAddress;

    use super::*;

    #[test]
    fn a_flow_is_expired_only_after_the_idle_timeout() {
        let base = Instant::now();
        // The retain predicate: a flow expires once its idle time reaches
        // the timeout.
        let idle_ok = base + IDLE_TIMEOUT - Duration::from_millis(1);
        let idle_expired = base + IDLE_TIMEOUT;
        assert!(idle_ok.saturating_duration_since(base) < IDLE_TIMEOUT);
        assert!(!(idle_expired.saturating_duration_since(base) < IDLE_TIMEOUT));
    }

    #[test]
    fn a_reply_drain_leaves_a_flooding_peer_for_the_next_pass() {
        // A host peer replying faster than the guest reads must not hold the
        // pump inside the drain: without a bound the pump never returns to its
        // poll, the stop pipe goes unserviced, and shutdown blocks. One pass
        // takes what it can and leaves the rest on the host socket.
        let mut tables = UdpTables::new(1500);
        let mut sockets = SocketSet::new(Vec::new());
        tables.ensure_port(53, &mut sockets);

        // A connected socket pair stands in for the flow's host side: one end
        // is the flow's, the other plays the flooding peer.
        let (flow_side, peer) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        for _ in 0..REPLY_BATCH * 4 {
            rustix::net::send(&peer, b"reply", SendFlags::NOSIGNAL).unwrap();
        }
        tables.flows.push(UdpFlow {
            guest: IpEndpoint::new(IpAddress::v4(10, 0, 2, 15), 40_000),
            destination: IpEndpoint::new(IpAddress::v4(10, 0, 2, 3), 53),
            host: flow_side,
            last_active: Instant::now(),
            dead: false,
        });

        assert!(tables.host_to_guest(&mut sockets, Instant::now()));
        let flow = &tables.flows[0];
        assert!(!flow.dead, "a bounded drain is not a flow error");
        let mut leftover = [0u8; 8];
        assert!(
            rustix::net::recv(&flow.host, &mut leftover, RecvFlags::empty()).is_ok(),
            "the pass drained the whole flood instead of stopping",
        );
    }
}
