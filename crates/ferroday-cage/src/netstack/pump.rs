//! The pump: the event loop that serves one attachment.
//!
//! One thread owns everything: the tap descriptor, the smoltcp interface
//! that terminates the guest's flows, and the host sockets those flows are
//! forwarded onto. Each iteration sleeps in a single `poll` over the stop
//! pipe, the tap, and the host sockets that currently want attention, then
//! ingests tap frames, lets the interface process them, and services the
//! flows until nothing moves — bounded, so a busy connection cannot starve
//! the loop.
//!
//! Ingestion classifies every frame before queueing it for the interface
//! ([`sniff`]): a TCP connection attempt admitted by [`host_target`]
//! creates its listening socket and starts its host connect first, so the
//! interface's processing of that same segment finds the listener already
//! in place. A refused or unadmitted attempt creates nothing, and the
//! interface answers it with a reset.
//!
//! The interface owns the gateway addresses, answers ARP, neighbor
//! discovery, and ICMP echo for them itself, and accepts any destination
//! (`any_ip`) so the sniffed listeners see segments addressed to the wider
//! world. `any_ip` covers only what the interface receives, not what it
//! answers for: an address on the guest's own subnet other than the gateway
//! is on-link as far as the guest is concerned, so the guest asks for its
//! hardware address and nothing replies. No segment for such a destination
//! ever reaches the stack, which is why that refusal alone is not a reset —
//! see [`host_target`].

use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use rustix::rand::GetRandomFlags;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp as tcp_socket;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, IpEndpoint};

use super::device::TapDevice;
use super::sniff::{self, Sniff};
use super::tcp::{self, TcpFlow};
use super::udp::UdpTables;
use super::{GATEWAY_MAC, Plan, PumpExit};

/// The most frames ingested from the tap per loop iteration, so servicing
/// and transmission interleave with heavy receive traffic.
const READ_BATCH: usize = 32;

/// The most service-and-poll rounds per iteration: enough to drain the
/// usual request-response exchanges, bounded so a firehose of traffic
/// still returns to `poll` and the other descriptors.
const SERVICE_ROUNDS: usize = 4;

/// Runs the pump until stopped. The tap descriptor's lifetime is the
/// attachment's: it closes when this returns.
pub(super) fn run(tap: OwnedFd, stop: OwnedFd, plan: Plan) -> PumpExit {
    match Engine::new(tap, plan) {
        Ok(mut engine) => engine.run(&stop),
        Err(exit) => exit,
    }
}

/// Who a poll slot belongs to.
#[derive(Clone, Copy)]
enum SlotOwner {
    /// The stop pipe.
    Stop,
    /// The tap descriptor.
    Tap,
    /// A TCP flow's host socket, by index.
    Tcp(usize),
    /// A UDP flow's host socket; a readable slot merely wakes the loop, so
    /// no index is needed.
    Udp,
}

/// The engine state: the device, the interface terminating the guest's
/// flows, and the flow tables.
struct Engine {
    device: TapDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    flows: Vec<TcpFlow>,
    udp: UdpTables,
    plan: Plan,
    /// The monotonic epoch the interface's clock counts from; wall-clock
    /// jumps must not disturb the stack's timers.
    epoch: std::time::Instant,
    /// The reusable tap read buffer, one frame large.
    read_buf: Vec<u8>,
}

impl Engine {
    fn new(tap: OwnedFd, plan: Plan) -> Result<Engine, PumpExit> {
        // The guest is untrusted, so the TCP initial sequence numbers need
        // real entropy.
        let seed = random_seed().map_err(|errno| PumpExit::Failed {
            op: "gathering entropy",
            source: Some(errno.into()),
        })?;
        let mut device = TapDevice::new(tap, plan.mtu);
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(GATEWAY_MAC)));
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut device, Instant::from_micros(0));
        iface.update_ip_addrs(|addrs| {
            if let Some(v4) = &plan.v4 {
                addrs
                    .push(IpCidr::new(v4.gateway.into(), v4.prefix_len))
                    .expect("the interface holds at most two addresses");
            }
            if let Some(v6) = &plan.v6 {
                addrs
                    .push(IpCidr::new(v6.gateway.into(), v6.prefix_len))
                    .expect("the interface holds at most two addresses");
            }
        });
        if let Some(v4) = &plan.v4 {
            iface
                .routes_mut()
                .add_default_ipv4_route(v4.gateway)
                .expect("the route table holds one default route per protocol");
        }
        if let Some(v6) = &plan.v6 {
            iface
                .routes_mut()
                .add_default_ipv6_route(v6.gateway)
                .expect("the route table holds one default route per protocol");
        }
        // The guest addresses the wider world through the gateway; the
        // interface must accept those destinations for the flows' sockets
        // to see them.
        iface.set_any_ip(true);

        let frame = device.frame_capacity();
        Ok(Engine {
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            flows: Vec::new(),
            udp: UdpTables::new(plan.mtu),
            plan,
            epoch: std::time::Instant::now(),
            read_buf: vec![0; frame],
        })
    }

    /// The interface's clock: monotonic time since the engine started.
    fn now(&self) -> Instant {
        Instant::from_micros(i64::try_from(self.epoch.elapsed().as_micros()).unwrap_or(i64::MAX))
    }

    fn run(&mut self, stop: &OwnedFd) -> PumpExit {
        loop {
            // Assemble the poll set: the stop pipe, the tap, and every
            // flow whose host socket has an interest right now. A flow
            // with nothing to wait for is left out entirely — its hangup
            // or error is discovered when it next has one.
            let timeout = self.poll_timeout();
            let mut owners: Vec<SlotOwner> = Vec::with_capacity(2 + self.flows.len());
            let mut fds: Vec<PollFd<'_>> = Vec::with_capacity(2 + self.flows.len());
            owners.push(SlotOwner::Stop);
            fds.push(PollFd::new(stop, PollFlags::IN));
            owners.push(SlotOwner::Tap);
            fds.push(PollFd::new(self.device.tap(), PollFlags::IN));
            for (index, flow) in self.flows.iter().enumerate() {
                let socket = self.sockets.get::<tcp_socket::Socket>(flow.handle);
                let interest = flow.interest(socket);
                // A flow whose host descriptor has been released (both
                // half-closes complete) has nothing left to poll; the guest
                // socket finishes its close on the interface's own timers.
                if let Some(host) = flow.host()
                    && !interest.is_empty()
                {
                    owners.push(SlotOwner::Tcp(index));
                    fds.push(PollFd::new(host, interest));
                }
            }
            // A UDP host socket is only ever waited on for replies to
            // wake the loop; the draining itself is unconditional.
            for host in self.udp.host_sockets() {
                owners.push(SlotOwner::Udp);
                fds.push(PollFd::new(host, PollFlags::IN));
            }

            match rustix::event::poll(&mut fds, timeout.as_ref()) {
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(errno) => {
                    return PumpExit::Failed {
                        op: "waiting for the descriptors",
                        source: Some(errno.into()),
                    };
                }
            }

            // Copy the results out before touching any flow: the poll
            // entries borrow the descriptors they watch.
            let events: Vec<PollFlags> = fds.iter().map(|fd| fd.revents()).collect();
            drop(fds);
            let mut stop_requested = false;
            let mut tap_readable = false;
            for flow in &mut self.flows {
                flow.events = PollFlags::empty();
            }
            for (owner, revents) in owners.iter().zip(events) {
                match owner {
                    SlotOwner::Stop => stop_requested = !revents.is_empty(),
                    SlotOwner::Tap => tap_readable = !revents.is_empty(),
                    SlotOwner::Tcp(index) => self.flows[*index].events = revents,
                    // UDP draining is unconditional, so its wakeups need no
                    // per-flow bookkeeping.
                    SlotOwner::Udp => {}
                }
            }
            if stop_requested {
                return PumpExit::Clean;
            }

            if tap_readable && let Err(exit) = self.ingest_tap() {
                return exit;
            }

            // Let the interface process what arrived, then alternate
            // servicing and interface polls until nothing moves.
            self.iface
                .poll(self.now(), &mut self.device, &mut self.sockets);
            for _ in 0..SERVICE_ROUNDS {
                if !self.service() {
                    break;
                }
                self.iface
                    .poll(self.now(), &mut self.device, &mut self.sockets);
            }

            self.reap();
        }
    }

    /// How long the next poll may sleep: bounded by the interface's own
    /// timers, the nearest TCP establish deadline, and the nearest UDP idle
    /// expiry.
    ///
    /// The interface's `poll_delay` already accounts for the TCP sockets'
    /// keep-alive and timeout timers, so an idle established flow's liveness
    /// checks wake the loop through that term; the UDP flows are a separate
    /// table the interface does not know about, so their idle expiry is folded
    /// in explicitly here rather than reaped only on the next unrelated wakeup.
    fn poll_timeout(&mut self) -> Option<Timespec> {
        let now = self.now();
        let mut limit: Option<Duration> = self
            .iface
            .poll_delay(now, &self.sockets)
            .map(|delay| Duration::from_micros(delay.total_micros()));
        let now_std = std::time::Instant::now();
        let mut tighten = |remaining: Duration| {
            limit = Some(match limit {
                Some(limit) => limit.min(remaining),
                None => remaining,
            });
        };
        for flow in &self.flows {
            if flow.dead {
                continue;
            }
            let socket = self.sockets.get::<tcp_socket::Socket>(flow.handle);
            if let Some(remaining) = flow.deadline_in(socket, now_std) {
                tighten(remaining);
            }
        }
        if let Some(remaining) = self.udp.next_deadline(now_std) {
            tighten(remaining);
        }
        limit.map(crate::poll::timeout)
    }

    /// Reads a batch of frames off the tap, classifying each ahead of the
    /// interface. A tap that fails to read — the device was deleted out
    /// from under the attachment — ends the pump; the sandbox itself is
    /// not affected.
    fn ingest_tap(&mut self) -> Result<(), PumpExit> {
        for _ in 0..READ_BATCH {
            match self.device.read_frame(&mut self.read_buf) {
                Ok(0) => {
                    return Err(PumpExit::Failed {
                        op: "reading the tap device",
                        source: None,
                    });
                }
                Ok(read) => {
                    // The queued frame is its own buffer, since the interface
                    // consumes it after this batch rather than during it. It
                    // comes from the device's free list, so a steady stream of
                    // traffic circulates a handful of buffers instead of
                    // allocating one per frame.
                    let mut frame = self.device.take_buffer();
                    frame.extend_from_slice(&self.read_buf[..read]);
                    self.consider(&frame);
                    self.device.enqueue(frame);
                }
                Err(Errno::AGAIN) => break,
                Err(Errno::INTR) => continue,
                Err(errno) => {
                    return Err(PumpExit::Failed {
                        op: "reading the tap device",
                        source: Some(errno.into()),
                    });
                }
            }
        }
        Ok(())
    }

    /// Acts on one classified frame before the interface sees it: a TCP
    /// connection attempt or a UDP datagram to an admitted destination gets
    /// the receive socket the interface will deliver to; everything else
    /// passes through untouched.
    fn consider(&mut self, frame: &[u8]) {
        match sniff::classify(frame) {
            Sniff::TcpSyn { src, dst } => self.admit_tcp(src, dst),
            Sniff::Udp { src, dst } => self.admit_udp(src, dst),
            Sniff::Other => {}
        }
    }

    /// Admits a TCP connection attempt: a listening socket on the sniffed
    /// destination and a parallel host connect, so the interface's
    /// processing of the same segment lands on the listener.
    ///
    /// The classifier does not verify checksums, so the host connect is
    /// initiated on a segment the interface has not yet validated. A guest
    /// emitting bad-checksum SYNs to a policy-permitted target thus starts
    /// real outbound connects it never completes. The exposure is bounded:
    /// the destination is still policy-checked by [`host_target`] (no reach
    /// past policy), the flow count by [`MAX_FLOWS`], and each unfinished flow
    /// by the establish deadline.
    ///
    /// [`MAX_FLOWS`]: tcp::MAX_FLOWS
    fn admit_tcp(&mut self, src: IpEndpoint, dst: IpEndpoint) {
        // A retransmitted attempt already has its flow; the interface
        // routes it to the existing socket.
        if self
            .flows
            .iter()
            .any(|flow| flow.guest == src && flow.destination == dst)
        {
            return;
        }
        if self.flows.len() >= tcp::MAX_FLOWS {
            return;
        }
        let Some(target) = host_target(dst, &self.plan) else {
            return;
        };
        let mut socket = tcp_socket::Socket::new(
            tcp_socket::SocketBuffer::new(vec![0; tcp::BUFFER_SIZE]),
            tcp_socket::SocketBuffer::new(vec![0; tcp::BUFFER_SIZE]),
        );
        // Probe an idle guest for liveness and abort the flow if it stops
        // answering: a guest that establishes a flow then vanishes without a
        // FIN or RST would otherwise pin its slot and buffers until the sandbox
        // ends. A live but idle guest answers the keep-alive and is left alone.
        // smoltcp folds these timers into its poll delay, so the pump wakes to
        // enforce them.
        socket.set_keep_alive(Some(tcp::KEEP_ALIVE_INTERVAL.into()));
        socket.set_timeout(Some(tcp::IDLE_TIMEOUT.into()));
        if socket.listen(dst).is_err() {
            return;
        }
        let handle = self.sockets.add(socket);
        match TcpFlow::connect(handle, src, dst, target, std::time::Instant::now()) {
            Ok(flow) => self.flows.push(flow),
            // The host side could not even start (say, IPv6 without an
            // IPv6 host stack). Withdraw the listener; the interface then
            // answers the attempt with a reset.
            Err(_) => {
                self.sockets.remove(handle);
            }
        }
    }

    /// Admits a UDP datagram by binding a receive socket to its destination
    /// port, if policy allows the destination at all. The flow itself is
    /// created lazily when the datagram is drained.
    fn admit_udp(&mut self, _src: IpEndpoint, dst: IpEndpoint) {
        if host_target(dst, &self.plan).is_none() {
            return;
        }
        self.udp.ensure_port(dst.port, &mut self.sockets);
    }

    /// Services every flow once, both protocols. Returns whether anything
    /// moved.
    fn service(&mut self) -> bool {
        let mut progress = false;
        let now = std::time::Instant::now();
        for flow in &mut self.flows {
            let socket = self.sockets.get_mut::<tcp_socket::Socket>(flow.handle);
            progress |= flow.service(socket, now);
        }
        progress |= self.udp.service(&mut self.sockets, &self.plan, now);
        progress
    }

    /// Enforces establish and idle deadlines and removes finished flows
    /// with their sockets.
    fn reap(&mut self) {
        let now = std::time::Instant::now();
        for flow in &mut self.flows {
            let socket = self.sockets.get_mut::<tcp_socket::Socket>(flow.handle);
            flow.enforce_deadline(socket, now);
        }
        let mut index = 0;
        while index < self.flows.len() {
            if self.flows[index].dead {
                let flow = self.flows.swap_remove(index);
                self.sockets.remove(flow.handle);
            } else {
                index += 1;
            }
        }
        self.udp.expire(&mut self.sockets, now);
    }
}

/// Applies the forwarding policy to a guest-addressed destination,
/// returning the host socket address to connect to, or `None` for a
/// destination the stack refuses (the interface answers those with a
/// reset).
///
/// This is an egress NAT: an accepted destination is reached from the host's
/// own network position and source IP, so the sandbox can reach whatever the
/// host can, an SSRF-style egress that is by design.
///
/// The refusals are:
///
/// - Multicast, broadcast, unspecified, loopback, and link-local destinations,
///   in both families. Refusing loopback specifically shields host services
///   bound to `127.0.0.1` or `::1`.
/// - The whole IPv4 `0.0.0.0/8` "this network" block and the IPv6 addresses that
///   embed an IPv4 one — the mapped `::ffff:a.b.c.d` and the deprecated
///   compatible `::a.b.c.d` alike — so an IPv4 refusal cannot be re-expressed in
///   the other family.
/// - The guest's own subnet, which is a private link between the guest and this
///   stack. Forwarding it would send the guest's on-link traffic to the host's
///   view of those addresses instead, colliding with a real LAN wherever the two
///   overlap. This subsumes the subnet's broadcast address.
///
/// Every refusal but the guest's own subnet is answered with a reset: the guest
/// routes those destinations through the gateway, so its segment arrives, finds
/// no listener waiting for it, and the interface resets it. The subnet is
/// different in kind. Those addresses are on-link, so the guest resolves a
/// hardware address before sending anything, and the interface answers ARP and
/// neighbor discovery only for the addresses it owns — the gateway. Nothing
/// replies, and the connection fails when the guest's own address resolution
/// gives up.
///
/// The refusals do not shield a host service bound to a wildcard address
/// (`0.0.0.0` or `::`): that service is reachable through the host's own
/// routable IP, which is an ordinary accepted destination, and RFC 1918 LAN
/// peers are reachable too. A caller that needs to bound egress must confine the
/// destination itself. The gateway address is the one special case: with
/// `host_loopback`, a connection to it maps to the host's loopback, port
/// preserved.
pub(super) fn host_target(dst: IpEndpoint, plan: &Plan) -> Option<SocketAddr> {
    match IpAddr::from(dst.addr) {
        IpAddr::V4(addr) => {
            let v4 = plan.v4.as_ref()?;
            if addr == v4.gateway {
                return plan
                    .host_loopback
                    .then(|| SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, dst.port)));
            }
            let mask = u32::MAX << (32 - u32::from(v4.prefix_len));
            let on_link = u32::from(addr) & mask == u32::from(v4.gateway) & mask;
            if addr.is_unspecified()
                // 0.0.0.0/8: `is_unspecified` covers only 0.0.0.0 itself, and
                // the rest of the block is no more routable.
                || addr.octets()[0] == 0
                || addr.is_multicast()
                || addr.is_broadcast()
                || addr.is_loopback()
                || addr.is_link_local()
                || on_link
            {
                return None;
            }
            Some(SocketAddr::from((addr, dst.port)))
        }
        IpAddr::V6(addr) => {
            let v6 = plan.v6.as_ref()?;
            if addr == v6.gateway {
                return plan
                    .host_loopback
                    .then(|| SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, dst.port)));
            }
            let mask = u128::MAX << (128 - u32::from(v6.prefix_len));
            let on_link = prefix_bits(addr) & mask == prefix_bits(v6.gateway) & mask;
            if addr.is_unspecified()
                || addr.is_multicast()
                || addr.is_loopback()
                || addr.is_unicast_link_local()
                // Both IPv4-in-IPv6 forms: mapped and the deprecated
                // compatible. `to_ipv4` accepts either, where `to_ipv4_mapped`
                // would let `::a.b.c.d` through.
                || addr.to_ipv4().is_some()
                || on_link
            {
                return None;
            }
            Some(SocketAddr::from((addr, dst.port)))
        }
    }
}

/// An IPv6 address as the integer its prefix comparison needs.
fn prefix_bits(addr: std::net::Ipv6Addr) -> u128 {
    u128::from_be_bytes(addr.octets())
}

/// Eight bytes of kernel entropy for the interface's seed.
fn random_seed() -> Result<u64, Errno> {
    let mut bytes = [0u8; 8];
    loop {
        match rustix::rand::getrandom(&mut bytes, GetRandomFlags::empty()) {
            Ok(8) => return Ok(u64::from_ne_bytes(bytes)),
            // A short read only happens under exotic conditions; retry.
            Ok(_) => continue,
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(errno),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use smoltcp::wire::IpAddress;

    use super::super::NetStack;
    use super::*;

    /// The default plan, with or without the loopback mapping.
    fn plan(host_loopback: bool) -> Plan {
        let stack = NetStack::builder()
            .host_loopback(host_loopback)
            .build()
            .expect("the default configuration is valid");
        stack.plan
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> IpEndpoint {
        IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::new(a, b, c, d)), port)
    }

    fn v6(addr: &str, port: u16) -> IpEndpoint {
        IpEndpoint::new(IpAddress::Ipv6(addr.parse::<Ipv6Addr>().unwrap()), port)
    }

    #[test]
    fn ordinary_destinations_pass_through_unchanged() {
        let plan = plan(false);
        assert_eq!(
            host_target(v4(203, 0, 113, 9, 443), &plan),
            Some("203.0.113.9:443".parse().unwrap()),
        );
        assert_eq!(
            host_target(v6("2001:db8::1", 443), &plan),
            Some("[2001:db8::1]:443".parse().unwrap()),
        );
    }

    #[test]
    fn loopback_link_local_and_group_destinations_are_refused() {
        let plan = plan(false);
        for dst in [
            v4(127, 0, 0, 1, 80),
            v4(127, 9, 9, 9, 80),
            v4(169, 254, 1, 1, 80),
            v4(224, 0, 0, 1, 80),
            v4(255, 255, 255, 255, 80),
            v4(0, 0, 0, 0, 80),
            // The rest of 0.0.0.0/8, not just the unspecified address itself.
            v4(0, 1, 2, 3, 80),
            v6("::1", 80),
            v6("fe80::1", 80),
            v6("ff02::1", 80),
            v6("::", 80),
            v6("::ffff:127.0.0.1", 80),
            v6("::ffff:203.0.113.9", 80),
            // The deprecated IPv4-compatible form of the same addresses.
            v6("::127.0.0.1", 80),
            v6("::203.0.113.9", 80),
        ] {
            assert_eq!(host_target(dst, &plan), None, "{dst}");
        }
    }

    #[test]
    fn the_guests_own_subnet_is_refused() {
        // The guest's link is private to the guest and this stack. Forwarding
        // it would reach the host's view of those addresses instead, which
        // collides with a real LAN wherever the default range overlaps one.
        let plan = plan(false);
        for dst in [
            // The guest itself, a neighbour, and the subnet's broadcast.
            v4(10, 0, 2, 15, 80),
            v4(10, 0, 2, 7, 80),
            v4(10, 0, 2, 255, 80),
            v4(10, 0, 2, 0, 80),
            v6("fd00::15", 80),
            v6("fd00::7", 80),
        ] {
            assert_eq!(host_target(dst, &plan), None, "{dst}");
        }
        // A neighbouring subnet is not the guest's own and still forwards.
        assert_eq!(
            host_target(v4(10, 0, 3, 7, 80), &plan),
            Some("10.0.3.7:80".parse().unwrap()),
        );
    }

    #[test]
    fn the_gateway_is_refused_by_default_and_maps_with_host_loopback() {
        let closed = plan(false);
        assert_eq!(host_target(v4(10, 0, 2, 2, 8080), &closed), None);
        assert_eq!(host_target(v6("fd00::2", 8080), &closed), None);

        let open = plan(true);
        assert_eq!(
            host_target(v4(10, 0, 2, 2, 8080), &open),
            Some("127.0.0.1:8080".parse().unwrap()),
        );
        assert_eq!(
            host_target(v6("fd00::2", 8080), &open),
            Some("[::1]:8080".parse().unwrap()),
        );
    }

    #[test]
    fn a_disabled_protocol_admits_nothing() {
        let stack = NetStack::builder()
            .ipv6(false)
            .build()
            .expect("a v4-only configuration is valid");
        assert_eq!(host_target(v6("2001:db8::1", 443), &stack.plan), None);
    }
}
