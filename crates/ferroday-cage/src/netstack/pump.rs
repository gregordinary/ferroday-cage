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
//! world. `any_ip` is a receive rule, and holding it to that is ingestion's
//! second job: smoltcp's own `any_ip` also makes the interface answer
//! address resolution and ICMP echo for every address, since the check both
//! answers run is the same "is this addressed to us" the switch overrides.
//! So an ARP request or an echo request naming an address the interface does
//! not hold is dropped before the interface sees it ([`Engine::holds`]), and
//! two properties follow. An address on the guest's own subnet other than the
//! gateway is on-link as far as the guest is concerned, so the guest asks for
//! its hardware address, nothing replies, and no segment for it ever reaches
//! the stack — which is why that refusal alone is not a reset, see
//! [`host_target`]. And a successful ping inside the guest means the gateway
//! answered, rather than the stack answering in the name of whatever was
//! pinged.
//!
//! Neighbor discovery needs no such rule: smoltcp answers a solicitation only
//! for an address whose solicited-node multicast group the interface has
//! joined, which `any_ip` does not widen.
//!
//! A published port runs the other way. Its host listener sits in the same
//! poll, and each connection it accepts becomes a flow whose guest-facing
//! socket *connects* to the guest, from the gateway address and a port of the
//! stack's choosing, where an outbound flow's socket listens. From there the
//! two kinds are one: the same splice, the same half-closes, and the same
//! deadlines. They differ only in the budget they count against,
//! [`MAX_PUBLISHED_FLOWS`](tcp::MAX_PUBLISHED_FLOWS) rather than
//! [`MAX_FLOWS`](tcp::MAX_FLOWS), so neither kind can crowd out the other.

use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use rustix::net::SocketFlags;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp as tcp_socket;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint};

use super::device::TapDevice;
use super::sniff::{self, Sniff};
use super::tcp::{self, TcpFlow};
use super::udp::UdpTables;
use super::{GATEWAY_MAC, Listener, Plan, PumpExit};

/// The most frames ingested from the tap per loop iteration, so servicing
/// and transmission interleave with heavy receive traffic.
const READ_BATCH: usize = 32;

/// The most service-and-poll rounds per iteration: enough to drain the
/// usual request-response exchanges, bounded so a firehose of traffic
/// still returns to `poll` and the other descriptors.
const SERVICE_ROUNDS: usize = 4;

/// The most connections accepted from one published port per loop iteration,
/// for the reason [`READ_BATCH`] bounds the tap.
const ACCEPT_BATCH: usize = 32;

/// How long a published port's listener sits out of the poll after an accept
/// failed for a reason of the host's, descriptor exhaustion the likely one.
///
/// The connection that failed is still queued, so the listener stays readable,
/// and polling it again at once would spin the pump at full CPU until the host
/// recovers. Sitting it out bounds the retries to a few a second.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(250);

/// The ports a published connection's guest-facing socket connects from: the
/// dynamic range, where no guest service is expected to listen.
const LOCAL_PORTS: std::ops::RangeInclusive<u16> = 49152..=65535;

/// Runs the pump until stopped. The tap descriptor's lifetime is the
/// attachment's: it closes when this returns, and so do the published ports'
/// listeners.
pub(super) fn run(tap: OwnedFd, stop: OwnedFd, plan: Plan, listeners: Vec<Listener>) -> PumpExit {
    match Engine::new(tap, plan, listeners) {
        Ok(mut engine) => engine.run(&stop),
        Err(exit) => exit,
    }
}

/// A published port as the pump serves it.
struct Inbound {
    /// The host listener.
    socket: OwnedFd,
    /// The guest endpoint each accepted connection is carried to.
    guest: IpEndpoint,
    /// The gateway address of the guest's family, which the connection
    /// arrives from.
    local: IpAddress,
    /// When a listener that failed to accept may be polled again.
    retry_at: Option<std::time::Instant>,
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
    /// A published port's listener, by index.
    Listener(usize),
}

/// The engine state: the device, the interface terminating the guest's
/// flows, and the flow tables.
struct Engine {
    device: TapDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    flows: Vec<TcpFlow>,
    udp: UdpTables,
    /// The published ports.
    inbound: Vec<Inbound>,
    /// Where the search for a free local port for the next published
    /// connection starts, so successive connections spread over the range.
    next_local_port: u16,
    plan: Plan,
    /// The monotonic epoch the interface's clock counts from; wall-clock
    /// jumps must not disturb the stack's timers.
    epoch: std::time::Instant,
    /// The reusable tap read buffer, one frame large.
    read_buf: Vec<u8>,
}

impl Engine {
    fn new(tap: OwnedFd, plan: Plan, listeners: Vec<Listener>) -> Result<Engine, PumpExit> {
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

        // The build refused a publication whose family is disabled, so each
        // listener finds its guest address here.
        let inbound = listeners
            .into_iter()
            .filter_map(|listener| {
                let (guest, local) = match listener.bound {
                    SocketAddr::V4(_) => {
                        let v4 = plan.v4.as_ref()?;
                        (IpAddress::from(v4.guest), IpAddress::from(v4.gateway))
                    }
                    SocketAddr::V6(_) => {
                        let v6 = plan.v6.as_ref()?;
                        (IpAddress::from(v6.guest), IpAddress::from(v6.gateway))
                    }
                };
                Some(Inbound {
                    socket: listener.socket,
                    guest: IpEndpoint::new(guest, listener.guest_port),
                    local,
                    retry_at: None,
                })
            })
            .collect();

        let frame = device.frame_capacity();
        Ok(Engine {
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            flows: Vec::new(),
            udp: UdpTables::new(plan.mtu),
            inbound,
            next_local_port: *LOCAL_PORTS.start(),
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
            // A listener whose backoff has run out is polled again, and stops
            // counting toward the timeout: an elapsed backoff left in place
            // would make every poll return at once.
            let now_std = std::time::Instant::now();
            for inbound in &mut self.inbound {
                if inbound.retry_at.is_some_and(|at| at <= now_std) {
                    inbound.retry_at = None;
                }
            }

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
            // A UDP host socket is waited on only for replies, and only while
            // its port socket has room for one: a reply that cannot be queued
            // stays on the host socket, which would otherwise stay readable and
            // return every poll at once. The draining itself is unconditional.
            for host in self.udp.reply_interest(&self.sockets) {
                owners.push(SlotOwner::Udp);
                fds.push(PollFd::new(host, PollFlags::IN));
            }
            // A listener sitting out its backoff is left out, which is what
            // keeps a connection it cannot accept from waking the loop.
            for (index, inbound) in self.inbound.iter().enumerate() {
                if inbound.retry_at.is_none() {
                    owners.push(SlotOwner::Listener(index));
                    fds.push(PollFd::new(&inbound.socket, PollFlags::IN));
                }
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
            let mut accepting = Vec::new();
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
                    SlotOwner::Listener(index) if !revents.is_empty() => accepting.push(*index),
                    SlotOwner::Listener(_) => {}
                }
            }
            if stop_requested {
                return PumpExit::Clean;
            }

            if tap_readable && let Err(exit) = self.ingest_tap() {
                return exit;
            }
            for index in accepting {
                self.accept(index);
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
        for inbound in &self.inbound {
            if let Some(at) = inbound.retry_at {
                tighten(at.saturating_duration_since(now_std));
            }
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
                    // Classified from the read buffer, before a queue buffer is
                    // taken: a frame the interface must not answer is withheld
                    // rather than queued and then regretted.
                    if !self.consider(sniff::classify(&self.read_buf[..read])) {
                        continue;
                    }
                    // The queued frame is its own buffer, since the interface
                    // consumes it after this batch rather than during it. It
                    // comes from the device's free list, so a steady stream of
                    // traffic circulates a handful of buffers instead of
                    // allocating one per frame.
                    let mut frame = self.device.take_buffer();
                    frame.extend_from_slice(&self.read_buf[..read]);
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

    /// Acts on one classified frame before the interface sees it, and reports
    /// whether the interface may have it.
    ///
    /// TCP and UDP from any source but the guest's own address are withheld,
    /// for the reason [`Plan::is_guest`] gives. A TCP connection attempt or a
    /// UDP datagram to an admitted destination gets the receive socket the
    /// interface will deliver to. A request the interface would answer on
    /// behalf of an address it does not hold is withheld — the one thing
    /// `any_ip` would otherwise widen beyond receiving. Everything else passes
    /// through untouched.
    fn consider(&mut self, sniff: Sniff) -> bool {
        match sniff {
            Sniff::TcpSyn { src, .. } | Sniff::Udp { src, .. } if !self.plan.is_guest(src.addr) => {
                return false;
            }
            Sniff::TcpSegment { src } => return self.plan.is_guest(src),
            Sniff::TcpSyn { src, dst } => self.admit_tcp(src, dst),
            Sniff::Udp { src, dst } => self.admit_udp(src, dst),
            Sniff::Resolve { target } => return self.holds(target),
            Sniff::Echo { dst } => return self.holds(dst),
            Sniff::Other => {}
        }
        true
    }

    /// Whether `addr` is an address this interface holds.
    ///
    /// Not [`Interface::has_ip_addr`], which answers `true` for everything
    /// under `any_ip` — that switch is exactly what this question exists to see
    /// past. The interface holds its gateway addresses and nothing else: the
    /// guest's own address is the guest's, and the rest of the guest's subnet
    /// is nobody's, which is what makes it safe to refuse in
    /// [`host_target`].
    fn holds(&self, addr: IpAddress) -> bool {
        match IpAddr::from(addr) {
            IpAddr::V4(addr) => self.plan.v4.as_ref().is_some_and(|v4| v4.gateway == addr),
            IpAddr::V6(addr) => self.plan.v6.as_ref().is_some_and(|v6| v6.gateway == addr),
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
        if self.held(false) >= tcp::MAX_FLOWS {
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

    /// Accepts the connections waiting on one published port, each becoming a
    /// flow toward the guest.
    ///
    /// A connection past [`MAX_PUBLISHED_FLOWS`](tcp::MAX_PUBLISHED_FLOWS), or
    /// one no local port is free for, is accepted and closed at once, which is
    /// how the host side learns it was refused. A connection the peer abandoned before it was
    /// accepted is passed over.
    fn accept(&mut self, index: usize) {
        for _ in 0..ACCEPT_BATCH {
            let accepted = match rustix::net::accept_with(
                &self.inbound[index].socket,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            ) {
                Ok(accepted) => accepted,
                Err(Errno::AGAIN) => return,
                Err(Errno::INTR | Errno::CONNABORTED) => continue,
                Err(_) => {
                    self.inbound[index].retry_at =
                        std::time::Instant::now().checked_add(ACCEPT_BACKOFF);
                    return;
                }
            };
            if self.held(true) >= tcp::MAX_PUBLISHED_FLOWS {
                continue;
            }
            let (guest, local_addr) = (self.inbound[index].guest, self.inbound[index].local);
            let Some(port) = self.free_local_port(guest, local_addr) else {
                continue;
            };
            let local = IpEndpoint::new(local_addr, port);
            let mut socket = tcp_socket::Socket::new(
                tcp_socket::SocketBuffer::new(vec![0; tcp::BUFFER_SIZE]),
                tcp_socket::SocketBuffer::new(vec![0; tcp::BUFFER_SIZE]),
            );
            // The same liveness watch an outbound flow's guest side carries.
            socket.set_keep_alive(Some(tcp::KEEP_ALIVE_INTERVAL.into()));
            socket.set_timeout(Some(tcp::IDLE_TIMEOUT.into()));
            if socket.connect(self.iface.context(), guest, local).is_err() {
                continue;
            }
            let handle = self.sockets.add(socket);
            self.flows.push(TcpFlow::accepted(
                handle,
                guest,
                local,
                accepted,
                std::time::Instant::now(),
            ));
        }
    }

    /// How many flows of one kind are held: those through the published ports,
    /// or those the guest opened.
    fn held(&self, published: bool) -> usize {
        self.flows
            .iter()
            .filter(|flow| flow.published == published)
            .count()
    }

    /// A local port on `local` that no flow toward `guest` is using, searched
    /// from where the last search stopped.
    fn free_local_port(&mut self, guest: IpEndpoint, local: IpAddress) -> Option<u16> {
        let span = usize::from(LOCAL_PORTS.end() - LOCAL_PORTS.start()) + 1;
        for _ in 0..span {
            let port = self.next_local_port;
            self.next_local_port = if port == *LOCAL_PORTS.end() {
                *LOCAL_PORTS.start()
            } else {
                port + 1
            };
            let taken = self.flows.iter().any(|flow| {
                flow.guest == guest && flow.destination == IpEndpoint::new(local, port)
            });
            if !taken {
                return Some(port);
            }
        }
        None
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
///   bound to `127.0.0.1` or `::1`. Link-local covers the IPv4 cloud metadata
///   services at `169.254.169.254`.
/// - AWS's IPv6 instance services, `fd00:ec2::/32`, the metadata service at
///   `fd00:ec2::254` among them; see [`is_aws_instance_service`].
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
/// gives up. That property is [held by ingestion](self), not by the interface:
/// under `any_ip` smoltcp would answer for every on-link address, and a stack
/// that did would be claiming to be each of them and then resetting.
///
/// The refusals do not shield a host service bound to a wildcard address
/// (`0.0.0.0` or `::`): that service is reachable through the host's own
/// routable IP, which is an ordinary accepted destination, and RFC 1918 LAN
/// peers are reachable too, as is a metadata service at any routable address
/// but AWS's. A caller that needs to bound egress must confine the destination
/// itself. The gateway address is the one special case: on a port
/// `host_loopback` or `host_loopback_port` admits, a connection to it maps to
/// the host's loopback, port preserved, and on any other port it is refused.
pub(super) fn host_target(dst: IpEndpoint, plan: &Plan) -> Option<SocketAddr> {
    match IpAddr::from(dst.addr) {
        IpAddr::V4(addr) => {
            let v4 = plan.v4.as_ref()?;
            if addr == v4.gateway {
                return plan
                    .host_loopback
                    .admits(dst.port)
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
                    .admits(dst.port)
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
                || is_aws_instance_service(addr)
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

/// Whether `addr` is in `fd00:ec2::/32`, the block AWS serves its IPv6 instance
/// services from: the metadata service at `fd00:ec2::254`, the DNS resolver at
/// `fd00:ec2::253`, and the time service at `fd00:ec2::123`.
///
/// Their IPv4 counterparts sit in `169.254.0.0/16` and are refused as
/// link-local. These are unique local addresses instead, which the host routes
/// like any other, so nothing about the address marks them as the host's own.
/// The metadata service answers anything on the instance that asks, with the
/// instance role's credentials among what it serves, so reaching it from the
/// guest would hand the guest the host's cloud identity. The whole block is
/// refused, the resolver and the time service with it, as their IPv4
/// counterparts are.
fn is_aws_instance_service(addr: std::net::Ipv6Addr) -> bool {
    matches!(addr.segments(), [0xfd00, 0x0ec2, ..])
}

/// Eight bytes of kernel entropy for the interface's seed.
///
/// A failure fails the attachment: the seed is what the guest-facing TCP
/// sockets draw their initial sequence numbers from, and the guest is not
/// trusted to be unable to predict a weak one.
fn random_seed() -> Result<u64, Errno> {
    let mut bytes = [0u8; 8];
    crate::host::fill_random(&mut bytes)?;
    Ok(u64::from_ne_bytes(bytes))
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
    fn the_cloud_metadata_services_are_refused() {
        // The IPv4 service is link-local; AWS's IPv6 block is a unique local
        // one the host routes, so it is refused by name.
        let plan = plan(false);
        for dst in [
            v4(169, 254, 169, 254, 80),
            v6("fd00:ec2::254", 80),
            v6("fd00:ec2::253", 53),
            v6("fd00:ec2:ffff::1", 443),
        ] {
            assert_eq!(host_target(dst, &plan), None, "{dst}");
        }
        // The block is exactly a /32: its neighbours are ordinary unique local
        // destinations.
        for dst in [v6("fd00:ec3::254", 80), v6("fd00:ec1:ffff::1", 80)] {
            assert_eq!(
                host_target(dst, &plan),
                Some(SocketAddr::from((IpAddr::from(dst.addr), dst.port))),
                "{dst}",
            );
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
    fn a_named_port_maps_alone() {
        // The narrower grant: one host service, not the whole loopback. A
        // neighbouring port of the gateway stays refused.
        let plan = NetStack::builder()
            .host_loopback_port(5432)
            .build()
            .expect("a valid configuration")
            .plan;
        assert_eq!(
            host_target(v4(10, 0, 2, 2, 5432), &plan),
            Some("127.0.0.1:5432".parse().unwrap()),
        );
        assert_eq!(
            host_target(v6("fd00::2", 5432), &plan),
            Some("[::1]:5432".parse().unwrap()),
        );
        assert_eq!(host_target(v4(10, 0, 2, 2, 5433), &plan), None);
        assert_eq!(host_target(v6("fd00::2", 80), &plan), None);
    }

    #[test]
    fn every_port_and_a_named_port_combine() {
        // The two grants are a union, so neither order of the calls narrows
        // what the other granted.
        for plan in [
            NetStack::builder()
                .host_loopback(true)
                .host_loopback_port(5432)
                .build(),
            NetStack::builder()
                .host_loopback_port(5432)
                .host_loopback(true)
                .build(),
        ] {
            let plan = plan.expect("a valid configuration").plan;
            assert_eq!(
                host_target(v4(10, 0, 2, 2, 8080), &plan),
                Some("127.0.0.1:8080".parse().unwrap()),
            );
        }
    }

    #[test]
    fn a_disabled_protocol_admits_nothing() {
        let stack = NetStack::builder()
            .ipv6(false)
            .build()
            .expect("a v4-only configuration is valid");
        assert_eq!(host_target(v6("2001:db8::1", 443), &stack.plan), None);
    }

    // -- The pump driven over a socket pair ----------------------------------
    //
    // A sequenced-packet socket pair stands in for the tap: each write is one
    // frame, as a tap's is. The test holds the guest's end and writes the
    // guest's frames into it, so the policy the pump applies to what arrives
    // there is testable without a tap device or a sandbox.

    use rustix::net::{AddressFamily, SocketType};
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        EthernetFrame, EthernetProtocol, EthernetRepr, IpProtocol, Ipv4Packet, Ipv4Repr,
        Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
    };
    use std::net::{Ipv6Addr as StdIpv6Addr, SocketAddr as StdSocketAddr, TcpListener, UdpSocket};

    use super::super::{GUEST_MAC, Publication, PumpExit, listen};
    use super::sniff::classify;

    /// The guest's own IPv4 address under the default plan.
    const GUEST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    /// The gateway's IPv4 address under the default plan.
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
    /// An address nothing on the guest's link holds: the source a guest
    /// spoofs.
    const STRANGER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    /// Wraps an IP packet in the Ethernet frame the guest would send it in.
    fn ethernet(protocol: EthernetProtocol, packet: &[u8]) -> Vec<u8> {
        let repr = EthernetRepr {
            src_addr: EthernetAddress(GUEST_MAC),
            dst_addr: EthernetAddress(GATEWAY_MAC),
            ethertype: protocol,
        };
        let mut frame = vec![0u8; repr.buffer_len() + packet.len()];
        let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
        repr.emit(&mut ethernet);
        ethernet.payload_mut().copy_from_slice(packet);
        frame
    }

    /// An IPv4 packet carrying `transport`, a segment or datagram already
    /// checksummed for these addresses.
    fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: IpProtocol, transport: &[u8]) -> Vec<u8> {
        let repr = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: protocol,
            payload_len: transport.len(),
            hop_limit: 64,
        };
        let mut packet = vec![0u8; repr.buffer_len() + transport.len()];
        let mut ip = Ipv4Packet::new_unchecked(&mut packet);
        repr.emit(&mut ip, &ChecksumCapabilities::default());
        ip.payload_mut().copy_from_slice(transport);
        ethernet(EthernetProtocol::Ipv4, &packet)
    }

    /// A UDP datagram from `src` to `dst`, checksummed for their addresses.
    fn datagram(src: IpEndpoint, dst: IpEndpoint, payload: &[u8]) -> Vec<u8> {
        let repr = UdpRepr {
            src_port: src.port,
            dst_port: dst.port,
        };
        let mut bytes = vec![0u8; repr.header_len() + payload.len()];
        repr.emit(
            &mut UdpPacket::new_unchecked(&mut bytes),
            &src.addr,
            &dst.addr,
            payload.len(),
            |buffer| buffer.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    /// A UDP datagram in an IPv4 frame.
    fn udp_v4(src: Ipv4Addr, dst: Ipv4Addr, port: u16, payload: &[u8]) -> Vec<u8> {
        let udp = datagram(
            IpEndpoint::new(src.into(), 40_000),
            IpEndpoint::new(dst.into(), port),
            payload,
        );
        ipv4(src, dst, IpProtocol::Udp, &udp)
    }

    /// A connection-opening segment in an IPv4 frame.
    fn syn_v4(src: Ipv4Addr, dst: Ipv4Addr, port: u16) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: 41_000,
            dst_port: port,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(7),
            ack_number: None,
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let mut segment = vec![0u8; repr.buffer_len()];
        repr.emit(
            &mut TcpPacket::new_unchecked(&mut segment),
            &src.into(),
            &dst.into(),
            &ChecksumCapabilities::default(),
        );
        ipv4(src, dst, IpProtocol::Tcp, &segment)
    }

    /// A UDP datagram in an IPv6 frame, behind a hop-by-hop options header
    /// when `hop_by_hop` is set.
    ///
    /// The classifier does not walk extension headers, so a datagram behind
    /// one reaches its port's socket without having been classified.
    fn udp_v6(
        src: StdIpv6Addr,
        dst: StdIpv6Addr,
        port: u16,
        payload: &[u8],
        hop_by_hop: bool,
    ) -> Vec<u8> {
        let udp = datagram(
            IpEndpoint::new(src.into(), 40_000),
            IpEndpoint::new(dst.into(), port),
            payload,
        );
        // Next header UDP, a length of zero (eight bytes in all), and one PadN
        // option filling the rest.
        let options: &[u8] = match hop_by_hop {
            true => &[17, 0, 1, 4, 0, 0, 0, 0],
            false => &[],
        };
        let repr = Ipv6Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: match hop_by_hop {
                true => IpProtocol::HopByHop,
                false => IpProtocol::Udp,
            },
            payload_len: options.len() + udp.len(),
            hop_limit: 64,
        };
        let mut packet = vec![0u8; repr.buffer_len() + options.len() + udp.len()];
        let mut ip = Ipv6Packet::new_unchecked(&mut packet);
        repr.emit(&mut ip);
        let payload = ip.payload_mut();
        payload[..options.len()].copy_from_slice(options);
        payload[options.len()..].copy_from_slice(&udp);
        ethernet(EthernetProtocol::Ipv6, &packet)
    }

    /// One end of a sequenced-packet pair for the engine, as its tap, and the
    /// guest's end for the test.
    fn tap_pair() -> (OwnedFd, OwnedFd) {
        rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("a socket pair stands in for the tap")
    }

    /// An engine over `tap`, for a test that drives it on its own thread.
    fn engine(tap: OwnedFd, plan: Plan, listeners: Vec<Listener>) -> Engine {
        match Engine::new(tap, plan, listeners) {
            Ok(engine) => engine,
            Err(_) => panic!("the engine could not gather entropy"),
        }
    }

    /// A pump running on a thread of its own over a socket pair.
    struct Driven {
        /// The guest's end of the pair.
        guest: OwnedFd,
        /// The stop pipe's write end; dropping it stops the pump.
        stop: Option<OwnedFd>,
        /// The pump's thread.
        pump: Option<std::thread::JoinHandle<PumpExit>>,
        /// The pump thread's id, for its processor time.
        tid: i32,
    }

    impl Driven {
        fn start(plan: Plan, listeners: Vec<Listener>) -> Driven {
            let (tap, guest) = tap_pair();
            let (stop_read, stop_write) =
                rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).expect("a pipe");
            let (tid_send, tid_receive) = std::sync::mpsc::channel();
            let pump = std::thread::spawn(move || {
                let _ = tid_send.send(rustix::thread::gettid().as_raw_nonzero().get());
                run(tap, stop_read, plan, listeners)
            });
            let tid = tid_receive.recv().expect("the pump thread reports its id");
            Driven {
                guest,
                stop: Some(stop_write),
                pump: Some(pump),
                tid,
            }
        }

        /// Sends one frame as the guest.
        fn send(&self, frame: &[u8]) {
            rustix::io::write(&self.guest, frame).expect("the pump's end takes the frame");
        }

        /// The processor time the pump's thread has used, in clock ticks.
        fn ticks(&self) -> u64 {
            let stat = std::fs::read_to_string(format!("/proc/self/task/{}/stat", self.tid))
                .expect("the pump thread's statistics are readable");
            // After the parenthesised name: state is the first field, and the
            // user and system times are the twelfth and thirteenth.
            let fields: Vec<&str> = stat[stat.rfind(')').expect("a name") + 2..]
                .split_whitespace()
                .collect();
            let field = |at: usize| fields[at].parse::<u64>().expect("a tick count");
            field(11) + field(12)
        }

        /// How many ticks the pump's thread uses over `window`.
        fn ticks_over(&self, window: Duration) -> u64 {
            let before = self.ticks();
            std::thread::sleep(window);
            self.ticks() - before
        }
    }

    impl Drop for Driven {
        fn drop(&mut self) {
            drop(self.stop.take());
            if let Some(pump) = self.pump.take() {
                let _ = pump.join();
            }
        }
    }

    /// A pump that sleeps between events uses next to no processor time; one
    /// that spins uses a tick every hundredth of a second it is scheduled.
    /// The window is one second, so a spinning pump shows close to a hundred
    /// and this bound leaves a sleeping one wide margin.
    const IDLE_TICKS: u64 = 20;

    /// A host UDP socket on `address` that answers each datagram it receives
    /// `replies` times, more than the guest's ring holds at once.
    fn replying_peer(address: StdSocketAddr, replies: usize) -> (UdpSocket, u16) {
        let socket = UdpSocket::bind(address).expect("a host socket binds");
        let port = socket.local_addr().expect("an address").port();
        let peer = socket.try_clone().expect("the socket clones");
        std::thread::spawn(move || {
            let mut buffer = [0u8; 1500];
            while let Ok((len, from)) = peer.recv_from(&mut buffer) {
                for _ in 0..replies {
                    let _ = peer.send_to(&buffer[..len], from);
                }
            }
        });
        (socket, port)
    }

    /// The plan with the gateway's `port` mapped onto host loopback.
    fn mapping(port: u16) -> Plan {
        NetStack::builder()
            .host_loopback_port(port)
            .build()
            .expect("a valid configuration")
            .plan
    }

    #[test]
    fn tcp_and_udp_from_another_source_are_withheld() {
        // A reply to an address nothing on the link holds waits on a neighbor
        // that never answers, so neither kind of traffic is carried from one.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a listener binds");
        let port = listener.local_addr().expect("an address").port();
        let (tap, _guest) = tap_pair();
        let mut engine = engine(tap, mapping(port), Vec::new());

        for frame in [
            syn_v4(STRANGER, GATEWAY, port),
            udp_v4(STRANGER, GATEWAY, port, b"spoofed"),
        ] {
            assert!(
                !engine.consider(classify(&frame)),
                "a stranger's frame passed"
            );
        }
        assert!(engine.flows.is_empty(), "a stranger's SYN opened a flow");
        // Every segment is held to the rule, not only the one that opens a
        // connection.
        assert!(!engine.consider(Sniff::TcpSegment {
            src: STRANGER.into()
        }));

        // The guest's own address is carried as before.
        assert!(engine.consider(classify(&syn_v4(GUEST, GATEWAY, port))));
        assert_eq!(engine.flows.len(), 1, "the guest's SYN opened a flow");
        assert!(engine.consider(Sniff::TcpSegment { src: GUEST.into() }));
    }

    #[test]
    fn a_datagram_behind_an_extension_header_from_another_source_opens_no_flow() {
        // The classifier never sees a datagram behind an extension header, so
        // the source rule has to hold where the UDP table opens a flow.
        let Ok(socket) = UdpSocket::bind((StdIpv6Addr::LOCALHOST, 0)) else {
            eprintln!("skipping: the host has no IPv6 loopback");
            return;
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("the timeout is settable");
        let port = socket.local_addr().expect("an address").port();
        let driven = Driven::start(mapping(port), Vec::new());
        let guest: StdIpv6Addr = "fd00::15".parse().unwrap();
        let gateway: StdIpv6Addr = "fd00::2".parse().unwrap();
        let stranger: StdIpv6Addr = "2001:db8::99".parse().unwrap();

        // The guest's own datagram binds the port's socket and opens a flow.
        driven.send(&udp_v6(guest, gateway, port, b"from the guest", false));
        let mut buffer = [0u8; 64];
        let (len, _) = socket
            .recv_from(&mut buffer)
            .expect("the guest's datagram arrives");
        assert_eq!(&buffer[..len], b"from the guest");

        // A stranger's, behind a hop-by-hop header, reaches that socket too.
        driven.send(&udp_v6(stranger, gateway, port, b"from a stranger", true));
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("the timeout is settable");
        match socket.recv_from(&mut buffer) {
            Ok((len, _)) => panic!(
                "a stranger's datagram was carried to the host: {:?}",
                String::from_utf8_lossy(&buffer[..len]),
            ),
            Err(error) => assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "{error}",
            ),
        }
    }

    #[test]
    fn a_reply_the_guest_cannot_take_yet_does_not_spin_the_pump() {
        // The stack has not learned the guest's hardware address, since the
        // guest never asked for the gateway's, so replies queue in the port's
        // ring until the ring is full. The rest stay on the host socket, which
        // stays readable; polling it regardless would return at once forever.
        let (_peer, port) = replying_peer((Ipv4Addr::LOCALHOST, 0).into(), 12);
        let driven = Driven::start(mapping(port), Vec::new());
        driven.send(&udp_v4(GUEST, GATEWAY, port, b"query"));
        // The replies arrive and fill the ring before the window opens.
        std::thread::sleep(Duration::from_millis(500));
        let used = driven.ticks_over(Duration::from_secs(1));
        assert!(
            used < IDLE_TICKS,
            "the pump spun: {used} ticks in one second"
        );
    }

    #[test]
    fn published_connections_have_a_budget_of_their_own() {
        let host = (Ipv4Addr::LOCALHOST, 0).into();
        let publication = Publication {
            host,
            guest_port: 8000,
        };
        let listener = listen(&publication).expect("the published port binds");
        let address = listener.bound;
        let plan = NetStack::builder()
            .publish(host, 8000)
            .host_loopback(true)
            .build()
            .expect("a valid configuration")
            .plan;
        let (tap, _guest) = tap_pair();
        let mut engine = engine(tap, plan, vec![listener]);

        // Fill the published budget with flows standing in for idle peers.
        let mut peers = Vec::new();
        for at in 0..tcp::MAX_PUBLISHED_FLOWS {
            let (host_side, peer) = rustix::net::socketpair(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )
            .expect("a socket pair stands in for a published peer");
            let handle = engine.sockets.add(tcp_socket::Socket::new(
                tcp_socket::SocketBuffer::new(vec![0; 64]),
                tcp_socket::SocketBuffer::new(vec![0; 64]),
            ));
            let port = 50_000 + u16::try_from(at).expect("the budget fits a port range");
            engine.flows.push(TcpFlow::accepted(
                handle,
                IpEndpoint::new(GUEST.into(), 8000),
                IpEndpoint::new(GATEWAY.into(), port),
                host_side,
                std::time::Instant::now(),
            ));
            peers.push(peer);
        }

        // One more published connection is accepted and closed at once.
        let mut late = std::net::TcpStream::connect(address).expect("the listener accepts");
        late.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("the timeout is settable");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while engine.flows.len() == tcp::MAX_PUBLISHED_FLOWS && std::time::Instant::now() < deadline
        {
            engine.accept(0);
            let mut byte = [0u8; 1];
            use std::io::Read as _;
            match late.read(&mut byte) {
                Ok(0) => break,
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                _ => {}
            }
        }
        assert_eq!(
            engine.flows.len(),
            tcp::MAX_PUBLISHED_FLOWS,
            "a published connection past the budget was carried",
        );

        // And the guest's own connections are not crowded out by them.
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a listener binds");
        let target = target.local_addr().expect("an address").port();
        assert!(engine.consider(classify(&syn_v4(GUEST, GATEWAY, target))));
        assert_eq!(
            engine.flows.len(),
            tcp::MAX_PUBLISHED_FLOWS + 1,
            "the guest's connection was refused for the published ones",
        );
        drop(peers);
    }

    #[test]
    fn a_listener_that_fails_to_accept_sits_out_the_poll() {
        // Descriptor exhaustion is the failure this guards against, which a
        // test cannot arrange without starving every other test in the
        // process. A listener shut down for reading stands in for it: every
        // accept on it fails, and it reports itself ready on every poll, as a
        // listener with a connection it cannot accept does.
        let host = (Ipv4Addr::LOCALHOST, 0).into();
        let listener = listen(&Publication {
            host,
            guest_port: 8000,
        })
        .expect("the published port binds");
        rustix::net::shutdown(&listener.socket, rustix::net::Shutdown::Read)
            .expect("the listener shuts down");
        let mut ready = [PollFd::new(&listener.socket, PollFlags::IN)];
        assert_eq!(
            rustix::event::poll(&mut ready, Some(&crate::poll::timeout(Duration::ZERO))),
            Ok(1),
            "the stand-in is ready for good, as the failure it stands in for is",
        );
        assert!(rustix::net::accept(&listener.socket).is_err());
        let plan = NetStack::builder()
            .publish(host, 8000)
            .build()
            .expect("a valid configuration")
            .plan;

        let driven = Driven::start(plan, vec![listener]);
        std::thread::sleep(Duration::from_millis(200));
        let used = driven.ticks_over(Duration::from_secs(1));
        assert!(
            used < IDLE_TICKS,
            "the pump spun: {used} ticks in one second"
        );
    }
}
