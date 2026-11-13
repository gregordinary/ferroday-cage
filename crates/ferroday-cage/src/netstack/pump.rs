//! The pump: the event loop that serves one attachment.
//!
//! One thread owns everything: the tap descriptor, the smoltcp interface
//! that terminates the guest's flows, and the host sockets those flows are
//! forwarded onto. Each iteration sleeps in a single `poll` over the eventfd
//! a [`Stop`] writes to, the tap, and the host sockets that currently want
//! attention, then ingests tap frames, lets the interface process them, and
//! services the flows until nothing moves — bounded, so a busy connection
//! cannot starve the loop.
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
//! So an ARP request, a neighbor solicitation, or an echo request naming an
//! address the interface does not hold is dropped before the interface sees it
//! ([`Engine::holds`]), and two properties follow. An address on the guest's
//! own subnet other than the gateway is on-link as far as the guest is
//! concerned, so the guest asks for its hardware address, nothing replies, and
//! no segment for it ever reaches the stack — which is why that refusal alone
//! is not a reset, see [`host_target`]. And the interface answers an echo
//! request only for the gateway, rather than in the name of whatever the
//! request named. A sandboxed command cannot send one in the first place: it
//! holds no capability over its network namespace, which `ping` needs.
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
use super::{GATEWAY_MAC, Listener, Plan, PlanV4, PumpExit};

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

/// Runs the pump until `stop`, the descriptor a [`Stop`] wakes, becomes
/// readable. The tap descriptor's lifetime is the attachment's: it closes when
/// this returns, and so do the published ports' listeners.
pub(super) fn run(tap: OwnedFd, stop: OwnedFd, plan: Plan, listeners: Vec<Listener>) -> PumpExit {
    match Engine::new(tap, plan, listeners) {
        Ok(mut engine) => engine.run(&stop),
        Err(exit) => exit,
    }
}

/// What stops a pump: an eventfd the pump polls, which its handle writes to.
///
/// The signal is a write rather than the close of the handle's descriptor. A
/// fork copies the caller's whole descriptor table, so a process the caller
/// forks while the stack runs holds a copy of the handle's descriptor: another
/// launch's stage until it sweeps its inherited descriptors, a child of the
/// caller's own until it executes. A close reaches the pump only once every
/// copy has closed, and a stop, or a dropped handle, would wait on the pump for
/// that long. A write reaches it at once. Unlike a write to a pipe whose reader
/// has gone, a write to an eventfd raises no `SIGPIPE` where the pump has
/// already exited on its own.
#[derive(Debug)]
pub(super) struct Stop(OwnedFd);

impl Stop {
    /// A stop, and the descriptor the pump it stops polls.
    pub(super) fn new() -> std::io::Result<(Stop, OwnedFd)> {
        let flags = rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK;
        let stop = rustix::event::eventfd(0, flags)?;
        let polled = rustix::io::fcntl_dupfd_cloexec(&stop, 0)?;
        Ok((Stop(stop), polled))
    }

    /// Tells the pump to stop. Telling it again, or once it has exited, does
    /// nothing more.
    pub(super) fn send(&self) {
        // The counter the write adds to would take some 2^64 sends to fill,
        // which is the one way the write can fail.
        let _ = rustix::io::write(&self.0, &1u64.to_ne_bytes());
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
    /// The descriptor a [`Stop`] wakes.
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
    /// Who each slot of the current iteration's poll set belongs to, in slot
    /// order.
    ///
    /// This and the two lists after it are kept across iterations and emptied
    /// at the start of each, since the loop runs for every batch of frames the
    /// sandbox sends or receives and a list built anew is an allocation each
    /// time. The poll set's descriptor list cannot be kept this way: it borrows
    /// the descriptors it watches, so it lasts one iteration and is the one
    /// list each iteration allocates.
    owners: Vec<SlotOwner>,
    /// What `poll` reported for each slot, copied out of the poll set so the
    /// flows it borrowed can be updated.
    events: Vec<PollFlags>,
    /// The published ports whose listeners are readable, by index.
    accepting: Vec<usize>,
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
            owners: Vec::new(),
            events: Vec::new(),
            accepting: Vec::new(),
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

            // Assemble the poll set: the stop, the tap, and every
            // flow whose host socket has an interest right now. A flow
            // with nothing to wait for is left out entirely — its hangup
            // or error is discovered when it next has one.
            let timeout = self.poll_timeout();
            let slots = self.poll_slots();
            self.owners.clear();
            self.owners.reserve(slots);
            let mut fds: Vec<PollFd<'_>> = Vec::with_capacity(slots);
            self.owners.push(SlotOwner::Stop);
            fds.push(PollFd::new(stop, PollFlags::IN));
            self.owners.push(SlotOwner::Tap);
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
                    self.owners.push(SlotOwner::Tcp(index));
                    fds.push(PollFd::new(host, interest));
                }
            }
            // A UDP host socket is waited on only for replies, and only while
            // its port socket has room for one: a reply that cannot be queued
            // stays on the host socket, which would otherwise stay readable and
            // return every poll at once. The draining itself is unconditional.
            for host in self.udp.reply_interest(&self.sockets) {
                self.owners.push(SlotOwner::Udp);
                fds.push(PollFd::new(host, PollFlags::IN));
            }
            // A listener sitting out its backoff is left out, which is what
            // keeps a connection it cannot accept from waking the loop.
            for (index, inbound) in self.inbound.iter().enumerate() {
                if inbound.retry_at.is_none() {
                    self.owners.push(SlotOwner::Listener(index));
                    fds.push(PollFd::new(&inbound.socket, PollFlags::IN));
                }
            }
            debug_assert!(
                fds.len() <= slots,
                "the poll set holds a kind of slot `poll_slots` does not count",
            );

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
            self.events.clear();
            self.events.extend(fds.iter().map(|fd| fd.revents()));
            drop(fds);
            let mut stop_requested = false;
            let mut tap_readable = false;
            self.accepting.clear();
            for flow in &mut self.flows {
                flow.events = PollFlags::empty();
            }
            for (owner, &revents) in self.owners.iter().zip(&self.events) {
                match owner {
                    SlotOwner::Stop => stop_requested = !revents.is_empty(),
                    SlotOwner::Tap => tap_readable = !revents.is_empty(),
                    SlotOwner::Tcp(index) => self.flows[*index].events = revents,
                    // UDP draining is unconditional, so its wakeups need no
                    // per-flow bookkeeping.
                    SlotOwner::Udp => {}
                    SlotOwner::Listener(index) if !revents.is_empty() => {
                        self.accepting.push(*index);
                    }
                    SlotOwner::Listener(_) => {}
                }
            }
            if stop_requested {
                return PumpExit::Clean;
            }

            if tap_readable && let Err(exit) = self.ingest_tap() {
                return exit;
            }
            // Accepting takes the whole engine, so the list is lent out for
            // the walk and put back with its allocation.
            let accepting = std::mem::take(&mut self.accepting);
            for &index in &accepting {
                self.accept(index);
            }
            self.accepting = accepting;

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

            self.reap(std::time::Instant::now());
        }
    }

    /// The most slots the next poll set can hold, which it is sized to up
    /// front: the stop and the tap, then one for each TCP flow, each UDP flow,
    /// and each published port, whether or not it wants attention this time.
    fn poll_slots(&self) -> usize {
        2 + self.flows.len() + self.udp.flow_count() + self.inbound.len()
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
        let mut socket = tcp::guest_facing_socket();
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
            let mut socket = tcp::guest_facing_socket();
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

    /// Enforces the flows' deadlines as of `now`, then removes finished flows
    /// with their sockets.
    ///
    /// A flow a deadline aborts still has its reset to send. smoltcp emits it
    /// on the socket's next dispatch, and removing the socket first would
    /// discard it. The guest would then never learn of the abort. Its side of
    /// an outbound connection is established before the host's is, since its
    /// handshake completes against the stack's own listener, so it would wait on
    /// a connection that no longer exists for as long as it cares to wait. The
    /// interface is therefore polled between the aborts and the removal. Every
    /// other abort happens while the flows are serviced, and the interface poll
    /// that follows each servicing round sends its reset.
    fn reap(&mut self, now: std::time::Instant) {
        let mut aborted = false;
        for flow in &mut self.flows {
            let socket = self.sockets.get_mut::<tcp_socket::Socket>(flow.handle);
            aborted |= flow.enforce_deadline(socket, now);
        }
        if aborted {
            self.iface
                .poll(self.now(), &mut self.device, &mut self.sockets);
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
/// - An address under NAT64's well-known prefix, `64:ff9b::/96`, whose embedded
///   IPv4 address the IPv4 rules refuse; see [`nat64_embedded`].
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
            if refuses_v4(addr, Some(v4)) {
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
            let translated_refusal =
                nat64_embedded(addr).is_some_and(|embedded| refuses_v4(embedded, plan.v4.as_ref()));
            if addr.is_unspecified()
                || addr.is_multicast()
                || addr.is_loopback()
                || addr.is_unicast_link_local()
                // Both IPv4-in-IPv6 forms: mapped and the deprecated
                // compatible. `to_ipv4` accepts either, where `to_ipv4_mapped`
                // would let `::a.b.c.d` through.
                || addr.to_ipv4().is_some()
                || translated_refusal
                || is_aws_instance_service(addr)
                || on_link
            {
                return None;
            }
            Some(SocketAddr::from((addr, dst.port)))
        }
    }
}

/// Whether the IPv4 rules refuse `addr`, other than as the gateway: the
/// special-purpose blocks, and the guest's own subnet where the plan has an
/// IPv4 side.
///
/// The gateway is the caller's to settle first, since a connection to it may
/// map to host loopback. Reached through NAT64 it is just an address on the
/// guest's subnet, and refused as one.
fn refuses_v4(addr: std::net::Ipv4Addr, v4: Option<&PlanV4>) -> bool {
    let on_link = v4.is_some_and(|v4| {
        let mask = u32::MAX << (32 - u32::from(v4.prefix_len));
        u32::from(addr) & mask == u32::from(v4.gateway) & mask
    });
    addr.is_unspecified()
        // 0.0.0.0/8: `is_unspecified` covers only 0.0.0.0 itself, and the rest
        // of the block is no more routable.
        || addr.octets()[0] == 0
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_loopback()
        || addr.is_link_local()
        || on_link
}

/// The IPv4 address `addr` embeds under NAT64's well-known prefix,
/// `64:ff9b::/96`, or `None` for an address outside it.
///
/// A host on an IPv6-only network reaches IPv4 destinations through a
/// translator, and the guest reaches what the host reaches, so the prefix as a
/// whole is carried. The translator connects to the embedded IPv4 address from
/// its own position, which is the host's where the translator runs on the
/// host. So an embedded address is held to the IPv4 rules. That keeps an IPv4
/// refusal from being re-expressed through the translator, as the mapped and
/// compatible forms would re-express it through the host's own stack.
///
/// Only the well-known prefix says so in the address. A network-specific
/// prefix, the local-use `64:ff9b:1::/48` among them, is indistinguishable
/// from any other routable address, and a caller on such a network confines
/// it outside the stack.
fn nat64_embedded(addr: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    match addr.segments() {
        [0x0064, 0xff9b, 0, 0, 0, 0, high, low] => Some(std::net::Ipv4Addr::from(
            u32::from(high) << 16 | u32::from(low),
        )),
        _ => None,
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
    fn nat64_carries_what_the_ipv4_rules_carry_and_nothing_else() {
        // A translator connects to the embedded IPv4 address from its own
        // position, possibly the host's, so that address is held to the IPv4
        // rules: the metadata service, loopback, and the guest's own IPv4
        // subnet stay refused when spelled under the well-known prefix.
        let plan = plan(false);
        for dst in [
            v6("64:ff9b::169.254.169.254", 80),
            v6("64:ff9b::127.0.0.1", 80),
            v6("64:ff9b::10.0.2.2", 80),
            v6("64:ff9b::10.0.2.15", 80),
            v6("64:ff9b::0.1.2.3", 80),
            v6("64:ff9b::224.0.0.1", 80),
        ] {
            assert_eq!(host_target(dst, &plan), None, "{dst}");
        }
        // What the IPv4 rules carry, a translator is asked to carry too: an
        // IPv6-only host reaches the IPv4 world this way.
        assert_eq!(
            host_target(v6("64:ff9b::203.0.113.9", 443), &plan),
            Some("[64:ff9b::cb00:7109]:443".parse().unwrap()),
        );
        // Only the well-known /96 embeds an address in its last 32 bits. Its
        // neighbours, the local-use /48 among them, are ordinary destinations.
        for dst in [
            v6("64:ff9b:1::a9fe:a9fe", 80),
            v6("64:ff9b:0:0:0:1:a9fe:a9fe", 80),
        ] {
            assert_eq!(
                host_target(dst, &plan),
                Some(SocketAddr::from((IpAddr::from(dst.addr), dst.port))),
                "{dst}",
            );
        }
        // Without an IPv4 side the guest has no IPv4 subnet to collide with,
        // and the special-purpose blocks are refused all the same.
        let v6_only = NetStack::builder()
            .ipv4(false)
            .build()
            .expect("a v6-only configuration is valid")
            .plan;
        assert_eq!(
            host_target(v6("64:ff9b::10.0.2.7", 80), &v6_only),
            Some("[64:ff9b::a00:207]:80".parse().unwrap()),
        );
        assert_eq!(
            host_target(v6("64:ff9b::169.254.169.254", 80), &v6_only),
            None
        );
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

    #[test]
    fn the_public_question_is_answered_by_the_policy_itself() {
        // `NetStack::forwards` is how a consumer composing the guest's resolver
        // configuration asks this, so it must answer as the pump does for every
        // kind of destination, the resolvers a host lists among them.
        let resolvers = [
            v4(9, 9, 9, 9, 53),
            v4(127, 0, 0, 53, 53),
            v4(169, 254, 169, 253, 53),
            v4(10, 0, 2, 3, 53),
            v4(10, 0, 2, 2, 53),
            v6("2606:4700:4700::1111", 53),
            v6("fd00:ec2::253", 53),
            v6("fe80::1", 53),
            v6("fd00::2", 53),
        ];
        for stack in [
            NetStack::default(),
            NetStack::builder()
                .host_loopback_port(53)
                .build()
                .expect("a valid configuration"),
            NetStack::builder()
                .ipv6(false)
                .build()
                .expect("a valid configuration"),
        ] {
            for dst in resolvers {
                let destination = SocketAddr::from((IpAddr::from(dst.addr), dst.port));
                assert_eq!(
                    stack.forwards(destination),
                    host_target(dst, &stack.plan).is_some(),
                    "{dst}",
                );
            }
        }
        let stack = NetStack::default();
        assert!(stack.forwards("9.9.9.9:53".parse().unwrap()));
        assert!(!stack.forwards("169.254.169.253:53".parse().unwrap()));
        assert!(!stack.forwards("[fd00:ec2::253]:53".parse().unwrap()));
    }

    // -- The pump driven over a socket pair ----------------------------------
    //
    // A sequenced-packet socket pair stands in for the tap: each write is one
    // frame, as a tap's is. The test holds the guest's end and writes the
    // guest's frames into it, so the policy the pump applies to what arrives
    // there is testable without a tap device or a sandbox.

    use rustix::net::{AddressFamily, SocketType};
    use smoltcp::iface::SocketHandle;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        ArpOperation, ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol, EthernetRepr,
        Icmpv6Message, Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet,
        Ipv6Repr, NdiscRepr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
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

    /// The port the guest's connections leave from.
    const GUEST_PORT: u16 = 41_000;

    /// The sequence number the guest's connection-opening segment carries.
    const GUEST_ISN: u32 = 7;

    /// The window the guest advertises: small, so a transfer toward it stops
    /// well short of the stack's transmit buffer.
    const GUEST_WINDOW: u16 = 4096;

    /// A TCP segment from [`GUEST_PORT`] on `src` to `port` on `dst`, in an
    /// IPv4 frame.
    fn segment_v4(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        port: u16,
        control: TcpControl,
        seq: u32,
        ack: Option<u32>,
        payload: &[u8],
    ) -> Vec<u8> {
        tcp_v4((src, GUEST_PORT), (dst, port), control, seq, ack, payload)
    }

    /// A TCP segment from `src` to `dst`, address and port, in an IPv4 frame.
    fn tcp_v4(
        (src, src_port): (Ipv4Addr, u16),
        (dst, dst_port): (Ipv4Addr, u16),
        control: TcpControl,
        seq: u32,
        ack: Option<u32>,
        payload: &[u8],
    ) -> Vec<u8> {
        let repr = TcpRepr {
            src_port,
            dst_port,
            control,
            seq_number: TcpSeqNumber(i32::from_ne_bytes(seq.to_ne_bytes())),
            ack_number: ack.map(|ack| TcpSeqNumber(i32::from_ne_bytes(ack.to_ne_bytes()))),
            window_len: GUEST_WINDOW,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
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

    /// A connection-opening segment in an IPv4 frame.
    fn syn_v4(src: Ipv4Addr, dst: Ipv4Addr, port: u16) -> Vec<u8> {
        segment_v4(src, dst, port, TcpControl::Syn, GUEST_ISN, None, &[])
    }

    /// A UDP datagram in an IPv6 frame, behind a hop-by-hop options header
    /// when `hop_by_hop` is set.
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
        /// What stops the pump, which dropping the harness sends.
        stop: Stop,
        /// The pump's thread.
        pump: Option<std::thread::JoinHandle<PumpExit>>,
        /// The pump thread's id, for its processor time.
        tid: i32,
    }

    impl Driven {
        fn start(plan: Plan, listeners: Vec<Listener>) -> Driven {
            let (tap, guest) = tap_pair();
            let (stop, polled) = Stop::new().expect("an eventfd");
            let (tid_send, tid_receive) = std::sync::mpsc::channel();
            let pump = std::thread::spawn(move || {
                let _ = tid_send.send(rustix::thread::gettid().as_raw_nonzero().get());
                run(tap, polled, plan, listeners)
            });
            let tid = tid_receive.recv().expect("the pump thread reports its id");
            Driven {
                guest,
                stop,
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
            ferroday_cage_testkit::process::thread_ticks(self.tid)
        }

        /// How many ticks the pump's thread uses over `window`.
        fn ticks_over(&self, window: Duration) -> u64 {
            let before = self.ticks();
            std::thread::sleep(window);
            self.ticks() - before
        }
    }

    impl Drop for Driven {
        /// Stops the pump and holds it to a clean exit: a pump that ended on
        /// its own, on a broken invariant among other causes, fails the test
        /// that drove it, which would otherwise not notice.
        fn drop(&mut self) {
            self.stop.send();
            let Some(pump) = self.pump.take() else {
                return;
            };
            let exit = pump.join();
            if std::thread::panicking() {
                return;
            }
            match exit {
                Ok(PumpExit::Clean) => {}
                Ok(PumpExit::Failed { op, source }) => {
                    panic!("the pump failed {op} before it was stopped: {source:?}")
                }
                // The panic hook has already reported it, on the pump's thread.
                Ok(PumpExit::Panicked) | Err(_) => {
                    panic!("the pump panicked before it was stopped")
                }
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

    /// Hands `frame` to the engine's interface as ingestion would once
    /// `consider` let it through, and lets the interface and the flows act on
    /// it.
    fn deliver(engine: &mut Engine, frame: &[u8]) {
        let mut queued = engine.device.take_buffer();
        queued.extend_from_slice(frame);
        engine.device.enqueue(queued);
        engine
            .iface
            .poll(engine.now(), &mut engine.device, &mut engine.sockets);
        engine.service();
    }

    /// Receives one datagram, retrying a read a signal interrupted: the test
    /// binary's other tests deliver signals to this process, and a read with a
    /// timeout is not restarted after a handler runs.
    fn recv_retrying(
        socket: &UdpSocket,
        buffer: &mut [u8],
    ) -> std::io::Result<(usize, std::net::SocketAddr)> {
        loop {
            match socket.recv_from(buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }

    #[test]
    fn a_datagram_from_another_source_opens_no_flow_whatever_carries_it() {
        let Ok(socket) = UdpSocket::bind((StdIpv6Addr::LOCALHOST, 0)) else {
            ferroday_cage_testkit::require::TUN.skip("the host has no IPv6 loopback");
            return;
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("the timeout is settable");
        let port = socket.local_addr().expect("an address").port();
        let (tap, _guest) = tap_pair();
        let mut engine = engine(tap, mapping(port), Vec::new());
        let guest: StdIpv6Addr = "fd00::15".parse().unwrap();
        let gateway: StdIpv6Addr = "fd00::2".parse().unwrap();
        let stranger: StdIpv6Addr = "2001:db8::99".parse().unwrap();

        // The guest's own datagram binds the port's socket and opens a flow.
        let own = udp_v6(guest, gateway, port, b"from the guest", false);
        assert!(engine.consider(classify(&own)));
        deliver(&mut engine, &own);
        let mut buffer = [0u8; 64];
        let (len, _) = recv_retrying(&socket, &mut buffer).expect("the guest's datagram arrives");
        assert_eq!(&buffer[..len], b"from the guest");

        // A stranger's behind a hop-by-hop header is withheld as one without
        // it is: the classifier reads past that header as the interface does.
        let spoofed = udp_v6(stranger, gateway, port, b"from a stranger", true);
        assert!(
            !engine.consider(classify(&spoofed)),
            "a stranger's datagram behind a hop-by-hop header passed",
        );

        // And one that reaches the interface without being classified, as one
        // behind a header smoltcp walked and the classifier did not would,
        // reaches the port's socket and still opens no flow.
        deliver(&mut engine, &spoofed);
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("the timeout is settable");
        match recv_retrying(&socket, &mut buffer) {
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

    /// A neighbor solicitation from the guest for `target`, sent to its
    /// solicited-node group with the hop limit neighbor discovery requires.
    fn solicit(target: StdIpv6Addr) -> Vec<u8> {
        let guest: StdIpv6Addr = "fd00::15".parse().unwrap();
        let [.., a, b, c] = target.octets();
        let group = StdIpv6Addr::new(
            0xff02,
            0,
            0,
            0,
            0,
            1,
            0xff00 | u16::from(a),
            u16::from_be_bytes([b, c]),
        );
        let message = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
            target_addr: target,
            lladdr: Some(EthernetAddress(GUEST_MAC).into()),
        });
        let mut icmp = vec![0u8; message.buffer_len()];
        message.emit(
            &guest,
            &group,
            &mut Icmpv6Packet::new_unchecked(&mut icmp),
            &ChecksumCapabilities::default(),
        );
        let repr = Ipv6Repr {
            src_addr: guest,
            dst_addr: group,
            next_header: IpProtocol::Icmpv6,
            payload_len: icmp.len(),
            hop_limit: 255,
        };
        let mut packet = vec![0u8; repr.buffer_len() + icmp.len()];
        let mut ip = Ipv6Packet::new_unchecked(&mut packet);
        repr.emit(&mut ip);
        ip.payload_mut().copy_from_slice(&icmp);
        ethernet(EthernetProtocol::Ipv6, &packet)
    }

    /// Whether the stack advertises `target` to the guest within `within`.
    fn advertised(driven: &Driven, target: StdIpv6Addr, within: Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        let mut buffer = [0u8; 2048];
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            let mut ready = [PollFd::new(&driven.guest, PollFlags::IN)];
            match rustix::event::poll(&mut ready, Some(&crate::poll::timeout(left))) {
                Ok(0) => return false,
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(errno) => panic!("the guest's end cannot be polled: {errno}"),
            }
            let len = match rustix::io::read(&driven.guest, &mut buffer) {
                Ok(len) => len,
                Err(Errno::AGAIN | Errno::INTR) => continue,
                Err(errno) => panic!("the guest's end cannot be read: {errno}"),
            };
            let Ok(frame) = EthernetFrame::new_checked(&buffer[..len]) else {
                continue;
            };
            let Ok(packet) = Ipv6Packet::new_checked(frame.payload()) else {
                continue;
            };
            if packet.next_header() != IpProtocol::Icmpv6 {
                continue;
            }
            let Ok(message) = Icmpv6Packet::new_checked(packet.payload()) else {
                continue;
            };
            if message.msg_type() == Icmpv6Message::NeighborAdvert
                && message.target_addr() == target
            {
                return true;
            }
        }
    }

    /// A fork copies the descriptor table, so a process the caller forks while
    /// the stack runs, another launch's stage before its sweep among them,
    /// holds a copy of whatever the stack's handle holds. The handle's stop
    /// reaches the pump all the same.
    #[test]
    fn a_stop_reaches_the_pump_while_a_copy_of_the_handles_end_lives() {
        let mut driven = Driven::start(NetStack::default().plan, Vec::new());
        let copy = driven.stop.0.try_clone().expect("a duplicate");
        driven.stop.send();
        let pump = driven.pump.take().expect("the pump runs");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !pump.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let stopped = pump.is_finished();
        drop(copy);
        assert!(matches!(pump.join(), Ok(PumpExit::Clean)));
        assert!(stopped, "the pump ran on past its stop");
    }

    #[test]
    fn neighbor_discovery_answers_for_the_gateway_alone() {
        let driven = Driven::start(NetStack::default().plan, Vec::new());

        // An on-link address that shares its low sixteen bits with the
        // gateway's, which is all smoltcp's own check compares; under `any_ip`
        // the interface would advertise it.
        let stranger: StdIpv6Addr = "fd00::1:2".parse().unwrap();
        driven.send(&solicit(stranger));
        assert!(
            !advertised(&driven, stranger, Duration::from_millis(500)),
            "the stack advertised an on-link address it does not hold",
        );

        // The gateway is the stack, and answers for itself.
        let gateway: StdIpv6Addr = "fd00::2".parse().unwrap();
        driven.send(&solicit(gateway));
        assert!(
            advertised(&driven, gateway, Duration::from_secs(2)),
            "the gateway did not answer for itself",
        );
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

    /// One TCP segment the stack sent the guest, as much of it as the tests
    /// read.
    #[derive(Debug)]
    struct Sent {
        syn: bool,
        rst: bool,
        fin: bool,
        seq: u32,
        payload: usize,
    }

    /// The TCP segments the stack has written to the guest's end of the pair
    /// since the last call, in order. Every other frame, an ARP reply say, is
    /// passed over.
    fn sent_to_guest(guest: &OwnedFd) -> Vec<Sent> {
        let mut sent = Vec::new();
        let mut frame = [0u8; 2048];
        loop {
            let read = match rustix::io::read(guest, &mut frame) {
                Ok(read) => read,
                Err(Errno::AGAIN) => return sent,
                Err(errno) => panic!("the guest's end failed: {errno}"),
            };
            let Ok(ethernet) = EthernetFrame::new_checked(&frame[..read]) else {
                continue;
            };
            if ethernet.ethertype() != EthernetProtocol::Ipv4 {
                continue;
            }
            let Ok(ip) = Ipv4Packet::new_checked(ethernet.payload()) else {
                continue;
            };
            if ip.next_header() != IpProtocol::Tcp {
                continue;
            }
            let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else {
                continue;
            };
            sent.push(Sent {
                syn: tcp.syn(),
                rst: tcp.rst(),
                fin: tcp.fin(),
                seq: u32::from_ne_bytes(tcp.seq_number().0.to_ne_bytes()),
                payload: tcp.payload().len(),
            });
        }
    }

    /// An ARP request from the guest for the gateway's hardware address, which
    /// is how the stack learns the guest's own: a guest resolves its gateway
    /// before it sends anything through it.
    fn resolve_gateway() -> Vec<u8> {
        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: EthernetAddress(GUEST_MAC),
            source_protocol_addr: GUEST,
            target_hardware_addr: EthernetAddress([0; 6]),
            target_protocol_addr: GATEWAY,
        };
        let mut packet = vec![0u8; repr.buffer_len()];
        repr.emit(&mut ArpPacket::new_unchecked(&mut packet));
        ethernet(EthernetProtocol::Arp, &packet)
    }

    /// Hands `frame` to the engine as ingestion does: classified first, so a
    /// connection attempt gets its flow, then delivered.
    fn guest_sends(engine: &mut Engine, frame: &[u8]) {
        assert!(
            engine.consider(classify(frame)),
            "the stack withheld the guest's frame"
        );
        deliver(engine, frame);
    }

    /// Opens a connection from the guest to the gateway's `port`, which the
    /// plan maps onto host loopback, and completes the guest's side of it.
    ///
    /// The guest's handshake completes against the stack's own listener at
    /// once, while the host connect runs in parallel. Nothing reports that
    /// connect's conclusion to the flow until the test does, so the flow is
    /// left established on the guest's side alone. Returns the sequence number
    /// the stack's next byte to the guest carries, which the guest's own
    /// segments acknowledge.
    fn guest_connects(engine: &mut Engine, guest: &OwnedFd, port: u16) -> u32 {
        guest_sends(engine, &resolve_gateway());
        guest_sends(engine, &syn_v4(GUEST, GATEWAY, port));
        let sent = sent_to_guest(guest);
        let syn_ack = sent
            .iter()
            .find(|segment| segment.syn)
            .unwrap_or_else(|| panic!("the stack never answered the guest's SYN: {sent:?}"));
        let next = syn_ack.seq.wrapping_add(1);
        guest_sends(
            engine,
            &segment_v4(
                GUEST,
                GATEWAY,
                port,
                TcpControl::None,
                GUEST_ISN + 1,
                Some(next),
                &[],
            ),
        );
        assert_eq!(
            engine
                .sockets
                .get::<tcp_socket::Socket>(engine.flows[0].handle)
                .state(),
            tcp_socket::State::Established,
            "the guest's side of the connection is established",
        );
        next
    }

    /// A flow the establish deadline aborts resets the guest, whose side of the
    /// connection is already established and would otherwise wait on it for as
    /// long as it cares to.
    #[test]
    fn a_flow_the_establish_deadline_aborts_resets_the_guest() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a listener binds");
        let port = listener.local_addr().expect("an address").port();
        let (tap, guest) = tap_pair();
        let mut engine = engine(tap, mapping(port), Vec::new());
        guest_connects(&mut engine, &guest, port);
        let now = std::time::Instant::now();
        let flow = &engine.flows[0];
        assert!(
            flow.deadline_in(engine.sockets.get(flow.handle), now)
                .is_some_and(|left| left > Duration::ZERO),
            "the flow waits on its host connect, under the establish deadline",
        );

        engine.reap(now + tcp::ESTABLISH_DEADLINE);
        assert!(engine.flows.is_empty(), "the deadline reclaimed the flow");
        let sent = sent_to_guest(&guest);
        assert!(
            sent.iter().any(|segment| segment.rst),
            "the guest was never told the connection is gone: {sent:?}",
        );
    }

    /// A flow the drain deadline reclaims, a guest that never reads behind a
    /// host that has finished sending, resets the guest the same way.
    #[test]
    fn a_flow_the_drain_deadline_reclaims_resets_the_guest() {
        use std::io::Write as _;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a listener binds");
        let port = listener.local_addr().expect("an address").port();
        let (tap, guest) = tap_pair();
        let mut engine = engine(tap, mapping(port), Vec::new());
        guest_connects(&mut engine, &guest, port);

        // The host connect concludes, as a poll reports it.
        let (mut peer, _) = listener.accept().expect("the stack's connect arrives");
        engine.flows[0].events = PollFlags::OUT;
        engine.service();

        // The host sends half as much again as the guest's transmit buffer
        // holds and hangs up, so the tail and its end of stream stay queued
        // behind a buffer the guest never drains. Written on a thread of its
        // own, since the kernel buffers only so much while the stack is not
        // reading.
        let writer = std::thread::spawn(move || {
            peer.write_all(&vec![b'x'; tcp::BUFFER_SIZE * 3 / 2])
                .expect("the host writes");
            peer.shutdown(std::net::Shutdown::Write)
                .expect("the host hangs up");
            peer
        });
        let patience = std::time::Instant::now() + Duration::from_secs(10);
        while !writer.is_finished() {
            assert!(
                std::time::Instant::now() < patience,
                "the host never finished writing"
            );
            engine.flows[0].events = PollFlags::IN;
            engine.service();
            engine
                .iface
                .poll(engine.now(), &mut engine.device, &mut engine.sockets);
            std::thread::sleep(Duration::from_millis(10));
        }
        let _peer = writer.join().expect("the writer completes");

        // The hangup is reported, the guest is sent what its window takes, and
        // the flow can move nothing more.
        engine.flows[0].events = PollFlags::IN | PollFlags::RDHUP;
        engine.service();
        engine
            .iface
            .poll(engine.now(), &mut engine.device, &mut engine.sockets);
        engine.flows[0].events = PollFlags::empty();
        engine.service();
        let now = std::time::Instant::now();
        let flow = &engine.flows[0];
        assert!(
            flow.deadline_in(engine.sockets.get(flow.handle), now)
                .is_some_and(|left| left > Duration::ZERO),
            "the flow is stalled, under the drain deadline",
        );
        let delivered: usize = sent_to_guest(&guest)
            .iter()
            .map(|segment| segment.payload)
            .sum();
        assert!(
            delivered > 0 && delivered <= usize::from(GUEST_WINDOW),
            "the guest's window, and no more, was filled: {delivered} bytes",
        );

        engine.reap(now + tcp::DRAIN_DEADLINE);
        assert!(engine.flows.is_empty(), "the deadline reclaimed the flow");
        let sent = sent_to_guest(&guest);
        assert!(
            sent.iter().any(|segment| segment.rst),
            "the guest was never told the connection is gone: {sent:?}",
        );
    }

    /// A guest that never acknowledges the tail a finished host left in the
    /// transmit buffer is reclaimed at the drain deadline, though the host's
    /// whole stream, its end included, fits in the buffer and nothing is left
    /// for the flow itself to copy.
    ///
    /// A real guest answering the stack's zero-window probes keeps the guest
    /// socket's own idle timeout from firing; this one says nothing at all,
    /// and the deadline is reached on the host's clock before that timeout
    /// would be on the interface's.
    #[test]
    fn a_guest_that_never_reads_behind_a_finished_host_is_reclaimed() {
        use std::io::{Read as _, Write as _};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a listener binds");
        let port = listener.local_addr().expect("an address").port();
        let (tap, guest) = tap_pair();
        let mut engine = engine(tap, mapping(port), Vec::new());
        guest_connects(&mut engine, &guest, port);
        let (mut peer, _) = listener.accept().expect("the stack's connect arrives");
        engine.flows[0].events = PollFlags::OUT;
        engine.service();

        // Twice what the guest's window takes, and the end of stream behind it.
        peer.write_all(&[b'x'; 2 * GUEST_WINDOW as usize])
            .expect("the host writes");
        peer.shutdown(std::net::Shutdown::Write)
            .expect("the host hangs up");
        let patience = std::time::Instant::now() + Duration::from_secs(5);
        let handle = engine.flows[0].handle;
        while engine.sockets.get::<tcp_socket::Socket>(handle).state()
            != tcp_socket::State::FinWait1
        {
            assert!(
                std::time::Instant::now() < patience,
                "the host's end of stream never reached the guest socket"
            );
            engine.flows[0].events = PollFlags::IN | PollFlags::RDHUP;
            engine.service();
            engine
                .iface
                .poll(engine.now(), &mut engine.device, &mut engine.sockets);
        }
        assert!(
            engine
                .sockets
                .get::<tcp_socket::Socket>(handle)
                .send_queue()
                > 0,
            "the guest has the host's tail to take",
        );

        // A pass that moves nothing finds the flow stalled.
        engine.flows[0].events = PollFlags::empty();
        engine.service();
        let now = std::time::Instant::now();
        let flow = &engine.flows[0];
        assert!(
            flow.deadline_in(engine.sockets.get(flow.handle), now)
                .is_some_and(|left| left > Duration::ZERO),
            "the flow is stalled, under the drain deadline",
        );

        engine.reap(now + tcp::DRAIN_DEADLINE);
        assert!(engine.flows.is_empty(), "the deadline reclaimed the flow");
        let sent = sent_to_guest(&guest);
        assert!(
            sent.iter().any(|segment| segment.rst),
            "the guest was never told the connection is gone: {sent:?}",
        );
        peer.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("the timeout is settable");
        let mut rest = Vec::new();
        let ended = peer.read_to_end(&mut rest);
        assert!(
            matches!(&ended, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
            "the host peer saw {ended:?} where its stream was cut off",
        );
    }

    /// A host that never reads the bytes a reset guest left queued for it is
    /// reclaimed at the drain deadline. The guest is gone, so nothing answers
    /// probes on its side, but the host side answers its own keep-alive.
    #[test]
    fn a_host_that_never_reads_behind_a_finished_guest_is_reclaimed() {
        let (tap, guest) = tap_pair();
        let mut engine = engine(tap, NetStack::default().plan, Vec::new());
        let mut published = Published::open(&mut engine, &guest);

        published.upload(&mut engine);
        // The stall begins no earlier than the reset, which bounds the
        // deadline from below whatever the scheduler does between here and
        // the checks.
        let before = std::time::Instant::now();
        published.guest_sends(&mut engine, TcpControl::Rst, &[]);
        let socket = published.socket(&engine);
        assert_eq!(socket.state(), tcp_socket::State::Closed);
        assert!(socket.recv_queue() > 0, "the guest's tail is still queued");

        let now = std::time::Instant::now();
        let flow = &engine.flows[0];
        assert!(
            flow.deadline_in(engine.sockets.get(flow.handle), now)
                .is_some(),
            "the flow is stalled, under the drain deadline",
        );
        engine.reap(before + tcp::DRAIN_DEADLINE - Duration::from_millis(1));
        assert_eq!(engine.flows.len(), 1, "the flow was reclaimed early");
        engine.reap(now + tcp::DRAIN_DEADLINE);
        assert!(engine.flows.is_empty(), "the deadline reclaimed the flow");
    }

    /// What the host peer of a guest's upload reads: the bytes, then how the
    /// stream ended, `Ok` for an end of stream and the error otherwise.
    ///
    /// The guest connects, sends `UPLOAD`, and ends the connection with
    /// `ending`, a FIN or a reset, sequenced after the upload. The flow is
    /// then reaped, as the pump's pass ends, and dropped if it is over.
    fn upload_ending_in(ending: TcpControl) -> (Vec<u8>, std::io::Result<()>) {
        use std::io::Read as _;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a listener binds");
        let port = listener.local_addr().expect("an address").port();
        let (tap, guest) = tap_pair();
        let mut engine = engine(tap, mapping(port), Vec::new());
        let next = guest_connects(&mut engine, &guest, port);
        let (mut peer, _) = listener.accept().expect("the stack's connect arrives");
        peer.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("the timeout is settable");
        engine.flows[0].events = PollFlags::OUT;
        engine.service();

        let after = GUEST_ISN + 1 + u32::try_from(UPLOAD.len()).expect("a short upload");
        guest_sends(
            &mut engine,
            &segment_v4(
                GUEST,
                GATEWAY,
                port,
                TcpControl::Psh,
                GUEST_ISN + 1,
                Some(next),
                UPLOAD,
            ),
        );
        let ack = (ending != TcpControl::Rst).then_some(next);
        guest_sends(
            &mut engine,
            &segment_v4(GUEST, GATEWAY, port, ending, after, ack, &[]),
        );
        engine.reap(std::time::Instant::now());

        let mut received = Vec::new();
        let mut buf = [0u8; 256];
        let ended = loop {
            match peer.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(read) => received.extend_from_slice(&buf[..read]),
                Err(error) => break Err(error),
            }
        };
        (received, ended)
    }

    /// What [`upload_ending_in`]'s guest sends ahead of its ending.
    const UPLOAD: &[u8] = b"the first part of an upload";

    /// A reset from the guest reaches the host peer as a reset, after the bytes
    /// the guest sent ahead of it. An end of stream in its place would pass the
    /// truncated stream off as complete: a server reading an upload to its end
    /// takes what arrived as the whole of it.
    #[test]
    fn a_reset_from_the_guest_resets_the_host_peer() {
        let (received, ended) = upload_ending_in(TcpControl::Rst);
        assert_eq!(received, UPLOAD, "the bytes ahead of the reset arrived");
        assert!(
            matches!(&ended, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
            "the host peer saw {ended:?} where the guest reset the connection",
        );
    }

    /// The guest's FIN reaches the host peer as an end of stream, after the
    /// bytes ahead of it: the orderly close a reset is told apart from.
    #[test]
    fn a_fin_from_the_guest_ends_the_host_peers_stream() {
        let (received, ended) = upload_ending_in(TcpControl::Fin);
        assert_eq!(received, UPLOAD, "the bytes ahead of the FIN arrived");
        assert!(
            ended.is_ok(),
            "the host peer saw {ended:?} where the guest finished its stream",
        );
    }

    /// A published connection the guest has accepted, carried by a flow whose
    /// host side takes a few kilobytes and then nothing more until its peer
    /// reads.
    struct Published {
        /// The guest-facing socket.
        handle: SocketHandle,
        /// The host side's peer, which the test reads as the host would.
        peer: OwnedFd,
        /// The guest's end of the connection, address and port.
        guest_at: (Ipv4Addr, u16),
        /// The stack's end of the connection, address and port.
        stack_at: (Ipv4Addr, u16),
        /// The sequence number the stack's next byte to the guest carries.
        stack_next: u32,
        /// The sequence number the guest's next byte carries.
        guest_next: u32,
    }

    impl Published {
        /// Opens the connection: the stack connects to the guest, which
        /// accepts.
        fn open(engine: &mut Engine, guest: &OwnedFd) -> Published {
            guest_sends(engine, &resolve_gateway());
            let (host_side, peer) = rustix::net::socketpair(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )
            .expect("a socket pair stands in for the host side");
            rustix::net::sockopt::set_socket_send_buffer_size(&host_side, 4096)
                .expect("the buffer is sizable");
            let (guest_at, stack_at) = ((GUEST, 8000), (GATEWAY, 50_000));
            let guest_end = IpEndpoint::new(GUEST.into(), guest_at.1);
            let stack_end = IpEndpoint::new(GATEWAY.into(), stack_at.1);
            let mut socket = tcp::guest_facing_socket();
            socket
                .connect(engine.iface.context(), guest_end, stack_end)
                .expect("the stack connects to the guest");
            let handle = engine.sockets.add(socket);
            engine.flows.push(TcpFlow::accepted(
                handle,
                guest_end,
                stack_end,
                host_side,
                std::time::Instant::now(),
            ));
            engine
                .iface
                .poll(engine.now(), &mut engine.device, &mut engine.sockets);
            let sent = sent_to_guest(guest);
            let syn = sent
                .iter()
                .find(|segment| segment.syn)
                .unwrap_or_else(|| panic!("the stack never connected to the guest: {sent:?}"));
            let mut published = Published {
                handle,
                peer,
                guest_at,
                stack_at,
                stack_next: syn.seq.wrapping_add(1),
                guest_next: 1000,
            };
            published.guest_sends(engine, TcpControl::Syn, &[]);
            published
        }

        /// Sends one segment from the guest, acknowledging everything the
        /// stack has sent, and advances the guest's sequence past it.
        fn guest_sends(&mut self, engine: &mut Engine, control: TcpControl, payload: &[u8]) {
            guest_sends(
                engine,
                &tcp_v4(
                    self.guest_at,
                    self.stack_at,
                    control,
                    self.guest_next,
                    Some(self.stack_next),
                    payload,
                ),
            );
            let flags = u32::from(matches!(control, TcpControl::Syn | TcpControl::Fin));
            let length = u32::try_from(payload.len()).expect("a segment's payload fits");
            self.guest_next = self.guest_next.wrapping_add(length + flags);
        }

        /// Uploads more than the host side takes, and returns what was sent.
        fn upload(&mut self, engine: &mut Engine) -> Vec<u8> {
            let mut uploaded = Vec::new();
            for fill in b'a'..b'q' {
                let chunk = [fill; 1024];
                self.guest_sends(engine, TcpControl::Psh, &chunk);
                uploaded.extend_from_slice(&chunk);
            }
            assert!(
                self.socket(engine).recv_queue() > 0,
                "the host side stopped taking the upload",
            );
            uploaded
        }

        /// The host side finishes without reading, and the stack passes its
        /// end of stream on as a FIN, which the guest's next segment
        /// acknowledges.
        fn host_finishes(&mut self, engine: &mut Engine, guest: &OwnedFd) {
            rustix::net::shutdown(&self.peer, rustix::net::Shutdown::Write)
                .expect("the peer finishes");
            engine.flows[0].events = PollFlags::IN | PollFlags::RDHUP;
            engine.service();
            engine
                .iface
                .poll(engine.now(), &mut engine.device, &mut engine.sockets);
            let sent = sent_to_guest(guest);
            let fin = sent
                .iter()
                .find(|segment| segment.fin)
                .unwrap_or_else(|| panic!("the stack never finished its side: {sent:?}"));
            let length = u32::try_from(fin.payload).expect("a segment's payload fits");
            self.stack_next = fin.seq.wrapping_add(length + 1);
        }

        /// The guest-facing socket.
        fn socket<'a>(&self, engine: &'a Engine) -> &'a tcp_socket::Socket<'static> {
            engine.sockets.get::<tcp_socket::Socket>(self.handle)
        }

        /// Reads the host side to its end as the host would, servicing the
        /// flow whenever the host has taken what was there, and returns what
        /// arrived.
        fn host_reads(&self, engine: &mut Engine, expected: usize) -> Vec<u8> {
            let mut received = Vec::new();
            let mut buf = [0u8; 4096];
            let patience = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                assert!(
                    std::time::Instant::now() < patience,
                    "the upload never finished arriving: {} of {expected} bytes",
                    received.len(),
                );
                match rustix::io::read(&self.peer, &mut buf) {
                    Ok(0) => return received,
                    Ok(read) => received.extend_from_slice(&buf[..read]),
                    Err(Errno::AGAIN) => {
                        if let Some(flow) = engine.flows.first_mut() {
                            flow.events = PollFlags::OUT;
                        }
                        engine.service();
                        engine.reap(std::time::Instant::now());
                    }
                    Err(errno) => panic!("the host side failed: {errno}"),
                }
            }
        }
    }

    /// Moves the interface's clock `by` ahead of the host's, as though that
    /// much time had passed with nothing to wake the pump.
    fn advance_clock(engine: &mut Engine, by: Duration) {
        engine.epoch = engine
            .epoch
            .checked_sub(by)
            .expect("the monotonic clock has run for longer than the advance");
    }

    /// Bytes the guest sent that the host side has yet to take outlast the
    /// guest socket's close: the flow forwards them, then passes the guest's
    /// end of stream on.
    ///
    /// An orderly exchange reaches that close while a slow host still has
    /// bytes to take. The guest finishes, the host finishes without reading,
    /// and the guest acknowledges the stack's FIN, which closes the socket
    /// with the guest's tail still queued in it.
    #[test]
    fn bytes_queued_for_the_host_outlast_the_guests_close() {
        let (tap, guest) = tap_pair();
        let mut engine = engine(tap, NetStack::default().plan, Vec::new());
        let mut published = Published::open(&mut engine, &guest);

        let uploaded = published.upload(&mut engine);
        published.guest_sends(&mut engine, TcpControl::Fin, &[]);
        published.host_finishes(&mut engine, &guest);
        published.guest_sends(&mut engine, TcpControl::None, &[]);
        let socket = published.socket(&engine);
        assert_eq!(socket.state(), tcp_socket::State::Closed);
        assert!(socket.recv_queue() > 0, "the guest's tail is still queued");
        engine.reap(std::time::Instant::now());

        let received = published.host_reads(&mut engine, uploaded.len());
        assert!(
            received == uploaded,
            "{} of {} bytes arrived",
            received.len(),
            uploaded.len()
        );
        assert!(engine.flows.is_empty(), "the finished flow was reclaimed");
    }

    /// Bytes the guest sent with the FIN that answers the host's outlast
    /// TIME_WAIT, however long the host takes to read them: the flow takes the
    /// guest socket out of TIME_WAIT keeping them, and smoltcp's own expiry of
    /// that state, which empties the socket, never comes.
    #[test]
    fn bytes_queued_for_the_host_outlast_time_wait() {
        let (tap, guest) = tap_pair();
        let mut engine = engine(tap, NetStack::default().plan, Vec::new());
        let mut published = Published::open(&mut engine, &guest);

        // The host finishes first, the guest uploads behind the stack's FIN,
        // and its own FIN brings the socket to TIME_WAIT with the upload still
        // queued for a host that has yet to read it.
        published.host_finishes(&mut engine, &guest);
        let uploaded = published.upload(&mut engine);
        published.guest_sends(&mut engine, TcpControl::Fin, &[]);
        let socket = published.socket(&engine);
        assert_eq!(
            socket.state(),
            tcp_socket::State::Closed,
            "the guest socket was left in TIME_WAIT",
        );
        assert!(socket.recv_queue() > 0, "the guest's tail is still queued");

        // The host reads nothing for far longer than smoltcp holds TIME_WAIT,
        // which is ten seconds.
        engine.reap(std::time::Instant::now());
        advance_clock(&mut engine, Duration::from_secs(30));
        engine
            .iface
            .poll(engine.now(), &mut engine.device, &mut engine.sockets);
        engine.service();
        engine.reap(std::time::Instant::now());

        let received = published.host_reads(&mut engine, uploaded.len());
        assert!(
            received == uploaded,
            "{} of {} bytes arrived",
            received.len(),
            uploaded.len()
        );
        assert!(engine.flows.is_empty(), "the finished flow was reclaimed");
    }

    /// A host-closes-first exchange whose host has taken everything ends its
    /// flow as the guest's FIN arrives, rather than holding a slot and two
    /// buffers through TIME_WAIT.
    #[test]
    fn a_finished_host_closes_first_exchange_releases_its_flow_at_once() {
        let (tap, guest) = tap_pair();
        let mut engine = engine(tap, NetStack::default().plan, Vec::new());
        let mut published = Published::open(&mut engine, &guest);

        published.host_finishes(&mut engine, &guest);
        published.guest_sends(&mut engine, TcpControl::Psh, b"the last word");
        published.guest_sends(&mut engine, TcpControl::Fin, &[]);
        engine.reap(std::time::Instant::now());
        assert!(engine.flows.is_empty(), "the finished flow is still held");
        assert_eq!(published.host_reads(&mut engine, 13), b"the last word");
    }
}
