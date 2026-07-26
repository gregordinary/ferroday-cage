//! TCP flow forwarding: one guest connection spliced onto one host socket.
//!
//! A flow is created when the pump sniffs a connection-opening segment: a
//! smoltcp socket is put in listening state on the sniffed destination
//! endpoint — so the interface's processing of that same segment lands on
//! it — and a nonblocking host connect toward the policy-mapped target
//! starts in parallel. After both sides establish, servicing copies bytes
//! directly between the smoltcp socket's buffers and the host socket, with
//! no intermediate staging: guest-to-host reads out of the socket's
//! receive buffer straight into `send` on the host descriptor, and
//! host-to-guest reads from the host descriptor straight into the socket's
//! transmit buffer.
//!
//! Each direction half-closes independently. A guest FIN, once the receive
//! buffer drains, becomes a write shutdown on the host socket; end of
//! stream from the host, once copied out, becomes a close of the smoltcp
//! socket, which sends the guest a FIN after the in-flight data. A failure
//! on either side — a failed or refused host connect, a host socket error,
//! a reset from the guest — aborts the other side. A flow that has not
//! established both sides within [`ESTABLISH_DEADLINE`] is aborted, which
//! bounds what a connection flood can pin.
//!
//! An established flow whose guest stops reading — filling the transmit buffer
//! so no forwarding is possible — stays watched for the host closing or
//! resetting, and is reclaimed when that happens. That watch alone does not
//! cover a peer that dies silently on an otherwise idle flow, so both sides
//! carry keep-alive: the guest-facing smoltcp socket has a
//! [`KEEP_ALIVE_INTERVAL`] keep-alive and an [`IDLE_TIMEOUT`], and the host
//! kernel socket is tuned to the same cadence. A peer that crashes without a
//! FIN or RST is then probed and, when it does not answer, the flow is aborted
//! and its slot, buffers, and host descriptor released. A flow both of whose
//! ends stay alive but idle is held until one side closes it or the sandbox
//! ends, bounded by [`MAX_FLOWS`]. That cap is per attachment: it bounds a
//! single guest's flows, not the caller process's total. The pump and every
//! host socket run in the caller's process, so several attachments in one
//! process share one descriptor table and one heap; the per-guest cap is a
//! guest's own budget, not a guarantee against a co-resident guest exhausting
//! the process. The process-shared resource model is set out in
//! `userspace-networking.md`.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use std::os::fd::OwnedFd;

use rustix::event::PollFlags;
use rustix::io::Errno;
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, sockopt};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;

/// The most guest TCP connections served at once. A connection attempt
/// past the cap is answered with a reset.
pub(super) const MAX_FLOWS: usize = 128;

/// Each smoltcp socket's receive and transmit buffer size. The receive
/// buffer also bounds how much a guest can send toward a slow host peer
/// before its window closes.
pub(super) const BUFFER_SIZE: usize = 64 * 1024;

/// How long a flow may sit with either side unestablished before it is
/// aborted.
pub(super) const ESTABLISH_DEADLINE: Duration = Duration::from_secs(30);

/// Seconds between keep-alive probes on an idle established flow. Held well
/// below [`IDLE_TIMEOUT`] so a live peer's answer to a probe resets the idle
/// clock inside the timeout window.
const KEEP_ALIVE_SECS: u64 = 25;

/// How often an idle established flow probes each peer for liveness.
///
/// The guest-facing smoltcp socket sends a keep-alive at this interval when
/// idle, and the host kernel socket is tuned to the same cadence. A live but
/// idle peer answers the probes, which resets the flow's idle clock and leaves
/// it alone; a peer that has crashed without a FIN or RST does not answer, and
/// after [`KEEP_ALIVE_COUNT`] unanswered probes the flow is reclaimed near
/// [`IDLE_TIMEOUT`].
pub(super) const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(KEEP_ALIVE_SECS);

/// Unanswered keep-alive probes tolerated before a flow's peer is declared
/// dead. Used directly as the host socket's `TCP_KEEPCNT`; the guest-facing
/// smoltcp socket has no probe counter of its own, so [`IDLE_TIMEOUT`]
/// expresses the same budget as a single duration.
pub(super) const KEEP_ALIVE_COUNT: u32 = 3;

/// How long an established flow tolerates silence from its peer before it is
/// aborted.
///
/// smoltcp measures this from the last segment *received* from the peer, not
/// from when probing begins, so it must exceed [`KEEP_ALIVE_INTERVAL`] for
/// keep-alive to function at all: a probe has to be sent, and answered by a
/// live peer, inside the window, or the timeout aborts the flow before any
/// probe goes out. Set to one interval past the last tolerated probe
/// (`KEEP_ALIVE_INTERVAL * (KEEP_ALIVE_COUNT + 1)`), so the guest-facing
/// timeout and the host socket's `TCP_KEEPIDLE + KEEP_ALIVE_COUNT *
/// TCP_KEEPINTVL` detection both land at the same point.
pub(super) const IDLE_TIMEOUT: Duration =
    Duration::from_secs(KEEP_ALIVE_SECS * (KEEP_ALIVE_COUNT as u64 + 1));

/// Keep-alive must fire, and be answerable, strictly before the idle timeout,
/// or the timeout aborts every idle flow before a single probe is sent. This
/// invariant is what keeps an idle-but-live flow alive, per the module
/// contract above.
const _: () = assert!(KEEP_ALIVE_INTERVAL.as_secs() < IDLE_TIMEOUT.as_secs());

/// What became of one servicing pass.
enum Copy {
    /// Bytes moved.
    Moved(usize),
    /// The descriptor would block.
    Blocked,
    /// End of stream.
    Finished,
    /// The descriptor failed.
    Failed,
}

/// One guest connection and its host side.
pub(super) struct TcpFlow {
    /// The guest-side smoltcp socket.
    pub(super) handle: SocketHandle,
    /// The guest endpoint, half of the flow's identity.
    pub(super) guest: IpEndpoint,
    /// The destination the guest addressed, the other half.
    pub(super) destination: IpEndpoint,
    /// The host-side socket, nonblocking from creation. Dropped once both
    /// half-closes complete, releasing the descriptor while the guest socket
    /// finishes its own close (TIME_WAIT) rather than holding it until then.
    host: Option<OwnedFd>,
    /// Whether the host connect has completed.
    connected: bool,
    /// The host poll events of the current pump iteration.
    pub(super) events: PollFlags,
    /// The host delivered end of stream.
    host_eof: bool,
    /// The guest's end of stream has been passed on as a host write
    /// shutdown.
    host_shutdown: bool,
    /// The host's end of stream has been passed on as a socket close.
    guest_closed: bool,
    /// When to give up on a flow that has not established both sides.
    deadline: Instant,
    /// The flow is finished; the pump reaps it and its socket.
    pub(super) dead: bool,
}

impl TcpFlow {
    /// Starts the host side of a flow: a nonblocking socket whose connect
    /// is initiated but typically not yet complete.
    pub(super) fn connect(
        handle: SocketHandle,
        guest: IpEndpoint,
        destination: IpEndpoint,
        target: SocketAddr,
        now: Instant,
    ) -> Result<TcpFlow, Errno> {
        let family = match target {
            SocketAddr::V4(_) => AddressFamily::INET,
            SocketAddr::V6(_) => AddressFamily::INET6,
        };
        let host = rustix::net::socket_with(
            family,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        // Enable keep-alive so a host peer that dies without a FIN or RST on an
        // otherwise idle flow is probed by the kernel and surfaced as a poll
        // error, which reclaims the flow rather than holding its descriptor
        // open indefinitely. Tuned to the same cadence as the guest-facing
        // socket. Best-effort: a kernel that refuses a tuning knob still runs
        // the connection, only with its default (longer) keep-alive timing.
        let _ = sockopt::set_socket_keepalive(&host, true);
        let _ = sockopt::set_tcp_keepidle(&host, KEEP_ALIVE_INTERVAL);
        let _ = sockopt::set_tcp_keepintvl(&host, KEEP_ALIVE_INTERVAL);
        let _ = sockopt::set_tcp_keepcnt(&host, KEEP_ALIVE_COUNT);
        let connected = match rustix::net::connect(&host, &target) {
            Ok(()) => true,
            Err(Errno::INPROGRESS) => false,
            Err(errno) => return Err(errno),
        };
        Ok(TcpFlow {
            handle,
            guest,
            destination,
            host: Some(host),
            connected,
            events: PollFlags::empty(),
            host_eof: false,
            host_shutdown: false,
            guest_closed: false,
            deadline: now + ESTABLISH_DEADLINE,
            dead: false,
        })
    }

    /// The host descriptor, for the pump's poll set. `None` once both
    /// half-closes have completed and the descriptor has been released.
    pub(super) fn host(&self) -> Option<&OwnedFd> {
        self.host.as_ref()
    }

    /// How long until this flow's establish deadline, for the pump's poll
    /// timeout; `None` once established (or finished), when no deadline
    /// applies.
    pub(super) fn deadline_in(&self, socket: &tcp::Socket, now: Instant) -> Option<Duration> {
        if self.dead || self.established(socket) {
            return None;
        }
        Some(self.deadline.saturating_duration_since(now))
    }

    /// The poll interest of the host descriptor right now, judged against
    /// the guest socket's state.
    pub(super) fn interest(&self, socket: &tcp::Socket) -> PollFlags {
        if self.dead {
            return PollFlags::empty();
        }
        if !self.connected {
            // A completing connect reports writability (or an error).
            return PollFlags::OUT;
        }
        let mut interest = PollFlags::empty();
        if !self.host_eof && socket.can_send() {
            interest |= PollFlags::IN;
        }
        if !self.host_shutdown && socket.can_recv() {
            // Guest bytes are waiting because an earlier host send did not
            // take them; wake when the host can.
            interest |= PollFlags::OUT;
        }
        // Watch for the host closing or resetting even when the guest has
        // stopped draining the transmit buffer, so `can_send()` is false and
        // no IN interest is set above. Without this the flow would leave the
        // poll set entirely and a dead host side would never be noticed.
        // RDHUP reports the peer's FIN; POLLERR and POLLHUP are reported
        // whenever the descriptor is in the set at all.
        if !self.host_eof {
            interest |= PollFlags::RDHUP;
        }
        interest
    }

    /// Moves the flow forward: connect completion, both copy directions,
    /// and shutdown propagation. Returns whether anything moved.
    pub(super) fn service(&mut self, socket: &mut tcp::Socket) -> bool {
        if self.dead {
            return false;
        }
        let mut progress = false;

        if !self.connected {
            if !self
                .events
                .intersects(PollFlags::OUT | PollFlags::ERR | PollFlags::HUP)
            {
                return false;
            }
            // Writability on a connecting socket means the connect
            // concluded; SO_ERROR says how. The host descriptor is always
            // present here — it is released only after both half-closes, well
            // past the connect.
            let socket_error = match self.host.as_ref() {
                Some(host) => sockopt::socket_error(host),
                None => Ok(Err(Errno::NOTCONN)),
            };
            match socket_error {
                Ok(Ok(())) => {
                    self.connected = true;
                    progress = true;
                }
                Ok(Err(_)) | Err(_) => {
                    // The destination is unreachable or refused; the guest
                    // learns through a reset.
                    socket.abort();
                    self.dead = true;
                    return true;
                }
            }
        }

        progress |= self.guest_to_host(socket);
        if self.dead {
            return true;
        }
        progress |= self.host_to_guest(socket);
        if self.dead {
            return true;
        }

        // When the guest has stopped draining the transmit buffer,
        // `host_to_guest` cannot run, so it never observes the host closing or
        // resetting. A hangup or error reported by poll while the buffer stays
        // full means the host side is finished and the guest is not consuming
        // it: reclaim the flow rather than hold the host descriptor and its
        // peer open indefinitely. With room in the buffer the ordinary read
        // path handles a host FIN through an end-of-stream, so this stays
        // scoped to the stalled case.
        if !self.host_eof
            && !socket.can_send()
            && self
                .events
                .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP)
        {
            socket.abort();
            self.dead = true;
            return true;
        }

        // Both directions have half-closed: the host socket is done both ways,
        // so release its descriptor now rather than hold it while the guest
        // socket works through its own close (TIME_WAIT). The flow lingers
        // until the guest side reaches Closed, but no host descriptor with it.
        if self.host_eof && self.host_shutdown && self.host.is_some() {
            self.host = None;
            progress = true;
        }

        // A fully closed guest socket ends the flow; dropping the host
        // descriptor with it releases the host side.
        if socket.state() == tcp::State::Closed {
            self.dead = true;
            progress = true;
        }
        progress
    }

    /// Whether both sides are past their handshakes.
    fn established(&self, socket: &tcp::Socket) -> bool {
        self.connected
            && !matches!(
                socket.state(),
                tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
            )
    }

    /// Aborts the flow if it has not established both sides by `now`.
    pub(super) fn enforce_deadline(&mut self, socket: &mut tcp::Socket, now: Instant) {
        if !self.dead && !self.established(socket) && now >= self.deadline {
            socket.abort();
            self.dead = true;
        }
    }

    /// Copies guest bytes to the host and propagates the guest's end of
    /// stream. Returns whether anything moved.
    fn guest_to_host(&mut self, socket: &mut tcp::Socket) -> bool {
        // The descriptor is released only after both half-closes, at which
        // point `host_shutdown` is already set and this does nothing.
        let Some(host) = self.host.as_ref() else {
            return false;
        };
        let mut progress = false;
        while socket.can_recv() && !self.host_shutdown {
            let outcome =
                socket.recv(
                    |buf| match rustix::net::send(host, buf, SendFlags::NOSIGNAL) {
                        Ok(sent) => (sent, Copy::Moved(sent)),
                        Err(Errno::AGAIN | Errno::INTR) => (0, Copy::Blocked),
                        Err(_) => (0, Copy::Failed),
                    },
                );
            match outcome {
                Ok(Copy::Moved(0)) | Ok(Copy::Blocked) => break,
                Ok(Copy::Moved(_)) => progress = true,
                Ok(Copy::Failed) => {
                    // The host side is gone; reset the guest.
                    socket.abort();
                    self.dead = true;
                    return true;
                }
                Ok(Copy::Finished) => unreachable!("a socket read does not produce Finished"),
                Err(tcp::RecvError::Finished | tcp::RecvError::InvalidState) => break,
            }
        }
        // The guest has finished sending and everything it sent has been
        // passed on: half-close the host side once.
        if !self.host_shutdown && self.connected && !socket.may_recv() && socket.recv_queue() == 0 {
            let _ = rustix::net::shutdown(host, rustix::net::Shutdown::Write);
            self.host_shutdown = true;
            progress = true;
        }
        progress
    }

    /// Copies host bytes to the guest and propagates the host's end of
    /// stream. Returns whether anything moved.
    fn host_to_guest(&mut self, socket: &mut tcp::Socket) -> bool {
        // Released only after both half-closes, by which point `host_eof` is
        // set and this does nothing.
        let Some(host) = self.host.as_ref() else {
            return false;
        };
        let mut progress = false;
        while !self.host_eof && socket.can_send() && self.events.contains(PollFlags::IN) {
            let outcome = socket.send(|buf| {
                match rustix::net::recv(host, &mut buf[..], RecvFlags::empty()) {
                    Ok((0, _)) => (0, Copy::Finished),
                    Ok((read, _)) => (read, Copy::Moved(read)),
                    Err(Errno::AGAIN | Errno::INTR) => (0, Copy::Blocked),
                    Err(_) => (0, Copy::Failed),
                }
            });
            match outcome {
                Ok(Copy::Moved(_)) => progress = true,
                Ok(Copy::Blocked) => break,
                Ok(Copy::Finished) => {
                    self.host_eof = true;
                    progress = true;
                }
                Ok(Copy::Failed) => {
                    // The host reset; pass the reset on to the guest.
                    socket.abort();
                    self.dead = true;
                    return true;
                }
                Err(tcp::SendError::InvalidState) => break,
            }
        }
        // Everything the host sent has been handed to the guest socket:
        // close it once, which sends a FIN after the in-flight data.
        if self.host_eof && !self.guest_closed {
            socket.close();
            self.guest_closed = true;
            progress = true;
        }
        progress
    }
}

#[cfg(test)]
mod tests {
    use smoltcp::iface::SocketSet;
    use smoltcp::wire::IpAddress;

    use super::*;

    /// A socket set holding one guest-facing TCP socket, with its handle.
    ///
    /// The socket starts Closed; a test that wants a half-open guest calls
    /// `listen` on it. Reaching Established needs a peer and an interface, so
    /// the copy loops themselves are the integration suite's to cover; what is
    /// here is the bookkeeping around them.
    fn guest_socket() -> (SocketSet<'static>, SocketHandle) {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 1024]),
            tcp::SocketBuffer::new(vec![0; 1024]),
        ));
        (sockets, handle)
    }

    /// A flow whose host side is one end of a connected socket pair, with the
    /// other end returned so a test can observe what the flow does to it.
    ///
    /// The pair stands in for a connected host socket: it carries bytes and
    /// honours a write shutdown, which is all the flow asks of it.
    fn connected_flow(handle: SocketHandle) -> (TcpFlow, OwnedFd) {
        let (host, peer) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket pair stands in for the host side");
        let endpoint = |port| IpEndpoint::new(IpAddress::v4(10, 0, 2, 15), port);
        (
            TcpFlow {
                handle,
                guest: endpoint(40_000),
                destination: endpoint(80),
                host: Some(host),
                connected: true,
                events: PollFlags::empty(),
                host_eof: false,
                host_shutdown: false,
                guest_closed: false,
                deadline: Instant::now() + ESTABLISH_DEADLINE,
                dead: false,
            },
            peer,
        )
    }

    /// Whether the peer end of the flow's host pair has reached end of stream,
    /// which is how the flow's write shutdown shows up from outside.
    fn peer_at_eof(peer: &OwnedFd) -> bool {
        let mut buf = [0u8; 1];
        matches!(
            rustix::net::recv(peer, &mut buf, RecvFlags::empty()),
            Ok((0, _))
        )
    }

    #[test]
    fn a_dead_flow_asks_for_nothing() {
        // A dead flow's descriptor is about to be released; leaving it in the
        // poll set with an interest would wake the pump for nothing.
        let (mut sockets, handle) = guest_socket();
        let (mut flow, _peer) = connected_flow(handle);
        flow.dead = true;
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        assert_eq!(flow.interest(socket), PollFlags::empty());
    }

    #[test]
    fn a_connecting_flow_waits_for_writability() {
        // A connect in progress concludes as writability, whatever the guest
        // side is doing; nothing else is worth waking for until it does.
        let (mut sockets, handle) = guest_socket();
        let (mut flow, _peer) = connected_flow(handle);
        flow.connected = false;
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        assert_eq!(flow.interest(socket), PollFlags::OUT);
    }

    #[test]
    fn a_stalled_flow_still_watches_for_the_host_hanging_up() {
        // The guest is not draining, so the transmit buffer is full and no
        // forwarding is possible. Without the RDHUP interest the flow would
        // leave the poll set and a host side that died would never be noticed.
        let (mut sockets, handle) = guest_socket();
        let (mut flow, _peer) = connected_flow(handle);
        {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            socket
                .listen(IpEndpoint::new(IpAddress::v4(10, 0, 2, 15), 80))
                .expect("a fresh socket listens");
            assert!(
                !socket.can_send() && !socket.can_recv(),
                "neither direction"
            );
            assert_eq!(flow.interest(socket), PollFlags::RDHUP);
        }

        // Once the host has delivered its end of stream there is nothing left
        // to hear from it, and the watch is dropped with the interest.
        flow.host_eof = true;
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        assert_eq!(flow.interest(socket), PollFlags::empty());
    }

    #[test]
    fn a_finished_guest_half_closes_the_host_write_side() {
        // The guest will send no more and everything it sent has been passed
        // on, so the host peer must see end of stream rather than wait on a
        // descriptor nothing will write to again.
        let (mut sockets, handle) = guest_socket();
        let (mut flow, peer) = connected_flow(handle);
        let socket = sockets.get_mut::<tcp::Socket>(handle);

        assert!(flow.service(socket), "the half-close is progress");
        assert!(flow.host_shutdown, "the host write side is shut down");
        assert!(peer_at_eof(&peer), "the host peer sees end of stream");
        // A closed guest socket ends the flow; the pump reaps it next pass.
        assert!(flow.dead);
    }

    #[test]
    fn a_stalled_flow_is_reclaimed_when_the_host_hangs_up() {
        // The stalled case again, now with the hangup actually reported: the
        // ordinary read path cannot run, so this is the only thing that
        // releases the descriptor and its peer.
        let (mut sockets, handle) = guest_socket();
        let (mut flow, _peer) = connected_flow(handle);
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        socket
            .listen(IpEndpoint::new(IpAddress::v4(10, 0, 2, 15), 80))
            .expect("a fresh socket listens");
        flow.events = PollFlags::RDHUP;

        assert!(flow.service(socket));
        assert!(flow.dead, "the flow is reclaimed rather than left stalled");
    }

    #[test]
    fn an_unestablished_flow_reports_the_time_left_and_then_zero() {
        // The pump takes the smallest deadline as its poll timeout, so an
        // elapsed deadline must report zero rather than underflow.
        let (mut sockets, handle) = guest_socket();
        let (mut flow, _peer) = connected_flow(handle);
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        socket
            .listen(IpEndpoint::new(IpAddress::v4(10, 0, 2, 15), 80))
            .expect("a fresh socket listens");
        let start = flow.deadline - ESTABLISH_DEADLINE;

        assert_eq!(flow.deadline_in(socket, start), Some(ESTABLISH_DEADLINE));
        assert_eq!(
            flow.deadline_in(socket, flow.deadline + Duration::from_secs(1)),
            Some(Duration::ZERO)
        );

        // A dead flow has no deadline either: it is about to be reaped.
        flow.dead = true;
        assert_eq!(flow.deadline_in(socket, start), None);
    }

    #[test]
    fn the_deadline_aborts_only_a_flow_that_never_established() {
        let (mut sockets, handle) = guest_socket();
        let (mut flow, _peer) = connected_flow(handle);
        let expired = flow.deadline + Duration::from_secs(1);
        {
            // Still listening: the guest never completed its handshake, so the
            // flow is aborted and its slot released.
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            socket
                .listen(IpEndpoint::new(IpAddress::v4(10, 0, 2, 15), 80))
                .expect("a fresh socket listens");
            assert_eq!(
                flow.deadline_in(socket, flow.deadline),
                Some(Duration::ZERO)
            );
            flow.enforce_deadline(socket, expired);
            assert!(flow.dead);
        }

        // A flow past both handshakes carries no deadline at all, so the same
        // instant leaves it alone.
        let (mut sockets, handle) = guest_socket();
        let (mut flow, _peer) = connected_flow(handle);
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        assert_eq!(flow.deadline_in(socket, expired), None);
        flow.enforce_deadline(socket, expired);
        assert!(!flow.dead, "an established flow outlives the deadline");
    }

    #[test]
    fn keep_alive_probes_fit_inside_the_idle_timeout() {
        // smoltcp measures the idle timeout from the last segment received,
        // not from when probing starts, so the budget has to hold every
        // tolerated probe and leave room for the answer. The `const` assertion
        // above pins the inequality; this pins the arithmetic behind it.
        assert_eq!(
            IDLE_TIMEOUT,
            KEEP_ALIVE_INTERVAL * (KEEP_ALIVE_COUNT + 1),
            "the idle budget is one interval past the last tolerated probe"
        );
    }
}
