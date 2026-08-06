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
//! socket, which sends the guest a FIN after the in-flight data. Where the
//! host closed first the guest's answering FIN leaves the smoltcp socket in
//! TIME_WAIT, which the flow collapses rather than hold a slot through (see
//! [`TcpFlow::only_time_wait_remains`]). A failure on either side — a failed
//! or refused host connect, a host socket error, a reset from the guest —
//! aborts the other side. A flow that has not established both sides within
//! [`ESTABLISH_DEADLINE`] is aborted, which bounds what a connection flood
//! can pin.
//!
//! An established flow whose guest stops reading fills the transmit buffer, so
//! no forwarding is possible until the guest reads again. Such a flow stays
//! watched for the host erroring or hanging up. An error is terminal and aborts
//! the flow at once. A hangup is not: the kernel reports the host's FIN the
//! moment it arrives, while unread bytes are still queued both in the receive
//! buffer and in the transmit buffer, so forwarding continues as the buffer
//! reopens and it is the eventual read of zero — not the hangup — that ends the
//! stream. What the hangup starts is a [`HANGUP_DEADLINE`], measured from the
//! last byte moved, past which a guest that never drains is reclaimed. Neither
//! covers a peer that dies silently on an otherwise idle flow, so both sides
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

/// How long a flow whose host side has hung up may go without moving a byte
/// before it is reclaimed.
///
/// A hangup says nothing on its own about whether the bytes still queued behind
/// it are wanted: a bulk transfer ending in a prompt close is exactly that
/// shape, and its tail is still being acknowledged when the FIN is reported.
/// What the hangup bounds is patience. A guest that establishes a flow and then
/// never reads holds the transmit buffer full indefinitely while answering
/// keep-alive probes, so [`IDLE_TIMEOUT`] never fires; this deadline is what
/// releases the slot, its buffers, and the host descriptor. Measured from the
/// last byte moved, so a flow that is draining, however slowly, is left alone;
/// the budget is the idle timeout's, for one silence tolerance across the
/// module.
pub(super) const HANGUP_DEADLINE: Duration = IDLE_TIMEOUT;

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
    /// half-closes complete, so the descriptor is released the moment the host
    /// side is done rather than held while the guest socket finishes its own
    /// close.
    host: Option<OwnedFd>,
    /// Whether the host connect has completed.
    connected: bool,
    /// The host poll events of the current pump iteration.
    pub(super) events: PollFlags,
    /// The host delivered end of stream.
    host_eof: bool,
    /// Poll reported the host's hangup. The descriptor stays readable from
    /// then on — data, then end of stream — so the watch for it is retired
    /// and reads no longer wait on a readability report.
    host_hangup: bool,
    /// The guest's end of stream has been passed on as a host write
    /// shutdown.
    host_shutdown: bool,
    /// The host's end of stream has been passed on as a socket close.
    guest_closed: bool,
    /// When to give up on a flow that has not established both sides.
    deadline: Instant,
    /// When a hung-up host side first found no room in the guest's transmit
    /// buffer; `None` whenever the flow can still move a byte. Bounds a guest
    /// that never drains, per [`HANGUP_DEADLINE`].
    stalled_since: Option<Instant>,
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
        // socket.
        //
        // Best-effort, and a refusal costs differently at each call. A refused
        // tuning knob leaves the kernel's own, much longer cadence, so the flow
        // is still reclaimed, late. A refused enable leaves no probing at all:
        // the guest answers the probes its own side of the flow sends, so
        // [`IDLE_TIMEOUT`] does not fire either, and the flow is held until the
        // guest closes it or the sandbox ends, bounded only by [`MAX_FLOWS`].
        // Neither is reachable through the kernel — every value here is a
        // constant inside the range it accepts — and neither is a reason to
        // refuse to forward the guest's traffic.
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
            host_hangup: false,
            host_shutdown: false,
            guest_closed: false,
            deadline: now + ESTABLISH_DEADLINE,
            stalled_since: None,
            dead: false,
        })
    }

    /// The host descriptor, for the pump's poll set. `None` once both
    /// half-closes have completed and the descriptor has been released.
    pub(super) fn host(&self) -> Option<&OwnedFd> {
        self.host.as_ref()
    }

    /// How long until this flow's next deadline, for the pump's poll timeout.
    ///
    /// Before both sides establish that is the establish deadline; afterwards
    /// it is the hangup deadline of a flow stalled against a guest that is not
    /// draining. `None` when neither applies, which is the ordinary case: a
    /// live flow is woken by its descriptors, not by a timer.
    pub(super) fn deadline_in(&self, socket: &tcp::Socket, now: Instant) -> Option<Duration> {
        if self.dead {
            return None;
        }
        if !self.established(socket) {
            return Some(self.deadline.saturating_duration_since(now));
        }
        self.stalled_since
            .map(|since| (since + HANGUP_DEADLINE).saturating_duration_since(now))
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
        // whenever the descriptor is in the set at all. Once the hangup has
        // been reported the watch has nothing left to say, and keeping it would
        // wake the pump on every pass — RDHUP is level-triggered — for a flow
        // that cannot move until the guest reads. The remaining bytes are
        // drained by the read path and the stall is bounded by
        // [`HANGUP_DEADLINE`], which the pump folds into its poll timeout.
        if !self.host_eof && !self.host_hangup {
            interest |= PollFlags::RDHUP;
        }
        interest
    }

    /// Moves the flow forward: connect completion, both copy directions,
    /// and shutdown propagation. Returns whether anything moved.
    pub(super) fn service(&mut self, socket: &mut tcp::Socket, now: Instant) -> bool {
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

        // A poll error is terminal: the host socket has failed, every read of it
        // would return that error rather than data, and the guest learns
        // through a reset.
        if !self.host_eof && self.events.contains(PollFlags::ERR) {
            socket.abort();
            self.dead = true;
            return true;
        }
        // A hangup is not terminal. It is reported the moment the host's FIN
        // arrives, with data still queued in the receive buffer and in the
        // guest's transmit buffer, so the read path below carries on until
        // `recv` returns zero and turns *that* into the guest's FIN. Recording
        // the hangup retires the RDHUP watch and makes the host descriptor
        // worth reading without a readability report, since from here it is
        // permanently readable.
        if !self.host_eof && self.events.intersects(PollFlags::HUP | PollFlags::RDHUP) {
            self.host_hangup = true;
        }

        progress |= self.guest_to_host(socket);
        if self.dead {
            return true;
        }
        progress |= self.host_to_guest(socket);
        if self.dead {
            return true;
        }

        // A hung-up host side with no room left in the guest's transmit buffer
        // can move nothing until the guest reads. That is ordinary mid-transfer
        // and resolves itself; a guest that never reads at all does not, and
        // keep-alive will not reclaim it because it answers the probes. Time
        // the stall from the moment it starts and clear it the moment the flow
        // can move again; `enforce_deadline` reclaims what stays stuck.
        if !self.host_eof && self.host_hangup && !socket.can_send() {
            self.stalled_since.get_or_insert(now);
        } else {
            self.stalled_since = None;
        }

        // Both directions have half-closed: the host socket is done both ways,
        // so release its descriptor now rather than hold it while the guest
        // socket works through its own close.
        if self.host_eof && self.host_shutdown && self.host.is_some() {
            self.host = None;
            progress = true;
        }

        // Nothing is left of the flow but the guest-facing socket's TIME_WAIT,
        // so collapse it and end the flow here.
        if self.only_time_wait_remains(socket.state()) {
            socket.abort();
        }

        // A fully closed guest socket ends the flow; dropping the host
        // descriptor with it releases the host side.
        if socket.state() == tcp::State::Closed {
            self.dead = true;
            progress = true;
        }
        progress
    }

    /// Whether the exchange is over and only the guest-facing socket's
    /// TIME_WAIT is still holding the flow's slot.
    ///
    /// That is the state a host-closes-first exchange ends in — `Connection:
    /// close` HTTP and most short request/response protocols — because the
    /// stack sends the first FIN and the guest answers it. smoltcp then holds
    /// the socket in TIME_WAIT for ten seconds, over which the flow would go on
    /// counting against [`MAX_FLOWS`] and pinning its two [`BUFFER_SIZE`]
    /// buffers: a sustained rate above `MAX_FLOWS` per ten seconds would fill
    /// the table with remnants and see every further connection refused. The
    /// flow is collapsed instead, which also keeps a fresh connection reusing
    /// the same endpoint pair from being taken for a retransmission of the
    /// finished one.
    ///
    /// Collapsing is safe because of what this link is. TIME_WAIT absorbs
    /// delayed duplicates from an earlier incarnation of the connection and
    /// covers the loss of the final acknowledgement. Neither can happen between
    /// a guest kernel, one tap queue, and this pump: the path is single-hop and
    /// in order, so no segment can arrive late, and the guest's kernel finishes
    /// its own close on its own schedule. The abort emits at most a reset, which
    /// arrives at a socket the guest has already closed and is discarded.
    ///
    /// Both half-closes must be complete, not merely the socket's state: a guest
    /// that sends data and its FIN together reaches TIME_WAIT with bytes still
    /// queued for the host, and those are forwarded — which is what sets
    /// `host_shutdown` — before the flow is finished with.
    fn only_time_wait_remains(&self, state: tcp::State) -> bool {
        self.host_eof && self.host_shutdown && state == tcp::State::TimeWait
    }

    /// Whether both sides are past their handshakes.
    fn established(&self, socket: &tcp::Socket) -> bool {
        self.connected
            && !matches!(
                socket.state(),
                tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
            )
    }

    /// Aborts the flow if it has run out of time: the establish deadline before
    /// both sides are up, the hangup deadline for a stall that never resolves.
    pub(super) fn enforce_deadline(&mut self, socket: &mut tcp::Socket, now: Instant) {
        if self.dead {
            return;
        }
        let expired = if self.established(socket) {
            self.stalled_since
                .is_some_and(|since| now >= since + HANGUP_DEADLINE)
        } else {
            now >= self.deadline
        };
        if expired {
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
        // passed on: half-close the host side once. Gated on both sides being
        // past their handshakes, because a socket still in Listen, SynSent, or
        // SynReceived also reports that it may not receive — the guest has yet
        // to say anything, not finished saying it. Without the gate a host
        // connect that concludes before the guest's ACK is ingested (a loopback
        // target against a tap round trip, say) would shut the host write side
        // down before the guest had sent its request, and the flow would linger
        // to the idle timeout with nothing forwarded.
        if !self.host_shutdown
            && self.established(socket)
            && !socket.may_recv()
            && socket.recv_queue() == 0
        {
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
        // A hung-up host descriptor is readable from then on — the queued data,
        // then end of stream — so it is read whether or not this pass polled
        // for readability. That matters when the transmit buffer was full at
        // the last poll: the flow then asked for nothing, and the room the
        // guest has since made would otherwise go unused for a whole iteration.
        while !self.host_eof
            && socket.can_send()
            && (self.host_hangup || self.events.contains(PollFlags::IN))
        {
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
                host_hangup: false,
                host_shutdown: false,
                guest_closed: false,
                deadline: Instant::now() + ESTABLISH_DEADLINE,
                stalled_since: None,
                dead: false,
            },
            peer,
        )
    }

    /// A socket set whose socket is listening, the state a flow's guest side
    /// occupies from the sniffed connection attempt until the guest's ACK is
    /// ingested. Distinct from a fresh socket's Closed, which counts as past
    /// the handshake.
    fn listening_socket() -> (SocketSet<'static>, SocketHandle) {
        let (mut sockets, handle) = guest_socket();
        sockets
            .get_mut::<tcp::Socket>(handle)
            .listen(IpEndpoint::new(IpAddress::v4(10, 0, 2, 15), 80))
            .expect("a fresh socket listens");
        (sockets, handle)
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
        let (mut sockets, handle) = listening_socket();
        let (mut flow, _peer) = connected_flow(handle);
        {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
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

        assert!(
            flow.service(socket, Instant::now()),
            "the half-close is progress"
        );
        assert!(flow.host_shutdown, "the host write side is shut down");
        assert!(peer_at_eof(&peer), "the host peer sees end of stream");
        // A closed guest socket ends the flow; the pump reaps it next pass.
        assert!(flow.dead);
    }

    #[test]
    fn the_host_write_side_waits_for_the_guests_handshake() {
        // A guest still handshaking has not finished sending — it has not
        // started. Reading its "may not receive" as end of stream would shut
        // the host write side down before the request, which the host answers
        // with an immediate EOF, and would permanently disable the
        // guest-to-host copy so the request could never be forwarded.
        let (mut sockets, handle) = listening_socket();
        let (mut flow, peer) = connected_flow(handle);
        let socket = sockets.get_mut::<tcp::Socket>(handle);

        flow.service(socket, Instant::now());
        assert!(!flow.host_shutdown, "the guest has yet to say anything");
        assert!(!peer_at_eof(&peer), "the host peer sees no end of stream");
        assert!(!flow.dead);
    }

    #[test]
    fn a_stalled_flow_survives_the_host_hanging_up() {
        // The hangup is reported the instant the host's FIN arrives, with the
        // transfer's tail still queued in both buffers. Aborting there resets
        // the guest and destroys every buffered byte, so the flow keeps its
        // descriptor and starts the clock that bounds a guest which never
        // drains instead.
        let (mut sockets, handle) = listening_socket();
        let (mut flow, _peer) = connected_flow(handle);
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        flow.events = PollFlags::RDHUP;
        let now = Instant::now();

        flow.service(socket, now);
        assert!(!flow.dead, "a hangup alone destroys nothing");
        assert!(flow.host_hangup, "the hangup is remembered");
        assert_eq!(flow.stalled_since, Some(now), "the stall clock is running");
        // The watch has said all it has to say, and RDHUP is level-triggered:
        // holding it would wake the pump on every pass for a flow that cannot
        // move until the guest reads.
        assert_eq!(flow.interest(socket), PollFlags::empty());
    }

    #[test]
    fn a_host_error_aborts_the_flow_at_once() {
        // Unlike a hangup, an error leaves nothing to read: every recv would
        // return it. The guest learns through a reset rather than waiting out
        // the hangup deadline.
        let (mut sockets, handle) = listening_socket();
        let (mut flow, _peer) = connected_flow(handle);
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        flow.events = PollFlags::ERR;

        assert!(flow.service(socket, Instant::now()));
        assert!(flow.dead, "a failed host side is not worth draining");
    }

    #[test]
    fn a_guest_that_never_drains_is_reclaimed_at_the_hangup_deadline() {
        // Keep-alive cannot reclaim this flow: the guest is alive and answers
        // the probes, it simply never reads. The deadline is what releases the
        // slot, its buffers, and the host descriptor.
        let (mut sockets, handle) = guest_socket();
        let (mut flow, _peer) = connected_flow(handle);
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        let stalled_at = Instant::now();
        flow.host_hangup = true;
        flow.stalled_since = Some(stalled_at);

        // The pump sleeps no longer than what is left of the deadline, since a
        // stalled flow is out of the poll set entirely.
        assert_eq!(flow.deadline_in(socket, stalled_at), Some(HANGUP_DEADLINE));
        flow.enforce_deadline(
            socket,
            stalled_at + HANGUP_DEADLINE - Duration::from_secs(1),
        );
        assert!(!flow.dead, "the deadline has not fallen due");
        flow.enforce_deadline(socket, stalled_at + HANGUP_DEADLINE);
        assert!(flow.dead);
    }

    #[test]
    fn an_unestablished_flow_reports_the_time_left_and_then_zero() {
        // The pump takes the smallest deadline as its poll timeout, so an
        // elapsed deadline must report zero rather than underflow.
        let (mut sockets, handle) = listening_socket();
        let (mut flow, _peer) = connected_flow(handle);
        let socket = sockets.get_mut::<tcp::Socket>(handle);
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
        let (mut sockets, handle) = listening_socket();
        let (mut flow, _peer) = connected_flow(handle);
        let expired = flow.deadline + Duration::from_secs(1);
        {
            // Still listening: the guest never completed its handshake, so the
            // flow is aborted and its slot released.
            let socket = sockets.get_mut::<tcp::Socket>(handle);
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
    fn a_finished_close_is_collapsed_out_of_time_wait() {
        // A host-closes-first exchange ends with the guest-facing socket in
        // TIME_WAIT, where it would hold a flow slot and two buffers for ten
        // seconds. Once both half-closes are through there is nothing left to
        // wait for, and the flow says so.
        let (_sockets, handle) = guest_socket();
        let (mut flow, _peer) = connected_flow(handle);
        flow.host_eof = true;
        flow.host_shutdown = true;
        assert!(flow.only_time_wait_remains(tcp::State::TimeWait));

        // Every earlier state has something still outstanding: an
        // acknowledgement, the guest's own FIN, or live traffic.
        for state in [
            tcp::State::Established,
            tcp::State::FinWait1,
            tcp::State::FinWait2,
            tcp::State::Closing,
            tcp::State::CloseWait,
            tcp::State::LastAck,
            tcp::State::Closed,
        ] {
            assert!(!flow.only_time_wait_remains(state), "{state}");
        }
    }

    #[test]
    fn a_time_wait_socket_with_bytes_still_to_forward_is_left_alone() {
        // The guest may send data after the stack's FIN and close in the same
        // breath, which reaches TIME_WAIT with those bytes still queued for the
        // host. Collapsing on the state alone would discard them; the host
        // half-close is what says they have been passed on.
        let (_sockets, handle) = guest_socket();
        let (mut flow, _peer) = connected_flow(handle);
        flow.host_eof = true;
        assert!(!flow.only_time_wait_remains(tcp::State::TimeWait));
        flow.host_shutdown = true;
        assert!(flow.only_time_wait_remains(tcp::State::TimeWait));
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
