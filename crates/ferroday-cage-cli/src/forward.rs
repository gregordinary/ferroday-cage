//! `--forward-loopback`: a port on the sandbox's loopback whose connections
//! arrive at a target on the host.
//!
//! The library makes the listener: [`Pending::listen`] creates it in the
//! sandbox's network namespace and hands it to `fcage`, which accepts the
//! connections the command makes and carries each one to the target. Nothing
//! of `fcage`'s runs inside the sandbox. The copy is this module's, over the
//! public API, and the library offers none.
//!
//! # One thread a forward
//!
//! A forward is one thread, however many connections the command makes. The
//! thread waits in one `poll` on the stop pipe, the listener, each connection
//! to the target still being made, and each connection being carried. Every
//! socket it holds is non-blocking, so nothing it does waits on a peer, and
//! closing the stop pipe ends it at its next wakeup, whatever the target or the
//! command's end of a connection is doing. Ending it closes the listener, which
//! keeps the sandbox's network namespace alive, and resets every connection it
//! holds: the run's end ends every forwarded connection.
//!
//! # Bounds
//!
//! - A forward holds at most [`MAX_CONNECTIONS`] connections at once, counting
//!   those whose connection to the target is still being made. A connection
//!   accepted past that is closed at once. The first one is reported on
//!   standard error, naming the bound, and the rest are not, so a command that
//!   keeps connecting does not flood standard error.
//! - A connection to the target not made within [`ESTABLISH_DEADLINE`] is
//!   abandoned: the command's connection is reset, and the failure reported,
//!   as a target that refuses is. Only the first failure of a run of them is
//!   reported, until a connection to the target is made again, so a command
//!   that keeps connecting to a target that is down does not flood standard
//!   error either. A TCP connect runs in the background and
//!   reports its end as writability. A unix socket whose accept queue is full
//!   answers a non-blocking connect with `EAGAIN` at once instead, and leaves
//!   nothing to wait on, so the connect is made again every [`CONNECT_RETRY`].
//! - Each direction of a carried connection holds at most [`BUFFER_SIZE`]
//!   bytes. A side is read only while its direction has room, and written only
//!   while its direction holds something, so a peer that stops reading stalls
//!   the direction toward it, with no more than that held for it.
//!
//! # Half-close
//!
//! Each direction ends on its own. The end of one side's input is passed on as
//! a shutdown of the other side's sending half once everything read before it
//! has been written, and the other direction carries on: a command that sends
//! a request and shuts down its sending half still receives the reply. A
//! connection is closed once both directions have ended.
//!
//! # A connection that does not end in order ends in a reset
//!
//! A connection ends in order only where both directions have ended. Every
//! other end resets each side the forward holds: a failure of either side, a
//! target that refuses the connection or does not take it in time, and the
//! forward's own end with the connection still open. Closing those plainly
//! would hand each peer an end of stream after whatever arrived, and a peer
//! reading to the end would take a cut-off stream for a complete one. A zero
//! linger makes the close a reset instead, as the library's network stack does
//! for a flow. A unix socket has no reset to send, so a unix target reads an
//! end of stream all the same.
//!
//! A connection past the budget is closed rather than reset, as the network
//! stack closes one past a published port's budget: it never reached a target,
//! and the command reads its end before any byte.

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ferroday_cage::{ErrorChain, Pending};
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, Shutdown, SocketAddrUnix, SocketFlags, SocketType, sockopt,
};
use rustix::pipe::{self, PipeFlags};

use crate::{Failure, output};

/// The most connections one forward holds at once, counting those whose
/// connection to the target is still being made. A connection accepted past it
/// is closed at once.
///
/// The figure is the network stack's budget for the connections through its
/// published ports, which answer the same question from the other side. That
/// budget is the library's own and private to it, and a forward is `fcage`'s,
/// built over the public API, so it states its own.
const MAX_CONNECTIONS: usize = 128;

/// How long a connection to the target may take to be made before it is
/// abandoned and the command's connection closed.
///
/// The network stack's deadline for establishing a flow, for the reason
/// [`MAX_CONNECTIONS`] gives: a connection a target never takes holds a place
/// in the budget, and this bounds how long.
const ESTABLISH_DEADLINE: Duration = Duration::from_secs(30);

/// How often a connection to a unix socket whose accept queue was full is made
/// again, until [`ESTABLISH_DEADLINE`].
///
/// A non-blocking connect to such a socket fails with `EAGAIN` rather than
/// completing later, and the socket polls as ready at once, so there is nothing
/// to wait on but time.
const CONNECT_RETRY: Duration = Duration::from_millis(50);

/// The bytes each direction of a carried connection holds on their way across.
///
/// The size of the network stack's per-socket buffers, for the reason
/// [`MAX_CONNECTIONS`] gives.
const BUFFER_SIZE: usize = 64 * 1024;

/// The most connections accepted from the listener on one wakeup, so the
/// connections already carried are served between them.
///
/// The network stack's figure for a published port, for the reason
/// [`MAX_CONNECTIONS`] gives.
const ACCEPT_BATCH: usize = 32;

/// How long the listener sits out of the poll after an accept failed for a
/// reason of the host's, descriptor exhaustion the likely one.
///
/// The connection that failed is still queued, so the listener stays readable,
/// and polling it again at once would spin the thread until the host recovers.
/// The network stack's figure for a published port, for the reason
/// [`MAX_CONNECTIONS`] gives.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(250);

/// Where a forwarded connection goes on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// A unix socket, named by its absolute path.
    Unix(PathBuf),
    /// A TCP address.
    Tcp(SocketAddr),
}

impl Target {
    /// Parses a target as `--forward-loopback` takes it: an absolute path names
    /// a unix socket, and anything else is an `ADDRESS:PORT`.
    pub(crate) fn parse(flag: &str, value: &str) -> Result<Target, String> {
        if value.starts_with('/') {
            return Ok(Target::Unix(PathBuf::from(value)));
        }
        value.parse::<SocketAddr>().map(Target::Tcp).map_err(|_| {
            format!(
                "{flag} expects an absolute path to a unix socket or an ADDRESS:PORT for the \
                 target, not {value:?}"
            )
        })
    }

    /// Opens a non-blocking socket and starts a connection to the target on
    /// it, without waiting for the connection to be made.
    fn connect(&self) -> io::Result<(OwnedFd, Attempt)> {
        let family = match self {
            Target::Unix(_) => AddressFamily::UNIX,
            Target::Tcp(SocketAddr::V4(_)) => AddressFamily::INET,
            Target::Tcp(SocketAddr::V6(_)) => AddressFamily::INET6,
        };
        let socket = rustix::net::socket_with(
            family,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        let attempt = self.connect_on(&socket)?;
        Ok((socket, attempt))
    }

    /// Asks `socket` to connect to the target, and says how far that got.
    fn connect_on(&self, socket: &OwnedFd) -> io::Result<Attempt> {
        let asked = match self {
            Target::Unix(path) => {
                rustix::net::connect(socket, &SocketAddrUnix::new(path.as_path())?)
            }
            Target::Tcp(address) => rustix::net::connect(socket, address),
        };
        match asked {
            Ok(()) => Ok(Attempt::Connected),
            Err(Errno::INPROGRESS) => Ok(Attempt::InProgress),
            Err(Errno::AGAIN) => Ok(Attempt::Busy),
            Err(errno) => Err(errno.into()),
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Unix(path) => write!(f, "{}", path.display()),
            Target::Tcp(address) => write!(f, "{address}"),
        }
    }
}

/// How far a non-blocking connect got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attempt {
    /// The connection is made.
    Connected,
    /// A TCP connect is under way, and reports its end as writability.
    InProgress,
    /// The target's accept queue is full, and the connect is to be made again.
    Busy,
}

/// A running forward: its thread, and the pipe that stops it.
pub(crate) struct Forward {
    /// The forward's thread.
    thread: JoinHandle<()>,
    /// The write end of the stop pipe; closing it ends the thread.
    stop: OwnedFd,
}

impl Forward {
    /// Makes the listener at `address` on the pending sandbox's loopback and
    /// starts carrying each connection made to it to `target`.
    ///
    /// The listener is the library's, so a failure to make it is the library's
    /// error. A failure to start the forward around it is `fcage`'s own, and
    /// leaves nothing behind: a thread that does not start drops what it was
    /// handed, the listener and the stop pipe's read end with it.
    pub(crate) fn start(
        pending: &Pending<'_>,
        address: SocketAddr,
        target: Target,
    ) -> Result<Forward, Failure> {
        let listener = pending.listen(address)?;
        let own = |op: &str, err: io::Error| {
            Failure::Fcage(
                format!(
                    "forwarding the sandbox's {address} to {target}: {op}: {}",
                    ErrorChain::new(&err)
                )
                .into(),
            )
        };
        let (stop_read, stop) = pipe::pipe_with(PipeFlags::CLOEXEC)
            .map_err(|errno| own("creating the stop pipe", errno.into()))?;
        let relay = Relay::new(listener, stop_read, address, target.clone())
            .map_err(|err| own("making the listener non-blocking", err))?;
        let thread = std::thread::Builder::new()
            .name("fcage-forward".to_string())
            .spawn(move || relay.run())
            .map_err(|err| own("starting its thread", err))?;
        Ok(Forward { thread, stop })
    }

    /// Ends the forward, and returns once its thread has. The listener, each
    /// connection to the target still being made, and each connection being
    /// carried are closed.
    ///
    /// The thread never waits on a peer, so the join is bounded whatever the
    /// target or the command's end of a connection is doing.
    pub(crate) fn stop(self) {
        drop(self.stop);
        let _ = self.thread.join();
    }
}

/// A forward's thread: the listener, and every connection it holds.
struct Relay {
    /// The sandbox's listener, non-blocking.
    listener: TcpListener,
    /// The read end of the stop pipe, which reports its writer gone.
    stop: OwnedFd,
    /// The listener's address, for reports.
    address: SocketAddr,
    /// Where each connection goes.
    target: Target,
    /// Whether the last poll found the listener readable.
    listener_ready: bool,
    /// When a listener sitting out an accept failure is polled again; `None`
    /// while it is polled.
    listener_resumes: Option<Instant>,
    /// Whether an accept has failed since the last one succeeded. Only the
    /// first failure of a run of them is reported.
    accept_failing: bool,
    /// Whether a connection past the budget has been closed. Only the first is
    /// reported.
    refused: bool,
    /// Whether a connection to the target has failed since the last one was
    /// made. Only the first failure of a run of them is reported.
    connect_failing: bool,
    /// The connections whose connection to the target is still being made.
    connecting: Vec<Connecting>,
    /// The connections being carried.
    carried: Vec<Carried>,
}

/// What a slot of the relay's poll set belongs to.
#[derive(Debug, Clone, Copy)]
enum Slot {
    /// The stop pipe.
    Stop,
    /// The listener.
    Listener,
    /// The socket of a connection to the target still being made, by its
    /// index among them.
    Connecting(usize),
    /// A side of a connection being carried, by its index among them.
    Carried(usize),
}

impl Relay {
    /// A relay carrying what arrives at `listener` to `target`, until `stop`
    /// reports its writer gone. Makes the listener non-blocking, so a
    /// connection gone between the poll and the accept does not hold the
    /// thread.
    fn new(
        listener: TcpListener,
        stop: OwnedFd,
        address: SocketAddr,
        target: Target,
    ) -> io::Result<Relay> {
        listener.set_nonblocking(true)?;
        Ok(Relay {
            listener,
            stop,
            address,
            target,
            listener_ready: false,
            listener_resumes: None,
            accept_failing: false,
            refused: false,
            connect_failing: false,
            connecting: Vec::new(),
            carried: Vec::new(),
        })
    }

    /// Carries connections until the stop pipe reports its writer gone, then
    /// drops everything the relay holds.
    ///
    /// A `poll` that fails ends the forward, and is reported; nothing it holds
    /// can be served without one.
    fn run(mut self) {
        loop {
            match self.wait() {
                Ok(true) => return,
                Ok(false) => self.step(Instant::now()),
                Err(errno) => {
                    self.say_failed("waiting on its connections", &errno.into());
                    return;
                }
            }
        }
    }

    /// Waits until something the relay holds is ready, or its next deadline,
    /// and marks what is ready. Answers whether the stop pipe reported its
    /// writer gone.
    fn wait(&mut self) -> Result<bool, Errno> {
        // The library states a `poll` timeout with its own `poll::timeout`,
        // which is private to it. Over the public API, a remainder a
        // `Timespec` cannot hold is no timeout at all, as the agent-tools
        // example reads one; every remainder here is shorter than
        // `ESTABLISH_DEADLINE`, so none comes near it.
        let timeout = self
            .next_deadline()
            .map(|at| at.saturating_duration_since(Instant::now()))
            .and_then(|left| Timespec::try_from(left).ok());
        let mut slots = vec![Slot::Stop];
        let mut fds = vec![PollFd::new(&self.stop, PollFlags::IN)];
        if self.listener_resumes.is_none() {
            slots.push(Slot::Listener);
            fds.push(PollFd::new(&self.listener, PollFlags::IN));
        }
        // A connect waiting out a full queue is left out: its socket polls as
        // ready at once, and there is nothing to wait on but its retry.
        for (index, connecting) in self.connecting.iter().enumerate() {
            if connecting.wait == Wait::Writable {
                slots.push(Slot::Connecting(index));
                fds.push(PollFd::new(&connecting.sides.outbound, PollFlags::OUT));
            }
        }
        // A side nothing is asked of is left out, as the library's poll loops
        // leave out a channel they are finished with: `poll` reports a hangup
        // whatever was asked, so a side whose peer has gone would otherwise be
        // ready on every pass. A connection being carried always asks
        // something of at least one side until it ends.
        for (index, carried) in self.carried.iter().enumerate() {
            let (inbound, outbound) = carried.interest();
            if !inbound.is_empty() {
                slots.push(Slot::Carried(index));
                fds.push(PollFd::new(&carried.sides.inbound, inbound));
            }
            if !outbound.is_empty() {
                slots.push(Slot::Carried(index));
                fds.push(PollFd::new(&carried.sides.outbound, outbound));
            }
        }
        match rustix::event::poll(&mut fds, timeout.as_ref()) {
            Ok(_) => {}
            Err(Errno::INTR) => return Ok(false),
            Err(errno) => return Err(errno),
        }
        let ready: Vec<Slot> = slots
            .into_iter()
            .zip(&fds)
            .filter(|(_, fd)| !fd.revents().is_empty())
            .map(|(slot, _)| slot)
            .collect();
        drop(fds);
        for slot in ready {
            match slot {
                Slot::Stop => return Ok(true),
                Slot::Listener => self.listener_ready = true,
                Slot::Connecting(index) => self.connecting[index].ready = true,
                Slot::Carried(index) => self.carried[index].ready = true,
            }
        }
        Ok(false)
    }

    /// The earliest time the relay has something to do without a descriptor
    /// waking it: a connect to make again, a deadline, or the listener's
    /// return to the poll.
    fn next_deadline(&self) -> Option<Instant> {
        self.connecting
            .iter()
            .flat_map(|connecting| [connecting.retry_at(), connecting.deadline])
            .flatten()
            .chain(self.listener_resumes)
            .min()
    }

    /// Serves what the last wait found ready, and what `now` has made due.
    ///
    /// Carried connections go first, so those that have ended give their place
    /// in the budget back before the listener is served.
    fn step(&mut self, now: Instant) {
        self.carried.retain_mut(|carried| {
            if std::mem::take(&mut carried.ready) {
                carried.carry()
            } else {
                true
            }
        });
        self.advance(now);
        if self.listener_resumes.is_some_and(|at| now >= at) {
            self.listener_resumes = None;
        }
        if std::mem::take(&mut self.listener_ready) {
            self.accept(now);
        }
    }

    /// Moves each connection to the target still being made along. One whose
    /// connect has ended is carried, or reported and reset. One waiting out a
    /// full accept queue is connected again once its retry is due. One past its
    /// deadline is abandoned, reported, and reset.
    fn advance(&mut self, now: Instant) {
        for mut connecting in std::mem::take(&mut self.connecting) {
            match connecting.advance(&self.target, now) {
                Ok(true) => self.carry(connecting.sides),
                Ok(false) => self.connecting.push(connecting),
                Err(err) => self.connect_failed(&err),
            }
        }
    }

    /// Accepts the connections waiting on the listener, each starting a
    /// connection to the target, or closed at once past the budget.
    fn accept(&mut self, now: Instant) {
        for _ in 0..ACCEPT_BATCH {
            let inbound = match rustix::net::accept_with(
                &self.listener,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            ) {
                Ok(inbound) => inbound,
                Err(Errno::AGAIN) => return,
                // A signal, or a connection abandoned before it was accepted:
                // the next one is still there to take.
                Err(Errno::INTR | Errno::CONNABORTED) => continue,
                Err(errno) => {
                    self.listener_resumes = now.checked_add(ACCEPT_BACKOFF);
                    if !std::mem::replace(&mut self.accept_failing, true) {
                        self.say_failed("accepting a connection", &errno.into());
                    }
                    return;
                }
            };
            self.accept_failing = false;
            if self.connecting.len() + self.carried.len() >= MAX_CONNECTIONS {
                // Dropping it closes it, which is how the command learns.
                if !std::mem::replace(&mut self.refused, true) {
                    self.report(format_args!(
                        "closed a connection past the budget of {MAX_CONNECTIONS} open at \
                         once; any further one is closed without a report"
                    ));
                }
                continue;
            }
            self.connect(inbound, now);
        }
    }

    /// Starts the connection to the target for `inbound`. A target that
    /// refuses it at once resets `inbound`, and is reported.
    fn connect(&mut self, inbound: OwnedFd, now: Instant) {
        let (outbound, attempt) = match self.target.connect() {
            Ok(started) => started,
            Err(err) => {
                reset_on_close(&inbound);
                self.connect_failed(&err);
                return;
            }
        };
        let sides = Sides {
            inbound,
            outbound,
            finished: false,
        };
        let wait = match attempt {
            Attempt::Connected => {
                self.carry(sides);
                return;
            }
            Attempt::InProgress => Wait::Writable,
            Attempt::Busy => Wait::Retry(now.checked_add(CONNECT_RETRY)),
        };
        self.connecting.push(Connecting {
            sides,
            wait,
            deadline: now.checked_add(ESTABLISH_DEADLINE),
            ready: false,
        });
    }

    /// Starts carrying a connection whose connection to the target is made,
    /// which ends a run of failures to make one.
    fn carry(&mut self, sides: Sides) {
        self.connect_failing = false;
        self.carried.push(Carried::new(sides));
    }

    /// Reports a failure to make a connection to the target, where it is the
    /// first of a run of them.
    fn connect_failed(&mut self, err: &io::Error) {
        if !std::mem::replace(&mut self.connect_failing, true) {
            self.say_failed("connecting to the target", err);
        }
    }

    /// Reports a failure of the forward on standard error.
    fn say_failed(&self, op: &str, err: &io::Error) {
        self.report(format_args!("{op}: {}", ErrorChain::new(err)));
    }

    /// Writes a line about the forward on standard error, naming it.
    fn report(&self, line: fmt::Arguments<'_>) {
        output::report(format_args!(
            "fcage: forwarding the sandbox's {} to {}: {line}",
            self.address, self.target
        ));
    }
}

/// The two sides of a forwarded connection: the command's, and the target's.
///
/// Each side is reset as it closes unless the connection ended in order; see
/// [the module documentation](self).
struct Sides {
    /// The command's side.
    inbound: OwnedFd,
    /// The target's side, connected or still connecting.
    outbound: OwnedFd,
    /// Both directions have ended in order, so closing each side is an end of
    /// stream rather than a reset.
    finished: bool,
}

impl Drop for Sides {
    fn drop(&mut self) {
        if !self.finished {
            reset_on_close(&self.inbound);
            reset_on_close(&self.outbound);
        }
    }
}

/// Makes the close of `socket` a reset rather than an end of stream, by a zero
/// linger. A unix socket takes the option and has no reset to send.
///
/// Best-effort: the option's value is a constant the kernel accepts on every
/// socket, so the one way it fails is a descriptor that is not a socket, which
/// neither side is.
fn reset_on_close(socket: &OwnedFd) {
    let _ = sockopt::set_socket_linger(socket, Some(Duration::ZERO));
}

/// A connection the command made whose connection to the target is still being
/// made.
struct Connecting {
    /// The command's connection, accepted and not yet read, and the socket
    /// connecting to the target.
    sides: Sides,
    /// What the connect waits on.
    wait: Wait,
    /// When the connect is abandoned; `None` where the clock cannot express it,
    /// which is no deadline at all.
    deadline: Option<Instant>,
    /// Whether the last poll found the target's side ready.
    ready: bool,
}

/// What a connect to the target waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wait {
    /// A TCP connect under way, which reports its end as writability.
    Writable,
    /// A full accept queue: the connect is made again at this time, or never
    /// where the clock cannot express it.
    Retry(Option<Instant>),
}

impl Connecting {
    /// When the connect is to be made again, if it waits out a full queue.
    fn retry_at(&self) -> Option<Instant> {
        match self.wait {
            Wait::Retry(at) => at,
            Wait::Writable => None,
        }
    }

    /// Moves the connect along: answers `true` once the connection is made,
    /// `false` while it is still being made, and the failure that ends it
    /// otherwise, its deadline passing included.
    fn advance(&mut self, target: &Target, now: Instant) -> io::Result<bool> {
        match self.wait {
            // Writability, or an error, means the connect ended; `SO_ERROR`
            // says how.
            Wait::Writable if std::mem::take(&mut self.ready) => {
                return match sockopt::socket_error(&self.sides.outbound)? {
                    Ok(()) => Ok(true),
                    Err(errno) => Err(errno.into()),
                };
            }
            Wait::Retry(Some(at)) if now >= at => match target.connect_on(&self.sides.outbound)? {
                Attempt::Connected => return Ok(true),
                Attempt::InProgress => self.wait = Wait::Writable,
                Attempt::Busy => self.wait = Wait::Retry(now.checked_add(CONNECT_RETRY)),
            },
            Wait::Writable | Wait::Retry(_) => {}
        }
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("not connected within {ESTABLISH_DEADLINE:?}"),
            ));
        }
        Ok(false)
    }
}

/// A connection being carried: the command's side, the target's, and a
/// direction each way between them.
struct Carried {
    /// The command's side and the target's.
    sides: Sides,
    /// What the command sends, on its way to the target.
    upstream: Direction,
    /// What the target sends, on its way to the command.
    downstream: Direction,
    /// Whether the last poll found either side ready.
    ready: bool,
}

impl Carried {
    /// A connection whose two sides are both connected.
    fn new(sides: Sides) -> Carried {
        Carried {
            sides,
            upstream: Direction::new(),
            downstream: Direction::new(),
            ready: false,
        }
    }

    /// What `poll` is asked of the command's side and of the target's: to read
    /// where a direction from it has room, and to write where a direction to it
    /// holds something.
    fn interest(&self) -> (PollFlags, PollFlags) {
        let side = |from: &Direction, to: &Direction| {
            let mut interest = PollFlags::empty();
            if from.wants_input() {
                interest |= PollFlags::IN;
            }
            if to.holds() {
                interest |= PollFlags::OUT;
            }
            interest
        };
        (
            side(&self.upstream, &self.downstream),
            side(&self.downstream, &self.upstream),
        )
    }

    /// Moves what each direction can without waiting. Answers whether the
    /// connection carries on: not once both directions have ended, and
    /// dropping it then closes both sides, nor once either side has failed,
    /// and dropping it then resets both.
    fn carry(&mut self) -> bool {
        let Sides {
            inbound, outbound, ..
        } = &self.sides;
        let upstream = self.upstream.carry(inbound, outbound);
        let downstream = self.downstream.carry(outbound, inbound);
        if upstream.is_err() || downstream.is_err() {
            return false;
        }
        self.sides.finished = self.upstream.passed && self.downstream.passed;
        !self.sides.finished
    }
}

/// One direction of a carried connection: what has been read from one side and
/// not yet written to the other, and how far its end has got.
struct Direction {
    /// [`BUFFER_SIZE`] bytes, of which `start..end` are waiting to be written.
    buffer: Box<[u8]>,
    /// Where the bytes waiting to be written begin.
    start: usize,
    /// Where they end.
    end: usize,
    /// The side read from has ended its input.
    ended: bool,
    /// The end has been passed on, as a shutdown of the sending half of the
    /// side written to.
    passed: bool,
}

impl Direction {
    /// An empty direction, with its input still open.
    fn new() -> Direction {
        Direction {
            buffer: vec![0; BUFFER_SIZE].into_boxed_slice(),
            start: 0,
            end: 0,
            ended: false,
            passed: false,
        }
    }

    /// Whether the side read from is to be read: its input has not ended, and
    /// there is room for more.
    fn wants_input(&self) -> bool {
        !self.ended && (self.end < self.buffer.len() || self.start > 0)
    }

    /// Whether the direction holds bytes waiting to be written.
    fn holds(&self) -> bool {
        self.start < self.end
    }

    /// Moves what it can from `from` to `to` without waiting, and passes the
    /// end of `from`'s input on once everything before it has been written.
    /// Answers the failure of either side.
    fn carry(&mut self, from: &OwnedFd, to: &OwnedFd) -> Result<(), Errno> {
        self.write(to)?;
        if self.wants_input() {
            if self.end == self.buffer.len() {
                self.buffer.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            match rustix::net::recv(from, &mut self.buffer[self.end..], RecvFlags::empty()) {
                Ok((0, _)) => self.ended = true,
                Ok((read, _)) => self.end += read,
                Err(Errno::AGAIN | Errno::INTR) => {}
                Err(errno) => return Err(errno),
            }
            self.write(to)?;
        }
        if self.ended && !self.holds() && !self.passed {
            // A side already gone cannot take the end; the other direction
            // finds that out as a failure of its own.
            let _ = rustix::net::shutdown(to, Shutdown::Write);
            self.passed = true;
        }
        Ok(())
    }

    /// Writes what the direction holds to `to`, as much as it takes without
    /// waiting.
    ///
    /// Sent with `MSG_NOSIGNAL`, so a side whose peer has gone answers `EPIPE`
    /// rather than raising `SIGPIPE`, whatever `fcage`'s disposition of it.
    fn write(&mut self, to: &OwnedFd) -> Result<(), Errno> {
        if !self.holds() {
            return Ok(());
        }
        match rustix::net::send(to, &self.buffer[self.start..self.end], SendFlags::NOSIGNAL) {
            Ok(written) => {
                self.start += written;
                if self.start == self.end {
                    self.start = 0;
                    self.end = 0;
                }
                Ok(())
            }
            Err(Errno::AGAIN | Errno::INTR) => Ok(()),
            Err(errno) => Err(errno),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use super::*;

    /// A relay over a listener of the host's own, standing in for the
    /// sandbox's, the listener's address, and the write end of its stop pipe.
    fn relay(target: &TcpListener) -> (Relay, SocketAddr, OwnedFd) {
        relay_to(target.local_addr().expect("the target has an address"))
    }

    /// [`relay`], toward `target` whether or not anything listens there.
    fn relay_to(target: SocketAddr) -> (Relay, SocketAddr, OwnedFd) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the listener binds");
        let address = listener.local_addr().expect("the listener has an address");
        let (stop_read, stop) = pipe::pipe_with(PipeFlags::CLOEXEC).expect("the stop pipe opens");
        let relay = Relay::new(listener, stop_read, address, Target::Tcp(target))
            .expect("the relay is made");
        (relay, address, stop)
    }

    /// How a connection read to its end ended.
    #[derive(Debug, PartialEq, Eq)]
    enum Ending {
        /// An end of stream.
        Closed,
        /// A reset.
        Reset,
    }

    /// Reads from `connection` until it ends, failing the test if it has not
    /// within ten seconds, and returns what arrived and how it ended.
    fn read_to_end(mut connection: TcpStream) -> (Vec<u8>, Ending) {
        connection
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("the read can be bounded");
        let mut received = Vec::new();
        match connection.read_to_end(&mut received) {
            Ok(_) => (received, Ending::Closed),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                (received, Ending::Reset)
            }
            Err(error) => panic!("the connection did not end: {error}"),
        }
    }

    /// Waits for `thread` to end, failing the test past `within`.
    fn joined_within(thread: &JoinHandle<()>, within: Duration, what: &str) {
        let deadline = Instant::now() + within;
        while !thread.is_finished() {
            assert!(
                Instant::now() < deadline,
                "{what} did not end within {within:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_connection_the_target_has_not_taken_by_its_deadline_is_reset() {
        let target = TcpListener::bind("127.0.0.1:0").expect("the target binds");
        let (mut relay, address, _stop) = relay(&target);
        let command = TcpStream::connect(address).expect("the command connects");

        // Accepted, with its connect to the target under way: a non-blocking
        // TCP connect answers `EINPROGRESS`, and nothing here polls for its
        // end, so only the clock can move it along.
        let accepted = Instant::now();
        relay.accept(accepted);
        assert_eq!(relay.connecting.len(), 1);
        assert_eq!(relay.connecting[0].wait, Wait::Writable);

        relay.advance(accepted + ESTABLISH_DEADLINE - Duration::from_millis(1));
        assert_eq!(relay.connecting.len(), 1, "abandoned before its deadline");
        relay.advance(accepted + ESTABLISH_DEADLINE);
        assert!(relay.connecting.is_empty(), "held past its deadline");
        assert!(relay.carried.is_empty());
        assert_eq!(read_to_end(command), (Vec::new(), Ending::Reset));
    }

    #[test]
    fn a_connection_the_target_refuses_is_reset() {
        // Nothing listens at the target's address once its listener is gone,
        // so the target refuses the connection, at once or as the connect's
        // end; the command's connection is reset either way.
        let address = TcpListener::bind("127.0.0.1:0")
            .and_then(|gone| gone.local_addr())
            .expect("an address nothing listens at");
        let (relay, listening, stop) = relay_to(address);
        let thread = std::thread::spawn(move || relay.run());
        let command = TcpStream::connect(listening).expect("the command connects");
        assert_eq!(read_to_end(command), (Vec::new(), Ending::Reset));
        drop(stop);
        joined_within(&thread, Duration::from_secs(5), "the relay");
    }

    #[test]
    fn a_connection_made_ends_a_run_of_failures_to_make_one() {
        // A target that comes back after a run of failures has its next
        // failure reported again, so the report says when it went down anew.
        let target = TcpListener::bind("127.0.0.1:0").expect("the target binds");
        let (mut relay, address, _stop) = relay(&target);
        relay.connect_failing = true;
        let _command = TcpStream::connect(address).expect("the command connects");
        relay.accept(Instant::now());
        let deadline = Instant::now() + Duration::from_secs(10);
        while relay.carried.is_empty() {
            assert!(
                Instant::now() < deadline,
                "the target's connection was never made"
            );
            relay.wait().expect("the relay waits");
            relay.step(Instant::now());
        }
        assert!(
            !relay.connect_failing,
            "a connection made left the run going"
        );
    }

    #[test]
    fn a_target_that_resets_mid_reply_resets_the_command() {
        // The command reads to the end of the connection, so an end of stream
        // where the target reset would pass the cut-off reply off as whole.
        let target = TcpListener::bind("127.0.0.1:0").expect("the target binds");
        let (relay, address, stop) = relay(&target);
        let thread = std::thread::spawn(move || relay.run());
        let command = TcpStream::connect(address).expect("the command connects");
        let (mut connection, _) = target.accept().expect("the relay connects to the target");
        connection
            .write_all(b"the first part of a reply")
            .expect("the target replies");
        let connection = OwnedFd::from(connection);
        reset_on_close(&connection);
        drop(connection);

        assert_eq!(
            read_to_end(command),
            (b"the first part of a reply".to_vec(), Ending::Reset)
        );
        drop(stop);
        joined_within(&thread, Duration::from_secs(5), "the relay");
    }

    #[test]
    fn a_connection_past_the_budget_is_closed_at_once() {
        // Nothing here polls, so a connect to the target that the kernel has
        // made is still one the relay is making: the budget counts both.
        let target = TcpListener::bind("127.0.0.1:0").expect("the target binds");
        let (mut relay, address, _stop) = relay(&target);
        let held: Vec<TcpStream> = (0..MAX_CONNECTIONS)
            .map(|_| {
                let command = TcpStream::connect(address).expect("the command connects");
                relay.accept(Instant::now());
                command
            })
            .collect();
        assert_eq!(
            relay.connecting.len() + relay.carried.len(),
            MAX_CONNECTIONS
        );
        assert!(!relay.refused);

        let past = TcpStream::connect(address).expect("the command connects");
        relay.accept(Instant::now());
        assert_eq!(
            relay.connecting.len() + relay.carried.len(),
            MAX_CONNECTIONS
        );
        assert!(relay.refused);
        assert_eq!(read_to_end(past), (Vec::new(), Ending::Closed));
        drop(held);
    }

    #[test]
    fn a_stop_ends_the_relay_while_its_target_reads_nothing() {
        let target = TcpListener::bind("127.0.0.1:0").expect("the target binds");
        let (relay, address, stop) = relay(&target);
        let thread = std::thread::spawn(move || relay.run());

        // The command sends without end, and the target takes the connection
        // and never reads it, so the relay fills its buffer toward a side that
        // will not take it.
        let mut command = TcpStream::connect(address).expect("the command connects");
        let flood = std::thread::spawn(move || {
            let chunk = [0x5a; 64 * 1024];
            while command.write_all(&chunk).is_ok() {}
        });
        let (connection, _) = target.accept().expect("the relay connects to the target");
        let arrived = Instant::now() + Duration::from_secs(10);
        assert!(
            ferroday_cage_testkit::fd::readable_by(&connection, arrived),
            "nothing reached the target"
        );

        drop(stop);
        joined_within(&thread, Duration::from_secs(5), "the relay");
        thread.join().expect("the relay ends cleanly");
        // The relay reset the command's side, so its writes fail, and the
        // target's: the connection did not end in order, and the target must
        // not take what reached it for the whole of it.
        joined_within(&flood, Duration::from_secs(10), "the command's writes");
        flood.join().expect("the command's thread ends cleanly");
        let (_, ending) = read_to_end(connection);
        assert_eq!(ending, Ending::Reset, "the target read an end of stream");
    }

    #[test]
    fn a_target_is_a_unix_socket_by_its_absolute_path_and_otherwise_an_address() {
        assert_eq!(
            Target::parse("--forward-loopback", "/run/egress.sock"),
            Ok(Target::Unix(PathBuf::from("/run/egress.sock")))
        );
        assert_eq!(
            Target::parse("--forward-loopback", "127.0.0.1:8080"),
            Ok(Target::Tcp("127.0.0.1:8080".parse().unwrap()))
        );
        assert_eq!(
            Target::parse("--forward-loopback", "[::1]:8080"),
            Ok(Target::Tcp("[::1]:8080".parse().unwrap()))
        );
        let refused = Target::parse("--forward-loopback", "egress.sock").unwrap_err();
        assert!(refused.contains("absolute path"), "{refused}");
    }
}
