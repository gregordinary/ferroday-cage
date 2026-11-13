//! `--forward-loopback`: a port on the sandbox's loopback whose connections
//! arrive at a target on the host.
//!
//! The library makes the listener: [`Pending::listen`] creates it in the
//! sandbox's network namespace and hands it to `fcage`, which accepts the
//! connections the command makes and copies each one to the target on threads
//! of its own. Nothing of `fcage`'s runs inside the sandbox. The copy is this
//! module's, over the public API, and the library offers none.
//!
//! The accept loop polls the listener beside a stop pipe, so the run's end
//! releases it whatever has become of the sandbox: a listener keeps the
//! sandbox's network namespace alive, and an `accept` on it after the sandbox
//! has exited would wait forever.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread::JoinHandle;

use ferroday_cage::{ErrorChain, Pending};
use rustix::event::{PollFd, PollFlags};
use rustix::io::Errno;
use rustix::pipe::{self, PipeFlags};

use crate::{Failure, output};

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

    /// Opens a connection to the target.
    fn connect(&self) -> io::Result<Stream> {
        match self {
            Target::Unix(path) => UnixStream::connect(path).map(Stream::Unix),
            Target::Tcp(address) => TcpStream::connect(address).map(Stream::Tcp),
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

/// One end of a forwarded connection, TCP or unix, with the two operations the
/// copy needs of either.
enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    /// A second handle to the same connection, for the other direction's
    /// thread.
    fn try_clone(&self) -> io::Result<Stream> {
        match self {
            Stream::Tcp(stream) => stream.try_clone().map(Stream::Tcp),
            Stream::Unix(stream) => stream.try_clone().map(Stream::Unix),
        }
    }

    /// Shuts down one or both halves, ignoring a connection already gone.
    fn shutdown(&self, how: Shutdown) {
        let _ = match self {
            Stream::Tcp(stream) => stream.shutdown(how),
            Stream::Unix(stream) => stream.shutdown(how),
        };
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.read(buf),
            Stream::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.write(buf),
            Stream::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.flush(),
            Stream::Unix(stream) => stream.flush(),
        }
    }
}

/// A running forward: the thread that accepts on the sandbox's loopback, and
/// the pipe that stops it.
pub(crate) struct Forward {
    /// The accept loop.
    thread: JoinHandle<()>,
    /// The write end of the stop pipe; closing it ends the loop.
    stop: OwnedFd,
}

impl Forward {
    /// Makes the listener at `address` on the pending sandbox's loopback and
    /// starts accepting on it, carrying each connection to `target`.
    ///
    /// The listener is the library's, so a failure to make it is the library's
    /// error. A failure to start the loop around it is `fcage`'s own.
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
        let accepted = target.clone();
        let thread = std::thread::Builder::new()
            .name("fcage-forward".to_string())
            .spawn(move || accept_until_stopped(&listener, &stop_read, address, &accepted))
            .map_err(|err| own("starting the accept thread", err))?;
        Ok(Forward { thread, stop })
    }

    /// Stops accepting, and returns once the accept loop has ended. A
    /// connection already being copied carries on until either end closes it.
    pub(crate) fn stop(self) {
        drop(self.stop);
        let _ = self.thread.join();
    }
}

/// Accepts connections until the stop pipe reports its writer gone, carrying
/// each to `target`.
fn accept_until_stopped(
    listener: &TcpListener,
    stop: &OwnedFd,
    address: SocketAddr,
    target: &Target,
) {
    loop {
        let mut fds = [
            PollFd::new(listener, PollFlags::IN),
            PollFd::new(stop, PollFlags::IN),
        ];
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(errno) => {
                say_failed(address, target, "waiting for a connection", &errno.into());
                return;
            }
        }
        if !fds[1].revents().is_empty() {
            return;
        }
        if fds[0].revents().is_empty() {
            continue;
        }
        match listener.accept() {
            Ok((inbound, _)) => carry(Stream::Tcp(inbound), address, target),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => {
                say_failed(address, target, "accepting a connection", &err);
                return;
            }
        }
    }
}

/// Connects `inbound` to the target and copies both directions on two threads
/// of their own. A target that refuses the connection closes `inbound`, and is
/// reported.
fn carry(inbound: Stream, address: SocketAddr, target: &Target) {
    let outbound = match target.connect() {
        Ok(outbound) => outbound,
        Err(err) => {
            say_failed(address, target, "connecting to the target", &err);
            return;
        }
    };
    let readers = inbound
        .try_clone()
        .and_then(|inbound| Ok((inbound, outbound.try_clone()?)));
    let (inbound_reader, outbound_reader) = match readers {
        Ok(readers) => readers,
        Err(err) => {
            say_failed(address, target, "duplicating the connection", &err);
            return;
        }
    };
    for (from, to) in [(inbound_reader, outbound), (outbound_reader, inbound)] {
        let spawned = std::thread::Builder::new()
            .name("fcage-forward-copy".to_string())
            .spawn(move || copy_half(from, to));
        if let Err(err) = spawned {
            say_failed(address, target, "starting a copy thread", &err);
            return;
        }
    }
}

/// Copies one direction of a connection until its reader ends, then passes the
/// end on by shutting down the writer's sending half. A failure on either side
/// shuts both down, which ends the other direction too.
fn copy_half(mut from: Stream, mut to: Stream) {
    match io::copy(&mut from, &mut to) {
        Ok(_) => to.shutdown(Shutdown::Write),
        Err(_) => {
            from.shutdown(Shutdown::Both);
            to.shutdown(Shutdown::Both);
        }
    }
}

/// Reports a failure of the forward on standard error.
fn say_failed(address: SocketAddr, target: &Target, op: &str, err: &io::Error) {
    output::report(format_args!(
        "fcage: forwarding the sandbox's {address} to {target}: {op}: {}",
        ErrorChain::new(err)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

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
