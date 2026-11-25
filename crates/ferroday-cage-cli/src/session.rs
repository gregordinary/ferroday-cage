//! `fcage --serve`: a sandbox held for a session, and the further commands the
//! programs that connect to its socket run in it.
//!
//! The server starts the sandbox with no command of its own, as the library's
//! `Cage::start` does, and attaches what a launch attaches. It then listens on
//! a unix socket at the path `--serve` names. Each connection is a program
//! asking for commands, and each command it asks for is the library's
//! `Running::exec`, confined as the sandbox's launch confines a command.
//!
//! # The socket, and who may use it
//!
//! The socket is created with mode 0600 in a directory the caller's user owns
//! and that neither its group nor others can write, so no other user reaches
//! it, and nothing replaces it. A path that already exists is refused, and the
//! server removes the socket it made once it is done.
//!
//! A sandbox's processes carry the caller's uid and gid, so neither tells them
//! apart from the caller's own. Their user namespace does: every connection is
//! asked where its peer runs, through the library's
//! `host::peer_in_own_user_namespace`, and a peer in any namespace but the
//! server's own is refused before anything it sent is read. A sandbox's
//! command reaches the socket only where a bind exposes its directory and the
//! sandbox's Landlock rules let it connect to a socket it did not create.
//!
//! # The protocol
//!
//! Each message is one JSON object on a line of its own, as the event stream
//! writes them:
//!
//! - **A request**, from the client: `{"id": 1, "method": "exec", "params":
//!   {...}}`, its `id` a number or a string.
//! - **A response**, one to each request: `{"id": 1, "result": {...}}`, or
//!   `{"id": 1, "error": {"code": ..., "text": ...}}` with the members the code
//!   names.
//! - **An event** of an exec's, the event stream's vocabulary, with an `exec`
//!   member naming the request that started it.
//!
//! The methods are `hello`, answered with the protocol version; `exec`, which
//! runs a command and answers with how it ended once it has; and `stop`, which
//! ends the session and answers once the sandbox has ended. A connection runs
//! one exec at a time, and its close ends the exec it is running.
//!
//! Descriptors travel with a message's first byte, as sd-varlink's rule has
//! them: an `exec` that passes its streams sends them attached to the first
//! byte of its request. The server reads each message's first byte alone and
//! the rest of it apart, peeking ahead to its newline so it never reads into
//! the next, and a descriptor that arrives anywhere but the first byte is a
//! protocol error that closes the connection. The kernel stops a read after the
//! data a descriptor came with, which is what lets the first byte's read take
//! that message's descriptors and nothing else.
//!
//! A descriptor is handed to the command as it is, so the server takes one of
//! the kinds a launch hands over, a pipe, a socket or a character device, and
//! refuses a file, which the command could reopen through `/proc/self/fd` with
//! more access than the descriptor carries. A client relays a file through a
//! pipe of its own, as a launch does.
//!
//! # Threads
//!
//! The library's handles stay on the thread that made them, so one thread
//! holds the sandbox's handle and every exec's, and waits on all of them, the
//! listening socket and the connections in one poll. Each connection has a
//! thread of its own that writes to it, so a client that stops reading holds
//! up only what is written to it. An exec whose seccomp filter reports its
//! refusals has a thread handing them on.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, IoSliceMut, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ferroday_cage::relay::{Escalation, Signals};
use ferroday_cage::{Exec, ExitStatus, Reports, Running, SeccompReport, Stdio};
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendFlags,
    SocketAddrUnix, SocketFlags, SocketType,
};
use rustix::process::Signal;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::events::{self, Bytes, EndReason, Event, Fault};
use crate::output::{QUEUED_REPORTS, Reporter};
use crate::seccomp::LAST_REPORTS;
use crate::streams;

/// How many connections the listening socket queues before the server takes
/// them.
const BACKLOG: i32 = 64;

/// The longest message a client may send. An `exec` carrying a command line
/// as long as the kernel takes, `ARG_MAX`'s two mebibytes, written as base64,
/// fits with room for its environment.
const MAX_MESSAGE: usize = 8 << 20;

/// How much of a connection's input one peek looks at for a message's end.
const PEEK: usize = 64 << 10;

/// The most descriptors a message carries: an exec's three streams.
const MAX_DESCRIPTORS: usize = 3;

/// The most responses a connection's writer holds unwritten before the server
/// takes the client for one that does not read, and closes the connection.
const MAX_UNWRITTEN: usize = 256;

/// How long a session's end waits, for every connection at once, for the
/// writers to deliver what they hold before giving up on a client that does
/// not read.
const LAST_WORDS: Duration = Duration::from_secs(2);

/// How often a thread handing on an exec's reports looks for the exec's end
/// while the reports go on.
const REPORTS_GLANCE: Duration = Duration::from_millis(50);

/// The signals that end a session. Each is blocked and read as data, as the
/// relay reads them; the others of the relay's set are dropped.
const ENDING_SIGNALS: [Signal; 4] = [Signal::INT, Signal::TERM, Signal::HUP, Signal::QUIT];

// ---------------------------------------------------------------------------
// The socket
// ---------------------------------------------------------------------------

/// The socket a session serves on, bound at the path `--serve` names, in a
/// directory that only the caller's user can write.
///
/// Dropping it removes the socket from the directory, where the entry is still
/// the one this bind made.
pub struct Socket {
    /// The path, as `--serve` named it.
    path: PathBuf,
    /// The directory holding it, opened once: the bind and the removal go
    /// through it, so both act on the directory whose ownership was checked.
    directory: OwnedFd,
    /// The socket's name in the directory.
    name: OsString,
    /// The bound socket, until [`listen`](Self::listen) makes it the
    /// session's listener.
    socket: Option<OwnedFd>,
    /// The device and inode of the entry the bind made.
    made: (u64, u64),
}

impl Socket {
    /// Binds a socket at `path`, mode 0600, refusing a directory another user
    /// owns or its group or others can write, and a path that exists.
    ///
    /// Called while `fcage` holds one thread, since the mode comes from a
    /// process-wide umask set around the bind.
    pub fn bind(path: &Path) -> Result<Socket, Fault> {
        let refused = |message: String| Fault::plain("fcage", message);
        let name = path
            .file_name()
            .filter(|_| !path.as_os_str().as_bytes().ends_with(b"/"))
            .ok_or_else(|| {
                refused(format!(
                    "--serve {}: the path names no socket; give the directory and the \
                     socket's name in it",
                    path.display()
                ))
            })?
            .to_os_string();
        // The library's `path::parent_of` answers this for itself; `fcage` is
        // a crate apart, and states the same fallback (`tools/idioms.toml`).
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let directory = rustix::fs::open(
            parent,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| {
            let mut fault = Fault::of("fcage", &io::Error::from(errno));
            fault.message = format!("opening {}: {}", parent.display(), fault.message);
            fault
        })?;
        let held = rustix::fs::fstat(&directory)
            .map_err(|errno| Fault::of("fcage", &io::Error::from(errno)))?;
        let user = rustix::process::geteuid().as_raw();
        if held.st_uid != user {
            return Err(refused(format!(
                "--serve {}: {} belongs to uid {}, not to fcage's user, uid {user}; a session's \
                 socket goes in a directory only its user can write, such as \
                 $XDG_RUNTIME_DIR",
                path.display(),
                parent.display(),
                held.st_uid,
            )));
        }
        if held.st_mode & 0o022 != 0 {
            return Err(refused(format!(
                "--serve {}: {} is writable by its group or by others (mode {:o}); a session's \
                 socket goes in a directory only its user can write, such as $XDG_RUNTIME_DIR",
                path.display(),
                parent.display(),
                held.st_mode & 0o7777,
            )));
        }

        let socket = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|errno| Fault::of("fcage", &io::Error::from(errno)))?;
        // Bound through the directory's descriptor, so the bind lands in the
        // directory checked above whatever its path names by now, and a path
        // too long for a socket address is bound all the same. A client
        // reaches such a path through a descriptor of its directory too.
        let mut through = PathBuf::from(format!("/proc/self/fd/{}", fd_number(&directory)));
        through.push(&name);
        let address = SocketAddrUnix::new(&through).map_err(|_| {
            refused(format!(
                "--serve {}: the socket's name is too long for a unix socket's address",
                path.display()
            ))
        })?;
        // The bind creates the entry with the umask's permissions, so the
        // umask is narrowed to the owner around it, and the socket is 0600
        // from the moment it exists.
        let previous = rustix::process::umask(Mode::from_raw_mode(0o177));
        let bound = rustix::net::bind(&socket, &address);
        rustix::process::umask(previous);
        bound.map_err(|errno| match errno {
            Errno::ADDRINUSE => refused(format!(
                "--serve {}: the path exists; remove it, or name another",
                path.display()
            )),
            errno => {
                let mut fault = Fault::of("fcage", &io::Error::from(errno));
                fault.message = format!("binding {}: {}", path.display(), fault.message);
                fault
            }
        })?;
        let entry = rustix::fs::statat(&directory, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|errno| Fault::of("fcage", &io::Error::from(errno)))?;
        Ok(Socket {
            path: path.to_path_buf(),
            directory,
            name,
            socket: Some(socket),
            made: (entry.st_dev, entry.st_ino),
        })
    }

    /// The path, as `--serve` named it.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Starts listening, and hands the session the listener, which it takes
    /// connections from without waiting. A client that connects before this is
    /// refused rather than left waiting, and so is one after the listener has
    /// closed: the listener is the bound socket's one descriptor.
    pub fn listen(&mut self) -> io::Result<UnixListener> {
        let socket = self
            .socket
            .take()
            .ok_or_else(|| io::Error::other("the session's socket listens already"))?;
        rustix::net::listen(&socket, BACKLOG)?;
        let listener = UnixListener::from(socket);
        listener.set_nonblocking(true)?;
        Ok(listener)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        // Removed only where the name still holds the entry the bind made.
        if let Ok(entry) =
            rustix::fs::statat(&self.directory, &self.name, AtFlags::SYMLINK_NOFOLLOW)
            && (entry.st_dev, entry.st_ino) == self.made
            && FileType::from_raw_mode(entry.st_mode) == FileType::Socket
        {
            let _ = rustix::fs::unlinkat(&self.directory, &self.name, AtFlags::empty());
        }
    }
}

/// The number of the descriptor `fd` is, for a path through `/proc/self/fd`.
fn fd_number(fd: &OwnedFd) -> i32 {
    use std::os::fd::AsRawFd as _;
    fd.as_raw_fd()
}

/// Opens the input `--serve-until-closed` names, whose end ends the session:
/// for reading, without waiting for a writer, so a pipe or a named pipe whose
/// writer is not there yet opens all the same.
pub fn open_until_closed(path: &Path) -> io::Result<File> {
    let opened = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(File::from(opened))
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// What a session holds while it serves.
pub struct Session<'a> {
    /// The sandbox's handle.
    sandbox: Running<'static>,
    /// The socket's listener, until the session begins to end, when closing
    /// it refuses every connection after.
    listener: Option<UnixListener>,
    /// The signals that end the session, read as data.
    signals: &'a Signals,
    /// `--serve-until-closed`'s input, until it ends.
    until_closed: Option<File>,
    /// Where the server's own reports go: the run's event stream or standard
    /// error, through a thread that never holds up the session.
    reporter: Reporter,
    /// The connections, in the order they came.
    connections: Vec<Connection>,
    /// The grace between an exec's termination and its kill, unless the exec
    /// names its own, and the session's at its end.
    kill_after: Duration,
    /// Whether an exec looks a bare command name up on `PATH` unless it says.
    path_lookup: bool,
    /// Why the session is ending, once it is, and the escalation that ends the
    /// sandbox.
    ending: Option<(EndReason, Escalation)>,
    /// The sandbox's outcome, once its handle has collected it.
    ended: Option<ExitStatus>,
}

/// One client's connection.
struct Connection {
    /// The socket.
    stream: UnixStream,
    /// What it has sent of the message being read.
    reader: Reader,
    /// What is written to it.
    outbox: Outbox,
    /// The exec it is running, if any.
    flight: Option<Flight>,
    /// Whether its requests are still read: not once the client has shut its
    /// side, or broken the protocol.
    reading: bool,
    /// Whether the client has gone, its socket closed both ways, or must be
    /// taken for gone: its exec is ended, and nothing more is written to it.
    gone: bool,
    /// The `stop` requests it made, answered once the sandbox has ended.
    stops: Vec<Value>,
}

/// An exec in flight on a connection.
struct Flight {
    /// The request that started it.
    id: Value,
    /// Its handle.
    running: Running<'static>,
    /// Its timeout, and the termination and kill that follow, or the ones its
    /// connection's close begins.
    escalation: Escalation,
    /// The grace between its termination and its kill.
    kill_after: Duration,
    /// The thread handing on its seccomp reports, where the exec makes them,
    /// which writes the response after the last of them.
    reports: Option<Sender<Vec<u8>>>,
}

/// What one of the poll's slots watches.
#[derive(Clone, Copy)]
enum Slot {
    Signals,
    Sandbox,
    Listener,
    UntilClosed,
    Connection(usize),
    Flight(usize),
}

impl<'a> Session<'a> {
    /// A session serving `sandbox` to the connections `listener` takes.
    pub fn new(
        sandbox: Running<'static>,
        listener: UnixListener,
        signals: &'a Signals,
        until_closed: Option<File>,
        reporter: Reporter,
        kill_after: Duration,
        path_lookup: bool,
    ) -> Session<'a> {
        Session {
            sandbox,
            listener: Some(listener),
            signals,
            until_closed,
            reporter,
            connections: Vec::new(),
            kill_after,
            path_lookup,
            ending: None,
            ended: None,
        }
    }

    /// Serves until the session ends, and answers why it did. Each exec still
    /// running when the sandbox ends is answered, and each connection's writer
    /// given [`LAST_WORDS`] to deliver what it holds.
    pub fn run(mut self) -> Result<EndReason, Fault> {
        // A handle's readiness descriptor reports its work once a wait has
        // asked it what it holds, so the sandbox's is asked once before the
        // poll waits on it, as each exec's is once it starts.
        self.collect_sandbox();
        while !self.finished() {
            for slot in self.wait()? {
                self.serve(slot);
            }
            self.expire();
            self.sweep();
        }
        // The sandbox's end begins the session's where nothing else had, so a
        // finished session is always ending.
        let reason = self
            .ending
            .as_ref()
            .map_or(EndReason::Stop, |(reason, _)| *reason);
        for connection in &mut self.connections {
            for id in std::mem::take(&mut connection.stops) {
                connection.outbox.deliver(result(&id, json!({})));
            }
        }
        let deadline = Instant::now().checked_add(LAST_WORDS);
        for connection in std::mem::take(&mut self.connections) {
            connection.outbox.finish(deadline);
        }
        Ok(reason)
    }

    /// Whether the session is done: the sandbox has ended and every exec has
    /// been collected.
    fn finished(&self) -> bool {
        self.ended.is_some()
            && self
                .connections
                .iter()
                .all(|connection| connection.flight.is_none())
    }

    /// Waits until something the session holds is ready, or its next
    /// deadline, and answers what is ready.
    fn wait(&self) -> Result<Vec<Slot>, Fault> {
        let mut slots = vec![Slot::Signals];
        let mut fds = vec![PollFd::new(self.signals, PollFlags::IN)];
        if self.ended.is_none() {
            slots.push(Slot::Sandbox);
            fds.push(PollFd::new(&self.sandbox, PollFlags::IN));
        }
        if let Some(listener) = &self.listener {
            slots.push(Slot::Listener);
            fds.push(PollFd::new(listener, PollFlags::IN));
        }
        if let Some(input) = &self.until_closed {
            slots.push(Slot::UntilClosed);
            fds.push(PollFd::new(input, PollFlags::IN));
        }
        for (index, connection) in self.connections.iter().enumerate() {
            // A connection no longer read is still watched for its close,
            // which `poll` reports whatever was asked; one already gone is
            // watched for nothing.
            if !connection.gone {
                let interest = match connection.reading {
                    true => PollFlags::IN,
                    false => PollFlags::empty(),
                };
                slots.push(Slot::Connection(index));
                fds.push(PollFd::new(&connection.stream, interest));
            }
            if let Some(flight) = &connection.flight {
                slots.push(Slot::Flight(index));
                fds.push(PollFd::new(&flight.running, PollFlags::IN));
            }
        }
        // The library states a `poll` timeout with its own `poll::timeout`,
        // which is private to it; over the public API a remainder a `Timespec`
        // cannot hold is no timeout at all, as the forwards read one.
        let timeout = self
            .next_deadline()
            .map(|at| at.saturating_duration_since(Instant::now()))
            .and_then(|left| Timespec::try_from(left).ok());
        match rustix::event::poll(&mut fds, timeout.as_ref()) {
            Ok(_) | Err(Errno::INTR) => {}
            Err(errno) => {
                let mut fault = Fault::of("fcage", &io::Error::from(errno));
                fault.message = format!("waiting on the session: {}", fault.message);
                return Err(fault);
            }
        }
        Ok(slots
            .into_iter()
            .zip(&fds)
            .filter(|(_, fd)| !fd.revents().is_empty())
            .map(|(slot, _)| slot)
            .collect())
    }

    /// The soonest deadline an escalation waits for.
    fn next_deadline(&self) -> Option<Instant> {
        let session = self
            .ending
            .as_ref()
            .and_then(|(_, escalation)| escalation.deadline())
            .filter(|_| self.ended.is_none());
        self.connections
            .iter()
            .filter_map(|connection| connection.flight.as_ref())
            .filter_map(|flight| flight.escalation.deadline())
            .chain(session)
            .min()
    }

    /// Serves what `slot` says is ready.
    fn serve(&mut self, slot: Slot) {
        match slot {
            Slot::Signals => self.take_signals(),
            Slot::Sandbox => self.collect_sandbox(),
            Slot::Listener => self.accept(),
            Slot::UntilClosed => self.read_until_closed(),
            Slot::Connection(index) => self.read(index),
            Slot::Flight(index) => self.collect(index),
        }
    }

    /// Reads the signals that arrived. The first that ends a session ends
    /// this one; a further one, while it ends, kills the sandbox at once.
    fn take_signals(&mut self) {
        loop {
            let signal = match self.signals.read() {
                Ok(Some(signal)) => signal,
                Ok(None) => return,
                Err(error) => {
                    self.reporter.report(format_args!(
                        "fcage: reading the signals that end the session: {}",
                        ferroday_cage::ErrorChain::new(&error)
                    ));
                    return;
                }
            };
            if !ENDING_SIGNALS
                .iter()
                .any(|ending| ending.as_raw() == signal)
            {
                continue;
            }
            match self.ending {
                None => self.begin_ending(EndReason::Signal(signal)),
                Some(_) if self.ended.is_none() => {
                    let _ = self.sandbox.kill();
                }
                Some(_) => {}
            }
        }
    }

    /// Begins the session's end: no further connection is taken, and the
    /// sandbox is asked to end, `SIGTERM` to every process of it, and killed
    /// past the grace.
    fn begin_ending(&mut self, reason: EndReason) {
        if self.ending.is_some() {
            return;
        }
        self.listener = None;
        let mut escalation = Escalation::new(Some(Duration::ZERO), self.kill_after);
        if self.ended.is_none()
            && let Err(error) = escalation.expire(&mut self.sandbox)
        {
            self.reporter.report(format_args!(
                "fcage: asking the sandbox to end: {}",
                ferroday_cage::ErrorChain::new(&error)
            ));
        }
        self.ending = Some((reason, escalation));
    }

    /// Collects the sandbox's outcome, where it has one: the sandbox has
    /// ended, and the session ends with it.
    fn collect_sandbox(&mut self) {
        match self.sandbox.try_wait() {
            Ok(Some(status)) => {
                self.ended = Some(status);
                if self.ending.is_none() {
                    self.begin_ending(EndReason::SandboxEnded(status));
                }
            }
            Ok(None) => {}
            Err(error) => {
                // The outcome is lost; the sandbox is ended and taken for it.
                self.reporter.report(format_args!(
                    "fcage: collecting the sandbox's end: {}",
                    ferroday_cage::ErrorChain::new(&error)
                ));
                let _ = self.sandbox.kill();
                let status = ExitStatus::signaled(Signal::KILL.as_raw());
                self.ended = Some(status);
                if self.ending.is_none() {
                    self.begin_ending(EndReason::SandboxEnded(status));
                }
            }
        }
    }

    /// Reads `--serve-until-closed`'s input, whose end ends the session.
    fn read_until_closed(&mut self) {
        let Some(input) = self.until_closed.as_mut() else {
            return;
        };
        let mut discard = [0u8; 4096];
        loop {
            match input.read(&mut discard) {
                Ok(0) => {
                    self.until_closed = None;
                    self.begin_ending(EndReason::Closed);
                    return;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) => {
                    self.reporter.report(format_args!(
                        "fcage: reading --serve-until-closed's input, which then ends the \
                         session: {}",
                        ferroday_cage::ErrorChain::new(&error)
                    ));
                    self.until_closed = None;
                    self.begin_ending(EndReason::Closed);
                    return;
                }
            }
        }
    }

    /// Takes the connections waiting, each only where its peer runs in the
    /// server's own user namespace.
    fn accept(&mut self) {
        let Some(listener) = &self.listener else {
            return;
        };
        loop {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                // A connection that went before it was taken, or a limit on
                // descriptors, which the next wake asks again about.
                Err(error) => {
                    self.reporter.report(format_args!(
                        "fcage: taking a connection: {}",
                        ferroday_cage::ErrorChain::new(&error)
                    ));
                    return;
                }
            };
            match ferroday_cage::host::peer_in_own_user_namespace(&stream) {
                Ok(true) => {}
                answer => {
                    refuse_peer(&stream, &answer);
                    let why = match &answer {
                        Ok(_) => "it runs in another user namespace, as a sandbox's process does"
                            .to_string(),
                        Err(error) => format!(
                            "its user namespace cannot be read: {}",
                            ferroday_cage::ErrorChain::new(error)
                        ),
                    };
                    self.reporter
                        .report(format_args!("fcage: refused a connection: {why}"));
                    continue;
                }
            }
            match Outbox::start(&stream) {
                Ok(outbox) => self.connections.push(Connection {
                    stream,
                    reader: Reader::default(),
                    outbox,
                    flight: None,
                    reading: true,
                    gone: false,
                    stops: Vec::new(),
                }),
                Err(error) => self.reporter.report(format_args!(
                    "fcage: starting the thread that writes to a connection: {}",
                    ferroday_cage::ErrorChain::new(&error)
                )),
            }
        }
    }

    /// Reads the requests connection `index` has sent, and serves each.
    fn read(&mut self, index: usize) {
        loop {
            let connection = &mut self.connections[index];
            if !connection.reading {
                // Watched for its close alone: `poll` reports a hangup.
                if peer_has_gone(&connection.stream) {
                    self.lose(index);
                }
                return;
            }
            match connection.reader.next(&connection.stream) {
                Ok(Framed::Message(message, fds)) => self.request(index, &message, fds),
                Ok(Framed::Pending) => {
                    if peer_has_gone(&connection.stream) {
                        self.lose(index);
                    }
                    return;
                }
                // The client shut its side: no further request comes, and
                // what it asked for is still answered.
                Ok(Framed::Closed) => {
                    connection.reading = false;
                    if peer_has_gone(&connection.stream) {
                        self.lose(index);
                    }
                    return;
                }
                Ok(Framed::Refused(why)) => {
                    let refusal = Refusal::new("protocol", why.to_string());
                    connection.outbox.deliver(refusal.response(&Value::Null));
                    self.lose(index);
                    return;
                }
                Err(_) => {
                    self.lose(index);
                    return;
                }
            }
        }
    }

    /// Takes connection `index` for gone: nothing more is read from it or
    /// written to it, and its exec is ended, `SIGTERM` and then a kill past
    /// the grace, with no one left to answer.
    fn lose(&mut self, index: usize) {
        let connection = &mut self.connections[index];
        connection.reading = false;
        connection.gone = true;
        connection.stops.clear();
        if let Some(flight) = &mut connection.flight {
            flight.reports = None;
            flight.escalation = Escalation::new(Some(Duration::ZERO), flight.kill_after);
            let _ = flight.escalation.expire(&mut flight.running);
        }
    }

    /// Serves one request of connection `index`'s, with the descriptors its
    /// first byte carried.
    fn request(&mut self, index: usize, message: &[u8], fds: Vec<OwnedFd>) {
        if message.iter().all(u8::is_ascii_whitespace) && fds.is_empty() {
            return;
        }
        let request = match Request::parse(message) {
            Ok(request) => request,
            Err((id, refusal)) => {
                self.answer(index, refusal.response(&id));
                return;
            }
        };
        let answer = match request.method.as_str() {
            "hello" => request.no_params().map(|()| {
                result(
                    &request.id,
                    json!({"protocol": events::PROTOCOL, "fcage": env!("CARGO_PKG_VERSION")}),
                )
            }),
            "exec" => match self.exec(index, &request, fds) {
                // Answered once it ends.
                Ok(()) => return,
                Err(refusal) => Err(refusal),
            },
            "stop" => match request.no_params() {
                Ok(()) => {
                    self.connections[index].stops.push(request.id.clone());
                    self.begin_ending(EndReason::Stop);
                    return;
                }
                Err(refusal) => Err(refusal),
            },
            other => Err(Refusal::new(
                "method-not-found",
                format!("no method is named {other:?}; the methods are hello, exec and stop"),
            )),
        };
        let line = answer.unwrap_or_else(|refusal| refusal.response(&request.id));
        self.answer(index, line);
    }

    /// Writes a response to connection `index`, closing the connection where
    /// it has stopped reading what it is sent.
    fn answer(&mut self, index: usize, line: Vec<u8>) {
        if !self.connections[index].outbox.deliver(line) {
            self.lose(index);
        }
    }

    /// Starts the exec `request` asks for on connection `index`, with `fds`
    /// as the streams it passes.
    fn exec(&mut self, index: usize, request: &Request, fds: Vec<OwnedFd>) -> Result<(), Refusal> {
        if self.connections[index].flight.is_some() {
            return Err(Refusal::new(
                "busy",
                "the connection runs an exec already; a connection runs one at a time".to_string(),
            ));
        }
        if self.ending.is_some() {
            return Err(match self.ended {
                Some(_) => Refusal::new("sandbox-ended", "the sandbox has ended".to_string()),
                None => Refusal::new("ending", "the session is ending".to_string()),
            });
        }
        let params: ExecParams = request.params_as()?;
        let (exec, timeout, kill_after) =
            params.into_exec(fds, self.path_lookup, self.kill_after)?;
        let mut running = self.sandbox.exec(&exec).map_err(|error| {
            let fault = Fault::of_cage(&error);
            Refusal::of_fault(fault).with("shell-code", json!(error.shell_code()))
        })?;
        let connection = &mut self.connections[index];
        connection
            .outbox
            .deliver(exec_event(&Event::started(running.pid()), &request.id));
        let reports = running.take_seccomp_reports().and_then(|reports| {
            ExecReports::start(reports, connection.outbox.handle(), request.id.clone())
                .inspect_err(|error| {
                    self.reporter.report(format_args!(
                        "fcage: starting the thread that hands on an exec's seccomp reports: {}",
                        ferroday_cage::ErrorChain::new(error)
                    ));
                })
                .ok()
        });
        connection.flight = Some(Flight {
            id: request.id.clone(),
            running,
            escalation: Escalation::new(timeout, kill_after),
            kill_after,
            reports,
        });
        self.collect(index);
        Ok(())
    }

    /// Collects the outcome of connection `index`'s exec, where it has one,
    /// and answers its request.
    fn collect(&mut self, index: usize) {
        let connection = &mut self.connections[index];
        let Some(flight) = &mut connection.flight else {
            return;
        };
        let line = match flight.running.try_wait() {
            Ok(None) => return,
            Ok(Some(status)) => {
                let status = flight.escalation.outcome(status);
                let code = status.map_or(crate::TIMED_OUT, |status| status.shell_code());
                let exited = events::Exited::of(status, flight.running.usage().as_ref(), code);
                result(
                    &flight.id,
                    serde_json::to_value(exited).unwrap_or(Value::Null),
                )
            }
            Err(error) => {
                let refusal = Refusal::of_fault(Fault::of_cage(&error))
                    .with("shell-code", json!(error.shell_code()));
                refusal.response(&flight.id)
            }
        };
        let flight = connection.flight.take().expect("checked above");
        if connection.gone {
            return;
        }
        match flight.reports {
            Some(handoff) => {
                // The thread writes it after the exec's last report; where the
                // thread has gone, it is written here.
                if let Err(mpsc::SendError(line)) = handoff.send(line) {
                    connection.outbox.deliver(line);
                }
            }
            None => {
                connection.outbox.deliver(line);
            }
        }
    }

    /// Acts on every escalation whose deadline has passed: an exec's timeout
    /// and the kill after it, and the session's own kill.
    fn expire(&mut self) {
        let now = Instant::now();
        for connection in &mut self.connections {
            if let Some(flight) = &mut connection.flight
                && flight.escalation.deadline().is_some_and(|at| at <= now)
            {
                let _ = flight.escalation.expire(&mut flight.running);
            }
        }
        if self.ended.is_none()
            && let Some((_, escalation)) = &mut self.ending
            && escalation.deadline().is_some_and(|at| at <= now)
        {
            let _ = escalation.expire(&mut self.sandbox);
        }
    }

    /// Lets go of every connection with nothing left to do: gone, or no longer
    /// read, with no exec running and no `stop` waiting for its answer.
    fn sweep(&mut self) {
        self.connections.retain(|connection| {
            let done = connection.flight.is_none()
                && (connection.gone || (!connection.reading && connection.stops.is_empty()));
            !done
        });
    }
}

/// Whether the client of `stream` has closed its socket both ways, which
/// `poll` reports as a hangup; a client that only shut its sending side has
/// not.
fn peer_has_gone(stream: &UnixStream) -> bool {
    let mut fds = [PollFd::new(stream, PollFlags::empty())];
    match rustix::event::poll(&mut fds, Some(&Timespec::default())) {
        Ok(_) => fds[0].revents().intersects(PollFlags::HUP | PollFlags::ERR),
        Err(_) => false,
    }
}

/// Tells a refused peer why, as well as a socket that is about to close can,
/// and closes it.
fn refuse_peer(stream: &UnixStream, answer: &io::Result<bool>) {
    let text = match answer {
        Ok(_) => {
            "the session serves only processes of its own user namespace; a sandbox's \
                  process is refused"
        }
        Err(_) => {
            "the session cannot tell where this process runs, and serves only processes \
                   it can place"
        }
    };
    let line = Refusal::new("peer-refused", text.to_string()).response(&Value::Null);
    // Without waiting: a fresh connection's buffer takes one line, and a peer
    // that does not read it loses nothing it was owed.
    let _ = rustix::net::send(stream, &line, SendFlags::DONTWAIT | SendFlags::NOSIGNAL);
}

// ---------------------------------------------------------------------------
// Reading a connection
// ---------------------------------------------------------------------------

/// A connection's reading of its client's messages: one JSON object a line,
/// descriptors only with a message's first byte.
#[derive(Default)]
struct Reader {
    /// The message read so far.
    partial: Vec<u8>,
    /// The descriptors that came with its first byte.
    fds: Vec<OwnedFd>,
    /// The buffer a peek looks ahead into.
    ahead: Vec<u8>,
}

/// What a connection's input holds next.
enum Framed {
    /// A whole message, without its newline, and the descriptors its first
    /// byte carried.
    Message(Vec<u8>, Vec<OwnedFd>),
    /// Nothing whole yet.
    Pending,
    /// The end of the client's input.
    Closed,
    /// A message the protocol refuses, which closes the connection.
    Refused(&'static str),
}

impl Reader {
    /// Reads what the client has sent without waiting, up to the end of the
    /// next whole message.
    fn next(&mut self, stream: &UnixStream) -> io::Result<Framed> {
        self.ahead.resize(PEEK, 0);
        loop {
            let peeked = match rustix::net::recv(
                stream,
                &mut self.ahead[..],
                RecvFlags::PEEK | RecvFlags::DONTWAIT,
            ) {
                Ok((peeked, _)) => peeked,
                Err(Errno::AGAIN) => return Ok(Framed::Pending),
                Err(Errno::INTR) => continue,
                Err(errno) => return Err(errno.into()),
            };
            if peeked == 0 {
                // A message cut off by the end is dropped with its
                // descriptors: nothing it asked for can be read whole.
                self.partial.clear();
                self.fds.clear();
                return Ok(Framed::Closed);
            }
            let newline = self.ahead[..peeked].iter().position(|&byte| byte == b'\n');
            let mut wanted = newline.map_or(peeked, |at| at + 1);
            if self.partial.is_empty() {
                // The first byte alone, so the descriptors that come with it
                // are the ones sent with this message's first byte.
                let (fds, truncated) = receive(stream, &mut self.partial, 1)?;
                // The control buffer's alignment leaves room for more than
                // three, so what arrived is counted as well as what the kernel
                // had no room for.
                if truncated || fds.len() > MAX_DESCRIPTORS {
                    return Ok(Framed::Refused(
                        "a message carried more descriptors than an exec's three streams",
                    ));
                }
                self.fds = fds;
                wanted -= 1;
            }
            if wanted > 0 {
                let (fds, truncated) = receive(stream, &mut self.partial, wanted)?;
                if truncated || !fds.is_empty() {
                    return Ok(Framed::Refused(
                        "descriptors arrived inside a message rather than with its first byte",
                    ));
                }
            }
            if self.partial.len() > MAX_MESSAGE {
                return Ok(Framed::Refused(
                    "a message was longer than the server reads",
                ));
            }
            if newline.is_some() {
                let mut message = std::mem::take(&mut self.partial);
                message.pop();
                return Ok(Framed::Message(message, std::mem::take(&mut self.fds)));
            }
        }
    }
}

/// Reads exactly `len` bytes the client has sent, which a peek has seen, onto
/// `into`, with the descriptors they carry, and whether the client sent more
/// descriptors than a message may carry.
fn receive(
    stream: &UnixStream,
    into: &mut Vec<u8>,
    len: usize,
) -> io::Result<(Vec<OwnedFd>, bool)> {
    let mut fds = Vec::new();
    let mut truncated = false;
    let start = into.len();
    into.resize(start + len, 0);
    let mut filled = 0;
    while filled < len {
        let mut space =
            [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(MAX_DESCRIPTORS))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = match rustix::net::recvmsg(
            stream,
            &mut [IoSliceMut::new(&mut into[start + filled..])],
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
        ) {
            Ok(received) => received,
            Err(Errno::INTR) => continue,
            Err(errno) => {
                into.truncate(start + filled);
                return Err(errno.into());
            }
        };
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(rights) = message {
                fds.extend(rights);
            }
        }
        truncated |= received.flags.contains(ReturnFlags::CTRUNC);
        if received.bytes == 0 {
            into.truncate(start + filled);
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled += received.bytes;
    }
    Ok((fds, truncated))
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// A request, its shape checked.
struct Request {
    /// Its id, a number or a string, which its response and its exec's events
    /// carry back.
    id: Value,
    /// The method it names.
    method: String,
    /// Its parameters, where it has any.
    params: Option<serde_json::Map<String, Value>>,
}

impl Request {
    /// Reads `message` as a request, or answers why not, with the id the
    /// response carries: the request's own where it could be read.
    fn parse(message: &[u8]) -> Result<Request, (Value, Refusal)> {
        let value: Value = serde_json::from_slice(message).map_err(|error| {
            (
                Value::Null,
                Refusal::new("parse", format!("the message is not JSON: {error}")),
            )
        })?;
        let Value::Object(mut object) = value else {
            return Err((
                Value::Null,
                Refusal::new("invalid-request", "a request is a JSON object".to_string()),
            ));
        };
        let id = match object.remove("id") {
            Some(id @ (Value::Number(_) | Value::String(_))) => id,
            _ => {
                return Err((
                    Value::Null,
                    Refusal::new(
                        "invalid-request",
                        "a request has an id, a number or a string".to_string(),
                    ),
                ));
            }
        };
        let invalid = |text: String| (id.clone(), Refusal::new("invalid-request", text));
        let method = match object.remove("method") {
            Some(Value::String(method)) => method,
            _ => {
                return Err(invalid(
                    "a request names its method as a string".to_string(),
                ));
            }
        };
        let params = match object.remove("params") {
            None => None,
            Some(Value::Object(params)) => Some(params),
            Some(_) => {
                return Err((
                    id,
                    Refusal::new(
                        "invalid-params",
                        "a request's params are an object".to_string(),
                    ),
                ));
            }
        };
        if let Some(member) = object.keys().next() {
            return Err(invalid(format!(
                "a request has no member {member:?}; its members are id, method and params"
            )));
        }
        Ok(Request { id, method, params })
    }

    /// Refuses parameters for a method that takes none.
    fn no_params(&self) -> Result<(), Refusal> {
        match &self.params {
            Some(params) if !params.is_empty() => Err(Refusal::new(
                "invalid-params",
                format!("{} takes no params", self.method),
            )),
            _ => Ok(()),
        }
    }

    /// The parameters, read as `T`.
    fn params_as<T: for<'de> Deserialize<'de>>(&self) -> Result<T, Refusal> {
        let params = Value::Object(self.params.clone().unwrap_or_default());
        serde_json::from_value(params).map_err(|error| {
            Refusal::new(
                "invalid-params",
                format!("{}'s params: {error}", self.method),
            )
        })
    }
}

/// An `exec` request's parameters.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ExecParams {
    /// The command: an absolute path, or with path lookup a bare name.
    command: Bytes,
    /// Its arguments, after the command.
    #[serde(default)]
    args: Vec<Bytes>,
    /// Variables set over the launch's environment, in order, as pairs.
    #[serde(default)]
    env: Vec<(Bytes, Bytes)>,
    /// The working directory, where not the launch's.
    #[serde(default)]
    cwd: Option<Bytes>,
    /// Whether a bare command name is looked up on `PATH`, where not as the
    /// launch says.
    #[serde(default)]
    path_lookup: Option<bool>,
    /// Standard input.
    #[serde(default)]
    stdin: Disposition,
    /// Standard output.
    #[serde(default)]
    stdout: Disposition,
    /// Standard error.
    #[serde(default)]
    stderr: Disposition,
    /// Seconds until the command is asked to end, as `--timeout` counts them.
    #[serde(default)]
    timeout: Option<f64>,
    /// Seconds from that until it is killed, as `--kill-after` counts them.
    #[serde(default)]
    kill_after: Option<f64>,
}

/// Where one of an exec's standard streams goes.
#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Disposition {
    /// Nowhere: `/dev/null`.
    #[default]
    Null,
    /// A descriptor the request passes, in stream order.
    Passed,
}

/// The streams by the names a refusal gives them, in stream order.
const STREAM_NAMES: [&str; 3] = ["stdin", "stdout", "stderr"];

impl ExecParams {
    /// The exec the parameters describe, its streams the descriptors `fds`
    /// passed in stream order, with its timeout and the grace before its kill.
    /// `path_lookup` and `kill_after` are what the session gives an exec that
    /// does not say.
    fn into_exec(
        self,
        fds: Vec<OwnedFd>,
        path_lookup: bool,
        kill_after: Duration,
    ) -> Result<(Exec, Option<Duration>, Duration), Refusal> {
        let dispositions = [self.stdin, self.stdout, self.stderr];
        let passed = dispositions
            .iter()
            .filter(|&&disposition| disposition == Disposition::Passed)
            .count();
        if passed != fds.len() {
            return Err(Refusal::new(
                "invalid-params",
                format!(
                    "the request passes {} descriptors and names {passed} streams \"passed\"",
                    fds.len()
                ),
            ));
        }
        let mut fds = fds.into_iter();
        let mut streams: [Stdio; 3] = [Stdio::Null, Stdio::Null, Stdio::Null];
        for ((stream, disposition), name) in streams.iter_mut().zip(dispositions).zip(STREAM_NAMES)
        {
            if disposition == Disposition::Passed {
                let fd = fds.next().expect("counted above");
                judge_passed(&fd, name)?;
                *stream = Stdio::from_fd(fd);
            }
        }
        let seconds = |name: &str, seconds: Option<f64>| {
            seconds
                .map(|seconds| crate::duration_of_seconds(name, seconds))
                .transpose()
                .map_err(|message| Refusal::new("invalid-params", message))
        };
        let timeout = seconds("timeout", self.timeout)?;
        let kill_after = seconds("kill-after", self.kill_after)?.unwrap_or(kill_after);
        let [stdin, stdout, stderr] = streams;
        let os = |bytes: &Bytes| OsStr::from_bytes(&bytes.0).to_os_string();
        let mut exec = Exec::new(PathBuf::from(os(&self.command)))
            .args(self.args.iter().map(os))
            .envs(self.env.iter().map(|(name, value)| (os(name), os(value))))
            .path_lookup(self.path_lookup.unwrap_or(path_lookup))
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr)
            // The server is the exec's caller: a server that goes takes its
            // execs with it.
            .stop_with_caller(true);
        if let Some(cwd) = &self.cwd {
            exec = exec.current_dir(PathBuf::from(os(cwd)));
        }
        Ok((exec, timeout, kill_after))
    }
}

/// Refuses a passed descriptor the command could not be handed as it is; see
/// the module documentation, and [`streams`], whose judgement this is.
fn judge_passed(fd: &OwnedFd, stream: &'static str) -> Result<(), Refusal> {
    let refused = |what: &str| {
        Refusal::new(
            "stream-refused",
            format!(
                "the {stream} passed is {what}; an exec is given a pipe, a socket or a \
                 character device"
            ),
        )
        .with("stream", json!(stream))
    };
    match streams::handling(fd.as_fd()) {
        Ok(streams::Handling::HandOver) => Ok(()),
        Ok(streams::Handling::Relay(_)) => Err(refused(
            "a file, which the command could reopen through /proc/self/fd with more access than \
             the descriptor carries; relay it through a pipe",
        )),
        Ok(streams::Handling::Refuse(what)) => Err(refused(what)),
        Err(error) => Err(refused(&format!(
            "a descriptor that cannot be examined ({})",
            ferroday_cage::ErrorChain::new(&error)
        ))),
    }
}

/// Why a request is refused: the error a response carries.
struct Refusal {
    /// The error's members: `code`, `text`, and those the code names.
    members: serde_json::Map<String, Value>,
}

impl Refusal {
    /// A refusal with `code`, saying `text`.
    fn new(code: &str, text: String) -> Refusal {
        let mut members = serde_json::Map::new();
        members.insert("code".to_string(), json!(code));
        members.insert("text".to_string(), json!(text));
        Refusal { members }
    }

    /// A refusal naming `fault` as the event stream names a failure: its kind
    /// as the code, and its step and errno where it has them.
    fn of_fault(fault: Fault) -> Refusal {
        let mut refusal = Refusal::new(fault.error, fault.message);
        if let Some(step) = fault.step {
            refusal = refusal.with("step", json!(step));
        }
        if let Some(errno) = fault.errno {
            refusal = refusal.with("errno", json!(errno));
        }
        refusal
    }

    /// The refusal with the member `name` added.
    fn with(mut self, name: &str, value: Value) -> Refusal {
        self.members.insert(name.to_string(), value);
        self
    }

    /// The response refusing the request `id` names.
    fn response(self, id: &Value) -> Vec<u8> {
        line(&json!({"id": id, "error": Value::Object(self.members)}))
    }
}

/// The response answering the request `id` names with `value`.
fn result(id: &Value, value: Value) -> Vec<u8> {
    line(&json!({"id": id, "result": value}))
}

/// `event` as a line of the connection, naming the exec `id` started.
fn exec_event(event: &Event, id: &Value) -> Vec<u8> {
    let mut value = serde_json::to_value(event).unwrap_or(Value::Null);
    if let Value::Object(members) = &mut value {
        members.insert("exec".to_string(), id.clone());
    }
    line(&value)
}

/// `value` as one line: its JSON and a newline.
fn line(value: &Value) -> Vec<u8> {
    // A value built of maps with string keys always writes.
    let mut line = serde_json::to_vec(value).unwrap_or_default();
    line.push(b'\n');
    line
}

// ---------------------------------------------------------------------------
// Writing a connection
// ---------------------------------------------------------------------------

/// What a connection's writer writes, in the order it is handed them.
enum Line {
    /// An event a report made, which is dropped and counted where the writer
    /// holds [`QUEUED_REPORTS`] of them already.
    Report(Vec<u8>),
    /// A response or an event the client is owed, which is never dropped.
    Owed(Vec<u8>),
}

/// A connection's writer: a thread of its own that writes what it is handed,
/// so a client that stops reading holds up only its own connection.
///
/// A second answer to what the CLI's `output::Reports` answers, a thread
/// writing what others hand it without their waiting on its reader. That one
/// carries reports alone, any of which it may drop; a connection's writer also
/// carries responses, which it must not, so it holds those without a bound and
/// the session closes a connection that lets them pile up.
struct Outbox {
    /// Where the lines go to the writer.
    queue: Sender<Line>,
    /// The reports and the owed lines handed over and not yet written.
    counts: Arc<Counts>,
    /// The socket, to shut where the writer cannot deliver at the session's
    /// end.
    stream: UnixStream,
    /// Hangs up once the writer has finished.
    finished: Receiver<()>,
    /// The writer.
    writer: JoinHandle<()>,
}

/// What a connection's writer holds, counted for the threads handing it lines.
#[derive(Default)]
struct Counts {
    /// Reports handed over and not yet written.
    reports: AtomicUsize,
    /// Reports dropped since the writer last said how many.
    dropped: AtomicUsize,
    /// Owed lines handed over and not yet written.
    owed: AtomicUsize,
}

/// A handle for a thread other than the session's to hand a connection lines.
#[derive(Clone)]
struct OutboxHandle {
    queue: Sender<Line>,
    counts: Arc<Counts>,
}

impl OutboxHandle {
    /// Hands over a report's line, or drops and counts it where the writer
    /// holds [`QUEUED_REPORTS`] already.
    fn offer(&self, line: Vec<u8>) {
        if self.counts.reports.load(Ordering::Relaxed) >= QUEUED_REPORTS {
            self.counts.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.counts.reports.fetch_add(1, Ordering::Relaxed);
        if self.queue.send(Line::Report(line)).is_err() {
            self.counts.reports.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Hands over a line the client is owed. Answers `false` where the writer
    /// already holds [`MAX_UNWRITTEN`] of them, which the client has not read.
    fn deliver(&self, line: Vec<u8>) -> bool {
        if self.counts.owed.load(Ordering::Relaxed) >= MAX_UNWRITTEN {
            return false;
        }
        self.counts.owed.fetch_add(1, Ordering::Relaxed);
        if self.queue.send(Line::Owed(line)).is_err() {
            self.counts.owed.fetch_sub(1, Ordering::Relaxed);
        }
        true
    }
}

impl Outbox {
    /// Starts the writer for `stream`.
    fn start(stream: &UnixStream) -> io::Result<Outbox> {
        let (queue, lines) = mpsc::channel();
        let (done, finished) = mpsc::sync_channel(0);
        let counts = Arc::new(Counts::default());
        let mut out = stream.try_clone()?;
        let writer = std::thread::Builder::new()
            .name("fcage-connection".to_string())
            .spawn({
                let counts = Arc::clone(&counts);
                move || {
                    write_lines(&mut out, &lines, &counts);
                    drop(done);
                }
            })?;
        Ok(Outbox {
            queue,
            counts,
            stream: stream.try_clone()?,
            finished,
            writer,
        })
    }

    /// A handle for another thread.
    fn handle(&self) -> OutboxHandle {
        OutboxHandle {
            queue: self.queue.clone(),
            counts: Arc::clone(&self.counts),
        }
    }

    /// Hands over a line the client is owed; see [`OutboxHandle::deliver`].
    fn deliver(&self, line: Vec<u8>) -> bool {
        self.handle().deliver(line)
    }

    /// Lets the writer deliver what it holds, by `deadline` at the latest, and
    /// then shuts the socket, which ends a write the client never takes.
    fn finish(self, deadline: Option<Instant>) {
        let Outbox {
            queue,
            stream,
            finished,
            writer,
            ..
        } = self;
        drop(queue);
        let patience = deadline.map_or(Duration::ZERO, |at| {
            at.saturating_duration_since(Instant::now())
        });
        if let Err(RecvTimeoutError::Timeout) = finished.recv_timeout(patience) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let _ = writer.join();
    }
}

/// The writer's body: writes each line as it comes, until every sender is gone
/// or the client stops taking them, and says before an owed line how many
/// reports it dropped.
fn write_lines(out: &mut UnixStream, lines: &Receiver<Line>, counts: &Counts) {
    let mut broken = false;
    let mut write = |out: &mut UnixStream, bytes: &[u8]| {
        if !broken && out.write_all(bytes).is_err() {
            broken = true;
        }
    };
    loop {
        let line = match lines.try_recv() {
            Ok(line) => line,
            Err(TryRecvError::Empty) => {
                say_dropped(out, counts, &mut write);
                match lines.recv() {
                    Ok(line) => line,
                    Err(_) => break,
                }
            }
            Err(TryRecvError::Disconnected) => break,
        };
        match line {
            Line::Report(bytes) => {
                counts.reports.fetch_sub(1, Ordering::Relaxed);
                write(out, &bytes);
            }
            Line::Owed(bytes) => {
                say_dropped(out, counts, &mut write);
                counts.owed.fetch_sub(1, Ordering::Relaxed);
                write(out, &bytes);
            }
        }
    }
    say_dropped(out, counts, &mut write);
}

/// Writes a `dropped` event for the reports dropped since the last, where any
/// were.
fn say_dropped(
    out: &mut UnixStream,
    counts: &Counts,
    write: &mut impl FnMut(&mut UnixStream, &[u8]),
) {
    let count = counts.dropped.swap(0, Ordering::Relaxed);
    if count > 0 {
        let plural = if count == 1 { "" } else { "s" };
        let event = Event::dropped(
            "fcage",
            count as u64,
            format!(
                "fcage: dropped {count} report{plural} while the connection was not taking them"
            ),
        );
        write(out, &event.line());
    }
}

// ---------------------------------------------------------------------------
// An exec's seccomp reports
// ---------------------------------------------------------------------------

/// The thread handing an exec's seccomp reports to its connection, which
/// writes the exec's response once the last of them is written.
struct ExecReports;

impl ExecReports {
    /// Starts handing on `reports` for the exec `id` started, to `outbox`, and
    /// returns where the response goes once the exec has ended.
    fn start(
        reports: Reports<SeccompReport>,
        outbox: OutboxHandle,
        id: Value,
    ) -> io::Result<Sender<Vec<u8>>> {
        let (handoff, response) = mpsc::channel();
        std::thread::Builder::new()
            .name("fcage-exec-reports".to_string())
            .spawn(move || hand_on(&reports, &outbox, &id, &response))?;
        Ok(handoff)
    }
}

/// The thread's body: hands on each report until they end, or until
/// [`LAST_REPORTS`] past the exec's end, and then writes the response.
///
/// The reports end once no process the exec's filter governs is left, which a
/// process it left behind holds off; the response is not held for that.
fn hand_on(
    reports: &Reports<SeccompReport>,
    outbox: &OutboxHandle,
    id: &Value,
    response: &Receiver<Vec<u8>>,
) {
    let mut owed = None;
    let mut until = None;
    let mut lingering = false;
    loop {
        if owed.is_none() {
            match response.try_recv() {
                Ok(line) => {
                    owed = Some(line);
                    until = Instant::now().checked_add(LAST_REPORTS);
                }
                // The connection went: nothing is owed, and the reports are
                // handed on to nobody.
                Err(TryRecvError::Disconnected) => return,
                Err(TryRecvError::Empty) => {}
            }
        }
        let patience = match until {
            Some(at) => at.saturating_duration_since(Instant::now()),
            None => REPORTS_GLANCE,
        };
        match reports.recv_timeout(patience) {
            Ok(report) => outbox.offer(exec_event(&events::seccomp(&report), id)),
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {
                if until.is_some_and(|at| Instant::now() >= at) {
                    lingering = true;
                    break;
                }
            }
        }
    }
    let dropped = reports.dropped();
    if dropped > 0 {
        let plural = if dropped == 1 { "" } else { "s" };
        let event = Event::dropped(
            "seccomp",
            dropped,
            format!(
                "fcage: the seccomp filter dropped {dropped} report{plural} its queue had no room \
                 for"
            ),
        );
        outbox.deliver(exec_event(&event, id));
    }
    if lingering {
        let event = Event::warning(
            "fcage: a process the command left behind still runs under the seccomp filter, and \
             what it refuses from here on is not written"
                .to_string(),
        );
        outbox.deliver(exec_event(&event, id));
    }
    let owed = match owed {
        Some(line) => Some(line),
        None => response.recv().ok(),
    };
    if let Some(line) = owed {
        outbox.deliver(line);
    }
}

#[cfg(test)]
mod tests {
    use std::io::IoSlice;
    use std::os::fd::BorrowedFd;

    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage};

    use super::*;

    /// Sends `bytes` on `stream` in one message, with `fds` attached to its
    /// first byte.
    fn send(stream: &UnixStream, bytes: &[u8], fds: &[BorrowedFd<'_>]) {
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !fds.is_empty() {
            assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
        }
        let sent = rustix::net::sendmsg(
            stream,
            &[IoSlice::new(bytes)],
            &mut control,
            SendFlags::empty(),
        )
        .expect("the message is sent");
        assert_eq!(sent, bytes.len());
    }

    /// A descriptor to pass: one end of a pipe.
    fn descriptor() -> OwnedFd {
        rustix::pipe::pipe().expect("a pipe").0
    }

    /// What `reader` makes of `stream` next.
    fn next(reader: &mut Reader, stream: &UnixStream) -> Framed {
        reader.next(stream).expect("the stream reads")
    }

    #[test]
    fn a_messages_descriptors_are_the_ones_its_first_byte_carried() {
        let (client, server) = UnixStream::pair().expect("a socket pair");
        let mut reader = Reader::default();
        let passed = descriptor();
        // Two messages queued before the server reads either: the first with
        // no descriptor, the second with one.
        send(&client, b"{\"id\":1}\n", &[]);
        send(&client, b"{\"id\":2}\n", &[passed.as_fd()]);
        match next(&mut reader, &server) {
            Framed::Message(message, fds) => {
                assert_eq!(message, b"{\"id\":1}");
                assert!(fds.is_empty(), "the second message's descriptor came early");
            }
            _ => panic!("the first message"),
        }
        match next(&mut reader, &server) {
            Framed::Message(message, fds) => {
                assert_eq!(message, b"{\"id\":2}");
                assert_eq!(fds.len(), 1);
            }
            _ => panic!("the second message"),
        }
        assert!(matches!(next(&mut reader, &server), Framed::Pending));
        drop(client);
        assert!(matches!(next(&mut reader, &server), Framed::Closed));
    }

    #[test]
    fn a_descriptor_inside_a_message_is_refused_however_it_is_queued() {
        // The message's two parts queued together, and with a read between
        // them: either way the descriptor came with its second part.
        for read_between in [false, true] {
            let (client, server) = UnixStream::pair().expect("a socket pair");
            let mut reader = Reader::default();
            let passed = descriptor();
            send(&client, b"{\"id\":", &[]);
            if read_between {
                assert!(matches!(next(&mut reader, &server), Framed::Pending));
            }
            send(&client, b"1}\n", &[passed.as_fd()]);
            assert!(
                matches!(next(&mut reader, &server), Framed::Refused(_)),
                "read between: {read_between}"
            );
        }
    }

    #[test]
    fn a_message_whole_only_across_reads_is_read_whole() {
        let (client, server) = UnixStream::pair().expect("a socket pair");
        let mut reader = Reader::default();
        let passed = descriptor();
        send(&client, b"{\"id\":", &[passed.as_fd()]);
        assert!(matches!(next(&mut reader, &server), Framed::Pending));
        send(&client, b"1}", &[]);
        assert!(matches!(next(&mut reader, &server), Framed::Pending));
        send(&client, b"\n", &[]);
        match next(&mut reader, &server) {
            Framed::Message(message, fds) => {
                assert_eq!(message, b"{\"id\":1}");
                assert_eq!(fds.len(), 1, "the first byte's descriptor is kept");
            }
            _ => panic!("the message"),
        }
    }

    #[test]
    fn more_descriptors_than_three_streams_are_refused() {
        let (client, server) = UnixStream::pair().expect("a socket pair");
        let mut reader = Reader::default();
        let passed: Vec<OwnedFd> = (0..4).map(|_| descriptor()).collect();
        let borrowed: Vec<BorrowedFd<'_>> = passed.iter().map(AsFd::as_fd).collect();
        send(&client, b"{\"id\":1}\n", &borrowed);
        assert!(matches!(next(&mut reader, &server), Framed::Refused(_)));
    }

    #[test]
    fn a_request_is_read_strictly() {
        let id = |message: &str| match Request::parse(message.as_bytes()) {
            Ok(request) => Ok(request.id),
            Err((id, refusal)) => Err((id, refusal.members["code"].clone())),
        };
        assert_eq!(id(r#"{"id": "a", "method": "hello"}"#), Ok(json!("a")));
        assert_eq!(
            id(r#"{"id": 7, "method": "hello", "params": {}}"#),
            Ok(json!(7))
        );
        for (message, answered_id, code) in [
            ("[]", Value::Null, "invalid-request"),
            (r#"{"method": "hello"}"#, Value::Null, "invalid-request"),
            (
                r#"{"id": null, "method": "hello"}"#,
                Value::Null,
                "invalid-request",
            ),
            (r#"{"id": 1.5e400}"#, Value::Null, "parse"),
            (r#"{"id": 3}"#, json!(3), "invalid-request"),
            (r#"{"id": 3, "method": 4}"#, json!(3), "invalid-request"),
            (
                r#"{"id": 3, "method": "hello", "params": []}"#,
                json!(3),
                "invalid-params",
            ),
            (
                r#"{"id": 3, "method": "hello", "jsonrpc": "2.0"}"#,
                json!(3),
                "invalid-request",
            ),
        ] {
            assert_eq!(id(message), Err((answered_id, json!(code))), "{message}");
        }
    }

    #[test]
    fn an_exec_names_as_many_passed_streams_as_it_passes() {
        let params = |value: Value| -> ExecParams {
            serde_json::from_value(value).expect("the params read")
        };
        let refused = |value: Value, fds: Vec<OwnedFd>| {
            params(value)
                .into_exec(fds, false, Duration::from_secs(10))
                .err()
                .map(|refusal| refusal.members["code"].clone())
        };
        assert_eq!(
            refused(
                json!({"command": "/bin/true", "stdout": "passed"}),
                Vec::new()
            ),
            Some(json!("invalid-params"))
        );
        assert_eq!(
            refused(json!({"command": "/bin/true"}), vec![descriptor()]),
            Some(json!("invalid-params"))
        );
        assert_eq!(
            refused(
                json!({"command": "/bin/true", "stdin": "passed"}),
                vec![descriptor()]
            ),
            None
        );
        let (exec, timeout, kill_after) = params(json!({
            "command": "/bin/true", "timeout": 1.5, "path-lookup": false,
        }))
        .into_exec(Vec::new(), true, Duration::from_secs(10))
        .ok()
        .expect("accepted");
        assert_eq!(timeout, Some(Duration::from_millis(1500)));
        assert_eq!(kill_after, Duration::from_secs(10), "the session's grace");
        assert!(!exec.get_path_lookup(), "the exec's own setting wins");
        assert!(exec.get_stop_with_caller(), "an exec ends with its server");
    }
}
