//! `fcage --exec`: a command run in the sandbox an `fcage --serve` session
//! holds, with this process's standard streams as its own.
//!
//! The client connects to the session's socket, sends one `exec` request with
//! its standard streams passed as descriptors, and waits for the answer. The
//! command reads the client's input and writes its output with nothing between
//! them, as a launch's command does. A stream that is a file is relayed through
//! a pipe instead, for the reason [`streams`] gives, and the session refuses
//! one passed as it is.
//!
//! `SIGINT`, `SIGTERM`, `SIGHUP` and `SIGQUIT` sent to the client are forwarded
//! to the command as `signal` requests, so a `^C` at the client's terminal
//! reaches the command. The client reads its signals as data, as a session's
//! server does, and drops the others of the relay's set, so `^Z` does not stop
//! it.
//!
//! The client exits as the command did, with 124 where its timeout expired,
//! and with 125 for a failure of its own: a session it cannot reach, an exec
//! the session refuses, or a connection that ends before the answer. Its death
//! closes the connection, and the session then ends the command: `SIGTERM`,
//! and a kill past the grace.
//!
//! What it says is what a launch says: the exec's events as they arrive,
//! `started` and the seccomp filter's reports among them, and then `exited` or
//! `failed`, on `--events`' stream, and otherwise each one's line on standard
//! error.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ferroday_cage::relay::Signals;
use rustix::event::{PollFd, PollFlags};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use rustix::process::Signal;
use serde_json::{Map, Value, json};

use crate::events::Fault;
use crate::output;
use crate::session::{self, Disposition, ExecParams, Framed, Reader};
use crate::streams::{self, StreamRelay};
use crate::{Diagnostic, FAILED, Failure, fail};

/// The signals the client forwards to the command.
const FORWARDED: [Signal; 4] = [Signal::INT, Signal::TERM, Signal::HUP, Signal::QUIT];

/// The id of the client's one `exec` request. Each `signal` request takes the
/// number after the last one sent.
const EXEC_ID: u64 = 1;

/// What `fcage --exec` runs, and where.
pub struct Call {
    /// The session's socket, as `--exec` names it.
    pub socket: PathBuf,
    /// The request's parameters, each stream the client passes `passed`.
    pub params: ExecParams,
}

/// How the session answered the exec.
enum Answer {
    /// The command ended: an `exited` event's members.
    Ended(Map<String, Value>),
    /// The command did not run: the response's error.
    Refused(Map<String, Value>),
}

/// Runs `call`, and returns what `fcage --exec` exits with.
pub fn run(call: Call) -> ExitCode {
    // Blocked before any thread of the client's exists, so each inherits the
    // mask and a signal to forward reaches the client's poll, rather than
    // ending the client and, with its connection, the command.
    let signals = match Signals::install() {
        Ok(signals) => signals,
        Err(error) => return fail(error),
    };
    let params = &call.params;
    let inherited = [params.stdin, params.stdout, params.stderr]
        .map(|disposition| disposition == Disposition::Passed);
    let judged = match streams::Judged::streams(inherited) {
        Ok(judged) => judged,
        Err(error) => return fail(error),
    };
    // Connected before a relay starts, so a session that cannot be reached
    // leaves the client's input unread.
    let stream = match connect(&call.socket) {
        Ok(stream) => stream,
        Err(fault) => return fail(Diagnostic(fault)),
    };
    let mut relay = match judged.start() {
        Ok(relay) => relay,
        Err(error) => return fail(error),
    };
    let answer = match passed_streams(&mut relay, inherited) {
        Ok(passed) => send_exec(&stream, params, passed).and_then(|()| converse(&stream, &signals)),
        Err(error) => Err(lost(fault_of("passing the standard streams", &error))),
    };
    // The connection's close is what ends a command the client gave up on.
    drop(stream);
    let undelivered = relay.finish();
    let code = conclude(answer);
    crate::undelivered_code(&undelivered).unwrap_or(code)
}

/// Connects to the session's socket at `path`, through a descriptor of its
/// directory, as the server binds it, so a path longer than a socket's address
/// is reached all the same.
fn connect(path: &Path) -> Result<UnixStream, Fault> {
    let refused = |what: &str| Fault::plain("fcage", format!("--exec {}: {what}", path.display()));
    let (parent, name) = session::place(path)
        .ok_or_else(|| refused("the path names no socket; give the socket a session serves on"))?;
    let directory = session::open_directory(parent)?;
    let address = session::address_in(&directory, name)
        .ok_or_else(|| refused("the socket's name is too long for a unix socket's address"))?;
    let socket = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|errno| fault_of("connecting to the session", &errno.into()))?;
    rustix::net::connect(&socket, &address).map_err(|errno| match errno {
        Errno::NOENT => refused("no session serves there"),
        Errno::CONNREFUSED => {
            refused("nothing listens there: the session has ended or not yet begun")
        }
        errno => fault_of(
            &format!("connecting to {}", path.display()),
            &io::Error::from(errno),
        ),
    })?;
    Ok(UnixStream::from(socket))
}

/// The descriptors the request passes, in stream order: each relayed stream's
/// pipe, and each other inherited stream as the client holds it.
fn passed_streams(relay: &mut StreamRelay, inherited: [bool; 3]) -> io::Result<Vec<OwnedFd>> {
    relay
        .take_replacements()
        .into_iter()
        .zip(streams::own_streams())
        .zip(inherited)
        .filter(|(_, inherited)| *inherited)
        .map(|((replacement, own), _)| replacement.map_or_else(|| own.try_clone_to_owned(), Ok))
        .collect()
}

/// Sends the `exec` request with `passed` attached, and closes the client's
/// copies, so a relay's pipe reaches its end once the command closes its own.
fn send_exec(
    stream: &UnixStream,
    params: &ExecParams,
    passed: Vec<OwnedFd>,
) -> Result<(), Failure> {
    let params = serde_json::to_value(params).unwrap_or(Value::Null);
    let line = session::line(&json!({"id": EXEC_ID, "method": "exec", "params": params}));
    let fds: Vec<BorrowedFd<'_>> = passed.iter().map(AsFd::as_fd).collect();
    session::send_message(stream, &line, &fds)
        .map_err(|error| lost(fault_of("sending the request to the session", &error)))
}

/// Waits for the exec's answer, saying its events as they come and forwarding
/// the signals the client receives meanwhile.
fn converse(stream: &UnixStream, signals: &Signals) -> Result<Answer, Failure> {
    let mut reader = Reader::default();
    let mut next_id = EXEC_ID + 1;
    loop {
        let mut fds = [
            PollFd::new(signals, PollFlags::IN),
            PollFd::new(stream, PollFlags::IN),
        ];
        match rustix::event::poll(&mut fds, None) {
            Ok(_) | Err(Errno::INTR) => {}
            Err(errno) => return Err(lost(fault_of("waiting on the session", &errno.into()))),
        }
        if !fds[0].revents().is_empty() {
            forward(stream, signals, &mut next_id)?;
        }
        if fds[1].revents().is_empty() {
            continue;
        }
        loop {
            match reader.next(stream) {
                Ok(Framed::Message(message, fds)) => {
                    if let Some(answer) = take(&message, &fds)? {
                        return Ok(answer);
                    }
                }
                Ok(Framed::Pending) => break,
                Ok(Framed::Closed) => {
                    return Err(lost(Fault::plain(
                        "fcage",
                        "the session closed the connection before the command ended".to_string(),
                    )));
                }
                Ok(Framed::Refused(why)) => {
                    return Err(lost(Fault::plain(
                        "fcage",
                        format!("reading the session's answer: {why}"),
                    )));
                }
                Err(error) => return Err(lost(fault_of("reading the session's answer", &error))),
            }
        }
    }
}

/// Forwards each pending signal of [`FORWARDED`] to the command, as a `signal`
/// request, and drops the others.
fn forward(stream: &UnixStream, signals: &Signals, next_id: &mut u64) -> Result<(), Failure> {
    loop {
        let signal = match signals.read() {
            Ok(Some(signal)) => signal,
            Ok(None) => return Ok(()),
            Err(error) => return Err(Failure::from(error)),
        };
        if !FORWARDED
            .iter()
            .any(|forwarded| forwarded.as_raw() == signal)
        {
            continue;
        }
        let params = json!({"exec": EXEC_ID, "signal": signal});
        let line = session::line(&json!({"id": *next_id, "method": "signal", "params": params}));
        *next_id += 1;
        // A session that has gone is read as the connection's end, which is
        // what the client reports.
        let _ = session::send_message(stream, &line, &[]);
    }
}

/// Takes one message of the session's: says it where it is an event, and
/// answers the exec's answer where it is that.
fn take(message: &[u8], fds: &[OwnedFd]) -> Result<Option<Answer>, Failure> {
    let unexpected = |what: &str| lost(Fault::plain("fcage", format!("the session sent {what}")));
    if !fds.is_empty() {
        return Err(unexpected(
            "descriptors, which no answer to an exec carries",
        ));
    }
    let Ok(Value::Object(mut message)) = serde_json::from_slice::<Value>(message) else {
        return Err(unexpected("a message that is not a JSON object"));
    };
    if message.contains_key("event") {
        // The exec's own events are the client's run's, so the member naming
        // the exec, which is the connection's, does not go with them.
        message.remove("exec");
        output::say_received(&message).map_err(|_| Failure::ReaderGone)?;
        return Ok(None);
    }
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    match (message.remove("result"), message.remove("error")) {
        (Some(Value::Object(result)), None) if id == EXEC_ID => Ok(Some(Answer::Ended(result))),
        (None, Some(Value::Object(error))) if id == EXEC_ID => Ok(Some(Answer::Refused(error))),
        // A signal's answer. A signal that crossed the command's end names no
        // exec of the connection's any more, and the end's answer follows.
        (_, Some(Value::Object(error))) if id.is_u64() => {
            if error.get("code").and_then(Value::as_str) != Some("no-such-exec") {
                output::report(format_args!(
                    "fcage: the session did not forward a signal: {}",
                    text_of(&error)
                ));
            }
            Ok(None)
        }
        (Some(_), None) if id.is_u64() => Ok(None),
        // An error answering no request: the session refused the connection,
        // or what the client sent.
        (None, Some(Value::Object(error))) => {
            Err(lost(Fault::plain("fcage", text_of(&error).to_string())))
        }
        _ => Err(unexpected(
            "a message that is neither an event nor an answer",
        )),
    }
}

/// Says how the exec ended, and answers what the client exits with.
fn conclude(answer: Result<Answer, Failure>) -> ExitCode {
    match answer {
        Ok(Answer::Ended(mut exited)) => {
            let code = shell_code(&exited).unwrap_or(FAILED);
            exited.insert("event".to_string(), json!("exited"));
            let _ = output::say_received(&exited);
            ExitCode::from(code)
        }
        Ok(Answer::Refused(error)) => {
            // A failure the session names is said as a launch says one: what
            // failed, its step and its errno where it has them, and the exit
            // status a launch failing so would have.
            let code = shell_code(&error).unwrap_or(FAILED);
            let mut failed = Map::new();
            failed.insert("event".to_string(), json!("failed"));
            failed.insert(
                "error".to_string(),
                error.get("code").cloned().unwrap_or(json!("fcage")),
            );
            for member in ["step", "errno"] {
                if let Some(value) = error.get(member) {
                    failed.insert(member.to_string(), value.clone());
                }
            }
            failed.insert("shell-code".to_string(), json!(code));
            failed.insert(
                "text".to_string(),
                json!(format!("fcage: {}", text_of(&error))),
            );
            let _ = output::say_received(&failed);
            ExitCode::from(code)
        }
        Err(failure) => failure.report(),
    }
}

/// The exit status a session's answer names, where it names one a process can
/// exit with.
fn shell_code(answer: &Map<String, Value>) -> Option<u8> {
    answer
        .get("shell-code")
        .and_then(Value::as_u64)
        .and_then(|code| u8::try_from(code).ok())
}

/// What an error the session sent says.
fn text_of(error: &Map<String, Value>) -> &str {
    error
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or("the session gave no reason")
}

/// A failure of the client's own, `doing` what failed, with `error` beneath.
fn fault_of(doing: &str, error: &io::Error) -> Fault {
    let mut fault = Fault::of("fcage", error);
    fault.message = format!("{doing}: {}", fault.message);
    fault
}

/// The client's own failure, which exits [`FAILED`].
fn lost(fault: Fault) -> Failure {
    Failure::Fcage(Diagnostic(fault))
}
