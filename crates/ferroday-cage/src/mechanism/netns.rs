//! Work done inside a sandbox's network namespace, on a helper process, for a
//! caller whose own threads never change namespace.
//!
//! The shape is dictated by a kernel rule. `setns` to a network namespace
//! demands `CAP_SYS_ADMIN` in the caller's *own* user namespace as well as the
//! target's, so no thread of an unprivileged caller can join the sandbox's
//! network namespace directly; owning it is not enough. Entering the sandbox's
//! *user* namespace first acquires those capabilities (the caller's user created
//! it, which is exactly what that entry requires), but the kernel refuses
//! user-namespace entry to any multithreaded process. A freshly forked child is
//! single-threaded by construction, so a helper forks, joins the user namespace
//! and then the network namespace, does its work, and hands one descriptor back
//! over a socket pair before it exits.
//!
//! Everything the helper opens after joining belongs to the sandbox's network
//! namespace: a socket is created in the namespace of the process creating it,
//! the tun clone device captures its namespace at open, and `/proc/sys/net`
//! resolves against the opener's namespace. The descriptor keeps that
//! namespace once the helper has gone.
//!
//! Two callers share the helper: the network stack's tap
//! (`netstack::tap::create`), and [`listen`], the listener
//! [`Pending::listen`](crate::Pending::listen) hands a caller.
//!
//! The fork may happen while other caller threads hold locks, so the helper
//! runs under the constraints [`child`](super::child) documents: everything it
//! needs is marshaled before the fork, and it allocates nothing, takes no
//! lock, and never panics. A failure travels back as one outcome record naming
//! the step in the caller's own vocabulary, and the caller turns it into its
//! typed error.

use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SendFlags, SocketFlags, SocketType};
use rustix::thread::LinkNameSpaceType;

use super::child::sweep_fds_keeping;
use super::frame::{self, RECORD_DONE, RECORD_LEN};
use super::sys::{self, PidfdFork};
use crate::wire::wire_enum;

/// The sandbox's user and network namespaces, opened for a helper to join.
///
/// The user namespace is joined first, for the capabilities the network
/// namespace's join demands; the network namespace is where the helper works.
pub(crate) struct Namespaces {
    /// The sandbox's user namespace.
    user: OwnedFd,
    /// The sandbox's network namespace.
    net: OwnedFd,
}

impl Namespaces {
    /// Opens the namespaces of the process `pid` names, through
    /// `/proc/<pid>/ns`.
    ///
    /// `pid` is a pending launch's supervisor, which the pending handle keeps
    /// alive, so the pid cannot be recycled while these are opened. A failure
    /// names what was being opened, as a phrase that completes "while".
    pub(crate) fn of(pid: u32) -> Result<Namespaces, (&'static str, Errno)> {
        let open = |kind: &str| {
            rustix::fs::open(
                format!("/proc/{pid}/ns/{kind}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
        };
        let net =
            open("net").map_err(|errno| ("opening the sandbox's network namespace", errno))?;
        let user = open("user").map_err(|errno| ("opening the sandbox's user namespace", errno))?;
        Ok(Namespaces { user, net })
    }
}

/// The wire values a caller gives the four steps every helper takes, in the
/// caller's own step vocabulary.
///
/// Each caller reports every failure of its helper in one vocabulary of its
/// own, the steps the helper shares with the other caller's included, as each
/// mapped-namespace helper names `child::MapStep` in its own.
pub(crate) struct JoinSteps {
    /// Closing the helper's inherited descriptors.
    pub(crate) sweep_fds: u32,
    /// Joining the sandbox's user namespace.
    pub(crate) join_user: u32,
    /// Joining the sandbox's network namespace.
    pub(crate) join_net: u32,
    /// Sending the descriptor back to the caller.
    pub(crate) send: u32,
}

/// How a helper ended without delivering its descriptor.
#[derive(Debug)]
pub(crate) enum HelperFailure {
    /// The helper could not be started: its socket pair or its fork failed.
    Spawn(Errno),
    /// The helper failed at a step, named by the caller's own wire value.
    Step {
        /// The step's wire value, in the caller's vocabulary.
        wire: u32,
        /// What the kernel answered.
        errno: Errno,
    },
    /// The helper exited without delivering a result: it was killed from
    /// outside, or its result could not be read.
    Lost,
}

/// Forks a helper that joins the sandbox's user namespace and then its network
/// namespace, runs `work` there, and sends back the descriptor `work` returns.
///
/// `work` names a failure by a wire value of the caller's own, as `steps` names
/// the four steps the helper takes around it. The helper is reaped through its
/// pidfd before this returns.
///
/// # Safety
///
/// `work` runs in the forked helper, under the post-fork discipline
/// [`child`](super::child) states: it allocates nothing, takes no lock, calls no
/// libc, and does not panic. It may use no descriptor of the caller's: the
/// helper sweeps every one but the namespaces and its socket before it joins.
pub(crate) unsafe fn in_network_namespace(
    namespaces: &Namespaces,
    steps: &JoinSteps,
    work: impl FnOnce() -> Result<OwnedFd, (u32, Errno)>,
) -> Result<OwnedFd, HelperFailure> {
    let (caller, helper_end) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(HelperFailure::Spawn)?;

    // SAFETY: the child branch runs `helper`, which makes raw syscalls over the
    // descriptors and step values marshaled above and calls `work`, whose
    // discipline the caller vouches for; it never returns, ending in
    // `exit_group` on every path.
    match unsafe { sys::fork_with_pidfd() } {
        Err(errno) => Err(HelperFailure::Spawn(errno)),
        Ok(PidfdFork::Child) => helper(namespaces, helper_end.as_fd(), steps, work),
        Ok(PidfdFork::ParentOf(child)) => {
            // This process's copy of the helper's end closes first, so the
            // helper's exit hangs the socket up for the receive below.
            drop(helper_end);
            let outcome = receive(caller.as_fd());
            let _ = child.reap();
            outcome
        }
    }
}

/// The helper: joins the namespaces, runs the work, and sends its descriptor
/// back, or the step it failed at. Never returns; there is no one to report a
/// failure to report to.
fn helper(
    namespaces: &Namespaces,
    socket: BorrowedFd<'_>,
    steps: &JoinSteps,
    work: impl FnOnce() -> Result<OwnedFd, (u32, Errno)>,
) -> ! {
    match join_and_work(namespaces, socket, steps, work) {
        Ok(()) => sys::exit_group(0),
        Err((wire, errno)) => {
            let record = frame::encode_record(wire, errno.raw_os_error());
            let _ = rustix::net::send(socket, &record, SendFlags::NOSIGNAL);
            sys::exit_group(127)
        }
    }
}

/// The helper's work, returning only on failure, naming the step.
fn join_and_work(
    namespaces: &Namespaces,
    socket: BorrowedFd<'_>,
    steps: &JoinSteps,
    work: impl FnOnce() -> Result<OwnedFd, (u32, Errno)>,
) -> Result<(), (u32, Errno)> {
    // Every signal stays blocked, as the fork left it: the copied address
    // space still names the caller's signal handlers, which must not run here,
    // and nothing here relies on receiving a signal. `SIGKILL` still ends the
    // helper, which the caller observes as a hangup.
    //
    // The descriptor table first, before anything that can block. The fork
    // copied the caller's whole table into this process, and an inherited copy
    // is not inert: it holds open a concurrently live sandbox's control socket
    // (which defers the supervisor's hangup detection), a concurrently
    // allocated pseudoterminal replica (which defers end-of-file on the
    // primary), and a concurrently open map gate. The helper's life is short
    // but bounded by nothing, so it sweeps like every other forked child. Only
    // the three channels it was given survive.
    sweep_fds_keeping(&[
        namespaces.user.as_raw_fd(),
        namespaces.net.as_raw_fd(),
        socket.as_raw_fd(),
    ])
    .map_err(|errno| (steps.sweep_fds, errno))?;

    rustix::thread::move_into_link_name_space(
        namespaces.user.as_fd(),
        Some(LinkNameSpaceType::User),
    )
    .map_err(|errno| (steps.join_user, errno))?;
    rustix::thread::move_into_link_name_space(
        namespaces.net.as_fd(),
        Some(LinkNameSpaceType::Network),
    )
    .map_err(|errno| (steps.join_net, errno))?;

    let made = work()?;
    frame::send_with_fd(socket, &frame::encode_record(RECORD_DONE, 0), made.as_fd())
        .map_err(|errno| (steps.send, errno))
}

/// Receives the helper's one record: the descriptor on success, the step and
/// errno of a failure, or a hangup where the helper died.
fn receive(socket: BorrowedFd<'_>) -> Result<OwnedFd, HelperFailure> {
    let mut record = [0u8; RECORD_LEN];
    let (bytes, descriptor) =
        frame::recv_with_fd(socket, &mut record).map_err(|_| HelperFailure::Lost)?;
    if bytes != RECORD_LEN {
        return Err(HelperFailure::Lost);
    }
    match frame::decode_record(record) {
        (RECORD_DONE, _) => descriptor.ok_or(HelperFailure::Lost),
        (wire, errno) => Err(HelperFailure::Step {
            wire,
            errno: Errno::from_raw_os_error(errno),
        }),
    }
}

wire_enum! {
    /// The steps of making a listener in the sandbox's network namespace, in
    /// wire form: a failure names the step and the errno.
    pub(crate) enum ListenStep {
        /// Close the inherited descriptors the helper does not own.
        SweepFds = 1 => "closing the listener helper's inherited descriptors",
        /// Join the sandbox's user namespace.
        JoinUser = 2 => "joining the sandbox's user namespace",
        /// Join the sandbox's network namespace.
        JoinNet = 3 => "joining the sandbox's network namespace",
        /// Create the socket.
        Socket = 4 => "creating the listening socket",
        /// Bind it to the address.
        Bind = 5 => "binding the listening socket",
        /// Make it listen.
        Listen = 6 => "listening on the socket",
        /// Send it back to the caller.
        Send = 7 => "sending the listening socket back to the caller",
    }
}

/// The backlog of a listener made here: the one [`std::net::TcpListener::bind`]
/// gives its own.
const BACKLOG: i32 = 128;

/// Why a listener could not be made in the sandbox's network namespace.
#[derive(Debug)]
pub(crate) enum ListenFailure {
    /// The helper could not be started.
    Spawn(Errno),
    /// A step failed.
    Step(ListenStep, Errno),
    /// The helper ended without delivering a result.
    Lost,
}

/// Makes a TCP socket listening at `address` in the sandbox's network
/// namespace, and returns it.
///
/// The helper holds the sandbox's `CAP_NET_BIND_SERVICE` while it binds, so a
/// privileged port is as available as any other. Nothing here judges the
/// address: [`Pending::listen`](crate::Pending::listen) holds it to the
/// sandbox's loopback before calling.
pub(crate) fn listen(
    namespaces: &Namespaces,
    address: SocketAddr,
) -> Result<OwnedFd, ListenFailure> {
    let steps = JoinSteps {
        sweep_fds: ListenStep::SweepFds.wire(),
        join_user: ListenStep::JoinUser.wire(),
        join_net: ListenStep::JoinNet.wire(),
        send: ListenStep::Send.wire(),
    };
    let family = match address {
        SocketAddr::V4(_) => AddressFamily::INET,
        SocketAddr::V6(_) => AddressFamily::INET6,
    };
    // SAFETY: `make_listener` makes three raw syscalls over the address copied
    // into it and returns; it allocates nothing, takes no lock and cannot panic,
    // and it uses no descriptor of the caller's.
    let made = unsafe {
        in_network_namespace(namespaces, &steps, move || {
            make_listener(family, &address).map_err(|(step, errno)| (step.wire(), errno))
        })
    };
    made.map_err(|failure| match failure {
        HelperFailure::Spawn(errno) => ListenFailure::Spawn(errno),
        HelperFailure::Step { wire, errno } => match ListenStep::from_wire(wire) {
            Some(step) => ListenFailure::Step(step, errno),
            None => ListenFailure::Lost,
        },
        HelperFailure::Lost => ListenFailure::Lost,
    })
}

/// Creates, binds, and listens on a TCP socket, in whatever network namespace
/// the calling process is in.
fn make_listener(
    family: AddressFamily,
    address: &SocketAddr,
) -> Result<OwnedFd, (ListenStep, Errno)> {
    let socket = rustix::net::socket_with(family, SocketType::STREAM, SocketFlags::CLOEXEC, None)
        .map_err(|errno| (ListenStep::Socket, errno))?;
    rustix::net::bind(&socket, address).map_err(|errno| (ListenStep::Bind, errno))?;
    rustix::net::listen(&socket, BACKLOG).map_err(|errno| (ListenStep::Listen, errno))?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every step decodes back to itself, and every step names itself in prose.
    #[test]
    fn listen_step_wire_round_trip() {
        for &step in ListenStep::ALL {
            assert_eq!(ListenStep::from_wire(step.wire()), Some(step));
            assert!(!step.describe().is_empty(), "{step:?} describes itself");
        }
        assert_eq!(ListenStep::from_wire(0), None);
        assert_eq!(ListenStep::from_wire(ListenStep::past_the_last()), None);
        assert_eq!(ListenStep::from_wire(RECORD_DONE), None);
    }
}
