//! Which user namespace the process at the other end of a unix socket runs in:
//! the reading behind
//! [`host::peer_in_own_user_namespace`](crate::host::peer_in_own_user_namespace).
//!
//! A peer's credentials do not tell a sandboxed process from one of the
//! caller's own. A sandbox's user namespace maps its identities onto the
//! caller's, so `SO_PEERCRED` reports a sandboxed peer with the caller's own
//! uid and gid. Its user namespace does tell them apart: every sandbox runs in
//! one of its own, nested below the caller's.
//!
//! The kernel names the peer process three ways, and the newest one available
//! is taken:
//!
//! - **Linux 6.11:** `SO_PEERPIDFD` gives a pidfd for the process that
//!   connected, and `PIDFD_GET_USER_NAMESPACE` a descriptor of its user
//!   namespace. A pidfd names one process for as long as it is held, so
//!   nothing else can answer for the peer.
//! - **Linux 6.5:** the same pidfd, whose `fdinfo` gives the process's pid,
//!   and `/proc/<pid>/ns/user` its namespace. A pid can name another process
//!   once its own has exited, so the answer counts only where the pidfd's
//!   process is still running after the read: a process holds its pid until
//!   it exits.
//! - **Before:** `SO_PEERCRED`'s pid, opened with `pidfd_open`, and then as
//!   for 6.5. A window remains between the connection and the `pidfd_open`, in
//!   which a peer that exited can have its pid taken by another process. Using
//!   it takes a process that reached the socket, handed its connection to
//!   another process and exited, and whose pid a process of the caller's own
//!   namespace then took before the check.
//!
//! Each needs the caller to be allowed to read the peer's namespace, which the
//! kernel decides as it decides a `ptrace` read. A process of the caller's own
//! user is, and so is a sandbox's, since the caller's namespace owns the
//! sandbox's.

use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::path::Path;

use rustix::fs::Stat;
use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags};

use super::sys;

/// A user namespace, as the kernel identifies one: the device of the namespace
/// filesystem and the namespace's inode on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserNamespace {
    device: u64,
    inode: u64,
}

impl UserNamespace {
    /// The calling process's own.
    pub(crate) fn own() -> io::Result<UserNamespace> {
        UserNamespace::at(Path::new("/proc/self/ns/user"))
    }

    /// The namespace a `/proc/<pid>/ns/user` link names.
    fn at(path: &Path) -> io::Result<UserNamespace> {
        Ok(UserNamespace::of_stat(&rustix::fs::stat(path)?))
    }

    /// The namespace a descriptor of one names.
    fn of(namespace: BorrowedFd<'_>) -> io::Result<UserNamespace> {
        Ok(UserNamespace::of_stat(&rustix::fs::fstat(namespace)?))
    }

    /// The namespace whose status this is.
    fn of_stat(stat: &Stat) -> UserNamespace {
        UserNamespace {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }
}

/// The user namespace of the process that connected `socket`'s other end, read
/// the newest way the kernel offers; see the module documentation.
pub(crate) fn of_peer(socket: BorrowedFd<'_>) -> io::Result<UserNamespace> {
    let pidfd = match sys::socket_peer_pidfd(socket) {
        Ok(pidfd) => pidfd,
        Err(Errno::NOPROTOOPT) => return through_peer_pid(socket),
        Err(errno) => return Err(errno.into()),
    };
    match through_pidfd(pidfd.as_fd()) {
        Err(error) if error.raw_os_error() == Some(Errno::NOTTY.raw_os_error()) => {
            through_procfs(pidfd.as_fd())
        }
        answer => answer,
    }
}

/// Linux 6.11's reading: the namespace of the pidfd's process, from the
/// kernel. `ENOTTY` on a kernel without it.
fn through_pidfd(pidfd: BorrowedFd<'_>) -> io::Result<UserNamespace> {
    let namespace = sys::pidfd_user_namespace(pidfd)?;
    UserNamespace::of(namespace.as_fd())
}

/// Linux 6.5's reading: the namespace `/proc` shows for the pid the pidfd's
/// `fdinfo` gives, while the pidfd's process still runs.
fn through_procfs(pidfd: BorrowedFd<'_>) -> io::Result<UserNamespace> {
    namespace_while_running(pid_of(pidfd)?, pidfd)
}

/// The reading before Linux 6.5: the namespace `/proc` shows for the pid
/// `SO_PEERCRED` gives, while a pidfd opened on it still runs.
fn through_peer_pid(socket: BorrowedFd<'_>) -> io::Result<UserNamespace> {
    let pid = sys::socket_peer_pid(socket)?.ok_or(Errno::SRCH)?;
    let pidfd = rustix::process::pidfd_open(pid, PidfdFlags::empty())?;
    namespace_while_running(pid, pidfd.as_fd())
}

/// The namespace `/proc` shows for `pid`, where `pidfd`'s process is still
/// running once it has been read, and so is the process `pid` named
/// throughout; `ESRCH` otherwise.
fn namespace_while_running(pid: Pid, pidfd: BorrowedFd<'_>) -> io::Result<UserNamespace> {
    let path = format!("/proc/{}/ns/user", pid.as_raw_nonzero());
    let namespace = UserNamespace::at(Path::new(&path))?;
    if !super::is_running(pidfd) {
        return Err(Errno::SRCH.into());
    }
    Ok(namespace)
}

/// The pid the `fdinfo` of `pidfd` gives its process, in this process's PID
/// namespace: `ESRCH` where the process has exited or has no pid here.
fn pid_of(pidfd: BorrowedFd<'_>) -> io::Result<Pid> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?;
    let pid = info
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .ok_or_else(|| io::Error::other("a pidfd's fdinfo names no pid"))?;
    // The kernel writes -1 for a process that has exited and 0 for one with
    // no pid in the namespace of the procfs read, which is the caller's.
    match pid.trim().parse::<i32>() {
        Ok(raw) if raw > 0 => Ok(Pid::from_raw(raw).ok_or(Errno::SRCH)?),
        Ok(_) => Err(Errno::SRCH.into()),
        Err(_) => Err(io::Error::other(
            "a pidfd's fdinfo names its pid unreadably",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    use rustix::event::{PollFd, PollFlags};
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};
    use rustix::thread::UnshareFlags;

    use super::super::Forked;
    use super::super::sys::PidfdFork;
    use super::*;
    use crate::scratch::Scratch;

    /// How long a test waits for its peer to connect.
    const PATIENCE: Duration = Duration::from_secs(30);

    /// A listening socket in a scratch directory of its own, and its address.
    fn listening(test: &str) -> (Scratch, UnixListener, SocketAddrUnix) {
        let scratch = Scratch::for_test(test, "peer");
        let path = scratch.path().join("socket");
        let listener = UnixListener::bind(&path).expect("the socket binds");
        let address = SocketAddrUnix::new(&path).expect("a scratch path fits an address");
        (scratch, listener, address)
    }

    /// A process that connects to `address` from a user namespace of its own,
    /// where `unshared`, or else from this process's, and then holds the
    /// connection until the far end closes it.
    ///
    /// The child makes system calls only, as the post-fork discipline asks: the
    /// address was made before the fork.
    fn peer_process(address: &SocketAddrUnix, unshared: bool) -> Forked {
        let child = || -> i32 {
            if unshared {
                // SAFETY: the child holds one thread, so a namespace of its own
                // changes what no other thread observes.
                if unsafe { rustix::thread::unshare_unsafe(UnshareFlags::NEWUSER) }.is_err() {
                    return 2;
                }
            }
            let Ok(socket) = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)
            else {
                return 3;
            };
            if rustix::net::connect(&socket, address).is_err() {
                return 4;
            }
            let _ = rustix::io::read(&socket, &mut [0u8; 1]);
            0
        };
        // SAFETY: the child runs `child`, which makes system calls and drops a
        // descriptor, and nothing else, then exits without returning here.
        match unsafe { sys::fork_with_pidfd() }.expect("the peer forks") {
            PidfdFork::Child => sys::exit_group(child()),
            PidfdFork::ParentOf(forked) => forked,
        }
    }

    /// Accepts the connection `peer` makes on `listener`, failing the test where
    /// the peer exits first, saying why from its exit code.
    fn accept_from(listener: &UnixListener, peer: &Forked) -> UnixStream {
        let mut fds = [
            PollFd::new(listener, PollFlags::IN),
            PollFd::from_borrowed_fd(peer.pidfd(), PollFlags::IN),
        ];
        let ready = rustix::event::poll(&mut fds, Some(&crate::poll::timeout(PATIENCE)))
            .expect("the poll succeeds");
        assert!(ready > 0, "the peer did not connect within {PATIENCE:?}");
        if fds[0].revents().is_empty() {
            let code = peer.reap().expect("the peer is reaped");
            panic!("the peer exited before it connected, with {code:?}");
        }
        listener.accept().expect("the connection is accepted").0
    }

    /// Ends the peer by closing its connection, and reaps it.
    fn finish(connection: UnixStream, peer: &Forked) {
        drop(connection);
        assert_eq!(peer.reap(), Ok(Some(0)), "the peer ends cleanly");
    }

    /// One way of reading a peer's namespace, from the socket.
    type Reading = fn(BorrowedFd<'_>) -> io::Result<UserNamespace>;

    /// Every reading, by name, for a test to run each one.
    const READINGS: [(&str, Reading); 3] = [
        ("the 6.11 reading", |socket| {
            through_pidfd(sys::socket_peer_pidfd(socket)?.as_fd())
        }),
        ("the 6.5 reading", |socket| {
            through_procfs(sys::socket_peer_pidfd(socket)?.as_fd())
        }),
        ("the reading before 6.5", through_peer_pid),
    ];

    /// Whether `reading` answered, reporting a skip where the kernel lacks what
    /// it reads through: `SO_PEERPIDFD` or the pidfd's namespace request.
    fn kernel_reads(name: &str, reading: &io::Result<UserNamespace>) -> bool {
        let lacking = [Errno::NOPROTOOPT, Errno::NOTTY].map(Errno::raw_os_error);
        match reading {
            Err(error) if lacking.contains(&error.raw_os_error().unwrap_or(0)) => {
                ferroday_cage_testkit::require::premise_unmet(format_args!(
                    "{name} needs a newer kernel: {error}"
                ));
                false
            }
            _ => true,
        }
    }

    #[test]
    fn a_peer_of_the_callers_own_namespace_reads_as_the_callers_own() {
        let (_scratch, listener, address) = listening("own-peer");
        let peer = peer_process(&address, false);
        let connection = accept_from(&listener, &peer);
        let own = UserNamespace::own().expect("the own namespace reads");
        for (name, reading) in READINGS {
            let read = reading(connection.as_fd());
            if kernel_reads(name, &read) {
                assert_eq!(read.expect(name), own, "{name}");
            }
        }
        assert_eq!(of_peer(connection.as_fd()).expect("the peer reads"), own);
        finish(connection, &peer);
    }

    #[test]
    fn a_peer_in_a_namespace_of_its_own_reads_as_another() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        let (_scratch, listener, address) = listening("unshared-peer");
        let peer = peer_process(&address, true);
        let connection = accept_from(&listener, &peer);
        let own = UserNamespace::own().expect("the own namespace reads");
        // The child's own namespace, read the way a test may: by its pid.
        let path = format!("/proc/{}/ns/user", peer.pid().as_raw_nonzero());
        let theirs = UserNamespace::at(Path::new(&path)).expect("the peer's namespace reads");
        assert_ne!(theirs, own, "the peer unshared its user namespace");
        for (name, reading) in READINGS {
            let read = reading(connection.as_fd());
            if kernel_reads(name, &read) {
                assert_eq!(read.expect(name), theirs, "{name}");
            }
        }
        assert_eq!(of_peer(connection.as_fd()).expect("the peer reads"), theirs);
        finish(connection, &peer);
    }

    /// A peer that connected and exited, still holding its pid as a process
    /// not yet reaped, and the connection it made, which this process holds
    /// open from its side too.
    fn exited_peer(listener: &UnixListener, address: &SocketAddrUnix) -> (Forked, UnixStream) {
        let socket =
            rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None).expect("a socket");
        let connector = || -> i32 { i32::from(rustix::net::connect(&socket, address).is_err()) };
        // SAFETY: the child connects and exits, making system calls only.
        let forked = match unsafe { sys::fork_with_pidfd() }.expect("the peer forks") {
            PidfdFork::Child => sys::exit_group(connector()),
            PidfdFork::ParentOf(forked) => forked,
        };
        assert!(
            crate::mechanism::exits_within(forked.pidfd(), PATIENCE),
            "the peer exits"
        );
        drop::<OwnedFd>(socket);
        let connection = listener.accept().expect("the connection is accepted").0;
        (forked, connection)
    }

    #[test]
    fn a_peer_that_has_exited_is_not_read_through_its_pid() {
        // The process that connected has exited by the time it is asked about.
        // Unreaped, it still holds its pid and `/proc` still shows its
        // namespace, so what refuses it is the check that its pidfd's process
        // runs. Reaped, its pid would be free for another process to take.
        let (_scratch, listener, address) = listening("exited-peer");
        let (forked, connection) = exited_peer(&listener, &address);
        let refused = [
            ("the 6.5 reading", READINGS[1].1),
            ("the reading before 6.5", READINGS[2].1),
        ];
        for (name, reading) in refused {
            let read = reading(connection.as_fd());
            if kernel_reads(name, &read) {
                let error = read.expect_err(name);
                assert_eq!(
                    error.raw_os_error(),
                    Some(Errno::SRCH.raw_os_error()),
                    "{name}: {error}"
                );
            }
        }
        assert_eq!(forked.reap(), Ok(Some(0)), "the peer connected");
    }
}
