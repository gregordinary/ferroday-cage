//! The running-sandbox handle: wait, deadline, terminate, kill.

use std::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags};
use rustix::io::Errno;
use rustix::net::SendFlags;
use rustix::process;
use rustix::process::Signal;

use crate::error::Error;
use crate::mechanism::{self, CONTROL_TERMINATE, LaunchPlan, ManagedPlaceholders};
use crate::observer::Observer;
use crate::poll;
use crate::provision::rooted::Rooted;
use crate::status::ExitStatus;
use crate::terminal::{Pty, Terminal};

/// The pump's read buffer size: one read per poll wake per stream.
const PUMP_BUF: usize = 8192;

/// A running sandbox.
///
/// Returned by [`Cage::spawn`] and [`Cage::spawn_with`] once the command is
/// executing. The handle owns the caller side of the sandbox's channels:
/// waiting pumps captured output to the observer and collects the command's
/// exit status, [`terminate`](Self::terminate) requests a graceful stop,
/// and [`kill`](Self::kill) forcibly tears the sandbox down.
///
/// Waiting is fused: once the outcome is known, every further wait returns
/// it without blocking.
///
/// Dropping the handle without waiting neither kills the sandbox (unless
/// [`stop_with_caller`] is set, whose tie the drop severs) nor collects its
/// outcome; without a PID namespace the supervisor process then remains a
/// zombie child process of the caller until the caller exits. Prefer waiting —
/// including after a kill.
///
/// The escalation recipe, for callers that need a bounded stop:
///
/// ```no_run
/// # use std::time::Instant;
/// # use std::time::Duration;
/// # fn main() -> ferroday_cage::Result<()> {
/// # let cage = ferroday_cage::Cage::builder().rootfs("/r").command("/bin/x").build()?;
/// # let soft = Instant::now() + Duration::from_secs(60);
/// # let hard = Instant::now() + Duration::from_secs(70);
/// let mut running = cage.spawn()?;
/// let status = match running.wait_deadline(soft)? {
///     Some(status) => status,
///     None => {
///         running.terminate()?; // SIGTERM: a chance to exit cleanly
///         match running.wait_deadline(hard)? {
///             Some(status) => status,
///             None => {
///                 running.kill()?; // SIGKILL: tear the sandbox down
///                 running.wait()?
///             }
///         }
///     }
/// };
/// # Ok(())
/// # }
/// ```
///
/// [`Cage::spawn`]: crate::Cage::spawn
/// [`Cage::spawn_with`]: crate::Cage::spawn_with
/// [`stop_with_caller`]: crate::CageBuilder::stop_with_caller
pub struct Running<'obs> {
    /// Pidfd of the supervisor; the kill anchor, immune to pid reuse.
    pidfd: OwnedFd,
    /// The supervisor's host pid.
    pid: u32,
    /// Caller end of the control socket.
    control: OwnedFd,
    /// Read end of the status pipe; dropped once the record or EOF arrives.
    status: Option<OwnedFd>,
    /// Captured stream read ends; each dropped at its EOF.
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
    /// The observer receiving captured output, when capturing.
    observer: Option<&'obs mut dyn Observer>,
    /// Accumulates the 8-byte status record across partial reads.
    record: [u8; 8],
    record_len: usize,
    /// The command's outcome, once known — the fuse for repeated waits.
    outcome: Option<ExitStatus>,
    /// Whether a kill was requested through this handle or a [`KillHandle`];
    /// decides how a status pipe that closes without a record is read.
    kill_sent: Arc<AtomicBool>,
    /// A pidfd of the launch stage, for the handle to reap once the status
    /// arrives (no PID namespace); the in-namespace init is not the caller's
    /// child process. A pidfd rather than a raw pid so the reap cannot alias a
    /// recycled pid.
    reap: Option<OwnedFd>,
    /// The pump's read buffer, allocated once when capturing.
    buf: Vec<u8>,
    /// Held only for its `Drop`: it removes the mount targets the launch
    /// created in the root, if any. See
    /// [`LaunchPlan::managed_placeholders`].
    _placeholders: PlaceholderGuard,
}

/// Which captured stream a read belongs to.
///
/// Deliberately a second answer to the question `provision::Stream` also asks.
/// That one is public and gated on a userland feature, and provisioning is built
/// on top of the launch mechanism rather than the other way round, so reaching
/// for it here would point the dependency backwards and put a feature gate on a
/// module every build compiles.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Channel {
    Stdout,
    Stderr,
}

impl<'obs> Running<'obs> {
    /// Launches the plan and wraps the caller-side channels.
    pub(crate) fn launch(
        plan: &LaunchPlan,
        mut observer: Option<&'obs mut dyn Observer>,
    ) -> Result<Running<'obs>, Error> {
        let observe = observer.is_some();
        if observe {
            check_capture_composes(plan)?;
        }
        // The guard is built before the spawn, not after it. `spawn` reports
        // every setup step through its return, and the mount ops run well
        // before the last of them: a launch that creates `/etc/resolv.conf` and
        // then fails at the pivot, the working-directory change, or the exec —
        // the case a caller getting a configuration right hits repeatedly —
        // would otherwise leave that file behind, which is the residue this
        // mechanism exists to prevent. Built here, the `?` below drops the
        // guard and takes the placeholders with it.
        let placeholders = PlaceholderGuard {
            placeholders: plan.managed_placeholders.clone(),
        };
        // The progress sink borrows the observer only for the launch; the
        // borrow ends with the statement, leaving the observer to move into
        // the handle for the output pump.
        let (launched, primary) = mechanism::spawn(plan, observe, None, &mut |event| {
            if let Some(observer) = observer.as_deref_mut() {
                observer.progress(event);
            }
        })?;
        debug_assert!(primary.is_none(), "a launch with no terminal returns none");
        Ok(Running::from_launched(launched, observer, placeholders))
    }

    /// Launches the plan on a pseudoterminal of its own, returning the handle
    /// and the caller's end of the terminal.
    ///
    /// No observer, so no progress milestone is reported and nothing is
    /// captured: the terminal is the command's output, and the caller reads it.
    pub(crate) fn launch_terminal(
        plan: &LaunchPlan,
        terminal: &Terminal,
    ) -> Result<(Running<'static>, Pty), Error> {
        check_terminal_composes(plan)?;
        let placeholders = PlaceholderGuard {
            placeholders: plan.managed_placeholders.clone(),
        };
        let (launched, primary) = mechanism::spawn(plan, false, Some(terminal), &mut |_| {})?;
        let primary = primary.ok_or_else(|| wait_error(Errno::PROTO))?;
        Ok((
            Running::from_launched(launched, None, placeholders),
            Pty::new(primary),
        ))
    }

    /// Wraps the caller-side channels of an already-launched sandbox.
    pub(crate) fn from_launched(
        launched: mechanism::Launched,
        observer: Option<&'obs mut dyn Observer>,
        placeholders: PlaceholderGuard,
    ) -> Running<'obs> {
        let buf = if observer.is_some() {
            vec![0; PUMP_BUF]
        } else {
            Vec::new()
        };
        Running {
            pidfd: launched.pidfd,
            pid: launched.pid,
            control: launched.control,
            status: Some(launched.status),
            stdout: launched.stdout,
            stderr: launched.stderr,
            observer,
            record: [0; 8],
            record_len: 0,
            outcome: None,
            kill_sent: Arc::new(AtomicBool::new(false)),
            reap: launched.reap,
            buf,
            _placeholders: placeholders,
        }
    }

    /// The host process id of the sandbox supervisor — the process this handle
    /// anchors on: the namespace init, or the command process itself without a
    /// PID namespace. Not the launch stage, which built the namespaces and, with
    /// a PID namespace, has already exited.
    ///
    /// Informational — for signaling, use [`kill`](Self::kill) and
    /// [`terminate`](Self::terminate), which cannot hit a recycled pid.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Waits for the command to terminate, pumping captured output to the
    /// observer, and returns its exit status.
    ///
    /// Like [`Cage::run`], a non-zero exit is data, not an error. An error
    /// means the library failed to collect the outcome.
    ///
    /// When output is captured, the wait completes once the command's
    /// outcome is known and both captured streams have reached end-of-file.
    /// Under the default PID namespace, teardown at command exit closes
    /// the streams promptly. With [`pid_namespace(false)`], a descendant
    /// that outlives the command holds the streams open, and an unbounded
    /// wait blocks until the last holder closes them; a caller whose
    /// command may leave such descendants behind should prefer
    /// [`wait_deadline`](Self::wait_deadline) or
    /// [`wait_timeout`](Self::wait_timeout).
    ///
    /// [`Cage::run`]: crate::Cage::run
    /// [`pid_namespace(false)`]: crate::CageBuilder::pid_namespace
    pub fn wait(&mut self) -> Result<ExitStatus, Error> {
        match self.pump(None, None)? {
            Some(status) => Ok(status),
            // The pump reports no outcome only where a deadline expired, and
            // there is none here, so this is unreachable today. It is an error
            // rather than a panic because the invariant lives in another
            // function: a future early return added to `pump` would break it
            // with no compiler assistance, and a library whose error type is
            // otherwise exhaustive should not answer that with an abort. Same
            // treatment `drain_status` gives a record it cannot decode.
            None => Err(wait_error(Errno::PROTO)),
        }
    }

    /// Waits until the command terminates or the deadline passes.
    ///
    /// Returns `Ok(None)` when the deadline passes first; the command keeps
    /// running, output produced before the deadline has been delivered, and
    /// the wait can be resumed. The deadline does not kill anything —
    /// escalation is the caller's, per the recipe above.
    pub fn wait_deadline(&mut self, deadline: Instant) -> Result<Option<ExitStatus>, Error> {
        self.pump(Some(deadline), None)
    }

    /// [`wait_deadline`](Self::wait_deadline) with a relative timeout.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<ExitStatus>, Error> {
        // A timeout too large for the clock is a wait without one.
        match Instant::now().checked_add(timeout) {
            Some(deadline) => self.pump(Some(deadline), None),
            None => self.pump(None, None),
        }
    }

    /// Waits until the command terminates, the deadline passes, or `wake`
    /// becomes readable, whichever comes first.
    ///
    /// For a waiter with a channel of its own to answer while it waits: the
    /// terminal relay's signal descriptor, once the session's terminal has
    /// closed and only the command's exit is left to collect. `Ok(None)` does
    /// not say which of the two ended the wait, because the caller can ask its
    /// own clock and drain its own channel, and draining an empty one costs a
    /// read.
    pub(crate) fn wait_or_readable(
        &mut self,
        deadline: Option<Instant>,
        wake: BorrowedFd<'_>,
    ) -> Result<Option<ExitStatus>, Error> {
        self.pump(deadline, Some(wake))
    }

    /// Requests graceful termination: SIGTERM to the command.
    ///
    /// The signal is deliverable and trappable, docker-stop style; a
    /// command may clean up and exit, or may ignore it. Follow with a
    /// deadline and [`kill`](Self::kill) for a bounded stop. Requesting
    /// termination of a sandbox that has already exited is not an error.
    pub fn terminate(&mut self) -> Result<(), Error> {
        send_terminate(&self.control)
    }

    /// Kills the sandbox: SIGKILL to the supervisor.
    ///
    /// With a PID namespace this kills its init, and the kernel then kills
    /// every process in the namespace — nothing survives. Without one, only
    /// the command process itself is killed; descendants it spawned are
    /// beyond the library's reach.
    ///
    /// The kill is delivered through a pidfd and cannot hit a recycled pid.
    /// Killing a sandbox that has already exited is not an error. After a
    /// kill, [`wait`](Self::wait) still pumps the output produced before
    /// the kill and then reports the outcome.
    ///
    /// The killed outcome is reported as `signaled(SIGKILL)` only once the
    /// signal is known delivered; the flag that carries that fact is set after
    /// the signal so a failed signal cannot fabricate a killed outcome. When a
    /// [`KillHandle`] on another thread issues the kill while this thread is
    /// waiting, that ordering leaves a narrow window in which the waiter can
    /// observe the supervisor's death before the flag is set and report
    /// [`Error::SupervisorLost`] instead of `signaled(SIGKILL)`. The kill still
    /// took effect; only the reported form differs, and only for a
    /// cross-thread kill racing the wait. A same-thread kill (this method
    /// before a subsequent [`wait`](Self::wait)) is not affected.
    ///
    /// [`Error::SupervisorLost`]: crate::Error::SupervisorLost
    pub fn kill(&mut self) -> Result<(), Error> {
        send_kill(&self.pidfd, &self.kill_sent)
    }

    /// Returns a handle that can terminate or kill the sandbox from another
    /// thread, while this handle blocks in a wait.
    pub fn kill_handle(&self) -> Result<KillHandle, Error> {
        Ok(KillHandle {
            pidfd: self.pidfd.try_clone().map_err(clone_error)?,
            control: self.control.try_clone().map_err(clone_error)?,
            kill_sent: Arc::clone(&self.kill_sent),
        })
    }

    /// Whether every channel has settled: the streams at end-of-file and
    /// the status record or its end-of-file received.
    fn settled(&self) -> bool {
        self.status.is_none() && self.stdout.is_none() && self.stderr.is_none()
    }

    /// The fused outcome once every channel has settled.
    ///
    /// A status pipe that closed without a record means the supervisor
    /// exited without reporting. After a kill that is the expected shape —
    /// the kill took the supervisor and, with it, the namespace — and the
    /// outcome is termination by SIGKILL. Unprovoked, it is an error.
    fn resolve(&mut self) -> Result<ExitStatus, Error> {
        if let Some(pidfd) = self.reap.take() {
            // Reap the supervisor through its pidfd, so the wait targets
            // exactly that process and cannot alias a pid a concurrent reaper
            // freed and the OS recycled. Best-effort: the supervisor exits
            // right after the status write, and an application-wide child
            // reaper may even have collected it first.
            let _ = mechanism::reap_via_pidfd(pidfd.as_fd());
        }
        if let Some(outcome) = self.outcome {
            return Ok(outcome);
        }
        if self.kill_sent.load(Ordering::SeqCst) {
            let outcome = ExitStatus::signaled(Signal::KILL.as_raw());
            self.outcome = Some(outcome);
            return Ok(outcome);
        }
        // The supervisor is gone with no status record and no kill flag set.
        // Unprovoked, that is a lost supervisor. The one benign case is a
        // cross-thread kill whose flag store has not yet landed when this
        // waiter observes the death: `send_kill` sets the flag after the signal
        // so a failed signal cannot fabricate a killed outcome, which leaves
        // that narrow window. The kill still took effect; only the reported
        // error differs. See `Running::kill`.
        Err(Error::SupervisorLost)
    }

    /// The pump: polls the live channels, delivers captured output, and
    /// accumulates the status record, until everything settles, the deadline
    /// passes, or `wake` becomes readable.
    fn pump(
        &mut self,
        deadline: Option<Instant>,
        wake: Option<BorrowedFd<'_>>,
    ) -> Result<Option<ExitStatus>, Error> {
        loop {
            if self.settled() {
                return self.resolve().map(Some);
            }

            let timeout = match deadline {
                None => None,
                Some(deadline) => {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        return Ok(None);
                    };
                    Some(poll::timeout(remaining))
                }
            };

            // One fixed poll slot per channel, so the hot loop allocates
            // nothing. A retired channel's slot watches the pidfd with no
            // requested events: a valid descriptor the poll ignores. The
            // waiter's own channel, where there is none, is the same.
            let mut pollfds = [
                poll::slot(&self.stdout, &self.pidfd),
                poll::slot(&self.stderr, &self.pidfd),
                poll::slot(&self.status, &self.pidfd),
                match wake {
                    Some(wake) => PollFd::from_borrowed_fd(wake, PollFlags::IN),
                    None => PollFd::new(&self.pidfd, PollFlags::empty()),
                },
            ];

            match rustix::event::poll(&mut pollfds, timeout.as_ref()) {
                Ok(0) => return Ok(None),
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(errno) => return Err(wait_error(errno)),
            }

            let ready: [bool; 4] = std::array::from_fn(|i| !pollfds[i].revents().is_empty());
            if ready[0] {
                self.drain_stream(Channel::Stdout)?;
            }
            if ready[1] {
                self.drain_stream(Channel::Stderr)?;
            }
            if ready[2] {
                self.drain_status()?;
            }
            // The waiter's channel is answered after this pass's own reads,
            // so an outcome that arrived beside it is reported rather than
            // left for the next wait. Without one, the slot's readiness is
            // the placeholder's, not a waiter's: a pidfd reports a hangup once
            // its process has been reaped, whatever events were asked for.
            if wake.is_some() && ready[3] {
                return match self.settled() {
                    true => self.resolve().map(Some),
                    false => Ok(None),
                };
            }
        }
    }

    /// Reads one chunk from a captured stream and delivers it; end-of-file
    /// retires the stream.
    fn drain_stream(&mut self, channel: Channel) -> Result<(), Error> {
        let slot = match channel {
            Channel::Stdout => &mut self.stdout,
            Channel::Stderr => &mut self.stderr,
        };
        let Some(fd) = slot else {
            return Ok(());
        };
        // The observer is checked before the read, not after it. The read buffer
        // is sized only when capturing, so a captured stream arriving without an
        // observer would read into a zero-length buffer, take the resulting
        // `Ok(0)` for end-of-file, and retire the stream with its output
        // discarded — masking the very mismatch a check after the read is meant
        // to catch. The pairing is established at launch, so a mismatch is a
        // library defect, reported the way `drain_status` reports a record it
        // cannot decode.
        let Some(observer) = self.observer.as_deref_mut() else {
            return Err(wait_error(Errno::PROTO));
        };
        match rustix::io::read(&*fd, &mut self.buf) {
            Ok(0) => {
                *slot = None;
            }
            Ok(n) => {
                let chunk = &self.buf[..n];
                match channel {
                    Channel::Stdout => observer.stdout(chunk),
                    Channel::Stderr => observer.stderr(chunk),
                }
            }
            Err(Errno::INTR) => {}
            Err(errno) => return Err(wait_error(errno)),
        }
        Ok(())
    }

    /// Accumulates the status record; the full record or end-of-file
    /// retires the pipe.
    fn drain_status(&mut self) -> Result<(), Error> {
        // The descriptor comes out of its slot for the read so the record can be
        // filled in place — the two are fields of the same struct, and the read
        // borrows one immutably and the other mutably. Every path that leaves
        // the pipe live puts it back; the two that retire it (end of file, and a
        // complete record) simply do not.
        let Some(fd) = self.status.take() else {
            return Ok(());
        };
        match rustix::io::read(&fd, &mut self.record[self.record_len..]) {
            Ok(0) => {}
            Ok(n) => {
                self.record_len += n;
                if self.record_len == self.record.len() {
                    // A record this build never writes is a defect in the
                    // library, not a caller error, but the decode still must
                    // not panic: EPROTO retires the pipe and fails the wait.
                    let Some(status) = mechanism::decode_status(self.record) else {
                        return Err(wait_error(Errno::PROTO));
                    };
                    self.outcome = Some(status);
                } else {
                    self.status = Some(fd);
                }
            }
            Err(Errno::INTR) => self.status = Some(fd),
            Err(errno) => {
                self.status = Some(fd);
                return Err(wait_error(errno));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Running<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Running")
            .field("pid", &self.pid)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

/// Removes the mount targets it holds when it goes out of scope.
///
/// A guard of its own, rather than a [`Drop`] on the handles that carry it,
/// because a type implementing `Drop` keeps every borrow it holds live until
/// the end of its scope. [`Running`] borrows the caller's observer, so a `Drop`
/// there would stop a caller from reading its own observer after waiting — the
/// ordinary way to collect captured output. The guard borrows nothing, so
/// dropping it observes nothing.
pub(crate) struct PlaceholderGuard {
    /// The root and the root-relative paths to remove; taken when they are
    /// handed on instead.
    pub(crate) placeholders: ManagedPlaceholders,
}

impl Drop for PlaceholderGuard {
    fn drop(&mut self) {
        if self.placeholders.is_empty() {
            return;
        }
        // One descriptor for the root, which every path below is resolved
        // against; nothing here walks the host's own tree.
        let Ok(root) = Rooted::open(&self.placeholders.root) else {
            return;
        };
        for path in &self.placeholders.paths {
            remove_managed_placeholder(&root, path);
        }
    }
}

/// Removes a mount target the launch created in the root, once the sandbox
/// that needed it is gone.
///
/// `path` is relative to `root` and is resolved against it by [`Rooted`], with
/// `openat2` and `RESOLVE_IN_ROOT` — the containment the sandbox stage gives
/// every mount target, for the same reason. A rootfs is entitled to hold an
/// absolute symbolic link (`./etc -> /etc` in an unpacked tarball, an
/// `/etc/resolv.conf` pointing into a resolver's runtime directory), and joining
/// the two into one host path would have that link resolve against the *host's*
/// root on this side of the fork, which is where the unlink below would then
/// land.
///
/// Only an empty regular file is removed. The placeholder a launch creates is
/// empty and stays that way — the bind covers it for the sandbox's whole life,
/// and the mount is confined to the sandbox's own namespace, so nothing can
/// write through it. Anything with content, or anything that is no longer a
/// plain file, arrived between the build and here and belongs to whoever put it
/// there.
///
/// Safe while the sandbox is still running, which a handle dropped without
/// waiting leaves it: the bind is established inside the sandbox's own mount
/// namespace, over its own root, so it holds the inode rather than this name.
/// Unlinking here leaves the running sandbox's `/etc/resolv.conf` intact.
///
/// Best-effort, like the teardown around it. A failure leaves a file the rootfs
/// did not ship, which is untidy but not a failure of the launch itself.
fn remove_managed_placeholder(root: &Rooted, path: &Path) {
    let _ = root.remove_if(path, Rooted::is_empty_file);
}

/// A detached signaling handle for a running sandbox.
///
/// Obtained from [`Running::kill_handle`]; owns duplicated channel ends, so
/// it works from any thread — typically a watchdog killing the sandbox
/// while another thread blocks in [`Running::wait`]. As long as it exists
/// it holds the [`stop_with_caller`] tie alongside the `Running`.
///
/// [`stop_with_caller`]: crate::CageBuilder::stop_with_caller
#[derive(Debug)]
pub struct KillHandle {
    pidfd: OwnedFd,
    control: OwnedFd,
    kill_sent: Arc<AtomicBool>,
}

impl KillHandle {
    /// Requests graceful termination: SIGTERM to the command. See
    /// [`Running::terminate`].
    pub fn terminate(&self) -> Result<(), Error> {
        send_terminate(&self.control)
    }

    /// Kills the sandbox: SIGKILL to the supervisor. See [`Running::kill`],
    /// including the note on the cross-thread kill racing a wait, which is
    /// exactly the case this handle serves.
    pub fn kill(&self) -> Result<(), Error> {
        send_kill(&self.pidfd, &self.kill_sent)
    }
}

/// A launched sandbox held before its command runs — the userspace-network
/// seam.
///
/// Returned by [`Cage::spawn_pending`] and [`Cage::spawn_pending_with`]. The
/// sandbox's namespaces exist and its supervisor is published, but the command
/// is held at a gate just before `execve`. [`netns_pid`](Self::netns_pid) is a
/// host pid of a process in the sandbox's network namespace, the target a
/// userspace network stack (`pasta`, `slirp4netns`) joins through
/// `/proc/<pid>/ns/net`; the process is alive until the handle is consumed or
/// dropped. Once the stack is attached and ready,
/// [`proceed`](Self::proceed) releases the command and returns the running
/// handle.
///
/// Dropping a `Pending` without proceeding tears the launch down: the
/// supervisor is killed and the launch stage reaped, so no sandbox is left
/// running.
///
/// ```no_run
/// # fn main() -> ferroday_cage::Result<()> {
/// # let cage = ferroday_cage::Cage::builder().rootfs("/r").command("/bin/x").build()?;
/// let pending = cage.spawn_pending()?;
/// let pid = pending.netns_pid();
/// // ... attach a userspace network stack to /proc/<pid>/ns/net and wait
/// //     for it to report ready ...
/// let mut running = pending.proceed()?;
/// let status = running.wait()?;
/// # let _ = (pid, status);
/// # Ok(())
/// # }
/// ```
///
/// [`Cage::spawn_pending`]: crate::Cage::spawn_pending
/// [`Cage::spawn_pending_with`]: crate::Cage::spawn_pending_with
pub struct Pending<'obs> {
    /// The mechanism-level pending launch; `None` only after it is consumed
    /// by [`proceed`](Self::proceed).
    inner: Option<mechanism::PendingLaunch>,
    /// The observer bound at spawn, carried into the [`Running`] handle.
    observer: Option<&'obs mut dyn Observer>,
    /// The mount targets the launch created in the root, handed to the
    /// [`Running`] this becomes, or removed here if it never proceeds.
    placeholders: PlaceholderGuard,
}

impl<'obs> Pending<'obs> {
    /// Launches the plan in the gated shape and wraps it.
    pub(crate) fn launch(
        plan: &LaunchPlan,
        mut observer: Option<&'obs mut dyn Observer>,
    ) -> Result<Pending<'obs>, Error> {
        let observe = observer.is_some();
        if observe {
            check_capture_composes(plan)?;
        }
        // Built before the spawn so a setup failure after the mount ops takes
        // the placeholders with it; see `Running::launch`.
        let placeholders = PlaceholderGuard {
            placeholders: plan.managed_placeholders.clone(),
        };
        let (inner, primary) = mechanism::spawn_pending(plan, observe, None, &mut |event| {
            if let Some(observer) = observer.as_deref_mut() {
                observer.progress(event);
            }
        })?;
        debug_assert!(primary.is_none(), "a launch with no terminal returns none");
        Ok(Pending {
            inner: Some(inner),
            observer,
            placeholders,
        })
    }

    /// Launches the plan gated and on a pseudoterminal of its own.
    ///
    /// The primary comes back beside the handle rather than out of
    /// [`proceed`](Self::proceed): the pseudoterminal is allocated before the
    /// fork, the gate sits after the controlling terminal is established, and
    /// nothing writes to the terminal while the launch is held, so the caller
    /// attaches its network stack and proceeds with the primary already in hand.
    pub(crate) fn launch_terminal(
        plan: &LaunchPlan,
        terminal: &Terminal,
    ) -> Result<(Pending<'static>, Pty), Error> {
        check_terminal_composes(plan)?;
        let placeholders = PlaceholderGuard {
            placeholders: plan.managed_placeholders.clone(),
        };
        let (inner, primary) = mechanism::spawn_pending(plan, false, Some(terminal), &mut |_| {})?;
        let primary = primary.ok_or_else(|| wait_error(Errno::PROTO))?;
        Ok((
            Pending {
                inner: Some(inner),
                observer: None,
                placeholders,
            },
            Pty::new(primary),
        ))
    }

    /// A host pid of a process in the sandbox's network namespace.
    ///
    /// The target for `/proc/<pid>/ns/net`: a userspace network stack joins
    /// that namespace to give the sandbox connectivity. Under
    /// [`Network::Isolated`](crate::Network::Isolated) (the default) or
    /// [`Network::None`](crate::Network::None) it names the sandbox's private
    /// network namespace; under [`Network::Host`](crate::Network::Host) there
    /// is no private namespace and this is the host's, where attaching a stack
    /// is not meaningful. The process is alive until this handle is consumed
    /// by [`proceed`](Self::proceed) or dropped.
    pub fn netns_pid(&self) -> u32 {
        self.inner
            .as_ref()
            .expect("a Pending holds its launch until proceed consumes it")
            .netns_pid()
    }

    /// Releases the gated command and returns a handle to it.
    ///
    /// Blocks until the command is executing, so a setup failure that occurred
    /// after the namespaces were created — a refused mount, a failed pivot —
    /// is reported here as the same typed [`Error`] a direct
    /// [`spawn`](crate::Cage::spawn) would return. The command runs with the
    /// standard streams the pending launch was configured for; the returned
    /// [`Running`] waits for, signals, or kills it.
    pub fn proceed(mut self) -> Result<Running<'obs>, Error> {
        let inner = self
            .inner
            .take()
            .expect("a Pending holds its launch until proceed consumes it");
        let mut observer = self.observer.take();
        let launched = inner.proceed(&mut |event| {
            if let Some(observer) = observer.as_deref_mut() {
                observer.progress(event);
            }
        })?;
        Ok(Running::from_launched(
            launched,
            observer,
            PlaceholderGuard {
                placeholders: std::mem::take(&mut self.placeholders.placeholders),
            },
        ))
    }
}

impl fmt::Debug for Pending<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field(
                "netns_pid",
                &self.inner.as_ref().map(|inner| inner.netns_pid()),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        // A pending launch dropped without proceeding must not leak the
        // sandbox; tear it down.
        if let Some(inner) = self.inner.take() {
            inner.abandon();
        }
        // The guard field removes the placeholders as this drops.
    }
}

/// Refuses a capturing launch of a sandbox whose output pair is directed
/// somewhere else.
///
/// Capture supplies a pipe for each output stream, which is a destination; a
/// plan that names one of its own contradicts it, and the caller meant one of
/// the two. [`Stdio::Inherit`](crate::Stdio::Inherit) names none, so it composes
/// with capture and is what every sandbox carries unless the caller said
/// otherwise.
///
/// Standard input is not part of this: capture never touches it, so no
/// disposition of it can contradict a capturing launch.
fn check_capture_composes(plan: &LaunchPlan) -> Result<(), Error> {
    for (stream, disposition) in [
        ("standard output", &plan.stdout),
        ("standard error", &plan.stderr),
    ] {
        if disposition.names_a_destination() {
            return Err(crate::ConfigError::StreamAttachmentConflict {
                stream,
                attachment: "an observer's capture pipe",
            }
            .into());
        }
    }
    Ok(())
}

/// Refuses a terminal launch of a sandbox whose streams are directed somewhere
/// else.
///
/// The replica is all three streams, so a disposition naming a different
/// destination is a contradiction: the caller asked for two things. As with
/// capture, [`Stdio::Inherit`](crate::Stdio::Inherit) names no destination and
/// is therefore no contradiction — the launch is free to supply one, and the
/// terminal overrides nothing the caller said.
fn check_terminal_composes(plan: &LaunchPlan) -> Result<(), Error> {
    for (stream, disposition) in [
        ("standard input", &plan.stdin),
        ("standard output", &plan.stdout),
        ("standard error", &plan.stderr),
    ] {
        if disposition.names_a_destination() {
            return Err(crate::ConfigError::StreamAttachmentConflict {
                stream,
                attachment: "a terminal",
            }
            .into());
        }
    }
    Ok(())
}

/// Sends the termination request byte; a sandbox that already exited took
/// its socket end with it, which is not an error.
fn send_terminate(control: &OwnedFd) -> Result<(), Error> {
    match rustix::net::send(control, &[CONTROL_TERMINATE], SendFlags::NOSIGNAL) {
        Ok(_) => Ok(()),
        Err(Errno::PIPE | Errno::CONNRESET | Errno::NOTCONN) => Ok(()),
        Err(errno) => Err(signal_error(errno)),
    }
}

/// Sends SIGKILL through the supervisor's pidfd; a supervisor that already
/// exited is not an error. The kill flag is raised only once the signal is
/// known delivered (or moot), so an unexpected failure cannot fabricate a
/// killed outcome.
fn send_kill(pidfd: &OwnedFd, kill_sent: &AtomicBool) -> Result<(), Error> {
    match process::pidfd_send_signal(pidfd, Signal::KILL) {
        Ok(()) | Err(Errno::SRCH) => {
            kill_sent.store(true, Ordering::SeqCst);
            Ok(())
        }
        Err(errno) => Err(signal_error(errno)),
    }
}

fn wait_error(errno: Errno) -> Error {
    Error::Wait {
        source: errno.into(),
    }
}

fn signal_error(errno: Errno) -> Error {
    Error::Signal {
        source: errno.into(),
    }
}

fn clone_error(err: std::io::Error) -> Error {
    Error::Signal { source: err }
}
