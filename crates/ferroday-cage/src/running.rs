//! The running-sandbox handle: wait, deadline, terminate, kill.

use std::ffi::OsStr;
use std::fmt;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, epoll};
use rustix::fs::{FlockOperation, Stat};
use rustix::io::Errno;
use rustix::net::SendFlags;
use rustix::process;
use rustix::process::Signal;

use crate::Network;
use crate::cgroup::Cgroup;
use crate::error::{Error, ListenRefusal};
use crate::mechanism::netns::{self, ListenFailure, Namespaces};
use crate::mechanism::{
    self, CONTROL_TERMINATE, CreatedTarget, LaunchPlan, ManagedPlaceholders, MountOp,
    STATUS_RECORD_LEN, wait_syscall_error,
};
use crate::observer::{Collect, Observer, Output};
use crate::poll;
use crate::provision::rooted::Rooted;
use crate::status::{ExitStatus, ResourceUsage};
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
/// outcome. Without a PID namespace the launch stage, the command's parent
/// outside the sandbox, then remains a zombie child process of the caller
/// until the caller exits. A file the launch created in the root as a file
/// bind's target stays there too, since removing it would unmount the running
/// sandbox's bind. Prefer waiting — including after a kill.
///
/// A sandbox with a cgroup of its own, from [`cgroup_parent`], has it removed
/// once the handle collects the outcome, where nothing is left in it then.
/// Without a PID namespace a process the command left behind can still occupy
/// it, and the handle keeps it. A [`kill`](Self::kill), through this handle or
/// a [`KillHandle`], ends that process through the cgroup, and the last of the
/// handle and its kill handles to drop removes the cgroup once its tree has
/// emptied, waiting up to five seconds for it. With [`stop_with_caller`], the
/// drop of the last of them ends the tree through the cgroup as a kill does,
/// and removes the cgroup the same way. Otherwise, without a kill, a cgroup
/// still occupied when the last of them drops stays beneath the parent, for
/// the caller to remove once what is in it has ended.
///
/// Where the launch gave the sandbox the foreground of the caller's terminal
/// (see [`Stdio`](crate::Stdio)), the wait that observes the outcome gives it
/// back to the caller's process group, and so does dropping the handle. A
/// sandbox still running when its handle is dropped runs on in the background
/// of the terminal, where a read of it fails or stops the reader, and a `^C`
/// typed at it reaches the caller's group rather than the sandbox. While the
/// sandbox holds the terminal, the caller's group is the background job: a
/// process in it that reads the terminal stops until its shell resumes it.
///
/// A caller that drives many sandboxes from one thread, such as an async
/// runtime's, waits on the handle's readiness descriptor instead of blocking a
/// thread on each: [`as_fd`](AsFd::as_fd) is readable whenever the handle has
/// work, and [`try_wait`](Self::try_wait) does it without blocking. The
/// embedding chapter of the guide gives the recipe for tokio.
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
/// [`cgroup_parent`]: crate::CageBuilder::cgroup_parent
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
    /// Accumulates the status record across partial reads.
    record: [u8; STATUS_RECORD_LEN],
    record_len: usize,
    /// The command's outcome, once known — the fuse for repeated waits.
    outcome: Option<ExitStatus>,
    /// What the command used, once its status record has arrived carrying it.
    usage: Option<ResourceUsage>,
    /// Whether a kill was requested through this handle or a [`KillHandle`];
    /// decides how a status pipe that closes without a record is read.
    kill_sent: Arc<AtomicBool>,
    /// A pidfd of the launch stage, for the handle to reap once the status
    /// arrives (no PID namespace); the in-namespace init is not the caller's
    /// child process. A pidfd rather than a raw pid so the reap cannot alias a
    /// recycled pid.
    reap: Option<OwnedFd>,
    /// Whether the supervisor has been seen to exit; see
    /// [`awaiting_supervisor`](Self::awaiting_supervisor).
    supervisor_exited: bool,
    /// The pump's read buffer, allocated once when capturing.
    buf: Vec<u8>,
    /// Held only for its `Drop`: it removes the mount targets the launch
    /// created in the root, if any. See
    /// [`LaunchPlan::managed_placeholders`].
    _placeholders: PlaceholderGuard,
    /// The caller's terminal, where the launch lent the sandbox its
    /// foreground: handed back once a wait observes the outcome, or when the
    /// handle drops. A field with a `Drop` of its own rather than a `Drop` on
    /// the handle, for the reason [`PlaceholderGuard`] gives.
    foreground: Option<mechanism::Foreground>,
    /// The readiness descriptor: an epoll set over the channels the pump
    /// would poll. See [`sync_readiness`](Self::sync_readiness).
    ready: Readiness,
    /// The sandbox's cgroup, where the launch has one, shared with each
    /// [`KillHandle`]: a kill ends its tree, before the outcome or after it,
    /// and the last of the handles to drop removes it.
    cgroup: Option<Arc<Cgroup>>,
    /// Whether [`resolve`](Self::resolve) has read the cgroup's account of the
    /// tree and tried to remove it, which it does once.
    cgroup_read: bool,
}

/// Which channel one of the pump's poll slots watches, and where its readiness
/// is recorded after a poll.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Watch {
    /// The captured standard output.
    Stdout,
    /// The captured standard error.
    Stderr,
    /// The status pipe the outcome arrives on: written by the init, or
    /// without a PID namespace by the launch stage.
    Status,
    /// The supervisor's pidfd, once the outcome is known and only until the
    /// supervisor has exited; see [`Running::awaiting_supervisor`].
    Supervisor,
    /// A waiter's own descriptor; see [`Running::wait_or_readable`].
    Wake,
}

/// What one pass of the pump over the live channels ended with.
enum Pass {
    /// Nothing became ready before the pass's timeout.
    TimedOut,
    /// The waiter's own descriptor became ready.
    Woken,
    /// The channels that were ready have been served.
    Served,
}

/// A handle's readiness descriptor: an epoll set over the channels its pump
/// polls, and which of them it holds.
///
/// An epoll registration belongs to the channel's open file description rather
/// than to the descriptor the handle registered it through, and a close ends it
/// only once no descriptor refers to that description. A fork copies the
/// caller's whole descriptor table, so a process the caller forks while the
/// sandbox runs holds every channel open after the handle has closed its own:
/// another launch's stage until it sweeps its inherited descriptors, a child of
/// the caller's own until it executes. A channel left to its close stays in the
/// set for that long, hung up and so always ready, and an event loop waiting on
/// the set spins. So a channel leaves the set through [`close`](Self::close),
/// which takes it out before closing it, and the supervisor's pidfd, which the
/// handle holds for its whole life, through [`remove`](Self::remove).
struct Readiness {
    /// The epoll set.
    set: OwnedFd,
    /// Which channels the set holds, one bit per [`Watch`].
    registered: u8,
}

impl Readiness {
    /// Creates the set a handle owns, before the launch it will serve, so a
    /// failure leaves nothing running.
    ///
    /// The set is kept off the standard streams' numbers, as every descriptor
    /// of the launch's is; see [`mechanism::above_stdio`].
    fn new() -> Result<Readiness, Error> {
        let failed = |errno: Errno| Error::Spawn {
            source: errno.into(),
        };
        let mut set = epoll::create(epoll::CreateFlags::CLOEXEC).map_err(failed)?;
        mechanism::above_stdio(&mut set).map_err(failed)?;
        Ok(Readiness { set, registered: 0 })
    }

    /// The bit [`registered`](Self::registered) keeps for `watch`.
    fn bit(watch: Watch) -> u8 {
        1 << watch as u8
    }

    /// Whether the set holds `watch`'s channel.
    fn holds(&self, watch: Watch) -> bool {
        self.registered & Readiness::bit(watch) != 0
    }

    /// Adds `fd`, the channel `watch` names, to the set.
    fn add(&mut self, watch: Watch, fd: BorrowedFd<'_>) -> Result<(), Error> {
        let data = epoll::EventData::new_u64(watch as u64);
        epoll::add(&self.set, fd, data, epoll::EventFlags::IN).map_err(wait_syscall_error)?;
        self.registered |= Readiness::bit(watch);
        Ok(())
    }

    /// Takes `fd`, the channel `watch` names, out of the set, leaving it open.
    fn remove(&mut self, watch: Watch, fd: BorrowedFd<'_>) -> Result<(), Error> {
        epoll::delete(&self.set, fd).map_err(wait_syscall_error)?;
        self.registered &= !Readiness::bit(watch);
        Ok(())
    }

    /// Closes the channel `slot` holds, if any, taking it out of the set first.
    ///
    /// The descriptor is closed whether or not the removal succeeds.
    fn close(&mut self, watch: Watch, slot: &mut Option<OwnedFd>) -> Result<(), Error> {
        let Some(fd) = slot.take() else {
            return Ok(());
        };
        match self.holds(watch) {
            true => self.remove(watch, fd.as_fd()),
            false => Ok(()),
        }
    }
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
        let ready = Readiness::new()?;
        let cgroup = plan
            .cgroup
            .as_ref()
            .map(|cgroup| Cgroup::create(cgroup, plan.stop_with_caller))
            .transpose()?;
        // The progress sink borrows the observer only for the launch; the
        // borrow ends with the statement, leaving the observer to move into
        // the handle for the output pump.
        let mut created = Vec::new();
        let spawned = mechanism::spawn(
            plan,
            observe,
            None,
            cgroup.as_ref().map(Cgroup::procs),
            &mut |event| {
                if let Some(observer) = observer.as_deref_mut() {
                    observer.progress(event);
                }
            },
            &mut created,
        );
        let (launched, primary) = guarded(plan, &created, spawned)?;
        debug_assert!(primary.is_none(), "a launch with no terminal returns none");
        let placeholders = PlaceholderGuard::new(plan, &created, Some(launched.pidfd.as_fd()));
        Ok(Running::from_launched(
            launched,
            observer,
            placeholders,
            ready,
            cgroup,
        ))
    }

    /// Launches the plan capturing both streams whole, waits for it, and
    /// returns the outcome with everything the command wrote: what
    /// [`Cage::output`](crate::Cage::output) and its restriction counterpart
    /// return.
    pub(crate) fn output(plan: &LaunchPlan) -> Result<Output, Error> {
        let mut collect = Collect::default();
        let (status, usage) = {
            let mut running = Running::launch(plan, Some(&mut collect))?;
            let status = running.wait()?;
            (status, running.usage())
        };
        Ok(collect.into_output(status, usage))
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
        let ready = Readiness::new()?;
        let cgroup = plan
            .cgroup
            .as_ref()
            .map(|cgroup| Cgroup::create(cgroup, plan.stop_with_caller))
            .transpose()?;
        let mut created = Vec::new();
        let spawned = mechanism::spawn(
            plan,
            false,
            Some(terminal),
            cgroup.as_ref().map(Cgroup::procs),
            &mut |_| {},
            &mut created,
        );
        let (launched, primary) = guarded(plan, &created, spawned)?;
        let placeholders = PlaceholderGuard::new(plan, &created, Some(launched.pidfd.as_fd()));
        let primary = primary.ok_or_else(|| wait_syscall_error(Errno::PROTO))?;
        Ok((
            Running::from_launched(launched, None, placeholders, ready, cgroup),
            Pty::new(primary),
        ))
    }

    /// Wraps the caller-side channels of an already-launched sandbox.
    fn from_launched(
        launched: mechanism::Launched,
        observer: Option<&'obs mut dyn Observer>,
        placeholders: PlaceholderGuard,
        ready: Readiness,
        cgroup: Option<Cgroup>,
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
            record: [0; STATUS_RECORD_LEN],
            record_len: 0,
            outcome: None,
            usage: None,
            kill_sent: Arc::new(AtomicBool::new(false)),
            reap: launched.reap,
            supervisor_exited: false,
            buf,
            _placeholders: placeholders,
            foreground: launched.foreground,
            ready,
            cgroup: cgroup.map(Arc::new),
            cgroup_read: false,
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
    /// The wait completes once the command's outcome is known and the
    /// supervisor has exited, which with a PID namespace is once the kernel
    /// has torn the namespace down. A process of the sandbox the kernel cannot
    /// end at once, one in an uninterruptible sleep on an unresponsive
    /// filesystem, holds that teardown, and the wait with it. When output is
    /// captured, both captured streams must also have reached end-of-file.
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
            None => Err(wait_syscall_error(Errno::PROTO)),
        }
    }

    /// Waits until the command terminates or the deadline passes.
    ///
    /// Returns `Ok(None)` when the deadline passes first; the sandbox keeps
    /// running, or is still being torn down, output produced before the
    /// deadline has been delivered, and the wait can be resumed. The deadline
    /// does not kill anything — escalation is the caller's, per the recipe
    /// above.
    ///
    /// A deadline already past still serves what is ready, without blocking,
    /// as [`try_wait`](Self::try_wait) does, and returns the outcome where
    /// that settles it. Collecting an outcome the supervisor reported can take
    /// two such calls: one reads the report, and the next sees the supervisor
    /// gone.
    pub fn wait_deadline(&mut self, deadline: Instant) -> Result<Option<ExitStatus>, Error> {
        self.pump(Some(deadline), None)
    }

    /// [`wait_deadline`](Self::wait_deadline) with a relative timeout.
    ///
    /// A zero timeout serves what is ready without blocking, as
    /// [`try_wait`](Self::try_wait) does.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<ExitStatus>, Error> {
        // A timeout too large for the clock is a wait without one.
        match Instant::now().checked_add(timeout) {
            Some(deadline) => self.pump(Some(deadline), None),
            None => self.pump(None, None),
        }
    }

    /// Serves whatever of the handle's channels is ready, without blocking,
    /// and returns the command's outcome once it is known.
    ///
    /// `Ok(None)` means the sandbox is still running, or still being torn
    /// down. Like [`wait`](Self::wait), it delivers captured output to the
    /// observer as it reads it, and reports the outcome only once every
    /// channel has settled, so it returns the same outcome a wait would.
    ///
    /// It is the non-blocking half of the readiness descriptor
    /// [`as_fd`](AsFd::as_fd) returns. A caller registers that descriptor
    /// with its event loop, calls `try_wait` once, and calls it again each
    /// time the descriptor is readable, until it returns the outcome:
    ///
    /// ```no_run
    /// # fn main() -> ferroday_cage::Result<()> {
    /// # let cage = ferroday_cage::Cage::builder().rootfs("/r").command("/bin/x").build()?;
    /// # fn readable(_: std::os::fd::BorrowedFd<'_>) {}
    /// use std::os::fd::AsFd;
    ///
    /// let mut running = cage.spawn()?;
    /// let status = loop {
    ///     if let Some(status) = running.try_wait()? {
    ///         break status;
    ///     }
    ///     // The event loop's wait for the descriptor to be readable.
    ///     readable(running.as_fd());
    /// };
    /// # let _ = status;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// One call reads at most one chunk of each captured stream, so a command
    /// writing without pause cannot hold it, and the descriptor stays readable
    /// while more is waiting.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        if !self.settled() {
            let now = poll::timeout(Duration::ZERO);
            self.pass(Some(&now), None)?;
        }
        self.sync_readiness()?;
        self.outcome_if_settled()
    }

    /// The outcome where every channel has settled, and `None` otherwise.
    fn outcome_if_settled(&mut self) -> Result<Option<ExitStatus>, Error> {
        match self.settled() {
            true => self.resolve().map(Some),
            false => Ok(None),
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

    /// The status pipe, for a waiter that polls channels of its own and must
    /// notice the command's exit among them.
    ///
    /// It becomes readable once the supervisor has reported the command's
    /// exit, or has gone without reporting one; either way the outcome is
    /// ready to be read. `None` means it has been read already. The terminal
    /// relay polls it beside the session's terminal, which a descendant that
    /// outlives the command can hold open without a PID namespace.
    pub(crate) fn status_pipe(&self) -> Option<BorrowedFd<'_>> {
        self.status.as_ref().map(AsFd::as_fd)
    }

    /// What the command and its descendants used of the processor and of
    /// memory, once a wait has returned the command's outcome.
    ///
    /// [`ResourceUsage`] says which processes it covers. `None` before the
    /// outcome is known, and where neither source reported a figure. Under a
    /// PID namespace a [`kill`](Self::kill) ends the init that would have
    /// reported the collected processes' figures, so a killed sandbox reports
    /// only what its cgroup read for the whole tree, and without a cgroup it
    /// reports no usage at all. Without a PID namespace the kill ends only the
    /// command, and its usage is reported as for any other exit.
    pub fn usage(&self) -> Option<ResourceUsage> {
        self.usage
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
    /// the command process itself is killed, and descendants it spawned are
    /// beyond the library's reach unless the sandbox has a cgroup of its own:
    /// the kill then also writes the cgroup's `cgroup.kill` (Linux 5.14),
    /// which ends every process of its tree. It does so once the outcome is
    /// known too, so a kill after a wait has returned ends what the command
    /// left behind, and the last handle to drop then removes the cgroup, as
    /// stated above.
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
        send_kill(&self.pidfd, &self.kill_sent, self.cgroup.as_deref())
    }

    /// Returns a handle that can terminate or kill the sandbox from another
    /// thread, while this handle blocks in a wait.
    ///
    /// # Errors
    ///
    /// [`Error::KillHandle`] where the handle's descriptors cannot be
    /// duplicated, typically because the process has run out of them.
    pub fn kill_handle(&self) -> Result<KillHandle, Error> {
        let duplicate = |fd: &OwnedFd| {
            fd.try_clone()
                .map_err(|source| Error::KillHandle { source })
        };
        Ok(KillHandle {
            pidfd: duplicate(&self.pidfd)?,
            control: duplicate(&self.control)?,
            kill_sent: Arc::clone(&self.kill_sent),
            cgroup: self.cgroup.clone(),
        })
    }

    /// Whether every channel has settled: the streams at end-of-file, the
    /// status record or its end-of-file received, and, where the outcome is
    /// known, the supervisor exited.
    fn settled(&self) -> bool {
        self.status.is_none()
            && self.stdout.is_none()
            && self.stderr.is_none()
            && !self.awaiting_supervisor()
    }

    /// Whether the outcome is known and the supervisor has not yet been seen
    /// to exit.
    ///
    /// A known outcome, a status record or a kill, means the supervisor is
    /// ending, and the wait lasts until it has ended. With a PID namespace its
    /// exit follows the kernel's teardown of the namespace, after which no
    /// process of the sandbox remains to hold a bind onto a file the launch
    /// created in the root, and the handle's drop can remove it. An unknown
    /// outcome is a lost supervisor, reported as one without waiting on a
    /// process that need never exit.
    fn awaiting_supervisor(&self) -> bool {
        !self.supervisor_exited && (self.outcome.is_some() || self.kill_sent.load(Ordering::SeqCst))
    }

    /// The fused outcome once every channel has settled.
    ///
    /// A status pipe that closed without a record means the supervisor
    /// exited without reporting. After a kill that is the expected shape —
    /// the kill took the supervisor and, with it, the namespace — and the
    /// outcome is termination by SIGKILL. Unprovoked, it is an error.
    fn resolve(&mut self) -> Result<ExitStatus, Error> {
        // Every process of the sandbox is gone once the channels settle, so the
        // terminal it held goes back to the caller's process group.
        if let Some(foreground) = &mut self.foreground {
            foreground.hand_back();
        }
        if let Some(pidfd) = self.reap.take() {
            // Reap the launch stage through its pidfd, so the wait targets
            // exactly that process and cannot alias a pid a concurrent reaper
            // freed and the OS recycled. Best-effort: the launch stage exits
            // right after the status write, and an application-wide child
            // reaper may even have collected it first. Reaped before the
            // cgroup below is removed, since the stage joined the cgroup, and
            // the kernel removes none that still holds a process.
            let _ = mechanism::reap_via_pidfd(pidfd.as_fd());
        }
        // The cgroup's own account of the tree, read once the outcome is known
        // and before the cgroup is removed. It stands alone where the
        // supervisor reported nothing, as after a kill. A cgroup still holding
        // a process the sandbox left behind stays with the handles, for a kill
        // to end its tree and the last of them to drop to remove it.
        if let Some(cgroup) = &self.cgroup
            && !self.cgroup_read
        {
            self.cgroup_read = true;
            self.usage = ResourceUsage::joined(self.usage, cgroup.usage());
            cgroup.remove_if_empty();
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
    ///
    /// Every wait makes at least one pass, so a deadline already past serves
    /// what is ready without blocking, as [`try_wait`](Self::try_wait) does,
    /// and makes no further pass.
    fn pump(
        &mut self,
        deadline: Option<Instant>,
        wake: Option<BorrowedFd<'_>>,
    ) -> Result<Option<ExitStatus>, Error> {
        loop {
            if self.settled() {
                return self.resolve().map(Some);
            }
            let timeout = deadline.map(poll::until);
            let pass = self.pass(timeout.as_ref(), wake)?;
            let passed = deadline.is_some_and(|deadline| deadline <= Instant::now());
            match pass {
                Pass::TimedOut => return Ok(None),
                // The waiter's channel is answered after this pass's own
                // reads, so an outcome that arrived beside it is reported
                // rather than left for the next wait.
                Pass::Woken => return self.outcome_if_settled(),
                Pass::Served if passed => return self.outcome_if_settled(),
                Pass::Served => {}
            }
        }
    }

    /// One pass of the pump: polls the live channels until one is ready or
    /// `timeout` passes, and serves each that is.
    fn pass(
        &mut self,
        timeout: Option<&Timespec>,
        wake: Option<BorrowedFd<'_>>,
    ) -> Result<Pass, Error> {
        // Only the live channels are polled: each is gathered to the front
        // of a fixed array, so the hot loop allocates nothing, and the
        // slice handed to `poll` ends where they do. A retired channel
        // left in it would be ready on every pass (see `poll`), the
        // supervisor's pidfd above all once its process is reaped, so it is
        // watched only until it is first seen ready. The entries past the
        // live ones are never polled; they hold the pidfd only because
        // every entry of the array needs a descriptor.
        let mut watched = [Watch::Stdout; 5];
        let mut pollfds: [PollFd<'_>; 5] =
            std::array::from_fn(|_| PollFd::new(&self.pidfd, PollFlags::empty()));
        let mut live = 0;
        for (watch, fd) in [
            (Watch::Stdout, self.stdout.as_ref().map(AsFd::as_fd)),
            (Watch::Stderr, self.stderr.as_ref().map(AsFd::as_fd)),
            (Watch::Status, self.status.as_ref().map(AsFd::as_fd)),
            (
                Watch::Supervisor,
                self.awaiting_supervisor().then(|| self.pidfd.as_fd()),
            ),
            (Watch::Wake, wake),
        ] {
            if let Some(fd) = fd {
                watched[live] = watch;
                pollfds[live] = PollFd::from_borrowed_fd(fd, PollFlags::IN);
                live += 1;
            }
        }

        match rustix::event::poll(&mut pollfds[..live], timeout) {
            Ok(0) => return Ok(Pass::TimedOut),
            Ok(_) => {}
            Err(Errno::INTR) => return Ok(Pass::Served),
            Err(errno) => return Err(wait_syscall_error(errno)),
        }

        let mut ready = [false; 5];
        for (&watch, fd) in watched[..live].iter().zip(&pollfds) {
            ready[watch as usize] = !fd.revents().is_empty();
        }
        if ready[Watch::Stdout as usize] {
            self.drain_stream(Channel::Stdout)?;
        }
        if ready[Watch::Stderr as usize] {
            self.drain_stream(Channel::Stderr)?;
        }
        if ready[Watch::Status as usize] {
            self.drain_status()?;
        }
        if ready[Watch::Supervisor as usize] {
            self.supervisor_exited = true;
        }
        self.sync_readiness()?;
        Ok(match ready[Watch::Wake as usize] {
            true => Pass::Woken,
            false => Pass::Served,
        })
    }

    /// Brings the readiness set in line with the channels the pump polls.
    ///
    /// The set holds what the next pass would poll, so it is readable exactly
    /// when that pass has work: a stream or the status pipe while it is live,
    /// and the supervisor's pidfd while the outcome is known and the
    /// supervisor has not been seen to exit. A pidfd stays readable once its
    /// process is gone, so the pump watches it only until it is first seen
    /// ready, and the set drops it then too. A stream and the status pipe
    /// leave the set as the pump closes them, through [`Readiness::close`].
    ///
    /// Run after every pass and by [`try_wait`](Self::try_wait), so the set
    /// follows the handle however it is driven.
    fn sync_readiness(&mut self) -> Result<(), Error> {
        for (watch, fd) in [
            (Watch::Stdout, &self.stdout),
            (Watch::Stderr, &self.stderr),
            (Watch::Status, &self.status),
        ] {
            if let Some(fd) = fd
                && !self.ready.holds(watch)
            {
                self.ready.add(watch, fd.as_fd())?;
            }
        }
        let supervisor = Watch::Supervisor;
        match (self.awaiting_supervisor(), self.ready.holds(supervisor)) {
            (true, false) => self.ready.add(supervisor, self.pidfd.as_fd()),
            (false, true) => self.ready.remove(supervisor, self.pidfd.as_fd()),
            _ => Ok(()),
        }
    }

    /// Reads one chunk from a captured stream and delivers it; end-of-file
    /// retires the stream.
    fn drain_stream(&mut self, channel: Channel) -> Result<(), Error> {
        let (slot, watch) = match channel {
            Channel::Stdout => (&mut self.stdout, Watch::Stdout),
            Channel::Stderr => (&mut self.stderr, Watch::Stderr),
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
            return Err(wait_syscall_error(Errno::PROTO));
        };
        match rustix::io::read(&*fd, &mut self.buf) {
            Ok(0) => return self.ready.close(watch, slot),
            Ok(n) => {
                let chunk = &self.buf[..n];
                match channel {
                    Channel::Stdout => observer.stdout(chunk),
                    Channel::Stderr => observer.stderr(chunk),
                }
            }
            Err(Errno::INTR) => {}
            Err(errno) => return Err(wait_syscall_error(errno)),
        }
        Ok(())
    }

    /// Accumulates the status record; the full record or end-of-file
    /// retires the pipe.
    fn drain_status(&mut self) -> Result<(), Error> {
        let Some(fd) = &self.status else {
            return Ok(());
        };
        match rustix::io::read(fd, &mut self.record[self.record_len..]) {
            Ok(0) => self.ready.close(Watch::Status, &mut self.status),
            Ok(n) => {
                self.record_len += n;
                if self.record_len < self.record.len() {
                    return Ok(());
                }
                let closed = self.ready.close(Watch::Status, &mut self.status);
                // A record this build never writes is a defect in the library,
                // not a caller error, but the decode still must not panic:
                // EPROTO fails the wait, with the pipe retired.
                let Some((status, usage)) = mechanism::decode_status(self.record) else {
                    return Err(wait_syscall_error(Errno::PROTO));
                };
                self.outcome = Some(status);
                self.usage = usage;
                closed
            }
            Err(Errno::INTR) => Ok(()),
            Err(errno) => Err(wait_syscall_error(errno)),
        }
    }
}

impl AsFd for Running<'_> {
    /// The handle's readiness descriptor, readable whenever
    /// [`try_wait`](Running::try_wait) has work: output to deliver, the
    /// outcome to read, or the teardown to observe.
    ///
    /// It is an epoll set the handle owns, over the channels a wait polls,
    /// and it follows them as each closes. Register it with an event loop as
    /// readable, level-triggered, and call `try_wait` once before the first
    /// wait on it and again each time it is readable. Once `try_wait` has
    /// returned the outcome the set is empty, and it never becomes readable
    /// again. A duplicate, such as one an event loop that owns its descriptors
    /// takes, watches the same set.
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.ready.set.as_fd()
    }
}

impl fmt::Debug for Running<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Running")
            .field("pid", &self.pid)
            .field("outcome", &self.outcome)
            .field("usage", &self.usage)
            .finish_non_exhaustive()
    }
}

/// The guard for what a launch created, given its outcome.
///
/// A launch that failed has ended every process of its own whose targets it
/// reports, so the guard built here, holding no supervisor, removes them as the
/// `?` it is used with drops it: a launch that creates `/etc/resolv.conf` and
/// then fails at the pivot, the working-directory change, or the exec, the case
/// a caller getting a configuration right hits repeatedly, leaves nothing
/// behind.
fn guarded<T>(
    plan: &LaunchPlan,
    created: &[CreatedTarget],
    spawned: Result<T, Error>,
) -> Result<T, Error> {
    spawned.inspect_err(|_| drop(PlaceholderGuard::new(plan, created, None)))
}

/// Removes the file-bind targets a launch created in the root, once the
/// sandbox that bound onto them is gone.
///
/// A guard of its own, rather than a [`Drop`] on the handles that carry it,
/// because a type implementing `Drop` keeps every borrow it holds live until
/// the end of its scope. [`Running`] borrows the caller's observer, so a `Drop`
/// there would stop a caller from reading its own observer after waiting — the
/// ordinary way to collect captured output. The guard borrows nothing, so
/// dropping it observes nothing.
///
/// What it removes is what the setup reported creating, and only once the
/// supervisor has exited. A bind holds the name it was made over, not only the
/// file: unlinking the name unmounts every mount on it, in every mount
/// namespace, the sandbox's nested one included. Removed while the sandbox
/// runs, a target would take the sandbox's bind with it: its
/// `/etc/resolv.conf`, or a writable file bind whose later writes would land in
/// the root instead. With a PID namespace the supervisor's exit is the whole
/// sandbox's. Without one it is the command's, and a descendant that outlives
/// the command is beyond the library's reach here as everywhere.
///
/// Two sandboxes on one root can share a target: the first creates it, and the
/// second finds it already there. Each holds a shared lock on it, and a removal
/// takes an exclusive one first, so the first's teardown leaves a target the
/// second still holds; see [`remove_placeholder`]. That target then stays in
/// the root for good, since the second did not create it and removes nothing
/// it did not create. Without a PID namespace the second holds its lock only
/// until its command executes, and from then on the first's teardown can
/// unmount the second's bind.
#[derive(Default)]
pub(crate) struct PlaceholderGuard {
    /// The root's writable layer, which every path below is relative to.
    root: PathBuf,
    /// The targets the launch created and the caller side can name.
    created: Vec<Placeholder>,
    /// The supervisor, whose exit frees them; `None` where no process of the
    /// launch is left.
    supervisor: Option<OwnedFd>,
}

/// One target a launch created: where it is, which file it is, and whether
/// creating it replaced an overlay whiteout that removing it puts back.
struct Placeholder {
    /// The path, relative to the guard's root.
    path: PathBuf,
    /// The created file's inode number; see [`CreatedTarget`].
    ino: u64,
    /// Whether the upper held a whiteout at the path before the launch.
    whiteout: bool,
}

impl PlaceholderGuard {
    /// The guard for the targets `created` reports of a launch of `plan`,
    /// freed by the exit of `supervisor`, or at once where there is none.
    pub(crate) fn new(
        plan: &LaunchPlan,
        created: &[CreatedTarget],
        supervisor: Option<BorrowedFd<'_>>,
    ) -> PlaceholderGuard {
        PlaceholderGuard::of(&plan.managed_placeholders, &plan.ops, created, supervisor)
    }

    /// [`new`](Self::new), from the two parts of the plan it reads.
    ///
    /// A report names the mount op that created a target, and `managed` says
    /// which of those the caller side can name in the root's writable layer: a
    /// target under an earlier mount is that mount's, not the root's. A
    /// supervisor whose pidfd cannot be duplicated cannot be watched, so its
    /// targets are kept rather than removed early.
    pub(crate) fn of(
        managed: &ManagedPlaceholders,
        ops: &[MountOp],
        created: &[CreatedTarget],
        supervisor: Option<BorrowedFd<'_>>,
    ) -> PlaceholderGuard {
        let supervisor = match supervisor.map(|fd| fd.try_clone_to_owned()) {
            None => None,
            Some(Ok(fd)) => Some(fd),
            Some(Err(_)) => return PlaceholderGuard::default(),
        };
        let created = created
            .iter()
            .filter_map(|target| {
                let file = ops.get(target.op)?.create_file.as_ref()?;
                let path = PathBuf::from(OsStr::from_bytes(file.to_bytes()));
                managed.paths.contains(&path).then(|| Placeholder {
                    whiteout: managed.whiteouts.contains(&path),
                    path,
                    ino: target.ino,
                })
            })
            .collect();
        PlaceholderGuard {
            root: managed.root.clone(),
            created,
            supervisor,
        }
    }
}

impl Drop for PlaceholderGuard {
    fn drop(&mut self) {
        if self.created.is_empty() {
            return;
        }
        if let Some(supervisor) = &self.supervisor
            && !mechanism::has_exited(supervisor.as_fd())
        {
            return;
        }
        // One descriptor for the root, which every path below is resolved
        // against; nothing here walks the host's own tree.
        let Ok(root) = Rooted::open(&self.root) else {
            return;
        };
        for placeholder in &self.created {
            remove_placeholder(&root, placeholder);
            // A target created over an overlay whiteout replaced it; the
            // whiteout goes back once the target is gone. A name still
            // occupied, by a target that was not removed, refuses the
            // whiteout, and is left as it is.
            if placeholder.whiteout {
                let _ = root.whiteout(&placeholder.path);
            }
        }
    }
}

/// Removes one target the launch created in the root, if the name still holds
/// the file it created and no other sandbox is bound onto it.
///
/// The path is relative to `root` and is resolved against it by [`Rooted`],
/// with `openat2` and `RESOLVE_IN_ROOT` — the containment the sandbox stage
/// gives every mount target, for the same reason. A root filesystem is entitled
/// to hold an absolute symbolic link (`./etc -> /etc` in an unpacked tarball, an
/// `/etc/resolv.conf` pointing into a resolver's runtime directory), and
/// joining the two into one host path would have that link resolve against the
/// *host's* root on this side of the fork, which is where the unlink would
/// then land.
///
/// Only an empty regular file with the inode number the setup reported is
/// removed.
/// The target a launch creates is empty and stays that way: the bind covers it
/// for the sandbox's whole life, and the mount is confined to the sandbox's own
/// namespace, so nothing can write through it. Anything else at the name
/// arrived from elsewhere and belongs to whoever put it there.
///
/// The file is opened and locked before it is removed. Every sandbox that binds
/// onto a regular file holds a shared lock on it: the init for the sandbox's
/// whole life, and, without a PID namespace, the command process only until it
/// executes. On a root two sandboxes share, a target this launch created and
/// the other then bound onto refuses the exclusive lock here while the other
/// holds it, and stays in the root rather than unmounting the other's bind.
///
/// Best-effort, like the teardown around it. A failure leaves a file the rootfs
/// did not ship, which is untidy but not a failure of the launch itself.
fn remove_placeholder(root: &Rooted, placeholder: &Placeholder) {
    let ours = |stat: &Stat| Rooted::is_empty_file(stat) && stat.st_ino == placeholder.ino;
    let Ok(file) = root.reader(&placeholder.path) else {
        return;
    };
    match rustix::fs::fstat(&file) {
        Ok(stat) if ours(&stat) => {}
        _ => return,
    }
    // A lock on the target itself rather than a lock file, so not
    // `provision::lock_exclusive`'s to take: it is only tried, through the
    // descriptor whose inode was just checked, and a refusal is an answer.
    #[expect(clippy::disallowed_methods)]
    let unheld = rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive);
    if unheld.is_err() {
        return;
    }
    let _ = root.remove_if(&placeholder.path, ours);
}

/// A detached signaling handle for a running sandbox.
///
/// Obtained from [`Running::kill_handle`]; owns duplicated channel ends, so
/// it works from any thread — typically a watchdog killing the sandbox
/// while another thread blocks in [`Running::wait`]. As long as it exists
/// it holds the [`stop_with_caller`] tie alongside the `Running`.
///
/// It shares the sandbox's cgroup, where the launch has one, with the
/// `Running`. Its [`kill`](Self::kill) ends the cgroup's tree as
/// [`Running::kill`] does, before the outcome or after it, and whichever of
/// the handles drops last removes the cgroup, waiting up to five seconds for a
/// killed tree to empty first; [`Running`] states when the cgroup goes.
///
/// [`stop_with_caller`]: crate::CageBuilder::stop_with_caller
#[derive(Debug)]
pub struct KillHandle {
    pidfd: OwnedFd,
    control: OwnedFd,
    kill_sent: Arc<AtomicBool>,
    /// The sandbox's cgroup, shared with the [`Running`] and every other kill
    /// handle of it.
    cgroup: Option<Arc<Cgroup>>,
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
        send_kill(&self.pidfd, &self.kill_sent, self.cgroup.as_deref())
    }
}

/// A launched sandbox held before its command runs — the userspace-network
/// seam.
///
/// Returned by [`Cage::spawn_pending`] and [`Cage::spawn_pending_with`]. The
/// sandbox's namespaces and mounts are in place and its supervisor is
/// published, but the command is held at a gate before its own confinement and
/// its `execve`. [`netns_pid`](Self::netns_pid) is a
/// host pid of a process in the sandbox's network namespace, the target a
/// userspace network stack (`pasta`, `slirp4netns`) joins through
/// `/proc/<pid>/ns/net`; the process is alive until the handle is consumed or
/// dropped. Once the stack is attached and ready,
/// [`proceed`](Self::proceed) releases the command and returns the running
/// handle.
///
/// Dropping a `Pending` without proceeding tears the launch down: the
/// supervisor is killed and the launch stage reaped, so no sandbox is left
/// running. The drop returns once the supervisor has exited.
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
    /// [`Running`] this becomes, or removed here once a launch that never
    /// proceeds is gone.
    placeholders: PlaceholderGuard,
    /// The sandbox's cgroup, handed to the [`Running`] this becomes.
    cgroup: Option<Cgroup>,
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
        let cgroup = plan
            .cgroup
            .as_ref()
            .map(|cgroup| Cgroup::create(cgroup, plan.stop_with_caller))
            .transpose()?;
        let mut created = Vec::new();
        let spawned = mechanism::spawn_pending(
            plan,
            observe,
            None,
            cgroup.as_ref().map(Cgroup::procs),
            &mut |event| {
                if let Some(observer) = observer.as_deref_mut() {
                    observer.progress(event);
                }
            },
            &mut created,
        );
        let (inner, primary) = guarded(plan, &created, spawned)?;
        debug_assert!(primary.is_none(), "a launch with no terminal returns none");
        let placeholders = PlaceholderGuard::new(plan, &created, Some(inner.supervisor()));
        Ok(Pending {
            inner: Some(inner),
            observer,
            placeholders,
            cgroup,
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
        let cgroup = plan
            .cgroup
            .as_ref()
            .map(|cgroup| Cgroup::create(cgroup, plan.stop_with_caller))
            .transpose()?;
        let mut created = Vec::new();
        let spawned = mechanism::spawn_pending(
            plan,
            false,
            Some(terminal),
            cgroup.as_ref().map(Cgroup::procs),
            &mut |_| {},
            &mut created,
        );
        let (inner, primary) = guarded(plan, &created, spawned)?;
        let placeholders = PlaceholderGuard::new(plan, &created, Some(inner.supervisor()));
        let primary = primary.ok_or_else(|| wait_syscall_error(Errno::PROTO))?;
        Ok((
            Pending {
                inner: Some(inner),
                observer: None,
                placeholders,
                cgroup,
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

    /// Makes a TCP listener at `address` on the sandbox's loopback, for the
    /// caller to accept the connections the command makes there.
    ///
    /// The command connects to `address` as to any server on its own loopback,
    /// and each connection arrives at the returned listener, in the caller's
    /// process. Nothing of the caller's runs inside the sandbox, and the
    /// command is the sandbox's only program: a
    /// [`terminate`](Running::terminate) reaches it rather than a relay
    /// standing in front of it. Made before [`proceed`](Self::proceed), the
    /// listener is in place before the command's first connection.
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let cage = ferroday_cage::Cage::builder().rootfs("/r").command("/bin/x").build()?;
    /// use std::io::Read;
    ///
    /// let pending = cage.spawn_pending()?;
    /// let listener = pending.listen("127.0.0.1:4100".parse()?)?;
    /// let mut running = pending.proceed()?;
    /// let (mut connection, _) = listener.accept()?;
    /// let mut request = Vec::new();
    /// connection.read_to_end(&mut request)?;
    /// let status = running.wait()?;
    /// drop(listener);
    /// # let _ = status;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// `address` is a loopback address, in `127.0.0.0/8` or `::1`, and any
    /// port, a privileged one included: a helper process makes the listener
    /// inside the sandbox's user namespace, where it holds
    /// `CAP_NET_BIND_SERVICE`. Port 0 has the kernel choose one, which
    /// [`local_addr`](TcpListener::local_addr) reports. The sandbox has a
    /// loopback of its own only under
    /// [`Network::Isolated`](crate::Network::Isolated), the default, so a
    /// sandbox under [`Network::None`](crate::Network::None) or
    /// [`Network::Host`](crate::Network::Host) is refused with
    /// [`Error::ListenRefused`], as is an address that is not a loopback one.
    /// A failure to make the listener is [`Error::Listen`], whose
    /// `EADDRINUSE` means an earlier listener already holds the address.
    ///
    /// # Lifetime
    ///
    /// A socket keeps its network namespace alive, so the listener keeps the
    /// sandbox's namespace in being until the caller closes it, whatever has
    /// become of the sandbox. Once the sandbox has exited no connection can
    /// arrive, and a blocking `accept` waits forever. The caller drops the
    /// listener once its wait returns.
    ///
    /// A thread blocked in `accept` is not released by another thread dropping
    /// the listener, and the caller cannot connect to it to wake it, since the
    /// address is the sandbox's. Two shapes stop such a thread:
    ///
    /// - **Accepting only when a poll reports a connection.** The listener is
    ///   made non-blocking, with
    ///   [`set_nonblocking`](TcpListener::set_nonblocking), and polled beside a
    ///   descriptor the caller makes readable to stop, such as a pipe, or this
    ///   handle's own readiness descriptor, which [`Running`] implements
    ///   [`AsFd`] for.
    /// - **Shutting the socket down for reading.** `shutdown(2)` with
    ///   `SHUT_RD` on the listener's descriptor makes a blocked `accept` fail
    ///   with `EINVAL`. The standard library's `TcpListener` has no method for
    ///   it; rustix spells it `rustix::net::shutdown(&listener,
    ///   rustix::net::Shutdown::Read)`.
    ///
    /// # Landlock
    ///
    /// A Landlock network grant governs `connect` to every TCP port, loopback
    /// included. A sandbox carrying one, from the hardening layer's
    /// `CageBuilder::landlock_net`, grants `NetAccess::CONNECT` on the
    /// listener's port, or the command's connection is refused.
    pub fn listen(&self, address: SocketAddr) -> Result<TcpListener, Error> {
        let refused = |reason| Error::ListenRefused { address, reason };
        if !address.ip().is_loopback() {
            return Err(refused(ListenRefusal::NotLoopback));
        }
        match self.network() {
            Network::Isolated => {}
            Network::None => return Err(refused(ListenRefusal::LoopbackDown)),
            Network::Host => return Err(refused(ListenRefusal::SharedNamespace)),
        }
        let failed = |op, source| Error::Listen {
            address,
            op,
            source,
        };
        let namespaces = self
            .namespaces()
            .map_err(|(which, errno)| failed(which, Some(errno.into())))?;
        let listener = netns::listen(&namespaces, address).map_err(|failure| match failure {
            ListenFailure::Spawn(errno) => {
                failed("starting the listener's helper", Some(errno.into()))
            }
            ListenFailure::Step(step, errno) => failed(step.describe(), Some(errno.into())),
            ListenFailure::Lost => failed("receiving the listener from its helper", None),
        })?;
        Ok(TcpListener::from(listener))
    }

    /// The network the sandbox was built with.
    pub(crate) fn network(&self) -> Network {
        self.inner
            .as_ref()
            .expect("a Pending holds its launch until proceed consumes it")
            .network()
    }

    /// Opens the sandbox's user and network namespaces, for a helper to join.
    ///
    /// The pid they are opened through is held to the supervisor's pidfd, as
    /// [`Namespaces::of`] states, since holding the launch does not keep a pid
    /// from being taken by another process once the supervisor is gone.
    pub(crate) fn namespaces(&self) -> Result<Namespaces, (&'static str, Errno)> {
        let inner = self
            .inner
            .as_ref()
            .expect("a Pending holds its launch until proceed consumes it");
        Namespaces::of(inner.netns_pid(), inner.supervisor())
    }

    /// The handled mask of the sandbox's Landlock network grants, zero where
    /// it has none: what a network stack attaching here checks the kernel can
    /// enforce.
    #[cfg(all(feature = "hardening", feature = "netstack"))]
    pub(crate) fn landlock_net_handled(&self) -> u64 {
        self.inner
            .as_ref()
            .expect("a Pending holds its launch until proceed consumes it")
            .landlock_net_handled()
    }

    /// Releases the gated command and returns a handle to it.
    ///
    /// Blocks until the command is executing, so a setup failure past the gate
    /// — the identity switch, the hardening, the exec — is reported here as
    /// the same typed [`Error`] a direct [`spawn`](crate::Cage::spawn) would
    /// return. A failure before the gate was the pending launch's own. The
    /// command runs with the standard streams the pending launch was
    /// configured for; the returned [`Running`] waits for, signals, or kills
    /// it.
    pub fn proceed(mut self) -> Result<Running<'obs>, Error> {
        // Before the gate opens: a failure here drops the pending launch,
        // which tears it down.
        let ready = Readiness::new()?;
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
            std::mem::take(&mut self.placeholders),
            ready,
            self.cgroup.take(),
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

/// Kills the supervisor through its pidfd, and every process of the sandbox's
/// cgroup through `cgroup.kill` where the launch has one.
///
/// A supervisor that already exited is not an error. The kill flag is raised
/// only once the signal is known delivered, or moot, so an unexpected failure
/// cannot fabricate a killed outcome. The cgroup reaches what the supervisor's
/// death does not: without a PID namespace, the descendants that left the
/// command's process tree, whether the outcome is known yet or not.
fn send_kill(
    pidfd: &OwnedFd,
    kill_sent: &AtomicBool,
    cgroup: Option<&Cgroup>,
) -> Result<(), Error> {
    match process::pidfd_send_signal(pidfd, Signal::KILL) {
        Ok(()) | Err(Errno::SRCH) => kill_sent.store(true, Ordering::SeqCst),
        Err(errno) => return Err(signal_error(errno)),
    }
    cgroup.map_or(Ok(()), Cgroup::kill).map_err(signal_error)
}

fn signal_error(errno: Errno) -> Error {
    Error::Signal {
        source: errno.into(),
    }
}

#[cfg(test)]
mod tests {
    use ferroday_cage_testkit::fd::readable_by;
    use rustix::pipe::{PipeFlags, pipe_with};
    use rustix::process::{Pid, PidfdFlags};

    use super::*;
    use crate::mechanism::MountAction;
    use crate::observer::Progress;
    use crate::scratch::Scratch;

    /// A pidfd for `child`, a process this test started.
    fn pidfd_of(child: &std::process::Child) -> OwnedFd {
        let pid = Pid::from_raw(i32::try_from(child.id()).expect("a pid fits"))
            .expect("a process id is not zero");
        process::pidfd_open(pid, PidfdFlags::empty()).expect("a pidfd")
    }

    #[test]
    fn a_placeholder_goes_once_its_sandbox_is_gone_and_no_other_holds_it() {
        // Unlinking a name unmounts every bind onto it, in every mount
        // namespace, so a target goes only once the supervisor has exited and
        // no other sandbox holds the shared lock a bind onto it takes, and only
        // while the name still holds the file the launch created.
        let dir = Scratch::new("placeholder-guard");
        std::fs::create_dir(dir.join("etc")).expect("the scratch tree is writable");
        let target = dir.join("etc/target");
        let managed = ManagedPlaceholders {
            root: dir.path().to_path_buf(),
            paths: vec![PathBuf::from("etc/target")],
            whiteouts: Vec::new(),
        };
        let ops = [MountOp {
            dirs: Vec::new(),
            create_file: Some(c"etc/target".to_owned()),
            action: MountAction::Bind {
                source: c"/etc/hostname".to_owned(),
                target: c"etc/target".to_owned(),
                read_only: true,
            },
        }];
        let created_now = |path: &std::path::Path| {
            let file = rustix::fs::stat(path).expect("the target exists");
            [CreatedTarget {
                op: 0,
                ino: file.st_ino,
            }]
        };
        std::fs::write(&target, b"").expect("the target is creatable");
        let created = created_now(&target);

        // The supervisor still runs.
        let mut supervisor = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("a process to stand for the supervisor");
        let pidfd = pidfd_of(&supervisor);
        drop(PlaceholderGuard::of(
            &managed,
            &ops,
            &created,
            Some(pidfd.as_fd()),
        ));
        assert!(target.exists(), "removed while the supervisor ran");

        // The supervisor is gone, and another sandbox is bound onto the target.
        supervisor.kill().expect("the stand-in is killed");
        supervisor.wait().expect("the stand-in is reaped");
        let other = std::fs::File::open(&target).expect("the target opens");
        // The shared lock a sandbox bound onto the target holds, which is
        // what is under test rather than a lock file.
        #[expect(clippy::disallowed_methods)]
        let shared = rustix::fs::flock(&other, FlockOperation::LockShared);
        shared.expect("the lock is taken");
        drop(PlaceholderGuard::of(
            &managed,
            &ops,
            &created,
            Some(pidfd.as_fd()),
        ));
        assert!(target.exists(), "removed while another sandbox held it");
        drop(other);

        // Another file has taken the name: created before the old one went, so
        // it cannot reuse its inode.
        std::fs::write(dir.join("etc/replacement"), b"").expect("the scratch tree is writable");
        std::fs::rename(dir.join("etc/replacement"), &target).expect("the rename succeeds");
        drop(PlaceholderGuard::of(
            &managed,
            &ops,
            &created,
            Some(pidfd.as_fd()),
        ));
        assert!(target.exists(), "removed a file the launch did not create");

        // The file the launch created, its sandbox gone and nobody holding it.
        let created = created_now(&target);
        drop(PlaceholderGuard::of(
            &managed,
            &ops,
            &created,
            Some(pidfd.as_fd()),
        ));
        assert!(!target.exists(), "the launch's own target was left behind");
    }

    /// How many clock ticks a wait may use over the window below while it
    /// blocks. A spinning wait uses the whole window, a hundred and more.
    const IDLE_TICKS: u64 = 20;

    /// A reaped process's pidfd reports a hangup whatever is asked of it, and
    /// the pump holds the supervisor's for as long as it waits. Without a PID
    /// namespace the supervisor is reaped as soon as it exits, while a
    /// descendant may hold the captured output open long after. Waiting out
    /// that stream must block, not spin on the pidfd.
    #[test]
    fn a_wait_on_a_stream_that_outlives_the_supervisor_blocks() {
        // The supervisor: a process that exits and is reaped before the wait.
        let mut supervisor = std::process::Command::new("true")
            .spawn()
            .expect("a process to stand for the supervisor");
        let pid = Pid::from_raw(i32::try_from(supervisor.id()).expect("a pid fits"))
            .expect("a process id is not zero");
        let pidfd = process::pidfd_open(pid, PidfdFlags::empty()).expect("a pidfd");
        supervisor.wait().expect("the stand-in is reaped");

        // The outcome is already waiting in the status pipe.
        let (status, status_write) = pipe_with(PipeFlags::CLOEXEC).expect("a pipe");
        let record = mechanism::encode_status(mechanism::STATUS_EXITED, 0, None);
        rustix::io::write(&status_write, &record).expect("the record fits the pipe");
        drop(status_write);

        // A descendant's hold on standard output, released after the window.
        let window = Duration::from_millis(1500);
        let (stdout, stdout_write) = pipe_with(PipeFlags::CLOEXEC).expect("a pipe");
        let holder = std::thread::spawn(move || {
            std::thread::sleep(window);
            drop(stdout_write);
        });

        let (control, _peer) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket pair stands in for the control channel");
        let mut observer = |_: Progress| {};
        let mut running = Running::from_launched(
            mechanism::Launched {
                pidfd,
                pid: supervisor.id(),
                control,
                status,
                stdout: Some(stdout),
                stderr: None,
                reap: None,
                foreground: None,
            },
            Some(&mut observer),
            PlaceholderGuard::default(),
            Readiness::new().expect("an epoll set"),
            None,
        );

        let thread = rustix::thread::gettid().as_raw_nonzero().get();
        let before = ferroday_cage_testkit::process::thread_ticks(thread);
        let started = Instant::now();
        let outcome = running.wait().expect("the outcome is collected");
        let used = ferroday_cage_testkit::process::thread_ticks(thread) - before;
        holder.join().expect("the holder releases the stream");

        assert_eq!(outcome.code(), Some(0));
        assert!(
            started.elapsed() >= window - Duration::from_millis(100),
            "the wait returned before the stream closed"
        );
        assert!(
            used < IDLE_TICKS,
            "the wait spun: {used} ticks while the stream was held open"
        );
    }

    /// A wait whose deadline has already passed still serves what is ready,
    /// so repeating a zero wait collects an outcome waiting in the status pipe
    /// rather than reporting the deadline passed before reading anything.
    #[test]
    fn a_wait_whose_deadline_has_passed_serves_what_is_ready() {
        let mut supervisor = std::process::Command::new("true")
            .spawn()
            .expect("a process to stand for the supervisor");
        let pidfd = pidfd_of(&supervisor);
        supervisor.wait().expect("the stand-in is reaped");
        let (status, status_write) = pipe_with(PipeFlags::CLOEXEC).expect("a pipe");
        let record = mechanism::encode_status(mechanism::STATUS_EXITED, 3, None);
        rustix::io::write(&status_write, &record).expect("the record fits the pipe");
        drop(status_write);
        let (control, _peer) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket pair stands in for the control channel");
        let mut running = Running::from_launched(
            mechanism::Launched {
                pidfd,
                pid: supervisor.id(),
                control,
                status,
                stdout: None,
                stderr: None,
                reap: None,
                foreground: None,
            },
            None,
            PlaceholderGuard::default(),
            Readiness::new().expect("an epoll set"),
            None,
        );
        // One wait reads the record and the next sees the supervisor gone.
        let outcome = (0..3).find_map(|_| {
            running
                .wait_timeout(Duration::ZERO)
                .expect("the channels are served")
        });
        assert_eq!(outcome.and_then(|status| status.code()), Some(3));
    }

    /// A fork copies the descriptor table, so a process the caller forks while
    /// a sandbox runs, another launch's stage before its sweep among them,
    /// holds the sandbox's channels open after the handle has closed them. A
    /// channel the handle has finished with leaves the readiness set all the
    /// same, or the set reports it, hung up, for as long as the copy lives,
    /// and an event loop waiting on the set spins.
    #[test]
    fn a_closed_channel_leaves_the_readiness_set_while_a_copy_of_it_lives() {
        // The supervisor: a process that exits and is reaped before the wait.
        let mut supervisor = std::process::Command::new("true")
            .spawn()
            .expect("a process to stand for the supervisor");
        let pidfd = pidfd_of(&supervisor);
        supervisor.wait().expect("the stand-in is reaped");

        let (status, status_write) = pipe_with(PipeFlags::CLOEXEC).expect("a pipe");
        let (stdout, stdout_write) = pipe_with(PipeFlags::CLOEXEC).expect("a pipe");
        // What a concurrent fork holds: the channels' own open file
        // descriptions, under descriptors of its own.
        let copies = [&status, &stdout].map(|fd| fd.try_clone().expect("a duplicate"));

        let (control, _peer) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket pair stands in for the control channel");
        let mut collect = Collect::default();
        let mut running = Running::from_launched(
            mechanism::Launched {
                pidfd,
                pid: supervisor.id(),
                control,
                status,
                stdout: Some(stdout),
                stderr: None,
                reap: None,
                foreground: None,
            },
            Some(&mut collect),
            PlaceholderGuard::default(),
            Readiness::new().expect("an epoll set"),
            None,
        );
        let quiet = |running: &Running<'_>| {
            !readable_by(running, Instant::now() + Duration::from_millis(100))
        };

        // The command writes its output and closes it; its outcome is still
        // to come.
        rustix::io::write(&stdout_write, b"out").expect("the output fits the pipe");
        drop(stdout_write);
        for _ in 0..10 {
            if running.stdout.is_none() {
                break;
            }
            assert_eq!(running.try_wait().expect("the stream is served"), None);
        }
        assert!(running.stdout.is_none(), "the stream was never closed");
        assert!(quiet(&running), "the set reports the closed stream");

        // The outcome arrives, and the supervisor that sent it is gone.
        let record = mechanism::encode_status(mechanism::STATUS_EXITED, 0, None);
        rustix::io::write(&status_write, &record).expect("the record fits the pipe");
        drop(status_write);
        let deadline = Instant::now() + Duration::from_secs(10);
        let outcome = loop {
            if let Some(outcome) = running.try_wait().expect("the outcome is collected") {
                break outcome;
            }
            assert!(
                readable_by(&running, deadline),
                "the outcome went unreported"
            );
        };
        assert_eq!(outcome.code(), Some(0));
        assert!(
            quiet(&running),
            "the set reports a channel once the outcome is known"
        );
        drop(running);
        drop(copies);
        assert_eq!(collect.into_output(outcome, None).stdout, b"out");
    }
}
