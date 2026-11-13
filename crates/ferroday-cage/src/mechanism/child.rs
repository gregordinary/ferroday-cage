//! The post-fork stages: namespaces, sandbox setup, the command exec, and
//! the supervisor.
//!
//! A launch runs across a small tree of forked processes. Stage A is forked
//! from the caller and is short-lived: it scrubs the inherited signal state,
//! unshares the namespaces, sweeps the inherited descriptor table, replaces the
//! inherited session keyring, forks the next stage, and publishes that stage's
//! pidfd back to the caller over the control socket.
//!
//! With a PID namespace (the default), the process A forks is the sandbox
//! init — PID 1 inside the namespace. It performs the sandbox setup
//! (identity maps, hostname, loopback, the mount profile over a fresh
//! procfs, the pivot), forks the command as PID 2, and then supervises:
//! collecting orphaned descendants, forwarding termination requests,
//! watching the control socket for caller exit, and reporting the command's
//! wait status over the status pipe before exiting. Its exit tears the
//! namespace down, so processes the command left running are terminated by
//! the kernel.
//!
//! Without a PID namespace there is no init, and the command process is itself
//! the supervisor the caller's handle anchors on. Stage A forks that one
//! process, which performs the sandbox setup and becomes the command, and stays
//! outside as its parent until the outcome arrives.
//!
//! A restriction launch (the fallback for hosts without user namespaces)
//! takes the same outside-supervised shape, with the namespace and mount
//! work removed: stage A creates no namespaces, and the command process
//! changes its working directory, applies the hardening plan, and execs
//! against the host filesystem.
//!
//! A container's command process ends one user namespace deeper than the rest
//! of the sandbox. Between its resource limits and its hardening it enters a
//! nested user namespace, which is what locks the flags of every mount the
//! setup established — see [`enter_nested_namespace`]. Under a range map the
//! nested map is written by whichever process forked the command, over a gate
//! that process creates immediately before the fork; see
//! [`delegate_nested_map`].
//!
//! Everything here executes between [`sys::fork`] and `execve` or
//! `exit_group`. The caller may be multithreaded, so these processes —
//! single-threaded copies — must not:
//!
//! - allocate from the global allocator, whose lock may be held by a caller
//!   thread that does not exist in the copy;
//! - acquire any other lock, for the same reason;
//! - panic, since unwinding formats and allocates;
//! - call into libc or the thread runtime, whose state is stale in the
//!   copy.
//!
//! Every operation below is a raw syscall, through rustix or [`sys`], over
//! data frozen by the caller before the fork. The exception is a dropped
//! [`OwnedFd`], which the standard library closes through libc's `close`, an
//! async-signal-safe wrapper of the one syscall; the [`mechanism`](super)
//! documentation states why that is safe here.
//!
//! Mount targets are resolved against the new-root descriptor with
//! `openat2` and `RESOLVE_IN_ROOT`, so an absolute symlink inside the
//! rootfs resolves within the rootfs and cannot reach the host tree during
//! the pre-pivot window. The mount syscalls then address the resolved
//! descriptor through its `/proc/self/fd` path, formatted into a stack
//! buffer; the host `/proc` is still mounted at that point.

use std::convert::Infallible;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{self, Mode, OFlags, RawDir, ResolveFlags, StatVfsMountFlags};
use rustix::io::Errno;
use rustix::ioctl;
use rustix::mount::{self, MountFlags, MountPropagationFlags, UnmountFlags};
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use rustix::process::Pid;
use rustix::process::Signal;
use rustix::process::{self, PidfdFlags, WaitOptions, WaitStatus};
use rustix::thread;
use syscalls::Sysno;

use super::bounds::LINK_BUF;
use super::frame;
use super::resolve;
use super::seccomp;
use super::sys::{self, Disposition, How, SigSet};
use super::{
    IdentityPlan, LaunchPlan, MountAction, MountOp, RootPlan, STATUS_EXITED, STATUS_SIGNALED,
    StdioPlan, encode_status,
};
use crate::error::SetupStep;

/// Everything the stages touch: the frozen plan plus the pointer arrays,
/// identity-map lines, and channel descriptors assembled by the caller
/// immediately before the fork.
pub(super) struct Context<'a> {
    pub(super) plan: &'a LaunchPlan,
    /// NUL-terminated `argv` pointer array over `plan.program` and
    /// `plan.args`.
    pub(super) argv: &'a [*const u8],
    /// NUL-terminated `envp` pointer array over `plan.env`.
    pub(super) envp: &'a [*const u8],
    /// The single-identity uid map line, `0 <euid> 1`; empty for a range
    /// map, which is written by the caller's delegate instead.
    pub(super) uid_line: &'a [u8],
    /// The single-identity gid map line, `0 <egid> 1`; empty for a range
    /// map.
    pub(super) gid_line: &'a [u8],
    /// Write end of the report pipe.
    pub(super) report_fd: BorrowedFd<'a>,
    /// Write end of the status pipe.
    pub(super) status_fd: BorrowedFd<'a>,
    /// Sandbox end of the control socket.
    pub(super) control_fd: BorrowedFd<'a>,
    /// The shared `/dev/null` descriptor: the null stdin disposition and
    /// the supervisor's own stdio.
    pub(super) null_fd: BorrowedFd<'a>,
    /// Write end of the captured standard output, when observing.
    pub(super) capture_stdout_fd: Option<BorrowedFd<'a>>,
    /// Write end of the captured standard error, when observing.
    pub(super) capture_stderr_fd: Option<BorrowedFd<'a>>,
    /// Read end of the proceed pipe, when the launch is gated: the command
    /// stage blocks on it before `execve` until the caller releases it, the
    /// window in which a userspace network stack is attached.
    pub(super) proceed_fd: Option<BorrowedFd<'a>>,
    /// Stage A's end of the map gate, when a delegate writes the map: stage
    /// A signals ready on it after unsharing and blocks until the caller's
    /// delegate has established the identity map.
    pub(super) map_gate_fd: Option<BorrowedFd<'a>>,
    /// The caller-supplied standard input, when the plan names one: kept
    /// through the descriptor sweep and duplicated onto the command's file
    /// descriptor 0 alongside the capture pipes.
    pub(super) stdin_fd: Option<BorrowedFd<'a>>,
    /// The caller-supplied standard output, when the plan names one, on the
    /// same terms as [`stdin_fd`](Self::stdin_fd).
    pub(super) stdout_fd: Option<BorrowedFd<'a>>,
    /// The caller-supplied standard error, when the plan names one.
    pub(super) stderr_fd: Option<BorrowedFd<'a>>,
    /// The pseudoterminal to allocate, when this is a terminal launch: the first
    /// process of the sandbox proper allocates it once the root is in place,
    /// makes it the session's controlling terminal, and the command wires its
    /// replica onto all three standard streams.
    pub(super) terminal: Option<&'a crate::terminal::Terminal>,
    /// The sandbox end of the terminal channel, when this is a terminal launch:
    /// the primary of the pseudoterminal goes back to the caller over it.
    pub(super) terminal_channel_fd: Option<BorrowedFd<'a>>,
}

/// A failed setup step: the step, the errno, and the 1-based index of the
/// subject it was operating on within its own list — the mount op, the resource
/// limit, the Landlock rule — or zero when the step has no subject.
type Failure = (SetupStep, Errno, u32);

/// Stage A: the launch stage, forked directly from the caller.
///
/// Never returns: control ends in `execve` (via a later stage on this
/// process's path), `exit_group`, or the supervisor loop's exit.
pub(super) fn stage_a(context: &Context<'_>) -> ! {
    match run_stage_a(context) {
        Ok(never) => match never {},
        Err((step, errno, detail)) => {
            report(context.report_fd, step, errno, detail);
            sys::exit_group(127)
        }
    }
}

/// The launch stage proper. Returns only on failure, naming the step.
fn run_stage_a(context: &Context<'_>) -> Result<Infallible, Failure> {
    let plan = context.plan;

    // Scrub the inherited signal state first: every disposition back to the
    // default. The caller's ignored dispositions would survive exec into the
    // command (a Rust caller ignores SIGPIPE, for one), and an inherited signal
    // handler running inside these no-allocation processes would violate their
    // constraints. The fork left every signal blocked until here, so neither
    // can happen.
    //
    // Every signal the outside supervisor ignores stays blocked. This process
    // is in the caller's process group, and without a PID namespace it
    // outlives the setup as the command's supervisor, which must not end
    // because a signal was sent to that group. Blocked from the fork on, a
    // signal that arrives waits until the supervisor ignores it, which
    // discards it; see `ignore_outside_signals`.
    reset_signals(&SigSet::all().without(&SUPERVISOR_KEEPS))
        .map_err(|errno| (SetupStep::ResetSignals, errno, 0))?;

    // New namespaces, owned by the new user namespace, over which this
    // process holds full capabilities: the sandbox setup below is
    // unprivileged operations against namespaces this process owns. With a
    // PID namespace requested, this process stays outside it; the child
    // process forked next is its PID 1. A restriction creates no namespaces
    // at all — that is its defining degradation.
    if matches!(plan.confinement, super::Confinement::Container) {
        // SAFETY: `unshare_unsafe` is unsafe only because UnshareFlags::FILES
        // can invalidate file descriptors observed by other threads; the flags
        // frozen at build time never include the descriptor table, and this
        // process is a freshly forked single-threaded child process besides.
        unsafe { thread::unshare_unsafe(plan.unshare) }
            .map_err(|errno| (SetupStep::Unshare, errno, 0))?;
    }

    // Sweep the descriptor table down to the launch channels. The sandbox
    // stages are forked from the post-sweep table, so the command starts
    // with exactly its standard streams — no caller descriptor leaks into
    // the sandbox, and no caller resource is pinned by the supervisor for
    // the sandbox's lifetime. A caller's own `Stdio::Fd` descriptor is kept
    // here, because the command stage still has to copy it onto a standard
    // stream; `wire_stdio` marks it close-on-exec once it has, so it is gone
    // by the time the command image starts.
    sweep_fds(context).map_err(|errno| (SetupStep::SweepFds, errno, 0))?;

    // The session keyring, the one piece of the caller's session the sweep
    // cannot reach because it is a credential rather than a descriptor. Every
    // sandbox stage is forked from this process, so replacing it here replaces
    // it for all of them, in a restriction as in a container.
    replace_session_keyring().map_err(|errno| (SetupStep::ReplaceSessionKeyring, errno, 0))?;

    // Establish the identity map, after the sweep so the map gate survives
    // it, and before any further fork so every sandbox stage runs in a
    // fully mapped namespace. This stage is the process that unshared, so
    // its /proc/self map files name the new namespace.
    if matches!(plan.confinement, super::Confinement::Container) {
        establish_identity_map(context)?;
    }

    // Without a PID namespace this stage is the delegate for the command's
    // nested identity map, and the host's `/proc` is the procfs that indexes
    // it: the command shares this PID namespace, so the pid the fork below
    // returns names it there. Opened now rather than after the fork, because
    // the command's `pivot_root` acts on the mount namespace this stage shares
    // with it and would change what the path resolves to.
    let procfs = if !plan.pid_namespace && delegates_nested_map(context) {
        Some(
            rustix::fs::open(
                c"/proc",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|errno| (SetupStep::OpenSandboxProcfs, errno, 0))?,
        )
    } else {
        None
    };
    // The gate the map is established across, created immediately before the
    // fork so that this stage and the command are its only holders.
    let seam = nested_seam(procfs)?;

    let fork_step = if plan.pid_namespace {
        SetupStep::ForkInit
    } else {
        SetupStep::ForkCommand
    };
    // SAFETY: the child process continues with frozen data and raw syscalls
    // only, per this module's constraints, and never returns.
    match unsafe { sys::fork() }.map_err(|errno| (fork_step, errno, 0))? {
        sys::Fork::Child => {
            unblock_signals().map_err(|errno| (SetupStep::ResetSignals, errno, 0))?;
            if plan.pid_namespace {
                stage_init(context)
            } else {
                // The command keeps its own end of the gate and drops the
                // delegate's side of the seam, which is not its to hold.
                let gate = seam.map(|seam| {
                    drop(seam.procfs);
                    drop(seam.delegate);
                    seam.command
                });
                stage_command(context, gate)
            }
        }
        sys::Fork::ParentOf(child) => {
            // The terminal channel is for the stage just forked, which allocates
            // the terminal and sends the primary; this process has nothing to
            // send over it.
            if let Some(channel) = context.terminal_channel_fd {
                // SAFETY: the raw descriptor is this process's own copy of the
                // channel's sandbox end, closed exactly once here and never used
                // again in this process.
                unsafe { rustix::io::close(channel.as_raw_fd()) };
            }
            let pidfd = match publish_supervised(context, child) {
                Ok(pidfd) => pidfd,
                Err(errno) => {
                    // The caller never received the supervisor, so the
                    // just-forked process must not outlive this failure:
                    // kill and collect it before reporting, so it cannot
                    // run unsupervised or write a report record of its own.
                    abandon_command(child);
                    return Err((SetupStep::SendPidfd, errno, 0));
                }
            };
            // The nested map, established while the report pipe is still open
            // and a failure is still reportable. The seam drops with it, so
            // neither the procfs nor the gate outlives the step that needed
            // them.
            if let Some(seam) = seam {
                let NestedSeam {
                    procfs,
                    delegate,
                    command,
                } = seam;
                drop(command);
                if let Err(failure) =
                    delegate_nested_map(context, procfs.as_fd(), delegate.as_fd(), child)
                {
                    abandon_command(child);
                    return Err(failure);
                }
            }
            if plan.pid_namespace {
                // The init supervises itself from inside the namespace;
                // this stage's work is done.
                sys::exit_group(0)
            } else {
                supervisor_hygiene(context, Role::Outside);
                supervise(context, pidfd.as_fd(), child, Role::Outside)
            }
        }
    }
}

/// Opens the supervised process's pidfd and sends it, with the host pid as
/// payload, to the caller over the control socket.
fn publish_supervised(context: &Context<'_>, child: Pid) -> Result<OwnedFd, Errno> {
    let pidfd = process::pidfd_open(child, PidfdFlags::empty())?;
    let payload = child.as_raw_nonzero().get().to_le_bytes();
    frame::send_with_fd(context.control_fd, &payload, pidfd.as_fd())?;
    Ok(pidfd)
}

/// Starts a session of this sandbox's own, when the plan asks for one.
///
/// A controlling terminal is reached through the session rather than through
/// the filesystem, so neither a namespace nor a swapped root affects it: without
/// this, a sandbox whose caller redirected every standard stream can still open
/// the caller's terminal through `/dev/tty` — the character device `5:0`, whose
/// open returns whatever the opening process's controlling terminal is — read
/// what is typed at it, and push characters into its input queue with `TIOCSTI`
/// for the caller's shell to run afterwards. In a session of its own the sandbox
/// has no controlling terminal at all: `/dev/tty` fails with `ENXIO`, and
/// `TIOCSTI` is refused on every terminal descriptor, since the kernel grants it
/// only for the caller's own controlling terminal.
///
/// Called by the first process of the sandbox proper — the namespace init, or
/// the command stage where there is none — so the whole sandbox shares the
/// session and every process it starts inherits it. That process is a fresh
/// fork and so not a process group leader, which is the one thing that would
/// fail the call.
///
/// The plan asks for this exactly when the command does not inherit the
/// caller's standard input; see
/// [`LaunchPlan::own_session`](super::LaunchPlan::own_session). A terminal
/// launch asks for it too, whatever the plan says: the pseudoterminal must be
/// the controlling terminal of a session the sandbox owns, and the default
/// standard-input disposition would otherwise leave the launch in the caller's.
/// [`open_terminal`] takes that terminal later, once the root it is allocated
/// from is in place.
fn start_own_session(context: &Context<'_>) -> Result<(), Failure> {
    if context.plan.own_session || context.terminal.is_some() {
        process::setsid()
            .map(|_| ())
            .map_err(|errno| (SetupStep::NewSession, errno, 0))?;
    }
    Ok(())
}

/// Allocates the pseudoterminal of a terminal launch, makes it this session's
/// controlling terminal, and sends its primary to the caller, returning the
/// replica for the command. `None` for every other launch.
///
/// Called by the first process of the sandbox proper, after its setup: the init
/// where there is a PID namespace, and the command stage where there is none,
/// in a restriction as in a container. After the setup, because the
/// `/dev/ptmx` the allocation opens has to be the one the command will see,
/// which in a container exists only once the root is swapped. In this process,
/// because it is the session leader [`start_own_session`] made, and `TIOCSCTTY`
/// succeeds only for a session leader. With a PID namespace the command is a
/// fork of this process and not a leader itself, so the controlling terminal is
/// taken here, as a property of the session the command then inherits.
///
/// Under a [`run_as`](crate::CageBuilder::run_as) identity the replica is given
/// to that identity, as a login's terminal is given to the user logging in, so
/// the command can open its terminal by the path `ttyname` reports. Its mode is
/// the managed `devpts` instance's `0620`.
///
/// The controlling terminal is taken before the primary is sent, so the caller
/// never holds a terminal whose setup then failed. The primary and this
/// process's copy of the channel close once it is sent: the caller's end of the
/// primary is the only one, and end-of-file on it means the last replica closed.
fn open_terminal(context: &Context<'_>) -> Result<Option<OwnedFd>, Failure> {
    let (Some(terminal), Some(channel)) = (context.terminal, context.terminal_channel_fd) else {
        return Ok(None);
    };
    let (primary, replica) = crate::terminal::allocate(terminal)
        .map_err(|errno| (SetupStep::AllocateTerminal, errno, 0))?;
    if let Some(run_as) = &context.plan.run_as {
        fs::fchown(&replica, Some(run_as.uid), Some(run_as.gid))
            .map_err(|errno| (SetupStep::AllocateTerminal, errno, 0))?;
    }
    process::ioctl_tiocsctty(&replica)
        .map_err(|errno| (SetupStep::SetControllingTerminal, errno, 0))?;
    frame::send_with_fd(channel, &[super::TERMINAL_BYTE], primary.as_fd())
        .map_err(|errno| (SetupStep::SendTerminal, errno, 0))?;
    drop(primary);
    // SAFETY: the raw descriptor is this process's own copy of the channel's
    // sandbox end, closed exactly once here and never used again in this
    // process.
    unsafe { rustix::io::close(channel.as_raw_fd()) };
    Ok(Some(replica))
}

/// Stage init: PID 1 of the new PID namespace. Sets the sandbox up, forks
/// the command as PID 2, and supervises it from inside.
fn stage_init(context: &Context<'_>) -> ! {
    if let Err((step, errno, detail)) = start_own_session(context) {
        report(context.report_fd, step, errno, detail);
        sys::exit_group(127)
    }
    let procfs = match setup_sandbox(context) {
        Ok(procfs) => procfs,
        Err((step, errno, detail)) => {
            report(context.report_fd, step, errno, detail);
            sys::exit_group(127)
        }
    };
    let replica = match open_terminal(context) {
        Ok(replica) => replica,
        Err((step, errno, detail)) => {
            report(context.report_fd, step, errno, detail);
            sys::exit_group(127)
        }
    };
    // The gate the command's nested identity map is established across, created
    // immediately before the fork so that this process and the command are its
    // only holders.
    let seam = match nested_seam(procfs) {
        Ok(seam) => seam,
        Err((step, errno, detail)) => {
            report(context.report_fd, step, errno, detail);
            sys::exit_group(127)
        }
    };

    // SAFETY: as at every fork here: the child process touches only frozen
    // data and raw syscalls, and never returns.
    match unsafe { sys::fork() } {
        Err(errno) => {
            report(context.report_fd, SetupStep::ForkCommand, errno, 0);
            sys::exit_group(127)
        }
        Ok(sys::Fork::Child) => {
            if let Err(errno) = unblock_signals() {
                report(context.report_fd, SetupStep::ResetSignals, errno, 0);
                sys::exit_group(127)
            }
            // The command keeps its own end of the gate and drops the
            // delegate's side of the seam, which is not its to hold.
            let gate = seam.map(|seam| {
                drop(seam.procfs);
                drop(seam.delegate);
                seam.command
            });
            exec_command(context, gate, replica)
        }
        Ok(sys::Fork::ParentOf(command)) => {
            // The replica is the command's now. End-of-file on the caller's
            // primary waits for the last replica anywhere to close, so this
            // process drops its copy before it settles in to supervise, which
            // never returns and so never drops anything.
            drop(replica);
            // The command's pidfd is what lets the supervisor sleep in one
            // poll; opened before anything else so a failure is still
            // reportable.
            let pidfd = match process::pidfd_open(command, PidfdFlags::empty()) {
                Ok(pidfd) => pidfd,
                Err(errno) => {
                    report(context.report_fd, SetupStep::WatchCommand, errno, 0);
                    sys::exit_group(127)
                }
            };
            // The nested map, established while the report pipe is still open
            // and a failure is still reportable. The seam drops with it, so
            // neither the procfs nor the gate outlives the step that needed
            // them.
            if let Some(seam) = seam {
                let NestedSeam {
                    procfs,
                    delegate,
                    command: command_end,
                } = seam;
                drop(command_end);
                if let Err((step, errno, detail)) =
                    delegate_nested_map(context, procfs.as_fd(), delegate.as_fd(), command)
                {
                    abandon_command(command);
                    report(context.report_fd, step, errno, detail);
                    sys::exit_group(127)
                }
            }
            supervisor_hygiene(context, Role::Init);
            supervise(context, pidfd.as_fd(), command, Role::Init)
        }
    }
}

/// Kills and collects the command after the delegate failed to establish its
/// nested identity map, or after its supervisor could not be published.
///
/// Killed rather than released by closing the gate: the command would see
/// end-of-file and report a failure of its own, and a second failure in a pipe
/// whose protocol ends at the first is a report the caller cannot decode. The
/// command is blocked at the gate, or has not reached it, before it has run
/// anything of the caller's, so nothing is lost by ending it here.
///
/// The caller side's [`abandon_gated_child`](super::abandon_gated_child) does
/// the same for its own children, and is not reached for from here because its
/// reap goes through [`wait_for_exit`](super::wait_for_exit), whose
/// `unreachable!` is a panic path this process must not have. The pid needs no
/// pidfd: the command is this process's unreaped child process until the wait
/// below, so the number names nothing else.
fn abandon_command(command: Pid) {
    let _ = process::kill_process(command, Signal::KILL);
    let _ = frame::retry_on_intr!(process::waitpid(Some(command), WaitOptions::empty()));
}

/// Stage command without a PID namespace: setup and exec in one process,
/// supervised from outside by stage A. In a container the setup is the full
/// sandbox sequence; in a restriction there is nothing to build and only the
/// working directory changes.
fn stage_command(context: &Context<'_>, nested_gate: Option<OwnedFd>) -> ! {
    let setup = start_own_session(context).and_then(|()| match context.plan.confinement {
        // The setup opens no procfs here: without a PID namespace the delegate
        // for the nested map is the launch stage, outside, which holds the
        // host's own.
        super::Confinement::Container => setup_sandbox(context).map(|_| ()),
        #[cfg(feature = "hardening")]
        super::Confinement::Restriction => setup_restriction(context),
    });
    let replica = setup.and_then(|()| open_terminal(context));
    match replica {
        Ok(replica) => exec_command(context, nested_gate, replica),
        Err((step, errno, detail)) => {
            report(context.report_fd, step, errno, detail);
            sys::exit_group(127)
        }
    }
}

/// The restriction setup: no namespaces to configure and no root to swap —
/// only the working directory changes, resolved against the host filesystem,
/// before the hardening and the exec.
///
/// The root is the working directory a plan carrying none means, exactly as it
/// is for a cage: `validate_workdir` collapses `/` to no workdir at all, so an
/// absent one and an explicit `/` are the same request. A cage arrives there by
/// the unconditional `chdir` its pivot ends with, and a restriction pivots
/// nothing, so it says so here. Without it the command would inherit the
/// caller's own directory, which is a different command each time it is
/// launched from somewhere else.
#[cfg(feature = "hardening")]
fn setup_restriction(context: &Context<'_>) -> Result<(), Failure> {
    let workdir = match &context.plan.workdir {
        Some(workdir) => workdir.as_c_str(),
        None => c"/",
    };
    process::chdir(workdir).map_err(|errno| (SetupStep::ChdirWorkdir, errno, 0))?;
    Ok(())
}

/// Wires the command's standard streams and executes the command.
///
/// `nested_gate` is this process's end of the gate the sandbox's own delegate
/// established the nested identity map across, present only where a delegate
/// writes it; it is closed as the entry returns. `terminal` is the replica of a
/// terminal launch's pseudoterminal, wired onto all three standard streams.
///
/// Never returns: on success `execve` replaces the process image, and on
/// failure the step and errno are reported over the report pipe and the
/// process exits. The exit status of a failed stage is not meaningful to
/// the caller, which trusts the pipe record instead.
fn exec_command(
    context: &Context<'_>,
    nested_gate: Option<OwnedFd>,
    terminal: Option<OwnedFd>,
) -> ! {
    if let Err(errno) = wire_stdio(context, terminal.as_ref().map(AsFd::as_fd)) {
        report(context.report_fd, SetupStep::WireStdio, errno, 0);
        sys::exit_group(127)
    }

    // The launch gate, when the caller requested one: block until the caller
    // releases the command. This is the seam at which a userspace network
    // stack is attached to the sandbox's network namespace — the caller holds
    // the command here, joins the namespace and brings up its tap, then
    // proceeds. The wait is before the hardening layer so a seccomp filter
    // cannot deny the read that releases it. The caller is told the command is
    // here first: every namespace and mount is in place by now, so the
    // process it attaches to is the one the sandbox will run in.
    if let Some(proceed) = context.proceed_fd {
        report_held(context.report_fd);
        if let Err((step, errno)) = await_proceed(proceed) {
            report(context.report_fd, step, errno, 0);
            sys::exit_group(127)
        }
    }

    // The resource limits, applied before the hardening layer, so no seccomp
    // filter is installed yet that could deny the call. A soft limit may move
    // anywhere up to its hard limit, and a hard limit may only come down:
    // raising one needs CAP_SYS_RESOURCE in the initial user namespace, which
    // no sandbox holds. Each limit is inherited across `execve` and by every
    // process the command starts.
    if let Err((step, errno, detail)) = apply_rlimits(context) {
        report(context.report_fd, step, errno, detail);
        sys::exit_group(127)
    }

    // The nested user namespace, entered before anything below it and after
    // everything above it. Entering one has the kernel copy the mount tree and
    // lock every restriction it carries, which is what makes a read-only bind a
    // boundary rather than a default the command could remount away.
    //
    // The position is forced, not preferred. The kernel re-derives the whole
    // credential for the new namespace: securebits go back to the default with
    // the locked bit among them, the bounding set is refilled, and the
    // inheritable and ambient sets are cleared. Every restriction below is
    // therefore applied to the credential this call produces, and any applied
    // above it would be silently undone. The launch gate stays above so a
    // caller attaches its network stack against the namespaces it already
    // knows, and the resource limits with it: raising a hard limit needs
    // CAP_SYS_RESOURCE in the initial user namespace, which no sandbox holds at
    // any depth.
    if let Err((step, errno, detail)) = enter_nested_namespace(context, nested_gate) {
        report(context.report_fd, step, errno, detail);
        sys::exit_group(127)
    }

    // The network filter, wherever the sandbox has a network namespace of its
    // own: it refuses the routes out that a network namespace does not cover,
    // and it is not opt-in, since without it the namespace's isolation is not
    // what the network posture says it is. See `seccomp::NETWORK_FILTER`.
    //
    // Installed here, after the nested user namespace is entered: creating one
    // grants the CAP_SYS_ADMIN that an install without no-new-privileges
    // requires, and a launch sets no-new-privileges only where the hardening
    // layer asks for it. A filter survives every step below, including the
    // identity switch and the exec. Installed before the hardening layer, so a
    // caller's own policy stacks on top of it and, where both answer a syscall
    // with an errno, answers with its own.
    if seccomp::installs_network_filter(context.plan)
        && let Err(errno) = seccomp::install(seccomp::NETWORK_FILTER)
    {
        report(context.report_fd, SetupStep::InstallNetworkFilter, errno, 0);
        sys::exit_group(127)
    }

    // The opt-in hardening layer and the identity switch, applied last so
    // their restrictions bind the command and its descendants and nothing
    // else. The hardening wraps the switch: securebits, no-new-privileges,
    // and Landlock apply first (their syscalls and grant-path opens need the
    // root-inside credentials), then the switch itself, then the capability
    // drop and the seccomp filter — so the filter never governs the switch,
    // and the drop's bounding-set edit relies on the securebits having
    // preserved CAP_SETPCAP. Without the `hardening` feature only the
    // switch exists.
    #[cfg(feature = "hardening")]
    if let Err((step, errno, detail)) = super::harden::apply_pre_switch(&context.plan.hardening) {
        report(context.report_fd, step, errno, detail);
        sys::exit_group(127)
    }

    if let Err((step, errno)) = switch_identity(context) {
        report(context.report_fd, step, errno, 0);
        sys::exit_group(127)
    }

    #[cfg(feature = "hardening")]
    if let Err((step, errno, detail)) = super::harden::apply_post_switch(&context.plan.hardening) {
        report(context.report_fd, step, errno, detail);
        sys::exit_group(127)
    }

    // `execve` returns only on failure; on success it replaces the process
    // image and never comes back. With a path-lookup search list the candidates
    // are tried in turn; with no search list (the ordinary case) the single
    // program path is executed directly.
    let errno = if context.plan.program_search.is_empty() {
        // SAFETY: `argv` and `envp` are NUL-terminated pointer arrays whose
        // entries point into CStrings owned by the launch plan and the launch
        // frame, all of which outlive this call.
        unsafe {
            sys::execve(
                &context.plan.program,
                context.argv.as_ptr(),
                context.envp.as_ptr(),
            )
        }
    } else {
        exec_search(context)
    };
    report(context.report_fd, SetupStep::Exec, errno, 0);
    sys::exit_group(127)
}

/// Executes the path-lookup candidates in order, returning the errno to report
/// when none of them replaced the process image.
///
/// This is `execvp`'s discipline. `argv[0]` stays the bare command name while
/// the path argument varies, so the command sees the name it was invoked by. A
/// candidate that is merely absent — `ENOENT`, or one of the idiosyncratic ways
/// a network filesystem says the same thing — moves on to the next. `EACCES`
/// also moves on, but is remembered and outranks a later `ENOENT` in the report:
/// "found it, may not run it" is the more useful diagnosis than "not found".
///
/// Any other errno means a candidate was found and its execution failed on its
/// own terms (`ELOOP`, `ENOEXEC`, `ETXTBSY`), so it is reported at once rather
/// than masked by whatever the remaining candidates return. Unlike a shell, the
/// search does not retry an `ENOEXEC` candidate through an interpreter.
fn exec_search(context: &Context<'_>) -> Errno {
    let mut denied = false;
    let mut last = Errno::NOENT;
    for candidate in &context.plan.program_search {
        // SAFETY: `argv` and `envp` are NUL-terminated pointer arrays whose
        // entries point into CStrings owned by the launch plan and the launch
        // frame, all of which outlive this call; `candidate` is a CString in
        // the plan's own search list.
        last = unsafe { sys::execve(candidate, context.argv.as_ptr(), context.envp.as_ptr()) };
        match last {
            Errno::ACCESS => denied = true,
            // Not here, or a filesystem's roundabout way of saying so.
            Errno::NOENT | Errno::STALE | Errno::NOTDIR | Errno::NODEV | Errno::TIMEDOUT => {}
            // A candidate that exists and could not be run.
            _ => return last,
        }
    }
    if denied { Errno::ACCESS } else { last }
}

/// Applies the plan's frozen resource limits to this process, in order.
///
/// `prlimit64` against pid 0 is one raw syscall over values marshaled at build
/// time, so this respects the no-allocation discipline of the post-fork
/// stages. A failure names the 1-based index of the limit that failed, which
/// the caller resolves to the limit's label.
fn apply_rlimits(context: &Context<'_>) -> Result<(), Failure> {
    for (index, entry) in context.plan.rlimits.iter().enumerate() {
        process::setrlimit(entry.kernel, entry.limit).map_err(|errno| {
            (
                SetupStep::SetRlimit,
                errno,
                u32::try_from(index + 1).unwrap_or(0),
            )
        })?;
    }
    Ok(())
}

/// Redirects the command's standard streams per the plan: `/dev/null` for a
/// null disposition, a caller-supplied descriptor for a descriptor one, and the
/// capture pipes on the output pair when observing.
///
/// A capture pipe wins over the plan's own output disposition because the two
/// never coexist: the launch refuses an observer against a disposition that
/// names a destination of its own, so a plan reaching this point with a capture
/// pipe present carries `Inherit`, which names none.
///
/// `dup2` clears close-on-exec on its target as a side effect, which is what
/// lets the redirected stream survive `execve` while every original copy still
/// closes. A caller-supplied source is the one copy the sweep had to keep, so
/// it is marked close-on-exec here once it has been copied — see the end of the
/// body.
///
/// Every source is moved above the standard-stream numbers first, so no source
/// is ever also a target. Only a caller-supplied
/// [`StdioPlan::Fd`](super::StdioPlan::Fd) can be low — the launch creates six
/// descriptors of its own before the null descriptor and the capture pipes, and
/// the terminal replica is opened after all of them, so each lands at 3 or
/// above — and with three streams
/// to wire, a low one is not merely the `dup2(fd, fd)` no-op that leaves
/// close-on-exec set: wiring one stream would *destroy* the source another had
/// not been copied from yet. With standard input on the caller's descriptor 1
/// and standard output somewhere else, the `dup2` onto 1 would take standard
/// input's source with it.
///
/// The relocation covers the sources. It does not cover the launch's own
/// channels: a caller that had already closed one of 0, 1 and 2 when it called
/// `spawn` would have the report pipe, the status pipe, the control socket or
/// the nested identity map's gate land there, and the `dup2`s below would
/// clobber it in the command process. A `std` program cannot start in that
/// state — the runtime's startup opens `/dev/null` over any standard descriptor
/// that is closed — so this is reachable only for a consumer that closes one at
/// runtime. A terminal launch is the widest exposure, since it wires all three
/// streams where a capturing launch wires at most two.
fn wire_stdio(context: &Context<'_>, terminal: Option<BorrowedFd<'_>>) -> Result<(), Errno> {
    /// The highest standard stream number: the ceiling a source must be above
    /// before anything is wired, and the floor it is moved to.
    const STDERR: RawFd = 2;
    /// The descriptor a stream's plan names, or `None` where it names no
    /// destination and the launch leaves the inherited one in place.
    fn wired<'fd>(
        plan: &StdioPlan,
        caller: Option<BorrowedFd<'fd>>,
        null: BorrowedFd<'fd>,
    ) -> Option<BorrowedFd<'fd>> {
        match plan {
            StdioPlan::Inherit => None,
            StdioPlan::Null => Some(null),
            // The caller's descriptor, kept through the sweep and carried here.
            StdioPlan::Fd(_) => caller,
        }
    }
    // A terminal launch wires the replica onto all three: a terminal is one
    // stream, and saying so here is more honest than saying it in the observer
    // contract. Nothing contradicts it — the launch refuses a terminal against
    // any stated disposition, and the terminal entry points take no observer —
    // so this is a substitution rather than a precedence rule.
    let (stdin, stdout, stderr) = match terminal {
        Some(replica) => (Some(replica), Some(replica), Some(replica)),
        None => (
            wired(&context.plan.stdin, context.stdin_fd, context.null_fd),
            context
                .capture_stdout_fd
                .or_else(|| wired(&context.plan.stdout, context.stdout_fd, context.null_fd)),
            context
                .capture_stderr_fd
                .or_else(|| wired(&context.plan.stderr, context.stderr_fd, context.null_fd)),
        ),
    };
    // Move any source that sits on a standard-stream number above them, and wire
    // from the relocation instead. The copies are close-on-exec and are closed
    // as this function returns, which is after every `dup2` has taken what it
    // needs; the wired streams are separate descriptors and keep what they were
    // given.
    let mut moved: [Option<OwnedFd>; 3] = [None, None, None];
    for (slot, source) in moved.iter_mut().zip([stdin, stdout, stderr]) {
        if let Some(source) = source
            && source.as_raw_fd() <= STDERR
        {
            *slot = Some(rustix::io::fcntl_dupfd_cloexec(source, STDERR + 1)?);
        }
    }
    let stdin = moved[0].as_ref().map(AsFd::as_fd).or(stdin);
    let stdout = moved[1].as_ref().map(AsFd::as_fd).or(stdout);
    let stderr = moved[2].as_ref().map(AsFd::as_fd).or(stderr);

    if let Some(stdin) = stdin {
        rustix::stdio::dup2_stdin(stdin)?;
    }
    if let Some(stdout) = stdout {
        rustix::stdio::dup2_stdout(stdout)?;
    }
    if let Some(stderr) = stderr {
        rustix::stdio::dup2_stderr(stderr)?;
    }

    // The sweep kept the caller's own descriptors so the `dup2`s above had
    // something to copy from, and a caller holds one at whatever number it
    // happened to get — 21, say, well clear of the standard streams the sweep
    // also keeps. Copied onto 0, 1 or 2 and left otherwise alone, the original
    // would survive the exec at that number: the command would start holding a
    // second handle to the caller's file, one it keeps after closing and
    // reopening its standard output, and one neither the crate's "a descriptor
    // table holding only its standard streams" nor `sweep_fds_keeping`'s own
    // contract admits. Marking it close-on-exec closes it, and only it: the
    // `dup2` targets were cleared of the flag by the copy, and descriptor flags
    // are per-descriptor and this process's own since the fork, so the caller's
    // copy is untouched.
    for caller in [context.stdin_fd, context.stdout_fd, context.stderr_fd] {
        if let Some(caller) = caller
            && caller.as_raw_fd() > STDERR
        {
            rustix::io::fcntl_setfd(caller, rustix::io::FdFlags::CLOEXEC)?;
        }
    }
    Ok(())
}

/// Switches to the configured run-as identity, immediately before the
/// capability drop and `execve`.
///
/// The order is forced by the kernel: supplementary groups and the gid
/// first, while `CAP_SETGID` is effective, and the uid last, because after
/// it the gid is no longer settable. The groups call sets the run-as
/// identity's supplementary groups wherever the build froze a list. It froze
/// none where the gid map is the caller's own gid alone, the single-identity
/// map's gid map: the kernel and shadow's `newgidmap` both deny `setgroups`
/// when they write that map, and the build rejects a run-as identity that
/// names groups. The command then keeps the process's inherited
/// supplementary group list. That list grants nothing beyond what the caller
/// has on the host: the namespace's single-entry gid map presents every other
/// gid as the overflow gid, which is what bounds group membership there, not a
/// clearing call here.
///
/// All three calls are the thread-scoped raw syscalls: this process is
/// single-threaded, so no cross-thread broadcast is needed and none of
/// libc's setxid machinery is involved.
///
/// # No-new-privileges
///
/// Set here rather than only in the hardening layer, because it is what makes
/// the switch a boundary at all. Dropping to a non-zero uid clears the
/// command's capabilities, but on its own it leaves the privilege-raising path
/// through `execve` open: the rootfs bind inherits the host mount's flags
/// rather than adding `nosuid`, and the provisioners apply a tree's permission
/// bits verbatim, so a Debian or Alpine rootfs inside the sandbox ships
/// set-user-ID binaries owned by in-namespace uid 0 and file capabilities to
/// match. Without the flag, the non-root command executes them and is root
/// inside again.
///
/// It costs one `prctl`, needs no privilege, and is inherited across `execve`
/// and by every descendant. The hardening layer sets it too, before Landlock
/// and the seccomp install, which both require it; setting it twice is
/// idempotent, and doing it here is what covers a build without that feature
/// and a launch that asks for a non-root identity and nothing else.
///
/// A presented identity sets it too, and has no switch to make: the nested map
/// already gave the command that identity. There is no uid 0 inside for it to
/// return to, and the flag keeps a file capability from granting it anything
/// across `execve` either.
fn switch_identity(context: &Context<'_>) -> Result<(), (SetupStep, Errno)> {
    if context.plan.run_as.is_none() && context.plan.present_as.is_none() {
        return Ok(());
    }
    rustix::thread::set_no_new_privs(true).map_err(|errno| (SetupStep::SetNoNewPrivs, errno))?;
    let Some(run_as) = &context.plan.run_as else {
        return Ok(());
    };
    if let Some(groups) = &run_as.groups {
        rustix::thread::set_thread_groups(groups).map_err(|errno| (SetupStep::SetGroups, errno))?;
    }
    rustix::thread::set_thread_res_gid(Some(run_as.gid), Some(run_as.gid), Some(run_as.gid))
        .map_err(|errno| (SetupStep::SetGid, errno))?;
    rustix::thread::set_thread_res_uid(Some(run_as.uid), Some(run_as.uid), Some(run_as.uid))
        .map_err(|errno| (SetupStep::SetUid, errno))?;
    Ok(())
}

/// Blocks at the launch gate until the caller releases the command.
///
/// The caller writes one byte to proceed, or drops the write end to abandon
/// the launch. A byte is the go signal; end-of-file means the caller left
/// without proceeding, which is reported as a gate failure so the command
/// never runs unreleased.
fn await_proceed(fd: BorrowedFd<'_>) -> Result<(), (SetupStep, Errno)> {
    let mut byte = [0u8; 1];
    match frame::retry_on_intr!(rustix::io::read(fd, &mut byte)) {
        Ok(0) => Err((SetupStep::AwaitNetworkStack, Errno::CANCELED)),
        Ok(_) => Ok(()),
        Err(errno) => Err((SetupStep::AwaitNetworkStack, errno)),
    }
}

/// The child's side of the identity-map protocol: what a process that has
/// just unshared must do to have a map in force.
///
/// The caller's side is [`ChildMap`](super::ChildMap), which also names the
/// delegate a range map is applied by. That delegate runs in the caller, so
/// the child never sees it, and this is the whole of what the child does.
pub(super) enum MapDuty<'a> {
    /// Write the single-identity map in process.
    Write {
        /// Where the writing process's own map files are.
        paths: MapPaths<'a>,
        /// The `uid_map` line.
        uid_line: &'a [u8],
        /// The `gid_map` line.
        gid_line: &'a [u8],
    },
    /// Signal ready on the map gate and block until the delegate has written a
    /// range map from outside.
    Await,
}

/// Where a process finds the files that establish its own user namespace's
/// identity map.
///
/// Named rather than hardcoded because the nested user namespace a command
/// enters is mapped after the root swap, where the procfs is wherever the mount
/// profile put it. Every other caller writes through the host's `/proc`, which
/// [`SELF`](MapPaths::SELF) names.
#[derive(Clone, Copy)]
pub(super) struct MapPaths<'a> {
    /// The `setgroups` file, written `deny` before the gid map.
    pub(super) setgroups: &'a CStr,
    /// The `gid_map` file.
    pub(super) gid_map: &'a CStr,
    /// The `uid_map` file.
    pub(super) uid_map: &'a CStr,
}

impl MapPaths<'static> {
    /// The writing process's own map files, through the procfs at `/proc`.
    pub(super) const SELF: MapPaths<'static> = MapPaths {
        setgroups: c"/proc/self/setgroups",
        gid_map: c"/proc/self/gid_map",
        uid_map: c"/proc/self/uid_map",
    };
}

/// A step of a child's entry into a user namespace of its own.
///
/// Each caller names these steps in its own vocabulary — a launch reports a
/// [`SetupStep`], the provisioning children report their own — so the shared
/// sequence reports the step it reached and leaves the naming to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MapStep {
    /// Resetting the inherited signal dispositions.
    ResetSignals,
    /// Closing the inherited descriptors.
    SweepFds,
    /// Unsharing the user namespace.
    Unshare,
    /// Writing `deny` to `/proc/self/setgroups`.
    DenySetgroups,
    /// Writing the gid map.
    WriteGidMap,
    /// Writing the uid map.
    WriteUidMap,
    /// Signalling ready at the map gate, or waiting there.
    AwaitMap,
}

/// Why a child did not reach its mapped user namespace.
pub(super) enum MapFailure {
    /// A step failed with an OS error.
    Step(MapStep, Errno),
    /// The caller closed the map gate without applying the map: it abandoned
    /// this child, and its own error is the diagnostic. Nothing is reported
    /// back, because the gate that would carry the report is the thing that
    /// closed.
    Abandoned,
}

/// Takes a freshly forked child into a user namespace of its own, with the
/// identity map in force: the sequence every provisioning child performs
/// before it touches the tree it was forked for.
///
/// `keep` is the descriptors the child needs — its channels to the caller;
/// everything else the fork copied is closed. The sweep matters beyond
/// hygiene: a provisioning child runs for as long as the tree is large, and
/// an inherited copy of a live sandbox's control socket would hold that
/// sandbox's supervisor open for all of it, since hangup detection — the
/// whole of [`stop_with_caller`](crate::CageBuilder::stop_with_caller) —
/// waits on the last copy closing.
///
/// `SIGPIPE` is put back to ignored after the scrub, whose default for it is
/// termination: a child killed the instant the caller stopped reading could
/// neither report the failure nor exit on its own terms.
///
/// The namespace is the only thing unshared. The work runs on the caller's
/// own mount view, through real paths, as root of the mapped namespace.
///
/// Post-fork safe: no allocation, no locking, and no panic.
pub(super) fn enter_mapped_namespace(
    keep: &[RawFd],
    duty: MapDuty<'_>,
    gate: Option<BorrowedFd<'_>>,
) -> Result<(), MapFailure> {
    reset_signals(&SigSet::empty())
        .map_err(|errno| MapFailure::Step(MapStep::ResetSignals, errno))?;
    ignore_sigpipe().map_err(|errno| MapFailure::Step(MapStep::ResetSignals, errno))?;
    sweep_fds_keeping(keep).map_err(|errno| MapFailure::Step(MapStep::SweepFds, errno))?;
    // SAFETY: the flags never include the descriptor table, and this process
    // is a freshly forked single-threaded child besides.
    unsafe { thread::unshare_unsafe(thread::UnshareFlags::NEWUSER) }
        .map_err(|errno| MapFailure::Step(MapStep::Unshare, errno))?;
    establish_map(duty, gate)
}

/// Establishes a freshly unshared user namespace's identity map.
///
/// The single-identity map is written in process: denying `setgroups` first
/// is what permits an unprivileged process to write its own gid map, and the
/// one-id exception permits nothing more. Any range map is written from
/// outside by the caller's delegate — a process that has just unshared cannot
/// write its own range map even if it was privileged before, because
/// capabilities extend to a namespace's descendants and never to its
/// ancestors — so the child signals ready on the map gate and blocks until
/// the caller releases it.
///
/// For a range map `setgroups` stays at `allow`: that is what makes
/// supplementary groups (and a later `setgroups` inside) possible, and a
/// privileged delegate's gid-map write does not need the denial.
///
/// The gate is left open. What it is worth keeping differs by caller — a
/// launch closes it so no sandbox stage inherits it, a provisioning child
/// carries its outcome back over the same descriptor — so the decision stays
/// with them.
///
/// Post-fork safe: no allocation, no locking, and no panic.
pub(super) fn establish_map(
    duty: MapDuty<'_>,
    gate: Option<BorrowedFd<'_>>,
) -> Result<(), MapFailure> {
    match duty {
        MapDuty::Write {
            paths,
            uid_line,
            gid_line,
        } => {
            write_file(paths.setgroups, b"deny")
                .map_err(|errno| MapFailure::Step(MapStep::DenySetgroups, errno))?;
            write_file(paths.gid_map, gid_line)
                .map_err(|errno| MapFailure::Step(MapStep::WriteGidMap, errno))?;
            write_file(paths.uid_map, uid_line)
                .map_err(|errno| MapFailure::Step(MapStep::WriteUidMap, errno))?;
        }
        MapDuty::Await => {
            let Some(gate) = gate else {
                // Every caller pairs a delegated map with a gate; a missing
                // one is a defect reported as a bad descriptor, since this
                // process must not panic.
                return Err(MapFailure::Step(MapStep::AwaitMap, Errno::BADF));
            };
            frame::retry_on_intr!(rustix::io::write(gate, &[super::MAP_READY_BYTE]))
                .map_err(|errno| MapFailure::Step(MapStep::AwaitMap, errno))?;
            let mut byte = [0u8; 1];
            match frame::retry_on_intr!(rustix::io::read(gate, &mut byte)) {
                Ok(0) => return Err(MapFailure::Abandoned),
                Ok(_) => {}
                Err(errno) => return Err(MapFailure::Step(MapStep::AwaitMap, errno)),
            }
        }
    }
    Ok(())
}

/// Establishes the new user namespace's identity map, from stage A.
///
/// End-of-file on the gate means the caller abandoned the launch (its
/// delegate failed); the failure is reported for form, though the caller
/// prefers the delegate's own error. The gate descriptor is closed before the
/// stage forks, so no sandbox stage inherits it.
fn establish_identity_map(context: &Context<'_>) -> Result<(), Failure> {
    let ranged = matches!(context.plan.identity, IdentityPlan::Ranged { .. });
    let duty = if ranged {
        MapDuty::Await
    } else {
        // Stage A has not swapped its root, so the host's `/proc` is the one
        // its own map files are under.
        MapDuty::Write {
            paths: MapPaths::SELF,
            uid_line: context.uid_line,
            gid_line: context.gid_line,
        }
    };
    let outcome = establish_map(duty, context.map_gate_fd);
    if let (true, Some(gate)) = (ranged, context.map_gate_fd) {
        // SAFETY: the raw descriptor is this process's own gate end, closed
        // exactly once here and never used again in this process.
        unsafe { rustix::io::close(gate.as_raw_fd()) };
    }
    outcome.map_err(|failure| match failure {
        MapFailure::Abandoned => (SetupStep::AwaitIdentityMap, Errno::CANCELED, 0),
        MapFailure::Step(step, errno) => (setup_step(step), errno, 0),
    })
}

/// Enters the nested user namespace that locks the sandbox's mount flags, and
/// establishes its identity map.
///
/// A read-only bind is established by the sandbox setup inside the user
/// namespace that setup created, and the kernel locks a mount's flags only as
/// it copies the tree into a *new* user namespace. Root of the namespace that
/// owns a mount may lift any restriction on it, so before this call the command
/// could remount its own read-only bind read-write and write through to the
/// host. `CLONE_NEWUSER | CLONE_NEWNS` has the kernel perform the copy, and
/// every mount the command inherits comes across locked.
///
/// The map is the identity reflection of the sandbox's own, frozen at build
/// time, so nothing about the command's view of itself changes: it is the same
/// uid, with the same ids reachable, one namespace deeper. The single-identity
/// tier writes its own map under the kernel's one-id exception; a range map is
/// written by the sandbox's own delegate, because a process that has just
/// unshared cannot write its own range map and neither can anything outside the
/// namespace it unshared *from*.
///
/// `gate` is this process's end of the delegate's gate, closed as this returns.
///
/// Post-fork safe: no allocation, no locking, and no panic.
fn enter_nested_namespace(context: &Context<'_>, gate: Option<OwnedFd>) -> Result<(), Failure> {
    // A restriction creates no user namespace, so it has none to nest inside.
    let Some(nested) = &context.plan.nested else {
        return Ok(());
    };

    // SAFETY: as at every unshare here, the flags never include the descriptor
    // table, and this process is a single-threaded forked child besides.
    unsafe { thread::unshare_unsafe(thread::UnshareFlags::NEWUSER | thread::UnshareFlags::NEWNS) }
        .map_err(|errno| (SetupStep::NestedUnshare, errno, 0))?;

    let duty = match &nested.map {
        super::NestedMap::SelfWritten {
            setgroups_path,
            gid_map_path,
            uid_map_path,
        } => MapDuty::Write {
            // The root was swapped before this stage ran, so the map files are
            // named through the procfs the mount profile established.
            paths: MapPaths {
                setgroups: setgroups_path.as_c_str(),
                gid_map: gid_map_path.as_c_str(),
                uid_map: uid_map_path.as_c_str(),
            },
            uid_line: &nested.uid_lines,
            gid_line: &nested.gid_lines,
        },
        super::NestedMap::Delegated { .. } => MapDuty::Await,
    };
    establish_map(duty, gate.as_ref().map(AsFd::as_fd)).map_err(|failure| match failure {
        // The delegate closed the gate without writing: it failed, and reports
        // its own error over the report pipe. Named for form.
        MapFailure::Abandoned => (SetupStep::AwaitNestedIdentityMap, Errno::CANCELED, 0),
        MapFailure::Step(step, errno) => (nested_setup_step(step), errno, 0),
    })
    // `gate` drops here, which closes this end: the delegate is done with it,
    // and nothing past this point may hold a descriptor the command did not
    // ask for.
}

/// The [`SetupStep`] a launch reports for a map step performed against the
/// nested user namespace.
///
/// Named apart from the outer namespace's steps so a failure says which of the
/// two the launch was establishing. The two steps this sequence never performs
/// keep the outer names: the signal scrub and the descriptor sweep happened in
/// the launch stage, before the command existed.
fn nested_setup_step(step: MapStep) -> SetupStep {
    match step {
        MapStep::ResetSignals => SetupStep::ResetSignals,
        MapStep::SweepFds => SetupStep::SweepFds,
        MapStep::Unshare => SetupStep::NestedUnshare,
        MapStep::DenySetgroups => SetupStep::NestedDenySetgroups,
        MapStep::WriteGidMap => SetupStep::NestedWriteGidMap,
        MapStep::WriteUidMap => SetupStep::NestedWriteUidMap,
        MapStep::AwaitMap => SetupStep::AwaitNestedIdentityMap,
    }
}

/// The sandbox's side of the nested identity map: the procfs the command's map
/// files are reached through, and the gate the command waits at.
///
/// Created by the process that forks the command — the init inside the PID
/// namespace, or the launch stage where there is none — immediately before that
/// fork. Immediately, and by that process, for a reason the launch's own map
/// gate has to work around: a gate created before the caller's fork can be
/// inherited by any process the *consumer* forked in that window, so its
/// abandoned-child path cannot close the gate and must `SIGKILL` instead. This
/// one is created inside the sandbox and after the descriptor sweep, so it has
/// exactly two holders and end-of-file means what it says.
struct NestedSeam {
    /// The procfs the delegate writes the command's map files through.
    procfs: OwnedFd,
    /// The delegate's end of the gate.
    delegate: OwnedFd,
    /// The command's end of the gate.
    command: OwnedFd,
}

/// Creates the nested identity-map seam, when this process is the delegate for
/// one.
///
/// `procfs` is the descriptor the map files are reached through, already open:
/// the sandbox's own for the init, which opened it during setup through the
/// new-root descriptor, and the host's `/proc` for the launch stage, which
/// opened it before the pivot that would have changed what the path names.
/// `None` when the map needs no delegate — the single-identity tier, whose
/// command writes its own — or when there is no nested namespace at all.
fn nested_seam(procfs: Option<OwnedFd>) -> Result<Option<NestedSeam>, Failure> {
    let Some(procfs) = procfs else {
        return Ok(None);
    };
    let (delegate, command) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|errno| (SetupStep::NestedMapGate, errno, 0))?;
    Ok(Some(NestedSeam {
        procfs,
        delegate,
        command,
    }))
}

/// Whether this process is the delegate for the command's nested identity map,
/// and so must open a procfs to write it through.
fn delegates_nested_map(context: &Context<'_>) -> bool {
    matches!(
        &context.plan.nested,
        Some(nested) if matches!(nested.map, super::NestedMap::Delegated { .. })
    )
}

/// The rootfs-relative procfs target a delegate inside the sandbox writes the
/// command's map files through, or `None` where this stage is not that
/// delegate.
///
/// Only a delegated map inside a PID namespace has its delegate in here; a
/// self-written map has no delegate at all, and a delegated map without a PID
/// namespace is written by the launch stage, outside, through the host's own
/// `/proc`. The build composes a target for that one case and for no other, so
/// a `None` here is the same condition as the build having required no procfs.
fn nested_procfs_target<'a>(context: &'a Context<'_>) -> Option<&'a CStr> {
    if !context.plan.pid_namespace {
        return None;
    }
    match &context.plan.nested.as_ref()?.map {
        super::NestedMap::Delegated { procfs_target } => procfs_target.as_deref(),
        super::NestedMap::SelfWritten { .. } => None,
    }
}

/// Writes the command's nested identity map from inside the sandbox, releasing
/// the command once it is in force.
///
/// The kernel accepts a range map only from a process that is root of the
/// namespace the new one is a child of. The command cannot write its own, and
/// neither can the host caller, which owns the sandbox's user namespace but is
/// not inside it: this process is, and is its root, which is what qualifies it.
///
/// Nothing about the command is transmitted. The pid `fork` returned here
/// already indexes the same procfs both processes see — in-namespace pid 2
/// where the sandbox has a PID namespace, the host pid where it has none — so
/// the map files are named from what this process already knows.
///
/// End-of-file at the gate means the command died before it unshared. It
/// reported its own failure over the report pipe, so there is nothing to add
/// and nothing to write: supervision proceeds and collects its exit.
///
/// Post-fork safe: no allocation, no locking, and no panic.
fn delegate_nested_map(
    context: &Context<'_>,
    procfs: BorrowedFd<'_>,
    gate: BorrowedFd<'_>,
    command: Pid,
) -> Result<(), Failure> {
    let Some(nested) = &context.plan.nested else {
        return Ok(());
    };

    // The command is unshared and waiting.
    let mut byte = [0u8; 1];
    match frame::retry_on_intr!(rustix::io::read(gate, &mut byte)) {
        Ok(0) => return Ok(()),
        Ok(_) => {}
        Err(errno) => return Err((SetupStep::NestedMapGate, errno, 0)),
    }

    // The gid map before the uid map, which is the order `establish_map` writes
    // them in; neither ordering is forced for a privileged writer, and matching
    // the self-written path leaves one order to know. `setgroups` is left at
    // `allow` — a privileged writer needs no denial, and denying it would cost
    // the supplementary groups a run-as identity sets.
    let pid = command.as_raw_nonzero().get() as u32;
    for (file, lines, step) in [
        (
            &b"gid_map"[..],
            &nested.gid_lines,
            SetupStep::NestedWriteGidMap,
        ),
        (
            &b"uid_map"[..],
            &nested.uid_lines,
            SetupStep::NestedWriteUidMap,
        ),
    ] {
        write_map_file(procfs, pid, file, lines).map_err(|errno| (step, errno, 0))?;
    }

    // Release the command.
    frame::retry_on_intr!(rustix::io::write(gate, &[super::MAP_GO_BYTE]))
        .map(|_| ())
        .map_err(|errno| (SetupStep::NestedMapGate, errno, 0))
}

/// Writes one of another process's identity-map files, addressed relative to a
/// descriptor for the procfs that indexes it.
fn write_map_file(procfs: BorrowedFd<'_>, pid: u32, file: &[u8], data: &[u8]) -> Result<(), Errno> {
    let path = map_file_path(pid, file);
    let fd = fs::openat(
        procfs,
        path.as_cstr(),
        OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    frame::write_whole(fd.as_fd(), data)
}

/// The [`SetupStep`] a launch reports for a shared map step.
fn setup_step(step: MapStep) -> SetupStep {
    match step {
        MapStep::ResetSignals => SetupStep::ResetSignals,
        MapStep::SweepFds => SetupStep::SweepFds,
        MapStep::Unshare => SetupStep::Unshare,
        MapStep::DenySetgroups => SetupStep::DenySetgroups,
        MapStep::WriteGidMap => SetupStep::WriteGidMap,
        MapStep::WriteUidMap => SetupStep::WriteUidMap,
        MapStep::AwaitMap => SetupStep::AwaitIdentityMap,
    }
}

/// The sandbox setup sequence: the identity-dependent namespace
/// configuration through the root swap. The identity map itself is already
/// established — by stage A, before this stage was forked.
///
/// Returns a descriptor for the sandbox's procfs when this stage is the
/// delegate for the command's nested identity map, and `None` otherwise. It is
/// opened here, through the new-root descriptor and with the same
/// `RESOLVE_IN_ROOT` discipline every mount target gets, because here is the
/// last moment at which nothing else could be mounted over it: the command does
/// not exist yet, and once it does it shares this mount namespace until it
/// unshares one of its own.
fn setup_sandbox(context: &Context<'_>) -> Result<Option<OwnedFd>, Failure> {
    let plan = context.plan;

    // The UTS namespace is always new; the hostname changes only when one
    // was configured.
    if let Some(hostname) = &plan.hostname {
        rustix::system::sethostname(hostname.to_bytes())
            .map_err(|errno| (SetupStep::SetHostname, errno, 0))?;
    }

    // In an isolated network namespace the only interface is loopback,
    // which starts down; bring it up so the sandbox can talk to itself.
    if plan.configure_loopback {
        bring_up_loopback().map_err(|errno| (SetupStep::ConfigureLoopback, errno, 0))?;
    }

    // Make the inherited mount tree recursively private: nothing done below
    // propagates back to the host, and pivot_root refuses shared parents.
    mount::mount_change(
        c"/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(|errno| (SetupStep::PrivatizeMounts, errno, 0))?;

    // pivot_root requires the new root to be a mount point. A plain cage binds
    // the rootfs onto itself; an overlay-rooted cage mounts an overlay over the
    // rootfs, whose own directory is the overlay's read-only lower, so writes
    // land in the disposable upper and the base stays pristine. Either way the
    // canonical path frozen at build time is resolved here, inside the new
    // namespace: `mount` refuses sources and targets whose mounts are not
    // attached in the caller's namespace, so a descriptor opened before
    // `unshare` cannot anchor this step. The overlay mounts as root inside the
    // now-established identity map, so its copy-up ownership resolves against
    // that map. An empty root has no path; see `mount_empty_root`.
    //
    // Each root carries `nosuid`; see `nosuid_root`. An overlay and an empty
    // root take it at their own mount, where the flag applies directly and no
    // fallback is needed; a bind inherits its source's flags instead and has
    // the attribute added once there is a descriptor for the mount to add it
    // to, before the profile's own mounts, so the recursion covers the root
    // bind and whatever it carried along and nothing the caller went on to
    // mount: a caller's bind keeps its source's flags.
    //
    // The descriptor anchors both the mount-target resolution below and the
    // pivot. Opening a path root anew lands on top of the mount stack, the new
    // mount.
    let newroot = match &plan.root {
        RootPlan::Bind(rootfs) => {
            mount::mount_bind_recursive(rootfs, rootfs)
                .map_err(|errno| (SetupStep::BindRootfs, errno, 0))?;
            let newroot = open_root(rootfs)?;
            nosuid_root(newroot.as_fd()).map_err(|errno| (SetupStep::NosuidRootfs, errno, 0))?;
            newroot
        }
        RootPlan::Overlay { base, overlay } => {
            mount::mount(
                c"overlay",
                base.as_c_str(),
                c"overlay",
                MountFlags::NOSUID,
                overlay.options.as_c_str(),
            )
            .map_err(|errno| (SetupStep::MountOverlayRoot, errno, 0))?;
            open_root(base)?
        }
        RootPlan::Empty => {
            mount_empty_root().map_err(|errno| (SetupStep::MountEmptyRoot, errno, 0))?
        }
        // A sandbox's plan always names a root to pivot into, and a
        // restriction's never reaches this stage.
        RootPlan::Host => return Err((SetupStep::EnterRootfs, Errno::INVAL, 0)),
    };

    // The mount profile: host bind sources are still resolvable (the host
    // tree is mounted until the pivot), and every target resolves inside
    // the new root.
    for (index, op) in plan.ops.iter().enumerate() {
        execute_op(newroot.as_fd(), op, index, context.report_fd)
            .map_err(|(step, errno)| (step, errno, index as u32 + 1))?;
    }

    // The procfs the command's nested identity map will be written through,
    // opened only where this stage is the delegate for it. The mount profile
    // has just established it, and the build refused a profile that establishes
    // none for a configuration that reaches here.
    let procfs = match nested_procfs_target(context) {
        Some(target) => Some(
            open_in_root(newroot.as_fd(), target, OFlags::RDONLY | OFlags::DIRECTORY)
                .map_err(|errno| (SetupStep::OpenSandboxProcfs, errno, 0))?,
        ),
        None => None,
    };

    // Last of all, once nothing more is made in it.
    if matches!(plan.root, RootPlan::Empty) {
        read_only_root(newroot.as_fd())
            .map_err(|errno| (SetupStep::ReadOnlyEmptyRoot, errno, 0))?;
    }

    process::fchdir(&newroot).map_err(|errno| (SetupStep::EnterRootfs, errno, 0))?;

    // The pivot-into-self idiom: with new_root and put_old both `.`, the old
    // root is stacked on the same mount point, where it can be lazily
    // detached — no put_old directory is imposed on the rootfs.
    process::pivot_root(c".", c".").map_err(|errno| (SetupStep::PivotRoot, errno, 0))?;
    mount::unmount(c".", UnmountFlags::DETACH)
        .map_err(|errno| (SetupStep::DetachOldRoot, errno, 0))?;
    process::chdir(c"/").map_err(|errno| (SetupStep::ChdirNewRoot, errno, 0))?;

    // The working directory, resolved inside the sandbox after the pivot.
    if let Some(workdir) = &plan.workdir {
        process::chdir(workdir.as_c_str()).map_err(|errno| (SetupStep::ChdirWorkdir, errno, 0))?;
    }

    Ok(procfs)
}

/// Who the supervisor is relative to the sandbox.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// PID 1 inside the sandbox's PID namespace. Its own exit tears the
    /// namespace down.
    Init,
    /// The launch stage outside the sandbox, when no PID namespace was
    /// requested: the command's parent, which collects its outcome.
    Outside,
}

/// Detaches the supervisor from the caller's streams before the long watch:
/// the report-pipe copy closes (the exec convention needs every copy gone),
/// the capture-pipe copies close (their end-of-file must track the command,
/// not this process), a caller-supplied standard stream closes (the supervisor
/// must not pin a caller resource for the sandbox's lifetime), stdio repoints
/// at `/dev/null` (a pipeline reading the caller's stdout must not wait for the
/// supervisor), and SIGPIPE becomes ignored so a status write after the handle
/// is dropped fails with `EPIPE` instead of killing the supervisor. Outside the
/// sandbox, every signal the supervisor does not need becomes ignored too; see
/// [`ignore_outside_signals`].
///
/// A terminal launch's replica is not among these. The only supervisor that
/// ever held one is the init, which allocated it and drops it itself before it
/// supervises; the launch stage never did. Dropping it costs the session
/// nothing: the controlling-terminal association `TIOCSCTTY` established is a
/// property of the session and survives every descriptor to the terminal
/// closing.
///
/// Everything here is best-effort: past this point there is no report pipe
/// to fail through, and none of these operations can fail in a way that
/// compromises supervision.
fn supervisor_hygiene(context: &Context<'_>, role: Role) {
    // SAFETY: these raw descriptors are this process's own copies of the
    // launch channels, closed exactly once here and never used again in
    // this process.
    unsafe {
        rustix::io::close(context.report_fd.as_raw_fd());
        if let Some(stdout) = context.capture_stdout_fd {
            rustix::io::close(stdout.as_raw_fd());
        }
        if let Some(stderr) = context.capture_stderr_fd {
            rustix::io::close(stderr.as_raw_fd());
        }
        // The caller-supplied standard streams, each if it landed anywhere but
        // on the standard-stream numbers the repoint below covers. One
        // descriptor may serve more than one stream — a caller is free to hand
        // the same open file to standard output and standard error — so a
        // number already closed here is skipped rather than closed twice, which
        // would risk closing whatever the kernel had since handed that number
        // to.
        let caller = [context.stdin_fd, context.stdout_fd, context.stderr_fd]
            .map(|fd| fd.map_or(-1 as RawFd, |fd| fd.as_raw_fd()));
        for index in 0..caller.len() {
            let fd = caller[index];
            if fd > 2 && !caller[..index].contains(&fd) {
                rustix::io::close(fd);
            }
        }
    }
    let _ = rustix::stdio::dup2_stdin(context.null_fd);
    let _ = rustix::stdio::dup2_stdout(context.null_fd);
    let _ = rustix::stdio::dup2_stderr(context.null_fd);
    // SAFETY: the null descriptor's job ends with the stdio repoint above;
    // closed exactly once and never used again in this process.
    unsafe { rustix::io::close(context.null_fd.as_raw_fd()) };
    let _ = ignore_sigpipe();
    if role == Role::Outside {
        let _ = ignore_outside_signals();
    }
}

/// The signals the outside supervisor leaves at their defaults, where it
/// ignores every other.
///
/// `SIGCHLD`, because its disposition decides who reaps the supervisor's
/// children: ignored, the kernel would collect the command itself, and the
/// supervisor's wait would never see its status. And the signals that report
/// this process's own failure: the faults the kernel raises on an instruction
/// it executes, which it delivers whatever the disposition, and `SIGABRT`.
/// `SIGKILL` and `SIGSTOP` take no disposition at all. Another process can
/// therefore still end this one by sending it one of these, as it can with
/// `SIGKILL`.
const SUPERVISOR_KEEPS: [Signal; 8] = [
    Signal::CHILD,
    Signal::SEGV,
    Signal::BUS,
    Signal::ILL,
    Signal::FPE,
    Signal::TRAP,
    Signal::SYS,
    Signal::ABORT,
];

/// Ignores every signal but [`SUPERVISOR_KEEPS`], then unblocks them all: the
/// outside supervisor's immunity, the one the init has as PID 1.
///
/// The init is immune by construction. A namespace's PID 1 is never sent a
/// signal it has left at the default, from inside the namespace or above it,
/// except `SIGKILL` and `SIGSTOP` from above. The launch stage, supervising from
/// outside, is an ordinary member of the caller's process group, and a signal
/// sent to that group would end it as it ends the caller: an interrupt typed at
/// the caller's terminal, a hangup, a shell's `kill %1`. Its command, in a
/// session of its own whenever it does not inherit the caller's standard input,
/// would then run on unsupervised: never stopped by
/// [`stop_with_caller`](crate::CageBuilder::stop_with_caller), and its outcome
/// never reported.
///
/// The library itself never signals this process to make it act. A termination
/// request and the caller's exit reach it over the control socket, and a kill
/// goes to the command through the command's pidfd. Only the teardown of a
/// launch being given up on ends it, with `SIGKILL`, which no disposition
/// stops.
///
/// Ignored only here, after the command was forked, because an ignored
/// disposition survives `execve` and the command must start with every one at
/// its default. The launch stage has kept them blocked since its own fork, so
/// one that arrived meanwhile is pending, and ignoring it discards it: there is
/// no moment at which one reaches this process at the default.
fn ignore_outside_signals() -> Result<(), Errno> {
    for number in 1..=64 {
        // SAFETY: the numbers are non-zero and within the kernel's signal
        // range on every architecture.
        let signal = unsafe { Signal::from_raw_unchecked(number) };
        if signal == Signal::KILL || signal == Signal::STOP || SUPERVISOR_KEEPS.contains(&signal) {
            continue;
        }
        match sys::set_disposition(signal, Disposition::Ignore) {
            // Numbers the kernel reserves are skipped, as the reset skips them.
            Ok(()) | Err(Errno::INVAL) => {}
            Err(errno) => return Err(errno),
        }
    }
    // SAFETY: every signal unblocked here was just ignored or keeps its
    // default, so unblocking it runs no handler; the process is
    // single-threaded.
    unsafe { sys::sigprocmask(How::SetMask, Some(&SigSet::empty())) }?;
    Ok(())
}

/// Empties the signal mask of a process the launch stage or the init just
/// forked.
///
/// [`sys::fork`] leaves every signal blocked in the child process. The
/// dispositions it inherited are its parent process's, which
/// [`reset_signals`] put back to the default and which nothing has set since,
/// so unblocking runs nothing: the init and the command start with the empty
/// mask a process ordinarily has.
fn unblock_signals() -> Result<(), Errno> {
    // SAFETY: every disposition is the default, so unblocking runs no handler;
    // the process is single-threaded and freshly forked.
    unsafe { sys::sigprocmask(How::SetMask, Some(&SigSet::empty())) }.map(|_| ())
}

/// Ignores `SIGPIPE`, so a write to a channel whose reader is gone fails with
/// `EPIPE` rather than terminating the process.
///
/// [`reset_signals`] puts every disposition back to the default, which for
/// `SIGPIPE` is termination. A process that keeps writing to the caller after
/// that — the supervisor with its status record, and each helper child with its
/// frame stream or outcome record — needs the errno instead: its write paths are
/// written to observe a failed write, report what they can, and end on their own
/// terms. Restored here rather than left out of the scrub, so the window between
/// the two carries no inherited disposition at all.
pub(super) fn ignore_sigpipe() -> Result<(), Errno> {
    sys::set_disposition(Signal::PIPE, Disposition::Ignore)
}

/// How often the in-namespace init wakes to collect orphaned descendants.
const REAP_TICK: Timespec = Timespec {
    tv_sec: 1,
    tv_nsec: 0,
};

/// The supervisor loop: reap, forward, watch, report.
///
/// Sleeps in one poll over the control socket and the supervised process's
/// pidfd. Control traffic is a termination request (SIGTERM to the command)
/// or a hangup — the caller exited or dropped the last handle — which stops
/// the sandbox when `stop_with_caller` is set and is otherwise ignored.
/// When the supervised process exits, its wait status goes out over the
/// status pipe and the supervisor exits; as namespace init, that exit makes
/// the kernel kill every remaining namespace member.
///
/// Zombies are collected on every wake. As init, the poll also wakes on
/// [`REAP_TICK`]: an orphaned descendant reparents to the init and its exit
/// raises no poll event of its own, so the tick bounds how long its zombie
/// can linger — without it, a long-lived sandbox whose command keeps
/// orphaning children would accumulate zombies until the command exited.
fn supervise(context: &Context<'_>, pidfd: BorrowedFd<'_>, child: Pid, role: Role) -> ! {
    // Outside the namespace no tick is needed: the supervised command is
    // the only child this process can ever have, and orphans reparent to
    // the host init, not here.
    let timeout = match role {
        Role::Init => Some(&REAP_TICK),
        Role::Outside => None,
    };
    let mut watch_control = true;
    loop {
        // The pidfd entry is always last, so its readiness index is stable
        // whether or not the control socket is still watched.
        let mut fds = [
            PollFd::new(&context.control_fd, PollFlags::IN),
            PollFd::new(&pidfd, PollFlags::IN),
        ];
        let watched = if watch_control {
            &mut fds[..]
        } else {
            &mut fds[1..]
        };
        match rustix::event::poll(watched, timeout) {
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            // An unpollable descriptor set has no recovery; exit visibly.
            // As init the exit also tears the namespace down.
            Err(_) => sys::exit_group(127),
        }

        let control_ready = watch_control && !fds[0].revents().is_empty();

        if control_ready {
            let mut byte = [0u8; 1];
            match rustix::io::read(context.control_fd, &mut byte) {
                // Hangup: every caller-side handle is gone.
                Ok(0) => {
                    if context.plan.stop_with_caller {
                        match role {
                            // Init's exit has the kernel kill the whole
                            // namespace; no status is reported, and there
                            // is no one to report to.
                            Role::Init => sys::exit_group(1),
                            // From outside, kill the command and keep
                            // supervising: its exit is still collected.
                            Role::Outside => {
                                let _ = process::kill_process(child, Signal::KILL);
                                watch_control = false;
                            }
                        }
                    } else {
                        watch_control = false;
                    }
                }
                Ok(_) => {
                    if byte[0] == CONTROL_TERMINATE {
                        // Termination is a request to the command, not the
                        // namespace: SIGTERM is deliverable and trappable
                        // there, docker-stop style. ESRCH means it already
                        // exited; the pidfd wake handles the rest.
                        let _ = process::kill_process(child, Signal::TERM);
                    }
                }
                Err(Errno::INTR) => {}
                Err(_) => watch_control = false,
            }
        }

        // Collect zombies on every wake — control traffic, the tick, or
        // the supervised process's exit, which ends supervision: its wait
        // status goes out over the status pipe.
        //
        // `wait` rather than `waitpid(None, ...)`: rustix renders the latter as
        // pid 0, which is "any child in *this process's* process group" and not
        // the "any child" this loop needs. The supervised process leaves that
        // group whenever the sandbox has a session of its own, and a command
        // free to call `setsid` itself can leave it at any time; either way a
        // group-scoped wait answers `ECHILD` for a child that is sitting there
        // exited, and the loop below reads that as "something else reaped it"
        // and exits without a status.
        loop {
            match process::wait(WaitOptions::NOHANG) {
                Ok(Some((pid, status))) if pid == child => {
                    collect_exited();
                    report_status(context.status_fd, status);
                    sys::exit_group(0)
                }
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(Errno::INTR) => continue,
                // No children left yet no status for the supervised
                // process: something else reaped it. Unreportable;
                // exiting without a record surfaces as a lost
                // supervisor.
                Err(_) => sys::exit_group(127),
            }
        }
    }
}

/// The control-socket request byte for graceful termination.
pub(crate) const CONTROL_TERMINATE: u8 = b'T';

/// Collects every child process that has already exited, without waiting for
/// one that has not.
///
/// Called once the command's own exit is collected, so the usage the status
/// record reports includes what the rest of the sandbox finished before then.
/// As the init, those are the orphans that reparented to it since its last
/// wake; outside the sandbox the command was the only child, and nothing is
/// left.
fn collect_exited() {
    loop {
        match process::wait(WaitOptions::NOHANG) {
            Ok(Some(_)) | Err(Errno::INTR) => {}
            Ok(None) | Err(_) => return,
        }
    }
}

/// Writes the status record: the command's outcome, and what the command and
/// the descendants this process collected used, as
/// [`STATUS_RECORD_LEN`](super::STATUS_RECORD_LEN) lays it out.
///
/// A failed write means the caller dropped the handle; with SIGPIPE ignored it
/// is an `EPIPE` to swallow, since there is no one left to report to.
fn report_status(fd: BorrowedFd<'_>, status: WaitStatus) {
    let (kind, value) = if let Some(code) = status.exit_status() {
        (STATUS_EXITED, code)
    } else if let Some(signal) = status.terminating_signal() {
        (STATUS_SIGNALED, signal)
    } else {
        // Neither exited nor signaled cannot describe a reaped process;
        // exit without a record rather than invent one.
        sys::exit_group(127)
    };
    // A failure reports the outcome without usage rather than losing it.
    let usage = sys::children_usage().ok();
    let record = encode_status(kind, value, usage.as_ref());
    let _ = rustix::io::write(fd, &record);
}

/// Resets every signal disposition to the default, then replaces the signal
/// mask with `blocked`.
///
/// The order matters. A fork carries the caller's handlers into the child
/// process, and [`sys::fork`] hands it a mask that blocks every signal so that
/// none of them can run before this call. Changing the mask first would open a
/// window in which a *newly delivered* signal — a process-group signal, a
/// terminal's `SIGWINCH`, an inherited interval timer — runs one of those
/// handlers inside a process that must not allocate, take a lock, or panic.
/// Resetting the dispositions first leaves nothing to run when the mask comes
/// off.
pub(super) fn reset_signals(blocked: &SigSet) -> Result<(), Errno> {
    for number in 1..=64 {
        if number == Signal::KILL.as_raw() || number == Signal::STOP.as_raw() {
            continue;
        }
        // SAFETY: the numbers are non-zero and within the kernel's signal
        // range on every architecture.
        let signal = unsafe { Signal::from_raw_unchecked(number) };
        match sys::set_disposition(signal, Disposition::Default) {
            Ok(()) => {}
            // Numbers the kernel reserves are skipped, not errors.
            Err(Errno::INVAL) => {}
            Err(errno) => return Err(errno),
        }
    }
    // SAFETY: replacing the whole mask neither unblocks a signal mid-handler
    // nor races other threads; this process is single-threaded and freshly
    // forked, and after the loop above has no inherited handler to run.
    unsafe { sys::sigprocmask(How::SetMask, Some(blocked)) }?;
    Ok(())
}

/// Closes every descriptor the launch does not own.
///
/// Keeps the standard streams (the command may inherit them) and the launch
/// channels; [`sweep_fds_keeping`] does the work.
fn sweep_fds(context: &Context<'_>) -> Result<(), Errno> {
    // The kept set is the channel list mapped one for one, so it is exactly
    // as long as the list itself: adding a channel here cannot overrun a
    // separately sized buffer, which in this no-panic process would be a
    // fatal, unwinding, allocating way to fail. An absent channel becomes
    // `-1`, a number no `/proc/self/fd` entry can name, so it matches nothing.
    let keep = [
        Some(context.report_fd),
        Some(context.status_fd),
        Some(context.control_fd),
        Some(context.null_fd),
        context.capture_stdout_fd,
        context.capture_stderr_fd,
        context.proceed_fd,
        context.map_gate_fd,
        context.stdin_fd,
        context.stdout_fd,
        context.stderr_fd,
        context.terminal_channel_fd,
    ]
    .map(|channel| channel.map_or(-1 as RawFd, |fd| fd.as_raw_fd()));
    sweep_fds_keeping(&keep)
}

/// Closes every descriptor this process does not own: the standard streams and
/// the entries of `keep` survive, everything else is closed.
///
/// Iterates `/proc/self/fd`. Entries arrive in ascending numeric order and
/// procfs positions are keyed by descriptor number, so closing the entry just
/// returned never perturbs the iteration.
///
/// Every forked child sweeps, not only the launch stage. A copied descriptor
/// table is not inert: an inherited copy of a live sandbox's control socket
/// holds that socket open, and the supervisor's hangup detection — the whole of
/// [`stop_with_caller`](crate::CageBuilder::stop_with_caller) — waits on the
/// last copy closing. A child that swept nothing would defer that for as long
/// as it runs.
///
/// Post-fork safe: no allocation, no locking, and no syscall but the directory
/// read and `close`.
pub(crate) fn sweep_fds_keeping(keep: &[RawFd]) -> Result<(), Errno> {
    let dir = rustix::fs::open(
        c"/proc/self/fd",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut buf = [MaybeUninit::uninit(); 2048];
    let mut entries = RawDir::new(&dir, &mut buf);
    while let Some(entry) = entries.next() {
        let entry = entry?;
        let Some(fd) = parse_fd(entry.file_name()) else {
            continue;
        };
        if fd <= 2 || fd == dir.as_fd().as_raw_fd() || keep.contains(&fd) {
            continue;
        }
        // SAFETY: the descriptor was just listed, is not the directory
        // being iterated, not a kept channel, and not otherwise referenced
        // by this freshly forked process; it is closed exactly once.
        unsafe { rustix::io::close(fd) };
    }
    Ok(())
}

/// Parses a `/proc/self/fd` entry name into a descriptor number. Returns
/// `None` for `.` and `..`.
fn parse_fd(name: &CStr) -> Option<RawFd> {
    let bytes = name.to_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut value: RawFd = 0;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as RawFd)?;
    }
    Some(value)
}

/// `KEYCTL_GET_KEYRING_ID`: report the serial of a special keyring, creating
/// nothing when the third argument is zero.
const KEYCTL_GET_KEYRING_ID: usize = 0;
/// `KEYCTL_JOIN_SESSION_KEYRING`: replace the session keyring, with a fresh
/// anonymous one when the name argument is null.
const KEYCTL_JOIN_SESSION_KEYRING: usize = 1;
/// `KEY_SPEC_SESSION_KEYRING`: the calling process's session keyring.
const KEY_SPEC_SESSION_KEYRING: i32 = -3;

/// Gives this process, and every process it forks, a session keyring of its
/// own in place of the one it inherited.
///
/// The session keyring is not partitioned by any namespace a launch creates.
/// A forked process inherits its parent's, and a process *possesses* every key
/// reachable from it, which is the one standing the default key permissions
/// grant reading and searching to. Left alone, a command in a fully isolated
/// sandbox could still read, through `keyctl`, every key the caller's login
/// session holds: a Kerberos ticket cache, an fscrypt or eCryptfs key, a secret
/// a desktop cached there. Joining a fresh anonymous keyring ends the
/// possession, and with it that reach.
///
/// What remains is what the kernel grants the key's owner, whom every sandbox
/// process is. A key whose permissions grant its owner *view* is still listed
/// in `/proc/keys`, description and all, much as the mount table stays
/// readable. One whose permissions grant its owner *read*, which the defaults
/// do not, stays readable by serial number. The user, user session, and
/// persistent keyrings belong to the user rather than the session: a sandbox's
/// user namespace gives it its own, while a restriction's command reaches the
/// caller's and can link them back in. The curated seccomp denylist, which
/// denies `keyctl`, closes what this does not.
///
/// A process that cannot call `keyctl` at all has nothing to replace, and
/// neither has anything it forks: a seccomp filter is inherited, and so is a
/// kernel built without key support. Container runtimes' default seccomp
/// profiles deny the call exactly so, and a launch under one proceeds. That is
/// established by asking rather than read into the errno: a refused join is
/// excused only when a read-only query of the inherited keyring is refused the
/// same way, so a refusal aimed at the join alone, which would leave the old
/// keyring in place and readable, still fails the launch. The query stands in
/// for every `keyctl` operation. A filter that refused the join and the query
/// while allowing `KEYCTL_READ` would be excused all the same; a filter written
/// to deny the call does not discriminate between its operations that way.
///
/// Post-fork safe: raw syscalls only.
fn replace_session_keyring() -> Result<(), Errno> {
    match keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0) {
        Ok(()) => Ok(()),
        Err(refused @ (Errno::PERM | Errno::NOSYS)) => {
            match keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING as usize) {
                Err(Errno::PERM | Errno::NOSYS) => Ok(()),
                _ => Err(refused),
            }
        }
        Err(errno) => Err(errno),
    }
}

/// Issues one two-argument `keyctl` operation, discarding its result value.
fn keyctl(operation: usize, argument: usize) -> Result<(), Errno> {
    // SAFETY: both operations used here take integer arguments only; a zero
    // second argument to `KEYCTL_JOIN_SESSION_KEYRING` is the null name the
    // kernel reads as "anonymous", so no pointer is passed and none is read.
    // The third argument is zero, which `KEYCTL_GET_KEYRING_ID` reads as "do
    // not create".
    unsafe { syscalls::syscall!(Sysno::keyctl, operation, argument, 0usize) }
        .map(|_| ())
        .map_err(sys::errno)
}

/// Creates one mount-target directory at exactly `mode`, leaving an existing
/// entry — directory or symlink — untouched.
///
/// The mode is set again after the `mkdir` because `mkdir` narrows it by the
/// process umask, and the mount point outlives the sandbox: a launch under
/// `umask 077` would otherwise leave a `0700` `/tmp` in the rootfs for a
/// provisioned tree to carry forward. Setting it only on the directory this
/// call just created keeps the rootfs's own modes intact — the tree owns what
/// it ships, the sandbox owns what it creates.
///
/// It is set through a descriptor rather than by name, for the reason
/// [`create_mount_file`] uses `fchmod`: a path-wise `chmodat` follows a symlink
/// at the leaf, so a host process racing the window between the `mkdir` and the
/// mode would have a path of its choosing chmod-ed instead. `O_NOFOLLOW` refuses
/// a leaf replaced by a symlink outright, and `O_DIRECTORY` refuses one replaced
/// by anything that is not a directory.
fn create_mount_dir(dir: BorrowedFd<'_>, leaf: &CStr, mode: Mode) -> Result<(), Errno> {
    match fs::mkdirat(dir, leaf, mode) {
        Ok(()) => {
            let created = fs::openat(
                dir,
                leaf,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            fs::fchmod(&created, mode)
        }
        Err(Errno::EXIST) => Ok(()),
        Err(errno) => Err(errno),
    }
}

/// The mode a file bind's created target carries. It exists for its mount to
/// cover and is taken away with the sandbox, so the value matters only for the
/// window before the mount and for a caller inspecting the tree in between.
const FILE_TARGET_MODE: fs::RawMode = 0o644;

/// Creates a file bind's target, empty and at exactly `mode`, leaving an entry
/// the root already ships — of any kind — untouched. Returns the created file,
/// or `None` where an entry was already there.
///
/// `O_EXCL` is what keeps the created file at the path the caller side
/// recorded. `RESOLVE_IN_ROOT` scopes symlink resolution to the root but does
/// not suppress it, so a plain `O_CREAT` on a root that ships this target as a
/// symlink would create the file at the link's destination instead — a path the
/// caller side does not know, so a file the root never had would be left behind
/// when the sandbox is gone (see [`LaunchPlan::managed_placeholders`]). With
/// `O_EXCL` an entry already at the path, symbolic link included, answers
/// `EEXIST`: there is nothing to create, and the bind that follows resolves the
/// path as the root intends.
///
/// The mode is set again after the create for the reason
/// [`create_mount_dir`] sets it again after the `mkdir`: `O_CREAT` narrows it by
/// the process umask. Only a file this call just created is chmod-ed, so a mode
/// the root ships is never rewritten.
///
/// The file is opened for reading, though it is created: nothing is written to
/// it, and the descriptor [`hold_file_target`] keeps open for its lock must not
/// count as a writer, which would refuse an
/// [empty root](crate::CageBuilder::empty_rootfs)'s read-only remount with
/// `EBUSY`.
///
/// [`LaunchPlan::managed_placeholders`]: super::LaunchPlan::managed_placeholders
fn create_mount_file(
    root: BorrowedFd<'_>,
    path: &CStr,
    mode: Mode,
) -> Result<Option<OwnedFd>, Errno> {
    match open_in_root_with(
        root,
        path,
        OFlags::CREATE | OFlags::EXCL | OFlags::RDONLY | OFlags::CLOEXEC,
        mode,
    ) {
        Ok(file) => {
            fs::fchmod(&file, mode)?;
            Ok(Some(file))
        }
        Err(Errno::EXIST) => Ok(None),
        Err(errno) => Err(errno),
    }
}

/// How many times [`hold_file_target`] looks again at a target another
/// sandbox's teardown is removing before it binds without a lock.
const TARGET_ATTEMPTS: usize = 64;

/// Makes sure a file bind's target exists, reports it to the caller side if
/// this call created it, and holds a shared lock on a regular-file target for
/// as long as this process keeps its descriptors.
///
/// A target this call creates is the launch's own, and the caller side removes
/// it once the sandbox is gone; see
/// [`LaunchPlan::managed_placeholders`](super::LaunchPlan::managed_placeholders).
/// Its identity goes back with it, so the removal can tell this file from one
/// that later took its name.
///
/// A target already at the path is the root's own, or another sandbox's on a
/// root two of them share: the first to bind creates it, the second finds it,
/// and the first's teardown must not remove it while the second can still be
/// running, since unlinking a name unmounts every bind onto it. The shared lock
/// is how the second says so. A teardown takes an exclusive lock before it
/// removes anything and leaves a target any sandbox still holds. One whose lock
/// is refused here holds an exclusive one and is removing the target, so the
/// target is created anew once it is gone, a bounded number of times before
/// the bind goes ahead without a lock.
///
/// The lock lasts as long as a descriptor for the file in this process, so the
/// descriptor is left open. The init keeps it for the sandbox's whole life. The
/// command process, which sets the sandbox up where there is no PID namespace,
/// keeps it until it executes: every descriptor here closes on exec, and none
/// may reach the command.
///
/// Post-fork safe: raw syscalls only.
fn hold_file_target(
    root: BorrowedFd<'_>,
    path: &CStr,
    op: usize,
    report_fd: BorrowedFd<'_>,
) -> Result<(), Errno> {
    for _ in 0..TARGET_ATTEMPTS {
        if let Some(file) = create_mount_file(root, path, Mode::from_raw_mode(FILE_TARGET_MODE))? {
            // A file nobody else has opened yet: the lock cannot be refused.
            let _ = share_target(&file);
            report_created(report_fd, op, &fs::fstat(&file)?);
            let _ = file.into_raw_fd();
            return Ok(());
        }
        let found = match open_in_root(root, path, OFlags::PATH) {
            Ok(found) => found,
            // A name that leads nowhere: removed since the create found it,
            // to be created again, or a link to nothing, which is the root's.
            Err(Errno::NOENT) => match open_in_root(root, path, OFlags::PATH | OFlags::NOFOLLOW) {
                Err(Errno::NOENT) => continue,
                _ => return Ok(()),
            },
            Err(errno) => return Err(errno),
        };
        if fs::FileType::from_raw_mode(fs::fstat(&found)?.st_mode) != fs::FileType::RegularFile {
            // Not a file a launch creates, so not one a teardown removes.
            return Ok(());
        }
        // Reopened through the descriptor rather than the path, so the file
        // locked is the file found; an `O_PATH` descriptor takes no lock.
        let file = fs::open(
            fd_path(&found).as_cstr(),
            OFlags::RDONLY | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        match share_target(&file) {
            // Granted after a teardown let go of it, the file may be unlinked
            // already, and the name then holds nothing of this lock's.
            Ok(()) if fs::fstat(&file)?.st_nlink == 0 => continue,
            Ok(()) => {
                let _ = file.into_raw_fd();
                return Ok(());
            }
            Err(Errno::WOULDBLOCK) => thread::sched_yield(),
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

/// Takes a shared lock on a file-bind target, without waiting.
///
/// A lock on the file a bind covers rather than a lock file, so not
/// `provision::lock_exclusive`'s to take: it is shared among the sandboxes
/// bound onto the file, never waited for, and taken after the fork, where that
/// helper's path handling cannot run.
fn share_target(file: &OwnedFd) -> Result<(), Errno> {
    #[expect(clippy::disallowed_methods)]
    let taken = fs::flock(file, fs::FlockOperation::NonBlockingLockShared);
    taken
}

/// Executes one frozen mount op, the plan's `index`th, against the new root.
fn execute_op(
    root: BorrowedFd<'_>,
    op: &MountOp,
    index: usize,
    report_fd: BorrowedFd<'_>,
) -> Result<(), (SetupStep, Errno)> {
    // Create missing mount-target directories, one component at a time.
    // The parent directory is resolved in-root first, so a symlinked
    // component is followed only within the rootfs; an existing entry —
    // directory or symlink — is left alone.
    for dir in &op.dirs {
        let mode = Mode::from_raw_mode(dir.mode);
        let created = if dir.parent.is_empty() {
            create_mount_dir(root, dir.leaf.as_c_str(), mode)
        } else {
            let parent = open_in_root(root, &dir.parent, OFlags::PATH | OFlags::DIRECTORY)
                .map_err(|errno| (SetupStep::CreateMountTarget, errno))?;
            create_mount_dir(parent.as_fd(), dir.leaf.as_c_str(), mode)
        };
        created.map_err(|errno| (SetupStep::CreateMountTarget, errno))?;
    }

    // The target of a file bind must exist before a file can be bound onto
    // it; create it empty where the root ships nothing at that path.
    if let Some(file) = &op.create_file {
        hold_file_target(root, file, index, report_fd)
            .map_err(|errno| (SetupStep::CreateMountTarget, errno))?;
    }

    match &op.action {
        MountAction::Tmpfs {
            target,
            flags,
            data,
        } => {
            let target = open_in_root(root, target, OFlags::PATH | OFlags::DIRECTORY)
                .map_err(|errno| (SetupStep::OpenMountTarget, errno))?;
            mount::mount(
                c"tmpfs",
                fd_path(&target).as_cstr(),
                c"tmpfs",
                *flags,
                data.as_c_str(),
            )
            .map_err(|errno| (SetupStep::MountTmpfs, errno))
        }
        MountAction::Procfs { target } => {
            // Mounted from inside the new PID namespace, so the instance
            // presents the sandbox's processes and nothing else.
            let target = open_in_root(root, target, OFlags::PATH | OFlags::DIRECTORY)
                .map_err(|errno| (SetupStep::OpenMountTarget, errno))?;
            mount::mount(
                c"proc",
                fd_path(&target).as_cstr(),
                c"proc",
                MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                c"",
            )
            .map_err(|errno| (SetupStep::MountProc, errno))
        }
        MountAction::Devpts { target, data } => {
            let target = open_in_root(root, target, OFlags::PATH | OFlags::DIRECTORY)
                .map_err(|errno| (SetupStep::OpenMountTarget, errno))?;
            mount::mount(
                c"devpts",
                fd_path(&target).as_cstr(),
                c"devpts",
                MountFlags::NOSUID | MountFlags::NOEXEC,
                data.as_c_str(),
            )
            .map_err(|errno| (SetupStep::MountDevpts, errno))
        }
        MountAction::Bind {
            source,
            target,
            read_only,
        } => {
            let target = open_in_root(root, target, OFlags::PATH)
                .map_err(|errno| (SetupStep::OpenMountTarget, errno))?;
            bind(source, target.as_fd(), *read_only)
        }
        MountAction::Raw {
            source,
            target,
            fstype,
            flags,
            data,
        } => {
            // Only the target is interpreted: resolved in-root like every
            // other target. Source, type, flags, and data pass through.
            let target = open_in_root(root, target, OFlags::PATH)
                .map_err(|errno| (SetupStep::OpenMountTarget, errno))?;
            mount::mount(
                source.as_c_str(),
                fd_path(&target).as_cstr(),
                fstype.as_c_str(),
                *flags,
                data.as_c_str(),
            )
            .map_err(|errno| (SetupStep::MountRaw, errno))
        }
        MountAction::Symlink {
            parent,
            leaf,
            content,
        } => {
            // A link at the root's top level has no parent to resolve: it is
            // made in the root itself.
            let parent = match parent.is_empty() {
                true => None,
                false => Some(
                    open_in_root(root, parent, OFlags::PATH | OFlags::DIRECTORY)
                        .map_err(|errno| (SetupStep::OpenMountTarget, errno))?,
                ),
            };
            let dir = parent.as_ref().map_or(root, AsFd::as_fd);
            match fs::symlinkat(content.as_c_str(), dir, leaf.as_c_str()) {
                Ok(()) => Ok(()),
                // The link this op makes, made by an earlier launch over the
                // same persistent root.
                Err(Errno::EXIST) if links_to(dir, leaf, content) => Ok(()),
                Err(errno) => Err((SetupStep::CreateSymlink, errno)),
            }
        }
    }
}

/// Whether the entry `leaf` names in `dir` is a symbolic link to `content`.
///
/// Read into a buffer on the stack, since this runs after the fork. The build
/// refused a `content` that does not fit it, so a target that fills it is a
/// longer one, truncated, and not `content`.
fn links_to(dir: BorrowedFd<'_>, leaf: &CStr, content: &CStr) -> bool {
    let mut target = [0u8; LINK_BUF];
    match fs::readlinkat_raw(dir, leaf, &mut target[..]) {
        Ok(len) => len < target.len() && &target[..len] == content.to_bytes(),
        Err(_) => false,
    }
}

/// Binds the host tree at `source`, with every mount beneath it, onto the
/// mount target `target` names, read-only throughout when `read_only` asks.
///
/// The tree is cloned detached first (`open_tree` with `OPEN_TREE_CLONE`), made
/// read-only while detached, and only then attached (`move_mount`) onto the
/// descriptor the target was resolved to. Nothing between the bind and its
/// restriction resolves a path again. Remounting by path after an ordinary
/// bind would: a sandbox sharing a writable root could rename and symlink in
/// that window, and land the read-only flag on a mount of its choosing while
/// this bind stayed writable. Restricted before it is attached, the bind is
/// never anything but read-only where a path can reach it.
///
/// `mount_setattr` with `AT_RECURSIVE` marks the whole tree in one call and
/// needs no locked-flag handling, because it only adds a restriction, so a
/// read-only bind of a tree that carries its own submounts leaves them
/// read-only too. A kernel without it (before 5.12) has the restriction made
/// after the attach instead, as a remount of the mount the tree's descriptor
/// names, which by then is the bind. No path is resolved again, but the bind
/// is writable for that moment, and only the bind itself is covered: its
/// submounts keep their own flags.
fn bind(source: &CStr, target: BorrowedFd<'_>, read_only: bool) -> Result<(), (SetupStep, Errno)> {
    let tree = mount::open_tree(
        fs::CWD,
        source,
        mount::OpenTreeFlags::OPEN_TREE_CLONE
            | mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
            | mount::OpenTreeFlags::AT_RECURSIVE,
    )
    .map_err(|errno| (SetupStep::BindMount, errno))?;
    let remount_after = read_only
        && match mount_setattr(tree.as_fd(), MOUNT_ATTR_RDONLY, true) {
            Ok(()) => false,
            Err(Errno::NOSYS) => true,
            Err(errno) => return Err((SetupStep::RemountReadOnly, errno)),
        };
    mount::move_mount(
        tree.as_fd(),
        c"",
        target,
        c"",
        mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH
            | mount::MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .map_err(|errno| (SetupStep::BindMount, errno))?;
    if remount_after {
        remount_top(tree.as_fd(), MountFlags::RDONLY)
            .map_err(|errno| (SetupStep::RemountReadOnly, errno))?;
    }
    Ok(())
}

/// Marks the sandbox's root mount, and every mount the rootfs bind carried
/// with it, `nosuid`.
///
/// The root is bound from a host tree and inherits that mount's flags, and the
/// provisioners apply a tree's permission bits verbatim, so a Debian or Alpine
/// rootfs inside the sandbox ships set-user-ID binaries owned by in-namespace
/// uid 0 and file capabilities to match. Without the flag a non-root
/// [`run_as`](crate::CageBuilder::run_as) command executes one of them and is
/// root inside again — and the flag is only worth setting because the nested
/// user namespace locks it, where before the command could have cleared it as
/// readily as it cleared a read-only bind.
///
/// Scoped to the root. A caller's own bind keeps inheriting its source's flags:
/// a caller who binds a host tree in order to run what is in it is entitled to
/// a different answer than the rootfs gets.
fn nosuid_root(root: BorrowedFd<'_>) -> Result<(), Errno> {
    match mount_setattr(root, MOUNT_ATTR_NOSUID, true) {
        Ok(()) => Ok(()),
        Err(Errno::NOSYS) => remount_top(root, MountFlags::NOSUID),
        Err(errno) => Err(errno),
    }
}

/// Opens the root mount a path root was just mounted at.
fn open_root(path: &CStr) -> Result<OwnedFd, Failure> {
    rustix::fs::open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| (SetupStep::EnterRootfs, errno, 0))
}

/// Mounts the tmpfs an empty root is made of, and returns a descriptor of it.
///
/// The mount profile names its bind sources as host paths, which resolve by
/// path until the pivot, so the root cannot be mounted over a host directory:
/// a source beneath that directory would be hidden. The tmpfs is created
/// detached instead, and attached on top of `/` itself. A path lookup starts at
/// the process's root, the mount beneath, and does not cross a mount stacked on
/// its starting point, so every host path resolves as it did before. The
/// descriptor is what reaches the new root, for the mount targets and the
/// pivot.
///
/// `nosuid` and `nodev` from the start: nothing in it is executable or a
/// device, and a mount the profile makes beneath it carries its own flags.
fn mount_empty_root() -> Result<OwnedFd, Errno> {
    let context = mount::fsopen(c"tmpfs", mount::FsOpenFlags::FSOPEN_CLOEXEC)?;
    mount::fsconfig_set_string(&context, c"mode", c"0755")?;
    mount::fsconfig_create(&context)?;
    let root = mount::fsmount(
        &context,
        mount::FsMountFlags::FSMOUNT_CLOEXEC,
        mount::MountAttrFlags::MOUNT_ATTR_NOSUID | mount::MountAttrFlags::MOUNT_ATTR_NODEV,
    )?;
    mount::move_mount(
        &root,
        c"",
        fs::CWD,
        c"/",
        mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(root)
}

/// Makes the root mount `root` names read-only, and only it: every mount the
/// profile made beneath it keeps its own flags, so a writable bind and the
/// managed `/tmp` stay writable.
fn read_only_root(root: BorrowedFd<'_>) -> Result<(), Errno> {
    match mount_setattr(root, MOUNT_ATTR_RDONLY, false) {
        Ok(()) => Ok(()),
        Err(Errno::NOSYS) => remount_top(root, MountFlags::RDONLY),
        Err(errno) => Err(errno),
    }
}

/// `MOUNT_ATTR_RDONLY`: with `mount_setattr`, mark the mount read-only.
const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
/// `MOUNT_ATTR_NOSUID`: with `mount_setattr`, ignore set-user-ID and set-group-ID
/// bits and file capabilities on the mount.
const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
/// `AT_RECURSIVE`: apply a `mount_setattr` change to the whole mount subtree.
const AT_RECURSIVE: usize = 0x8000;
/// `AT_EMPTY_PATH`: operate on the mount the descriptor itself names.
const AT_EMPTY_PATH: usize = 0x1000;

/// The kernel's `struct mount_attr`, the fifth `mount_setattr` argument. Only
/// `attr_set` is used here; the rest are zero.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

// The layout must match the kernel's, or the attribute would be misread.
const _: () = assert!(size_of::<MountAttr>() == 32);

/// Sets `attr_set` on the mount `target` names, and with `recursive` on every
/// mount beneath it, through `mount_setattr`.
///
/// Only ever used to *add* a restriction, which is what makes the recursion
/// safe to apply without locked-flag handling: the call never clears a flag the
/// namespace holds locked.
///
/// Returns `Errno::NOSYS` on a kernel that predates `mount_setattr` (before
/// 5.12), which each caller answers with a top-level remount.
fn mount_setattr(target: BorrowedFd<'_>, attr_set: u64, recursive: bool) -> Result<(), Errno> {
    let attr = MountAttr {
        attr_set,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let scope = if recursive { AT_RECURSIVE } else { 0 };
    // SAFETY: `target` is a descriptor naming a mount: the root, or a detached
    // tree. With AT_EMPTY_PATH and an empty path the call operates on that
    // mount, and with AT_RECURSIVE on its submounts too. The attr pointer and
    // its size describe a valid `struct mount_attr` for the duration of the
    // call.
    unsafe {
        syscalls::syscall!(
            Sysno::mount_setattr,
            target.as_raw_fd(),
            c"".as_ptr(),
            scope | AT_EMPTY_PATH,
            &attr as *const MountAttr,
            size_of::<MountAttr>()
        )
    }
    .map(|_| ())
    .map_err(sys::errno)
}

/// Remounts only the mount `target` names with `added` set, the fallback for a
/// kernel without `mount_setattr`. Submounts keep their own flags.
fn remount_top(target: BorrowedFd<'_>, added: MountFlags) -> Result<(), Errno> {
    let flags = remount_flags(fs::fstatvfs(target)?.f_flag, added);
    mount::mount_remount(fd_path(&target).as_cstr(), flags, c"")
}

/// Translates the flags `fstatvfs` observed on a mount into the flags a remount
/// of it must carry, `added` being the restriction the remount is for.
///
/// A remount in a user namespace must not clear the mount flags the namespace
/// holds locked (`nosuid`, `nodev`, ...), so the observed flags are carried
/// into the remount alongside the one being added. Atime flags are left
/// unspecified — the kernel preserves the existing atime settings on a remount
/// that names none — because `fstatvfs` reports raw `ST_*` bits, and
/// `ST_RELATIME` does not share `MS_RELATIME`'s value; the flags copied here
/// all have coinciding `ST_*` and `MS_*` values.
///
/// Split out from its callers because it is pure logic on a path no current
/// kernel takes: the fallback runs only below Linux 5.12, so the table is
/// testable where the remount around it is not.
fn remount_flags(observed: StatVfsMountFlags, added: MountFlags) -> MountFlags {
    let mut flags = MountFlags::BIND | added;
    for (statvfs_flag, mount_flag) in [
        (StatVfsMountFlags::RDONLY, MountFlags::RDONLY),
        (StatVfsMountFlags::NOSUID, MountFlags::NOSUID),
        (StatVfsMountFlags::NODEV, MountFlags::NODEV),
        (StatVfsMountFlags::NOEXEC, MountFlags::NOEXEC),
        (StatVfsMountFlags::SYNCHRONOUS, MountFlags::SYNCHRONOUS),
        (
            StatVfsMountFlags::MANDLOCK,
            MountFlags::PERMIT_MANDATORY_FILE_LOCKING,
        ),
    ] {
        if observed.contains(statvfs_flag) {
            flags |= mount_flag;
        }
    }
    flags
}

/// Opens a rootfs-relative path against the new-root descriptor, confining
/// symlink resolution to the rootfs.
fn open_in_root(root: BorrowedFd<'_>, path: &CStr, oflags: OFlags) -> Result<OwnedFd, Errno> {
    open_in_root_with(root, path, oflags | OFlags::CLOEXEC, Mode::empty())
}

/// [`open_in_root`] with an explicit creation mode.
///
/// The post-fork stage's own opener, rather than
/// `provision::containment::open_dir`: a mount target is whatever the caller
/// named, a file as readily as a directory, and the stage creates where asked
/// to, so the `O_DIRECTORY` that helper folds in would refuse half of them. The
/// lookup goes through [`resolve::openat2`] all the same, so a rename or a mount
/// elsewhere on the host racing a `..` step of the walk is retried rather than
/// failing the launch.
fn open_in_root_with(
    root: BorrowedFd<'_>,
    path: &CStr,
    oflags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno> {
    resolve::openat2(root, path, oflags, mode, ResolveFlags::IN_ROOT)
}

/// A path assembled into a stack buffer, for the post-fork stages that cannot
/// allocate one.
///
/// The buffer holds every path formatted here with room to spare: the longest
/// is `/proc/self/fd/` and ten decimal digits. A push that would not fit is
/// dropped rather than truncating mid-way — these processes must not panic, and
/// a short path fails its `open` with `ENOENT` instead of naming something else.
struct StackPath {
    buf: [u8; 48],
    len: usize,
}

impl StackPath {
    /// An empty path.
    fn new() -> StackPath {
        StackPath {
            buf: [0u8; 48],
            len: 0,
        }
    }

    /// Appends literal bytes, if they fit alongside the terminating NUL.
    fn push(&mut self, bytes: &[u8]) {
        if self.len + bytes.len() >= self.buf.len() {
            return;
        }
        for &byte in bytes {
            self.buf[self.len] = byte;
            self.len += 1;
        }
    }

    /// Appends a value in decimal.
    fn push_decimal(&mut self, mut value: u32) {
        // The widest u32 is ten digits, emitted least-significant first and
        // reversed into the buffer.
        let mut digits = [0u8; 10];
        let mut count = 0;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            value /= 10;
            count += 1;
            if value == 0 {
                break;
            }
        }
        digits[..count].reverse();
        self.push(&digits[..count]);
    }

    fn as_cstr(&self) -> &CStr {
        // SAFETY: the buffer is zero-initialized and `push` never lets `len`
        // reach the final byte, so the slice holds exactly one NUL, at the end.
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.buf[..self.len + 1]) }
    }
}

/// Formats the `/proc/self/fd` path that names `fd`, so a descriptor
/// resolved with `RESOLVE_IN_ROOT` can anchor a mount syscall that only
/// accepts paths.
fn fd_path<Fd: AsFd>(fd: &Fd) -> StackPath {
    let mut path = StackPath::new();
    path.push(b"/proc/self/fd/");
    // Descriptors are non-negative, so the cast is lossless.
    path.push_decimal(fd.as_fd().as_raw_fd() as u32);
    path
}

/// Formats the `<pid>/<file>` path of one identity-map file, relative to a
/// descriptor for the procfs it lives in.
///
/// The delegate that writes another process's map addresses it this way rather
/// than through an absolute path, because the procfs that indexes the process
/// differs by launch shape: the sandbox's own where there is a PID namespace,
/// the host's where there is not.
fn map_file_path(pid: u32, file: &[u8]) -> StackPath {
    let mut path = StackPath::new();
    path.push_decimal(pid);
    path.push(b"/");
    path.push(file);
    path
}

/// The flags half of `struct ifreq`, as the kernel's interface ioctls
/// expect it: the interface name and a union whose largest member pads the
/// struct to 40 bytes.
#[repr(C)]
struct IfreqFlags {
    name: [u8; 16],
    flags: i16,
    _pad: [u8; 22],
}

/// The ioctls copy `size_of::<IfreqFlags>()` bytes; a layout that drifts
/// from `struct ifreq` must fail the build, not misissue the ioctl.
const _: () = assert!(size_of::<IfreqFlags>() == 40);

/// `IFF_UP` from the kernel's interface flags.
const IFF_UP: i16 = 0x1;
/// `SIOCGIFFLAGS`: read an interface's flags.
const SIOCGIFFLAGS: ioctl::Opcode = 0x8913;
/// `SIOCSIFFLAGS`: set an interface's flags.
const SIOCSIFFLAGS: ioctl::Opcode = 0x8914;

/// Brings up the loopback interface in this process's network namespace,
/// via the interface-flags ioctls on a throwaway datagram socket — no
/// netlink machinery for a single flag flip.
fn bring_up_loopback() -> Result<(), Errno> {
    let socket = rustix::net::socket_with(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    let mut request = IfreqFlags {
        name: *b"lo\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        flags: 0,
        _pad: [0; 22],
    };
    // SAFETY: SIOCGIFFLAGS reads and writes a `struct ifreq`, which
    // `IfreqFlags` lays out: the 16-byte name, then the flags at the start
    // of the union, padded to the kernel's 40-byte size.
    unsafe {
        ioctl::ioctl(
            &socket,
            ioctl::Updater::<SIOCGIFFLAGS, IfreqFlags>::new(&mut request),
        )
    }?;
    request.flags |= IFF_UP;
    // SAFETY: SIOCSIFFLAGS reads the same `struct ifreq` layout.
    unsafe {
        ioctl::ioctl(
            &socket,
            ioctl::Setter::<SIOCSIFFLAGS, IfreqFlags>::new(request),
        )
    }?;
    Ok(())
}

/// Opens `path` and writes `data` in a single `write`, on the terms
/// [`frame::write_whole`] states for the identity-map files under `/proc`.
pub(super) fn write_file(path: &CStr, data: &[u8]) -> Result<(), Errno> {
    let fd = rustix::fs::open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())?;
    frame::write_whole(fd.as_fd(), data)
}

/// Writes the failure record: the step discriminant, the errno, and the detail
/// index, all little-endian. Smaller than `PIPE_BUF`, the write is atomic. If it
/// fails the caller is gone and there is no one to report to.
fn report(fd: BorrowedFd<'_>, step: SetupStep, errno: Errno, detail: u32) {
    let mut record = [0u8; super::REPORT_FAILURE_LEN];
    record[0..4].copy_from_slice(&(step as u32).to_le_bytes());
    record[4..8].copy_from_slice(&errno.raw_os_error().to_le_bytes());
    record[8..12].copy_from_slice(&detail.to_le_bytes());
    let _ = rustix::io::write(fd, &record);
}

/// Writes the created-target record for the `op`th mount op's file: the tag,
/// the op index, and the file's inode number, all little-endian. Smaller than
/// `PIPE_BUF`, the write is atomic. If it fails the caller is gone, and the file
/// stays in the root for want of anyone to remove it.
fn report_created(fd: BorrowedFd<'_>, op: usize, file: &fs::Stat) {
    let mut record = [0u8; super::REPORT_CREATED_LEN];
    record[0..4].copy_from_slice(&super::REPORT_CREATED.to_le_bytes());
    record[4..8].copy_from_slice(&u32::try_from(op).unwrap_or(u32::MAX).to_le_bytes());
    record[8..16].copy_from_slice(&file.st_ino.to_le_bytes());
    let _ = rustix::io::write(fd, &record);
}

/// Writes the held record: the command is at its gate, with every setup step
/// behind it. If the write fails the caller is gone, and the gate's read reports
/// that next.
fn report_held(fd: BorrowedFd<'_>) {
    let _ = rustix::io::write(fd, &super::REPORT_HELD.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    #[test]
    fn a_remount_carries_the_locked_flags_forward() {
        // Every remount is a bind remount adding one restriction, and each
        // locked flag the kernel reported must come back with it: a user
        // namespace refuses a remount that would clear one.
        assert_eq!(
            remount_flags(StatVfsMountFlags::empty(), MountFlags::RDONLY),
            MountFlags::BIND | MountFlags::RDONLY,
        );
        for (observed, expected) in [
            (StatVfsMountFlags::RDONLY, MountFlags::RDONLY),
            (StatVfsMountFlags::NOSUID, MountFlags::NOSUID),
            (StatVfsMountFlags::NODEV, MountFlags::NODEV),
            (StatVfsMountFlags::NOEXEC, MountFlags::NOEXEC),
            (StatVfsMountFlags::SYNCHRONOUS, MountFlags::SYNCHRONOUS),
            (
                StatVfsMountFlags::MANDLOCK,
                MountFlags::PERMIT_MANDATORY_FILE_LOCKING,
            ),
        ] {
            assert_eq!(
                remount_flags(observed, MountFlags::RDONLY),
                MountFlags::BIND | MountFlags::RDONLY | expected,
                "{observed:?}",
            );
        }
        // The rootfs's `nosuid` remount is the other user of the table, and it
        // must not make the root read-only along the way: only the restriction
        // it was asked for is added, and a read-only source is still carried
        // forward because clearing it is what a user namespace refuses.
        assert_eq!(
            remount_flags(StatVfsMountFlags::empty(), MountFlags::NOSUID),
            MountFlags::BIND | MountFlags::NOSUID,
        );
        assert_eq!(
            remount_flags(StatVfsMountFlags::RDONLY, MountFlags::NOSUID),
            MountFlags::BIND | MountFlags::NOSUID | MountFlags::RDONLY,
        );
    }

    /// Opens a directory the way the sandbox stage holds its new root.
    fn open_root(path: &std::path::Path) -> OwnedFd {
        fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("the scratch directory opens")
    }

    /// The mode of an entry, without following a symbolic link.
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::symlink_metadata(path)
            .expect("the entry exists")
            .permissions()
            .mode()
            & 0o7777
    }

    #[test]
    fn a_mount_point_is_created_at_exactly_its_mode() {
        // The umask must not decide a mode the sandbox contributes: the mount
        // point outlives the sandbox, so a launch under `umask 077` would leave
        // a 0700 `/tmp` behind for a provisioned tree to carry forward. 0777 is
        // the value that shows it, since a umask conventionally clears write
        // bits and `mkdir` would otherwise land on 0755.
        let dir = Scratch::new("mount-dir-mode");
        let root = open_root(dir.path());

        create_mount_dir(root.as_fd(), c"created", Mode::from_raw_mode(0o777))
            .expect("a mount point the root does not ship is created");

        assert_eq!(mode_of(&dir.join("created")), 0o777);
        assert!(dir.join("created").is_dir());
    }

    #[test]
    fn a_mount_point_the_root_ships_is_left_exactly_as_it_is() {
        // The tree owns what it ships and the sandbox owns what it creates, so
        // an existing directory keeps its mode however the profile spells the
        // mount point's.
        use std::os::unix::fs::PermissionsExt;

        let dir = Scratch::new("mount-dir-shipped");
        let root = open_root(dir.path());
        std::fs::create_dir(dir.join("shipped")).expect("the directory is creatable");
        std::fs::write(dir.join("shipped/kept"), b"the root's own").expect("the file is writable");
        std::fs::set_permissions(dir.join("shipped"), std::fs::Permissions::from_mode(0o700))
            .expect("the directory's mode is settable");

        create_mount_dir(root.as_fd(), c"shipped", Mode::from_raw_mode(0o777))
            .expect("a mount point the root ships is not an error");

        assert_eq!(mode_of(&dir.join("shipped")), 0o700);
        assert_eq!(
            std::fs::read(dir.join("shipped/kept")).expect("the entry is readable"),
            b"the root's own",
        );
    }

    #[test]
    fn a_mount_point_the_root_ships_as_a_symlink_is_left_alone() {
        // A symbolic link to a directory is a mount point the root arranged
        // that way — the merged-`/usr` layout is the common case — so it is
        // satisfied rather than replaced, and its mode is never rewritten
        // through it.
        let dir = Scratch::new("mount-dir-symlink");
        let root = open_root(dir.path());
        std::fs::create_dir(dir.join("real")).expect("the directory is creatable");
        std::os::unix::fs::symlink("real", dir.join("linked"))
            .expect("the symbolic link is creatable");

        create_mount_dir(root.as_fd(), c"linked", Mode::from_raw_mode(0o777))
            .expect("an entry the root ships is not an error, whatever kind it is");

        assert!(
            std::fs::symlink_metadata(dir.join("linked"))
                .expect("the link is still there")
                .is_symlink(),
            "the root's own symbolic link was replaced",
        );
        assert_ne!(
            mode_of(&dir.join("real")),
            0o777,
            "the mode was set through the link",
        );
    }

    #[test]
    fn a_file_bind_target_is_created_at_exactly_its_mode() {
        // The umask must not decide a mode the sandbox contributes, for the
        // reason a mount point's mode is set again after the `mkdir`. 0666 is
        // the value that shows it: a umask conventionally clears write bits, so
        // an `O_CREAT` left to decide the mode lands on 0644 under the usual
        // `022` and on 0664 under the `002` of a user-private-group host.
        let dir = Scratch::new("mount-file-mode");
        let root = open_root(dir.path());

        create_mount_file(root.as_fd(), c"created", Mode::from_raw_mode(0o666))
            .expect("a target the root does not ship is created");

        assert_eq!(mode_of(&dir.join("created")), 0o666);
        assert_eq!(
            std::fs::read(dir.join("created")).expect("the target is readable"),
            b"",
            "a bind's target is created empty"
        );
    }

    #[test]
    fn a_file_bind_target_the_root_ships_is_left_exactly_as_it_is() {
        // The root owns what it ships. A target already present is one the
        // caller side never recorded for removal, so rewriting its mode here
        // would change a tree the launch has no claim on.
        use std::os::unix::fs::PermissionsExt;

        let dir = Scratch::new("mount-file-shipped");
        let root = open_root(dir.path());
        std::fs::write(dir.join("shipped"), b"the root's own").expect("the entry is writable");
        std::fs::set_permissions(dir.join("shipped"), std::fs::Permissions::from_mode(0o600))
            .expect("the entry's mode is settable");

        create_mount_file(root.as_fd(), c"shipped", Mode::from_raw_mode(0o666))
            .expect("a target the root ships is not an error");

        assert_eq!(mode_of(&dir.join("shipped")), 0o600);
        assert_eq!(
            std::fs::read(dir.join("shipped")).expect("the entry is readable"),
            b"the root's own",
        );
    }

    #[test]
    fn a_file_bind_target_the_root_ships_as_a_symlink_is_not_created_through() {
        // `RESOLVE_IN_ROOT` scopes symlink resolution to the root but does not
        // suppress it, so a plain `O_CREAT` would create the file at the link's
        // destination — a path the caller side does not record and therefore
        // never takes away, leaving the root holding content it never shipped.
        // `O_EXCL` refuses the link instead.
        let dir = Scratch::new("mount-file-symlink");
        let root = open_root(dir.path());
        std::os::unix::fs::symlink("../absent", dir.join("linked"))
            .expect("the symbolic link is creatable");

        create_mount_file(root.as_fd(), c"linked", Mode::from_raw_mode(0o644))
            .expect("an entry the root ships is not an error, whatever kind it is");

        assert!(
            std::fs::symlink_metadata(dir.join("linked"))
                .expect("the link is still there")
                .is_symlink(),
            "the root's own symbolic link was replaced",
        );
        // `..` is clamped to the root, so the destination the link names is
        // inside it. Nothing was created there.
        assert!(
            !dir.join("absent").exists(),
            "a file was created through the link",
        );
    }

    #[test]
    fn a_read_only_remount_leaves_the_atime_flags_unspecified() {
        // `ST_RELATIME` and `MS_RELATIME` do not share a value, so translating
        // the atime bits would set the wrong mount flag. The remount names none
        // and the kernel preserves what the mount already had.
        let atime = StatVfsMountFlags::RELATIME
            | StatVfsMountFlags::NOATIME
            | StatVfsMountFlags::NODIRATIME;
        assert_eq!(
            remount_flags(atime, MountFlags::RDONLY),
            MountFlags::BIND | MountFlags::RDONLY,
            "an atime bit reached the remount flags",
        );
    }
}
