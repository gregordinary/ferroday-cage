//! The post-fork stages: namespaces, sandbox setup, the command exec, and
//! the supervisor.
//!
//! A launch runs across a small tree of forked processes. Stage A is forked
//! from the caller and is short-lived: it scrubs the inherited signal state,
//! holds each standard stream number the caller left closed, unshares the
//! namespaces, sweeps the inherited descriptor table, replaces the inherited
//! session keyring or, where it cannot, refuses the key syscalls to everything
//! it forks, forks the next stage, and publishes that stage's pidfd back to the
//! caller over the control socket.
//!
//! With a PID namespace (the default), the process A forks is the sandbox
//! init — PID 1 inside the namespace. It leaves the caller's session or
//! process group, performs the sandbox setup (identity maps, hostname,
//! loopback, the mount profile over a fresh procfs, the pivot), forks the
//! command as PID 2 once stage A is gone, and then supervises: collecting
//! orphaned descendants, forwarding termination requests, watching the
//! control socket for caller exit, and reporting the command's wait status
//! over the status pipe before exiting. Its exit tears the namespace down, so
//! processes the command left running are terminated by the kernel.
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
//! The launch stage runs inside [`sys::in_child`], and every stage forked from
//! it carries that in the stack the fork copied, so a panic that broke the
//! rule would end the process with `exit_group(127)` rather than unwind into
//! the caller's code.
//!
//! Every operation below is a raw syscall, through rustix or [`sys`], over
//! data frozen by the caller before the fork. The exception is a dropped
//! [`OwnedFd`], which the standard library closes through libc's `close`, an
//! async-signal-safe wrapper of the one syscall; the [`mechanism`](super)
//! documentation states why that is safe here.
//!
//! Mount targets are resolved against the new-root descriptor with `openat2`
//! and `RESOLVE_IN_ROOT`, so an absolute symlink inside the rootfs resolves
//! within the rootfs and cannot reach the host tree during the pre-pivot
//! window. A target beneath an earlier mount of the profile is resolved the
//! same way from that mount's own descriptor, which the setup keeps while a
//! later step needs it, so it lands in that mount whatever renames the
//! directories above it meanwhile; see [`Profile`]. What a step mounts is made
//! detached and attached onto the resolved descriptor with `move_mount`: a
//! filesystem of the sandbox's own through `fsopen` and `fsmount` (see
//! [`fresh_mount`]), a bind as a clone of its source's tree, an overlay through
//! the same calls. A raw mount is the one step `mount(2)` makes, verbatim, and
//! it and the remount that stands in for `mount_setattr` below Linux 5.12
//! address the descriptor through its `/proc/self/fd` path, formatted into a
//! stack buffer; the host `/proc` is still mounted at that point.

use std::cell::Cell;
use std::convert::Infallible;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};

use rustix::event::{PollFd, PollFlags};
use rustix::fs::{
    self, AtFlags, Mode, OFlags, RawDir, ResolveFlags, StatVfsMountFlags, StatxAttributes,
    StatxFlags,
};
use rustix::io::Errno;
use rustix::ioctl;
use rustix::mount::{self, MountFlags, MountPropagationFlags, UnmountFlags};
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use rustix::process::Pid;
use rustix::process::Signal;
use rustix::process::{self, PidfdFlags, WaitOptions, WaitStatus};
use rustix::termios;
use rustix::thread;
use syscalls::Sysno;

use super::bounds::LINK_BUF;
use super::frame;
use super::overlay::{OverlayLayers, mount_overlay};
use super::resolve;
use super::seccomp;
use super::sys::{self, Disposition, How, SigSet};
use super::{
    FreshFs, FsParam, IdentityPlan, JoinTarget, LaunchPlan, MountAction, MountOp, OverlayPlan,
    RootPlan,
    STATUS_DUMPED, STATUS_EXITED, STATUS_SIGNALED, STDERR_FILENO, StdioPlan, encode_status,
};
use crate::error::SetupStep;
use crate::spec::covers;

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
    /// The shared `/dev/null` descriptor: the null stdin disposition, the
    /// placeholders [`hold_closed_streams`] holds closed standard numbers
    /// with, and the supervisor's own stdio.
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
    /// The sandbox end of the listener channel, where a seccomp filter's
    /// refusals are reported: the command stage sends the filter's listener
    /// back over it. Every other process of the launch closes its copy, so the
    /// caller reads end-of-file where the command stage fails first.
    pub(super) listener_channel_fd: Option<BorrowedFd<'a>>,
    /// Whether the init makes its process group the foreground of the caller's
    /// terminal, standard input: the caller decided at the launch that it
    /// lends the terminal, as [`Foreground`](super::Foreground) describes.
    pub(super) take_foreground: bool,
    /// One slot per op of the mount profile, allocated by the caller, where the
    /// setup keeps the descriptor of what an op mounted while a later step
    /// resolves a path beneath it, and a hidden directory's tmpfs until the
    /// profile is in place and the tmpfs is made read-only. The caller's copy
    /// stays empty.
    pub(super) mounts: &'a [MountSlot],
    /// The `cgroup.procs` of the sandbox's leaf cgroup, when the launch has a
    /// cgroup: the launch stage writes itself into it before anything else.
    pub(super) cgroup_procs_fd: Option<BorrowedFd<'a>>,
    /// The process that holds a running sandbox's namespaces, when this
    /// launch is a further command joining that sandbox rather than a sandbox
    /// of its own: its init, or without a PID namespace the launch stage that
    /// supervises its first command from outside. The launch stage joins those
    /// namespaces in place of creating its own; see [`join_sandbox`].
    pub(super) join: Option<JoinTarget<'a>>,
}

impl Context<'_> {
    /// Whether the process that forks the command gives it a process group of
    /// its own in the caller's session: the init, or for a joining launch the
    /// command itself; see [`LaunchPlan::own_process_group`].
    fn own_process_group(&self) -> bool {
        self.plan.own_process_group(self.terminal.is_some())
    }

    /// Whether this launch joins a running sandbox; see
    /// [`join`](Self::join).
    fn joins(&self) -> bool {
        self.join.is_some()
    }

    /// Whether the launch stage supervises the command from outside the
    /// sandbox's PID namespace: where the sandbox has none, and wherever the
    /// launch joins a running sandbox, whose init is the first command's.
    fn supervised_outside(&self) -> bool {
        self.joins() || !self.plan.pid_namespace
    }

    /// Whether the launch stage holds the namespaces a further command joins:
    /// the stage of a container's first command without a PID namespace; see
    /// [`withhold_stage`].
    fn holds_sandbox(&self) -> bool {
        matches!(self.plan.confinement, super::Confinement::Container)
            && !self.joins()
            && !self.plan.pid_namespace
    }
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
    // Every signal stays blocked. This process is in the caller's process
    // group, and where it supervises from outside it outlives the setup as the
    // command's supervisor, which must not end because a signal was sent to
    // that group, or by a process of the sandbox. Blocked from the fork on, a
    // signal that arrives waits until the supervisor ignores it, which
    // discards it; see `ignore_outside_signals`. `SIGCHLD` stays blocked too,
    // for good: the supervisor reads it from a descriptor, and one delivered
    // at its default disposition before that would be discarded.
    reset_signals(&SigSet::all()).map_err(|errno| (SetupStep::ResetSignals, errno, 0))?;

    // Every standard number the caller left closed, held before anything here
    // creates a descriptor that would land on it. Nothing above created one,
    // and the fork's pidfd is the caller's alone.
    hold_closed_streams(context.null_fd).map_err(|errno| (SetupStep::SweepFds, errno, 0))?;

    // The sandbox's leaf cgroup, before any namespace: every process forked
    // from here on is charged to the cgroup above it that holds the limits,
    // and the cgroup namespace the unshare below creates is rooted at the
    // leaf, below them. A joining launch's stage stays where the caller is:
    // it supervises a further command from outside the sandbox, and a kill of
    // the sandbox's tree must not take that command's supervisor with it, or
    // nothing would report the command's end. Its command joins instead, first
    // of all.
    if let Some(procs) = context.cgroup_procs_fd
        && !context.joins()
    {
        join_cgroup(procs)?;
    }

    // New namespaces, owned by the new user namespace, over which this
    // process holds full capabilities: the sandbox setup below is
    // unprivileged operations against namespaces this process owns. With a
    // PID namespace requested, this process stays outside it; the child
    // process forked next is its PID 1. A restriction creates no namespaces
    // at all — that is its defining degradation. Nor does a launch that joins a
    // running sandbox: it joins that sandbox's below, once the descriptors it
    // keeps are the only ones left.
    if matches!(plan.confinement, super::Confinement::Container) && !context.joins() {
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

    // Where this stage supervises from outside the sandbox's PID namespace, it
    // is the delegate for the command's nested identity map, and the host's
    // `/proc` is the procfs that indexes it: the pid the fork below returns
    // names the command there, in the PID namespace this stage is in. Opened
    // now rather than after the fork, because the command's `pivot_root` acts
    // on the mount namespace this stage shares with it and would change what
    // the path resolves to, and before a join, which changes it the same way.
    let procfs = if context.supervised_outside() && delegates_nested_map(context) {
        Some(open_procfs(HOST_PROCFS).map_err(|errno| (SetupStep::OpenSandboxProcfs, errno, 0))?)
    } else {
        None
    };

    // A joining command that moves into a cgroup of its own enters the
    // sandbox's cgroup namespace itself, once it has moved; see
    // `CGROUP_NAMESPACE_AFTER_MOVE`.
    let deferred = if context.cgroup_procs_fd.is_some() {
        CGROUP_NAMESPACE_AFTER_MOVE
    } else {
        thread::UnshareFlags::empty()
    };
    let mut entry = match context.join {
        Some(target) => Some(
            join_sandbox(target, plan.unshare, deferred)
                .map_err(|errno| (SetupStep::JoinSandbox, errno, 0))?,
        ),
        None => None,
    };

    // The session keyring, the one piece of the caller's session the sweep
    // cannot reach because it is a credential rather than a descriptor. Every
    // sandbox stage is forked from this process, so replacing it here replaces
    // it for all of them, in a restriction as in a container, and so does the
    // filter installed where it cannot be replaced.
    replace_session_keyring(plan).map_err(|errno| (SetupStep::ReplaceSessionKeyring, errno, 0))?;

    // Establish the identity map, after the sweep so the map gate survives
    // it, and before any further fork so every sandbox stage runs in a
    // fully mapped namespace. This stage is the process that unshared, so
    // its /proc/self map files name the new namespace. A joining launch
    // entered a namespace whose map is in force already.
    if matches!(plan.confinement, super::Confinement::Container) && !context.joins() {
        establish_identity_map(context)?;
    }

    // The gate the map is established across, created immediately before the
    // fork so that this stage and the command are its only holders.
    let seam = nested_seam(procfs)?;

    // Where the init takes a process group of its own, it forks the command
    // only once this stage is gone, and watches for that through a pidfd of
    // this stage that it inherits; see `await_launch_stage`. A joining launch
    // has no init, and its command takes the group itself.
    let launch_stage = if context.own_process_group() && !context.joins() {
        Some(
            process::pidfd_open(process::getpid(), PidfdFlags::empty())
                .map_err(|errno| (SetupStep::AwaitLaunchStage, errno, 0))?,
        )
    } else {
        None
    };

    let fork_step = if context.supervised_outside() {
        SetupStep::ForkCommand
    } else {
        SetupStep::ForkInit
    };
    // SAFETY: the child process continues with frozen data and raw syscalls
    // only, per this module's constraints, and never returns.
    match unsafe { sys::fork() }.map_err(|errno| (fork_step, errno, 0))? {
        sys::Fork::Child => {
            if !context.supervised_outside() {
                // The init unblocks its own signals, once it has left the
                // caller's process group; see `take_process_group`.
                stage_init(context, launch_stage)
            } else {
                // A joining command enters the sandbox's cgroup before anything
                // else, then the cgroup namespace the launch stage left it, and
                // leaves the caller's process group as the init does for a
                // first command, for the same reason, with every signal still
                // blocked as the fork left it. The command keeps them blocked
                // until its exec is near; see `withhold_image`.
                if context.joins() {
                    if let Some(procs) = context.cgroup_procs_fd {
                        join_cgroup(procs)?;
                    }
                    if let Some(mut entry) = entry.take() {
                        entry
                            .enter(deferred)
                            .map_err(|errno| (SetupStep::JoinSandbox, errno, 0))?;
                    }
                    take_process_group(context)?;
                }
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
            // The command enters what is left of the sandbox through its own
            // copy of the entry.
            drop(entry);
            // The terminal channel is for the stage just forked, which allocates
            // the terminal and sends the primary, and the listener channel for
            // the command stage below it; this process sends over neither.
            for channel in [context.terminal_channel_fd, context.listener_channel_fd]
                .into_iter()
                .flatten()
            {
                // SAFETY: the raw descriptor is this process's own copy of the
                // channel's sandbox end, closed exactly once here and never used
                // again in this process.
                unsafe { rustix::io::close(channel.as_raw_fd()) };
            }
            drop(launch_stage);
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
            if !context.supervised_outside() {
                // The init supervises itself from inside the namespace;
                // this stage's work is done.
                sys::exit_group(0)
            }
            if !context.holds_sandbox()
                && let Err(errno) = withhold_stage()
            {
                abandon_command(child);
                return Err((SetupStep::SetNotDumpable, errno, 0));
            }
            let children = match watch_children() {
                Ok(children) => children,
                Err(errno) => {
                    abandon_command(child);
                    return Err((SetupStep::WatchCommand, errno, 0));
                }
            };
            supervisor_hygiene(context, Role::Outside);
            supervise(
                context,
                Some(pidfd.as_fd()),
                children.as_fd(),
                Some(child),
                Role::Outside,
            )
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
///
/// A launch that keeps the caller's session leaves only the caller's process
/// group, where it has a PID namespace; see [`take_process_group`].
fn start_own_session(context: &Context<'_>) -> Result<(), Failure> {
    if context.plan.own_session || context.terminal.is_some() {
        process::setsid()
            .map(|_| ())
            .map_err(|errno| (SetupStep::NewSession, errno, 0))?;
    }
    Ok(())
}

/// Moves the sandbox into a process group of its own, in the caller's session,
/// and gives that group the caller's terminal where the caller lent it.
///
/// A signal sent to a process group reaches every member, whatever PID
/// namespace it sends from: `kill(0, sig)` goes to the sender's own group with
/// no namespace filter, and a command running as the caller's own uid passes
/// the permission check. A sandbox left in the caller's group could therefore
/// signal the caller and every process beside it, the way an interrupt typed at
/// the terminal reaches them all. In a group of its own, a signal it sends to
/// its group reaches the sandbox's own processes, and one sent to any other
/// group names a group its PID namespace cannot see. The command and every
/// process it starts inherit the group.
///
/// Only the launches that keep the caller's session need this, and only where
/// the sandbox has a PID namespace; see
/// [`LaunchPlan::own_process_group`](super::LaunchPlan::own_process_group).
/// A session of the sandbox's own is a process group of its own already, and
/// without a PID namespace the command shares the caller's PID space and can
/// name the caller's processes directly, which a group does not change.
///
/// The group takes the terminal's foreground when
/// [`take_foreground`](Context::take_foreground) says the caller lent it, so a
/// `^C` typed at the terminal reaches the command and a read of the terminal
/// is not a background read. It does so before the command exists, so the
/// command never touches the terminal from a background group.
///
/// Called by the init, first, or for a launch that joins a running sandbox by
/// its command, first, with every signal still blocked as the fork left it, and
/// that is a requirement rather than an order of convenience. The group
/// is a background group of the terminal until the call that makes it the
/// foreground, and the kernel answers that call from a background group by
/// sending `SIGTTOU` to the group and restarting the call, unless the caller
/// blocks or ignores the signal. The init, the namespace's PID 1, ignores a
/// signal at its default disposition, so with `SIGTTOU` unblocked the call
/// would restart forever, and a joining command, which is no PID 1, would be
/// stopped. Blocked, the kernel lets the call through.
///
/// The init's own `setpgid` creates the group, and the launch stage does not
/// set it a second time from outside, as a shell does for a job it is about to
/// hand the terminal. A shell needs the second call because the shell itself
/// acts on the group next; here nothing outside the init acts on it before the
/// init has created it, and the init takes the foreground itself.
fn take_process_group(context: &Context<'_>) -> Result<(), Failure> {
    if !context.own_process_group() {
        return Ok(());
    }
    process::setpgid(None, None).map_err(|errno| (SetupStep::NewProcessGroup, errno, 0))?;
    if context.take_foreground {
        termios::tcsetpgrp(rustix::stdio::stdin(), process::getpgrp())
            .map_err(|errno| (SetupStep::TakeForeground, errno, 0))?;
    }
    Ok(())
}

/// Waits until the launch stage has exited, through the pidfd of it the init
/// inherited.
///
/// The launch stage, in the caller's process group, is the init's parent until
/// it exits, and its exit is what usually leaves the sandbox's group without a
/// member whose parent is in another group of the same session: an orphaned
/// group, in the kernel's terms. The kernel discards the terminal's stop
/// signals for such a group, which is what makes `^Z` harmless there. At the
/// moment a group becomes orphaned, though, it sends `SIGHUP` and then
/// `SIGCONT` to the whole group if any member is stopped. A command forked
/// before the launch stage exits could be stopped by a `^Z` in that window and
/// then hung up as the stage exits. Forked only afterwards, the command is
/// never a member at that moment, and the init itself is never stopped by the
/// terminal.
fn await_launch_stage(launch_stage: Option<OwnedFd>) -> Result<(), Failure> {
    if let Some(stage) = launch_stage {
        super::await_exit(stage.as_fd())
            .map_err(|errno| (SetupStep::AwaitLaunchStage, errno, 0))?;
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
/// the managed `devpts` instance's `0620`. Under a
/// [`present_as`](crate::CageBuilder::present_as) identity there is nothing to
/// give: the sandbox's namespace maps no id but its own root, which the
/// replica already belongs to, and the command's nested map presents that root
/// as the presented identity, which a matching run-as identity is. The replica
/// is the command's as it stands.
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
    if let Some(run_as) = &context.plan.run_as
        && context.plan.present_as.is_none()
    {
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

/// Stage init: PID 1 of the new PID namespace. Leaves the caller's session or
/// process group, sets the sandbox up, forks the command as PID 2 once the
/// launch stage is gone, and supervises it from inside.
///
/// `launch_stage` is a pidfd of the launch stage, present where the init takes
/// a process group of its own; see [`await_launch_stage`].
///
/// Entered with every signal blocked, as the fork left it. The mask is
/// replaced only once [`take_process_group`] is behind it, and with the
/// supervisor's own mask rather than an empty one: `SIGCHLD` stays blocked for
/// the descriptor [`supervise`] reads it from.
fn stage_init(context: &Context<'_>, launch_stage: Option<OwnedFd>) -> ! {
    let detached = start_own_session(context)
        .and_then(|()| take_process_group(context))
        .and_then(|()| {
            replace_mask(&SUPERVISOR_MASK).map_err(|errno| (SetupStep::ResetSignals, errno, 0))
        });
    if let Err((step, errno, detail)) = detached {
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
    if let Err((step, errno, detail)) = await_launch_stage(launch_stage) {
        report(context.report_fd, step, errno, detail);
        sys::exit_group(127)
    }
    if !context.plan.runs_command {
        drop(seam);
        drop(replica);
        hold_sandbox(context)
    }

    // SAFETY: as at every fork here: the child process touches only frozen
    // data and raw syscalls, and never returns.
    match unsafe { sys::fork() } {
        Err(errno) => {
            report(context.report_fd, SetupStep::ForkCommand, errno, 0);
            sys::exit_group(127)
        }
        Ok(sys::Fork::Child) => {
            // The command keeps every signal blocked until its exec is near;
            // see `withhold_image`. It keeps its own end of the gate and drops
            // the delegate's side of the seam, which is not its to hold.
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
            // The listener channel is the command's to send over, and the
            // caller reads end-of-file on it only once this copy is gone too.
            if let Some(channel) = context.listener_channel_fd {
                // SAFETY: the raw descriptor is this process's own copy of the
                // channel's sandbox end, closed exactly once here and never
                // used again in this process.
                unsafe { rustix::io::close(channel.as_raw_fd()) };
            }
            // The descriptors the supervisor sleeps on, the command's pidfd
            // and its children's signals; opened before anything else so a
            // failure is still reportable.
            let watched = process::pidfd_open(command, PidfdFlags::empty())
                .and_then(|pidfd| watch_children().map(|children| (pidfd, children)));
            let (pidfd, children) = match watched {
                Ok(watched) => watched,
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
            supervise(
                context,
                Some(pidfd.as_fd()),
                children.as_fd(),
                Some(command),
                Role::Init,
            )
        }
    }
}

/// Holds a sandbox started with no command of its own, as its init: in place of
/// forking a command, waits at the gate where the launch is held there, and then
/// supervises the sandbox until it is ended.
///
/// The gate is the one a command waits at before its own confinement, and the
/// init reports itself held at it as a command does, so a caller attaches a
/// network stack to a started sandbox as to any other. The listener channel
/// has no command to send over it, and this process's copy closes, so the
/// caller's end reads end-of-file.
///
/// The supervisor then has nothing of its own to wait for. A further command
/// joins the sandbox from outside, and what it leaves behind is reparented here
/// and collected. The sandbox ends when the caller ends it, and on a
/// termination request once every process of it has ended; see [`supervise`].
fn hold_sandbox(context: &Context<'_>) -> ! {
    if let Some(channel) = context.listener_channel_fd {
        // SAFETY: the raw descriptor is this process's own copy of the
        // channel's sandbox end, closed exactly once here and never used again
        // in this process.
        unsafe { rustix::io::close(channel.as_raw_fd()) };
    }
    if let Some(proceed) = context.proceed_fd {
        report_held(context.report_fd);
        if let Err((step, errno)) = await_proceed(proceed) {
            report(context.report_fd, step, errno, 0);
            sys::exit_group(127)
        }
    }
    let children = match watch_children() {
        Ok(children) => children,
        Err(errno) => {
            report(context.report_fd, SetupStep::WatchCommand, errno, 0);
            sys::exit_group(127)
        }
    };
    supervisor_hygiene(context, Role::Init);
    supervise(context, None, children.as_fd(), None, Role::Init)
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
/// the same for its own children, through the pidfds their forks opened,
/// because the caller may run a reaper of its own. The command needs none: it
/// is this process's unreaped child process until the wait below, and nothing
/// else in this process reaps, so the number names nothing else.
fn abandon_command(command: Pid) {
    let _ = process::kill_process(command, Signal::KILL);
    let _ = frame::retry_on_intr!(process::waitpid(Some(command), WaitOptions::empty()));
}

/// Stage command, supervised from outside by the launch stage: setup and exec
/// in one process. In a container without a PID namespace the setup is the
/// full sandbox sequence. In a restriction there is nothing to build, and in a
/// launch that joins a running sandbox everything is built already, so only
/// the working directory changes.
fn stage_command(context: &Context<'_>, nested_gate: Option<OwnedFd>) -> ! {
    let setup = start_own_session(context).and_then(|()| match context.plan.confinement {
        _ if context.joins() => enter_workdir(context),
        // The setup opens no procfs here: without a PID namespace the delegate
        // for the nested map is the launch stage, outside, which holds the
        // host's own.
        super::Confinement::Container => setup_sandbox(context).map(|_| ()),
        #[cfg(feature = "hardening")]
        super::Confinement::Restriction => enter_workdir(context),
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

/// The setup of a command whose root is in place already: no namespaces to
/// configure and no root to swap, only the working directory to change,
/// before the hardening and the exec. A restriction's root is the host's, and
/// a joining command's is the running sandbox's, which the join made its root.
///
/// The root is the working directory a plan carrying none means, exactly as it
/// is for a cage: `validate_workdir` collapses `/` to no workdir at all, so an
/// absent one and an explicit `/` are the same request. A cage arrives there by
/// the unconditional `chdir` its pivot ends with, and a restriction pivots
/// nothing, so it says so here. Without it the command would inherit the
/// caller's own directory, which is a different command each time it is
/// launched from somewhere else.
fn enter_workdir(context: &Context<'_>) -> Result<(), Failure> {
    let workdir = match &context.plan.workdir {
        Some(workdir) => workdir.as_c_str(),
        None => c"/",
    };
    process::chdir(workdir).map_err(|errno| (SetupStep::ChdirWorkdir, errno, 0))?;
    Ok(())
}

/// Moves this process into the sandbox's leaf cgroup through its
/// `cgroup.procs`, where `0` names the writing process.
fn join_cgroup(procs: BorrowedFd<'_>) -> Result<(), Failure> {
    rustix::io::write(procs, b"0")
        .map(drop)
        .map_err(|errno| (SetupStep::JoinCgroup, errno, 0))
}

/// Joins a running sandbox: enters every namespace the sandbox's own launch
/// created, `namespaces`, the plan's unshare flags.
///
/// Those flags are the running sandbox's, since a joining launch's plan is its
/// sandbox's with the command's own fields replaced. A flag the sandbox did not
/// unshare would name the holder's instance of that namespace, the caller's
/// own, over which the joined user namespace grants nothing, and the join would
/// fail.
///
/// The user namespace is entered first and the others with the capabilities
/// its root holds, which this process has as the namespace's owner. Joining the
/// mount namespace makes its root this process's root and working directory:
/// the sandbox's own, as its pivot left it. A PID namespace is the one this
/// process's children are created in, so the command is forked after this, and
/// this process stays in the caller's, outside the sandbox's.
///
/// Those of `deferred` are left out, for the command to enter once it has
/// moved into its cgroup, through the entry this returns.
///
/// A holder that has exited answers `ESRCH`: the sandbox has ended. One that
/// exits after this, before the fork, fails the fork with `ENOMEM` instead.
fn join_sandbox<'a>(
    target: JoinTarget<'a>,
    namespaces: thread::UnshareFlags,
    deferred: thread::UnshareFlags,
) -> Result<SandboxEntry<'a>, Errno> {
    let mut entry = SandboxEntry::new(target, namespaces);
    entry.enter(namespaces.difference(deferred))?;
    Ok(entry)
}

/// The namespace a joining command that moves into a cgroup of its own enters
/// itself, once it has moved, rather than the launch stage before the fork.
///
/// A kernel without the fix for CVE-2021-4197, from Linux 5.16 and in the
/// stable kernels it reached, judges a write to `cgroup.procs` by the writer's
/// cgroup namespace rather than the opener's. Under `nsdelegate`, which systemd
/// mounts the hierarchy with, the source and the destination cgroup must both
/// lie beneath that namespace's root, and the command's source, the caller's
/// cgroup, does not lie beneath the sandbox's. Moved from the caller's cgroup
/// namespace, the command is judged by the caller's, as every kernel judges it
/// by the opener's.
const CGROUP_NAMESPACE_AFTER_MOVE: thread::UnshareFlags = thread::UnshareFlags::NEWCGROUP;

/// The namespaces a launch unshares, each with the name of its
/// `/proc/<pid>/ns` entry, in the order a join enters them: the user namespace
/// first, for the capabilities joining each of the others takes.
const NAMESPACE_FILES: [(thread::UnshareFlags, &CStr); 7] = [
    (thread::UnshareFlags::NEWUSER, c"user"),
    (thread::UnshareFlags::NEWNS, c"mnt"),
    (thread::UnshareFlags::NEWUTS, c"uts"),
    (thread::UnshareFlags::NEWIPC, c"ipc"),
    (thread::UnshareFlags::NEWPID, c"pid"),
    (thread::UnshareFlags::NEWCGROUP, c"cgroup"),
    (thread::UnshareFlags::NEWNET, c"net"),
];

/// A running sandbox's namespaces, as a launch joining it enters them.
///
/// Through a pidfd of the holder, with one `setns` (Linux 5.8). A kernel that
/// joins nothing through a pidfd answers that `setns` with `EINVAL`, and the
/// namespaces are then opened through `/proc/<pid>/ns` under the holder's pid,
/// in the procfs of the caller's mount namespace, and entered one by one.
///
/// That is the read-then-check pattern
/// [`Namespaces::of`](super::netns::Namespaces::of) holds a pid to, in a form a
/// process after a fork can take, with every descriptor on the stack: every
/// file is opened before the pidfd is asked whether the holder has exited, so a
/// holder still running was running when they were opened, and they are its.
/// One that has exited is refused with `ESRCH`, as a pidfd's join refuses it.
struct SandboxEntry<'a> {
    /// The holder, by pidfd and by pid.
    target: JoinTarget<'a>,
    /// Every namespace the sandbox has.
    sandbox: thread::UnshareFlags,
    /// Each namespace of [`sandbox`](Self::sandbox), at its place in
    /// [`NAMESPACE_FILES`], once the pidfd's join was refused; empty until
    /// then.
    opened: [Option<OwnedFd>; NAMESPACE_FILES.len()],
}

impl<'a> SandboxEntry<'a> {
    /// The sandbox `target` holds, which has the namespaces of `sandbox`.
    fn new(target: JoinTarget<'a>, sandbox: thread::UnshareFlags) -> SandboxEntry<'a> {
        SandboxEntry {
            target,
            sandbox,
            opened: [const { None }; NAMESPACE_FILES.len()],
        }
    }

    /// Enters those of the sandbox's namespaces `namespaces` names.
    ///
    /// The first entry that falls back to the procfs opens every namespace of
    /// the sandbox's, before entering any, so a later entry still finds those
    /// it did not enter, by the procfs that indexed the holder: the command
    /// enters through its copy of the entry from a mount namespace in which
    /// that procfs is no longer the one at `/proc`.
    fn enter(&mut self, namespaces: thread::UnshareFlags) -> Result<(), Errno> {
        if namespaces.is_empty() {
            return Ok(());
        }
        if self.opened.iter().all(Option::is_none) {
            match thread::move_into_thread_name_spaces(
                self.target.holder,
                thread::ThreadNameSpaceType::from_bits_retain(namespaces.bits()),
            ) {
                Err(Errno::INVAL) => self.open()?,
                joined => return joined,
            }
        }
        for ((namespace, _), opened) in NAMESPACE_FILES.iter().zip(&self.opened) {
            if let (true, Some(opened)) = (namespaces.contains(*namespace), opened) {
                thread::move_into_link_name_space(opened.as_fd(), None)?;
            }
        }
        Ok(())
    }

    /// Opens every namespace of the sandbox's through `/proc/<pid>/ns`, held
    /// to the holder's pidfd.
    ///
    /// The pidfd is asked once every open is done, failed or not: an exited
    /// holder's entries name nothing to enter, or by then another process's,
    /// and either way the sandbox has ended.
    fn open(&mut self) -> Result<(), Errno> {
        let opened = self.open_each();
        if super::has_exited(self.target.holder) {
            return Err(Errno::SRCH);
        }
        opened
    }

    /// Opens each namespace of the sandbox's under the holder's pid, stopping
    /// at the first that fails.
    fn open_each(&mut self) -> Result<(), Errno> {
        for ((namespace, name), slot) in NAMESPACE_FILES.iter().zip(&mut self.opened) {
            if self.sandbox.contains(*namespace) {
                let mut path = StackPath::new();
                path.push(b"/proc/");
                path.push_decimal(self.target.pid);
                path.push(b"/ns/");
                path.push(name.to_bytes());
                *slot = Some(fs::open(
                    path.as_cstr(),
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
            }
        }
        Ok(())
    }
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

    // Every identity map that needed this process dumpable is written, so it
    // is made not dumpable, and only then are its signals unblocked.
    if let Err((step, errno)) = withhold_image() {
        report(context.report_fd, step, errno, 0);
        sys::exit_group(127)
    }

    // The network filter, wherever the sandbox has a network namespace of its
    // own: it refuses the routes out that a network namespace does not cover,
    // and it is not opt-in, since without it the namespace's isolation is not
    // what the network posture says it is. See `seccomp::NETWORK_FILTER`.
    //
    // Installed here, after the nested user namespace is entered: creating one
    // grants the CAP_SYS_ADMIN that an install without no-new-privileges
    // requires, and nothing has set no-new-privileges yet. The hardening layer
    // and the identity switch set it below, and only where a hardening
    // control, a run-as identity, or a presented identity asks for it. A
    // filter survives every step below, including the identity switch and the
    // exec. Installed before the hardening layer, so a caller's own policy
    // stacks on top of it and, where both answer a syscall with an errno,
    // answers with its own.
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
    if let Err((step, errno, detail)) =
        super::harden::apply_post_switch(&context.plan.hardening, context.listener_channel_fd)
    {
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
/// [`StdioPlan::Fd`](super::StdioPlan::Fd) can be low. The launch keeps its own
/// channels above them, the null descriptor and the capture pipes among them
/// (see [`above_stdio`](super::above_stdio)), and the terminal replica is
/// opened once [`hold_closed_streams`] holds every standard number the caller
/// left closed, so it cannot land on one either. With three streams to wire, a
/// low source is not merely the `dup2(fd, fd)` no-op that leaves close-on-exec
/// set: wiring one stream would *destroy* the source another had not been
/// copied from yet. With standard input on the caller's descriptor 1 and
/// standard output somewhere else, the `dup2` onto 1 would take standard
/// input's source with it.
///
/// A stream the plan leaves inherited is not touched. Where the caller had
/// closed it, its number holds the launch stage's close-on-exec placeholder,
/// and the exec closes it: the command finds the stream closed, as the caller
/// had it, and no channel of the launch's in its place.
fn wire_stdio(context: &Context<'_>, terminal: Option<BorrowedFd<'_>>) -> Result<(), Errno> {
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
            && source.as_raw_fd() <= STDERR_FILENO
        {
            *slot = Some(rustix::io::fcntl_dupfd_cloexec(source, STDERR_FILENO + 1)?);
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
            && caller.as_raw_fd() > STDERR_FILENO
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
/// through `execve` open. The provisioners apply a tree's permission bits
/// verbatim, so a Debian or Alpine tree ships set-user-ID binaries owned by
/// in-namespace uid 0 and file capabilities to match. The root carries `nosuid`
/// (see `nosuid_root`), but a caller's bind or raw mount keeps its source's
/// flags, and below Linux 5.12 so does every mount the rootfs bind carried
/// along. Without the flag, the non-root command executes such a binary on one
/// of them and is root inside again.
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
        /// The procfs the writing process reaches its own map files through,
        /// by `self`: the host's at [`HOST_PROCFS`], or, for the nested user
        /// namespace a command enters after the root swap, wherever the mount
        /// profile put one.
        procfs: &'a CStr,
        /// The `uid_map` line.
        uid_line: &'a [u8],
        /// The `gid_map` line.
        gid_line: &'a [u8],
    },
    /// Signal ready on the map gate and block until the delegate has written a
    /// range map from outside.
    Await,
}

/// The host's procfs, where a process that has not swapped its root reaches
/// its own map files.
pub(super) const HOST_PROCFS: &CStr = c"/proc";

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
/// before it touches the tree it was forked for, and every probe that asks the
/// kernel something only a mapped user namespace can ask.
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
/// neither report the failure nor exit on its own terms. A probe writes to no
/// pipe, and the ignored signal changes nothing for it.
///
/// `also` is what is unshared beside the user namespace, in the same call, so
/// the user namespace owns it: a mount namespace for a probe that mounts, and
/// a PID namespace for one whose next child must be that namespace's first
/// process. A provisioning child unshares nothing else, and its work runs on
/// the caller's own mount view, through real paths, as root of the mapped
/// namespace.
///
/// Post-fork safe: no allocation, no locking, and no panic.
pub(super) fn enter_mapped_namespace(
    keep: &[RawFd],
    also: thread::UnshareFlags,
    duty: MapDuty<'_>,
    gate: Option<BorrowedFd<'_>>,
) -> Result<(), MapFailure> {
    reset_signals(&SigSet::empty())
        .map_err(|errno| MapFailure::Step(MapStep::ResetSignals, errno))?;
    ignore_sigpipe().map_err(|errno| MapFailure::Step(MapStep::ResetSignals, errno))?;
    sweep_fds_keeping(keep).map_err(|errno| MapFailure::Step(MapStep::SweepFds, errno))?;
    // SAFETY: the callers never ask for the descriptor table, and this process
    // is a freshly forked single-threaded child besides.
    unsafe { thread::unshare_unsafe(thread::UnshareFlags::NEWUSER | also) }
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
            procfs,
            uid_line,
            gid_line,
        } => {
            let procfs = open_procfs(procfs)
                .map_err(|errno| MapFailure::Step(MapStep::DenySetgroups, errno))?;
            write_in_procfs(procfs.as_fd(), c"self/setgroups", b"deny")
                .map_err(|errno| MapFailure::Step(MapStep::DenySetgroups, errno))?;
            write_in_procfs(procfs.as_fd(), c"self/gid_map", gid_line)
                .map_err(|errno| MapFailure::Step(MapStep::WriteGidMap, errno))?;
            write_in_procfs(procfs.as_fd(), c"self/uid_map", uid_line)
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
            procfs: HOST_PROCFS,
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
        super::NestedMap::SelfWritten { procfs } => MapDuty::Write {
            // The root was swapped before this stage ran, or the stage joined a
            // sandbox whose root is, so the map files are reached through the
            // procfs the mount profile established.
            procfs,
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

/// The mount op whose procfs a delegate inside the sandbox writes the command's
/// map files through, or `None` where this stage is not that delegate.
///
/// Only a delegated map inside a PID namespace has its delegate in here; a
/// self-written map has no delegate at all, and a delegated map without a PID
/// namespace is written by the launch stage, outside, through the host's own
/// `/proc`. The build names an op for that one case and for no other, so a
/// `None` here is the same condition as the build having required no procfs.
fn nested_procfs_op(context: &Context<'_>) -> Option<usize> {
    if !context.plan.pid_namespace {
        return None;
    }
    match &context.plan.nested.as_ref()?.map {
        super::NestedMap::Delegated { procfs_op } => *procfs_op,
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

    // The gid map, then the uid map, the order `establish_map` writes them in.
    // Neither order is forced for a privileged writer, and the caller's
    // delegates for the launch's own map write the uid map first. `setgroups`
    // is left at `allow` — a privileged writer needs no denial, and denying it
    // would cost the supplementary groups a run-as identity sets.
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
    write_in_procfs(procfs, map_file_path(pid, file).as_cstr(), data)
}

/// Opens the procfs at `path`, refusing anything that is not one: what an
/// identity map is written through.
///
/// A map file the kernel does not provide accepts the map's bytes as readily as
/// a real one, and the map is then not in force: a directory of a root two
/// sandboxes share, put where the procfs was mounted, holds whatever another
/// process wrote there. The descriptor is checked to be a procfs, and every
/// file is opened beneath it with [`write_in_procfs`]. `EMEDIUMTYPE` refuses
/// another filesystem.
pub(super) fn open_procfs(path: &CStr) -> Result<OwnedFd, Errno> {
    let procfs = fs::open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    ensure_procfs(procfs.as_fd())?;
    Ok(procfs)
}

/// Refuses, with `EMEDIUMTYPE`, a descriptor that is not of a procfs.
fn ensure_procfs(procfs: BorrowedFd<'_>) -> Result<(), Errno> {
    match fs::fstatfs(procfs)?.f_type == fs::PROC_SUPER_MAGIC {
        true => Ok(()),
        false => Err(Errno::MEDIUMTYPE),
    }
}

/// Opens `path` beneath the procfs `procfs` names and writes `data` in a
/// single `write`, on the terms [`frame::write_whole`] states for the
/// identity-map files.
///
/// The open stays beneath the procfs (`RESOLVE_BENEATH`), crosses no mount
/// (`RESOLVE_NO_XDEV`), so no file bound over a map file stands in for it, and
/// follows no magic link (`RESOLVE_NO_MAGICLINKS`). An ordinary link is
/// followed, since a process's own files are reached through `self`, which in
/// a procfs is the kernel's link to the reader's own entry.
fn write_in_procfs(procfs: BorrowedFd<'_>, path: &CStr, data: &[u8]) -> Result<(), Errno> {
    let file = resolve::openat2(
        procfs,
        path,
        OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
    )?;
    frame::write_whole(file.as_fd(), data)
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
/// the descriptor of the procfs the mount profile made, which the setup keeps
/// from the moment it is mounted, so nothing put at the procfs's path later,
/// within the launch or by a process sharing the root, stands in for it. A
/// procfs a raw mount made is opened again by name once it is mounted, as
/// every raw mount the setup needs again is; see [`execute_op`].
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
    // canonical path frozen at build time is opened here, inside the new
    // namespace, without following a link (see `open_frozen`): a mount refuses
    // sources and targets whose mounts are not attached in the caller's
    // namespace, so a descriptor opened before `unshare` cannot anchor this
    // step. The overlay mounts as root inside the now-established identity
    // map, so its copy-up ownership resolves against that map. An empty root
    // has no path; see `mount_empty_root`.
    //
    // Each root carries `nosuid`; see `nosuid_root`. An overlay and an empty
    // root take it at their own mount, where the flag applies directly and no
    // fallback is needed; a bind inherits its source's flags instead and has
    // the attribute added once there is a descriptor for the mount to add it
    // to, before the profile's own mounts, so the recursion covers the root
    // bind and whatever it carried along and nothing the caller went on to
    // mount: a caller's bind keeps its source's flags.
    //
    // The root is mounted detached and attached onto the descriptor of the
    // path, and the descriptor of the mount itself anchors both the
    // mount-target resolution below and the pivot, so no path names the root
    // again.
    let newroot = match &plan.root {
        RootPlan::Bind(rootfs) => {
            let failed = |errno| (SetupStep::BindRootfs, errno, 0);
            let rootfs = open_frozen(rootfs, OFlags::DIRECTORY).map_err(failed)?;
            let newroot = clone_tree(rootfs.as_fd()).map_err(failed)?;
            attach(newroot.as_fd(), rootfs.as_fd()).map_err(failed)?;
            nosuid_root(newroot.as_fd()).map_err(|errno| (SetupStep::NosuidRootfs, errno, 0))?;
            newroot
        }
        RootPlan::Overlay { base, overlay } => {
            let failed = |errno| (SetupStep::MountOverlayRoot, errno, 0);
            let base = open_frozen(base, OFlags::DIRECTORY).map_err(failed)?;
            let layers = OverlayLayers {
                base: base.as_fd(),
                stacked: overlay.lower.get(1..).unwrap_or_default(),
                upper: &overlay.upper,
                work: &overlay.work,
            };
            let newroot = mount_overlay(&layers).map_err(failed)?;
            attach(newroot.as_fd(), base.as_fd()).map_err(failed)?;
            newroot
        }
        RootPlan::Empty => {
            mount_empty_root().map_err(|errno| (SetupStep::MountEmptyRoot, errno, 0))?
        }
        RootPlan::HostReadOnly => {
            mount_host_root().map_err(|errno| (SetupStep::MountHostRoot, errno, 0))?
        }
        // A sandbox's plan always names a root to pivot into, and a
        // restriction's never reaches this stage.
        RootPlan::Host => return Err((SetupStep::EnterRootfs, Errno::INVAL, 0)),
    };

    // The mount profile: host bind sources are still resolvable (the host
    // tree is mounted until the pivot), and every target resolves inside
    // the new root, from the mount it lies beneath (see `Profile`). What an op
    // mounted is kept, in the slot the caller allocated for it, while a later
    // step still resolves beneath it, and a hidden directory's tmpfs until
    // nothing more is made in it.
    let procfs_op = nested_procfs_op(context);
    let profile = Profile {
        root: newroot.as_fd(),
        ops: &plan.ops,
        slots: context.mounts,
        procfs: procfs_op,
    };
    for index in 0..plan.ops.len() {
        execute_op(&profile, index, context.report_fd)
            .map_err(|(step, errno)| (step, errno, index as u32 + 1))?;
    }

    // The procfs the command's nested identity map will be written through,
    // taken only where this stage is the delegate for it. The mount profile
    // has just established it, and the build refused a profile that establishes
    // none for a configuration that reaches here.
    let procfs = match procfs_op {
        Some(op) => {
            let procfs = context
                .mounts
                .get(op)
                .and_then(|slot| slot.mount.take())
                .ok_or((SetupStep::OpenSandboxProcfs, Errno::BADF, 0))?;
            ensure_procfs(procfs.as_fd())
                .map_err(|errno| (SetupStep::OpenSandboxProcfs, errno, 0))?;
            Some(procfs)
        }
        None => None,
    };

    // Last of all, once nothing more is made in them: every hidden
    // directory, and an empty root.
    for (index, op) in plan.ops.iter().enumerate() {
        let Some(slot) = context.mounts.get(index) else {
            continue;
        };
        if let (MountAction::Hide { .. }, Some(hidden)) = (&op.action, slot.mount.take()) {
            let made = is_directory(hidden.as_fd())
                .and_then(|directory| match directory {
                    true => read_only_mount(hidden.as_fd()),
                    false => Ok(()),
                })
                .map_err(|errno| (SetupStep::HidePath, errno, index as u32 + 1));
            slot.mount.set(Some(hidden));
            made?;
        }
    }
    if matches!(plan.root, RootPlan::Empty) {
        read_only_mount(newroot.as_fd())
            .map_err(|errno| (SetupStep::ReadOnlyEmptyRoot, errno, 0))?;
    }

    // Then the name of every path made read-only, now that each mount a hold
    // clones carries the flags it ends with.
    for (index, op) in plan.ops.iter().enumerate() {
        if let MountAction::ReadOnly { parent, .. } = &op.action {
            hold_name(&profile, index, parent)
                .map_err(|(step, errno)| (step, errno, index as u32 + 1))?;
        }
    }

    // Nothing past the profile resolves beneath a mount it kept.
    for slot in context.mounts {
        drop(slot.mount.take());
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
            if fd > STDERR_FILENO && !caller[..index].contains(&fd) {
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

/// The signal mask every supervisor runs under: `SIGCHLD` alone.
///
/// The supervisor reads `SIGCHLD` from a descriptor, which sees a signal only
/// while it is blocked; see [`watch_children`]. Its disposition stays the
/// default in every process here, because the disposition decides who reaps
/// the supervisor's children: ignored, the kernel would collect the command
/// itself, and the supervisor's wait would never see its status.
const SUPERVISOR_MASK: SigSet = SigSet::of(&[Signal::CHILD]);

/// Ignores every signal but `SIGCHLD`, then unblocks all but `SIGCHLD`: the
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
/// request, a request to end the sandbox, and the caller's exit reach it over
/// the control socket, and a kill goes to the command through the command's
/// pidfd. Only the teardown of a launch being given up on ends it, with
/// `SIGKILL`, which no disposition stops.
///
/// The signals the kernel raises on a fault, `SIGSEGV`, `SIGBUS`, `SIGILL`,
/// `SIGFPE`, `SIGTRAP` and `SIGSYS`, are ignored with the rest. Without a PID
/// namespace the sandbox's processes run as this process's own user in its PID
/// namespace, and each of those, sent by one of them, would end this copy of
/// the caller's address space with a core dump, written where the dumping
/// process's root and working directory say, which the pivot may have made
/// the sandbox's. A fault this process raises itself is still delivered: the
/// kernel resets an ignored or blocked fault's disposition to the default as
/// it delivers it. `SIGABRT` comes from `abort`, which nothing here calls.
/// `SIGKILL` and `SIGSTOP` take no disposition, so another process can still
/// end this one, or stop it until a kill or a termination through the handle
/// continues it.
///
/// Ignored only here, after the command was forked, because an ignored
/// disposition survives `execve` and the command must start with every one at
/// its default. The launch stage has kept them blocked since its own fork, so
/// one that arrived meanwhile is pending, and ignoring it discards it: there is
/// no moment at which one reaches this process at the default.
fn ignore_outside_signals() -> Result<(), Errno> {
    for signal in every_signal() {
        if signal == Signal::KILL || signal == Signal::STOP || signal == Signal::CHILD {
            continue;
        }
        match sys::set_disposition(signal, Disposition::Ignore) {
            // Numbers the kernel reserves are skipped, as the reset skips them.
            Ok(()) | Err(Errno::INVAL) => {}
            Err(errno) => return Err(errno),
        }
    }
    // Every signal unblocked here was just ignored or keeps its default.
    replace_mask(&SUPERVISOR_MASK)
}

/// Empties the signal mask of the command, once [`withhold_image`] has made
/// it not dumpable.
///
/// [`sys::fork`] leaves every signal blocked in the child process. The
/// dispositions it inherited are its parent process's, which
/// [`reset_signals`] put back to the default and which nothing has set since,
/// so unblocking runs nothing: the command starts with the empty mask a
/// process ordinarily has.
fn unblock_signals() -> Result<(), Errno> {
    replace_mask(&SigSet::empty())
}

/// Makes the command's process not dumpable, then unblocks its signals: the
/// step between its last identity-map write and its hardening.
///
/// Until its `execve` the process is a copy of the caller's address space,
/// whatever the caller held in it. Any process running as the same user that
/// can name it may signal it, a process of the sandbox among them where it is
/// in the sandbox's PID namespace, as a further command is, or shares the
/// caller's. A signal whose default action dumps core, `SIGQUIT` or `SIGSEGV`
/// for one, would have the kernel write that copy where the core pattern says:
/// a file in the process's working directory or under its root, a container's
/// own by then, or a handler that forwards it into the process's root.
/// The process therefore keeps every signal blocked from its fork, and once it
/// is not dumpable the kernel dumps nothing, so a signal that arrived
/// meanwhile acts on its default as it is unblocked, and dumps nothing. The
/// `execve` makes the process dumpable again, as the command's own image.
///
/// Not dumpable any earlier, because the kernel gives such a process's
/// `/proc/<pid>` files to root of the caller's user namespace, and the
/// command's identity-map files are among them: neither the command writing
/// its own nested map nor the sandbox's root writing it could then write it.
///
/// What remains is a stop: `SIGSTOP` takes no mask, and a process of the
/// sandbox can still hold the command short of its exec, and the launch
/// waiting for it.
fn withhold_image() -> Result<(), (SetupStep, Errno)> {
    process::set_dumpable_behavior(process::DumpableBehavior::NotDumpable)
        .map_err(|errno| (SetupStep::SetNotDumpable, errno))?;
    unblock_signals().map_err(|errno| (SetupStep::ResetSignals, errno))
}

/// Makes a launch stage that supervises from outside, and holds nothing a
/// further command joins, not dumpable, once its command is forked.
///
/// The stage is a copy of the caller's address space for as long as it
/// supervises, and the command's processes can name it, as a further
/// command's processes can without a PID namespace and a restriction's always
/// can. [`ignore_outside_signals`] keeps a signal from making it dump; not
/// dumpable, a fault of its own dumps nothing either, and no process without
/// `CAP_SYS_PTRACE` reads it. Only after the fork, since the command inherits
/// the state and its identity maps are still to be written.
///
/// The launch stage of a container's first command without a PID namespace,
/// and the init of one with a PID namespace, stay dumpable: each holds the
/// sandbox's namespaces, and the kernel lets a further command's launch stage
/// join them through its pidfd, and a caller open them under `/proc/<pid>/ns`,
/// only while it is. Neither is exposed by it. That launch stage ignores every
/// signal that dumps, the init receives from inside its namespace no signal it
/// has no handler for, and it has none, and a command, in a user namespace of
/// its own below theirs, holds no capability over either to trace it.
fn withhold_stage() -> Result<(), Errno> {
    process::set_dumpable_behavior(process::DumpableBehavior::NotDumpable)
}

/// Replaces the signal mask of this process, every disposition of which is the
/// default or ignored: it was freshly forked from a process whose dispositions
/// [`reset_signals`] put back to the default.
fn replace_mask(mask: &SigSet) -> Result<(), Errno> {
    // SAFETY: no disposition here names a handler, so unblocking runs none;
    // the process is single-threaded.
    unsafe { sys::sigprocmask(How::SetMask, Some(mask)) }.map(|_| ())
}

/// Opens the descriptor a supervisor reads its children's `SIGCHLD` from.
///
/// The kernel sends `SIGCHLD` to a parent whenever a child exits, stops, or
/// continues, and when a tracer lets go of a child's exit that it was holding.
/// Read from a descriptor in the supervisor's poll, it wakes the supervisor for
/// each of them, including an orphan's exit once the orphan is the init's.
/// [`SUPERVISOR_MASK`] keeps it blocked from before the command is forked, so
/// one sent before the descriptor exists waits for it.
fn watch_children() -> Result<OwnedFd, Errno> {
    sys::signalfd(&SUPERVISOR_MASK)
}

/// Reads every record a signal descriptor holds, without waiting for one.
///
/// Reading dequeues the signal, so a descriptor drained before the waits it
/// woke the supervisor for becomes readable again for any change after them.
fn drain_signals(signals: BorrowedFd<'_>) {
    let mut record = [0u8; sys::SIGINFO_LEN];
    while matches!(rustix::io::read(signals, &mut record), Ok(read) if read > 0) {}
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

/// A channel of the supervisor's poll.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Watch {
    /// The descriptor the children's `SIGCHLD` arrives on.
    Children,
    /// The supervised process's pidfd, until it first reports an exit.
    Exit,
    /// The control socket, until it hangs up.
    Control,
}

/// The supervisor loop: reap, forward, watch, report.
///
/// Sleeps in one poll over the children's signal descriptor, the supervised
/// process's pidfd, and the control socket. Control traffic is a termination
/// request (SIGTERM to the command), a signal to deliver to the command, a
/// request to end the sandbox, or a hangup — the caller exited or dropped the
/// last handle — which ends the sandbox the same way when `stop_with_caller`
/// is set and is otherwise ignored; see [`end_sandbox`]. When the supervised
/// process exits, its wait status goes out over the status pipe and the
/// supervisor exits; as namespace init, that exit makes the kernel kill every
/// remaining namespace member.
///
/// Every child's exit, stop, or continuation wakes the poll through
/// `SIGCHLD`, so a zombie is collected as soon as it exits, an orphan that
/// reparented to the init included.
///
/// # A held exit
///
/// The pidfd turns readable once the supervised process has exited, and stays
/// readable from then on, so it is polled only until it first reports. Its
/// exit is not always collectable by then: a process tracing it with `ptrace`
/// holds its exit until it lets go, and until then a wait of its parent's does
/// not see it at all. As the init, the supervisor then ends every other process
/// of the namespace, as its own exit would a moment later: the tracer goes with
/// them, which lets go of the exit, and the `SIGCHLD` that follows wakes the
/// collection. Outside, the tracer is a host process the launch does not
/// govern, so the supervisor sleeps until the tracer lets go on its own.
///
/// # Stops
///
/// As the init, the supervisor continues a child that a terminal's `^Z`
/// stopped. The sandbox's process group is in the caller's session when the
/// sandbox keeps it; see [`take_process_group`]. Where the group's members
/// have no parent in another group of that session, the kernel discards a stop
/// sent by the terminal; where they do, as when the caller's reaper is a
/// subreaper in the same session, `^Z` would stop the command with nothing in
/// the sandbox to resume it. A stop by `SIGTTIN` or `SIGTTOU`, which the
/// terminal sends a background read or write, is left alone: the call that
/// raised it would raise it again as soon as the process continued. Outside,
/// the command shares the caller's process group, a stop of it is the
/// caller's job control, and the supervisor does not ask about stops.
fn supervise(
    context: &Context<'_>,
    exit: Option<BorrowedFd<'_>>,
    children: BorrowedFd<'_>,
    child: Option<Pid>,
    role: Role,
) -> ! {
    let stops = match role {
        Role::Init => WaitOptions::UNTRACED,
        Role::Outside => WaitOptions::empty(),
    };
    let mut watch_exit = exit.is_some();
    let mut watch_control = true;
    let mut released = false;
    // A sandbox with no command of its own, asked to terminate: every process
    // of it has been sent `SIGTERM`, and it ends once none is left.
    let mut terminating = false;
    loop {
        // Only the live channels are polled, gathered to the front: a retired
        // pidfd would be ready on every pass.
        let mut watched = [Watch::Children; 3];
        let mut fds = [
            PollFd::new(&children, PollFlags::IN),
            PollFd::new(&children, PollFlags::IN),
            PollFd::new(&children, PollFlags::IN),
        ];
        let mut live = 1;
        if let (true, Some(exit)) = (watch_exit, &exit) {
            watched[live] = Watch::Exit;
            fds[live] = PollFd::new(exit, PollFlags::IN);
            live += 1;
        }
        if watch_control {
            watched[live] = Watch::Control;
            fds[live] = PollFd::new(&context.control_fd, PollFlags::IN);
            live += 1;
        }
        // Terminating with no command of its own, the sandbox's other processes
        // are no children of this one, so nothing wakes it as they end: it
        // looks again at an interval instead.
        let timeout = terminating.then(|| crate::poll::timeout(ALONE_INTERVAL));
        match rustix::event::poll(&mut fds[..live], timeout.as_ref()) {
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            // An unpollable descriptor set has no recovery; exit visibly.
            // As init the exit also tears the namespace down.
            Err(_) => sys::exit_group(127),
        }
        let ready = |watch: Watch| {
            watched[..live]
                .iter()
                .zip(&fds)
                .any(|(&slot, fd)| slot == watch && !fd.revents().is_empty())
        };

        if ready(Watch::Exit) {
            watch_exit = false;
        }

        if ready(Watch::Control) {
            // Each request is one packet; a shorter one fills the front.
            let mut request = [0u8; 2];
            match rustix::io::read(context.control_fd, &mut request) {
                // Hangup: every caller-side handle is gone. A hangup stays
                // readable, so the socket is not polled again.
                Ok(0) => {
                    if context.plan.stop_with_caller {
                        end_sandbox(role, child);
                    }
                    watch_control = false;
                }
                Ok(read) => match (request[0], read) {
                    // Termination is a request to the command, not the
                    // namespace: SIGTERM is deliverable and trappable there,
                    // docker-stop style. ESRCH means it already exited; the
                    // wait below handles the rest.
                    (CONTROL_TERMINATE, _) => match child {
                        Some(child) => {
                            let _ = process::kill_process(child, Signal::TERM);
                        }
                        // With no command of its own, termination is a request
                        // to every process of the sandbox.
                        None => {
                            terminating = true;
                            let _ = sys::kill_all(Signal::TERM);
                        }
                    },
                    // A signal is the command's too, forwarded as termination
                    // is, since an init receives from outside its namespace
                    // only the signals it has a handler for. It ends nothing
                    // of the sandbox's own: with no command, every process is
                    // sent it, and the sandbox holds once they are gone.
                    (CONTROL_SIGNAL, 2) => {
                        if let Some(signal) = Signal::from_named_raw(i32::from(request[1])) {
                            let _ = match child {
                                Some(child) => process::kill_process(child, signal),
                                None => sys::kill_all(signal),
                            };
                        }
                    }
                    (CONTROL_END, _) => end_sandbox(role, child),
                    _ => {}
                },
                Err(Errno::INTR) => {}
                Err(_) => watch_control = false,
            }
        }

        // The signals first, then the waits they announced: a child that
        // changes state after the drain sends one more, which wakes the next
        // poll.
        drain_signals(children);

        // Collect zombies on every wake. The supervised process's exit ends
        // supervision: its wait status goes out over the status pipe.
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
            match process::wait(WaitOptions::NOHANG | stops) {
                Ok(Some((pid, status))) if status.stopped() => {
                    // A stopped child is this process's unreaped child, so
                    // its pid names nothing else.
                    if status.stopping_signal() == Some(Signal::TSTP.as_raw()) {
                        let _ = process::kill_process(pid, Signal::CONT);
                    }
                }
                Ok(Some((pid, status))) if Some(pid) == child => {
                    collect_exited();
                    report_status(context.status_fd, status);
                    sys::exit_group(0)
                }
                Ok(Some(_)) | Err(Errno::INTR) => {}
                Ok(None) => break,
                // With no command of its own, no child at all is the init's
                // ordinary state between further commands.
                Err(Errno::CHILD) if child.is_none() => break,
                // No children left yet no status for the supervised
                // process: something else reaped it. Unreportable;
                // exiting without a record surfaces as a lost
                // supervisor.
                Err(_) => sys::exit_group(127),
            }
        }

        // Terminating with no command of its own, and nothing left: the
        // sandbox has ended as its command's exit would end it.
        if terminating && !sys::others_remain() {
            collect_exited();
            report_outcome(context.status_fd, STATUS_EXITED, 0);
            sys::exit_group(0)
        }

        // The supervised process has exited, and no wait could collect it: a
        // tracer holds its exit. See "A held exit" above.
        if child.is_some() && !watch_exit && !released && role == Role::Init {
            let _ = sys::kill_all(Signal::KILL);
            released = true;
        }
    }
}

/// The control-socket request byte for graceful termination.
pub(crate) const CONTROL_TERMINATE: u8 = b'T';

/// The control-socket request byte that delivers a signal to the command, the
/// signal's number the request's second byte.
pub(crate) const CONTROL_SIGNAL: u8 = b'S';

/// The control-socket request byte that ends the sandbox, as a hangup does
/// under [`stop_with_caller`](crate::CageBuilder::stop_with_caller).
///
/// The caller sends it where it holds the control socket but not the
/// supervisor's pidfd, which is the one other way to end a launch: a launch
/// whose pidfd did not arrive; see `mechanism::end_unreceived`.
pub(super) const CONTROL_END: u8 = b'E';

/// Ends the sandbox from its supervisor, without waiting for the command.
///
/// As the init, the supervisor exits, and its exit has the kernel kill every
/// process of the namespace; no status is reported, since whoever asked has
/// let go of the sandbox. From outside, it kills the command and keeps
/// supervising, so the command's exit is still collected and reported.
fn end_sandbox(role: Role, child: Option<Pid>) {
    match (role, child) {
        (Role::Init, _) => sys::exit_group(1),
        // The command is this process's unreaped child until the wait in the
        // supervisor loop collects it, so its pid names nothing else.
        (Role::Outside, Some(child)) => {
            let _ = process::kill_process(child, Signal::KILL);
        }
        // Outside the sandbox there is always a command; nothing to end.
        (Role::Outside, None) => {}
    }
}

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

/// The bit of a wait status that says the kernel dumped the terminated
/// process's core, which `WCOREDUMP` tests. rustix reads the signal from a
/// wait status and not this bit.
const WCOREFLAG: i32 = 0x80;

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
        let dumped = status.as_raw() & WCOREFLAG != 0;
        (
            if dumped {
                STATUS_DUMPED
            } else {
                STATUS_SIGNALED
            },
            signal,
        )
    } else {
        // Neither exited nor signaled cannot describe a reaped process;
        // exit without a record rather than invent one.
        sys::exit_group(127)
    };
    report_outcome(fd, kind, value);
}

/// Writes the status record for an outcome of `kind` and `value`, with what
/// this process's collected descendants used; see [`report_status`].
fn report_outcome(fd: BorrowedFd<'_>, kind: u32, value: i32) {
    // A failure reports the outcome without usage rather than losing it.
    let usage = sys::children_usage().ok();
    let record = encode_status(kind, value, usage.as_ref());
    let _ = rustix::io::write(fd, &record);
}

/// How often a sandbox with no command of its own, terminating, looks whether
/// any process of it is left.
const ALONE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

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
    for signal in every_signal() {
        if signal == Signal::KILL || signal == Signal::STOP {
            continue;
        }
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

/// Every signal number from 1 to 64, the kernel's range on every architecture
/// the build admits, for the two loops that set every disposition after a fork:
/// [`reset_signals`] and [`ignore_outside_signals`].
///
/// rustix asks that a number a libc reserves for itself, such as the ones
/// glibc keeps for its threads and timers, not be used to alter a handler, so
/// that the libc's own use of the signal is not disturbed. That use belongs to
/// a process with a libc running in it, and none runs here: each of these
/// processes is a single-threaded copy of the caller that makes raw syscalls
/// only and ends in `execve` or `exit_group`. A command it executes starts its
/// own libc against the dispositions `execve` leaves, the defaults the reset
/// put back.
fn every_signal() -> impl Iterator<Item = Signal> {
    (1..=64).map(|number| {
        // SAFETY: the number is non-zero and within the kernel's signal range
        // on every architecture the build admits. One a libc reserves alters a
        // disposition only in a process no libc runs in, as stated above.
        unsafe { Signal::from_raw_unchecked(number) }
    })
}

/// Holds each standard stream number the caller left closed with a
/// close-on-exec copy of the null descriptor, so that nothing a stage creates
/// afterwards can land there.
///
/// A descriptor is created at the lowest number free. With a standard number
/// empty, the next one a stage opened would take it: the descriptor sweep's own
/// directory, the pseudoterminal of a terminal launch, the init's pidfd of the
/// command. The last is what the init sleeps on, and [`supervisor_hygiene`]
/// repoints all three standard numbers at the null descriptor, which would
/// replace it there and leave the init waiting on `/dev/null`.
///
/// A stream the plan wires replaces its copy through [`wire_stdio`]'s `dup2`,
/// as it replaces whatever the number holds, and a stream the plan leaves
/// inherited reaches the command closed, as the caller had it, since its copy
/// closes at the exec. A supervisor's repointing replaces its copies.
///
/// `F_DUPFD_CLOEXEC` from zero takes the lowest number free, so each call takes
/// the lowest closed standard number until none is left, and the first copy
/// above them is closed again at once. `EMFILE` means no number is free at all,
/// which leaves nothing to land on a closed standard number either.
///
/// The launch stage calls it before it creates a descriptor of its own, and
/// every later stage is forked from it. The caller's side of the same rule is
/// [`above_stdio`](super::above_stdio).
///
/// Post-fork safe: raw syscalls only.
fn hold_closed_streams(null: BorrowedFd<'_>) -> Result<(), Errno> {
    loop {
        match rustix::io::fcntl_dupfd_cloexec(null, 0) {
            Ok(copy) if copy.as_raw_fd() <= STDERR_FILENO => {
                // Held until the exec closes it or a `dup2` replaces it.
                let _ = copy.into_raw_fd();
            }
            // Above the standard numbers, so none is closed; the copy drops.
            Ok(_) | Err(Errno::MFILE) => return Ok(()),
            Err(errno) => return Err(errno),
        }
    }
}

/// Closes every descriptor the launch does not own.
///
/// Keeps the standard streams (the command may inherit them, and
/// [`hold_closed_streams`] holds the ones the caller closed) and the launch
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
        context.listener_channel_fd,
        context.join.map(|join| join.holder),
        // A joining launch's command joins the cgroup after the sweep.
        context.cgroup_procs_fd.filter(|_| context.joins()),
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
        if fd <= STDERR_FILENO || fd == dir.as_fd().as_raw_fd() || keep.contains(&fd) {
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

/// `KEYCTL_JOIN_SESSION_KEYRING`: replace the session keyring, with a fresh
/// anonymous one when the name argument is null.
const KEYCTL_JOIN_SESSION_KEYRING: usize = 1;

/// Gives this process, and every process it forks, a session keyring of its
/// own in place of the one it inherited, or, where the kernel refuses that,
/// refuses them the key syscalls.
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
/// # Where the join is refused
///
/// A kernel built without key support refuses the join with `ENOSYS`, and a
/// seccomp policy the launch runs under can refuse it too, with `EPERM` where
/// the policy was written to deny the call, as moby's default profile denies
/// `keyctl`. The inherited keyring then stays, and with it the possession of
/// every key it reaches. What else the policy refuses cannot be
/// read from the refusal: one can refuse the join and allow `KEYCTL_READ`, and
/// asking another operation answers for that operation alone. So nothing is
/// asked. Where the join is refused with either errno, this installs
/// [`seccomp::KEYRING_FILTER`], which refuses `add_key`, `request_key`, and
/// `keyctl` whole, before anything is forked. Every process of the sandbox
/// inherits it, so none reads, links, or searches a key through any
/// operation, whatever the policy allows.
///
/// The install needs no-new-privileges, or `CAP_SYS_ADMIN` in the calling
/// process's user namespace. A container's launch stage holds the capability
/// here, in the user namespace it has just created, so the flag is left as the
/// launch would otherwise leave it: unset, unless a hardening control, a
/// run-as identity, or a presented identity sets it later. A restriction
/// creates no namespace, and always runs under no-new-privileges, which its
/// hardening sets before the exec; setting it here, before the install, changes
/// nothing the command sees. A filter that cannot be installed fails the
/// launch at this step, and so does a join refused with any other errno.
/// `EDQUOT`, the calling user's key quota spent, is reported as
/// [`Error::KeyQuotaExhausted`](crate::Error::KeyQuotaExhausted).
///
/// Under the filter the sandbox still possesses the inherited keyring, and two
/// things follow from possession without a syscall. `/proc/keys` lists every
/// key it reaches whose permissions let a possessor view it, as the default
/// permissions do. And a kernel service that acts on the caller's keys on the
/// sandbox's behalf still finds them, as a network filesystem finds the
/// credentials it authenticates with. No syscall reaches a key's payload.
///
/// Post-fork safe: raw syscalls only, over a static program.
fn replace_session_keyring(plan: &LaunchPlan) -> Result<(), Errno> {
    match join_anonymous_session_keyring() {
        Ok(()) => Ok(()),
        Err(Errno::PERM | Errno::NOSYS) => {
            match plan.confinement {
                super::Confinement::Container => {}
                #[cfg(feature = "hardening")]
                super::Confinement::Restriction => thread::set_no_new_privs(true)?,
            }
            seccomp::install(seccomp::KEYRING_FILTER)
        }
        Err(errno) => Err(errno),
    }
}

/// Joins a fresh anonymous session keyring, in place of the calling process's.
fn join_anonymous_session_keyring() -> Result<(), Errno> {
    // SAFETY: the operation takes a name pointer, and zero is the null name
    // the kernel reads as "anonymous", so no pointer is passed and none is
    // read.
    unsafe { syscalls::syscall!(Sysno::keyctl, KEYCTL_JOIN_SESSION_KEYRING, 0usize) }
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
            let created = crate::provision::containment::open_child_dir(dir, leaf, OFlags::RDONLY)?;
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

/// How long, in all, [`hold_file_target`] waits for another sandbox's teardown
/// to finish removing a target before it binds without a lock.
///
/// A teardown holds its lock for an open, a `stat` and an unlink, so a wait
/// this long is one the teardown's process spent descheduled on a loaded host.
/// The bound keeps a lock held for longer, which only a process sharing the
/// root and taking one of its own holds, from stalling the launch.
const TARGET_PATIENCE: std::time::Duration = std::time::Duration::from_secs(1);

/// How long [`hold_file_target`] sleeps between looks at a target whose lock
/// a teardown holds.
const TARGET_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1);

/// The most looks [`hold_file_target`] takes at a target: one per
/// [`TARGET_INTERVAL`] of [`TARGET_PATIENCE`], which also bounds a name that
/// keeps vanishing between a create and a look.
const TARGET_ATTEMPTS: u128 = TARGET_PATIENCE.as_nanos() / TARGET_INTERVAL.as_nanos();

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
/// target is created anew once it is gone, looked at again every
/// [`TARGET_INTERVAL`] for up to [`TARGET_PATIENCE`] before the bind goes ahead
/// without a lock.
///
/// Through an overlay, a root or one mounted at a path, the lock is taken on
/// the overlay's own file, which a teardown does not meet: it removes the file
/// from the upper, under a lock of the upper's file. Another sandbox's bind
/// onto that target stands on its own overlay's entry, which removing the
/// upper's file does not unmount, so it keeps its bind all the same.
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
    let interval = thread::Timespec {
        tv_sec: i64::try_from(TARGET_INTERVAL.as_secs()).unwrap_or(0),
        tv_nsec: TARGET_INTERVAL.subsec_nanos().into(),
    };
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
        // locked is the file found; an `O_PATH` descriptor takes no lock. A
        // file this stage cannot open for reading is no placeholder, which a
        // launch creates readable: it is the root's own, as a root-shipped
        // `/etc/shadow` is, which no teardown removes, so the bind goes ahead
        // without a lock, as it does where the lock is refused.
        let Ok(file) = fs::open(
            fd_path(&found).as_cstr(),
            OFlags::RDONLY | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            return Ok(());
        };
        match share_target(&file) {
            // Granted after a teardown let go of it, the file may be unlinked
            // already, and the name then holds nothing of this lock's.
            Ok(()) if fs::fstat(&file)?.st_nlink == 0 => continue,
            Ok(()) => {
                let _ = file.into_raw_fd();
                return Ok(());
            }
            Err(Errno::WOULDBLOCK) => {
                let _ = thread::nanosleep(&interval);
            }
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

/// The mount profile as the setup executes it: the frozen ops, the new root
/// their paths are resolved against, and a slot per op, where the setup keeps
/// what the op mounted for as long as it needs it again.
///
/// A path beneath an earlier mount is resolved from that mount's descriptor
/// rather than from the root, and so lands in that mount, which is where the
/// build places it: [`covers`] reads the profile by its paths alone, for the
/// targets the launch creates and removes again, for the procfs the nested map
/// is written through, and for what a host root must already hold. Resolved
/// from the root, the path would follow whatever holds its directories when
/// its step runs. A process writing a root two sandboxes share could rename a
/// mount point between two steps: the mount moves with the directory it stands
/// on, and a hide or a path made read-only beneath it would land on nothing, or
/// on an entry of that process's own, while the command found the mount under
/// the new name with nothing hidden in it.
///
/// A lookup that starts at a mount's root does not cross a mount stacked on
/// that root, which a step reaching the same place by another path makes: the
/// host root's `/var/run` hide, which follows the host's link to `/run` and
/// lands on the `/run` hide. So each step that brings a mount to rest on the
/// root of one the setup holds records it there (see [`MountSlot`]), and a path
/// beneath that root is resolved from the mount on top, which is what the
/// command sees.
struct Profile<'a> {
    /// The new root.
    root: BorrowedFd<'a>,
    /// The ops, in the order they run.
    ops: &'a [MountOp],
    /// One slot per op, allocated by the caller.
    slots: &'a [MountSlot],
    /// The op whose procfs the command's nested identity map is written
    /// through, by a delegate inside the sandbox, which the setup keeps.
    procfs: Option<usize>,
}

/// What the setup keeps of one op of the mount profile, in a slot the caller
/// allocates, since the setup cannot.
#[derive(Default)]
pub(super) struct MountSlot {
    /// What the op mounted, while a later step resolves a path beneath it or
    /// stacks onto it, and a hidden directory's tmpfs until it is made
    /// read-only.
    mount: Cell<Option<OwnedFd>>,
    /// The later op whose mount came to rest on this one's root and stands
    /// over its whole tree.
    covered_by: Cell<Option<usize>>,
}

/// Where a path of an op is resolved from: beneath the target of the `op`th
/// op, which is what [`covers`] places it beneath, from the mount of the
/// `held`th, which stands on top of that target's mount.
#[derive(Clone, Copy)]
struct Anchor {
    /// The op whose target the path lies at or beneath.
    op: usize,
    /// The op whose mount the path is resolved from.
    held: usize,
}

impl Profile<'_> {
    /// Where a path the `before`th op names is resolved from: the latest op
    /// before it whose mount stands at or above `path`, of those whose mount
    /// the setup holds, or `None` where there is none and `path` is resolved
    /// from the root.
    ///
    /// A hide that found nothing mounted nothing and holds no slot, so a path
    /// beneath it lands where it would with no hide, as the build reads it.
    fn anchor(&self, before: usize, path: &CStr) -> Option<Anchor> {
        self.anchor_where(before, path, |_| true)
    }

    /// [`anchor`](Self::anchor), of the mounts that stand strictly above
    /// `path`: a lookup of `path` from one crosses by name whatever is mounted
    /// at `path` itself.
    fn anchor_above(&self, before: usize, path: &CStr) -> Option<Anchor> {
        self.anchor_where(before, path, |target| target != path)
    }

    /// The latest op before the `before`th whose mount the setup holds and
    /// whose target covers `path` and is one `admits` takes, and the mount on
    /// top of it of those an op before the `before`th made.
    fn anchor_where(
        &self,
        before: usize,
        path: &CStr,
        admits: impl Fn(&CStr) -> bool,
    ) -> Option<Anchor> {
        let ops = self.ops.get(..before).unwrap_or(self.ops);
        let op = ops.iter().enumerate().rev().find_map(|(at, op)| {
            let (target, _) = op.action.arrival()?;
            (covers(target, path) && admits(target) && self.holds(at)).then_some(at)
        })?;
        // Each cover is a later op, so the walk ends.
        let mut held = op;
        while let Some(over) = self.slots.get(held).and_then(|slot| slot.covered_by.get())
            && over < before
            && self.holds(over)
        {
            held = over;
        }
        Some(Anchor { op, held })
    }

    /// Whether the setup holds the mount the `at`th op made.
    fn holds(&self, at: usize) -> bool {
        self.slots.get(at).is_some_and(|slot| {
            let held = slot.mount.take();
            let holds = held.is_some();
            slot.mount.set(held);
            holds
        })
    }

    /// The part of `path` beneath the target of the op `anchor` names, empty
    /// where `path` is that target, or `None` where `path` is not at or beneath
    /// it. Without an anchor, `path` is the root's whole.
    fn beneath<'p>(&self, anchor: Option<Anchor>, path: &'p CStr) -> Option<&'p CStr> {
        let Some(anchor) = anchor else {
            return Some(path);
        };
        let (target, _) = self.ops.get(anchor.op)?.action.arrival()?;
        if !covers(target, path) {
            return None;
        }
        // What follows the target is its terminator alone, or a slash and the
        // rest of the path.
        let rest = path.to_bytes_with_nul().get(target.to_bytes().len()..)?;
        CStr::from_bytes_with_nul(rest.strip_prefix(b"/").unwrap_or(rest)).ok()
    }

    /// Calls `f` with the descriptor a path beneath `anchor` is resolved from:
    /// the mount it names, or the root without an anchor.
    ///
    /// The descriptor is lent out of its slot for the call, so `f` does not ask
    /// the profile for an anchor of its own. A slot that holds nothing is a
    /// defect, since [`anchor`](Self::anchor) names only one that does, and is
    /// reported as a bad descriptor, since this process must not panic.
    fn within<R>(
        &self,
        anchor: Option<Anchor>,
        f: impl FnOnce(BorrowedFd<'_>) -> Result<R, (SetupStep, Errno)>,
    ) -> Result<R, (SetupStep, Errno)> {
        let Some(anchor) = anchor else {
            return f(self.root);
        };
        let Some(slot) = self.slots.get(anchor.held) else {
            return Err((SetupStep::OpenMountTarget, Errno::BADF));
        };
        let Some(held) = slot.mount.take() else {
            return Err((SetupStep::OpenMountTarget, Errno::BADF));
        };
        let done = f(held.as_fd());
        slot.mount.set(Some(held));
        done
    }

    /// The op before the `before`th whose mount the setup holds and has its
    /// root where `place` is, if any: the mount a step that brings its own to
    /// rest at `place` stacks onto.
    fn held_at(&self, before: usize, place: BorrowedFd<'_>) -> Result<Option<usize>, Errno> {
        for at in (0..before.min(self.slots.len())).rev() {
            let Some(slot) = self.slots.get(at) else {
                continue;
            };
            let Some(held) = slot.mount.take() else {
                continue;
            };
            let same = same_place(place, held.as_fd());
            slot.mount.set(Some(held));
            if same? {
                return Ok(Some(at));
            }
        }
        Ok(None)
    }
}

/// Whether `a` and `b` name the same directory of the same mount.
///
/// The mount is told by its id, which `statx` reports from Linux 5.8. Before
/// it, or where `statx` is refused, two names of one directory are taken for
/// one place: a tmpfs of the launch's own is one mount wherever it is named,
/// and a bind's root is its source's, which only another bind of that source
/// shares.
fn same_place(a: BorrowedFd<'_>, b: BorrowedFd<'_>) -> Result<bool, Errno> {
    let ask = |fd| {
        fs::statx(
            fd,
            c"",
            AtFlags::EMPTY_PATH,
            StatxFlags::INO | StatxFlags::MNT_ID,
        )
    };
    let (a, b) = match (ask(a), ask(b)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(Errno::NOSYS | Errno::PERM), _) | (_, Err(Errno::NOSYS | Errno::PERM)) => {
            let (a, b) = (fs::fstat(a)?, fs::fstat(b)?);
            return Ok((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino));
        }
        (Err(errno), _) | (_, Err(errno)) => return Err(errno),
    };
    let mount_ids = StatxFlags::from_bits_retain(a.stx_mask & b.stx_mask);
    let mounts = !mount_ids.contains(StatxFlags::MNT_ID) || a.stx_mnt_id == b.stx_mnt_id;
    Ok(mounts
        && (a.stx_dev_major, a.stx_dev_minor, a.stx_ino)
            == (b.stx_dev_major, b.stx_dev_minor, b.stx_ino))
}

/// Whether a later op of `ops` resolves a path beneath what the `index`th
/// mounts, so the setup keeps that mount's descriptor until the profile is in
/// place.
fn anchors_later(ops: &[MountOp], index: usize) -> bool {
    let Some((target, _)) = ops.get(index).and_then(|op| op.action.arrival()) else {
        return false;
    };
    ops.get(index + 1..)
        .unwrap_or_default()
        .iter()
        .any(|later| covers(target, later.action.anchored_path()))
}

/// A mount target as the setup holds it: the descriptor of the earlier mount
/// whose target it is, or one opened beneath that mount.
enum Target<'a> {
    /// The earlier mount's own descriptor.
    Anchor(BorrowedFd<'a>),
    /// A descriptor opened beneath it.
    Opened(OwnedFd),
}

impl Target<'_> {
    /// The target's descriptor.
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Target::Anchor(fd) => *fd,
            Target::Opened(fd) => fd.as_fd(),
        }
    }

    /// Where a mount brought to rest on this target stands, once the anchor's
    /// descriptor is no longer lent.
    fn place(self) -> Place {
        match self {
            Target::Anchor(_) => Place::Anchor,
            Target::Opened(fd) => Place::Opened(fd),
        }
    }
}

/// Where an op brought a mount of its own to rest.
enum Place {
    /// Nowhere: a link, a hide of nothing, a raw remount or propagation change.
    Nowhere,
    /// On the root of the mount its anchor holds.
    Anchor,
    /// On the target opened beneath the anchor.
    Opened(OwnedFd),
}

/// Opens what `rest` names beneath `at` as [`open_in_root`] does, or lends `at`
/// itself where `rest` is empty: a target that is an earlier mount's own
/// target, which a step stacks onto. `O_DIRECTORY` holds for `at` as an open
/// would hold to it.
fn open_target<'a>(at: BorrowedFd<'a>, rest: &CStr, oflags: OFlags) -> Result<Target<'a>, Errno> {
    if !rest.is_empty() {
        return open_in_root(at, rest, oflags).map(Target::Opened);
    }
    if oflags.contains(OFlags::DIRECTORY) && !is_directory(at)? {
        return Err(Errno::NOTDIR);
    }
    Ok(Target::Anchor(at))
}

/// Whether `fd` names a directory.
fn is_directory(fd: BorrowedFd<'_>) -> Result<bool, Errno> {
    fs::fstat(fd).map(|stat| fs::FileType::from_raw_mode(stat.st_mode) == fs::FileType::Directory)
}

/// Executes the profile's `index`th op, and keeps what it mounted where the
/// setup needs it again: where a later step resolves beneath it or stacks onto
/// its root, the procfs a delegate writes the nested map through, and a hidden
/// directory's tmpfs, to make it read-only once the profile is in place.
///
/// Every path the op names is resolved from its anchor (see [`Profile`]): its
/// target, the directories made on the way to it, and the file a bind needs
/// there. A raw mount is made by path, which leaves no descriptor of what it
/// mounted, so where the setup needs it again, its target is opened once it is
/// mounted, by name from the nearest mount above it, which crosses into it. A
/// later step lands in it as long as nothing renames the directories between
/// the two in that moment.
fn execute_op(
    profile: &Profile<'_>,
    index: usize,
    report_fd: BorrowedFd<'_>,
) -> Result<(), (SetupStep, Errno)> {
    let Some(op) = profile.ops.get(index) else {
        return Ok(());
    };
    let path = op.action.anchored_path();
    let anchor = profile.anchor(index, path);
    let (place, mut mounted) = profile.within(anchor, |at| {
        // Create missing mount-target directories beneath the anchor, one
        // component at a time; those at and above its target stood when its
        // own step resolved that target through them. Each parent is resolved
        // in-root first, so a symlinked component is followed only within the
        // anchor's tree; an existing entry — directory or symlink — is left
        // alone.
        for dir in &op.dirs {
            let Some(parent) = profile.beneath(anchor, &dir.parent) else {
                continue;
            };
            let failed = |errno| (SetupStep::CreateMountTarget, errno);
            let parent =
                open_target(at, parent, OFlags::PATH | OFlags::DIRECTORY).map_err(failed)?;
            create_mount_dir(parent.as_fd(), &dir.leaf, Mode::from_raw_mode(dir.mode))
                .map_err(failed)?;
        }

        // The target of a file bind must exist before a file can be bound onto
        // it; create it empty where the tree holds nothing at that path. One
        // that is the anchor's own target is a mount, there already.
        if let Some(file) = op.create_file.as_deref() {
            match profile.beneath(anchor, file) {
                Some(file) if !file.is_empty() => hold_file_target(at, file, index, report_fd)
                    .map_err(|errno| (SetupStep::CreateMountTarget, errno))?,
                _ => {}
            }
        }

        let rest = profile
            .beneath(anchor, path)
            .ok_or((SetupStep::OpenMountTarget, Errno::INVAL))?;
        perform(profile.root, &op.action, at, rest)
    })?;

    // The mount this one came to rest on the root of, if the setup holds it.
    let stacked = match place {
        Place::Nowhere => None,
        Place::Anchor => anchor.map(|anchor| anchor.held),
        Place::Opened(place) => profile
            .held_at(index, place.as_fd())
            .map_err(|errno| (SetupStep::OpenMountTarget, errno))?,
    };
    let kept =
        stacked.is_some() || profile.procfs == Some(index) || anchors_later(profile.ops, index);
    if let MountAction::Raw { target, .. } = &op.action
        && kept
    {
        let above = profile.anchor_above(index, target);
        mounted = Some(profile.within(above, |at| {
            let rest = profile
                .beneath(above, target)
                .ok_or((SetupStep::OpenMountTarget, Errno::INVAL))?;
            open_in_root(at, rest, OFlags::PATH)
                .map_err(|errno| (SetupStep::OpenMountTarget, errno))
        })?);
    }
    let Some(slot) = profile.slots.get(index) else {
        return Ok(());
    };
    if let Some(mount) = mounted
        && (kept || matches!(op.action, MountAction::Hide { .. }))
    {
        slot.mount.set(Some(mount));
        if let Some(under) = stacked.and_then(|under| profile.slots.get(under)) {
            under.covered_by.set(Some(index));
        }
    }
    Ok(())
}

/// Performs `action` on its target, which `rest` names beneath `at`, and
/// returns where it brought a mount to rest, with that mount where it holds a
/// descriptor of it: every action but a raw mount, which `mount(2)` makes by
/// path. `root` is the new root, which a file of the launch's own is made
/// beside.
fn perform(
    root: BorrowedFd<'_>,
    action: &MountAction,
    at: BorrowedFd<'_>,
    rest: &CStr,
) -> Result<(Place, Option<OwnedFd>), (SetupStep, Errno)> {
    let open =
        |oflags| open_target(at, rest, oflags).map_err(|errno| (SetupStep::OpenMountTarget, errno));
    let (target, mount) = match action {
        MountAction::Hide { required, .. } => match hide(root, at, rest, *required)? {
            Some((target, mount)) => (target, mount),
            None => return Ok((Place::Nowhere, None)),
        },
        MountAction::File { contents, .. } => {
            let target = open(OFlags::PATH)?;
            let mount = place_file(root, target.as_fd(), contents)?;
            (target, mount)
        }
        MountAction::ReadOnly { .. } => {
            let target = open(OFlags::PATH)?;
            let mount = read_only_in_place(target.as_fd())?;
            (target, mount)
        }
        // A procfs is made from inside the new PID namespace, so the instance
        // presents the sandbox's processes and nothing else.
        MountAction::Tmpfs { fs, .. } => {
            let target = open(OFlags::PATH | OFlags::DIRECTORY)?;
            let mount = mount_fresh(target.as_fd(), fs, SetupStep::MountTmpfs)?;
            (target, mount)
        }
        MountAction::Devpts { fs, .. } => {
            let target = open(OFlags::PATH | OFlags::DIRECTORY)?;
            let mount = mount_fresh(target.as_fd(), fs, SetupStep::MountDevpts)?;
            (target, mount)
        }
        MountAction::Procfs { .. } => {
            let target = open(OFlags::PATH | OFlags::DIRECTORY)?;
            let fs = &super::procfs::FRESH_PROCFS;
            let mount = mount_fresh(target.as_fd(), fs, SetupStep::MountProc)?;
            (target, mount)
        }
        MountAction::Bind {
            source, read_only, ..
        } => {
            let target = open(OFlags::PATH)?;
            let mount = bind(source, target.as_fd(), *read_only)?;
            (target, mount)
        }
        MountAction::Overlay { overlay, .. } => {
            let target = open(OFlags::PATH | OFlags::DIRECTORY)?;
            let mount = mount_overlay_at(overlay, target.as_fd())?;
            (target, mount)
        }
        MountAction::Raw {
            source,
            fstype,
            flags,
            data,
            ..
        } => {
            // Only the target is interpreted: resolved in-root like every
            // other target. Source, type, flags, and data pass through.
            let target = open(OFlags::PATH)?;
            mount::mount(
                source.as_c_str(),
                fd_path(&target.as_fd()).as_cstr(),
                fstype.as_c_str(),
                *flags,
                data.as_c_str(),
            )
            .map_err(|errno| (SetupStep::MountRaw, errno))?;
            let place = match super::Arrival::of_raw(*flags) {
                Some(_) => target.place(),
                None => Place::Nowhere,
            };
            return Ok((place, None));
        }
        MountAction::Symlink { leaf, content, .. } => {
            // A link at the root's top level has no parent to resolve: it is
            // made in the root itself.
            let dir = open(OFlags::PATH | OFlags::DIRECTORY)?;
            return match fs::symlinkat(content.as_c_str(), dir.as_fd(), leaf.as_c_str()) {
                Ok(()) => Ok((Place::Nowhere, None)),
                // The link this op makes, made by an earlier launch over the
                // same persistent root.
                Err(Errno::EXIST) if links_to(dir.as_fd(), leaf, content) => {
                    Ok((Place::Nowhere, None))
                }
                Err(errno) => Err((SetupStep::CreateSymlink, errno)),
            };
        }
    };
    Ok((target.place(), Some(mount)))
}

/// Mounts the filesystem instance `fs` describes onto the directory `target`
/// names, reporting a failure of the mount as `step`, and returns the mount.
fn mount_fresh(
    target: BorrowedFd<'_>,
    fs: &FreshFs,
    step: SetupStep,
) -> Result<OwnedFd, (SetupStep, Errno)> {
    let mount = fresh_mount(fs).map_err(|errno| (step, errno))?;
    attach(mount.as_fd(), target).map_err(|errno| (step, errno))?;
    Ok(mount)
}

/// Hides what `rest` names beneath `at`: an empty tmpfs over a directory, and
/// an empty read-only file of the launch's own over anything else. Nothing at
/// the path hides nothing, unless the hide is `required`, which fails with the
/// `ENOENT` the lookup answered.
///
/// Returns the target and what it mounted there: a hidden directory's tmpfs,
/// writable, so that a later op can still make a mount point in it, which the
/// setup makes read-only once the profile is in place, or the file. A hidden
/// file is read-only from the start: nothing is made in a file.
fn hide<'a>(
    root: BorrowedFd<'_>,
    at: BorrowedFd<'a>,
    rest: &CStr,
    required: bool,
) -> Result<Option<(Target<'a>, OwnedFd)>, (SetupStep, Errno)> {
    let target = match open_target(at, rest, OFlags::PATH) {
        Ok(target) => target,
        Err(Errno::NOENT) if !required => return Ok(None),
        Err(errno) => return Err((SetupStep::OpenMountTarget, errno)),
    };
    let failed = |errno| (SetupStep::HidePath, errno);
    if is_directory(target.as_fd()).map_err(failed)? {
        let tmpfs = empty_tmpfs(OWN_TMPFS_ATTRIBUTES).map_err(failed)?;
        attach(tmpfs.as_fd(), target.as_fd()).map_err(failed)?;
        return Ok(Some((target, tmpfs)));
    }
    let file = own_file(root, &[]).map_err(failed)?;
    let file = attach_tree(file, target.as_fd(), true, SetupStep::HidePath)?;
    Ok(Some((target, file)))
}

/// Places a read-only file of the launch's own, holding `contents`, over the
/// file `target` names, which must exist: the build has the launch create it
/// where the tree holds nothing there. Returns the file's mount. `root` is the
/// new root, which the file is made beside; see [`own_file`].
fn place_file(
    root: BorrowedFd<'_>,
    target: BorrowedFd<'_>,
    contents: &[u8],
) -> Result<OwnedFd, (SetupStep, Errno)> {
    let file = own_file(root, contents).map_err(|errno| (SetupStep::PlaceFile, errno))?;
    attach_tree(file, target, true, SetupStep::PlaceFile)
}

/// A regular file holding `contents`, as a detached mount of its own ready to
/// attach over a target: what a hidden file and a placed one are bound from.
///
/// The file is created in a tmpfs of its own, so the command sees a regular
/// file, not a device, and nothing of the host's holds it. A clone of a path is
/// taken only of a mount attached in the caller's mount namespace, so that
/// tmpfs is attached for the moment the clone takes, stacked on the root mount
/// `root` names, where no lookup crosses it, and detached again at once: a
/// lookup that starts at a mount's root does not cross a mount stacked on that
/// root.
fn own_file(root: BorrowedFd<'_>, contents: &[u8]) -> Result<OwnedFd, Errno> {
    let tmpfs = empty_tmpfs(OWN_TMPFS_ATTRIBUTES)?;
    let file = fs::openat(
        &tmpfs,
        OWN_FILE,
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::from_raw_mode(OWN_FILE_MODE),
    )?;
    frame::write_full(file.as_fd(), contents)?;
    drop(file);
    attach(tmpfs.as_fd(), root)?;
    let clone = mount::open_tree(
        &tmpfs,
        OWN_FILE,
        mount::OpenTreeFlags::OPEN_TREE_CLONE | mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
    );
    let detached = mount::unmount(fd_path(&tmpfs).as_cstr(), UnmountFlags::DETACH);
    let clone = clone?;
    detached?;
    Ok(clone)
}

/// What a tmpfs of the launch's own carries: nothing in it is a device, set-id
/// or executable.
const OWN_TMPFS_ATTRIBUTES: mount::MountAttrFlags = mount::MountAttrFlags::MOUNT_ATTR_NOSUID
    .union(mount::MountAttrFlags::MOUNT_ATTR_NODEV)
    .union(mount::MountAttrFlags::MOUNT_ATTR_NOEXEC);

/// The name of a file of the launch's own, inside its own tmpfs.
const OWN_FILE: &CStr = c"file";

/// The mode of a file of the launch's own: an ordinary file's.
const OWN_FILE_MODE: u32 = 0o644;

/// Makes the tree at `target` read-only where it stands: a clone of it, every
/// mount beneath it included, read-only, bound onto it. Returns the clone.
fn read_only_in_place(target: BorrowedFd<'_>) -> Result<OwnedFd, (SetupStep, Errno)> {
    let tree = clone_tree(target).map_err(|errno| (SetupStep::ReadOnlyPath, errno))?;
    attach_tree(tree, target, true, SetupStep::ReadOnlyPath)
}

/// The most directories [`hold_name`] binds for one path: more than a path the
/// kernel resolves can hold, so reaching it means the walk never met a root.
const MAX_HELD_DIRECTORIES: usize = 4096;

/// Holds the name of a path made read-only: every directory between the
/// nearest mount above the path and the path itself is bound onto itself, a
/// mount point of its own, so renaming or removing one fails with `EBUSY`.
///
/// The read-only bind refuses a write, and a rename or removal of the path
/// itself, which is its mount point. The kernel asks only of the entry renamed
/// whether a mount stands on it, though, so renaming a directory above the
/// path would carry the bind away with it and leave the name free for a new
/// entry, which whatever reads the tree by name later reads instead: the
/// caller's own git, reading a working tree after the command.
///
/// `parent` is the directory the name is in, root-relative and empty where
/// that is the root, the parent of the `index`th op's target, resolved from the
/// anchor that op's target was resolved from (see [`Profile`]). The walk climbs
/// from it through `..` and stops at the first mount root, which its own mount
/// cannot rename, or at the sandbox's root. A parent that is the anchor's own
/// target is a mount root already. A kernel that does not say whether a
/// directory is a mount root (before Linux 5.8) has every directory up to the
/// sandbox's root held instead: one that is already a mount root gains a mount
/// stacked on it, and nothing is lost.
///
/// Each hold is a clone of the directory's tree with every mount beneath it,
/// so the read-only bind and each hold below stay in view, and runs after the
/// empty root and every hidden directory are made read-only, so a hold cloned
/// from one of them is as read-only as it.
fn hold_name(profile: &Profile<'_>, index: usize, parent: &CStr) -> Result<(), (SetupStep, Errno)> {
    if parent.is_empty() {
        return Ok(());
    }
    let held = |errno| (SetupStep::HoldReadOnlyName, errno);
    let opened = |errno| (SetupStep::OpenMountTarget, errno);
    let top = fs::fstat(profile.root).map_err(held)?;
    let anchor = profile.anchor(index, parent);
    let start = profile.within(anchor, |at| {
        let rest = profile
            .beneath(anchor, parent)
            .ok_or(opened(Errno::INVAL))?;
        match open_target(at, rest, OFlags::PATH | OFlags::DIRECTORY).map_err(opened)? {
            Target::Opened(dir) => Ok(Some(dir)),
            Target::Anchor(_) => Ok(None),
        }
    })?;
    let Some(mut dir) = start else {
        return Ok(());
    };
    for _ in 0..MAX_HELD_DIRECTORIES {
        let at = fs::fstat(&dir).map_err(held)?;
        if (at.st_dev, at.st_ino) == (top.st_dev, top.st_ino)
            || is_mount_root(dir.as_fd()).map_err(held)? == Some(true)
        {
            return Ok(());
        }
        let tree = clone_tree(dir.as_fd()).map_err(held)?;
        attach(tree.as_fd(), dir.as_fd()).map_err(held)?;
        dir = fs::openat(
            &dir,
            c"..",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(opened)?;
    }
    Err(held(Errno::LOOP))
}

/// Whether the directory `dir` names is the root of a mount, or `None` where
/// the kernel does not say: before Linux 5.8, which added the attribute, or
/// where `statx` itself is refused.
fn is_mount_root(dir: BorrowedFd<'_>) -> Result<Option<bool>, Errno> {
    match fs::statx(dir, c"", AtFlags::EMPTY_PATH, StatxFlags::empty()) {
        Ok(stat)
            if stat
                .stx_attributes_mask
                .contains(StatxAttributes::MOUNT_ROOT) =>
        {
            Ok(Some(
                stat.stx_attributes.contains(StatxAttributes::MOUNT_ROOT),
            ))
        }
        Ok(_) | Err(Errno::NOSYS) => Ok(None),
        Err(errno) => Err(errno),
    }
}

/// Clones the tree `at` names, every mount beneath it included, detached.
fn clone_tree(at: BorrowedFd<'_>) -> Result<OwnedFd, Errno> {
    mount::open_tree(
        at,
        c"",
        mount::OpenTreeFlags::OPEN_TREE_CLONE
            | mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
            | mount::OpenTreeFlags::AT_RECURSIVE
            | mount::OpenTreeFlags::AT_EMPTY_PATH,
    )
}

/// Opens a host path the build froze canonical, for a mount to act on the
/// descriptor, refusing a symbolic link at any component of it.
///
/// The build resolves the rootfs, the overlay's base and every bind source to
/// its canonical path, which holds no link, and a launch reaches the path again
/// only here. A link met there was put in place since, by whatever can write a
/// directory the path runs through: a sandbox an earlier launch of the same
/// plan bound such a directory into writable, for one. Followed, it would mount
/// whatever it names, `~/.ssh` as readily as the tree the plan named. The
/// kernel refuses it instead, with `ELOOP`, and the launch fails at the mount
/// the path was for. The mount then acts on the descriptor, so nothing
/// resolves the path a second time.
pub(super) fn open_frozen(path: &CStr, oflags: OFlags) -> Result<OwnedFd, Errno> {
    resolve::openat2(
        fs::CWD,
        path,
        OFlags::PATH | OFlags::CLOEXEC | oflags,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
}

/// Attaches the detached mount `mount` names onto the mount target `target`
/// names.
pub(super) fn attach(mount: BorrowedFd<'_>, target: BorrowedFd<'_>) -> Result<(), Errno> {
    mount::move_mount(
        mount,
        c"",
        target,
        c"",
        mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH
            | mount::MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
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
/// The source is opened without following a link; see [`open_frozen`]. The
/// tree is cloned detached from that descriptor (`open_tree` with
/// `OPEN_TREE_CLONE`), made read-only while detached, and only then attached
/// (`move_mount`) onto the descriptor the target was resolved to. Nothing
/// between the bind and its restriction resolves a path again. Remounting by
/// path after an ordinary
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
fn bind(
    source: &CStr,
    target: BorrowedFd<'_>,
    read_only: bool,
) -> Result<OwnedFd, (SetupStep, Errno)> {
    let failed = |errno| (SetupStep::BindMount, errno);
    let source = open_frozen(source, OFlags::empty()).map_err(failed)?;
    let tree = clone_tree(source.as_fd()).map_err(failed)?;
    attach_tree(tree, target, read_only, SetupStep::BindMount)
}

/// Mounts the overlay `overlay` onto the mount target `target` names, its
/// layers opened as the overlay root's are, without following a link, and
/// through [`mount_overlay`] as that root is mounted, `nosuid` included.
/// Returns the overlay's mount.
fn mount_overlay_at(
    overlay: &OverlayPlan,
    target: BorrowedFd<'_>,
) -> Result<OwnedFd, (SetupStep, Errno)> {
    let failed = |errno| (SetupStep::MountOverlay, errno);
    let (base, stacked) = overlay
        .lower
        .split_first()
        .ok_or((SetupStep::MountOverlay, Errno::INVAL))?;
    let base = open_frozen(base, OFlags::DIRECTORY).map_err(failed)?;
    let layers = OverlayLayers {
        base: base.as_fd(),
        stacked,
        upper: &overlay.upper,
        work: &overlay.work,
    };
    let mount = mount_overlay(&layers).map_err(failed)?;
    attach_tree(mount, target, false, SetupStep::MountOverlay)
}

/// Attaches a detached clone, `tree`, onto the mount target `target` names,
/// read-only throughout when `read_only` asks, with the restriction made
/// before the attach as [`bind`] sets out, and returns it, attached. A failure
/// of the attach is reported as `step`, the operation the clone serves.
fn attach_tree(
    tree: OwnedFd,
    target: BorrowedFd<'_>,
    read_only: bool,
    step: SetupStep,
) -> Result<OwnedFd, (SetupStep, Errno)> {
    let remount_after = read_only
        && match mount_setattr(tree.as_fd(), MOUNT_ATTR_RDONLY, true) {
            Ok(()) => false,
            Err(Errno::NOSYS) => true,
            Err(errno) => return Err((SetupStep::RemountReadOnly, errno)),
        };
    attach(tree.as_fd(), target).map_err(|errno| (step, errno))?;
    if remount_after {
        remount_top(tree.as_fd(), MountFlags::RDONLY)
            .map_err(|errno| (SetupStep::RemountReadOnly, errno))?;
    }
    Ok(tree)
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
///
/// Below Linux 5.12 there is no `mount_setattr`, and the fallback remounts the
/// root mount alone: a mount the rootfs bind carried along beneath it keeps its
/// source's flags there. No-new-privileges, which every non-root command runs
/// with, is what still disarms a set-user-ID binary on one; see
/// `switch_identity`.
fn nosuid_root(root: BorrowedFd<'_>) -> Result<(), Errno> {
    match mount_setattr(root, MOUNT_ATTR_NOSUID, true) {
        Ok(()) => Ok(()),
        Err(Errno::NOSYS) => remount_top(root, MountFlags::NOSUID),
        Err(errno) => Err(errno),
    }
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
    let root = empty_tmpfs(
        mount::MountAttrFlags::MOUNT_ATTR_NOSUID | mount::MountAttrFlags::MOUNT_ATTR_NODEV,
    )?;
    attach_over_root(root.as_fd())?;
    Ok(root)
}

/// Clones the host's mount tree, makes every mount of the clone read-only and
/// `nosuid`, and attaches it on top of `/`, returning a descriptor of it.
///
/// The clone is taken in the sandbox's own mount namespace, after the
/// inherited tree was made private, so nothing done to it reaches the host.
/// The mounts the namespace copied are locked, which the clone keeps: a lock
/// refuses lifting a restriction, and this only adds them. Attached on top of
/// `/`, as the empty root is, every host path a bind of the profile names still
/// resolves on the host until the pivot.
///
/// There is no fallback below Linux 5.12. A remount by path reaches only the
/// top mount of a tree, and a root whose submounts stayed writable is not the
/// read-only host it is configured as, so `ENOSYS` fails the launch.
fn mount_host_root() -> Result<OwnedFd, Errno> {
    let tree = mount::open_tree(
        fs::CWD,
        c"/",
        mount::OpenTreeFlags::OPEN_TREE_CLONE
            | mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
            | mount::OpenTreeFlags::AT_RECURSIVE,
    )?;
    mount_setattr(tree.as_fd(), MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID, true)?;
    attach_over_root(tree.as_fd())?;
    Ok(tree)
}

/// Creates a tmpfs of the sandbox's own, mode `0755`, detached, carrying
/// `attributes`, and returns a descriptor of it.
pub(super) fn empty_tmpfs(attributes: mount::MountAttrFlags) -> Result<OwnedFd, Errno> {
    fresh_mount(&FreshFs {
        fstype: c"tmpfs",
        params: &[FsParam::String(c"mode", c"0755")],
        attributes,
    })
}

/// Creates the filesystem instance `fs` describes, detached, and returns a
/// descriptor of its mount: how the launch makes every filesystem of the
/// sandbox's own, a raw mount's aside.
///
/// The instance belongs to the namespaces of the process that opens its
/// context, so a procfs made here presents this process's PID namespace. The
/// source is the type's name, as a `mount(2)` naming it would record, so the
/// sandbox's mount table reads as before. The mount is attached to nothing: the
/// caller attaches it onto a target's descriptor with [`attach`], and keeps the
/// descriptor of the mount where a later step reaches into it.
pub(super) fn fresh_mount(fs: &FreshFs) -> Result<OwnedFd, Errno> {
    let context = mount::fsopen(fs.fstype, mount::FsOpenFlags::FSOPEN_CLOEXEC)?;
    mount::fsconfig_set_string(&context, c"source", fs.fstype)?;
    for param in fs.params {
        match *param {
            FsParam::Flag(key) => mount::fsconfig_set_flag(&context, key)?,
            FsParam::String(key, value) => mount::fsconfig_set_string(&context, key, value)?,
        }
    }
    mount::fsconfig_create(&context)?;
    mount::fsmount(
        &context,
        mount::FsMountFlags::FSMOUNT_CLOEXEC,
        fs.attributes,
    )
}

/// Attaches the detached mount `root` names on top of `/`, as a root the
/// sandbox pivots into.
pub(super) fn attach_over_root(root: BorrowedFd<'_>) -> Result<(), Errno> {
    mount::move_mount(
        root,
        c"",
        fs::CWD,
        c"/",
        mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
}

/// Makes the mount `target` names read-only, and only it: every mount made
/// beneath it keeps its own flags. That is an empty root once the profile is
/// in place, where a writable bind and the managed `/tmp` stay writable, and a
/// hidden directory, where a working tree bound back in stays writable.
fn read_only_mount(target: BorrowedFd<'_>) -> Result<(), Errno> {
    match mount_setattr(target, MOUNT_ATTR_RDONLY, false) {
        Ok(()) => Ok(()),
        Err(Errno::NOSYS) => remount_top(target, MountFlags::RDONLY),
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
/// failing the launch. It refuses a magic link by name, as that helper does: a
/// `/proc/*/fd/*` entry reopens whatever it names, from anywhere on the host,
/// and no mount target has a use for one. `RESOLVE_IN_ROOT` refuses one too on
/// every kernel so far, and the kernel documents that as subject to change.
fn open_in_root_with(
    root: BorrowedFd<'_>,
    path: &CStr,
    oflags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno> {
    resolve::openat2(
        root,
        path,
        oflags,
        mode,
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
    )
}

/// Bytes assembled into a stack buffer of `N`, for the post-fork stages that
/// cannot allocate: a path, as [`StackPath`], or the overlay's mount options.
///
/// A push that would not fit is dropped rather than truncating mid-way — these
/// processes must not panic, and a short path fails its `open` with `ENOENT`
/// instead of naming something else. A caller for whom a dropped push changes
/// what the bytes mean, rather than leaving a path that names nothing, asks
/// [`dropped`](Self::dropped).
pub(super) struct StackBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
    dropped: bool,
}

/// A path in a [`StackBuf`] that holds every path formatted here with room to
/// spare: the longest is `/proc/self/fd/` and ten decimal digits.
pub(super) type StackPath = StackBuf<48>;

impl<const N: usize> StackBuf<N> {
    /// An empty buffer.
    pub(super) fn new() -> StackBuf<N> {
        StackBuf {
            buf: [0u8; N],
            len: 0,
            dropped: false,
        }
    }

    /// Appends bytes, if they fit alongside the terminating NUL and hold no NUL
    /// of their own; anything else is dropped whole. Every caller appends
    /// literals and digits, which always pass.
    pub(super) fn push(&mut self, bytes: &[u8]) {
        if self.len + bytes.len() >= self.buf.len() || bytes.contains(&0) {
            self.dropped = true;
            return;
        }
        for &byte in bytes {
            self.buf[self.len] = byte;
            self.len += 1;
        }
    }

    /// Appends a value in decimal.
    pub(super) fn push_decimal(&mut self, mut value: u32) {
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

    /// Appends the `/proc/self/fd` path that names `fd`.
    pub(super) fn push_fd_path(&mut self, fd: BorrowedFd<'_>) {
        self.push(b"/proc/self/fd/");
        // Descriptors are non-negative, so the cast is lossless.
        self.push_decimal(fd.as_raw_fd() as u32);
    }

    /// Whether a push was dropped.
    pub(super) fn dropped(&self) -> bool {
        self.dropped
    }

    pub(super) fn as_cstr(&self) -> &CStr {
        // SAFETY: the buffer is zero-initialized, `push` never lets `len` reach
        // the final byte, and it appends no NUL, so the slice holds exactly one
        // NUL, at the end.
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.buf[..self.len + 1]) }
    }
}

/// Formats the `/proc/self/fd` path that names `fd`, so a descriptor
/// resolved with `RESOLVE_IN_ROOT` can anchor a mount syscall that only
/// accepts paths.
pub(super) fn fd_path<Fd: AsFd>(fd: &Fd) -> StackPath {
    let mut path = StackPath::new();
    path.push_fd_path(fd.as_fd());
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
    use std::time::Duration;

    use rustix::pipe::PipeFlags;
    use rustix::thread::UnshareFlags;

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

    /// A frozen op with nothing to create, performing `action`.
    fn op(action: MountAction) -> MountOp {
        MountOp {
            dirs: Vec::new(),
            create_file: None,
            action,
        }
    }

    /// A slot holding a descriptor, as one whose op mounted something.
    fn held_slot() -> MountSlot {
        let slot = MountSlot::default();
        let held =
            fs::open(c"/", OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).expect("the root opens");
        slot.mount.set(Some(held));
        slot
    }

    #[test]
    fn a_path_is_resolved_from_the_latest_held_mount_above_it() {
        let ops = [
            op(MountAction::Tmpfs {
                target: c"work".into(),
                fs: FreshFs {
                    fstype: c"tmpfs",
                    params: &[],
                    attributes: OWN_TMPFS_ATTRIBUTES,
                },
            }),
            op(MountAction::Hide {
                target: c"work/secrets".into(),
                required: false,
            }),
            op(MountAction::Bind {
                source: c"/srv/tree".into(),
                target: c"work/tree".into(),
                read_only: false,
            }),
            op(MountAction::Symlink {
                parent: c"work/tree".into(),
                leaf: c"link".into(),
                content: c"target".into(),
            }),
        ];
        // The hide found nothing, so it holds no slot.
        let slots = [
            held_slot(),
            MountSlot::default(),
            held_slot(),
            MountSlot::default(),
        ];
        let root = open_root(std::path::Path::new("/"));
        let profile = Profile {
            root: root.as_fd(),
            ops: &ops,
            slots: &slots,
            procfs: None,
        };
        let anchored = |before, path: &CStr| {
            let anchor = profile.anchor(before, path);
            (
                anchor.map(|anchor| anchor.op),
                profile.beneath(anchor, path).map(CStr::to_owned),
            )
        };

        // Beneath the hide of nothing, the tmpfs under it.
        assert_eq!(
            anchored(2, c"work/secrets/key"),
            (Some(0), Some(c"secrets/key".into())),
        );
        // The bind is later, and nearer.
        assert_eq!(
            anchored(3, c"work/tree/a/b"),
            (Some(2), Some(c"a/b".into())),
        );
        // A target that is a mount's own is that mount, with nothing beneath.
        assert_eq!(anchored(3, c"work/tree"), (Some(2), Some(c"".into())));
        // Only the ops before the one asking count.
        assert_eq!(
            anchored(2, c"work/tree/a"),
            (Some(0), Some(c"tree/a".into()))
        );
        // A path no mount covers is the root's whole, and so is a sibling
        // whose name only begins like a target.
        assert_eq!(anchored(4, c"etc/x"), (None, Some(c"etc/x".into())));
        assert_eq!(anchored(4, c"workshop"), (None, Some(c"workshop".into())));
        // Strictly above: the mount at the path itself is crossed by name.
        let above = profile.anchor_above(4, c"work/tree");
        assert_eq!(above.map(|anchor| anchor.op), Some(0));
        assert_eq!(profile.beneath(above, c"work/tree"), Some(c"tree"));
    }

    #[test]
    fn a_path_beneath_a_mount_resolves_from_whatever_stacked_on_its_root() {
        let ops = [
            op(MountAction::Hide {
                target: c"run".into(),
                required: false,
            }),
            op(MountAction::Hide {
                target: c"var/run".into(),
                required: false,
            }),
        ];
        let slots = [held_slot(), held_slot()];
        // The second hide reached the first's root through a link.
        slots[0].covered_by.set(Some(1));
        let root = open_root(std::path::Path::new("/"));
        let profile = Profile {
            root: root.as_fd(),
            ops: &ops,
            slots: &slots,
            procfs: None,
        };
        let anchor = profile.anchor(2, c"run/x").expect("the hide covers it");
        // Beneath the first hide's target, from the second's mount.
        assert_eq!((anchor.op, anchor.held), (0, 1));
        assert_eq!(profile.beneath(Some(anchor), c"run/x"), Some(c"x"));
        // An op that ran before the cover resolves from the first.
        let anchor = profile.anchor(1, c"run/x").expect("the hide covers it");
        assert_eq!((anchor.op, anchor.held), (0, 0));
    }

    /// Forks a child that enters a user and a mount namespace of its own,
    /// executes the first of `ops` against `root`, waits while `between` runs
    /// in this process, then executes the rest and answers with `check`'s
    /// code. `procfs` names the op whose procfs a delegate would write through.
    /// `check` and the ops run under the post-fork discipline.
    fn run_profile(
        root: &CStr,
        ops: &[MountOp],
        procfs: Option<usize>,
        between: impl FnOnce(),
        check: impl FnOnce(&[MountSlot]) -> i32,
    ) -> Option<i32> {
        let (uid_line, gid_line) = crate::idmap::single_identity_lines();
        let slots: Vec<MountSlot> = ops.iter().map(|_| MountSlot::default()).collect();
        let null = fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
            .expect("/dev/null opens");
        let (parent_end, child_end) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("the socket pair is created");
        // SAFETY: the child makes raw syscalls only, over data allocated
        // before the fork, and ends in `exit_group`.
        match unsafe { sys::fork_with_pidfd() }.expect("the fork succeeds") {
            sys::PidfdFork::Child => {
                let duty = MapDuty::Write {
                    procfs: HOST_PROCFS,
                    uid_line: &uid_line,
                    gid_line: &gid_line,
                };
                let keep = [child_end.as_raw_fd(), null.as_raw_fd()];
                if enter_mapped_namespace(&keep, thread::UnshareFlags::NEWNS, duty, None).is_err()
                    || mount::mount_change(
                        c"/",
                        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
                    )
                    .is_err()
                {
                    sys::exit_group(100)
                }
                let Ok(root) = fs::open(
                    root,
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                ) else {
                    sys::exit_group(101)
                };
                let profile = Profile {
                    root: root.as_fd(),
                    ops,
                    slots: &slots,
                    procfs,
                };
                if execute_op(&profile, 0, null.as_fd()).is_err() {
                    sys::exit_group(102)
                }
                let mut byte = [0u8; 1];
                if rustix::io::write(&child_end, b"1").is_err()
                    || rustix::io::read(&child_end, &mut byte).is_err()
                {
                    sys::exit_group(103)
                }
                for index in 1..ops.len() {
                    if execute_op(&profile, index, null.as_fd()).is_err() {
                        sys::exit_group(104)
                    }
                }
                sys::exit_group(check(&slots))
            }
            sys::PidfdFork::ParentOf(child) => {
                drop(child_end);
                let mut byte = [0u8; 1];
                let ready = rustix::io::read(&parent_end, &mut byte);
                if ready == Ok(1) {
                    between();
                    let _ = rustix::io::write(&parent_end, b"1");
                }
                child.reap().expect("the child is collected")
            }
        }
    }

    /// The bytes a file holds, up to 16, or `None` where it cannot be read.
    /// Post-fork safe.
    fn contents(path: &CStr) -> Option<([u8; 16], usize)> {
        let file = fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).ok()?;
        let mut buf = [0u8; 16];
        let len = rustix::io::read(&file, &mut buf).ok()?;
        Some((buf, len))
    }

    /// A path as a C string.
    fn c_path(path: &std::path::Path) -> std::ffi::CString {
        std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("the path holds no NUL")
    }

    #[test]
    fn a_rename_between_two_ops_cannot_move_a_later_one_out_of_the_mount_above_it() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        // Another process writing the root renames the bind's mount point after
        // the bind and before the ops beneath it, and puts entries of its own
        // under the old name. The bind moves with its mount point, and the
        // hide and the path made read-only follow it there.
        let dir = Scratch::new("anchored-rename");
        let base = std::fs::canonicalize(dir.path()).expect("the scratch directory resolves");
        let (root, project) = (base.join("root"), base.join("project"));
        std::fs::create_dir_all(root.join("work")).unwrap();
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::write(project.join(".env"), b"secret").unwrap();
        std::fs::write(project.join(".git/config"), b"config").unwrap();

        let ops = [
            op(MountAction::Bind {
                source: c_path(&project),
                target: c"work".into(),
                read_only: false,
            }),
            op(MountAction::Hide {
                target: c"work/.env".into(),
                required: false,
            }),
            op(MountAction::ReadOnly {
                target: c"work/.git".into(),
                parent: c"work".into(),
            }),
        ];
        let moved_env = c_path(&root.join("moved/.env"));
        let moved_config = c_path(&root.join("moved/.git/config"));
        let decoy_env = c_path(&root.join("work/.env"));
        let decoy_config = c_path(&root.join("work/.git/config"));
        let code = run_profile(
            &c_path(&root),
            &ops,
            None,
            || {
                std::fs::rename(root.join("work"), root.join("moved")).unwrap();
                std::fs::create_dir_all(root.join("work/.git")).unwrap();
                std::fs::write(root.join("work/.env"), b"decoy").unwrap();
                std::fs::write(root.join("work/.git/config"), b"decoy").unwrap();
            },
            |_| {
                let writable = |path: &CStr| {
                    fs::open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty()).map(drop)
                };
                match contents(&moved_env) {
                    Some((_, 0)) => {}
                    _ => return 1,
                }
                match contents(&decoy_env) {
                    Some((buf, 5)) if &buf[..5] == b"decoy" => {}
                    _ => return 2,
                }
                if writable(&moved_config) != Err(Errno::ROFS) {
                    return 3;
                }
                if writable(&decoy_config).is_err() {
                    return 4;
                }
                0
            },
        );
        assert_eq!(
            code,
            Some(0),
            "1: the bound .env was not hidden; 2: the root's own .env was; 3: the bound \
             .git was left writable; 4: the root's own .git was made read-only; 100 and \
             up: the child could not set up",
        );
    }

    #[test]
    fn a_mount_stacked_on_another_through_a_link_takes_the_paths_beneath_it() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        // A host root hides `/run` and `/var/run`, a link to it, so the second
        // hide's tmpfs lands on the first's. A link made at a path beneath
        // `/run` is made in the tmpfs on top, where it can be seen.
        let dir = Scratch::new("anchored-stack");
        let base = std::fs::canonicalize(dir.path()).expect("the scratch directory resolves");
        let root = base.join("root");
        std::fs::create_dir_all(root.join("run")).unwrap();
        std::fs::create_dir_all(root.join("var")).unwrap();
        std::os::unix::fs::symlink("../run", root.join("var/run")).unwrap();

        let ops = [
            op(MountAction::Hide {
                target: c"run".into(),
                required: false,
            }),
            op(MountAction::Hide {
                target: c"var/run".into(),
                required: false,
            }),
            op(MountAction::Symlink {
                parent: c"run".into(),
                leaf: c"marker".into(),
                content: c"made".into(),
            }),
        ];
        let marker = c_path(&root.join("run/marker"));
        let code = run_profile(
            &c_path(&root),
            &ops,
            None,
            || {},
            |_| {
                let mut target = [0u8; 8];
                match fs::readlinkat_raw(fs::CWD, marker.as_c_str(), &mut target[..]) {
                    Ok(len) if &target[..len] == b"made" => 0,
                    _ => 1,
                }
            },
        );
        assert_eq!(
            code,
            Some(0),
            "1: the link was made in the tmpfs underneath; 100 and up: the child could not \
             set up",
        );
    }

    #[test]
    fn the_mount_a_delegate_writes_through_is_kept_from_its_own_step() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        // The delegate inside a PID namespace writes the command's map through
        // the procfs the profile made, by the descriptor its step returned,
        // not by its path, which a process sharing the root can put another
        // directory at. A tmpfs stands in for it here, since a procfs needs a
        // PID namespace of its own to mount, and nothing beneath it would keep
        // it otherwise.
        let dir = Scratch::new("kept-procfs");
        let base = std::fs::canonicalize(dir.path()).expect("the scratch directory resolves");
        let root = base.join("root");
        std::fs::create_dir_all(root.join("proc")).unwrap();
        let ops = [op(MountAction::Tmpfs {
            target: c"proc".into(),
            fs: FreshFs {
                fstype: c"tmpfs",
                params: &[],
                attributes: OWN_TMPFS_ATTRIBUTES,
            },
        })];
        let kept = |procfs| {
            run_profile(
                &c_path(&root),
                &ops,
                procfs,
                || {},
                |slots| {
                    let Some(held) = slots.first().and_then(|slot| slot.mount.take()) else {
                        return 1;
                    };
                    match fs::fstatfs(held.as_fd()) {
                        // `TMPFS_MAGIC`, which rustix does not name.
                        Ok(stat) if stat.f_type == 0x0102_1994 => 0,
                        _ => 2,
                    }
                },
            )
        };
        assert_eq!(kept(Some(0)), Some(0), "1: not kept; 2: not the tmpfs");
        assert_eq!(kept(None), Some(1), "nothing else keeps it");
    }

    #[test]
    fn a_map_is_written_only_through_a_procfs_and_beneath_it() {
        // Anything else is refused before a byte is written.
        assert_eq!(open_procfs(c"/").map(drop), Err(Errno::MEDIUMTYPE));
        let procfs = open_procfs(HOST_PROCFS).expect("the host's procfs opens");
        // `self` is a link of the procfs's own, and is followed; `root` beneath
        // it is a magic link, refused by name.
        assert_eq!(
            write_in_procfs(procfs.as_fd(), c"self/root/tmp/x", b""),
            Err(Errno::LOOP),
        );
        assert_eq!(
            write_in_procfs(procfs.as_fd(), c"../tmp/x", b""),
            Err(Errno::XDEV),
        );
    }

    #[test]
    fn a_target_a_teardown_is_removing_is_waited_for_and_created_anew() {
        // A teardown holds the target's exclusive lock while it removes it. A
        // launch that finds the lock refused waits, and creates the target
        // anew once it is gone, rather than bind onto a name about to go. The
        // teardown here is held for longer than a burst of yields lasts.
        let dir = Scratch::new("target-teardown");
        let root = open_root(dir.path());
        let target = dir.join("target");
        std::fs::write(&target, b"").unwrap();
        let removing = std::fs::File::open(&target).unwrap();
        removing.lock().expect("the teardown's lock is taken");
        let teardown = {
            let target = target.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(50));
                std::fs::remove_file(&target).unwrap();
                drop(removing);
            })
        };
        let (read, write) = rustix::pipe::pipe().expect("the report pipe opens");

        hold_file_target(root.as_fd(), c"target", 7, write.as_fd()).expect("the target is held");
        drop(write);
        teardown.join().unwrap();

        // The created record: the tag, the op, and the inode of the file
        // the launch made.
        let mut record = [0u8; super::super::REPORT_CREATED_LEN];
        assert_eq!(
            rustix::io::read(&read, &mut record),
            Ok(record.len()),
            "the target was not created anew",
        );
        assert_eq!(record[0..4], super::super::REPORT_CREATED.to_le_bytes());
        assert_eq!(record[4..8], 7u32.to_le_bytes());
        let made = std::fs::metadata(&target).expect("the target was created anew");
        assert_eq!(
            record[8..16],
            std::os::unix::fs::MetadataExt::ino(&made).to_le_bytes(),
        );
    }

    #[test]
    fn a_mount_target_through_a_magic_link_is_refused_by_name() {
        // A procfs inside the root holds magic links, and a target named
        // through one is refused. `RESOLVE_IN_ROOT` alone refuses the jump with
        // `EXDEV`, a refusal the kernel reserves the right to lift; refused by
        // name, it is `ELOOP`.
        let root = open_root(std::path::Path::new("/"));
        let held =
            fs::open(c"/", OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).expect("the root opens");
        let path = std::ffi::CString::new(format!("proc/self/fd/{}", held.as_raw_fd()))
            .expect("the path holds no NUL");

        assert_eq!(
            open_in_root(root.as_fd(), &path, OFlags::PATH).map(drop),
            Err(Errno::LOOP),
        );
    }

    #[test]
    fn a_stack_path_drops_what_would_end_it_early_or_overrun_it() {
        let mut path = StackPath::new();
        path.push(b"/proc/self/fd/");
        path.push(b"3\0/etc");
        path.push_decimal(7);
        assert_eq!(path.as_cstr(), c"/proc/self/fd/7");
        assert!(path.dropped());
        let mut path = StackPath::new();
        path.push(b"/proc/self/fd/7");
        assert!(!path.dropped());
        path.push(&[b'x'; 48]);
        assert_eq!(path.as_cstr(), c"/proc/self/fd/7");
        assert!(path.dropped());
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

    #[test]
    fn a_closed_standard_number_is_held_until_the_exec() {
        // In a forked child of its own, since closing a standard stream is
        // process-wide. The child answers through its exit code, the only thing
        // it can report without allocating.
        let null = fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
            .expect("/dev/null opens");
        // SAFETY: the child makes raw syscalls only, through rustix, and ends
        // in `exit_group`.
        match unsafe { sys::fork_with_pidfd() }.expect("the fork succeeds") {
            sys::PidfdFork::Child => sys::in_child(|| {
                // SAFETY: the numbers are this child's own copies of the
                // standard streams, which nothing in it holds or uses again.
                unsafe {
                    rustix::io::close(0);
                    rustix::io::close(2);
                }
                if hold_closed_streams(null.as_fd()).is_err() {
                    sys::exit_group(1)
                }
                let flags = |fd| rustix::io::fcntl_getfd(fd).ok();
                // The closed ones are held, close-on-exec, and the open one is
                // left as it was.
                let cloexec = Some(rustix::io::FdFlags::CLOEXEC);
                if flags(rustix::stdio::stdin()) != cloexec
                    || flags(rustix::stdio::stderr()) != cloexec
                    || flags(rustix::stdio::stdout()) == cloexec
                {
                    sys::exit_group(2)
                }
                // Nothing created afterwards lands on a standard number.
                match fs::open(
                    c"/dev/null",
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(fd) if fd.as_raw_fd() > STDERR_FILENO => sys::exit_group(0),
                    _ => sys::exit_group(3),
                }
            }),
            sys::PidfdFork::ParentOf(child) => {
                assert_eq!(
                    child.reap(),
                    Ok(Some(0)),
                    "1: the hold failed; 2: a number was not held close-on-exec, or the \
                     open one was touched; 3: a descriptor landed on a standard number",
                );
            }
        }
    }

    #[test]
    fn the_command_is_withheld_once_its_map_is_written_and_not_before() {
        if !ferroday_cage_testkit::require::not_root(
            "root owns its processes' /proc files dumpable or not",
        ) {
            return;
        }
        let (uid_line, gid_line) = crate::idmap::single_identity_lines();
        let duty = || MapDuty::Write {
            procfs: HOST_PROCFS,
            uid_line: &uid_line,
            gid_line: &gid_line,
        };

        // As the command: its map written, then withheld with every signal
        // blocked until then, and held there for the parent to look at.
        let (ready, ready_end) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC).expect("a pipe");
        let (hold_end, hold) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC).expect("a pipe");
        // SAFETY: the child makes raw syscalls only, through rustix, `sys` and
        // the shared map sequence, and ends in `exit_group`.
        let child = match unsafe { sys::fork_with_pidfd() }.expect("the fork succeeds") {
            sys::PidfdFork::Child => sys::in_child(|| {
                let keep = [ready_end.as_raw_fd(), hold_end.as_raw_fd()];
                if enter_mapped_namespace(&keep, UnshareFlags::empty(), duty(), None).is_err() {
                    sys::exit_group(1)
                }
                // SAFETY: blocking signals runs nothing.
                if unsafe { sys::sigprocmask(How::SetMask, Some(&SigSet::all())) }.is_err()
                    || withhold_image().is_err()
                    || rustix::io::write(&ready_end, b"R").is_err()
                {
                    sys::exit_group(2)
                }
                let mut byte = [0u8; 1];
                let _ = rustix::io::read(&hold_end, &mut byte);
                sys::exit_group(0)
            }),
            sys::PidfdFork::ParentOf(child) => child,
        };
        drop((ready_end, hold_end));
        let mut byte = [0u8; 1];
        if rustix::io::read(&ready, &mut byte) != Ok(1) {
            let _ = child.reap();
            ferroday_cage_testkit::require::USERNS
                .skip("a forked child could not enter a user namespace of its own");
            return;
        }
        let pid = child.pid().as_raw_nonzero().get();
        let owner = fs::stat(format!("/proc/{pid}/environ"))
            .expect("the child's environment is there to stat")
            .st_uid;
        let status =
            std::fs::read_to_string(format!("/proc/{pid}/status")).expect("the status reads");
        drop(hold);
        assert_eq!(child.reap(), Ok(Some(0)));
        assert_eq!(owner, 0, "the withheld command's /proc files are root's");
        assert_eq!(
            ferroday_cage_testkit::process::status_field(&status, "SigBlk"),
            Some("0000000000000000"),
            "the withheld command blocks no signal"
        );

        // Withheld first, the map can no longer be written: why the command
        // waits for it.
        // SAFETY: as above.
        match unsafe { sys::fork_with_pidfd() }.expect("the fork succeeds") {
            sys::PidfdFork::Child => sys::in_child(|| {
                if withhold_image().is_err() {
                    sys::exit_group(2)
                }
                match enter_mapped_namespace(&[], UnshareFlags::empty(), duty(), None) {
                    Err(MapFailure::Step(MapStep::DenySetgroups, Errno::ACCESS)) => {
                        sys::exit_group(0)
                    }
                    _ => sys::exit_group(1),
                }
            }),
            sys::PidfdFork::ParentOf(child) => assert_eq!(
                child.reap(),
                Ok(Some(0)),
                "1: the map was written, or failed another way; 2: the process could not be \
                 withheld"
            ),
        }
    }

    /// Enters `target`'s namespaces of `namespaces` through `/proc/<pid>/ns`,
    /// the route a kernel that joins nothing through a pidfd takes, in a forked
    /// child, and answers its exit code: `0` where its host name is then
    /// `holder`, `1` where the entries did not open, `2` where they were not
    /// entered, `3` where the namespace entered was another's, and `4` where
    /// the holder had exited.
    fn enter_through_procfs(target: JoinTarget<'_>, namespaces: UnshareFlags) -> Option<i32> {
        // SAFETY: the child makes raw syscalls only, through rustix, and ends
        // in `exit_group`.
        match unsafe { sys::fork_with_pidfd() }.expect("the fork succeeds") {
            sys::PidfdFork::Child => sys::in_child(|| {
                let mut entry = SandboxEntry::new(target, namespaces);
                match entry.open() {
                    Ok(()) => {}
                    Err(Errno::SRCH) => sys::exit_group(4),
                    Err(_) => sys::exit_group(1),
                }
                if entry.enter(namespaces).is_err() {
                    sys::exit_group(2)
                }
                let name = rustix::system::uname();
                sys::exit_group(if name.nodename().to_bytes() == b"holder" {
                    0
                } else {
                    3
                })
            }),
            sys::PidfdFork::ParentOf(joiner) => joiner.reap().expect("the joiner is reaped"),
        }
    }

    #[test]
    fn a_sandbox_is_entered_through_its_holders_procfs_entries() {
        // A holder in a user and UTS namespace of its own, named `holder`,
        // which signals once it is there and holds until its pipe closes.
        let (uid_line, gid_line) = crate::idmap::single_identity_lines();
        let (ready, ready_end) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC).expect("a pipe");
        let (hold_end, hold) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC).expect("a pipe");
        // SAFETY: the holder makes raw syscalls only, through rustix and the
        // shared map sequence, and ends in `exit_group`.
        let holder = match unsafe { sys::fork_with_pidfd() }.expect("the fork succeeds") {
            sys::PidfdFork::Child => sys::in_child(|| {
                let duty = MapDuty::Write {
                    procfs: HOST_PROCFS,
                    uid_line: &uid_line,
                    gid_line: &gid_line,
                };
                let keep = [ready_end.as_raw_fd(), hold_end.as_raw_fd()];
                if enter_mapped_namespace(&keep, UnshareFlags::NEWUTS, duty, None).is_err()
                    || rustix::system::sethostname(b"holder").is_err()
                    || rustix::io::write(&ready_end, b"R").is_err()
                {
                    sys::exit_group(1)
                }
                let mut byte = [0u8; 1];
                let _ = rustix::io::read(&hold_end, &mut byte);
                sys::exit_group(0)
            }),
            sys::PidfdFork::ParentOf(holder) => holder,
        };
        drop((ready_end, hold_end));
        let mut byte = [0u8; 1];
        if rustix::io::read(&ready, &mut byte) != Ok(1) {
            let _ = holder.reap();
            ferroday_cage_testkit::require::USERNS
                .skip("a forked child could not enter a user namespace of its own");
            return;
        }
        let target = JoinTarget {
            holder: holder.pidfd(),
            pid: holder.pid().as_raw_nonzero().get() as u32,
        };
        let namespaces = UnshareFlags::NEWUSER | UnshareFlags::NEWUTS;

        assert_eq!(
            enter_through_procfs(target, namespaces),
            Some(0),
            "1: the entries did not open; 2: they were not entered; 3: the namespace \
             entered was not the holder's; 4: the holder was taken for exited",
        );

        // Exited and not yet collected, the holder still has its user
        // namespace's entry, and no other; the sandbox has ended all the same.
        drop(hold);
        assert!(
            super::super::exits_within(holder.pidfd(), Duration::from_secs(10)),
            "the holder exits once its pipe closes"
        );
        assert_eq!(enter_through_procfs(target, namespaces), Some(4));
        assert_eq!(holder.reap(), Ok(Some(0)));
    }
}
