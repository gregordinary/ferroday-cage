//! The post-fork stages: namespaces, sandbox setup, the command exec, and
//! the supervisor.
//!
//! A launch runs across a small tree of forked processes. Stage A is forked
//! from the caller and is short-lived: it scrubs the inherited signal state,
//! unshares the namespaces, sweeps the inherited descriptor table, forks the
//! next stage, and publishes that stage's pidfd back to the caller over the
//! control socket.
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
//! Everything here executes between `kernel_fork` and `execve` or
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
//! Every operation below is a raw rustix syscall over data frozen by the
//! caller before the fork.
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
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{self, AtFlags, Mode, OFlags, RawDir, ResolveFlags, StatVfsMountFlags};
use rustix::io::Errno;
use rustix::ioctl;
use rustix::mount::{self, MountFlags, MountPropagationFlags, UnmountFlags};
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use rustix::process::Pid;
use rustix::process::Signal;
use rustix::process::{self, PidfdFlags, WaitOptions, WaitStatus};
use rustix::runtime::{self, How, KernelSigSet, KernelSigaction};
use rustix::thread;
use syscalls::Sysno;

use super::{
    IdentityPlan, LaunchPlan, MountAction, MountOp, STATUS_EXITED, STATUS_SIGNALED, StdinPlan,
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
    pub(super) stdout_fd: Option<BorrowedFd<'a>>,
    /// Write end of the captured standard error, when observing.
    pub(super) stderr_fd: Option<BorrowedFd<'a>>,
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
}

/// A failed setup step: the step, the errno, and the 1-based index of the
/// mount op it belonged to (zero when the step has no op).
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
            runtime::exit_group(127)
        }
    }
}

/// The launch stage proper. Returns only on failure, naming the step.
fn run_stage_a(context: &Context<'_>) -> Result<Infallible, Failure> {
    let plan = context.plan;

    // Scrub the inherited signal state first: every disposition back to the
    // default and an empty mask. The caller's ignored dispositions would
    // survive exec into the command (a Rust caller ignores SIGPIPE, for
    // one), and an inherited signal handler running inside these
    // no-allocation processes would violate their constraints. After the
    // reset, neither can happen.
    reset_signals().map_err(|errno| (SetupStep::ResetSignals, errno, 0))?;

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
    // the sandbox's lifetime.
    sweep_fds(context).map_err(|errno| (SetupStep::SweepFds, errno, 0))?;

    // Establish the identity map, after the sweep so the map gate survives
    // it, and before any further fork so every sandbox stage runs in a
    // fully mapped namespace. This stage is the process that unshared, so
    // its /proc/self map files name the new namespace.
    if matches!(plan.confinement, super::Confinement::Container) {
        establish_identity_map(context)?;
    }

    let fork_step = if plan.pid_namespace {
        SetupStep::ForkInit
    } else {
        SetupStep::ForkCommand
    };
    // SAFETY: the child process continues with frozen data and raw syscalls
    // only, per this module's constraints, and never returns.
    match unsafe { runtime::kernel_fork() }.map_err(|errno| (fork_step, errno, 0))? {
        runtime::Fork::Child(_) => {
            if plan.pid_namespace {
                stage_init(context)
            } else {
                stage_command(context)
            }
        }
        runtime::Fork::ParentOf(child) => {
            let pidfd = match publish_supervised(context, child) {
                Ok(pidfd) => pidfd,
                Err(errno) => {
                    // The caller never received the supervisor, so the
                    // just-forked process must not outlive this failure:
                    // kill and collect it before reporting, so it cannot
                    // run unsupervised or write a report record of its own.
                    let _ = process::kill_process(child, Signal::KILL);
                    while let Err(Errno::INTR) = process::waitpid(Some(child), WaitOptions::empty())
                    {
                    }
                    return Err((SetupStep::SendPidfd, errno, 0));
                }
            };
            if plan.pid_namespace {
                // The init supervises itself from inside the namespace;
                // this stage's work is done.
                runtime::exit_group(0)
            } else {
                supervisor_hygiene(context);
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
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut space);
    let fds = [pidfd.as_fd()];
    ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(&fds));
    loop {
        match rustix::net::sendmsg(
            context.control_fd,
            &[std::io::IoSlice::new(&payload)],
            &mut ancillary,
            rustix::net::SendFlags::NOSIGNAL,
        ) {
            Ok(_) => return Ok(pidfd),
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(errno),
        }
    }
}

/// Stage init: PID 1 of the new PID namespace. Sets the sandbox up, forks
/// the command as PID 2, and supervises it from inside.
fn stage_init(context: &Context<'_>) -> ! {
    if let Err((step, errno, detail)) = setup_sandbox(context) {
        report(context.report_fd, step, errno, detail);
        runtime::exit_group(127)
    }

    // SAFETY: as at every fork here: the child process touches only frozen
    // data and raw syscalls, and never returns.
    match unsafe { runtime::kernel_fork() } {
        Err(errno) => {
            report(context.report_fd, SetupStep::ForkCommand, errno, 0);
            runtime::exit_group(127)
        }
        Ok(runtime::Fork::Child(_)) => exec_command(context),
        Ok(runtime::Fork::ParentOf(command)) => {
            // The command's pidfd is what lets the supervisor sleep in one
            // poll; opened before anything else so a failure is still
            // reportable.
            let pidfd = match process::pidfd_open(command, PidfdFlags::empty()) {
                Ok(pidfd) => pidfd,
                Err(errno) => {
                    report(context.report_fd, SetupStep::WatchCommand, errno, 0);
                    runtime::exit_group(127)
                }
            };
            supervisor_hygiene(context);
            supervise(context, pidfd.as_fd(), command, Role::Init)
        }
    }
}

/// Stage command without a PID namespace: setup and exec in one process,
/// supervised from outside by stage A. In a container the setup is the full
/// sandbox sequence; in a restriction there is nothing to build and only the
/// working directory changes.
fn stage_command(context: &Context<'_>) -> ! {
    let setup = match context.plan.confinement {
        super::Confinement::Container => setup_sandbox(context),
        #[cfg(feature = "hardening")]
        super::Confinement::Restriction => setup_restriction(context),
    };
    if let Err((step, errno, detail)) = setup {
        report(context.report_fd, step, errno, detail);
        runtime::exit_group(127)
    }
    exec_command(context)
}

/// The restriction setup: no namespaces to configure and no root to swap —
/// only the working directory changes, resolved against the host filesystem,
/// before the hardening and the exec.
#[cfg(feature = "hardening")]
fn setup_restriction(context: &Context<'_>) -> Result<(), Failure> {
    if let Some(workdir) = &context.plan.workdir {
        process::chdir(workdir.as_c_str()).map_err(|errno| (SetupStep::ChdirWorkdir, errno, 0))?;
    }
    Ok(())
}

/// Wires the command's standard streams and executes the command.
///
/// Never returns: on success `execve` replaces the process image, and on
/// failure the step and errno are reported over the report pipe and the
/// process exits. The exit status of a failed stage is not meaningful to
/// the caller, which trusts the pipe record instead.
fn exec_command(context: &Context<'_>) -> ! {
    if let Err(errno) = wire_stdio(context) {
        report(context.report_fd, SetupStep::WireStdio, errno, 0);
        runtime::exit_group(127)
    }

    // The launch gate, when the caller requested one: block until the caller
    // releases the command. This is the seam at which a userspace network
    // stack is attached to the sandbox's network namespace — the caller holds
    // the command here, joins the namespace and brings up its tap, then
    // proceeds. The wait is before the hardening layer so a seccomp filter
    // cannot deny the read that releases it.
    if let Some(proceed) = context.proceed_fd
        && let Err((step, errno)) = await_proceed(proceed)
    {
        report(context.report_fd, step, errno, 0);
        runtime::exit_group(127)
    }

    // The resource limits, applied before the hardening layer: the command
    // still holds its in-namespace capabilities here, so raising a hard limit
    // within the caller's own is permitted, and no seccomp filter is installed
    // yet that could deny the call. Each limit is inherited across `execve` and
    // by every process the command starts.
    if let Err((step, errno, detail)) = apply_rlimits(context) {
        report(context.report_fd, step, errno, detail);
        runtime::exit_group(127)
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
    if let Err((step, errno)) = super::harden::apply_pre_switch(&context.plan.hardening) {
        report(context.report_fd, step, errno, 0);
        runtime::exit_group(127)
    }

    if let Err((step, errno)) = switch_identity(context) {
        report(context.report_fd, step, errno, 0);
        runtime::exit_group(127)
    }

    #[cfg(feature = "hardening")]
    if let Err((step, errno)) = super::harden::apply_post_switch(&context.plan.hardening) {
        report(context.report_fd, step, errno, 0);
        runtime::exit_group(127)
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
            runtime::execve(
                &context.plan.program,
                context.argv.as_ptr(),
                context.envp.as_ptr(),
            )
        }
    } else {
        exec_search(context)
    };
    report(context.report_fd, SetupStep::Exec, errno, 0);
    runtime::exit_group(127)
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
        last = unsafe { runtime::execve(candidate, context.argv.as_ptr(), context.envp.as_ptr()) };
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
        process::setrlimit(entry.resource, entry.limit).map_err(|errno| {
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
/// null stdin, the capture pipes when observing.
///
/// `dup2` clears close-on-exec on its target as a side effect, which is what
/// lets the redirected stream survive `execve` while every original copy still
/// closes. The one exception is `dup2(fd, fd)`, a kernel no-op that leaves the
/// flag set. Only a caller-supplied [`StdinPlan::Fd`](super::StdinPlan::Fd) that
/// already sits at file descriptor 0 can reach it: the launch creates six
/// descriptors of its own before the null descriptor and the capture pipes, so
/// those always land at 3 or above. Clearing close-on-exec explicitly keeps the
/// stream from closing at exec, which would otherwise leave the command without
/// it and without an error.
fn wire_stdio(context: &Context<'_>) -> Result<(), Errno> {
    // The standard stream numbers `dup2` targets. A source descriptor already
    // at its target number needs close-on-exec cleared directly, since
    // `dup2(fd, fd)` is a no-op that leaves the flag set.
    const STDIN: RawFd = 0;
    const STDOUT: RawFd = 1;
    const STDERR: RawFd = 2;
    let stdin = match &context.plan.stdin {
        StdinPlan::Inherit => None,
        StdinPlan::Null => Some(context.null_fd),
        // The caller's descriptor, kept through the sweep and carried here.
        StdinPlan::Fd(_) => context.stdin_fd,
    };
    if let Some(stdin) = stdin {
        if stdin.as_raw_fd() == STDIN {
            clear_cloexec(stdin)?;
        } else {
            rustix::stdio::dup2_stdin(stdin)?;
        }
    }
    if let Some(stdout) = context.stdout_fd {
        if stdout.as_raw_fd() == STDOUT {
            clear_cloexec(stdout)?;
        } else {
            rustix::stdio::dup2_stdout(stdout)?;
        }
    }
    if let Some(stderr) = context.stderr_fd {
        if stderr.as_raw_fd() == STDERR {
            clear_cloexec(stderr)?;
        } else {
            rustix::stdio::dup2_stderr(stderr)?;
        }
    }
    Ok(())
}

/// Clears close-on-exec on `fd` so it survives `execve`. `FD_CLOEXEC` is the
/// only file-descriptor flag, so an empty flag set clears it.
fn clear_cloexec(fd: BorrowedFd<'_>) -> Result<(), Errno> {
    rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::empty())
}

/// Switches to the configured run-as identity, immediately before the
/// capability drop and `execve`.
///
/// The order is forced by the kernel: supplementary groups and the gid
/// first, while `CAP_SETGID` is effective, and the uid last, because after
/// it the gid is no longer settable. The groups call sets the run-as
/// identity's supplementary groups, and happens only under a range map. Under
/// the single-identity map it is skipped — `setgroups` is denied there, and
/// the build rejects a run-as identity that names groups — so the command
/// keeps the process's inherited supplementary group list. That list still
/// grants nothing the caller has on the host: the namespace's single-entry
/// gid map presents every other gid as the overflow gid, which is what bounds
/// group membership under a single map, not a clearing call here.
///
/// All three calls are the thread-scoped raw syscalls: this process is
/// single-threaded, so no cross-thread broadcast is needed and none of
/// libc's setxid machinery is involved.
fn switch_identity(context: &Context<'_>) -> Result<(), (SetupStep, Errno)> {
    let Some(run_as) = &context.plan.run_as else {
        return Ok(());
    };
    if context.plan.identity.is_ranged() {
        rustix::thread::set_thread_groups(&run_as.groups)
            .map_err(|errno| (SetupStep::SetGroups, errno))?;
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
    loop {
        match rustix::io::read(fd, &mut byte) {
            Ok(0) => return Err((SetupStep::AwaitNetworkStack, Errno::CANCELED)),
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => continue,
            Err(errno) => return Err((SetupStep::AwaitNetworkStack, errno)),
        }
    }
}

/// Establishes the new user namespace's identity map, from stage A.
///
/// The single-identity map is written in process: denying `setgroups` first
/// is what permits an unprivileged process to write its own gid map, and
/// the one-id exception permits nothing more. Any range map is written from
/// outside by the caller's delegate — a process that has just unshared
/// cannot write its own range map even if it was privileged before, because
/// capabilities extend to a namespace's descendants and never to its
/// ancestors — so this stage signals ready on the map gate and blocks until
/// the caller releases it. End-of-file on the gate means the caller
/// abandoned the launch (its delegate failed); the failure is reported for
/// form, though the caller prefers the delegate's own error. The gate
/// descriptor is closed before the stage forks, so no sandbox stage
/// inherits it.
///
/// For a range map `setgroups` stays at `allow`: that is what makes
/// supplementary groups (and a later `setgroups` inside) possible, and a
/// privileged delegate's gid-map write does not need the denial.
fn establish_identity_map(context: &Context<'_>) -> Result<(), Failure> {
    match &context.plan.identity {
        IdentityPlan::Single => {
            write_file(c"/proc/self/setgroups", b"deny")
                .map_err(|errno| (SetupStep::DenySetgroups, errno, 0))?;
            write_file(c"/proc/self/gid_map", context.gid_line)
                .map_err(|errno| (SetupStep::WriteGidMap, errno, 0))?;
            write_file(c"/proc/self/uid_map", context.uid_line)
                .map_err(|errno| (SetupStep::WriteUidMap, errno, 0))?;
        }
        IdentityPlan::Ranged { .. } => {
            let Some(gate) = context.map_gate_fd else {
                // fork_launch pairs every ranged plan with a gate; a missing
                // one is a defect reported as a bad descriptor, since this
                // process must not panic.
                return Err((SetupStep::AwaitIdentityMap, Errno::BADF, 0));
            };
            loop {
                match rustix::io::write(gate, &[super::MAP_READY_BYTE]) {
                    Ok(_) => break,
                    Err(Errno::INTR) => continue,
                    Err(errno) => return Err((SetupStep::AwaitIdentityMap, errno, 0)),
                }
            }
            let mut byte = [0u8; 1];
            loop {
                match rustix::io::read(gate, &mut byte) {
                    Ok(0) => return Err((SetupStep::AwaitIdentityMap, Errno::CANCELED, 0)),
                    Ok(_) => break,
                    Err(Errno::INTR) => continue,
                    Err(errno) => return Err((SetupStep::AwaitIdentityMap, errno, 0)),
                }
            }
            // SAFETY: the raw descriptor is this process's own gate end,
            // closed exactly once here and never used again in this process.
            unsafe { rustix::io::close(gate.as_raw_fd()) };
        }
    }
    Ok(())
}

/// The sandbox setup sequence: the identity-dependent namespace
/// configuration through the root swap. The identity map itself is already
/// established — by stage A, before this stage was forked.
fn setup_sandbox(context: &Context<'_>) -> Result<(), Failure> {
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
    // that map.
    match &plan.overlay {
        None => {
            mount::mount_bind_recursive(&plan.rootfs_path, &plan.rootfs_path)
                .map_err(|errno| (SetupStep::BindRootfs, errno, 0))?;
        }
        Some(overlay) => {
            mount::mount(
                c"overlay",
                plan.rootfs_path.as_c_str(),
                c"overlay",
                MountFlags::empty(),
                overlay.options.as_c_str(),
            )
            .map_err(|errno| (SetupStep::MountOverlayRoot, errno, 0))?;
        }
    }

    // Open the root mount just created. Opening the path anew lands on top
    // of the mount stack — the new mount — and the descriptor anchors both
    // the mount-target resolution below and the pivot.
    let newroot = rustix::fs::open(
        &plan.rootfs_path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| (SetupStep::EnterRootfs, errno, 0))?;

    // The mount profile: host bind sources are still resolvable (the host
    // tree is mounted until the pivot), and every target resolves inside
    // the new root.
    for (index, op) in plan.ops.iter().enumerate() {
        execute_op(newroot.as_fd(), op).map_err(|(step, errno)| (step, errno, index as u32 + 1))?;
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

    Ok(())
}

/// Who the supervisor is relative to the sandbox.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// PID 1 inside the sandbox's PID namespace. Its own exit tears the
    /// namespace down.
    Init,
    /// Stage A outside the sandbox, when no PID namespace was requested.
    Outside,
}

/// Detaches the supervisor from the caller's streams before the long watch:
/// the report-pipe copy closes (the exec convention needs every copy gone),
/// the capture-pipe copies close (their end-of-file must track the command,
/// not this process), a caller-supplied standard input closes (the supervisor
/// must not pin a caller resource for the sandbox's lifetime), stdio repoints
/// at `/dev/null` (a pipeline reading the caller's stdout must not wait for
/// the supervisor), and SIGPIPE becomes ignored so a status write after the
/// handle is dropped fails with `EPIPE` instead of killing the supervisor.
///
/// Everything here is best-effort: past this point there is no report pipe
/// to fail through, and none of these operations can fail in a way that
/// compromises supervision.
fn supervisor_hygiene(context: &Context<'_>) {
    // SAFETY: these raw descriptors are this process's own copies of the
    // launch channels, closed exactly once here and never used again in
    // this process.
    unsafe {
        rustix::io::close(context.report_fd.as_raw_fd());
        if let Some(stdout) = context.stdout_fd {
            rustix::io::close(stdout.as_raw_fd());
        }
        if let Some(stderr) = context.stderr_fd {
            rustix::io::close(stderr.as_raw_fd());
        }
        // A caller-supplied standard input, if it landed anywhere but on the
        // standard-stream numbers the repoint below covers.
        if let Some(stdin) = context.stdin_fd
            && stdin.as_raw_fd() > 2
        {
            rustix::io::close(stdin.as_raw_fd());
        }
    }
    let _ = rustix::stdio::dup2_stdin(context.null_fd);
    let _ = rustix::stdio::dup2_stdout(context.null_fd);
    let _ = rustix::stdio::dup2_stderr(context.null_fd);
    // SAFETY: the null descriptor's job ends with the stdio repoint above;
    // closed exactly once and never used again in this process.
    unsafe { rustix::io::close(context.null_fd.as_raw_fd()) };
    let ignore = KernelSigaction {
        sa_handler_kernel: runtime::kernel_sig_ign(),
        ..Default::default()
    };
    // SAFETY: installing SIG_IGN carries no handler address and so none of
    // `kernel_sigaction`'s trampoline hazards.
    let _ = unsafe { runtime::kernel_sigaction(Signal::PIPE, Some(ignore)) };
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
            Err(_) => runtime::exit_group(127),
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
                            Role::Init => runtime::exit_group(1),
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
        loop {
            match process::waitpid(None, WaitOptions::NOHANG) {
                Ok(Some((pid, status))) if pid == child => {
                    report_status(context.status_fd, status);
                    runtime::exit_group(0)
                }
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(Errno::INTR) => continue,
                // No children left yet no status for the supervised
                // process: something else reaped it. Unreportable;
                // exiting without a record surfaces as a lost
                // supervisor.
                Err(_) => runtime::exit_group(127),
            }
        }
    }
}

/// The control-socket request byte for graceful termination.
pub(crate) const CONTROL_TERMINATE: u8 = b'T';

/// Writes the 8-byte status record: the kind discriminant and the value,
/// little-endian. At 8 bytes the write is atomic under `PIPE_BUF`. A failed
/// write means the caller dropped the handle; with SIGPIPE ignored it is
/// an `EPIPE` to swallow, since there is no one left to report to.
fn report_status(fd: BorrowedFd<'_>, status: WaitStatus) {
    let (kind, value) = if let Some(code) = status.exit_status() {
        (STATUS_EXITED, code)
    } else if let Some(signal) = status.terminating_signal() {
        (STATUS_SIGNALED, signal)
    } else {
        // Neither exited nor signaled cannot describe a reaped process;
        // exit without a record rather than invent one.
        runtime::exit_group(127)
    };
    let mut record = [0u8; 8];
    record[0..4].copy_from_slice(&kind.to_le_bytes());
    record[4..8].copy_from_slice(&value.to_le_bytes());
    let _ = rustix::io::write(fd, &record);
}

/// Resets every signal disposition to the default and empties the signal
/// mask, in that order.
///
/// The order matters. `fork` clears the pending set but not the mask, and it
/// carries the caller's handlers into the child. Emptying the mask first would
/// open a window in which a *newly delivered* signal — a process-group signal, a
/// terminal's `SIGWINCH`, an inherited interval timer — runs one of those
/// handlers inside a process that must not allocate, take a lock, or panic.
/// Resetting the dispositions first leaves nothing to run when the mask comes
/// off.
pub(super) fn reset_signals() -> Result<(), Errno> {
    for number in 1..=64 {
        if number == Signal::KILL.as_raw() || number == Signal::STOP.as_raw() {
            continue;
        }
        // SAFETY: the numbers are non-zero and within the kernel's signal
        // range on every architecture.
        let signal = unsafe { Signal::from_raw_unchecked(number) };
        // SAFETY: installing SIG_DFL carries no handler address and so none
        // of `kernel_sigaction`'s trampoline hazards.
        match unsafe { runtime::kernel_sigaction(signal, Some(KernelSigaction::default())) } {
            Ok(_) => {}
            // Numbers the kernel reserves are skipped, not errors.
            Err(Errno::INVAL) => {}
            Err(errno) => return Err(errno),
        }
    }
    // SAFETY: replacing the whole mask with an empty set neither unblocks a
    // handler-less signal mid-handler nor races other threads; this process
    // is single-threaded and freshly forked, with no pending set (fork
    // clears it) and, after the loop above, no inherited handler to run.
    unsafe { runtime::kernel_sigprocmask(How::SETMASK, Some(&KernelSigSet::empty())) }?;
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
        context.stdout_fd,
        context.stderr_fd,
        context.proceed_fd,
        context.map_gate_fd,
        context.stdin_fd,
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
pub(super) fn sweep_fds_keeping(keep: &[RawFd]) -> Result<(), Errno> {
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

/// Creates one mount-target directory at exactly `mode`, leaving an existing
/// entry — directory or symlink — untouched.
///
/// The mode is set again after the `mkdir` because `mkdir` narrows it by the
/// process umask, and the mount point outlives the sandbox: a launch under
/// `umask 077` would otherwise leave a `0700` `/tmp` in the rootfs for a
/// provisioned tree to carry forward. Setting it only on the directory this
/// call just created keeps the rootfs's own modes intact — the tree owns what
/// it ships, the sandbox owns what it creates.
fn create_mount_dir(dir: BorrowedFd<'_>, leaf: &CStr, mode: Mode) -> Result<(), Errno> {
    match fs::mkdirat(dir, leaf, mode) {
        Ok(()) => fs::chmodat(dir, leaf, mode, AtFlags::empty()),
        Err(Errno::EXIST) => Ok(()),
        Err(errno) => Err(errno),
    }
}

/// Executes one frozen mount op against the new root.
fn execute_op(root: BorrowedFd<'_>, op: &MountOp) -> Result<(), (SetupStep, Errno)> {
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
    // it; create it empty. An existing file is opened and left as it is.
    if let Some(file) = &op.create_file {
        open_in_root_with(
            root,
            file,
            OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
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
            {
                let target = open_in_root(root, target, OFlags::PATH)
                    .map_err(|errno| (SetupStep::OpenMountTarget, errno))?;
                mount::mount_bind_recursive(source.as_c_str(), fd_path(&target).as_cstr())
                    .map_err(|errno| (SetupStep::BindMount, errno))?;
            }
            if *read_only {
                remount_read_only(root, target).map_err(|errno| (SetupStep::RemountReadOnly, errno))
            } else {
                Ok(())
            }
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
            let parent = open_in_root(root, parent, OFlags::PATH | OFlags::DIRECTORY)
                .map_err(|errno| (SetupStep::OpenMountTarget, errno))?;
            fs::symlinkat(content.as_c_str(), &parent, leaf.as_c_str())
                .map_err(|errno| (SetupStep::CreateSymlink, errno))
        }
    }
}

/// Remounts the bind mount at `target`, and every mount beneath it,
/// read-only.
///
/// The target is re-resolved so the descriptor references the bind mount just
/// created, now top of the mount stack. `mount_setattr` with `AT_RECURSIVE`
/// marks the whole subtree read-only in one atomic call and needs no locked-
/// flag handling, because it only adds a restriction; it is preferred so a
/// read-only bind of a tree that carries its own submounts leaves those
/// submounts read-only too. On a kernel without `mount_setattr` (before 5.12)
/// this falls back to a top-level remount, which covers the bind itself but
/// leaves any submounts with their own flags.
fn remount_read_only(root: BorrowedFd<'_>, target: &CStr) -> Result<(), Errno> {
    let target = fs::openat2(
        root,
        target,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::IN_ROOT,
    )?;
    match mount_setattr_recursive_read_only(target.as_fd()) {
        Ok(()) => Ok(()),
        Err(Errno::NOSYS) => remount_read_only_top(target.as_fd()),
        Err(errno) => Err(errno),
    }
}

/// `MOUNT_ATTR_RDONLY`: with `mount_setattr`, mark the mount read-only.
const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
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

/// Marks the mount `target` names, and every mount beneath it, read-only
/// through `mount_setattr`.
///
/// Returns `Errno::NOSYS` on a kernel that predates `mount_setattr` (before
/// 5.12), which the caller handles by falling back to a top-level remount.
fn mount_setattr_recursive_read_only(target: BorrowedFd<'_>) -> Result<(), Errno> {
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: `target` is an O_PATH descriptor naming the freshly created bind
    // mount; with AT_EMPTY_PATH and an empty path the call operates on that
    // mount, and with AT_RECURSIVE on its submounts. The attr pointer and its
    // size describe a valid `struct mount_attr` for the duration of the call.
    unsafe {
        syscalls::syscall!(
            Sysno::mount_setattr,
            target.as_raw_fd(),
            c"".as_ptr(),
            AT_RECURSIVE | AT_EMPTY_PATH,
            &attr as *const MountAttr,
            size_of::<MountAttr>()
        )
    }
    .map(|_| ())
    .map_err(|err| Errno::from_raw_os_error(err.into_raw()))
}

/// Remounts only the bind mount `target` names read-only, the fallback for a
/// kernel without `mount_setattr`.
fn remount_read_only_top(target: BorrowedFd<'_>) -> Result<(), Errno> {
    let flags = remount_flags(fs::fstatvfs(target)?.f_flag);
    mount::mount_remount(fd_path(&target).as_cstr(), flags, c"")
}

/// Translates the flags `fstatvfs` observed on a mount into the flags its
/// read-only remount must carry.
///
/// A read-only remount in a user namespace must not clear the mount flags the
/// namespace holds locked (`nosuid`, `nodev`, ...), so the observed flags are
/// carried into the remount. Atime flags are left unspecified — the kernel
/// preserves the existing atime settings on a remount that names none —
/// because `fstatvfs` reports raw `ST_*` bits, and `ST_RELATIME` does not
/// share `MS_RELATIME`'s value; the flags copied here all have coinciding
/// `ST_*` and `MS_*` values.
///
/// Split out from its one caller because it is pure logic on a path no current
/// kernel takes: the fallback runs only below Linux 5.12, so the table is
/// testable where the remount around it is not.
fn remount_flags(observed: StatVfsMountFlags) -> MountFlags {
    let mut flags = MountFlags::BIND | MountFlags::RDONLY;
    for (statvfs_flag, mount_flag) in [
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
fn open_in_root_with(
    root: BorrowedFd<'_>,
    path: &CStr,
    oflags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno> {
    fs::openat2(root, path, oflags, mode, ResolveFlags::IN_ROOT)
}

/// The `/proc/self/fd/<fd>` path of a descriptor, formatted into a stack
/// buffer: the widest raw descriptor is ten decimal digits.
struct FdPath {
    buf: [u8; 25],
    len: usize,
}

/// Formats the `/proc/self/fd` path that names `fd`, so a descriptor
/// resolved with `RESOLVE_IN_ROOT` can anchor a mount syscall that only
/// accepts paths.
fn fd_path<Fd: AsFd>(fd: &Fd) -> FdPath {
    const PREFIX: &[u8] = b"/proc/self/fd/";
    let mut buf = [0u8; 25];
    buf[..PREFIX.len()].copy_from_slice(PREFIX);
    // Descriptors are non-negative, so the cast is lossless.
    let mut value = fd.as_fd().as_raw_fd() as u32;
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
    let mut len = PREFIX.len();
    while count > 0 {
        count -= 1;
        buf[len] = digits[count];
        len += 1;
    }
    FdPath { buf, len }
}

impl FdPath {
    fn as_cstr(&self) -> &CStr {
        // SAFETY: the buffer is zero-initialized and `len` never reaches the
        // final byte, so the slice holds exactly one NUL, at the end.
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.buf[..self.len + 1]) }
    }
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

/// Opens `path` and writes `data` in a single `write`.
///
/// The identity-map files under `/proc` accept the whole map in one write
/// and nothing else; a short write is reported as an I/O error, not retried.
pub(super) fn write_file(path: &CStr, data: &[u8]) -> Result<(), Errno> {
    let fd = rustix::fs::open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())?;
    match rustix::io::write(&fd, data) {
        Ok(n) if n == data.len() => Ok(()),
        Ok(_) => Err(Errno::IO),
        Err(errno) => Err(errno),
    }
}

/// Writes the 12-byte failure record: the step discriminant, the errno, and
/// the detail index, all little-endian. At 12 bytes the write is atomic
/// under `PIPE_BUF`. If it fails the caller is gone and there is no one to
/// report to.
fn report(fd: BorrowedFd<'_>, step: SetupStep, errno: Errno, detail: u32) {
    let step_bytes = (step as u32).to_le_bytes();
    let errno_bytes = errno.raw_os_error().to_le_bytes();
    let detail_bytes = detail.to_le_bytes();
    let mut record = [0u8; 12];
    record[0..4].copy_from_slice(&step_bytes);
    record[4..8].copy_from_slice(&errno_bytes);
    record[8..12].copy_from_slice(&detail_bytes);
    let _ = rustix::io::write(fd, &record);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_only_remount_carries_the_locked_flags_forward() {
        // Every remount is a read-only bind, and each locked flag the kernel
        // reported must come back with it: a user namespace refuses a remount
        // that would clear one.
        assert_eq!(
            remount_flags(StatVfsMountFlags::empty()),
            MountFlags::BIND | MountFlags::RDONLY,
        );
        for (observed, expected) in [
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
                remount_flags(observed),
                MountFlags::BIND | MountFlags::RDONLY | expected,
                "{observed:?}",
            );
        }
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
            remount_flags(atime),
            MountFlags::BIND | MountFlags::RDONLY,
            "an atime bit reached the remount flags",
        );
    }
}
