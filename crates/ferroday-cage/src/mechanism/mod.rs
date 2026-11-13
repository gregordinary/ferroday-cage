//! The sandbox launch mechanism: fork, the launch-stage pipes, and the
//! supervisor plumbing.
//!
//! This module is one of the crate's homes of `unsafe`. The unsafe
//! surface here is the process-creation and exec boundary — `fork`,
//! `unshare_unsafe`, `execve`, the signal-state calls, and the descriptor
//! sweep — each with its invariant documented at the call site, and
//! everything after the fork runs in a child process under the constraints
//! documented in [`child`].
//! Every syscall the stages make themselves is issued with inline assembly,
//! through rustix's `linux_raw` backend or, for the calls rustix keeps to its
//! runtime module and those it does not wrap, the `syscalls` crate: [`sys`]
//! holds the process-level ones. Neither touches the libc `errno` slot, the
//! allocator, or a lock, which is what keeps the post-fork window
//! async-signal-safe. rustix selects that backend by target and build
//! configuration, not by the mere fact of depending on rustix, so a
//! compile-time guard (below) fails the build on any configuration where rustix
//! would fall back to its libc backend instead.
//!
//! One libc call remains, and it is the standard library's rather than the
//! stages': dropping an [`OwnedFd`] closes it through libc's `close`, which a
//! debug build precedes with an `fcntl` checking that the descriptor is open.
//! Both are async-signal-safe wrappers of a single syscall. Neither allocates
//! or takes a lock, and the `errno` either may write belongs to the one thread
//! the copy holds.
//!
//! A launch forks a short-lived stage that creates the namespaces and forks
//! the sandbox's long-lived processes (see [`child`] for the full process
//! tree). Four channels connect the caller to them, all created here before
//! the fork, and all above the standard streams' numbers (see
//! [`above_stdio`]):
//!
//! - the **report pipe** carries the setup's account of itself as a stream of
//!   little-endian records, each opening with a 4-byte tag: one for each
//!   file-bind target the setup created, one saying a gated command is held at
//!   its gate, and, when a step fails, that step as the last record — step
//!   discriminant, errno, detail index. A successful `execve` closes the last
//!   write end, so end-of-file with no failure means the command is running.
//!   See [`read_report`].
//! - the **status pipe** carries the command's wait status as one 8-byte
//!   record — kind, value, little-endian — written by the supervisor when
//!   the command terminates.
//! - the **control socket** (a seqpacket pair) first delivers the
//!   supervisor's pidfd and host pid to the caller, then carries control
//!   requests toward the supervisor; its hangup is the caller-exit signal
//!   for [`stop_with_caller`].
//! - the supervisor's **pidfd** is the kill handle.
//!
//! A terminal launch adds a fifth, the **terminal channel** (a seqpacket pair):
//! the first process of the sandbox proper allocates the pseudoterminal from
//! the sandbox's own `/dev/ptmx` and sends its primary back over it, as one
//! message with the descriptor attached.
//!
//! [`stop_with_caller`]: crate::CageBuilder::stop_with_caller

#![allow(unsafe_code)]

// The post-fork stages are async-signal-safe only because rustix issues
// syscalls through its `linux_raw` backend (inline assembly; no libc `errno`
// slot, allocator, or locks). rustix falls back to its libc backend on targets
// it has no `linux_raw` support for, on the x32 and arm64-ILP32 ABIs (a 32-bit
// pointer on an otherwise-64-bit arch), under Miri, and when `rustix_use_libc`
// or `rustix_no_linux_raw` is set via `--cfg`. Any of those would silently
// invalidate the discipline documented in `child`, so fail the build instead.
// The default `linux_raw` architecture set is x86_64, x86, aarch64, arm, and
// riscv64; architectures rustix drives only through libc by default (powerpc,
// s390x, mips) are excluded here by omission. The one selector this cannot
// observe is rustix's own `use-libc` cargo feature, a deliberate opt-out that
// no default build enables. `sys` states the kernel's signal constants and
// structure layouts for exactly this set of architectures.
#[cfg(any(
    rustix_use_libc,
    rustix_no_linux_raw,
    miri,
    not(target_os = "linux"),
    not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
    )),
    all(target_arch = "x86_64", target_pointer_width = "32"),
    all(target_arch = "aarch64", target_pointer_width = "32"),
))]
compile_error!(
    "ferroday-cage requires rustix's linux_raw backend for post-fork \
     async-signal-safety, but this target or build configuration selects \
     rustix's libc backend. See the mechanism module documentation."
);

pub(crate) mod bounds;
mod cgroup;
mod child;
mod copyin;
#[cfg(feature = "tarball")]
mod export;
pub(crate) mod frame;
#[cfg(feature = "hardening")]
mod harden;
pub(crate) mod netns;
mod overlay;
mod procfs;
mod remove;
pub(crate) mod resolve;
pub(crate) mod seccomp;
pub(crate) mod sys;

#[cfg(feature = "hardening")]
pub(crate) use harden::probe_landlock_abi;

pub(crate) use cgroup::{JoinProbe, probe_cgroup_join};
pub(crate) use child::CONTROL_TERMINATE;
pub(crate) use copyin::{
    COPY_DIR, COPY_END, COPY_FIFO, COPY_FILE, COPY_LEAVE, COPY_LINK, COPY_OWN, COPY_SYMLINK,
    CopyFailure, start_copy_in,
};
#[cfg(feature = "tarball")]
pub(crate) use export::{
    ExportStep, FRAME_DIR, FRAME_END, FRAME_ERROR, FRAME_FILE, FRAME_LEAVE, FRAME_SYMLINK,
    StartError, kill_export, start_export,
};
pub(crate) use overlay::{
    OverlayOptionsError, OverlayProbe, overlay_options, probe_overlay_mount, xattr_unsupported,
};
pub(crate) use procfs::{ProcfsProbe, probe_procfs_mount};
pub(crate) use remove::{RemoveFailure, delete_tree, remove_tree_mapped};

use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags};
use rustix::fs::RawMode;
use rustix::io::Errno;
use rustix::mount::{MountFlags, MountPropagationFlags};
use rustix::net::{AddressFamily, SendFlags, SocketFlags, SocketType};
use rustix::pipe::{self, PipeFlags};
use rustix::process::Signal;
use rustix::process::{self, Pid, WaitId, WaitIdOptions};
use rustix::thread::UnshareFlags;

use crate::Network;
use crate::error::{Error, SetupStep};
use crate::host;
use crate::idmap::{IdMapper, ResolvedMap};
use crate::observer::Progress;
use crate::status::{ExitStatus, ResourceUsage};
use crate::terminal::Terminal;
use sys::PidfdFork;

/// What the launch stages build around the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Confinement {
    /// The container: namespaces, identity maps, the mount profile, and the
    /// pivot into the rootfs.
    Container,
    /// The restriction fallback: a plain child process on the host, confined
    /// by the hardening plan alone. No namespaces are created, and the
    /// namespace and mount fields of the plan are empty and unused.
    #[cfg(feature = "hardening")]
    Restriction,
}

/// How the launch establishes the sandbox's identity map.
///
/// The tier is a property of the plan, decided at build time: the map files
/// are write-once, so whichever party applies the map must apply all of it,
/// once.
#[derive(Debug, Clone)]
pub(crate) enum IdentityPlan {
    /// The single-identity map, written by stage A in process under the
    /// kernel's unprivileged one-id exception. No gate.
    Single,
    /// A range map, written from outside the new namespace by the resolved
    /// delegate while stage A blocks at the map gate.
    Ranged {
        /// The delegate that applies the map.
        mapper: Arc<dyn IdMapper>,
        /// The extents, resolved at build time.
        map: ResolvedMap,
    },
}

impl IdentityPlan {
    /// Whether this plan's map is written by a delegate through the map
    /// gate.
    pub(crate) fn is_ranged(&self) -> bool {
        matches!(self, IdentityPlan::Ranged { .. })
    }
}

/// How the command's nested user namespace gets its identity map, and the
/// procfs paths that way of getting it names.
///
/// The tier mirrors the sandbox's own: the single-identity map is one extent of
/// one id and the command writes it in process, and a range map is written from
/// outside the nested namespace by a delegate — here a delegate inside the
/// sandbox, because the party that writes it must be root of the namespace the
/// nested one is a child of.
///
/// Each variant carries the paths its own route needs and no others, so a
/// configuration that names none — a delegated map whose delegate is outside
/// the sandbox — records that rather than a path nothing opens.
#[derive(Debug, Clone)]
pub(crate) enum NestedMap {
    /// The command writes its own map, under the kernel's unprivileged one-id
    /// exception: `setgroups` is denied first, which is what permits the write.
    ///
    /// The files are reached by path, after the pivot, so they are named
    /// through the procfs the mount profile establishes.
    SelfWritten {
        /// `/proc/self/setgroups` as it is named inside the sandbox.
        setgroups_path: CString,
        /// `/proc/self/gid_map` as it is named inside the sandbox.
        gid_map_path: CString,
        /// `/proc/self/uid_map` as it is named inside the sandbox.
        uid_map_path: CString,
    },
    /// A delegate — the process that forked the command — writes the map while
    /// the command blocks at a gate. `setgroups` stays at `allow`, so the
    /// supplementary groups a run-as identity names still work.
    Delegated {
        /// The procfs mount target, rootfs-relative, that a delegate inside the
        /// sandbox opens during setup and writes the command's map files
        /// through.
        ///
        /// `None` where the sandbox has no PID namespace: the delegate is then
        /// the launch stage, which is outside and opens the host's `/proc`
        /// before the pivot, so the profile's own procfs is never consulted and
        /// a profile that mounts none still works.
        procfs_target: Option<CString>,
    },
}

/// The nested user namespace the command enters before the hardening layer,
/// composed and frozen at build time.
///
/// A read-only bind is established by the sandbox setup inside the user
/// namespace that setup created, and the kernel locks a mount's flags only when
/// it copies the mount tree *into* a new user namespace. Root of the namespace
/// that owns a mount may therefore remount it read-write — so the command, root
/// of its own namespace, could clear the very flag the bind was for. Entering a
/// nested user namespace has the kernel do the copy, and with it the locking:
/// past the entry no mount the command inherited can have a restriction lifted.
///
/// The map is the identity reflection of the sandbox's own (see
/// [`reflect_inside`](crate::idmap::reflect_inside)), so the command's view of
/// itself is unchanged one namespace deeper.
///
/// Present for every container; `None` for the restriction fallback, which
/// creates no user namespace to nest inside.
#[derive(Debug, Clone)]
pub(crate) struct NestedPlan {
    /// Who writes the map, and the procfs paths that route names.
    pub(crate) map: NestedMap,
    /// The `uid_map` content, formatted at build time.
    pub(crate) uid_lines: Vec<u8>,
    /// The `gid_map` content, formatted at build time.
    pub(crate) gid_lines: Vec<u8>,
}

/// The root a launch pivots into, as the build froze it.
#[derive(Debug, Clone)]
pub(crate) enum RootPlan {
    /// No root swap: a restriction's command runs against the host's own
    /// filesystem, and the sandbox stage that would use a root never runs.
    ///
    /// Only a restriction builds it, and restrictions come with the
    /// `hardening` feature; the readers of a plan match it in every build.
    #[cfg_attr(not(feature = "hardening"), expect(dead_code))]
    Host,
    /// The canonical rootfs, bound onto itself.
    ///
    /// The sandbox stage opens the path anew inside its own mount namespace,
    /// without following a link: a descriptor opened before `unshare` still
    /// references the original namespace's mounts, and a mount refuses sources
    /// and targets that are not attached in the caller's namespace.
    Bind(CString),
    /// An overlay mounted over the canonical rootfs, which is its read-only
    /// base lower, so writes land in a disposable upper. The path is opened
    /// anew as [`Bind`](Self::Bind)'s is.
    Overlay {
        /// The canonical rootfs the overlay is mounted over.
        base: CString,
        /// The overlay's frozen mount options and layers.
        overlay: OverlayPlan,
    },
    /// A tmpfs of the sandbox's own, holding only what the mount profile
    /// creates in it and made read-only once the profile is in place.
    Empty,
    /// The host's own mount tree, cloned inside the sandbox's mount namespace
    /// and read-only throughout. The launch creates nothing in it.
    HostReadOnly,
}

/// How an overlay-rooted cage's root is assembled.
///
/// The base is the read-only lower and the path the overlay is mounted over
/// both, so this carries only the preformatted mount options naming the lower,
/// the disposable upper, and its work directory.
#[derive(Debug, Clone)]
pub(crate) struct OverlayPlan {
    /// The overlay mount options, composed at build time by
    /// [`overlay_options`]: `lowerdir=<lowers>,upperdir=<upper>,workdir=<work>,userxattr`.
    pub(crate) options: CString,
    /// The resolved lower layers, first (the base the overlay mounts over)
    /// first. Kept beside the formatted options so `resolved_inputs` can report
    /// the stack as a structure rather than leave a caller to parse it back out
    /// of the option string.
    pub(crate) lower: Vec<PathBuf>,
    /// The resolved upper layer, where the sandbox's writes land.
    pub(crate) upper: PathBuf,
    /// The resolved work directory the overlay requires beside the upper.
    pub(crate) work: PathBuf,
}

/// How the command stage wires one standard stream, frozen at build time.
///
/// The descriptor form holds the caller's descriptor for the plan's lifetime,
/// shared so a clonable plan can launch repeatedly against it.
#[derive(Debug, Clone, Default)]
pub(crate) enum StdioPlan {
    /// Leave the stream's descriptor as the launch inherited it.
    #[default]
    Inherit,
    /// Redirect the stream to `/dev/null`.
    Null,
    /// Redirect the stream to a caller-supplied descriptor.
    Fd(Arc<OwnedFd>),
}

impl StdioPlan {
    /// Lowers a public disposition into the plan's own form.
    pub(crate) fn of(stdio: &crate::Stdio) -> StdioPlan {
        match stdio {
            crate::Stdio::Inherit => StdioPlan::Inherit,
            crate::Stdio::Null => StdioPlan::Null,
            crate::Stdio::Fd(fd) => StdioPlan::Fd(Arc::clone(fd)),
        }
    }

    /// The caller's descriptor, for the one variant that names one.
    ///
    /// The launch keeps these through the descriptor sweep and wires them onto
    /// the command's standard streams; every other variant names no descriptor
    /// of the caller's.
    pub(crate) fn caller_fd(&self) -> Option<BorrowedFd<'_>> {
        match self {
            StdioPlan::Fd(fd) => Some(fd.as_fd()),
            StdioPlan::Inherit | StdioPlan::Null => None,
        }
    }

    /// Whether this disposition names a destination of its own, which a
    /// launch-time attachment — capture pipes — would contradict.
    ///
    /// [`Inherit`](Self::Inherit) states no destination, so it is not a
    /// contradiction: the launch is free to supply one.
    pub(crate) fn names_a_destination(&self) -> bool {
        !matches!(self, StdioPlan::Inherit)
    }
}

/// Refuses a launch that would hand the command a directory as a standard
/// stream.
///
/// A directory descriptor is a path as well as a stream: `/proc/self/fd/N` and
/// `openat(N, "..")` walk from it through the host's filesystem, past any root
/// the sandbox swapped in, and nothing in the default posture stands in the
/// way. No program reads its input from a directory or writes its output to
/// one, so the refusal takes nothing a command could use.
///
/// Checked at the launch rather than at build, because
/// [`Inherit`](StdioPlan::Inherit) hands over whatever the caller's own
/// descriptor names at the moment of the fork. A stream the launch replaces is
/// not examined: a terminal launch replaces all three, and capture replaces the
/// output pair.
fn refuse_directory_streams(plan: &LaunchPlan, observe: bool, terminal: bool) -> Result<(), Error> {
    if terminal {
        return Ok(());
    }
    refuse_directory("standard input", &plan.stdin, rustix::stdio::stdin())?;
    if !observe {
        refuse_directory("standard output", &plan.stdout, rustix::stdio::stdout())?;
        refuse_directory("standard error", &plan.stderr, rustix::stdio::stderr())?;
    }
    Ok(())
}

/// One stream's half of [`refuse_directory_streams`]. `own` is the caller's
/// descriptor at the stream's number, which [`Inherit`](StdioPlan::Inherit)
/// hands over.
///
/// A closed descriptor hands the command nothing, so it passes.
fn refuse_directory(
    stream: &'static str,
    disposition: &StdioPlan,
    own: BorrowedFd<'_>,
) -> Result<(), Error> {
    let handed = match disposition {
        StdioPlan::Null => return Ok(()),
        StdioPlan::Inherit => own,
        StdioPlan::Fd(fd) => fd.as_fd(),
    };
    match rustix::fs::fstat(handed) {
        Ok(stat)
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                == rustix::fs::FileType::Directory =>
        {
            Err(Error::StreamIsDirectory { stream })
        }
        Ok(_) | Err(Errno::BADF) => Ok(()),
        Err(errno) => Err(spawn_error(errno)),
    }
}

/// One frozen resource limit, in the kernel's own terms.
///
/// Validated and translated at build time, so the command stage only replays
/// a `prlimit64` per entry.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RlimitPlan {
    /// The resource as the caller named it.
    ///
    /// Carried beside the kernel's own, rather than recovered from it, so that
    /// [`ResolvedInputs`](crate::ResolvedInputs) reports the resource a
    /// provenance record is asked about instead of searching for one that
    /// translates to the same kernel number. It joins `op_labels`, `exec_label`
    /// and `rlimit_labels` as caller-side data the sandbox stages never read.
    pub(crate) resource: crate::Resource,
    /// The kernel resource the limit is applied against.
    pub(crate) kernel: rustix::process::Resource,
    /// The soft and hard values, with `None` meaning `RLIM_INFINITY`.
    pub(crate) limit: rustix::process::Rlimit,
}

/// The frozen non-root identity the command switches to before `execve`.
///
/// The ids are sandbox-inside ids, validated against the identity map at
/// build time, so the switch itself replays frozen values.
#[derive(Debug, Clone)]
pub(crate) struct RunAsPlan {
    /// The uid the command runs as.
    pub(crate) uid: rustix::thread::Uid,
    /// The gid the command runs as.
    pub(crate) gid: rustix::thread::Gid,
    /// The supplementary groups, set verbatim — an empty list clears the
    /// caller's inherited groups — or `None` where the gid map cannot carry a
    /// list and the inherited one stands.
    pub(crate) groups: Option<Vec<rustix::thread::Gid>>,
}

/// The identity the single-identity map presents the caller to the command as,
/// resolved at build time.
///
/// The presentation itself is the nested map's inside ids, which
/// [`NestedPlan`] already carries as formatted lines. This is what the rest of
/// the launch asks about it: whether to set no-new-privileges, and what a
/// resolved-inputs record reports.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PresentPlan {
    /// The uid the command sees the caller as.
    pub(crate) uid: u32,
    /// The gid the command sees the caller as.
    pub(crate) gid: u32,
}

/// The mount targets a launch has to create as empty files in the root, and the
/// writable layer they are created in.
///
/// A file bind needs its target to exist before anything can be mounted onto it,
/// so a root shipping none gets an empty file created. Left behind, that file is
/// content the root did not have — a resolver configuration, an empty binary —
/// which an export carries into whatever is made of the tree. The caller side
/// removes each one once the sandbox is gone instead: the sandbox owns what it
/// creates.
///
/// Only the targets the caller side can name are listed: one under an earlier
/// mount is created inside that mount rather than in the root, and one the root
/// already ships — an entry of any kind at the path — is not the launch's to
/// remove. The list is what a launch *may* create. Which of them it did is what
/// the setup reports as it creates each one, as a [`CreatedTarget`]: a target
/// another launch created first, on a root two sandboxes share, is found rather
/// than created, and is not this launch's.
///
/// The paths are held root-relative, with the root named once, so the removal
/// can resolve them the way the sandbox stage resolves its mount targets:
/// against a descriptor for the root, with `RESOLVE_IN_ROOT`. Joined into
/// absolute host paths instead, a rootfs-internal symbolic link — which an
/// untrusted unpacked tree is entitled to contain — would resolve against the
/// *host's* root on this side of the fork, and the removal could land outside
/// the rootfs entirely.
///
/// Caller-side only, and never touched by the sandbox stages: inside the sandbox
/// each path is under its bind, where unlinking it is `EBUSY`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ManagedPlaceholders {
    /// The root's writable layer — the rootfs itself, or an overlay's upper —
    /// which is where the launch creates the targets below. Canonical, so a root
    /// the caller named relatively does not re-resolve against whatever
    /// directory the process happens to be in when the handle drops. Empty when
    /// there are no placeholders.
    pub(crate) root: PathBuf,
    /// The targets, as paths relative to [`root`](Self::root).
    pub(crate) paths: Vec<PathBuf>,
    /// The targets among [`paths`](Self::paths) an overlay's upper held a
    /// whiteout at before the launch, which the removal puts back.
    ///
    /// Creating the target over a whiteout replaces the whiteout, so removing
    /// the target alone would bring back the entry a lower layer holds there,
    /// which the upper had deleted.
    pub(crate) whiteouts: Vec<PathBuf>,
}

impl ManagedPlaceholders {
    /// Whether the launch creates no mount target the caller side has to remove.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

/// The frozen launch plan: everything the sandbox stages need, marshaled by
/// [`CageBuilder::build`] so that the post-fork windows perform no fallible
/// or allocating preparation of their own.
///
/// [`CageBuilder::build`]: crate::CageBuilder::build
#[derive(Debug, Clone)]
pub(crate) struct LaunchPlan {
    /// What the stages build around the command: the full container, or the
    /// restriction fallback's plain confined process.
    pub(crate) confinement: Confinement,
    /// How the sandbox's identity map is established; unused in a
    /// restriction, which creates no user namespace.
    pub(crate) identity: IdentityPlan,
    /// The nested user namespace the command enters before the hardening
    /// layer, which is what locks the flags of every mount it inherited.
    /// `None` in a restriction, which creates no namespace to nest inside.
    pub(crate) nested: Option<NestedPlan>,
    /// The identity the command switches to before `execve`; `None` leaves
    /// it running as root inside, or as its presented identity. Always `None`
    /// in a restriction.
    pub(crate) run_as: Option<RunAsPlan>,
    /// The identity the single-identity map presents the caller to the
    /// command as, when one is configured. Always `None` under a range map and
    /// in a restriction.
    pub(crate) present_as: Option<PresentPlan>,
    /// The command path, executed after the root swap in a container and
    /// against the host filesystem in a restriction. When
    /// [`program_search`](Self::program_search) is non-empty this is the bare
    /// command name, used as `argv[0]`, and the search list holds the paths to
    /// try.
    pub(crate) program: CString,
    /// Candidate absolute paths to `execve` in order, resolved from the
    /// sandbox's `PATH` when the caller opts into path lookup for a command
    /// with no slash. Empty for the ordinary case, where
    /// [`program`](Self::program) is executed directly.
    pub(crate) program_search: Vec<CString>,
    /// The command's arguments, excluding the conventional `argv[0]`.
    pub(crate) args: Vec<CString>,
    /// The command's complete environment, as frozen `NAME=value` entries.
    pub(crate) env: Vec<CString>,
    /// The root the sandbox stage pivots into, validated at build time.
    pub(crate) root: RootPlan,
    /// The namespaces the launch stage unshares into.
    pub(crate) unshare: UnshareFlags,
    /// Whether the sandbox gets its own PID namespace, and with it the
    /// library init and namespace-wide teardown.
    pub(crate) pid_namespace: bool,
    /// How the command's standard input is wired.
    pub(crate) stdin: StdioPlan,
    /// How the command's standard output is wired, when the launch captures
    /// nothing. A capturing launch supplies its own pipe, and a plan that names
    /// a destination of its own is refused against one.
    pub(crate) stdout: StdioPlan,
    /// How the command's standard error is wired, on the same terms as
    /// [`stdout`](Self::stdout).
    pub(crate) stderr: StdioPlan,
    /// Whether the launch stage starts a new session, so the sandbox has no
    /// controlling terminal.
    ///
    /// Derived from [`stdin`](Self::stdin) alone: it is the stream whose
    /// inheritance carries the caller's session with it. A command that
    /// inherits the caller's standard input has been handed the caller's
    /// terminal along with it and stays in the caller's session; one that does
    /// not inherit it gets a session of its own, in which `/dev/tty` names
    /// nothing and `TIOCSTI` is refused. That closes what is reached through
    /// the session; the output pair is closed by its own disposition. See
    /// [`Stdio`](crate::Stdio).
    pub(crate) own_session: bool,
    /// Whether the supervisor stops the sandbox when the control socket
    /// hangs up — the caller exited or dropped the last handle.
    pub(crate) stop_with_caller: bool,
    /// The hostname to set inside the UTS namespace, when configured.
    pub(crate) hostname: Option<CString>,
    /// Whether to bring up loopback in the isolated network namespace.
    pub(crate) configure_loopback: bool,
    /// The network posture the sandbox was built with.
    ///
    /// Carried rather than reconstructed from [`unshare`](Self::unshare) and
    /// [`configure_loopback`](Self::configure_loopback), which encode it
    /// between them: `resolved_inputs` reports it, and a record derived from
    /// two flags would go quietly wrong the first time a third posture did not
    /// map onto them. A restriction creates no network namespace, so it carries
    /// [`Network::Host`](crate::Network::Host) — the caller's, which is what it
    /// runs in.
    pub(crate) network: crate::Network,
    /// The working directory inside the sandbox; `None` means `/`.
    pub(crate) workdir: Option<CString>,
    /// The mount profile, lowered into frozen ops the sandbox stage executes
    /// in order between binding the rootfs and pivoting into it.
    pub(crate) ops: Vec<MountOp>,
    /// Caller-side labels parallel to `ops`, naming each mount in a setup
    /// error. Never touched by the sandbox stages.
    pub(crate) op_labels: Vec<String>,
    /// The mount targets the launch has to create as empty files, removed once
    /// the sandbox that needed them is gone.
    pub(crate) managed_placeholders: ManagedPlaceholders,
    /// The caller-side label naming the command in a failed exec step: the
    /// program path, or the bare name and the candidates a path lookup tried.
    /// Never touched by the sandbox stages.
    pub(crate) exec_label: String,
    /// The resource limits applied to the command process before the
    /// hardening layer, in a deterministic order.
    pub(crate) rlimits: Vec<RlimitPlan>,
    /// Caller-side labels parallel to `rlimits`, naming each limit in a setup
    /// error. Never touched by the sandbox stages.
    pub(crate) rlimit_labels: Vec<String>,
    /// The cgroup each launch creates for the sandbox, where one is asked for.
    /// The caller creates it before the fork; the launch stage only joins it,
    /// through a descriptor the context carries.
    pub(crate) cgroup: Option<crate::cgroup::CgroupPlan>,
    /// The cgroup limits a launch runs without: set, not required, and with no
    /// parent named. Caller-side, for the resolved inputs to report.
    pub(crate) cgroup_unapplied: Vec<crate::cgroup::CgroupLimit>,
    /// The frozen hardening plan applied in the command stage before exec.
    /// Present only with the `hardening` feature.
    #[cfg(feature = "hardening")]
    pub(crate) hardening: HardeningPlan,
}

impl LaunchPlan {
    /// Whether a launch of this plan gives the sandbox a process group of its
    /// own in the caller's session: a launch that keeps the caller's session,
    /// with a PID namespace. `terminal` is whether the launch is a terminal
    /// launch, which is a property of the launch rather than of the plan.
    ///
    /// A launch that does not keep the caller's session gets a session of its
    /// own, which is a process group of its own already: any standard input
    /// but [`Inherit`](StdioPlan::Inherit), and every terminal launch. Without a
    /// PID namespace the command shares the caller's PID space and can name
    /// the caller's processes directly, so a group of its own would bound
    /// nothing there; the hardening layer's `LandlockScope::Signal` is that
    /// reach's bound.
    pub(crate) fn own_process_group(&self, terminal: bool) -> bool {
        self.pid_namespace && !self.own_session && !terminal
    }
}

/// The caller's terminal, lent to the sandbox's process group for as long as
/// the sandbox runs.
///
/// A sandbox that keeps the caller's session under a PID namespace runs in a
/// process group of its own (see
/// [`LaunchPlan::own_process_group`]). An interactive run, whose standard input
/// and standard output are both the caller's controlling terminal while the
/// caller's own process group holds that terminal's foreground, has the caller
/// lend the foreground to the sandbox: the init takes it for the sandbox's
/// group before the command exists. A `^C` typed at the terminal then reaches
/// the command, as it reached the caller's job before, and the caller's group
/// stays out of reach of what the command sends to its own. The caller's group
/// is a background job of the terminal meanwhile, so a process in it that
/// reads the terminal stops until its shell resumes it. [`lend`](Self::lend)
/// says why output that goes anywhere else lends nothing.
///
/// This is the caller's half: the decision, made at the launch rather than at
/// build because it is a property of the caller's process at that moment, and
/// the return of the foreground once the sandbox is gone. The terminal is held
/// as a duplicate of the caller's descriptor 0 taken at the launch, so what the
/// caller does with its own descriptor 0 afterwards changes nothing here.
///
/// [`hand_back`](Self::hand_back) returns the foreground, at most once, and
/// dropping a `Foreground` hands it back too. A handle hands it back once a
/// wait has observed the sandbox's outcome, and a launch that fails hands it
/// back once its processes have ended. A handle dropped while the sandbox runs
/// hands it back then: the terminal is the caller's, and a caller that kept
/// running in the background of its own terminal would be stopped by the
/// kernel at its first read of it. The sandbox runs on in the background from
/// then, where a read of the terminal fails or stops the reader, and a `^C` no
/// longer reaches it.
pub(crate) struct Foreground {
    /// The caller's terminal, until the foreground is handed back.
    terminal: Option<OwnedFd>,
    /// The caller's process group, which held the foreground at the launch.
    caller: Pid,
    /// The sandbox's process group: the init's host pid, once the launch has
    /// published it.
    sandbox: Option<Pid>,
}

impl Foreground {
    /// Decides whether a launch of `plan` lends the caller's terminal, and
    /// takes the terminal if it does. `observe` is whether the launch captures
    /// the output pair, and `terminal` whether it is a terminal launch.
    ///
    /// The caller lends it to an interactive run alone: the sandbox takes a
    /// process group of its own, its standard input and standard output are
    /// both inherited and both the caller's controlling terminal, and the
    /// caller's own process group is that terminal's foreground group.
    ///
    /// Output that goes anywhere else, piped, redirected, or captured, means
    /// the caller's job is more than the sandbox: a pipeline reads what the
    /// command writes, and a member of it may read the terminal, as a pager
    /// does. The caller's job keeps the terminal then, and so does a caller in
    /// the background of its terminal or whose standard input is no terminal.
    /// The sandbox's group is a background group of whatever terminal it has,
    /// orphaned once the launch stage exits, so its reads of the terminal fail,
    /// and a `^C` typed at the terminal reaches the caller's job.
    fn lend(plan: &LaunchPlan, observe: bool, terminal: bool) -> Result<Option<Foreground>, Error> {
        if !plan.own_process_group(terminal)
            || observe
            || !matches!(plan.stdout, StdioPlan::Inherit)
        {
            return Ok(None);
        }
        let stdin = rustix::stdio::stdin();
        let caller = process::getpgrp();
        // A terminal that is not this process's controlling terminal answers
        // `ENOTTY`, and one whose foreground group is outside this process's
        // PID namespace answers zero, which rustix reports as an error too.
        match rustix::termios::tcgetpgrp(stdin) {
            Ok(holder) if holder == caller => {}
            _ => return Ok(None),
        }
        if !same_terminal(stdin, rustix::stdio::stdout()) {
            return Ok(None);
        }
        // Close-on-exec, and above the standard streams' numbers.
        let terminal = stdin
            .try_clone_to_owned()
            .map_err(|source| Error::Spawn { source })?;
        Ok(Some(Foreground {
            terminal: Some(terminal),
            caller,
            sandbox: None,
        }))
    }

    /// Records the sandbox's process group, the init's host pid, once the
    /// launch has published the init.
    fn lent_to(&mut self, init: u32) {
        self.sandbox = i32::try_from(init).ok().and_then(Pid::from_raw);
    }

    /// Gives the terminal's foreground back to the caller's process group, the
    /// first time it is called.
    ///
    /// It takes the foreground back only from the sandbox: when the terminal's
    /// foreground group is the sandbox's own, or a group with no process left
    /// in it, which is where a shell inside the sandbox can leave it once the
    /// sandbox is gone. Any other group holding it has been given it since, by
    /// the caller's shell after a stop of the caller for instance, and keeps
    /// it.
    ///
    /// The caller's group is in the background of its terminal until the call
    /// returns, and the kernel stops a background group that takes the
    /// foreground, with `SIGTTOU`, unless the calling thread blocks or ignores
    /// it. The signal is blocked in the calling thread for the call alone.
    /// Best-effort: a terminal the session no longer controls refuses the call,
    /// and there is nothing to give back.
    pub(crate) fn hand_back(&mut self) {
        let Some(terminal) = self.terminal.take() else {
            return;
        };
        let Ok(holder) = rustix::termios::tcgetpgrp(&terminal) else {
            return;
        };
        if holder == self.caller {
            return;
        }
        let lent = Some(holder) == self.sandbox
            || process::test_kill_process_group(holder) == Err(Errno::SRCH);
        if lent {
            let _ = sys::with_blocked(&sys::SigSet::of(&[Signal::TTOU]), || {
                rustix::termios::tcsetpgrp(&terminal, self.caller)
            });
        }
    }
}

impl Drop for Foreground {
    fn drop(&mut self) {
        self.hand_back();
    }
}

/// Whether `output` is the same terminal as `input`: two character devices of
/// one device number.
///
/// Asked of standard output once standard input is known to be the caller's
/// controlling terminal, so a yes means output goes to that terminal too. The
/// device is compared, rather than `tcgetpgrp` asked of the output as it is of
/// the input. A pseudoterminal's primary answers `tcgetpgrp` with its
/// replica's foreground group, controlling terminal or not, so a caller
/// writing into the primary of a terminal whose foreground group happened to be
/// its own would pass that test while its output reaches nobody's terminal.
/// The device numbers of a primary and its replica differ.
fn same_terminal(input: BorrowedFd<'_>, output: BorrowedFd<'_>) -> bool {
    let device = |fd| {
        rustix::fs::fstat(fd).ok().and_then(|stat| {
            (rustix::fs::FileType::from_raw_mode(stat.st_mode)
                == rustix::fs::FileType::CharacterDevice)
                .then_some(stat.st_rdev)
        })
    };
    matches!((device(input), device(output)), (Some(input), Some(output)) if input == output)
}

/// A single BPF instruction, the unit of a compiled seccomp program.
///
/// Layout-compatible with the kernel's `struct sock_filter`.
#[cfg_attr(
    feature = "hardening",
    doc = "A caller building a program with an external compiler passes a \
           `Vec<SockFilter>` through \
           [`SeccompPolicy::Program`](crate::SeccompPolicy::Program)."
)]
// Every build carries the type, since every sandbox with a network namespace
// of its own installs `seccomp::NETWORK_FILTER`. Only the `hardening` feature
// exports it, and only there does a caller have a program to hand the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SockFilter {
    /// The instruction opcode.
    pub code: u16,
    /// Jump offset when the test is true.
    pub jt: u8,
    /// Jump offset when the test is false.
    pub jf: u8,
    /// The generic argument.
    pub k: u32,
}

// The kernel reads a program as an array of these, so a layout that drifts
// from `struct sock_filter` must fail the build rather than misissue every
// instruction of every filter.
const _: () = assert!(size_of::<SockFilter>() == 8);

/// One frozen Landlock grant: an absolute sandbox path and the kernel
/// `LANDLOCK_ACCESS_FS_*` bitmask allowed beneath it. The command stage masks
/// the access to the running kernel's ABI and opens the path after the pivot,
/// through symbolic links only where
/// [`HardeningPlan::grants_follow_links`] says so.
#[cfg(feature = "hardening")]
#[derive(Debug, Clone)]
pub(crate) struct LandlockRule {
    /// The grant's target, an absolute path resolved inside the pivoted root.
    pub(crate) path: CString,
    /// The unmasked `LANDLOCK_ACCESS_FS_*` rights allowed beneath the path.
    pub(crate) access: u64,
}

/// One frozen Landlock network grant: a TCP port and the kernel
/// `LANDLOCK_ACCESS_NET_*` bitmask allowed on it. The command stage masks the
/// access to the running kernel's ABI. The port is host-order and fits a
/// `u16`, so the kernel's rejection of ports above 65535 cannot arise.
#[cfg(feature = "hardening")]
#[derive(Debug, Clone)]
pub(crate) struct LandlockNetRule {
    /// The TCP port the grant governs.
    pub(crate) port: u16,
    /// The unmasked `LANDLOCK_ACCESS_NET_*` rights allowed on the port.
    pub(crate) access: u64,
}

/// The frozen hardening plan: Landlock rules, a compiled seccomp program, and
/// the capability set to retain, all applied in the command stage between the
/// stdio wiring and `execve`. Every field is empty in a sandbox that requests
/// no hardening.
#[cfg(feature = "hardening")]
#[derive(Debug, Default, Clone)]
pub(crate) struct HardeningPlan {
    /// Landlock filesystem grants; an empty list means the ruleset governs no
    /// filesystem access.
    pub(crate) landlock: Vec<LandlockRule>,
    /// The `handled_access_fs` mask the ruleset governs, masked to the kernel
    /// ABI in the child: the ABI 5 set where a grant names a file right, and
    /// `RESOLVE_UNIX` where the unix-socket restriction applies. Zero when
    /// neither does. A ruleset is built when it is non-zero, grants or none,
    /// since the unix-socket restriction needs a domain as a scope does.
    pub(crate) landlock_handled: u64,
    /// Landlock network grants; an empty list means the ruleset governs no
    /// network access. A ruleset is built when either grant list is non-empty.
    pub(crate) landlock_net: Vec<LandlockNetRule>,
    /// The `handled_access_net` mask the ruleset governs — the full modeled
    /// set, masked to the kernel ABI in the child. Zero when no network grant
    /// applies.
    pub(crate) landlock_net_handled: u64,
    /// The `LANDLOCK_SCOPE_*` flags the ruleset scopes, masked to the kernel
    /// ABI in the child. Zero when no scope applies. A ruleset is built when it
    /// is non-zero even with no grant at all, since a scope needs a domain to
    /// confine its reach to. A scope the mask would drop where nothing else
    /// bounds its reach was refused at build, so the mask only ever narrows a
    /// scope a namespace stands behind.
    pub(crate) landlock_scoped: u64,
    /// Caller-side labels naming each Landlock rule in a setup error:
    /// [`landlock`](Self::landlock)'s grants first, then
    /// [`landlock_net`](Self::landlock_net)'s, in the order the command stage
    /// adds them. Never touched by the sandbox stages.
    pub(crate) landlock_labels: Vec<String>,
    /// Whether a filesystem grant's path is resolved through symbolic links.
    ///
    /// False for a sandbox, whose root may hold links a package or an earlier
    /// run planted: a link on the way to a grant's target would carry the grant
    /// to wherever it points, so a path crossing one fails the rule instead.
    /// True for a restriction, whose paths are the caller's host paths, where
    /// a link such as a merged-`/usr` host's `/lib` is how the host is laid out.
    pub(crate) grants_follow_links: bool,
    /// The compiled seccomp program, installed verbatim when present.
    pub(crate) seccomp: Option<Vec<SockFilter>>,
    /// The capability bits to retain across the drop; `None` leaves the
    /// namespaced capability set untouched.
    pub(crate) keep_caps: Option<u64>,
    /// Whether to lock `SECBIT_NO_SETUID_FIXUP` before the identity switch,
    /// so a kept capability set survives it. Set only when a non-root
    /// run-as identity is combined with a capability keep set.
    pub(crate) set_securebits: bool,
}

#[cfg(feature = "hardening")]
impl HardeningPlan {
    /// Whether the command stage has any hardening to apply.
    ///
    /// `set_securebits` is included for completeness even though it never holds
    /// alone: it is set only alongside a capability keep set, so `keep_caps`
    /// already forces a non-empty plan. Checking it keeps the invariant
    /// enforced by the code rather than by that coupling.
    pub(crate) fn is_empty(&self) -> bool {
        self.landlock.is_empty()
            && self.landlock_net.is_empty()
            && self.landlock_scoped == 0
            && self.landlock_handled == 0
            && self.seccomp.is_none()
            && self.keep_caps.is_none()
            && !self.set_securebits
    }

    /// Checks that the plan's Landlock grants can be enforced on a kernel at
    /// `abi`, the probed Landlock ABI, or `None` where the LSM is absent.
    ///
    /// For the restriction fallback, whose only filesystem and network boundary
    /// is Landlock: when the plan requests a grant but this host's Landlock ABI
    /// (or the absence of the LSM) leaves that grant governing nothing — every
    /// right of it masked away, as a network grant is on a kernel below ABI 4 —
    /// the command would run unconfined for that access kind. Refuse at build
    /// time rather than silently drop the confinement.
    ///
    /// The check is per access kind: a filesystem grant that survives the ABI
    /// must not paper over a network grant the same ABI masks away, or a
    /// restriction configured to "apply these filesystem grants and connect only
    /// to port 443" would enforce the filesystem side while leaving the network
    /// unrestricted. A plan with no Landlock grant passes; a cage does not call
    /// this — for its filesystem grants and for an isolated-network cage the
    /// namespace isolation remains the boundary — but see
    /// [`ensure_sandbox_enforceable`](Self::ensure_sandbox_enforceable) for
    /// what a cage must check.
    pub(crate) fn ensure_landlock_enforceable(
        &self,
        abi: Option<i32>,
    ) -> Result<(), crate::error::ConfigError> {
        if self.landlock.is_empty() && self.landlock_net.is_empty() {
            return Ok(());
        }
        let unenforceable = match abi {
            None => true,
            Some(abi) => {
                crate::hardening::fs_grant_masked_away(self.landlock_handled, abi)
                    || crate::hardening::net_grant_masked_away(self.landlock_net_handled, abi)
            }
        };
        if unenforceable {
            return Err(crate::error::ConfigError::RestrictionLandlockUnenforceable { abi });
        }
        Ok(())
    }

    /// Checks that a sandbox's Landlock requests can be enforced wherever no
    /// namespace of the sandbox stands behind them, asking `landlock_abi` for
    /// the kernel's Landlock ABI only when there is such a request.
    ///
    /// `host_network` is a sandbox under [`Network::Host`](crate::Network::Host),
    /// which has no network namespace, and `host_pids` one without a PID
    /// namespace. Each leaves Landlock the only boundary on one reach:
    ///
    /// - Under host networking, a network grant bounds the host network, so a
    ///   kernel that masks it away (below ABI 4, or without the LSM) is
    ///   refused with `HostNetworkLandlockUnenforceable`. So is
    ///   [`LandlockScope::AbstractUnixSocket`](crate::LandlockScope::AbstractUnixSocket),
    ///   the only bound on the host's abstract sockets.
    /// - Without a PID namespace,
    ///   [`LandlockScope::Signal`](crate::LandlockScope::Signal) is the only
    ///   bound on signalling the host's processes.
    ///
    /// A scope refused here is `LandlockScopeUnenforceable`, on a kernel below
    /// ABI 6 or without the LSM. Anything a namespace also bounds is additive
    /// hardening, so the command stage narrows it best-effort instead: the
    /// filesystem grants, behind the swapped root; a network grant or the
    /// socket scope in a network namespace of the sandbox's own; the signal
    /// scope in a PID namespace.
    ///
    /// A network namespace stops bounding a network grant once a network stack
    /// attaches to it, which the build cannot see. `NetStack::attach` asks
    /// [`net_grant_unenforced`](Self::net_grant_unenforced) for that case.
    pub(crate) fn ensure_sandbox_enforceable(
        &self,
        host_network: bool,
        host_pids: bool,
        landlock_abi: impl FnOnce() -> Option<i32>,
    ) -> Result<(), crate::error::ConfigError> {
        use crate::hardening::scope;

        let net_grant = host_network && !self.landlock_net.is_empty();
        let mut unbounded = 0;
        if host_network {
            unbounded |= scope::ABSTRACT_UNIX_SOCKET;
        }
        if host_pids {
            unbounded |= scope::SIGNAL;
        }
        let scoped = self.landlock_scoped & unbounded;
        if !net_grant && scoped == 0 {
            return Ok(());
        }

        let abi = landlock_abi();
        if net_grant && Self::net_grant_unenforced(self.landlock_net_handled, abi) {
            return Err(crate::error::ConfigError::HostNetworkLandlockUnenforceable { abi });
        }
        crate::hardening::ensure_scopes_enforceable(scoped, abi)
    }

    /// Whether a kernel at `abi` leaves a Landlock network grant whose handled
    /// mask is `net_handled` governing nothing: a kernel below ABI 4, which
    /// masks every network right away, or one without the LSM (`None`). A zero
    /// mask is no grant, and nothing is lost.
    ///
    /// The rule for every place a network grant is the only bound on a reach:
    /// a host-network sandbox at build
    /// ([`ensure_sandbox_enforceable`](Self::ensure_sandbox_enforceable)), and
    /// a sandbox a network stack attaches to, whose namespace the stack gives
    /// outbound TCP (`NetStack::attach`).
    pub(crate) fn net_grant_unenforced(net_handled: u64, abi: Option<i32>) -> bool {
        net_handled != 0
            && abi.is_none_or(|abi| crate::hardening::net_grant_masked_away(net_handled, abi))
    }
}

/// One frozen mount operation.
///
/// Every target path is a rootfs-relative `CString` the sandbox stage
/// resolves against the new-root descriptor with `RESOLVE_IN_ROOT`, so
/// rootfs-internal absolute symlinks cannot escape into the host during the
/// pre-pivot window.
#[derive(Debug, Clone)]
pub(crate) struct MountOp {
    /// Mount-target directories to create first, outermost first. Existing
    /// entries are left alone.
    pub(crate) dirs: Vec<MountDir>,
    /// A rootfs-relative file to create (empty, mode 0644) as the target of
    /// a file bind. An entry the root already ships at that path is left
    /// exactly as it is, whatever kind it is.
    ///
    /// Unlike a mount point directory, it does not outlive the sandbox: the
    /// setup reports each one it creates, and the caller side removes it; see
    /// [`LaunchPlan::managed_placeholders`].
    pub(crate) create_file: Option<CString>,
    /// The mount action itself.
    pub(crate) action: MountAction,
}

/// One mount-target directory to create, and the mode to create it at.
///
/// A mount point the sandbox creates outlives the sandbox: it persists in the
/// rootfs directory on the host, and a provisioned tree carries it into
/// whatever is made of the tree afterwards. Its mode is therefore part of what
/// a launch contributes, and is stated here rather than left to the mount that
/// covers it — which hides the mode for as long as it is mounted.
#[derive(Debug, Clone)]
pub(crate) struct MountDir {
    /// The rootfs-relative directory to create it in; the empty string is the
    /// rootfs itself.
    pub(crate) parent: CString,
    /// The directory's own name.
    pub(crate) leaf: CString,
    /// The mode to create it at, applied exactly.
    pub(crate) mode: RawMode,
}

/// The action a [`MountOp`] performs once its target exists.
#[derive(Debug, Clone)]
pub(crate) enum MountAction {
    /// Mount a tmpfs.
    Tmpfs {
        /// Rootfs-relative mount target.
        target: CString,
        /// Mount flags for the tmpfs.
        flags: MountFlags,
        /// Filesystem data string (`mode=...`).
        data: CString,
    },
    /// Mount a fresh procfs instance, presenting the sandbox's own PID
    /// namespace.
    Procfs {
        /// Rootfs-relative mount target.
        target: CString,
    },
    /// Mount a fresh devpts instance.
    Devpts {
        /// Rootfs-relative mount target.
        target: CString,
        /// Filesystem data string.
        data: CString,
    },
    /// Recursively bind a host path onto a rootfs target.
    Bind {
        /// Absolute host source path, canonicalized at build time and
        /// opened by the sandbox stage before the pivot, while the host view
        /// is still mounted, without following a link.
        source: CString,
        /// Rootfs-relative mount target.
        target: CString,
        /// Whether to remount the bind read-only.
        read_only: bool,
    },
    /// Perform a raw mount: everything but the target goes to the kernel
    /// verbatim.
    Raw {
        /// The mount source, as given; empty when none was.
        source: CString,
        /// Rootfs-relative mount target.
        target: CString,
        /// The filesystem type, as given; empty when none was.
        fstype: CString,
        /// The raw mount flags, as given.
        flags: MountFlags,
        /// The filesystem data string, as given; empty when none was.
        data: CString,
    },
    /// Create a symlink inside the rootfs.
    Symlink {
        /// Rootfs-relative directory holding the link.
        parent: CString,
        /// The link's name inside `parent`.
        leaf: CString,
        /// The link's content.
        content: CString,
    },
    /// Hide what is at a path: an empty tmpfs over a directory, made read-only
    /// once the profile is in place, or an empty read-only file over anything
    /// else. A path with nothing at it hides nothing.
    Hide {
        /// Rootfs-relative path to hide.
        target: CString,
    },
    /// Bind the tree at a path onto itself, read-only, with every mount
    /// beneath it.
    ReadOnly {
        /// Rootfs-relative path to make read-only.
        target: CString,
    },
}

/// What a [`MountAction`] brings to rest on its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arrival {
    /// A filesystem instance of its own, which nothing outside the sandbox
    /// holds: a tmpfs, a procfs, a devpts, or a raw mount of a filesystem type.
    Fresh,
    /// A tree that already stood elsewhere, bound or moved onto the target:
    /// what is written under it lands wherever that tree lives.
    Tree,
}

/// `MS_REMOUNT`. rustix keeps the flag to its own remount call, and a raw
/// mount carries the caller's bits verbatim.
pub(crate) const MS_REMOUNT: u32 = 0x20;
/// `MS_MOVE`, kept to rustix's own move call for the same reason.
const MS_MOVE: u32 = 0x2000;
/// `MS_MGC_VAL`, the magic number `mount(2)` once required in the high half of
/// its flags word.
const MS_MGC_VAL: u32 = 0xC0ED_0000;
/// `MS_MGC_MSK`, the half of the flags word the magic number occupies.
const MS_MGC_MSK: u32 = 0xFFFF_0000;

/// A raw mount's flags as `mount(2)` acts on them: the legacy magic number
/// discarded where the high half of the word is exactly that number.
///
/// The kernel's `path_mount` strips it before it reads a single flag, and the
/// magic's bits overlap `MS_PRIVATE` and `MS_SLAVE`. Read as given, a raw mount
/// carrying it looks like a propagation change while the kernel performs a
/// fresh mount, so every reading of a raw mount's flags goes through this.
pub(crate) fn raw_mount_flags(flags: MountFlags) -> u32 {
    let flags = flags.bits();
    if flags & MS_MGC_MSK == MS_MGC_VAL {
        flags & !MS_MGC_MSK
    } else {
        flags
    }
}

impl Arrival {
    /// What a raw mount carrying `flags` brings to rest on its target, or
    /// `None` where it brings none.
    ///
    /// Read the way `mount(2)` reads its flags, in the order the kernel tests
    /// them, after [`raw_mount_flags`] has discarded the legacy magic. A
    /// remount changes a mount already standing and brings none. `MS_BIND`
    /// binds a tree, whatever else is set. A propagation change brings none.
    /// `MS_MOVE` moves a mount standing elsewhere onto the target, and anything
    /// else mounts a fresh filesystem of the type named.
    pub(crate) fn of_raw(flags: MountFlags) -> Option<Arrival> {
        let propagation = (MountPropagationFlags::SHARED
            | MountPropagationFlags::PRIVATE
            | MountPropagationFlags::DOWNSTREAM
            | MountPropagationFlags::UNBINDABLE)
            .bits();
        let flags = raw_mount_flags(flags);
        if flags & MS_REMOUNT != 0 {
            None
        } else if flags & MountFlags::BIND.bits() != 0 {
            Some(Arrival::Tree)
        } else if flags & propagation != 0 {
            None
        } else if flags & MS_MOVE != 0 {
            Some(Arrival::Tree)
        } else {
            Some(Arrival::Fresh)
        }
    }
}

impl MountAction {
    /// The rootfs-relative path this action brings a mount to rest on, and
    /// what arrives there, or `None` for an action that brings none.
    ///
    /// A path under one of these is inside that mount once the action has run,
    /// not in the rootfs directory on the host, which is what decides whether
    /// a target the launch creates has a host path at all. It also decides
    /// what an earlier mount at the same place still shows. A raw action is
    /// read through [`Arrival::of_raw`].
    pub(crate) fn arrival(&self) -> Option<(&CStr, Arrival)> {
        match self {
            MountAction::Tmpfs { target, .. }
            | MountAction::Procfs { target }
            | MountAction::Devpts { target, .. }
            | MountAction::Hide { target } => Some((target, Arrival::Fresh)),
            MountAction::Bind { target, .. } | MountAction::ReadOnly { target } => {
                Some((target, Arrival::Tree))
            }
            MountAction::Raw { target, flags, .. } => {
                Arrival::of_raw(*flags).map(|arrival| (target.as_c_str(), arrival))
            }
            MountAction::Symlink { .. } => None,
        }
    }
}

/// The wire encoding of the status record: the command exited with a code.
pub(crate) const STATUS_EXITED: u32 = 1;
/// The wire encoding of the status record: the command was terminated by a
/// signal.
pub(crate) const STATUS_SIGNALED: u32 = 2;
/// The wire encoding of the status record: the command was terminated by a
/// signal, and the kernel dumped its core.
pub(crate) const STATUS_DUMPED: u32 = 3;

/// The length of the status record the supervisor writes once it has collected
/// the command's exit, little-endian throughout:
///
/// | Bytes | Field |
/// | --- | --- |
/// | 0..4 | The kind, [`STATUS_EXITED`], [`STATUS_SIGNALED`], or [`STATUS_DUMPED`] |
/// | 4..8 | The exit code, or the signal number |
/// | 8..12 | 1 when the three fields below hold what `getrusage` reported, 0 when it failed |
/// | 12..20 | User processor time, in microseconds |
/// | 20..28 | System processor time, in microseconds |
/// | 28..36 | The peak resident set size, in kibibytes |
///
/// Short of `PIPE_BUF`, so the one write that carries it is atomic.
pub(crate) const STATUS_RECORD_LEN: usize = 36;

/// Encodes the status record [`STATUS_RECORD_LEN`] lays out.
///
/// Copies and integer arithmetic only, since the supervisor calls it after a
/// fork.
pub(crate) fn encode_status(
    kind: u32,
    value: i32,
    usage: Option<&sys::Rusage>,
) -> [u8; STATUS_RECORD_LEN] {
    let mut record = [0u8; STATUS_RECORD_LEN];
    record[0..4].copy_from_slice(&kind.to_le_bytes());
    record[4..8].copy_from_slice(&value.to_le_bytes());
    if let Some(usage) = usage {
        let rss = u64::try_from(usage.maxrss).unwrap_or(0);
        record[8..12].copy_from_slice(&1u32.to_le_bytes());
        record[12..20].copy_from_slice(&usage.utime.micros().to_le_bytes());
        record[20..28].copy_from_slice(&usage.stime.micros().to_le_bytes());
        record[28..36].copy_from_slice(&rss.to_le_bytes());
    }
    record
}

/// Decodes the status record [`encode_status`] writes, into the command's exit
/// status and, where the supervisor could read it, what the command used.
///
/// `None` for a kind or a usage flag this build never writes, which is a defect
/// in this library: the reader reports it as a broken protocol rather than
/// panicking, the same posture the report decoder takes.
pub(crate) fn decode_status(
    record: [u8; STATUS_RECORD_LEN],
) -> Option<(ExitStatus, Option<ResourceUsage>)> {
    let word = |at: usize| u32::from_le_bytes(record[at..at + 4].try_into().expect("four bytes"));
    let wide = |at: usize| u64::from_le_bytes(record[at..at + 8].try_into().expect("eight bytes"));
    let value = word(4) as i32;
    let status = match word(0) {
        STATUS_EXITED => ExitStatus::exited(value),
        STATUS_SIGNALED => ExitStatus::signaled(value),
        STATUS_DUMPED => ExitStatus::signaled_with_core_dump(value),
        _ => return None,
    };
    let usage = match word(8) {
        0 => None,
        1 => Some(ResourceUsage::of_processes(
            Duration::from_micros(wide(12)),
            Duration::from_micros(wide(20)),
            wide(28).saturating_mul(1024),
        )),
        _ => return None,
    };
    Some((status, usage))
}

/// The tag of a report record saying the setup created a file-bind target:
/// the mount op's index, then the created file's inode number as a
/// little-endian `u64`.
///
/// Above every step's wire value, which [`wire_enum`](crate::wire::wire_enum)
/// numbers from zero upward and so never reaches it, as
/// [`frame::RECORD_DONE`] is for the helper children's records.
pub(super) const REPORT_CREATED: u32 = u32::MAX;
/// The tag of a report record saying a gated command is at its gate, with
/// every setup step behind it. The tag is the whole record.
pub(super) const REPORT_HELD: u32 = u32::MAX - 1;
/// The length of a report record's tag, which opens every record.
const REPORT_TAG_LEN: usize = 4;
/// The length of a created-target record: the tag, the op index, and the inode
/// number.
pub(super) const REPORT_CREATED_LEN: usize = 16;
/// The length of a failure record: the step's wire value as the tag, the
/// errno, and the detail index.
pub(super) const REPORT_FAILURE_LEN: usize = 12;

/// A file-bind target the setup created in the root, as it reported it.
///
/// The inode number is the file's, taken through the descriptor the exclusive
/// create returned, so it names the file this launch made and not one that
/// took its name later. The caller side removes a target only while the name
/// still holds that inode.
///
/// The inode number is the whole of the identity, without the device, because
/// an overlay root reports its own device for every file in it. The number of
/// a file in the upper is the upper's own, whichever filesystems the layers
/// are on, so it is the one the caller side sees there too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CreatedTarget {
    /// The index of the mount op whose
    /// [`create_file`](MountOp::create_file) it is.
    pub(crate) op: usize,
    /// The created file's inode number.
    pub(crate) ino: u64,
}

/// A launched sandbox, as handed to the running-sandbox handle: the command
/// is executing and these are the caller's ends of its channels.
pub(crate) struct Launched {
    /// Pidfd of the supervisor: the sandbox init inside the PID namespace,
    /// or the command process itself without one. The kill handle.
    pub(crate) pidfd: OwnedFd,
    /// The supervisor's host pid, informational.
    pub(crate) pid: u32,
    /// Caller end of the control socket.
    pub(crate) control: OwnedFd,
    /// Read end of the status pipe.
    pub(crate) status: OwnedFd,
    /// Read end of the command's captured standard output, when observing.
    pub(crate) stdout: Option<OwnedFd>,
    /// Read end of the command's captured standard error, when observing.
    pub(crate) stderr: Option<OwnedFd>,
    /// A pidfd of the launch stage, for the handle to reap after the status
    /// arrives. `None` with a PID namespace, where the launch stage is reaped
    /// at spawn time and the init is not the caller's child process. A pidfd
    /// rather than a raw pid so the deferred reap targets exactly this process
    /// and cannot alias a pid a concurrent reaper freed and the OS recycled.
    pub(crate) reap: Option<OwnedFd>,
    /// The caller's terminal, where the launch lent the sandbox its
    /// foreground, for the handle to hand back.
    pub(crate) foreground: Option<Foreground>,
}

/// A process this caller forked, named by the pidfd its fork opened.
///
/// The pidfd comes from the fork itself
/// ([`sys::fork_with_pidfd`](sys::fork_with_pidfd)), so it refers to the
/// process from its first instant, whatever else in the caller waits for
/// children. Every signal and reap goes through it, so neither can reach a
/// process that took the pid after an application-wide reaper collected this
/// one first: a signal then answers `ESRCH`, and a reap `ECHILD`.
///
/// The pid is kept beside it for an identity-map delegate, which names the
/// process it maps by number. The delegate runs while the process is blocked at
/// its map gate, alive, so the number names this process while the delegate
/// uses it.
///
/// Every child the caller side forks is held as one of these: the launch stage,
/// and the export, copy-in, removal, overlay-probe, seccomp-probe and network
/// stack helpers.
#[derive(Debug)]
pub(crate) struct Forked {
    /// The process's pid, for a delegate.
    pid: Pid,
    /// The process's pidfd, for everything else.
    pidfd: OwnedFd,
}

impl Forked {
    /// The process `pid` names, through the pidfd its fork opened.
    pub(crate) fn new(pid: Pid, pidfd: OwnedFd) -> Forked {
        Forked { pid, pidfd }
    }

    /// The process's pid, for a delegate that names it by number while it is
    /// alive.
    pub(crate) fn pid(&self) -> Pid {
        self.pid
    }

    /// Sends the process `SIGKILL`. A process that has already exited is not
    /// an error.
    pub(crate) fn kill(&self) {
        let _ = process::pidfd_send_signal(&self.pidfd, Signal::KILL);
    }

    /// Reaps the process, blocking until it exits, and returns its exit code:
    /// `None` where a signal ended it. A process something else already reaped
    /// answers `ECHILD`.
    pub(crate) fn reap(&self) -> Result<Option<i32>, Errno> {
        reap_via_pidfd(self.pidfd.as_fd())
    }

    /// The process's pidfd, to poll for its exit.
    #[cfg(test)]
    pub(crate) fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    /// The pidfd, for a holder that reaps the process later.
    fn into_pidfd(self) -> OwnedFd {
        self.pidfd
    }
}

/// The caller's ends of a freshly forked launch: the launch stage and every
/// channel the caller keeps, returned by [`fork_launch`] in the parent.
struct ParentSide {
    /// The launch stage (stage A), forked directly from the caller.
    stage: Forked,
    /// Caller end of the control socket.
    host_sock: OwnedFd,
    /// Read end of the report pipe.
    report_read: OwnedFd,
    /// Read end of the status pipe.
    status_read: OwnedFd,
    /// Read end of the captured standard output, when observing.
    stdout: Option<OwnedFd>,
    /// Read end of the captured standard error, when observing.
    stderr: Option<OwnedFd>,
    /// Write end of the proceed pipe, present only for a gated launch: a
    /// write releases the gated command, a close abandons it.
    proceed_write: Option<OwnedFd>,
    /// Caller end of the map gate, present only for a range-mapped launch:
    /// stage A signals ready on it after unsharing, the caller applies the
    /// map against stage A's pid, and the go byte releases the stage.
    map_gate: Option<OwnedFd>,
    /// Caller end of the terminal channel, present only for a terminal launch:
    /// the sandbox sends the primary of the pseudoterminal it allocated over
    /// it, and [`receive_primary`] takes it.
    terminal: Option<OwnedFd>,
    /// The caller's terminal, where the launch lends the sandbox its
    /// foreground. Dropped with the rest of this on a launch that fails, which
    /// hands the foreground back.
    foreground: Option<Foreground>,
}

/// The payload byte the primary rides on over the terminal channel. Its value
/// is immaterial; a message of one byte with a descriptor is the primary, and
/// anything else is a broken protocol.
pub(super) const TERMINAL_BYTE: u8 = b'P';

/// The go byte written to the proceed pipe to release a gated command. Its
/// value is immaterial; the child treats any byte as the signal to proceed.
const PROCEED_BYTE: u8 = b'G';

/// How a forked helper child's identity map is established.
///
/// Shared by the export child, which reads a tree as root of the mapped
/// namespace, and the copy-in child, which writes one: both need to be inside
/// the map the tree's ownership is expressed in, and neither can establish a
/// range map on its own.
pub(crate) enum ChildMap<'a> {
    /// The single-identity map, which the child writes itself under the
    /// kernel's unprivileged one-id exception. The lines are formatted by the
    /// caller before the fork, as a launch formats its own.
    SelfMap {
        /// The `uid_map` line: `0 <euid> 1\n`.
        uid_line: &'a [u8],
        /// The `gid_map` line: `0 <egid> 1\n`.
        gid_line: &'a [u8],
    },
    /// A range map, written from outside the new namespace by the resolved
    /// delegate while the child blocks at the map gate.
    Delegated {
        /// The delegate that applies the map.
        mapper: &'a dyn IdMapper,
        /// The extents, resolved by the caller.
        map: &'a ResolvedMap,
    },
}

impl ChildMap<'_> {
    /// The child's half of this map: what the forked process itself must do.
    ///
    /// The delegate a range map is applied by runs in the caller, so it does
    /// not cross the fork.
    pub(in crate::mechanism) fn duty(&self) -> child::MapDuty<'_> {
        match self {
            // A provisioning child runs on the caller's own mount view, so its
            // map files are under the host's `/proc`.
            ChildMap::SelfMap { uid_line, gid_line } => child::MapDuty::Write {
                paths: child::MapPaths::SELF,
                uid_line,
                gid_line,
            },
            ChildMap::Delegated { .. } => child::MapDuty::Await,
        }
    }
}

/// The ready byte a stage sends on its map gate once it has unshared and is
/// blocked waiting for the identity map. Every child that waits for a
/// delegated map sends it: stage A, the command stage at its nested entry, the
/// export child, the copy-in child, and the removal child.
pub(super) const MAP_READY_BYTE: u8 = b'R';

/// The go byte the delegate sends on the map gate once the identity map is
/// established — the caller for a launch's own namespace, and the process that
/// forked the command for its nested one. The waiting side treats any byte as
/// the signal.
pub(super) const MAP_GO_BYTE: u8 = b'M';

use frame::RECORD_LEN;

/// How driving a map gate ended.
pub(super) enum Gated {
    /// The map is in force and the child has been released.
    Released,
    /// The child reported a failure before it signalled ready, so it never
    /// reached the gate. The record is the caller's to decode, since only the
    /// caller knows which step vocabulary it names.
    EarlyRecord([u8; RECORD_LEN]),
    /// The child is gone, or said something that is neither a ready byte nor a
    /// failure record. Nothing was applied and nothing was released.
    ChildLost,
}

/// Why driving a map gate failed.
pub(super) enum GateFailure {
    /// A read or write on the gate itself failed.
    Io(Errno),
    /// The delegate refused to establish the map; its own error is the
    /// diagnostic.
    Map(crate::idmap::IdMapError),
}

/// The caller's half of a map gate: waits for the child's ready byte, has the
/// delegate establish the child's identity map, and releases the child.
///
/// Every provisioning child that takes a delegated map is driven through this:
/// the export, the copy-in, and the removal. The child's side of the same
/// handshake is [`child::enter_mapped_namespace`], which is why the two byte
/// constants above are shared rather than restated.
///
/// The gate is a seqpacket socket, so one read receives one whole message and
/// its length distinguishes the two things a child may send: one byte is
/// [`MAP_READY_BYTE`], and [`RECORD_LEN`] bytes is a failure the child hit
/// before it ever reached the gate — it could not sweep its descriptors, or
/// could not unshare. Reading the record here is what lets that failure name
/// its step instead of surfacing as a child that vanished.
///
/// Nothing is killed or reaped here. A caller that gets anything but
/// [`Gated::Released`] has a child blocked in an unmapped namespace, and
/// [`abandon_gated_child`] is how it ends it. The child is named by its pid
/// because the delegate names it that way; see [`Forked`].
///
/// The fork that produces the child stays in each helper's own module even
/// though the three read alike. The child branch runs a different
/// never-returning function each time, and the `unsafe` block's SAFETY comment
/// has to vouch for *that* function's post-fork discipline by name; a shared
/// harness would leave the comment vouching for a closure whose body is
/// somewhere else.
pub(super) fn drive_map_gate(
    gate: BorrowedFd<'_>,
    child: Pid,
    mapper: &dyn crate::idmap::IdMapper,
    map: &crate::idmap::ResolvedMap,
) -> Result<Gated, GateFailure> {
    let mut record = [0u8; RECORD_LEN];
    let received =
        frame::retry_on_intr!(rustix::io::read(gate, &mut record)).map_err(GateFailure::Io)?;
    match received {
        1 if record[0] == MAP_READY_BYTE => {}
        RECORD_LEN => return Ok(Gated::EarlyRecord(record)),
        _ => return Ok(Gated::ChildLost),
    }

    let pid = child.as_raw_nonzero().get() as u32;
    mapper.apply(pid, map).map_err(GateFailure::Map)?;

    // A failed write means the child is already gone. Whatever it was going to
    // report, it reports through its own channel or not at all; that is not a
    // failure of the gate.
    let _ = frame::retry_on_intr!(rustix::io::write(gate, &[MAP_GO_BYTE]));
    Ok(Gated::Released)
}

/// Ends a child left blocked at its map gate, and reaps it.
///
/// A child whose map the delegate could not establish is waiting for a go byte
/// that will never come. It holds nothing but its own descriptors and has
/// touched no tree, so killing it is a clean end, and it is the only end
/// available.
///
/// Killed rather than released by closing the gate. A fork copies the
/// whole descriptor table, so any process this caller forked concurrently holds
/// its own copy of this gate's caller end and keeps the child's peer open
/// however promptly this one closes. The library's own children sweep their
/// inherited descriptors, but each only once its own fork has returned in it,
/// and a child the *consumer* forked never sweeps at all. The end of input the
/// blocked child is waiting for is therefore not something this caller can make
/// arrive, and a reap would block on it forever.
///
/// The kill and the reap both go through the child's pidfd, so a caller whose
/// own path reaps again afterwards meets `ECHILD` rather than collecting
/// another child of this process.
pub(super) fn abandon_gated_child(child: &Forked) {
    child.kill();
    let _ = child.reap();
}

/// Moves a descriptor of the launch's own off the standard streams' numbers,
/// if it holds one: a close-on-exec copy at 3 or above takes its place, and the
/// standard number is closed again.
///
/// A descriptor is created at the lowest number free, so a caller that has
/// closed one of 0, 1 and 2 would find the next descriptor the launch creates
/// there. The launch keeps every one of its own above them instead, on both
/// sides of the fork:
///
/// - The sandbox's processes inherit the caller's descriptor table, and the
///   command stage `dup2`s the wired streams onto 0, 1 and 2. A channel on one
///   of them would be replaced in the command process, and one on a stream the
///   plan leaves inherited would reach the command. A report pipe replaced
///   that way ends early, and its end of input reads as a successful exec.
/// - The caller's own table keeps a closed standard number closed. It is the
///   caller's to reuse, and a later launch that inherits the stream hands the
///   command nothing.
///
/// Every descriptor the launch creates passes through here: the channels
/// [`fork_launch`] creates, the handle's readiness set, and the cgroup's
/// descriptors. One created before the fork that cannot be moved fails the
/// launch, as its creation failing would. One the caller comes to hold once the
/// fork is behind it, the launch stage's pidfd, the supervisor's, and a
/// terminal's primary, is moved where a number above the standard streams is
/// free and kept where the kernel put it where none is: the sandbox's processes
/// never hold it, and failing a launch already under way would cost more than
/// the number. A copy the standard library takes with `try_clone` or
/// `try_clone_to_owned`, as of the caller's terminal or of the supervisor's
/// pidfd, needs nothing more, since its search starts at 3.
///
/// The sandbox's side of the rule is the launch stage's: before it creates a
/// descriptor of its own, it holds every standard number the caller left closed
/// with a close-on-exec placeholder, so nothing a stage creates can land there.
pub(crate) fn above_stdio(fd: &mut OwnedFd) -> Result<(), Errno> {
    if fd.as_raw_fd() > STDERR_FILENO {
        return Ok(());
    }
    // The assignment drops the descriptor on the standard number, closing it.
    *fd = rustix::io::fcntl_dupfd_cloexec(&*fd, STDERR_FILENO + 1)?;
    Ok(())
}

/// The highest of the standard streams' descriptor numbers, standard error's.
pub(crate) const STDERR_FILENO: RawFd = 2;

/// Marshals the launch data, creates the launch channels, and forks the
/// launch stage.
///
/// In the child this never returns: it constructs the [`child::Context`] and
/// runs [`child::stage_a`], which ends in `execve` or `exit_group`. In the
/// parent it returns the caller's ends of the channels. A `gated` launch
/// additionally carries a proceed pipe, whose read end the command stage
/// blocks on before `execve`; a `terminal` launch additionally carries the
/// terminal channel, over which the sandbox sends the primary of the
/// pseudoterminal it allocates for itself.
///
/// The caller's terminal is lent to the sandbox here, as [`Foreground`]
/// decides, and the decision travels to the init in the context.
fn fork_launch(
    plan: &LaunchPlan,
    observe: bool,
    gated: bool,
    terminal: Option<&Terminal>,
    cgroup_procs: Option<BorrowedFd<'_>>,
) -> Result<ParentSide, Error> {
    refuse_directory_streams(plan, observe, terminal.is_some())?;
    let foreground = Foreground::lend(plan, observe, terminal.is_some())?;

    // Pre-fork marshaling, caller side. The pointer arrays and identity-map
    // lines are the last pieces the sandbox stages need; they are assembled
    // here, where allocation is still permitted, and only read after the
    // fork.
    let mut argv: Vec<*const u8> = Vec::with_capacity(plan.args.len() + 2);
    argv.push(plan.program.as_ptr().cast());
    argv.extend(plan.args.iter().map(|arg| arg.as_ptr().cast::<u8>()));
    argv.push(std::ptr::null());
    let mut envp: Vec<*const u8> = Vec::with_capacity(plan.env.len() + 1);
    envp.extend(plan.env.iter().map(|entry| entry.as_ptr().cast::<u8>()));
    envp.push(std::ptr::null());

    // The single-identity map lines, formatted here where the euid and egid
    // are still the caller's. A range-mapped launch writes no lines; its map
    // goes through the delegate against the gated stage.
    let (uid_line, gid_line) = match &plan.identity {
        IdentityPlan::Single => crate::idmap::single_identity_lines(),
        IdentityPlan::Ranged { .. } => (Vec::new(), Vec::new()),
    };

    // Both ends of every channel are kept off the standard streams' numbers,
    // the caller's as well as the sandbox's; see `above_stdio`.
    let pair = |(mut first, mut second): (OwnedFd, OwnedFd)| {
        above_stdio(&mut first)?;
        above_stdio(&mut second)?;
        Ok((first, second))
    };
    let pipe = || pipe::pipe_with(PipeFlags::CLOEXEC).and_then(pair);
    // Seqpacket keeps each message whole: the pidfd delivery and each control
    // request on the control socket, ready and go on the map gate, and the
    // primary on the terminal channel.
    let seqpacket = || {
        rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .and_then(pair)
    };

    let (report_read, report_write) = pipe().map_err(spawn_error)?;
    let (status_read, status_write) = pipe().map_err(spawn_error)?;
    let (host_sock, cage_sock) = seqpacket().map_err(spawn_error)?;
    // The map gate, created only when a delegate writes the map: one
    // seqpacket pair carries ready out and go back, the shape the control
    // socket already set.
    let map_gate = if plan.identity.is_ranged() {
        Some(seqpacket().map_err(spawn_error)?)
    } else {
        None
    };
    // One descriptor serves the null stdin disposition, the placeholders the
    // launch stage holds closed standard numbers with, and the supervisor's
    // own stdio; opened read-write so it fits all three.
    let mut null = rustix::fs::open(
        c"/dev/null",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(spawn_error)?;
    above_stdio(&mut null).map_err(spawn_error)?;
    let (stdout_pipe, stderr_pipe) = if observe {
        (
            Some(pipe().map_err(spawn_error)?),
            Some(pipe().map_err(spawn_error)?),
        )
    } else {
        (None, None)
    };
    // The proceed pipe exists only for a gated launch.
    let proceed = if gated {
        Some(pipe().map_err(spawn_error)?)
    } else {
        None
    };
    // The terminal channel exists only for a terminal launch. The
    // pseudoterminal itself is allocated inside the sandbox, from the
    // `/dev/ptmx` the sandbox sees, so its replica is a node the command can
    // name; only the primary crosses back.
    let terminal_channel = if terminal.is_some() {
        Some(seqpacket().map_err(spawn_error)?)
    } else {
        None
    };

    // The slots the setup keeps each hidden directory's tmpfs in until the
    // profile is in place, allocated here because the child cannot allocate.
    let hidden: Vec<std::cell::Cell<Option<OwnedFd>>> = plan
        .ops
        .iter()
        .filter(|op| matches!(op.action, MountAction::Hide { .. }))
        .map(|_| std::cell::Cell::new(None))
        .collect();

    // SAFETY: the child-process branch only constructs a struct of references
    // on its own stack and runs `child::stage_a`, which performs raw rustix
    // syscalls over the data frozen above — no allocation, no locking, no
    // libc — and never returns: every path ends in `execve` or `exit_group`.
    match unsafe { sys::fork_with_pidfd() } {
        Err(errno) => Err(spawn_error(errno)),
        Ok(PidfdFork::Child) => {
            let context = child::Context {
                plan,
                argv: &argv,
                envp: &envp,
                uid_line: &uid_line,
                gid_line: &gid_line,
                report_fd: report_write.as_fd(),
                status_fd: status_write.as_fd(),
                control_fd: cage_sock.as_fd(),
                null_fd: null.as_fd(),
                capture_stdout_fd: stdout_pipe.as_ref().map(|(_, write)| write.as_fd()),
                capture_stderr_fd: stderr_pipe.as_ref().map(|(_, write)| write.as_fd()),
                proceed_fd: proceed.as_ref().map(|(read, _)| read.as_fd()),
                map_gate_fd: map_gate.as_ref().map(|(_, stage)| stage.as_fd()),
                stdin_fd: plan.stdin.caller_fd(),
                stdout_fd: plan.stdout.caller_fd(),
                stderr_fd: plan.stderr.caller_fd(),
                terminal,
                terminal_channel_fd: terminal_channel
                    .as_ref()
                    .map(|(_, sandbox)| sandbox.as_fd()),
                take_foreground: foreground.is_some(),
                hidden: &hidden,
                cgroup_procs_fd: cgroup_procs,
            };
            child::stage_a(&context)
        }
        Ok(PidfdFork::ParentOf(mut stage_a)) => {
            // The pidfd the fork opened, kept off a standard number where a
            // number above them is free; see `above_stdio`.
            let _ = above_stdio(&mut stage_a.pidfd);
            // Close the caller's copies of the sandbox-side ends: from here
            // on, end-of-file on each read side means the sandbox's copies
            // are gone.
            drop(report_write);
            drop(status_write);
            drop(cage_sock);
            drop(null);
            let stdout = stdout_pipe.map(|(read, write)| {
                drop(write);
                read
            });
            let stderr = stderr_pipe.map(|(read, write)| {
                drop(write);
                read
            });
            let proceed_write = proceed.map(|(read, write)| {
                drop(read);
                write
            });
            let map_gate = map_gate.map(|(caller, stage)| {
                drop(stage);
                caller
            });
            let terminal = terminal_channel.map(|(caller, sandbox)| {
                drop(sandbox);
                caller
            });
            Ok(ParentSide {
                stage: stage_a,
                host_sock,
                report_read,
                status_read,
                stdout,
                stderr,
                proceed_write,
                map_gate,
                terminal,
                foreground,
            })
        }
    }
}

/// Receives the primary of the sandbox's pseudoterminal over the terminal
/// channel.
///
/// `None` when the channel hung up without one: every process that could have
/// sent it is gone, having failed first, and the report pipe says which step.
fn receive_primary(channel: &OwnedFd) -> Result<Option<OwnedFd>, Error> {
    let mut payload = [0u8; 1];
    let (bytes, primary) =
        frame::recv_with_fd(channel.as_fd(), &mut payload).map_err(wait_syscall_error)?;
    match (bytes, primary) {
        (0, _) => Ok(None),
        (1, Some(mut primary)) if payload[0] == TERMINAL_BYTE => {
            // Kept off a standard number where a number above them is free;
            // see `above_stdio`.
            let _ = above_stdio(&mut primary);
            Ok(Some(primary))
        }
        _ => Err(wait_syscall_error(Errno::PROTO)),
    }
}

/// Establishes a range-mapped launch's identity map through its delegate.
///
/// A no-op for the single-identity tier, which carries no gate. For a range
/// tier: waits for stage A's ready byte (sent once it has unshared and
/// swept), applies the resolved map against stage A's pid, and releases the
/// stage with the go byte.
///
/// If stage A exits before signalling ready, the report pipe holds the true
/// cause and is read for it. If the delegate fails, stage A is killed and
/// reaped, and the delegate's own error is returned: the delegate ran
/// caller-side, so the better diagnostic is already in hand. Either way stage A
/// had not forked anything yet, so nothing else of the launch exists.
///
/// The wait for the ready byte has no deadline, deliberately, like the launch's
/// other reads of its own stages: [`read_report`] and [`receive_supervisor`].
/// Every end they wait on belongs to a process this launch created, which sends
/// what is awaited or exits, and its exit closes the end. Only a stage blocked
/// in the kernel holds one open, a mount against an unresponsive server for
/// instance, and the launch then waits as long as that mount does.
fn establish_identity_map(plan: &LaunchPlan, parent: &mut ParentSide) -> Result<(), Error> {
    let Some(gate) = &parent.map_gate else {
        return Ok(());
    };
    let IdentityPlan::Ranged { mapper, map } = &plan.identity else {
        // fork_launch creates the gate only for a ranged plan.
        return Ok(());
    };

    let mut byte = [0u8; 1];
    match frame::retry_on_intr!(rustix::io::read(gate, &mut byte)) {
        // Stage A is unshared and waiting; the namespace exists.
        Ok(n) if n > 0 => {}
        // End-of-file: stage A exited before reaching the gate. The report
        // pipe holds the step that failed, and no target, since nothing that
        // creates one had been forked.
        Ok(_) => {
            let report = read_report(&parent.report_read, &mut Vec::new(), 0);
            let _ = parent.stage.reap();
            return Err(match report {
                Ok(Report::SetupFailed {
                    step,
                    errno,
                    detail,
                }) => setup_error(step, errno, detail, Labels::of(plan)),
                Ok(Report::ExecSucceeded | Report::Held) => Error::SupervisorLost,
                Err(err) => err,
            });
        }
        Err(errno) => {
            parent.stage.kill();
            let _ = parent.stage.reap();
            return Err(wait_syscall_error(errno));
        }
    }

    // The map is written against stage A: the process that unshared, so the
    // process whose /proc map files name the new namespace.
    let pid = parent.stage.pid().as_raw_nonzero().get() as u32;
    match mapper.apply(pid, map) {
        Ok(()) => {
            // Release the stage. A failed write means it died; the caller's
            // next read on the report or control path reports the outcome.
            let _ = frame::retry_on_intr!(rustix::io::write(gate, &[MAP_GO_BYTE]));
            Ok(())
        }
        Err(err) => {
            // The delegate failed. Stage A is blocked at the gate in an
            // unmapped namespace, before it forks anything, so killing it ends
            // the launch cleanly; its report record is superseded by the
            // delegate's error.
            //
            // Killed rather than released by closing the gate: a fork
            // copies the whole descriptor table, so any process this caller
            // forked concurrently holds a copy of this gate's caller end and
            // keeps the peer open however promptly this one closes. The
            // library's own children do sweep their inherited tables, but each
            // only after its fork has returned in it, and nothing bounds when
            // the kernel next schedules that child; a child the *consumer*
            // forked sweeps nothing at all, and drops the copy only when it
            // execs — the gate is close-on-exec — or exits. The end-of-file
            // stage A waits on is therefore not something this caller can make
            // arrive, and the reap below would block on it.
            parent.stage.kill();
            parent.map_gate = None;
            let _ = parent.stage.reap();
            Err(Error::IdentityMap(err))
        }
    }
}

/// Decides how the launch stage is reaped for a command that is now running.
///
/// Without a PID namespace the launch stage stays outside as the command's
/// parent and is reaped by the handle once the status arrives, so its pidfd is
/// returned; with one it has already exited and is reaped here, best-effort in
/// case the application reaps child processes of its own.
fn reap_after(pid_namespace: bool, stage: Forked) -> Option<OwnedFd> {
    if pid_namespace {
        let _ = stage.reap();
        None
    } else {
        Some(stage.into_pidfd())
    }
}

/// Reaps the process a pidfd refers to, blocking until it exits, and returns
/// its exit code: `None` where a signal ended it.
///
/// Immune to pid reuse: the pidfd names the exact process, so unlike a raw
/// `waitpid` this cannot alias a pid a concurrent reaper freed and the OS
/// recycled for another same-parent child. A process already reaped answers
/// `ECHILD`.
pub(crate) fn reap_via_pidfd(pidfd: BorrowedFd<'_>) -> Result<Option<i32>, Errno> {
    frame::retry_on_intr!(process::waitid(WaitId::PidFd(pidfd), WaitIdOptions::EXITED))
        .map(|status| status.and_then(|status| status.exit_status()))
}

/// Blocks until the process a pidfd refers to has exited, retrying `EINTR`.
///
/// The process need not be the caller's child, and the namespace init is not,
/// so its exit is read rather than collected: a pidfd turns readable once its
/// process has exited, reaped or not.
pub(crate) fn await_exit(pidfd: BorrowedFd<'_>) -> Result<(), Errno> {
    loop {
        let mut fds = [PollFd::from_borrowed_fd(pidfd, PollFlags::IN)];
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(errno),
        }
    }
}

/// Whether the process a pidfd refers to has exited, asked without waiting.
///
/// A failed poll answers `false`: the callers act only on a process known to
/// be gone.
pub(crate) fn has_exited(pidfd: BorrowedFd<'_>) -> bool {
    let mut fds = [PollFd::from_borrowed_fd(pidfd, PollFlags::IN)];
    matches!(
        rustix::event::poll(&mut fds, Some(&rustix::event::Timespec::default())),
        Ok(ready) if ready > 0
    )
}

/// Ends a launch this side is giving up on: kills the supervisor and the launch
/// stage, reaps the stage, and waits for the supervisor to exit.
///
/// With a PID namespace the supervisor is the init, whose exit takes every
/// process of the sandbox with it; without one it is the command process. Once
/// this returns, the targets the setup reported creating are bound by no
/// process of this launch, which is what lets the caller remove them.
fn abort_launch(stage: &Forked, supervisor: &OwnedFd) {
    let _ = process::pidfd_send_signal(supervisor, Signal::KILL);
    stage.kill();
    let _ = stage.reap();
    let _ = await_exit(supervisor.as_fd());
}

/// Launches the sandbox and blocks until the command is executing.
///
/// Returns once the report pipe settles: end-of-file means every setup step
/// succeeded and `execve` replaced the command process's image, and a failure
/// record means a step failed and is returned as the typed error. A terminal
/// launch returns the caller's end of the pseudoterminal beside the launched
/// sandbox; every other launch returns `None` for it.
///
/// `created` receives the file-bind targets the setup reported creating. After
/// success they are the running sandbox's, free once its supervisor has exited.
/// After an error it holds them only where the supervisor is known to have
/// exited, so what it holds then is free at once: a launch whose supervisor was
/// never published may have left a process running that this side cannot name,
/// and one whose init's pidfd did not arrive has an end this side cannot wait
/// for, and the targets of either are left where they are.
pub(crate) fn spawn(
    plan: &LaunchPlan,
    observe: bool,
    terminal: Option<&Terminal>,
    cgroup_procs: Option<BorrowedFd<'_>>,
    progress: &mut dyn FnMut(Progress),
    created: &mut Vec<CreatedTarget>,
) -> Result<(Launched, Option<OwnedFd>), Error> {
    progress(Progress::Launching);
    let mut parent = fork_launch(plan, observe, false, terminal, cgroup_procs)?;
    // A range map is established before the supervisor is published, so a
    // published sandbox always has a fully mapped user namespace.
    establish_identity_map(plan, &mut parent)?;
    let received = receive_supervisor(&parent.host_sock);
    if let Ok(publication) = &received
        && let Some(foreground) = &mut parent.foreground
    {
        foreground.lent_to(publication.pid());
    }
    if let Ok(Publication::Received(..)) = &received {
        progress(Progress::Supervised);
    }
    let report = read_report(&parent.report_read, created, plan.ops.len());

    match (report, received) {
        // The command is running and the supervisor is published. A terminal
        // launch's primary was sent before the command was forked, so it is
        // already waiting on the channel.
        (Ok(Report::ExecSucceeded), Ok(Publication::Received(pidfd, pid))) => {
            let primary = match &parent.terminal {
                Some(channel) => match receive_primary(channel) {
                    Ok(Some(primary)) => Some(primary),
                    // The command runs on a terminal nobody holds. That is a
                    // defect in this library rather than a state to hand out,
                    // so the sandbox is torn down with it.
                    outcome => {
                        abort_launch(&parent.stage, &pidfd);
                        return Err(match outcome {
                            Err(err) => err,
                            _ => wait_syscall_error(Errno::PROTO),
                        });
                    }
                },
                None => None,
            };
            progress(Progress::Executing);
            Ok((
                Launched {
                    pidfd,
                    pid,
                    control: parent.host_sock,
                    status: parent.status_read,
                    stdout: parent.stdout,
                    stderr: parent.stderr,
                    reap: reap_after(plan.pid_namespace, parent.stage),
                    foreground: parent.foreground,
                },
                primary,
            ))
        }
        // A setup step failed. Every stage at or below the failure has
        // exited, and a supervisor above it exits as soon as it observes the
        // exit, so the launch stage is reapable and the supervisor's exit is
        // near.
        (
            Ok(Report::SetupFailed {
                step,
                errno,
                detail,
            }),
            received,
        ) => {
            match &received {
                Ok(Publication::Received(pidfd, _)) => {
                    let _ = parent.stage.reap();
                    let _ = await_exit(pidfd.as_fd());
                }
                // A supervisor this process cannot wait for is asked to end
                // too, in case it has not observed the failure yet.
                Ok(Publication::Unreceived(_)) => {
                    end_unreceived(&parent.stage, &parent.host_sock, plan, created);
                }
                // Unpublished, the supervisor is the launch stage's to have
                // ended, which it does before reporting its own failure, so
                // every process of the launch is gone.
                Err(_) => {
                    parent.stage.kill();
                    let _ = parent.stage.reap();
                }
            }
            Err(setup_error(step, errno, detail, Labels::of(plan)))
        }
        // The report pipe reached end-of-file, so every setup step succeeded,
        // but the supervisor is not in hand. Either the launch stage exited
        // before sending it, leaving whatever it forked to run on, or this
        // process could not receive it, and the launch is ended.
        (Ok(Report::ExecSucceeded), received) => {
            give_up(&parent.stage, &parent.host_sock, &received, plan, created);
            Err(match received {
                Err(err) => err,
                Ok(_) => Error::SupervisorUnreceived,
            })
        }
        // An ungated launch holds no command at a gate, so a held record is a
        // broken protocol, as an unreadable report is. Unsupervisable; tear the
        // launch down rather than leave it running blind.
        (Ok(Report::Held), received) => {
            give_up(&parent.stage, &parent.host_sock, &received, plan, created);
            Err(wait_syscall_error(Errno::PROTO))
        }
        (Err(err), received) => {
            give_up(&parent.stage, &parent.host_sock, &received, plan, created);
            Err(err)
        }
    }
}

/// Tears down a launch that will not be handed out, keeping in `created` only
/// what is free once it is gone.
///
/// With the supervisor's pidfd in hand, [`abort_launch`] ends the whole launch.
/// With only the control socket, [`end_unreceived`] does. With neither, only
/// the launch stage can be reached, and a process it forked may run on.
///
/// A gated launch's caller drops its proceed pipe first, so that a command held
/// at the gate is released into failing rather than left waiting there.
fn give_up(
    stage: &Forked,
    control: &OwnedFd,
    received: &Result<Publication, Error>,
    plan: &LaunchPlan,
    created: &mut Vec<CreatedTarget>,
) {
    match received {
        Ok(Publication::Received(pidfd, _)) => abort_launch(stage, pidfd),
        Ok(Publication::Unreceived(_)) => end_unreceived(stage, control, plan, created),
        Err(_) => {
            stage.kill();
            let _ = stage.reap();
            created.clear();
        }
    }
}

/// Ends a launch whose supervisor was published but whose pidfd this process
/// could not receive, keeping in `created` only what is free once it returns.
///
/// The supervisor runs and supervises, and the control socket is the one
/// channel to it left, so [`CONTROL_END`](child::CONTROL_END) asks it to end
/// the sandbox, as a hangup does under
/// [`stop_with_caller`](crate::CageBuilder::stop_with_caller). The init exits,
/// and its exit ends every process of the namespace. Without a PID namespace
/// the supervisor is the launch stage itself, which kills the command,
/// collects it and exits, and so is not killed here: killed, it would leave
/// the command running with no supervisor at all. A supervisor still busy
/// with the launch acts on the request once it supervises, and a gated
/// command reaches that point only once its proceed pipe has closed, which is
/// why the gated caller drops it first.
///
/// The launch stage is then reaped. Without a PID namespace that is the
/// supervisor's exit, so every target is free; with one, the init's exit
/// cannot be awaited without its pidfd, and the targets are left where they
/// are.
fn end_unreceived(
    stage: &Forked,
    control: &OwnedFd,
    plan: &LaunchPlan,
    created: &mut Vec<CreatedTarget>,
) {
    // A supervisor already gone answers `EPIPE`, which ends nothing more.
    let _ = rustix::net::send(control, &[child::CONTROL_END], SendFlags::NOSIGNAL);
    let _ = stage.reap();
    if plan.pid_namespace {
        created.clear();
    }
}

/// A launched sandbox held at the gate before `execve`, the seam at which a
/// caller attaches a userspace network stack to the sandbox's network
/// namespace.
///
/// Every setup step is behind the command, and the supervisor is published, so
/// [`netns_pid`] is a live process and a valid target for `/proc/<pid>/ns/net`;
/// the command has not yet run. [`proceed`] releases it, and dropping the
/// handle without proceeding tears the launch down through [`abandon`].
///
/// [`netns_pid`]: PendingLaunch::netns_pid
/// [`proceed`]: PendingLaunch::proceed
/// [`abandon`]: PendingLaunch::abandon
pub(crate) struct PendingLaunch {
    /// The launch stage, reaped at proceed or abandon.
    stage: Forked,
    /// Pidfd of the supervisor: the kill handle, and the process whose
    /// network namespace a stack attaches to.
    pidfd: OwnedFd,
    /// The supervisor's host pid, in every sandbox namespace.
    pid: u32,
    /// Caller end of the control socket.
    host_sock: OwnedFd,
    /// Read end of the report pipe, read again once the command is released.
    report_read: OwnedFd,
    /// Read end of the status pipe.
    status_read: OwnedFd,
    /// Read end of the captured standard output, when observing.
    stdout: Option<OwnedFd>,
    /// Read end of the captured standard error, when observing.
    stderr: Option<OwnedFd>,
    /// Write end of the proceed pipe: a write releases the command.
    proceed_write: OwnedFd,
    /// Whether the sandbox has its own PID namespace, deciding the reap.
    pid_namespace: bool,
    /// The network the sandbox was built with, which decides whether it has a
    /// network namespace of its own and a loopback up in it.
    network: Network,
    /// The caller's terminal, where the launch lent the sandbox its
    /// foreground. Handed to the running handle at proceed, and handed back
    /// when the launch fails or is abandoned.
    foreground: Option<Foreground>,
    /// The mount labels, for naming a setup step that fails after release.
    op_labels: Vec<String>,
    /// The command label, for naming an exec step that fails after release.
    exec_label: String,
    /// The resource-limit labels, for naming an rlimit step that fails after
    /// release.
    rlimit_labels: Vec<String>,
    /// The Landlock rule labels, for naming a rule the command stage fails to
    /// add after release.
    #[cfg(feature = "hardening")]
    landlock_labels: Vec<String>,
    /// The handled mask of the launch's Landlock network grants, zero where it
    /// has none, for a network stack attaching to it to check against the
    /// kernel.
    #[cfg(all(feature = "hardening", feature = "netstack"))]
    landlock_net_handled: u64,
}

/// Launches the sandbox but holds the command at the gate before `execve`,
/// returning once the command is there.
///
/// The command says it is held only with every step ahead of the gate behind
/// it: the sandbox's namespaces and mounts are in place, and a terminal's
/// primary is sent. A setup failure before that (a denied `unshare`, a refused
/// mount) surfaces here as the typed error; one after it (the command's nested
/// user namespace, the identity switch, the hardening, the exec) is deferred to
/// [`PendingLaunch::proceed`], where the report is read again.
///
/// With a PID namespace the init supervises the held command, except under a
/// range map. There the init is the delegate for the command's nested identity
/// map, and waits at that map's gate, which the command reaches only once it
/// is released; it supervises from then on.
///
/// `created` as for [`spawn`]. Every target is reported before the command is
/// held, so a pending launch has them all.
pub(crate) fn spawn_pending(
    plan: &LaunchPlan,
    observe: bool,
    terminal: Option<&Terminal>,
    cgroup_procs: Option<BorrowedFd<'_>>,
    progress: &mut dyn FnMut(Progress),
    created: &mut Vec<CreatedTarget>,
) -> Result<(PendingLaunch, Option<OwnedFd>), Error> {
    progress(Progress::Launching);
    let mut parent = fork_launch(plan, observe, true, terminal, cgroup_procs)?;
    // The map precedes the supervisor's publication, so by the time the
    // caller holds a Pending, /proc/<pid>/ns/user is fully mapped — the
    // ordering the network stack's helper relies on when it enters the
    // namespace.
    establish_identity_map(plan, &mut parent)?;
    let proceed_write = parent
        .proceed_write
        .take()
        .expect("a gated launch carries a proceed pipe");

    let (pidfd, pid) = match receive_supervisor(&parent.host_sock) {
        Ok(Publication::Received(pidfd, pid)) => (pidfd, pid),
        // Not in hand. The record says why where a setup step failed, and the
        // launch is torn down either way. The proceed pipe goes first, so a
        // command held at its gate, or on its way there, fails at it rather
        // than waiting on a pipe whose only write end is this function's.
        received => {
            drop(proceed_write);
            if let Ok(publication) = &received
                && let Some(foreground) = &mut parent.foreground
            {
                foreground.lent_to(publication.pid());
            }
            let failed = match read_report(&parent.report_read, created, plan.ops.len()) {
                Ok(Report::SetupFailed {
                    step,
                    errno,
                    detail,
                }) => Some(setup_error(step, errno, detail, Labels::of(plan))),
                _ => None,
            };
            match &received {
                // The supervisor was never published because a setup step
                // failed before the command was forked, or because the launch
                // stage failed to publish it and ended what it had forked
                // before saying so. Every process of the launch is gone, and
                // with them whatever held its targets.
                Err(_) if failed.is_some() => {
                    parent.stage.kill();
                    let _ = parent.stage.reap();
                }
                _ => give_up(&parent.stage, &parent.host_sock, &received, plan, created),
            }
            return Err(match (failed, received) {
                (Some(err), _) | (None, Err(err)) => err,
                (None, Ok(_)) => Error::SupervisorUnreceived,
            });
        }
    };
    if let Some(foreground) = &mut parent.foreground {
        foreground.lent_to(pid);
    }
    progress(Progress::Supervised);

    match read_report(&parent.report_read, created, plan.ops.len()) {
        Ok(Report::Held) => {}
        // With the proceed pipe still open no command has been released, so a
        // failure is a step before the gate, and the supervisor exits on it.
        Ok(Report::SetupFailed {
            step,
            errno,
            detail,
        }) => {
            let _ = parent.stage.reap();
            let _ = await_exit(pidfd.as_fd());
            return Err(setup_error(step, errno, detail, Labels::of(plan)));
        }
        // Every process of the launch let go of the report without a word: the
        // command never reached its gate, and nothing says why.
        Ok(Report::ExecSucceeded) => {
            abort_launch(&parent.stage, &pidfd);
            return Err(Error::SupervisorLost);
        }
        Err(err) => {
            abort_launch(&parent.stage, &pidfd);
            return Err(err);
        }
    }

    // The primary was sent before the command reached its gate, so a held
    // launch's is already waiting on the channel. Nothing writes to the
    // terminal while the launch is held, and the caller attaches its network
    // stack and proceeds with the primary already in hand.
    let primary = match &parent.terminal {
        Some(channel) => match receive_primary(channel) {
            Ok(Some(primary)) => Some(primary),
            outcome => {
                abort_launch(&parent.stage, &pidfd);
                return Err(match outcome {
                    Err(err) => err,
                    _ => wait_syscall_error(Errno::PROTO),
                });
            }
        },
        None => None,
    };
    Ok((
        PendingLaunch {
            stage: parent.stage,
            pidfd,
            pid,
            host_sock: parent.host_sock,
            report_read: parent.report_read,
            status_read: parent.status_read,
            stdout: parent.stdout,
            stderr: parent.stderr,
            proceed_write,
            pid_namespace: plan.pid_namespace,
            network: plan.network,
            foreground: parent.foreground,
            op_labels: plan.op_labels.clone(),
            exec_label: plan.exec_label.clone(),
            rlimit_labels: plan.rlimit_labels.clone(),
            #[cfg(feature = "hardening")]
            landlock_labels: plan.hardening.landlock_labels.clone(),
            #[cfg(all(feature = "hardening", feature = "netstack"))]
            landlock_net_handled: plan.hardening.landlock_net_handled,
        },
        primary,
    ))
}

impl PendingLaunch {
    /// The supervisor's host pid: a process in the sandbox's network
    /// namespace, the target for `/proc/<pid>/ns/net`.
    pub(crate) fn netns_pid(&self) -> u32 {
        self.pid
    }

    /// The network the sandbox was built with.
    pub(crate) fn network(&self) -> Network {
        self.network
    }

    /// The handled mask of the launch's Landlock network grants, zero where it
    /// has none.
    #[cfg(all(feature = "hardening", feature = "netstack"))]
    pub(crate) fn landlock_net_handled(&self) -> u64 {
        self.landlock_net_handled
    }

    /// The supervisor's pidfd.
    pub(crate) fn supervisor(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    /// Releases the gated command and blocks until it is executing, returning
    /// the launched sandbox or the typed setup error.
    ///
    /// Once this returns an error, the supervisor has exited.
    pub(crate) fn proceed(self, progress: &mut dyn FnMut(Progress)) -> Result<Launched, Error> {
        // Release the command: any byte is the go signal. A failed write means
        // the command process is already gone; the report read below reports
        // the true outcome.
        let _ = frame::retry_on_intr!(rustix::io::write(&self.proceed_write, &[PROCEED_BYTE]));
        drop(self.proceed_write);

        // Every created target was reported before the command was held, so a
        // record naming one now is a broken protocol.
        match read_report(&self.report_read, &mut Vec::new(), 0) {
            Ok(Report::ExecSucceeded) => {
                progress(Progress::Executing);
                Ok(Launched {
                    pidfd: self.pidfd,
                    pid: self.pid,
                    control: self.host_sock,
                    status: self.status_read,
                    stdout: self.stdout,
                    stderr: self.stderr,
                    reap: reap_after(self.pid_namespace, self.stage),
                    foreground: self.foreground,
                })
            }
            Ok(Report::SetupFailed {
                step,
                errno,
                detail,
            }) => {
                let _ = self.stage.reap();
                let _ = await_exit(self.pidfd.as_fd());
                // Assembled field by field rather than from `&self`: the
                // proceed pipe was moved out of `self` above, so `self` as a
                // whole can no longer be borrowed — which is what a helper
                // taking `&self` would need. `Labels::of` does not apply
                // either; it reads a plan, and this side holds only the labels
                // the plan was built with.
                Err(setup_error(
                    step,
                    errno,
                    detail,
                    Labels {
                        ops: &self.op_labels,
                        exec: &self.exec_label,
                        rlimits: &self.rlimit_labels,
                        // The cgroup is joined before the launch is held, so
                        // no step after release names it.
                        cgroup_parent: None,
                        #[cfg(feature = "hardening")]
                        landlock: &self.landlock_labels,
                    },
                ))
            }
            Ok(Report::Held) => {
                abort_launch(&self.stage, &self.pidfd);
                Err(wait_syscall_error(Errno::PROTO))
            }
            Err(err) => {
                abort_launch(&self.stage, &self.pidfd);
                Err(err)
            }
        }
    }

    /// Tears the pending launch down: kills the supervisor, reaps the launch
    /// stage, and waits for the supervisor to exit. The gated command ends with
    /// its supervisor — with a PID namespace the kernel tears the namespace
    /// down, and without one the supervisor pidfd is the command process
    /// itself.
    pub(crate) fn abandon(self) {
        abort_launch(&self.stage, &self.pidfd);
    }
}

/// The caller-side labels that name a failed setup step's subject.
///
/// The report record's detail index selects within whichever list the failed
/// step belongs to — the mount ops for a mount step, the resource limits for
/// the rlimit step, the Landlock rules for adding one — and the exec step has a
/// single subject rather than a list. The sandbox stages never see any of this;
/// it exists so a reported step carries the thing it was operating on.
#[derive(Clone, Copy)]
struct Labels<'a> {
    ops: &'a [String],
    exec: &'a str,
    rlimits: &'a [String],
    /// The parent the sandbox's cgroup is created beneath, where it has one.
    cgroup_parent: Option<&'a std::path::Path>,
    #[cfg(feature = "hardening")]
    landlock: &'a [String],
}

impl<'a> Labels<'a> {
    /// The labels a plan carries.
    fn of(plan: &'a LaunchPlan) -> Labels<'a> {
        Labels {
            ops: &plan.op_labels,
            exec: &plan.exec_label,
            rlimits: &plan.rlimit_labels,
            cgroup_parent: plan.cgroup.as_ref().map(|cgroup| cgroup.parent.as_path()),
            #[cfg(feature = "hardening")]
            landlock: &plan.hardening.landlock_labels,
        }
    }
}

/// Resolves a report record's 1-based detail index against a label list; a
/// zero index means the step named no subject.
fn index_label(detail: u32, labels: &[String]) -> Option<String> {
    detail
        .checked_sub(1)
        .and_then(|index| labels.get(index as usize))
        .cloned()
}

/// Maps a reported setup failure onto the public error, attaching the label
/// naming what the step was operating on and identifying the host
/// configuration responsible when namespace creation itself was denied.
fn setup_error(step: SetupStep, errno: i32, detail: u32, labels: Labels<'_>) -> Error {
    // A denied unshare is almost always a host that disables unprivileged
    // user namespaces; report it as such, with the blocking configuration
    // when the probe can identify it.
    if step == SetupStep::Unshare
        && (errno == Errno::PERM.raw_os_error() || errno == Errno::ACCESS.raw_os_error())
    {
        return Error::UsernsUnavailable {
            blocker: host::userns_blocker(),
            source: std::io::Error::from_raw_os_error(errno),
        };
    }
    // Creating a namespace answers `ENOSPC` for a namespace limit and nothing
    // else: one of the per-user counts under `/proc/sys/user`, each charged at
    // every level of user namespace up to the initial one, or the nesting depth
    // of user or PID namespaces. The error names that family rather than
    // leaving a reader with "No space left on device" against a step that
    // touched no filesystem. Only these two steps create namespaces; `ENOSPC`
    // from allocating a terminal means something else, below.
    if matches!(step, SetupStep::Unshare | SetupStep::NestedUnshare)
        && errno == Errno::NOSPC.raw_os_error()
    {
        return Error::NamespaceLimitReached {
            step,
            source: std::io::Error::from_raw_os_error(errno),
        };
    }
    // The fresh session keyring is charged against the calling user's key
    // quota, and `EDQUOT` from creating it is that quota and nothing else, so
    // the error names the sysctls rather than a disk quota the step never
    // touched.
    if step == SetupStep::ReplaceSessionKeyring && errno == Errno::DQUOT.raw_os_error() {
        return Error::KeyQuotaExhausted {
            source: std::io::Error::from_raw_os_error(errno),
        };
    }
    // A procfs for the sandbox's PID namespace is refused `EPERM` where no
    // procfs already mounted is fully visible, as inside a container whose
    // runtime masks its entries. The mount table says which mounts are in the
    // way, and the error names the remedies.
    if step == SetupStep::MountProc && errno == Errno::PERM.raw_os_error() {
        return Error::ProcfsRefused {
            blocker: host::procfs_refusal(),
            source: std::io::Error::from_raw_os_error(errno),
        };
    }
    // The launch stage's move into the sandbox's cgroup is refused for the
    // reasons the cgroup's own preparation is, and is reported as one of them.
    if step == SetupStep::JoinCgroup
        && let Some(parent) = labels.cgroup_parent
        && let Some(reason) = crate::cgroup::join_refusal(Errno::from_raw_os_error(errno))
    {
        return Error::CgroupRefused {
            parent: parent.to_path_buf(),
            reason,
        };
    }
    // A `devpts` instance answers an open of its multiplexer with `ENOSPC` when
    // the host's pseudoterminals are spent, and has no other meaning for it.
    if step == SetupStep::AllocateTerminal && errno == Errno::NOSPC.raw_os_error() {
        return Error::TerminalsExhausted {
            source: std::io::Error::from_raw_os_error(errno),
        };
    }
    // The exec step carries no detail index — there is one command, not a list
    // — so its subject comes from the plan's own label. Every other step with a
    // subject indexes the list it belongs to.
    let detail = match step {
        SetupStep::Exec => Some(labels.exec.to_string()),
        SetupStep::SetRlimit => index_label(detail, labels.rlimits),
        #[cfg(feature = "hardening")]
        SetupStep::LandlockAddRule => index_label(detail, labels.landlock),
        _ => index_label(detail, labels.ops),
    };
    Error::Setup {
        step,
        source: std::io::Error::from_raw_os_error(errno),
        detail,
    }
}

/// What the launch stage's publication of the supervisor delivered to this
/// process.
enum Publication {
    /// The supervisor's pidfd and its host pid.
    Received(OwnedFd, u32),
    /// The supervisor's host pid alone. The stage published the supervisor,
    /// which runs and supervises, but its pidfd did not arrive: the kernel
    /// installs a descriptor passed over a socket only where the receiver has
    /// a number free for it under `RLIMIT_NOFILE` and the system's file limit,
    /// and where no security module refuses it, and otherwise delivers the
    /// message without it. The control socket is then the one way left to
    /// reach the supervisor; see [`end_unreceived`].
    Unreceived(u32),
}

impl Publication {
    /// The supervisor's host pid.
    fn pid(&self) -> u32 {
        match self {
            Publication::Received(_, pid) | Publication::Unreceived(pid) => *pid,
        }
    }
}

/// Receives the supervisor's pidfd and host pid from the launch stage.
///
/// The stage sends one seqpacket message: the pid as four little-endian
/// bytes, with the pidfd attached as `SCM_RIGHTS` ancillary data. A closed
/// socket without the message means the stage exited before publishing, and
/// is [`Error::SupervisorLost`]. A whole message without the pidfd means the
/// stage published it and this process could not receive it, which is
/// [`Publication::Unreceived`].
fn receive_supervisor(sock: &OwnedFd) -> Result<Publication, Error> {
    let mut payload = [0u8; 4];
    let (bytes, pidfd) =
        frame::recv_with_fd(sock.as_fd(), &mut payload).map_err(wait_syscall_error)?;
    if bytes != payload.len() {
        // A short message means the stage died before publishing the
        // supervisor. A descriptor a truncated message still carried is
        // dropped with it here.
        return Err(Error::SupervisorLost);
    }
    let pid = u32::from_le_bytes(payload);
    Ok(match pidfd {
        Some(mut pidfd) => {
            // Kept off a standard number where a number above them is free;
            // see `above_stdio`.
            let _ = above_stdio(&mut pidfd);
            Publication::Received(pidfd, pid)
        }
        None => Publication::Unreceived(pid),
    })
}

/// What the report pipe has said when its reader stops.
enum Report {
    /// End of input with no failure: every process that held a write end
    /// replaced its image or exited without reporting one, so the command is
    /// running.
    ExecSucceeded,
    /// A gated command is at its gate, with every setup step behind it.
    Held,
    /// A stage reported a failed setup step and exited. `detail` is the
    /// 1-based index of the step's subject within its own list, or zero; see
    /// [`Labels`].
    SetupFailed {
        step: SetupStep,
        errno: i32,
        detail: u32,
    },
}

/// Reads the report pipe up to the next record that settles it, appending each
/// created target on the way to `created`.
///
/// The records are the setup's account of itself, in the order it acted: a
/// [`REPORT_CREATED`] record for each file-bind target it created, at most
/// `ops` of them, then a [`REPORT_HELD`] record where the launch is gated, or a
/// failure. Each is shorter than `PIPE_BUF`, so each arrives whole however the
/// writers interleave, and the tag opening it says how long it is.
///
/// A failure is the last thing the pipe carries, since the stage that reports
/// one exits, so the read continues to end of input after it and anything more
/// is a broken protocol. So is a record cut short, a tag this build never
/// writes, or more created targets than the plan has mount ops. Each is an
/// `EPROTO`, which the caller tears the launch down over rather than trusting
/// a report it cannot decode, and none is a panic.
fn read_report(
    fd: &OwnedFd,
    created: &mut Vec<CreatedTarget>,
    ops: usize,
) -> Result<Report, Error> {
    let fd = fd.as_fd();
    let broken = || wait_syscall_error(Errno::PROTO);
    // Inside a record, end of input is a record cut short.
    let rest = |buf: &mut [u8]| match frame::read_full(fd, buf) {
        Ok(()) => Ok(()),
        Err(Errno::PIPE) => Err(broken()),
        Err(errno) => Err(wait_syscall_error(errno)),
    };
    let word = |bytes: &[u8]| u32::from_le_bytes(bytes.try_into().expect("slice length is 4"));
    let wide = |bytes: &[u8]| u64::from_le_bytes(bytes.try_into().expect("slice length is 8"));
    loop {
        // Between records, end of input is the ending the protocol defines.
        let mut tag = [0u8; REPORT_TAG_LEN];
        match frame::read_full_or_short(fd, &mut tag).map_err(wait_syscall_error)? {
            0 => return Ok(Report::ExecSucceeded),
            REPORT_TAG_LEN => {}
            _ => return Err(broken()),
        }
        match u32::from_le_bytes(tag) {
            REPORT_HELD => return Ok(Report::Held),
            REPORT_CREATED => {
                let mut body = [0u8; REPORT_CREATED_LEN - REPORT_TAG_LEN];
                rest(&mut body)?;
                if created.len() >= ops {
                    return Err(broken());
                }
                created.push(CreatedTarget {
                    op: word(&body[0..4]) as usize,
                    ino: wide(&body[4..12]),
                });
            }
            wire => {
                // A step this build never writes is a defect, but the reader
                // still must not panic.
                let step = SetupStep::from_wire(wire).ok_or_else(broken)?;
                let mut body = [0u8; REPORT_FAILURE_LEN - REPORT_TAG_LEN];
                rest(&mut body)?;
                let mut beyond = [0u8; 1];
                if frame::read_full_or_short(fd, &mut beyond).map_err(wait_syscall_error)? != 0 {
                    return Err(broken());
                }
                return Ok(Report::SetupFailed {
                    step,
                    errno: word(&body[0..4]) as i32,
                    detail: word(&body[4..8]),
                });
            }
        }
    }
}

fn spawn_error(errno: Errno) -> Error {
    Error::Spawn {
        source: errno.into(),
    }
}

pub(crate) fn wait_syscall_error(errno: Errno) -> Error {
    Error::Wait {
        source: errno.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a status record carrying no usage.
    fn record(kind: u32, value: i32) -> [u8; STATUS_RECORD_LEN] {
        encode_status(kind, value, None)
    }

    #[test]
    fn a_status_record_decodes_both_kinds() {
        let (exited, usage) =
            decode_status(record(STATUS_EXITED, 42)).expect("a written kind decodes");
        assert_eq!(exited.code(), Some(42));
        assert_eq!(exited.signal(), None);
        assert_eq!(usage, None);

        let (signaled, _) =
            decode_status(record(STATUS_SIGNALED, 9)).expect("a written kind decodes");
        assert_eq!(signaled.code(), None);
        assert_eq!(signaled.signal(), Some(9));
    }

    #[test]
    fn a_status_record_carries_the_usage_through() {
        let usage = sys::children_usage().expect("the usage is read");
        let (status, decoded) = decode_status(encode_status(STATUS_EXITED, 0, Some(&usage)))
            .expect("a written record decodes");
        assert!(status.success());
        let decoded = decoded.expect("the usage was written");
        assert_eq!(
            decoded.user_time,
            Some(Duration::from_micros(usage.utime.micros()))
        );
        assert_eq!(
            decoded.system_time,
            Some(Duration::from_micros(usage.stime.micros()))
        );
        assert_eq!(
            decoded.peak_rss_bytes,
            Some(u64::try_from(usage.maxrss).expect("a size is not negative") * 1024)
        );
    }

    #[test]
    fn an_unknown_usage_flag_decodes_to_nothing() {
        let mut written = record(STATUS_EXITED, 0);
        written[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(decode_status(written).is_none());
    }

    /// Labels with nothing in them but the Landlock rules given.
    fn labels_with_rules(rules: &[String]) -> Labels<'_> {
        #[cfg(not(feature = "hardening"))]
        let _ = rules;
        Labels {
            ops: &[],
            exec: "",
            rlimits: &[],
            cgroup_parent: None,
            #[cfg(feature = "hardening")]
            landlock: rules,
        }
    }

    #[test]
    fn a_refused_cgroup_join_is_reported_as_the_refusal_it_stands_for() {
        let parent = std::path::Path::new("/sys/fs/cgroup/delegated");
        let labels = || Labels {
            cgroup_parent: Some(parent),
            ..labels_with_rules(&[])
        };
        match setup_error(
            SetupStep::JoinCgroup,
            Errno::ACCESS.raw_os_error(),
            0,
            labels(),
        ) {
            Error::CgroupRefused {
                parent: reported,
                reason: crate::CgroupRefusal::CallerOutside,
            } => assert_eq!(reported, parent),
            other => panic!("{other:?}"),
        }
        // An errno no refusal names stays the setup step's failure.
        assert!(matches!(
            setup_error(
                SetupStep::JoinCgroup,
                Errno::NOMEM.raw_os_error(),
                0,
                labels()
            ),
            Error::Setup {
                step: SetupStep::JoinCgroup,
                ..
            }
        ));
    }

    #[test]
    fn a_recognized_exhaustion_keeps_the_errno_it_came_from() {
        use std::error::Error as _;

        for (step, errno) in [
            (SetupStep::Unshare, Errno::NOSPC),
            (SetupStep::NestedUnshare, Errno::NOSPC),
            (SetupStep::ReplaceSessionKeyring, Errno::DQUOT),
            (SetupStep::AllocateTerminal, Errno::NOSPC),
        ] {
            let error = setup_error(step, errno.raw_os_error(), 0, labels_with_rules(&[]));
            match &error {
                Error::NamespaceLimitReached { step: named, .. } => assert_eq!(*named, step),
                Error::KeyQuotaExhausted { .. } | Error::TerminalsExhausted { .. } => {}
                other => panic!("{step:?} is not recognized: {other:?}"),
            }
            let source = error
                .source()
                .and_then(|source| source.downcast_ref::<std::io::Error>())
                .expect("the syscall's error is the source");
            assert_eq!(source.raw_os_error(), Some(errno.raw_os_error()));
        }
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_failed_landlock_rule_is_named_by_its_position() {
        let rules = ["rx on /usr".to_string(), "r on /etc/hostname".to_string()];
        let error = setup_error(
            SetupStep::LandlockAddRule,
            Errno::INVAL.raw_os_error(),
            2,
            labels_with_rules(&rules),
        );
        assert!(
            matches!(&error, Error::Setup { detail: Some(detail), .. } if detail == "r on /etc/hostname"),
            "{error:?}",
        );
    }

    #[test]
    fn a_directory_is_refused_on_every_stream_that_hands_one_over() {
        let dir = crate::scratch::Scratch::new("stream-directory");
        let directory = || -> OwnedFd {
            std::fs::File::open(&*dir)
                .expect("the scratch directory opens")
                .into()
        };
        let file = || -> OwnedFd {
            let path = dir.join("file");
            std::fs::write(&path, b"").expect("the scratch file is writable");
            std::fs::File::open(path)
                .expect("the scratch file opens")
                .into()
        };

        // Inherited, the caller's own descriptor at the stream's number is what
        // the command receives; supplied, the descriptor given.
        let own = directory();
        assert!(matches!(
            refuse_directory("standard input", &StdioPlan::Inherit, own.as_fd()),
            Err(Error::StreamIsDirectory {
                stream: "standard input"
            })
        ));
        let supplied = StdioPlan::Fd(Arc::new(directory()));
        let unrelated = file();
        assert!(matches!(
            refuse_directory("standard output", &supplied, unrelated.as_fd()),
            Err(Error::StreamIsDirectory {
                stream: "standard output"
            })
        ));

        // A null stream hands nothing over, whatever the caller holds, and a
        // file is a stream like any other.
        assert!(refuse_directory("standard error", &StdioPlan::Null, own.as_fd()).is_ok());
        assert!(refuse_directory("standard input", &StdioPlan::Inherit, unrelated.as_fd()).is_ok());
        let file = StdioPlan::Fd(Arc::new(file()));
        assert!(refuse_directory("standard error", &file, own.as_fd()).is_ok());
    }

    #[test]
    fn an_unknown_status_kind_decodes_to_nothing() {
        // The reader turns this into EPROTO rather than panicking: a kind this
        // build never writes is a defect, and a defect must not unwind through
        // the wait.
        assert!(decode_status(record(0, 0)).is_none());
        assert!(decode_status(record(99, 0)).is_none());
    }
}
