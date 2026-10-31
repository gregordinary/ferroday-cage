//! The sandbox launch mechanism: fork, the launch-stage pipes, and the
//! supervisor plumbing.
//!
//! This module is one of the crate's homes of `unsafe`. The unsafe
//! surface here is the process-creation and exec boundary — `fork`,
//! `unshare_unsafe`, `execve`, the signal-state calls, and the descriptor
//! sweep — each with its invariant documented at the call site, and
//! everything after the fork runs in a child process under the constraints
//! documented in [`child`].
//! Every syscall is issued with inline assembly, through rustix's `linux_raw`
//! backend or, for the calls rustix keeps to its runtime module and those it
//! does not wrap, the `syscalls` crate: [`sys`] holds the process-level ones.
//! Neither touches the libc `errno` slot, the allocator, or a lock, which is
//! what keeps the post-fork window async-signal-safe. rustix selects that
//! backend by target and build configuration, not by the mere fact of
//! depending on rustix, so a compile-time guard (below) fails the build on any
//! configuration where rustix would fall back to its libc backend instead.
//!
//! A launch forks a short-lived stage that creates the namespaces and forks
//! the sandbox's long-lived processes (see [`child`] for the full process
//! tree). Four channels connect the caller to them, all created here before
//! the fork:
//!
//! - the **report pipe** carries a failed setup step as one 12-byte record —
//!   step discriminant, errno, detail index, little-endian. A successful
//!   `execve` closes the last write end, so end-of-file means the command is
//!   running.
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
mod child;
mod copyin;
#[cfg(feature = "tarball")]
mod export;
pub(crate) mod frame;
#[cfg(feature = "hardening")]
mod harden;
mod overlay;
mod remove;
pub(crate) mod sys;

#[cfg(feature = "hardening")]
pub(crate) use harden::probe_landlock_abi;

pub(crate) use child::CONTROL_TERMINATE;
// The network stack's tap helper is the one forked child outside this module,
// and it sweeps like every child inside it.
#[cfg(feature = "netstack")]
pub(crate) use child::sweep_fds_keeping;
pub(crate) use copyin::{
    COPY_DIR, COPY_END, COPY_FIFO, COPY_FILE, COPY_LEAVE, COPY_LINK, COPY_SYMLINK, CopyFailure,
    start_copy_in,
};
#[cfg(feature = "tarball")]
pub(crate) use export::{
    ExportStep, FRAME_DIR, FRAME_END, FRAME_ERROR, FRAME_FILE, FRAME_LEAVE, FRAME_SYMLINK,
    StartError, kill_export, start_export,
};
pub(crate) use overlay::{
    OverlayOptionsError, OverlayProbe, overlay_options, probe_overlay_mount, xattr_unsupported,
};
pub(crate) use remove::{RemoveFailure, remove_tree_mapped};

use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;

use rustix::event::{PollFd, PollFlags};
use rustix::fs::RawMode;
use rustix::io::Errno;
use rustix::mount::{MountFlags, MountPropagationFlags};
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use rustix::pipe::{self, PipeFlags};
use rustix::process::Signal;
use rustix::process::{self, Pid, PidfdFlags, WaitId, WaitIdOptions, WaitOptions, WaitStatus};
use rustix::thread::UnshareFlags;

use crate::error::{Error, SetupStep};
use crate::host;
use crate::idmap::{IdMapper, ResolvedMap};
use crate::observer::Progress;
use crate::status::ExitStatus;
use crate::terminal::Terminal;
use sys::Fork;

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

/// How an overlay-rooted cage's root is assembled.
///
/// The base is the read-only lower and [`rootfs_path`](LaunchPlan::rootfs_path)
/// both — the overlay is mounted over the base's own directory — so this
/// carries only the preformatted mount options naming the lower, the disposable
/// upper, and its work directory. Present only when the caller requested an
/// overlay root; a plain cage binds its rootfs onto itself instead.
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
    /// caller's inherited groups.
    pub(crate) groups: Vec<rustix::thread::Gid>,
}

/// The mount targets a launch has to create as empty files in the root, and the
/// writable layer they are created in.
///
/// A file bind needs its target to exist before anything can be mounted onto it,
/// so a root shipping none gets an empty file created. Left behind, that file is
/// content the root did not have — a resolver configuration, an empty binary —
/// which an export carries into whatever is made of the tree. The caller side
/// removes each one after the launch instead: the sandbox owns what it creates.
///
/// Only the targets the caller side can name are listed: one under an earlier
/// mount is created inside that mount rather than in the root, and one the root
/// already ships — an entry of any kind at the path — is not the launch's to
/// remove.
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
    /// it running as root inside. Always `None` in a restriction.
    pub(crate) run_as: Option<RunAsPlan>,
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
    /// The canonicalized rootfs path, validated at build time; empty and
    /// unused in a restriction, which swaps no root.
    ///
    /// The sandbox stage resolves this path anew inside its own mount
    /// namespace: a descriptor opened before `unshare` still references the
    /// original namespace's mounts, and `mount` refuses bind sources and
    /// targets that are not attached in the caller's namespace.
    pub(crate) rootfs_path: CString,
    /// When set, root the cage on an overlay of the rootfs rather than the
    /// rootfs directly: [`rootfs_path`](Self::rootfs_path) is the read-only
    /// lower, and the sandbox stage mounts the overlay over it before the pivot
    /// so writes land in a disposable upper. `None` for a plain rootfs.
    pub(crate) overlay: Option<OverlayPlan>,
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
    /// The frozen hardening plan applied in the command stage before exec.
    /// Present only with the `hardening` feature.
    #[cfg(feature = "hardening")]
    pub(crate) hardening: HardeningPlan,
}

/// A single BPF instruction, the unit of a compiled seccomp program.
///
/// Layout-compatible with the kernel's `struct sock_filter`. A caller
/// building a program with an external compiler passes a `Vec<SockFilter>`
/// through [`SeccompPolicy::Program`](crate::SeccompPolicy::Program).
#[cfg(feature = "hardening")]
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
#[cfg(feature = "hardening")]
const _: () = assert!(size_of::<SockFilter>() == 8);

/// One frozen Landlock grant: an absolute sandbox path and the kernel
/// `LANDLOCK_ACCESS_FS_*` bitmask allowed beneath it. The command stage masks
/// the access to the running kernel's ABI and opens the path after the pivot.
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
    /// The `handled_access_fs` mask the ruleset governs — the full modeled
    /// set, masked to the kernel ABI in the child. Zero when no filesystem
    /// grant applies.
    pub(crate) landlock_handled: u64,
    /// Landlock network grants; an empty list means the ruleset governs no
    /// network access. A ruleset is built when either grant list is non-empty.
    pub(crate) landlock_net: Vec<LandlockNetRule>,
    /// The `handled_access_net` mask the ruleset governs — the full modeled
    /// set, masked to the kernel ABI in the child. Zero when no network grant
    /// applies.
    pub(crate) landlock_net_handled: u64,
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
            && self.seccomp.is_none()
            && self.keep_caps.is_none()
            && !self.set_securebits
    }

    /// Checks that the plan's Landlock grants can be enforced on this host.
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
    /// [`ensure_host_net_enforceable`](Self::ensure_host_net_enforceable) for
    /// the one case a cage must check.
    pub(crate) fn ensure_landlock_enforceable(&self) -> Result<(), crate::error::ConfigError> {
        if self.landlock.is_empty() && self.landlock_net.is_empty() {
            return Ok(());
        }
        let abi = probe_landlock_abi();
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

    /// Checks that a host-network cage's Landlock network grant can be enforced.
    ///
    /// Under [`Network::Host`](crate::Network::Host) there is no network
    /// namespace, so a Landlock network grant is the sandbox's only network
    /// boundary — exactly the restriction fallback's situation for that one
    /// access kind. When the grant is masked away (a kernel below Landlock ABI
    /// 4, or the LSM absent), the command would reach the host network
    /// unrestricted despite the explicit grant; refuse the build instead.
    ///
    /// A cage with no network grant, or one whose network is
    /// [`Isolated`](crate::Network::Isolated) or [`None`](crate::Network::None),
    /// does not need this: the network namespace is the boundary there, and a
    /// masked-away Landlock grant is a best-effort downgrade of additive
    /// hardening. The caller invokes this only on the host-network path.
    pub(crate) fn ensure_host_net_enforceable(&self) -> Result<(), crate::error::ConfigError> {
        if self.landlock_net.is_empty() {
            return Ok(());
        }
        let abi = probe_landlock_abi();
        let unenforceable = match abi {
            None => true,
            Some(abi) => crate::hardening::net_grant_masked_away(self.landlock_net_handled, abi),
        };
        if unenforceable {
            return Err(crate::error::ConfigError::HostNetworkLandlockUnenforceable { abi });
        }
        Ok(())
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
    /// Unlike a mount point directory, it does not outlive the sandbox: see
    /// [`LaunchPlan::managed_placeholders`], which the caller side removes.
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
        /// resolved by the sandbox stage before the pivot, while the host
        /// view is still mounted.
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
const MS_REMOUNT: u32 = 0x20;
/// `MS_MOVE`, kept to rustix's own move call for the same reason.
const MS_MOVE: u32 = 0x2000;

impl MountAction {
    /// The rootfs-relative path this action brings a mount to rest on, and
    /// what arrives there, or `None` for an action that brings none.
    ///
    /// A path under one of these is inside that mount once the action has run,
    /// not in the rootfs directory on the host, which is what decides whether
    /// a target the launch creates has a host path at all. It also decides
    /// what an earlier mount at the same place still shows.
    ///
    /// A raw action is read the way `mount(2)` reads its flags, in the order the
    /// kernel tests them. A remount changes a mount already standing and brings
    /// none. `MS_BIND` binds a tree, whatever else is set. A propagation change
    /// brings none. `MS_MOVE` moves a mount standing elsewhere onto the target,
    /// and anything else mounts a fresh filesystem of the type named.
    pub(crate) fn arrival(&self) -> Option<(&CStr, Arrival)> {
        match self {
            MountAction::Tmpfs { target, .. }
            | MountAction::Procfs { target }
            | MountAction::Devpts { target, .. } => Some((target, Arrival::Fresh)),
            MountAction::Bind { target, .. } => Some((target, Arrival::Tree)),
            MountAction::Raw { target, flags, .. } => {
                let propagation = (MountPropagationFlags::SHARED
                    | MountPropagationFlags::PRIVATE
                    | MountPropagationFlags::DOWNSTREAM
                    | MountPropagationFlags::UNBINDABLE)
                    .bits();
                let flags = flags.bits();
                if flags & MS_REMOUNT != 0 {
                    None
                } else if flags & MountFlags::BIND.bits() != 0 {
                    Some((target, Arrival::Tree))
                } else if flags & propagation != 0 {
                    None
                } else if flags & MS_MOVE != 0 {
                    Some((target, Arrival::Tree))
                } else {
                    Some((target, Arrival::Fresh))
                }
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

/// Decodes the 8-byte status record the supervisor writes.
///
/// `None` for a kind this build never writes, which is a defect in this
/// library: the reader reports it as a broken protocol rather than panicking,
/// the same posture the report decoder takes.
pub(crate) fn decode_status(record: [u8; 8]) -> Option<ExitStatus> {
    let kind = u32::from_le_bytes(record[0..4].try_into().expect("slice length is 4"));
    let value = i32::from_le_bytes(record[4..8].try_into().expect("slice length is 4"));
    match kind {
        STATUS_EXITED => Some(ExitStatus::exited(value)),
        STATUS_SIGNALED => Some(ExitStatus::signaled(value)),
        _ => None,
    }
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
}

/// The caller's ends of a freshly forked launch: the launch stage's pid and
/// every channel the caller keeps, returned by [`fork_launch`] in the parent.
struct ParentSide {
    /// The launch stage (stage A), forked directly from the caller.
    stage_a: Pid,
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

/// The length of a helper child's failure record: a step's wire value then an
/// errno, both little-endian.
pub(super) const RECORD_LEN: usize = 8;

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
/// [`abandon_gated_child`] is how it ends it.
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

/// Ends a child left blocked at its map gate, leaving it to be reaped.
///
/// A child whose map the delegate could not establish is waiting for a go byte
/// that will never come. It holds nothing but its own descriptors and has
/// touched no tree, so killing it is a clean end — and it is the only end
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
/// The reap is separate because it is the caller's, and exactly one caller may
/// perform it: a pid is the kernel's to reuse the moment its status is
/// collected, so a second wait on the same number can collect an unrelated
/// child of this process instead. A caller whose own path already waits calls
/// this; one that returns without waiting calls
/// [`abandon_gated_child`] and has the reap done here.
pub(super) fn kill_gated_child(child: Pid) {
    let _ = process::kill_process(child, Signal::KILL);
}

/// [`kill_gated_child`], and reaps it.
///
/// For a caller that gives up on a child by returning, so nothing further in
/// its own path would collect the status.
pub(super) fn abandon_gated_child(child: Pid) {
    kill_gated_child(child);
    let _ = wait_for_exit(child);
}

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
fn fork_launch(
    plan: &LaunchPlan,
    observe: bool,
    gated: bool,
    terminal: Option<&Terminal>,
) -> Result<ParentSide, Error> {
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

    // The single-identity map lines: root inside is the calling user
    // outside. The kernel requires the mapped outer id to be the writer's
    // effective id, so the lines are formatted from the current euid/egid —
    // captured here, before any fork or unshare, where geteuid still
    // answers with the caller's id. A range-mapped launch writes no lines;
    // its map goes through the delegate against the gated stage.
    let (uid_line, gid_line) = match &plan.identity {
        IdentityPlan::Single => (
            format!("0 {} 1\n", process::geteuid().as_raw()).into_bytes(),
            format!("0 {} 1\n", process::getegid().as_raw()).into_bytes(),
        ),
        IdentityPlan::Ranged { .. } => (Vec::new(), Vec::new()),
    };

    let (report_read, report_write) = pipe::pipe_with(PipeFlags::CLOEXEC).map_err(spawn_error)?;
    let (status_read, status_write) = pipe::pipe_with(PipeFlags::CLOEXEC).map_err(spawn_error)?;
    // Seqpacket keeps the pidfd delivery and each control request a single
    // atomic message.
    let (host_sock, cage_sock) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(spawn_error)?;
    // The map gate, created only when a delegate writes the map: one
    // seqpacket pair carries ready out and go back, the shape the control
    // socket already set.
    let map_gate = if plan.identity.is_ranged() {
        Some(
            rustix::net::socketpair(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )
            .map_err(spawn_error)?,
        )
    } else {
        None
    };
    // One descriptor serves the null stdin disposition and the supervisor's
    // own stdio; opened read-write so it fits both.
    let null = rustix::fs::open(
        c"/dev/null",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(spawn_error)?;
    let (stdout_pipe, stderr_pipe) = if observe {
        (
            Some(pipe::pipe_with(PipeFlags::CLOEXEC).map_err(spawn_error)?),
            Some(pipe::pipe_with(PipeFlags::CLOEXEC).map_err(spawn_error)?),
        )
    } else {
        (None, None)
    };
    // The proceed pipe exists only for a gated launch.
    let proceed = if gated {
        Some(pipe::pipe_with(PipeFlags::CLOEXEC).map_err(spawn_error)?)
    } else {
        None
    };
    // The terminal channel exists only for a terminal launch. The
    // pseudoterminal itself is allocated inside the sandbox, from the
    // `/dev/ptmx` the sandbox sees, so its replica is a node the command can
    // name; only the primary crosses back.
    let terminal_channel = if terminal.is_some() {
        Some(
            rustix::net::socketpair(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )
            .map_err(spawn_error)?,
        )
    } else {
        None
    };

    // SAFETY: the child-process branch only constructs a struct of references
    // on its own stack and runs `child::stage_a`, which performs raw rustix
    // syscalls over the data frozen above — no allocation, no locking, no
    // libc — and never returns: every path ends in `execve` or `exit_group`.
    match unsafe { sys::fork() } {
        Err(errno) => Err(spawn_error(errno)),
        Ok(Fork::Child) => {
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
            };
            child::stage_a(&context)
        }
        Ok(Fork::ParentOf(stage_a)) => {
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
                stage_a,
                host_sock,
                report_read,
                status_read,
                stdout,
                stderr,
                proceed_write,
                map_gate,
                terminal,
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
        (1, Some(primary)) if payload[0] == TERMINAL_BYTE => Ok(Some(primary)),
        _ => Err(wait_syscall_error(Errno::PROTO)),
    }
}

/// Waits for whichever comes first: the primary on the terminal channel, or
/// word on the report pipe, and returns the primary when it came.
///
/// A held launch has no `execve` to wait for, so the report pipe closes only
/// when a stage fails. Watching it beside the channel is what lets a failure
/// before the terminal existed be read at once, rather than when the last copy
/// of the channel's sandbox end happens to close. `None` means the report pipe
/// has something to say, or the channel hung up, and the caller reads the
/// report next.
///
/// The wait has no deadline, deliberately, like the launch's other reads of its
/// own stages: [`read_report`], [`receive_supervisor`], and the identity-map
/// gate in [`establish_identity_map`]. Every end they wait on belongs to a
/// process this launch created, which sends what is awaited or exits, and its
/// exit closes the end. Only a stage blocked in the kernel holds one open, a
/// mount against an unresponsive server for instance, and the launch then
/// waits as long as that mount does.
fn await_primary(channel: &OwnedFd, report: &OwnedFd) -> Result<Option<OwnedFd>, Error> {
    loop {
        let mut fds = [
            PollFd::new(channel, PollFlags::IN),
            PollFd::new(report, PollFlags::IN),
        ];
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(wait_syscall_error(errno)),
        }
        if !fds[0].revents().is_empty() {
            return receive_primary(channel);
        }
        if !fds[1].revents().is_empty() {
            return Ok(None);
        }
    }
}

/// Establishes a range-mapped launch's identity map through its delegate.
///
/// A no-op for the single-identity tier, which carries no gate. For a range
/// tier: waits for stage A's ready byte (sent once it has unshared and
/// swept), applies the resolved map against stage A's pid, and releases the
/// stage with the go byte.
///
/// If stage A dies before signalling ready, the report pipe holds the true
/// cause and is read for it. If the delegate fails, the gate is closed —
/// stage A sees end-of-file and exits, reporting a gate failure it knows the
/// caller will not read — and the delegate's own error is returned: the
/// delegate ran caller-side, so the better diagnostic is already in hand.
fn establish_identity_map(plan: &LaunchPlan, parent: &mut ParentSide) -> Result<(), Error> {
    let Some(gate) = &parent.map_gate else {
        return Ok(());
    };
    let IdentityPlan::Ranged { mapper, map } = &plan.identity else {
        // fork_launch creates the gate only for a ranged plan.
        return Ok(());
    };

    let mut byte = [0u8; 1];
    loop {
        match rustix::io::read(gate, &mut byte) {
            // Stage A is unshared and waiting; the namespace exists.
            Ok(n) if n > 0 => break,
            // End-of-file: stage A died before reaching the gate. The
            // report pipe holds the step that failed.
            Ok(_) => {
                let report = read_report(&parent.report_read);
                let _ = wait_for_exit(parent.stage_a);
                return Err(match report {
                    Ok(Report::SetupFailed {
                        step,
                        errno,
                        detail,
                    }) => setup_error(step, errno, detail, Labels::of(plan)),
                    Ok(Report::ExecSucceeded) => Error::SupervisorLost,
                    Err(err) => err,
                });
            }
            Err(Errno::INTR) => continue,
            Err(errno) => {
                let _ = process::kill_process(parent.stage_a, Signal::KILL);
                let _ = wait_for_exit(parent.stage_a);
                return Err(wait_syscall_error(errno));
            }
        }
    }

    // The map is written against stage A: the process that unshared, so the
    // process whose /proc map files name the new namespace.
    let pid = parent.stage_a.as_raw_nonzero().get() as u32;
    match mapper.apply(pid, map) {
        Ok(()) => {
            // Release the stage. A failed write means it died; the caller's
            // next read on the report or control path reports the outcome.
            let _ = rustix::io::write(gate, &[MAP_GO_BYTE]);
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
            let _ = process::kill_process(parent.stage_a, Signal::KILL);
            parent.map_gate = None;
            let _ = wait_for_exit(parent.stage_a);
            Err(Error::IdentityMap(err))
        }
    }
}

/// Decides how the launch stage is reaped for a command that is now running.
///
/// Without a PID namespace the launch stage stays outside as the command's
/// parent and is reaped by the handle once the status arrives, so it is
/// returned; with one it has already exited and is reaped here, best-effort in
/// case the application reaps child processes of its own.
fn reap_after(pid_namespace: bool, stage_a: Pid) -> Option<OwnedFd> {
    if pid_namespace {
        // The launch stage is short-lived here and reaped now, before its pid
        // could be reused: it is still an un-reaped child at this point.
        let _ = wait_for_exit(stage_a);
        None
    } else {
        // The launch stage outlives spawn here, so the handle reaps it later.
        // Take a pidfd now, while it is still a child, so that deferred reap
        // targets exactly this process rather than a raw pid a concurrent
        // reaper could free and the OS recycle. If it was already reaped,
        // `pidfd_open` fails and there is nothing left to reap.
        process::pidfd_open(stage_a, PidfdFlags::empty()).ok()
    }
}

/// Reaps the process a pidfd refers to, blocking until it exits.
///
/// Immune to pid reuse: the pidfd names the exact process, so unlike a raw
/// `waitpid` this cannot alias a pid a concurrent reaper freed and the OS
/// recycled for another same-parent child.
pub(crate) fn reap_via_pidfd(pidfd: BorrowedFd<'_>) -> Result<(), Errno> {
    frame::retry_on_intr!(process::waitid(WaitId::PidFd(pidfd), WaitIdOptions::EXITED)).map(|_| ())
}

/// Launches the sandbox and blocks until the command is executing.
///
/// Returns once the report pipe settles: end-of-file means every setup step
/// succeeded and `execve` replaced the command process's image, and a record
/// means a step failed and is returned as the typed error. A terminal launch
/// returns the caller's end of the pseudoterminal beside the launched sandbox;
/// every other launch returns `None` for it.
pub(crate) fn spawn(
    plan: &LaunchPlan,
    observe: bool,
    terminal: Option<&Terminal>,
    progress: &mut dyn FnMut(Progress),
) -> Result<(Launched, Option<OwnedFd>), Error> {
    progress(Progress::Launching);
    let mut parent = fork_launch(plan, observe, false, terminal)?;
    // A range map is established before the supervisor is published, so a
    // published sandbox always has a fully mapped user namespace.
    establish_identity_map(plan, &mut parent)?;
    let received = receive_supervisor(&parent.host_sock);
    if received.is_ok() {
        progress(Progress::Supervised);
    }
    let report = read_report(&parent.report_read);

    match (report, received) {
        // The command is running and the supervisor is published. A terminal
        // launch's primary was sent before the command was forked, so it is
        // already waiting on the channel.
        (Ok(Report::ExecSucceeded), Ok((pidfd, pid))) => {
            let primary = match &parent.terminal {
                Some(channel) => match receive_primary(channel) {
                    Ok(Some(primary)) => Some(primary),
                    // The command runs on a terminal nobody holds. That is a
                    // defect in this library rather than a state to hand out,
                    // so the sandbox is torn down with it.
                    outcome => {
                        let _ = process::pidfd_send_signal(&pidfd, Signal::KILL);
                        let _ = wait_for_exit(parent.stage_a);
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
                    reap: reap_after(plan.pid_namespace, parent.stage_a),
                },
                primary,
            ))
        }
        // A setup step failed. Every stage at or below the failure has
        // exited, and a supervisor above it exits as soon as it observes the
        // exit, so the launch stage is reapable.
        (
            Ok(Report::SetupFailed {
                step,
                errno,
                detail,
            }),
            _,
        ) => {
            let _ = wait_for_exit(parent.stage_a);
            Err(setup_error(step, errno, detail, Labels::of(plan)))
        }
        // The report pipe reached end-of-file — every setup step succeeded —
        // but the supervisor was never published: the launch stage exited
        // before sending it.
        (Ok(Report::ExecSucceeded), Err(err)) => {
            let _ = wait_for_exit(parent.stage_a);
            Err(err)
        }
        // The report pipe could not be read. Unsupervisable; tear the launch
        // down rather than leave it running blind.
        (Err(err), received) => {
            if let Ok((pidfd, _)) = received {
                let _ = process::pidfd_send_signal(&pidfd, Signal::KILL);
            }
            let _ = process::kill_process(parent.stage_a, Signal::KILL);
            let _ = wait_for_exit(parent.stage_a);
            Err(err)
        }
    }
}

/// A launched sandbox held at the gate before `execve`, the seam at which a
/// caller attaches a userspace network stack to the sandbox's network
/// namespace.
///
/// The namespaces exist and the supervisor is published, so [`netns_pid`] is a
/// valid target for `/proc/<pid>/ns/net`; the command has not yet run.
/// [`proceed`] releases it, and dropping the handle without proceeding tears
/// the launch down through [`abandon`].
///
/// [`netns_pid`]: PendingLaunch::netns_pid
/// [`proceed`]: PendingLaunch::proceed
/// [`abandon`]: PendingLaunch::abandon
pub(crate) struct PendingLaunch {
    /// The launch stage, reaped at proceed or abandon.
    stage_a: Pid,
    /// Pidfd of the supervisor: the kill handle, and the process whose
    /// network namespace a stack attaches to.
    pidfd: OwnedFd,
    /// The supervisor's host pid, in every sandbox namespace.
    pid: u32,
    /// Caller end of the control socket.
    host_sock: OwnedFd,
    /// Read end of the report pipe, read once the command is released.
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
    /// The mount labels, for naming a setup step that fails after release.
    op_labels: Vec<String>,
    /// The command label, for naming an exec step that fails after release.
    exec_label: String,
    /// The resource-limit labels, for naming an rlimit step that fails after
    /// release.
    rlimit_labels: Vec<String>,
}

/// Launches the sandbox but holds the command at the gate before `execve`,
/// returning once the supervisor is published.
///
/// A setup failure before the supervisor is published (a denied `unshare`, a
/// failed fork) surfaces here as the typed error; a failure after it is
/// deferred to [`PendingLaunch::proceed`], where the report is read.
pub(crate) fn spawn_pending(
    plan: &LaunchPlan,
    observe: bool,
    terminal: Option<&Terminal>,
    progress: &mut dyn FnMut(Progress),
) -> Result<(PendingLaunch, Option<OwnedFd>), Error> {
    progress(Progress::Launching);
    let mut parent = fork_launch(plan, observe, true, terminal)?;
    // The map precedes the supervisor's publication, so by the time the
    // caller holds a Pending, /proc/<pid>/ns/user is fully mapped — the
    // ordering the network stack's helper relies on when it enters the
    // namespace.
    establish_identity_map(plan, &mut parent)?;
    let proceed_write = parent
        .proceed_write
        .expect("a gated launch carries a proceed pipe");

    match receive_supervisor(&parent.host_sock) {
        Ok((pidfd, pid)) => {
            progress(Progress::Supervised);
            // The primary comes back here rather than out of `proceed`: the
            // sandbox allocates the pseudoterminal and sends it before the
            // command reaches the gate, so the caller attaches its network stack
            // and proceeds with the primary already in hand. Nothing writes to
            // the terminal while the launch is held.
            let primary = match &parent.terminal {
                Some(channel) => match await_primary(channel, &parent.report_read) {
                    Ok(Some(primary)) => Some(primary),
                    // A stage failed before the terminal existed, and the report
                    // says which. With the proceed pipe still open no command
                    // has been released, so everything the report can hold is a
                    // failure.
                    Ok(None) => {
                        let report = read_report(&parent.report_read);
                        let _ = process::pidfd_send_signal(&pidfd, Signal::KILL);
                        let _ = wait_for_exit(parent.stage_a);
                        return Err(match report {
                            Ok(Report::SetupFailed {
                                step,
                                errno,
                                detail,
                            }) => setup_error(step, errno, detail, Labels::of(plan)),
                            Ok(Report::ExecSucceeded) => Error::SupervisorLost,
                            Err(err) => err,
                        });
                    }
                    Err(err) => {
                        let _ = process::pidfd_send_signal(&pidfd, Signal::KILL);
                        let _ = wait_for_exit(parent.stage_a);
                        return Err(err);
                    }
                },
                None => None,
            };
            Ok((
                PendingLaunch {
                    stage_a: parent.stage_a,
                    pidfd,
                    pid,
                    host_sock: parent.host_sock,
                    report_read: parent.report_read,
                    status_read: parent.status_read,
                    stdout: parent.stdout,
                    stderr: parent.stderr,
                    proceed_write,
                    pid_namespace: plan.pid_namespace,
                    op_labels: plan.op_labels.clone(),
                    exec_label: plan.exec_label.clone(),
                    rlimit_labels: plan.rlimit_labels.clone(),
                },
                primary,
            ))
        }
        // The supervisor was never published: a setup step failed before the
        // command reached the gate. The child reported it and exited; read
        // the record for the precise cause, then reap the launch stage.
        Err(err) => {
            let report = read_report(&parent.report_read);
            let _ = wait_for_exit(parent.stage_a);
            match report {
                Ok(Report::SetupFailed {
                    step,
                    errno,
                    detail,
                }) => Err(setup_error(step, errno, detail, Labels::of(plan))),
                _ => Err(err),
            }
        }
    }
}

impl PendingLaunch {
    /// The supervisor's host pid: a process in the sandbox's network
    /// namespace, the target for `/proc/<pid>/ns/net`.
    pub(crate) fn netns_pid(&self) -> u32 {
        self.pid
    }

    /// Releases the gated command and blocks until it is executing, returning
    /// the launched sandbox or the typed setup error.
    pub(crate) fn proceed(self, progress: &mut dyn FnMut(Progress)) -> Result<Launched, Error> {
        // Release the command: any byte is the go signal. A failed write means
        // the command process is already gone; the report read below reports
        // the true outcome.
        let _ = rustix::io::write(&self.proceed_write, &[PROCEED_BYTE]);
        drop(self.proceed_write);

        match read_report(&self.report_read) {
            Ok(Report::ExecSucceeded) => {
                progress(Progress::Executing);
                Ok(Launched {
                    pidfd: self.pidfd,
                    pid: self.pid,
                    control: self.host_sock,
                    status: self.status_read,
                    stdout: self.stdout,
                    stderr: self.stderr,
                    reap: reap_after(self.pid_namespace, self.stage_a),
                })
            }
            Ok(Report::SetupFailed {
                step,
                errno,
                detail,
            }) => {
                let _ = wait_for_exit(self.stage_a);
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
                    },
                ))
            }
            Err(err) => {
                let _ = process::pidfd_send_signal(&self.pidfd, Signal::KILL);
                let _ = process::kill_process(self.stage_a, Signal::KILL);
                let _ = wait_for_exit(self.stage_a);
                Err(err)
            }
        }
    }

    /// Tears the pending launch down: kills the supervisor and reaps the
    /// launch stage. The gated command dies with its supervisor — with a PID
    /// namespace the kernel tears the namespace down, and without one the
    /// supervisor pidfd is the command process itself.
    pub(crate) fn abandon(self) {
        let _ = process::pidfd_send_signal(&self.pidfd, Signal::KILL);
        let _ = process::kill_process(self.stage_a, Signal::KILL);
        let _ = wait_for_exit(self.stage_a);
    }
}

/// The caller-side labels that name a failed setup step's subject.
///
/// The report record's detail index selects within whichever list the failed
/// step belongs to — the mount ops for a mount step, the resource limits for
/// the rlimit step — and the exec step has a single subject rather than a
/// list. The sandbox stages never see any of this; it exists so a reported
/// step carries the thing it was operating on.
#[derive(Clone, Copy)]
struct Labels<'a> {
    ops: &'a [String],
    exec: &'a str,
    rlimits: &'a [String],
}

impl<'a> Labels<'a> {
    /// The labels a plan carries.
    fn of(plan: &'a LaunchPlan) -> Labels<'a> {
        Labels {
            ops: &plan.op_labels,
            exec: &plan.exec_label,
            rlimits: &plan.rlimit_labels,
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
    // A user namespace is charged against `user.max_user_namespaces` at every
    // level up to the initial namespace, and a launch holds two. `ENOSPC` from
    // the nested entry is that budget and nothing else — no other setup step
    // reports it — so the error names the sysctl rather than leaving a reader
    // with "No space left on device" against a step that touched no filesystem.
    if step == SetupStep::NestedUnshare && errno == Errno::NOSPC.raw_os_error() {
        return Error::NestedUsernsBudgetExhausted;
    }
    // The fresh session keyring is charged against the calling user's key
    // quota, and `EDQUOT` from creating it is that quota and nothing else, so
    // the error names the sysctls rather than a disk quota the step never
    // touched.
    if step == SetupStep::ReplaceSessionKeyring && errno == Errno::DQUOT.raw_os_error() {
        return Error::KeyQuotaExhausted;
    }
    // A `devpts` instance answers an open of its multiplexer with `ENOSPC` when
    // the host's pseudoterminals are spent, and has no other meaning for it.
    if step == SetupStep::AllocateTerminal && errno == Errno::NOSPC.raw_os_error() {
        return Error::TerminalsExhausted;
    }
    // The exec step carries no detail index — there is one command, not a list
    // — so its subject comes from the plan's own label. Every other step with a
    // subject indexes the list it belongs to.
    let detail = match step {
        SetupStep::Exec => Some(labels.exec.to_string()),
        SetupStep::SetRlimit => index_label(detail, labels.rlimits),
        _ => index_label(detail, labels.ops),
    };
    Error::Setup {
        step,
        source: std::io::Error::from_raw_os_error(errno),
        detail,
    }
}

/// Receives the supervisor's pidfd and host pid from the launch stage.
///
/// The stage sends one seqpacket message: the pid as four little-endian
/// bytes, with the pidfd attached as `SCM_RIGHTS` ancillary data. A closed
/// socket without the message means the stage exited before publishing.
fn receive_supervisor(sock: &OwnedFd) -> Result<(OwnedFd, u32), Error> {
    let mut payload = [0u8; 4];
    let (bytes, pidfd) =
        frame::recv_with_fd(sock.as_fd(), &mut payload).map_err(wait_syscall_error)?;
    // A short message means the stage died before publishing the supervisor.
    // A descriptor a truncated message still carried is dropped with it here.
    match pidfd {
        Some(pidfd) if bytes == payload.len() => Ok((pidfd, u32::from_le_bytes(payload))),
        _ => Err(Error::SupervisorLost),
    }
}

/// The decoded contents of the report pipe.
enum Report {
    /// The pipe closed empty: `execve` succeeded and the command is
    /// running.
    ExecSucceeded,
    /// A stage reported a failed setup step and exited. `detail` is the
    /// 1-based index of the mount op the step belonged to, or zero.
    SetupFailed {
        step: SetupStep,
        errno: i32,
        detail: u32,
    },
}

/// Reads the report pipe to EOF and decodes the record, if any.
///
/// A record is exactly 12 bytes and, being smaller than `PIPE_BUF`, arrives
/// atomically or not at all. Any other length is a broken report protocol,
/// surfaced as an error so the caller tears the launch down rather than
/// trusting a report it cannot decode.
fn read_report(fd: &OwnedFd) -> Result<Report, Error> {
    // One byte beyond the record size: a longer read proves corruption
    // without consuming an unbounded stream.
    let mut buf = [0u8; 13];
    let mut len = 0;
    while len < buf.len() {
        match rustix::io::read(fd, &mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(wait_syscall_error(errno)),
        }
    }
    match len {
        0 => Ok(Report::ExecSucceeded),
        12 => {
            let wire = u32::from_le_bytes(buf[0..4].try_into().expect("slice length is 4"));
            let errno = i32::from_le_bytes(buf[4..8].try_into().expect("slice length is 4"));
            let detail = u32::from_le_bytes(buf[8..12].try_into().expect("slice length is 4"));
            // A step this build never writes is a defect, but the reader
            // still must not panic: EPROTO, as for a malformed length.
            let step =
                SetupStep::from_wire(wire).ok_or_else(|| wait_syscall_error(Errno::PROTO))?;
            Ok(Report::SetupFailed {
                step,
                errno,
                detail,
            })
        }
        // A partial or over-length read: the single-writer protocol was
        // broken. EPROTO, so the failure is typed rather than a panic.
        _ => Err(wait_syscall_error(Errno::PROTO)),
    }
}

/// Waits for a direct child process to terminate, retrying on signal
/// interruption.
pub(crate) fn wait_for_exit(pid: Pid) -> Result<WaitStatus, Errno> {
    match frame::retry_on_intr!(process::waitpid(Some(pid), WaitOptions::empty()))? {
        Some((_, status)) => Ok(status),
        None => unreachable!("ferroday-cage: waitpid without WNOHANG returned no status"),
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

    /// Builds a status record from its two little-endian words.
    fn record(kind: u32, value: i32) -> [u8; 8] {
        let mut record = [0u8; 8];
        record[0..4].copy_from_slice(&kind.to_le_bytes());
        record[4..8].copy_from_slice(&value.to_le_bytes());
        record
    }

    #[test]
    fn a_status_record_decodes_both_kinds() {
        let exited = decode_status(record(STATUS_EXITED, 42)).expect("a written kind decodes");
        assert_eq!(exited.code(), Some(42));
        assert_eq!(exited.signal(), None);

        let signaled = decode_status(record(STATUS_SIGNALED, 9)).expect("a written kind decodes");
        assert_eq!(signaled.code(), None);
        assert_eq!(signaled.signal(), Some(9));
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
