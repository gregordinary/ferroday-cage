//! Typed errors for sandbox configuration, spawn, setup, and wait failures.
//!
//! # Every `Display` here is written out, and none is derived
//!
//! The crate carries roughly 1,100 lines of hand-written `Display` and
//! `source`, one match arm per variant, and a derive macro would remove almost
//! all of it. It is written out on purpose.
//!
//! What these messages are is the reason. Several are three sentences of
//! guidance — what failed, what it was operating on, and what to do about it —
//! and one of them is chosen by a guard rather than by a variant:
//! `CommandNotAbsolute` says something different about a bare name than about
//! a relative path with a slash, and different again to a builder with no path
//! lookup, because path lookup is the remedy for one and misdirection for the
//! others. Attribute strings hold a label well and a paragraph badly, and the
//! paragraph is what a caller acts on.
//!
//! No message repeats its cause. A variant that carries an OS error, or another
//! error of the crate's, returns it from `source()`, and its own message says
//! what failed and what it was operating on and stops there. A wrapper such as
//! [`Error::Config`] is a layer like any other, with a message of its own. A
//! renderer that walks the chain, such as [`ErrorChain`](crate::ErrorChain),
//! then prints each layer once.
//!
//! The cost is real and worth naming: a variant, its message, and its cause sit
//! in three places in this file. What the arrangement buys is that the messages
//! read as prose someone wrote, and that the crate's manifest still justifies
//! every dependency in it — a rendering convenience is not a reason to add a
//! proc macro to a sandbox library's build.
//!
//! The `Io { op, path, source }` shape those errors share *is* declared once,
//! by `failure::path_io_error!`; it is the constructors that were four copies,
//! not the messages.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::cgroup::{CgroupReach, CgroupRefusal};
use crate::host::{ProcfsBlocker, UsernsBlocker};
use crate::spec::{HOST_ROOT_HIDDEN, is_command_name};
use crate::wire::wire_enum;

wire_enum! {
    /// A step of the sandbox setup sequence, performed in the child process.
    ///
    /// When a setup step fails inside the sandbox process, the failure is
    /// reported to the caller as [`Error::Setup`], naming the step and the
    /// `errno` the kernel returned.
    ///
    /// The explicit discriminants are the wire encoding of the setup-error
    /// pipe, which both ends of a single build write and read. They are an
    /// implementation detail: a step inserted in a later release renumbers the
    /// ones after it, and no discriminant is guaranteed to denote the same step
    /// across versions. Do not persist, transmit, or compare them — match on
    /// the variant, and use [`Display`](std::fmt::Display) for a human-readable
    /// name.
    #[non_exhaustive]
    pub enum SetupStep {
        /// Unshare into the new namespaces.
        Unshare = 1 => "unsharing the namespaces",
        /// Write `deny` to `/proc/self/setgroups`.
        DenySetgroups = 2 => "denying setgroups",
        /// Write the single-identity gid map.
        WriteGidMap = 3 => "writing the gid map",
        /// Write the single-identity uid map.
        WriteUidMap = 4 => "writing the uid map",
        /// Set the sandbox hostname.
        SetHostname = 5 => "setting the hostname",
        /// Bring up the loopback interface in the isolated network namespace.
        ConfigureLoopback = 6 => "bringing up the loopback interface",
        /// Make mount propagation recursively private.
        PrivatizeMounts = 7 => "making mount propagation private",
        /// Bind the rootfs onto itself so it becomes a mount point.
        BindRootfs = 8 => "binding the rootfs onto itself",
        /// Enter the rootfs mount point.
        EnterRootfs = 9 => "entering the rootfs mount point",
        /// Create a missing mount target inside the rootfs.
        CreateMountTarget = 10 => "creating a mount target",
        /// Open a mount target inside the rootfs.
        OpenMountTarget = 11 => "opening a mount target",
        /// Mount a tmpfs.
        MountTmpfs = 12 => "mounting a tmpfs",
        /// Mount a devpts instance.
        MountDevpts = 13 => "mounting devpts",
        /// Bind-mount a host path into the rootfs.
        BindMount = 14 => "bind-mounting",
        /// Remount a bind mount read-only.
        RemountReadOnly = 15 => "remounting a bind mount read-only",
        /// Create a symlink inside the rootfs.
        CreateSymlink = 16 => "creating a symlink",
        /// Pivot the root into the rootfs.
        PivotRoot = 17 => "pivoting into the rootfs",
        /// Lazily detach the old root mount.
        DetachOldRoot = 18 => "detaching the old root",
        /// Change directory to the new root.
        ChdirNewRoot = 19 => "changing to the new root directory",
        /// Change to the configured working directory.
        ChdirWorkdir = 20 => "changing to the working directory",
        /// Execute the command.
        Exec = 21 => "executing the command",
        /// Reset the inherited signal dispositions and mask.
        ResetSignals = 22 => "resetting the inherited signal state",
        /// Fork the sandbox init process.
        ForkInit = 23 => "forking the sandbox init process",
        /// Send the supervisor's pidfd back to the caller.
        SendPidfd = 24 => "publishing the supervisor pidfd",
        /// Mount a fresh procfs instance.
        MountProc = 25 => "mounting a fresh procfs",
        /// Perform a raw mount.
        MountRaw = 26 => "performing a raw mount",
        /// Sweep inherited file descriptors, having first held each standard
        /// stream number the caller left closed.
        SweepFds = 27 => "sweeping inherited file descriptors",
        /// Fork the command process.
        ForkCommand = 28 => "forking the command process",
        /// Open the descriptors the supervisor watches the command through: a
        /// pidfd for the command, and the descriptor its children's `SIGCHLD`
        /// arrives on.
        WatchCommand = 29 => "opening the descriptors the supervisor watches the command through",
        /// Wire the command's standard streams.
        WireStdio = 30 => "wiring the command's standard streams",
        /// Drop or reduce the command's capabilities.
        DropCapabilities = 31 => "dropping capabilities",
        /// Set the no-new-privileges flag before restricting the command.
        SetNoNewPrivs = 32 => "setting the no-new-privileges flag",
        /// Create the Landlock ruleset.
        LandlockCreateRuleset = 33 => "creating the Landlock ruleset",
        /// Add a rule to the Landlock ruleset.
        LandlockAddRule = 34 => "adding a Landlock rule",
        /// Enforce the Landlock ruleset on the command.
        LandlockRestrictSelf = 35 => "enforcing the Landlock ruleset",
        /// Install the seccomp filter.
        InstallSeccomp = 36 => "installing the seccomp filter",
        /// Wait at the launch gate for the caller to attach a network stack and
        /// release the command.
        AwaitNetworkStack = 37 => "waiting for the network stack to attach",
        /// Wait for the caller's delegate to establish the identity map.
        AwaitIdentityMap = 38 => "waiting for the identity map to be established",
        /// Lock the securebits that preserve capabilities across the identity
        /// switch.
        SetSecurebits = 39 => "locking the securebits for the identity switch",
        /// Set the command's supplementary groups.
        SetGroups = 40 => "setting the supplementary groups",
        /// Switch to the command's gid.
        SetGid = 41 => "switching to the command gid",
        /// Switch to the command's uid.
        SetUid = 42 => "switching to the command uid",
        /// Mount the overlay that roots an overlay-rooted cage.
        MountOverlayRoot = 43 => "mounting the overlay root",
        /// Apply a resource limit to the command.
        SetRlimit = 44 => "applying a resource limit",
        /// Start the sandbox's own session, detaching it from the caller's
        /// controlling terminal.
        NewSession = 45 => "starting the sandbox's own session",
        /// Make the launch's pseudoterminal the controlling terminal of the
        /// sandbox's session.
        SetControllingTerminal = 46 => "making the sandbox's pseudoterminal its controlling terminal",
        /// Enter the nested user namespace that locks the sandbox's mount flags.
        NestedUnshare = 47 => "entering the nested user namespace",
        /// Write `deny` to the nested user namespace's `setgroups`.
        NestedDenySetgroups = 48 => "denying setgroups in the nested user namespace",
        /// Write the nested user namespace's gid map.
        NestedWriteGidMap = 49 => "writing the nested user namespace's gid map",
        /// Write the nested user namespace's uid map.
        NestedWriteUidMap = 50 => "writing the nested user namespace's uid map",
        /// Wait for the sandbox's own delegate to establish the nested user
        /// namespace's identity map.
        AwaitNestedIdentityMap = 51 => "waiting for the nested identity map to be established",
        /// Open the procfs the nested user namespace's identity map is
        /// established through.
        OpenSandboxProcfs = 52 => "opening the procfs the nested identity map is established through",
        /// Create or operate the gate the nested identity map is established
        /// across.
        NestedMapGate = 53 => "operating the nested identity-map gate",
        /// Mark the sandbox's root mount `nosuid`.
        NosuidRootfs = 54 => "marking the root mount nosuid",
        /// Give the sandbox a session keyring of its own, in place of the one
        /// the caller's session carries, or, where the kernel refuses that,
        /// install the filter that refuses the sandbox the key syscalls.
        ReplaceSessionKeyring = 55 => "replacing the inherited session keyring",
        /// Allocate the sandbox's pseudoterminal from the `/dev/ptmx` the
        /// sandbox sees, and establish its size and line discipline.
        AllocateTerminal = 56 => "allocating the sandbox's pseudoterminal",
        /// Hand the primary of the sandbox's pseudoterminal back to the caller.
        SendTerminal = 57 => "handing the sandbox's pseudoterminal to the caller",
        /// Install the seccomp filter a sandbox with a network namespace of its
        /// own carries, which refuses the routes out that the namespace does
        /// not cover. See [`Network::Isolated`](crate::Network::Isolated).
        InstallNetworkFilter = 58 => "installing the network namespace's seccomp filter",
        /// Mount the tmpfs an empty root is made of, on top of the sandbox's
        /// inherited root. See [`CageBuilder::empty_rootfs`](crate::CageBuilder::empty_rootfs).
        MountEmptyRoot = 59 => "mounting the empty root",
        /// Make an empty root read-only once the mount profile is in place.
        ReadOnlyEmptyRoot = 60 => "making the empty root read-only",
        /// Move a sandbox that keeps the caller's session into a process group
        /// of its own, out of the caller's.
        NewProcessGroup = 61 => "moving the sandbox into a process group of its own",
        /// Make the sandbox's process group the foreground of the caller's
        /// terminal, which the caller lends it for the launch.
        TakeForeground = 62 => "giving the sandbox's process group the terminal's foreground",
        /// Wait for the launch stage to exit before the command is forked,
        /// where the sandbox has a process group of its own in the caller's
        /// session.
        AwaitLaunchStage = 63 => "waiting for the launch stage to exit",
        /// Clone the host's mount tree as the sandbox's root and make every
        /// mount of it read-only; see
        /// [`CageBuilder::host_rootfs`](crate::CageBuilder::host_rootfs).
        MountHostRoot = 64 => "mounting the host's root, read-only",
        /// Hide a path; see [`CageBuilder::hide`](crate::CageBuilder::hide).
        HidePath = 65 => "hiding a path",
        /// Make a path read-only where it stands; see
        /// [`CageBuilder::read_only`](crate::CageBuilder::read_only).
        ReadOnlyPath = 66 => "making a path read-only",
        /// Move the launch stage into the sandbox's cgroup, through the
        /// `cgroup.procs` the caller opened, before any namespace is created.
        JoinCgroup = 67 => "joining the sandbox's cgroup",
    }
}

/// Which directory of an overlay root a failure names.
///
/// Every layer is the caller's to place, and each must exist and be resolvable
/// before the mount, so a failure preparing one has to say which it was. The
/// rootfs is the overlay's first lower and keeps its own
/// [`RootfsUnusable`](ConfigError::RootfsUnusable) reporting; `Lower` names the
/// stacked layers beneath it, except in an
/// [`OverlayLayersOverlap`](ConfigError::OverlayLayersOverlap), where it names
/// any lower, the rootfs included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OverlayLayer {
    /// A lower layer stacked beneath the rootfs: read-only, contributing files
    /// the merge shows through.
    Lower,
    /// The upper layer: where the sandbox's writes land.
    Upper,
    /// The work directory the overlay uses for its own bookkeeping.
    Work,
}

impl fmt::Display for OverlayLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OverlayLayer::Lower => "lower",
            OverlayLayer::Upper => "upper",
            OverlayLayer::Work => "work",
        })
    }
}

/// A sandbox configuration rejected by [`CageBuilder::build`].
///
/// [`CageBuilder::build`]: crate::CageBuilder::build
#[derive(Debug)]
#[non_exhaustive]
pub enum ConfigError {
    /// No root was provided: no rootfs, no overlay, no empty root, and not the
    /// host's own root.
    RootfsMissing,
    /// More than one of a plain rootfs, an overlay root, an empty root, and the
    /// host's own root was configured, where exactly one root can be in force.
    ///
    /// The builder's setters keep them exclusive — each of [`rootfs`],
    /// [`overlay`], [`empty_rootfs`], and [`host_rootfs`] clears the others —
    /// so this arises from a profile that carries more than one of their keys.
    /// Honoring one silently would discard the others' configuration.
    ///
    /// [`rootfs`]: crate::CageBuilder::rootfs
    /// [`overlay`]: crate::CageBuilder::overlay
    /// [`empty_rootfs`]: crate::CageBuilder::empty_rootfs
    /// [`host_rootfs`]: crate::CageBuilder::host_rootfs
    RootContradiction,
    /// The rootfs path could not be resolved and opened as a directory.
    #[non_exhaustive]
    RootfsUnusable {
        /// The rootfs path as it was given to the builder.
        path: PathBuf,
        /// The error encountered while resolving or opening it.
        source: io::Error,
    },
    /// The rootfs resolves to the host root directory.
    RootfsIsHostRoot,
    /// No command was provided, or the path given names nothing.
    ///
    /// An empty path is the second: it is not a command that could not be
    /// found, it is the absence of one written down. Every later check reads it
    /// as something else — it carries no slash, so a path lookup takes it for a
    /// bare name and joining it onto a `PATH` entry yields that entry — so it is
    /// refused where the command is read rather than deferred to an `execve` of
    /// a directory.
    CommandMissing,
    /// The command path is not absolute.
    ///
    /// The message names the remedy that fits: a bare command name — the most
    /// common form of this mistake — is resolvable with
    /// [`path_lookup`](crate::CageBuilder::path_lookup) where the builder
    /// offers it, while a relative path is never searched and must be made
    /// absolute. That includes `.` and `..`, which carry no slash but name
    /// directories rather than commands.
    #[non_exhaustive]
    CommandNotAbsolute {
        /// The command path as it was given to the builder.
        command: PathBuf,
        /// Whether the builder that refused it resolves a bare name by path
        /// lookup: `true` for a [`CageBuilder`](crate::CageBuilder), and
        /// `false` for a restriction, which never searches `PATH`.
        lookup_offered: bool,
    },
    /// The managed mount profile was opted out of, while one of its mounts was
    /// explicitly asked for. The two cannot both be honored.
    #[non_exhaustive]
    ManagedMountsContradiction {
        /// The builder method naming the mount that was explicitly requested.
        toggle: &'static str,
    },
    /// Path lookup was requested, but the `PATH` in force holds no absolute
    /// directory to search, so the command could not resolve to any candidate.
    #[non_exhaustive]
    SearchPathUnusable {
        /// The `PATH` the lookup would have searched.
        path: std::ffi::OsString,
    },
    /// A bind-mount source could not be resolved on the host.
    #[non_exhaustive]
    BindSourceUnusable {
        /// The source path as it was given to the builder.
        path: PathBuf,
        /// The error encountered while resolving it.
        source: io::Error,
    },
    /// A mount target is not a normal absolute path inside the rootfs.
    ///
    /// A bind or raw-mount target, and a symlink's path, must be absolute, must
    /// not be `/` itself, and must not contain a `..` component. A `.`
    /// component names the directory it is in, and is dropped.
    #[non_exhaustive]
    MountTargetInvalid {
        /// The target path as it was given to the builder.
        path: PathBuf,
    },
    /// A symbolic link's target is empty, or too long for a path.
    #[non_exhaustive]
    SymlinkTargetInvalid {
        /// The link's path inside the sandbox, as it was given to the builder.
        path: PathBuf,
        /// The target as it was given to the builder.
        target: PathBuf,
    },
    /// A raw mount's flags do not fit the kernel's mount-flags word.
    #[non_exhaustive]
    MountFlagsInvalid {
        /// The raw mount's target, as it was given to the builder.
        target: PathBuf,
        /// The flags as they were given to the builder.
        flags: u64,
    },
    /// The working directory is not a normal absolute path: it is relative, or
    /// has a component other than a plain name, such as `..`.
    #[non_exhaustive]
    WorkdirNotAbsolute {
        /// The working directory as it was given to the builder.
        path: PathBuf,
    },
    /// The hostname is empty, longer than 64 bytes, or contains a NUL byte.
    #[non_exhaustive]
    HostnameInvalid {
        /// The hostname as it was given to the builder.
        name: std::ffi::OsString,
    },
    /// An environment variable name is empty, contains `=`, or contains a NUL
    /// byte.
    #[non_exhaustive]
    EnvNameInvalid {
        /// The offending variable name.
        name: std::ffi::OsString,
    },
    /// A configured path, argument, or value contains an interior NUL byte,
    /// which nothing the kernel is handed can carry.
    ///
    /// A hostname and an environment variable's name are reported by their own
    /// variants, [`HostnameInvalid`](Self::HostnameInvalid) and
    /// [`EnvNameInvalid`](Self::EnvNameInvalid).
    #[non_exhaustive]
    EmbeddedNul {
        /// The configured value holding the NUL, as it was given.
        value: std::ffi::OsString,
    },
    /// A seccomp policy could not be compiled into a BPF program.
    #[non_exhaustive]
    SeccompInvalid {
        /// What the compiler reported.
        reason: String,
    },
    /// Seccomp filtering is not available for the host architecture.
    #[non_exhaustive]
    SeccompUnsupportedArch {
        /// The host architecture, as `std::env::consts::ARCH` reports it.
        arch: String,
    },
    /// A seccomp program is longer than the kernel's instruction ceiling.
    ///
    /// The kernel accepts a classic BPF filter of at most `BPF_MAXINSNS`
    /// (4096) instructions. A precompiled `SeccompPolicy::Program` escape
    /// hatch that exceeds it is rejected here rather than being silently
    /// truncated when the filter is installed.
    #[non_exhaustive]
    SeccompProgramTooLong {
        /// The program's instruction count.
        len: usize,
        /// The kernel's maximum instruction count.
        max: usize,
    },
    /// A Landlock grant path is not a normal absolute path.
    ///
    /// A grant path must be absolute and must not contain a `..` component. A
    /// `.` component names the directory it is in, and is accepted. In a cage
    /// it is a sandbox path, resolved after the pivot; in a restriction it is a
    /// host path.
    #[non_exhaustive]
    LandlockPathInvalid {
        /// The grant path as it was given to the builder.
        path: PathBuf,
    },
    /// A Landlock grant names no access at all.
    ///
    /// An empty access set is not "grant nothing here": enrolling any grant
    /// denies everything ungranted, and the kernel skips a rule that permits
    /// nothing — so an empty grant is a total denial of the class it belongs
    /// to. That is never what an author means by naming a path or a port, so
    /// it is refused rather than silently applied.
    #[non_exhaustive]
    LandlockGrantEmpty {
        /// The grant as it was written: the path of a filesystem grant, or
        /// `tcp:<port>` for a network grant.
        grant: String,
    },
    /// A restriction names no Landlock grant and no seccomp policy.
    ///
    /// A restriction exists to confine the command; with nothing to enforce
    /// it would launch a plain process while appearing to sandbox it, so an
    /// empty restriction is rejected instead.
    RestrictionEmpty,
    /// A restriction's Landlock grants cannot be enforced on this host.
    ///
    /// A restriction is confined only by what the running kernel enforces, so
    /// its build refuses a grant the kernel would drop rather than launch
    /// without it. That is every Landlock grant where the Landlock LSM is
    /// absent, and every network grant on a kernel below ABI 4, whatever
    /// filesystem grants accompany it. A sandbox in the same case keeps its
    /// namespace isolation, so this is specific to the restriction fallback;
    /// a network stack attaching to such a sandbox refuses the grant itself.
    #[non_exhaustive]
    RestrictionLandlockUnenforceable {
        /// The kernel's supported Landlock ABI, or `None` when the LSM is
        /// absent.
        abi: Option<i32>,
    },
    /// A host-network cage requests a Landlock network grant the kernel cannot
    /// enforce.
    ///
    /// Under [`Network::Host`](crate::Network::Host) there is no network
    /// namespace, so a Landlock network grant is the only network boundary.
    /// When the kernel's Landlock ABI is below 4 (network rights first appear
    /// there) or the LSM is absent, the grant governs nothing and the command
    /// would reach the host network unrestricted, so the build is refused. A
    /// [`Isolated`](crate::Network::Isolated) or [`None`](crate::Network::None)
    /// cage builds: its network namespace remains the boundary until a network
    /// stack attaches, and the attachment is where such a grant is refused.
    #[non_exhaustive]
    HostNetworkLandlockUnenforceable {
        /// The kernel's supported Landlock ABI, or `None` when the LSM is
        /// absent.
        abi: Option<i32>,
    },
    /// A Landlock scope that is the only bound on its reach cannot be enforced
    /// on this host.
    ///
    /// A sandbox's namespaces bound the reaches the scopes confine: a PID
    /// namespace hides the host's processes from a signal, and a network
    /// namespace hides the host's abstract sockets. Where none stands behind a
    /// requested scope, the scope is the boundary, and the build is refused on
    /// a kernel that cannot enforce it: one below Landlock ABI 6, or one without
    /// the LSM. That is `signal` under
    /// [`pid_namespace(false)`](crate::CageBuilder::pid_namespace),
    /// `abstract-unix-socket` under [`Network::Host`](crate::Network::Host),
    /// and any scope a restriction names explicitly. A restriction's default
    /// scopes are dropped on such a kernel instead.
    #[non_exhaustive]
    LandlockScopeUnenforceable {
        /// The scope, as a profile names it: `signal` or
        /// `abstract-unix-socket`.
        scope: &'static str,
        /// The kernel's supported Landlock ABI, or `None` when the LSM is
        /// absent.
        abi: Option<i32>,
    },
    /// A profile loaded under the restricted policy uses an operation only a
    /// trusted profile may.
    ///
    /// Deserializing a profile straight into a `CageBuilder` trusts it as
    /// code-equivalent configuration. A profile from an untrusted source is
    /// loaded under the restricted policy instead.
    // The paragraph links a feature-gated item, so its doc text is gated on the
    // feature: present in the canonical all-features build, absent — link and
    // all — from a build without `serde`, where no profile is loaded at all.
    #[cfg_attr(
        feature = "serde",
        doc = "
[`RestrictedProfile`](crate::RestrictedProfile) lists what the policy refuses,
in the words `operation` names it by.

Returned by [`RestrictedProfile::try_from`](crate::RestrictedProfile) on a
[`CageBuilder`](crate::CageBuilder). Deserializing a `RestrictedProfile`
directly reports the same refusal through the serde format's own error,
rendered as text.
"
    )]
    #[non_exhaustive]
    ProfileOperationForbidden {
        /// The forbidden operation, as a short phrase.
        operation: &'static str,
    },
    /// A launch attaches a conduit to a standard stream the sandbox was built
    /// to send somewhere else.
    ///
    /// [`Stdio::Inherit`](crate::Stdio::Inherit) states no destination, so a
    /// launch is free to supply one and this never arises against it.
    /// [`Stdio::Null`](crate::Stdio::Null) and
    /// [`Stdio::from_fd`](crate::Stdio::from_fd) state one, and a launch that
    /// would supply its own is refused rather than silently overriding what the
    /// caller said. Two launches supply one: an [`Observer`](crate::Observer)'s
    /// capture pipes, on the output pair, and a terminal launch's
    /// pseudoterminal replica, on all three at once.
    ///
    /// Reported by the launch rather than by
    /// [`build`](crate::CageBuilder::build): the contradiction is between the
    /// frozen sandbox and one particular launch of it, and the same sandbox
    /// launches without contradiction through an entry point that attaches
    /// nothing.
    #[non_exhaustive]
    StreamAttachmentConflict {
        /// The stream whose disposition the attachment contradicts, as a short
        /// phrase — `"standard input"`, `"standard output"`, or
        /// `"standard error"`.
        stream: &'static str,
        /// What the launch attaches to it, as a short phrase.
        attachment: &'static str,
    },
    /// An identity map's ranges are structurally invalid.
    ///
    /// The kernel's rules are enforced here so an unwritable map is a typed
    /// configuration error: both lists non-empty, inside-id 0 mapped, no
    /// zero-count or wrapping extents, no overlaps, and at most 340 extents.
    #[non_exhaustive]
    IdentityMapInvalid {
        /// What makes the map unwritable.
        reason: String,
    },
    /// No identity-map delegate can satisfy the requested range map.
    ///
    /// The fallback is between delegates, never between tiers: a range
    /// request that no delegate can establish is refused rather than
    /// silently downgraded to the single-identity map. The reason carries
    /// each delegate's refusal. The subordinate delegate refuses a host its
    /// helpers cannot work on with the condition
    /// [`host::range_map_blocker`](crate::host::range_map_blocker) names.
    #[non_exhaustive]
    IdentityMapUnavailable {
        /// Why each delegate refused, each refusal rendered with its causes.
        ///
        /// The message includes it only for the bundled chain. A configured
        /// delegate's refusal is the `source`, which a renderer reaches on its
        /// own, so repeating it here would print it twice.
        reason: String,
        /// The refusal of the delegate configured with
        /// [`id_mapper`](crate::CageBuilder::id_mapper), which is the whole
        /// chain when one is configured. `None` for the bundled chain, whose
        /// `reason` collects a refusal from each of its delegates.
        source: Option<crate::IdMapError>,
    },
    /// A run-as id is not contained in a range identity map.
    ///
    /// Every id the command runs as must be representable in the sandbox's
    /// user namespace, and a range map contains what its extents say. The
    /// single-identity map's case is
    /// [`RunAsOutsideSingleMap`](Self::RunAsOutsideSingleMap).
    #[non_exhaustive]
    RunAsUnmapped {
        /// The unmapped id.
        id: u32,
        /// Which id it is: `"uid"`, `"gid"`, or `"supplementary group"`.
        space: &'static str,
    },
    /// A run-as id is not the single-identity map's one id.
    ///
    /// That map holds one id, the caller, which the command sees as uid and
    /// gid 0, or as the identity [`present_as`](crate::CageBuilder::present_as)
    /// names. There is no other id to switch to. Presenting the caller as an
    /// id is how the command runs as it under this map.
    #[non_exhaustive]
    RunAsOutsideSingleMap {
        /// The run-as id.
        id: u32,
        /// Which id it is: `"uid"` or `"gid"`.
        space: &'static str,
        /// The id the command sees the caller as, in the same space.
        presented: u32,
    },
    /// A presented identity is configured with a range identity map.
    ///
    /// [`present_as`](crate::CageBuilder::present_as) changes which id the
    /// single-identity map's one id, the caller, appears as. A range map has
    /// ids of its own, and [`run_as`](crate::CageBuilder::run_as) switches the
    /// command to one of them.
    PresentAsWithRangeMap,
    /// A presented identity's uid is 0.
    ///
    /// The command runs as the presented uid in a user namespace it is the
    /// creator of, so uid 0 there is root inside the sandbox with every
    /// capability across its `execve`, which is what a sandbox with no
    /// presented identity already gives it. [`PresentedIdentity::Own`]
    /// resolves to 0 for a caller that is the host's root. A presented gid of 0
    /// carries no capability and is accepted.
    ///
    /// [`PresentedIdentity::Own`]: crate::PresentedIdentity::Own
    #[non_exhaustive]
    PresentAsRoot {
        /// The presented identity as it was configured.
        identity: crate::PresentedIdentity,
    },
    /// A run-as identity names supplementary groups under the
    /// single-identity map's gid map: the caller's own gid alone.
    ///
    /// The single-identity map has that gid map, and so does a range map whose
    /// gid list is that one extent. Establishing it without privilege over the
    /// parent namespace denies `setgroups`, as the kernel and the shadow
    /// helpers do, so no group list can be set inside it. Supplementary groups
    /// need a gid map that maps more than the caller's own gid.
    RunAsGroupsWithSingleMap,
    /// The profile mounts no procfs the nested user namespace's identity map
    /// can be established through.
    ///
    /// Every container enters a nested user namespace before it hardens, which
    /// is what locks the flags of the mounts it inherited — without it the
    /// command is root of the namespace those mounts belong to and may lift any
    /// restriction they carry. Establishing that namespace's map reaches for a
    /// procfs by path from inside the sandbox, so a sandbox with no procfs has
    /// no way to establish one.
    ///
    /// The map files are written, and named from a procfs's root, so a procfs
    /// that cannot take the write does not count. That is one that ends up
    /// read-only, through a read-only bind, `MS_RDONLY` on a raw mount, a later
    /// read-only remount, a path made read-only at or above it, or a source
    /// mounted read-only, which
    /// [`NestedUsernsProcfsReadOnly`](Self::NestedUsernsProcfsReadOnly) reports
    /// where it is the only reason. It is also a bind of a
    /// tree inside a procfs, such as `/proc/sys`, rather than of its root.
    ///
    /// Reachable only from a profile that opts out of the managed mounts with
    /// [`managed_mounts(false)`](crate::CageBuilder::managed_mounts) (or
    /// [`mount_proc(false)`](crate::CageBuilder::mount_proc)) and mounts no
    /// procfs of its own, and then only where the map's route reads one. The
    /// single-identity map's command writes its own map files, and a bind of
    /// the host's procfs serves it — every instance resolves `self` for its
    /// reader. A range [`identity_map`](crate::CageBuilder::identity_map) is
    /// written by a delegate, and where the sandbox has a PID namespace that
    /// delegate is inside it and needs a *fresh* procfs, since it names the
    /// command by an in-namespace pid a bound procfs does not index. Where the
    /// sandbox has no PID namespace the delegate is outside it and reads the
    /// host's own `/proc`, so no procfs is required at all.
    NestedUsernsNeedsProcfs,
    /// A retained set-id capability alongside a non-root run-as identity.
    ///
    /// The securebits that preserve kept capabilities across the identity
    /// switch also mean a command holding `CAP_SETUID`, `CAP_SETGID`, or
    /// `CAP_SETPCAP` could return to the mapped uid 0, making the non-root
    /// identity no boundary at all. The combination is rejected by name
    /// rather than shipped as a claim the configuration does not keep.
    #[non_exhaustive]
    SetidCapWithNonRootIdentity {
        /// The offending capability.
        capability: &'static str,
    },
    /// An overlay-root path holds a character the overlay mount options cannot
    /// carry: a `,`.
    ///
    /// The lower, upper, and work directories are passed to the kernel in one
    /// comma-separated option string. A `\` or a `:` in a layer path is escaped
    /// there, but a comma is not one every reader of the string honours an
    /// escape for: a security module that takes its own options out of the same
    /// string splits it at every comma first. Such a path is refused rather than
    /// mounted as something else.
    #[non_exhaustive]
    OverlayPathInvalid {
        /// The offending path.
        path: PathBuf,
    },
    /// An overlay root's mount options are longer than the kernel passes on
    /// whole.
    ///
    /// The options name every layer by its absolute path, and `mount(2)` cuts
    /// its data at one page rather than refusing a longer string. A cut string
    /// still mounts whenever what is left names directories that exist, which
    /// is a different overlay from the one configured, so a stack whose paths
    /// do not fit is refused. Fewer lowers, or shorter paths to them, fit.
    #[non_exhaustive]
    OverlayOptionsTooLong {
        /// The length of the composed options, in bytes.
        length: usize,
    },
    /// An overlay root names no lower layer.
    ///
    /// The first lower is the base the overlay mounts over — the sandbox's root
    /// filesystem — so an overlay carrying only an upper has nothing to merge;
    /// [`Overlay::lower`](crate::Overlay::lower) is required.
    OverlayLowerMissing,
    /// An overlay root names no upper layer.
    ///
    /// An overlay with only lowers is a read-only merge; the sandbox needs
    /// somewhere for its writes to land, so
    /// [`Overlay::upper`](crate::Overlay::upper) is required.
    OverlayUpperMissing,
    /// An overlay layer directory could not be prepared.
    ///
    /// Every layer is canonicalized, since the mount options name the layers
    /// absolutely; the upper and work directories are additionally created when
    /// absent, while a stacked lower must already exist. This reports a host
    /// failure at either step: a path that does not resolve, a permission
    /// refusal, or a path that resolves to something other than a usable
    /// directory.
    #[non_exhaustive]
    OverlayDirUnusable {
        /// Which layer directory failed.
        layer: OverlayLayer,
        /// The directory that could not be prepared.
        path: PathBuf,
        /// The error the preparation failed with.
        source: io::Error,
    },
    /// An overlay layer directory the library would have created was already
    /// there, and is not a directory the calling user owns.
    ///
    /// The upper and work directories are created if absent, and the caller may
    /// name them under a directory it shares with other local users. An entry
    /// already at the path is adopted only when it is a directory belonging to
    /// the calling user: a symbolic link — which would send every write the
    /// sandbox makes to a destination of whoever planted it, and hand that
    /// destination back to the caller as the layer its run produced — or a
    /// directory owned by someone else is refused instead of used.
    #[non_exhaustive]
    OverlayDirUnowned {
        /// Which layer directory was refused.
        layer: OverlayLayer,
        /// The path that was already occupied.
        path: PathBuf,
    },
    /// An overlay's upper or work directory is the filesystem root, or another
    /// path that names no directory inside a parent, such as one ending in
    /// `..`.
    ///
    /// The library creates both directories inside their parents, and the
    /// upper's parent also holds the work directory the library derives and
    /// the host overlay preflight's scratch entries. `/` has no parent, and an
    /// upper there would put the sandbox's writes over the whole host root.
    #[non_exhaustive]
    OverlayLayerIsRoot {
        /// Which layer directory the path was given for.
        layer: OverlayLayer,
        /// The offending path.
        path: PathBuf,
    },
    /// Two of an overlay's layers are not disjoint: one is the other, or lies
    /// beneath it.
    ///
    /// The kernel mounts an upper or a work directory beneath a lower, and
    /// every write the sandbox makes then lands inside that lower, so the build
    /// refuses it before it creates anything. It refuses the overlaps the kernel
    /// refuses at mount too, rather than leave them to an `ELOOP` or `EINVAL`
    /// from a mount the caller never issued: a lower that is, or lies beneath,
    /// the upper or the work directory; the upper and the work directory the
    /// same or nested; and two lowers the same or nested. The paths are
    /// compared as the mount options name them, with every symbolic link above
    /// a layer resolved. A directory a bind mount presents at a second path is
    /// not recognised there.
    #[non_exhaustive]
    OverlayLayersOverlap {
        /// The layer that is, or lies beneath, the other. A lower is any of the
        /// overlay's lowers, the rootfs included.
        layer: OverlayLayer,
        /// That layer's path, as the mount options name it.
        path: PathBuf,
        /// The layer it is, or lies beneath.
        within: OverlayLayer,
        /// That layer's path, as the mount options name it.
        within_path: PathBuf,
    },
    /// An overlay-rooted cage was requested on a host that cannot establish an
    /// unprivileged overlay mount.
    ///
    /// The overlay preflight names what is missing: the running kernel may
    /// predate unprivileged overlay-in-a-user-namespace (Linux 5.11), or the
    /// upper layer's filesystem may not support the `user.*` extended-attribute
    /// namespace an unprivileged overlay records its metadata in — which tmpfs
    /// gained only in Linux 6.6, so an on-disk upper (ext4, xfs, btrfs) is the
    /// portable choice.
    #[non_exhaustive]
    OverlayUnavailable {
        /// The host blocker the overlay preflight identified.
        blocker: crate::host::OverlayBlocker,
    },
    /// A resource limit names a soft value above its hard value.
    ///
    /// The kernel refuses such a pair with `EINVAL`; it is caught here so the
    /// mistake is a typed configuration error rather than a launch failure.
    #[non_exhaustive]
    RlimitInvalid {
        /// The resource the limit governs.
        resource: crate::limits::Resource,
        /// The soft limit as it was given.
        soft: crate::limits::Limit,
        /// The hard limit as it was given.
        hard: crate::limits::Limit,
    },
    /// A mount target the [host's own root](crate::CageBuilder::host_rootfs)
    /// would need created is not there, or could not be looked up there.
    ///
    /// That root is the host's tree, read-only, and a launch creates nothing in
    /// it. A target must already exist on the host, or lie inside a filesystem
    /// the sandbox mounts itself, such as a hidden directory or the managed
    /// `/tmp`, where it is created. A symbolic link of the caller's is
    /// [`SymlinkInHostRoot`](Self::SymlinkInHostRoot)'s case.
    ///
    /// The message says the target is not in the host's root only where the
    /// lookup found nothing there, `ENOENT`, or found a file where a directory
    /// above the target should be, `ENOTDIR`.
    #[non_exhaustive]
    MountTargetMissing {
        /// The target, as the mount names it inside the sandbox.
        target: PathBuf,
        /// What looking the target up on the host answered.
        source: io::Error,
    },
    /// [`CageBuilder::reveal`](crate::CageBuilder::reveal) names a path the
    /// root does not hide by default: one outside the
    /// [host's own root](crate::CageBuilder::host_rootfs)'s list, or any path
    /// for another kind of root.
    #[non_exhaustive]
    RevealUnhidden {
        /// The path as it was given.
        path: PathBuf,
    },
    /// The unix-socket restriction was asked for on a kernel that cannot
    /// enforce it: one below Landlock ABI 9, or one without the Landlock LSM.
    ///
    /// The restriction is the only bound on the pathname sockets a sandbox's
    /// mounts do not hide, so a request for it is refused rather than dropped.
    /// Where the library applies it by default, under the
    /// [host's own root](crate::CageBuilder::host_rootfs), such a kernel runs
    /// without it instead.
    #[non_exhaustive]
    LandlockResolveUnixUnenforceable {
        /// The kernel's supported Landlock ABI, or `None` when the LSM is
        /// absent.
        abi: Option<i32>,
    },
    /// A Landlock grant allows only connecting to unix sockets, where no
    /// unix-socket restriction applies to allow them past.
    ///
    /// Without the restriction a pathname socket is reachable wherever the
    /// command can name it, so the grant would allow nothing, and turning the
    /// restriction on is what the grant reads as meaning.
    #[non_exhaustive]
    ResolveUnixUnhandled {
        /// The grant, as `access on path`.
        grant: String,
    },
    /// The only procfs the sandbox mounts that could serve its nested user
    /// namespace is read-only.
    ///
    /// The [`NestedUsernsNeedsProcfs`](Self::NestedUsernsNeedsProcfs) refusal,
    /// where read-only is the one reason the procfs at `target` does not count:
    /// the identity map of the nested user namespace is written through it.
    /// A procfs bound read-only, a fresh one mounted read-only, one a later
    /// remount makes read-only, and one beneath a path made read-only are each
    /// such a procfs.
    #[non_exhaustive]
    NestedUsernsProcfsReadOnly {
        /// Where the read-only procfs is mounted inside the sandbox.
        target: PathBuf,
    },
    /// A cgroup setting is not one a launch can carry out: a limit without a
    /// parent to create the sandbox's cgroup beneath, a parent that is not an
    /// absolute path, or a value the kernel does not take.
    #[non_exhaustive]
    CgroupLimitInvalid {
        /// What is wrong with it.
        reason: String,
    },
    /// A restriction with a cgroup leaves its command a way to lift the
    /// cgroup's limits or to leave the cgroup.
    ///
    /// A restriction carrying a cgroup parent or a limit builds only where its
    /// Landlock domain keeps every write off the cgroup v2 hierarchy and its
    /// seccomp policy answers `clone3` with an errno; [`CgroupReach`] says
    /// which of those does not hold.
    // The sentence links a feature-gated item, so its doc text is gated on the
    // feature, as a restriction is.
    #[cfg_attr(
        feature = "hardening",
        doc = "Limits that are not [required](crate::RestrictionBuilder::cgroup_required) \
               are refused the same way."
    )]
    #[non_exhaustive]
    RestrictionCgroupReachable {
        /// What the command could reach the cgroup through.
        reach: CgroupReach,
    },
    /// A symbolic link of the caller's would be made in the
    /// [host's own root](crate::CageBuilder::host_rootfs), where the host's
    /// tree does not already hold it.
    ///
    /// That root is the host's tree, read-only, and a launch makes nothing in
    /// it, so a link is made only inside a filesystem the sandbox mounts
    /// itself, such as a hidden directory or the managed `/tmp`. Where the same
    /// link already stands on the host, the launch leaves it as it is.
    #[non_exhaustive]
    SymlinkInHostRoot {
        /// The link's path inside the sandbox.
        path: PathBuf,
        /// What the link points at, as it was given to the builder.
        target: PathBuf,
    },
    /// An overlay's work directory is on another filesystem than its upper.
    ///
    /// The overlay moves files between the two, so the kernel requires them on
    /// one filesystem. The work directory a caller names is compared with the
    /// upper once both exist, and refused here, with both named, rather than
    /// left to the mount's `EXDEV`.
    #[non_exhaustive]
    OverlayWorkOnAnotherFilesystem {
        /// The work directory, as the mount options name it.
        work: PathBuf,
        /// The upper, as the mount options name it.
        upper: PathBuf,
    },
}

impl fmt::Display for ConfigError {
    // Every path and value named here is configuration, and configuration can
    // come from a profile nothing vouches for: a `RestrictedProfile`'s rootfs,
    // command, working directory, and hidden paths, or whatever a consumer
    // composes one with. Each is named with `{:?}`, as the `failure` module
    // states, so a control character in one reaches a terminal as an escape.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::RootfsMissing => f.write_str(
                "no root was provided: set a rootfs, an overlay, an empty rootfs, or the \
                     host's own root",
            ),
            ConfigError::RootContradiction => f.write_str(
                "more than one of a rootfs, an overlay root, an empty rootfs, and the host's own \
                 root is configured, but exactly one root is in force; keep one",
            ),
            ConfigError::RootfsUnusable { path, .. } => {
                write!(f, "cannot use {path:?} as the rootfs")
            }
            ConfigError::RootfsIsHostRoot => {
                f.write_str("the host root directory cannot be the rootfs")
            }
            ConfigError::CommandMissing => f.write_str("no command was provided"),
            // A bare name is the usual case, and `path_lookup` is exactly its
            // remedy where the builder has it. A relative path is never
            // searched, and a restriction searches nothing, so pointing at path
            // lookup for either would be misdirection.
            ConfigError::CommandNotAbsolute {
                command,
                lookup_offered: true,
            } if is_command_name(command) => write!(
                f,
                "the command path {command:?} is not absolute; give an absolute path, or enable \
                 path lookup to resolve a bare command name against the sandbox's PATH",
            ),
            ConfigError::CommandNotAbsolute {
                command,
                lookup_offered: false,
            } if is_command_name(command) => write!(
                f,
                "the command path {command:?} is not absolute; a restriction never searches PATH \
                 for a bare command name, so give an absolute path",
            ),
            ConfigError::CommandNotAbsolute { command, .. } => {
                write!(f, "the command path {command:?} is not absolute")
            }
            ConfigError::ManagedMountsContradiction { toggle } => write!(
                f,
                "managed_mounts(false) suppresses every mount the library establishes, \
                 but {toggle} explicitly asks for one; drop one of the two",
            ),
            ConfigError::SearchPathUnusable { path } => write!(
                f,
                "path lookup has nothing to search: PATH {path:?} holds no absolute directory",
            ),
            ConfigError::BindSourceUnusable { path, .. } => {
                write!(f, "cannot use {path:?} as a bind-mount source")
            }
            ConfigError::MountTargetInvalid { path } => write!(
                f,
                "the mount target {path:?} is not a normal absolute path inside the rootfs",
            ),
            ConfigError::SymlinkTargetInvalid { path, target } => write!(
                f,
                "the symlink at {path:?} has an empty target, or one too long for a path: \
                 {target:?}",
            ),
            ConfigError::MountFlagsInvalid { target, flags } => write!(
                f,
                "the flags {flags:#x} of the raw mount at {target:?} do not fit the kernel's \
                 mount-flags word",
            ),
            ConfigError::WorkdirNotAbsolute { path } => write!(
                f,
                "the working directory {path:?} is not a normal absolute path",
            ),
            ConfigError::HostnameInvalid { name } => write!(
                f,
                "the hostname {name:?} is empty, longer than 64 bytes, or contains a NUL byte",
            ),
            ConfigError::EnvNameInvalid { name } => write!(
                f,
                "the environment variable name {:?} is empty or contains '=' or a NUL byte",
                name,
            ),
            ConfigError::EmbeddedNul { value } => {
                write!(
                    f,
                    "the configured value {value:?} contains an interior NUL byte"
                )
            }
            ConfigError::SeccompInvalid { reason } => {
                write!(f, "the seccomp policy could not be compiled: {reason}")
            }
            ConfigError::SeccompUnsupportedArch { arch } => write!(
                f,
                "seccomp filtering is not available for the {arch} architecture",
            ),
            ConfigError::SeccompProgramTooLong { len, max } => write!(
                f,
                "the seccomp program is {len} instructions, over the kernel maximum of {max}",
            ),
            ConfigError::LandlockGrantEmpty { grant } => write!(
                f,
                "the Landlock grant on {grant} names no access; enrolling a grant denies \
                 everything ungranted, so an empty one denies the whole class",
            ),
            ConfigError::LandlockPathInvalid { path } => write!(
                f,
                "the Landlock grant path {path:?} is not a normal absolute path",
            ),
            ConfigError::RestrictionLandlockUnenforceable { abi } => match abi {
                Some(abi) => write!(
                    f,
                    "the restriction's Landlock network grant needs Landlock ABI 4, and the \
                     kernel supports ABI {abi}"
                ),
                None => f.write_str(
                    "the restriction requests Landlock confinement, but the kernel offers no \
                     Landlock LSM",
                ),
            },
            ConfigError::HostNetworkLandlockUnenforceable { abi } => match abi {
                Some(abi) => write!(
                    f,
                    "a host-network cage's Landlock network grant falls outside the kernel's \
                     supported Landlock ABI ({abi}); a network grant needs ABI 4, and host \
                     networking has no network namespace to fall back on"
                ),
                None => f.write_str(
                    "a host-network cage requests a Landlock network grant, but the kernel offers \
                     no Landlock LSM to enforce it, and host networking has no network namespace \
                     to fall back on",
                ),
            },
            ConfigError::LandlockScopeUnenforceable { scope, abi } => match abi {
                Some(abi) => write!(
                    f,
                    "the Landlock scope {scope} needs Landlock ABI 6, and the kernel supports ABI \
                     {abi}; no namespace bounds the reach it confines"
                ),
                None => write!(
                    f,
                    "the Landlock scope {scope} needs the Landlock LSM, which the kernel does not \
                     offer; no namespace bounds the reach it confines"
                ),
            },
            ConfigError::ProfileOperationForbidden { operation } => write!(
                f,
                "this profile uses {operation}, which the restricted policy reserves for a \
                 trusted profile"
            ),
            ConfigError::StreamAttachmentConflict { stream, attachment } => write!(
                f,
                "this launch attaches {attachment} to the command's {stream}, which the sandbox \
                 directs elsewhere"
            ),
            ConfigError::RestrictionEmpty => {
                f.write_str("the restriction names no Landlock grant or seccomp policy")
            }
            ConfigError::IdentityMapInvalid { reason } => {
                write!(f, "the identity map is invalid: {reason}")
            }
            // A configured delegate's refusal is the source, which `reason`
            // only renders; the bundled chain's reason collects one from each
            // delegate and has no single error to return.
            ConfigError::IdentityMapUnavailable {
                source: Some(_), ..
            } => f.write_str("no delegate can establish the requested identity map"),
            ConfigError::IdentityMapUnavailable {
                reason,
                source: None,
            } => write!(
                f,
                "no delegate can establish the requested identity map: {reason}"
            ),
            ConfigError::RunAsUnmapped { id, space } => {
                write!(
                    f,
                    "the run-as {space} {id} is not contained in the identity map"
                )
            }
            ConfigError::RunAsOutsideSingleMap {
                id,
                space,
                presented,
            } => write!(
                f,
                "the single-identity map holds one id, the caller, which the command sees as \
                 {space} {presented}, so the command cannot run as {space} {id}; present the \
                 caller as {space} {id} instead",
            ),
            ConfigError::PresentAsWithRangeMap => f.write_str(
                "a presented identity applies only to the single-identity map; under a range \
                 map, run the command as one of the map's own ids instead",
            ),
            ConfigError::PresentAsRoot { identity } => {
                match identity {
                    crate::PresentedIdentity::Own => {
                        f.write_str("the presented identity `own` is the caller's uid, 0")?
                    }
                    crate::PresentedIdentity::Ids { .. } => {
                        write!(f, "the presented identity {identity} has uid 0")?
                    }
                }
                f.write_str(
                    ", which is root inside the sandbox with every capability; present a \
                     non-root uid, or none for a root command",
                )
            }
            ConfigError::RunAsGroupsWithSingleMap => f.write_str(
                "run-as supplementary groups require a gid map wider than the caller's own gid; \
                 a gid map of that gid alone, the single-identity map's, denies setgroups",
            ),
            ConfigError::NestedUsernsNeedsProcfs => f.write_str(
                "the sandbox mounts no procfs the nested user namespace that locks its mount \
                 flags can establish its identity map through; mount one, or leave the \
                 managed profile's own in place. A range identity map inside a PID namespace \
                 of the sandbox's own needs a fresh procfs rather than a bind of the host's, \
                 which the sandbox's pids do not index; without a PID namespace it needs none, \
                 because its map is written from outside",
            ),
            ConfigError::SetidCapWithNonRootIdentity { capability } => write!(
                f,
                "keeping {capability} alongside a non-root run-as identity would let the \
                 command return to uid 0; drop the capability or run as root inside",
            ),
            ConfigError::OverlayPathInvalid { path } => write!(
                f,
                "the overlay-root path {path:?} contains a ',', which the overlay mount options \
                 cannot carry",
            ),
            ConfigError::OverlayOptionsTooLong { length } => write!(
                f,
                "the overlay root's mount options are {length} bytes, longer than the kernel \
                 passes on whole; stack fewer lowers, or reach them by shorter paths",
            ),
            ConfigError::OverlayLowerMissing => {
                f.write_str("the overlay root names no lower layer to mount over")
            }
            ConfigError::OverlayUpperMissing => {
                f.write_str("the overlay root names no upper layer for its writes")
            }
            ConfigError::OverlayDirUnusable { layer, path, .. } => {
                write!(f, "cannot use {path:?} as the overlay {layer} directory")
            }
            ConfigError::OverlayDirUnowned { layer, path } => write!(
                f,
                "cannot use {path:?} as the overlay {layer} directory: something is already there \
                 that is not a directory the calling user owns; the layer directories are created \
                 fresh, and adopting an entry another user could have planted would send the \
                 sandbox's writes wherever it pointed",
            ),
            ConfigError::OverlayLayersOverlap {
                layer,
                path,
                within,
                within_path,
            } => {
                match (path == within_path, layer == within) {
                    (true, true) => {
                        write!(f, "the overlay names {path:?} as two of its {layer}s")
                    }
                    (true, false) => write!(
                        f,
                        "the overlay names {path:?} as both its {within} and its {layer}",
                    ),
                    (false, _) => write!(
                        f,
                        "the overlay's {layer} {path:?} lies inside its {within} {within_path:?}",
                    ),
                }?;
                f.write_str("; an overlay's layers must be disjoint")
            }
            ConfigError::OverlayLayerIsRoot { layer, path } => write!(
                f,
                "cannot use {path:?} as the overlay {layer} directory: it names no directory \
                 inside a parent, and the {layer} is created in one",
            ),
            ConfigError::OverlayUnavailable { blocker } => {
                write!(f, "an overlay-rooted cage cannot be established: {blocker}")
            }
            ConfigError::RlimitInvalid {
                resource,
                soft,
                hard,
            } => write!(
                f,
                "the {resource} soft limit {soft} is above its hard limit {hard}",
            ),
            // Only a lookup that found nothing at the target says it is not
            // there; any other failure says no more than that it was not found.
            ConfigError::MountTargetMissing { target, source }
                if matches!(
                    source.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                write!(
                    f,
                    "the mount target {target:?} is not in the host's root, where a launch \
                     creates nothing (mount over a path that exists, or beneath a filesystem the \
                     sandbox mounts, such as a hidden directory or /tmp)",
                )
            }
            ConfigError::MountTargetMissing { target, .. } => write!(
                f,
                "the mount target {target:?} could not be looked up in the host's root, where a \
                 launch creates nothing",
            ),
            ConfigError::LandlockResolveUnixUnenforceable { abi } => match abi {
                Some(abi) => write!(
                    f,
                    "the unix-socket restriction needs Landlock ABI 9, and the kernel supports \
                     ABI {abi}"
                ),
                None => f.write_str(
                    "the unix-socket restriction needs Landlock, which the kernel does not offer",
                ),
            },
            ConfigError::ResolveUnixUnhandled { grant } => write!(
                f,
                "the Landlock grant {grant} allows only connecting to unix sockets, which nothing \
                 restricts unless the unix-socket restriction is on"
            ),
            // The hidden paths are read from the list the build hides, so the
            // message cannot name a list the root no longer has.
            ConfigError::RevealUnhidden { path } => {
                write!(
                    f,
                    "{path:?} is not a path the root hides by default, so revealing it is a \
                     mistake (the host's own root hides "
                )?;
                let hidden = HOST_ROOT_HIDDEN;
                for (at, hidden_path) in hidden.iter().enumerate() {
                    match at {
                        0 => {}
                        at if at + 1 == hidden.len() => f.write_str(", and ")?,
                        _ => f.write_str(", ")?,
                    }
                    f.write_str(hidden_path)?;
                }
                f.write_str(")")
            }
            ConfigError::CgroupLimitInvalid { reason } => {
                write!(f, "the cgroup settings cannot be carried out: {reason}")
            }
            ConfigError::RestrictionCgroupReachable { reach } => write!(
                f,
                "the restriction's command could lift its cgroup's limits or leave its cgroup: \
                 {reach}"
            ),
            ConfigError::SymlinkInHostRoot { path, target } => write!(
                f,
                "the host's root holds no symbolic link at {path:?} to {target:?}, and a launch \
                 makes nothing there (make the link beneath a filesystem the sandbox mounts, such \
                 as a hidden directory or /tmp)",
            ),
            ConfigError::OverlayWorkOnAnotherFilesystem { work, upper } => write!(
                f,
                "the overlay work directory {work:?} is on another filesystem than its upper \
                 {upper:?}; the overlay moves files between the two, so they share one",
            ),
            ConfigError::NestedUsernsProcfsReadOnly { target } => write!(
                f,
                "the procfs at {target:?} is read-only, and the nested user namespace that locks \
                 the sandbox's mount flags writes its identity map through it; keep one procfs \
                 writable, neither mounted read-only nor beneath a path made read-only",
            ),
        }
    }
}

impl std::error::Error for ConfigError {
    /// The failure underneath, for the refusals that have one: an OS failure
    /// for the four that resolve a host path, and a configured identity-map
    /// delegate's own error.
    ///
    /// Every other variant is a request the builder refused on its own terms —
    /// a contradiction, a missing field, a path that is not the shape it has to
    /// be — where nothing failed and there is nothing to return.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::RootfsUnusable { source, .. }
            | ConfigError::BindSourceUnusable { source, .. }
            | ConfigError::OverlayDirUnusable { source, .. }
            | ConfigError::MountTargetMissing { source, .. } => Some(source),
            ConfigError::IdentityMapUnavailable {
                source: Some(source),
                ..
            } => Some(source),
            _ => None,
        }
    }
}

/// An error from the library itself.
///
/// [`Cage::run`] returns `Err` only when the library fails: invalid
/// configuration, an unsupported host, a failed setup step, or a failure to
/// spawn or wait. The sandboxed command's own exit code is data, carried by
/// [`ExitStatus`], and is never an `Error`.
///
/// The message says what failed and what it was operating on. The cause
/// underneath, such as the OS error a setup step met or the [`ConfigError`] a
/// build refused with, is returned from
/// [`source`](std::error::Error::source) rather than repeated in it. Print an
/// error through [`ErrorChain`](crate::ErrorChain) to show both.
///
/// [`Cage::run`]: crate::Cage::run
/// [`ExitStatus`]: crate::ExitStatus
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The sandbox configuration was rejected at build time.
    Config(ConfigError),
    /// The host cannot create unprivileged user namespaces.
    ///
    /// Produced when namespace creation is denied by the kernel. When the
    /// probe in [`crate::host`] identifies the mechanism responsible, it is
    /// carried in `blocker`.
    #[non_exhaustive]
    UsernsUnavailable {
        /// The host configuration identified as blocking user namespaces,
        /// when one could be determined.
        blocker: Option<UsernsBlocker>,
        /// The error the kernel returned for namespace creation.
        source: io::Error,
    },
    /// The kernel refused to create a namespace because a namespace limit is
    /// reached.
    ///
    /// The limits are a family: a per-user count of each kind of namespace, set
    /// by the `user.max_*_namespaces` sysctls under `/proc/sys/user`, and the
    /// nesting depth of user and PID namespaces, 32 levels each. A namespace
    /// is charged against its count at every level of user namespace up to the
    /// initial one, and a launch holds two user namespaces and two mount
    /// namespaces: the sandbox's own, and the nested ones the command enters.
    /// The kernel's `ENOSPC` names none of them, so this is reported rather
    /// than a bare "No space left on device".
    ///
    /// `step` says which creation was refused:
    /// [`Unshare`](SetupStep::Unshare) for the sandbox's own namespaces, and
    /// [`NestedUnshare`](SetupStep::NestedUnshare) for the command's nested
    /// ones, where a host whose ceiling admits one user namespace and not two
    /// fails. Distinct from [`UsernsUnavailable`](Self::UsernsUnavailable),
    /// which is a host that permits no user namespace at all.
    #[non_exhaustive]
    NamespaceLimitReached {
        /// The creation that was refused.
        step: SetupStep,
        /// The error the kernel returned, `ENOSPC`.
        source: io::Error,
    },
    /// The calling user's kernel key quota is exhausted, so the sandbox could
    /// not be given a session keyring of its own.
    ///
    /// Every launch replaces the session keyring it inherited with a fresh one,
    /// so that the command cannot read the keys the caller's session holds, and
    /// that keyring is charged against the calling user's quota for as long as
    /// the sandbox runs. The quota is `kernel.keys.maxkeys` keys and
    /// `kernel.keys.maxbytes` bytes per user, 200 and 20000 by default, shared
    /// with every other key the user holds. A host running that many sandboxes
    /// at once as one user reports this rather than a bare `EDQUOT`.
    #[non_exhaustive]
    KeyQuotaExhausted {
        /// The error the kernel returned for the new keyring, `EDQUOT`.
        source: io::Error,
    },
    /// A sandbox setup step failed in the child process.
    #[non_exhaustive]
    Setup {
        /// The step that failed.
        step: SetupStep,
        /// The error the step failed with.
        source: io::Error,
        /// What the step was operating on, when the step has a subject — for a
        /// mount step, the mount it was assembling; for
        /// [`Exec`](SetupStep::Exec), the command path, and for a command
        /// resolved by path lookup, the candidates the search tried.
        ///
        /// An `ENOENT` from the exec step means either that the command itself
        /// is absent or that its ELF interpreter is: a dynamically linked
        /// binary whose loader is missing from the rootfs reports the same
        /// errno as a missing binary. The detail names the command, not the
        /// interpreter, so a path that plainly exists inside the rootfs points
        /// at the second reading.
        detail: Option<String>,
    },
    /// The sandbox process could not be created.
    #[non_exhaustive]
    Spawn {
        /// The error from pipe creation or fork.
        source: io::Error,
    },
    /// The sandbox process outcome could not be collected.
    #[non_exhaustive]
    Wait {
        /// The error from collecting the outcome: reading the setup-error,
        /// status, or capture pipes, waiting on them, or the wait itself.
        source: io::Error,
    },
    /// The sandbox supervisor exited without reporting the command's
    /// outcome.
    ///
    /// The supervisor always reports the command's wait status before it
    /// exits; its silent disappearance means it was killed from outside or
    /// exited abnormally, and the command's outcome is unknown. A kill
    /// requested through the handle is not this error: after
    /// [`Running::kill`], the outcome is reported as termination by
    /// `SIGKILL`.
    ///
    /// [`Running::kill`]: crate::Running::kill
    SupervisorLost,
    /// The sandbox could not be signaled through the handle.
    #[non_exhaustive]
    Signal {
        /// The error from the signaling machinery.
        source: io::Error,
    },
    /// A [`KillHandle`](crate::KillHandle) could not be made: duplicating the
    /// handle's descriptors failed, typically because the process has run out
    /// of them. Nothing was signaled.
    #[non_exhaustive]
    KillHandle {
        /// The error from duplicating a descriptor.
        source: io::Error,
    },
    /// The identity-map delegate failed to establish the range map.
    ///
    /// The delegate runs caller-side against the gated launch, so its own
    /// error is the diagnostic; the gated sandbox is torn down.
    IdentityMap(crate::IdMapError),
    /// A pseudoterminal operation on the caller's side failed: reading or
    /// setting the window size of the sandbox's terminal.
    ///
    /// The allocation itself happens inside the sandbox, so a failure there is
    /// [`Setup`](Self::Setup) with
    /// [`SetupStep::AllocateTerminal`](SetupStep::AllocateTerminal).
    #[non_exhaustive]
    Terminal {
        /// The error the operation failed with.
        source: io::Error,
    },
    /// The host has no free pseudoterminal to allocate.
    ///
    /// Pseudoterminals are a bounded resource, so a host running many sandboxes
    /// at once can exhaust them. `/proc/sys/kernel/pty/max` states the ceiling,
    /// and `/proc/sys/kernel/pty/reserve` the share of it kept for the host's own
    /// `devpts`, which a sandbox's private instance cannot draw on. Distinct from
    /// [`Setup`](Self::Setup) because it is the one allocation failure that says
    /// nothing is wrong with the request: the same launch succeeds once something
    /// releases a terminal.
    #[non_exhaustive]
    TerminalsExhausted {
        /// The error the sandbox's `devpts` instance returned for the
        /// multiplexer, `ENOSPC`.
        source: io::Error,
    },
    /// A launch would have handed the command a directory as one of its standard
    /// streams, and refused before creating anything.
    ///
    /// A directory descriptor is a path as well as a stream. `/proc/self/fd/N`
    /// and `openat(N, "..")` walk from it through the host's filesystem, past
    /// the root the sandbox swapped in. The rule covers every stream a launch
    /// hands over, whether [`Stdio::from_fd`](crate::Stdio::from_fd) supplied
    /// it or [`Stdio::Inherit`](crate::Stdio::Inherit) passes on the caller's
    /// own. See [`Stdio`](crate::Stdio).
    #[non_exhaustive]
    StreamIsDirectory {
        /// The stream, as a short phrase: `"standard input"`,
        /// `"standard output"`, or `"standard error"`.
        stream: &'static str,
    },
    /// [`Pending::listen`](crate::Pending::listen) was asked for a listener it
    /// does not make, and created nothing.
    #[non_exhaustive]
    ListenRefused {
        /// The address the listener was asked for.
        address: SocketAddr,
        /// Why no listener is made there.
        reason: ListenRefusal,
    },
    /// [`Pending::listen`](crate::Pending::listen) could not make the listener
    /// in the sandbox's network namespace.
    ///
    /// `EADDRINUSE` from the bind means the sandbox already listens at the
    /// address, through an earlier listener of the caller's.
    #[non_exhaustive]
    Listen {
        /// The address the listener was to bind.
        address: SocketAddr,
        /// What was being done, as a phrase that completes "while".
        op: &'static str,
        /// The error the operation failed with, absent where the helper that
        /// makes the listener ended without saying why.
        source: Option<io::Error>,
    },
    /// The kernel refused the fresh procfs a sandbox with a PID namespace of
    /// its own mounts, as it does inside a container whose runtime masks
    /// entries of the container's procfs.
    ///
    /// The kernel mounts a procfs for a user namespace only where an existing
    /// procfs is fully visible, and [`ProcfsBlocker`] says what the mount table
    /// shows about why none is, and what to do. The same check is available
    /// before a launch as [`host::procfs_blocker`](crate::host::procfs_blocker).
    /// Reported in place of [`Setup`](Self::Setup) for a
    /// [`MountProc`](SetupStep::MountProc) step that failed with `EPERM`.
    #[non_exhaustive]
    ProcfsRefused {
        /// What the mount table shows, and the remedies.
        blocker: ProcfsBlocker,
        /// The error the kernel returned for the mount, `EPERM`.
        source: io::Error,
    },
    /// The sandbox could not be given a cgroup of its own beneath the parent
    /// [`cgroup_parent`](crate::CageBuilder::cgroup_parent) names, for a
    /// reason [`CgroupRefusal`] states. Nothing was launched.
    #[non_exhaustive]
    CgroupRefused {
        /// The parent the caller named.
        parent: PathBuf,
        /// Why it cannot hold the sandbox's cgroup.
        reason: CgroupRefusal,
    },
    /// Preparing the sandbox's cgroup failed for a reason of the host's that no
    /// [`CgroupRefusal`] names, such as running out of descriptors. Nothing
    /// was launched.
    #[non_exhaustive]
    Cgroup {
        /// What the step was doing.
        op: &'static str,
        /// The cgroup directory concerned.
        path: PathBuf,
        /// The error the step failed with.
        source: io::Error,
    },
    /// The launch stage published the sandbox's supervisor, and the descriptor
    /// naming it did not reach this process, so the launch was ended.
    ///
    /// The kernel installs a descriptor sent over a socket only where the
    /// receiving process has a descriptor number free under `RLIMIT_NOFILE`
    /// and the system's file limit, and where no security module refuses it;
    /// otherwise the message arrives without it. A sandbox whose supervisor
    /// this process holds no handle to could be neither waited for nor killed,
    /// so the launch asks the supervisor to end it, over the channel the
    /// launch still holds, before this is returned. Without a PID namespace
    /// every process of the launch has exited by then; with one, the
    /// namespace is ending.
    SupervisorUnreceived,
}

/// Why [`Pending::listen`](crate::Pending::listen) makes no listener at an
/// address, carried by [`Error::ListenRefused`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenRefusal {
    /// The address is not a loopback address: it is outside `127.0.0.0/8` and
    /// is not `::1`. A listener carries what the command connects to on its
    /// own loopback, and nothing else.
    NotLoopback,
    /// The sandbox runs under [`Network::None`](crate::Network::None), whose
    /// loopback is down.
    LoopbackDown,
    /// The sandbox runs under [`Network::Host`](crate::Network::Host) and has
    /// no network namespace of its own: its loopback is the host's.
    SharedNamespace,
}

impl fmt::Display for ListenRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ListenRefusal::NotLoopback => "the address is not a loopback address",
            ListenRefusal::LoopbackDown => {
                "the sandbox runs without a network, whose loopback is down"
            }
            ListenRefusal::SharedNamespace => {
                "the sandbox shares the host's network namespace, whose loopback is the host's"
            }
        })
    }
}

impl Error {
    /// The exit code a launcher reports when a launch fails, following the
    /// conventions `sh` and `timeout(1)` established.
    ///
    /// A caller whose whole purpose is to run one command inside a sandbox is a
    /// launcher, and a launcher's own failures have to be distinguishable from
    /// the command's exit codes. The conventions are:
    ///
    /// | Code | Meaning |
    /// | --- | --- |
    /// | 127 | The command does not exist. |
    /// | 126 | The command exists but could not be executed. |
    /// | 125 | The launcher itself failed, for any other reason. |
    ///
    /// The distinction between 127 and 126 comes from the errno the
    /// [`Exec`](SetupStep::Exec) step failed with. An `ENOENT` there has two
    /// readings — the command is absent, or its ELF interpreter is — and both
    /// are reported as 127, since neither produced a runnable process.
    ///
    /// This is what the `fcage` binary returns. A caller with its own
    /// convention is free to map [`Error`] itself; this is the answer for one
    /// that has none, and the one that makes a consumer behave like a shell.
    ///
    /// 124, `timeout(1)`'s "the deadline expired", is not produced here: an
    /// expired deadline is not an [`Error`], it is a
    /// [`Running::wait_timeout`](crate::Running::wait_timeout) that returned no
    /// status, so only the caller knows it happened.
    ///
    /// # Example
    ///
    /// ```
    /// use std::process::ExitCode;
    ///
    /// use ferroday_cage::{Cage, ErrorChain};
    ///
    /// fn launch(rootfs: &str) -> ExitCode {
    ///     match Cage::builder().command("/bin/true").rootfs(rootfs).build() {
    ///         Ok(_cage) => ExitCode::SUCCESS,
    ///         Err(error) => {
    ///             eprintln!("myapp: {}", ErrorChain::new(&error));
    ///             ExitCode::from(error.shell_code())
    ///         }
    ///     }
    /// }
    /// # let _ = launch;
    /// ```
    pub fn shell_code(&self) -> u8 {
        match self {
            Error::Setup {
                step: SetupStep::Exec,
                source,
                ..
            } => match source.kind() {
                std::io::ErrorKind::NotFound => 127,
                _ => 126,
            },
            _ => 125,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(_) => f.write_str("invalid sandbox configuration"),
            // The guidance sits in parentheses wherever the message carries a
            // cause, so the cause a renderer appends reads as the reason for the
            // failure rather than for the remedy.
            Error::UsernsUnavailable {
                blocker: Some(blocker),
                ..
            } => write!(
                f,
                "unprivileged user namespaces are unavailable ({blocker})"
            ),
            Error::UsernsUnavailable { blocker: None, .. } => f.write_str(
                "the kernel denied user namespace creation (a seccomp filter or an LSM policy \
                 may be blocking unprivileged user namespaces)",
            ),
            Error::NamespaceLimitReached { step, .. } => write!(
                f,
                "sandbox setup failed while {step}, because a namespace limit is reached (a \
                 count under /proc/sys/user such as user.max_user_namespaces or \
                 user.max_mnt_namespaces, of which every launch takes two, or the nesting \
                 depth of 32 user or PID namespaces; raise the count, or reduce the number of \
                 namespaces already live)"
            ),
            Error::KeyQuotaExhausted { .. } => f.write_str(
                "the sandbox could not be given a session keyring of its own, because the \
                 calling user's kernel key quota is exhausted (every running sandbox holds one \
                 keyring; raise kernel.keys.maxkeys and kernel.keys.maxbytes, or run fewer \
                 sandboxes at once)",
            ),
            Error::Setup {
                step,
                detail: Some(detail),
                ..
            } => write!(f, "sandbox setup failed while {step} ({detail})"),
            Error::Setup {
                step, detail: None, ..
            } => write!(f, "sandbox setup failed while {step}"),
            Error::Spawn { .. } => f.write_str("could not spawn the sandbox process"),
            Error::Wait { .. } => f.write_str("could not collect the sandbox process outcome"),
            Error::SupervisorLost => {
                f.write_str("the sandbox supervisor exited without reporting the command's outcome")
            }
            Error::Signal { .. } => f.write_str("could not signal the sandbox"),
            Error::KillHandle { .. } => f.write_str("could not make a kill handle for the sandbox"),
            Error::IdentityMap(_) => f.write_str("could not establish the identity map"),
            Error::Terminal { .. } => f.write_str("a pseudoterminal operation failed"),
            Error::TerminalsExhausted { .. } => f.write_str(
                "the host has no free pseudoterminal to allocate (/proc/sys/kernel/pty/max \
                 states the ceiling, less /proc/sys/kernel/pty/reserve for a sandbox's own)",
            ),
            Error::StreamIsDirectory { stream } => write!(
                f,
                "the command's {stream} would be a directory, which reaches the host's \
                 filesystem by path; a launch hands no directory to the command"
            ),
            Error::ListenRefused { address, reason } => write!(
                f,
                "no listener is made at {address} on the sandbox's loopback: {reason}"
            ),
            Error::Listen { address, op, .. } => write!(
                f,
                "could not listen at {address} on the sandbox's loopback while {op}"
            ),
            Error::ProcfsRefused { blocker, .. } => write!(
                f,
                "sandbox setup failed while mounting a fresh procfs for the sandbox's PID \
                 namespace ({blocker})"
            ),
            Error::CgroupRefused { parent, reason } => write!(
                f,
                "the sandbox cannot be given a cgroup beneath {}: {reason}",
                parent.display(),
            ),
            Error::Cgroup { op, path, .. } => write!(
                f,
                "the sandbox's cgroup could not be prepared while {op} {}",
                path.display(),
            ),
            Error::SupervisorUnreceived => f.write_str(
                "the launch was ended because this process could not receive the descriptor \
                 naming the sandbox's supervisor (no descriptor number was free under \
                 RLIMIT_NOFILE, or a security module refused it)",
            ),
        }
    }
}

impl std::error::Error for Error {
    /// The failure underneath, where there is one.
    ///
    /// Every OS failure this type carries is an [`io::Error`], so every one of
    /// them is returned here, including the syscall a recognized exhaustion
    /// came from. The variants that answer `None` carry nothing, since no
    /// syscall failed: [`SupervisorLost`](Self::SupervisorLost) and
    /// [`SupervisorUnreceived`](Self::SupervisorUnreceived) are absences the
    /// library noticed, [`StreamIsDirectory`](Self::StreamIsDirectory) and
    /// [`ListenRefused`](Self::ListenRefused) are refusals it made before it
    /// made any, and [`Listen`](Self::Listen) answers `None` where its helper
    /// ended without saying why.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Config(err) => Some(err),
            Error::IdentityMap(err) => Some(err),
            Error::UsernsUnavailable { source, .. }
            | Error::NamespaceLimitReached { source, .. }
            | Error::KeyQuotaExhausted { source }
            | Error::Setup { source, .. }
            | Error::Spawn { source }
            | Error::Wait { source }
            | Error::Signal { source }
            | Error::KillHandle { source }
            | Error::Terminal { source }
            | Error::TerminalsExhausted { source }
            | Error::ProcfsRefused { source, .. }
            | Error::Cgroup { source, .. } => Some(source),
            Error::Listen { source, .. } => source
                .as_ref()
                .map(|source| source as &(dyn std::error::Error + 'static)),
            Error::SupervisorLost
            | Error::SupervisorUnreceived
            | Error::StreamIsDirectory { .. }
            | Error::ListenRefused { .. }
            | Error::CgroupRefused { .. } => None,
        }
    }
}

impl From<ConfigError> for Error {
    fn from(err: ConfigError) -> Self {
        Error::Config(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every step decodes back to itself, and every step names itself in prose.
    ///
    /// The round trip is structural now — the decoder's match arms are the same
    /// literals the variants are declared with, so a value used twice is a
    /// duplicate discriminant and a duplicate pattern, both of which the
    /// compiler refuses. What this still checks is that the list of steps and
    /// the encoding agree about which values exist, and that no step was left
    /// without a description.
    #[test]
    fn setup_step_wire_round_trip() {
        for &step in SetupStep::ALL {
            assert_eq!(SetupStep::from_wire(step.wire()), Some(step));
            assert!(!step.describe().is_empty(), "{step:?} describes itself");
        }
    }

    #[test]
    fn setup_step_unknown_wire_value_is_rejected() {
        assert_eq!(SetupStep::from_wire(0), None);
        assert_eq!(SetupStep::from_wire(SetupStep::past_the_last()), None);
        assert_eq!(SetupStep::from_wire(u32::MAX), None);
    }

    #[test]
    fn error_display_names_the_failed_step() {
        let err = Error::Setup {
            step: SetupStep::PivotRoot,
            source: io::Error::from_raw_os_error(22),
            detail: None,
        };
        let message = err.to_string();
        assert!(message.contains("pivoting into the rootfs"), "{message}");
    }

    #[test]
    fn a_bare_command_name_is_told_about_path_lookup() {
        let err = ConfigError::CommandNotAbsolute {
            command: PathBuf::from("sh"),
            lookup_offered: true,
        };
        let message = err.to_string();
        assert!(
            message.contains("the command path \"sh\" is not absolute"),
            "{message}"
        );
        assert!(message.contains("enable path lookup"), "{message}");
    }

    #[test]
    fn a_bare_command_name_is_not_offered_path_lookup_a_builder_lacks() {
        // A restriction runs a host command and searches no `PATH`, so the
        // remedy a sandbox's builder offers would be one this builder has not.
        let err = ConfigError::CommandNotAbsolute {
            command: PathBuf::from("sh"),
            lookup_offered: false,
        };
        let message = err.to_string();
        assert!(
            message.contains("the command path \"sh\" is not absolute"),
            "{message}"
        );
        assert!(message.contains("never searches PATH"), "{message}");
        assert!(!message.contains("path lookup"), "{message}");
    }

    #[test]
    fn a_relative_command_path_is_not_told_about_path_lookup() {
        // Path lookup never searches a path containing a slash, so naming it
        // here would send the caller down a road that does not lead anywhere.
        for lookup_offered in [true, false] {
            let err = ConfigError::CommandNotAbsolute {
                command: PathBuf::from("./bin/sh"),
                lookup_offered,
            };
            let message = err.to_string();
            assert_eq!(message, "the command path \"./bin/sh\" is not absolute");
        }
    }

    /// A target the host's root lacks is said to be missing from it; a lookup
    /// that failed otherwise is not, since nothing says the target is absent.
    #[test]
    fn a_mount_target_is_called_missing_only_where_the_lookup_found_nothing() {
        let missing = |errno: i32| {
            ConfigError::MountTargetMissing {
                target: PathBuf::from("/srv/data"),
                source: io::Error::from_raw_os_error(errno),
            }
            .to_string()
        };
        // ENOENT and ENOTDIR.
        for errno in [2, 20] {
            assert!(
                missing(errno).contains("is not in the host's root"),
                "{}",
                missing(errno)
            );
        }
        // EACCES.
        let denied = missing(13);
        assert!(!denied.contains("is not in"), "{denied}");
        assert!(denied.contains("could not be looked up"), "{denied}");
    }

    #[test]
    fn a_reveal_of_an_unhidden_path_names_what_the_host_root_hides() {
        let message = ConfigError::RevealUnhidden {
            path: PathBuf::from("/srv"),
        }
        .to_string();
        assert!(
            message.ends_with(
                "(the host's own root hides /home, /root, /run, /var/run, and /var/tmp)"
            ),
            "{message}"
        );
    }

    #[test]
    fn error_display_includes_the_step_detail() {
        let err = Error::Setup {
            step: SetupStep::BindMount,
            source: io::Error::from_raw_os_error(13),
            detail: Some("/host/data at /data, read-only".to_string()),
        };
        let message = err.to_string();
        assert!(
            message.contains("bind-mounting (/host/data at /data, read-only)"),
            "{message}"
        );
    }
}
