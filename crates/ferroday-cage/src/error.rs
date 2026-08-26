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
//! a relative path with a slash, because path lookup is the remedy for one and
//! misdirection for the other. Attribute strings hold a label well and a
//! paragraph badly, and the paragraph is what a caller acts on.
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
use std::path::PathBuf;

use crate::host::UsernsBlocker;
use crate::spec::command_has_slash;
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
        /// Sweep inherited file descriptors.
        SweepFds = 27 => "sweeping inherited file descriptors",
        /// Fork the command process.
        ForkCommand = 28 => "forking the command process",
        /// Open a pidfd for the command process.
        WatchCommand = 29 => "opening a pidfd for the command process",
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
    }
}

/// Which directory of an overlay root a failure names.
///
/// Every layer is the caller's to place, and each must exist and be resolvable
/// before the mount, so a failure preparing one has to say which it was. The
/// rootfs is the overlay's first lower and keeps its own
/// [`RootfsUnusable`](ConfigError::RootfsUnusable) reporting; `Lower` names the
/// stacked layers beneath it.
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
    /// No rootfs was provided.
    RootfsMissing,
    /// A plain rootfs and an overlay root were both configured, where exactly
    /// one root can be in force.
    ///
    /// The builder's setters keep the two exclusive — [`rootfs`] clears an
    /// overlay and [`overlay`] clears a rootfs — so this arises from a profile
    /// that carries both keys. Honoring either one silently would discard the
    /// other's configuration.
    ///
    /// [`rootfs`]: crate::CageBuilder::rootfs
    /// [`overlay`]: crate::CageBuilder::overlay
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
    /// [`path_lookup`](crate::CageBuilder::path_lookup), while a relative path
    /// containing a slash is never searched and must be made absolute.
    #[non_exhaustive]
    CommandNotAbsolute {
        /// The command path as it was given to the builder.
        command: PathBuf,
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
    /// A bind or raw-mount target must be absolute, must not be `/` itself,
    /// and must not contain `.` or `..` components.
    #[non_exhaustive]
    MountTargetInvalid {
        /// The target path as it was given to the builder.
        path: PathBuf,
    },
    /// A raw mount's flags do not fit the kernel's mount-flags word.
    #[non_exhaustive]
    MountFlagsInvalid {
        /// The flags as they were given to the builder.
        flags: u64,
    },
    /// The working directory path is not absolute.
    #[non_exhaustive]
    WorkdirNotAbsolute {
        /// The working directory as it was given to the builder.
        path: PathBuf,
    },
    /// The hostname is empty or longer than 64 bytes.
    HostnameInvalid,
    /// An environment variable name is empty or contains `=`.
    #[non_exhaustive]
    EnvNameInvalid {
        /// The offending variable name.
        name: std::ffi::OsString,
    },
    /// A configured path, name, or value contains an interior NUL byte.
    EmbeddedNul,
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
    /// A grant path must be absolute and must not contain `.` or `..`
    /// components. In a cage it is a sandbox path, resolved after the pivot;
    /// in a restriction it is a host path.
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
    /// A restriction is confined only by what the running kernel enforces.
    /// When its Landlock grants all fall outside the supported Landlock ABI —
    /// a network grant on a kernel below ABI 4 — or the Landlock LSM is
    /// absent, no ruleset applies and the command would run unconfined, so the
    /// build is refused rather than silently dropping the requested
    /// confinement. A cage in the same case keeps its namespace isolation, so
    /// this is specific to the restriction fallback.
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
    /// cage is unaffected: its network namespace remains the boundary.
    #[non_exhaustive]
    HostNetworkLandlockUnenforceable {
        /// The kernel's supported Landlock ABI, or `None` when the LSM is
        /// absent.
        abi: Option<i32>,
    },
    /// A profile loaded under the restricted policy uses an operation only a
    /// trusted profile may.
    ///
    /// Deserializing a profile straight into a `CageBuilder` trusts it as
    /// code-equivalent configuration. A profile from an untrusted source is
    /// loaded under the restricted policy instead, which forbids the
    /// operations that map host resources into the sandbox or share a host
    /// namespace: bind mounts, raw mounts, an overlay root, host networking,
    /// and sharing the host PID namespace.
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
    /// each delegate's refusal, and the host probe's diagnosis when
    /// [`host::range_map_blocker`](crate::host::range_map_blocker)
    /// identifies one.
    #[non_exhaustive]
    IdentityMapUnavailable {
        /// Why each delegate refused, and any identified host blocker.
        reason: String,
    },
    /// A run-as id is not contained in the identity map.
    ///
    /// Every id the command runs as must be representable in the sandbox's
    /// user namespace. Under the single-identity map the only id is 0; a
    /// range map contains what its extents say.
    #[non_exhaustive]
    RunAsUnmapped {
        /// The unmapped id.
        id: u32,
        /// Which id it is: `"uid"`, `"gid"`, or `"supplementary group"`.
        space: &'static str,
    },
    /// A run-as identity names supplementary groups under the
    /// single-identity map.
    ///
    /// Establishing that map requires denying `setgroups`, so no group list
    /// can ever be set inside it. Supplementary groups need a range gid
    /// map.
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
    /// carry.
    ///
    /// The lower, upper, and work directories are passed to the kernel as a
    /// comma-separated, colon-delimited option string, so a `,` or `:` in any of
    /// their resolved paths would be misparsed. Such a path is refused rather
    /// than silently truncated.
    #[non_exhaustive]
    OverlayPathInvalid {
        /// The offending path.
        path: PathBuf,
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
    /// An overlay's upper layer is the filesystem root.
    ///
    /// The upper needs a parent directory: the work directory the library
    /// derives is a sibling of the upper, and the host overlay preflight runs in
    /// that parent so its scratch entries land beside the upper rather than
    /// inside it. `/` has no parent — and an upper there would put the sandbox's
    /// writes over the whole host root.
    #[non_exhaustive]
    OverlayUpperIsRoot {
        /// The offending path.
        path: PathBuf,
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
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::RootfsMissing => f.write_str("no rootfs was provided"),
            ConfigError::RootContradiction => f.write_str(
                "a rootfs and an overlay root are both configured, but exactly one root is \
                 in force; drop one of the two",
            ),
            ConfigError::RootfsUnusable { path, source } => {
                write!(f, "cannot use {} as the rootfs: {}", path.display(), source,)
            }
            ConfigError::RootfsIsHostRoot => {
                f.write_str("the host root directory cannot be the rootfs")
            }
            ConfigError::CommandMissing => f.write_str("no command was provided"),
            // A bare name is the usual case, and `path_lookup` is exactly its
            // remedy; a relative path with a slash is never searched, so
            // pointing at path lookup there would be misdirection.
            ConfigError::CommandNotAbsolute { command } if !command_has_slash(command) => write!(
                f,
                "the command path {} is not absolute; give an absolute path, or enable \
                 path lookup to resolve a bare command name against the sandbox's PATH",
                command.display(),
            ),
            ConfigError::CommandNotAbsolute { command } => {
                write!(f, "the command path {} is not absolute", command.display())
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
            ConfigError::BindSourceUnusable { path, source } => write!(
                f,
                "cannot use {} as a bind-mount source: {}",
                path.display(),
                source,
            ),
            ConfigError::MountTargetInvalid { path } => write!(
                f,
                "the mount target {} is not a normal absolute path inside the rootfs",
                path.display(),
            ),
            ConfigError::MountFlagsInvalid { flags } => write!(
                f,
                "the raw mount flags {flags:#x} do not fit the kernel's mount-flags word",
            ),
            ConfigError::WorkdirNotAbsolute { path } => write!(
                f,
                "the working directory {} is not absolute",
                path.display(),
            ),
            ConfigError::HostnameInvalid => {
                f.write_str("the hostname is empty or longer than 64 bytes")
            }
            ConfigError::EnvNameInvalid { name } => write!(
                f,
                "the environment variable name {:?} is empty or contains '='",
                name,
            ),
            ConfigError::EmbeddedNul => {
                f.write_str("a configured path, name, or value contains an interior NUL byte")
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
                "the Landlock grant path {} is not a normal absolute path",
                path.display(),
            ),
            ConfigError::RestrictionLandlockUnenforceable { abi } => match abi {
                Some(abi) => write!(
                    f,
                    "the restriction's Landlock grants fall outside the kernel's supported \
                     Landlock ABI ({abi}); a network grant needs ABI 4"
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
            ConfigError::IdentityMapUnavailable { reason } => {
                write!(
                    f,
                    "no delegate can establish the requested identity map: {reason}"
                )
            }
            ConfigError::RunAsUnmapped { id, space } => {
                write!(
                    f,
                    "the run-as {space} {id} is not contained in the identity map"
                )
            }
            ConfigError::RunAsGroupsWithSingleMap => f.write_str(
                "run-as supplementary groups require a range gid map; the single-identity \
                 map denies setgroups",
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
                "the overlay-root path {} contains a ',' or ':', which the overlay mount \
                 options cannot carry",
                path.display(),
            ),
            ConfigError::OverlayLowerMissing => {
                f.write_str("the overlay root names no lower layer to mount over")
            }
            ConfigError::OverlayUpperMissing => {
                f.write_str("the overlay root names no upper layer for its writes")
            }
            ConfigError::OverlayDirUnusable {
                layer,
                path,
                source,
            } => write!(
                f,
                "cannot use {} as the overlay {layer} directory: {}",
                path.display(),
                source,
            ),
            ConfigError::OverlayDirUnowned { layer, path } => write!(
                f,
                "cannot use {} as the overlay {layer} directory: something is already there that \
                 is not a directory the calling user owns; the layer directories are created \
                 fresh, and adopting an entry another user could have planted would send the \
                 sandbox's writes wherever it pointed",
                path.display(),
            ),
            ConfigError::OverlayUpperIsRoot { path } => write!(
                f,
                "cannot use {} as the overlay upper directory: the upper needs a parent \
                 directory, for the work directory beside it and for the host preflight",
                path.display(),
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
        }
    }
}

impl std::error::Error for ConfigError {
    /// The OS failure underneath, for the three refusals that have one.
    ///
    /// Every other variant is a request the builder refused on its own terms —
    /// a contradiction, a missing field, a path that is not the shape it has to
    /// be — where nothing failed and there is nothing to return.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::RootfsUnusable { source, .. }
            | ConfigError::BindSourceUnusable { source, .. }
            | ConfigError::OverlayDirUnusable { source, .. } => Some(source),
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
    /// The host's user-namespace budget is exhausted, so the command could not
    /// enter the nested user namespace that locks the sandbox's mount flags.
    ///
    /// A user namespace is charged against `user.max_user_namespaces` at every
    /// level up to the initial namespace, and a launch holds two: the sandbox's
    /// own, and the nested one the command enters. A host whose ceiling admits
    /// the first and not the second reports this rather than a bare `ENOSPC`.
    ///
    /// Distinct from [`UsernsUnavailable`](Self::UsernsUnavailable), which is a
    /// host that permits no user namespace at all: here the sandbox was built
    /// and only the second namespace was refused.
    NestedUsernsBudgetExhausted,
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
    /// The identity-map delegate failed to establish the range map.
    ///
    /// The delegate runs caller-side against the gated launch, so its own
    /// error is the diagnostic; the gated sandbox is torn down.
    IdentityMap(crate::IdMapError),
    /// A pseudoterminal operation failed: allocating one for the sandbox, or
    /// reading or setting its window size.
    #[non_exhaustive]
    Terminal {
        /// The error the operation failed with.
        source: io::Error,
    },
    /// The host has no free pseudoterminal to allocate.
    ///
    /// Pseudoterminals are a bounded resource — `/proc/sys/kernel/pty/max`
    /// states the ceiling — so a host running many sandboxes at once can
    /// exhaust them. Distinct from [`Terminal`](Self::Terminal) because it is
    /// the one allocation failure that says nothing is wrong with the request:
    /// the same launch succeeds once something releases a terminal.
    TerminalsExhausted,
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
    /// use ferroday_cage::Cage;
    ///
    /// fn launch(rootfs: &str) -> ExitCode {
    ///     match Cage::builder().command("/bin/true").rootfs(rootfs).build() {
    ///         Ok(_cage) => ExitCode::SUCCESS,
    ///         Err(error) => {
    ///             eprintln!("myapp: {error}");
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
            Error::Config(err) => write!(f, "invalid sandbox configuration: {err}"),
            Error::UsernsUnavailable {
                blocker: Some(blocker),
                ..
            } => write!(f, "unprivileged user namespaces are unavailable: {blocker}"),
            Error::UsernsUnavailable {
                blocker: None,
                source,
            } => write!(
                f,
                "the kernel denied user namespace creation ({}); a seccomp filter or LSM \
                 policy may be blocking unprivileged user namespaces",
                source,
            ),
            Error::NestedUsernsBudgetExhausted => f.write_str(
                "the sandbox could not enter its nested user namespace: the host's user \
                 namespace budget is exhausted. Every launch holds two user namespaces; \
                 raise user.max_user_namespaces, or reduce the number of namespaces already \
                 live",
            ),
            Error::Setup {
                step,
                source,
                detail: Some(detail),
            } => write!(
                f,
                "sandbox setup failed while {step} ({detail}): {}",
                source,
            ),
            Error::Setup {
                step,
                source,
                detail: None,
            } => write!(f, "sandbox setup failed while {step}: {}", source,),
            Error::Spawn { source } => {
                write!(f, "could not spawn the sandbox process: {}", source,)
            }
            Error::Wait { source } => write!(
                f,
                "could not collect the sandbox process outcome: {}",
                source,
            ),
            Error::SupervisorLost => {
                f.write_str("the sandbox supervisor exited without reporting the command's outcome")
            }
            Error::Signal { source } => write!(f, "could not signal the sandbox: {}", source,),
            Error::IdentityMap(err) => {
                write!(f, "could not establish the identity map: {err}")
            }
            Error::Terminal { source } => {
                write!(f, "a pseudoterminal operation failed: {}", source,)
            }
            Error::TerminalsExhausted => f.write_str(
                "the host has no free pseudoterminal to allocate; \
                 /proc/sys/kernel/pty/max states the ceiling",
            ),
        }
    }
}

impl std::error::Error for Error {
    /// The failure underneath, where there is one.
    ///
    /// Every OS failure this type carries is an [`io::Error`], so every one of
    /// them is returned here. The variants that answer `None` carry nothing:
    /// [`NestedUsernsBudgetExhausted`](Self::NestedUsernsBudgetExhausted),
    /// [`SupervisorLost`](Self::SupervisorLost), and
    /// [`TerminalsExhausted`](Self::TerminalsExhausted) are conditions the
    /// library recognized rather than syscalls that failed.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Config(err) => Some(err),
            Error::IdentityMap(err) => Some(err),
            Error::UsernsUnavailable { source, .. }
            | Error::Setup { source, .. }
            | Error::Spawn { source }
            | Error::Wait { source }
            | Error::Signal { source }
            | Error::Terminal { source } => Some(source),
            _ => None,
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
        };
        let message = err.to_string();
        assert!(
            message.contains("the command path sh is not absolute"),
            "{message}"
        );
        assert!(message.contains("path lookup"), "{message}");
    }

    #[test]
    fn a_relative_command_path_is_not_told_about_path_lookup() {
        // Path lookup never searches a path containing a slash, so naming it
        // here would send the caller down a road that does not lead anywhere.
        let err = ConfigError::CommandNotAbsolute {
            command: PathBuf::from("./bin/sh"),
        };
        let message = err.to_string();
        assert!(
            message.contains("the command path ./bin/sh is not absolute"),
            "{message}"
        );
        assert!(!message.contains("path lookup"), "{message}");
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
