//! Typed errors for sandbox configuration, spawn, setup, and wait failures.

use std::fmt;
use std::path::PathBuf;

use crate::host::UsernsBlocker;
use crate::spec::command_has_slash;

/// A step of the sandbox setup sequence, performed in the child process.
///
/// When a setup step fails inside the sandbox process, the failure is reported
/// to the caller as [`Error::Setup`], naming the step and the `errno` the
/// kernel returned.
///
/// The explicit discriminants are the wire encoding of the setup-error pipe,
/// which both ends of a single build write and read. They are an
/// implementation detail: a step inserted in a later release renumbers the
/// ones after it, and no discriminant is guaranteed to denote the same step
/// across versions. Do not persist, transmit, or compare them — match on the
/// variant, and use [`Display`](std::fmt::Display) for a human-readable name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u32)]
pub enum SetupStep {
    /// Unshare into the new namespaces.
    Unshare = 1,
    /// Write `deny` to `/proc/self/setgroups`.
    DenySetgroups = 2,
    /// Write the single-identity gid map.
    WriteGidMap = 3,
    /// Write the single-identity uid map.
    WriteUidMap = 4,
    /// Set the sandbox hostname.
    SetHostname = 5,
    /// Bring up the loopback interface in the isolated network namespace.
    ConfigureLoopback = 6,
    /// Make mount propagation recursively private.
    PrivatizeMounts = 7,
    /// Bind the rootfs onto itself so it becomes a mount point.
    BindRootfs = 8,
    /// Enter the rootfs mount point.
    EnterRootfs = 9,
    /// Create a missing mount target inside the rootfs.
    CreateMountTarget = 10,
    /// Open a mount target inside the rootfs.
    OpenMountTarget = 11,
    /// Mount a tmpfs.
    MountTmpfs = 12,
    /// Mount a devpts instance.
    MountDevpts = 13,
    /// Bind-mount a host path into the rootfs.
    BindMount = 14,
    /// Remount a bind mount read-only.
    RemountReadOnly = 15,
    /// Create a symlink inside the rootfs.
    CreateSymlink = 16,
    /// Pivot the root into the rootfs.
    PivotRoot = 17,
    /// Lazily detach the old root mount.
    DetachOldRoot = 18,
    /// Change directory to the new root.
    ChdirNewRoot = 19,
    /// Change to the configured working directory.
    ChdirWorkdir = 20,
    /// Execute the command.
    Exec = 21,
    /// Reset the inherited signal dispositions and mask.
    ResetSignals = 22,
    /// Fork the sandbox init process.
    ForkInit = 23,
    /// Send the supervisor's pidfd back to the caller.
    SendPidfd = 24,
    /// Mount a fresh procfs instance.
    MountProc = 25,
    /// Perform a raw mount.
    MountRaw = 26,
    /// Sweep inherited file descriptors.
    SweepFds = 27,
    /// Fork the command process.
    ForkCommand = 28,
    /// Open a pidfd for the command process.
    WatchCommand = 29,
    /// Wire the command's standard streams.
    WireStdio = 30,
    /// Drop or reduce the command's capabilities.
    DropCapabilities = 31,
    /// Set the no-new-privileges flag before restricting the command.
    SetNoNewPrivs = 32,
    /// Create the Landlock ruleset.
    LandlockCreateRuleset = 33,
    /// Add a rule to the Landlock ruleset.
    LandlockAddRule = 34,
    /// Enforce the Landlock ruleset on the command.
    LandlockRestrictSelf = 35,
    /// Install the seccomp filter.
    InstallSeccomp = 36,
    /// Wait at the launch gate for the caller to attach a network stack and
    /// release the command.
    AwaitNetworkStack = 37,
    /// Wait for the caller's delegate to establish the identity map.
    AwaitIdentityMap = 38,
    /// Lock the securebits that preserve capabilities across the identity
    /// switch.
    SetSecurebits = 39,
    /// Set the command's supplementary groups.
    SetGroups = 40,
    /// Switch to the command's gid.
    SetGid = 41,
    /// Switch to the command's uid.
    SetUid = 42,
    /// Mount the overlay that roots an overlay-rooted cage.
    MountOverlayRoot = 43,
    /// Apply a resource limit to the command.
    SetRlimit = 44,
    /// Start the sandbox's own session, detaching it from the caller's
    /// controlling terminal.
    NewSession = 45,
    /// Make the launch's pseudoterminal the controlling terminal of the
    /// sandbox's session.
    SetControllingTerminal = 46,
}

impl SetupStep {
    /// Every step, in wire order. Used by the wire-protocol tests.
    #[cfg(test)]
    pub(crate) const ALL: [SetupStep; 46] = [
        SetupStep::Unshare,
        SetupStep::DenySetgroups,
        SetupStep::WriteGidMap,
        SetupStep::WriteUidMap,
        SetupStep::SetHostname,
        SetupStep::ConfigureLoopback,
        SetupStep::PrivatizeMounts,
        SetupStep::BindRootfs,
        SetupStep::EnterRootfs,
        SetupStep::CreateMountTarget,
        SetupStep::OpenMountTarget,
        SetupStep::MountTmpfs,
        SetupStep::MountDevpts,
        SetupStep::BindMount,
        SetupStep::RemountReadOnly,
        SetupStep::CreateSymlink,
        SetupStep::PivotRoot,
        SetupStep::DetachOldRoot,
        SetupStep::ChdirNewRoot,
        SetupStep::ChdirWorkdir,
        SetupStep::Exec,
        SetupStep::ResetSignals,
        SetupStep::ForkInit,
        SetupStep::SendPidfd,
        SetupStep::MountProc,
        SetupStep::MountRaw,
        SetupStep::SweepFds,
        SetupStep::ForkCommand,
        SetupStep::WatchCommand,
        SetupStep::WireStdio,
        SetupStep::DropCapabilities,
        SetupStep::SetNoNewPrivs,
        SetupStep::LandlockCreateRuleset,
        SetupStep::LandlockAddRule,
        SetupStep::LandlockRestrictSelf,
        SetupStep::InstallSeccomp,
        SetupStep::AwaitNetworkStack,
        SetupStep::AwaitIdentityMap,
        SetupStep::SetSecurebits,
        SetupStep::SetGroups,
        SetupStep::SetGid,
        SetupStep::SetUid,
        SetupStep::MountOverlayRoot,
        SetupStep::SetRlimit,
        SetupStep::NewSession,
        SetupStep::SetControllingTerminal,
    ];

    /// Decodes a step from its setup-error-pipe wire value.
    pub(crate) fn from_wire(value: u32) -> Option<SetupStep> {
        Some(match value {
            1 => SetupStep::Unshare,
            2 => SetupStep::DenySetgroups,
            3 => SetupStep::WriteGidMap,
            4 => SetupStep::WriteUidMap,
            5 => SetupStep::SetHostname,
            6 => SetupStep::ConfigureLoopback,
            7 => SetupStep::PrivatizeMounts,
            8 => SetupStep::BindRootfs,
            9 => SetupStep::EnterRootfs,
            10 => SetupStep::CreateMountTarget,
            11 => SetupStep::OpenMountTarget,
            12 => SetupStep::MountTmpfs,
            13 => SetupStep::MountDevpts,
            14 => SetupStep::BindMount,
            15 => SetupStep::RemountReadOnly,
            16 => SetupStep::CreateSymlink,
            17 => SetupStep::PivotRoot,
            18 => SetupStep::DetachOldRoot,
            19 => SetupStep::ChdirNewRoot,
            20 => SetupStep::ChdirWorkdir,
            21 => SetupStep::Exec,
            22 => SetupStep::ResetSignals,
            23 => SetupStep::ForkInit,
            24 => SetupStep::SendPidfd,
            25 => SetupStep::MountProc,
            26 => SetupStep::MountRaw,
            27 => SetupStep::SweepFds,
            28 => SetupStep::ForkCommand,
            29 => SetupStep::WatchCommand,
            30 => SetupStep::WireStdio,
            31 => SetupStep::DropCapabilities,
            32 => SetupStep::SetNoNewPrivs,
            33 => SetupStep::LandlockCreateRuleset,
            34 => SetupStep::LandlockAddRule,
            35 => SetupStep::LandlockRestrictSelf,
            36 => SetupStep::InstallSeccomp,
            37 => SetupStep::AwaitNetworkStack,
            38 => SetupStep::AwaitIdentityMap,
            39 => SetupStep::SetSecurebits,
            40 => SetupStep::SetGroups,
            41 => SetupStep::SetGid,
            42 => SetupStep::SetUid,
            43 => SetupStep::MountOverlayRoot,
            44 => SetupStep::SetRlimit,
            45 => SetupStep::NewSession,
            46 => SetupStep::SetControllingTerminal,
            _ => return None,
        })
    }
}

impl fmt::Display for SetupStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SetupStep::Unshare => "unsharing the namespaces",
            SetupStep::DenySetgroups => "denying setgroups",
            SetupStep::WriteGidMap => "writing the gid map",
            SetupStep::WriteUidMap => "writing the uid map",
            SetupStep::SetHostname => "setting the hostname",
            SetupStep::ConfigureLoopback => "bringing up the loopback interface",
            SetupStep::PrivatizeMounts => "making mount propagation private",
            SetupStep::BindRootfs => "binding the rootfs onto itself",
            SetupStep::EnterRootfs => "entering the rootfs mount point",
            SetupStep::CreateMountTarget => "creating a mount target",
            SetupStep::OpenMountTarget => "opening a mount target",
            SetupStep::MountTmpfs => "mounting a tmpfs",
            SetupStep::MountDevpts => "mounting devpts",
            SetupStep::BindMount => "bind-mounting",
            SetupStep::RemountReadOnly => "remounting a bind mount read-only",
            SetupStep::CreateSymlink => "creating a symlink",
            SetupStep::PivotRoot => "pivoting into the rootfs",
            SetupStep::DetachOldRoot => "detaching the old root",
            SetupStep::ChdirNewRoot => "changing to the new root directory",
            SetupStep::ChdirWorkdir => "changing to the working directory",
            SetupStep::Exec => "executing the command",
            SetupStep::ResetSignals => "resetting the inherited signal state",
            SetupStep::ForkInit => "forking the sandbox init process",
            SetupStep::SendPidfd => "publishing the supervisor pidfd",
            SetupStep::MountProc => "mounting a fresh procfs",
            SetupStep::MountRaw => "performing a raw mount",
            SetupStep::SweepFds => "sweeping inherited file descriptors",
            SetupStep::ForkCommand => "forking the command process",
            SetupStep::WatchCommand => "opening a pidfd for the command process",
            SetupStep::WireStdio => "wiring the command's standard streams",
            SetupStep::DropCapabilities => "dropping capabilities",
            SetupStep::SetNoNewPrivs => "setting the no-new-privileges flag",
            SetupStep::LandlockCreateRuleset => "creating the Landlock ruleset",
            SetupStep::LandlockAddRule => "adding a Landlock rule",
            SetupStep::LandlockRestrictSelf => "enforcing the Landlock ruleset",
            SetupStep::InstallSeccomp => "installing the seccomp filter",
            SetupStep::AwaitNetworkStack => "waiting for the network stack to attach",
            SetupStep::AwaitIdentityMap => "waiting for the identity map to be established",
            SetupStep::SetSecurebits => "locking the securebits for the identity switch",
            SetupStep::SetGroups => "setting the supplementary groups",
            SetupStep::SetGid => "switching to the command gid",
            SetupStep::SetUid => "switching to the command uid",
            SetupStep::MountOverlayRoot => "mounting the overlay root",
            SetupStep::SetRlimit => "applying a resource limit",
            SetupStep::NewSession => "starting the sandbox's own session",
            SetupStep::SetControllingTerminal => {
                "making the sandbox's pseudoterminal its controlling terminal"
            }
        })
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
        /// The raw OS error encountered while resolving or opening it.
        errno: i32,
    },
    /// The rootfs resolves to the host root directory.
    RootfsIsHostRoot,
    /// No command was provided.
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
        /// The raw OS error encountered while resolving it.
        errno: i32,
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
    /// would supply its own — an [`Observer`](crate::Observer)'s capture pipes
    /// — is refused rather than silently overriding what the caller said.
    ///
    /// Reported by the launch rather than by
    /// [`build`](crate::CageBuilder::build): the contradiction is between the
    /// frozen sandbox and one particular launch of it, and the same sandbox
    /// launches without contradiction through an entry point that attaches
    /// nothing.
    #[non_exhaustive]
    StreamAttachmentConflict {
        /// The stream whose disposition the attachment contradicts:
        /// `"standard output"` or `"standard error"`.
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
        /// The raw OS error the preparation failed with.
        errno: i32,
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
            ConfigError::RootfsUnusable { path, errno } => write!(
                f,
                "cannot use {} as the rootfs: {}",
                path.display(),
                std::io::Error::from_raw_os_error(*errno),
            ),
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
            ConfigError::BindSourceUnusable { path, errno } => write!(
                f,
                "cannot use {} as a bind-mount source: {}",
                path.display(),
                std::io::Error::from_raw_os_error(*errno),
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
            ConfigError::OverlayDirUnusable { layer, path, errno } => write!(
                f,
                "cannot use {} as the overlay {layer} directory: {}",
                path.display(),
                std::io::Error::from_raw_os_error(*errno),
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

impl std::error::Error for ConfigError {}

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
        /// The raw OS error the kernel returned for namespace creation.
        errno: i32,
    },
    /// A sandbox setup step failed in the child process.
    #[non_exhaustive]
    Setup {
        /// The step that failed.
        step: SetupStep,
        /// The raw OS error the step failed with.
        errno: i32,
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
        /// The raw OS error from pipe creation or fork.
        errno: i32,
    },
    /// The sandbox process outcome could not be collected.
    #[non_exhaustive]
    Wait {
        /// The raw OS error from collecting the outcome: reading the
        /// setup-error, status, or capture pipes, waiting on them, or the wait
        /// itself.
        errno: i32,
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
        /// The raw OS error from the signaling machinery.
        errno: i32,
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
        /// The raw OS error the operation failed with.
        errno: i32,
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
                errno,
            } => write!(
                f,
                "the kernel denied user namespace creation ({}); a seccomp filter or LSM \
                 policy may be blocking unprivileged user namespaces",
                std::io::Error::from_raw_os_error(*errno),
            ),
            Error::Setup {
                step,
                errno,
                detail: Some(detail),
            } => write!(
                f,
                "sandbox setup failed while {step} ({detail}): {}",
                std::io::Error::from_raw_os_error(*errno),
            ),
            Error::Setup {
                step,
                errno,
                detail: None,
            } => write!(
                f,
                "sandbox setup failed while {step}: {}",
                std::io::Error::from_raw_os_error(*errno),
            ),
            Error::Spawn { errno } => write!(
                f,
                "could not spawn the sandbox process: {}",
                std::io::Error::from_raw_os_error(*errno),
            ),
            Error::Wait { errno } => write!(
                f,
                "could not collect the sandbox process outcome: {}",
                std::io::Error::from_raw_os_error(*errno),
            ),
            Error::SupervisorLost => {
                f.write_str("the sandbox supervisor exited without reporting the command's outcome")
            }
            Error::Signal { errno } => write!(
                f,
                "could not signal the sandbox: {}",
                std::io::Error::from_raw_os_error(*errno),
            ),
            Error::IdentityMap(err) => {
                write!(f, "could not establish the identity map: {err}")
            }
            Error::Terminal { errno } => write!(
                f,
                "a pseudoterminal operation failed: {}",
                std::io::Error::from_raw_os_error(*errno),
            ),
            Error::TerminalsExhausted => f.write_str(
                "the host has no free pseudoterminal to allocate; \
                 /proc/sys/kernel/pty/max states the ceiling",
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Config(err) => Some(err),
            Error::IdentityMap(err) => Some(err),
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

    #[test]
    fn setup_step_wire_round_trip() {
        for step in SetupStep::ALL {
            assert_eq!(SetupStep::from_wire(step as u32), Some(step));
        }
    }

    #[test]
    fn setup_step_unknown_wire_value_is_rejected() {
        assert_eq!(SetupStep::from_wire(0), None);
        assert_eq!(SetupStep::from_wire(u32::MAX), None);
    }

    #[test]
    fn error_display_names_the_failed_step() {
        let err = Error::Setup {
            step: SetupStep::PivotRoot,
            errno: 22,
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
            errno: 13,
            detail: Some("/host/data at /data, read-only".to_string()),
        };
        let message = err.to_string();
        assert!(
            message.contains("bind-mounting (/host/data at /data, read-only)"),
            "{message}"
        );
    }
}
