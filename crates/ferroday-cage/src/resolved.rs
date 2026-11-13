//! The inputs a built sandbox will actually apply.
//!
//! A [`CageBuilder`](crate::CageBuilder)'s `get_` accessors report what the
//! caller asked for. This module reports what that request resolved to: the
//! root filesystem the command will see, the environment it will carry, base
//! included, the mounts the sandbox will establish, managed profile included,
//! in the order they will be applied, and the posture the launch will put it
//! under.
//!
//! The distinction matters to a consumer recording provenance. What a build
//! produces depends on the environment and the filesystem the command sees, on
//! the identity it holds and the privileges that come with it, on whether it
//! can reach a network, and on which syscalls will succeed — and neither the
//! caller's own inputs nor a library version number states those directly. [`ResolvedInputs`] does, as data a
//! consumer can stamp into an artifact beside its own version pin.

use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use crate::Network;
use crate::cgroup::CgroupLimit;
use crate::idmap::{IdRange, Identity};
use crate::limits::{Limit, Resource};
use crate::mechanism::{Confinement, IdentityPlan, LaunchPlan, MountAction, RootPlan, seccomp};

/// The root, environment, mounts, and posture a built sandbox will apply.
///
/// Obtained from [`Cage::resolved_inputs`](crate::Cage::resolved_inputs).
///
/// It records the conditions a command runs under, not the command line: the
/// command, its arguments, and its working directory are not part of it. Those
/// are what the caller states, and a launch applies them as stated, the
/// working directory being `/` where none is set, so a consumer's provenance
/// names them beside this record. Two builds that differ only in them produce
/// the same record.
///
/// # Stability
///
/// This type's *shape* follows the compatibility promise like any other public
/// item, and with the `serde` feature that includes the keys it serializes to:
/// a test pins every key the record can carry. Its *contents* do not: they
/// report the defaults in force, and those are explicitly outside the promise
/// — the mount profile and the base environment may both change in a patch
/// release. That is the reason to
/// record the value rather than assume it, and a consumer that needs the
/// contents themselves to be stable should set
/// [`managed_mounts(false)`](crate::CageBuilder::managed_mounts) and
/// [`base_env(false)`](crate::CageBuilder::base_env) and declare its own.
///
/// # Example
///
/// ```no_run
/// # fn main() -> ferroday_cage::Result<()> {
/// let cage = ferroday_cage::Cage::builder()
///     .rootfs("/srv/rootfs/alpine")
///     .command("/usr/bin/make")
///     .build()?;
///
/// let inputs = cage.resolved_inputs();
/// for (name, value) in &inputs.env {
///     println!("{}={}", name.to_string_lossy(), value.to_string_lossy());
/// }
/// for mount in &inputs.mounts {
///     println!("{}", mount.get_target().display());
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "kebab-case")
)]
pub struct ResolvedInputs {
    /// What the command's root filesystem is.
    ///
    /// Its own field rather than a mount: the root is not something the profile
    /// lays over the sandbox, it is what the profile is laid over.
    pub root: ResolvedRoot,
    /// The command's complete environment, sorted by variable name.
    ///
    /// The caller's variables composed over the library's base, or the
    /// caller's alone where [`base_env(false)`](crate::CageBuilder::base_env)
    /// is set.
    #[cfg_attr(feature = "serde", serde(with = "crate::spec::serde_os::string_map"))]
    pub env: Vec<(OsString, OsString)>,
    /// Every mount the sandbox establishes over its root, in the order it
    /// establishes them: the managed profile, then the caller's own, and last
    /// the `resolv.conf` bind that [`Network::Host`] adds.
    ///
    /// Empty for a restriction, which mounts nothing.
    pub mounts: Vec<ResolvedMount>,
    /// The identity map of the sandbox's user namespace: which ids exist
    /// inside it, and what each is on the host.
    pub identity: ResolvedIdentity,
    /// The identity the command switches to before it executes, when one is
    /// configured with [`run_as`](crate::CageBuilder::run_as).
    ///
    /// It is the configured [`Identity`], which a build has validated against
    /// the map in [`identity`](Self::identity) and does not change: every id
    /// is a sandbox-inside one, as that map holds it.
    ///
    /// `None` runs the command as uid 0 of the sandbox's user namespace, or as
    /// the identity in [`present_as`](Self::present_as), or, for a
    /// restriction, as the calling user. Whether a build sees uid 0 or another
    /// id changes what it produces: a Debian build's `Rules-Requires-Root`
    /// handling turns on exactly this.
    ///
    /// A switch to a non-root id clears the command's capabilities, unless a
    /// keep set carries some across it, which [`hardening`](Self::hardening)
    /// records. A configured identity of any id also sets
    /// [`no_new_privileges`](Self::no_new_privileges). Under a gid map of the
    /// caller's own gid alone, the single-identity map's or a range map's, no
    /// supplementary group can be set. The command then keeps the list it
    /// inherited, every entry of which the map does not hold presenting as the
    /// overflow gid.
    pub run_as: Option<Identity>,
    /// The identity the single-identity map presents the caller to the
    /// command as, when one is configured with
    /// [`present_as`](crate::CageBuilder::present_as).
    ///
    /// [`PresentedIdentity::Own`](crate::PresentedIdentity::Own) is reported
    /// as the ids it resolved to when the sandbox was built. It carries no
    /// supplementary groups, and is never set alongside a range map. The
    /// command runs as this identity without a switch, and holds no capability
    /// across its `execve` beyond those [`hardening`](Self::hardening) records
    /// a keep set carrying. It also sets
    /// [`no_new_privileges`](Self::no_new_privileges). On the host the command
    /// is still the caller.
    pub present_as: Option<Identity>,
    /// Whether the command runs with the no-new-privileges flag set, so that a
    /// set-user-ID binary or a file capability grants nothing across
    /// `execve`.
    ///
    /// A run-as identity sets it, so does a presented identity, and so does
    /// any hardening control. A build
    /// whose packages reach for `sudo` or a capability-bearing helper behaves
    /// differently under it.
    pub no_new_privileges: bool,
    /// The network the command can reach.
    ///
    // The sentence links a feature-gated item, so its doc text is gated on the
    // feature: present in the canonical all-features build, absent — link and
    // all — from a no-feature `cargo doc`.
    #[cfg_attr(
        feature = "netstack",
        doc = "A [`NetStack`](crate::NetStack) is not visible here: a stack attaches to"
    )]
    #[cfg_attr(
        feature = "netstack",
        doc = "
a pending launch after the cage is built, so what this reports is the
namespace the sandbox creates, not what may later be plugged into it.
"
    )]
    pub network: Network,
    /// What the network filter refuses, where the sandbox carries it: under
    /// [`Network::Isolated`] and [`Network::None`], which give the sandbox a
    /// network namespace of its own.
    ///
    /// `None` under [`Network::Host`] and for a restriction, neither of which
    /// installs the filter. The filter is the library's own rather than a
    /// policy of the caller's, so what it refuses follows the library version
    /// rather than the configuration. It is recorded for the reason
    /// [`hardening`](Self::hardening) is: a configure test that probes one of
    /// these calls reads the refusal as an absent feature.
    pub network_filter: Option<ResolvedNetworkFilter>,
    /// Whether the command runs in a PID namespace of the sandbox's own, under
    /// the sandbox's init.
    ///
    /// Without one the command shares the caller's PID namespace: `/proc` is
    /// the host's, the command sees and can signal the caller's processes, and
    /// its descendants can outlive it. `false` for a restriction, which creates
    /// no namespace.
    pub pid_namespace: bool,
    /// The hostname the command sees.
    ///
    /// The one configured with [`hostname`](crate::CageBuilder::hostname), or
    /// else the host's own: a sandbox's UTS namespace starts with the host's
    /// name, and a restriction shares the host's. The host's is read when the
    /// record is made, which is the name a launch made then inherits.
    #[cfg_attr(feature = "serde", serde(with = "crate::spec::serde_os::string"))]
    pub hostname: OsString,
    /// Where the command's three standard streams are wired.
    pub streams: ResolvedStreams,
    /// The resource limits applied to the command process, in the order they
    /// are applied.
    pub rlimits: Vec<ResolvedRlimit>,
    /// The cgroup each launch is placed in, with the limits it holds the
    /// sandbox's whole process tree to, or the cgroup limits a launch runs
    /// without.
    ///
    /// `None` where the configuration names neither a cgroup parent nor a
    /// cgroup limit.
    pub cgroup: Option<ResolvedCgroup>,
    /// The hardening controls the command runs under.
    ///
    /// Present whether or not the `hardening` feature is compiled in, reporting
    /// [`Unavailable`](ResolvedHardening::Unavailable) when it is not. A record
    /// that simply omitted the key could not be told apart from one written
    /// before the key existed, and a provenance record has to be readable
    /// without knowing which build wrote it.
    pub hardening: ResolvedHardening,
}

/// What a built sandbox's root filesystem is.
///
/// The root is a first-order build input on the same argument this module
/// exists on — it is the filesystem the command sees — and it is not a mount:
/// a plain rootfs is pivoted into, and an overlay is assembled before every
/// mount the profile lays over it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(
        tag = "kind",
        rename_all = "kebab-case",
        rename_all_fields = "kebab-case"
    )
)]
pub enum ResolvedRoot {
    /// No root swap: the command runs against the host's own filesystem.
    // The sentence links a feature-gated item, so its doc text is gated on the
    // feature: present in the canonical all-features build, absent — link and
    // all — from a no-feature `cargo doc`.
    #[cfg_attr(
        feature = "hardening",
        doc = "That is what a [`Restriction`](crate::Restriction)'s command sees."
    )]
    Host,
    /// A plain rootfs, pivoted into.
    #[non_exhaustive]
    Plain {
        /// The rootfs as the build resolved it: an absolute, canonicalized host
        /// path.
        path: PathBuf,
    },
    /// An overlay assembled over the rootfs and pivoted into.
    #[non_exhaustive]
    Overlay {
        /// The lower layers, base first — the reverse of the kernel's own
        /// highest-precedence-first option order.
        lower: Vec<PathBuf>,
        /// The upper layer, where the sandbox's writes land.
        upper: PathBuf,
        /// The work directory the overlay requires beside the upper.
        work: PathBuf,
    },
    /// An empty root: a tmpfs of the sandbox's own, holding only what the
    /// mount profile creates in it, and read-only once the profile is in
    /// place. See [`CageBuilder::empty_rootfs`](crate::CageBuilder::empty_rootfs).
    Empty,
    /// The host's own tree, cloned and read-only throughout, with the profile
    /// laid over it. See
    /// [`CageBuilder::host_rootfs`](crate::CageBuilder::host_rootfs).
    HostReadOnly,
}

/// The identity map a built sandbox's user namespace carries.
///
/// Which ids exist inside the sandbox changes what a build produces: a file's
/// recorded ownership follows from it, and a `chown` to an id the map does not
/// hold fails. The id the command itself runs as is
/// [`ResolvedInputs::run_as`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(
        tag = "kind",
        rename_all = "kebab-case",
        rename_all_fields = "kebab-case"
    )
)]
pub enum ResolvedIdentity {
    /// No user namespace, so no map: the command runs as the calling user.
    // Gated for the reason `ResolvedRoot::Host`'s second sentence is.
    #[cfg_attr(
        feature = "hardening",
        doc = "That is what a [`Restriction`](crate::Restriction)'s command holds."
    )]
    Caller,
    /// The single-identity map: the calling user is root inside the sandbox
    /// and no other id is mapped.
    ///
    /// The command sees that one id as root too, unless
    /// [`ResolvedInputs::present_as`] names the identity it is presented as.
    Single,
    /// A range map, written from outside the namespace by a delegate.
    #[non_exhaustive]
    Ranged {
        /// The uid extents, in the order they are written.
        uid: Vec<IdRange>,
        /// The gid extents, in the order they are written.
        gid: Vec<IdRange>,
    },
}

/// Where a built sandbox wires the command's three standard streams.
///
/// What a build produces depends on what the command sees, and these are that:
/// `isatty` on the standard streams steers debconf's frontend choice, a
/// compiler's color diagnostics, and every progress display, and the
/// standard-input disposition additionally decides whether the command runs in
/// the caller's session.
///
/// # What this reports
///
/// The plan — what every launch of the sandbox shares. A launch that attaches a
/// conduit of its own supersedes it at that one call site, in two ways:
///
/// - a capturing launch ([`Cage::run_with`](crate::Cage::run_with),
///   [`Cage::output`](crate::Cage::output)) puts a pipe on the output pair;
/// - a terminal launch
///   ([`Cage::spawn_terminal`](crate::Cage::spawn_terminal),
///   [`Cage::spawn_pending_terminal`](crate::Cage::spawn_pending_terminal))
///   wires a pseudoterminal replica onto all three, because a terminal is one
///   stream rather than three.
///
/// That act belongs to the caller that made it, and recording it does too. The
/// dispositions here are refused against a launch that would contradict them,
/// so a record and a launch cannot disagree about a stream the caller directed
/// somewhere. [`Inherit`](ResolvedStdio::Inherit) states no destination and so
/// contradicts nothing: a record reading `Inherit` on all three is what a cage
/// launched with a terminal reports, and it is a true statement about the plan
/// rather than about what that launch's command saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "kebab-case")
)]
pub struct ResolvedStreams {
    /// Where the command's standard input reads from.
    pub stdin: ResolvedStdio,
    /// Where the command's standard output is written.
    pub stdout: ResolvedStdio,
    /// Where the command's standard error is written.
    pub stderr: ResolvedStdio,
}

/// One standard stream's disposition, by kind.
///
/// The counterpart of [`Stdio`](crate::Stdio), reduced to the kind of wiring: a
/// descriptor is reported as [`Fd`](Self::Fd) and not otherwise described,
/// because it names a live resource of the caller's rather than anything a
/// record could carry forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "kebab-case")
)]
pub enum ResolvedStdio {
    /// The stream is left as the launch inherited it.
    Inherit,
    /// The stream is wired to `/dev/null`.
    Null,
    /// The stream is wired to a descriptor the caller supplied.
    Fd,
}

/// The seccomp filter a built sandbox with a network namespace of its own
/// installs, closing the routes out that such a namespace does not cover.
///
/// [`Network`] describes the routes and why each answer is the one it is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "kebab-case")
)]
pub struct ResolvedNetworkFilter {
    /// Each syscall the filter refuses, with the errno it answers in place of
    /// running the call. Every other syscall the filter allows.
    pub refusals: Vec<ResolvedSyscallRefusal>,
}

/// One syscall a seccomp filter refuses, and the errno the command reads from
/// it instead.
///
/// The refusal applies at every entry point the host's kernel presents that
/// has the call: the 64-bit ABI, x32, and the 32-bit compat layer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "kebab-case")
)]
pub struct ResolvedSyscallRefusal {
    /// The syscall, by its name in the kernel's syscall table.
    ///
    /// A name rather than a number, because the number differs from one entry
    /// point to the next where the name does not.
    pub syscall: String,
    /// The value the low 32 bits of the call's first argument hold where the
    /// call is refused: the address family for `socket`, and the call number
    /// for `socketcall`.
    ///
    /// `None` where the call is refused whatever its arguments.
    pub first_argument: Option<u32>,
    /// The errno the call answers with, as the kernel numbers it.
    pub errno: u16,
}

/// One resource limit a built sandbox applies to the command process.
///
/// A build that adapts its parallelism to `RLIMIT_NOFILE`, or that fails a link
/// under `RLIMIT_AS`, produces different output, so the limits in force belong
/// in the record beside the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "kebab-case")
)]
pub struct ResolvedRlimit {
    /// The kernel resource the limit governs.
    pub resource: Resource,
    /// The soft limit: what the kernel enforces.
    pub soft: Limit,
    /// The hard limit: the ceiling the command may raise its soft limit to.
    pub hard: Limit,
}

/// The cgroup a built sandbox's launches are placed in, and the limits on the
/// whole process tree.
///
/// A tree held to a memory or a process ceiling can fail a build that an
/// unbounded one completes, so the limits belong in the record beside the
/// resource limits. Limits a launch runs without are recorded as well, so a
/// record shows them dropped rather than leaving them out.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(
        tag = "kind",
        rename_all = "kebab-case",
        rename_all_fields = "kebab-case"
    )
)]
pub enum ResolvedCgroup {
    /// Each launch creates a cgroup of its own beneath `parent` and holds the
    /// sandbox's whole process tree to `limits`. See
    /// [`CageBuilder::cgroup_parent`](crate::CageBuilder::cgroup_parent).
    #[non_exhaustive]
    Applied {
        /// The delegated directory each launch's cgroup is created beneath.
        parent: PathBuf,
        /// The limits, one of each kind, in a fixed order. Serialized as the
        /// profile format's `[cgroup]` table spells them.
        #[cfg_attr(
            feature = "serde",
            serde(serialize_with = "crate::cgroup::serialize_limits")
        )]
        limits: Vec<CgroupLimit>,
    },
    /// The limits are not applied. The configuration does not require them,
    /// with [`cgroup_required(false)`](crate::CageBuilder::cgroup_required),
    /// and names no parent, so a launch runs without them.
    #[non_exhaustive]
    NotApplied {
        /// The limits a launch runs without, as
        /// [`Applied::limits`](Self::Applied::limits) holds them.
        #[cfg_attr(
            feature = "serde",
            serde(serialize_with = "crate::cgroup::serialize_limits")
        )]
        limits: Vec<CgroupLimit>,
    },
}

/// The hardening controls a built sandbox applies before `execve`.
///
/// The subtlest of the postures to record and the one most worth recording: a
/// seccomp policy changes which syscalls succeed, and a configure test that
/// probes a syscall reads the refusal as an absent feature, so two builds under
/// two policies can differ with nothing else to show for it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(
        tag = "kind",
        rename_all = "kebab-case",
        rename_all_fields = "kebab-case"
    )
)]
pub enum ResolvedHardening {
    /// The hardening layer is not compiled into this build, so no Landlock
    /// ruleset, seccomp filter, or capability drop can apply.
    ///
    /// Distinct from an [`Applied`](Self::Applied) posture whose controls are
    /// all empty, which is a build that *could* have hardened and did not.
    Unavailable,
    /// The hardening layer is compiled in; these are the controls in force.
    /// Every field empty is a sandbox that applies no hardening.
    #[non_exhaustive]
    Applied {
        /// The Landlock filesystem grants, in the order they were declared.
        landlock_fs: Vec<ResolvedLandlockFs>,
        /// The Landlock network grants, in the order they were declared.
        landlock_net: Vec<ResolvedLandlockNet>,
        /// Whether the ruleset handles `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`: the
        /// unix-socket restriction, which refuses a connection to a pathname
        /// socket created outside the command's domain except beneath a path
        /// granted it.
        ///
        /// What the build kept: the default the host's own root applies is
        /// dropped at build on a kernel below Landlock ABI 9.
        landlock_resolve_unix: bool,
        /// The `LANDLOCK_SCOPE_*` flags the ruleset scopes, as the kernel spells
        /// them; zero when none applies.
        ///
        /// A sandbox reports what it asked for, before the command stage masks it
        /// to the running kernel's ABI. A restriction starts with every scope
        /// and drops at build the default ones the kernel cannot enforce, so it
        /// reports what the build kept.
        landlock_scope: u64,
        /// The installed seccomp filter's length in BPF instructions; `None`
        /// when no filter is installed.
        ///
        /// The program itself is not reported: it is thousands of instructions
        /// and means nothing to a reader. The length is what distinguishes one
        /// policy from another at a glance, and a consumer that needs to pin
        /// the exact program has the policy it supplied.
        seccomp_instructions: Option<usize>,
        /// The capability bits retained across the drop.
        ///
        /// `None` drops nothing, leaving the set the identity switch leaves:
        /// every capability of the namespace's root, or none at all for a
        /// non-root [`run_as`](ResolvedInputs::run_as).
        keep_capabilities: Option<u64>,
        /// The Landlock ABI the running kernel supports, read when the record
        /// is made.
        ///
        /// The grants and the scope above are what the posture requests, and
        /// the command stage masks them to this ABI, so two hosts recording the
        /// same requests can enforce different postures; this is what tells
        /// them apart. `None` where the posture requests nothing of Landlock,
        /// which the ABI then does not touch, and where the kernel offers no
        /// Landlock, under which a request fails at launch.
        landlock_abi: Option<i32>,
    },
}

/// One Landlock filesystem grant a built sandbox enrols.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "kebab-case")
)]
pub struct ResolvedLandlockFs {
    /// The granted path, as the command sees it after the root swap.
    pub path: PathBuf,
    /// The `LANDLOCK_ACCESS_FS_*` rights allowed beneath the path, as the
    /// kernel spells them.
    ///
    /// This is what the build kept of the grant: the rights it asks for, less
    /// `RESOLVE_UNIX` where the unix-socket restriction does not apply, which
    /// is where it is off, by default or by request, and where it is only the
    /// host root's default and the kernel cannot enforce it. It is reported
    /// before the command stage narrows it further at launch: to the running
    /// kernel's ABI, and, where the path names something other than a
    /// directory, to the rights that act on a file.
    // Gated for the reason `ResolvedRoot::Host`'s second sentence is: the type
    // is reported whether or not the feature is compiled in, but the type it
    // contrasts with is not.
    #[cfg_attr(
        feature = "hardening",
        doc = "They are the kernel's own bits rather than [`FsAccess`](crate::FsAccess)'s."
    )]
    pub access: u64,
}

/// One Landlock network grant a built sandbox enrols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "kebab-case")
)]
pub struct ResolvedLandlockNet {
    /// The TCP port the grant governs.
    pub port: u16,
    /// The `LANDLOCK_ACCESS_NET_*` rights allowed on the port, as the kernel
    /// spells them and before the command stage masks them to its ABI.
    pub access: u64,
}

/// One mount a built sandbox will establish.
///
/// The resolved counterpart of [`Mount`](crate::Mount): where that records
/// what a caller declared, this records every mount the sandbox performs,
/// including the ones the managed profile contributes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(
        tag = "kind",
        rename_all = "kebab-case",
        rename_all_fields = "kebab-case"
    )
)]
pub enum ResolvedMount {
    /// A tmpfs.
    #[non_exhaustive]
    Tmpfs {
        /// The mount point inside the sandbox.
        target: PathBuf,
        /// The kernel's raw `MS_*` flags.
        flags: u64,
        /// The filesystem data string.
        data: String,
    },
    /// A procfs instance.
    #[non_exhaustive]
    Procfs {
        /// The mount point inside the sandbox.
        target: PathBuf,
    },
    /// A devpts instance.
    #[non_exhaustive]
    Devpts {
        /// The mount point inside the sandbox.
        target: PathBuf,
        /// The filesystem data string.
        data: String,
    },
    /// A bind of a host path.
    #[non_exhaustive]
    Bind {
        /// The host path bound in.
        source: PathBuf,
        /// The mount point inside the sandbox.
        target: PathBuf,
        /// Whether the bind is remounted read-only.
        read_only: bool,
    },
    /// A mount whose parameters go to the kernel verbatim.
    ///
    /// The optional fields report `None` both for a parameter that was never
    /// set and for one set to the empty string: the two are frozen alike, and
    /// the kernel receives the same nothing from either.
    #[non_exhaustive]
    Raw {
        /// The mount source, when one was given.
        source: Option<PathBuf>,
        /// The mount point inside the sandbox.
        target: PathBuf,
        /// The filesystem type, when one was given.
        fstype: Option<String>,
        /// The kernel's raw `MS_*` flags.
        flags: u64,
        /// The filesystem data string, when one was given.
        data: Option<String>,
    },
    /// A symlink created inside the rootfs.
    ///
    /// Not a mount in the kernel's sense, but part of what the mount profile
    /// establishes — the five `/dev` symlinks arrive this way, as does each
    /// [`Symlink`](crate::Symlink) of the caller's — and so part of the
    /// filesystem the command sees.
    #[non_exhaustive]
    Symlink {
        /// The link's own path inside the sandbox.
        path: PathBuf,
        /// The path the link points at, as written.
        target: PathBuf,
    },
    /// A hidden path: an empty directory or an empty file, read-only, where
    /// something stands at the path. See [`Hide`](crate::Hide). The
    /// [host's own root](crate::CageBuilder::host_rootfs)'s default hides
    /// arrive this way.
    #[non_exhaustive]
    Hide {
        /// The path inside the sandbox it hides.
        target: PathBuf,
    },
    /// A path made read-only where it stands. See
    /// [`ReadOnly`](crate::ReadOnly).
    #[non_exhaustive]
    ReadOnly {
        /// The path inside the sandbox it makes read-only.
        target: PathBuf,
    },
}

impl ResolvedMount {
    /// The path inside the sandbox this mount is established at.
    ///
    /// For a [`Symlink`](Self::Symlink) this is the link itself, not the path
    /// it points at.
    pub fn get_target(&self) -> &std::path::Path {
        match self {
            ResolvedMount::Tmpfs { target, .. }
            | ResolvedMount::Procfs { target }
            | ResolvedMount::Devpts { target, .. }
            | ResolvedMount::Bind { target, .. }
            | ResolvedMount::Raw { target, .. }
            | ResolvedMount::Hide { target }
            | ResolvedMount::ReadOnly { target } => target,
            ResolvedMount::Symlink { path, .. } => path,
        }
    }
}

impl ResolvedInputs {
    /// Projects a frozen launch plan onto the public shape.
    ///
    /// Runs on the caller's own thread, on demand: nothing here is computed
    /// during a launch, and a [`Cage`](crate::Cage) does not carry the result.
    pub(crate) fn project(plan: &LaunchPlan) -> ResolvedInputs {
        ResolvedInputs {
            root: project_root(plan),
            env: plan.env.iter().map(split_env).collect(),
            mounts: plan
                .ops
                .iter()
                .map(|op| project_mount(&op.action))
                .collect(),
            identity: project_identity(plan),
            run_as: plan.run_as.as_ref().map(|run_as| {
                Identity::new(run_as.uid.as_raw(), run_as.gid.as_raw())
                    .groups(run_as.groups.iter().flatten().map(|gid| gid.as_raw()))
            }),
            present_as: plan
                .present_as
                .map(|presented| Identity::new(presented.uid, presented.gid)),
            no_new_privileges: no_new_privileges(plan),
            network: plan.network,
            network_filter: project_network_filter(plan),
            pid_namespace: plan.pid_namespace,
            hostname: project_hostname(plan),
            streams: ResolvedStreams {
                stdin: project_stdio(&plan.stdin),
                stdout: project_stdio(&plan.stdout),
                stderr: project_stdio(&plan.stderr),
            },
            rlimits: plan.rlimits.iter().map(project_rlimit).collect(),
            cgroup: project_cgroup(plan),
            hardening: project_hardening(plan),
        }
    }
}

/// Projects the cgroup each launch is placed in, or the limits a launch runs
/// without.
fn project_cgroup(plan: &LaunchPlan) -> Option<ResolvedCgroup> {
    match &plan.cgroup {
        Some(cgroup) => Some(ResolvedCgroup::Applied {
            parent: cgroup.parent.clone(),
            limits: cgroup.limits.clone(),
        }),
        None if !plan.cgroup_unapplied.is_empty() => Some(ResolvedCgroup::NotApplied {
            limits: plan.cgroup_unapplied.clone(),
        }),
        None => None,
    }
}

/// Projects the sandbox's root filesystem.
///
/// The root is reported from the plan's own root rather than from `ops`
/// because it is not in them: the setup establishes it before the profile's
/// mounts, which land in it.
fn project_root(plan: &LaunchPlan) -> ResolvedRoot {
    match &plan.root {
        RootPlan::Host => ResolvedRoot::Host,
        RootPlan::Bind(path) => ResolvedRoot::Plain {
            path: PathBuf::from(OsString::from_vec(path.as_bytes().to_vec())),
        },
        RootPlan::Overlay { overlay, .. } => ResolvedRoot::Overlay {
            lower: overlay.lower.clone(),
            upper: overlay.upper.clone(),
            work: overlay.work.clone(),
        },
        RootPlan::Empty => ResolvedRoot::Empty,
        RootPlan::HostReadOnly => ResolvedRoot::HostReadOnly,
    }
}

/// Projects the network filter the launch installs, if it installs one.
///
/// The question is the launch's own, asked of the same plan, and the refusals
/// are the ones the unit tests hold the installed program to.
fn project_network_filter(plan: &LaunchPlan) -> Option<ResolvedNetworkFilter> {
    seccomp::installs_network_filter(plan).then(|| ResolvedNetworkFilter {
        refusals: seccomp::NETWORK_FILTER_REFUSALS
            .iter()
            .map(|refusal| ResolvedSyscallRefusal {
                syscall: refusal.syscall.to_string(),
                first_argument: refusal.first_argument,
                errno: refusal.errno,
            })
            .collect(),
    })
}

/// Projects the hostname the command sees: the configured one, or the host's.
///
/// No configured name leaves the UTS namespace with the one it started with,
/// which is the caller's, so that is read here.
fn project_hostname(plan: &LaunchPlan) -> OsString {
    let name = match &plan.hostname {
        Some(name) => name.as_bytes().to_vec(),
        None => rustix::system::uname().nodename().to_bytes().to_vec(),
    };
    OsString::from_vec(name)
}

/// Projects one stream's disposition onto its kind.
fn project_stdio(plan: &crate::mechanism::StdioPlan) -> ResolvedStdio {
    match plan {
        crate::mechanism::StdioPlan::Inherit => ResolvedStdio::Inherit,
        crate::mechanism::StdioPlan::Null => ResolvedStdio::Null,
        crate::mechanism::StdioPlan::Fd(_) => ResolvedStdio::Fd,
    }
}

/// Projects the identity the command holds.
///
/// A restriction creates no user namespace, so its plan's `Single` map is a
/// placeholder rather than a map that is applied; the confinement is what
/// distinguishes the two.
fn project_identity(plan: &LaunchPlan) -> ResolvedIdentity {
    match plan.confinement {
        #[cfg(feature = "hardening")]
        Confinement::Restriction => ResolvedIdentity::Caller,
        Confinement::Container => match &plan.identity {
            IdentityPlan::Single => ResolvedIdentity::Single,
            IdentityPlan::Ranged { map, .. } => ResolvedIdentity::Ranged {
                uid: map.uid().to_vec(),
                gid: map.gid().to_vec(),
            },
        },
    }
}

/// Whether the launch sets the no-new-privileges flag on the command.
///
/// The two places the launch sets it decide this: the identity switch sets it
/// whenever a run-as or a presented identity is configured, and the hardening
/// layer whenever its plan holds any control. A restriction's plan always does,
/// since it drops every capability.
fn no_new_privileges(plan: &LaunchPlan) -> bool {
    #[cfg(feature = "hardening")]
    let hardened = !plan.hardening.is_empty();
    #[cfg(not(feature = "hardening"))]
    let hardened = false;
    plan.run_as.is_some() || plan.present_as.is_some() || hardened
}

/// Projects one frozen resource limit.
///
/// The plan carries the resource the caller named alongside the kernel number
/// it was lowered to, so this reads it back rather than searching for a
/// resource that translates to the same number. A provenance record is the one
/// value that cannot afford to answer approximately, and a reverse lookup has
/// no honest answer when it finds nothing.
fn project_rlimit(plan: &crate::mechanism::RlimitPlan) -> ResolvedRlimit {
    ResolvedRlimit {
        resource: plan.resource,
        soft: plan.limit.current.map_or(Limit::UNLIMITED, Limit::of),
        hard: plan.limit.maximum.map_or(Limit::UNLIMITED, Limit::of),
    }
}

/// Projects the hardening posture.
///
/// Always reports something: without the feature there is nothing that could
/// have been applied, which is itself the fact a provenance record needs.
fn project_hardening(plan: &LaunchPlan) -> ResolvedHardening {
    #[cfg(not(feature = "hardening"))]
    {
        let _ = plan;
        ResolvedHardening::Unavailable
    }
    #[cfg(feature = "hardening")]
    {
        ResolvedHardening::Applied {
            landlock_fs: plan
                .hardening
                .landlock
                .iter()
                .map(|rule| ResolvedLandlockFs {
                    path: PathBuf::from(OsString::from_vec(rule.path.as_bytes().to_vec())),
                    access: rule.access,
                })
                .collect(),
            landlock_net: plan
                .hardening
                .landlock_net
                .iter()
                .map(|rule| ResolvedLandlockNet {
                    port: rule.port,
                    access: rule.access,
                })
                .collect(),
            landlock_resolve_unix: plan.hardening.landlock_handled
                & crate::hardening::fs_access::RESOLVE_UNIX
                != 0,
            landlock_scope: plan.hardening.landlock_scoped,
            seccomp_instructions: plan.hardening.seccomp.as_ref().map(Vec::len),
            keep_capabilities: plan.hardening.keep_caps,
            landlock_abi: requests_landlock(&plan.hardening)
                .then(crate::mechanism::probe_landlock_abi)
                .flatten(),
        }
    }
}

/// Whether a hardening plan asks anything of Landlock: a grant of either kind,
/// a scope, or the unix-socket restriction.
#[cfg(feature = "hardening")]
fn requests_landlock(plan: &crate::mechanism::HardeningPlan) -> bool {
    !plan.landlock.is_empty()
        || !plan.landlock_net.is_empty()
        || plan.landlock_scoped != 0
        || plan.landlock_handled != 0
}

/// Splits a frozen `NAME=value` entry back into its pair.
///
/// The environment is lowered to `NAME=value` byte strings at build time
/// because that is what `execve` takes. Splitting at the first `=` inverts
/// that exactly: a name may not contain `=` — the builder rejects one that
/// does — so the first separator is always the right one, and a value
/// containing `=` is preserved whole.
fn split_env(entry: &CString) -> (OsString, OsString) {
    let bytes = entry.as_bytes();
    match bytes.iter().position(|byte| *byte == b'=') {
        Some(index) => (
            OsString::from_vec(bytes[..index].to_vec()),
            OsString::from_vec(bytes[index + 1..].to_vec()),
        ),
        // Unreachable through the builder, which composes every entry with a
        // separator. Reporting the whole entry as a name beats panicking in an
        // inspection method.
        None => (OsString::from_vec(bytes.to_vec()), OsString::new()),
    }
}

/// Projects one internal mount action onto the public shape.
fn project_mount(action: &MountAction) -> ResolvedMount {
    match action {
        MountAction::Tmpfs {
            target,
            flags,
            data,
        } => ResolvedMount::Tmpfs {
            target: absolute(target),
            // Widened to match `RawMount::get_flags`, which is `u64` so the
            // public surface does not depend on the kernel type's width.
            flags: u64::from(flags.bits()),
            data: lossy(data),
        },
        MountAction::Procfs { target } => ResolvedMount::Procfs {
            target: absolute(target),
        },
        MountAction::Devpts { target, data } => ResolvedMount::Devpts {
            target: absolute(target),
            data: lossy(data),
        },
        MountAction::Bind {
            source,
            target,
            read_only,
        } => ResolvedMount::Bind {
            source: PathBuf::from(OsString::from_vec(source.as_bytes().to_vec())),
            target: absolute(target),
            read_only: *read_only,
        },
        MountAction::Raw {
            source,
            target,
            fstype,
            flags,
            data,
        } => ResolvedMount::Raw {
            // An unset source, fstype, or data is frozen as an empty string,
            // which is what the kernel receives either way, so the projection
            // reads empty back as absent.
            source: optional(source).map(PathBuf::from),
            target: absolute(target),
            fstype: optional(fstype).map(|value| value.to_string_lossy().into_owned()),
            // Widened to match `RawMount::get_flags`, which is `u64` so the
            // public surface does not depend on the kernel type's width.
            flags: u64::from(flags.bits()),
            data: optional(data).map(|value| value.to_string_lossy().into_owned()),
        },
        MountAction::Symlink {
            parent,
            leaf,
            content,
        } => {
            let mut path = absolute(parent);
            path.push(OsString::from_vec(leaf.as_bytes().to_vec()));
            ResolvedMount::Symlink {
                path,
                target: PathBuf::from(OsString::from_vec(content.as_bytes().to_vec())),
            }
        }
        MountAction::Hide { target } => ResolvedMount::Hide {
            target: absolute(target),
        },
        MountAction::ReadOnly { target } => ResolvedMount::ReadOnly {
            target: absolute(target),
        },
    }
}

/// Turns a rootfs-relative frozen target into the absolute path it occupies
/// inside the sandbox, which is how a consumer reading the record thinks of
/// it.
fn absolute(target: &CString) -> PathBuf {
    let mut path = Vec::with_capacity(target.as_bytes().len() + 1);
    path.push(b'/');
    path.extend_from_slice(target.as_bytes());
    PathBuf::from(OsString::from_vec(path))
}

/// Reads a frozen optional field: empty means it was never set.
fn optional(value: &CString) -> Option<OsString> {
    if value.as_bytes().is_empty() {
        None
    } else {
        Some(OsString::from_vec(value.as_bytes().to_vec()))
    }
}

/// Reads a frozen data string. These are composed by the crate itself from
/// ASCII literals, so the conversion never actually loses anything.
fn lossy(value: &CString) -> String {
    String::from_utf8_lossy(value.as_bytes()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `NAME=value` entry, as the builder freezes them.
    fn entry(text: &str) -> CString {
        CString::new(text).unwrap()
    }

    #[test]
    fn a_value_containing_an_equals_sign_survives_the_split() {
        // Only the first separator is the separator: a name cannot contain
        // `=` — the builder refuses one that does — so everything after the
        // first is value.
        let (name, value) = split_env(&entry("CFLAGS=-DA=1 -DB=2"));
        assert_eq!(name, OsString::from("CFLAGS"));
        assert_eq!(value, OsString::from("-DA=1 -DB=2"));
    }

    #[test]
    fn an_empty_value_round_trips() {
        let (name, value) = split_env(&entry("EMPTY="));
        assert_eq!(name, OsString::from("EMPTY"));
        assert_eq!(value, OsString::new());
    }

    #[test]
    fn a_rootfs_relative_target_is_reported_as_an_absolute_path() {
        // Targets are frozen relative to the rootfs, because that is what the
        // sandbox stage resolves them against; a consumer reading the record
        // wants the path as the command sees it.
        assert_eq!(absolute(&entry("dev/pts")), PathBuf::from("/dev/pts"));
        assert_eq!(absolute(&entry("tmp")), PathBuf::from("/tmp"));
    }

    #[test]
    fn an_unset_raw_field_reads_back_as_absent() {
        assert_eq!(optional(&entry("")), None);
        assert_eq!(optional(&entry("tmpfs")), Some(OsString::from("tmpfs")));
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{
        ResolvedCgroup, ResolvedHardening, ResolvedIdentity, ResolvedInputs, ResolvedLandlockFs,
        ResolvedLandlockNet, ResolvedMount, ResolvedNetworkFilter, ResolvedRlimit, ResolvedRoot,
        ResolvedStdio, ResolvedStreams, ResolvedSyscallRefusal,
    };
    use crate::cgroup::CgroupLimit;
    use crate::idmap::{IdRange, Identity};
    use crate::limits::{Limit, Resource};
    use crate::scratch::Scratch;
    use crate::{Cage, Network, RawMount};

    /// The keys the records below render between them, in sorted order.
    const EXPECTED_RECORD_KEYS: [&str; 75] = [
        "cgroup",
        "cgroup.kind",
        "cgroup.limits",
        "cgroup.limits.cpu-max",
        "cgroup.limits.cpu-max.period",
        "cgroup.limits.cpu-max.quota",
        "cgroup.limits.cpu-weight",
        "cgroup.limits.memory-max",
        "cgroup.limits.memory-swap-max",
        "cgroup.limits.pids-max",
        "cgroup.parent",
        "env",
        "env.SOURCE_DATE_EPOCH",
        "hardening",
        "hardening.keep-capabilities",
        "hardening.kind",
        "hardening.landlock-abi",
        "hardening.landlock-fs",
        "hardening.landlock-fs[].access",
        "hardening.landlock-fs[].path",
        "hardening.landlock-net",
        "hardening.landlock-net[].access",
        "hardening.landlock-net[].port",
        "hardening.landlock-resolve-unix",
        "hardening.landlock-scope",
        "hardening.seccomp-instructions",
        "hostname",
        "identity",
        "identity.gid",
        "identity.gid[].count",
        "identity.gid[].inside",
        "identity.gid[].outside",
        "identity.kind",
        "identity.uid",
        "identity.uid[].count",
        "identity.uid[].inside",
        "identity.uid[].outside",
        "mounts",
        "mounts[].data",
        "mounts[].flags",
        "mounts[].fstype",
        "mounts[].kind",
        "mounts[].path",
        "mounts[].read-only",
        "mounts[].source",
        "mounts[].target",
        "network",
        "network-filter",
        "network-filter.refusals",
        "network-filter.refusals[].errno",
        "network-filter.refusals[].first-argument",
        "network-filter.refusals[].syscall",
        "no-new-privileges",
        "pid-namespace",
        "present-as",
        "present-as.gid",
        "present-as.uid",
        "rlimits",
        "rlimits[].hard",
        "rlimits[].resource",
        "rlimits[].soft",
        "root",
        "root.kind",
        "root.lower",
        "root.path",
        "root.upper",
        "root.work",
        "run-as",
        "run-as.gid",
        "run-as.groups",
        "run-as.uid",
        "streams",
        "streams.stderr",
        "streams.stdin",
        "streams.stdout",
    ];

    /// Records that between them hold every field and every variant the
    /// record's types have, every optional field set.
    ///
    /// Built directly rather than from a cage, because no one host builds them
    /// all: an overlay root needs an unprivileged overlay, a host root a
    /// restriction, and an unavailable hardening layer a build without the
    /// feature. The struct literals name every field, so a field added to any
    /// of the types fails to compile here until it is given a value.
    fn every_shape() -> Vec<ResolvedInputs> {
        let extent = IdRange {
            inside: 0,
            outside: 100_000,
            count: 65_536,
        };
        let streams = ResolvedStreams {
            stdin: ResolvedStdio::Null,
            stdout: ResolvedStdio::Fd,
            stderr: ResolvedStdio::Inherit,
        };
        let everything = ResolvedInputs {
            root: ResolvedRoot::Plain {
                path: PathBuf::from("/srv/rootfs"),
            },
            env: vec![(
                OsString::from("SOURCE_DATE_EPOCH"),
                OsString::from("1700000000"),
            )],
            mounts: vec![
                ResolvedMount::Tmpfs {
                    target: PathBuf::from("/tmp"),
                    flags: 6,
                    data: "mode=1777".to_string(),
                },
                ResolvedMount::Procfs {
                    target: PathBuf::from("/proc"),
                },
                ResolvedMount::Devpts {
                    target: PathBuf::from("/dev/pts"),
                    data: "newinstance".to_string(),
                },
                ResolvedMount::Bind {
                    source: PathBuf::from("/etc"),
                    target: PathBuf::from("/usr/src"),
                    read_only: true,
                },
                ResolvedMount::Raw {
                    source: Some(PathBuf::from("none")),
                    target: PathBuf::from("/dev/shm"),
                    fstype: Some("tmpfs".to_string()),
                    flags: 2,
                    data: Some("size=1m".to_string()),
                },
                ResolvedMount::Symlink {
                    path: PathBuf::from("/dev/fd"),
                    target: PathBuf::from("/proc/self/fd"),
                },
                ResolvedMount::Hide {
                    target: PathBuf::from("/home"),
                },
                ResolvedMount::ReadOnly {
                    target: PathBuf::from("/work/.git/hooks"),
                },
            ],
            identity: ResolvedIdentity::Ranged {
                uid: vec![extent],
                gid: vec![extent],
            },
            run_as: Some(Identity::new(1000, 1000).groups([1000, 27])),
            present_as: None,
            no_new_privileges: true,
            network: Network::Host,
            network_filter: Some(ResolvedNetworkFilter {
                refusals: vec![ResolvedSyscallRefusal {
                    syscall: "socket".to_string(),
                    first_argument: Some(40),
                    errno: 97,
                }],
            }),
            pid_namespace: true,
            hostname: OsString::from("builder"),
            streams,
            rlimits: vec![ResolvedRlimit {
                resource: Resource::OpenFiles,
                soft: Limit::of(1024),
                hard: Limit::UNLIMITED,
            }],
            cgroup: Some(ResolvedCgroup::Applied {
                parent: PathBuf::from("/sys/fs/cgroup/delegated"),
                limits: vec![
                    CgroupLimit::MemoryMax(1 << 30),
                    CgroupLimit::MemorySwapMax(0),
                    CgroupLimit::PidsMax(64),
                    CgroupLimit::cpu_max(50_000, 100_000),
                    CgroupLimit::CpuWeight(100),
                ],
            }),
            hardening: ResolvedHardening::Applied {
                landlock_fs: vec![ResolvedLandlockFs {
                    path: PathBuf::from("/usr"),
                    access: 1,
                }],
                landlock_net: vec![ResolvedLandlockNet {
                    port: 443,
                    access: 2,
                }],
                landlock_resolve_unix: true,
                landlock_scope: 3,
                seccomp_instructions: Some(4),
                keep_capabilities: Some(5),
                landlock_abi: Some(6),
            },
        };
        let overlaid = ResolvedInputs {
            root: ResolvedRoot::Overlay {
                lower: vec![PathBuf::from("/srv/base")],
                upper: PathBuf::from("/srv/upper"),
                work: PathBuf::from("/srv/.upper.work"),
            },
            identity: ResolvedIdentity::Single,
            run_as: None,
            present_as: Some(Identity::new(1000, 1000)),
            cgroup: Some(ResolvedCgroup::NotApplied {
                limits: vec![CgroupLimit::PidsMax(64)],
            }),
            hardening: ResolvedHardening::Unavailable,
            ..everything.clone()
        };
        let restricted = ResolvedInputs {
            root: ResolvedRoot::Host,
            identity: ResolvedIdentity::Caller,
            ..everything.clone()
        };
        let empty = ResolvedInputs {
            root: ResolvedRoot::Empty,
            ..everything.clone()
        };
        let host = ResolvedInputs {
            root: ResolvedRoot::HostReadOnly,
            ..everything.clone()
        };
        vec![everything, overlaid, restricted, empty, host]
    }

    /// Which variant of each of the record's enums a record holds.
    ///
    /// Every match is exhaustive, with no wildcard, so a variant added to any of
    /// them fails to compile here until it is named, and then fails
    /// [`the_record_format_keys_are_what_they_are`] until [`every_shape`] holds
    /// one.
    fn variants(record: &ResolvedInputs) -> Vec<&'static str> {
        let root = match record.root {
            ResolvedRoot::Host => "root host",
            ResolvedRoot::Plain { .. } => "root plain",
            ResolvedRoot::Overlay { .. } => "root overlay",
            ResolvedRoot::Empty => "root empty",
            ResolvedRoot::HostReadOnly => "root host read-only",
        };
        let identity = match record.identity {
            ResolvedIdentity::Caller => "identity caller",
            ResolvedIdentity::Single => "identity single",
            ResolvedIdentity::Ranged { .. } => "identity ranged",
        };
        let hardening = match record.hardening {
            ResolvedHardening::Unavailable => "hardening unavailable",
            ResolvedHardening::Applied { .. } => "hardening applied",
        };
        let cgroup = record.cgroup.as_ref().map(|cgroup| match cgroup {
            ResolvedCgroup::Applied { .. } => "cgroup applied",
            ResolvedCgroup::NotApplied { .. } => "cgroup not applied",
        });
        let mounts = record.mounts.iter().map(|mount| match mount {
            ResolvedMount::Tmpfs { .. } => "mount tmpfs",
            ResolvedMount::Procfs { .. } => "mount procfs",
            ResolvedMount::Devpts { .. } => "mount devpts",
            ResolvedMount::Bind { .. } => "mount bind",
            ResolvedMount::Raw { .. } => "mount raw",
            ResolvedMount::Symlink { .. } => "mount symlink",
            ResolvedMount::Hide { .. } => "mount hide",
            ResolvedMount::ReadOnly { .. } => "mount read-only",
        });
        [root, identity, hardening]
            .into_iter()
            .chain(cgroup)
            .chain(mounts)
            .collect()
    }

    /// Every key the serialized provenance record can carry.
    ///
    /// The record is meant to be stored in an artifact's provenance and read
    /// back by tools that never saw the build that wrote it, so its keys are a
    /// format as much as the profile's are. They come from field names and
    /// `rename_all` on each container, so a Rust-side rename, a changed
    /// container attribute, and a newly added field all move a key silently.
    /// This is what notices. A deliberate change to the format updates this
    /// list, and the diff is the review.
    #[test]
    fn the_record_format_keys_are_what_they_are() {
        let records = every_shape();
        let held: BTreeSet<&str> = records.iter().flat_map(variants).collect();
        assert_eq!(
            held,
            BTreeSet::from([
                "cgroup applied",
                "cgroup not applied",
                "hardening applied",
                "hardening unavailable",
                "identity caller",
                "identity ranged",
                "identity single",
                "mount bind",
                "mount devpts",
                "mount hide",
                "mount procfs",
                "mount raw",
                "mount read-only",
                "mount symlink",
                "mount tmpfs",
                "root empty",
                "root host",
                "root host read-only",
                "root overlay",
                "root plain",
            ]),
            "a variant the records do not hold has no keys pinned",
        );

        let mut keys = Vec::new();
        for record in &records {
            let rendered = toml::to_string(record).expect("the record serializes");
            keys.extend(crate::spec::serde_tests::profile_keys(&rendered));
        }
        keys.sort();
        keys.dedup();
        assert_eq!(keys, EXPECTED_RECORD_KEYS, "the record format's keys moved");
    }

    /// Every value a stream's disposition can take in the record.
    ///
    /// The values come from `rename_all` as the keys do, and the match is
    /// exhaustive, so a variant added later fails to compile here until its
    /// spelling is pinned.
    #[test]
    fn the_stream_spellings_are_what_they_are() {
        let spelling = |stdio: ResolvedStdio| match stdio {
            ResolvedStdio::Inherit => "inherit",
            ResolvedStdio::Null => "null",
            ResolvedStdio::Fd => "fd",
        };
        for stdio in [
            ResolvedStdio::Inherit,
            ResolvedStdio::Null,
            ResolvedStdio::Fd,
        ] {
            let rendered = toml::Value::try_from(stdio).expect("a disposition serializes");
            assert_eq!(rendered.as_str(), Some(spelling(stdio)));
        }
    }

    /// The record a consumer stamps into provenance is a TOML document, and
    /// its shape is what that consumer's own format has to accommodate.
    #[test]
    fn the_record_renders_as_a_provenance_document() {
        // Both opt-outs, which is the combination a reproducibility-focused
        // consumer runs and which keeps the document short enough to assert
        // whole. The managed profile's own contribution is covered below. The
        // raw mount is the procfs the nested user namespace's identity map is
        // established through, which an opted-out profile declares for itself.
        let cage = Cage::builder()
            .rootfs("/tmp")
            .managed_mounts(false)
            .base_env(false)
            .command("/bin/sh")
            .hostname("builder")
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .bind_ro("/etc", "/usr/src")
            .raw_mount(RawMount::new("/proc").fstype("proc").flags(2))
            .build()
            .expect("a valid sandbox configuration");
        let rendered = toml::to_string(&cage.resolved_inputs()).expect("the record serializes");
        // The hardening block is the one part that depends on the build rather
        // than on the configuration, which is the whole point of the field
        // being present either way.
        #[cfg(feature = "hardening")]
        let hardening = "[hardening]\nkind = \"applied\"\nlandlock-fs = []\nlandlock-net = []\nlandlock-resolve-unix = false\nlandlock-scope = 0\n";
        #[cfg(not(feature = "hardening"))]
        let hardening = "[hardening]\nkind = \"unavailable\"\n";
        // The isolated network's filter, which refuses `socketcall`'s socket
        // creation where the host's kernel family has the call.
        let socketcall = if cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
            "[[network-filter.refusals]]\n\
             syscall = \"socketcall\"\n\
             first-argument = 1\n\
             errno = 97\n\
             \n"
        } else {
            ""
        };
        // TOML puts bare keys ahead of tables, so `no-new-privileges`,
        // `network`, `pid-namespace`, `hostname` and `rlimits` lead whatever
        // order the struct declares; the rest follow in declaration order. A
        // `None` renders as an absent key, which is what TOML has: no `run-as`
        // table here, and no Landlock ABI for a posture that asks nothing of
        // Landlock.
        assert_eq!(
            rendered,
            "no-new-privileges = false\n\
             network = \"isolated\"\n\
             pid-namespace = true\n\
             hostname = \"builder\"\n\
             rlimits = []\n\
             \n\
             [root]\n\
             kind = \"plain\"\n\
             path = \"/tmp\"\n\
             \n\
             [env]\n\
             SOURCE_DATE_EPOCH = \"1700000000\"\n\
             \n\
             [[mounts]]\n\
             kind = \"bind\"\n\
             source = \"/etc\"\n\
             target = \"/usr/src\"\n\
             read-only = true\n\
             \n\
             [[mounts]]\n\
             kind = \"raw\"\n\
             target = \"/proc\"\n\
             fstype = \"proc\"\n\
             flags = 2\n\
             \n\
             [identity]\n\
             kind = \"single\"\n\
             \n\
             [[network-filter.refusals]]\n\
             syscall = \"socket\"\n\
             first-argument = 40\n\
             errno = 97\n\
             \n\
             [[network-filter.refusals]]\n\
             syscall = \"io_uring_setup\"\n\
             errno = 38\n\
             \n"
            .to_string()
                + socketcall
                + "[streams]\n\
                   stdin = \"inherit\"\n\
                   stdout = \"inherit\"\n\
                   stderr = \"inherit\"\n\
                   \n"
                + hardening,
        );
    }

    #[test]
    fn a_plain_root_and_an_overlay_root_produce_different_records() {
        // The whole complaint this field answers: `mounts` is projected from
        // the plan's mount actions, and the root is not one of them, so before
        // this a plain root and an overlay over the same base recorded byte for
        // byte the same thing while describing two different builds.
        let scratch = Scratch::new("resolved-overlay");
        let base = scratch.join("base");
        let patches = scratch.join("patches");
        std::fs::create_dir_all(&base).expect("the base is creatable");
        std::fs::create_dir_all(&patches).expect("the patch layer is creatable");

        let plain = Cage::builder()
            .rootfs(&base)
            .managed_mounts(false)
            // The procfs the nested user namespace's identity map is
            // established through, which an opted-out profile declares itself.
            .bind("/proc", "/proc")
            .command("/bin/sh")
            .build()
            .expect("a plain root over the same base builds")
            .resolved_inputs();
        let built = Cage::builder()
            .overlay(
                crate::Overlay::new()
                    .lower(&base)
                    .lower(&patches)
                    .upper(scratch.join("upper")),
            )
            .managed_mounts(false)
            // The procfs the nested user namespace's identity map is
            // established through, which an opted-out profile declares itself.
            .bind("/proc", "/proc")
            .command("/bin/sh")
            .build();
        let cage = match built {
            Ok(cage) => cage,
            // A host that cannot establish an unprivileged overlay refuses the
            // build; there is nothing to record and nothing to assert. Any
            // other refusal is this test's failure.
            Err(crate::Error::Config(crate::ConfigError::OverlayUnavailable { blocker })) => {
                ferroday_cage_testkit::require::OVERLAY.skip(format!(
                    "an unprivileged overlay is unavailable here: {blocker}"
                ));
                return;
            }
            Err(err) => panic!("the overlay sandbox builds: {err}"),
        };
        let layered = cage.resolved_inputs();

        assert_ne!(plain.root, layered.root, "the two roots record differently");
        assert_eq!(plain.mounts, layered.mounts, "and it is not the mounts");

        let crate::ResolvedRoot::Plain { path } = &plain.root else {
            panic!("a rootfs records as a plain root: {:?}", plain.root);
        };
        assert!(path.ends_with("base"), "{path:?}");

        let crate::ResolvedRoot::Overlay { lower, upper, .. } = &layered.root else {
            panic!("an overlay records as one: {:?}", layered.root);
        };
        assert_eq!(lower.len(), 2, "both lowers are recorded: {lower:?}");
        assert!(lower[0].ends_with("base"), "{lower:?}");
        assert!(lower[1].ends_with("patches"), "{lower:?}");
        assert!(upper.ends_with("upper"), "{upper:?}");
    }

    #[test]
    fn every_posture_the_launch_applies_reaches_the_record() {
        // One cage carrying all four postures at once, so a field that stopped
        // being projected shows up here rather than in a consumer's provenance.
        let cage = Cage::builder()
            .rootfs("/tmp")
            .command("/bin/sh")
            .managed_mounts(false)
            // The procfs the nested user namespace's identity map is
            // established through, which an opted-out profile declares itself.
            .bind("/proc", "/proc")
            .base_env(false)
            .network(crate::Network::Host)
            .rlimit(crate::limits::Resource::OpenFiles, 1024, 4096)
            .rlimit(
                crate::limits::Resource::Processes,
                64,
                crate::limits::Limit::UNLIMITED,
            )
            .build()
            .expect("a valid sandbox configuration");
        let inputs = cage.resolved_inputs();

        assert_eq!(inputs.network, crate::Network::Host);
        assert_eq!(inputs.identity, crate::ResolvedIdentity::Single);
        assert_eq!(
            inputs.rlimits,
            [
                crate::ResolvedRlimit {
                    resource: crate::limits::Resource::OpenFiles,
                    soft: crate::limits::Limit::of(1024),
                    hard: crate::limits::Limit::of(4096),
                },
                crate::ResolvedRlimit {
                    resource: crate::limits::Resource::Processes,
                    soft: crate::limits::Limit::of(64),
                    hard: crate::limits::Limit::UNLIMITED,
                },
            ],
        );
    }

    /// The network filter reaches the record under the two postures that
    /// install it, refusal by refusal, and is absent where nothing installs
    /// it, so a host-network record renders as one made before the filter
    /// existed.
    #[test]
    fn the_network_filter_reaches_the_record_where_the_launch_installs_it() {
        let record = |network: Network| {
            Cage::builder()
                .rootfs("/tmp")
                .command("/bin/sh")
                .network(network)
                .build()
                .expect("a valid sandbox configuration")
                .resolved_inputs()
        };
        let refusal =
            |syscall: &str, first_argument: Option<u32>, errno: i32| ResolvedSyscallRefusal {
                syscall: syscall.to_string(),
                first_argument,
                errno: u16::try_from(errno).expect("an errno fits a u16"),
            };
        let vsock = u32::try_from(libc::AF_VSOCK).expect("a family fits a u32");
        let mut expected = vec![
            refusal("socket", Some(vsock), libc::EAFNOSUPPORT),
            refusal("io_uring_setup", None, libc::ENOSYS),
        ];
        if cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
            // SYS_SOCKET, the call number socketcall creates a socket under.
            expected.push(refusal("socketcall", Some(1), libc::EAFNOSUPPORT));
        }
        for network in [Network::Isolated, Network::None] {
            let filter = record(network)
                .network_filter
                .unwrap_or_else(|| panic!("{network:?} records no network filter"));
            assert_eq!(filter.refusals, expected, "{network:?}");
        }

        let host = record(Network::Host);
        assert_eq!(host.network_filter, None);
        let rendered = toml::to_string(&host).expect("the record serializes");
        assert!(!rendered.contains("network-filter"), "{rendered}");
    }

    /// A restriction creates no network namespace and installs no network
    /// filter, and its record says so.
    #[cfg(feature = "hardening")]
    #[test]
    fn a_restriction_records_no_network_filter() {
        let inputs = crate::Restriction::builder()
            .command("/bin/true")
            .seccomp(crate::SeccompPolicy::Rules(crate::SeccompRules::curated()))
            .build()
            .expect("a valid restriction")
            .resolved_inputs();
        assert_eq!(inputs.network_filter, None);
    }

    /// A run-as identity reaches the record with the no-new-privileges flag the
    /// launch sets alongside it, so two builds that differ only in the id they
    /// run as record differently.
    #[test]
    fn a_run_as_identity_reaches_the_record_with_its_no_new_privileges() {
        #[derive(Debug)]
        struct Ranges;
        impl crate::IdMapper for Ranges {
            fn resolve(
                &self,
                _request: &crate::IdentityMap,
            ) -> Result<crate::ResolvedMap, crate::IdMapError> {
                let extent = crate::IdRange {
                    inside: 0,
                    outside: 100000,
                    count: 65536,
                };
                Ok(crate::ResolvedMap::new(vec![extent], vec![extent]))
            }
            fn apply(&self, _pid: u32, _map: &crate::ResolvedMap) -> Result<(), crate::IdMapError> {
                Ok(())
            }
        }
        let record = |run_as: Option<crate::Identity>| {
            let builder = Cage::builder()
                .rootfs("/tmp")
                .command("/bin/sh")
                .identity_map(crate::IdentityMap::Subordinate)
                .id_mapper(Ranges);
            let builder = match run_as {
                Some(identity) => builder.run_as(identity),
                None => builder,
            };
            builder
                .build()
                .expect("a valid sandbox configuration")
                .resolved_inputs()
        };

        let unset = record(None);
        assert_eq!(unset.run_as, None);
        assert!(!unset.no_new_privileges);

        let root = record(Some(crate::Identity::new(0, 0)));
        let builder = record(Some(crate::Identity::new(1000, 1000).groups([1000, 27])));
        assert_eq!(unset.identity, builder.identity, "the map is the same");
        assert_ne!(root, builder, "the identity the build ran as is not");
        assert_eq!(
            builder.run_as,
            Some(crate::Identity::new(1000, 1000).groups([1000, 27])),
        );
        assert!(root.no_new_privileges && builder.no_new_privileges);

        let rendered = toml::to_string(&builder).expect("the record serializes");
        assert!(
            rendered.contains("no-new-privileges = true\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("[run-as]\nuid = 1000\ngid = 1000\ngroups = [1000, 27]\n"),
            "{rendered}"
        );
    }

    /// A presented identity reaches the record as the ids the command sees, the
    /// caller's own resolved for `own`, and sets no-new-privileges. The map
    /// itself is still the single-identity one.
    #[test]
    fn a_presented_identity_reaches_the_record_with_its_no_new_privileges() {
        let record = |presented: crate::PresentedIdentity| {
            Cage::builder()
                .rootfs("/tmp")
                .command("/bin/sh")
                .present_as(presented)
                .build()
                .expect("a valid sandbox configuration")
                .resolved_inputs()
        };

        let ids = record(crate::PresentedIdentity::Ids {
            uid: 1000,
            gid: 100,
        });
        assert_eq!(ids.identity, ResolvedIdentity::Single);
        assert_eq!(ids.present_as, Some(Identity::new(1000, 100)));
        assert_eq!(ids.run_as, None);
        assert!(ids.no_new_privileges);

        let own = record(crate::PresentedIdentity::Own);
        assert_eq!(
            own.present_as,
            Some(Identity::new(
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
            )),
        );

        let rendered = toml::to_string(&ids).expect("the record serializes");
        assert!(
            rendered.contains("[present-as]\nuid = 1000\ngid = 100\n"),
            "{rendered}"
        );
    }

    /// Any hardening control sets the no-new-privileges flag, which the record
    /// states rather than leaving it to be inferred from the controls.
    #[cfg(feature = "hardening")]
    #[test]
    fn a_hardening_control_records_its_no_new_privileges() {
        let inputs = Cage::builder()
            .rootfs("/tmp")
            .command("/bin/sh")
            .seccomp(crate::SeccompPolicy::Rules(crate::SeccompRules::curated()))
            .build()
            .expect("a valid sandbox configuration")
            .resolved_inputs();
        assert!(inputs.no_new_privileges);
        assert_eq!(inputs.run_as, None);
    }

    /// A hardening posture reaches the record: the grants by path and port, and
    /// the seccomp filter by the one property that distinguishes two policies
    /// without dumping thousands of instructions into a provenance document.
    #[cfg(feature = "hardening")]
    #[test]
    fn a_hardening_posture_records_its_grants_and_its_filter_size() {
        use crate::{FsAccess, NetAccess, SeccompPolicy, SeccompRules};

        let cage = Cage::builder()
            .rootfs("/tmp")
            .command("/bin/sh")
            .managed_mounts(false)
            // The procfs the nested user namespace's identity map is
            // established through, which an opted-out profile declares itself.
            .bind("/proc", "/proc")
            .landlock_fs(FsAccess::READ, "/usr")
            .landlock_net(NetAccess::CONNECT, 443)
            .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
            .build()
            .expect("a valid sandbox configuration");
        let crate::ResolvedHardening::Applied {
            landlock_fs,
            landlock_net,
            seccomp_instructions,
            ..
        } = cage.resolved_inputs().hardening
        else {
            panic!("a build with the feature reports an applied posture");
        };

        assert_eq!(landlock_fs.len(), 1);
        assert_eq!(landlock_fs[0].path, std::path::Path::new("/usr"));
        assert_ne!(landlock_fs[0].access, 0, "the granted rights are recorded");
        assert_eq!(landlock_net.len(), 1);
        assert_eq!(landlock_net[0].port, 443);
        assert!(
            seccomp_instructions.is_some_and(|count| count > 0),
            "the curated policy compiles to a program: {seccomp_instructions:?}",
        );
    }

    /// The Landlock ABI is recorded beside a posture that asks for Landlock,
    /// since the command stage masks the recorded requests to it, and not
    /// beside one that asks nothing of Landlock, where it changes nothing.
    #[cfg(feature = "hardening")]
    #[test]
    fn a_landlock_posture_records_the_abi_its_requests_are_masked_to() {
        let abi_of = |builder: crate::CageBuilder| {
            let cage = builder
                .rootfs("/tmp")
                .command("/bin/sh")
                .build()
                .expect("a valid sandbox configuration");
            let crate::ResolvedHardening::Applied { landlock_abi, .. } =
                cage.resolved_inputs().hardening
            else {
                panic!("a build with the feature reports an applied posture");
            };
            landlock_abi
        };
        let host = crate::host::landlock_abi();
        assert_eq!(
            abi_of(Cage::builder().landlock_fs(crate::FsAccess::READ, "/usr")),
            host,
        );
        assert_eq!(
            abi_of(Cage::builder().landlock_scope([crate::LandlockScope::Signal])),
            host,
        );
        assert_eq!(
            abi_of(
                Cage::builder()
                    .seccomp(crate::SeccompPolicy::Rules(crate::SeccompRules::curated()))
            ),
            None,
            "a posture without Landlock records no ABI",
        );
    }

    /// The UTS hostname and the PID namespace change what a build sees, so
    /// both reach the record, the host's own name included where none is set.
    #[test]
    fn the_hostname_and_the_pid_namespace_reach_the_record() {
        let built = |builder: crate::CageBuilder| {
            builder
                .rootfs("/tmp")
                .command("/bin/sh")
                .build()
                .expect("a valid sandbox configuration")
                .resolved_inputs()
        };
        let named = built(Cage::builder().hostname("builder").pid_namespace(false));
        assert_eq!(named.hostname, "builder");
        assert!(!named.pid_namespace);

        let inherited = built(Cage::builder());
        let host = rustix::system::uname();
        assert_eq!(
            std::os::unix::ffi::OsStrExt::as_bytes(inherited.hostname.as_os_str()),
            host.nodename().to_bytes(),
            "an unset hostname is the host's",
        );
        assert!(inherited.pid_namespace);
    }

    /// A sandbox that hardens nothing still reports the layer as available.
    ///
    /// The distinction the always-present field exists for: this is a build
    /// that could have hardened and did not, which is not the same fact as a
    /// build that could not.
    #[cfg(feature = "hardening")]
    #[test]
    fn a_sandbox_that_hardens_nothing_is_not_a_build_that_cannot() {
        let inputs = Cage::builder()
            .rootfs("/tmp")
            .command("/bin/sh")
            .managed_mounts(false)
            // The procfs the nested user namespace's identity map is
            // established through, which an opted-out profile declares itself.
            .bind("/proc", "/proc")
            .build()
            .expect("a valid sandbox configuration")
            .resolved_inputs();
        assert!(
            matches!(inputs.hardening, crate::ResolvedHardening::Applied { .. }),
            "{:?}",
            inputs.hardening,
        );
    }

    /// Without the feature the record says so, rather than saying nothing.
    #[cfg(not(feature = "hardening"))]
    #[test]
    fn a_build_without_the_hardening_layer_records_that_it_has_none() {
        let inputs = Cage::builder()
            .rootfs("/tmp")
            .command("/bin/sh")
            .managed_mounts(false)
            // The procfs the nested user namespace's identity map is
            // established through, which an opted-out profile declares itself.
            .bind("/proc", "/proc")
            .build()
            .expect("a valid sandbox configuration")
            .resolved_inputs();
        assert_eq!(inputs.hardening, crate::ResolvedHardening::Unavailable);
    }

    #[test]
    fn the_managed_profile_records_its_symlinks() {
        // The five /dev symlinks are the part of the default profile no other
        // accessor can report, and the reason `get_mount_dev()` alone does not
        // tell a consumer what `/dev` will contain.
        let inputs = Cage::builder()
            .rootfs("/tmp")
            .command("/bin/sh")
            .build()
            .expect("a valid sandbox configuration")
            .resolved_inputs();
        let rendered = toml::to_string(&inputs).expect("the record serializes");
        for link in ["stdin", "stdout", "stderr", "fd", "ptmx"] {
            assert!(
                rendered.contains(&format!("path = \"/dev/{link}\"")),
                "missing /dev/{link} in:\n{rendered}",
            );
        }
    }
}
