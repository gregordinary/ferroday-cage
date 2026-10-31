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
use crate::idmap::IdRange;
use crate::limits::{Limit, Resource};
use crate::mechanism::{Confinement, IdentityPlan, LaunchPlan, MountAction};

/// The root, environment, mounts, and posture a built sandbox will apply.
///
/// Obtained from [`Cage::resolved_inputs`](crate::Cage::resolved_inputs).
///
/// # Stability
///
/// This type's *shape* follows the compatibility promise like any other public
/// item. Its *contents* do not: they report the defaults in force, and those
/// are explicitly outside the promise — the mount profile and the base
/// environment may both change in a patch release. That is the reason to
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
    /// `None` runs the command as uid 0 of the sandbox's user namespace, or,
    /// for a restriction, as the calling user. Whether a build sees uid 0 or
    /// another id changes what it produces: a Debian build's
    /// `Rules-Requires-Root` handling turns on exactly this.
    ///
    /// A switch to a non-root id clears the command's capabilities, unless a
    /// keep set carries some across it, which [`hardening`](Self::hardening)
    /// records. A configured identity of any id also sets
    /// [`no_new_privileges`](Self::no_new_privileges).
    pub run_as: Option<ResolvedRunAs>,
    /// Whether the command runs with the no-new-privileges flag set, so that a
    /// set-user-ID binary or a file capability grants nothing across
    /// `execve`.
    ///
    /// A run-as identity sets it, and so does any hardening control. A build
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
    /// Where the command's three standard streams are wired.
    pub streams: ResolvedStreams,
    /// The resource limits applied to the command process, in the order they
    /// are applied.
    pub rlimits: Vec<ResolvedRlimit>,
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

/// The identity a built sandbox's command switches to before it executes.
///
/// The resolved counterpart of [`Identity`](crate::Identity), with every id a
/// sandbox-inside one, as the map in [`ResolvedInputs::identity`] holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ResolvedRunAs {
    /// The uid the command runs as.
    pub uid: u32,
    /// The gid the command runs as.
    pub gid: u32,
    /// The supplementary groups the command runs with. Under the
    /// single-identity map none can be set, and the command keeps the list it
    /// inherited, every entry of which the map presents as the overflow gid.
    pub groups: Vec<u32>,
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
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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
    serde(rename_all = "lowercase")
)]
pub enum ResolvedStdio {
    /// The stream is left as the launch inherited it.
    Inherit,
    /// The stream is wired to `/dev/null`.
    Null,
    /// The stream is wired to a descriptor the caller supplied.
    Fd,
}

/// One resource limit a built sandbox applies to the command process.
///
/// A build that adapts its parallelism to `RLIMIT_NOFILE`, or that fails a link
/// under `RLIMIT_AS`, produces different output, so the limits in force belong
/// in the record beside the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ResolvedRlimit {
    /// The kernel resource the limit governs.
    pub resource: Resource,
    /// The soft limit: what the kernel enforces.
    pub soft: Limit,
    /// The hard limit: the ceiling the command may raise its soft limit to.
    pub hard: Limit,
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
        /// The `LANDLOCK_SCOPE_*` flags the ruleset scopes, as the kernel spells
        /// them; zero when none applies.
        ///
        /// A sandbox reports what it asked for, before the command stage masks it
        /// to the running kernel's ABI. A restriction requests every scope and
        /// drops at build those the kernel cannot enforce, so it reports what
        /// the build kept.
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
    },
}

/// One Landlock filesystem grant a built sandbox enrols.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ResolvedLandlockFs {
    /// The granted path, as the command sees it after the root swap.
    pub path: PathBuf,
    /// The `LANDLOCK_ACCESS_FS_*` rights allowed beneath the path, as the
    /// kernel spells them.
    ///
    /// This is what the grant asks for, reported before the command stage
    /// narrows it: to the running kernel's ABI, and, where the path names
    /// something other than a directory, to the rights that act on a file.
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
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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
    /// Not a mount in the kernel's sense, but part of what the managed profile
    /// establishes — the five `/dev` symlinks arrive this way — and so part of
    /// the filesystem the command sees.
    #[non_exhaustive]
    Symlink {
        /// The link's own path inside the sandbox.
        path: PathBuf,
        /// The path the link points at, as written.
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
            | ResolvedMount::Raw { target, .. } => target,
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
            run_as: plan.run_as.as_ref().map(|run_as| ResolvedRunAs {
                uid: run_as.uid.as_raw(),
                gid: run_as.gid.as_raw(),
                groups: run_as.groups.iter().map(|gid| gid.as_raw()).collect(),
            }),
            no_new_privileges: no_new_privileges(plan),
            network: plan.network,
            streams: ResolvedStreams {
                stdin: project_stdio(&plan.stdin),
                stdout: project_stdio(&plan.stdout),
                stderr: project_stdio(&plan.stderr),
            },
            rlimits: plan.rlimits.iter().map(project_rlimit).collect(),
            hardening: project_hardening(plan),
        }
    }
}

/// Projects the sandbox's root filesystem.
///
/// The overlay is reported from the plan's own overlay rather than from `ops`
/// because it is not in them: the setup establishes it before the profile's
/// mounts, over the rootfs the plan names, which is the base lower.
fn project_root(plan: &LaunchPlan) -> ResolvedRoot {
    match plan.confinement {
        Confinement::Container => match &plan.overlay {
            Some(overlay) => ResolvedRoot::Overlay {
                lower: overlay.lower.clone(),
                upper: overlay.upper.clone(),
                work: overlay.work.clone(),
            },
            None => ResolvedRoot::Plain {
                path: PathBuf::from(OsString::from_vec(plan.rootfs_path.as_bytes().to_vec())),
            },
        },
        #[cfg(feature = "hardening")]
        Confinement::Restriction => ResolvedRoot::Host,
    }
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
/// whenever a run-as identity is configured, and the hardening layer whenever
/// its plan holds any control. A restriction's plan always does, since it drops
/// every capability.
fn no_new_privileges(plan: &LaunchPlan) -> bool {
    #[cfg(feature = "hardening")]
    let hardened = !plan.hardening.is_empty();
    #[cfg(not(feature = "hardening"))]
    let hardened = false;
    plan.run_as.is_some() || hardened
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
            landlock_scope: plan.hardening.landlock_scoped,
            seccomp_instructions: plan.hardening.seccomp.as_ref().map(Vec::len),
            keep_capabilities: plan.hardening.keep_caps,
        }
    }
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
    use crate::scratch::Scratch;
    use crate::{Cage, RawMount};

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
        let hardening = "[hardening]\nkind = \"applied\"\nlandlock-fs = []\nlandlock-net = []\nlandlock-scope = 0\n";
        #[cfg(not(feature = "hardening"))]
        let hardening = "[hardening]\nkind = \"unavailable\"\n";
        // TOML puts bare keys ahead of tables, so `no-new-privileges`,
        // `network` and `rlimits` lead whatever order the struct declares; the
        // rest follow in declaration order. A `None` renders as an absent key,
        // which is what TOML has: no `run-as` table here.
        assert_eq!(
            rendered,
            "no-new-privileges = false\n\
             network = \"isolated\"\n\
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
             [streams]\n\
             stdin = \"inherit\"\n\
             stdout = \"inherit\"\n\
             stderr = \"inherit\"\n\
             \n"
            .to_string()
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
            Some(crate::ResolvedRunAs {
                uid: 1000,
                gid: 1000,
                groups: vec![1000, 27],
            }),
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

    /// Any hardening control sets the no-new-privileges flag, which the record
    /// states rather than leaving it to be inferred from the controls.
    #[cfg(feature = "hardening")]
    #[test]
    fn a_hardening_control_records_its_no_new_privileges() {
        let inputs = Cage::builder()
            .rootfs("/tmp")
            .command("/bin/sh")
            .seccomp(crate::SeccompPolicy::Curated)
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
        use crate::{FsAccess, NetAccess, SeccompPolicy};

        let cage = Cage::builder()
            .rootfs("/tmp")
            .command("/bin/sh")
            .managed_mounts(false)
            // The procfs the nested user namespace's identity map is
            // established through, which an opted-out profile declares itself.
            .bind("/proc", "/proc")
            .landlock_fs(FsAccess::READ, "/usr")
            .landlock_net(NetAccess::CONNECT, 443)
            .seccomp(SeccompPolicy::Curated)
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
