//! Run a command inside an unprivileged Linux sandbox.
//!
//! ferroday-cage stands up a sandbox — a set of Linux namespaces and mounts —
//! and executes a command in it as the calling user mapped to root inside.
//! The command sees a root filesystem the caller provides, runs in an
//! isolated process space, and receives a clean, reproducible environment.
//!
//! The isolation is established by talking to the kernel directly, as an
//! ordinary unprivileged user, and the default build is self-contained: pure
//! Rust throughout, resting on the kernel alone. One opt-in feature reaches
//! beyond it — `subid` delegates uid/gid range maps to the shadow suite's
//! privileged `newuidmap`/`newgidmap` helpers, the standard subordinate-id
//! mechanism every rootless container runtime uses. `unsafe` is confined to
//! the kernel-facing core — the launch mechanism, and the tap-device layer
//! of the optional native network stack — and every consumer of the crate
//! is safe Rust.
//!
//! # Example
//!
//! A sandbox is configured with a builder, validated by
//! [`build`](CageBuilder::build), and launched with [`run`](Cage::run):
//!
//! ```no_run
//! use ferroday_cage::Cage;
//!
//! # fn main() -> ferroday_cage::Result<()> {
//! let status = Cage::builder()
//!     .rootfs("/srv/rootfs/alpine")
//!     .command("/bin/sh")
//!     .args(["-c", "echo hello from the cage"])
//!     .build()?
//!     .run()?;
//! assert!(status.success());
//! # Ok(())
//! # }
//! ```
//!
//! # The sandbox
//!
//! A launch creates new user, mount, PID, UTS, IPC, cgroup, and (by
//! default) network namespaces, maps the calling user to root inside,
//! assembles the mount profile over the configured rootfs, pivots into it,
//! and executes the command as PID 2 under a minimal init that collects
//! orphaned descendants and tears the namespace down when the command exits.
//!
//! By default the command sees the rootfs at `/` with a fresh `/proc`, a
//! minimal `/dev`, and a tmpfs `/tmp` assembled over it, plus any bind
//! mounts the caller configures; it runs in an isolated network namespace
//! whose only interface is loopback, keeps the host's hostname, starts in
//! `/` with inherited standard streams, default signal dispositions, an
//! empty signal mask, a descriptor table holding only its standard
//! streams, and a deterministic base environment (`PATH` and `HOME`) plus
//! the caller's variables. Every part of that profile is a builder call
//! away: mounts can be dropped, the host network shared, the hostname set,
//! the working directory, environment, and stream dispositions chosen, and
//! unmodeled mounts expressed through the [`RawMount`] escape hatch.
//!
//! The isolation bounds what the command can reach, not what it can learn. Its
//! own mount table — `/proc/self/mountinfo` — names the host path of the rootfs
//! and of every bind source, so a command can read the calling user's name and
//! the layout of the build that started it. That is what a bind-mount-based
//! sandbox exposes; the guide's [what the sandbox does not
//! hide](https://gregordinary.github.io/ferroday-cage/how-the-sandbox-is-built.html#what-the-sandbox-does-not-hide)
//! sets out the whole of it.
//!
//! [`run`](Cage::run) returns the command's [`ExitStatus`] whenever the
//! command was executed — a non-zero exit is data, not an error. [`Error`]
//! is reserved for the library failing, and a setup failure inside the
//! sandbox names the exact step, the OS error, and the mount it concerned,
//! rather than surfacing an opaque exit.
//!
//! # Streaming and the handle
//!
//! [`run_with`](Cage::run_with) streams the command's output to a
//! caller-supplied [`Observer`] as it is produced, which also receives the
//! library's own launch [`Progress`] milestones. [`spawn`](Cage::spawn)
//! and [`spawn_with`](Cage::spawn_with) return a [`Running`] handle that
//! waits with or without a deadline, requests graceful termination,
//! and kills the sandbox outright; a [`KillHandle`] does the latter two
//! from another thread. The library installs no signal handlers; the
//! defined behavior around caller signals and caller exit is documented
//! in the guide, with [`stop_with_caller`](CageBuilder::stop_with_caller)
//! tying the sandbox's lifetime to the caller's when asked.
//!
//! # Terminals
//!
//! [`spawn_terminal`](Cage::spawn_terminal) starts the command on a
//! pseudoterminal allocated for it and returns the caller's end as a [`Pty`]
//! beside the running handle. `isatty` is true on all three of the command's
//! standard streams, a full-screen program behaves, and a shell inside the
//! sandbox runs jobs of its own — against a terminal the caller does not
//! share, and reaching nothing of the caller's own. See [`Terminal`].
//!
//! # Userspace networking
//!
//! The default network is an isolated namespace whose only interface is
//! loopback. To give the sandbox outbound connectivity while it keeps that
//! private namespace, a userspace network stack attaches at a seam:
//! [`spawn_pending`](Cage::spawn_pending) creates the sandbox but holds the
//! command before it runs and hands back a [`Pending`] whose
//! [`netns_pid`](Pending::netns_pid) names a process in the sandbox's
//! network namespace. The caller attaches a stack to that namespace, then
//! calls [`proceed`](Pending::proceed) to release the command — so the network
//! is up before the command's first instruction.
// The closing sentence names the netstack items when the feature provides
// them; without the feature the seam is all the library ships, and the text
// (with its intra-doc links) says so instead.
#![cfg_attr(
    not(feature = "netstack"),
    doc = "An external stack (`pasta`, `slirp4netns`) is the caller's to run and"
)]
#![cfg_attr(
    not(feature = "netstack"),
    doc = "manage against that seam; the library ships the seam, not a stack."
)]
#![cfg_attr(
    feature = "netstack",
    doc = "An external stack (`pasta`, `slirp4netns`) can attach there, and with"
)]
#![cfg_attr(
    feature = "netstack",
    doc = "the `netstack` feature the library brings its own:"
)]
#![cfg_attr(
    feature = "netstack",
    doc = "[`NetStack::attach`] creates a tap device inside the sandbox's"
)]
#![cfg_attr(
    feature = "netstack",
    doc = "namespace and terminates the guest's TCP and UDP flows in the"
)]
#![cfg_attr(
    feature = "netstack",
    doc = "caller's process, forwarding each over an ordinary host socket —"
)]
#![cfg_attr(
    feature = "netstack",
    doc = "self-contained, unprivileged outbound connectivity."
)]
//!
//! # Profiles
//!
//! With the `serde` feature, [`CageBuilder`] serializes and deserializes
//! as the sandbox specification, so a profile — a sandbox described in a
//! TOML (or any serde-format) file — is a capability of any consumer.
//! Deserializing one into a `CageBuilder` trusts it as code-equivalent
//! configuration; a profile from an untrusted source is loaded through
//! `RestrictedProfile`, which forbids the operations that reach host
//! resources. See the [`CageBuilder`] "Trust" section.
//!
// The hardening and restriction-fallback sections describe feature-gated
// items, so their doc text (with its intra-doc links) is gated on the feature
// too: it appears in the canonical all-features build and is absent — links
// and all — when the feature is off, keeping a no-feature `cargo doc` clean.
#![cfg_attr(feature = "hardening", doc = "# Hardening")]
#![cfg_attr(feature = "hardening", doc = "")]
#![cfg_attr(
    feature = "hardening",
    doc = "With the `hardening` feature, the default rootless-convenience profile can"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "be tightened into a boundary against untrusted code. Opt-in Landlock"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "filesystem rules ([`landlock_fs`](CageBuilder::landlock_fs)) and TCP"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "port rules ([`landlock_net`](CageBuilder::landlock_net)), seccomp"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "syscall filters ([`seccomp`](CageBuilder::seccomp)), capability drops"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "([`drop_all_capabilities`](CageBuilder::drop_all_capabilities)), and a"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "fully denied network ([`Network::None`]) apply to the command and the"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "processes it starts. The restrictions are compiled at build time and"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "enforced in the command stage after the pivot, immediately before the"
)]
#![cfg_attr(feature = "hardening", doc = "command executes.")]
#![cfg_attr(feature = "hardening", doc = "")]
#![cfg_attr(feature = "hardening", doc = "# The restriction fallback")]
#![cfg_attr(feature = "hardening", doc = "")]
#![cfg_attr(
    feature = "hardening",
    doc = "A host that disables unprivileged user namespaces cannot run the cage at"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "all; a launch there fails with [`Error::UsernsUnavailable`]. With the"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "`hardening` feature, [`Restriction`] is the degraded mode for such hosts:"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "it spawns a command directly on the host, confined by Landlock rules and"
)]
#![cfg_attr(feature = "hardening", doc = "a seccomp filter. The")]
#![cfg_attr(
    feature = "hardening",
    doc = "command sees the host filesystem as far as the grants allow, the host"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "network, and the host PID space, so a restriction is a weaker boundary"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "configured with host paths, sharing the cage's process model, streaming,"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "and handle. A caller that wants to degrade catches"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "[`Error::UsernsUnavailable`] from the cage and runs its separately"
)]
#![cfg_attr(feature = "hardening", doc = "configured restriction.")]
#![cfg_attr(feature = "hardening", doc = "")]
//! # Provisioning
//!
//! The [`provision`] module produces the rootfs a sandbox runs against:
//! a [`Provisioner`](provision::Provisioner) fills a staging directory
//! and [`ensure`](provision::ensure) publishes it atomically, so a rootfs
//! directory either does not exist or is complete.
#![cfg_attr(
    feature = "tarball",
    doc = "With the `tarball` feature, [`Tarball`](provision::Tarball) provisions"
)]
#![cfg_attr(
    feature = "tarball",
    doc = "from a tar archive (plain, gzip, xz, or zstd) with kernel-enforced"
)]
#![cfg_attr(feature = "tarball", doc = "containment.")]
#![cfg_attr(
    feature = "debian",
    doc = "With the `debian` feature, [`Debian`](provision::debian::Debian)"
)]
#![cfg_attr(
    feature = "debian",
    doc = "bootstraps a Debian suite from the archive and configures it inside a"
)]
#![cfg_attr(feature = "debian", doc = "cage of its own.")]
//!
//! # Host requirements
//!
//! The sandbox requires Linux 5.6 or later with unprivileged user
//! namespaces enabled. Hosts commonly disable them; [`host`] probes for the
//! known blocking configurations, and a denied launch is reported as
//! [`Error::UsernsUnavailable`] with the identified cause rather than a raw
//! `EPERM`. On such hosts the restriction fallback above remains available:
//! it needs only Landlock or seccomp, not user namespaces.
//!
//! # Status
//!
//! The crate is under active development and the public API is not yet
//! stable.

mod error;
#[cfg(feature = "hardening")]
mod hardening;
pub mod host;
mod idmap;
pub mod limits;
mod mechanism;
#[cfg(feature = "netstack")]
mod netstack;
mod observer;
mod path;
mod poll;
pub mod provision;
mod resolved;
#[cfg(feature = "hardening")]
mod restrict;
mod running;
#[cfg(test)]
mod scratch;
mod spec;
mod status;
mod terminal;
mod wire;

pub use error::{ConfigError, Error, OverlayLayer, SetupStep};
#[cfg(feature = "hardening")]
pub use hardening::{
    Capability, FsAccess, NetAccess, ParseCapabilityError, ParseFsAccessError, ParseNetAccessError,
    SeccompAction, SeccompArg, SeccompArgLen, SeccompCompare, SeccompPolicy, SeccompRules,
};
#[cfg(feature = "subid")]
pub use idmap::SubidMapper;
pub use idmap::{DirectMapper, IdMapError, IdMapper, IdRange, Identity, IdentityMap, ResolvedMap};
pub use limits::{Limit, Resource};
#[cfg(feature = "hardening")]
pub use mechanism::SockFilter;
#[cfg(feature = "netstack")]
pub use netstack::{NetStack, NetStackBuilder, NetStackError, NetStackHandle};
pub use observer::{Observer, Output, Progress};
pub use resolved::{
    ResolvedHardening, ResolvedIdentity, ResolvedInputs, ResolvedLandlockFs, ResolvedLandlockNet,
    ResolvedMount, ResolvedRlimit, ResolvedRoot, ResolvedStdio, ResolvedStreams,
};
#[cfg(feature = "hardening")]
pub use restrict::{Restriction, RestrictionBuilder};
pub use running::{KillHandle, Pending, Running};
#[cfg(feature = "serde")]
pub use spec::RestrictedProfile;
pub use spec::{Bind, Cage, CageBuilder, Mount, Network, Overlay, RawMount, Stdio};
pub use status::ExitStatus;
pub use terminal::{Pty, Terminal};

/// Shorthand for a result whose error is [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
