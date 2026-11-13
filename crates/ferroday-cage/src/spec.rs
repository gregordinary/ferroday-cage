//! The sandbox specification: builder, validation, and the launch entry point.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawMode};
use rustix::io::Errno;
use rustix::mount::MountFlags;
use rustix::thread::UnshareFlags;

use crate::cgroup::{CgroupLimit, CgroupSettings};
use crate::error::{ConfigError, Error, OverlayLayer};
use crate::idmap::{self, IdMapper, Identity, IdentityMap, PresentedIdentity};
use crate::limits::{Limit, Resource};
use crate::mechanism::{
    self, Arrival, Confinement, IdentityPlan, LaunchPlan, ManagedPlaceholders, MountAction,
    MountDir, MountOp, NestedMap, NestedPlan, OverlayOptionsError, OverlayPlan, PresentPlan,
    RlimitPlan, RootPlan, RunAsPlan, StdioPlan,
};
use crate::observer::{Observer, Output};
use crate::path;
use crate::provision::rooted::Rooted;
use crate::resolved::ResolvedInputs;
use crate::running::{Pending, Running};
use crate::status::ExitStatus;
use crate::terminal::{Pty, Terminal};

/// The deterministic base `PATH`, shared by the cage's and the restriction's
/// base environments.
pub(crate) const BASE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The base environment a sandboxed command starts with, where it runs as
/// uid 0 of its namespace.
///
/// Deterministic: nothing is read from the host. Caller-supplied variables
/// are added on top and override these on collision. `HOME` is `/root`,
/// root's home. A command running as another identity starts from
/// [`BASE_ENV_UNPRIVILEGED`] instead.
const BASE_ENV: [(&str, &str); 2] = [("PATH", BASE_PATH), ("HOME", "/root")];

/// The base environment of a command running as an identity other than uid 0:
/// a [presented identity](CageBuilder::present_as), or a non-root
/// [run-as identity](CageBuilder::run_as).
///
/// It carries no `HOME`. The library cannot know where that identity's home is
/// in the sandbox, and contributes nothing rather than something wrong: a
/// program that needs one falls back to its passwd entry, and the caller sets
/// `HOME` where it knows better. `USER` and `LOGNAME` are the caller's to set
/// for every identity.
const BASE_ENV_UNPRIVILEGED: [(&str, &str); 1] = [("PATH", BASE_PATH)];

/// The character devices bound from the host into the sandbox's `/dev`.
///
/// `mknod` for character devices is denied in an unprivileged user
/// namespace, so the minimal device set is bind-mounted from the host.
///
/// `tty` is device `5:0`, whose open returns the opening process's controlling
/// terminal rather than the inode the bind carries, so binding it conveys no
/// terminal of its own: what a sandbox reaches through it follows from its
/// session. See [`Stdio`], which decides that.
const DEV_DEVICES: [&str; 6] = ["null", "zero", "full", "random", "urandom", "tty"];

/// The mode a mount point the sandbox creates is given, and the mode of any
/// ancestor directory created on the way to one.
///
/// A mount point outlives the sandbox — it persists in the rootfs directory on
/// the host — so the profile states the mode rather than leaving it to the
/// process umask. This is the conventional directory mode, and what a
/// distribution ships `/dev` and `/proc` as.
const DIR_MODE: RawMode = 0o755;

/// The paths the [host's own root](CageBuilder::host_rootfs) hides by default:
/// where the host keeps its users' credentials and its live sockets, which a
/// read-only mount does not stop a `connect` to.
///
/// `/tmp` and `/dev/shm` are not here because the managed profile already
/// replaces them with tmpfs instances of the sandbox's own.
const HOST_ROOT_HIDDEN: [&str; 5] = ["/home", "/root", "/run", "/var/run", "/var/tmp"];

/// The sandbox path the host's resolver configuration is bound onto, and the
/// one a caller's own mount there replaces.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// [`RESOLV_CONF`] as the root-relative target the lowered ops carry.
const RESOLV_CONF_TARGET: &CStr = c"etc/resolv.conf";

/// Whether a mount of the caller's claims the sandbox's [`RESOLV_CONF`], so
/// the managed bind there yields to it.
///
/// A mount at the target itself claims it, whatever its kind. What the managed
/// mount yields to is the caller having claimed the target, and a
/// [`Mount::Raw`] carries a source and the kernel's own flags, so a bind
/// spelled through the escape hatch is the more deliberate spelling of the
/// claim, not a weaker one.
///
/// A mount over a directory above the target claims it too when what arrives
/// there is a tree that already stood elsewhere: a bind, or a raw bind or move.
/// So does a [`Mount::Symlink`] at a directory above it, which sends the
/// target's path wherever the link points.
/// The managed bind's target would otherwise be created inside that tree, which
/// is the caller's host directory: an empty file left there for good, or a
/// launch that fails where the bind is read-only. A fresh filesystem mounted
/// above the target is the sandbox's own, and the target is created in it as
/// it would be in the root.
///
/// A target is read through [`path::absolute_components`] and compared as the
/// launch freezes it, through [`covers`], so `/etc//resolv.conf` and
/// `/etc/./resolv.conf` are the same target here as they will be at launch. A
/// mount whose target or flags [`build`](CageBuilder::build) refuses claims
/// nothing, since no sandbox is built with it.
fn claims_resolv_conf(mount: &Mount) -> bool {
    let arrival = match mount {
        // A link at the target or above it decides what the path names, as a
        // tree mounted there would. A path made read-only is a tree bound onto
        // itself.
        Mount::Bind(_) | Mount::Symlink(_) | Mount::ReadOnly(_) => Some(Arrival::Tree),
        // A hidden directory is a tmpfs of the sandbox's own, as a fresh
        // filesystem mounted above the target is.
        Mount::Hide(_) => Some(Arrival::Fresh),
        Mount::Raw(raw) => u32::try_from(raw.flags)
            .ok()
            .and_then(|flags| Arrival::of_raw(MountFlags::from_bits_retain(flags))),
    };
    let target = sandbox_target(mount.get_target());
    let (Some(arrival), Ok(target)) = (arrival, target) else {
        return false;
    };
    target.as_c_str() == RESOLV_CONF_TARGET
        || (arrival == Arrival::Tree && covers(&target, RESOLV_CONF_TARGET))
}

/// The mode of a mount point standing in for a world-writable sticky
/// directory: `/tmp` and `/dev/shm`, which the profile covers with a
/// `mode=1777` tmpfs.
///
/// The mount hides the mode for as long as it is established, so this is what
/// the directory is for every other purpose — including a rootfs provisioned
/// through a sandbox and then deployed, where a `/tmp` no unprivileged process
/// can write to is a broken image.
const STICKY_DIR_MODE: RawMode = 0o1777;

/// The symlinks created inside the sandbox's `/dev`, as (name, content).
const DEV_SYMLINKS: [(&str, &str); 5] = [
    ("stdin", "/proc/self/fd/0"),
    ("stdout", "/proc/self/fd/1"),
    ("stderr", "/proc/self/fd/2"),
    ("fd", "/proc/self/fd"),
    ("ptmx", "pts/ptmx"),
];

/// The sandbox's network posture.
///
/// [`Isolated`](Self::Isolated) and [`None`](Self::None) give the sandbox a
/// network namespace of its own. Some routes out of a sandbox do not pass
/// through a network namespace, so a sandbox under either posture also carries
/// a seccomp filter that refuses them:
///
/// - An `AF_VSOCK` socket is refused with `EAFNOSUPPORT`. From any network
///   namespace, vsock reaches the hypervisor's host from a virtual machine
///   guest, and the host's own services where the host runs vsock loopback.
/// - `io_uring_setup` is refused with `ENOSYS`. A ring creates sockets of its
///   own, which no syscall filter sees.
/// - On x86, socket creation through `socketcall` is refused with
///   `EAFNOSUPPORT`, whatever the family. `socketcall` passes the address
///   family by pointer, where a filter cannot read it, and 64-bit code reaches
///   it through `int 0x80`. A 32-bit glibc program creates every socket that
///   way, so it creates none in such a sandbox, and reads each family as one
///   the kernel does not offer. A musl program tries the direct call first,
///   and a 64-bit program always makes it, so both create sockets as usual.
///
/// Each answer is the one a kernel without the facility gives, so a program
/// that probes for one reads it as absent. Every other address family is the
/// namespace's to govern. A seccomp policy of the hardening layer is installed
/// after the filter. Where both refuse a syscall with an errno, the command
/// sees the policy's. [`ResolvedInputs::network_filter`](crate::ResolvedInputs::network_filter)
/// records the refusals.
///
/// A host that cannot install the filter fails the launch at
/// [`SetupStep::InstallNetworkFilter`](crate::SetupStep::InstallNetworkFilter).
/// [`host::seccomp_available`](crate::host::seccomp_available) reports whether
/// this process can install one. [`Host`](Self::Host) carries no filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum Network {
    /// A new network namespace whose only interface is loopback, brought up
    /// during setup, and the filter the type's documentation describes. The
    /// sandbox has no external connectivity. This is the default.
    #[default]
    Isolated,
    /// Share the host's network namespace. The sandbox sees the host's
    /// interfaces, and the host's `resolv.conf` is bound read-only into the
    /// rootfs unless disabled with [`CageBuilder::resolv_conf`]. No network
    /// filter is installed: the host's network includes its vsock.
    Host,
    /// A new network namespace with no interface brought up, not even
    /// loopback, and the same filter as [`Isolated`](Self::Isolated). The
    /// sandbox has no connectivity at all. Unlike `Isolated`, it cannot even
    /// reach `127.0.0.1`.
    None,
}

/// The disposition of one of the command's standard streams.
///
/// One enum serves all three, through [`stdin`](CageBuilder::stdin),
/// [`stdout`](CageBuilder::stdout), and [`stderr`](CageBuilder::stderr). The
/// two unit variants are dispositions a profile can express;
/// [`Fd`](Self::Fd) hands the command an open descriptor and is therefore code,
/// not configuration. See [`from_fd`](Self::from_fd) for the descriptor form.
///
/// The variants read per position. On standard input,
/// [`Inherit`](Self::Inherit) hands the command the caller's own standard input
/// and [`Null`](Self::Null) is immediate end-of-file; on the output pair,
/// `Inherit` sends what the command writes wherever the caller's own output
/// goes and `Null` discards it.
///
/// `Inherit` states no destination: it is the absence of a choice rather than a
/// choice of the caller's descriptors, and what the command actually receives
/// follows from the launch. A capturing launch — [`run_with`](Cage::run_with),
/// [`output`](Cage::output), [`spawn_with`](Cage::spawn_with) — supplies the
/// output pair itself, and `Inherit` leaves it free to. `Null` and `Fd` state a
/// destination, so a launch that would supply its own is refused rather than
/// silently overriding what the caller said.
///
/// # The caller's terminal
///
/// Closing the caller's terminal to the sandbox takes all three streams, not
/// standard input alone. A controlling terminal is reached through the session
/// rather than through the filesystem — no namespace and no swapped root
/// affects it — and the rule is that a sandboxed command reaches the caller's
/// terminal exactly through the standard streams the caller handed it.
///
/// **The session follows standard input alone.**
/// [`Inherit`](Self::Inherit) there hands the command the caller's standard
/// input, so the command stays in the caller's session, where the terminal is
/// reachable through file descriptor 0 and equally through `/dev/tty`, which
/// names the same terminal. [`Null`](Self::Null) and [`Fd`](Self::Fd) do not,
/// so the command runs in a session of its own with no controlling terminal at
/// all: `/dev/tty` fails with `ENXIO`, and `TIOCSTI` — the ioctl that pushes
/// characters into a terminal's input queue, which the caller's shell would
/// then run — is refused on every terminal descriptor, since the kernel grants
/// it only for the caller's own controlling terminal.
///
/// **A session of the sandbox's own does not close the output pair.** It closes
/// what is reached *through the session*; a descriptor the caller handed over
/// is reached directly. Run from a shell with no redirection, file descriptors
/// 1 and 2 are dups of one read-write open of the caller's terminal, so a
/// command that inherits them can read what is typed at it, leave the caller's
/// terminal without echo with `tcsetattr`, and resize it with `TIOCSWINSZ`,
/// which delivers `SIGWINCH` to the caller's foreground process group. `Null`
/// or `Fd` on the output pair is what closes that, and a capturing launch
/// closes it too by supplying pipes of its own.
///
/// # A stream that is a file
///
/// A descriptor carries its file, and the file is reachable through it by path.
/// `/proc/self/fd/N` reopens whatever a descriptor names, with the access the
/// command's own credentials allow rather than the access the descriptor was
/// opened with. Under the single-identity map those credentials are the
/// caller's. A command whose standard input is an open file can therefore open
/// `/proc/self/fd/0` for writing and rewrite the file, and one whose standard
/// output is a log opened for appending can read the log back and truncate it.
/// [`Inherit`](Self::Inherit) and [`Fd`](Self::Fd) reach the file alike, and no
/// namespace or swapped root changes that.
///
/// A Landlock grant closes it: the reopened file lies outside every grant, so
/// the open is refused. Without one, a caller that means only a file's bytes to
/// cross hands the command a pipe and copies between the pipe and the file
/// itself. `fcage` does exactly that for a standard stream that is a regular
/// file or a block device.
///
/// A pipe, a socket, and `/dev/null` carry no such reach. Reopening a pipe
/// reaches the same pipe, and a socket cannot be reopened at all. A terminal is
/// the subject of the section above.
///
/// # A stream that is a directory
///
/// A directory descriptor reaches further than the directory. `/proc/self/fd/N`
/// and `openat(N, "..")` walk from it through the host's filesystem, past the
/// root the sandbox swapped in, so a command handed one could read and write
/// whatever the caller can. Every launch therefore refuses a directory on any
/// stream it hands over, with [`Error::StreamIsDirectory`](crate::Error::StreamIsDirectory),
/// before it creates anything. The rule covers [`Inherit`](Self::Inherit),
/// which hands over the caller's own descriptor as it stands at the launch,
/// and [`Fd`](Self::Fd) alike. A stream the launch replaces is not handed over
/// and is not examined: [`Null`](Self::Null), the output pair of a capturing
/// launch, and all three streams of a terminal launch.
///
/// # Job control
///
/// Job control has two senses, and the disposition decides where each happens.
///
/// *Caller-session job control* is the caller's shell managing the sandbox as
/// one of its own jobs: an interrupt typed at the caller's terminal reaches the
/// sandbox, `^Z` suspends it, `fg` resumes it. *Sandbox-session job control* is
/// a shell inside the sandbox running jobs of its own, which takes `tcsetpgrp`
/// on a terminal whose session that shell shares.
///
/// Under `Inherit` on standard input the sandbox stays in the caller's
/// session, so a shell inside it runs jobs of its own on the caller's
/// terminal, competing with the caller's own shell for it. With a PID
/// namespace, the default, the sandbox is a process group of its own in that
/// session, which keeps the caller's group out of reach of the signals the
/// sandbox sends its own. An interactive run, whose standard input and
/// standard output are both the caller's controlling terminal while the
/// caller's group holds its foreground, lends the sandbox's group the
/// foreground until the outcome is collected: an interrupt typed at the
/// terminal reaches the sandbox, and `^Z` does not suspend it. With output
/// piped, redirected, or captured, the caller's job keeps the terminal, so a
/// pipeline's far end reads it as before. The sandbox is then a background
/// group of the terminal, orphaned once the launch stage exits, so its reads
/// of the terminal fail, and an interrupt reaches the caller's job rather than
/// the sandbox. Without a PID namespace
/// the command is in the caller's own process group, and the caller's shell
/// manages it as any job.
///
/// Under `Null` or `Fd` neither sense works: the sandbox is outside the
/// caller's session, and the session it has instead owns no terminal to run
/// jobs against. A caller that wants to stop such a command on an interrupt
/// uses [`Running::terminate`](crate::Running::terminate) or
/// [`Running::kill`](crate::Running::kill).
///
/// [`Cage::spawn_terminal`] is the posture where the second sense works without
/// the first's cost: the sandbox gets a terminal of its own, so a shell inside
/// it takes *that* terminal's foreground process group and the caller's is not
/// involved at all.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum Stdio {
    /// The stream is left as the launch inherited it: what the caller's own
    /// stream is wired to, unless the launch supplies its own destination.
    /// This is the default for all three.
    ///
    /// On standard input it also keeps the command in the caller's session,
    /// and with it the caller's controlling terminal; see
    /// [Job control](#job-control). A launch refuses a
    /// caller's stream that is a directory; see
    /// [A stream that is a directory](#a-stream-that-is-a-directory).
    ///
    /// A stream the caller has closed reaches the command closed. The launch
    /// keeps every descriptor of its own above the standard streams' numbers,
    /// so none of them takes the closed stream's place, and the caller's closed
    /// number stays closed through the launch.
    #[default]
    Inherit,
    /// The stream is wired to `/dev/null`: immediate end-of-file on standard
    /// input, and a discard on the output pair.
    ///
    /// On standard input the command also runs in a session of its own.
    Null,
    /// The stream is a descriptor the caller supplies.
    ///
    /// On standard input the command also runs in a session of its own.
    ///
    /// Built with [`from_fd`](Self::from_fd). The descriptor is shared rather
    /// than owned outright because a [`Cage`] is a clonable frozen plan that
    /// launches any number of times, so no single launch can consume it.
    Fd(Arc<OwnedFd>),
}

impl Stdio {
    /// The stream is wired to `fd`.
    ///
    /// The descriptor is duplicated onto the command's own file descriptor
    /// after the pivot and survives `execve`; the caller's own copy is
    /// unaffected. What serves follows from the position: anything readable on
    /// standard input — the read end of a pipe the caller writes, an open file,
    /// a pseudoterminal replica — and anything writable on the output pair. A
    /// directory serves on neither, and a launch refuses one; see
    /// [A stream that is a directory](Stdio#a-stream-that-is-a-directory).
    ///
    /// The descriptor is *shared*, not consumed: a [`Cage`] is a frozen plan
    /// that can launch repeatedly, and every launch wires the same descriptor.
    /// For a pipe on standard input that means the second launch reads whatever
    /// the first left, so a cage feeding distinct input per launch is built per
    /// launch; for a file on an output stream it means the second launch appends
    /// where the first stopped, since the offset is a property of the open file
    /// description both share.
    ///
    /// The caller owns both ends of whatever it supplies. Feeding a pipe from
    /// the same thread that waits for the command deadlocks once the write
    /// exceeds the pipe's capacity (64 KiB by default), because nothing is
    /// draining the command's output meanwhile; write the input and close the
    /// write end before waiting, or drive the write from another thread.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::io::Write;
    ///
    /// use ferroday_cage::{Cage, Stdio};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (reader, mut writer) = std::io::pipe()?;
    /// let cage = Cage::builder()
    ///     .rootfs("/srv/rootfs/alpine")
    ///     .stdin(Stdio::from_fd(reader.into()))
    ///     .command("/bin/sh")
    ///     .args(["-c", "wc -l"])
    ///     .build()?;
    ///
    /// // Write the input and close the write end, so the command sees
    /// // end-of-file rather than waiting for more.
    /// writer.write_all(b"one\ntwo\n")?;
    /// drop(writer);
    ///
    /// let output = cage.output()?;
    /// assert_eq!(output.stdout.trim_ascii(), b"2");
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_fd(fd: OwnedFd) -> Stdio {
        Stdio::Fd(Arc::new(fd))
    }
}

// A descriptor has no profile representation, so the two unit dispositions
// serialize as their lowercase names and `Fd` is refused outright rather than
// serialized as something a reader would take for a disposition it is not.
#[cfg(feature = "serde")]
impl serde::Serialize for Stdio {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Stdio::Inherit => serializer.serialize_str("inherit"),
            Stdio::Null => serializer.serialize_str("null"),
            Stdio::Fd(_) => Err(serde::ser::Error::custom(
                "a standard-stream descriptor cannot be represented in a profile",
            )),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Stdio {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Stdio, D::Error> {
        let name = String::deserialize(deserializer)?;
        match name.as_str() {
            "inherit" => Ok(Stdio::Inherit),
            "null" => Ok(Stdio::Null),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["inherit", "null"],
            )),
        }
    }
}

/// A raw mount operation, for options the typed profile does not model yet.
///
/// A raw mount is passed to the kernel as given: the source, filesystem
/// type, flags, and data string go into the `mount` syscall verbatim, and a
/// refused mount surfaces as a setup error naming this mount. Only the
/// target is validated and confined — it must be a normal absolute path,
/// resolved inside the rootfs, and missing directories along it are
/// created.
///
/// Raw mounts and bind mounts share one sequence, applied in the order they
/// are configured.
///
/// # Example
///
/// ```
/// use ferroday_cage::RawMount;
///
/// // MS_NOSUID | MS_NODEV | MS_NOEXEC
/// let sysfs = RawMount::new("/sys").fstype("sysfs").flags(0xE);
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub struct RawMount {
    /// The mount target, an absolute path inside the sandbox.
    target: PathBuf,
    /// The mount source, passed to the kernel verbatim.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    source: Option<PathBuf>,
    /// The filesystem type.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    fstype: Option<String>,
    /// Mount flags: the kernel's raw `MS_*` bits.
    #[cfg_attr(feature = "serde", serde(default))]
    flags: u64,
    /// The filesystem data string.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    data: Option<String>,
}

impl RawMount {
    /// Returns a raw mount of the given target, an absolute path inside the
    /// sandbox.
    pub fn new(target: impl AsRef<Path>) -> RawMount {
        RawMount {
            target: target.as_ref().to_path_buf(),
            source: None,
            fstype: None,
            flags: 0,
            data: None,
        }
    }

    /// Sets the mount source, passed to the kernel verbatim.
    pub fn source(mut self, source: impl AsRef<Path>) -> RawMount {
        self.source = Some(source.as_ref().to_path_buf());
        self
    }

    /// Sets the filesystem type.
    pub fn fstype(mut self, fstype: impl Into<String>) -> RawMount {
        self.fstype = Some(fstype.into());
        self
    }

    /// Sets the mount flags: the kernel's raw `MS_*` bits.
    pub fn flags(mut self, flags: u64) -> RawMount {
        self.flags = flags;
        self
    }

    /// Sets the filesystem data string.
    pub fn data(mut self, data: impl Into<String>) -> RawMount {
        self.data = Some(data.into());
        self
    }

    /// The mount target inside the sandbox.
    pub fn get_target(&self) -> &Path {
        &self.target
    }

    /// The mount source, when one was set.
    pub fn get_source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    /// The filesystem type, when one was set.
    pub fn get_fstype(&self) -> Option<&str> {
        self.fstype.as_deref()
    }

    /// The raw `MS_*` mount flags.
    pub fn get_flags(&self) -> u64 {
        self.flags
    }

    /// The filesystem data string, when one was set.
    pub fn get_data(&self) -> Option<&str> {
        self.data.as_deref()
    }
}

/// A validated, ready-to-run sandbox.
///
/// A `Cage` is constructed by [`Cage::builder`]; all validation and all
/// fallible preparation happen in [`CageBuilder::build`], which freezes the
/// configuration into a launch plan. [`Cage::run`] then executes the command
/// inside the sandbox and blocks until it terminates.
///
/// The rootfs is resolved to a canonical path and validated at build time;
/// each launch resolves that canonical path again inside the sandbox's own
/// mount namespace.
///
/// A `Cage` holds no live resources — it is a frozen plan — so it is `Clone`
/// and every launch method takes `&self`. One cage can launch the same
/// sandbox any number of times, concurrently or in sequence, and a clone is
/// an independent copy a caller can adjust nothing on (adjustment happens on
/// the [`CageBuilder`], which is also `Clone`).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Cage {
    /// The frozen launch plan the mechanism executes.
    plan: LaunchPlan,
}

impl Cage {
    /// Returns a builder for configuring a sandbox.
    pub fn builder() -> CageBuilder {
        CageBuilder::default()
    }

    /// The environment and mounts this cage will actually apply.
    ///
    /// Where the builder's `get_` accessors report what the caller asked for,
    /// this reports what that request resolved to: the caller's variables
    /// composed over the library's base, and the caller's mounts behind the
    /// managed profile, in the order the sandbox establishes them.
    ///
    /// The value a consumer stamps into an artifact's provenance to record the
    /// inputs a build ran under. See [`ResolvedInputs`] for what its
    /// contents do and do not promise.
    pub fn resolved_inputs(&self) -> ResolvedInputs {
        ResolvedInputs::project(&self.plan)
    }

    /// Runs the command inside the sandbox and blocks until it terminates.
    ///
    /// Returns `Ok` with the command's [`ExitStatus`] whenever the command was
    /// executed, regardless of its exit code. `Err` is reserved for the
    /// library failing: spawning the sandbox process, a setup step inside it,
    /// or collecting its outcome.
    ///
    /// The command runs with the stream dispositions the sandbox carries,
    /// which are inherited unless the builder said otherwise.
    pub fn run(&self) -> Result<ExitStatus, Error> {
        self.spawn()?.wait()
    }

    /// Runs the command inside the sandbox, streaming its output to the
    /// observer, and blocks until it terminates.
    ///
    /// Like [`run`](Self::run), but the command's standard output and
    /// standard error are captured and delivered to `observer` as they are
    /// produced, on the calling thread.
    pub fn run_with(&self, observer: &mut dyn Observer) -> Result<ExitStatus, Error> {
        self.spawn_with(observer)?.wait()
    }

    /// Runs the command inside the sandbox and returns its exit status
    /// together with everything it wrote.
    ///
    /// The whole-run convenience: [`run_with`](Self::run_with) against an
    /// observer that keeps both streams entire.
    ///
    /// ```no_run
    /// # fn main() -> ferroday_cage::Result<()> {
    /// let output = ferroday_cage::Cage::builder()
    ///     .rootfs("/srv/rootfs/alpine")
    ///     .command("/bin/sh")
    ///     .args(["-c", "echo out; echo err >&2"])
    ///     .build()?
    ///     .output()?;
    /// assert!(output.status.success());
    /// assert_eq!(output.stdout, b"out\n");
    /// assert_eq!(output.stderr, b"err\n");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// What it keeps is unbounded: a command that writes without stopping is
    /// held entirely in memory. For a command whose output volume the caller
    /// does not control — model-generated code, an untrusted build — use
    /// [`run_with`](Self::run_with) with an [`Observer`] that caps what it
    /// retains, or [`spawn_with`](Self::spawn_with) with a deadline.
    ///
    /// Capture reaches the command's descendants too, and with it the endpoint
    /// of the wait; see [`Running::wait`](crate::Running::wait) for the case
    /// where the command leaves descendants behind.
    pub fn output(&self) -> Result<Output, Error> {
        Running::output(&self.plan)
    }

    /// Starts the command inside the sandbox and returns a handle to it.
    ///
    /// `spawn` blocks until the sandbox is set up and the command is
    /// executing, so a setup failure is reported here, as the same typed
    /// error [`run`](Self::run) would return. The command runs with
    /// the stream dispositions the sandbox carries; the returned [`Running`] waits for,
    /// signals, or kills it.
    pub fn spawn(&self) -> Result<Running<'static>, Error> {
        Running::launch(&self.plan, None)
    }

    /// Starts the command inside the sandbox, capturing its output for the
    /// observer, and returns a handle to it.
    ///
    /// Like [`spawn`](Self::spawn), but the command's standard output and
    /// standard error are captured into pipes. The captured bytes are
    /// delivered to `observer` while the returned handle is waited on;
    /// see [`Observer`].
    pub fn spawn_with<'obs>(
        &self,
        observer: &'obs mut dyn Observer,
    ) -> Result<Running<'obs>, Error> {
        Running::launch(&self.plan, Some(observer))
    }

    /// Starts the sandbox but holds the command before it runs, returning a
    /// [`Pending`] handle — the userspace-network seam.
    ///
    /// The namespaces are created and the supervisor is published, but the
    /// command is held at a gate before its own confinement and its `execve`.
    /// The returned handle
    /// exposes [`netns_pid`](Pending::netns_pid), a process in the sandbox's
    /// network namespace, so a caller can attach a userspace network stack
    /// (`pasta`, `slirp4netns`) to `/proc/<pid>/ns/net` before releasing the
    /// command with [`proceed`](Pending::proceed). Attaching a stack before
    /// proceeding is what lets the command see the network from its first
    /// instruction, with no race against the stack's startup.
    ///
    /// The seam is meaningful only for a network posture with a private
    /// namespace — [`Network::Isolated`] (the default) or [`Network::None`];
    /// under [`Network::Host`] the sandbox shares the host's network
    /// namespace and there is nothing to attach.
    ///
    /// The call returns once the command is at the gate, with the sandbox's
    /// namespaces and mounts in place, so a setup step that fails up to there,
    /// a refused mount or a failed pivot, is its error. One that fails past the
    /// gate, in the command's nested user namespace, the identity switch, the
    /// hardening, or the exec, is `proceed`'s.
    ///
    /// A caller that needs no pause uses [`spawn`](Self::spawn) instead; this
    /// entry point exists for the attach-then-run sequence.
    pub fn spawn_pending(&self) -> Result<Pending<'static>, Error> {
        Pending::launch(&self.plan, None)
    }

    /// Starts the sandbox held before its command runs, capturing the
    /// command's output for the observer once it is released.
    ///
    /// Like [`spawn_pending`](Self::spawn_pending), but the observer bound
    /// here receives the command's captured output while the [`Running`]
    /// handle from [`proceed`](Pending::proceed) is waited on, exactly as
    /// [`spawn_with`](Self::spawn_with) does for a direct launch.
    pub fn spawn_pending_with<'obs>(
        &self,
        observer: &'obs mut dyn Observer,
    ) -> Result<Pending<'obs>, Error> {
        Pending::launch(&self.plan, Some(observer))
    }

    /// Starts the command on a pseudoterminal of its own, returning a handle to
    /// it and the caller's end of the terminal.
    ///
    /// The replica is wired onto the command's file descriptors 0, 1 and 2 — a
    /// terminal is one stream — and the launch owns its session, so the
    /// pseudoterminal is the sandbox's controlling terminal whatever the
    /// standard-input disposition would otherwise have decided. `isatty` is
    /// deterministically true inside, a full-screen program behaves, and a shell
    /// inside the sandbox runs jobs of its own. Nothing of the *caller's*
    /// terminal is reachable.
    ///
    /// The two values come back together because the caller holds both at once
    /// and drives them against each other — reading the primary while waiting on
    /// the command. See [`Pty`] for what that takes, including the one ordering
    /// that deadlocks.
    ///
    /// Nothing is captured, so no [`Observer`] is involved and no
    /// [`Progress`](crate::Progress) milestone is reported. A terminal composes
    /// with [`Stdio::Inherit`] on all three streams and is refused against a
    /// disposition that names a destination of its own, since the replica is
    /// already all three.
    ///
    /// ```no_run
    /// use ferroday_cage::{Cage, Terminal};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let cage = Cage::builder()
    ///     .rootfs("/srv/rootfs/alpine")
    ///     .command("/bin/sh")
    ///     .env("TERM", "xterm-256color")
    ///     .build()?;
    ///
    /// let (mut running, mut pty) = cage.spawn_terminal(&Terminal::new())?;
    /// std::io::copy(&mut pty, &mut std::io::stdout())?;
    /// let status = running.wait()?;
    /// # let _ = status;
    /// # Ok(())
    /// # }
    /// ```
    pub fn spawn_terminal(&self, terminal: &Terminal) -> Result<(Running<'static>, Pty), Error> {
        Running::launch_terminal(&self.plan, terminal)
    }

    /// [`spawn_terminal`](Self::spawn_terminal), held at the gate before the
    /// command runs — the userspace-network seam with a terminal.
    ///
    /// The composition an interactive session needs: a shell with outbound
    /// networking. The primary comes back here rather than out of
    /// [`proceed`](Pending::proceed), because the sandbox allocates the
    /// pseudoterminal and sends its primary before the command reaches the
    /// gate, and this returns once the command is there, so a setup step that
    /// fails before the gate is reported here rather than by `proceed`. Nothing
    /// writes to the terminal while the launch is held, so the caller attaches
    /// its stack and proceeds with the primary in hand.
    pub fn spawn_pending_terminal(
        &self,
        terminal: &Terminal,
    ) -> Result<(Pending<'static>, Pty), Error> {
        Pending::launch_terminal(&self.plan, terminal)
    }
}

/// One bind mount a sandbox carries: a host path presented at a path inside.
///
/// Added with [`CageBuilder::bind`] or [`CageBuilder::bind_ro`], or as a
/// `[[mount]]` table with `kind = "bind"` in a profile, and read back through
/// [`CageBuilder::get_binds`].
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub struct Bind {
    source: PathBuf,
    target: PathBuf,
    #[cfg_attr(feature = "serde", serde(default))]
    read_only: bool,
}

impl Bind {
    /// Returns a read-write bind of `source`, a host path, at `target`, an
    /// absolute path inside the sandbox.
    ///
    /// [`CageBuilder::bind`] and [`CageBuilder::bind_ro`] are the ordinary way
    /// to add one. This constructor is for a consumer assembling a
    /// [`Mount`] sequence directly, which [`CageBuilder::mount`] and
    /// [`CageBuilder::mounts`] add.
    pub fn new(source: impl AsRef<Path>, target: impl AsRef<Path>) -> Bind {
        Bind {
            source: source.as_ref().to_path_buf(),
            target: target.as_ref().to_path_buf(),
            read_only: false,
        }
    }

    /// Sets whether the bind is remounted read-only.
    pub fn read_only(mut self, read_only: bool) -> Bind {
        self.read_only = read_only;
        self
    }

    /// The host path the bind presents.
    pub fn get_source(&self) -> &Path {
        &self.source
    }

    /// The path inside the sandbox it is presented at.
    pub fn get_target(&self) -> &Path {
        &self.target
    }

    /// Whether the bind is remounted read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }
}

/// One symbolic link a sandbox creates: a link at a path inside, pointing at a
/// target.
///
/// Added with [`CageBuilder::symlink`], or as a `[[mount]]` table with
/// `kind = "symlink"` in a profile, and read back through
/// [`CageBuilder::get_mounts`]. It takes its place in the mount sequence, so a
/// link is made after the mounts declared before it and before those declared
/// after. That is what lays out the links of a root composed from binds, such
/// as `/bin` pointing at `usr/bin` beside a bind of the host's `/usr`.
///
/// The link is made in whatever holds its path at that point: an
/// [empty root](CageBuilder::empty_rootfs), a tmpfs mounted earlier, or a
/// plain rootfs on the host, where it stays after the sandbox exits. A path
/// that already holds a link with the same target is left as it is, so a
/// sandbox over a persistent rootfs launches again. Anything else at the path
/// fails the launch.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub struct Symlink {
    target: PathBuf,
    path: PathBuf,
}

impl Symlink {
    /// Returns a link at `path`, an absolute path inside the sandbox, pointing
    /// at `target`.
    ///
    /// The target is written into the link as given, in the order `ln -s`
    /// takes them. A relative target resolves from the link's directory, and
    /// an absolute one inside the sandbox, as every link the command follows
    /// does. [`CageBuilder::symlink`] is the ordinary way to add one.
    pub fn new(target: impl AsRef<Path>, path: impl AsRef<Path>) -> Symlink {
        Symlink {
            target: target.as_ref().to_path_buf(),
            path: path.as_ref().to_path_buf(),
        }
    }

    /// The path the link points at, as written.
    pub fn get_target(&self) -> &Path {
        &self.target
    }

    /// The link's own path inside the sandbox.
    pub fn get_path(&self) -> &Path {
        &self.path
    }
}

/// A path inside the sandbox the command finds empty: a directory holding
/// nothing, or an empty file, either on a read-only mount.
///
/// Added with [`CageBuilder::hide`], or as a `[[mount]]` table with
/// `kind = "hide"` in a profile. It takes its place in the mount sequence, and
/// works on every kind of root.
///
/// What is at the path when the sequence reaches it decides what hides it. A
/// directory gets an empty tmpfs of the sandbox's own, mounted `nosuid`,
/// `nodev` and `noexec`, and made read-only once the mount profile is in
/// place, so a later mount can still be made beneath it: a working tree bound
/// back into a hidden home directory, for one. Anything else gets an empty
/// regular file bound over it from a tmpfs of the sandbox's own, read-only
/// from the start. Reads find nothing there, and a write fails with `EROFS`
/// wherever the file's permissions, `0644` to the sandbox's root, admit one.
///
/// A path with nothing at it hides nothing and is not an error, so one list of
/// paths serves hosts that hold different subsets of them. A mount declared
/// after it, beneath that path, lands where it would with no hide: in the root,
/// where a file target the launch creates is removed once the sandbox is gone,
/// or, on the host's own root, at a target the host must already hold. A
/// symbolic link at the path is followed inside the root, as every mount target
/// is, and what it names is hidden.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub struct Hide {
    target: PathBuf,
}

impl Hide {
    /// Hides `target`, an absolute path inside the sandbox.
    ///
    /// [`CageBuilder::hide`] is the ordinary way to add one.
    pub fn new(target: impl AsRef<Path>) -> Hide {
        Hide {
            target: target.as_ref().to_path_buf(),
        }
    }

    /// The path inside the sandbox it hides.
    pub fn get_target(&self) -> &Path {
        &self.target
    }
}

/// A path inside the sandbox made read-only where it stands: the tree at the
/// path is bound onto itself, read-only, with every mount beneath it.
///
/// Added with [`CageBuilder::read_only`], or as a `[[mount]]` table with
/// `kind = "read-only"` in a profile. It takes its place in the mount
/// sequence, after the mount that brought the path, and works on every kind
/// of root. It protects a path inside a writable bind, such as a working
/// tree's `.git/hooks`, without naming the host path the bind came from, so it
/// holds wherever the tree is bound from.
///
/// The path must exist when the sequence reaches it, or the launch fails at
/// [`SetupStep::OpenMountTarget`](crate::SetupStep::OpenMountTarget): a path
/// left writable because it was missing is one the command could create. A
/// symbolic link at the path is followed inside the root, as every mount
/// target is.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub struct ReadOnly {
    target: PathBuf,
}

impl ReadOnly {
    /// Makes `target`, an absolute path inside the sandbox, read-only.
    ///
    /// [`CageBuilder::read_only`] is the ordinary way to add one.
    pub fn new(target: impl AsRef<Path>) -> ReadOnly {
        ReadOnly {
            target: target.as_ref().to_path_buf(),
        }
    }

    /// The path inside the sandbox it makes read-only.
    pub fn get_target(&self) -> &Path {
        &self.target
    }
}

/// One mount a consumer adds to a sandbox: a bind, a raw mount, a symbolic
/// link, a hidden path, or a path made read-only.
///
/// The sandbox applies these in the order they are declared, after the
/// managed mount profile. Holding every kind in one sequence is what makes
/// that order expressible: a raw tmpfs and the binds that populate it can be
/// interleaved, which a bind-then-raw arrangement cannot express.
///
/// Added with [`CageBuilder::bind`], [`CageBuilder::bind_ro`],
/// [`CageBuilder::raw_mount`], [`CageBuilder::symlink`], [`CageBuilder::hide`],
/// and [`CageBuilder::read_only`], whole with [`CageBuilder::mount`] and
/// [`CageBuilder::mounts`], or as a `[[mount]]` table in a profile, and read
/// back through [`CageBuilder::get_mounts`].
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(tag = "kind", rename_all = "kebab-case")
)]
pub enum Mount {
    /// A bind mount of a host path.
    Bind(Bind),
    /// A raw mount, passed to the kernel verbatim.
    Raw(RawMount),
    /// A symbolic link, created in the sandbox's filesystem.
    Symlink(Symlink),
    /// A path the command finds empty.
    Hide(Hide),
    /// A path made read-only where it stands.
    ReadOnly(ReadOnly),
}

impl Mount {
    /// The path inside the sandbox the mount is established at.
    ///
    /// For a [`Symlink`](Self::Symlink) this is the link itself, not the path
    /// it points at, as [`ResolvedMount::get_target`] reports it.
    ///
    /// [`ResolvedMount::get_target`]: crate::ResolvedMount::get_target
    pub fn get_target(&self) -> &Path {
        match self {
            Mount::Bind(bind) => bind.get_target(),
            Mount::Raw(raw) => raw.get_target(),
            Mount::Symlink(symlink) => symlink.get_path(),
            Mount::Hide(hide) => hide.get_target(),
            Mount::ReadOnly(read_only) => read_only.get_target(),
        }
    }
}

/// An overlay root: an ordered stack of read-only lower layers, and the upper
/// layer every write lands in.
///
/// Set on a builder with [`CageBuilder::overlay`]. The command sees a merged
/// view: the lowers stay pristine, while every create, modify, and delete the
/// sandbox performs lands in the upper. Discarding the upper afterward reverts
/// the sandbox's changes — the "run against a base, discard the changes" model,
/// and the basis for staging a build root of `base + increment` over a shared,
/// unmodified base.
///
/// # Example
///
/// ```no_run
/// use ferroday_cage::{Cage, Overlay};
///
/// # fn main() -> Result<(), ferroday_cage::Error> {
/// let cage = Cage::builder()
///     .overlay(
///         Overlay::new()
///             .lower("/srv/base")
///             .lower("/srv/patches")
///             .upper("/srv/scratch/run-1"),
///     )
///     .command("/bin/sh")
///     .build()?;
/// # let _ = cage;
/// # Ok(())
/// # }
/// ```
///
/// # Where the upper lives
///
/// The upper and its work directory are the one part of an overlay root the
/// library creates on the host, and they should live under a directory the
/// calling user controls, not a world-writable one such as `/var/tmp` — the same
/// requirement [`CageBuilder::rootfs`] states for a plain root.
///
/// An entry already at either path is adopted only when it is a directory
/// belonging to the calling user, and is otherwise refused with
/// [`ConfigError::OverlayDirUnowned`], so a symbolic link another user planted
/// there is never followed. That check closes the create; it does not make a
/// shared parent safe, since the mount options name the layers as paths and the
/// kernel resolves them again at mount time.
///
/// [`ConfigError::OverlayDirUnowned`]: crate::ConfigError::OverlayDirUnowned
///
/// # Disjoint layers
///
/// Every layer lies outside every other: no lower, upper, or work directory is
/// another, or lies beneath one. The kernel mounts an upper or a work
/// directory beneath a lower, and every write the sandbox makes then lands in
/// that lower, so [`build`](CageBuilder::build) refuses the overlap with
/// [`ConfigError::OverlayLayersOverlap`] before it creates anything on the
/// host. It refuses the overlaps the kernel itself refuses at mount as well.
///
/// The comparison is between the paths the mount options name. Every lower is
/// canonicalized, and the upper and the work directory are their parent's
/// canonical path joined with their own name, a parent that does not exist yet
/// resolved as it will be once created. A symbolic link above a layer is
/// therefore followed, and two spellings of one directory compare equal. A
/// directory a bind mount presents at a second path is not recognised there.
///
/// [`ConfigError::OverlayLayersOverlap`]: crate::ConfigError::OverlayLayersOverlap
///
/// # Layer order
///
/// Lowers stack base-first, the way image layers do: the first added is the
/// base, and each later one is laid over it, so a later lower shadows an earlier
/// one where both hold the same path. The first lower is also the directory the
/// overlay is mounted over, and the one the sandbox pivots into.
///
/// (The kernel's own `lowerdir=` option is highest-precedence-first, the reverse
/// of this order; the mount options are emitted reversed to match.)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(default, rename_all = "kebab-case", deny_unknown_fields)
)]
pub struct Overlay {
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    lower: Vec<PathBuf>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    upper: Option<PathBuf>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    work: Option<PathBuf>,
}

impl Overlay {
    /// Returns an empty overlay, to be given at least one lower and an upper.
    pub fn new() -> Overlay {
        Overlay::default()
    }

    /// Appends a read-only lower layer, over any already added.
    ///
    /// Repeatable and ordered: the first lower is the base the overlay is
    /// mounted over, and each later one is laid over it, shadowing what an
    /// earlier lower holds at the same path. Each must exist and be a directory,
    /// exactly as [`CageBuilder::rootfs`] requires.
    pub fn lower(mut self, path: impl AsRef<Path>) -> Overlay {
        self.lower.push(path.as_ref().to_path_buf());
        self
    }

    /// Sets the upper layer, where every write lands.
    ///
    /// Created if absent, and persists on the host after the sandbox exits: it
    /// is the caller's to keep or discard. Its filesystem must record `user.*`
    /// extended attributes, so an on-disk filesystem (ext4, xfs, btrfs) works on
    /// Linux 5.11 and later, while a tmpfs upper needs Linux 6.6.
    ///
    /// It must live under a directory the calling user controls, not a
    /// world-writable one — see [Where the upper lives](Overlay#where-the-upper-lives).
    /// The upper is also not the filesystem root: it needs a parent directory
    /// for the work directory beside it.
    pub fn upper(mut self, path: impl AsRef<Path>) -> Overlay {
        self.upper = Some(path.as_ref().to_path_buf());
        self
    }

    /// Overrides the work directory the overlay requires.
    ///
    /// By default the library manages a hidden sibling of the upper. A caller
    /// naming its own must place it on the same filesystem as the upper, which
    /// the overlay requires so it can move files between them; a work directory
    /// on another filesystem is refused at build time rather than at the mount.
    /// It carries the same parent-directory requirement the upper does — see
    /// [Where the upper lives](Overlay#where-the-upper-lives).
    ///
    /// The work area holds a directory the kernel creates mode `0`, which the
    /// calling user cannot read into. Discard a work directory named here with
    /// [`provision::Remove`](crate::provision::Remove) under the map the
    /// sandbox ran under, declining the lock: a removal it refuses escalates
    /// through that map.
    pub fn work(mut self, path: impl AsRef<Path>) -> Overlay {
        self.work = Some(path.as_ref().to_path_buf());
        self
    }

    /// The read-only lower layers, base-first.
    pub fn get_lowers(&self) -> &[PathBuf] {
        &self.lower
    }

    /// The upper layer every write lands in, when one was set.
    pub fn get_upper(&self) -> Option<&Path> {
        self.upper.as_deref()
    }

    /// The caller-named work directory, when one was set. `None` means the
    /// library manages a hidden sibling of the upper.
    pub fn get_work(&self) -> Option<&Path> {
        self.work.as_deref()
    }
}

/// Builder for a [`Cage`].
///
/// A sandbox needs at least a rootfs and a command:
///
/// ```no_run
/// use ferroday_cage::Cage;
///
/// # fn main() -> Result<(), ferroday_cage::Error> {
/// let status = Cage::builder()
///     .rootfs("/srv/rootfs/alpine")
///     .command("/bin/sh")
///     .args(["-c", "echo hello"])
///     .build()?
///     .run()?;
/// assert!(status.success());
/// # Ok(())
/// # }
/// ```
///
/// By default the sandbox mounts `/proc`, a minimal `/dev`, and a tmpfs
/// `/tmp` over the rootfs, runs in its own PID namespace under a reaping
/// init and in an isolated loopback-only network namespace, starts in `/`
/// with the deterministic base environment (`PATH`, and `HOME` for a command
/// running as root inside), and keeps the host's hostname. Every part of that profile has a builder method to
/// change it.
///
/// With the `serde` feature the builder is the profile format: it
/// serializes and deserializes as the sandbox specification, so a profile
/// file is a `CageBuilder` in any serde format. Keys are kebab-case;
/// unknown keys are rejected. In TOML:
///
/// ```toml
/// rootfs = "/srv/rootfs/alpine"
/// command = "/usr/bin/make"
/// network = "host"
/// workdir = "/build"
///
/// [env]
/// CARGO_HOME = "/cache/cargo"
///
/// [[mount]]
/// kind = "bind"
/// source = "/home/user/project"
/// target = "/build"
///
/// [[mount]]
/// kind = "bind"
/// source = "/home/user/cache"
/// target = "/cache"
/// read-only = true
/// ```
///
/// # Trust
///
/// Deserializing a profile straight into a `CageBuilder` trusts it as
/// code-equivalent configuration. A profile can bind any host path into the
/// sandbox (`/`, `/etc/shadow`), issue a raw mount with an arbitrary source,
/// type, flags, and data, share the host network namespace, and overmount the
/// sandbox's managed `/proc` and `/dev`. Under the single-identity map these
/// take effect as the calling user, so it is an isolation bypass rather than a
/// privilege escalation — but a consumer that loads profiles from an untrusted
/// source (a repository, a download, a multi-tenant store) hands that source
/// the full sandbox surface.
///
// The paragraph links a feature-gated item, so it is gated on the feature: a
// build without `serde` loads no profile at all.
#[cfg_attr(
    feature = "serde",
    doc = "
Load a profile from an untrusted source through
[`RestrictedProfile`](crate::RestrictedProfile) instead, whose documentation
lists what it refuses: the operations that map host resources into the
sandbox, write to the host, or share a host namespace, and the hardening a
consumer's own calls add to rather than replace. What it yields is a builder
the consumer extends with its own trusted calls.
"
)]
///
/// # Inspection
///
/// A builder can be read back as well as written. Every setting has a `get_`
/// accessor — [`get_binds`](Self::get_binds),
/// [`get_network`](Self::get_network),
/// [`get_identity_map`](Self::get_identity_map), and so on — so a consumer
/// that loads configuration it did not write can answer "what does this bind?"
/// and "does this share the host network?" before launching it. The prefix
/// exists because the setters own the bare names, the same arrangement
/// [`std::process::Command`] uses.
///
/// The whole builder is also `Debug`, and with `serde` it serializes back to
/// the profile format, so `toml::to_string(&builder)` renders a configuration
/// for review. Some things do not survive that. An
/// [`id_mapper`](Self::id_mapper) delegate is code rather than configuration,
/// and is simply absent from the output. A builder holding anything a profile
/// cannot spell fails to serialize at all: a
/// [`Stdio::from_fd`](crate::Stdio::from_fd) disposition, since a descriptor
/// names nothing a profile could carry; a value that is not UTF-8, since a
/// profile is text; and a seccomp policy the profile's table cannot state,
/// which is a precompiled program, a rule set whose actions are not a plain
/// allow-list's or deny-list's, or one that names no syscall. Everything else
/// round-trips.
// Scalar fields precede the env table and the bind and raw-mount table
// arrays so the serialized form is valid TOML in field order.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(default, rename_all = "kebab-case", deny_unknown_fields)
)]
pub struct CageBuilder {
    rootfs: Option<PathBuf>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "std::ops::Not::not"))]
    empty_rootfs: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "std::ops::Not::not"))]
    host_rootfs: bool,
    // The host root's default hides the caller takes back. An array of strings
    // is a value rather than a table, so it may sit among the scalars.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    reveal: Vec<PathBuf>,
    command: Option<PathBuf>,
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_os::string_vec", skip_serializing_if = "Vec::is_empty")
    )]
    args: Vec<OsString>,
    network: Network,
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_os::string_opt", skip_serializing_if = "Option::is_none")
    )]
    hostname: Option<OsString>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    workdir: Option<PathBuf>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    pid_namespace: bool,
    // The managed mounts are `Option<bool>` rather than `bool` so that "left at
    // its default" is distinguishable from "explicitly asked for". Only that
    // distinction lets `managed_mounts(false)` refuse a contradicting
    // `mount_dev(true)` instead of silently overriding it. `None` reads as the
    // default, which every one of them documents as `true`.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    managed_mounts: Option<bool>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    mount_proc: Option<bool>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    mount_dev: Option<bool>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    mount_tmp: Option<bool>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    resolv_conf: Option<bool>,
    // Whether the library's deterministic base environment is composed under
    // the caller's variables. `false` means the command's environment is
    // exactly what the caller set, with nothing of the library's underneath.
    // `Option` for the same reason the mount toggles carry one: a profile
    // records what its author asked for, and an unstated key stays unstated
    // through a render-and-reload cycle.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    base_env: Option<bool>,
    stop_with_caller: bool,
    path_lookup: bool,
    // The identity fields sit between the scalars and the tables. The presented
    // identity is always a string and the run-as identity always a table, and
    // the map is a string for the unit forms and a table for ranges, so this
    // order keeps the serialized profile valid TOML in field order whichever
    // form the map takes.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    present_as: Option<PresentedIdentity>,
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "identity_map_is_default")
    )]
    identity_map: IdentityMap,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    run_as: Option<Identity>,
    // The overlay root, set only for an overlay-rooted cage; `None` for a plain
    // `rootfs`. Exactly one of the two is in force. It serializes as a table, so
    // it sits after every scalar key: a scalar following a table header would be
    // parsed into that table.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    overlay: Option<Overlay>,
    // The delegate is code, not configuration: never part of a profile.
    #[cfg_attr(feature = "serde", serde(skip))]
    id_mapper: Option<Arc<dyn IdMapper>>,
    // Keyed by resource, so a repeated call replaces and the applied order is
    // fixed. It serializes as the `[rlimit]` table, so it sits with the other
    // tables rather than among the scalars.
    // One of the two fields whose wire name is not what `rename_all` derives:
    // the Rust field is plural and the TOML table it names is singular, as a
    // table of entries reads. `mounts` below is the other, and they are the
    // only two — every other key in the format comes from `rename_all`.
    #[cfg_attr(
        feature = "serde",
        serde(
            rename = "rlimit",
            with = "crate::limits::serde_rlimits",
            skip_serializing_if = "BTreeMap::is_empty"
        )
    )]
    rlimits: BTreeMap<Resource, (Limit, Limit)>,
    // The `[cgroup]` table: the parent directory and the limits, each optional.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "CgroupSettings::is_unset")
    )]
    cgroup: CgroupSettings,
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_os::string_map", skip_serializing_if = "Vec::is_empty")
    )]
    env: Vec<(OsString, OsString)>,
    // Binds and raw mounts share one sequence so the order the caller declared
    // them in is the order they are applied in. Two kind-segregated lists could
    // not express a raw tmpfs populated by binds, because every bind would
    // precede every raw mount whatever the caller wrote.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "mount", skip_serializing_if = "Vec::is_empty")
    )]
    mounts: Vec<Mount>,
    // The hardening request — Landlock grants, a seccomp policy, and a
    // capability posture — as the `[hardening]` table. The field holds the
    // request directly; a serde adapter bridges it to the profile's reviewable
    // form (see `crate::hardening::serde_request`).
    #[cfg(feature = "hardening")]
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            with = "crate::hardening::serde_request",
            skip_serializing_if = "crate::hardening::Request::has_no_hardening"
        )
    )]
    hardening: crate::hardening::Request,
    // In a build with `serde` but without `hardening`, a placeholder keeps the
    // `hardening` key known so a profile that configures it is refused with a
    // clear message rather than silently ignored. The field is never read; it
    // exists only for the rejecting `Deserialize` its type carries.
    #[cfg(all(feature = "serde", not(feature = "hardening")))]
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    hardening: HardeningUnsupported,
}

/// Placeholder occupying the `hardening` profile key in a build with `serde`
/// but without the `hardening` feature.
///
/// Its [`Deserialize`](serde::Deserialize) rejects a `[hardening]` table with
/// a clear message, so a profile's hardening posture is refused outright
/// rather than silently dropped by a library that cannot enforce it. It never
/// serializes and is never constructed with data.
#[cfg(all(feature = "serde", not(feature = "hardening")))]
#[derive(Debug, Clone, Default)]
struct HardeningUnsupported;

#[cfg(all(feature = "serde", not(feature = "hardening")))]
impl<'de> serde::Deserialize<'de> for HardeningUnsupported {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Consume the table so the deserializer stays consistent, then refuse:
        // a hardening posture must never be silently discarded.
        serde::de::IgnoredAny::deserialize(deserializer)?;
        Err(serde::de::Error::custom(
            "this profile configures hardening, but the library was built without the \
             `hardening` feature",
        ))
    }
}

impl Default for CageBuilder {
    fn default() -> Self {
        CageBuilder {
            rootfs: None,
            empty_rootfs: false,
            host_rootfs: false,
            reveal: Vec::new(),
            command: None,
            args: Vec::new(),
            network: Network::default(),
            hostname: None,
            workdir: None,
            stdin: Stdio::default(),
            stdout: Stdio::default(),
            stderr: Stdio::default(),
            pid_namespace: true,
            managed_mounts: None,
            mount_proc: None,
            mount_dev: None,
            mount_tmp: None,
            resolv_conf: None,
            base_env: None,
            stop_with_caller: false,
            path_lookup: false,
            present_as: None,
            identity_map: IdentityMap::Single,
            run_as: None,
            overlay: None,
            id_mapper: None,
            rlimits: BTreeMap::new(),
            cgroup: CgroupSettings::default(),
            env: Vec::new(),
            mounts: Vec::new(),
            #[cfg(feature = "hardening")]
            hardening: crate::hardening::Request::default(),
            #[cfg(all(feature = "serde", not(feature = "hardening")))]
            hardening: HardeningUnsupported,
        }
    }
}

impl CageBuilder {
    /// Sets the directory that becomes the sandbox's root filesystem.
    ///
    /// The path is resolved and opened by [`build`](Self::build); it must
    /// exist, be a directory, and not be the host root. Setting a plain rootfs
    /// supersedes an [`overlay_rootfs`](Self::overlay_rootfs), an
    /// [`empty_rootfs`](Self::empty_rootfs), or a
    /// [`host_rootfs`](Self::host_rootfs) call, and each of those supersedes
    /// it; the last call wins. A consumer overriding an untrusted profile's
    /// rootfs therefore clears any other root it configured along with it.
    ///
    /// The rootfs must live under a directory the calling user controls, not a
    /// world-writable one. The launch resolves the path a second time inside the
    /// new mount namespace — a descriptor opened beforehand cannot anchor a
    /// mount there — so a local user who can replace a component of the path
    /// between the two resolutions could redirect the new root. This is the same
    /// requirement [`provision::ensure`](crate::provision::ensure) states for
    /// its destination.
    pub fn rootfs(mut self, path: impl AsRef<Path>) -> Self {
        self.rootfs = Some(path.as_ref().to_path_buf());
        self.overlay = None;
        self.empty_rootfs = false;
        self.host_rootfs = false;
        self
    }

    /// Roots the sandbox on an empty filesystem of its own, which the mount
    /// profile populates.
    ///
    /// The root is a tmpfs the sandbox mounts inside its own mount namespace,
    /// so no directory on the host is needed for it and nothing is written
    /// there. It holds only what the launch makes in it: the managed `/proc`,
    /// `/dev` and `/tmp`, the targets of the caller's mounts, and the caller's
    /// [`symlink`](Self::symlink)s. Once those are in place the root itself is
    /// made read-only, so the command writes only where a mount lets it: a
    /// writable bind, the managed `/tmp`, or a tmpfs added with
    /// [`raw_mount`](Self::raw_mount).
    ///
    /// A command typically runs from the host's own userland, bound in
    /// read-only, with the links a merged `/usr` layout expects:
    ///
    /// ```no_run
    /// # fn main() -> ferroday_cage::Result<()> {
    /// let cage = ferroday_cage::Cage::builder()
    ///     .empty_rootfs()
    ///     .bind_ro("/usr", "/usr")
    ///     .symlink("usr/bin", "/bin")
    ///     .symlink("usr/lib", "/lib")
    ///     .symlink("usr/lib64", "/lib64")
    ///     .bind("/srv/work", "/work")
    ///     .command("/bin/sh")
    ///     .build()?;
    /// # let _ = cage;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Setting an empty root supersedes a plain [`rootfs`](Self::rootfs), an
    /// [`overlay`](Self::overlay), or a [`host_rootfs`](Self::host_rootfs),
    /// and each of those supersedes it; the last call wins.
    pub fn empty_rootfs(mut self) -> Self {
        self.rootfs = None;
        self.overlay = None;
        self.empty_rootfs = true;
        self.host_rootfs = false;
        self
    }

    /// Roots the sandbox on the host's own filesystem, read-only throughout.
    ///
    /// The command sees the host's tree as the host does, every mount in it
    /// included, and can write nowhere in it: the launch clones the host's
    /// mount tree inside the sandbox's own mount namespace and makes every
    /// mount of the clone read-only and `nosuid`. The managed `/proc`, `/dev`
    /// and `/tmp` are mounted over the host's, and the caller's mounts go on
    /// top: a working tree bound writable is where the command writes.
    ///
    /// The host's tree holds the user's credentials and live sockets, and a
    /// read-only mount does not stop a `connect`. So this root
    /// [hides](Self::hide) `/home`, `/root`, `/run`, `/var/run`, and
    /// `/var/tmp` by default, and a working tree beneath one of them is bound
    /// back in. Each default hide is listed in
    /// [`resolved_inputs`](Cage::resolved_inputs), [`reveal`](Self::reveal)
    /// takes one back, and [`managed_mounts(false)`](Self::managed_mounts)
    /// takes them all with the rest of the managed profile. `/sys` is the
    /// host's, read-only.
    ///
    /// ```no_run
    /// # fn main() -> ferroday_cage::Result<()> {
    /// let cage = ferroday_cage::Cage::builder()
    ///     .host_rootfs()
    ///     .bind("/home/user/project", "/home/user/project")
    ///     .read_only("/home/user/project/.git/hooks")
    ///     .current_dir("/home/user/project")
    ///     .command("/usr/bin/make")
    ///     .build()?;
    /// # let _ = cage;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Nothing is created on the host. A mount target must already exist,
    /// unless it lies inside a filesystem the sandbox mounts itself, such as a
    /// hidden directory or the managed `/tmp`. [`build`](Self::build) refuses
    /// one missing from the host with [`ConfigError::MountTargetMissing`],
    /// and a target that disappears before the launch fails it at
    /// [`SetupStep::OpenMountTarget`](crate::SetupStep::OpenMountTarget). A
    /// symbolic link of the caller's must likewise be made inside such a
    /// filesystem, and `build` refuses one outside with
    /// [`ConfigError::SymlinkInHostRoot`] unless the host's tree already holds
    /// that link. With [`Network::Host`] the host's own `/etc/resolv.conf` is
    /// the sandbox's, so no `resolv.conf` is bound; one that links into
    /// `/run` reads through the hidden `/run`, and is reached by binding the
    /// file it links to at its own path.
    ///
    /// With the `hardening` feature the command also runs under Landlock's
    /// unix-socket restriction by default, which refuses a connection to a
    /// socket the hides left in view; see `landlock_resolve_unix`.
    ///
    /// The clone and its read-only marking need `mount_setattr`, Linux 5.12;
    /// an older kernel fails the launch at
    /// [`SetupStep::MountHostRoot`](crate::SetupStep::MountHostRoot) rather
    /// than leave a mount of the host writable.
    ///
    /// Setting the host's root supersedes a plain [`rootfs`](Self::rootfs), an
    /// [`overlay`](Self::overlay), or an [`empty_rootfs`](Self::empty_rootfs),
    /// and each of those supersedes it; the last call wins.
    pub fn host_rootfs(mut self) -> Self {
        self.rootfs = None;
        self.overlay = None;
        self.empty_rootfs = false;
        self.host_rootfs = true;
        self
    }

    /// Takes back one of the paths [`host_rootfs`](Self::host_rootfs) hides by
    /// default, so the command sees the host's own there, read-only.
    ///
    /// `path` is one of `/home`, `/root`, `/run`, `/var/run`, and `/var/tmp`.
    /// [`build`](Self::build) refuses any other, and any at all for another
    /// kind of root, with [`ConfigError::RevealUnhidden`], since a path taken
    /// back from nothing is most likely a misspelling. A hidden path is
    /// followed where it is a symbolic link, so on a host where `/var/run`
    /// links to `/run`, the host's `/run` is shown only with both taken back.
    pub fn reveal(mut self, path: impl AsRef<Path>) -> Self {
        self.reveal.push(path.as_ref().to_path_buf());
        self
    }

    /// Roots the sandbox on an overlay of `lower`, with writes landing in
    /// `upper`.
    ///
    /// The command sees a merged view of the two: `lower` is read-only and stays
    /// pristine, while every create, modify, and delete the sandbox performs
    /// lands in `upper`. Discarding `upper` afterward reverts the sandbox's
    /// changes and leaves `lower` untouched — the "run against a base, discard
    /// the changes" model, and the basis for staging a build root of `base +
    /// increment` over a shared, unmodified base.
    ///
    /// `lower` must exist and be a directory, exactly as [`rootfs`](Self::rootfs)
    /// requires, and `upper` must lie outside it, as
    /// [Disjoint layers](Overlay#disjoint-layers) sets out. `upper` is created
    /// if absent, along with a sibling work directory the overlay requires on
    /// the same filesystem; both persist on the host after the sandbox exits
    /// and are the caller's to keep or discard, and both should live under a
    /// directory the calling user controls rather than a world-writable one,
    /// for the reason `rootfs` gives and for the one in
    /// [Where the upper lives](Overlay#where-the-upper-lives). The
    /// overlay's work area holds a directory the kernel creates mode `0`, which
    /// the calling user cannot read into: discard the upper and its work
    /// directory together with
    /// [`provision::Remove::overlay_upper`](crate::provision::Remove::overlay_upper),
    /// under the map the sandbox ran under.
    ///
    /// This is an unprivileged overlay mounted from inside the sandbox's user
    /// namespace, which the host must support: [`build`](Self::build) refuses a
    /// host that cannot establish one, and
    /// [`host::overlay_blocker`](crate::host::overlay_blocker) reports what is
    /// missing. The upper's filesystem must record `user.*` extended attributes,
    /// so an on-disk filesystem (ext4, xfs, btrfs) works on Linux 5.11 and later,
    /// while a tmpfs upper needs Linux 6.6. Setting an overlay root supersedes a
    /// plain [`rootfs`](Self::rootfs) or an [`empty_rootfs`](Self::empty_rootfs),
    /// and the reverse; the last call wins.
    ///
    /// The shorthand for [`overlay`](Self::overlay), carrying the one lower and
    /// one upper an overlay always needs. Reach for the value form to stack
    /// several lowers or to name the work directory.
    pub fn overlay_rootfs(self, lower: impl AsRef<Path>, upper: impl AsRef<Path>) -> Self {
        self.overlay(Overlay::new().lower(lower).upper(upper))
    }

    /// Roots the sandbox on an [`Overlay`].
    ///
    /// The extensible form of [`overlay_rootfs`](Self::overlay_rootfs): it takes
    /// the whole overlay as a value, so a stack of several lowers or a
    /// caller-named work directory is expressible, and further axes arrive as
    /// methods on [`Overlay`].
    ///
    /// Setting an overlay root supersedes a plain [`rootfs`](Self::rootfs) or an
    /// [`empty_rootfs`](Self::empty_rootfs), and the reverse; the last call
    /// wins.
    ///
    /// This is an unprivileged overlay mounted from inside the sandbox's user
    /// namespace, which the host must support: [`build`](Self::build) refuses a
    /// host that cannot establish one, and
    /// [`host::overlay_blocker`](crate::host::overlay_blocker) reports what is
    /// missing. The upper and work directories should live under a directory the
    /// calling user controls; see
    /// [Where the upper lives](Overlay#where-the-upper-lives). No layer may lie
    /// within another; see [Disjoint layers](Overlay#disjoint-layers).
    pub fn overlay(mut self, overlay: Overlay) -> Self {
        self.rootfs = None;
        self.empty_rootfs = false;
        self.host_rootfs = false;
        self.overlay = Some(overlay);
        self
    }

    /// Sets the command to execute inside the sandbox.
    ///
    /// The path is interpreted inside the sandbox's root filesystem and must
    /// be absolute, unless [`path_lookup`](Self::path_lookup) is enabled and
    /// the command is a bare name, in which case it is resolved against the
    /// sandbox's `PATH`.
    pub fn command(mut self, program: impl AsRef<Path>) -> Self {
        self.command = Some(program.as_ref().to_path_buf());
        self
    }

    /// Resolves a command with no slash against the sandbox's `PATH`, like a
    /// shell.
    ///
    /// Off by default: a command must be an absolute path, executed directly.
    /// With path lookup on, a command that contains no slash — a bare name such
    /// as `dpkg-buildpackage` — is searched for in each directory of the
    /// command's effective `PATH` (the deterministic base `PATH`, or a `PATH`
    /// the caller set through [`env`](Self::env)), running the first match. The
    /// search happens inside the sandbox against its own filesystem, after the
    /// root swap, so it finds the sandbox's executables rather than the host's.
    /// A command that contains a slash is still required to be absolute; path
    /// lookup never resolves a relative path. Nor does it take `.` or `..` for a
    /// name: each is a relative path, and is refused as one.
    ///
    /// Only absolute `PATH` entries are searched — an empty or relative entry is
    /// skipped rather than resolved against the working directory. A `PATH` with
    /// no absolute entry therefore leaves nothing to search, and
    /// [`build`](Self::build) refuses it with
    /// [`ConfigError::SearchPathUnusable`] rather than fall back to a relative
    /// execution.
    pub fn path_lookup(mut self, enabled: bool) -> Self {
        self.path_lookup = enabled;
        self
    }

    /// Appends one argument to the command's argument list.
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Appends arguments to the command's argument list.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_os_string()));
        self
    }

    /// Clears the command's argument list.
    ///
    /// [`command`](Self::command) replaces the program but leaves the
    /// arguments in place, and [`arg`](Self::arg) and [`args`](Self::args)
    /// append to whatever is already configured. A consumer composing over a
    /// profile that carries its own arguments calls this before setting a new
    /// command, so the command is replaced as a unit rather than the new
    /// command inheriting the profile's arguments.
    pub fn clear_args(mut self) -> Self {
        self.args.clear();
        self
    }

    /// Bind-mounts a host path read-write into the sandbox.
    ///
    /// `source` is a host path and must exist at build time; `target` is an
    /// absolute path inside the sandbox. Mounts are applied in the order they
    /// are configured — binds and raw mounts in one sequence — after the
    /// managed mount profile, save the `resolv.conf` bind of
    /// [`Network::Host`], which is applied last of all. Submounts of the
    /// source are included.
    ///
    /// A missing target is created inside the rootfs, including missing parent
    /// directories. Those directories are created mode `0755` and persist in
    /// the rootfs directory on the host after the sandbox exits, as a mount
    /// point directory of the managed profile does. A missing *file* target is
    /// created as an empty mode-`0644` file and does not persist: it is content
    /// the rootfs never had, present only for the mount to cover, and it is
    /// removed once the sandbox handle is dropped. A target the rootfs already
    /// ships is left untouched — the mount covers it for the sandbox's life and
    /// reveals it again afterwards — and so is one created inside another mount
    /// rather than in the rootfs itself.
    pub fn bind(mut self, source: impl AsRef<Path>, target: impl AsRef<Path>) -> Self {
        self.mounts.push(Mount::Bind(Bind {
            source: source.as_ref().to_path_buf(),
            target: target.as_ref().to_path_buf(),
            read_only: false,
        }));
        self
    }

    /// Bind-mounts a host path read-only into the sandbox.
    ///
    /// Like [`bind`](Self::bind), but the mount is made read-only,
    /// recursively: submounts of the source are included in the bind and are
    /// made read-only along with it, so a read-only bind of a tree that
    /// carries nested mounts does not leave those nested mounts writable. On a
    /// kernel that predates `mount_setattr` (before Linux 5.12) only the top
    /// mount is made read-only and any submounts keep their own flags.
    ///
    /// # What read-only means here
    ///
    /// A boundary, not merely a view. The command cannot remount the bind
    /// read-write, and a write to it answers `EROFS`.
    ///
    /// The kernel locks a mount's flags when it copies a mount tree *into* a
    /// new user namespace, and the command enters one of its own between the
    /// resource limits and the hardening layer. The lock holds against a
    /// command that is root of that namespace with `CAP_SYS_ADMIN` and an
    /// unfiltered `mount` syscall, so nothing else has to be configured for a
    /// `bind_ro` to mean what it says: no capability drop, no seccomp filter,
    /// and no non-root [`run_as`](Self::run_as) identity. The same lock covers
    /// unmounting, so the bind cannot be detached to reveal the target
    /// underneath it either.
    pub fn bind_ro(mut self, source: impl AsRef<Path>, target: impl AsRef<Path>) -> Self {
        self.mounts.push(Mount::Bind(Bind {
            source: source.as_ref().to_path_buf(),
            target: target.as_ref().to_path_buf(),
            read_only: true,
        }));
        self
    }

    /// Sets an environment variable for the command.
    ///
    /// The command's environment is built from scratch: the deterministic
    /// base plus the variables set here, which override the base on
    /// collision. Nothing is inherited from the host. The base is `PATH`, and
    /// `HOME=/root` where the command runs as uid 0 of its namespace; a
    /// [presented](Self::present_as) or non-root [run-as](Self::run_as)
    /// identity gets no `HOME` from the library, and a caller that knows where
    /// that identity's home is sets it here.
    pub fn env(mut self, name: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env
            .push((name.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    /// Sets environment variables for the command.
    ///
    /// Equivalent to calling [`env`](Self::env) for each pair.
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.env.extend(
            vars.into_iter()
                .map(|(k, v)| (k.as_ref().to_os_string(), v.as_ref().to_os_string())),
        );
        self
    }

    /// Selects the sandbox's network posture.
    ///
    /// The default is [`Network::Isolated`]: a new network namespace whose
    /// only interface is loopback, and a filter refusing the routes out that a
    /// network namespace does not cover. [`Network`] lists them.
    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Sets the hostname inside the sandbox.
    ///
    /// The sandbox always runs in its own UTS namespace; without this call
    /// it keeps the host's hostname. The name must be non-empty and at most
    /// 64 bytes.
    pub fn hostname(mut self, name: impl AsRef<OsStr>) -> Self {
        self.hostname = Some(name.as_ref().to_os_string());
        self
    }

    /// Sets the command's working directory inside the sandbox.
    ///
    /// The path must be absolute, with no `..` component, and must exist
    /// inside the sandbox at launch; a missing directory is a setup error, not
    /// a fallback. The default is `/`.
    pub fn current_dir(mut self, path: impl AsRef<Path>) -> Self {
        self.workdir = Some(path.as_ref().to_path_buf());
        self
    }

    /// Selects the disposition of the command's standard input.
    ///
    /// The default is [`Stdio::Inherit`], which also keeps the command in the
    /// caller's session; see [`Stdio`] for the whole rule.
    pub fn stdin(mut self, stdin: Stdio) -> Self {
        self.stdin = stdin;
        self
    }

    /// Selects the disposition of the command's standard output.
    ///
    /// The default is [`Stdio::Inherit`], under which the command writes
    /// wherever the caller's own standard output goes — which at a shell
    /// prompt is the caller's terminal, readable and writable both.
    /// [`Stdio::Null`] discards the output, and [`Stdio::from_fd`] sends it to
    /// a descriptor the caller supplies.
    ///
    /// A launch that captures — [`Cage::run_with`], [`Cage::output`],
    /// [`Cage::spawn_with`] — supplies its own pipe for this stream, so it
    /// composes with [`Stdio::Inherit`] alone and is refused against a
    /// disposition that names a different destination.
    pub fn stdout(mut self, stdout: Stdio) -> Self {
        self.stdout = stdout;
        self
    }

    /// Selects the disposition of the command's standard error.
    ///
    /// The counterpart of [`stdout`](Self::stdout), with the same default and
    /// the same interaction with a capturing launch.
    pub fn stderr(mut self, stderr: Stdio) -> Self {
        self.stderr = stderr;
        self
    }

    /// Controls whether the sandbox gets its own PID namespace (default
    /// `true`).
    ///
    /// With a PID namespace, the command runs as PID 2 under a minimal init
    /// provided by the library, which collects orphaned descendants; when
    /// the command exits, the namespace is torn down and any processes it
    /// left running are terminated. Without one, the sandbox shares the
    /// host's PID namespace, `/proc` becomes a bind of the host's procfs,
    /// the command's descendants can outlive it, and
    /// [`kill`](crate::Running::kill) reaches only the command process
    /// itself.
    ///
    /// Without one the command can also signal every process of the calling
    /// user's, the caller among them: it names them in the PID namespace they
    /// share, and it is in the caller's process group when it inherits the
    /// caller's standard input. The `hardening` feature's
    /// `LandlockScope::Signal` is the bound on that reach. With one, a sandbox
    /// that keeps the caller's session runs in a process group of its own,
    /// and the caller's processes are out of its sight.
    ///
    /// When output is captured, those surviving descendants also govern
    /// capture's endpoint: a descendant holding the command's streams keeps
    /// an unbounded wait blocked after the command exits; see
    /// [`Running::wait`](crate::Running::wait).
    ///
    /// A PID namespace of the sandbox's own needs a fresh procfs, which the
    /// kernel refuses inside a container whose runtime masks entries of the
    /// container's procfs. A launch there fails with
    /// [`Error::ProcfsRefused`](crate::Error::ProcfsRefused), and sharing the
    /// caller's PID namespace is one of its remedies; see
    /// [`host::procfs_blocker`](crate::host::procfs_blocker).
    pub fn pid_namespace(mut self, isolate: bool) -> Self {
        self.pid_namespace = isolate;
        self
    }

    /// Ties the sandbox's lifetime to the caller's (default `false`).
    ///
    /// When enabled, the sandbox is stopped as soon as the calling process
    /// exits — however it exits — or the last handle to the launch (the
    /// [`Running`] and any [`KillHandle`]s) is dropped. The tie is the launch's
    /// control socket: the handle holds its caller end, and the supervisor
    /// stops the sandbox when that end hangs up. It is not a signal
    /// arrangement in the caller, so it works from any thread and involves no
    /// signal handlers.
    ///
    /// The hangup comes when the last copy of the caller end closes, and a
    /// process the caller forks without executing holds a copy until it exits
    /// or executes; the sandbox runs on until then. Without a PID namespace
    /// the supervisor outside the sandbox is a member of the caller's process
    /// group. It ignores every signal but `SIGCHLD` and those that report a
    /// fault (`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`, `SIGTRAP`, `SIGSYS`,
    /// `SIGABRT`). One of those, or a `SIGKILL`, sent to the whole group ends it
    /// as it ends the caller, and the command then runs on unsupervised.
    ///
    /// With a [`cgroup_parent`](Self::cgroup_parent), dropping the last handle
    /// also ends every process of the cgroup's tree, as
    /// [`Running::kill`](crate::Running::kill) does, without waiting for the
    /// supervisor, and removes the cgroup once they have exited. That reaches a
    /// descendant that left the command's process tree without a PID
    /// namespace, and does not wait for a forked copy of the caller's end.
    ///
    /// [`KillHandle`]: crate::KillHandle
    pub fn stop_with_caller(mut self, tie: bool) -> Self {
        self.stop_with_caller = tie;
        self
    }

    /// Selects how the sandbox's user namespace maps identities to the
    /// host's.
    ///
    /// The default is [`IdentityMap::Single`]: root inside is the calling
    /// user outside, and no other id exists. A range map gives the sandbox
    /// more ids — so `chown` to a non-root id succeeds, packaging tools can
    /// drop privileges, and [`run_as`](Self::run_as) has identities to run
    /// as — but must be established from outside the new namespace:
    /// [`build`](Self::build) resolves the request through the configured
    /// [`id_mapper`](Self::id_mapper), or through the bundled delegates
    /// ([`DirectMapper`](crate::DirectMapper) first, then the shadow
    /// suite's helpers with the `subid` feature). A request no delegate can
    /// satisfy is rejected by `build` — never silently downgraded to the
    /// single-identity map.
    pub fn identity_map(mut self, map: IdentityMap) -> Self {
        self.identity_map = map;
        self
    }

    /// Supplies the delegate that establishes a range identity map,
    /// replacing the bundled fallback chain.
    ///
    /// The delegate's [`resolve`](IdMapper::resolve) runs at
    /// [`build`](Self::build) and its [`apply`](IdMapper::apply) runs
    /// during each launch, against the launch stage held at an internal
    /// gate. [`IdentityMap::Single`] needs no delegate and never consults
    /// one. The delegate holds the outside ids a map names to the caller's
    /// own authority, as [`IdMapper`]'s authority section sets out, since a
    /// profile can name them.
    ///
    /// The delegate is taken by value and kept, as every builder that takes
    /// one keeps it: the [`Cage`] this builds applies it at each launch, long
    /// after the call that configured it, and may be moved to another thread
    /// with it. A caller naming one delegate instance to several builders, such
    /// as a sandbox and the export of the tree it wrote, passes each an
    /// [`Arc`] of it, which is a delegate too; a `Box<dyn IdMapper>` chosen at
    /// run time is one as well.
    pub fn id_mapper(mut self, mapper: impl IdMapper + 'static) -> Self {
        self.id_mapper = Some(Arc::new(mapper));
        self
    }

    /// Supplies a delegate another builder already holds, or clears one.
    ///
    /// A provisioner hands each sandbox it launches the `Arc` it keeps, so the
    /// one delegate its caller supplied applies every map, rather than a second
    /// wrapping of it.
    #[cfg(any(feature = "debian", feature = "alpine"))]
    pub(crate) fn shared_id_mapper(mut self, mapper: Option<Arc<dyn IdMapper>>) -> Self {
        self.id_mapper = mapper;
        self
    }

    /// Runs the command as a non-root identity inside the sandbox.
    ///
    /// The switch sits within the hardening layer, after securebits,
    /// no-new-privileges, and Landlock and before the capability drop and the
    /// seccomp filter, so the command holds the identity from its first
    /// instruction and its descendants inherit it. Every id must be contained
    /// in the [`identity_map`](Self::identity_map); supplementary groups
    /// additionally require a gid map wider than the caller's own gid,
    /// because a gid map of that gid alone, the single-identity map's, denies
    /// `setgroups`. The command then keeps the group list it inherited.
    /// Without a keep-capabilities request the kernel clears the command's
    /// capabilities across the switch, which is the boundary a non-root
    /// identity exists to draw; a kept capability set survives it, and
    /// retaining `CAP_SETUID`, `CAP_SETGID`, or `CAP_SETPCAP` alongside a
    /// non-root identity is rejected at build time.
    ///
    /// The launch sets no-new-privileges whenever a run-as identity is
    /// configured, in every build of the library and whatever else the sandbox
    /// requests, because the cleared capability set is only half of the
    /// boundary. The provisioners apply a tree's permission bits verbatim, so a
    /// tree ships set-user-ID binaries and file capabilities owned by
    /// in-namespace uid 0. The root is mounted `nosuid`, which disarms those in
    /// the rootfs. A [`bind`](Self::bind) or a [`raw_mount`](Self::raw_mount)
    /// keeps its own flags, though, and below Linux 5.12 so does every mount the
    /// rootfs bind carried along beneath the root. Without the flag the non-root
    /// command executes such a binary there and is root inside again. The flag
    /// closes that path for the command and everything it starts.
    ///
    /// The single-identity map holds one id, the caller, which the command
    /// sees as uid 0, or as the identity [`present_as`](Self::present_as)
    /// names. A run-as identity there may name that id and no other, and
    /// switches nothing. Running the command as a non-root id under that map
    /// is a presentation, which `present_as` configures.
    pub fn run_as(mut self, identity: Identity) -> Self {
        self.run_as = Some(identity);
        self
    }

    /// Presents the caller to the command as another identity, under the
    /// single-identity map.
    ///
    /// That map holds one id, the caller, which the command otherwise sees as
    /// uid and gid 0. With a presented identity the command sees the caller as
    /// the given uid and gid, or, with [`PresentedIdentity::Own`], as the ids
    /// the host knows the caller by. It runs as that identity from its first
    /// instruction, without an identity switch: `id` reports it, files the
    /// caller owns read as its own, and it holds no capability across its
    /// `execve` beyond those a keep set carries. Nothing maps uid 0, so it
    /// cannot become root inside. The sandbox is still built as root inside;
    /// only the nested user namespace the command runs in changes its map.
    ///
    /// It is a presentation, not a boundary. On the host the command is still
    /// the caller, so it owns every file the caller owns, a rootfs the caller
    /// provisioned among them. A mount target of `/` is refused, so a plain
    /// rootfs cannot be mounted read-only whole. A command that must not write
    /// it is kept from it another way:
    ///
    /// - a root composed with [`empty_rootfs`](Self::empty_rootfs) from
    ///   read-only binds;
    /// - a [`bind_ro`](Self::bind_ro) of each part of the rootfs it must not
    ///   write, at that part's own path;
    /// - a read-only Landlock grant, `landlock_fs` with the `hardening`
    ///   feature;
    /// - a range [`identity_map`](Self::identity_map) and a
    ///   [`run_as`](Self::run_as) identity, a second id the rootfs does not
    ///   belong to.
    ///
    /// A presented identity sets no-new-privileges, as a run-as identity does.
    /// A run-as identity may name the presented identity, which the command
    /// already holds, and no other. A range map refuses a presented identity
    /// at build time. So does a uid of 0, with
    /// [`ConfigError::PresentAsRoot`](crate::ConfigError::PresentAsRoot): the
    /// command would be root inside, with every capability. That includes
    /// [`PresentedIdentity::Own`] for a caller that is the host's root. A uid or
    /// gid of `u32::MAX`, which no identity map can carry, is refused too.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ferroday_cage::{Cage, PresentedIdentity};
    ///
    /// # fn main() -> ferroday_cage::Result<()> {
    /// let cage = Cage::builder()
    ///     .rootfs("/srv/rootfs")
    ///     .command("/usr/bin/id")
    ///     .present_as(PresentedIdentity::Own)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn present_as(mut self, identity: PresentedIdentity) -> Self {
        self.present_as = Some(identity);
        self
    }

    /// Adds a raw mount, applied in declaration order alongside the binds.
    ///
    /// See [`RawMount`]. The escape hatch for mounts the typed profile does
    /// not model; everything but the target goes to the kernel verbatim.
    ///
    /// Order matters here more than anywhere else on the builder: a raw mount
    /// establishing a filesystem over a path hides whatever was mounted there
    /// before it. Declaring a tmpfs and then the binds that populate it is the
    /// way to build a directory the sandbox owns outright.
    pub fn raw_mount(mut self, mount: RawMount) -> Self {
        self.mounts.push(Mount::Raw(mount));
        self
    }

    /// Creates a symbolic link at `path` inside the sandbox, pointing at
    /// `target`, in its place in the mount sequence.
    ///
    /// The arguments come in the order `ln -s` takes them. See [`Symlink`] for
    /// where the link is made and what an entry already at its path does.
    pub fn symlink(mut self, target: impl AsRef<Path>, path: impl AsRef<Path>) -> Self {
        self.mounts.push(Mount::Symlink(Symlink::new(target, path)));
        self
    }

    /// Hides `path`, an absolute path inside the sandbox, in its place in the
    /// mount sequence: the command finds an empty directory or an empty file
    /// there, on a read-only mount.
    ///
    /// See [`Hide`] for what hides each kind of entry, and for a path with
    /// nothing at it, which hides nothing. A mount declared after the hide can
    /// still land beneath a hidden directory:
    ///
    /// ```no_run
    /// # fn main() -> ferroday_cage::Result<()> {
    /// let cage = ferroday_cage::Cage::builder()
    ///     .rootfs("/srv/rootfs/alpine")
    ///     .bind("/home/user", "/home/user")
    ///     .hide("/home/user/.ssh")
    ///     .hide("/home/user/.env")
    ///     .command("/bin/sh")
    ///     .build()?;
    /// # let _ = cage;
    /// # Ok(())
    /// # }
    /// ```
    pub fn hide(mut self, path: impl AsRef<Path>) -> Self {
        self.mounts.push(Mount::Hide(Hide::new(path)));
        self
    }

    /// Makes `path`, an absolute path inside the sandbox, read-only where it
    /// stands, in its place in the mount sequence.
    ///
    /// The tree at the path is bound onto itself read-only, mounts beneath it
    /// included, so a path inside a writable bind is protected without naming
    /// the host path the bind came from. See [`ReadOnly`]. The path must exist
    /// when the sequence reaches it.
    pub fn read_only(mut self, path: impl AsRef<Path>) -> Self {
        self.mounts.push(Mount::ReadOnly(ReadOnly::new(path)));
        self
    }

    /// Adds a mount of any kind, applied in declaration order with the rest.
    ///
    /// The counterpart of [`get_mounts`](Self::get_mounts), for a caller that
    /// holds a [`Mount`] rather than its parts: one read back from another
    /// builder, or one assembled with [`Bind::new`]. A [`Mount::Bind`] is the
    /// [`bind`](Self::bind) or [`bind_ro`](Self::bind_ro) its read-only flag
    /// names, a [`Mount::Raw`] is a [`raw_mount`](Self::raw_mount), a
    /// [`Mount::Symlink`] is a [`symlink`](Self::symlink), a [`Mount::Hide`] is
    /// a [`hide`](Self::hide), and a [`Mount::ReadOnly`] is a
    /// [`read_only`](Self::read_only).
    pub fn mount(mut self, mount: Mount) -> Self {
        self.mounts.push(mount);
        self
    }

    /// Adds mounts of any kind, in iteration order, after those already
    /// configured.
    ///
    /// Repeated [`mount`](Self::mount) calls, so a sequence read back through
    /// [`get_mounts`](Self::get_mounts) carries over whole, its order intact.
    pub fn mounts<I>(mut self, mounts: I) -> Self
    where
        I: IntoIterator<Item = Mount>,
    {
        self.mounts.extend(mounts);
        self
    }

    /// Sets a resource limit on the command.
    ///
    /// The namespaces bound what the command can reach; a limit bounds what it
    /// can consume. Without one the command inherits the caller's limits,
    /// which on a typical host are generous enough to permit a fork bomb,
    /// unbounded memory growth, and filling the filesystem — none of which the
    /// isolation or the hardening layer addresses. See [`limits`](crate::limits)
    /// for what each [`Resource`] governs and the two whose kernel semantics
    /// need care inside a sandbox.
    ///
    /// The limit is applied to the command process before the hardening layer,
    /// so the command and every process it starts inherit it. Repeating a
    /// resource replaces the earlier setting; the limits are then applied in a
    /// fixed order that does not depend on the order they were configured.
    /// `soft` must not exceed `hard`, which [`build`](Self::build) checks.
    ///
    /// ```no_run
    /// use ferroday_cage::{Cage, Limit, Resource};
    ///
    /// # fn main() -> ferroday_cage::Result<()> {
    /// let cage = Cage::builder()
    ///     .rootfs("/srv/rootfs/alpine")
    ///     .command("/usr/bin/analyze")
    ///     // 64 processes, 512 MiB of address space, 64 MiB of file, and ten
    ///     // seconds of CPU.
    ///     .rlimit(Resource::Processes, 64, 64)
    ///     .rlimit(Resource::AddressSpace, 512 << 20, 512 << 20)
    ///     .rlimit(Resource::FileSize, 64 << 20, 64 << 20)
    ///     .rlimit(Resource::CpuTime, 10, Limit::UNLIMITED)
    ///     .build()?;
    /// # let _ = cage;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// With the `serde` feature the limits are part of the profile format, as
    /// an `[rlimit]` table keyed by the resource's kebab-case name. One value
    /// sets the soft and hard limits alike; a `{ soft, hard }` table sets them
    /// apart. Either position takes an amount or `"unlimited"`.
    ///
    /// ```toml
    /// [rlimit]
    /// processes = 64
    /// address-space = 536870912
    /// cpu-time = { soft = 10, hard = "unlimited" }
    /// ```
    pub fn rlimit(
        mut self,
        resource: Resource,
        soft: impl Into<Limit>,
        hard: impl Into<Limit>,
    ) -> Self {
        self.rlimits.insert(resource, (soft.into(), hard.into()));
        self
    }

    /// Places each launch in a cgroup of its own beneath `parent` (default:
    /// none).
    ///
    /// `parent` is a directory of a cgroup v2 hierarchy in which the caller may
    /// create cgroups: a delegated subtree, such as systemd's `Delegate=yes`
    /// gives a service or a scope, or a container's own cgroup where its
    /// runtime delegates it. The library creates no hierarchy, configures no
    /// service manager, and needs no privilege. Each launch creates
    /// `<parent>/fcage-<unique>`, enables the controllers its
    /// [`cgroup_limit`](Self::cgroup_limit)s need in the parent's
    /// `cgroup.subtree_control`, and writes them, and creates the leaf
    /// `<parent>/fcage-<unique>/sandbox` beneath it. The launch stage then
    /// moves itself into the leaf before it creates any namespace, so
    /// everything the sandbox runs is charged to the cgroup and held to its
    /// limits, and the sandbox's cgroup namespace is rooted at the leaf, below
    /// them. A command that mounts the cgroup filesystem in its own namespace
    /// finds neither the limits nor the parent there, whatever the host's mount
    /// options, unless the cgroup filesystem is bound into the sandbox
    /// writable.
    ///
    /// The cgroup is what [`Running::kill`](crate::Running::kill) ends the
    /// whole tree through, descendants that left the command's process tree
    /// included, where the kernel has `cgroup.kill` (Linux 5.14).
    /// [`ResourceUsage`](crate::ResourceUsage) reports what the whole tree
    /// used, read from it. The handle removes the cgroup once the outcome is
    /// known and no process is left in it. A sandbox without a PID namespace
    /// can leave processes running past the outcome, and the handle then keeps
    /// the cgroup: a kill ends them, and the handle's drop removes it once
    /// they have exited. Without a kill, a cgroup still holding them when the
    /// handle drops stays beneath the parent; [`Running`](crate::Running)
    /// states the detail.
    ///
    /// A cgroup with processes of its own cannot enable controllers for its
    /// children, so a caller that runs inside `parent` moves itself into a
    /// leaf cgroup beside the sandboxes' first;
    /// [`host::own_cgroup`](crate::host::own_cgroup) names the cgroup it runs
    /// in. The launch fails with
    /// [`Error::CgroupRefused`](crate::Error::CgroupRefused), and a
    /// [`CgroupRefusal`](crate::CgroupRefusal) saying why, where the parent
    /// cannot hold the sandbox's cgroup: one that is missing, outside a cgroup
    /// v2 hierarchy, read-only, not delegated to the caller, lacking a
    /// controller a limit needs, or holding processes, a kernel without a
    /// limit's file, and a caller that runs where the launch cannot move into
    /// the parent's subtree from. A launch does not run without the limits it
    /// was given. [`host::cgroup_blocker`](crate::host::cgroup_blocker) gives
    /// the same answer before a launch.
    ///
    /// ```no_run
    /// use ferroday_cage::{Cage, CgroupLimit};
    ///
    /// # fn main() -> ferroday_cage::Result<()> {
    /// let cage = Cage::builder()
    ///     .rootfs("/srv/rootfs/alpine")
    ///     .command("/usr/bin/analyze")
    ///     .cgroup_parent("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/sandboxes.scope")
    ///     .cgroup_limit(CgroupLimit::MemoryMax(512 << 20))
    ///     .cgroup_limit(CgroupLimit::PidsMax(64))
    ///     .cgroup_limit(CgroupLimit::cpu_max(50_000, 100_000))
    ///     .build()?;
    /// # let _ = cage;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// With the `serde` feature the settings are part of the profile format, as
    /// a `[cgroup]` table:
    ///
    /// ```toml
    /// [cgroup]
    /// parent = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/sandboxes.scope"
    /// memory-max = 536870912
    /// pids-max = 64
    /// cpu-max = { quota = 50000, period = 100000 }
    /// ```
    pub fn cgroup_parent(mut self, parent: impl AsRef<Path>) -> Self {
        self.cgroup.parent = Some(parent.as_ref().to_path_buf());
        self
    }

    /// Holds the sandbox's whole process tree to `limit`, through its cgroup.
    ///
    /// Needs [`cgroup_parent`](Self::cgroup_parent), which
    /// [`build`](Self::build) checks unless the limits are not
    /// [required](Self::cgroup_required), and holds the limit's value to what
    /// the kernel takes either way. Repeating a kind of limit replaces the
    /// earlier one. Where
    /// [`rlimit`](Self::rlimit) bounds each process alone, this bounds the tree
    /// together: its memory, its count of processes, and its processor time.
    pub fn cgroup_limit(mut self, limit: CgroupLimit) -> Self {
        self.cgroup.set(limit);
        self
    }

    /// Whether the [`cgroup_limit`](Self::cgroup_limit)s need a
    /// [`cgroup_parent`](Self::cgroup_parent) (default `true`).
    ///
    /// Required, a limit without a parent is refused at [`build`](Self::build),
    /// since it would hold nothing. Not required, a sandbox without a parent
    /// runs without its cgroup limits, and
    /// [`resolved_inputs`](Cage::resolved_inputs) reports them as
    /// [`ResolvedCgroup::NotApplied`](crate::ResolvedCgroup::NotApplied), so
    /// nothing drops silently. That suits a profile that holds a command to
    /// limits where its caller can delegate a cgroup and runs it elsewhere,
    /// with [`rlimit`](Self::rlimit)s as the floor that applies everywhere.
    ///
    /// It decides only what a missing parent means. A parent that is named and
    /// cannot hold the sandbox's cgroup is refused at launch either way.
    ///
    /// ```toml
    /// [cgroup]
    /// required = false
    /// memory-max = 4294967296
    /// pids-max = 1024
    /// ```
    pub fn cgroup_required(mut self, required: bool) -> Self {
        self.cgroup.required = Some(required);
        self
    }

    /// Controls whether `/proc` is mounted (default `true`).
    ///
    /// With the default PID namespace, `/proc` is a fresh procfs instance
    /// showing only the sandbox's processes. With
    /// [`pid_namespace(false)`](Self::pid_namespace) the sandbox shares the
    /// host PID namespace and `/proc` is the host's procfs, bind-mounted.
    /// Either way, `/proc/net` and `/proc/sys/net` resolve through the
    /// sandbox's own network namespace.
    ///
    /// A container usually needs a procfs from somewhere: the nested user
    /// namespace the command enters — which is what locks the sandbox's mount
    /// flags — establishes its identity map through one, by path. Setting this
    /// to `false` therefore obliges the profile to mount a writable procfs of
    /// its own, and [`build`](Self::build) refuses one that does not with
    /// [`ConfigError::NestedUsernsNeedsProcfs`](crate::ConfigError::NestedUsernsNeedsProcfs).
    /// The exception is a range
    /// [`identity_map`](Self::identity_map) with
    /// [`pid_namespace(false)`](Self::pid_namespace), whose nested map is
    /// written from outside the sandbox through the host's own `/proc`: that
    /// combination reads no procfs of the profile's and needs none.
    pub fn mount_proc(mut self, mount: bool) -> Self {
        self.mount_proc = Some(mount);
        self
    }

    /// Controls whether a minimal `/dev` is assembled (default `true`).
    ///
    /// The minimal `/dev` is a tmpfs holding the host's `null`, `zero`,
    /// `full`, `random`, `urandom`, and `tty` devices, the standard-stream
    /// and `fd` symlinks, a fresh `devpts` instance on `/dev/pts`, and a
    /// tmpfs on `/dev/shm`.
    ///
    /// `/dev/tty` is not an ordinary device node. It is the character device
    /// `5:0`, whose open returns *the opening process's controlling terminal*,
    /// whatever that happens to be — so what the sandbox reaches through it is
    /// decided by the sandbox's session, not by the bind. With the default
    /// [`Stdio::Inherit`] that is the caller's terminal, which the command was
    /// handed anyway as file descriptor 0; with any other standard-input
    /// disposition the sandbox has a session of its own and `/dev/tty` fails
    /// with `ENXIO`. See [`Stdio`] for the whole rule. Dropping this mount does
    /// not change any of that: it removes `/dev/tty` as a *name*, while an
    /// inherited terminal descriptor is still an inherited terminal.
    pub fn mount_dev(mut self, mount: bool) -> Self {
        self.mount_dev = Some(mount);
        self
    }

    /// Controls whether a tmpfs is mounted on `/tmp` (default `true`).
    ///
    /// The tmpfs is `mode=1777`, and a `/tmp` the sandbox has to create to
    /// mount it on is created the same way, so the mount point a rootfs is left
    /// with is the directory it stands for.
    pub fn mount_tmp(mut self, mount: bool) -> Self {
        self.mount_tmp = Some(mount);
        self
    }

    /// Controls whether the host's `resolv.conf` is bound into the sandbox
    /// (default `true`).
    ///
    /// A [`bind`](Self::bind) of the caller's own onto `/etc/resolv.conf`
    /// replaces the managed bind rather than sitting under it, so a caller who
    /// composes their own resolver configuration need not also decline this
    /// one. So does a bind of a host directory over `/etc`: that directory is
    /// the caller's, and the managed bind would otherwise create its target
    /// there. A tmpfs over `/etc` is the sandbox's own, and the managed bind
    /// lands in it.
    ///
    /// The bind only happens with [`Network::Host`], where host DNS
    /// configuration is meaningful: the host's `/etc/resolv.conf` is
    /// resolved to its real file and bound read-only onto
    /// `/etc/resolv.conf` in the rootfs. When the host has no usable
    /// `resolv.conf` the bind is omitted. An isolated network never binds
    /// it.
    ///
    /// A rootfs that ships no `/etc/resolv.conf` gets an empty one created to
    /// mount onto, and it is removed once the sandbox is gone: the tree is left
    /// as it was, rather than carrying a resolver configuration it never had
    /// into whatever is made of it. A rootfs that does ship the file keeps it,
    /// untouched — the bind covers it for the sandbox's life and reveals it
    /// again afterwards. An overlay root's created file lands in the upper,
    /// which is where the merged view's writes go, and is removed from there.
    /// A file bind a caller configures is treated the same way; see
    /// [`bind`](Self::bind).
    pub fn resolv_conf(mut self, bind: bool) -> Self {
        self.resolv_conf = Some(bind);
        self
    }

    /// Controls whether the library contributes any mount of its own
    /// (default `true`).
    ///
    /// Set to `false`, the sandbox carries exactly the mounts the caller
    /// declared through [`bind`](Self::bind), [`bind_ro`](Self::bind_ro),
    /// [`raw_mount`](Self::raw_mount), and [`mount`](Self::mount), and nothing
    /// else — no `/proc`, no `/dev`, no `/tmp`, no `resolv.conf`. **A managed
    /// mount introduced in a later release is suppressed too**, which is the
    /// point: the individual toggles can only turn off the mounts that exist
    /// today, so they cannot protect a consumer from one added tomorrow.
    ///
    /// That makes this the mount-side counterpart of
    /// [`base_env`](Self::base_env), and the setting for a consumer whose
    /// output depends on the exact filesystem the command sees.
    ///
    /// Combining it with an explicit `mount_*(true)` is a contradiction and
    /// is refused by [`build`](Self::build) rather than resolved silently.
    /// Leaving those toggles alone is not a contradiction, so
    /// `managed_mounts(false)` on its own is all it takes.
    ///
    /// One mount the profile must then declare for itself is a procfs; see
    /// [`mount_proc`](Self::mount_proc) for why, and for the error a profile
    /// that declares none is refused with.
    pub fn managed_mounts(mut self, managed: bool) -> Self {
        self.managed_mounts = Some(managed);
        self
    }

    /// Controls whether the library's deterministic base environment is
    /// composed under the caller's variables (default `true`).
    ///
    /// Set to `false`, the command's environment is exactly the pairs given
    /// to [`env`](Self::env) and [`envs`](Self::envs) — neither `PATH` nor
    /// `HOME` is supplied, and **no variable the library may add to its base in a
    /// later release is supplied either**. That is what this exists for: a
    /// caller can override base variables it knows the names of, but only an
    /// exact environment excludes one it cannot yet name.
    ///
    /// A command resolved through [`path_lookup`](Self::path_lookup) needs a
    /// `PATH` to search. With no base and no `PATH` of the caller's own there
    /// is nothing to search, and [`build`](Self::build) says so rather than
    /// searching a `PATH` the command will not have.
    pub fn base_env(mut self, base: bool) -> Self {
        self.base_env = Some(base);
        self
    }

    /// The configured rootfs, when a plain one is set.
    ///
    /// `None` for an overlay-rooted cage, whose base is the first lower of
    /// [`get_overlay`](Self::get_overlay), for an
    /// [empty root](Self::get_empty_rootfs), and for a builder with no root at
    /// all — which [`build`](Self::build) rejects.
    pub fn get_rootfs(&self) -> Option<&Path> {
        self.rootfs.as_deref()
    }

    /// Whether the sandbox is rooted on an [empty root](Self::empty_rootfs).
    pub fn get_empty_rootfs(&self) -> bool {
        self.empty_rootfs
    }

    /// The configured overlay root, when one is set.
    pub fn get_overlay(&self) -> Option<&Overlay> {
        self.overlay.as_ref()
    }

    /// Whether the sandbox is rooted on the [host's own root](Self::host_rootfs).
    pub fn get_host_rootfs(&self) -> bool {
        self.host_rootfs
    }

    /// The default hides of the host's root taken back with
    /// [`reveal`](Self::reveal), in the order they were named.
    pub fn get_reveal(&self) -> &[PathBuf] {
        &self.reveal
    }

    /// The configured command path.
    pub fn get_command(&self) -> Option<&Path> {
        self.command.as_deref()
    }

    /// The command's arguments, excluding the conventional `argv[0]`.
    pub fn get_args(&self) -> &[OsString] {
        &self.args
    }

    /// Whether a bare command name is resolved against the sandbox's `PATH`.
    pub fn get_path_lookup(&self) -> bool {
        self.path_lookup
    }

    /// The caller-set environment variables, in the order they were set.
    ///
    /// These are the caller's additions; the command's full environment is
    /// these composed over the library's deterministic base.
    pub fn get_envs(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.env
            .iter()
            .map(|(name, value)| (name.as_os_str(), value.as_os_str()))
    }

    /// Every mount the caller added, in the order they were added and the
    /// order they are applied.
    ///
    /// This is the whole picture. [`get_binds`](Self::get_binds) and
    /// [`get_raw_mounts`](Self::get_raw_mounts) narrow it to one kind, at the
    /// cost of the relative order between the kinds.
    pub fn get_mounts(&self) -> &[Mount] {
        &self.mounts
    }

    /// The bind mounts the sandbox carries, in the order they were added.
    pub fn get_binds(&self) -> impl Iterator<Item = &Bind> {
        self.mounts.iter().filter_map(|mount| match mount {
            Mount::Bind(bind) => Some(bind),
            Mount::Raw(_) | Mount::Symlink(_) | Mount::Hide(_) | Mount::ReadOnly(_) => None,
        })
    }

    /// The raw mounts the sandbox carries, in the order they were added.
    pub fn get_raw_mounts(&self) -> impl Iterator<Item = &RawMount> {
        self.mounts.iter().filter_map(|mount| match mount {
            Mount::Raw(raw) => Some(raw),
            Mount::Bind(_) | Mount::Symlink(_) | Mount::Hide(_) | Mount::ReadOnly(_) => None,
        })
    }

    /// The sandbox's network posture.
    pub fn get_network(&self) -> Network {
        self.network
    }

    /// Whether the host's `resolv.conf` bind is made: the
    /// [`resolv_conf`](Self::resolv_conf) setting, with the managed-mount
    /// master switch folded in, and with the caller's own claim on the target.
    ///
    /// A mount or a symlink of the caller's at `/etc/resolv.conf`, a host tree
    /// bound or moved over a directory above it, or a symlink at such a
    /// directory, replaces the bind, so this answers `false` for a sandbox
    /// carrying one. So does the [host's own root](Self::host_rootfs), whose
    /// `/etc` is the host's already. The library acts on this only under
    /// [`Network::Host`]. A caller that composes resolver configuration of its
    /// own, as `fcage` does for a native-stack run, reads it to honor the same
    /// opt-outs and to yield to the same mounts.
    pub fn get_resolv_conf(&self) -> bool {
        self.managed(self.resolv_conf)
            && !self.host_rootfs
            && !self.mounts.iter().any(claims_resolv_conf)
    }

    /// Whether the sandbox gets its own PID namespace.
    pub fn get_pid_namespace(&self) -> bool {
        self.pid_namespace
    }

    /// Whether `/proc` is mounted.
    pub fn get_mount_proc(&self) -> bool {
        self.managed(self.mount_proc)
    }

    /// Whether the minimal `/dev` is assembled.
    pub fn get_mount_dev(&self) -> bool {
        self.managed(self.mount_dev)
    }

    /// Whether a tmpfs is mounted on `/tmp`.
    pub fn get_mount_tmp(&self) -> bool {
        self.managed(self.mount_tmp)
    }

    /// Whether the library contributes any mount of its own.
    pub fn get_managed_mounts(&self) -> bool {
        self.managed_mounts.unwrap_or(true)
    }

    /// Whether the library's deterministic base environment is composed under
    /// the caller's variables.
    pub fn get_base_env(&self) -> bool {
        self.base_env.unwrap_or(true)
    }

    /// Resolves one managed-mount toggle: the caller's explicit choice or the
    /// default, and never established when the managed profile as a whole is
    /// opted out of.
    ///
    /// The master switch wins here rather than being a contradiction, because
    /// [`build`](Self::build) has already refused the only combination where
    /// the two genuinely disagree — an explicit `true` under
    /// `managed_mounts(false)`.
    fn managed(&self, toggle: Option<bool>) -> bool {
        self.get_managed_mounts() && toggle.unwrap_or(true)
    }

    /// The sandbox's hostname, when one is set.
    pub fn get_hostname(&self) -> Option<&OsStr> {
        self.hostname.as_deref()
    }

    /// The command's working directory inside the sandbox, when one is set.
    pub fn get_current_dir(&self) -> Option<&Path> {
        self.workdir.as_deref()
    }

    /// The command's standard-input disposition.
    pub fn get_stdin(&self) -> &Stdio {
        &self.stdin
    }

    /// The command's standard-output disposition.
    pub fn get_stdout(&self) -> &Stdio {
        &self.stdout
    }

    /// The command's standard-error disposition.
    pub fn get_stderr(&self) -> &Stdio {
        &self.stderr
    }

    /// Whether the sandbox's lifetime is tied to the caller's.
    pub fn get_stop_with_caller(&self) -> bool {
        self.stop_with_caller
    }

    /// The requested identity map.
    pub fn get_identity_map(&self) -> &IdentityMap {
        &self.identity_map
    }

    /// The identity the command runs as inside the sandbox, when one is set.
    pub fn get_run_as(&self) -> Option<&Identity> {
        self.run_as.as_ref()
    }

    /// The identity the single-identity map presents the caller to the
    /// command as, when one is set.
    pub fn get_present_as(&self) -> Option<PresentedIdentity> {
        self.present_as
    }

    /// The configured resource limits, ordered by resource.
    pub fn get_rlimits(&self) -> impl Iterator<Item = (Resource, Limit, Limit)> {
        self.rlimits
            .iter()
            .map(|(resource, (soft, hard))| (*resource, *soft, *hard))
    }

    /// The directory each launch's cgroup is created beneath, if one is set.
    pub fn get_cgroup_parent(&self) -> Option<&Path> {
        self.cgroup.parent.as_deref()
    }

    /// The configured cgroup limits, one of each kind, in a fixed order.
    pub fn get_cgroup_limits(&self) -> Vec<CgroupLimit> {
        self.cgroup.limits()
    }

    /// Whether the cgroup limits need a cgroup parent; see
    /// [`cgroup_required`](Self::cgroup_required).
    pub fn get_cgroup_required(&self) -> bool {
        self.cgroup.required()
    }

    /// Validates the configuration and freezes it into a [`Cage`].
    ///
    /// All fallible and allocating preparation happens here, in the calling
    /// process: the rootfs and bind sources are resolved, the mount profile
    /// is lowered into a frozen op list, and the command line and
    /// environment are marshaled into their final form. After `build`
    /// succeeds, launching performs no work that can fail for configuration
    /// reasons.
    ///
    /// An overlay root's upper and work directories are the one thing `build`
    /// creates on the host. It creates them once the rest of the configuration
    /// has been accepted, and removes what it created if the overlay is then
    /// refused, so a refused build leaves nothing behind.
    pub fn build(self) -> Result<Cage, Error> {
        // Opting out of the managed mounts while explicitly asking for one of
        // them is a contradiction. Refuse it rather than let either side win
        // quietly: a consumer that wrote both wants something the sandbox
        // cannot deliver, and silently dropping one of the two would hand back
        // a sandbox that differs from the one described.
        if self.managed_mounts == Some(false) {
            for (toggle, name) in [
                (self.mount_proc, "mount_proc"),
                (self.mount_dev, "mount_dev"),
                (self.mount_tmp, "mount_tmp"),
                (self.resolv_conf, "resolv_conf"),
            ] {
                if toggle == Some(true) {
                    return Err(ConfigError::ManagedMountsContradiction { toggle: name }.into());
                }
            }
        }

        // The managed profile resolved to plain booleans up front, before any
        // field is moved out of `self` below, through the accessors that
        // report it: each is the caller's explicit choice or the documented
        // default, and none survives opting out of the profile as a whole. The
        // `resolv.conf` bind also folds in the caller's own claim on the
        // target: a mount of theirs at it, or a tree of theirs over it,
        // replaces the bind.
        let profile_managed = self.get_managed_mounts();
        let mount_proc = self.get_mount_proc();
        let mount_dev = self.get_mount_dev();
        let mount_tmp = self.get_mount_tmp();
        let resolv_conf = self.get_resolv_conf();
        let base_env = self.get_base_env();

        // Exactly one root is in force: a plain rootfs, an overlay whose first
        // lower is the base the overlay mounts over, or an empty root, which
        // has no host path at all. The builder's setters keep them exclusive,
        // but a deserialized profile can carry several keys; taking one would
        // silently discard the others' configuration, so a profile that names
        // two is refused.
        let named = [
            self.rootfs.is_some(),
            self.overlay.is_some(),
            self.empty_rootfs,
            self.host_rootfs,
        ];
        if named.into_iter().filter(|&named| named).count() > 1 {
            return Err(ConfigError::RootContradiction.into());
        }
        let rootfs = match (&self.rootfs, &self.overlay) {
            (Some(rootfs), _) => Some(rootfs.clone()),
            (None, Some(overlay)) => Some(
                overlay
                    .lower
                    .first()
                    .ok_or(ConfigError::OverlayLowerMissing)?
                    .clone(),
            ),
            (None, None) if self.empty_rootfs || self.host_rootfs => None,
            (None, None) => return Err(ConfigError::RootfsMissing.into()),
        };
        let command = validate_command(self.command, Some(self.path_lookup))?;
        // With the base opted out of, the caller's pairs are the whole
        // environment; the library contributes nothing, in this release or a
        // later one. A command that runs as another identity than uid 0 gets
        // no `HOME`: a presented identity is never uid 0, and a run-as one is
        // where it names another uid.
        let runs_as_root = self.present_as.is_none()
            && self
                .run_as
                .as_ref()
                .is_none_or(|identity| identity.uid == 0);
        let base: &[(&str, &str)] = match (base_env, runs_as_root) {
            (false, _) => &[],
            (true, true) => &BASE_ENV,
            (true, false) => &BASE_ENV_UNPRIVILEGED,
        };
        // Composed before the search below, so a NUL in `PATH` is reported
        // against the value that carries it rather than a candidate built
        // from it.
        let env = compose_env(base, &self.env)?;
        let program_search = if command.searched {
            // A `PATH` with no absolute entry leaves nothing to search. Refuse
            // it here rather than fall through to an `execve` of the bare name,
            // which the kernel would resolve against the sandbox's working
            // directory — the relative resolution path lookup exists to avoid.
            let path = effective_path(&self.env, base_env);
            let candidates = search_candidates(&path, &command.path)?;
            if candidates.is_empty() {
                return Err(ConfigError::SearchPathUnusable { path }.into());
            }
            candidates
        } else {
            Vec::new()
        };
        // The label a failed exec step reports. `ENOENT` from `execve` means
        // either "no such binary" or "no such ELF interpreter", so naming the
        // command — and, for a path lookup, every candidate that was tried —
        // is what makes the report actionable.
        let exec_label = exec_label(&command.path, &program_search);
        let (rlimits, rlimit_labels) = lower_rlimits(&self.rlimits)?;
        let cgroup = self.cgroup.plan()?;
        let cgroup_unapplied = self.cgroup.unapplied();
        let args = self
            .args
            .iter()
            .map(|arg| cstring(arg))
            .collect::<Result<Vec<_>, _>>()?;

        let hostname = self
            .hostname
            .map(|name| validate_hostname(&name))
            .transpose()?;
        let workdir = self
            .workdir
            .map(|path| validate_workdir(&path))
            .transpose()?
            .flatten();

        let canonical = rootfs.as_deref().map(canonical_rootfs).transpose()?;

        let mut unshare = UnshareFlags::NEWUSER
            | UnshareFlags::NEWNS
            | UnshareFlags::NEWUTS
            | UnshareFlags::NEWIPC
            | UnshareFlags::NEWCGROUP;
        if self.pid_namespace {
            unshare |= UnshareFlags::NEWPID;
        }
        let configure_loopback = match self.network {
            Network::Isolated => {
                unshare |= UnshareFlags::NEWNET;
                true
            }
            Network::None => {
                unshare |= UnshareFlags::NEWNET;
                false
            }
            Network::Host => false,
        };

        // The managed profile, each mount resolved through `managed` so that
        // opting out of the profile as a whole suppresses every one of them —
        // including any added to this list in a later release.
        let mut lowering = Lowering::default();
        if mount_proc {
            if self.pid_namespace {
                lowering.push_proc_fresh()?;
            } else {
                lowering.push_proc_bind()?;
            }
        }
        if mount_dev {
            lowering.push_dev()?;
        }
        if mount_tmp {
            lowering.push_tmp()?;
        }
        // The host root's default hides, part of the managed profile, less the
        // ones the caller took back. A path taken back from nothing is refused
        // rather than ignored: it is most likely a misspelling of one that is
        // hidden.
        let hidden_by_default = HOST_ROOT_HIDDEN
            .iter()
            .map(|hidden| Ok((*hidden, sandbox_target(Path::new(hidden))?)))
            .collect::<Result<Vec<_>, Error>>()?;
        let mut revealed = Vec::with_capacity(self.reveal.len());
        for path in &self.reveal {
            let target = sandbox_target(path).ok().filter(|target| {
                self.host_rootfs && hidden_by_default.iter().any(|(_, hidden)| hidden == target)
            });
            match target {
                Some(target) => revealed.push(target),
                None => return Err(ConfigError::RevealUnhidden { path: path.clone() }.into()),
            }
        }
        if self.host_rootfs && profile_managed {
            for (hidden, target) in &hidden_by_default {
                if !revealed.contains(target) {
                    lowering.push_hide(&Hide::new(hidden))?;
                }
            }
        }
        // The caller's mounts in declaration order, every kind in one pass.
        // The managed profile above goes first because it establishes the tree
        // these land in; among the caller's own, the order is theirs.
        for mount in &self.mounts {
            match mount {
                Mount::Bind(bind) => lowering.push_bind(bind)?,
                Mount::Raw(raw) => lowering.push_raw(raw)?,
                Mount::Symlink(symlink) => lowering.push_symlink(symlink)?,
                Mount::Hide(hide) => lowering.push_hide(hide)?,
                Mount::ReadOnly(read_only) => lowering.push_read_only(read_only)?,
            }
        }
        // The host's own root is read-only and the launch creates nothing in
        // it, so every target outside a filesystem the sandbox mounts must
        // already be there.
        if self.host_rootfs {
            settle_host_root_targets(&mut lowering.ops)?;
        }
        // The managed `resolv.conf` bind, which `resolv_conf` above already
        // withholds where the caller mounted something of their own at that
        // target, or a tree of their own over it. Theirs was pushed by the loop
        // above and this would land on top of it, which takes back the "among
        // the caller's own, the order is theirs" rule for the one mount they
        // were most deliberate about. A caller who mounts it has replaced the
        // managed one as surely as `resolv_conf(false)` declines it.
        if resolv_conf && matches!(self.network, Network::Host) {
            lowering.push_resolv_conf()?;
        }

        // The presented identity: the single-identity map's one id as the
        // command will see it. A range map refuses one before its delegate is
        // consulted, since a range map has ids of its own to run as.
        let present_as = match (self.present_as, &self.identity_map) {
            (None, _) => None,
            (Some(presented), IdentityMap::Single) => Some(validate_present_as(presented)?),
            (Some(_), _) => return Err(ConfigError::PresentAsWithRangeMap.into()),
        };

        // The identity plan: validate the requested map, resolve a range
        // request through the delegate seam, and validate the run-as
        // identity against the ranges that result — so an identity the map
        // cannot represent is a configuration error here, not a launch
        // failure.
        let identity = match &self.identity_map {
            IdentityMap::Single => IdentityPlan::Single,
            request => {
                // A configured delegate is the whole chain: its refusal is
                // final. Without one, the bundled delegates are tried in turn.
                let (mapper, map) = idmap::resolve_delegate(request, self.id_mapper.as_ref())?;
                IdentityPlan::Ranged { mapper, map }
            }
        };
        let run_as = self
            .run_as
            .as_ref()
            .map(|identity_request| validate_run_as(identity_request, &identity, present_as))
            .transpose()?;

        // The nested user namespace the command enters before it hardens, which
        // is what locks the flags of every mount the sandbox established. Its
        // map reflects the one resolved above, and the procfs it is written
        // through is the profile's, so both are settled here and the command
        // stage replays frozen bytes.
        let nested = build_nested_plan(&identity, present_as, &lowering.ops, self.pid_namespace)?;

        // The hardening request, compiled and validated here so the command
        // stage only replays frozen data.
        #[cfg(feature = "hardening")]
        let hardening = {
            // The host's own root restricts unix sockets unless the caller
            // says otherwise: it leaves the host's sockets connectable through
            // the read-only tree wherever no hide covers them.
            let mut hardening = self.hardening.lower(self.host_rootfs)?;
            // Whether the command switches from root inside to a non-root id.
            // A presented identity is never root inside, and a run-as identity
            // under one is the identity the command already holds, so there is
            // no switch for the securebits to carry capabilities across and no
            // mapped uid 0 for a kept set-id capability to return to.
            let switches_from_root =
                present_as.is_none() && matches!(&self.run_as, Some(identity) if identity.uid != 0);
            // A kept set-id capability would let a non-root command return
            // to the mapped uid 0 under the securebits below; refuse the
            // combination rather than ship an identity that is not a
            // boundary.
            if let Some(keep) = hardening.keep_caps
                && switches_from_root
            {
                use rustix::thread::CapabilitySet;
                for (capability, name) in [
                    (CapabilitySet::SETUID, "CAP_SETUID"),
                    (CapabilitySet::SETGID, "CAP_SETGID"),
                    (CapabilitySet::SETPCAP, "CAP_SETPCAP"),
                ] {
                    if keep & capability.bits() != 0 {
                        return Err(
                            ConfigError::SetidCapWithNonRootIdentity { capability: name }.into(),
                        );
                    }
                }
            }
            // The securebits that carry a kept capability set across the
            // identity switch. An explicitly empty keep set needs them too:
            // its bounding-set narrowing runs after the switch, which would
            // otherwise have cleared the CAP_SETPCAP it requires.
            hardening.set_securebits = switches_from_root && hardening.keep_caps.is_some();
            // Where no namespace of the sandbox stands behind a reach (the host
            // network under host networking, the host's processes without a
            // PID namespace), a Landlock request is that reach's only boundary.
            // Refuse a build whose request this kernel cannot enforce rather
            // than run without it, the posture the restriction fallback takes
            // for its Landlock-only confinement. The ABI is probed only when
            // such a request exists.
            hardening.ensure_sandbox_enforceable(
                matches!(self.network, Network::Host),
                !self.pid_namespace,
                crate::mechanism::probe_landlock_abi,
            )?;
            // The unix-socket restriction is refused where the caller asked
            // for it and the kernel cannot enforce it, and dropped where it is
            // the host root's default.
            crate::hardening::settle_resolve_unix(
                &mut hardening,
                self.hardening.resolve_unix() == Some(true),
                crate::mechanism::probe_landlock_abi,
            )?;
            hardening
        };

        // The root, with every mount target the launch has to create in it as
        // an empty file, as the host path it comes to rest at. A file the
        // sandbox creates only to mount over is not part of the root, so the
        // caller side takes it away once the sandbox is gone. Writes land in
        // the root filesystem itself for a plain root and in the upper for an
        // overlay root, whose pivoted root is the merged view. Both are
        // canonical paths, so a root the caller named relatively does not leave
        // a path that re-resolves against whatever directory the process
        // happens to be in when the handle drops. An empty root is the
        // sandbox's own: what the launch creates in it goes with it, and none
        // of it has a host path.
        let (root, managed_placeholders) = match &canonical {
            None if self.host_rootfs => (RootPlan::HostReadOnly, ManagedPlaceholders::default()),
            None => (RootPlan::Empty, ManagedPlaceholders::default()),
            Some(canonical) => {
                let base = cstring(canonical.as_os_str())?;
                match &self.overlay {
                    None => (
                        RootPlan::Bind(base),
                        created_file_targets(&lowering.ops, &RootLayers::Plain(canonical)),
                    ),
                    // An overlay root: `canonical` is the base lower the
                    // overlay mounts over, any further lowers are resolved
                    // beside it, and the caller's upper — with its work
                    // directory — is prepared and frozen into the mount options
                    // here, so the sandbox stage only replays them. A host that
                    // cannot establish an unprivileged overlay is refused now,
                    // before any fork. This is the one step that creates
                    // anything on the host, so it runs once every other part of
                    // the configuration has been accepted: a build refused for
                    // any other reason leaves no layer directory behind.
                    Some(overlay) => {
                        let overlay = build_overlay_plan(canonical, overlay)?;
                        let layers = RootLayers::Overlay {
                            upper: &overlay.upper,
                            lower: &overlay.lower,
                        };
                        let placeholders = created_file_targets(&lowering.ops, &layers);
                        (RootPlan::Overlay { base, overlay }, placeholders)
                    }
                }
            }
        };

        Ok(Cage {
            plan: LaunchPlan {
                confinement: Confinement::Container,
                identity,
                nested: Some(nested),
                run_as,
                present_as,
                program: command.program,
                program_search,
                args,
                env,
                root,
                unshare,
                pid_namespace: self.pid_namespace,
                // Lower each disposition into the plan's own form; the descriptor
                // variant carries the shared descriptor through unchanged.
                stdin: StdioPlan::of(&self.stdin),
                stdout: StdioPlan::of(&self.stdout),
                stderr: StdioPlan::of(&self.stderr),
                // The session follows standard input alone: it is the stream
                // whose inheritance carries the caller's session with it.
                own_session: !matches!(self.stdin, Stdio::Inherit),
                stop_with_caller: self.stop_with_caller,
                hostname,
                configure_loopback,
                network: self.network,
                workdir,
                ops: lowering.ops,
                op_labels: lowering.labels,
                managed_placeholders,
                exec_label,
                rlimits,
                rlimit_labels,
                cgroup,
                cgroup_unapplied,
                #[cfg(feature = "hardening")]
                hardening,
            },
        })
    }
}

/// Whether the identity map is the default, for profile serialization.
#[cfg(feature = "serde")]
fn identity_map_is_default(map: &IdentityMap) -> bool {
    matches!(map, IdentityMap::Single)
}

/// A [`CageBuilder`] deserialized under the restricted policy, for a profile
/// from a source the consumer does not control.
///
/// Deserializing a profile straight into a [`CageBuilder`] trusts it as
/// code-equivalent configuration (see the builder's "Trust" section): the
/// profile can bind any host path, issue raw mounts, share the host network
/// namespace, and overmount the sandbox's managed mounts. When the profile
/// comes from an untrusted source — a repository, a download, a multi-tenant
/// store — deserialize it into a `RestrictedProfile` instead, in the same
/// serde format:
///
/// ```toml
/// rootfs = "/srv/rootfs/alpine"
/// command = "/usr/bin/make"
/// workdir = "/build"
///
/// [env]
/// CARGO_HOME = "/cache/cargo"
/// ```
///
/// # What the restricted policy refuses
///
/// This list is the policy: the refusals the code makes are held to it, and
/// every other description of the policy refers here. A profile using any entry
/// is refused, and the refusal names the entry in the words it has here.
///
/// The operations that map host resources into the sandbox, write to the host
/// outside it, or share a host namespace:
///
/// - a bind mount, and a raw mount (`kind = "bind"`, `kind = "raw"`). Each maps
///   a host resource in: a host path, or whatever a raw mount's source, type,
///   and data reach.
/// - a symbolic link (`kind = "symlink"`). The setup makes it before any
///   confinement applies, and in a plain rootfs it stays on the host after the
///   sandbox exits: a link at `/etc/ld.so.preload`, pointing at a path a
///   confined command can write, reaches every later sandbox on that tree.
/// - host networking (`network = "host"`).
/// - an overlay root (`[overlay]`). Its upper, with a work directory beside
///   it, is created at whatever host path the profile names, where a rootfs
///   must already exist.
/// - the host's own root (`host-rootfs`), which maps the host's whole tree in,
///   and a path the host's root hides taken back (`reveal`), which a
///   consumer's own [`host_rootfs`](CageBuilder::host_rootfs) after loading
///   would honor.
/// - the host PID namespace (`pid-namespace = false`). The managed `/proc` is
///   then the host's own, bound in read-write, through which the command can
///   read and signal every host process of its user.
/// - a cgroup parent (`parent` in `[cgroup]`), a host directory each launch
///   creates a cgroup in and enables controllers on for every cgroup beneath
///   it.
///
/// The hardening that a consumer's own trusted calls add to rather than
/// replace, since the profile's part would then widen the consumer's
/// confinement:
///
/// - a Landlock filesystem grant (`landlock-fs`), and a Landlock network grant
///   (`landlock-net`). Grants are an allow-list the builder only appends to,
///   so the profile's would be added to the consumer's.
/// - a kept capability set (`keep-caps`), which survives the switch to a
///   consumer's non-root [`run_as`](CageBuilder::run_as) identity.
/// - the unix-socket restriction turned off (`resolve-unix = false`), which
///   would take the restriction away from the host's own root, which applies
///   it by default, should the consumer root the sandbox there.
///
/// Everything else is admitted, so a restricted profile still shapes the
/// sandbox: the rootfs (never the host root, which [`CageBuilder::build`]
/// rejects for every profile), an empty root, a hidden path or one made
/// read-only, the command, its arguments, environment, and working directory,
/// path lookup, the hostname, the stream dispositions, the tie to the caller's
/// lifetime, the resource limits and the cgroup limits, the identity map, the
/// run-as and presented identities, the base environment, and the remaining
/// mount toggles. So is the hardening that only removes: a seccomp policy, a
/// full capability drop (`drop-caps`), the Landlock scopes, and the unix-socket
/// restriction turned on, each of which a consumer's own call replaces.
///
/// # What the restricted policy does not constrain
///
/// The policy bounds what the profile may *map in*, not the host authority the
/// resulting command wields, which remains the calling user's:
///
/// - **Rootfs reach.** The profile's rootfs is bind-mounted onto itself
///   read-write and pivoted to `/`, so the command gets read-write access
///   (bounded by the calling user's credentials) to whatever host subtree the
///   profile named. A profile naming `rootfs = "/home/service"` therefore
///   reaches that subtree. A consumer that does not trust the profile to
///   choose its own rootfs should override it — `into_builder().rootfs(path)`
///   with a directory the consumer controls — after loading.
/// - **Identity.** A range [`identity_map`](CageBuilder::identity_map) and a
///   [`run_as`](CageBuilder::run_as) identity survive the filter. Under the
///   bundled delegates this is safe: each validates the requested ids against
///   the caller's own authority (`CAP_SETUID`/`CAP_SETGID` and the readable
///   map, or the caller's `/etc/subuid` allocation). A consumer that supplies
///   a custom privileged [`id_mapper`](CageBuilder::id_mapper) must validate
///   the profile-supplied outside ids against the caller's authority itself;
///   otherwise a profile could map host root into the sandbox.
///
/// [`into_builder`](Self::into_builder) yields the validated builder, which the
/// consumer extends with its own trusted calls — including any binds it means
/// to allow — before [`build`](CageBuilder::build).
///
/// # The refusal as a value
///
/// Deserializing a `RestrictedProfile` reports a forbidden operation through
/// the serde format's own error, as text, since that is the only error a
/// `Deserialize` can return. A consumer that matches on the refusal
/// deserializes a [`CageBuilder`] instead and converts it with
/// [`RestrictedProfile::try_from`], which holds it to the same policy and
/// returns [`ConfigError::ProfileOperationForbidden`]:
///
/// ```
/// use ferroday_cage::{CageBuilder, ConfigError, RestrictedProfile};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let builder: CageBuilder = toml::from_str("network = \"host\"\n")?;
/// match RestrictedProfile::try_from(builder) {
///     Err(ConfigError::ProfileOperationForbidden { operation, .. }) => {
///         assert_eq!(operation, "host networking");
///     }
///     other => panic!("host networking is refused: {other:?}"),
/// }
/// # Ok(())
/// # }
/// ```
///
/// [`ConfigError::ProfileOperationForbidden`]: crate::ConfigError::ProfileOperationForbidden
#[cfg(feature = "serde")]
#[derive(Debug, Clone)]
pub struct RestrictedProfile(CageBuilder);

#[cfg(feature = "serde")]
impl RestrictedProfile {
    /// The validated builder, for extending with the consumer's own trusted
    /// calls and building into a [`Cage`].
    pub fn into_builder(self) -> CageBuilder {
        self.0
    }
}

/// Holds a builder to the restricted policy, as deserializing a
/// `RestrictedProfile` does, and returns the refusal as a value.
#[cfg(feature = "serde")]
impl TryFrom<CageBuilder> for RestrictedProfile {
    type Error = ConfigError;

    /// Accepts `builder` under the restricted policy, or refuses it with
    /// [`ConfigError::ProfileOperationForbidden`] naming the first forbidden
    /// operation it uses.
    fn try_from(builder: CageBuilder) -> Result<RestrictedProfile, ConfigError> {
        builder.check_restricted()?;
        Ok(RestrictedProfile(builder))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for RestrictedProfile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        RestrictedProfile::try_from(CageBuilder::deserialize(deserializer)?)
            .map_err(|err| serde::de::Error::custom(crate::failure::ErrorChain::new(&err)))
    }
}

#[cfg(feature = "serde")]
impl CageBuilder {
    /// Rejects the profile operations the restricted policy reserves for a
    /// trusted profile, which [`RestrictedProfile`] lists, naming the first one
    /// the builder uses. Backs [`RestrictedProfile`]'s conversion from a
    /// builder, and through it its deserialization.
    fn check_restricted(&self) -> Result<(), ConfigError> {
        // Destructured exhaustively, with no `..`: a new builder field fails to
        // compile here until someone classifies it, so the untrusted-profile
        // surface cannot widen by omission. A knob that reaches the host, or
        // that a consumer's own trusted calls would add to rather than replace,
        // belongs in the examined group below; anything else is bound to `_`
        // here as a deliberate record that it was considered and allowed. The
        // examined fields are matched exhaustively in turn, so a new `Mount` or
        // `Network` variant, or a new part of the hardening request, is
        // classified the same way.
        //
        // It carries a second duty. `RestrictionBuilder` is this type's
        // deliberate twin, and a field added here without a counterpart there
        // is how the two come apart; the test beside that type destructures it
        // the same way, and between them neither grows a field the other has
        // not been asked about.
        let CageBuilder {
            // Examined below: each can reach host resources, or widen what the
            // consumer configures after loading.
            mounts,
            network,
            overlay,
            pid_namespace,
            hardening,
            // Bounded by the calling user's own authority, and allowed. See
            // this type's documentation for what a profile still governs.
            rootfs: _,
            // A tmpfs of the sandbox's own maps nothing of the host in; what
            // the profile could then put in it, it could not bind there.
            empty_rootfs: _,
            // Examined below: the host's whole tree, and a default hide of it
            // taken back.
            host_rootfs,
            reveal,
            command: _,
            args: _,
            hostname: _,
            workdir: _,
            // A stream disposition reaches no host resource a profile could not
            // already reach: `Inherit` is what a launch does anyway, `Null` only
            // narrows, and `Fd` has no serial form and so cannot appear in a
            // profile at all.
            stdin: _,
            stdout: _,
            stderr: _,
            mount_proc: _,
            mount_dev: _,
            mount_tmp: _,
            resolv_conf: _,
            // Both narrow the sandbox rather than widen it. Opting out of the
            // managed mounts removes mounts; opting out of the base
            // environment removes variables. Neither can reach a host resource
            // the profile could not already reach.
            managed_mounts: _,
            base_env: _,
            stop_with_caller: _,
            path_lookup: _,
            identity_map: _,
            run_as: _,
            // Changes only which id the command sees the caller as. It maps no
            // host id the single-identity map did not already, and the command
            // it presents is less privileged inside, not more.
            present_as: _,
            // A limit reaches nothing: it is set on the command process, and an
            // unprivileged `setrlimit` can only lower a hard limit or move a
            // soft one within the hard limit the caller already had. The worst
            // a profile can do with one is constrain its own command.
            rlimits: _,
            // Code, never part of a profile: `serde(skip)` keeps it unset here.
            id_mapper: _,
            env: _,
            // Examined below: a parent is a host directory a launch creates
            // cgroups in and enables controllers on.
            cgroup,
        } = self;

        if let Some(operation) = mounts.iter().find_map(restricted_mount_refusal) {
            return Err(ConfigError::ProfileOperationForbidden { operation });
        }
        match network {
            Network::Host => {
                return Err(ConfigError::ProfileOperationForbidden {
                    operation: "host networking",
                });
            }
            // A namespace of the sandbox's own, which reaches no host network.
            Network::Isolated | Network::None => {}
        }
        // An overlay root reaches further onto the host than the rootfs it
        // layers over. The rootfs must already exist, so a profile naming one
        // reaches only a subtree that is already there; an upper is *created*,
        // along with a sibling work directory, at whatever host path the profile
        // names, and the preflight probe then runs in its parent. Reserve it for
        // a trusted profile, which sets it through `overlay` after loading.
        if overlay.is_some() {
            return Err(ConfigError::ProfileOperationForbidden {
                operation: "an overlay root",
            });
        }
        // The host's own root maps the host's whole tree in, read-only, and a
        // consumer that roots a restricted profile on it later would have the
        // profile's revealed paths shown where the default hides them.
        if *host_rootfs {
            return Err(ConfigError::ProfileOperationForbidden {
                operation: "the host's own root (host-rootfs)",
            });
        }
        if !reveal.is_empty() {
            return Err(ConfigError::ProfileOperationForbidden {
                operation: "a path the host's root hides taken back (reveal)",
            });
        }
        // A shared host PID namespace is a host-resource mapping in disguise:
        // with `pid_namespace = false` the default `mount_proc` binds the
        // host's own `/proc` read-write into the sandbox (see
        // `push_proc_bind`), so the command can enumerate, read, and signal
        // every host process sharing its mapped uid — the same reach an
        // explicit `[[mount]] kind = "bind"` of /proc grants, which this
        // filter already rejects. Reserve it for a trusted profile.
        if !pid_namespace {
            return Err(ConfigError::ProfileOperationForbidden {
                operation: "the host PID namespace",
            });
        }
        // A cgroup parent names a host directory each launch creates a cgroup
        // in, and whose `cgroup.subtree_control` it enables controllers on,
        // which every sibling beneath the parent then has. Reserve it for a
        // trusted profile; the limits alone constrain only the sandbox, and
        // without a parent `build` refuses them. `required = false` changes
        // only that refusal: the limits are then the profile's own to waive,
        // and the record reports them unapplied.
        if cgroup.parent.is_some() {
            return Err(ConfigError::ProfileOperationForbidden {
                operation: "a cgroup parent",
            });
        }
        // The hardening request holds two parts a consumer's own calls add to
        // rather than replace, and the request classifies its own fields; see
        // `Request::restricted_refusal`.
        #[cfg(feature = "hardening")]
        if let Some(operation) = hardening.restricted_refusal() {
            return Err(ConfigError::ProfileOperationForbidden { operation });
        }
        // Without the feature the field is a placeholder, whose deserialization
        // has already refused any `[hardening]` table outright.
        #[cfg(not(feature = "hardening"))]
        let HardeningUnsupported = hardening;
        Ok(())
    }
}

/// The operation the restricted policy names a mount by, where it refuses the
/// mount, or `None` for a kind it admits.
///
/// Matched exhaustively, so a new kind of mount fails to compile here until it
/// is classified. Each kind is named on its own rather than as one "a mount", so
/// the refusal names what the profile actually asked for.
#[cfg(feature = "serde")]
fn restricted_mount_refusal(mount: &Mount) -> Option<&'static str> {
    match mount {
        // Each maps a host resource in: a host path, or whatever a raw mount's
        // source, type, and data reach.
        Mount::Bind(_) => Some("a bind mount"),
        Mount::Raw(_) => Some("a raw mount"),
        // A link maps nothing in, but it is made in the setup stage, before
        // Landlock, the run-as switch, or any capability drop applies, and on a
        // plain rootfs it stays on the host after the sandbox exits. A profile
        // could plant `/etc/ld.so.preload` in a rootfs a consumer shares between
        // sandboxes, pointing at a path a confined command can write. A
        // restricted profile can bind nothing, so an empty root, where links
        // persist nowhere, gains nothing from one either.
        Mount::Symlink(_) => Some("a symbolic link"),
        // Each takes something away from what the command sees or can write,
        // and maps nothing in: a hidden path is a tmpfs of the sandbox's own
        // or an empty file from one, and a path made read-only is the
        // sandbox's own tree, restricted. Neither creates anything where a
        // path is missing.
        Mount::Hide(_) | Mount::ReadOnly(_) => None,
    }
}

/// Resolves a presented identity and checks it, through [`present_plan`].
fn validate_present_as(presented: PresentedIdentity) -> Result<PresentPlan, Error> {
    let (uid, gid) = presented.resolve();
    present_plan(presented, uid, gid)
}

/// Checks the ids `presented` resolved to, and freezes them.
///
/// The ids become the inside ids of the command's nested map, and the kernel
/// refuses the id `(u32)-1` in any map, so it is refused here, as the
/// identity-map error it would otherwise surface as at launch. A uid of 0 is
/// refused too, with [`ConfigError::PresentAsRoot`]: the nested map would then
/// read `0 0 1`, and the command would be root inside with every capability
/// across its `execve`.
fn present_plan(presented: PresentedIdentity, uid: u32, gid: u32) -> Result<PresentPlan, Error> {
    for (id, space) in [(uid, "uid"), (gid, "gid")] {
        if id == u32::MAX {
            return Err(ConfigError::IdentityMapInvalid {
                reason: format!("the presented {space} {id} is one no identity map can carry"),
            }
            .into());
        }
    }
    if uid == 0 {
        return Err(ConfigError::PresentAsRoot {
            identity: presented,
        }
        .into());
    }
    Ok(PresentPlan { uid, gid })
}

/// Validates a run-as identity against the identity plan and freezes it.
///
/// Every id must be contained in the map the command will see. Under the
/// single-identity map that is one id, the caller, as uid and gid 0 or as the
/// presented identity, so a run-as identity there names the identity the
/// command already holds. Supplementary groups require a gid map wider than the
/// caller's own gid. The
/// single-identity map's gid map is that gid alone, and is established by
/// denying `setgroups`, so no group list can ever be set inside it. A range
/// map whose gid list is that one extent is held to the same rule, since the
/// shadow helpers deny `setgroups` when they write it; see
/// [`idmap::is_own_gid_alone`]. Under either, the plan carries no group list,
/// and the command keeps the one it inherited.
fn validate_run_as(
    identity: &Identity,
    plan: &IdentityPlan,
    present_as: Option<PresentPlan>,
) -> Result<RunAsPlan, Error> {
    let unmapped =
        |id: u32, space: &'static str| Error::from(ConfigError::RunAsUnmapped { id, space });
    let settable = match plan {
        IdentityPlan::Single => {
            let (uid, gid) = present_as.map_or((0, 0), |presented| (presented.uid, presented.gid));
            let outside = |id: u32, space: &'static str, presented: u32| {
                Error::from(ConfigError::RunAsOutsideSingleMap {
                    id,
                    space,
                    presented,
                })
            };
            if identity.uid != uid {
                return Err(outside(identity.uid, "uid", uid));
            }
            if identity.gid != gid {
                return Err(outside(identity.gid, "gid", gid));
            }
            false
        }
        IdentityPlan::Ranged { map, .. } => {
            if !idmap::maps_inside_id(map.uid(), identity.uid) {
                return Err(unmapped(identity.uid, "uid"));
            }
            if !idmap::maps_inside_id(map.gid(), identity.gid) {
                return Err(unmapped(identity.gid, "gid"));
            }
            for &group in &identity.groups {
                if !idmap::maps_inside_id(map.gid(), group) {
                    return Err(unmapped(group, "supplementary group"));
                }
            }
            !idmap::is_own_gid_alone(map.gid())
        }
    };
    if !settable && !identity.groups.is_empty() {
        return Err(ConfigError::RunAsGroupsWithSingleMap.into());
    }
    // `from_raw_unchecked` is the safe constructor without the debug assert
    // against the sentinel -1; the kernel rejects unusable ids at the
    // switch, and the map validation above has already bounded these.
    Ok(RunAsPlan {
        uid: rustix::thread::Uid::from_raw_unchecked(identity.uid),
        gid: rustix::thread::Gid::from_raw_unchecked(identity.gid),
        groups: settable.then(|| {
            identity
                .groups
                .iter()
                .map(|&group| rustix::thread::Gid::from_raw_unchecked(group))
                .collect()
        }),
    })
}

/// Composes the nested user namespace's plan: the map it takes, and the procfs
/// paths through which that map is established.
///
/// The map is the identity reflection of the sandbox's own, so the command sees
/// the same ids one namespace deeper; the tier follows the sandbox's, because
/// the kernel's one-id exception is what lets a process write its own map and
/// nothing richer. A presented identity is the one departure: the single
/// tier's one extent then gives the sandbox's root the presented ids inside,
/// which the same exception admits, since it constrains only the outside id.
///
/// A procfs is required exactly where the chosen route reaches for one, and a
/// profile that mounts none is then refused here rather than at launch, where
/// the failure would be an `ENOENT` on a path nobody asked for. Two of the
/// three routes reach for one: a self-written map, whose command names its own
/// map files by path after the pivot, and a delegated map inside a PID
/// namespace, whose delegate is inside the sandbox. The third — a delegated map
/// without a PID namespace — is written by the launch stage, outside, through
/// the host's own `/proc`, and needs nothing of the profile.
fn build_nested_plan(
    identity: &IdentityPlan,
    present_as: Option<PresentPlan>,
    ops: &[MountOp],
    pid_namespace: bool,
) -> Result<NestedPlan, Error> {
    let (map, uid, gid) = match identity {
        // The single-identity tier collapses to one extent of one id, which is
        // all it ever had, and which the command may write for itself. Any
        // procfs serves: a process writing its own map reaches it through
        // `self`, which every instance resolves for its reader.
        IdentityPlan::Single => {
            let procfs_target =
                visible_procfs(ops, false).ok_or_else(|| procfs_refusal(ops, false))?;
            // The map files as the command names them after the pivot:
            // absolute, under the profile's own procfs target.
            let under_procfs =
                |leaf: &str| cstring(sandbox_path(procfs_target).join(leaf).as_os_str());
            // The one extent names the sandbox's root, the writer's own id,
            // as the command is to see it: 0, or the presented identity.
            let (uid, gid) = present_as.map_or((0, 0), |presented| (presented.uid, presented.gid));
            let root = |inside| {
                vec![idmap::IdRange {
                    inside,
                    outside: 0,
                    count: 1,
                }]
            };
            (
                NestedMap::SelfWritten {
                    setgroups_path: under_procfs("self/setgroups")?,
                    gid_map_path: under_procfs("self/gid_map")?,
                    uid_map_path: under_procfs("self/uid_map")?,
                },
                root(uid),
                root(gid),
            )
        }
        IdentityPlan::Ranged { map, .. } => {
            // Inside a PID namespace the delegate is the sandbox's own init and
            // reads the profile's procfs, which must then exist and be a *fresh*
            // instance: the delegate names the command's map files by the pid
            // its `fork` returned, an in-namespace pid a bound procfs from
            // outside does not index. See `procfs_op_target`.
            let procfs_target = if pid_namespace {
                Some(
                    visible_procfs(ops, true)
                        .ok_or_else(|| procfs_refusal(ops, true))?
                        .to_owned(),
                )
            } else {
                None
            };
            (
                NestedMap::Delegated { procfs_target },
                idmap::reflect_inside(map.uid()),
                idmap::reflect_inside(map.gid()),
            )
        }
    };

    Ok(NestedPlan {
        map,
        uid_lines: idmap::format_map(&uid),
        gid_lines: idmap::format_map(&gid),
    })
}

/// The rootfs-relative target of the procfs the sandbox ends up with, or `None`
/// when the profile mounts none the nested map can be established through.
///
/// The ops execute in order, so a later mount can hide an earlier one; the scan
/// follows the same order and drops a procfs another mount comes to rest on top
/// of. Where a profile mounts more than one, the last still visible is taken —
/// any of them would serve. An op that brings no mount to rest, such as a
/// remount or a propagation change, hides nothing; see
/// [`MountAction::arrival`]. Nor does a path made read-only, which binds the
/// tree it finds onto itself, a procfs within it included. Either can still
/// make a procfs unusable, by leaving it read-only, and one that does drops it
/// as a cover would.
fn visible_procfs(ops: &[MountOp], needs_fresh: bool) -> Option<&CStr> {
    standing_procfs(ops, needs_fresh, Writable::Required)
}

/// Whether a procfs search holds candidates to being writable.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Writable {
    /// A read-only procfs is no candidate: the search the nested map rests on.
    Required,
    /// A read-only procfs is a candidate too: the search that tells a profile
    /// whose only procfs is read-only from one that has none.
    Ignored,
}

/// The refusal for a profile whose nested map finds no procfs to be written
/// through: the read-only one where read-only is the only reason one does not
/// count, and the plain refusal otherwise.
fn procfs_refusal(ops: &[MountOp], needs_fresh: bool) -> ConfigError {
    match standing_procfs(ops, needs_fresh, Writable::Ignored) {
        Some(target) => ConfigError::NestedUsernsProcfsReadOnly {
            target: sandbox_path(target),
        },
        None => ConfigError::NestedUsernsNeedsProcfs,
    }
}

/// The search behind [`visible_procfs`] and [`procfs_refusal`]: the last
/// procfs candidate no later mount comes to rest on, with `writable` deciding
/// whether a read-only one counts.
fn standing_procfs(ops: &[MountOp], needs_fresh: bool, writable: Writable) -> Option<&CStr> {
    // Walked backwards, because what is wanted is the *last* one still visible:
    // a candidate qualifies when nothing after it comes to rest on top of it.
    // Carrying only the most recent candidate forward instead would report no
    // procfs at all for a profile that mounted two and covered the second,
    // though the first is still standing.
    for (at, op) in ops.iter().enumerate().rev() {
        let Some(target) = procfs_op_target(op, needs_fresh, writable) else {
            continue;
        };
        let later = &ops[at + 1..];
        // A path made read-only brings the tree it finds back to rest where it
        // stood, the procfs with it, so it covers nothing; it leaves the
        // procfs read-only instead.
        let covered = later
            .iter()
            .filter(|later| !matches!(later.action, MountAction::ReadOnly { .. }))
            .filter_map(|later| later.action.arrival())
            .any(|(over, _)| covers(over, target));
        let read_only = writable == Writable::Required && left_read_only(later, target);
        if !covered && !read_only {
            return Some(target);
        }
    }
    None
}

/// Whether the last op among `later` that sets the read-only flag of the mount
/// at `target` leaves it read-only.
///
/// A remount acts on the mount standing at exactly its target, and sets the
/// flag to what it names. A path made read-only at `target` or above it makes
/// every mount within its tree read-only, this one included. The last of them
/// decides; a remount at another path leaves this mount as it was.
fn left_read_only(later: &[MountOp], target: &CStr) -> bool {
    later
        .iter()
        .rev()
        .find_map(|op| match &op.action {
            MountAction::Raw {
                target: at, flags, ..
            } if at.as_c_str() == target => {
                let flags = mechanism::raw_mount_flags(*flags);
                (flags & mechanism::MS_REMOUNT != 0)
                    .then_some(flags & MountFlags::RDONLY.bits() != 0)
            }
            MountAction::ReadOnly { target: at } if covers(at, target) => Some(true),
            _ => None,
        })
        .unwrap_or(false)
}

/// The rootfs-relative target an op mounts a usable procfs on, or `None` for
/// every other op.
///
/// A fresh procfs instance is mounted by the stage that performs the setup, so
/// it presents the sandbox's own PID namespace whatever that namespace is. A
/// bind carries whichever namespace its source presents instead, which matters
/// in exactly one case: a delegate names the command's map files by the pid its
/// `fork` returned, which is a pid of the sandbox's own PID namespace, and a
/// bound procfs from outside that namespace does not index it. Everything else
/// is served by either kind, because a process writing its *own* map reaches it
/// through `self`, which every procfs instance resolves for its reader.
///
/// A raw mount is read by what the kernel will do with it rather than by what it
/// says, through [`MountAction::arrival`]: `mount(2)` ignores `fstype` entirely
/// when `MS_BIND` or `MS_MOVE` is set, so a raw op carrying either flag brings a
/// tree that already stood elsewhere however it spells its filesystem, and is
/// held to the bind rule rather than to the fresh-instance one. Reading it the
/// other way would let `RawMount::new("/proc").source("/proc").fstype("proc")
/// .flags(MS_BIND)` satisfy a requirement it does not meet, and the failure
/// would arrive at launch instead of as the typed build error this machinery
/// exists to give. A remount or a propagation change mounts nothing.
///
/// The map files are written, so a procfs that arrives read-only serves no
/// route: a read-only bind, a raw procfs carrying `MS_RDONLY`, and a bind of a
/// source mounted read-only. A bound tree must also be a procfs's root, since
/// the map files are named from there. A bind of `/proc/sys` or `/proc/1`
/// carries the procfs magic number and holds no `self` to name them under.
/// [`Writable::Ignored`] admits a procfs that arrives read-only, and nothing
/// else.
fn procfs_op_target(op: &MountOp, needs_fresh: bool, writable: Writable) -> Option<&CStr> {
    let admits = |procfs_writable: bool| procfs_writable || writable == Writable::Ignored;
    match (&op.action, op.action.arrival()?) {
        (MountAction::Procfs { target }, _) => Some(target),
        (
            MountAction::Bind {
                source,
                target,
                read_only,
            },
            _,
        ) => (!needs_fresh
            && procfs_root_writable(source).is_some_and(|w| admits(w && !read_only)))
        .then_some(target.as_c_str()),
        (MountAction::Raw { source, target, .. }, (_, Arrival::Tree)) => (!needs_fresh
            && procfs_root_writable(source).is_some_and(admits))
        .then_some(target.as_c_str()),
        (
            MountAction::Raw {
                target,
                fstype,
                flags,
                ..
            },
            (_, Arrival::Fresh),
        ) => {
            let read_only = mechanism::raw_mount_flags(*flags) & MountFlags::RDONLY.bits() != 0;
            (fstype.as_bytes() == b"proc" && admits(!read_only)).then_some(target.as_c_str())
        }
        _ => None,
    }
}

/// The inode number of a procfs's root directory, `PROC_ROOT_INO`, which every
/// procfs instance gives its root and nothing else in it.
const PROC_ROOT_INO: u64 = 1;

/// Whether the bind source is the root of a procfs, and then whether it is
/// mounted writable, by the filesystem's own magic number rather than by its
/// path: the managed profile binds `/proc`, and a caller is free to bind a
/// procfs mounted anywhere else.
///
/// A bind takes its source mount's flags, and `mount(2)` ignores `MS_RDONLY` on
/// the bind itself, so a source mounted read-only arrives read-only whatever the
/// op says. All three questions go to one descriptor, so they describe one
/// object.
///
/// A source that cannot be interrogated is not one, which is the safe answer:
/// the build then refuses rather than composing paths into a filesystem that
/// holds no map files. Where its mount flags cannot be read it is read-only,
/// for the same reason.
fn procfs_root_writable(source: &CStr) -> Option<bool> {
    let source = rustix::fs::open(source, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).ok()?;
    let procfs =
        rustix::fs::fstatfs(&source).is_ok_and(|stat| stat.f_type == rustix::fs::PROC_SUPER_MAGIC);
    let root = rustix::fs::fstat(&source).is_ok_and(|stat| stat.st_ino == PROC_ROOT_INO);
    let writable = rustix::fs::fstatvfs(&source)
        .is_ok_and(|stat| !stat.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY));
    (procfs && root).then_some(writable)
}

/// Whether a mount at `mount` hides an entry at `covered`: the same path, or a
/// directory the covered path sits beneath.
///
/// Both are rootfs-relative and carry no leading slash, as the launch freezes
/// every target, so the comparison is a plain component-aligned prefix test.
/// It is the one answer to whether a path is at or under a mount target, which
/// the procfs requirement, the managed `resolv.conf` bind, and the placeholder
/// bookkeeping all ask.
fn covers(mount: &CStr, covered: &CStr) -> bool {
    let (mount, covered) = (mount.to_bytes(), covered.to_bytes());
    covered.starts_with(mount) && (covered.len() == mount.len() || covered[mount.len()] == b'/')
}

/// Builder methods for the opt-in hardening layer: Landlock filesystem and
/// network rules and scopes, seccomp syscall filters, and capability drops. See
/// [`crate::FsAccess`], [`crate::NetAccess`], [`crate::LandlockScope`],
/// [`crate::SeccompPolicy`], and [`crate::Capability`].
#[cfg(feature = "hardening")]
impl CageBuilder {
    /// Grants `access` beneath `path` under a Landlock ruleset.
    ///
    /// Configuring any grant enrolls the sandbox in Landlock: the command may
    /// then read, write, and execute files, and list, create, remove, and
    /// rename entries, only where a grant allows it. `path` is a sandbox path
    /// (absolute, resolved after the pivot), so grants describe the mounted
    /// view — the rootfs, the binds, and the `/proc`, `/dev`, and `/tmp` mounts
    /// alike. A grant may name a single file or device node as well as a
    /// directory; there it allows only the rights that act on a file, since
    /// there are no entries to list, create, or remove.
    ///
    /// Landlock does not govern a file's metadata. `chmod`, `chown`, extended
    /// attributes, timestamps, `stat`, and `chdir` reach any path the command
    /// can name, so a read-only grant over a writable bind still lets the
    /// command change the modes and owners beneath it. Truncation is governed
    /// from Landlock ABI 3 and device `ioctl` from ABI 5; an older kernel
    /// leaves them unrestricted.
    ///
    /// The path names its target itself, without a symbolic link at any
    /// component, the last included. A link in a root that is not fully trusted
    /// could point anywhere in the sandbox, and a grant resolved through it
    /// would cover wherever it pointed. A path that crosses one fails the
    /// launch with `ELOOP`, reported against the grant. On a root whose `/lib`
    /// is a link to `usr/lib`, grant `/usr/lib`, or `/usr` for both.
    ///
    /// The ruleset is enforced on a kernel that offers Landlock, best-effort
    /// down to the kernel's supported ABI; a kernel without the Landlock LSM
    /// is a setup error, so a requested restriction never silently fails to
    /// apply.
    ///
    /// An empty `access` is refused at build with
    /// [`ConfigError::LandlockGrantEmpty`](crate::ConfigError::LandlockGrantEmpty):
    /// it reads as "grant nothing here" and would behave as "deny the whole
    /// filesystem", the command's own binary included.
    pub fn landlock_fs(
        mut self,
        access: crate::hardening::FsAccess,
        path: impl AsRef<Path>,
    ) -> Self {
        self.hardening.grant_fs(access, path.as_ref());
        self
    }

    /// Grants network `access` on the TCP `port` under a Landlock ruleset.
    ///
    /// Configuring any grant — filesystem or network — enrolls the sandbox in
    /// Landlock. A network grant then governs both TCP bind and connect: the
    /// command may bind only ports granted [`NetAccess::BIND`] and connect only
    /// to ports granted [`NetAccess::CONNECT`], and every other bind and
    /// connect is denied. A grant of `port` `0` for [`NetAccess::BIND`] permits
    /// binding to a kernel-assigned ephemeral port.
    ///
    /// Network rights require Landlock ABI 4. On an older kernel that offers
    /// Landlock they are narrowed away best-effort, exactly as an unsupported
    /// filesystem right is;
    /// [`host::landlock_enforces_net`](crate::host::landlock_enforces_net)
    /// reports whether the running kernel enforces them.
    ///
    /// # Where the downgrade is refused, and where it is silent
    ///
    /// Under [`Network::Host`] a network grant is the sandbox's only network
    /// boundary, so a kernel that cannot enforce it is a build error rather than
    /// a downgrade.
    ///
    /// Under [`Network::Isolated`] and [`Network::None`] the network namespace
    /// is the boundary and the grant is additive hardening, so the downgrade is
    /// silent. That includes the case where the grant is the *only* Landlock
    /// request made: with every network right masked away and no filesystem
    /// grant to carry, no ruleset is built at all, and the command runs with the
    /// namespace as its sole network confinement. Check
    /// [`host::landlock_enforces_net`](crate::host::landlock_enforces_net)
    /// before the build where that matters.
    ///
    /// A network stack attached to such a sandbox gives its namespace outbound
    /// TCP, after which the grant is the only bound on the ports the command
    /// reaches. The build cannot see a stack, which attaches at the pending
    /// seam, so the attachment refuses a kernel that cannot enforce the grant:
    /// `NetStack::attach` answers `NetStackError::LandlockNetUnenforceable`.
    ///
    /// An empty `access` is refused at build with
    /// [`ConfigError::LandlockGrantEmpty`](crate::ConfigError::LandlockGrantEmpty):
    /// enrolling a grant denies everything ungranted and the kernel skips a rule
    /// that permits nothing, so it would deny all TCP rather than nothing.
    ///
    /// [`NetAccess::BIND`]: crate::NetAccess::BIND
    /// [`NetAccess::CONNECT`]: crate::NetAccess::CONNECT
    pub fn landlock_net(mut self, access: crate::hardening::NetAccess, port: u16) -> Self {
        self.hardening.grant_net(access, port);
        self
    }

    /// Confines the command's reach to processes outside its Landlock domain,
    /// for each of `scopes`, replacing any scopes set before.
    ///
    /// A scope denies an interaction with a process the sandbox did not start,
    /// and leaves it open between the command and its own descendants:
    /// [`LandlockScope::Signal`] denies sending a signal, and
    /// [`LandlockScope::AbstractUnixSocket`] denies connecting to an abstract
    /// socket. A default sandbox needs neither, because its PID and network
    /// namespaces already hide those processes. They matter under
    /// [`pid_namespace(false)`](Self::pid_namespace), where the command can see
    /// and signal the calling user's other processes, and under
    /// [`Network::Host`], where it can reach the host's abstract sockets. The
    /// default is no scope.
    ///
    /// A scope needs Landlock ABI 6 (Linux 6.12). What an older kernel does with
    /// one depends on whether a namespace also bounds its reach:
    ///
    /// - Where one does, the scope is additive. A kernel that offers Landlock
    ///   below ABI 6 narrows it away best-effort, as an unsupported filesystem
    ///   right. A kernel without the Landlock LSM fails the launch with a setup
    ///   error, as it does a grant.
    /// - Where none does, the scope is the boundary: `Signal` without a PID
    ///   namespace, and `AbstractUnixSocket` under [`Network::Host`]. Either
    ///   kernel refuses the build with
    ///   [`ConfigError::LandlockScopeUnenforceable`](crate::ConfigError::LandlockScopeUnenforceable),
    ///   rather than run the command with that reach open.
    ///
    /// [`host::landlock_enforces_scope`](crate::host::landlock_enforces_scope)
    /// reports whether the running kernel enforces a scope.
    ///
    /// A scope is not a grant: it enrolls no path and no port, so the
    /// filesystem and the network stay as open as the grants leave them.
    ///
    /// [`LandlockScope::Signal`]: crate::LandlockScope::Signal
    /// [`LandlockScope::AbstractUnixSocket`]: crate::LandlockScope::AbstractUnixSocket
    pub fn landlock_scope<I>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = crate::hardening::LandlockScope>,
    {
        self.hardening.set_scope(scopes);
        self
    }

    /// Refuses the command a connection to a pathname unix socket created
    /// outside its Landlock domain, except beneath a path granted
    /// [`FsAccess::RESOLVE_UNIX`](crate::FsAccess::RESOLVE_UNIX) (default:
    /// on under the [host's own root](Self::host_rootfs), off otherwise).
    ///
    /// A read-only mount does not stop a `connect`, and a hidden path covers
    /// only the places it names, so a socket anywhere else in the command's
    /// view accepts its connection: inside a bound working tree, or an agent's
    /// socket at an unexpected path. This is Landlock's
    /// `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` right, which governs `connect`, and
    /// `sendmsg` with an explicit address, to such a socket, and answers
    /// `EACCES`. A socket the command or a process it started created stays
    /// reachable, as an abstract socket does under
    /// [`LandlockScope::AbstractUnixSocket`](crate::LandlockScope::AbstractUnixSocket).
    ///
    /// ```no_run
    /// use ferroday_cage::{Cage, FsAccess};
    ///
    /// # fn main() -> ferroday_cage::Result<()> {
    /// let cage = Cage::builder()
    ///     .rootfs("/srv/rootfs/alpine")
    ///     .bind("/run/egress", "/run/egress")
    ///     .landlock_resolve_unix(true)
    ///     .landlock_fs(FsAccess::RESOLVE_UNIX, "/run/egress")
    ///     .command("/usr/bin/agent")
    ///     .build()?;
    /// # let _ = cage;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// It enrolls no other right, so a grant of `RESOLVE_UNIX` alone opens one
    /// socket directory without closing the rest of the filesystem. A grant of
    /// it where the restriction is off allows nothing, and is refused at build
    /// with [`ConfigError::ResolveUnixUnhandled`](crate::ConfigError::ResolveUnixUnhandled).
    ///
    /// The right needs Landlock ABI 9. A restriction asked for here is refused
    /// at build on an older kernel, or one without the Landlock LSM, with
    /// [`ConfigError::LandlockResolveUnixUnenforceable`](crate::ConfigError::LandlockResolveUnixUnenforceable),
    /// since it is the only bound on the sockets a mount does not hide.
    /// [`host::landlock_enforces_fs`](crate::host::landlock_enforces_fs) with
    /// [`FsAccess::RESOLVE_UNIX`](crate::FsAccess::RESOLVE_UNIX) reports whether
    /// the running kernel enforces it. The host root's default is dropped on
    /// such a kernel instead, and [`resolved_inputs`](Cage::resolved_inputs)
    /// reports whether it applies.
    pub fn landlock_resolve_unix(mut self, restrict: bool) -> Self {
        self.hardening.set_resolve_unix(restrict);
        self
    }

    /// Applies a seccomp syscall filter to the command.
    ///
    /// See [`SeccompPolicy`](crate::SeccompPolicy) for rule sets, the
    /// [curated roster](crate::SeccompRules::curated) among them, and the
    /// pre-compiled escape hatch. The filter binds the command and its
    /// descendants.
    pub fn seccomp(mut self, policy: crate::hardening::SeccompPolicy) -> Self {
        self.hardening.set_seccomp(policy);
        self
    }

    /// Drops every capability from the command.
    ///
    /// The command runs mapped to root inside the user namespace but holds no
    /// capabilities, so operations gated on one are refused. The bounding and
    /// ambient sets are cleared too, so no capability can be regained across
    /// `execve`.
    pub fn drop_all_capabilities(mut self) -> Self {
        self.hardening.drop_all_capabilities();
        self
    }

    /// Drops every capability except those named.
    ///
    /// Like [`drop_all_capabilities`](Self::drop_all_capabilities), but the
    /// listed capabilities are retained in the permitted, effective,
    /// inheritable, bounding, and ambient sets.
    pub fn keep_capabilities<I>(mut self, caps: I) -> Self
    where
        I: IntoIterator<Item = crate::hardening::Capability>,
    {
        self.hardening.keep_capabilities(caps);
        self
    }

    /// The Landlock filesystem grants, in the order they were configured: each
    /// access set with the sandbox path it is granted beneath.
    pub fn get_landlock_fs(&self) -> impl Iterator<Item = (crate::hardening::FsAccess, &Path)> {
        self.hardening.fs_grants()
    }

    /// The Landlock network grants, in the order they were configured: each
    /// access set with the TCP port it governs.
    pub fn get_landlock_net(&self) -> impl Iterator<Item = (crate::hardening::NetAccess, u16)> {
        self.hardening.net_grants()
    }

    /// The Landlock scopes requested, in the order
    /// [`LandlockScope::ALL`](crate::LandlockScope::ALL) lists them; none by
    /// default.
    pub fn get_landlock_scope(&self) -> impl Iterator<Item = crate::hardening::LandlockScope> {
        self.hardening.scopes()
    }

    /// Whether the command is held to the unix-socket restriction: the
    /// [`landlock_resolve_unix`](Self::landlock_resolve_unix) setting, or the
    /// root's default where it is unset. What a kernel too old for the
    /// default does with it is [`resolved_inputs`](Cage::resolved_inputs)'s to
    /// report.
    pub fn get_landlock_resolve_unix(&self) -> bool {
        self.hardening.resolve_unix().unwrap_or(self.host_rootfs)
    }

    /// The seccomp policy applied to the command, or `None` for no filter.
    ///
    /// What a caller reads to extend a policy a profile set rather than replace
    /// it: [`SeccompRules`](crate::SeccompRules) is a value, so the rules come
    /// back out, take another entry, and go back in through
    /// [`seccomp`](Self::seccomp).
    pub fn get_seccomp(&self) -> Option<&crate::hardening::SeccompPolicy> {
        self.hardening.seccomp()
    }

    /// The capabilities the command keeps, or `None` where the capability sets
    /// are left as the identity switch leaves them, which is the default.
    ///
    /// The reading of both capability setters: an empty list is
    /// [`drop_all_capabilities`](Self::drop_all_capabilities), and a list of
    /// names is [`keep_capabilities`](Self::keep_capabilities).
    pub fn get_keep_capabilities(&self) -> Option<&[crate::hardening::Capability]> {
        self.hardening.kept_capabilities()
    }
}

/// Composes a command's environment: the given deterministic base plus the
/// caller's variables, later entries overriding earlier ones, frozen as
/// sorted `NAME=value` strings.
pub(crate) fn compose_env(
    base: &[(&str, &str)],
    vars: &[(OsString, OsString)],
) -> Result<Vec<CString>, Error> {
    let mut env: BTreeMap<OsString, OsString> = base
        .iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect();
    for (name, value) in vars {
        // A NUL in the name is the name's fault, and is reported against it; a
        // NUL in the value is reported as the value it is.
        if name.is_empty() || name.as_bytes().contains(&b'=') || cstring(name).is_err() {
            return Err(ConfigError::EnvNameInvalid { name: name.clone() }.into());
        }
        cstring(value)?;
        env.insert(name.clone(), value.clone());
    }
    env.iter()
        .map(|(name, value)| {
            let mut entry = Vec::with_capacity(name.len() + value.len() + 1);
            entry.extend_from_slice(name.as_bytes());
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            CString::new(entry).map_err(|err| embedded_nul(err.into_vec()).into())
        })
        .collect()
}

/// Validates a hostname: non-empty, at most 64 bytes, no NUL.
fn validate_hostname(name: &OsStr) -> Result<CString, Error> {
    let invalid = || {
        Error::from(ConfigError::HostnameInvalid {
            name: name.to_os_string(),
        })
    };
    if name.is_empty() || name.len() > 64 {
        return Err(invalid());
    }
    CString::new(name.as_bytes()).map_err(|_| invalid())
}

/// Validates a working directory: an absolute path of plain components, as
/// [`path::absolute_components`] holds every configured absolute path, with no
/// NUL. Returns `None` for the root, where no `chdir` is needed.
///
/// A `..` is refused rather than left to `chdir`, as it is in a mount target:
/// nothing composes a working directory with one on purpose.
pub(crate) fn validate_workdir(path: &Path) -> Result<Option<CString>, Error> {
    let components =
        path::absolute_components(path).map_err(|_| ConfigError::WorkdirNotAbsolute {
            path: path.to_path_buf(),
        })?;
    if components.is_empty() {
        return Ok(None);
    }
    Ok(Some(cstring(path.as_os_str())?))
}

/// Prepares an overlay root: resolves the lowers, creates the upper and its work
/// directory, refuses a host that cannot mount an unprivileged overlay, and
/// freezes the mount options.
///
/// `base` is the already-canonicalized root filesystem, which is the first
/// lower. Every further lower is resolved beside it, and the upper and work
/// directories are resolved to the absolute paths the mount options name. The
/// work directory, which the overlay requires empty and on the upper's
/// filesystem, is a hidden sibling of the upper unless the caller named one.
///
/// Everything that can be refused without creating a directory is checked
/// before one is created: the lowers, the presence of an upper, whether every
/// layer is disjoint from every other, and whether the option string can carry
/// every layer path. The missing directories above the upper and the work
/// directory are created next, and then the host's support for an unprivileged
/// overlay is probed in the upper's parent, through
/// [`overlay_blocker`](crate::host::overlay_blocker). A refusal after that
/// removes the directories this call created, so a refused build leaves the host
/// as it found it.
fn build_overlay_plan(base: &Path, overlay: &Overlay) -> Result<OverlayPlan, Error> {
    // The base is already canonical: it is the first lower, resolved as the
    // rootfs. Resolve any further lowers the same way, so a missing or
    // non-directory layer is a typed configuration error here.
    let mut lowers = vec![base.to_path_buf()];
    for lower in overlay.lower.iter().skip(1) {
        let resolved = std::fs::canonicalize(lower)
            .map_err(|err| overlay_io(OverlayLayer::Lower, lower, err))?;
        rustix::fs::open(
            &resolved,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| ConfigError::OverlayDirUnusable {
            layer: OverlayLayer::Lower,
            path: lower.clone(),
            source: errno.into(),
        })?;
        lowers.push(resolved);
    }

    // An overlay with no upper would be a read-only merge; the sandbox needs
    // somewhere for its writes to land, so the upper is required.
    let Some(upper) = overlay.upper.as_deref() else {
        return Err(ConfigError::OverlayUpperMissing.into());
    };

    let upper = layer_path(OverlayLayer::Upper, upper)?;
    // The work directory sits beside the upper, on the same filesystem, so the
    // overlay can move files between them. A hidden sibling keyed to the upper's
    // name keeps it out of the way and distinct per upper; a caller may name its
    // own instead.
    let work = match overlay.work.as_deref() {
        Some(work) => layer_path(OverlayLayer::Work, work)?,
        None => LayerPath {
            parent: upper.parent.clone(),
            name: overlay_work_name(&upper.name),
        },
    };
    let (upper_path, work_path) = (upper.path(), work.path());

    check_layers_disjoint(&lowers, &upper_path, &work_path)?;

    let options =
        crate::mechanism::overlay_options(&lowers, &upper_path, &work_path).map_err(|refusal| {
            match refusal {
                OverlayOptionsError::Unrepresentable(path) => {
                    ConfigError::OverlayPathInvalid { path }
                }
                OverlayOptionsError::TooLong(length) => {
                    ConfigError::OverlayOptionsTooLong { length }
                }
            }
        })?;

    let mut created = CreatedDirs::default();
    for (layer, at) in [(OverlayLayer::Upper, &upper), (OverlayLayer::Work, &work)] {
        created
            .create_all(&at.parent)
            .map_err(|err| overlay_io(layer, &at.parent, err))?;
    }

    // Refuse a host that cannot establish an unprivileged overlay whose upper
    // lives on this filesystem, before any fork — the same fail-early posture
    // the identity-map validation takes. The probe runs in the upper's parent,
    // whose filesystem the upper is created on, so its scratch entries land
    // beside the upper rather than inside it.
    if let Some(blocker) = crate::host::overlay_blocker(&upper.parent) {
        return Err(ConfigError::OverlayUnavailable { blocker }.into());
    }

    create_layer_dir(OverlayLayer::Upper, &upper, &mut created)?;
    create_layer_dir(OverlayLayer::Work, &work, &mut created)?;

    // The overlay moves files between the upper and the work directory, so the
    // kernel requires them on one filesystem. A caller that named its own work
    // directory can have put it elsewhere; comparing the two devices refuses
    // that here, with both named, rather than at the mount as a bare EXDEV
    // from a syscall the caller never issued.
    let device = |layer, path: &Path| {
        rustix::fs::stat(path)
            .map(|stat| stat.st_dev)
            .map_err(|errno| overlay_errno(layer, path, errno))
    };
    if device(OverlayLayer::Upper, &upper_path)? != device(OverlayLayer::Work, &work_path)? {
        return Err(ConfigError::OverlayWorkOnAnotherFilesystem {
            work: work_path,
            upper: upper_path,
        }
        .into());
    }

    created.keep();
    Ok(OverlayPlan {
        options,
        lower: lowers,
        upper: upper_path,
        work: work_path,
    })
}

/// The overlay work directory the library manages beside `upper`: a hidden
/// sibling keyed to the upper's name, on the same filesystem the overlay
/// requires it share with the upper. Returns `None` when `upper` has no parent or
/// no file name.
///
/// [`Remove::overlay_upper`](crate::provision::Remove::overlay_upper), and so a
/// layered build's disposal, finds the work directory through this, and the
/// overlay-plan construction here names it through [`overlay_work_name`], so the
/// directory an overlay-rooted sandbox creates and the one a removal of its
/// upper takes are the same.
pub(crate) fn overlay_work_dir(upper: &Path) -> Option<PathBuf> {
    let (parent, name) = (upper.parent()?, upper.file_name()?);
    Some(parent.join(overlay_work_name(name)))
}

/// The name of the work directory managed beside an upper named `upper`.
fn overlay_work_name(upper: &OsStr) -> OsString {
    let mut work_name = OsString::from(".");
    work_name.push(upper);
    work_name.push(".work");
    work_name
}

/// The mode an overlay layer directory the library creates is given.
///
/// Stated rather than left to the process umask, for the same reason
/// [`DIR_MODE`] is: the directory outlives the sandbox on the host, and whether
/// the layer a build keeps is readable is not a property worth taking from
/// whatever umask the build happened to run under. A layer directory that was
/// already there is left at the mode its owner gave it.
const OVERLAY_DIR_MODE: RawMode = 0o755;

/// Where an overlay layer directory goes: its parent directory, resolved, and
/// the layer's own name inside it.
///
/// The absolute path the mount options name is composed from the parent's
/// canonical path and the leaf's own name, so the leaf is never resolved as a
/// link. [`create_layer_dir`] establishes that it is not one.
struct LayerPath {
    /// The parent directory, canonical.
    parent: PathBuf,
    /// The layer directory's name inside `parent`.
    name: OsString,
}

impl LayerPath {
    /// The layer directory's absolute path.
    fn path(&self) -> PathBuf {
        self.parent.join(&self.name)
    }
}

/// Resolves where the layer directory `path` goes, creating nothing.
///
/// The parent is resolved through symbolic links, as
/// [`std::fs::canonicalize`] resolves a path: the caller named it, so reaching
/// it through a link is the caller's business, the same position
/// `provision::containment::open_dir` takes. A parent that does not exist yet
/// resolves to the path it will have once its missing directories are created;
/// see [`canonical_once_created`]. The layer directory itself is never resolved:
/// [`create_layer_dir`] creates it, or adopts a directory the calling user owns,
/// never a link.
fn layer_path(layer: OverlayLayer, path: &Path) -> Result<LayerPath, Error> {
    // A path with no file name is `/` or one ending in `..`; neither names a
    // directory this can create inside a parent.
    let Some(name) = path.file_name() else {
        return Err(ConfigError::OverlayLayerIsRoot {
            layer,
            path: path.to_path_buf(),
        }
        .into());
    };
    let parent = crate::path::parent_of(path);
    Ok(LayerPath {
        parent: canonical_once_created(parent).map_err(|err| overlay_io(layer, parent, err))?,
        name: name.to_os_string(),
    })
}

/// The canonical path `dir` will have once [`CreatedDirs::create_all`] has
/// created whatever of it is missing.
///
/// [`std::fs::canonicalize`] answers for the longest leading part of `dir` that
/// exists. Each missing component after that part is a plain directory once it
/// is created, so it is appended by name, and a `..` among them steps back over
/// the one before it, as it does once that one exists. A failure other than a
/// missing entry, such as a permission refusal or a file where a directory
/// belongs, is returned.
fn canonical_once_created(dir: &Path) -> std::io::Result<PathBuf> {
    // Each missing component by name, outermost last, or `None` for a `..`.
    let mut missing: Vec<Option<&OsStr>> = Vec::new();
    let mut existing = dir;
    let mut resolved = loop {
        match std::fs::canonicalize(existing) {
            Ok(resolved) => break resolved,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                missing.push(match existing.components().next_back() {
                    Some(Component::Normal(name)) => Some(name),
                    Some(Component::ParentDir) => None,
                    // A `.` or a root that is missing has nothing above it to
                    // resolve instead.
                    _ => return Err(err),
                });
                existing = crate::path::parent_of(existing);
            }
            Err(err) => return Err(err),
        }
    };
    for name in missing.into_iter().rev() {
        match name {
            Some(name) => resolved.push(name),
            None => {
                resolved.pop();
            }
        }
    }
    Ok(resolved)
}

/// Refuses an overlay whose layers are not disjoint: a layer that is another
/// one, or that lies beneath it.
///
/// The kernel refuses some overlaps at mount and accepts others. An upper or a
/// work directory beneath a lower mounts, and every write the sandbox makes
/// then lands inside that lower, so it is refused here, before the build
/// creates anything. The overlaps the kernel refuses are refused here as well,
/// naming the two layers rather than leaving an `ELOOP` or an `EINVAL` from a
/// mount the caller never issued.
///
/// The paths compared are the ones the mount options name: every lower
/// canonicalized, and the upper and the work directory as their canonicalized
/// parent and their own name. A symbolic link anywhere above a layer is
/// therefore resolved before the comparison, and two spellings of one directory
/// compare equal. A directory a bind mount presents at a second path is not
/// recognised there.
fn check_layers_disjoint(lowers: &[PathBuf], upper: &Path, work: &Path) -> Result<(), ConfigError> {
    let layers: Vec<(OverlayLayer, &Path)> = lowers
        .iter()
        .map(|lower| (OverlayLayer::Lower, lower.as_path()))
        .chain([(OverlayLayer::Upper, upper), (OverlayLayer::Work, work)])
        .collect();
    for (index, &(layer, path)) in layers.iter().enumerate() {
        for &(earlier, earlier_path) in &layers[..index] {
            let (inner, outer) = if path.starts_with(earlier_path) {
                ((layer, path), (earlier, earlier_path))
            } else if earlier_path.starts_with(path) {
                ((earlier, earlier_path), (layer, path))
            } else {
                continue;
            };
            return Err(ConfigError::OverlayLayersOverlap {
                layer: inner.0,
                path: inner.1.to_path_buf(),
                within: outer.0,
                within_path: outer.1.to_path_buf(),
            });
        }
    }
    Ok(())
}

/// Creates an overlay layer directory if it is absent, refusing to adopt an
/// entry the calling user does not own.
///
/// The layer directories are the one part of an overlay root the library
/// creates on the host, and the caller may well name them under a directory it
/// shares — a scratch area, a build tree several jobs write to. A plain
/// `create_dir_all` would succeed against anything already at the path that
/// *resolves* to a directory, a symbolic link to one included, and the resolved
/// destination is what would then go into `upperdir=`: every write the sandbox
/// makes would land wherever the link pointed, and the caller would read that
/// back afterwards as the increment its build produced.
///
/// So the leaf is created with `mkdirat` against a descriptor for its parent,
/// which refuses a name that exists rather than following it, and an `EEXIST` is
/// adopted only when `fstatat` — with `AT_SYMLINK_NOFOLLOW`, so a link is a link
/// and not its destination — reports a directory belonging to the calling user.
/// The same discipline [`host::overlay_blocker`](crate::host::overlay_blocker)
/// already applies to its throwaway probe entries in the same directory. A
/// directory this creates is recorded in `created`; an adopted one is not, and
/// is never removed.
fn create_layer_dir(
    layer: OverlayLayer,
    at: &LayerPath,
    created: &mut CreatedDirs,
) -> Result<(), Error> {
    let path = at.path();
    let dirfd = rustix::fs::open(
        &at.parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| overlay_errno(layer, &at.parent, errno))?;

    match rustix::fs::mkdirat(&dirfd, &at.name, Mode::from_raw_mode(OVERLAY_DIR_MODE)) {
        // The mode is set again, because `mkdir` narrows it by the process
        // umask and the layer outlives the sandbox on the host: a build under
        // `umask 077` would otherwise leave a `0700` upper for whatever consumes
        // it next. Only the directory this call just created is chmod-ed, so an
        // adopted one keeps the mode its owner gave it — the same rule the
        // sandbox stage follows for a mount point it creates, and set the same
        // way, through a descriptor: `O_NOFOLLOW` and `O_DIRECTORY` refuse
        // whatever replaced the name since the `mkdir`, where a chmod by name
        // would follow a link put there to the file it names.
        Ok(()) => {
            created.record(path.clone());
            let made = rustix::fs::openat(
                &dirfd,
                &at.name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|errno| overlay_errno(layer, &path, errno))?;
            rustix::fs::fchmod(&made, Mode::from_raw_mode(OVERLAY_DIR_MODE))
                .map_err(|errno| overlay_errno(layer, &path, errno))?;
        }
        Err(Errno::EXIST) => {
            let stat = rustix::fs::statat(&dirfd, &at.name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|errno| overlay_errno(layer, &path, errno))?;
            let is_dir = FileType::from_raw_mode(stat.st_mode) == FileType::Directory;
            if !is_dir || stat.st_uid != rustix::process::geteuid().as_raw() {
                return Err(ConfigError::OverlayDirUnowned { layer, path }.into());
            }
        }
        Err(errno) => return Err(overlay_errno(layer, &path, errno)),
    }
    Ok(())
}

/// The host directories one overlay preparation created, removed again unless
/// the build that created them succeeds.
///
/// Removal is `rmdir`, deepest first, so a directory goes only while it is
/// still empty. One that something else wrote into meanwhile stays, and so does
/// every directory above it.
#[derive(Default)]
struct CreatedDirs(Vec<PathBuf>);

impl CreatedDirs {
    /// Creates `dir` and every missing directory above it, as `create_dir_all`
    /// does, recording each one created.
    fn create_all(&mut self, dir: &Path) -> std::io::Result<()> {
        if dir.as_os_str().is_empty() || dir.is_dir() {
            return Ok(());
        }
        if let Some(parent) = dir.parent() {
            self.create_all(parent)?;
        }
        match std::fs::create_dir(dir) {
            Ok(()) => {
                self.record(dir.to_path_buf());
                Ok(())
            }
            // Created by someone else in the meantime, or a `..` naming a
            // directory that already exists.
            Err(_) if dir.is_dir() => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Records a directory this preparation created.
    fn record(&mut self, dir: PathBuf) {
        self.0.push(dir);
    }

    /// Keeps every directory recorded: the build succeeded, and they are its.
    fn keep(mut self) {
        self.0.clear();
    }
}

impl Drop for CreatedDirs {
    fn drop(&mut self) {
        for dir in self.0.iter().rev() {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// Builds the configuration error for a host I/O failure preparing an overlay
/// layer directory, naming which of the two the failure was.
fn overlay_io(layer: OverlayLayer, path: &Path, err: std::io::Error) -> Error {
    ConfigError::OverlayDirUnusable {
        layer,
        path: path.to_path_buf(),
        source: err,
    }
    .into()
}

/// [`overlay_io`] for the raw-syscall paths, which report an [`Errno`] rather
/// than an [`std::io::Error`].
fn overlay_errno(layer: OverlayLayer, path: &Path, errno: Errno) -> Error {
    ConfigError::OverlayDirUnusable {
        layer,
        path: path.to_path_buf(),
        source: errno.into(),
    }
    .into()
}

/// Lowers the mount profile into the frozen op list the child process
/// executes.
///
/// Each op carries every path it needs as a rootfs-relative `CString`, with
/// mount-target directory chains precomputed as [`MountDir`]s, so the child
/// process performs no path manipulation. The label list is parallel to the ops
/// and caller-side only: it names the mount in a setup error. A configured path
/// is named there with `{:?}`, since a profile nothing vouches for can supply a
/// hidden path or one made read-only, and every kind is named the same way.
#[derive(Default)]
struct Lowering {
    ops: Vec<MountOp>,
    labels: Vec<String>,
}

impl Lowering {
    fn push(&mut self, op: MountOp, label: String) {
        self.ops.push(op);
        self.labels.push(label);
    }

    /// A fresh procfs instance, presenting the sandbox's own PID namespace.
    fn push_proc_fresh(&mut self) -> Result<(), Error> {
        self.push(
            MountOp {
                dirs: dir_chain(&["proc"], DIR_MODE)?,
                create_file: None,
                action: MountAction::Procfs {
                    target: rel_cstring(&["proc"])?,
                },
            },
            "/proc".to_string(),
        );
        Ok(())
    }

    /// The host's procfs, bind-mounted: without a new PID namespace a fresh
    /// procfs instance would present the same processes — and the kernel
    /// refuses one in a user namespace when the host /proc carries
    /// overmounts (a systemd binfmt_misc automount, for example). The bind
    /// carries those submounts along.
    fn push_proc_bind(&mut self) -> Result<(), Error> {
        self.push(
            MountOp {
                dirs: dir_chain(&["proc"], DIR_MODE)?,
                create_file: None,
                action: MountAction::Bind {
                    source: cstring(OsStr::new("/proc"))?,
                    target: rel_cstring(&["proc"])?,
                    read_only: false,
                },
            },
            "/proc".to_string(),
        );
        Ok(())
    }

    fn push_dev(&mut self) -> Result<(), Error> {
        // The /dev tmpfs is NOSUID but deliberately not NODEV: it must carry
        // the device nodes bound below, which NODEV would render inoperable.
        // The nodes themselves are bind-mounted read-write from the host, not
        // recreated (mknod is denied to an unprivileged process, even in a
        // user namespace). This is safe in the sandbox's user namespace: the
        // bound nodes are the host's own null/zero/random/etc., not fresh
        // nodes the sandbox could use to reach an arbitrary device, and access
        // to them is governed by the namespace. It mirrors what bubblewrap
        // does, and the choice is intentional rather than an oversight.
        self.push(
            MountOp {
                dirs: dir_chain(&["dev"], DIR_MODE)?,
                create_file: None,
                action: MountAction::Tmpfs {
                    target: rel_cstring(&["dev"])?,
                    flags: MountFlags::NOSUID,
                    data: c"mode=0755".to_owned(),
                },
            },
            "/dev".to_string(),
        );
        for device in DEV_DEVICES {
            // Canonical, as every bind source is, since the launch opens it
            // without following a link. A device the host lacks keeps its
            // name, and the launch fails at its bind.
            let source = PathBuf::from(format!("/dev/{device}"));
            let source = std::fs::canonicalize(&source).unwrap_or(source);
            self.push(
                MountOp {
                    dirs: Vec::new(),
                    create_file: Some(rel_cstring(&["dev", device])?),
                    action: MountAction::Bind {
                        source: cstring(source.as_os_str())?,
                        target: rel_cstring(&["dev", device])?,
                        read_only: false,
                    },
                },
                format!("/dev/{device}"),
            );
        }
        for (name, content) in DEV_SYMLINKS {
            self.push(
                MountOp {
                    dirs: Vec::new(),
                    create_file: None,
                    action: MountAction::Symlink {
                        parent: rel_cstring(&["dev"])?,
                        leaf: cstring(OsStr::new(name))?,
                        content: cstring(OsStr::new(content))?,
                    },
                },
                format!("/dev/{name}"),
            );
        }
        self.push(
            MountOp {
                // The mount point is an ordinary directory: devpts's `mode=` is
                // the mode of the pseudo-terminals it allocates, not of its
                // own root, so there is nothing here to mirror.
                dirs: dir_chain(&["dev", "pts"], DIR_MODE)?,
                create_file: None,
                action: MountAction::Devpts {
                    target: rel_cstring(&["dev", "pts"])?,
                    // No gid= option: the conventional tty group is not
                    // mapped under the default single-identity map and an
                    // unmapped gid fails the mount.
                    data: c"newinstance,ptmxmode=0666,mode=0620".to_owned(),
                },
            },
            "/dev/pts".to_string(),
        );
        self.push(
            MountOp {
                dirs: dir_chain(&["dev", "shm"], STICKY_DIR_MODE)?,
                create_file: None,
                action: MountAction::Tmpfs {
                    target: rel_cstring(&["dev", "shm"])?,
                    flags: MountFlags::NOSUID | MountFlags::NODEV,
                    data: c"mode=1777".to_owned(),
                },
            },
            "/dev/shm".to_string(),
        );
        Ok(())
    }

    fn push_tmp(&mut self) -> Result<(), Error> {
        self.push(
            MountOp {
                dirs: dir_chain(&["tmp"], STICKY_DIR_MODE)?,
                create_file: None,
                action: MountAction::Tmpfs {
                    target: rel_cstring(&["tmp"])?,
                    flags: MountFlags::NOSUID | MountFlags::NODEV,
                    data: c"mode=1777".to_owned(),
                },
            },
            "/tmp".to_string(),
        );
        Ok(())
    }

    fn push_bind(&mut self, bind: &Bind) -> Result<(), Error> {
        let source = std::fs::canonicalize(&bind.source).map_err(|err| {
            Error::from(ConfigError::BindSourceUnusable {
                path: bind.source.clone(),
                source: err,
            })
        })?;
        let source_is_dir = source.is_dir();
        let components = sandbox_path_components(&bind.target)?;

        let (dirs, create_file) = if source_is_dir {
            (dir_chain(&components, DIR_MODE)?, None)
        } else {
            // A file bind creates the parent directories and then the
            // target file itself.
            let parents = &components[..components.len() - 1];
            (
                dir_chain(parents, DIR_MODE)?,
                Some(rel_cstring(&components)?),
            )
        };

        let label = format!(
            "{source:?} at {:?}{}",
            bind.target,
            if bind.read_only { ", read-only" } else { "" },
        );
        self.push(
            MountOp {
                dirs,
                create_file,
                action: MountAction::Bind {
                    source: cstring(source.as_os_str())?,
                    target: rel_cstring(&components)?,
                    read_only: bind.read_only,
                },
            },
            label,
        );
        Ok(())
    }

    fn push_raw(&mut self, raw: &RawMount) -> Result<(), Error> {
        let components = sandbox_path_components(&raw.target)?;
        let flags = u32::try_from(raw.flags).map_err(|_| ConfigError::MountFlagsInvalid {
            target: raw.target.clone(),
            flags: raw.flags,
        })?;
        let source = match &raw.source {
            Some(path) => cstring(path.as_os_str())?,
            None => CString::default(),
        };
        let fstype = match &raw.fstype {
            Some(fstype) => cstring(OsStr::new(fstype))?,
            None => CString::default(),
        };
        let data = match &raw.data {
            Some(data) => cstring(OsStr::new(data))?,
            None => CString::default(),
        };
        self.push(
            MountOp {
                dirs: dir_chain(&components, DIR_MODE)?,
                create_file: None,
                action: MountAction::Raw {
                    source,
                    target: rel_cstring(&components)?,
                    fstype,
                    flags: MountFlags::from_bits_retain(flags),
                    data,
                },
            },
            format!("raw mount at {:?}", raw.target),
        );
        Ok(())
    }

    /// A hidden path. It creates nothing: what is at the path when the launch
    /// reaches it decides how it is hidden, and nothing there hides nothing.
    fn push_hide(&mut self, hide: &Hide) -> Result<(), Error> {
        self.push(
            MountOp {
                dirs: Vec::new(),
                create_file: None,
                action: MountAction::Hide {
                    target: sandbox_target(&hide.target)?,
                },
            },
            format!("hiding {:?}", hide.target),
        );
        Ok(())
    }

    /// A path made read-only where it stands. It creates nothing: a path that
    /// is missing when the launch reaches it fails the launch.
    fn push_read_only(&mut self, read_only: &ReadOnly) -> Result<(), Error> {
        self.push(
            MountOp {
                dirs: Vec::new(),
                create_file: None,
                action: MountAction::ReadOnly {
                    target: sandbox_target(&read_only.target)?,
                },
            },
            format!("{:?} made read-only", read_only.target),
        );
        Ok(())
    }

    /// A caller's symbolic link, made in whatever holds its parent directory
    /// once the ops before it have run.
    fn push_symlink(&mut self, symlink: &Symlink) -> Result<(), Error> {
        let components = sandbox_path_components(&symlink.path)?;
        let (leaf, parents) = components
            .split_last()
            .expect("a mount target names at least one component");
        // The kernel refuses an empty target, and one that does not fit a path
        // with its terminator, so either is refused here with its name. The
        // launch reads an existing link back into a buffer of this size, which
        // a target filling it could not be told apart from a longer one in.
        let target = symlink.target.as_os_str();
        if target.is_empty() || target.len() >= mechanism::bounds::LINK_BUF {
            return Err(ConfigError::SymlinkTargetInvalid {
                path: symlink.path.clone(),
                target: symlink.target.clone(),
            }
            .into());
        }
        self.push(
            MountOp {
                dirs: dir_chain(parents, DIR_MODE)?,
                create_file: None,
                action: MountAction::Symlink {
                    parent: rel_cstring(parents)?,
                    leaf: cstring(leaf)?,
                    content: cstring(target)?,
                },
            },
            format!("symlink at {:?} to {:?}", symlink.path, symlink.target),
        );
        Ok(())
    }

    /// The host's `resolv.conf`, bound read-only over the rootfs's own.
    ///
    /// Resolving the host's `resolv.conf` can fail — it is commonly a symlink
    /// into a resolver's runtime directory, which need not exist — and a host
    /// without a usable one simply gets no bind.
    ///
    /// A bind needs its target to exist before anything can be mounted onto it,
    /// so a root shipping no `resolv.conf` gets an empty one created. That file
    /// would otherwise outlive the sandbox as a resolver configuration the root
    /// never had, which an export carries into whatever is made of the tree;
    /// [`created_file_targets`] picks it up from the finished op list, along
    /// with every other target the launch creates, and the caller side removes
    /// it once the sandbox is gone.
    fn push_resolv_conf(&mut self) -> Result<(), Error> {
        let Ok(source) = std::fs::canonicalize(RESOLV_CONF) else {
            return Ok(());
        };
        if !source.is_file() {
            return Ok(());
        }
        self.push(
            MountOp {
                dirs: dir_chain(&["etc"], DIR_MODE)?,
                create_file: Some(RESOLV_CONF_TARGET.to_owned()),
                action: MountAction::Bind {
                    source: cstring(source.as_os_str())?,
                    target: RESOLV_CONF_TARGET.to_owned(),
                    read_only: true,
                },
            },
            RESOLV_CONF.to_string(),
        );
        Ok(())
    }
}

/// Holds a host-rooted sandbox's ops to what that root allows: the launch
/// creates nothing in the host's tree.
///
/// Each op's target is placed by the latest op before it whose arrival covers
/// it, as the launch will find it. Inside a fresh filesystem of the sandbox's
/// own, a hidden directory or the managed `/tmp` for instance, the directories
/// and the file the target needs below that filesystem are created as on any
/// root, and those above it are already there. Anywhere else the target is in
/// the host's tree, or in a tree a mount brought, which is the host's too, so
/// nothing is created and the target must exist: it is looked up on the host,
/// through a bind's source where a bind brought the tree, and refused with
/// [`ConfigError::MountTargetMissing`] when it is not there. A symbolic link
/// there could only be made in the host's tree, so it is refused, with
/// [`ConfigError::SymlinkInHostRoot`], unless the same link already stands,
/// which the launch leaves as it is. A tree a raw
/// mount or a read-only path brought is not looked into; the launch fails at
/// the target if it is missing.
///
/// A hidden path and a read-only one create nothing. A hidden path is looked up
/// as a target is, and one missing there hides nothing at launch, so it covers
/// nothing beneath it here either: a target beneath it is the host's to hold.
fn settle_host_root_targets(ops: &mut [MountOp]) -> Result<(), Error> {
    // The ops that bring nothing to rest at launch: a hide of a missing path.
    let mut hides_nothing = vec![false; ops.len()];
    for at in 0..ops.len() {
        let target = match &ops[at].action {
            MountAction::ReadOnly { .. } => continue,
            MountAction::Symlink { parent, leaf, .. } => join_target(parent, leaf),
            MountAction::Hide { target }
            | MountAction::Tmpfs { target, .. }
            | MountAction::Procfs { target }
            | MountAction::Devpts { target, .. }
            | MountAction::Bind { target, .. }
            | MountAction::Raw { target, .. } => target.clone(),
        };
        let cover = ops[..at]
            .iter()
            .enumerate()
            .rev()
            .filter(|(index, _)| !hides_nothing[*index])
            .find_map(|(_, earlier)| {
                earlier
                    .action
                    .arrival()
                    .filter(|(over, _)| covers(over, &target))
                    .map(|(over, arrival)| (over.to_owned(), arrival, &earlier.action))
            });
        let host_path = match &cover {
            Some((over, Arrival::Fresh, _)) => {
                let beneath = |path: &CStr| path != over.as_c_str() && covers(over, path);
                let op = &mut ops[at];
                op.dirs
                    .retain(|dir| beneath(&join_target(&dir.parent, &dir.leaf)));
                if op.create_file.as_deref().is_some_and(|file| !beneath(file)) {
                    op.create_file = None;
                }
                continue;
            }
            Some((over, Arrival::Tree, MountAction::Bind { source, .. })) => {
                let rest = &target.as_bytes()[over.as_bytes().len()..];
                let mut path = source.as_bytes().to_vec();
                path.extend_from_slice(rest);
                Some(PathBuf::from(OsString::from_vec(path)))
            }
            Some((_, Arrival::Tree, _)) => None,
            None => Some(sandbox_path(&target)),
        };
        // A hide follows a link at its path, as the launch's lookup does, and
        // what is not found hides nothing. Anything else found, or a lookup
        // that fails otherwise, is left for the launch to hide or fail on.
        if let MountAction::Hide { .. } = ops[at].action {
            hides_nothing[at] = host_path.is_some_and(|path| {
                std::fs::metadata(path).is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound)
            });
            continue;
        }
        let op = &mut ops[at];
        op.dirs.clear();
        op.create_file = None;
        let Some(host_path) = host_path else {
            continue;
        };
        let named = sandbox_path(&target);
        match &op.action {
            MountAction::Symlink { content, .. } => {
                let standing = std::fs::read_link(&host_path)
                    .is_ok_and(|link| link.as_os_str().as_bytes() == content.as_bytes());
                if !standing {
                    return Err(ConfigError::SymlinkInHostRoot {
                        path: named,
                        target: PathBuf::from(OsStr::from_bytes(content.as_bytes())),
                    }
                    .into());
                }
            }
            _ => {
                std::fs::metadata(&host_path).map_err(|source| {
                    ConfigError::MountTargetMissing {
                        target: named,
                        source,
                    }
                })?;
            }
        }
    }
    Ok(())
}

/// The root-relative path an entry `leaf` in the root-relative directory
/// `parent` has, the empty `parent` being the root itself.
fn join_target(parent: &CStr, leaf: &CStr) -> CString {
    let mut path = parent.to_bytes().to_vec();
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(leaf.to_bytes());
    CString::new(path).expect("two C strings joined hold no NUL")
}

/// The host directories a sandbox's root is made of, as far as the mount
/// targets the launch creates are concerned.
enum RootLayers<'a> {
    /// A plain root filesystem: the launch's writes land in it, and an entry is
    /// present when the root filesystem holds one.
    Plain(&'a Path),
    /// An overlay root: the launch's writes land in the upper, and an entry is
    /// present when the merged view of the layers shows one.
    Overlay {
        /// The upper layer.
        upper: &'a Path,
        /// The lower layers, base first.
        lower: &'a [PathBuf],
    },
}

/// The host paths of the mount targets `ops` has to create as empty files.
///
/// A file bind needs its target to exist, so the launch creates one where the
/// root ships none — the managed `/etc/resolv.conf` bind of host networking,
/// and any file bind a caller configures. That file is the sandbox's own
/// contribution, not part of the root, so it is reported here for the caller
/// side to remove once the sandbox is gone.
///
/// Two targets are deliberately left out, because neither is a file in the root
/// at a path this can name:
///
/// - one already present in the root, which the root ships and the launch
///   therefore does not create. Presence is any entry at the path, a symbolic
///   link included: the launch creates the target with `O_EXCL`, so an entry of
///   any kind is one it leaves alone. For an overlay root, presence is what the
///   merged view shows; see [`merged_presence`];
/// - one under the target of an earlier op, which is created inside that mount
///   — a tmpfs that vanishes with the namespace, or a caller's own bind source
///   — rather than in the root directory on the host. A hide mounts nothing
///   over a path with nothing at it, so a hidden path counts only where the
///   root holds an entry there when this asks. A root that changes between
///   the build and the launch can make that answer wrong either way, and
///   neither way removes what the launch did not create: a target counted as
///   covered is not removed, and one counted as the root's is removed only
///   where the name still holds the file the launch reported creating.
///
/// Directories the launch creates are not placeholders: a mount point directory
/// is part of what a launch contributes to a tree, created at the mode of the
/// directory it stands for, and is left in place.
fn created_file_targets(ops: &[MountOp], root: &RootLayers<'_>) -> ManagedPlaceholders {
    // One descriptor per layer, in the order the merged view consults them:
    // the upper, then the lowers from the last stacked down to the base. A
    // layer that cannot be opened at all is a lookup that reaches no verdict.
    let (writable, layers): (&Path, Vec<Option<Rooted>>) = match root {
        RootLayers::Plain(rootfs) => (rootfs, vec![Rooted::open(rootfs).ok()]),
        RootLayers::Overlay { upper, lower } => (
            upper,
            std::iter::once(*upper)
                .chain(lower.iter().rev().map(PathBuf::as_path))
                .map(|layer| Rooted::open(layer).ok())
                .collect(),
        ),
    };
    let overlay = matches!(root, RootLayers::Overlay { .. });

    let presence = |path: &CStr| {
        let relative = Path::new(OsStr::from_bytes(path.to_bytes()));
        if overlay {
            merged_presence(&layers, relative)
        } else {
            layer_presence(layers[0].as_ref(), relative)
        }
    };

    let mut mounted: Vec<&CStr> = Vec::new();
    let mut paths = Vec::new();
    let mut whiteouts = Vec::new();
    for op in ops {
        if let Some(file) = &op.create_file {
            let relative = Path::new(OsStr::from_bytes(file.to_bytes()));
            if !mounted.iter().any(|mount| covers(mount, file)) {
                match presence(file) {
                    Presence::Absent => paths.push(relative.to_path_buf()),
                    Presence::WhitedOut => {
                        paths.push(relative.to_path_buf());
                        whiteouts.push(relative.to_path_buf());
                    }
                    Presence::Present | Presence::Unknown => {}
                }
            }
        }
        if let Some((target, _)) = op.action.arrival() {
            // A hide in the root itself, of a path the root holds nothing at,
            // brings nothing to rest. One beneath an earlier mount is covered
            // by that mount whatever it brings.
            let hides_nothing = matches!(op.action, MountAction::Hide { .. })
                && !mounted.iter().any(|mount| covers(mount, target))
                && matches!(presence(target), Presence::Absent | Presence::WhitedOut);
            if !hides_nothing {
                mounted.push(target);
            }
        }
    }
    ManagedPlaceholders {
        root: if paths.is_empty() {
            PathBuf::new()
        } else {
            writable.to_path_buf()
        },
        paths,
        whiteouts,
    }
}

/// What a lookup in the root found at a mount target's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    /// Nothing is at the path.
    Absent,
    /// Nothing is at the path in the merged view, because the overlay's upper
    /// holds a whiteout there: creating the target replaces the whiteout.
    WhitedOut,
    /// An entry of some kind is at the path.
    Present,
    /// The lookup could not reach a verdict — a permission refusal, an
    /// unreadable layer. Treated as [`Present`](Self::Present): what the answer
    /// decides is whether the launch created an entry that this side may later
    /// unlink, and "not sure" must not become "mine to remove".
    Unknown,
}

/// Whether `relative` names an entry inside the tree `layer` holds.
///
/// Resolved through [`Rooted`], the containment every host-side operation on a
/// tree takes: `openat2` with `RESOLVE_IN_ROOT`, as the sandbox stage resolves
/// every mount target against the new-root descriptor. An absolute symbolic link
/// inside the tree — `./etc -> /etc` in an untrusted unpacked tarball, or the
/// `/etc/resolv.conf -> /run/systemd/resolve/…` any image taken from a resolved
/// host ships — therefore resolves *within the tree* rather than against the
/// host's own root. Joining the two paths and asking the host instead would
/// answer a question about the host's filesystem, and would let a later removal
/// keyed to the same path land outside the tree entirely.
///
/// The leaf is not followed, so an entry is an entry whatever its kind: the
/// launch creates its target with `O_EXCL` and leaves anything already there
/// alone, dangling symbolic link included.
fn layer_presence(layer: Option<&Rooted>, relative: &Path) -> Presence {
    match layer.map(|layer| layer.stat(relative)) {
        Some(Ok(Some(_))) => Presence::Present,
        Some(Ok(None)) => Presence::Absent,
        Some(Err(_)) | None => Presence::Unknown,
    }
}

/// Whether the merged view of an overlay shows an entry at `relative`.
///
/// `layers` is in the order overlayfs consults them: the upper, then the lowers
/// from the last stacked down to the base. The first layer holding an entry at
/// the path decides. A whiteout there, a character device numbered 0:0, hides
/// the name from every layer below; anything else is the entry the merged view
/// shows. A layer holding nothing at the path passes the question down, unless
/// it hides the directory the path lies in: a whiteout or another non-directory
/// at an ancestor, or an ancestor directory marked opaque, behind which the
/// layers below do not show.
///
/// Each layer is read on its own, with symbolic links resolved inside it, where
/// the merged view resolves a link across layers. An ancestor that is a link
/// therefore passes the question down rather than deciding it, which is right
/// for the links a provisioned root carries, such as a merged-usr `bin`, since
/// every layer that has one has the same one.
fn merged_presence(layers: &[Option<Rooted>], relative: &Path) -> Presence {
    let ancestors: Vec<&Path> = relative
        .ancestors()
        .skip(1)
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect();
    for (depth, layer) in layers.iter().enumerate() {
        let Some(layer) = layer else {
            return Presence::Unknown;
        };
        match layer.stat(relative) {
            Ok(Some(stat)) if Rooted::is_whiteout(&stat) => {
                return if depth == 0 {
                    Presence::WhitedOut
                } else {
                    Presence::Absent
                };
            }
            Ok(Some(_)) => return Presence::Present,
            Ok(None) => {}
            Err(_) => return Presence::Unknown,
        }
        // Outermost ancestor first, as the kernel walks the path.
        for ancestor in ancestors.iter().rev() {
            let stat = match layer.stat(ancestor) {
                // Nothing here at or below this ancestor: the layers beneath
                // decide.
                Ok(None) => break,
                Ok(Some(stat)) => stat,
                Err(_) => return Presence::Unknown,
            };
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => match layer.is_opaque(ancestor) {
                    Ok(true) => return Presence::Absent,
                    Ok(false) => {}
                    Err(_) => return Presence::Unknown,
                },
                FileType::Symlink => break,
                // A whiteout, or a file standing where a directory would have to
                // be: either way nothing below shows through here.
                _ => return Presence::Absent,
            }
        }
    }
    Presence::Absent
}

/// Splits an absolute sandbox path into its ordinary components.
///
/// The bare root is refused on top of what [`path::absolute_components`]
/// refuses: a mount target names something *inside* the rootfs, and the rootfs
/// itself is what the target would be established over.
/// Resolves a configured rootfs to the canonical directory a launch roots on,
/// and proves it can be opened as one, so a missing or unusable rootfs is a
/// typed configuration error at build rather than a launch failure.
///
/// The launch resolves the canonical path again inside the new mount
/// namespace, where a descriptor opened here could not anchor the mounts.
fn canonical_rootfs(rootfs: &Path) -> Result<PathBuf, Error> {
    let unusable = |source: std::io::Error| ConfigError::RootfsUnusable {
        path: rootfs.to_path_buf(),
        source,
    };
    let canonical = std::fs::canonicalize(rootfs).map_err(unusable)?;
    if canonical.parent().is_none() {
        return Err(ConfigError::RootfsIsHostRoot.into());
    }
    rustix::fs::open(
        &canonical,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| unusable(errno.into()))?;
    Ok(canonical)
}

fn sandbox_path_components(path: &Path) -> Result<Vec<&OsStr>, Error> {
    let invalid = || {
        Error::from(ConfigError::MountTargetInvalid {
            path: path.to_path_buf(),
        })
    };
    let components = path::absolute_components(path).map_err(|_| invalid())?;
    if components.is_empty() {
        return Err(invalid());
    }
    Ok(components)
}

/// A sandbox path as the launch freezes a mount target: root-relative, with no
/// leading slash, its components read through [`sandbox_path_components`].
fn sandbox_target(path: &Path) -> Result<CString, Error> {
    rel_cstring(&sandbox_path_components(path)?)
}

/// The absolute path inside the sandbox that a frozen root-relative target
/// names, the way [`sandbox_target`] reads it back: how an error or a record
/// names a target to a reader.
pub(crate) fn sandbox_path(target: &CStr) -> PathBuf {
    Path::new("/").join(OsStr::from_bytes(target.to_bytes()))
}

/// Builds the mount-target directory chain for a rootfs-relative path: one
/// [`MountDir`] per component, the first parent being the empty string, meaning
/// the rootfs itself.
///
/// The mount point itself — the last component — is created at `leaf_mode`,
/// the mode of the directory it stands for once the mount that covers it is
/// gone. Every ancestor created on the way to it is an ordinary directory.
fn dir_chain<S: AsRef<OsStr>>(
    components: &[S],
    leaf_mode: RawMode,
) -> Result<Vec<MountDir>, Error> {
    let mut chain = Vec::with_capacity(components.len());
    let mut parent: Vec<u8> = Vec::new();
    for (depth, component) in components.iter().enumerate() {
        chain.push(MountDir {
            parent: CString::new(parent.clone()).map_err(|err| embedded_nul(err.into_vec()))?,
            leaf: cstring(component.as_ref())?,
            // Only the mount point itself carries the profile's mode; an
            // ancestor created on the way to it is an ordinary directory.
            mode: if depth + 1 == components.len() {
                leaf_mode
            } else {
                DIR_MODE
            },
        });
        if !parent.is_empty() {
            parent.push(b'/');
        }
        parent.extend_from_slice(component.as_ref().as_bytes());
    }
    Ok(chain)
}

/// Joins rootfs-relative components with `/` into a `CString`.
fn rel_cstring<S: AsRef<OsStr>>(components: &[S]) -> Result<CString, Error> {
    let mut path: Vec<u8> = Vec::new();
    for component in components {
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(component.as_ref().as_bytes());
    }
    Ok(CString::new(path).map_err(|err| embedded_nul(err.into_vec()))?)
}

/// Converts an `OsStr` to a `CString`, rejecting interior NUL bytes.
pub(crate) fn cstring(value: &OsStr) -> Result<CString, ConfigError> {
    CString::new(value.as_bytes()).map_err(|err| embedded_nul(err.into_vec()))
}

/// The refusal of a configured value that holds a NUL, naming the value.
fn embedded_nul(value: Vec<u8>) -> ConfigError {
    ConfigError::EmbeddedNul {
        value: OsString::from_vec(value),
    }
}

/// Validates the configured resource limits and lowers them into the plan's
/// frozen form, paired with the labels that name each in a setup error.
///
/// The map's iteration order is the resource's own, so the applied order does
/// not depend on the order the caller configured them in.
pub(crate) fn lower_rlimits(
    rlimits: &BTreeMap<Resource, (Limit, Limit)>,
) -> Result<(Vec<RlimitPlan>, Vec<String>), Error> {
    let mut plans = Vec::with_capacity(rlimits.len());
    let mut labels = Vec::with_capacity(rlimits.len());
    for (resource, (soft, hard)) in rlimits {
        if !soft.fits_within(*hard) {
            return Err(ConfigError::RlimitInvalid {
                resource: *resource,
                soft: *soft,
                hard: *hard,
            }
            .into());
        }
        plans.push(RlimitPlan {
            resource: *resource,
            kernel: resource.to_kernel(),
            limit: rustix::process::Rlimit {
                current: soft.amount(),
                maximum: hard.amount(),
            },
        });
        labels.push(format!("{resource} soft {soft}, hard {hard}"));
    }
    Ok((plans, labels))
}

/// The label a failed exec step reports as its subject.
///
/// For an ordinary command it is the path that was executed. For a path lookup
/// it is the bare name followed by every candidate the search tried, since the
/// reported errno is the search's verdict rather than any one candidate's.
///
/// Each is named with `{:?}`, as every configured path a setup error names is:
/// a profile nothing vouches for can supply the command and the `PATH` the
/// candidates come from.
pub(crate) fn exec_label(command: &Path, search: &[CString]) -> String {
    if search.is_empty() {
        return format!("{command:?}");
    }
    let candidates: Vec<String> = search
        .iter()
        .map(|candidate| format!("{:?}", Path::new(OsStr::from_bytes(candidate.as_bytes()))))
        .collect();
    format!("{command:?}, searched {}", candidates.join(", "))
}

/// A command validated for execution.
pub(crate) struct ValidCommand {
    /// The command as it was configured, for the label a failed exec reports.
    pub(crate) path: PathBuf,
    /// The command as `execve` is handed it, and as `argv[0]`.
    pub(crate) program: CString,
    /// Whether the command is a bare name, resolved against the sandbox's
    /// `PATH` rather than executed as a path.
    pub(crate) searched: bool,
}

/// Validates the command a builder was given: present, not empty, holding no
/// NUL, and either an absolute path or a bare name that `path_lookup` resolves.
///
/// [`CageBuilder::build`] and `RestrictionBuilder::build` both read their
/// command through this, so the two accept the same commands. `path_lookup` is
/// the builder's setting, or `None` for a builder that has none: a restriction
/// never searches the host's `PATH`, and its refusal of a bare name says so
/// rather than offering a lookup it cannot do.
///
/// An empty path is the absence of a command written down, and every later
/// check reads it as something else: it carries no slash, so a path lookup takes
/// it for a bare name to search, and joining it onto a `PATH` entry yields that
/// entry. What would survive is an `execve` of a directory at launch, reported
/// as a failure of the sandbox rather than of the configuration.
///
/// A bare name is one ordinary path component, as
/// [`path::is_ordinary_component`] defines it. `.` and `..` carry no slash and
/// are still not names: joined onto a `PATH` entry, each names a directory,
/// which `execve` refuses only at launch. They are relative paths, and are
/// refused as one whether path lookup is on or not.
pub(crate) fn validate_command(
    command: Option<PathBuf>,
    path_lookup: Option<bool>,
) -> Result<ValidCommand, Error> {
    let command = command.ok_or(ConfigError::CommandMissing)?;
    if command.as_os_str().is_empty() {
        return Err(ConfigError::CommandMissing.into());
    }
    let program = cstring(command.as_os_str())?;
    // The execvp rule plus the absolute-path requirement: a bare name is
    // resolved against `PATH` only when path lookup is opted into, and anything
    // else must be absolute. A relative path is never searched.
    let searched = path_lookup == Some(true) && is_command_name(&command);
    if !command.is_absolute() && !searched {
        return Err(ConfigError::CommandNotAbsolute {
            command,
            lookup_offered: path_lookup.is_some(),
        }
        .into());
    }
    Ok(ValidCommand {
        path: command,
        program,
        searched,
    })
}

/// Whether a command is a bare name, which path lookup resolves against `PATH`,
/// rather than a path naming a location.
pub(crate) fn is_command_name(command: &Path) -> bool {
    path::is_ordinary_component(command.as_os_str().as_bytes())
}

/// The `PATH` a path-lookup command is resolved against: the last `PATH` the
/// caller set through [`CageBuilder::env`], or the deterministic
/// [`BASE_PATH`] when none is set and the base environment is in force. It
/// mirrors the value the command's own environment will carry, so lookup and
/// the running command agree on `PATH`.
///
/// With the base environment opted out of and no `PATH` of the caller's own,
/// the command will run with no `PATH` at all, so there is genuinely nothing
/// to search. Returning empty here rather than the base is what makes
/// [`CageBuilder::build`] report that, instead of resolving the command
/// against a `PATH` the command will never see.
fn effective_path(env: &[(OsString, OsString)], base_env: bool) -> OsString {
    env.iter()
        .rev()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| {
            if base_env {
                OsString::from(BASE_PATH)
            } else {
                OsString::new()
            }
        })
}

/// The candidate absolute paths a bare `command` resolves to: one per absolute
/// directory in `path`, in order. Empty and relative `PATH` entries are
/// skipped rather than resolved against the working directory, so lookup never
/// depends on the sandbox's current directory. The candidates are executed in
/// order by the command stage.
///
/// The list may come back empty, when `path` holds no absolute entry at all;
/// [`CageBuilder::build`] turns that into a configuration error rather than
/// letting the command stage fall back to the bare name.
fn search_candidates(path: &OsStr, command: &Path) -> Result<Vec<CString>, ConfigError> {
    path.as_bytes()
        .split(|byte| *byte == b':')
        .filter_map(|entry| {
            let dir = Path::new(OsStr::from_bytes(entry));
            dir.is_absolute()
                .then(|| cstring(dir.join(command).as_os_str()))
        })
        .collect()
}

/// Serde adapters for the `OsString`-typed builder fields.
///
/// Profiles are text files, so these fields serialize through `String`: a
/// non-UTF-8 value is a serialization error, and the programmatic builder
/// API keeps its full `OsStr` capability.
#[cfg(feature = "serde")]
pub(crate) mod serde_os {
    /// `Vec<OsString>` as a sequence of strings.
    pub(super) mod string_vec {
        use std::ffi::OsString;

        use serde::ser::Error as _;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub(crate) fn serialize<S: Serializer>(
            values: &[OsString],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let strings = values
                .iter()
                .map(|value| {
                    value
                        .to_str()
                        .ok_or_else(|| S::Error::custom("a non-UTF-8 value cannot be serialized"))
                })
                .collect::<Result<Vec<&str>, _>>()?;
            strings.serialize(serializer)
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<OsString>, D::Error> {
            Ok(Vec::<String>::deserialize(deserializer)?
                .into_iter()
                .map(OsString::from)
                .collect())
        }
    }

    /// `OsString` as a string, for a record that only serializes.
    // `pub(crate)` for the resolved-inputs record, whose hostname is one.
    pub(crate) mod string {
        use std::ffi::OsStr;

        use serde::ser::Error as _;
        use serde::{Serialize, Serializer};

        pub(crate) fn serialize<S: Serializer>(
            value: &OsStr,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            value
                .to_str()
                .ok_or_else(|| S::Error::custom("a non-UTF-8 value cannot be serialized"))?
                .serialize(serializer)
        }
    }

    /// `Option<OsString>` as an optional string.
    pub(super) mod string_opt {
        use std::ffi::OsString;

        use serde::ser::Error as _;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub(crate) fn serialize<S: Serializer>(
            value: &Option<OsString>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(value) => value
                    .to_str()
                    .ok_or_else(|| S::Error::custom("a non-UTF-8 value cannot be serialized"))?
                    .serialize(serializer),
                None => serializer.serialize_none(),
            }
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<OsString>, D::Error> {
            Ok(Option::<String>::deserialize(deserializer)?.map(OsString::from))
        }
    }

    /// Environment pairs as a name-to-value map.
    ///
    /// Serialization folds the pairs through a map, so a later duplicate
    /// overrides an earlier one — the same override the builder applies.
    // `pub(crate)` rather than `pub(super)`: the resolved-inputs record
    // serializes its environment through this same adapter, so the two agree
    // on how an environment appears in text.
    pub(crate) mod string_map {
        use std::collections::BTreeMap;
        use std::ffi::OsString;

        use serde::ser::Error as _;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub(crate) fn serialize<S: Serializer>(
            pairs: &[(OsString, OsString)],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let mut map = BTreeMap::new();
            for (name, value) in pairs {
                let name = name
                    .to_str()
                    .ok_or_else(|| S::Error::custom("a non-UTF-8 name cannot be serialized"))?;
                let value = value
                    .to_str()
                    .ok_or_else(|| S::Error::custom("a non-UTF-8 value cannot be serialized"))?;
                map.insert(name, value);
            }
            map.serialize(serializer)
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<(OsString, OsString)>, D::Error> {
            Ok(BTreeMap::<String, String>::deserialize(deserializer)?
                .into_iter()
                .map(|(name, value)| (OsString::from(name), OsString::from(value)))
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    fn sh_in(rootfs: &str) -> CageBuilder {
        Cage::builder().rootfs(rootfs).command("/bin/sh")
    }

    #[test]
    fn build_requires_a_rootfs() {
        let err = Cage::builder().command("/bin/sh").build().unwrap_err();
        assert!(matches!(err, Error::Config(ConfigError::RootfsMissing)));
    }

    #[test]
    fn build_requires_a_command() {
        let err = Cage::builder().rootfs("/").build().unwrap_err();
        assert!(matches!(err, Error::Config(ConfigError::CommandMissing)));
    }

    #[test]
    fn build_rejects_a_relative_command() {
        let err = sh_in("/tmp").command("bin/sh").build().unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::CommandNotAbsolute { .. })
        ));
    }

    #[test]
    fn build_rejects_a_bare_command_without_path_lookup() {
        // A slash-free command is not resolved against PATH unless the caller
        // opts in; by default it is the same absolute-path error as any other
        // non-absolute command.
        let err = sh_in("/tmp").command("sh").build().unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::CommandNotAbsolute { .. })
        ));
    }

    #[test]
    fn path_lookup_resolves_a_bare_command_against_the_base_path() {
        // With path lookup on, a bare name builds: argv[0] stays the name and
        // the search list carries one candidate per absolute PATH directory.
        let cage = sh_in("/tmp")
            .command("sh")
            .path_lookup(true)
            .build()
            .expect("a bare command builds under path lookup");
        assert_eq!(cage.plan.program, CString::new("sh").unwrap());
        assert_eq!(
            cage.plan.program_search,
            [
                "/usr/local/sbin/sh",
                "/usr/local/bin/sh",
                "/usr/sbin/sh",
                "/usr/bin/sh",
                "/sbin/sh",
                "/bin/sh",
            ]
            .map(|path| CString::new(path).unwrap()),
        );
    }

    #[test]
    fn path_lookup_still_rejects_a_relative_path_with_a_slash() {
        // Path lookup resolves bare names only; a relative path that names a
        // location is never searched and stays an absolute-path error.
        let err = sh_in("/tmp")
            .command("bin/sh")
            .path_lookup(true)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::CommandNotAbsolute { .. })
        ));
    }

    #[test]
    fn path_lookup_leaves_an_absolute_command_unsearched() {
        // An absolute command is executed directly even under path lookup: no
        // search list, so the exact path is what runs.
        let cage = sh_in("/tmp")
            .command("/bin/sh")
            .path_lookup(true)
            .build()
            .expect("an absolute command builds");
        assert!(cage.plan.program_search.is_empty());
    }

    #[test]
    fn path_lookup_follows_a_caller_set_path() {
        // The search uses the command's effective PATH, so a PATH the caller
        // set through env drives resolution, and relative or empty entries are
        // skipped rather than resolved against the working directory.
        let cage = sh_in("/tmp")
            .command("make")
            .path_lookup(true)
            .env("PATH", "/opt/bin::relative:/usr/bin")
            .build()
            .expect("a bare command builds under a caller PATH");
        assert_eq!(
            cage.plan.program_search,
            ["/opt/bin/make", "/usr/bin/make"].map(|path| CString::new(path).unwrap()),
        );
    }

    #[test]
    fn path_lookup_rejects_a_path_with_nothing_to_search() {
        // Skipping every entry leaves no candidate. Executing the bare name
        // instead would resolve it against the sandbox's working directory,
        // which is exactly what path lookup is defined not to do.
        let err = sh_in("/tmp")
            .command("make")
            .path_lookup(true)
            .env("PATH", "relative:")
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::SearchPathUnusable { path }) => {
                assert_eq!(path, OsStr::new("relative:"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn an_empty_command_names_no_command_at_all() {
        // Every check below reads an empty path as something else: it carries
        // no slash, so a path lookup takes it for a bare name, and joining it
        // onto a `PATH` entry yields that entry -- so the search finds a list of
        // directories and refuses nothing, deferring an `execve` of a directory
        // to launch. It is the absence of a command, and is reported as one.
        for builder in [
            sh_in("/tmp").command("").path_lookup(true),
            sh_in("/tmp").command(""),
        ] {
            assert!(
                matches!(
                    builder.build().unwrap_err(),
                    Error::Config(ConfigError::CommandMissing),
                ),
                "an empty command must not build",
            );
        }
    }

    #[test]
    fn a_dot_or_dot_dot_command_is_a_relative_path_rather_than_a_name() {
        // Neither carries a slash, and neither is a name: searched, each joins
        // onto a `PATH` entry as that directory or its parent, and `execve`
        // refuses a directory only at launch. Both are refused here as the
        // relative paths they are, and the refusal does not suggest the path
        // lookup that would not help.
        for command in [".", ".."] {
            for lookup in [true, false] {
                let err = sh_in("/tmp")
                    .command(command)
                    .path_lookup(lookup)
                    .build()
                    .unwrap_err();
                let message = crate::failure::ErrorChain::new(&err).to_string();
                assert!(
                    !message.contains("path lookup"),
                    "{command} under path_lookup({lookup}): {message}",
                );
                match err {
                    Error::Config(ConfigError::CommandNotAbsolute {
                        command: refused,
                        lookup_offered: true,
                    }) => {
                        assert_eq!(refused, Path::new(command));
                    }
                    other => panic!("{command} under path_lookup({lookup}): {other}"),
                }
            }
        }
    }

    #[test]
    fn path_lookup_without_a_base_or_a_path_has_nothing_to_search() {
        // The base is where `PATH` would otherwise come from. Opting out of it
        // and setting none leaves the command with no `PATH` at all, so the
        // lookup is reported rather than resolved against the base the command
        // will not carry.
        let err = sh_in("/tmp")
            .command("make")
            .path_lookup(true)
            .base_env(false)
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::SearchPathUnusable { path }) => {
                assert_eq!(path, OsStr::new(""));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn path_lookup_without_a_base_uses_the_callers_own_path() {
        // The caller's `PATH` is the command's `PATH`, so the lookup resolves
        // against exactly what the command will see.
        let cage = sh_in("/tmp")
            .command("sh")
            .path_lookup(true)
            .base_env(false)
            .env("PATH", "/sbin")
            .build()
            .unwrap();
        assert_eq!(cage.plan.program_search, [c"/sbin/sh".to_owned()]);
        assert_eq!(cage.plan.env, [c"PATH=/sbin".to_owned()]);
    }

    #[test]
    fn an_exact_environment_composes_no_base_underneath() {
        let cage = sh_in("/tmp").base_env(false).env("A", "b").build().unwrap();
        assert_eq!(cage.plan.env, [c"A=b".to_owned()]);
    }

    #[test]
    fn opting_out_of_the_managed_mounts_establishes_none_of_them() {
        // The caller's own procfs is all the plan carries: none of the managed
        // profile's mounts survive the opt-out, and the one the nested user
        // namespace's map needs is the caller's to declare.
        let cage = sh_in("/tmp")
            .managed_mounts(false)
            .bind("/proc", "/proc")
            .build()
            .unwrap();
        assert_eq!(
            cage.plan.op_labels.len(),
            1,
            "expected only the caller's own mount, got {:?}",
            cage.plan.op_labels,
        );
    }

    #[test]
    fn opting_out_while_asking_for_a_managed_mount_is_refused() {
        // The two cannot both be honored, and silently dropping either would
        // hand back a sandbox that differs from the one described.
        let err = sh_in("/tmp")
            .managed_mounts(false)
            .mount_dev(true)
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::ManagedMountsContradiction { toggle }) => {
                assert_eq!(toggle, "mount_dev");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn opting_out_alongside_an_explicit_off_toggle_is_not_a_contradiction() {
        // Both say the same thing, so there is nothing to refuse.
        let cage = sh_in("/tmp")
            .managed_mounts(false)
            .mount_dev(false)
            .bind("/proc", "/proc")
            .build()
            .unwrap();
        assert_eq!(cage.plan.op_labels.len(), 1);
    }

    #[test]
    fn build_rejects_a_nul_byte_in_an_argument() {
        let err = sh_in("/tmp")
            .arg(OsStr::from_bytes(b"with\0nul"))
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::EmbeddedNul { value }) => {
                assert_eq!(value, OsStr::from_bytes(b"with\0nul"), "the value is named");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_nul_byte_is_reported_against_what_carries_it() {
        // In a variable's name it is the name that is invalid, and it is
        // reported as one, beside an empty name and one holding `=`.
        let err = sh_in("/tmp")
            .env(OsStr::from_bytes(b"NA\0ME"), "value")
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::EnvNameInvalid { name }) => {
                assert_eq!(name, OsStr::from_bytes(b"NA\0ME"));
            }
            other => panic!("unexpected error: {other}"),
        }
        // In its value, the value is named.
        let err = sh_in("/tmp")
            .env("NAME", OsStr::from_bytes(b"val\0ue"))
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::EmbeddedNul { value }) => {
                assert_eq!(value, OsStr::from_bytes(b"val\0ue"));
            }
            other => panic!("unexpected error: {other}"),
        }
        // In a hostname, the hostname is what is invalid.
        let err = sh_in("/tmp")
            .hostname(OsStr::from_bytes(b"host\0name"))
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::HostnameInvalid { name }) => {
                assert_eq!(name, OsStr::from_bytes(b"host\0name"));
            }
            other => panic!("unexpected error: {other}"),
        }
        // In the command, the command is named.
        let err = Cage::builder()
            .rootfs("/tmp")
            .command(OsStr::from_bytes(b"/bin/s\0h"))
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::EmbeddedNul { value }) => {
                assert_eq!(value, OsStr::from_bytes(b"/bin/s\0h"));
            }
            other => panic!("unexpected error: {other}"),
        }
        // In the `PATH` a lookup searches, it is the value that is named, not
        // a candidate the search built from it.
        let err = sh_in("/tmp")
            .command("sh")
            .path_lookup(true)
            .env("PATH", OsStr::from_bytes(b"/usr/b\0in"))
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::EmbeddedNul { value }) => {
                assert_eq!(value, OsStr::from_bytes(b"/usr/b\0in"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn build_rejects_a_missing_rootfs_with_the_os_error() {
        let err = sh_in("/ferroday-cage/does/not/exist").build().unwrap_err();
        match err {
            Error::Config(ConfigError::RootfsUnusable { source, .. }) => {
                assert_eq!(source.raw_os_error(), Some(Errno::NOENT.raw_os_error()));
            }
            other => panic!("expected RootfsUnusable, got {other:?}"),
        }
    }

    #[test]
    fn build_rejects_a_rootfs_that_is_not_a_directory() {
        let err = sh_in("/dev/null").build().unwrap_err();
        match err {
            Error::Config(ConfigError::RootfsUnusable { source, .. }) => {
                assert_eq!(source.raw_os_error(), Some(Errno::NOTDIR.raw_os_error()));
            }
            other => panic!("expected RootfsUnusable, got {other:?}"),
        }
    }

    #[test]
    fn build_rejects_the_host_root_as_rootfs() {
        let err = sh_in("/").build().unwrap_err();
        assert!(matches!(err, Error::Config(ConfigError::RootfsIsHostRoot)));
    }

    #[test]
    fn build_accepts_a_real_directory() {
        let cage = sh_in("/tmp").arg("-c").arg("true").build().unwrap();
        // The plan pins the canonicalized rootfs; its debug form names the
        // frozen program.
        assert!(format!("{cage:?}").contains("/bin/sh"));
    }

    #[test]
    fn the_last_root_call_wins_among_all_three() {
        let empty = Cage::builder()
            .rootfs("/srv/rootfs")
            .overlay_rootfs("/srv/base", "/tmp/upper")
            .empty_rootfs();
        assert!(empty.get_empty_rootfs());
        assert!(empty.get_rootfs().is_none() && empty.get_overlay().is_none());

        let plain = empty.clone().rootfs("/srv/rootfs");
        assert!(!plain.get_empty_rootfs());
        let overlaid = empty.overlay_rootfs("/srv/base", "/tmp/upper");
        assert!(!overlaid.get_empty_rootfs());
    }

    #[test]
    fn an_empty_root_plans_no_placeholders() {
        // A file bind's target is created in the root, which for an empty
        // root is the sandbox's own and leaves nothing on the host to remove.
        let source = Scratch::new("empty-root-placeholders");
        std::fs::write(source.join("file"), b"").unwrap();
        let cage = Cage::builder()
            .empty_rootfs()
            .bind_ro(source.join("file"), "/etc/file")
            .command("/bin/sh")
            .build()
            .expect("a valid sandbox configuration");
        assert!(matches!(cage.plan.root, RootPlan::Empty));
        assert!(cage.plan.managed_placeholders.is_empty());
        assert!(cage.plan.ops.iter().any(|op| op.create_file.is_some()));
    }

    #[test]
    fn a_symlink_is_validated_at_build() {
        let build = |target: &OsStr, path: &str| {
            Cage::builder()
                .empty_rootfs()
                .symlink(target, path)
                .command("/bin/sh")
                .build()
        };
        let long = OsString::from("a".repeat(mechanism::bounds::LINK_BUF));
        for target in [OsStr::new(""), long.as_os_str()] {
            let err = build(target, "/bin").unwrap_err();
            assert!(
                matches!(err, Error::Config(ConfigError::SymlinkTargetInvalid { .. })),
                "{err}"
            );
        }
        for path in ["/", "bin", "/usr/../bin"] {
            let err = build(OsStr::new("usr/bin"), path).unwrap_err();
            assert!(
                matches!(err, Error::Config(ConfigError::MountTargetInvalid { .. })),
                "{path}: {err}"
            );
        }
        // The longest target a link can hold is accepted.
        let longest = OsString::from("a".repeat(mechanism::bounds::LINK_BUF - 1));
        build(&longest, "/bin").expect("a target one short of the buffer fits");
    }

    #[test]
    fn a_symlink_at_or_above_resolv_conf_claims_it() {
        let host = Cage::builder().rootfs("/tmp").network(Network::Host);
        assert!(host.get_resolv_conf());
        for path in ["/etc/resolv.conf", "/etc"] {
            let linked = host.clone().symlink("/run/resolver", path);
            assert!(!linked.get_resolv_conf(), "{path}");
        }
        assert!(host.symlink("/run/x", "/etc/hosts").get_resolv_conf());
    }

    #[test]
    fn a_built_cage_clones_its_frozen_plan() {
        let cage = sh_in("/tmp").arg("-c").arg("true").build().unwrap();
        let clone = cage.clone();
        // The clone is an independent copy carrying the same frozen program
        // and arguments; the original is untouched and both remain usable.
        assert_eq!(clone.plan.program, cage.plan.program);
        assert_eq!(clone.plan.args, cage.plan.args);
        assert!(matches!(
            (&clone.plan.root, &cage.plan.root),
            (RootPlan::Bind(cloned), RootPlan::Bind(original)) if cloned == original
        ));
    }

    #[test]
    fn clear_args_drops_prior_arguments_for_a_unit_override() {
        // The composition a profile-driven consumer performs: a builder that
        // already carries a command and arguments — as if deserialized from a
        // profile — has its command replaced as a unit. clear_args drops the
        // profile's arguments so the new command does not inherit them.
        let cage = sh_in("/tmp")
            .args(["-c", "profile default"])
            .clear_args()
            .command("/bin/echo")
            .arg("override")
            .build()
            .unwrap();
        assert!(format!("{cage:?}").contains("/bin/echo"));
        let args: Vec<&str> = cage
            .plan
            .args
            .iter()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        assert_eq!(args, ["override"]);
    }

    #[test]
    fn build_rejects_a_missing_bind_source() {
        let err = sh_in("/tmp")
            .bind("/ferroday-cage/no/such/source", "/data")
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::BindSourceUnusable { source, .. }) => {
                assert_eq!(source.raw_os_error(), Some(Errno::NOENT.raw_os_error()));
            }
            other => panic!("expected BindSourceUnusable, got {other:?}"),
        }
    }

    #[test]
    fn build_rejects_a_relative_bind_target() {
        let err = sh_in("/tmp").bind("/etc", "data").build().unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::MountTargetInvalid { .. })
        ));
    }

    #[test]
    fn build_rejects_the_root_as_bind_target() {
        let err = sh_in("/tmp").bind("/etc", "/").build().unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::MountTargetInvalid { .. })
        ));
    }

    #[test]
    fn build_rejects_dot_dot_in_a_bind_target() {
        let err = sh_in("/tmp")
            .bind("/etc", "/data/../escape")
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::MountTargetInvalid { .. })
        ));
    }

    #[test]
    fn build_rejects_a_relative_workdir() {
        let err = sh_in("/tmp").current_dir("srv").build().unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::WorkdirNotAbsolute { .. })
        ));
    }

    /// A working directory is a configured absolute path, held to the rule
    /// every other one is: plain components, with `.` and repeated slashes
    /// normalized away and a `..` refused.
    #[test]
    fn a_workdir_is_held_to_the_absolute_path_rule() {
        let err = sh_in("/tmp")
            .current_dir("/build/../etc")
            .build()
            .unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::WorkdirNotAbsolute { .. })),
            "{err}",
        );
        let workdir = |path: &str| {
            sh_in("/tmp")
                .current_dir(path)
                .build()
                .unwrap()
                .plan
                .workdir
        };
        assert_eq!(workdir("/build").as_deref(), Some(c"/build"));
        assert_eq!(workdir("/"), None);
        assert_eq!(workdir("/."), None, "the root, however it is spelled");
    }

    #[test]
    fn build_rejects_an_empty_hostname() {
        let err = sh_in("/tmp").hostname("").build().unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::HostnameInvalid { .. })
        ));
    }

    #[test]
    fn build_rejects_an_overlong_hostname() {
        let err = sh_in("/tmp").hostname("h".repeat(65)).build().unwrap_err();
        match err {
            Error::Config(ConfigError::HostnameInvalid { name }) => {
                assert_eq!(
                    name,
                    OsString::from("h".repeat(65)),
                    "the hostname is named"
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn build_rejects_an_env_name_with_equals() {
        let err = sh_in("/tmp").env("NAME=EXTRA", "v").build().unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::EnvNameInvalid { .. })
        ));
    }

    #[test]
    fn the_environment_is_the_base_plus_overrides_sorted() {
        let cage = sh_in("/tmp")
            .env("ZED", "last")
            .env("PATH", "/custom")
            .build()
            .unwrap();
        let env: Vec<&str> = cage
            .plan
            .env
            .iter()
            .map(|entry| entry.to_str().unwrap())
            .collect();
        assert_eq!(env, ["HOME=/root", "PATH=/custom", "ZED=last"]);
    }

    /// `HOME` follows the identity the command runs as: root's home for uid 0
    /// of the namespace, and none from the library for any other, which the
    /// caller's own `HOME` then supplies.
    #[test]
    fn home_follows_the_command_s_identity() {
        let env = |builder: CageBuilder| -> Vec<String> {
            builder
                .build()
                .unwrap()
                .plan
                .env
                .iter()
                .map(|entry| entry.to_str().unwrap().to_owned())
                .collect()
        };
        let path = format!("PATH={BASE_PATH}");
        assert_eq!(env(sh_in("/tmp")), ["HOME=/root", path.as_str()]);
        assert_eq!(
            env(sh_in("/tmp").run_as(Identity::new(0, 0))),
            ["HOME=/root", path.as_str()]
        );
        assert_eq!(
            env(sh_in("/tmp").present_as(PresentedIdentity::Ids {
                uid: 1000,
                gid: 1000
            })),
            [path.as_str()]
        );
        assert_eq!(
            env(sh_in("/tmp")
                .present_as(PresentedIdentity::Ids {
                    uid: 1000,
                    gid: 1000
                })
                .env("HOME", "/home/user")),
            ["HOME=/home/user", path.as_str()]
        );
        assert!(env(sh_in("/tmp").base_env(false)).is_empty());
    }

    #[test]
    fn the_default_profile_mounts_proc_dev_and_tmp() {
        let cage = sh_in("/tmp").build().unwrap();
        assert!(cage.plan.op_labels.contains(&"/proc".to_string()));
        assert!(cage.plan.op_labels.contains(&"/dev".to_string()));
        assert!(cage.plan.op_labels.contains(&"/tmp".to_string()));
        // Isolated network: no resolv.conf bind.
        assert!(
            !cage
                .plan
                .op_labels
                .contains(&"/etc/resolv.conf".to_string())
        );
        assert!(cage.plan.configure_loopback);
    }

    #[test]
    fn the_default_plan_isolates_pids_and_mounts_a_fresh_proc() {
        let cage = sh_in("/tmp").build().unwrap();
        assert!(cage.plan.pid_namespace);
        assert!(cage.plan.unshare.contains(UnshareFlags::NEWPID));
        assert!(matches!(cage.plan.stdin, StdioPlan::Inherit));
        assert!(!cage.plan.stop_with_caller);
        let proc_op = &cage.plan.ops[cage
            .plan
            .op_labels
            .iter()
            .position(|label| label == "/proc")
            .unwrap()];
        assert!(matches!(proc_op.action, MountAction::Procfs { .. }));
    }

    #[test]
    fn without_a_pid_namespace_proc_is_a_bind_of_the_host_procfs() {
        let cage = sh_in("/tmp").pid_namespace(false).build().unwrap();
        assert!(!cage.plan.pid_namespace);
        assert!(!cage.plan.unshare.contains(UnshareFlags::NEWPID));
        let proc_op = &cage.plan.ops[cage
            .plan
            .op_labels
            .iter()
            .position(|label| label == "/proc")
            .unwrap()];
        assert!(matches!(proc_op.action, MountAction::Bind { .. }));
    }

    #[test]
    fn stdin_and_lifetime_options_reach_the_plan() {
        let cage = sh_in("/tmp")
            .stdin(Stdio::Null)
            .stop_with_caller(true)
            .build()
            .unwrap();
        assert!(matches!(cage.plan.stdin, StdioPlan::Null));
        assert!(cage.plan.stop_with_caller);
    }

    #[test]
    fn each_stream_lowers_into_its_own_plan_field() {
        // Three independent dispositions, so a sandbox that discards its
        // standard error keeps whatever the other two were set to.
        let cage = sh_in("/tmp")
            .stdin(Stdio::from_fd(open_null()))
            .stderr(Stdio::Null)
            .build()
            .unwrap();
        assert!(matches!(cage.plan.stdin, StdioPlan::Fd(_)));
        assert!(matches!(cage.plan.stdout, StdioPlan::Inherit));
        assert!(matches!(cage.plan.stderr, StdioPlan::Null));
    }

    #[test]
    fn the_session_follows_standard_input_alone() {
        // The output pair is closed by its own disposition, not by the session,
        // so directing it elsewhere must not start one: a command that still
        // inherits standard input is still in the caller's session, where its
        // job control lives.
        let cage = sh_in("/tmp")
            .stdout(Stdio::Null)
            .stderr(Stdio::Null)
            .build()
            .unwrap();
        assert!(!cage.plan.own_session);

        let cage = sh_in("/tmp").stdin(Stdio::Null).build().unwrap();
        assert!(cage.plan.own_session);
    }

    #[test]
    fn a_capturing_launch_is_refused_against_a_directed_output_stream() {
        // Capture supplies a pipe, which is a destination; a plan naming one of
        // its own means the caller asked for two different things. Refused at
        // the launch rather than at build, because the same sandbox launches
        // without contradiction through an entry point that captures nothing —
        // and refused before anything is forked, which is what lets this assert
        // it without a rootfs to launch into.
        for builder in [
            sh_in("/tmp").stdout(Stdio::Null),
            sh_in("/tmp").stderr(Stdio::from_fd(open_null())),
        ] {
            let cage = builder.build().expect("the sandbox itself is valid");
            let err = cage.output().unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::Config(ConfigError::StreamAttachmentConflict { .. })
                ),
                "{err:?}",
            );
        }
    }

    #[test]
    fn a_capturing_launch_is_indifferent_to_standard_input() {
        // Capture never touches standard input, so no disposition of it
        // contradicts a capturing launch. The launch below gets as far as
        // trying to build a sandbox over `/tmp`, which is exactly the point:
        // whatever it fails with, it is not the stream refusal.
        let cage = sh_in("/tmp")
            .stdin(Stdio::from_fd(open_null()))
            .build()
            .unwrap();
        assert!(!matches!(
            cage.output(),
            Err(Error::Config(ConfigError::StreamAttachmentConflict { .. })),
        ));
    }

    /// An owned descriptor for `/dev/null`, for the descriptor disposition.
    fn open_null() -> OwnedFd {
        std::fs::File::open("/dev/null")
            .expect("/dev/null is openable")
            .into()
    }

    #[test]
    fn a_raw_mount_lowers_with_its_flags_in_declaration_order() {
        // Declared before the bind, so it is applied before the bind. The two
        // kinds share one sequence precisely so this is expressible.
        let cage = sh_in("/tmp")
            .raw_mount(
                RawMount::new("/raw")
                    .source("none")
                    .fstype("tmpfs")
                    .flags(0x6) // MS_NOSUID | MS_NODEV
                    .data("mode=0777"),
            )
            .bind("/etc", "/host-etc")
            .build()
            .unwrap();
        let raw_index = cage
            .plan
            .op_labels
            .iter()
            .position(|label| label == "raw mount at \"/raw\"")
            .unwrap();
        let bind_index = cage
            .plan
            .op_labels
            .iter()
            .position(|label| label.contains("/host-etc"))
            .unwrap();
        assert!(
            raw_index < bind_index,
            "the declared order is the applied order"
        );
        match &cage.plan.ops[raw_index].action {
            MountAction::Raw {
                source,
                fstype,
                flags,
                data,
                ..
            } => {
                assert_eq!(source.to_str().unwrap(), "none");
                assert_eq!(fstype.to_str().unwrap(), "tmpfs");
                assert_eq!(flags.bits(), 0x6);
                assert_eq!(data.to_str().unwrap(), "mode=0777");
            }
            other => panic!("expected a raw mount action, got {other:?}"),
        }
    }

    #[test]
    fn a_raw_mount_target_is_validated_like_a_bind_target() {
        let err = sh_in("/tmp")
            .raw_mount(RawMount::new("relative"))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::MountTargetInvalid { .. })
        ));
    }

    #[test]
    fn raw_mount_flags_beyond_the_kernel_word_are_rejected() {
        let err = sh_in("/tmp")
            .raw_mount(RawMount::new("/raw").flags(1 << 40))
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::MountFlagsInvalid { target, flags }) => {
                assert_eq!(flags, 1 << 40);
                assert_eq!(target, Path::new("/raw"), "the raw mount is named");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_nul_byte_in_raw_mount_data_is_rejected() {
        let err = sh_in("/tmp")
            .raw_mount(RawMount::new("/raw").fstype("tmpfs").data("mode\u{0}777"))
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::EmbeddedNul { value }) => {
                assert_eq!(value, OsStr::new("mode\u{0}777"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn toggles_remove_the_profile_mounts() {
        // Each toggle removes its own mount; the procfs the nested user
        // namespace's map is established through comes back as the caller's
        // own, which is what `mount_proc(false)` now obliges them to supply.
        let cage = sh_in("/tmp")
            .mount_proc(false)
            .mount_dev(false)
            .mount_tmp(false)
            .bind("/proc", "/proc")
            .build()
            .unwrap();
        assert_eq!(cage.plan.op_labels.len(), 1, "{:?}", cage.plan.op_labels);
        assert!(cage.plan.op_labels[0].starts_with("\"/proc\" at \"/proc\""));
    }

    #[test]
    fn a_container_with_no_procfs_at_all_is_refused() {
        // The nested user namespace that locks the sandbox's mount flags
        // establishes its identity map through a procfs, by path, from inside
        // the sandbox. A profile that mounts none is refused here rather than
        // failing at launch on a path nobody asked for.
        let err = sh_in("/tmp").mount_proc(false).build().unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::NestedUsernsNeedsProcfs),
        ));
    }

    #[test]
    fn a_covered_procfs_does_not_hide_one_that_is_still_standing() {
        // The ops run in order, so a later mount can bury an earlier one, and
        // the scan follows the same order. What it must not do is track only
        // the most recent candidate: this profile mounts a procfs, mounts a
        // second, and covers the second — and the first is still there to
        // establish the map through.
        let cage = sh_in("/tmp")
            .mount_proc(false)
            .raw_mount(RawMount::new("/proc").fstype("proc"))
            .raw_mount(RawMount::new("/mnt").fstype("proc"))
            .raw_mount(RawMount::new("/mnt").fstype("tmpfs"))
            .build()
            .expect("the first procfs is still visible");
        let nested = cage.plan.nested.as_ref().expect("a container nests");
        let crate::mechanism::NestedMap::SelfWritten { uid_map_path, .. } = &nested.map else {
            panic!("this tier writes its own map: {:?}", nested.map);
        };
        // Composed from the procfs that is still standing, not from the one
        // the tmpfs came to rest on.
        assert_eq!(uid_map_path.to_bytes(), b"/proc/self/uid_map");
    }

    #[test]
    fn an_op_that_mounts_nothing_does_not_hide_a_procfs() {
        // A remount and a propagation change act on the mount already standing
        // at their target; neither brings a mount to rest over it. Each kept
        // the managed procfs standing, and writable, so the profile is valid.
        const MS_REMOUNT: u64 = 0x20;
        const MS_PRIVATE: u64 = 1 << 18;
        const MS_NOEXEC: u64 = 8;
        for flags in [
            MS_REMOUNT | MS_NOEXEC,
            MS_REMOUNT | u64::from(MountFlags::BIND.bits()) | MS_NOEXEC,
            MS_PRIVATE,
        ] {
            sh_in("/tmp")
                .raw_mount(RawMount::new("/proc").flags(flags))
                .build()
                .unwrap_or_else(|err| panic!("flags {flags:#x}: {err}"));
        }

        // A move does bring a mount to rest: whatever stood at its source now
        // covers the managed procfs, which is gone from the sandbox's view.
        const MS_MOVE: u64 = 0x2000;
        let err = sh_in("/tmp")
            .raw_mount(RawMount::new("/proc").source("/mnt").flags(MS_MOVE))
            .build()
            .unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::NestedUsernsNeedsProcfs)),
            "{err}"
        );
    }

    /// A mount hides its own target and what sits beneath it, aligned on whole
    /// components, and every question of that shape reads the same answer: a
    /// sibling sharing a prefix is not beneath it, at the managed
    /// `resolv.conf` bind as at the placeholder bookkeeping.
    #[test]
    fn a_mount_covers_its_target_and_what_lies_beneath_it() {
        assert!(covers(c"etc", c"etc"));
        assert!(covers(c"etc", c"etc/resolv.conf"));
        assert!(!covers(c"et", c"etc/resolv.conf"));
        assert!(!covers(c"etc/resolv.conf", c"etc"));
        assert!(!covers(c"etc/resolv", c"etc/resolv.conf"));

        // A bind over a sibling whose name shares the prefix claims nothing,
        // and the managed bind stands.
        let sibling = Mount::Bind(Bind::new("/tmp", "/et"));
        assert!(!claims_resolv_conf(&sibling));
        assert!(claims_resolv_conf(&Mount::Bind(Bind::new("/tmp", "/etc"))));
    }

    /// The nested map is written through the procfs, so one that is standing
    /// but cannot take the write is refused at build, as an absent one is,
    /// rather than failing the launch with `EROFS` or `ENOENT`. Where read-only
    /// is the one reason it does not count, the refusal says so.
    #[test]
    fn a_procfs_the_nested_map_cannot_be_written_through_is_refused() {
        const MS_RDONLY: u64 = 1;
        const MS_REMOUNT: u64 = 0x20;
        const MS_BIND: u64 = 0x1000;
        let refused = |builder: CageBuilder, what: &str| {
            let err = builder.build().unwrap_err();
            assert!(
                matches!(err, Error::Config(ConfigError::NestedUsernsNeedsProcfs)),
                "{what}: {err}",
            );
        };
        let read_only = |builder: CageBuilder, what: &str| {
            let err = builder.build().unwrap_err();
            assert!(
                matches!(
                    &err,
                    Error::Config(ConfigError::NestedUsernsProcfsReadOnly { target })
                        if target == Path::new("/proc")
                ),
                "{what}: {err}",
            );
        };
        let opted_out = || sh_in("/tmp").managed_mounts(false);

        read_only(opted_out().bind_ro("/proc", "/proc"), "a read-only bind");
        read_only(
            sh_in("/tmp")
                .mount_proc(false)
                .raw_mount(RawMount::new("/proc").fstype("proc").flags(MS_RDONLY)),
            "a read-only raw procfs",
        );
        for remount in [MS_REMOUNT | MS_RDONLY, MS_REMOUNT | MS_BIND | MS_RDONLY] {
            read_only(
                sh_in("/tmp").raw_mount(RawMount::new("/proc").flags(remount)),
                "a read-only remount",
            );
        }
        // A path made read-only at the procfs leaves it where it stood,
        // read-only, and so does one above it.
        read_only(sh_in("/tmp").read_only("/proc"), "a read-only /proc");
        let err = sh_in("/tmp")
            .mount_proc(false)
            .raw_mount(RawMount::new("/sys/proc").fstype("proc"))
            .read_only("/sys")
            .build()
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::Config(ConfigError::NestedUsernsProcfsReadOnly { target })
                    if target == Path::new("/sys/proc")
            ),
            "a read-only path above the procfs: {err}",
        );
        // A read-only procfs a later mount covers is gone, not read-only.
        refused(
            opted_out()
                .bind_ro("/proc", "/proc")
                .raw_mount(RawMount::new("/proc").fstype("tmpfs")),
            "a covered read-only bind",
        );
        // Not the root of a procfs, though each carries its magic number: the
        // map files are named under `self`, which neither holds.
        refused(
            opted_out().bind("/proc/sys", "/proc"),
            "a bind of /proc/sys",
        );
        refused(
            opted_out().bind("/proc/self", "/proc"),
            "a bind of /proc/self",
        );

        // The last remount decides, and one that makes it writable again
        // leaves a procfs the map can be written through.
        sh_in("/tmp")
            .raw_mount(RawMount::new("/proc").flags(MS_REMOUNT | MS_RDONLY))
            .raw_mount(RawMount::new("/proc").flags(MS_REMOUNT))
            .build()
            .expect("a procfs remounted writable serves");
        // A read-only remount elsewhere leaves this one as it was, and so does
        // a path made read-only within the procfs.
        sh_in("/tmp")
            .raw_mount(RawMount::new("/tmp").flags(MS_REMOUNT | MS_RDONLY))
            .build()
            .expect("a remount of another mount leaves the procfs writable");
        sh_in("/tmp")
            .read_only("/proc/sys")
            .build()
            .expect("a read-only tree within the procfs leaves its root writable");
        opted_out()
            .bind("/proc", "/proc")
            .build()
            .expect("a writable bind of a procfs root serves");
    }

    /// `mount(2)` discards the legacy magic number from the high half of its
    /// flags before it reads them, and the magic's bits overlap `MS_PRIVATE`
    /// and `MS_SLAVE`. A raw mount carrying it is the fresh mount the kernel
    /// performs, not a propagation change.
    #[test]
    fn a_raw_mount_carrying_the_legacy_magic_is_read_as_the_kernel_reads_it() {
        const MS_MGC_VAL: u32 = 0xC0ED_0000;
        let magic = |flags: u32| Arrival::of_raw(MountFlags::from_bits_retain(MS_MGC_VAL | flags));
        assert_eq!(magic(0), Some(Arrival::Fresh));
        assert_eq!(magic(MountFlags::BIND.bits()), Some(Arrival::Tree));
        assert_eq!(magic(0x20), None, "a remount");

        sh_in("/tmp")
            .mount_proc(false)
            .raw_mount(
                RawMount::new("/proc")
                    .fstype("proc")
                    .flags(u64::from(MS_MGC_VAL)),
            )
            .build()
            .expect("a raw procfs carrying the magic is a procfs");
        // Discarding the magic leaves the low half, `MS_RDONLY` included, as
        // the caller gave it.
        let err = sh_in("/tmp")
            .mount_proc(false)
            .raw_mount(
                RawMount::new("/proc")
                    .fstype("proc")
                    .flags(u64::from(MS_MGC_VAL) | 1),
            )
            .build()
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Config(ConfigError::NestedUsernsProcfsReadOnly { .. })
            ),
            "{err}",
        );
    }

    #[test]
    fn a_moved_mount_is_held_to_the_bind_rule() {
        // `mount(2)` ignores the filesystem type of a move as it does of a bind,
        // so a move naming `proc` is a fresh procfs only if its source is one,
        // and then not a fresh one.
        const MS_MOVE: u64 = 0x2000;
        let moved = |source: &str| {
            sh_in("/tmp")
                .mount_proc(false)
                .raw_mount(
                    RawMount::new("/proc")
                        .source(source)
                        .fstype("proc")
                        .flags(MS_MOVE),
                )
                .build()
        };
        assert!(matches!(
            moved("/tmp").unwrap_err(),
            Error::Config(ConfigError::NestedUsernsNeedsProcfs),
        ));
        // The host's procfs, moved, serves the single map, whose command
        // reaches its own map files through `self`.
        moved("/proc").expect("a moved procfs serves the single-identity map");
    }

    #[test]
    fn a_raw_mount_that_binds_is_a_bind_whatever_it_calls_its_filesystem() {
        // `mount(2)` ignores `fstype` when `MS_BIND` is set, so a raw op
        // carrying that flag mounts whatever its source already is. Reading it
        // by the name it gives would have this configuration satisfy the
        // fresh-procfs requirement it does not meet, and the failure would
        // arrive at launch rather than here.
        let err = sh_in("/tmp")
            .mount_proc(false)
            .identity_map(IdentityMap::ranges(
                vec![crate::IdRange {
                    inside: 0,
                    outside: 1000,
                    count: 1,
                }],
                vec![crate::IdRange {
                    inside: 0,
                    outside: 1000,
                    count: 1,
                }],
            ))
            .id_mapper(FakeMapper)
            .raw_mount(
                RawMount::new("/proc")
                    .source("/proc")
                    .fstype("proc")
                    .flags(MountFlags::BIND.bits().into()),
            )
            .build()
            .unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::NestedUsernsNeedsProcfs)),
            "{err:?}",
        );
    }

    #[test]
    fn a_delegated_map_outside_a_pid_namespace_needs_no_procfs() {
        // The requirement follows the route the map actually takes. A range map
        // without a PID namespace is written by the launch stage, outside the
        // sandbox, through the host's own `/proc` — opened before the pivot,
        // and never named through the profile — so a profile that mounts no
        // procfs serves it. Refusing this configuration would rule out
        // `managed_mounts(false)`, the reproducibility opt-out, alongside a
        // range map for no reason the code has.
        let cage = sh_in("/tmp")
            .mount_proc(false)
            .pid_namespace(false)
            .identity_map(IdentityMap::ranges(
                vec![crate::IdRange {
                    inside: 0,
                    outside: 1000,
                    count: 1,
                }],
                vec![crate::IdRange {
                    inside: 0,
                    outside: 1000,
                    count: 1,
                }],
            ))
            .id_mapper(FakeMapper)
            .build()
            .expect("no procfs is needed where no in-sandbox delegate reads one");
        let nested = cage.plan.nested.as_ref().expect("a container nests");
        assert!(matches!(
            nested.map,
            crate::mechanism::NestedMap::Delegated {
                procfs_target: None
            },
        ));
    }

    #[test]
    fn a_ranged_map_in_a_pid_namespace_will_not_take_a_bound_procfs() {
        // The sandbox's own delegate names the command's map files by the pid
        // its `fork` returned, which is a pid of the sandbox's PID namespace. A
        // bind of the host's procfs does not index that namespace, so it cannot
        // serve — while the same bind serves the single-identity tier, whose
        // command reaches its own map through `self`.
        let ranged = || {
            sh_in("/tmp")
                .managed_mounts(false)
                .bind("/proc", "/proc")
                .identity_map(IdentityMap::ranges(
                    vec![crate::IdRange {
                        inside: 0,
                        outside: 1000,
                        count: 1,
                    }],
                    vec![crate::IdRange {
                        inside: 0,
                        outside: 1000,
                        count: 1,
                    }],
                ))
                .id_mapper(FakeMapper)
        };
        assert!(matches!(
            ranged().build().unwrap_err(),
            Error::Config(ConfigError::NestedUsernsNeedsProcfs),
        ));
        // Without a PID namespace of its own the sandbox's pids are the
        // caller's, and the bind indexes exactly the processes the delegate
        // names.
        ranged()
            .pid_namespace(false)
            .build()
            .expect("a bound procfs serves where the pids agree");
    }

    #[test]
    fn denied_network_isolates_but_leaves_loopback_down() {
        let cage = sh_in("/tmp").network(Network::None).build().unwrap();
        assert!(cage.plan.unshare.contains(UnshareFlags::NEWNET));
        assert!(!cage.plan.configure_loopback);
        assert!(
            !cage
                .plan
                .op_labels
                .contains(&"/etc/resolv.conf".to_string())
        );
    }

    /// A test delegate resolving whatever it is asked, recording nothing:
    /// the subordinate form resolves to a fixed allocation-shaped map.
    #[derive(Debug)]
    pub(super) struct FakeMapper;

    impl crate::IdMapper for FakeMapper {
        fn resolve(&self, request: &IdentityMap) -> Result<crate::ResolvedMap, crate::IdMapError> {
            let fixed = |own| {
                vec![
                    crate::IdRange {
                        inside: 0,
                        outside: own,
                        count: 1,
                    },
                    crate::IdRange {
                        inside: 1,
                        outside: 100000,
                        count: 65536,
                    },
                ]
            };
            Ok(match request {
                IdentityMap::Ranges { uid, gid, .. } => {
                    crate::ResolvedMap::new(uid.clone(), gid.clone())
                }
                _ => crate::ResolvedMap::new(fixed(1000), fixed(1000)),
            })
        }

        fn apply(&self, _pid: u32, _map: &crate::ResolvedMap) -> Result<(), crate::IdMapError> {
            Ok(())
        }
    }

    fn subordinate_cage() -> CageBuilder {
        sh_in("/tmp")
            .identity_map(IdentityMap::Subordinate)
            .id_mapper(FakeMapper)
    }

    #[test]
    fn the_default_identity_plan_is_the_single_map() {
        let cage = sh_in("/tmp").build().unwrap();
        assert!(matches!(cage.plan.identity, IdentityPlan::Single));
        assert!(cage.plan.run_as.is_none());
    }

    #[test]
    fn a_delegate_resolved_map_reaches_the_plan() {
        let cage = subordinate_cage().build().unwrap();
        match &cage.plan.identity {
            IdentityPlan::Ranged { map, .. } => {
                assert_eq!(map.uid().len(), 2);
                assert_eq!(map.uid()[0].outside, 1000);
                assert_eq!(map.gid()[1].count, 65536);
            }
            other => panic!("expected a ranged identity plan, got {other:?}"),
        }
    }

    #[test]
    fn an_invalid_range_request_is_rejected_before_any_delegate() {
        let err = sh_in("/tmp")
            .identity_map(IdentityMap::ranges(vec![], vec![]))
            .id_mapper(FakeMapper)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::IdentityMapInvalid { .. })
        ));
    }

    #[test]
    fn an_unsatisfiable_range_request_is_a_config_error() {
        // Without a configured delegate, the bundled chain must refuse: the
        // direct mapper requires capabilities an unprivileged test run does
        // not hold. Skip silently when the test itself runs privileged.
        if crate::idmap::effective_capabilities().contains(rustix::thread::CapabilitySet::SETUID) {
            return;
        }
        let extent = crate::IdRange {
            inside: 0,
            outside: 4_000_000_000,
            count: 1,
        };
        let request = IdentityMap::ranges(vec![extent], vec![extent]);
        let err = sh_in("/tmp").identity_map(request).build().unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::IdentityMapUnavailable { .. })
        ));
    }

    #[test]
    fn a_configured_delegates_refusal_is_carried_as_the_source() {
        #[derive(Debug)]
        struct Refusing;
        impl crate::IdMapper for Refusing {
            fn resolve(
                &self,
                _request: &IdentityMap,
            ) -> Result<crate::ResolvedMap, crate::IdMapError> {
                Err(crate::IdMapError::helper_spawn(
                    "newuidmap",
                    Some(std::io::Error::from_raw_os_error(
                        Errno::ACCESS.raw_os_error(),
                    )),
                ))
            }
            fn apply(&self, _pid: u32, _map: &crate::ResolvedMap) -> Result<(), crate::IdMapError> {
                Ok(())
            }
        }
        let err = sh_in("/tmp")
            .identity_map(IdentityMap::Subordinate)
            .id_mapper(Refusing)
            .build()
            .unwrap_err();
        let Error::Config(config) = &err else {
            panic!("unexpected error: {err}");
        };
        // The delegate's error is the source, and its own source, the OS
        // error, is reachable through it rather than flattened into text.
        let delegate = std::error::Error::source(config).expect("the delegate's refusal");
        assert!(
            matches!(
                delegate.downcast_ref::<crate::IdMapError>(),
                Some(crate::IdMapError::HelperSpawn { .. })
            ),
            "{delegate}"
        );
        let os = delegate.source().expect("the helper's OS error");
        assert_eq!(
            os.downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error),
            Some(Errno::ACCESS.raw_os_error()),
        );
    }

    #[test]
    fn run_as_requires_a_mapped_uid() {
        let err = subordinate_cage()
            .run_as(Identity::new(70000, 0))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::RunAsUnmapped {
                id: 70000,
                space: "uid"
            })
        ));
    }

    #[test]
    fn run_as_requires_a_mapped_gid_and_groups() {
        let err = subordinate_cage()
            .run_as(Identity::new(250, 70000))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::RunAsUnmapped {
                id: 70000,
                space: "gid"
            })
        ));

        let err = subordinate_cage()
            .run_as(Identity::new(250, 250).groups([250, 70000]))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::RunAsUnmapped {
                id: 70000,
                space: "supplementary group"
            })
        ));
    }

    #[test]
    fn a_mapped_run_as_freezes_into_the_plan() {
        let cage = subordinate_cage()
            .run_as(Identity::new(250, 250).groups([250, 100]))
            .build()
            .unwrap();
        let run_as = cage.plan.run_as.as_ref().unwrap();
        assert_eq!(run_as.uid.as_raw(), 250);
        assert_eq!(run_as.gid.as_raw(), 250);
        let groups: Vec<u32> = run_as
            .groups
            .iter()
            .flatten()
            .map(|group| group.as_raw())
            .collect();
        assert_eq!(groups, [250, 100]);
    }

    /// A range map whose gid list is the caller's own gid alone has the
    /// single-identity map's gid map, which the shadow helpers establish by
    /// denying `setgroups`. A run-as identity under it is valid and keeps the
    /// group list it inherited, where a `setgroups` call would fail the launch;
    /// a group list of its own is refused here, as under the single map.
    #[test]
    fn an_own_gid_alone_gid_map_sets_no_group_list() {
        let own = |id: u32| {
            vec![crate::IdRange {
                inside: 0,
                outside: id,
                count: 1,
            }]
        };
        let euid = rustix::process::geteuid().as_raw();
        let egid = rustix::process::getegid().as_raw();
        let mut uid = own(euid);
        uid.push(crate::IdRange {
            inside: 1,
            outside: 100_000,
            count: 65_536,
        });
        let own_gid = || {
            sh_in("/tmp")
                .identity_map(IdentityMap::ranges(uid.clone(), own(egid)))
                .id_mapper(FakeMapper)
        };

        let cage = own_gid()
            .run_as(Identity::new(250, 0))
            .build()
            .expect("a non-root uid under the caller's own gid builds");
        let run_as = cage.plan.run_as.as_ref().unwrap();
        assert_eq!(run_as.uid.as_raw(), 250);
        assert!(run_as.groups.is_none(), "{:?}", run_as.groups);

        let err = own_gid()
            .run_as(Identity::new(250, 0).groups([0]))
            .build()
            .unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::RunAsGroupsWithSingleMap)),
            "{err}",
        );

        // A single gid that is not the caller's own is a map a helper wrote
        // from a subordinate grant, and the list is set as given.
        let cage = sh_in("/tmp")
            .identity_map(IdentityMap::ranges(uid.clone(), own(100_000)))
            .id_mapper(FakeMapper)
            .run_as(Identity::new(250, 0))
            .build()
            .expect("a subordinate gid builds");
        assert_eq!(cage.plan.run_as.as_ref().unwrap().groups, Some(Vec::new()));
    }

    #[test]
    fn run_as_root_is_valid_under_the_single_map() {
        let cage = sh_in("/tmp").run_as(Identity::new(0, 0)).build().unwrap();
        let run_as = cage.plan.run_as.as_ref().unwrap();
        assert_eq!(run_as.uid.as_raw(), 0);
    }

    #[test]
    fn run_as_nonroot_under_the_single_map_is_outside_it() {
        let err = sh_in("/tmp")
            .run_as(Identity::new(250, 250).groups([250]))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::RunAsOutsideSingleMap {
                id: 250,
                space: "uid",
                presented: 0,
            })
        ));
        // The message names the remedy, since the map has no other id to
        // switch to.
        let Error::Config(config) = &err else {
            unreachable!("matched above")
        };
        assert!(
            config.to_string().contains("present the caller as uid 250"),
            "{config}"
        );
    }

    /// The single-identity map's nested map gives the sandbox's root the
    /// inside id the command sees: 0 by default.
    #[test]
    fn the_single_maps_nested_map_presents_root_by_default() {
        let cage = sh_in("/tmp").build().unwrap();
        let nested = cage.plan.nested.as_ref().unwrap();
        assert_eq!(nested.uid_lines, b"0 0 1\n");
        assert_eq!(nested.gid_lines, b"0 0 1\n");
        assert!(cage.plan.present_as.is_none());
    }

    #[test]
    fn a_presented_identity_is_the_nested_maps_inside_id() {
        let cage = sh_in("/tmp")
            .present_as(PresentedIdentity::Ids {
                uid: 1000,
                gid: 100,
            })
            .build()
            .unwrap();
        let nested = cage.plan.nested.as_ref().unwrap();
        assert!(matches!(nested.map, NestedMap::SelfWritten { .. }));
        assert_eq!(nested.uid_lines, b"1000 0 1\n");
        assert_eq!(nested.gid_lines, b"100 0 1\n");
        // The sandbox's own map is untouched: it is still built as root.
        assert!(matches!(cage.plan.identity, IdentityPlan::Single));
        assert!(cage.plan.run_as.is_none());
        let presented = cage.plan.present_as.unwrap();
        assert_eq!((presented.uid, presented.gid), (1000, 100));
    }

    #[test]
    fn own_presents_the_callers_effective_ids() {
        let cage = sh_in("/tmp")
            .present_as(PresentedIdentity::Own)
            .build()
            .unwrap();
        let presented = cage.plan.present_as.unwrap();
        assert_eq!(
            (presented.uid, presented.gid),
            (
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
            ),
        );
    }

    /// Under a presented identity the map's one id is that identity, so a
    /// run-as identity may name it, which switches nothing, and nothing else.
    #[test]
    fn run_as_under_a_presented_identity_names_that_identity_or_nothing() {
        let presented = || {
            sh_in("/tmp").present_as(PresentedIdentity::Ids {
                uid: 1000,
                gid: 1000,
            })
        };
        let same = presented()
            .run_as(Identity::new(1000, 1000))
            .build()
            .unwrap();
        assert_eq!(same.plan.run_as.as_ref().unwrap().uid.as_raw(), 1000);

        let err = presented().run_as(Identity::new(0, 0)).build().unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::RunAsOutsideSingleMap {
                id: 0,
                space: "uid",
                presented: 1000,
            })
        ));
        let err = presented()
            .run_as(Identity::new(1000, 0))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::RunAsOutsideSingleMap {
                id: 0,
                space: "gid",
                presented: 1000,
            })
        ));
        let err = presented()
            .run_as(Identity::new(1000, 1000).groups([1000]))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::RunAsGroupsWithSingleMap)
        ));
    }

    /// A range map has ids of its own to run as, and refuses a presented
    /// identity before its delegate is consulted.
    #[test]
    fn a_range_map_refuses_a_presented_identity() {
        let err = subordinate_cage()
            .present_as(PresentedIdentity::Own)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::PresentAsWithRangeMap)
        ));
    }

    /// The kernel refuses the id `(u32)-1` in any map, so a presented identity
    /// naming it is a configuration error rather than a launch failure.
    #[test]
    fn a_presented_identity_of_the_sentinel_id_is_refused() {
        for (uid, gid) in [(u32::MAX, 1000), (1000, u32::MAX)] {
            let err = sh_in("/tmp")
                .present_as(PresentedIdentity::Ids { uid, gid })
                .build()
                .unwrap_err();
            assert!(
                matches!(err, Error::Config(ConfigError::IdentityMapInvalid { .. })),
                "{err}"
            );
        }
    }

    /// A presented uid of 0 would make the nested map `0 0 1`, and the command
    /// root inside with every capability, so it is refused at build. A gid of 0
    /// carries no capability, and is presented.
    #[test]
    fn a_presented_identity_of_uid_0_is_refused() {
        for gid in [0, 100] {
            let presented = PresentedIdentity::ids(0, gid);
            let err = sh_in("/tmp").present_as(presented).build().unwrap_err();
            let Error::Config(err @ ConfigError::PresentAsRoot { identity }) = &err else {
                panic!("expected the refusal, got {err:?}");
            };
            assert_eq!(*identity, presented);
            assert!(err.to_string().contains("has uid 0"), "{err}");
        }
        let cage = sh_in("/tmp")
            .present_as(PresentedIdentity::ids(1000, 0))
            .build()
            .expect("a presented gid of 0 is accepted");
        let presented = cage.plan.present_as.unwrap();
        assert_eq!((presented.uid, presented.gid), (1000, 0));
    }

    /// `own` is the caller's own uid, which is 0 for the host's root, and is
    /// refused there as a uid of 0 given outright is.
    #[test]
    fn own_resolving_to_uid_0_is_refused() {
        let err = present_plan(PresentedIdentity::Own, 0, 0).unwrap_err();
        let Error::Config(
            err @ ConfigError::PresentAsRoot {
                identity: PresentedIdentity::Own,
            },
        ) = &err
        else {
            panic!("expected the refusal, got {err:?}");
        };
        assert!(
            err.to_string().contains("`own` is the caller's uid, 0"),
            "{err}"
        );
        assert!(present_plan(PresentedIdentity::Own, 1000, 0).is_ok());

        // And through the build, against whoever runs the test.
        let built = sh_in("/tmp").present_as(PresentedIdentity::Own).build();
        if rustix::process::geteuid().is_root() {
            assert!(matches!(
                built,
                Err(Error::Config(ConfigError::PresentAsRoot { .. }))
            ));
        } else {
            built.expect("a non-root caller presents as itself");
        }
    }

    #[test]
    fn a_presented_identity_parses_and_renders_its_two_forms() {
        for (text, presented) in [
            ("own", PresentedIdentity::Own),
            (
                "1000:100",
                PresentedIdentity::Ids {
                    uid: 1000,
                    gid: 100,
                },
            ),
            ("0:0", PresentedIdentity::Ids { uid: 0, gid: 0 }),
        ] {
            assert_eq!(text.parse::<PresentedIdentity>(), Ok(presented));
            assert_eq!(presented.to_string(), text);
        }
        for text in [
            "",
            "OWN",
            "1000",
            "1000:",
            ":1000",
            "1000:100:10",
            "-1:0",
            "a:b",
        ] {
            let err = text.parse::<PresentedIdentity>().unwrap_err();
            assert_eq!(err.text(), text);
        }
    }

    #[test]
    fn run_as_groups_under_the_single_map_are_rejected() {
        // Group 0 is mapped, but establishing the single-identity map denies
        // setgroups, so no group list can ever be applied inside it.
        let err = sh_in("/tmp")
            .run_as(Identity::new(0, 0).groups([0]))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::RunAsGroupsWithSingleMap)
        ));
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_kept_setid_capability_with_nonroot_run_as_is_rejected() {
        use crate::hardening::Capability;
        let err = subordinate_cage()
            .run_as(Identity::new(250, 250))
            .keep_capabilities([Capability::NetBindService, Capability::Setuid])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::SetidCapWithNonRootIdentity {
                capability: "CAP_SETUID"
            })
        ));
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn nonroot_run_as_with_kept_caps_sets_the_securebits() {
        use crate::hardening::Capability;
        let cage = subordinate_cage()
            .run_as(Identity::new(250, 250))
            .keep_capabilities([Capability::NetBindService])
            .build()
            .unwrap();
        assert!(cage.plan.hardening.set_securebits);
        // drop_all is an explicitly empty keep set: its post-switch
        // bounding-set narrowing needs the securebits too.
        let cage = subordinate_cage()
            .run_as(Identity::new(250, 250))
            .drop_all_capabilities()
            .build()
            .unwrap();
        assert!(cage.plan.hardening.set_securebits);
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn the_securebits_stay_clear_without_run_as_or_without_kept_caps() {
        use crate::hardening::Capability;
        // Kept capabilities under the root identity: no switch, no bits.
        let cage = sh_in("/tmp")
            .keep_capabilities([Capability::NetBindService])
            .build()
            .unwrap();
        assert!(!cage.plan.hardening.set_securebits);
        // A non-root identity without a keep request: the kernel clearing
        // the capabilities across the switch is the correct outcome.
        let cage = subordinate_cage()
            .run_as(Identity::new(250, 250))
            .build()
            .unwrap();
        assert!(!cage.plan.hardening.set_securebits);
    }

    /// A presented identity is never root inside, so there is no switch for the
    /// securebits to carry capabilities across, and no mapped uid 0 for a kept
    /// set-id capability to return to. A run-as identity naming it switches
    /// nothing either.
    #[cfg(feature = "hardening")]
    #[test]
    fn a_presented_identity_keeps_capabilities_without_a_switch() {
        use crate::hardening::Capability;
        for run_as in [None, Some(Identity::new(1000, 1000))] {
            let builder = sh_in("/tmp")
                .present_as(PresentedIdentity::Ids {
                    uid: 1000,
                    gid: 1000,
                })
                .keep_capabilities([Capability::NetBindService, Capability::Setuid]);
            let builder = match run_as {
                Some(identity) => builder.run_as(identity),
                None => builder,
            };
            let cage = builder.build().unwrap();
            assert!(!cage.plan.hardening.set_securebits);
        }
    }

    /// Whether the plan holds the managed `resolv.conf` bind.
    fn binds_resolv_conf(cage: &Cage) -> bool {
        cage.plan
            .op_labels
            .contains(&"/etc/resolv.conf".to_string())
    }

    /// `path` expressed relative to the process's working directory, for a
    /// test that needs a root the caller named relatively. Both are absolute
    /// and physical — `current_dir` reports the kernel's own answer — so
    /// ascending to the root and descending again names the same directory.
    fn relative_to_working_dir(path: &Path) -> PathBuf {
        let working = std::env::current_dir().expect("a working directory");
        let mut relative = PathBuf::new();
        for _ in working.components().skip(1) {
            relative.push("..");
        }
        relative.extend(path.components().skip(1));
        relative
    }

    /// Whether the host end of the `resolv.conf` bind is available at all; the
    /// rootfs end is what each case below varies.
    fn host_has_resolv_conf() -> bool {
        std::fs::canonicalize("/etc/resolv.conf")
            .map(|path| path.is_file())
            .unwrap_or(false)
    }

    /// Whether the host has a resolver configuration a test can watch the
    /// build bind; the skip without one says so.
    fn resolv_conf_to_bind() -> bool {
        let present = host_has_resolv_conf();
        if !present {
            ferroday_cage_testkit::require::premise_unmet(
                "the host has no /etc/resolv.conf to bind",
            );
        }
        present
    }

    #[test]
    fn host_network_skips_the_loopback_and_may_bind_resolv_conf() {
        let cage = sh_in("/tmp").network(Network::Host).build().unwrap();
        assert!(!cage.plan.configure_loopback);
        assert_eq!(binds_resolv_conf(&cage), host_has_resolv_conf());

        let cage = sh_in("/tmp")
            .network(Network::Host)
            .resolv_conf(false)
            .build()
            .unwrap();
        assert!(!binds_resolv_conf(&cage));
        assert!(cage.plan.managed_placeholders.is_empty());
    }

    #[test]
    fn a_callers_own_resolv_conf_mount_replaces_the_managed_one() {
        // The caller's mounts go last so their order is theirs, and a managed
        // mount pushed after them takes that back for the one target they were
        // most deliberate about: the sandbox's DNS would be the host's however
        // explicitly they said otherwise.
        if !resolv_conf_to_bind() {
            return;
        }
        let dir = Scratch::new("resolv-replaced");
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/hosts"), b"127.0.0.1 localhost\n").unwrap();
        let rootfs = dir.to_str().unwrap();

        let cage = sh_in(rootfs)
            .network(Network::Host)
            .bind_ro(dir.join("etc/hosts"), "/etc/resolv.conf")
            .build()
            .unwrap();
        let binds: Vec<&String> = cage
            .plan
            .op_labels
            .iter()
            .filter(|label| label.contains("/etc/resolv.conf"))
            .collect();
        assert_eq!(binds.len(), 1, "one bind at the target, not two: {binds:?}");
        assert!(
            binds[0].contains("etc/hosts"),
            "the caller's own bind is the one in force: {binds:?}",
        );
        // Written a way the mount target reader normalizes, and the same
        // target, so the managed bind is still replaced.
        let cage = sh_in(rootfs)
            .network(Network::Host)
            .bind_ro(dir.join("etc/hosts"), "/etc/./resolv.conf")
            .build()
            .unwrap();
        assert_eq!(
            cage.plan
                .op_labels
                .iter()
                .filter(|label| label.contains("resolv.conf"))
                .count(),
            1,
        );

        // The same claim spelled through the raw escape hatch. `RawMount`
        // carries a source and the kernel's own flags, so a bind is expressible
        // there too -- and a caller who reaches for it has been more explicit
        // about the target than one who called `bind_ro`, not less.
        let cage = sh_in(rootfs)
            .network(Network::Host)
            .raw_mount(
                RawMount::new("/etc/resolv.conf")
                    .source(dir.join("etc/hosts"))
                    .flags(0x1000), // MS_BIND
            )
            .build()
            .unwrap();
        assert_eq!(
            cage.plan
                .op_labels
                .iter()
                .filter(|label| label.contains("resolv.conf"))
                .count(),
            1,
            "a raw mount at the target replaces the managed bind as a bind does",
        );
    }

    #[test]
    fn a_callers_tree_over_etc_claims_resolv_conf_and_a_fresh_one_does_not() {
        // A bind of a host directory over /etc is the caller's /etc. The
        // managed bind's target would be created in it, which is the caller's
        // host directory: an empty file left there for good, or, for a
        // read-only bind, a launch that fails. It yields instead.
        if !resolv_conf_to_bind() {
            return;
        }
        let dir = Scratch::new("resolv-under-a-bind");
        std::fs::create_dir_all(dir.join("host-etc")).unwrap();
        for read_only in [false, true] {
            let builder = sh_in("/tmp").network(Network::Host);
            let builder = if read_only {
                builder.bind_ro(dir.join("host-etc"), "/etc")
            } else {
                builder.bind(dir.join("host-etc"), "/etc")
            };
            let cage = builder.build().unwrap();
            assert!(!binds_resolv_conf(&cage), "read-only: {read_only}");
            assert!(cage.plan.managed_placeholders.is_empty());
        }
        // A raw bind and a move bring a tree of the host's just the same.
        for flags in [0x1000, 0x2000] {
            let cage = sh_in("/tmp")
                .network(Network::Host)
                .raw_mount(
                    RawMount::new("/etc")
                        .source(dir.join("host-etc"))
                        .flags(flags),
                )
                .build()
                .unwrap();
            assert!(!binds_resolv_conf(&cage), "flags {flags:#x}");
        }

        // A fresh filesystem over /etc is the sandbox's own, and the target is
        // created in it as it would be in the root: the managed bind stays.
        let cage = sh_in("/tmp")
            .network(Network::Host)
            .raw_mount(RawMount::new("/etc").fstype("tmpfs"))
            .build()
            .unwrap();
        assert!(binds_resolv_conf(&cage));
        assert!(
            cage.plan.managed_placeholders.is_empty(),
            "the target is created in the tmpfs, not in the root"
        );
    }

    /// The same signal answers for the caller's own claim on the target, so a
    /// consumer composing its own bind yields to exactly the mounts the
    /// library's bind yields to.
    #[test]
    fn a_callers_claim_on_the_target_turns_the_resolv_conf_bind_off() {
        for claimed in [
            Cage::builder().bind_ro("/etc/hosts", "/etc/resolv.conf"),
            Cage::builder().bind_ro("/etc/hosts", "/etc/./resolv.conf"),
            Cage::builder().raw_mount(
                RawMount::new("/etc/resolv.conf")
                    .source("/etc/hosts")
                    .flags(0x1000), // MS_BIND
            ),
            // Any kind of mount at the target itself claims it.
            Cage::builder().raw_mount(RawMount::new("/etc/resolv.conf").fstype("tmpfs")),
            // A host tree over a directory above it: a bind, a raw bind, a move.
            Cage::builder().bind("/srv/etc", "/etc"),
            Cage::builder().bind_ro("/srv/etc", "/etc"),
            Cage::builder().raw_mount(RawMount::new("/etc").source("/srv/etc").flags(0x1000)),
            Cage::builder().raw_mount(RawMount::new("/etc").source("/srv/etc").flags(0x2000)),
        ] {
            assert!(!claimed.get_resolv_conf(), "{:?}", claimed.get_mounts());
        }

        for unclaimed in [
            Cage::builder(),
            Cage::builder().bind_ro("/etc/hosts", "/etc/hosts"),
            // A fresh filesystem above the target is the sandbox's own.
            Cage::builder().raw_mount(RawMount::new("/etc").fstype("tmpfs")),
            // A remount and a propagation change bring no mount at all.
            Cage::builder().raw_mount(RawMount::new("/etc/resolv.conf").flags(0x20)),
            Cage::builder().raw_mount(RawMount::new("/etc").flags(1 << 18)),
            // A target the build refuses names nothing.
            Cage::builder().bind_ro("/etc/hosts", "etc/resolv.conf"),
        ] {
            assert!(unclaimed.get_resolv_conf(), "{:?}", unclaimed.get_mounts());
        }
    }

    #[test]
    fn a_resolv_conf_target_the_launch_creates_is_recorded_for_removal() {
        // A bind needs its target to exist, so a rootfs shipping no resolv.conf
        // has one created. The plan records that path, which is how the caller
        // side knows to take it away once the sandbox is gone. A rootfs that
        // ships the file has nothing created and so nothing to remove.
        if !resolv_conf_to_bind() {
            return;
        }
        let dir = Scratch::new("resolv");
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        let rootfs = dir.to_str().unwrap();

        let created = sh_in(rootfs).network(Network::Host).build().unwrap();
        assert!(binds_resolv_conf(&created));
        let canonical = std::fs::canonicalize(&dir).unwrap();
        assert_eq!(
            (
                created.plan.managed_placeholders.root.as_path(),
                created.plan.managed_placeholders.paths.as_slice(),
            ),
            (canonical.as_path(), &[PathBuf::from("etc/resolv.conf")][..]),
            "a target the launch creates must be recorded for removal"
        );

        // The same rootfs named relative to the working directory records the
        // same canonical path. The removal happens whenever the handle drops,
        // which need not be in the directory the cage was built in, so a
        // relative path recorded here would later resolve somewhere else.
        let relative = relative_to_working_dir(&std::fs::canonicalize(&dir).unwrap());
        let named_relatively = sh_in(relative.to_str().unwrap())
            .network(Network::Host)
            .build()
            .unwrap();
        assert_eq!(
            named_relatively.plan.managed_placeholders.root, canonical,
            "a relatively named rootfs must still record an absolute root"
        );

        std::fs::write(dir.join("etc/resolv.conf"), b"nameserver 192.0.2.1\n").unwrap();
        let shipped = sh_in(rootfs).network(Network::Host).build().unwrap();
        assert!(binds_resolv_conf(&shipped));
        assert!(
            shipped.plan.managed_placeholders.is_empty(),
            "a file the rootfs ships is not the sandbox's to remove"
        );

        // An isolated network never binds it, so it never creates one either.
        let isolated = sh_in(rootfs).build().unwrap();
        assert!(!binds_resolv_conf(&isolated));
        assert!(isolated.plan.managed_placeholders.is_empty());
    }

    #[test]
    fn an_overlay_root_records_the_placeholder_in_the_upper() {
        // The bind's target is created inside the pivoted root, which for an
        // overlay cage is the merged view, so the file lands in the upper. A
        // placeholder recorded against the lower would name a path that never
        // exists — a silent no-op leaving the upper with a resolver
        // configuration the base never had, which an export of that upper
        // carries onward.
        if !resolv_conf_to_bind() {
            return;
        }
        let dir = Scratch::new("resolv-overlay");
        let base = dir.join("base");
        let upper = dir.join("upper");
        std::fs::create_dir_all(base.join("etc")).unwrap();

        let built = Cage::builder()
            .overlay_rootfs(&base, &upper)
            .network(Network::Host)
            .command("/bin/sh")
            .build();
        let cage = match built {
            Ok(cage) => cage,
            // A host that cannot establish an unprivileged overlay refuses the
            // build, so there is no plan to assert against. Any other refusal
            // is this test's failure.
            Err(Error::Config(ConfigError::OverlayUnavailable { blocker })) => {
                ferroday_cage_testkit::require::OVERLAY.skip(format!(
                    "an unprivileged overlay is unavailable here: {blocker}"
                ));
                return;
            }
            Err(err) => panic!("the overlay sandbox builds: {err}"),
        };
        assert!(binds_resolv_conf(&cage));
        assert_eq!(
            (
                cage.plan.managed_placeholders.root.as_path(),
                cage.plan.managed_placeholders.paths.as_slice(),
            ),
            (
                std::fs::canonicalize(&upper).unwrap().as_path(),
                &[PathBuf::from("etc/resolv.conf")][..],
            ),
            "an overlay root's placeholder belongs to the upper"
        );

        // A file any layer ships is not the sandbox's to create or remove,
        // even though the layer is not the one writes land in.
        std::fs::write(base.join("etc/resolv.conf"), b"nameserver 192.0.2.1\n").unwrap();
        let shipped = Cage::builder()
            .overlay_rootfs(&base, &upper)
            .network(Network::Host)
            .command("/bin/sh")
            .build()
            .unwrap();
        assert!(shipped.plan.managed_placeholders.is_empty());
    }

    /// Creates an overlay whiteout at `path`, or says why the host cannot.
    fn whiteout(path: &Path) -> Result<(), Errno> {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            path,
            FileType::CharacterDevice,
            Mode::empty(),
            0,
        )
    }

    /// Marks the directory at `path` opaque, as an unprivileged overlay does,
    /// or says why the filesystem cannot. The attribute is the overlay's own,
    /// which `Rooted::is_opaque` reads.
    fn mark_opaque(path: &Path, value: &[u8]) -> Result<(), Errno> {
        rustix::fs::setxattr(
            path,
            c"user.overlay.opaque",
            value,
            rustix::fs::XattrFlags::empty(),
        )
    }

    #[test]
    fn the_merged_view_decides_what_an_overlay_root_already_ships() {
        // Three layers as overlayfs stacks them: the upper over a middle lower
        // over the base. The base ships `etc/x` in every case below; what the
        // layers above do to it decides whether the merged view shows it.
        let scratch = Scratch::new("merged-presence");
        let (upper, middle, base) = (
            scratch.join("upper"),
            scratch.join("middle"),
            scratch.join("base"),
        );
        let reset = || {
            for layer in [&upper, &middle, &base] {
                let _ = crate::provision::remove_tree(layer, &IdentityMap::Single, None);
                std::fs::create_dir_all(layer.join("etc")).unwrap();
            }
            std::fs::write(base.join("etc/x"), b"shipped").unwrap();
        };
        let presence = || {
            let layers: Vec<Option<Rooted>> = [&upper, &middle, &base]
                .into_iter()
                .map(|layer| Rooted::open(layer).ok())
                .collect();
            merged_presence(&layers, Path::new("etc/x"))
        };

        reset();
        assert_eq!(presence(), Presence::Present, "the base shows through");

        // A whiteout in the upper hides the base's entry. Creating the target
        // replaces it, which the removal has to undo, so it is told apart.
        reset();
        if let Err(errno) = whiteout(&upper.join("etc/x")) {
            ferroday_cage_testkit::require::OVERLAY
                .skip(format!("this host cannot create a whiteout: {errno}"));
            return;
        }
        assert_eq!(presence(), Presence::WhitedOut);

        // One in a lower hides it too, and stays where it is.
        reset();
        whiteout(&middle.join("etc/x")).unwrap();
        assert_eq!(presence(), Presence::Absent);

        // A whiteout, or a file, where a directory above the target would have
        // to be hides everything beneath it.
        reset();
        std::fs::remove_dir(upper.join("etc")).unwrap();
        whiteout(&upper.join("etc")).unwrap();
        assert_eq!(presence(), Presence::Absent);
        reset();
        std::fs::remove_dir(middle.join("etc")).unwrap();
        std::fs::write(middle.join("etc"), b"").unwrap();
        assert_eq!(presence(), Presence::Absent);

        // An entry in a higher layer is what the merged view shows, whatever
        // the layers below it hold.
        reset();
        std::fs::write(upper.join("etc/x"), b"").unwrap();
        whiteout(&middle.join("etc/x")).unwrap();
        assert_eq!(presence(), Presence::Present);

        // A directory above the target marked opaque hides what the layers
        // below hold in it. The marker's other value names a directory holding
        // whiteouts of another kind, and is not opaque.
        reset();
        if let Err(errno) = mark_opaque(&middle.join("etc"), b"y") {
            ferroday_cage_testkit::require::OVERLAY
                .skip(format!("this filesystem cannot hold a user xattr: {errno}"));
            return;
        }
        assert_eq!(presence(), Presence::Absent);
        reset();
        mark_opaque(&middle.join("etc"), b"x").unwrap();
        assert_eq!(presence(), Presence::Present);

        // A symbolic link above the target, as a merged-usr layer carries one,
        // is resolved by the merged view across layers: the question passes to
        // the layers below, which carry the same link.
        reset();
        for layer in [&upper, &base] {
            std::fs::create_dir_all(layer.join("usr/lib")).unwrap();
            std::os::unix::fs::symlink("usr/lib", layer.join("lib")).unwrap();
        }
        crate::provision::remove_tree(&upper.join("usr"), &IdentityMap::Single, None).unwrap();
        std::fs::write(base.join("usr/lib/y"), b"").unwrap();
        let layers: Vec<Option<Rooted>> = [&upper, &middle, &base]
            .into_iter()
            .map(|layer| Rooted::open(layer).ok())
            .collect();
        assert_eq!(
            merged_presence(&layers, Path::new("lib/y")),
            Presence::Present
        );
        assert_eq!(
            merged_presence(&layers, Path::new("lib/z")),
            Presence::Absent
        );
    }

    /// Builds an overlay-rooted cage and returns the overlap it is refused for:
    /// the layer, its path, the layer it lies within, and that one's path.
    fn overlap_refusal(overlay: Overlay) -> (OverlayLayer, PathBuf, OverlayLayer, PathBuf) {
        match Cage::builder().overlay(overlay).command("/bin/sh").build() {
            Err(Error::Config(ConfigError::OverlayLayersOverlap {
                layer,
                path,
                within,
                within_path,
            })) => (layer, path, within, within_path),
            other => panic!("expected the layers to be refused as overlapping: {other:?}"),
        }
    }

    /// A scratch tree holding a base lower with one file in it, and the base's
    /// canonical path.
    fn overlap_scratch(name: &str) -> (Scratch, PathBuf) {
        let scratch = Scratch::new(name);
        let base = scratch.join("base");
        std::fs::create_dir_all(base.join("etc")).unwrap();
        std::fs::write(base.join("etc/hostname"), b"base\n").unwrap();
        let canonical = std::fs::canonicalize(&base).unwrap();
        (scratch, canonical)
    }

    /// The names a directory holds, sorted, to show a refusal created nothing.
    fn entries(dir: &Path) -> Vec<OsString> {
        let mut names: Vec<OsString> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        names
    }

    /// The kernel mounts an upper beneath a lower, and every write the sandbox
    /// made would land in the lower, so the build refuses it before it creates
    /// the upper, its work directory, or the missing directories above them.
    #[test]
    fn an_upper_beneath_a_lower_is_refused_before_anything_is_created() {
        let (_scratch, base) = overlap_scratch("overlap-upper-in-lower");
        let before = entries(&base);
        for upper in [base.join("up"), base.join("new/deeper/up")] {
            assert_eq!(
                overlap_refusal(Overlay::new().lower(&base).upper(&upper)),
                (
                    OverlayLayer::Upper,
                    upper,
                    OverlayLayer::Lower,
                    base.clone()
                ),
            );
            assert_eq!(entries(&base), before, "the lower is untouched");
        }
    }

    #[test]
    fn an_upper_that_is_a_lower_is_refused() {
        let (scratch, base) = overlap_scratch("overlap-upper-is-lower");
        let patches = scratch.join("patches");
        std::fs::create_dir(&patches).unwrap();
        let patches = std::fs::canonicalize(&patches).unwrap();
        assert_eq!(
            overlap_refusal(Overlay::new().lower(&base).lower(&patches).upper(&patches)),
            (
                OverlayLayer::Upper,
                patches.clone(),
                OverlayLayer::Lower,
                patches
            ),
        );
    }

    #[test]
    fn a_work_directory_beneath_a_lower_is_refused() {
        let (scratch, base) = overlap_scratch("overlap-work-in-lower");
        let before = entries(&base);
        let upper = scratch.join("upper");
        assert_eq!(
            overlap_refusal(
                Overlay::new()
                    .lower(&base)
                    .upper(&upper)
                    .work(base.join("work"))
            ),
            (
                OverlayLayer::Work,
                base.join("work"),
                OverlayLayer::Lower,
                base.clone()
            ),
        );
        assert_eq!(entries(&base), before, "the lower is untouched");
        assert!(!upper.exists(), "nor is the upper created");
    }

    #[test]
    fn a_lower_beneath_the_upper_is_refused() {
        let (scratch, base) = overlap_scratch("overlap-lower-in-upper");
        let upper = std::fs::canonicalize(&*scratch).unwrap().join("upper");
        std::fs::create_dir_all(upper.join("patches")).unwrap();
        assert_eq!(
            overlap_refusal(
                Overlay::new()
                    .lower(&base)
                    .lower(upper.join("patches"))
                    .upper(&upper)
            ),
            (
                OverlayLayer::Lower,
                upper.join("patches"),
                OverlayLayer::Upper,
                upper
            ),
        );
    }

    #[test]
    fn a_lower_beneath_the_work_directory_is_refused() {
        let (scratch, base) = overlap_scratch("overlap-lower-in-work");
        let work = std::fs::canonicalize(&*scratch).unwrap().join("work");
        std::fs::create_dir_all(work.join("patches")).unwrap();
        assert_eq!(
            overlap_refusal(
                Overlay::new()
                    .lower(&base)
                    .lower(work.join("patches"))
                    .upper(scratch.join("upper"))
                    .work(&work)
            ),
            (
                OverlayLayer::Lower,
                work.join("patches"),
                OverlayLayer::Work,
                work
            ),
        );
    }

    #[test]
    fn an_upper_and_a_work_directory_that_overlap_are_refused() {
        let (scratch, base) = overlap_scratch("overlap-upper-work");
        let root = std::fs::canonicalize(&*scratch).unwrap();
        let (upper, work) = (root.join("upper"), root.join("work"));
        for (upper, work, expected) in [
            // The work directory beneath the upper.
            (
                &upper,
                upper.join("work"),
                (
                    OverlayLayer::Work,
                    upper.join("work"),
                    OverlayLayer::Upper,
                    upper.clone(),
                ),
            ),
            // The upper beneath the work directory.
            (
                &work.join("upper"),
                work.clone(),
                (
                    OverlayLayer::Upper,
                    work.join("upper"),
                    OverlayLayer::Work,
                    work.clone(),
                ),
            ),
            // The two the same.
            (
                &upper,
                upper.clone(),
                (
                    OverlayLayer::Work,
                    upper.clone(),
                    OverlayLayer::Upper,
                    upper.clone(),
                ),
            ),
        ] {
            assert_eq!(
                overlap_refusal(Overlay::new().lower(&base).upper(upper).work(&work)),
                expected,
            );
        }
        assert!(!upper.exists() && !work.exists(), "nothing is created");
    }

    #[test]
    fn two_lowers_that_overlap_are_refused() {
        let (_scratch, base) = overlap_scratch("overlap-lowers");
        let upper = base.parent().unwrap().join("upper");
        assert_eq!(
            overlap_refusal(
                Overlay::new()
                    .lower(&base)
                    .lower(base.join("etc"))
                    .upper(&upper)
            ),
            (
                OverlayLayer::Lower,
                base.join("etc"),
                OverlayLayer::Lower,
                base.clone()
            ),
        );
        assert_eq!(
            overlap_refusal(Overlay::new().lower(&base).lower(&base).upper(&upper)),
            (OverlayLayer::Lower, base.clone(), OverlayLayer::Lower, base),
        );
    }

    /// The comparison is between the paths the mount names, so a symbolic link
    /// above a layer is resolved, and so is a `..` among directories the build
    /// would create.
    #[test]
    fn an_overlap_through_a_link_or_a_dot_dot_is_refused() {
        let (scratch, base) = overlap_scratch("overlap-spelled");
        let before = entries(&base);
        let link = scratch.join("link");
        std::os::unix::fs::symlink(&base, &link).unwrap();
        assert_eq!(
            overlap_refusal(Overlay::new().lower(&base).upper(link.join("up"))),
            (
                OverlayLayer::Upper,
                base.join("up"),
                OverlayLayer::Lower,
                base.clone()
            ),
        );
        assert_eq!(
            overlap_refusal(
                Overlay::new()
                    .lower(&base)
                    .upper(scratch.join("missing/../base/up"))
            ),
            (
                OverlayLayer::Upper,
                base.join("up"),
                OverlayLayer::Lower,
                base.clone()
            ),
        );
        assert_eq!(entries(&base), before, "the lower is untouched");
        assert!(!scratch.join("missing").exists(), "nothing is created");
    }

    /// Paths compare by whole components, so a sibling whose name begins with a
    /// lower's is disjoint from it.
    #[test]
    fn a_sibling_sharing_a_lowers_name_as_a_prefix_is_disjoint() {
        let (_scratch, base) = overlap_scratch("overlap-prefix");
        let mut sibling = base.clone().into_os_string();
        sibling.push("-upper");
        let sibling = PathBuf::from(sibling);
        check_layers_disjoint(
            std::slice::from_ref(&base),
            &sibling,
            &base.with_file_name(".base-upper.work"),
        )
        .expect("a sibling is disjoint");
    }

    /// A directory that does not exist yet resolves to the path it will have
    /// once its missing directories are created.
    #[test]
    fn a_missing_directory_resolves_to_where_it_will_be_created() {
        let scratch = Scratch::new("canonical-once-created");
        let root = std::fs::canonicalize(&*scratch).unwrap();
        std::fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        for (dir, expected) in [
            (root.join("real"), root.join("real")),
            (root.join("link"), root.join("real")),
            (root.join("link/a/b"), root.join("real/a/b")),
            (root.join("a/b/../c"), root.join("a/c")),
            (root.join("a/../../x"), root.parent().unwrap().join("x")),
            (root.join("real/./a"), root.join("real/a")),
        ] {
            assert_eq!(canonical_once_created(&dir).unwrap(), expected, "{dir:?}");
        }
        // A relative path starts from the working directory, missing in whole.
        let missing = format!("fcage-missing-{}/a", crate::host::unique_hex());
        assert_eq!(
            canonical_once_created(Path::new(&missing)).unwrap(),
            std::fs::canonicalize(std::env::current_dir().unwrap())
                .unwrap()
                .join(&missing),
        );
        // A file where a directory belongs is reported, not walked past.
        std::fs::write(root.join("file"), b"").unwrap();
        assert!(canonical_once_created(&root.join("file/a")).is_err());
        assert!(!root.join("a").exists(), "nothing is created");
    }

    #[test]
    fn a_target_created_over_a_whiteout_puts_the_whiteout_back() {
        // The build records a target whose name the upper had whited out, and
        // the teardown, once the launch's empty file is gone, recreates the
        // whiteout: the upper goes on recording the deletion it held.
        let scratch = Scratch::new("whiteout-restore");
        let (upper, base) = (scratch.join("upper"), scratch.join("base"));
        std::fs::create_dir_all(upper.join("etc")).unwrap();
        std::fs::create_dir_all(base.join("etc")).unwrap();
        std::fs::write(base.join("etc/shipped"), b"shipped").unwrap();
        if let Err(errno) = whiteout(&upper.join("etc/shipped")) {
            ferroday_cage_testkit::require::OVERLAY
                .skip(format!("this host cannot create a whiteout: {errno}"));
            return;
        }
        let mut lowering = Lowering::default();
        lowering
            .push_bind(&Bind::new("/etc/hostname", "/etc/shipped"))
            .unwrap();
        let lower = [base.clone()];
        let placeholders = created_file_targets(
            &lowering.ops,
            &RootLayers::Overlay {
                upper: &upper,
                lower: &lower,
            },
        );
        assert_eq!(placeholders.paths, [Path::new("etc/shipped")]);
        assert_eq!(placeholders.whiteouts, [Path::new("etc/shipped")]);

        // What the launch does: the target replaces the whiteout, and the
        // setup reports the file it created.
        std::fs::remove_file(upper.join("etc/shipped")).unwrap();
        std::fs::write(upper.join("etc/shipped"), b"").unwrap();
        let file = rustix::fs::lstat(upper.join("etc/shipped")).unwrap();
        let created = [crate::mechanism::CreatedTarget {
            op: lowering
                .ops
                .iter()
                .position(|op| op.create_file.is_some())
                .expect("the bind creates its target"),
            ino: file.st_ino,
        }];
        drop(crate::running::PlaceholderGuard::of(
            &placeholders,
            &lowering.ops,
            &created,
            None,
        ));
        let stat = rustix::fs::lstat(upper.join("etc/shipped")).expect("the name is taken");
        assert!(Rooted::is_whiteout(&stat), "the whiteout is back");
    }

    #[test]
    fn a_caller_file_bind_target_the_launch_creates_is_recorded_for_removal() {
        // A caller's file bind creates its target the same way the managed
        // resolv.conf bind does, and leaves the same residue if nothing takes
        // it away — an empty file the root never shipped, carried into an
        // export of the tree.
        let dir = Scratch::new("bind-placeholder");
        let rootfs = dir.join("rootfs");
        let source = dir.join("source");
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::fs::create_dir_all(dir.join("host-etc")).unwrap();
        std::fs::write(&source, b"contents").unwrap();
        std::fs::write(rootfs.join("etc/shipped"), b"already here").unwrap();
        let canonical = std::fs::canonicalize(&rootfs).unwrap();
        let placeholders =
            |builder: CageBuilder| builder.build().unwrap().plan.managed_placeholders;

        // The paths are recorded relative to the root's writable layer, and
        // resolved against a descriptor for it when the time comes to remove
        // them; the root is named once, canonically.
        let recorded = placeholders(
            Cage::builder()
                .rootfs(&rootfs)
                .command("/bin/sh")
                .bind_ro(&source, "/etc/created"),
        );
        assert_eq!(recorded.root, canonical);
        assert_eq!(recorded.paths, [Path::new("etc/created")]);

        // A target the rootfs ships is not the launch's to create or remove.
        let cage = Cage::builder()
            .rootfs(&rootfs)
            .command("/bin/sh")
            .bind_ro(&source, "/etc/shipped");
        assert!(placeholders(cage).is_empty());

        // A symbolic link is an entry the rootfs ships, dangling or not: the
        // launch creates the target with `O_EXCL` and so leaves it alone. Read
        // as an absent file, a dangling one would record a placeholder for a
        // path the launch never wrote to, while the file it did create — at the
        // link's destination — went unrecorded and stayed.
        std::os::unix::fs::symlink("../var/absent", rootfs.join("etc/linked")).unwrap();
        std::os::unix::fs::symlink("shipped", rootfs.join("etc/resolvable")).unwrap();
        for target in ["/etc/linked", "/etc/resolvable"] {
            let cage = Cage::builder()
                .rootfs(&rootfs)
                .command("/bin/sh")
                .bind_ro(&source, target);
            assert!(
                placeholders(cage).is_empty(),
                "{target} is an entry the rootfs ships"
            );
        }

        // A target under an earlier mount is created inside that mount, not in
        // the rootfs directory on the host: in the managed tmpfs on /tmp, which
        // vanishes with the namespace, and in the caller's own bind source,
        // which is theirs.
        let cage = Cage::builder()
            .rootfs(&rootfs)
            .command("/bin/sh")
            .bind_ro(&source, "/tmp/under-a-tmpfs")
            .bind(dir.join("host-etc"), "/etc")
            .bind_ro(&source, "/etc/under-a-bind");
        assert!(placeholders(cage).is_empty());

        // A directory bind creates no file, so it contributes no placeholder;
        // the mount-point directory it creates stays.
        let cage = Cage::builder()
            .rootfs(&rootfs)
            .command("/bin/sh")
            .bind_ro(dir.join("host-etc"), "/mnt/data");
        assert!(placeholders(cage).is_empty());
    }

    #[test]
    fn a_hide_covers_a_file_target_only_where_the_root_holds_the_hidden_path() {
        let dir = Scratch::new("hide-placeholder");
        let rootfs = dir.join("rootfs");
        let source = dir.join("source");
        std::fs::create_dir_all(rootfs.join("root")).unwrap();
        std::fs::write(&source, b"contents").unwrap();
        let hidden = || {
            Cage::builder()
                .rootfs(&rootfs)
                .command("/bin/sh")
                .hide("/root/.config")
                .bind_ro(&source, "/root/.config/git/config")
                .build()
                .unwrap()
                .plan
                .managed_placeholders
        };

        // Nothing at the hidden path: the hide mounts nothing, and the bind
        // creates its target in the root itself, which the root never held.
        assert_eq!(hidden().paths, [Path::new("root/.config/git/config")]);

        // A directory there: the hide's tmpfs takes the target, and the target
        // goes with the namespace.
        std::fs::create_dir_all(rootfs.join("root/.config")).unwrap();
        assert!(hidden().is_empty());
    }

    #[test]
    fn a_hide_of_a_path_the_host_lacks_covers_nothing_on_the_host_root() {
        const ABSENT: &str = "/ferroday-cage-test-hidden-absent";
        assert!(
            std::fs::symlink_metadata(ABSENT).is_err(),
            "{ABSENT} is free on this host"
        );
        let err = Cage::builder()
            .host_rootfs()
            .hide(ABSENT)
            .bind_ro("/etc/passwd", format!("{ABSENT}/passwd"))
            .command("/bin/true")
            .build()
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::Config(ConfigError::MountTargetMissing { target, .. })
                    if *target == Path::new(ABSENT).join("passwd")
            ),
            "{err:?}"
        );

        // A hidden path the host holds is the sandbox's own tmpfs, which the
        // target is created in.
        let cage = Cage::builder()
            .host_rootfs()
            .hide("/usr/share")
            .bind_ro("/etc/passwd", "/usr/share/ferroday-cage-test/passwd")
            .command("/bin/true")
            .build()
            .expect("a target beneath a hidden directory the host holds");
        let at = cage
            .plan
            .op_labels
            .iter()
            .position(|label| label.contains("/usr/share/ferroday-cage-test/passwd"))
            .expect("the bind is planned");
        assert_eq!(
            cage.plan.ops[at].create_file.as_deref(),
            Some(c"usr/share/ferroday-cage-test/passwd")
        );
    }

    #[test]
    fn a_root_internal_absolute_symlink_is_judged_inside_the_root() {
        // A rootfs may hold an absolute symbolic link — an unpacked tarball is
        // entitled to ship `./absolute -> /etc`, and any image taken from a
        // systemd-resolved host ships `/etc/resolv.conf` as one. The launch
        // resolves its mount targets against the new-root descriptor with
        // RESOLVE_IN_ROOT, so such a link lands inside the rootfs; the
        // bookkeeping here has to agree, or it records a path the launch never
        // wrote to and answers a question about the host's filesystem instead.
        let dir = Scratch::new("placeholder-in-root");
        let rootfs = dir.join("rootfs");
        let source = dir.join("source");
        std::fs::create_dir_all(rootfs.join("real")).unwrap();
        std::fs::write(&source, b"contents").unwrap();
        // `/absolute` inside the rootfs points at `/real` inside the rootfs.
        std::os::unix::fs::symlink("/real", rootfs.join("absolute")).unwrap();
        // The same name exists on the host and holds a file, so a judgement
        // made against the host's root would read the target as already
        // shipped and record nothing.
        std::fs::create_dir_all(dir.join("host-side/real")).unwrap();
        std::fs::write(dir.join("host-side/real/entry"), b"host").unwrap();

        let placeholders =
            |builder: CageBuilder| builder.build().unwrap().plan.managed_placeholders;
        let recorded = placeholders(
            Cage::builder()
                .rootfs(&rootfs)
                .command("/bin/sh")
                .bind_ro(&source, "/absolute/entry"),
        );
        assert_eq!(
            recorded.paths,
            [Path::new("absolute/entry")],
            "a target behind a root-internal absolute symlink is the launch's to create"
        );

        // And once the rootfs ships it — at the path the link resolves to
        // inside the rootfs — there is nothing for the launch to create.
        std::fs::write(rootfs.join("real/entry"), b"shipped").unwrap();
        assert!(
            placeholders(
                Cage::builder()
                    .rootfs(&rootfs)
                    .command("/bin/sh")
                    .bind_ro(&source, "/absolute/entry"),
            )
            .is_empty(),
            "the link must resolve inside the rootfs, where the entry now is"
        );
    }

    #[test]
    fn a_managed_mount_point_carries_the_mode_of_the_directory_it_stands_for() {
        // The mount hides the mode for as long as it is established, but the
        // mount point outlives the sandbox: a `/tmp` the sandbox creates must be
        // the 1777 directory `/tmp` is, not a 0755 one nothing unprivileged can
        // write to.
        let cage = sh_in("/tmp").build().unwrap();
        let mode_of = |target: &str| -> RawMode {
            let (op, _) = cage
                .plan
                .ops
                .iter()
                .zip(&cage.plan.op_labels)
                .find(|(_, label)| label.as_str() == target)
                .unwrap_or_else(|| panic!("no {target} op in {:?}", cage.plan.op_labels));
            op.dirs.last().expect("a mount point to create").mode
        };
        assert_eq!(mode_of("/tmp"), 0o1777);
        assert_eq!(mode_of("/dev/shm"), 0o1777);
        assert_eq!(mode_of("/dev"), 0o755);
        assert_eq!(mode_of("/proc"), 0o755);
        // devpts's `mode=` is the mode of the pseudo-terminals it allocates,
        // not of its own root, so its mount point is an ordinary directory.
        assert_eq!(mode_of("/dev/pts"), 0o755);

        // An ancestor created on the way to a mount point is an ordinary
        // directory whatever the mount point itself is.
        let cage = sh_in("/tmp")
            .bind("/etc/hostname", "/a/b/hostname")
            .build()
            .expect("a file bind into fresh directories builds");
        let (op, _) = cage
            .plan
            .ops
            .iter()
            .zip(&cage.plan.op_labels)
            .find(|(_, label)| label.ends_with("at \"/a/b/hostname\""))
            .expect("the bind op");
        assert_eq!(op.dirs.len(), 2, "both /a and /a/b are created");
        assert!(op.dirs.iter().all(|dir| dir.mode == 0o755));
    }
}

#[cfg(all(test, feature = "serde"))]
pub(crate) mod serde_tests {
    use super::*;
    use crate::scratch::Scratch;

    /// Every key a rendered TOML document carries, as a sorted list of dotted
    /// paths, with an array index rendered as `[]`.
    ///
    /// The one reading behind each serde format's key pin: the profile format
    /// here, which needs the hardening layer to name every key,
    /// `NetStackBuilder`'s beside the network stack, and the resolved
    /// provenance record's beside the record.
    pub(crate) fn profile_keys(rendered: &str) -> Vec<String> {
        fn walk(value: &toml::Value, prefix: &str, into: &mut Vec<String>) {
            match value {
                toml::Value::Table(table) => {
                    for (key, nested) in table {
                        let path = if prefix.is_empty() {
                            key.clone()
                        } else {
                            format!("{prefix}.{key}")
                        };
                        into.push(path.clone());
                        walk(nested, &path, into);
                    }
                }
                toml::Value::Array(items) => {
                    for item in items {
                        walk(item, &format!("{prefix}[]"), into);
                    }
                }
                _ => {}
            }
        }

        let rendered: toml::Table =
            toml::from_str(rendered).expect("the rendering parses back as TOML");
        let mut keys = Vec::new();
        walk(&toml::Value::Table(rendered), "", &mut keys);
        keys.sort();
        keys.dedup();
        keys
    }

    /// A profile naming every field the format has, for the key-pinning test
    /// below. Nothing here is a meaningful configuration; it exists so that
    /// serializing it renders every key.
    ///
    /// The `hardening` feature is required, and not because the test wants it:
    /// a build without it refuses a profile that configures hardening, which is
    /// a promise of its own that
    /// [`a_hardening_profile_is_rejected_without_the_feature`] holds. A profile
    /// naming every key therefore only parses where every key exists.
    #[cfg(feature = "hardening")]
    const EVERY_KEY_PROFILE: &str = r#"
rootfs = "/srv/rootfs"
command = "/bin/sh"
args = ["-c", "true"]
network = "host"
hostname = "builder"
workdir = "/build"
stdin = "null"
stdout = "inherit"
stderr = "null"
pid-namespace = false
managed-mounts = true
mount-proc = true
mount-dev = false
mount-tmp = true
resolv-conf = false
base-env = false
stop-with-caller = true
path-lookup = true
present-as = "1000:1000"
run-as = { uid = 1000, gid = 1000, groups = [10, 20] }

[identity-map.ranges]
uid = [{ inside = 0, outside = 100000, count = 65536 }]
gid = [{ inside = 0, outside = 100000, count = 65536 }]

[overlay]
lower = ["/srv/base"]
upper = "/var/tmp/upper"
work = "/var/tmp/work"

[cgroup]
parent = "/sys/fs/cgroup/delegated"
required = true
memory-max = 536870912
memory-swap-max = 0
pids-max = 64
cpu-max = { quota = 50000, period = 100000 }
cpu-weight = 100

[rlimit]
address-space = "unlimited"
core-dump = 0
cpu-time = { soft = 10, hard = "unlimited" }
data = "unlimited"
file-size = "unlimited"
locked-memory = 65536
open-files = 1024
pending-signals = 64
processes = 64
stack = 8388608

[env]
PATH = "/usr/bin"

[[mount]]
kind = "bind"
source = "/etc"
target = "/host-etc"
read-only = true

[[mount]]
kind = "raw"
target = "/raw"
fstype = "tmpfs"
flags = 6
data = "mode=0777"

[hardening]
seccomp = "curated"
keep-caps = ["net-bind-service"]
landlock-scope = ["signal"]
resolve-unix = true

[[hardening.landlock-fs]]
path = "/usr"
access = "rx"

[[hardening.landlock-net]]
port = 443
access = "c"
"#;

    /// The hardening keys the profile above cannot carry beside its own,
    /// because each names the other form of a value it already sets: dropping
    /// every capability rather than keeping some, and a seccomp table rather
    /// than the curated policy, once per side, since a table allows or denies
    /// and never both.
    #[cfg(feature = "hardening")]
    const OTHER_FORM_PROFILES: [&str; 4] = [
        r#"
[hardening]
drop-caps = true

[hardening.seccomp]
allow = ["read", "write", "exit_group"]
errno = { clone3 = "ENOSYS" }

[[hardening.seccomp.allow-rule]]
syscall = "ioctl"
[[hardening.seccomp.allow-rule.arg]]
index = 1
len = "dword"
op = "masked-eq"
mask = 255
value = 21
"#,
        r#"
[hardening.seccomp]
curated = true
deny = ["sethostname"]

[[hardening.seccomp.deny-rule]]
syscall = "clone"
[[hardening.seccomp.deny-rule.arg]]
index = 0
len = "qword"
op = "eq"
value = 268435456
"#,
        r#"
empty-rootfs = true

[[mount]]
kind = "symlink"
target = "usr/bin"
path = "/bin"
"#,
        r#"
host-rootfs = true
reveal = ["/run"]

[[mount]]
kind = "hide"
target = "/home/user/.ssh"

[[mount]]
kind = "read-only"
target = "/work/.git/hooks"
"#,
    ];

    /// Every value `network` can take, as a profile spells it.
    ///
    /// The values come from `rename_all` as the keys do, and the match is
    /// exhaustive, so a variant added later fails to compile here until its
    /// spelling is pinned.
    #[test]
    fn the_network_spellings_are_what_they_are() {
        let spelling = |network: Network| match network {
            Network::Isolated => "isolated",
            Network::None => "none",
            Network::Host => "host",
        };
        for network in [Network::Isolated, Network::None, Network::Host] {
            let rendered = toml::Value::try_from(network).expect("a network serializes");
            assert_eq!(rendered.as_str(), Some(spelling(network)));
            let parsed: Network = rendered.try_into().expect("the spelling parses back");
            assert_eq!(parsed, network);
        }
    }

    /// The keys the profiles above render between them, in sorted order.
    #[cfg(feature = "hardening")]
    const EXPECTED_PROFILE_KEYS: [&str; 106] = [
        "args",
        "base-env",
        "cgroup",
        "cgroup.cpu-max",
        "cgroup.cpu-max.period",
        "cgroup.cpu-max.quota",
        "cgroup.cpu-weight",
        "cgroup.memory-max",
        "cgroup.memory-swap-max",
        "cgroup.parent",
        "cgroup.pids-max",
        "cgroup.required",
        "command",
        "empty-rootfs",
        "env",
        "env.PATH",
        "hardening",
        "hardening.drop-caps",
        "hardening.keep-caps",
        "hardening.landlock-fs",
        "hardening.landlock-fs[].access",
        "hardening.landlock-fs[].path",
        "hardening.landlock-net",
        "hardening.landlock-net[].access",
        "hardening.landlock-net[].port",
        "hardening.landlock-scope",
        "hardening.resolve-unix",
        "hardening.seccomp",
        "hardening.seccomp.allow",
        "hardening.seccomp.allow-rule",
        "hardening.seccomp.allow-rule[].arg",
        "hardening.seccomp.allow-rule[].arg[].index",
        "hardening.seccomp.allow-rule[].arg[].len",
        "hardening.seccomp.allow-rule[].arg[].mask",
        "hardening.seccomp.allow-rule[].arg[].op",
        "hardening.seccomp.allow-rule[].arg[].value",
        "hardening.seccomp.allow-rule[].syscall",
        "hardening.seccomp.curated",
        "hardening.seccomp.deny",
        "hardening.seccomp.deny-rule",
        "hardening.seccomp.deny-rule[].arg",
        "hardening.seccomp.deny-rule[].arg[].index",
        "hardening.seccomp.deny-rule[].arg[].len",
        "hardening.seccomp.deny-rule[].arg[].op",
        "hardening.seccomp.deny-rule[].arg[].value",
        "hardening.seccomp.deny-rule[].syscall",
        "hardening.seccomp.errno",
        "hardening.seccomp.errno.clone3",
        "host-rootfs",
        "hostname",
        "identity-map",
        "identity-map.ranges",
        "identity-map.ranges.gid",
        "identity-map.ranges.gid[].count",
        "identity-map.ranges.gid[].inside",
        "identity-map.ranges.gid[].outside",
        "identity-map.ranges.uid",
        "identity-map.ranges.uid[].count",
        "identity-map.ranges.uid[].inside",
        "identity-map.ranges.uid[].outside",
        "managed-mounts",
        "mount",
        "mount-dev",
        "mount-proc",
        "mount-tmp",
        "mount[].data",
        "mount[].flags",
        "mount[].fstype",
        "mount[].kind",
        "mount[].path",
        "mount[].read-only",
        "mount[].source",
        "mount[].target",
        "network",
        "overlay",
        "overlay.lower",
        "overlay.upper",
        "overlay.work",
        "path-lookup",
        "pid-namespace",
        "present-as",
        "resolv-conf",
        "reveal",
        "rlimit",
        "rlimit.address-space",
        "rlimit.core-dump",
        "rlimit.cpu-time",
        "rlimit.cpu-time.hard",
        "rlimit.cpu-time.soft",
        "rlimit.data",
        "rlimit.file-size",
        "rlimit.locked-memory",
        "rlimit.open-files",
        "rlimit.pending-signals",
        "rlimit.processes",
        "rlimit.stack",
        "rootfs",
        "run-as",
        "run-as.gid",
        "run-as.groups",
        "run-as.uid",
        "stderr",
        "stdin",
        "stdout",
        "stop-with-caller",
        "workdir",
    ];

    /// Every key a serialized profile can carry, as the profiles above render
    /// them.
    ///
    /// The profile format is a compatibility commitment, and a key's spelling
    /// comes from `rename_all` on the container rather than from a `rename` on
    /// every field — so a Rust-side field rename, a changed `rename_all`, a
    /// typo in a container attribute, and a newly added field all move a key
    /// silently. This is what notices. A deliberate change to the format
    /// updates this list, and the diff is the review.
    #[cfg(feature = "hardening")]
    #[test]
    fn the_profile_format_keys_are_what_they_are() {
        let mut keys = Vec::new();
        for profile in std::iter::once(EVERY_KEY_PROFILE).chain(OTHER_FORM_PROFILES) {
            let builder: CageBuilder = toml::from_str(profile).expect("the profile parses");
            let rendered = toml::to_string(&builder).expect("the builder serializes");
            keys.extend(profile_keys(&rendered));
        }
        keys.sort();
        keys.dedup();

        assert_eq!(
            keys, EXPECTED_PROFILE_KEYS,
            "the profile format's keys moved"
        );
    }

    /// Every operation the restricted policy refuses, in the order
    /// [`RestrictedProfile`]'s list names them: a profile that uses it, and the
    /// words the refusal names it in.
    const RESTRICTED_REFUSALS: &[(&str, &str)] = &[
        (
            "[[mount]]\nkind = \"bind\"\nsource = \"/etc\"\ntarget = \"/host-etc\"\n",
            "a bind mount",
        ),
        (
            "[[mount]]\nkind = \"raw\"\ntarget = \"/raw\"\nsource = \"/dev/shm\"\n\
             fstype = \"tmpfs\"\nflags = 6\ndata = \"mode=0777\"\n",
            "a raw mount",
        ),
        (
            "[[mount]]\nkind = \"symlink\"\ntarget = \"/var/tmp/x.so\"\n\
             path = \"/etc/ld.so.preload\"\n",
            "a symbolic link",
        ),
        ("network = \"host\"\n", "host networking"),
        (
            "[overlay]\nlower = [\"/srv/base\"]\nupper = \"/var/tmp/upper\"\n\
             work = \"/var/tmp/work\"\n",
            "an overlay root",
        ),
        ("host-rootfs = true\n", "the host's own root (host-rootfs)"),
        (
            "rootfs = \"/srv/rootfs\"\nreveal = [\"/run\"]\n",
            "a path the host's root hides taken back (reveal)",
        ),
        ("pid-namespace = false\n", "the host PID namespace"),
        (
            "[cgroup]\nparent = \"/sys/fs/cgroup/delegated\"\n",
            "a cgroup parent",
        ),
        #[cfg(feature = "hardening")]
        (
            "[[hardening.landlock-fs]]\npath = \"/\"\naccess = \"rwx\"\n",
            "a Landlock filesystem grant (landlock-fs)",
        ),
        #[cfg(feature = "hardening")]
        (
            "[[hardening.landlock-net]]\nport = 443\naccess = \"c\"\n",
            "a Landlock network grant (landlock-net)",
        ),
        #[cfg(feature = "hardening")]
        (
            "[hardening]\nkeep-caps = [\"dac-override\"]\n",
            "a kept capability set (keep-caps)",
        ),
        #[cfg(feature = "hardening")]
        (
            "[hardening]\nresolve-unix = false\n",
            "the unix-socket restriction turned off (resolve-unix = false)",
        ),
    ];

    /// The restricted policy refuses each operation its list names, both where
    /// a `RestrictedProfile` is deserialized and where a builder is converted,
    /// and names it in the list's words.
    #[test]
    fn a_restricted_profile_refuses_each_operation_its_list_names() {
        for (profile, operation) in RESTRICTED_REFUSALS {
            let err = toml::from_str::<RestrictedProfile>(profile).unwrap_err();
            assert!(err.to_string().contains(operation), "{profile}\ngot: {err}");
            let builder: CageBuilder = toml::from_str(profile).expect("a trusted load accepts it");
            match RestrictedProfile::try_from(builder) {
                Err(ConfigError::ProfileOperationForbidden { operation: named }) => {
                    assert_eq!(named, *operation, "{profile}");
                }
                other => panic!("{profile}: expected the refusal, got {other:?}"),
            }
        }
    }

    /// Profiles that between them carry every key of the profile format at a
    /// value the restricted policy admits, where it admits one. Only the keys
    /// the list refuses outright are missing.
    #[cfg(feature = "hardening")]
    const RESTRICTED_ADMITTED: [&str; 2] = [
        r#"
rootfs = "/srv/rootfs"
command = "/bin/sh"
args = ["-c", "true"]
network = "none"
hostname = "builder"
workdir = "/build"
stdin = "null"
stdout = "inherit"
stderr = "null"
managed-mounts = true
mount-proc = true
mount-dev = false
mount-tmp = true
resolv-conf = false
base-env = false
stop-with-caller = true
path-lookup = true
present-as = "1000:1000"
run-as = { uid = 1000, gid = 1000, groups = [10, 20] }

[identity-map.ranges]
uid = [{ inside = 0, outside = 100000, count = 65536 }]
gid = [{ inside = 0, outside = 100000, count = 65536 }]

[cgroup]
required = false
memory-max = 536870912
memory-swap-max = 0
pids-max = 64
cpu-max = { quota = 50000, period = 100000 }
cpu-weight = 100

[rlimit]
address-space = "unlimited"
core-dump = 0
cpu-time = { soft = 10, hard = "unlimited" }
data = "unlimited"
file-size = "unlimited"
locked-memory = 65536
open-files = 1024
pending-signals = 64
processes = 64
stack = 8388608

[env]
PATH = "/usr/bin"

[[mount]]
kind = "hide"
target = "/home/user/.ssh"

[[mount]]
kind = "read-only"
target = "/work/.git/hooks"

[hardening]
seccomp = "curated"
landlock-scope = ["signal"]
resolve-unix = true
"#,
        "empty-rootfs = true\n",
    ];

    /// Every key of the profile format is either one a profile the restricted
    /// policy refuses carries or one a profile it admits carries, so a key
    /// added to the format is classified here as the policy classifies it,
    /// and a refusal the list does not name fails an admitted profile.
    #[cfg(feature = "hardening")]
    #[test]
    fn every_profile_key_is_one_the_restricted_policy_refuses_or_admits() {
        let admitted = RESTRICTED_ADMITTED
            .into_iter()
            .chain(OTHER_FORM_PROFILES[..2].iter().copied());
        for profile in admitted.clone() {
            toml::from_str::<RestrictedProfile>(profile)
                .unwrap_or_else(|err| panic!("{profile}\nrefused: {err}"));
        }
        let mut keys: Vec<String> = RESTRICTED_REFUSALS
            .iter()
            .map(|(profile, _)| *profile)
            .chain(admitted)
            .flat_map(|profile| {
                let builder: CageBuilder = toml::from_str(profile).expect("the profile parses");
                profile_keys(&toml::to_string(&builder).expect("the builder serializes"))
            })
            .collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys, EXPECTED_PROFILE_KEYS);
    }

    const FULL_PROFILE: &str = r#"
rootfs = "/srv/rootfs/alpine"
command = "/usr/bin/make"
args = ["-j4", "all"]
network = "host"
hostname = "builder"
workdir = "/build"
stdin = "null"
pid-namespace = false
mount-proc = true
mount-dev = false
mount-tmp = true
resolv-conf = false
stop-with-caller = true

[rlimit]
processes = 64
open-files = "unlimited"
cpu-time = { soft = 10, hard = "unlimited" }

[env]
CARGO_HOME = "/cache/cargo"
RUST_LOG = "debug"

[[mount]]
kind = "bind"
source = "/tmp"
target = "/build"

[[mount]]
kind = "raw"
target = "/raw"
fstype = "tmpfs"
flags = 6
data = "mode=0777"

[[mount]]
kind = "bind"
source = "/etc"
target = "/host-etc"
read-only = true
"#;

    #[test]
    fn a_full_profile_deserializes_into_the_builder() {
        let builder: CageBuilder = toml::from_str(FULL_PROFILE).unwrap();
        assert_eq!(
            builder.rootfs.as_deref(),
            Some(Path::new("/srv/rootfs/alpine"))
        );
        assert_eq!(builder.command.as_deref(), Some(Path::new("/usr/bin/make")));
        assert_eq!(builder.args, ["-j4", "all"]);
        assert_eq!(builder.network, Network::Host);
        assert_eq!(builder.hostname.as_deref(), Some(OsStr::new("builder")));
        assert_eq!(builder.workdir.as_deref(), Some(Path::new("/build")));
        assert!(matches!(builder.stdin, Stdio::Null));
        assert!(!builder.pid_namespace);
        // The profile states all four explicitly, so each reads back as an
        // explicit choice rather than as the default.
        assert_eq!(builder.mount_proc, Some(true));
        assert_eq!(builder.mount_dev, Some(false));
        assert_eq!(builder.mount_tmp, Some(true));
        assert_eq!(builder.resolv_conf, Some(false));
        assert!(builder.stop_with_caller);
        assert_eq!(builder.env.len(), 2);
        // Three mounts in one sequence, and the profile's declaration order is
        // preserved: the raw mount sits between the two binds.
        assert_eq!(builder.mounts.len(), 3);
        assert!(matches!(builder.mounts[0], Mount::Bind(_)));
        assert!(matches!(&builder.mounts[1], Mount::Raw(raw) if raw.flags == 6));
        assert!(matches!(&builder.mounts[2], Mount::Bind(bind) if bind.read_only));
    }

    #[test]
    fn an_overlay_profile_round_trips() {
        // The overlay root is a table with an ordered `lower` array, so a
        // stacked profile survives a load-and-save cycle unchanged.
        let profile = "command = \"/bin/sh\"\n\n\
                       [overlay]\n\
                       lower = [\"/srv/base\", \"/srv/patches\"]\n\
                       upper = \"/var/tmp/scratch\"\n\
                       work = \"/var/tmp/work\"\n";
        let builder: CageBuilder = toml::from_str(profile).expect("the profile parses");
        let overlay = builder.overlay.as_ref().expect("the overlay is set");
        assert_eq!(
            overlay.lower,
            [Path::new("/srv/base"), Path::new("/srv/patches")],
        );
        assert_eq!(
            overlay.upper.as_deref(),
            Some(Path::new("/var/tmp/scratch"))
        );
        assert_eq!(overlay.work.as_deref(), Some(Path::new("/var/tmp/work")));
        // A plain rootfs and an overlay are alternatives; the profile named
        // only the overlay.
        assert!(builder.rootfs.is_none());

        let reparsed: CageBuilder = toml::from_str(&toml::to_string(&builder).unwrap())
            .expect("the serialized profile parses back");
        assert_eq!(reparsed.overlay, builder.overlay);
    }

    #[test]
    fn an_unknown_overlay_key_is_rejected() {
        let profile = "command = \"/bin/sh\"\n\n[overlay]\nlower = [\"/srv/base\"]\n\
                       upperdir = \"/var/tmp/scratch\"\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("upperdir"), "{err}");
    }

    #[test]
    fn a_profile_omitting_everything_is_the_default_builder() {
        let builder: CageBuilder = toml::from_str("").unwrap();
        assert!(builder.rootfs.is_none());
        assert!(builder.command.is_none());
        assert!(builder.pid_namespace);
        // Unstated in the profile, so unset on the builder — and each still
        // resolves to its documented default of `true`.
        assert!(builder.mount_proc.is_none() && builder.mount_dev.is_none());
        assert!(builder.mount_tmp.is_none() && builder.managed_mounts.is_none());
        assert!(builder.get_mount_proc() && builder.get_mount_dev() && builder.get_mount_tmp());
        assert!(builder.get_managed_mounts() && builder.get_base_env());
        assert_eq!(builder.network, Network::Isolated);
        assert!(matches!(builder.stdin, Stdio::Inherit));
        assert!(!builder.stop_with_caller);
    }

    /// `get_resolv_conf` is a consumer-facing opt-out signal, not only an
    /// internal one: `fcage` reads it to decide whether to compose a
    /// `resolv.conf` for a native-stack run, where the library's own bind does
    /// not apply. Either toggle has to turn it off, from a profile as surely as
    /// from a setter.
    #[test]
    fn either_toggle_turns_the_resolv_conf_bind_off() {
        let default: CageBuilder = toml::from_str("").unwrap();
        assert!(default.get_resolv_conf());

        assert!(!Cage::builder().resolv_conf(false).get_resolv_conf());
        assert!(!Cage::builder().managed_mounts(false).get_resolv_conf());

        let from_profile: CageBuilder = toml::from_str("resolv-conf = false").unwrap();
        assert!(!from_profile.get_resolv_conf());
        let managed_off: CageBuilder = toml::from_str("managed-mounts = false").unwrap();
        assert!(!managed_off.get_resolv_conf());
    }

    #[test]
    fn the_builder_round_trips_through_toml() {
        let original: CageBuilder = toml::from_str(FULL_PROFILE).unwrap();
        let serialized = toml::to_string(&original).unwrap();
        let restored: CageBuilder = toml::from_str(&serialized).unwrap();
        assert_eq!(format!("{original:?}"), format!("{restored:?}"));
    }

    #[test]
    fn a_profile_carries_resource_limits_in_both_forms() {
        let builder: CageBuilder = toml::from_str(FULL_PROFILE).unwrap();
        assert_eq!(
            builder.get_rlimits().collect::<Vec<_>>(),
            [
                (Resource::CpuTime, Limit::of(10), Limit::UNLIMITED),
                (Resource::OpenFiles, Limit::UNLIMITED, Limit::UNLIMITED),
                (Resource::Processes, Limit::of(64), Limit::of(64)),
            ],
        );
    }

    #[test]
    fn a_limit_serializes_in_the_shorter_form_that_fits() {
        // The shorthand whenever the two agree, the table only when they
        // differ, so a rendered profile is no wordier than the setting needs.
        let builder = Cage::builder()
            .rlimit(Resource::Processes, 64, 64)
            .rlimit(Resource::OpenFiles, Limit::UNLIMITED, Limit::UNLIMITED)
            .rlimit(Resource::CpuTime, 10, Limit::UNLIMITED);
        let rendered: toml::Table = toml::to_string(&builder).unwrap().parse().unwrap();
        let rlimit = rendered["rlimit"].as_table().expect("an rlimit table");
        assert_eq!(rlimit["processes"].as_integer(), Some(64));
        assert_eq!(rlimit["open-files"].as_str(), Some("unlimited"));
        assert_eq!(
            rlimit["cpu-time"]
                .as_table()
                .map(|pair| (pair["soft"].as_integer(), pair["hard"].as_str())),
            Some((Some(10), Some("unlimited"))),
        );
    }

    #[test]
    fn a_profile_with_no_limits_renders_no_rlimit_table() {
        let rendered = toml::to_string(&Cage::builder().rootfs("/r")).unwrap();
        assert!(!rendered.contains("rlimit"), "{rendered}");
    }

    #[test]
    fn an_explicit_pair_may_agree_and_a_shorthand_may_be_unlimited() {
        // The two forms are alternatives everywhere, not each other's only
        // spelling: the table is accepted for equal limits too.
        let builder: CageBuilder =
            toml::from_str("[rlimit]\nprocesses = { soft = 8, hard = 8 }\nstack = \"unlimited\"\n")
                .unwrap();
        assert_eq!(
            builder.get_rlimits().collect::<Vec<_>>(),
            [
                (Resource::Processes, Limit::of(8), Limit::of(8)),
                (Resource::Stack, Limit::UNLIMITED, Limit::UNLIMITED),
            ],
        );
    }

    #[test]
    fn a_malformed_limit_is_rejected_by_what_it_got_wrong() {
        for (profile, expected) in [
            ("[rlimit]\nnope = 5\n", "unknown variant `nope`"),
            (
                "[rlimit]\ncpu-time = { soft = 1, hrad = 2 }\n",
                "unknown field `hrad`",
            ),
            (
                "[rlimit]\ncpu-time = { soft = 1 }\n",
                "missing field `hard`",
            ),
            ("[rlimit]\ncpu-time = -1\n", "cannot be negative"),
            ("[rlimit]\ncpu-time = \"lots\"\n", "not \"lots\""),
            ("[rlimit]\ncpu-time = true\n", "invalid type: boolean"),
        ] {
            let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
            assert!(err.to_string().contains(expected), "{profile}\ngot: {err}");
        }
    }

    #[test]
    fn a_restricted_profile_accepts_resource_limits() {
        // A limit is set on the command process and can only narrow what the
        // caller already had, so it reaches nothing an untrusted profile is
        // kept away from.
        let restricted: RestrictedProfile =
            toml::from_str("rootfs = \"/srv/r\"\n[rlimit]\nprocesses = 64\n").unwrap();
        assert_eq!(
            restricted.into_builder().get_rlimits().collect::<Vec<_>>(),
            [(Resource::Processes, Limit::of(64), Limit::of(64))],
        );
    }

    #[test]
    fn an_unknown_profile_key_is_rejected() {
        let err =
            toml::from_str::<CageBuilder>("rootfs = \"/r\"\nmispelled-key = true\n").unwrap_err();
        assert!(err.to_string().contains("mispelled-key"), "{err}");
    }

    #[test]
    fn an_unknown_bind_key_is_rejected() {
        let profile =
            "[[mount]]\nkind = \"bind\"\nsource = \"/a\"\ntarget = \"/b\"\nwritable = true\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("writable"), "{err}");
    }

    #[test]
    fn a_mount_without_a_kind_is_rejected() {
        // The tag is what selects the variant, so a mount table that omits it
        // is refused rather than guessed at from the fields present.
        let profile = "[[mount]]\nsource = \"/a\"\ntarget = \"/b\"\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("kind"), "{err}");
    }

    #[test]
    fn an_unknown_mount_kind_is_rejected() {
        let profile = "[[mount]]\nkind = \"sideways\"\ntarget = \"/b\"\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("sideways"), "{err}");
    }

    #[test]
    fn a_field_from_the_other_mount_kind_is_rejected() {
        // The tag narrows which fields are legal: `read-only` belongs to a
        // bind, and naming it under `kind = "raw"` is a mistake worth
        // reporting rather than silently dropping. (`source` and `target` are
        // common to both kinds, so only the distinctive field tests this.)
        let profile = "[[mount]]\nkind = \"raw\"\ntarget = \"/b\"\nread-only = true\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("read-only"), "{err}");
    }

    #[test]
    fn the_mount_order_a_profile_declares_is_preserved() {
        // The whole point of one sequence: a raw mount written between two
        // binds is applied between them, which two kind-segregated arrays
        // could not express.
        let profile = "[[mount]]\nkind = \"raw\"\ntarget = \"/dev\"\nfstype = \"tmpfs\"\n\n\
                       [[mount]]\nkind = \"bind\"\nsource = \"/dev/null\"\ntarget = \"/dev/null\"\n";
        let builder: CageBuilder = toml::from_str(profile).unwrap();
        assert!(matches!(builder.mounts[0], Mount::Raw(_)));
        assert!(matches!(builder.mounts[1], Mount::Bind(_)));

        // And it survives a render-and-reload cycle, so a rendered profile
        // stays a complete record of what will run.
        let rendered = toml::to_string(&builder).unwrap();
        let reloaded: CageBuilder = toml::from_str(&rendered).unwrap();
        assert!(matches!(reloaded.mounts[0], Mount::Raw(_)));
        assert!(matches!(reloaded.mounts[1], Mount::Bind(_)));
    }

    #[test]
    fn a_restricted_profile_accepts_a_host_mapping_free_profile() {
        // The sandbox-shaping fields are all permitted; only host-mapping
        // operations are forbidden.
        let profile = "rootfs = \"/srv/rootfs/alpine\"\ncommand = \"/bin/sh\"\n\
                       network = \"isolated\"\nworkdir = \"/work\"\n";
        let restricted: RestrictedProfile = toml::from_str(profile).unwrap();
        let builder = restricted.into_builder();
        assert_eq!(
            builder.rootfs.as_deref(),
            Some(Path::new("/srv/rootfs/alpine"))
        );
        assert_eq!(builder.command.as_deref(), Some(Path::new("/bin/sh")));
    }

    /// What a restricted profile states reaches an error, and the label a setup
    /// error names its subject by, with its control characters escaped: the
    /// profile is loaded under the policy because nothing vouches for it.
    #[test]
    fn a_restricted_profile_s_values_are_named_escaped() {
        use crate::failure::hostile::{TEXT, assert_escaped};

        // TOML carries a control character only as an escape, which the
        // value's own rendering writes.
        let quoted = |value: String| toml::Value::String(value).to_string();
        let load = |profile: String| -> CageBuilder {
            toml::from_str::<RestrictedProfile>(&profile)
                .expect("the restricted policy admits it")
                .into_builder()
        };
        let refused = |profile: String| {
            let err = load(profile).build().expect_err("the build refuses it");
            assert_escaped(&crate::ErrorChain::new(&err).to_string());
        };

        let sandbox = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n";
        refused(format!(
            "{sandbox}workdir = {}\n",
            quoted(format!("work{TEXT}"))
        ));
        refused(format!(
            "{sandbox}[[mount]]\nkind = \"hide\"\ntarget = {}\n",
            quoted(format!("home{TEXT}")),
        ));
        refused(format!(
            "command = \"/bin/sh\"\nrootfs = {}\n",
            quoted(format!("/nonexistent/{TEXT}")),
        ));
        refused(format!(
            "rootfs = \"/tmp\"\ncommand = {}\n",
            quoted(format!("bin/{TEXT}")),
        ));

        // A path the build accepts is named in the label of the step it fails.
        let cage = load(format!(
            "{sandbox}[[mount]]\nkind = \"hide\"\ntarget = {}\n\n\
             [[mount]]\nkind = \"read-only\"\ntarget = {}\n",
            quoted(format!("/home/{TEXT}")),
            quoted(format!("/work/{TEXT}")),
        ))
        .build()
        .expect("both are paths a launch can act on");
        let labels = &cage.plan.op_labels;
        let named: Vec<&String> = labels
            .iter()
            .filter(|label| label.starts_with("hiding") || label.ends_with("made read-only"))
            .collect();
        assert_eq!(named.len(), 2, "{labels:?}");
        for label in named {
            assert_escaped(label);
        }
        let searched = load(format!(
            "rootfs = \"/tmp\"\ncommand = \"sh\"\npath-lookup = true\n[env]\nPATH = {}\n",
            quoted(format!("/bin/{TEXT}")),
        ))
        .build()
        .expect("a PATH with an absolute entry");
        assert_escaped(&searched.plan.exec_label);
    }

    /// The `[cgroup]` table reads back as the limits it states, and a value the
    /// kernel would refuse is refused at build.
    #[test]
    #[cfg(feature = "serde")]
    fn a_cgroup_table_reads_back_as_its_limits() {
        let profile = "[cgroup]\nparent = \"/sys/fs/cgroup/delegated\"\nmemory-max = 1048576\n\
                       cpu-max = { quota = 50000, period = 100000 }\n";
        let builder: CageBuilder = toml::from_str(profile).expect("the table parses");
        assert_eq!(
            builder.get_cgroup_parent(),
            Some(Path::new("/sys/fs/cgroup/delegated"))
        );
        assert_eq!(
            builder.get_cgroup_limits(),
            [
                CgroupLimit::MemoryMax(1 << 20),
                CgroupLimit::cpu_max(50_000, 100_000)
            ],
        );
        assert!(toml::from_str::<CageBuilder>("[cgroup]\nmemory-limit = 1\n").is_err());
        let unparented: CageBuilder =
            toml::from_str("rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n[cgroup]\npids-max = 8\n")
                .expect("the table parses");
        let err = unparented.build().unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::CgroupLimitInvalid { .. })),
            "a limit without a parent: {err}",
        );
    }

    #[test]
    fn the_profile_key_set_is_pinned() {
        // A deliberate second answer to `the_profile_format_keys_are_what_they_are`,
        // which pins the same interface from the other end. That one reads an
        // exhaustive profile *document* and walks what it renders back as dotted
        // paths; this one drives the *builder's setters* and reads the top level
        // and each nested table. Three things follow from the difference, and
        // each is why both are here:
        //
        // - The document-driven test needs `hardening` for its profile to
        //   parse, so it does not run at all in a build without that feature.
        //   This one does, and the keys it pins are the ones such a build has.
        // - A key reachable from the setters but not from a document, or the
        //   reverse, is a format that does not round-trip. Pinning each
        //   direction separately is what would notice.
        // - A dotted path unions an array's entries, so `mount[].fstype` says
        //   only that *some* mount carries it. Here each `[[mount]]` variant's
        //   key set is asserted on its own, which is what catches a bind entry
        //   that started rendering a raw mount's field.
        //
        // `rootfs`, `overlay`, and `empty-rootfs` are alternatives — setting any
        // clears the others — so the full key set is the union of a
        // plain-rooted, an overlay-rooted, and an empty-rooted profile. The
        // identity keys are rendered together though no build would accept
        // `present-as` beside a range map: a profile renders what it holds,
        // and the build is what refuses the combination.
        let builder = Cage::builder()
            .rootfs("/srv/rootfs")
            .command("/bin/sh")
            .args(["-c", "true"])
            .network(Network::Host)
            .hostname("box")
            .current_dir("/build")
            .stdin(Stdio::Null)
            .pid_namespace(false)
            .mount_proc(false)
            .mount_dev(false)
            .mount_tmp(false)
            .resolv_conf(false)
            .managed_mounts(true)
            .base_env(false)
            .stop_with_caller(true)
            .path_lookup(true)
            .rlimit(Resource::Processes, 64, 64)
            .rlimit(Resource::CpuTime, 10, Limit::UNLIMITED)
            .identity_map(IdentityMap::Subordinate)
            .run_as(Identity::new(250, 250).groups([250]))
            .present_as(PresentedIdentity::ids(1000, 1000))
            .env("K", "V")
            .bind("/host", "/guest")
            .bind_ro("/host-ro", "/guest-ro")
            .raw_mount(
                RawMount::new("/dev/shm")
                    .source("/host-shm")
                    .fstype("tmpfs")
                    .flags(1)
                    .data("mode=1777"),
            )
            .symlink("usr/bin", "/bin");
        let overlaid = builder.clone().overlay(
            Overlay::new()
                .lower("/srv/base")
                .upper("/tmp/upper")
                .work("/tmp/work"),
        );
        let emptied = builder.clone().empty_rootfs();

        let render = |builder: &CageBuilder| -> toml::Table {
            toml::to_string(builder)
                .expect("the builder serializes")
                .parse()
                .expect("the profile is valid TOML")
        };
        let table = render(&builder);
        let overlay_table = render(&overlaid);
        let empty_table = render(&emptied);

        let mut keys: Vec<&str> = table
            .keys()
            .chain(overlay_table.keys())
            .chain(empty_table.keys())
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(
            keys,
            [
                "args",
                "base-env",
                "command",
                "empty-rootfs",
                "env",
                "hostname",
                "identity-map",
                "managed-mounts",
                "mount",
                "mount-dev",
                "mount-proc",
                "mount-tmp",
                "network",
                "overlay",
                "path-lookup",
                "pid-namespace",
                "present-as",
                "resolv-conf",
                "rlimit",
                "rootfs",
                "run-as",
                "stderr",
                "stdin",
                "stdout",
                "stop-with-caller",
                "workdir",
            ],
        );

        // The nested tables are part of the same interface.
        let nested = |key: &str| -> Vec<String> {
            let source = if key == "overlay" {
                &overlay_table
            } else {
                &table
            };
            let mut keys: Vec<String> = match &source[key] {
                toml::Value::Table(t) => t.keys().cloned().collect(),
                toml::Value::Array(a) => match &a[0] {
                    toml::Value::Table(t) => t.keys().cloned().collect(),
                    other => panic!("{key} holds {other:?}"),
                },
                other => panic!("{key} is {other:?}"),
            };
            keys.sort();
            keys
        };
        assert_eq!(nested("overlay"), ["lower", "upper", "work"]);
        assert_eq!(nested("run-as"), ["gid", "groups", "uid"]);
        // The `[rlimit]` keys are resource names rather than a fixed set, so
        // what is pinned here is the pair of value forms: the shorthand for a
        // resource whose limits agree, the table for one whose limits differ.
        assert_eq!(nested("rlimit"), ["cpu-time", "processes"]);
        // The `[[mount]]` array is heterogeneous, so each variant's key set is
        // pinned separately, `kind` tag included: it is as much part of the
        // interface as the fields it selects between.
        let mount_entry = |index: usize| -> Vec<String> {
            let toml::Value::Array(mounts) = &table["mount"] else {
                panic!("mount is not an array");
            };
            let toml::Value::Table(entry) = &mounts[index] else {
                panic!("mount entry {index} is not a table");
            };
            let mut keys: Vec<String> = entry.keys().cloned().collect();
            keys.sort();
            keys
        };
        assert_eq!(mount_entry(0), ["kind", "read-only", "source", "target"]);
        assert_eq!(mount_entry(1), ["kind", "read-only", "source", "target"]);
        assert_eq!(
            mount_entry(2),
            ["data", "flags", "fstype", "kind", "source", "target"],
        );
        assert_eq!(mount_entry(3), ["kind", "path", "target"]);
        // Each alternative root renders only its own key, so the three are
        // never written into one profile.
        assert!(table.contains_key("rootfs") && !table.contains_key("empty-rootfs"));
        assert!(!empty_table.contains_key("rootfs") && !empty_table.contains_key("overlay"));
    }

    #[test]
    fn a_profile_naming_both_roots_is_refused() {
        // The setters keep the two exclusive, but nothing stops a profile from
        // carrying both keys. Taking the rootfs would drop the overlay's whole
        // lower stack; taking the overlay would ignore the stated rootfs. The
        // contradiction is the author's to resolve.
        let profile = "rootfs = \"/srv/alpine\"\ncommand = \"/bin/sh\"\n\n\
                       [overlay]\n\
                       lower = [\"/srv/base\", \"/srv/patches\"]\n\
                       upper = \"/tmp/upper\"\n";
        let builder: CageBuilder = toml::from_str(profile).expect("the profile parses");
        let err = builder.build().unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::RootContradiction)),
            "{err}"
        );
    }

    #[test]
    fn a_profile_naming_an_empty_root_beside_another_root_is_refused() {
        for other in [
            "rootfs = \"/srv/alpine\"\n",
            "[overlay]\nlower = [\"/srv/base\"]\n",
        ] {
            let profile = format!("empty-rootfs = true\ncommand = \"/bin/sh\"\n{other}");
            let builder: CageBuilder = toml::from_str(&profile).expect("the profile parses");
            let err = builder.build().unwrap_err();
            assert!(
                matches!(err, Error::Config(ConfigError::RootContradiction)),
                "{err}"
            );
        }
    }

    #[test]
    fn a_restricted_profile_accepts_an_empty_root() {
        // A tmpfs of the sandbox's own maps nothing of the host in.
        let profile = "empty-rootfs = true\ncommand = \"/bin/sh\"\n";
        let builder = toml::from_str::<RestrictedProfile>(profile)
            .expect("the restricted policy admits an empty root")
            .into_builder();
        assert!(builder.get_empty_rootfs());
        let inputs = builder.build().expect("a valid sandbox").resolved_inputs();
        assert!(matches!(inputs.root, crate::ResolvedRoot::Empty));
    }

    #[test]
    fn a_profile_naming_the_host_root_beside_another_root_is_refused() {
        for other in [
            "rootfs = \"/srv/alpine\"\n",
            "empty-rootfs = true\n",
            "[overlay]\nlower = [\"/srv/base\"]\n",
        ] {
            let profile = format!("host-rootfs = true\ncommand = \"/bin/sh\"\n{other}");
            let builder: CageBuilder = toml::from_str(&profile).expect("the profile parses");
            let err = builder.build().unwrap_err();
            assert!(
                matches!(err, Error::Config(ConfigError::RootContradiction)),
                "{err}"
            );
        }
    }

    /// The host's whole tree is a host resource mapped in, and a path taken
    /// back from its hides would be honored by a consumer's own `host_rootfs`
    /// after loading. A hidden path and a read-only one only take away.
    #[test]
    fn a_restricted_profile_rejects_the_host_root_and_admits_hiding() {
        for (profile, operation) in [
            (
                "host-rootfs = true\ncommand = \"/bin/sh\"\n",
                "the host's own root (host-rootfs)",
            ),
            (
                "rootfs = \"/srv/rootfs\"\nreveal = [\"/run\"]\ncommand = \"/bin/sh\"\n",
                "a path the host's root hides taken back (reveal)",
            ),
            #[cfg(feature = "hardening")]
            (
                "rootfs = \"/srv/rootfs\"\ncommand = \"/bin/sh\"\n\
                 [hardening]\nresolve-unix = false\n",
                "the unix-socket restriction turned off (resolve-unix = false)",
            ),
        ] {
            let builder: CageBuilder = toml::from_str(profile).expect("a trusted load accepts it");
            match RestrictedProfile::try_from(builder) {
                Err(ConfigError::ProfileOperationForbidden { operation: named }) => {
                    assert_eq!(named, operation);
                }
                other => panic!("{profile}: {other:?}"),
            }
        }
        let profile = "empty-rootfs = true\ncommand = \"/bin/sh\"\n\
                       [[mount]]\nkind = \"hide\"\ntarget = \"/home\"\n\
                       [[mount]]\nkind = \"read-only\"\ntarget = \"/etc\"\n";
        let builder = toml::from_str::<RestrictedProfile>(profile)
            .expect("the restricted policy admits a hidden path and a read-only one")
            .into_builder();
        assert!(matches!(
            builder.get_mounts(),
            [Mount::Hide(_), Mount::ReadOnly(_)]
        ));
    }

    /// Under the host's own root, a link of the caller's can be made only
    /// inside a filesystem the sandbox mounts, and a bind target outside one
    /// creates nothing: its directories are not made, and one missing is
    /// refused.
    #[test]
    fn the_host_root_creates_mount_targets_only_inside_the_sandbox_s_own_filesystems() {
        let refused = Cage::builder()
            .host_rootfs()
            .symlink("/usr/bin/env", "/usr/local/bin/ferroday-cage-test-link")
            .command("/bin/true")
            .build()
            .unwrap_err();
        assert!(
            matches!(
                &refused,
                Error::Config(ConfigError::SymlinkInHostRoot { path, .. })
                    if path == Path::new("/usr/local/bin/ferroday-cage-test-link")
            ),
            "{refused:?}"
        );
        assert!(
            std::error::Error::source(&refused)
                .and_then(std::error::Error::source)
                .is_none(),
            "nothing failed beneath the refusal: {refused:?}",
        );

        let cage = Cage::builder()
            .host_rootfs()
            .symlink("/usr/bin/env", "/tmp/links/env")
            .bind_ro("/etc/passwd", "/home/user/passwd")
            .bind_ro("/usr", "/usr")
            .command("/bin/true")
            .build()
            .expect("targets inside the sandbox's own filesystems, or present on the host");
        let op = |label: &str| {
            let at = cage
                .plan
                .op_labels
                .iter()
                .position(|named| named.contains(label))
                .expect("the op is planned");
            &cage.plan.ops[at]
        };
        // The link's directory is made inside the managed /tmp.
        let link = op("symlink at \"/tmp/links/env\"");
        assert_eq!(link.dirs.len(), 1, "{:?}", link.dirs);
        assert_eq!(link.dirs[0].leaf.as_bytes(), b"links");
        // The file target is made inside the hidden /home, its directory too.
        let file = op("/home/user/passwd");
        assert_eq!(file.dirs.len(), 1, "{:?}", file.dirs);
        assert_eq!(file.create_file.as_deref(), Some(c"home/user/passwd"));
        // The host's own /usr is the target, and nothing is made for it.
        let usr = op("\"/usr\" at \"/usr\"");
        assert!(usr.dirs.is_empty() && usr.create_file.is_none());
    }

    /// A link is made before any confinement applies, and on a plain rootfs it
    /// stays on the host, so a restricted profile carries none, whatever root
    /// it names.
    #[test]
    fn a_restricted_profile_rejects_a_symbolic_link() {
        let link = "[[mount]]\nkind = \"symlink\"\ntarget = \"/var/tmp/x.so\"\n\
                    path = \"/etc/ld.so.preload\"\n";
        for root in ["rootfs = \"/srv/rootfs\"\n", "empty-rootfs = true\n"] {
            let profile = format!("{root}command = \"/bin/sh\"\n{link}");
            let err = toml::from_str::<RestrictedProfile>(&profile).unwrap_err();
            assert!(err.to_string().contains("a symbolic link"), "{err}");

            let builder: CageBuilder = toml::from_str(&profile).expect("a trusted load accepts it");
            assert!(matches!(
                RestrictedProfile::try_from(builder),
                Err(ConfigError::ProfileOperationForbidden {
                    operation: "a symbolic link"
                })
            ));
        }
    }

    /// What only removes stays allowed: a seccomp policy, a full capability
    /// drop, and the Landlock scopes.
    #[cfg(feature = "hardening")]
    #[test]
    fn a_restricted_profile_accepts_the_hardening_that_only_removes() {
        use crate::hardening::LandlockScope;

        for hardening in [
            "drop-caps = true\n",
            "seccomp = \"curated\"\n",
            "landlock-scope = [\"signal\"]\n",
            "[hardening.seccomp]\ndeny = [\"ptrace\"]\n",
        ] {
            let profile = format!("rootfs = \"/srv/rootfs\"\n[hardening]\n{hardening}");
            toml::from_str::<RestrictedProfile>(&profile)
                .unwrap_or_else(|err| panic!("{profile}\nrefused: {err}"));
        }

        let profile = "rootfs = \"/srv/rootfs\"\n[hardening]\ndrop-caps = true\n\
                       landlock-scope = [\"signal\", \"abstract-unix-socket\"]\n\
                       seccomp = \"curated\"\n";
        let builder = toml::from_str::<RestrictedProfile>(profile)
            .expect("each of these only removes")
            .into_builder();
        assert_eq!(builder.get_keep_capabilities(), Some(&[][..]));
        assert_eq!(
            builder.get_landlock_scope().count(),
            LandlockScope::ALL.len()
        );
        assert!(builder.get_seccomp().is_some());
    }

    #[test]
    fn an_empty_root_and_its_links_round_trip() {
        let builder = Cage::builder()
            .empty_rootfs()
            .symlink("usr/lib", "/lib")
            .command("/bin/sh");
        let rendered = toml::to_string(&builder).expect("the builder serializes");
        assert!(rendered.starts_with("empty-rootfs = true\n"), "{rendered}");
        let reparsed: CageBuilder = toml::from_str(&rendered).expect("the profile parses back");
        assert!(reparsed.get_empty_rootfs());
        let [Mount::Symlink(symlink)] = reparsed.get_mounts() else {
            panic!("one symlink: {:?}", reparsed.get_mounts());
        };
        assert_eq!(symlink.get_target(), Path::new("usr/lib"));
        assert_eq!(symlink.get_path(), Path::new("/lib"));
        // A plain root renders no empty-rootfs key at all.
        let plain = toml::to_string(&Cage::builder().rootfs("/srv")).unwrap();
        assert!(!plain.contains("empty-rootfs"), "{plain}");
    }

    #[test]
    fn an_overlay_without_a_lower_names_what_is_missing() {
        // "no rootfs was provided" reads as an oversight to an author who
        // provided an overlay table and forgot its base layer.
        let err = Cage::builder()
            .overlay(Overlay::new().upper("/tmp/upper"))
            .command("/bin/sh")
            .build()
            .unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::OverlayLowerMissing)),
            "{err}"
        );
    }

    /// Resolves and creates one layer directory as an overlay build does,
    /// keeping whatever it creates.
    fn prepare_layer(layer: OverlayLayer, path: &Path) -> Result<PathBuf, Error> {
        let mut created = CreatedDirs::default();
        let at = layer_path(layer, path)?;
        created
            .create_all(&at.parent)
            .map_err(|err| overlay_io(layer, &at.parent, err))?;
        create_layer_dir(layer, &at, &mut created)?;
        created.keep();
        Ok(at.path())
    }

    #[test]
    fn an_overlay_layer_directory_is_created_fresh_and_owned() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = Scratch::new("overlay-layer-dir");

        // A layer directory the library creates: made here, at the stated mode.
        // (The umask is not set here to prove the chmod that follows the
        // `mkdir`: it is process-global, and this suite runs its tests in
        // parallel threads, so narrowing it would reach every directory another
        // test created meanwhile.)
        let fresh = scratch.join("nested/fresh");
        let prepared = prepare_layer(OverlayLayer::Upper, &fresh).unwrap();
        assert_eq!(prepared, std::fs::canonicalize(&fresh).unwrap());
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&fresh), OVERLAY_DIR_MODE);

        // Preparing it a second time adopts it: it is a directory this user
        // owns, which is exactly what the first call left. An adopted directory
        // keeps the mode its owner gave it — only a directory this created is
        // chmod-ed, so a caller reusing a layer of its own does not find the
        // mode changed underneath it.
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            prepare_layer(OverlayLayer::Upper, &fresh).unwrap(),
            prepared
        );
        assert_eq!(mode(&fresh), 0o700, "an adopted layer keeps its own mode");

        // A symbolic link at the path is refused rather than followed. Left
        // followed, `upperdir=` would name the destination and every write the
        // sandbox made would land there instead.
        let destination = scratch.join("elsewhere");
        std::fs::create_dir(&destination).unwrap();
        let planted = scratch.join("planted");
        std::os::unix::fs::symlink(&destination, &planted).unwrap();
        let err = prepare_layer(OverlayLayer::Upper, &planted).unwrap_err();
        assert!(
            matches!(
                err,
                Error::Config(ConfigError::OverlayDirUnowned {
                    layer: OverlayLayer::Upper,
                    ..
                })
            ),
            "{err}"
        );

        // So is an entry that is not a directory at all.
        let file = scratch.join("file");
        std::fs::write(&file, b"").unwrap();
        let err = prepare_layer(OverlayLayer::Work, &file).unwrap_err();
        assert!(
            matches!(
                err,
                Error::Config(ConfigError::OverlayDirUnowned {
                    layer: OverlayLayer::Work,
                    ..
                })
            ),
            "{err}"
        );
    }

    #[test]
    fn an_overlay_layer_at_the_filesystem_root_is_refused_by_its_layer() {
        // `/` has no parent, so there is nowhere for the work directory beside
        // the upper or for the host preflight's scratch entries — and an upper
        // there would put the sandbox's writes over the whole host root. The
        // refusal names the layer the path was given for.
        let scratch = Scratch::new("overlay-layer-root");
        let err = Cage::builder()
            .overlay_rootfs(&*scratch, "/")
            .command("/bin/sh")
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::OverlayLayerIsRoot { layer, path }) => {
                assert_eq!(
                    (layer, path.as_path()),
                    (OverlayLayer::Upper, Path::new("/"))
                );
            }
            other => panic!("unexpected error: {other}"),
        }

        let err = Cage::builder()
            .overlay(
                Overlay::new()
                    .lower(&*scratch)
                    .upper(scratch.join("upper"))
                    .work("/"),
            )
            .command("/bin/sh")
            .build()
            .unwrap_err();
        match err {
            Error::Config(ConfigError::OverlayLayerIsRoot { layer, path }) => {
                assert_eq!(
                    (layer, path.as_path()),
                    (OverlayLayer::Work, Path::new("/"))
                );
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(
            !scratch.join("upper").exists(),
            "a refused build leaves no upper behind"
        );
    }

    #[test]
    fn a_build_refused_for_any_reason_leaves_no_layer_directory_behind() {
        // The layer directories are the one thing a build creates on the host,
        // so they are created once everything else has been accepted.
        let scratch = Scratch::new("overlay-refused");
        let base = scratch.join("base");
        std::fs::create_dir(&base).unwrap();
        let upper = scratch.join("fresh/parent/upper");
        let err = Cage::builder()
            .overlay_rootfs(&base, &upper)
            .command("/bin/sh")
            .hostname("")
            .build()
            .unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::HostnameInvalid { .. })),
            "{err}"
        );
        assert!(!scratch.join("fresh").exists(), "nothing was created");

        // A refusal inside the overlay's own preparation, after the parents of
        // the upper were created, takes them away again. Options the kernel
        // would cut short are refused before the layers themselves exist.
        // Two lowers whose paths each fit a path, and together do not fit a
        // page of options.
        let deep = |name: &str| {
            let mut deep = scratch.join(name);
            while deep.as_os_str().len() < 2200 {
                deep.push("l".repeat(200));
            }
            std::fs::create_dir_all(&deep).unwrap();
            deep
        };
        let (first, second) = (deep("first"), deep("second"));
        let err = Cage::builder()
            .overlay(
                Overlay::new()
                    .lower(&base)
                    .lower(&first)
                    .lower(&second)
                    .upper(&upper),
            )
            .command("/bin/sh")
            .build()
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Config(ConfigError::OverlayOptionsTooLong { .. })
            ),
            "{err}"
        );
        assert!(
            !scratch.join("fresh").exists(),
            "the parents created for the upper are removed again"
        );
    }

    #[test]
    fn a_layer_refused_after_creation_is_removed_again() {
        // A caller-named work directory on another filesystem is refused once
        // both layer directories exist, since the device comparison needs them;
        // the refusal takes both away again, and the parents created for them.
        let scratch = Scratch::new("overlay-exdev");
        let other = Path::new("/dev/shm");
        let device = |path: &Path| rustix::fs::stat(path).map(|stat| stat.st_dev);
        let (Ok(here), Ok(there)) = (device(&scratch), device(other)) else {
            ferroday_cage_testkit::require::premise_unmet(
                "no second filesystem to place the work directory on",
            );
            return;
        };
        if here == there {
            ferroday_cage_testkit::require::premise_unmet(
                "/dev/shm shares the scratch directory's filesystem",
            );
            return;
        }
        let elsewhere = other.join(format!("fcage-exdev-{}", crate::host::unique_hex()));
        let base = scratch.join("base");
        std::fs::create_dir(&base).unwrap();
        let upper = scratch.join("fresh/upper");
        let built = Cage::builder()
            .overlay(
                Overlay::new()
                    .lower(&base)
                    .upper(&upper)
                    .work(elsewhere.join("work")),
            )
            .command("/bin/sh")
            .build();
        let leftover = elsewhere.exists();
        let _ = crate::provision::remove_tree(&elsewhere, &IdentityMap::Single, None);
        match built {
            Err(Error::Config(ConfigError::OverlayWorkOnAnotherFilesystem { work, .. })) => {
                assert_eq!(work, elsewhere.join("work"));
            }
            Err(Error::Config(ConfigError::OverlayUnavailable { blocker })) => {
                ferroday_cage_testkit::require::OVERLAY.skip(format!(
                    "an unprivileged overlay is unavailable here: {blocker}"
                ));
                return;
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert!(!leftover, "the work directory and its parent are removed");
        assert!(
            !scratch.join("fresh").exists(),
            "so are the upper and its parent"
        );
    }

    #[test]
    fn a_layer_path_the_kernel_would_unescape_mounts_the_directory_named() {
        // Overlayfs unescapes every layer path, so `up\x` written verbatim is
        // mounted as `upx`. The options name it escaped, which is the directory
        // whose ownership the build checked.
        let scratch = Scratch::new("overlay-escape");
        let base = scratch.join("ba:se");
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(scratch.join("upx")).unwrap();
        let built = Cage::builder()
            .overlay_rootfs(&base, scratch.join(r"up\x"))
            .command("/bin/sh")
            .build();
        let cage = match built {
            Ok(cage) => cage,
            Err(Error::Config(ConfigError::OverlayUnavailable { blocker })) => {
                ferroday_cage_testkit::require::OVERLAY.skip(format!(
                    "an unprivileged overlay is unavailable here: {blocker}"
                ));
                return;
            }
            Err(err) => panic!("unexpected error: {err}"),
        };
        let RootPlan::Overlay { overlay, .. } = &cage.plan.root else {
            panic!("an overlay-rooted cage plans an overlay root");
        };
        let options = overlay.options.to_str().unwrap();
        let canonical = std::fs::canonicalize(&*scratch).unwrap();
        let canonical = canonical.to_str().unwrap();
        assert_eq!(
            options,
            format!(
                r"lowerdir={canonical}/ba\:se,upperdir={canonical}/up\\x,workdir={canonical}/.up\\x.work,userxattr"
            ),
        );

        // A comma is refused rather than escaped.
        let err = Cage::builder()
            .overlay_rootfs(&base, scratch.join("up,per"))
            .command("/bin/sh")
            .build()
            .unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::OverlayPathInvalid { .. })),
            "{err}"
        );
        assert!(
            !scratch.join("up,per").exists(),
            "and nothing is created for it"
        );
    }

    #[test]
    fn overriding_the_rootfs_clears_an_overlay() {
        // A consumer overriding an untrusted profile's rootfs must not be left
        // with the overlay that profile configured; the last root call wins.
        let builder = Cage::builder()
            .overlay_rootfs("/srv/base", "/tmp/upper")
            .rootfs("/srv/rootfs/alpine");
        assert_eq!(builder.overlay, None);
        assert_eq!(
            builder.rootfs.as_deref(),
            Some(Path::new("/srv/rootfs/alpine"))
        );
    }

    #[test]
    fn profile_env_composes_with_builder_env_calls() {
        let builder: CageBuilder =
            toml::from_str("[env]\nA = \"profile\"\nB = \"profile\"\n").unwrap();
        let cage = builder
            .rootfs("/tmp")
            .command("/bin/sh")
            .env("B", "override")
            .build()
            .unwrap();
        let env: Vec<&str> = cage
            .plan
            .env
            .iter()
            .map(|entry| entry.to_str().unwrap())
            .collect();
        assert!(env.contains(&"A=profile"));
        assert!(env.contains(&"B=override"));
    }

    #[test]
    fn a_deserialized_profile_builds_a_runnable_plan() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\nstdin = \"null\"\n";
        let builder: CageBuilder = toml::from_str(profile).unwrap();
        let cage = builder.build().unwrap();
        assert!(matches!(cage.plan.stdin, StdioPlan::Null));
    }

    #[test]
    fn an_identity_map_profile_round_trips() {
        let profile = r#"
rootfs = "/tmp"
command = "/bin/sh"

[identity-map.ranges]
uid = [{ inside = 0, outside = 1000, count = 1 }, { inside = 1, outside = 100000, count = 65536 }]
gid = [{ inside = 0, outside = 1000, count = 1 }]

[run-as]
uid = 250
gid = 250
groups = [250, 100]
"#;
        let original: CageBuilder = toml::from_str(profile).unwrap();
        match &original.identity_map {
            IdentityMap::Ranges { uid, gid, .. } => {
                assert_eq!(uid.len(), 2);
                assert_eq!(uid[1].outside, 100000);
                assert_eq!(gid.len(), 1);
            }
            other => panic!("expected ranges, got {other:?}"),
        }
        let run_as = original.run_as.as_ref().unwrap();
        assert_eq!(run_as.uid, 250);
        assert_eq!(run_as.groups, [250, 100]);

        let serialized = toml::to_string(&original).unwrap();
        let restored: CageBuilder = toml::from_str(&serialized).unwrap();
        assert_eq!(format!("{original:?}"), format!("{restored:?}"));
        assert!(serialized.contains("identity-map"), "{serialized}");
        assert!(serialized.contains("run-as"), "{serialized}");
    }

    #[cfg(feature = "subid")]
    #[test]
    fn a_subordinate_identity_map_profile_round_trips() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\nidentity-map = \"subordinate\"\n";
        let original: CageBuilder = toml::from_str(profile).unwrap();
        assert_eq!(original.identity_map, IdentityMap::Subordinate);
        let serialized = toml::to_string(&original).unwrap();
        assert!(
            serialized.contains("identity-map = \"subordinate\""),
            "{serialized}"
        );
        let restored: CageBuilder = toml::from_str(&serialized).unwrap();
        assert_eq!(format!("{original:?}"), format!("{restored:?}"));
    }

    /// A subordinate profile loads in every build, and the build decides: a
    /// configured delegate that reports an allocation establishes it, and
    /// without one a build lacking the `subid` feature refuses it by name
    /// rather than downgrading the identity posture.
    #[test]
    fn a_subordinate_profile_loads_and_the_build_decides() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\nidentity-map = \"subordinate\"\n";
        let builder: CageBuilder = toml::from_str(profile).expect("every identity form loads");
        assert_eq!(builder.identity_map, IdentityMap::Subordinate);
        builder
            .clone()
            .id_mapper(tests::FakeMapper)
            .build()
            .expect("a delegate that reports an allocation establishes it");

        #[cfg(not(feature = "subid"))]
        {
            let err = builder.build().unwrap_err();
            assert!(
                matches!(
                    &err,
                    Error::Config(ConfigError::IdentityMapUnavailable { reason, .. })
                        if reason.contains("`subid` feature")
                ),
                "{err}",
            );
        }
    }

    #[test]
    fn the_default_identity_map_stays_out_of_the_profile() {
        let builder: CageBuilder = toml::from_str("rootfs = \"/r\"\ncommand = \"/c\"\n").unwrap();
        let serialized = toml::to_string(&builder).unwrap();
        assert!(!serialized.contains("identity-map"), "{serialized}");
        assert!(!serialized.contains("run-as"), "{serialized}");
    }

    #[test]
    fn an_unknown_identity_map_form_is_rejected() {
        let profile = "rootfs = \"/r\"\ncommand = \"/c\"\nidentity-map = \"everything\"\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("everything"), "{err}");
    }

    /// A profile spells a presented identity as `own` or `UID:GID`, the form
    /// the type renders and parses, and reads back what it wrote.
    #[test]
    fn a_presented_identity_round_trips_through_a_profile() {
        for (value, presented) in [
            ("own", PresentedIdentity::Own),
            (
                "1000:100",
                PresentedIdentity::Ids {
                    uid: 1000,
                    gid: 100,
                },
            ),
        ] {
            let profile = format!("rootfs = \"/r\"\ncommand = \"/c\"\npresent-as = \"{value}\"\n");
            let builder: CageBuilder = toml::from_str(&profile).expect("the profile parses");
            assert_eq!(builder.get_present_as(), Some(presented));
            let rendered = toml::to_string(&builder).expect("the builder serializes");
            assert!(
                rendered.contains(&format!("present-as = \"{value}\"\n")),
                "{rendered}"
            );
        }
        let err = toml::from_str::<CageBuilder>(
            "rootfs = \"/r\"\ncommand = \"/c\"\npresent-as = \"root\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("UID:GID"), "{err}");
    }

    #[test]
    fn an_unknown_run_as_key_is_rejected() {
        let profile =
            "rootfs = \"/r\"\ncommand = \"/c\"\n[run-as]\nuid = 1\ngid = 1\nshell = \"/bin/sh\"\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("shell"), "{err}");
    }

    #[test]
    fn an_unknown_id_range_key_is_rejected() {
        let profile = "rootfs = \"/r\"\ncommand = \"/c\"\n\
                       [identity-map.ranges]\n\
                       uid = [{ inside = 0, outside = 1000, count = 1, extra = 1 }]\n\
                       gid = [{ inside = 0, outside = 1000, count = 1 }]\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("extra"), "{err}");
    }

    /// A buildable profile carrying a full hardening posture: a capability
    /// keep-list, a seccomp denylist named by syscall, and Landlock filesystem
    /// and network grants.
    #[cfg(feature = "hardening")]
    const HARDENED_PROFILE: &str = r#"
rootfs = "/tmp"
command = "/bin/sh"

[hardening]
keep-caps = ["net-bind-service", "sys-chroot"]

[hardening.seccomp]
deny = ["mount", "ptrace"]

[[hardening.landlock-fs]]
access = "rx"
path = "/usr"

[[hardening.landlock-fs]]
access = "rwx"
path = "/work"

[[hardening.landlock-net]]
access = "c"
port = 443

[[hardening.landlock-net]]
access = "bc"
port = 8080
"#;

    #[cfg(feature = "hardening")]
    #[test]
    fn a_hardening_profile_lowers_into_the_plan() {
        let builder: CageBuilder = toml::from_str(HARDENED_PROFILE).unwrap();
        let cage = builder.build().unwrap();
        let hardening = &cage.plan.hardening;
        // The filesystem and network grants each lower into rules and a ruleset
        // that governs the corresponding modeled access set.
        assert_eq!(hardening.landlock.len(), 2);
        assert_ne!(hardening.landlock_handled, 0);
        assert_eq!(hardening.landlock_net.len(), 2);
        assert_ne!(hardening.landlock_net_handled, 0);
        // The denylist compiled to a program, and the keep-list lowered to a
        // non-empty capability mask.
        assert!(hardening.seccomp.is_some());
        assert!(matches!(hardening.keep_caps, Some(bits) if bits != 0));
    }

    /// A consumer vetting a profile it did not write reads its hardening
    /// posture back through the getters, as it reads every other setting.
    #[cfg(feature = "hardening")]
    #[test]
    fn a_profiles_hardening_posture_reads_back_through_the_getters() {
        use crate::hardening::{Capability, FsAccess, LandlockScope, NetAccess, SeccompPolicy};

        let profile = format!("{HARDENED_PROFILE}\n");
        let profile = profile.replacen(
            "[hardening]\n",
            "[hardening]\nlandlock-scope = [\"abstract-unix-socket\", \"signal\"]\n",
            1,
        );
        let builder: CageBuilder = toml::from_str(&profile).expect("the profile loads");

        let fs: Vec<(FsAccess, &Path)> = builder.get_landlock_fs().collect();
        assert_eq!(
            fs,
            [
                (FsAccess::READ | FsAccess::EXECUTE, Path::new("/usr")),
                (
                    FsAccess::READ | FsAccess::WRITE | FsAccess::EXECUTE,
                    Path::new("/work")
                ),
            ],
        );
        let net: Vec<(NetAccess, u16)> = builder.get_landlock_net().collect();
        assert_eq!(
            net,
            [
                (NetAccess::CONNECT, 443),
                (NetAccess::BIND | NetAccess::CONNECT, 8080),
            ],
        );
        let scopes: Vec<LandlockScope> = builder.get_landlock_scope().collect();
        assert_eq!(
            scopes,
            [LandlockScope::Signal, LandlockScope::AbstractUnixSocket]
        );
        assert!(matches!(
            builder.get_seccomp(),
            Some(SeccompPolicy::Rules(_))
        ));
        assert_eq!(
            builder.get_keep_capabilities(),
            Some(&[Capability::NetBindService, Capability::SysChroot][..]),
        );

        // The defaults: nothing granted, scoped, filtered, or dropped.
        let plain = Cage::builder().rootfs("/tmp").command("/bin/sh");
        assert_eq!(plain.get_landlock_fs().count(), 0);
        assert_eq!(plain.get_landlock_net().count(), 0);
        assert_eq!(plain.get_landlock_scope().count(), 0);
        assert!(plain.get_seccomp().is_none());
        assert_eq!(plain.get_keep_capabilities(), None);
        // Dropping every capability reads back as keeping none.
        assert_eq!(
            plain.drop_all_capabilities().get_keep_capabilities(),
            Some(&[][..]),
        );
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_hardening_profile_round_trips_through_toml() {
        let original: CageBuilder = toml::from_str(HARDENED_PROFILE).unwrap();
        let serialized = toml::to_string(&original).unwrap();
        let restored: CageBuilder = toml::from_str(&serialized).unwrap();
        assert_eq!(format!("{original:?}"), format!("{restored:?}"));
        // The seccomp rules table, the capability list, and both Landlock grant
        // arrays survive the trip.
        assert!(serialized.contains("[hardening.seccomp]"), "{serialized}");
        assert!(serialized.contains("keep-caps"), "{serialized}");
        assert!(serialized.contains("mount"), "{serialized}");
        assert!(
            serialized.contains("[[hardening.landlock-fs]]"),
            "{serialized}"
        );
        assert!(
            serialized.contains("[[hardening.landlock-net]]"),
            "{serialized}"
        );
        assert!(serialized.contains("port = 443"), "{serialized}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn the_curated_and_drop_caps_forms_round_trip() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [hardening]\ndrop-caps = true\nseccomp = \"curated\"\n";
        let original: CageBuilder = toml::from_str(profile).unwrap();
        let serialized = toml::to_string(&original).unwrap();
        assert!(serialized.contains("drop-caps = true"), "{serialized}");
        assert!(serialized.contains("seccomp = \"curated\""), "{serialized}");
        let restored: CageBuilder = toml::from_str(&serialized).unwrap();
        assert_eq!(format!("{original:?}"), format!("{restored:?}"));
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn an_allowlist_seccomp_profile_round_trips() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [hardening.seccomp]\nallow = [\"read\", \"write\", \"exit_group\"]\n";
        let original: CageBuilder = toml::from_str(profile).unwrap();
        let serialized = toml::to_string(&original).unwrap();
        let restored: CageBuilder = toml::from_str(&serialized).unwrap();
        assert_eq!(format!("{original:?}"), format!("{restored:?}"));
        assert!(serialized.contains("allow"), "{serialized}");
        assert!(serialized.contains("exit_group"), "{serialized}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn an_unknown_syscall_name_is_rejected() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [hardening.seccomp]\ndeny = [\"not_a_syscall\"]\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("not_a_syscall"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn an_invalid_access_string_is_rejected() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [[hardening.landlock-fs]]\naccess = \"rq\"\npath = \"/usr\"\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("access"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn an_invalid_net_access_string_is_rejected() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [[hardening.landlock-net]]\naccess = \"z\"\nport = 443\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("access"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_net_port_above_the_u16_range_is_rejected() {
        // The profile's port is a u16, so a value the kernel would reject is
        // refused at deserialization instead.
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [[hardening.landlock-net]]\naccess = \"c\"\nport = 70000\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("70000"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn drop_caps_and_keep_caps_together_are_rejected() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [hardening]\ndrop-caps = true\nkeep-caps = [\"chown\"]\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("keep-caps"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn an_empty_keep_caps_list_is_rejected() {
        // An empty keep-list is ambiguous: it must not silently mean "keep
        // everything" when a reader might intend "drop everything".
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n[hardening]\nkeep-caps = []\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("drop-caps"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn an_unknown_hardening_key_is_rejected() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n[hardening]\nbogus = true\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_precompiled_seccomp_program_cannot_be_serialized() {
        use crate::{SeccompPolicy, SockFilter};
        let builder =
            Cage::builder()
                .rootfs("/tmp")
                .command("/bin/sh")
                .seccomp(SeccompPolicy::Program(vec![SockFilter {
                    code: 6,
                    jt: 0,
                    jf: 0,
                    k: 0,
                }]));
        let err = toml::to_string(&builder).unwrap_err();
        assert!(err.to_string().contains("precompiled"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_seccomp_policy_listing_no_syscall_cannot_be_serialized() {
        use crate::{SeccompPolicy, SeccompRules};
        // The table names its side by listing one, so a policy with neither
        // side populated renders as a bare `[hardening.seccomp]` -- a document
        // the reader then refuses. Reported on the way out instead, which is
        // what "a serialization error, never a silent omission" means.
        for policy in [
            SeccompPolicy::Rules(SeccompRules::allowing([])),
            SeccompPolicy::Rules(SeccompRules::denying([])),
        ] {
            let builder = Cage::builder()
                .rootfs("/tmp")
                .command("/bin/sh")
                .seccomp(policy);
            let err = toml::to_string(&builder).expect_err("an empty rule set is refused");
            assert!(err.to_string().contains("listing no syscall"), "{err}");
        }
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_custom_action_seccomp_rule_cannot_be_serialized() {
        use crate::{SeccompAction, SeccompPolicy, SeccompRules};
        let builder =
            Cage::builder()
                .rootfs("/tmp")
                .command("/bin/sh")
                .seccomp(SeccompPolicy::Rules(
                    SeccompRules::denying([1i64]).listed_action(SeccompAction::KillProcess),
                ));
        let err = toml::to_string(&builder).unwrap_err();
        assert!(err.to_string().contains("custom action"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn an_argument_conditioned_seccomp_profile_round_trips() {
        // An allowlist that names bare syscalls and one argument-conditioned
        // entry: ioctl is allowed only when its request argument equals a
        // value.
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [hardening.seccomp]\n\
                       allow = [\"read\", \"write\"]\n\
                       [[hardening.seccomp.allow-rule]]\n\
                       syscall = \"ioctl\"\n\
                       [[hardening.seccomp.allow-rule.arg]]\n\
                       index = 1\nlen = \"dword\"\nop = \"eq\"\nvalue = 21523\n";
        let original: CageBuilder = toml::from_str(profile).unwrap();
        let serialized = toml::to_string(&original).unwrap();
        let restored: CageBuilder = toml::from_str(&serialized).unwrap();
        assert_eq!(format!("{original:?}"), format!("{restored:?}"));
        assert!(serialized.contains("allow-rule"), "{serialized}");
        assert!(serialized.contains("ioctl"), "{serialized}");
        assert!(serialized.contains("21523"), "{serialized}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_masked_eq_seccomp_profile_round_trips() {
        // clone is allowed only when the CLONE_NEWUSER bit is clear in its
        // flags argument: masked-eq against a value of 0.
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [[hardening.seccomp.allow-rule]]\n\
                       syscall = \"clone\"\n\
                       [[hardening.seccomp.allow-rule.arg]]\n\
                       index = 0\nlen = \"qword\"\nop = \"masked-eq\"\nvalue = 0\nmask = 268435456\n";
        let original: CageBuilder = toml::from_str(profile).unwrap();
        let serialized = toml::to_string(&original).unwrap();
        let restored: CageBuilder = toml::from_str(&serialized).unwrap();
        assert_eq!(format!("{original:?}"), format!("{restored:?}"));
        assert!(serialized.contains("masked-eq"), "{serialized}");
        assert!(serialized.contains("mask = 268435456"), "{serialized}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_seccomp_profile_mixing_allow_and_deny_is_rejected() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [hardening.seccomp]\nallow = [\"read\"]\ndeny = [\"write\"]\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("allow and a deny"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn an_empty_seccomp_table_is_rejected() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n[hardening.seccomp]\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("lists no syscalls"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_masked_eq_argument_without_a_mask_is_rejected() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [[hardening.seccomp.deny-rule]]\n\
                       syscall = \"socket\"\n\
                       [[hardening.seccomp.deny-rule.arg]]\n\
                       index = 0\nlen = \"dword\"\nop = \"masked-eq\"\nvalue = 0\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("requires a mask"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_mask_on_a_non_masked_argument_is_rejected() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [[hardening.seccomp.deny-rule]]\n\
                       syscall = \"socket\"\n\
                       [[hardening.seccomp.deny-rule.arg]]\n\
                       index = 0\nlen = \"dword\"\nop = \"eq\"\nvalue = 2\nmask = 15\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("masked-eq"), "{err}");
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_seccomp_argument_without_a_width_is_rejected() {
        // The width has no safe default, so a profile must state it.
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n\
                       [[hardening.seccomp.deny-rule]]\n\
                       syscall = \"socket\"\n\
                       [[hardening.seccomp.deny-rule.arg]]\n\
                       index = 0\nop = \"eq\"\nvalue = 2\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("len"), "{err}");
    }

    /// A build with `serde` but not `hardening` must refuse a profile that
    /// configures hardening rather than silently discard the posture.
    #[cfg(not(feature = "hardening"))]
    #[test]
    fn a_hardening_profile_is_rejected_without_the_feature() {
        let profile =
            "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n[hardening]\nseccomp = \"curated\"\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("hardening"), "{err}");
        // A profile with no hardening table still loads.
        let ok: CageBuilder = toml::from_str("rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\n").unwrap();
        assert_eq!(ok.command.as_deref(), Some(Path::new("/bin/sh")));
    }
}
