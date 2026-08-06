//! The sandbox specification: builder, validation, and the launch entry point.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawMode, ResolveFlags};
use rustix::io::Errno;
use rustix::mount::MountFlags;
use rustix::thread::UnshareFlags;

use crate::error::{ConfigError, Error, OverlayLayer};
use crate::idmap::{self, IdMapper, Identity, IdentityMap};
use crate::limits::{Limit, Resource};
use crate::mechanism::{
    Confinement, IdentityPlan, LaunchPlan, ManagedPlaceholders, MountAction, MountDir, MountOp,
    NestedMap, NestedPlan, OverlayPlan, RlimitPlan, RunAsPlan, StdioPlan,
};
use crate::observer::{Collect, Observer, Output};
use crate::resolved::ResolvedInputs;
use crate::running::{Pending, Running};
use crate::status::ExitStatus;
use crate::terminal::{Pty, Terminal};

/// The deterministic base `PATH`, shared by the cage's and the restriction's
/// base environments.
pub(crate) const BASE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The base environment every sandboxed command starts with.
///
/// Deterministic: nothing is read from the host. Caller-supplied variables
/// are added on top and override these on collision. `HOME` is `/root`
/// because the command runs mapped to root inside the sandbox.
const BASE_ENV: [(&str, &str); 2] = [("PATH", BASE_PATH), ("HOME", "/root")];

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "lowercase")
)]
pub enum Network {
    /// A new network namespace whose only interface is loopback, brought up
    /// during setup. The sandbox has no external connectivity. This is the
    /// default.
    #[default]
    Isolated,
    /// Share the host's network namespace. The sandbox sees the host's
    /// interfaces, and the host's `resolv.conf` is bound read-only into the
    /// rootfs unless disabled with [`CageBuilder::resolv_conf`].
    Host,
    /// A new network namespace with no interface brought up, not even
    /// loopback. The sandbox has no connectivity at all — unlike
    /// [`Isolated`](Self::Isolated), it cannot even reach `127.0.0.1`.
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
/// Under `Inherit` on standard input both work, and both work by reaching into
/// the caller's session — the second by the sandbox taking the caller's
/// terminal's foreground process group, a shell inside the sandbox competing
/// with the caller's own shell for one terminal. Under `Null` or `Fd` neither
/// works: the sandbox is outside the caller's session, and the session it has
/// instead owns no terminal to run jobs against. A caller that wants to stop
/// such a command on an interrupt uses
/// [`Running::terminate`](crate::Running::terminate) or
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
    /// and with it the caller's controlling terminal.
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
    /// a pseudoterminal replica — and anything writable on the output pair.
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
    #[cfg_attr(feature = "serde", serde(rename = "target"))]
    target: PathBuf,
    /// The mount source, passed to the kernel verbatim.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    #[cfg_attr(feature = "serde", serde(rename = "source"))]
    source: Option<PathBuf>,
    /// The filesystem type.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    #[cfg_attr(feature = "serde", serde(rename = "fstype"))]
    fstype: Option<String>,
    /// Mount flags: the kernel's raw `MS_*` bits.
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "serde", serde(rename = "flags"))]
    flags: u64,
    /// The filesystem data string.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    #[cfg_attr(feature = "serde", serde(rename = "data"))]
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
        let mut collect = Collect::default();
        let status = self.run_with(&mut collect)?;
        Ok(collect.into_output(status))
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
    /// command is held at a gate just before `execve`. The returned handle
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
    /// [`proceed`](Pending::proceed), because the pseudoterminal is allocated
    /// before the fork and the gate sits after its controlling terminal is
    /// established; nothing writes to the terminal while the launch is held, so
    /// the caller attaches its stack and proceeds with the primary in hand.
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
    #[cfg_attr(feature = "serde", serde(rename = "source"))]
    source: PathBuf,
    #[cfg_attr(feature = "serde", serde(rename = "target"))]
    target: PathBuf,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "serde", serde(rename = "read-only"))]
    read_only: bool,
}

impl Bind {
    /// Returns a read-write bind of `source`, a host path, at `target`, an
    /// absolute path inside the sandbox.
    ///
    /// [`CageBuilder::bind`] and [`CageBuilder::bind_ro`] are the ordinary way
    /// to add one. This constructor is for a consumer assembling a
    /// [`Mount`] sequence directly.
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

/// One mount a consumer adds to a sandbox: a bind, or a raw mount.
///
/// The sandbox applies these in the order they are declared, after the
/// managed mount profile. Holding both kinds in one sequence is what makes
/// that order expressible: a raw tmpfs and the binds that populate it can be
/// interleaved, which a bind-then-raw arrangement cannot express.
///
/// Added with [`CageBuilder::bind`], [`CageBuilder::bind_ro`], and
/// [`CageBuilder::raw_mount`], or as a `[[mount]]` table in a profile, and
/// read back through [`CageBuilder::get_mounts`].
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(tag = "kind")
)]
pub enum Mount {
    /// A bind mount of a host path.
    #[cfg_attr(feature = "serde", serde(rename = "bind"))]
    Bind(Bind),
    /// A raw mount, passed to the kernel verbatim.
    #[cfg_attr(feature = "serde", serde(rename = "raw"))]
    Raw(RawMount),
}

impl Mount {
    /// The path inside the sandbox the mount is established at.
    pub fn get_target(&self) -> &Path {
        match self {
            Mount::Bind(bind) => bind.get_target(),
            Mount::Raw(raw) => raw.get_target(),
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
    serde(default, deny_unknown_fields)
)]
pub struct Overlay {
    #[cfg_attr(
        feature = "serde",
        serde(rename = "lower", skip_serializing_if = "Vec::is_empty")
    )]
    lower: Vec<PathBuf>,
    #[cfg_attr(
        feature = "serde",
        serde(rename = "upper", skip_serializing_if = "Option::is_none")
    )]
    upper: Option<PathBuf>,
    #[cfg_attr(
        feature = "serde",
        serde(rename = "work", skip_serializing_if = "Option::is_none")
    )]
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
    /// The work area holds a directory the kernel creates mode `0`, so a plain
    /// recursive delete cannot descend into it: discard it with a removal that
    /// restores traversable permissions as it descends.
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
/// with the deterministic base environment (`PATH` and `HOME`), and keeps
/// the host's hostname. Every part of that profile has a builder method to
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
/// Load a profile from an untrusted source through `RestrictedProfile`
/// instead. It forbids the operations that map host resources into the sandbox
/// or share a host namespace — bind mounts, raw mounts, and host networking —
/// and yields a builder the consumer can extend with its own trusted calls.
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
/// for review. Two things do not survive that, both because they are code or a
/// resource rather than configuration: an [`id_mapper`](Self::id_mapper)
/// delegate is simply absent from the output, and a builder holding a
/// [`Stdio::from_fd`](crate::Stdio::from_fd) disposition fails to serialize at
/// all, since a descriptor names nothing a profile could carry. Everything else
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
    #[cfg_attr(feature = "serde", serde(rename = "rootfs"))]
    rootfs: Option<PathBuf>,
    #[cfg_attr(feature = "serde", serde(rename = "command"))]
    command: Option<PathBuf>,
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_os::string_vec", skip_serializing_if = "Vec::is_empty")
    )]
    #[cfg_attr(feature = "serde", serde(rename = "args"))]
    args: Vec<OsString>,
    #[cfg_attr(feature = "serde", serde(rename = "network"))]
    network: Network,
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_os::string_opt", skip_serializing_if = "Option::is_none")
    )]
    #[cfg_attr(feature = "serde", serde(rename = "hostname"))]
    hostname: Option<OsString>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "serde", serde(rename = "workdir"))]
    workdir: Option<PathBuf>,
    #[cfg_attr(feature = "serde", serde(rename = "stdin"))]
    stdin: Stdio,
    #[cfg_attr(feature = "serde", serde(rename = "stdout"))]
    stdout: Stdio,
    #[cfg_attr(feature = "serde", serde(rename = "stderr"))]
    stderr: Stdio,
    #[cfg_attr(feature = "serde", serde(rename = "pid-namespace"))]
    pid_namespace: bool,
    // The managed mounts are `Option<bool>` rather than `bool` so that "left at
    // its default" is distinguishable from "explicitly asked for". Only that
    // distinction lets `managed_mounts(false)` refuse a contradicting
    // `mount_dev(true)` instead of silently overriding it. `None` reads as the
    // default, which every one of them documents as `true`.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "serde", serde(rename = "managed-mounts"))]
    managed_mounts: Option<bool>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "serde", serde(rename = "mount-proc"))]
    mount_proc: Option<bool>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "serde", serde(rename = "mount-dev"))]
    mount_dev: Option<bool>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "serde", serde(rename = "mount-tmp"))]
    mount_tmp: Option<bool>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "serde", serde(rename = "resolv-conf"))]
    resolv_conf: Option<bool>,
    // Whether the library's deterministic base environment is composed under
    // the caller's variables. `false` means the command's environment is
    // exactly what the caller set, with nothing of the library's underneath.
    // `Option` for the same reason the mount toggles carry one: a profile
    // records what its author asked for, and an unstated key stays unstated
    // through a render-and-reload cycle.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "serde", serde(rename = "base-env"))]
    base_env: Option<bool>,
    #[cfg_attr(feature = "serde", serde(rename = "stop-with-caller"))]
    stop_with_caller: bool,
    #[cfg_attr(feature = "serde", serde(rename = "path-lookup"))]
    path_lookup: bool,
    // The identity fields sit between the scalars and the tables: the map
    // serializes as a string for the unit forms and a table for ranges, and
    // the run-as identity is always a table, so this position keeps the
    // serialized profile valid TOML in field order either way.
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "identity_map_is_default")
    )]
    #[cfg_attr(feature = "serde", serde(rename = "identity-map"))]
    identity_map: IdentityMap,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "serde", serde(rename = "run-as"))]
    run_as: Option<Identity>,
    // The overlay root, set only for an overlay-rooted cage; `None` for a plain
    // `rootfs`. Exactly one of the two is in force. It serializes as a table, so
    // it sits after every scalar key: a scalar following a table header would be
    // parsed into that table.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "serde", serde(rename = "overlay"))]
    overlay: Option<Overlay>,
    // The delegate is code, not configuration: never part of a profile.
    #[cfg_attr(feature = "serde", serde(skip))]
    id_mapper: Option<Arc<dyn IdMapper>>,
    // Keyed by resource, so a repeated call replaces and the applied order is
    // fixed. It serializes as the `[rlimit]` table, so it sits with the other
    // tables rather than among the scalars.
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "crate::limits::serde_rlimits",
            skip_serializing_if = "BTreeMap::is_empty"
        )
    )]
    #[cfg_attr(feature = "serde", serde(rename = "rlimit"))]
    rlimits: BTreeMap<Resource, (Limit, Limit)>,
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_os::string_map", skip_serializing_if = "Vec::is_empty")
    )]
    #[cfg_attr(feature = "serde", serde(rename = "env"))]
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
    #[cfg_attr(feature = "serde", serde(rename = "hardening"))]
    hardening: crate::hardening::Request,
    // In a build with `serde` but without `hardening`, a placeholder keeps the
    // `hardening` key known so a profile that configures it is refused with a
    // clear message rather than silently ignored. The field is never read; it
    // exists only for the rejecting `Deserialize` its type carries.
    #[cfg(all(feature = "serde", not(feature = "hardening")))]
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    #[cfg_attr(feature = "serde", serde(rename = "hardening"))]
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
            identity_map: IdentityMap::Single,
            run_as: None,
            overlay: None,
            id_mapper: None,
            rlimits: BTreeMap::new(),
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
    /// supersedes an [`overlay_rootfs`](Self::overlay_rootfs) call, and the
    /// reverse; the last call wins. A consumer overriding an untrusted profile's
    /// rootfs therefore clears any overlay it configured along with it.
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
    /// requires. `upper` is created if absent, along with a sibling work
    /// directory the overlay requires on the same filesystem; both persist on the
    /// host after the sandbox exits and are the caller's to keep or discard, and
    /// both should live under a directory the calling user controls rather than a
    /// world-writable one, for the reason `rootfs` gives and for the one in
    /// [Where the upper lives](Overlay#where-the-upper-lives). The
    /// overlay's work area holds a directory the kernel creates mode `0`, so a
    /// plain recursive delete cannot descend into it: discard the upper and its
    /// work directory with a removal that restores traversable permissions as it
    /// descends.
    ///
    /// This is an unprivileged overlay mounted from inside the sandbox's user
    /// namespace, which the host must support: [`build`](Self::build) refuses a
    /// host that cannot establish one, and
    /// [`host::overlay_blocker`](crate::host::overlay_blocker) reports what is
    /// missing. The upper's filesystem must record `user.*` extended attributes,
    /// so an on-disk filesystem (ext4, xfs, btrfs) works on Linux 5.11 and later,
    /// while a tmpfs upper needs Linux 6.6. Setting an overlay root supersedes a
    /// plain [`rootfs`](Self::rootfs), and the reverse; the last call wins.
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
    /// Setting an overlay root supersedes a plain [`rootfs`](Self::rootfs), and
    /// the reverse; the last call wins.
    ///
    /// This is an unprivileged overlay mounted from inside the sandbox's user
    /// namespace, which the host must support: [`build`](Self::build) refuses a
    /// host that cannot establish one, and
    /// [`host::overlay_blocker`](crate::host::overlay_blocker) reports what is
    /// missing. The upper and work directories should live under a directory the
    /// calling user controls; see
    /// [Where the upper lives](Overlay#where-the-upper-lives).
    pub fn overlay(mut self, overlay: Overlay) -> Self {
        self.rootfs = None;
        self.overlay = Some(overlay);
        self
    }

    /// Sets the command to execute inside the sandbox.
    ///
    /// The path is interpreted inside the sandbox's root filesystem and must
    /// be absolute, unless [`path_lookup`](Self::path_lookup) is enabled and
    /// the command has no slash, in which case it is resolved against the
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
    /// lookup never resolves a relative path.
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
    /// base (`PATH` and `HOME`) plus the variables set here, which override
    /// the base on collision. Nothing is inherited from the host.
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
    /// only interface is loopback.
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
    /// The path must be absolute and must exist inside the sandbox at launch;
    /// a missing directory is a setup error, not a fallback. The default is
    /// `/`.
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
    /// When output is captured, those surviving descendants also govern
    /// capture's endpoint: a descendant holding the command's streams keeps
    /// an unbounded wait blocked after the command exits; see
    /// [`Running::wait`](crate::Running::wait).
    pub fn pid_namespace(mut self, isolate: bool) -> Self {
        self.pid_namespace = isolate;
        self
    }

    /// Ties the sandbox's lifetime to the caller's (default `false`).
    ///
    /// When enabled, the sandbox is stopped as soon as the calling process
    /// exits — however it exits — or the last handle to the launch (the
    /// [`Running`] and any [`KillHandle`]s) is dropped. The tie is a pipe
    /// held open by the handle, not a signal arrangement in the caller, so
    /// it works from any thread and involves no signal handlers.
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
    /// one.
    pub fn id_mapper(mut self, mapper: impl IdMapper + 'static) -> Self {
        self.id_mapper = Some(Arc::new(mapper));
        self
    }

    /// Runs the command as a non-root identity inside the sandbox.
    ///
    /// The switch sits within the hardening layer, after securebits,
    /// no-new-privileges, and Landlock and before the capability drop and the
    /// seccomp filter, so the command holds the identity from its first
    /// instruction and its descendants inherit it. Every id must be contained in the
    /// [`identity_map`](Self::identity_map); supplementary groups
    /// additionally require a range gid map, because the single-identity
    /// map denies `setgroups`. Without a keep-capabilities request the
    /// kernel clears the command's capabilities across the switch, which is
    /// the boundary a non-root identity exists to draw; a kept capability
    /// set survives it, and retaining `CAP_SETUID`, `CAP_SETGID`, or
    /// `CAP_SETPCAP` alongside a non-root identity is rejected at build
    /// time.
    ///
    /// The launch sets no-new-privileges whenever a run-as identity is
    /// configured, in every build of the library and whatever else the sandbox
    /// requests, because the cleared capability set is only half of the
    /// boundary. A rootfs ships set-user-ID binaries and file capabilities
    /// owned by in-namespace uid 0 — the provisioners apply a tree's
    /// permission bits verbatim, so `/usr/bin/sudo` is a working
    /// `/usr/bin/sudo` — and without the flag the non-root command executes
    /// them and is root inside again. The flag closes that path for the
    /// command and everything it starts.
    pub fn run_as(mut self, identity: Identity) -> Self {
        self.run_as = Some(identity);
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

    /// Controls whether `/proc` is mounted (default `true`).
    ///
    /// With the default PID namespace, `/proc` is a fresh procfs instance
    /// showing only the sandbox's processes. With
    /// [`pid_namespace(false)`](Self::pid_namespace) the sandbox shares the
    /// host PID namespace and `/proc` is the host's procfs, bind-mounted.
    /// Either way, `/proc/net` and `/proc/sys/net` resolve through the
    /// sandbox's own network namespace.
    ///
    /// A container needs a procfs from somewhere: the nested user namespace the
    /// command enters — which is what locks the sandbox's mount flags —
    /// establishes its identity map through one, by path. Setting this to
    /// `false` therefore obliges the profile to mount a procfs of its own, and
    /// [`build`](Self::build) refuses one that does not with
    /// [`ConfigError::NestedUsernsNeedsProcfs`](crate::ConfigError::NestedUsernsNeedsProcfs).
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
    /// declared through [`bind`](Self::bind), [`bind_ro`](Self::bind_ro), and
    /// [`raw_mount`](Self::raw_mount), and nothing else — no `/proc`, no
    /// `/dev`, no `/tmp`, no `resolv.conf`. **A managed mount introduced in a
    /// later release is suppressed too**, which is the point: the individual
    /// toggles can only turn off the mounts that exist today, so they cannot
    /// protect a consumer from one added tomorrow.
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
    /// to [`env`](Self::env) and [`envs`](Self::envs) — `PATH` and `HOME` are
    /// not supplied, and **no variable the library may add to its base in a
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
    /// [`get_overlay`](Self::get_overlay), and for a builder with no root at
    /// all — which [`build`](Self::build) rejects.
    pub fn get_rootfs(&self) -> Option<&Path> {
        self.rootfs.as_deref()
    }

    /// The configured overlay root, when one is set.
    pub fn get_overlay(&self) -> Option<&Overlay> {
        self.overlay.as_ref()
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
    /// cost of the relative order between the two.
    pub fn get_mounts(&self) -> &[Mount] {
        &self.mounts
    }

    /// The bind mounts the sandbox carries, in the order they were added.
    pub fn get_binds(&self) -> impl Iterator<Item = &Bind> {
        self.mounts.iter().filter_map(|mount| match mount {
            Mount::Bind(bind) => Some(bind),
            Mount::Raw(_) => None,
        })
    }

    /// The raw mounts the sandbox carries, in the order they were added.
    pub fn get_raw_mounts(&self) -> impl Iterator<Item = &RawMount> {
        self.mounts.iter().filter_map(|mount| match mount {
            Mount::Raw(raw) => Some(raw),
            Mount::Bind(_) => None,
        })
    }

    /// The sandbox's network posture.
    pub fn get_network(&self) -> Network {
        self.network
    }

    /// Whether the host's `resolv.conf` bind is enabled, with the
    /// managed-mount master switch folded in.
    ///
    /// The library acts on this only under [`Network::Host`]. A caller that
    /// composes resolver configuration of its own — as `fcage` does for a
    /// native-stack run — can read it to honor the same opt-out.
    pub fn get_resolv_conf(&self) -> bool {
        self.managed(self.resolv_conf)
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
        self.managed_mounts.unwrap_or(true) && toggle.unwrap_or(true)
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

    /// The configured resource limits, ordered by resource.
    pub fn get_rlimits(&self) -> impl Iterator<Item = (Resource, Limit, Limit)> {
        self.rlimits
            .iter()
            .map(|(resource, (soft, hard))| (*resource, *soft, *hard))
    }

    /// Validates the configuration and freezes it into a [`Cage`].
    ///
    /// All fallible and allocating preparation happens here, in the calling
    /// process: the rootfs and bind sources are resolved, the mount profile
    /// is lowered into a frozen op list, and the command line and
    /// environment are marshaled into their final form. After `build`
    /// succeeds, launching performs no work that can fail for configuration
    /// reasons.
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
        // field is moved out of `self` below. Each is the caller's explicit
        // choice or the documented default, and none survives opting out of
        // the profile as a whole.
        let profile_managed = self.managed_mounts.unwrap_or(true);
        let mount_proc = profile_managed && self.mount_proc.unwrap_or(true);
        let mount_dev = profile_managed && self.mount_dev.unwrap_or(true);
        let mount_tmp = profile_managed && self.mount_tmp.unwrap_or(true);
        let resolv_conf = profile_managed && self.resolv_conf.unwrap_or(true);
        let base_env = self.base_env.unwrap_or(true);

        // Exactly one root is in force: a plain rootfs, or an overlay whose
        // first lower is the base the overlay mounts over. The builder's
        // setters keep the two exclusive, but a deserialized profile can carry
        // both keys; taking either one would silently discard the other's
        // configuration, so a profile that names both is refused.
        let rootfs = match (&self.rootfs, &self.overlay) {
            (Some(_), Some(_)) => return Err(ConfigError::RootContradiction.into()),
            (Some(rootfs), None) => rootfs.clone(),
            (None, Some(overlay)) => overlay
                .lower
                .first()
                .ok_or(ConfigError::OverlayLowerMissing)?
                .clone(),
            (None, None) => return Err(ConfigError::RootfsMissing.into()),
        };
        let command = self.command.ok_or(ConfigError::CommandMissing)?;

        // A command with no slash is resolved against PATH only when path
        // lookup is opted into; otherwise, and for any command that contains a
        // slash, the path must be absolute. This is the execvp rule plus the
        // cage's absolute-path requirement: a slash-bearing relative path is
        // never searched.
        let searchable = self.path_lookup && !command_has_slash(&command);
        if !command.is_absolute() && !searchable {
            return Err(ConfigError::CommandNotAbsolute { command }.into());
        }
        let program = cstring(command.as_os_str())?;
        let program_search = if searchable {
            // A `PATH` with no absolute entry leaves nothing to search. Refuse
            // it here rather than fall through to an `execve` of the bare name,
            // which the kernel would resolve against the sandbox's working
            // directory — the relative resolution path lookup exists to avoid.
            let path = effective_path(&self.env, base_env);
            let candidates = search_candidates(&path, &command)?;
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
        let exec_label = exec_label(&command, &program_search);
        let (rlimits, rlimit_labels) = lower_rlimits(&self.rlimits)?;
        let args = self
            .args
            .iter()
            .map(|arg| cstring(arg))
            .collect::<Result<Vec<_>, _>>()?;

        // With the base opted out of, the caller's pairs are the whole
        // environment; the library contributes nothing, in this release or a
        // later one.
        let base: &[(&str, &str)] = if base_env { &BASE_ENV } else { &[] };
        let env = compose_env(base, &self.env)?;
        let hostname = self
            .hostname
            .map(|name| validate_hostname(&name))
            .transpose()?;
        let workdir = self
            .workdir
            .map(|path| validate_workdir(&path))
            .transpose()?
            .flatten();

        // Resolve the rootfs to a canonical directory and prove it can be
        // opened as one, so a missing or unusable rootfs is a typed
        // configuration error here, before any fork. The launch itself
        // resolves the canonical path again inside the new mount namespace,
        // where descriptors opened here could not anchor the mounts.
        let canonical = std::fs::canonicalize(&rootfs).map_err(|err| {
            Error::from(ConfigError::RootfsUnusable {
                path: rootfs.clone(),
                errno: err.raw_os_error().unwrap_or(Errno::IO.raw_os_error()),
            })
        })?;
        if canonical.parent().is_none() {
            return Err(ConfigError::RootfsIsHostRoot.into());
        }
        rustix::fs::open(
            &canonical,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| ConfigError::RootfsUnusable {
            path: rootfs.clone(),
            errno: errno.raw_os_error(),
        })?;
        let rootfs_path = cstring(canonical.as_os_str())?;

        // An overlay root: `canonical` is the base lower the overlay mounts
        // over, any further lowers are resolved beside it, and the caller's
        // upper — with its work directory — is prepared and frozen into the
        // mount options here, so the sandbox stage only replays them. A host
        // that cannot establish an unprivileged overlay is refused now, before
        // any fork.
        let overlay = self
            .overlay
            .as_ref()
            .map(|overlay| build_overlay_plan(&canonical, overlay))
            .transpose()?;

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
        // The caller's mounts in declaration order, both kinds in one pass.
        // The managed profile above goes first because it establishes the tree
        // these land in; among the caller's own, the order is theirs.
        for mount in &self.mounts {
            match mount {
                Mount::Bind(bind) => lowering.push_bind(bind)?,
                Mount::Raw(raw) => lowering.push_raw(raw)?,
            }
        }
        if resolv_conf && matches!(self.network, Network::Host) {
            lowering.push_resolv_conf()?;
        }

        // Every mount target the launch has to create as an empty file, as the
        // host path it comes to rest at. A file the sandbox creates only to
        // mount over is not part of the root, so the caller side takes it away
        // once the sandbox is gone. Writes land in the rootfs itself for a
        // plain root and in the upper for an overlay root, whose pivoted root
        // is the merged view; an existing file may come from any layer. Both
        // are canonical paths, so a root the caller named relatively does not
        // leave a path that re-resolves against whatever directory the process
        // happens to be in when the handle drops.
        let (writable, layers) = match &overlay {
            Some(plan) => {
                let mut layers = vec![plan.upper.clone()];
                layers.extend(plan.lower.iter().cloned());
                (plan.upper.as_path(), layers)
            }
            None => (canonical.as_path(), vec![canonical.clone()]),
        };
        let managed_placeholders = created_file_targets(&lowering.ops, writable, &layers);

        // The identity plan: validate the requested map, resolve a range
        // request through the delegate seam, and validate the run-as
        // identity against the ranges that result — so an identity the map
        // cannot represent is a configuration error here, not a launch
        // failure.
        idmap::validate_request(&self.identity_map)?;
        let identity = match &self.identity_map {
            IdentityMap::Single => IdentityPlan::Single,
            request => {
                let (mapper, map) = resolve_mapper(self.id_mapper.clone(), request)?;
                idmap::validate_resolved(&map)?;
                IdentityPlan::Ranged { mapper, map }
            }
        };
        let run_as = self
            .run_as
            .as_ref()
            .map(|identity_request| validate_run_as(identity_request, &identity))
            .transpose()?;

        // The nested user namespace the command enters before it hardens, which
        // is what locks the flags of every mount the sandbox established. Its
        // map reflects the one resolved above, and the procfs it is written
        // through is the profile's, so both are settled here and the command
        // stage replays frozen bytes.
        let nested = build_nested_plan(&identity, &lowering.ops, self.pid_namespace)?;

        // The hardening request, compiled and validated here so the command
        // stage only replays frozen data.
        #[cfg(feature = "hardening")]
        let hardening = {
            let mut hardening = self.hardening.lower()?;
            // A kept set-id capability would let a non-root command return
            // to the mapped uid 0 under the securebits below; refuse the
            // combination rather than ship an identity that is not a
            // boundary.
            if let (Some(run_as_request), Some(keep)) = (&self.run_as, hardening.keep_caps)
                && run_as_request.uid != 0
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
            hardening.set_securebits = matches!(&self.run_as, Some(identity) if identity.uid != 0)
                && hardening.keep_caps.is_some();
            // Under host networking there is no network namespace, so a
            // Landlock network grant is the sandbox's only network boundary.
            // Refuse a build whose grant this kernel cannot enforce rather than
            // reach the host network unrestricted, the same posture the
            // restriction fallback takes for its Landlock-only confinement.
            if matches!(self.network, Network::Host) {
                hardening.ensure_host_net_enforceable()?;
            }
            hardening
        };

        Ok(Cage {
            plan: LaunchPlan {
                confinement: Confinement::Container,
                identity,
                nested: Some(nested),
                run_as,
                program,
                program_search,
                args,
                env,
                rootfs_path,
                overlay,
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
/// The restricted policy forbids the operations that map host resources into
/// the sandbox, write to the host outside it, or share a host namespace: a bind
/// mount, a raw mount, host networking, an overlay root (`[overlay]`, whose upper
/// creates host directories at a path the profile picks), and sharing the host
/// PID namespace (`pid-namespace = false`, which would bind the host's `/proc`
/// into the sandbox). A profile using any of them is rejected with
/// [`ConfigError::ProfileOperationForbidden`]. Everything else — the rootfs
/// (never the host root, which [`CageBuilder::build`] rejects for every
/// profile), command, arguments, environment, working directory, hostname,
/// hardening posture, resource limits, the identity map and run-as identity,
/// and the remaining mount toggles — is accepted, so a restricted profile
/// still shapes the sandbox.
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

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for RestrictedProfile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let builder = CageBuilder::deserialize(deserializer)?;
        builder
            .check_restricted()
            .map_err(serde::de::Error::custom)?;
        Ok(RestrictedProfile(builder))
    }
}

#[cfg(feature = "serde")]
impl CageBuilder {
    /// Rejects the profile operations the restricted policy reserves for a
    /// trusted profile: bind mounts, raw mounts, host networking, an overlay
    /// root, and sharing the host PID namespace. Backs [`RestrictedProfile`]'s
    /// deserialization.
    fn check_restricted(&self) -> Result<(), ConfigError> {
        // Destructured exhaustively, with no `..`: a new builder field fails to
        // compile here until someone classifies it, so the untrusted-profile
        // surface cannot widen by omission. A knob that reaches the host belongs
        // in the forbidden group below; anything else is bound to `_` here as a
        // deliberate record that it was considered and allowed.
        let CageBuilder {
            // Reaches host resources, and is refused below.
            mounts,
            network,
            overlay,
            pid_namespace,
            // Bounded by the calling user's own authority, and allowed. See
            // this type's documentation for what a profile still governs.
            rootfs: _,
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
            // A limit reaches nothing: it is set on the command process, and an
            // unprivileged `setrlimit` can only lower a hard limit or move a
            // soft one within the hard limit the caller already had. The worst
            // a profile can do with one is constrain its own command.
            rlimits: _,
            // Code, never part of a profile: `serde(skip)` keeps it unset here.
            id_mapper: _,
            env: _,
            // Tightens the sandbox rather than widening it, and is validated on
            // its own; a build without the feature refuses the key outright.
            hardening: _,
        } = self;

        // Reported by kind rather than as one "a mount" refusal, so the message
        // names the operation the profile actually asked for.
        if mounts.iter().any(|mount| matches!(mount, Mount::Bind(_))) {
            return Err(ConfigError::ProfileOperationForbidden {
                operation: "a bind mount",
            });
        }
        if mounts.iter().any(|mount| matches!(mount, Mount::Raw(_))) {
            return Err(ConfigError::ProfileOperationForbidden {
                operation: "a raw mount",
            });
        }
        if matches!(network, Network::Host) {
            return Err(ConfigError::ProfileOperationForbidden {
                operation: "host networking",
            });
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
        Ok(())
    }
}

/// Resolves a range request through the configured delegate, or the bundled
/// fallback chain: [`DirectMapper`](crate::DirectMapper) first, then the
/// subordinate delegate when the `subid` feature is enabled. Each refusal is
/// collected, and the host probe's diagnosis appended, so the error names
/// what to fix.
fn resolve_mapper(
    configured: Option<Arc<dyn IdMapper>>,
    request: &IdentityMap,
) -> Result<(Arc<dyn IdMapper>, idmap::ResolvedMap), Error> {
    // A configured delegate is the whole chain: its refusal is final.
    if let Some(mapper) = configured {
        return match mapper.resolve(request) {
            Ok(map) => Ok((mapper, map)),
            Err(err) => Err(ConfigError::IdentityMapUnavailable {
                reason: err.to_string(),
            }
            .into()),
        };
    }

    idmap::resolve_default_chain(request)
        .map_err(|reason| ConfigError::IdentityMapUnavailable { reason }.into())
}

/// Validates a run-as identity against the identity plan and freezes it.
///
/// Every id must be contained in the map that will exist at launch, and
/// supplementary groups require a range gid map: the single-identity map is
/// established by denying `setgroups`, so no group list can ever be set
/// inside it.
fn validate_run_as(identity: &Identity, plan: &IdentityPlan) -> Result<RunAsPlan, Error> {
    let unmapped =
        |id: u32, space: &'static str| Error::from(ConfigError::RunAsUnmapped { id, space });
    match plan {
        IdentityPlan::Single => {
            if identity.uid != 0 {
                return Err(unmapped(identity.uid, "uid"));
            }
            if identity.gid != 0 {
                return Err(unmapped(identity.gid, "gid"));
            }
            if !identity.groups.is_empty() {
                return Err(ConfigError::RunAsGroupsWithSingleMap.into());
            }
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
        }
    }
    // `from_raw_unchecked` is the safe constructor without the debug assert
    // against the sentinel -1; the kernel rejects unusable ids at the
    // switch, and the map validation above has already bounded these.
    Ok(RunAsPlan {
        uid: rustix::thread::Uid::from_raw_unchecked(identity.uid),
        gid: rustix::thread::Gid::from_raw_unchecked(identity.gid),
        groups: identity
            .groups
            .iter()
            .map(|&group| rustix::thread::Gid::from_raw_unchecked(group))
            .collect(),
    })
}

/// Composes the nested user namespace's plan: the map it takes, and the procfs
/// paths through which that map is established.
///
/// The map is the identity reflection of the sandbox's own, so the command sees
/// the same ids one namespace deeper; the tier follows the sandbox's, because
/// the kernel's one-id exception is what lets a process write its own map and
/// nothing richer.
///
/// A container needs a procfs for this: the map files are reached by path, and
/// the paths that name them are inside the sandbox by the time the command
/// writes them. A profile that mounts none is refused here rather than at
/// launch, where the failure would be an `ENOENT` on a path nobody asked for.
fn build_nested_plan(
    identity: &IdentityPlan,
    ops: &[MountOp],
    pid_namespace: bool,
) -> Result<NestedPlan, Error> {
    // Only a delegated map inside a PID namespace of the sandbox's own needs a
    // *fresh* procfs; see `procfs_op_target`.
    let needs_fresh_procfs = pid_namespace && matches!(identity, IdentityPlan::Ranged { .. });
    let procfs_target =
        visible_procfs(ops, needs_fresh_procfs).ok_or(ConfigError::NestedUsernsNeedsProcfs)?;

    // The map files as the command names them after the pivot: absolute, under
    // the profile's own procfs target.
    let under_procfs = |leaf: &str| -> Result<CString, ConfigError> {
        let target = procfs_target.to_bytes();
        let mut path = Vec::with_capacity(target.len() + leaf.len() + 2);
        path.push(b'/');
        path.extend_from_slice(target);
        path.push(b'/');
        path.extend_from_slice(leaf.as_bytes());
        CString::new(path).map_err(|_| ConfigError::EmbeddedNul)
    };

    let (map, uid, gid) = match identity {
        // The single-identity tier collapses to one extent of one id, which is
        // all it ever had, and which the command may write for itself.
        IdentityPlan::Single => {
            let root = [idmap::IdRange {
                inside: 0,
                outside: 0,
                count: 1,
            }];
            (NestedMap::SelfWritten, root.to_vec(), root.to_vec())
        }
        IdentityPlan::Ranged { map, .. } => (
            NestedMap::Delegated,
            idmap::reflect_inside(map.uid()),
            idmap::reflect_inside(map.gid()),
        ),
    };

    Ok(NestedPlan {
        map,
        uid_lines: idmap::format_map(&uid),
        gid_lines: idmap::format_map(&gid),
        setgroups_path: under_procfs("self/setgroups")?,
        gid_map_path: under_procfs("self/gid_map")?,
        uid_map_path: under_procfs("self/uid_map")?,
        procfs_target: procfs_target.to_owned(),
    })
}

/// The rootfs-relative target of the procfs the sandbox ends up with, or `None`
/// when the profile mounts none the nested map can be established through.
///
/// The ops execute in order, so a later mount can hide an earlier one; the scan
/// follows the same order and drops a procfs another mount comes to rest on top
/// of. Where a profile mounts more than one, the last still visible is taken —
/// any of them would serve.
fn visible_procfs(ops: &[MountOp], needs_fresh: bool) -> Option<&CStr> {
    let mut visible: Option<&CStr> = None;
    for op in ops {
        if let Some(target) = procfs_op_target(op, needs_fresh) {
            visible = Some(target);
        } else if let (Some(chosen), Some(target)) = (visible, op.action.target())
            && covers(target, chosen)
        {
            visible = None;
        }
    }
    visible
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
fn procfs_op_target(op: &MountOp, needs_fresh: bool) -> Option<&CStr> {
    match &op.action {
        MountAction::Procfs { target } => Some(target),
        MountAction::Raw { target, fstype, .. } if fstype.as_bytes() == b"proc" => Some(target),
        MountAction::Bind { source, target, .. } if !needs_fresh && is_procfs(source) => {
            Some(target)
        }
        _ => None,
    }
}

/// Whether the bind source is a procfs, by the filesystem's own magic number
/// rather than by its path: the managed profile binds `/proc`, and a caller is
/// free to bind a procfs mounted anywhere else.
///
/// A source that cannot be interrogated is not one, which is the safe answer:
/// the build then refuses rather than composing paths into a filesystem that
/// holds no map files.
fn is_procfs(source: &CStr) -> bool {
    rustix::fs::statfs(source).is_ok_and(|stat| stat.f_type == rustix::fs::PROC_SUPER_MAGIC)
}

/// Whether a mount at `mount` hides an entry at `covered`: the same path, or a
/// directory the covered path sits beneath.
///
/// Both are rootfs-relative and carry no leading slash, so the comparison is a
/// plain component-aligned prefix test.
fn covers(mount: &CStr, covered: &CStr) -> bool {
    let (mount, covered) = (mount.to_bytes(), covered.to_bytes());
    covered.starts_with(mount) && (covered.len() == mount.len() || covered[mount.len()] == b'/')
}

/// Builder methods for the opt-in hardening layer: Landlock filesystem and
/// network rules, seccomp syscall filters, and capability drops. See
/// [`crate::FsAccess`], [`crate::NetAccess`], [`crate::SeccompPolicy`], and
/// [`crate::Capability`].
#[cfg(feature = "hardening")]
impl CageBuilder {
    /// Grants `access` beneath `path` under a Landlock ruleset.
    ///
    /// Configuring any grant enrolls the sandbox in Landlock: the command may
    /// then reach a path only where a grant allows it, and everything else on
    /// the filesystem is denied. `path` is a sandbox path (absolute, resolved
    /// after the pivot), so grants describe the mounted view — the rootfs, the
    /// binds, and the `/proc`, `/dev`, and `/tmp` mounts alike.
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
    /// filesystem right is; [`host::landlock_abi`](crate::host::landlock_abi)
    /// reports whether the running kernel reaches ABI 4.
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
    /// [`host::landlock_abi`](crate::host::landlock_abi) before the build where
    /// that matters.
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

    /// Applies a seccomp syscall filter to the command.
    ///
    /// See [`SeccompPolicy`](crate::SeccompPolicy) for the curated profile,
    /// caller-authored rules, and the pre-compiled escape hatch. The filter
    /// binds the command and its descendants.
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
        if name.is_empty() || name.as_bytes().contains(&b'=') {
            return Err(ConfigError::EnvNameInvalid { name: name.clone() }.into());
        }
        env.insert(name.clone(), value.clone());
    }
    env.iter()
        .map(|(name, value)| {
            let mut entry = Vec::with_capacity(name.len() + value.len() + 1);
            entry.extend_from_slice(name.as_bytes());
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            CString::new(entry).map_err(|_| ConfigError::EmbeddedNul.into())
        })
        .collect()
}

/// Validates a hostname: non-empty, at most 64 bytes, no NUL.
fn validate_hostname(name: &OsStr) -> Result<CString, Error> {
    if name.is_empty() || name.len() > 64 {
        return Err(ConfigError::HostnameInvalid.into());
    }
    Ok(cstring(name)?)
}

/// Validates a working directory: absolute, no NUL. Returns `None` for `/`,
/// where no `chdir` is needed.
pub(crate) fn validate_workdir(path: &Path) -> Result<Option<CString>, Error> {
    if !path.is_absolute() {
        return Err(ConfigError::WorkdirNotAbsolute {
            path: path.to_path_buf(),
        }
        .into());
    }
    if path == Path::new("/") {
        return Ok(None);
    }
    Ok(Some(cstring(path.as_os_str())?))
}

/// Prepares an overlay root: creates the upper and its work directory, refuses
/// a host that cannot mount an unprivileged overlay, and freezes the mount
/// options.
///
/// `lower` is the already-canonicalized rootfs. The upper is created if absent
/// and resolved, and a hidden work directory — which the overlay requires empty
/// and on the same filesystem as the upper — is created beside it. The three
/// layer paths are checked for the `,` and `:` characters the overlay option
/// string reserves, the host is preflighted through
/// [`overlay_blocker`](crate::host::overlay_blocker), and the
/// `lowerdir=…,upperdir=…,workdir=…,userxattr` option string is built once.
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
            errno: errno.raw_os_error(),
        })?;
        lowers.push(resolved);
    }

    // An overlay with no upper would be a read-only merge; the sandbox needs
    // somewhere for its writes to land, so the upper is required.
    let Some(upper) = overlay.upper.as_deref() else {
        return Err(ConfigError::OverlayUpperMissing.into());
    };

    // Create and resolve the upper. A relative or non-existent upper is created;
    // the result is the absolute path the mount options name.
    let upper = prepare_layer_dir(OverlayLayer::Upper, upper)?;

    // The upper needs a parent directory: the work directory the library
    // derives is a sibling of the upper, and the host preflight below runs in
    // the parent so its scratch entries land beside the upper rather than inside
    // it. The upper is canonical here, so the only path without one is `/` —
    // which an overlay could not use anyway, since its writes would land over
    // the whole host root.
    let Some(scratch) = upper.parent().map(Path::to_path_buf) else {
        return Err(ConfigError::OverlayUpperIsRoot { path: upper }.into());
    };

    // The work directory sits beside the upper, on the same filesystem, so the
    // overlay can move files between them. A hidden sibling keyed to the upper's
    // name keeps it out of the way and distinct per upper; a caller may name its
    // own instead.
    let work = match overlay.work.as_deref() {
        Some(work) => work.to_path_buf(),
        None => overlay_work_dir(&upper).ok_or(ConfigError::OverlayUpperIsRoot {
            path: upper.clone(),
        })?,
    };
    let work = prepare_layer_dir(OverlayLayer::Work, &work)?;

    // The overlay moves files between the upper and the work directory, so the
    // kernel requires them on one filesystem. A caller that named its own work
    // directory can have put it elsewhere; comparing the two devices refuses
    // that here, with the layer named, rather than at the mount as a bare
    // EXDEV from a syscall the caller never issued.
    let device = |layer, path: &Path| {
        rustix::fs::stat(path)
            .map(|stat| stat.st_dev)
            .map_err(|errno| overlay_errno(layer, path, errno))
    };
    if device(OverlayLayer::Upper, &upper)? != device(OverlayLayer::Work, &work)? {
        return Err(ConfigError::OverlayDirUnusable {
            layer: OverlayLayer::Work,
            path: work,
            errno: Errno::XDEV.raw_os_error(),
        }
        .into());
    }

    // The option string is comma-separated and colon-delimited; a layer path
    // bearing either character would misparse, so refuse it rather than build a
    // truncated mount.
    for path in lowers
        .iter()
        .map(PathBuf::as_path)
        .chain([upper.as_path(), work.as_path()])
    {
        let bytes = path.as_os_str().as_bytes();
        if bytes.contains(&b',') || bytes.contains(&b':') {
            return Err(ConfigError::OverlayPathInvalid {
                path: path.to_path_buf(),
            }
            .into());
        }
    }

    // Refuse a host that cannot establish an unprivileged overlay whose upper
    // lives on this filesystem, before any fork — the same fail-early posture
    // the identity-map validation takes. The probe runs on the upper's parent
    // (its own filesystem, since the upper is a directory within it), so its
    // scratch files land beside the upper rather than inside it.
    if let Some(blocker) = crate::host::overlay_blocker(&scratch) {
        return Err(ConfigError::OverlayUnavailable { blocker }.into());
    }

    // `lowerdir=` is highest-precedence-first, the reverse of this type's
    // base-first order, so the resolved stack is emitted reversed.
    let mut options = Vec::new();
    options.extend_from_slice(b"lowerdir=");
    for (i, lower) in lowers.iter().rev().enumerate() {
        if i > 0 {
            options.push(b':');
        }
        options.extend_from_slice(lower.as_os_str().as_bytes());
    }
    options.extend_from_slice(b",upperdir=");
    options.extend_from_slice(upper.as_os_str().as_bytes());
    options.extend_from_slice(b",workdir=");
    options.extend_from_slice(work.as_os_str().as_bytes());
    options.extend_from_slice(b",userxattr");
    let options = CString::new(options).map_err(|_| ConfigError::EmbeddedNul)?;
    Ok(OverlayPlan {
        options,
        lower: lowers,
        upper,
        work,
    })
}

/// The overlay work directory the library manages beside `upper`: a hidden
/// sibling keyed to the upper's name, on the same filesystem the overlay
/// requires it share with the upper. Returns `None` when `upper` has no parent or
/// no file name.
///
/// Shared by the overlay-plan construction here and the layered-build layer's
/// disposal, so the directory an overlay-rooted cage creates and the one the
/// build layer removes are the same.
pub(crate) fn overlay_work_dir(upper: &Path) -> Option<PathBuf> {
    let (parent, name) = (upper.parent()?, upper.file_name()?);
    let mut work_name = OsString::from(".");
    work_name.push(name);
    work_name.push(".work");
    Some(parent.join(work_name))
}

/// The mode an overlay layer directory the library creates is given.
///
/// Stated rather than left to the process umask, for the same reason
/// [`DIR_MODE`] is: the directory outlives the sandbox on the host, and whether
/// the layer a build keeps is readable is not a property worth taking from
/// whatever umask the build happened to run under. A layer directory that was
/// already there is left at the mode its owner gave it.
const OVERLAY_DIR_MODE: RawMode = 0o755;

/// Creates an overlay layer directory if it is absent and returns its absolute
/// path, refusing to adopt an entry the calling user does not own.
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
/// already applies to its throwaway probe entries in the same directory.
///
/// Ancestors above the leaf are created with `create_dir_all`, as before: the
/// caller named them, so reaching them through a symbolic link is the caller's
/// business, the same position [`open_dir`] takes. The absolute path is composed
/// from the *parent's* canonical path and the leaf's own name, so the leaf is
/// never resolved as a link that the checks above just established it is not.
fn prepare_layer_dir(layer: OverlayLayer, path: &Path) -> Result<PathBuf, Error> {
    // A path with no file name is `/` or a `..` chain; neither is a directory
    // this can create, and `/` as a layer is refused by name below.
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(ConfigError::OverlayUpperIsRoot {
            path: path.to_path_buf(),
        }
        .into());
    };
    // An empty parent means a bare relative name: the working directory.
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    std::fs::create_dir_all(parent).map_err(|err| overlay_io(layer, parent, err))?;
    let dirfd = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| overlay_errno(layer, parent, errno))?;

    match rustix::fs::mkdirat(&dirfd, name, Mode::from_raw_mode(OVERLAY_DIR_MODE)) {
        // The mode is set again, because `mkdir` narrows it by the process
        // umask and the layer outlives the sandbox on the host: a build under
        // `umask 077` would otherwise leave a `0700` upper for whatever consumes
        // it next. Only the directory this call just created is chmod-ed, so an
        // adopted one keeps the mode its owner gave it — the same rule the
        // sandbox stage follows for a mount point it creates.
        Ok(()) => {
            rustix::fs::chmodat(
                &dirfd,
                name,
                Mode::from_raw_mode(OVERLAY_DIR_MODE),
                AtFlags::empty(),
            )
            .map_err(|errno| overlay_errno(layer, path, errno))?;
        }
        Err(Errno::EXIST) => {
            let stat = rustix::fs::statat(&dirfd, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|errno| overlay_errno(layer, path, errno))?;
            let is_dir = FileType::from_raw_mode(stat.st_mode) == FileType::Directory;
            if !is_dir || stat.st_uid != rustix::process::geteuid().as_raw() {
                return Err(ConfigError::OverlayDirUnowned {
                    layer,
                    path: path.to_path_buf(),
                }
                .into());
            }
        }
        Err(errno) => return Err(overlay_errno(layer, path, errno)),
    }

    let parent = std::fs::canonicalize(parent).map_err(|err| overlay_io(layer, parent, err))?;
    Ok(parent.join(name))
}

/// Builds the configuration error for a host I/O failure preparing an overlay
/// layer directory, naming which of the two the failure was.
fn overlay_io(layer: OverlayLayer, path: &Path, err: std::io::Error) -> Error {
    ConfigError::OverlayDirUnusable {
        layer,
        path: path.to_path_buf(),
        errno: err.raw_os_error().unwrap_or(Errno::IO.raw_os_error()),
    }
    .into()
}

/// [`overlay_io`] for the raw-syscall paths, which report an [`Errno`] rather
/// than an [`std::io::Error`].
fn overlay_errno(layer: OverlayLayer, path: &Path, errno: Errno) -> Error {
    ConfigError::OverlayDirUnusable {
        layer,
        path: path.to_path_buf(),
        errno: errno.raw_os_error(),
    }
    .into()
}

/// Lowers the mount profile into the frozen op list the child process
/// executes.
///
/// Each op carries every path it needs as a rootfs-relative `CString`, with
/// mount-target directory chains precomputed as [`MountDir`]s, so the child
/// process performs no path manipulation. The label list is parallel to the ops
/// and caller-side only: it names the mount in a setup error.
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
            self.push(
                MountOp {
                    dirs: Vec::new(),
                    create_file: Some(rel_cstring(&["dev", device])?),
                    action: MountAction::Bind {
                        source: cstring(OsStr::new(&format!("/dev/{device}")))?,
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
                errno: err.raw_os_error().unwrap_or(Errno::IO.raw_os_error()),
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
            "{} at {}{}",
            source.display(),
            bind.target.display(),
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
        let flags = u32::try_from(raw.flags)
            .map_err(|_| ConfigError::MountFlagsInvalid { flags: raw.flags })?;
        let source = match &raw.source {
            Some(path) => cstring(path.as_os_str())?,
            None => CString::default(),
        };
        let fstype = match &raw.fstype {
            Some(fstype) => CString::new(fstype.as_str()).map_err(|_| ConfigError::EmbeddedNul)?,
            None => CString::default(),
        };
        let data = match &raw.data {
            Some(data) => CString::new(data.as_str()).map_err(|_| ConfigError::EmbeddedNul)?,
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
            format!("raw mount at {}", raw.target.display()),
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
        let Ok(source) = std::fs::canonicalize("/etc/resolv.conf") else {
            return Ok(());
        };
        if !source.is_file() {
            return Ok(());
        }
        self.push(
            MountOp {
                dirs: dir_chain(&["etc"], DIR_MODE)?,
                create_file: Some(rel_cstring(&["etc", "resolv.conf"])?),
                action: MountAction::Bind {
                    source: cstring(source.as_os_str())?,
                    target: rel_cstring(&["etc", "resolv.conf"])?,
                    read_only: true,
                },
            },
            "/etc/resolv.conf".to_string(),
        );
        Ok(())
    }
}

/// The host paths of the mount targets `ops` has to create as empty files.
///
/// A file bind needs its target to exist, so the launch creates one where the
/// root ships none — the managed `/etc/resolv.conf` bind of host networking,
/// and any file bind a caller configures. That file is the sandbox's own
/// contribution, not part of the root, so it is reported here for the caller
/// side to remove once the sandbox is gone.
///
/// `writable` is the host directory the sandbox's writes land in, and `layers`
/// the host directories an already-present target could come from; for a plain
/// rootfs both are that rootfs, and for an overlay root the upper and the whole
/// layer stack respectively.
///
/// Two targets are deliberately left out, because neither is a file in the root
/// at a path this can name:
///
/// - one already present in any layer, which the root ships and the launch
///   therefore does not create. Presence is any entry at the path, a symbolic
///   link included: the launch creates the target with `O_EXCL`, so an entry of
///   any kind is one it leaves alone;
/// - one under the target of an earlier op, which is created inside that mount
///   — a tmpfs that vanishes with the namespace, or a caller's own bind source
///   — rather than in the root directory on the host.
///
/// Directories the launch creates are not placeholders: a mount point directory
/// is part of what a launch contributes to a tree, created at the mode of the
/// directory it stands for, and is left in place.
fn created_file_targets(
    ops: &[MountOp],
    writable: &Path,
    layers: &[PathBuf],
) -> ManagedPlaceholders {
    let mut mounted: Vec<PathBuf> = Vec::new();
    let mut paths = Vec::new();
    let layers: Vec<Option<OwnedFd>> = layers.iter().map(|layer| open_root(layer)).collect();
    for op in ops {
        if let Some(file) = &op.create_file {
            let relative = Path::new(OsStr::from_bytes(file.to_bytes()));
            let covered = mounted.iter().any(|mount| relative.starts_with(mount));
            let present = layers
                .iter()
                .any(|layer| entry_in_root(layer.as_ref(), relative) != Presence::Absent);
            if !covered && !present {
                paths.push(relative.to_path_buf());
            }
        }
        if let Some(target) = op.action.target() {
            mounted.push(PathBuf::from(OsStr::from_bytes(target.to_bytes())));
        }
    }
    ManagedPlaceholders {
        root: if paths.is_empty() {
            PathBuf::new()
        } else {
            writable.to_path_buf()
        },
        paths,
    }
}

/// What a root-relative lookup found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Presence {
    /// Nothing is at the path.
    Absent,
    /// An entry of some kind is at the path.
    Present,
    /// The lookup could not reach a verdict — a permission refusal, an
    /// unreadable root. Treated as [`Present`](Self::Present) everywhere here:
    /// what the answer decides is whether the launch created an entry that this
    /// side may later unlink, and "not sure" must not become "mine to remove".
    Unknown,
}

/// Opens a root directory for the root-relative lookups below, or `None` when it
/// cannot be opened at all.
///
/// `O_PATH`: this descriptor is only ever the anchor of an `openat2`, so it needs
/// no read access to the directory itself.
pub(crate) fn open_root(root: &Path) -> Option<OwnedFd> {
    rustix::fs::open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()
}

/// Whether `relative` names an entry inside the tree rooted at `root`.
///
/// Resolved with `openat2` and `RESOLVE_IN_ROOT`, the same way the sandbox stage
/// resolves every mount target against the new-root descriptor, so that an
/// absolute symbolic link inside the tree — `./etc -> /etc` in an untrusted
/// unpacked tarball, or the `/etc/resolv.conf -> /run/systemd/resolve/…` any
/// image taken from a resolved host ships — resolves *within the tree* rather
/// than against the host's own root. Joining the two paths and asking the host
/// instead would answer a question about the host's filesystem, and would let a
/// later removal keyed to the same path land outside the tree entirely.
///
/// `O_NOFOLLOW` on the final component, so an entry is an entry whatever its
/// kind: the launch creates its target with `O_EXCL` and leaves anything already
/// there alone, dangling symbolic link included.
pub(crate) fn entry_in_root(root: Option<&OwnedFd>, relative: &Path) -> Presence {
    let Some(root) = root else {
        return Presence::Unknown;
    };
    let Ok(relative) = CString::new(relative.as_os_str().as_bytes()) else {
        return Presence::Unknown;
    };
    match rustix::fs::openat2(
        root,
        relative.as_c_str(),
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::IN_ROOT,
    ) {
        Ok(_) => Presence::Present,
        // Nothing at the path, or a non-directory where a directory would have
        // to be for anything to sit under it: either way the entry is absent.
        Err(Errno::NOENT | Errno::NOTDIR) => Presence::Absent,
        Err(_) => Presence::Unknown,
    }
}

/// Splits an absolute sandbox path into its normal components, rejecting
/// relative paths, the bare root, and `.` or `..` components.
fn sandbox_path_components(path: &Path) -> Result<Vec<&OsStr>, Error> {
    let invalid = || {
        Error::from(ConfigError::MountTargetInvalid {
            path: path.to_path_buf(),
        })
    };
    let mut iter = path.components();
    if iter.next() != Some(Component::RootDir) {
        return Err(invalid());
    }
    let mut components = Vec::new();
    for component in iter {
        match component {
            Component::Normal(name) => components.push(name),
            _ => return Err(invalid()),
        }
    }
    if components.is_empty() {
        return Err(invalid());
    }
    Ok(components)
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
            parent: CString::new(parent.clone()).map_err(|_| ConfigError::EmbeddedNul)?,
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
    Ok(CString::new(path).map_err(|_| ConfigError::EmbeddedNul)?)
}

/// Converts an `OsStr` to a `CString`, rejecting interior NUL bytes.
pub(crate) fn cstring(value: &OsStr) -> Result<CString, ConfigError> {
    CString::new(value.as_bytes()).map_err(|_| ConfigError::EmbeddedNul)
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
            resource: resource.to_kernel(),
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
pub(crate) fn exec_label(command: &Path, search: &[CString]) -> String {
    let command = command.display();
    if search.is_empty() {
        return command.to_string();
    }
    let candidates: Vec<String> = search
        .iter()
        .map(|candidate| {
            Path::new(OsStr::from_bytes(candidate.as_bytes()))
                .display()
                .to_string()
        })
        .collect();
    format!("{command}, searched {}", candidates.join(", "))
}

/// Whether a command path contains a path separator, so it names a location
/// rather than a bare name to resolve against `PATH`.
pub(crate) fn command_has_slash(command: &Path) -> bool {
    command.as_os_str().as_bytes().contains(&b'/')
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
        assert!(matches!(err, Error::Config(ConfigError::EmbeddedNul)));
    }

    #[test]
    fn build_rejects_a_missing_rootfs_with_the_os_error() {
        let err = sh_in("/ferroday-cage/does/not/exist").build().unwrap_err();
        match err {
            Error::Config(ConfigError::RootfsUnusable { errno, .. }) => {
                assert_eq!(errno, Errno::NOENT.raw_os_error());
            }
            other => panic!("expected RootfsUnusable, got {other:?}"),
        }
    }

    #[test]
    fn build_rejects_a_rootfs_that_is_not_a_directory() {
        let err = sh_in("/dev/null").build().unwrap_err();
        match err {
            Error::Config(ConfigError::RootfsUnusable { errno, .. }) => {
                assert_eq!(errno, Errno::NOTDIR.raw_os_error());
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
    fn a_built_cage_clones_its_frozen_plan() {
        let cage = sh_in("/tmp").arg("-c").arg("true").build().unwrap();
        let clone = cage.clone();
        // The clone is an independent copy carrying the same frozen program
        // and arguments; the original is untouched and both remain usable.
        assert_eq!(clone.plan.program, cage.plan.program);
        assert_eq!(clone.plan.args, cage.plan.args);
        assert_eq!(clone.plan.rootfs_path, cage.plan.rootfs_path);
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
            Error::Config(ConfigError::BindSourceUnusable { errno, .. }) => {
                assert_eq!(errno, Errno::NOENT.raw_os_error());
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

    #[test]
    fn build_rejects_an_empty_hostname() {
        let err = sh_in("/tmp").hostname("").build().unwrap_err();
        assert!(matches!(err, Error::Config(ConfigError::HostnameInvalid)));
    }

    #[test]
    fn build_rejects_an_overlong_hostname() {
        let err = sh_in("/tmp").hostname("h".repeat(65)).build().unwrap_err();
        assert!(matches!(err, Error::Config(ConfigError::HostnameInvalid)));
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
            .position(|label| label == "raw mount at /raw")
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
        assert!(matches!(
            err,
            Error::Config(ConfigError::MountFlagsInvalid { flags }) if flags == 1 << 40
        ));
    }

    #[test]
    fn a_nul_byte_in_raw_mount_data_is_rejected() {
        let err = sh_in("/tmp")
            .raw_mount(RawMount::new("/raw").fstype("tmpfs").data("mode\u{0}777"))
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(ConfigError::EmbeddedNul)));
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
        assert!(cage.plan.op_labels[0].starts_with("/proc at /proc"));
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
    struct FakeMapper;

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
        let effective = rustix::thread::capabilities(None)
            .map(|sets| sets.effective)
            .unwrap_or(rustix::thread::CapabilitySet::empty());
        if effective.contains(rustix::thread::CapabilitySet::SETUID) {
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
        let groups: Vec<u32> = run_as.groups.iter().map(|group| group.as_raw()).collect();
        assert_eq!(groups, [250, 100]);
    }

    #[test]
    fn run_as_root_is_valid_under_the_single_map() {
        let cage = sh_in("/tmp").run_as(Identity::new(0, 0)).build().unwrap();
        let run_as = cage.plan.run_as.as_ref().unwrap();
        assert_eq!(run_as.uid.as_raw(), 0);
    }

    #[test]
    fn run_as_nonroot_under_the_single_map_is_unmapped() {
        let err = sh_in("/tmp")
            .run_as(Identity::new(250, 250).groups([250]))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::RunAsUnmapped { id: 250, .. })
        ));
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
    fn a_resolv_conf_target_the_launch_creates_is_recorded_for_removal() {
        // A bind needs its target to exist, so a rootfs shipping no resolv.conf
        // has one created. The plan records that path, which is how the caller
        // side knows to take it away once the sandbox is gone. A rootfs that
        // ships the file has nothing created and so nothing to remove.
        if !host_has_resolv_conf() {
            return;
        }
        let dir = crate::scratch::Scratch::new("resolv");
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
        if !host_has_resolv_conf() {
            return;
        }
        let dir = crate::scratch::Scratch::new("resolv-overlay");
        let base = dir.join("base");
        let upper = dir.join("upper");
        std::fs::create_dir_all(base.join("etc")).unwrap();

        let built = Cage::builder()
            .overlay_rootfs(&base, &upper)
            .network(Network::Host)
            .command("/bin/sh")
            .build();
        let Ok(cage) = built else {
            // A host that cannot establish an unprivileged overlay refuses the
            // build, so there is no plan to assert against.
            assert!(
                std::env::var_os("FERRODAY_CAGE_REQUIRE_OVERLAY").is_none(),
                "overlay-rooted cages are required but unavailable here"
            );
            eprintln!("skipping: an unprivileged overlay is unavailable here");
            return;
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

    #[test]
    fn a_caller_file_bind_target_the_launch_creates_is_recorded_for_removal() {
        // A caller's file bind creates its target the same way the managed
        // resolv.conf bind does, and leaves the same residue if nothing takes
        // it away — an empty file the root never shipped, carried into an
        // export of the tree.
        let dir = crate::scratch::Scratch::new("bind-placeholder");
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
    fn a_root_internal_absolute_symlink_is_judged_inside_the_root() {
        // A rootfs may hold an absolute symbolic link — an unpacked tarball is
        // entitled to ship `./absolute -> /etc`, and any image taken from a
        // systemd-resolved host ships `/etc/resolv.conf` as one. The launch
        // resolves its mount targets against the new-root descriptor with
        // RESOLVE_IN_ROOT, so such a link lands inside the rootfs; the
        // bookkeeping here has to agree, or it records a path the launch never
        // wrote to and answers a question about the host's filesystem instead.
        let dir = crate::scratch::Scratch::new("placeholder-in-root");
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
            .find(|(_, label)| label.ends_with("at /a/b/hostname"))
            .expect("the bind op");
        assert_eq!(op.dirs.len(), 2, "both /a and /a/b are created");
        assert!(op.dirs.iter().all(|dir| dir.mode == 0o755));
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    /// A profile exercising every serializable field.
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

    #[test]
    fn a_restricted_profile_rejects_a_bind_mount() {
        let profile = "[[mount]]\nkind = \"bind\"\nsource = \"/etc\"\ntarget = \"/host-etc\"\n";
        let err = toml::from_str::<RestrictedProfile>(profile).unwrap_err();
        assert!(err.to_string().contains("bind mount"), "{err}");
    }

    #[test]
    fn a_restricted_profile_rejects_a_raw_mount() {
        let profile = "[[mount]]\nkind = \"raw\"\ntarget = \"/raw\"\nfstype = \"tmpfs\"\n";
        let err = toml::from_str::<RestrictedProfile>(profile).unwrap_err();
        assert!(err.to_string().contains("raw mount"), "{err}");
    }

    #[test]
    fn the_profile_key_set_is_pinned() {
        // The profile format is a published interface, and every serialised
        // field carries an explicit `rename`, so a Rust-side field rename
        // cannot silently rename a key. This test is the other half of that
        // guarantee: it fails when a key appears, disappears, or changes
        // spelling, which is a profile-format change whatever the Rust API did.
        // `rootfs` and `overlay` are alternatives — setting either clears the
        // other — so the full key set is the union of a plain-rooted and an
        // overlay-rooted profile.
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
            .env("K", "V")
            .bind("/host", "/guest")
            .bind_ro("/host-ro", "/guest-ro")
            .raw_mount(
                RawMount::new("/dev/shm")
                    .source("/host-shm")
                    .fstype("tmpfs")
                    .flags(1)
                    .data("mode=1777"),
            );
        let overlaid = builder.clone().overlay(
            Overlay::new()
                .lower("/srv/base")
                .upper("/tmp/upper")
                .work("/tmp/work"),
        );

        let render = |builder: &CageBuilder| -> toml::Table {
            toml::to_string(builder)
                .expect("the builder serializes")
                .parse()
                .expect("the profile is valid TOML")
        };
        let table = render(&builder);
        let overlay_table = render(&overlaid);

        let mut keys: Vec<&str> = table
            .keys()
            .chain(overlay_table.keys())
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
    }

    #[test]
    fn a_restricted_profile_rejects_host_networking() {
        let err = toml::from_str::<RestrictedProfile>("network = \"host\"\n").unwrap_err();
        assert!(err.to_string().contains("host networking"), "{err}");
    }

    #[test]
    fn a_restricted_profile_rejects_an_overlay_root() {
        // An overlay upper is created, not required to exist, so honoring one
        // would have the profile choose a host path for the library to make
        // directories at — and to run the overlay preflight probe in.
        let profile = "command = \"/bin/sh\"\n\
                       [overlay]\nlower = [\"/srv/base\"]\n\
                       upper = \"/tmp/profile-chosen-upper\"\n";
        let err = toml::from_str::<RestrictedProfile>(profile).unwrap_err();
        assert!(err.to_string().contains("an overlay root"), "{err}");
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

    #[test]
    fn an_overlay_layer_directory_is_created_fresh_and_owned() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = crate::scratch::Scratch::new("overlay-layer-dir");

        // A layer directory the library creates: made here, at the stated mode.
        // (The umask is not set here to prove the chmod that follows the
        // `mkdir`: it is process-global, and this suite runs its tests in
        // parallel threads, so narrowing it would reach every directory another
        // test created meanwhile.)
        let fresh = scratch.join("nested/fresh");
        let prepared = prepare_layer_dir(OverlayLayer::Upper, &fresh).unwrap();
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
            prepare_layer_dir(OverlayLayer::Upper, &fresh).unwrap(),
            prepared,
        );
        assert_eq!(mode(&fresh), 0o700, "an adopted layer keeps its own mode");

        // A symbolic link at the path is refused rather than followed. Left
        // followed, `upperdir=` would name the destination and every write the
        // sandbox made would land there instead.
        let destination = scratch.join("elsewhere");
        std::fs::create_dir(&destination).unwrap();
        let planted = scratch.join("planted");
        std::os::unix::fs::symlink(&destination, &planted).unwrap();
        let err = prepare_layer_dir(OverlayLayer::Upper, &planted).unwrap_err();
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
        let err = prepare_layer_dir(OverlayLayer::Work, &file).unwrap_err();
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
    fn an_overlay_upper_at_the_filesystem_root_is_refused() {
        // `/` has no parent, so there is nowhere for the work directory beside
        // the upper or for the host preflight's scratch entries — and an upper
        // there would put the sandbox's writes over the whole host root.
        let lower = crate::scratch::Scratch::new("overlay-upper-root");
        let err = Cage::builder()
            .overlay_rootfs(&*lower, "/")
            .command("/bin/sh")
            .build()
            .unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::OverlayUpperIsRoot { .. })),
            "{err}"
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
    fn a_restricted_profile_rejects_the_host_pid_namespace() {
        // `pid-namespace = false` binds the host's /proc read-write into the
        // sandbox, the same host-resource mapping an explicit `[[mount]]` bind
        // of /proc would perform; the restricted policy reserves it.
        let profile = "rootfs = \"/srv/rootfs/alpine\"\ncommand = \"/bin/sh\"\n\
                       pid-namespace = false\n";
        let err = toml::from_str::<RestrictedProfile>(profile).unwrap_err();
        assert!(err.to_string().contains("host PID namespace"), "{err}");
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

    /// A build without the `subid` feature refuses a subordinate profile at
    /// load time: no delegate could establish it, and an identity posture is
    /// never silently downgraded.
    #[cfg(not(feature = "subid"))]
    #[test]
    fn a_subordinate_profile_is_refused_without_the_subid_feature() {
        let profile = "rootfs = \"/tmp\"\ncommand = \"/bin/sh\"\nidentity-map = \"subordinate\"\n";
        let err = toml::from_str::<CageBuilder>(profile).unwrap_err();
        assert!(err.to_string().contains("subid"), "{err}");
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
