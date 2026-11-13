//! The restriction fallback: confine a plain spawned command with Landlock
//! and seccomp, for hosts without unprivileged user namespaces.
//!
//! A [`Restriction`] is the degraded counterpart of a [`Cage`], for a host that
//! cannot provide the namespaces and root-swap a cage is built from. It spawns
//! the command directly on the host, confined by the same Landlock filesystem
//! and network rules and seccomp filters the cage's hardening layer applies,
//! always under the no-new-privileges flag. The command runs in the host PID
//! space as the calling user, unmapped.
//!
//! Each control confines only what it covers, and nothing is confined by
//! default:
//!
//! - a Landlock filesystem grant restricts the host filesystem to the granted
//!   paths, but with no filesystem grant the command sees the entire host
//!   filesystem;
//! - a Landlock network grant restricts *TCP* bind and connect to the granted
//!   ports, but leaves UDP, other socket families, and — with no network grant
//!   — all networking unrestricted;
//! - a seccomp filter restricts syscalls, but confines neither the filesystem
//!   nor the network.
//!
//! A restriction confined only by seccomp therefore still exposes the whole
//! host filesystem as the calling user; the filesystem boundary is the
//! Landlock grant, not the filter.
//!
//! # Residual host surface
//!
//! Because a restriction runs a host process with no namespace or root-swap
//! isolation, several host-reaching surfaces are governed only by the controls
//! the restriction applies. A restriction always drops to the empty capability
//! set, so no capability-gated reach remains; what is left is same-credential
//! access:
//!
//! - **Signals.** The command shares the host's PID space and runs as the
//!   calling user, so it can signal every process that user owns, and
//!   `kill(-1, ..)` reaches all of them at once.
//! - **Abstract-socket services.** An abstract `AF_UNIX` address belongs to the
//!   network namespace, which a restriction shares, so the session bus and the
//!   X server are reachable through theirs. A Landlock network grant governs TCP
//!   alone, and a seccomp filter cannot read the address a connect names.
//! - **Pathname sockets.** A unix socket at a path the command can name accepts
//!   its connection: the session bus's under `/run/user`, an SSH agent's, a
//!   container runtime's. A Landlock filesystem grant governs files, not a
//!   `connect`, before ABI 9. From ABI 9,
//!   [`landlock_resolve_unix`](RestrictionBuilder::landlock_resolve_unix)
//!   confines it to the sockets the command created and those beneath a path
//!   granted [`FsAccess::RESOLVE_UNIX`](crate::FsAccess::RESOLVE_UNIX).
//! - **Same-user `/proc` and `ptrace`.** A command with no Landlock domain can
//!   `ptrace` the calling user's other processes, where the host's Yama policy
//!   permits it, and read their `/proc/<pid>/{environ,mem,maps}`. Any Landlock
//!   domain refuses both against a process outside it, whatever it grants.
//! - **The user's keyrings.** The fresh session keyring every launch joins
//!   ends possession of the caller's session keys, but the user keyring, the
//!   user session keyring, and the persistent keyring belong to the user rather
//!   than the session. The command is that user, so it can link them into its
//!   own keyring and read every key they hold. A launch the kernel refuses the
//!   fresh keyring refuses the command every key syscall instead, which closes
//!   this too. See [The session
//!   keyring](https://gregordinary.github.io/ferroday-cage/how-the-sandbox-is-built.html#the-session-keyring).
//! - **The caller's terminal.** A command holding a descriptor onto the
//!   caller's terminal can read what is typed at it, change its settings, and —
//!   where the terminal is the command's own controlling terminal — push input
//!   into it with the `TIOCSTI` ioctl. Landlock does not close this, whatever
//!   the ABI: its rights bind a descriptor when it is opened, and an inherited
//!   terminal was opened before the ruleset existed. Neither does a namespace or
//!   a swapped root: a controlling terminal is reached through the session, not
//!   through the filesystem, and an inherited descriptor is reached through
//!   neither. What closes it is not handing the terminal over — see below — the
//!   `dev.tty.legacy_tiocsti` sysctl, which modern kernels default to off, or a
//!   seccomp filter on `ioctl`, which the curated denylist provides.
//!
//! On a kernel with Landlock ABI 6 (Linux 6.12) or later a restriction closes
//! the first three. Its default [`landlock_scope`](RestrictionBuilder::landlock_scope)
//! confines signals and abstract-socket connections to the processes the
//! command started, and the scopes give every restriction a Landlock domain,
//! grants or none. On an older kernel the default scopes are dropped, signals
//! and abstract sockets stay open, and only a Landlock grant creates a domain;
//! the curated seccomp denylist still blocks `ptrace` and `process_vm_*`. Scopes
//! the caller names are refused there instead, since nothing else would bound
//! those reaches. The curated denylist also blocks `keyctl`, which is what
//! closes the keyrings.
//!
//! A default sandbox closes the first three through its PID and network
//! namespaces. Its own user namespace gives it user keyrings of its own, so of
//! the fourth only a key whose permissions grant its owner read stays
//! reachable, by serial number.
//!
//! # The caller's terminal
//!
//! The terminal is not a namespace question, so a sandbox and a restriction
//! answer it the same way: **a sandboxed command reaches the caller's terminal
//! exactly through the standard streams the caller handed it.** Closing it
//! therefore takes all three streams, and each closes a different part.
//!
//! **Standard input decides the session.** A command that inherits it
//! ([`Stdio::Inherit`](crate::Stdio::Inherit), the default) has been given the
//! caller's terminal along with it, so it stays in the caller's session. There
//! the terminal is reachable through file descriptor 0 and through `/dev/tty`,
//! which is the same terminal by a different name. A command that does not
//! inherit it — [`Stdio::Null`](crate::Stdio::Null) or
//! [`Stdio::Fd`](crate::Stdio::Fd) — runs in a session of its own, with no
//! controlling terminal at all: `/dev/tty` fails with `ENXIO`, and `TIOCSTI` is
//! refused on every terminal descriptor, because the kernel grants it only for
//! the caller's own controlling terminal.
//!
//! **The output pair is not closed by the session.** Run from a shell with no
//! redirection, file descriptors 1 and 2 are dups of one read-write open of the
//! caller's terminal, and a session of the sandbox's own does not take them
//! away. A command holding them can still read what is typed, leave the
//! terminal without echo with `tcsetattr`, and resize it with `TIOCSWINSZ`.
//! [`stdout`](RestrictionBuilder::stdout) and
//! [`stderr`](RestrictionBuilder::stderr) are what close that, and a capturing
//! launch closes it too by supplying pipes of its own.
//!
//! **What it costs.** A sandbox in a session of its own is outside the caller's
//! job control, so a caller that wants to stop it on an interrupt uses
//! [`Running::terminate`](crate::Running::terminate) or
//! [`Running::kill`](crate::Running::kill). It also has no job control of its
//! own, since the session it holds owns no terminal — and under
//! [`Stdio::Inherit`](crate::Stdio::Inherit) it does, but only by taking the
//! caller's terminal's foreground process group, a shell inside the sandbox
//! competing with the caller's own shell for one terminal.
//!
//! A restriction is a deliberately weaker boundary with its own
//! configuration, not an automatic downgrade of a cage: its paths are host
//! paths, so the grants that make a command runnable (its interpreter and
//! libraries among them) must name host locations. A launch of a [`Cage`] on
//! a blocked host still fails with [`Error::UsernsUnavailable`]; a caller
//! that wants to degrade catches that error and runs its separately
//! configured restriction.
//!
//! Beyond the confinement, a restriction shares the cage's process model:
//! the clean deterministic environment, the standard-stream dispositions,
//! output streaming to an [`Observer`], a pseudoterminal of its own through
//! [`spawn_terminal`](Restriction::spawn_terminal), and the [`Running`] handle
//! with waiting, deadlines, termination, and kill. Because there is no PID
//! namespace, the same caveats as [`CageBuilder::pid_namespace`]`(false)`
//! apply: descendants of the command can outlive it, and a kill reaches only
//! the command process itself, unless the restriction has a cgroup of its own
//! from [`cgroup_parent`](RestrictionBuilder::cgroup_parent), through which it
//! ends every process of the tree. The cgroup is also what bounds the tree
//! together, where an [`rlimit`](RestrictionBuilder::rlimit) bounds each
//! process alone.
//!
//! [`Cage`]: crate::Cage
//! [`CageBuilder::pid_namespace`]: crate::CageBuilder::pid_namespace
//! [`Error::UsernsUnavailable`]: crate::Error::UsernsUnavailable

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;

use rustix::thread::UnshareFlags;

use crate::cgroup::{CgroupLimit, CgroupReach, CgroupSettings};
use crate::error::{ConfigError, Error};
use crate::hardening::{FsAccess, LandlockScope, NetAccess, Request, SeccompPolicy};
use crate::limits::{Limit, Resource};
use crate::mechanism::{
    Confinement, HardeningPlan, IdentityPlan, LaunchPlan, ManagedPlaceholders, RootPlan, StdioPlan,
};
use crate::observer::{Observer, Output};
use crate::running::Running;
use crate::spec::{self, Stdio};
use crate::status::ExitStatus;

/// The base environment every restricted command starts with.
///
/// Deterministic, like the cage's base: nothing is read from the host.
/// Unlike the cage's, it carries no `HOME` — the command runs as the real
/// calling user, for whom `/root` would be wrong, and reading the host's
/// `HOME` would break determinism. A caller that wants `HOME` sets it.
const BASE_ENV: [(&str, &str); 1] = [("PATH", spec::BASE_PATH)];

/// A validated, ready-to-run restriction.
///
/// Constructed by [`Restriction::builder`]; all validation, the seccomp
/// compilation, and the Landlock lowering happen in
/// [`RestrictionBuilder::build`], which freezes the configuration into a
/// launch plan. [`run`](Restriction::run) then executes the command under
/// the restriction and blocks until it terminates.
///
/// # Example
///
/// Run a command that may read the system trees and a work directory, and
/// nothing else on the filesystem:
///
/// ```no_run
/// use ferroday_cage::{FsAccess, Restriction};
///
/// # fn main() -> ferroday_cage::Result<()> {
/// let status = Restriction::builder()
///     .command("/usr/bin/sort")
///     .args(["/work/input"])
///     .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/usr")
///     .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
///     .landlock_fs(FsAccess::READ, "/etc")
///     .landlock_fs(FsAccess::READ | FsAccess::WRITE, "/work")
///     .build()?
///     .run()?;
/// assert!(status.success());
/// # Ok(())
/// # }
/// ```
///
/// A `Restriction` holds no live resources — it is a frozen plan — so it is
/// `Clone` and every launch method takes `&self`, exactly as
/// [`Cage`](crate::Cage) is. One restriction can launch the same command any
/// number of times, concurrently or in sequence.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Restriction {
    /// The frozen launch plan the mechanism executes.
    plan: LaunchPlan,
}

impl Restriction {
    /// The environment this restriction will actually apply.
    ///
    /// The counterpart of [`Cage::resolved_inputs`](crate::Cage::resolved_inputs).
    /// Its mount list is always empty: a restriction confines a process in
    /// place rather than building a filesystem for it.
    pub fn resolved_inputs(&self) -> crate::ResolvedInputs {
        crate::ResolvedInputs::project(&self.plan)
    }

    /// Returns a builder for configuring a restriction.
    pub fn builder() -> RestrictionBuilder {
        RestrictionBuilder::default()
    }

    /// Runs the command under the restriction and blocks until it
    /// terminates.
    ///
    /// Returns `Ok` with the command's [`ExitStatus`] whenever the command
    /// was executed, regardless of its exit code. `Err` is reserved for the
    /// library failing: spawning the process, a setup step (a Landlock rule
    /// that cannot apply, a rejected filter), or collecting the outcome.
    ///
    /// The command runs with the stream dispositions the restriction carries,
    /// which are inherited unless the builder said otherwise.
    pub fn run(&self) -> Result<ExitStatus, Error> {
        self.spawn()?.wait()
    }

    /// Runs the command under the restriction, streaming its output to the
    /// observer, and blocks until it terminates.
    ///
    /// Like [`run`](Self::run), but the command's standard output and
    /// standard error are captured and delivered to `observer` as they are
    /// produced, on the calling thread.
    pub fn run_with(&self, observer: &mut dyn Observer) -> Result<ExitStatus, Error> {
        self.spawn_with(observer)?.wait()
    }

    /// Runs the command under the restriction and returns its exit status
    /// together with everything it wrote.
    ///
    /// The restriction's counterpart of [`Cage::output`](crate::Cage::output),
    /// with the same unbounded-capture caution: for a command whose output
    /// volume the caller does not control, stream through an [`Observer`] that
    /// caps what it keeps instead.
    pub fn output(&self) -> Result<Output, Error> {
        Running::output(&self.plan)
    }

    /// Starts the command under the restriction and returns a handle to it.
    ///
    /// `spawn` blocks until the restriction is applied and the command is
    /// executing, so a setup failure is reported here, as the same typed
    /// error [`run`](Self::run) would return. The command runs with
    /// the stream dispositions the restriction carries; the returned [`Running`]
    /// waits for,
    /// signals, or kills it.
    pub fn spawn(&self) -> Result<Running<'static>, Error> {
        Running::launch(&self.plan, None)
    }

    /// Starts the command under the restriction, capturing its output for
    /// the observer, and returns a handle to it.
    ///
    /// Like [`spawn`](Self::spawn), but the command's standard output and
    /// standard error are captured into pipes. The captured bytes are
    /// delivered to `observer` while the returned handle is waited on; see
    /// [`Observer`].
    pub fn spawn_with<'obs>(
        &self,
        observer: &'obs mut dyn Observer,
    ) -> Result<Running<'obs>, Error> {
        Running::launch(&self.plan, Some(observer))
    }

    /// Starts the command on a pseudoterminal of its own, returning a handle to
    /// it and the caller's end of the terminal.
    ///
    /// The counterpart of
    /// [`Cage::spawn_terminal`](crate::Cage::spawn_terminal), and the fallback
    /// supports it in full. The terminal is allocated the same way, from the
    /// `/dev/ptmx` the command sees, which for a restriction is the host's, so
    /// its replica is a node of the host's `devpts` that the command can name.
    /// The command process is the session leader here, and the allocating
    /// process, since a restriction has no PID namespace and so no init above
    /// it.
    pub fn spawn_terminal(
        &self,
        terminal: &crate::Terminal,
    ) -> Result<(Running<'static>, crate::Pty), Error> {
        Running::launch_terminal(&self.plan, terminal)
    }
}

/// Builder for a [`Restriction`].
///
/// A restriction needs a command and at least one thing to enforce — a
/// Landlock grant or a seccomp policy; a restriction that restricts nothing
/// is rejected by [`build`](Self::build) rather than launching a plain
/// process that appears sandboxed.
///
/// The command starts in `/` with the deterministic base environment
/// (`PATH` alone) plus the caller's variables, inherited standard streams,
/// default signal dispositions, an empty signal mask, and a descriptor table
/// holding only its standard streams. It also starts with no capabilities: a
/// restriction always drops to the empty capability set, and the always-set
/// no-new-privileges flag keeps a set-user-ID or file-capabilities binary from
/// regaining any across the exec. This matters when the caller is privileged —
/// a root process on a host with unprivileged user namespaces disabled is a
/// plausible way to reach the restriction fallback — since it would otherwise
/// pass its full capability set to the command; when the caller is already
/// unprivileged the drop is a no-op.
#[derive(Debug, Clone)]
pub struct RestrictionBuilder {
    command: Option<std::path::PathBuf>,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    /// Whether the deterministic base environment is composed under the
    /// caller's variables. Defaults to `true`, which is why this type carries
    /// a hand-written `Default` rather than deriving one.
    base_env: bool,
    workdir: Option<std::path::PathBuf>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    stop_with_caller: bool,
    rlimits: BTreeMap<Resource, (Limit, Limit)>,
    cgroup: CgroupSettings,
    hardening: Request,
    /// Whether the caller named the scopes through
    /// [`landlock_scope`](Self::landlock_scope), rather than leaving the default
    /// every restriction starts with. A kernel that cannot enforce a named scope
    /// refuses the build, and drops a default one.
    scopes_named: bool,
}

impl Default for RestrictionBuilder {
    fn default() -> Self {
        RestrictionBuilder {
            command: None,
            args: Vec::new(),
            env: Vec::new(),
            base_env: true,
            workdir: None,
            stdin: Stdio::default(),
            stdout: Stdio::default(),
            stderr: Stdio::default(),
            stop_with_caller: false,
            rlimits: BTreeMap::new(),
            cgroup: CgroupSettings::default(),
            hardening: {
                // Every scope, which a restriction needs and a sandbox does not: it
                // has no PID namespace and no network namespace to hide the
                // calling user's other processes behind.
                let mut hardening = Request::default();
                hardening.set_scope(LandlockScope::ALL.iter().copied());
                hardening
            },
            scopes_named: false,
        }
    }
}

impl RestrictionBuilder {
    /// Sets the command to execute under the restriction.
    ///
    /// The path is a host path and must be absolute. It is not resolved
    /// against `PATH`. Executing it requires a Landlock grant with
    /// [`FsAccess::EXECUTE`] covering the file when any grant is configured.
    pub fn command(mut self, program: impl AsRef<Path>) -> Self {
        self.command = Some(program.as_ref().to_path_buf());
        self
    }

    /// Sets a resource limit on the command.
    ///
    /// The restriction's counterpart of
    /// [`CageBuilder::rlimit`](crate::CageBuilder::rlimit), with the same
    /// semantics: the limit is applied to the command process before the
    /// hardening layer and inherited by every process it starts. It matters
    /// more here than in a cage, because a restriction has no namespaces at
    /// all — the only thing bounding what the command consumes is what the
    /// caller sets, this and a cgroup's limits. Each process is held to it
    /// alone, so a command that starts more processes uses more in all;
    /// [`cgroup_limit`](Self::cgroup_limit) bounds the tree together.
    pub fn rlimit(
        mut self,
        resource: Resource,
        soft: impl Into<Limit>,
        hard: impl Into<Limit>,
    ) -> Self {
        self.rlimits.insert(resource, (soft.into(), hard.into()));
        self
    }

    /// Places each launch in a cgroup of its own beneath `parent`.
    ///
    /// The restriction's counterpart of
    /// [`CageBuilder::cgroup_parent`](crate::CageBuilder::cgroup_parent), with
    /// the same semantics: the launch stage joins the cgroup's leaf before it
    /// runs anything, so the command and every process it starts are charged
    /// to the cgroup and held to its limits, and
    /// [`Running::kill`](crate::Running::kill) ends every process of the tree
    /// through it.
    ///
    /// # What the build requires
    ///
    /// The command runs as the caller's user in the host's cgroup namespace,
    /// and the kernel gives a cgroup's files to the user that created it. Left
    /// to itself, the command could lift its limits by writing the files that
    /// hold them, or leave the tree by writing its process id to the parent's
    /// `cgroup.procs`. It could also start a process in another cgroup with
    /// `clone3` and `CLONE_INTO_CGROUP`, which names the cgroup by a
    /// descriptor that may be opened with `O_PATH`, and Landlock checks no such
    /// open. A restriction with a cgroup parent or a
    /// [`cgroup_limit`](Self::cgroup_limit) therefore builds only where both
    /// reaches are closed:
    ///
    /// - its Landlock domain governs file writes, which a filesystem grant
    ///   gives it, and no grant carrying [`FsAccess::WRITE`] lies at, above, or
    ///   beneath a mount of the cgroup v2 hierarchy in this process's mount
    ///   table, judged through links as the launch resolves the grant;
    /// - its [`seccomp`](Self::seccomp) policy answers `clone3` with an errno,
    ///   as the [curated roster](crate::SeccompRules::curated) does with
    ///   `ENOSYS`. A precompiled [`SeccompPolicy::Program`] is not read, so it
    ///   does not count.
    ///
    /// Otherwise [`build`](Self::build) fails with
    /// [`ConfigError::RestrictionCgroupReachable`], whose
    /// [`CgroupReach`](crate::CgroupReach) names the reach left open. Limits
    /// that are not [required](Self::cgroup_required) are refused the same way:
    /// what is refused is a cgroup the command could escape, not a missing
    /// parent.
    ///
    /// ```no_run
    /// use ferroday_cage::{CgroupLimit, FsAccess, Restriction, SeccompPolicy, SeccompRules};
    ///
    /// # fn main() -> ferroday_cage::Result<()> {
    /// let restriction = Restriction::builder()
    ///     .command("/usr/bin/sort")
    ///     .args(["/work/input"])
    ///     .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/usr")
    ///     .landlock_fs(FsAccess::READ | FsAccess::WRITE, "/work")
    ///     .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
    ///     .cgroup_parent("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/sandboxes.scope")
    ///     .cgroup_limit(CgroupLimit::PidsMax(64))
    ///     .build()?;
    /// # let _ = restriction;
    /// # Ok(())
    /// # }
    /// ```
    pub fn cgroup_parent(mut self, parent: impl AsRef<Path>) -> Self {
        self.cgroup.parent = Some(parent.as_ref().to_path_buf());
        self
    }

    /// Holds the command's whole process tree to `limit`, through its cgroup.
    ///
    /// The restriction's counterpart of
    /// [`CageBuilder::cgroup_limit`](crate::CageBuilder::cgroup_limit). The
    /// build requires the confinement
    /// [`cgroup_parent`](Self::cgroup_parent) states, which keeps the command
    /// from lifting the limit or leaving the cgroup, whether or not the limits
    /// are [required](Self::cgroup_required).
    pub fn cgroup_limit(mut self, limit: CgroupLimit) -> Self {
        self.cgroup.set(limit);
        self
    }

    /// Whether the cgroup limits need a cgroup parent (default `true`).
    ///
    /// The restriction's counterpart of
    /// [`CageBuilder::cgroup_required`](crate::CageBuilder::cgroup_required),
    /// with the same semantics. It does not waive the confinement
    /// [`cgroup_parent`](Self::cgroup_parent) states.
    pub fn cgroup_required(mut self, required: bool) -> Self {
        self.cgroup.required = Some(required);
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

    /// Sets an environment variable for the command.
    ///
    /// The command's environment is built from scratch: the deterministic
    /// base (`PATH` alone) plus the variables set here, which override the
    /// base on collision. Nothing is inherited from the host.
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

    /// Controls whether the deterministic base environment is composed under
    /// the caller's variables (default `true`).
    ///
    /// Set to `false`, the command's environment is exactly the pairs given
    /// to [`env`](Self::env) and [`envs`](Self::envs) — `PATH` is not
    /// supplied, and no variable the library may add to its base in a later
    /// release is supplied either.
    ///
    /// The counterpart of [`CageBuilder::base_env`](crate::CageBuilder::base_env),
    /// over the restriction's own `PATH`-only base.
    pub fn base_env(mut self, base: bool) -> Self {
        self.base_env = base;
        self
    }

    /// Sets the command's working directory, a host path.
    ///
    /// The path must be absolute, with no `..` component, and must exist at
    /// launch; a missing directory is a setup error, not a fallback. The
    /// default is `/`.
    pub fn current_dir(mut self, path: impl AsRef<Path>) -> Self {
        self.workdir = Some(path.as_ref().to_path_buf());
        self
    }

    /// Selects the disposition of the command's standard input.
    ///
    /// The default is [`Stdio::Inherit`], which also keeps the command in the
    /// caller's session; see [`Stdio`] for the whole rule. It applies here
    /// unchanged: a restriction has no namespace to close the caller's terminal
    /// with, so the standard streams are the only thing that can.
    pub fn stdin(mut self, stdin: Stdio) -> Self {
        self.stdin = stdin;
        self
    }

    /// Selects the disposition of the command's standard output.
    ///
    /// The counterpart of [`CageBuilder::stdout`](crate::CageBuilder::stdout),
    /// with the same default and the same interaction with a capturing launch.
    /// It matters at least as much here: a restriction's command inherits the
    /// caller's file descriptors exactly as a cage's does, and closing the
    /// caller's terminal to it takes the output pair as well as standard input.
    pub fn stdout(mut self, stdout: Stdio) -> Self {
        self.stdout = stdout;
        self
    }

    /// Selects the disposition of the command's standard error.
    ///
    /// The counterpart of [`stdout`](Self::stdout).
    pub fn stderr(mut self, stderr: Stdio) -> Self {
        self.stderr = stderr;
        self
    }

    /// Ties the command's lifetime to the caller's (default `false`).
    ///
    /// As on the cage builder: when enabled, the command is stopped as soon
    /// as the calling process exits — however it exits — or the last handle
    /// to the launch is dropped, with the exceptions
    /// [`CageBuilder::stop_with_caller`](crate::CageBuilder::stop_with_caller)
    /// states for a launch without a PID namespace. The supervisor stops only
    /// the command process itself; its descendants are beyond that reach.
    /// With a [`cgroup_parent`](Self::cgroup_parent), dropping the last handle
    /// also ends every process of the cgroup's tree, as
    /// [`Running::kill`](crate::Running::kill) does, and removes the cgroup
    /// once they have exited.
    pub fn stop_with_caller(mut self, tie: bool) -> Self {
        self.stop_with_caller = tie;
        self
    }

    /// Grants `access` beneath the host path `path` under a Landlock
    /// ruleset.
    ///
    /// Configuring any grant enrolls the command in Landlock: it may then
    /// read, write, and execute files, and list, create, remove, and rename
    /// entries, only where a grant allows it. A runnable command therefore
    /// needs grants covering its own binary and libraries — commonly
    /// `FsAccess::READ | FsAccess::EXECUTE` on `/usr`, `/bin`, and `/lib` —
    /// alongside the data paths it works on. A grant may name a single file or
    /// device node as well as a directory; there it allows only the rights that
    /// act on a file, since there are no entries to list, create, or remove.
    ///
    /// The path is resolved as the host resolves it, through symbolic links, so
    /// a grant on a merged-`/usr` host's `/lib` covers `/usr/lib`. A grant
    /// therefore covers whatever a link on its path points at when the command
    /// starts, including a link an earlier run left in a directory it could
    /// write.
    ///
    /// Landlock does not govern a file's metadata, as
    /// [`CageBuilder::landlock_fs`](crate::CageBuilder::landlock_fs) states:
    /// `chmod`, `chown`, extended attributes, timestamps, `stat`, and `chdir`
    /// reach any host path the command can name.
    ///
    /// The ruleset is enforced on a kernel that offers Landlock, best-effort
    /// down to the kernel's supported ABI. A filesystem grant keeps its ABI-1
    /// base rights on every Landlock kernel, so it always enforces there; a
    /// kernel without the Landlock LSM cannot enforce the grant, so the
    /// restriction is refused at build rather than run unconfined.
    ///
    /// An empty `access` is refused at build with
    /// [`ConfigError::LandlockGrantEmpty`](crate::ConfigError::LandlockGrantEmpty):
    /// it reads as "grant nothing here" and would behave as "deny the whole
    /// filesystem", the command's own binary included.
    pub fn landlock_fs(mut self, access: FsAccess, path: impl AsRef<Path>) -> Self {
        self.hardening.grant_fs(access, path.as_ref());
        self
    }

    /// Grants network `access` on the TCP `port` under a Landlock ruleset.
    ///
    /// Configuring any grant — filesystem or network — enrolls the command in
    /// Landlock. A network grant governs TCP bind and connect only: the command
    /// may bind only ports granted [`NetAccess::BIND`] and connect only to
    /// ports granted [`NetAccess::CONNECT`], and every other TCP bind and
    /// connect is denied. Because a restriction runs on the host, these grants
    /// govern the command's access to the host network.
    ///
    /// Landlock's network rights confine TCP alone. UDP, raw sockets, and
    /// other socket families are not restricted by a network grant, and a
    /// restriction that must deny them needs a seccomp filter on the socket
    /// syscalls. An abstract `AF_UNIX` socket, such as the session bus's or the
    /// X server's, is the exception: the default
    /// [`landlock_scope`](Self::landlock_scope) confines connections to one.
    ///
    /// Network rights require Landlock ABI 4. A sandbox on an older kernel
    /// narrows them away best-effort, but a restriction has no network
    /// namespace behind the grant, so a restriction with any network grant is
    /// refused at build on such a kernel, whatever filesystem grants it also
    /// makes. The refusal is
    /// [`ConfigError::RestrictionLandlockUnenforceable`](crate::ConfigError::RestrictionLandlockUnenforceable).
    /// An empty `access` is refused at build for the same reason an empty
    /// filesystem grant is: it would deny all TCP rather than nothing.
    ///
    /// [`NetAccess::BIND`]: crate::NetAccess::BIND
    /// [`NetAccess::CONNECT`]: crate::NetAccess::CONNECT
    pub fn landlock_net(mut self, access: NetAccess, port: u16) -> Self {
        self.hardening.grant_net(access, port);
        self
    }

    /// Replaces the Landlock scopes the command is confined by (default:
    /// every scope).
    ///
    /// A scope denies an interaction with a process outside the restriction's
    /// Landlock domain: [`LandlockScope::Signal`] sending it a signal, and
    /// [`LandlockScope::AbstractUnixSocket`] connecting to an abstract socket it
    /// created. A restriction shares the host's PID space and network
    /// namespace, so without them the command can signal every process of the
    /// calling user and reach the session bus and the X server. Both are on by
    /// default; name fewer only for a command that needs that reach.
    ///
    /// Scopes need Landlock ABI 6 (Linux 6.12), and a restriction has no
    /// namespace behind either reach. A scope named here is therefore refused at
    /// build on a kernel without it, Landlock LSM or not, as
    /// [`ConfigError::LandlockScopeUnenforceable`](crate::ConfigError::LandlockScopeUnenforceable).
    /// The default scopes, left unnamed, are dropped on such a kernel instead,
    /// which leaves those reaches open so that a seccomp-only restriction still
    /// runs there.
    /// [`host::landlock_enforces_scope`](crate::host::landlock_enforces_scope)
    /// reports whether the running kernel enforces a scope. Naming no scope at
    /// all, an empty list, turns them off on every kernel.
    ///
    /// Unlike a grant, a scope alone does not count as confinement: a
    /// restriction with no grant and no seccomp policy is still refused as
    /// [`ConfigError::RestrictionEmpty`](crate::ConfigError::RestrictionEmpty).
    ///
    /// [`LandlockScope::Signal`]: crate::LandlockScope::Signal
    /// [`LandlockScope::AbstractUnixSocket`]: crate::LandlockScope::AbstractUnixSocket
    pub fn landlock_scope<I: IntoIterator<Item = LandlockScope>>(mut self, scopes: I) -> Self {
        self.hardening.set_scope(scopes);
        self.scopes_named = true;
        self
    }

    /// Refuses the command a connection to a pathname unix socket created
    /// outside its Landlock domain, except beneath a path granted
    /// [`FsAccess::RESOLVE_UNIX`] (default: off).
    ///
    /// A restriction runs on the host, so every socket the calling user can
    /// name is otherwise reachable: the session bus's, an agent's, a container
    /// runtime's. See
    /// [`CageBuilder::landlock_resolve_unix`](crate::CageBuilder::landlock_resolve_unix)
    /// for what the right governs. It needs Landlock ABI 9, and a restriction
    /// has nothing else behind it, so it is refused at build on an older
    /// kernel, or one without the Landlock LSM, as
    /// [`ConfigError::LandlockResolveUnixUnenforceable`](crate::ConfigError::LandlockResolveUnixUnenforceable).
    /// Like a scope, it does not count as confinement on its own.
    pub fn landlock_resolve_unix(mut self, restrict: bool) -> Self {
        self.hardening.set_resolve_unix(restrict);
        self
    }

    /// Applies a seccomp syscall filter to the command.
    ///
    /// See [`SeccompPolicy`] for rule sets, the
    /// [curated roster](crate::SeccompRules::curated) among them, and the
    /// pre-compiled escape hatch. The filter binds the command and its
    /// descendants.
    pub fn seccomp(mut self, policy: SeccompPolicy) -> Self {
        self.hardening.set_seccomp(policy);
        self
    }

    /// The configured command path.
    pub fn get_command(&self) -> Option<&Path> {
        self.command.as_deref()
    }

    /// The command's arguments, excluding the conventional `argv[0]`.
    pub fn get_args(&self) -> &[OsString] {
        &self.args
    }

    /// The caller-set environment variables, in the order they were set.
    ///
    /// These are the caller's additions; the command's full environment is
    /// these composed over the restriction's `PATH`-only base, unless
    /// [`base_env`](Self::base_env) is off.
    pub fn get_envs(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.env
            .iter()
            .map(|(name, value)| (name.as_os_str(), value.as_os_str()))
    }

    /// Whether the deterministic base environment is composed under the
    /// caller's variables.
    pub fn get_base_env(&self) -> bool {
        self.base_env
    }

    /// The command's working directory, a host path, when one is set.
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

    /// Whether the command's lifetime is tied to the caller's.
    pub fn get_stop_with_caller(&self) -> bool {
        self.stop_with_caller
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

    /// Validates the configuration and freezes it into a [`Restriction`].
    ///
    /// All fallible and allocating preparation happens here: the command
    /// line and environment are marshaled, the Landlock grants are validated
    /// and frozen, and the seccomp policy is compiled to its BPF program. A
    /// restriction with no grant and no policy is rejected as
    /// [`ConfigError::RestrictionEmpty`].
    pub fn build(self) -> Result<Restriction, Error> {
        // The rule a sandbox reads its command by, without path lookup: a
        // restriction never searches the host's `PATH`.
        let command = spec::validate_command(self.command, None)?;
        let exec_label = spec::exec_label(&command.path, &[]);
        let (rlimits, rlimit_labels) = spec::lower_rlimits(&self.rlimits)?;
        let cgroup = self.cgroup.plan()?;
        let cgroup_unapplied = self.cgroup.unapplied();
        let args = self
            .args
            .iter()
            .map(|arg| spec::cstring(arg))
            .collect::<Result<Vec<_>, _>>()?;
        let base: &[(&str, &str)] = if self.base_env { &BASE_ENV } else { &[] };
        let env = spec::compose_env(base, &self.env)?;
        let workdir = self
            .workdir
            .map(|path| spec::validate_workdir(&path))
            .transpose()?
            .flatten();

        if self.hardening.is_unrestricted() {
            return Err(ConfigError::RestrictionEmpty.into());
        }
        let mut hardening = self.hardening.lower(false)?;
        let abi = crate::mechanism::probe_landlock_abi();
        settle_landlock(&mut hardening, self.scopes_named, abi)?;
        if self.cgroup.parent.is_some() || !self.cgroup.limits().is_empty() {
            let mounts = std::fs::read_to_string("/proc/self/mountinfo")
                .ok()
                .map(|table| {
                    crate::host::cgroup2_mounts(&table)
                        .map(|mount| mount.mount_point)
                        .collect::<Vec<_>>()
                });
            ensure_cgroup_held(
                &hardening,
                self.hardening.seccomp(),
                mounts.as_deref(),
                |grant| std::fs::canonicalize(grant).unwrap_or_else(|_| grant.to_path_buf()),
            )?;
        }
        // The grants are host paths, resolved as the host resolves them: a
        // merged-`/usr` host's `/lib` is a link, and refusing links would refuse
        // the very grants that make a host command runnable.
        hardening.grants_follow_links = true;
        // Always drop to the empty capability set. A restriction runs on the
        // host with no user namespace, so a privileged caller (root, or one
        // holding file capabilities) would otherwise carry its full permitted
        // and effective sets into the command — CAP_SYS_PTRACE, CAP_SYS_ADMIN,
        // and the rest, none of which Landlock governs. The drop is applied
        // after the (no-op) identity switch, under the no-new-privileges flag
        // set for every non-empty plan, so nothing can be regained across the
        // exec. Reducing the capability sets is safe and a no-op when the
        // caller is already unprivileged, which is the common case a
        // restriction exists to serve.
        hardening.keep_caps = Some(0);

        Ok(Restriction {
            plan: LaunchPlan {
                confinement: Confinement::Restriction,
                // A restriction creates no user namespace: there is no map
                // to establish, no identity to switch to or to present, and
                // nothing to nest inside — the mount flags a cage locks by
                // nesting are the host's here, and no mount of its own is
                // established.
                identity: IdentityPlan::Single,
                nested: None,
                run_as: None,
                present_as: None,
                program: command.program,
                // A restriction keeps the absolute-command contract: no PATH
                // search over the shared host filesystem.
                program_search: Vec::new(),
                args,
                env,
                // No root is swapped and no namespace is created: the
                // container fields stay empty and the launch runs the
                // outside-supervised process shape.
                root: RootPlan::Host,
                unshare: UnshareFlags::empty(),
                pid_namespace: false,
                stdin: StdioPlan::of(&self.stdin),
                stdout: StdioPlan::of(&self.stdout),
                stderr: StdioPlan::of(&self.stderr),
                // The same rule a cage follows: the command joins the caller's
                // session only to inherit its standard input. A restriction has
                // no namespace to close the terminal, so the session and the
                // output dispositions are the only things that can.
                own_session: !matches!(self.stdin, Stdio::Inherit),
                stop_with_caller: self.stop_with_caller,
                hostname: None,
                configure_loopback: false,
                // No network namespace is created, so the command runs in the
                // caller's.
                network: crate::Network::Host,
                workdir,
                ops: Vec::new(),
                op_labels: Vec::new(),
                // A restriction establishes no mount, so it creates no target.
                managed_placeholders: ManagedPlaceholders::default(),
                exec_label,
                rlimits,
                rlimit_labels,
                cgroup,
                cgroup_unapplied,
                hardening,
            },
        })
    }
}

/// Holds a restriction's Landlock request to what a kernel at `abi` enforces,
/// where `abi` is `None` when the kernel offers no Landlock LSM.
///
/// The unix-socket restriction comes first. A restriction applies it only where
/// its caller asked for it, so a kernel that cannot enforce it refuses the
/// build, and it does so under its own error: a grant of
/// [`FsAccess::RESOLVE_UNIX`](crate::FsAccess::RESOLVE_UNIX) alone is masked
/// away below ABI 9, which the grant check below would otherwise report as a
/// grant of another kind.
///
/// A restriction is confined only by what the host enforces, so a grant that
/// falls outside the kernel's ABI, which would leave the command unconfined
/// for that access kind, is refused rather than dropped. So is a scope the
/// caller named (`scopes_named`): a restriction has no namespace behind either
/// reach a scope confines. The default scopes are the exception, since every
/// restriction requests them unasked. A kernel that cannot enforce them drops
/// them here, or a kernel with no Landlock LSM would fail a seccomp-only
/// restriction at setup for want of a ruleset nobody asked for.
fn settle_landlock(
    hardening: &mut HardeningPlan,
    scopes_named: bool,
    abi: Option<i32>,
) -> Result<(), ConfigError> {
    crate::hardening::settle_resolve_unix(hardening, true, || abi)?;
    hardening.ensure_landlock_enforceable(abi)?;
    if scopes_named {
        crate::hardening::ensure_scopes_enforceable(hardening.landlock_scoped, abi)
    } else {
        hardening.landlock_scoped &= abi.map_or(0, crate::hardening::scope_for_abi);
        Ok(())
    }
}

/// Refuses a restriction with a cgroup whose command could lift the cgroup's
/// limits or leave the cgroup, naming the [`CgroupReach`] it would have.
///
/// The command could write the cgroup's files unless its Landlock domain
/// governs file writes and grants none at, above, or beneath a mount of the
/// cgroup v2 hierarchy, and could start a process in another cgroup unless its
/// seccomp policy answers `clone3` with an errno. A grant is judged both as
/// named and as resolved through links, as the launch resolves it.
///
/// `mounts` is where this process's mount table mounts the hierarchy, or
/// `None` where the table cannot be read, and `resolve` reads a grant's path
/// through its links.
fn ensure_cgroup_held(
    hardening: &HardeningPlan,
    seccomp: Option<&SeccompPolicy>,
    mounts: Option<&[std::path::PathBuf]>,
    resolve: impl Fn(&Path) -> std::path::PathBuf,
) -> Result<(), ConfigError> {
    use std::os::unix::ffi::OsStrExt;

    use crate::hardening::fs_access::WRITE_FILE;

    let refused = |reach| Err(ConfigError::RestrictionCgroupReachable { reach });
    if hardening.landlock_handled & WRITE_FILE == 0 {
        return refused(CgroupReach::WritesUngoverned);
    }
    let Some(mounts) = mounts else {
        return refused(CgroupReach::MountTableUnread);
    };
    for rule in &hardening.landlock {
        if rule.access & WRITE_FILE == 0 {
            continue;
        }
        let grant = Path::new(OsStr::from_bytes(rule.path.to_bytes()));
        let resolved = resolve(grant);
        let reaches = |mount: &Path| {
            [grant, resolved.as_path()]
                .iter()
                .any(|path| path.starts_with(mount) || mount.starts_with(path))
        };
        if let Some(mount) = mounts.iter().find(|mount| reaches(mount)) {
            return refused(CgroupReach::WriteGranted {
                grant: grant.to_path_buf(),
                mount: mount.clone(),
            });
        }
    }
    let clone3 = i64::from(syscalls::Sysno::clone3.id());
    if !seccomp.is_some_and(|policy| policy.answers_with_errno(clone3)) {
        return refused(CgroupReach::Clone3Allowed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SeccompRules;

    /// Every field of a restriction's builder is classified against the cage
    /// builder's, and stays classified because this stops compiling otherwise.
    ///
    /// The two types are deliberate twins: a restriction is the degraded mode a
    /// cage's caller falls back to, and the point is that the same
    /// configuration reads the same way. What holds them together is prose --
    /// each setter says what its knob means *under a restriction* -- so the
    /// pair cannot be generated from one source without losing the thing that
    /// makes two worth having. What can be held mechanically is that neither
    /// grows a field the other has not considered.
    ///
    /// The destructure below is exhaustive, with no `..`, the technique
    /// `CageBuilder::check_restricted` uses: a field added to
    /// `RestrictionBuilder` fails to compile here until someone classifies it.
    /// The other direction is that same `check_restricted`, which destructures
    /// `CageBuilder` exhaustively for its own reason -- so a field added there
    /// is already refused until it is classified, and this comment is where a
    /// reader is told the pair is what the two destructures are about.
    #[test]
    fn every_restriction_builder_field_is_classified_against_the_cage_builder() {
        let RestrictionBuilder {
            // The same field, meaning the same thing, on `CageBuilder`. A
            // change to one of these is a change to both.
            command: _,
            args: _,
            env: _,
            workdir: _,
            stdin: _,
            stdout: _,
            stderr: _,
            rlimits: _,
            cgroup: _,
            hardening: _,
            // Deliberately different in type. `CageBuilder` holds an
            // `Option<bool>` for each, because a profile that says nothing has
            // to be distinguishable from one that says `false` when the two are
            // merged. A restriction has no profile, so the two-state form is
            // the whole question here.
            base_env: _,
            stop_with_caller: _,
            // A restriction's alone. It starts with every scope, which a
            // sandbox does not, so it tells that default apart from scopes its
            // caller named: a kernel too old for scopes drops the one and
            // refuses the other.
            scopes_named: _,
        } = RestrictionBuilder::default();
    }

    /// Every setting the two builders share reads back through a getter of the
    /// cage builder's name and shape, so a caller judging a launch asks the
    /// builder rather than tracking what it set.
    #[test]
    fn a_restriction_reads_back_the_settings_it_shares_with_a_cage() {
        let unset = RestrictionBuilder::default();
        assert_eq!(unset.get_command(), None);
        assert!(unset.get_args().is_empty());
        assert_eq!(unset.get_envs().count(), 0);
        assert!(unset.get_base_env());
        assert_eq!(unset.get_current_dir(), None);
        for stream in [unset.get_stdin(), unset.get_stdout(), unset.get_stderr()] {
            assert!(matches!(stream, Stdio::Inherit), "{stream:?}");
        }
        assert!(!unset.get_stop_with_caller());
        assert_eq!(unset.get_rlimits().count(), 0);

        let set = Restriction::builder()
            .command("/bin/sh")
            .args(["-c", "true"])
            .env("K", "V")
            .base_env(false)
            .current_dir("/srv")
            .stdin(Stdio::Null)
            .stdout(Stdio::Fd(std::sync::Arc::new(
                std::fs::File::open("/dev/null").unwrap().into(),
            )))
            .stop_with_caller(true)
            .rlimit(Resource::OpenFiles, 64, 128);
        assert_eq!(set.get_command(), Some(Path::new("/bin/sh")));
        assert_eq!(
            set.get_args(),
            [OsString::from("-c"), OsString::from("true")]
        );
        assert_eq!(
            set.get_envs().collect::<Vec<_>>(),
            [(OsStr::new("K"), OsStr::new("V"))],
        );
        assert!(!set.get_base_env());
        assert_eq!(set.get_current_dir(), Some(Path::new("/srv")));
        // Three different dispositions, so each getter is seen to read its own.
        assert!(matches!(set.get_stdin(), Stdio::Null));
        assert!(matches!(set.get_stdout(), Stdio::Fd(_)));
        assert!(matches!(set.get_stderr(), Stdio::Inherit));
        assert!(set.get_stop_with_caller());
        assert_eq!(
            set.get_rlimits().collect::<Vec<_>>(),
            [(Resource::OpenFiles, Limit::of(64), Limit::of(128))],
        );
    }

    fn restricted_true() -> RestrictionBuilder {
        Restriction::builder()
            .command("/bin/true")
            .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
    }

    #[test]
    fn build_requires_a_command() {
        let err = Restriction::builder()
            .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(ConfigError::CommandMissing)));
    }

    #[test]
    fn build_rejects_a_relative_command() {
        let err = Restriction::builder()
            .command("bin/true")
            .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::CommandNotAbsolute { .. })
        ));
    }

    #[test]
    fn a_bare_command_is_refused_without_an_offer_of_path_lookup() {
        // A restriction has no path lookup, so the refusal of a bare name
        // cannot point at one: it says the name is never searched.
        let err = Restriction::builder()
            .command("true")
            .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
            .build()
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::Config(ConfigError::CommandNotAbsolute {
                    lookup_offered: false,
                    ..
                })
            ),
            "{err:?}"
        );
        let Error::Config(config) = &err else {
            unreachable!()
        };
        let message = config.to_string();
        assert!(message.contains("never searches PATH"), "{message}");
        assert!(!message.contains("path lookup"), "{message}");
    }

    #[test]
    fn a_dot_or_dot_dot_command_is_refused_as_a_cage_refuses_it() {
        // The command is read by the rule a sandbox reads its own by.
        for command in [".", ".."] {
            let err = Restriction::builder()
                .command(command)
                .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
                .build()
                .unwrap_err();
            assert!(
                matches!(err, Error::Config(ConfigError::CommandNotAbsolute { .. })),
                "{command}: {err}"
            );
        }
    }

    #[test]
    fn an_empty_restriction_is_rejected() {
        let err = Restriction::builder()
            .command("/bin/true")
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(ConfigError::RestrictionEmpty)));
    }

    #[test]
    fn a_net_grant_alone_is_a_valid_restriction() {
        // A network grant is something to enforce, so it satisfies the
        // non-empty requirement on its own. Whether it then builds depends on
        // the host: a network grant needs Landlock ABI 4, and a net-only
        // restriction is refused below it rather than run unconfined.
        let builder = || {
            Restriction::builder()
                .command("/bin/true")
                .landlock_net(NetAccess::CONNECT, 443)
        };
        let abi = crate::mechanism::probe_landlock_abi();
        match crate::hardening::net_enforced(NetAccess::CONNECT, abi) {
            true => {
                let restriction = builder().build().expect("a network grant is a restriction");
                let hardening = &restriction.plan.hardening;
                assert_eq!(hardening.landlock_net.len(), 1);
                assert_ne!(hardening.landlock_net_handled, 0);
                assert!(hardening.landlock.is_empty());
            }
            false => {
                // Below ABI 4, or with no Landlock LSM, the grant cannot apply,
                // so the build is refused rather than silently dropping it.
                assert!(matches!(
                    builder().build(),
                    Err(Error::Config(
                        ConfigError::RestrictionLandlockUnenforceable { .. }
                    ))
                ));
            }
        }
    }

    /// Settles `builder`'s Landlock request against a kernel that reported
    /// `abi`, returning the scopes it kept.
    fn settle(builder: RestrictionBuilder, abi: Option<i32>) -> Result<u64, ConfigError> {
        let mut hardening = builder.hardening.lower(false).expect("a valid request");
        settle_landlock(&mut hardening, builder.scopes_named, abi)?;
        Ok(hardening.landlock_scoped)
    }

    #[test]
    fn a_kernel_without_scopes_drops_the_default_and_refuses_named_ones() {
        use crate::hardening::scope;
        let every = scope::SIGNAL | scope::ABSTRACT_UNIX_SOCKET;
        for abi in [None, Some(5)] {
            // The default is every restriction's, asked for or not, so a kernel
            // that cannot enforce it drops it and the build goes ahead.
            assert_eq!(settle(restricted_true(), abi).unwrap(), 0);
            // A scope the caller named is refused, since nothing but Landlock
            // would bound its reach. The full default, named, is refused too.
            for (named, name) in [
                (vec![LandlockScope::Signal], "signal"),
                (
                    vec![LandlockScope::AbstractUnixSocket],
                    "abstract-unix-socket",
                ),
                (LandlockScope::ALL.to_vec(), "signal"),
            ] {
                match settle(restricted_true().landlock_scope(named), abi) {
                    Err(ConfigError::LandlockScopeUnenforceable {
                        scope,
                        abi: reported,
                    }) => {
                        assert_eq!((scope, reported), (name, abi));
                    }
                    other => panic!("a named scope at {abi:?} was not refused: {other:?}"),
                }
            }
            // Naming none asks for nothing to refuse.
            let off = restricted_true().landlock_scope([]);
            assert_eq!(settle(off, abi).unwrap(), 0);
        }
        // A kernel with scopes keeps the default and a named scope alike.
        assert_eq!(settle(restricted_true(), Some(6)).unwrap(), every);
        let named = restricted_true().landlock_scope([LandlockScope::Signal]);
        assert_eq!(settle(named, Some(6)).unwrap(), scope::SIGNAL);
    }

    #[test]
    fn a_grant_the_kernel_cannot_enforce_is_refused_whatever_the_scopes() {
        let granted = || restricted_true().landlock_fs(FsAccess::READ, "/usr");
        assert!(matches!(
            settle(granted(), None),
            Err(ConfigError::RestrictionLandlockUnenforceable { abi: None })
        ));
        let net = || restricted_true().landlock_net(NetAccess::CONNECT, 443);
        assert!(matches!(
            settle(net(), Some(3)),
            Err(ConfigError::RestrictionLandlockUnenforceable { abi: Some(3) })
        ));
        assert!(settle(net(), Some(4)).is_ok());
        assert!(settle(granted(), Some(1)).is_ok());
    }

    #[test]
    fn a_unix_socket_grant_alone_is_refused_as_the_unix_socket_restriction() {
        let granted = || {
            restricted_true()
                .landlock_resolve_unix(true)
                .landlock_fs(FsAccess::RESOLVE_UNIX, "/run")
        };
        for abi in [None, Some(4), Some(6), Some(8)] {
            assert!(
                matches!(
                    settle(granted(), abi),
                    Err(ConfigError::LandlockResolveUnixUnenforceable { abi: reported })
                        if reported == abi
                ),
                "{abi:?}",
            );
        }
        assert!(settle(granted(), Some(9)).is_ok());
    }

    #[test]
    fn a_named_scope_builds_only_where_the_kernel_enforces_it() {
        let built = restricted_true()
            .landlock_scope([LandlockScope::Signal])
            .build();
        let abi = crate::mechanism::probe_landlock_abi();
        match crate::hardening::scope_enforced(LandlockScope::Signal, abi) {
            true => {
                let restriction = built.expect("a kernel with scopes enforces a named one");
                assert_eq!(
                    restriction.plan.hardening.landlock_scoped,
                    crate::hardening::scope::SIGNAL,
                );
            }
            false => assert!(matches!(
                built,
                Err(Error::Config(ConfigError::LandlockScopeUnenforceable { abi: reported, .. }))
                    if reported == abi
            )),
        }
    }

    #[test]
    fn a_restriction_lets_its_grants_follow_the_hosts_links() {
        let restriction = restricted_true().build().unwrap();
        assert!(restriction.plan.hardening.grants_follow_links);
    }

    #[test]
    fn a_relative_landlock_path_is_rejected() {
        let err = Restriction::builder()
            .command("/bin/true")
            .landlock_fs(FsAccess::READ, "usr")
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::LandlockPathInvalid { .. })
        ));
    }

    #[test]
    fn a_dot_dot_landlock_path_is_rejected() {
        let err = Restriction::builder()
            .command("/bin/true")
            .landlock_fs(FsAccess::READ, "/usr/../etc")
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::LandlockPathInvalid { .. })
        ));
    }

    #[test]
    fn the_root_is_a_valid_landlock_path() {
        restricted_true()
            .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/")
            .build()
            .expect("a grant on the root covers the whole filesystem");
    }

    #[test]
    fn build_rejects_an_empty_command() {
        // The absence of a command written down, reported as that rather than
        // as a path that is not absolute -- which is how a cage reads it too.
        let err = Restriction::builder()
            .command("")
            .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
            .build()
            .unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::CommandMissing)),
            "{err}",
        );
    }

    #[test]
    fn build_rejects_a_relative_workdir() {
        let err = restricted_true().current_dir("work").build().unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::WorkdirNotAbsolute { .. })
        ));
    }

    #[test]
    fn the_environment_base_is_path_alone() {
        let restriction = restricted_true().env("A", "b").build().unwrap();
        let env: Vec<&str> = restriction
            .plan
            .env
            .iter()
            .map(|entry| entry.to_str().unwrap())
            .collect();
        assert_eq!(env, ["A=b", &format!("PATH={}", spec::BASE_PATH)]);
    }

    #[test]
    fn an_exact_environment_drops_the_restriction_base_too() {
        // The restriction's base is `PATH` alone, and opting out removes it as
        // completely as the cage's opt-out removes `PATH` and `HOME`.
        let restriction = restricted_true()
            .base_env(false)
            .env("A", "b")
            .build()
            .unwrap();
        let env: Vec<&str> = restriction
            .plan
            .env
            .iter()
            .map(|entry| entry.to_str().unwrap())
            .collect();
        assert_eq!(env, ["A=b"]);
    }

    #[test]
    fn the_plan_creates_no_namespaces_and_mounts_nothing() {
        let restriction = restricted_true()
            .current_dir("/tmp")
            .stdin(Stdio::Null)
            .stop_with_caller(true)
            .build()
            .unwrap();
        let plan = &restriction.plan;
        assert_eq!(plan.confinement, Confinement::Restriction);
        assert!(plan.unshare.is_empty());
        assert!(!plan.pid_namespace);
        assert!(!plan.configure_loopback);
        assert!(plan.hostname.is_none());
        assert!(plan.ops.is_empty() && plan.op_labels.is_empty());
        assert!(matches!(plan.root, RootPlan::Host));
        assert!(matches!(plan.stdin, StdioPlan::Null));
        assert!(plan.stop_with_caller);
        assert_eq!(plan.workdir.as_deref(), Some(c"/tmp"));
        // The lowered hardening carries the compiled policy and always the
        // empty capability keep set, so a privileged caller's capabilities are
        // dropped rather than inherited by the command.
        assert!(plan.hardening.seccomp.is_some());
        assert_eq!(plan.hardening.keep_caps, Some(0));
    }

    /// The reach `builder`'s Landlock grants and seccomp policy leave a
    /// command to a cgroup beneath `/sys/fs/cgroup`, with every grant's path
    /// resolving as `resolve` reads it.
    fn reach(
        builder: RestrictionBuilder,
        resolve: impl Fn(&Path) -> std::path::PathBuf,
    ) -> Option<CgroupReach> {
        let hardening = builder.hardening.lower(false).expect("a valid request");
        let mounts = [std::path::PathBuf::from("/sys/fs/cgroup")];
        match ensure_cgroup_held(
            &hardening,
            builder.hardening.seccomp(),
            Some(&mounts),
            resolve,
        ) {
            Ok(()) => None,
            Err(ConfigError::RestrictionCgroupReachable { reach }) => Some(reach),
            Err(err) => panic!("{err:?}"),
        }
    }

    /// A grant's path as it stands, with no link on it.
    fn as_named(path: &Path) -> std::path::PathBuf {
        path.to_path_buf()
    }

    /// A restriction granted read and execute on the system and write on a
    /// working tree, under `policy`.
    fn confined(policy: SeccompPolicy) -> RestrictionBuilder {
        Restriction::builder()
            .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/")
            .landlock_fs(FsAccess::READ | FsAccess::WRITE, "/home/user/work")
            .seccomp(policy)
    }

    #[test]
    fn a_restriction_held_from_its_cgroup_s_files_and_clone3_keeps_its_cgroup() {
        let curated = || SeccompPolicy::Rules(SeccompRules::curated());
        assert_eq!(reach(confined(curated()), as_named), None);
        // The roster's errno for clone3 can be the caller's own.
        let enosys = SeccompRules::curated().errno_for(clone3_number(), 38);
        assert_eq!(
            reach(confined(SeccompPolicy::Rules(enosys)), as_named),
            None
        );
        // An allowlist answers what it does not list with its default errno.
        let allowlist = SeccompRules::allowing([clone3_number() - 1]);
        assert_eq!(
            reach(confined(SeccompPolicy::Rules(allowlist)), as_named),
            None
        );
        let denied = SeccompRules::denying([clone3_number()]);
        assert_eq!(
            reach(confined(SeccompPolicy::Rules(denied)), as_named),
            None
        );
    }

    #[test]
    fn a_restriction_whose_landlock_domain_governs_no_write_is_refused_a_cgroup() {
        let curated = SeccompPolicy::Rules(SeccompRules::curated());
        let no_grant = Restriction::builder().seccomp(curated.clone());
        assert_eq!(
            reach(no_grant, as_named),
            Some(CgroupReach::WritesUngoverned)
        );
        // A network grant governs no file.
        let network = Restriction::builder()
            .landlock_net(NetAccess::CONNECT, 443)
            .seccomp(curated);
        assert_eq!(
            reach(network, as_named),
            Some(CgroupReach::WritesUngoverned)
        );
    }

    #[test]
    fn a_write_grant_at_above_or_beneath_the_cgroup_mount_is_refused_a_cgroup() {
        let curated = || SeccompPolicy::Rules(SeccompRules::curated());
        for path in [
            "/",
            "/sys",
            "/sys/fs/cgroup",
            "/sys/fs/cgroup/user.slice/x.scope",
        ] {
            let builder = confined(curated()).landlock_fs(FsAccess::WRITE, path);
            assert_eq!(
                reach(builder, as_named),
                Some(CgroupReach::WriteGranted {
                    grant: path.into(),
                    mount: "/sys/fs/cgroup".into(),
                }),
                "{path}",
            );
        }
        // A sibling of the mount, and a name that only begins like it.
        for path in ["/sys/fs/bpf", "/sys/fs/cgroupx"] {
            let builder = confined(curated()).landlock_fs(FsAccess::WRITE, path);
            assert_eq!(reach(builder, as_named), None, "{path}");
        }
        // A grant reaching the mount through a link.
        let linked = confined(curated()).landlock_fs(FsAccess::WRITE, "/home/user/cgroup");
        let through_link = |path: &Path| match path == Path::new("/home/user/cgroup") {
            true => "/sys/fs/cgroup/user.slice".into(),
            false => path.to_path_buf(),
        };
        assert_eq!(
            reach(linked, through_link),
            Some(CgroupReach::WriteGranted {
                grant: "/home/user/cgroup".into(),
                mount: "/sys/fs/cgroup".into(),
            })
        );
    }

    #[test]
    fn a_restriction_whose_seccomp_policy_lets_clone3_run_is_refused_a_cgroup() {
        let clone3 = clone3_number();
        let flags_on_the_stack =
            SeccompRules::denying([]).rule(clone3, [crate::SeccompArg::eq_qword(1, 88)]);
        let killed =
            SeccompRules::denying([clone3]).listed_action(crate::SeccompAction::KillThread);
        for policy in [
            None,
            Some(SeccompPolicy::Rules(SeccompRules::denying([
                clone3_number() - 1,
            ]))),
            Some(SeccompPolicy::Rules(SeccompRules::allowing([clone3]))),
            Some(SeccompPolicy::Rules(flags_on_the_stack)),
            Some(SeccompPolicy::Rules(killed)),
            // A program the build cannot read.
            Some(SeccompPolicy::Program(Vec::new())),
        ] {
            let mut builder =
                Restriction::builder().landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/");
            if let Some(policy) = policy.clone() {
                builder = builder.seccomp(policy);
            }
            assert_eq!(
                reach(builder, as_named),
                Some(CgroupReach::Clone3Allowed),
                "{policy:?}"
            );
        }
    }

    #[test]
    fn a_restriction_s_cgroup_is_refused_whether_or_not_its_limits_are_required() {
        let seccomp_only = || {
            Restriction::builder()
                .command("/bin/true")
                .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
        };
        seccomp_only()
            .build()
            .expect("a seccomp policy is a restriction");
        for builder in [
            seccomp_only().cgroup_parent("/sys/fs/cgroup/delegated"),
            seccomp_only()
                .cgroup_limit(CgroupLimit::PidsMax(8))
                .cgroup_required(false),
        ] {
            assert!(matches!(
                builder.build(),
                Err(Error::Config(ConfigError::RestrictionCgroupReachable {
                    reach: CgroupReach::WritesUngoverned,
                }))
            ));
        }
    }

    /// `clone3`'s number on the host architecture.
    fn clone3_number() -> i64 {
        SeccompRules::syscall("clone3").expect("the host has clone3")
    }
}
