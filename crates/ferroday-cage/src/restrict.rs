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
//!   own keyring and read every key they hold. See [The session
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
//! the command process itself.
//!
//! [`Cage`]: crate::Cage
//! [`CageBuilder::pid_namespace`]: crate::CageBuilder::pid_namespace
//! [`Error::UsernsUnavailable`]: crate::Error::UsernsUnavailable

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;

use rustix::thread::UnshareFlags;

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
    /// caller sets.
    pub fn rlimit(
        mut self,
        resource: Resource,
        soft: impl Into<Limit>,
        hard: impl Into<Limit>,
    ) -> Self {
        self.rlimits.insert(resource, (soft.into(), hard.into()));
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
    /// states for a launch without a PID namespace. Only the command process
    /// itself is stopped; without a PID namespace its descendants are beyond
    /// the library's reach.
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
    /// runs there. [`host::landlock_abi`](crate::host::landlock_abi) reports the
    /// running ABI. Naming no scope at all, an empty list, turns them off on
    /// every kernel.
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
        // A restriction applies the unix-socket restriction only where its
        // caller asked for it, so it is refused where the kernel cannot.
        crate::hardening::settle_resolve_unix(&mut hardening, true, || abi)?;
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
                hardening,
            },
        })
    }
}

/// Holds a restriction's Landlock request to what a kernel at `abi` enforces,
/// where `abi` is `None` when the kernel offers no Landlock LSM.
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
    hardening.ensure_landlock_enforceable(abi)?;
    if scopes_named {
        crate::hardening::ensure_scopes_enforceable(hardening.landlock_scoped, abi)
    } else {
        hardening.landlock_scoped &= abi.map_or(0, crate::hardening::scope_for_abi);
        Ok(())
    }
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
        match crate::mechanism::probe_landlock_abi() {
            Some(abi) if abi >= 4 => {
                let restriction = builder().build().expect("a network grant is a restriction");
                let hardening = &restriction.plan.hardening;
                assert_eq!(hardening.landlock_net.len(), 1);
                assert_ne!(hardening.landlock_net_handled, 0);
                assert!(hardening.landlock.is_empty());
            }
            _ => {
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
    fn a_named_scope_builds_only_where_the_kernel_enforces_it() {
        let built = restricted_true()
            .landlock_scope([LandlockScope::Signal])
            .build();
        match crate::mechanism::probe_landlock_abi() {
            Some(abi) if abi >= 6 => {
                let restriction = built.expect("a kernel with scopes enforces a named one");
                assert_eq!(
                    restriction.plan.hardening.landlock_scoped,
                    crate::hardening::scope::SIGNAL,
                );
            }
            abi => assert!(matches!(
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
}
