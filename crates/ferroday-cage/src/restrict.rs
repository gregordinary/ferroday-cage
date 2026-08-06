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
//! isolation, several host-reaching surfaces are governed only by whatever
//! Landlock and seccomp the caller configured. A restriction always drops to
//! the empty capability set, so no capability-gated reach remains; what is left
//! is same-credential access that only a configured control closes:
//!
//! - **Abstract-socket services.** A Landlock network grant governs TCP alone,
//!   so `AF_UNIX` sockets — including the abstract-namespace paths to D-Bus, the
//!   X server, and the session bus — stay reachable. Denying them needs a
//!   seccomp filter on the socket syscalls, or a cage's network namespace.
//! - **Same-user `/proc`.** Under a seccomp-only restriction with no Landlock
//!   filesystem grant, `/proc/<pid>/{environ,mem,maps}` of other host processes
//!   sharing the caller's uid remain readable. A Landlock filesystem grant that
//!   does not cover `/proc` closes this.
//! - **Same-user `ptrace`.** Under a Landlock-only restriction (no seccomp),
//!   `ptrace` of other same-uid host processes is possible where the host's
//!   Yama policy permits it. The curated seccomp denylist blocks `ptrace`
//!   outright.
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
//! A cage closes the first three through its namespaces and swapped root; a
//! restriction closes each of those only through the control that covers it.
//!
//! # The caller's terminal
//!
//! The fourth surface is not a namespace question, so a cage and a restriction
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
use std::ffi::{CString, OsStr, OsString};
use std::path::Path;

use rustix::thread::UnshareFlags;

use crate::error::{ConfigError, Error};
use crate::hardening::{FsAccess, NetAccess, Request, SeccompPolicy};
use crate::limits::{Limit, Resource};
use crate::mechanism::{Confinement, IdentityPlan, LaunchPlan, ManagedPlaceholders, StdioPlan};
use crate::observer::{Collect, Observer, Output};
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
        let mut collect = Collect::default();
        let status = self.run_with(&mut collect)?;
        Ok(collect.into_output(status))
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
    /// supports it in full: a host-allocated pseudoterminal needs no `devpts`
    /// instance, so a restriction gets the same interactive story a cage does.
    /// The command process is the session leader here, since a restriction has
    /// no PID namespace and so no init above it.
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
            hardening: Request::default(),
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
    /// The path must be absolute and must exist at launch; a missing
    /// directory is a setup error, not a fallback. The default is `/`.
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
    /// to the launch is dropped. Only the command process itself is stopped;
    /// without a PID namespace its descendants are beyond the library's
    /// reach.
    pub fn stop_with_caller(mut self, tie: bool) -> Self {
        self.stop_with_caller = tie;
        self
    }

    /// Grants `access` beneath the host path `path` under a Landlock
    /// ruleset.
    ///
    /// Configuring any grant enrolls the command in Landlock: it may then
    /// reach a path only where a grant allows it, and everything else on the
    /// host filesystem is denied. A runnable command therefore needs grants
    /// covering its own binary and libraries — commonly
    /// `FsAccess::READ | FsAccess::EXECUTE` on `/usr`, `/bin`, and `/lib` —
    /// alongside the data paths it works on.
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
    /// Landlock confines TCP alone. UDP, raw sockets, and other socket
    /// families — including `AF_UNIX`, so abstract-socket paths to host
    /// services such as the session bus or the X server — are not restricted
    /// by a network grant. A restriction that must deny those needs a seccomp
    /// filter on the relevant socket syscalls, or a cage's network namespace.
    ///
    /// Network rights require Landlock ABI 4. On an older kernel that offers
    /// Landlock they narrow away best-effort, as an unsupported filesystem
    /// right does — except that a restriction whose only Landlock grant is a
    /// network grant is refused at build, since nothing would then be
    /// enforced. An empty `access` is refused at build for the same reason an
    /// empty filesystem grant is: it would deny all TCP rather than nothing.
    ///
    /// [`NetAccess::BIND`]: crate::NetAccess::BIND
    /// [`NetAccess::CONNECT`]: crate::NetAccess::CONNECT
    pub fn landlock_net(mut self, access: NetAccess, port: u16) -> Self {
        self.hardening.grant_net(access, port);
        self
    }

    /// Applies a seccomp syscall filter to the command.
    ///
    /// See [`SeccompPolicy`] for the curated profile, caller-authored rules,
    /// and the pre-compiled escape hatch. The filter binds the command and
    /// its descendants.
    pub fn seccomp(mut self, policy: SeccompPolicy) -> Self {
        self.hardening.set_seccomp(policy);
        self
    }

    /// Validates the configuration and freezes it into a [`Restriction`].
    ///
    /// All fallible and allocating preparation happens here: the command
    /// line and environment are marshaled, the Landlock grants are validated
    /// and frozen, and the seccomp policy is compiled to its BPF program. A
    /// restriction with no grant and no policy is rejected as
    /// [`ConfigError::RestrictionEmpty`].
    pub fn build(self) -> Result<Restriction, Error> {
        let command = self.command.ok_or(ConfigError::CommandMissing)?;
        if !command.is_absolute() {
            return Err(ConfigError::CommandNotAbsolute { command }.into());
        }
        let program = spec::cstring(command.as_os_str())?;
        let exec_label = spec::exec_label(&command, &[]);
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
        let mut hardening = self.hardening.lower()?;
        // A restriction is confined only by what this host enforces, so its
        // Landlock grants must actually apply here. If they all fall outside
        // the running kernel's Landlock ABI, no ruleset is built and the
        // command would run unconfined; refuse rather than silently drop the
        // requested confinement.
        hardening.ensure_landlock_enforceable()?;
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
                // to establish, no identity to switch to, and nothing to nest
                // inside — the mount flags a cage locks by nesting are the
                // host's here, and no mount of its own is established.
                identity: IdentityPlan::Single,
                nested: None,
                run_as: None,
                program,
                // A restriction keeps the absolute-command contract: no PATH
                // search over the shared host filesystem.
                program_search: Vec::new(),
                args,
                env,
                // No root is swapped and no namespace is created: the
                // container fields stay empty and the launch runs the
                // outside-supervised process shape.
                rootfs_path: CString::default(),
                overlay: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn restricted_true() -> RestrictionBuilder {
        Restriction::builder()
            .command("/bin/true")
            .seccomp(SeccompPolicy::Curated)
    }

    #[test]
    fn build_requires_a_command() {
        let err = Restriction::builder()
            .seccomp(SeccompPolicy::Curated)
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(ConfigError::CommandMissing)));
    }

    #[test]
    fn build_rejects_a_relative_command() {
        let err = Restriction::builder()
            .command("bin/true")
            .seccomp(SeccompPolicy::Curated)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Config(ConfigError::CommandNotAbsolute { .. })
        ));
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
        assert!(plan.rootfs_path.is_empty());
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
