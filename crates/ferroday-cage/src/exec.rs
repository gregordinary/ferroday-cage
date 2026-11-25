//! A further command run in a sandbox that is already running.
//!
//! [`Exec`] states the command; [`Running::exec`] runs it. The sandbox is the
//! one the handle's own command runs in, and everything that confines a
//! command there is the launch's: its identity, its resource limits and its
//! hardening. Only what names the command and its streams is the exec's own.
//!
//! [`Running::exec`]: crate::Running::exec

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::mechanism::{LaunchPlan, ManagedPlaceholders, StdioPlan};
use crate::spec::{self, Stdio};

/// A further command to run in a sandbox that is already running, confined as
/// its first command is.
///
/// Built with [`Exec::new`] and run with [`Running::exec`]:
///
/// ```no_run
/// # fn main() -> ferroday_cage::Result<()> {
/// # let cage = ferroday_cage::Cage::builder().rootfs("/r").command("/bin/x").build()?;
/// use ferroday_cage::Exec;
///
/// let sandbox = cage.spawn()?;
/// let mut make = sandbox.exec(&Exec::new("/usr/bin/make").arg("test").current_dir("/src"))?;
/// let status = make.wait()?;
/// # Ok(())
/// # }
/// ```
///
/// # What an exec states, and what it inherits
///
/// An exec names a command, its arguments, variables added to its
/// environment, its working directory, its standard streams, and whether it
/// ends with the caller. Everything that confines it is the launch's: the
/// identity the first command runs as, its resource limits, and its hardening,
/// the Landlock grants and scopes, the seccomp policy and its reports, and the
/// capabilities kept. So is the environment it starts from: the launch's, with
/// the exec's variables composed over it, a later value replacing an earlier
/// one. A working directory left unset is the launch's.
///
/// What it states is checked when it runs, against the launch it runs in: a
/// bare command name is found on the `PATH` its composed environment carries,
/// as [`CageBuilder::path_lookup`](crate::CageBuilder::path_lookup) finds the
/// first command's.
///
/// An `Exec` holds no live resources and is a plain description, so it is
/// `Clone` and runs in any number of sandboxes.
///
/// [`Running::exec`]: crate::Running::exec
#[derive(Debug, Clone)]
pub struct Exec {
    /// The command, as given.
    command: PathBuf,
    /// Whether a bare command name is found on the sandbox's `PATH`.
    path_lookup: bool,
    /// The arguments, excluding `argv[0]`.
    args: Vec<OsString>,
    /// The variables composed over the launch's environment, in order.
    env: Vec<(OsString, OsString)>,
    /// The working directory, where the exec names one of its own.
    workdir: Option<PathBuf>,
    /// The standard input's disposition.
    stdin: Stdio,
    /// The standard output's disposition.
    stdout: Stdio,
    /// The standard error's disposition.
    stderr: Stdio,
    /// Whether the command is ended once the caller lets go of its handle.
    stop_with_caller: bool,
}

impl Exec {
    /// A further command running `command`: an absolute path, executed
    /// directly, or with [`path_lookup`](Self::path_lookup) a bare name.
    ///
    /// The command is checked when the exec runs, as
    /// [`CageBuilder::command`](crate::CageBuilder::command)'s is at build.
    pub fn new(command: impl AsRef<Path>) -> Exec {
        Exec {
            command: command.as_ref().to_path_buf(),
            path_lookup: false,
            args: Vec::new(),
            env: Vec::new(),
            workdir: None,
            stdin: Stdio::default(),
            stdout: Stdio::default(),
            stderr: Stdio::default(),
            stop_with_caller: false,
        }
    }

    /// Resolves a command with no slash against the `PATH` the command's
    /// environment carries, as
    /// [`CageBuilder::path_lookup`](crate::CageBuilder::path_lookup) does for
    /// the first command.
    ///
    /// Off by default: a command must be an absolute path. The `PATH` searched
    /// is the exec's own, where it sets one through [`env`](Self::env), or else
    /// the launch's.
    pub fn path_lookup(mut self, enabled: bool) -> Self {
        self.path_lookup = enabled;
        self
    }

    /// Appends one argument.
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Appends several arguments, in order.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_os_string()));
        self
    }

    /// Sets one variable in the command's environment, over the launch's.
    ///
    /// The environment starts as the launch's, and each variable set here is
    /// composed over it in order, a later value replacing an earlier one, as
    /// [`CageBuilder::env`](crate::CageBuilder::env) composes over the base.
    pub fn env(mut self, name: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env
            .push((name.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    /// Sets several variables, in order; see [`env`](Self::env).
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.env
            .extend(vars.into_iter().map(|(name, value)| {
                (name.as_ref().to_os_string(), value.as_ref().to_os_string())
            }));
        self
    }

    /// Sets the working directory, an absolute path inside the sandbox.
    ///
    /// Unset, the command starts in the launch's working directory.
    pub fn current_dir(mut self, path: impl AsRef<Path>) -> Self {
        self.workdir = Some(path.as_ref().to_path_buf());
        self
    }

    /// Selects the disposition of the command's standard input, as
    /// [`CageBuilder::stdin`](crate::CageBuilder::stdin) does for the first
    /// command. The default is [`Stdio::Inherit`].
    pub fn stdin(mut self, stdin: Stdio) -> Self {
        self.stdin = stdin;
        self
    }

    /// Selects the disposition of the command's standard output. The default
    /// is [`Stdio::Inherit`].
    pub fn stdout(mut self, stdout: Stdio) -> Self {
        self.stdout = stdout;
        self
    }

    /// Selects the disposition of the command's standard error. The default
    /// is [`Stdio::Inherit`].
    pub fn stderr(mut self, stderr: Stdio) -> Self {
        self.stderr = stderr;
        self
    }

    /// Ends the command once the caller lets go of it: when the last of its
    /// handle and that handle's kill handles drops, or the caller exits.
    ///
    /// Off by default. It ends this command, and never the sandbox, which its
    /// own handle governs.
    pub fn stop_with_caller(mut self, tie: bool) -> Self {
        self.stop_with_caller = tie;
        self
    }

    /// The command, as given to [`new`](Self::new).
    pub fn get_command(&self) -> &Path {
        &self.command
    }

    /// Whether a bare command name is looked up; see
    /// [`path_lookup`](Self::path_lookup).
    pub fn get_path_lookup(&self) -> bool {
        self.path_lookup
    }

    /// The arguments, in order.
    pub fn get_args(&self) -> &[OsString] {
        &self.args
    }

    /// The variables set over the launch's environment, in the order they
    /// were set.
    pub fn get_envs(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.env
            .iter()
            .map(|(name, value)| (name.as_os_str(), value.as_os_str()))
    }

    /// The working directory, where the exec names one of its own.
    pub fn get_current_dir(&self) -> Option<&Path> {
        self.workdir.as_deref()
    }

    /// The standard input's disposition.
    pub fn get_stdin(&self) -> &Stdio {
        &self.stdin
    }

    /// The standard output's disposition.
    pub fn get_stdout(&self) -> &Stdio {
        &self.stdout
    }

    /// The standard error's disposition.
    pub fn get_stderr(&self) -> &Stdio {
        &self.stderr
    }

    /// Whether the command ends with the caller; see
    /// [`stop_with_caller`](Self::stop_with_caller).
    pub fn get_stop_with_caller(&self) -> bool {
        self.stop_with_caller
    }

    /// The plan of this command run in the sandbox `sandbox` plans: the
    /// sandbox's own, with the command's fields replaced by this exec's.
    ///
    /// The command is composed by the answers the builder composes its own
    /// by, so the two cannot disagree: the command check, the environment's
    /// composition, path lookup over the composed `PATH`, and the working
    /// directory's check. The setup's fields are emptied, since the setup is
    /// the sandbox's and is behind it: a joining launch mounts nothing, places
    /// no target, sets no hostname, and creates no cgroup.
    pub(crate) fn plan(&self, sandbox: &LaunchPlan) -> Result<LaunchPlan, Error> {
        let command = spec::validate_command(Some(self.command.clone()), Some(self.path_lookup))?;
        let mut vars = spec::env_pairs(&sandbox.env);
        vars.extend(self.env.iter().cloned());
        let env = spec::compose_env(&[], &vars)?;
        let program_search = spec::lookup_candidates(&command, &env)?;
        let exec_label = spec::exec_label(&command.path, &program_search);
        let args = self
            .args
            .iter()
            .map(|arg| spec::cstring(arg))
            .collect::<Result<Vec<_>, _>>()?;
        let workdir = match &self.workdir {
            Some(path) => spec::validate_workdir(path)?,
            None => sandbox.workdir.clone(),
        };
        Ok(LaunchPlan {
            program: command.program,
            program_search,
            args,
            env,
            stdin: StdioPlan::of(&self.stdin),
            stdout: StdioPlan::of(&self.stdout),
            stderr: StdioPlan::of(&self.stderr),
            // The session follows standard input alone, as the builder's does.
            own_session: !matches!(self.stdin, Stdio::Inherit),
            stop_with_caller: self.stop_with_caller,
            workdir,
            exec_label,
            hostname: None,
            configure_loopback: false,
            ops: Vec::new(),
            op_labels: Vec::new(),
            managed_placeholders: ManagedPlaceholders::default(),
            cgroup: None,
            cgroup_unapplied: Vec::new(),
            ..sandbox.clone()
        })
    }
}
