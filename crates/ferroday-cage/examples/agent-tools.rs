//! A sandbox for a coding agent's tool commands, built on ferroday-cage.
//!
//! A coding agent works by running commands its model chooses: a test suite, a
//! search, a build. An agent runtime runs each of them in a sandbox of its own,
//! and `agent-tools` confines one such command the way a runtime does:
//!
//! ```sh
//! agent-tools --worktree ~/project -- git status
//! ```
//!
//! - **The root** is the host's own tree, read-only, with the home directories
//!   and the runtime directories hidden. `--empty-root` composes one from the
//!   host's `/usr` and `/etc` instead.
//! - **The working tree** is bound read-write at its own path. `.env` is
//!   hidden, and `.git/hooks` and `.git/config` are read-only, since git runs or
//!   obeys what they hold the next time the user runs git outside the sandbox.
//! - **The identity** is the caller's own: the command runs as the caller's uid
//!   and gid, so files read as the caller's and the host's account database
//!   agrees with it. Its home directory is its own `/tmp`, since the caller's is
//!   hidden.
//! - **The network** is a namespace of the sandbox's own, whose one way out is
//!   a loopback port the example serves itself, with a stand-in for the service
//!   a runtime offers its tool commands.
//! - **The restrictions** are the curated seccomp roster, and Landlock's refusal
//!   of the pathname sockets the mounts leave in view, where the kernel enforces
//!   it.
//! - **The limits** are on the whole process tree, in a cgroup of the command's
//!   own, where the example runs in a delegated cgroup. Elsewhere they are
//!   per-process resource limits.
//!
//! Once the command has exited, the example reports what it used, the whole
//! tree's figures included where the limits are a cgroup's.
//!
//! It exists to exercise the library from the vantage of an agent runtime: the
//! host root with `hide` and `read_only`, a presented identity, a listener on
//! the sandbox's loopback, the unix-socket restriction, cgroup limits, and a
//! wait driven through the handle's readiness descriptor. Everything it does is
//! public API, and `crates/ferroday-cage/examples/agent-tools.toml` gives
//! `fcage` the same sandbox.
//!
//! # Usage
//!
//! ```text
//! agent-tools [OPTIONS] [--] COMMAND [ARGS...]
//! ```
//!
//! A command without a slash is found on the sandbox's `PATH`.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use ferroday_cage::relay::Escalation;
use ferroday_cage::{
    Cage, CageBuilder, CgroupLimit, Error, ErrorChain, ExitStatus, Network, PresentedIdentity,
    Resource, ResourceUsage, Running, SeccompPolicy, SeccompRules, Stdio, host,
};
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;

mod common;

use common::{failure, flag_value, into_string, string_value, usage_error, value_for};

/// Paths of a working tree hidden by default: they conventionally hold the
/// project's secrets.
const HIDDEN: &[&str] = &[".env"];

/// Paths of a git working tree made read-only by default, with what each is.
/// Git runs the hooks, and obeys the configuration, the next time the user runs
/// git outside the sandbox, so a command that could write them could run code
/// there.
const PROTECTED: &[(&str, Entry)] = &[
    (".git/hooks", Entry::Directory),
    (".git/config", Entry::File),
];

/// The home directory the command runs with: the sandbox's own `/tmp`, empty at
/// each launch and discarded with the sandbox.
const HOME: &str = "/tmp";

/// The loopback port the stand-in service answers on, unless `--port` says
/// otherwise. The port is the sandbox's own, so it collides with nothing on
/// the host.
const DEFAULT_PORT: u16 = 8080;

/// The grace a command that outlived its timeout has between the request to
/// stop and the kill.
const KILL_AFTER: Duration = Duration::from_secs(5);

/// The memory the command may use: the whole tree's under a cgroup, and each
/// process's writable memory under the per-process limits.
const MEMORY_MAX: u64 = 4 << 30;

/// The processes and threads the command may run: at once across the tree
/// under a cgroup, and per user id under the per-process limits.
const PROCESSES_MAX: u64 = 1024;

/// What the example exits with when the command outlived its timeout, as
/// `timeout(1)` and `fcage --timeout` do.
const TIMED_OUT: u8 = 124;

/// The most of a request the stand-in service reads: its request line and its
/// headers.
const REQUEST_HEAD_MAX: usize = 16 << 10;

/// How long the stand-in service waits for a request on a connection the
/// command opened.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const USAGE: &str = "\
Run a coding agent's tool command in a sandbox of its own.

Usage:
  agent-tools [OPTIONS] [--] COMMAND [ARGS...]

The working tree:
  --worktree DIR        The working tree, bound read-write at its own path
                        (default: the current directory). Its .env is hidden,
                        and its .git/hooks and .git/config are read-only
  --hide PATH           Hide PATH, so it reads empty and cannot be written
                        (repeatable). A relative PATH is in the working tree
  --read-only PATH      Make PATH read-only (repeatable). A relative PATH is in
                        the working tree, and PATH must exist
  --expose PATH         Bind host PATH read-only at its own path, such as a
                        toolchain in the hidden home directory (repeatable)

The root:
  --empty-root          Compose the root from the host's /usr and /etc alone,
                        rather than the host's whole tree, read-only

The command:
  --port PORT           The loopback port the stand-in service answers on
                        (default: 8080)
  --timeout SECONDS     Ask the command to stop after SECONDS, and kill it 5
                        seconds later
  --env NAME VALUE      Set an environment variable for the command (repeatable)

  -h, --help            Print this help
  -V, --version         Print the version

The command's exit code is the example's, or 128 plus the signal number when a
signal terminates it, and 124 when it outlives --timeout. 125 announces a
sandbox that could not be built or launched, 126 a command that cannot be
executed, 127 a command that does not exist, and 2 a usage error.
";

/// A parsed command line.
enum Invocation {
    Help,
    Version,
    /// Boxed because a run's configuration is much the largest of the three.
    Run(Box<Config>),
}

/// A resolved run configuration.
struct Config {
    /// The working tree as given; `run` resolves it.
    worktree: Option<PathBuf>,
    /// Paths to hide, beyond the defaults.
    hide: Vec<PathBuf>,
    /// Paths to make read-only, beyond the defaults.
    read_only: Vec<PathBuf>,
    /// Host paths to bind read-only at their own paths.
    expose: Vec<PathBuf>,
    /// Whether the root is composed on an empty root rather than the host's.
    empty_root: bool,
    /// The loopback port the stand-in service answers on.
    port: u16,
    /// When the command is asked to stop.
    timeout: Option<Duration>,
    /// Environment variables for the command.
    env: Vec<(OsString, OsString)>,
    /// The command line, never empty.
    command: Vec<OsString>,
}

/// What a protected path is, for creating one that is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    Directory,
    File,
}

/// How the example bounds what a command consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Limits {
    /// A cgroup of the command's own beneath this delegated directory, which
    /// bounds the whole tree.
    Cgroup(PathBuf),
    /// Per-process resource limits, where no delegated cgroup is available.
    PerProcess,
}

/// Why a run did not reach the command's outcome.
enum Failure {
    /// The library's error, which carries the code a launcher reports.
    Sandbox(Error),
    /// A failure of the example's own.
    Own(String),
}

impl From<Error> for Failure {
    fn from(error: Error) -> Failure {
        Failure::Sandbox(error)
    }
}

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Invocation::Version) => {
            println!("agent-tools {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(config)) => match run(*config) {
            Ok(code) => code,
            Err(Failure::Sandbox(error)) => {
                eprintln!("agent-tools: {}", ErrorChain::new(&error));
                ExitCode::from(error.shell_code())
            }
            Err(Failure::Own(message)) => failure("agent-tools", &message),
        },
        Err(message) => usage_error("agent-tools", &message),
    }
}

/// Parses the command line, excluding the program name.
fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let mut config = Config {
        worktree: None,
        hide: Vec::new(),
        read_only: Vec::new(),
        expose: Vec::new(),
        empty_root: false,
        port: DEFAULT_PORT,
        timeout: None,
        env: Vec::new(),
        command: Vec::new(),
    };
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(Invocation::Help);
        } else if arg == "-V" || arg == "--version" {
            return Ok(Invocation::Version);
        } else if arg == "--" {
            config.command.extend(args.by_ref());
            break;
        } else if arg == "--worktree" {
            config.worktree = Some(PathBuf::from(value_for("--worktree", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--worktree=") {
            config.worktree = Some(PathBuf::from(value));
        } else if arg == "--hide" {
            config
                .hide
                .push(PathBuf::from(value_for("--hide", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--hide=") {
            config.hide.push(PathBuf::from(value));
        } else if arg == "--read-only" {
            config
                .read_only
                .push(PathBuf::from(value_for("--read-only", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--read-only=") {
            config.read_only.push(PathBuf::from(value));
        } else if arg == "--expose" {
            config
                .expose
                .push(PathBuf::from(value_for("--expose", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--expose=") {
            config.expose.push(PathBuf::from(value));
        } else if arg == "--empty-root" {
            config.empty_root = true;
        } else if arg == "--port" {
            config.port = port(string_value("--port", &mut args)?)?;
        } else if let Some(value) = flag_value(&arg, b"--port=") {
            config.port = port(into_string("--port", value)?)?;
        } else if arg == "--timeout" {
            config.timeout = Some(seconds(string_value("--timeout", &mut args)?)?);
        } else if let Some(value) = flag_value(&arg, b"--timeout=") {
            config.timeout = Some(seconds(into_string("--timeout", value)?)?);
        } else if arg == "--env" {
            let name = value_for("--env", &mut args)?;
            let value = args
                .next()
                .ok_or_else(|| "--env requires a name and a value".to_string())?;
            config.env.push((name, value));
        } else if arg.as_bytes().starts_with(b"-") && arg != "-" {
            return Err(format!("unrecognized option {}", arg.to_string_lossy()));
        } else {
            // The first positional is the command; the rest are its arguments.
            config.command.push(arg);
            config.command.extend(args.by_ref());
            break;
        }
    }
    if config.command.is_empty() {
        return Err("a command to run is required".to_string());
    }
    Ok(Invocation::Run(Box::new(config)))
}

/// Reads `--port`'s value: a port other than 0.
fn port(value: String) -> Result<u16, String> {
    match value.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(format!(
            "--port takes a port from 1 to 65535, not {value:?}"
        )),
    }
}

/// Reads `--timeout`'s value: a whole number of seconds.
fn seconds(value: String) -> Result<Duration, String> {
    value
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| format!("--timeout takes a whole number of seconds, not {value:?}"))
}

/// Confines the command, serves its one way out until it exits, and reports
/// its outcome and what it used.
fn run(config: Config) -> Result<ExitCode, Failure> {
    let given = match &config.worktree {
        Some(worktree) => worktree.clone(),
        None => std::env::current_dir()
            .map_err(|err| Failure::Own(format!("cannot read the current directory: {err}")))?,
    };
    // The real path, so that the bind's target names no symbolic link in the
    // host's tree.
    let worktree = std::fs::canonicalize(&given).map_err(|err| {
        Failure::Own(format!(
            "cannot resolve the working tree {}: {err}",
            given.display()
        ))
    })?;
    if !worktree.is_dir() {
        return Err(Failure::Own(format!(
            "the working tree {} is not a directory",
            worktree.display()
        )));
    }
    prepare_protected(&worktree)?;

    let limits = match delegated_cgroup() {
        Ok(parent) => {
            eprintln!(
                "agent-tools: limits on the whole tree, in a cgroup beneath {}",
                parent.display()
            );
            Limits::Cgroup(parent)
        }
        Err(reason) => {
            eprintln!("agent-tools: limits on each process alone: {reason}");
            Limits::PerProcess
        }
    };
    let resolve_unix = resolve_unix_enforceable();
    if !resolve_unix {
        eprintln!(
            "agent-tools: this kernel's Landlock cannot refuse connections to pathname unix \
             sockets, so the command can connect to any socket in its view"
        );
    }

    let cage = posture(&config, &worktree, &limits, resolve_unix)
        .command(&config.command[0])
        .args(&config.command[1..])
        .build()?;

    let pending = cage.spawn_pending()?;
    // Made before the command starts, so its first connection finds it.
    let listener = pending.listen(SocketAddr::from((Ipv4Addr::LOCALHOST, config.port)))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| Failure::Own(format!("cannot make the listener non-blocking: {err}")))?;
    let mut running = pending.proceed()?;
    let mut escalation = Escalation::new(config.timeout, KILL_AFTER);
    let status = serve_until_exit(&mut running, &listener, &mut escalation)?;
    // The listener holds the sandbox's network namespace, which nothing needs
    // once the command has exited.
    drop(listener);

    report(status, running.usage());
    Ok(match escalation.outcome(status) {
        Some(status) => ExitCode::from(status.shell_code()),
        None => {
            eprintln!("agent-tools: the command outlived its timeout");
            ExitCode::from(TIMED_OUT)
        }
    })
}

/// The sandbox a tool command runs in, short of the command itself.
fn posture(config: &Config, worktree: &Path, limits: &Limits, resolve_unix: bool) -> CageBuilder {
    let mut builder = if config.empty_root {
        host_userland()
    } else {
        Cage::builder().host_rootfs()
    };
    for path in &config.expose {
        builder = builder.bind_ro(path, path);
    }
    builder = builder.bind(worktree, worktree).current_dir(worktree);
    // In order: each hide and read-only path lands on the working tree's bind.
    for path in defaults(worktree, HIDDEN).chain(within(worktree, &config.hide)) {
        builder = builder.hide(path);
    }
    for path in protected(worktree).chain(within(worktree, &config.read_only)) {
        builder = builder.read_only(path);
    }

    builder = builder
        .present_as(PresentedIdentity::Own)
        .network(Network::Isolated)
        .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
        .landlock_resolve_unix(resolve_unix)
        // A core dump would land in the working tree.
        .rlimit(Resource::CoreDump, 0, 0)
        .stdin(Stdio::Null)
        .stop_with_caller(true)
        .path_lookup(true)
        // The base environment gives a command that is not root inside no HOME,
        // and the caller's own is hidden.
        .env("HOME", HOME)
        .envs(config.env.iter().map(|(name, value)| (name, value)));

    match limits {
        // Without a swap limit, a tree past its memory limit goes on in swap.
        Limits::Cgroup(parent) => builder
            .cgroup_parent(parent)
            .cgroup_limit(CgroupLimit::MemoryMax(MEMORY_MAX))
            .cgroup_limit(CgroupLimit::MemorySwapMax(0))
            .cgroup_limit(CgroupLimit::PidsMax(PROCESSES_MAX)),
        Limits::PerProcess => builder
            .rlimit(Resource::Data, MEMORY_MAX, MEMORY_MAX)
            .rlimit(Resource::Processes, PROCESSES_MAX, PROCESSES_MAX),
    }
}

/// An empty root holding the host's userland, read-only: `/usr`, `/etc`, and
/// the top-level directories, or the links a merged `/usr` makes of them, as
/// the host has them.
fn host_userland() -> CageBuilder {
    let mut builder = Cage::builder()
        .empty_rootfs()
        .bind_ro("/usr", "/usr")
        .bind_ro("/etc", "/etc");
    for top in ["/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"] {
        let Ok(meta) = std::fs::symlink_metadata(top) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            if let Ok(target) = std::fs::read_link(top) {
                builder = builder.symlink(target, top);
            }
        } else if meta.is_dir() {
            builder = builder.bind_ro(top, top);
        }
    }
    builder
}

/// `names` joined to the working tree.
fn defaults<'a>(worktree: &'a Path, names: &'a [&str]) -> impl Iterator<Item = PathBuf> + 'a {
    names.iter().map(move |name| worktree.join(name))
}

/// The paths a caller named, a relative one taken inside the working tree.
fn within<'a>(worktree: &'a Path, paths: &'a [PathBuf]) -> impl Iterator<Item = PathBuf> + 'a {
    paths.iter().map(move |path| worktree.join(path))
}

/// The default read-only paths, with what each is, for a working tree whose
/// `.git` is a directory.
fn protected_entries(worktree: &Path) -> impl Iterator<Item = (PathBuf, Entry)> + '_ {
    let git = worktree.join(".git").is_dir();
    PROTECTED
        .iter()
        .filter(move |_| git)
        .map(move |&(name, entry)| (worktree.join(name), entry))
}

/// The default read-only paths of a working tree.
fn protected(worktree: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    protected_entries(worktree).map(|(path, _)| path)
}

/// Creates whichever default read-only path is missing from a git working tree,
/// empty. A path left missing is one the command could create, and a hook it
/// created would run outside the sandbox.
fn prepare_protected(worktree: &Path) -> Result<(), Failure> {
    for (path, entry) in protected_entries(worktree) {
        if path.symlink_metadata().is_ok() {
            continue;
        }
        let created = match entry {
            Entry::Directory => std::fs::create_dir(&path),
            Entry::File => std::fs::File::create_new(&path).map(drop),
        };
        created.map_err(|err| Failure::Own(format!("cannot create {}: {err}", path.display())))?;
        eprintln!(
            "agent-tools: created an empty {}, to make it read-only",
            path.display()
        );
    }
    Ok(())
}

/// The cgroup this process runs in, made ready to hold each command's cgroup,
/// or why it cannot be.
///
/// A delegated cgroup is one the process may create cgroups in, as systemd
/// arranges for a service or a scope with `Delegate=yes`. A cgroup that holds
/// processes cannot enable a controller for its children, so the example takes
/// its cgroup only where it runs there alone, and steps into a leaf of its own
/// first. The commands' cgroups then sit beside that leaf.
fn delegated_cgroup() -> Result<PathBuf, String> {
    let own = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|err| format!("cannot read this process's cgroup: {err}"))?;
    let relative = own
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("this host mounts no cgroup v2 hierarchy")?;
    let cgroup = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    let members = std::fs::read_to_string(cgroup.join("cgroup.procs"))
        .map_err(|err| format!("cannot list the processes of {}: {err}", cgroup.display()))?;
    let me = std::process::id().to_string();
    if members.lines().any(|pid| pid != me) {
        return Err(format!(
            "{} holds processes besides this one",
            cgroup.display()
        ));
    }
    let leaf = cgroup.join("agent-tools");
    match std::fs::create_dir(&leaf) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(format!(
                "cannot create a cgroup in {}, which is not delegated: {err}",
                cgroup.display()
            ));
        }
    }
    std::fs::write(leaf.join("cgroup.procs"), "0")
        .map_err(|err| format!("cannot move into {}: {err}", leaf.display()))?;
    Ok(cgroup)
}

/// Whether the kernel enforces Landlock's unix-socket restriction, which
/// arrives in Landlock ABI 9. Asked for on an older kernel, it is refused at
/// build, so the example asks only where it holds.
fn resolve_unix_enforceable() -> bool {
    host::landlock_abi().is_some_and(|abi| abi >= 9)
}

/// Answers the command's connections on `listener` until its outcome is known,
/// asking it to stop, and then killing it, as its timeout runs out.
///
/// One `poll` waits on the handle's readiness descriptor, the listener, and
/// the escalation's next deadline. An event loop registers the same two
/// descriptors.
fn serve_until_exit(
    running: &mut Running<'_>,
    listener: &TcpListener,
    escalation: &mut Escalation,
) -> Result<ExitStatus, Failure> {
    let mut serving = true;
    loop {
        if let Some(status) = running.try_wait()? {
            return Ok(status);
        }
        if escalation.passed() {
            escalation.expire(running)?;
            continue;
        }
        let timeout = escalation
            .deadline()
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .and_then(|left| Timespec::try_from(left).ok());
        let connection = {
            let mut fds = vec![PollFd::new(&*running, PollFlags::IN)];
            if serving {
                fds.push(PollFd::new(listener, PollFlags::IN));
            }
            match rustix::event::poll(&mut fds, timeout.as_ref()) {
                Ok(_) | Err(Errno::INTR) => {}
                Err(errno) => {
                    return Err(Failure::Own(format!(
                        "cannot wait for the command: {}",
                        io::Error::from(errno)
                    )));
                }
            }
            fds.get(1).is_some_and(|fd| !fd.revents().is_empty())
        };
        if !connection {
            continue;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(err) = std::thread::Builder::new()
                    .name("agent-tools-service".to_string())
                    .spawn(move || answer(stream))
                {
                    eprintln!("agent-tools: cannot start the service's thread: {err}");
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            // A listener that fails leaves the polled set, and the wait goes on.
            Err(err) => {
                eprintln!("agent-tools: the service stopped accepting: {err}");
                serving = false;
            }
        }
    }
}

/// Answers one connection of the command's with a line naming its request.
///
/// This stands in for the service a runtime offers its tool commands, such as
/// a proxy that admits the registries a build needs. What the service carries,
/// and where, is the runtime's policy, and the sandbox's network reaches
/// nothing else.
fn answer(mut connection: TcpStream) {
    let _ = connection.set_read_timeout(Some(REQUEST_TIMEOUT));
    let mut head = Vec::new();
    let mut chunk = [0; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") && head.len() < REQUEST_HEAD_MAX {
        match connection.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => head.extend_from_slice(&chunk[..read]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let line = head.split(|&byte| byte == b'\n').next().unwrap_or_default();
    let request = String::from_utf8_lossy(line).trim_end().to_string();
    // The request is the sandbox's text, so it is quoted with its control
    // characters escaped.
    eprintln!("agent-tools: the service answered {request:?}");
    let body = format!("stand-in service: {request}\n");
    let _ = write!(
        connection,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
}

/// Reports how the command ended and what it used, on standard error.
fn report(status: ExitStatus, usage: Option<ResourceUsage>) {
    eprintln!("agent-tools: the command's status: {status}");
    let Some(usage) = usage else {
        return;
    };
    let mebibytes = |bytes: u64| bytes as f64 / f64::from(1 << 20);
    match (
        usage.cgroup_user_time,
        usage.cgroup_system_time,
        usage.cgroup_peak_memory_bytes,
        usage.cgroup_peak_processes,
    ) {
        (Some(user), Some(system), Some(memory), Some(processes)) => eprintln!(
            "agent-tools: the whole tree used {:.2} s of user time and {:.2} s of system \
             time, and held at most {:.1} MiB of memory and {processes} processes",
            user.as_secs_f64(),
            system.as_secs_f64(),
            mebibytes(memory),
        ),
        _ => eprintln!(
            "agent-tools: the command and its descendants used {:.2} s of user time and \
             {:.2} s of system time, and the largest process held {:.1} MiB",
            usage.user_time.as_secs_f64(),
            usage.system_time.as_secs_f64(),
            mebibytes(usage.peak_rss_bytes),
        ),
    }
    match usage.cgroup_oom_kills {
        None | Some(0) => {}
        Some(1) => eprintln!("agent-tools: the memory limit ended a process of the tree"),
        Some(kills) => {
            eprintln!("agent-tools: the memory limit ended {kills} processes of the tree")
        }
    }
}

/// The documented command lines, and the profile beside this file, held to the
/// sandbox the example builds.
///
/// A launch needs the host's facilities, so these go as far as the build,
/// which is where a configuration is refused.
#[cfg(test)]
mod tests {
    use super::*;

    /// Parses `line` as a run invocation.
    fn parse_run(line: &[&str]) -> Config {
        match parse(line.iter().map(OsString::from)) {
            Ok(Invocation::Run(config)) => *config,
            Ok(_) => panic!("{line:?} is a run invocation"),
            Err(message) => panic!("{line:?}: {message}"),
        }
    }

    /// A working tree with a git directory, made fresh for the test.
    fn worktree(name: &str) -> PathBuf {
        let dir = ferroday_cage_testkit::scratch::scratch_dir(&format!("agent-tools-{name}"));
        std::fs::create_dir(dir.join(".git")).expect("the git directory is created");
        dir
    }

    #[test]
    fn the_documented_invocations_parse() {
        let config = parse_run(&["--worktree", "/w", "--", "git", "status"]);
        assert_eq!(config.worktree.as_deref(), Some(Path::new("/w")));
        assert_eq!(config.command, ["git", "status"]);
        assert_eq!(config.port, DEFAULT_PORT);

        let config = parse_run(&[
            "--empty-root",
            "--port=4100",
            "--timeout",
            "30",
            "--hide",
            "secrets",
            "--read-only=.config",
            "--expose",
            "/opt/toolchain",
            "--env",
            "LANG",
            "C.UTF-8",
            "sh",
            "-c",
            "curl -s http://127.0.0.1:4100/",
        ]);
        assert!(config.empty_root);
        assert_eq!(config.port, 4100);
        assert_eq!(config.timeout, Some(Duration::from_secs(30)));
        assert_eq!(config.hide, [PathBuf::from("secrets")]);
        assert_eq!(config.read_only, [PathBuf::from(".config")]);
        assert_eq!(config.expose, [PathBuf::from("/opt/toolchain")]);
        assert_eq!(
            config.env,
            [(OsString::from("LANG"), OsString::from("C.UTF-8"))]
        );
        // Everything after the command is the command's, flags included.
        assert_eq!(
            config.command,
            ["sh", "-c", "curl -s http://127.0.0.1:4100/"]
        );
    }

    #[test]
    fn a_command_line_the_example_cannot_run_is_a_usage_error() {
        for line in [
            &[][..],
            &["--worktree", "/w"],
            &["--"],
            &["--port", "0", "true"],
            &["--timeout", "soon", "true"],
            &["--no-such-flag", "true"],
        ] {
            assert!(
                parse(line.iter().map(OsString::from)).is_err(),
                "{line:?} parses"
            );
        }
    }

    #[test]
    fn a_relative_path_is_taken_inside_the_working_tree() {
        let tree = Path::new("/home/user/project");
        let paths = [PathBuf::from("secrets"), PathBuf::from("/etc/token")];
        let joined: Vec<PathBuf> = within(tree, &paths).collect();
        assert_eq!(
            joined,
            [
                PathBuf::from("/home/user/project/secrets"),
                PathBuf::from("/etc/token")
            ]
        );
    }

    #[test]
    fn the_posture_builds_on_either_root_with_either_limits() {
        let tree = worktree("posture");
        for empty_root in [false, true] {
            for limits in [
                Limits::PerProcess,
                Limits::Cgroup(PathBuf::from("/sys/fs/cgroup/agent")),
            ] {
                let mut config = parse_run(&["git", "status"]);
                config.empty_root = empty_root;
                let built = posture(&config, &tree, &limits, resolve_unix_enforceable())
                    .command("git")
                    .arg("status")
                    .build();
                if let Err(error) = built {
                    panic!(
                        "empty root {empty_root}, {limits:?}: {}",
                        ErrorChain::new(&error)
                    );
                }
            }
        }
    }

    #[test]
    fn a_git_tree_s_hooks_and_configuration_are_protected_and_a_missing_one_is_made() {
        let tree = worktree("protected");
        assert_eq!(
            protected(&tree).collect::<Vec<_>>(),
            [tree.join(".git/hooks"), tree.join(".git/config")]
        );
        assert!(prepare_protected(&tree).is_ok());
        assert!(tree.join(".git/hooks").is_dir());
        assert!(tree.join(".git/config").is_file());
        // A tree that is not a git working tree has nothing to protect.
        let plain = ferroday_cage_testkit::scratch::scratch_dir("agent-tools-plain");
        assert_eq!(protected(&plain).count(), 0);
        assert!(prepare_protected(&plain).is_ok());
        assert!(!plain.join(".git").exists());
    }

    /// `fcage` reads the profile beside this file, and the guide's command line
    /// adds the working tree. Composed the way `fcage` composes them, the two
    /// give the sandbox the example builds with per-process limits.
    #[cfg(feature = "serde")]
    #[test]
    fn the_profile_describes_the_example_s_sandbox() {
        const PROFILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/agent-tools.toml");
        let text = std::fs::read_to_string(PROFILE).expect("the profile is readable");
        let profile: CageBuilder = toml::from_str(&text).expect("the profile parses");

        let tree = worktree("profile");
        // The flags the guide gives: --bind, --chdir, --hide and --read-only,
        // each extending the profile's lists or replacing its value.
        let from_profile = profile
            .bind(&tree, &tree)
            .current_dir(&tree)
            .hide(tree.join(".env"))
            .read_only(tree.join(".git/hooks"))
            .read_only(tree.join(".git/config"))
            .command("git");
        let example = posture(
            &parse_run(&["git"]),
            &tree,
            &Limits::PerProcess,
            resolve_unix_enforceable(),
        )
        .command("git");
        // Two settings the resolved inputs do not record.
        assert_eq!(
            from_profile.get_stop_with_caller(),
            example.get_stop_with_caller()
        );
        assert_eq!(from_profile.get_path_lookup(), example.get_path_lookup());
        // The profile leaves the unix-socket restriction to the host root's
        // default, which holds where the kernel enforces it, as the example's
        // own choice does.
        let [from_profile, example] = [from_profile, example].map(|builder| {
            builder
                .build()
                .unwrap_or_else(|error| panic!("{}", ErrorChain::new(&error)))
        });
        assert_eq!(from_profile.resolved_inputs(), example.resolved_inputs());
    }
}
