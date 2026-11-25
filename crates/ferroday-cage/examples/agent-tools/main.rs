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
//! - **The working tree** is bound read-write at its own path, and `.env` is
//!   hidden.
//! - **Git** in the sandbox works against private gitdirs, so the command
//!   writes no gitdir the user's git reads, and its commits come back through
//!   a fetch that checks every object. The [`git`] module sets out the modes,
//!   the paths held read-only, and what is reported.
//! - **The identity** is the caller's own: the command runs as the caller's uid
//!   and gid, so files read as the caller's and the host's account database
//!   agrees with it. Its home directory is its own `/tmp`, since the caller's is
//!   hidden.
//! - **The network** is a namespace of the sandbox's own, whose one way out is
//!   a loopback port the example serves itself, with a stand-in for the service
//!   a runtime offers its tool commands. With `--registries`, the library's
//!   network stack also carries the command's connections to the package
//!   registries a build fetches from, and to nothing else, and the example
//!   prints each connection and lookup the stack refuses.
//! - **The restrictions** are the curated seccomp roster, and Landlock's refusal
//!   of the pathname sockets the mounts leave in view, where the kernel enforces
//!   it.
//! - **The limits** are on each process, and on the whole process tree in a
//!   cgroup of the command's own where the example runs in a delegated cgroup.
//!
//! Once the command has exited, the example reports what it used, the whole
//! tree's figures included where the limits are a cgroup's.
//!
//! It exists to exercise the library from the vantage of an agent runtime: the
//! host root with `hide` and `read_only`, a presented identity, a listener on
//! the sandbox's loopback, the network stack's destination rules and reports,
//! the unix-socket restriction, cgroup limits, and a wait driven through the
//! handle's readiness descriptor. Everything it does is public API, and
//! `crates/ferroday-cage/examples/agent-tools.toml` gives `fcage` the same
//! sandbox.
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
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ferroday_cage::relay::Escalation;
use ferroday_cage::{
    Cage, CageBuilder, CgroupLimit, DestinationRule, Error, ErrorChain, ExitStatus, FsAccess,
    NetStack, NetStackBuilder, NetStackError, NetStackHandle, Network, Pending, PresentedIdentity,
    Resource, ResourceUsage, Running, SeccompPolicy, SeccompRules, Stdio, host,
};
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;

#[path = "../common/mod.rs"]
mod common;
mod git;

use common::{failure, flag_value, into_string, string_value, usage_error, value_for};

/// Paths of a working tree hidden by default: they conventionally hold the
/// project's secrets.
const HIDDEN: &[&str] = &[".env"];

/// The home directory the command runs with: the sandbox's own `/tmp`, empty at
/// each launch and discarded with the sandbox.
const HOME: &str = "/tmp";

/// The loopback port the stand-in service answers on, unless `--port` says
/// otherwise. The port is the sandbox's own, so it collides with nothing on
/// the host.
const DEFAULT_PORT: u16 = 8080;

/// The package registries a build fetches from, as the destination rules
/// `--registries` admits: each a name, on HTTPS's port alone.
///
/// - crates.io: the sparse index, and the crate files.
/// - PyPI: the index, and the distribution files.
/// - npm: the registry, which serves both.
/// - Go: the module proxy, and the checksum database `go` verifies against.
///
/// A name rule admits a TCP flow only to an address the stack's own nameserver
/// resolved for one of these names, and only where the TLS server name the
/// flow sends is one of them too.
const REGISTRIES: &[&str] = &[
    "index.crates.io:443",
    "static.crates.io:443",
    "pypi.org:443",
    "files.pythonhosted.org:443",
    "registry.npmjs.org:443",
    "proxy.golang.org:443",
    "sum.golang.org:443",
];

/// The grace a command that outlived its timeout has between the request to
/// stop and the kill.
const KILL_AFTER: Duration = Duration::from_secs(5);

/// The memory the command may use: each process's writable memory, and the
/// whole tree's under a cgroup.
const MEMORY_MAX: u64 = 4 << 30;

/// The processes and threads the command may run: per user id, and at once
/// across the tree under a cgroup.
const PROCESSES_MAX: u64 = 1024;

/// The limits on the whole tree. Without the swap limit, a tree past its memory
/// limit goes on in swap.
const CGROUP_LIMITS: [CgroupLimit; 3] = [
    CgroupLimit::MemoryMax(MEMORY_MAX),
    CgroupLimit::MemorySwapMax(0),
    CgroupLimit::PidsMax(PROCESSES_MAX),
];

/// What the example exits with when the command outlived its timeout, as
/// `timeout(1)` and `fcage --timeout` do.
const TIMED_OUT: u8 = 124;

/// The most of a request the stand-in service reads: its request line and its
/// headers.
const REQUEST_HEAD_MAX: usize = 16 << 10;

/// How long the stand-in service waits for a request on a connection the
/// command opened, in all: a command trickling a byte at a time cannot hold a
/// connection past it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The most connections the stand-in service answers at once.
///
/// The service runs in this process, so what it holds for the command, a
/// thread and a request head per connection, is bounded by none of the
/// command's limits. A connection past this waits in the listener's backlog
/// until one in hand is answered.
const MAX_CONNECTIONS: usize = 16;

/// How often a wait whose service is answering all it may checks whether a
/// connection has been answered since.
const SATURATED_RECHECK: Duration = Duration::from_millis(50);

const USAGE: &str = "\
Run a coding agent's tool command in a sandbox of its own.

Usage:
  agent-tools [OPTIONS] [--] COMMAND [ARGS...]

The working tree:
  --worktree DIR        The working tree, bound read-write at its own path
                        (default: the current directory). Its .env is hidden
  --hide PATH           Hide PATH, so it reads empty and cannot be written
                        (repeatable). A relative PATH is in the working tree
  --read-only PATH      Make PATH read-only (repeatable). A relative PATH is in
                        the working tree, and PATH must exist
  --expose PATH         Bind host PATH read-only at its own path, such as a
                        toolchain in the hidden home directory (repeatable)

Git, where the working tree is a repository's:
  --git MODE            How the command's git reaches the repository. private
                        (the default): a private gitdir for each of the tree's,
                        whose commits come back into the repository and move
                        the checked-out branch where they fast-forward it.
                        read-only: the repository's gitdirs, read-only.
                        isolated: a checkout of HEAD in the session, whose
                        commits come back and move nothing
  --session DIR         Keep the session in DIR across commands, made where
                        missing (default: a temporary one, removed at exit)
  --no-repository-report
                        Report no repository the command makes in the tree
  --protected           Print the paths the command may not write, which a
                        runtime's own editing tool refuses as well, and exit

The root:
  --empty-root          Compose the root from the host's /usr and /etc alone,
                        rather than the host's whole tree, read-only

The network:
  --port PORT           The loopback port the stand-in service answers on
                        (default: 8080)
  --registries          Carry connections to the package registries of
                        crates.io, PyPI, npm and Go as well, through the
                        library's network stack, and print each connection
                        and lookup it refuses. Needs the host's own root
  --allow RULE          Admit RULE beside the registries (repeatable), a
                        destination rule such as github.com:443 or
                        192.0.2.0/24

The command:
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
    /// Whether the network stack carries connections to the registries.
    registries: bool,
    /// Destination rules admitted beside the registries.
    allow: Vec<DestinationRule>,
    /// When the command is asked to stop.
    timeout: Option<Duration>,
    /// Environment variables for the command.
    env: Vec<(OsString, OsString)>,
    /// How the command's git reaches the repository.
    git: git::Mode,
    /// The session directory kept across commands, where one is named.
    session: Option<PathBuf>,
    /// Whether a repository the command makes in the tree is reported.
    report: bool,
    /// Whether the run prints the protected paths rather than running.
    print_protected: bool,
    /// The command line, never empty.
    command: Vec<OsString>,
}

/// Why a run did not reach the command's outcome.
enum Failure {
    /// The library's error, which carries the code a launcher reports.
    Sandbox(Error),
    /// The network stack could not be built or attached. The command never
    /// ran, so the example reports it as a failure of its own.
    Stack(NetStackError),
    /// A failure of the example's own.
    Own(String),
}

impl From<Error> for Failure {
    fn from(error: Error) -> Failure {
        Failure::Sandbox(error)
    }
}

impl From<NetStackError> for Failure {
    fn from(error: NetStackError) -> Failure {
        Failure::Stack(error)
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
            Err(Failure::Stack(error)) => failure(
                "agent-tools",
                &format!("the network stack: {}", ErrorChain::new(&error)),
            ),
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
        registries: false,
        allow: Vec::new(),
        timeout: None,
        env: Vec::new(),
        git: git::Mode::Private,
        session: None,
        report: true,
        print_protected: false,
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
        } else if arg == "--git" {
            config.git = git::Mode::parse(&string_value("--git", &mut args)?)?;
        } else if let Some(value) = flag_value(&arg, b"--git=") {
            config.git = git::Mode::parse(&into_string("--git", value)?)?;
        } else if arg == "--session" {
            config.session = Some(PathBuf::from(value_for("--session", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--session=") {
            config.session = Some(PathBuf::from(value));
        } else if arg == "--no-repository-report" {
            config.report = false;
        } else if arg == "--protected" {
            config.print_protected = true;
        } else if arg == "--empty-root" {
            config.empty_root = true;
        } else if arg == "--port" {
            config.port = port(string_value("--port", &mut args)?)?;
        } else if let Some(value) = flag_value(&arg, b"--port=") {
            config.port = port(into_string("--port", value)?)?;
        } else if arg == "--registries" {
            config.registries = true;
        } else if arg == "--allow" {
            config
                .allow
                .push(rule(string_value("--allow", &mut args)?)?);
        } else if let Some(value) = flag_value(&arg, b"--allow=") {
            config.allow.push(rule(into_string("--allow", value)?)?);
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
    if config.command.is_empty() && !config.print_protected {
        return Err("a command to run is required".to_string());
    }
    if !config.allow.is_empty() && !config.registries {
        return Err("--allow requires --registries".to_string());
    }
    // The empty root binds the host's /etc, which claims its resolv.conf, so
    // the library places no file naming the stack's nameserver there, and
    // nothing in the sandbox would resolve a registry's name.
    if config.registries && config.empty_root {
        return Err(
            "--registries needs the host's own root: the empty root binds the host's /etc, \
             whose resolv.conf cannot name the network stack's nameserver"
                .to_string(),
        );
    }
    Ok(Invocation::Run(Box::new(config)))
}

/// Reads `--allow`'s value: a destination rule.
fn rule(value: String) -> Result<DestinationRule, String> {
    value
        .parse()
        .map_err(|err| format!("--allow {value:?}: {err}"))
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
    let session = git::Session::open(
        &worktree,
        config.git,
        config.session.as_deref(),
        config.report,
    )
    .map_err(Failure::Own)?;
    if config.print_protected {
        if let Some(session) = session {
            for path in session.protected() {
                println!("{}", path.display());
            }
            session.discard();
        }
        return Ok(ExitCode::SUCCESS);
    }
    // Once the command has run, what it committed is taken in, whatever its
    // outcome; a launch that never reached the command leaves nothing to take.
    let launched = launch(&config, &worktree, session.as_ref());
    match (session, launched) {
        (Some(session), Ok(code)) => {
            session.finish().map_err(Failure::Own)?;
            Ok(code)
        }
        (Some(session), Err(failure)) => {
            session.discard();
            Err(failure)
        }
        (None, launched) => launched,
    }
}

/// Launches the command in its sandbox over `worktree`, with the mounts the
/// git `session` needs where the tree is a repository's, serves its one way out
/// until it exits, and reports its outcome and what it used.
fn launch(
    config: &Config,
    worktree: &Path,
    session: Option<&git::Session>,
) -> Result<ExitCode, Failure> {
    let cgroup = match delegated_cgroup() {
        Ok(parent) => {
            eprintln!(
                "agent-tools: limits on the whole tree, in a cgroup beneath {}",
                parent.display()
            );
            Some(parent)
        }
        Err(reason) => {
            eprintln!("agent-tools: limits on each process alone: {reason}");
            None
        }
    };
    // Asked for on a kernel that cannot enforce it, the unix-socket restriction
    // is refused at build, so the example asks for it only where it holds.
    let resolve_unix = host::landlock_enforces_fs(FsAccess::RESOLVE_UNIX);
    if !resolve_unix {
        eprintln!(
            "agent-tools: this kernel's Landlock cannot refuse connections to pathname unix \
             sockets, so the command can connect to any socket in its view"
        );
    }

    // Built before the sandbox, whose resolv.conf names the stack's nameserver.
    let stack = if config.registries {
        Some(registries(&config.allow).build()?)
    } else {
        None
    };
    let cage = posture(
        config,
        worktree,
        session,
        cgroup.as_deref(),
        resolve_unix,
        stack.as_ref(),
    )
    .command(&config.command[0])
    .args(&config.command[1..])
    .build()?;

    let pending = cage.spawn_pending()?;
    // Attached and listening before the command starts, so its first lookup
    // and its first connection find them.
    let attached = match &stack {
        Some(stack) => Some(Attached::start(stack, &pending)?),
        None => None,
    };
    let listener = pending.listen(SocketAddr::from((Ipv4Addr::LOCALHOST, config.port)))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| Failure::Own(format!("cannot make the listener non-blocking: {err}")))?;
    let mut running = pending.proceed()?;
    let mut escalation = Escalation::new(config.timeout, KILL_AFTER);
    let status = serve_until_exit(&mut running, &listener, &mut escalation)?;
    // The listener and the stack hold the sandbox's network namespace, which
    // nothing needs once the command has exited.
    drop(listener);
    if let Some(attached) = attached {
        attached.stop();
    }

    report(status, running.usage());
    Ok(match escalation.outcome(status) {
        Some(status) => ExitCode::from(status.shell_code()),
        None => {
            eprintln!("agent-tools: the command outlived its timeout");
            ExitCode::from(TIMED_OUT)
        }
    })
}

/// The sandbox a tool command runs in, short of the command itself, with its
/// limits on the whole tree in a cgroup beneath `cgroup` where one is given,
/// and its `resolv.conf` naming the nameserver of `stack` where one is attached.
fn posture(
    config: &Config,
    worktree: &Path,
    session: Option<&git::Session>,
    cgroup: Option<&Path>,
    resolve_unix: bool,
    stack: Option<&NetStack>,
) -> CageBuilder {
    let mut builder = if config.empty_root {
        host_userland()
    } else {
        Cage::builder().host_rootfs()
    };
    for path in &config.expose {
        builder = builder.bind_ro(path, path);
    }
    // The caller's tree, or an isolated session's checkout of it, at the
    // working tree's path.
    let tree = session.map_or(worktree, git::Session::tree);
    builder = builder.bind(tree, worktree).current_dir(worktree);
    if let Some(session) = session {
        builder = session.mount(builder);
    }
    // In order: each hide and read-only path lands on the working tree's bind.
    for path in defaults(worktree, HIDDEN).chain(within(worktree, &config.hide)) {
        builder = builder.hide(path);
    }
    for path in within(worktree, &config.read_only) {
        builder = builder.read_only(path);
    }

    builder = builder
        .present_as(PresentedIdentity::Own)
        .network(Network::Isolated)
        .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
        .landlock_resolve_unix(resolve_unix)
        // A core dump would land in the working tree.
        .rlimit(Resource::CoreDump, 0, 0)
        // Each process alone, whether or not a cgroup holds the tree.
        .rlimit(Resource::Data, MEMORY_MAX, MEMORY_MAX)
        .rlimit(Resource::Processes, PROCESSES_MAX, PROCESSES_MAX)
        // The whole tree, where a parent is named; without one the launch runs
        // without these, and its resolved inputs say so.
        .cgroup_required(false)
        .stdin(Stdio::Null)
        .stop_with_caller(true)
        .path_lookup(true)
        // The base environment gives a command that is not root inside no HOME,
        // and the caller's own is hidden.
        .env("HOME", HOME)
        .envs(config.env.iter().map(|(name, value)| (name, value)));

    if let Some(stack) = stack {
        // The name rules admit the addresses the stack's nameserver resolved,
        // so the command asks that nameserver.
        builder = builder.nameservers(stack.nameservers());
    }

    builder = CGROUP_LIMITS
        .into_iter()
        .fold(builder, CageBuilder::cgroup_limit);
    match cgroup {
        Some(parent) => builder.cgroup_parent(parent),
        None => builder,
    }
}

/// The network stack `--registries` attaches: the [`REGISTRIES`] admitted, with
/// `allow`'s rules beside them. Any allow rule refuses whatever no allow rule
/// admits, so the command reaches the registries, the caller's additions, and
/// nothing else through the stack.
fn registries(allow: &[DestinationRule]) -> NetStackBuilder {
    REGISTRIES
        .iter()
        .map(|rule| {
            rule.parse::<DestinationRule>()
                .expect("each registry is a destination rule")
        })
        .chain(allow.iter().cloned())
        .fold(NetStack::builder(), NetStackBuilder::allow)
}

/// The network stack attached to a run's sandbox, and the thread printing what
/// it refuses.
struct Attached {
    handle: NetStackHandle,
    /// Prints each refusal the stack reports until the stack has stopped, and
    /// answers how many reports the stack had no room for.
    printer: JoinHandle<u64>,
}

impl Attached {
    /// Attaches `stack` to the sandbox `pending` holds, and starts printing
    /// the refusals it reports.
    ///
    /// The stack never waits on a reader: a report it has no room for is
    /// dropped and counted. So the refusals are read on a thread of their own,
    /// and the wait for the command goes on beside it.
    fn start(stack: &NetStack, pending: &Pending<'_>) -> Result<Attached, Failure> {
        let mut handle = stack.attach(pending)?;
        let reports = handle
            .take_reports()
            .expect("a new attachment's reports are not yet taken");
        let printer = std::thread::Builder::new()
            .name("agent-tools-reports".to_string())
            .spawn(move || {
                // The reports end once the stack has stopped and each one
                // queued has been read.
                while let Ok(report) = reports.recv() {
                    if report.is_refusal() {
                        eprintln!("agent-tools: the network stack {report}");
                    }
                }
                reports.dropped()
            })
            .map_err(|err| Failure::Own(format!("cannot start the reports' thread: {err}")))?;
        Ok(Attached { handle, printer })
    }

    /// Stops the stack once the command has exited, and waits for the last of
    /// its refusals to be printed.
    fn stop(self) {
        if let Err(error) = self.handle.stop() {
            eprintln!(
                "agent-tools: the network stack did not stop cleanly: {}",
                ErrorChain::new(&error)
            );
        }
        match self.printer.join() {
            Ok(0) | Err(_) => {}
            Ok(dropped) => {
                let plural = if dropped == 1 { "" } else { "s" };
                eprintln!(
                    "agent-tools: the network stack dropped {dropped} report{plural} its queue \
                     had no room for"
                );
            }
        }
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

/// The cgroup this process runs in, made ready to hold each command's cgroup,
/// or why it cannot be.
///
/// A delegated cgroup is one the process may create cgroups in, as systemd
/// arranges for a service or a scope with `Delegate=yes`. A cgroup that holds
/// processes cannot enable a controller for its children, so the example takes
/// its cgroup only where it runs there alone, and steps into a leaf of its own
/// first. The commands' cgroups then sit beside that leaf, and the library
/// answers whether the cgroup can hold them.
fn delegated_cgroup() -> Result<PathBuf, String> {
    let cgroup = host::own_cgroup().ok_or("this process runs in no cgroup v2 hierarchy")?;
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
                "cannot create a cgroup in {}: {err}",
                cgroup.display()
            ));
        }
    }
    std::fs::write(leaf.join("cgroup.procs"), "0")
        .map_err(|err| format!("cannot move into {}: {err}", leaf.display()))?;
    match host::cgroup_blocker(&cgroup, &CGROUP_LIMITS) {
        None => Ok(cgroup),
        Some(refusal) => Err(format!(
            "{} cannot hold the commands' cgroups: {refusal}",
            cgroup.display()
        )),
    }
}

/// Answers the command's connections on `listener` until its outcome is known,
/// asking it to stop, and then killing it, as its timeout runs out.
///
/// One `poll` waits on the handle's readiness descriptor, the listener, and
/// the escalation's next deadline. An event loop registers the same two
/// descriptors. Each connection is answered on a thread of its own, at most
/// [`MAX_CONNECTIONS`] at once: while that many are in hand the listener is
/// left out of the wait, which looks again every [`SATURATED_RECHECK`].
fn serve_until_exit(
    running: &mut Running<'_>,
    listener: &TcpListener,
    escalation: &mut Escalation,
) -> Result<ExitStatus, Failure> {
    let mut serving = true;
    let answering = Arc::new(AtomicUsize::new(0));
    loop {
        if let Some(status) = running.try_wait()? {
            return Ok(status);
        }
        if escalation.passed() {
            escalation.expire(running)?;
            continue;
        }
        // A service answering all it may leaves the listener out of the wait,
        // and looks again shortly for a connection answered since.
        let accepting = serving && answering.load(Ordering::Acquire) < MAX_CONNECTIONS;
        let left = escalation
            .deadline()
            .map(|deadline| deadline.saturating_duration_since(Instant::now()));
        let wait = match (left, serving && !accepting) {
            (Some(left), true) => Some(left.min(SATURATED_RECHECK)),
            (None, true) => Some(SATURATED_RECHECK),
            (left, false) => left,
        };
        let timeout = wait.and_then(|wait| Timespec::try_from(wait).ok());
        let connection = {
            let mut fds = vec![PollFd::new(&*running, PollFlags::IN)];
            if accepting {
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
                answering.fetch_add(1, Ordering::AcqRel);
                let answered = Answered(Arc::clone(&answering));
                if let Err(err) = std::thread::Builder::new()
                    .name("agent-tools-service".to_string())
                    .spawn(move || {
                        let _answered = answered;
                        answer(stream);
                    })
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

/// A connection the service has in hand, counted while it is: dropping it,
/// when the answer is done or its thread could not start, frees its place.
struct Answered(Arc<AtomicUsize>);

impl Drop for Answered {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Answers one connection: reads its request head, within
/// [`REQUEST_HEAD_MAX`] bytes and [`REQUEST_TIMEOUT`] in all, and replies with
/// its request line.
fn answer(connection: TcpStream) {
    answer_within(connection, REQUEST_TIMEOUT);
}

/// [`answer`], with `timeout` for the whole of the request head.
fn answer_within(mut connection: TcpStream, timeout: Duration) {
    // A deadline the clock cannot express is no deadline, and each read is
    // then held to the timeout alone.
    let deadline = Instant::now().checked_add(timeout);
    let _ = connection.set_write_timeout(Some(timeout));
    let mut head = Vec::new();
    let mut chunk = [0; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") && head.len() < REQUEST_HEAD_MAX {
        let left = deadline.map_or(timeout, |deadline| {
            deadline.saturating_duration_since(Instant::now())
        });
        if left.is_zero() || connection.set_read_timeout(Some(left)).is_err() {
            break;
        }
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
///
/// The whole tree's figures are a cgroup's, and they are reported for a killed
/// command too. The collected processes' figures are the sandbox's init's,
/// which a kill ends before it reports.
fn report(status: ExitStatus, usage: Option<ResourceUsage>) {
    eprintln!("agent-tools: the command's status: {status}");
    let Some(usage) = usage else {
        return;
    };
    let mebibytes = |bytes: u64| bytes as f64 / f64::from(1 << 20);
    if let (Some(user), Some(system), Some(memory), Some(processes)) = (
        usage.cgroup_user_time,
        usage.cgroup_system_time,
        usage.cgroup_peak_memory_bytes,
        usage.cgroup_peak_processes,
    ) {
        eprintln!(
            "agent-tools: the whole tree used {:.2} s of user time and {:.2} s of system \
             time, and held at most {:.1} MiB of memory and {processes} processes",
            user.as_secs_f64(),
            system.as_secs_f64(),
            mebibytes(memory),
        );
    } else if let (Some(user), Some(system), Some(peak)) =
        (usage.user_time, usage.system_time, usage.peak_rss_bytes)
    {
        eprintln!(
            "agent-tools: the command and its descendants used {:.2} s of user time and \
             {:.2} s of system time, and the largest process held {:.1} MiB",
            user.as_secs_f64(),
            system.as_secs_f64(),
            mebibytes(peak),
        );
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

    /// A git repository with one commit on `main`, made fresh for the test.
    fn repository(name: &str) -> PathBuf {
        let dir = ferroday_cage_testkit::scratch::scratch_dir(&format!("agent-tools-{name}"));
        let dir = std::fs::canonicalize(dir).expect("the scratch directory resolves");
        host_git_in(&dir, &["init", "--quiet", "--initial-branch=main"]);
        std::fs::write(dir.join("README"), "one\n").unwrap();
        host_git_in(&dir, &["add", "README"]);
        host_git_in(&dir, &["commit", "--quiet", "--message", "one"]);
        dir
    }

    /// Runs git in `dir` as the caller does, with an identity of its own and
    /// nothing of the caller's environment.
    fn host_git_in(dir: &Path, args: &[&str]) -> String {
        let mut command = std::process::Command::new("git");
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("GIT_") {
                command.env_remove(name);
            }
        }
        let output = command
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=tester",
                "-c",
                "user.email=tester@example.invalid",
            ])
            .args(["-c", "protocol.file.allow=always"])
            .args(args)
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    #[test]
    fn the_documented_invocations_parse() {
        let config = parse_run(&["--worktree", "/w", "--", "git", "status"]);
        assert_eq!(config.worktree.as_deref(), Some(Path::new("/w")));
        assert_eq!(config.command, ["git", "status"]);
        assert_eq!(config.port, DEFAULT_PORT);
        assert!(!config.registries);

        let config = parse_run(&[
            "--registries",
            "--allow",
            "github.com:443",
            "--allow=192.0.2.0/24",
            "--",
            "cargo",
            "fetch",
        ]);
        assert!(config.registries);
        assert_eq!(
            config.allow,
            [
                "github.com:443".parse::<DestinationRule>().unwrap(),
                "192.0.2.0/24".parse().unwrap(),
            ]
        );

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
            // A rule needs the stack that holds it, and a rule must parse.
            &["--allow", "github.com:443", "true"],
            &["--registries", "--allow", "github.com:0", "true"],
            // The empty root's /etc keeps the stack's nameserver unnamed.
            &["--registries", "--empty-root", "true"],
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
    fn the_posture_builds_on_either_root_with_or_without_a_cgroup() {
        let tree = worktree("posture");
        for empty_root in [false, true] {
            for cgroup in [None, Some(Path::new("/sys/fs/cgroup/agent"))] {
                let mut config = parse_run(&["git", "status"]);
                config.empty_root = empty_root;
                let built = posture(
                    &config,
                    &tree,
                    None,
                    cgroup,
                    host::landlock_enforces_fs(FsAccess::RESOLVE_UNIX),
                    None,
                )
                .command("git")
                .arg("status")
                .build();
                if let Err(error) = built {
                    panic!(
                        "empty root {empty_root}, cgroup {cgroup:?}: {}",
                        ErrorChain::new(&error)
                    );
                }
            }
        }
    }

    #[test]
    fn the_registries_build_a_stack_the_sandbox_resolves_through() {
        let extra: DestinationRule = "github.com:443".parse().unwrap();
        let builder = registries(std::slice::from_ref(&extra));
        assert_eq!(builder.get_allow().len(), REGISTRIES.len() + 1);
        assert_eq!(builder.get_allow().last(), Some(&extra));
        let stack = builder.build().expect("the registries build a stack");

        let tree = worktree("registries");
        let config = parse_run(&["--registries", "cargo", "fetch"]);
        let built = posture(
            &config,
            &tree,
            None,
            None,
            host::landlock_enforces_fs(FsAccess::RESOLVE_UNIX),
            Some(&stack),
        );
        assert_eq!(built.get_nameservers(), stack.nameservers());
        if let Err(error) = built.command("cargo").arg("fetch").build() {
            panic!("{}", ErrorChain::new(&error));
        }
    }

    /// `fcage` reads the profile beside this file, and the guide's command line
    /// adds the working tree. Composed the way `fcage` composes them, the two
    /// give the sandbox the example builds, with a cgroup parent and without
    /// one, and with `--netstack` the stack `--registries` attaches.
    #[cfg(feature = "serde")]
    #[test]
    fn the_profile_describes_the_example_s_sandbox() {
        const PROFILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/agent-tools.toml");
        let text = std::fs::read_to_string(PROFILE).expect("the profile is readable");
        // `fcage` takes the [netstack] table apart, as the stack's own format,
        // and reads the rest as the sandbox's.
        let mut table: toml::Table = text.parse().expect("the profile parses");
        let stack: NetStackBuilder = table
            .remove("netstack")
            .expect("the profile configures a stack")
            .try_into()
            .expect("the stack's table parses");
        let profile: CageBuilder = table.try_into().expect("the sandbox's keys parse");

        // The table is the stack `--registries` attaches, setting for setting.
        let serialized = |builder: &NetStackBuilder| {
            toml::to_string(builder).expect("a stack's settings serialize")
        };
        assert_eq!(serialized(&stack), serialized(&registries(&[])));
        let stack = stack.build().expect("the profile's stack builds");

        let tree = repository("profile");
        // `fcage` can offer the read-only posture alone: the private ones need
        // the example's own steps before and after the command.
        let session = git::Session::open(&tree, git::Mode::ReadOnly, None, false)
            .expect("the session opens")
            .expect("the tree is a repository's");
        let parent = Path::new("/sys/fs/cgroup/agent");
        for (cgroup, attached) in [None, Some(parent)]
            .into_iter()
            .flat_map(|cgroup| [(cgroup, None), (cgroup, Some(&stack))])
        {
            // The flags the guide gives: --bind, --chdir, --hide and
            // --read-only, each extending the profile's lists or replacing its
            // value, and --cgroup-parent where a delegated cgroup is available.
            let from_profile = profile
                .clone()
                .bind(&tree, &tree)
                .current_dir(&tree)
                .read_only(tree.join(".git"))
                .hide(tree.join(".env"))
                .command("git");
            let from_profile = match cgroup {
                Some(parent) => from_profile.cgroup_parent(parent),
                None => from_profile,
            };
            // `fcage --netstack` names the stack's nameserver, as
            // `--registries` does.
            let from_profile = match attached {
                Some(stack) => from_profile.nameservers(stack.nameservers()),
                None => from_profile,
            };
            let example = posture(
                &parse_run(&["git"]),
                &tree,
                Some(&session),
                cgroup,
                host::landlock_enforces_fs(FsAccess::RESOLVE_UNIX),
                attached,
            )
            .command("git");
            // Two settings the resolved inputs do not record.
            assert_eq!(
                from_profile.get_stop_with_caller(),
                example.get_stop_with_caller()
            );
            assert_eq!(from_profile.get_path_lookup(), example.get_path_lookup());
            // The profile leaves the unix-socket restriction to the host root's
            // default, which holds where the kernel enforces it, as the
            // example's own choice does.
            let [from_profile, example] = [from_profile, example].map(|builder| {
                builder
                    .build()
                    .unwrap_or_else(|error| panic!("{}", ErrorChain::new(&error)))
            });
            assert_eq!(
                from_profile.resolved_inputs(),
                example.resolved_inputs(),
                "cgroup {cgroup:?}, stack attached {}",
                attached.is_some()
            );
        }
    }

    // -- Git, end to end ------------------------------------------------------
    //
    // A real repository, a real sandbox, and a command that tries what a
    // hostile one would, writing a marker file where the caller's git would
    // run what it planted. Each needs user namespaces.

    /// Runs `script` as the command over `tree` under `--git mode`, with the
    /// example's other `flags`.
    fn run_script(
        tree: &Path,
        mode: &str,
        flags: &[&str],
        script: &str,
    ) -> Result<ExitCode, String> {
        let mut line = vec!["--worktree", tree.to_str().unwrap(), "--git", mode];
        line.extend_from_slice(flags);
        line.extend_from_slice(&["--", "/bin/sh", "-c", script]);
        match run(parse_run(&line)) {
            Ok(code) => Ok(code),
            Err(Failure::Own(message)) => Err(message),
            Err(Failure::Sandbox(error)) => Err(ErrorChain::new(&error).to_string()),
            Err(Failure::Stack(error)) => Err(ErrorChain::new(&error).to_string()),
        }
    }

    /// A repository whose own configuration names the identity its commits
    /// carry, so a private gitdir carries it too.
    fn identified(name: &str) -> PathBuf {
        let tree = repository(name);
        host_git_in(&tree, &["config", "user.name", "tester"]);
        host_git_in(&tree, &["config", "user.email", "tester@example.invalid"]);
        tree
    }

    #[test]
    fn a_private_gitdir_keeps_what_the_command_plants_and_its_commits_come_back() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        let tree = identified("git-private");
        let marker = tree.parent().unwrap().join("git-private-marker");
        let _ = std::fs::remove_file(&marker);
        let script = format!(
            "set -e
             echo two >> README && git add README && git commit -q -m two
             # The caller's hooks are read-only, here as everywhere.
             if printf '#!/bin/sh\\ntouch {m}\\n' > .git/hooks/post-checkout 2>/dev/null; then
                 exit 5
             fi
             git config core.fsmonitor 'touch {m}; false'
             if mv .git moved 2>/dev/null; then exit 3; fi
             mkdir decoy
             if mv -T decoy .git 2>/dev/null; then exit 4; fi
             rmdir decoy",
            m = marker.display()
        );
        let code = run_script(&tree, "private", &[], &script).expect("the run settles");
        assert_eq!(code, ExitCode::SUCCESS);
        // The caller's branch moved to the command's commit, and its tree and
        // index agree with it.
        assert_eq!(host_git_in(&tree, &["log", "-1", "--format=%s"]), "two");
        assert_eq!(host_git_in(&tree, &["status", "--porcelain"]), "");
        // What the command planted stayed in its session.
        assert!(!tree.join(".git/hooks/post-checkout").exists());
        assert!(!host_git_in(&tree, &["config", "--list"]).contains("fsmonitor"));
        host_git_in(&tree, &["checkout", "--quiet", "-b", "other"]);
        assert!(
            !marker.exists(),
            "the caller's git ran what the command planted"
        );
        // Nothing is left under the session's namespace once taken in.
        assert_eq!(host_git_in(&tree, &["for-each-ref", "refs/agent"]), "");
    }

    #[test]
    fn a_planted_commondir_never_reaches_the_callers_gitdir() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        let tree = identified("git-commondir");
        let session =
            ferroday_cage_testkit::scratch::scratch_dir("agent-tools-git-commondir-session");
        // The command breaks its own private gitdir, so nothing can be taken in
        // from it, and the run says so.
        let refused = run_script(
            &tree,
            "private",
            &["--session", session.to_str().unwrap()],
            "echo /tmp > .git/commondir",
        );
        assert!(refused.is_err(), "{refused:?}");
        assert!(!tree.join(".git/commondir").exists());
        assert_eq!(host_git_in(&tree, &["log", "-1", "--format=%s"]), "one");
    }

    #[test]
    fn a_commit_git_would_not_fetch_from_a_server_is_refused() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        let tree = identified("git-hostile");
        let script = "set -e
             blob=$(echo x | git hash-object -w --stdin)
             subtree=$(printf '100644 blob %s\\tconfig\\n' \"$blob\" | git mktree)
             top=$(printf '040000 tree %s\\t.git\\n' \"$subtree\" | git mktree)
             commit=$(echo hostile | git commit-tree \"$top\" -p HEAD)
             git update-ref refs/heads/main \"$commit\"";
        let refused = run_script(&tree, "private", &[], script);
        let message = refused.expect_err("the commits are refused");
        assert!(message.contains("refused"), "{message}");
        assert_eq!(host_git_in(&tree, &["log", "-1", "--format=%s"]), "one");
    }

    #[test]
    fn a_submodule_gets_a_private_gitdir_and_its_gitfile_is_held() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        let inner = identified("git-inner");
        let tree = identified("git-outer");
        host_git_in(
            &tree,
            &[
                "submodule",
                "--quiet",
                "add",
                inner.to_str().unwrap(),
                "sub",
            ],
        );
        host_git_in(&tree, &["commit", "--quiet", "-m", "sub"]);
        host_git_in(&tree.join("sub"), &["config", "user.name", "tester"]);
        host_git_in(
            &tree.join("sub"),
            &["config", "user.email", "tester@example.invalid"],
        );
        let gitfile = std::fs::read(tree.join("sub/.git")).unwrap();
        // Renaming the submodule's directory would carry the held gitfile
        // away and free its name for one the command wrote.
        let script = "set -e
             if echo 'gitdir: /tmp' > sub/.git 2>/dev/null; then exit 3; fi
             if mv sub sub.held 2>/dev/null; then exit 4; fi
             cd sub && echo change > inner && git add inner && git commit -q -m inner-change
             cd .. && git add sub && git commit -q -m bump";
        let code = run_script(&tree, "private", &[], script).expect("the run settles");
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(std::fs::read(tree.join("sub/.git")).unwrap(), gitfile);
        assert_eq!(host_git_in(&tree, &["log", "-1", "--format=%s"]), "bump");
        assert_eq!(
            host_git_in(&tree.join("sub"), &["log", "-1", "--format=%s"]),
            "inner-change"
        );
        assert_eq!(host_git_in(&tree, &["status", "--porcelain"]), "");
    }

    #[test]
    fn an_isolated_session_leaves_the_tree_and_its_branch_alone() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        let tree = identified("git-isolated");
        let script = "set -e
             echo two >> README && git commit -q -a -m two";
        let code = run_script(&tree, "isolated", &[], script).expect("the run settles");
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(
            std::fs::read_to_string(tree.join("README")).unwrap(),
            "one\n"
        );
        assert_eq!(host_git_in(&tree, &["log", "-1", "--format=%s"]), "one");
        let taken = host_git_in(
            &tree,
            &[
                "for-each-ref",
                "--format=%(refname) %(subject)",
                "refs/agent",
            ],
        );
        assert!(
            taken.lines().any(|line| line.ends_with("/heads/main two")),
            "{taken}"
        );
    }

    #[test]
    fn the_read_only_mode_reads_and_refuses_writes() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        let tree = identified("git-read-only");
        let script = "git status --short >/dev/null || exit 3
             if git commit -q --allow-empty -m nope 2>/dev/null; then exit 4; fi
             if echo /tmp > .git/commondir 2>/dev/null; then exit 5; fi";
        let code = run_script(&tree, "read-only", &[], script).expect("the run settles");
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(host_git_in(&tree, &["log", "-1", "--format=%s"]), "one");
    }

    #[test]
    fn a_linked_working_tree_gets_a_private_gitdir_of_its_own() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        let main = identified("git-linked-main");
        let linked = std::fs::canonicalize(ferroday_cage_testkit::scratch::scratch_dir(
            "agent-tools-git-linked-worktree",
        ))
        .unwrap();
        host_git_in(
            &main,
            &[
                "worktree",
                "add",
                "--quiet",
                "-b",
                "feature",
                linked.to_str().unwrap(),
            ],
        );
        let gitfile = std::fs::read(linked.join(".git")).unwrap();
        let script = "set -e
             if echo 'gitdir: /tmp' > .git 2>/dev/null; then exit 3; fi
             echo two >> README && git commit -q -a -m two";
        let code = run_script(&linked, "private", &[], script).expect("the run settles");
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(std::fs::read(linked.join(".git")).unwrap(), gitfile);
        assert_eq!(
            host_git_in(&main, &["log", "-1", "--format=%s", "feature"]),
            "two"
        );
        assert_eq!(
            host_git_in(&main, &["log", "-1", "--format=%s", "main"]),
            "one"
        );
    }

    #[test]
    fn the_paths_git_obeys_in_the_tree_are_held_and_listed() {
        if !ferroday_cage_testkit::require::userns() {
            return;
        }
        let inner = identified("git-held-inner");
        let tree = identified("git-held");
        // A submodule the tree does not check out, a repository of its own
        // inside the tree, and configuration the repository includes from it.
        host_git_in(
            &tree,
            &[
                "submodule",
                "--quiet",
                "add",
                inner.to_str().unwrap(),
                "sub",
            ],
        );
        host_git_in(&tree, &["commit", "--quiet", "-m", "sub"]);
        host_git_in(&tree, &["submodule", "--quiet", "deinit", "--force", "sub"]);
        let vendored = tree.join("vendor/tool");
        std::fs::create_dir_all(&vendored).unwrap();
        host_git_in(&vendored, &["init", "--quiet"]);
        std::fs::write(tree.join("shared.gitconfig"), "").unwrap();
        host_git_in(&tree, &["config", "include.path", "../shared.gitconfig"]);

        let session = git::Session::open(&tree, git::Mode::Private, None, false)
            .expect("the session opens")
            .expect("the tree is a repository's");
        let listed = session.protected();
        session.discard();
        for path in [".git", "sub", "vendor/tool/.git", "shared.gitconfig"] {
            assert!(
                listed.contains(&tree.join(path)),
                "{path} is not listed: {listed:?}"
            );
        }

        let script = "if mkdir sub/.git 2>/dev/null; then exit 3; fi
             if echo '[core]' >> vendor/tool/.git/config 2>/dev/null; then exit 4; fi
             if echo '[core]' >> shared.gitconfig 2>/dev/null; then exit 5; fi
             echo free > free";
        let code = run_script(&tree, "private", &[], script).expect("the run settles");
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(
            std::fs::read_to_string(tree.join("free")).unwrap(),
            "free\n"
        );
    }

    #[test]
    fn a_request_trickled_a_byte_at_a_time_is_held_to_its_deadline() {
        // A command can keep a connection's thread only as long as the whole
        // request head is allowed, however it spaces its bytes.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let trickle = std::thread::spawn(move || {
            let mut client = TcpStream::connect(address).unwrap();
            for byte in b"GET / HTTP/1.1\r\nHost: x\r\n".iter().cycle().take(200) {
                if client.write_all(&[*byte]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let (connection, _) = listener.accept().unwrap();
        let started = Instant::now();
        answer_within(connection, Duration::from_millis(300));
        let took = started.elapsed();
        assert!(took < Duration::from_secs(2), "the answer took {took:?}");
        trickle.join().unwrap();
    }
}
