//! A multi-repository Debian provisioning sandbox built on ferroday-cage.
//!
//! `deb-multirepo` bootstraps a Debian root filesystem that draws packages from
//! more than one source: the primary archive mirror, an optional
//! `snapshot.debian.org` backstop for it, and one or more local trusted `.deb`
//! repositories the caller points at. It is the counterpart of `deb-build` for
//! the [`Repository`](ferroday_cage::provision::debian::Repository) surface —
//! where that example audits
//! [`build_depend_names`](ferroday_cage::provision::debian::build_depend_names), this one
//! audits the repository builder against a real consumer that merges a mirror
//! with a local pool.
//!
//! ```sh
//! deb-multirepo --rootfs ./trixie --cache ./deb-cache \
//!     --local-repo ./my-debs --include my-package
//! ```
//!
//! # The two axes of a repository
//!
//! A [`Repository`](ferroday_cage::provision::debian::Repository) carries an
//! ordered list of mirror URLs, and the two things a caller reaches for fall out
//! of that one type:
//!
//! - **Distinct sources.** The primary mirror and each `--local-repo` are
//!   separate repositories, merged into one dependency resolution. Resolution is
//!   highest-version-wins across every repository, so a package a local pool
//!   ships supersedes the mirror's copy when its version is higher, and a
//!   package only the pool ships is pulled from it while its dependencies close
//!   against the mirror.
//! - **Interchangeable URLs.** `--snapshot` adds a backstop URL to the *primary*
//!   repository, tried when the live mirror reports a resource missing — a
//!   version that has rotated off the live pool. It is the same source reached a
//!   second way, not a second source.
//!
//! # The local repository is a trusted file:// source
//!
//! A `--local-repo` is a `dists/`-structured repository on disk — the layout
//! `apt` reads, the same one the provisioner fetches from a mirror — trusted
//! without a signature, apt's `[trusted=yes]`. That is the shape a build
//! produces when it regenerates a pool of its own `.deb`s each run, so no
//! signing ceremony and no flat-repository parser stand between the build and
//! the bootstrap. With no signature, authenticity rests on the transport, so
//! the provisioner requires one that supplies some — `file://` or `https://` —
//! and a `file://` pool under the caller's control is exactly its intended use.
//!
//! Each additional repository writes its own
//! `/etc/apt/sources.list.d/<name>.list` into the finished rootfs, so an
//! in-cage `apt` sees the same sources the bootstrap resolved against.
//!
//! # Usage
//!
//! ```text
//! deb-multirepo [OPTIONS] --rootfs DIR
//! deb-multirepo [OPTIONS] --rootfs DIR -- COMMAND [ARGS...]
//! ```
//!
//! With no trailing command the sandbox provisions the root and exits, printing
//! whether it was created or reused; an already-provisioned root is reused as it
//! stands. With `--plan` it resolves and prints the merged install set,
//! fetching the package indices it resolves against but downloading no
//! packages. With a command after `--` it provisions and then runs
//! that command in a cage rooted at the provisioned tree; the command is
//! interpreted inside the sandbox and must be absolute.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ferroday_cage::provision::debian::{Debian, DebianError, DebianEvent, Repository};
use ferroday_cage::provision::{self, Provisioned};
use ferroday_cage::{Cage, ConfigError, Error, ErrorChain};

mod common;

use common::{failure, flag_value, into_string, string_value, usage_error, value_for};

/// The suite bootstrapped when `--suite` is not given.
const DEFAULT_SUITE: &str = "trixie";

const USAGE: &str = "\
Provision a Debian root filesystem from several repositories.

Usage:
  deb-multirepo [OPTIONS] --rootfs DIR
  deb-multirepo [OPTIONS] --rootfs DIR -- COMMAND [ARGS...]

Root filesystem:
  --suite SUITE         Bootstrap this Debian suite (default: trixie); ignored
                        once the root exists
  --rootfs DIR          The provisioned root (required); provisioned on the
                        first run, reused thereafter
  --cache DIR           Cache downloaded packages here, content-addressed and
                        reused across bootstraps

Sources:
  --mirror URL          The primary archive mirror (default: the Debian CDN)
  --snapshot URL        A snapshot.debian.org backstop for the primary mirror,
                        tried when the live mirror reports a resource missing;
                        implies accepting the snapshot's expired release
  --local-repo DIR      A dists/-structured local repository, trusted without a
                        signature and merged into the resolution (repeatable)

Packages:
  --include PKG         Install PKG beyond the base system (repeatable)
  --plan                Resolve and print the merged install set, then exit;
                        fetches package indices but downloads no packages

  -h, --help            Print this help
  -V, --version         Print the version

With no trailing command the sandbox provisions the root and exits; with a
command after --, it provisions and then runs that command in the cage. The
command's exit code is the sandbox's exit code, or 128 plus the signal number
when it is terminated by a signal; 125 announces a sandbox that could not be
provisioned or launched, 126 a command that cannot be executed, 127 a command
that does not exist, and 2 a usage error.
";

/// A parsed command line.
enum Invocation {
    Help,
    Version,
    Run(Config),
}

/// A resolved `run` configuration.
struct Config {
    suite: String,
    rootfs: PathBuf,
    cache: Option<PathBuf>,
    mirror: Option<String>,
    snapshot: Option<String>,
    local_repos: Vec<PathBuf>,
    includes: Vec<String>,
    plan_only: bool,
    command: Option<Vec<OsString>>,
}

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Invocation::Version) => {
            println!("deb-multirepo {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(config)) => run(config),
        Err(message) => usage_error("deb-multirepo", &message),
    }
}

/// Parses the command line, excluding the program name.
fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let mut suite = None;
    let mut rootfs = None;
    let mut cache = None;
    let mut mirror = None;
    let mut snapshot = None;
    let mut local_repos = Vec::new();
    let mut includes = Vec::new();
    let mut plan_only = false;
    let mut command = None;

    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(Invocation::Help);
        } else if arg == "-V" || arg == "--version" {
            return Ok(Invocation::Version);
        } else if arg == "--" {
            command = Some(args.by_ref().collect::<Vec<_>>());
            break;
        } else if arg == "--suite" {
            suite = Some(string_value("--suite", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--suite=") {
            suite = Some(into_string("--suite", value)?);
        } else if arg == "--rootfs" {
            rootfs = Some(PathBuf::from(value_for("--rootfs", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--rootfs=") {
            rootfs = Some(PathBuf::from(value));
        } else if arg == "--cache" {
            cache = Some(PathBuf::from(value_for("--cache", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--cache=") {
            cache = Some(PathBuf::from(value));
        } else if arg == "--mirror" {
            mirror = Some(string_value("--mirror", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--mirror=") {
            mirror = Some(into_string("--mirror", value)?);
        } else if arg == "--snapshot" {
            snapshot = Some(string_value("--snapshot", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--snapshot=") {
            snapshot = Some(into_string("--snapshot", value)?);
        } else if arg == "--local-repo" {
            local_repos.push(PathBuf::from(value_for("--local-repo", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--local-repo=") {
            local_repos.push(PathBuf::from(value));
        } else if arg == "--include" {
            includes.push(string_value("--include", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--include=") {
            includes.push(into_string("--include", value)?);
        } else if arg == "--plan" {
            plan_only = true;
        } else if arg.as_bytes().starts_with(b"-") && arg != "-" {
            return Err(format!("unrecognized option {}", arg.to_string_lossy()));
        } else {
            return Err(format!(
                "unexpected argument {}; a command goes after --",
                arg.to_string_lossy()
            ));
        }
    }

    let rootfs = rootfs.ok_or("--rootfs DIR is required")?;
    let command = match command {
        Some(argv) if argv.is_empty() => return Err("-- requires a command".to_string()),
        other => other,
    };

    Ok(Invocation::Run(Config {
        suite: suite.unwrap_or_else(|| DEFAULT_SUITE.to_string()),
        rootfs,
        cache,
        mirror,
        snapshot,
        local_repos,
        includes,
        plan_only,
        command,
    }))
}

/// Composes the provisioner, then provisions the root and optionally launches a
/// command in it — or, with `--plan`, resolves and prints the install set.
fn run(config: Config) -> ExitCode {
    let mut debian = match compose(&config) {
        Ok(debian) => debian,
        Err(error) => return failure("deb-multirepo", &ErrorChain::new(&error).to_string()),
    };

    let mut progress = print_progress;
    if config.plan_only {
        return match debian.observe(&mut progress).resolve() {
            Ok(plan) => {
                for package in &plan.packages {
                    println!(
                        "{} {} {}",
                        package.name, package.version, package.architecture
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => failure(
                "deb-multirepo",
                &format!("cannot resolve the plan: {}", ErrorChain::new(&error)),
            ),
        };
    }

    match provision::ensure(&config.rootfs, &mut debian.observe(&mut progress)) {
        Ok(Provisioned::Created) => {
            eprintln!("deb-multirepo: provisioned {}", config.rootfs.display());
        }
        Ok(_) => {
            eprintln!("deb-multirepo: reusing {}", config.rootfs.display());
        }
        Err(error) => {
            return failure(
                "deb-multirepo",
                &format!("cannot provision the root: {}", ErrorChain::new(&error)),
            );
        }
    }

    match &config.command {
        Some(argv) => launch(&config.rootfs, argv),
        None => ExitCode::SUCCESS,
    }
}

/// Builds the [`Debian`] provisioner from the configured sources.
///
/// The primary mirror, its optional snapshot backstop, and the base
/// configuration go on through the [`Debian`] builder's own setters; each
/// `--local-repo` becomes a trusted `file://`
/// [`Repository`](ferroday_cage::provision::debian::Repository) merged in
/// alongside.
fn compose(config: &Config) -> Result<Debian, ComposeError> {
    let mut builder = Debian::builder(&config.suite).include(config.includes.clone());
    if let Some(mirror) = &config.mirror {
        builder = builder.mirror(mirror);
    }
    if let Some(snapshot) = &config.snapshot {
        // A snapshot's release is expired by design; accepting it is a
        // repository-wide posture, and the primary repository is where the
        // backstop lives.
        builder = builder.mirror_fallback(snapshot).allow_stale_release(true);
    }
    if let Some(cache) = &config.cache {
        builder = builder.cache_dir(cache);
    }
    for (index, dir) in config.local_repos.iter().enumerate() {
        builder = builder.repository(local_repository(&config.suite, dir, index)?);
    }
    Ok(builder.build()?)
}

/// Builds a trusted `file://` repository from a local `dists/`-structured pool.
///
/// The directory is canonicalized so the `file://` URL is absolute regardless
/// of the working directory, and named after its final path component (or a
/// generated stem) for its `sources.list.d` entry.
fn local_repository(suite: &str, dir: &Path, index: usize) -> Result<Repository, ComposeError> {
    let canonical = dir
        .canonicalize()
        .map_err(|source| ComposeError::LocalRepo {
            path: dir.to_path_buf(),
            source,
        })?;
    // The library owns the `file://` form, including the case a hand-written
    // `format!` degrades: a path that is not valid UTF-8 is reported rather than
    // lossily rendered into a URL naming something else.
    let url = provision::file_url(&canonical).map_err(DebianError::Fetch)?;
    let name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("local-{index}"));
    Ok(Repository::builder(suite)
        .mirror(url)
        .trust_unsigned(true)
        .name(name)
        .build()?)
}

/// Reduces a path component to the portable stem a repository name accepts:
/// ASCII letters, digits, and `.`, `-`, `_`, with anything else replaced by
/// `-`.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Runs a command in a cage rooted at the provisioned tree.
fn launch(rootfs: &Path, argv: &[OsString]) -> ExitCode {
    let mut argv = argv.iter();
    let program = argv.next().expect("a command line is never empty here");
    let cage = match Cage::builder()
        .rootfs(rootfs)
        .command(PathBuf::from(program))
        .args(argv)
        .build()
    {
        Ok(cage) => cage,
        Err(error) => {
            report_launch_error(&error);
            return ExitCode::from(error.shell_code());
        }
    };
    match cage.run() {
        Ok(status) => ExitCode::from(status.shell_code()),
        Err(error) => {
            eprintln!("deb-multirepo: {}", ErrorChain::new(&error));
            ExitCode::from(error.shell_code())
        }
    }
}

/// A failure composing the provisioner: an unreadable local repository, or an
/// invalid bootstrap configuration.
///
/// It follows the library's convention for an error: the message says what
/// failed and on what, and the cause is the [`source`](std::error::Error::source)
/// that [`ErrorChain`] renders after it.
#[derive(Debug)]
enum ComposeError {
    LocalRepo {
        path: PathBuf,
        source: std::io::Error,
    },
    Debian(DebianError),
}

impl From<DebianError> for ComposeError {
    fn from(error: DebianError) -> Self {
        ComposeError::Debian(error)
    }
}

impl std::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComposeError::LocalRepo { path, .. } => {
                write!(f, "local repository {} is unreadable", path.display())
            }
            ComposeError::Debian(_) => f.write_str("cannot configure the bootstrap"),
        }
    }
}

impl std::error::Error for ComposeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ComposeError::LocalRepo { source, .. } => Some(source),
            ComposeError::Debian(error) => Some(error),
        }
    }
}

/// Prints a Debian bootstrap progress event to stderr.
fn print_progress(event: DebianEvent<'_>) {
    use std::io::Write;
    // Two levels of openness, and each needs its own escape: the `_` arm
    // absorbs a future variant, and the `..` in every struct arm absorbs a
    // future field within a variant already matched here.
    match event {
        DebianEvent::Fetching { url, .. } => eprintln!("deb-multirepo: fetching {url}"),
        DebianEvent::Resolving => eprintln!("deb-multirepo: resolving the package set"),
        DebianEvent::Unsatisfiable {
            requirement,
            required_by,
            reason,
            ..
        } => eprintln!("deb-multirepo: {required_by} requires {requirement}, and {reason}"),
        DebianEvent::Downloading {
            package,
            index,
            total,
            ..
        } => eprintln!("deb-multirepo: downloading {package} ({index}/{total})"),
        DebianEvent::Extracting { package, .. } => eprintln!("deb-multirepo: extracting {package}"),
        DebianEvent::CommandOutput { bytes, .. } => {
            let _ = std::io::stderr().write_all(bytes);
        }
        _ => {}
    }
}

/// Explains a launch failure, pointing at the fix for the configuration errors
/// an invocation most often omits.
fn report_launch_error(error: &Error) {
    match error {
        Error::Config(ConfigError::RootfsMissing) => {
            eprintln!("deb-multirepo: no root; pass --rootfs DIR")
        }
        Error::Config(ConfigError::RootfsUnusable { path, .. }) => eprintln!(
            "deb-multirepo: root {} is unusable; it is provisioned on the first run",
            path.display()
        ),
        other => eprintln!("deb-multirepo: {}", ErrorChain::new(other)),
    }
}
