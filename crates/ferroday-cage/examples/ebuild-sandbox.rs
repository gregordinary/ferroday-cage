//! An ebuild development sandbox built on ferroday-cage.
//!
//! `ebuild-sandbox` provisions a Gentoo stage3 root filesystem, binds a
//! portage tree into it read-only, opens the network for source fetches, and
//! runs `emerge` inside a cage. A package build happens against a clean
//! stage3, with the host system left untouched: the tree the build reads is a
//! read-only view of the host's, and everything the build writes lands in the
//! provisioned root or in the read-write caches the caller binds.
//!
//! ```sh
//! ebuild-sandbox --stage3 stage3-amd64-openrc.tar.xz --rootfs ./gentoo \
//!     --repo /var/db/repos/gentoo --distfiles ./distfiles \
//!     app-misc/hello
//! ```
//!
//! It exists to exercise the library's provisioning path from the vantage of a
//! real consumer: it is the worked example that calls
//! [`provision::ensure`](ferroday_cage::provision::ensure) itself — extracting
//! a multi-hundred-megabyte stage3 through the tarball provisioner — rather
//! than taking a rootfs prepared elsewhere. The build posture is nothing more
//! than ordinary builder calls: a read-only `bind_ro` for the tree,
//! read-write `bind`s for the distfiles and binary-package caches, and
//! `Network::Host` for fetches.
//!
//! No hardening layer is applied. A package merge legitimately chowns files,
//! writes across the tree, and runs helper daemons; the isolation the build
//! needs is the cage's namespaces and private root, not a syscall filter over
//! the top. Portage's own internal sandboxing is disabled for the same reason
//! it would be inside any container — the cage already provides the boundary,
//! and the two nest badly.
//!
//! The cage's identity map is [`IdentityMap::Subordinate`]: root plus the
//! calling user's whole subordinate-id allocation, so the `portage` uid and
//! gid genuinely exist inside the sandbox. Portage chowns its state
//! directories at startup and drops to the `portage` user for builds and
//! fetches (`userpriv`, `userfetch`), exactly as it would on a host —
//! nothing is worked around. The map needs the `subid` feature and, on the
//! host, the shadow suite's `newuidmap`/`newgidmap` helpers with a
//! subordinate allocation for the calling user; a host without them is
//! reported with the missing piece named.
//!
//! One consequence of real ids: directories portage chowns to its own user
//! (its state and cache trees) are owned by subordinate ids on the host, so
//! a later `rm -rf` of the rootfs by the plain calling user fails inside
//! them. Remove it from inside the same mapping — `unshare --map-auto rm
//! -rf ./gentoo-root` — as rootless container storage is removed.
//!
//! # Usage
//!
//! ```text
//! ebuild-sandbox [OPTIONS] PACKAGE...
//! ebuild-sandbox [OPTIONS] -- COMMAND [ARGS...]
//! ```
//!
//! With one or more package atoms, the sandbox runs `emerge --oneshot` over
//! them. With a command after `--`, it runs that command instead — a shell,
//! say, for interactive ebuild work in the same posture. The command path is
//! interpreted inside the sandbox and must be absolute.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::process::ExitCode;

use ferroday_cage::provision::{self, Provisioned, Tarball};
use ferroday_cage::{Cage, ConfigError, Error, ExitStatus, IdentityMap, Network, SetupStep};

/// Where the host portage tree is bound, read-only, inside the sandbox.
const REPO_DEST: &str = "/var/db/repos/gentoo";
/// Where a host distfiles cache is bound, read-write.
const DISTFILES_DEST: &str = "/var/cache/distfiles";
/// Where a host binary-package cache is bound, read-write.
const BINPKGS_DEST: &str = "/var/cache/binpkgs";
/// The package manager, addressed by absolute path: the cage does not resolve
/// the command against `PATH`.
const EMERGE: &str = "/usr/bin/emerge";
/// The portage feature posture inside the cage. The `sandbox` and
/// `*-sandbox` features intercept a build's filesystem writes and unshare
/// further namespaces around each build step; inside the cage the boundary
/// already exists, and nesting them fights the cage's own namespaces.
/// `userpriv` is enabled: under the subordinate range map the `portage`
/// user exists, so builds drop to it exactly as on a host (`userfetch` is
/// on by default and needs no mention). Set as an environment default so a
/// `--env FEATURES=...` from the caller replaces it.
const FEATURES: &str = "-sandbox -usersandbox -ipc-sandbox -network-sandbox -pid-sandbox userpriv";

const USAGE: &str = "\
Provision a Gentoo stage3 and build packages in an isolated sandbox.

Usage:
  ebuild-sandbox [OPTIONS] PACKAGE...
  ebuild-sandbox [OPTIONS] -- COMMAND [ARGS...]

Root filesystem:
  --stage3 FILE         Provision the root from this stage3 tarball (any
                        compression) before launching; skipped, and fast, once
                        the root exists
  --rootfs DIR          The provisioned stage3 root filesystem (required)

Mounts:
  --repo DIR            Bind a host portage tree read-only at
                        /var/db/repos/gentoo
  --distfiles DIR       Bind a host distfiles cache read-write at
                        /var/cache/distfiles, so fetched sources persist
  --binpkgs DIR         Bind a host binary-package cache read-write at
                        /var/cache/binpkgs, for --buildpkg output

Build environment:
  --env NAME VALUE      Set an environment variable for the build (repeatable);
                        NAME=FEATURES overrides the sandbox's default
  --offline             Deny outbound network; the default shares the host
                        network so emerge can fetch sources

  -h, --help            Print this help
  -V, --version         Print the version

With package atoms, the sandbox runs 'emerge --oneshot' over them; with a
command after --, it runs that command instead. The command's exit code is the
sandbox's exit code, or 128 plus the signal number when it is terminated by a
signal; 125 announces a sandbox that could not be provisioned, built, or
launched, 126 a command that cannot be executed, 127 a command that does not
exist, and 2 a usage error.
";

/// A parsed command line.
enum Invocation {
    Help,
    Version,
    Run(Config),
}

/// A resolved `run` configuration.
struct Config {
    stage3: Option<PathBuf>,
    rootfs: PathBuf,
    repo: Option<PathBuf>,
    distfiles: Option<PathBuf>,
    binpkgs: Option<PathBuf>,
    env: Vec<(OsString, OsString)>,
    offline: bool,
    task: Task,
}

/// What to run inside the sandbox.
enum Task {
    /// `emerge --oneshot` over these package atoms.
    Emerge(Vec<OsString>),
    /// An explicit command line given after `--`.
    Command(Vec<OsString>),
}

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Invocation::Version) => {
            println!("ebuild-sandbox {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(config)) => run(config),
        Err(message) => usage_error(&message),
    }
}

/// Parses the command line, excluding the program name.
fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let mut stage3 = None;
    let mut rootfs = None;
    let mut repo = None;
    let mut distfiles = None;
    let mut binpkgs = None;
    let mut env = Vec::new();
    let mut offline = false;
    let mut packages = Vec::new();
    let mut command_line = None;

    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(Invocation::Help);
        } else if arg == "-V" || arg == "--version" {
            return Ok(Invocation::Version);
        } else if arg == "--" {
            command_line = Some(args.by_ref().collect::<Vec<_>>());
            break;
        } else if arg == "--stage3" {
            stage3 = Some(PathBuf::from(value_for("--stage3", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--stage3=") {
            stage3 = Some(PathBuf::from(value));
        } else if arg == "--rootfs" {
            rootfs = Some(PathBuf::from(value_for("--rootfs", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--rootfs=") {
            rootfs = Some(PathBuf::from(value));
        } else if arg == "--repo" {
            repo = Some(PathBuf::from(value_for("--repo", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--repo=") {
            repo = Some(PathBuf::from(value));
        } else if arg == "--distfiles" {
            distfiles = Some(PathBuf::from(value_for("--distfiles", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--distfiles=") {
            distfiles = Some(PathBuf::from(value));
        } else if arg == "--binpkgs" {
            binpkgs = Some(PathBuf::from(value_for("--binpkgs", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--binpkgs=") {
            binpkgs = Some(PathBuf::from(value));
        } else if arg == "--env" {
            let name = value_for("--env", &mut args)?;
            let value = args
                .next()
                .ok_or_else(|| "--env requires a name and a value".to_string())?;
            env.push((name, value));
        } else if arg == "--offline" {
            offline = true;
        } else if arg.as_bytes().starts_with(b"-") && arg != "-" {
            return Err(format!("unrecognized option {}", arg.to_string_lossy()));
        } else {
            // The first positional is a package atom; the rest follow.
            packages.push(arg);
            packages.extend(args.by_ref());
            break;
        }
    }

    let rootfs = rootfs.ok_or("--rootfs DIR is required")?;
    let task = match command_line {
        Some(argv) if argv.is_empty() => {
            return Err("-- requires a command".to_string());
        }
        Some(argv) => Task::Command(argv),
        None if packages.is_empty() => {
            return Err("a package atom or a command after -- is required".to_string());
        }
        None => Task::Emerge(packages),
    };

    Ok(Invocation::Run(Config {
        stage3,
        rootfs,
        repo,
        distfiles,
        binpkgs,
        env,
        offline,
        task,
    }))
}

/// Provisions the root if asked, composes the sandbox, and launches it.
fn run(config: Config) -> ExitCode {
    if let Some(stage3) = &config.stage3 {
        match provision::ensure(&config.rootfs, &mut Tarball::new(stage3)) {
            Ok(Provisioned::Created) => eprintln!(
                "ebuild-sandbox: provisioned {} from {}",
                config.rootfs.display(),
                stage3.display()
            ),
            // A published root is reused silently, so the flag stays in an
            // invocation permanently at no cost after the first run.
            Ok(_) => {}
            Err(error) => {
                eprintln!("ebuild-sandbox: cannot provision the stage3: {error}");
                return ExitCode::from(125);
            }
        }
    } else if !config.rootfs.is_dir() {
        return usage_error(&format!(
            "root filesystem {} does not exist; pass --stage3 FILE to provision it",
            config.rootfs.display()
        ));
    }

    let mut builder = Cage::builder().rootfs(&config.rootfs);
    if let Some(repo) = &config.repo {
        builder = builder.bind_ro(repo, REPO_DEST);
    }
    if let Some(distfiles) = &config.distfiles {
        builder = builder.bind(distfiles, DISTFILES_DEST);
    }
    if let Some(binpkgs) = &config.binpkgs {
        builder = builder.bind(binpkgs, BINPKGS_DEST);
    }
    builder = builder.network(if config.offline {
        Network::Isolated
    } else {
        Network::Host
    });
    // The subordinate range map is what lets portage own and drop to its
    // own ids inside the sandbox; the feature default rides on top of it,
    // and the caller's overrides on top of that.
    builder = builder
        .identity_map(IdentityMap::Subordinate)
        .env("FEATURES", FEATURES)
        .envs(config.env);
    builder = match config.task {
        Task::Command(argv) => {
            let mut argv = argv.into_iter();
            let program = argv.next().expect("a command line is never empty here");
            builder.command(PathBuf::from(program)).args(argv)
        }
        Task::Emerge(packages) => builder.command(EMERGE).arg("--oneshot").args(packages),
    };

    match builder.build() {
        Ok(cage) => launch(cage),
        Err(error) => {
            report_build_error(&error);
            ExitCode::from(error_exit_code(&error))
        }
    }
}

/// Launches a built cage with inherited standard streams and waits for it,
/// mapping the outcome onto the process exit status.
fn launch(cage: Cage) -> ExitCode {
    match cage.run() {
        Ok(status) => exit_code_for(status),
        Err(error) => {
            eprintln!("ebuild-sandbox: {error}");
            ExitCode::from(error_exit_code(&error))
        }
    }
}

/// Maps a command's exit status onto the process exit code, following the
/// shell convention of 128 plus the signal number for a signalled command.
fn exit_code_for(status: ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        ExitCode::from(code as u8)
    } else if let Some(signal) = status.signal() {
        ExitCode::from(128_u8.wrapping_add(signal as u8))
    } else {
        // A wait status is always an exit code or a signal; a fallback rather
        // than a panic keeps this tail total.
        ExitCode::FAILURE
    }
}

/// Explains a build failure, pointing at the fix for the configuration errors
/// an invocation most often omits.
fn report_build_error(error: &Error) {
    match error {
        Error::Config(ConfigError::RootfsMissing) => {
            eprintln!("ebuild-sandbox: no root filesystem; pass --rootfs DIR")
        }
        Error::Config(ConfigError::RootfsUnusable { path, .. }) => eprintln!(
            "ebuild-sandbox: root filesystem {} is unusable; provision it with --stage3 FILE",
            path.display()
        ),
        // The build needs real portage ids, so the range map is a hard
        // requirement; the reason names what the host is missing.
        Error::Config(ConfigError::IdentityMapUnavailable { reason, .. }) => {
            eprintln!("ebuild-sandbox: a uid/gid range map is required and unavailable: {reason}")
        }
        other => eprintln!("ebuild-sandbox: {other}"),
    }
}

/// The launcher conventions: 127 when the command does not exist, 126 when it
/// exists but cannot be executed, 125 for any other library failure.
fn error_exit_code(error: &Error) -> u8 {
    match error {
        Error::Setup {
            step: SetupStep::Exec,
            errno,
            ..
        } => match std::io::Error::from_raw_os_error(*errno).kind() {
            std::io::ErrorKind::NotFound => 127,
            _ => 126,
        },
        _ => 125,
    }
}

/// Prints a usage error and returns the usage exit code.
fn usage_error(message: &str) -> ExitCode {
    eprintln!("ebuild-sandbox: {message}");
    eprintln!("Try 'ebuild-sandbox --help' for usage.");
    ExitCode::from(2)
}

/// Consumes the next argument as a required value.
fn value_for(name: &str, args: &mut dyn Iterator<Item = OsString>) -> Result<OsString, String> {
    args.next()
        .ok_or_else(|| format!("{name} requires a value"))
}

/// Splits `--flag=value` syntax, preserving a non-UTF-8 value.
fn flag_value(arg: &OsStr, prefix: &[u8]) -> Option<OsString> {
    arg.as_bytes()
        .strip_prefix(prefix)
        .map(|value| OsString::from_vec(value.to_vec()))
}
