//! A profile-driven sandbox orchestrator built on ferroday-cage.
//!
//! `orchestrator` keeps a directory of named sandbox profiles — TOML files,
//! one per group — and runs commands inside them. A group describes a sandbox
//! *posture* (its root filesystem, network, environment, and mounts) rather
//! than a single application, so many commands share one group:
//!
//! ```sh
//! orchestrator run offline -- cargo test
//! orchestrator run offline -- cargo build
//! orchestrator run net-dev -- curl https://example.com
//! ```
//!
//! It exists to exercise the library's `serde` feature and its
//! profile-plus-overrides composition path from the vantage of a real
//! consumer. Because a profile *is* a [`CageBuilder`], composition is nothing
//! more than ordinary builder calls layered onto the deserialized profile:
//!
//! - [`bind`](CageBuilder::bind), [`bind_ro`](CageBuilder::bind_ro), and
//!   [`env`](CageBuilder::env) extend the profile's lists;
//! - a scalar such as [`network`](CageBuilder::network),
//!   [`current_dir`](CageBuilder::current_dir), or
//!   [`rootfs`](CageBuilder::rootfs) replaces the profile's value;
//! - [`clear_args`](CageBuilder::clear_args) followed by
//!   [`command`](CageBuilder::command) and [`args`](CageBuilder::args)
//!   replaces a group's default command as a unit, so the new command never
//!   inherits the profile's arguments.
//!
//! # Usage
//!
//! ```text
//! orchestrator [--profiles DIR] list
//! orchestrator [--profiles DIR] run GROUP [OVERRIDES] [--] [COMMAND [ARGS...]]
//! ```
//!
//! The profile directory comes from `--profiles DIR` or the
//! `FERRODAY_CAGE_PROFILES` environment variable. Group profiles ship beside
//! this file; run against them with a rootfs of your own:
//!
//! ```sh
//! cargo run --example orchestrator --features serde -- \
//!     --profiles crates/ferroday-cage/examples/orchestrator-profiles \
//!     run offline --rootfs /srv/rootfs/alpine -- /bin/echo hello
//! ```

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ferroday_cage::{Cage, CageBuilder, ConfigError, Error, Network};

mod common;

use common::{flag_value, into_string, usage_error, value_for};

const USAGE: &str = "\
Run commands inside named, group-based sandbox profiles.

Usage:
  orchestrator [--profiles DIR] list
  orchestrator [--profiles DIR] run GROUP [OVERRIDES] [--] [COMMAND [ARGS...]]

Commands:
  list                  List the group profiles (*.toml) in the profile
                        directory
  run GROUP             Run a command in the sandbox described by GROUP.toml

Profile directory:
  --profiles DIR        The directory of group profiles; overrides the
                        FERRODAY_CAGE_PROFILES environment variable

Overrides (run), composed onto the group profile:
  --rootfs DIR          Replace the group's root filesystem
  --bind SRC DEST       Bind-mount host SRC read-write at DEST (repeatable;
                        extends the group's binds)
  --ro-bind SRC DEST    Bind-mount host SRC read-only at DEST (repeatable)
  --setenv NAME VALUE   Set an environment variable (repeatable; extends the
                        group's environment)
  --chdir DIR           Replace the working directory inside the sandbox
  --share-net           Share the host network
  --isolate-net         Isolated loopback-only network
  --deny-net            Isolated network with loopback left down
  -h, --help            Print this help
  -V, --version         Print the version

A command given after the group replaces the group's default command as a
unit; a group without a default command requires one. The command path is
interpreted inside the sandbox and must be absolute. The command's exit code
is the orchestrator's exit code, or 128 plus the signal number when it is
terminated by a signal; 125 announces a sandbox that could not be built or
launched, 126 a command that cannot be executed, 127 a command that does not
exist, and 2 a usage error.
";

/// A parsed command line.
enum Invocation {
    Help,
    Version,
    /// List the group profiles in the profile directory.
    List {
        profiles: Option<PathBuf>,
    },
    /// Run a command in a named group's sandbox.
    Run {
        profiles: Option<PathBuf>,
        group: String,
        overrides: Overrides,
        command_line: Vec<OsString>,
    },
}

/// Per-invocation overrides composed onto a group profile.
#[derive(Default)]
struct Overrides {
    rootfs: Option<PathBuf>,
    binds: Vec<(PathBuf, PathBuf, bool)>,
    env: Vec<(OsString, OsString)>,
    network: Option<Network>,
    chdir: Option<PathBuf>,
}

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Invocation::Version) => {
            println!("orchestrator {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::List { profiles }) => match profile_dir(profiles) {
            Ok(dir) => run_list(&dir),
            Err(message) => usage_error("orchestrator", &message),
        },
        Ok(Invocation::Run {
            profiles,
            group,
            overrides,
            command_line,
        }) => match profile_dir(profiles) {
            Ok(dir) => run_group(&dir, &group, overrides, command_line),
            Err(message) => usage_error("orchestrator", &message),
        },
        Err(message) => usage_error("orchestrator", &message),
    }
}

/// Parses the command line, excluding the program name.
///
/// Global options (`--profiles`, `--help`, `--version`) precede the
/// subcommand; `run` then takes a group name, its overrides, and the command.
fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let mut profiles = None;

    let subcommand = loop {
        let Some(arg) = args.next() else {
            return Err("a subcommand is required: list or run".to_string());
        };
        if arg == "-h" || arg == "--help" {
            return Ok(Invocation::Help);
        } else if arg == "-V" || arg == "--version" {
            return Ok(Invocation::Version);
        } else if arg == "--profiles" {
            profiles = Some(PathBuf::from(value_for("--profiles", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--profiles=") {
            profiles = Some(PathBuf::from(value));
        } else if arg.as_bytes().starts_with(b"-") && arg != "-" {
            return Err(format!("unrecognized option {}", arg.to_string_lossy()));
        } else {
            break arg;
        }
    };

    if subcommand == "list" {
        // The only option `list` accepts is a late --profiles.
        while let Some(arg) = args.next() {
            if arg == "--profiles" {
                profiles = Some(PathBuf::from(value_for("--profiles", &mut args)?));
            } else if let Some(value) = flag_value(&arg, b"--profiles=") {
                profiles = Some(PathBuf::from(value));
            } else {
                return Err(format!("list takes no argument {}", arg.to_string_lossy()));
            }
        }
        return Ok(Invocation::List { profiles });
    }

    if subcommand == "run" {
        return parse_run(profiles, args);
    }

    Err(format!(
        "unknown subcommand {}; use list or run",
        subcommand.to_string_lossy()
    ))
}

/// Parses a `run` invocation: the group name, its overrides, and the command.
fn parse_run(
    mut profiles: Option<PathBuf>,
    mut args: impl Iterator<Item = OsString>,
) -> Result<Invocation, String> {
    // The group name comes first, after any late --profiles.
    let group = loop {
        let Some(arg) = args.next() else {
            return Err("run requires a group name".to_string());
        };
        if arg == "-h" || arg == "--help" {
            return Ok(Invocation::Help);
        } else if arg == "--profiles" {
            profiles = Some(PathBuf::from(value_for("--profiles", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--profiles=") {
            profiles = Some(PathBuf::from(value));
        } else if arg.as_bytes().starts_with(b"-") && arg != "-" {
            return Err(format!("unrecognized option {}", arg.to_string_lossy()));
        } else {
            break into_string("the group name", arg)?;
        }
    };

    let mut overrides = Overrides::default();
    let mut command_line = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--" {
            command_line.extend(args);
            break;
        } else if arg == "--rootfs" {
            overrides.rootfs = Some(PathBuf::from(value_for("--rootfs", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--rootfs=") {
            overrides.rootfs = Some(PathBuf::from(value));
        } else if arg == "--bind" || arg == "--ro-bind" {
            let read_only = arg == "--ro-bind";
            let name = if read_only { "--ro-bind" } else { "--bind" };
            let source = value_for(name, &mut args)?;
            let target = args
                .next()
                .ok_or_else(|| format!("{name} requires a source and a target"))?;
            overrides
                .binds
                .push((PathBuf::from(source), PathBuf::from(target), read_only));
        } else if arg == "--setenv" {
            let name = value_for("--setenv", &mut args)?;
            let value = args
                .next()
                .ok_or_else(|| "--setenv requires a name and a value".to_string())?;
            overrides.env.push((name, value));
        } else if arg == "--chdir" {
            overrides.chdir = Some(PathBuf::from(value_for("--chdir", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--chdir=") {
            overrides.chdir = Some(PathBuf::from(value));
        } else if arg == "--share-net" {
            overrides.network = Some(Network::Host);
        } else if arg == "--isolate-net" {
            overrides.network = Some(Network::Isolated);
        } else if arg == "--deny-net" {
            overrides.network = Some(Network::None);
        } else if arg.as_bytes().starts_with(b"-") && arg != "-" {
            return Err(format!("unrecognized option {}", arg.to_string_lossy()));
        } else {
            // The first positional is the command; the rest belong to it.
            command_line.push(arg);
            command_line.extend(args);
            break;
        }
    }

    Ok(Invocation::Run {
        profiles,
        group,
        overrides,
        command_line,
    })
}

/// Resolves the profile directory: `--profiles` if given, otherwise the
/// `FERRODAY_CAGE_PROFILES` environment variable.
fn profile_dir(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(dir) = explicit {
        return Ok(dir);
    }
    if let Some(dir) = std::env::var_os("FERRODAY_CAGE_PROFILES") {
        return Ok(PathBuf::from(dir));
    }
    Err("no profile directory: pass --profiles DIR or set FERRODAY_CAGE_PROFILES".to_string())
}

/// Lists the group profiles — the `*.toml` files — in the profile directory.
fn run_list(dir: &Path) -> ExitCode {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!(
                "orchestrator: cannot read profile directory {}: {err}",
                dir.display()
            );
            return ExitCode::from(125);
        }
    };

    let mut groups: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension() != Some(OsStr::new("toml")) {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(OsStr::to_str) {
            groups.push(stem.to_string());
        }
    }

    if groups.is_empty() {
        eprintln!(
            "orchestrator: no group profiles (*.toml) in {}",
            dir.display()
        );
        return ExitCode::SUCCESS;
    }
    groups.sort();
    for group in groups {
        println!("{group}");
    }
    ExitCode::SUCCESS
}

/// Composes a group profile with the invocation's overrides and launches it.
fn run_group(
    dir: &Path,
    group: &str,
    overrides: Overrides,
    command_line: Vec<OsString>,
) -> ExitCode {
    let path = match group_profile_path(dir, group) {
        Ok(path) => path,
        Err(message) => return usage_error("orchestrator", &message),
    };

    // A profile is a CageBuilder, so it deserializes straight into one.
    let mut builder = match load_group(&path) {
        Ok(builder) => builder,
        Err(message) => {
            eprintln!("orchestrator: {message}");
            return ExitCode::from(125);
        }
    };

    // Scalar overrides replace the profile's value.
    if let Some(rootfs) = overrides.rootfs {
        builder = builder.rootfs(rootfs);
    }
    // A command from the prompt replaces the group's default command as a
    // unit: clear_args drops the profile's arguments so the new command does
    // not inherit them. Without a command, the group's default (if any) runs.
    let mut command_line = command_line.into_iter();
    if let Some(program) = command_line.next() {
        builder = builder
            .clear_args()
            .command(PathBuf::from(program))
            .args(command_line);
    }
    // List overrides extend the profile's lists.
    for (source, target, read_only) in overrides.binds {
        builder = if read_only {
            builder.bind_ro(source, target)
        } else {
            builder.bind(source, target)
        };
    }
    builder = builder.envs(overrides.env);
    if let Some(network) = overrides.network {
        builder = builder.network(network);
    }
    if let Some(chdir) = overrides.chdir {
        builder = builder.current_dir(chdir);
    }

    match builder.build() {
        Ok(cage) => launch(cage),
        Err(error) => {
            report_build_error(group, &error);
            ExitCode::from(error.shell_code())
        }
    }
}

/// Resolves a group name to its profile path, rejecting names that are not a
/// single path component so a group cannot escape the profile directory.
fn group_profile_path(dir: &Path, group: &str) -> Result<PathBuf, String> {
    let is_component = !group.is_empty()
        && group != "."
        && group != ".."
        && !group.contains('/')
        && !group.contains('\0');
    if !is_component {
        return Err(format!("invalid group name {group:?}"));
    }
    Ok(dir.join(format!("{group}.toml")))
}

/// Reads a group profile and deserializes it into a builder.
fn load_group(path: &Path) -> Result<CageBuilder, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read group profile {}: {err}", path.display()))?;
    toml::from_str(&text)
        .map_err(|err| format!("cannot parse group profile {}: {err}", path.display()))
}

/// Launches a built cage with inherited standard streams and waits for it,
/// mapping the outcome onto the process exit status.
fn launch(cage: Cage) -> ExitCode {
    match cage.spawn().and_then(|mut running| running.wait()) {
        Ok(status) => ExitCode::from(status.shell_code()),
        Err(error) => {
            eprintln!("orchestrator: {error}");
            ExitCode::from(error.shell_code())
        }
    }
}

/// Explains a build failure, naming the group and pointing at the fix for the
/// two configuration errors a group profile most often omits.
fn report_build_error(group: &str, error: &Error) {
    match error {
        Error::Config(ConfigError::CommandMissing) => {
            eprintln!("orchestrator: group '{group}' defines no default command; give one after --")
        }
        Error::Config(ConfigError::RootfsMissing) => eprintln!(
            "orchestrator: group '{group}' sets no rootfs; add one to the profile or pass --rootfs DIR"
        ),
        other => eprintln!("orchestrator: {other}"),
    }
}
