//! A Debian source-package build sandbox built on ferroday-cage.
//!
//! `deb-build` bootstraps a Debian root filesystem with the build toolchain and
//! a source tree's declared build dependencies, then runs `dpkg-buildpackage`
//! inside a cage to build a `.deb` from that source. The host is left
//! untouched: no build tooling is installed on it, the source tree is bound
//! read-only and built from a copy, and only the finished packages are written
//! back, into a directory the caller names.
//!
//! ```sh
//! deb-build --rootfs ./trixie-build --cache ./deb-cache \
//!     --source ./hello-2.10 --output ./out
//! ```
//!
//! It is the Debian counterpart of the ebuild sandbox: where that example
//! provisions a Gentoo stage3 through the Gentoo provisioner, this one
//! bootstraps a Debian suite from the archive through the
//! [`Debian`](ferroday_cage::provision::debian::Debian) provisioner. Both wire
//! a progress sink, this one through
//! [`observe`](ferroday_cage::provision::debian::Debian::observe), so the heavy
//! bootstrap reports what it is doing.
//!
//! # The build environment is baked in
//!
//! The bootstrap installs the generic Debian build toolchain
//! (`build-essential`, `dpkg-dev`, `fakeroot`) plus the build dependencies the
//! source tree declares. Those come from the tree's `debian/control`, read
//! through [`debian::build_depend_names`](ferroday_cage::provision::debian::build_depend_names)
//! and folded into the bootstrap's install set, so the build resolves no
//! dependencies at build time and runs with an isolated network. `--build-dep`
//! adds packages beyond the declared set. Because the dependencies are baked
//! into the root, changing them means provisioning a fresh `--rootfs`; an
//! existing root is reused as it stands.
//!
//! The provisioner resolves those dependencies itself, speaking to the archive
//! directly, so the build needs no network and no writable package database.
//! The root's `sources.list` names binary packages only, which leaves
//! `apt-get build-dep` nothing to resolve against inside the cage.
//!
//! # No hardening, and the identity map
//!
//! No [hardening](ferroday_cage) layer is applied. A package build compiles
//! code, writes across a tree, and runs helper processes; the boundary it needs
//! is the cage's namespaces and private root, not a syscall filter over the
//! top.
//!
//! The cage maps the calling user to root and nothing else, and a Debian source
//! build is content with that. A package's file ownership is stored in the
//! package itself and applied by `dpkg` at install time, not by changing
//! ownership on the build tree, so the build asks for no user the map does not
//! contain. A package that declares `Rules-Requires-Root: no`, as many now do,
//! is built with no privilege emulation at all; one that still needs root for
//! its packaging step gets it from `fakeroot`, which the bootstrap installs.
//! This is the contrast with a Gentoo `emerge`, whose portage tooling chowns
//! its own state to a dedicated `portage` uid that a single-identity map cannot
//! represent: Debian's build tooling accommodates the single root identity
//! where Gentoo's does not.
//!
//! # Usage
//!
//! ```text
//! deb-build [OPTIONS] --rootfs DIR --source DIR --output DIR
//! deb-build [OPTIONS] --rootfs DIR --source DIR --output DIR -- COMMAND [ARGS...]
//! ```
//!
//! With no trailing command the sandbox copies the source tree to a writable
//! build directory, runs `dpkg-buildpackage -us -uc -b`, and collects the built
//! packages into `--output`. With a command after `--` it runs that instead, in
//! the same posture — a shell, say, for interactive packaging work. The command
//! path is interpreted inside the sandbox and must be absolute.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ferroday_cage::provision::debian::{Debian, DebianEvent};
use ferroday_cage::provision::{self, Provisioned};
use ferroday_cage::{Cage, ConfigError, Error, ErrorChain, Network};

mod common;

use common::{failure, flag_value, into_string, string_value, usage_error, value_for};

/// The suite bootstrapped when `--suite` is not given.
const DEFAULT_SUITE: &str = "trixie";
/// The generic Debian build toolchain, installed into every build root. The
/// source tree's own build dependencies are added on top.
const BASE_TOOLING: [&str; 3] = ["build-essential", "dpkg-dev", "fakeroot"];
/// Where the host source tree is bound, read-only.
const SOURCE_DEST: &str = "/src";
/// Where the host output directory is bound, read-write.
const OUTPUT_DEST: &str = "/out";
/// The shell that drives the default build, addressed by absolute path: the
/// cage does not resolve the command against `PATH`.
const SHELL: &str = "/bin/sh";

/// The default build: copy the read-only source to a writable tree, build a
/// binary package from it, and collect the artifacts into the output bind.
///
/// The copy keeps the host's source tree pristine — `dpkg-buildpackage` writes
/// build products throughout a tree — and lands the artifacts, which it writes
/// beside the tree, in the build root rather than in `--output`, so only the
/// finished packages are copied out. `find` gathers them by extension; a binary
/// build produces `.deb` and `.ddeb` packages, a `.buildinfo`, and a
/// `.changes`.
const BUILD_SCRIPT: &str = r#"rm -rf /build
mkdir -p /build
cp -a /src /build/tree
cd /build/tree
dpkg-buildpackage -us -uc -b
find /build -maxdepth 1 -type f \( -name '*.deb' -o -name '*.ddeb' -o -name '*.changes' -o -name '*.buildinfo' \) -exec cp -p {} /out/ \;
"#;

const USAGE: &str = "\
Build a Debian source package in an isolated sandbox.

Usage:
  deb-build [OPTIONS] --rootfs DIR --source DIR --output DIR
  deb-build [OPTIONS] --rootfs DIR --source DIR --output DIR -- COMMAND [ARGS...]

Root filesystem:
  --suite SUITE         Bootstrap this Debian suite (default: trixie); ignored
                        once the root exists
  --rootfs DIR          The provisioned build root (required); provisioned on
                        the first run, reused thereafter
  --cache DIR           Cache downloaded packages here, content-addressed and
                        reused across bootstraps

Source and output:
  --source DIR          The unpacked Debian source tree to build (required); it
                        must contain a debian/ directory, and is bound
                        read-only
  --output DIR          Collect the built packages here (required); bound
                        read-write

Build dependencies:
  --build-dep PKG       Install PKG as a build dependency (repeatable), beyond
                        those the source tree declares in debian/control
  --network             Share the host network with the build; by default the
                        build runs with an isolated network, which a
                        policy-conforming Debian build does not need.
                        Provisioning always fetches from the archive over the
                        host network

  -h, --help            Print this help
  -V, --version         Print the version

With no trailing command the sandbox runs 'dpkg-buildpackage -us -uc -b' over a
copy of the source and collects the built packages into --output; with a
command after --, it runs that instead. The command's exit code is the
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
    suite: String,
    rootfs: PathBuf,
    cache: Option<PathBuf>,
    source: PathBuf,
    output: PathBuf,
    build_deps: Vec<String>,
    network: bool,
    task: Task,
}

/// What to run inside the sandbox.
enum Task {
    /// Build a binary package from the bound source tree.
    Build,
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
            println!("deb-build {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(config)) => run(config),
        Err(message) => usage_error("deb-build", &message),
    }
}

/// Parses the command line, excluding the program name.
fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let mut suite = None;
    let mut rootfs = None;
    let mut cache = None;
    let mut source = None;
    let mut output = None;
    let mut build_deps = Vec::new();
    let mut network = false;
    let mut command_line = None;

    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(Invocation::Help);
        } else if arg == "-V" || arg == "--version" {
            return Ok(Invocation::Version);
        } else if arg == "--" {
            command_line = Some(args.by_ref().collect::<Vec<_>>());
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
        } else if arg == "--source" {
            source = Some(PathBuf::from(value_for("--source", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--source=") {
            source = Some(PathBuf::from(value));
        } else if arg == "--output" {
            output = Some(PathBuf::from(value_for("--output", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--output=") {
            output = Some(PathBuf::from(value));
        } else if arg == "--build-dep" {
            build_deps.push(string_value("--build-dep", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--build-dep=") {
            build_deps.push(into_string("--build-dep", value)?);
        } else if arg == "--network" {
            network = true;
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
    let source = source.ok_or("--source DIR is required")?;
    let output = output.ok_or("--output DIR is required")?;
    let task = match command_line {
        Some(argv) if argv.is_empty() => return Err("-- requires a command".to_string()),
        Some(argv) => Task::Command(argv),
        None => Task::Build,
    };

    Ok(Invocation::Run(Config {
        suite: suite.unwrap_or_else(|| DEFAULT_SUITE.to_string()),
        rootfs,
        cache,
        source,
        output,
        build_deps,
        network,
        task,
    }))
}

/// Provisions the build root if needed, composes the sandbox, and launches it.
fn run(config: Config) -> ExitCode {
    // A build needs a source tree with packaging metadata; fail early and
    // clearly rather than letting dpkg-buildpackage report it from inside.
    let control = config.source.join("debian/control");
    if matches!(config.task, Task::Build) && !control.is_file() {
        return usage_error(
            "deb-build",
            &format!(
                "{} is not a Debian source tree: no debian/control",
                config.source.display()
            ),
        );
    }

    if let Err(code) = provision(&config, &control) {
        return code;
    }

    let mut builder = Cage::builder()
        .rootfs(&config.rootfs)
        .bind_ro(&config.source, SOURCE_DEST)
        .bind(&config.output, OUTPUT_DEST)
        .network(if config.network {
            Network::Host
        } else {
            Network::Isolated
        });
    builder = match &config.task {
        Task::Build => builder
            .command(SHELL)
            .args(["-e", "-u", "-c", BUILD_SCRIPT]),
        Task::Command(argv) => common::with_command(builder, argv),
    };

    let cage = match builder.build() {
        Ok(cage) => cage,
        Err(error) => {
            report_build_error(&error);
            return ExitCode::from(error.shell_code());
        }
    };

    match cage.run() {
        Ok(status) => {
            if matches!(config.task, Task::Build) && status.code() == Some(0) {
                report_artifacts(&config.output);
            }
            ExitCode::from(status.shell_code())
        }
        Err(error) => {
            eprintln!("deb-build: {}", ErrorChain::new(&error));
            ExitCode::from(error.shell_code())
        }
    }
}

/// Bootstraps the build root, baking in the toolchain and the source tree's
/// declared build dependencies. An already-provisioned root is reused as it
/// stands, so its baked dependency set is whatever the first run installed.
fn provision(config: &Config, control: &Path) -> Result<(), ExitCode> {
    // The bootstrap below names no architecture, so it targets the host's, and
    // the restrictions in the control file are evaluated against that.
    let architecture = provision::debian::host_architecture();
    let declared = std::fs::read_to_string(control)
        .map(|text| provision::debian::build_depend_names(&text, &architecture))
        .unwrap_or_default();

    let mut builder = Debian::builder(&config.suite)
        .include(BASE_TOOLING)
        .include(declared)
        .include(config.build_deps.clone());
    if let Some(cache) = &config.cache {
        builder = builder.cache_dir(cache);
    }

    let mut debian = builder.build().map_err(|error| {
        failure(
            "deb-build",
            &format!(
                "cannot configure the bootstrap: {}",
                ErrorChain::new(&error)
            ),
        )
    })?;
    let mut progress = print_progress;
    match provision::ensure(&config.rootfs, &mut debian.observe(&mut progress)) {
        Ok(Provisioned::Created) => {
            eprintln!("deb-build: provisioned {}", config.rootfs.display());
            Ok(())
        }
        // A published root is reused silently, so the flags stay in an
        // invocation permanently at no cost after the first run.
        Ok(_) => Ok(()),
        Err(error) => Err(failure(
            "deb-build",
            &format!(
                "cannot provision the build root: {}",
                ErrorChain::new(&error)
            ),
        )),
    }
}

/// Prints a Debian bootstrap progress event to stderr.
fn print_progress(event: DebianEvent<'_>) {
    use std::io::Write;
    // Two levels of openness, and each needs its own escape: the `_` arm
    // absorbs a future variant, and the `..` in every struct arm absorbs a
    // future field within a variant already matched here.
    match event {
        DebianEvent::Fetching { url, .. } => eprintln!("deb-build: fetching {url}"),
        DebianEvent::Resolving => eprintln!("deb-build: resolving the package set"),
        DebianEvent::Unsatisfiable {
            requirement,
            required_by,
            reason,
            ..
        } => eprintln!("deb-build: {required_by} requires {requirement}, and {reason}"),
        DebianEvent::Conflict {
            relation,
            stated_by,
            against,
            ..
        } => eprintln!("deb-build: {stated_by} states {relation}, against {against}"),
        DebianEvent::Downloading {
            package,
            index,
            total,
            ..
        } => eprintln!("deb-build: downloading {package} ({index}/{total})"),
        DebianEvent::Extracting { package, .. } => eprintln!("deb-build: extracting {package}"),
        // dpkg's own output during configuration flows straight to stderr.
        DebianEvent::CommandOutput { bytes, .. } => {
            let _ = std::io::stderr().write_all(bytes);
        }
        _ => {}
    }
}

/// Lists the packages collected into the output directory after a build.
fn report_artifacts(output: &Path) {
    let mut debs: Vec<PathBuf> = match std::fs::read_dir(output) {
        Ok(entries) => entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                let ext = path.extension().and_then(OsStr::to_str);
                matches!(ext, Some("deb") | Some("ddeb"))
            })
            .collect(),
        Err(_) => return,
    };
    debs.sort();
    for deb in debs {
        if let Some(name) = deb.file_name() {
            println!("deb-build: built {}", Path::new(name).display());
        }
    }
}

/// Explains a build failure, pointing at the fix for the configuration errors
/// an invocation most often omits.
fn report_build_error(error: &Error) {
    match error {
        Error::Config(ConfigError::RootfsMissing) => {
            eprintln!("deb-build: no build root; pass --rootfs DIR")
        }
        Error::Config(ConfigError::RootfsUnusable { path, .. }) => eprintln!(
            "deb-build: build root {} is unusable; it is provisioned on the first run",
            path.display()
        ),
        other => eprintln!("deb-build: {}", ErrorChain::new(other)),
    }
}
