//! A Gentoo binary-package sandbox built on ferroday-cage.
//!
//! `gentoo-binhost` provisions a Gentoo root filesystem from a signed stage3
//! and installs prebuilt packages into it from the archive's binary-package
//! host, then runs a command in a cage over the result. It is the worked
//! consumer of the binhost surface, as `ebuild-sandbox` is of the stage3 one:
//! where that example builds packages from source with `emerge`, this one
//! installs them already built.
//!
//! ```sh
//! gentoo-binhost --rootfs ./gentoo --cache ./gentoo-cache \
//!     --install dev-vcs/git -- git --version
//! ```
//!
//! # Resolution starts from the root, not from the archive
//!
//! This is the difference from every other package resolution in the library,
//! and it is not a detail. A stage3 unpacks with 296 packages already installed
//! and a database describing them, so the resolver asks what is *missing*
//! rather than what is needed — and one of those 296, `app-crypt/pinentry`, the
//! binhost publishes in no version at all. Ask for `dev-vcs/git` against a real
//! stage3 and a dozen packages arrive; ask against an empty root and the
//! request fails on a dependency the root would have answered.
//!
//! That is why `--plan` takes the root it would install into. There is no
//! meaningful answer without one.
//!
//! # A constraint and a preference are different things
//!
//! The archive publishes a version more than once — up to twenty-four times —
//! and the builds differ in the USE flags they were compiled with, and so in
//! what they pull in. `dev-vcs/git` has a build without `keyring` that needs a
//! dozen packages and one with it that needs seventy.
//!
//! - `--install 'dev-vcs/git[keyring]'` is a **constraint**: it removes every
//!   build without the flag, and if the archive publishes none the request
//!   fails and says so.
//! - `--prefer-use keyring` is a **preference**: it reorders the candidates and
//!   removes none, so it can never turn a resolvable request into an
//!   unresolvable one.
//!
//! State a flag the install must have the first way and a flag you would rather
//! it had the second.
//!
//! # What is installed and what is not
//!
//! Files are merged and a database entry is registered, so portage inside the
//! finished sandbox sees the packages as installed and will not rebuild them.
//! Their *phase functions* are not run: a `pkg_postinst` is a bash function
//! that needs portage's own `ebuild.sh`, so an `acct-user` package's account is
//! not created and `ca-certificates` does not regenerate its bundle. A caller
//! who needs them has a root portage can act on, which is what registering the
//! entry properly buys.
//!
//! # Usage
//!
//! ```text
//! gentoo-binhost [OPTIONS] --rootfs DIR
//! gentoo-binhost [OPTIONS] --rootfs DIR -- COMMAND [ARGS...]
//! ```
//!
//! With no trailing command the sandbox provisions the root and exits, printing
//! whether it was created or reused; an already-provisioned root is reused as
//! it stands. With `--plan` it resolves against `--rootfs` and prints the plan
//! document, fetching the index but downloading no package and merging nothing.
//! A trailing command that is a bare name, such as `git`, is looked up on the
//! sandbox's `PATH`, as a shell would.
//!
//! # Resolve now, replay later
//!
//! `--plan` and `--plan-file` are the two halves of the plan format's whole
//! argument, and this example has both so the round trip can be run:
//!
//! ```sh
//! gentoo-binhost --rootfs ./gentoo --install dev-vcs/git --plan > binhost.plan
//! gentoo-binhost --rootfs ./elsewhere --plan-file binhost.plan -- git --version
//! ```
//!
//! A plan carries the build id, path, size and MD5 of every package, what the
//! index stated about each build, and the order they merge in, so the replay
//! fetches no index and makes no choice. The binhost keeps a published version
//! far longer than the five weeks the stage3 autobuilds tree keeps a build, so a
//! plan replays for as long as the archive carries what it names and the key
//! that signs its containers is in force.
//!
//! A replay is held to the root it lands in, which is normally newer than the
//! one the plan was resolved against. A package the root already has at the
//! planned version is skipped, and one whose slot the root already holds
//! refuses the run before anything is merged. `--install` and `--prefer-use`
//! describe a resolution, so neither is accepted beside `--plan-file`.
//!
//! ```text
//! --rootfs DIR         Where the root filesystem lives (required)
//! --arch ARCH          Architecture to provision (default: amd64)
//! --variant NAME       stage3 variant (default: amd64-openrc)
//! --binhost SUBARCH    Binary-package tree (default: x86-64)
//! --install ATOM       Install ATOM and its runtime dependencies; repeatable
//! --prefer-use FLAGS   Prefer builds with these space-separated USE flags,
//!                      and without the ones written -flag; repeatable
//! --cache DIR          Keep the stage3 and the packages here across runs
//! --plan               Resolve against --rootfs, print the plan, and exit
//! --plan-file FILE     Install what this plan names, resolving nothing
//! --help               Print this help and exit
//! ```

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ferroday_cage::provision::gentoo::{Gentoo, GentooEvent, Plan};
use ferroday_cage::provision::{Provision, ProvisionEvent};
use ferroday_cage::{Cage, CageBuilder, Error, ErrorChain};

mod common;
use common::{failure, flag_value, into_string, string_value, usage_error, value_for};

/// The program name in diagnostics and usage.
const PROGRAM: &str = "gentoo-binhost";

/// The architecture provisioned when the caller names none.
const DEFAULT_ARCH: &str = "amd64";

/// The stage3 variant installed when the caller names none.
const DEFAULT_VARIANT: &str = "amd64-openrc";

/// The binary-package tree read when the caller names none.
///
/// A default is safe here where the library offers none, because this example
/// also defaults the architecture: `x86-64` is the tree that goes with
/// `amd64`, and a caller changing one is expected to change the other.
const DEFAULT_BINHOST: &str = "x86-64";

fn main() -> ExitCode {
    let options = match parse(std::env::args_os().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => return ExitCode::SUCCESS,
        Err(message) => return usage_error(PROGRAM, &message),
    };
    match run(options) {
        Ok(code) => code,
        Err(message) => failure(PROGRAM, &message),
    }
}

/// Everything the example configures.
struct Options {
    rootfs: PathBuf,
    architecture: String,
    variant: String,
    binhost: String,
    install: Vec<String>,
    prefer_use: Vec<String>,
    cache: Option<PathBuf>,
    /// Resolve and print, installing nothing.
    plan_only: bool,
    /// A plan document to install, where one was named. The atoms and the
    /// preferences describe a resolution, so neither is given beside one.
    plan_file: Option<PathBuf>,
    /// The command to run in the finished sandbox, where one was given.
    command: Vec<OsString>,
}

/// Parses the command line, or `None` where `--help` answered it.
fn parse(args: impl Iterator<Item = OsString>) -> Result<Option<Options>, String> {
    let mut rootfs: Option<PathBuf> = None;
    let mut architecture = DEFAULT_ARCH.to_string();
    let mut variant = DEFAULT_VARIANT.to_string();
    let mut binhost = DEFAULT_BINHOST.to_string();
    let mut install: Vec<String> = Vec::new();
    let mut prefer_use: Vec<String> = Vec::new();
    let mut cache: Option<PathBuf> = None;
    let mut plan_only = false;
    let mut plan_file: Option<PathBuf> = None;
    let mut command: Vec<OsString> = Vec::new();
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        if arg == "--" {
            command.extend(args.by_ref());
            break;
        } else if arg == "--help" || arg == "-h" {
            print_help();
            return Ok(None);
        } else if arg == "--rootfs" {
            rootfs = Some(PathBuf::from(value_for("--rootfs", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--rootfs=") {
            rootfs = Some(PathBuf::from(value));
        } else if arg == "--arch" {
            architecture = string_value("--arch", &mut args)?;
        } else if let Some(value) = flag_value(&arg, b"--arch=") {
            architecture = into_string("--arch", value)?;
        } else if arg == "--variant" {
            variant = string_value("--variant", &mut args)?;
        } else if let Some(value) = flag_value(&arg, b"--variant=") {
            variant = into_string("--variant", value)?;
        } else if arg == "--binhost" {
            binhost = string_value("--binhost", &mut args)?;
        } else if let Some(value) = flag_value(&arg, b"--binhost=") {
            binhost = into_string("--binhost", value)?;
        } else if arg == "--install" {
            install.push(string_value("--install", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--install=") {
            install.push(into_string("--install", value)?);
        } else if arg == "--prefer-use" {
            prefer_use.extend(
                string_value("--prefer-use", &mut args)?
                    .split_ascii_whitespace()
                    .map(str::to_string),
            );
        } else if let Some(value) = flag_value(&arg, b"--prefer-use=") {
            prefer_use.extend(
                into_string("--prefer-use", value)?
                    .split_ascii_whitespace()
                    .map(str::to_string),
            );
        } else if arg == "--cache" {
            cache = Some(PathBuf::from(value_for("--cache", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--cache=") {
            cache = Some(PathBuf::from(value));
        } else if arg == "--plan" {
            plan_only = true;
        } else if arg == "--plan-file" {
            plan_file = Some(PathBuf::from(value_for("--plan-file", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--plan-file=") {
            plan_file = Some(PathBuf::from(value));
        } else {
            return Err(format!("unknown option {}", arg.to_string_lossy()));
        }
    }

    let Some(rootfs) = rootfs else {
        return Err("--rootfs is required".to_string());
    };
    if plan_only && plan_file.is_some() {
        return Err("--plan resolves and --plan-file replays; name one or the other".to_string());
    }
    // A plan is a resolution that already happened, so the flags that shape
    // one have nothing to shape beside it. The library refuses the pair too;
    // refusing it here makes it the usage error it is.
    if plan_file.is_some() && !(install.is_empty() && prefer_use.is_empty()) {
        return Err(
            "--plan-file replays a resolution, so --install and --prefer-use have nothing to \
             shape; name one or the other"
                .to_string(),
        );
    }
    Ok(Some(Options {
        rootfs,
        architecture,
        variant,
        binhost,
        install,
        prefer_use,
        cache,
        plan_only,
        plan_file,
        command,
    }))
}

/// Provisions the root and runs whatever was asked for in it.
fn run(options: Options) -> Result<ExitCode, String> {
    let mut builder = Gentoo::builder(&options.architecture)
        .variant(&options.variant)
        .binhost(&options.binhost)
        .install(&options.install)
        .prefer_use(&options.prefer_use);
    if let Some(path) = &options.plan_file {
        // The other half of `--plan`. A plan names every container and the
        // order they merge in, so a run given one fetches no index and makes no
        // choice -- and the builder's own architecture and binhost have to be
        // the ones it was resolved for, which `build()` checks.
        let document = std::fs::read_to_string(path)
            .map_err(|err| format!("reading {}: {}", path.display(), ErrorChain::new(&err)))?;
        builder = builder.plan(
            Plan::parse_document(&document).map_err(|err| ErrorChain::new(&err).to_string())?,
        );
    }
    if let Some(cache) = &options.cache {
        builder = builder.cache_dir(cache);
    }
    let mut gentoo = builder
        .build()
        .map_err(|error| ErrorChain::new(&error).to_string())?;

    // A plan is resolved against the root it would install into, for the reason
    // the module documentation gives: on this archive there is no meaningful
    // answer without one.
    if options.plan_only {
        let plan = gentoo
            .resolve_packages(&options.rootfs)
            .map_err(|error| ErrorChain::new(&error).to_string())?;
        print!(
            "{}",
            plan.to_document()
                .map_err(|error| ErrorChain::new(&error).to_string())?
        );
        return Ok(ExitCode::SUCCESS);
    }

    let mut progress = |event: ProvisionEvent<'_>| {
        if let ProvisionEvent::Gentoo(event) = event {
            report(event);
        }
    };
    let outcome = Provision::new(&options.rootfs)
        .observe(&mut progress)
        .run(&mut gentoo)
        .map_err(|error| ErrorChain::new(&error).to_string())?;
    eprintln!(
        "{PROGRAM}: the root at {} is {outcome:?}",
        options.rootfs.display()
    );

    let Some((program, arguments)) = options.command.split_first() else {
        return Ok(ExitCode::SUCCESS);
    };
    let status = sandbox(&options.rootfs, program, arguments)
        .build()
        .and_then(|cage| cage.run())
        .map_err(|error: Error| ErrorChain::new(&error).to_string())?;
    Ok(ExitCode::from(status.shell_code()))
}

/// The sandbox a trailing command runs in, over the root just provisioned.
///
/// Nothing beyond the cage's own namespaces and private root: what runs here
/// is whatever the caller asked for against a root they just provisioned, and
/// the boundary it needs is the one the cage already draws. A bare command
/// name is looked up on the `PATH` set here, so `-- git --version` works as it
/// does at a shell prompt.
fn sandbox(rootfs: &Path, program: &OsStr, arguments: &[OsString]) -> CageBuilder {
    Cage::builder()
        .rootfs(rootfs)
        .command(program)
        .args(arguments)
        .path_lookup(true)
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
}

/// Prints what a provisioning run is doing, one line per step.
fn report(event: &GentooEvent<'_>) {
    match event {
        GentooEvent::Resolved { stage3, .. } => eprintln!(
            "{PROGRAM}: stage3 {} build {}, vouched for by {}",
            stage3.variant(),
            stage3.build_id(),
            stage3.certificate(),
        ),
        GentooEvent::Index { builds, .. } => {
            eprintln!("{PROGRAM}: the binhost publishes {builds} builds");
        }
        // The count is what the root is *missing* rather than what was asked
        // for, which is the whole shape of this layer's resolution.
        GentooEvent::Planned {
            packages, bytes, ..
        } => eprintln!("{PROGRAM}: installing {packages} packages ({bytes} bytes)"),
        GentooEvent::Merging {
            package, version, ..
        } => eprintln!("{PROGRAM}: merging {package}-{version}"),
        // Reported before the run fails, so a caller sees every atom the
        // binhost cannot answer rather than the first.
        GentooEvent::Unsatisfiable {
            atom,
            wanted_by,
            reason,
            ..
        } => eprintln!("{PROGRAM}: {wanted_by} requires {atom}, and no build {reason}"),
        GentooEvent::Conflict {
            atom,
            stated_by,
            blocks,
            ..
        } => eprintln!("{PROGRAM}: {stated_by} blocks {blocks} with {atom}"),
        _ => {}
    }
}

/// Prints the usage block from this file's own documentation.
fn print_help() {
    println!(
        "\
Provision a Gentoo root from a stage3 and install binary packages into it.

Usage:
  {PROGRAM} [OPTIONS] --rootfs DIR
  {PROGRAM} [OPTIONS] --rootfs DIR -- COMMAND [ARGS...]

COMMAND runs in the provisioned root. A bare name is looked up on the
sandbox's PATH.

Options:
  --rootfs DIR         Where the root filesystem lives (required)
  --arch ARCH          Architecture to provision (default: {DEFAULT_ARCH})
  --variant NAME       stage3 variant (default: {DEFAULT_VARIANT})
  --binhost SUBARCH    Binary-package tree (default: {DEFAULT_BINHOST})
  --install ATOM       Install ATOM and its runtime dependencies; repeatable.
                       A USE dependency in the atom is a constraint:
                       'dev-vcs/git[keyring]' refuses a build without the flag
  --prefer-use FLAGS   Prefer builds with these space-separated USE flags, and
                       without the ones written -flag; repeatable. A
                       preference, not a constraint: it cannot make an atom
                       unsatisfiable
  --cache DIR          Keep the stage3 and the packages here across runs
  --plan               Resolve against --rootfs, print the plan, and exit
  --plan-file FILE     Install what this plan names, resolving nothing. A
                       package the root has at the planned version is skipped,
                       and one whose slot the root holds is refused. The other
                       half of --plan: a plan replays for as long as the
                       binhost carries what it names and its signing key is in
                       force. Not accepted with --install or --prefer-use
  --help               Print this help and exit",
    );
}

/// The command lines this file documents, held to what they claim as far as
/// the build: provisioning reaches a live archive, which a test does not.
#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a documented command line and builds the sandbox its trailing
    /// command runs in, over a root filesystem that exists.
    fn build(line: &[&str]) -> Result<Cage, Error> {
        let options = parse(line.iter().map(OsString::from))
            .expect("a documented command line parses")
            .expect("not a help request");
        let (program, arguments) = options
            .command
            .split_first()
            .expect("the documented line carries a command");
        sandbox(&std::env::temp_dir(), program, arguments).build()
    }

    #[test]
    fn the_documented_commands_build() {
        for line in [
            &[
                "--rootfs",
                "./gentoo",
                "--cache",
                "./gentoo-cache",
                "--install",
                "dev-vcs/git",
                "--",
                "git",
                "--version",
            ][..],
            &[
                "--rootfs",
                "./elsewhere",
                "--plan-file",
                "binhost.plan",
                "--",
                "git",
                "--version",
            ],
        ] {
            if let Err(error) = build(line) {
                panic!("{line:?}: {}", ErrorChain::new(&error));
            }
        }
    }

    #[test]
    fn a_plan_file_is_not_accepted_beside_what_shapes_a_resolution() {
        for (flag, value) in [("--install", "dev-vcs/git"), ("--prefer-use", "keyring")] {
            let line = [
                "--rootfs",
                "./elsewhere",
                "--plan-file",
                "binhost.plan",
                flag,
                value,
            ];
            let Err(refusal) = parse(line.iter().map(OsString::from)) else {
                panic!("{flag} beside --plan-file parsed");
            };
            assert!(refusal.contains(flag), "{refusal}");
        }
    }
}
