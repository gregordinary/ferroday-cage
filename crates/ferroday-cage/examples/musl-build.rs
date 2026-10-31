//! A statically linked C build sandbox built on ferroday-cage.
//!
//! `musl-build` bootstraps an Alpine root filesystem with the C toolchain, then
//! runs `make` inside a cage over a copy of a source tree and collects what it
//! produced. The host is left untouched: no compiler is installed on it, the
//! source tree is bound read-only and built from a copy, and only the finished
//! binaries are written back, into a directory the caller names.
//!
//! ```sh
//! musl-build --rootfs ./alpine-build --cache ./apk-cache \
//!     --source ./hello --output ./out
//! ```
//!
//! It is the Alpine counterpart of the Debian package-build example, and the
//! reason to reach for Alpine rather than Debian is what comes out: Alpine's
//! toolchain links against musl, whose static linking produces a binary that
//! runs on any Linux of the same architecture with no runtime at all. So the
//! example ends by reading each artifact's ELF program headers and reporting
//! whether it really is static, rather than asserting it.
//!
//! # The build environment is baked in
//!
//! The bootstrap installs `build-base` — Alpine's `gcc`, `musl-dev`, `make` and
//! `binutils` set, the counterpart of Debian's `build-essential` — and whatever
//! `--package` names beyond it. apk publishes no priority band, so nothing
//! arrives that was not asked for or required by something that was: a build
//! root here is exactly its `include` list closed over its dependencies, which
//! is why one is small enough to provision per project.
//!
//! Because the toolchain is baked into the root, adding a library means
//! provisioning a fresh `--rootfs`; an existing root is reused as it stands.
//!
//! # No hardening, and the identity map
//!
//! No [hardening](ferroday_cage) layer is applied. A build compiles code, writes
//! across a tree, and runs helper processes; the boundary it needs is the cage's
//! namespaces and private root, not a syscall filter over the top.
//!
//! The cage maps the calling user to root and nothing else, and both halves of
//! this are content with that. Every file of every package in an Alpine closure
//! is owned by root, so the bootstrap needs no ownership the map cannot
//! represent; and a `make` that compiles and links asks for no user at all. The
//! one call in the archive's own install scripts that wants another identity —
//! `alpine-baselayout` giving `/etc/shadow` to the `shadow` group — fails
//! harmlessly under this map, exactly as it does under `apk` itself.
//!
//! # Usage
//!
//! ```text
//! musl-build [OPTIONS] --rootfs DIR --source DIR --output DIR
//! musl-build [OPTIONS] --rootfs DIR --source DIR --output DIR -- COMMAND [ARGS...]
//! ```
//!
//! With no trailing command the sandbox copies the source tree to a writable
//! build directory, runs `make`, and collects the executables it left at the top
//! of that tree into `--output`. With a command after `--` it runs that instead,
//! in the same posture — a shell, say, for interactive work. The command path is
//! interpreted inside the sandbox and must be absolute.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ferroday_cage::provision::alpine::{Alpine, AlpineEvent};
use ferroday_cage::provision::{self, Provisioned};
use ferroday_cage::{Cage, ConfigError, Error, Network};

mod common;

use common::{failure, flag_value, into_string, string_value, usage_error, value_for};

/// The Alpine release bootstrapped when `--release` is not given.
const DEFAULT_RELEASE: &str = "v3.23";
/// Alpine's C toolchain meta-package, and a shell.
///
/// `build-base` is `gcc`, `musl-dev`, `make`, `binutils` and the rest of what a
/// source build expects to find — the counterpart of Debian's
/// `build-essential`. `busybox-binsh` is the package that ships `/bin/sh`, and
/// naming it is the whole of what "apk has no priority band" means in practice:
/// nothing in the toolchain's closure happens to require a shell, so a root that
/// did not ask for one would not have one, and the build script below would find
/// no interpreter. Debian would have installed a shell as an essential package
/// without being asked.
const BASE_TOOLING: [&str; 2] = ["build-base", "busybox-binsh"];
/// Where the host source tree is bound, read-only.
const SOURCE_DEST: &str = "/src";
/// Where the host output directory is bound, read-write.
const OUTPUT_DEST: &str = "/out";
/// The shell that drives the default build, addressed by absolute path: the
/// cage does not resolve the command against `PATH`.
const SHELL: &str = "/bin/sh";

/// The default build: copy the read-only source to a writable tree, `make` it,
/// and collect the executables into the output bind.
///
/// The copy keeps the host's tree pristine, since a build writes objects and
/// binaries throughout one. `LDFLAGS` is where `-static` belongs: it reaches the
/// link step, which is the one that decides whether the result carries an
/// interpreter, and leaves the compile steps alone. A project that sets its own
/// `LDFLAGS` in the makefile overrides this, which is the honest outcome — the
/// report at the end says what was actually produced.
const BUILD_SCRIPT: &str = r#"rm -rf /build
mkdir -p /build
cp -a /src /build/tree
cd /build/tree
make
find /build/tree -maxdepth 1 -type f -perm -u+x -exec cp -p {} /out/ \;
"#;

const USAGE: &str = "\
Build a C project against musl in an isolated sandbox.

Usage:
  musl-build [OPTIONS] --rootfs DIR --source DIR --output DIR
  musl-build [OPTIONS] --rootfs DIR --source DIR --output DIR -- COMMAND [ARGS...]

Root filesystem:
  --release REL         Bootstrap this Alpine release (default: v3.23); ignored
                        once the root exists
  --rootfs DIR          The provisioned build root (required); provisioned on
                        the first run, reused thereafter
  --cache DIR           Cache downloaded packages here, reused across bootstraps

Source and output:
  --source DIR          The source tree to build (required); it must contain a
                        Makefile, and is bound read-only
  --output DIR          Collect the built executables here (required); bound
                        read-write

Build environment:
  --package PKG         Install PKG into the build root (repeatable), beyond the
                        build-base toolchain -- a library's -dev package, say
  --network             Share the host network with the build; by default the
                        build runs with an isolated network. Provisioning always
                        fetches from the archive over the host network

  -h, --help            Print this help
  -V, --version         Print the version

With no trailing command the sandbox runs 'make' over a copy of the source and
collects the executables into --output, reporting for each whether it is
statically linked; with a command after --, it runs that instead. The command's
exit code is the sandbox's exit code, or 128 plus the signal number when it is
terminated by a signal; 125 announces a sandbox that could not be provisioned,
built, or launched, 126 a command that cannot be executed, 127 a command that
does not exist, and 2 a usage error.
";

/// A parsed command line.
enum Invocation {
    Help,
    Version,
    Run(Config),
}

/// A resolved `run` configuration.
struct Config {
    release: String,
    rootfs: PathBuf,
    cache: Option<PathBuf>,
    source: PathBuf,
    output: PathBuf,
    packages: Vec<String>,
    network: bool,
    task: Task,
}

/// What to run inside the sandbox.
enum Task {
    /// Build the bound source tree with `make`.
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
            println!("musl-build {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(config)) => run(config),
        Err(message) => usage_error("musl-build", &message),
    }
}

/// Parses the command line, excluding the program name.
fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let mut release = None;
    let mut rootfs = None;
    let mut cache = None;
    let mut source = None;
    let mut output = None;
    let mut packages = Vec::new();
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
        } else if arg == "--release" {
            release = Some(string_value("--release", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--release=") {
            release = Some(into_string("--release", value)?);
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
        } else if arg == "--package" {
            packages.push(string_value("--package", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--package=") {
            packages.push(into_string("--package", value)?);
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
        release: release.unwrap_or_else(|| DEFAULT_RELEASE.to_string()),
        rootfs,
        cache,
        source,
        output,
        packages,
        network,
        task,
    }))
}

/// Provisions the build root if needed, composes the sandbox, and launches it.
fn run(config: Config) -> ExitCode {
    // The default build runs `make`; fail early and clearly rather than letting
    // the shell report it from inside the cage.
    if matches!(config.task, Task::Build)
        && !["Makefile", "makefile", "GNUmakefile"]
            .iter()
            .any(|name| config.source.join(name).is_file())
    {
        return usage_error(
            "musl-build",
            &format!("{} contains no Makefile", config.source.display()),
        );
    }

    if let Err(code) = provision(&config) {
        return code;
    }

    let mut builder = Cage::builder()
        .rootfs(&config.rootfs)
        .bind_ro(&config.source, SOURCE_DEST)
        .bind(&config.output, OUTPUT_DEST)
        // The link step is what decides whether the result carries an ELF
        // interpreter, so this is where static linking is asked for.
        .env("LDFLAGS", "-static")
        .network(if config.network {
            Network::Host
        } else {
            Network::Isolated
        });
    builder = match &config.task {
        Task::Build => builder
            .command(SHELL)
            .args(["-e", "-u", "-c", BUILD_SCRIPT]),
        Task::Command(argv) => {
            let mut argv = argv.iter();
            let program = argv.next().expect("a command line is never empty here");
            builder.command(PathBuf::from(program)).args(argv)
        }
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
            eprintln!("musl-build: {error}");
            ExitCode::from(error.shell_code())
        }
    }
}

/// Bootstraps the build root, baking in the toolchain and any extra packages.
///
/// An already-provisioned root is reused as it stands, so its baked package set
/// is whatever the first run installed.
fn provision(config: &Config) -> Result<(), ExitCode> {
    let mut builder = Alpine::builder(&config.release)
        .include(BASE_TOOLING)
        .include(config.packages.clone());
    if let Some(cache) = &config.cache {
        builder = builder.cache_dir(cache);
    }

    let mut alpine = builder.build().map_err(|error| {
        failure(
            "musl-build",
            &format!("cannot configure the bootstrap: {error}"),
        )
    })?;
    let mut progress = print_progress;
    match provision::ensure(&config.rootfs, &mut alpine.observe(&mut progress)) {
        Ok(Provisioned::Created) => {
            eprintln!("musl-build: provisioned {}", config.rootfs.display());
            Ok(())
        }
        // A published root is reused silently, so the flags stay in an
        // invocation permanently at no cost after the first run.
        Ok(_) => Ok(()),
        Err(error) => Err(failure(
            "musl-build",
            &format!("cannot provision the build root: {error}"),
        )),
    }
}

/// Prints an Alpine bootstrap progress event to stderr.
fn print_progress(event: AlpineEvent<'_>) {
    use std::io::Write;
    // Two levels of openness, and each needs its own escape: the `_` arm
    // absorbs a future variant, and the `..` in every struct arm absorbs a
    // future field within a variant already matched here.
    match event {
        AlpineEvent::Fetching { url, .. } => eprintln!("musl-build: fetching {url}"),
        AlpineEvent::Resolving => eprintln!("musl-build: resolving the package set"),
        AlpineEvent::Downloading {
            package,
            index,
            total,
            ..
        } => eprintln!("musl-build: downloading {package} ({index}/{total})"),
        AlpineEvent::Extracting { package, .. } => eprintln!("musl-build: extracting {package}"),
        // An install script's own output flows straight to stderr.
        AlpineEvent::CommandOutput { bytes, .. } => {
            let _ = std::io::stderr().write_all(bytes);
        }
        _ => {}
    }
}

/// Lists what the build left in the output directory, and whether each artifact
/// is statically linked.
fn report_artifacts(output: &Path) {
    let mut built: Vec<PathBuf> = match std::fs::read_dir(output) {
        Ok(entries) => entries.flatten().map(|entry| entry.path()).collect(),
        Err(_) => return,
    };
    built.sort();
    for path in built {
        let Some(name) = path.file_name() else {
            continue;
        };
        let linkage = match interpreter(&path) {
            Ok(None) => "static".to_string(),
            Ok(Some(interpreter)) => format!("dynamic, needs {interpreter}"),
            // Not an ELF file at all, or unreadable: report it as built and say
            // nothing about linkage rather than guessing.
            Err(_) => "not an ELF executable".to_string(),
        };
        println!(
            "musl-build: built {} ({linkage})",
            Path::new(name).display()
        );
    }
}

/// The ELF interpreter `path` names, or `None` where it names none — which is
/// what a statically linked executable looks like.
///
/// This reads the program header table for a `PT_INTERP` entry rather than
/// running a tool inside the sandbox, because the question is about a file the
/// caller now owns on the host. It is also the whole of what "static" means
/// here: an executable with no interpreter is one the kernel maps and enters
/// directly, with no dynamic loader and so no shared libc to find at run time.
///
/// # Errors
///
/// Returns the reason where `path` cannot be read or is not a 64-bit
/// little-endian ELF file, which is every artifact this example is asked about
/// on the architectures Alpine builds for.
fn interpreter(path: &Path) -> Result<Option<String>, String> {
    /// The ELF header field offsets this reads, all from the 64-bit layout.
    const E_PHOFF: usize = 0x20;
    const E_PHENTSIZE: usize = 0x36;
    const E_PHNUM: usize = 0x38;
    /// The segment type that names an interpreter.
    const PT_INTERP: u32 = 3;

    let elf = std::fs::read(path).map_err(|err| err.to_string())?;
    let at = |offset: usize, width: usize| -> Result<u64, String> {
        let bytes = elf
            .get(offset..offset + width)
            .ok_or("the file ends inside its ELF header")?;
        let mut value = [0u8; 8];
        value[..width].copy_from_slice(bytes);
        Ok(u64::from_le_bytes(value))
    };

    if elf.get(..5) != Some(&[0x7f, b'E', b'L', b'F', 2]) || elf.get(5) != Some(&1) {
        return Err("not a 64-bit little-endian ELF file".to_string());
    }
    let table = at(E_PHOFF, 8)? as usize;
    let entry_size = at(E_PHENTSIZE, 2)? as usize;
    let entries = at(E_PHNUM, 2)? as usize;
    for entry in 0..entries {
        let header = table + entry * entry_size;
        if at(header, 4)? != u64::from(PT_INTERP) {
            continue;
        }
        // p_offset and p_filesz, the segment's extent in the file. The
        // interpreter is a NUL-terminated path stored there.
        let offset = at(header + 0x08, 8)? as usize;
        let size = at(header + 0x20, 8)? as usize;
        let segment = elf
            .get(offset..offset + size)
            .ok_or("the file ends inside its interpreter segment")?;
        let name = segment.split(|byte| *byte == 0).next().unwrap_or(segment);
        return Ok(Some(String::from_utf8_lossy(name).into_owned()));
    }
    Ok(None)
}

/// Explains a build failure, pointing at the fix for the configuration errors
/// an invocation most often omits.
fn report_build_error(error: &Error) {
    match error {
        Error::Config(ConfigError::RootfsMissing) => {
            eprintln!("musl-build: no build root; pass --rootfs DIR")
        }
        Error::Config(ConfigError::RootfsUnusable { path, .. }) => eprintln!(
            "musl-build: build root {} is unusable; it is provisioned on the first run",
            path.display()
        ),
        other => eprintln!("musl-build: {other}"),
    }
}
