//! A foreign-architecture build-and-test sandbox built on ferroday-cage.
//!
//! `cross-arch-test` bootstraps a Debian root filesystem for an architecture
//! the host cannot execute, then compiles and runs a C program inside it. Every
//! binary involved after the bootstrap is a foreign one: the compiler, the
//! linker, and the program they produce all run through the host's `qemu-user`
//! binfmt handler.
//!
//! ```sh
//! cross-arch-test --rootfs ./trixie-arm64 --cache ./deb-cache
//! ```
//!
//! It is the demonstration of the one host mode the library claims and the
//! other examples do not exercise: [`deb-build`](../deb-build) builds a package
//! for the host's own architecture, where nothing is emulated and no
//! interpreter is involved.
//!
//! # What it proves
//!
//! That the whole path holds with a foreign binary at the end of it. The
//! provisioner already takes an architecture, checks for a handler, and offers
//! extract-only where target binaries cannot run at all; what this exercises is
//! everything above the provisioner — the cage, the identity map, the mounts,
//! and optionally the hardening layer — with a command the host CPU cannot
//! execute.
//!
//! The default task compiles a program that reports what it was built for and
//! checks it against what was asked for. A compiler that silently produced host
//! binaries, or a handler that quietly failed over to one, would pass a test
//! that only checked the program ran; this one fails, because the program
//! itself asserts its own architecture, pointer width and endianness.
//!
//! # Hardening under emulation
//!
//! `--harden` applies the curated seccomp policy, and what it filters is worth
//! understanding before reading a failure.
//!
//! A seccomp filter gates on the audit architecture of the task making the
//! syscall. Under `qemu-user` that task is qemu itself — a native binary — so
//! the syscalls reaching the kernel are the *host's*, issued by the emulator on
//! the guest's behalf. The filter therefore applies correctly, with no
//! translation and nothing architecture-specific to get wrong.
//!
//! What changes is the set of syscalls a given workload makes. An emulator maps
//! the guest's address space, keeps its own threads, and translates guest calls
//! into host ones that need not correspond one to one, so a filter narrow enough
//! for a native workload can be too narrow for the same workload emulated.
//!
//! The curated policy turns out to be wide enough for this one: `--harden`
//! compiles and runs the probe under it unchanged. It stays a flag because the
//! caveat holds for a caller-authored allowlist, which is narrow by construction
//! and was written against whatever the workload did natively.
//!
//! # Usage
//!
//! ```text
//! cross-arch-test [OPTIONS] --rootfs DIR
//! cross-arch-test [OPTIONS] --rootfs DIR -- COMMAND [ARGS...]
//! ```
//!
//! With no trailing command the sandbox compiles and runs the built-in probe.
//! With a command after `--` it runs that instead, in the same foreign root.
//! The command path is interpreted inside the sandbox and must be absolute.
//!
//! # Requirements
//!
//! A registered `qemu-user` binfmt handler for the target architecture, with
//! the fix-binary (`F`) flag. On Debian and Ubuntu that is the
//! `qemu-user-static` and `binfmt-support` packages. The sandbox reports
//! exactly what is missing before it provisions anything.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use ferroday_cage::provision::debian::{Debian, DebianEvent, foreign_interpreter};
use ferroday_cage::provision::{self, Provisioned};
use ferroday_cage::{Cage, ConfigError, Error, ErrorChain, Network, SeccompPolicy, SeccompRules};

mod common;

use common::{failure, flag_value, into_string, string_value, usage_error, value_for};

/// The suite bootstrapped when `--suite` is not given.
const DEFAULT_SUITE: &str = "trixie";
/// The architecture bootstrapped when `--architecture` is not given. arm64 is
/// the one a `qemu-user` installation is most likely to already cover.
const DEFAULT_ARCHITECTURE: &str = "arm64";
/// The toolchain the probe needs: a C compiler, a linker, and `readelf`.
const TOOLING: [&str; 2] = ["build-essential", "binutils"];
/// The shell that drives the default task, addressed by absolute path: the cage
/// does not resolve the command against `PATH`.
const SHELL: &str = "/bin/sh";

/// The probe compiled and run inside the foreign root.
///
/// It asserts what it was *built* for rather than reporting what it observes,
/// which is the distinction that makes it a test. The macros are the compiler's
/// own view of its target, so a toolchain that silently produced host binaries
/// fails to compile this rather than running and printing something reassuring.
const PROBE_SOURCE: &str = r#"#include <stdint.h>
#include <stdio.h>

#if defined(__aarch64__)
#  define TARGET "arm64"
#elif defined(__x86_64__)
#  define TARGET "amd64"
#elif defined(__riscv) && __riscv_xlen == 64
#  define TARGET "riscv64"
#elif defined(__s390x__)
#  define TARGET "s390x"
#elif defined(__powerpc64__)
#  define TARGET "ppc64el"
#elif defined(__arm__)
#  define TARGET "armhf"
#elif defined(__i386__)
#  define TARGET "i386"
#else
#  error "the probe does not know this architecture"
#endif

/* Real work, not a constant the compiler can fold away to a printf: a CRC32
   over a table the program fills in at runtime. The expected value is the same
   on every architecture -- verified equal between an emulated arm64 build and a
   native x86_64 one -- so a wrong answer means arithmetic went wrong rather than
   that the target differs. */
static uint32_t checksum(void) {
    uint32_t table[256];
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int bit = 0; bit < 8; bit++) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        table[i] = c;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (const char *p = "ferroday-cage"; *p; p++) {
        crc = table[(crc ^ (unsigned char)*p) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

int main(void) {
    int failures = 0;
    const uint32_t union_probe = 1;
    const int little_endian = *(const unsigned char *)&union_probe == 1;

    printf("probe: built for %s, %zu-bit pointers, %s-endian\n",
           TARGET, sizeof(void *) * 8, little_endian ? "little" : "big");

    if (sizeof(void *) * 8 != POINTER_BITS) {
        printf("probe: FAIL pointer width is %zu, expected %d\n",
               sizeof(void *) * 8, POINTER_BITS);
        failures++;
    }
    const uint32_t got = checksum();
    if (got != 0xDD45671Au) {
        printf("probe: FAIL checksum is 0x%08X, expected 0xDD45671A\n", got);
        failures++;
    }
    printf("probe: %s\n", failures ? "FAILED" : "all checks passed");
    return failures ? 1 : 0;
}
"#;

const USAGE: &str = "\
Build and run a C program for a foreign architecture, under emulation.

Usage:
  cross-arch-test [OPTIONS] --rootfs DIR
  cross-arch-test [OPTIONS] --rootfs DIR -- COMMAND [ARGS...]

Root filesystem:
  --architecture ARCH   Bootstrap this Debian architecture (default: arm64);
                        ignored once the root exists
  --suite SUITE         Bootstrap this Debian suite (default: trixie); ignored
                        once the root exists
  --rootfs DIR          The provisioned root (required); provisioned on the
                        first run, reused thereafter
  --cache DIR           Cache downloaded packages here, content-addressed and
                        reused across bootstraps

Running:
  --harden              Apply the curated seccomp policy to the command. Off
                        by default: an emulator makes syscalls of its own, so a
                        filter narrow enough for a native workload can be too
                        narrow for the same workload emulated
  --network             Share the host network with the command; by default it
                        runs with an isolated network. Provisioning always
                        fetches from the archive over the host network

  -h, --help            Print this help
  -V, --version         Print the version

With no trailing command the sandbox compiles the built-in probe with the
foreign toolchain and runs it; with a command after --, it runs that instead.
The command's exit code is the sandbox's exit code, or 128 plus the signal
number when it is terminated by a signal; 125 announces a sandbox that could
not be provisioned, built, or launched, 126 a command that cannot be executed,
127 a command that does not exist, and 2 a usage error.
";

/// A parsed command line.
enum Invocation {
    Help,
    Version,
    Run(Config),
}

/// A resolved `run` configuration.
struct Config {
    architecture: String,
    suite: String,
    rootfs: PathBuf,
    cache: Option<PathBuf>,
    harden: bool,
    network: bool,
    task: Task,
}

/// What to run inside the sandbox.
enum Task {
    /// Compile and run the built-in probe.
    Probe,
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
            println!("cross-arch-test {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(config)) => run(config),
        Err(message) => usage_error("cross-arch-test", &message),
    }
}

/// Parses the command line, excluding the program name.
fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let mut architecture = None;
    let mut suite = None;
    let mut rootfs = None;
    let mut cache = None;
    let mut harden = false;
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
        } else if arg == "--architecture" {
            architecture = Some(string_value("--architecture", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--architecture=") {
            architecture = Some(into_string("--architecture", value)?);
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
        } else if arg == "--harden" {
            harden = true;
        } else if arg == "--network" {
            network = true;
        } else {
            return Err(format!("unrecognized argument {}", arg.to_string_lossy()));
        }
    }

    let task = match command_line {
        Some(argv) if argv.is_empty() => return Err("-- was given with no command".to_string()),
        Some(argv) => Task::Command(argv),
        None => Task::Probe,
    };
    Ok(Invocation::Run(Config {
        architecture: architecture.unwrap_or_else(|| DEFAULT_ARCHITECTURE.to_string()),
        suite: suite.unwrap_or_else(|| DEFAULT_SUITE.to_string()),
        rootfs: rootfs.ok_or("--rootfs DIR is required")?,
        cache,
        harden,
        network,
        task,
    }))
}

/// Provisions the foreign root if it is absent, then runs the task in it.
fn run(config: Config) -> ExitCode {
    if let Err(code) = report_interpreter(&config.architecture) {
        return code;
    }
    if let Err(code) = provision(&config) {
        return code;
    }

    let mut builder = Cage::builder()
        .rootfs(&config.rootfs)
        .network(if config.network {
            Network::Host
        } else {
            Network::Isolated
        });
    if config.harden {
        builder = builder.seccomp(SeccompPolicy::Rules(SeccompRules::curated()));
    }
    builder = match &config.task {
        Task::Probe => {
            builder
                .command(SHELL)
                .args(["-e", "-u", "-c", &probe_script(&config.architecture)])
        }
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
        Ok(status) => ExitCode::from(status.shell_code()),
        Err(error) => {
            eprintln!("cross-arch-test: {}", ErrorChain::new(&error));
            ExitCode::from(error.shell_code())
        }
    }
}

/// Reports the interpreter the command will run through, and refuses to go on
/// where it cannot run at all.
///
/// The three refusals are three different problems with three different fixes,
/// so they are told apart rather than collapsed into one message. The
/// provisioner's own preflight refuses the same hosts before it downloads
/// anything, but only when it bootstraps. This runs on every launch, because a
/// root that already exists is reused as it stands and its command needs the
/// handler all the same. It also refuses a host that runs the architecture
/// natively, where the example would demonstrate nothing.
fn report_interpreter(architecture: &str) -> Result<(), ExitCode> {
    let Some(interpreter) = foreign_interpreter(architecture) else {
        // Either the host runs this architecture natively, in which case the
        // example demonstrates nothing, or no handler is registered for it.
        let host = provision::debian::host_architecture();
        let reason = if host == architecture {
            format!(
                "{architecture} is this host's own architecture, so nothing here would be \
                 emulated; pass --architecture with a foreign one"
            )
        } else {
            format!(
                "no qemu-user binfmt handler is registered for {architecture}; install \
                 qemu-user-static and binfmt-support"
            )
        };
        return Err(failure("cross-arch-test", &reason));
    };
    if !interpreter.enabled {
        return Err(failure(
            "cross-arch-test",
            &format!(
                "the qemu-{} binfmt handler is registered but disabled; enable it by writing 1 \
                 to /proc/sys/fs/binfmt_misc/qemu-{}",
                interpreter.name, interpreter.name,
            ),
        ));
    }
    // The fix-binary flag makes the kernel hold the interpreter open from
    // registration, which is what keeps it working after the cage pivots into a
    // root where the interpreter's own path does not exist.
    if !interpreter.flags.contains('F') {
        return Err(failure(
            "cross-arch-test",
            &format!(
                "the qemu-{} binfmt handler lacks the fix-binary (F) flag, and its flags are \
                 {:?}; without F the interpreter is looked up inside the sandbox root, where it \
                 does not exist",
                interpreter.name, interpreter.flags,
            ),
        ));
    }
    eprintln!(
        "cross-arch-test: {architecture} runs through {} (flags {})",
        interpreter.path.display(),
        interpreter.flags,
    );
    Ok(())
}

/// The shell script that writes the probe, compiles it, and runs it.
///
/// `readelf` reads the machine out of the ELF header of what the compiler
/// actually produced, which is the check the probe itself cannot make: a
/// program that runs and prints its own architecture has already been executed,
/// and the point is to see what was built before trusting what it says.
fn probe_script(architecture: &str) -> String {
    let bits = if matches!(architecture, "i386" | "armhf") {
        32
    } else {
        64
    };
    format!(
        r#"mkdir -p /build
cd /build
echo "uname -m inside the cage: $(uname -m)"
cat > probe.c <<'PROBE_EOF'
{PROBE_SOURCE}
PROBE_EOF
cc -O2 -DPOINTER_BITS={bits} -o probe probe.c
readelf -h probe | sed -n 's/^ *Machine: */readelf: machine is /p'
./probe
"#
    )
}

/// Bootstraps the foreign root. An already-provisioned root is reused as it
/// stands.
fn provision(config: &Config) -> Result<(), ExitCode> {
    let mut builder = Debian::builder(&config.suite)
        .architecture(&config.architecture)
        .include(TOOLING);
    if let Some(cache) = &config.cache {
        builder = builder.cache_dir(cache);
    }
    let mut debian = builder.build().map_err(|error| {
        failure(
            "cross-arch-test",
            &format!(
                "cannot configure the bootstrap: {}",
                ErrorChain::new(&error)
            ),
        )
    })?;
    let mut progress = print_progress;
    match provision::ensure(&config.rootfs, &mut debian.observe(&mut progress)) {
        Ok(Provisioned::Created) => {
            eprintln!(
                "cross-arch-test: provisioned {} for {}",
                config.rootfs.display(),
                config.architecture,
            );
            Ok(())
        }
        // A published root is reused silently, so the flags stay in an
        // invocation permanently at no cost after the first run.
        Ok(_) => Ok(()),
        Err(error) => Err(failure(
            "cross-arch-test",
            &format!("cannot provision the root: {}", ErrorChain::new(&error)),
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
        DebianEvent::Fetching { url, .. } => eprintln!("cross-arch-test: fetching {url}"),
        DebianEvent::Resolving => eprintln!("cross-arch-test: resolving the package set"),
        DebianEvent::Unsatisfiable {
            requirement,
            required_by,
            reason,
            ..
        } => eprintln!("cross-arch-test: {required_by} requires {requirement}, and {reason}"),
        DebianEvent::Conflict {
            relation,
            stated_by,
            against,
            ..
        } => eprintln!("cross-arch-test: {stated_by} states {relation}, against {against}"),
        DebianEvent::Downloading {
            package,
            index,
            total,
            ..
        } => eprintln!("cross-arch-test: downloading {package} ({index}/{total})"),
        DebianEvent::Extracting { package, .. } => {
            eprintln!("cross-arch-test: extracting {package}")
        }
        // dpkg's own output during configuration flows straight to stderr. Under
        // emulation this is where the handler first proves itself: every one of
        // those processes is a foreign binary.
        DebianEvent::CommandOutput { bytes, .. } => {
            let _ = std::io::stderr().write_all(bytes);
        }
        _ => {}
    }
}

/// Explains a build failure, pointing at the fix for the configuration errors
/// an invocation most often omits.
fn report_build_error(error: &Error) {
    match error {
        Error::Config(ConfigError::RootfsMissing) => {
            eprintln!("cross-arch-test: no root; pass --rootfs DIR")
        }
        Error::Config(ConfigError::RootfsUnusable { path, .. }) => eprintln!(
            "cross-arch-test: root {} is unusable; it is provisioned on the first run",
            path.display()
        ),
        other => eprintln!("cross-arch-test: {}", ErrorChain::new(other)),
    }
}
