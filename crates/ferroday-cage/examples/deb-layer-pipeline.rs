//! A layered, multi-component Debian build pipeline built on ferroday-cage.
//!
//! `deb-layer-pipeline` builds a sequence of Debian source packages against one
//! shared base, feeding each built package into the next build's resolution
//! through a local pool. It provisions the base — system plus build toolchain —
//! once, then for each component in turn stages only that component's build
//! dependencies as a disposable overlay layer over the base, builds it, and
//! publishes the result into a `dists/`-structured pool the later components
//! resolve against.
//!
//! ```sh
//! deb-layer-pipeline --base ./base-trixie --cache ./deb-cache --pool ./pool \
//!     --output ./out --component ./libgreet-1.0 --component ./greeter-1.0
//! ```
//!
//! It is the pipeline counterpart of the `deb-build` example: where that bakes
//! one build root and builds one package, this one reuses a single base across
//! many components and carries the inter-component edge — `greeter`
//! build-depending on the freshly built `libgreet` — through the pool rather
//! than the archive.
//!
//! # Why a layer, not a fresh bootstrap
//!
//! A build root is `base + toolchain + this component's build-dependencies`. The
//! first two are identical across every component; only the dependency set
//! differs. Rather than bootstrap the whole root per component, this provisions
//! the base once through [`provision::ensure`] and, per component, calls
//! [`Debian::stage_layer`] with a
//! [`base_layer`](ferroday_cage::provision::debian::DebianBuilder::base_layer)
//! set to that base. The layer resolves against the base's already-installed set,
//! so only the packages the base lacks are downloaded and installed, into a
//! throwaway overlay upper. The build then runs in a cage rooted on
//! [`overlay_rootfs`](ferroday_cage::CageBuilder::overlay_rootfs) — the pristine
//! base as the read-only lower, the increment as the writable upper — and the
//! layer's [`BuildLayer`](ferroday_cage::provision::BuildLayer) drop discards
//! the upper afterward. The base is never mutated and is ready for the next
//! component unchanged.
//!
//! # The feed-forward pool
//!
//! Before the first component, an empty pool is published with
//! [`Pool`], which the resolver accepts as a valid (if empty)
//! repository. Each component's layer declares that pool as a trusted `file://`
//! [`repository`](ferroday_cage::provision::debian::DebianBuilder::repository),
//! so a component that build-depends on an earlier one resolves it from the pool.
//! After a component builds, its `.deb`s are published into the pool, growing the
//! set the next component sees. The components must be given in dependency order.
//!
//! # Usage
//!
//! ```text
//! deb-layer-pipeline [OPTIONS] --base DIR --pool DIR --output DIR \
//!     --component DIR [--component DIR ...]
//! ```
//!
//! Each `--component` names an unpacked Debian source tree (one containing a
//! `debian/` directory); they are built in the order given. A component's build
//! dependencies are read from its `debian/control` and resolved against the
//! archive plus the pool. The build runs `dpkg-buildpackage -us -uc -b` with an
//! isolated network, exactly as `deb-build` does.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ferroday_cage::provision::debian::{
    Debian, DebianEvent, Pool, Repository, build_depend_names, host_architecture,
};
use ferroday_cage::provision::{self, Provisioned};
use ferroday_cage::{Cage, Network};

mod common;

use common::{flag_value, into_string, string_value, value_for};

/// The suite bootstrapped when `--suite` is not given.
const DEFAULT_SUITE: &str = "trixie";
/// The generic Debian build toolchain, baked into the shared base.
const BASE_TOOLING: [&str; 3] = ["build-essential", "dpkg-dev", "fakeroot"];
/// The pool component the built packages are published under.
const POOL_COMPONENT: &str = "main";
/// The local pool the pipeline publishes each component's packages into, and
/// which every later component resolves against.
fn pool(config: &Config) -> Pool {
    Pool::at(&config.pool)
        .suite(&config.suite)
        .component(POOL_COMPONENT)
        .architecture(&config.arch)
}

/// Where a component's source tree is bound, read-only.
const SOURCE_DEST: &str = "/src";
/// Where a component's output directory is bound, read-write.
const OUTPUT_DEST: &str = "/out";
/// The shell that drives each build, addressed by absolute path.
const SHELL: &str = "/bin/sh";

/// The per-component build: copy the read-only source to a writable tree in the
/// overlay upper, build a binary package, and collect the artifacts into the
/// output bind. Identical in shape to `deb-build`'s, but the writable tree lives
/// in the overlay upper, discarded with the layer once the artifacts are copied
/// out.
const BUILD_SCRIPT: &str = r#"rm -rf /build
mkdir -p /build
cp -a /src /build/tree
cd /build/tree
dpkg-buildpackage -us -uc -b
find /build -maxdepth 1 -type f \( -name '*.deb' -o -name '*.ddeb' \) -exec cp -p {} /out/ \;
"#;

const USAGE: &str = "\
Build a sequence of Debian source packages against one shared base, feeding each
into the next through a local pool.

Usage:
  deb-layer-pipeline [OPTIONS] --base DIR --pool DIR --output DIR \\
      --component DIR [--component DIR ...]

Base and pool:
  --suite SUITE         Bootstrap this Debian suite (default: trixie); ignored
                        once the base exists
  --base DIR            The shared base build root (required); provisioned with
                        the toolchain on the first run, reused thereafter
  --pool DIR            The feed-forward package pool (required); created empty
                        and grown as each component publishes into it
  --cache DIR           Cache downloaded packages here, shared by the base
                        bootstrap and every layer
  --arch ARCH           The Debian architecture of the pool (default: the host)

Components:
  --component DIR       An unpacked Debian source tree to build (repeatable);
                        built in the order given, each resolved against the
                        archive plus the pool so far
  --output DIR          Collect every component's built packages here (required),
                        under a per-component subdirectory
  --network             Share the host network with each build; by default a
                        build runs with an isolated network

  -h, --help            Print this help
  -V, --version         Print the version

Each build runs 'dpkg-buildpackage -us -uc -b' over a copy of the component's
source. The process exits 0 when every component builds, 1 when a build fails,
and 2 on a usage error.
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
    base: PathBuf,
    pool: PathBuf,
    cache: Option<PathBuf>,
    arch: String,
    components: Vec<PathBuf>,
    output: PathBuf,
    network: bool,
}

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Invocation::Version) => {
            println!("deb-layer-pipeline {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(config)) => match run(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("deb-layer-pipeline: {message}");
                ExitCode::FAILURE
            }
        },
        Err(message) => {
            eprintln!("deb-layer-pipeline: {message}");
            eprintln!("Try 'deb-layer-pipeline --help' for usage.");
            ExitCode::from(2)
        }
    }
}

/// Provisions the base, seeds the pool, and builds each component in order.
fn run(config: Config) -> Result<(), String> {
    for component in &config.components {
        if !component.join("debian/control").is_file() {
            return Err(format!(
                "{} is not a Debian source tree: no debian/control",
                component.display()
            ));
        }
    }

    provision_base(&config)?;

    // Seed an empty but valid pool up front, so the first component's layer can
    // declare it as a repository before anything has been published into it.
    pool(&config)
        .publish::<&Path>([])
        .map_err(|error| format!("cannot create the pool: {error}"))?;

    for (at, component) in config.components.iter().enumerate() {
        build_component(&config, at, component)?;
    }
    Ok(())
}

/// Provisions the shared base with the build toolchain, if it does not already
/// exist. An existing base is reused as it stands.
fn provision_base(config: &Config) -> Result<(), String> {
    let mut builder = Debian::builder(&config.suite)
        .architecture(&config.arch)
        .include(BASE_TOOLING);
    if let Some(cache) = &config.cache {
        builder = builder.cache_dir(cache);
    }
    let mut debian = builder
        .build()
        .map_err(|error| format!("cannot configure the base bootstrap: {error}"))?;

    let mut progress = print_progress;
    match provision::ensure(&config.base, &mut debian.observe(&mut progress)) {
        Ok(Provisioned::Created) => {
            eprintln!(
                "deb-layer-pipeline: provisioned base {}",
                config.base.display()
            );
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(error) => Err(format!("cannot provision the base: {error}")),
    }
}

/// Stages one component's build dependencies as a layer over the base, builds
/// it, and publishes its packages into the pool.
///
/// `at` is the component's position on the command line, which is what keeps two
/// `--component` paths with the same last segment — `a/src` and `b/src` — from
/// sharing an output directory and a layer upper. The packages themselves are
/// pool-addressed and would not collide; the tree the run leaves behind would.
fn build_component(config: &Config, at: usize, source: &Path) -> Result<(), String> {
    let name = source
        .file_name()
        .map(|name| format!("{at:02}-{}", name.to_string_lossy()))
        .unwrap_or_else(|| format!("{at:02}-component"));
    eprintln!("deb-layer-pipeline: building {name}");

    // This component's declared build dependencies, resolved against the archive
    // plus the pool the earlier components have fed.
    let control = std::fs::read_to_string(source.join("debian/control"))
        .map_err(|error| format!("cannot read {name}'s debian/control: {error}"))?;
    let build_deps = build_depend_names(&control, &config.arch);

    let pool_repo = pool_repository(config)?;
    let upper = config.base.with_file_name(format!(".{name}.layer"));

    // Stage only the delta over the base into a disposable upper.
    let mut builder = Debian::builder(&config.suite)
        .architecture(&config.arch)
        .base_layer(&config.base)
        .include(build_deps)
        .repository(pool_repo);
    if let Some(cache) = &config.cache {
        builder = builder.cache_dir(cache);
    }
    let mut debian = builder
        .build()
        .map_err(|error| format!("cannot configure {name}'s layer: {error}"))?;
    let mut progress = print_progress;
    let layer = debian
        .observe(&mut progress)
        .stage_layer(&upper)
        .map_err(|error| format!("cannot stage {name}'s build root: {error}"))?;

    // Build against the merged base-plus-increment view. The output subdirectory
    // is where this component's packages land and, from there, are published.
    let out_dir = config.output.join(&name);
    std::fs::create_dir_all(&out_dir)
        .map_err(|error| format!("cannot create {}'s output: {error}", name))?;
    let status = Cage::builder()
        .overlay_rootfs(&config.base, layer.path())
        .bind_ro(source, SOURCE_DEST)
        .bind(&out_dir, OUTPUT_DEST)
        .network(if config.network {
            Network::Host
        } else {
            Network::Isolated
        })
        .command(SHELL)
        .args(["-e", "-u", "-c", BUILD_SCRIPT])
        .build()
        .map_err(|error| format!("cannot compose {name}'s build cage: {error}"))?
        .run()
        .map_err(|error| format!("cannot launch {name}'s build: {error}"))?;

    // Drop the layer before publishing: the build's artifacts are already in the
    // host output directory, and the increment has served its purpose.
    drop(layer);

    if !status.success() {
        return Err(format!("{name}'s build failed with {status}"));
    }

    // Publish the built packages into the pool, so the next component resolves
    // against them.
    let debs = collect_debs(&out_dir)?;
    for deb in &debs {
        eprintln!(
            "deb-layer-pipeline: publishing {}",
            deb.file_name().unwrap_or(OsStr::new("?")).to_string_lossy()
        );
    }
    pool(config)
        .publish(&debs)
        .map_err(|error| format!("cannot publish {name}'s packages: {error}"))?;
    Ok(())
}

/// Builds a [`Repository`] pointing at the pool: a trusted `file://` mirror the
/// resolver merges alongside the archive.
fn pool_repository(config: &Config) -> Result<Repository, String> {
    // The pool names its own mirror URL, so the pipeline holds no copy of the
    // archive layout.
    let mirror = pool(config)
        .mirror_url()
        .map_err(|error| format!("cannot resolve the pool's mirror URL: {error}"))?;
    Repository::builder(&config.suite)
        .mirror(mirror)
        .trust_unsigned(true)
        .name("pipeline-pool")
        .build()
        .map_err(|error| format!("cannot configure the pool repository: {error}"))
}

/// Collects the `.deb` and `.ddeb` files a build left in `out_dir`.
fn collect_debs(out_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut debs: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .map_err(|error| format!("cannot read the build output: {error}"))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            let ext = path.extension().and_then(OsStr::to_str);
            matches!(ext, Some("deb") | Some("ddeb"))
        })
        .collect();
    debs.sort();
    if debs.is_empty() {
        return Err(format!(
            "the build produced no packages in {}",
            out_dir.display()
        ));
    }
    Ok(debs)
}

/// Prints a Debian provisioning progress event to stderr.
fn print_progress(event: DebianEvent<'_>) {
    use std::io::Write;
    // Two levels of openness, and each needs its own escape: the `_` arm
    // absorbs a future variant, and the `..` in every struct arm absorbs a
    // future field within a variant already matched here.
    match event {
        DebianEvent::Fetching { url, .. } => eprintln!("deb-layer-pipeline: fetching {url}"),
        DebianEvent::Resolving => eprintln!("deb-layer-pipeline: resolving the package set"),
        DebianEvent::Unsatisfiable {
            requirement,
            required_by,
            reason,
            ..
        } => eprintln!("deb-layer-pipeline: {required_by} requires {requirement}, and {reason}"),
        DebianEvent::Downloading {
            package,
            index,
            total,
            ..
        } => eprintln!("deb-layer-pipeline: downloading {package} ({index}/{total})"),
        DebianEvent::Extracting { package, .. } => {
            eprintln!("deb-layer-pipeline: extracting {package}")
        }
        // dpkg's own output during configuration flows straight to stderr.
        DebianEvent::CommandOutput { bytes, .. } => {
            let _ = std::io::stderr().write_all(bytes);
        }
        _ => {}
    }
}

/// Parses the command line, excluding the program name.
fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let mut suite = None;
    let mut base = None;
    let mut pool = None;
    let mut cache = None;
    let mut arch = None;
    let mut components = Vec::new();
    let mut output = None;
    let mut network = false;

    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(Invocation::Help);
        } else if arg == "-V" || arg == "--version" {
            return Ok(Invocation::Version);
        } else if arg == "--suite" {
            suite = Some(string_value("--suite", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--suite=") {
            suite = Some(into_string("--suite", value)?);
        } else if arg == "--base" {
            base = Some(PathBuf::from(value_for("--base", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--base=") {
            base = Some(PathBuf::from(value));
        } else if arg == "--pool" {
            pool = Some(PathBuf::from(value_for("--pool", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--pool=") {
            pool = Some(PathBuf::from(value));
        } else if arg == "--cache" {
            cache = Some(PathBuf::from(value_for("--cache", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--cache=") {
            cache = Some(PathBuf::from(value));
        } else if arg == "--arch" {
            arch = Some(string_value("--arch", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--arch=") {
            arch = Some(into_string("--arch", value)?);
        } else if arg == "--component" {
            components.push(PathBuf::from(value_for("--component", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--component=") {
            components.push(PathBuf::from(value));
        } else if arg == "--output" {
            output = Some(PathBuf::from(value_for("--output", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--output=") {
            output = Some(PathBuf::from(value));
        } else if arg == "--network" {
            network = true;
        } else {
            return Err(format!("unrecognized argument {}", arg.to_string_lossy()));
        }
    }

    let base = base.ok_or("--base DIR is required")?;
    let pool = pool.ok_or("--pool DIR is required")?;
    let output = output.ok_or("--output DIR is required")?;
    if components.is_empty() {
        return Err("at least one --component DIR is required".to_string());
    }

    Ok(Invocation::Run(Config {
        suite: suite.unwrap_or_else(|| DEFAULT_SUITE.to_string()),
        base,
        pool,
        cache,
        arch: arch.unwrap_or_else(host_architecture),
        components,
        output,
        network,
    }))
}
