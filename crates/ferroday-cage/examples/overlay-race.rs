//! A harness for a reported transient: a parallel first-touch of an
//! overlay-merged directory answering `ENOENT` for a file that is present.
//!
//! # The report
//!
//! A consumer running `make -j32` on an overlay root has twice seen a compile
//! fail with `ENOENT` on a header that is provably in the upper layer, and pass
//! on immediate retry. What makes the report worth an instrument rather than a
//! shrug is that the transient is established without one: the same stage's
//! `./configure` had, minutes earlier and in the same layer, successfully
//! compiled probes that `#include`d both of the headers that later went
//! missing. The file was momentarily unfindable, not absent.
//!
//! Their build root is a fresh mount per command — configure, then make, then
//! install, each in its own cage over the same upper — so the parallel build
//! starts against a superblock whose dentry cache the serial configure warmed
//! and which was then destroyed. Their one clean control does its serial
//! configure and its parallel build inside a *single* mount, and never
//! first-touches under parallelism.
//!
//! # What this runs
//!
//! Mount, storm, unmount, repeat. Each iteration is one fresh overlay
//! superblock and one race, so thousands of trials cost seconds rather than a
//! full build. Every trial:
//!
//! 1. builds a cage rooted on an overlay whose lower and upper both carry the
//!    probe directory, so overlayfs must assemble it from both;
//! 2. releases `--parallel` processes that all look up three probes at once;
//! 3. tears the mount down.
//!
//! The three probes are the shapes the field evidence distinguishes, and
//! looking for all three in one storm is what tells a reproduction of the
//! reported fault from a reproduction of something else:
//!
//! - `upper-only`, a file directly in the merged directory;
//! - `upper-dir/inside`, a file under an upper-only *subdirectory* of it;
//! - `lower-only`, a file the lower alone carries.
//!
//! The report says the first two fail and the third never has, which is a
//! constraint rather than an absence: lower-only paths are opened orders of
//! magnitude more often, by the same processes in the same command. A run that
//! misses all three evenly is reproducing something else and should be read as
//! such.
//!
//! `--warm` performs one serial lookup of the merged directory in the same
//! mount before releasing the storm. That is the direct test of the reported
//! discriminator: if the storm fires without it and never with it, the
//! consumer's mount-per-command shape is the cause and collapsing two commands
//! into one cage is the fix.
//!
//! # Usage
//!
//! ```text
//! cargo run --release --example overlay-race -- --rootfs ./alpine \
//!     [--trials 2000] [--parallel 32] [--warm]
//! ```
//!
//! `--rootfs` is any rootfs carrying a POSIX shell; the crate's own test
//! fixture will do. Nothing in it is written to: the probes go in layers of the
//! harness's own, and the rootfs is only ever a lower.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ferroday_cage::provision;
use ferroday_cage::{Cage, ErrorChain, IdentityMap, Overlay};

mod common;

use common::{string_value, value_for};

fn main() -> ExitCode {
    let options = match Options::parse() {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("overlay-race: {reason}");
            eprintln!("usage: overlay-race --rootfs DIR [--trials N] [--parallel N] [--warm]");
            return ExitCode::from(2);
        }
    };

    let scratch = std::env::temp_dir().join(format!("overlay-race-{}", std::process::id()));
    let _ = ferroday_cage::provision::remove(&scratch);
    if let Err(err) = lay_out_layers(&scratch) {
        eprintln!(
            "overlay-race: preparing the layers: {}",
            ErrorChain::new(&err)
        );
        return ExitCode::FAILURE;
    }

    println!(
        "trials {}, {} processes each, {} start\n",
        options.trials,
        options.parallel,
        if options.warm { "warm" } else { "cold" },
    );

    let mut misses = Misses::default();
    let mut trial = 0;
    while trial < options.trials {
        match storm(&options, &scratch, trial) {
            Ok(report) => misses.absorb(&report),
            Err(err) => {
                eprintln!("overlay-race: trial {trial}: {err}");
                let _ = ferroday_cage::provision::remove(&scratch);
                return ExitCode::FAILURE;
            }
        }
        trial += 1;
        if trial % 100 == 0 {
            println!("{trial} trials: {misses}");
        }
    }

    println!("\n{} trials complete: {misses}", options.trials);
    if misses.total() == 0 {
        println!(
            "nothing fired. That is a result about this host and this shape, not a \
             refutation of the report."
        );
    } else if misses.lower_only > 0 && misses.upper_only > 0 && misses.upper_dir > 0 {
        println!(
            "all three shapes missed. The field evidence has never lost a lower-only \
             path, so this is very likely a different fault -- read it as such before \
             reading it as the reported one."
        );
    } else {
        println!(
            "the upper-side shapes missed and the lower-only one did not, which is the \
             asymmetry the report describes."
        );
    }
    let _ = ferroday_cage::provision::remove(&scratch);
    ExitCode::SUCCESS
}

/// What the harness was asked to run.
struct Options {
    rootfs: PathBuf,
    trials: u32,
    parallel: u32,
    warm: bool,
}

impl Options {
    fn parse() -> Result<Options, String> {
        let mut rootfs = None;
        let mut trials = 2000;
        let mut parallel = 32;
        let mut warm = false;
        let mut args = std::env::args_os().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--rootfs" {
                rootfs = Some(PathBuf::from(value_for("--rootfs", &mut args)?));
            } else if arg == "--trials" {
                trials = count("--trials", &mut args)?;
            } else if arg == "--parallel" {
                parallel = count("--parallel", &mut args)?;
            } else if arg == "--warm" {
                warm = true;
            } else {
                return Err(format!("unrecognized option {}", arg.to_string_lossy()));
            }
        }
        Ok(Options {
            rootfs: rootfs.ok_or("--rootfs is required")?,
            trials,
            parallel,
            warm,
        })
    }
}

/// Reads a count-valued option.
fn count(name: &str, args: &mut dyn Iterator<Item = OsString>) -> Result<u32, String> {
    string_value(name, args)?
        .parse()
        .map_err(|_| format!("{name} needs a number"))
}

/// How many lookups of each shape came back missing.
#[derive(Default)]
struct Misses {
    upper_only: u32,
    upper_dir: u32,
    lower_only: u32,
}

impl Misses {
    fn absorb(&mut self, other: &Misses) {
        self.upper_only += other.upper_only;
        self.upper_dir += other.upper_dir;
        self.lower_only += other.lower_only;
    }

    fn total(&self) -> u32 {
        self.upper_only + self.upper_dir + self.lower_only
    }
}

impl std::fmt::Display for Misses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "upper-only {}, upper-dir {}, lower-only {}",
            self.upper_only, self.upper_dir, self.lower_only,
        )
    }
}

/// Builds the two layers the probes live in.
///
/// The probe directory exists in the lower *and* the upper, which is the whole
/// point: overlayfs has to assemble one entry for it from both, and it is that
/// assembly the report suspects. A directory only one layer carries is copied
/// straight through and races nothing.
fn lay_out_layers(scratch: &Path) -> std::io::Result<()> {
    let lower = scratch.join("lower/probe");
    std::fs::create_dir_all(&lower)?;
    std::fs::write(lower.join("lower-only"), b"the base layer's own\n")?;

    let upper = scratch.join("upper/probe");
    std::fs::create_dir_all(upper.join("upper-dir"))?;
    std::fs::write(upper.join("upper-only"), b"a file directly in the merge\n")?;
    std::fs::write(
        upper.join("upper-dir/inside"),
        b"a file under an upper-only subdirectory\n",
    )?;
    std::fs::create_dir_all(scratch.join("work"))?;
    Ok(())
}

/// Runs one trial: one fresh mount, one storm, one teardown.
fn storm(options: &Options, scratch: &Path, trial: u32) -> Result<Misses, String> {
    // A fresh upper per trial, so a copy-up in one trial cannot warm the next.
    // The layers are laid out once and the upper is cheap to re-create.
    let upper = scratch.join(format!("upper-{}", trial % 2));
    let work = scratch.join(format!("work-{}", trial % 2));
    // What the trial two back left is a tree a sandbox wrote, mode-`0` work
    // directory included, so it goes the way the library removes such a tree.
    // The cage runs under its default single map, and neither directory is a
    // published rootfs with a lock beside it.
    for layer in [&upper, &work] {
        let _ = provision::Remove::new(layer)
            .map(IdentityMap::Single)
            .remove_lock(false)
            .run();
    }
    copy_tree(&scratch.join("upper"), &upper)
        .map_err(|err| format!("staging the upper: {}", ErrorChain::new(&err)))?;
    std::fs::create_dir_all(&work)
        .map_err(|err| format!("staging the work dir: {}", ErrorChain::new(&err)))?;

    let cage = Cage::builder()
        .overlay(
            Overlay::new()
                .lower(&options.rootfs)
                .lower(scratch.join("lower"))
                .upper(&upper)
                .work(&work),
        )
        .command("/bin/sh")
        .args(["-c", &script(options)])
        .build()
        .map_err(|err| format!("building the cage: {}", ErrorChain::new(&err)))?;
    let output = cage
        .output()
        .map_err(|err| format!("running: {}", ErrorChain::new(&err)))?;

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(Misses {
        upper_only: text.matches("MISS upper-only").count() as u32,
        upper_dir: text.matches("MISS upper-dir").count() as u32,
        lower_only: text.matches("MISS lower-only").count() as u32,
    })
}

/// The storm itself, as a shell script.
///
/// Every process is started before any of them reads, so the lookups land
/// together rather than in a queue: the shell forks the whole batch and each
/// one waits on a shared start file that appears last. Without that the first
/// process warms the directory for all the others and there is no race left to
/// observe.
fn script(options: &Options) -> String {
    let warm = if options.warm {
        // One serial lookup of the merged directory, in this mount, before the
        // storm. The direct test of the reported discriminator.
        "ls /probe >/dev/null 2>&1\n"
    } else {
        ""
    };
    format!(
        "{warm}\
         i=0\n\
         while [ $i -lt {parallel} ]; do\n\
         (\n\
         while [ ! -f /tmp/go ]; do :; done\n\
         [ -r /probe/upper-only ] || echo 'MISS upper-only'\n\
         [ -r /probe/upper-dir/inside ] || echo 'MISS upper-dir'\n\
         [ -r /probe/lower-only ] || echo 'MISS lower-only'\n\
         ) &\n\
         i=$((i+1))\n\
         done\n\
         : > /tmp/go\n\
         wait\n",
        parallel = options.parallel,
    )
}

/// Copies a directory tree, for staging a fresh upper each trial.
fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}
