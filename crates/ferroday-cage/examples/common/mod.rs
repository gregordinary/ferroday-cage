//! Command-line scaffolding shared by the examples.
//!
//! Each example is a worked consumer of the library, so what it *shows* is the
//! library's API. Argument parsing is not that: it is the same few functions
//! every time, down to handing the command line it collected to the builder,
//! and a reader who meets them once has met them all. They live here so each
//! example's own file is about the sandbox it builds.
//!
//! Cargo builds `examples/*.rs` as binaries and leaves a subdirectory without a
//! `main.rs` alone, so this file is included with `mod common;` rather than
//! compiled as an example of its own. Each example includes only what it uses,
//! so `#[allow(dead_code)]` sits on every item here.
//!
//! A status maps to a process exit code through
//! [`ExitStatus::shell_code`](ferroday_cage::ExitStatus::shell_code) and a
//! library failure through [`Error::shell_code`](ferroday_cage::Error::shell_code):
//! the library owns those conventions and states them once. An error is printed
//! through [`ErrorChain`](ferroday_cage::ErrorChain), which renders it with the
//! causes its own message leaves to `source()`, and that rendering is the
//! library's too. What is here is the two codes an example reports of itself,
//! for a command line it cannot understand and for a failure that is not a
//! launch's.
//!
//! The `fcage` binary keeps helpers of its own that answer the same three
//! questions, and that is where the sharing stops. A crate's examples are not
//! reachable from another crate, so the two could only meet in a crate
//! published for the purpose — a dependency on every consumer's build for four
//! functions that parse arguments. The boundary is therefore deliberate: each
//! side owns the wording of its own diagnostics, and neither is the reference
//! for the other.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::process::ExitCode;

use ferroday_cage::CageBuilder;

/// Consumes the next argument as a required value.
#[allow(dead_code)]
pub fn value_for(name: &str, args: &mut dyn Iterator<Item = OsString>) -> Result<OsString, String> {
    args.next()
        .ok_or_else(|| format!("{name} requires a value"))
}

/// Requires a value to be UTF-8, naming the option on failure.
///
/// A path, and therefore an argument, is bytes rather than text, so this is the
/// one place an example decides that a particular option's value has to be
/// text. Values that stay bytes — a rootfs path, the command to run — never
/// pass through here.
#[allow(dead_code)]
pub fn into_string(name: &str, value: OsString) -> Result<String, String> {
    value.into_string().map_err(|value| {
        format!(
            "{name} value {} is not valid UTF-8",
            value.to_string_lossy()
        )
    })
}

/// Consumes the next argument as a required UTF-8 value.
#[allow(dead_code)]
pub fn string_value(
    name: &str,
    args: &mut dyn Iterator<Item = OsString>,
) -> Result<String, String> {
    into_string(name, value_for(name, args)?)
}

/// Splits `--flag=value` syntax, preserving a non-UTF-8 value.
#[allow(dead_code)]
pub fn flag_value(arg: &OsStr, prefix: &[u8]) -> Option<OsString> {
    arg.as_bytes()
        .strip_prefix(prefix)
        .map(|value| OsString::from_vec(value.to_vec()))
}

/// Gives `builder` the command line `argv` names: its first word as the command
/// and the rest as the command's arguments.
///
/// # Panics
///
/// Where `argv` is empty. An example's parser collects a command line only
/// where a word follows it, so an empty one never reaches here.
#[allow(dead_code)]
pub fn with_command(builder: CageBuilder, argv: &[OsString]) -> CageBuilder {
    let (program, args) = argv
        .split_first()
        .expect("a command line is never empty here");
    builder.command(PathBuf::from(program)).args(args)
}

/// Prints a usage error naming `program`, and returns the usage exit code.
///
/// 2 is the conventional exit code for a command-line that could not be
/// understood, distinct from the 125-127 range a *launcher* uses to report that
/// it could not run what it was asked to.
#[allow(dead_code)]
pub fn usage_error(program: &str, message: &str) -> ExitCode {
    eprintln!("{program}: {message}");
    eprintln!("Try '{program} --help' for usage.");
    ExitCode::from(2)
}

/// Prints a failure of the example's own, naming `program`, and returns the
/// code a launcher exits with when it fails.
///
/// 125 is what [`Error::shell_code`](ferroday_cage::Error::shell_code) answers
/// for every launch failure but the exec step's. A failure that is not an
/// `Error` at all, such as a provisioning run or a host that lacks what the
/// example needs, exits the same way, so a caller reads one code for "the
/// launcher failed".
#[allow(dead_code)]
pub fn failure(program: &str, message: &str) -> ExitCode {
    eprintln!("{program}: {message}");
    ExitCode::from(125)
}
