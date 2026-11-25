//! A sandbox kept for a session, built on ferroday-cage.
//!
//! A runtime that runs each command in a sandbox of its own keeps what a
//! command writes, through a bind, and loses what it starts: a server one
//! command starts is gone before the next command reaches for it.
//! `session-sandbox` keeps one sandbox for a whole session instead, and runs
//! each line it reads as a further command in it:
//!
//! ```sh
//! session-sandbox --worktree ~/project <<'EOF'
//! python3 -m http.server 8000 --bind 127.0.0.1 >/dev/null 2>&1 &
//! sleep 1; python3 -c 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8000/").status)'
//! EOF
//! ```
//!
//! - **The sandbox** starts with no command of its own, through
//!   [`Cage::start`](ferroday_cage::Cage::start): the host's own root,
//!   read-only, with the working tree bound read-write at its own path, a
//!   network namespace of its own whose only interface is loopback, and a PID
//!   namespace whose init holds the sandbox between commands.
//! - **Each line** runs as `/bin/sh -c LINE` through
//!   [`Running::exec`](ferroday_cage::Running::exec), in the working tree, with
//!   standard input closed. What a line starts in the background runs on in the
//!   sandbox for the lines after it, and each line is confined as the first
//!   command of a sandbox is, in a user namespace of its own.
//! - **The end of input** ends the session:
//!   [`terminate`](ferroday_cage::Running::terminate) sends every process of
//!   the sandbox `SIGTERM`, the sandbox ends once none is left, and a kill
//!   follows past a grace.
//!
//! The sandbox is tied to the example's handle, so it ends with the example
//! however the example ends.
//!
//! # Usage
//!
//! ```text
//! session-sandbox [--worktree DIR]
//! ```
//!
//! The exit code is the last line's, as a shell script's is.

mod common;

use std::ffi::OsString;
use std::io::BufRead as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use common::{failure, flag_value, usage_error, value_for};
use ferroday_cage::{Cage, Error, ErrorChain, Exec, ExitStatus, Running, Stdio};

const USAGE: &str = "\
Usage: session-sandbox [--worktree DIR]

Starts one sandbox on the host's root, read-only, and runs each line read from
standard input as a further command in it, under /bin/sh -c. What a line starts
in the background keeps running for the lines after it. The end of input ends
the sandbox.

  --worktree DIR    Bind DIR read-write at its own path, and run each line in it
  -h, --help        Show this help
";

/// How long the end of a session waits for the sandbox's processes to end
/// after asking them to, before it kills them.
const GRACE: Duration = Duration::from_secs(5);

/// The parsed command line.
struct Options {
    /// The working tree, made absolute, where one was named.
    worktree: Option<PathBuf>,
}

fn main() -> ExitCode {
    let options = match parse(std::env::args_os().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => return usage_error("session-sandbox", &message),
    };
    match session(&options) {
        Ok(Some(status)) => ExitCode::from(status.shell_code()),
        Ok(None) => ExitCode::SUCCESS,
        Err(Failure::Cage(error)) => {
            eprintln!("session-sandbox: {}", ErrorChain::new(&error));
            ExitCode::from(error.shell_code())
        }
        Err(Failure::Input(error)) => failure(
            "session-sandbox",
            &format!("reading a command line failed: {error}"),
        ),
    }
}

/// Why a session ended early.
enum Failure {
    /// The library failed: starting the sandbox, or running a line in it.
    Cage(Error),
    /// Standard input could not be read.
    Input(std::io::Error),
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Failure::Cage(error)
    }
}

/// Runs the session: starts the sandbox, runs every line in it, and ends it,
/// returning the last line's outcome.
fn session(options: &Options) -> Result<Option<ExitStatus>, Failure> {
    let mut builder = Cage::builder().host_rootfs().stop_with_caller(true);
    if let Some(tree) = &options.worktree {
        builder = builder.bind(tree, tree);
    }
    let mut sandbox = builder.build()?.start()?;

    let mut last = None;
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(Failure::Input)?;
        if line.trim().is_empty() {
            continue;
        }
        let status = run_line(&sandbox, options, &line)?;
        eprintln!("session-sandbox: {status}: {line}");
        last = Some(status);
    }

    end(&mut sandbox)?;
    Ok(last)
}

/// Runs one line as a further command of `sandbox`, and waits for it.
fn run_line(sandbox: &Running<'_>, options: &Options, line: &str) -> Result<ExitStatus, Error> {
    let mut exec = Exec::new("/bin/sh")
        .args(["-c", line])
        // The lines are the example's input, not the command's.
        .stdin(Stdio::Null);
    if let Some(tree) = &options.worktree {
        exec = exec.current_dir(tree);
    }
    sandbox.exec(&exec)?.wait()
}

/// Ends the sandbox: asks every process of it to end, and kills what is left
/// past [`GRACE`].
fn end(sandbox: &mut Running<'_>) -> Result<(), Error> {
    sandbox.terminate()?;
    if sandbox.wait_timeout(GRACE)?.is_none() {
        sandbox.kill()?;
        sandbox.wait()?;
    }
    Ok(())
}

/// Parses the command line. `Ok(None)` asks for the help text.
fn parse(args: impl Iterator<Item = OsString>) -> Result<Option<Options>, String> {
    let mut args = args;
    let mut worktree = None;
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(None);
        } else if arg == "--worktree" {
            worktree = Some(PathBuf::from(value_for("--worktree", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--worktree=") {
            worktree = Some(PathBuf::from(value));
        } else {
            return Err(format!("unexpected argument {}", arg.to_string_lossy()));
        }
    }
    // Bound at its own path, so it is named as the host names it.
    let worktree = worktree
        .map(|tree| {
            std::fs::canonicalize(&tree)
                .map_err(|error| format!("--worktree {}: {error}", tree.display()))
        })
        .transpose()?;
    Ok(Some(Options { worktree }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_worktree_is_named_as_the_host_names_it() {
        let options = parse(["--worktree", "/tmp/."].into_iter().map(OsString::from))
            .expect("a valid command line")
            .expect("not a request for help");
        assert_eq!(
            options.worktree,
            Some(std::fs::canonicalize("/tmp").unwrap())
        );
    }

    #[test]
    fn an_unknown_argument_is_refused() {
        assert!(parse(["--rootfs"].into_iter().map(OsString::from)).is_err());
    }
}
