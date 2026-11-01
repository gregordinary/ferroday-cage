//! `fcage`'s own writes to its standard streams.
//!
//! Rust ignores `SIGPIPE`, so a write to a pipe whose reader has gone fails
//! with `EPIPE` rather than ending the process. The `print!` family panics on
//! that failure: exit 101, and a panic message nobody reads, where a shell
//! expects what a process `SIGPIPE` ended exits with, 141. Every write `fcage`
//! makes of its own goes through here instead, so a reader gone is an outcome
//! rather than a panic.
//!
//! What the outcome is depends on what the write was for:
//!
//! - Output that is the invocation's purpose, such as the help, the version, or
//!   a listing, ends it with 141 when its reader goes ([`print_stdout`]).
//! - A line written while work remains, such as a warning before a launch or a
//!   provisioning run's progress, stops that work at the first point it can
//!   stop cleanly, and the invocation exits 141 ([`say`]). That is what a
//!   shell's `| head` asks of a producer, and what a C program would do by
//!   dying of the signal at the write.
//! - A line reporting how the invocation ended leaves that ending as it was
//!   ([`report`]). A failure still exits 125 and a usage error 2; only the
//!   words are lost.
//!
//! Any other failure to write a diagnostic is dropped. There is nowhere left to
//! report it, and the exit code carries the outcome whatever became of the
//! words.

use std::fmt;
use std::io::{self, Write};
use std::process::ExitCode;

use ferroday_cage::{ErrorChain, ExitStatus};

/// The exit code of a writer whose reader went away: what a process `SIGPIPE`
/// killed exits with, which is what a shell expects of a pipeline's early end.
pub fn broken_pipe() -> u8 {
    ExitStatus::signaled(rustix::process::Signal::PIPE.as_raw()).shell_code()
}

/// The reader of standard error has gone: a line of `fcage`'s own could not be
/// written, because nothing reads the pipe it was written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderGone;

/// Writes one line of `fcage`'s own to standard error, while work remains.
///
/// The caller stops that work on [`ReaderGone`] and exits with
/// [`broken_pipe`].
pub fn say(line: fmt::Arguments<'_>) -> Result<(), ReaderGone> {
    say_to(&mut io::stderr().lock(), line)
}

/// Writes one line of `fcage`'s own to standard error, reporting how the
/// invocation ended. A reader gone loses the words and changes nothing else.
pub fn report(line: fmt::Arguments<'_>) {
    // The ending is the caller's exit code, which a lost line does not change.
    let _ = say(line);
}

/// Writes `line` and a newline to `out`, answering [`ReaderGone`] where the
/// reader has gone and dropping any other failure.
pub fn say_to(out: &mut dyn Write, line: fmt::Arguments<'_>) -> Result<(), ReaderGone> {
    let written = out.write_fmt(line).and_then(|()| out.write_all(b"\n"));
    gone_or_dropped(written.and_then(|()| out.flush()))
}

/// Writes `bytes` to `out` as they are: the output of a command a provisioner
/// runs, which carries its own newlines.
pub fn pass_to(out: &mut dyn Write, bytes: &[u8]) -> Result<(), ReaderGone> {
    gone_or_dropped(out.write_all(bytes).and_then(|()| out.flush()))
}

/// [`ReaderGone`] for a write whose reader went away; nothing for any other
/// outcome.
fn gone_or_dropped(written: io::Result<()>) -> Result<(), ReaderGone> {
    match written {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Err(ReaderGone),
        Ok(()) | Err(_) => Ok(()),
    }
}

/// Writes output that is the invocation's purpose to standard output, and
/// returns the exit code its writes earned.
///
/// The help, the version, and the Gentoo listings each go through here. A
/// listing is a stream a reader is expected to walk away from, and
/// `fcage --gentoo-packages amd64 | head` is the everyday case, so a reader
/// gone ends it as the quiet 141 a shell expects.
///
/// `--export-rootfs` answers the same question in its own terms, because its
/// write goes through the library and fails as a `ProvisionError` naming what
/// it was doing, a diagnostic this could only report as a bare `io::Error`.
pub fn print_stdout(
    subject: &str,
    records: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> ExitCode {
    // Buffered, so a listing of thousands of lines is a handful of writes: the
    // records are small and there is no reader waiting on each one.
    let mut out = io::BufWriter::new(io::stdout().lock());
    let written = records(&mut out).and_then(|()| out.flush());
    ExitCode::from(stdout_status(subject, written))
}

/// What output on standard output exits with, given how its writes ended.
///
/// Separate from [`print_stdout`] because that one owns the process's own
/// standard output, and what is worth pinning is the reading of the outcome.
pub fn stdout_status(subject: &str, written: io::Result<()>) -> u8 {
    match written {
        Ok(()) => 0,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => broken_pipe(),
        Err(error) => {
            report(format_args!(
                "fcage: cannot write {subject}: {}",
                ErrorChain::new(&error)
            ));
            crate::FAILED
        }
    }
}
