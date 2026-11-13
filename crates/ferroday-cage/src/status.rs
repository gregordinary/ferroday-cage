//! The exit status of a sandboxed command, and what it used.

use std::fmt;
use std::time::Duration;

/// How the sandboxed command terminated.
///
/// Returned by [`Cage::run`] whenever the command was executed, regardless of
/// its exit code: a non-zero exit is data, not an error. The status reflects
/// either a normal exit with a code or termination by a signal, exactly one
/// of which applies.
///
/// [`Cage::run`]: crate::Cage::run
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExitStatus(Kind);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Exited(i32),
    Signaled { signal: i32, core_dumped: bool },
}

impl ExitStatus {
    /// The status of a command that exited normally with `code`.
    ///
    /// A launch reports the status it collected, so a caller has no need of
    /// this to read one. It is for a caller that reports an outcome of its own
    /// in the same terms, and through [`shell_code`](Self::shell_code) in the
    /// same convention, as a status the library collected.
    pub fn exited(code: i32) -> ExitStatus {
        ExitStatus(Kind::Exited(code))
    }

    /// The status of a command that signal number `signal` terminated.
    ///
    /// For the caller [`exited`](Self::exited) describes. A writer that finds
    /// its reader gone reports the code a process killed by `SIGPIPE` exits
    /// with, which is what a shell expects of a pipeline's early end:
    ///
    /// ```
    /// use ferroday_cage::ExitStatus;
    ///
    /// // SIGPIPE is signal 13 on every Linux architecture.
    /// assert_eq!(ExitStatus::signaled(13).shell_code(), 141);
    /// ```
    pub fn signaled(signal: i32) -> ExitStatus {
        ExitStatus(Kind::Signaled {
            signal,
            core_dumped: false,
        })
    }

    /// The status of a command that signal number `signal` terminated, and
    /// whose core the kernel dumped.
    ///
    /// For the caller [`exited`](Self::exited) describes, reporting a crash of
    /// its own in the terms a launch reports one. [`signaled`](Self::signaled)
    /// reports no dump.
    pub fn signaled_with_core_dump(signal: i32) -> ExitStatus {
        ExitStatus(Kind::Signaled {
            signal,
            core_dumped: true,
        })
    }

    /// Returns `true` if the command exited normally with code `0`.
    pub fn success(&self) -> bool {
        self.code() == Some(0)
    }

    /// The exit code, if the command exited normally.
    pub fn code(&self) -> Option<i32> {
        match self.0 {
            Kind::Exited(code) => Some(code),
            Kind::Signaled { .. } => None,
        }
    }

    /// The signal number that terminated the command, if it was terminated
    /// by a signal.
    pub fn signal(&self) -> Option<i32> {
        match self.0 {
            Kind::Exited(_) => None,
            Kind::Signaled { signal, .. } => Some(signal),
        }
    }

    /// Whether the kernel dumped the command's core when a signal terminated
    /// it.
    ///
    /// The supervisor reads it from the wait status it collects, the flag
    /// `WCOREDUMP` tests, so it reports what the kernel did and nothing else.
    /// Whether the kernel dumps a core at all is the host's to decide: a signal
    /// whose default action dumps one, `kernel.core_pattern`, and the
    /// [`Resource::CoreDump`](crate::Resource::CoreDump) limit, which a pattern that
    /// pipes the core to a program does not consult. A command that exited
    /// reports `false`.
    pub fn core_dumped(&self) -> bool {
        matches!(
            self.0,
            Kind::Signaled {
                core_dumped: true,
                ..
            }
        )
    }

    /// The status as a process exit code, following the shell's convention.
    ///
    /// A command that exited reports its own code; a command a signal
    /// terminated reports `128 + signal`, which is what `sh` reports in `$?`
    /// and what a caller propagating the outcome to its own exit status wants.
    /// This is what the `fcage` binary returns, and what a consumer that
    /// re-exports a sandboxed command's outcome should return.
    ///
    /// The result is a `u8` because that is the width a process exit status
    /// has: `wait` carries eight bits, so a code outside `0..=255` was never
    /// reachable and no case is lost by narrowing here.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> Result<(), ferroday_cage::Error> {
    /// # #[cfg(feature = "tarball")] {
    /// use std::process::ExitCode;
    ///
    /// use ferroday_cage::Cage;
    ///
    /// # let rootfs = "/var/cache/myapp/rootfs";
    /// let status = Cage::builder().command("/bin/false").rootfs(rootfs).build()?.run()?;
    /// let _code = ExitCode::from(status.shell_code());
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn shell_code(&self) -> u8 {
        match self.0 {
            Kind::Exited(code) => code as u8,
            // A signal number never approaches 128, so the sum is in range;
            // the wrapping form states what happens to a nonsensical one
            // rather than leaving it to a debug-only panic.
            Kind::Signaled { signal, .. } => 128_u8.wrapping_add(signal as u8),
        }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Kind::Exited(code) => write!(f, "exit code {code}"),
            Kind::Signaled {
                signal,
                core_dumped: false,
            } => write!(f, "terminated by signal {signal}"),
            Kind::Signaled {
                signal,
                core_dumped: true,
            } => write!(f, "terminated by signal {signal} (core dumped)"),
        }
    }
}

/// What a sandboxed command and its descendants used of the processor and of
/// memory.
///
/// Reported by [`Running::usage`] and carried on [`Output::usage`] once the
/// command's exit has been collected. The supervisor reads it from the kernel
/// (`getrusage` over its reaped children) right after it collects that exit,
/// so it covers the command and every descendant that had exited and been
/// collected by then:
///
/// - Under a PID namespace, the default, the sandbox's init collects every
///   process of the namespace that exits, so a descendant counts whether the
///   command waited for it or it was orphaned to the init.
/// - Without one, a descendant counts only through the process that waited for
///   it. An orphan is collected outside the sandbox and is not counted.
///
/// A process still running when the command exits is not counted: under a PID
/// namespace the teardown ends it, and without one it runs on outside the
/// sandbox.
///
/// [`Running::usage`]: crate::Running::usage
/// [`Output::usage`]: crate::Output::usage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ResourceUsage {
    /// Processor time the processes spent in user mode, summed over them.
    pub user_time: Duration,
    /// Processor time the kernel spent on the processes' behalf, summed over
    /// them.
    pub system_time: Duration,
    /// The largest resident set size any one of the processes reached, in
    /// bytes.
    ///
    /// The peak of the largest process, not a sum: two processes that each
    /// held 100 MiB report 100 MiB, whether or not they ran at once. The
    /// kernel counts it in kibibytes, so it is a multiple of 1024.
    ///
    /// # The launching process's floor
    ///
    /// The figure is never below the resident set the launching process had
    /// when it launched the sandbox, its heap and stacks above all. The launch
    /// forks copies of the launching process down to the command, and a copy
    /// shares the resident pages it was copied with, which count toward its own
    /// resident set. When the command's `execve` replaces the last copy, the
    /// kernel records that copy's peak as the command's. A service holding
    /// 2 GiB that runs `/bin/true` therefore reports about 2 GiB. The kernel
    /// keeps no figure that leaves the replaced image out and that a process
    /// without privilege can read, so a peak below the launching process's own
    /// is not one this field can show.
    pub peak_rss_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exited_zero_is_success() {
        let status = ExitStatus::exited(0);
        assert!(status.success());
        assert_eq!(status.code(), Some(0));
        assert_eq!(status.signal(), None);
    }

    #[test]
    fn exited_nonzero_is_not_success() {
        let status = ExitStatus::exited(42);
        assert!(!status.success());
        assert_eq!(status.code(), Some(42));
        assert_eq!(status.signal(), None);
    }

    #[test]
    fn signaled_reports_the_signal_only() {
        let status = ExitStatus::signaled(9);
        assert!(!status.success());
        assert_eq!(status.code(), None);
        assert_eq!(status.signal(), Some(9));
    }

    #[test]
    fn the_shell_code_is_the_exit_code_or_128_plus_the_signal() {
        assert_eq!(ExitStatus::exited(0).shell_code(), 0);
        assert_eq!(ExitStatus::exited(42).shell_code(), 42);
        assert_eq!(ExitStatus::exited(255).shell_code(), 255);
        // SIGKILL and SIGTERM, the two a caller most often sees.
        assert_eq!(ExitStatus::signaled(9).shell_code(), 137);
        assert_eq!(ExitStatus::signaled(15).shell_code(), 143);
    }

    #[test]
    fn a_core_dump_is_reported_beside_the_signal_and_changes_no_code() {
        let dumped = ExitStatus::signaled_with_core_dump(11);
        assert!(dumped.core_dumped());
        assert_eq!(dumped.signal(), Some(11));
        assert_eq!(dumped.shell_code(), 139, "the shell's code takes no flag");
        assert_eq!(dumped.to_string(), "terminated by signal 11 (core dumped)");
        assert_ne!(dumped, ExitStatus::signaled(11));
        assert!(!ExitStatus::signaled(11).core_dumped());
        assert!(!ExitStatus::exited(0).core_dumped());
    }
}
