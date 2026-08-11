//! The exit status of a sandboxed command.

use std::fmt;

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
    Signaled(i32),
}

impl ExitStatus {
    /// A status for a command that exited normally with `code`.
    pub(crate) fn exited(code: i32) -> ExitStatus {
        ExitStatus(Kind::Exited(code))
    }

    /// A status for a command terminated by signal number `signal`.
    pub(crate) fn signaled(signal: i32) -> ExitStatus {
        ExitStatus(Kind::Signaled(signal))
    }

    /// Returns `true` if the command exited normally with code `0`.
    pub fn success(&self) -> bool {
        self.code() == Some(0)
    }

    /// The exit code, if the command exited normally.
    pub fn code(&self) -> Option<i32> {
        match self.0 {
            Kind::Exited(code) => Some(code),
            Kind::Signaled(_) => None,
        }
    }

    /// The signal number that terminated the command, if it was terminated
    /// by a signal.
    pub fn signal(&self) -> Option<i32> {
        match self.0 {
            Kind::Exited(_) => None,
            Kind::Signaled(signal) => Some(signal),
        }
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
            Kind::Signaled(signal) => 128_u8.wrapping_add(signal as u8),
        }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Kind::Exited(code) => write!(f, "exit code {code}"),
            Kind::Signaled(signal) => write!(f, "terminated by signal {signal}"),
        }
    }
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
}
