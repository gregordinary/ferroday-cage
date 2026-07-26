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
}
