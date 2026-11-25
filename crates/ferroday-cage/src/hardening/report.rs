//! The seccomp filter's reports: each call it refuses the command, delivered to
//! the caller without the command waiting on a reader.
//!
//! The listener thread in `mechanism::listener` makes them; this is the public
//! shape they take.

use std::fmt;

/// A call the command's seccomp filter refused, as
/// [`Running::take_seccomp_reports`](crate::Running::take_seccomp_reports)
/// delivers it.
///
/// A filter whose refusals are reported
/// ([`seccomp_reports`](crate::CageBuilder::seccomp_reports)) holds each call
/// its policy answers with an errno, and the caller answers it with that errno
/// and reports it. A call answered `ENOSYS` is not reported: the answer tells
/// the command the call does not exist, so that it falls back, as the curated
/// roster answers `clone3`. Nor is a call the launch's own filters refuse, nor
/// one the policy answers by ending the thread or the process.
///
/// [`Display`](fmt::Display) writes a report as one line:
///
/// ```text
/// denied mount to thread 48213 (mount): EPERM
/// denied ioctl to thread 48230 (sh): EPERM
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeccompReport {
    /// The filter refused a call, which returned the errno the policy answers
    /// it with.
    #[non_exhaustive]
    Denied {
        /// The syscall's number, in the table of the architecture the call
        /// was made under.
        syscall: i64,
        /// The syscall's name, where the call was made under the build's own
        /// architecture and its table names the number.
        name: Option<&'static str>,
        /// The audit architecture (`AUDIT_ARCH_*`) the call was made under.
        arch: u32,
        /// The thread that made the call: its id in the caller's PID namespace.
        thread: u32,
        /// The name of the program the thread runs (`/proc/<thread>/comm`),
        /// where it could be read.
        command: Option<String>,
        /// The call's six arguments, as the registers held them. A pointer is
        /// not followed: what it points at belongs to the command, and a thread
        /// of its own could change it before anything read it.
        arguments: [u64; 6],
        /// The errno the call returned.
        errno: u16,
    },
}

impl fmt::Display for SeccompReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeccompReport::Denied {
                syscall,
                name,
                arch,
                thread,
                command,
                errno,
                arguments: _,
            } => {
                write!(f, "denied ")?;
                match name {
                    Some(name) => write!(f, "{name}")?,
                    None => write!(f, "syscall {syscall} (audit architecture {arch:#x})")?,
                }
                write!(f, " to thread {thread}")?;
                if let Some(command) = command {
                    write!(f, " ({})", command.escape_debug())?;
                }
                match syscalls::Errno::new(i32::from(*errno)).name() {
                    Some(errno) => write!(f, ": {errno}"),
                    None => write!(f, ": errno {errno}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied(name: Option<&'static str>, command: Option<&str>, errno: u16) -> SeccompReport {
        SeccompReport::Denied {
            syscall: 165,
            name,
            arch: 0xC000_003E,
            thread: 48213,
            command: command.map(str::to_string),
            arguments: [0; 6],
            errno,
        }
    }

    #[test]
    fn a_report_reads_as_one_line() {
        assert_eq!(
            denied(Some("mount"), Some("mount"), 1).to_string(),
            "denied mount to thread 48213 (mount): EPERM"
        );
        // A name the table lacks, a command that could not be read, an errno
        // without a name.
        assert_eq!(
            denied(None, None, 4000).to_string(),
            "denied syscall 165 (audit architecture 0xc000003e) to thread 48213: errno 4000"
        );
    }

    #[test]
    fn a_command_name_cannot_break_the_line() {
        // A program names itself, so its name is the command's to choose.
        let line = denied(Some("mount"), Some("a\nb\u{1b}[2J"), 1).to_string();
        assert!(!line.contains('\n') && !line.contains('\u{1b}'), "{line}");
    }
}
