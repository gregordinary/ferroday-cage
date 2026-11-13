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
    Exited(u8),
    Signaled { signal: i32, core_dumped: bool },
}

impl ExitStatus {
    /// The status of a command that exited normally with `code`.
    ///
    /// A launch reports the status it collected, so a caller has no need of
    /// this to read one. It is for a caller that reports an outcome of its own
    /// in the same terms, and through [`shell_code`](Self::shell_code) in the
    /// same convention, as a status the library collected.
    ///
    /// The code is a `u8` because the kernel reports a process's exit code in
    /// eight bits: whatever a process passes to `exit`, its parent collects the
    /// low eight, so no status outside `0..=255` can be collected, and none can
    /// be made here.
    pub fn exited(code: u8) -> ExitStatus {
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

    /// The exit code, if the command exited normally: in `0..=255`, as an
    /// `i32` to match [`std::process::ExitStatus::code`].
    pub fn code(&self) -> Option<i32> {
        match self.0 {
            Kind::Exited(code) => Some(i32::from(code)),
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
    /// has: `wait` carries eight bits, which is also the width
    /// [`exited`](Self::exited) takes, so an exit code is reported as it is.
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
            Kind::Exited(code) => code,
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
/// command's exit has been collected. It holds two sets of figures, each
/// `None` where its source reported nothing:
///
/// - **The collected processes'**, [`user_time`](Self::user_time),
///   [`system_time`](Self::system_time) and
///   [`peak_rss_bytes`](Self::peak_rss_bytes). The supervisor reads them from
///   the kernel (`getrusage` over its reaped children) right after it collects
///   the command's exit, so they cover the command and every descendant that
///   had exited and been collected by then.
/// - **The whole tree's**, the `cgroup_` fields, read from the sandbox's
///   cgroup where the launch has one: see
///   [`CageBuilder::cgroup_parent`](crate::CageBuilder::cgroup_parent).
///
/// Which descendants the collected processes' figures cover depends on the PID
/// namespace:
///
/// - Under a PID namespace, the default, the sandbox's init collects every
///   process of the namespace that exits, so a descendant counts whether the
///   command waited for it or it was orphaned to the init.
/// - Without one, a descendant counts only through the process that waited for
///   it. An orphan is collected outside the sandbox and is not counted.
///
/// A process still running when the command exits is not counted: under a PID
/// namespace the teardown ends it, and without one it runs on outside the
/// sandbox. A [`kill`](crate::Running::kill) under a PID namespace ends the
/// init before it reports, so a killed sandbox has none of these figures, and
/// only a cgroup's account of it remains.
///
/// [`Running::usage`]: crate::Running::usage
/// [`Output::usage`]: crate::Output::usage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ResourceUsage {
    /// Processor time the collected processes spent in user mode, summed over
    /// them. `None` where the supervisor reported no usage.
    pub user_time: Option<Duration>,
    /// Processor time the kernel spent on the collected processes' behalf,
    /// summed over them. `None` where the supervisor reported no usage.
    pub system_time: Option<Duration>,
    /// The largest resident set size any one of the collected processes
    /// reached, in bytes. `None` where the supervisor reported no usage.
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
    pub peak_rss_bytes: Option<u64>,
    /// Processor time the whole tree spent in user mode, read from the
    /// sandbox's cgroup (`cpu.stat`).
    ///
    /// Where [`user_time`](Self::user_time) counts the processes the sandbox
    /// collected, this counts every process the cgroup held: without a PID
    /// namespace, an orphan collected outside the sandbox, and a process still
    /// running when the outcome was read, up to that moment. `None` without a
    /// cgroup.
    pub cgroup_user_time: Option<Duration>,
    /// Processor time the kernel spent on the whole tree's behalf, read from
    /// the sandbox's cgroup, as [`cgroup_user_time`](Self::cgroup_user_time)
    /// is.
    pub cgroup_system_time: Option<Duration>,
    /// The most memory the whole tree held at once, in bytes: the cgroup's
    /// `memory.peak` (Linux 5.19).
    ///
    /// A sum over the tree's processes at its peak, page cache it caused
    /// included, rather than the largest one process reached. The launching
    /// process's own pages are not charged to the cgroup, so the floor
    /// [`peak_rss_bytes`](Self::peak_rss_bytes) carries does not apply. `None`
    /// without a cgroup, where the parent does not offer the memory
    /// controller, or on a kernel without the file.
    pub cgroup_peak_memory_bytes: Option<u64>,
    /// The most processes and threads the whole tree held at once: the
    /// cgroup's `pids.peak`. `None` without a cgroup, where the parent does not
    /// offer the pids controller, or on a kernel without the file.
    pub cgroup_peak_processes: Option<u64>,
    /// How many processes of the tree the kernel's OOM killer ended because
    /// the cgroup reached its memory limit: `memory.events`' `oom_kill`. A
    /// command its signal says was killed, with a count above zero here, was
    /// most likely killed for memory. `None` where the cgroup has no memory
    /// controller, or without a cgroup.
    pub cgroup_oom_kills: Option<u64>,
}

impl ResourceUsage {
    /// What the supervisor read for the processes it collected, before
    /// anything is read from a cgroup.
    pub(crate) fn of_processes(
        user_time: Duration,
        system_time: Duration,
        peak_rss_bytes: u64,
    ) -> ResourceUsage {
        ResourceUsage {
            user_time: Some(user_time),
            system_time: Some(system_time),
            peak_rss_bytes: Some(peak_rss_bytes),
            cgroup_user_time: None,
            cgroup_system_time: None,
            cgroup_peak_memory_bytes: None,
            cgroup_peak_processes: None,
            cgroup_oom_kills: None,
        }
    }

    /// What the supervisor reported, `processes`, joined with what the
    /// sandbox's cgroup read for the whole tree: `None` only where neither
    /// holds a figure.
    ///
    /// A killed sandbox under a PID namespace has no report from its
    /// supervisor, and its cgroup's figures are then the whole account.
    pub(crate) fn joined(
        processes: Option<ResourceUsage>,
        tree: crate::cgroup::CgroupUsage,
    ) -> Option<ResourceUsage> {
        let crate::cgroup::CgroupUsage {
            user_time,
            system_time,
            peak_memory_bytes,
            peak_processes,
            oom_kills,
        } = tree;
        let joined = ResourceUsage {
            cgroup_user_time: user_time,
            cgroup_system_time: system_time,
            cgroup_peak_memory_bytes: peak_memory_bytes,
            cgroup_peak_processes: peak_processes,
            cgroup_oom_kills: oom_kills,
            ..processes.unwrap_or(ResourceUsage {
                user_time: None,
                system_time: None,
                peak_rss_bytes: None,
                cgroup_user_time: None,
                cgroup_system_time: None,
                cgroup_peak_memory_bytes: None,
                cgroup_peak_processes: None,
                cgroup_oom_kills: None,
            })
        };
        let figures = [
            joined.user_time.is_some(),
            joined.system_time.is_some(),
            joined.peak_rss_bytes.is_some(),
            joined.cgroup_user_time.is_some(),
            joined.cgroup_system_time.is_some(),
            joined.cgroup_peak_memory_bytes.is_some(),
            joined.cgroup_peak_processes.is_some(),
            joined.cgroup_oom_kills.is_some(),
        ];
        figures.contains(&true).then_some(joined)
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

    #[test]
    fn a_cgroup_s_figures_stand_alone_where_the_supervisor_reported_none() {
        let tree = crate::cgroup::CgroupUsage {
            user_time: Some(Duration::from_millis(30)),
            peak_memory_bytes: Some(1 << 20),
            ..Default::default()
        };
        let killed = ResourceUsage::joined(None, tree).expect("the cgroup has figures");
        assert_eq!(killed.user_time, None);
        assert_eq!(killed.peak_rss_bytes, None);
        assert_eq!(killed.cgroup_user_time, Some(Duration::from_millis(30)));
        assert_eq!(killed.cgroup_peak_memory_bytes, Some(1 << 20));

        let reported = ResourceUsage::of_processes(Duration::from_millis(20), Duration::ZERO, 4096);
        let joined = ResourceUsage::joined(Some(reported), tree).expect("both have figures");
        assert_eq!(joined.user_time, Some(Duration::from_millis(20)));
        assert_eq!(joined.cgroup_user_time, Some(Duration::from_millis(30)));

        let unread = crate::cgroup::CgroupUsage::default();
        assert_eq!(
            ResourceUsage::joined(None, unread),
            None,
            "nothing to report"
        );
        assert_eq!(
            ResourceUsage::joined(Some(reported), unread),
            Some(reported)
        );
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
