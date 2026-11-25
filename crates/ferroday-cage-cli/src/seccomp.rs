//! The seccomp filter's reports, written on standard error.
//!
//! With `--seccomp-reports`, or `seccomp-reports = true` in a profile's
//! `[hardening]` table, the launch reports each call its seccomp filter refuses
//! the command, and `fcage` writes each as one line, or on an event stream one
//! `seccomp` event, so the command's caller reads which call failed and why:
//!
//! ```text
//! fcage: the seccomp filter denied mount to thread 48213 (mount): EPERM
//! ```
//!
//! A thread of its own reads the reports and writes each line. The filter
//! never waits on that thread: the library drops a report its queue has no room
//! for, and counts it, and the count is written once the reports end.

use std::io;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

use ferroday_cage::{ErrorChain, Reports, Running, SeccompReport};

use crate::events::{self, Event};
use crate::output;

/// How long a run waits, once the command has exited, for the last of the
/// reports.
///
/// They end once no process under the filter is left, which with a PID
/// namespace is as soon as the sandbox has gone. Without one, a process the
/// command left behind holds them open, and the run does not wait for it.
const LAST_REPORTS: Duration = Duration::from_secs(2);

/// Runs `wait` over `running`, writing the seccomp filter's refusals while it
/// waits, where the launch reports them, and the last of them once it has.
///
/// Every way a run waits for its command goes through here, so a refusal is
/// written however the run started.
pub(crate) fn writing_refusals<'obs, T>(
    mut running: Running<'obs>,
    wait: impl FnOnce(Running<'obs>) -> T,
) -> T {
    let refusals = FilterReports::start(&mut running);
    let outcome = wait(running);
    if let Some(refusals) = refusals {
        refusals.finish();
    }
    outcome
}

/// The thread that writes the seccomp filter's reports.
struct FilterReports {
    /// Hangs up once the thread has written the last report.
    written: Receiver<()>,
    /// The thread.
    thread: JoinHandle<()>,
}

impl FilterReports {
    /// Takes the seccomp filter's reports from `running` and starts writing
    /// them, where the launch makes them.
    ///
    /// The command already runs, so a thread that cannot start is said and the
    /// run goes on without its reports; the filter refuses as it would without
    /// them.
    fn start(running: &mut Running<'_>) -> Option<FilterReports> {
        let reports = running.take_seccomp_reports()?;
        match FilterReports::writing(reports) {
            Ok(started) => Some(started),
            Err(err) => {
                output::report(format_args!(
                    "fcage: starting the thread that writes the seccomp filter's reports: {}",
                    ErrorChain::new(&err)
                ));
                None
            }
        }
    }

    /// Starts the thread that writes `reports`.
    fn writing(reports: Reports<SeccompReport>) -> io::Result<FilterReports> {
        let (done, written) = std::sync::mpsc::sync_channel(0);
        let thread = std::thread::Builder::new()
            .name("fcage-seccomp-reports".to_string())
            .spawn(move || {
                write_all(&reports);
                drop(done);
            })?;
        Ok(FilterReports { written, thread })
    }

    /// Waits for the last report to be written, once the command has exited.
    ///
    /// Where a process the command left behind still runs under the filter
    /// after [`LAST_REPORTS`], the run says so and goes on without it.
    fn finish(self) {
        match self.written.recv_timeout(LAST_REPORTS) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                // A thread that panicked has nothing left to write.
                let _ = self.thread.join();
            }
            Err(RecvTimeoutError::Timeout) => output::report(format_args!(
                "fcage: a process the command left behind still runs under the seccomp \
                 filter, and what it refuses from here on is not written"
            )),
        }
    }
}

/// Writes each report until the reports end, and then how many the filter
/// dropped, where it dropped any.
fn write_all(reports: &Reports<SeccompReport>) {
    while let Ok(report) = reports.recv() {
        output::report_event(&events::seccomp(&report));
    }
    let dropped = reports.dropped();
    if dropped > 0 {
        let plural = if dropped == 1 { "" } else { "s" };
        output::report_event(&Event::dropped(
            "seccomp",
            dropped,
            format!(
                "fcage: the seccomp filter dropped {dropped} report{plural} its queue had no room \
                 for"
            ),
        ));
    }
}
