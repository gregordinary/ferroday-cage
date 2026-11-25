//! The native network stack's reports, written on standard error.
//!
//! The stack reports each flow of the sandbox's that it carries or refuses, and
//! each question its nameserver relays or refuses, and why. Under destination
//! rules, `--netstack-allow` or `--netstack-deny`, `fcage` writes every
//! refusal, so the command's caller reads why a connection or a lookup failed.
//! `--netstack-log` writes every report, carried flows and relayed questions
//! too, which with no rules is a log of where the sandbox goes, by name. Each
//! is one line, or on an event stream one `network` event:
//!
//! ```text
//! fcage: the network stack refused tcp from 10.0.2.15:41234 to 192.0.2.1:443: no allow rule admits it
//! fcage: the network stack refused the A question for example.net from 10.0.2.15:53140: no allow rule admits it
//! ```
//!
//! A thread of its own takes the reports from the stack and hands each line to
//! the run's [`Reports`](crate::output::Reports) thread, which the forwards'
//! reports share, so neither the stack nor this thread waits on standard
//! error's reader. The stack drops a report its queue has no room for, and the
//! writer one it holds no room for. Each counts what it dropped, and the count
//! is written once the run ends.

use std::io;
use std::thread::JoinHandle;

use ferroday_cage::{NetStackReport, Reports};

use crate::events::{self, Event};
use crate::output::Reporter;

/// Which of the stack's reports a run writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shown {
    /// Its refusals: a run with destination rules.
    Refusals,
    /// Every report: a run with `--netstack-log`.
    Every,
}

impl Shown {
    /// What a run writes: every report under `--netstack-log`, the refusals
    /// where it has destination rules, and nothing otherwise.
    pub(crate) fn of(log: bool, ruled: bool) -> Option<Shown> {
        match (log, ruled) {
            (true, _) => Some(Shown::Every),
            (false, true) => Some(Shown::Refusals),
            (false, false) => None,
        }
    }
}

/// The thread that hands the stack's reports to the run's writer.
pub(crate) struct StackReports {
    /// The thread, which ends once the stack has stopped and every report has
    /// been handed on.
    thread: JoinHandle<()>,
}

impl StackReports {
    /// Starts handing the reports `shown` selects from `reports` to
    /// `reporter`.
    pub(crate) fn start(
        reports: Reports<NetStackReport>,
        shown: Shown,
        reporter: Reporter,
    ) -> io::Result<StackReports> {
        let thread = std::thread::Builder::new()
            .name("fcage-netstack-reports".to_string())
            .spawn(move || hand_on(&reports, shown, &reporter))?;
        Ok(StackReports { thread })
    }

    /// Waits until every report has been handed on, which is once the stack
    /// has stopped.
    pub(crate) fn finish(self) {
        // A thread that panicked has nothing left to hand on.
        let _ = self.thread.join();
    }
}

/// Hands each report `shown` selects to `reporter`, as a line of `fcage`'s,
/// until the stack has stopped, and then how many reports the stack dropped,
/// where it dropped any.
fn hand_on(reports: &Reports<NetStackReport>, shown: Shown, reporter: &Reporter) {
    while let Ok(report) = reports.recv() {
        if shown == Shown::Every || report.is_refusal() {
            reporter.offer(events::network(&report));
        }
    }
    let dropped = reports.dropped();
    if dropped > 0 {
        let plural = if dropped == 1 { "" } else { "s" };
        reporter.offer(Event::dropped(
            "network",
            dropped,
            format!(
                "fcage: the network stack dropped {dropped} report{plural} its queue had no room \
                 for"
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_writes_what_its_flags_ask_for() {
        assert_eq!(Shown::of(false, false), None);
        assert_eq!(Shown::of(false, true), Some(Shown::Refusals));
        assert_eq!(Shown::of(true, false), Some(Shown::Every));
        assert_eq!(Shown::of(true, true), Some(Shown::Every));
    }
}
