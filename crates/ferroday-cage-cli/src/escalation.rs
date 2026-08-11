//! What `--timeout` does when it runs out.
//!
//! The policy is the one `timeout(1)` established and the library's process
//! model documents as the bounded-stop recipe: at the deadline the command is
//! asked to stop, and if it has not stopped by the end of the `--kill-after`
//! grace it is killed. The run then reports 124 whatever became of the command
//! afterwards, because what the caller asked about is whether it finished in
//! time.
//!
//! `fcage` waits a launch out in two places — a plain blocking wait, and the
//! terminal relay's poll loop, which must keep moving bytes while the
//! escalation happens — so the policy is stated here, as a value both drive,
//! and each keeps only its own way of waiting. The library deliberately does
//! not offer this: a deadline of its own kills nothing, because escalation is a
//! decision about the caller's program rather than about the sandbox.

use std::time::{Duration, Instant};

use ferroday_cage::{Error, ExitStatus, Running};

/// What a passed deadline sends the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signalled {
    /// `SIGTERM` to the command, which it may act on or ignore.
    Terminate,
    /// `SIGKILL` to the supervisor, which nothing inside survives.
    Kill,
    /// Nothing: the kill has already been sent.
    Nothing,
}

/// How far the escalation has gone.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Running normally; the deadline is the caller's `--timeout`.
    Running,
    /// Terminated once; the deadline is the `--kill-after` grace.
    Terminated,
    /// Killed; no deadline remains.
    Killed,
}

/// The `--timeout` policy: the deadline a waiter honours, and what happens each
/// time one passes.
pub struct Escalation {
    stage: Stage,
    /// The grace between the termination request and the kill.
    kill_after: Duration,
    /// When the current stage runs out, or `None` where nothing is waited for
    /// beyond the command's own end.
    deadline: Option<Instant>,
    /// Whether a deadline has passed at all, which is what the run reports.
    expired: bool,
}

impl Escalation {
    /// The escalation a run starts in.
    ///
    /// A `--timeout` too large for the clock to express becomes no deadline at
    /// all, rather than a panic on the addition: a caller asking to wait some
    /// hundreds of billions of years is asking to wait, and the library's own
    /// [`Running::wait_timeout`] reads such a timeout the same way.
    pub fn new(timeout: Option<Duration>, kill_after: Duration) -> Escalation {
        Escalation {
            stage: Stage::Running,
            kill_after,
            deadline: timeout.and_then(|timeout| Instant::now().checked_add(timeout)),
            expired: false,
        }
    }

    /// The instant the current stage runs out, or `None` where the waiter has
    /// only the command's own end left to wait for.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Acts on the deadline that has just passed and moves to the next stage.
    ///
    /// The termination request is a `SIGTERM` the command may trap, clean up
    /// under, or ignore; the kill takes the sandbox's supervisor and, with it,
    /// everything inside.
    pub fn expire(&mut self, running: &mut Running<'_>) -> Result<(), Error> {
        match self.advance() {
            Signalled::Terminate => running.terminate(),
            Signalled::Kill => running.kill(),
            Signalled::Nothing => Ok(()),
        }
    }

    /// Moves to the next stage and reports what the sandbox is to be sent.
    ///
    /// Separate from [`expire`](Self::expire) so the sequence can be pinned by
    /// a test without a sandbox to send anything to. A waiter calls this only
    /// when its own deadline passed, so the final stage has nothing left to do;
    /// it is written out rather than left to an assumption about who calls it.
    fn advance(&mut self) -> Signalled {
        self.expired = true;
        match self.stage {
            Stage::Running => {
                self.stage = Stage::Terminated;
                self.deadline = Instant::now().checked_add(self.kill_after);
                Signalled::Terminate
            }
            Stage::Terminated => {
                self.stage = Stage::Killed;
                self.deadline = None;
                Signalled::Kill
            }
            Stage::Killed => {
                self.deadline = None;
                Signalled::Nothing
            }
        }
    }

    /// The outcome a run reports, given the status it collected: the status
    /// itself, or `None` where the timeout expired.
    ///
    /// `None` survives a command that stopped on the termination request and
    /// exited normally within the grace, which is deliberate: the run is
    /// reported as timed out because it was, and the caller who set the
    /// deadline is the one who wants to hear so.
    pub fn outcome(&self, status: ExitStatus) -> Option<ExitStatus> {
        (!self.expired).then_some(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRACE: Duration = Duration::from_secs(10);

    // `expired` is what `outcome` reports through, and an `ExitStatus` is the
    // library's to construct, so the flag itself is what these assert on.

    #[test]
    fn a_run_without_a_timeout_waits_and_reports_what_it_waited_for() {
        let escalation = Escalation::new(None, GRACE);
        assert_eq!(escalation.deadline(), None);
        assert!(!escalation.expired);
    }

    #[test]
    fn a_timeout_the_clock_cannot_express_is_a_run_without_one() {
        // The addition would otherwise panic, which is what a `--timeout` of
        // some hundreds of billions of years would have bought.
        let escalation = Escalation::new(Some(Duration::MAX), GRACE);
        assert_eq!(escalation.deadline(), None);
        assert!(!escalation.expired);
    }

    #[test]
    fn the_first_deadline_is_the_timeout_and_the_second_is_the_grace() {
        let mut escalation = Escalation::new(Some(Duration::from_secs(60)), GRACE);
        let first = escalation.deadline().expect("a timeout sets a deadline");
        assert!(first > Instant::now());

        assert_eq!(escalation.advance(), Signalled::Terminate);
        let second = escalation.deadline().expect("the grace sets a deadline");
        assert!(
            second < first,
            "the grace hangs off the expiry, not off the start",
        );
    }

    #[test]
    fn escalation_runs_terminate_then_kill_and_then_stops() {
        let mut escalation = Escalation::new(Some(Duration::from_secs(60)), GRACE);
        assert_eq!(escalation.advance(), Signalled::Terminate);
        assert_eq!(escalation.advance(), Signalled::Kill);
        assert_eq!(
            escalation.deadline(),
            None,
            "nothing is waited for after the kill",
        );
        assert_eq!(escalation.advance(), Signalled::Nothing);
        assert_eq!(escalation.deadline(), None);
    }

    #[test]
    fn an_expired_run_reports_no_status_whatever_it_collects() {
        // The `timeout(1)` convention: 124 answers the question the caller
        // asked, which was whether the command finished in time.
        let mut escalation = Escalation::new(Some(Duration::from_secs(60)), GRACE);
        escalation.advance();
        assert!(
            escalation.expired,
            "the run is reported as timed out however the command ended",
        );
    }
}
