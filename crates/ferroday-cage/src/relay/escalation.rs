//! The bounded-stop policy: what a passed deadline sends the sandbox.

use std::time::{Duration, Instant};

use crate::error::Error;
use crate::running::Running;
use crate::status::ExitStatus;

/// What a passed deadline sends the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signalled {
    /// `SIGTERM` to the command, which it may act on or ignore.
    Terminate,
    /// `SIGKILL` to the supervisor: with a PID namespace nothing inside
    /// survives it, and without one it reaches the command alone.
    Kill,
    /// Nothing: the kill has already been sent.
    Nothing,
}

/// How far the escalation has gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Running normally; the deadline is the caller's timeout.
    Running,
    /// Terminated once; the deadline is the grace before the kill.
    Terminated,
    /// Killed; no deadline remains.
    Killed,
}

/// A bounded stop: the deadline a waiter honours, and what happens each time
/// one passes.
///
/// The policy is the one `timeout(1)` established and the guide's process model
/// documents as the bounded-stop recipe: at the deadline the command is asked to
/// stop, and if it has not stopped by the end of the grace it is killed. The run
/// then reports no status whatever became of the command afterwards, because
/// what the caller asked about is whether it finished in time.
///
/// This is a value the caller composes rather than anything the library does on
/// its own. [`Running`]'s waits still kill nothing: a deadline of theirs reports
/// that it passed and leaves the command running, because escalation is a
/// decision about the caller's program rather than about the sandbox. What this
/// type adds is that the decision is *stated once* — an interactive session
/// drives it from [`Relay::run`](crate::relay::Relay::run) until the command's
/// exit is collected, whether or not the command's terminal is still open, and
/// a plain wait drives the same value from a loop of its own, so the two cannot
/// disagree about what a timeout means.
///
/// # The deadline runs from construction
///
/// [`new`](Self::new) reads the clock, so the timeout is measured from there
/// rather than from the first wait. Build it where the run begins.
///
/// # A plain wait
///
/// ```no_run
/// use std::time::Duration;
///
/// use ferroday_cage::relay::Escalation;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let cage = ferroday_cage::Cage::builder().rootfs("/r").command("/bin/sh").build()?;
/// let mut running = cage.spawn()?;
/// let mut escalation = Escalation::new(Some(Duration::from_secs(30)), Duration::from_secs(5));
/// let status = loop {
///     // No deadline left: either none was asked for, or the escalation has run
///     // its course and only the outcome is outstanding.
///     let Some(deadline) = escalation.deadline() else {
///         break running.wait()?;
///     };
///     match running.wait_deadline(deadline)? {
///         Some(status) => break status,
///         None => escalation.expire(&mut running)?,
///     }
/// };
/// // `None` where the deadline passed, whatever the command did afterwards.
/// let outcome = escalation.outcome(status);
/// # let _ = outcome;
/// # Ok(())
/// # }
/// ```
/// Deliberately neither `Clone` nor `Copy`: an escalation is a run's own state,
/// advanced as its deadlines pass, so a second value holding the first's
/// progress would report an expiry that had not happened to it, or miss one that
/// had. Handing one to [`Relay::escalation`](super::Relay::escalation) moves it,
/// for the same reason.
#[derive(Debug)]
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
    /// The escalation a run starts in: `timeout` until the termination request,
    /// then `kill_after` until the kill.
    ///
    /// `None` is a run without a deadline, which escalates to nothing and waits
    /// for the command's own end.
    ///
    /// A timeout too large for the clock to express becomes no deadline at all,
    /// rather than a panic on the addition: a caller asking to wait some
    /// hundreds of billions of years is asking to wait, and
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

    /// Whether the current stage's deadline has passed and
    /// [`expire`](Self::expire) is owed.
    ///
    /// A waiter that sleeps *on* the deadline can tell it passed by how it woke
    /// up; a relay cannot, because it wakes on descriptors as well, and once the
    /// deadline is behind it every wakeup is a wakeup with a zero timeout left.
    /// Asking the question rather than inferring it from a timed-out sleep is
    /// what makes the escalation a consequence of the clock rather than of what
    /// the sandbox happened to be printing.
    pub fn passed(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Acts on the deadline that has just passed and moves to the next stage.
    ///
    /// The termination request is a `SIGTERM` the command may trap, clean up
    /// under, or ignore. The kill takes the sandbox's supervisor, and with a
    /// PID namespace everything inside goes with it; without one it reaches
    /// the command alone, as [`Running::kill`] states. Either way the command
    /// has exited once the kill lands, which is what a waiter collects. Called
    /// by a waiter whose own deadline passed; on the final stage there is
    /// nothing left to send and it does nothing.
    pub fn expire(&mut self, running: &mut Running<'_>) -> Result<(), Error> {
        match self.advance() {
            Signalled::Terminate => running.terminate(),
            Signalled::Kill => running.kill(),
            Signalled::Nothing => Ok(()),
        }
    }

    /// The outcome a run reports, given the status it collected: the status
    /// itself, or `None` where a deadline passed.
    ///
    /// `None` survives a command that stopped on the termination request and
    /// exited normally within the grace, which is deliberate: the run is
    /// reported as timed out because it was, and the caller who set the deadline
    /// is the one who wants to hear so.
    pub fn outcome(&self, status: ExitStatus) -> Option<ExitStatus> {
        (!self.expired).then_some(status)
    }

    /// Moves to the next stage and reports what the sandbox is to be sent.
    ///
    /// Separate from [`expire`](Self::expire) so the sequence can be pinned by a
    /// test without a sandbox to send anything to. A waiter calls this only when
    /// its own deadline passed, so the final stage has nothing left to do; it is
    /// written out rather than left to an assumption about who calls it.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRACE: Duration = Duration::from_secs(10);

    // `expired` is what `outcome` reports through, and an `ExitStatus` is not
    // constructible without a launch, so the flag itself is what these assert
    // on.

    #[test]
    fn a_run_without_a_timeout_waits_and_reports_what_it_waited_for() {
        let escalation = Escalation::new(None, GRACE);
        assert_eq!(escalation.deadline(), None);
        assert!(!escalation.expired);
    }

    #[test]
    fn a_timeout_the_clock_cannot_express_is_a_run_without_one() {
        // The addition would otherwise panic, which is what a timeout of some
        // hundreds of billions of years would have bought.
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
    fn a_passed_deadline_is_reported_by_the_clock_alone() {
        // What a relay asks on every wakeup, however it woke: it polls on
        // descriptors as well as on the deadline, so it cannot read the expiry
        // off a timed-out sleep the way a plain wait does.
        let mut escalation = Escalation::new(Some(Duration::from_secs(60)), GRACE);
        assert!(!escalation.passed(), "the timeout has not run out");

        // A deadline already behind the run, reached the way the escalation
        // itself reaches one rather than by editing the field.
        escalation.deadline = Instant::now().checked_sub(Duration::from_secs(1));
        assert!(escalation.passed());

        // And after the kill there is no deadline left to pass, so nothing is
        // owed however long the command goes on running.
        escalation.advance();
        escalation.advance();
        assert_eq!(escalation.deadline(), None);
        assert!(!escalation.passed());
    }

    #[test]
    fn a_run_without_a_timeout_has_no_deadline_to_pass() {
        let escalation = Escalation::new(None, GRACE);
        assert!(!escalation.passed());
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
        // The `timeout(1)` convention: the expiry answers the question the
        // caller asked, which was whether the command finished in time.
        let mut escalation = Escalation::new(Some(Duration::from_secs(60)), GRACE);
        escalation.advance();
        assert!(
            escalation.expired,
            "the run is reported as timed out however the command ended",
        );
    }
}
