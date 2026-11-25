//! Report queues: what a part of the library tells its caller as it works,
//! delivered without that part waiting on a reader.
//!
//! The part that makes the reports offers each one through its [`Reporter`]
//! to a queue of [`QUEUED_REPORTS`], and the caller reads them from the
//! queue's other end, a [`Reports`]. A report the queue has no room for is
//! dropped and counted, so a reader that falls behind, or never reads, costs
//! reports and never the work they describe. The network stack's pump serves
//! every flow of the sandbox on one thread, and a wait on a reader would stall
//! them all.
//!
//! `fcage` hands its own lines to standard error the same way, through its
//! `output::Reports`. The two do not share code, since the CLI's queue is the
//! CLI's and this one is part of the library's API.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{
    Receiver, RecvError, RecvTimeoutError, SyncSender, TryRecvError, TrySendError,
};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// The most reports a queue holds for its reader before a further one is
/// dropped.
///
/// Each slot holds a pointer to its report, since the queue allocates every
/// slot when it is made: a source whose caller never reads its reports holds
/// those 1024 reports at most, and the empty queue costs a few kilobytes.
pub(crate) const QUEUED_REPORTS: usize = 1024;

/// The receiving end of a stream of reports.
///
// Each source is feature-gated, so the sentence naming it, and its intra-doc
// link, is gated with it, per the crate-level convention.
#[cfg_attr(
    feature = "netstack",
    doc = "The network stack's decisions arrive in one, from
[`NetStackHandle::take_reports`](crate::NetStackHandle::take_reports)."
)]
#[cfg_attr(
    feature = "hardening",
    doc = "A seccomp filter's refusals arrive in one, from
[`Running::take_seccomp_reports`](crate::Running::take_seccomp_reports)."
)]
///
/// Whatever makes the reports never waits on their reader. The queue holds
/// 1024 reports, and a report it has no room for is dropped and counted, which
/// [`dropped`](Self::dropped) answers. A reader that keeps up therefore loses
/// nothing, and one that falls behind, or never reads, loses reports and
/// nothing else.
///
/// The reports end once their source has finished and every report it queued
/// has been read: [`recv`](Self::recv) then answers [`RecvError`]. Each source
/// says when it finishes. A thread that reads them in a loop therefore ends
/// having read everything.
///
/// One reader reads at a time: a second thread's call waits for the first's to
/// return.
pub struct Reports<T> {
    /// The queue's receiving end. The queue's own receiver can serve only one
    /// thread, and the lock is what lets this be shared.
    queue: Mutex<Receiver<Box<T>>>,
    /// How many reports the queue had no room for.
    dropped: Arc<AtomicU64>,
}

impl<T> Reports<T> {
    /// Waits for the next report.
    ///
    /// Answers [`RecvError`] once the source has finished and every report has
    /// been read.
    pub fn recv(&self) -> Result<T, RecvError> {
        self.queue().recv().map(|report| *report)
    }

    /// Takes the next report, if one is waiting.
    ///
    /// Answers [`TryRecvError::Empty`] where none is, and
    /// [`TryRecvError::Disconnected`] once the source has finished and every
    /// report has been read.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        self.queue().try_recv().map(|report| *report)
    }

    /// Waits for the next report, for at most `timeout`.
    ///
    /// Answers [`RecvTimeoutError::Timeout`] where none arrived in that time,
    /// and [`RecvTimeoutError::Disconnected`] once the source has finished and
    /// every report has been read.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<T, RecvTimeoutError> {
        self.queue().recv_timeout(timeout).map(|report| *report)
    }

    /// How many reports the source has dropped so far because the queue was
    /// full.
    ///
    /// The count is final once [`recv`](Self::recv) has answered
    /// [`RecvError`], since the source has finished by then.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The queue, which nothing that can panic ever holds.
    fn queue(&self) -> MutexGuard<'_, Receiver<Box<T>>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<T> fmt::Debug for Reports<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reports")
            .field("dropped", &self.dropped())
            .finish_non_exhaustive()
    }
}

/// Where a source offers its reports: the sending end of the queue a
/// [`Reports`] reads.
pub(crate) struct Reporter<T> {
    /// The queue, or `None` once its receiving end is gone, after which the
    /// source makes no report at all.
    queue: Option<SyncSender<Box<T>>>,
    /// How many reports the queue had no room for, which the receiving end
    /// reads.
    dropped: Arc<AtomicU64>,
}

impl<T> Reporter<T> {
    /// A reporter, and the receiving end of its queue, which holds
    /// [`QUEUED_REPORTS`].
    pub(crate) fn new() -> (Reporter<T>, Reports<T>) {
        Reporter::holding(QUEUED_REPORTS)
    }

    /// A reporter whose queue holds `capacity` reports, and the queue's
    /// receiving end.
    pub(crate) fn holding(capacity: usize) -> (Reporter<T>, Reports<T>) {
        let (queue, received) = std::sync::mpsc::sync_channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        (
            Reporter {
                queue: Some(queue),
                dropped: Arc::clone(&dropped),
            },
            Reports {
                queue: Mutex::new(received),
                dropped,
            },
        )
    }

    /// Offers the report `report` makes to the queue, or drops it and counts
    /// it where the queue is full. Never waits.
    ///
    /// The report is made only where its receiving end is still there to read
    /// it.
    pub(crate) fn offer(&mut self, report: impl FnOnce() -> T) {
        let Some(queue) = &self.queue else {
            return;
        };
        match queue.try_send(Box::new(report())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => self.queue = None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_queue_drops_and_counts_and_never_waits() {
        let (mut reporter, reports) = Reporter::holding(4);
        for index in 0..10 {
            reporter.offer(|| index);
        }
        assert_eq!(reports.dropped(), 6);
        // The four the queue held are the first four, in order.
        for index in 0..4 {
            assert_eq!(reports.try_recv(), Ok(index));
        }
        assert_eq!(reports.try_recv(), Err(TryRecvError::Empty));
        // Room again, so the next is queued.
        reporter.offer(|| 10);
        assert_eq!(reports.try_recv(), Ok(10));
        assert_eq!(reports.dropped(), 6);
    }

    #[test]
    fn the_reports_end_once_the_source_has_finished_and_they_are_read() {
        let (mut reporter, reports) = Reporter::holding(4);
        reporter.offer(|| 0);
        drop(reporter);
        assert_eq!(reports.recv(), Ok(0));
        assert_eq!(reports.recv(), Err(RecvError));
        assert_eq!(
            reports.recv_timeout(Duration::from_millis(10)),
            Err(RecvTimeoutError::Disconnected)
        );
        assert_eq!(reports.try_recv(), Err(TryRecvError::Disconnected));
    }

    #[test]
    fn nothing_is_made_once_the_receiving_end_is_gone() {
        let (mut reporter, reports) = Reporter::<u32>::holding(4);
        drop(reports);
        // The first offer finds the receiving end gone; neither it nor any
        // later offer is counted, and no later report is made at all.
        reporter.offer(|| 0);
        let mut made = false;
        reporter.offer(|| {
            made = true;
            1
        });
        assert!(!made);
    }
}
