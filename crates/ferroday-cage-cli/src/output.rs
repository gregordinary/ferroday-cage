//! `fcage`'s own writes to its standard streams.
//!
//! Rust ignores `SIGPIPE`, so a write to a pipe whose reader has gone fails
//! with `EPIPE` rather than ending the process. The `print!` family panics on
//! that failure: exit 101, and a panic message nobody reads, where a shell
//! expects what a process `SIGPIPE` ended exits with, 141. Every write `fcage`
//! makes of its own goes through here instead, so a reader gone is an outcome
//! rather than a panic.
//!
//! What the outcome is depends on what the write was for:
//!
//! - Output that is the invocation's purpose, such as the help, the version, or
//!   a listing, ends it with 141 when its reader goes ([`print_stdout`]).
//! - A line written while work remains, such as a warning before a launch or a
//!   provisioning run's progress, stops that work at the first point it can
//!   stop cleanly, and the invocation exits 141 ([`say`]). That is what a
//!   shell's `| head` asks of a producer, and what a C program would do by
//!   dying of the signal at the write.
//! - A line reporting how the invocation ended leaves that ending as it was
//!   ([`report`]). A failure still exits 125 and a usage error 2; only the
//!   words are lost.
//!
//! Any other failure to write a diagnostic is dropped. There is nowhere left to
//! report it, and the exit code carries the outcome whatever became of the
//! words.
//!
//! # Reports from a thread that carries data
//!
//! Each of the above writes standard error where it is called, and waits for
//! as long as the reader takes. A thread that carries data, such as a
//! forward's, must not: a reader that stops reading, a pipe nobody drains or a
//! terminal held by flow control, would stall every connection the thread
//! carries. Such a thread reports through a [`Reporter`] instead, which hands
//! the line to a [`Reports`] thread that writes it, and never waits. Where the
//! writer already holds [`QUEUED_REPORTS`] lines, the line is dropped and
//! counted, and the writer says how many it dropped once it has written what
//! it held, so a lost report is never a silent one.
//!
//! # The event stream
//!
//! A launch given `--events PATH` says everything of its own there instead, as
//! the events [`crate::events`] defines, and nothing on standard error, which
//! then carries the command's output alone. Each line of `fcage`'s is an
//! [`Event`], whatever the run's sink: [`say_event`] and [`report_event`] write
//! it to the stream where the run has one, and its line on standard error where
//! it does not, and [`say`] and [`report`] say a line as a `warning`. The
//! stream's reader going away is the same outcome as standard error's.

use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::thread::JoinHandle;

use ferroday_cage::{ErrorChain, ExitStatus};
use rustix::fs::{Mode, OFlags};

use crate::events::Event;

/// The exit code of a writer whose reader went away: what a process `SIGPIPE`
/// killed exits with, which is what a shell expects of a pipeline's early end.
pub fn broken_pipe() -> u8 {
    ExitStatus::signaled(rustix::process::Signal::PIPE.as_raw()).shell_code()
}

/// The reader of what `fcage` says has gone, standard error's or the event
/// stream's: a line of `fcage`'s own could not be written, because nothing
/// reads the pipe it was written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderGone;

/// Writes one line of `fcage`'s own, while work remains: on standard error, or
/// as a `warning` on the run's event stream.
///
/// The caller stops that work on [`ReaderGone`] and exits with
/// [`broken_pipe`].
pub fn say(line: fmt::Arguments<'_>) -> Result<(), ReaderGone> {
    say_event(&Event::warning(line.to_string()))
}

/// Writes one line of `fcage`'s own, reporting how the invocation ended, as
/// [`say`] does. A reader gone loses the words and changes nothing else.
pub fn report(line: fmt::Arguments<'_>) {
    // The ending is the caller's exit code, which a lost line does not change.
    let _ = say(line);
}

/// Says `event` while work remains: on the run's event stream where it has
/// one, and otherwise its line on standard error, where it has a line.
///
/// The caller stops that work on [`ReaderGone`], as for [`say`].
pub fn say_event(event: &Event) -> Result<(), ReaderGone> {
    match EVENTS.get() {
        Some(stream) => stream.write(event),
        None => match event.text() {
            Some(text) => say_to(&mut io::stderr().lock(), format_args!("{text}")),
            None => Ok(()),
        },
    }
}

/// Says `event` as [`say_event`] does, reporting how the invocation ended, as
/// [`report`] does a line.
pub fn report_event(event: &Event) {
    // As for `report`: the ending is the exit code's, not the words'.
    let _ = say_event(event);
}

/// A run's event stream: one JSON object per line, each written whole, by one
/// writer at a time, whichever thread says it.
pub struct EventStream {
    /// Where the lines go.
    out: Mutex<Box<dyn Write + Send>>,
}

impl EventStream {
    /// A stream writing to `out`.
    pub fn new(out: impl Write + Send + 'static) -> EventStream {
        EventStream {
            out: Mutex::new(Box::new(out)),
        }
    }

    /// Writes `event` as one line, answering [`ReaderGone`] where the stream's
    /// reader has gone and dropping any other failure, as a line on standard
    /// error does.
    pub fn write(&self, event: &Event) -> Result<(), ReaderGone> {
        let line = event.line();
        // A writer that panicked left at most a line unfinished, and a reader
        // skips a line it cannot read as it skips one it does not know.
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        gone_or_dropped(out.write_all(&line).and_then(|()| out.flush()))
    }
}

/// The run's event stream, once [`open_events`] has opened one.
static EVENTS: OnceLock<Arc<EventStream>> = OnceLock::new();

/// Opens `path` as the run's event stream, and says `hello` on it. From here on
/// every line of `fcage`'s own is an event there, and none goes to standard
/// error.
///
/// `path` is opened for appending, and created where it does not exist, so a
/// program hands `fcage` a pipe it reads as `/dev/fd/N` and a person names a
/// file. Opening by name is what keeps `fcage` free of `unsafe`: a descriptor
/// taken by its number alone would be one `fcage` claims to own without
/// knowing that nothing else does. The open does not wait for a reader: a pipe
/// or a named pipe that nothing reads, and a socket, which cannot be opened by
/// name, fail with `ENXIO`.
pub fn open_events(path: &Path) -> io::Result<()> {
    let flags = OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE | OFlags::CLOEXEC;
    let opened = rustix::fs::open(path, flags | OFlags::NONBLOCK, Mode::from_raw_mode(0o666))?;
    // Writes wait for the reader once it is there, as they would to standard
    // error.
    rustix::fs::fcntl_setfl(
        &opened,
        rustix::fs::fcntl_getfl(&opened)?.difference(OFlags::NONBLOCK),
    )?;
    let stream = Arc::new(EventStream::new(File::from(opened)));
    // A reader already gone loses this as it loses every later event.
    let _ = stream.write(&Event::hello());
    // A run opens its stream once, before it says anything else.
    let _ = EVENTS.set(stream);
    Ok(())
}

/// Whether the run says what it has to say on an event stream.
pub fn has_events() -> bool {
    EVENTS.get().is_some()
}

/// The run's event stream, where it has one.
pub fn events() -> Option<Arc<EventStream>> {
    EVENTS.get().cloned()
}

/// Writes `line` and a newline to `out`, answering [`ReaderGone`] where the
/// reader has gone and dropping any other failure.
///
/// Every such line goes to standard error. While an interactive `--terminal`
/// run holds the caller's terminal in raw mode, and standard error is a
/// terminal, the newline is a carriage return and a line feed: raw mode turns
/// off the output processing that adds the return, and a bare line feed would
/// start the next line where this one ended.
pub fn say_to(out: &mut dyn Write, line: fmt::Arguments<'_>) -> Result<(), ReaderGone> {
    let end: &[u8] = if RAW_TERMINAL.load(Ordering::Relaxed) {
        b"\r\n"
    } else {
        b"\n"
    };
    let written = out.write_fmt(line).and_then(|()| out.write_all(end));
    gone_or_dropped(written.and_then(|()| out.flush()))
}

/// Whether standard error is the caller's terminal, held in raw mode by a
/// `--terminal` run's relay; see [`say_to`].
static RAW_TERMINAL: AtomicBool = AtomicBool::new(false);

/// Ends `fcage`'s lines for a terminal in raw mode until it drops, where
/// `raw` says standard error is one. The relay holds it while it runs.
pub struct RawLines(());

impl RawLines {
    /// Ends lines for a raw terminal from now on, where `raw`.
    pub fn hold(raw: bool) -> RawLines {
        RAW_TERMINAL.store(raw, Ordering::Relaxed);
        RawLines(())
    }
}

impl Drop for RawLines {
    fn drop(&mut self) {
        RAW_TERMINAL.store(false, Ordering::Relaxed);
    }
}

/// Writes `bytes` to `out` as they are: the output of a command a provisioner
/// runs, which carries its own newlines.
pub fn pass_to(out: &mut dyn Write, bytes: &[u8]) -> Result<(), ReaderGone> {
    gone_or_dropped(out.write_all(bytes).and_then(|()| out.flush()))
}

/// [`ReaderGone`] for a write whose reader went away; nothing for any other
/// outcome.
fn gone_or_dropped(written: io::Result<()>) -> Result<(), ReaderGone> {
    match written {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Err(ReaderGone),
        Ok(()) | Err(_) => Ok(()),
    }
}

/// Writes output that is the invocation's purpose to standard output, and
/// returns the exit code its writes earned.
///
/// The help, the version, and the Gentoo listings each go through here. A
/// listing is a stream a reader is expected to walk away from, and
/// `fcage --gentoo-packages amd64 | head` is the everyday case, so a reader
/// gone ends it as the quiet 141 a shell expects.
///
/// `--export-rootfs` answers the same question in its own terms, because its
/// write goes through the library and fails as a `ProvisionError` naming what
/// it was doing, a diagnostic this could only report as a bare `io::Error`.
pub fn print_stdout(
    subject: &str,
    records: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> ExitCode {
    // Buffered, so a listing of thousands of lines is a handful of writes: the
    // records are small and there is no reader waiting on each one.
    let mut out = io::BufWriter::new(io::stdout().lock());
    let written = records(&mut out).and_then(|()| out.flush());
    ExitCode::from(stdout_status(subject, written))
}

/// Writes a listing as one JSON document on a line of its own, what `--json`
/// prints, and returns the exit code its write earned, as [`print_stdout`]
/// does.
///
/// A document that cannot be written as JSON, which only a map with keys
/// other than strings is, fails the invocation, naming `subject`.
pub fn print_json(subject: &str, document: &impl serde::Serialize) -> ExitCode {
    match serde_json::to_vec(document) {
        Ok(mut line) => {
            line.push(b'\n');
            print_stdout(subject, |out| out.write_all(&line))
        }
        Err(error) => crate::fail(format!("cannot render {subject} as JSON: {error}")),
    }
}

/// What output on standard output exits with, given how its writes ended.
///
/// Separate from [`print_stdout`] because that one owns the process's own
/// standard output, and what is worth pinning is the reading of the outcome.
pub fn stdout_status(subject: &str, written: io::Result<()>) -> u8 {
    match written {
        Ok(()) => 0,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => broken_pipe(),
        Err(error) => {
            report(format_args!(
                "fcage: cannot write {subject}: {}",
                ErrorChain::new(&error)
            ));
            crate::FAILED
        }
    }
}

/// The most events a [`Reports`] writer holds before a further one is
/// dropped.
///
/// The events are a forward's reports, each the first of a run of failures,
/// and the network stack's, so a run fills this only while nothing takes what
/// the writer writes. The bound is what a reader that never reads can make
/// `fcage` hold.
pub const QUEUED_REPORTS: usize = 64;

/// A thread of `fcage`'s own that writes events for threads that must not wait
/// on their reader, and the [`Reporter`] they hand them to.
///
/// [`finish`](Self::finish) ends it once every reporter is gone.
pub struct Reports {
    /// The reporter that [`reporter`](Self::reporter) clones.
    reporter: Reporter,
    /// The thread writing the events.
    writer: JoinHandle<()>,
}

/// Where a thread that must not wait on its reader hands its events: to the
/// [`Reports`] thread it came from.
#[derive(Clone)]
pub struct Reporter {
    /// The events on their way to the writer.
    queue: SyncSender<Event>,
    /// The events dropped since the writer last said how many it dropped.
    dropped: Arc<AtomicUsize>,
}

/// Where a [`Reports`] writer writes: lines for a person, or an event stream.
pub enum Destination {
    /// Each event's line, where it has one, as on standard error.
    Lines(Box<dyn Write + Send>),
    /// Each event, on an event stream.
    Events(Arc<EventStream>),
}

impl Destination {
    /// Where the run says what it has to say: its event stream where it has
    /// one, and standard error otherwise.
    pub fn of_run() -> Destination {
        match events() {
            Some(stream) => Destination::Events(stream),
            None => Destination::Lines(Box::new(io::stderr())),
        }
    }

    /// Writes `event`. A reader gone loses it, as [`report`] loses a line.
    fn write(&mut self, event: &Event) {
        match self {
            Destination::Lines(out) => {
                if let Some(text) = event.text() {
                    let _ = say_to(out, format_args!("{text}"));
                }
            }
            Destination::Events(stream) => {
                let _ = stream.write(event);
            }
        }
    }

    /// What a dropped report was not taken by, as its count's line says.
    fn name(&self) -> &'static str {
        match self {
            Destination::Lines(_) => "standard error",
            Destination::Events(_) => "the event stream",
        }
    }
}

impl Reports {
    /// Starts the thread writing where the run says what it has to say.
    pub fn start() -> io::Result<Reports> {
        Reports::start_to(Destination::of_run())
    }

    /// Starts the thread writing to `destination`.
    pub fn start_to(destination: Destination) -> io::Result<Reports> {
        let (queue, events) = std::sync::mpsc::sync_channel(QUEUED_REPORTS);
        let dropped = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&dropped);
        let writer = std::thread::Builder::new()
            .name("fcage-reports".into())
            .spawn(move || write_reports(destination, &events, &counted))?;
        Ok(Reports {
            reporter: Reporter { queue, dropped },
            writer,
        })
    }

    /// A reporter whose events this writes.
    pub fn reporter(&self) -> Reporter {
        self.reporter.clone()
    }

    /// Writes what is still queued, and returns once the writer has, which is
    /// once every [`Reporter`] is gone too.
    ///
    /// The wait is on the reader, as every line `fcage` writes of its own waits
    /// on it; what is lost by not waiting is a report nothing would count.
    /// `fcage` finishes the reports before it writes its own last lines, so
    /// those follow the reports.
    pub fn finish(self) {
        drop(self.reporter);
        // A writer that panicked has nothing left to write.
        let _ = self.writer.join();
    }
}

impl Reporter {
    /// Hands `line` to the writer as a `warning`; see [`offer`](Self::offer).
    pub fn report(&self, line: fmt::Arguments<'_>) {
        self.offer(Event::warning(line.to_string()));
    }

    /// Hands `event` to the writer, or drops and counts it where the writer
    /// holds [`QUEUED_REPORTS`] events already. Never waits.
    pub fn offer(&self, event: Event) {
        match self.queue.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            // The writer is gone only where it panicked; the event goes with
            // it.
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

/// The [`Reports`] thread: writes each event as it arrives, and says how many
/// were dropped each time it has written everything queued, until every
/// [`Reporter`] is gone.
///
/// An event arrives behind the ones queued before it, so the count of those
/// dropped while the queue was full follows every event that was queued when
/// they were. A reader gone loses the words, as [`report`] does.
fn write_reports(mut destination: Destination, events: &Receiver<Event>, dropped: &AtomicUsize) {
    loop {
        let event = match events.try_recv() {
            Ok(event) => event,
            Err(TryRecvError::Empty) => {
                say_dropped(&mut destination, dropped);
                match events.recv() {
                    Ok(event) => event,
                    Err(_) => break,
                }
            }
            Err(TryRecvError::Disconnected) => break,
        };
        destination.write(&event);
    }
    say_dropped(&mut destination, dropped);
}

/// Says how many events were dropped since it last said, where any were.
fn say_dropped(destination: &mut Destination, dropped: &AtomicUsize) {
    let count = dropped.swap(0, Ordering::Relaxed);
    if count > 0 {
        let plural = if count == 1 { "" } else { "s" };
        let text = format!(
            "fcage: dropped {count} report{plural} while {} was not taking them",
            destination.name()
        );
        destination.write(&Event::dropped("fcage", count as u64, text));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Mutex, mpsc};

    use super::*;

    /// A writer that keeps everything written, for a test to read back once
    /// the writing is done.
    #[derive(Clone, Default)]
    pub(crate) struct Kept(Arc<Mutex<Vec<u8>>>);

    impl Kept {
        /// Everything written so far, as text.
        pub(crate) fn text(&self) -> String {
            let written = self.0.lock().expect("nothing panicked holding the output");
            String::from_utf8_lossy(&written).into_owned()
        }
    }

    impl Write for Kept {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("nothing panicked holding the output")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Set in the child [`a_line_ends_for_a_terminal_in_raw_mode`] starts: the
    /// ending is process-wide, so the child changes its own.
    const RAW_CHILD: &str = "FCAGE_TEST_RAW_LINES";

    #[test]
    fn a_line_ends_for_a_terminal_in_raw_mode() {
        if std::env::var_os(RAW_CHILD).is_some() {
            let kept = Kept::default();
            let _ = say_to(&mut kept.clone(), format_args!("before"));
            let held = RawLines::hold(true);
            let _ = say_to(&mut kept.clone(), format_args!("raw"));
            drop(held);
            let _ = say_to(&mut kept.clone(), format_args!("after"));
            print!("{}", kept.text().escape_debug());
            return;
        }
        let child = ferroday_cage_testkit::process::run_bounded(
            ferroday_cage_testkit::process::rerun(
                "output::tests::a_line_ends_for_a_terminal_in_raw_mode",
            )
            .env(RAW_CHILD, "1"),
            std::time::Duration::from_secs(60),
        );
        let printed = String::from_utf8_lossy(&child.stdout);
        assert!(child.status.success(), "{printed}");
        assert!(printed.contains("before\\nraw\\r\\nafter\\n"), "{printed}");
    }

    /// A [`Kept`] that holds its first write until the test lets it go.
    struct Gate {
        /// Told once the first write has begun.
        entered: Option<mpsc::Sender<()>>,
        /// Waited on before the first write completes.
        release: Option<mpsc::Receiver<()>>,
        /// Everything written.
        written: Kept,
    }

    impl Write for Gate {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let (Some(entered), Some(release)) = (self.entered.take(), self.release.take()) {
                entered.send(()).expect("the test waits for the write");
                release.recv().expect("the test lets the write go");
            }
            self.written.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_reporter_never_waits_and_counts_what_it_drops() {
        let (entered, has_entered) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let written = Kept::default();
        let reports = Reports::start_to(Destination::Lines(Box::new(Gate {
            entered: Some(entered),
            release: Some(released),
            written: written.clone(),
        })))
        .expect("the writer starts");
        let reporter = reports.reporter();

        // The writer takes the first line and is held writing it, so the queue
        // holds the next `QUEUED_REPORTS`, and the rest are dropped. None of
        // the reports waits.
        reporter.report(format_args!("line 0"));
        has_entered.recv().expect("the writer takes the first line");
        for at in 1..=QUEUED_REPORTS + 3 {
            reporter.report(format_args!("line {at}"));
        }
        release.send(()).expect("the writer is waiting");
        drop(reporter);
        reports.finish();

        let written = written.text();
        let mut expected: Vec<String> = (0..=QUEUED_REPORTS)
            .map(|at| format!("line {at}"))
            .collect();
        expected
            .push("fcage: dropped 3 reports while standard error was not taking them".to_string());
        assert_eq!(written.lines().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn on_an_event_stream_the_reports_and_their_count_are_events() {
        let (entered, has_entered) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let written = Kept::default();
        let stream = Arc::new(EventStream::new(Gate {
            entered: Some(entered),
            release: Some(released),
            written: written.clone(),
        }));
        let reports = Reports::start_to(Destination::Events(stream)).expect("the writer starts");
        let reporter = reports.reporter();

        // As on standard error: the writer is held on the first event, the
        // queue fills, and the rest are counted.
        reporter.report(format_args!("fcage: the first"));
        has_entered
            .recv()
            .expect("the writer takes the first event");
        for at in 1..=QUEUED_REPORTS + 2 {
            reporter.report(format_args!("fcage: event {at}"));
        }
        release.send(()).expect("the writer is waiting");
        drop(reporter);
        reports.finish();

        let lines: Vec<serde_json::Value> = written
            .text()
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line is JSON"))
            .collect();
        assert_eq!(lines.len(), QUEUED_REPORTS + 2);
        assert_eq!(
            lines[0],
            serde_json::json!({"event": "warning", "text": "fcage: the first"})
        );
        assert_eq!(
            lines.last().expect("the count"),
            &serde_json::json!({
                "event": "dropped",
                "source": "fcage",
                "count": 2,
                "text": "fcage: dropped 2 reports while the event stream was not taking them",
            })
        );
    }

    #[test]
    fn finishing_writes_what_is_queued() {
        let written = Kept::default();
        let reports = Reports::start_to(Destination::Lines(Box::new(written.clone())))
            .expect("the writer starts");
        reports.reporter().report(format_args!("the last word"));
        reports.finish();
        assert_eq!(written.text(), "the last word\n");
    }
}
