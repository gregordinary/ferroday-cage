//! `fcage`'s relay for a standard stream that is a file.
//!
//! A descriptor carries more than a stream. `/proc/self/fd/N` reopens the file
//! a descriptor names, with whatever access the opener's credentials allow
//! rather than the access the descriptor was opened with. A sandboxed command
//! whose standard input is `fcage`'s own file, as in `fcage ... < notes.txt`,
//! can therefore open `/proc/self/fd/0` for writing and rewrite `notes.txt`. A
//! command whose standard output is a log opened for appending can read the log
//! back and truncate it. A Landlock grant closes the reopen, because the file
//! lies outside every grant, but nothing else a launch configures does.
//!
//! So a stream that is a regular file or a block device, the two kinds whose
//! contents outlive the run, never reaches the sandbox. The command gets a pipe
//! in its place, and a thread of `fcage`'s copies between the pipe and the
//! file. The bytes cross and the file does not. A pipe, a socket, a terminal,
//! and a character device such as `/dev/null` are handed over as they are: none
//! of them holds content a reopen could rewrite, and a terminal is covered by
//! the library's own session rules.
//!
//! A relayed standard input changes one thing beyond the descriptor. The library
//! gives a command whose standard input is a descriptor of the caller's a
//! session of its own, as `--stdin null` does, so `/dev/tty` names nothing
//! inside it and the caller's job control does not reach it.
//!
//! Only a stream the launch would otherwise inherit is relayed. One a profile or
//! `--stdin null` already sends somewhere else is not fcage's to replace, and a
//! `--terminal` launch hands the sandbox no stream of `fcage`'s at all.

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileTypeExt as _;
use std::thread::JoinHandle;

use ferroday_cage::Stdio;
use rustix::event::{PollFd, PollFlags};
use rustix::io::Errno;

/// The size of one copy between a relay pipe and `fcage`'s own stream.
const CHUNK: usize = 64 * 1024;

/// The relays one launch runs, and the dispositions that route the command's
/// streams through them.
pub struct StreamRelay {
    /// The dispositions to give the builder in place of the inherited ones:
    /// standard input, output, and error, in that order. `None` leaves a stream
    /// as it was.
    replacements: [Option<Stdio>; 3],
    /// The output relays, each with the stream it serves, joined by
    /// [`finish`](Self::finish).
    outputs: Vec<(&'static str, JoinHandle<io::Result<()>>)>,
    /// The write end of the stop pipe. Closing it tells every output relay that
    /// the sandbox is gone, so each drains what is buffered and returns.
    stop: Option<OwnedFd>,
}

impl StreamRelay {
    /// Starts a relay for each of `fcage`'s own standard streams that is a file
    /// and that the launch would inherit.
    ///
    /// `inherited` says, for standard input, output, and error in that order,
    /// whether the launch leaves the stream as it inherited it.
    pub fn start(inherited: [bool; 3]) -> io::Result<StreamRelay> {
        let mut relay = StreamRelay {
            replacements: [None, None, None],
            outputs: Vec::new(),
            stop: None,
        };
        if inherited[0] && is_file(io::stdin().as_fd()) {
            let (reader, writer) = io::pipe()?;
            // Not joined. It ends at end-of-file on the file, or when a write
            // finds the command gone; a command that never reads leaves it
            // blocked, and the process exiting ends it then.
            std::thread::Builder::new()
                .name("fcage-stdin".into())
                .spawn(move || feed(writer))?;
            relay.replacements[0] = Some(Stdio::from_fd(reader.into()));
        }
        // The read end of the stop pipe, held here only until every relay has a
        // copy of its own: once `finish` closes the write end, end-of-file on
        // it has to mean that and nothing else.
        let mut stop_read: Option<OwnedFd> = None;
        for (index, name, stream) in [
            (
                1,
                "standard output",
                io::stdout().as_fd().try_clone_to_owned()?,
            ),
            (
                2,
                "standard error",
                io::stderr().as_fd().try_clone_to_owned()?,
            ),
        ] {
            if !inherited[index] || !is_file(stream.as_fd()) {
                continue;
            }
            let stop = match &stop_read {
                Some(stop) => stop.try_clone()?,
                None => {
                    let (read, write) = io::pipe()?;
                    relay.stop = Some(write.into());
                    let read: OwnedFd = read.into();
                    let copy = read.try_clone()?;
                    stop_read = Some(read);
                    copy
                }
            };
            let (reader, writer) = io::pipe()?;
            let destination = File::from(stream);
            let pump = std::thread::Builder::new()
                .name("fcage-output".into())
                .spawn(move || pump(reader.into(), destination, stop))?;
            relay.outputs.push((name, pump));
            relay.replacements[index] = Some(Stdio::from_fd(writer.into()));
        }
        Ok(relay)
    }

    /// The dispositions to set on the builder, taken once: a stream this
    /// returns `None` for is left as it was.
    pub fn take_replacements(&mut self) -> [Option<Stdio>; 3] {
        std::mem::take(&mut self.replacements)
    }

    /// Tells the output relays the sandbox is gone and waits for each to copy
    /// what the command wrote, returning the ones that failed.
    ///
    /// Called once the command's outcome is in hand. A relay that reaches
    /// end-of-file first simply returns. One that does not, because a process
    /// that outlived the command still holds the pipe, copies what is already
    /// buffered and stops there rather than waiting on it.
    pub fn finish(mut self) -> Vec<(&'static str, io::Error)> {
        drop(self.stop.take());
        let mut failures = Vec::new();
        for (name, pump) in self.outputs.drain(..) {
            match pump.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push((name, error)),
                Err(_) => failures.push((name, io::Error::other("the relay thread panicked"))),
            }
        }
        failures
    }
}

/// Whether a stream is one the relay covers: a regular file or a block device.
///
/// A descriptor that cannot be examined, a closed one among them, is not
/// relayed. The launch then does whatever it would have done with it.
fn is_file(stream: BorrowedFd<'_>) -> bool {
    let Ok(duplicate) = stream.try_clone_to_owned() else {
        return false;
    };
    match File::from(duplicate).metadata() {
        Ok(metadata) => {
            let kind = metadata.file_type();
            kind.is_file() || kind.is_block_device()
        }
        Err(_) => false,
    }
}

/// Copies `fcage`'s standard input into the pipe the command reads.
///
/// A write that finds the command gone ends the copy without an error: the
/// command owed nothing to the rest of its input.
fn feed(pipe: io::PipeWriter) -> io::Result<()> {
    let mut pipe = pipe;
    match io::copy(&mut io::stdin().lock(), &mut pipe) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error),
    }
}

/// Copies what the command writes to a pipe onto one of `fcage`'s own streams,
/// until end-of-file or until the stop pipe closes.
///
/// A failed write to `destination` ends the relay, and drops the pipe with it,
/// so the command's next write fails with `EPIPE` rather than blocking on a
/// pipe nothing drains.
fn pump(source: OwnedFd, mut destination: File, stop: OwnedFd) -> io::Result<()> {
    let mut source = File::from(source);
    let mut buf = vec![0u8; CHUNK];
    loop {
        let mut fds = [
            PollFd::new(&source, PollFlags::IN),
            PollFd::new(&stop, PollFlags::IN),
        ];
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(errno.into()),
        }
        // The stop is looked at first. A process that outlived the command and
        // keeps writing would otherwise keep the pipe readable, and with it
        // this loop, for as long as it ran.
        if !fds[1].revents().is_empty() {
            return drain(&mut source, &mut destination, &mut buf);
        }
        if !fds[0].revents().is_empty() {
            match source.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(read) => destination.write_all(&buf[..read])?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

/// Copies what the pipe holds at this moment, and returns.
///
/// The command is gone by the time this runs, so everything it wrote is already
/// in the pipe. A process that outlived it may write more, and copying that
/// would last as long as it does, which is what the stop exists to prevent.
/// The count is taken once, so a read never waits for bytes that are not there.
fn drain(source: &mut File, destination: &mut File, buf: &mut [u8]) -> io::Result<()> {
    let mut left = rustix::io::ioctl_fionread(&*source)?;
    while left > 0 {
        let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        match source.read(&mut buf[..want]) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                destination.write_all(&buf[..read])?;
                left = left.saturating_sub(read as u64);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
