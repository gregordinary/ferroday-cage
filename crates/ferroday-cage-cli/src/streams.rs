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
//! So each standard stream a launch would hand over is judged by its kind:
//!
//! - A pipe, a socket, or a character device such as a terminal or `/dev/null`
//!   is handed over as it is. None of them holds content a reopen could
//!   rewrite, and a terminal is covered by the library's own session rules.
//! - A regular file or a block device, the two kinds whose contents outlive
//!   the run, is relayed. The command gets a pipe in its place, and a thread of
//!   `fcage`'s copies between the pipe and the file. The bytes cross and the
//!   file does not.
//! - Anything else is refused, and the run exits 125 before anything starts.
//!   A directory reaches the host's filesystem by path, so a command handed
//!   one could walk out of its root; the library refuses one too. An `O_PATH`
//!   descriptor carries no stream at all, and neither does an anonymous inode
//!   such as an eventfd or a pidfd.
//!
//! # Standard input
//!
//! The feed reads the file without buffering, and never more than one page
//! ahead of the command: the pipe holds one page, and the feed reads only when
//! the pipe has room for what it reads. When the command finishes, or the
//! launch fails, the feed stops, `fcage` takes back what the pipe still holds,
//! and the file's offset moves back over every byte the command did not read.
//! The offset belongs to the open file description the caller shares, so the
//! next reader of the file starts where the command stopped. That is what
//! keeps `while read -r line; do fcage ...; done < list` reading the whole
//! list. A read the file refuses ends the command's input there, and the run
//! exits 125 once the command finishes.
//!
//! A relayed standard input also gives the command a session of its own, as
//! `--stdin null` does, so `/dev/tty` names nothing inside it and the caller's
//! job control does not reach it.
//!
//! # Standard output and error
//!
//! An output stream that is a file gets a pipe and a thread of `fcage`'s. Two
//! streams on one file share them, so `> log 2>&1` keeps the order the command
//! wrote in. The test is the file's identity, its device and inode, rather than
//! the open file description's: the kernel compares descriptions only through
//! `kcmp`, which `fcage` cannot call without unsafe code. Writes through either
//! description of one file reach the same bytes.
//! Routing both streams through standard output's description changes where
//! they land only for two separate truncating opens, as in `> log 2> log`,
//! where without the relay each stream overwrites the other.
//!
//! # What the command sees
//!
//! A relayed stream is a pipe, so the command cannot seek it or learn the
//! file's size, and a program that reads a regular file differently from a
//! pipe takes its pipe path. A process the command leaves running loses the
//! stream when the run ends: its input reaches end-of-file, and what it writes
//! afterwards is not delivered.
//!
//! Only a stream the launch would otherwise inherit is judged. One a profile or
//! `--stdin null` already sends somewhere else is not fcage's to replace, and a
//! `--terminal` launch hands the sandbox no stream of `fcage`'s at all.
//!
//! `fcage` itself still holds the file at its own descriptor. A sandbox's
//! command cannot reach it there: it runs in a user namespace below `fcage`'s,
//! and reading another process's descriptors from a different user namespace
//! takes `CAP_SYS_PTRACE` in the target's user namespace. A restricted command
//! runs beside `fcage` in the host's namespaces, which is why `fcage` makes
//! itself non-dumpable before a restricted launch.

use std::fmt;
use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::thread::JoinHandle;

use ferroday_cage::Stdio;
use rustix::event::{PollFd, PollFlags};
use rustix::fs::{FileType, OFlags, Stat};
use rustix::io::Errno;

/// The size of one copy between an output relay's pipe and `fcage`'s own
/// stream.
const CHUNK: usize = 64 * 1024;

/// How far a relayed standard input reads ahead of the command: the capacity of
/// the pipe the command reads, and the most one read from the file takes.
///
/// One page, the smallest capacity a pipe can have. Every byte read ahead is
/// returned to the file when the command finishes, so the bound matters only
/// when `fcage` cannot return it: killed outright, it leaves the file's offset
/// at most this far, plus one read in flight, past what the command consumed.
const READ_AHEAD: usize = 4096;

/// The standard streams, by number, as a diagnostic names them.
const STREAMS: [&str; 3] = ["standard input", "standard output", "standard error"];

/// What `fcage` does with one of its own standard streams that a launch would
/// hand to the command.
enum Handling {
    /// Handed over as it is: a pipe, a socket, or a character device.
    HandOver,
    /// Relayed through a pipe: a regular file or a block device. The status
    /// tells two streams on one file from two on different files.
    Relay(Box<Stat>),
    /// Refused, with what the stream is, as a phrase completing "standard
    /// input is ...".
    Refuse(&'static str),
}

/// Judges a stream by its kind; see the module documentation.
fn handling(stream: BorrowedFd<'_>) -> io::Result<Handling> {
    // An `O_PATH` descriptor answers `fstat` with the kind of what it names,
    // so it is recognized by its flags before its kind is read.
    if rustix::fs::fcntl_getfl(stream)?.contains(OFlags::PATH) {
        return Ok(Handling::Refuse(
            "an O_PATH descriptor, which carries no stream",
        ));
    }
    let stat = rustix::fs::fstat(stream)?;
    Ok(match FileType::from_raw_mode(stat.st_mode) {
        FileType::Fifo | FileType::Socket | FileType::CharacterDevice => Handling::HandOver,
        FileType::RegularFile | FileType::BlockDevice => Handling::Relay(Box::new(stat)),
        FileType::Directory => {
            Handling::Refuse("a directory, whose descriptor reaches the host's filesystem by path")
        }
        // Reachable only through `O_PATH`, which is refused above; named so
        // that a kernel answering otherwise is still refused for what it is.
        FileType::Symlink => Handling::Refuse("a symbolic link, which carries no stream"),
        FileType::Unknown => Handling::Refuse(
            "an anonymous inode, such as an eventfd or a pidfd, which carries no stream",
        ),
    })
}

/// Why the relay could not start.
#[derive(Debug)]
pub enum StartError {
    /// A stream is of a kind `fcage` neither hands over nor relays.
    Refused {
        /// The stream, as [`STREAMS`] names it.
        stream: &'static str,
        /// What the stream is, as [`Handling::Refuse`] phrases it.
        what: &'static str,
    },
    /// The relay's own plumbing failed: a stream could not be examined, or a
    /// pipe or a thread could not be created.
    Io(io::Error),
}

impl From<io::Error> for StartError {
    fn from(error: io::Error) -> StartError {
        StartError::Io(error)
    }
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::Refused { stream, what } => write!(
                f,
                "{stream} is {what}; a command is given a pipe, a socket, a character \
                 device, or a file's contents, and nothing else"
            ),
            StartError::Io(_) => f.write_str("cannot relay the standard streams"),
        }
    }
}

impl std::error::Error for StartError {
    /// The OS error underneath a plumbing failure. A refused stream carries
    /// none: nothing failed, `fcage` declined it.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StartError::Refused { .. } => None,
            StartError::Io(error) => Some(error),
        }
    }
}

/// The relays one launch runs, and the dispositions that route the command's
/// streams through them.
pub struct StreamRelay {
    /// The dispositions to give the builder in place of the inherited ones:
    /// standard input, output, and error, in that order. `None` leaves a stream
    /// as it was.
    replacements: [Option<Stdio>; 3],
    /// The standard input relay, where standard input is a file.
    input: Option<Input>,
    /// The output relays, each with the streams it serves, joined by
    /// [`finish`](Self::finish).
    outputs: Vec<(&'static str, JoinHandle<io::Result<()>>)>,
    /// The write end of the stop pipe. Closing it tells every relay thread
    /// that the command is gone: the feed stops reading, and each output relay
    /// copies what is buffered and returns.
    stop: Option<OwnedFd>,
}

impl StreamRelay {
    /// Starts a relay for each of `fcage`'s own standard streams that is a file
    /// and that the launch would inherit.
    ///
    /// `inherited` says, for standard input, output, and error in that order,
    /// whether the launch leaves the stream as it inherited it. Every such
    /// stream is judged before anything starts, so a refusal leaves no thread
    /// running and no input read.
    pub fn start(inherited: [bool; 3]) -> Result<StreamRelay, StartError> {
        let own = [
            rustix::stdio::stdin(),
            rustix::stdio::stdout(),
            rustix::stdio::stderr(),
        ];
        let mut judged: [Option<Handling>; 3] = [None, None, None];
        for (index, stream) in own.iter().enumerate() {
            if !inherited[index] {
                continue;
            }
            match handling(*stream)? {
                Handling::Refuse(what) => {
                    return Err(StartError::Refused {
                        stream: STREAMS[index],
                        what,
                    });
                }
                kind => judged[index] = Some(kind),
            }
        }

        let mut relay = StreamRelay {
            replacements: [None, None, None],
            input: None,
            outputs: Vec::new(),
            stop: None,
        };
        let relayed = |index: usize| match &judged[index] {
            Some(Handling::Relay(stat)) => Some(stat),
            _ => None,
        };
        if relayed(0).is_none() && relayed(1).is_none() && relayed(2).is_none() {
            return Ok(relay);
        }
        // The read end of the stop pipe stays here, and each thread takes a copy
        // of its own: once `finish` closes the write end, end-of-file on it has
        // to mean that and nothing else.
        let (stop_read, stop_write) = io::pipe()?;
        let stop_read: OwnedFd = stop_read.into();
        relay.stop = Some(stop_write.into());

        let shared = match (relayed(1), relayed(2)) {
            (Some(out), Some(err)) => out.st_dev == err.st_dev && out.st_ino == err.st_ino,
            _ => false,
        };
        if shared {
            let writer = relay.pump(own[1], "standard output and error", &stop_read)?;
            relay.replacements[2] = Some(Stdio::from_fd(writer.try_clone()?));
            relay.replacements[1] = Some(Stdio::from_fd(writer));
        } else {
            for index in [1, 2] {
                if relayed(index).is_some() {
                    let writer = relay.pump(own[index], STREAMS[index], &stop_read)?;
                    relay.replacements[index] = Some(Stdio::from_fd(writer));
                }
            }
        }

        // The feed starts last, so a failure above has read nothing of the
        // caller's input: a relay that never reaches `finish` cannot return it.
        if relayed(0).is_some() {
            let file = File::from(own[0].try_clone_to_owned()?);
            let (input, reader) = Input::start(file, stop_read.try_clone()?)?;
            relay.input = Some(input);
            relay.replacements[0] = Some(Stdio::from_fd(reader));
        }
        Ok(relay)
    }

    /// Starts an output relay copying a pipe onto `destination`, and returns
    /// the pipe's write end for the command.
    fn pump(
        &mut self,
        destination: BorrowedFd<'_>,
        streams: &'static str,
        stop: &OwnedFd,
    ) -> io::Result<OwnedFd> {
        let destination = File::from(destination.try_clone_to_owned()?);
        let stop = stop.try_clone()?;
        let (reader, writer) = io::pipe()?;
        let pump = std::thread::Builder::new()
            .name("fcage-output".into())
            .spawn(move || pump(reader.into(), destination, stop))?;
        self.outputs.push((streams, pump));
        Ok(writer.into())
    }

    /// The dispositions to set on the builder, taken once: a stream this
    /// returns `None` for is left as it was.
    pub fn take_replacements(&mut self) -> [Option<Stdio>; 3] {
        std::mem::take(&mut self.replacements)
    }

    /// Tells every relay the command is gone, returns the input it did not
    /// read, and waits for each output relay to copy what the command wrote.
    /// Returns the relays that failed, each with the streams it served.
    ///
    /// Called once the command's outcome is in hand, or once the launch has
    /// failed, and before `fcage` prints anything about the run, so that its own
    /// words land after the command's in a relayed file. An output relay that
    /// reaches end-of-file first simply returns. One that does not, because a
    /// process that outlived the command still holds the pipe, copies what is
    /// already buffered and stops there rather than waiting on it.
    pub fn finish(mut self) -> Vec<(&'static str, io::Error)> {
        drop(self.stop.take());
        let mut failures = Vec::new();
        if let Some(input) = self.input.take()
            && let Err(error) = input.finish()
        {
            failures.push((STREAMS[0], error));
        }
        for (streams, pump) in self.outputs.drain(..) {
            match pump.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push((streams, error)),
                Err(_) => failures.push((streams, io::Error::other("the relay thread panicked"))),
            }
        }
        failures
    }
}

/// The relay of a standard input that is a file.
struct Input {
    /// The thread copying the file into the pipe.
    feed: JoinHandle<Fed>,
    /// `fcage`'s own copy of the pipe's read end, from which
    /// [`finish`](Self::finish) takes back what the command never read.
    pipe: File,
    /// The file, through a descriptor sharing `fcage`'s standard input's open
    /// file description, and with it the offset the caller sees.
    file: File,
}

/// How a feed ended.
struct Fed {
    /// The bytes the feed read from the file and never wrote to the pipe.
    held: usize,
    /// The read or the write that ended the feed early, where one did.
    result: io::Result<()>,
}

impl Input {
    /// Starts feeding `file` into a pipe bounded to [`READ_AHEAD`], until the
    /// file ends or `stop` closes, and returns the pipe's read end for the
    /// command.
    fn start(file: File, stop: OwnedFd) -> io::Result<(Input, OwnedFd)> {
        let (reader, writer) = io::pipe()?;
        rustix::pipe::fcntl_setpipe_size(&writer, READ_AHEAD)?;
        // The feed waits for room or for the stop, whichever comes first, so
        // its writes must not block. The two ends are separate open file
        // descriptions, so the command's end stays blocking.
        rustix::io::ioctl_fionbio(&writer, true)?;
        let pipe = File::from(OwnedFd::from(reader.try_clone()?));
        let source = file.try_clone()?;
        let feed = std::thread::Builder::new()
            .name("fcage-stdin".into())
            .spawn(move || feed(&source, writer.into(), &stop))?;
        Ok((Input { feed, pipe, file }, reader.into()))
    }

    /// Waits for the feed to stop, takes back what the pipe still holds, and
    /// moves the file's offset back over every byte the command did not read.
    ///
    /// The stop must already have been signaled. Once the feed has returned,
    /// nothing writes to the pipe: the feed's end was the only write end, and
    /// the launch's own processes closed their inherited copies before the
    /// command started. A read here therefore ends at end-of-file rather than
    /// waiting, whether the bytes are taken by this or by a process the command
    /// left running.
    fn finish(self) -> io::Result<()> {
        let fed = self.feed.join().unwrap_or_else(|_| Fed {
            held: 0,
            result: Err(io::Error::other("the relay thread panicked")),
        });
        let unread = take_back(&self.pipe)?;
        let back = i64::try_from(fed.held + unread).map_err(io::Error::other)?;
        if back > 0 {
            (&self.file).seek(SeekFrom::Current(-back))?;
        }
        fed.result
    }
}

/// Copies `file` into the pipe the command reads, never reading more than the
/// pipe has room for.
///
/// Waiting for room before each read is what bounds the read-ahead: a byte is
/// read from the file only when the pipe can take it at once, so the stop
/// almost never finds the feed holding any. A write that finds no reader left
/// ends the feed without an error, since the command owed nothing to the rest
/// of its input.
fn feed(file: &File, pipe: OwnedFd, stop: &OwnedFd) -> Fed {
    let mut buf = [0u8; READ_AHEAD];
    let ended = |held: usize, result: io::Result<()>| Fed { held, result };
    loop {
        match room_or_stop(&pipe, stop) {
            Ok(true) => {}
            Ok(false) => return ended(0, Ok(())),
            Err(error) => return ended(0, Err(error)),
        }
        // Unbuffered: what this read takes is exactly what moves the offset,
        // so the count `finish` returns is exact.
        let read = match (&*file).read(&mut buf) {
            Ok(0) => return ended(0, Ok(())),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return ended(0, Err(error)),
        };
        let mut written = 0;
        while written < read {
            match rustix::io::write(&pipe, &buf[written..read]) {
                Ok(count) => written += count,
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => match room_or_stop(&pipe, stop) {
                    Ok(true) => {}
                    Ok(false) => return ended(read - written, Ok(())),
                    Err(error) => return ended(read - written, Err(error)),
                },
                Err(Errno::PIPE) => return ended(read - written, Ok(())),
                Err(errno) => return ended(read - written, Err(errno.into())),
            }
        }
    }
}

/// Waits until the pipe has room or the stop closes, answering `true` for
/// room.
///
/// A pipe with no reader left also reports itself writable, and the write that
/// follows answers `EPIPE`.
fn room_or_stop(pipe: &OwnedFd, stop: &OwnedFd) -> io::Result<bool> {
    loop {
        let mut fds = [
            PollFd::new(pipe, PollFlags::OUT),
            PollFd::new(stop, PollFlags::IN),
        ];
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(errno.into()),
        }
        if !fds[1].revents().is_empty() {
            return Ok(false);
        }
        if !fds[0].revents().is_empty() {
            return Ok(true);
        }
    }
}

/// Reads and discards what the pipe holds, and returns how much that was.
///
/// The count is taken once and read no further, as [`drain`] does, so a read
/// never waits for bytes that are not there.
fn take_back(pipe: &File) -> io::Result<usize> {
    let mut buf = [0u8; READ_AHEAD];
    let mut left = usize::try_from(rustix::io::ioctl_fionread(pipe)?).unwrap_or(usize::MAX);
    let mut taken = 0;
    while left > 0 {
        let want = buf.len().min(left);
        match (&*pipe).read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(read) => {
                taken += read;
                left = left.saturating_sub(read);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(taken)
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    /// A scratch file holding `contents`, opened for reading.
    fn file_holding(dir: &Path, contents: &[u8]) -> File {
        let path = dir.join("input");
        std::fs::write(&path, contents).expect("the scratch file is writable");
        File::open(path).expect("the scratch file opens")
    }

    /// What the relay does with `stream`, as the variant's name.
    fn judged(stream: impl AsFd) -> &'static str {
        match handling(stream.as_fd()).expect("the stream can be examined") {
            Handling::HandOver => "hand over",
            Handling::Relay(_) => "relay",
            Handling::Refuse(_) => "refuse",
        }
    }

    #[test]
    fn a_stream_is_handed_over_relayed_or_refused_by_its_kind() {
        let dir = ferroday_cage_testkit::scratch::scratch_dir("fcage-stream-kinds");
        let (reader, writer) = io::pipe().expect("a pipe");
        let (socket, _peer) = UnixStream::pair().expect("a socket pair");
        let null = File::open("/dev/null").expect("/dev/null opens");
        assert_eq!(judged(&reader), "hand over");
        assert_eq!(judged(&writer), "hand over");
        assert_eq!(judged(&socket), "hand over");
        assert_eq!(judged(&null), "hand over");

        assert_eq!(judged(file_holding(&dir, b"text")), "relay");

        // A directory walks the host's filesystem by path, and the other two
        // carry no stream at all.
        assert_eq!(
            judged(File::open(&dir).expect("the directory opens")),
            "refuse"
        );
        let path_only = rustix::fs::open(
            &dir,
            OFlags::PATH | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("an O_PATH descriptor");
        assert_eq!(judged(&path_only), "refuse");
        let path_file = rustix::fs::open(
            dir.join("input"),
            OFlags::PATH | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("an O_PATH descriptor of a file");
        assert_eq!(judged(&path_file), "refuse");
        let event =
            rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC).expect("an eventfd");
        assert_eq!(judged(&event), "refuse");
    }

    /// Feeds `contents` to a reader that takes `consumed` bytes and closes its
    /// end, then finishes the relay and returns where the file's offset ended.
    fn offset_after(consumed: usize, contents: &[u8]) -> u64 {
        let dir = ferroday_cage_testkit::scratch::scratch_dir("fcage-stdin-offset");
        let file = file_holding(&dir, contents);
        let observer = file.try_clone().expect("the file duplicates");
        let (stop_read, stop_write) = io::pipe().expect("a stop pipe");
        let (input, reader) = Input::start(file, stop_read.into()).expect("the feed starts");
        let mut reader = File::from(reader);
        let mut taken = vec![0u8; consumed];
        reader.read_exact(&mut taken).expect("the feed delivers");
        assert_eq!(taken, contents[..consumed]);
        drop(reader);
        drop(stop_write);
        input.finish().expect("the relay finishes");
        (&observer)
            .stream_position()
            .expect("the offset is readable")
    }

    #[test]
    fn the_input_the_command_did_not_read_is_returned_to_the_file() {
        let contents: Vec<u8> = (0..3 * READ_AHEAD).map(|index| index as u8).collect();
        // Nothing, a little, a whole page and some, and everything: each
        // leaves the offset exactly where the reader stopped.
        for consumed in [0, 6, READ_AHEAD + 1, contents.len()] {
            assert_eq!(
                offset_after(consumed, &contents),
                consumed as u64,
                "after a reader took {consumed} bytes",
            );
        }
    }

    #[test]
    fn a_file_the_feed_cannot_read_is_reported() {
        let dir = ferroday_cage_testkit::scratch::scratch_dir("fcage-stdin-unreadable");
        let path = dir.join("input");
        std::fs::write(&path, b"text").expect("the scratch file is writable");
        // Open for writing only, so every read the feed makes is refused.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("the scratch file opens");
        let (stop_read, stop_write) = io::pipe().expect("a stop pipe");
        let (input, reader) = Input::start(file, stop_read.into()).expect("the feed starts");
        // The command sees end-of-file where its input could not be read.
        let mut seen = Vec::new();
        File::from(reader)
            .read_to_end(&mut seen)
            .expect("the pipe reads to its end");
        assert!(seen.is_empty());
        drop(stop_write);
        assert!(input.finish().is_err(), "the refused read went unreported");
    }
}
