//! A pseudoterminal of the sandbox's own, and the caller's end of it.
//!
//! The pseudoterminal is allocated inside the sandbox, from the `/dev/ptmx` the
//! sandbox itself sees, by the first process of the sandbox proper once the
//! root is in place. The primary then travels back to the caller over a channel
//! of the launch's own, and the replica stays behind for the command. Allocated
//! there, the replica's device node is one the sandbox can name, so a program
//! that resolves a path for its terminal finds it; see [`Terminal`].

use std::fmt;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::{Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use rustix::pty::{self, OpenptFlags};
use rustix::termios::{
    self, ControlModes, InputModes, LocalModes, OptionalActions, OutputModes, SpecialCodeIndex,
    Winsize,
};

use crate::error::Error;

/// The conventional line-discipline speed, and the one the kernel's own
/// `tty_std_termios` states. A pseudoterminal has no wire, so this is a value
/// programs read rather than a rate anything is clocked at.
const BASELINE_SPEED: u32 = 38400;

/// A pseudoterminal to allocate for the sandbox.
///
/// A terminal is a launch mode rather than builder state: it hands the caller a
/// live resource, so it belongs to one launch rather than to the frozen plan
/// every launch shares. Pass one to
/// [`Cage::spawn_terminal`](crate::Cage::spawn_terminal) or
/// [`Cage::spawn_pending_terminal`](crate::Cage::spawn_pending_terminal), which
/// return the caller's end of it as a [`Pty`] beside the running sandbox.
///
/// The replica is wired onto the command's file descriptors 0, 1 and 2 — a
/// terminal is one stream — and the launch owns its session, so the
/// pseudoterminal is the sandbox's own controlling terminal. `isatty` is true
/// on all three, `tcgetattr` and `tcsetattr` work, a full-screen program
/// behaves, and a shell inside the sandbox runs jobs of its own against a
/// terminal the caller does not share.
///
/// # What a terminal launch reaches
///
/// Nothing of the caller's terminal. That is the point of it: the sandbox has a
/// terminal, and it is not this one. `/dev/tty` inside the sandbox resolves to
/// the sandbox's own pseudoterminal, and `TIOCSTI` on it pushes characters into
/// the sandbox's own input queue.
///
/// # Where it comes from
///
/// The pseudoterminal is allocated inside the sandbox, from the `/dev/ptmx` the
/// sandbox sees, so its replica is a node in the sandbox's own `devpts`
/// instance. A program that resolves a *path* for its terminal therefore finds
/// one: `ttyname` names `/dev/pts/0`, and `tty(1)`, `who`, and `GPG_TTY`, which
/// gpg populates from `tty` and pinentry then opens, all work. Under a
/// [`run_as`](crate::CageBuilder::run_as) identity the replica belongs to that
/// identity, as a login's terminal belongs to the user logging in, so the
/// command can open it by that path too. The sandbox holds no host
/// pseudoterminal at all.
///
/// The managed `/dev` profile is what provides the `/dev/ptmx` the allocation
/// opens, and the `devpts` instance behind it.
/// [`mount_dev(false)`](crate::CageBuilder::mount_dev) or
/// [`managed_mounts(false)`](crate::CageBuilder::managed_mounts) removes both,
/// and a terminal launch in a root that ships no `/dev/ptmx` of its own then
/// fails at [`SetupStep::AllocateTerminal`](crate::SetupStep::AllocateTerminal).
/// A caller that assembles `/dev` itself mounts a `devpts` instance with
/// `newinstance` and links `/dev/ptmx` to its `ptmx`, as the managed profile
/// does.
///
/// The restriction fallback has no `/dev` of its own, so a restriction's
/// terminal comes from the host's `/dev/ptmx`, and a path for it resolves
/// against the host's `/dev/pts`, which the command sees.
///
/// Nested allocation, by `tmux`, `script`, `sshd`, or Python's `pty`, draws on
/// the same private instance, and sees no pseudoterminal but the sandbox's own.
///
/// # Determinism
///
/// Nothing here is read from the host. The size is whatever the caller states,
/// and [`new`](Self::new) is a stated constant rather than the caller's own
/// window; `TERM` is an environment variable, so a caller that wants one sets
/// it with [`env`](crate::CageBuilder::env); and the termios baseline is
/// written out below rather than inherited.
///
/// # The termios baseline
///
/// Set on the replica before the command exists, so the value is the library's
/// promise rather than the kernel's. It is field for field the kernel's own
/// `tty_std_termios`, which is what a fresh pseudoterminal already carries — a
/// kernel that changed its default would not change this table:
///
/// | Group | Flags |
/// | --- | --- |
/// | Input | `ICRNL`, `IXON` |
/// | Output | `OPOST`, `ONLCR` |
/// | Control | `B38400`, `CS8`, `CREAD`, `HUPCL` |
/// | Local | `ISIG`, `ICANON`, `ECHO`, `ECHOE`, `ECHOK`, `ECHOCTL`, `ECHOKE`, `IEXTEN` |
/// | Characters | `VINTR` `^C`, `VQUIT` `^\`, `VERASE` `DEL`, `VKILL` `^U`, `VEOF` `^D`, `VSTART` `^Q`, `VSTOP` `^S`, `VSUSP` `^Z`, `VREPRINT` `^R`, `VDISCARD` `^O`, `VWERASE` `^W`, `VLNEXT` `^V` |
/// | Reads | `VMIN` 1, `VTIME` 0; `VEOL` and `VEOL2` unset |
///
/// It governs line-mode behavior only. A full-screen application calls
/// `tcsetattr` on the replica itself and takes the terminal from there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Terminal {
    /// The window height in character cells.
    rows: u16,
    /// The window width in character cells.
    cols: u16,
}

impl Terminal {
    /// A terminal 24 rows tall and 80 columns wide.
    ///
    /// The value for a caller with nothing better to say, and a stated constant
    /// rather than anything read from the host. An interactive caller passes
    /// the real size to [`size`](Self::size) and calls [`Pty::resize`] on every
    /// `SIGWINCH` afterwards, because a terminal's size changes over the life of
    /// a session and no launch-time constant can track it.
    pub fn new() -> Terminal {
        Terminal { rows: 24, cols: 80 }
    }

    /// Sets the window size the command starts with, as (rows, columns).
    ///
    /// The size is established on the replica before the command exists, so the
    /// command cannot observe a 0x0 window during startup.
    ///
    /// A zero dimension leaves that dimension as it was, which for a terminal
    /// that has not been sized before is [`new`](Self::new)'s value. Zero is not a small
    /// terminal: it is what a terminal reports when its size is *unknown* — a
    /// pseudoterminal nobody has sized, which is what a multiplexer or
    /// `script(1)` hands on when it was itself started without one — and the
    /// kernel accepts it silently, leaving the sandbox a terminal that answers
    /// "no size" to everything that asks. `stty size` refuses it and a
    /// full-screen program has nothing to draw into. A caller plumbing a real
    /// terminal's reported dimensions into this therefore gets 24 or 80 for a
    /// dimension its own terminal could not report, rather than propagating the
    /// non-answer.
    ///
    /// ```
    /// use ferroday_cage::Terminal;
    ///
    /// assert_eq!(Terminal::new().size(50, 0).get_size(), (50, 80));
    /// assert_eq!(Terminal::new().size(0, 0).get_size(), (24, 80));
    /// ```
    pub fn size(mut self, rows: u16, cols: u16) -> Terminal {
        if rows != 0 {
            self.rows = rows;
        }
        if cols != 0 {
            self.cols = cols;
        }
        self
    }

    /// The window size, as (rows, columns).
    pub fn get_size(&self) -> (u16, u16) {
        (self.rows, self.cols)
    }
}

impl Default for Terminal {
    fn default() -> Terminal {
        Terminal::new()
    }
}

/// The caller's end of the sandbox's terminal: the primary.
///
/// Returned beside the running sandbox by
/// [`Cage::spawn_terminal`](crate::Cage::spawn_terminal). Everything the
/// sandbox writes to its terminal is readable here, and everything written here
/// arrives as the sandbox's terminal input.
///
/// [`Read`](io::Read) and [`Write`](io::Write) are implemented for `&Pty` as
/// well as for `Pty`, and [`resize`](Self::resize) takes `&self`, so an
/// `Arc<Pty>` serves a reader thread and a `SIGWINCH` handler at once. Without
/// that a reader thread has to move the `Pty` and the resize path has nothing
/// left to call; a mutex is worse, because the reader holds the lock while
/// blocked in `read` and a resize then lands only when the sandbox next produces
/// output.
///
/// # Draining
///
/// The primary's buffer is a few kilobytes. A command that writes more than that
/// blocks, so a caller that waits without reading deadlocks. When an unbounded
/// [`Running::wait`](crate::Running::wait) starts, the `Pty` is in one of three
/// states, and only the third is a deadlock:
///
/// - **Drained to end-of-file** — safe: end-of-file means every replica is
///   closed, so nothing can block writing to the terminal. It does not mean the
///   command has exited. A command that closes its standard streams goes on
///   running, and the wait lasts as long as it does.
/// - **Dropped** — safe: after the hangup the command's writes fail with `EIO`
///   rather than block, so a caller that has dropped the primary owes the wait
///   no drain.
/// - **Held and unread** — the deadlocking case.
///
/// A caller that sends no input drains to end-of-file and then waits, which
/// cannot deadlock and ends when the command does:
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let cage = ferroday_cage::Cage::builder().rootfs("/r").command("/bin/sh").build()?;
/// let (mut running, mut pty) = cage.spawn_terminal(&ferroday_cage::Terminal::new())?;
/// std::io::copy(&mut pty, &mut std::io::stdout())?;
/// let status = running.wait()?;
/// # let _ = status;
/// # Ok(())
/// # }
/// ```
///
/// An interactive caller needs both directions at once, and
/// [`relay::Relay`](crate::relay::Relay) is the answer: one poll loop over the
/// primary, the caller's terminal, and the signals a session has to handle,
/// with raw mode and its restoration. A caller composing its own instead needs
/// concurrency, because writes to the primary block too once its input buffer
/// fills, so a large paste into a command that is not reading stalls a loop that
/// writes from the thread it also reads on. Two threads — a reader beside the
/// main thread in the wait — is the right minimum, and a wait that must be
/// bounded is bounded with [`wait_deadline`](crate::Running::wait_deadline) and
/// [`kill_handle`](crate::Running::kill_handle) from the other thread.
///
/// # Lifecycle
///
/// Dropping the `Pty` hangs the terminal up, and the kernel sends `SIGHUP` to
/// the sandbox's foreground process group. That is how an interactive session is
/// ended deliberately; dropping it early ends the session early, which is why it
/// normally outlives the wait.
pub struct Pty {
    /// The primary. The replica is the command's, and no copy of it is kept on
    /// this side: end-of-file here depends on every other copy being closed.
    primary: OwnedFd,
}

impl Pty {
    /// Wraps the primary a launch received from the sandbox.
    pub(crate) fn new(primary: OwnedFd) -> Pty {
        Pty { primary }
    }

    /// Sets the terminal's window size, as (rows, columns), and delivers
    /// `SIGWINCH` to the sandbox's foreground process group.
    ///
    /// Takes `&self`, so a `SIGWINCH` handler can call it while a reader thread
    /// holds the same `Pty` through an `Arc`. An interactive caller calls this
    /// on every `SIGWINCH` of its own, with the size its terminal reports.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), Error> {
        termios::tcsetwinsize(
            &self.primary,
            Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .map_err(terminal_error)
    }

    /// The terminal's window size, as (rows, columns).
    pub fn size(&self) -> Result<(u16, u16), Error> {
        let size = termios::tcgetwinsize(&self.primary).map_err(terminal_error)?;
        Ok((size.ws_row, size.ws_col))
    }
}

impl AsFd for Pty {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.primary.as_fd()
    }
}

impl fmt::Debug for Pty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pty")
            .field("fd", &self.primary)
            .finish_non_exhaustive()
    }
}

impl io::Read for &Pty {
    /// Reads what the sandbox wrote to its terminal.
    ///
    /// Hangup is reported as end-of-file. Reading a pseudoterminal primary after
    /// the last replica closes fails with `EIO` on Linux rather than returning
    /// zero; mapping it here, rather than leaving each caller to know it, is
    /// what makes `std::io::copy` from a `Pty` terminate the way it would from a
    /// pipe. Output the line discipline still holds is readable first, so a
    /// drain that runs to end-of-file loses nothing the command wrote.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match rustix::io::read(&self.primary, buf) {
            Ok(read) => Ok(read),
            Err(Errno::IO) => Ok(0),
            Err(errno) => Err(errno.into()),
        }
    }
}

impl io::Read for Pty {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut &*self, buf)
    }
}

impl io::Write for &Pty {
    /// Writes to the sandbox's terminal input, as though typed at it.
    ///
    /// # Closing input
    ///
    /// There is no way to close the write side of a pseudoterminal: end-of-file
    /// is sent as the `VEOF` character (`^D` in the baseline). That is a line
    /// discipline behavior rather than a property of the descriptor, and it
    /// holds only while the replica is in canonical mode — a program that has
    /// put its terminal in raw mode, an editor or a shell reading a line itself,
    /// receives `VEOF` as the literal byte `0x04` and does whatever it does with
    /// it. Even in canonical mode, `VEOF` on a partial line flushes that line
    /// rather than signalling end-of-file, so a strict end-of-input takes it
    /// twice.
    ///
    /// A caller that needs end-of-input to be unambiguous drops the [`Pty`],
    /// which hangs the terminal up and cannot be mistaken for data, or does not
    /// use a terminal at all: [`Stdio::from_fd`](crate::Stdio::from_fd) on a pipe
    /// closes for real.
    ///
    /// # After the hangup
    ///
    /// A write once every replica is closed still succeeds rather than failing.
    /// Linux puts a write to the primary into the replica's input queue whether
    /// or not a replica is open, and there it stays.
    ///
    /// The consequence for a caller: end-of-file on the [`Read`] side is the
    /// hangup detector, and a successful write is not evidence of anything. A
    /// caller that has drained to end-of-file should stop writing rather than
    /// read the success as a live session.
    ///
    /// [`Read`]: std::io::Read
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        rustix::io::write(&self.primary, buf).map_err(Into::into)
    }

    /// A no-op: a terminal has no buffer on this side to flush.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Write for Pty {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut &*self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut &*self)
    }
}

/// Allocates a pseudoterminal from the `/dev/ptmx` the calling process sees and
/// establishes its size and termios baseline, returning (primary, replica).
///
/// The launch calls this in the first process of the sandbox proper, after the
/// root swap. In a container, `/dev/ptmx` is then the managed `/dev`'s link into
/// the sandbox's own `devpts` instance; in a restriction, it is the host's. The
/// call runs between `fork` and `exec`, so it keeps that window's discipline:
/// raw syscalls over stack data, no allocation, and no panic.
///
/// The open refuses a magic link anywhere in the path. `/dev/ptmx` is a
/// symbolic link in the managed profile, which is followed, but a root that
/// shipped one pointing through `/proc/self/fd` would otherwise hand this
/// process one of its own descriptors in place of a multiplexer. A path that
/// names anything but a multiplexer fails at the unlock, with `ENOTTY`.
///
/// Both ends are opened `O_NOCTTY`: the allocating process takes the replica as
/// its controlling terminal deliberately, with `TIOCSCTTY`, rather than by
/// accident at the open. Both are opened close-on-exec, so no exec'd
/// descendant can hold one it was not given.
///
/// The replica is opened with `TIOCGPTPEER` rather than by the path `ptsname`
/// reports. The peer resolves from the primary's own `devpts` mount, so the
/// replica cannot be a different file than the one just allocated. It is Linux
/// 4.13, well under this crate's floor.
pub(crate) fn allocate(terminal: &Terminal) -> Result<(OwnedFd, OwnedFd), Errno> {
    // Not `provision::containment::open_dir`: this opens one device node by an
    // absolute path, where that helper opens a directory contained in a tree.
    #[expect(clippy::disallowed_methods)]
    let primary = rustix::fs::openat2(
        rustix::fs::CWD,
        c"/dev/ptmx",
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_MAGICLINKS,
    )?;
    pty::unlockpt(&primary)?;
    let replica = pty::ioctl_tiocgptpeer(
        &primary,
        OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
    )?;

    termios::tcsetwinsize(
        &replica,
        Winsize {
            ws_row: terminal.rows,
            ws_col: terminal.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )?;
    let baseline = baseline_termios(&replica)?;
    termios::tcsetattr(&replica, OptionalActions::Now, &baseline)?;
    Ok((primary, replica))
}

/// The termios baseline, stated field for field.
///
/// The fresh replica's own settings are read first only to obtain a `Termios`
/// to overwrite — it has private speed fields, so there is no literal to write.
/// Every mode is then *assigned* rather than composed, so what the command sees
/// is this table and not this table over whatever the kernel had. The line
/// discipline is the one field left alone: `N_TTY` is the only one a
/// pseudoterminal is created with, and its field is spelled differently per
/// architecture.
///
/// The speed is set last, because `set_speed` writes the baud bits of the
/// control modes and assigning those afterwards would drop them.
///
/// Post-fork safe, as [`allocate`] must be: the `Termios` lives on the stack
/// and every write to it is a field assignment.
fn baseline_termios(replica: &OwnedFd) -> Result<termios::Termios, Errno> {
    let mut baseline = termios::tcgetattr(replica)?;
    baseline.input_modes = InputModes::ICRNL | InputModes::IXON;
    baseline.output_modes = OutputModes::OPOST | OutputModes::ONLCR;
    baseline.control_modes = ControlModes::CS8 | ControlModes::CREAD | ControlModes::HUPCL;
    baseline.local_modes = LocalModes::ISIG
        | LocalModes::ICANON
        | LocalModes::ECHO
        | LocalModes::ECHOE
        | LocalModes::ECHOK
        | LocalModes::ECHOCTL
        | LocalModes::ECHOKE
        | LocalModes::IEXTEN;
    // The kernel's own `INIT_C_CC`, index for index. `VSWTC` is undefined on
    // Linux and `VEOL`/`VEOL2` are the "no additional line terminator" zeroes.
    for (index, code) in [
        (SpecialCodeIndex::VINTR, 0o003),
        (SpecialCodeIndex::VQUIT, 0o034),
        (SpecialCodeIndex::VERASE, 0o177),
        (SpecialCodeIndex::VKILL, 0o025),
        (SpecialCodeIndex::VEOF, 0o004),
        (SpecialCodeIndex::VTIME, 0),
        (SpecialCodeIndex::VMIN, 1),
        (SpecialCodeIndex::VSWTC, 0),
        (SpecialCodeIndex::VSTART, 0o021),
        (SpecialCodeIndex::VSTOP, 0o023),
        (SpecialCodeIndex::VSUSP, 0o032),
        (SpecialCodeIndex::VEOL, 0),
        (SpecialCodeIndex::VREPRINT, 0o022),
        (SpecialCodeIndex::VDISCARD, 0o017),
        (SpecialCodeIndex::VWERASE, 0o027),
        (SpecialCodeIndex::VLNEXT, 0o026),
        (SpecialCodeIndex::VEOL2, 0),
    ] {
        baseline.special_codes[index] = code;
    }
    baseline.set_speed(BASELINE_SPEED).map(|()| baseline)
}

/// A failed pseudoterminal operation, as the typed error.
fn terminal_error(errno: Errno) -> Error {
    Error::Terminal {
        source: errno.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_terminal_is_eighty_by_twenty_four() {
        // A stated constant rather than anything read from the host, so a launch
        // that says nothing about its size is still reproducible.
        assert_eq!(Terminal::new().get_size(), (24, 80));
        assert_eq!(Terminal::default(), Terminal::new());
    }

    #[test]
    fn a_stated_size_replaces_the_default() {
        assert_eq!(Terminal::new().size(50, 200).get_size(), (50, 200));
    }

    /// Zero is what a terminal reports when its size is unknown, not a terminal
    /// with no rows. A caller passing along what its own terminal said should
    /// land on the default rather than hand the sandbox a terminal that answers
    /// "no size" to everything that asks.
    #[test]
    fn a_zero_dimension_leaves_that_dimension_alone() {
        assert_eq!(Terminal::new().size(0, 0).get_size(), (24, 80));
        assert_eq!(Terminal::new().size(50, 0).get_size(), (50, 80));
        assert_eq!(Terminal::new().size(0, 200).get_size(), (24, 200));
        // Only the zero dimension is left alone; a stated one still applies.
        assert_eq!(
            Terminal::new().size(50, 200).size(0, 132).get_size(),
            (50, 132),
        );
    }

    #[test]
    fn an_allocated_terminal_carries_the_size_and_the_baseline() {
        let terminal = Terminal::new().size(43, 132);
        let (primary, replica) = allocate(&terminal).expect("a pseudoterminal is allocatable");

        // The size is established before the command exists, so nothing can
        // observe a 0x0 window; it reads back from either end.
        let pty = Pty::new(primary);
        assert_eq!(pty.size().expect("the primary reports its size"), (43, 132));

        let settings = termios::tcgetattr(&replica).expect("the replica reports its settings");
        assert_eq!(
            settings.input_modes,
            InputModes::ICRNL | InputModes::IXON,
            "the input modes are the stated baseline exactly",
        );
        assert_eq!(
            settings.output_modes,
            OutputModes::OPOST | OutputModes::ONLCR
        );
        assert!(
            settings
                .local_modes
                .contains(LocalModes::ICANON | LocalModes::ECHO)
        );
        assert!(
            settings
                .control_modes
                .contains(ControlModes::CS8 | ControlModes::CREAD)
        );
        assert_eq!(settings.output_speed(), BASELINE_SPEED);
        assert_eq!(settings.special_codes[SpecialCodeIndex::VEOF], 0o004);
        assert_eq!(settings.special_codes[SpecialCodeIndex::VMIN], 1);
        assert_eq!(settings.special_codes[SpecialCodeIndex::VEOL], 0);
    }

    #[test]
    fn a_resize_is_visible_from_both_ends() {
        let (primary, replica) = allocate(&Terminal::new()).expect("a pseudoterminal");
        let pty = Pty::new(primary);
        pty.resize(11, 22).expect("the resize applies");
        assert_eq!(pty.size().expect("the size reads back"), (11, 22));
        let size = termios::tcgetwinsize(&replica).expect("the replica sees the size");
        assert_eq!((size.ws_row, size.ws_col), (11, 22));
    }

    #[test]
    fn hangup_reads_as_end_of_file() {
        use std::io::{Read as _, Write as _};

        let (primary, replica) = allocate(&Terminal::new()).expect("a pseudoterminal");
        let mut pty = Pty::new(primary);
        // Output the line discipline still holds is readable before the hangup
        // is reported, so a drain loses nothing the replica wrote.
        rustix::io::write(&replica, b"held\n").expect("the replica writes");
        drop(replica);

        let mut drained = Vec::new();
        pty.read_to_end(&mut drained)
            .expect("the drain ends rather than failing with EIO");
        // `ONLCR` is in force, so the newline the replica wrote arrives as CRLF.
        assert_eq!(drained, b"held\r\n");
        assert_eq!(pty.read(&mut [0u8; 8]).expect("end-of-file repeats"), 0);
        // The write side keeps accepting bytes after the hangup rather than
        // failing: Linux puts a write to the primary into the replica's input
        // queue whether or not a replica is open. So the read side is the
        // hangup detector and the write side is not — a successful write says
        // nothing about whether anyone is there.
        assert_eq!(pty.write(b"x").expect("the write is accepted"), 1);

        // What a read finds after that write is timing, and is deliberately not
        // asserted. `ECHO` is in force, so the line discipline copies the byte
        // the primary wrote onto the output queue the primary reads from: a
        // read that beats the echo answers end-of-file, and one that does not
        // answers the echoed byte. What holds either way is that the read side
        // stays usable — a hangup already reported never becomes an error.
        let mut echo = [0u8; 8];
        let read = pty
            .read(&mut echo)
            .expect("the read side stays usable after a write");
        assert!(
            read == 0 || &echo[..read] == b"x",
            "a read after the hangup found neither end-of-file nor the echo: {:?}",
            &echo[..read],
        );
    }
}
