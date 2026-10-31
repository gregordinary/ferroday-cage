//! A pseudoterminal a test plays the user at: allocating one, starting a
//! process on it, reading what it writes, and comparing its settings.
//!
//! The library's relay tests drive the relay in process over a pair from
//! [`pair`], and `fcage`'s terminal tests run the built binary on the replica
//! of one with [`spawn_controlled`]. Both read the primary through
//! [`drain_until`], so a deadline is always a deadline.

use std::os::fd::{AsFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use rustix::pty::OpenptFlags;
use rustix::termios::{self, LocalModes, SpecialCodeIndex, Termios, Winsize};

/// A pseudoterminal pair sized `rows` by `cols`: the primary, which the test
/// holds, and the replica, which stands in for a terminal.
///
/// Both ends are close-on-exec, so a process the test starts inherits only the
/// descriptors it is handed, and neither is anyone's controlling terminal until
/// [`spawn_controlled`] makes the replica one.
pub fn pair(rows: u16, cols: u16) -> (OwnedFd, OwnedFd) {
    let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
    let primary = rustix::pty::openpt(flags).expect("a pseudoterminal is available");
    rustix::pty::unlockpt(&primary).expect("the replica unlocks");
    let replica = rustix::pty::ioctl_tiocgptpeer(&primary, flags).expect("the replica opens");
    // Sized before anything runs on it, so a size a process copies at its start
    // is this one rather than the race's winner.
    termios::tcsetwinsize(&primary, winsize(rows, cols)).expect("the size is settable");
    (primary, replica)
}

/// A window size in rows and columns.
pub fn winsize(rows: u16, cols: u16) -> Winsize {
    Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// Starts `command` in a session of its own whose controlling terminal is
/// `replica`, with the replica on all three standard descriptors.
///
/// That is the posture a program run from an interactive shell has, and the
/// only one in which raw mode, the size copy, job control and the terminal's
/// restoration can be observed from outside.
///
/// The one `unsafe` block in this crate: `pre_exec` is how a child process
/// joins a session of its own before it executes.
#[expect(unsafe_code)]
pub fn spawn_controlled(command: &mut Command, replica: &OwnedFd) -> Child {
    use std::os::unix::process::CommandExt as _;

    let clone = || Stdio::from(replica.try_clone().expect("the replica clones"));
    command.stdin(clone()).stdout(clone()).stderr(clone());
    // SAFETY: between fork and exec the child calls only `setsid` and one
    // ioctl, both async-signal-safe, and allocates nothing. A session of its own
    // is what lets the replica, already its standard input, become its
    // controlling terminal.
    unsafe {
        command.pre_exec(|| {
            rustix::process::setsid()?;
            rustix::process::ioctl_tiocsctty(rustix::stdio::stdin())?;
            Ok(())
        });
    }
    command.spawn().expect("the command starts")
}

/// Writes all of `text` to `fd`, which is how a test types at a session.
pub fn send(fd: impl AsFd, text: &str) {
    let fd = fd.as_fd();
    let mut written = 0;
    while written < text.len() {
        written += rustix::io::write(fd, &text.as_bytes()[written..]).expect("the write lands");
    }
}

/// Reads whatever `primary` has ready, waiting no later than `deadline`, and
/// appends it to `into`.
///
/// Returns whether the session is still producing: `false` at end of file, at
/// the hangup a pseudoterminal primary reports as `EIO`, or once the deadline
/// has passed.
///
/// Polled rather than read outright, so a deadline is a deadline: a blocking
/// read on a quiet session would ignore it and hang the whole run. `EINTR` and
/// `EAGAIN` both mean "nothing yet, ask again" and neither ends the session.
pub fn drain_until(primary: impl AsFd, deadline: Instant, into: &mut String) -> bool {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::io::Errno;

    let primary = primary.as_fd();
    let remaining = deadline.saturating_duration_since(Instant::now());
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(remaining.subsec_nanos()),
    };
    let mut slots = [PollFd::new(&primary, PollFlags::IN)];
    match poll(&mut slots, Some(&timeout)) {
        Ok(0) => return false,
        Ok(_) => {}
        Err(Errno::INTR) => return true,
        Err(errno) => panic!("waiting on the session failed: {errno}"),
    }
    let mut buf = [0u8; 4096];
    match rustix::io::read(primary, &mut buf) {
        Ok(0) | Err(Errno::IO) => false,
        Ok(read) => {
            into.push_str(&String::from_utf8_lossy(&buf[..read]));
            true
        }
        Err(Errno::INTR | Errno::AGAIN) => true,
        Err(errno) => panic!("reading the session failed: {errno}"),
    }
}

/// Reads `primary` into `seen` until `needle` appears in it or `deadline`
/// passes, and reports whether it appeared.
///
/// Everything is accumulated rather than searched per read, because a session's
/// echo and its command's output arrive interleaved and in whatever chunks the
/// line discipline chose.
pub fn read_until(primary: impl AsFd, needle: &str, deadline: Instant, seen: &mut String) -> bool {
    let primary = primary.as_fd();
    while !seen.contains(needle) {
        if !drain_until(primary, deadline, seen) {
            break;
        }
    }
    seen.contains(needle)
}

/// Whether `settings` are raw: canonical input and echo both off.
///
/// They are the two `make_raw` clears that a user notices at once, and the two
/// a cooked terminal always has.
pub fn is_raw(settings: &Termios) -> bool {
    !settings
        .local_modes
        .intersects(LocalModes::ICANON | LocalModes::ECHO)
}

/// Asserts a terminal's settings came back field for field as they went in.
///
/// Compared rather than eyeballed, because "looks interactive again" is not
/// the promise a relay makes.
pub fn assert_restored(before: &Termios, after: &Termios) {
    assert_eq!(
        before.input_modes, after.input_modes,
        "the input modes were not restored",
    );
    assert_eq!(
        before.output_modes, after.output_modes,
        "the output modes were not restored",
    );
    assert_eq!(
        before.control_modes, after.control_modes,
        "the control modes were not restored",
    );
    assert_eq!(
        before.local_modes, after.local_modes,
        "the local modes were not restored",
    );
    // `SpecialCodes` carries no equality of its own, and `make_raw` clears VMIN
    // and VTIME and leaves the rest, so a restoration that missed any of them
    // would show here.
    for (name, index) in [
        ("VINTR", SpecialCodeIndex::VINTR),
        ("VQUIT", SpecialCodeIndex::VQUIT),
        ("VERASE", SpecialCodeIndex::VERASE),
        ("VKILL", SpecialCodeIndex::VKILL),
        ("VEOF", SpecialCodeIndex::VEOF),
        ("VTIME", SpecialCodeIndex::VTIME),
        ("VMIN", SpecialCodeIndex::VMIN),
        ("VSTART", SpecialCodeIndex::VSTART),
        ("VSTOP", SpecialCodeIndex::VSTOP),
        ("VSUSP", SpecialCodeIndex::VSUSP),
        ("VEOL", SpecialCodeIndex::VEOL),
        ("VREPRINT", SpecialCodeIndex::VREPRINT),
        ("VDISCARD", SpecialCodeIndex::VDISCARD),
        ("VWERASE", SpecialCodeIndex::VWERASE),
        ("VLNEXT", SpecialCodeIndex::VLNEXT),
        ("VEOL2", SpecialCodeIndex::VEOL2),
    ] {
        assert_eq!(
            before.special_codes[index], after.special_codes[index],
            "{name} was not restored",
        );
    }
}
