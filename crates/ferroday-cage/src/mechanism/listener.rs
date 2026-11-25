//! The listener of a seccomp filter whose refusals are reported: a thread of
//! the caller's that answers each call the filter holds, and reports it.
//!
//! A reporting filter ([`notifying`](super::seccomp::notifying)) holds each
//! call its policy refuses and notifies its listener, which the command stage
//! hands the caller before it executes the command. The thread here starts
//! before the launch forks and waits on the listener channel, so nothing the
//! launch does waits on it in turn: the caller reads the setup's report as it
//! always does, and a refused call the stage makes after the hand-over, its
//! `execve` among them, is answered. It then receives each notification, answers it with what the policy as compiled answers the
//! same call, run by [`eval`] over the `seccomp_data` the kernel recorded, and
//! offers a [`SeccompReport`] of it to a queue the caller reads. The command
//! waits for each answer, so the thread never waits on the queue: a report it
//! has no room for is dropped and counted.
//!
//! # Pace
//!
//! A command that spins on a refused call has this thread answer as fast as it
//! asks: about half a core of the caller's, measured, for as long as it spins,
//! and outside any limit the sandbox runs under. The thread answers a burst of
//! [`BURST`] at once and paces the rest at one every [`SPACING`], holding each
//! call until its answer is due, so a command that spins slows itself rather
//! than costing the caller. No command that is not spinning comes near either
//! number.
//!
//! # Ending
//!
//! From Linux 5.8 the listener hangs up once no task the filter governs is
//! left, and the thread ends then, which ends the queue for its reader. Below
//! 5.8 it ends with the caller's process. A caller that exits takes the thread
//! with it, and the kernel then answers every later refused call `ENOSYS`:
//! still refused, under another errno.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::Arc;
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags};
use rustix::io::Errno;
use syscalls::Sysno;

use super::seccomp::{RET_ACTION_FULL, RET_DATA, RET_ERRNO, eval};
use super::sys::errno;
use super::{ReportedFilter, SockFilter};
use crate::hardening::SeccompReport;
use crate::reports::{Reporter, Reports};

/// How many calls the listener answers at once before it paces them.
pub(crate) const BURST: u32 = 1000;

/// The time between paced answers, a thousand a second.
pub(crate) const SPACING: Duration = Duration::from_millis(1);

/// The largest errno a seccomp answer carries: the kernel answers a larger one
/// as this.
const MAX_ERRNO: u32 = 4095;

/// The kernel's `struct seccomp_notif`: a notification's id, the thread's pid,
/// flags, and the call's `seccomp_data`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Notification {
    id: u64,
    pid: u32,
    flags: u32,
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

/// The kernel's `struct seccomp_notif_resp`: the answer to the notification
/// `id`, the value or the negated errno the call returns, and flags.
#[repr(C)]
#[derive(Clone, Copy)]
struct Answer {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

// The layouts are the kernel's on every architecture the crate builds for, and
// the ioctl numbers below encode their sizes.
const _: () = {
    assert!(size_of::<Notification>() == 80);
    assert!(std::mem::offset_of!(Notification, nr) == 16);
    assert!(std::mem::offset_of!(Notification, args) == 32);
    assert!(size_of::<Answer>() == 24);
};

/// `SECCOMP_IOCTL_NOTIF_RECV`: `_IOWR('!', 0, struct seccomp_notif)`.
const NOTIF_RECV: usize = 0xC050_2100;
/// `SECCOMP_IOCTL_NOTIF_SEND`: `_IOWR('!', 1, struct seccomp_notif_resp)`.
const NOTIF_SEND: usize = 0xC018_2101;
/// `SECCOMP_IOCTL_NOTIF_ID_VALID` as Linux 5.0 defined it, `_IOR('!', 2,
/// __u64)`. Linux 5.17 corrected the direction to `_IOW` and kept this number,
/// so it is the one every kernel answers.
const NOTIF_ID_VALID: usize = 0x8008_2102;
/// `SECCOMP_GET_NOTIF_SIZES`.
const GET_NOTIF_SIZES: usize = 3;

/// A listener thread waiting for its launch to fork: it takes the caller's end
/// of the listener channel once there is one, and then the listener the
/// command stage sends over it.
pub(crate) struct Awaiting {
    /// Where the channel's caller end goes. Dropped unsent, as a launch that
    /// fails before it forks drops it, it ends the thread.
    channel: SyncSender<OwnedFd>,
}

impl Awaiting {
    /// Hands the thread the caller's end of the listener channel.
    pub(crate) fn hand(self, channel: OwnedFd) {
        // A thread already gone has ended its reports, and needs nothing more.
        let _ = self.channel.send(channel);
    }
}

/// Starts the thread that serves a launch's listener, before the launch forks,
/// and returns it waiting for the launch with the receiving end of its reports.
///
/// The filter is installed from `reported`'s program by
/// [`notifying`](super::seccomp::notifying), and the thread answers by the
/// program itself. Where the channel hangs up without a listener, the command
/// stage failed first, and the thread ends with no report.
///
/// Fails where the kernel's notification structures are not the ones the
/// thread reads, which no kernel since they were added (Linux 5.0) has
/// changed, or where the thread cannot be started.
pub(crate) fn prepare(
    reported: &ReportedFilter,
) -> std::io::Result<(Awaiting, Reports<SeccompReport>)> {
    if notification_sizes()? != [80, 24, 64] {
        return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
    }
    let (reporter, reports) = Reporter::new();
    let (hand, handed) = std::sync::mpsc::sync_channel::<OwnedFd>(1);
    let answers = Arc::clone(&reported.answers);
    let arch = reported.arch;
    std::thread::Builder::new()
        .name("fcage-seccomp".to_string())
        .spawn(move || {
            let Ok(channel) = handed.recv() else {
                return;
            };
            let Ok(Some(listener)) = super::receive_tagged(&channel, super::LISTENER_BYTE) else {
                return;
            };
            drop(channel);
            serve(&listener, &answers, arch, reporter);
        })?;
    Ok((Awaiting { channel: hand }, reports))
}

/// The sizes of `seccomp_notif`, `seccomp_notif_resp` and `seccomp_data` as
/// this kernel has them.
fn notification_sizes() -> std::io::Result<[u16; 3]> {
    let mut sizes = [0u16; 3];
    // SAFETY: the kernel writes the three sizes, six bytes, into the array,
    // which outlives the call.
    unsafe { syscalls::syscall!(Sysno::seccomp, GET_NOTIF_SIZES, 0usize, sizes.as_mut_ptr()) }
        .map_err(|err| std::io::Error::from(errno(err)))?;
    Ok(sizes)
}

/// Answers and reports each notification on `listener` until it hangs up.
fn serve(
    listener: &OwnedFd,
    answers: &[SockFilter],
    arch: u32,
    mut reporter: Reporter<SeccompReport>,
) {
    let mut pace = Pace::new(Instant::now());
    while wait_for(listener.as_fd()) {
        let notification = match receive(listener.as_fd()) {
            Ok(notification) => notification,
            // The call was interrupted, or its thread ended, before this read
            // it; nothing is waiting for an answer.
            Err(Errno::NOENT | Errno::INTR) => continue,
            Err(_) => return,
        };
        if let Some(wait) = pace.answer(Instant::now()) {
            std::thread::sleep(wait);
        }
        let call = eval::Call {
            arch: notification.arch,
            nr: notification.nr as u32,
            instruction_pointer: notification.instruction_pointer,
            args: notification.args,
        };
        let errno = errno_for(answers, &call);
        // The name is read before the notification is checked, so a name read
        // from a thread the notification still names is that thread's: a
        // thread holding a call is not gone, and its id not reused.
        let command = command_of(notification.pid);
        if !still_waiting(listener.as_fd(), notification.id) {
            continue;
        }
        // An answer the kernel refuses is one the call never received: a
        // signal interrupted it, and a restarted call is notified again.
        if send(listener.as_fd(), notification.id, errno).is_err() {
            continue;
        }
        reporter.offer(|| SeccompReport::Denied {
            syscall: i64::from(notification.nr),
            name: name_of(notification.nr, notification.arch, arch),
            arch: notification.arch,
            thread: notification.pid,
            command,
            arguments: notification.args,
            errno,
        });
    }
}

/// Waits until `listener` holds a notification, answering `false` once it has
/// hung up with none.
fn wait_for(listener: BorrowedFd<'_>) -> bool {
    loop {
        let mut fds = [PollFd::new(&listener, PollFlags::IN)];
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => {
                let events = fds[0].revents();
                if events.contains(PollFlags::IN) {
                    return true;
                }
                if events.intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL) {
                    return false;
                }
            }
            Err(Errno::INTR) => {}
            Err(_) => return false,
        }
    }
}

/// Receives the next notification.
fn receive(listener: BorrowedFd<'_>) -> Result<Notification, Errno> {
    // The kernel refuses a buffer that is not zeroed.
    let mut notification = Notification {
        id: 0,
        pid: 0,
        flags: 0,
        nr: 0,
        arch: 0,
        instruction_pointer: 0,
        args: [0; 6],
    };
    // SAFETY: the kernel writes one `seccomp_notif`, whose layout and size the
    // struct has, into it; the struct outlives the call.
    unsafe {
        syscalls::syscall!(
            Sysno::ioctl,
            listener.as_raw_fd(),
            NOTIF_RECV,
            &mut notification as *mut Notification
        )
    }
    .map_err(errno)?;
    Ok(notification)
}

/// Whether the call notification `id` names still waits for its answer.
fn still_waiting(listener: BorrowedFd<'_>, id: u64) -> bool {
    // SAFETY: the kernel reads the id, eight bytes, from the variable, which
    // outlives the call.
    unsafe {
        syscalls::syscall!(
            Sysno::ioctl,
            listener.as_raw_fd(),
            NOTIF_ID_VALID,
            &id as *const u64
        )
    }
    .is_ok()
}

/// Answers the call notification `id` names with `errno`.
fn send(listener: BorrowedFd<'_>, id: u64, errno_answered: u16) -> Result<(), Errno> {
    let answer = Answer {
        id,
        val: 0,
        error: -i32::from(errno_answered),
        flags: 0,
    };
    // SAFETY: the kernel reads one `seccomp_notif_resp`, whose layout and size
    // the struct has, from it; the struct outlives the call.
    unsafe {
        syscalls::syscall!(
            Sysno::ioctl,
            listener.as_raw_fd(),
            NOTIF_SEND,
            &answer as *const Answer
        )
    }
    .map(|_| ())
    .map_err(errno)
}

/// The errno the policy as compiled, `answers`, answers `call` with.
///
/// Every notification comes from a return the notifying program rewrote from
/// an errno answer, so the compiled program answers the same call with that
/// errno; the kernel's ceiling applies to it as to any. Were it to answer
/// anything else, the call is refused with `EPERM`, which is what the filter
/// is there to do.
fn errno_for(answers: &[SockFilter], call: &eval::Call) -> u16 {
    match eval::answer(answers, call) {
        Some(ret) if ret & RET_ACTION_FULL == RET_ERRNO => (ret & RET_DATA).min(MAX_ERRNO) as u16,
        _ => rustix::io::Errno::PERM.raw_os_error() as u16,
    }
}

/// The name of the program the thread `pid` runs, from its `comm`, or `None`
/// where it cannot be read.
fn command_of(pid: u32) -> Option<String> {
    let comm = std::fs::read(format!("/proc/{pid}/comm")).ok()?;
    let comm = comm.strip_suffix(b"\n").unwrap_or(&comm);
    Some(String::from_utf8_lossy(comm).into_owned())
}

/// The name of syscall `nr`, made under the audit architecture `made`, where
/// that is the build's own, `native`, and its table names the number.
fn name_of(nr: i32, made: u32, native: u32) -> Option<&'static str> {
    if made != native {
        return None;
    }
    let nr = usize::try_from(nr).ok()?;
    Sysno::new(nr).map(|syscall| syscall.name())
}

/// The listener's pace: a burst of [`BURST`] answers at once, then one every
/// [`SPACING`].
///
/// Kept as the time the next answer is due. Each answer moves it on by
/// [`SPACING`], and it never falls further behind the clock than
/// [`span`](Pace::span), which is how a listener idle for that long has its
/// whole burst back.
#[derive(Debug)]
struct Pace {
    /// When the next answer is due.
    due: Instant,
}

impl Pace {
    /// A pace with its whole burst to give.
    fn new(now: Instant) -> Pace {
        Pace {
            due: now.checked_sub(Pace::span()).unwrap_or(now),
        }
    }

    /// How far the next answer's turn may fall behind the clock: the turns of
    /// a whole burst, the last of them now.
    fn span() -> Duration {
        SPACING.saturating_mul(BURST - 1)
    }

    /// Takes the next answer's turn at `now`, returning how long to wait for
    /// it, or `None` where it is due already.
    fn answer(&mut self, now: Instant) -> Option<Duration> {
        let earliest = now.checked_sub(Pace::span()).unwrap_or(now);
        let turn = self.due.max(earliest);
        self.due = turn.checked_add(SPACING).unwrap_or(turn);
        turn.checked_duration_since(now)
            .filter(|wait| !wait.is_zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_answered_at_once_and_the_rest_are_paced() {
        let start = Instant::now();
        let mut pace = Pace::new(start);
        for answered in 0..BURST {
            assert_eq!(pace.answer(start), None, "answer {answered}");
        }
        // Past the burst, each answer waits one spacing more than the last.
        assert_eq!(pace.answer(start), Some(SPACING));
        assert_eq!(pace.answer(start), Some(SPACING * 2));
    }

    #[test]
    fn an_idle_listener_has_its_burst_back() {
        let start = Instant::now();
        let mut pace = Pace::new(start);
        for _ in 0..BURST + 10 {
            pace.answer(start);
        }
        let later = start.checked_add(Pace::span() * 2).unwrap();
        for answered in 0..BURST {
            assert_eq!(pace.answer(later), None, "answer {answered}");
        }
        assert!(pace.answer(later).is_some());
    }

    #[test]
    fn a_paced_answer_waits_only_for_its_turn() {
        let start = Instant::now();
        let mut pace = Pace::new(start);
        for _ in 0..BURST {
            pace.answer(start);
        }
        // A second on, the spinning command has had its thousand; the next is
        // due one spacing past the burst it used.
        let later = start.checked_add(Duration::from_secs(1)).unwrap();
        assert_eq!(pace.answer(later), None);
    }

    #[test]
    fn the_answer_is_the_compiled_programs_errno() {
        use super::super::seccomp::{AUDIT_ARCH_X86_64, ret_errno};
        // A program refusing call 5 with EACCES and call 6 with an errno past
        // the kernel's ceiling, allowing the rest.
        let program = [
            SockFilter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: 5,
            },
            SockFilter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: ret_errno(13),
            },
            SockFilter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: 6,
            },
            SockFilter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: ret_errno(9000),
            },
            SockFilter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: super::super::seccomp::RET_ALLOW,
            },
        ];
        let call = |nr| eval::Call::new(AUDIT_ARCH_X86_64, nr, &[]);
        assert_eq!(errno_for(&program, &call(5)), 13);
        assert_eq!(errno_for(&program, &call(6)), 4095);
        // Not an errno answer: refused all the same.
        assert_eq!(errno_for(&program, &call(7)), 1);
    }

    #[test]
    fn a_name_is_given_only_under_the_builds_own_architecture() {
        let native = 0xC000_003E;
        let getpid = Sysno::getpid.id();
        assert_eq!(name_of(getpid, native, native), Some("getpid"));
        assert_eq!(name_of(getpid, 0x4000_0003, native), None);
        assert_eq!(name_of(-1, native, native), None);
    }
}
