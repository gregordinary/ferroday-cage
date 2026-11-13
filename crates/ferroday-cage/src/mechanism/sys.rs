//! The process-level system calls the launch path makes itself: fork, exec,
//! exit, a signal's disposition, the signal mask, a descriptor signals are
//! read from, and what reaped children used.
//!
//! rustix keeps these in a module reserved for libc-like runtimes, whose name
//! it does not hold stable for anyone else, so they are issued here through the
//! `syscalls` conduit the crate already carries for `mount_setattr` and the
//! seccomp install. Every function is inline assembly and a register move:
//! none allocates, takes a lock, or touches a libc `errno` slot, so each is
//! usable in the post-fork window [`child`](super::child) documents.
//!
//! The kernel's signal constants and the layout of its `struct sigaction` are
//! per architecture. The values below are the ones every architecture the
//! mechanism's build gate admits agrees on, and the one layout difference
//! between them, riscv64 having no restorer field, is spelled out where it
//! applies. An architecture outside the gate does not build.

use std::ffi::{CStr, c_long, c_ulong};
use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};

use rustix::fs::OFlags;
use rustix::io::Errno;
use rustix::process::{Pid, Signal};
use syscalls::Sysno;

use super::Forked;

/// Which side of a [`fork`] a process is on.
#[derive(Debug)]
pub(crate) enum Fork {
    /// The new process.
    Child,
    /// The process that called [`fork`], and the new process's pid.
    ParentOf(Pid),
}

/// Which side of a [`fork_with_pidfd`] a process is on.
#[derive(Debug)]
pub(crate) enum PidfdFork {
    /// The new process.
    Child,
    /// The process that called [`fork_with_pidfd`], and the new process, named
    /// by its pid and the pidfd the fork opened for it.
    ParentOf(Forked),
}

/// `CLONE_PIDFD`: the kernel opens a pidfd for the new process as it creates
/// it, and stores the descriptor where the parent-tid argument points.
const CLONE_PIDFD: usize = 0x1000;

/// Forks the calling process: `clone` with `SIGCHLD` as the exit signal and
/// no other flag, which is what the `fork` system call is on the architectures
/// that still have one.
///
/// Every other argument is zero, and with no flag that reads them the kernel
/// ignores them.
///
/// Every signal is blocked across the call, as `posix_spawn` blocks them. The
/// child process is a copy of one whose handlers are still installed in it,
/// and a handler that ran there — one that takes a lock, as a logging or
/// signal-forwarding library's does — would break the post-fork discipline
/// before the child process's first instruction could prevent it. The child
/// process therefore starts with every signal blocked, and unblocks none until
/// it has put the dispositions it inherited back to the default; the caller's
/// mask is restored in the parent process before this returns there.
/// `SIGKILL` and `SIGSTOP` cannot be blocked, and need no handler to be safe.
///
/// # Safety
///
/// The child is a copy of the calling process that holds only the calling
/// thread. Until it calls [`execve`] or [`exit_group`] it may do only what
/// [`child`](super::child) permits after a fork: no allocation, no lock, no
/// libc, no panic.
pub(crate) unsafe fn fork() -> Result<Fork, Errno> {
    // SAFETY: no flag reads a pointer argument, and the caller's contract is
    // this function's.
    let pid = unsafe { clone_process(0, std::ptr::null_mut()) }?;
    Ok(match pid {
        Some(child) => Fork::ParentOf(child),
        None => Fork::Child,
    })
}

/// [`fork`], with a pidfd for the new process opened by the same call.
///
/// The kernel opens the pidfd as it creates the process, so it refers to that
/// process from its first instant. A pidfd opened afterwards with
/// `pidfd_open` names whatever holds the pid by then, which, once something
/// else in the caller has reaped the child, can be an unrelated process.
///
/// `clone` with `CLONE_PIDFD` rather than `clone3`, which carries the same
/// flag. Both arrived before the crate's kernel floor, and the container
/// runtimes' default seccomp profiles answer `clone3` with `ENOSYS` so that
/// their C libraries fall back to `clone`. The descriptor is stored through the
/// parent-tid argument, which is `clone`'s third on every architecture the
/// build admits; the arguments whose order differs between them, the child-tid
/// pointer and the thread pointer, are not read.
///
/// The descriptor is close-on-exec. The kernel stores its number into the
/// parent's memory after the child's memory was copied, and installs it in the
/// parent's descriptor table alone, so the child holds no copy of it.
///
/// # Safety
///
/// As for [`fork`].
pub(crate) unsafe fn fork_with_pidfd() -> Result<PidfdFork, Errno> {
    let mut pidfd: i32 = -1;
    // SAFETY: `pidfd` is a live local the kernel writes one `int` to, in this
    // process only, and the caller's contract is this function's.
    let pid = unsafe { clone_process(CLONE_PIDFD, &raw mut pidfd) }?;
    Ok(match pid {
        Some(child) => {
            // SAFETY: the kernel stored a fresh descriptor, owned by this
            // process and by nothing else, where `CLONE_PIDFD` asked it to.
            let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
            PidfdFork::ParentOf(Forked::new(child, pidfd))
        }
        None => PidfdFork::Child,
    })
}

/// The `clone` both forks make: `flags` with `SIGCHLD` as the exit signal,
/// `parent_tid` as the third argument, and every other argument zero, with
/// every signal blocked across the call. `None` in the child, and the child's
/// pid in the parent.
///
/// # Safety
///
/// As for [`fork`]; and `parent_tid` is null or valid for the write a flag in
/// `flags` asks of it.
unsafe fn clone_process(flags: usize, parent_tid: *mut i32) -> Result<Option<Pid>, Errno> {
    let flags = flags | Signal::CHILD.as_raw() as usize;
    // SAFETY: blocking signals runs nothing. The mask is the calling thread's
    // own, and the previous one is restored below on every path that returns
    // in this process.
    let previous = unsafe { sigprocmask(How::SetMask, Some(&SigSet::all())) }?;
    // SAFETY: `clone` with an exit signal duplicates the process as `fork`
    // does; it writes `parent_tid` only for a flag that asks it to, which the
    // caller vouches for, and reads no other pointer. What the child may do
    // afterwards is the caller's contract.
    let pid =
        unsafe { syscalls::syscall!(Sysno::clone, flags, 0usize, parent_tid, 0usize, 0usize) }
            .map_err(errno);
    // The kernel answers 0 in the child and the child's pid, which is never 0,
    // in the parent.
    let forked = pid.map(|pid| Pid::from_raw(pid as i32));
    if !matches!(forked, Ok(None)) {
        // SAFETY: `previous` is the mask this thread ran under before the
        // block above, so restoring it lets run only what could run then. The
        // call cannot fail with a live set of the kernel's size, and a failure
        // would leave this thread blocked rather than run anything.
        let _ = unsafe { sigprocmask(How::SetMask, Some(&previous)) };
    }
    forked
}

/// Sends `signal` to every process the caller may signal, except itself and
/// the init of its PID namespace: `kill(-1, signal)`.
///
/// Sent by the init of a PID namespace, it reaches every other process of the
/// namespace, and of any namespace nested in it. rustix's `Pid` cannot spell
/// `-1`.
pub(crate) fn kill_all(signal: Signal) -> Result<(), Errno> {
    // SAFETY: the call takes two integers and touches no memory.
    unsafe { syscalls::syscall!(Sysno::kill, -1i32, signal.as_raw()) }
        .map(|_| ())
        .map_err(errno)
}

/// Replaces the process image, returning only the reason it could not.
///
/// # Safety
///
/// `argv` and `envp` point at null-terminated arrays of pointers to
/// NUL-terminated strings, all of which stay valid for the call.
pub(crate) unsafe fn execve(path: &CStr, argv: *const *const u8, envp: *const *const u8) -> Errno {
    // SAFETY: `path` is a live C string and the caller vouches for the two
    // arrays. On success the call does not return.
    match unsafe { syscalls::syscall!(Sysno::execve, path.as_ptr(), argv, envp) } {
        Err(err) => errno(err),
        // `execve` answers only with an error; a success replaces this image.
        Ok(_) => Errno::NOEXEC,
    }
}

/// Ends the process with `code`.
///
/// `exit_group` does not return. A seccomp policy can nonetheless refuse it
/// with an errno, and then `exit` ends the calling thread, which after a fork
/// is the only one. A policy that refuses both leaves nothing to end the
/// process with, and this sleeps until a signal ends it instead.
pub(crate) fn exit_group(code: i32) -> ! {
    // SAFETY: the call takes an integer and touches no memory.
    let _ = unsafe { syscalls::syscall!(Sysno::exit_group, code) };
    loop {
        // SAFETY: as above.
        let _ = unsafe { syscalls::syscall!(Sysno::exit, code) };
        // SAFETY: a `ppoll` over no descriptors with no timeout and no mask
        // reads no memory and returns only when a signal interrupts it.
        let _ = unsafe { syscalls::syscall!(Sysno::ppoll, 0usize, 0usize, 0usize, 0usize) };
    }
}

/// What a signal does when it arrives.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Disposition {
    /// The signal's default action, `SIG_DFL`.
    Default,
    /// Nothing, `SIG_IGN`.
    Ignore,
}

impl Disposition {
    /// The handler value the kernel reads for this disposition. Neither is an
    /// address, which is what spares the call a restorer trampoline.
    fn handler(self) -> usize {
        match self {
            Disposition::Default => 0,
            Disposition::Ignore => 1,
        }
    }
}

/// The kernel's `struct sigaction`, as `rt_sigaction` reads it.
///
/// Not libc's: the kernel's has no union, a word of flags, a restorer where
/// the architecture has one, and a mask of the kernel's own size.
#[repr(C)]
struct KernelSigaction {
    handler: usize,
    flags: c_ulong,
    #[cfg(not(target_arch = "riscv64"))]
    restorer: usize,
    mask: SigSet,
}

/// Sets `signal`'s disposition.
///
/// # Errors
///
/// `EINVAL` for a signal whose disposition cannot be changed, `SIGKILL` and
/// `SIGSTOP`, and for a number the kernel reserves.
pub(crate) fn set_disposition(signal: Signal, disposition: Disposition) -> Result<(), Errno> {
    let action = KernelSigaction {
        handler: disposition.handler(),
        flags: 0,
        #[cfg(not(target_arch = "riscv64"))]
        restorer: 0,
        mask: SigSet::empty(),
    };
    // SAFETY: `action` is a live local of the layout the kernel reads, the old
    // action is not asked for, and the size is that of the kernel's mask. No
    // handler address is installed, so no signal can run code here.
    unsafe {
        syscalls::syscall!(
            Sysno::rt_sigaction,
            signal.as_raw(),
            std::ptr::from_ref(&action),
            0usize,
            size_of::<SigSet>()
        )
    }
    .map(|_| ())
    .map_err(errno)
}

/// Whether the process ignores `signal`: whether its disposition is `SIG_IGN`.
///
/// A blocked signal is queued whatever its disposition, since the disposition
/// may change before it is unblocked, so a caller reading a signal it blocked
/// asks this first to tell one the process would have ignored.
pub(crate) fn is_ignored(signal: Signal) -> Result<bool, Errno> {
    let mut action = KernelSigaction {
        handler: 0,
        flags: 0,
        #[cfg(not(target_arch = "riscv64"))]
        restorer: 0,
        mask: SigSet::empty(),
    };
    // SAFETY: no action is installed, the old one is written to a live local of
    // the layout the kernel writes, and the size is that of the kernel's mask.
    unsafe {
        syscalls::syscall!(
            Sysno::rt_sigaction,
            signal.as_raw(),
            0usize,
            std::ptr::from_mut(&mut action),
            size_of::<SigSet>()
        )
    }
    .map_err(errno)?;
    Ok(action.handler == Disposition::Ignore.handler())
}

/// The number of `unsigned long` words in the kernel's signal set: 64 signals
/// on every architecture the build admits.
const SIGSET_WORDS: usize = 64 / c_ulong::BITS as usize;

/// The kernel's `sigset_t`: one bit per signal, signal `n` at bit `n - 1`,
/// in `unsigned long` words.
///
/// It is the type `rt_sigprocmask` and `signalfd4` take, and its size is the
/// size they are told.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SigSet([c_ulong; SIGSET_WORDS]);

impl SigSet {
    /// No signal.
    pub(crate) const fn empty() -> SigSet {
        SigSet([0; SIGSET_WORDS])
    }

    /// Every signal: the mask [`fork`] holds across the call, and leaves in
    /// force in the child process.
    pub(crate) const fn all() -> SigSet {
        SigSet([!0; SIGSET_WORDS])
    }

    /// Exactly `signals`.
    pub(crate) const fn of(signals: &[Signal]) -> SigSet {
        let mut set = SigSet::empty();
        let mut index = 0;
        while index < signals.len() {
            let (word, bit) = SigSet::position(signals[index]);
            set.0[word] |= bit;
            index += 1;
        }
        set
    }

    /// This set without `signals`.
    pub(crate) const fn without(mut self, signals: &[Signal]) -> SigSet {
        let mut index = 0;
        while index < signals.len() {
            let (word, bit) = SigSet::position(signals[index]);
            self.0[word] &= !bit;
            index += 1;
        }
        self
    }

    /// The word and bit `signal` occupies.
    const fn position(signal: Signal) -> (usize, c_ulong) {
        let bit = (signal.as_raw() - 1) as usize;
        let width = c_ulong::BITS as usize;
        (bit / width, 1 << (bit % width))
    }

    /// Adds `signal`.
    #[cfg(test)]
    pub(crate) fn insert(&mut self, signal: Signal) {
        let (word, bit) = SigSet::position(signal);
        self.0[word] |= bit;
    }

    /// Whether `signal` is in the set.
    #[cfg(test)]
    pub(crate) fn contains(&self, signal: Signal) -> bool {
        let (word, bit) = SigSet::position(signal);
        self.0[word] & bit != 0
    }
}

/// How [`sigprocmask`] combines a set with the mask in force.
///
/// The values are the kernel's on every architecture the build admits.
#[derive(Clone, Copy, Debug)]
pub(crate) enum How {
    /// Adds the set to the mask.
    Block = 0,
    /// Removes the set from the mask.
    #[cfg(test)]
    Unblock = 1,
    /// Replaces the mask with the set.
    SetMask = 2,
}

/// Changes the calling thread's signal mask by `set` as `how` says, and
/// returns the mask that was in force. `None` changes nothing and only reads
/// it.
///
/// # Safety
///
/// Unblocking a signal lets it run whatever handler the process has for it,
/// so the caller answers for what runs, in particular after a fork.
pub(crate) unsafe fn sigprocmask(how: How, set: Option<&SigSet>) -> Result<SigSet, Errno> {
    let mut previous = SigSet::empty();
    let set = set.map_or(std::ptr::null(), std::ptr::from_ref);
    // SAFETY: `set` is null or a live `SigSet`, `previous` is a live local of
    // the same type, and the size is that type's. What unblocking lets run is
    // the caller's contract.
    unsafe {
        syscalls::syscall!(
            Sysno::rt_sigprocmask,
            how as usize,
            set,
            std::ptr::from_mut(&mut previous),
            size_of::<SigSet>()
        )
    }
    .map_err(errno)?;
    Ok(previous)
}

/// Runs `call` with `signals` blocked in the calling thread, and puts the
/// thread's mask back as it was.
///
/// For a call whose effect depends on a signal being blocked rather than on
/// what the signal would do, on a thread of the caller's that must not be left
/// with the block: the kernel lets a background process group take a terminal's
/// foreground without raising `SIGTTOU` only while the caller blocks or ignores
/// it, which [`Foreground`](super::Foreground) relies on. A signal of the set
/// that arrives meanwhile is delivered as the mask comes back, as it would have
/// been without the block.
pub(crate) fn with_blocked<T>(signals: &SigSet, call: impl FnOnce() -> T) -> Result<T, Errno> {
    // SAFETY: blocking signals runs nothing.
    let previous = unsafe { sigprocmask(How::Block, Some(signals)) }?;
    let result = call();
    // SAFETY: `previous` is the mask this thread ran under before the block,
    // so restoring it lets run only what could run before the call, a moment
    // late. A failure leaves the thread blocked rather than run anything.
    let _ = unsafe { sigprocmask(How::SetMask, Some(&previous)) };
    Ok(result)
}

/// `SFD_CLOEXEC`, so no exec'd descendant inherits a signal descriptor.
///
/// `signalfd4` takes the `O_*` bits under other names: `SFD_CLOEXEC` is
/// `O_CLOEXEC` and `SFD_NONBLOCK` is `O_NONBLOCK`. Those values differ by
/// architecture, so both are read from rustix's per-target table rather than
/// written out here.
const SFD_CLOEXEC: usize = OFlags::CLOEXEC.bits() as usize;
/// `SFD_NONBLOCK`, so draining a signal descriptor never blocks.
const SFD_NONBLOCK: usize = OFlags::NONBLOCK.bits() as usize;

/// The size of one `struct signalfd_siginfo`, the record a signal descriptor
/// yields per signal. Its first field is the signal number as a `__u32` in the
/// host's own byte order, and the struct is padded to a size the kernel
/// promises not to change.
pub(crate) const SIGINFO_LEN: usize = 128;

/// Opens a descriptor that yields the signals of `signals` as records of
/// [`SIGINFO_LEN`] bytes, non-blocking and close-on-exec.
///
/// The set must be blocked in the threads it is meant for: a signal that is not
/// blocked is acted on as it arrives and never reaches the descriptor. Reading
/// a record dequeues the signal it describes.
pub(crate) fn signalfd(signals: &SigSet) -> Result<OwnedFd, Errno> {
    // SAFETY: `signals` is a live reference to the kernel's own `sigset_t`
    // layout, and the size passed alongside it is that type's, which is what
    // `signalfd4` compares against. The first argument, -1, asks for a new
    // descriptor rather than modifying an existing one.
    let fd = unsafe {
        syscalls::syscall!(
            Sysno::signalfd4,
            -1i32,
            std::ptr::from_ref(signals),
            size_of::<SigSet>(),
            SFD_CLOEXEC | SFD_NONBLOCK
        )
    }
    .map_err(errno)?;
    // SAFETY: the call returned a fresh descriptor this process owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Sends `signal` to the thread `tid` of this process, rather than to the
/// process as a whole, which delivers it to whichever thread has it unblocked.
///
/// # Safety
///
/// `tid` names a thread of this process that is still running, so a recycled
/// id cannot turn the call on another process's thread.
#[cfg(test)]
pub(crate) unsafe fn tkill(tid: Pid, signal: Signal) -> Result<(), Errno> {
    // SAFETY: the call takes two integers; the caller vouches for `tid`.
    unsafe { syscalls::syscall!(Sysno::tkill, tid.as_raw_nonzero().get(), signal.as_raw()) }
        .map(|_| ())
        .map_err(errno)
}

/// The kernel's `struct timeval` as `struct rusage` carries it: seconds and
/// microseconds, each a `long`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Timeval {
    sec: c_long,
    usec: c_long,
}

impl Timeval {
    /// The time in microseconds.
    ///
    /// Saturating rather than wrapping, and a negative field read as zero,
    /// which the kernel never reports: the supervisor calls this after a fork,
    /// where an overflow must not panic.
    pub(crate) fn micros(self) -> u64 {
        let sec = u64::try_from(self.sec).unwrap_or(0);
        let usec = u64::try_from(self.usec).unwrap_or(0);
        sec.saturating_mul(1_000_000).saturating_add(usec)
    }
}

/// The kernel's `struct rusage`, as `getrusage` writes it: two `timeval`s and
/// fourteen `long`s on every architecture.
///
/// Only the fields the crate reads are named. The rest are counters this crate
/// does not report, and several of them Linux leaves at zero.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Rusage {
    /// The processor time spent in user mode.
    pub(crate) utime: Timeval,
    /// The processor time spent in the kernel.
    pub(crate) stime: Timeval,
    /// The peak resident set size, in kibibytes.
    pub(crate) maxrss: c_long,
    rest: [c_long; 13],
}

/// `getrusage`'s selector for the calling process's children.
const RUSAGE_CHILDREN: isize = -1;

/// What the calling process's children have used: every child that has exited
/// and been waited for, with each of the descendants that child waited for in
/// turn.
///
/// The times are sums over those processes. The peak resident set size is the
/// largest any one of them reached, not a sum.
pub(crate) fn children_usage() -> Result<Rusage, Errno> {
    let mut usage = Rusage::default();
    // SAFETY: `usage` is a live, writable `struct rusage` of the kernel's
    // layout for the duration of the call, and nothing else refers to it.
    unsafe { syscalls::syscall!(Sysno::getrusage, RUSAGE_CHILDREN, &raw mut usage as usize) }
        .map(|_| usage)
        .map_err(errno)
}

/// A `syscalls` errno as the rustix errno the rest of the crate speaks.
pub(crate) fn errno(err: syscalls::Errno) -> Errno {
    Errno::from_raw_os_error(err.into_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ignored_signal_reads_as_ignored() {
        // SIGURG, which nothing in a test binary handles, and whose default
        // action is to do nothing, so a process-wide change to it is inert.
        assert_eq!(is_ignored(Signal::URG), Ok(false));
        set_disposition(Signal::URG, Disposition::Ignore).expect("SIGURG can be ignored");
        assert_eq!(is_ignored(Signal::URG), Ok(true));
        set_disposition(Signal::URG, Disposition::Default).expect("and put back");
        assert_eq!(is_ignored(Signal::URG), Ok(false));
    }

    #[test]
    fn a_signal_occupies_the_bit_below_its_number() {
        // The kernel's convention, which a set built here and read by the
        // kernel has to share: signal 1 is bit 0 of word 0.
        let mut set = SigSet::empty();
        set.insert(Signal::HUP);
        let mut expected = [0 as c_ulong; SIGSET_WORDS];
        expected[0] = 1;
        assert_eq!(set.0, expected);

        // SIGRTMIN is 34 and SIGRTMAX 64 on every admitted architecture; the
        // highest number is the last bit of the last word.
        let mut high = SigSet::empty();
        // SAFETY: 64 is a signal number the kernel defines on every admitted
        // architecture.
        high.insert(unsafe { Signal::from_raw_unchecked(64) });
        assert_eq!(high.0[SIGSET_WORDS - 1], 1 << (c_ulong::BITS - 1));
        assert!(!high.contains(Signal::HUP));
    }

    #[test]
    fn the_mask_the_kernel_reports_is_the_one_set() {
        // Through the kernel and back, on a thread of the test's own so the
        // runner's threads keep their masks.
        std::thread::spawn(|| {
            let mut set = SigSet::empty();
            set.insert(Signal::USR1);
            set.insert(Signal::WINCH);
            // SAFETY: blocking signals runs nothing.
            let before = unsafe { sigprocmask(How::Block, Some(&set)) }.expect("the mask blocks");
            assert!(!before.contains(Signal::USR1));
            // SAFETY: reading the mask changes nothing.
            let now = unsafe { sigprocmask(How::Block, None) }.expect("the mask reads");
            assert!(now.contains(Signal::USR1) && now.contains(Signal::WINCH));

            // SAFETY: SIGUSR1 is blocked, so it is made pending rather than
            // delivered, and the thread is this one.
            unsafe { tkill(rustix::thread::gettid(), Signal::USR1) }.expect("the signal is sent");
            let mut winch = SigSet::empty();
            winch.insert(Signal::WINCH);
            // SAFETY: SIGWINCH's default action is to ignore it, and the test
            // installs no handler, so unblocking it runs nothing.
            unsafe { sigprocmask(How::Unblock, Some(&winch)) }.expect("the mask unblocks");
            // SAFETY: reading the mask changes nothing.
            let now = unsafe { sigprocmask(How::Block, None) }.expect("the mask reads");
            assert!(now.contains(Signal::USR1) && !now.contains(Signal::WINCH));
        })
        .join()
        .expect("the mask thread ran");
    }

    #[test]
    fn the_kernel_acts_on_the_disposition_set() {
        // Proof that the kernel reads the handler where this module writes it:
        // an ignored SIGUSR2 is discarded and a defaulted one terminates. Each
        // case runs in a child of its own, so a misread layout ends that child
        // rather than the test binary.
        for (disposition, survives) in [(Disposition::Ignore, true), (Disposition::Default, false)]
        {
            // SAFETY: the child makes only raw system calls, and every path in
            // it ends in `exit_group` or in the signal it raises.
            match unsafe { fork() }.expect("the fork succeeds") {
                Fork::Child => {
                    // The opposite first, so the case does not pass on what
                    // the child happened to inherit.
                    let opposite = match disposition {
                        Disposition::Ignore => Disposition::Default,
                        Disposition::Default => Disposition::Ignore,
                    };
                    let set = set_disposition(Signal::USR2, opposite)
                        .and_then(|()| set_disposition(Signal::USR2, disposition));
                    // SAFETY: the child has no handler to run, and the thread
                    // is its only one.
                    let raised = unsafe { sigprocmask(How::SetMask, Some(&SigSet::empty())) }
                        .and_then(|_| unsafe { tkill(rustix::thread::gettid(), Signal::USR2) });
                    exit_group(if set.is_ok() && raised.is_ok() { 0 } else { 1 })
                }
                Fork::ParentOf(child) => {
                    let status = rustix::process::waitpid(
                        Some(child),
                        rustix::process::WaitOptions::empty(),
                    )
                    .expect("the child is collected")
                    .expect("the child reported a status")
                    .1;
                    if survives {
                        assert_eq!(status.exit_status(), Some(0), "{disposition:?}");
                    } else {
                        assert_eq!(
                            status.terminating_signal(),
                            Some(Signal::USR2.as_raw()),
                            "{disposition:?}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_fork_blocks_every_signal_in_the_child_and_restores_the_parent() {
        // On a thread of the test's own, so the runner's threads keep their
        // masks, and with one signal blocked beforehand, so the parent
        // process's restoration is told from an emptied mask.
        std::thread::spawn(|| {
            let mut usr1 = SigSet::empty();
            usr1.insert(Signal::USR1);
            // SAFETY: blocking signals runs nothing.
            let before = unsafe { sigprocmask(How::Block, Some(&usr1)) }.expect("the mask blocks");
            // SAFETY: the child process reads its mask and calls `exit_group`,
            // raw system calls both.
            match unsafe { fork() }.expect("the fork succeeds") {
                Fork::Child => {
                    // SAFETY: reading the mask changes nothing.
                    let blocked = unsafe { sigprocmask(How::Block, None) };
                    let every = blocked.is_ok_and(|mask| {
                        // SAFETY: 64 is a signal number the kernel defines on
                        // every admitted architecture.
                        let last = unsafe { Signal::from_raw_unchecked(64) };
                        [
                            Signal::INT,
                            Signal::TERM,
                            Signal::CHILD,
                            Signal::WINCH,
                            last,
                        ]
                        .into_iter()
                        .all(|signal| mask.contains(signal))
                    });
                    exit_group(if every { 0 } else { 1 })
                }
                Fork::ParentOf(child) => {
                    let status = rustix::process::waitpid(
                        Some(child),
                        rustix::process::WaitOptions::empty(),
                    )
                    .expect("the child is collected")
                    .expect("the child reported a status")
                    .1;
                    assert_eq!(status.exit_status(), Some(0), "the child ran unblocked");
                    // SAFETY: reading the mask changes nothing.
                    let after = unsafe { sigprocmask(How::Block, None) }.expect("the mask reads");
                    assert!(
                        after.contains(Signal::USR1),
                        "the parent's mask was emptied"
                    );
                    assert!(
                        !after.contains(Signal::INT),
                        "the parent's mask was left full"
                    );
                    // SAFETY: restoring the mask this thread started with.
                    unsafe { sigprocmask(How::SetMask, Some(&before)) }.expect("the mask restores");
                }
            }
        })
        .join()
        .expect("the fork thread ran");
    }

    #[test]
    fn a_disposition_is_refused_for_a_signal_that_cannot_have_one() {
        assert_eq!(
            set_disposition(Signal::KILL, Disposition::Ignore),
            Err(Errno::INVAL),
        );
    }

    #[test]
    fn a_reaped_child_s_processor_time_is_counted() {
        // The processor time the child is charged before it is killed, in the
        // clock ticks its `/proc` record counts in.
        const CHARGED_TICKS: u64 = 5;
        // A clock tick in microseconds: `USER_HZ` is 100 on every architecture
        // the crate builds for.
        const TICK_MICROS: u64 = 10_000;
        // How long the child may take to be charged that much, however loaded
        // the host or however small its share of a processor. It bounds a
        // broken accounting, and is not what the assertion measures.
        const PATIENCE: std::time::Duration = std::time::Duration::from_secs(60);

        // Other tests reap children of this process concurrently, so the
        // counters only grow past what this test adds; the assertion is a floor.
        let before = children_usage().expect("the usage is read");
        // SAFETY: the child spins, calling nothing, until it is killed.
        let child = match unsafe { fork_with_pidfd() }.expect("the fork succeeds") {
            PidfdFork::Child => loop {
                std::hint::spin_loop();
            },
            PidfdFork::ParentOf(child) => child,
        };
        // The work is measured in processor time, not wall time: a preempted
        // child, or one under a processor quota, is charged less than the time
        // it spends, however long that is. So the parent watches the child's
        // own account, and kills it once that holds the target.
        let pid = child.pid().as_raw_nonzero().get() as u32;
        let deadline = std::time::Instant::now() + PATIENCE;
        let charged = loop {
            let ticks = ferroday_cage_testkit::process::cpu_ticks(pid)
                .expect("the child is there until it is killed");
            if ticks >= CHARGED_TICKS {
                break ticks;
            }
            if std::time::Instant::now() >= deadline {
                child.kill();
                let _ = child.reap();
                panic!("the child was charged {ticks} ticks in {PATIENCE:?}");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        child.kill();
        assert_eq!(child.reap(), Ok(None), "the child ends by its kill");
        let after = children_usage().expect("the usage is read");
        let used = (after.utime.micros() + after.stime.micros())
            .saturating_sub(before.utime.micros() + before.stime.micros());
        // The kernel's account of a process only grows, so what the reaped
        // child is counted at is at least what its record held before the kill.
        assert!(
            used >= charged * TICK_MICROS,
            "the child was charged {charged} ticks and counted {used} µs"
        );
        assert!(after.maxrss > 0, "a reaped child has a resident set");
    }

    #[test]
    fn a_forks_pidfd_names_the_child_after_another_wait_collects_it() {
        // SAFETY: the child calls only `exit_group`.
        match unsafe { fork_with_pidfd() }.expect("the fork succeeds") {
            PidfdFork::Child => exit_group(42),
            PidfdFork::ParentOf(forked) => {
                // A wait elsewhere in the caller collects the child first, by
                // pid, as an application-wide reaper would.
                let status = rustix::process::waitpid(
                    Some(forked.pid()),
                    rustix::process::WaitOptions::empty(),
                )
                .expect("the child is collected")
                .expect("the child reported a status")
                .1;
                assert_eq!(status.exit_status(), Some(42));
                // The pidfd still names that child, exited and collected,
                // rather than whatever takes its pid next.
                assert!(super::super::has_exited(forked.pidfd()));
                assert_eq!(forked.reap(), Err(Errno::CHILD));
                // A kill reaches nothing: not that child, which is gone, nor a
                // process that has taken its pid since.
                // SAFETY: the bystander only sleeps, through one raw syscall,
                // and exits.
                let bystander = match unsafe { fork_with_pidfd() }.expect("the fork succeeds") {
                    PidfdFork::Child => {
                        let _ = rustix::thread::nanosleep(&rustix::thread::Timespec {
                            tv_sec: 5,
                            tv_nsec: 0,
                        });
                        exit_group(0)
                    }
                    PidfdFork::ParentOf(bystander) => bystander,
                };
                forked.kill();
                assert!(
                    !super::super::has_exited(bystander.pidfd()),
                    "the kill reached a process that was not its target"
                );
                bystander.kill();
                assert_eq!(
                    bystander.reap(),
                    Ok(None),
                    "the bystander ends by its own kill"
                );
            }
        }
    }

    #[test]
    fn a_signal_descriptor_reads_a_blocked_signal() {
        // On a thread of the test's own, so the runner's threads keep their
        // masks.
        std::thread::spawn(|| {
            let usr1 = SigSet::of(&[Signal::USR1]);
            let read = with_blocked(&usr1, || {
                let signals = signalfd(&usr1).expect("the descriptor opens");
                let mut record = [0u8; SIGINFO_LEN];
                let empty = rustix::io::read(&signals, &mut record);
                // SAFETY: SIGUSR1 is blocked in this thread, so it is made
                // pending rather than delivered, and the thread is this one.
                unsafe { tkill(rustix::thread::gettid(), Signal::USR1) }
                    .expect("the signal is sent");
                let read = rustix::io::read(&signals, &mut record);
                let number = i32::from_ne_bytes(record[0..4].try_into().expect("four bytes"));
                (empty, read, number)
            })
            .expect("the mask blocks");
            assert_eq!(read.0, Err(Errno::AGAIN), "nothing was pending yet");
            assert_eq!(read.1, Ok(SIGINFO_LEN));
            assert_eq!(read.2, Signal::USR1.as_raw());
            // SAFETY: reading the mask changes nothing.
            let after = unsafe { sigprocmask(How::Block, None) }.expect("the mask reads");
            assert!(!after.contains(Signal::USR1), "the block outlived the call");
        })
        .join()
        .expect("the descriptor thread ran");
    }

    #[test]
    fn a_forked_child_exits_with_the_code_it_was_given() {
        // SAFETY: the child calls only `exit_group`.
        match unsafe { fork() }.expect("the fork succeeds") {
            Fork::Child => exit_group(42),
            Fork::ParentOf(child) => {
                let status =
                    rustix::process::waitpid(Some(child), rustix::process::WaitOptions::empty())
                        .expect("the child is collected")
                        .expect("the child reported a status")
                        .1;
                assert_eq!(status.exit_status(), Some(42));
            }
        }
    }
}
