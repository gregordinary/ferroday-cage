//! The process-level system calls the launch path makes itself: fork, exec,
//! exit, a signal's disposition, and the signal mask.
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

use std::ffi::{CStr, c_ulong};

use rustix::io::Errno;
use rustix::process::{Pid, Signal};
use syscalls::Sysno;

/// Which side of a [`fork`] a process is on.
#[derive(Debug)]
pub(crate) enum Fork {
    /// The new process.
    Child,
    /// The process that called [`fork`], and the new process's pid.
    ParentOf(Pid),
}

/// Forks the calling process: `clone` with `SIGCHLD` as the exit signal and
/// no other flag, which is what the `fork` system call is on the architectures
/// that still have one.
///
/// Every other argument is zero, and with no flag that reads them the kernel
/// ignores them. That is also what makes the call architecture-neutral: the
/// order of `clone`'s pointer arguments differs between architectures, and
/// none of them is read.
///
/// # Safety
///
/// The child is a copy of the calling process that holds only the calling
/// thread. Until it calls [`execve`] or [`exit_group`] it may do only what
/// [`child`](super::child) permits after a fork: no allocation, no lock, no
/// libc, no panic.
pub(crate) unsafe fn fork() -> Result<Fork, Errno> {
    let exit_signal = Signal::CHILD.as_raw() as usize;
    // SAFETY: `clone` with only an exit signal duplicates the process as
    // `fork` does; it reads no pointer argument, so the zeros are never
    // dereferenced. What the child may do afterwards is the caller's contract.
    let pid =
        unsafe { syscalls::syscall!(Sysno::clone, exit_signal, 0usize, 0usize, 0usize, 0usize) }
            .map_err(errno)?;
    // The kernel answers 0 in the child and the child's pid, which is never 0,
    // in the parent.
    Ok(match Pid::from_raw(pid as i32) {
        Some(child) => Fork::ParentOf(child),
        None => Fork::Child,
    })
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

    /// Every signal. The network stack's tap helper, which blocks them all, is
    /// the one caller.
    #[cfg_attr(not(feature = "netstack"), allow(dead_code))]
    pub(crate) const fn all() -> SigSet {
        SigSet([!0; SIGSET_WORDS])
    }

    /// The word and bit `signal` occupies.
    fn position(signal: Signal) -> (usize, c_ulong) {
        let bit = (signal.as_raw() - 1) as usize;
        let width = c_ulong::BITS as usize;
        (bit / width, 1 << (bit % width))
    }

    /// Adds `signal`.
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

/// A `syscalls` errno as the rustix errno the rest of the crate speaks.
pub(crate) fn errno(err: syscalls::Errno) -> Errno {
    Errno::from_raw_os_error(err.into_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_disposition_is_refused_for_a_signal_that_cannot_have_one() {
        assert_eq!(
            set_disposition(Signal::KILL, Disposition::Ignore),
            Err(Errno::INVAL),
        );
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
