//! The seccomp filters the launch installs, and the classic-BPF vocabulary
//! they are written in.
//!
//! Two kinds of program reach the kernel through [`install`]: a caller's
//! hardening policy, compiled at build time by the `hardening` layer, and
//! [`NETWORK_FILTER`], which every sandbox with a network namespace of its own
//! carries and which this module states outright. The opcodes, the
//! `seccomp_data` offsets, the audit architectures, and the answers below are
//! the one vocabulary both are written in. They are named here rather than
//! taken from a binding, so the crate's raw BPF is self-contained and
//! reviewable.

use rustix::io::Errno;
use rustix::thread::UnshareFlags;
use syscalls::Sysno;

use super::sys::errno;
use super::{LaunchPlan, SockFilter};

/// Classic-BPF opcodes and `seccomp_data` field offsets.
pub(crate) mod bpf {
    /// `BPF_LD | BPF_W | BPF_ABS`: load a 32-bit word from a fixed offset in
    /// `seccomp_data` into the accumulator.
    pub(crate) const LD_W_ABS: u16 = 0x20;
    /// `BPF_ALU | BPF_AND | BPF_K`: keep only the accumulator's bits that `k`
    /// also has.
    pub(crate) const ALU_AND_K: u16 = 0x54;
    /// `BPF_JMP | BPF_JEQ | BPF_K`: branch on the accumulator equalling `k`.
    pub(crate) const JMP_JEQ_K: u16 = 0x15;
    /// `BPF_JMP | BPF_JSET | BPF_K`: branch on the accumulator sharing any bit
    /// with `k`. Only the hardening layer's fragments use it.
    #[cfg(any(feature = "hardening", test))]
    pub(crate) const JMP_JSET_K: u16 = 0x45;
    /// `BPF_JMP | BPF_JA`: jump forward `k` instructions unconditionally. Only
    /// the hardening layer's fragments use it.
    #[cfg(any(feature = "hardening", test))]
    pub(crate) const JMP_JA: u16 = 0x05;
    /// `BPF_RET | BPF_K`: return `k` as the seccomp action.
    pub(crate) const RET_K: u16 = 0x06;

    /// Byte offset of `seccomp_data.nr`, the syscall number.
    pub(crate) const OFF_NR: u32 = 0;
    /// Byte offset of `seccomp_data.arch`, the audit architecture of the
    /// syscall.
    pub(crate) const OFF_ARCH: u32 = 4;
    /// Byte offset of the low 32 bits of `seccomp_data.args[0]`.
    ///
    /// The argument is a 64-bit field in the kernel's byte order, which is the
    /// build's, so its low half leads on a little-endian target and trails on
    /// a big-endian one.
    pub(crate) const OFF_ARG0_LOW: u32 = if cfg!(target_endian = "little") {
        16
    } else {
        20
    };
}

/// `AUDIT_ARCH_X86_64`: a 64-bit x86 syscall, and an x32 one, which shares
/// the 64-bit audit architecture and is told apart only by
/// [`X32_SYSCALL_BIT`].
pub(crate) const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// `AUDIT_ARCH_I386`: a 32-bit x86 syscall, whether a 32-bit process made it
/// or a 64-bit one made it through `int 0x80`.
pub(crate) const AUDIT_ARCH_I386: u32 = 0x4000_0003;
/// `AUDIT_ARCH_AARCH64`.
pub(crate) const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
/// `AUDIT_ARCH_ARM`: a 32-bit arm syscall, native or through an arm64
/// kernel's compat layer.
pub(crate) const AUDIT_ARCH_ARM: u32 = 0x4000_0028;
/// `AUDIT_ARCH_RISCV64`.
pub(crate) const AUDIT_ARCH_RISCV64: u32 = 0xC000_00F3;
/// `AUDIT_ARCH_RISCV32`: a 32-bit RISC-V syscall, through a 64-bit kernel's
/// compat layer.
pub(crate) const AUDIT_ARCH_RISCV32: u32 = 0x4000_00F3;

/// `__X32_SYSCALL_BIT`: set on every syscall number issued through x86_64's
/// x32 ABI.
///
/// Adding it to a syscall number gives the x32 alias of the same call, under
/// the 64-bit audit architecture, which is how an x32 caller slips past a
/// filter that names only the 64-bit numbers. No architecture's own syscall
/// table reaches it.
pub(crate) const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// `SECCOMP_RET_ALLOW`: let the syscall run.
pub(crate) const RET_ALLOW: u32 = 0x7FFF_0000;
/// `SECCOMP_RET_KILL_PROCESS`: kill the whole process, as by `SIGSYS`.
pub(crate) const RET_KILL_PROCESS: u32 = 0x8000_0000;

/// `SECCOMP_RET_ERRNO` with `errno` as its data: fail the syscall with that
/// errno without running it.
///
/// The hardening layer encodes a policy's actions through seccompiler's own
/// conversion instead, which covers actions no filter here returns. This
/// encoding is the network filter's, which cannot depend on seccompiler: that
/// ships only with the `hardening` feature.
pub(crate) const fn ret_errno(errno: u16) -> u32 {
    0x0005_0000 | errno as u32
}

/// `ENOSYS`, the error a kernel answers a syscall it does not implement with.
///
/// The generic number, which every architecture this crate builds for shares.
/// A filter answers with it where the caller should read a refusal as
/// absence.
pub(crate) const ENOSYS: u16 = 38;

/// `EAFNOSUPPORT`, the error `socket` answers for an address family the
/// kernel does not offer. The generic number, as [`ENOSYS`] is.
pub(crate) const EAFNOSUPPORT: u16 = 97;

/// `AF_VSOCK`, the vsock address family.
const AF_VSOCK: u32 = 40;
/// `SYS_SOCKET`, the call number under which `socketcall` creates a socket.
const SYS_SOCKET: u32 = 1;
/// `io_uring_setup`, under the number every architecture shares, as each
/// syscall added since Linux 5.1 does.
const IO_URING_SETUP: u32 = 425;
/// `socket` on x86_64, and through the x32 ABI with [`X32_SYSCALL_BIT`] set.
const X86_64_SOCKET: u32 = 41;
/// `socket` on 32-bit x86: the direct call Linux 4.3 added beside
/// `socketcall`.
const I386_SOCKET: u32 = 359;
/// `socketcall` on 32-bit x86: one entry point for every socket call, its
/// arguments passed by pointer.
const I386_SOCKETCALL: u32 = 102;
/// `socket` on 32-bit arm, under the EABI.
const ARM_SOCKET: u32 = 281;
/// `socket` in the generic syscall table aarch64 and RISC-V share.
const GENERIC_SOCKET: u32 = 198;

/// One instruction that takes no branch.
const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// One conditional jump: forward `jt` instructions when the test holds, `jf`
/// when it does not, each counted from the instruction after this one.
const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// The network filter for an x86 kernel: x86_64, x32, and 32-bit x86.
///
/// ```text
///   [0]  A = arch
///   [1]  x86_64 or x32: to [4]
///   [2]  32-bit x86: to [9]
///   [3]  any other architecture: kill
///   [4]  A = nr
///   [5]  A &= !__X32_SYSCALL_BIT        an x32 call reads as its 64-bit twin
///   [6]  socket: to [17]
///   [7]  io_uring_setup: to [21]
///   [8]  allow
///   [9]  A = nr
///   [10] socket: to [17]
///   [11] socketcall: to [14]
///   [12] io_uring_setup: to [21]
///   [13] allow
///   [14] A = the low half of args[0]    socketcall's call number
///   [15] SYS_SOCKET: to [20]
///   [16] allow
///   [17] A = the low half of args[0]    socket's address family
///   [18] AF_VSOCK: to [20]
///   [19] allow
///   [20] return EAFNOSUPPORT
///   [21] return ENOSYS
/// ```
const X86_FILTER: [SockFilter; 22] = [
    stmt(bpf::LD_W_ABS, bpf::OFF_ARCH),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_X86_64, 2, 0),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_I386, 6, 0),
    stmt(bpf::RET_K, RET_KILL_PROCESS),
    stmt(bpf::LD_W_ABS, bpf::OFF_NR),
    stmt(bpf::ALU_AND_K, !X32_SYSCALL_BIT),
    jump(bpf::JMP_JEQ_K, X86_64_SOCKET, 10, 0),
    jump(bpf::JMP_JEQ_K, IO_URING_SETUP, 13, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::LD_W_ABS, bpf::OFF_NR),
    jump(bpf::JMP_JEQ_K, I386_SOCKET, 6, 0),
    jump(bpf::JMP_JEQ_K, I386_SOCKETCALL, 2, 0),
    jump(bpf::JMP_JEQ_K, IO_URING_SETUP, 8, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::LD_W_ABS, bpf::OFF_ARG0_LOW),
    jump(bpf::JMP_JEQ_K, SYS_SOCKET, 4, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::LD_W_ABS, bpf::OFF_ARG0_LOW),
    jump(bpf::JMP_JEQ_K, AF_VSOCK, 1, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::RET_K, ret_errno(EAFNOSUPPORT)),
    stmt(bpf::RET_K, ret_errno(ENOSYS)),
];

/// The network filter for an arm kernel: aarch64, and 32-bit arm natively or
/// through an arm64 kernel's compat layer.
///
/// 32-bit arm's `socketcall` belongs to the OABI. An arm kernel built with
/// OABI compatibility offers no seccomp filters at all, and an arm64 kernel's
/// compat layer is EABI only, so no kernel this filter can be installed on
/// reaches it.
///
/// ```text
///   [0]  A = arch
///   [1]  aarch64: to [4]
///   [2]  32-bit arm: to [8]
///   [3]  any other architecture: kill
///   [4]  A = nr
///   [5]  socket: to [12]
///   [6]  io_uring_setup: to [16]
///   [7]  allow
///   [8]  A = nr
///   [9]  socket: to [12]
///   [10] io_uring_setup: to [16]
///   [11] allow
///   [12] A = the low half of args[0]    socket's address family
///   [13] AF_VSOCK: to [15]
///   [14] allow
///   [15] return EAFNOSUPPORT
///   [16] return ENOSYS
/// ```
const ARM_FILTER: [SockFilter; 17] = [
    stmt(bpf::LD_W_ABS, bpf::OFF_ARCH),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_AARCH64, 2, 0),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_ARM, 5, 0),
    stmt(bpf::RET_K, RET_KILL_PROCESS),
    stmt(bpf::LD_W_ABS, bpf::OFF_NR),
    jump(bpf::JMP_JEQ_K, GENERIC_SOCKET, 6, 0),
    jump(bpf::JMP_JEQ_K, IO_URING_SETUP, 9, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::LD_W_ABS, bpf::OFF_NR),
    jump(bpf::JMP_JEQ_K, ARM_SOCKET, 2, 0),
    jump(bpf::JMP_JEQ_K, IO_URING_SETUP, 5, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::LD_W_ABS, bpf::OFF_ARG0_LOW),
    jump(bpf::JMP_JEQ_K, AF_VSOCK, 1, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::RET_K, ret_errno(EAFNOSUPPORT)),
    stmt(bpf::RET_K, ret_errno(ENOSYS)),
];

/// The network filter for a RISC-V kernel: 64-bit, and 32-bit through its
/// compat layer, both on the generic syscall table.
///
/// ```text
///   [0]  A = arch
///   [1]  64-bit: to [4]
///   [2]  32-bit: to [4]
///   [3]  any other architecture: kill
///   [4]  A = nr
///   [5]  socket: to [8]
///   [6]  io_uring_setup: to [12]
///   [7]  allow
///   [8]  A = the low half of args[0]    socket's address family
///   [9]  AF_VSOCK: to [11]
///   [10] allow
///   [11] return EAFNOSUPPORT
///   [12] return ENOSYS
/// ```
const RISCV_FILTER: [SockFilter; 13] = [
    stmt(bpf::LD_W_ABS, bpf::OFF_ARCH),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_RISCV64, 2, 0),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_RISCV32, 1, 0),
    stmt(bpf::RET_K, RET_KILL_PROCESS),
    stmt(bpf::LD_W_ABS, bpf::OFF_NR),
    jump(bpf::JMP_JEQ_K, GENERIC_SOCKET, 2, 0),
    jump(bpf::JMP_JEQ_K, IO_URING_SETUP, 5, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::LD_W_ABS, bpf::OFF_ARG0_LOW),
    jump(bpf::JMP_JEQ_K, AF_VSOCK, 1, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::RET_K, ret_errno(EAFNOSUPPORT)),
    stmt(bpf::RET_K, ret_errno(ENOSYS)),
];

/// The kernel families a build can run on, each with the syscall entry points
/// its kernel presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    /// x86_64, x32, and 32-bit x86.
    X86,
    /// aarch64 and 32-bit arm.
    Arm,
    /// 64-bit and 32-bit RISC-V.
    RiscV,
}

/// The build's family.
///
/// Spelled with `cfg!` rather than `#[cfg]`, so every variant and every
/// family's program is compiled, and tested, on every host. The last arm is
/// riscv64: the mechanism's build guard refuses any target outside the five
/// architectures it states, and the other four are named above it.
const HOST: Family = if cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
    Family::X86
} else if cfg!(any(target_arch = "aarch64", target_arch = "arm")) {
    Family::Arm
} else {
    Family::RiscV
};

/// The network filter for `family`.
const fn program_for(family: Family) -> &'static [SockFilter] {
    match family {
        Family::X86 => &X86_FILTER,
        Family::Arm => &ARM_FILTER,
        Family::RiscV => &RISCV_FILTER,
    }
}

/// The filter a sandbox with a network namespace of its own carries, closing
/// the routes out that the namespace does not cover.
///
/// A network namespace governs the address families that route through it,
/// and the launch leaves the sandbox only its loopback. Three routes do not
/// pass through a network namespace at all, and the filter closes each:
///
/// - **vsock.** An `AF_VSOCK` socket reaches the hypervisor's host from a
///   virtual machine guest, and the host's own services wherever the host
///   runs vsock loopback, from whichever network namespace it was created in.
///   `socket` with that family is answered `EAFNOSUPPORT`, as a kernel built
///   without vsock answers it, so a program that probes for vsock reads it as
///   absent. Only the low 32 bits of the family are compared: `socket` takes
///   an `int` and the kernel discards the rest, so a family with high bits set
///   is still `AF_VSOCK` to the kernel, and is refused.
/// - **io_uring.** A ring creates sockets itself, out of a filter's sight.
///   `io_uring_setup` is answered `ENOSYS`, as a kernel built without io_uring
///   answers it. The other io_uring calls act on a ring that only
///   `io_uring_setup` creates, and no descriptor reaches the sandbox but those
///   the caller grants it.
/// - **socketcall.** 32-bit x86 code creates sockets through `socketcall`,
///   which passes the family by pointer, where a filter cannot read it. A
///   64-bit process reaches the call too, through `int 0x80`. Its socket
///   creation is answered `EAFNOSUPPORT` whatever the family. That is the
///   answer `socket` gives for a family the kernel does not offer, which a
///   program probing for an optional facility reads as the facility being
///   absent: `useradd` opens the kernel's audit socket this way, and on this
///   answer goes on without auditing where another would abort it. A 32-bit
///   glibc program creates every socket through `socketcall`, so it creates
///   none in such a sandbox. musl tries the direct call first and is
///   unaffected, as is every 64-bit program. 32-bit arm's `socketcall` is out
///   of reach, as [`ARM_FILTER`] states, and no other architecture has the
///   call.
///
/// Every entry point a kernel of the build's family presents is checked: the
/// 64-bit ABI, x32 under x86_64's audit architecture, and the 32-bit compat
/// layer. A syscall under any other audit architecture kills the process, as
/// the hardening layer's filters do. No such syscall reaches a kernel this
/// build runs on. Everything else is allowed.
///
/// [`NETWORK_FILTER_REFUSALS`] states the same refusals as data.
pub(crate) const NETWORK_FILTER: &[SockFilter] = program_for(HOST);

/// One syscall the network filter refuses: the call, the value its first
/// argument holds where the refusal depends on one, and the errno it answers
/// in place of running the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// The syscall's name in the kernel's syscall table, which is the same at
    /// every entry point that has the call, where its number is not.
    pub(crate) syscall: &'static str,
    /// The value the low 32 bits of the first argument hold where the call is
    /// refused, or `None` where every call is.
    pub(crate) first_argument: Option<u32>,
    /// The errno the call is answered with.
    pub(crate) errno: u16,
}

/// `socket` creating an `AF_VSOCK` socket.
const VSOCK_SOCKET: Refusal = Refusal {
    syscall: "socket",
    first_argument: Some(AF_VSOCK),
    errno: EAFNOSUPPORT,
};
/// `io_uring_setup`, whatever it is asked.
const RING_SETUP: Refusal = Refusal {
    syscall: "io_uring_setup",
    first_argument: None,
    errno: ENOSYS,
};
/// `socketcall` creating a socket of any family.
const SOCKETCALL_SOCKET: Refusal = Refusal {
    syscall: "socketcall",
    first_argument: Some(SYS_SOCKET),
    errno: EAFNOSUPPORT,
};

/// What `family`'s network filter refuses.
const fn refusals_for(family: Family) -> &'static [Refusal] {
    match family {
        Family::X86 => &[VSOCK_SOCKET, RING_SETUP, SOCKETCALL_SOCKET],
        Family::Arm | Family::RiscV => &[VSOCK_SOCKET, RING_SETUP],
    }
}

/// What [`NETWORK_FILTER`] refuses, each refusal applying at every entry point
/// of the build's family that has the call. Everything else it allows.
///
/// The provenance record reports these. The unit tests hold the list to the
/// programs, every family's: each refusal is made, and nothing else is.
pub(crate) const NETWORK_FILTER_REFUSALS: &[Refusal] = refusals_for(HOST);

/// Whether a launch of `plan` installs [`NETWORK_FILTER`]: wherever its
/// sandbox has a network namespace of its own.
///
/// The launch asks this before it installs the filter, and the provenance
/// record asks it before it reports the filter, so the two cannot disagree.
pub(crate) fn installs_network_filter(plan: &LaunchPlan) -> bool {
    plan.unshare.contains(UnshareFlags::NEWNET)
}

/// `SECCOMP_SET_MODE_FILTER`: install a classic BPF filter.
const SECCOMP_SET_MODE_FILTER: usize = 1;

/// The kernel's `struct sock_fprog`: a filter program's length and pointer.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

// The layout must match the kernel's, or the install would read a program
// length and a program address the caller never wrote. The size is stated
// against the pointer's own, since the padding between the two fields is the
// pointer's alignment: sixteen bytes on a 64-bit target, eight on a 32-bit
// one. The offsets pin the fields inside it, so a field added or widened
// fails the build even where the total happens to come out the same.
const _: () = {
    let pointer = size_of::<*const SockFilter>();
    assert!(size_of::<SockFprog>() == 2 * pointer);
    assert!(std::mem::offset_of!(SockFprog, len) == 0);
    assert!(std::mem::offset_of!(SockFprog, filter) == pointer);
};

/// Installs `program` on the calling thread, for it and every process it
/// starts.
///
/// The kernel accepts the install from a thread holding no-new-privileges, or
/// one holding `CAP_SYS_ADMIN` in its own user namespace, and refuses any
/// other with `EACCES`. A filter installed after another stacks on it: the
/// kernel runs the newest first and keeps the most severe action, and between
/// two that fail a syscall with an errno, the newer one's errno.
///
/// The length of every program that reaches here fits a `u16`. The network
/// filter's is fixed, and the hardening layer refuses anything longer than
/// `BPF_MAXINSNS` (4096) at build time, so the narrowing cannot wrap.
pub(crate) fn install(program: &[SockFilter]) -> Result<(), Errno> {
    let fprog = SockFprog {
        len: program.len() as u16,
        filter: program.as_ptr(),
    };
    // SAFETY: the fprog points at a program that outlives the call, with its
    // own length; the kernel copies the program before returning and writes
    // through neither pointer.
    unsafe {
        syscalls::syscall!(
            Sysno::seccomp,
            SECCOMP_SET_MODE_FILTER,
            0usize,
            &fprog as *const SockFprog
        )
    }
    .map(|_| ())
    .map_err(errno)
}

/// A classic-BPF seccomp program, run the way the kernel runs it, for the unit
/// tests of every program the crate writes or compiles.
#[cfg(test)]
pub(crate) mod eval {
    use super::{SockFilter, bpf};

    /// The `seccomp_data` a filter is run over: the syscall number, the audit
    /// architecture, and the six arguments.
    pub(crate) struct Call {
        arch: u32,
        nr: u32,
        args: [u64; 6],
    }

    impl Call {
        /// A call of syscall `nr` under the audit architecture `arch`, with
        /// `args` and then zeroes.
        pub(crate) fn new(arch: u32, nr: u32, args: &[u64]) -> Call {
            let mut all = [0; 6];
            all[..args.len()].copy_from_slice(args);
            Call {
                arch,
                nr,
                args: all,
            }
        }
    }

    /// Runs `program` over `call` as the kernel does, returning the
    /// `SECCOMP_RET_*` value it answers.
    ///
    /// Only the instructions this crate's programs and seccompiler's backend
    /// emit are interpreted. Any other fails the test, so a program that
    /// starts using one is not misread, and so does a jump past the program's
    /// end, which the kernel's verifier would refuse.
    pub(crate) fn run(program: &[SockFilter], call: &Call) -> u32 {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&call.nr.to_ne_bytes());
        data[4..8].copy_from_slice(&call.arch.to_ne_bytes());
        for (index, arg) in call.args.iter().enumerate() {
            let at = 16 + 8 * index;
            data[at..at + 8].copy_from_slice(&arg.to_ne_bytes());
        }
        let mut accumulator = 0u32;
        let mut next = 0usize;
        loop {
            let insn = *program
                .get(next)
                .unwrap_or_else(|| panic!("the program runs past its end, to {next}"));
            next += 1;
            let k = insn.k;
            let branch = |taken: bool| usize::from(if taken { insn.jt } else { insn.jf });
            match insn.code {
                bpf::LD_W_ABS => {
                    let at = k as usize;
                    accumulator = u32::from_ne_bytes(data[at..at + 4].try_into().unwrap());
                }
                bpf::ALU_AND_K => accumulator &= k,
                bpf::JMP_JA => next += k as usize,
                bpf::JMP_JEQ_K => next += branch(accumulator == k),
                // BPF_JMP | BPF_JGT | BPF_K
                0x25 => next += branch(accumulator > k),
                // BPF_JMP | BPF_JGE | BPF_K
                0x35 => next += branch(accumulator >= k),
                bpf::JMP_JSET_K => next += branch(accumulator & k != 0),
                bpf::RET_K => return k,
                code => panic!("instruction {code:#06x} at {} is not interpreted", next - 1),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::eval::{Call, run};
    use super::*;

    /// Every entry point each family's kernel presents: its audit
    /// architecture, the `socket` number under it, and, where it has one, the
    /// `socketcall` number.
    fn entry_points(family: Family) -> Vec<(u32, u32, Option<u32>)> {
        match family {
            Family::X86 => vec![
                (AUDIT_ARCH_X86_64, X86_64_SOCKET, None),
                (AUDIT_ARCH_X86_64, X86_64_SOCKET | X32_SYSCALL_BIT, None),
                (AUDIT_ARCH_I386, I386_SOCKET, Some(I386_SOCKETCALL)),
            ],
            Family::Arm => vec![
                (AUDIT_ARCH_AARCH64, GENERIC_SOCKET, None),
                (AUDIT_ARCH_ARM, ARM_SOCKET, None),
            ],
            Family::RiscV => vec![
                (AUDIT_ARCH_RISCV64, GENERIC_SOCKET, None),
                (AUDIT_ARCH_RISCV32, GENERIC_SOCKET, None),
            ],
        }
    }

    const FAMILIES: [Family; 3] = [Family::X86, Family::Arm, Family::RiscV];

    /// The `io_uring_setup` number at the entry point whose `socket` number is
    /// `socket`: the x32 alias carries the x32 bit, and every other entry point
    /// uses the shared number.
    fn io_uring_setup_beside(socket: u32) -> u32 {
        IO_URING_SETUP | (socket & X32_SYSCALL_BIT)
    }

    #[test]
    fn every_entry_point_refuses_a_vsock_socket() {
        for family in FAMILIES {
            let program = program_for(family);
            for (arch, socket, _) in entry_points(family) {
                for kind in [1, 2, 5] {
                    let call = Call::new(arch, socket, &[u64::from(AF_VSOCK), kind, 0]);
                    assert_eq!(
                        run(program, &call),
                        ret_errno(EAFNOSUPPORT),
                        "{family:?}, arch {arch:#x}, socket {socket:#x}, type {kind}"
                    );
                }
            }
        }
    }

    #[test]
    fn high_bits_do_not_hide_the_vsock_family() {
        // The kernel reads the family as an int, so these are all AF_VSOCK.
        for family in FAMILIES {
            let program = program_for(family);
            for (arch, socket, _) in entry_points(family) {
                for domain in [1 << 32 | 40, u64::MAX << 32 | 40] {
                    let call = Call::new(arch, socket, &[domain, 1, 0]);
                    assert_eq!(
                        run(program, &call),
                        ret_errno(EAFNOSUPPORT),
                        "{family:?}, arch {arch:#x}, domain {domain:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_other_family_is_allowed() {
        // AF_UNIX, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, and the families
        // either side of AF_VSOCK.
        for family in FAMILIES {
            let program = program_for(family);
            for (arch, socket, _) in entry_points(family) {
                for domain in [1, 2, 10, 16, 17, 39, 41] {
                    let call = Call::new(arch, socket, &[domain, 1, 0]);
                    assert_eq!(
                        run(program, &call),
                        RET_ALLOW,
                        "{family:?}, arch {arch:#x}, domain {domain}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_entry_point_refuses_io_uring_setup() {
        for family in FAMILIES {
            let program = program_for(family);
            for (arch, socket, _) in entry_points(family) {
                let nr = io_uring_setup_beside(socket);
                let call = Call::new(arch, nr, &[1, 0x1000]);
                assert_eq!(
                    run(program, &call),
                    ret_errno(ENOSYS),
                    "{family:?}, arch {arch:#x}, nr {nr:#x}"
                );
                // io_uring_enter and io_uring_register act on a ring only
                // io_uring_setup creates.
                for other in [nr + 1, nr + 2] {
                    let call = Call::new(arch, other, &[3, 1, 1, 0]);
                    assert_eq!(run(program, &call), RET_ALLOW, "nr {other:#x}");
                }
            }
        }
    }

    #[test]
    fn socketcall_cannot_create_a_socket() {
        // The family is behind the pointer in args[1], so every socket
        // creation is refused, with the answer `socket` gives for a family
        // the kernel does not offer; the other calls socketcall carries run.
        for family in FAMILIES {
            let program = program_for(family);
            for (arch, _, socketcall) in entry_points(family) {
                let Some(socketcall) = socketcall else {
                    continue;
                };
                for pointer in [0, 0x0804_8000] {
                    let call = Call::new(arch, socketcall, &[u64::from(SYS_SOCKET), pointer]);
                    assert_eq!(
                        run(program, &call),
                        ret_errno(EAFNOSUPPORT),
                        "pointer {pointer:#x}"
                    );
                }
                let high = Call::new(arch, socketcall, &[1 << 32 | u64::from(SYS_SOCKET), 0]);
                assert_eq!(run(program, &high), ret_errno(EAFNOSUPPORT));
                // SYS_BIND through SYS_SENDMMSG.
                for call_number in 2..=20 {
                    let call = Call::new(arch, socketcall, &[call_number, 0x0804_8000]);
                    assert_eq!(run(program, &call), RET_ALLOW, "call {call_number}");
                }
            }
        }
    }

    /// The number `refusal`'s syscall has at the entry point whose `socket`
    /// and `socketcall` numbers are given, or `None` where it has no such
    /// call.
    fn number_at(refusal: &Refusal, socket: u32, socketcall: Option<u32>) -> Option<u32> {
        match refusal.syscall {
            "socket" => Some(socket),
            "io_uring_setup" => Some(io_uring_setup_beside(socket)),
            "socketcall" => socketcall,
            other => panic!("the tests know no number for {other}"),
        }
    }

    #[test]
    fn each_program_refuses_exactly_what_its_refusals_state() {
        // Every number an entry point's syscall table reaches, each over first
        // arguments that cover every address family and every socketcall call
        // number, with and without high bits set. Whatever no stated refusal
        // covers is allowed, so a refusal the list omits fails here as surely
        // as one the program does not make.
        let firsts: Vec<u64> = (0..=64)
            .chain([1 << 32 | 1, 1 << 32 | 40, u64::MAX << 32 | 40, u64::MAX])
            .collect();
        for family in FAMILIES {
            let program = program_for(family);
            let refusals = refusals_for(family);
            for refusal in refusals {
                assert!(
                    entry_points(family)
                        .into_iter()
                        .any(
                            |(_, socket, socketcall)| number_at(refusal, socket, socketcall)
                                .is_some()
                        ),
                    "{family:?} states a refusal of a call it has no entry point for: {refusal:?}"
                );
            }
            for (arch, socket, socketcall) in entry_points(family) {
                let tag = socket & X32_SYSCALL_BIT;
                for nr in (0..1024).map(|base| base | tag) {
                    for &first in &firsts {
                        // The low 32 bits, as the filter compares them.
                        let low = first as u32;
                        let expected = refusals
                            .iter()
                            .find(|refusal| {
                                number_at(refusal, socket, socketcall) == Some(nr)
                                    && refusal.first_argument.is_none_or(|value| value == low)
                            })
                            .map_or(RET_ALLOW, |refusal| ret_errno(refusal.errno));
                        let call = Call::new(arch, nr, &[first, 0x0804_8000, 0]);
                        assert_eq!(
                            run(program, &call),
                            expected,
                            "{family:?}, arch {arch:#x}, nr {nr:#x}, first argument {first:#x}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_host_reports_its_own_familys_refusals() {
        assert_eq!(NETWORK_FILTER_REFUSALS, refusals_for(HOST));
    }

    #[test]
    fn an_unrelated_syscall_is_allowed() {
        // getpid under several entry points: 39 on x86_64 and x32, 20 on
        // 32-bit x86, 172 on aarch64 and RISC-V. Then a number that is
        // socket's under another architecture of the same family, which is not
        // mistaken for it under this one.
        let cases: [(Family, u32, u32); 7] = [
            (Family::X86, AUDIT_ARCH_X86_64, 39),
            (Family::X86, AUDIT_ARCH_X86_64, X32_SYSCALL_BIT | 39),
            (Family::X86, AUDIT_ARCH_I386, 20),
            (Family::X86, AUDIT_ARCH_I386, X86_64_SOCKET),
            (Family::Arm, AUDIT_ARCH_AARCH64, 172),
            (Family::Arm, AUDIT_ARCH_ARM, GENERIC_SOCKET),
            (Family::RiscV, AUDIT_ARCH_RISCV32, 172),
        ];
        for (family, arch, nr) in cases {
            let call = Call::new(arch, nr, &[u64::from(AF_VSOCK), u64::from(SYS_SOCKET)]);
            assert_eq!(
                run(program_for(family), &call),
                RET_ALLOW,
                "{family:?}, arch {arch:#x}, nr {nr}"
            );
        }
    }

    #[test]
    fn a_foreign_architecture_is_killed() {
        let foreign = [
            (Family::X86, AUDIT_ARCH_AARCH64),
            (Family::Arm, AUDIT_ARCH_X86_64),
            (Family::Arm, AUDIT_ARCH_I386),
            (Family::RiscV, AUDIT_ARCH_ARM),
        ];
        for (family, arch) in foreign {
            let call = Call::new(arch, 39, &[]);
            assert_eq!(
                run(program_for(family), &call),
                RET_KILL_PROCESS,
                "{family:?}"
            );
        }
    }

    #[test]
    fn the_host_runs_its_own_familys_filter() {
        let expected = if cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
            Family::X86
        } else if cfg!(any(target_arch = "aarch64", target_arch = "arm")) {
            Family::Arm
        } else {
            Family::RiscV
        };
        assert_eq!(HOST, expected);
        assert_eq!(NETWORK_FILTER, program_for(expected));
    }

    #[test]
    fn the_native_numbers_are_the_c_librarys() {
        assert_eq!(i64::from(IO_URING_SETUP), libc::SYS_io_uring_setup);
        assert_eq!(AF_VSOCK, libc::AF_VSOCK as u32);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(i64::from(X86_64_SOCKET), libc::SYS_socket);
        #[cfg(target_arch = "x86")]
        {
            assert_eq!(i64::from(I386_SOCKET), libc::SYS_socket);
            assert_eq!(i64::from(I386_SOCKETCALL), libc::SYS_socketcall);
        }
        #[cfg(target_arch = "arm")]
        assert_eq!(i64::from(ARM_SOCKET), libc::SYS_socket);
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        assert_eq!(i64::from(GENERIC_SOCKET), libc::SYS_socket);
    }

    #[test]
    fn the_errnos_are_the_kernels() {
        assert_eq!(i32::from(ENOSYS), Errno::NOSYS.raw_os_error());
        assert_eq!(i32::from(EAFNOSUPPORT), Errno::AFNOSUPPORT.raw_os_error());
    }
}
