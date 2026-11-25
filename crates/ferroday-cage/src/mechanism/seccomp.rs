//! The seccomp filters the launch installs, and the classic-BPF vocabulary
//! they are written in.
//!
//! Three kinds of program reach the kernel through [`install`]: a caller's
//! hardening policy, compiled at build time by the `hardening` layer;
//! [`NETWORK_FILTER`], which every sandbox with a network namespace of its own
//! carries; and [`KEYRING_FILTER`], which a launch carries where it cannot give
//! the sandbox a session keyring of its own. This module states the last two
//! outright. The opcodes, the `seccomp_data` offsets, the audit architectures,
//! and the answers below are the one vocabulary all three are written in. They
//! are named here rather than taken from a binding, so the crate's raw BPF is
//! self-contained and reviewable.

#[cfg(feature = "hardening")]
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use rustix::io::Errno;
use rustix::thread::UnshareFlags;
use syscalls::Sysno;

use super::sys::{self, errno};
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
    #[cfg(feature = "hardening")]
    pub(crate) const JMP_JSET_K: u16 = 0x45;
    /// `BPF_JMP | BPF_JA`: jump forward `k` instructions unconditionally. Only
    /// the hardening layer's fragments use it.
    #[cfg(any(feature = "hardening", test))]
    pub(crate) const JMP_JA: u16 = 0x05;
    /// `BPF_RET | BPF_K`: return `k` as the seccomp action.
    pub(crate) const RET_K: u16 = 0x06;
    /// `BPF_RET | BPF_A`: return the accumulator as the seccomp action.
    #[cfg(any(feature = "hardening", test))]
    pub(crate) const RET_A: u16 = 0x16;

    /// The rest of the instructions the kernel's seccomp verifier accepts,
    /// which no program of the crate's own emits and a caller's precompiled
    /// one may: the evaluator interprets them. `K` takes the operand from the
    /// instruction, `X` from the index register.
    #[cfg(any(feature = "hardening", test))]
    pub(crate) mod more {
        /// `BPF_LD | BPF_W | BPF_LEN`: the accumulator takes the length of
        /// `seccomp_data`, 64.
        pub(crate) const LD_W_LEN: u16 = 0x80;
        /// `BPF_LDX | BPF_W | BPF_LEN`: the index register takes it.
        pub(crate) const LDX_W_LEN: u16 = 0x81;
        /// `BPF_LD | BPF_IMM`: the accumulator takes `k`.
        pub(crate) const LD_IMM: u16 = 0x00;
        /// `BPF_LDX | BPF_IMM`: the index register takes `k`.
        pub(crate) const LDX_IMM: u16 = 0x01;
        /// `BPF_LD | BPF_MEM`: the accumulator takes scratch word `k`.
        pub(crate) const LD_MEM: u16 = 0x60;
        /// `BPF_LDX | BPF_MEM`: the index register takes scratch word `k`.
        pub(crate) const LDX_MEM: u16 = 0x61;
        /// `BPF_ST`: scratch word `k` takes the accumulator.
        pub(crate) const ST: u16 = 0x02;
        /// `BPF_STX`: scratch word `k` takes the index register.
        pub(crate) const STX: u16 = 0x03;
        /// `BPF_MISC | BPF_TAX`: the index register takes the accumulator.
        pub(crate) const TAX: u16 = 0x07;
        /// `BPF_MISC | BPF_TXA`: the accumulator takes the index register.
        pub(crate) const TXA: u16 = 0x87;
        /// `BPF_ALU | BPF_NEG`: the accumulator is negated.
        pub(crate) const ALU_NEG: u16 = 0x84;
        /// `BPF_ALU`, the class of the arithmetic instructions, each of which
        /// is `ALU | op | source`.
        pub(crate) const ALU: u16 = 0x04;
        /// `BPF_JMP`, the class of the jumps, each `JMP | test | source`.
        pub(crate) const JMP: u16 = 0x05;
        /// `BPF_X`: the operand is the index register rather than `k`.
        pub(crate) const X: u16 = 0x08;
        /// The arithmetic operations the verifier accepts, by their `op`
        /// field: add, subtract, multiply, divide, or, and, shift left, shift
        /// right, exclusive or. `BPF_MOD` is not among them.
        pub(crate) const ADD: u16 = 0x00;
        /// `BPF_SUB`.
        pub(crate) const SUB: u16 = 0x10;
        /// `BPF_MUL`.
        pub(crate) const MUL: u16 = 0x20;
        /// `BPF_DIV`.
        pub(crate) const DIV: u16 = 0x30;
        /// `BPF_OR`.
        pub(crate) const OR: u16 = 0x40;
        /// `BPF_AND`.
        pub(crate) const AND: u16 = 0x50;
        /// `BPF_LSH`.
        pub(crate) const LSH: u16 = 0x60;
        /// `BPF_RSH`.
        pub(crate) const RSH: u16 = 0x70;
        /// `BPF_XOR`.
        pub(crate) const XOR: u16 = 0xa0;
        /// The jump tests, by their `op` field: equal, greater, greater or
        /// equal, any bit in common.
        pub(crate) const JEQ: u16 = 0x10;
        /// `BPF_JGT`.
        pub(crate) const JGT: u16 = 0x20;
        /// `BPF_JGE`.
        pub(crate) const JGE: u16 = 0x30;
        /// `BPF_JSET`.
        pub(crate) const JSET: u16 = 0x40;
    }

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
/// `SECCOMP_RET_USER_NOTIF`: hold the syscall and notify the filter's
/// listener, whose answer the syscall returns.
#[cfg(feature = "hardening")]
pub(crate) const RET_USER_NOTIF: u32 = 0x7FC0_0000;
/// `SECCOMP_RET_LOG`: let the syscall run, and log it.
#[cfg(feature = "hardening")]
pub(crate) const RET_LOG: u32 = 0x7FFC_0000;
/// `SECCOMP_RET_ERRNO`, the action an errno answer carries in its high half.
pub(crate) const RET_ERRNO: u32 = 0x0005_0000;
/// `SECCOMP_RET_ACTION_FULL`: the bits of a return value that name its action.
#[cfg(feature = "hardening")]
pub(crate) const RET_ACTION_FULL: u32 = 0xFFFF_0000;
/// `SECCOMP_RET_DATA`: the bits of a return value that carry its data, an
/// errno answer's errno.
#[cfg(feature = "hardening")]
pub(crate) const RET_DATA: u32 = 0x0000_FFFF;

/// `SECCOMP_RET_ERRNO` with `errno` as its data: fail the syscall with that
/// errno without running it.
///
/// The hardening layer encodes a policy's actions through seccompiler's own
/// conversion instead, which covers actions no filter here returns. This
/// encoding is the network and keyring filters', which cannot depend on
/// seccompiler: that ships only with the `hardening` feature.
pub(crate) const fn ret_errno(errno: u16) -> u32 {
    RET_ERRNO | errno as u32
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

/// The three key-management calls, by the numbers one syscall table gives
/// them.
struct KeyCalls {
    /// `add_key`.
    add_key: u32,
    /// `request_key`.
    request_key: u32,
    /// `keyctl`.
    keyctl: u32,
}

/// The key calls on x86_64, and through the x32 ABI with [`X32_SYSCALL_BIT`]
/// set.
const X86_64_KEY_CALLS: KeyCalls = KeyCalls {
    add_key: 248,
    request_key: 249,
    keyctl: 250,
};
/// The key calls on 32-bit x86.
const I386_KEY_CALLS: KeyCalls = KeyCalls {
    add_key: 286,
    request_key: 287,
    keyctl: 288,
};
/// The key calls on 32-bit arm, under the EABI.
const ARM_KEY_CALLS: KeyCalls = KeyCalls {
    add_key: 309,
    request_key: 310,
    keyctl: 311,
};
/// The key calls in the generic syscall table aarch64 and RISC-V share.
const GENERIC_KEY_CALLS: KeyCalls = KeyCalls {
    add_key: 217,
    request_key: 218,
    keyctl: 219,
};

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
const X86_NETWORK_FILTER: [SockFilter; 22] = [
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
const ARM_NETWORK_FILTER: [SockFilter; 17] = [
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
const RISCV_NETWORK_FILTER: [SockFilter; 13] = [
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
const fn network_program_for(family: Family) -> &'static [SockFilter] {
    match family {
        Family::X86 => &X86_NETWORK_FILTER,
        Family::Arm => &ARM_NETWORK_FILTER,
        Family::RiscV => &RISCV_NETWORK_FILTER,
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
///   of reach, as [`ARM_NETWORK_FILTER`] states, and no other architecture has
///   the call.
///
/// Every entry point a kernel of the build's family presents is checked: the
/// 64-bit ABI, x32 under x86_64's audit architecture, and the 32-bit compat
/// layer. A syscall under any other audit architecture kills the process, as
/// the hardening layer's filters do. No such syscall reaches a kernel this
/// build runs on. Everything else is allowed.
///
/// [`NETWORK_FILTER_REFUSALS`] states the same refusals as data.
pub(crate) const NETWORK_FILTER: &[SockFilter] = network_program_for(HOST);

/// One syscall a filter of this module refuses: the call, the value its first
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
const fn network_refusals_for(family: Family) -> &'static [Refusal] {
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
pub(crate) const NETWORK_FILTER_REFUSALS: &[Refusal] = network_refusals_for(HOST);

/// Whether a launch of `plan` installs [`NETWORK_FILTER`]: wherever its
/// sandbox has a network namespace of its own.
///
/// The launch asks this before it installs the filter, and the provenance
/// record asks it before it reports the filter, so the two cannot disagree.
pub(crate) fn installs_network_filter(plan: &LaunchPlan) -> bool {
    plan.unshare.contains(UnshareFlags::NEWNET)
}

/// The keyring filter for an x86 kernel: x86_64, x32, and 32-bit x86.
///
/// ```text
///   [0]  A = arch
///   [1]  x86_64 or x32: to [4]
///   [2]  32-bit x86: to [10]
///   [3]  any other architecture: kill
///   [4]  A = nr
///   [5]  A &= !__X32_SYSCALL_BIT        an x32 call reads as its 64-bit twin
///   [6]  add_key: to [15]
///   [7]  request_key: to [15]
///   [8]  keyctl: to [15]
///   [9]  allow
///   [10] A = nr
///   [11] add_key: to [15]
///   [12] request_key: to [15]
///   [13] keyctl: to [15]
///   [14] allow
///   [15] return ENOSYS
/// ```
const X86_KEYRING_FILTER: [SockFilter; 16] = [
    stmt(bpf::LD_W_ABS, bpf::OFF_ARCH),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_X86_64, 2, 0),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_I386, 7, 0),
    stmt(bpf::RET_K, RET_KILL_PROCESS),
    stmt(bpf::LD_W_ABS, bpf::OFF_NR),
    stmt(bpf::ALU_AND_K, !X32_SYSCALL_BIT),
    jump(bpf::JMP_JEQ_K, X86_64_KEY_CALLS.add_key, 8, 0),
    jump(bpf::JMP_JEQ_K, X86_64_KEY_CALLS.request_key, 7, 0),
    jump(bpf::JMP_JEQ_K, X86_64_KEY_CALLS.keyctl, 6, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::LD_W_ABS, bpf::OFF_NR),
    jump(bpf::JMP_JEQ_K, I386_KEY_CALLS.add_key, 3, 0),
    jump(bpf::JMP_JEQ_K, I386_KEY_CALLS.request_key, 2, 0),
    jump(bpf::JMP_JEQ_K, I386_KEY_CALLS.keyctl, 1, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::RET_K, ret_errno(ENOSYS)),
];

/// The keyring filter for an arm kernel: aarch64, and 32-bit arm natively or
/// through an arm64 kernel's compat layer.
///
/// ```text
///   [0]  A = arch
///   [1]  aarch64: to [4]
///   [2]  32-bit arm: to [9]
///   [3]  any other architecture: kill
///   [4]  A = nr
///   [5]  add_key: to [14]
///   [6]  request_key: to [14]
///   [7]  keyctl: to [14]
///   [8]  allow
///   [9]  A = nr
///   [10] add_key: to [14]
///   [11] request_key: to [14]
///   [12] keyctl: to [14]
///   [13] allow
///   [14] return ENOSYS
/// ```
const ARM_KEYRING_FILTER: [SockFilter; 15] = [
    stmt(bpf::LD_W_ABS, bpf::OFF_ARCH),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_AARCH64, 2, 0),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_ARM, 6, 0),
    stmt(bpf::RET_K, RET_KILL_PROCESS),
    stmt(bpf::LD_W_ABS, bpf::OFF_NR),
    jump(bpf::JMP_JEQ_K, GENERIC_KEY_CALLS.add_key, 8, 0),
    jump(bpf::JMP_JEQ_K, GENERIC_KEY_CALLS.request_key, 7, 0),
    jump(bpf::JMP_JEQ_K, GENERIC_KEY_CALLS.keyctl, 6, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::LD_W_ABS, bpf::OFF_NR),
    jump(bpf::JMP_JEQ_K, ARM_KEY_CALLS.add_key, 3, 0),
    jump(bpf::JMP_JEQ_K, ARM_KEY_CALLS.request_key, 2, 0),
    jump(bpf::JMP_JEQ_K, ARM_KEY_CALLS.keyctl, 1, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::RET_K, ret_errno(ENOSYS)),
];

/// The keyring filter for a RISC-V kernel: 64-bit, and 32-bit through its
/// compat layer, both on the generic syscall table.
///
/// ```text
///   [0]  A = arch
///   [1]  64-bit: to [4]
///   [2]  32-bit: to [4]
///   [3]  any other architecture: kill
///   [4]  A = nr
///   [5]  add_key: to [9]
///   [6]  request_key: to [9]
///   [7]  keyctl: to [9]
///   [8]  allow
///   [9]  return ENOSYS
/// ```
const RISCV_KEYRING_FILTER: [SockFilter; 10] = [
    stmt(bpf::LD_W_ABS, bpf::OFF_ARCH),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_RISCV64, 2, 0),
    jump(bpf::JMP_JEQ_K, AUDIT_ARCH_RISCV32, 1, 0),
    stmt(bpf::RET_K, RET_KILL_PROCESS),
    stmt(bpf::LD_W_ABS, bpf::OFF_NR),
    jump(bpf::JMP_JEQ_K, GENERIC_KEY_CALLS.add_key, 3, 0),
    jump(bpf::JMP_JEQ_K, GENERIC_KEY_CALLS.request_key, 2, 0),
    jump(bpf::JMP_JEQ_K, GENERIC_KEY_CALLS.keyctl, 1, 0),
    stmt(bpf::RET_K, RET_ALLOW),
    stmt(bpf::RET_K, ret_errno(ENOSYS)),
];

/// The keyring filter for `family`.
const fn keyring_program_for(family: Family) -> &'static [SockFilter] {
    match family {
        Family::X86 => &X86_KEYRING_FILTER,
        Family::Arm => &ARM_KEYRING_FILTER,
        Family::RiscV => &RISCV_KEYRING_FILTER,
    }
}

/// The filter a launch carries where it cannot give the sandbox a session
/// keyring of its own: `add_key`, `request_key`, and `keyctl` answer `ENOSYS`.
///
/// A launch joins a fresh session keyring before it forks anything, which ends
/// the sandbox's possession of the keys the caller's session holds. Where the
/// join is refused, the caller's keyring stays, and with it the possession. This filter then keeps the keys out of the sandbox's reach: with
/// the three calls refused whole, no process of the sandbox reads, links,
/// searches, or adds a key through any operation, whichever operations a
/// policy the launch runs under allows. The launch stage's
/// `replace_session_keyring` says when it is installed and what it leaves.
///
/// `ENOSYS` is what a kernel built without key support answers, so a program
/// that probes for the keyring reads it as absent. Every entry point a kernel
/// of the build's family presents is checked, as [`NETWORK_FILTER`] checks
/// them, and a syscall under any other audit architecture kills the process.
/// Everything else is allowed.
///
/// The curated seccomp denylist refuses the same three calls, with `EPERM`,
/// where a caller asks for it. That is a policy of the `hardening` layer,
/// compiled for the host's architecture alone; this filter is the launch's
/// own, in every build, which is why it states the calls itself.
pub(crate) const KEYRING_FILTER: &[SockFilter] = keyring_program_for(HOST);

/// What [`KEYRING_FILTER`] refuses, at every entry point of every family.
///
/// Stated for the unit tests, which hold every family's program to it: each
/// refusal is made, and nothing else is. No provenance record reports it,
/// since whether a launch installs the filter is settled only by what the
/// kernel answers the launch's join.
#[cfg(test)]
const KEYRING_FILTER_REFUSALS: &[Refusal] = &[
    Refusal {
        syscall: "add_key",
        first_argument: None,
        errno: ENOSYS,
    },
    Refusal {
        syscall: "request_key",
        first_argument: None,
        errno: ENOSYS,
    },
    Refusal {
        syscall: "keyctl",
        first_argument: None,
        errno: ENOSYS,
    },
];

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
/// The length of every program that reaches here fits a `u16`. The network and
/// keyring filters' are fixed, and the hardening layer refuses anything longer
/// than `BPF_MAXINSNS` (4096) at build time, so the narrowing cannot wrap.
pub(crate) fn install(program: &[SockFilter]) -> Result<(), Errno> {
    install_with(program, 0).map(|_| ())
}

/// Installs `program` with the `SECCOMP_FILTER_FLAG_*` bits of `flags`,
/// returning what the kernel answers: the listener's descriptor number where
/// the flags ask for one, and zero otherwise.
fn install_with(program: &[SockFilter], flags: usize) -> Result<usize, Errno> {
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
            flags,
            &fprog as *const SockFprog
        )
    }
    .map_err(errno)
}

/// `SECCOMP_FILTER_FLAG_NEW_LISTENER`: install the filter with a listener, a
/// descriptor its notifications are read from and answered through.
#[cfg(feature = "hardening")]
const FILTER_FLAG_NEW_LISTENER: usize = 1 << 3;

/// `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (Linux 5.19): a call whose
/// notification the listener has received waits for the answer through every
/// signal but a fatal one.
#[cfg(feature = "hardening")]
const FILTER_FLAG_WAIT_KILLABLE_RECV: usize = 1 << 5;

/// Installs `program` as [`install`] does, with a listener, and returns the
/// listener: the descriptor the filter's notifications are read from and
/// answered through, close-on-exec as the kernel opens it.
///
/// Asks for `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`, and installs without it
/// where the kernel does not know it (before Linux 5.19) and answers `EINVAL`.
/// Without it, a call that a signal interrupts while its notification waits is
/// notified again when it restarts.
///
/// A task can be under one filter with a listener at most: where one it
/// already runs under has one, the kernel answers `EBUSY`.
#[cfg(feature = "hardening")]
pub(crate) fn install_listening(program: &[SockFilter]) -> Result<OwnedFd, Errno> {
    let listener = match install_with(
        program,
        FILTER_FLAG_NEW_LISTENER | FILTER_FLAG_WAIT_KILLABLE_RECV,
    ) {
        Err(Errno::INVAL) => install_with(program, FILTER_FLAG_NEW_LISTENER)?,
        installed => installed?,
    };
    // SAFETY: the kernel opened the listener for this process as the install's
    // answer, and nothing else holds or closes that number.
    Ok(unsafe { OwnedFd::from_raw_fd(listener as RawFd) })
}

/// The program `program` is with its refusals turned into notifications, for a
/// filter whose refusals are reported.
///
/// Every `RET` of an errno answer returns `SECCOMP_RET_USER_NOTIF` instead,
/// except an answer of `ENOSYS`, which tells the command the call does not
/// exist so that it falls back, and is no refusal to report. Every other
/// return is kept. The listener answers each notification with what `program`
/// answers the call ([`eval`]), so the command sees what it would have without
/// the reports.
///
/// `None` where the program returns a computed value (`RET A`), which no
/// rewrite of its instructions can reach.
#[cfg(feature = "hardening")]
pub(crate) fn notifying(program: &[SockFilter]) -> Option<Vec<SockFilter>> {
    program
        .iter()
        .map(|insn| match insn.code {
            bpf::RET_A => None,
            bpf::RET_K if is_reported(insn.k) => Some(SockFilter {
                k: RET_USER_NOTIF,
                ..*insn
            }),
            _ => Some(*insn),
        })
        .collect()
}

/// Whether `ret`, a `SECCOMP_RET_*` value, is an answer a reporting filter
/// notifies its listener of: an errno other than `ENOSYS`.
#[cfg(feature = "hardening")]
pub(crate) fn is_reported(ret: u32) -> bool {
    ret & RET_ACTION_FULL == RET_ERRNO && ret & RET_DATA != u32::from(ENOSYS)
}

/// Whether the command stage's hand-over of a listener on `channel` runs under
/// `program`, a filter for calls under the audit architecture `arch`.
///
/// The hand-over is one `sendmsg` on the channel ([`frame::send_with_fd`]),
/// made after the filter is installed, since the install is what makes the
/// listener. A filter that refused it would hold the stage in a notification
/// no one could answer: the only listener is the one the stage was sending.
/// Only an answer that runs the call passes, allow or log. The message's
/// address is on the stage's stack, which no rule names, so it is taken as
/// zero.
///
/// [`frame::send_with_fd`]: super::frame::send_with_fd
#[cfg(feature = "hardening")]
pub(crate) fn hands_over(program: &[SockFilter], arch: u32, channel: RawFd) -> bool {
    let flags = u64::from(super::frame::SEND_WITH_FD_FLAGS.bits());
    let call = eval::Call::new(
        arch,
        Sysno::sendmsg.id() as u32,
        &[channel as u64, 0, flags],
    );
    eval::answer(program, &call)
        .is_some_and(|ret| matches!(ret & RET_ACTION_FULL, RET_ALLOW | RET_LOG))
}

/// Whether this process can install a seccomp filter, found by installing
/// [`NETWORK_FILTER`] in a forked child that does nothing else and exits.
///
/// Whatever refuses a launch's install refuses this one, so the answer is
/// exact: a kernel built without `CONFIG_SECCOMP_FILTER` answers the install
/// `EINVAL`, and a seccomp policy the caller already runs under, such as a
/// container runtime's, may answer the `seccomp` syscall with an errno or kill
/// whatever makes it. Either way the child fails and the caller is untouched.
/// A query made in the calling process answers less. `PR_GET_SECCOMP` sees
/// neither case, `SECCOMP_GET_ACTION_AVAIL` is served by a kernel whose
/// filters are compiled out, and a probe of the `seccomp` syscall itself dies
/// with the caller under a policy that kills.
///
/// The child sets no-new-privileges first. A launch installs the filter
/// holding the capability its nested user namespace grants instead, and the
/// kernel accepts either. A fork that fails answers `false`: it established
/// nothing, and a launch would fail at the same fork.
pub(crate) fn installable() -> bool {
    // SAFETY: `install_in_probe` makes only raw syscalls over static data,
    // with no allocation, no lock, no libc and no panic. It leaves every signal
    // blocked, as the fork hands it, so no inherited handler can run before it
    // exits.
    let installed = unsafe { sys::probe(install_in_probe) };
    installed == Ok(Some(0))
}

/// The probe child of [`installable`]: closes the caller's descriptors, takes
/// no-new-privileges, and installs the filter, answering the exit code the
/// parent reads.
///
/// The descriptors are closed for every forked child's reason, which
/// `sweep_fds_keeping` states. That close is not what is asked, so a sweep
/// that fails, as one does where `/proc` is not mounted, changes no answer.
fn install_in_probe() -> i32 {
    let _ = super::child::sweep_fds_keeping(&[]);
    let installed =
        rustix::thread::set_no_new_privs(true).is_ok() && install(NETWORK_FILTER).is_ok();
    if installed { 0 } else { 1 }
}

/// Whether this process can install a seccomp filter with a listener, found as
/// [`installable`] is, by installing one in a forked child that does nothing
/// else and exits.
///
/// A process may be under one filter with a listener at most, so the answer is
/// `false` where a filter this process runs under holds one, and wherever no
/// filter can be installed at all.
#[cfg(feature = "hardening")]
pub(crate) fn listener_installable() -> bool {
    // SAFETY: `install_listening_in_probe` makes only raw syscalls over static
    // data, with no allocation, no lock, no libc and no panic, and leaves every
    // signal blocked, as the fork hands it.
    let installed = unsafe { sys::probe(install_listening_in_probe) };
    installed == Ok(Some(0))
}

/// The probe child of [`listener_installable`], as [`install_in_probe`] is
/// [`installable`]'s: installs a filter that allows everything, with a
/// listener.
#[cfg(feature = "hardening")]
fn install_listening_in_probe() -> i32 {
    const ALLOW_ALL: [SockFilter; 1] = [stmt(bpf::RET_K, RET_ALLOW)];
    let _ = super::child::sweep_fds_keeping(&[]);
    let installed = rustix::thread::set_no_new_privs(true).is_ok()
        && install_with(&ALLOW_ALL, FILTER_FLAG_NEW_LISTENER).is_ok();
    if installed { 0 } else { 1 }
}

/// A classic-BPF seccomp program, run the way the kernel runs it.
///
/// Three users: the listener of a filter whose refusals are reported, which
/// answers each notification with what the policy as compiled answers the
/// call; the command stage, which checks before installing such a filter that
/// it lets the stage hand the listener over (`hands_over`); and the unit tests
/// of every program the crate writes or compiles.
///
/// Every instruction the kernel's seccomp verifier accepts is interpreted, so a
/// caller's precompiled program is run as faithfully as the crate's own. A
/// program the verifier would refuse answers `None`: an instruction outside its
/// set, a load beyond `seccomp_data` or off a word boundary, a scratch word
/// out of range, a jump past the end. Post-fork safe: nothing here allocates,
/// locks, or panics.
#[cfg(any(feature = "hardening", test))]
pub(crate) mod eval {
    use super::SockFilter;
    use super::bpf::{self, more};

    /// The size of `seccomp_data`, which `BPF_LEN` loads.
    const DATA_LEN: u32 = 64;

    /// The `seccomp_data` a filter is run over: the syscall number, the audit
    /// architecture, the address the call was made from, and the six
    /// arguments.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Call {
        /// The audit architecture the call was made under.
        pub(crate) arch: u32,
        /// The syscall number, in that architecture's table.
        pub(crate) nr: u32,
        /// The address of the instruction that made the call.
        pub(crate) instruction_pointer: u64,
        /// The six arguments, as the registers held them.
        pub(crate) args: [u64; 6],
    }

    impl Call {
        /// A call of syscall `nr` under the audit architecture `arch`, with
        /// `args` and then zeroes, made from address zero. Arguments past the
        /// sixth are ignored.
        pub(crate) fn new(arch: u32, nr: u32, args: &[u64]) -> Call {
            let mut all = [0; 6];
            for (slot, &arg) in all.iter_mut().zip(args) {
                *slot = arg;
            }
            Call {
                arch,
                nr,
                instruction_pointer: 0,
                args: all,
            }
        }

        /// The call as the kernel lays `seccomp_data` out, in the build's byte
        /// order.
        fn data(&self) -> [u8; DATA_LEN as usize] {
            let mut data = [0u8; DATA_LEN as usize];
            data[0..4].copy_from_slice(&self.nr.to_ne_bytes());
            data[4..8].copy_from_slice(&self.arch.to_ne_bytes());
            data[8..16].copy_from_slice(&self.instruction_pointer.to_ne_bytes());
            for (index, arg) in self.args.iter().enumerate() {
                let at = 16 + 8 * index;
                data[at..at + 8].copy_from_slice(&arg.to_ne_bytes());
            }
            data
        }
    }

    /// Runs `program` over `call` as the kernel does, returning the
    /// `SECCOMP_RET_*` value it answers, or `None` for a program the kernel's
    /// verifier would refuse.
    ///
    /// Division by a zero index register ends the program with 0, as the
    /// kernel's does, and a shift by the index register takes its low five
    /// bits. Every jump goes forward, so the run ends within the program's
    /// length.
    pub(crate) fn answer(program: &[SockFilter], call: &Call) -> Option<u32> {
        let data = call.data();
        let mut accumulator = 0u32;
        let mut index = 0u32;
        let mut scratch = [0u32; 16];
        let mut next = 0usize;
        loop {
            let insn = *program.get(next)?;
            next += 1;
            let k = insn.k;
            let operand = if insn.code & more::X != 0 { index } else { k };
            let branch = |taken: bool| usize::from(if taken { insn.jt } else { insn.jf });
            match insn.code {
                bpf::LD_W_ABS => {
                    if k % 4 != 0 || k >= DATA_LEN {
                        return None;
                    }
                    let at = k as usize;
                    let word = data.get(at..at + 4)?;
                    accumulator = u32::from_ne_bytes([word[0], word[1], word[2], word[3]]);
                }
                more::LD_W_LEN => accumulator = DATA_LEN,
                more::LDX_W_LEN => index = DATA_LEN,
                more::LD_IMM => accumulator = k,
                more::LDX_IMM => index = k,
                more::LD_MEM => accumulator = *scratch.get(k as usize)?,
                more::LDX_MEM => index = *scratch.get(k as usize)?,
                more::ST => *scratch.get_mut(k as usize)? = accumulator,
                more::STX => *scratch.get_mut(k as usize)? = index,
                more::TAX => index = accumulator,
                more::TXA => accumulator = index,
                more::ALU_NEG => accumulator = accumulator.wrapping_neg(),
                // `ALU | op | source`, an opcode of one byte.
                code if code < 0x100 && code & 0x07 == more::ALU => {
                    accumulator = match code & 0xf0 {
                        more::ADD => accumulator.wrapping_add(operand),
                        more::SUB => accumulator.wrapping_sub(operand),
                        more::MUL => accumulator.wrapping_mul(operand),
                        more::DIV => match accumulator.checked_div(operand) {
                            Some(quotient) => quotient,
                            None if code & more::X != 0 => return Some(0),
                            None => return None,
                        },
                        more::OR => accumulator | operand,
                        more::AND => accumulator & operand,
                        more::LSH if code & more::X != 0 || operand < 32 => {
                            accumulator.wrapping_shl(operand)
                        }
                        more::RSH if code & more::X != 0 || operand < 32 => {
                            accumulator.wrapping_shr(operand)
                        }
                        more::XOR => accumulator ^ operand,
                        _ => return None,
                    };
                }
                bpf::JMP_JA => next = next.checked_add(k as usize)?,
                // `JMP | test | source`.
                code if code < 0x100 && code & 0x07 == more::JMP => {
                    let taken = match code & 0xf0 {
                        more::JEQ => accumulator == operand,
                        more::JGT => accumulator > operand,
                        more::JGE => accumulator >= operand,
                        more::JSET => accumulator & operand != 0,
                        _ => return None,
                    };
                    next += branch(taken);
                }
                bpf::RET_K => return Some(k),
                bpf::RET_A => return Some(accumulator),
                _ => return None,
            }
        }
    }

    /// [`answer`], for a test that holds a program the kernel accepts: a
    /// program it would refuse fails the test.
    #[cfg(test)]
    pub(crate) fn run(program: &[SockFilter], call: &Call) -> u32 {
        answer(program, call)
            .unwrap_or_else(|| panic!("the kernel's verifier would refuse the program"))
    }
}

#[cfg(test)]
mod tests {
    use super::eval::{self, Call, run};
    use super::*;

    /// A syscall table of the `syscalls` crate: one per architecture a
    /// family's kernel numbers calls by.
    #[derive(Debug, Clone, Copy)]
    enum Table {
        X86_64,
        I386,
        Aarch64,
        Arm,
        Riscv64,
        Riscv32,
    }

    /// One entry point a family's kernel presents: the audit architecture its
    /// calls carry, the table that numbers them, and the bits every number
    /// carries beyond the table's, which is [`X32_SYSCALL_BIT`] on x32 and none
    /// elsewhere.
    #[derive(Debug, Clone, Copy)]
    struct EntryPoint {
        arch: u32,
        table: Table,
        tag: u32,
    }

    impl EntryPoint {
        /// The number `name` is called by at this entry point, or `None` where
        /// the entry point has no such call.
        ///
        /// Read from the `syscalls` crate's table for the architecture rather
        /// than from the constants the programs are written with, so each
        /// program is held to numbers it did not state, every family's on
        /// every host.
        fn number(self, name: &str) -> Option<u32> {
            use std::str::FromStr;
            let id = match self.table {
                Table::X86_64 => syscalls::x86_64::Sysno::from_str(name).map(|call| call.id()),
                Table::I386 => syscalls::x86::Sysno::from_str(name).map(|call| call.id()),
                Table::Aarch64 => syscalls::aarch64::Sysno::from_str(name).map(|call| call.id()),
                Table::Arm => syscalls::arm::Sysno::from_str(name).map(|call| call.id()),
                Table::Riscv64 => syscalls::riscv64::Sysno::from_str(name).map(|call| call.id()),
                Table::Riscv32 => syscalls::riscv32::Sysno::from_str(name).map(|call| call.id()),
            };
            let id = u32::try_from(id.ok()?).expect("a syscall number is not negative");
            Some(id | self.tag)
        }

        /// The number of `name`, a call every entry point the tests name has.
        fn call(self, name: &str) -> u32 {
            self.number(name)
                .unwrap_or_else(|| panic!("{self:?} has no {name}"))
        }
    }

    /// Every entry point each family's kernel presents.
    fn entry_points(family: Family) -> Vec<EntryPoint> {
        let entry = |arch, table, tag| EntryPoint { arch, table, tag };
        match family {
            Family::X86 => vec![
                entry(AUDIT_ARCH_X86_64, Table::X86_64, 0),
                entry(AUDIT_ARCH_X86_64, Table::X86_64, X32_SYSCALL_BIT),
                entry(AUDIT_ARCH_I386, Table::I386, 0),
            ],
            Family::Arm => vec![
                entry(AUDIT_ARCH_AARCH64, Table::Aarch64, 0),
                entry(AUDIT_ARCH_ARM, Table::Arm, 0),
            ],
            Family::RiscV => vec![
                entry(AUDIT_ARCH_RISCV64, Table::Riscv64, 0),
                entry(AUDIT_ARCH_RISCV32, Table::Riscv32, 0),
            ],
        }
    }

    const FAMILIES: [Family; 3] = [Family::X86, Family::Arm, Family::RiscV];

    #[test]
    fn every_entry_point_refuses_a_vsock_socket() {
        for family in FAMILIES {
            let program = network_program_for(family);
            for entry in entry_points(family) {
                let socket = entry.call("socket");
                for kind in [1, 2, 5] {
                    let call = Call::new(entry.arch, socket, &[u64::from(AF_VSOCK), kind, 0]);
                    assert_eq!(
                        run(program, &call),
                        ret_errno(EAFNOSUPPORT),
                        "{entry:?}, socket {socket:#x}, type {kind}"
                    );
                }
            }
        }
    }

    #[test]
    fn high_bits_do_not_hide_the_vsock_family() {
        // The kernel reads the family as an int, so these are all AF_VSOCK.
        for family in FAMILIES {
            let program = network_program_for(family);
            for entry in entry_points(family) {
                for domain in [1 << 32 | 40, u64::MAX << 32 | 40] {
                    let call = Call::new(entry.arch, entry.call("socket"), &[domain, 1, 0]);
                    assert_eq!(
                        run(program, &call),
                        ret_errno(EAFNOSUPPORT),
                        "{entry:?}, domain {domain:#x}"
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
            let program = network_program_for(family);
            for entry in entry_points(family) {
                for domain in [1, 2, 10, 16, 17, 39, 41] {
                    let call = Call::new(entry.arch, entry.call("socket"), &[domain, 1, 0]);
                    assert_eq!(run(program, &call), RET_ALLOW, "{entry:?}, domain {domain}");
                }
            }
        }
    }

    #[test]
    fn every_entry_point_refuses_io_uring_setup() {
        for family in FAMILIES {
            let program = network_program_for(family);
            for entry in entry_points(family) {
                let nr = entry.call("io_uring_setup");
                let call = Call::new(entry.arch, nr, &[1, 0x1000]);
                assert_eq!(
                    run(program, &call),
                    ret_errno(ENOSYS),
                    "{entry:?}, nr {nr:#x}"
                );
                // io_uring_enter and io_uring_register act on a ring only
                // io_uring_setup creates.
                for other in ["io_uring_enter", "io_uring_register"] {
                    let call = Call::new(entry.arch, entry.call(other), &[3, 1, 1, 0]);
                    assert_eq!(run(program, &call), RET_ALLOW, "{entry:?}, {other}");
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
            let program = network_program_for(family);
            for entry in entry_points(family) {
                let Some(socketcall) = entry.number("socketcall") else {
                    continue;
                };
                let arch = entry.arch;
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

    /// Holds `program`, `family`'s, to `refusals`: every number an entry
    /// point's syscall table reaches, each over first arguments that cover
    /// every address family and every socketcall call number, with and without
    /// high bits set, is refused where a stated refusal covers it and allowed
    /// everywhere else. A refusal the list omits therefore fails as surely as
    /// one the program does not make.
    fn assert_refuses_exactly(family: Family, program: &[SockFilter], refusals: &[Refusal]) {
        for refusal in refusals {
            assert!(
                entry_points(family)
                    .into_iter()
                    .any(|entry| entry.number(refusal.syscall).is_some()),
                "{family:?} states a refusal of a call it has no entry point for: {refusal:?}"
            );
        }
        let firsts: Vec<u64> = (0..=64)
            .chain([1 << 32 | 1, 1 << 32 | 40, u64::MAX << 32 | 40, u64::MAX])
            .collect();
        for entry in entry_points(family) {
            for nr in (0..1024).map(|base| base | entry.tag) {
                for &first in &firsts {
                    // The low 32 bits, as the filter compares them.
                    let low = first as u32;
                    let expected = refusals
                        .iter()
                        .find(|refusal| {
                            entry.number(refusal.syscall) == Some(nr)
                                && refusal.first_argument.is_none_or(|value| value == low)
                        })
                        .map_or(RET_ALLOW, |refusal| ret_errno(refusal.errno));
                    let call = Call::new(entry.arch, nr, &[first, 0x0804_8000, 0]);
                    assert_eq!(
                        run(program, &call),
                        expected,
                        "{entry:?}, nr {nr:#x}, first argument {first:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn each_program_refuses_exactly_what_its_refusals_state() {
        for family in FAMILIES {
            assert_refuses_exactly(
                family,
                network_program_for(family),
                network_refusals_for(family),
            );
            assert_refuses_exactly(family, keyring_program_for(family), KEYRING_FILTER_REFUSALS);
        }
    }

    #[test]
    fn every_entry_point_refuses_the_key_calls() {
        // Whatever the operation or the key a call names, as a policy that
        // allowed some operations would not.
        for family in FAMILIES {
            let program = keyring_program_for(family);
            for entry in entry_points(family) {
                for name in ["add_key", "request_key", "keyctl"] {
                    let nr = entry.call(name);
                    for first in [0, 1, 11, 0xffff_fffd, u64::MAX] {
                        let call = Call::new(entry.arch, nr, &[first, 0x0804_8000, 0]);
                        assert_eq!(
                            run(program, &call),
                            ret_errno(ENOSYS),
                            "{entry:?}, {name}, first argument {first:#x}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_host_reports_its_own_familys_refusals() {
        assert_eq!(NETWORK_FILTER_REFUSALS, network_refusals_for(HOST));
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
                run(network_program_for(family), &call),
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
            for program in [network_program_for(family), keyring_program_for(family)] {
                assert_eq!(run(program, &call), RET_KILL_PROCESS, "{family:?}");
            }
        }
    }

    #[test]
    fn the_host_runs_its_own_familys_filters() {
        let expected = if cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
            Family::X86
        } else if cfg!(any(target_arch = "aarch64", target_arch = "arm")) {
            Family::Arm
        } else {
            Family::RiscV
        };
        assert_eq!(HOST, expected);
        assert_eq!(NETWORK_FILTER, network_program_for(expected));
        assert_eq!(KEYRING_FILTER, keyring_program_for(expected));
    }

    #[test]
    fn the_native_numbers_are_the_c_librarys() {
        // libc spells a syscall number as a `c_long`, whose width is the
        // target's, so each is read into the filter's own type to compare.
        assert_eq!(Ok(IO_URING_SETUP), u32::try_from(libc::SYS_io_uring_setup));
        assert_eq!(AF_VSOCK, libc::AF_VSOCK as u32);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(Ok(X86_64_SOCKET), u32::try_from(libc::SYS_socket));
        #[cfg(target_arch = "x86")]
        {
            assert_eq!(Ok(I386_SOCKET), u32::try_from(libc::SYS_socket));
            assert_eq!(Ok(I386_SOCKETCALL), u32::try_from(libc::SYS_socketcall));
        }
        #[cfg(target_arch = "arm")]
        assert_eq!(Ok(ARM_SOCKET), u32::try_from(libc::SYS_socket));
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        assert_eq!(Ok(GENERIC_SOCKET), u32::try_from(libc::SYS_socket));
    }

    #[test]
    fn the_errnos_are_the_kernels() {
        assert_eq!(i32::from(ENOSYS), Errno::NOSYS.raw_os_error());
        assert_eq!(i32::from(EAFNOSUPPORT), Errno::AFNOSUPPORT.raw_os_error());
    }

    // -- The evaluator: every instruction the kernel's verifier accepts -------

    /// A call of syscall 5 under audit architecture 7, made from an address
    /// whose halves differ, with arguments that tell each other apart.
    const CALL: Call = Call {
        arch: 7,
        nr: 5,
        instruction_pointer: 0x1122_3344_5566_7788,
        args: [10, 20, 30, 40, 50, 60],
    };

    /// What `program` answers [`CALL`].
    fn answered(program: &[SockFilter]) -> Option<u32> {
        eval::answer(program, &CALL)
    }

    /// The accumulator after `a` meets `k` under `op`, or the program's
    /// refusal, for an operation with an immediate operand and then the same
    /// with the index register as the operand.
    fn arithmetic(op: u16, a: u32, k: u32) -> [Option<u32>; 2] {
        use bpf::more::{ALU, LD_IMM, LDX_IMM, X};
        [
            answered(&[stmt(LD_IMM, a), stmt(ALU | op, k), stmt(bpf::RET_A, 0)]),
            answered(&[
                stmt(LDX_IMM, k),
                stmt(LD_IMM, a),
                stmt(ALU | op | X, 0),
                stmt(bpf::RET_A, 0),
            ]),
        ]
    }

    #[test]
    fn the_evaluator_reads_every_load() {
        use bpf::more::{LD_IMM, LD_MEM, LD_W_LEN, LDX_IMM, LDX_MEM, LDX_W_LEN, ST, STX, TAX, TXA};
        let low_half = |offset: u32| {
            if cfg!(target_endian = "little") {
                offset
            } else {
                offset + 4
            }
        };
        let ret_a = stmt(bpf::RET_A, 0);
        assert_eq!(answered(&[stmt(bpf::LD_W_ABS, 0), ret_a]), Some(5));
        assert_eq!(answered(&[stmt(bpf::LD_W_ABS, 4), ret_a]), Some(7));
        assert_eq!(
            answered(&[stmt(bpf::LD_W_ABS, low_half(8)), ret_a]),
            Some(0x5566_7788)
        );
        assert_eq!(
            answered(&[stmt(bpf::LD_W_ABS, low_half(56)), ret_a]),
            Some(60)
        );
        assert_eq!(answered(&[stmt(LD_W_LEN, 0), ret_a]), Some(64));
        assert_eq!(
            answered(&[stmt(LDX_W_LEN, 0), stmt(TXA, 0), ret_a]),
            Some(64)
        );
        assert_eq!(
            answered(&[
                stmt(LD_IMM, 9),
                stmt(TAX, 0),
                stmt(LD_IMM, 1),
                stmt(TXA, 0),
                ret_a
            ]),
            Some(9)
        );
        // Scratch words, stored from either register and loaded into either.
        let program = [
            stmt(LD_IMM, 42),
            stmt(ST, 15),
            stmt(LDX_IMM, 7),
            stmt(STX, 0),
            stmt(LD_MEM, 15),
            stmt(LDX_MEM, 0),
            stmt(bpf::more::ALU | bpf::more::SUB | bpf::more::X, 0),
            ret_a,
        ];
        assert_eq!(answered(&program), Some(35));
        assert_eq!(answered(&[stmt(bpf::RET_K, 0x1234)]), Some(0x1234));
    }

    #[test]
    fn the_evaluator_does_the_verifiers_arithmetic() {
        use bpf::more::{ADD, AND, DIV, LSH, MUL, OR, RSH, SUB, XOR};
        assert_eq!(arithmetic(ADD, u32::MAX, 2), [Some(1); 2]);
        assert_eq!(arithmetic(SUB, 1, 2), [Some(u32::MAX); 2]);
        assert_eq!(arithmetic(MUL, 0x8000_0000, 3), [Some(0x8000_0000); 2]);
        assert_eq!(arithmetic(DIV, 7, 2), [Some(3); 2]);
        assert_eq!(arithmetic(OR, 0b1100, 0b1010), [Some(0b1110); 2]);
        assert_eq!(arithmetic(AND, 0b1100, 0b1010), [Some(0b1000); 2]);
        assert_eq!(arithmetic(XOR, 0b1100, 0b1010), [Some(0b0110); 2]);
        assert_eq!(arithmetic(LSH, 1, 31), [Some(0x8000_0000); 2]);
        assert_eq!(arithmetic(RSH, 0x8000_0000, 31), [Some(1); 2]);
        // A zero divisor the verifier sees is refused; one in the index
        // register ends the program with 0, as the kernel's does.
        assert_eq!(arithmetic(DIV, 7, 0), [None, Some(0)]);
        // A shift past the width is refused as a constant, and takes the low
        // five bits from the register.
        assert_eq!(arithmetic(LSH, 1, 33), [None, Some(2)]);
        assert_eq!(
            answered(&[
                stmt(bpf::more::LD_IMM, 1),
                stmt(bpf::more::ALU_NEG, 0),
                stmt(bpf::RET_A, 0)
            ]),
            Some(u32::MAX)
        );
    }

    #[test]
    fn the_evaluator_takes_every_jump() {
        use bpf::more::{JEQ, JGE, JGT, JMP, JSET, LD_IMM, LDX_IMM, X};
        // A program that answers 1 where the test holds and 2 where it does
        // not, comparing 6 with the operand, given as `k` or in the register.
        let tested = |test: u16, operand: u32| {
            let with_k = [
                stmt(LD_IMM, 6),
                jump(JMP | test, operand, 0, 1),
                stmt(bpf::RET_K, 1),
                stmt(bpf::RET_K, 2),
            ];
            let with_x = [
                stmt(LDX_IMM, operand),
                stmt(LD_IMM, 6),
                jump(JMP | test | X, 0, 0, 1),
                stmt(bpf::RET_K, 1),
                stmt(bpf::RET_K, 2),
            ];
            let (k, x) = (answered(&with_k), answered(&with_x));
            assert_eq!(k, x, "test {test:#x} against {operand}");
            k
        };
        assert_eq!(tested(JEQ, 6), Some(1));
        assert_eq!(tested(JEQ, 5), Some(2));
        assert_eq!(tested(JGT, 5), Some(1));
        assert_eq!(tested(JGT, 6), Some(2));
        assert_eq!(tested(JGE, 6), Some(1));
        assert_eq!(tested(JGE, 7), Some(2));
        assert_eq!(tested(JSET, 2), Some(1));
        assert_eq!(tested(JSET, 1), Some(2));
        let skipped = [
            stmt(bpf::JMP_JA, 1),
            stmt(bpf::RET_K, 1),
            stmt(bpf::RET_K, 2),
        ];
        assert_eq!(answered(&skipped), Some(2));
    }

    #[test]
    fn the_evaluator_refuses_what_the_verifier_refuses() {
        let ret_a = stmt(bpf::RET_A, 0);
        for refused in [
            // Off a word boundary, and beyond `seccomp_data`.
            vec![stmt(bpf::LD_W_ABS, 2), ret_a],
            vec![stmt(bpf::LD_W_ABS, 64), ret_a],
            // A half-word load, which classic BPF has and seccomp refuses.
            vec![stmt(0x28, 0), ret_a],
            // A scratch word past the sixteenth.
            vec![stmt(bpf::more::ST, 16), ret_a],
            // The remainder, which the verifier leaves out.
            vec![stmt(bpf::more::ALU | 0x90, 2), ret_a],
            // A jump past the end, and a program with no return.
            vec![stmt(bpf::JMP_JA, 5), ret_a],
            vec![stmt(bpf::more::LD_IMM, 1)],
            vec![],
        ] {
            assert_eq!(answered(&refused), None, "{refused:?}");
        }
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn a_rewritten_program_notifies_where_the_original_refuses_with_an_errno() {
        let refuse = |errno| stmt(bpf::RET_K, ret_errno(errno));
        // Call 5 refused with EPERM, call 6 answered ENOSYS, call 7 killed, the
        // rest allowed.
        let program = [
            stmt(bpf::LD_W_ABS, bpf::OFF_NR),
            jump(bpf::JMP_JEQ_K, 5, 0, 1),
            refuse(1),
            jump(bpf::JMP_JEQ_K, 6, 0, 1),
            refuse(ENOSYS),
            jump(bpf::JMP_JEQ_K, 7, 0, 1),
            stmt(bpf::RET_K, RET_KILL_PROCESS),
            stmt(bpf::RET_K, RET_ALLOW),
        ];
        let rewritten = notifying(&program).expect("every return is a constant");
        let call = |nr| Call::new(AUDIT_ARCH_X86_64, nr, &[]);
        assert_eq!(run(&rewritten, &call(5)), RET_USER_NOTIF);
        assert_eq!(run(&rewritten, &call(6)), ret_errno(ENOSYS));
        assert_eq!(run(&rewritten, &call(7)), RET_KILL_PROCESS);
        assert_eq!(run(&rewritten, &call(8)), RET_ALLOW);
        // A computed return cannot be rewritten.
        assert_eq!(
            notifying(&[stmt(bpf::more::LD_IMM, RET_ALLOW), stmt(bpf::RET_A, 0)]),
            None
        );
    }

    #[cfg(feature = "hardening")]
    #[test]
    fn the_hand_over_passes_only_a_filter_that_runs_its_sendmsg() {
        let sendmsg = Sysno::sendmsg.id() as u32;
        let arch = AUDIT_ARCH_X86_64;
        // A filter refusing sendmsg on one descriptor number, and logging it on
        // another.
        let program = [
            stmt(bpf::LD_W_ABS, bpf::OFF_NR),
            jump(bpf::JMP_JEQ_K, sendmsg, 0, 5),
            stmt(bpf::LD_W_ABS, bpf::OFF_ARG0_LOW),
            jump(bpf::JMP_JEQ_K, 9, 0, 1),
            stmt(bpf::RET_K, RET_USER_NOTIF),
            jump(bpf::JMP_JEQ_K, 10, 0, 1),
            stmt(bpf::RET_K, RET_LOG),
            stmt(bpf::RET_K, RET_ALLOW),
        ];
        assert!(!hands_over(&program, arch, 9));
        assert!(hands_over(&program, arch, 10));
        assert!(hands_over(&program, arch, 11));
    }
}
