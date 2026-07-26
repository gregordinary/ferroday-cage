//! The hardening layer: opt-in Landlock filesystem and network rules, seccomp
//! syscall filters, and capability drops applied to the sandboxed command.
//!
//! Everything here is configured on the [`CageBuilder`] and takes effect only
//! when requested; the default sandbox profile is a rootless convenience, not
//! a boundary against hostile code. The public types describe *what* to
//! restrict; [`CageBuilder::build`] lowers them into the frozen plan the
//! command stage applies, after the pivot and immediately before `execve`, so
//! the restrictions bind the command and every process it starts.
//!
//! The restrictions are inherited across `execve` and apply only to the
//! command, never to the sandbox init or the supervisor. A missing kernel
//! facility is reported: a request for Landlock on a kernel without the LSM,
//! or seccomp on an architecture the compiler does not target, is a build or
//! setup error rather than a silent no-op.
//!
//! With the `serde` feature, a hardening request is part of the profile
//! format: it serializes and deserializes as the `[hardening]` table on the
//! [`CageBuilder`] profile, so a Landlock, seccomp, and capability posture is
//! a versionable, reviewable artifact like the rest of the specification.
//!
//! [`CageBuilder`]: crate::CageBuilder
//! [`CageBuilder::build`]: crate::CageBuilder::build

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fmt;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use rustix::thread::CapabilitySet;

use crate::error::ConfigError;
use crate::mechanism::{HardeningPlan, LandlockNetRule, LandlockRule, SockFilter};

/// Kernel `LANDLOCK_ACCESS_FS_*` rights. Named here rather than pulled from a
/// binding so the ABI contract is visible in one place; re-verify against the
/// kernel uapi when the Landlock ABI grows.
pub(crate) mod fs_access {
    pub(crate) const EXECUTE: u64 = 1 << 0;
    pub(crate) const WRITE_FILE: u64 = 1 << 1;
    pub(crate) const READ_FILE: u64 = 1 << 2;
    pub(crate) const READ_DIR: u64 = 1 << 3;
    pub(crate) const REMOVE_DIR: u64 = 1 << 4;
    pub(crate) const REMOVE_FILE: u64 = 1 << 5;
    pub(crate) const MAKE_CHAR: u64 = 1 << 6;
    pub(crate) const MAKE_DIR: u64 = 1 << 7;
    pub(crate) const MAKE_REG: u64 = 1 << 8;
    pub(crate) const MAKE_SOCK: u64 = 1 << 9;
    pub(crate) const MAKE_FIFO: u64 = 1 << 10;
    pub(crate) const MAKE_BLOCK: u64 = 1 << 11;
    pub(crate) const MAKE_SYM: u64 = 1 << 12;
    pub(crate) const REFER: u64 = 1 << 13;
    pub(crate) const TRUNCATE: u64 = 1 << 14;
    pub(crate) const IOCTL_DEV: u64 = 1 << 15;

    /// Every filesystem right this crate models — the ABI 5 set. The command
    /// stage masks this down to the running kernel's supported ABI.
    pub(crate) const ALL: u64 = EXECUTE
        | WRITE_FILE
        | READ_FILE
        | READ_DIR
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM
        | REFER
        | TRUNCATE
        | IOCTL_DEV;
}

/// Kernel `LANDLOCK_ACCESS_NET_*` rights, keyed by TCP port rather than by
/// path. Named here alongside the filesystem rights so the ABI contract lives
/// in one place; re-verify against the kernel uapi when the Landlock ABI grows.
pub(crate) mod net_access {
    pub(crate) const BIND_TCP: u64 = 1 << 0;
    pub(crate) const CONNECT_TCP: u64 = 1 << 1;

    /// Every network right this crate models — the ABI 4 set. The command
    /// stage masks this down to the running kernel's supported ABI.
    pub(crate) const ALL: u64 = BIND_TCP | CONNECT_TCP;
}

/// Masks a filesystem access set down to the rights a Landlock ABI version
/// defines, so a ruleset built for a newer ABI still enforces on an older
/// kernel — narrowing what is enforced, never widening it.
///
/// A right absent from the running ABI cannot be part of a ruleset that
/// ABI's kernel will accept; dropping it leaves the access unrestricted for
/// that right, the same best-effort downgrade the reference library performs.
pub(crate) fn fs_access_for_abi(abi: i32) -> u64 {
    use fs_access::*;
    // v1: EXECUTE through MAKE_SYM. Each later version adds the rights below.
    let mut mask = EXECUTE
        | WRITE_FILE
        | READ_FILE
        | READ_DIR
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM;
    if abi >= 2 {
        mask |= REFER;
    }
    if abi >= 3 {
        mask |= TRUNCATE;
    }
    // ABI 4 adds only network rights, masked separately by net_access_for_abi.
    if abi >= 5 {
        mask |= IOCTL_DEV;
    }
    mask
}

/// Masks a network access set down to the rights a Landlock ABI version
/// defines, so a ruleset built for a newer ABI still enforces on an older
/// kernel — narrowing what is enforced, never widening it.
///
/// The TCP bind and connect rights are the whole modeled set and arrive
/// together in ABI 4; a kernel older than that defines no network rights, so
/// the mask is empty and network access is left unrestricted, the same
/// best-effort downgrade [`fs_access_for_abi`] performs for filesystem rights.
pub(crate) fn net_access_for_abi(abi: i32) -> u64 {
    // ABI 4 introduced BIND_TCP and CONNECT_TCP together. Later network rights
    // (the UDP rights of ABI 10) become additional gated additions here.
    if abi >= 4 { net_access::ALL } else { 0 }
}

/// Whether a requested filesystem grant carrying this handled mask falls
/// entirely outside `abi`, so a ruleset built at `abi` would govern none of it.
/// A zero mask means no filesystem grant was requested, so nothing is dropped.
///
/// A filesystem grant keeps its ABI-1 base rights on every Landlock kernel, so
/// in practice this is only ever true when the LSM reports an ABI of zero,
/// which cannot occur; it exists for symmetry with the network predicate and to
/// state the invariant explicitly.
pub(crate) fn fs_grant_masked_away(fs_handled: u64, abi: i32) -> bool {
    fs_handled != 0 && fs_handled & fs_access_for_abi(abi) == 0
}

/// Whether a requested network grant carrying this handled mask falls entirely
/// outside `abi`, so a ruleset built at `abi` would govern none of it. A zero
/// mask means no network grant was requested, so nothing is dropped.
///
/// Network rights first appear in Landlock ABI 4 (Linux 6.7), so a network
/// grant is masked away on every older kernel. The grant must be judged per
/// access kind rather than against the whole ruleset: a filesystem grant that
/// survives the same ABI must not mask this refusal, or a configured network
/// boundary would silently vanish while the filesystem side enforced.
///
/// Callers that treat a masked-away grant as a build error rather than run
/// unconfined: `HardeningPlan::ensure_landlock_enforceable` (the restriction
/// fallback) and `HardeningPlan::ensure_host_net_enforceable` (a host-network
/// cage, whose only network boundary is Landlock).
pub(crate) fn net_grant_masked_away(net_handled: u64, abi: i32) -> bool {
    net_handled != 0 && net_handled & net_access_for_abi(abi) == 0
}

/// A set of filesystem access rights, granted on a path by
/// [`CageBuilder::landlock_fs`].
///
/// The three primitives — [`READ`](Self::READ), [`WRITE`](Self::WRITE), and
/// [`EXECUTE`](Self::EXECUTE) — combine with `|`, mask with `&`, and
/// complement with `!` (within the modeled rights):
///
/// ```
/// use ferroday_cage::FsAccess;
///
/// let read_execute = FsAccess::READ | FsAccess::EXECUTE;
/// assert!(read_execute.contains(FsAccess::READ));
/// assert_eq!(read_execute & FsAccess::WRITE, FsAccess::empty());
/// assert_eq!(!FsAccess::WRITE, FsAccess::READ | FsAccess::EXECUTE);
/// ```
///
/// [`CageBuilder::landlock_fs`]: crate::CageBuilder::landlock_fs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct FsAccess(u8);

impl FsAccess {
    /// Read files and list directories beneath the path.
    pub const READ: FsAccess = FsAccess(0b001);
    /// Write files, and create, remove, and rename entries beneath the path.
    pub const WRITE: FsAccess = FsAccess(0b010);
    /// Execute files beneath the path.
    pub const EXECUTE: FsAccess = FsAccess(0b100);

    /// The bits every modeled right occupies, for masking a complement.
    const MASK: u8 = 0b111;

    /// The empty access set — no rights. Equivalent to [`FsAccess::default`].
    pub const fn empty() -> FsAccess {
        FsAccess(0)
    }

    /// Every modeled right: [`READ`](Self::READ), [`WRITE`](Self::WRITE), and
    /// [`EXECUTE`](Self::EXECUTE).
    pub const fn all() -> FsAccess {
        FsAccess(FsAccess::MASK)
    }

    /// Returns `true` if no right is present.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if every right in `other` is present.
    pub const fn contains(self, other: FsAccess) -> bool {
        self.0 & other.0 == other.0
    }

    /// The kernel `LANDLOCK_ACCESS_FS_*` rights this access set grants.
    ///
    /// `WRITE` maps to the full set of content and directory-mutation rights
    /// so a read-write grant behaves as a caller expects; rights the mount
    /// makes impossible anyway (device-node creation) are harmless to grant.
    ///
    /// `IOCTL_DEV` (device-specific `ioctl`, an ABI-5 right) is granted with
    /// either `READ` or `WRITE`: a caller who can read or write a device file
    /// expects its ioctls to work, and the right has no effect on a regular
    /// file or directory. Because it is in the handled set, a grant that omits
    /// both — an `EXECUTE`-only grant — still denies device ioctls. Were it not
    /// granted here at all, every filesystem grant would deny device ioctls on
    /// an ABI-5 kernel, since a handled right absent from a path's allowed set
    /// is denied there.
    pub(crate) fn to_landlock(self) -> u64 {
        use fs_access::*;
        let mut bits = 0;
        if self.contains(FsAccess::READ) {
            bits |= READ_FILE | READ_DIR;
        }
        if self.contains(FsAccess::EXECUTE) {
            bits |= EXECUTE;
        }
        if self.contains(FsAccess::WRITE) {
            bits |= WRITE_FILE
                | REMOVE_DIR
                | REMOVE_FILE
                | MAKE_CHAR
                | MAKE_DIR
                | MAKE_REG
                | MAKE_SOCK
                | MAKE_FIFO
                | MAKE_BLOCK
                | MAKE_SYM
                | REFER
                | TRUNCATE;
        }
        if self.contains(FsAccess::READ) || self.contains(FsAccess::WRITE) {
            bits |= IOCTL_DEV;
        }
        bits
    }
}

impl BitOr for FsAccess {
    type Output = FsAccess;

    fn bitor(self, rhs: FsAccess) -> FsAccess {
        FsAccess(self.0 | rhs.0)
    }
}

impl BitOrAssign for FsAccess {
    fn bitor_assign(&mut self, rhs: FsAccess) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for FsAccess {
    type Output = FsAccess;

    fn bitand(self, rhs: FsAccess) -> FsAccess {
        FsAccess(self.0 & rhs.0)
    }
}

impl BitAndAssign for FsAccess {
    fn bitand_assign(&mut self, rhs: FsAccess) {
        self.0 &= rhs.0;
    }
}

impl Not for FsAccess {
    type Output = FsAccess;

    /// The modeled rights this set does not hold; bits outside the modeled
    /// set are never produced.
    fn not(self) -> FsAccess {
        FsAccess(!self.0 & FsAccess::MASK)
    }
}

impl fmt::Display for FsAccess {
    /// Writes the rights as the letters `r`, `w`, and `x`, in that order, like
    /// a Unix file mode; the empty set writes nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.contains(FsAccess::READ) {
            f.write_str("r")?;
        }
        if self.contains(FsAccess::WRITE) {
            f.write_str("w")?;
        }
        if self.contains(FsAccess::EXECUTE) {
            f.write_str("x")?;
        }
        Ok(())
    }
}

impl FromStr for FsAccess {
    type Err = ParseFsAccessError;

    /// Parses an access set from the letters `r` (read), `w` (write), and `x`
    /// (execute), in any order and any case. A letter outside that set, or a
    /// letter given twice, is an error; the empty string is the empty set.
    fn from_str(s: &str) -> Result<FsAccess, ParseFsAccessError> {
        let mut access = FsAccess::empty();
        for ch in s.chars() {
            let right = match ch {
                'r' | 'R' => FsAccess::READ,
                'w' | 'W' => FsAccess::WRITE,
                'x' | 'X' => FsAccess::EXECUTE,
                _ => {
                    return Err(ParseFsAccessError {
                        text: s.to_string(),
                    });
                }
            };
            if access.contains(right) {
                return Err(ParseFsAccessError {
                    text: s.to_string(),
                });
            }
            access |= right;
        }
        Ok(access)
    }
}

/// The error from parsing an [`FsAccess`] from an invalid access string.
///
/// Produced when the string holds a character other than `r`, `w`, or `x`, or
/// repeats one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFsAccessError {
    text: String,
}

impl ParseFsAccessError {
    /// The access string that failed to parse, as it was given.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ParseFsAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid access set {:?}: expected some combination of the letters r, w, and x",
            self.text,
        )
    }
}

impl std::error::Error for ParseFsAccessError {}

#[cfg(feature = "serde")]
impl serde::Serialize for FsAccess {
    /// Serializes as the `rwx` letter string, through [`Display`](fmt::Display).
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for FsAccess {
    /// Deserializes from the `rwx` letter string, through [`FromStr`].
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<FsAccess, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// A set of Landlock network access rights, granted on a TCP port by
/// [`CageBuilder::landlock_net`].
///
/// Landlock's network control covers TCP alone: these rights govern TCP bind
/// and connect and nothing else. UDP, raw sockets, and other socket families
/// — `AF_UNIX` among them, including abstract sockets to host IPC — are
/// outside a network grant's reach, and a restriction that must deny them
/// needs a seccomp filter or a cage's network namespace instead.
///
/// The kernel keys network rights by port, so these are the network
/// counterpart of [`FsAccess`]: the two primitives — [`BIND`](Self::BIND) and
/// [`CONNECT`](Self::CONNECT) — combine with `|`, mask with `&`, and complement
/// with `!` (within the modeled rights):
///
/// ```
/// use ferroday_cage::NetAccess;
///
/// let bind_connect = NetAccess::BIND | NetAccess::CONNECT;
/// assert!(bind_connect.contains(NetAccess::BIND));
/// assert_eq!(bind_connect & NetAccess::CONNECT, NetAccess::CONNECT);
/// assert_eq!(!NetAccess::BIND, NetAccess::CONNECT);
/// ```
///
/// [`CageBuilder::landlock_net`]: crate::CageBuilder::landlock_net
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct NetAccess(u8);

impl NetAccess {
    /// Bind a TCP socket to the port (`LANDLOCK_ACCESS_NET_BIND_TCP`).
    pub const BIND: NetAccess = NetAccess(0b01);
    /// Connect a TCP socket to the port (`LANDLOCK_ACCESS_NET_CONNECT_TCP`).
    pub const CONNECT: NetAccess = NetAccess(0b10);

    /// The bits every modeled right occupies, for masking a complement.
    const MASK: u8 = 0b11;

    /// The empty access set — no rights. Equivalent to [`NetAccess::default`].
    pub const fn empty() -> NetAccess {
        NetAccess(0)
    }

    /// Every modeled right: [`BIND`](Self::BIND) and [`CONNECT`](Self::CONNECT).
    pub const fn all() -> NetAccess {
        NetAccess(NetAccess::MASK)
    }

    /// Returns `true` if no right is present.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if every right in `other` is present.
    pub const fn contains(self, other: NetAccess) -> bool {
        self.0 & other.0 == other.0
    }

    /// The kernel `LANDLOCK_ACCESS_NET_*` rights this access set grants.
    pub(crate) fn to_landlock(self) -> u64 {
        use net_access::*;
        let mut bits = 0;
        if self.contains(NetAccess::BIND) {
            bits |= BIND_TCP;
        }
        if self.contains(NetAccess::CONNECT) {
            bits |= CONNECT_TCP;
        }
        bits
    }
}

impl BitOr for NetAccess {
    type Output = NetAccess;

    fn bitor(self, rhs: NetAccess) -> NetAccess {
        NetAccess(self.0 | rhs.0)
    }
}

impl BitOrAssign for NetAccess {
    fn bitor_assign(&mut self, rhs: NetAccess) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for NetAccess {
    type Output = NetAccess;

    fn bitand(self, rhs: NetAccess) -> NetAccess {
        NetAccess(self.0 & rhs.0)
    }
}

impl BitAndAssign for NetAccess {
    fn bitand_assign(&mut self, rhs: NetAccess) {
        self.0 &= rhs.0;
    }
}

impl Not for NetAccess {
    type Output = NetAccess;

    /// The modeled rights this set does not hold; bits outside the modeled
    /// set are never produced.
    fn not(self) -> NetAccess {
        NetAccess(!self.0 & NetAccess::MASK)
    }
}

impl fmt::Display for NetAccess {
    /// Writes the rights as the letters `b` (bind) and `c` (connect), in that
    /// order; the empty set writes nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.contains(NetAccess::BIND) {
            f.write_str("b")?;
        }
        if self.contains(NetAccess::CONNECT) {
            f.write_str("c")?;
        }
        Ok(())
    }
}

impl FromStr for NetAccess {
    type Err = ParseNetAccessError;

    /// Parses an access set from the letters `b` (bind) and `c` (connect), in
    /// any order and any case. A letter outside that set, or a letter given
    /// twice, is an error; the empty string is the empty set.
    fn from_str(s: &str) -> Result<NetAccess, ParseNetAccessError> {
        let mut access = NetAccess::empty();
        for ch in s.chars() {
            let right = match ch {
                'b' | 'B' => NetAccess::BIND,
                'c' | 'C' => NetAccess::CONNECT,
                _ => {
                    return Err(ParseNetAccessError {
                        text: s.to_string(),
                    });
                }
            };
            if access.contains(right) {
                return Err(ParseNetAccessError {
                    text: s.to_string(),
                });
            }
            access |= right;
        }
        Ok(access)
    }
}

/// The error from parsing a [`NetAccess`] from an invalid access string.
///
/// Produced when the string holds a character other than `b` or `c`, or
/// repeats one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseNetAccessError {
    text: String,
}

impl ParseNetAccessError {
    /// The access string that failed to parse, as it was given.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ParseNetAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid access set {:?}: expected some combination of the letters b and c",
            self.text,
        )
    }
}

impl std::error::Error for ParseNetAccessError {}

#[cfg(feature = "serde")]
impl serde::Serialize for NetAccess {
    /// Serializes as the `bc` letter string, through [`Display`](fmt::Display).
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for NetAccess {
    /// Deserializes from the `bc` letter string, through [`FromStr`].
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<NetAccess, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// One Landlock filesystem grant, as configured on the builder.
#[derive(Debug, Clone)]
struct Grant {
    access: FsAccess,
    path: PathBuf,
}

/// One Landlock network grant, as configured on the builder: an access set
/// bound to a single TCP port.
#[derive(Debug, Clone)]
struct NetGrant {
    access: NetAccess,
    port: u16,
}

/// The action a seccomp filter takes for a syscall.
///
/// Mirrors the kernel's seccomp return actions. `Errno` is the gentlest —
/// the syscall fails with the given error number and the command continues;
/// `KillProcess` is the strictest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SeccompAction {
    /// Allow the syscall.
    Allow,
    /// Fail the syscall with this error number, without running it.
    Errno(u16),
    /// Log the syscall (audit), then allow it.
    Log,
    /// Kill the calling thread.
    KillThread,
    /// Kill the whole process.
    KillProcess,
}

impl SeccompAction {
    fn to_seccompiler(self) -> seccompiler::SeccompAction {
        match self {
            SeccompAction::Allow => seccompiler::SeccompAction::Allow,
            SeccompAction::Errno(errno) => seccompiler::SeccompAction::Errno(u32::from(errno)),
            SeccompAction::Log => seccompiler::SeccompAction::Log,
            SeccompAction::KillThread => seccompiler::SeccompAction::KillThread,
            SeccompAction::KillProcess => seccompiler::SeccompAction::KillProcess,
        }
    }

    /// Whether the action lets the syscall run. `Allow` runs it and `Log` runs
    /// it after auditing; the rest deny it. Used to decide whether a policy
    /// restricts anything at all.
    fn is_permissive(self) -> bool {
        matches!(self, SeccompAction::Allow | SeccompAction::Log)
    }
}

/// `EPERM`, the error a denied syscall reports by default.
const EPERM: u16 = 1;

/// `BPF_MAXINSNS`, the kernel's ceiling on a classic BPF filter's length. A
/// compiled seccomp program is checked against it at build time so an
/// over-long program is rejected rather than silently truncated when its
/// length is later narrowed to a `u16` for the kernel's `sock_fprog`.
const BPF_MAXINSNS: usize = 4096;

/// The width of a syscall argument to compare: the low 32 bits (`Dword`) or
/// all 64 (`Qword`).
///
/// The kernel presents every syscall argument to a seccomp filter as a 64-bit
/// value, whatever the argument's declared type. The width is a deliberate
/// choice with a security edge: comparing only the low 32 bits of an argument
/// that is really 64 bits lets a value hide in the high bits, and comparing
/// all 64 bits of an argument the kernel treats as a 32-bit `int` lets a value
/// hide there instead. Match the width to the argument's kernel type — `Dword`
/// for an `int`, `unsigned int`, or a 32-bit flag set; `Qword` for a pointer,
/// an `unsigned long`, or any 64-bit value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SeccompArgLen {
    /// The low 32 bits of the argument.
    Dword,
    /// All 64 bits of the argument.
    Qword,
}

/// The comparison a [`SeccompArg`] applies between a syscall argument and a
/// reference value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SeccompCompare {
    /// The argument equals the value.
    Eq,
    /// The argument does not equal the value.
    Ne,
    /// The argument is greater than or equal to the value.
    Ge,
    /// The argument is greater than the value.
    Gt,
    /// The argument is less than or equal to the value.
    Le,
    /// The argument is less than the value.
    Lt,
    /// The argument, masked with the carried bits, equals the value masked
    /// with the same bits: `(arg & mask) == (value & mask)`. Tests individual
    /// flag bits — for example, that `CLONE_NEWUSER` is clear in a `clone`
    /// flags argument, with `MaskedEq(CLONE_NEWUSER)` against a value of `0`.
    MaskedEq(u64),
}

/// A condition on one argument of a syscall.
///
/// A condition names an argument by index (0 through 5, the six syscall
/// registers), a [width](SeccompArgLen) to compare, a [comparison](SeccompCompare),
/// and a reference value. It narrows which invocations of a listed syscall a
/// [`SeccompRules`] rule matches — "`ioctl` only when its request equals
/// `TIOCGWINSZ`," "`socket` only when its domain equals `AF_INET`."
///
/// The width-named constructors ([`eq_dword`](Self::eq_dword),
/// [`eq_qword`](Self::eq_qword), and the rest) are the usual way to build one;
/// they make the [`Dword`](SeccompArgLen::Dword)/[`Qword`](SeccompArgLen::Qword)
/// choice explicit at the call site, since it has no safe default. [`new`](Self::new)
/// takes the parts directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeccompArg {
    index: u8,
    len: SeccompArgLen,
    compare: SeccompCompare,
    value: u64,
}

impl SeccompArg {
    /// A condition from its parts: the argument `index` (0 through 5), the
    /// `len` to compare, the `compare` operation, and the reference `value`.
    pub fn new(index: u8, len: SeccompArgLen, compare: SeccompCompare, value: u64) -> SeccompArg {
        SeccompArg {
            index,
            len,
            compare,
            value,
        }
    }

    /// The low 32 bits of argument `index` equal `value`.
    pub fn eq_dword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Dword, SeccompCompare::Eq, value)
    }

    /// All 64 bits of argument `index` equal `value`.
    pub fn eq_qword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Qword, SeccompCompare::Eq, value)
    }

    /// The low 32 bits of argument `index` do not equal `value`.
    pub fn ne_dword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Dword, SeccompCompare::Ne, value)
    }

    /// All 64 bits of argument `index` do not equal `value`.
    pub fn ne_qword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Qword, SeccompCompare::Ne, value)
    }

    /// The low 32 bits of argument `index` are greater than or equal to
    /// `value`.
    pub fn ge_dword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Dword, SeccompCompare::Ge, value)
    }

    /// All 64 bits of argument `index` are greater than or equal to `value`.
    pub fn ge_qword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Qword, SeccompCompare::Ge, value)
    }

    /// The low 32 bits of argument `index` are greater than `value`.
    pub fn gt_dword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Dword, SeccompCompare::Gt, value)
    }

    /// All 64 bits of argument `index` are greater than `value`.
    pub fn gt_qword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Qword, SeccompCompare::Gt, value)
    }

    /// The low 32 bits of argument `index` are less than or equal to `value`.
    pub fn le_dword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Dword, SeccompCompare::Le, value)
    }

    /// All 64 bits of argument `index` are less than or equal to `value`.
    pub fn le_qword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Qword, SeccompCompare::Le, value)
    }

    /// The low 32 bits of argument `index` are less than `value`.
    pub fn lt_dword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Dword, SeccompCompare::Lt, value)
    }

    /// All 64 bits of argument `index` are less than `value`.
    pub fn lt_qword(index: u8, value: u64) -> SeccompArg {
        SeccompArg::new(index, SeccompArgLen::Qword, SeccompCompare::Lt, value)
    }

    /// The low 32 bits of argument `index`, masked with `mask`, equal `value`
    /// masked with `mask`.
    pub fn masked_eq_dword(index: u8, mask: u64, value: u64) -> SeccompArg {
        SeccompArg::new(
            index,
            SeccompArgLen::Dword,
            SeccompCompare::MaskedEq(mask),
            value,
        )
    }

    /// All 64 bits of argument `index`, masked with `mask`, equal `value`
    /// masked with `mask`.
    pub fn masked_eq_qword(index: u8, mask: u64, value: u64) -> SeccompArg {
        SeccompArg::new(
            index,
            SeccompArgLen::Qword,
            SeccompCompare::MaskedEq(mask),
            value,
        )
    }

    /// Lowers the condition to the compiler backend's representation, mapping a
    /// rejected argument index to a [`ConfigError`].
    fn to_seccompiler(self) -> Result<seccompiler::SeccompCondition, ConfigError> {
        let len = match self.len {
            SeccompArgLen::Dword => seccompiler::SeccompCmpArgLen::Dword,
            SeccompArgLen::Qword => seccompiler::SeccompCmpArgLen::Qword,
        };
        let op = match self.compare {
            SeccompCompare::Eq => seccompiler::SeccompCmpOp::Eq,
            SeccompCompare::Ne => seccompiler::SeccompCmpOp::Ne,
            SeccompCompare::Ge => seccompiler::SeccompCmpOp::Ge,
            SeccompCompare::Gt => seccompiler::SeccompCmpOp::Gt,
            SeccompCompare::Le => seccompiler::SeccompCmpOp::Le,
            SeccompCompare::Lt => seccompiler::SeccompCmpOp::Lt,
            SeccompCompare::MaskedEq(mask) => seccompiler::SeccompCmpOp::MaskedEq(mask),
        };
        seccompiler::SeccompCondition::new(self.index, len, op, self.value).map_err(|err| {
            ConfigError::SeccompInvalid {
                reason: err.to_string(),
            }
        })
    }
}

/// A listed syscall and the argument conditions, if any, that narrow which of
/// its invocations the rule matches. Empty conditions match the syscall
/// regardless of its arguments.
#[derive(Debug, Clone)]
struct SyscallRule {
    syscall: i64,
    /// Conditions that all must hold (an AND) for the rule to match.
    conditions: Vec<SeccompArg>,
}

impl SyscallRule {
    /// A rule that matches `syscall` regardless of its arguments.
    fn unconditional(syscall: i64) -> SyscallRule {
        SyscallRule {
            syscall,
            conditions: Vec::new(),
        }
    }
}

/// A caller-authored seccomp policy: a default action for unlisted syscalls,
/// and the opposite action for a named list.
///
/// The two shapes cover the common cases. An allowlist names the syscalls the
/// command may make and denies the rest — the strict posture, which must
/// include every syscall the command needs (`execve` among them, since it is
/// the first syscall the filter governs). A denylist names the syscalls to
/// refuse and allows the rest.
///
/// Syscalls are named by their kernel number for the host architecture; the
/// `syscalls` crate or `libc` provides them.
///
/// A listed syscall may carry [argument conditions](SeccompArg) through
/// [`rule`](Self::rule), so the listed action applies only to invocations
/// whose arguments match — an allowlist that permits `ioctl` only for a
/// specific request, a denylist that refuses `socket` only for `AF_INET`. A
/// syscall listed both plainly and with conditions matches unconditionally:
/// the broader listing wins.
///
/// A seccomp filter governs syscalls, not the operations an asynchronous
/// submission interface performs on their behalf. An allowlist that permits
/// `io_uring_enter` therefore permits the file opens, connects, and reads
/// submitted through the ring, even where it denies `openat`, `connect`, or
/// `read` directly. Do not allowlist the io_uring syscalls unless the command
/// genuinely needs them; the [curated policy](SeccompPolicy::Curated) denies
/// them for this reason.
#[derive(Debug, Clone)]
pub struct SeccompRules {
    default_action: SeccompAction,
    listed_action: SeccompAction,
    rules: Vec<SyscallRule>,
}

impl SeccompRules {
    /// A denylist: `syscalls` fail with `EPERM`, everything else is allowed.
    pub fn denying<I: IntoIterator<Item = i64>>(syscalls: I) -> SeccompRules {
        SeccompRules {
            default_action: SeccompAction::Allow,
            listed_action: SeccompAction::Errno(EPERM),
            rules: syscalls
                .into_iter()
                .map(SyscallRule::unconditional)
                .collect(),
        }
    }

    /// An allowlist: `syscalls` are allowed, everything else fails with
    /// `EPERM`.
    pub fn allowing<I: IntoIterator<Item = i64>>(syscalls: I) -> SeccompRules {
        SeccompRules {
            default_action: SeccompAction::Errno(EPERM),
            listed_action: SeccompAction::Allow,
            rules: syscalls
                .into_iter()
                .map(SyscallRule::unconditional)
                .collect(),
        }
    }

    /// Lists `syscall` with argument conditions: the listed action applies
    /// only when every condition in `conditions` holds (an AND). Call this
    /// more than once for the same syscall to accept any of several condition
    /// sets (an OR).
    ///
    /// Passing no conditions lists the syscall unconditionally, the same as
    /// naming it in [`denying`](Self::denying) or [`allowing`](Self::allowing).
    /// If a syscall is listed both unconditionally and with conditions, the
    /// unconditional listing wins.
    pub fn rule<I: IntoIterator<Item = SeccompArg>>(
        mut self,
        syscall: i64,
        conditions: I,
    ) -> SeccompRules {
        self.rules.push(SyscallRule {
            syscall,
            conditions: conditions.into_iter().collect(),
        });
        self
    }

    /// Sets the action for unlisted syscalls (the default is `Allow` for a
    /// denylist, `Errno(EPERM)` for an allowlist).
    pub fn default_action(mut self, action: SeccompAction) -> SeccompRules {
        self.default_action = action;
        self
    }

    /// Sets the action for the listed syscalls.
    pub fn listed_action(mut self, action: SeccompAction) -> SeccompRules {
        self.listed_action = action;
        self
    }

    /// Whether the policy denies any syscall. A default-deny (allowlist)
    /// posture always restricts, since it denies every unlisted syscall; a
    /// default-allow (denylist) posture restricts only when it lists at least
    /// one syscall under a denying action. An empty `denying([])` restricts
    /// nothing.
    fn restricts(&self) -> bool {
        !self.default_action.is_permissive()
            || (!self.rules.is_empty() && !self.listed_action.is_permissive())
    }
}

/// A seccomp syscall-filtering policy for the sandboxed command.
#[non_exhaustive]
pub enum SeccompPolicy {
    /// A curated default-deny of dangerous and rarely-legitimate syscalls,
    /// allowing the rest. A convenience posture, not a boundary claim; its
    /// exact roster is documented and grows only additively.
    Curated,
    /// A caller-authored allow- or denylist.
    Rules(SeccompRules),
    /// An already-compiled BPF program, installed verbatim — the escape hatch
    /// for a policy an external compiler produced.
    Program(Vec<SockFilter>),
}

impl SeccompPolicy {
    /// Whether the policy denies any syscall. The curated roster and any
    /// non-empty caller policy restrict; an empty `denying([])` does not. Used
    /// to decide whether a restriction confines anything through seccomp, so a
    /// no-op policy does not pass the empty-restriction guard.
    pub(crate) fn restricts(&self) -> bool {
        match self {
            SeccompPolicy::Curated => true,
            SeccompPolicy::Rules(rules) => rules.restricts(),
            // The escape hatch is opaque; a non-empty program is assumed to
            // restrict, an empty one (which the kernel would reject anyway)
            // does not.
            SeccompPolicy::Program(program) => !program.is_empty(),
        }
    }
}

// A hand-written Debug so the escape-hatch program prints its length, not
// every instruction.
impl std::fmt::Debug for SeccompPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeccompPolicy::Curated => f.write_str("Curated"),
            SeccompPolicy::Rules(rules) => f.debug_tuple("Rules").field(rules).finish(),
            SeccompPolicy::Program(program) => f
                .debug_tuple("Program")
                .field(&format_args!("{} instructions", program.len()))
                .finish(),
        }
    }
}

/// The curated denylist: dangerous or rarely-legitimate syscalls, denied with
/// `EPERM`. Named through the `syscalls` crate so the numbers are correct for
/// the host architecture. Not exhaustive — a convenience posture.
///
/// The list denies `io_uring_setup`/`io_uring_enter`/`io_uring_register`
/// because io_uring can carry filesystem and network operations
/// (`IORING_OP_OPENAT`, `IORING_OP_CONNECT`, ...) that a syscall filter never
/// sees. That same limitation means an *allowlist* a caller authors is
/// bypassable if it permits the io_uring syscalls but denies the operations
/// io_uring can perform: filter the io_uring syscalls too, or leave them
/// unlisted so the allowlist's default action denies them. See
/// [`SeccompRules`].
fn curated_denylist() -> Vec<i64> {
    use syscalls::Sysno;
    // Filesystem topology, kernel modules, the keyring, tracing, time, and
    // other administrative surfaces a sandboxed command has no business
    // reaching. Every entry of the base roster exists on all three
    // seccomp-supported architectures; anything that does not is added after it,
    // under the architecture it belongs to.
    let base = [
        Sysno::mount,
        Sysno::umount2,
        Sysno::pivot_root,
        Sysno::mount_setattr,
        Sysno::move_mount,
        Sysno::open_tree,
        Sysno::fsopen,
        Sysno::fsconfig,
        Sysno::fsmount,
        Sysno::fspick,
        // A file handle names an inode by (mount id, opaque handle) rather than
        // by path, so it reaches across the mount topology the way the calls
        // above reshape it. Opening one needs CAP_DAC_READ_SEARCH, which the
        // sandbox's own user namespace grants.
        Sysno::name_to_handle_at,
        Sysno::open_by_handle_at,
        Sysno::swapon,
        Sysno::swapoff,
        Sysno::reboot,
        Sysno::kexec_load,
        Sysno::kexec_file_load,
        Sysno::init_module,
        Sysno::finit_module,
        Sysno::delete_module,
        Sysno::add_key,
        Sysno::keyctl,
        Sysno::request_key,
        Sysno::bpf,
        Sysno::ptrace,
        // The natural complements to ptrace: cross-process memory access,
        // reachable against another process of the same uid in a restriction
        // (no PID namespace) where ptrace alone would not suffice.
        Sysno::process_vm_readv,
        Sysno::process_vm_writev,
        Sysno::perf_event_open,
        // Handing page-fault resolution to userspace is a standard primitive
        // for widening a kernel race into a reliable exploit, and nothing a
        // sandboxed build needs.
        Sysno::userfaultfd,
        // Changing the execution domain can weaken protections the sandbox
        // relies on (for instance READ_IMPLIES_EXEC, or re-enabling layout
        // randomization the caller disabled).
        Sysno::personality,
        // io_uring is a submission ring for asynchronous syscalls; denying it
        // keeps operations from reaching the kernel outside the filter's view.
        Sysno::io_uring_setup,
        Sysno::io_uring_enter,
        Sysno::io_uring_register,
        Sysno::settimeofday,
        Sysno::clock_settime,
        Sysno::clock_adjtime,
        Sysno::adjtimex,
        Sysno::setns,
        Sysno::acct,
        Sysno::quotactl,
    ];

    // `modify_ldt` changes the execution domain like `personality` does, and is
    // denied for the same reason — but the local descriptor table is an x86
    // construct, so the name exists only there.
    #[cfg(target_arch = "x86_64")]
    let arch_specific = [Sysno::modify_ldt];
    #[cfg(not(target_arch = "x86_64"))]
    let arch_specific: [Sysno; 0] = [];

    base.into_iter()
        .chain(arch_specific)
        .map(|sysno| sysno.id() as i64)
        .collect()
}

/// A named capability, for [`CageBuilder::keep_capabilities`].
///
/// In a fresh user namespace the command is mapped to root and holds every
/// capability *within that namespace* — none of which confers authority over
/// the host, but which do grant power inside the sandbox.
/// [`drop_all_capabilities`](crate::CageBuilder::drop_all_capabilities) sheds
/// them; a keep-list retains the named few.
///
/// Each capability has a canonical kebab-case name (`net-bind-service`),
/// printed by [`Display`](std::fmt::Display) and parsed by
/// [`FromStr`](std::str::FromStr). Parsing also accepts the snake-case form
/// and an optional `cap-`/`cap_` prefix, and is case-insensitive, so
/// `CAP_SYS_ADMIN`, `sys_admin`, and `sys-admin` all parse to
/// [`SysAdmin`](Self::SysAdmin). [`ALL`](Self::ALL) lists every variant.
///
/// [`CageBuilder::keep_capabilities`]: crate::CageBuilder::keep_capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Capability {
    /// `CAP_CHOWN`.
    Chown,
    /// `CAP_DAC_OVERRIDE`.
    DacOverride,
    /// `CAP_DAC_READ_SEARCH`.
    DacReadSearch,
    /// `CAP_FOWNER`.
    Fowner,
    /// `CAP_FSETID`.
    Fsetid,
    /// `CAP_KILL`.
    Kill,
    /// `CAP_SETGID`.
    Setgid,
    /// `CAP_SETUID`.
    Setuid,
    /// `CAP_SETPCAP`.
    Setpcap,
    /// `CAP_LINUX_IMMUTABLE`.
    LinuxImmutable,
    /// `CAP_NET_BIND_SERVICE`.
    NetBindService,
    /// `CAP_NET_BROADCAST`.
    NetBroadcast,
    /// `CAP_NET_ADMIN`.
    NetAdmin,
    /// `CAP_NET_RAW`.
    NetRaw,
    /// `CAP_IPC_LOCK`.
    IpcLock,
    /// `CAP_IPC_OWNER`.
    IpcOwner,
    /// `CAP_SYS_MODULE`.
    SysModule,
    /// `CAP_SYS_RAWIO`.
    SysRawio,
    /// `CAP_SYS_CHROOT`.
    SysChroot,
    /// `CAP_SYS_PTRACE`.
    SysPtrace,
    /// `CAP_SYS_PACCT`.
    SysPacct,
    /// `CAP_SYS_ADMIN`.
    SysAdmin,
    /// `CAP_SYS_BOOT`.
    SysBoot,
    /// `CAP_SYS_NICE`.
    SysNice,
    /// `CAP_SYS_RESOURCE`.
    SysResource,
    /// `CAP_SYS_TIME`.
    SysTime,
    /// `CAP_SYS_TTY_CONFIG`.
    SysTtyConfig,
    /// `CAP_MKNOD`.
    Mknod,
    /// `CAP_LEASE`.
    Lease,
    /// `CAP_AUDIT_WRITE`.
    AuditWrite,
    /// `CAP_AUDIT_CONTROL`.
    AuditControl,
    /// `CAP_SETFCAP`.
    Setfcap,
    /// `CAP_MAC_OVERRIDE`.
    MacOverride,
    /// `CAP_MAC_ADMIN`.
    MacAdmin,
    /// `CAP_SYSLOG`.
    Syslog,
    /// `CAP_WAKE_ALARM`.
    WakeAlarm,
    /// `CAP_BLOCK_SUSPEND`.
    BlockSuspend,
    /// `CAP_AUDIT_READ`.
    AuditRead,
    /// `CAP_PERFMON`.
    Perfmon,
    /// `CAP_BPF`.
    Bpf,
    /// `CAP_CHECKPOINT_RESTORE`.
    CheckpointRestore,
}

impl Capability {
    /// The single-bit capability set naming this capability.
    fn to_set(self) -> CapabilitySet {
        match self {
            Capability::Chown => CapabilitySet::CHOWN,
            Capability::DacOverride => CapabilitySet::DAC_OVERRIDE,
            Capability::DacReadSearch => CapabilitySet::DAC_READ_SEARCH,
            Capability::Fowner => CapabilitySet::FOWNER,
            Capability::Fsetid => CapabilitySet::FSETID,
            Capability::Kill => CapabilitySet::KILL,
            Capability::Setgid => CapabilitySet::SETGID,
            Capability::Setuid => CapabilitySet::SETUID,
            Capability::Setpcap => CapabilitySet::SETPCAP,
            Capability::LinuxImmutable => CapabilitySet::LINUX_IMMUTABLE,
            Capability::NetBindService => CapabilitySet::NET_BIND_SERVICE,
            Capability::NetBroadcast => CapabilitySet::NET_BROADCAST,
            Capability::NetAdmin => CapabilitySet::NET_ADMIN,
            Capability::NetRaw => CapabilitySet::NET_RAW,
            Capability::IpcLock => CapabilitySet::IPC_LOCK,
            Capability::IpcOwner => CapabilitySet::IPC_OWNER,
            Capability::SysModule => CapabilitySet::SYS_MODULE,
            Capability::SysRawio => CapabilitySet::SYS_RAWIO,
            Capability::SysChroot => CapabilitySet::SYS_CHROOT,
            Capability::SysPtrace => CapabilitySet::SYS_PTRACE,
            Capability::SysPacct => CapabilitySet::SYS_PACCT,
            Capability::SysAdmin => CapabilitySet::SYS_ADMIN,
            Capability::SysBoot => CapabilitySet::SYS_BOOT,
            Capability::SysNice => CapabilitySet::SYS_NICE,
            Capability::SysResource => CapabilitySet::SYS_RESOURCE,
            Capability::SysTime => CapabilitySet::SYS_TIME,
            Capability::SysTtyConfig => CapabilitySet::SYS_TTY_CONFIG,
            Capability::Mknod => CapabilitySet::MKNOD,
            Capability::Lease => CapabilitySet::LEASE,
            Capability::AuditWrite => CapabilitySet::AUDIT_WRITE,
            Capability::AuditControl => CapabilitySet::AUDIT_CONTROL,
            Capability::Setfcap => CapabilitySet::SETFCAP,
            Capability::MacOverride => CapabilitySet::MAC_OVERRIDE,
            Capability::MacAdmin => CapabilitySet::MAC_ADMIN,
            Capability::Syslog => CapabilitySet::SYSLOG,
            Capability::WakeAlarm => CapabilitySet::WAKE_ALARM,
            Capability::BlockSuspend => CapabilitySet::BLOCK_SUSPEND,
            Capability::AuditRead => CapabilitySet::AUDIT_READ,
            Capability::Perfmon => CapabilitySet::PERFMON,
            Capability::Bpf => CapabilitySet::BPF,
            Capability::CheckpointRestore => CapabilitySet::CHECKPOINT_RESTORE,
        }
    }

    /// Every capability variant, in declaration order.
    ///
    /// The roster tracks the kernel's own, which grows: a capability Linux
    /// adds appears here in a later release. The slice type deliberately keeps
    /// that length out of the signature, so the addition stays additive.
    pub const ALL: &'static [Capability] = &[
        Capability::Chown,
        Capability::DacOverride,
        Capability::DacReadSearch,
        Capability::Fowner,
        Capability::Fsetid,
        Capability::Kill,
        Capability::Setgid,
        Capability::Setuid,
        Capability::Setpcap,
        Capability::LinuxImmutable,
        Capability::NetBindService,
        Capability::NetBroadcast,
        Capability::NetAdmin,
        Capability::NetRaw,
        Capability::IpcLock,
        Capability::IpcOwner,
        Capability::SysModule,
        Capability::SysRawio,
        Capability::SysChroot,
        Capability::SysPtrace,
        Capability::SysPacct,
        Capability::SysAdmin,
        Capability::SysBoot,
        Capability::SysNice,
        Capability::SysResource,
        Capability::SysTime,
        Capability::SysTtyConfig,
        Capability::Mknod,
        Capability::Lease,
        Capability::AuditWrite,
        Capability::AuditControl,
        Capability::Setfcap,
        Capability::MacOverride,
        Capability::MacAdmin,
        Capability::Syslog,
        Capability::WakeAlarm,
        Capability::BlockSuspend,
        Capability::AuditRead,
        Capability::Perfmon,
        Capability::Bpf,
        Capability::CheckpointRestore,
    ];

    /// The canonical kebab-case name, without the `cap-` prefix.
    const fn as_str(self) -> &'static str {
        match self {
            Capability::Chown => "chown",
            Capability::DacOverride => "dac-override",
            Capability::DacReadSearch => "dac-read-search",
            Capability::Fowner => "fowner",
            Capability::Fsetid => "fsetid",
            Capability::Kill => "kill",
            Capability::Setgid => "setgid",
            Capability::Setuid => "setuid",
            Capability::Setpcap => "setpcap",
            Capability::LinuxImmutable => "linux-immutable",
            Capability::NetBindService => "net-bind-service",
            Capability::NetBroadcast => "net-broadcast",
            Capability::NetAdmin => "net-admin",
            Capability::NetRaw => "net-raw",
            Capability::IpcLock => "ipc-lock",
            Capability::IpcOwner => "ipc-owner",
            Capability::SysModule => "sys-module",
            Capability::SysRawio => "sys-rawio",
            Capability::SysChroot => "sys-chroot",
            Capability::SysPtrace => "sys-ptrace",
            Capability::SysPacct => "sys-pacct",
            Capability::SysAdmin => "sys-admin",
            Capability::SysBoot => "sys-boot",
            Capability::SysNice => "sys-nice",
            Capability::SysResource => "sys-resource",
            Capability::SysTime => "sys-time",
            Capability::SysTtyConfig => "sys-tty-config",
            Capability::Mknod => "mknod",
            Capability::Lease => "lease",
            Capability::AuditWrite => "audit-write",
            Capability::AuditControl => "audit-control",
            Capability::Setfcap => "setfcap",
            Capability::MacOverride => "mac-override",
            Capability::MacAdmin => "mac-admin",
            Capability::Syslog => "syslog",
            Capability::WakeAlarm => "wake-alarm",
            Capability::BlockSuspend => "block-suspend",
            Capability::AuditRead => "audit-read",
            Capability::Perfmon => "perfmon",
            Capability::Bpf => "bpf",
            Capability::CheckpointRestore => "checkpoint-restore",
        }
    }
}

impl fmt::Display for Capability {
    /// Writes the canonical kebab-case name, such as `net-bind-service`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Capability {
    type Err = ParseCapabilityError;

    /// Parses a capability name, accepting the kebab or snake form, an
    /// optional `cap-`/`cap_` prefix, and any letter case.
    fn from_str(s: &str) -> Result<Capability, ParseCapabilityError> {
        let lowered = s.to_ascii_lowercase().replace('_', "-");
        let normalized = lowered.strip_prefix("cap-").unwrap_or(&lowered);
        Capability::ALL
            .iter()
            .copied()
            .find(|cap| cap.as_str() == normalized)
            .ok_or_else(|| ParseCapabilityError {
                name: s.to_string(),
            })
    }
}

/// The error from parsing an unrecognized [`Capability`] name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCapabilityError {
    name: String,
}

impl ParseCapabilityError {
    /// The unrecognized name, as it was given.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for ParseCapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown capability {:?}", self.name)
    }
}

impl std::error::Error for ParseCapabilityError {}

/// The capability posture: leave the namespaced set alone, or reduce it to a
/// kept few (empty for a full drop).
#[derive(Debug, Clone, Default)]
enum CapabilityPosture {
    /// Do not touch capabilities (the default).
    #[default]
    Keep,
    /// Reduce the bounding, ambient, permitted, effective, and inheritable
    /// sets to exactly these capabilities.
    Reduce(Vec<Capability>),
}

/// The hardening request accumulated on the builder, lowered by `build` into
/// the frozen [`HardeningPlan`].
///
/// One field on [`CageBuilder`] rather than several, so the builder and the
/// lowering each touch a single place.
///
/// [`CageBuilder`]: crate::CageBuilder
#[derive(Debug, Clone, Default)]
pub(crate) struct Request {
    landlock: Vec<Grant>,
    landlock_net: Vec<NetGrant>,
    seccomp: Option<SeccompPolicy>,
    capabilities: CapabilityPosture,
}

impl Clone for SeccompPolicy {
    fn clone(&self) -> SeccompPolicy {
        match self {
            SeccompPolicy::Curated => SeccompPolicy::Curated,
            SeccompPolicy::Rules(rules) => SeccompPolicy::Rules(rules.clone()),
            SeccompPolicy::Program(program) => SeccompPolicy::Program(program.clone()),
        }
    }
}

impl Request {
    /// Adds a Landlock grant of `access` beneath `path`.
    pub(crate) fn grant_fs(&mut self, access: FsAccess, path: &Path) {
        self.landlock.push(Grant {
            access,
            path: path.to_path_buf(),
        });
    }

    /// Adds a Landlock grant of network `access` on the TCP `port`.
    pub(crate) fn grant_net(&mut self, access: NetAccess, port: u16) {
        self.landlock_net.push(NetGrant { access, port });
    }

    /// Sets the seccomp policy.
    pub(crate) fn set_seccomp(&mut self, policy: SeccompPolicy) {
        self.seccomp = Some(policy);
    }

    /// Whether the request restricts nothing: no Landlock grant — filesystem
    /// or network — and no seccomp policy that denies a syscall. A seccomp
    /// policy that denies nothing (an empty `denying([])`) does not count, so a
    /// restriction whose only "confinement" is a no-op filter is caught by the
    /// empty-restriction guard rather than run unconfined. The capability
    /// posture does not count — the restriction fallback, the check's consumer,
    /// cannot express one.
    pub(crate) fn is_unrestricted(&self) -> bool {
        self.landlock.is_empty()
            && self.landlock_net.is_empty()
            && self
                .seccomp
                .as_ref()
                .is_none_or(|policy| !policy.restricts())
    }

    /// Whether the request carries no hardening at all: no Landlock grant, no
    /// seccomp policy, and the default, untouched capability posture. Unlike
    /// [`is_unrestricted`](Self::is_unrestricted), this also requires the
    /// default capability posture, so a profile that only drops capabilities
    /// still serializes its `[hardening]` table. Serde skips the field when
    /// this holds.
    #[cfg(feature = "serde")]
    pub(crate) fn has_no_hardening(&self) -> bool {
        self.landlock.is_empty()
            && self.landlock_net.is_empty()
            && self.seccomp.is_none()
            && matches!(self.capabilities, CapabilityPosture::Keep)
    }

    /// Drops every capability.
    pub(crate) fn drop_all_capabilities(&mut self) {
        self.capabilities = CapabilityPosture::Reduce(Vec::new());
    }

    /// Keeps only the named capabilities, dropping the rest.
    pub(crate) fn keep_capabilities<I: IntoIterator<Item = Capability>>(&mut self, caps: I) {
        self.capabilities = CapabilityPosture::Reduce(caps.into_iter().collect());
    }

    /// Lowers the request into the frozen plan, compiling the seccomp policy
    /// and validating the Landlock grant paths. Called from the builders'
    /// `build`, where allocation and failure are free.
    pub(crate) fn lower(&self) -> Result<HardeningPlan, ConfigError> {
        let landlock = self
            .landlock
            .iter()
            .map(|grant| {
                Ok(LandlockRule {
                    path: grant_path_cstring(&grant.path)?,
                    access: grant.access.to_landlock(),
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let landlock_net = self
            .landlock_net
            .iter()
            .map(|grant| LandlockNetRule {
                port: grant.port,
                access: grant.access.to_landlock(),
            })
            .collect::<Vec<_>>();

        let seccomp = match &self.seccomp {
            Some(policy) => Some(compile_seccomp(policy)?),
            None => None,
        };

        let keep_caps = match &self.capabilities {
            CapabilityPosture::Keep => None,
            CapabilityPosture::Reduce(caps) => {
                let mut set = CapabilitySet::empty();
                for cap in caps {
                    set |= cap.to_set();
                }
                Some(set.bits())
            }
        };

        Ok(HardeningPlan {
            landlock,
            landlock_handled: if self.landlock.is_empty() {
                0
            } else {
                fs_access::ALL
            },
            landlock_net,
            landlock_net_handled: if self.landlock_net.is_empty() {
                0
            } else {
                net_access::ALL
            },
            seccomp,
            keep_caps,
            // Whether the identity switch needs securebits is decided by
            // the builder, which alone knows the run-as identity.
            set_securebits: false,
        })
    }
}

/// Validates a Landlock grant path — absolute, normal components only, the
/// bare root allowed so a grant can cover a whole tree — and freezes it as a
/// `CString`. In a cage the path resolves after the pivot; in a restriction
/// it resolves against the host filesystem.
fn grant_path_cstring(path: &Path) -> Result<CString, ConfigError> {
    let invalid = || ConfigError::LandlockPathInvalid {
        path: path.to_path_buf(),
    };
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(invalid());
    }
    for component in components {
        if !matches!(component, Component::Normal(_)) {
            return Err(invalid());
        }
    }
    crate::spec::cstring(path.as_os_str())
}

/// Compiles a seccomp policy to a BPF program, rejecting one that exceeds the
/// kernel's instruction ceiling.
fn compile_seccomp(policy: &SeccompPolicy) -> Result<Vec<SockFilter>, ConfigError> {
    let program = match policy {
        SeccompPolicy::Curated => {
            let rules: Vec<SyscallRule> = curated_denylist()
                .into_iter()
                .map(SyscallRule::unconditional)
                .collect();
            compile_filter(SeccompAction::Allow, SeccompAction::Errno(EPERM), &rules)?
        }
        SeccompPolicy::Rules(rules) => {
            compile_filter(rules.default_action, rules.listed_action, &rules.rules)?
        }
        SeccompPolicy::Program(program) => program.clone(),
    };
    // The kernel rejects a filter longer than BPF_MAXINSNS, but only if the
    // length reaching it is honest; the install path narrows the length to a
    // u16, so an over-long program (a caller's precompiled escape hatch) must
    // be caught here, before that cast can wrap it into a different filter.
    if program.len() > BPF_MAXINSNS {
        return Err(ConfigError::SeccompProgramTooLong {
            len: program.len(),
            max: BPF_MAXINSNS,
        });
    }
    Ok(program)
}

/// Classic-BPF opcodes and `seccomp_data` field offsets for the hand-emitted
/// x32 guard. Named here rather than pulled from a binding so the one raw-BPF
/// fragment in the crate is self-contained and reviewable.
mod bpf {
    /// `BPF_LD | BPF_W | BPF_ABS`: load a 32-bit word from a fixed offset in
    /// `seccomp_data` into the accumulator.
    pub(super) const LD_W_ABS: u16 = 0x20;
    /// `BPF_JMP | BPF_JEQ | BPF_K`: branch on the accumulator equalling `k`.
    pub(super) const JMP_JEQ_K: u16 = 0x15;
    /// `BPF_JMP | BPF_JSET | BPF_K`: branch on the accumulator sharing any bit
    /// with `k`.
    pub(super) const JMP_JSET_K: u16 = 0x45;
    /// `BPF_RET | BPF_K`: return `k` as the seccomp action.
    pub(super) const RET_K: u16 = 0x06;

    /// Byte offset of `seccomp_data.nr`, the syscall number.
    pub(super) const OFF_NR: u32 = 0;
    /// Byte offset of `seccomp_data.arch`, the AUDIT_ARCH of the syscall.
    pub(super) const OFF_ARCH: u32 = 4;
}

/// `AUDIT_ARCH_X86_64`: the audit architecture the x32 ABI shares with 64-bit
/// x86_64, which is why an x32 syscall passes an x86_64 arch gate.
///
/// Only a denylist needs to care: an allowlist's default-deny already refuses
/// the x32 numbers, so the guard this constant serves — [`x32_deny_prologue`] —
/// is emitted for a permissive default alone, in [`compile_filter`].
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `__X32_SYSCALL_BIT`: set on every syscall number issued through the x32 ABI.
///
/// Adding it to a syscall number gives the x32 alias of the same call, which is
/// what lets an x32 caller slip past a denylist that names only the 64-bit
/// numbers; see [`AUDIT_ARCH_X86_64`].
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The raw `SECCOMP_RET_*` value a BPF `ret` returns for `action`.
///
/// The x32 guard emits a `ret` directly, below seccompiler's compilation, so
/// it needs the same encoding seccompiler produces from a
/// [`seccompiler::SeccompAction`]. The action words are the kernel's, from
/// `<linux/seccomp.h>`.
fn seccomp_ret_value(action: SeccompAction) -> u32 {
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_DATA: u32 = 0x0000_ffff;
    match action {
        SeccompAction::Allow => SECCOMP_RET_ALLOW,
        SeccompAction::Errno(errno) => SECCOMP_RET_ERRNO | (u32::from(errno) & SECCOMP_RET_DATA),
        SeccompAction::Log => SECCOMP_RET_LOG,
        SeccompAction::KillThread => SECCOMP_RET_KILL_THREAD,
        SeccompAction::KillProcess => SECCOMP_RET_KILL_PROCESS,
    }
}

/// A five-instruction classic-BPF prologue applying `deny` to every syscall
/// carrying `__X32_SYSCALL_BIT`, for prepending to a denylist compiled for
/// x86_64.
///
/// A denylist gates on AUDIT_ARCH_X86_64 and then matches raw syscall numbers.
/// The x32 ABI shares that arch but sets `__X32_SYSCALL_BIT` on every number,
/// so a denied syscall (`ptrace`, `mount`, ...) issued through x32 matches no
/// rule and falls through to the allowing default. Denying the whole x32 range
/// closes that path; the crate does not otherwise support x32. The fragment
/// falls through to seccompiler's program (which reloads the arch word) when
/// the arch is not x86_64, or when the bit is clear:
///
/// ```text
///   [0] A = seccomp_data.arch
///   [1] if A != AUDIT_ARCH_X86_64: jump past the guard
///   [2] A = seccomp_data.nr
///   [3] if A & __X32_SYSCALL_BIT == 0: jump past the guard
///   [4] return `deny`
/// ```
fn x32_deny_prologue(deny: SeccompAction) -> [SockFilter; 5] {
    let ret = seccomp_ret_value(deny);
    [
        SockFilter {
            code: bpf::LD_W_ABS,
            jt: 0,
            jf: 0,
            k: bpf::OFF_ARCH,
        },
        SockFilter {
            code: bpf::JMP_JEQ_K,
            jt: 0,
            jf: 3,
            k: AUDIT_ARCH_X86_64,
        },
        SockFilter {
            code: bpf::LD_W_ABS,
            jt: 0,
            jf: 0,
            k: bpf::OFF_NR,
        },
        SockFilter {
            code: bpf::JMP_JSET_K,
            jt: 0,
            jf: 1,
            k: X32_SYSCALL_BIT,
        },
        SockFilter {
            code: bpf::RET_K,
            jt: 0,
            jf: 0,
            k: ret,
        },
    ]
}

/// Compiles a single-match-action filter: `listed_action` for the listed
/// syscalls (subject to any argument conditions), `default_action` for the
/// rest.
///
/// A syscall's argument conditions decide whether an invocation counts as
/// matched; a matched invocation takes the `listed_action`, an unmatched one
/// the `default_action`. So conditions refine which invocations of a listed
/// syscall the listed action governs, without any per-syscall action.
fn compile_filter(
    default_action: SeccompAction,
    listed_action: SeccompAction,
    rules: &[SyscallRule],
) -> Result<Vec<SockFilter>, ConfigError> {
    let arch = host_target_arch()?;
    // An unconditional listing matches the syscall regardless of its
    // arguments and dominates any conditioned listing of the same syscall, so
    // the two are gathered separately before the map is built: unconditional
    // syscalls map to an empty rule vector (the backend's match-anything
    // form), conditioned ones to a rule per condition set (an OR).
    let mut unconditional: BTreeSet<i64> = BTreeSet::new();
    let mut conditioned: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for rule in rules {
        if rule.conditions.is_empty() {
            unconditional.insert(rule.syscall);
            continue;
        }
        let conditions = rule
            .conditions
            .iter()
            .map(|condition| condition.to_seccompiler())
            .collect::<Result<Vec<_>, _>>()?;
        let seccomp_rule = seccompiler::SeccompRule::new(conditions).map_err(|err| {
            ConfigError::SeccompInvalid {
                reason: err.to_string(),
            }
        })?;
        conditioned
            .entry(rule.syscall)
            .or_default()
            .push(seccomp_rule);
    }
    let mut map: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for &syscall in &unconditional {
        map.insert(syscall, Vec::new());
    }
    for (syscall, seccomp_rules) in conditioned {
        if !unconditional.contains(&syscall) {
            map.insert(syscall, seccomp_rules);
        }
    }
    let filter = seccompiler::SeccompFilter::new(
        map,
        default_action.to_seccompiler(),
        listed_action.to_seccompiler(),
        arch,
    )
    .map_err(|err| ConfigError::SeccompInvalid {
        reason: err.to_string(),
    })?;
    let program: seccompiler::BpfProgram =
        filter
            .try_into()
            .map_err(
                |err: seccompiler::BackendError| ConfigError::SeccompInvalid {
                    reason: err.to_string(),
                },
            )?;
    let compiled = program.into_iter().map(|insn| SockFilter {
        code: insn.code,
        jt: insn.jt,
        jf: insn.jf,
        k: insn.k,
    });

    // On x86_64 a denylist (a permissive default) is bypassable through the x32
    // ABI: it shares AUDIT_ARCH_X86_64 but tags every syscall number with
    // __X32_SYSCALL_BIT, so a denied number matches no rule and falls through
    // to the allowing default. Prepend a guard denying the whole x32 range. An
    // allowlist needs none — an unmatched x32 number already takes its denying
    // default — and only x86_64 aliases arch and ABI this way. seccompiler's
    // per-syscall map cannot express the guard, so it is emitted as raw BPF
    // ahead of seccompiler's program, which reloads the arch word itself.
    let needs_x32_guard =
        matches!(arch, seccompiler::TargetArch::x86_64) && default_action.is_permissive();
    let program: Vec<SockFilter> = if needs_x32_guard {
        x32_deny_prologue(listed_action)
            .into_iter()
            .chain(compiled)
            .collect()
    } else {
        compiled.collect()
    };
    Ok(program)
}

/// The seccomp target architecture for the host, or an error on an
/// architecture the compiler does not target.
fn host_target_arch() -> Result<seccompiler::TargetArch, ConfigError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(seccompiler::TargetArch::x86_64),
        "aarch64" => Ok(seccompiler::TargetArch::aarch64),
        "riscv64" => Ok(seccompiler::TargetArch::riscv64),
        other => Err(ConfigError::SeccompUnsupportedArch {
            arch: other.to_string(),
        }),
    }
}

/// The serde adapter bridging the in-memory [`Request`] and a profile's
/// hardening representation.
///
/// The programmatic API works in the request's own terms — real
/// [`SeccompPolicy`] values (raw syscall numbers, the precompiled escape
/// hatch), [`FsAccess`] bitsets, and [`Capability`] values. A profile is
/// written in a reviewable form instead: `rwx` access strings, syscalls and
/// capabilities by name, and no place for a precompiled program. This module
/// converts between the two through a mirror struct, so [`Request`] stays the
/// single in-memory representation and serde is only an adapter, as the
/// `serde_os` adapters in [`crate::spec`] are for the builder's `OsString`
/// fields.
///
/// The `[hardening]` table this produces is:
///
/// ```toml
/// [hardening]
/// drop-caps = true                 # or: keep-caps = ["net-bind-service"]
/// seccomp = "curated"              # or a [hardening.seccomp] deny/allow table
///
/// [[hardening.landlock-fs]]
/// access = "rx"
/// path = "/usr"
///
/// [[hardening.landlock-net]]
/// access = "c"
/// port = 443
/// ```
///
/// A seccomp allow- or denylist may narrow a syscall by its arguments through
/// an `allow-rule` or `deny-rule` array-of-tables, each naming a syscall and
/// the argument conditions its listed action requires:
///
/// ```toml
/// [hardening.seccomp]
/// allow = ["read", "write", "exit-group"]
///
/// [[hardening.seccomp.allow-rule]]
/// syscall = "ioctl"
/// [[hardening.seccomp.allow-rule.arg]]
/// index = 1
/// len = "dword"
/// op = "eq"
/// value = 21523            # TIOCGWINSZ
/// ```
///
/// Names resolve for the host architecture: syscall names through the
/// `syscalls` crate, capability names through [`Capability`]'s `FromStr`. An
/// unknown name is a deserialization error; a policy a profile cannot express
/// — a precompiled program, or rules with a custom action — is a
/// serialization error, never a silent omission.
#[cfg(feature = "serde")]
pub(crate) mod serde_request {
    use std::path::PathBuf;

    use serde::de::Error as _;
    use serde::ser::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use syscalls::Sysno;

    use super::{
        Capability, CapabilityPosture, EPERM, FsAccess, Grant, NetAccess, NetGrant, Request,
        SeccompAction, SeccompArg, SeccompArgLen, SeccompCompare, SeccompPolicy, SeccompRules,
    };

    /// The profile form of a hardening request: the `[hardening]` table.
    ///
    /// The two capability keys and the seccomp key precede the `landlock-fs`
    /// and `landlock-net` arrays so the serialized table is valid TOML in field
    /// order — a bare key after an array-of-tables header would bind to the
    /// wrong table, the same ordering constraint the top-level builder
    /// observes.
    #[derive(Serialize, Deserialize, Default)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
    struct HardeningProfile {
        /// Drop every capability. Mutually exclusive with `keep-caps`.
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        drop_caps: bool,
        /// Keep only these capabilities, by name, dropping the rest. Mutually
        /// exclusive with `drop-caps`. An empty list is rejected rather than
        /// read as a drop-all, which `drop-caps` expresses.
        #[serde(skip_serializing_if = "Option::is_none")]
        keep_caps: Option<Vec<String>>,
        /// The seccomp policy, when one is configured.
        #[serde(skip_serializing_if = "Option::is_none")]
        seccomp: Option<SeccompProfile>,
        /// The Landlock filesystem grants.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        landlock_fs: Vec<GrantProfile>,
        /// The Landlock network (TCP port) grants.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        landlock_net: Vec<NetGrantProfile>,
    }

    /// One Landlock filesystem grant in a profile: an `rwx` access string and a
    /// path.
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    struct GrantProfile {
        access: FsAccess,
        path: PathBuf,
    }

    /// One Landlock network grant in a profile: a `bc` access string and a TCP
    /// port.
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    struct NetGrantProfile {
        access: NetAccess,
        port: u16,
    }

    /// The seccomp policy in a profile. The precompiled-program escape hatch is
    /// deliberately absent: a profile is declarative and reviewable.
    ///
    /// Written either as the string `"curated"` or as a table naming syscalls
    /// to allow or deny. The two forms are different TOML types — a string and
    /// a table — so the (de)serialization is written by hand rather than
    /// derived: the derive for a mixed string-or-table shape (an untagged enum)
    /// would silently drop the `deny_unknown_fields` strictness the rest of the
    /// profile keeps.
    enum SeccompProfile {
        /// The curated denylist. Written as the string `"curated"`.
        Curated,
        /// An allow- or denylist, with optional per-syscall argument rules.
        Lists(SeccompLists),
    }

    impl Serialize for SeccompProfile {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self {
                SeccompProfile::Curated => serializer.serialize_str("curated"),
                SeccompProfile::Lists(lists) => lists.serialize(serializer),
            }
        }
    }

    impl<'de> Deserialize<'de> for SeccompProfile {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            use serde::de::{self, MapAccess, Visitor};

            struct SeccompProfileVisitor;

            impl<'de> Visitor<'de> for SeccompProfileVisitor {
                type Value = SeccompProfile;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("the string \"curated\" or a seccomp allow/deny table")
                }

                fn visit_str<E: de::Error>(self, value: &str) -> Result<SeccompProfile, E> {
                    match value {
                        "curated" => Ok(SeccompProfile::Curated),
                        other => Err(E::custom(format!(
                            "unknown seccomp policy {other:?}, expected \"curated\" or a table"
                        ))),
                    }
                }

                fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<SeccompProfile, A::Error> {
                    SeccompLists::deserialize(de::value::MapAccessDeserializer::new(map))
                        .map(SeccompProfile::Lists)
                }
            }

            deserializer.deserialize_any(SeccompProfileVisitor)
        }
    }

    /// The table form of a seccomp policy: bare syscall names in `allow` or
    /// `deny`, and argument-conditioned entries in `allow-rule` or `deny-rule`.
    /// The allow and deny sides are mutually exclusive; a table must set one
    /// side.
    #[derive(Serialize, Deserialize, Default)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
    struct SeccompLists {
        #[serde(skip_serializing_if = "Vec::is_empty")]
        allow: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        allow_rule: Vec<RuleProfile>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        deny: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        deny_rule: Vec<RuleProfile>,
    }

    /// One argument-conditioned syscall entry: a syscall name and the argument
    /// conditions its listed action requires (all of which must hold).
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    struct RuleProfile {
        syscall: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        arg: Vec<ArgProfile>,
    }

    /// One argument condition in a profile: an argument index, the width to
    /// compare, the comparison, and a value. `mask` is set only for the
    /// `masked-eq` comparison. The width is required rather than defaulted,
    /// since neither width is a safe default.
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    struct ArgProfile {
        index: u8,
        len: ArgLenProfile,
        op: ArgOp,
        value: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mask: Option<u64>,
    }

    /// The argument width in a profile.
    #[derive(Serialize, Deserialize, Clone, Copy)]
    #[serde(rename_all = "kebab-case")]
    enum ArgLenProfile {
        Dword,
        Qword,
    }

    /// The comparison operator in a profile. `MaskedEq` takes its mask from the
    /// entry's `mask` field.
    #[derive(Serialize, Deserialize, Clone, Copy)]
    #[serde(rename_all = "kebab-case")]
    enum ArgOp {
        Eq,
        Ne,
        Ge,
        Gt,
        Le,
        Lt,
        MaskedEq,
    }

    /// Serializes a request through its profile form.
    pub(crate) fn serialize<S: serde::Serializer>(
        request: &Request,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        HardeningProfile::from_request(request)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }

    /// Deserializes a request from its profile form.
    pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Request, D::Error> {
        HardeningProfile::deserialize(deserializer)?
            .into_request()
            .map_err(D::Error::custom)
    }

    impl HardeningProfile {
        /// Lowers the profile into the in-memory request, resolving capability
        /// names for the host and rejecting a contradictory capability posture.
        fn into_request(self) -> Result<Request, String> {
            let capabilities = match (self.drop_caps, self.keep_caps) {
                (true, Some(_)) => {
                    return Err(
                        "drop-caps and keep-caps cannot both be set in a hardening profile"
                            .to_string(),
                    );
                }
                (true, None) => CapabilityPosture::Reduce(Vec::new()),
                (false, Some(names)) if names.is_empty() => {
                    return Err("keep-caps is empty; use drop-caps = true to drop every \
                                capability"
                        .to_string());
                }
                (false, Some(names)) => CapabilityPosture::Reduce(
                    names
                        .iter()
                        .map(|name| name.parse::<Capability>().map_err(|err| err.to_string()))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                (false, None) => CapabilityPosture::Keep,
            };

            let seccomp = self.seccomp.map(SeccompProfile::into_policy).transpose()?;

            let landlock = self
                .landlock_fs
                .into_iter()
                .map(|grant| Grant {
                    access: grant.access,
                    path: grant.path,
                })
                .collect();

            let landlock_net = self
                .landlock_net
                .into_iter()
                .map(|grant| NetGrant {
                    access: grant.access,
                    port: grant.port,
                })
                .collect();

            Ok(Request {
                landlock,
                landlock_net,
                seccomp,
                capabilities,
            })
        }

        /// Raises the in-memory request into its profile form, rejecting the
        /// parts a profile cannot represent.
        fn from_request(request: &Request) -> Result<HardeningProfile, String> {
            let (drop_caps, keep_caps) = match &request.capabilities {
                CapabilityPosture::Keep => (false, None),
                CapabilityPosture::Reduce(caps) if caps.is_empty() => (true, None),
                CapabilityPosture::Reduce(caps) => (
                    false,
                    Some(caps.iter().map(|cap| cap.to_string()).collect()),
                ),
            };

            let seccomp = request
                .seccomp
                .as_ref()
                .map(SeccompProfile::from_policy)
                .transpose()?;

            let landlock_fs = request
                .landlock
                .iter()
                .map(|grant| GrantProfile {
                    access: grant.access,
                    path: grant.path.clone(),
                })
                .collect();

            let landlock_net = request
                .landlock_net
                .iter()
                .map(|grant| NetGrantProfile {
                    access: grant.access,
                    port: grant.port,
                })
                .collect();

            Ok(HardeningProfile {
                drop_caps,
                keep_caps,
                seccomp,
                landlock_fs,
                landlock_net,
            })
        }
    }

    impl SeccompProfile {
        /// Resolves the profile's seccomp policy to a [`SeccompPolicy`],
        /// translating syscall names to numbers for the host architecture.
        fn into_policy(self) -> Result<SeccompPolicy, String> {
            let lists = match self {
                SeccompProfile::Curated => return Ok(SeccompPolicy::Curated),
                SeccompProfile::Lists(lists) => lists,
            };
            Ok(SeccompPolicy::Rules(lists.into_rules()?))
        }

        /// Raises a [`SeccompPolicy`] into its profile form, rejecting a
        /// precompiled program and any rules a profile cannot express — a
        /// custom action, or a shape that is neither a plain allow- nor
        /// denylist.
        fn from_policy(policy: &SeccompPolicy) -> Result<SeccompProfile, String> {
            match policy {
                SeccompPolicy::Curated => Ok(SeccompProfile::Curated),
                SeccompPolicy::Rules(rules) => {
                    Ok(SeccompProfile::Lists(SeccompLists::from_rules(rules)?))
                }
                SeccompPolicy::Program(_) => Err(
                    "a precompiled seccomp program cannot be represented in a profile".to_string(),
                ),
            }
        }
    }

    impl SeccompLists {
        /// Lowers the table into a [`SeccompRules`], choosing the allow or deny
        /// side and attaching each entry's argument conditions. A table that
        /// sets both sides, or neither, is rejected.
        fn into_rules(self) -> Result<SeccompRules, String> {
            let allow_side = !self.allow.is_empty() || !self.allow_rule.is_empty();
            let deny_side = !self.deny.is_empty() || !self.deny_rule.is_empty();
            let (mut rules, rule_profiles) = match (allow_side, deny_side) {
                (true, true) => {
                    return Err(
                        "a seccomp profile cannot set both an allow and a deny side".to_string()
                    );
                }
                (false, false) => {
                    return Err("a seccomp table lists no syscalls; set allow, allow-rule, \
                                deny, or deny-rule"
                        .to_string());
                }
                (true, false) => (
                    SeccompRules::allowing(resolve_syscalls(&self.allow)?),
                    self.allow_rule,
                ),
                (false, true) => (
                    SeccompRules::denying(resolve_syscalls(&self.deny)?),
                    self.deny_rule,
                ),
            };
            for profile in rule_profiles {
                let syscall = resolve_syscall(&profile.syscall)?;
                let conditions = profile
                    .arg
                    .iter()
                    .map(ArgProfile::to_arg)
                    .collect::<Result<Vec<_>, _>>()?;
                rules = rules.rule(syscall, conditions);
            }
            Ok(rules)
        }

        /// Raises a [`SeccompRules`] into its table form, partitioning the
        /// listed syscalls into bare names and argument-conditioned entries.
        /// Rejects a policy with a custom action, which a profile cannot name.
        fn from_rules(rules: &SeccompRules) -> Result<SeccompLists, String> {
            let mut bare: Vec<String> = Vec::new();
            let mut rule_profiles: Vec<RuleProfile> = Vec::new();
            for rule in &rules.rules {
                let syscall = name_syscall(rule.syscall)?;
                if rule.conditions.is_empty() {
                    bare.push(syscall);
                } else {
                    rule_profiles.push(RuleProfile {
                        syscall,
                        arg: rule.conditions.iter().map(ArgProfile::from_arg).collect(),
                    });
                }
            }
            match (rules.default_action, rules.listed_action) {
                (SeccompAction::Allow, SeccompAction::Errno(EPERM)) => Ok(SeccompLists {
                    deny: bare,
                    deny_rule: rule_profiles,
                    ..SeccompLists::default()
                }),
                (SeccompAction::Errno(EPERM), SeccompAction::Allow) => Ok(SeccompLists {
                    allow: bare,
                    allow_rule: rule_profiles,
                    ..SeccompLists::default()
                }),
                _ => Err(
                    "a seccomp policy with custom actions cannot be represented in a profile"
                        .to_string(),
                ),
            }
        }
    }

    impl ArgProfile {
        /// Lowers one profile argument condition to a [`SeccompArg`], checking
        /// that `mask` is present exactly when the comparison is `masked-eq`.
        fn to_arg(&self) -> Result<SeccompArg, String> {
            let len = match self.len {
                ArgLenProfile::Dword => SeccompArgLen::Dword,
                ArgLenProfile::Qword => SeccompArgLen::Qword,
            };
            let compare = match self.op {
                ArgOp::MaskedEq => {
                    let mask = self
                        .mask
                        .ok_or_else(|| "op = \"masked-eq\" requires a mask".to_string())?;
                    SeccompCompare::MaskedEq(mask)
                }
                other => {
                    if self.mask.is_some() {
                        return Err("mask is only valid with op = \"masked-eq\"".to_string());
                    }
                    match other {
                        ArgOp::Eq => SeccompCompare::Eq,
                        ArgOp::Ne => SeccompCompare::Ne,
                        ArgOp::Ge => SeccompCompare::Ge,
                        ArgOp::Gt => SeccompCompare::Gt,
                        ArgOp::Le => SeccompCompare::Le,
                        ArgOp::Lt => SeccompCompare::Lt,
                        ArgOp::MaskedEq => unreachable!("masked-eq handled above"),
                    }
                }
            };
            Ok(SeccompArg::new(self.index, len, compare, self.value))
        }

        /// Raises one [`SeccompArg`] into its profile form.
        fn from_arg(arg: &SeccompArg) -> ArgProfile {
            let len = match arg.len {
                SeccompArgLen::Dword => ArgLenProfile::Dword,
                SeccompArgLen::Qword => ArgLenProfile::Qword,
            };
            let (op, mask) = match arg.compare {
                SeccompCompare::Eq => (ArgOp::Eq, None),
                SeccompCompare::Ne => (ArgOp::Ne, None),
                SeccompCompare::Ge => (ArgOp::Ge, None),
                SeccompCompare::Gt => (ArgOp::Gt, None),
                SeccompCompare::Le => (ArgOp::Le, None),
                SeccompCompare::Lt => (ArgOp::Lt, None),
                SeccompCompare::MaskedEq(mask) => (ArgOp::MaskedEq, Some(mask)),
            };
            ArgProfile {
                index: arg.index,
                len,
                op,
                value: arg.value,
                mask,
            }
        }
    }

    /// Resolves syscall names to their numbers for the host architecture.
    fn resolve_syscalls(names: &[String]) -> Result<Vec<i64>, String> {
        names.iter().map(|name| resolve_syscall(name)).collect()
    }

    /// Resolves one syscall name to its number for the host architecture.
    fn resolve_syscall(name: &str) -> Result<i64, String> {
        name.parse::<Sysno>()
            .map(|sysno| i64::from(sysno.id()))
            .map_err(|_| format!("unknown syscall {name:?}"))
    }

    /// Names one syscall number for the host architecture, for serialization.
    fn name_syscall(number: i64) -> Result<String, String> {
        usize::try_from(number)
            .ok()
            .and_then(Sysno::new)
            .map(|sysno| sysno.name().to_string())
            .ok_or_else(|| format!("syscall number {number} has no name on this architecture"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_access_composes_and_contains() {
        let rx = FsAccess::READ | FsAccess::EXECUTE;
        assert!(rx.contains(FsAccess::READ));
        assert!(rx.contains(FsAccess::EXECUTE));
        assert!(!rx.contains(FsAccess::WRITE));
    }

    #[test]
    fn fs_access_bit_operations() {
        assert!(FsAccess::empty().is_empty());
        assert_eq!(FsAccess::default(), FsAccess::empty());
        assert_eq!(
            FsAccess::all(),
            FsAccess::READ | FsAccess::WRITE | FsAccess::EXECUTE
        );

        let mut set = FsAccess::READ;
        set |= FsAccess::WRITE;
        assert!(set.contains(FsAccess::WRITE));

        // Masking keeps only the shared rights.
        assert_eq!(set & FsAccess::EXECUTE, FsAccess::empty());
        assert_eq!(set & FsAccess::READ, FsAccess::READ);
        set &= FsAccess::READ;
        assert_eq!(set, FsAccess::READ);

        // Complement stays within the modeled rights.
        assert_eq!(!FsAccess::WRITE, FsAccess::READ | FsAccess::EXECUTE);
        assert_eq!(!FsAccess::all(), FsAccess::empty());
        assert_eq!(!FsAccess::empty(), FsAccess::all());
    }

    #[test]
    fn read_lowers_to_file_and_dir_reads() {
        let bits = FsAccess::READ.to_landlock();
        // Read maps to the file and directory read rights, plus device ioctls
        // (see `a_read_or_write_grant_allows_device_ioctls`).
        assert_eq!(
            bits,
            fs_access::READ_FILE | fs_access::READ_DIR | fs_access::IOCTL_DEV
        );
    }

    #[test]
    fn fs_access_displays_and_parses_in_rwx_order() {
        assert_eq!(FsAccess::empty().to_string(), "");
        assert_eq!(FsAccess::READ.to_string(), "r");
        assert_eq!((FsAccess::READ | FsAccess::EXECUTE).to_string(), "rx");
        assert_eq!(FsAccess::all().to_string(), "rwx");
        // Display and FromStr round-trip across every subset.
        for access in [
            FsAccess::empty(),
            FsAccess::READ,
            FsAccess::WRITE,
            FsAccess::EXECUTE,
            FsAccess::READ | FsAccess::WRITE,
            FsAccess::READ | FsAccess::EXECUTE,
            FsAccess::WRITE | FsAccess::EXECUTE,
            FsAccess::all(),
        ] {
            assert_eq!(access.to_string().parse::<FsAccess>(), Ok(access));
        }
    }

    #[test]
    fn fs_access_parse_is_order_and_case_insensitive() {
        let rwx = FsAccess::all();
        assert_eq!("xwr".parse::<FsAccess>(), Ok(rwx));
        assert_eq!("RWX".parse::<FsAccess>(), Ok(rwx));
    }

    #[test]
    fn fs_access_parse_rejects_unknown_and_repeated_letters() {
        let err = "rq".parse::<FsAccess>().unwrap_err();
        assert_eq!(err.text(), "rq");
        assert!(err.to_string().contains("r, w, and x"));
        assert!("rr".parse::<FsAccess>().is_err());
    }

    #[test]
    fn net_access_composes_and_contains() {
        let bc = NetAccess::BIND | NetAccess::CONNECT;
        assert!(bc.contains(NetAccess::BIND));
        assert!(bc.contains(NetAccess::CONNECT));
        assert_eq!(NetAccess::all(), bc);

        let mut set = NetAccess::BIND;
        set |= NetAccess::CONNECT;
        assert!(set.contains(NetAccess::CONNECT));

        // Masking keeps only the shared rights; complement stays in the set.
        assert_eq!(set & NetAccess::BIND, NetAccess::BIND);
        set &= NetAccess::BIND;
        assert_eq!(set, NetAccess::BIND);
        assert_eq!(!NetAccess::BIND, NetAccess::CONNECT);
        assert_eq!(!NetAccess::all(), NetAccess::empty());
        assert_eq!(!NetAccess::empty(), NetAccess::all());
        assert!(NetAccess::empty().is_empty());
        assert_eq!(NetAccess::default(), NetAccess::empty());
    }

    #[test]
    fn net_access_lowers_to_kernel_rights() {
        assert_eq!(NetAccess::BIND.to_landlock(), net_access::BIND_TCP);
        assert_eq!(NetAccess::CONNECT.to_landlock(), net_access::CONNECT_TCP);
        assert_eq!(NetAccess::all().to_landlock(), net_access::ALL);
    }

    #[test]
    fn net_access_displays_and_parses_in_bc_order() {
        assert_eq!(NetAccess::empty().to_string(), "");
        assert_eq!(NetAccess::BIND.to_string(), "b");
        assert_eq!(NetAccess::CONNECT.to_string(), "c");
        assert_eq!(NetAccess::all().to_string(), "bc");
        // Display and FromStr round-trip across every subset.
        for access in [
            NetAccess::empty(),
            NetAccess::BIND,
            NetAccess::CONNECT,
            NetAccess::all(),
        ] {
            assert_eq!(access.to_string().parse::<NetAccess>(), Ok(access));
        }
        // Order- and case-insensitive, like FsAccess.
        assert_eq!("cb".parse::<NetAccess>(), Ok(NetAccess::all()));
        assert_eq!("BC".parse::<NetAccess>(), Ok(NetAccess::all()));
    }

    #[test]
    fn net_access_parse_rejects_unknown_and_repeated_letters() {
        let err = "bz".parse::<NetAccess>().unwrap_err();
        assert_eq!(err.text(), "bz");
        assert!(err.to_string().contains("b and c"));
        assert!("bb".parse::<NetAccess>().is_err());
    }

    #[test]
    fn net_abi_mask_narrows_by_version() {
        // Network rights arrive together in ABI 4; nothing below it.
        assert_eq!(net_access_for_abi(1), 0);
        assert_eq!(net_access_for_abi(3), 0);
        assert_eq!(net_access_for_abi(4), net_access::ALL);
        assert_eq!(net_access_for_abi(5), net_access::ALL);
    }

    #[test]
    fn net_grant_masked_away_reflects_the_abi() {
        // A network grant is masked away below ABI 4, but enforceable at ABI 4
        // and above.
        assert!(net_grant_masked_away(net_access::ALL, 3));
        assert!(!net_grant_masked_away(net_access::ALL, 4));
        // No network grant requested (zero mask) drops nothing.
        assert!(!net_grant_masked_away(0, 3));
        // The judgement is per access kind: a surviving filesystem grant at the
        // same ABI must not mask a dropped network grant, or a configured
        // network boundary would silently vanish (H2).
        assert!(net_grant_masked_away(net_access::ALL, 1));
    }

    #[test]
    fn fs_grant_masked_away_reflects_the_abi() {
        // A filesystem grant keeps its ABI-1 base rights, so it is never masked
        // away on any Landlock kernel.
        assert!(!fs_grant_masked_away(fs_access::ALL, 1));
        // No filesystem grant requested (zero mask) drops nothing.
        assert!(!fs_grant_masked_away(0, 1));
    }

    #[test]
    fn net_grants_lower_to_rules_and_the_handled_set() {
        let mut request = Request::default();
        request.grant_net(NetAccess::BIND, 8080);
        request.grant_net(NetAccess::CONNECT, 443);
        let plan = request.lower().unwrap();
        assert_eq!(plan.landlock_net.len(), 2);
        assert_eq!(plan.landlock_net[0].port, 8080);
        assert_eq!(plan.landlock_net[0].access, net_access::BIND_TCP);
        assert_eq!(plan.landlock_net[1].port, 443);
        assert_eq!(plan.landlock_net[1].access, net_access::CONNECT_TCP);
        // Any network grant enrolls the full modeled network set, so an
        // ungranted right is denied rather than left unrestricted.
        assert_eq!(plan.landlock_net_handled, net_access::ALL);
        // Filesystem rules and their handled set stay empty.
        assert!(plan.landlock.is_empty());
        assert_eq!(plan.landlock_handled, 0);
    }

    #[test]
    fn a_net_only_request_is_restricting() {
        let mut request = Request::default();
        request.grant_net(NetAccess::BIND, 0);
        assert!(!request.is_unrestricted());
    }

    #[test]
    fn abi_mask_narrows_by_version() {
        // v1 excludes REFER, TRUNCATE, and IOCTL_DEV.
        let v1 = fs_access_for_abi(1);
        assert_eq!(v1 & fs_access::REFER, 0);
        assert_eq!(v1 & fs_access::TRUNCATE, 0);
        assert_eq!(v1 & fs_access::IOCTL_DEV, 0);
        // v3 gains REFER and TRUNCATE but not IOCTL_DEV.
        let v3 = fs_access_for_abi(3);
        assert_ne!(v3 & fs_access::REFER, 0);
        assert_ne!(v3 & fs_access::TRUNCATE, 0);
        assert_eq!(v3 & fs_access::IOCTL_DEV, 0);
        // v5 is the full set.
        assert_eq!(fs_access_for_abi(5), fs_access::ALL);
    }

    #[test]
    fn the_curated_denylist_covers_each_category_it_claims() {
        use syscalls::Sysno;

        // The roster is not exhaustive, but it grows only additively, so one
        // representative of each category it does cover must stay in it.
        let list = curated_denylist();
        for sysno in [
            // Filesystem topology, including the new-mount API in full and the
            // file-handle pair that reaches an inode without a path.
            Sysno::mount,
            Sysno::pivot_root,
            Sysno::open_tree,
            Sysno::fsopen,
            Sysno::fsconfig,
            Sysno::fsmount,
            Sysno::fspick,
            Sysno::move_mount,
            Sysno::name_to_handle_at,
            Sysno::open_by_handle_at,
            // Kernel modules, the keyring, and the administrative surfaces.
            Sysno::init_module,
            Sysno::keyctl,
            Sysno::setns,
            // Tracing, cross-process memory, and the exploit primitives beside
            // them.
            Sysno::ptrace,
            Sysno::process_vm_readv,
            Sysno::perf_event_open,
            Sysno::bpf,
            Sysno::userfaultfd,
            // Execution domain, and the asynchronous submission ring a filter
            // cannot see through.
            Sysno::personality,
            Sysno::io_uring_setup,
            // The clock.
            Sysno::clock_settime,
        ] {
            assert!(
                list.contains(&(sysno.id() as i64)),
                "{sysno} left the curated denylist",
            );
        }

        #[cfg(target_arch = "x86_64")]
        assert!(list.contains(&(Sysno::modify_ldt.id() as i64)));
    }

    #[test]
    fn curated_profile_compiles() {
        let program = compile_seccomp(&SeccompPolicy::Curated).unwrap();
        assert!(!program.is_empty());
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn a_denylist_is_prefixed_with_the_x32_guard_on_x86_64() {
        // A denylist (permissive default) is bypassable through the x32 ABI, so
        // the compiled program must begin with the guard denying that range.
        let program = compile_seccomp(&SeccompPolicy::Curated).unwrap();
        let guard = x32_deny_prologue(SeccompAction::Errno(EPERM));
        assert!(program.len() > guard.len());
        assert_eq!(&program[..guard.len()], &guard[..]);
    }

    #[test]
    fn the_x32_guard_emits_the_expected_instructions() {
        // Five hand-emitted instructions with hand-computed jump offsets: the
        // one raw-BPF fragment in the crate, and the one place a wrong constant
        // would silently disable a guard rather than fail. Assert them exactly.
        //
        // Both false branches must land on instruction 5, the first of
        // seccompiler's own program: from [1] that is 1 + 1 + jf(3) = 5, and
        // from [3] it is 3 + 1 + jf(1) = 5.
        let guard = x32_deny_prologue(SeccompAction::Errno(EPERM));
        assert_eq!(
            guard,
            [
                // [0] A = seccomp_data.arch
                SockFilter {
                    code: 0x20,
                    jt: 0,
                    jf: 0,
                    k: 4,
                },
                // [1] if A != AUDIT_ARCH_X86_64: jump past the guard
                SockFilter {
                    code: 0x15,
                    jt: 0,
                    jf: 3,
                    k: 0xC000_003E,
                },
                // [2] A = seccomp_data.nr
                SockFilter {
                    code: 0x20,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                // [3] if A & __X32_SYSCALL_BIT == 0: jump past the guard
                SockFilter {
                    code: 0x45,
                    jt: 0,
                    jf: 1,
                    k: 0x4000_0000,
                },
                // [4] return EPERM
                SockFilter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: 0x0005_0000 | u32::from(EPERM),
                },
            ],
        );

        // The returned action is the caller's, not a constant.
        assert_eq!(
            x32_deny_prologue(SeccompAction::KillProcess)[4].k,
            0x8000_0000,
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn an_allowlist_has_no_x32_guard() {
        // An allowlist's denying default already refuses an unmatched x32
        // number, so no guard is prepended.
        let program = compile_seccomp(&SeccompPolicy::Rules(SeccompRules::allowing([
            libc::SYS_read,
        ])))
        .unwrap();
        assert!(
            !program
                .iter()
                .any(|insn| insn.code == bpf::JMP_JSET_K && insn.k == X32_SYSCALL_BIT)
        );
    }

    #[test]
    fn seccomp_policies_report_whether_they_restrict() {
        assert!(SeccompPolicy::Curated.restricts());
        assert!(SeccompPolicy::Rules(SeccompRules::denying([libc::SYS_ptrace])).restricts());
        // An allowlist denies every unlisted syscall, so it restricts even when
        // it lists nothing.
        assert!(SeccompPolicy::Rules(SeccompRules::allowing([])).restricts());
        // An empty denylist denies nothing.
        assert!(!SeccompPolicy::Rules(SeccompRules::denying([])).restricts());
        // A denylist whose listed action still allows denies nothing.
        assert!(
            !SeccompPolicy::Rules(
                SeccompRules::denying([libc::SYS_ptrace]).listed_action(SeccompAction::Allow)
            )
            .restricts()
        );
    }

    #[test]
    fn a_no_op_seccomp_policy_does_not_save_a_restriction_from_the_empty_guard() {
        // A filter that denies nothing leaves a restriction unconfined, so it
        // must not count as a restriction.
        let mut empty = Request::default();
        empty.set_seccomp(SeccompPolicy::Rules(SeccompRules::denying([])));
        assert!(empty.is_unrestricted());
        // The curated policy, which does deny, counts.
        let mut curated = Request::default();
        curated.set_seccomp(SeccompPolicy::Curated);
        assert!(!curated.is_unrestricted());
    }

    #[test]
    fn a_read_or_write_grant_allows_device_ioctls() {
        // IOCTL_DEV is in the handled set, so it must be granted with read or
        // write access or a granted device path would deny all driver ioctls.
        assert_ne!(FsAccess::READ.to_landlock() & fs_access::IOCTL_DEV, 0);
        assert_ne!(FsAccess::WRITE.to_landlock() & fs_access::IOCTL_DEV, 0);
        // An execute-only grant does not, so device ioctls stay denied there.
        assert_eq!(FsAccess::EXECUTE.to_landlock() & fs_access::IOCTL_DEV, 0);
    }

    #[test]
    fn argument_conditioned_rules_compile() {
        // An allowlist that permits ioctl only for a specific request, plus a
        // masked-eq condition, compiles to a non-empty program.
        let rules = SeccompRules::allowing([libc::SYS_read, libc::SYS_write])
            .rule(libc::SYS_ioctl, [SeccompArg::eq_dword(1, 0x5413)])
            .rule(
                libc::SYS_clone,
                [SeccompArg::masked_eq_qword(0, 0x1000_0000, 0)],
            );
        let program = compile_seccomp(&SeccompPolicy::Rules(rules)).unwrap();
        assert!(!program.is_empty());
    }

    #[test]
    fn an_unconditional_listing_dominates_a_condition() {
        // A syscall listed both unconditionally and with a condition matches
        // unconditionally: the compiled program equals the one from the plain
        // listing alone, and the extra condition changes nothing.
        let plain = compile_seccomp(&SeccompPolicy::Rules(SeccompRules::allowing([
            libc::SYS_ioctl,
        ])))
        .unwrap();
        let with_redundant_condition = compile_seccomp(&SeccompPolicy::Rules(
            SeccompRules::allowing([libc::SYS_ioctl])
                .rule(libc::SYS_ioctl, [SeccompArg::eq_dword(1, 0x5413)]),
        ))
        .unwrap();
        assert_eq!(plain, with_redundant_condition);
    }

    #[test]
    fn an_out_of_range_argument_index_is_rejected() {
        // A syscall has six argument registers (indices 0 through 5); an index
        // past them is rejected when the condition is lowered.
        let rules = SeccompRules::allowing([libc::SYS_read])
            .rule(libc::SYS_ioctl, [SeccompArg::eq_dword(6, 0)]);
        assert!(matches!(
            compile_seccomp(&SeccompPolicy::Rules(rules)),
            Err(ConfigError::SeccompInvalid { .. })
        ));
    }

    #[test]
    fn an_over_long_program_is_rejected() {
        // A precompiled escape-hatch program longer than the kernel ceiling is
        // rejected at build time, so its length cannot wrap when narrowed to a
        // u16 for the kernel's sock_fprog.
        let instruction = SockFilter {
            code: 0,
            jt: 0,
            jf: 0,
            k: 0,
        };
        let program = vec![instruction; BPF_MAXINSNS + 1];
        let mut request = Request::default();
        request.set_seccomp(SeccompPolicy::Program(program));
        assert!(matches!(
            request.lower(),
            Err(ConfigError::SeccompProgramTooLong {
                len,
                max: BPF_MAXINSNS,
            }) if len == BPF_MAXINSNS + 1
        ));
    }

    #[test]
    fn a_maximal_program_is_accepted() {
        // Exactly BPF_MAXINSNS instructions is at the boundary and allowed.
        let instruction = SockFilter {
            code: 0,
            jt: 0,
            jf: 0,
            k: 0,
        };
        let program = vec![instruction; BPF_MAXINSNS];
        assert_eq!(
            compile_seccomp(&SeccompPolicy::Program(program))
                .unwrap()
                .len(),
            BPF_MAXINSNS,
        );
    }

    #[test]
    fn capability_names_round_trip() {
        for &cap in Capability::ALL {
            // Display produces the canonical name, which parses back.
            let name = cap.to_string();
            assert_eq!(name.parse::<Capability>(), Ok(cap));
            // The snake form, the cap- prefix, and upper case all parse too.
            let snake = name.replace('-', "_");
            assert_eq!(snake.parse::<Capability>(), Ok(cap));
            assert_eq!(format!("CAP_{snake}").parse::<Capability>(), Ok(cap));
            assert_eq!(name.to_uppercase().parse::<Capability>(), Ok(cap));
        }
    }

    #[test]
    fn unknown_capability_name_is_rejected() {
        let err = "not-a-cap".parse::<Capability>().unwrap_err();
        assert_eq!(err.name(), "not-a-cap");
        assert!(err.to_string().contains("not-a-cap"));
    }

    #[test]
    fn capability_all_has_no_duplicates() {
        let mut names: Vec<&str> = Capability::ALL.iter().map(|cap| cap.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "capability names must be unique");
    }

    #[test]
    fn drop_all_lowers_to_empty_keep_set() {
        let mut request = Request::default();
        request.drop_all_capabilities();
        let plan = request.lower().unwrap();
        assert_eq!(plan.keep_caps, Some(0));
    }

    #[test]
    fn keep_list_lowers_to_named_bits() {
        let mut request = Request::default();
        request.keep_capabilities([Capability::NetBindService, Capability::Chown]);
        let plan = request.lower().unwrap();
        let expected = (CapabilitySet::NET_BIND_SERVICE | CapabilitySet::CHOWN).bits();
        assert_eq!(plan.keep_caps, Some(expected));
    }

    #[test]
    fn no_hardening_lowers_to_an_empty_plan() {
        let plan = Request::default().lower().unwrap();
        assert!(plan.landlock.is_empty());
        assert_eq!(plan.landlock_handled, 0);
        assert!(plan.landlock_net.is_empty());
        assert_eq!(plan.landlock_net_handled, 0);
        assert!(plan.seccomp.is_none());
        assert!(plan.keep_caps.is_none());
    }
}
