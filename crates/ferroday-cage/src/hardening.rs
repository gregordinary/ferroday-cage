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
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rustix::thread::CapabilitySet;

use crate::error::ConfigError;
use crate::mechanism::seccomp::{
    AUDIT_ARCH_AARCH64, AUDIT_ARCH_RISCV64, AUDIT_ARCH_X86_64, ENOSYS, X32_SYSCALL_BIT, bpf,
};
use crate::mechanism::{HardeningPlan, LandlockNetRule, LandlockRule, SockFilter};
use crate::roster::roster_enum;

/// Declares the text side of a letter-set access type: its
/// [`Display`](fmt::Display), its [`FromStr`], the parse error it produces, and
/// the serde adapters that go through both.
///
/// [`FsAccess`] and [`NetAccess`] are the same type twice — a bitflag newtype
/// whose textual form is an unordered set of single letters — differing only in
/// the letters, the flags, and their names. Everything that follows from the
/// letter table is generated from the table.
///
/// Letters are declared in the order [`Display`](fmt::Display) writes them, and
/// parsing accepts them in any order and any case. A letter outside the table,
/// or a letter given twice, is a parse error; the empty string is the empty
/// set.
macro_rules! letter_set_text {
    (
        $set:ident, $expected:literal,
        $( $letter:literal => $flag:ident, )+
        $(#[$error_meta:meta])*
        $error:ident
    ) => {
        impl fmt::Display for $set {
            #[doc = concat!("Writes the rights as the letters ", $expected, ", in that order; the empty set writes nothing.")]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                $(
                    if self.contains($set::$flag) {
                        write!(f, "{}", $letter)?;
                    }
                )+
                Ok(())
            }
        }

        impl FromStr for $set {
            type Err = $error;

            #[doc = concat!("Parses an access set from the letters ", $expected, ", in any order and any case. A letter outside that set, or a letter given twice, is an error; the empty string is the empty set.")]
            fn from_str(s: &str) -> Result<$set, $error> {
                let mut access = $set::empty();
                for ch in s.chars() {
                    let right = match ch.to_ascii_lowercase() {
                        $( $letter => $set::$flag, )+
                        _ => return Err($error { text: s.to_string() }),
                    };
                    if access.contains(right) {
                        return Err($error { text: s.to_string() });
                    }
                    access |= right;
                }
                Ok(access)
            }
        }

        $(#[$error_meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $error {
            text: String,
        }

        impl $error {
            /// The access string that failed to parse, as it was given.
            ///
            /// Named `text` on every parse error in this crate, so a caller
            /// moving between them does not have to check.
            pub fn text(&self) -> &str {
                &self.text
            }
        }

        impl fmt::Display for $error {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    concat!("invalid access set {:?}: expected some combination of the letters ", $expected),
                    self.text,
                )
            }
        }

        impl std::error::Error for $error {}

        #[cfg(feature = "serde")]
        impl serde::Serialize for $set {
            /// Serializes as the letter string, through [`Display`](fmt::Display).
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $set {
            /// Deserializes from the letter string, through [`FromStr`].
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<$set, D::Error> {
                let text = <String as serde::Deserialize>::deserialize(deserializer)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

/// Declares the bitwise operators of a bitflag newtype over an integer.
///
/// `!` complements within `MASK`, so a bit outside the modeled set is never
/// produced.
macro_rules! bitflag_ops {
    ($set:ident) => {
        impl BitOr for $set {
            type Output = $set;

            fn bitor(self, rhs: $set) -> $set {
                $set(self.0 | rhs.0)
            }
        }

        impl BitOrAssign for $set {
            fn bitor_assign(&mut self, rhs: $set) {
                self.0 |= rhs.0;
            }
        }

        impl BitAnd for $set {
            type Output = $set;

            fn bitand(self, rhs: $set) -> $set {
                $set(self.0 & rhs.0)
            }
        }

        impl BitAndAssign for $set {
            fn bitand_assign(&mut self, rhs: $set) {
                self.0 &= rhs.0;
            }
        }

        impl Not for $set {
            type Output = $set;

            /// The modeled rights this set does not hold; bits outside the
            /// modeled set are never produced.
            fn not(self) -> $set {
                $set(!self.0 & $set::MASK)
            }
        }
    };
}

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

    /// The rights that act on a file itself rather than on the entries of a
    /// directory: the kernel's `ACCESS_FILE`.
    ///
    /// A rule whose target is not a directory may allow these and nothing else.
    /// The kernel refuses the rule with `EINVAL` otherwise, so the command stage
    /// narrows a grant on a file or a device node to this set before adding it.
    pub(crate) const FILE: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;
}

/// Kernel `LANDLOCK_SCOPE_*` flags: the IPC reaches a ruleset can confine to
/// its own domain. Named here beside the access rights so the ABI contract
/// lives in one place; re-verify against the kernel uapi when the Landlock ABI
/// grows.
pub(crate) mod scope {
    pub(crate) const ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    pub(crate) const SIGNAL: u64 = 1 << 1;
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

/// Masks a scope set down to the scopes a Landlock ABI version defines, so a
/// ruleset built for a newer ABI still enforces on an older kernel, narrowing
/// what is enforced and never widening it.
///
/// Both scopes arrive together in ABI 6 (Linux 6.12). Below it the kernel
/// defines no scope, and a ruleset carrying one is refused outright, so the
/// command stage drops them there: the same best-effort downgrade
/// [`fs_access_for_abi`] performs for a filesystem right. A scope that is the
/// only bound on its reach never gets that far, since
/// [`ensure_scopes_enforceable`] refuses it at build.
pub(crate) fn scope_for_abi(abi: i32) -> u64 {
    if abi >= 6 {
        scope::ABSTRACT_UNIX_SOCKET | scope::SIGNAL
    } else {
        0
    }
}

/// Refuses the first scope in `scoped` that a kernel at `abi` cannot enforce,
/// where `abi` is `None` when the kernel offers no Landlock LSM at all.
///
/// For the scopes nothing but Landlock bounds: [`LandlockScope::Signal`]
/// without a PID namespace, [`LandlockScope::AbstractUnixSocket`] without a
/// network namespace of the sandbox's own, and every scope a restriction names.
/// Dropping one of those would leave the reach it names wide open, so the
/// build fails with [`ConfigError::LandlockScopeUnenforceable`] instead. The
/// callers pick which scopes they pass; a scope a namespace also bounds, or a
/// restriction's default, is masked by [`scope_for_abi`] rather than refused.
pub(crate) fn ensure_scopes_enforceable(scoped: u64, abi: Option<i32>) -> Result<(), ConfigError> {
    let enforced = abi.map_or(0, scope_for_abi);
    match LandlockScope::ALL
        .iter()
        .find(|scope| scoped & !enforced & scope.to_landlock() != 0)
    {
        Some(scope) => Err(ConfigError::LandlockScopeUnenforceable {
            scope: scope.as_str(),
            abi,
        }),
        None => Ok(()),
    }
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
/// fallback) and `HardeningPlan::ensure_sandbox_enforceable` (a host-network
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

bitflag_ops!(FsAccess);

letter_set_text! {
    FsAccess, "r, w, and x",
    'r' => READ,
    'w' => WRITE,
    'x' => EXECUTE,
    /// The error from parsing an [`FsAccess`] from an invalid access string.
    ///
    /// Produced when the string holds a character other than `r`, `w`, or `x`,
    /// or repeats one of them.
    ParseFsAccessError
}

/// A set of Landlock network access rights, granted on a TCP port by
/// [`CageBuilder::landlock_net`].
///
/// Landlock's network rights cover TCP alone: these govern TCP bind and
/// connect and nothing else. UDP, raw sockets, and other socket families are
/// outside a network grant's reach, and so is `AF_UNIX`. A connection to an
/// abstract socket outside the sandbox is confined by
/// [`LandlockScope::AbstractUnixSocket`] instead, or by a sandbox's network
/// namespace.
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

bitflag_ops!(NetAccess);

letter_set_text! {
    NetAccess, "b and c",
    'b' => BIND,
    'c' => CONNECT,
    /// The error from parsing a [`NetAccess`] from an invalid access string.
    ///
    /// Produced when the string holds a character other than `b` or `c`, or
    /// repeats one of them.
    ParseNetAccessError
}

roster_enum! {
    /// A Landlock scope, for [`CageBuilder::landlock_scope`]: a reach the
    /// kernel confines to the command's own Landlock domain.
    ///
    /// A scope is not a grant. It names an interaction with processes outside
    /// the domain and denies it, while the same interaction between the
    /// command and the processes it starts stays open. A scope needs Landlock
    /// ABI 6 (Linux 6.12). On an older kernel it narrows away best-effort where
    /// a namespace also bounds its reach, and is refused at build where nothing
    /// else does; [`CageBuilder::landlock_scope`] says which is which.
    ///
    /// Each scope has a canonical kebab-case name (`abstract-unix-socket`),
    /// printed by [`Display`](std::fmt::Display) and parsed by
    /// [`FromStr`](std::str::FromStr), which also accepts the snake-case form in
    /// any letter case. [`ALL`](Self::ALL) lists every variant.
    ///
    /// [`CageBuilder::landlock_scope`]: crate::CageBuilder::landlock_scope
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum LandlockScope {
        /// The kernel `LANDLOCK_SCOPE_*` flag this scope sets.
        pub(crate) fn to_landlock -> u64;
        /// The canonical kebab-case name.
        fn as_str;

        /// `LANDLOCK_SCOPE_SIGNAL`: the command cannot signal a process outside
        /// its domain.
        ///
        /// Without it, a command that can see the calling user's other
        /// processes can signal every one of them. A sandbox sees them under
        /// [`pid_namespace(false)`](crate::CageBuilder::pid_namespace), and a
        /// restriction always does.
        Signal = scope::SIGNAL => "signal",
        /// `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`: the command cannot connect to
        /// an abstract `AF_UNIX` socket that a process outside its domain
        /// created.
        ///
        /// Abstract sockets belong to a network namespace rather than to the
        /// filesystem, so a Landlock filesystem grant does not reach them, and
        /// seccomp cannot read the address a connect names. A sandbox reaches the
        /// host's under [`Network::Host`](crate::Network::Host), and a
        /// restriction always does: the session bus and the X server listen on
        /// them.
        AbstractUnixSocket = scope::ABSTRACT_UNIX_SOCKET => "abstract-unix-socket",
    }
}

impl LandlockScope {
    /// The kernel flags of a set of scopes, joined.
    pub(crate) fn bits_of<I: IntoIterator<Item = LandlockScope>>(scopes: I) -> u64 {
        scopes
            .into_iter()
            .fold(0, |bits, scope| bits | scope.to_landlock())
    }
}

impl fmt::Display for LandlockScope {
    /// Writes the canonical kebab-case name, such as `abstract-unix-socket`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LandlockScope {
    type Err = ParseLandlockScopeError;

    /// Parses a scope name, accepting the kebab or snake form in any letter
    /// case.
    fn from_str(s: &str) -> Result<LandlockScope, ParseLandlockScopeError> {
        let normalized = s.to_ascii_lowercase().replace('_', "-");
        LandlockScope::ALL
            .iter()
            .copied()
            .find(|scope| scope.as_str() == normalized)
            .ok_or_else(|| ParseLandlockScopeError {
                text: s.to_string(),
            })
    }
}

/// The error from parsing an unrecognized [`LandlockScope`] name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLandlockScopeError {
    text: String,
}

impl ParseLandlockScopeError {
    /// The unrecognized name, as it was given.
    ///
    /// Named `text` on every parse error in this crate, so a caller moving
    /// between them does not have to check.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ParseLandlockScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown Landlock scope {:?}, expected one of ",
            self.text
        )?;
        for (index, scope) in LandlockScope::ALL.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            f.write_str(scope.as_str())?;
        }
        Ok(())
    }
}

impl std::error::Error for ParseLandlockScopeError {}

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
    ///
    /// The number is one through 4095, the range the C library reads a failed
    /// syscall's result as. Zero would report a success the syscall never
    /// performed, and a larger number would read as the value it returned, so
    /// the build refuses either with
    /// [`ConfigError::SeccompInvalid`](crate::ConfigError::SeccompInvalid).
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

/// The largest errno a syscall can fail with. The C library reads a raw result
/// in `-4095..=-1` as a failure with that errno, and any other as a value.
const MAX_ERRNO: u16 = 4095;

/// Whether a filter answering a syscall with `errno` makes it fail: one through
/// [`MAX_ERRNO`].
///
/// Zero answers a call with a success it never performed, so `getpid` reports
/// pid 0 and a `clone3` caller takes itself for the new child process. A larger
/// number reads as the value the syscall returned. [`SeccompRules::errno`]
/// reads a spelling through this, and the build holds every errno a policy
/// answers with to it.
fn is_failure_errno(errno: u16) -> bool {
    (1..=MAX_ERRNO).contains(&errno)
}

/// Refuses an errno a policy answers with that no failed syscall reports; see
/// [`is_failure_errno`]. `answering` is the clause naming what answers with it,
/// a syscall or one of a rule set's two actions, up to the errno itself.
fn check_errno(answering: &str, errno: u16) -> Result<(), ConfigError> {
    if is_failure_errno(errno) {
        return Ok(());
    }
    let read_as = if errno == 0 {
        "a success the syscall never performed"
    } else {
        "the value the syscall returned"
    };
    Err(ConfigError::SeccompInvalid {
        reason: format!(
            "{answering} errno {errno}, which the C library reads as {read_as}; a filter \
             answers with an errno from 1 through {MAX_ERRNO}"
        ),
    })
}

/// The errno a name such as `ENOSYS` spells, in any letter case, or `None` for
/// a name no errno has.
///
/// Through the `syscalls` crate's errno table, the source the syscall names
/// come from. Its numbers are the generic ones every architecture with seccomp
/// support here shares.
fn errno_named(name: &str) -> Option<u16> {
    let wanted = name.to_ascii_uppercase();
    (1..=i32::from(MAX_ERRNO))
        .map(syscalls::Errno::new)
        .find(|errno| errno.name() == Some(wanted.as_str()))
        .and_then(|errno| u16::try_from(errno.into_raw()).ok())
}

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
    ///
    /// The reference value, and a [`MaskedEq`](SeccompCompare::MaskedEq) mask,
    /// must fit in 32 bits as well: a wider one is refused at build with
    /// [`ConfigError::SeccompInvalid`](crate::ConfigError::SeccompInvalid),
    /// since its high bits could take no part in the comparison. A negative
    /// `int` is written as its 32-bit two's complement, `(-1i32) as u32`.
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
    ///
    /// A filter sees a syscall's registers and nothing they point at. `clone3`
    /// takes its flags in a structure in memory, so a condition on `clone`'s
    /// flags says nothing about it, and a policy that gates on them has to
    /// deny `clone3` outright. Denied with `EPERM`, `clone3` breaks thread
    /// creation in glibc 2.34 and later. Answered `ENOSYS` instead, through
    /// [`SeccompRules::errno_for`], the C library falls back to `clone`, which
    /// the condition does see.
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
    /// rejected argument index, and a `Dword` value or mask wider than the 32
    /// bits it compares, to a [`ConfigError`].
    fn to_seccompiler(self) -> Result<seccompiler::SeccompCondition, ConfigError> {
        if matches!(self.len, SeccompArgLen::Dword) {
            let mask = match self.compare {
                SeccompCompare::MaskedEq(mask) => mask,
                _ => 0,
            };
            // The backend compares the low half and drops the rest, so a wider
            // operand would be silently truncated: `masked_eq_dword(0, 1 << 32,
            // 0)` would mask with zero and match every call.
            if u32::try_from(self.value).is_err() || u32::try_from(mask).is_err() {
                return Err(ConfigError::SeccompInvalid {
                    reason: format!(
                        "a dword condition on argument {} compares 32 bits, but its value \
                         {:#x} or mask {mask:#x} is wider",
                        self.index, self.value,
                    ),
                });
            }
        }
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
/// Syscalls are named by their kernel number for the host architecture: `libc`
/// provides them as constants, and [`syscall`](Self::syscall) reads one from
/// its name.
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
    /// The syscalls answered with an errno of their own, ahead of the listed
    /// and default actions.
    errnos: BTreeMap<i64, u16>,
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
            errnos: BTreeMap::new(),
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
            errnos: BTreeMap::new(),
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

    /// Answers every call of `syscall` with `errno`, whatever the listed and
    /// default actions say, replacing an errno given for it before.
    ///
    /// The listed action is one action for every listed syscall, and some
    /// callers tell refusals apart by their errno. The case this exists for is
    /// `clone3`: the C library takes `ENOSYS` from it to mean an older kernel
    /// and falls back to `clone`, while any other refusal fails the thread or
    /// process it was creating. A policy that conditions `clone`'s flags has
    /// to answer `clone3` this way, since a filter cannot read the structure
    /// `clone3` takes its flags in:
    ///
    /// ```
    /// use ferroday_cage::{SeccompArg, SeccompRules};
    ///
    /// const CLONE_NEWUSER: u64 = 0x1000_0000;
    /// // Refuse a new user namespace through clone, and send clone3's callers
    /// // to clone.
    /// let rules = SeccompRules::denying([])
    ///     .rule(libc::SYS_clone, [SeccompArg::masked_eq_qword(0, CLONE_NEWUSER, CLONE_NEWUSER)])
    ///     .errno_for(libc::SYS_clone3, libc::ENOSYS as u16);
    /// # let _ = rules;
    /// ```
    ///
    /// A syscall answered this way must not also be listed, with or without
    /// conditions: one of the two would silently lose, so the build refuses
    /// the policy with
    /// [`ConfigError::SeccompInvalid`](crate::ConfigError::SeccompInvalid).
    /// The build refuses an `errno` outside one through 4095 the same way, for
    /// the reason [`SeccompAction::Errno`] gives; [`errno`](Self::errno) reads
    /// a name or a number into that range.
    pub fn errno_for(mut self, syscall: i64, errno: u16) -> SeccompRules {
        self.errnos.insert(syscall, errno);
        self
    }

    /// The syscall number `name` spells on the host architecture, as
    /// [`denying`](Self::denying), [`allowing`](Self::allowing),
    /// [`rule`](Self::rule) and [`errno_for`](Self::errno_for) take it, or
    /// `None` where the host has no syscall of that name.
    ///
    /// The name is the kernel's, spelled exactly, and resolves through the
    /// table a profile's syscall names resolve through. A syscall another
    /// architecture has and this one lacks, such as `open` on aarch64, has no
    /// number here.
    ///
    /// ```
    /// use ferroday_cage::SeccompRules;
    ///
    /// assert_eq!(SeccompRules::syscall("clone3"), Some(libc::SYS_clone3));
    /// assert_eq!(SeccompRules::syscall("CLONE3"), None);
    /// assert_eq!(SeccompRules::syscall("nosuchcall"), None);
    /// ```
    pub fn syscall(name: &str) -> Option<i64> {
        name.parse::<syscalls::Sysno>()
            .ok()
            .map(|sysno| i64::from(sysno.id()))
    }

    /// The errno `spelling` names, as [`errno_for`](Self::errno_for) takes it,
    /// or `None` where it names none a syscall can fail with.
    ///
    /// A name such as `ENOSYS` resolves in any letter case, through the table
    /// a profile's `errno` entries resolve through. A number is taken as it
    /// stands when it is one through 4095, the errnos the C library reads a
    /// failed syscall's result as. Zero is refused, since a filter answering
    /// with it reports a success the syscall never performed, and so is
    /// anything larger, which the caller would read as a returned value.
    ///
    /// ```
    /// use ferroday_cage::SeccompRules;
    ///
    /// assert_eq!(SeccompRules::errno("ENOSYS"), Some(libc::ENOSYS as u16));
    /// assert_eq!(SeccompRules::errno("enosys"), Some(libc::ENOSYS as u16));
    /// assert_eq!(SeccompRules::errno("38"), Some(38));
    /// assert_eq!(SeccompRules::errno("0"), None);
    /// assert_eq!(SeccompRules::errno("4096"), None);
    /// ```
    pub fn errno(spelling: &str) -> Option<u16> {
        match spelling.parse::<u16>() {
            Ok(number) => is_failure_errno(number).then_some(number),
            Err(_) => errno_named(spelling),
        }
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
    /// one syscall under a denying action, or answers one with an errno of its
    /// own. An empty `denying([])` restricts nothing.
    fn restricts(&self) -> bool {
        !self.default_action.is_permissive()
            || (!self.rules.is_empty() && !self.listed_action.is_permissive())
            || !self.errnos.is_empty()
    }
}

/// A seccomp syscall-filtering policy for the sandboxed command.
#[derive(Clone)]
#[non_exhaustive]
pub enum SeccompPolicy {
    /// A curated default-deny of dangerous and rarely-legitimate syscalls,
    /// allowing the rest. A convenience posture, not a boundary claim; its
    /// exact roster is documented and grows only additively.
    ///
    /// Some entries are conditioned on an argument rather than naming a whole
    /// syscall. `ioctl` is denied for the `TIOCSTI` and `TIOCLINUX` requests,
    /// which write to a terminal's input queue, and allowed for everything
    /// else. `unshare` and `clone` are denied whenever their flags create a
    /// namespace, and allowed otherwise, so processes and threads start as
    /// usual. `clone3` takes its flags in memory a filter cannot read, so it
    /// is answered `ENOSYS`, and the C library falls back to `clone`.
    ///
    /// Denying namespace creation means a command that builds a sandbox of
    /// its own, such as a browser or a container runtime, does not run under
    /// this policy as it does elsewhere.
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
// every instruction. `Clone` is derived on the type, being structural.
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
        Sysno::open_tree_attr,
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
        // The natural complements to ptrace: cross-process memory access and
        // descriptor theft, reachable against another process of the same uid
        // in a restriction (no PID namespace) where ptrace alone would not
        // suffice. `pidfd_getfd` copies a descriptor out of a process under
        // the same ptrace check `process_vm_readv` makes.
        Sysno::process_vm_readv,
        Sysno::process_vm_writev,
        Sysno::pidfd_getfd,
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

/// `TIOCSTI`: push one character into a terminal's input queue, as though it
/// had been typed.
const TIOCSTI: u64 = 0x5412;
/// `TIOCLINUX`: the Linux console multiplexer, whose `TIOCL_SETSEL`/
/// `TIOCL_PASTESEL` subcommands paste a console selection into the input queue
/// and so reach the same place `TIOCSTI` does.
const TIOCLINUX: u64 = 0x541C;

/// The curated denylist's argument-conditioned entries: the two `ioctl`
/// requests that write to a terminal's input queue.
///
/// Denied by request rather than by syscall, because `ioctl` itself is the
/// ordinary way to ask anything of a device and a sandboxed command needs it.
/// A command that holds a descriptor for the caller's terminal — an inherited
/// standard stream, or `/dev/tty` while it shares the caller's session — can
/// otherwise use these to enqueue characters that the caller's shell reads and
/// runs once the sandbox exits. Modern kernels gate `TIOCSTI` behind the
/// `dev.tty.legacy_tiocsti` sysctl, which defaults to off, and grant it only
/// for the process's own controlling terminal; this denies it outright, on
/// every kernel, whichever terminal is named. See [`Stdio`](crate::Stdio),
/// which decides whether the sandbox reaches the *caller's* terminal at all —
/// the reach this exists to close. A terminal launch
/// ([`Cage::spawn_terminal`](crate::Cage::spawn_terminal)) reaches none of it
/// whatever `Stdio` says, since the sandbox has a terminal of its own; the
/// denial still applies there, and denies an operation on a terminal nobody
/// else can see, which is the price of a denylist that does not ask whose
/// terminal it is.
///
/// The comparison is on the low 32 bits because `ioctl`'s request argument
/// reaches the kernel as an `unsigned int`: the high half is discarded before
/// dispatch, so comparing all 64 bits would let a request with anything set
/// above bit 31 pass the filter and still be honoured.
fn curated_ioctl_rules() -> Vec<SyscallRule> {
    [TIOCSTI, TIOCLINUX]
        .into_iter()
        .map(|request| SyscallRule {
            syscall: syscalls::Sysno::ioctl.id() as i64,
            conditions: vec![SeccompArg::eq_dword(1, request)],
        })
        .collect()
}

/// The curated denylist's namespace entries: `clone` and `unshare` whenever
/// their flags create a namespace of any kind.
///
/// `setns` is denied outright, and these close the other way in. A command
/// that creates a user namespace holds every capability inside it, and with a
/// network namespace beside it reaches netfilter and the rest of the network
/// configuration a capability gates. Denied by flag rather than by syscall,
/// because `clone` is how every process and thread starts.
///
/// One rule per flag, since a masked comparison tests its mask's bits against
/// a single value, and "any of these bits" is the union of the one-bit tests.
/// The comparison is on the low 32 bits: every flag here sits in them, and
/// `clone` reads no more of its flags than that. `CLONE_NEWTIME` is
/// `unshare`'s alone, because in `clone`'s flags its bit falls in the low
/// byte, which carries the exit signal.
///
/// `clone3` takes its flags in a structure a filter cannot read, which is why
/// [`curated_errnos`] answers it `ENOSYS`: the C library then falls back to
/// `clone`, where these rules see the flags.
fn curated_namespace_rules() -> Vec<SyscallRule> {
    use rustix::thread::UnshareFlags;
    use syscalls::Sysno;

    let created = UnshareFlags::NEWNS
        | UnshareFlags::NEWCGROUP
        | UnshareFlags::NEWUTS
        | UnshareFlags::NEWIPC
        | UnshareFlags::NEWUSER
        | UnshareFlags::NEWPID
        | UnshareFlags::NEWNET;
    let each_flag = |syscall: Sysno, flags: UnshareFlags| {
        flags.iter().map(move |flag| SyscallRule {
            syscall: syscall.id() as i64,
            conditions: vec![SeccompArg::masked_eq_dword(
                0,
                u64::from(flag.bits()),
                u64::from(flag.bits()),
            )],
        })
    };
    each_flag(Sysno::clone, created)
        .chain(each_flag(Sysno::unshare, created | UnshareFlags::NEWTIME))
        .collect()
}

/// The syscalls the curated policy answers with an errno of their own: `clone3`
/// with `ENOSYS`, which the C library reads as a kernel without it.
///
/// Denied with the policy's `EPERM`, `clone3` would fail every thread glibc
/// 2.34 and later starts. Allowed, it would create the namespaces
/// [`curated_namespace_rules`] refuse through `clone`, since its flags are out
/// of the filter's sight.
fn curated_errnos() -> BTreeMap<i64, u16> {
    BTreeMap::from([(syscalls::Sysno::clone3.id() as i64, ENOSYS)])
}

roster_enum! {
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
        /// The single-bit capability set naming this capability.
        fn to_set -> CapabilitySet;
        /// The canonical kebab-case name, without the `cap-` prefix.
        fn as_str;

        /// `CAP_CHOWN`.
        Chown = CapabilitySet::CHOWN => "chown",
        /// `CAP_DAC_OVERRIDE`.
        DacOverride = CapabilitySet::DAC_OVERRIDE => "dac-override",
        /// `CAP_DAC_READ_SEARCH`.
        DacReadSearch = CapabilitySet::DAC_READ_SEARCH => "dac-read-search",
        /// `CAP_FOWNER`.
        Fowner = CapabilitySet::FOWNER => "fowner",
        /// `CAP_FSETID`.
        Fsetid = CapabilitySet::FSETID => "fsetid",
        /// `CAP_KILL`.
        Kill = CapabilitySet::KILL => "kill",
        /// `CAP_SETGID`.
        Setgid = CapabilitySet::SETGID => "setgid",
        /// `CAP_SETUID`.
        Setuid = CapabilitySet::SETUID => "setuid",
        /// `CAP_SETPCAP`.
        Setpcap = CapabilitySet::SETPCAP => "setpcap",
        /// `CAP_LINUX_IMMUTABLE`.
        LinuxImmutable = CapabilitySet::LINUX_IMMUTABLE => "linux-immutable",
        /// `CAP_NET_BIND_SERVICE`.
        NetBindService = CapabilitySet::NET_BIND_SERVICE => "net-bind-service",
        /// `CAP_NET_BROADCAST`.
        NetBroadcast = CapabilitySet::NET_BROADCAST => "net-broadcast",
        /// `CAP_NET_ADMIN`.
        NetAdmin = CapabilitySet::NET_ADMIN => "net-admin",
        /// `CAP_NET_RAW`.
        NetRaw = CapabilitySet::NET_RAW => "net-raw",
        /// `CAP_IPC_LOCK`.
        IpcLock = CapabilitySet::IPC_LOCK => "ipc-lock",
        /// `CAP_IPC_OWNER`.
        IpcOwner = CapabilitySet::IPC_OWNER => "ipc-owner",
        /// `CAP_SYS_MODULE`.
        SysModule = CapabilitySet::SYS_MODULE => "sys-module",
        /// `CAP_SYS_RAWIO`.
        SysRawio = CapabilitySet::SYS_RAWIO => "sys-rawio",
        /// `CAP_SYS_CHROOT`.
        SysChroot = CapabilitySet::SYS_CHROOT => "sys-chroot",
        /// `CAP_SYS_PTRACE`.
        SysPtrace = CapabilitySet::SYS_PTRACE => "sys-ptrace",
        /// `CAP_SYS_PACCT`.
        SysPacct = CapabilitySet::SYS_PACCT => "sys-pacct",
        /// `CAP_SYS_ADMIN`.
        SysAdmin = CapabilitySet::SYS_ADMIN => "sys-admin",
        /// `CAP_SYS_BOOT`.
        SysBoot = CapabilitySet::SYS_BOOT => "sys-boot",
        /// `CAP_SYS_NICE`.
        SysNice = CapabilitySet::SYS_NICE => "sys-nice",
        /// `CAP_SYS_RESOURCE`.
        SysResource = CapabilitySet::SYS_RESOURCE => "sys-resource",
        /// `CAP_SYS_TIME`.
        SysTime = CapabilitySet::SYS_TIME => "sys-time",
        /// `CAP_SYS_TTY_CONFIG`.
        SysTtyConfig = CapabilitySet::SYS_TTY_CONFIG => "sys-tty-config",
        /// `CAP_MKNOD`.
        Mknod = CapabilitySet::MKNOD => "mknod",
        /// `CAP_LEASE`.
        Lease = CapabilitySet::LEASE => "lease",
        /// `CAP_AUDIT_WRITE`.
        AuditWrite = CapabilitySet::AUDIT_WRITE => "audit-write",
        /// `CAP_AUDIT_CONTROL`.
        AuditControl = CapabilitySet::AUDIT_CONTROL => "audit-control",
        /// `CAP_SETFCAP`.
        Setfcap = CapabilitySet::SETFCAP => "setfcap",
        /// `CAP_MAC_OVERRIDE`.
        MacOverride = CapabilitySet::MAC_OVERRIDE => "mac-override",
        /// `CAP_MAC_ADMIN`.
        MacAdmin = CapabilitySet::MAC_ADMIN => "mac-admin",
        /// `CAP_SYSLOG`.
        Syslog = CapabilitySet::SYSLOG => "syslog",
        /// `CAP_WAKE_ALARM`.
        WakeAlarm = CapabilitySet::WAKE_ALARM => "wake-alarm",
        /// `CAP_BLOCK_SUSPEND`.
        BlockSuspend = CapabilitySet::BLOCK_SUSPEND => "block-suspend",
        /// `CAP_AUDIT_READ`.
        AuditRead = CapabilitySet::AUDIT_READ => "audit-read",
        /// `CAP_PERFMON`.
        Perfmon = CapabilitySet::PERFMON => "perfmon",
        /// `CAP_BPF`.
        Bpf = CapabilitySet::BPF => "bpf",
        /// `CAP_CHECKPOINT_RESTORE`.
        CheckpointRestore = CapabilitySet::CHECKPOINT_RESTORE => "checkpoint-restore",
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
                text: s.to_string(),
            })
    }
}

/// The error from parsing an unrecognized [`Capability`] name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCapabilityError {
    text: String,
}

impl ParseCapabilityError {
    /// The unrecognized name, as it was given.
    ///
    /// Named `text` on every parse error in this crate, so a caller moving
    /// between them does not have to check.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ParseCapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown capability {:?}", self.text)
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
    /// The `LANDLOCK_SCOPE_*` flags requested, joined.
    scope: u64,
    seccomp: Option<SeccompPolicy>,
    capabilities: CapabilityPosture,
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

    /// Replaces the Landlock scopes with `scopes`.
    pub(crate) fn set_scope<I: IntoIterator<Item = LandlockScope>>(&mut self, scopes: I) {
        self.scope = LandlockScope::bits_of(scopes);
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
    /// cannot express one — and neither do the Landlock scopes, which a
    /// restriction requests by default and which leave the filesystem and the
    /// network as open as they found them.
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
            && self.scope == 0
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

    /// The Landlock filesystem grants, in the order they were added.
    pub(crate) fn fs_grants(&self) -> impl Iterator<Item = (FsAccess, &Path)> {
        self.landlock
            .iter()
            .map(|grant| (grant.access, grant.path.as_path()))
    }

    /// The Landlock network grants, in the order they were added.
    pub(crate) fn net_grants(&self) -> impl Iterator<Item = (NetAccess, u16)> {
        self.landlock_net
            .iter()
            .map(|grant| (grant.access, grant.port))
    }

    /// The Landlock scopes requested, in [`LandlockScope::ALL`]'s order.
    pub(crate) fn scopes(&self) -> impl Iterator<Item = LandlockScope> {
        LandlockScope::ALL
            .iter()
            .copied()
            .filter(|scope| self.scope & scope.to_landlock() != 0)
    }

    /// The seccomp policy, when one is set.
    pub(crate) fn seccomp(&self) -> Option<&SeccompPolicy> {
        self.seccomp.as_ref()
    }

    /// The capabilities kept: `None` leaves the capability sets untouched, and
    /// an empty list drops every capability.
    pub(crate) fn kept_capabilities(&self) -> Option<&[Capability]> {
        match &self.capabilities {
            CapabilityPosture::Keep => None,
            CapabilityPosture::Reduce(caps) => Some(caps),
        }
    }

    /// Lowers the request into the frozen plan, compiling the seccomp policy
    /// and validating the Landlock grant paths. Called from the builders'
    /// `build`, where allocation and failure are free.
    pub(crate) fn lower(&self) -> Result<HardeningPlan, ConfigError> {
        // An empty access set is a trap rather than a no-op: enrolling any
        // grant denies everything ungranted, while the kernel skips a rule that
        // permits nothing. A grant of `FsAccess::empty()` therefore denies the
        // entire filesystem — including the command's own binary, which fails
        // the launch at `execve` with nothing pointing at the cause — and an
        // empty network grant denies all TCP. Neither is what naming a path or
        // a port means, so both are refused here.
        //
        // Each grant also leaves a label behind, filesystem grants first and
        // network grants after them, in the order the command stage adds the
        // rules. A rule the kernel refuses is reported by its position in that
        // order, which is what names the grant in the setup error.
        let mut landlock_labels = Vec::with_capacity(self.landlock.len() + self.landlock_net.len());
        let landlock = self
            .landlock
            .iter()
            .map(|grant| {
                let subject = grant.path.display();
                if grant.access.is_empty() {
                    return Err(ConfigError::LandlockGrantEmpty {
                        grant: subject.to_string(),
                    });
                }
                landlock_labels.push(format!("{} on {subject}", grant.access));
                Ok(LandlockRule {
                    path: grant_path_cstring(&grant.path)?,
                    access: grant.access.to_landlock(),
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let landlock_net = self
            .landlock_net
            .iter()
            .map(|grant| {
                let subject = format!("tcp:{}", grant.port);
                if grant.access.is_empty() {
                    return Err(ConfigError::LandlockGrantEmpty { grant: subject });
                }
                landlock_labels.push(format!("{} on {subject}", grant.access));
                Ok(LandlockNetRule {
                    port: grant.port,
                    access: grant.access.to_landlock(),
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

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
            landlock_scoped: self.scope,
            landlock_labels,
            // A sandbox's grants refuse a link on their way, and the
            // restriction's build, whose paths are the host's, lets them follow.
            grants_follow_links: false,
            seccomp,
            keep_caps,
            // Whether the identity switch needs securebits is decided by
            // the builder, which alone knows the run-as identity.
            set_securebits: false,
        })
    }
}

/// Validates a Landlock grant path — absolute, ordinary components only, the
/// bare root allowed so a grant can cover a whole tree — and freezes it as a
/// `CString`.
///
/// The bare root is the one way this differs from a mount target's check: a
/// grant over `/` is a coherent request, where a mount target of `/` is not.
/// In a cage the path resolves after the pivot; in a restriction it resolves
/// against the host filesystem.
fn grant_path_cstring(path: &Path) -> Result<CString, ConfigError> {
    crate::path::absolute_components(path).map_err(|_| ConfigError::LandlockPathInvalid {
        path: path.to_path_buf(),
    })?;
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
                .chain(curated_ioctl_rules())
                .chain(curated_namespace_rules())
                .collect();
            compile_filter(
                SeccompAction::Allow,
                SeccompAction::Errno(EPERM),
                &rules,
                &curated_errnos(),
            )?
        }
        SeccompPolicy::Rules(rules) => compile_filter(
            rules.default_action,
            rules.listed_action,
            &rules.rules,
            &rules.errnos,
        )?,
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

/// The audit architecture a filter for `arch` gates on.
///
/// seccompiler gates its own program on the same value and keeps it private,
/// so the fragments emitted ahead of that program state it here.
fn audit_arch(arch: seccompiler::TargetArch) -> u32 {
    match arch {
        seccompiler::TargetArch::x86_64 => AUDIT_ARCH_X86_64,
        seccompiler::TargetArch::aarch64 => AUDIT_ARCH_AARCH64,
        seccompiler::TargetArch::riscv64 => AUDIT_ARCH_RISCV64,
    }
}

/// The raw `SECCOMP_RET_*` value a BPF `ret` returns for `action`.
///
/// The fragments emitted ahead of seccompiler's program return an action
/// directly, so they take the encoding seccompiler itself uses.
fn ret_value(action: SeccompAction) -> u32 {
    u32::from(action.to_seccompiler())
}

/// Refuses a syscall number no filter can name: a negative one, and one at or
/// above [`X32_SYSCALL_BIT`].
///
/// That bit is the ceiling on every architecture: no architecture's own table
/// reaches it, and on x86_64 a number at or above it is an x32 alias, which
/// [`x32_deny_prologue`] refuses wholesale and the crate does not otherwise
/// support.
///
/// The compiler backend narrows every number to the 32 bits a BPF comparison
/// holds and would panic on one that does not fit, so this runs before it.
fn check_syscall_number(syscall: i64) -> Result<(), ConfigError> {
    if (0..i64::from(X32_SYSCALL_BIT)).contains(&syscall) {
        return Ok(());
    }
    Err(ConfigError::SeccompInvalid {
        reason: format!(
            "syscall number {syscall} is out of range: a filter names numbers from 0 \
             below {X32_SYSCALL_BIT:#x}, where x86_64's x32 aliases begin"
        ),
    })
}

/// A classic-BPF prologue answering each syscall in `errnos` with its own
/// errno, for prepending to seccompiler's program, whose one match action
/// cannot give a single syscall an answer of its own.
///
/// The numbers are the host architecture's, so the prologue applies them only
/// under that architecture's audit value and otherwise jumps past itself to
/// seccompiler's program, which reloads the arch word and refuses a foreign
/// one. The jump is a `ja` with a 32-bit offset, so no count of syscalls
/// outgrows it; the kernel's instruction ceiling bounds the count instead.
///
/// ```text
///   [0] A = seccomp_data.arch
///   [1] if A == arch: skip [2]
///   [2] jump past the prologue
///   [3] A = seccomp_data.nr
///   [4] if A != nr: skip [5]        one pair per syscall
///   [5] return ERRNO(errno)
/// ```
///
/// Every number was held to [`check_syscall_number`] first, so it fits the
/// comparison's 32 bits.
fn errno_prologue(arch: u32, errnos: &BTreeMap<i64, u16>) -> Vec<SockFilter> {
    let pairs = errnos.len();
    let past = u32::try_from(1 + 2 * pairs).unwrap_or(u32::MAX);
    let mut program = Vec::with_capacity(4 + 2 * pairs);
    program.push(SockFilter {
        code: bpf::LD_W_ABS,
        jt: 0,
        jf: 0,
        k: bpf::OFF_ARCH,
    });
    program.push(SockFilter {
        code: bpf::JMP_JEQ_K,
        jt: 1,
        jf: 0,
        k: arch,
    });
    program.push(SockFilter {
        code: bpf::JMP_JA,
        jt: 0,
        jf: 0,
        k: past,
    });
    program.push(SockFilter {
        code: bpf::LD_W_ABS,
        jt: 0,
        jf: 0,
        k: bpf::OFF_NR,
    });
    for (&syscall, &errno) in errnos {
        program.push(SockFilter {
            code: bpf::JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        program.push(SockFilter {
            code: bpf::RET_K,
            jt: 0,
            jf: 0,
            k: ret_value(SeccompAction::Errno(errno)),
        });
    }
    program
}

/// A five-instruction classic-BPF prologue answering every syscall carrying
/// `__X32_SYSCALL_BIT` with `ENOSYS`, for prepending to a denylist compiled
/// for x86_64.
///
/// Only a denylist needs it: an allowlist's denying default already refuses
/// the x32 numbers, so [`compile_filter`] emits this for a permissive default
/// alone.
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
///   [4] return ERRNO(ENOSYS)
/// ```
///
/// The answer is fixed rather than taken from the policy. A denylist's listed
/// action may itself let a syscall run (`Log` does), and the errnos a policy
/// gives single syscalls are keyed by their 64-bit numbers, so neither
/// describes the x32 range. `ENOSYS` is what a kernel built without x32
/// answers for the same numbers, so a program that probes for x32 reads it
/// as absent, and nothing is let through whatever the policy says.
fn x32_deny_prologue() -> [SockFilter; 5] {
    let ret = ret_value(SeccompAction::Errno(ENOSYS));
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
/// rest, and each syscall in `errnos` answered with its own errno ahead of
/// both.
///
/// A syscall's argument conditions decide whether an invocation counts as
/// matched; a matched invocation takes the `listed_action`, an unmatched one
/// the `default_action`. So conditions refine which invocations of a listed
/// syscall the listed action governs. The one per-syscall action is the errno
/// of `errnos`, which seccompiler cannot express and a prologue of its own
/// carries; a syscall given one may not be listed as well.
///
/// Every errno the filter answers with, the two actions' and those of
/// `errnos`, is held to [`check_errno`] before anything is compiled.
fn compile_filter(
    default_action: SeccompAction,
    listed_action: SeccompAction,
    rules: &[SyscallRule],
    errnos: &BTreeMap<i64, u16>,
) -> Result<Vec<SockFilter>, ConfigError> {
    let arch = host_target_arch()?;
    for &syscall in rules.iter().map(|rule| &rule.syscall).chain(errnos.keys()) {
        check_syscall_number(syscall)?;
    }
    for (answering, action) in [
        ("the default action answers with", default_action),
        ("the listed action answers with", listed_action),
    ] {
        if let SeccompAction::Errno(errno) = action {
            check_errno(answering, errno)?;
        }
    }
    for (&syscall, &errno) in errnos {
        check_errno(&format!("syscall number {syscall} is answered with"), errno)?;
    }
    if let Some(rule) = rules.iter().find(|rule| errnos.contains_key(&rule.syscall)) {
        return Err(ConfigError::SeccompInvalid {
            reason: format!(
                "syscall number {} is both listed and answered with an errno of its own; \
                 one of the two would never apply",
                rule.syscall
            ),
        });
    }
    // The prologue answers its syscalls first and falls through to the rest,
    // and the whole program is held to the kernel's ceiling afterwards. A count
    // that could not fit is refused here, before the prologue is built for it.
    if 4 + 2 * errnos.len() > BPF_MAXINSNS {
        return Err(ConfigError::SeccompProgramTooLong {
            len: 4 + 2 * errnos.len(),
            max: BPF_MAXINSNS,
        });
    }
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
    let guard = needs_x32_guard.then(x32_deny_prologue);
    let answers = (!errnos.is_empty()).then(|| errno_prologue(audit_arch(arch), errnos));
    let program: Vec<SockFilter> = guard
        .into_iter()
        .flatten()
        .chain(answers.into_iter().flatten())
        .chain(compiled)
        .collect();
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
/// landlock-scope = ["signal"]      # or: ["signal", "abstract-unix-socket"]
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
/// the argument conditions its listed action requires, and may answer a
/// syscall with an errno of its own through an `errno` table:
///
/// ```toml
/// [hardening.seccomp]
/// allow = ["execve", "read", "write", "exit_group"]
/// errno = { clone3 = "ENOSYS" }
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
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use serde::de::Error as _;
    use serde::ser::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use syscalls::Sysno;

    use super::{
        Capability, CapabilityPosture, EPERM, FsAccess, Grant, LandlockScope, NetAccess, NetGrant,
        Request, SeccompAction, SeccompArg, SeccompArgLen, SeccompCompare, SeccompPolicy,
        SeccompRules,
    };

    /// The profile form of a hardening request: the `[hardening]` table.
    ///
    /// The two capability keys, the scope list, and the seccomp key precede the
    /// `landlock-fs` and `landlock-net` arrays so the serialized table is valid
    /// TOML in field order — a bare key after an array-of-tables header would
    /// bind to the wrong table, the same ordering constraint the top-level
    /// builder observes. The scope list precedes the seccomp key for the same
    /// reason, since that key may be a table of its own.
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
        /// The Landlock scopes, by name.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        landlock_scope: Vec<String>,
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
    /// `deny`, argument-conditioned entries in `allow-rule` or `deny-rule`, and
    /// syscalls answered with an errno of their own in `errno`, a table of
    /// syscall names to errno names. The allow and deny sides are mutually
    /// exclusive; a table must set one side, and `errno` alone counts as the
    /// deny side, since what it does is refuse.
    ///
    /// `errno` precedes the two rule arrays so the serialized table is valid
    /// TOML in field order, as [`HardeningProfile`] keeps its own.
    #[derive(Serialize, Deserialize, Default)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
    struct SeccompLists {
        #[serde(skip_serializing_if = "Vec::is_empty")]
        allow: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        deny: Vec<String>,
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        errno: BTreeMap<String, String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        allow_rule: Vec<RuleProfile>,
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

            let scope = LandlockScope::bits_of(
                self.landlock_scope
                    .iter()
                    .map(|name| name.parse::<LandlockScope>().map_err(|err| err.to_string()))
                    .collect::<Result<Vec<_>, _>>()?,
            );

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
                scope,
                seccomp,
                capabilities,
            })
        }

        /// Raises the in-memory request into its profile form, rejecting the
        /// parts a profile cannot represent.
        fn from_request(request: &Request) -> Result<HardeningProfile, String> {
            let (drop_caps, keep_caps) = match request.kept_capabilities() {
                None => (false, None),
                Some([]) => (true, None),
                Some(caps) => (
                    false,
                    Some(caps.iter().map(|cap| cap.to_string()).collect()),
                ),
            };

            let landlock_scope = request.scopes().map(|scope| scope.to_string()).collect();

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
                landlock_scope,
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
                (false, false) if self.errno.is_empty() => {
                    return Err("a seccomp table lists no syscalls; set allow, allow-rule, \
                                deny, deny-rule, or errno"
                        .to_string());
                }
                (true, false) => (
                    SeccompRules::allowing(resolve_syscalls(&self.allow)?),
                    self.allow_rule,
                ),
                // The deny side, including a table whose only entries are
                // errnos: what those do is refuse, and everything else runs.
                (false, _) => (
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
            for (syscall, errno) in &self.errno {
                rules = rules.errno_for(resolve_syscall(syscall)?, resolve_errno(errno)?);
            }
            Ok(rules)
        }

        /// Raises a [`SeccompRules`] into its table form, partitioning the
        /// listed syscalls into bare names and argument-conditioned entries.
        /// Rejects a policy with a custom action, which a profile cannot name.
        ///
        /// A rule set listing no syscall at all is rejected here for the same
        /// reason. The table tells its allow side from its deny side by which
        /// of them is non-empty, so a policy with neither has no table that
        /// says which it was — it renders as a bare `[hardening.seccomp]` that
        /// [`into_rules`](SeccompLists::into_rules) then refuses. Reporting it
        /// on the way out is what keeps the promise that a policy a profile
        /// cannot express is a serialization error rather than a document that
        /// will not read back.
        fn from_rules(rules: &SeccompRules) -> Result<SeccompLists, String> {
            let errno = rules
                .errnos
                .iter()
                .map(|(&syscall, &errno)| Ok((name_syscall(syscall)?, name_errno(errno)?)))
                .collect::<Result<BTreeMap<_, _>, String>>()?;
            // A table that answers syscalls with an errno and lists none reads
            // back as a denylist, so that one shape is representable.
            if rules.rules.is_empty()
                && !errno.is_empty()
                && rules.default_action == SeccompAction::Allow
                && rules.listed_action == SeccompAction::Errno(EPERM)
            {
                return Ok(SeccompLists {
                    errno,
                    ..SeccompLists::default()
                });
            }
            if rules.rules.is_empty() {
                return Err(
                    "a seccomp policy listing no syscall cannot be represented in a \
                            profile: the table names its side by listing one"
                        .to_string(),
                );
            }
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
                    errno,
                    ..SeccompLists::default()
                }),
                (SeccompAction::Errno(EPERM), SeccompAction::Allow) => Ok(SeccompLists {
                    allow: bare,
                    allow_rule: rule_profiles,
                    errno,
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
        SeccompRules::syscall(name).ok_or_else(|| format!("unknown syscall {name:?}"))
    }

    /// Resolves an errno name, such as `ENOSYS`, to its number, in any letter
    /// case. A profile names an errno and does not number one.
    fn resolve_errno(name: &str) -> Result<u16, String> {
        super::errno_named(name).ok_or_else(|| format!("unknown errno {name:?}"))
    }

    /// Names one errno, for serialization.
    fn name_errno(errno: u16) -> Result<String, String> {
        syscalls::Errno::new(i32::from(errno))
            .name()
            .map(str::to_string)
            .ok_or_else(|| format!("errno {errno} has no name a profile can spell"))
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
    use crate::mechanism::seccomp::eval::{self, Call};

    /// A call of `syscall` on the host's architecture, with `args` and then
    /// zeroes.
    fn host_call(syscall: i64, args: &[u64]) -> Call {
        Call::new(
            audit_arch(host_target_arch().unwrap()),
            u32::try_from(syscall).unwrap(),
            args,
        )
    }

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
            Sysno::open_tree_attr,
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
            Sysno::pidfd_getfd,
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
    fn the_curated_denylist_denies_the_terminal_injection_ioctls_by_request() {
        use syscalls::Sysno;

        // `ioctl` is denied by request, not outright: a sandboxed command asks
        // devices for things the ordinary way, and only the two requests that
        // write to a terminal's input queue are refused.
        let ioctl = Sysno::ioctl.id() as i64;
        assert!(
            !curated_denylist().contains(&ioctl),
            "ioctl is denied by request, so it must not be listed unconditionally",
        );
        let rules = curated_ioctl_rules();
        assert!(rules.iter().all(|rule| rule.syscall == ioctl));
        let requests: Vec<u64> = rules
            .iter()
            .flat_map(|rule| rule.conditions.iter())
            .map(|arg| arg.value)
            .collect();
        assert_eq!(requests, [TIOCSTI, TIOCLINUX]);
        // The low 32 bits alone: the kernel takes the request as an
        // `unsigned int`, so a 64-bit comparison would miss a request carrying
        // anything above bit 31 that is nonetheless dispatched as this one.
        for arg in rules.iter().flat_map(|rule| rule.conditions.iter()) {
            assert_eq!(arg.index, 1);
            assert!(matches!(arg.len, SeccompArgLen::Dword));
            assert!(matches!(arg.compare, SeccompCompare::Eq));
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn a_denylist_is_prefixed_with_the_x32_guard_on_x86_64() {
        // A denylist (permissive default) is bypassable through the x32 ABI, so
        // the compiled program must begin with the guard denying that range.
        let program = compile_seccomp(&SeccompPolicy::Curated).unwrap();
        let guard = x32_deny_prologue();
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
        let guard = x32_deny_prologue();
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
                // [4] return ENOSYS
                SockFilter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: 0x0005_0000 | 38,
                },
            ],
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn the_x32_guard_denies_whatever_the_policy_lets_run() {
        // A listed action that lets the call run, and an errno the policy gives
        // one syscall by its 64-bit number. Neither describes an x32 call, and
        // the guard answers every one of them ENOSYS all the same.
        let rules = SeccompRules::denying([libc::SYS_ptrace])
            .listed_action(SeccompAction::Log)
            .errno_for(libc::SYS_keyctl, EPERM);
        let program = compile_seccomp(&SeccompPolicy::Rules(rules)).unwrap();
        let enosys = ret_value(SeccompAction::Errno(ENOSYS));
        for syscall in [libc::SYS_keyctl, libc::SYS_ptrace, libc::SYS_getpid] {
            let x32 = host_call(syscall | i64::from(X32_SYSCALL_BIT), &[]);
            assert_eq!(eval::run(&program, &x32), enosys, "x32 syscall {syscall}");
        }
        // The 64-bit calls keep the answers the policy gives them.
        for (syscall, action) in [
            (libc::SYS_keyctl, SeccompAction::Errno(EPERM)),
            (libc::SYS_ptrace, SeccompAction::Log),
            (libc::SYS_getpid, SeccompAction::Allow),
        ] {
            let call = host_call(syscall, &[]);
            assert_eq!(eval::run(&program, &call), ret_value(action), "{syscall}");
        }
    }

    #[test]
    fn eperm_is_the_kernels() {
        assert_eq!(i32::from(EPERM), libc::EPERM);
    }

    #[test]
    fn the_curated_policy_denies_creating_a_namespace() {
        let program = compile_seccomp(&SeccompPolicy::Curated).unwrap();
        let eperm = ret_value(SeccompAction::Errno(EPERM));
        let allow = ret_value(SeccompAction::Allow);
        let sigchld = libc::SIGCHLD as u64;
        let new = [
            libc::CLONE_NEWNS,
            libc::CLONE_NEWCGROUP,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWNET,
        ]
        .map(|flag| flag as u64);

        // Every namespace flag, alone or beside others, refuses the call.
        for flag in new {
            for flags in [flag, flag | sigchld, flag | libc::CLONE_NEWUSER as u64] {
                let clone = host_call(libc::SYS_clone, &[flags]);
                assert_eq!(eval::run(&program, &clone), eperm, "clone {flags:#x}");
                let unshare = host_call(libc::SYS_unshare, &[flags]);
                assert_eq!(eval::run(&program, &unshare), eperm, "unshare {flags:#x}");
            }
        }
        let new_time = host_call(libc::SYS_unshare, &[libc::CLONE_NEWTIME as u64]);
        assert_eq!(eval::run(&program, &new_time), eperm);
        // Bits above the low 32 hide nothing: `clone` never reads them, and
        // `unshare` refuses them itself.
        let high = host_call(libc::SYS_unshare, &[1 << 32 | libc::CLONE_NEWUSER as u64]);
        assert_eq!(eval::run(&program, &high), eperm);

        // A process or a thread starts as usual. glibc's thread flags, its
        // fork's, and a vfork-style spawn are all flags without a namespace.
        let thread = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u64;
        let fork = (libc::CLONE_CHILD_SETTID | libc::CLONE_CHILD_CLEARTID) as u64 | sigchld;
        let spawn = (libc::CLONE_VM | libc::CLONE_VFORK) as u64 | sigchld;
        for flags in [thread, fork, spawn] {
            let clone = host_call(libc::SYS_clone, &[flags]);
            assert_eq!(eval::run(&program, &clone), allow, "clone {flags:#x}");
        }
        // Unsharing what is not a namespace stays allowed. The exit signal's
        // byte is `clone`'s, so a signal number sharing `CLONE_NEWTIME`'s bit
        // is not mistaken for it.
        let files = host_call(libc::SYS_unshare, &[libc::CLONE_FILES as u64]);
        assert_eq!(eval::run(&program, &files), allow);
        let signal = host_call(libc::SYS_clone, &[libc::CLONE_NEWTIME as u64 | sigchld]);
        assert_eq!(eval::run(&program, &signal), allow);

        // `clone3` is answered ENOSYS, whatever it was asked, so the C library
        // falls back to `clone`.
        let clone3 = host_call(libc::SYS_clone3, &[0, 88]);
        assert_eq!(
            eval::run(&program, &clone3),
            ret_value(SeccompAction::Errno(ENOSYS))
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
        assert_eq!(err.text(), "not-a-cap");
        assert!(err.to_string().contains("not-a-cap"));
    }

    /// `SeccompPolicy` is `Clone`, and stays so.
    ///
    /// It was a hand-written impl and is now a derive, which the committed API
    /// snapshot omits as noise along with every other derived impl in the
    /// crate. Losing the trait would therefore no longer show up in that diff,
    /// so it is pinned here instead — where the type is, rather than in the
    /// snapshot the change moved it out of.
    #[test]
    fn a_seccomp_policy_clones() {
        let program =
            compile_seccomp(&SeccompPolicy::Curated).expect("the curated policy compiles");
        for policy in [
            SeccompPolicy::Curated,
            SeccompPolicy::Rules(SeccompRules::denying([libc::SYS_ptrace])),
            SeccompPolicy::Program(program),
        ] {
            let copy = policy.clone();
            assert_eq!(format!("{policy:?}"), format!("{copy:?}"));
        }
    }

    #[test]
    fn capability_all_has_no_duplicates() {
        let mut names: Vec<&str> = Capability::ALL.iter().map(|cap| cap.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "capability names must be unique");
    }

    /// The roster names every capability bit the kernel defines.
    ///
    /// `ALL` is derived from the declaration, so a variant cannot be missing
    /// from it; what this catches is the other direction, which nothing else
    /// can. A capability the kernel gained and this enum has not is one a
    /// keep-list cannot name, and it shows up here as a bit no variant claims.
    ///
    /// Asked against the bits `rustix` gives a name, rather than against every
    /// bit of the word: the set is a bitflags type with a catch-all, so its
    /// `all()` holds the reserved high bits too, and `iter_names` is the set
    /// the kernel actually defines.
    #[test]
    fn every_capability_bit_has_a_variant() {
        let claimed = Capability::ALL
            .iter()
            .fold(CapabilitySet::empty(), |set, cap| set | cap.to_set());
        let unclaimed: Vec<&str> = CapabilitySet::all()
            .iter_names()
            .filter(|(_, bit)| !claimed.contains(*bit))
            .map(|(name, _)| name)
            .collect();
        assert!(
            unclaimed.is_empty(),
            "capabilities the kernel defines and this enum does not name: {unclaimed:?}",
        );
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
        assert_eq!(plan.landlock_scoped, 0);
        assert!(plan.landlock_labels.is_empty());
        assert!(plan.seccomp.is_none());
        assert!(plan.keep_caps.is_none());
        assert!(plan.is_empty());
    }

    #[test]
    fn the_file_rights_are_the_kernels_access_file() {
        // The kernel accepts these, and only these, on a rule whose target is
        // not a directory. Every right besides them acts on a directory's
        // entries.
        assert_eq!(
            fs_access::FILE,
            fs_access::EXECUTE
                | fs_access::WRITE_FILE
                | fs_access::READ_FILE
                | fs_access::TRUNCATE
                | fs_access::IOCTL_DEV,
        );
        // Every grant keeps something on a file, so narrowing one never leaves
        // a rule that permits nothing.
        for access in [FsAccess::READ, FsAccess::WRITE, FsAccess::EXECUTE] {
            assert_ne!(
                access.to_landlock() & fs_access::FILE & fs_access_for_abi(1),
                0
            );
        }
    }

    #[test]
    fn rule_labels_name_filesystem_grants_then_network_grants() {
        // The command stage numbers the rules in the order it adds them,
        // filesystem first, and a reported position indexes these labels.
        let mut request = Request::default();
        request.grant_net(NetAccess::CONNECT, 443);
        request.grant_fs(FsAccess::READ | FsAccess::EXECUTE, Path::new("/usr"));
        request.grant_fs(FsAccess::READ | FsAccess::WRITE, Path::new("/dev/null"));
        let plan = request.lower().unwrap();
        assert_eq!(
            plan.landlock_labels,
            ["rx on /usr", "rw on /dev/null", "c on tcp:443"],
        );
    }

    #[test]
    fn scopes_arrive_together_in_abi_6() {
        assert_eq!(scope_for_abi(5), 0);
        assert_eq!(
            scope_for_abi(6),
            LandlockScope::bits_of(LandlockScope::ALL.iter().copied()),
        );
        assert_eq!(scope_for_abi(9), scope_for_abi(6));
    }

    /// Whether `result` refuses `scope` on a kernel that reported `abi`.
    fn refuses_scope(result: Result<(), ConfigError>, scope: &str, abi: Option<i32>) -> bool {
        matches!(
            result,
            Err(ConfigError::LandlockScopeUnenforceable { scope: refused, abi: reported })
                if refused == scope && reported == abi
        )
    }

    #[test]
    fn a_scope_is_refused_where_the_kernel_cannot_enforce_it() {
        let both = scope::SIGNAL | scope::ABSTRACT_UNIX_SOCKET;
        for abi in [Some(6), Some(9)] {
            assert!(ensure_scopes_enforceable(both, abi).is_ok());
        }
        // Below ABI 6, and with no Landlock at all, every scope is refused,
        // naming the first of them.
        for abi in [None, Some(1), Some(5)] {
            assert!(refuses_scope(
                ensure_scopes_enforceable(scope::SIGNAL, abi),
                "signal",
                abi,
            ));
            assert!(refuses_scope(
                ensure_scopes_enforceable(scope::ABSTRACT_UNIX_SOCKET, abi),
                "abstract-unix-socket",
                abi,
            ));
            assert!(ensure_scopes_enforceable(both, abi).is_err());
            // No scope asked for, nothing to refuse.
            assert!(ensure_scopes_enforceable(0, abi).is_ok());
        }
    }

    #[test]
    fn a_sandbox_refuses_the_signal_scope_only_without_a_pid_namespace() {
        let mut request = Request::default();
        request.set_scope([LandlockScope::Signal]);
        let plan = request.lower().unwrap();
        let unasked = || -> Option<i32> { panic!("the ABI was probed with nothing to check") };

        // Behind a PID namespace the scope is additive, so nothing is checked
        // and the ABI is never probed. Host networking does not change that.
        assert!(
            plan.ensure_sandbox_enforceable(false, false, unasked)
                .is_ok()
        );
        assert!(
            plan.ensure_sandbox_enforceable(true, false, unasked)
                .is_ok()
        );
        // Without one it is the only bound on signalling the host's processes.
        for abi in [None, Some(5)] {
            assert!(refuses_scope(
                plan.ensure_sandbox_enforceable(false, true, || abi),
                "signal",
                abi,
            ));
        }
        assert!(
            plan.ensure_sandbox_enforceable(false, true, || Some(6))
                .is_ok()
        );
    }

    #[test]
    fn a_host_network_sandbox_refuses_what_it_cannot_enforce_on_the_host_network() {
        let unasked = || -> Option<i32> { panic!("the ABI was probed with nothing to check") };

        let mut scoped = Request::default();
        scoped.set_scope([LandlockScope::AbstractUnixSocket]);
        let scoped = scoped.lower().unwrap();
        // In a network namespace of its own, and without a PID namespace, the
        // socket scope is additive.
        assert!(
            scoped
                .ensure_sandbox_enforceable(false, true, unasked)
                .is_ok()
        );
        for abi in [None, Some(5)] {
            assert!(refuses_scope(
                scoped.ensure_sandbox_enforceable(true, false, || abi),
                "abstract-unix-socket",
                abi,
            ));
        }
        assert!(
            scoped
                .ensure_sandbox_enforceable(true, false, || Some(6))
                .is_ok()
        );

        // A network grant needs only ABI 4, so at ABI 5 the grant passes and
        // the scope beside it is what is refused.
        let mut granted = Request::default();
        granted.grant_net(NetAccess::CONNECT, 443);
        let mut both = granted.clone();
        let granted = granted.lower().unwrap();
        assert!(
            granted
                .ensure_sandbox_enforceable(false, true, unasked)
                .is_ok()
        );
        for abi in [None, Some(3)] {
            assert!(matches!(
                granted.ensure_sandbox_enforceable(true, false, || abi),
                Err(ConfigError::HostNetworkLandlockUnenforceable { abi: reported })
                    if reported == abi
            ));
        }
        assert!(
            granted
                .ensure_sandbox_enforceable(true, false, || Some(4))
                .is_ok()
        );
        both.set_scope([LandlockScope::AbstractUnixSocket]);
        let both = both.lower().unwrap();
        assert!(refuses_scope(
            both.ensure_sandbox_enforceable(true, false, || Some(5)),
            "abstract-unix-socket",
            Some(5),
        ));
    }

    #[test]
    fn landlock_scopes_round_trip_by_name() {
        for &scope in LandlockScope::ALL {
            assert_eq!(scope.to_string().parse::<LandlockScope>(), Ok(scope));
        }
        assert_eq!(
            "ABSTRACT_UNIX_SOCKET".parse::<LandlockScope>(),
            Ok(LandlockScope::AbstractUnixSocket),
        );
        let err = "signals".parse::<LandlockScope>().unwrap_err();
        assert_eq!(err.text(), "signals");
        assert!(
            err.to_string().contains("signal, abstract-unix-socket"),
            "{err}"
        );
        // The kernel's own bits, distinct from each other.
        assert_eq!(LandlockScope::AbstractUnixSocket.to_landlock(), 1);
        assert_eq!(LandlockScope::Signal.to_landlock(), 2);
        assert_eq!(
            LandlockScope::bits_of([LandlockScope::Signal, LandlockScope::Signal]),
            scope::SIGNAL,
        );
    }

    #[test]
    fn a_scope_alone_is_hardening_but_not_a_restriction() {
        let mut request = Request::default();
        request.set_scope([LandlockScope::Signal]);
        // A restriction asks for scopes unasked, so they cannot be what saves
        // one from the empty-restriction guard.
        assert!(request.is_unrestricted());
        let plan = request.lower().unwrap();
        assert_eq!(plan.landlock_scoped, scope::SIGNAL);
        assert!(!plan.is_empty());
    }

    #[test]
    fn a_syscall_number_no_filter_can_name_is_refused() {
        // Below zero, past the 32 bits a comparison holds, and at the x32 bit
        // where x86_64's aliases begin: refused, where the compiler backend
        // would panic on the first two.
        for number in [-1, i64::from(u32::MAX) + 1, i64::from(X32_SYSCALL_BIT)] {
            for rules in [
                SeccompRules::denying([number]),
                SeccompRules::allowing([libc::SYS_read]).rule(number, []),
                SeccompRules::denying([]).errno_for(number, 38),
            ] {
                assert!(
                    matches!(
                        compile_seccomp(&SeccompPolicy::Rules(rules)),
                        Err(ConfigError::SeccompInvalid { .. })
                    ),
                    "{number} is refused",
                );
            }
        }
        // The last number below the ceiling is a legitimate one to name.
        assert!(
            compile_seccomp(&SeccompPolicy::Rules(SeccompRules::denying([i64::from(
                X32_SYSCALL_BIT - 1
            )])))
            .is_ok()
        );
    }

    #[test]
    fn a_dword_operand_wider_than_32_bits_is_refused() {
        // A mask of `1 << 32` would truncate to zero and match every call.
        for arg in [
            SeccompArg::masked_eq_dword(0, 1 << 32, 0),
            SeccompArg::eq_dword(0, 1 << 32),
            SeccompArg::eq_dword(0, u64::MAX),
        ] {
            let rules = SeccompRules::denying([]).rule(libc::SYS_clone, [arg]);
            assert!(
                matches!(
                    compile_seccomp(&SeccompPolicy::Rules(rules)),
                    Err(ConfigError::SeccompInvalid { .. })
                ),
                "{arg:?} is refused",
            );
        }
        // The widest 32-bit operands, and a wide one compared as a qword, are
        // all fine.
        for arg in [
            SeccompArg::masked_eq_dword(0, u64::from(u32::MAX), u64::from(u32::MAX)),
            SeccompArg::masked_eq_qword(0, 1 << 32, 0),
        ] {
            let rules = SeccompRules::denying([]).rule(libc::SYS_clone, [arg]);
            assert!(compile_seccomp(&SeccompPolicy::Rules(rules)).is_ok());
        }
    }

    #[test]
    fn the_return_values_are_the_kernels() {
        // The fragments ahead of seccompiler's program return these directly,
        // so they are pinned to `<linux/seccomp.h>`.
        assert_eq!(ret_value(SeccompAction::Allow), 0x7fff_0000);
        assert_eq!(ret_value(SeccompAction::Errno(38)), 0x0005_0026);
        assert_eq!(ret_value(SeccompAction::Log), 0x7ffc_0000);
        assert_eq!(ret_value(SeccompAction::KillThread), 0);
        assert_eq!(ret_value(SeccompAction::KillProcess), 0x8000_0000);
    }

    #[test]
    fn the_errno_prologue_emits_the_expected_instructions() {
        // Hand-emitted like the x32 guard, so asserted exactly. From [1] a
        // match skips [2]; [2] jumps 1 + 2 * 2 = 5 forward, to [8], the first
        // instruction past the prologue; each comparison's false branch skips
        // its own return.
        let errnos = BTreeMap::from([(435, 38), (163, 1)]);
        let prologue = errno_prologue(AUDIT_ARCH_AARCH64, &errnos);
        let insn = |code, jt, jf, k| SockFilter { code, jt, jf, k };
        assert_eq!(
            prologue,
            [
                insn(0x20, 0, 0, 4),
                insn(0x15, 1, 0, AUDIT_ARCH_AARCH64),
                insn(0x05, 0, 0, 5),
                insn(0x20, 0, 0, 0),
                insn(0x15, 0, 1, 163),
                insn(0x06, 0, 0, 0x0005_0001),
                insn(0x15, 0, 1, 435),
                insn(0x06, 0, 0, 0x0005_0026),
            ],
        );
    }

    #[test]
    fn an_errno_prologue_sits_between_the_x32_guard_and_the_filter() {
        let rules = SeccompRules::denying([libc::SYS_acct]).errno_for(libc::SYS_clone3, 38);
        let program = compile_seccomp(&SeccompPolicy::Rules(rules)).unwrap();
        let arch = audit_arch(host_target_arch().unwrap());
        let prologue = errno_prologue(arch, &BTreeMap::from([(libc::SYS_clone3, 38)]));
        let guard = if cfg!(target_arch = "x86_64") { 5 } else { 0 };
        assert_eq!(&program[guard..guard + prologue.len()], &prologue[..]);
        // An errno alone is a restriction: it refuses the syscall it names.
        assert!(
            SeccompPolicy::Rules(SeccompRules::denying([]).errno_for(libc::SYS_clone3, 38))
                .restricts()
        );
    }

    #[test]
    fn a_syscall_both_listed_and_given_an_errno_is_refused() {
        for rules in [
            SeccompRules::denying([libc::SYS_clone3]).errno_for(libc::SYS_clone3, 38),
            SeccompRules::allowing([libc::SYS_read])
                .rule(libc::SYS_clone3, [SeccompArg::eq_qword(1, 0)])
                .errno_for(libc::SYS_clone3, 38),
        ] {
            assert!(matches!(
                compile_seccomp(&SeccompPolicy::Rules(rules)),
                Err(ConfigError::SeccompInvalid { .. })
            ));
        }
    }

    #[test]
    fn an_errno_no_failed_syscall_reports_is_refused() {
        // Zero answers a call with a success it never performed: `getpid`
        // reports pid 0, and a `clone3` caller takes itself for the child.
        // Past 4095 the C library reads the answer as a returned value.
        for errno in [0, MAX_ERRNO + 1, u16::MAX] {
            for (rules, names) in [
                (
                    SeccompRules::denying([]).errno_for(libc::SYS_clone3, errno),
                    format!("syscall number {}", libc::SYS_clone3),
                ),
                (
                    SeccompRules::denying([libc::SYS_acct])
                        .listed_action(SeccompAction::Errno(errno)),
                    "the listed action".to_string(),
                ),
                (
                    SeccompRules::allowing([libc::SYS_read])
                        .default_action(SeccompAction::Errno(errno)),
                    "the default action".to_string(),
                ),
            ] {
                match compile_seccomp(&SeccompPolicy::Rules(rules)) {
                    Err(ConfigError::SeccompInvalid { reason }) => {
                        assert!(reason.contains(&names), "{reason}");
                        assert!(reason.contains(&format!("errno {errno},")), "{reason}");
                    }
                    other => panic!("errno {errno} from {names} is refused: {other:?}"),
                }
            }
        }
        // The two ends of the range are errnos a syscall fails with.
        for errno in [1, MAX_ERRNO] {
            for rules in [
                SeccompRules::denying([]).errno_for(libc::SYS_clone3, errno),
                SeccompRules::denying([libc::SYS_acct]).listed_action(SeccompAction::Errno(errno)),
                SeccompRules::allowing([libc::SYS_read])
                    .default_action(SeccompAction::Errno(errno)),
            ] {
                assert!(
                    compile_seccomp(&SeccompPolicy::Rules(rules)).is_ok(),
                    "{errno}"
                );
            }
        }
    }

    #[test]
    fn the_curated_denylist_reaches_the_newer_mount_and_pidfd_calls() {
        use syscalls::Sysno;
        let list = curated_denylist();
        for sysno in [Sysno::open_tree_attr, Sysno::pidfd_getfd] {
            assert!(list.contains(&(sysno.id() as i64)), "{sysno} is denied");
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use crate::CageBuilder;

    #[test]
    fn the_documented_hardening_table_parses_and_round_trips() {
        // The example the profile adapter's documentation shows, with the keys
        // a sandbox needs around it.
        let profile = r#"
rootfs = "/srv/rootfs"
command = "/bin/sh"

[hardening]
drop-caps = true
landlock-scope = ["signal"]

[hardening.seccomp]
allow = ["execve", "read", "write", "exit_group"]
errno = { clone3 = "ENOSYS" }

[[hardening.seccomp.allow-rule]]
syscall = "ioctl"
[[hardening.seccomp.allow-rule.arg]]
index = 1
len = "dword"
op = "eq"
value = 21523
"#;
        let builder: CageBuilder = toml::from_str(profile).expect("the example parses");
        let written = toml::to_string(&builder).expect("the profile serializes");
        assert!(
            written.contains("landlock-scope = [\"signal\"]"),
            "{written}"
        );
        assert!(written.contains("clone3 = \"ENOSYS\""), "{written}");
        let reread: CageBuilder = toml::from_str(&written).expect("it reads back");
        assert_eq!(toml::to_string(&reread).unwrap(), written);
    }

    #[test]
    fn an_errno_table_alone_is_a_denylist() {
        let profile = r#"
rootfs = "/srv/rootfs"
command = "/bin/sh"

[hardening.seccomp]
errno = { clone3 = "enosys" }
"#;
        let builder: CageBuilder = toml::from_str(profile).expect("an errno alone parses");
        let written = toml::to_string(&builder).unwrap();
        assert!(written.contains("clone3 = \"ENOSYS\""), "{written}");
        assert!(!written.contains("allow"), "{written}");
    }

    #[test]
    fn an_unknown_errno_or_scope_is_refused() {
        // A profile names an errno and does not number one, so no table can
        // spell zero or a number past the range a failed syscall reports.
        for profile in [
            "rootfs = \"/r\"\ncommand = \"/c\"\n[hardening.seccomp]\nerrno = { clone3 = \"ENOPE\" }\n",
            "rootfs = \"/r\"\ncommand = \"/c\"\n[hardening.seccomp]\nerrno = { clone3 = \"0\" }\n",
            "rootfs = \"/r\"\ncommand = \"/c\"\n[hardening.seccomp]\nerrno = { getpid = \"4096\" }\n",
            "rootfs = \"/r\"\ncommand = \"/c\"\n[hardening]\nlandlock-scope = [\"signals\"]\n",
        ] {
            assert!(toml::from_str::<CageBuilder>(profile).is_err(), "{profile}");
        }
    }
}
