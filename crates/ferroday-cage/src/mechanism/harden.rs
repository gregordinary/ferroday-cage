//! The command-stage hardening application: capability drops, Landlock, and
//! seccomp, applied after the pivot and immediately before `execve`.
//!
//! Like the rest of this module, everything here runs in a forked child under
//! the post-fork constraints: no allocation, no libc lock, no panic. The
//! request was compiled and frozen by [`CageBuilder::build`], so this path
//! only opens paths and issues syscalls over the frozen data.
//!
//! Capabilities go through rustix. Landlock and the seccomp filter install use
//! syscalls rustix does not expose, issued through the `syscalls` crate — a
//! libc-free, allocation-free inline-assembly conduit — over kernel `uapi`
//! structs defined and size-checked here.
//!
//! The hardening applies in two halves around the identity switch, and the
//! order within them is fixed by the kernel's rules. Before the switch:
//! lock the securebits that preserve capabilities across a uid change (they
//! need `CAP_SETPCAP`, and the coming switch must not strip the sets the
//! rest of the sequence relies on), set no-new-privileges (which Landlock
//! enforcement and an unprivileged seccomp filter both require), and enforce
//! Landlock, whose grant paths are opened while still root inside. After the
//! switch: drop capabilities — the bounding-set edit needs an effective
//! `CAP_SETPCAP`, which the securebits preserved — and install the seccomp
//! filter last, so the active filter governs only `execve` and what follows
//! it, and never the switch itself.
//!
//! [`CageBuilder::build`]: crate::CageBuilder::build

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use rustix::thread::{CapabilitiesSecureBits, CapabilitySet, CapabilitySets};
use syscalls::Sysno;

use super::HardeningPlan;
use crate::error::SetupStep;
use crate::hardening::{fs_access_for_abi, net_access_for_abi};

/// A failed hardening step: the step and the errno.
type Failure = (SetupStep, Errno);

/// Applies the hardening that precedes the identity switch: securebits,
/// no-new-privileges, and Landlock.
pub(super) fn apply_pre_switch(plan: &HardeningPlan) -> Result<(), Failure> {
    if plan.is_empty() {
        return Ok(());
    }

    // The securebits, while CAP_SETPCAP is effective: NO_SETUID_FIXUP keeps
    // the capability sets across the coming uid switch — without it the
    // switch would clear them, and with them the kept set and the
    // bounding-set edit that follows the switch. The locked variant keeps
    // the command from clearing the bit and restoring the default fixup.
    // Set only when a non-root run-as identity is combined with a
    // capability keep set; inherited bits are preserved, since a locked
    // inherited bit cannot be cleared.
    if plan.set_securebits {
        let inherited =
            rustix::thread::capabilities_secure_bits().unwrap_or(CapabilitiesSecureBits::empty());
        rustix::thread::set_capabilities_secure_bits(
            inherited
                | CapabilitiesSecureBits::NO_SETUID_FIXUP
                | CapabilitiesSecureBits::NO_SETUID_FIXUP_LOCKED,
        )
        .map_err(|errno| (SetupStep::SetSecurebits, errno))?;
    }

    // No-new-privileges: required before Landlock enforcement and an
    // unprivileged seccomp filter, and desirable for a capability drop so a
    // set-user-ID file cannot regain privilege across the exec.
    rustix::thread::set_no_new_privs(true).map_err(|errno| (SetupStep::SetNoNewPrivs, errno))?;

    if !plan.landlock.is_empty() || !plan.landlock_net.is_empty() {
        apply_landlock(plan)?;
    }

    Ok(())
}

/// Applies the hardening that follows the identity switch: the capability
/// drop and the seccomp filter.
pub(super) fn apply_post_switch(plan: &HardeningPlan) -> Result<(), Failure> {
    if plan.is_empty() {
        return Ok(());
    }

    // The capability drop. With a non-root identity the securebits above
    // preserved the full sets across the switch, so CAP_SETPCAP is still
    // effective for the bounding-set edit; without a switch this is the
    // same drop at the same privilege as always.
    if let Some(keep) = plan.keep_caps {
        drop_capabilities(CapabilitySet::from_bits_retain(keep))
            .map_err(|errno| (SetupStep::DropCapabilities, errno))?;
    }

    // Seccomp last: once installed the filter is active, so nothing but the
    // exec runs under it — the identity switch already happened outside its
    // governance.
    if let Some(program) = &plan.seccomp {
        install_seccomp(program).map_err(|errno| (SetupStep::InstallSeccomp, errno))?;
    }

    Ok(())
}

/// Reduces the command's capabilities to `keep`, dropping the rest from the
/// bounding, ambient, permitted, effective, and inheritable sets.
///
/// The bounding set is narrowed first, when the thread holds `CAP_SETPCAP` (a
/// cage always does at this point; an unprivileged restriction does not, and
/// there the narrowing is neither possible nor needed). The permitted,
/// effective, and inheritable sets are then reduced to `keep` — a reduction
/// that never requires a capability — and the kept capabilities are raised into
/// the ambient set so they survive the coming `execve` of a file that carries
/// no file capabilities.
fn drop_capabilities(keep: CapabilitySet) -> Result<(), Errno> {
    // Narrowing the bounding set needs CAP_SETPCAP. In a cage the switch
    // preserved it (a mapped-root identity holds it; a non-root identity keeps
    // it across the switch via the securebits), so the edit runs. In a
    // restriction the caller may be unprivileged and hold no CAP_SETPCAP; there
    // the bounding set cannot be narrowed, but it need not be — the capset
    // reduction below still empties the permitted, effective, and inheritable
    // sets, and the no-new-privileges flag keeps a set-user-ID or file-caps
    // exec from raising anything the wide bounding set would still admit. Skip
    // the edit rather than fail on an EPERM the reduction already covers.
    let hold_setpcap = rustix::thread::capabilities(None)
        .map(|sets| sets.effective.contains(CapabilitySet::SETPCAP))
        .unwrap_or(false);
    if hold_setpcap {
        // Drop every known capability the caller did not keep from the bounding
        // set. A capability the running kernel does not define answers EINVAL,
        // which is not a failure.
        for capability in CapabilitySet::all().iter() {
            if !keep.contains(capability) {
                match rustix::thread::remove_capability_from_bounding_set(capability) {
                    Ok(()) | Err(Errno::INVAL) => {}
                    Err(errno) => return Err(errno),
                }
            }
        }
    }

    // Narrow the thread's capability sets to exactly the kept set. Reducing a
    // capability set never requires a capability.
    rustix::thread::set_capabilities(
        None,
        CapabilitySets {
            effective: keep,
            permitted: keep,
            inheritable: keep,
        },
    )?;

    // Rebuild the ambient set: clear it, then raise the kept capabilities so
    // they carry across the exec. An empty keep set leaves the ambient set
    // cleared.
    rustix::thread::clear_ambient_capability_set()?;
    for capability in keep.iter() {
        rustix::thread::configure_capability_in_ambient_set(capability, true)?;
    }
    Ok(())
}

/// `LANDLOCK_CREATE_RULESET_VERSION`: query the supported ABI version.
const LANDLOCK_CREATE_RULESET_VERSION: usize = 1 << 0;
/// `LANDLOCK_RULE_PATH_BENEATH`: a filesystem-hierarchy rule.
const LANDLOCK_RULE_PATH_BENEATH: usize = 1;
/// `LANDLOCK_RULE_NET_PORT`: a TCP-port rule.
const LANDLOCK_RULE_NET_PORT: usize = 2;

/// The kernel's `struct landlock_ruleset_attr`, through the ABI-4
/// `handled_access_net` field.
///
/// The kernel reads its own `sizeof` from the size passed alongside: an ABI-1
/// through ABI-3 kernel expects only `handled_access_fs`, and accepts this
/// larger struct because its trailing `handled_access_net` is zero there, the
/// same forward-compatible extension the kernel uses across every Landlock
/// version. Later fields (`scoped`, and the quiet-access masks) stay unmodeled
/// and unread.
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

/// The kernel's `struct landlock_path_beneath_attr`.
///
/// The kernel copies its own `sizeof` (the `u64` then the `i32`, twelve
/// bytes); this `repr(C)` struct's first twelve bytes match, and the trailing
/// padding is never read.
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// The kernel's `struct landlock_net_port_attr`: the rights allowed on a TCP
/// port, and the port itself in host endianness.
#[repr(C)]
struct LandlockNetPortAttr {
    allowed_access: u64,
    port: u64,
}

// The layouts must match the kernel's, or a rule would be misissued.
const _: () = assert!(size_of::<LandlockRulesetAttr>() == 16);
const _: () = assert!(size_of::<LandlockPathBeneathAttr>() >= 12);
const _: () = assert!(size_of::<LandlockNetPortAttr>() == 16);

/// Builds and enforces the Landlock ruleset over the frozen grants, filesystem
/// and network alike. A single ruleset governs both access kinds; each rule's
/// access is masked to the running kernel's ABI, and a rule that masks to
/// nothing is skipped.
fn apply_landlock(plan: &HardeningPlan) -> Result<(), Failure> {
    // Query the kernel's supported ABI. ENOSYS (or any error) here means the
    // Landlock LSM is unavailable; a requested restriction that cannot apply
    // is a setup failure, not a silent no-op.
    let abi = landlock_abi().map_err(|errno| (SetupStep::LandlockCreateRuleset, errno))?;
    let fs_mask = fs_access_for_abi(abi);
    let net_mask = net_access_for_abi(abi);

    let handled_fs = plan.landlock_handled & fs_mask;
    let handled_net = plan.landlock_net_handled & net_mask;

    // A kernel older than a requested right narrows it away best-effort. When
    // nothing modeled survives the mask, this kernel can enforce none of the
    // request and there is no ruleset to build — the same silent downgrade an
    // unsupported filesystem right receives. Filesystem grants keep their
    // ABI-1 base rights, so an empty handled set arises only for a
    // network-only request on a kernel below ABI 4.
    //
    // The two cases where that downgrade would leave the command genuinely
    // unconfined are refused at build time instead, before any fork: the
    // restriction fallback (`ensure_landlock_enforceable`) and a host-network
    // cage (`ensure_host_net_enforceable`). What reaches here is a cage whose
    // network namespace remains the boundary, which is why the drop is
    // tolerated; `CageBuilder::landlock_net` states it for callers.
    if handled_fs == 0 && handled_net == 0 {
        return Ok(());
    }

    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_fs,
        handled_access_net: handled_net,
    };
    let ruleset =
        create_ruleset(&attr).map_err(|errno| (SetupStep::LandlockCreateRuleset, errno))?;

    for rule in &plan.landlock {
        let allowed = rule.access & fs_mask;
        if allowed == 0 {
            continue;
        }
        // Post-pivot the sandbox root is `/`, so the grant's absolute path
        // resolves within the sandbox. O_PATH opens the file or directory the
        // rule is tied to; the kernel accepts either.
        let target = rustix::fs::open(
            rule.path.as_c_str(),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| (SetupStep::LandlockAddRule, errno))?;
        let beneath = LandlockPathBeneathAttr {
            allowed_access: allowed,
            parent_fd: target.as_raw_fd(),
        };
        add_rule(ruleset.as_fd(), &beneath).map_err(|errno| (SetupStep::LandlockAddRule, errno))?;
    }

    for rule in &plan.landlock_net {
        let allowed = rule.access & net_mask;
        if allowed == 0 {
            continue;
        }
        let net_port = LandlockNetPortAttr {
            allowed_access: allowed,
            port: u64::from(rule.port),
        };
        add_net_rule(ruleset.as_fd(), &net_port)
            .map_err(|errno| (SetupStep::LandlockAddRule, errno))?;
    }

    restrict_self(ruleset.as_fd()).map_err(|errno| (SetupStep::LandlockRestrictSelf, errno))
}

/// The supported Landlock ABI version, or `None` when the kernel offers no
/// Landlock LSM. Backs [`crate::host::landlock_abi`] and the tests' skips.
pub(crate) fn probe_landlock_abi() -> Option<i32> {
    landlock_abi().ok()
}

/// Queries the kernel's supported Landlock ABI version.
fn landlock_abi() -> Result<i32, Errno> {
    // SAFETY: a version query passes a null attr, zero size, and the version
    // flag; it creates no ruleset and returns the ABI as a small integer.
    let version = unsafe {
        syscalls::syscall!(
            Sysno::landlock_create_ruleset,
            0usize,
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION
        )
    }
    .map_err(errno)?;
    Ok(version as i32)
}

/// Creates a Landlock ruleset from the attribute, returning its descriptor.
fn create_ruleset(attr: &LandlockRulesetAttr) -> Result<OwnedFd, Errno> {
    // SAFETY: the attr pointer and its size describe a valid ABI-1 ruleset
    // attribute; the syscall returns a new owned descriptor on success.
    let fd = unsafe {
        syscalls::syscall!(
            Sysno::landlock_create_ruleset,
            attr as *const LandlockRulesetAttr,
            size_of::<LandlockRulesetAttr>(),
            0usize
        )
    }
    .map_err(errno)?;
    // SAFETY: the syscall returned a fresh, owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Adds one path-beneath rule to the ruleset.
fn add_rule(ruleset: BorrowedFd<'_>, beneath: &LandlockPathBeneathAttr) -> Result<(), Errno> {
    // SAFETY: the attr pointer references a valid path-beneath attribute whose
    // parent_fd is open for the duration of the call.
    unsafe {
        syscalls::syscall!(
            Sysno::landlock_add_rule,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            beneath as *const LandlockPathBeneathAttr,
            0usize
        )
    }
    .map(|_| ())
    .map_err(errno)
}

/// Adds one TCP-port rule to the ruleset.
fn add_net_rule(ruleset: BorrowedFd<'_>, net_port: &LandlockNetPortAttr) -> Result<(), Errno> {
    // SAFETY: the attr pointer references a valid net-port attribute for the
    // duration of the call; it owns no descriptor and borrows no memory beyond
    // itself.
    unsafe {
        syscalls::syscall!(
            Sysno::landlock_add_rule,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_NET_PORT,
            net_port as *const LandlockNetPortAttr,
            0usize
        )
    }
    .map(|_| ())
    .map_err(errno)
}

/// Enforces the ruleset on the calling thread and its future children.
fn restrict_self(ruleset: BorrowedFd<'_>) -> Result<(), Errno> {
    // SAFETY: a plain enforcement of an owned ruleset descriptor; no memory is
    // referenced.
    unsafe { syscalls::syscall!(Sysno::landlock_restrict_self, ruleset.as_raw_fd(), 0usize) }
        .map(|_| ())
        .map_err(errno)
}

/// `SECCOMP_SET_MODE_FILTER`: install a classic BPF filter.
const SECCOMP_SET_MODE_FILTER: usize = 1;

/// The kernel's `struct sock_fprog`: a filter program's length and pointer.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const super::SockFilter,
}

// The layout must match the kernel's, or the install would read a program
// length and a program address the caller never wrote. The size is stated
// against the pointer's own, since the padding between the two fields is the
// pointer's alignment: sixteen bytes on a 64-bit target, eight on a 32-bit
// one. The offsets pin the fields inside it, so a field added or widened
// fails the build even where the total happens to come out the same.
const _: () = {
    let pointer = size_of::<*const super::SockFilter>();
    assert!(size_of::<SockFprog>() == 2 * pointer);
    assert!(std::mem::offset_of!(SockFprog, len) == 0);
    assert!(std::mem::offset_of!(SockFprog, filter) == pointer);
};

/// Installs the compiled seccomp filter on the command process.
fn install_seccomp(program: &[super::SockFilter]) -> Result<(), Errno> {
    // The program length fits a u16: `compile_seccomp` rejected anything over
    // `BPF_MAXINSNS` (4096) at build time, so this narrowing cannot wrap.
    let fprog = SockFprog {
        len: program.len() as u16,
        filter: program.as_ptr(),
    };
    // SAFETY: the fprog points at the frozen program for the call's duration;
    // no-new-privileges was set above, so the unprivileged install is allowed.
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

/// Converts a `syscalls` errno into the rustix errno the rest of the
/// mechanism speaks.
fn errno(err: syscalls::Errno) -> Errno {
    Errno::from_raw_os_error(err.into_raw())
}
