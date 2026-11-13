//! The command-stage hardening application: capability drops, Landlock, and
//! seccomp, applied after the pivot and immediately before `execve`.
//!
//! Like the rest of this module, everything here runs in a forked child under
//! the post-fork constraints: no allocation, no libc lock, no panic. The
//! request was compiled and frozen by [`CageBuilder::build`], so this path
//! only opens paths and issues syscalls over the frozen data.
//!
//! Capabilities go through rustix. Landlock uses syscalls rustix does not
//! expose, issued through the `syscalls` crate — a libc-free, allocation-free
//! inline-assembly conduit — over kernel `uapi` structs defined and
//! size-checked here. The seccomp filter goes through [`seccomp::install`],
//! which installs every filter the launch carries.
//!
//! Everything here runs *after* the command has entered its nested user
//! namespace, and that ordering is a requirement rather than a preference.
//! Entering a user namespace has the kernel re-derive the whole credential for
//! the new namespace: the securebits go back to the default — the `_LOCKED` bit
//! wiped with the rest — the bounding set is refilled from the full set, and
//! the inheritable and ambient sets are cleared. Hardening applied before the
//! entry would therefore not merely fail to help; it would be silently undone,
//! and a capability dropped from the bounding set would come back. The entry is
//! the last thing `exec_command` does before calling into this module, and
//! moving it after any of the calls below would quietly disable them.
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

use rustix::fs::{CWD, FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use rustix::thread::{CapabilitiesSecureBits, CapabilitySet, CapabilitySets};
use syscalls::Sysno;

use super::HardeningPlan;
use super::seccomp;
use super::sys::errno;
use crate::error::SetupStep;
use crate::hardening::{fs_access, fs_access_for_abi, net_access_for_abi, scope_for_abi};

/// A failed hardening step: the step, the errno, and the 1-based position of
/// the Landlock rule it was adding, zero when the step has no rule.
///
/// The position counts the filesystem rules first and the network rules after
/// them, which is the order [`HardeningPlan::landlock_labels`] names them in.
type Failure = (SetupStep, Errno, u32);

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
    //
    // A failed read of the inherited bits fails the step rather than standing
    // in an empty set for them. The write below states the whole set, so an
    // empty stand-in clears every unlocked bit already held — among them
    // NOROOT, whose loss restores privilege by uid. A locked bit cannot be
    // cleared, so that much would surface as an EPERM on the write, but the
    // unlocked ones would go silently.
    if plan.set_securebits {
        let inherited = rustix::thread::capabilities_secure_bits()
            .map_err(|errno| (SetupStep::SetSecurebits, errno, 0))?;
        rustix::thread::set_capabilities_secure_bits(
            inherited
                | CapabilitiesSecureBits::NO_SETUID_FIXUP
                | CapabilitiesSecureBits::NO_SETUID_FIXUP_LOCKED,
        )
        .map_err(|errno| (SetupStep::SetSecurebits, errno, 0))?;
    }

    // No-new-privileges: required before Landlock enforcement and an
    // unprivileged seccomp filter, and desirable for a capability drop so a
    // set-user-ID file cannot regain privilege across the exec.
    rustix::thread::set_no_new_privs(true).map_err(|errno| (SetupStep::SetNoNewPrivs, errno, 0))?;

    if !plan.landlock.is_empty() || !plan.landlock_net.is_empty() || plan.landlock_scoped != 0 {
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
            .map_err(|errno| (SetupStep::DropCapabilities, errno, 0))?;
    }

    // Seccomp last: once installed the filter is active, so nothing but the
    // exec runs under it — the identity switch already happened outside its
    // governance. No-new-privileges, set before the switch, is what admits the
    // install once the switch has left the command without CAP_SYS_ADMIN.
    if let Some(program) = &plan.seccomp {
        seccomp::install(program).map_err(|errno| (SetupStep::InstallSeccomp, errno, 0))?;
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
    //
    // A failed query is not that case. It leaves which of the two applies
    // unknown, and answering the unknown with the unprivileged one would drop
    // the narrowing on the very path that needs it, so the query's own failure
    // fails the step.
    let hold_setpcap = rustix::thread::capabilities(None)?
        .effective
        .contains(CapabilitySet::SETPCAP);
    if hold_setpcap {
        // Drop every capability the caller did not keep from the bounding set:
        // every position the kernel's sets hold, not only the capabilities this
        // build names, so one a later kernel adds is dropped as well. A
        // position past the running kernel's last capability answers EINVAL,
        // which is not a failure.
        for capability in every_capability_position() {
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

/// Every position a capability can occupy in the kernel's 64-bit capability
/// sets, each as a set holding that one capability.
///
/// Every capability any kernel can define sits in one of these positions,
/// since the `capget` and `capset` ABI carries the sets as 64 bits, so a
/// capability newer than this build is among them. `CapabilitySet::all()`
/// covers the same bits but iterates the ones rustix does not name as a single
/// set, which no one-capability call accepts.
fn every_capability_position() -> impl Iterator<Item = CapabilitySet> {
    (0..u64::BITS).map(|position| CapabilitySet::from_bits_retain(1 << position))
}

/// `LANDLOCK_CREATE_RULESET_VERSION`: query the supported ABI version.
const LANDLOCK_CREATE_RULESET_VERSION: usize = 1 << 0;
/// `LANDLOCK_RULE_PATH_BENEATH`: a filesystem-hierarchy rule.
const LANDLOCK_RULE_PATH_BENEATH: usize = 1;
/// `LANDLOCK_RULE_NET_PORT`: a TCP-port rule.
const LANDLOCK_RULE_NET_PORT: usize = 2;

/// The kernel's `struct landlock_ruleset_attr`, through the ABI-6 `scoped`
/// field.
///
/// The kernel reads its own `sizeof` from the size passed alongside, and
/// accepts a larger struct from userspace as long as every byte past its own
/// is zero: the forward-compatible extension it uses across every Landlock
/// version. An ABI-1 through ABI-3 kernel expects only `handled_access_fs`,
/// and an ABI-4 or ABI-5 kernel stops before `scoped`. Each field is masked to
/// the running ABI before the call, so on those kernels the fields they do not
/// know are zero. Later fields (the quiet-access masks) stay unmodeled and
/// unread.
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
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
const _: () = assert!(size_of::<LandlockRulesetAttr>() == 24);
const _: () = assert!(size_of::<LandlockPathBeneathAttr>() >= 12);
const _: () = assert!(size_of::<LandlockNetPortAttr>() == 16);

/// Builds and enforces the Landlock ruleset over the frozen grants, filesystem
/// and network alike, and the frozen scopes. A single ruleset governs every
/// kind; each rule's access and the scopes are masked to the running kernel's
/// ABI, and a rule that masks to nothing is skipped.
fn apply_landlock(plan: &HardeningPlan) -> Result<(), Failure> {
    // Query the kernel's supported ABI. ENOSYS (or any error) here means the
    // Landlock LSM is unavailable; a requested restriction that cannot apply
    // is a setup failure, not a silent no-op.
    let abi = landlock_abi().map_err(|errno| (SetupStep::LandlockCreateRuleset, errno, 0))?;
    let fs_mask = fs_access_for_abi(abi);
    let net_mask = net_access_for_abi(abi);

    let handled_fs = plan.landlock_handled & fs_mask;
    let handled_net = plan.landlock_net_handled & net_mask;
    let scoped = plan.landlock_scoped & scope_for_abi(abi);

    // A kernel older than a requested right narrows it away best-effort. When
    // nothing modeled survives the mask, this kernel can enforce none of the
    // request and there is no ruleset to build — the same silent downgrade an
    // unsupported filesystem right receives. Filesystem grants keep their
    // ABI-1 base rights, so an empty ruleset arises only for a request of
    // network grants and scopes alone on a kernel too old for either.
    //
    // Every case where that downgrade would leave a reach genuinely unconfined
    // is refused at build time instead, before any fork: a restriction's grants
    // and the scopes it names (`ensure_landlock_enforceable`,
    // `ensure_scopes_enforceable`), and a sandbox's network grant or scope with
    // no namespace behind it (`ensure_sandbox_enforceable`). What reaches here
    // is a request some namespace also bounds, or a restriction's default
    // scopes, which its build already masked to this kernel; that is why the
    // drop is tolerated. `CageBuilder::landlock_net` and
    // `CageBuilder::landlock_scope` state it for callers.
    if handled_fs == 0 && handled_net == 0 && scoped == 0 {
        return Ok(());
    }

    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_fs,
        handled_access_net: handled_net,
        scoped,
    };
    let ruleset =
        create_ruleset(&attr).map_err(|errno| (SetupStep::LandlockCreateRuleset, errno, 0))?;

    // The rules are numbered from one in the order they are added, filesystem
    // rules first, which is the order the plan's labels name them in.
    let mut position: u32 = 0;
    for rule in &plan.landlock {
        position = position.saturating_add(1);
        let failed = |errno| (SetupStep::LandlockAddRule, errno, position);
        let mut allowed = rule.access & fs_mask;
        if allowed == 0 {
            continue;
        }
        // Post-pivot the sandbox root is `/`, so the grant's absolute path
        // resolves within the sandbox. O_PATH opens the file or directory the
        // rule is tied to. A sandbox's walk follows no link, the last component
        // included: a planted `/var/lib/app -> /` would carry the grant to the
        // whole sandbox view, so the walk answers ELOOP and the rule fails
        // under its grant's name. A restriction resolves its host paths as the
        // host does, through the links the host is laid out with.
        let resolve = if plan.grants_follow_links {
            ResolveFlags::empty()
        } else {
            ResolveFlags::NO_SYMLINKS
        };
        let target = super::resolve::openat2(
            CWD,
            rule.path.as_c_str(),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        )
        .map_err(failed)?;
        // The kernel refuses a rule on anything but a directory that allows a
        // right acting on a directory's entries: `READ` lowers to include
        // listing one, and `WRITE` to creating and removing in one. Narrowed
        // to the rights that act on the file itself, a grant on a file or a
        // device node means what it says.
        if !is_directory(target.as_fd()).map_err(failed)? {
            allowed &= fs_access::FILE;
            if allowed == 0 {
                continue;
            }
        }
        let beneath = LandlockPathBeneathAttr {
            allowed_access: allowed,
            parent_fd: target.as_raw_fd(),
        };
        add_rule(ruleset.as_fd(), &beneath).map_err(failed)?;
    }

    for rule in &plan.landlock_net {
        position = position.saturating_add(1);
        let allowed = rule.access & net_mask;
        if allowed == 0 {
            continue;
        }
        let net_port = LandlockNetPortAttr {
            allowed_access: allowed,
            port: u64::from(rule.port),
        };
        add_net_rule(ruleset.as_fd(), &net_port)
            .map_err(|errno| (SetupStep::LandlockAddRule, errno, position))?;
    }

    restrict_self(ruleset.as_fd()).map_err(|errno| (SetupStep::LandlockRestrictSelf, errno, 0))
}

/// Whether `fd` refers to a directory.
///
/// `fstat` accepts an `O_PATH` descriptor, so the type is read from the very
/// inode the rule will be tied to rather than by looking the path up again.
fn is_directory(fd: BorrowedFd<'_>) -> Result<bool, Errno> {
    let stat = rustix::fs::fstat(fd)?;
    Ok(FileType::from_raw_mode(stat.st_mode) == FileType::Directory)
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
    // SAFETY: the attr pointer and its size describe a valid ruleset attribute,
    // whose fields past the running ABI's are zero; the syscall returns a new
    // owned descriptor on success.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bounding_drop_reaches_every_position_the_sets_hold() {
        let positions: Vec<CapabilitySet> = every_capability_position().collect();
        assert_eq!(positions.len(), 64);
        assert!(
            positions.iter().all(|one| one.bits().count_ones() == 1),
            "each position is one capability: {positions:?}"
        );
        let union = positions
            .iter()
            .fold(CapabilitySet::empty(), |all, one| all | *one);
        assert_eq!(union.bits(), u64::MAX, "every position, each once");
        // The named iteration reaches the positions past the last capability
        // rustix names only as one set, which a bounding-set drop refuses with
        // EINVAL, the answer a capability the kernel lacks also gets.
        assert!(
            CapabilitySet::all()
                .iter()
                .any(|item| item.bits().count_ones() > 1),
            "the named iteration yields each position alone"
        );
    }
}
