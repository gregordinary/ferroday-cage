//! Host support probing for unprivileged user namespaces.
//!
//! The sandbox is built from unprivileged user namespaces, and several common
//! host configurations disable them. [`userns_blocker`] inspects the host for
//! the known ones, so that a denial surfaces as an explanation rather than a
//! raw `EPERM`, and so that test suites can skip sandbox tests explicitly on
//! hosts that cannot run them. [`range_map_blocker`] does the same for
//! uid/gid range maps, whose availability depends on the caller's privilege
//! and, for the delegated tier, on the shadow suite's helpers.

use std::ffi::CString;
use std::fmt;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Mode, OFlags, XattrFlags};
use rustix::io::Errno;
use rustix::rand::GetRandomFlags;

/// A host configuration known to block unprivileged user namespace creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UsernsBlocker {
    /// The `kernel.unprivileged_userns_clone` sysctl is `0`.
    ///
    /// This out-of-tree sysctl appears on Debian-derived kernels; `0` denies
    /// user namespace creation to unprivileged processes.
    UnprivilegedUsernsCloneDisabled,
    /// The `user.max_user_namespaces` sysctl is `0`.
    ///
    /// A limit of zero denies user namespace creation outright.
    MaxUserNamespacesIsZero,
    /// The `user.max_user_namespaces` sysctl is `1`, and a launch needs two.
    ///
    /// The sandbox creates one user namespace, and the command enters a nested
    /// one before it hardens — which is what locks the flags of the mounts the
    /// sandbox established. A namespace is charged against the sysctl at every
    /// level up to the initial namespace, so a ceiling of one admits the first
    /// and refuses the second.
    ///
    /// The condition is necessary and not sufficient, as every blocker here is:
    /// a host whose ceiling is four with three namespaces already live fails
    /// the same way, and only the launch can know that. It surfaces there as
    /// [`Error::NestedUsernsBudgetExhausted`](crate::Error::NestedUsernsBudgetExhausted).
    MaxUserNamespacesBelowNesting,
    /// The `kernel.apparmor_restrict_unprivileged_userns` sysctl is `1`.
    ///
    /// On Ubuntu-derived systems this restricts user namespace creation to
    /// programs granted the capability by an AppArmor profile.
    ApparmorRestrictsUnprivilegedUserns,
}

impl fmt::Display for UsernsBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UsernsBlocker::UnprivilegedUsernsCloneDisabled => {
                "the kernel.unprivileged_userns_clone sysctl is 0; set it to 1 to permit \
                 unprivileged user namespace creation"
            }
            UsernsBlocker::MaxUserNamespacesIsZero => {
                "the user.max_user_namespaces sysctl is 0; raise it to permit user \
                 namespace creation"
            }
            UsernsBlocker::MaxUserNamespacesBelowNesting => {
                "the user.max_user_namespaces sysctl is 1, and every launch holds two user \
                 namespaces: the sandbox's own, and the nested one its command enters to \
                 lock the sandbox's mount flags. Raise the sysctl to at least 2"
            }
            UsernsBlocker::ApparmorRestrictsUnprivilegedUserns => {
                "the kernel.apparmor_restrict_unprivileged_userns sysctl is 1; set it to 0, \
                 or grant this program an AppArmor profile that permits user namespace \
                 creation"
            }
        })
    }
}

/// Probes the host for configurations that block unprivileged user namespace
/// creation, returning the first one identified.
///
/// The probe is best-effort and read-only: it inspects sysctl values and
/// creates no namespaces. `None` means no known blocker was found, not a
/// guarantee that namespace creation succeeds — a seccomp filter or an LSM
/// policy can still deny it. The blockers describe creation by unprivileged
/// processes; a privileged process may be exempt from some of them.
pub fn userns_blocker() -> Option<UsernsBlocker> {
    if sysctl_value("/proc/sys/kernel/unprivileged_userns_clone") == Some(0) {
        return Some(UsernsBlocker::UnprivilegedUsernsCloneDisabled);
    }
    // The budget, not merely its presence: a launch holds two user namespaces,
    // so a ceiling of one admits the sandbox's and refuses the nested one the
    // command enters. Reporting that here turns a launch-time `ENOSPC` into a
    // condition a caller can check for before it starts.
    match sysctl_value("/proc/sys/user/max_user_namespaces") {
        Some(0) => return Some(UsernsBlocker::MaxUserNamespacesIsZero),
        Some(1) => return Some(UsernsBlocker::MaxUserNamespacesBelowNesting),
        _ => {}
    }
    if sysctl_value("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == Some(1) {
        return Some(UsernsBlocker::ApparmorRestrictsUnprivilegedUserns);
    }
    None
}

/// The supported Landlock ABI version, or `None` when the running kernel
/// offers no Landlock security module.
///
/// The version rises as the kernel gains filesystem and network access
/// rights; [`CageBuilder::landlock_fs`] enforces best-effort down to it. A
/// `None` result means a Landlock request is refused rather than applied: at
/// build where Landlock is its only boundary, and at launch otherwise.
///
/// [`CageBuilder::landlock_fs`]: crate::CageBuilder::landlock_fs
#[cfg(feature = "hardening")]
pub fn landlock_abi() -> Option<i32> {
    crate::mechanism::probe_landlock_abi()
}

/// Whether the running kernel offers seccomp syscall filtering.
///
/// `false` means the kernel was built without `CONFIG_SECCOMP` and a seccomp
/// policy would fail to install.
#[cfg(feature = "hardening")]
pub fn seccomp_available() -> bool {
    // PR_GET_SECCOMP answers with the current mode when seccomp is compiled
    // in, and errors when it is not. The probe changes no state.
    rustix::thread::secure_computing_mode().is_ok()
}

/// Reads a sysctl file and parses its leading integer value.
///
/// Returns `None` when the file does not exist, cannot be read, or does not
/// parse; an absent sysctl is simply not part of this host's configuration.
fn sysctl_value(path: &str) -> Option<i64> {
    let contents = std::fs::read_to_string(path).ok()?;
    contents.split_whitespace().next()?.parse().ok()
}

/// A host condition known to make a uid/gid range map unavailable.
///
/// The single-identity map needs none of this; the conditions concern the
/// range tiers: writing a map directly requires capabilities over the parent
/// user namespace, and delegating to the shadow suite requires working,
/// privileged helpers and a subordinate allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RangeMapBlocker {
    /// The library was built without the `subid` feature, and the caller
    /// holds no capabilities over its user namespace.
    ///
    /// Without the feature the only bundled delegate writes maps directly,
    /// which requires `CAP_SETUID` and `CAP_SETGID` — running as root, or
    /// inside an already range-mapped namespace.
    SubidFeatureDisabled,
    /// The calling process runs under `no_new_privs`, so the shadow suite's
    /// helpers run without their privilege.
    ///
    /// A helper holds its privilege as a setuid bit or a file capability, and
    /// an exec under `no_new_privs` honours neither, so every map it is asked to
    /// write fails with `EPERM`. The flag is inherited and cannot be cleared:
    /// a process started under a service manager's `NoNewPrivileges=` setting,
    /// or by a launcher that set it, has it for good. The remedy is to start
    /// the caller without it.
    NoNewPrivileges,
    /// A shadow suite helper is not on `PATH`.
    ///
    /// The commonest cause is a container runtime installed without its
    /// recommended packages. The helpers ship with the shadow suite's
    /// subordinate-id tools: `uidmap` on Debian, Devuan, and Ubuntu,
    /// `shadow-subids` on Alpine, `shadow` elsewhere.
    #[non_exhaustive]
    HelperMissing {
        /// The missing helper, `newuidmap` or `newgidmap`.
        helper: &'static str,
    },
    /// A helper exists but holds no privilege.
    ///
    /// A working helper is either setuid-root or carries the needed
    /// capability as a file capability; this one is neither. openSUSE's
    /// `shadow.paranoid` permissions profile ships the helpers this way,
    /// and a copy that did not preserve `security.*` extended attributes
    /// loses a file capability while leaving the file looking intact.
    #[non_exhaustive]
    HelperUnprivileged {
        /// The unprivileged helper.
        path: PathBuf,
    },
    /// A subordinate file is a symbolic link, which the helpers refuse.
    ///
    /// `newuidmap` opens the file with `O_NOFOLLOW` and reports the
    /// refusal as a missing-privilege error, obscuring the real cause.
    #[non_exhaustive]
    SubordinateFileSymlink {
        /// The offending file, `/etc/subuid` or `/etc/subgid`.
        path: &'static str,
    },
    /// The calling user has no subordinate id allocation.
    NoSubordinateAllocation,
    /// The caller's subordinate allocation could not be determined at all.
    ///
    /// Distinct from [`NoSubordinateAllocation`](Self::NoSubordinateAllocation),
    /// which is the query answering that there is none. This is the query
    /// failing to answer: `getsubids` exists but did not report, or
    /// `nsswitch.conf` sources subordinate ids from a module beyond `files` and
    /// `getsubids` — the only tool that consults it — is not installed. On such
    /// a host the subordinate files are not the authority, so the remedy is to
    /// install `getsubids`, not to add entries to them.
    #[non_exhaustive]
    SubordinateAllocationUnknown {
        /// What the query could not do, and what would let it.
        reason: String,
    },
}

impl fmt::Display for RangeMapBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RangeMapBlocker::SubidFeatureDisabled => f.write_str(
                "the caller holds no CAP_SETUID/CAP_SETGID over its user namespace, and the \
                 library was built without the `subid` feature, so no delegate can establish \
                 a range map; enable the feature, or run with those capabilities",
            ),
            RangeMapBlocker::NoNewPrivileges => f.write_str(
                "the calling process runs under no_new_privs, so newuidmap and newgidmap run \
                 without the setuid bit or file capability that is their privilege; start the \
                 caller without the flag",
            ),
            RangeMapBlocker::HelperMissing { helper } => write!(
                f,
                "{helper} was not found on PATH; install the shadow suite's subordinate-id \
                 helpers (packaged as uidmap on Debian and Ubuntu, shadow-subids on Alpine, \
                 and shadow on most other distributions)",
            ),
            RangeMapBlocker::HelperUnprivileged { path } => write!(
                f,
                "{} is neither setuid-root nor granted a file capability, so it cannot \
                 establish maps; reinstall the shadow suite's subordinate-id helpers or \
                 restore the packaged privilege",
                path.display(),
            ),
            RangeMapBlocker::SubordinateFileSymlink { path } => write!(
                f,
                "{path} is a symbolic link, which the shadow helpers refuse to follow; make \
                 it a regular file",
            ),
            RangeMapBlocker::NoSubordinateAllocation => f.write_str(
                "the calling user has no subordinate id allocation; grant one with \
                 usermod --add-subuids and --add-subgids, or entries in /etc/subuid and \
                 /etc/subgid",
            ),
            RangeMapBlocker::SubordinateAllocationUnknown { reason } => write!(
                f,
                "the calling user's subordinate id allocation could not be determined: {reason}",
            ),
        }
    }
}

/// A host condition known to prevent an unprivileged overlay-rooted cage.
///
/// A cage rooted on an overlay ([`CageBuilder::overlay_rootfs`]) mounts an
/// overlay from inside its user namespace. Two host properties gate that, and
/// each maps to a variant here.
///
/// [`CageBuilder::overlay_rootfs`]: crate::CageBuilder::overlay_rootfs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OverlayBlocker {
    /// An unprivileged overlay mount was refused.
    ///
    /// The running kernel predates unprivileged overlay in a user namespace
    /// (before Linux 5.11), or the overlay filesystem is otherwise unavailable.
    Unsupported,
    /// The upper layer's filesystem does not support the `user.*` extended-
    /// attribute namespace.
    ///
    /// An unprivileged overlay records its metadata — whiteouts and opaque
    /// markers — in `user.*` xattrs. tmpfs gained support for them only in
    /// Linux 6.6; an on-disk filesystem (ext4, xfs, btrfs) supports them
    /// throughout. Place the overlay's upper layer on such a filesystem, or use
    /// a newer kernel.
    UpperUnsupported,
}

impl fmt::Display for OverlayBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OverlayBlocker::Unsupported => {
                "the kernel refused an unprivileged overlay mount; overlay in a user namespace \
                 needs Linux 5.11 or later"
            }
            OverlayBlocker::UpperUnsupported => {
                "the upper layer's filesystem does not support user.* extended attributes, which \
                 an unprivileged overlay records its metadata in; put the upper on an on-disk \
                 filesystem such as ext4, xfs, or btrfs, or use Linux 6.6 or later for a tmpfs \
                 upper"
            }
        })
    }
}

/// Probes the host for a condition that prevents an unprivileged overlay-rooted
/// cage whose upper layer sits on the filesystem hosting `scratch_dir`.
///
/// `scratch_dir` is a directory on the filesystem the overlay's upper layer
/// will live on; the probe tests that filesystem for `user.*` xattr support and
/// forks a throwaway child that attempts an unprivileged overlay mount. It
/// returns the first blocker found, or `None` when an overlay-rooted cage should
/// be establishable.
///
/// The probe is best-effort. It creates and removes temporary files and
/// directories under `scratch_dir` and forks a short-lived child, but changes no
/// durable state; `None` is the absence of a known blocker, not a guarantee.
/// When the probe cannot set up a user namespace to test in — because
/// unprivileged user namespaces are themselves unavailable — it returns `None`
/// and leaves that diagnosis to [`userns_blocker`], the boundary that owns it.
/// Test suites use it to skip overlay tests explicitly on hosts that cannot run
/// them, as they use [`userns_blocker`] and [`range_map_blocker`].
pub fn overlay_blocker(scratch_dir: impl AsRef<Path>) -> Option<OverlayBlocker> {
    let scratch_dir = scratch_dir.as_ref();
    // The upper-filesystem gate first: it is a direct, fork-free xattr write on
    // the target filesystem, and it identifies the specific "upper cannot record
    // metadata" case a bare mount test would miss (a pre-6.6 tmpfs mounts but
    // cannot record whiteouts).
    if upper_lacks_user_xattr(scratch_dir) {
        return Some(OverlayBlocker::UpperUnsupported);
    }
    // The mount gate: can an unprivileged overlay mount at all on this kernel?
    if overlay_mount_refused(scratch_dir) {
        return Some(OverlayBlocker::Unsupported);
    }
    None
}

/// Opens `dir` as a directory descriptor for the work below to anchor against.
///
/// `dir` is the caller's to name, so reaching it through a symlink is the
/// caller's business; what the descriptor buys is that every entry created,
/// inspected, or removed within it resolves relative to one directory, with no
/// path walk another user of a shared directory can step into.
fn open_dir(dir: &Path) -> rustix::io::Result<OwnedFd> {
    rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// A probe entry name: `prefix` followed by 16 hex digits of kernel entropy.
///
/// Every probe entry is created exclusively — `O_EXCL` for the xattr probe's
/// file, `mkdirat` for the mount probe's directory — so an unpredictable name is
/// not what makes the probe safe against a hostile neighbour. It is what keeps
/// one from parking a squatter at a name the probe is bound to choose and
/// turning the preflight into a standing denial of service.
fn probe_name(prefix: &str) -> String {
    format!("{prefix}{}", unique_hex())
}

/// Sixteen hex digits distinguishing one call from every other, for naming a
/// filesystem entry no concurrent caller may collide with.
///
/// The kernel's randomness is combined with, rather than substituted for, a seed
/// that is already unique per call: the process id in the high half distinguishes
/// concurrent processes, and a process-wide counter in the low half distinguishes
/// calls within one process, which threads sharing a pid would not be. Combining
/// the two by exclusive-or keeps the claim in the first sentence true on a host
/// where `getrandom` fails: the outcome is then the seed combined with whatever
/// [`fill_random`] managed, still unique.
///
/// Uniqueness is not what makes the naming safe in any case: every caller
/// creates its entry with `O_EXCL` or `mkdirat` and treats a collision as a
/// failure. What it buys is that a neighbour cannot park a squatter at a name
/// this is bound to choose.
pub(crate) fn unique_hex() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Distinguishes calls within one process, where the pid cannot.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut random = [0u8; 8];
    // A failure is tolerated: the seed alone keeps the name unique, and the
    // randomness only makes it unpredictable.
    let _ = fill_random(&mut random);
    let seed = (u64::from(std::process::id()) << 32)
        | (COUNTER.fetch_add(1, Ordering::Relaxed) & u64::from(u32::MAX));
    format!("{:016x}", seed ^ u64::from_ne_bytes(random))
}

/// Fills `buf` from the kernel's randomness.
///
/// A short read is resumed where it stopped, and `EINTR` is retried. A read of
/// nothing into a buffer with room left is not an answer `getrandom` documents,
/// so it is reported as `EIO` rather than retried, which would spin. What a
/// failure leaves filled stays in `buf`.
///
/// What a failure means is the caller's to decide. [`unique_hex`] carries on
/// without the randomness, since its seed is unique already, while the network
/// stack refuses to start without the entropy its TCP sequence numbers need.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), Errno> {
    fill_from(buf, |rest| {
        // The call `clippy.toml` sends every other site here for: this is that
        // answer.
        #[expect(clippy::disallowed_methods)]
        rustix::rand::getrandom(rest, GetRandomFlags::empty())
    })
}

/// The body of [`fill_random`], with each read made by `read`.
///
/// Split so the answers the kernel rarely gives, a short read, an
/// interruption, and a read of nothing, are reachable from a test.
fn fill_from(
    buf: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> Result<usize, Errno>,
) -> Result<(), Errno> {
    let mut filled = 0;
    while filled < buf.len() {
        match read(&mut buf[filled..]) {
            Ok(0) => return Err(Errno::IO),
            Ok(read) => filled += read,
            Err(Errno::INTR) => {}
            Err(errno) => return Err(errno),
        }
    }
    Ok(())
}

/// Whether the filesystem hosting `dir` refuses a `user.*` extended attribute,
/// the condition that makes it unable to back an unprivileged overlay.
///
/// A write that succeeds, or fails for any reason other than the namespace being
/// unsupported (a full disk, a permission quirk), is not treated as a blocker:
/// the probe reports only the specific unsupported-namespace signal.
fn upper_lacks_user_xattr(dir: &Path) -> bool {
    let Ok(parent) = open_dir(dir) else {
        // Cannot even open the directory: inconclusive, not a blocker.
        return false;
    };
    let name = probe_name(".fcage-xattr-probe-");
    let Ok(probe) = create_probe_file(&parent, &name) else {
        // Cannot write here at all: inconclusive, not a blocker.
        return false;
    };
    // The attribute goes on the descriptor rather than the name, so the write
    // cannot land anywhere the exclusive create did not reach.
    let result = rustix::fs::fsetxattr(&probe, "user.fcage.probe", b"1", XattrFlags::empty());
    drop(probe);
    let _ = rustix::fs::unlinkat(&parent, name.as_str(), AtFlags::empty());
    matches!(result, Err(errno) if crate::mechanism::xattr_unsupported(errno))
}

/// Creates the xattr probe's file at `name` under `parent`, refusing anything
/// already there.
///
/// `O_EXCL | O_NOFOLLOW`: the scratch directory may be shared with other local
/// users, so the probe must only ever hold a file it created itself. Anything
/// already at the name — a regular file, or a symlink aimed at a file the caller
/// can write — fails the create with `EEXIST` instead of being truncated and
/// written through.
fn create_probe_file(parent: &OwnedFd, name: &str) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
}

/// Whether an unprivileged overlay mount is refused on this host, tested by
/// mounting a throwaway overlay under `scratch_dir` in a forked child.
///
/// Returns `false` when the mount succeeds and when the probe is inconclusive —
/// it could not lay out the test directories, or could not create a user
/// namespace to test in — so only a genuine mount refusal reads as a blocker.
fn overlay_mount_refused(scratch_dir: &Path) -> bool {
    let Ok(parent) = open_dir(scratch_dir) else {
        return false;
    };
    let name = probe_name(".fcage-overlay-probe-");
    // `mkdirat` refuses a name that already exists — including one another user
    // planted as a symlink — so, like the xattr probe's `O_EXCL` create, the
    // probe works only inside a directory it created itself. Mode `0700` keeps
    // the layer directories laid out below out of a neighbour's reach.
    if rustix::fs::mkdirat(&parent, name.as_str(), Mode::RWXU).is_err() {
        return false;
    }

    // The mount syscall names its layers as paths, so the layout below is
    // path-based; it is safe because this base directory is fresh, private, and
    // unpredictably named.
    let base = scratch_dir.join(&name);
    let outcome = overlay_mount_probe(&base);
    // The mount leaves a mode-`0` directory in its work area. Empty, it goes
    // as the calling user; anything left inside it is what the single-map
    // escalation clears. Best effort: the verdict does not depend on it.
    let _ = crate::provision::remove_tree(&base, &crate::IdentityMap::Single, None);
    matches!(outcome, Some(crate::mechanism::OverlayProbe::MountFailed))
}

/// Lays out the probe's lower, upper, work, and merged directories under `base`
/// and runs the fork-based mount test, returning its outcome or `None` when the
/// layout could not be prepared.
///
/// `base` was just created empty and private by [`overlay_mount_refused`], so
/// each layer directory is created outright: a name already taken is a surprise
/// worth failing on, not something to reuse.
fn overlay_mount_probe(base: &Path) -> Option<crate::mechanism::OverlayProbe> {
    let dir = |name: &str| {
        let path = base.join(name);
        std::fs::create_dir(&path).ok().map(|()| path)
    };
    let lower = dir("lower")?;
    let upper = dir("upper")?;
    let work = dir("work")?;
    let merged = dir("merged")?;

    // A scratch path the option string cannot carry leaves the probe
    // inconclusive rather than reported as a mount refusal.
    let options = crate::mechanism::overlay_options(&[lower], &upper, &work).ok()?;
    let merged = CString::new(merged.as_os_str().as_bytes()).ok()?;
    Some(crate::mechanism::probe_overlay_mount(&merged, &options))
}

/// Probes the host for conditions that make a uid/gid range map unavailable,
/// returning the first one identified.
///
/// Returns `None` when a range map should be establishable: the caller holds
/// `CAP_SETUID` and `CAP_SETGID` in its effective set (enough to write a map
/// directly), or (with the `subid` feature) the shadow suite's helpers are
/// present, privileged, and backed by an allocation.
///
/// The capability check reflects the effective set only. The direct tier and
/// the kernel's map write both require the capabilities effective and do not
/// raise them from the permitted set, so a caller that has parked them in
/// `permitted` — after a privilege-lowering wrapper, say — reads as needing
/// the delegate until it raises them into effective itself.
///
/// A map naming the parent namespace's uid 0 among its outside ids needs
/// `CAP_SETFCAP` as well. That is a property of the request, which the probe
/// does not know: for a direct write the build judges it. Only a root caller's
/// own uid is outside uid 0, so an unprivileged caller's delegated map never
/// names it. A root caller's exec of a helper grants every capability in its
/// bounding set, whatever capabilities the helper's file carries, unless the
/// caller set `SECBIT_NOROOT`. shadow's helpers keep `CAP_SETFCAP` for such a
/// map since shadow 4.9. So a helper's own file capabilities do not decide it,
/// and the probe does not read them for it.
///
/// The probe is best-effort and read-only; `None` is an absence of known
/// blockers, not a guarantee.
pub fn range_map_blocker() -> Option<RangeMapBlocker> {
    // A caller holding CAP_SETUID and CAP_SETGID in its effective set writes
    // maps directly; nothing else matters. The effective set is the right
    // question here because the direct tier requires the capabilities
    // effective and does not raise them from permitted (see `DirectMapper`).
    if let Ok(sets) = rustix::thread::capabilities(None)
        && sets
            .effective
            .contains(rustix::thread::CapabilitySet::SETUID)
        && sets
            .effective
            .contains(rustix::thread::CapabilitySet::SETGID)
    {
        return None;
    }

    #[cfg(not(feature = "subid"))]
    {
        Some(RangeMapBlocker::SubidFeatureDisabled)
    }
    #[cfg(feature = "subid")]
    {
        delegated_blocker()
    }
}

/// The delegated-tier checks behind [`range_map_blocker`]: whatever stops the
/// helpers themselves, then the allocation.
#[cfg(feature = "subid")]
fn delegated_blocker() -> Option<RangeMapBlocker> {
    if let Some(blocker) = helper_blocker() {
        return Some(blocker);
    }

    match crate::idmap::probe_allocation() {
        None => {}
        Some((_, crate::idmap::AllocationUnusable::Empty)) => {
            return Some(RangeMapBlocker::NoSubordinateAllocation);
        }
        // The query could not answer, which is a different diagnosis from an
        // empty allocation and has a different remedy — most often "install
        // getsubids", on a host whose subordinate ids come from a directory
        // service rather than from the files. Reporting the empty-allocation
        // blocker here would advise adding /etc/subuid entries, which on such a
        // host is wrong twice over: the user may well have an allocation, and
        // the files are not the authority.
        Some((kind, unusable)) => {
            return Some(RangeMapBlocker::SubordinateAllocationUnknown {
                reason: unusable.to_string(kind),
            });
        }
    }

    None
}

/// Why the shadow suite's helpers cannot establish a map on this host, or
/// `None` when nothing known stands in their way.
///
/// The conditions are the caller's own `no_new_privs`, a helper absent from
/// `PATH` or holding no privilege, and a subordinate file the helpers refuse to
/// open. Each one fails every map the helpers are asked to write, whatever the
/// request and whatever the allocation.
///
/// The one answer to whether the helpers can work here.
/// [`SubidMapper`](crate::SubidMapper)'s `resolve` asks it before it reports a
/// map, so a build and a provisioner's preflight refuse a host the launch would
/// fail on. [`range_map_blocker`] asks it before the allocation, so the probe
/// and the delegate name the same condition. A helper is judged at the path
/// [`find_on_path`] resolves, which is the path the delegate executes.
#[cfg(feature = "subid")]
pub(crate) fn helper_blocker() -> Option<RangeMapBlocker> {
    use rustix::thread::CapabilitySet;

    // First, since it defeats every helper whatever the helper's own state.
    if crate::idmap::no_new_privs() {
        return Some(RangeMapBlocker::NoNewPrivileges);
    }

    for (helper, capability) in [
        ("newuidmap", CapabilitySet::SETUID),
        ("newgidmap", CapabilitySet::SETGID),
    ] {
        let Some(path) = find_on_path(helper) else {
            return Some(RangeMapBlocker::HelperMissing { helper });
        };
        if helper_privilege(&path, capability) == HelperPrivilege::None {
            return Some(RangeMapBlocker::HelperUnprivileged { path });
        }
    }

    for path in ["/etc/subuid", "/etc/subgid"] {
        if std::fs::symlink_metadata(path)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Some(RangeMapBlocker::SubordinateFileSymlink { path });
        }
    }

    None
}

/// How a shadow helper holds its privilege, if at all.
///
/// A file-capability helper needs only the one capability its map file asks
/// for. `CAP_SETFCAP` matters only to a map naming the parent namespace's uid 0,
/// which is a root caller's, and a root caller's exec does not take its
/// capabilities from the file; see [`range_map_blocker`].
#[cfg(feature = "subid")]
#[derive(Debug, PartialEq, Eq)]
enum HelperPrivilege {
    /// Setuid-root: full privilege when run.
    SetuidRoot,
    /// File capabilities carrying the needed `CAP_SETUID`/`CAP_SETGID`.
    FileCaps,
    /// Neither: the helper cannot work.
    None,
}

/// The `VFS_CAP_FLAGS_EFFECTIVE` bit of a `security.capability` attribute's
/// magic word: the file's capabilities are raised in the effective set at exec,
/// rather than merely permitted for a program that raises them itself.
#[cfg(feature = "subid")]
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;

/// Determines a helper's privilege: the setuid bit, or the needed capability
/// in its `security.capability` extended attribute. Podman's probe accepts
/// either, and so does this one; a mode check alone would misreport
/// capability-based installations (Alpine's, for one) as unprivileged.
#[cfg(feature = "subid")]
fn helper_privilege(
    path: &std::path::Path,
    capability: rustix::thread::CapabilitySet,
) -> HelperPrivilege {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if let Ok(meta) = std::fs::metadata(path)
        && meta.uid() == 0
        && meta.permissions().mode() & 0o4000 != 0
    {
        return HelperPrivilege::SetuidRoot;
    }

    let mut buf = [0u8; 40];
    let Ok(len) = rustix::fs::getxattr(path, "security.capability", &mut buf[..]) else {
        return HelperPrivilege::None;
    };
    file_capability_privilege(&buf[..len], capability)
}

/// What a helper's `security.capability` attribute grants it, for a helper
/// that needs `capability`.
///
/// The attribute is a little-endian magic/version word, then per-word
/// permitted and inheritable masks. `CAP_SETUID` and `CAP_SETGID` both live in
/// the low word, the attribute's second `u32`.
#[cfg(feature = "subid")]
fn file_capability_privilege(
    attribute: &[u8],
    capability: rustix::thread::CapabilitySet,
) -> HelperPrivilege {
    let (Some(magic), Some(permitted_low)) = (attribute.get(0..4), attribute.get(4..8)) else {
        return HelperPrivilege::None;
    };
    let magic = u32::from_le_bytes(magic.try_into().expect("slice length is 4"));
    // The effective bit rides in the magic word. Without it the capability is
    // permitted but not raised at exec, so a helper that is not itself
    // capability-aware — and `newuidmap` is not — runs without it and fails.
    // Reporting such a helper as privileged would have the probe name no
    // blocker where there is one.
    if magic & VFS_CAP_FLAGS_EFFECTIVE == 0 {
        return HelperPrivilege::None;
    }
    let permitted_low = u32::from_le_bytes(permitted_low.try_into().expect("slice length is 4"));
    if u64::from(permitted_low) & capability.bits() == 0 {
        return HelperPrivilege::None;
    }
    HelperPrivilege::FileCaps
}

/// Finds an executable on `PATH`, returning its absolute path.
///
/// Shared by the probe above and by the delegate that executes the helper, so
/// the binary whose privilege the probe judged is the one chosen by the same
/// rules — a probe describing a different binary from the one that runs is a
/// verdict about nothing.
///
/// Only absolute `PATH` entries are searched. An empty or relative entry names
/// the process's working directory, and resolving a privileged helper against
/// whatever directory the process happens to be in is not a lookup this should
/// perform; [`spec::search_candidates`](crate::spec) takes the same position for
/// the sandbox's own path lookup, for the same reason.
#[cfg(feature = "subid")]
pub(crate) fn find_on_path(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if !dir.is_absolute() {
            continue;
        }
        let candidate = dir.join(name);
        if let Ok(meta) = std::fs::metadata(&candidate)
            && meta.is_file()
            && meta.permissions().mode() & 0o111 != 0
        {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    #[test]
    fn probe_runs_without_panicking() {
        // The result is host-dependent; the probe itself must always be safe
        // to call.
        let _ = userns_blocker();
    }

    /// A `security.capability` attribute of the second revision: the magic
    /// word with the effective flag where asked for, then the permitted and
    /// inheritable masks of the low and high words.
    #[cfg(feature = "subid")]
    fn capability_attribute(effective: bool, permitted_low: u32) -> Vec<u8> {
        const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
        let flags = if effective {
            VFS_CAP_FLAGS_EFFECTIVE
        } else {
            0
        };
        let magic = VFS_CAP_REVISION_2 | flags;
        [magic, permitted_low, 0, 0, 0]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    /// shadow installs `newuidmap` with `cap_setuid+ep` and nothing else, and
    /// that helper writes every map an unprivileged caller can ask for: only a
    /// map naming the parent's uid 0 needs `CAP_SETFCAP`, and that map is a
    /// root caller's, whose exec does not take its capabilities from the file.
    #[cfg(feature = "subid")]
    #[test]
    fn a_helper_granted_only_its_own_capability_is_a_working_one() {
        use rustix::thread::CapabilitySet;

        let setuid = u32::try_from(CapabilitySet::SETUID.bits()).expect("a low-word capability");
        let setgid = u32::try_from(CapabilitySet::SETGID.bits()).expect("a low-word capability");
        assert_eq!(
            file_capability_privilege(&capability_attribute(true, setuid), CapabilitySet::SETUID),
            HelperPrivilege::FileCaps,
        );
        assert_eq!(
            file_capability_privilege(&capability_attribute(true, setgid), CapabilitySet::SETGID),
            HelperPrivilege::FileCaps,
        );

        // The capability the map file asks for is the one that counts.
        assert_eq!(
            file_capability_privilege(&capability_attribute(true, setgid), CapabilitySet::SETUID),
            HelperPrivilege::None,
        );
        // Permitted but not raised at exec, which `newuidmap` does not do itself.
        assert_eq!(
            file_capability_privilege(&capability_attribute(false, setuid), CapabilitySet::SETUID),
            HelperPrivilege::None,
        );
        // An attribute too short to carry a permitted mask grants nothing.
        assert_eq!(
            file_capability_privilege(
                &capability_attribute(true, setuid)[..6],
                CapabilitySet::SETUID
            ),
            HelperPrivilege::None,
        );
    }

    #[test]
    fn overlay_probe_runs_without_panicking_and_cleans_up() {
        // The result is host-dependent, but the probe — which forks a child and
        // creates temporary files and directories — must always be safe to call
        // and must leave nothing behind under the scratch directory.
        let dir = Scratch::new("overlay-probe");
        let _ = overlay_blocker(&dir);
        // No probe residue remains in the scratch directory.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(
            leftovers.is_empty(),
            "the overlay probe left {} entries behind",
            leftovers.len(),
        );
    }

    #[test]
    fn unique_hex_distinguishes_calls_within_one_process() {
        // The doc comment promises a name no concurrent caller collides with,
        // and the promise has to hold when `getrandom` is unavailable — where
        // the entropy is the seed alone. A pid seed cannot distinguish two calls
        // in one process, so the process-wide counter is what makes this true
        // rather than the randomness.
        let names: std::collections::HashSet<String> = (0..1000).map(|_| unique_hex()).collect();
        assert_eq!(names.len(), 1000, "unique_hex repeated a name");
        assert!(names.iter().all(|name| name.len() == 16));
    }

    #[test]
    fn a_fill_resumes_a_short_read_where_it_stopped() {
        // Three bytes at a time, counting up, so a fill that restarted rather
        // than resumed would overwrite what it had and leave the tail zero.
        let mut next = 1u8;
        let mut buf = [0u8; 8];
        fill_from(&mut buf, |rest| {
            let take = rest.len().min(3);
            for byte in &mut rest[..take] {
                *byte = next;
                next += 1;
            }
            Ok(take)
        })
        .expect("the fill completes");
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn a_fill_retries_an_interruption_and_reports_a_failure() {
        let mut interrupted = false;
        let mut buf = [0u8; 4];
        fill_from(&mut buf, |rest| match interrupted {
            false => {
                interrupted = true;
                Err(Errno::INTR)
            }
            true => {
                rest.fill(7);
                Ok(rest.len())
            }
        })
        .expect("an interruption is retried");
        assert_eq!(buf, [7; 4]);

        assert_eq!(
            fill_from(&mut buf, |_| Err(Errno::NOSYS)),
            Err(Errno::NOSYS),
            "any other failure is the caller's to judge",
        );
    }

    #[test]
    fn a_read_of_nothing_ends_the_fill_rather_than_spinning() {
        let mut reads = 0;
        let mut buf = [0u8; 8];
        let outcome = fill_from(&mut buf, |_| {
            reads += 1;
            assert!(reads < 100, "the fill spun on a read of nothing");
            Ok(0)
        });
        assert_eq!(outcome, Err(Errno::IO));
        assert_eq!(reads, 1);
    }

    #[test]
    fn the_kernels_randomness_fills_a_buffer() {
        let mut buf = [0u8; 64];
        fill_random(&mut buf).expect("the kernel's randomness is available");
        assert!(buf.iter().any(|&byte| byte != 0));
        // An empty buffer asks nothing of the kernel.
        fill_random(&mut []).expect("nothing to fill");
    }

    #[test]
    fn probe_names_differ_between_calls() {
        // The names carry kernel entropy, not just a pid, so a neighbour in a
        // shared scratch directory cannot predict — and squat on — the next one.
        let first = probe_name(".fcage-probe-");
        let second = probe_name(".fcage-probe-");
        assert!(first.starts_with(".fcage-probe-"));
        assert_ne!(first, second);
    }

    #[test]
    fn the_xattr_probe_refuses_a_planted_name() {
        // A neighbour who guesses the probe's name must not have the probe write
        // through what it finds there. Both plants are refused outright, and the
        // symlink's target survives intact.
        let dir = Scratch::new("plant");
        std::fs::write(dir.join("victim"), b"intact").unwrap();
        std::os::unix::fs::symlink("victim", dir.join("link")).unwrap();
        std::fs::write(dir.join("regular"), b"mine").unwrap();

        let parent = open_dir(&dir).unwrap();
        for name in ["link", "regular"] {
            assert_eq!(
                create_probe_file(&parent, name).map(|_| ()),
                Err(rustix::io::Errno::EXIST),
                "the probe created {name} over a planted entry",
            );
        }
        assert_eq!(std::fs::read(dir.join("victim")).unwrap(), b"intact");

        // The mount probe's directory is created the same way, and `mkdirat`
        // refuses a planted name for the same reason.
        assert_eq!(
            rustix::fs::mkdirat(&parent, "link", Mode::RWXU),
            Err(rustix::io::Errno::EXIST),
        );
    }

    #[test]
    fn sysctl_value_parses_a_leading_integer() {
        // max_user_namespaces exists on any modern kernel and holds a
        // non-negative integer.
        if let Some(value) = sysctl_value("/proc/sys/user/max_user_namespaces") {
            assert!(value >= 0);
        }
    }

    #[test]
    fn sysctl_value_is_none_for_missing_files() {
        assert_eq!(sysctl_value("/proc/sys/ferroday/cage/does_not_exist"), None);
    }
}
