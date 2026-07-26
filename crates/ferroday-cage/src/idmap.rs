//! Identity maps: how the sandbox's user namespace presents uids and gids,
//! and the delegate seam through which range maps are established.
//!
//! The default map is [`IdentityMap::Single`]: root inside the sandbox is the
//! calling user outside, and no other id exists. The kernel permits an
//! unprivileged process to write exactly that map and nothing more — one
//! extent, of one id, naming the writer's own effective id — so any richer
//! map must be written from outside the new namespace by a party that holds
//! `CAP_SETUID`/`CAP_SETGID` over its parent. [`IdMapper`] is that party's
//! seam: [`CageBuilder::id_mapper`] accepts any implementation, and the
//! library bundles two.
//!
//! [`DirectMapper`] writes the map itself, in process. It succeeds when the
//! caller already holds the needed capabilities over the parent user
//! namespace — running as root, or running inside another range-mapped
//! namespace.
//!
//! `SubidMapper` (behind the `subid` feature) delegates to the shadow
//! suite's privileged `newuidmap`/`newgidmap` helpers, which apply the
//! subordinate-id allocation an administrator granted in `/etc/subuid` and
//! `/etc/subgid`. It is the only route to a range map for an ordinary
//! unprivileged caller, and the one feature of this crate that executes an
//! external binary.
//!
//! Without a configured mapper, [`CageBuilder::build`] resolves a range
//! request through the bundled delegates in that order. The fallback is
//! between delegates, never between tiers: a range request no delegate can
//! satisfy is a configuration error, not a quiet downgrade to the
//! single-identity map.
//!
//! [`CageBuilder::id_mapper`]: crate::CageBuilder::id_mapper
//! [`CageBuilder::build`]: crate::CageBuilder::build

use std::fmt;

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::error::ConfigError;

/// The kernel's ceiling on identity-map extents, `UID_GID_MAP_MAX_EXTENTS`.
///
/// A map file accepts at most this many lines (five before Linux 4.16; this
/// crate requires 5.6 or later, where the limit is 340).
pub(crate) const MAX_EXTENTS: usize = 340;

/// How the sandbox's user namespace maps identities to the host's.
///
/// Selected with [`CageBuilder::identity_map`]. The single-identity map is
/// established by the sandbox itself; every range map is established from
/// outside the new namespace by an [`IdMapper`], because the kernel does not
/// permit a process to write its own multi-id map — not even a process that
/// was privileged before it unshared.
///
/// [`CageBuilder::identity_map`]: crate::CageBuilder::identity_map
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", try_from = "profile::IdentityMapWire")
)]
pub enum IdentityMap {
    /// Root inside is the calling user outside, and no other id exists.
    /// This is the default.
    ///
    /// Reads of host ids outside the map present the overflow id (`nobody`),
    /// and changing a file's ownership to any other id fails with `EINVAL`,
    /// because the namespace cannot represent the id at all.
    #[default]
    Single,
    /// Explicit ranges, written verbatim.
    ///
    /// Both lists must be non-empty, map inside-id 0, stay within the
    /// kernel's 340-extent ceiling, and contain no overlapping extents.
    /// The configured [`IdMapper`] decides whether the outside ids are
    /// available to it.
    ///
    /// Construct this variant with [`IdentityMap::ranges`]. It is
    /// `#[non_exhaustive]` so that a further extent list — the kernel has
    /// `projid_map` alongside `uid_map` and `gid_map` — can be added without
    /// breaking callers; match it with a trailing `..`.
    #[non_exhaustive]
    Ranges {
        /// The uid extents.
        uid: Vec<IdRange>,
        /// The gid extents.
        gid: Vec<IdRange>,
    },
    /// Root plus the caller's whole subordinate allocation, as the delegate
    /// reports it.
    ///
    /// The composed map is `0` to the caller's own id, then inside ids from
    /// `1` onward covering each allocated range in order. Requires a
    /// delegate that can report an allocation; the bundled one is
    /// `SubidMapper`, behind the `subid` feature.
    Subordinate,
}

impl IdentityMap {
    /// Returns an explicit range map of the given uid and gid extents.
    ///
    /// The constructor for [`IdentityMap::Ranges`], which is
    /// `#[non_exhaustive]` so it can gain a further extent list later.
    ///
    /// # Example
    ///
    /// ```
    /// use ferroday_cage::{IdRange, IdentityMap};
    ///
    /// let root = IdRange { inside: 0, outside: 1000, count: 1 };
    /// let rest = IdRange { inside: 1, outside: 100_000, count: 65_536 };
    /// let map = IdentityMap::ranges(vec![root, rest], vec![root, rest]);
    /// ```
    pub fn ranges(uid: Vec<IdRange>, gid: Vec<IdRange>) -> IdentityMap {
        IdentityMap::Ranges { uid, gid }
    }
}

/// One contiguous mapping: `count` ids starting at `inside` within the
/// sandbox correspond to `count` ids starting at `outside` on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub struct IdRange {
    /// The first id inside the sandbox.
    #[cfg_attr(feature = "serde", serde(rename = "inside"))]
    pub inside: u32,
    /// The first id on the host.
    #[cfg_attr(feature = "serde", serde(rename = "outside"))]
    pub outside: u32,
    /// How many consecutive ids the extent covers.
    #[cfg_attr(feature = "serde", serde(rename = "count"))]
    pub count: u32,
}

/// The identity the command executes as inside the sandbox.
///
/// Configured with [`CageBuilder::run_as`]; the default is root inside. The
/// switch sits within the hardening layer, after securebits,
/// no-new-privileges, and Landlock and before the capability drop and the
/// seccomp filter, so it is the identity the command holds from its first
/// instruction. Every id must be mapped:
/// [`CageBuilder::build`](crate::CageBuilder::build) rejects an identity the
/// configured [`IdentityMap`] cannot represent.
///
/// # Example
///
/// ```
/// use ferroday_cage::Identity;
///
/// let identity = Identity::new(250, 250).groups([250, 100]);
/// ```
///
/// [`CageBuilder::run_as`]: crate::CageBuilder::run_as
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub struct Identity {
    /// The uid the command runs as, a sandbox-inside id.
    #[cfg_attr(feature = "serde", serde(rename = "uid"))]
    pub(crate) uid: u32,
    /// The gid the command runs as, a sandbox-inside id.
    #[cfg_attr(feature = "serde", serde(rename = "gid"))]
    pub(crate) gid: u32,
    /// The supplementary groups, sandbox-inside ids. Requires a range gid
    /// map: the single-identity map denies `setgroups`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    #[cfg_attr(feature = "serde", serde(rename = "groups"))]
    pub(crate) groups: Vec<u32>,
}

impl Identity {
    /// Returns an identity of the given uid and gid, with no supplementary
    /// groups.
    pub fn new(uid: u32, gid: u32) -> Identity {
        Identity {
            uid,
            gid,
            groups: Vec::new(),
        }
    }

    /// Sets the supplementary groups.
    ///
    /// Supplementary groups require a range gid map; under the
    /// single-identity map `setgroups` is denied and any groups are rejected
    /// at build time.
    pub fn groups<I: IntoIterator<Item = u32>>(mut self, groups: I) -> Identity {
        self.groups = groups.into_iter().collect();
        self
    }
}

/// A resolved identity map: the extents a delegate will establish, known at
/// build time.
///
/// Produced by [`IdMapper::resolve`] and consumed by [`IdMapper::apply`].
/// Resolution happens in [`CageBuilder::build`], so the ranges are available
/// for validating [`run_as`](crate::CageBuilder::run_as) before any launch.
///
/// A delegate constructs one with [`new`](Self::new) and the crate reads it
/// back through [`uid`](Self::uid) and [`gid`](Self::gid). The fields are
/// private, and the struct `#[non_exhaustive]`, so a further extent list can
/// be added without breaking the delegates that build one.
///
/// [`CageBuilder::build`]: crate::CageBuilder::build
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedMap {
    /// The uid extents, in the order they are written.
    uid: Vec<IdRange>,
    /// The gid extents, in the order they are written.
    gid: Vec<IdRange>,
}

impl ResolvedMap {
    /// Returns a resolved map of the given uid and gid extents, in the order
    /// they are to be written.
    pub fn new(uid: Vec<IdRange>, gid: Vec<IdRange>) -> ResolvedMap {
        ResolvedMap { uid, gid }
    }

    /// The uid extents, in the order they are written.
    pub fn uid(&self) -> &[IdRange] {
        &self.uid
    }

    /// The gid extents, in the order they are written.
    pub fn gid(&self) -> &[IdRange] {
        &self.gid
    }
}

/// Establishes a user namespace's identity map on behalf of a caller that
/// cannot write one itself.
///
/// The kernel permits a multi-extent map to be written only from outside the
/// namespace, by a process holding `CAP_SETUID`/`CAP_SETGID` over its
/// parent. Implementations of this trait are that outside party: the
/// launch holds the freshly-unshared sandbox at an internal gate, calls
/// [`apply`](Self::apply) against its pid, and releases it once the map is
/// in place.
///
/// The bundled implementations are [`DirectMapper`] and, behind the `subid`
/// feature, `SubidMapper`. A caller with site-specific machinery — a
/// privileged broker, a different helper — supplies its own through
/// [`CageBuilder::id_mapper`].
///
/// # Stability
///
/// Every method added to this trait in a later release will carry a default
/// body, so an existing implementation keeps compiling. The two existing
/// methods take their inputs as loose parameters because those inputs are
/// closed: a resolution is a request, and an application is a process and the
/// extents to write it. Anything richer arrives as a new defaulted method.
///
/// [`CageBuilder::id_mapper`]: crate::CageBuilder::id_mapper
pub trait IdMapper: fmt::Debug + Send + Sync {
    /// The ranges this delegate can provide for the request.
    ///
    /// Called from [`CageBuilder::build`], so a map that cannot be satisfied
    /// is a configuration error rather than a launch failure. The returned
    /// map is validated against the same rules as an explicit
    /// [`IdentityMap::Ranges`].
    ///
    /// [`CageBuilder::build`]: crate::CageBuilder::build
    fn resolve(&self, request: &IdentityMap) -> Result<ResolvedMap, IdMapError>;

    /// Applies the resolved map to a process sitting in a fresh, unmapped
    /// user namespace.
    ///
    /// `pid` names a process that has unshared its user namespace and is
    /// blocked waiting for the map; the launch machinery guarantees it stays
    /// blocked until this call returns. The map files are write-once, so the
    /// whole map must land in one write per file.
    fn apply(&self, pid: u32, map: &ResolvedMap) -> Result<(), IdMapError>;
}

/// An identity-map delegate failure.
///
/// Returned by [`IdMapper`] implementations. A `resolve` failure surfaces
/// from [`CageBuilder::build`] as
/// [`ConfigError::IdentityMapUnavailable`](crate::ConfigError::IdentityMapUnavailable);
/// an `apply` failure surfaces from the launch as
/// [`Error::IdentityMap`](crate::Error::IdentityMap).
///
/// [`CageBuilder::build`]: crate::CageBuilder::build
#[derive(Debug)]
#[non_exhaustive]
pub enum IdMapError {
    /// The delegate cannot satisfy the request, and says why.
    #[non_exhaustive]
    Unsatisfiable {
        /// What the delegate is missing: privilege, an allocation, a
        /// queryable source.
        reason: String,
    },
    /// A helper binary could not be executed.
    #[non_exhaustive]
    HelperSpawn {
        /// The helper that failed to start.
        helper: String,
        /// The raw OS error the spawn failed with.
        errno: i32,
    },
    /// A helper binary ran and refused the map.
    #[non_exhaustive]
    HelperFailed {
        /// The helper that refused.
        helper: String,
        /// What the helper reported on standard error, trimmed.
        detail: String,
    },
    /// Writing a map file failed.
    #[non_exhaustive]
    MapWrite {
        /// The file that could not be written: `"uid_map"` or `"gid_map"`.
        which: &'static str,
        /// The raw OS error the write failed with.
        errno: i32,
    },
}

impl IdMapError {
    /// The delegate cannot satisfy the request, and says why.
    ///
    /// The refusal every delegate needs: `reason` names what is missing —
    /// privilege, an allocation, a queryable source — and surfaces verbatim in
    /// the configuration error the build reports.
    pub fn unsatisfiable(reason: impl Into<String>) -> IdMapError {
        IdMapError::Unsatisfiable {
            reason: reason.into(),
        }
    }

    /// A helper binary could not be executed.
    pub fn helper_spawn(helper: impl Into<String>, errno: i32) -> IdMapError {
        IdMapError::HelperSpawn {
            helper: helper.into(),
            errno,
        }
    }

    /// A helper binary ran and refused the map.
    pub fn helper_failed(helper: impl Into<String>, detail: impl Into<String>) -> IdMapError {
        IdMapError::HelperFailed {
            helper: helper.into(),
            detail: detail.into(),
        }
    }

    /// Writing a map file failed. `which` is `"uid_map"` or `"gid_map"`.
    pub fn map_write(which: &'static str, errno: i32) -> IdMapError {
        IdMapError::MapWrite { which, errno }
    }
}

impl fmt::Display for IdMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdMapError::Unsatisfiable { reason } => f.write_str(reason),
            IdMapError::HelperSpawn { helper, errno } => write!(
                f,
                "could not execute {helper}: {}",
                std::io::Error::from_raw_os_error(*errno),
            ),
            IdMapError::HelperFailed { helper, detail } => {
                if detail.is_empty() {
                    write!(f, "{helper} refused the map")
                } else {
                    write!(f, "{helper} refused the map: {detail}")
                }
            }
            IdMapError::MapWrite { which, errno } => write!(
                f,
                "could not write {which}: {}",
                std::io::Error::from_raw_os_error(*errno),
            ),
        }
    }
}

impl std::error::Error for IdMapError {}

/// Whether `id` falls inside one of the extents' inside ranges.
pub(crate) fn maps_inside_id(ranges: &[IdRange], id: u32) -> bool {
    ranges
        .iter()
        .any(|range| id >= range.inside && id - range.inside < range.count)
}

/// Validates one extent list: non-empty, positive counts, no arithmetic
/// wrap, inside-id 0 present, at most [`MAX_EXTENTS`] extents, and no
/// overlap on either side of the mapping.
///
/// `which` names the list (`"uid"` or `"gid"`) in the reason.
fn validate_ranges(which: &str, ranges: &[IdRange]) -> Result<(), String> {
    if ranges.is_empty() {
        return Err(format!("the {which} range list is empty"));
    }
    if ranges.len() > MAX_EXTENTS {
        return Err(format!(
            "the {which} range list has {} extents, over the kernel maximum of {MAX_EXTENTS}",
            ranges.len(),
        ));
    }
    for range in ranges {
        if range.count == 0 {
            return Err(format!(
                "the {which} extent at inside id {} has a zero count",
                range.inside,
            ));
        }
        if range.inside.checked_add(range.count - 1).is_none()
            || range.outside.checked_add(range.count - 1).is_none()
        {
            return Err(format!(
                "the {which} extent at inside id {} wraps the id space",
                range.inside,
            ));
        }
    }
    if !maps_inside_id(ranges, 0) {
        return Err(format!(
            "the {which} map does not contain inside id 0; the sandbox is built as root inside",
        ));
    }
    check_overlap(which, "inside", ranges, |range| range.inside)?;
    check_overlap(which, "outside", ranges, |range| range.outside)
}

/// Rejects overlapping extents on one side of a mapping, `key` selecting
/// which side is examined.
fn check_overlap(
    which: &str,
    side: &str,
    ranges: &[IdRange],
    key: fn(&IdRange) -> u32,
) -> Result<(), String> {
    let mut sorted: Vec<&IdRange> = ranges.iter().collect();
    sorted.sort_by_key(|range| key(range));
    for pair in sorted.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        if key(a) + (a.count - 1) >= key(b) {
            return Err(format!(
                "the {which} extents at {side} ids {} and {} overlap",
                key(a),
                key(b),
            ));
        }
    }
    Ok(())
}

/// Validates a requested identity map's structure.
///
/// Single and subordinate maps carry no ranges to validate; explicit ranges
/// are checked against the kernel's rules so a map the kernel would refuse
/// is a typed configuration error instead of a launch failure.
pub(crate) fn validate_request(map: &IdentityMap) -> Result<(), ConfigError> {
    match map {
        IdentityMap::Single | IdentityMap::Subordinate => Ok(()),
        IdentityMap::Ranges { uid, gid } => {
            for (which, ranges) in [("uid", uid), ("gid", gid)] {
                validate_ranges(which, ranges)
                    .map_err(|reason| ConfigError::IdentityMapInvalid { reason })?;
            }
            Ok(())
        }
    }
}

/// Validates the map a delegate resolved, with the same rules as an explicit
/// range request.
///
/// A delegate is caller-supplied code; a malformed resolution is reported as
/// the delegate's defect rather than passed to the kernel.
pub(crate) fn validate_resolved(map: &ResolvedMap) -> Result<(), ConfigError> {
    for (which, ranges) in [("uid", map.uid()), ("gid", map.gid())] {
        validate_ranges(which, ranges).map_err(|reason| ConfigError::IdentityMapInvalid {
            reason: format!("the identity-map delegate resolved an invalid map: {reason}"),
        })?;
    }
    Ok(())
}

/// Formats an extent list as the kernel map-file text: one `inside outside
/// count` line per extent.
pub(crate) fn format_map(ranges: &[IdRange]) -> Vec<u8> {
    let mut text = String::new();
    for range in ranges {
        text.push_str(&format!(
            "{} {} {}\n",
            range.inside, range.outside, range.count
        ));
    }
    text.into_bytes()
}

/// Opens `path` and writes `data` in a single `write`, as the map files
/// require: they accept the whole map in one write and nothing else.
fn write_map_file(path: &str, which: &'static str, data: &[u8]) -> Result<(), IdMapError> {
    let map_write = |errno: Errno| IdMapError::map_write(which, errno.raw_os_error());
    let fd = rustix::fs::open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(map_write)?;
    match rustix::io::write(&fd, data) {
        Ok(n) if n == data.len() => Ok(()),
        Ok(_) => Err(map_write(Errno::IO)),
        Err(errno) => Err(map_write(errno)),
    }
}

/// The in-process delegate: the caller writes the sandbox's map itself.
///
/// Writing another process's map requires `CAP_SETUID` and `CAP_SETGID`
/// over the user namespace the new one is a child of — the caller's own
/// namespace. A process running as root holds them; so does a process
/// running inside a range-mapped user namespace, over that namespace, which
/// is what lets a cage nested inside a range-mapped cage (or a rootless
/// container) establish a range map on its own.
///
/// [`resolve`](IdMapper::resolve) checks the capabilities and, where the
/// caller's own namespace has a readable map, that the requested outside ids
/// exist in it, so an unsatisfiable request fails at build time with the
/// reason. `DirectMapper` cannot serve [`IdentityMap::Subordinate`]:
/// reporting an allocation is the subordinate delegate's business.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct DirectMapper;

impl DirectMapper {
    /// Returns the direct delegate.
    pub fn new() -> DirectMapper {
        DirectMapper
    }
}

impl IdMapper for DirectMapper {
    fn resolve(&self, request: &IdentityMap) -> Result<ResolvedMap, IdMapError> {
        let (uid, gid) = match request {
            IdentityMap::Single => {
                return Err(IdMapError::unsatisfiable(
                    "the single-identity map is established in process and needs no \
                             delegate"
                        .to_string(),
                ));
            }
            IdentityMap::Subordinate => {
                return Err(IdMapError::unsatisfiable(
                    "the direct mapper cannot report a subordinate allocation".to_string(),
                ));
            }
            IdentityMap::Ranges { uid, gid } => (uid.clone(), gid.clone()),
        };

        let effective = rustix::thread::capabilities(None)
            .map(|sets| sets.effective)
            .unwrap_or_else(|_| rustix::thread::CapabilitySet::empty());
        for (capability, name) in [
            (rustix::thread::CapabilitySet::SETUID, "CAP_SETUID"),
            (rustix::thread::CapabilitySet::SETGID, "CAP_SETGID"),
        ] {
            if !effective.contains(capability) {
                return Err(IdMapError::unsatisfiable(format!(
                    "writing a range map directly requires {name} over the current user \
                         namespace, which the caller does not hold",
                )));
            }
        }

        // Where the caller's own map is readable, require the requested
        // outside ids to exist in this namespace: the kernel would refuse
        // them at apply time, and the refusal is clearer here. An unreadable
        // map skips the check and leaves the kernel as the arbiter.
        for (which, path, ranges) in [
            ("uid", "/proc/self/uid_map", &uid),
            ("gid", "/proc/self/gid_map", &gid),
        ] {
            let Some(own) = read_own_map(path) else {
                continue;
            };
            for range in ranges {
                let last = range.outside.checked_add(range.count.saturating_sub(1));
                let covered = last.is_some_and(|last| {
                    own.iter()
                        .any(|&(inside, count)| range.outside >= inside && last - inside < count)
                });
                if !covered {
                    return Err(IdMapError::unsatisfiable(format!(
                        "the {which} extent {} {} {} names outside ids that do not exist \
                             in the caller's user namespace",
                        range.inside, range.outside, range.count,
                    )));
                }
            }
        }

        Ok(ResolvedMap::new(uid, gid))
    }

    fn apply(&self, pid: u32, map: &ResolvedMap) -> Result<(), IdMapError> {
        // A privileged writer needs no setgroups denial, and none is
        // performed: a range gid map deliberately leaves `setgroups` at
        // `allow` so supplementary groups work inside.
        write_map_file(
            &format!("/proc/{pid}/uid_map"),
            "uid_map",
            &format_map(map.uid()),
        )?;
        write_map_file(
            &format!("/proc/{pid}/gid_map"),
            "gid_map",
            &format_map(map.gid()),
        )
    }
}

/// Reads an identity-map file into `(inside, count)` pairs, or `None` when
/// it cannot be read or parsed. The outside column is not needed: the
/// question is which ids exist in the namespace the file describes.
fn read_own_map(path: &str) -> Option<Vec<(u32, u32)>> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut ranges = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let inside: u32 = fields.next()?.parse().ok()?;
        let _outside: u64 = fields.next()?.parse().ok()?;
        let count: u32 = fields.next()?.parse().ok()?;
        ranges.push((inside, count));
    }
    if ranges.is_empty() {
        None
    } else {
        Some(ranges)
    }
}

/// The serde profile forms.
///
/// Deserialization runs through a mirror type so that a build without the
/// `subid` feature refuses a profile requesting the subordinate map at load
/// time, with a message naming the feature — an identity posture is never
/// silently downgraded by a library that cannot establish it.
#[cfg(feature = "serde")]
mod profile {
    use super::{IdRange, IdentityMap};

    /// The wire shape of [`IdentityMap`], deserialized then converted.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    pub(crate) enum IdentityMapWire {
        Single,
        Ranges {
            uid: Vec<IdRange>,
            gid: Vec<IdRange>,
        },
        Subordinate,
    }

    impl TryFrom<IdentityMapWire> for IdentityMap {
        type Error = String;

        fn try_from(wire: IdentityMapWire) -> Result<IdentityMap, String> {
            Ok(match wire {
                IdentityMapWire::Single => IdentityMap::Single,
                IdentityMapWire::Ranges { uid, gid } => IdentityMap::Ranges { uid, gid },
                #[cfg(feature = "subid")]
                IdentityMapWire::Subordinate => IdentityMap::Subordinate,
                #[cfg(not(feature = "subid"))]
                IdentityMapWire::Subordinate => {
                    return Err(
                        "this profile requests the subordinate identity map, but the library \
                         was built without the `subid` feature"
                            .to_string(),
                    );
                }
            })
        }
    }
}

#[cfg(feature = "subid")]
pub use subid::SubidMapper;
#[cfg(feature = "subid")]
pub(crate) use subid::probe_allocation_is_empty;

/// The subordinate-id delegate: `newuidmap` and `newgidmap`.
#[cfg(feature = "subid")]
mod subid {
    use std::process::Command;

    use super::{IdMapError, IdMapper, IdRange, IdentityMap, ResolvedMap, maps_outside_range};

    /// The delegated mapper: establishes range maps through the shadow
    /// suite's privileged `newuidmap` and `newgidmap` helpers.
    ///
    /// The helpers apply the subordinate-id allocation an administrator
    /// granted the calling user in `/etc/subuid` and `/etc/subgid` (or a
    /// site's NSS `subid` source). They are the standard mechanism every
    /// rootless container runtime uses, and the only route to a range map
    /// for an unprivileged caller on an ordinary host. This is the one
    /// delegate that executes an external binary, which is why it lives
    /// behind the `subid` feature.
    ///
    /// [`resolve`](IdMapper::resolve) determines the caller's allocation
    /// with the NSS-aware `getsubids` query where available, falling back to
    /// reading `/etc/subuid` and `/etc/subgid` only on hosts whose
    /// `nsswitch.conf` names no other `subid` source — the same rule the
    /// helpers themselves follow, so the fallback can never invent an
    /// allocation an NSS module would deny. [`apply`](IdMapper::apply)
    /// executes the helpers against the gated sandbox process.
    ///
    /// [`host::range_map_blocker`](crate::host::range_map_blocker) explains
    /// a host on which this delegate cannot work.
    #[derive(Debug, Clone, Default)]
    #[non_exhaustive]
    pub struct SubidMapper;

    impl SubidMapper {
        /// Returns the subordinate-id delegate.
        pub fn new() -> SubidMapper {
            SubidMapper
        }
    }

    impl IdMapper for SubidMapper {
        fn resolve(&self, request: &IdentityMap) -> Result<ResolvedMap, IdMapError> {
            match request {
                IdentityMap::Single => Err(IdMapError::unsatisfiable(
                    "the single-identity map is established in process and needs no \
                             delegate"
                        .to_string(),
                )),
                IdentityMap::Subordinate => {
                    let euid = rustix::process::geteuid().as_raw();
                    let egid = rustix::process::getegid().as_raw();
                    let uid_alloc = subordinate_ranges(Kind::Uid)?;
                    let gid_alloc = subordinate_ranges(Kind::Gid)?;
                    Ok(ResolvedMap::new(
                        compose_subordinate(euid, &uid_alloc),
                        compose_subordinate(egid, &gid_alloc),
                    ))
                }
                IdentityMap::Ranges { uid, gid } => {
                    // The helpers accept an outside range only when the
                    // caller's allocation (or the caller's own single id)
                    // covers it; check here so the refusal happens at build
                    // time with the offending extent named.
                    let euid = rustix::process::geteuid().as_raw();
                    let egid = rustix::process::getegid().as_raw();
                    for (which, own, ranges, alloc) in [
                        ("uid", euid, uid, subordinate_ranges(Kind::Uid)?),
                        ("gid", egid, gid, subordinate_ranges(Kind::Gid)?),
                    ] {
                        for range in ranges {
                            let is_own = range.count == 1 && range.outside == own;
                            if !is_own && !maps_outside_range(&alloc, range) {
                                return Err(IdMapError::unsatisfiable(format!(
                                    "the {which} extent {} {} {} is outside the caller's \
                                         subordinate allocation",
                                    range.inside, range.outside, range.count,
                                )));
                            }
                        }
                    }
                    Ok(ResolvedMap::new(uid.clone(), gid.clone()))
                }
            }
        }

        fn apply(&self, pid: u32, map: &ResolvedMap) -> Result<(), IdMapError> {
            run_helper("newuidmap", pid, map.uid())?;
            run_helper("newgidmap", pid, map.gid())
        }
    }

    /// Executes one helper with the extent triples for one map file.
    fn run_helper(helper: &'static str, pid: u32, ranges: &[IdRange]) -> Result<(), IdMapError> {
        let mut command = Command::new(helper);
        command.arg(pid.to_string());
        for range in ranges {
            command
                .arg(range.inside.to_string())
                .arg(range.outside.to_string())
                .arg(range.count.to_string());
        }
        let output = command
            .output()
            .map_err(|err| IdMapError::helper_spawn(helper, err.raw_os_error().unwrap_or(0)))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(IdMapError::helper_failed(
                helper,
                String::from_utf8_lossy(&output.stderr).trim(),
            ))
        }
    }

    /// Which id space an allocation query concerns.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Kind {
        Uid,
        Gid,
    }

    impl Kind {
        fn noun(self) -> &'static str {
            match self {
                Kind::Uid => "uid",
                Kind::Gid => "gid",
            }
        }

        fn file(self) -> &'static str {
            match self {
                Kind::Uid => "/etc/subuid",
                Kind::Gid => "/etc/subgid",
            }
        }
    }

    /// The caller's subordinate allocation for one id space, as `(start,
    /// count)` pairs in the order granted.
    ///
    /// The query prefers `getsubids`, which consults the same NSS `subid`
    /// sources the helpers do. When `getsubids` is absent, the subordinate
    /// files are read directly only if `nsswitch.conf` names no `subid`
    /// module beyond `files` — on any other host the files are not the
    /// authority and reading them could silently miss (or invent) an
    /// allocation, so the query fails naming the missing tool instead.
    pub(crate) fn subordinate_ranges(kind: Kind) -> Result<Vec<(u32, u32)>, IdMapError> {
        // The helpers match a subordinate entry by user name or by literal
        // uid string, so the query tries both. The name lookup is delegated
        // to `id`, whose NSS-aware resolution covers directory-service
        // users that /etc/passwd does not list.
        let mut keys: Vec<String> = Vec::new();
        if let Ok(output) = Command::new("id").arg("-un").output()
            && output.status.success()
            && let Ok(name) = String::from_utf8(output.stdout)
        {
            let name = name.trim().to_string();
            if !name.is_empty() {
                keys.push(name);
            }
        }
        keys.push(rustix::process::geteuid().as_raw().to_string());

        match query_getsubids(kind, &keys) {
            Ok(ranges) => return finish(kind, ranges),
            Err(GetsubidsUnusable::Absent) => {}
            Err(GetsubidsUnusable::Failed(detail)) => {
                return Err(IdMapError::unsatisfiable(format!(
                    "getsubids could not report the allocation: {detail}"
                )));
            }
        }

        if let Some(modules) = non_files_subid_modules() {
            return Err(IdMapError::unsatisfiable(format!(
                "nsswitch.conf sources subordinate ids from `{modules}` and getsubids is \
                     not installed, so the allocation cannot be determined; install getsubids \
                     (shadow 4.10 or later)",
            )));
        }

        finish(kind, parse_subid_file(kind.file(), &keys))
    }

    /// Wraps an allocation query result, turning an empty allocation into
    /// the typed refusal.
    fn finish(kind: Kind, ranges: Vec<(u32, u32)>) -> Result<Vec<(u32, u32)>, IdMapError> {
        if ranges.is_empty() {
            Err(IdMapError::unsatisfiable(format!(
                "the calling user has no subordinate {} allocation; grant one with \
                     usermod --add-sub{}s or an entry in {}",
                kind.noun(),
                kind.noun(),
                kind.file(),
            )))
        } else {
            Ok(ranges)
        }
    }

    /// Why a `getsubids` query produced no answer.
    enum GetsubidsUnusable {
        /// The tool is not installed; the files may still be authoritative.
        Absent,
        /// The tool exists but failed; its answer is not safely replaceable
        /// by a file read.
        Failed(String),
    }

    /// Queries `getsubids` for each key until one answers with ranges.
    ///
    /// Output lines have the shape `index: owner start count`.
    fn query_getsubids(kind: Kind, keys: &[String]) -> Result<Vec<(u32, u32)>, GetsubidsUnusable> {
        let mut ranges = Vec::new();
        for key in keys {
            let mut command = Command::new("getsubids");
            if kind == Kind::Gid {
                command.arg("-g");
            }
            let output = command.arg(key).output().map_err(|err| {
                if err.kind() == std::io::ErrorKind::NotFound {
                    GetsubidsUnusable::Absent
                } else {
                    GetsubidsUnusable::Failed(err.to_string())
                }
            })?;
            // A key with no allocation makes getsubids exit non-zero; that
            // is an empty answer for this key, not a failure of the tool.
            if !output.status.success() {
                continue;
            }
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let mut fields = line.split_whitespace();
                let (_index, _owner) = (fields.next(), fields.next());
                if let (Some(start), Some(count)) = (fields.next(), fields.next())
                    && let (Ok(start), Ok(count)) = (start.parse(), count.parse())
                {
                    ranges.push((start, count));
                }
            }
            if !ranges.is_empty() {
                break;
            }
        }
        Ok(ranges)
    }

    /// The `subid` modules `nsswitch.conf` names beyond `files`, joined, or
    /// `None` when the files are the authority (no `subid` line, or a line
    /// naming only `files`).
    fn non_files_subid_modules() -> Option<String> {
        let text = std::fs::read_to_string("/etc/nsswitch.conf").ok()?;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let Some((database, modules)) = line.split_once(':') else {
                continue;
            };
            if database.trim() != "subid" {
                continue;
            }
            let foreign: Vec<&str> = modules
                .split_whitespace()
                .filter(|module| *module != "files")
                .collect();
            if foreign.is_empty() {
                return None;
            }
            return Some(foreign.join(" "));
        }
        None
    }

    /// Reads a subordinate file directly, collecting the ranges of every
    /// entry whose owner field matches one of the keys.
    ///
    /// Only reached when the files are the host's authority; see
    /// [`subordinate_ranges`].
    fn parse_subid_file(path: &str, keys: &[String]) -> Vec<(u32, u32)> {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        let mut ranges = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split(':');
            let Some(owner) = fields.next() else { continue };
            if !keys.iter().any(|key| key == owner) {
                continue;
            }
            if let (Some(start), Some(count)) = (fields.next(), fields.next())
                && let (Ok(start), Ok(count)) = (start.parse(), count.parse())
            {
                ranges.push((start, count));
            }
        }
        ranges
    }

    /// Whether the caller has no subordinate allocation at all, for the host
    /// probe. Query failures count as empty: the probe reports conditions,
    /// it does not fail.
    pub(crate) fn probe_allocation_is_empty() -> bool {
        subordinate_ranges(Kind::Uid).is_err() || subordinate_ranges(Kind::Gid).is_err()
    }

    /// Composes the subordinate map: the caller's own id as inside id 0,
    /// then inside ids from 1 onward covering each allocated range in order.
    fn compose_subordinate(own: u32, allocation: &[(u32, u32)]) -> Vec<IdRange> {
        let mut ranges = vec![IdRange {
            inside: 0,
            outside: own,
            count: 1,
        }];
        let mut inside = 1u32;
        for &(start, count) in allocation {
            // An allocation vast enough to exhaust the 32-bit inside space
            // is truncated at the boundary; ids beyond it are unaddressable.
            let count = count.min(u32::MAX - inside);
            if count == 0 {
                break;
            }
            ranges.push(IdRange {
                inside,
                outside: start,
                count,
            });
            inside += count;
        }
        ranges
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_subordinate_map_is_root_then_the_allocation() {
            let map = compose_subordinate(1000, &[(100000, 65536), (300000, 1000)]);
            assert_eq!(
                map,
                [
                    IdRange {
                        inside: 0,
                        outside: 1000,
                        count: 1
                    },
                    IdRange {
                        inside: 1,
                        outside: 100000,
                        count: 65536
                    },
                    IdRange {
                        inside: 65537,
                        outside: 300000,
                        count: 1000
                    },
                ]
            );
        }
    }
}

/// Resolves a range request through the bundled delegate chain:
/// [`DirectMapper`] first, then the subordinate delegate when the `subid`
/// feature is enabled. On failure the reason collects each delegate's
/// refusal and the host probe's diagnosis, so the error names what to fix.
///
/// Shared by [`CageBuilder::build`](crate::CageBuilder::build) (when no
/// mapper is configured) and by the map-assisted removal in
/// [`provision::remove`](crate::provision::remove).
pub(crate) fn resolve_default_chain(
    request: &IdentityMap,
) -> Result<(std::sync::Arc<dyn IdMapper>, ResolvedMap), String> {
    let mut reasons: Vec<String> = Vec::new();

    let direct: std::sync::Arc<dyn IdMapper> = std::sync::Arc::new(DirectMapper::new());
    match direct.resolve(request) {
        Ok(map) => return Ok((direct, map)),
        Err(err) => reasons.push(format!("direct: {err}")),
    }

    #[cfg(feature = "subid")]
    {
        let subid: std::sync::Arc<dyn IdMapper> = std::sync::Arc::new(SubidMapper::new());
        match subid.resolve(request) {
            Ok(map) => return Ok((subid, map)),
            Err(err) => reasons.push(format!("subid: {err}")),
        }
    }

    if let Some(blocker) = crate::host::range_map_blocker() {
        reasons.push(blocker.to_string());
    }

    Err(reasons.join("; "))
}

/// Whether the allocation covers the extent's whole outside range.
#[cfg(feature = "subid")]
fn maps_outside_range(allocation: &[(u32, u32)], range: &IdRange) -> bool {
    let Some(last) = range.outside.checked_add(range.count.saturating_sub(1)) else {
        return false;
    };
    allocation
        .iter()
        .any(|&(start, count)| range.outside >= start && last - start < count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(inside: u32, outside: u32, count: u32) -> IdRange {
        IdRange {
            inside,
            outside,
            count,
        }
    }

    fn ranges_map(uid: Vec<IdRange>, gid: Vec<IdRange>) -> IdentityMap {
        IdentityMap::Ranges { uid, gid }
    }

    #[test]
    fn the_single_and_subordinate_requests_have_nothing_to_validate() {
        validate_request(&IdentityMap::Single).unwrap();
        validate_request(&IdentityMap::Subordinate).unwrap();
    }

    #[test]
    fn a_plain_range_map_validates() {
        validate_request(&ranges_map(
            vec![range(0, 1000, 1), range(1, 100000, 65536)],
            vec![range(0, 1000, 1), range(1, 100000, 65536)],
        ))
        .unwrap();
    }

    #[test]
    fn an_empty_range_list_is_rejected() {
        let err = validate_request(&ranges_map(vec![], vec![range(0, 1000, 1)])).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::IdentityMapInvalid { reason } if reason.contains("uid range list is empty")
        ));
    }

    #[test]
    fn a_zero_count_extent_is_rejected() {
        let err = validate_request(&ranges_map(
            vec![range(0, 1000, 1), range(1, 100000, 0)],
            vec![range(0, 1000, 1)],
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::IdentityMapInvalid { reason } if reason.contains("zero count")
        ));
    }

    #[test]
    fn a_map_without_root_inside_is_rejected() {
        let err = validate_request(&ranges_map(
            vec![range(1, 100000, 65536)],
            vec![range(0, 1000, 1)],
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::IdentityMapInvalid { reason } if reason.contains("inside id 0")
        ));
    }

    #[test]
    fn overlapping_inside_extents_are_rejected() {
        let err = validate_request(&ranges_map(
            vec![
                range(0, 1000, 1),
                range(1, 100000, 100),
                range(50, 300000, 10),
            ],
            vec![range(0, 1000, 1)],
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::IdentityMapInvalid { reason } if reason.contains("overlap")
        ));
    }

    #[test]
    fn overlapping_outside_extents_are_rejected() {
        let err = validate_request(&ranges_map(
            vec![
                range(0, 1000, 1),
                range(1, 100000, 100),
                range(101, 100050, 100),
            ],
            vec![range(0, 1000, 1)],
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::IdentityMapInvalid { reason } if reason.contains("overlap")
        ));
    }

    #[test]
    fn an_extent_wrapping_the_id_space_is_rejected() {
        let err = validate_request(&ranges_map(
            vec![range(0, 1000, 1), range(u32::MAX, 100000, 2)],
            vec![range(0, 1000, 1)],
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::IdentityMapInvalid { reason } if reason.contains("wraps")
        ));
    }

    #[test]
    fn more_extents_than_the_kernel_accepts_are_rejected() {
        let mut uid = vec![range(0, 1000, 1)];
        for i in 0..MAX_EXTENTS as u32 {
            uid.push(range(1 + i * 2, 100000 + i * 2, 1));
        }
        let err = validate_request(&ranges_map(uid, vec![range(0, 1000, 1)])).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::IdentityMapInvalid { reason } if reason.contains("340")
        ));
    }

    #[test]
    fn maps_inside_id_matches_extent_boundaries() {
        let ranges = [range(0, 1000, 1), range(1, 100000, 65536)];
        assert!(maps_inside_id(&ranges, 0));
        assert!(maps_inside_id(&ranges, 1));
        assert!(maps_inside_id(&ranges, 65536));
        assert!(!maps_inside_id(&ranges, 65537));
    }

    #[test]
    fn a_resolved_map_is_validated_like_a_request() {
        let err = validate_resolved(&ResolvedMap::new(
            vec![range(1, 100000, 10)],
            vec![range(0, 1000, 1)],
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::IdentityMapInvalid { reason }
                if reason.contains("delegate resolved an invalid map")
        ));
    }

    #[test]
    fn format_map_emits_one_line_per_extent() {
        let text = format_map(&[range(0, 1000, 1), range(1, 100000, 65536)]);
        assert_eq!(text, b"0 1000 1\n1 100000 65536\n");
    }

    #[test]
    fn the_direct_mapper_refuses_single_and_subordinate() {
        let mapper = DirectMapper::new();
        assert!(matches!(
            mapper.resolve(&IdentityMap::Single),
            Err(IdMapError::Unsatisfiable { .. })
        ));
        assert!(matches!(
            mapper.resolve(&IdentityMap::Subordinate),
            Err(IdMapError::Unsatisfiable { .. })
        ));
    }

    #[test]
    fn an_identity_carries_its_groups() {
        let identity = Identity::new(250, 250).groups([250, 100]);
        assert_eq!(identity.uid, 250);
        assert_eq!(identity.gid, 250);
        assert_eq!(identity.groups, [250, 100]);
    }
}
