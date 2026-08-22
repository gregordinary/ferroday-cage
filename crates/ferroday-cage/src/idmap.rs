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
use std::io;

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
    pub inside: u32,
    /// The first id on the host.
    pub outside: u32,
    /// How many consecutive ids the extent covers.
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
    pub(crate) uid: u32,
    /// The gid the command runs as, a sandbox-inside id.
    pub(crate) gid: u32,
    /// The supplementary groups, sandbox-inside ids. Requires a range gid
    /// map: the single-identity map denies `setgroups`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
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
        /// The underlying error, absent where the spawn failed with none.
        source: Option<io::Error>,
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
        /// The underlying error.
        source: io::Error,
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
    ///
    /// `source` is `None` where the failure carried no OS error at all, which
    /// is a fact rather than an errno of zero: rendering zero would read
    /// "Success (os error 0)".
    pub fn helper_spawn(helper: impl Into<String>, source: Option<io::Error>) -> IdMapError {
        IdMapError::HelperSpawn {
            helper: helper.into(),
            source,
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
    pub fn map_write(which: &'static str, source: io::Error) -> IdMapError {
        IdMapError::MapWrite { which, source }
    }
}

impl fmt::Display for IdMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdMapError::Unsatisfiable { reason } => f.write_str(reason),
            IdMapError::HelperSpawn {
                helper,
                source: None,
            } => write!(f, "could not execute {helper}"),
            IdMapError::HelperSpawn {
                helper,
                source: Some(source),
            } => write!(f, "could not execute {helper}: {source}"),
            IdMapError::HelperFailed { helper, detail } => {
                if detail.is_empty() {
                    write!(f, "{helper} refused the map")
                } else {
                    write!(f, "{helper} refused the map: {detail}")
                }
            }
            IdMapError::MapWrite { which, source } => {
                write!(f, "could not write {which}: {source}")
            }
        }
    }
}

impl std::error::Error for IdMapError {
    /// The OS failure underneath, where there is one.
    ///
    /// [`Unsatisfiable`](Self::Unsatisfiable) and
    /// [`HelperFailed`](Self::HelperFailed) carry no inner error: the first is
    /// a refusal this crate composed, and the second is what a helper wrote to
    /// its standard error, which is text rather than an error value.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IdMapError::HelperSpawn { source, .. } => source
                .as_ref()
                .map(|source| source as &(dyn std::error::Error + 'static)),
            IdMapError::MapWrite { source, .. } => Some(source),
            _ => None,
        }
    }
}

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
        // `start + count` rather than `start + count - 1`: the kernel rejects
        // the id `(u32)-1`, so an extent ending exactly at `u32::MAX` is one the
        // map cannot carry. Catching it here keeps the promise that an
        // unrepresentable extent is a typed build error rather than a failure
        // at apply time.
        if range.inside.checked_add(range.count).is_none()
            || range.outside.checked_add(range.count).is_none()
        {
            return Err(format!(
                "the {which} extent at inside id {} runs past the last usable id",
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
///
/// The arithmetic is checked rather than plain, though both preconditions that
/// would make it wrap hold at the only call site: `validate_ranges` has already
/// refused a zero count and an extent running past the last usable id. This is
/// the identity map's validator and a release build wraps rather than panics,
/// so a wrapped comparison here would accept the overlap the function exists to
/// refuse — a cost out of all proportion to the two operations it saves.
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
        let last = key(a).saturating_add(a.count.saturating_sub(1));
        if last >= key(b) {
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

/// The map a namespace nested inside one these extents describe must carry to
/// leave the inside view unchanged: each extent reproduced as an identity
/// mapping of its own inside ids.
///
/// A nested user namespace maps against its parent's id space, not the host's,
/// so the parent's outside ids are not the ids to name. Reproducing each
/// extent as `inside inside count` gives the nested namespace exactly the ids
/// the outer one has, under the same names, and a process inside sees no
/// change at all.
///
/// The extent count is preserved, so a map within the kernel's
/// [`MAX_EXTENTS`] ceiling reflects to one that is too.
pub(crate) fn reflect_inside(ranges: &[IdRange]) -> Vec<IdRange> {
    ranges
        .iter()
        .map(|range| IdRange {
            inside: range.inside,
            outside: range.inside,
            count: range.count,
        })
        .collect()
}

/// Opens `path` and writes `data` in a single `write`, as the map files
/// require: they accept the whole map in one write and nothing else.
fn write_map_file(path: &str, which: &'static str, data: &[u8]) -> Result<(), IdMapError> {
    let map_write = |errno: Errno| IdMapError::map_write(which, errno.into());
    let fd = rustix::fs::open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(map_write)?;
    match rustix::io::write(&fd, data) {
        Ok(n) if n == data.len() => Ok(()),
        // The kernel takes a map file's contents whole or not at all, so a
        // short write is not an errno the kernel reported. Fabricating one
        // would render as "Input/output error" and send a reader looking for a
        // device fault; `EMSGSIZE` says what happened — the write did not
        // carry the whole map.
        Ok(_) => Err(map_write(Errno::MSGSIZE)),
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
        // A line this does not recognize is skipped, not taken as grounds to
        // abandon the file: "unreadable" is what leaves the kernel as the
        // arbiter, and one unexpected line is a different thing. Giving up here
        // would drop the check for both id spaces and turn a named extent at
        // build time into a bare EPERM at apply time.
        let mut fields = line.split_whitespace();
        let (Some(inside), Some(outside), Some(count)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (Ok(inside), Ok(_outside), Ok(count)) = (
            inside.parse::<u32>(),
            outside.parse::<u64>(),
            count.parse::<u32>(),
        ) else {
            continue;
        };
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
pub(crate) use subid::{AllocationUnusable, probe_allocation};

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
    /// *Which* helpers is decided by the ambient `PATH`, which is worth knowing
    /// for a consumer running this from a daemon with an inherited environment.
    /// They are looked up by name among the absolute `PATH` entries — a relative
    /// entry is skipped rather than resolved against the process's working
    /// directory — and the resolved absolute path is what executes.
    /// [`host::range_map_blocker`](crate::host::range_map_blocker) judges a
    /// helper's privilege through the same lookup, so the two agree on the same
    /// `PATH`; a `PATH` that changes between the probe and the launch is the
    /// caller's to keep still. The two auxiliary tools [`resolve`](IdMapper::resolve)
    /// consults — `id` for the caller's user name, and `getsubids` for the
    /// allocation itself — are resolved by the same rule.
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
    ///
    /// The helper is resolved to an absolute path first, by the same lookup
    /// [`host::range_map_blocker`](crate::host::range_map_blocker) uses to judge
    /// its privilege, rather than handed to `Command` as a bare name for it to
    /// resolve again on its own terms. The two would otherwise be free to differ
    /// — `Command` searches every `PATH` entry, this lookup only the absolute
    /// ones — and the probe's verdict would describe a binary that is not the
    /// one that runs.
    fn run_helper(helper: &'static str, pid: u32, ranges: &[IdRange]) -> Result<(), IdMapError> {
        let resolved = crate::host::find_on_path(helper).ok_or_else(|| {
            IdMapError::helper_spawn(helper, Some(rustix::io::Errno::NOENT.into()))
        })?;
        let mut command = Command::new(resolved);
        command.arg(pid.to_string());
        for range in ranges {
            command
                .arg(range.inside.to_string())
                .arg(range.outside.to_string())
                .arg(range.count.to_string());
        }
        let output = command.output().map_err(|err| {
            // A spawn failure with no OS error behind it is reported as
            // having none, rather than as errno zero.
            let carried = err.raw_os_error().is_some().then_some(err);
            IdMapError::helper_spawn(helper, carried)
        })?;
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
        allocation(kind).map_err(|unusable| IdMapError::unsatisfiable(unusable.to_string(kind)))
    }

    /// Why the caller's subordinate allocation cannot be used.
    ///
    /// The two are different diagnoses with different remedies, and the host
    /// probe reports whichever applies rather than collapsing both into "no
    /// allocation": on a host whose `nsswitch.conf` sources subordinate ids
    /// from a directory service, the user may well have an allocation, and
    /// adding `/etc/subuid` entries would not help because the files are not
    /// the authority there.
    pub(crate) enum AllocationUnusable {
        /// The query answered, and the answer is that there is no allocation.
        Empty,
        /// The query could not answer at all; the reason names what to do.
        Unknown(String),
    }

    impl AllocationUnusable {
        /// The reason as a message, `kind` naming the id space.
        pub(crate) fn to_string(&self, kind: Kind) -> String {
            match self {
                AllocationUnusable::Empty => format!(
                    "the calling user has no subordinate {} allocation; grant one with \
                     usermod --add-sub{}s or an entry in {}",
                    kind.noun(),
                    kind.noun(),
                    kind.file(),
                ),
                AllocationUnusable::Unknown(reason) => reason.clone(),
            }
        }
    }

    /// The caller's allocation for one id space, or why it could not be had.
    pub(crate) fn allocation(kind: Kind) -> Result<Vec<(u32, u32)>, AllocationUnusable> {
        // The helpers match a subordinate entry by user name or by literal
        // uid string, so the query tries both. The name lookup is delegated
        // to `id`, whose NSS-aware resolution covers directory-service
        // users that /etc/passwd does not list.
        //
        // Resolved through `find_on_path` rather than by bare name, for the
        // reason that lookup exists: `Command`'s own search is `execvp`'s, which
        // honours a relative or empty `PATH` entry and so would run whatever
        // binary of that name the process's working directory happens to hold.
        let mut keys: Vec<String> = Vec::new();
        if let Some(id) = crate::host::find_on_path("id")
            && let Ok(output) = Command::new(id).arg("-un").output()
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
            Ok(ranges) => return finish(ranges),
            Err(GetsubidsUnusable::Absent) => {}
            Err(GetsubidsUnusable::Failed(detail)) => {
                return Err(AllocationUnusable::Unknown(format!(
                    "getsubids could not report the allocation: {detail}"
                )));
            }
        }

        if let Some(modules) = non_files_subid_modules() {
            return Err(AllocationUnusable::Unknown(format!(
                "nsswitch.conf sources subordinate ids from `{modules}` and getsubids is \
                     not installed, so the allocation cannot be determined; install getsubids \
                     (shadow 4.10 or later)",
            )));
        }

        finish(parse_subid_file(kind.file(), &keys))
    }

    /// Wraps an allocation query result, turning an empty allocation into
    /// the typed refusal.
    fn finish(ranges: Vec<(u32, u32)>) -> Result<Vec<(u32, u32)>, AllocationUnusable> {
        if ranges.is_empty() {
            Err(AllocationUnusable::Empty)
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
    ///
    /// The tool is resolved through
    /// [`find_on_path`](crate::host::find_on_path), the same lookup the helpers
    /// themselves go through, so only absolute `PATH` entries are searched: what
    /// this query answers decides what allocation the delegate believes the
    /// caller has, and it is not a question to put to a binary found in whatever
    /// directory the process happens to be in. A lookup that finds nothing is
    /// the tool being absent, which is the case the files may still answer.
    fn query_getsubids(kind: Kind, keys: &[String]) -> Result<Vec<(u32, u32)>, GetsubidsUnusable> {
        let Some(getsubids) = crate::host::find_on_path("getsubids") else {
            return Err(GetsubidsUnusable::Absent);
        };
        let mut ranges = Vec::new();
        for key in keys {
            let mut command = Command::new(&getsubids);
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
        // The key the file turned out to be written under, fixed by the first
        // entry that yielded a range.
        let mut matching: Option<&String> = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split(':');
            let Some(owner) = fields.next() else { continue };
            // The first key that answers owns the file, as `query_getsubids`
            // has it: a host granting the same block under both the user name
            // and the literal uid would otherwise yield each range twice, and
            // the duplicate overlaps itself and fails the build with a message
            // blaming a perfectly legal configuration.
            let Some(answering) = keys.iter().find(|key| *key == owner) else {
                continue;
            };
            if matching.is_some_and(|key| key != answering) {
                continue;
            }
            if let (Some(start), Some(count)) = (fields.next(), fields.next())
                && let (Ok(start), Ok(count)) = (start.parse(), count.parse())
            {
                matching = Some(answering);
                ranges.push((start, count));
            }
        }
        ranges
    }

    /// Why the caller's subordinate allocation cannot be used, for the host
    /// probe, or `None` when both id spaces answer with one.
    ///
    /// The reason is carried rather than reduced to "no allocation": the probe
    /// reports conditions, and the condition it reports has to be the one whose
    /// remedy is right. See [`AllocationUnusable`].
    pub(crate) fn probe_allocation() -> Option<(Kind, AllocationUnusable)> {
        for kind in [Kind::Uid, Kind::Gid] {
            if let Err(unusable) = allocation(kind) {
                return Some((kind, unusable));
            }
        }
        None
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
            // A zero-count entry contributes nothing but is a legal line in a
            // subordinate file; skipping it keeps the entries after it, which
            // stopping would silently drop.
            if count == 0 {
                continue;
            }
            // An allocation vast enough to exhaust the 32-bit inside space is
            // truncated at the boundary; ids beyond it are unaddressable, and
            // nothing after this entry can be addressed either.
            let count = count.min(u32::MAX - inside);
            if count == 0 {
                break;
            }
            // A map file carries at most MAX_EXTENTS lines, and an
            // administrator is free to grant more separate ranges than that.
            // Truncating keeps a legal host configuration working with a
            // smaller map, where emitting them all would fail the build with a
            // message blaming the delegate for the host's allocation.
            if ranges.len() == super::MAX_EXTENTS {
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

        #[test]
        fn an_allocation_beyond_the_extent_ceiling_is_truncated_to_it() {
            // A user granted more separate subordinate ranges than a map file
            // can carry is unusual but entirely legal. Emitting them all would
            // fail `validate_resolved` with a message blaming the bundled
            // delegate for the host's allocation; truncating keeps the
            // configuration working with a smaller map, as the u32-exhaustion
            // case above it already does.
            let allocation: Vec<(u32, u32)> = (0..super::super::MAX_EXTENTS + 20)
                .map(|i| (100_000 + (i as u32) * 10, 5))
                .collect();
            let map = compose_subordinate(1000, &allocation);
            assert_eq!(map.len(), super::super::MAX_EXTENTS);
            // Still a map the kernel accepts, with the caller's own id at
            // inside id 0 where every map this library builds has it.
            let resolved = ResolvedMap::new(map.clone(), map);
            crate::idmap::validate_resolved(&resolved)
                .expect("a truncated map is still a valid one");
        }

        #[test]
        fn a_zero_count_allocation_entry_does_not_truncate_the_map() {
            // `user:100000:0` parses fine and grants nothing. Stopping there
            // would silently drop every range after it, leaving a map far
            // smaller than the host allocated and a sandbox unable to reach
            // ids it was granted.
            let map = compose_subordinate(1000, &[(100000, 0), (300000, 1000)]);
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
///
/// Adjoining entries count as one span, which is what shadow's own `have_range`
/// does: a caller granted `100000:65536` and `165536:65536` may legally ask for
/// a single extent across both, and refusing it would reject a map the delegate
/// would have applied. (The kernel's own requirement, which [`DirectMapper`]
/// checks against the parent's map, is different and genuinely per-extent.)
#[cfg(feature = "subid")]
fn maps_outside_range(allocation: &[(u32, u32)], range: &IdRange) -> bool {
    let Some(last) = range.outside.checked_add(range.count.saturating_sub(1)) else {
        return false;
    };
    coalesce(allocation)
        .into_iter()
        .any(|(start, end)| range.outside >= start && last <= end)
}

/// The allocation as inclusive `(start, end)` spans, with adjoining and
/// overlapping entries merged.
#[cfg(feature = "subid")]
fn coalesce(allocation: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut spans: Vec<(u32, u32)> = allocation
        .iter()
        .filter(|&&(_, count)| count > 0)
        .map(|&(start, count)| (start, start.saturating_add(count - 1)))
        .collect();
    spans.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            // `start - 1` is safe: a span starting at 0 sorts first and cannot
            // follow another.
            Some(last) if start <= last.1 || start - 1 == last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    #[test]
    fn an_unparsable_map_line_is_skipped_rather_than_abandoning_the_file() {
        // The coverage check exists so that a requested outside id the caller's
        // namespace does not hold is named at build time instead of arriving as
        // a bare EPERM from the kernel at apply time. Abandoning the file on one
        // line the parser did not expect would drop that check silently — and
        // drop it for both id spaces, since the failure is per-file.
        let dir = Scratch::new("own-map");
        let path = dir.join("uid_map");
        std::fs::write(
            &path,
            b"         0       1000          1\n\
              this line is not a map entry\n\
              1 100000 65536\n",
        )
        .unwrap();
        assert_eq!(
            read_own_map(path.to_str().unwrap()),
            Some(vec![(0, 1), (1, 65536)]),
            "the entries around an unparsable line must survive it"
        );

        // A file with nothing parsable in it is still "no map to check
        // against", which leaves the kernel as the arbiter.
        std::fs::write(&path, b"not a map at all\n").unwrap();
        assert_eq!(read_own_map(path.to_str().unwrap()), None);
        // As is a file that cannot be read.
        assert_eq!(read_own_map("/proc/self/no-such-map"), None);
    }

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
    fn an_extent_running_past_the_last_usable_id_is_rejected() {
        let err = validate_request(&ranges_map(
            vec![range(0, 1000, 1), range(u32::MAX, 100000, 2)],
            vec![range(0, 1000, 1)],
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::IdentityMapInvalid { reason } if reason.contains("past the last usable id")
        ));

        // The bound is the kernel's, which reserves `(u32)-1`: an extent ending
        // exactly there is refused here rather than at apply time, where the
        // build error the docs promise is no longer available.
        let ends_at_max = validate_request(&ranges_map(
            vec![range(0, 1000, 1), range(1, u32::MAX - 1, 2)],
            vec![range(0, 1000, 1)],
        ))
        .unwrap_err();
        assert!(matches!(
            ends_at_max,
            ConfigError::IdentityMapInvalid { reason } if reason.contains("past the last usable id")
        ));
        // One id short of it is fine.
        validate_request(&ranges_map(
            vec![range(0, 1000, 1), range(1, u32::MAX - 2, 2)],
            vec![range(0, 1000, 1)],
        ))
        .expect("an extent ending one short of the reserved id is representable");
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
    fn a_reflected_map_names_the_inside_ids_on_both_sides() {
        // The nested namespace maps against the outer one's id space, so the
        // map that leaves the inside view unchanged names each extent's inside
        // ids twice. The outside column of the outer map — the host's ids — has
        // no meaning one namespace deeper.
        let outer = [range(0, 1000, 1), range(1, 100000, 65536)];
        assert_eq!(reflect_inside(&outer), [range(0, 0, 1), range(1, 1, 65536)],);
        assert_eq!(format_map(&reflect_inside(&outer)), b"0 0 1\n1 1 65536\n",);

        // The reflection preserves the extent count, so a map the kernel
        // accepts reflects to one it accepts. Checked at the ceiling, where a
        // reflection that split or merged extents would show.
        let ceiling: Vec<IdRange> = (0..MAX_EXTENTS as u32)
            .map(|i| range(i * 2, 100_000 + i * 2, 1))
            .collect();
        let reflected = reflect_inside(&ceiling);
        assert_eq!(reflected.len(), MAX_EXTENTS);
        validate_resolved(&ResolvedMap::new(reflected.clone(), reflected))
            .expect("a reflected map at the ceiling is still a valid one");
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

    #[cfg(feature = "subid")]
    #[test]
    fn an_extent_is_checked_against_the_whole_allocation() {
        // The containment check behind the `Ranges` refusal. An extent inside
        // one entry passes; one running past every entry does not.
        let allocation = [(100_000, 65_536), (300_000, 1_000)];
        assert!(maps_outside_range(&allocation, &range(1, 100_000, 65_536)));
        assert!(maps_outside_range(&allocation, &range(1, 165_535, 1)));
        assert!(!maps_outside_range(&allocation, &range(1, 165_536, 1)));
        assert!(!maps_outside_range(&allocation, &range(1, 99_999, 2)));
        assert!(!maps_outside_range(&allocation, &range(1, 300_000, 1_001)));
        // An extent spanning adjoining entries is legal — shadow's own
        // `have_range` accepts it — so refusing it would reject a map the
        // delegate would have applied.
        let adjoining = [(100_000, 65_536), (165_536, 65_536)];
        assert!(maps_outside_range(&adjoining, &range(1, 100_000, 131_072)));
        // A gap of one id is still a gap.
        let gapped = [(100_000, 65_536), (165_537, 65_536)];
        assert!(!maps_outside_range(&gapped, &range(1, 100_000, 131_072)));
        // An empty allocation covers nothing, and a zero-count entry is empty.
        assert!(!maps_outside_range(&[], &range(1, 100_000, 1)));
        assert!(!maps_outside_range(&[(100_000, 0)], &range(1, 100_000, 1)));
    }

    #[test]
    fn an_identity_carries_its_groups() {
        let identity = Identity::new(250, 250).groups([250, 100]);
        assert_eq!(identity.uid, 250);
        assert_eq!(identity.gid, 250);
        assert_eq!(identity.groups, [250, 100]);
    }
}
