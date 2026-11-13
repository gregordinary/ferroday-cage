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
use std::os::fd::AsFd;

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::error::ConfigError;
use crate::failure::ErrorChain;

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
/// Every form loads from a profile in every build of the library. Whether a
/// delegate can establish it is decided at [`CageBuilder::build`], which
/// refuses one no delegate can: a profile naming `subordinate` builds with a
/// configured delegate that reports an allocation, with or without the
/// `subid` feature.
///
/// [`CageBuilder::identity_map`]: crate::CageBuilder::identity_map
/// [`CageBuilder::build`]: crate::CageBuilder::build
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub enum IdentityMap {
    /// Root inside is the calling user outside, and no other id exists.
    /// This is the default.
    ///
    /// Reads of host ids outside the map present the overflow id (`nobody`),
    /// and changing a file's ownership to any other id fails with `EINVAL`,
    /// because the namespace cannot represent the id at all.
    ///
    /// A provisioner may substitute the `chown` and `chgrp` commands so that a
    /// packaging script shelling out to one succeeds here. Nothing covers a
    /// compiled helper calling `fchownat()` directly, or a POSIX ACL naming an
    /// unmapped id: both reach the kernel and fail. A userland holding packages
    /// that do either — `systemd`, whose `postinst` runs `systemd-tmpfiles`, is
    /// the common one — needs [`Subordinate`](IdentityMap::Subordinate) or
    /// [`Ranges`](IdentityMap::Ranges) instead.
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
/// Configured with [`CageBuilder::run_as`]; the default is root inside. A built
/// sandbox reports the identity it switches to as
/// [`ResolvedInputs::run_as`](crate::ResolvedInputs::run_as). The
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
    /// The supplementary groups, sandbox-inside ids. Requires a gid map wider
    /// than the caller's own gid: the single-identity map denies `setgroups`.
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
    /// Supplementary groups require a gid map wider than the caller's own
    /// gid. A gid map of that gid alone is the single-identity map's, under
    /// which `setgroups` is denied, so any groups are rejected at build time.
    /// That holds for a range map whose gid list is that one extent too.
    pub fn groups<I: IntoIterator<Item = u32>>(mut self, groups: I) -> Identity {
        self.groups = groups.into_iter().collect();
        self
    }

    /// The uid the command runs as, a sandbox-inside id.
    pub fn get_uid(&self) -> u32 {
        self.uid
    }

    /// The gid the command runs as, a sandbox-inside id.
    pub fn get_gid(&self) -> u32 {
        self.gid
    }

    /// The supplementary groups, sandbox-inside ids, in the order they were
    /// given.
    pub fn get_groups(&self) -> &[u32] {
        &self.groups
    }
}

/// The identity the single-identity map presents the caller to the command as.
///
/// Under [`IdentityMap::Single`] the sandbox holds one id, the caller, and the
/// command sees it as uid and gid 0. A presented identity shows the caller to
/// the command as another uid and gid instead. `id` reports them, files the
/// caller owns read as theirs, and the command holds no capability across its
/// `execve`. Configured with [`CageBuilder::present_as`].
///
/// It is a presentation, not a boundary. On the host the command is still the
/// caller, so it owns every file the caller owns, a rootfs the caller
/// provisioned among them. Nothing maps uid 0, so the command cannot become
/// root inside: a presented uid of 0 is refused when the sandbox is built, and
/// so is [`Own`](Self::Own) for a caller that is the host's root. Separating
/// the command from the rootfs by ownership needs a second id, which a range
/// map provides, and [`run_as`](crate::CageBuilder::run_as) switches the
/// command to it.
///
/// It renders and parses as `own` or `UID:GID`, the form a profile's
/// `present-as` key and the command line take.
///
/// # Example
///
/// ```
/// use ferroday_cage::PresentedIdentity;
///
/// let own: PresentedIdentity = "own".parse().unwrap();
/// assert_eq!(own, PresentedIdentity::Own);
/// let ids: PresentedIdentity = "1000:1000".parse().unwrap();
/// assert_eq!(ids, PresentedIdentity::ids(1000, 1000));
/// assert_eq!(ids.to_string(), "1000:1000");
/// ```
///
/// [`CageBuilder::present_as`]: crate::CageBuilder::present_as
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PresentedIdentity {
    /// The caller's own effective uid and gid, read when the sandbox is built.
    ///
    /// The command then sees the ids the host knows the caller by, so a
    /// layout that binds the host's `/etc` finds the caller's account there.
    /// A caller that is the host's root has uid 0 to present, which the build
    /// refuses.
    Own,
    /// The given uid and gid.
    ///
    /// Construct this variant with [`PresentedIdentity::ids`]. It is
    /// `#[non_exhaustive]` so that a further field can be added without
    /// breaking callers; match it with a trailing `..`.
    #[non_exhaustive]
    Ids {
        /// The uid the command sees the caller as.
        uid: u32,
        /// The gid the command sees the caller as.
        gid: u32,
    },
}

impl PresentedIdentity {
    /// Returns a presented identity of the given uid and gid.
    ///
    /// The constructor for [`PresentedIdentity::Ids`], which is
    /// `#[non_exhaustive]`.
    pub const fn ids(uid: u32, gid: u32) -> PresentedIdentity {
        PresentedIdentity::Ids { uid, gid }
    }

    /// The uid and gid this presents the caller as, reading the caller's own
    /// effective ids for [`Own`](Self::Own).
    ///
    /// Read from the process building the sandbox, which is the process whose
    /// effective ids the single-identity map names: see
    /// [`single_identity_lines`].
    pub(crate) fn resolve(self) -> (u32, u32) {
        match self {
            PresentedIdentity::Own => (
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
            ),
            PresentedIdentity::Ids { uid, gid } => (uid, gid),
        }
    }
}

impl fmt::Display for PresentedIdentity {
    /// Writes `own`, or the ids as `UID:GID`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PresentedIdentity::Own => f.write_str(PRESENTED_OWN),
            PresentedIdentity::Ids { uid, gid } => write!(f, "{uid}:{gid}"),
        }
    }
}

impl std::str::FromStr for PresentedIdentity {
    type Err = ParsePresentedIdentityError;

    /// Parses `own`, or a uid and a gid as `UID:GID`.
    fn from_str(s: &str) -> Result<PresentedIdentity, ParsePresentedIdentityError> {
        if s == PRESENTED_OWN {
            return Ok(PresentedIdentity::Own);
        }
        let error = || ParsePresentedIdentityError {
            text: s.to_string(),
        };
        let (uid, gid) = s.split_once(':').ok_or_else(error)?;
        Ok(PresentedIdentity::Ids {
            uid: uid.parse().map_err(|_| error())?,
            gid: gid.parse().map_err(|_| error())?,
        })
    }
}

/// The spelling of [`PresentedIdentity::Own`].
const PRESENTED_OWN: &str = "own";

/// A presented identity renders as its string form.
#[cfg(feature = "serde")]
impl serde::Serialize for PresentedIdentity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Accepts the string form a presented identity renders as.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PresentedIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(PresentedIdentityVisitor)
    }
}

#[cfg(feature = "serde")]
struct PresentedIdentityVisitor;

#[cfg(feature = "serde")]
impl serde::de::Visitor<'_> for PresentedIdentityVisitor {
    type Value = PresentedIdentity;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PRESENTED_OWN:?} or UID:GID")
    }

    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<PresentedIdentity, E> {
        text.parse().map_err(E::custom)
    }
}

/// The error from parsing a [`PresentedIdentity`] that is neither `own` nor
/// `UID:GID`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePresentedIdentityError {
    text: String,
}

impl ParsePresentedIdentityError {
    /// The unparsed text, as it was given.
    ///
    /// Named `text` on every parse error in this crate, so a caller moving
    /// between them does not have to check.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ParsePresentedIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "expected {PRESENTED_OWN:?} or UID:GID for a presented identity, not {:?}",
            self.text
        )
    }
}

impl std::error::Error for ParsePresentedIdentityError {}

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
/// An `Arc` or a `Box` of a delegate is a delegate too, forwarding every
/// method to what it holds. One instance is shared between builders as an
/// `Arc`, and one chosen at run time is passed as a `Box<dyn IdMapper>`.
///
/// # Authority
///
/// A delegate decides which host ids a sandbox holds, so it holds every
/// request to the caller's own authority. The request is configuration, and
/// an untrusted profile can carry one: a range `identity-map` and a `run-as`
/// identity pass the restricted policy a `RestrictedProfile` loads under. The
/// bundled delegates check the outside ids in [`resolve`](Self::resolve) and
/// refuse the rest. [`DirectMapper`] checks them against the caller's
/// capabilities and its own namespace's map, and `SubidMapper` against the
/// caller's subordinate allocation. A delegate with privilege of its own, such
/// as a broker running as root, must check them too. One that maps whatever it
/// is asked lets a profile map host ids the caller does not hold, host root
/// among them, into the sandbox.
///
/// # Stability
///
/// Every method added to this trait in a later release will carry a default
/// body, so an existing implementation keeps compiling. The two existing
/// methods take their inputs as loose parameters because those inputs are
/// closed: a resolution is a request, and an application is a process and the
/// extents to write it. Anything richer arrives as a new defaulted method.
///
/// A method added here is forwarded by the `Arc` and `Box` implementations as
/// well, defaulted ones included. A wrapper that left one out would run the
/// default body in place of the wrapped delegate's own. A test compares the
/// method lists.
///
/// [`CageBuilder::id_mapper`]: crate::CageBuilder::id_mapper
pub trait IdMapper: fmt::Debug + Send + Sync {
    /// The ranges this delegate can provide for the request.
    ///
    /// Called from [`CageBuilder::build`], so a map that cannot be satisfied
    /// is a configuration error rather than a launch failure. A delegate
    /// refuses here whatever it can already tell [`apply`](Self::apply) would
    /// fail on: a helper it cannot run, a privilege it lacks, outside ids the
    /// caller has no claim to. The returned map is validated against the same
    /// rules as an explicit [`IdentityMap::Ranges`].
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

/// A shared delegate is a delegate, so one instance can be named to every
/// builder that must establish the same map.
///
/// Every method forwards to the shared delegate, the defaulted ones included.
/// A caller cannot write this for an `Arc` of a delegate of its own, since
/// neither the trait nor `Arc` is the caller's.
impl<M: IdMapper + ?Sized> IdMapper for std::sync::Arc<M> {
    fn resolve(&self, request: &IdentityMap) -> Result<ResolvedMap, IdMapError> {
        (**self).resolve(request)
    }

    fn apply(&self, pid: u32, map: &ResolvedMap) -> Result<(), IdMapError> {
        (**self).apply(pid, map)
    }
}

/// A boxed delegate is a delegate, so one chosen at run time is passed wherever
/// a delegate is taken.
///
/// Every method forwards to the boxed delegate, the defaulted ones included. A
/// caller cannot write this for a `Box<dyn IdMapper>`, since neither the trait
/// nor the trait object is the caller's.
impl<M: IdMapper + ?Sized> IdMapper for Box<M> {
    fn resolve(&self, request: &IdentityMap) -> Result<ResolvedMap, IdMapError> {
        (**self).resolve(request)
    }

    fn apply(&self, pid: u32, map: &ResolvedMap) -> Result<(), IdMapError> {
        (**self).apply(pid, map)
    }
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
            IdMapError::HelperSpawn { helper, .. } => write!(f, "could not execute {helper}"),
            IdMapError::HelperFailed { helper, detail } => {
                if detail.is_empty() {
                    write!(f, "{helper} refused the map")
                } else {
                    write!(f, "{helper} refused the map: {detail}")
                }
            }
            IdMapError::MapWrite { which, .. } => write!(f, "could not write {which}"),
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

/// Whether a gid map is the caller's own gid alone: one extent, of one id,
/// naming the caller's effective gid.
///
/// That is the single-identity map's gid map, and the writers that hold no
/// privilege over the parent namespace deny `setgroups` when they write it.
/// The kernel requires the denial of a process writing its own map. shadow's
/// `newgidmap` writes the denial for any map no subordinate grant covers, and
/// a caller's own gid lies outside its subordinate allocation. No supplementary
/// group list can then be set inside, so a run-as identity under such a map
/// names none, whoever wrote it, and keeps the list it inherited.
pub(crate) fn is_own_gid_alone(gid: &[IdRange]) -> bool {
    matches!(gid, [only] if only.count == 1 && only.outside == rustix::process::getegid().as_raw())
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
fn validate_request(map: &IdentityMap) -> Result<(), ConfigError> {
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
fn validate_resolved(map: &ResolvedMap) -> Result<(), ConfigError> {
    for (which, ranges) in [("uid", map.uid()), ("gid", map.gid())] {
        validate_ranges(which, ranges).map_err(|reason| ConfigError::IdentityMapInvalid {
            reason: format!("the identity-map delegate resolved an invalid map: {reason}"),
        })?;
    }
    Ok(())
}

/// Resolves a range request to the delegate that applies it and the extents
/// it resolved: the configured delegate, whose refusal is final, and the
/// bundled chain where none is configured.
///
/// The step every range map passes through: a build, a provisioner's
/// preflight, an export, a copy in, and a map-assisted removal alike. The
/// request is validated before any delegate sees it and the delegate's answer
/// after, so a malformed map is a typed refusal naming its defect rather than
/// an `EINVAL` from the kernel at the write.
pub(crate) fn resolve_delegate(
    request: &IdentityMap,
    configured: Option<&std::sync::Arc<dyn IdMapper>>,
) -> Result<(std::sync::Arc<dyn IdMapper>, ResolvedMap), ConfigError> {
    match configured {
        Some(mapper) => {
            let map = resolve_range(request, mapper.as_ref())?;
            Ok((std::sync::Arc::clone(mapper), map))
        }
        None => resolve_range_bundled(request),
    }
}

/// Whether `request` can be established, through the configured delegate or
/// the bundled chain: the preflight a provisioner takes before it downloads
/// anything, so an unavailable range map is a configuration refusal rather than
/// a failure partway through a run. The single-identity map needs no delegate
/// and is always establishable.
///
/// The map is resolved here and dropped; each sandbox the run launches
/// resolves its own at its build.
#[cfg(any(feature = "debian", feature = "alpine"))]
pub(crate) fn establishable(
    request: &IdentityMap,
    configured: Option<&std::sync::Arc<dyn IdMapper>>,
) -> Result<(), ConfigError> {
    match request {
        IdentityMap::Single => Ok(()),
        _ => resolve_delegate(request, configured).map(drop),
    }
}

/// Resolves a range request through the caller's own delegate, whose refusal
/// is final.
///
/// One of the two halves of [`resolve_delegate`], with
/// [`resolve_range_bundled`].
fn resolve_range(request: &IdentityMap, mapper: &dyn IdMapper) -> Result<ResolvedMap, ConfigError> {
    // The delegate's refusal is carried whole, as the error's source, as well as
    // rendered with its causes into the reason.
    checked(request, || {
        mapper
            .resolve(request)
            .map(|map| ((), map))
            .map_err(|err| (ErrorChain::new(&err).to_string(), Some(err)))
    })
    .map(|((), map)| map)
}

/// Resolves a range request through the bundled delegates, returning the one
/// that accepted it with the map it resolved.
///
/// The other half of [`resolve_delegate`], for a caller that configured no
/// delegate of its own.
fn resolve_range_bundled(
    request: &IdentityMap,
) -> Result<(std::sync::Arc<dyn IdMapper>, ResolvedMap), ConfigError> {
    // The chain's reason collects a refusal from each delegate, so there is no
    // one error to carry as the source.
    checked(request, || {
        resolve_default_chain(request).map_err(|reason| (reason, None))
    })
}

/// The validation both entry points share: the request before `resolve` runs,
/// and the map it resolved after.
///
/// A refusal is the reason text and, where one delegate's error is the whole
/// story, that error.
fn checked<T>(
    request: &IdentityMap,
    resolve: impl FnOnce() -> Result<(T, ResolvedMap), (String, Option<IdMapError>)>,
) -> Result<(T, ResolvedMap), ConfigError> {
    validate_request(request)?;
    let (delegate, map) = resolve()
        .map_err(|(reason, source)| ConfigError::IdentityMapUnavailable { reason, source })?;
    validate_resolved(&map)?;
    Ok((delegate, map))
}

/// Whether the calling thread runs under `no_new_privs`, which an exec cannot
/// raise privilege across: what the subordinate delegate and the host probe
/// both ask before relying on a setuid or file-capability helper. An
/// unreadable flag answers `false`, leaving the helpers themselves as the
/// arbiter.
#[cfg(feature = "subid")]
pub(crate) fn no_new_privs() -> bool {
    rustix::thread::no_new_privs().unwrap_or(false)
}

/// The single-identity map's `uid_map` and `gid_map` contents, in that order:
/// root inside as the caller's effective uid and gid outside.
///
/// The kernel's one-id exception admits exactly this map, naming the writer's
/// own effective ids. A child that writes it has unshared by then, and its
/// `geteuid` answers inside the new namespace, so the lines are formatted
/// before the fork, where the ids are still the caller's, and the child only
/// writes them.
pub(crate) fn single_identity_lines() -> (Vec<u8>, Vec<u8>) {
    let line = |outside| {
        format_map(&[IdRange {
            inside: 0,
            outside,
            count: 1,
        }])
    };
    (
        line(rustix::process::geteuid().as_raw()),
        line(rustix::process::getegid().as_raw()),
    )
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
/// require: they accept the whole map in one write and nothing else. The write
/// is [`frame::write_whole`](crate::mechanism::frame::write_whole), the one the
/// post-fork stages make for the same files.
fn write_map_file(path: &str, which: &'static str, data: &[u8]) -> Result<(), IdMapError> {
    let map_write = |errno: Errno| IdMapError::map_write(which, errno.into());
    let fd = rustix::fs::open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(map_write)?;
    crate::mechanism::frame::write_whole(fd.as_fd(), data).map_err(map_write)
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

        if let Some(reason) = direct_write_refusal(&uid, effective_capabilities()) {
            return Err(IdMapError::unsatisfiable(reason));
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

/// The calling thread's effective capability set, or the empty set where it
/// cannot be read.
///
/// The effective set is the one the direct tier asks about: the map files need
/// the capabilities effective, and a write does not raise them from the
/// permitted set.
pub(crate) fn effective_capabilities() -> rustix::thread::CapabilitySet {
    rustix::thread::capabilities(None)
        .map(|sets| sets.effective)
        .unwrap_or_else(|_| rustix::thread::CapabilitySet::empty())
}

/// Why a caller holding `effective` cannot write a map with these uid extents
/// directly, or `None` when it can.
///
/// The one answer to whether a caller writes a range map directly:
/// [`DirectMapper`] asks it of a request, and
/// [`range_map_blocker`](crate::host::range_map_blocker) asks it of no extent
/// at all, which leaves the capabilities every direct write needs.
///
/// The map files need `CAP_SETUID` and `CAP_SETGID` over the parent namespace.
/// Since Linux 5.12 a `uid_map` naming the parent's uid 0 among its outside ids
/// also needs `CAP_SETFCAP`: without it, a root that had shed the capability
/// could hand the new namespace file capabilities the parent honours. The rule
/// is about the outside id alone, so `0 1 1` needs no `CAP_SETFCAP` and `5 0 1`
/// does.
pub(crate) fn direct_write_refusal(
    uid: &[IdRange],
    effective: rustix::thread::CapabilitySet,
) -> Option<String> {
    use rustix::thread::CapabilitySet;

    for (capability, name) in [
        (CapabilitySet::SETUID, "CAP_SETUID"),
        (CapabilitySet::SETGID, "CAP_SETGID"),
    ] {
        if !effective.contains(capability) {
            return Some(format!(
                "writing a range map directly requires {name} over the current user \
                 namespace, which the caller does not hold",
            ));
        }
    }
    if uid.iter().any(|range| range.outside == 0) && !effective.contains(CapabilitySet::SETFCAP) {
        return Some(
            "the uid map names outside uid 0, which a direct write may map only while \
             holding CAP_SETFCAP over the current user namespace, and the caller does not"
                .to_string(),
        );
    }
    None
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
    /// [`resolve`](IdMapper::resolve) first refuses a host on which the helpers
    /// cannot work at all: a caller under `no_new_privs`, a helper missing from
    /// `PATH` or holding no privilege, or a subordinate file that is a symbolic
    /// link. It asks the same question
    /// [`host::range_map_blocker`](crate::host::range_map_blocker) asks, through
    /// the same check, so the build refuses exactly the hosts the probe names.
    /// It then determines the caller's allocation with the NSS-aware
    /// `getsubids` query where available, falling back to reading `/etc/subuid`
    /// and `/etc/subgid` only on hosts whose `nsswitch.conf` names no other
    /// `subid` source — the same rule the helpers themselves follow, so the
    /// fallback can never invent an allocation an NSS module would deny.
    /// [`apply`](IdMapper::apply) executes the helpers against the gated
    /// sandbox process.
    ///
    /// *Which* helpers is decided by the ambient `PATH`, which is worth knowing
    /// for a consumer running this from a daemon with an inherited environment.
    /// They are looked up by name among the absolute `PATH` entries — a relative
    /// entry is skipped rather than resolved against the process's working
    /// directory — and the resolved absolute path is what executes. `resolve`
    /// judges a helper's privilege through the same lookup, so the binary it
    /// judged is the one `apply` runs; a `PATH` that changes between the build
    /// and the launch is the caller's to keep still. The two auxiliary tools
    /// `resolve` consults — `id` for the caller's user name, and `getsubids`
    /// for the allocation itself — are resolved by the same rule.
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
            // A condition that stops the helpers themselves fails every map
            // they are asked to write, so it is a refusal here rather than an
            // `EPERM` or a missing binary at the launch.
            if !matches!(request, IdentityMap::Single)
                && let Some(blocker) = crate::host::helper_blocker()
            {
                return Err(IdMapError::unsatisfiable(blocker.to_string()));
            }
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
    /// [`host::helper_blocker`](crate::host::helper_blocker) uses to judge its
    /// privilege at `resolve`, rather than handed to `Command` as a bare name
    /// for it to resolve again on its own terms. The two would otherwise be free
    /// to differ — `Command` searches every `PATH` entry, this lookup only the
    /// absolute ones — and the build's verdict would describe a binary that is
    /// not the one that runs.
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
        // The helpers honour a subordinate entry under the user name and one
        // under the literal uid string alike, so the allocation is the entries
        // of both keys. The name lookup is delegated to `id`, whose NSS-aware
        // resolution covers directory-service users that /etc/passwd does not
        // list.
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

    /// Queries `getsubids` for each key, collecting the ranges every one
    /// answers with, in the order of the keys.
    ///
    /// Output lines have the shape `index: owner start count`. A `getsubids`
    /// asked for a user name lists the entries under that user's uid as well,
    /// and asking for the uid then lists them again; the duplicate is harmless,
    /// since composing the map skips ids an earlier entry already granted.
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
    /// entry whose owner field matches one of the keys, in file order.
    ///
    /// Every key counts, as it does for the helpers: `newuidmap` accepts an
    /// extent inside an entry under the caller's user name or under the
    /// caller's uid, and one spanning adjoining entries of either. A block
    /// granted under both is collected twice, which composing the map
    /// absorbs. shadow also honours an entry under another user name that
    /// resolves to the same uid; that one is not collected, since telling it
    /// apart would take a lookup of every owner in the file, and missing it
    /// only refuses at build a map the helpers would have written.
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
    ///
    /// An outside id is mapped once. The part of an entry an earlier extent
    /// already maps is skipped, so a block granted under both the user name
    /// and the uid, or entries an administrator let overlap, compose to the
    /// ids they grant between them rather than to a map the kernel refuses
    /// for its overlap.
    fn compose_subordinate(own: u32, allocation: &[(u32, u32)]) -> Vec<IdRange> {
        let mut ranges = vec![IdRange {
            inside: 0,
            outside: own,
            count: 1,
        }];
        let mut inside = 1u32;
        // A zero-count entry contributes nothing but is a legal line in a
        // subordinate file; it has no unmapped part, so it is passed over and
        // the entries after it are kept, which stopping would silently drop.
        'entries: for &(start, count) in allocation {
            for (start, count) in unmapped_parts(&ranges, start, count) {
                // An allocation vast enough to exhaust the 32-bit inside space
                // is truncated at the boundary; ids beyond it are
                // unaddressable, and nothing after this entry can be addressed
                // either.
                let count = count.min(u32::MAX - inside);
                if count == 0 {
                    break 'entries;
                }
                // A map file carries at most MAX_EXTENTS lines, and an
                // administrator is free to grant more separate ranges than
                // that. Truncating keeps a legal host configuration working
                // with a smaller map, where emitting them all would fail the
                // build with a message blaming the delegate for the host's
                // allocation.
                if ranges.len() == super::MAX_EXTENTS {
                    break 'entries;
                }
                ranges.push(IdRange {
                    inside,
                    outside: start,
                    count,
                });
                inside += count;
            }
        }
        ranges
    }

    /// The parts of the outside ids `start` onward, `count` of them, that no
    /// extent in `mapped` maps yet, as `(start, count)` pairs in ascending
    /// order.
    ///
    /// A span running past the last id is cut at it, as the entry's own
    /// arithmetic cannot carry it further.
    fn unmapped_parts(mapped: &[IdRange], start: u32, count: u32) -> Vec<(u32, u32)> {
        if count == 0 {
            return Vec::new();
        }
        // Inclusive bounds, so a span ending at the last id needs no id past it.
        let mut parts = vec![(start, start.saturating_add(count - 1))];
        for extent in mapped {
            let taken_first = extent.outside;
            let taken_last = extent
                .outside
                .saturating_add(extent.count.saturating_sub(1));
            parts = parts
                .into_iter()
                .flat_map(|(first, last)| {
                    if taken_last < first || taken_first > last {
                        return vec![(first, last)];
                    }
                    // The subtractions cannot wrap: each runs only where the
                    // taken span starts after `first` or ends before `last`.
                    let mut kept = Vec::with_capacity(2);
                    if first < taken_first {
                        kept.push((first, taken_first - 1));
                    }
                    if taken_last < last {
                        kept.push((taken_last + 1, last));
                    }
                    kept
                })
                .collect();
        }
        parts
            .into_iter()
            .map(|(first, last)| (first, (last - first).saturating_add(1)))
            .collect()
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

        /// `newuidmap` honours an entry under the caller's name and one under
        /// the caller's uid alike, so the allocation is every entry of either,
        /// in file order, and an entry of another owner is no part of it.
        #[test]
        fn every_entry_under_the_name_or_the_uid_is_the_allocation() {
            let dir = crate::scratch::Scratch::new("subid-owners");
            let path = dir.join("subuid");
            std::fs::write(
                &path,
                "alice:100000:65536\n\
                 bob:165536:65536\n\
                 # a comment\n\
                 1000:231072:65536\n\
                 alice:300000:1000\n",
            )
            .unwrap();
            let keys = ["alice".to_string(), "1000".to_string()];
            assert_eq!(
                parse_subid_file(path.to_str().unwrap(), &keys),
                [(100000, 65536), (231072, 65536), (300000, 1000)],
            );
        }

        /// A block granted under both the name and the uid is one grant, and
        /// entries that overlap compose to the ids they grant between them: a
        /// map naming an outside id twice is one the kernel refuses.
        #[test]
        fn an_outside_id_granted_twice_is_mapped_once() {
            let duplicated = compose_subordinate(1000, &[(100000, 65536), (100000, 65536)]);
            assert_eq!(
                duplicated,
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
                ]
            );

            // An entry straddling an earlier one keeps the parts on either
            // side of it, in order, and the caller's own id is not mapped a
            // second time either.
            let straddling = compose_subordinate(1000, &[(200, 100), (100, 400), (900, 200)]);
            assert_eq!(
                straddling,
                [
                    IdRange {
                        inside: 0,
                        outside: 1000,
                        count: 1
                    },
                    IdRange {
                        inside: 1,
                        outside: 200,
                        count: 100
                    },
                    IdRange {
                        inside: 101,
                        outside: 100,
                        count: 100
                    },
                    IdRange {
                        inside: 201,
                        outside: 300,
                        count: 200
                    },
                    IdRange {
                        inside: 401,
                        outside: 900,
                        count: 100
                    },
                    IdRange {
                        inside: 501,
                        outside: 1001,
                        count: 99
                    },
                ]
            );
            for map in [duplicated, straddling] {
                crate::idmap::validate_resolved(&ResolvedMap::new(map.clone(), map))
                    .expect("a composed map never overlaps itself");
            }
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
/// feature is enabled. On failure the reason collects one refusal from each,
/// so the error names what to fix.
///
/// The subordinate delegate's refusal is the host probe's diagnosis already:
/// it refuses a host the helpers cannot work on with the condition
/// [`host::range_map_blocker`](crate::host::range_map_blocker) names, and an
/// unusable allocation in the probe's words. Without the feature the chain says
/// that delegate is absent, which is the probe's one other diagnosis.
///
/// Reached only through [`resolve_range_bundled`], which validates around it.
fn resolve_default_chain(
    request: &IdentityMap,
) -> Result<(std::sync::Arc<dyn IdMapper>, ResolvedMap), String> {
    let mut reasons: Vec<String> = Vec::new();

    let direct: std::sync::Arc<dyn IdMapper> = std::sync::Arc::new(DirectMapper::new());
    match direct.resolve(request) {
        Ok(map) => return Ok((direct, map)),
        Err(err) => reasons.push(format!("direct: {}", ErrorChain::new(&err))),
    }

    #[cfg(feature = "subid")]
    {
        let subid: std::sync::Arc<dyn IdMapper> = std::sync::Arc::new(SubidMapper::new());
        match subid.resolve(request) {
            Ok(map) => return Ok((subid, map)),
            Err(err) => reasons.push(format!("subid: {}", ErrorChain::new(&err))),
        }
    }
    #[cfg(not(feature = "subid"))]
    reasons.push(
        "subid: the library was built without the `subid` feature, whose delegate runs the \
         shadow suite's helpers and reports a subordinate allocation"
            .to_string(),
    );

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

    /// A shared or boxed delegate runs the delegate's own methods, and a shared
    /// one is the same instance in every builder it is named to.
    #[test]
    fn a_shared_or_boxed_delegate_forwards_every_method() {
        /// Counts the calls each of its methods takes.
        #[derive(Debug, Default)]
        struct Counting {
            resolved: std::sync::Mutex<usize>,
            applied: std::sync::Mutex<usize>,
        }
        impl IdMapper for Counting {
            fn resolve(&self, _request: &IdentityMap) -> Result<ResolvedMap, IdMapError> {
                *self.resolved.lock().unwrap() += 1;
                let root = IdRange {
                    inside: 0,
                    outside: 100_000,
                    count: 1,
                };
                Ok(ResolvedMap::new(vec![root], vec![root]))
            }
            fn apply(&self, _pid: u32, _map: &ResolvedMap) -> Result<(), IdMapError> {
                *self.applied.lock().unwrap() += 1;
                Ok(())
            }
        }

        let shared = std::sync::Arc::new(Counting::default());
        let as_dyn: std::sync::Arc<dyn IdMapper> = std::sync::Arc::clone(&shared) as _;
        let boxed: Box<dyn IdMapper> = Box::new(std::sync::Arc::clone(&shared));
        for wrapper in [&as_dyn as &dyn IdMapper, &boxed as &dyn IdMapper] {
            let map = wrapper
                .resolve(&IdentityMap::Subordinate)
                .expect("the delegate resolves");
            wrapper.apply(1, &map).expect("the delegate applies");
        }
        assert_eq!(*shared.resolved.lock().unwrap(), 2);
        assert_eq!(*shared.applied.lock().unwrap(), 2);

        // Named to a builder, the shared instance is the one asked.
        crate::Cage::builder()
            .rootfs("/tmp")
            .command("/bin/sh")
            .identity_map(IdentityMap::Subordinate)
            .id_mapper(std::sync::Arc::clone(&shared))
            .build()
            .expect("the shared delegate resolves the build's map");
        assert_eq!(*shared.resolved.lock().unwrap(), 3);
    }

    /// An identity reads back as it was built, so the value `get_run_as` and a
    /// resolved record hand a caller is one the caller can read.
    #[test]
    fn an_identity_reads_back_what_it_was_built_from() {
        let plain = Identity::new(250, 100);
        assert_eq!((plain.get_uid(), plain.get_gid()), (250, 100));
        assert!(plain.get_groups().is_empty());

        let grouped = plain.groups([100, 27, 4]);
        assert_eq!((grouped.get_uid(), grouped.get_gid()), (250, 100));
        assert_eq!(grouped.get_groups(), [100, 27, 4], "in the order given");
    }

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

    #[test]
    fn a_direct_write_naming_outside_uid_0_needs_cap_setfcap() {
        use rustix::thread::CapabilitySet;

        // The kernel's rule, measured: `0 0 1` and `5 0 1` are refused to a
        // writer without CAP_SETFCAP, and `0 1 1` is written.
        let setid = CapabilitySet::SETUID | CapabilitySet::SETGID;
        let names_root = [range(0, 0, 1)];
        let names_root_elsewhere = [range(0, 1, 1), range(5, 0, 1)];
        let spares_root = [range(0, 1, 1), range(1, 100_000, 65_536)];
        for uid in [&names_root[..], &names_root_elsewhere[..]] {
            let reason = direct_write_refusal(uid, setid).expect("refused without CAP_SETFCAP");
            assert!(reason.contains("CAP_SETFCAP"), "{reason}");
            assert_eq!(
                direct_write_refusal(uid, setid | CapabilitySet::SETFCAP),
                None
            );
        }
        assert_eq!(direct_write_refusal(&spares_root, setid), None);
        // The id-setting capabilities come first, whatever the map.
        let reason = direct_write_refusal(&spares_root, CapabilitySet::SETGID).unwrap();
        assert!(reason.contains("CAP_SETUID"), "{reason}");
    }

    /// A delegate that resolves whatever it is given, verbatim, or a map of its
    /// own choosing.
    #[derive(Debug)]
    struct Verbatim(Option<ResolvedMap>);

    impl IdMapper for Verbatim {
        fn resolve(&self, request: &IdentityMap) -> Result<ResolvedMap, IdMapError> {
            match (&self.0, request) {
                (Some(map), _) => Ok(map.clone()),
                (None, IdentityMap::Ranges { uid, gid }) => {
                    Ok(ResolvedMap::new(uid.clone(), gid.clone()))
                }
                (None, _) => Err(IdMapError::unsatisfiable("ranges only")),
            }
        }

        fn apply(&self, _pid: u32, _map: &ResolvedMap) -> Result<(), IdMapError> {
            Ok(())
        }
    }

    #[test]
    fn a_range_request_is_validated_whichever_delegate_resolves_it() {
        // A delegate that would answer anything does not let a malformed request
        // through: the request is held to the kernel's rules before it is
        // asked, even by a delegate whose answer would be a valid map.
        let valid = ResolvedMap::new(vec![range(0, 1000, 1)], vec![range(0, 1000, 1)]);
        let empty_uid = ranges_map(vec![], vec![range(0, 1000, 1)]);
        let err = resolve_range(&empty_uid, &Verbatim(Some(valid))).unwrap_err();
        assert!(
            matches!(&err, ConfigError::IdentityMapInvalid { reason } if reason.contains("uid range list is empty")),
            "{err}",
        );

        // Nor does a delegate's own malformed answer reach the kernel.
        let no_root = ResolvedMap::new(vec![range(1, 1000, 1)], vec![range(0, 1000, 1)]);
        let request = ranges_map(vec![range(0, 1000, 1)], vec![range(0, 1000, 1)]);
        let err = resolve_range(&request, &Verbatim(Some(no_root))).unwrap_err();
        assert!(
            matches!(&err, ConfigError::IdentityMapInvalid { reason } if reason.contains("delegate resolved an invalid map")),
            "{err}",
        );

        // A refusal is the delegate's, reported as unavailability.
        let err = resolve_range(&IdentityMap::Subordinate, &Verbatim(None)).unwrap_err();
        assert!(
            matches!(&err, ConfigError::IdentityMapUnavailable { reason, .. } if reason == "ranges only"),
            "{err}",
        );

        // And a well-formed request through a willing delegate resolves.
        assert_eq!(
            resolve_range(&request, &Verbatim(None)).unwrap().uid(),
            [range(0, 1000, 1)],
        );
    }

    #[cfg(feature = "subid")]
    #[test]
    fn no_new_privs_defeats_the_subordinate_delegate_and_the_probe_says_so() {
        // The flag is a property of the thread, and setting it cannot be undone,
        // so it is set on a thread of the test's own that ends with the test.
        std::thread::spawn(|| {
            rustix::thread::set_no_new_privs(true).expect("no_new_privs can be set");
            let err = SubidMapper::new()
                .resolve(&IdentityMap::Subordinate)
                .unwrap_err();
            assert!(err.to_string().contains("no_new_privs"), "{err}");
            // A caller holding CAP_SETUID and CAP_SETGID writes maps directly,
            // and the flag is no obstacle to that; this test process holds
            // neither unless it runs as root.
            if !effective_capabilities().contains(rustix::thread::CapabilitySet::SETUID) {
                assert_eq!(
                    crate::host::range_map_blocker(),
                    Some(crate::host::RangeMapBlocker::NoNewPrivileges),
                );
            }
        })
        .join()
        .expect("the no_new_privs thread asserts");
    }

    /// Marks the child run of the helper test below, carrying the text the
    /// refusal must name.
    #[cfg(feature = "subid")]
    const HELPER_REFUSAL: &str = "FERRODAY_CAGE_TEST_HELPER_REFUSAL";

    /// A host whose shadow helpers cannot work refuses a range map at build and
    /// at a provisioner's preflight, naming the condition the probe names,
    /// rather than passing both and failing at the launch.
    ///
    /// `PATH` decides which helpers there are, and it is the process's own, so
    /// each case runs in a child process of this test binary with a `PATH` of
    /// the case's making.
    #[cfg(feature = "subid")]
    #[test]
    fn helpers_that_cannot_work_refuse_the_build_and_the_preflight() {
        if let Some(expected) = std::env::var_os(HELPER_REFUSAL) {
            let expected = expected.to_str().expect("the expectation is text");
            let blocker = crate::host::helper_blocker().expect("the helpers cannot work here");
            assert!(blocker.to_string().contains(expected), "{blocker}");
            if !effective_capabilities().contains(rustix::thread::CapabilitySet::SETUID) {
                assert_eq!(crate::host::range_map_blocker(), Some(blocker.clone()));
            }

            let ranges = IdentityMap::ranges(
                vec![range(0, rustix::process::geteuid().as_raw(), 1)],
                vec![range(0, rustix::process::getegid().as_raw(), 1)],
            );
            for request in [IdentityMap::Subordinate, ranges] {
                let refusal = SubidMapper::new()
                    .resolve(&request)
                    .expect_err("the delegate refuses what its helpers cannot write");
                assert_eq!(refusal.to_string(), blocker.to_string());
            }

            let err = crate::Cage::builder()
                .rootfs("/tmp")
                .command("/bin/true")
                .identity_map(IdentityMap::Subordinate)
                .build()
                .expect_err("the build refuses the map");
            assert!(
                matches!(
                    &err,
                    crate::Error::Config(ConfigError::IdentityMapUnavailable { reason, .. })
                        if reason.contains(expected)
                ),
                "{err}",
            );
            // What the Debian and Alpine provisioners ask before they download.
            #[cfg(any(feature = "debian", feature = "alpine"))]
            {
                let refusal = establishable(&IdentityMap::Subordinate, None)
                    .expect_err("the preflight refuses the map");
                assert!(refusal.to_string().contains(expected), "{refusal}");
            }
            return;
        }

        // The flag stops every helper first, so neither case below is
        // reachable under it; the test above holds that case.
        if no_new_privs() {
            return;
        }
        let run = |path: &std::path::Path, expected: &str| {
            let output = ferroday_cage_testkit::process::run_bounded(
                ferroday_cage_testkit::process::rerun(
                    "idmap::tests::helpers_that_cannot_work_refuse_the_build_and_the_preflight",
                )
                .env("PATH", path)
                .env(HELPER_REFUSAL, expected),
                std::time::Duration::from_secs(60),
            );
            assert!(
                output.status.success(),
                "the child refused otherwise:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        };

        // No helper on `PATH` at all.
        let missing = Scratch::new("helpers-missing");
        run(&missing, "newuidmap was not found on PATH");

        // Helpers that are present but hold no privilege, beside the real tools
        // the allocation query uses: the allocation answers as it does on this
        // host, so the helpers are all that can refuse.
        let stripped = Scratch::new("helpers-stripped");
        for helper in ["newuidmap", "newgidmap"] {
            let path = stripped.join(helper);
            std::fs::write(&path, "#!/bin/sh\nexit 1\n").unwrap();
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .unwrap();
        }
        for tool in ["id", "getsubids"] {
            if let Some(real) = crate::host::find_on_path(tool) {
                std::os::unix::fs::symlink(real, stripped.join(tool)).unwrap();
            }
        }
        run(
            &stripped,
            "is neither setuid-root nor granted a file capability",
        );
    }
}
