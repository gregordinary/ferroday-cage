//! Per-process resource limits applied to the sandboxed command.
//!
//! The sandbox's namespaces bound what the command can *reach*; a resource
//! limit bounds what it can *consume*. The two are independent: a command
//! confined to a private root with no network can still fork without end,
//! allocate without end, and fill the filesystem it was given.
//!
//! A limit is set with [`CageBuilder::rlimit`](crate::CageBuilder::rlimit) and
//! is applied to the command process immediately before the hardening layer, so
//! the command and every process it starts inherit it. Limits are the kernel's
//! own `setrlimit` values with the kernel's own semantics — see
//! [`Resource`] for the caveats that matter in a sandbox.
//!
#![cfg_attr(
    feature = "hardening",
    doc = "The restriction fallback carries the same knob as"
)]
#![cfg_attr(
    feature = "hardening",
    doc = "[`RestrictionBuilder::rlimit`](crate::RestrictionBuilder::rlimit)."
)]
#![cfg_attr(feature = "hardening", doc = "")]
//! With the `serde` feature a cage's limits are part of the profile format, as
//! an `[rlimit]` table keyed by resource name:
//!
//! ```toml
//! [rlimit]
//! processes = 64                                # soft and hard alike
//! address-space = 536870912
//! open-files = "unlimited"
//! cpu-time = { soft = 10, hard = "unlimited" }  # when the two differ
//! ```
//!
//! Amounts there are TOML integers, so a profile expresses limits up to
//! `i64::MAX`. Nothing a real resource is counted in reaches that; a limit
//! meant to be absent is `"unlimited"` rather than a very large number.
//!
//! Resource *governance* is a different thing and remains outside this
//! library: cgroup controllers, disk quotas, and I/O throttling are the host's
//! to configure. What is here is the per-process axis, which needs no
//! privilege and no host configuration.

/// The spelling both the profile format and the command line use for
/// [`Limit::UNLIMITED`].
const UNLIMITED_NAME: &str = "unlimited";

/// A resource limit value: a finite amount, or no limit at all.
///
/// Constructed from a `u64` — `.rlimit(Resource::Processes, 64, 64)` — or as
/// [`UNLIMITED`](Self::UNLIMITED) for the kernel's `RLIM_INFINITY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limit(Option<u64>);

/// Orders limits by how much they permit, so `UNLIMITED` is the maximum.
///
/// Not derived: the inner `Option` orders `None` *below* every `Some`, which
/// would make `Limit::UNLIMITED < Limit::of(0)` — the inverse of what a limit
/// means and of what this type documents.
impl Ord for Limit {
    fn cmp(&self, other: &Limit) -> std::cmp::Ordering {
        match (self.0, other.0) {
            (Some(left), Some(right)) => left.cmp(&right),
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
        }
    }
}

impl PartialOrd for Limit {
    fn partial_cmp(&self, other: &Limit) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Limit {
    /// No limit: the kernel's `RLIM_INFINITY`.
    ///
    /// Ordered above every finite limit, so a finite soft limit under an
    /// unlimited hard limit is valid.
    pub const UNLIMITED: Limit = Limit(None);

    /// A finite limit, in the resource's own unit.
    ///
    /// `u64::MAX` is the kernel's `RLIM_INFINITY` rather than an amount, so it
    /// yields [`UNLIMITED`](Self::UNLIMITED): there is no finite limit the
    /// kernel would distinguish from no limit at all.
    pub const fn of(amount: u64) -> Limit {
        if amount == u64::MAX {
            Limit::UNLIMITED
        } else {
            Limit(Some(amount))
        }
    }

    /// The finite amount, or `None` when the limit is
    /// [`UNLIMITED`](Self::UNLIMITED).
    pub const fn amount(self) -> Option<u64> {
        self.0
    }

    /// Whether this limit is at most `other`, with unlimited as the maximum.
    pub(crate) fn fits_within(self, other: Limit) -> bool {
        match (self.0, other.0) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(soft), Some(hard)) => soft <= hard,
        }
    }
}

impl From<u64> for Limit {
    fn from(amount: u64) -> Limit {
        Limit::of(amount)
    }
}

impl std::fmt::Display for Limit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(amount) => write!(f, "{amount}"),
            None => f.write_str(UNLIMITED_NAME),
        }
    }
}

/// A limit renders as its bare amount, or as the string `"unlimited"`.
#[cfg(feature = "serde")]
impl serde::Serialize for Limit {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Some(amount) => serializer.serialize_u64(amount),
            None => serializer.serialize_str(UNLIMITED_NAME),
        }
    }
}

/// Accepts either form a limit renders as, in a self-describing format.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Limit {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(LimitVisitor)
    }
}

#[cfg(feature = "serde")]
struct LimitVisitor;

#[cfg(feature = "serde")]
impl serde::de::Visitor<'_> for LimitVisitor {
    type Value = Limit;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a non-negative amount or {UNLIMITED_NAME:?}")
    }

    fn visit_u64<E: serde::de::Error>(self, amount: u64) -> Result<Limit, E> {
        Ok(Limit::of(amount))
    }

    // TOML integers are signed, so a profile's amounts arrive here.
    fn visit_i64<E: serde::de::Error>(self, amount: i64) -> Result<Limit, E> {
        u64::try_from(amount)
            .map(Limit::of)
            .map_err(|_| E::custom(format!("a resource limit cannot be negative: {amount}")))
    }

    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Limit, E> {
        if text == UNLIMITED_NAME {
            Ok(Limit::UNLIMITED)
        } else {
            Err(E::custom(format!(
                "expected an amount or {UNLIMITED_NAME:?}, not {text:?}"
            )))
        }
    }
}

/// A per-process resource whose limit the launch sets on the command.
///
/// Each variant names the kernel's `RLIMIT_*` resource it sets and the unit
/// its values are counted in. Two carry sandbox-specific caveats:
///
/// - [`Processes`](Self::Processes) is the kernel's `RLIMIT_NPROC`, which
///   counts processes per *real user id* across the whole system, not per
///   namespace or per sandbox. Under the single-identity map the command's
///   real uid outside the sandbox is the calling user's, so the limit counts
///   the caller's other processes too, and the cap is a ceiling on the pair
///   rather than on the sandbox alone. A range identity map gives the sandbox
///   distinct host ids, so the count is the sandbox's own.
/// - [`AddressSpace`](Self::AddressSpace) counts mapped address space, not
///   resident memory, so a command that maps far more than it touches — many
///   runtimes and allocators do — hits it long before its real memory use
///   approaches the value.
///
/// The kebab-case spelling of each variant is the name a profile's `[rlimit]`
/// table and the command line's `--rlimit` flag both use: `address-space`,
/// `cpu-time`, `open-files`, and so on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
#[non_exhaustive]
pub enum Resource {
    /// `RLIMIT_AS`: the total mapped address space, in bytes.
    AddressSpace,
    /// `RLIMIT_CORE`: the size of a core dump, in bytes.
    CoreDump,
    /// `RLIMIT_CPU`: CPU time consumed, in seconds. Exceeding the soft limit
    /// raises `SIGXCPU`; exceeding the hard limit is fatal.
    CpuTime,
    /// `RLIMIT_DATA`: the data segment — the heap and anonymous mappings — in
    /// bytes.
    Data,
    /// `RLIMIT_FSIZE`: the largest file the command may create, in bytes. A
    /// write beyond it raises `SIGXFSZ`.
    FileSize,
    /// `RLIMIT_MEMLOCK`: memory that may be locked into RAM, in bytes.
    LockedMemory,
    /// `RLIMIT_NOFILE`: one greater than the highest file descriptor the
    /// command may open.
    OpenFiles,
    /// `RLIMIT_SIGPENDING`: signals that may be queued for the command's real
    /// user id.
    PendingSignals,
    /// `RLIMIT_NPROC`: processes and threads for the command's real user id.
    /// The fork-bomb ceiling; see the caveat above.
    Processes,
    /// `RLIMIT_STACK`: the main thread's stack, in bytes.
    Stack,
}

impl Resource {
    /// Every resource a limit can be set on, in the order they are documented.
    ///
    /// The roster grows as the kernel's does, so this is a slice rather than a
    /// fixed-length array: a consumer that presents the resources — a help
    /// text, a form, a completion script — picks up an addition without a
    /// change. Pair it with [`spelling`](Self::spelling) for the names a
    /// profile and the command line accept.
    pub const ALL: &'static [Resource] = &[
        Resource::AddressSpace,
        Resource::CoreDump,
        Resource::CpuTime,
        Resource::Data,
        Resource::FileSize,
        Resource::LockedMemory,
        Resource::OpenFiles,
        Resource::PendingSignals,
        Resource::Processes,
        Resource::Stack,
    ];

    /// The name a profile's `[rlimit]` table and the `--rlimit` flag spell this
    /// resource with: the kebab-case form of the variant.
    ///
    /// Distinct from [`Display`](std::fmt::Display), which renders the kernel's
    /// own `RLIMIT_*` name because that is what an error about the kernel's
    /// refusal should say.
    pub fn spelling(self) -> &'static str {
        match self {
            Resource::AddressSpace => "address-space",
            Resource::CoreDump => "core-dump",
            Resource::CpuTime => "cpu-time",
            Resource::Data => "data",
            Resource::FileSize => "file-size",
            Resource::LockedMemory => "locked-memory",
            Resource::OpenFiles => "open-files",
            Resource::PendingSignals => "pending-signals",
            Resource::Processes => "processes",
            Resource::Stack => "stack",
        }
    }

    /// The kernel resource this names.
    pub(crate) fn to_kernel(self) -> rustix::process::Resource {
        use rustix::process::Resource as Kernel;
        match self {
            Resource::AddressSpace => Kernel::As,
            Resource::CoreDump => Kernel::Core,
            Resource::CpuTime => Kernel::Cpu,
            Resource::Data => Kernel::Data,
            Resource::FileSize => Kernel::Fsize,
            Resource::LockedMemory => Kernel::Memlock,
            Resource::OpenFiles => Kernel::Nofile,
            Resource::PendingSignals => Kernel::Sigpending,
            Resource::Processes => Kernel::Nproc,
            Resource::Stack => Kernel::Stack,
        }
    }

    /// The kernel's own name for the resource, for error messages.
    pub(crate) fn kernel_name(self) -> &'static str {
        match self {
            Resource::AddressSpace => "RLIMIT_AS",
            Resource::CoreDump => "RLIMIT_CORE",
            Resource::CpuTime => "RLIMIT_CPU",
            Resource::Data => "RLIMIT_DATA",
            Resource::FileSize => "RLIMIT_FSIZE",
            Resource::LockedMemory => "RLIMIT_MEMLOCK",
            Resource::OpenFiles => "RLIMIT_NOFILE",
            Resource::PendingSignals => "RLIMIT_SIGPENDING",
            Resource::Processes => "RLIMIT_NPROC",
            Resource::Stack => "RLIMIT_STACK",
        }
    }
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kernel_name())
    }
}

/// Serde adapter for a builder's resource-limit map, as the profile's
/// `[rlimit]` table.
///
/// Each entry is keyed by the resource's kebab-case name. Its value is the
/// shorthand — a bare [`Limit`] standing for both the soft and the hard limit
/// — whenever the two agree, and the explicit `{ soft = …, hard = … }` table
/// when they differ. Both forms are accepted on the way in whether or not the
/// values agree, so a hand-written profile may always spell out the pair.
#[cfg(feature = "serde")]
pub(crate) mod serde_rlimits {
    use super::{Limit, Resource};
    use serde::Deserialize as _;
    use serde::de::{Error as _, MapAccess, Visitor};
    use serde::ser::SerializeMap;
    use std::collections::BTreeMap;

    /// The explicit form, for a resource whose soft and hard limits differ.
    #[derive(serde::Serialize)]
    struct Pair {
        soft: Limit,
        hard: Limit,
    }

    pub(crate) fn serialize<S: serde::Serializer>(
        rlimits: &BTreeMap<Resource, (Limit, Limit)>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(rlimits.len()))?;
        for (resource, &(soft, hard)) in rlimits {
            if soft == hard {
                map.serialize_entry(resource, &soft)?;
            } else {
                map.serialize_entry(resource, &Pair { soft, hard })?;
            }
        }
        map.end()
    }

    pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<Resource, (Limit, Limit)>, D::Error> {
        let settings = BTreeMap::<Resource, Setting>::deserialize(deserializer)?;
        Ok(settings
            .into_iter()
            .map(|(resource, Setting(soft, hard))| (resource, (soft, hard)))
            .collect())
    }

    /// One entry's value: a soft and a hard limit, however it was spelled.
    struct Setting(Limit, Limit);

    impl<'de> serde::Deserialize<'de> for Setting {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(SettingVisitor)
        }
    }

    struct SettingVisitor;

    impl<'de> Visitor<'de> for SettingVisitor {
        type Value = Setting;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(
                "a resource limit: one value for both the soft and the hard limit, \
                 or a table of `soft` and `hard`",
            )
        }

        // The shorthand: one value standing for both limits. Delegating to
        // `Limit` keeps the accepted spellings identical in both positions.
        fn visit_u64<E: serde::de::Error>(self, amount: u64) -> Result<Setting, E> {
            let limit = super::LimitVisitor.visit_u64(amount)?;
            Ok(Setting(limit, limit))
        }

        fn visit_i64<E: serde::de::Error>(self, amount: i64) -> Result<Setting, E> {
            let limit = super::LimitVisitor.visit_i64(amount)?;
            Ok(Setting(limit, limit))
        }

        fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Setting, E> {
            let limit = super::LimitVisitor.visit_str(text)?;
            Ok(Setting(limit, limit))
        }

        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Setting, M::Error> {
            let (mut soft, mut hard) = (None, None);
            while let Some(key) = map.next_key::<String>()? {
                let slot = match key.as_str() {
                    "soft" => &mut soft,
                    "hard" => &mut hard,
                    other => return Err(M::Error::unknown_field(other, &["soft", "hard"])),
                };
                if slot.is_some() {
                    return Err(M::Error::custom(format!("duplicate field `{key}`")));
                }
                *slot = Some(map.next_value::<Limit>()?);
            }
            Ok(Setting(
                soft.ok_or_else(|| M::Error::missing_field("soft"))?,
                hard.ok_or_else(|| M::Error::missing_field("hard"))?,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::*;

    #[test]
    fn the_comparison_operators_agree_with_fits_within() {
        // The derived ordering on the inner `Option` would put `UNLIMITED`
        // below every finite limit, so a consumer sorting or clamping limits
        // through the public operators would get the inverse of what a limit
        // means. The two answers must not disagree.
        assert!(Limit::UNLIMITED > Limit::of(0));
        assert!(Limit::UNLIMITED > Limit::of(u64::MAX - 1));
        assert!(Limit::of(1) < Limit::of(2));
        assert_eq!(Limit::UNLIMITED.cmp(&Limit::UNLIMITED), Ordering::Equal);
        for (soft, hard) in [
            (Limit::of(1), Limit::UNLIMITED),
            (Limit::UNLIMITED, Limit::UNLIMITED),
            (Limit::UNLIMITED, Limit::of(u64::MAX - 1)),
            (Limit::of(2), Limit::of(1)),
            (Limit::of(1), Limit::of(2)),
        ] {
            assert_eq!(
                soft.fits_within(hard),
                soft <= hard,
                "{soft} within {hard} disagrees with the ordering",
            );
        }
    }

    #[test]
    fn unlimited_is_the_ceiling_in_both_directions() {
        assert!(Limit::of(1).fits_within(Limit::UNLIMITED));
        assert!(Limit::UNLIMITED.fits_within(Limit::UNLIMITED));
        // `u64::MAX` is the kernel's infinity rather than an amount, so the
        // largest finite limit is one below it.
        assert!(!Limit::UNLIMITED.fits_within(Limit::of(u64::MAX - 1)));
    }

    #[test]
    fn a_finite_soft_limit_must_not_exceed_its_hard_limit() {
        assert!(Limit::of(4).fits_within(Limit::of(4)));
        assert!(Limit::of(4).fits_within(Limit::of(5)));
        assert!(!Limit::of(5).fits_within(Limit::of(4)));
    }

    #[test]
    fn a_limit_renders_its_amount_or_the_word() {
        assert_eq!(Limit::of(64).to_string(), "64");
        assert_eq!(Limit::UNLIMITED.to_string(), "unlimited");
    }

    /// Every resource's `spelling` is the name the configuration formats
    /// accept, which is serde's kebab-case rename of the variant. The two are
    /// written out separately, so this proves they agree — and, because it
    /// walks `ALL`, that a resource added to the enum is added to the roster.
    #[cfg(feature = "serde")]
    #[test]
    fn every_resources_spelling_is_the_name_a_profile_accepts() {
        use serde::Deserialize as _;
        for resource in Resource::ALL {
            let parsed = Resource::deserialize(serde::de::value::StrDeserializer::<
                serde::de::value::Error,
            >::new(resource.spelling()))
            .unwrap_or_else(|err| panic!("{:?} should parse: {err}", resource.spelling()));
            assert_eq!(parsed, *resource);
        }
    }

    #[test]
    fn the_kernels_infinity_is_no_limit_rather_than_an_amount() {
        // `RLIM_INFINITY` is `u64::MAX`, so the two are one value to the
        // kernel and the type must not offer a distinction it cannot keep.
        assert_eq!(Limit::of(u64::MAX), Limit::UNLIMITED);
        assert_eq!(Limit::of(u64::MAX).amount(), None);
        assert_eq!(Limit::of(u64::MAX - 1).amount(), Some(u64::MAX - 1));
    }
}
