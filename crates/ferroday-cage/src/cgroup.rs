//! A cgroup of the sandbox's own, beneath a directory the caller delegates.
//!
//! The library creates no hierarchy and needs no privilege. The caller hands it
//! a directory of a cgroup v2 hierarchy in which it may create cgroups: a
//! delegated subtree, such as systemd's `Delegate=yes` gives a service or a
//! scope. Each launch then creates a cgroup of its own beneath that directory,
//! enables the controllers its limits need, and writes the limits. Beneath it,
//! it creates one more cgroup, [`LEAF`], and opens the leaf's `cgroup.procs`.
//! The launch stage moves itself into the leaf through that descriptor before
//! it creates any namespace, so every process the sandbox runs is charged
//! there, and the cgroup namespace the sandbox creates is rooted at it.
//!
//! The limits sit one level above anything the sandbox can name. The kernel
//! creates a cgroup's files owned by the process that created it, the caller,
//! and a sandbox's processes run as the caller's own user on the host. Joined
//! to the cgroup that holds the limits, a command could write them, or move
//! itself out through the parent's `cgroup.procs`, wherever it can reach the
//! cgroup's files. In the leaf it can reach neither from its cgroup namespace:
//! the namespace's root is the leaf, which holds no limit and whose parent is
//! outside the namespace. A restriction shares the host's cgroup namespace,
//! where what keeps its command from the files is the confinement it runs
//! under; see
//! [`RestrictionBuilder::cgroup_parent`](crate::RestrictionBuilder::cgroup_parent).
//!
//! The leaf enables no controller for children of its own, so a process in it,
//! or in a cgroup the sandbox creates beneath it, is charged to the limits'
//! cgroup itself. Everything the crate reads or writes for the tree is there:
//! the usage files, `cgroup.events`, and `cgroup.kill`, each of which covers
//! the cgroup's descendants.
//!
//! The running handle reads what the whole tree used from the cgroup once the
//! command's outcome is known, and removes the leaf and the cgroup then if
//! nothing is left in them. A kill through the handle or one of its kill
//! handles ends the tree through `cgroup.kill`, where the kernel has one,
//! whether or not the outcome is known yet. The handles share the cgroup, and
//! the last of them to drop removes it, once a tree a kill ended has emptied.

use std::ffi::CString;
use std::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::error::Error;
use crate::mechanism::frame::retry_on_intr;

/// A limit a sandbox's cgroup holds its whole process tree to.
///
/// Each is written to the file of the cgroup's interface that its variant
/// names, in that file's own units, when the sandbox's cgroup is created. A
/// limit needs its controller, which the parent directory must offer; see
/// [`CageBuilder::cgroup_parent`](crate::CageBuilder::cgroup_parent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CgroupLimit {
    /// `memory.max`: the most memory the tree may use, in bytes. Past it the
    /// kernel reclaims, and where it cannot, its OOM killer ends a process of
    /// the tree.
    MemoryMax(u64),
    /// `memory.swap.max`: the most swap the tree may use, in bytes. `0` keeps
    /// the tree out of swap. The kernel offers it only where swap is accounted.
    MemorySwapMax(u64),
    /// `pids.max`: the most processes and threads the tree may hold at once. A
    /// `fork` past it fails with `EAGAIN`.
    PidsMax(u64),
    /// `cpu.max`: at most `quota_micros` of processor time in each period of
    /// `period_micros`, both in microseconds. A quota above the period spans
    /// more than one processor. The period runs from 1,000 to 1,000,000, and
    /// the quota is at least 1,000.
    #[non_exhaustive]
    CpuMax {
        /// The processor time the tree may use in each period.
        quota_micros: u64,
        /// The length of a period.
        period_micros: u64,
    },
    /// `cpu.weight`: the tree's share of processor time against its siblings
    /// when they contend, from 1 to 10,000, with 100 a sibling's default.
    CpuWeight(u16),
}

impl CgroupLimit {
    /// A [`CpuMax`](Self::CpuMax) limit of `quota_micros` in each period of
    /// `period_micros`.
    pub fn cpu_max(quota_micros: u64, period_micros: u64) -> CgroupLimit {
        CgroupLimit::CpuMax {
            quota_micros,
            period_micros,
        }
    }
}

impl std::str::FromStr for CgroupLimit {
    type Err = ParseCgroupLimitError;

    /// Parses `NAME=VALUE`, a limit named as a profile's `[cgroup]` table names
    /// it, in the units of the file it is written to.
    ///
    /// `memory-max`, `memory-swap-max`, and `pids-max` take a count, and
    /// `cpu-weight` a weight. `cpu-max` takes `QUOTA:PERIOD` in microseconds,
    /// or `QUOTA` alone, in each period of 100000, the kernel's own default.
    /// Whitespace around the name and the value is ignored. A value of the
    /// right form that the kernel would refuse parses, and is refused at build,
    /// as one a profile states is.
    fn from_str(s: &str) -> Result<CgroupLimit, ParseCgroupLimitError> {
        /// The period `cpu.max` holds where only a quota is written to it.
        const DEFAULT_PERIOD: &str = "100000";

        let error = |reason| ParseCgroupLimitError {
            text: s.to_string(),
            reason,
        };
        let (name, value) = s
            .split_once('=')
            .ok_or_else(|| error(CgroupLimitParse::Shape))?;
        let value = value.trim();
        let number = |text: &str| {
            text.trim()
                .parse::<u64>()
                .map_err(|_| error(CgroupLimitParse::Value))
        };
        Ok(match name.trim() {
            "memory-max" => CgroupLimit::MemoryMax(number(value)?),
            "memory-swap-max" => CgroupLimit::MemorySwapMax(number(value)?),
            "pids-max" => CgroupLimit::PidsMax(number(value)?),
            "cpu-max" => {
                let (quota, period) = value.split_once(':').unwrap_or((value, DEFAULT_PERIOD));
                CgroupLimit::cpu_max(number(quota)?, number(period)?)
            }
            "cpu-weight" => {
                CgroupLimit::CpuWeight(value.parse().map_err(|_| error(CgroupLimitParse::Value))?)
            }
            _ => return Err(error(CgroupLimitParse::Name)),
        })
    }
}

/// The error from parsing a [`CgroupLimit`] that is not `NAME=VALUE` with a
/// limit's name and a value of its form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCgroupLimitError {
    text: String,
    reason: CgroupLimitParse,
}

/// What made a limit's text unparsable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CgroupLimitParse {
    /// No `=` between a name and a value.
    Shape,
    /// A name no limit has.
    Name,
    /// A value not of the limit's form.
    Value,
}

impl ParseCgroupLimitError {
    /// The unparsed text, as it was given.
    ///
    /// Named `text` on every parse error in this crate, so a caller moving
    /// between them does not have to check.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ParseCgroupLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = &self.text;
        match self.reason {
            CgroupLimitParse::Shape => {
                write!(f, "expected NAME=VALUE for a cgroup limit, not {text:?}")
            }
            CgroupLimitParse::Name => write!(
                f,
                "{text:?} names no cgroup limit; expected memory-max, memory-swap-max, \
                 pids-max, cpu-max, or cpu-weight"
            ),
            CgroupLimitParse::Value => write!(
                f,
                "{text:?} is not a value of its cgroup limit's form: a count, QUOTA[:PERIOD] \
                 for cpu-max, or a weight for cpu-weight"
            ),
        }
    }
}

impl std::error::Error for ParseCgroupLimitError {}

/// Why a sandbox could not be given a cgroup of its own beneath the parent the
/// caller named.
///
/// A launch reports it as [`Error::CgroupRefused`], and
/// [`host::cgroup_blocker`](crate::host::cgroup_blocker) answers it before a
/// launch, by the launch's own steps.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CgroupRefusal {
    /// Nothing is at the parent's path, or a component of it is not a
    /// directory.
    Missing,
    /// The parent is not a directory of a cgroup v2 hierarchy. A host that
    /// mounts only the v1 hierarchies offers none.
    NotCgroup2,
    /// The cgroup filesystem the parent is on is mounted read-only, as a
    /// container runtime mounts a container's by default.
    ReadOnly,
    /// This process may not create a cgroup beneath the parent, or enable a
    /// controller in it: the parent is not delegated to this process.
    NotDelegated,
    /// A limit needs a controller the parent does not offer: its
    /// `cgroup.controllers` lists only what its own parent enabled for it.
    #[non_exhaustive]
    ControllerUnavailable {
        /// The controller, such as `memory`.
        controller: &'static str,
    },
    /// The parent holds processes of its own, so it cannot enable a controller
    /// for its children: a cgroup v2 rule. The caller moves its own processes
    /// into a leaf cgroup beside the sandbox's first.
    ParentHoldsProcesses,
    /// A limit's file is not one the kernel offers, as `memory.swap.max` is
    /// absent where swap is not accounted.
    #[non_exhaustive]
    LimitUnsupported {
        /// The file the limit is written to.
        file: &'static str,
    },
    /// The launch cannot move into a cgroup beneath the parent from the cgroup
    /// this process runs in. The kernel lets a process move another, itself
    /// included, only where it may write the `cgroup.procs` of the nearest
    /// cgroup the two share, and only within its cgroup namespace, so a caller
    /// outside the delegated subtree cannot move a launch into it.
    CallerOutside,
}

impl fmt::Display for CgroupRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CgroupRefusal::Missing => f.write_str("it does not exist"),
            CgroupRefusal::NotCgroup2 => f.write_str(
                "it is not a directory of a cgroup v2 hierarchy, which a host that mounts only \
                 the v1 hierarchies has none of",
            ),
            CgroupRefusal::ReadOnly => f.write_str(
                "the cgroup filesystem it is on is mounted read-only, as a container runtime \
                 mounts a container's by default",
            ),
            CgroupRefusal::NotDelegated => f.write_str(
                "this process may not create a cgroup in it or enable its controllers; it is \
                 not delegated to this process, as systemd's Delegate=yes delegates a scope or \
                 a service",
            ),
            CgroupRefusal::ControllerUnavailable { controller } => write!(
                f,
                "it does not offer the {controller} controller a limit needs; its \
                 cgroup.controllers lists what its own parent enabled for it",
            ),
            CgroupRefusal::ParentHoldsProcesses => f.write_str(
                "it holds processes of its own, so it cannot enable a controller for its \
                 children; move them into a leaf cgroup beside the sandbox's first",
            ),
            CgroupRefusal::LimitUnsupported { file } => {
                write!(
                    f,
                    "the kernel offers no {file}, which a limit is written to"
                )
            }
            CgroupRefusal::CallerOutside => f.write_str(
                "a launch cannot move from the cgroup this process runs in to one beneath it, \
                 since the nearest cgroup the two share is not this process's to write; run \
                 the caller in a leaf cgroup beside the sandbox's",
            ),
        }
    }
}

/// A step of giving a launch its cgroup whose failure can be a refusal: what
/// [`refusal`] reads an errno against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Opening the parent directory.
    OpenParent,
    /// Enabling a controller in the parent's `cgroup.subtree_control`.
    Enable,
    /// Creating the sandbox's cgroup beneath the parent, or its leaf.
    Create,
    /// Opening a file of the sandbox's cgroup to write: a limit, its
    /// `cgroup.kill`, or the leaf's `cgroup.procs`.
    OpenFile,
    /// Moving the launch stage into the sandbox's leaf.
    Join,
}

/// The refusal an errno from `step` stands for, where it stands for one; an
/// errno it does not name is a failure of the host's.
///
/// The one reading of what the kernel answered, whether the launch's own
/// steps met it or [`probe`] did on their behalf.
fn refusal(step: Step, errno: Errno) -> Option<CgroupRefusal> {
    Some(match (step, errno) {
        (Step::OpenParent, Errno::NOENT | Errno::NOTDIR) => CgroupRefusal::Missing,
        (Step::Enable | Step::Create | Step::OpenFile, Errno::ROFS) => CgroupRefusal::ReadOnly,
        (Step::OpenParent | Step::Enable | Step::Create, Errno::ACCESS | Errno::PERM) => {
            CgroupRefusal::NotDelegated
        }
        // A domain controller cannot be enabled where the parent holds
        // processes, and with only a threaded controller enabled the parent
        // accepts the child and its limits and then refuses the move.
        (Step::Enable, Errno::BUSY) | (Step::Join, Errno::OPNOTSUPP) => {
            CgroupRefusal::ParentHoldsProcesses
        }
        // The nearest cgroup the writer and the destination share is not the
        // writer's to write, or the destination lies outside its cgroup
        // namespace.
        (Step::Join, Errno::ACCESS | Errno::PERM | Errno::NOENT) => CgroupRefusal::CallerOutside,
        _ => return None,
    })
}

/// The refusal the launch stage's move into the sandbox's leaf failed with,
/// where its errno stands for one.
pub(crate) fn join_refusal(errno: Errno) -> Option<CgroupRefusal> {
    refusal(Step::Join, errno)
}

/// Whether a launch beneath `parent` holding the tree to `limits` would be
/// refused its cgroup, and why: [`host::cgroup_blocker`]'s answer.
///
/// The launch's own steps, carried out: [`Cgroup::create`], then a child of
/// this process moving itself into the leaf as the launch stage does, and
/// last the removal of the leaf and the cgroup. `None` where every step succeeded, and where one
/// failed for a reason of the host's rather than a refusal, or a value the
/// build refuses stopped the probe before it began.
///
/// [`host::cgroup_blocker`]: crate::host::cgroup_blocker
pub(crate) fn probe(parent: &Path, limits: &[CgroupLimit]) -> Option<CgroupRefusal> {
    let mut settings = CgroupSettings {
        parent: Some(parent.to_path_buf()),
        ..CgroupSettings::default()
    };
    for limit in limits {
        settings.set(*limit);
    }
    let plan = settings.plan().ok()??;
    let cgroup = match Cgroup::create(&plan) {
        Ok(cgroup) => cgroup,
        Err(Error::CgroupRefused { reason, .. }) => return Some(reason),
        Err(_) => return None,
    };
    match crate::mechanism::probe_cgroup_join(cgroup.procs()) {
        crate::mechanism::JoinProbe::Refused(errno) => join_refusal(errno),
        crate::mechanism::JoinProbe::Joined | crate::mechanism::JoinProbe::Inconclusive => None,
    }
}

/// The cgroup settings a builder holds, as the profile format's `[cgroup]`
/// table spells them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub(crate) struct CgroupSettings {
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub(crate) parent: Option<PathBuf>,
    /// Whether a launch without a parent is refused (the default) or runs
    /// without the limits. `None` is the default.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub(crate) required: Option<bool>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub(crate) memory_max: Option<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub(crate) memory_swap_max: Option<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub(crate) pids_max: Option<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub(crate) cpu_max: Option<CpuMax>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub(crate) cpu_weight: Option<u16>,
}

/// `cpu.max`'s two values, in microseconds, as the `[cgroup]` table's
/// `cpu-max = { quota = …, period = … }` spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub(crate) struct CpuMax {
    pub(crate) quota: u64,
    pub(crate) period: u64,
}

impl CgroupSettings {
    /// Whether nothing is set, which serializes as no table at all.
    #[cfg(feature = "serde")]
    pub(crate) fn is_unset(&self) -> bool {
        *self == CgroupSettings::default()
    }

    /// Records `limit`, replacing any earlier limit of its kind.
    pub(crate) fn set(&mut self, limit: CgroupLimit) {
        match limit {
            CgroupLimit::MemoryMax(bytes) => self.memory_max = Some(bytes),
            CgroupLimit::MemorySwapMax(bytes) => self.memory_swap_max = Some(bytes),
            CgroupLimit::PidsMax(count) => self.pids_max = Some(count),
            CgroupLimit::CpuMax {
                quota_micros,
                period_micros,
            } => {
                self.cpu_max = Some(CpuMax {
                    quota: quota_micros,
                    period: period_micros,
                });
            }
            CgroupLimit::CpuWeight(weight) => self.cpu_weight = Some(weight),
        }
    }

    /// The limits set, in a fixed order.
    pub(crate) fn limits(&self) -> Vec<CgroupLimit> {
        let mut limits = Vec::new();
        limits.extend(self.memory_max.map(CgroupLimit::MemoryMax));
        limits.extend(self.memory_swap_max.map(CgroupLimit::MemorySwapMax));
        limits.extend(self.pids_max.map(CgroupLimit::PidsMax));
        limits.extend(
            self.cpu_max
                .map(|cpu| CgroupLimit::cpu_max(cpu.quota, cpu.period)),
        );
        limits.extend(self.cpu_weight.map(CgroupLimit::CpuWeight));
        limits
    }

    /// Whether a launch without a parent is refused rather than run without
    /// the limits.
    pub(crate) fn required(&self) -> bool {
        self.required.unwrap_or(true)
    }

    /// The limits a launch leaves unapplied: every limit set, where no parent
    /// is named and the limits are not required.
    pub(crate) fn unapplied(&self) -> Vec<CgroupLimit> {
        match self.parent.is_none() && !self.required() {
            true => self.limits(),
            false => Vec::new(),
        }
    }

    /// The plan a launch carries out, or the reason the settings are not one.
    ///
    /// `None` where no parent is named, which is no cgroup at all. A limit
    /// without a parent is refused, since it would hold nothing, unless the
    /// limits are not [required](Self::required): the launch then runs
    /// without them, and [`unapplied`](Self::unapplied) names them.
    pub(crate) fn plan(&self) -> Result<Option<CgroupPlan>, crate::ConfigError> {
        let limits = self.limits();
        let Some(parent) = &self.parent else {
            return match limits.is_empty() || !self.required() {
                true => Ok(None),
                false => Err(crate::ConfigError::CgroupLimitInvalid {
                    reason: "a cgroup limit needs a cgroup parent to create the sandbox's cgroup \
                             beneath, unless the limits are not required"
                        .to_string(),
                }),
            };
        };
        if !parent.is_absolute() {
            return Err(crate::ConfigError::CgroupLimitInvalid {
                reason: format!(
                    "the cgroup parent {} is not an absolute path",
                    parent.display()
                ),
            });
        }
        let mut writes = Vec::new();
        for limit in &limits {
            writes.push(LimitWrite::of(*limit)?);
        }
        Ok(Some(CgroupPlan {
            parent: parent.clone(),
            limits,
            writes,
        }))
    }
}

/// What a launch does to give the sandbox a cgroup: where, and what it writes.
#[derive(Debug, Clone)]
pub(crate) struct CgroupPlan {
    /// The delegated directory the sandbox's cgroup is created beneath.
    pub(crate) parent: PathBuf,
    /// The limits, in [`CgroupSettings::limits`]' order.
    pub(crate) limits: Vec<CgroupLimit>,
    /// The limits, as the files and values they are written as.
    writes: Vec<LimitWrite>,
}

/// Writes `limits` as the profile format's `[cgroup]` table spells them, for
/// the record [`ResolvedCgroup`](crate::ResolvedCgroup) serializes to.
#[cfg(feature = "serde")]
pub(crate) fn serialize_limits<S: serde::Serializer>(
    limits: &[CgroupLimit],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut table = CgroupSettings::default();
    for limit in limits {
        table.set(*limit);
    }
    serde::Serialize::serialize(&table, serializer)
}

/// One limit, as the write that sets it.
#[derive(Debug, Clone)]
struct LimitWrite {
    /// The controller the file belongs to.
    controller: &'static str,
    /// The file of the cgroup's interface.
    file: &'static str,
    /// What is written to it.
    value: String,
}

impl LimitWrite {
    /// The write that sets `limit`, or why its value is not one the kernel
    /// takes.
    fn of(limit: CgroupLimit) -> Result<LimitWrite, crate::ConfigError> {
        let invalid = |reason: String| crate::ConfigError::CgroupLimitInvalid { reason };
        Ok(match limit {
            CgroupLimit::MemoryMax(bytes) => LimitWrite {
                controller: "memory",
                file: "memory.max",
                value: bytes.to_string(),
            },
            CgroupLimit::MemorySwapMax(bytes) => LimitWrite {
                controller: "memory",
                file: "memory.swap.max",
                value: bytes.to_string(),
            },
            CgroupLimit::PidsMax(count) => LimitWrite {
                controller: "pids",
                file: "pids.max",
                value: count.to_string(),
            },
            CgroupLimit::CpuMax {
                quota_micros,
                period_micros,
            } => {
                if !(1_000..=1_000_000).contains(&period_micros) {
                    return Err(invalid(format!(
                        "the cpu-max period of {period_micros} microseconds is outside the \
                         1000 to 1000000 the kernel takes"
                    )));
                }
                if quota_micros < 1_000 {
                    return Err(invalid(format!(
                        "the cpu-max quota of {quota_micros} microseconds is below the 1000 the \
                         kernel takes"
                    )));
                }
                LimitWrite {
                    controller: "cpu",
                    file: "cpu.max",
                    value: format!("{quota_micros} {period_micros}"),
                }
            }
            CgroupLimit::CpuWeight(weight) => {
                if !(1..=10_000).contains(&weight) {
                    return Err(invalid(format!(
                        "the cpu-weight {weight} is outside the 1 to 10000 the kernel takes"
                    )));
                }
                LimitWrite {
                    controller: "cpu",
                    file: "cpu.weight",
                    value: weight.to_string(),
                }
            }
        })
    }
}

/// The filesystem magic of a cgroup v2 hierarchy, which `statfs` reports.
const CGROUP2_SUPER_MAGIC: rustix::fs::FsWord = 0x6367_7270;

/// The controllers whose accounting a sandbox's cgroup reports where the parent
/// offers them, whether or not a limit needs them.
const ACCOUNTED: [&str; 2] = ["memory", "pids"];

/// The name of the cgroup beneath a sandbox's own that the launch stage joins:
/// `<parent>/fcage-<unique>/sandbox`.
///
/// The limits are written to `fcage-<unique>`, and every process of the
/// sandbox runs in the leaf or beneath it, where neither the limits nor the
/// parent's `cgroup.procs` lie within the sandbox's cgroup namespace; see the
/// module documentation.
const LEAF: &str = "sandbox";

/// How long the drop of a cgroup whose tree a kill ended waits for the tree to
/// empty before it removes the cgroup.
///
/// A killed process leaves the cgroup as its exit completes: within a
/// millisecond for most, and within a fraction of a second for one releasing
/// gigabytes of memory. One in an uninterruptible sleep, on an unresponsive
/// filesystem, leaves only once that sleep ends, and past the bound its cgroup
/// stays beneath the parent rather than hold the drop.
const EMPTYING_BOUND: Duration = Duration::from_secs(5);

/// The sandbox's cgroup and its [`LEAF`], from their creation before the
/// launch until their removal.
///
/// The running handle and each of its kill handles share it. The handle reads
/// what the tree used once the outcome is known, and removes the cgroup then
/// through [`remove_if_empty`](Self::remove_if_empty). A process the sandbox
/// left behind keeps it occupied past that, and the drop of the last owner
/// removes it instead: after a [`kill`](Self::kill), once the tree has emptied,
/// waiting up to [`EMPTYING_BOUND`] for it, and without one only if the tree
/// has emptied by itself. A cgroup still holding a process stays beneath the
/// parent.
///
/// Its descriptors are the launch's, and are kept off the standard streams'
/// numbers as every descriptor of the launch's is; see
/// [`mechanism::above_stdio`](crate::mechanism::above_stdio). The launch stage
/// inherits them at the fork.
pub(crate) struct Cgroup {
    /// The parent directory, which the cgroup is removed from.
    parent: OwnedFd,
    /// The parent as the caller named it, for errors.
    parent_path: PathBuf,
    /// The cgroup's name beneath the parent.
    name: CString,
    /// The cgroup's own directory, which holds the limits and the leaf.
    dir: OwnedFd,
    /// The leaf's `cgroup.procs`, which the launch stage writes itself into.
    procs: OwnedFd,
    /// Its `cgroup.kill`, where the kernel has one (Linux 5.14).
    kill: Option<OwnedFd>,
    /// Whether [`kill`](Self::kill) has ended the tree, so that the drop waits
    /// for it to empty.
    killed: AtomicBool,
    /// Whether [`remove_if_empty`](Self::remove_if_empty) has removed the
    /// cgroup, so that the drop has nothing to do.
    removed: AtomicBool,
}

impl Cgroup {
    /// Creates the sandbox's cgroup beneath the plan's parent, enables the
    /// controllers its limits need, writes the limits, and creates the
    /// [`LEAF`] beneath it that the launch stage joins.
    ///
    /// # Errors
    ///
    /// [`Error::CgroupRefused`] where the parent cannot hold such a cgroup, and
    /// [`Error::Cgroup`] where a step fails for a reason of the host's that no
    /// [`CgroupRefusal`] names.
    pub(crate) fn create(plan: &CgroupPlan) -> Result<Cgroup, Error> {
        // An errno a step met: the refusal it stands for, or else the host's
        // failure, named by what the step was doing.
        let failed = |step: Step, op: &'static str, path: &Path| {
            let path = path.to_path_buf();
            move |errno: Errno| match refusal(step, errno) {
                Some(reason) => Error::CgroupRefused {
                    parent: plan.parent.clone(),
                    reason,
                },
                None => Error::Cgroup {
                    op,
                    path,
                    source: errno.into(),
                },
            }
        };
        let io_error = |op: &'static str, path: &Path| {
            let path = path.to_path_buf();
            move |errno: Errno| Error::Cgroup {
                op,
                path,
                source: errno.into(),
            }
        };
        let refused = |reason: CgroupRefusal| Error::CgroupRefused {
            parent: plan.parent.clone(),
            reason,
        };
        // Each descriptor the cgroup keeps, off the standard streams' numbers.
        let kept = |mut fd: OwnedFd| crate::mechanism::above_stdio(&mut fd).map(|()| fd);
        let parent = rustix::fs::open(
            &plan.parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .and_then(kept)
        .map_err(failed(
            Step::OpenParent,
            "opening the cgroup parent",
            &plan.parent,
        ))?;
        let magic = rustix::fs::fstatfs(&parent)
            .map_err(io_error(
                "reading the cgroup parent's filesystem",
                &plan.parent,
            ))?
            .f_type;
        if magic != CGROUP2_SUPER_MAGIC {
            return Err(refused(CgroupRefusal::NotCgroup2));
        }

        let offered = read_words(&parent, "cgroup.controllers").map_err(io_error(
            "reading the parent's cgroup.controllers",
            &plan.parent,
        ))?;
        let mut needed: Vec<&'static str> = Vec::new();
        for write in &plan.writes {
            if !offered.iter().any(|offer| offer == write.controller) {
                return Err(refused(CgroupRefusal::ControllerUnavailable {
                    controller: write.controller,
                }));
            }
            if !needed.contains(&write.controller) {
                needed.push(write.controller);
            }
        }
        let enabled = read_words(&parent, "cgroup.subtree_control").map_err(io_error(
            "reading the parent's cgroup.subtree_control",
            &plan.parent,
        ))?;
        // A parent with processes of its own cannot hand a controller to a
        // child: the kernel refuses enabling a domain controller there, and
        // refuses moving a process into a child once any controller is
        // enabled. Asked before anything is created, so the refusal names the
        // cause rather than the join it would otherwise surface at.
        let holds_processes = !read_text(&parent, "cgroup.procs")
            .map_err(io_error("reading the parent's cgroup.procs", &plan.parent))?
            .trim()
            .is_empty();
        if holds_processes && !(needed.is_empty() && enabled.is_empty()) {
            return Err(refused(CgroupRefusal::ParentHoldsProcesses));
        }
        for controller in needed.iter().copied() {
            if enabled.iter().any(|on| on == controller) {
                continue;
            }
            enable(&parent, controller).map_err(failed(
                Step::Enable,
                "enabling a controller in the parent's cgroup.subtree_control",
                &plan.parent,
            ))?;
        }
        // Accounting a limit does not need is enabled where it can be and left
        // out where it cannot: what is not enabled is reported as unknown.
        for controller in ACCOUNTED {
            if !holds_processes
                && !needed.contains(&controller)
                && offered.iter().any(|offer| offer == controller)
                && !enabled.iter().any(|on| on == controller)
            {
                let _ = enable(&parent, controller);
            }
        }

        let name = CString::new(format!("fcage-{}", crate::host::unique_hex()))
            .expect("a hex name holds no NUL");
        rustix::fs::mkdirat(&parent, name.as_c_str(), Mode::from_raw_mode(0o755)).map_err(
            failed(
                Step::Create,
                "creating the sandbox's cgroup beneath",
                &plan.parent,
            ),
        )?;
        let path = plan
            .parent
            .join(std::ffi::OsStr::from_bytes(name.as_bytes()));
        // From here on a failure removes what was created.
        let created = (|| {
            let dir = rustix::fs::openat(
                &parent,
                name.as_c_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .and_then(kept)
            .map_err(io_error("opening the sandbox's cgroup", &path))?;
            for write in &plan.writes {
                let file = open_write(&dir, write.file).map_err(|errno| match errno {
                    Errno::NOENT => refused(CgroupRefusal::LimitUnsupported { file: write.file }),
                    errno => failed(
                        Step::OpenFile,
                        "opening a limit of the sandbox's cgroup",
                        &path,
                    )(errno),
                })?;
                rustix::io::write(&file, write.value.as_bytes())
                    .map(drop)
                    .map_err(io_error("writing a limit to the sandbox's cgroup", &path))?;
            }
            // The leaf enables no controller for children of its own, so what
            // runs in it, or beneath it, is charged to this cgroup and held to
            // its limits.
            let leaf_path = path.join(LEAF);
            rustix::fs::mkdirat(&dir, LEAF, Mode::from_raw_mode(0o755)).map_err(failed(
                Step::Create,
                "creating the sandbox's leaf cgroup",
                &leaf_path,
            ))?;
            let leaf = rustix::fs::openat(
                &dir,
                LEAF,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io_error("opening the sandbox's leaf cgroup", &leaf_path))?;
            let procs = open_write(&leaf, "cgroup.procs")
                .and_then(kept)
                .map_err(failed(
                    Step::OpenFile,
                    "opening the leaf cgroup's cgroup.procs",
                    &leaf_path,
                ))?;
            // A kernel before Linux 5.14 has no `cgroup.kill`, and the tree is
            // then ended only as far as the supervisor's death reaches. Any
            // other failure to open it is one of the host's, reported rather
            // than read as that kernel.
            let kill = match open_write(&dir, "cgroup.kill").and_then(kept) {
                Ok(kill) => Some(kill),
                Err(Errno::NOENT) => None,
                Err(errno) => {
                    return Err(failed(
                        Step::OpenFile,
                        "opening the sandbox's cgroup.kill",
                        &path,
                    )(errno));
                }
            };
            Ok((dir, procs, kill))
        })();
        match created {
            Ok((dir, procs, kill)) => Ok(Cgroup {
                parent,
                parent_path: plan.parent.clone(),
                name,
                dir,
                procs,
                kill,
                killed: AtomicBool::new(false),
                removed: AtomicBool::new(false),
            }),
            Err(err) => {
                let leaf = Path::new(std::ffi::OsStr::from_bytes(name.as_bytes())).join(LEAF);
                let _ = rustix::fs::unlinkat(&parent, &leaf, AtFlags::REMOVEDIR);
                let _ = rustix::fs::unlinkat(&parent, name.as_c_str(), AtFlags::REMOVEDIR);
                Err(err)
            }
        }
    }

    /// The leaf's `cgroup.procs`, which the launch stage writes `0` to, moving
    /// itself in.
    pub(crate) fn procs(&self) -> BorrowedFd<'_> {
        self.procs.as_fd()
    }

    /// Ends every process of the tree through `cgroup.kill`, where the kernel
    /// has one, and nothing without it.
    ///
    /// A cgroup already removed has nothing left in it to end. The kernel
    /// answers a write to its `cgroup.kill` with `ENODEV`, or with `ENOENT`
    /// while the removal is under way, and neither is a failure here.
    pub(crate) fn kill(&self) -> Result<(), Errno> {
        let Some(kill) = &self.kill else {
            return Ok(());
        };
        match rustix::io::write(kill, b"1") {
            Ok(_) => {
                self.killed.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(Errno::NODEV | Errno::NOENT) => Ok(()),
            Err(errno) => Err(errno),
        }
    }

    /// Removes the cgroup if nothing is left in it. One that still holds a
    /// process stays, for the drop to remove.
    pub(crate) fn remove_if_empty(&self) {
        if self.remove() {
            self.removed.store(true, Ordering::SeqCst);
        }
    }

    /// Removes the leaf and then the cgroup, and says whether the cgroup went.
    ///
    /// The kernel removes neither while it holds a process, nor the cgroup
    /// while the leaf is still there. A cgroup the sandbox created beneath the
    /// leaf keeps both.
    fn remove(&self) -> bool {
        let _ = rustix::fs::unlinkat(&self.dir, LEAF, AtFlags::REMOVEDIR);
        rustix::fs::unlinkat(&self.parent, self.name.as_c_str(), AtFlags::REMOVEDIR).is_ok()
    }

    /// Waits until no process is left in the tree, or `deadline` passes;
    /// `None` is no deadline.
    ///
    /// `cgroup.events` reports the tree's state on its `populated` line, and
    /// a change to the file raises `POLLPRI` and `POLLERR` on a descriptor of
    /// it until the descriptor reads the file again. `POLLIN` it raises
    /// whatever the state, so only `POLLPRI` is asked for, and each read comes
    /// before the poll it rearms. A cgroup removed meanwhile raises both at
    /// once and refuses the read, which ends the wait.
    fn await_empty(&self, deadline: Option<Instant>) {
        let Ok(events) = rustix::fs::openat(
            &self.dir,
            "cgroup.events",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) else {
            return;
        };
        // `populated 0` and `frozen 0`, one line each.
        let mut text = [0; 64];
        loop {
            let Ok(len) = retry_on_intr!(rustix::io::pread(&events, &mut text, 0)) else {
                return;
            };
            let populated = std::str::from_utf8(&text[..len])
                .ok()
                .and_then(|text| keyed(text, "populated"));
            if populated == Some(0) {
                return;
            }
            let timeout = match deadline {
                None => None,
                Some(deadline) => match deadline.checked_duration_since(Instant::now()) {
                    Some(remaining) => Some(crate::poll::timeout(remaining)),
                    None => return,
                },
            };
            let mut ready = [PollFd::new(&events, PollFlags::PRI)];
            match rustix::event::poll(&mut ready, timeout.as_ref()) {
                Ok(_) | Err(Errno::INTR) => {}
                Err(_) => return,
            }
        }
    }

    /// What the tree used, as far as the cgroup's files report it.
    pub(crate) fn usage(&self) -> CgroupUsage {
        let cpu = read_text(&self.dir, "cpu.stat").unwrap_or_default();
        let micros = |key: &str| keyed(&cpu, key).map(Duration::from_micros);
        let events = read_text(&self.dir, "memory.events").unwrap_or_default();
        CgroupUsage {
            user_time: micros("user_usec"),
            system_time: micros("system_usec"),
            peak_memory_bytes: read_number(&self.dir, "memory.peak"),
            peak_processes: read_number(&self.dir, "pids.peak"),
            oom_kills: keyed(&events, "oom_kill"),
        }
    }
}

impl fmt::Debug for Cgroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cgroup")
            .field("parent", &self.parent_path)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Drop for Cgroup {
    /// Removes the leaf and the cgroup, which the kernel allows once no process
    /// is left in them, waiting up to [`EMPTYING_BOUND`] for a tree a kill
    /// ended to empty. One that still holds processes, as a sandbox without a
    /// PID namespace can leave behind, stays beneath the parent.
    fn drop(&mut self) {
        if *self.removed.get_mut() {
            return;
        }
        if *self.killed.get_mut() {
            self.await_empty(Instant::now().checked_add(EMPTYING_BOUND));
        }
        self.remove();
    }
}

/// What a sandbox's whole process tree used, read from its cgroup.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CgroupUsage {
    pub(crate) user_time: Option<Duration>,
    pub(crate) system_time: Option<Duration>,
    pub(crate) peak_memory_bytes: Option<u64>,
    pub(crate) peak_processes: Option<u64>,
    pub(crate) oom_kills: Option<u64>,
}

/// Writes `+controller` to `parent`'s `cgroup.subtree_control`.
fn enable(parent: &OwnedFd, controller: &str) -> Result<(), Errno> {
    let file = open_write(parent, "cgroup.subtree_control")?;
    rustix::io::write(&file, format!("+{controller}").as_bytes()).map(drop)
}

/// Opens a file of a cgroup's interface for writing.
fn open_write(dir: &OwnedFd, file: &str) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(
        dir,
        file,
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
}

/// The most a file of a cgroup's interface is read to: `cpu.stat` and
/// `memory.events` are a few hundred bytes.
const MAX_INTERFACE_FILE: u64 = 64 << 10;

/// Reads a file of a cgroup's interface whole.
fn read_text(dir: &OwnedFd, file: &str) -> Result<String, Errno> {
    use std::io::Read;

    let fd = rustix::fs::openat(
        dir,
        file,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let mut text = String::new();
    std::fs::File::from(fd)
        .take(MAX_INTERFACE_FILE)
        .read_to_string(&mut text)
        .map_err(|err| Errno::from_io_error(&err).unwrap_or(Errno::IO))?;
    Ok(text)
}

/// The space-separated words of a file of a cgroup's interface.
fn read_words(dir: &OwnedFd, file: &str) -> Result<Vec<String>, Errno> {
    Ok(read_text(dir, file)?
        .split_whitespace()
        .map(str::to_string)
        .collect())
}

/// A file of a cgroup's interface holding one number, or `None` where the
/// kernel offers no such file or it holds none.
fn read_number(dir: &OwnedFd, file: &str) -> Option<u64> {
    read_text(dir, file).ok()?.trim().parse().ok()
}

/// The value of `key` in a flat-keyed file such as `cpu.stat`, one
/// `key value` pair a line.
fn keyed(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(' ')?;
        (name == key).then(|| value.trim().parse().ok())?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_parses_from_its_name_and_value() {
        let parsed = |text: &str| text.parse::<CgroupLimit>();
        assert_eq!(
            parsed("memory-max=1048576"),
            Ok(CgroupLimit::MemoryMax(1 << 20))
        );
        assert_eq!(parsed(" pids-max = 64 "), Ok(CgroupLimit::PidsMax(64)));
        assert_eq!(
            parsed("cpu-max=50000:200000"),
            Ok(CgroupLimit::cpu_max(50_000, 200_000))
        );
        assert_eq!(
            parsed("cpu-max=50000"),
            Ok(CgroupLimit::cpu_max(50_000, 100_000)),
            "the kernel's own default period",
        );
        assert_eq!(parsed("cpu-weight=200"), Ok(CgroupLimit::CpuWeight(200)));
        for (text, says) in [
            ("pids-max", "NAME=VALUE"),
            ("memory-maximum=1", "names no cgroup limit"),
            ("pids-max=many", "not a value"),
            ("cpu-max=1:", "not a value"),
            ("cpu-weight=70000", "not a value"),
        ] {
            let error = parsed(text).expect_err(text);
            assert_eq!(error.text(), text);
            assert!(error.to_string().contains(says), "{text}: {error}");
        }
    }

    /// Every name the parse takes is the key a profile's `[cgroup]` table
    /// spells the same limit with, which the table's field names decide.
    #[cfg(feature = "serde")]
    #[test]
    fn a_limits_name_is_its_profile_key() {
        for limit in [
            "memory-max=1048576",
            "memory-swap-max=0",
            "pids-max=64",
            "cpu-weight=200",
        ] {
            let (name, value) = limit.split_once('=').expect("a name and a value");
            let table: CgroupSettings =
                toml::from_str(&format!("{name} = {value}\n")).expect("the table reads");
            assert_eq!(table.limits(), [limit.parse::<CgroupLimit>().expect(limit)]);
        }
        let table: CgroupSettings =
            toml::from_str("cpu-max = { quota = 50000, period = 100000 }\n")
                .expect("the table reads");
        assert_eq!(
            table.limits(),
            ["cpu-max=50000:100000".parse().expect("cpu-max")]
        );
    }

    #[test]
    fn a_flat_keyed_file_is_read_by_its_key() {
        let stat = "usage_usec 1500\nuser_usec 1000\nsystem_usec 500\nnr_periods 0\n";
        assert_eq!(keyed(stat, "user_usec"), Some(1000));
        assert_eq!(keyed(stat, "system_usec"), Some(500));
        assert_eq!(keyed(stat, "usage"), None, "a key is matched whole");
        assert_eq!(keyed("oom 0\noom_kill 2\n", "oom_kill"), Some(2));
    }

    #[test]
    fn each_limit_is_written_to_its_file_in_its_units() {
        let write = |limit| LimitWrite::of(limit).expect("a limit the kernel takes");
        let cpu = write(CgroupLimit::cpu_max(50_000, 100_000));
        assert_eq!(
            (cpu.controller, cpu.file, cpu.value.as_str()),
            ("cpu", "cpu.max", "50000 100000")
        );
        let memory = write(CgroupLimit::MemoryMax(1 << 20));
        assert_eq!(
            (memory.file, memory.value.as_str()),
            ("memory.max", "1048576")
        );
        assert_eq!(write(CgroupLimit::PidsMax(64)).controller, "pids");
        assert_eq!(write(CgroupLimit::CpuWeight(100)).file, "cpu.weight");
    }

    #[test]
    fn a_value_the_kernel_refuses_is_refused_at_build() {
        for limit in [
            CgroupLimit::cpu_max(50_000, 999),
            CgroupLimit::cpu_max(50_000, 1_000_001),
            CgroupLimit::cpu_max(999, 100_000),
            CgroupLimit::CpuWeight(0),
            CgroupLimit::CpuWeight(10_001),
        ] {
            assert!(
                matches!(
                    LimitWrite::of(limit),
                    Err(crate::ConfigError::CgroupLimitInvalid { .. })
                ),
                "{limit:?}",
            );
        }
    }

    #[test]
    fn an_errno_reads_as_the_refusal_its_step_stands_for() {
        let cases = [
            (Step::OpenParent, Errno::NOENT, Some(CgroupRefusal::Missing)),
            (
                Step::OpenParent,
                Errno::NOTDIR,
                Some(CgroupRefusal::Missing),
            ),
            (Step::Create, Errno::ROFS, Some(CgroupRefusal::ReadOnly)),
            (Step::Enable, Errno::ROFS, Some(CgroupRefusal::ReadOnly)),
            (
                Step::Create,
                Errno::ACCESS,
                Some(CgroupRefusal::NotDelegated),
            ),
            (Step::Enable, Errno::PERM, Some(CgroupRefusal::NotDelegated)),
            (
                Step::Enable,
                Errno::BUSY,
                Some(CgroupRefusal::ParentHoldsProcesses),
            ),
            (
                Step::Join,
                Errno::OPNOTSUPP,
                Some(CgroupRefusal::ParentHoldsProcesses),
            ),
            (
                Step::Join,
                Errno::ACCESS,
                Some(CgroupRefusal::CallerOutside),
            ),
            (Step::Join, Errno::NOENT, Some(CgroupRefusal::CallerOutside)),
            // A failure no refusal names stays the host's.
            (Step::Create, Errno::NOSPC, None),
            (Step::OpenFile, Errno::MFILE, None),
            (Step::Join, Errno::NOMEM, None),
        ];
        for (step, errno, expected) in cases {
            assert_eq!(refusal(step, errno), expected, "{step:?} {errno:?}");
        }
        assert_eq!(
            join_refusal(Errno::ACCESS),
            Some(CgroupRefusal::CallerOutside)
        );
    }

    #[test]
    fn a_limit_needs_an_absolute_parent() {
        let mut settings = CgroupSettings::default();
        assert!(settings.plan().expect("nothing set").is_none());
        settings.set(CgroupLimit::PidsMax(8));
        assert!(settings.plan().is_err(), "a limit without a parent");
        settings.parent = Some(PathBuf::from("relative"));
        assert!(settings.plan().is_err(), "a relative parent");
        settings.parent = Some(PathBuf::from("/sys/fs/cgroup/delegated"));
        let plan = settings.plan().expect("a valid plan").expect("a cgroup");
        assert_eq!(plan.writes.len(), 1);
        assert_eq!(plan.limits, [CgroupLimit::PidsMax(8)]);
        assert!(settings.unapplied().is_empty(), "a parent applies them");
    }

    #[test]
    fn limits_not_required_and_without_a_parent_are_named_rather_than_refused() {
        let mut settings = CgroupSettings::default();
        settings.set(CgroupLimit::PidsMax(8));
        settings.required = Some(false);
        assert!(settings.plan().expect("not refused").is_none());
        assert_eq!(settings.unapplied(), [CgroupLimit::PidsMax(8)]);
        settings.required = Some(true);
        assert!(settings.plan().is_err(), "required is the default's answer");
        assert!(settings.unapplied().is_empty());
    }
}
