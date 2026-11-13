//! A cgroup of the sandbox's own, beneath a directory the caller delegates.
//!
//! The library creates no hierarchy and needs no privilege. The caller hands it
//! a directory of a cgroup v2 hierarchy in which it may create cgroups: a
//! delegated subtree, such as systemd's `Delegate=yes` gives a service or a
//! scope. Each launch then creates a cgroup of its own beneath that directory,
//! enables the controllers its limits need, writes the limits, and opens the
//! cgroup's `cgroup.procs`. The launch stage moves itself into the cgroup
//! through that descriptor before it creates any namespace, so every process
//! the sandbox runs is charged there, and the cgroup namespace the sandbox
//! creates is rooted at it.
//!
//! The handle reads what the whole tree used from the cgroup once the command's
//! outcome is known, ends the tree through `cgroup.kill` where the kernel has
//! one, and removes the cgroup once nothing is left in it.

use std::ffi::CString;
use std::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::error::Error;

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

/// Why a sandbox could not be given a cgroup of its own beneath the parent the
/// caller named.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CgroupRefusal {
    /// The parent is not a directory of a cgroup v2 hierarchy. A host that
    /// mounts only the v1 hierarchies offers none.
    NotCgroup2,
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
}

impl fmt::Display for CgroupRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CgroupRefusal::NotCgroup2 => f.write_str(
                "it is not a directory of a cgroup v2 hierarchy, which a host that mounts only \
                 the v1 hierarchies has none of",
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
        }
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

    /// The plan a launch carries out, or the reason the settings are not one.
    ///
    /// `None` where no parent is named, which is no cgroup at all. A limit
    /// without a parent is refused, since it would hold nothing.
    pub(crate) fn plan(&self) -> Result<Option<CgroupPlan>, crate::ConfigError> {
        let limits = self.limits();
        let Some(parent) = &self.parent else {
            return match limits.is_empty() {
                true => Ok(None),
                false => Err(crate::ConfigError::CgroupLimitInvalid {
                    reason: "a cgroup limit needs a cgroup parent to create the sandbox's cgroup \
                             beneath"
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
        for limit in limits {
            writes.push(LimitWrite::of(limit)?);
        }
        Ok(Some(CgroupPlan {
            parent: parent.clone(),
            writes,
        }))
    }
}

/// What a launch does to give the sandbox a cgroup: where, and what it writes.
#[derive(Debug, Clone)]
pub(crate) struct CgroupPlan {
    /// The delegated directory the sandbox's cgroup is created beneath.
    pub(crate) parent: PathBuf,
    /// The limits, as the files and values they are written as.
    writes: Vec<LimitWrite>,
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

/// The sandbox's cgroup, from its creation before the launch until the handle
/// has read what the tree used and removed it.
pub(crate) struct Cgroup {
    /// The parent directory, which the cgroup is removed from.
    parent: OwnedFd,
    /// The parent as the caller named it, for errors.
    parent_path: PathBuf,
    /// The cgroup's name beneath the parent.
    name: CString,
    /// The cgroup's own directory.
    dir: OwnedFd,
    /// Its `cgroup.procs`, which the launch stage writes itself into.
    procs: OwnedFd,
    /// Its `cgroup.kill`, where the kernel has one (Linux 5.14).
    kill: Option<OwnedFd>,
}

impl Cgroup {
    /// Creates the sandbox's cgroup beneath the plan's parent, enables the
    /// controllers its limits need, and writes the limits.
    ///
    /// # Errors
    ///
    /// [`Error::CgroupRefused`] where the parent cannot hold such a cgroup, and
    /// [`Error::Cgroup`] where a step fails for a reason of the host's, such as
    /// a parent the caller may not write.
    pub(crate) fn create(plan: &CgroupPlan) -> Result<Cgroup, Error> {
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
        let parent = rustix::fs::open(
            &plan.parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io_error("opening the cgroup parent", &plan.parent))?;
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
            match enable(&parent, controller) {
                Ok(()) => {}
                Err(Errno::BUSY) => return Err(refused(CgroupRefusal::ParentHoldsProcesses)),
                Err(errno) => {
                    return Err(io_error(
                        "enabling a controller in the parent's cgroup.subtree_control",
                        &plan.parent,
                    )(errno));
                }
            }
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
            io_error("creating the sandbox's cgroup beneath", &plan.parent),
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
            .map_err(io_error("opening the sandbox's cgroup", &path))?;
            for write in &plan.writes {
                match open_write(&dir, write.file) {
                    Ok(file) => rustix::io::write(&file, write.value.as_bytes())
                        .map(drop)
                        .map_err(io_error("writing a limit to the sandbox's cgroup", &path))?,
                    Err(Errno::NOENT) => {
                        return Err(refused(CgroupRefusal::LimitUnsupported {
                            file: write.file,
                        }));
                    }
                    Err(errno) => {
                        return Err(io_error("opening a limit of the sandbox's cgroup", &path)(
                            errno,
                        ));
                    }
                }
            }
            let procs = open_write(&dir, "cgroup.procs")
                .map_err(io_error("opening the sandbox's cgroup.procs", &path))?;
            let kill = open_write(&dir, "cgroup.kill").ok();
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
            }),
            Err(err) => {
                let _ = rustix::fs::unlinkat(&parent, name.as_c_str(), AtFlags::REMOVEDIR);
                Err(err)
            }
        }
    }

    /// The cgroup's `cgroup.procs`, which the launch stage writes `0` to, moving
    /// itself in.
    pub(crate) fn procs(&self) -> BorrowedFd<'_> {
        self.procs.as_fd()
    }

    /// A duplicate of the cgroup's `cgroup.kill`, for a handle that kills from
    /// elsewhere, or `None` where the kernel has none.
    pub(crate) fn kill_switch(&self) -> Option<OwnedFd> {
        self.kill.as_ref().and_then(|fd| fd.try_clone().ok())
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
    /// Removes the cgroup, which the kernel allows once no process is left in
    /// it. One that still holds processes, as a sandbox without a PID namespace
    /// can leave behind, stays beneath the parent.
    fn drop(&mut self) {
        let _ = rustix::fs::unlinkat(&self.parent, self.name.as_c_str(), AtFlags::REMOVEDIR);
    }
}

/// Ends every process of a cgroup through its `cgroup.kill`.
pub(crate) fn kill_tree(kill: &OwnedFd) -> Result<(), Errno> {
    rustix::io::write(kill, b"1").map(drop)
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
    }
}
