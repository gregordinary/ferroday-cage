//! The inputs a built sandbox will actually apply.
//!
//! A [`CageBuilder`](crate::CageBuilder)'s `get_` accessors report what the
//! caller asked for. This module reports what that request resolved to: the
//! environment the command will carry, base included, and the mounts the
//! sandbox will establish, managed profile included, in the order they will be
//! applied.
//!
//! The distinction matters to a consumer recording provenance. What a build
//! produces depends on the environment and the filesystem the command sees,
//! and neither the caller's own inputs nor a library version number states
//! those directly. [`ResolvedInputs`] does, as data a consumer can stamp into
//! an artifact beside its own version pin.

use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use crate::mechanism::{LaunchPlan, MountAction};

/// The environment and mounts a built sandbox will apply.
///
/// Obtained from [`Cage::resolved_inputs`](crate::Cage::resolved_inputs) or
/// [`Restriction::resolved_inputs`](crate::Restriction::resolved_inputs).
///
/// # Stability
///
/// This type's *shape* follows the compatibility promise like any other public
/// item. Its *contents* do not: they report the defaults in force, and those
/// are explicitly outside the promise — the mount profile and the base
/// environment may both change in a patch release. That is the reason to
/// record the value rather than assume it, and a consumer that needs the
/// contents themselves to be stable should set
/// [`managed_mounts(false)`](crate::CageBuilder::managed_mounts) and
/// [`base_env(false)`](crate::CageBuilder::base_env) and declare its own.
///
/// # Example
///
/// ```no_run
/// # fn main() -> ferroday_cage::Result<()> {
/// let cage = ferroday_cage::Cage::builder()
///     .rootfs("/srv/rootfs/alpine")
///     .command("/usr/bin/make")
///     .build()?;
///
/// let inputs = cage.resolved_inputs();
/// for (name, value) in &inputs.env {
///     println!("{}={}", name.to_string_lossy(), value.to_string_lossy());
/// }
/// for mount in &inputs.mounts {
///     println!("{}", mount.get_target().display());
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ResolvedInputs {
    /// The command's complete environment, sorted by variable name.
    ///
    /// The caller's variables composed over the library's base, or the
    /// caller's alone where [`base_env(false)`](crate::CageBuilder::base_env)
    /// is set.
    #[cfg_attr(feature = "serde", serde(with = "crate::spec::serde_os::string_map"))]
    pub env: Vec<(OsString, OsString)>,
    /// Every mount the sandbox establishes, in the order it establishes them:
    /// the managed profile, then the caller's own, and last the `resolv.conf`
    /// bind that [`Network::Host`](crate::Network::Host) adds.
    ///
    /// Empty for a [`Restriction`](crate::Restriction), which swaps no root
    /// and mounts nothing.
    pub mounts: Vec<ResolvedMount>,
}

/// One mount a built sandbox will establish.
///
/// The resolved counterpart of [`Mount`](crate::Mount): where that records
/// what a caller declared, this records every mount the sandbox performs,
/// including the ones the managed profile contributes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(tag = "kind"))]
pub enum ResolvedMount {
    /// A tmpfs.
    #[cfg_attr(feature = "serde", serde(rename = "tmpfs"))]
    Tmpfs {
        /// The mount point inside the sandbox.
        target: PathBuf,
        /// The kernel's raw `MS_*` flags.
        flags: u64,
        /// The filesystem data string.
        data: String,
    },
    /// A procfs instance.
    #[cfg_attr(feature = "serde", serde(rename = "procfs"))]
    Procfs {
        /// The mount point inside the sandbox.
        target: PathBuf,
    },
    /// A devpts instance.
    #[cfg_attr(feature = "serde", serde(rename = "devpts"))]
    Devpts {
        /// The mount point inside the sandbox.
        target: PathBuf,
        /// The filesystem data string.
        data: String,
    },
    /// A bind of a host path.
    #[cfg_attr(feature = "serde", serde(rename = "bind"))]
    Bind {
        /// The host path bound in.
        source: PathBuf,
        /// The mount point inside the sandbox.
        target: PathBuf,
        /// Whether the bind is remounted read-only.
        #[cfg_attr(feature = "serde", serde(rename = "read-only"))]
        read_only: bool,
    },
    /// A mount whose parameters go to the kernel verbatim.
    #[cfg_attr(feature = "serde", serde(rename = "raw"))]
    Raw {
        /// The mount source, when one was given.
        source: Option<PathBuf>,
        /// The mount point inside the sandbox.
        target: PathBuf,
        /// The filesystem type, when one was given.
        fstype: Option<String>,
        /// The kernel's raw `MS_*` flags.
        flags: u64,
        /// The filesystem data string, when one was given.
        data: Option<String>,
    },
    /// A symlink created inside the rootfs.
    ///
    /// Not a mount in the kernel's sense, but part of what the managed profile
    /// establishes — the five `/dev` symlinks arrive this way — and so part of
    /// the filesystem the command sees.
    #[cfg_attr(feature = "serde", serde(rename = "symlink"))]
    Symlink {
        /// The link's own path inside the sandbox.
        path: PathBuf,
        /// The path the link points at, as written.
        target: PathBuf,
    },
}

impl ResolvedMount {
    /// The path inside the sandbox this mount is established at.
    ///
    /// For a [`Symlink`](Self::Symlink) this is the link itself, not the path
    /// it points at.
    pub fn get_target(&self) -> &std::path::Path {
        match self {
            ResolvedMount::Tmpfs { target, .. }
            | ResolvedMount::Procfs { target }
            | ResolvedMount::Devpts { target, .. }
            | ResolvedMount::Bind { target, .. }
            | ResolvedMount::Raw { target, .. } => target,
            ResolvedMount::Symlink { path, .. } => path,
        }
    }
}

impl ResolvedInputs {
    /// Projects a frozen launch plan onto the public shape.
    ///
    /// Runs on the caller's own thread, on demand: nothing here is computed
    /// during a launch, and a [`Cage`](crate::Cage) does not carry the result.
    pub(crate) fn project(plan: &LaunchPlan) -> ResolvedInputs {
        ResolvedInputs {
            env: plan.env.iter().map(split_env).collect(),
            mounts: plan
                .ops
                .iter()
                .map(|op| project_mount(&op.action))
                .collect(),
        }
    }
}

/// Splits a frozen `NAME=value` entry back into its pair.
///
/// The environment is lowered to `NAME=value` byte strings at build time
/// because that is what `execve` takes. Splitting at the first `=` inverts
/// that exactly: a name may not contain `=` — the builder rejects one that
/// does — so the first separator is always the right one, and a value
/// containing `=` is preserved whole.
fn split_env(entry: &CString) -> (OsString, OsString) {
    let bytes = entry.as_bytes();
    match bytes.iter().position(|byte| *byte == b'=') {
        Some(index) => (
            OsString::from_vec(bytes[..index].to_vec()),
            OsString::from_vec(bytes[index + 1..].to_vec()),
        ),
        // Unreachable through the builder, which composes every entry with a
        // separator. Reporting the whole entry as a name beats panicking in an
        // inspection method.
        None => (OsString::from_vec(bytes.to_vec()), OsString::new()),
    }
}

/// Projects one internal mount action onto the public shape.
fn project_mount(action: &MountAction) -> ResolvedMount {
    match action {
        MountAction::Tmpfs {
            target,
            flags,
            data,
        } => ResolvedMount::Tmpfs {
            target: absolute(target),
            // Widened to match `RawMount::get_flags`, which is `u64` so the
            // public surface does not depend on the kernel type's width.
            flags: u64::from(flags.bits()),
            data: lossy(data),
        },
        MountAction::Procfs { target } => ResolvedMount::Procfs {
            target: absolute(target),
        },
        MountAction::Devpts { target, data } => ResolvedMount::Devpts {
            target: absolute(target),
            data: lossy(data),
        },
        MountAction::Bind {
            source,
            target,
            read_only,
        } => ResolvedMount::Bind {
            source: PathBuf::from(OsString::from_vec(source.as_bytes().to_vec())),
            target: absolute(target),
            read_only: *read_only,
        },
        MountAction::Raw {
            source,
            target,
            fstype,
            flags,
            data,
        } => ResolvedMount::Raw {
            // An unset source, fstype, or data is frozen as an empty string,
            // which is what the kernel receives either way, so the projection
            // reads empty back as absent.
            source: optional(source).map(PathBuf::from),
            target: absolute(target),
            fstype: optional(fstype).map(|value| value.to_string_lossy().into_owned()),
            // Widened to match `RawMount::get_flags`, which is `u64` so the
            // public surface does not depend on the kernel type's width.
            flags: u64::from(flags.bits()),
            data: optional(data).map(|value| value.to_string_lossy().into_owned()),
        },
        MountAction::Symlink {
            parent,
            leaf,
            content,
        } => {
            let mut path = absolute(parent);
            path.push(OsString::from_vec(leaf.as_bytes().to_vec()));
            ResolvedMount::Symlink {
                path,
                target: PathBuf::from(OsString::from_vec(content.as_bytes().to_vec())),
            }
        }
    }
}

/// Turns a rootfs-relative frozen target into the absolute path it occupies
/// inside the sandbox, which is how a consumer reading the record thinks of
/// it.
fn absolute(target: &CString) -> PathBuf {
    let mut path = Vec::with_capacity(target.as_bytes().len() + 1);
    path.push(b'/');
    path.extend_from_slice(target.as_bytes());
    PathBuf::from(OsString::from_vec(path))
}

/// Reads a frozen optional field: empty means it was never set.
fn optional(value: &CString) -> Option<OsString> {
    if value.as_bytes().is_empty() {
        None
    } else {
        Some(OsString::from_vec(value.as_bytes().to_vec()))
    }
}

/// Reads a frozen data string. These are composed by the crate itself from
/// ASCII literals, so the conversion never actually loses anything.
fn lossy(value: &CString) -> String {
    String::from_utf8_lossy(value.as_bytes()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `NAME=value` entry, as the builder freezes them.
    fn entry(text: &str) -> CString {
        CString::new(text).unwrap()
    }

    #[test]
    fn a_value_containing_an_equals_sign_survives_the_split() {
        // Only the first separator is the separator: a name cannot contain
        // `=` — the builder refuses one that does — so everything after the
        // first is value.
        let (name, value) = split_env(&entry("CFLAGS=-DA=1 -DB=2"));
        assert_eq!(name, OsString::from("CFLAGS"));
        assert_eq!(value, OsString::from("-DA=1 -DB=2"));
    }

    #[test]
    fn an_empty_value_round_trips() {
        let (name, value) = split_env(&entry("EMPTY="));
        assert_eq!(name, OsString::from("EMPTY"));
        assert_eq!(value, OsString::new());
    }

    #[test]
    fn a_rootfs_relative_target_is_reported_as_an_absolute_path() {
        // Targets are frozen relative to the rootfs, because that is what the
        // sandbox stage resolves them against; a consumer reading the record
        // wants the path as the command sees it.
        assert_eq!(absolute(&entry("dev/pts")), PathBuf::from("/dev/pts"));
        assert_eq!(absolute(&entry("tmp")), PathBuf::from("/tmp"));
    }

    #[test]
    fn an_unset_raw_field_reads_back_as_absent() {
        assert_eq!(optional(&entry("")), None);
        assert_eq!(optional(&entry("tmpfs")), Some(OsString::from("tmpfs")));
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use crate::{Cage, RawMount};

    /// The record a consumer stamps into provenance is a TOML document, and
    /// its shape is what that consumer's own format has to accommodate.
    #[test]
    fn the_record_renders_as_a_provenance_document() {
        // Both opt-outs, which is the combination a reproducibility-focused
        // consumer runs and which keeps the document short enough to assert
        // whole. The managed profile's own contribution is covered below.
        let cage = Cage::builder()
            .rootfs("/tmp")
            .managed_mounts(false)
            .base_env(false)
            .command("/bin/sh")
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .bind_ro("/etc", "/usr/src")
            .raw_mount(RawMount::new("/dev").fstype("tmpfs").flags(2))
            .build()
            .expect("a valid sandbox configuration");
        let rendered = toml::to_string(&cage.resolved_inputs()).expect("the record serializes");
        assert_eq!(
            rendered,
            "[env]\n\
             SOURCE_DATE_EPOCH = \"1700000000\"\n\
             \n\
             [[mounts]]\n\
             kind = \"bind\"\n\
             source = \"/etc\"\n\
             target = \"/usr/src\"\n\
             read-only = true\n\
             \n\
             [[mounts]]\n\
             kind = \"raw\"\n\
             target = \"/dev\"\n\
             fstype = \"tmpfs\"\n\
             flags = 2\n",
        );
    }

    #[test]
    fn the_managed_profile_records_its_symlinks() {
        // The five /dev symlinks are the part of the default profile no other
        // accessor can report, and the reason `get_mount_dev()` alone does not
        // tell a consumer what `/dev` will contain.
        let inputs = Cage::builder()
            .rootfs("/tmp")
            .command("/bin/sh")
            .build()
            .expect("a valid sandbox configuration")
            .resolved_inputs();
        let rendered = toml::to_string(&inputs).expect("the record serializes");
        for link in ["stdin", "stdout", "stderr", "fd", "ptmx"] {
            assert!(
                rendered.contains(&format!("path = \"/dev/{link}\"")),
                "missing /dev/{link} in:\n{rendered}",
            );
        }
    }
}
