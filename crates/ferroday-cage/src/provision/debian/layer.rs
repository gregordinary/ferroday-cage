//! Layered build roots: install a delta over a shared base into a disposable
//! overlay upper.
//!
//! A build pipeline provisions a base system once, then per component stages
//! only that component's build dependencies over it — resolving against the base
//! as already-installed, extracting the increment into an overlay upper, and
//! configuring it in a cage rooted on an overlay of the pristine base. The base
//! is never mutated; the increment lives in the upper, which the returned
//! [`BuildLayer`] removes when dropped.
//!
//! This module holds the two self-contained pieces: reading a base's
//! already-installed set for the resolver, and the [`BuildLayer`] disposal
//! handle. The staging and configure orchestration lives in the [parent
//! module](super) beside the full-bootstrap pipeline it reuses.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::DebianError;
use super::index::{parse_provides, parse_stanzas};
use crate::IdentityMap;

/// Reads a base layer's already-installed set: every configured package's name
/// and the virtual packages those packages provide, in one set.
///
/// The set seeds a delta resolution as pre-satisfied, so the increment
/// [`Debian::stage_layer`] resolves closes only over packages the base does not
/// carry. It is read from the base's own dpkg status database
/// (`<base>/var/lib/dpkg/status`), keeping the ids the resolver assumes and the
/// files the base actually holds in agreement, and requiring the caller to
/// thread nothing.
///
/// Only packages the status database records as installed and error-free count —
/// `install ok installed`, and the held `hold ok installed` alongside it. The
/// base must be a fully configured bootstrap, so a base whose status database is
/// absent or lists nothing installed — an `extract_only` tree — is rejected
/// rather than treated as an empty base, which would draw the whole base system
/// into the increment.
///
/// [`Debian::stage_layer`]: super::Debian::stage_layer
pub(super) fn read_installed_set(base: &Path) -> Result<HashSet<String>, DebianError> {
    let status_path = base.join("var/lib/dpkg/status");
    let text = match std::fs::read_to_string(&status_path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(DebianError::Config {
                reason: format!(
                    "the base layer at {} has no dpkg status database; a base layer must be a fully \
                 configured bootstrap, not extract-only",
                    base.display(),
                ),
            });
        }
        Err(source) => {
            return Err(DebianError::Io {
                op: "reading the base layer's dpkg status database",
                path: status_path,
                source,
            });
        }
    };

    let mut installed = HashSet::new();
    for stanza in parse_stanzas(&text) {
        let (Some(name), Some(status)) = (stanza.get("Package"), stanza.get("Status")) else {
            continue;
        };
        // Anything short of present-and-configured is not a dependency the
        // increment may assume satisfied.
        if !is_configured(status) {
            continue;
        }
        installed.insert(name.to_string());
        // A package's provided virtuals satisfy dependencies named against them,
        // so folding them into the set lets one membership test in the resolver
        // cover a base that satisfies a group either by real name or by virtual.
        if let Some(provides) = stanza.get("Provides") {
            installed.extend(parse_provides(provides));
        }
    }

    if installed.is_empty() {
        return Err(DebianError::Config {
            reason: format!(
                "the base layer at {} lists no configured packages; a base layer must be a fully \
             configured bootstrap, not extract-only",
                base.display(),
            ),
        });
    }
    Ok(installed)
}

/// Whether a dpkg `Status` field describes a package present and configured in
/// the tree.
///
/// The field is three words, `<want> <error flag> <state>`. Only the last two
/// speak to what is on disk: the state must be `installed` — not `unpacked`,
/// `half-configured`, or `config-files` — and the error flag must be `ok`, since
/// a package awaiting reinstallation cannot be assumed whole. The want is the
/// administrator's intention rather than the tree's contents, so a held package
/// (`hold ok installed`) counts exactly as an `install ok installed` one does.
fn is_configured(status: &str) -> bool {
    let mut words = status.split_ascii_whitespace();
    let (_want, flag, state) = (words.next(), words.next(), words.next());
    words.next().is_none() && flag == Some("ok") && state == Some("installed")
}

/// A staged build layer: the disposable overlay upper an increment was installed
/// into, removed when the handle is dropped.
///
/// Returned by [`Debian::stage_layer`](super::Debian::stage_layer). The upper it
/// owns is the writable layer of a build root — the caller roots a cage on
/// [`overlay_rootfs(base, layer.path())`](crate::CageBuilder::overlay_rootfs) to
/// build against the merged `base + increment` view. Dropping the handle removes
/// the upper and the overlay's work directory beside it, reverting the increment
/// and leaving the base pristine; the base is a separate directory the handle
/// never touches.
///
/// Keep the handle alive for as long as the build root is in use, and drop it to
/// dispose of the increment. The removal is best-effort at drop time — a drop
/// cannot report an error — so a caller that must observe a disposal failure
/// removes the upper directory explicitly through
/// [`provision::remove`](crate::provision::remove) before dropping the handle,
/// which then finds nothing to remove.
#[derive(Debug)]
pub struct BuildLayer {
    /// The overlay upper the increment was installed into: the build root's
    /// writable layer.
    upper: PathBuf,
    /// The overlay work directory beside the upper. The kernel leaves a mode-`0`
    /// directory here that a plain recursive delete cannot descend, so disposal
    /// treats it specially.
    work: PathBuf,
    /// The identity map the increment was configured under, which decides how the
    /// upper and work directory are removed.
    identity_map: IdentityMap,
}

impl BuildLayer {
    /// Builds a layer handle over a staged `upper`, computing the sibling work
    /// directory the overlay-rooted cage manages so disposal removes both.
    pub(super) fn new(upper: &Path, identity_map: IdentityMap) -> BuildLayer {
        // The work directory is the same sibling an overlay-rooted cage derives
        // from this upper; a canonical upper always has a parent and file name,
        // so the fallback to the upper itself is unreachable in practice and
        // simply makes disposal a no-op rather than panicking.
        let work = crate::spec::overlay_work_dir(upper).unwrap_or_else(|| upper.to_path_buf());
        BuildLayer {
            upper: upper.to_path_buf(),
            work,
            identity_map,
        }
    }

    /// The overlay upper directory, the build root's writable layer.
    ///
    /// Pass it as the upper of
    /// [`CageBuilder::overlay_rootfs`](crate::CageBuilder::overlay_rootfs), with
    /// the base as the lower, to root a build cage on the merged view.
    pub fn path(&self) -> &Path {
        &self.upper
    }
}

impl Drop for BuildLayer {
    fn drop(&mut self) {
        // Under the single-identity map every entry is the caller's own, but the
        // overlay leaves a mode-`0` work directory a plain delete cannot descend;
        // a chmod-aware removal restores traversable permissions as it goes.
        // Under a range map the increment and the work directory hold
        // subordinate-owned entries the caller cannot chmod, so the removal
        // escalates through the identity map, where root inside it owns them.
        if matches!(self.identity_map, IdentityMap::Single) {
            crate::host::force_remove_dir_all(&self.upper);
            crate::host::force_remove_dir_all(&self.work);
        } else {
            let _ = crate::provision::remove(&self.upper);
            let _ = crate::provision::remove(&self.work);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    fn base_with_status(dir: &Path, status: &str) {
        let dpkg = dir.join("var/lib/dpkg");
        std::fs::create_dir_all(&dpkg).unwrap();
        std::fs::write(dpkg.join("status"), status).unwrap();
    }

    fn tempdir(tag: &str) -> Scratch {
        Scratch::new(&format!("layer-{tag}"))
    }

    #[test]
    fn read_installed_set_collects_configured_names_and_provides() {
        // Two configured packages, one carrying a Provides, and one half-installed
        // package that must not count. The set is the configured names plus the
        // virtuals they provide.
        let dir = tempdir("installed-set");
        base_with_status(
            &dir,
            "Package: libc6\nStatus: install ok installed\nVersion: 2.41\n\n\
             Package: mawk\nStatus: install ok installed\nProvides: awk\nVersion: 1.3\n\n\
             Package: half\nStatus: install ok unpacked\nVersion: 1.0\n",
        );
        let set = read_installed_set(&dir).expect("the status database reads");
        assert!(set.contains("libc6"));
        assert!(set.contains("mawk"));
        assert!(set.contains("awk"), "a provided virtual is in the set");
        assert!(
            !set.contains("half"),
            "a package not `install ok installed` is not assumed",
        );
    }

    #[test]
    fn read_installed_set_rejects_a_missing_or_empty_database() {
        // A base with no status database is not a configured bootstrap.
        let missing = tempdir("no-status");
        assert!(matches!(
            read_installed_set(&missing),
            Err(DebianError::Config { .. }),
        ));

        // A status database listing nothing installed (an extract-only tree) is
        // rejected rather than treated as an empty base.
        let empty = tempdir("empty-status");
        base_with_status(&empty, "");
        assert!(matches!(
            read_installed_set(&empty),
            Err(DebianError::Config { .. }),
        ));
    }

    #[test]
    fn a_single_map_layer_drop_removes_the_upper_and_work_tree() {
        // A single-identity layer disposes of its upper and the overlay work
        // directory, including a mode-`0` work/work directory a plain recursive
        // delete cannot descend — the artifact an overlay mount leaves behind.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir("dispose-single");
        let upper = dir.join("upper");
        std::fs::create_dir_all(upper.join("usr/bin")).unwrap();
        std::fs::write(upper.join("usr/bin/tool"), b"x").unwrap();

        let work = crate::spec::overlay_work_dir(&upper).unwrap();
        std::fs::create_dir_all(work.join("work")).unwrap();
        std::fs::write(work.join("index"), b"i").unwrap();
        // The overlay artifact: a directory with no permissions at all.
        std::fs::set_permissions(work.join("work"), std::fs::Permissions::from_mode(0o000))
            .unwrap();

        let layer = BuildLayer::new(&upper, IdentityMap::Single);
        assert_eq!(layer.path(), upper.as_path());
        drop(layer);

        assert!(!upper.exists(), "the upper is removed");
        assert!(
            !work.exists(),
            "the work directory is removed despite mode-0"
        );
    }
}
