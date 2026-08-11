//! Layered build roots: what a Debian base layer already carries.
//!
//! A build pipeline provisions a base system once, then per component stages
//! only that component's build dependencies over it — resolving against the base
//! as already-installed, extracting the increment into an overlay upper, and
//! configuring it in a cage rooted on an overlay of the pristine base. The base
//! is never mutated; the increment lives in the upper, which the
//! [`BuildLayer`](crate::provision::BuildLayer) the staging returns removes when
//! dropped.
//!
//! This module holds the one self-contained piece: reading a base's
//! already-installed set for the resolver. The staging and configure
//! orchestration lives in the [parent module](super) beside the full-bootstrap
//! pipeline it reuses.

use std::collections::HashSet;
use std::path::Path;

use super::DebianError;
use super::index::parse_provides;
use crate::provision::document;

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
/// The base is a caller-supplied tree, so the read is anchored to a descriptor
/// for it: a symbolic link at the status path would otherwise be followed
/// against the host's root, turning this into a read of an arbitrary host file
/// whose contents decide what the increment resolves against.
///
/// [`Debian::stage_layer`]: super::Debian::stage_layer
pub(super) fn read_installed_set(base: &Path) -> Result<HashSet<String>, DebianError> {
    let text = match super::bootstrap::read_base_status(base) {
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
            return Err(DebianError::io(
                "reading the base layer's dpkg status database",
                base.join(super::bootstrap::STATUS),
                source,
            ));
        }
    };

    let mut installed = HashSet::new();
    for stanza in document::parse(&text) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    fn base_with_status(dir: &Path, status: &str) {
        let dpkg = dir.join("var/lib/dpkg");
        std::fs::create_dir_all(&dpkg).unwrap();
        std::fs::write(dpkg.join("status"), status).unwrap();
    }
    #[test]
    fn read_installed_set_collects_configured_names_and_provides() {
        // Two configured packages, one carrying a Provides, and one half-installed
        // package that must not count. The set is the configured names plus the
        // virtuals they provide.
        let dir = Scratch::for_test("layer", "installed-set");
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
        let missing = Scratch::for_test("layer", "no-status");
        assert!(matches!(
            read_installed_set(&missing),
            Err(DebianError::Config { .. }),
        ));

        // A status database listing nothing installed (an extract-only tree) is
        // rejected rather than treated as an empty base.
        let empty = Scratch::for_test("layer", "empty-status");
        base_with_status(&empty, "");
        assert!(matches!(
            read_installed_set(&empty),
            Err(DebianError::Config { .. }),
        ));
    }
}
