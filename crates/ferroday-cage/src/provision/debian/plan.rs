//! The resolved install plan: the packages a bootstrap would install, reported
//! without downloading or configuring any of them.

use super::index::Package;

/// The packages a [`Debian`](super::Debian) bootstrap resolves for its suite,
/// produced without downloading or unpacking anything.
///
/// Returned by [`Debian::resolve`](super::Debian::resolve). Every package's
/// digest is archive-verified: it is read from an index whose own digest the
/// signed release records, so a plan resolved from a signed archive is anchored
/// to the archive signature rather than to a mirror's unverified word. The
/// packages are ordered by name, so the plan is a stable value to cache a build
/// on or compare across runs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Plan {
    /// The suite the plan resolves against, as requested.
    pub suite: String,
    /// The architecture the packages target.
    pub architecture: String,
    /// The resolved install set, ordered by name.
    pub packages: Vec<PlannedPackage>,
}

/// One package in a [`Plan`]: enough to identify the exact `.deb` and to key a
/// cache on it, carrying no dependency or download state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlannedPackage {
    /// The package name.
    pub name: String,
    /// The exact version that would be installed.
    pub version: String,
    /// The package's architecture: the target architecture, or `all`.
    pub architecture: String,
    /// The SHA-256 the archive records for the `.deb`, as lowercase hex.
    pub sha256: String,
    /// The pool path of the `.deb`, relative to the mirror root.
    pub filename: String,
}

impl Plan {
    /// Builds a plan from a resolved package set, projecting each package onto
    /// the public shape. Shared by [`Debian::resolve`](super::Debian::resolve)
    /// and the mid-bootstrap [`Resolved`](super::DebianEvent::Resolved) event, so
    /// the plan a caller previews and the plan an in-flight bootstrap reports are
    /// the same value built one way.
    pub(crate) fn project(suite: &str, architecture: &str, packages: &[Package]) -> Plan {
        Plan {
            suite: suite.to_string(),
            architecture: architecture.to_string(),
            packages: packages.iter().map(PlannedPackage::from_package).collect(),
        }
    }
}

impl PlannedPackage {
    /// Projects an internal [`Package`] onto the public plan shape.
    pub(crate) fn from_package(package: &Package) -> PlannedPackage {
        PlannedPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            architecture: package.architecture.clone(),
            sha256: package.sha256.clone(),
            filename: package.filename.clone(),
        }
    }
}
