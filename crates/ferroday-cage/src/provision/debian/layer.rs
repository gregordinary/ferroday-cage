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

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use super::DebianError;
use super::index::{
    Clash, Dependency, Provided, is_multi_arch_allowed, is_package_name, parse_clashes,
    parse_provides, parse_relations,
};
use crate::provision::document;

/// What a base layer supplies, and what its packages need, as the resolver has
/// to ask about it.
///
/// *Does the base supply this name, at a version a dependency accepts?* is
/// asked of every name, real or virtual, each mapped to every [`Supply`] of it.
/// One name can be supplied more than one way — as a real package, and as a
/// virtual that one or more packages `Provides` — so it can be supplied at more
/// than one version. A `None` version is a bare `Provides`, which Debian Policy
/// 7.5 says satisfies only an unversioned dependency.
///
/// Each supply records the package it comes from, because an increment can
/// replace that package. Selecting another version of a name the base has
/// installed replaces the installed version, and everything that version
/// supplied goes with it, its own name and its `Provides` alike. The resolver
/// asks which supplies its selection leaves standing.
///
/// *Which version of this package is installed, and what does it depend on?*
/// is asked of real packages alone. The version decides what a dependency the
/// base does not meet may upgrade the package to, and a virtual name is not a
/// package to upgrade. The dependencies, its `Pre-Depends` and its `Depends`,
/// are what a package the base keeps needs of the root the increment is
/// installed into.
///
/// The versions matter because a base is provisioned once and resolved against
/// later: `libc6 (>= 2.43)` is not answered by "the base has a libc6", and
/// treating it as though it were is what lets an aged base pass a resolve and
/// fail the compile.
///
/// *What can this package not be installed beside, and which packages state
/// that of this name?* is asked of real packages too: a layer removes nothing
/// from its base, so a package the base keeps is never one a candidate may
/// clash with.
#[derive(Debug, Default)]
pub(super) struct InstalledSet {
    supplies: HashMap<String, Vec<Supply>>,
    /// Every installed package this layer can name, in name order, so a check
    /// over all of them meets them in an order nothing else decides.
    packages: BTreeMap<String, Installed>,
    /// The installed packages stating a [`Clash`] on each name, in name order.
    clashing: HashMap<String, Vec<String>>,
}

/// One way a base layer supplies a name: as the package of that name, or as a
/// virtual that a package `Provides`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Supply {
    /// The installed package the supply comes from: the name itself for a real
    /// package, and the providing package for a virtual.
    pub(super) provider: String,
    /// The version the name is supplied at, `None` for a bare `Provides`.
    pub(super) version: Option<String>,
}

/// One installed package of a base layer.
#[derive(Debug, Default)]
pub(super) struct Installed {
    /// The version, where the status database states one.
    pub(super) version: Option<String>,
    /// Its `Pre-Depends`, then its `Depends`.
    pub(super) relations: Vec<Dependency>,
    /// The names it provides, each at the version it states.
    pub(super) provides: Vec<Provided>,
    /// What it cannot be installed beside: its `Conflicts`, then its `Breaks`.
    pub(super) clashes: Vec<Clash>,
    /// Whether it declares `Multi-Arch: allowed`.
    pub(super) multi_arch_allowed: bool,
}

impl InstalledSet {
    /// Records the real package `name` installed at `version` and depending
    /// on `relations`. It also supplies its own name.
    ///
    /// `name` is one [`is_package_name`] admits: a refusal names a package
    /// whose dependency the merged root leaves unmet bare, and this is the
    /// list of packages the root is checked for.
    ///
    /// A stanza with no `Version`, or one outside the alphabet
    /// [`version::is_version`](super::version::is_version) admits, is malformed
    /// rather than versionless, and is recorded as a bare supply: it still
    /// satisfies unversioned dependencies, no versioned one silently, and is no
    /// version to upgrade from or to name in a refusal.
    ///
    /// A name recorded twice, as a status database records a package
    /// installed for two architectures, keeps the first version stated and
    /// both stanzas' relations.
    pub(super) fn install(
        &mut self,
        name: &str,
        version: Option<&str>,
        relations: Vec<Dependency>,
    ) {
        self.supply(name, name, version);
        let installed = self.packages.entry(name.to_string()).or_default();
        if installed.version.is_none() {
            installed.version = version.map(str::to_string);
        }
        installed.relations.extend(relations);
    }

    /// Records that the installed package `provider` supplies `provided`.
    pub(super) fn provide(&mut self, provider: &str, provided: &Provided) {
        self.supply(&provided.name, provider, provided.version.as_deref());
        if let Some(installed) = self.packages.get_mut(provider) {
            installed.provides.push(provided.clone());
        }
    }

    /// Records what the real package `name`, recorded by
    /// [`install`](Self::install), cannot be installed beside, and whether it
    /// declares `Multi-Arch: allowed`.
    pub(super) fn clash(&mut self, name: &str, clashes: Vec<Clash>, multi_arch_allowed: bool) {
        let Some(installed) = self.packages.get_mut(name) else {
            return;
        };
        for clash in &clashes {
            let staters = self.clashing.entry(clash.atom.name.clone()).or_default();
            if let Err(at) = staters.binary_search_by(|stater| stater.as_str().cmp(name)) {
                staters.insert(at, name.to_string());
            }
        }
        installed.clashes.extend(clashes);
        installed.multi_arch_allowed |= multi_arch_allowed;
    }

    /// Records that the installed package `provider` supplies `name` at
    /// `version`, `None` for a bare `Provides`.
    pub(super) fn supply(&mut self, name: &str, provider: &str, version: Option<&str>) {
        self.supplies
            .entry(name.to_string())
            .or_default()
            .push(Supply {
                provider: provider.to_string(),
                version: version.map(str::to_string),
            });
    }

    /// Whether the base supplies `name` at all, by a real package or a virtual.
    pub(super) fn contains(&self, name: &str) -> bool {
        self.supplies.contains_key(name)
    }

    /// Every supply of `name` the base holds, empty where it supplies no such
    /// name.
    pub(super) fn supplied(&self, name: &str) -> &[Supply] {
        self.supplies.get(name).map_or(&[], Vec::as_slice)
    }

    /// The version of the real package `name` the base has installed.
    pub(super) fn installed(&self, name: &str) -> Option<&str> {
        self.packages
            .get(name)
            .and_then(|installed| installed.version.as_deref())
    }

    /// Every real package [`install`](Self::install) recorded, in name order,
    /// so a check over all of them meets them in an order nothing else
    /// decides.
    pub(super) fn members(&self) -> impl Iterator<Item = (&str, &Installed)> {
        self.packages
            .iter()
            .map(|(name, installed)| (name.as_str(), installed))
    }

    /// The real package `name`, where [`install`](Self::install) recorded it.
    pub(super) fn package(&self, name: &str) -> Option<&Installed> {
        self.packages.get(name)
    }

    /// The installed packages stating a `Conflicts` or `Breaks` entry naming
    /// `name`, in name order.
    pub(super) fn clashing(&self, name: &str) -> &[String] {
        self.clashing.get(name).map_or(&[], Vec::as_slice)
    }

    /// Whether the base supplies nothing at all.
    pub(super) fn is_empty(&self) -> bool {
        self.supplies.is_empty()
    }
}

/// Reads a base layer's already-installed set: every configured package, with
/// its dependencies and what it cannot be installed beside, and the virtual
/// packages those packages provide, each with the version it supplies and the
/// package supplying it. The base's `architecture` is what an architecture
/// qualifier on a relation is read against.
///
/// The set seeds a delta resolution, so the increment [`Debian::stage_layer`]
/// resolves closes only over packages the base does not carry, except where it
/// replaces one, and holds what the base keeps to working beside the increment.
/// It is read from the base's own dpkg status database
/// (`<base>/var/lib/dpkg/status`), keeping the ids the resolver assumes and the
/// files the base actually holds in agreement, and requiring the caller to
/// thread nothing.
///
/// Only packages the status database records as installed and error-free count,
/// as [`is_configured`](super::bootstrap::is_configured) reads the field. The
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
pub(super) fn read_installed_set(
    base: &Path,
    architecture: &str,
) -> Result<InstalledSet, DebianError> {
    let text = match super::bootstrap::read_base_status(base) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(DebianError::config(format!(
                "the base layer at {} has no dpkg status database; a base layer must be a fully \
                 configured bootstrap, not extract-only",
                base.display(),
            )));
        }
        Err(source) => {
            return Err(DebianError::io(
                "reading the base layer's dpkg status database",
                base.join(super::bootstrap::STATUS),
                source,
            ));
        }
    };

    let mut installed = InstalledSet::default();
    for stanza in document::parse(&text) {
        let [
            name,
            status,
            version,
            provides,
            pre_depends,
            depends,
            conflicts,
            breaks,
            multi_arch,
        ] = stanza.get_each([
            "Package",
            "Status",
            "Version",
            "Provides",
            "Pre-Depends",
            "Depends",
            "Conflicts",
            "Breaks",
            "Multi-Arch",
        ]);
        let (Some(name), Some(status)) = (name, status) else {
            continue;
        };
        // Anything short of present-and-configured is not a dependency the
        // increment may assume satisfied.
        if !super::bootstrap::is_configured(&status) {
            continue;
        }
        // A version dpkg would not have written is read as none: the database
        // is the base's own text, which its scripts could write too.
        let version = version
            .as_deref()
            .filter(|version| super::version::is_version(version));
        if is_package_name(&name) {
            let relations = [pre_depends, depends]
                .into_iter()
                .flatten()
                .flat_map(|value| parse_relations(&value, architecture))
                .collect();
            installed.install(&name, version, relations);
            installed.clash(
                &name,
                parse_clashes(conflicts.as_deref(), breaks.as_deref(), architecture),
                multi_arch.is_some_and(|value| is_multi_arch_allowed(&value)),
            );
        } else {
            // A name policy does not admit still supplies itself, so nothing
            // installs it again. It is no package this layer names, though: no
            // index this layer reads offers it, so no increment replaces it,
            // and a refusal names a package bare, so its own dependencies are
            // left out of the merged root's check, and so are the packages it
            // states it cannot be installed beside.
            installed.supply(&name, &name, version);
        }
        // A package's provided virtuals satisfy dependencies named against them,
        // so folding them into the same map lets one lookup in the resolver
        // cover a base that satisfies a group either by real name or by virtual.
        for provided in provides.iter().flat_map(|value| parse_provides(value)) {
            installed.provide(&name, &provided);
        }
    }

    if installed.is_empty() {
        return Err(DebianError::config(format!(
            "the base layer at {} lists no configured packages; a base layer must be a fully \
             configured bootstrap, not extract-only",
            base.display(),
        )));
    }
    Ok(installed)
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

    /// Each supply of `name` as `(provider, version)`, for an assertion.
    fn supplies<'s>(set: &'s InstalledSet, name: &str) -> Vec<(&'s str, Option<&'s str>)> {
        set.supplied(name)
            .iter()
            .map(|supply| (supply.provider.as_str(), supply.version.as_deref()))
            .collect()
    }

    /// Each installed package's relations, rendered by name, for an assertion.
    fn relations(set: &InstalledSet) -> Vec<(&str, Vec<Vec<&str>>)> {
        set.members()
            .map(|(name, installed)| {
                let groups = installed
                    .relations
                    .iter()
                    .map(|group| group.iter().map(|atom| atom.name.as_str()).collect())
                    .collect();
                (name, groups)
            })
            .collect()
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
        let set = read_installed_set(&dir, "amd64").expect("the status database reads");
        assert_eq!(supplies(&set, "libc6"), [("libc6", Some("2.41"))]);
        assert_eq!(supplies(&set, "mawk"), [("mawk", Some("1.3"))]);
        // The virtual is present, and bare: `Provides: awk` names no version,
        // so it answers an unversioned dependency and no versioned one. It is
        // no installed package, so nothing upgrades it, and it comes from mawk,
        // so an increment replacing mawk takes it away.
        assert_eq!(supplies(&set, "awk"), [("mawk", None)]);
        assert_eq!(set.installed("awk"), None);
        assert_eq!(set.installed("libc6"), Some("2.41"));
        assert!(
            !set.contains("half"),
            "a package not `install ok installed` is not assumed",
        );
    }

    #[test]
    fn a_version_dpkg_would_not_have_written_is_read_as_none() {
        // The database is the base's own text, which its scripts can write.
        let dir = Scratch::for_test("layer", "unwritable-version");
        let hostile = crate::failure::hostile::TEXT;
        base_with_status(
            &dir,
            &format!("Package: libfoo1\nStatus: install ok installed\nVersion: {hostile}\n"),
        );
        let set = read_installed_set(&dir, "amd64").expect("the status database reads");
        assert_eq!(supplies(&set, "libfoo1"), [("libfoo1", None)]);
        assert_eq!(set.installed("libfoo1"), None);
    }

    #[test]
    fn a_versioned_provides_records_the_version_it_supplies() {
        let dir = Scratch::for_test("layer", "versioned-provides");
        base_with_status(
            &dir,
            "Package: libfoo1\nStatus: install ok installed\nVersion: 1.4-2\n\
             Provides: libfoo (= 1.4)\n",
        );
        let set = read_installed_set(&dir, "amd64").expect("the status database reads");
        assert_eq!(supplies(&set, "libfoo1"), [("libfoo1", Some("1.4-2"))]);
        assert_eq!(supplies(&set, "libfoo"), [("libfoo1", Some("1.4"))]);
        assert_eq!(set.installed("libfoo"), None);
    }

    #[test]
    fn a_configured_package_records_its_pre_depends_then_its_depends() {
        // What a package the base keeps needs of the merged root, read with the
        // index's own relation grammar: alternatives, constraints, and an
        // architecture qualifier read apart from the name. A package short of
        // configured records nothing.
        let dir = Scratch::for_test("layer", "relations");
        base_with_status(
            &dir,
            "Package: libc-bin\nStatus: install ok installed\nVersion: 2.41-10\n\
             Depends: libc6 (>> 2.41), libc6 (<< 2.42)\nPre-Depends: perl:any | awk\n\n\
             Package: libc6\nStatus: install ok installed\nVersion: 2.41-10\n\n\
             Package: half\nStatus: install ok unpacked\nVersion: 1.0\nDepends: libc6\n",
        );
        let set = read_installed_set(&dir, "amd64").expect("the status database reads");
        assert_eq!(
            relations(&set),
            [
                (
                    "libc-bin",
                    vec![vec!["perl", "awk"], vec!["libc6"], vec!["libc6"]]
                ),
                ("libc6", vec![]),
            ],
        );
        let (_, libc_bin) = set.members().next().unwrap();
        let constraint = libc_bin.relations[2][0].constraint.as_ref().unwrap();
        assert_eq!(constraint.to_string(), "<< 2.42");
    }

    #[test]
    fn a_configured_package_records_what_it_clashes_with() {
        // Read with the index's own grammar, the qualifiers against the base's
        // architecture, beside the names it provides and its `Multi-Arch`.
        let dir = Scratch::for_test("layer", "clashes");
        base_with_status(
            &dir,
            "Package: postfix\nStatus: install ok installed\nVersion: 3.10\n\
             Provides: mail-transport-agent\nConflicts: mail-transport-agent, \
             exim4:arm64\nBreaks: libfoo1 (<< 2)\nMulti-Arch: allowed\n\n\
             Package: half\nStatus: install ok unpacked\nVersion: 1.0\n\
             Conflicts: postfix\n",
        );
        let set = read_installed_set(&dir, "amd64").expect("the status database reads");
        let postfix = set.package("postfix").expect("postfix is installed");
        let clashes: Vec<String> = postfix.clashes.iter().map(ToString::to_string).collect();
        assert_eq!(
            clashes,
            [
                "Conflicts: mail-transport-agent",
                "Conflicts: exim4:arm64",
                "Breaks: libfoo1 (<< 2)",
            ],
        );
        assert!(postfix.multi_arch_allowed);
        assert_eq!(postfix.provides[0].name, "mail-transport-agent");
        assert_eq!(set.clashing("mail-transport-agent"), ["postfix"]);
        assert!(
            set.clashing("postfix").is_empty(),
            "a package not configured states nothing the base holds",
        );
    }

    #[test]
    fn a_name_policy_does_not_admit_supplies_itself_and_is_no_package() {
        // Such a name reaches no index this layer reads, so nothing replaces
        // it, and a refusal could not name it bare. It still answers what it
        // supplies, so nothing installs it again.
        let dir = Scratch::for_test("layer", "unnamed");
        let hostile = crate::failure::hostile::TEXT;
        base_with_status(
            &dir,
            &format!(
                "Package: {hostile}\nStatus: install ok installed\nVersion: 1.0\n\
                 Depends: libc6 (= 9)\nProvides: awk\n"
            ),
        );
        let set = read_installed_set(&dir, "amd64").expect("the status database reads");
        assert_eq!(supplies(&set, hostile), [(hostile, Some("1.0"))]);
        assert_eq!(supplies(&set, "awk"), [(hostile, None)]);
        assert_eq!(set.installed(hostile), None);
        assert_eq!(set.members().count(), 0);
    }

    #[test]
    fn read_installed_set_rejects_a_missing_or_empty_database() {
        // A base with no status database is not a configured bootstrap.
        let missing = Scratch::for_test("layer", "no-status");
        assert!(matches!(
            read_installed_set(&missing, "amd64"),
            Err(DebianError::Config { .. }),
        ));

        // A status database listing nothing installed (an extract-only tree) is
        // rejected rather than treated as an empty base.
        let empty = Scratch::for_test("layer", "empty-status");
        base_with_status(&empty, "");
        assert!(matches!(
            read_installed_set(&empty, "amd64"),
            Err(DebianError::Config { .. }),
        ));
    }
}
