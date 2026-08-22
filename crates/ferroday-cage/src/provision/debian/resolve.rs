//! Dependency resolution: the install closure over a package index.
//!
//! From a seed set the resolver closes over `Depends` and `Pre-Depends`,
//! following `debootstrap`'s discipline: the first satisfiable alternative of
//! an `a | b` group, virtual packages satisfied by preferring an
//! already-selected provider. The result is the set of real packages to
//! download and install.
//!
//! Version constraints are **enforced**, not assumed. A full bootstrap draws
//! from one coherent suite, where a constraint is satisfied almost by
//! construction; a layered resolve ([`resolve_seeded`]) does not, because it
//! closes an increment over a base provisioned earlier and possibly from an
//! older archive. Checking the constraint is what keeps `libc6 (>= 2.43)` from
//! being answered by "the base has a libc6" — an answer that passes the resolve
//! and fails the compile an hour later, naming a library that is present and
//! correct.
//!
//! A group nothing satisfies is an error rather than a silent omission. Leaving
//! it out produces a root that cannot work, and produces it quietly: the
//! post-install check verifies that every *selected* package configured, and a
//! dependency dropped here was never selected, so nothing downstream is in a
//! position to notice.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;

use super::index::{DepAtom, Dependency, Index, Package};
use super::layer::InstalledSet;
use super::version::Constraint;

/// A dependency the resolver could not satisfy.
#[derive(Debug)]
pub(crate) enum ResolveError {
    /// A requested package is neither a real package nor a known virtual.
    PackageNotFound {
        /// The requested name.
        name: String,
    },
    /// A caller both requested and excluded the same package.
    ExcludedAndIncluded {
        /// The contradicted name.
        name: String,
    },
    /// An excluded package is the only thing that satisfies a hard dependency
    /// of a selected package, so honoring the exclusion would leave the
    /// dependency unmet. This mirrors apt's refusal of a `pkgname-` deselection
    /// a hard dependency needs.
    ExcludedButRequired {
        /// The excluded package the dependency needed.
        package: String,
        /// The selected package whose dependency it was.
        required_by: String,
    },
    /// No alternative of a hard dependency group can be satisfied: the archive
    /// offers none of the names, or offers them only at versions the declared
    /// constraint rules out, and the base layer supplies none either.
    ///
    /// Reported rather than dropped. dpkg configures with `--force-depends`, so
    /// installing anyway would succeed and leave a root whose packages cannot
    /// work — and would leave it quietly, since the post-install check looks
    /// only at packages that were selected.
    Unsatisfiable {
        /// The dependency group as declared, alternatives included.
        requirement: String,
        /// The selected package whose dependency it was.
        required_by: String,
        /// What is available for the group's names, when anything is — the
        /// evidence that separates "no such package" from "wrong version".
        available: Option<String>,
    },
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::PackageNotFound { name } => {
                write!(f, "package {name} is not in the index")
            }
            ResolveError::ExcludedAndIncluded { name } => {
                write!(f, "package {name} is both included and excluded")
            }
            ResolveError::ExcludedButRequired {
                package,
                required_by,
            } => write!(
                f,
                "package {package} is excluded but required by {required_by}",
            ),
            ResolveError::Unsatisfiable {
                requirement,
                required_by,
                available,
            } => match available {
                Some(available) => write!(
                    f,
                    "{required_by} requires `{requirement}`, which nothing satisfies \
                     (available: {available})",
                ),
                None => write!(
                    f,
                    "{required_by} requires `{requirement}`, which no configured archive \
                     offers and no base layer supplies",
                ),
            },
        }
    }
}

/// Resolves the install closure of `base` plus `includes`, honoring
/// `excludes`.
///
/// `base` names (the essential/priority seed and `apt`) are trusted to
/// exist; a missing one is skipped. Each caller `include` must resolve to a
/// real package or a provided virtual, or the resolution fails naming it. An
/// excluded package is never selected: it is dropped from the seed, and skipped
/// as a dependency alternative so a later alternative satisfies the group
/// instead. A hard dependency an exclusion leaves unsatisfiable fails the
/// resolution rather than shipping a broken closure, and a package that is both
/// included and excluded is a contradiction that fails likewise. The returned
/// packages are sorted by name.
pub(crate) fn resolve(
    index: &Index,
    base: &[String],
    includes: &[String],
    excludes: &[String],
) -> Result<Vec<Package>, ResolveError> {
    resolve_seeded(index, base, includes, excludes, &InstalledSet::new())
}

/// Resolves the install closure while treating `assume_installed` as
/// already-satisfied, so only the increment over an existing base is selected.
///
/// This is [`resolve`] with one additive input. `assume_installed` holds the
/// names a base layer already supplies — every package configured in it, plus
/// the virtual packages those packages `Provides` — expanded into one set. A
/// name in that set is skipped as a seed, satisfies any dependency group naming
/// it, and is never re-selected, so the resolution closes only over the
/// packages the base does not already carry. A caller `include` the base
/// already supplies is likewise satisfied by the base rather than pulled again.
/// [`resolve`] passes an empty set, so a full bootstrap is unaffected. Because a
/// configured base is dependency-complete, the transitive dependencies of an
/// assumed package are themselves assumed, so declining to walk them omits
/// nothing the increment needs.
pub(crate) fn resolve_seeded(
    index: &Index,
    base: &[String],
    includes: &[String],
    excludes: &[String],
    assume_installed: &InstalledSet,
) -> Result<Vec<Package>, ResolveError> {
    let excluded: HashSet<&str> = excludes.iter().map(String::as_str).collect();
    let mut selected: BTreeMap<String, Package> = BTreeMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    // Seed the whole base set before closing over anything, so a virtual
    // dependency encountered during the closure sees every base package as an
    // already-selected candidate provider. An excluded base package is simply
    // not seeded, and one the layer already carries is left to the base.
    for name in base {
        if excluded.contains(name.as_str()) || assume_installed.contains_key(name) {
            continue;
        }
        if let Some(package) = index.get(name) {
            add(&mut selected, &mut queue, package);
        }
    }
    for name in includes {
        // Asking for a package and excluding it in the same breath is a
        // contradiction, reported rather than silently resolved either way.
        if excluded.contains(name.as_str()) {
            return Err(ResolveError::ExcludedAndIncluded { name: name.clone() });
        }
        // A requested package the base already supplies is satisfied by the base
        // and needs no re-selection into the increment.
        if assume_installed.contains_key(name) {
            continue;
        }
        if let Some(package) = index.get(name) {
            add(&mut selected, &mut queue, package);
        } else if let Some(provider) =
            // A caller `include` names a package, never a constrained version,
            // so it asks the unversioned question.
            first_available_provider(
                index,
                &DepAtom {
                    name: name.clone(),
                    constraint: None,
                },
                &excluded,
            )
        {
            let package = index.get(&provider).expect("a provider is a real package");
            add(&mut selected, &mut queue, package);
        } else {
            return Err(ResolveError::PackageNotFound { name: name.clone() });
        }
    }

    while let Some(name) = queue.pop_front() {
        // Clone the relationships so the closure can mutate `selected` freely.
        let package = &selected[&name];
        let relations: Vec<Dependency> = package
            .pre_depends
            .iter()
            .chain(package.depends.iter())
            .cloned()
            .collect();
        for group in &relations {
            resolve_group(
                index,
                group,
                &excluded,
                assume_installed,
                &name,
                &mut selected,
                &mut queue,
            )?;
        }
    }

    Ok(selected.into_values().collect())
}

/// Satisfies one dependency group (a set of alternatives) of `required_by`.
///
/// If any alternative is already satisfied the group is done. Otherwise the
/// first alternative that resolves to a non-excluded package — a real package,
/// or a virtual with a provider — is selected. Excluding a real package that is
/// also a provided virtual name therefore falls through to a provider rather
/// than failing the group. An alternative whose candidate exists at a version
/// the group's constraint rules out is not an answer either, so the search
/// continues to the next one rather than stopping there.
///
/// A group nothing satisfies fails the resolution. Where the reason is an
/// exclusion, [`ResolveError::ExcludedButRequired`] names the excluded package,
/// since that is the actionable fact; otherwise
/// [`ResolveError::Unsatisfiable`] names the group and what is actually
/// available for it. Neither is dropped: dpkg runs with `--force-depends`, so
/// installing anyway would succeed and leave a root whose packages cannot work,
/// and the post-install check would not catch it — that check verifies the
/// packages that *were* selected, and a dropped dependency never is.
///
/// A group whose satisfier the base layer already supplies (`assume_installed`)
/// is satisfied by the base and pulls nothing, provided the base supplies it at
/// a version the constraint accepts.
fn resolve_group(
    index: &Index,
    group: &Dependency,
    excluded: &HashSet<&str>,
    assume_installed: &InstalledSet,
    required_by: &str,
    selected: &mut BTreeMap<String, Package>,
    queue: &mut VecDeque<String>,
) -> Result<(), ResolveError> {
    // An excluded package is never added to `selected`, so a satisfied check
    // over `selected` already ignores exclusions. The base's map carries both
    // its real names and the virtuals those packages provide, so one lookup
    // covers a group the base satisfies either way — and carries the versions,
    // so a constrained group is answered by the version actually there rather
    // than by the name being present.
    for atom in group {
        if base_satisfies(assume_installed, atom) || selected_satisfies(index, selected, atom) {
            return Ok(());
        }
    }
    // Try each alternative in order, preferring the real package named then a
    // provider — the resolver's existing discipline. Remember an excluded name
    // that would otherwise have satisfied the group, so a group left
    // unsatisfied solely by exclusion can be reported against it.
    let mut blocked: Option<String> = None;
    for atom in group {
        match index.get(&atom.name) {
            Some(package) if !excluded.contains(atom.name.as_str()) => {
                // The archive's candidate counts only if it actually meets the
                // constraint. When it does not, this alternative is no answer
                // and the search continues — a provider may still supply the
                // name at a version that is, and a later alternative may too.
                if meets(atom.constraint.as_ref(), &package.version) {
                    add(selected, queue, package);
                    return Ok(());
                }
            }
            // The real package is excluded. One name can be both a real package
            // and a virtual that others provide, so a provider may still
            // satisfy the group — which is what apt's own deselection does.
            // Fall through to the provider lookup, remembering the exclusion in
            // case nothing else answers.
            Some(_) => {
                blocked.get_or_insert_with(|| atom.name.clone());
            }
            None => {}
        }
        if let Some(provider) = first_available_provider(index, atom, excluded) {
            let package = index.get(&provider).expect("a provider is a real package");
            add(selected, queue, package);
            return Ok(());
        }
        // A virtual whose every provider is excluded: record the first, so an
        // all-excluded alternative group is reported rather than silently
        // dropped.
        if let Some(provider) = index
            .providers(&atom.name)
            .iter()
            .find(|provider| excluded.contains(provider.as_str()))
        {
            blocked.get_or_insert_with(|| provider.clone());
        }
    }
    match blocked {
        Some(package) => Err(ResolveError::ExcludedButRequired {
            package,
            required_by: required_by.to_string(),
        }),
        // Nothing was excluded, and nothing satisfies the group: the archive
        // offers none of these names, or offers them only at versions the
        // constraint rules out. Either way the closure is incomplete, and
        // shipping it would produce a root whose packages cannot work.
        None => Err(ResolveError::Unsatisfiable {
            requirement: render_group(group),
            required_by: required_by.to_string(),
            available: describe_available(index, assume_installed, group),
        }),
    }
}

/// Whether `version` meets `constraint`. An absent constraint is met by any
/// version, which is what an unversioned dependency asks.
fn meets(constraint: Option<&Constraint>, version: &str) -> bool {
    constraint.is_none_or(|c| c.satisfied_by(version))
}

/// Whether the base layer supplies `atom` — the name, at a version its
/// constraint accepts.
///
/// A bare `Provides` records `None`, which supplies only an unversioned
/// dependency: Policy 7.5 gives an unversioned provide no version to compare,
/// so it cannot answer a versioned question.
fn base_satisfies(assume_installed: &InstalledSet, atom: &DepAtom) -> bool {
    let Some(versions) = assume_installed.get(&atom.name) else {
        return false;
    };
    match atom.constraint.as_ref() {
        None => true,
        Some(constraint) => versions.iter().any(|version| {
            version
                .as_deref()
                .is_some_and(|v| constraint.satisfied_by(v))
        }),
    }
}

/// Whether the already-selected packages satisfy `atom`, by real name or by a
/// selected package's `Provides`.
fn selected_satisfies(index: &Index, selected: &BTreeMap<String, Package>, atom: &DepAtom) -> bool {
    if let Some(package) = selected.get(&atom.name)
        && meets(atom.constraint.as_ref(), &package.version)
    {
        return true;
    }
    index.providers(&atom.name).iter().any(|provider| {
        selected
            .get(provider)
            .is_some_and(|package| provides_satisfies(package, atom))
    })
}

/// Whether `package`'s `Provides` supplies `atom`'s name at a version the
/// constraint accepts.
fn provides_satisfies(package: &Package, atom: &DepAtom) -> bool {
    package
        .provides
        .iter()
        .filter(|provided| provided.name == atom.name)
        .any(|provided| match atom.constraint.as_ref() {
            None => true,
            Some(constraint) => provided
                .version
                .as_deref()
                .is_some_and(|v| constraint.satisfied_by(v)),
        })
}

/// Renders a dependency group the way the archive declares it, so the error
/// names what was asked for rather than a reconstruction of it.
fn render_group(group: &Dependency) -> String {
    group
        .iter()
        .map(|atom| match atom.constraint.as_ref() {
            Some(constraint) => format!("{} ({constraint})", atom.name),
            None => atom.name.clone(),
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

/// What is actually available for a group's names, for the error's evidence
/// line: the archive's version, or the base's, whichever exists.
///
/// This is what separates the two failures a reader has to tell apart — a name
/// no archive carries, and a name carried at the wrong version. `None` when the
/// group's names are simply absent everywhere.
fn describe_available(
    index: &Index,
    assume_installed: &InstalledSet,
    group: &Dependency,
) -> Option<String> {
    let mut found: Vec<String> = Vec::new();
    for atom in group {
        if let Some(package) = index.get(&atom.name) {
            found.push(format!("{} {} in the archive", atom.name, package.version));
        }
        if let Some(versions) = assume_installed.get(&atom.name) {
            let rendered: Vec<&str> = versions
                .iter()
                .map(|v| v.as_deref().unwrap_or("no version"))
                .collect();
            found.push(format!(
                "{} {} in the base layer",
                atom.name,
                rendered.join(", ")
            ));
        }
    }
    (!found.is_empty()).then(|| found.join("; "))
}

/// The first provider of `atom`'s virtual name that is not excluded and that
/// supplies it at a version the constraint accepts, or `None` when no provider
/// qualifies. Providers are held in sorted order, so the choice is
/// deterministic.
fn first_available_provider(
    index: &Index,
    atom: &DepAtom,
    excluded: &HashSet<&str>,
) -> Option<String> {
    index
        .providers(&atom.name)
        .iter()
        .find(|provider| {
            !excluded.contains(provider.as_str())
                && index
                    .get(provider)
                    .is_some_and(|package| provides_satisfies(package, atom))
        })
        .cloned()
}

/// Adds a package to the selection and the work queue if new.
fn add(selected: &mut BTreeMap<String, Package>, queue: &mut VecDeque<String>, package: &Package) {
    if !selected.contains_key(&package.name) {
        selected.insert(package.name.clone(), package.clone());
        queue.push_back(package.name.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::super::index::Priority;
    use super::*;

    fn index(text: &str) -> Index {
        Index::parse(text, "amd64")
    }

    fn names(packages: &[Package]) -> Vec<String> {
        packages.iter().map(|p| p.name.clone()).collect()
    }

    fn stanza(name: &str, deps: &str, extra: &str) -> String {
        // A deterministic, per-name stand-in for a real SHA-256: the name's
        // bytes in hex, padded to the 64 lowercase hex characters the index
        // parser now requires.
        let mut sha256: String = name.bytes().map(|b| format!("{b:02x}")).collect();
        sha256.truncate(64);
        while sha256.len() < 64 {
            sha256.push('0');
        }
        let mut text = format!(
            "Package: {name}\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/{name}.deb\n\
             Size: 1\nSHA256: {sha256}\nDepends: {deps}\n"
        );
        if !extra.is_empty() {
            text.push_str(extra);
            text.push('\n');
        }
        // A blank line terminates the stanza.
        text.push('\n');
        text
    }

    #[test]
    fn closure_follows_depends_and_pre_depends() {
        let text = format!(
            "{}{}{}",
            stanza("a", "b", "Pre-Depends: c"),
            stanza("b", "", ""),
            stanza("c", "", ""),
        );
        let selected = resolve(&index(&text), &["a".into()], &[], &[]).unwrap();
        assert_eq!(names(&selected), ["a", "b", "c"]);
    }

    #[test]
    fn first_alternative_is_taken() {
        let text = format!(
            "{}{}{}",
            stanza("a", "x | y", ""),
            stanza("x", "", ""),
            stanza("y", "", "")
        );
        let selected = resolve(&index(&text), &["a".into()], &[], &[]).unwrap();
        assert_eq!(names(&selected), ["a", "x"]);
    }

    #[test]
    fn virtual_prefers_an_already_selected_provider() {
        // base pre-depends on the virtual `awk`; mawk (a provider) is in the
        // base seed, so the alternative is satisfied without pulling gawk.
        let text = format!(
            "{}{}{}",
            stanza("base", "awk", ""),
            stanza("mawk", "", "Provides: awk\nPriority: required"),
            stanza("gawk", "", "Provides: awk"),
        );
        let index = index(&text);
        let selected = resolve(
            &index,
            &index.base_seed(Priority::Required),
            &["base".into()],
            &[],
        )
        .unwrap();
        assert_eq!(names(&selected), ["base", "mawk"]);
    }

    #[test]
    fn two_packages_a_real_archive_conflicts_both_enter_the_closure() {
        // The resolver reads Depends, Pre-Depends, and Provides, and no other
        // relation: a coherent suite is internally consistent, and dpkg runs
        // with --force-depends. So Conflicts and Replaces are not consulted, and
        // a closure can legitimately hold two packages a real archive expects
        // never to be unpacked together.
        //
        // Pinned because it is what makes a duplicate statoverride reachable
        // without anything malformed — two selected packages shipping one path.
        // The collapsing is the accumulator's job, not the resolver's, and it
        // has to stay that way while this rule holds.
        let text = format!(
            "{}{}{}",
            stanza("base", "left, right", ""),
            stanza("left", "", "Conflicts: right\nReplaces: right"),
            stanza("right", "", "Conflicts: left\nReplaces: left"),
        );
        let selected = resolve(&index(&text), &["base".into()], &[], &[]).unwrap();
        assert_eq!(names(&selected), ["base", "left", "right"]);
    }

    #[test]
    fn an_unknown_include_is_an_error() {
        let text = stanza("a", "", "");
        let err = resolve(&index(&text), &[], &["nonesuch".into()], &[]).unwrap_err();
        assert!(matches!(err, ResolveError::PackageNotFound { name } if name == "nonesuch"));
    }

    #[test]
    fn a_cycle_terminates() {
        let text = format!("{}{}", stanza("a", "b", ""), stanza("b", "a", ""));
        let selected = resolve(&index(&text), &["a".into()], &[], &[]).unwrap();
        assert_eq!(names(&selected), ["a", "b"]);
    }

    #[test]
    fn an_exclude_drops_a_seed_package() {
        // A package named in the seed is left out when excluded, and nothing it
        // alone would have pulled comes along either.
        let text = format!("{}{}", stanza("keep", "", ""), stanza("drop", "", ""));
        let selected = resolve(
            &index(&text),
            &["keep".into(), "drop".into()],
            &[],
            &["drop".into()],
        )
        .unwrap();
        assert_eq!(names(&selected), ["keep"]);
    }

    #[test]
    fn an_exclude_selects_the_other_alternative() {
        // `a` depends on `x | y`; excluding `x` resolves the group to `y`
        // rather than pulling the excluded first alternative.
        let text = format!(
            "{}{}{}",
            stanza("a", "x | y", ""),
            stanza("x", "", ""),
            stanza("y", "", ""),
        );
        let selected = resolve(&index(&text), &["a".into()], &[], &["x".into()]).unwrap();
        assert_eq!(names(&selected), ["a", "y"]);
    }

    #[test]
    fn an_excluded_hard_dependency_is_refused() {
        // `a` depends on `x` with no alternative; excluding `x` would leave the
        // dependency unmet, so the resolution fails naming both packages.
        let text = format!("{}{}", stanza("a", "x", ""), stanza("x", "", ""));
        let err = resolve(&index(&text), &["a".into()], &[], &["x".into()]).unwrap_err();
        assert!(matches!(
            err,
            ResolveError::ExcludedButRequired { package, required_by }
                if package == "x" && required_by == "a"
        ));
    }

    #[test]
    fn an_exclude_defers_to_a_virtual_provider() {
        // `a` depends on the virtual `awk`, provided by both gawk and mawk.
        // Providers are held sorted, so gawk is the default pick; excluding it
        // resolves the group through mawk, proving the exclusion redirected the
        // choice rather than the default coinciding with it.
        let text = format!(
            "{}{}{}",
            stanza("a", "awk", ""),
            stanza("gawk", "", "Provides: awk"),
            stanza("mawk", "", "Provides: awk"),
        );
        let selected = resolve(&index(&text), &["a".into()], &[], &["gawk".into()]).unwrap();
        assert_eq!(names(&selected), ["a", "mawk"]);
    }

    #[test]
    fn an_include_that_is_also_excluded_is_refused() {
        let text = stanza("a", "", "");
        let err = resolve(&index(&text), &[], &["a".into()], &["a".into()]).unwrap_err();
        assert!(matches!(
            err,
            ResolveError::ExcludedAndIncluded { name } if name == "a"
        ));
    }

    /// [`stanza`] at a chosen version, for the cases where the archive's
    /// version is what decides the outcome.
    fn stanza_at(name: &str, version: &str, deps: &str, extra: &str) -> String {
        stanza(name, deps, extra).replace("\nVersion: 1.0\n", &format!("\nVersion: {version}\n"))
    }

    /// The `Unsatisfiable` rendering of a failed resolve, or a panic naming
    /// what came back instead.
    fn unsatisfiable(result: Result<Vec<Package>, ResolveError>) -> String {
        match result {
            Err(err @ ResolveError::Unsatisfiable { .. }) => err.to_string(),
            Err(other) => panic!("expected Unsatisfiable, got {other}"),
            Ok(packages) => panic!("expected Unsatisfiable, resolved {:?}", names(&packages)),
        }
    }

    /// Builds an assume-installed set from names, each supplied at version
    /// `1.0` — the version the test stanzas use, so an unconstrained test reads
    /// exactly as it did before versions were enforced.
    fn assumed(names: &[&str]) -> InstalledSet {
        names
            .iter()
            .map(|name| ((*name).to_string(), vec![Some("1.0".to_string())]))
            .collect()
    }

    /// Builds an assume-installed set from explicit `(name, version)` pairs,
    /// for the cases where the base's version is the thing under test.
    fn assumed_at(entries: &[(&str, &str)]) -> InstalledSet {
        let mut set = InstalledSet::new();
        for (name, version) in entries {
            set.entry((*name).to_string())
                .or_default()
                .push(Some((*version).to_string()));
        }
        set
    }

    #[test]
    fn an_assumed_dependency_is_not_reselected() {
        // `a` depends on `b`; the base already carries `b`, so resolving the
        // increment selects only `a` and leaves `b` to the base.
        let text = format!("{}{}", stanza("a", "b", ""), stanza("b", "", ""));
        let selected =
            resolve_seeded(&index(&text), &[], &["a".into()], &[], &assumed(&["b"])).unwrap();
        assert_eq!(names(&selected), ["a"]);
    }

    #[test]
    fn an_assumed_virtual_satisfies_a_dependency() {
        // `a` depends on the virtual `awk`; the base carries a provider, so the
        // base's set includes the virtual name and the group is satisfied without
        // pulling any provider into the increment.
        let text = format!(
            "{}{}",
            stanza("a", "awk", ""),
            stanza("gawk", "", "Provides: awk"),
        );
        let selected = resolve_seeded(
            &index(&text),
            &[],
            &["a".into()],
            &[],
            &assumed(&["gawk", "awk"]),
        )
        .unwrap();
        assert_eq!(names(&selected), ["a"]);
    }

    #[test]
    fn an_assumed_include_selects_nothing() {
        // A requested package the base already supplies is satisfied by the base:
        // the increment is empty.
        let text = stanza("a", "", "");
        let selected =
            resolve_seeded(&index(&text), &[], &["a".into()], &[], &assumed(&["a"])).unwrap();
        assert!(selected.is_empty());
    }

    #[test]
    fn only_the_assumed_dependency_is_omitted() {
        // `a` depends on `b` and `c`; the base carries `b` but not `c`, so the
        // increment is `a` and `c` — the assume-installed set omits exactly what
        // the base supplies and no more.
        let text = format!(
            "{}{}{}",
            stanza("a", "b, c", ""),
            stanza("b", "", ""),
            stanza("c", "", ""),
        );
        let selected =
            resolve_seeded(&index(&text), &[], &["a".into()], &[], &assumed(&["b"])).unwrap();
        assert_eq!(names(&selected), ["a", "c"]);
    }

    #[test]
    fn a_dependency_nothing_offers_is_reported_rather_than_dropped() {
        // The libicu76 shape: a package depends on a name no configured archive
        // carries. Installing anyway succeeds under --force-depends and leaves a
        // root whose apt is wedged, so the resolve refuses instead.
        let text = stanza("jellyfin-server", "libicu76", "");
        let rendered = unsatisfiable(resolve(
            &index(&text),
            &[],
            &["jellyfin-server".into()],
            &[],
        ));
        assert!(rendered.contains("jellyfin-server"), "{rendered}");
        assert!(rendered.contains("libicu76"), "{rendered}");
        assert!(
            rendered.contains("no configured archive"),
            "an absent name is distinguished from a wrong version: {rendered}",
        );
    }

    #[test]
    fn a_base_too_old_for_a_constraint_is_reported_with_both_versions() {
        // The libglib2.0-0t64 / libc6 shape, and the one a name-only check
        // cannot catch: the base HAS the package, at a version the constraint
        // rules out. Before versions were enforced this resolved clean and the
        // failure surfaced an hour later as a link error.
        let text = stanza("libglib2.0-0t64", "libc6 (>= 2.43)", "");
        let rendered = unsatisfiable(resolve_seeded(
            &index(&text),
            &[],
            &["libglib2.0-0t64".into()],
            &[],
            &assumed_at(&[("libc6", "2.42-17")]),
        ));
        assert!(rendered.contains("libc6 (>= 2.43)"), "{rendered}");
        assert!(
            rendered.contains("2.42-17"),
            "the error carries what is actually installed: {rendered}",
        );
    }

    #[test]
    fn a_base_new_enough_for_a_constraint_satisfies_it() {
        // The other side of the same test: the constraint is met, so the
        // increment closes over nothing extra and the base answers the group.
        let text = stanza("libglib2.0-0t64", "libc6 (>= 2.43)", "");
        let selected = resolve_seeded(
            &index(&text),
            &[],
            &["libglib2.0-0t64".into()],
            &[],
            &assumed_at(&[("libc6", "2.43-3")]),
        )
        .expect("the base satisfies the constraint");
        assert_eq!(names(&selected), ["libglib2.0-0t64"]);
    }

    #[test]
    fn the_archives_own_version_must_meet_the_constraint_too() {
        // Enforcement is not only about the base. An archive that carries the
        // name at too old a version does not satisfy a constrained dependency
        // on it either.
        let text = format!(
            "{}{}",
            stanza("app", "libfoo (>= 2.0)", ""),
            stanza_at("libfoo", "1.9", "", "")
        );
        let rendered = unsatisfiable(resolve(&index(&text), &[], &["app".into()], &[]));
        assert!(rendered.contains("libfoo (>= 2.0)"), "{rendered}");
        assert!(
            rendered.contains("1.9 in the archive"),
            "the error says what the archive actually offers: {rendered}",
        );
    }

    #[test]
    fn a_later_alternative_answers_what_the_first_ones_version_cannot() {
        // An `a | b` group where `a` exists but is too old: the group is not
        // failed on the first alternative, since `b` still satisfies it.
        let text = format!(
            "{}{}{}",
            stanza("app", "libfoo (>= 2.0) | libbar", ""),
            stanza_at("libfoo", "1.9", "", ""),
            stanza("libbar", "", "")
        );
        let selected =
            resolve(&index(&text), &[], &["app".into()], &[]).expect("the alternative resolves");
        assert_eq!(names(&selected), ["app", "libbar"]);
    }

    #[test]
    fn a_bare_provides_does_not_satisfy_a_versioned_dependency() {
        // Policy 7.5: an unversioned Provides has no version to compare, so it
        // answers an unversioned dependency and no versioned one.
        let text = format!(
            "{}{}",
            stanza("app", "libfoo (>= 2.0)", ""),
            stanza("libfoo-impl", "", "Provides: libfoo")
        );
        let rendered = unsatisfiable(resolve(&index(&text), &[], &["app".into()], &[]));
        assert!(rendered.contains("libfoo (>= 2.0)"), "{rendered}");
    }

    #[test]
    fn a_versioned_provides_satisfies_a_constraint_it_meets() {
        // And the converse: `Provides: libfoo (= 2.1)` does answer `>= 2.0`.
        let text = format!(
            "{}{}",
            stanza("app", "libfoo (>= 2.0)", ""),
            stanza("libfoo-impl", "", "Provides: libfoo (= 2.1)")
        );
        let selected =
            resolve(&index(&text), &[], &["app".into()], &[]).expect("the provider satisfies it");
        assert_eq!(names(&selected), ["app", "libfoo-impl"]);
    }

    #[test]
    fn a_bare_provides_still_satisfies_an_unversioned_dependency() {
        // The common case must not regress: `Depends: awk` is answered by
        // `Provides: awk` exactly as before.
        let text = format!(
            "{}{}",
            stanza("app", "awk", ""),
            stanza("mawk", "", "Provides: awk")
        );
        let selected =
            resolve(&index(&text), &[], &["app".into()], &[]).expect("the virtual resolves");
        assert_eq!(names(&selected), ["app", "mawk"]);
    }

    #[test]
    fn an_exclusion_is_still_reported_as_an_exclusion() {
        // The new error must not swallow the older, more specific one: a group
        // left unsatisfiable purely by an exclusion still names the exclusion.
        let text = format!(
            "{}{}",
            stanza("app", "libfoo", ""),
            stanza("libfoo", "", "")
        );
        let err = resolve(&index(&text), &[], &["app".into()], &["libfoo".into()])
            .expect_err("the exclusion breaks a hard dependency");
        assert!(
            matches!(err, ResolveError::ExcludedButRequired { .. }),
            "got {err}",
        );
    }
}
