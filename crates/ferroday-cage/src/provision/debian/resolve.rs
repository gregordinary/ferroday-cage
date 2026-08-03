//! Dependency resolution: the install closure over a package index.
//!
//! From a seed set the resolver closes over `Depends` and `Pre-Depends`,
//! following `debootstrap`'s discipline: the first satisfiable alternative of
//! an `a | b` group, virtual packages satisfied by preferring an
//! already-selected provider, version constraints trusted rather than
//! enforced (a single suite is internally consistent). The result is the set
//! of real packages to download and install.

use std::collections::{BTreeMap, HashSet, VecDeque};

use super::index::{Dependency, Index, Package};

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
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    resolve_seeded(index, base, includes, excludes, &HashSet::new())
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
    assume_installed: &HashSet<String>,
) -> Result<Vec<Package>, ResolveError> {
    let excluded: HashSet<&str> = excludes.iter().map(String::as_str).collect();
    let mut selected: BTreeMap<String, Package> = BTreeMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    // Seed the whole base set before closing over anything, so a virtual
    // dependency encountered during the closure sees every base package as an
    // already-selected candidate provider. An excluded base package is simply
    // not seeded, and one the layer already carries is left to the base.
    for name in base {
        if excluded.contains(name.as_str()) || assume_installed.contains(name) {
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
        if assume_installed.contains(name) {
            continue;
        }
        if let Some(package) = index.get(name) {
            add(&mut selected, &mut queue, package);
        } else if let Some(provider) = first_available_provider(index, name, &excluded) {
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
/// than failing the group. A group left unsatisfiable
/// purely because its every satisfier is excluded fails the resolution: the
/// exclusion would break a hard dependency, which is refused rather than
/// shipped broken. A group unsatisfiable for reasons unrelated to exclusion is
/// dropped, as dpkg runs with `--force-depends` and the post-install check
/// catches a genuinely missing dependency by name. A group whose satisfier the
/// base layer already supplies (`assume_installed`) is satisfied by the base and
/// pulls nothing.
fn resolve_group(
    index: &Index,
    group: &Dependency,
    excluded: &HashSet<&str>,
    assume_installed: &HashSet<String>,
    required_by: &str,
    selected: &mut BTreeMap<String, Package>,
    queue: &mut VecDeque<String>,
) -> Result<(), ResolveError> {
    // An excluded package is never added to `selected`, so a satisfied check
    // over `selected` already ignores exclusions. The base's set carries both
    // its real names and the virtuals those packages provide, so one membership
    // test covers a group the base satisfies either way.
    for atom in group {
        if selected.contains_key(&atom.name)
            || assume_installed.contains(&atom.name)
            || index
                .providers(&atom.name)
                .iter()
                .any(|provider| selected.contains_key(provider))
        {
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
                add(selected, queue, package);
                return Ok(());
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
        if let Some(provider) = first_available_provider(index, &atom.name, excluded) {
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
        None => Ok(()),
    }
}

/// The first provider of the virtual package `name` that is not excluded, or
/// `None` when `name` has no provider or every provider is excluded. Providers
/// are held in sorted order, so the choice is deterministic.
fn first_available_provider(index: &Index, name: &str, excluded: &HashSet<&str>) -> Option<String> {
    index
        .providers(name)
        .iter()
        .find(|provider| !excluded.contains(provider.as_str()))
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

    /// Builds an assume-installed set from names.
    fn assumed(names: &[&str]) -> HashSet<String> {
        names.iter().map(|name| name.to_string()).collect()
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
}
