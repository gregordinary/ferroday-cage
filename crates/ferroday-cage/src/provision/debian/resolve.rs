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
//!
//! Every such refusal is collected and reported, and the resolution fails once
//! with all of them named. A caller correcting an install list wants the whole
//! list of what the archive cannot give them; learning them one run at a time
//! turns one correction into as many bootstraps as there are mistakes.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;

use super::index::{DepAtom, Dependency, Index, Package};
use super::layer::InstalledSet;
use super::version::Constraint;

/// Who asked for something the resolver was not walking a dependency for: the
/// caller's own install list.
///
/// Gentoo's resolver names the same party the same way, so a consumer reading
/// refusals from either layer meets one phrase rather than two.
const THE_INSTALL_LIST: &str = "the install list";

/// A dependency the resolver could not satisfy.
///
/// One refusal, not the whole of a failure. A resolution collects every one it
/// meets into [`Refusals`] and fails once at the end, so a caller fixing an
/// install list sees the whole list rather than the first entry of it.
#[derive(Debug)]
pub(crate) enum Refusal {
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

impl Refusal {
    /// What could not be supplied: the dependency group as the archive declares
    /// it, or the package name where the caller named one directly.
    pub(crate) fn requirement(&self) -> &str {
        match self {
            Refusal::PackageNotFound { name } | Refusal::ExcludedAndIncluded { name } => name,
            Refusal::ExcludedButRequired { package, .. } => package,
            Refusal::Unsatisfiable { requirement, .. } => requirement,
        }
    }

    /// Who asked for it: the selected package whose dependency it was, or
    /// [`THE_INSTALL_LIST`] where the caller asked directly.
    pub(crate) fn required_by(&self) -> &str {
        match self {
            Refusal::PackageNotFound { .. } | Refusal::ExcludedAndIncluded { .. } => {
                THE_INSTALL_LIST
            }
            Refusal::ExcludedButRequired { required_by, .. }
            | Refusal::Unsatisfiable { required_by, .. } => required_by,
        }
    }

    /// What the wall was, as the clause following "and": the half of the
    /// refusal the other two accessors do not already carry.
    pub(crate) fn reason(&self) -> String {
        match self {
            Refusal::PackageNotFound { .. } => "it is not in the index".to_string(),
            Refusal::ExcludedAndIncluded { .. } => "it is both included and excluded".to_string(),
            Refusal::ExcludedButRequired { .. } => "it is excluded".to_string(),
            Refusal::Unsatisfiable { available, .. } => match available {
                Some(available) => format!("nothing satisfies it (available: {available})"),
                None => "no configured archive offers it and no base layer supplies it".to_string(),
            },
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} requires `{}`, and {}",
            self.required_by(),
            self.requirement(),
            self.reason(),
        )
    }
}

/// Everything one resolution refused, in the order it met them.
///
/// Debian's own rather than Gentoo's `Refusals`, which is the same idea under
/// the same name in the same position. The two are deliberately separate: a
/// portage resolution refuses in three shapes — an atom nothing answers, a
/// blocker, and two builds contending for one slot — and the last two are
/// portage concepts with no Debian meaning, so a shared type would carry two
/// collections that are always empty here. What the layers share is the
/// discipline, not the vocabulary, and `CONTRIBUTING.md`'s shared-vocabulary
/// table records the split.
#[derive(Debug, Default)]
pub(crate) struct Refusals {
    refused: Vec<Refusal>,
}

impl Refusals {
    /// Records one refusal.
    fn push(&mut self, refusal: Refusal) {
        self.refused.push(refusal);
    }

    /// Whether the resolution can be acted on.
    pub(crate) fn is_empty(&self) -> bool {
        self.refused.is_empty()
    }

    /// Every refusal, in the order the resolution met them.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Refusal> {
        self.refused.iter()
    }

    /// The whole refusal as one sentence a caller reads.
    pub(crate) fn describe(&self) -> String {
        self.refused
            .iter()
            .map(Refusal::to_string)
            .collect::<Vec<_>>()
            .join("; ")
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
/// instead. A hard dependency an exclusion leaves unsatisfiable refuses the
/// resolution rather than shipping a broken closure, and a package that is both
/// included and excluded is a contradiction that refuses likewise. The returned
/// packages are sorted by name.
pub(crate) fn resolve(
    index: &Index,
    base: &[String],
    includes: &[String],
    excludes: &[String],
) -> (Vec<Package>, Refusals) {
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
///
/// # Refusals
///
/// The walk continues past a refusal rather than returning at it, so the
/// returned [`Refusals`] holds every one the resolution met. A group nothing
/// satisfies contributes nothing to the selection, which is what makes
/// continuing possible: the closure below it was never reachable anyway, and
/// the rest of the walk is unaffected. The caller reports each refusal and then
/// fails; a non-empty `Refusals` means the returned packages are an incomplete
/// closure and must not be installed.
///
/// A refusal cannot cascade here the way it can in a resolver that drops the
/// package that asked. A package whose dependency is refused stays selected and
/// its other groups still resolve, so nothing downstream of it is refused *for
/// that reason*. Two packages needing one absent name produce two refusals,
/// which is the fact rather than noise: both have to change.
///
/// A contradiction in the caller's own arguments — a name that is neither a
/// package nor a virtual, a name both included and excluded — is collected
/// alongside the rest rather than returned immediately. It is discovered
/// before the closure walk rather than during it, but a caller correcting an
/// install list of twenty names wants all four mistakes, not the first, and
/// that is the same reason the walk collects.
pub(crate) fn resolve_seeded(
    index: &Index,
    base: &[String],
    includes: &[String],
    excludes: &[String],
    assume_installed: &InstalledSet,
) -> (Vec<Package>, Refusals) {
    let excluded: HashSet<&str> = excludes.iter().map(String::as_str).collect();
    let mut selected: BTreeMap<String, Package> = BTreeMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut refusals = Refusals::default();

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
            refusals.push(Refusal::ExcludedAndIncluded { name: name.clone() });
            continue;
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
            refusals.push(Refusal::PackageNotFound { name: name.clone() });
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
            if let Some(refusal) = resolve_group(
                index,
                group,
                &excluded,
                assume_installed,
                &name,
                &mut selected,
                &mut queue,
            ) {
                refusals.push(refusal);
            }
        }
    }

    (selected.into_values().collect(), refusals)
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
/// A group nothing satisfies is refused, and the refusal returned for the
/// caller to collect. Where the reason is an exclusion,
/// [`Refusal::ExcludedButRequired`] names the excluded package, since that is
/// the actionable fact; otherwise [`Refusal::Unsatisfiable`] names the group
/// and what is actually available for it. Neither is dropped: dpkg runs with
/// `--force-depends`, so installing anyway would succeed and leave a root whose
/// packages cannot work, and the post-install check would not catch it — that
/// check verifies the packages that *were* selected, and a dropped dependency
/// never is.
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
) -> Option<Refusal> {
    // An excluded package is never added to `selected`, so a satisfied check
    // over `selected` already ignores exclusions. The base's map carries both
    // its real names and the virtuals those packages provide, so one lookup
    // covers a group the base satisfies either way — and carries the versions,
    // so a constrained group is answered by the version actually there rather
    // than by the name being present.
    for atom in group {
        if base_satisfies(assume_installed, atom) || selected_satisfies(index, selected, atom) {
            return None;
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
                    return None;
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
            return None;
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
        Some(package) => Some(Refusal::ExcludedButRequired {
            package,
            required_by: required_by.to_string(),
        }),
        // Nothing was excluded, and nothing satisfies the group: the archive
        // offers none of these names, or offers them only at versions the
        // constraint rules out. Either way the closure is incomplete, and
        // shipping it would produce a root whose packages cannot work.
        None => Some(Refusal::Unsatisfiable {
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

    /// What a test reads out of a resolution, so that every test states which
    /// of the two outcomes it is about rather than destructuring the pair.
    ///
    /// A resolution now always returns packages *and* refusals, so a test that
    /// only looked at the packages would pass while the resolution refused
    /// everything it was asked for.
    trait Resolution {
        /// The selected packages, asserting the resolution refused nothing.
        fn into_packages(self) -> Vec<Package>;
        /// The same, naming what the test expected in the panic.
        fn expecting(self, what: &str) -> Vec<Package>;
        /// The one refusal a test about a single failure pins.
        fn into_refusal(self) -> Refusal;
    }

    impl Resolution for (Vec<Package>, Refusals) {
        fn into_packages(self) -> Vec<Package> {
            self.expecting("the resolution to succeed")
        }

        fn expecting(self, what: &str) -> Vec<Package> {
            let (packages, refusals) = self;
            assert!(
                refusals.is_empty(),
                "expected {what}, and it refused: {}",
                refusals.describe(),
            );
            packages
        }

        fn into_refusal(self) -> Refusal {
            let (packages, refusals) = self;
            let mut refused: Vec<Refusal> = refusals.refused;
            match refused.len() {
                1 => refused.remove(0),
                0 => panic!("expected a refusal, resolved {:?}", names(&packages)),
                _ => panic!(
                    "expected exactly one refusal, got {}: {}",
                    refused.len(),
                    Refusals { refused }.describe(),
                ),
            }
        }
    }

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
        let selected = resolve(&index(&text), &["a".into()], &[], &[]).into_packages();
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
        let selected = resolve(&index(&text), &["a".into()], &[], &[]).into_packages();
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
        .into_packages();
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
        let selected = resolve(&index(&text), &["base".into()], &[], &[]).into_packages();
        assert_eq!(names(&selected), ["base", "left", "right"]);
    }

    #[test]
    fn an_unknown_include_is_an_error() {
        let text = stanza("a", "", "");
        let err = resolve(&index(&text), &[], &["nonesuch".into()], &[]).into_refusal();
        assert!(matches!(err, Refusal::PackageNotFound { name } if name == "nonesuch"));
    }

    #[test]
    fn a_cycle_terminates() {
        let text = format!("{}{}", stanza("a", "b", ""), stanza("b", "a", ""));
        let selected = resolve(&index(&text), &["a".into()], &[], &[]).into_packages();
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
        .into_packages();
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
        let selected = resolve(&index(&text), &["a".into()], &[], &["x".into()]).into_packages();
        assert_eq!(names(&selected), ["a", "y"]);
    }

    #[test]
    fn an_excluded_hard_dependency_is_refused() {
        // `a` depends on `x` with no alternative; excluding `x` would leave the
        // dependency unmet, so the resolution fails naming both packages.
        let text = format!("{}{}", stanza("a", "x", ""), stanza("x", "", ""));
        let err = resolve(&index(&text), &["a".into()], &[], &["x".into()]).into_refusal();
        assert!(matches!(
            err,
            Refusal::ExcludedButRequired { package, required_by }
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
        let selected = resolve(&index(&text), &["a".into()], &[], &["gawk".into()]).into_packages();
        assert_eq!(names(&selected), ["a", "mawk"]);
    }

    #[test]
    fn an_include_that_is_also_excluded_is_refused() {
        let text = stanza("a", "", "");
        let err = resolve(&index(&text), &[], &["a".into()], &["a".into()]).into_refusal();
        assert!(matches!(
            err,
            Refusal::ExcludedAndIncluded { name } if name == "a"
        ));
    }

    /// [`stanza`] at a chosen version, for the cases where the archive's
    /// version is what decides the outcome.
    fn stanza_at(name: &str, version: &str, deps: &str, extra: &str) -> String {
        stanza(name, deps, extra).replace("\nVersion: 1.0\n", &format!("\nVersion: {version}\n"))
    }

    /// The `Unsatisfiable` rendering of a refused resolve, or a panic naming
    /// what came back instead.
    fn unsatisfiable(resolution: (Vec<Package>, Refusals)) -> String {
        match resolution.into_refusal() {
            refusal @ Refusal::Unsatisfiable { .. } => refusal.to_string(),
            other => panic!("expected Unsatisfiable, got {other}"),
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
        let selected = resolve_seeded(&index(&text), &[], &["a".into()], &[], &assumed(&["b"]))
            .into_packages();
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
        .into_packages();
        assert_eq!(names(&selected), ["a"]);
    }

    #[test]
    fn an_assumed_include_selects_nothing() {
        // A requested package the base already supplies is satisfied by the base:
        // the increment is empty.
        let text = stanza("a", "", "");
        let selected = resolve_seeded(&index(&text), &[], &["a".into()], &[], &assumed(&["a"]))
            .into_packages();
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
        let selected = resolve_seeded(&index(&text), &[], &["a".into()], &[], &assumed(&["b"]))
            .into_packages();
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
        .expecting("the base satisfies the constraint");
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
            resolve(&index(&text), &[], &["app".into()], &[]).expecting("the alternative resolves");
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
        let selected = resolve(&index(&text), &[], &["app".into()], &[])
            .expecting("the provider satisfies it");
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
            resolve(&index(&text), &[], &["app".into()], &[]).expecting("the virtual resolves");
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
        let err = resolve(&index(&text), &[], &["app".into()], &["libfoo".into()]).into_refusal();
        assert!(
            matches!(err, Refusal::ExcludedButRequired { .. }),
            "got {err}",
        );
    }

    #[test]
    fn every_unsatisfiable_group_is_reported_not_only_the_first() {
        // Three packages, each depending on a name no archive carries. Before
        // the walk collected, the first ended it and the caller learned about
        // libicu76 alone -- then fixed it, re-bootstrapped, and learned about
        // the second.
        let text = format!(
            "{}{}{}",
            stanza("first", "libicu76", ""),
            stanza("second", "libfoo77", ""),
            stanza("third", "libbar78", ""),
        );
        let (_, refusals) = resolve(
            &index(&text),
            &[],
            &["first".into(), "second".into(), "third".into()],
            &[],
        );
        assert_eq!(refusals.iter().count(), 3, "{}", refusals.describe());
        let described = refusals.describe();
        for absent in ["libicu76", "libfoo77", "libbar78"] {
            assert!(
                described.contains(absent),
                "{absent} is missing: {described}"
            );
        }
    }

    #[test]
    fn a_single_refusal_still_reads_as_one() {
        // The other side of collecting: one refusal describes as one sentence,
        // with no separator and nothing suggesting a list.
        let text = stanza("first", "libicu76", "");
        let (_, refusals) = resolve(&index(&text), &[], &["first".into()], &[]);
        assert_eq!(refusals.iter().count(), 1);
        assert!(
            !refusals.describe().contains("; "),
            "{}",
            refusals.describe()
        );
    }

    #[test]
    fn a_refused_group_does_not_stop_the_rest_of_the_walk() {
        // The property that makes collecting possible: a group nothing
        // satisfies contributes nothing to the selection, so everything the
        // walk had left to do is still done. `wanted` depends on both an absent
        // name and a present one, and the present one is still selected.
        let text = format!(
            "{}{}",
            stanza("wanted", "libicu76, present", ""),
            stanza("present", "", ""),
        );
        let (packages, refusals) = resolve(&index(&text), &[], &["wanted".into()], &[]);
        assert_eq!(refusals.iter().count(), 1, "{}", refusals.describe());
        assert_eq!(
            names(&packages),
            ["present", "wanted"],
            "the closure past the refusal is still walked",
        );
    }

    #[test]
    fn two_packages_needing_one_absent_name_are_two_refusals() {
        // Not deduplicated, because they are two facts: both packages have to
        // change, and a caller shown one of them would fix half the problem.
        let text = format!(
            "{}{}",
            stanza("first", "libicu76", ""),
            stanza("second", "libicu76", ""),
        );
        let (_, refusals) = resolve(&index(&text), &[], &["first".into(), "second".into()], &[]);
        assert_eq!(refusals.iter().count(), 2, "{}", refusals.describe());
        let asking: Vec<&str> = refusals.iter().map(Refusal::required_by).collect();
        assert_eq!(asking, ["first", "second"]);
    }

    #[test]
    fn a_contradicted_install_list_reports_every_contradiction() {
        // A caller's own mistakes collect the same way a dependency's do: an
        // install list of four names with three mistakes is corrected once.
        let text = format!("{}{}", stanza("real", "", ""), stanza("kept", "", ""));
        let (packages, refusals) = resolve(
            &index(&text),
            &[],
            &[
                "kept".into(),
                "nonesuch".into(),
                "alsomissing".into(),
                "real".into(),
            ],
            &["real".into()],
        );
        assert_eq!(refusals.iter().count(), 3, "{}", refusals.describe());
        assert_eq!(
            names(&packages),
            ["kept"],
            "the names that were fine are still selected",
        );
        let described = refusals.describe();
        for expected in ["nonesuch", "alsomissing", "real"] {
            assert!(described.contains(expected), "{expected}: {described}");
        }
    }

    #[test]
    fn a_refusal_names_who_asked_and_what_the_wall_was() {
        // The three parts the progress event carries, pinned here rather than
        // only through the sentence they compose into.
        let text = stanza("jellyfin-server", "libicu76 (>= 76)", "");
        let refusal = resolve(&index(&text), &[], &["jellyfin-server".into()], &[]).into_refusal();
        assert_eq!(refusal.requirement(), "libicu76 (>= 76)");
        assert_eq!(refusal.required_by(), "jellyfin-server");
        assert!(
            refusal.reason().contains("no configured archive"),
            "{}",
            refusal.reason(),
        );
        assert_eq!(
            refusal.to_string(),
            format!(
                "{} requires `{}`, and {}",
                refusal.required_by(),
                refusal.requirement(),
                refusal.reason(),
            ),
            "the sentence is composed from the parts, not written twice",
        );
    }

    #[test]
    fn an_install_list_refusal_names_the_install_list() {
        // A caller's own name has no requiring package, so it names the party
        // Gentoo's resolver names for the same case.
        let refusal = resolve(&index(""), &[], &["nonesuch".into()], &[]).into_refusal();
        assert_eq!(refusal.required_by(), THE_INSTALL_LIST);
        assert_eq!(refusal.requirement(), "nonesuch");
    }
}
