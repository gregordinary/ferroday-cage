//! Choosing what to install: which builds answer the caller's atoms, and in
//! what order they merge.
//!
//! The algorithm is deliberately predictable, and its whole value is that a
//! reader can say what it will do:
//!
//! 1. Seed a queue with the caller's atoms.
//! 2. An atom already satisfied — by the root's installed set, or by something
//!    the resolution has already chosen — is done.
//! 3. Otherwise take the index's builds of the atom's package that the atom
//!    admits, keep those at the highest version among them, and rank the rest.
//! 4. Queue the chosen build's `RDEPEND` and `PDEPEND`.
//! 5. An `|| ( ... )` group with a satisfied alternative is done; otherwise its
//!    first alternative with a viable candidate is taken.
//! 6. A blocker is checked against the finished set, and a match is a conflict.
//! 7. An atom nothing answers is unsatisfiable, and the refusal says which of
//!    the name, the version, the slot or a USE flag was the wall.
//!
//! # Which build, and why it decides the outcome
//!
//! The archive publishes a version more than once — 2,774 of them, up to
//! twenty-four times — and the builds differ in the USE flags they were
//! compiled with, and so in what they depend on. Choosing among them is
//! therefore not a tie-break. Measured over four hundred sampled package names
//! against an `amd64-openrc` stage3:
//!
//! | Rule | Resolves cleanly | Unsatisfiable atoms | Conflicts | p90 closure |
//! | --- | --- | --- | --- | --- |
//! | newest build time | 262/400 | 884 | 129 | 173 |
//! | fewest dependencies | 338/400 | 206 | 74 | 148 |
//! | fewest USE flags | 361/400 | 26 | 50 | 126 |
//!
//! Fewest USE flags wins every column at once, which is the argument for it: it
//! is not a trade. Portage makes the same choice from a profile's computed USE;
//! this layer has no profile, so it needs a rule of its own, and the rule is
//! the one the numbers chose.
//!
//! # A preference reorders; it cannot refuse
//!
//! A caller who needs a flag states it in the atom, where it is a constraint:
//! `dev-vcs/git[keyring]` removes every build without the flag, and if none is
//! left the atom is unsatisfiable and says so. A caller who has a taste states
//! it as a preference, which sorts the candidates and removes none — so it
//! cannot turn a resolvable request into an unresolvable one. Over the same
//! four hundred seeds the unsatisfiable count is 26 with no preference and 26
//! under every preference tried, including one broad enough to halve the clean
//! resolutions. What a broad preference costs is a larger closure, which meets
//! more of the archive's own conflicts.
//!
//! # No backtracking
//!
//! A conflict is reported rather than resolved around, on the evidence: an
//! any-of policy that preferred a non-conflicting alternative changed nothing
//! over the same four hundred seeds, and the conflicts that remain are ones
//! portage refuses too — a desktop stack asked for in a root built against the
//! other init system. Backtracking is additive if measurement later disagrees.

use std::collections::HashMap;

use super::atom::{Atom, Dependency, Unmet};
use super::index::{Index, Record};
use super::installed::Installed;
use super::version;

/// A USE flag the caller would rather a build carried, or rather it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Preference {
    /// The flag's name.
    flag: String,
    /// Whether the caller prefers it on or off.
    wanted: bool,
}

impl Preference {
    /// Reads one preference, `flag` or `-flag`.
    ///
    /// # Errors
    ///
    /// Returns the reason where the text does not name a flag.
    pub(super) fn parse(text: &str) -> Result<Preference, String> {
        let (wanted, flag) = match text.strip_prefix('-') {
            Some(flag) => (false, flag),
            None => (true, text),
        };
        if flag.is_empty()
            || !flag.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'_' | b'-' | b'@')
            })
        {
            return Err(format!("{text:?} does not name a USE flag"));
        }
        Ok(Preference {
            flag: flag.to_string(),
            wanted,
        })
    }

    /// Whether `record` is the way this preference would have it.
    fn met_by(&self, record: &Record) -> bool {
        record.has_use(&self.flag) == self.wanted
    }
}

/// What a resolution produced.
pub(super) struct Resolved {
    /// The chosen builds, in the order they merge.
    pub packages: Vec<Record>,
    /// Where a runtime-dependency cycle was broken, each naming the packages
    /// that formed it.
    pub cycles: Vec<Vec<String>>,
}

/// Why an atom could not be satisfied.
///
/// Carried out of the resolver so the wave can report each one before the run
/// fails, rather than a caller learning only that something did not resolve.
pub(super) struct Unsatisfied {
    /// The atom, as it was written.
    pub atom: String,
    /// Who asked for it: the caller, or the package whose dependency it is.
    pub wanted_by: String,
    /// What the wall was, in the sentence "no build ...".
    pub reason: String,
}

/// A blocker that matched something the root has or the resolution chose.
pub(super) struct Conflict {
    /// The blocker atom, as it was written.
    pub atom: String,
    /// The package that states it.
    pub stated_by: String,
    /// What it matched, as `category/name-version`.
    pub blocks: String,
    /// Whether what it matched is already in the root or would be installed.
    pub installed: bool,
}

/// Everything one resolution refused, in the order it met them.
#[derive(Default)]
pub(super) struct Refusals {
    pub unsatisfied: Vec<Unsatisfied>,
    pub conflicts: Vec<Conflict>,
}

impl Refusals {
    /// Whether the resolution can be acted on.
    pub(super) fn is_empty(&self) -> bool {
        self.unsatisfied.is_empty() && self.conflicts.is_empty()
    }

    /// The whole refusal as one sentence a caller reads.
    pub(super) fn describe(&self) -> String {
        let mut parts = Vec::new();
        for unmet in &self.unsatisfied {
            parts.push(format!(
                "{} requires {}, and no build {}",
                unmet.wanted_by, unmet.atom, unmet.reason,
            ));
        }
        for conflict in &self.conflicts {
            parts.push(format!(
                "{} blocks {} with {}, and {} would {}",
                conflict.stated_by,
                conflict.blocks,
                conflict.atom,
                conflict.blocks,
                if conflict.installed {
                    "have to be removed from the root first"
                } else {
                    "be installed by this same resolution"
                },
            ));
        }
        parts.join("; ")
    }
}

/// One atom waiting to be resolved, and who asked for it.
struct Pending {
    dependency: Dependency,
    wanted_by: String,
}

/// Resolves `wanted` against `index` and what `installed` already holds.
///
/// Reports every refusal rather than stopping at the first: a caller fixing an
/// install list wants the whole list of what the archive cannot give them, and
/// an atom nothing answers only stops the branch below it.
pub(super) fn resolve(
    index: &Index,
    installed: &Installed,
    wanted: &[Atom],
    prefer: &[Preference],
) -> (Resolved, Refusals) {
    let mut queue: Vec<Pending> = wanted
        .iter()
        .map(|atom| Pending {
            dependency: Dependency::One(atom.clone()),
            wanted_by: "the install list".to_string(),
        })
        .collect();
    // Reversed so the queue pops in the order the caller wrote them, which is
    // what makes a resolution reproducible from an install list rather than
    // from a set.
    queue.reverse();

    let mut chosen: Vec<Record> = Vec::new();
    let mut refusals = Refusals::default();
    // Blockers are collected and checked at the end rather than as they arrive:
    // a blocker met early would pass against a set the resolution had not
    // finished choosing, and the package it refuses may be chosen later.
    let mut blockers: Vec<(Atom, String)> = Vec::new();

    while let Some(pending) = queue.pop() {
        let alternatives: Vec<&Atom> = match &pending.dependency {
            Dependency::One(atom) => vec![atom],
            Dependency::AnyOf(atoms) => atoms.iter().collect(),
        };
        if let Some(atom) = alternatives.iter().find(|atom| atom.blocker().is_some()) {
            // A blocker inside an any-of group is one alternative among
            // several, and the group is satisfied by any of them; a blocker on
            // its own is a refusal to record.
            if alternatives.len() == 1 {
                blockers.push(((*atom).clone(), pending.wanted_by.clone()));
            }
            continue;
        }
        // Already answered, by the root or by something chosen: the whole
        // reason resolution here starts from a populated root.
        if alternatives
            .iter()
            .any(|atom| satisfied(atom, installed, &chosen))
        {
            continue;
        }
        // The first alternative anything can answer. A group of one is the
        // plain-atom case, so both go through one path.
        let picked = alternatives
            .iter()
            .find_map(|atom| select(index, atom, prefer));
        let Some(record) = picked else {
            refusals.unsatisfied.push(Unsatisfied {
                atom: alternatives
                    .iter()
                    .map(|atom| atom.to_string())
                    .collect::<Vec<_>>()
                    .join(" or "),
                wanted_by: pending.wanted_by,
                reason: wall(index, installed, &alternatives),
            });
            continue;
        };
        let wanted_by = record.cpv();
        for dependency in record.rdepend.iter().chain(&record.pdepend) {
            queue.push(Pending {
                dependency: dependency.clone(),
                wanted_by: wanted_by.clone(),
            });
        }
        chosen.push(record);
    }

    for (blocker, stated_by) in blockers {
        for package in installed.under(blocker.name()) {
            if blocker.matches(package) {
                refusals.conflicts.push(Conflict {
                    atom: blocker.to_string(),
                    stated_by: stated_by.clone(),
                    blocks: format!("{}-{}", package.name(), package.version()),
                    installed: true,
                });
            }
        }
        for record in chosen.iter().filter(|record| record.name == blocker.name()) {
            if blocker.matches(record) {
                refusals.conflicts.push(Conflict {
                    atom: blocker.to_string(),
                    stated_by: stated_by.clone(),
                    blocks: record.cpv(),
                    installed: false,
                });
            }
        }
    }

    let (packages, cycles) = order(chosen);
    (Resolved { packages, cycles }, refusals)
}

/// Whether anything already answers `atom`.
fn satisfied(atom: &Atom, installed: &Installed, chosen: &[Record]) -> bool {
    installed
        .under(atom.name())
        .any(|package| atom.matches(package))
        || chosen
            .iter()
            .any(|record| record.name == atom.name() && atom.matches(record))
}

/// The build to install for `atom`, or `None` where the index publishes none it
/// admits.
///
/// The highest version among the builds the atom admits, then the ranking the
/// module documentation defends. The atom's own USE dependencies have already
/// removed what they exclude, since they are part of admitting a build at all.
fn select(index: &Index, atom: &Atom, prefer: &[Preference]) -> Option<Record> {
    let admitted: Vec<&Record> = index
        .builds(atom.name())
        .filter(|record| atom.matches(*record))
        .collect();
    let highest = admitted.iter().copied().reduce(|best, candidate| {
        match version::compare(&candidate.version, &best.version) {
            Some(std::cmp::Ordering::Greater) => candidate,
            _ => best,
        }
    })?;
    admitted
        .into_iter()
        .filter(|record| record.version == highest.version)
        .max_by_key(|record| rank(record, prefer))
        .cloned()
}

/// How good a build is, greater being better.
///
/// The keys, in order: how many of the caller's preferences it meets, then how
/// few USE flags it carries, then how recently it was built, then its build id.
/// With no preference configured the first key is constant across the
/// candidates and the rule is the measured default exactly.
///
/// The build id is a final key rather than a real preference. Two builds of one
/// version can share a build time, and a resolution that chose between them by
/// iteration order would not be the same resolution twice.
fn rank(record: &Record, prefer: &[Preference]) -> (usize, std::cmp::Reverse<usize>, i64, u64) {
    let met = prefer
        .iter()
        .filter(|preference| preference.met_by(record))
        .count();
    (
        met,
        std::cmp::Reverse(record.use_count()),
        record.build_time,
        record.build_id,
    )
}

/// What stopped `alternatives`, in the sentence "no build ...".
///
/// The four walls are separated because they call for different answers: a name
/// the archive does not publish is a package to install another way, a flag no
/// build carries is a build nobody produced, and a slot or a version is a
/// request the archive has moved past.
fn wall(index: &Index, installed: &Installed, alternatives: &[&Atom]) -> String {
    let mut furthest: Option<Unmet> = None;
    let mut unpublished = Vec::new();
    for atom in alternatives {
        if !index.publishes(atom.name()) && !installed.holds(atom.name()) {
            unpublished.push(atom.name());
            continue;
        }
        for record in index.builds(atom.name()) {
            let unmet = atom.unmet_by(record);
            if furthest.is_none_or(|held| unmet.ordinal() > held.ordinal()) {
                furthest = Some(unmet);
            }
        }
    }
    match furthest {
        Some(unmet) => format!("published for it {}", unmet.describe()),
        None => format!(
            "of {} is published by this binhost at all",
            unpublished.join(" or "),
        ),
    }
}

/// Puts the chosen builds in an order each can be merged in.
///
/// A topological sort over runtime dependencies alone. `PDEPEND` is left out on
/// purpose: it is what portage satisfies *after* a package is merged, so it
/// belongs to the closure and not to the order, and treating it as an edge
/// would manufacture cycles the archive deliberately avoids.
///
/// Where a real cycle remains — Gentoo's runtime graph has them, and portage
/// breaks them too — the lexicographically first package still waiting is
/// emitted and the cycle is reported. That rule is stable, so a cycle broken in
/// one run is broken the same way in the next.
fn order(chosen: Vec<Record>) -> (Vec<Record>, Vec<Vec<String>>) {
    let at: HashMap<String, usize> = chosen
        .iter()
        .enumerate()
        .map(|(at, record)| (record.name.clone(), at))
        .collect();
    // `needs[i]` is what package `i` must be merged after.
    let mut needs: Vec<Vec<usize>> = vec![Vec::new(); chosen.len()];
    for (index_of, record) in chosen.iter().enumerate() {
        for dependency in &record.rdepend {
            let Dependency::One(atom) = dependency else {
                // An any-of group's alternatives were resolved as a choice
                // rather than as a requirement of this package, so the chosen
                // one carries no edge back here.
                continue;
            };
            if atom.blocker().is_some() {
                continue;
            }
            if let Some(&needed) = at.get(atom.name())
                && needed != index_of
                && atom.matches(&chosen[needed])
            {
                needs[index_of].push(needed);
            }
        }
    }

    let mut merged = Vec::with_capacity(chosen.len());
    let mut done = vec![false; chosen.len()];
    let mut cycles = Vec::new();
    // The candidates in name order, so a round that has several ready emits
    // them the same way every time.
    let mut by_name: Vec<usize> = (0..chosen.len()).collect();
    by_name.sort_by(|a, b| chosen[*a].name.cmp(&chosen[*b].name));

    while merged.len() < chosen.len() {
        let ready = by_name
            .iter()
            .copied()
            .find(|at| !done[*at] && needs[*at].iter().all(|needed| done[*needed]));
        let next = match ready {
            Some(next) => next,
            None => {
                // Nothing is ready and something is left: a cycle. The first
                // remaining package in name order goes next, and the cycle is
                // reported with everything still in it.
                let stuck: Vec<usize> = by_name.iter().copied().filter(|at| !done[*at]).collect();
                cycles.push(stuck.iter().map(|at| chosen[*at].cpv()).collect());
                stuck[0]
            }
        };
        done[next] = true;
        merged.push(next);
    }
    (
        merged.into_iter().map(|at| chosen[at].clone()).collect(),
        cycles,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::gentoo::atom;

    /// The fixture archive every test below resolves against.
    ///
    /// It holds the shapes the design's measurement separates: a package the
    /// root already has, a version published as two builds differing in USE, an
    /// any-of group, a blocker, and one of each unsatisfiable kind.
    const ARCHIVE: &str = "\
TIMESTAMP: 1787145736

BUILD_ID: 5
BUILD_TIME: 100
CPV: dev-vcs/git-2.54.0
IUSE: +curl keyring
MD5: 6a539af72c5577fdce267834d3dfd2f1
PATH: dev-vcs/git/git-2.54.0-5.gpkg.tar
RDEPEND: >=sys-libs/zlib-1.3 || ( app-crypt/gnupg app-crypt/pinentry )
SIZE: 10
USE: amd64 curl

BUILD_ID: 8
BUILD_TIME: 200
CPV: dev-vcs/git-2.54.0
IUSE: +curl keyring
MD5: dadac993dfc5d6e6c0fbefbbb4093e0e
PATH: dev-vcs/git/git-2.54.0-8.gpkg.tar
RDEPEND: >=sys-libs/zlib-1.3 app-crypt/libsecret || ( app-crypt/gnupg app-crypt/pinentry )
SIZE: 10
USE: amd64 curl keyring

BUILD_ID: 1
BUILD_TIME: 50
CPV: sys-libs/zlib-1.3.1
MD5: 3a61f698748c7323c87081584f383b3c
PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar
SIZE: 10
SLOT: 0/1
USE: amd64

BUILD_ID: 1
BUILD_TIME: 60
CPV: sys-libs/zlib-1.3.2
MD5: b3ae71ef373f5aa4405e637a2d263f51
PATH: sys-libs/zlib/zlib-1.3.2-1.gpkg.tar
SIZE: 10
SLOT: 0/1
USE: amd64

BUILD_ID: 1
BUILD_TIME: 70
CPV: app-crypt/libsecret-0.21.7
MD5: 49c242775827cc9cdb5e308933d97d18
PATH: app-crypt/libsecret/libsecret-0.21.7-1.gpkg.tar
RDEPEND: dev-libs/glib:2
SIZE: 10
USE: amd64

BUILD_ID: 1
BUILD_TIME: 80
CPV: dev-libs/glib-2.86.0
MD5: 1fea75aab3015c66c56ca3efe50f0b9b
PATH: dev-libs/glib/glib-2.86.0-1.gpkg.tar
SIZE: 10
SLOT: 2
USE: amd64

BUILD_ID: 1
BUILD_TIME: 90
CPV: app-crypt/gnupg-2.4.9
MD5: ed8f7e7c5c4aa5dda85165f0dca871fd
PATH: app-crypt/gnupg/gnupg-2.4.9-1.gpkg.tar
SIZE: 10
USE: amd64

BUILD_ID: 1
BUILD_TIME: 95
CPV: www-client/firefox-145.0
MD5: 66dcb7730c8bcf40774639146d39fbf6
PATH: www-client/firefox/firefox-145.0-1.gpkg.tar
RDEPEND: !sys-apps/sysvinit
SIZE: 10
USE: amd64

BUILD_ID: 1
BUILD_TIME: 96
CPV: app-editors/vim-9.1
IUSE: +python
MD5: d742bb6b8540666df485536830c8fe25
PATH: app-editors/vim/vim-9.1-1.gpkg.tar
SIZE: 10
SLOT: 0
USE: amd64 python

BUILD_ID: 1
BUILD_TIME: 97
CPV: dev-lang/ruby-3.4.9
MD5: 3a61f698748c7323c87081584f383b3d
PATH: dev-lang/ruby/ruby-3.4.9-1.gpkg.tar
SIZE: 10
SLOT: 3.4
USE: amd64
";

    /// The fixture index.
    fn archive() -> Index {
        Index::parse(ARCHIVE)
    }

    /// A root holding `entries`, each `category/name-version` in slot `0`.
    fn root(entries: &[&str]) -> Installed {
        Installed::of(
            entries
                .iter()
                .map(|cpv| {
                    let (category, package, version) =
                        version::split_cpv(cpv).expect("a fixture CPV");
                    (
                        format!("{category}/{package}"),
                        version.to_string(),
                        "0".to_string(),
                        String::new(),
                    )
                })
                .collect(),
        )
    }

    /// Resolves `atoms` against the fixture archive and `installed`.
    #[track_caller]
    fn run(installed: &Installed, atoms: &[&str], prefer: &[&str]) -> (Resolved, Refusals) {
        let parsed: Vec<Atom> = atoms
            .iter()
            .map(|text| atom::parse(text).expect("a fixture atom"))
            .collect();
        let prefer: Vec<Preference> = prefer
            .iter()
            .map(|text| Preference::parse(text).expect("a fixture preference"))
            .collect();
        resolve(&archive(), installed, &parsed, &prefer)
    }

    /// The `CPV`s a resolution chose, in install order.
    fn installing(resolved: &Resolved) -> Vec<String> {
        resolved.packages.iter().map(Record::cpv).collect()
    }

    #[test]
    fn an_atom_the_root_already_answers_pulls_nothing() {
        // The whole reason resolution starts from the root: the median closure
        // over the real archive is five packages because everything else is
        // already there.
        let installed = root(&["dev-vcs/git-2.54.0", "sys-libs/zlib-1.3.2"]);
        let (resolved, refusals) = run(&installed, &["dev-vcs/git"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        assert!(installing(&resolved).is_empty());
    }

    #[test]
    fn a_dependency_the_binhost_does_not_publish_is_answered_by_the_root() {
        // The measured case: the stage3 ships app-crypt/pinentry and the
        // binhost publishes it in no version. A resolver reading only the index
        // would refuse an install the root already satisfies.
        let installed = root(&["app-crypt/pinentry-1.3.2"]);
        let (resolved, refusals) = run(&installed, &["dev-vcs/git"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        // gnupg is not pulled in: the any-of group's other alternative is
        // already satisfied by the root.
        assert_eq!(
            installing(&resolved),
            ["sys-libs/zlib-1.3.2", "dev-vcs/git-2.54.0"],
        );
    }

    #[test]
    fn the_default_rule_takes_the_highest_version_and_then_the_fewest_flags() {
        // Two builds of one version differing in `keyring`: the one without it
        // pulls nothing extra, the one with it pulls libsecret and glib. The
        // measured rule takes the first, and it is what decides whether a
        // resolution stays small.
        let (resolved, refusals) = run(&root(&[]), &["dev-vcs/git"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        let installing = installing(&resolved);
        assert!(installing.contains(&"dev-vcs/git-2.54.0".to_string()));
        assert!(
            !installing
                .iter()
                .any(|cpv| cpv.starts_with("app-crypt/libsecret"))
        );
        // The highest version of a dependency, not the first one published.
        assert!(installing.contains(&"sys-libs/zlib-1.3.2".to_string()));
    }

    #[test]
    fn a_preference_reorders_the_candidates_and_a_constraint_removes_them() {
        // The distinction the API is built around. Both reach the keyring
        // build; only the constraint can fail.
        let preferred = run(&root(&[]), &["dev-vcs/git"], &["keyring"]).0;
        assert!(
            installing(&preferred)
                .iter()
                .any(|cpv| cpv.starts_with("app-crypt/libsecret")),
            "a preference reaches the build the default rule would not choose",
        );
        let constrained = run(&root(&[]), &["dev-vcs/git[keyring]"], &[]).0;
        assert!(
            installing(&constrained)
                .iter()
                .any(|cpv| cpv.starts_with("app-crypt/libsecret")),
        );
        // A constraint no build can meet is unsatisfiable, and says so.
        let refusals = run(&root(&[]), &["dev-vcs/git[bindist]"], &[]).1;
        assert_eq!(refusals.unsatisfied.len(), 1);
        assert!(
            refusals.describe().contains("USE flags"),
            "{}",
            refusals.describe(),
        );
    }

    #[test]
    fn a_preference_never_makes_an_atom_unsatisfiable() {
        // The guarantee stated as a property rather than as a case, and the one
        // test that would catch a preference quietly becoming a filter. Every
        // preference drawn from the flags the fixture archive carries resolves
        // the same atoms as no preference at all.
        let atoms = ["dev-vcs/git", "app-editors/vim", "www-client/firefox"];
        let installed = root(&["sys-apps/sysvinit-3.15"]);
        let baseline = run(&installed, &atoms, &[]).1;
        for flag in ["curl", "keyring", "python", "amd64", "bindist"] {
            for preference in [flag.to_string(), format!("-{flag}")] {
                let refusals = run(&installed, &atoms, &[&preference]).1;
                assert_eq!(
                    refusals.unsatisfied.len(),
                    baseline.unsatisfied.len(),
                    "the preference {preference:?} changed what could be satisfied",
                );
            }
        }
    }

    #[test]
    fn an_any_of_group_takes_its_first_viable_alternative() {
        let (resolved, refusals) = run(&root(&[]), &["dev-vcs/git"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        // gnupg is the first alternative and the archive publishes it;
        // pinentry it does not publish at all.
        assert!(installing(&resolved).contains(&"app-crypt/gnupg-2.4.9".to_string()));
    }

    #[test]
    fn a_blocker_that_matches_is_a_conflict_naming_both_sides() {
        // The measured shape: a desktop package blocking the init system an
        // openrc stage3 ships. Portage refuses the same request for the same
        // reason.
        let installed = root(&["sys-apps/sysvinit-3.15"]);
        let (_, refusals) = run(&installed, &["www-client/firefox"], &[]);
        assert_eq!(refusals.conflicts.len(), 1);
        let conflict = &refusals.conflicts[0];
        assert_eq!(conflict.stated_by, "www-client/firefox-145.0");
        assert_eq!(conflict.blocks, "sys-apps/sysvinit-3.15");
        assert!(conflict.installed);
        assert!(
            refusals.describe().contains("removed from the root first"),
            "{}",
            refusals.describe(),
        );
        // With nothing to block, the same request resolves.
        assert!(run(&root(&[]), &["www-client/firefox"], &[]).1.is_empty());
    }

    #[test]
    fn each_unsatisfiable_kind_says_which_wall_it_hit() {
        let installed = root(&[]);
        for (atoms, expected) in [
            (["app-misc/jq"], "is published by this binhost at all"),
            ([">=dev-vcs/git-3.0"], "has a version the atom admits"),
            (["dev-lang/ruby:3.3"], "is in the slot the atom names"),
            (["dev-vcs/git[bindist]"], "carries the USE flags"),
        ] {
            let refusals = run(&installed, &atoms, &[]).1;
            assert_eq!(refusals.unsatisfied.len(), 1, "{}", atoms[0]);
            assert!(
                refusals.describe().contains(expected),
                "{}: {}",
                atoms[0],
                refusals.describe(),
            );
        }
    }

    #[test]
    fn a_package_merges_after_what_it_needs_at_run_time() {
        let (resolved, refusals) = run(&root(&[]), &["dev-vcs/git[keyring]"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        let order = installing(&resolved);
        let position = |cpv: &str| {
            order
                .iter()
                .position(|held| held == cpv)
                .unwrap_or_else(|| panic!("{cpv} is installed"))
        };
        assert!(position("sys-libs/zlib-1.3.2") < position("dev-vcs/git-2.54.0"));
        assert!(position("dev-libs/glib-2.86.0") < position("app-crypt/libsecret-0.21.7"));
        assert!(position("app-crypt/libsecret-0.21.7") < position("dev-vcs/git-2.54.0"));
        assert!(resolved.cycles.is_empty());
    }

    #[test]
    fn a_resolution_is_the_same_resolution_twice() {
        // Two builds can share everything the ranking looks at, and a choice
        // made by iteration order would not be reproducible; so would an
        // install order taken from a hash map's walk.
        let installed = root(&["app-crypt/pinentry-1.3.2"]);
        let first = installing(&run(&installed, &["dev-vcs/git", "app-editors/vim"], &[]).0);
        for _ in 0..8 {
            assert_eq!(
                installing(&run(&installed, &["dev-vcs/git", "app-editors/vim"], &[]).0),
                first,
            );
        }
    }

    #[test]
    fn a_runtime_cycle_is_broken_by_a_stable_rule_and_reported() {
        // Gentoo's runtime graph has cycles and portage breaks them too. What
        // matters is that the break is the same one every time.
        let cyclic = "\
TIMESTAMP: 1

BUILD_ID: 1
CPV: dev-lang/perl-5.42
MD5: 1fea75aab3015c66c56ca3efe50f0b9b
PATH: dev-lang/perl/perl-5.42-1.gpkg.tar
RDEPEND: dev-perl/Module-Build
SIZE: 10
USE: amd64

BUILD_ID: 1
CPV: dev-perl/Module-Build-0.42
MD5: ed8f7e7c5c4aa5dda85165f0dca871fd
PATH: dev-perl/Module-Build/Module-Build-0.42-1.gpkg.tar
RDEPEND: dev-lang/perl
SIZE: 10
USE: amd64
";
        let index = Index::parse(cyclic);
        let wanted = [atom::parse("dev-lang/perl").expect("a fixture atom")];
        let installed = Installed::default();
        let (resolved, refusals) = resolve(&index, &installed, &wanted, &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        assert_eq!(resolved.cycles.len(), 1);
        assert_eq!(
            resolved
                .packages
                .iter()
                .map(Record::cpv)
                .collect::<Vec<_>>(),
            ["dev-lang/perl-5.42", "dev-perl/Module-Build-0.42"],
        );
    }

    #[test]
    fn a_preference_that_does_not_name_a_flag_is_refused() {
        assert!(Preference::parse("keyring").is_ok());
        assert!(Preference::parse("-X").is_ok());
        for text in ["", "-", "a b", "a/b", "a,b"] {
            assert!(Preference::parse(text).is_err(), "{text:?} was accepted");
        }
    }
}
