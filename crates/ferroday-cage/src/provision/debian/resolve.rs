//! Dependency resolution: the install closure over a package index.
//!
//! From a seed set the resolver closes over `Depends` and `Pre-Depends`,
//! following `debootstrap`'s discipline: the first satisfiable alternative of
//! an `a | b` group, virtual packages satisfied by preferring an
//! already-selected provider. The result is the set of real packages to
//! download and install, none of which `Conflicts` with or `Breaks` another.
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
//! # The order of the walk
//!
//! A choice depends on what is selected when its group is met, so the order the
//! walk meets groups in is apt's. Every seed is selected before any group is
//! resolved, as apt marks every package its command line names before it marks
//! any dependency. The seeds are then walked in turn, each depth first: its
//! `Pre-Depends` then its `Depends`, and a package a group selects is walked
//! whole before the next group of the package that needed it. A group answered
//! by a package already selected walks nothing, so a seed met as another's
//! dependency waits for its own turn. apt 2.8 marks in that order: where `aa`
//! depends on `mm` and on `bb | cc`, `mm` on `xx`, and `bb` conflicts with
//! `xx`, it marks `xx` before it meets `bb | cc`, and takes `cc`.
//!
//! A group nothing satisfies is an error rather than a silent omission. Leaving
//! it out produces a root that cannot work, and produces it quietly: the
//! post-install check verifies that every *selected* package configured, and a
//! dependency dropped here was never selected, so nothing downstream is in a
//! position to notice.
//!
//! The same holds for a layered resolve's root as a whole. dpkg configures an
//! increment with `--force-depends`, so the resolve is the only step that can
//! notice an upgrade in the increment breaking a package the base keeps, or a
//! dependency the base answered until the upgrade replaced what answered it.
//! [`resolve_seeded`] therefore holds the merged root to every hard dependency
//! it carries before it reports a selection.
//!
//! Every such refusal is collected and reported, and the resolution fails once
//! with all of them named. A caller correcting an install list wants the whole
//! list of what the archive cannot give them; learning them one run at a time
//! turns one correction into as many bootstraps as there are mistakes.
//!
//! # Which version of a name
//!
//! Each name resolves to one version, chosen as apt chooses one. By default
//! that is the index's candidate, ranked by each release's
//! [`ReleasePriority`](super::release::ReleasePriority). An install list entry
//! written `name/release` asks for the name from that release instead, and the
//! versioned dependencies its candidates cannot meet are taken from the same
//! release where that meets them, as apt's `pkgDepCache::SetCandidateRelease`
//! does. A layered resolve takes a name its base has installed at the
//! installed version, and upgrades it only where a dependency needs a newer
//! one, or an upgrade of another package breaks one of its own, and apt would
//! take that newer one over the installed one.
//!
//! A name a [pin](super::DebianBuilder::pin) holds resolves to its pinned
//! version by every one of those routes, since the [`Index`] answers each of
//! them with the pinned version alone. Where the pinned version cannot answer
//! what is asked of it, the resolution refuses the pin as
//! [`Refusal::Pinned`] rather than resolving around it: an entry naming a
//! release that does not offer the pinned version, or a dependency the pinned
//! version does not meet.
//!
//! # Conflicts and Breaks
//!
//! The root a resolution produces holds no two packages one of which
//! `Conflicts` with or `Breaks` the other, as apt holds a resolution to. The
//! two fields keep packages apart alike: they differ in how dpkg orders an
//! unpack, and apt 2.8 resolves around a `Breaks` exactly as around a
//! `Conflicts`. A [`Clash`] says what each entry names.
//!
//! A choice is where a clash is avoided, as apt avoids one. A dependency group
//! takes its first alternative that clashes with nothing the root holds as the
//! walk meets the group: the real package an alternative names, then each of
//! its providers in turn, then the next alternative. A clash in either
//! direction passes a candidate over, whichever of the two states it. Only
//! where every alternative clashes is the first that answers the group taken,
//! and the clash it brings refused.
//!
//! A package selected later can clash with one chosen earlier, before the
//! later one was there to avoid. Where the later one states the clash, and the
//! earlier one was selected for a dependency rather than named by the install
//! list or kept by the base, the earlier one is unselected, as apt 2.8 unmarks
//! it, and every group it answered is answered again
//! ([`Closure::unselect_named`]). Otherwise the walk does not go back on the
//! choice, and the clash is refused. apt does the same: `apt-get install a z`,
//! where `a` depends on `b | c`, `b` conflicts with `x`, and `z` depends on
//! `x`, takes `b` for `a` and then fails on `z`'s `x`.
//!
//! A layered resolution removes nothing from its base, so a package the base
//! keeps stands as apt treats one it may not remove, an essential one. A
//! candidate that clashes with it is passed over, unless the base package has
//! an upgrade apt would take that clashes with nothing. apt upgrades a package
//! in that position, and so does the resolution. Where nothing avoids the
//! clash, the resolution refuses it where apt would remove the base package.
//! A base that already holds two packages that clash is refused too, as apt
//! refuses to act on a broken system.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;

use super::index::{Clash, DepAtom, Dependency, Index, Package, Provided};
use super::layer::{Installed, InstalledSet, Supply};
use super::pin::{UnheldPin, UnheldReason};
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
    /// A caller asked for a package from a release that does not carry it.
    NotInRelease {
        /// The install list's entry, `name/release`, as written.
        entry: String,
        /// The release named.
        release: String,
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
    /// constraint rules out, and the base layer supplies none either. Where the
    /// base supplied one until the increment replaced the package supplying it,
    /// the refusal is [`Broken`](Self::Broken) instead.
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
    /// The pin holds a name at a version that cannot answer what was asked of
    /// it: an install list entry naming a release that does not offer the
    /// pinned entry, or a dependency group nothing answers, one of whose
    /// alternatives names a pinned package at a version the pinned one does
    /// not meet.
    ///
    /// The resolution fails with [`DebianError::Pin`](super::DebianError::Pin)
    /// where it refuses one of these, since what is in the way is the pin.
    Pinned {
        /// The install list's entry, or the dependency group as declared.
        requirement: String,
        /// The selected package whose dependency it was, or the install list.
        required_by: String,
        /// The pin, and what was asked of it.
        unheld: UnheldPin,
    },
    /// A layered resolution's root leaves a hard dependency unmet: nothing the
    /// base keeps and nothing the increment installs satisfies it.
    ///
    /// The increment replaces each base package it selects another version of,
    /// and everything the replaced version supplied goes with it, its own name
    /// and its `Provides` alike. A dependency the replaced version met is then
    /// met only where what replaces it, or something else in the root, meets
    /// it too. A package the base keeps whose dependency the increment breaks
    /// is upgraded with it where apt would upgrade it, and refused here where
    /// nothing would: a layer installs over its base and removes nothing from
    /// it.
    Broken {
        /// The dependency group as declared, alternatives included.
        requirement: String,
        /// Whose dependency it is: a package the increment selects, a package
        /// the base keeps, or the install list, for an entry the base answered.
        required_by: String,
        /// What the root holds for the group's names, when it holds anything:
        /// what the increment installs, and what the base keeps.
        offered: Option<String>,
        /// The replacements that took away a supply meeting the group, in name
        /// order. Empty where none did, which is a package the base keeps
        /// whose dependency the base itself left unmet.
        replaced: Vec<Replacement>,
    },
}

/// A base package an increment replaces, as [`Refusal::Broken`] names it.
///
/// Each part is named bare. The name and the version taken in its place are
/// the index's, held to policy's alphabet as the index is read; the version
/// replaced is the base's status database's, held to the same alphabet as the
/// database is read, and absent where it states none that alphabet admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Replacement {
    /// The package.
    pub(crate) package: String,
    /// The version the base has installed, where its status database states
    /// one.
    pub(crate) installed: Option<String>,
    /// The version the increment installs in its place.
    pub(crate) version: String,
}

impl fmt::Display for Replacement {
    /// Writes `libcore 1.0 with 2.0`, or `libcore with 2.0` where the base's
    /// version is unknown, for the clause a refusal composes it into.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.installed {
            Some(installed) => write!(f, "{} {installed} with {}", self.package, self.version),
            None => write!(f, "{} with {}", self.package, self.version),
        }
    }
}

/// Two packages of the root a resolution produces that cannot be installed
/// together: one states a `Conflicts` or `Breaks` entry naming the other.
///
/// Each party is named bare, as `name version`: the name is held to policy's
/// alphabet as the index or the base's status database is read, and so is the
/// version, which a base package states nothing of where its database states
/// none that alphabet admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Conflict {
    /// The entry, as its field states it: `Breaks: libfoo (<< 2)`.
    pub(crate) relation: String,
    /// The package stating it.
    pub(crate) stated_by: String,
    /// Whether the package stating it is one a layered build's base keeps,
    /// rather than one the resolution selects.
    pub(crate) stated_in_base: bool,
    /// The package it names.
    pub(crate) against: String,
    /// Whether the package it names is one a layered build's base keeps.
    pub(crate) against_in_base: bool,
}

impl fmt::Display for Conflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let which = if self.stated_in_base {
            ", which the base layer keeps,"
        } else {
            ""
        };
        write!(
            f,
            "{}{which} states {:?}, and ",
            self.stated_by, self.relation
        )?;
        match (self.against_in_base, self.stated_in_base) {
            (true, false) => write!(
                f,
                "the base layer keeps {}, which a layer does not remove",
                self.against,
            ),
            (true, true) => write!(f, "the base layer keeps {} too", self.against),
            (false, _) => write!(f, "the resolution selects {} too", self.against),
        }
    }
}

impl Refusal {
    /// What could not be supplied: the dependency group as the archive, or a
    /// base layer's status database, declares it, or the package name where
    /// the caller named one directly.
    pub(crate) fn requirement(&self) -> &str {
        match self {
            Refusal::PackageNotFound { name } | Refusal::ExcludedAndIncluded { name } => name,
            Refusal::NotInRelease { entry, .. } => entry,
            Refusal::ExcludedButRequired { package, .. } => package,
            Refusal::Unsatisfiable { requirement, .. }
            | Refusal::Pinned { requirement, .. }
            | Refusal::Broken { requirement, .. } => requirement,
        }
    }

    /// Who asked for it: the selected package whose dependency it was, a
    /// package the base keeps, or [`THE_INSTALL_LIST`] where the caller asked
    /// directly.
    pub(crate) fn required_by(&self) -> &str {
        match self {
            Refusal::PackageNotFound { .. }
            | Refusal::ExcludedAndIncluded { .. }
            | Refusal::NotInRelease { .. } => THE_INSTALL_LIST,
            Refusal::ExcludedButRequired { required_by, .. }
            | Refusal::Unsatisfiable { required_by, .. }
            | Refusal::Pinned { required_by, .. }
            | Refusal::Broken { required_by, .. } => required_by,
        }
    }

    /// What the wall was, as the clause following "and": the half of the
    /// refusal the other two accessors do not already carry.
    pub(crate) fn reason(&self) -> String {
        match self {
            Refusal::PackageNotFound { .. } => "it is not in the index".to_string(),
            Refusal::ExcludedAndIncluded { .. } => "it is both included and excluded".to_string(),
            Refusal::NotInRelease { release, .. } => {
                format!("no repository publishing {release} offers it")
            }
            Refusal::ExcludedButRequired { .. } => "it is excluded".to_string(),
            Refusal::Unsatisfiable { available, .. } => match available {
                Some(available) => format!("nothing satisfies it (available: {available:?})"),
                None => "no configured archive offers it and no base layer supplies it".to_string(),
            },
            Refusal::Pinned { unheld, .. } => {
                let UnheldPin {
                    package, version, ..
                } = unheld;
                match &unheld.reason {
                    UnheldReason::Release { release, archive } => format!(
                        "the pin holds {package} at {version}, where {release} offers {archive}"
                    ),
                    UnheldReason::Digest { pin, archive } => format!(
                        "the pin holds {package} {version} at the {} digest {}, where that \
                         release records {}",
                        pin.algorithm().name(),
                        pin.hex(),
                        archive.hex(),
                    ),
                    UnheldReason::DigestNotOffered { pin } => format!(
                        "the pin holds {package} {version} at its {} digest, where that release \
                         records no {}",
                        pin.algorithm().name(),
                        pin.algorithm().name(),
                    ),
                    _ => format!("the pin holds {package} at {version}"),
                }
            }
            Refusal::Broken {
                offered, replaced, ..
            } => {
                let offered = offered
                    .as_ref()
                    .map(|offered| format!(" (offered: {offered:?})"))
                    .unwrap_or_default();
                if replaced.is_empty() {
                    format!(
                        "nothing the base layer keeps or the increment installs satisfies \
                         it{offered}"
                    )
                } else {
                    let replaced: Vec<String> = replaced.iter().map(ToString::to_string).collect();
                    format!(
                        "the increment replaces {}, leaving nothing that satisfies it{offered}",
                        replaced.join(" and "),
                    )
                }
            }
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} requires {:?}, and {}",
            self.required_by(),
            self.requirement(),
            self.reason(),
        )
    }
}

/// Everything one resolution refused: every dependency in the order it met
/// them, then every [`Conflict`] in the root it produced.
///
/// Debian's own rather than Gentoo's `Refusals`, which is the same idea under
/// the same name in the same position. The two are deliberately separate: a
/// portage resolution refuses in three shapes — an atom nothing answers, a
/// blocker, and two builds contending for one slot — and the last is a portage
/// concept with no Debian meaning, so a shared type would carry a collection
/// that is always empty here. What the layers share is the discipline, not the
/// vocabulary, and `CONTRIBUTING.md`'s shared-vocabulary table records the
/// split.
#[derive(Debug, Default)]
pub(crate) struct Refusals {
    refused: Vec<Refusal>,
    conflicts: Vec<Conflict>,
}

impl Refusals {
    /// Records one refusal.
    fn push(&mut self, refusal: Refusal) {
        self.refused.push(refusal);
    }

    /// Whether the resolution can be acted on.
    pub(crate) fn is_empty(&self) -> bool {
        self.refused.is_empty() && self.conflicts.is_empty()
    }

    /// Every dependency refused, in the order the resolution met them.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Refusal> {
        self.refused.iter()
    }

    /// Every conflict the root holds, the selected packages' first, each
    /// party's in name order.
    pub(crate) fn conflicts(&self) -> impl Iterator<Item = &Conflict> {
        self.conflicts.iter()
    }

    /// Every package the pin could not be held to, in name order, and in the
    /// order the resolution met them within one name.
    ///
    /// Empty where nothing the resolution refused is the pin's.
    pub(crate) fn unheld(&self) -> Vec<UnheldPin> {
        let mut unheld: Vec<UnheldPin> = self
            .refused
            .iter()
            .filter_map(|refusal| match refusal {
                Refusal::Pinned { unheld, .. } => Some(unheld.clone()),
                _ => None,
            })
            .collect();
        // The same order `Pins::check` reports in, so the pin's refusals read
        // alike whichever of the two found them.
        unheld.sort_by(|a, b| a.package.cmp(&b.package));
        unheld
    }

    /// The whole refusal as one sentence a caller reads.
    pub(crate) fn describe(&self) -> String {
        self.refused
            .iter()
            .map(Refusal::to_string)
            .chain(self.conflicts.iter().map(Conflict::to_string))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Resolves the install closure of `base` plus `includes`, honoring
/// `excludes`.
///
/// `base` names (the essential/priority seed and `apt`) are trusted to
/// exist; a missing one is skipped. Each caller `include` must resolve to a
/// real package or a provided virtual, or the resolution fails naming it; one
/// written `name/release` must be a real package that release carries. An
/// excluded package is never selected: it is dropped from the seed, and skipped
/// as a dependency alternative so a later alternative satisfies the group
/// instead. A hard dependency an exclusion leaves unsatisfiable refuses the
/// resolution rather than shipping a broken closure, and a package that is both
/// included and excluded is a contradiction that refuses likewise, as does a
/// closure holding two packages that clash. The returned packages are sorted by
/// name.
pub(crate) fn resolve(
    index: &Index,
    base: &[String],
    includes: &[String],
    excludes: &[String],
) -> (Vec<Package>, Refusals) {
    resolve_seeded(index, base, includes, excludes, &InstalledSet::default())
}

/// Resolves the install closure while treating `assume_installed` as
/// already-satisfied, so only the increment over an existing base is selected.
///
/// This is [`resolve`] with one additive input. `assume_installed` holds the
/// names a base layer already supplies — every package configured in it, plus
/// the virtual packages those packages `Provides` — and what each of its
/// packages depends on. A name in that set is skipped as a seed, satisfies any
/// dependency group naming it at a version the group accepts, and is otherwise
/// re-selected only as an upgrade, so the resolution closes only over what the
/// base does not already carry. A caller `include` the base already supplies is
/// likewise satisfied by the base rather than pulled again, unless it names a
/// release whose version the base does not hold. [`resolve`] passes an empty
/// set, so a full bootstrap is unaffected. Because a configured base is
/// dependency-complete, the transitive dependencies of a package the base keeps
/// are themselves kept, so declining to walk them omits nothing the increment
/// needs.
///
/// # The merged set
///
/// The root a layered resolution produces is the increment *and* what the base
/// keeps of its own. The increment replaces each base package it selects
/// another version of, and everything the replaced version supplied goes with
/// it: its own name, and every name it `Provides`. A dependency answers only to
/// what is left, the increment's packages and the base's supplies that no
/// replacement took away, so a selection made late in the walk can take away
/// what answered a dependency resolved earlier, and can break a package the
/// base keeps.
///
/// So the walk ends with a check of the merged set, which runs until a pass of
/// it selects nothing:
///
/// - Every group of every selected package, and every install list entry the
///   base answered, is resolved again against what is left. One a replacement
///   broke is answered as the walk would have answered it had the replacement
///   come first, which selects what it needs, and the walk closes over that.
/// - Every group of every package the base keeps is held to what is left. A
///   package with a group nothing answers is upgraded where [`Candidates::of`]
///   offers it an upgrade, as apt upgrades an installed package whose
///   dependency an upgrade breaks, and the walk closes over the upgrade, which
///   replaces the package in turn.
///
/// What still has no answer is refused as [`Refusal::Broken`]. The walk and the
/// check select by the same rules, so the order of the install list does not
/// decide what a replacement breaks: a dependency the walk met before the
/// replacement that breaks it is answered by its next alternative, or refused,
/// exactly as one it met after.
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
/// package nor a virtual, a name both included and excluded, a release that
/// does not carry the name asked of it — is collected alongside the rest rather
/// than returned immediately. It is discovered before the closure walk rather
/// than during it, but a caller correcting an install list of twenty names
/// wants all four mistakes, not the first, and that is the same reason the walk
/// collects.
pub(crate) fn resolve_seeded(
    index: &Index,
    base: &[String],
    includes: &[String],
    excludes: &[String],
    assume_installed: &InstalledSet,
) -> (Vec<Package>, Refusals) {
    let excluded: HashSet<&str> = excludes.iter().map(String::as_str).collect();
    let mut candidates = Candidates {
        index,
        installed: assume_installed,
        targeted: HashMap::new(),
    };
    let mut refusals = Refusals::default();
    // The install list's entries the base answers rather than the increment,
    // which the merged set's check asks about again.
    let mut answered: Vec<String> = Vec::new();

    // The entries naming a release switch their names' candidates before
    // anything is selected, as apt switches them when it reads the command
    // line: a base package one of them needs a newer version of is then seeded
    // at that version rather than at the one it would replace.
    let mut asked: Vec<Option<&str>> = Vec::with_capacity(includes.len());
    for entry in includes {
        let (name, release) = split_release(entry);
        if excluded.contains(name) {
            // Asking for a package and excluding it in the same breath is a
            // contradiction, reported rather than silently resolved either way.
            refusals.push(Refusal::ExcludedAndIncluded {
                name: entry.clone(),
            });
            asked.push(None);
            continue;
        }
        let Some(release) = release else {
            asked.push(Some(name));
            continue;
        };
        let package = match index.in_release(name, release) {
            Ok(Some(package)) => package,
            Ok(None) => {
                refusals.push(Refusal::NotInRelease {
                    entry: entry.clone(),
                    release: release.to_string(),
                });
                asked.push(None);
                continue;
            }
            Err(unheld) => {
                refusals.push(Refusal::Pinned {
                    requirement: entry.clone(),
                    required_by: THE_INSTALL_LIST.to_string(),
                    unheld,
                });
                asked.push(None);
                continue;
            }
        };
        // The base holding that very version answers the entry already.
        if assume_installed
            .installed(name)
            .is_some_and(|version| super::version::compare(version, &package.version).is_eq())
        {
            answered.push(name.to_string());
            asked.push(None);
            continue;
        }
        candidates.target(package, release, &excluded);
        asked.push(Some(name));
    }

    let mut closure = Closure {
        candidates,
        excluded,
        selected: BTreeMap::new(),
        queue: VecDeque::new(),
        refusals,
        refused: HashSet::new(),
        answered,
        seeds: HashSet::new(),
        unselected: HashSet::new(),
    };

    // Seed the whole base set before closing over anything, so a virtual
    // dependency encountered during the closure sees every base package as an
    // already-selected candidate provider. An excluded base package is simply
    // not seeded, and one the layer already carries is left to the base.
    for name in base {
        if closure.excluded.contains(name.as_str()) || assume_installed.contains(name) {
            continue;
        }
        if let Some(package) = closure.candidates.of(name) {
            add(&mut closure.selected, &mut closure.queue, package);
        }
    }
    for (entry, name) in includes.iter().zip(asked) {
        let Some(name) = name else {
            continue;
        };
        // A requested package the base already supplies is satisfied by the
        // base and needs no re-selection into the increment, unless the entry
        // switched it to a version the base does not hold.
        if assume_installed.contains(name) && !closure.candidates.is_targeted(name) {
            closure.answered.push(name.to_string());
            continue;
        }
        if let Some(package) = closure.candidates.of(name) {
            add(&mut closure.selected, &mut closure.queue, package);
        } else if let Some(provider) =
            // A caller `include` names a package, never a constrained version,
            // so it asks the unversioned question.
            first_available_provider(
                &closure.candidates,
                &unversioned(name),
                &closure.excluded,
            )
        {
            let package = closure
                .candidates
                .of(&provider)
                .expect("a provider is a real package");
            add(&mut closure.selected, &mut closure.queue, package);
        } else {
            closure.refusals.push(Refusal::PackageNotFound {
                name: entry.clone(),
            });
        }
    }

    closure.seeds = closure.selected.keys().cloned().collect();
    loop {
        closure.walk();
        if !closure.settle() {
            break;
        }
    }
    closure.sweep();
    (closure.selected.into_values().collect(), closure.refusals)
}

/// The dependency an install list entry naming `name` states: the name, at any
/// version.
fn unversioned(name: &str) -> DepAtom {
    DepAtom {
        name: name.to_string(),
        constraint: None,
    }
}

/// One resolution under way: what it has selected, what it has still to walk,
/// and what it has refused.
struct Closure<'a> {
    candidates: Candidates<'a>,
    excluded: HashSet<&'a str>,
    selected: BTreeMap<String, Package>,
    /// The selected packages whose groups the walk has still to resolve, in
    /// the order it takes them up: the seeds, and what the merged set's check
    /// upgrades. A package a group selects is walked as it is selected rather
    /// than waiting here; [`walk`](Self::walk) takes it off the back.
    queue: VecDeque<String>,
    refusals: Refusals,
    /// Every group refused so far, by who declares it and its place among
    /// their groups, so the merged set's check does not refuse a group the
    /// walk already refused a second time.
    refused: HashSet<(String, usize)>,
    /// The install list's entries the base answered rather than the
    /// increment, by name.
    answered: Vec<String>,
    /// What was selected before the walk began: the base seed and the install
    /// list's entries, which nothing unselects.
    seeds: HashSet<String>,
    /// Every package a later selection unselected ([`unselect_named`]), which
    /// is unselected once at most and, selected again, unselects nothing.
    ///
    /// [`unselect_named`]: Self::unselect_named
    unselected: HashSet<String>,
}

impl Closure<'_> {
    /// Resolves every group of every package selected since the walk last
    /// ran, and of every package those select in turn, depth first, as the
    /// module's [order of the walk](self#the-order-of-the-walk) describes.
    fn walk(&mut self) {
        while let Some(name) = self.queue.pop_front() {
            // Each entry is a package and the groups it has still to resolve.
            let mut stack: Vec<(String, VecDeque<(usize, Dependency)>)> = Vec::new();
            let groups = relations(&self.selected[&name]).into_iter().enumerate();
            stack.push((name, groups.collect()));
            while let Some((name, groups)) = stack.last_mut() {
                // A package a later selection unselected has nothing left to
                // need.
                let Some((at, group)) = groups
                    .pop_front()
                    .filter(|_| self.selected.contains_key(name.as_str()))
                else {
                    stack.pop();
                    continue;
                };
                let name = name.clone();
                if let Some(chosen) = self.resolve(&name, at, &group) {
                    // Walked here rather than when the queue reaches it.
                    self.queue.retain(|queued| *queued != chosen);
                    let groups = relations(&self.selected[&chosen]).into_iter().enumerate();
                    stack.push((chosen, groups.collect()));
                }
            }
        }
    }

    /// Resolves `group`, the `at`th of the groups `required_by` declares,
    /// and records its refusal, where it is refused, once.
    ///
    /// Returns the package the group selected, where it selected one, which
    /// [`add`] has queued.
    fn resolve(&mut self, required_by: &str, at: usize, group: &Dependency) -> Option<String> {
        let key = (required_by.to_string(), at);
        if self.refused.contains(&key) {
            return None;
        }
        let waiting = self.queue.len();
        if let Some(refusal) = resolve_group(
            &self.candidates,
            group,
            &self.excluded,
            required_by,
            &mut self.selected,
            &mut self.queue,
        ) {
            self.refused.insert(key);
            self.refusals.push(refusal);
        }
        // A group selects one package at most, which `add` queued last.
        let chosen = (self.queue.len() > waiting)
            .then(|| self.queue.back().cloned())
            .flatten()?;
        self.unselect_named(&chosen);
        Some(chosen)
    }

    /// Unselects each package `chosen` states a clash against that a
    /// dependency selected, as apt 2.8 unmarks a package it marked for a
    /// dependency where a package it marks later conflicts with or breaks it.
    ///
    /// Only a package [`resolve_group`] had to take though it clashes reaches
    /// here with a clash: any other is one that fits. Where `aa` depends on
    /// `mm` and on `xx`, `mm` on `bb | cc`, and `xx` conflicts with `bb`, apt
    /// takes `bb` for `mm`, unmarks it when it marks `xx`, and answers `mm`
    /// with `cc` instead; the merged set's check here answers again every group
    /// the unselected package answered. A clash stated against `chosen` rather
    /// than by it unselects nothing, and fails in apt as it is refused here,
    /// and so does one against a seed, a package the base keeps, or a package
    /// unselected once already. A package selected again after it was
    /// unselected unselects nothing, which is what ends two packages that
    /// conflict with each other taking turns.
    fn unselect_named(&mut self, chosen: &str) {
        if self.unselected.contains(chosen) {
            return;
        }
        let Some(package) = self.selected.get(chosen) else {
            return;
        };
        let named: Vec<String> =
            stated(&self.candidates, &self.selected, Member::selected(package))
                .iter()
                .filter(|clash| !clash.against.in_base)
                .map(|clash| clash.against.name.to_string())
                .filter(|name| !self.seeds.contains(name) && !self.unselected.contains(name))
                .collect();
        for name in named {
            self.selected.remove(&name);
            self.queue.retain(|queued| *queued != name);
            self.unselected.insert(name);
        }
    }

    /// Drops what only an unselected package needed, as apt drops what it
    /// marked for a package it later unmarked, and the refusals of groups no
    /// package the root holds declares any more.
    ///
    /// A package stays where the seeds reach it: through any group of a
    /// package already reached, by any alternative the selection answers it
    /// with, by name or by `Provides`. A base package the increment replaces is
    /// reached as a seed is, and so is what answers an install list entry the
    /// base answered. Nothing is dropped unless something was unselected: every
    /// other selection was made for a group of a package already reached.
    fn sweep(&mut self) {
        if self.unselected.is_empty() {
            return;
        }
        let installed = self.candidates.installed;
        let index = self.candidates.index;
        let mut reached: HashSet<String> = HashSet::new();
        let mut pending: Vec<String> = Vec::new();
        let answered: Vec<Dependency> = self
            .answered
            .iter()
            .map(|name| vec![unversioned(name)])
            .collect();
        let roots = self.selected.keys().filter(|name| {
            self.seeds.contains(name.as_str()) || installed.installed(name).is_some()
        });
        pending.extend(roots.cloned());
        for group in &answered {
            pending.extend(group_answers(index, &self.selected, group));
        }
        while let Some(name) = pending.pop() {
            if !reached.insert(name.clone()) {
                continue;
            }
            for group in relations(&self.selected[&name]) {
                pending.extend(group_answers(index, &self.selected, &group));
            }
        }
        self.selected.retain(|name, _| reached.contains(name));
        let selected = &self.selected;
        self.refusals.refused.retain(|refusal| {
            let by = refusal.required_by();
            by == THE_INSTALL_LIST || selected.contains_key(by) || installed.installed(by).is_some()
        });
    }
    /// One pass of the merged set's check, as [`resolve_seeded`] describes it.
    ///
    /// Returns whether the pass selected anything, which leaves the walk to
    /// close over it and the check to run again. A pass that selected nothing
    /// is the last, and refuses what the base keeps that is still broken, and
    /// every clash the root holds. Only that pass refuses them, since an
    /// earlier pass's selection can answer a group of the base's that a later
    /// one leaves broken, and upgrade a base package out of a clash. The groups
    /// of selected packages are refused as they are met, as the walk refuses
    /// them: nothing selected later answers a group no candidate answers.
    ///
    /// A package the base keeps that clashes with a selected one is upgraded
    /// where the upgrade [`Candidates::upgrade`] offers clashes with nothing,
    /// as apt upgrades a package a candidate's `Breaks` or `Conflicts` names
    /// before it would remove it.
    fn settle(&mut self) -> bool {
        for (at, name) in self.answered.clone().iter().enumerate() {
            self.resolve(THE_INSTALL_LIST, at, &vec![unversioned(name)]);
        }
        let names: Vec<String> = self.selected.keys().cloned().collect();
        for name in &names {
            for (at, group) in relations(&self.selected[name]).iter().enumerate() {
                self.resolve(name, at, group);
            }
        }
        if !self.queue.is_empty() {
            return true;
        }

        let installed = self.candidates.installed;
        let mut broken = Vec::new();
        for (name, package) in installed.members() {
            if self.selected.contains_key(name) {
                continue;
            }
            for group in &package.relations {
                if group
                    .iter()
                    .any(|atom| merged_satisfies(&self.candidates, &self.selected, atom))
                {
                    continue;
                }
                if let Some(upgrade) = self.candidates.upgrade(name, &self.excluded) {
                    add(&mut self.selected, &mut self.queue, upgrade);
                    break;
                }
                broken.push(Refusal::Broken {
                    requirement: render_group(group),
                    required_by: name.to_string(),
                    offered: describe_merged(&self.candidates, &self.selected, group),
                    replaced: replacements(installed, &self.selected, group),
                });
            }
        }
        if !self.queue.is_empty() {
            return true;
        }
        for (name, package) in installed.members() {
            if self.selected.contains_key(name) {
                continue;
            }
            let kept = Member::kept(name, package);
            let clashes_with_selection = clashes(&self.candidates, &self.selected, kept)
                .iter()
                .any(|clash| !clash.stated_by.in_base || !clash.against.in_base);
            if !clashes_with_selection {
                continue;
            }
            if let Some(upgrade) = self.candidates.upgrade(name, &self.excluded)
                && fits(&self.candidates, &self.excluded, &self.selected, upgrade)
            {
                add(&mut self.selected, &mut self.queue, upgrade);
            }
        }
        if !self.queue.is_empty() {
            return true;
        }
        for refusal in broken {
            self.refusals.push(refusal);
        }
        self.refusals.conflicts = root_conflicts(&self.candidates, &self.selected);
        false
    }
}

/// A package's hard dependency groups, its `Pre-Depends` then its `Depends`,
/// held apart from the package so the selection can change while they are
/// walked.
fn relations(package: &Package) -> Vec<Dependency> {
    package
        .pre_depends
        .iter()
        .chain(package.depends.iter())
        .cloned()
        .collect()
}

/// Splits an install list entry into the package it names and the release it
/// names it from, where it is written `name/release`.
///
/// A Debian package name holds no `/`, so the first one ends the name and
/// everything after it is the release, which may itself name a subtree.
pub(super) fn split_release(entry: &str) -> (&str, Option<&str>) {
    match entry.split_once('/') {
        Some((name, release)) => (name, Some(release)),
        None => (entry, None),
    }
}

/// Which version each name resolves to in one resolution.
///
/// The index's candidate, unless an install list entry named a release for the
/// name or for something that needed it, or the base layer has the name
/// installed, in which case only an upgrade apt would take is a version to
/// select at all. Each of those answers comes from the [`Index`], which answers
/// a name the pin holds with its pinned version alone, so no route selects a
/// pinned name at another version.
struct Candidates<'a> {
    index: &'a Index,
    installed: &'a InstalledSet,
    /// The versions an entry written `name/release` switched to: its own, and
    /// those of the versioned dependencies it switched to the same release.
    targeted: HashMap<String, Package>,
}

impl<'a> Candidates<'a> {
    /// The version `name` resolves to where it has to be selected, or `None`
    /// where no version is to be: a name nothing offers, or one the base has
    /// installed that apt would not upgrade.
    fn of(&self, name: &str) -> Option<&Package> {
        if let Some(package) = self.targeted.get(name) {
            return Some(package);
        }
        match self.installed.installed(name) {
            Some(version) => self.index.upgrade_over(name, version),
            None => self.index.get(name),
        }
    }

    /// Whether an install list entry switched `name` to a release's version.
    fn is_targeted(&self, name: &str) -> bool {
        self.targeted.contains_key(name)
    }

    /// The version a package the base keeps is upgraded to where the merged
    /// set breaks one of its dependencies or clashes with it: the one
    /// [`of`](Self::of) offers, as apt upgrades an installed package an
    /// upgrade breaks.
    ///
    /// `None` for a package the caller excluded, and for one whose installed
    /// version the status database does not state, which is no version to
    /// upgrade from.
    fn upgrade(&self, name: &str, excluded: &HashSet<&str>) -> Option<&Package> {
        if excluded.contains(name) || self.installed.installed(name).is_none() {
            return None;
        }
        self.of(name)
    }

    /// Switches `package`'s name to that version, then each versioned
    /// dependency of it that nothing else meets to the version `release`
    /// offers, where that one meets it, and that version's dependencies the
    /// same way: apt's handling of `name/release`.
    ///
    /// A dependency group is left alone where the base meets it, or a
    /// candidate or a provider does and can itself be installed as things
    /// stand ([`installable`](Self::installable)). So a release is reached
    /// into only as far as the entry needs it, and a candidate that meets the
    /// constraint but needs the release's versions in turn is walked as a
    /// switch would be: a backports kernel metapackage names an image only
    /// backports carries, and that image needs a newer `linux-base`. A switch
    /// can only help a versioned dependency, so the search through a group's
    /// alternatives stops at the first unversioned one, as apt's does. A
    /// version already switched to is not walked again, which is what ends a
    /// cycle.
    ///
    /// A name the pin holds is switched only to its pinned version, where the
    /// release offers that. One the release offers at another version is
    /// passed over like an excluded one, so the group is left to a later
    /// alternative, or to [`resolve_group`] to refuse as the pin's.
    fn target(&mut self, package: &'a Package, release: &str, excluded: &HashSet<&str>) {
        self.targeted.insert(package.name.clone(), package.clone());
        let groups: Vec<&Dependency> = package
            .pre_depends
            .iter()
            .chain(package.depends.iter())
            .collect();
        for group in groups {
            let met = group.iter().any(|atom| {
                self.base_supplies(atom)
                    || self.of(&atom.name).is_some_and(|candidate| {
                        meets(atom.constraint.as_ref(), &candidate.version)
                            && self.installable(candidate, excluded)
                    })
                    || first_available_provider(self, atom, excluded).is_some_and(|provider| {
                        self.of(&provider)
                            .is_some_and(|candidate| self.installable(candidate, excluded))
                    })
            });
            if met {
                continue;
            }
            for atom in group {
                let Some(constraint) = atom.constraint.as_ref() else {
                    break;
                };
                if excluded.contains(atom.name.as_str()) {
                    continue;
                }
                let Ok(Some(version)) = self.index.in_release(&atom.name, release) else {
                    continue;
                };
                if !constraint.satisfied_by(&version.version) {
                    continue;
                }
                let switched = self.targeted.get(&atom.name).is_some_and(|held| {
                    held.origin == version.origin && held.version == version.version
                });
                if !switched {
                    self.target(version, release, excluded);
                }
                break;
            }
        }
    }

    /// Whether every dependency group of `package` has an answer as things
    /// stand: the base, a candidate at a version the group accepts, or a
    /// provider. One level deep, as the question apt asks before it leaves a
    /// candidate alone is (its `DepCandMin`).
    fn installable(&self, package: &Package, excluded: &HashSet<&str>) -> bool {
        package
            .pre_depends
            .iter()
            .chain(package.depends.iter())
            .all(|group| {
                group.iter().any(|atom| {
                    self.base_supplies(atom)
                        || (!excluded.contains(atom.name.as_str())
                            && self.of(&atom.name).is_some_and(|candidate| {
                                meets(atom.constraint.as_ref(), &candidate.version)
                            }))
                        || first_available_provider(self, atom, excluded).is_some()
                })
            })
    }

    /// Whether the base, whole, supplies `atom`.
    ///
    /// The question an install list entry's switch asks: it is asked before
    /// anything is selected, so no replacement has taken a supply away yet.
    fn base_supplies(&self, atom: &DepAtom) -> bool {
        base_satisfies(self.installed, &BTreeMap::new(), atom)
    }
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
/// A group whose satisfier the base layer already supplies is satisfied by the
/// base and pulls nothing, provided the base supplies it at a version the
/// constraint accepts and the selection has not replaced the package supplying
/// it. Where it does not, the name is upgraded into the increment only as
/// [`Candidates::of`] allows. A group nothing answers where a supply the
/// selection took away would have is refused as [`Refusal::Broken`], naming
/// the replacement, since that is what is in the way.
///
/// A name the pin holds answers only at its pinned version. A group left
/// unsatisfied where an alternative names a pinned package at a version the
/// pinned one does not meet is refused as [`Refusal::Pinned`], naming the
/// first such alternative, since without the pin a version that does meet it
/// may be there to take. An exclusion is reported ahead of a pin: it removes
/// the name whatever version would have answered.
///
/// An answer that clashes with the root as it stands is passed over for the
/// next one that does not ([`fits`]): the real package an alternative names,
/// then each of its providers, then the next alternative, as apt 2.8 passes
/// one over. Where every answer clashes, the first is taken all the same, and
/// the merged set's check refuses the clash it brings, naming both packages
/// and the entry, which says more than refusing the group would.
fn resolve_group(
    candidates: &Candidates<'_>,
    group: &Dependency,
    excluded: &HashSet<&str>,
    required_by: &str,
    selected: &mut BTreeMap<String, Package>,
    queue: &mut VecDeque<String>,
) -> Option<Refusal> {
    let index = candidates.index;
    // An excluded package is never added to `selected`, so a satisfied check
    // over `selected` already ignores exclusions. The base's map carries both
    // its real names and the virtuals those packages provide, so one lookup
    // covers a group the base satisfies either way — and carries the versions,
    // so a constrained group is answered by the version actually there rather
    // than by the name being present.
    if group
        .iter()
        .any(|atom| merged_satisfies(candidates, selected, atom))
    {
        return None;
    }
    // Try each alternative in order, preferring the real package named then a
    // provider — the resolver's existing discipline. Remember an excluded name
    // that would otherwise have satisfied the group, so a group left
    // unsatisfied solely by exclusion can be reported against it.
    let mut blocked: Option<String> = None;
    let mut pinned: Option<UnheldPin> = None;
    // The first answer, where every answer clashes.
    let mut clashing: Option<&Package> = None;
    for atom in group {
        if excluded.contains(atom.name.as_str()) {
            // The real package is excluded. One name can be both a real
            // package and a virtual that others provide, so a provider may
            // still satisfy the group — which is what apt's own deselection
            // does. Fall through to the provider lookup, remembering the
            // exclusion in case nothing else answers.
            if index.get(&atom.name).is_some() {
                blocked.get_or_insert_with(|| atom.name.clone());
            }
        } else if let Some(package) = candidates.of(&atom.name) {
            // The candidate counts only if it actually meets the constraint.
            // When it does not, this alternative is no answer and the search
            // continues — a provider may still supply the name at a version
            // that is, and a later alternative may too.
            if meets(atom.constraint.as_ref(), &package.version) {
                if fits(candidates, excluded, selected, package) {
                    add(selected, queue, package);
                    return None;
                }
                clashing.get_or_insert(package);
            }
        }
        if pinned.is_none() && !excluded.contains(atom.name.as_str()) {
            pinned = index.pins().refuse_requirement(
                &atom.name,
                atom.constraint.as_ref(),
                &render_group(group),
                required_by,
            );
        }
        for provider in available_providers(candidates, atom, excluded) {
            let package = candidates
                .of(provider)
                .expect("a provider is a real package");
            if fits(candidates, excluded, selected, package) {
                add(selected, queue, package);
                return None;
            }
            clashing.get_or_insert(package);
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
    if let Some(package) = clashing {
        add(selected, queue, package);
        return None;
    }
    match (blocked, pinned) {
        (Some(package), _) => Some(Refusal::ExcludedButRequired {
            package,
            required_by: required_by.to_string(),
        }),
        (None, Some(unheld)) => Some(Refusal::Pinned {
            requirement: render_group(group),
            required_by: required_by.to_string(),
            unheld,
        }),
        // Nothing was excluded or pinned, and nothing satisfies the group: the
        // archive offers none of these names, or offers them only at versions
        // the constraint rules out, and the base supplies none, or supplied one
        // the selection replaced. Either way the closure is incomplete, and
        // shipping it would produce a root whose packages cannot work.
        (None, None) => {
            let replaced = replacements(candidates.installed, selected, group);
            Some(if replaced.is_empty() {
                Refusal::Unsatisfiable {
                    requirement: render_group(group),
                    required_by: required_by.to_string(),
                    available: describe_available(candidates, selected, group),
                }
            } else {
                Refusal::Broken {
                    requirement: render_group(group),
                    required_by: required_by.to_string(),
                    offered: describe_merged(candidates, selected, group),
                    replaced,
                }
            })
        }
    }
}

/// Whether `version` meets `constraint`. An absent constraint is met by any
/// version, which is what an unversioned dependency asks.
fn meets(constraint: Option<&Constraint>, version: &str) -> bool {
    constraint.is_none_or(|c| c.satisfied_by(version))
}

/// Whether a name supplied at `version` answers `constraint`: [`meets`] for a
/// supply that states a version.
///
/// A bare `Provides` states none, which supplies only an unversioned
/// dependency: Policy 7.5 gives an unversioned provide no version to compare,
/// so it cannot answer a versioned question.
fn answers(version: Option<&str>, constraint: Option<&Constraint>) -> bool {
    match version {
        Some(version) => meets(constraint, version),
        None => constraint.is_none(),
    }
}

/// Whether the root a resolution produces satisfies `atom`: a package it
/// selected, or one of the base's supplies its selection leaves standing.
fn merged_satisfies(
    candidates: &Candidates<'_>,
    selected: &BTreeMap<String, Package>,
    atom: &DepAtom,
) -> bool {
    base_satisfies(candidates.installed, selected, atom)
        || selected_satisfies(candidates.index, selected, atom)
}

/// The base's supplies of `name` that `selected` leaves standing: every one
/// but those of a package the selection replaces, which takes them away.
fn kept<'s>(
    installed: &'s InstalledSet,
    selected: &'s BTreeMap<String, Package>,
    name: &str,
) -> impl Iterator<Item = &'s Supply> {
    installed
        .supplied(name)
        .iter()
        .filter(|supply| !selected.contains_key(&supply.provider))
}

/// Whether what the base keeps beside `selected` supplies `atom` — the name, at
/// a version its constraint accepts.
fn base_satisfies(
    installed: &InstalledSet,
    selected: &BTreeMap<String, Package>,
    atom: &DepAtom,
) -> bool {
    kept(installed, selected, &atom.name)
        .any(|supply| answers(supply.version.as_deref(), atom.constraint.as_ref()))
}

/// The base packages `selected` replaces that supplied one of `group`'s names
/// at a version its alternative accepts, in name order: what took away an
/// answer the group had in the base.
fn replacements(
    installed: &InstalledSet,
    selected: &BTreeMap<String, Package>,
    group: &Dependency,
) -> Vec<Replacement> {
    let mut replaced: BTreeMap<&str, Replacement> = BTreeMap::new();
    for atom in group {
        for supply in installed.supplied(&atom.name) {
            if !answers(supply.version.as_deref(), atom.constraint.as_ref()) {
                continue;
            }
            let Some(package) = selected.get(&supply.provider) else {
                continue;
            };
            replaced
                .entry(package.name.as_str())
                .or_insert_with(|| Replacement {
                    package: package.name.clone(),
                    installed: installed.installed(&package.name).map(str::to_string),
                    version: package.version.clone(),
                });
        }
    }
    replaced.into_values().collect()
}

/// The selected packages answering any alternative of `group`, by name or by
/// `Provides`.
fn group_answers(
    index: &Index,
    selected: &BTreeMap<String, Package>,
    group: &Dependency,
) -> Vec<String> {
    group
        .iter()
        .flat_map(|atom| selected_answers(index, selected, atom))
        .map(|package| package.name.clone())
        .collect()
}

/// The selected packages answering `atom`: the one of its name, at a version
/// the constraint accepts, then each whose `Provides` answers it.
fn selected_answers<'s>(
    index: &'s Index,
    selected: &'s BTreeMap<String, Package>,
    atom: &'s DepAtom,
) -> impl Iterator<Item = &'s Package> {
    let real = selected
        .get(&atom.name)
        .filter(|package| meets(atom.constraint.as_ref(), &package.version));
    let providers = index
        .providers(&atom.name)
        .iter()
        .filter_map(|provider| selected.get(provider))
        .filter(|package| provides_satisfies(package, atom));
    real.into_iter().chain(providers)
}

/// Whether the already-selected packages satisfy `atom`, by real name or by a
/// selected package's `Provides`.
fn selected_satisfies(index: &Index, selected: &BTreeMap<String, Package>, atom: &DepAtom) -> bool {
    selected_answers(index, selected, atom).next().is_some()
}

/// Whether `package`'s `Provides` supplies `atom`'s name at a version the
/// constraint accepts.
fn provides_satisfies(package: &Package, atom: &DepAtom) -> bool {
    package
        .provides
        .iter()
        .filter(|provided| provided.name == atom.name)
        .any(|provided| answers(provided.version.as_deref(), atom.constraint.as_ref()))
}

/// Renders a dependency group the way its package declares it, so the error
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
/// line: what the archives offer, and what the base keeps.
///
/// This is what separates the two failures a reader has to tell apart — a name
/// no archive carries, and a name carried at the wrong version. A version a
/// release other than the candidate's offers is named with its release, since
/// that is the one an install list entry written `name/release` would take.
/// `None` when the group's names are simply absent everywhere.
fn describe_available(
    candidates: &Candidates<'_>,
    selected: &BTreeMap<String, Package>,
    group: &Dependency,
) -> Option<String> {
    let index = candidates.index;
    let mut found: Vec<String> = Vec::new();
    for atom in group {
        let offers = index.offers(&atom.name);
        if let Some((candidate, others)) = offers.split_first() {
            found.push(format!(
                "{} {} in the archive",
                atom.name, candidate.version
            ));
            for other in others
                .iter()
                .filter(|other| other.version != candidate.version)
            {
                found.push(format!(
                    "{} {} in {}",
                    atom.name,
                    other.version,
                    index.suite(other.origin)
                ));
            }
        }
        found.extend(base_kept(candidates.installed, selected, &atom.name));
    }
    (!found.is_empty()).then(|| found.join("; "))
}

/// What the root a layered resolution produces holds for a group's names, for
/// a [`Refusal::Broken`]: what the increment installs, by real name or by
/// `Provides`, and what the base keeps. `None` where it holds none of them.
fn describe_merged(
    candidates: &Candidates<'_>,
    selected: &BTreeMap<String, Package>,
    group: &Dependency,
) -> Option<String> {
    let mut found: Vec<String> = Vec::new();
    for atom in group {
        let mut versions: Vec<&str> = Vec::new();
        if let Some(package) = selected.get(&atom.name) {
            versions.push(&package.version);
        }
        for provider in candidates.index.providers(&atom.name) {
            let Some(package) = selected.get(provider) else {
                continue;
            };
            versions.extend(
                package
                    .provides
                    .iter()
                    .filter(|provided| provided.name == atom.name)
                    .map(|provided| provided.version.as_deref().unwrap_or("no version")),
            );
        }
        if !versions.is_empty() {
            found.push(format!(
                "{} {} in the increment",
                atom.name,
                versions.join(", ")
            ));
        }
        found.extend(base_kept(candidates.installed, selected, &atom.name));
    }
    (!found.is_empty()).then(|| found.join("; "))
}

/// The versions the base keeps `name` at beside `selected`, as an evidence line
/// names them, or `None` where it keeps none.
fn base_kept(
    installed: &InstalledSet,
    selected: &BTreeMap<String, Package>,
    name: &str,
) -> Option<String> {
    let versions: Vec<&str> = kept(installed, selected, name)
        .map(|supply| supply.version.as_deref().unwrap_or("no version"))
        .collect();
    (!versions.is_empty()).then(|| format!("{name} {} in the base layer", versions.join(", ")))
}

/// The first provider of `atom`'s virtual name that is not excluded and whose
/// version supplies it at a version the constraint accepts, or `None` when no
/// provider qualifies. Providers are held in sorted order, so the choice is
/// deterministic.
fn first_available_provider(
    candidates: &Candidates<'_>,
    atom: &DepAtom,
    excluded: &HashSet<&str>,
) -> Option<String> {
    available_providers(candidates, atom, excluded)
        .next()
        .cloned()
}

/// Every provider of `atom`'s virtual name that is not excluded and whose
/// version supplies it at a version the constraint accepts, in name order.
fn available_providers<'c>(
    candidates: &'c Candidates<'_>,
    atom: &'c DepAtom,
    excluded: &'c HashSet<&str>,
) -> impl Iterator<Item = &'c String> {
    candidates
        .index
        .providers(&atom.name)
        .iter()
        .filter(move |provider| {
            !excluded.contains(provider.as_str())
                && candidates
                    .of(provider)
                    .is_some_and(|package| provides_satisfies(package, atom))
        })
}

/// One package of the root a resolution produces, as a [`Clash`] asks about
/// it: one the resolution selects, or one a layered build's base keeps.
#[derive(Debug, Clone, Copy)]
struct Member<'r> {
    name: &'r str,
    /// The version, which a base package's status database may not state.
    version: Option<&'r str>,
    provides: &'r [Provided],
    clashes: &'r [Clash],
    multi_arch_allowed: bool,
    /// Whether the base keeps it, rather than the resolution selecting it.
    in_base: bool,
}

impl<'r> Member<'r> {
    /// A package the resolution selects.
    fn selected(package: &'r Package) -> Member<'r> {
        Member {
            name: &package.name,
            version: Some(&package.version),
            provides: &package.provides,
            clashes: &package.clashes,
            multi_arch_allowed: package.multi_arch_allowed,
            in_base: false,
        }
    }

    /// The package `name` the base keeps.
    fn kept(name: &'r str, package: &'r Installed) -> Member<'r> {
        Member {
            name,
            version: package.version.as_deref(),
            provides: &package.provides,
            clashes: &package.clashes,
            multi_arch_allowed: package.multi_arch_allowed,
            in_base: true,
        }
    }

    /// Whether `clash`, stated by another package, names this one: by its
    /// own name or by a name it provides, at a version the entry's constraint
    /// accepts, as a dependency on the same name would be answered.
    fn named_by(&self, clash: &Clash) -> bool {
        let atom = &clash.atom;
        let constraint = atom.constraint.as_ref();
        (!clash.any || self.multi_arch_allowed)
            && ((self.name == atom.name && answers(self.version, constraint))
                || self.provides.iter().any(|provided| {
                    provided.name == atom.name && answers(provided.version.as_deref(), constraint)
                }))
    }

    /// The package as a refusal names it, `name version`.
    fn describe(&self) -> String {
        match self.version {
            Some(version) => format!("{} {version}", self.name),
            None => self.name.to_string(),
        }
    }
}

/// One clash between two members of the root: who states it, the entry, and
/// what it names.
struct Clashing<'r> {
    stated_by: Member<'r>,
    clash: &'r Clash,
    against: Member<'r>,
}

impl Clashing<'_> {
    /// The clash as a refusal reports it.
    fn conflict(&self) -> Conflict {
        Conflict {
            relation: self.clash.to_string(),
            stated_by: self.stated_by.describe(),
            stated_in_base: self.stated_by.in_base,
            against: self.against.describe(),
            against_in_base: self.against.in_base,
        }
    }
}

/// The members of the root that supply `name`, as a clash on it could name
/// them: the selected package of that name and each selected provider of it,
/// then each package the base keeps supplying it. A package is listed once
/// however many ways it supplies the name.
fn supplying<'r>(
    candidates: &'r Candidates<'_>,
    selected: &'r BTreeMap<String, Package>,
    name: &str,
) -> Vec<Member<'r>> {
    let mut members: Vec<Member<'r>> = Vec::new();
    let real = selected.get(name).into_iter();
    let providers = candidates
        .index
        .providers(name)
        .iter()
        .filter_map(|provider| selected.get(provider));
    for package in real.chain(providers) {
        if !members.iter().any(|member| member.name == package.name) {
            members.push(Member::selected(package));
        }
    }
    let installed = candidates.installed;
    for supply in kept(installed, selected, name) {
        if members.iter().any(|member| member.name == supply.provider) {
            continue;
        }
        if let Some(package) = installed.package(&supply.provider) {
            members.push(Member::kept(&supply.provider, package));
        }
    }
    members
}

/// The members of the root stating a clash on `name`: the selected ones, then
/// those the base keeps.
fn stating<'r>(
    candidates: &'r Candidates<'_>,
    selected: &'r BTreeMap<String, Package>,
    name: &str,
) -> Vec<Member<'r>> {
    let installed = candidates.installed;
    let chosen = candidates
        .index
        .clashing(name)
        .iter()
        .filter_map(|stater| selected.get(stater))
        .map(Member::selected);
    let base = installed
        .clashing(name)
        .iter()
        .filter(|stater| !selected.contains_key(stater.as_str()))
        .filter_map(|stater| {
            installed
                .package(stater)
                .map(|package| Member::kept(stater, package))
        });
    chosen.chain(base).collect()
}

/// Every clash `member` states against the rest of the root.
///
/// A member never clashes with a package of its own name, which is itself or
/// the base package it replaces.
fn stated<'r>(
    candidates: &'r Candidates<'_>,
    selected: &'r BTreeMap<String, Package>,
    member: Member<'r>,
) -> Vec<Clashing<'r>> {
    let mut found = Vec::new();
    for clash in member.clashes {
        for against in supplying(candidates, selected, &clash.atom.name) {
            if against.name != member.name && against.named_by(clash) {
                found.push(Clashing {
                    stated_by: member,
                    clash,
                    against,
                });
            }
        }
    }
    found
}

/// Every clash between `member` and the rest of the root, in either direction:
/// those it states, then those stated against it.
fn clashes<'r>(
    candidates: &'r Candidates<'_>,
    selected: &'r BTreeMap<String, Package>,
    member: Member<'r>,
) -> Vec<Clashing<'r>> {
    let mut found = stated(candidates, selected, member);
    let mut names: Vec<&str> = vec![member.name];
    names.extend(
        member
            .provides
            .iter()
            .map(|provided| provided.name.as_str()),
    );
    names.sort_unstable();
    names.dedup();
    for name in names {
        for stated_by in stating(candidates, selected, name) {
            if stated_by.name == member.name {
                continue;
            }
            for clash in stated_by.clashes {
                if clash.atom.name == name && member.named_by(clash) {
                    found.push(Clashing {
                        stated_by,
                        clash,
                        against: member,
                    });
                }
            }
        }
    }
    found
}

/// Whether `package` can join the root as it stands without a clash nothing
/// resolves.
///
/// A clash with a selected package is never resolved: the walk does not go
/// back on what it chose. One with a package the base keeps is resolved where
/// that package's upgrade ([`Candidates::upgrade`]) clashes with `package` in
/// neither direction, since the merged set's check then takes the upgrade, as
/// apt upgrades a package before it would remove it.
fn fits(
    candidates: &Candidates<'_>,
    excluded: &HashSet<&str>,
    selected: &BTreeMap<String, Package>,
    package: &Package,
) -> bool {
    let member = Member::selected(package);
    clashes(candidates, selected, member).iter().all(|clash| {
        let base = if clash.stated_by.in_base {
            clash.stated_by
        } else {
            clash.against
        };
        base.in_base
            && candidates
                .upgrade(base.name, excluded)
                .is_some_and(|upgrade| !clash_between(Member::selected(upgrade), member))
    })
}

/// Whether either of two packages states a clash naming the other.
fn clash_between(one: Member<'_>, other: Member<'_>) -> bool {
    one.name != other.name
        && (one.clashes.iter().any(|clash| other.named_by(clash))
            || other.clashes.iter().any(|clash| one.named_by(clash)))
}

/// Every clash the root holds, as the refusals report them: each stated by a
/// selected package, then each stated by a package the base keeps, every
/// party in name order.
fn root_conflicts(
    candidates: &Candidates<'_>,
    selected: &BTreeMap<String, Package>,
) -> Vec<Conflict> {
    let installed = candidates.installed;
    let chosen = selected.values().map(Member::selected);
    let base = installed
        .members()
        .filter(|(name, _)| !selected.contains_key(*name))
        .map(|(name, package)| Member::kept(name, package));
    let mut conflicts = Vec::new();
    for member in chosen.chain(base) {
        for clashing in stated(candidates, selected, member) {
            // A field naming one package twice, or a package supplying the
            // name twice, is one conflict to report.
            let conflict = clashing.conflict();
            if !conflicts.contains(&conflict) {
                conflicts.push(conflict);
            }
        }
    }
    conflicts
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
    use super::super::index::{Priority, fixture};
    use super::super::pin::Pins;
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
        /// Every conflict, asserting the resolution refused no dependency.
        fn into_conflicts(self) -> Vec<Conflict>;
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
            let Refusals {
                mut refused,
                conflicts,
            } = refusals;
            match (refused.len(), conflicts.len()) {
                (1, 0) => refused.remove(0),
                (0, 0) => panic!("expected a refusal, resolved {:?}", names(&packages)),
                (count, _) => panic!(
                    "expected exactly one refusal, got {count} and {} conflicts: {}",
                    conflicts.len(),
                    Refusals { refused, conflicts }.describe(),
                ),
            }
        }

        fn into_conflicts(self) -> Vec<Conflict> {
            let (packages, refusals) = self;
            assert!(
                refusals.refused.is_empty(),
                "expected only conflicts, and it refused: {}",
                refusals.describe(),
            );
            assert!(
                !refusals.conflicts.is_empty(),
                "expected a conflict, resolved {:?}",
                names(&packages),
            );
            refusals.conflicts
        }
    }

    fn index(text: &str) -> Index {
        Index::parse(text, "amd64")
    }

    fn names(packages: &[Package]) -> Vec<String> {
        packages.iter().map(|p| p.name.clone()).collect()
    }

    /// A stanza offering `name` at 1.0 with `deps` as its `Depends` and
    /// `extra` fields after them.
    fn stanza(name: &str, deps: &str, extra: &str) -> String {
        stanza_at(name, "1.0", deps, extra)
    }

    #[test]
    fn closure_follows_depends_and_pre_depends() {
        let text = format!(
            "{}{}{}",
            stanza("aa", "bb", "Pre-Depends: cc"),
            stanza("bb", "", ""),
            stanza("cc", "", ""),
        );
        let selected = resolve(&index(&text), &["aa".into()], &[], &[]).into_packages();
        assert_eq!(names(&selected), ["aa", "bb", "cc"]);
    }

    #[test]
    fn first_alternative_is_taken() {
        let text = format!(
            "{}{}{}",
            stanza("aa", "xx | yy", ""),
            stanza("xx", "", ""),
            stanza("yy", "", "")
        );
        let selected = resolve(&index(&text), &["aa".into()], &[], &[]).into_packages();
        assert_eq!(names(&selected), ["aa", "xx"]);
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

    /// Resolves `includes` with nothing seeded besides, as `apt-get install`
    /// with them on its command line on a system with nothing installed.
    fn install(index: &Index, includes: &[&str]) -> (Vec<Package>, Refusals) {
        let includes: Vec<String> = includes.iter().map(|name| name.to_string()).collect();
        resolve(index, &[], &includes, &[])
    }

    /// Each conflict a refused resolution reports, as one sentence each.
    fn conflicts(resolution: (Vec<Package>, Refusals)) -> Vec<String> {
        resolution
            .into_conflicts()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    // The conflict tests pin what apt 2.8.4 answers for the same index: each
    // was measured with `apt-get --simulate install`, against a flat `file:`
    // repository holding these stanzas and a status database holding the
    // base, before it was written here.

    #[test]
    fn an_alternative_that_clashes_with_the_selection_is_passed_over() {
        // apt takes cc for aa's `bb | cc` whichever of bb and xx states the
        // clash, and whether it is a Conflicts or a Breaks.
        for (b, x) in [
            ("Conflicts: xx", ""),
            ("", "Conflicts: bb"),
            ("Breaks: xx", ""),
            ("", "Breaks: bb"),
        ] {
            let text = format!(
                "{}{}{}{}",
                stanza("aa", "bb | cc", ""),
                stanza("bb", "", b),
                stanza("cc", "", ""),
                stanza("xx", "", x),
            );
            let selected = install(&index(&text), &["xx", "aa"]).into_packages();
            assert_eq!(names(&selected), ["aa", "cc", "xx"], "{b:?} {x:?}");
        }
    }

    #[test]
    fn a_provider_that_clashes_is_passed_over_for_the_next() {
        // p1 is the provider the resolver takes first, and it conflicts with
        // xx, so p2 answers. Where every provider clashes, the next
        // alternative does.
        let text = format!(
            "{}{}{}{}{}",
            stanza("aa", "vv", ""),
            stanza("p1", "", "Provides: vv\nConflicts: xx"),
            stanza("p2", "", "Provides: vv"),
            stanza("xx", "", ""),
            stanza("dd", "ww | cc", ""),
        );
        let text = format!(
            "{text}{}{}",
            stanza("qq", "", "Provides: ww\nBreaks: xx"),
            stanza("cc", "", ""),
        );
        let index = index(&text);
        assert_eq!(
            names(&install(&index, &["xx", "aa"]).into_packages()),
            ["aa", "p2", "xx"],
        );
        assert_eq!(
            names(&install(&index, &["aa"]).into_packages()),
            ["aa", "p1"],
            "a clash with nothing selected is no reason to pass p1 over",
        );
        assert_eq!(
            names(&install(&index, &["xx", "dd"]).into_packages()),
            ["cc", "dd", "xx"],
        );
    }

    #[test]
    fn a_versioned_breaks_names_only_the_versions_it_states() {
        // bb breaks the xx before 2, so xx 2 stands beside it and xx 1 does
        // not.
        for (version, expected) in [("2", ["aa", "bb", "xx"]), ("1", ["aa", "cc", "xx"])] {
            let text = format!(
                "{}{}{}{}",
                stanza("aa", "bb | cc", ""),
                stanza("bb", "", "Breaks: xx (<< 2)"),
                stanza("cc", "", ""),
                stanza_at("xx", version, "", ""),
            );
            let selected = install(&index(&text), &["xx", "aa"]).into_packages();
            assert_eq!(names(&selected), expected, "xx {version}");
        }
    }

    #[test]
    fn a_package_conflicting_with_a_name_it_provides_keeps_out_only_the_others() {
        // The idiom every mail transport agent states: it conflicts with,
        // provides, and replaces `mail-transport-agent`, so no two are
        // installed, and each stands beside its own provide.
        let mta = "Provides: mta\nConflicts: mta\nReplaces: mta";
        let text = format!(
            "{}{}{}",
            stanza("aa", "mta", ""),
            stanza("exim", "", mta),
            stanza("postfix", "", mta),
        );
        let index = index(&text);
        assert_eq!(
            names(&install(&index, &["postfix", "aa"]).into_packages()),
            ["aa", "postfix"],
        );
        assert_eq!(
            conflicts(install(&index, &["postfix", "exim"])),
            [
                "exim 1.0 states \"Conflicts: mta\", and the resolution selects postfix 1.0 too",
                "postfix 1.0 states \"Conflicts: mta\", and the resolution selects exim 1.0 too",
            ],
        );
    }

    #[test]
    fn a_clash_on_a_virtual_name_names_each_provider_its_constraint_accepts() {
        // An unversioned entry names every provider. A versioned one names a
        // provider only at a version it states that the constraint accepts,
        // as a versioned dependency is answered only by one.
        let text = format!(
            "{}{}{}{}{}",
            stanza("bb", "", "Conflicts: vv"),
            stanza("versioned", "", "Conflicts: vv (<< 2)"),
            stanza("bare", "", "Provides: vv"),
            stanza("old", "", "Provides: vv (= 1)"),
            stanza("new", "", "Provides: vv (= 3)"),
        );
        let index = index(&text);
        assert_eq!(
            conflicts(install(&index, &["bb", "bare"])),
            ["bb 1.0 states \"Conflicts: vv\", and the resolution selects bare 1.0 too"],
        );
        for provider in ["bare", "new"] {
            install(&index, &["versioned", provider]).expecting(provider);
        }
        assert_eq!(
            conflicts(install(&index, &["versioned", "old"])),
            [
                "versioned 1.0 states \"Conflicts: vv (<< 2)\", and the resolution selects \
                 old 1.0 too"
            ],
        );
    }

    #[test]
    fn an_architecture_qualifier_names_what_apt_names() {
        // In a resolution of one architecture, `:native` and the native
        // architecture name what an unqualified entry names, another
        // architecture names nothing, `all` included, and `:any` names only a
        // package `Multi-Arch: allowed`.
        let text = format!(
            "{}{}{}{}{}{}{}",
            stanza("xx", "", ""),
            stanza("allowed", "", "Multi-Arch: allowed"),
            stanza("native", "", "Conflicts: xx:amd64"),
            stanza("named", "", "Conflicts: xx:native"),
            stanza("foreign", "", "Conflicts: xx:i386"),
            stanza("indep", "", "Conflicts: xx:all"),
            stanza("any", "", "Breaks: xx:any, allowed:any"),
        );
        let index = index(&text);
        for stater in ["native", "named"] {
            assert_eq!(
                conflicts(install(&index, &[stater, "xx"])),
                [format!(
                    "{stater} 1.0 states \"Conflicts: xx\", and the resolution selects xx 1.0 too"
                )],
            );
        }
        for stater in ["foreign", "indep", "any"] {
            install(&index, &[stater, "xx"]).expecting(stater);
        }
        assert_eq!(
            conflicts(install(&index, &["any", "allowed"])),
            [
                "any 1.0 states \"Breaks: allowed:any\", and the resolution selects allowed \
                 1.0 too"
            ],
        );
    }

    #[test]
    fn a_clash_no_choice_avoids_is_refused_naming_both_packages() {
        // aa needs both, and bb conflicts with cc. apt fails, naming aa's
        // dependency on cc; the refusal names the entry that is in the way.
        let text = format!(
            "{}{}{}",
            stanza("aa", "bb, cc", ""),
            stanza("bb", "", "Conflicts: cc"),
            stanza("cc", "", ""),
        );
        let resolution = install(&index(&text), &["aa"]);
        assert_eq!(
            conflicts(resolution),
            ["bb 1.0 states \"Conflicts: cc\", and the resolution selects cc 1.0 too"],
        );
    }

    #[test]
    fn a_choice_a_later_selection_clashes_with_is_refused_rather_than_made_again() {
        // aa's `bb | cc` is met before anything selects xx, so bb is taken,
        // and zz's xx then clashes with it. apt 2.8 takes bb and fails on xx the same
        // way; it does not go back on the choice either. Met the other way
        // round, xx is there to avoid.
        let text = format!(
            "{}{}{}{}{}",
            stanza("aa", "bb | cc", ""),
            stanza("bb", "", "Conflicts: xx"),
            stanza("cc", "", ""),
            stanza("xx", "", ""),
            stanza("zz", "xx", ""),
        );
        let index = index(&text);
        assert_eq!(
            conflicts(install(&index, &["aa", "zz"])),
            ["bb 1.0 states \"Conflicts: xx\", and the resolution selects xx 1.0 too"],
        );
        assert_eq!(
            names(&install(&index, &["zz", "aa"]).into_packages()),
            ["aa", "cc", "xx", "zz"],
        );
    }

    #[test]
    fn a_package_a_later_selection_clashes_with_is_unselected_where_apt_unmarks_it() {
        // bb answers mm's `bb | cc` before anything selects xx, which ww needs
        // and nothing else answers, and xx conflicts with bb. apt unmarks bb
        // and what it marked for bb, and answers mm with cc; so does the
        // resolution, for a Breaks as for a Conflicts.
        let packages = |relation: &str, mm: &str| {
            index(&format!(
                "{}{}{}{}{}{}{}",
                stanza("aa", "mm, ww", ""),
                stanza("mm", mm, ""),
                stanza("bb", "dd", ""),
                stanza("dd", "", ""),
                stanza("cc", "", ""),
                stanza("ww", "xx", ""),
                stanza("xx", "", &format!("{relation}: bb")),
            ))
        };
        for relation in ["Conflicts", "Breaks"] {
            let selected = install(&packages(relation, "bb | cc"), &["aa"]).into_packages();
            assert_eq!(
                names(&selected),
                ["aa", "cc", "mm", "ww", "xx"],
                "{relation}"
            );
        }
        // A package the install list names is not unselected, and nor is one
        // nothing else answers: apt fails on both.
        let expected = ["xx 1.0 states \"Conflicts: bb\", and the resolution selects bb 1.0 too"];
        assert_eq!(
            conflicts(install(&packages("Conflicts", "bb | cc"), &["aa", "bb"])),
            expected,
        );
        assert_eq!(
            conflicts(install(&packages("Conflicts", "bb"), &["aa"])),
            expected,
        );
    }

    #[test]
    fn the_walk_marks_depth_first_in_the_order_apt_does() {
        // xx is two levels below zz, and bb conflicts with it. apt walks zz
        // whole before aa, so xx is there when aa's `bb | cc` is met, and cc
        // answers; a walk taking zz's and aa's groups level by level would
        // meet `bb | cc` first, take bb, and refuse xx after it.
        let shared = format!(
            "{}{}{}{}{}",
            stanza("mm", "xx", ""),
            stanza("bb", "", "Conflicts: xx"),
            stanza("cc", "", ""),
            stanza("xx", "", ""),
            stanza("zz", "mm", ""),
        );
        let index_with = |aa: &str| index(&format!("{shared}{aa}"));
        let walked = install(&index_with(&stanza("aa", "bb | cc", "")), &["zz", "aa"]);
        assert_eq!(
            names(&walked.into_packages()),
            ["aa", "cc", "mm", "xx", "zz"]
        );

        // Within one package: mm, its first group, is walked down to xx
        // before its second is met. A `Pre-Depends` comes before a `Depends`
        // however the stanza orders them.
        for aa in [
            stanza("aa", "mm, bb | cc", ""),
            stanza("aa", "bb | cc", "Pre-Depends: mm"),
        ] {
            let walked = install(&index_with(&aa), &["aa"]);
            assert_eq!(
                names(&walked.into_packages()),
                ["aa", "cc", "mm", "xx"],
                "{aa}"
            );
        }

        // A seed another seed depends on waits for its own turn: aa's zz is
        // already selected, so nothing below it is walked before `bb | cc`.
        // apt takes bb and fails the same way.
        let aa = stanza("aa", "zz, bb | cc", "");
        assert_eq!(
            conflicts(install(&index_with(&aa), &["aa", "zz"])),
            ["bb 1.0 states \"Conflicts: xx\", and the resolution selects xx 1.0 too"],
        );
    }

    /// Builds an assume-installed set from `(name, version, fields)`, each
    /// package stating the `Conflicts` and `Breaks` lines `fields` holds.
    fn base_clashing(entries: &[(&str, &str, &str)]) -> InstalledSet {
        let mut set = InstalledSet::default();
        for (name, version, fields) in entries {
            set.install(name, Some(version), Vec::new());
            let field = |prefix: &str| {
                fields
                    .lines()
                    .find_map(|line| line.strip_prefix(prefix))
                    .map(str::to_string)
            };
            let (conflicts, breaks) = (field("Conflicts: "), field("Breaks: "));
            set.clash(
                name,
                super::super::index::parse_clashes(
                    conflicts.as_deref(),
                    breaks.as_deref(),
                    "amd64",
                ),
                false,
            );
        }
        set
    }

    #[test]
    fn an_alternative_clashing_with_what_the_base_keeps_is_passed_over() {
        // apt removes an installed package a candidate breaks, where nothing
        // upgrades it, and takes the next alternative only where it may not
        // remove the package, as for an essential one. A layer removes
        // nothing, so cc answers, whichever of bb and xx states the clash.
        for (b, x) in [("Breaks: xx", ""), ("", "Conflicts: bb")] {
            let text = format!(
                "{}{}{}{}",
                stanza("aa", "bb | cc", ""),
                stanza("bb", "", b),
                stanza("cc", "", ""),
                stanza("xx", "", ""),
            );
            let base = base_clashing(&[("xx", "1.0", x)]);
            let selected = resolve_seeded(&index(&text), &[], &["aa".into()], &[], &base)
                .expecting("cc answers aa");
            assert_eq!(names(&selected), ["aa", "cc"], "{b:?} {x:?}");
        }
    }

    #[test]
    fn a_base_package_a_candidate_clashes_with_is_upgraded_where_the_upgrade_does_not() {
        // The archive's xx 2.0 neither breaks bb nor is broken by it, so apt
        // takes bb and upgrades xx, whichever of the two states the clash, and
        // so does the layer.
        for (b, x) in [("Breaks: xx (<< 2.0)", ""), ("", "Breaks: bb")] {
            let text = format!(
                "{}{}{}{}",
                stanza("aa", "bb | cc", ""),
                stanza("bb", "", b),
                stanza("cc", "", ""),
                stanza_at("xx", "2.0", "", ""),
            );
            let base = base_clashing(&[("xx", "1.0", x)]);
            let selected = resolve_seeded(&index(&text), &[], &["aa".into()], &[], &base)
                .expecting("xx is upgraded");
            assert_eq!(
                chosen(&selected),
                [
                    ("aa".into(), "1.0".into(), 0),
                    ("bb".into(), "1.0".into(), 0),
                    ("xx".into(), "2.0".into(), 0),
                ],
                "{b:?} {x:?}",
            );
        }
        // Where bb breaks xx 2.0 as well, the upgrade is no way out: apt would
        // remove xx, and the layer takes cc instead.
        let text = format!(
            "{}{}{}{}",
            stanza("aa", "bb | cc", ""),
            stanza("bb", "", "Breaks: xx (<< 3)"),
            stanza("cc", "", ""),
            stanza_at("xx", "2.0", "", ""),
        );
        let base = base_clashing(&[("xx", "1.0", "")]);
        let selected = resolve_seeded(&index(&text), &[], &["aa".into()], &[], &base)
            .expecting("cc answers aa");
        assert_eq!(names(&selected), ["aa", "cc"]);
    }

    #[test]
    fn an_increment_clashing_with_a_base_package_nothing_upgrades_is_refused() {
        // bb is asked for by name, so nothing else answers, and nothing
        // upgrades xx. apt removes xx; a layer removes nothing from its base.
        let text = format!("{}{}", stanza("bb", "", "Breaks: xx"), stanza("xx", "", ""));
        let base = base_clashing(&[("xx", "1.0", "")]);
        let resolution = resolve_seeded(&index(&text), &[], &["bb".into()], &[], &base);
        assert_eq!(
            conflicts(resolution),
            [
                "bb 1.0 states \"Breaks: xx\", and the base layer keeps xx 1.0, which a layer \
                 does not remove"
            ],
        );
        // The same where the base package states it.
        let text = format!("{}{}", stanza("bb", "", ""), stanza("xx", "", ""));
        let base = base_clashing(&[("xx", "1.0", "Conflicts: bb")]);
        let resolution = resolve_seeded(&index(&text), &[], &["bb".into()], &[], &base);
        let refused = resolution.into_conflicts();
        assert_eq!(
            refused[0].to_string(),
            "xx 1.0, which the base layer keeps, states \"Conflicts: bb\", and the resolution \
             selects bb 1.0 too",
        );
        assert!(refused[0].stated_in_base && !refused[0].against_in_base);
    }

    #[test]
    fn a_base_already_holding_a_clash_is_refused() {
        // apt acts on no system whose installed packages clash until it is
        // fixed, and a layer cannot fix its base.
        let text = stanza("zz", "", "");
        let base = base_clashing(&[("xx", "1.0", "Conflicts: yy"), ("yy", "1.0", "")]);
        let resolution = resolve_seeded(&index(&text), &[], &["zz".into()], &[], &base);
        assert_eq!(
            conflicts(resolution),
            [
                "xx 1.0, which the base layer keeps, states \"Conflicts: yy\", and the base \
                 layer keeps yy 1.0 too"
            ],
        );
    }

    #[test]
    fn an_unknown_include_is_an_error() {
        let text = stanza("aa", "", "");
        let err = resolve(&index(&text), &[], &["nonesuch".into()], &[]).into_refusal();
        assert!(matches!(err, Refusal::PackageNotFound { name } if name == "nonesuch"));
    }

    #[test]
    fn a_cycle_terminates() {
        let text = format!("{}{}", stanza("aa", "bb", ""), stanza("bb", "aa", ""));
        let selected = resolve(&index(&text), &["aa".into()], &[], &[]).into_packages();
        assert_eq!(names(&selected), ["aa", "bb"]);
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
        // `aa` depends on `xx | yy`; excluding `xx` resolves the group to `yy`
        // rather than pulling the excluded first alternative.
        let text = format!(
            "{}{}{}",
            stanza("aa", "xx | yy", ""),
            stanza("xx", "", ""),
            stanza("yy", "", ""),
        );
        let selected = resolve(&index(&text), &["aa".into()], &[], &["xx".into()]).into_packages();
        assert_eq!(names(&selected), ["aa", "yy"]);
    }

    #[test]
    fn an_excluded_hard_dependency_is_refused() {
        // `aa` depends on `xx` with no alternative; excluding `xx` would leave the
        // dependency unmet, so the resolution fails naming both packages.
        let text = format!("{}{}", stanza("aa", "xx", ""), stanza("xx", "", ""));
        let err = resolve(&index(&text), &["aa".into()], &[], &["xx".into()]).into_refusal();
        assert!(matches!(
            err,
            Refusal::ExcludedButRequired { package, required_by }
                if package == "xx" && required_by == "aa"
        ));
    }

    #[test]
    fn an_exclude_defers_to_a_virtual_provider() {
        // `aa` depends on the virtual `awk`, provided by both gawk and mawk.
        // Providers are held sorted, so gawk is the default pick; excluding it
        // resolves the group through mawk, proving the exclusion redirected the
        // choice rather than the default coinciding with it.
        let text = format!(
            "{}{}{}",
            stanza("aa", "awk", ""),
            stanza("gawk", "", "Provides: awk"),
            stanza("mawk", "", "Provides: awk"),
        );
        let selected =
            resolve(&index(&text), &["aa".into()], &[], &["gawk".into()]).into_packages();
        assert_eq!(names(&selected), ["aa", "mawk"]);
    }

    #[test]
    fn an_include_that_is_also_excluded_is_refused() {
        let text = stanza("aa", "", "");
        let err = resolve(&index(&text), &[], &["aa".into()], &["aa".into()]).into_refusal();
        assert!(matches!(
            err,
            Refusal::ExcludedAndIncluded { name } if name == "aa"
        ));
    }

    /// [`stanza`] at a chosen version, for the cases where the archive's
    /// version is what decides the outcome.
    fn stanza_at(name: &str, version: &str, deps: &str, extra: &str) -> String {
        let fields = match extra {
            "" => format!("Depends: {deps}"),
            extra => format!("Depends: {deps}\n{extra}"),
        };
        fixture::stanza(name, version, &fixture::digest_of(name), &fields)
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
        let mut set = InstalledSet::default();
        for name in names {
            set.install(name, Some("1.0"), Vec::new());
        }
        set
    }

    /// Builds an assume-installed set from explicit `(name, version)` pairs,
    /// for the cases where the base's version is the thing under test.
    fn assumed_at(entries: &[(&str, &str)]) -> InstalledSet {
        let mut set = InstalledSet::default();
        for (name, version) in entries {
            set.install(name, Some(version), Vec::new());
        }
        set
    }

    /// Builds an assume-installed set from `(name, version, depends)`, each
    /// package depending on what a `Depends` field stating `depends` would,
    /// for the cases where what the base keeps needs something of the root.
    fn base_depending(entries: &[(&str, &str, &str)]) -> InstalledSet {
        let mut set = InstalledSet::default();
        for (name, version, depends) in entries {
            set.install(
                name,
                Some(version),
                super::super::index::parse_relations(depends),
            );
        }
        set
    }

    /// Resolves `includes` over `base` in the order given and in the reverse
    /// order, for a test holding that the order decides nothing.
    fn both_orders(
        index: &Index,
        includes: &[&str],
        base: &InstalledSet,
    ) -> [(Vec<Package>, Refusals); 2] {
        let forward: Vec<String> = includes.iter().map(|name| name.to_string()).collect();
        let reverse: Vec<String> = forward.iter().rev().cloned().collect();
        [forward, reverse].map(|includes| resolve_seeded(index, &[], &includes, &[], base))
    }

    #[test]
    fn an_assumed_dependency_is_not_reselected() {
        // `aa` depends on `bb`; the base already carries `bb`, so resolving the
        // increment selects only `aa` and leaves `bb` to the base.
        let text = format!("{}{}", stanza("aa", "bb", ""), stanza("bb", "", ""));
        let selected = resolve_seeded(&index(&text), &[], &["aa".into()], &[], &assumed(&["bb"]))
            .into_packages();
        assert_eq!(names(&selected), ["aa"]);
    }

    #[test]
    fn an_assumed_virtual_satisfies_a_dependency() {
        // `aa` depends on the virtual `awk`; the base carries a provider, so the
        // base's set includes the virtual name and the group is satisfied without
        // pulling any provider into the increment.
        let text = format!(
            "{}{}",
            stanza("aa", "awk", ""),
            stanza("gawk", "", "Provides: awk"),
        );
        let selected = resolve_seeded(
            &index(&text),
            &[],
            &["aa".into()],
            &[],
            &assumed(&["gawk", "awk"]),
        )
        .into_packages();
        assert_eq!(names(&selected), ["aa"]);
    }

    #[test]
    fn an_assumed_include_selects_nothing() {
        // A requested package the base already supplies is satisfied by the base:
        // the increment is empty.
        let text = stanza("aa", "", "");
        let selected = resolve_seeded(&index(&text), &[], &["aa".into()], &[], &assumed(&["aa"]))
            .into_packages();
        assert!(selected.is_empty());
    }

    #[test]
    fn only_the_assumed_dependency_is_omitted() {
        // `aa` depends on `bb` and `cc`; the base carries `bb` but not `cc`, so the
        // increment is `aa` and `cc` — the assume-installed set omits exactly what
        // the base supplies and no more.
        let text = format!(
            "{}{}{}",
            stanza("aa", "bb, cc", ""),
            stanza("bb", "", ""),
            stanza("cc", "", ""),
        );
        let selected = resolve_seeded(&index(&text), &[], &["aa".into()], &[], &assumed(&["bb"]))
            .into_packages();
        assert_eq!(names(&selected), ["aa", "cc"]);
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
    fn a_relation_an_index_spells_reaches_a_refusal_with_its_control_characters_escaped() {
        // A relation's text is the index's, held to no alphabet: a pool
        // publishes a package's control file as the package wrote it.
        let hostile = crate::failure::hostile::TEXT;
        let refusal = resolve(
            &index(&stanza("app", hostile, "")),
            &[],
            &["app".into()],
            &[],
        )
        .into_refusal();
        crate::failure::hostile::assert_escaped(&refusal.to_string());

        // A version is held to policy's alphabet as the index is read, so a
        // stanza stating one outside it offers nothing, and the evidence a
        // refusal carries names no version of it.
        let text = format!(
            "{}\n{}",
            stanza("app", "lib (= 2)", ""),
            stanza_at("lib", hostile, "", ""),
        );
        let refusal = resolve(&index(&text), &[], &["app".into()], &[]).into_refusal();
        assert!(!refusal.reason().contains("available"), "{refusal}");
        assert!(!refusal.to_string().contains('\u{1b}'), "{refusal}");
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
                "{} requires {:?}, and {}",
                refusal.required_by(),
                refusal.requirement(),
                refusal.reason(),
            ),
            "the sentence is composed from the parts, not written twice",
        );
    }

    /// An index over trixie (origin 0), its backports (origin 1), and
    /// experimental (origin 2), each ranked as its release marks it.
    fn ranked(primary: &str, backports: &str, experimental: &str) -> Index {
        ranked_under(primary, backports, experimental, &Pins::none())
    }

    /// [`ranked`], merged under `pins`.
    fn ranked_under(primary: &str, backports: &str, experimental: &str, pins: &Pins) -> Index {
        use super::super::index::Source;
        use super::super::release::ReleasePriority;
        Index::merge(
            [
                Source {
                    origin: 0,
                    suite: "trixie",
                    priority: ReleasePriority::Default,
                    text: primary,
                },
                Source {
                    origin: 1,
                    suite: "trixie-backports",
                    priority: ReleasePriority::AutomaticUpgrades,
                    text: backports,
                },
                Source {
                    origin: 2,
                    suite: "experimental",
                    priority: ReleasePriority::NotAutomatic,
                    text: experimental,
                },
            ],
            "amd64",
            pins,
        )
    }

    /// The pin holding each `(name, origin)` at the entry `index` offers the
    /// name at from that origin, as a plan that resolved it would.
    fn pin_of(index: &Index, held: &[(&str, usize)]) -> Pins {
        let packages: Vec<Package> = held
            .iter()
            .map(|(name, origin)| {
                index
                    .offers(name)
                    .iter()
                    .find(|package| package.origin == *origin)
                    .expect("the index offers the name from that origin")
                    .clone()
            })
            .collect();
        Pins::holding(&packages)
    }

    /// Each selected package's name, version, and origin.
    fn chosen(packages: &[Package]) -> Vec<(String, String, usize)> {
        packages
            .iter()
            .map(|p| (p.name.clone(), p.version.clone(), p.origin))
            .collect()
    }

    /// An archive where experimental carries a newer `app` that needs a newer
    /// `libfoo` than trixie's, a `libc6` trixie's already satisfies, and an
    /// unversioned `helper`.
    fn experimental_app() -> Index {
        let (primary, experimental) = experimental_app_texts();
        ranked(&primary, "", &experimental)
    }

    /// The trixie and experimental indexes [`experimental_app`] merges.
    fn experimental_app_texts() -> (String, String) {
        (
            format!(
                "{}{}{}{}",
                stanza_at("app", "1.0", "libfoo (>= 1.0)", ""),
                stanza_at("libfoo", "1.0", "", ""),
                stanza_at("libc6", "2.41", "", ""),
                stanza_at("helper", "0.5", "", ""),
            ),
            format!(
                "{}{}{}{}{}",
                stanza_at("app", "2.0", "libfoo (>= 2.0), libc6 (>= 2.30), helper", ""),
                stanza_at("libfoo", "2.0", "", ""),
                stanza_at("libc6", "2.43", "", ""),
                stanza_at("helper", "0.9", "", ""),
                stanza_at("newtool", "1.0", "libfoo (>= 2.0)", ""),
            ),
        )
    }

    #[test]
    fn a_name_resolves_to_the_release_that_outranks_the_rest() {
        // Without a release named, experimental supplies nothing trixie offers.
        let selected = resolve(&experimental_app(), &[], &["app".into()], &[]).into_packages();
        assert_eq!(
            chosen(&selected),
            [
                ("app".into(), "1.0".into(), 0),
                ("libfoo".into(), "1.0".into(), 0)
            ],
        );
    }

    #[test]
    fn a_release_named_in_the_install_list_supplies_what_it_needs_and_no_more() {
        // apt's `app/experimental`: the entry's own version, and each
        // versioned dependency the candidate cannot meet from the same
        // release. libc6 2.41 meets `>= 2.30` and stays trixie's; `helper` is
        // unversioned, which a switch cannot help, and stays trixie's.
        let selected =
            resolve(&experimental_app(), &[], &["app/experimental".into()], &[]).into_packages();
        assert_eq!(
            chosen(&selected),
            [
                ("app".into(), "2.0".into(), 2),
                ("helper".into(), "0.5".into(), 0),
                ("libc6".into(), "2.41".into(), 0),
                ("libfoo".into(), "2.0".into(), 2),
            ],
        );
    }

    #[test]
    fn a_switched_dependency_is_seeded_at_its_switched_version() {
        // The switch happens before anything is selected, as apt makes it when
        // it reads the command line, so a base package the entry needs newer is
        // seeded once, at the version the entry needs.
        let selected = resolve(
            &experimental_app(),
            &["libfoo".into()],
            &["app/experimental".into()],
            &[],
        )
        .into_packages();
        let libfoo = selected.iter().find(|p| p.name == "libfoo").unwrap();
        assert_eq!((libfoo.version.as_str(), libfoo.origin), ("2.0", 2));
    }

    #[test]
    fn a_candidate_that_meets_the_constraint_but_needs_the_release_is_walked() {
        // The backports kernel's shape: the metapackage names an image only
        // backports carries, so that image's candidate already meets the
        // exact constraint, and the image needs a newer linux-base than the
        // default release's. A candidate that cannot be installed as things
        // stand is no answer, so it is walked as a switch is.
        let index = ranked(
            &stanza_at("linux-base", "4.12", "", ""),
            &format!(
                "{}{}{}",
                stanza_at(
                    "linux-image-amd64",
                    "7.2",
                    "linux-image-7.2-amd64 (= 7.2)",
                    ""
                ),
                stanza_at("linux-image-7.2-amd64", "7.2", "linux-base (>= 4.17~)", ""),
                stanza_at("linux-base", "4.17~bpo", "", ""),
            ),
            "",
        );
        let selected = resolve(
            &index,
            &[],
            &["linux-image-amd64/trixie-backports".into()],
            &[],
        )
        .into_packages();
        assert_eq!(
            chosen(&selected),
            [
                ("linux-base".into(), "4.17~bpo".into(), 1),
                ("linux-image-7.2-amd64".into(), "7.2".into(), 1),
                ("linux-image-amd64".into(), "7.2".into(), 1),
            ],
        );
    }

    #[test]
    fn a_lower_ranked_package_needing_more_than_the_candidates_names_the_release() {
        // A name only experimental offers is its to supply, but its
        // dependencies resolve to their candidates, as apt's would. The refusal
        // says which release has the version that would do, which is what an
        // entry naming that release takes.
        let rendered = unsatisfiable(resolve(&experimental_app(), &[], &["newtool".into()], &[]));
        assert!(rendered.contains("libfoo 1.0 in the archive"), "{rendered}");
        assert!(
            rendered.contains("libfoo 2.0 in experimental"),
            "{rendered}"
        );
        let selected = resolve(
            &experimental_app(),
            &[],
            &["newtool/experimental".into()],
            &[],
        )
        .into_packages();
        assert_eq!(names(&selected), ["libfoo", "newtool"]);
    }

    #[test]
    fn a_release_that_does_not_carry_the_name_is_refused() {
        let refusal = resolve(
            &experimental_app(),
            &[],
            &["libfoo/trixie-backports".into()],
            &[],
        )
        .into_refusal();
        assert!(matches!(
            &refusal,
            Refusal::NotInRelease { entry, release }
                if entry == "libfoo/trixie-backports" && release == "trixie-backports"
        ));
        assert_eq!(refusal.required_by(), THE_INSTALL_LIST);
    }

    #[test]
    fn a_layer_takes_a_release_named_for_a_name_its_base_holds_older() {
        // The base has trixie's libfoo 1.0. The entry needs 2.0, which the base
        // does not meet, so experimental's is switched to and installed into
        // the increment; the entry naming exactly what the base holds would
        // select nothing.
        let selected = resolve_seeded(
            &experimental_app(),
            &[],
            &["app/experimental".into()],
            &[],
            &assumed_at(&[("libfoo", "1.0"), ("libc6", "2.41"), ("helper", "0.5")]),
        )
        .into_packages();
        assert_eq!(
            chosen(&selected),
            [
                ("app".into(), "2.0".into(), 2),
                ("libfoo".into(), "2.0".into(), 2)
            ],
        );
        let held = resolve_seeded(
            &experimental_app(),
            &[],
            &["libfoo/trixie".into()],
            &[],
            &assumed_at(&[("libfoo", "1.0")]),
        )
        .into_packages();
        assert!(held.is_empty(), "{:?}", names(&held));
    }

    #[test]
    fn a_layer_upgrades_what_its_base_holds_only_as_apt_would() {
        // Where an increment needs a newer version of something its base has
        // installed, the version taken is the one apt would upgrade to: never
        // experimental's, backports' only for a package backports supplied, and
        // a default release's whenever it is newer. Nothing is downgraded.
        let index = ranked(
            &format!(
                "{}{}{}",
                stanza_at("from-main", "1.0", "", ""),
                stanza_at("from-bpo", "0.9", "", ""),
                stanza_at(
                    "app",
                    "1.0",
                    "from-main (>= 1.1~), from-bpo (>= 1.1~), old (<< 2.0)",
                    ""
                ),
            ),
            &format!(
                "{}{}",
                stanza_at("from-main", "1.1~bpo", "", ""),
                stanza_at("from-bpo", "1.1~bpo", "", ""),
            ),
            &format!(
                "{}{}",
                stanza_at("from-main", "2.0", "", ""),
                stanza_at("old", "1.0", "", ""),
            ),
        );
        let (packages, refusals) = resolve_seeded(
            &index,
            &[],
            &["app".into()],
            &[],
            &assumed_at(&[
                ("from-main", "1.0"),
                ("from-bpo", "1.0~bpo"),
                ("old", "2.0"),
            ]),
        );
        assert_eq!(
            chosen(&packages),
            [
                ("app".into(), "1.0".into(), 0),
                ("from-bpo".into(), "1.1~bpo".into(), 1)
            ],
        );
        let refused: Vec<&str> = refusals.iter().map(Refusal::requirement).collect();
        assert_eq!(refused, ["from-main (>= 1.1~)", "old (<< 2.0)"]);
    }

    /// An index offering an upgrade of `libcore` to 2.0, `app-new` needing it,
    /// and whatever `extra` adds.
    fn libcore_upgrade(extra: &str) -> Index {
        index(&format!(
            "{}{}{extra}",
            stanza_at("libcore", "2.0", "", ""),
            stanza_at("app-new", "1.0", "libcore (>= 2.0)", ""),
        ))
    }

    #[test]
    fn an_upgrade_breaking_a_selected_dependency_is_refused_in_either_order() {
        // The base has libcore 1.0. app-new needs 2.0, so the layer upgrades
        // it, and app-old needs exactly the 1.0 the upgrade replaces. The two
        // cannot share a root, and apt refuses them together. The walk meets
        // app-old's dependency before the upgrade in one order and after it in
        // the other, and refuses it the same way in both.
        let index = libcore_upgrade(&stanza_at("app-old", "1.0", "libcore (= 1.0)", ""));
        let base = assumed_at(&[("libcore", "1.0")]);
        for resolution in both_orders(&index, &["app-new", "app-old"], &base) {
            let refusal = resolution.into_refusal();
            assert!(matches!(refusal, Refusal::Broken { .. }), "{refusal}");
            assert_eq!(
                refusal.to_string(),
                "app-old requires \"libcore (= 1.0)\", and the increment replaces libcore 1.0 \
                 with 2.0, leaving nothing that satisfies it (offered: \"libcore 2.0 in the \
                 increment\")",
            );
        }
    }

    #[test]
    fn a_dependency_an_upgrade_breaks_takes_its_next_alternative_in_either_order() {
        // app-old takes libcore 1.0 or libcompat. Once app-new's upgrade
        // replaces libcore 1.0, libcompat answers, whichever entry comes first:
        // the check asks again what the walk answered from the base.
        let index = libcore_upgrade(&format!(
            "{}{}",
            stanza_at("app-old", "1.0", "libcore (= 1.0) | libcompat", ""),
            stanza_at("libcompat", "1.0", "", ""),
        ));
        let base = assumed_at(&[("libcore", "1.0")]);
        for resolution in both_orders(&index, &["app-new", "app-old"], &base) {
            let selected = resolution.into_packages();
            assert_eq!(
                names(&selected),
                ["app-new", "app-old", "libcompat", "libcore"]
            );
        }
    }

    #[test]
    fn an_upgrade_takes_away_the_versioned_provides_it_replaces() {
        // The base's libv 1 provides v at 1, and the libv 2 the layer upgrades
        // it to provides v at 2. needs-v1 asks for v at 1, which went with the
        // libv it replaced.
        let index = index(&format!(
            "{}{}{}",
            stanza_at("libv", "2", "", "Provides: v (= 2)"),
            stanza_at("needs-v1", "1.0", "v (= 1)", ""),
            stanza_at("wants-libv2", "1.0", "libv (>= 2)", ""),
        ));
        let mut base = assumed_at(&[("libv", "1")]);
        base.supply("v", "libv", Some("1"));
        for resolution in both_orders(&index, &["wants-libv2", "needs-v1"], &base) {
            assert_eq!(
                resolution.into_refusal().to_string(),
                "needs-v1 requires \"v (= 1)\", and the increment replaces libv 1 with 2, \
                 leaving nothing that satisfies it (offered: \"v 2 in the increment\")",
            );
        }
    }

    #[test]
    fn an_install_list_entry_the_base_answered_is_asked_again_after_an_upgrade() {
        // The base's mawk 1.3 provides awk, which answers the entry. The mawk
        // 1.4 app needs provides nothing, so gawk answers it instead, as apt
        // takes it; with no other provider, the entry is refused, naming the
        // upgrade that took awk away.
        let text = format!(
            "{}{}",
            stanza_at("mawk", "1.4", "", ""),
            stanza_at("app", "1.0", "mawk (>= 1.4)", ""),
        );
        let mut base = assumed_at(&[("mawk", "1.3")]);
        base.supply("awk", "mawk", None);
        let with_gawk = index(&format!("{text}{}", stanza("gawk", "", "Provides: awk")));
        for resolution in both_orders(&with_gawk, &["awk", "app"], &base) {
            assert_eq!(names(&resolution.into_packages()), ["app", "gawk", "mawk"]);
        }
        for resolution in both_orders(&index(&text), &["awk", "app"], &base) {
            let refusal = resolution.into_refusal();
            assert_eq!(refusal.required_by(), THE_INSTALL_LIST);
            assert_eq!(
                refusal.reason(),
                "the increment replaces mawk 1.3 with 1.4, leaving nothing that satisfies it",
            );
        }
    }

    #[test]
    fn a_base_package_an_upgrade_breaks_is_upgraded_with_it() {
        // The base's dep 1.0 needs exactly the libcore 1.0 the layer upgrades
        // for app-new, and the archive's dep 1.1 needs the 2.0 that replaces
        // it. apt upgrades dep with libcore, and so does the layer.
        let index = libcore_upgrade(&stanza_at("dep", "1.1", "libcore (= 2.0)", ""));
        let base = base_depending(&[("libcore", "1.0", ""), ("dep", "1.0", "libcore (= 1.0)")]);
        let selected = resolve_seeded(&index, &[], &["app-new".into()], &[], &base)
            .expecting("dep is upgraded with libcore");
        assert_eq!(
            chosen(&selected),
            [
                ("app-new".into(), "1.0".into(), 0),
                ("dep".into(), "1.1".into(), 0),
                ("libcore".into(), "2.0".into(), 0),
            ],
        );
    }

    #[test]
    fn upgrading_libc6_upgrades_the_libc_bin_that_holds_its_range() {
        // libc-bin holds libc6 to one upstream version, so a layer upgrading
        // libc6 past it upgrades libc-bin too, as apt does.
        let index = index(&format!(
            "{}{}{}",
            stanza_at("libc6", "2.42-1", "", ""),
            stanza_at("libc-bin", "2.42-1", "libc6 (>> 2.42), libc6 (<< 2.43)", ""),
            stanza_at("app", "1.0", "libc6 (>= 2.42)", ""),
        ));
        let base = base_depending(&[
            ("libc6", "2.41-10", ""),
            ("libc-bin", "2.41-10", "libc6 (>> 2.41), libc6 (<< 2.42)"),
        ]);
        let selected = resolve_seeded(&index, &[], &["app".into()], &[], &base)
            .expecting("libc-bin is upgraded with libc6");
        assert_eq!(
            chosen(&selected),
            [
                ("app".into(), "1.0".into(), 0),
                ("libc-bin".into(), "2.42-1".into(), 0),
                ("libc6".into(), "2.42-1".into(), 0),
            ],
        );
    }

    #[test]
    fn a_base_package_an_upgrade_breaks_and_nothing_upgrades_is_refused() {
        // The archive's dep is the version the base holds, so nothing replaces
        // it. apt removes dep to install app-new; a layer removes nothing from
        // its base, so it refuses, naming dep and the upgrade that broke it.
        let index = libcore_upgrade(&stanza_at("dep", "1.0", "libcore (= 1.0)", ""));
        let base = base_depending(&[("libcore", "1.0", ""), ("dep", "1.0", "libcore (= 1.0)")]);
        let refusal = resolve_seeded(&index, &[], &["app-new".into()], &[], &base).into_refusal();
        assert_eq!(
            refusal.to_string(),
            "dep requires \"libcore (= 1.0)\", and the increment replaces libcore 1.0 with \
             2.0, leaving nothing that satisfies it (offered: \"libcore 2.0 in the \
             increment\")",
        );
        // An excluded package is not one to upgrade either.
        let index = libcore_upgrade(&stanza_at("dep", "1.1", "libcore (= 2.0)", ""));
        let refusal =
            resolve_seeded(&index, &[], &["app-new".into()], &["dep".into()], &base).into_refusal();
        assert_eq!(refusal.required_by(), "dep");
    }

    #[test]
    fn an_upgrade_that_breaks_nothing_leaves_the_base_as_it_was() {
        // dep accepts any libcore from 1.0, so the upgrade breaks nothing, and
        // the base keeps dep 1.0 though the archive offers 1.1: only a broken
        // dependency is a reason to upgrade what the base keeps.
        let index = libcore_upgrade(&stanza_at("dep", "1.1", "libcore (>= 1.0)", ""));
        let base = base_depending(&[("libcore", "1.0", ""), ("dep", "1.0", "libcore (>= 1.0)")]);
        let selected = resolve_seeded(&index, &[], &["app-new".into()], &[], &base)
            .expecting("the upgrade breaks nothing");
        assert_eq!(names(&selected), ["app-new", "libcore"]);
    }

    #[test]
    fn a_base_package_whose_dependency_the_base_left_unmet_is_refused() {
        // Nothing the increment selects broke it, and nothing in the root
        // answers it: the base itself left dep's dependency unmet. apt refuses
        // to act on such a system, and the refusal names no replacement.
        let index = index(&stanza("tool", "", ""));
        let base = base_depending(&[("dep", "1.0", "absent")]);
        let refusal = resolve_seeded(&index, &[], &["tool".into()], &[], &base).into_refusal();
        assert_eq!(
            refusal.to_string(),
            "dep requires \"absent\", and nothing the base layer keeps or the increment \
             installs satisfies it",
        );
    }

    #[test]
    fn a_relation_a_base_records_reaches_a_refusal_with_its_control_characters_escaped() {
        // A base package's relations are its status database's text, which
        // the base's own scripts can write.
        let hostile = crate::failure::hostile::TEXT;
        let base = base_depending(&[("dep", "1.0", hostile)]);
        let refusal = resolve_seeded(
            &index(&stanza("tool", "", "")),
            &[],
            &["tool".into()],
            &[],
            &base,
        )
        .into_refusal();
        assert_eq!(refusal.required_by(), "dep");
        crate::failure::hostile::assert_escaped(&refusal.to_string());
    }

    /// The pin a refusal could not hold, or a panic naming what came back.
    fn unheld(refusal: Refusal) -> UnheldPin {
        match refusal {
            Refusal::Pinned { unheld, .. } => unheld,
            other => panic!("expected the pin refused, got {other}"),
        }
    }

    #[test]
    fn a_release_named_for_a_pinned_name_answers_with_the_pinned_version_or_refuses() {
        // The pin holds the kernel at trixie's version, and the install list
        // asks for it from backports. Taking backports' would resolve the name
        // around its pin; taking trixie's would ignore the release the entry
        // names. Neither is an answer, so the pin is refused.
        let primary = stanza_at("kernel", "6.12", "", "");
        let backports = stanza_at("kernel", "6.16~bpo", "", "");
        let unpinned = ranked(&primary, &backports, "");
        let entry = "kernel/trixie-backports".to_string();

        let index = ranked_under(
            &primary,
            &backports,
            "",
            &pin_of(&unpinned, &[("kernel", 0)]),
        );
        let refusal = resolve(&index, &[], std::slice::from_ref(&entry), &[]).into_refusal();
        assert_eq!(refusal.requirement(), entry);
        assert_eq!(refusal.required_by(), THE_INSTALL_LIST);
        let held = unheld(refusal);
        assert_eq!(
            (held.package.as_str(), held.version.as_str()),
            ("kernel", "6.12")
        );
        assert_eq!(
            held.reason,
            UnheldReason::Release {
                release: "trixie-backports".to_string(),
                archive: "6.16~bpo".to_string(),
            },
        );

        // A pin taken from the backports version is answered by it.
        let index = ranked_under(
            &primary,
            &backports,
            "",
            &pin_of(&unpinned, &[("kernel", 1)]),
        );
        let selected = resolve(&index, &[], &[entry], &[]).into_packages();
        assert_eq!(chosen(&selected), [("kernel".into(), "6.16~bpo".into(), 1)]);
    }

    #[test]
    fn a_dependency_a_release_switches_is_held_to_the_pin() {
        // `app/experimental` needs libfoo 2.0, which only experimental offers,
        // and the pin holds libfoo at trixie's 1.0. The switch would take
        // experimental's; the pin refuses instead, naming who needed what.
        let pins = pin_of(&experimental_app(), &[("libfoo", 0)]);
        let (primary, experimental) = experimental_app_texts();
        let index = ranked_under(&primary, "", &experimental, &pins);
        let refusal = resolve(&index, &[], &["app/experimental".into()], &[]).into_refusal();
        assert_eq!(refusal.requirement(), "libfoo (>= 2.0)");
        assert_eq!(refusal.required_by(), "app");
        let held = unheld(refusal);
        assert_eq!(
            (held.package.as_str(), held.version.as_str()),
            ("libfoo", "1.0")
        );
        assert_eq!(
            held.reason,
            UnheldReason::Requirement {
                requirement: "libfoo (>= 2.0)".to_string(),
                required_by: "app".to_string(),
            },
        );

        // A pin holding experimental's libfoo is what the switch takes.
        let pins = pin_of(&experimental_app(), &[("libfoo", 2)]);
        let index = ranked_under(&primary, "", &experimental, &pins);
        let selected = resolve(&index, &[], &["app/experimental".into()], &[]).into_packages();
        let libfoo = selected.iter().find(|p| p.name == "libfoo").unwrap();
        assert_eq!((libfoo.version.as_str(), libfoo.origin), ("2.0", 2));
    }

    #[test]
    fn a_layer_upgrades_a_pinned_name_to_its_pinned_version_alone() {
        // The base holds libfoo1 1.0-1, the pin holds trixie's 1.0-2, and a
        // security release of the same rank offers 1.0-2+deb13u1. An increment
        // needing 1.0-2 or newer takes the pinned version, not the newest. One
        // needing more than the pinned version refuses the pin.
        use super::super::index::Source;
        use super::super::release::ReleasePriority;
        let primary = format!(
            "{}{}{}",
            stanza_at("libfoo1", "1.0-2", "", ""),
            stanza_at("app", "1.0", "libfoo1 (>= 1.0-2)", ""),
            stanza_at("fixed", "1.0", "libfoo1 (>= 1.0-2+deb13u1)", ""),
        );
        let security = stanza_at("libfoo1", "1.0-2+deb13u1", "", "");
        let merged = |pins: &Pins| {
            Index::merge(
                [
                    Source {
                        origin: 0,
                        suite: "trixie",
                        priority: ReleasePriority::Default,
                        text: primary.as_str(),
                    },
                    Source {
                        origin: 1,
                        suite: "trixie-security",
                        priority: ReleasePriority::Default,
                        text: security.as_str(),
                    },
                ],
                "amd64",
                pins,
            )
        };
        let base = assumed_at(&[("libfoo1", "1.0-1")]);
        let unpinned = merged(&Pins::none());
        let selected = resolve_seeded(&unpinned, &[], &["app".into()], &[], &base).into_packages();
        assert!(
            chosen(&selected).contains(&("libfoo1".into(), "1.0-2+deb13u1".into(), 1)),
            "{:?}",
            chosen(&selected),
        );

        let index = merged(&pin_of(&unpinned, &[("libfoo1", 0)]));
        let selected = resolve_seeded(&index, &[], &["app".into()], &[], &base).into_packages();
        assert_eq!(
            chosen(&selected),
            [
                ("app".into(), "1.0".into(), 0),
                ("libfoo1".into(), "1.0-2".into(), 0)
            ],
        );

        // The base holds the pinned version already, and an increment needs a
        // newer one: the pin holds the name where it is.
        let base = assumed_at(&[("libfoo1", "1.0-2")]);
        let refusal = resolve_seeded(&index, &[], &["fixed".into()], &[], &base).into_refusal();
        assert_eq!(refusal.required_by(), "fixed");
        let held = unheld(refusal);
        assert_eq!(
            (held.package.as_str(), held.version.as_str()),
            ("libfoo1", "1.0-2")
        );
    }

    #[test]
    fn a_candidate_dependency_the_pinned_version_does_not_meet_refuses_the_pin() {
        // No release named and no base: the pinned candidate is simply too old
        // for something selected, where an unpinned resolution takes the newer
        // version another repository offers. The refusal is the pin's, since
        // the pin is what is in the way. Another alternative that answers the
        // group leaves the pin nothing to refuse.
        let primary = format!(
            "{}{}{}",
            stanza_at("libfoo", "1.0", "", ""),
            stanza_at("app", "1.0", "libfoo (>= 2.0)", ""),
            stanza_at("either", "1.0", "libfoo (>= 2.0) | libbar", ""),
        );
        let pool = format!(
            "{}{}",
            stanza_at("libfoo", "2.0", "", ""),
            stanza_at("libbar", "1.0", "", ""),
        );
        let merged = |pins: &Pins| {
            Index::merge(
                super::super::index::sources([(0, primary.as_str()), (1, pool.as_str())]),
                "amd64",
                pins,
            )
        };
        let unpinned = merged(&Pins::none());
        let selected = resolve(&unpinned, &[], &["app".into()], &[]).into_packages();
        assert!(chosen(&selected).contains(&("libfoo".into(), "2.0".into(), 1)));

        let index = merged(&pin_of(&unpinned, &[("libfoo", 0)]));
        let rendered = resolve(&index, &[], &["app".into()], &[])
            .into_refusal()
            .to_string();
        assert_eq!(
            rendered,
            "app requires \"libfoo (>= 2.0)\", and the pin holds libfoo at 1.0",
        );
        let selected = resolve(&index, &[], &["either".into()], &[]).into_packages();
        assert_eq!(names(&selected), ["either", "libbar"]);
    }

    #[test]
    fn the_pins_refusals_are_listed_by_name_beside_the_rest() {
        // A resolution refusing the pin and something else names both as
        // refusals; the pin's are what `unheld` lists, in name order.
        let primary = format!(
            "{}{}{}",
            stanza_at("zlib", "1.0", "", ""),
            stanza_at("alib", "1.0", "", ""),
            stanza_at("app", "1.0", "zlib (>= 2.0), alib (>= 2.0), absent", ""),
        );
        let unpinned = index(&primary);
        let index = Index::merge(
            super::super::index::sources([(0, primary.as_str())]),
            "amd64",
            &pin_of(&unpinned, &[("zlib", 0), ("alib", 0)]),
        );
        let (_, refusals) = resolve(&index, &[], &["app".into()], &[]);
        assert_eq!(refusals.iter().count(), 3, "{}", refusals.describe());
        let unheld: Vec<String> = refusals.unheld().into_iter().map(|u| u.package).collect();
        assert_eq!(unheld, ["alib", "zlib"]);
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
