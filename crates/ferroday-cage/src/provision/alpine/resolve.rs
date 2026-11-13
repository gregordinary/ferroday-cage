//! Dependency resolution: the install closure over a merged apk index.
//!
//! From the requested set the resolver closes over `D:`, choosing a provider for
//! each name, refusing a closure a `!` entry forbids, and finally adding every
//! package whose `i:` condition the closure has come to satisfy. The result is
//! the set of real packages a bootstrap downloads and installs.
//!
//! # Choosing among providers
//!
//! A name may be answered by more than one package: a real package answers its
//! own name at its own version, and every package whose `p:` field names it
//! answers it at the version that entry states. The ranking between them is
//! the one `apk.static` 3.0.7 applies, and it is not the obvious one:
//!
//! 1. **The version offered**, highest first — and the version *offered*, not
//!    the offering package's own. A package providing `thing=9.0` beats the real
//!    `thing` at 1.0.
//! 2. **`k:`, the provider priority**, highest first, which therefore breaks a
//!    tie in the offered version rather than overriding it.
//! 3. **The package name**, lowest first. This last step is ours. apk's own
//!    tie-break is the order the providers appear in the index, which is a
//!    property of the mirror rather than of the archive, so a closure resolved
//!    twice against two mirrors of one repository could differ. A closure has to
//!    be reproducible, so the tie is broken on something both mirrors agree on.
//!
//! Two further rules follow the same measurements. A `p:` entry with no version
//! satisfies no *constrained* dependency, so a mirror cannot answer
//! `python3>=3.12` with a package that merely says it provides `python3`. And a
//! name whose best answer is such an entry is selectable only where that package
//! declares a `k:` — without one apk refuses to choose and asks to be told which
//! package to install, and so does this.
//!
//! # A `!` entry is a negated constraint
//!
//! `!alsa-lib<1.2.14-r2` does not say that `alsa-lib` must be absent. It says
//! the closure must not hold an `alsa-lib` *below* that version, and the
//! companion `!alsa-lib>1.2.14-r2` says the same above it — the pair being how a
//! debug package states that it needs exactly the build it was split from. Both
//! hold when `alsa-lib` is present at that version, and a bare `!name` with no
//! constraint is the special case where any version at all breaks it.
//!
//! # One package per name a version is offered for
//!
//! A root holds one package for a name that is a package's own, or that a
//! package provides at a version: apk refuses `icu-data-en` beside
//! `icu-data-full`, which both provide `icu-data=78.1-r0`, and the package `x`
//! beside anything else that provides `x`. Packages that provide a name at no
//! version share it, which is how alternatives that rank themselves with `k:`
//! coexist.
//!
//! The closure is built one dependency at a time, so it can take one provider
//! for a name and later, for another name, a package that answers the first
//! one too. apk's solver weighs the whole closure instead, and installs
//! `icu-data-full` alone for a closure that asks for `icu-data` and for
//! `icu-data-full` by name. So where a closure holds two packages for such a
//! name, it is resolved again, changing as little as settles it:
//!
//! 1. Each of them taken first, as though it had been requested. That is
//!    enough for `icu-data`: with `icu-data-full` taken first, `icu-data` is
//!    already answered.
//! 2. Failing that, each kept and the others set aside. A package set aside is
//!    not taken for any name, and nor is a provider that needs one by a
//!    requirement of its own, which is how `nginx-mod-devel-kit` comes to be
//!    answered by itself rather than by `openresty-mod-devel-kit` once
//!    `openresty` is set aside. Each such closure is searched in the same way.
//!
//! Within each step the packages are tried in the order the ranking above puts
//! them for the name, and the first closure that holds one package per name is
//! the answer. A package that offers the name at no version, without a provider
//! priority, is tried only where the closure needs it by its own name, which is
//! when apk lets it answer one. Where no closure holds, the resolution is
//! refused, naming the packages, rather than installing two packages apk would
//! never install together. This is a search over the packages that contend
//! rather than apk's solver; for every package of Alpine's own `main` and
//! `community`, resolved alone, it keeps the packages apk keeps.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;

use super::index::{Dependency, Index, Record};
use super::pin::UnheldPin;
use super::version;

/// A closure the archives cannot supply.
#[derive(Debug)]
pub(super) enum ResolveError {
    /// A requested package is neither a real package nor a provided name.
    NotFound {
        /// The requested name.
        name: String,
    },
    /// A caller both requested and excluded the same package.
    ExcludedAndIncluded {
        /// The contradicted name.
        name: String,
    },
    /// Every package that could have satisfied a dependency is excluded.
    ExcludedButRequired {
        /// The dependency, as the index spells it.
        dependency: String,
        /// The package that needed it, or `None` for a requested one.
        required_by: Option<String>,
    },
    /// A dependency names a package the pin holds at a version the dependency
    /// does not accept, and nothing else answers it.
    Pinned {
        /// The pinned package, and the requirement it does not meet.
        unheld: UnheldPin,
    },
    /// A dependency's name is offered, and at no version it accepts.
    Unsatisfied {
        /// The dependency, as the index spells it.
        dependency: String,
        /// The package that needed it, or `None` for a requested one.
        required_by: Option<String>,
        /// What the archives offer instead, package by package.
        offered: Vec<String>,
    },
    /// A name is answered only by packages that state no version for it and
    /// declare no provider priority, so there is nothing to choose between them.
    Ambiguous {
        /// The name that was asked for.
        name: String,
        /// The packages that provide it, in a stable order.
        providers: Vec<String>,
        /// The package that needed it, or `None` for a requested one.
        required_by: Option<String>,
    },
    /// The closure holds a package another one in it refuses.
    Conflict {
        /// The refusal, as the index spells it.
        dependency: String,
        /// The package that declared it.
        declared_by: String,
        /// The package and version that broke it.
        present: String,
    },
    /// The closure holds more than one package for a name only one may answer:
    /// a package's own name, or a name provided at a version.
    Contended {
        /// The name more than one package answers.
        name: String,
        /// Each package answering it, with the version it answers at.
        answers: Vec<String>,
    },
    /// A delta resolution would install a second version of a package the base
    /// layer already carries.
    WouldUpgrade {
        /// The package the base carries.
        name: String,
        /// The version it carries it at.
        installed: String,
        /// The version the increment would have installed.
        offered: String,
        /// The dependency that could not be met by what the base carries.
        dependency: String,
        /// The package that needed it, or `None` for a requested one.
        required_by: Option<String>,
    },
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// Renders `required_by` as a clause, or nothing for a requested name.
        fn by(required_by: &Option<String>) -> String {
            match required_by {
                Some(package) => format!(", required by {package}"),
                None => String::new(),
            }
        }
        match self {
            ResolveError::NotFound { name } => {
                write!(f, "no repository offers {name}")
            }
            ResolveError::ExcludedAndIncluded { name } => {
                write!(f, "{name} is both included and excluded")
            }
            ResolveError::ExcludedButRequired {
                dependency,
                required_by,
            } => write!(
                f,
                "everything that could satisfy {dependency}{} is excluded",
                by(required_by),
            ),
            ResolveError::Pinned { unheld } => write!(f, "{unheld}"),
            ResolveError::Unsatisfied {
                dependency,
                required_by,
                offered,
            } if offered.is_empty() => {
                write!(f, "no repository offers {dependency}{}", by(required_by),)
            }
            ResolveError::Unsatisfied {
                dependency,
                required_by,
                offered,
            } => write!(
                f,
                "nothing satisfies {dependency}{}; the repositories offer {}",
                by(required_by),
                offered.join(", "),
            ),
            ResolveError::Ambiguous {
                name,
                providers,
                required_by,
            } => write!(
                f,
                "{name}{} is provided at no version by {}, and none of them declares a provider \
                 priority, so there is nothing to choose between them; name one of them to \
                 install",
                by(required_by),
                providers.join(", "),
            ),
            ResolveError::Conflict {
                dependency,
                declared_by,
                present,
            } => write!(
                f,
                "{declared_by} refuses {dependency}, and the closure holds {present}",
            ),
            ResolveError::Contended { name, answers } => write!(
                f,
                "{name} is answered by {}, and a root holds one package for a name that is a \
                 package's own or is provided at a version; name the one to install",
                answers.join(" and "),
            ),
            ResolveError::WouldUpgrade {
                name,
                installed,
                offered,
                dependency,
                required_by,
            } => write!(
                f,
                "the base layer carries {name} at {installed}, and {dependency}{} needs {offered}; \
                 an increment installs over a base rather than upgrading it, so rebuild the base \
                 against the repositories as they stand now",
                by(required_by),
            ),
        }
    }
}

/// Resolves the install closure of `world`, honoring `excludes`, over a base
/// layer that already carries `installed`.
///
/// `world` is the set the caller asked for, which is the whole seed: apk has no
/// priority field and no essential flag, so a closure holds what was requested
/// and what that requires and nothing else. It is a set, as apk reads and
/// writes it, so it is seeded in name order: which provider one requested
/// package's dependency takes cannot then depend on the order the caller named
/// the packages in. The returned records are ordered by name, so one resolution
/// of one archive state is one value.
///
/// A closure that would hold two packages for a name only one may answer is
/// resolved again as the module documentation describes, and refused where no
/// closure holds one.
///
/// `installed` is empty for a whole root and is a base layer's packages for the
/// increment of a layered build. Each of those answers its own name at its own
/// version and every name it provides at the version it provides it at, so a
/// dependency the base already satisfies extends the closure no further — and
/// one it does not, because the base's version is too old, is refused rather
/// than answered with a second copy of the package.
///
/// The version is why a base is seeded as records rather than as the set of
/// names the Debian layer's counterpart seeds. apk spells a soname
/// `so:libc.musl-x86_64.so.1=1.2.5-r23` and a split package's dependency on its
/// own source `musl=1.2.5-r23`, so a base treated as answering a name at any
/// version would leave an increment that does not close.
///
/// # Errors
///
/// Returns a [`ResolveError`] for a requested name nothing offers, a dependency
/// no offered version satisfies or only the pin's version could, a name whose
/// only providers cannot be chosen
/// between, a `!` entry the closure breaks, an exclusion that leaves a
/// dependency unsatisfiable, a name more than one package answers where only one
/// may, or a dependency that needs a newer version of a package the base already
/// carries.
pub(super) fn resolve<'a>(
    index: &Index,
    world: &[String],
    excludes: &[String],
    installed: impl IntoIterator<Item = &'a Record>,
) -> Result<Vec<Record>, ResolveError> {
    let excluded: Vec<&str> = excludes.iter().map(String::as_str).collect();
    let mut seeds: Vec<&str> = world.iter().map(String::as_str).collect();
    seeds.sort_unstable();
    seeds.dedup();
    if let Some(name) = seeds.iter().find(|name| excluded.contains(name)) {
        return Err(ResolveError::ExcludedAndIncluded {
            name: (*name).to_string(),
        });
    }
    let closing = Closing {
        index,
        seeds: &seeds,
        excluded: &excluded,
        installed: installed.into_iter().collect(),
    };
    let mut budget = MAX_CLOSURES;
    let selection = search(&closing, &BTreeSet::new(), &BTreeSet::new(), &mut budget)?;
    Ok(selection.packages.into_values().collect())
}

/// How many closures one resolution may build while it looks for one that holds
/// a single package per name only one may answer.
///
/// Each is a whole closure, and each name two packages contend for multiplies
/// the alternatives, so the search is bounded rather than left to the shape of
/// the index. Alpine's own indexes need two or three where they need any.
const MAX_CLOSURES: usize = 64;

/// What every closure of one resolution is built from.
struct Closing<'i, 'w> {
    /// The merged index the closure is drawn from.
    index: &'i Index,
    /// The requested names, in name order and without a repeat.
    seeds: &'w [&'w str],
    /// The packages the caller excluded.
    excluded: &'w [&'w str],
    /// The packages a base layer already carries.
    installed: Vec<&'i Record>,
}

/// The packages one closure may not take.
#[derive(Clone, Copy)]
struct Barred<'a> {
    /// What the caller excluded, which a dependency nothing else answers is
    /// refused over.
    excluded: &'a [&'a str],
    /// What a search for one package per contended name set aside for this
    /// closure; see [`search`].
    forbidden: &'a BTreeSet<String>,
}

impl Barred<'_> {
    /// Whether `record` is set aside: forbidden itself, or needing by a
    /// requirement of its own a name only forbidden packages answer.
    ///
    /// The second is what keeps a closure from taking a provider only to fail
    /// one step later on what it needs: `openresty-mod-devel-kit` provides
    /// `nginx-mod-devel-kit` at a higher version than the package of that name,
    /// and requires `openresty`.
    fn sets_aside(&self, index: &Index, record: &Record) -> bool {
        if self.forbidden.is_empty() {
            return false;
        }
        self.forbidden.contains(&record.name)
            || record.depends.iter().any(|entry| {
                let answers = candidates(index, &entry.name);
                !entry.conflict
                    && !answers.is_empty()
                    && answers
                        .iter()
                        .all(|answer| self.forbidden.contains(&answer.package.name))
            })
    }
}

/// Builds the closure of `closing` with the packages in `held` taken first and
/// those in `forbidden` set aside, and where it holds two packages for a name
/// only one may answer, builds it again in the two steps the module
/// documentation describes: each of them held, then each held with the others
/// forbidden.
///
/// The first closure that holds one package per such name is the answer, so the
/// greedy closure is kept wherever it already does. A second-step retry forbids
/// a package the closure before it held and never one already held, so the
/// forbidden set only grows and the search ends; `budget` bounds how many
/// closures it builds. Where no alternative holds, the refusal is the first
/// closure's own: it is the one the requested packages led to.
fn search(
    closing: &Closing<'_, '_>,
    held: &BTreeSet<String>,
    forbidden: &BTreeSet<String>,
    budget: &mut usize,
) -> Result<Selection, ResolveError> {
    *budget = budget.saturating_sub(1);
    let selection = close(closing, held, forbidden)?;
    let Some((name, contenders)) = contention(&selection) else {
        return Ok(selection);
    };
    let alternatives = alternatives(closing, &selection, &name, &contenders);
    let with = |package: &String| {
        let mut taken = held.clone();
        taken.insert(package.clone());
        taken
    };
    for package in alternatives
        .iter()
        .filter(|package| !held.contains(*package))
    {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        if let Ok(selection) = close(closing, &with(package), forbidden)
            && contention(&selection).is_none()
        {
            return Ok(selection);
        }
    }
    for package in &alternatives {
        if *budget == 0 {
            break;
        }
        let others: Vec<&String> = contenders
            .iter()
            .filter(|other| *other != package)
            .collect();
        if others.iter().any(|other| held.contains(*other)) {
            continue;
        }
        let mut aside = forbidden.clone();
        aside.extend(others.into_iter().cloned());
        if let Ok(selection) = search(closing, &with(package), &aside, budget) {
            return Ok(selection);
        }
    }
    Err(ResolveError::Contended {
        answers: selection.offers[&name]
            .iter()
            .filter(|offer| contenders.contains(&offer.package))
            .map(Offer::to_string)
            .collect(),
        name,
    })
}

/// The closure of `closing`, with the packages in `held` taken before any name
/// is answered and those in `forbidden` never taken.
///
/// A held package is taken as itself rather than as an answer to its name, and
/// before the requested names, so a requested name it answers is already
/// answered: apk installs `p2` alone for a world of `x` and `p2` where `p2`
/// provides `x`.
fn close(
    closing: &Closing<'_, '_>,
    held: &BTreeSet<String>,
    forbidden: &BTreeSet<String>,
) -> Result<Selection, ResolveError> {
    let Closing { index, seeds, .. } = *closing;
    let barred = Barred {
        excluded: closing.excluded,
        forbidden,
    };
    let mut selection = Selection::new();
    for record in &closing.installed {
        selection.assume((*record).clone());
    }
    let mut queue: VecDeque<String> = VecDeque::new();

    for name in held {
        let record = index
            .get(name)
            .expect("a held package is one the index offers");
        add(&mut selection, &mut queue, record);
    }
    for name in seeds {
        // A requested name carries no constraint, so it is a dependency that
        // accepts any version — which is what makes one path serve the seed and
        // the closure alike.
        let wanted = Dependency {
            name: (*name).to_string(),
            constraint: None,
            conflict: false,
        };
        select(index, &wanted, None, barred, &mut selection, &mut queue)?;
    }

    while let Some(name) = queue.pop_front() {
        // Cloned so the closure may extend the selection while it walks one
        // package's requirements.
        let requirements = selection.packages[&name].depends.clone();
        for dependency in &requirements {
            if dependency.conflict {
                // A refusal constrains the closure rather than extending it, so
                // it is checked once the closure is whole. Acting on one here
                // would refuse a package the closure had not yet decided to
                // hold.
                continue;
            }
            select(
                index,
                dependency,
                Some(&name),
                barred,
                &mut selection,
                &mut queue,
            )?;
        }
    }

    install_if(index, barred, &mut selection, &mut queue)?;
    conflicts(&selection)?;
    Ok(selection)
}

/// The first name, in name order, that more than one of the closure's packages
/// answer where only one may, with the packages that contend for it.
///
/// Only one may where a package of that name is in the closure, or where a
/// package provides it at a version. A name that only base packages contend for
/// is the base's, which already exists; one the increment contends for is
/// reported, since the merged root would hold both.
fn contention(selection: &Selection) -> Option<(String, BTreeSet<String>)> {
    let mut names: Vec<&String> = selection.offers.keys().collect();
    names.sort_unstable();
    names.into_iter().find_map(|name| {
        let offers = &selection.offers[name];
        let increment = |offer: &Offer| selection.packages.contains_key(&offer.package);
        let mut contenders = BTreeSet::new();
        for one in offers {
            for other in offers {
                if one.contends_with(other) && (increment(one) || increment(other)) {
                    contenders.insert(one.package.clone());
                    contenders.insert(other.package.clone());
                }
            }
        }
        (!contenders.is_empty()).then(|| (name.clone(), contenders))
    })
}

/// The packages contending for `name` in `selection` that a closure may be
/// built around, best first by the ranking the module documents.
///
/// One a base layer carries is not an alternative, since the base cannot be
/// changed. Neither is one that offers `name` at no version without a provider
/// priority, unless the closure needs it by its own name: apk chooses such a
/// package for a name only where something already requires it.
fn alternatives(
    closing: &Closing<'_, '_>,
    selection: &Selection,
    name: &str,
    contenders: &BTreeSet<String>,
) -> Vec<String> {
    let named = |package: &str| {
        closing.seeds.contains(&package)
            || selection.packages.values().any(|record| {
                record
                    .depends
                    .iter()
                    .any(|entry| !entry.conflict && entry.name == package)
            })
    };
    let candidates = candidates(closing.index, name);
    let mut eligible: Vec<&Candidate<'_>> = candidates
        .iter()
        .filter(|candidate| {
            let package = candidate.package.name.as_str();
            contenders.contains(package)
                && !selection.assumed.contains_key(package)
                && (candidate.offers.is_some()
                    || candidate.package.provider_priority.is_some()
                    || named(package))
        })
        .collect();
    eligible.sort_by(|a, b| match (better(a, b), better(b, a)) {
        (true, _) => std::cmp::Ordering::Less,
        (_, true) => std::cmp::Ordering::Greater,
        _ => std::cmp::Ordering::Equal,
    });
    eligible
        .into_iter()
        .map(|candidate| candidate.package.name.clone())
        .collect()
}

/// Satisfies one dependency, extending the selection where it is not already
/// satisfied.
fn select(
    index: &Index,
    dependency: &Dependency,
    required_by: Option<&str>,
    barred: Barred<'_>,
    selection: &mut Selection,
    queue: &mut VecDeque<String>,
) -> Result<(), ResolveError> {
    if selection.holds(dependency, required_by) {
        return Ok(());
    }
    let candidates = candidates(index, &dependency.name);
    if candidates.is_empty() {
        return match required_by {
            Some(package) => Err(ResolveError::Unsatisfied {
                dependency: dependency.to_string(),
                required_by: Some(package.to_string()),
                offered: Vec::new(),
            }),
            None => Err(ResolveError::NotFound {
                name: dependency.name.clone(),
            }),
        };
    }

    let mut excluded_one = false;
    let mut accepted: Vec<&Candidate<'_>> = Vec::new();
    for candidate in &candidates {
        if barred.excluded.contains(&candidate.package.name.as_str()) {
            excluded_one = true;
            continue;
        }
        if barred.sets_aside(index, candidate.package) {
            continue;
        }
        if dependency.accepts(candidate.offers) {
            accepted.push(candidate);
        }
    }
    let Some(highest) = best(&accepted) else {
        if excluded_one {
            return Err(ResolveError::ExcludedButRequired {
                dependency: dependency.to_string(),
                required_by: required_by.map(str::to_string),
            });
        }
        // The index offers a pinned package at its pinned version alone, so
        // where that version is what the dependency rules out, the pin is what
        // refuses it. A requested name accepts every version, so it is never
        // one.
        if let Some(declared_by) = required_by
            && index.get(&dependency.name).is_some()
            && let Some(unheld) = index.pins().refuse_requirement(dependency, declared_by)
        {
            return Err(ResolveError::Pinned { unheld });
        }
        return Err(ResolveError::Unsatisfied {
            dependency: dependency.to_string(),
            required_by: required_by.map(str::to_string),
            offered: candidates
                .iter()
                .map(|candidate| match candidate.offers {
                    Some(version) => format!("{} at {version}", candidate.package.name),
                    None => format!("{} at no version", candidate.package.name),
                })
                .collect(),
        });
    };

    // A base layer already carrying a candidate means installing that candidate
    // would leave two versions of one package in the merged root: the base's own
    // offer was consulted first, at the top of this function, and did not satisfy
    // the entry. So does a base carrying a package that contends with the
    // candidate for the name, since a root holds one of the two: apk would purge
    // the base's, which an increment cannot. Such a candidate cannot be taken, so
    // it is dropped here rather than being ranked and then refused — a
    // *different* provider that satisfies the entry without either is a
    // resolution, and one apk's own solver would find. Only when every candidate
    // would displace something the base carries is there nothing left to do but
    // stop, and the refusal then names what the base carries in the way of the
    // highest-ranked of them, which is the one that was asked for.
    let installable: Vec<&Candidate<'_>> = accepted
        .iter()
        .copied()
        .filter(|candidate| {
            selection
                .carried_in_the_way(&dependency.name, candidate)
                .is_none()
        })
        .collect();
    let Some(best) = best(&installable) else {
        let carried = selection
            .carried_in_the_way(&dependency.name, highest)
            .expect("no candidate is installable, so the base carries one in the highest's way");
        return Err(ResolveError::WouldUpgrade {
            name: carried.name.clone(),
            installed: carried.version.clone(),
            offered: highest
                .offers
                .unwrap_or(&highest.package.version)
                .to_string(),
            dependency: dependency.to_string(),
            required_by: required_by.map(str::to_string),
        });
    };

    // A name answered only by unversioned `p:` entries is one apk declines to
    // choose for, unless a provider ranks itself with `k:` above zero. Following
    // that is what keeps a closure from silently taking whichever shell or
    // whichever `awk` the archive happens to list. The choice is among what can
    // be installed, so a provider the base already carries is not one of the
    // names the refusal offers.
    if best.offers.is_none() && best.package.provider_priority.is_none() {
        return Err(ResolveError::Ambiguous {
            name: dependency.name.clone(),
            providers: installable
                .iter()
                .map(|candidate| candidate.package.name.clone())
                .collect(),
            required_by: required_by.map(str::to_string),
        });
    }

    add(selection, queue, best.package);
    Ok(())
}

/// Adds every package whose `i:` condition the closure satisfies, to a fixed
/// point.
///
/// A package added this way can satisfy another's condition, so the pass repeats
/// until a round adds nothing. It runs after the main closure rather than during
/// it, since a condition tested against a half-built selection would answer
/// about a closure that never existed.
///
/// A condition may be negated — one package in Alpine's `main` states
/// `install_if: docs !tk-doc` — and a negated condition is not monotone: a
/// package added by a later round can be one an earlier round's condition
/// required to be absent. The passes only add, so such a package stays, which is
/// the same order of evaluation apk applies and the reason the rule is stated
/// here rather than left to be inferred.
fn install_if(
    index: &Index,
    barred: Barred<'_>,
    selection: &mut Selection,
    queue: &mut VecDeque<String>,
) -> Result<(), ResolveError> {
    loop {
        let mut added = Vec::new();
        for record in index.records() {
            if record.install_if.is_empty()
                || selection.packages.contains_key(&record.name)
                // A base layer already carrying it needs no second copy, and its
                // own installation ran whatever condition it declared.
                || selection.assumed.contains_key(&record.name)
                || barred.excluded.contains(&record.name.as_str())
                || barred.sets_aside(index, record)
            {
                continue;
            }
            if record
                .install_if
                .iter()
                .all(|condition| selection.holds(condition, Some(&record.name)))
            {
                added.push(record);
            }
        }
        if added.is_empty() {
            return Ok(());
        }
        // Sorted so that a round adding several packages adds them in one order
        // whatever order the index yielded them in.
        added.sort_by(|a, b| a.name.cmp(&b.name));
        for record in added {
            add(selection, queue, record);
        }
        // Whatever the new packages require is resolved before the next round,
        // so a condition is tested against a closure that is whole again.
        while let Some(name) = queue.pop_front() {
            let requirements = selection.packages[&name].depends.clone();
            for dependency in requirements.iter().filter(|entry| !entry.conflict) {
                select(index, dependency, Some(&name), barred, selection, queue)?;
            }
        }
    }
}

/// Checks every `!` entry the closure's packages declare against the closure.
///
/// Run once the closure is whole: a refusal is about what was selected in the
/// end, and one checked as the closure was built would fire on a package that
/// had not been chosen yet or miss one chosen later.
///
/// A base layer's packages declare refusals too, and the merged root has to hold
/// against those as well — an increment must not install what the base refuses.
/// What is *not* reported is a base refusal that only the base breaks: the base
/// is a root that already exists, and refusing to layer over it because of
/// something the increment did not cause would name the wrong thing.
fn conflicts(selection: &Selection) -> Result<(), ResolveError> {
    let declarations = selection
        .packages
        .values()
        .map(|record| (record, false))
        .chain(selection.assumed.values().map(|record| (record, true)));
    for (record, carried) in declarations {
        for refusal in record.depends.iter().filter(|entry| entry.conflict) {
            // Every breaker rather than the first: a carried declarer excuses
            // only the breakers the base itself already held, and base offers
            // sort ahead of the increment's, so stopping at the first would
            // excuse the increment along with the base whenever both break the
            // same refusal.
            let mut breakers = selection.breakers(refusal, Some(&record.name));
            let present = match carried {
                true => breakers.find(|offer| selection.packages.contains_key(&offer.package)),
                false => breakers.next(),
            };
            let Some(present) = present else { continue };
            return Err(ResolveError::Conflict {
                dependency: refusal.to_string(),
                declared_by: record.name.clone(),
                present: present.to_string(),
            });
        }
    }
    Ok(())
}

/// One package that answers a name, and the version it answers it at.
struct Candidate<'a> {
    package: &'a Record,
    /// The version offered *for the name asked about*: the package's own where
    /// it is that package, and the `p:` entry's where it is a provider.
    offers: Option<&'a str>,
}

/// Every package that answers `name`, in no particular order.
fn candidates<'a>(index: &'a Index, name: &str) -> Vec<Candidate<'a>> {
    let mut candidates = Vec::new();
    if let Some(package) = index.get(name) {
        candidates.push(Candidate {
            package,
            offers: Some(&package.version),
        });
    }
    for provider in index.providers(name) {
        let Some(package) = index.get(provider) else {
            continue;
        };
        candidates.push(Candidate {
            package,
            offers: package
                .provides
                .iter()
                .find(|provided| provided.name == name)
                .and_then(|provided| provided.version.as_deref()),
        });
    }
    candidates
}

/// The candidate a resolution takes, by the ranking the module documents.
fn best<'a, 'b>(candidates: &[&'b Candidate<'a>]) -> Option<&'b Candidate<'a>> {
    candidates.iter().copied().reduce(|best, candidate| {
        if better(candidate, best) {
            candidate
        } else {
            best
        }
    })
}

/// Whether `candidate` outranks `best`.
fn better(candidate: &Candidate<'_>, best: &Candidate<'_>) -> bool {
    // A candidate offering no version ranks below every one that offers a
    // version, and two of them rank only by what follows.
    let order = match (candidate.offers, best.offers) {
        (Some(a), Some(b)) => version::compare(a, b).unwrap_or(std::cmp::Ordering::Equal),
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (None, None) => std::cmp::Ordering::Equal,
    };
    order
        .then_with(|| {
            // A stated priority is always greater than zero — `Record` collapses
            // `k:0` into "none" because that is what apk does with it — so "no
            // priority" ranks below every stated one and beside every other
            // absent one, which is exactly zero.
            candidate
                .package
                .provider_priority
                .unwrap_or(0)
                .cmp(&best.package.provider_priority.unwrap_or(0))
        })
        // The names are distinct, so this settles every remaining tie.
        .then_with(|| best.package.name.cmp(&candidate.package.name))
        .is_gt()
}

/// Adds a package to the selection and the work queue, if it is not held
/// already.
fn add(selection: &mut Selection, queue: &mut VecDeque<String>, record: &Record) {
    if selection.packages.contains_key(&record.name) {
        return;
    }
    selection.insert(record.clone());
    queue.push_back(record.name.clone());
}

/// One selected package's answer to one name.
struct Offer {
    /// The package answering.
    package: String,
    /// The version it answers at, absent for a `p:` entry that states none.
    version: Option<String>,
    /// Whether it answers by being that package rather than by providing the
    /// name.
    own_name: bool,
}

impl Offer {
    /// The offer `candidate` makes for `name`.
    fn of(name: &str, candidate: &Candidate<'_>) -> Offer {
        Offer {
            package: candidate.package.name.clone(),
            version: candidate.offers.map(str::to_string),
            own_name: candidate.package.name == name,
        }
    }

    /// Whether this offer and `other`, from another package, cannot both answer
    /// their name in one root.
    ///
    /// The rule apk applies, as the module documentation states it: a package's
    /// own name contends with every other answer to it, and two answers at a
    /// version contend with each other. Two answers at no version share the
    /// name.
    fn contends_with(&self, other: &Offer) -> bool {
        let exclusive = |offer: &Offer| offer.own_name || offer.version.is_some();
        self.package != other.package
            && (self.own_name || other.own_name || (exclusive(self) && exclusive(other)))
    }
}

impl fmt::Display for Offer {
    /// Names the package and the version it offers, for the refusals that quote
    /// what broke them.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.version {
            Some(version) => write!(f, "{} at {version}", self.package),
            None => write!(f, "{} at no version", self.package),
        }
    }
}

/// The packages chosen so far, and what they answer to.
///
/// The two are kept together because every question the resolver asks is about
/// what the selection *answers*, not about which packages are in it: a
/// dependency on `so:libc.musl-x86_64.so.1` is satisfied by whichever selected
/// package provides that name.
struct Selection {
    /// The chosen packages by name, ordered so the resolution is one value.
    packages: BTreeMap<String, Record>,
    /// The packages a base layer already carries, which answer names without
    /// being installed again. Empty for a full bootstrap, which has no base.
    assumed: BTreeMap<String, Record>,
    /// Every name the chosen and carried packages answer to, and how.
    offers: HashMap<String, Vec<Offer>>,
}

impl Selection {
    /// An empty selection.
    fn new() -> Selection {
        Selection {
            packages: BTreeMap::new(),
            assumed: BTreeMap::new(),
            offers: HashMap::new(),
        }
    }

    /// Adds a package and records everything it answers to.
    fn insert(&mut self, record: Record) {
        self.answer(&record);
        self.packages.insert(record.name.clone(), record);
    }

    /// Records a package a base layer already carries: it answers names as a
    /// selected package does, and is not part of the increment.
    fn assume(&mut self, record: Record) {
        self.answer(&record);
        self.assumed.insert(record.name.clone(), record);
    }

    /// The package a base layer carries that `candidate` cannot be installed
    /// beside as an answer to `name`: the candidate itself, or a package that
    /// contends with it for the name.
    fn carried_in_the_way(&self, name: &str, candidate: &Candidate<'_>) -> Option<&Record> {
        if let Some(carried) = self.assumed.get(&candidate.package.name) {
            return Some(carried);
        }
        let offer = Offer::of(name, candidate);
        self.offers
            .get(name)
            .into_iter()
            .flatten()
            .filter(|carried| carried.contends_with(&offer))
            .find_map(|carried| self.assumed.get(&carried.package))
    }

    /// Records everything one package answers to.
    fn answer(&mut self, record: &Record) {
        self.offers
            .entry(record.name.clone())
            .or_default()
            .push(Offer {
                package: record.name.clone(),
                version: Some(record.version.clone()),
                own_name: true,
            });
        for provided in &record.provides {
            self.offers
                .entry(provided.name.clone())
                .or_default()
                .push(Offer {
                    package: record.name.clone(),
                    version: provided.version.clone(),
                    own_name: false,
                });
        }
    }

    /// Whether `dependency` holds against this selection.
    ///
    /// `declared_by` is the package the entry came from, where there is one. It
    /// matters for a refusal alone: a package that provides a name and refuses
    /// it in the same breath is not refusing itself, which is the exemption apk
    /// makes and the reason this takes an argument it otherwise would not.
    fn holds(&self, dependency: &Dependency, declared_by: Option<&str>) -> bool {
        self.materializer(dependency, declared_by).is_some() != dependency.conflict
    }

    /// Every offer that breaks `dependency`, where `dependency` is a refusal and
    /// the selection holds something it refuses.
    ///
    /// All of them rather than the first, because which one a refusal is
    /// reported against is a decision the caller makes: a refusal declared by a
    /// package the base carries is excused by a breaker the base already held
    /// and not by one the increment brought.
    fn breakers<'s, 'd>(
        &'s self,
        dependency: &'d Dependency,
        declared_by: Option<&'d str>,
    ) -> impl Iterator<Item = &'s Offer> + use<'s, 'd> {
        debug_assert!(dependency.conflict, "only a refusal can be broken");
        self.materializers(dependency, declared_by)
    }

    /// The first offer that answers `dependency` at a version it accepts.
    fn materializer(&self, dependency: &Dependency, declared_by: Option<&str>) -> Option<&Offer> {
        self.materializers(dependency, declared_by).next()
    }

    /// Every offer that answers `dependency` at a version it accepts, in the
    /// order they were recorded.
    ///
    /// `declared_by` is the package the entry came from, where there is one. It
    /// matters for a refusal alone: a package that provides a name and refuses
    /// it in the same breath is not refusing itself, which is the exemption apk
    /// makes and the reason this takes an argument it otherwise would not.
    fn materializers<'s, 'd>(
        &'s self,
        dependency: &'d Dependency,
        declared_by: Option<&'d str>,
    ) -> impl Iterator<Item = &'s Offer> + use<'s, 'd> {
        self.offers
            .get(&dependency.name)
            .into_iter()
            .flatten()
            .filter(move |offer| {
                let itself = dependency.conflict
                    && !offer.own_name
                    && Some(offer.package.as_str()) == declared_by;
                !itself && dependency.accepts(offer.version.as_deref())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::alpine::AlpineError;
    use crate::provision::alpine::index;
    use crate::provision::alpine::pin::{Pins, UnheldReason};

    /// One record, spelled as an index spells it: the fields every record
    /// carries, then whatever the case is about.
    fn record(name: &str, version: &str, fields: &str) -> String {
        let mut identity = String::from("Q1");
        for byte in name.bytes().cycle().take(27) {
            identity.push(char::from(b'a' + byte % 26));
        }
        identity.push('=');
        format!("C:{identity}\nP:{name}\nV:{version}\nA:x86_64\nS:1024\n{fields}\n")
    }

    /// An index over `records`, each a `(name, version, fields)` triple.
    fn merged(records: &[(&str, &str, &str)]) -> Index {
        let text: String = records
            .iter()
            .map(|(name, version, fields)| record(name, version, fields))
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = index::parse("the index", &text, 0)
            .unwrap_or_else(|err| panic!("the index parses: {err}"));
        Index::merge([parsed], "x86_64", &Pins::none())
    }

    /// The names the closure of `world` holds, or a panic naming the refusal.
    fn closure(index: &Index, world: &[&str]) -> Vec<String> {
        resolved(index, world, &[]).unwrap_or_else(|err| panic!("the closure resolves: {err}"))
    }

    /// The closure of `world` under `excludes`, as names.
    fn resolved(
        index: &Index,
        world: &[&str],
        excludes: &[&str],
    ) -> Result<Vec<String>, ResolveError> {
        resolved_over(index, world, excludes, &[])
    }

    /// The records a base layer's `installed` database would hand a layered
    /// resolution, spelled as index records because that is what it holds.
    fn carried(records: &[(&str, &str, &str)]) -> Vec<Record> {
        let text: String = records
            .iter()
            .map(|(name, version, fields)| record(name, version, fields))
            .collect::<Vec<_>>()
            .join("\n");
        index::parse("the base", &text, usize::MAX)
            .unwrap_or_else(|err| panic!("the base parses: {err}"))
    }

    /// The increment `world` resolves to over a base carrying `installed`.
    fn resolved_over(
        index: &Index,
        world: &[&str],
        excludes: &[&str],
        installed: &[Record],
    ) -> Result<Vec<String>, ResolveError> {
        let world: Vec<String> = world.iter().map(|name| (*name).to_string()).collect();
        let excludes: Vec<String> = excludes.iter().map(|name| (*name).to_string()).collect();
        Ok(resolve(index, &world, &excludes, installed)?
            .into_iter()
            .map(|record| record.name)
            .collect())
    }

    #[test]
    fn the_closure_follows_what_a_package_requires_and_stops() {
        let index = merged(&[
            ("app", "1.0-r0", "D:lib so:libc.musl-x86_64.so.1"),
            ("lib", "2.0-r0", ""),
            ("musl", "1.2.5-r23", "p:so:libc.musl-x86_64.so.1=1.2.5-r23"),
            ("unrelated", "1.0-r0", ""),
        ]);
        assert_eq!(closure(&index, &["app"]), ["app", "lib", "musl"]);
    }

    #[test]
    fn a_cycle_terminates() {
        let index = merged(&[("a", "1.0-r0", "D:b"), ("b", "1.0-r0", "D:a")]);
        assert_eq!(closure(&index, &["a"]), ["a", "b"]);
    }

    #[test]
    fn the_version_offered_outranks_the_package_that_offers_it() {
        // As apk.static ranks them: a package providing `thing=9.0` beats the
        // real `thing` at 1.0, and the real one wins when it is the higher. The
        // ranking is on the version offered for the name, not on the offering
        // package's own version -- both providers here are at 1.0-r0.
        let higher_provider = merged(&[
            ("app", "1.0-r0", "D:thing"),
            ("thing", "1.0-r0", ""),
            ("other", "1.0-r0", "p:thing=9.0-r0"),
        ]);
        assert_eq!(closure(&higher_provider, &["app"]), ["app", "other"]);

        let higher_real = merged(&[
            ("app", "1.0-r0", "D:thing"),
            ("thing", "9.0-r0", ""),
            ("other", "1.0-r0", "p:thing=1.0-r0"),
        ]);
        assert_eq!(closure(&higher_real, &["app"]), ["app", "thing"]);
    }

    #[test]
    fn the_provider_priority_breaks_a_tie_in_the_offered_version() {
        // And only a tie: a k: of 90 does not lift a provider over one offering
        // a higher version, which is the order apk.static applies.
        let tie = merged(&[
            ("app", "1.0-r0", "D:thing"),
            ("thing", "1.0-r0", ""),
            ("other", "1.0-r0", "p:thing=1.0-r0\nk:50"),
        ]);
        assert_eq!(closure(&tie, &["app"]), ["app", "other"]);

        let outranked = merged(&[
            ("app", "1.0-r0", "D:virt"),
            ("hi", "1.0-r0", "p:virt=1.0-r0\nk:90"),
            ("lo", "1.0-r0", "p:virt=2.0-r0\nk:10"),
        ]);
        assert_eq!(closure(&outranked, &["app"]), ["app", "lo"]);
    }

    #[test]
    fn a_tie_nothing_else_settles_is_broken_on_the_name() {
        // This step is ours rather than apk's: apk takes whichever provider the
        // index lists first, which is a property of the mirror. A closure has to
        // resolve the same way twice, so the tie breaks on the name.
        let index = merged(&[
            ("app", "1.0-r0", "D:virt"),
            ("zzz", "1.0-r0", "p:virt=1.0-r0"),
            ("aaa", "1.0-r0", "p:virt=1.0-r0"),
        ]);
        assert_eq!(closure(&index, &["app"]), ["aaa", "app"]);
    }

    #[test]
    fn a_name_provided_at_no_version_needs_a_provider_priority() {
        // apk declines to choose between unversioned providers and asks to be
        // told which package to install; so does this, naming them. One provider
        // is no less ambiguous than two -- the point is that the repository has
        // expressed no preference.
        let index = merged(&[
            ("app", "1.0-r0", "D:virt"),
            ("pa", "1.0-r0", "p:virt"),
            ("pb", "1.0-r0", "p:virt"),
        ]);
        match resolved(&index, &["app"], &[]) {
            Err(ResolveError::Ambiguous { providers, .. }) => {
                assert_eq!(providers, ["pa", "pb"]);
            }
            other => panic!("expected an ambiguity, got {other:?}"),
        }

        // A k: on one of them is the repository expressing one.
        let ranked = merged(&[
            ("app", "1.0-r0", "D:virt"),
            ("pa", "1.0-r0", "p:virt"),
            ("pb", "1.0-r0", "p:virt\nk:10"),
        ]);
        assert_eq!(closure(&ranked, &["app"]), ["app", "pb"]);
    }

    #[test]
    fn a_base_answers_a_name_and_the_increment_leaves_it_alone() {
        // The whole of what a layered resolution does differently: a package the
        // base carries is already answered, so neither it nor anything only it
        // needed joins the increment.
        let index = merged(&[
            ("app", "1.0-r0", "D:lib"),
            ("lib", "1.0-r0", "D:only-for-lib"),
            ("only-for-lib", "1.0-r0", ""),
        ]);
        let base = carried(&[
            ("lib", "1.0-r0", "D:only-for-lib"),
            ("only-for-lib", "1.0-r0", ""),
        ]);
        assert_eq!(
            resolved_over(&index, &["app"], &[], &base).unwrap(),
            ["app"]
        );
    }

    #[test]
    fn a_base_answers_at_a_version_rather_than_by_name() {
        // A constraint the base's version does not meet is reported as the
        // upgrade it would be, rather than being quietly taken as answered: an
        // increment installs over a base, and a package the base carries cannot
        // be replaced without rebuilding it.
        let index = merged(&[("app", "1.0-r0", "D:lib>=2.0-r0"), ("lib", "2.0-r0", "")]);
        let base = carried(&[("lib", "1.0-r0", "")]);
        match resolved_over(&index, &["app"], &[], &base) {
            Err(ResolveError::WouldUpgrade {
                name,
                installed,
                offered,
                ..
            }) => {
                assert_eq!(
                    (name.as_str(), installed.as_str(), offered.as_str()),
                    ("lib", "1.0-r0", "2.0-r0")
                );
            }
            other => panic!("expected an upgrade refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_alternative_provider_is_taken_before_an_upgrade_is_refused() {
        // The base answers `lib` through `shim`, at no version, so not for the
        // constraint. The highest-ranked candidate is the package `lib`, which a
        // root cannot hold beside another answer to its own name: apk would
        // purge `shim` for it, and an increment cannot. A provider at a version
        // shares the name with `shim`'s, so it is the resolution that exists.
        let index = merged(&[
            ("app", "1.0-r0", "D:lib>=2.0-r0"),
            ("lib", "4.0-r0", ""),
            ("other-lib", "1.0-r0", "p:lib=3.0-r0"),
        ]);
        let base = carried(&[("shim", "1.0-r0", "p:lib\nk:1")]);
        assert_eq!(
            resolved_over(&index, &["app"], &[], &base).unwrap(),
            ["app", "other-lib"],
        );

        let index = merged(&[
            ("app", "1.0-r0", "D:lib>=2.0-r0"),
            ("lib", "2.0-r0", ""),
            ("other-lib", "1.0-r0", "p:lib=3.0-r0"),
            ("third-lib", "1.0-r0", "p:lib=2.5-r0"),
        ]);
        let base = carried(&[("base-lib", "1.0-r0", "p:lib=1.0-r0")]);
        // Every offer at a version contends with the base's own, which apk would
        // purge and an increment cannot, so this is the upgrade it would be,
        // named against what the base carries.
        match resolved_over(&index, &["app"], &[], &base) {
            Err(ResolveError::WouldUpgrade {
                name,
                installed,
                offered,
                ..
            }) => {
                assert_eq!(name, "base-lib");
                assert_eq!(installed, "1.0-r0");
                assert_eq!(offered, "3.0-r0", "the highest-ranked offer");
            }
            other => panic!("expected an upgrade refusal, got {other:?}"),
        }

        // A provider of the base's own package name contends with it too: apk
        // purges `lib` to install `other-lib` here.
        let index = merged(&[
            ("app", "1.0-r0", "D:lib>=2.0-r0"),
            ("lib", "2.0-r0", ""),
            ("other-lib", "1.0-r0", "p:lib=3.0-r0"),
        ]);
        let base = carried(&[("lib", "1.0-r0", "")]);
        assert!(matches!(
            resolved_over(&index, &["app"], &[], &base),
            Err(ResolveError::WouldUpgrade { name, .. }) if name == "lib",
        ));

        // And with no alternative there is still nothing to do but stop, naming
        // the candidate that was asked for.
        let alone = merged(&[("app", "1.0-r0", "D:lib>=2.0-r0"), ("lib", "2.0-r0", "")]);
        assert!(matches!(
            resolved_over(&alone, &["app"], &[], &base),
            Err(ResolveError::WouldUpgrade { .. }),
        ));
    }

    #[test]
    fn a_carried_refusal_is_reported_against_the_increment_that_breaks_it() {
        // A base package refusing a name the base itself already answers is the
        // base's own business — refusing to layer over it would name the wrong
        // thing. But the base's offers sort ahead of the increment's, so a
        // refusal broken by *both* must still be reported: it is the increment
        // that is being decided here.
        let index = merged(&[
            ("app", "1.0-r0", "D:plugin"),
            ("plugin", "1.0-r0", "p:feature=1.0-r0"),
        ]);
        // The base holds `host`, which refuses `feature`, and its own `shipped`
        // already provides one — a tree that already violates its own refusal.
        let base = carried(&[
            ("host", "1.0-r0", "D:!feature"),
            ("shipped", "1.0-r0", "p:feature=1.0-r0"),
        ]);
        match resolved_over(&index, &["app"], &[], &base) {
            Err(ResolveError::Conflict {
                declared_by,
                present,
                ..
            }) => {
                assert_eq!(declared_by, "host");
                assert!(present.contains("plugin"), "{present}");
            }
            other => panic!("expected a conflict naming the increment, got {other:?}"),
        }

        // With nothing in the increment breaking it, the base's own violation
        // stays the base's own business.
        let quiet = merged(&[("app", "1.0-r0", "")]);
        assert_eq!(
            resolved_over(&quiet, &["app"], &[], &base).unwrap(),
            ["app"]
        );
    }

    #[test]
    fn a_priority_that_is_not_above_zero_is_no_preference_at_all() {
        // `apk.static` 3.0.7 reads it this way: a provider stating `k:0`,
        // `k:-1` or `k:abc` leaves it refusing to choose against one stating
        // no `k:` at all, exactly as two unranked providers do, while `k:1`
        // wins outright. Telling `k:0` apart from an absent `k:` would
        // make a zero-priority provider silently auto-selectable here and not
        // under apk.
        for stated in ["k:0", "k:-1", "k:abc", "k:"] {
            let index = merged(&[
                ("app", "1.0-r0", "D:virt"),
                ("pa", "1.0-r0", "p:virt"),
                ("pb", "1.0-r0", &format!("p:virt\n{stated}")),
            ]);
            match resolved(&index, &["app"], &[]) {
                Err(ResolveError::Ambiguous { providers, .. }) => {
                    assert_eq!(providers, ["pa", "pb"], "{stated}");
                }
                other => panic!("expected an ambiguity for {stated}, got {other:?}"),
            }
        }

        // And the record is kept rather than refused, which is what keeps this
        // reader from refusing an index apk itself reads: `pb` is still there to
        // be installed by name.
        let index = merged(&[("pa", "1.0-r0", "p:virt"), ("pb", "1.0-r0", "p:virt\nk:0")]);
        assert_eq!(closure(&index, &["pb"]), ["pb"]);

        // A stated priority still outranks an absent one, in either order.
        for order in [["k:2", ""], ["", "k:2"]] {
            let index = merged(&[
                ("app", "1.0-r0", "D:virt"),
                ("pa", "1.0-r0", &format!("p:virt\n{}", order[0])),
                ("pb", "1.0-r0", &format!("p:virt\n{}", order[1])),
            ]);
            let winner = if order[0] == "k:2" { "pa" } else { "pb" };
            assert_eq!(closure(&index, &["app"]), ["app", winner], "{order:?}");
        }
    }

    #[test]
    fn a_name_provided_at_no_version_satisfies_no_constraint() {
        // Otherwise a mirror could answer python3>=3.12 with a package that
        // merely says it provides python3.
        let index = merged(&[
            ("app", "1.0-r0", "D:virt>=2.0"),
            ("prov", "9.9-r0", "p:virt\nk:100"),
        ]);
        match resolved(&index, &["app"], &[]) {
            Err(ResolveError::Unsatisfied { offered, .. }) => {
                assert_eq!(offered, ["prov at no version"]);
            }
            other => panic!("expected an unsatisfied dependency, got {other:?}"),
        }
    }

    #[test]
    fn a_refusal_is_a_negated_constraint_rather_than_an_absence() {
        // The pair a debug package publishes: it needs alsa-lib, and refuses
        // every version of it but the one it was split from. All three hold
        // together, which a resolver reading `!` as "must be absent" would
        // refuse -- and that combination is what Alpine actually publishes.
        let matching = merged(&[
            (
                "alsa-lib-dbg",
                "1.2.14-r2",
                "D:alsa-lib !alsa-lib<1.2.14-r2 !alsa-lib>1.2.14-r2",
            ),
            ("alsa-lib", "1.2.14-r2", ""),
        ]);
        assert_eq!(
            closure(&matching, &["alsa-lib-dbg"]),
            ["alsa-lib", "alsa-lib-dbg"],
        );

        let moved_on = merged(&[
            (
                "alsa-lib-dbg",
                "1.2.14-r2",
                "D:alsa-lib !alsa-lib<1.2.14-r2 !alsa-lib>1.2.14-r2",
            ),
            ("alsa-lib", "1.2.14-r3", ""),
        ]);
        match resolved(&moved_on, &["alsa-lib-dbg"], &[]) {
            Err(ResolveError::Conflict {
                dependency,
                declared_by,
                present,
            }) => {
                assert_eq!(dependency, "!alsa-lib>1.2.14-r2");
                assert_eq!(declared_by, "alsa-lib-dbg");
                assert_eq!(present, "alsa-lib at 1.2.14-r3");
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn a_refusal_with_no_constraint_refuses_every_version() {
        let index = merged(&[
            ("dropbear-ssh", "1.0-r0", "D:!openssh-client"),
            ("openssh-client", "1.0-r0", ""),
        ]);
        closure(&index, &["dropbear-ssh"]);
        assert!(
            resolved(&index, &["dropbear-ssh", "openssh-client"], &[]).is_err(),
            "the two cannot be installed together",
        );
    }

    #[test]
    fn a_refusal_reaches_a_provided_name_and_not_the_package_making_it() {
        // Both halves of apk's rule: a refusal is checked against what the
        // closure provides as well as what it is named, and a package that
        // provides a name and refuses it in the same breath is not refusing
        // itself.
        let provided = merged(&[
            ("app", "1.0-r0", "D:x !virt"),
            ("x", "1.0-r0", "p:virt=1.0-r0"),
        ]);
        assert!(resolved(&provided, &["app"], &[]).is_err());

        let itself = merged(&[("sole", "1.0-r0", "p:virt=1.0-r0\nD:!virt")]);
        assert_eq!(closure(&itself, &["sole"]), ["sole"]);
    }

    #[test]
    fn a_package_joins_the_closure_when_its_condition_comes_to_hold() {
        let index = merged(&[
            ("app", "1.0-r0", ""),
            ("docs", "1.0-r0", ""),
            ("app-doc", "1.0-r0", "i:docs app=1.0-r0"),
        ]);
        assert_eq!(closure(&index, &["app"]), ["app"], "docs is absent");
        assert_eq!(
            closure(&index, &["app", "docs"]),
            ["app", "app-doc", "docs"],
        );
    }

    #[test]
    fn one_conditional_package_can_satisfy_another_s_condition() {
        // Which is why the pass runs to a fixed point rather than once.
        let index = merged(&[
            ("a", "1.0-r0", ""),
            ("b", "1.0-r0", "i:a"),
            ("c", "1.0-r0", "i:b"),
        ]);
        assert_eq!(closure(&index, &["a"]), ["a", "b", "c"]);
    }

    #[test]
    fn a_condition_may_require_a_package_to_be_absent() {
        let index = merged(&[
            ("a", "1.0-r0", ""),
            ("x", "1.0-r0", ""),
            ("b", "1.0-r0", "i:a !x"),
        ]);
        assert_eq!(closure(&index, &["a"]), ["a", "b"]);
        assert_eq!(closure(&index, &["a", "x"]), ["a", "x"], "x is present");
    }

    #[test]
    fn what_a_conditional_package_requires_joins_the_closure_with_it() {
        let index = merged(&[
            ("a", "1.0-r0", ""),
            ("b", "1.0-r0", "i:a\nD:helper"),
            ("helper", "1.0-r0", ""),
        ]);
        assert_eq!(closure(&index, &["a"]), ["a", "b", "helper"]);
    }

    #[test]
    fn an_exclusion_redirects_a_name_to_another_provider() {
        let index = merged(&[
            ("app", "1.0-r0", "D:cmd:awk"),
            ("gawk", "1.0-r0", "p:cmd:awk=1.0-r0"),
            ("mawk", "1.0-r0", "p:cmd:awk=1.0-r0"),
        ]);
        // The tie breaks on the name, so gawk is the default pick; excluding it
        // proves the exclusion redirected the choice rather than coinciding
        // with it.
        assert_eq!(closure(&index, &["app"]), ["app", "gawk"]);
        assert_eq!(
            resolved(&index, &["app"], &["gawk"]).expect("mawk answers instead"),
            ["app", "mawk"],
        );
    }

    #[test]
    fn an_exclusion_that_leaves_a_requirement_unsatisfiable_is_refused() {
        // apk has no alternative groups, so there is nothing else for a
        // dependency to fall through to; shipping the closure without it would
        // be shipping a root that does not work.
        let index = merged(&[("app", "1.0-r0", "D:lib"), ("lib", "1.0-r0", "")]);
        match resolved(&index, &["app"], &["lib"]) {
            Err(ResolveError::ExcludedButRequired {
                dependency,
                required_by,
            }) => {
                assert_eq!(dependency, "lib");
                assert_eq!(required_by.as_deref(), Some("app"));
            }
            other => panic!("expected an exclusion refusal, got {other:?}"),
        }
    }

    #[test]
    fn asking_for_a_package_and_excluding_it_is_a_contradiction() {
        let index = merged(&[("app", "1.0-r0", "")]);
        assert!(matches!(
            resolved(&index, &["app"], &["app"]),
            Err(ResolveError::ExcludedAndIncluded { name }) if name == "app",
        ));
    }

    #[test]
    fn a_requested_name_no_repository_offers_is_refused() {
        let index = merged(&[("app", "1.0-r0", "")]);
        assert!(matches!(
            resolved(&index, &["nonesuch"], &[]),
            Err(ResolveError::NotFound { name }) if name == "nonesuch",
        ));
    }

    #[test]
    fn a_constraint_the_merged_index_cannot_meet_names_what_is_offered() {
        // The index holds one version of each name, so a constraint only an
        // older publication would satisfy is refused rather than resolved
        // downwards. The message says what the repositories do offer, since that
        // is what a caller has to act on.
        let index = merged(&[("app", "1.0-r0", "D:lib>=2.0"), ("lib", "1.0-r0", "")]);
        match resolved(&index, &["app"], &[]) {
            Err(ResolveError::Unsatisfied {
                dependency,
                required_by,
                offered,
            }) => {
                assert_eq!(dependency, "lib>=2.0");
                assert_eq!(required_by.as_deref(), Some("app"));
                assert_eq!(offered, ["lib at 1.0-r0"]);
            }
            other => panic!("expected an unsatisfied dependency, got {other:?}"),
        }
    }

    #[test]
    fn an_already_answered_name_pulls_nothing_further() {
        // Two packages needing the same virtual name select one provider, not
        // one each.
        let index = merged(&[
            ("app", "1.0-r0", "D:one two"),
            ("one", "1.0-r0", "D:virt"),
            ("two", "1.0-r0", "D:virt"),
            ("pa", "1.0-r0", "p:virt=1.0-r0"),
            ("pb", "1.0-r0", "p:virt=1.0-r0"),
        ]);
        assert_eq!(closure(&index, &["app"]), ["app", "one", "pa", "two"]);
    }

    #[test]
    fn a_closure_is_one_value_whatever_order_its_world_is_named_in() {
        // `p1` and `p2` both answer `x` at no version, which they may share,
        // and only `p2` answers `y`. Taken in the order named, `b` first had
        // `p2` answer `x` too and left `p1` out; `a` first took `p1` for `x`,
        // as its priority asks. apk installs both, whichever order it is told.
        let index = merged(&[
            ("a", "1.0-r0", "D:x"),
            ("b", "1.0-r0", "D:y"),
            ("p1", "1.0-r0", "p:x\nk:10"),
            ("p2", "1.0-r0", "p:x y=1"),
        ]);
        for world in [&["a", "b"][..], &["b", "a"], &["b", "a", "b"]] {
            assert_eq!(closure(&index, world), ["a", "b", "p1", "p2"], "{world:?}");
        }
    }

    #[test]
    fn a_closure_holds_one_package_for_a_name_offered_at_a_version() {
        // `p1` offers `x` at 2 and `p2` at 1, and only `p2` answers `y`. Taking
        // the highest offer for `x` first and `p2` for `y` after would hold two
        // packages for `x`, which apk never installs: it takes `p2` alone, and
        // so does this, whichever order the world is named in.
        let index = merged(&[
            ("a", "1.0-r0", "D:x"),
            ("b", "1.0-r0", "D:y"),
            ("p1", "1.0-r0", "p:x=2"),
            ("p2", "1.0-r0", "p:x=1 y=1"),
        ]);
        for world in [&["a", "b"][..], &["b", "a"]] {
            assert_eq!(closure(&index, world), ["a", "b", "p2"], "{world:?}");
        }

        // The package `x` and a provider of `x` contend in the same way.
        let index = merged(&[
            ("a", "1.0-r0", "D:x"),
            ("b", "1.0-r0", "D:y"),
            ("x", "2.0-r0", ""),
            ("p2", "1.0-r0", "p:x=1 y=1"),
        ]);
        for world in [&["a", "b"][..], &["b", "a"]] {
            assert_eq!(closure(&index, world), ["a", "b", "p2"], "{world:?}");
        }
        // And naming both leaves the provider, as apk does.
        assert_eq!(closure(&index, &["x", "p2"]), ["p2"]);
        assert_eq!(closure(&index, &["p2", "x"]), ["p2"]);
    }

    #[test]
    fn alpine_s_icu_data_is_answered_by_the_package_named_for_it() {
        // Alpine's own case: a KDE application needs `icu-data`, which
        // `icu-data-en` answers first by its priority, and a Qt package needs
        // `icu-data-full` by name. Both provide `icu-data=78.1-r0`; apk
        // installs `icu-data-full` alone, in either order.
        let index = merged(&[
            ("kde-app", "1.0-r0", "D:icu-data"),
            ("qt-dev", "1.0-r0", "D:icu-data-full"),
            ("icu-data-en", "78.1-r0", "k:100\np:icu-data=78.1-r0"),
            ("icu-data-full", "78.1-r0", "k:10\np:icu-data=78.1-r0"),
        ]);
        for world in [&["kde-app", "qt-dev"][..], &["qt-dev", "kde-app"]] {
            assert_eq!(
                closure(&index, world),
                ["icu-data-full", "kde-app", "qt-dev"],
                "{world:?}",
            );
        }
    }

    #[test]
    fn a_closure_no_alternative_holds_is_refused_naming_the_packages() {
        // `a` needs the offer only `p1` makes, and `b` the name only `p2`
        // answers: apk refuses the pair, and so does this.
        let index = merged(&[
            ("a", "1.0-r0", "D:x>=2"),
            ("b", "1.0-r0", "D:y"),
            ("p1", "1.0-r0", "p:x=2"),
            ("p2", "1.0-r0", "p:x=1 y=1"),
        ]);
        for world in [&["a", "b"][..], &["b", "a"]] {
            match resolved(&index, world, &[]) {
                Err(ResolveError::Contended { name, answers }) => {
                    assert_eq!(name, "x");
                    assert_eq!(answers, ["p1 at 2", "p2 at 1"], "{world:?}");
                }
                other => panic!("{world:?}: expected a contention, got {other:?}"),
            }
        }
        let err = resolved(&index, &["a", "b"], &[]).expect_err("refused");
        assert!(err.to_string().contains("name the one to install"), "{err}");

        // Two providers of one name at one version are no different.
        let index = merged(&[("p1", "1.0-r0", "p:x=1"), ("p2", "1.0-r0", "p:x=1")]);
        assert!(matches!(
            resolved(&index, &["p1", "p2"], &[]),
            Err(ResolveError::Contended { .. }),
        ));

        // The package `x` contends with a provider of `x` at no version, too,
        // and a provider that offers no version and no priority is not one apk
        // would choose for `x`, so nothing settles it.
        let index = merged(&[
            ("a", "1.0-r0", "D:x"),
            ("b", "1.0-r0", "D:y"),
            ("x", "2.0-r0", ""),
            ("p2", "1.0-r0", "p:x y=1"),
        ]);
        assert!(matches!(
            resolved(&index, &["a", "b"], &[]),
            Err(ResolveError::Contended { name, .. }) if name == "x",
        ));
    }

    #[test]
    fn a_contention_only_the_base_holds_is_the_base_s() {
        // A base that already holds two packages for one name exists; refusing
        // to layer over it would name something the increment did not do.
        let index = merged(&[("app", "1.0-r0", "")]);
        let base = carried(&[("p1", "1.0-r0", "p:x=1"), ("p2", "1.0-r0", "p:x=2")]);
        assert_eq!(
            resolved_over(&index, &["app"], &[], &base).unwrap(),
            ["app"]
        );
    }

    #[test]
    fn a_provider_needing_a_package_set_aside_is_not_taken() {
        // Alpine's nginx and openresty, reduced. `openresty-kit` offers `kit`
        // at a higher version than `kit` itself, so it ranks first, and needs
        // `openresty`, which contends with `nginx` for `cmd:nginx`. apk
        // installs `kit` and `nginx` and no openresty.
        let index = merged(&[
            ("mod", "1.30-r0", "D:nginx=1.30-r0 kit"),
            ("nginx", "1.30-r0", "p:cmd:nginx=1.30-r0"),
            ("openresty", "1.31-r0", "p:nginx cmd:nginx=1.31-r0"),
            ("kit", "1.30-r0", "D:nginx=1.30-r0"),
            (
                "openresty-kit",
                "1.31-r0",
                "D:cmd:nginx openresty\np:kit=1.31-r0",
            ),
        ]);
        assert_eq!(closure(&index, &["mod"]), ["kit", "mod", "nginx"]);
    }

    #[test]
    fn a_package_needed_by_its_own_name_may_answer_a_name_at_no_version() {
        // Alpine's opencv-dev needs `blas-dev` and `openblas-dev`, which
        // provides `blas-dev` at no version and declares no priority. apk lets
        // it answer `blas-dev`, since it is installed anyway, rather than hold
        // it beside the package `blas-dev`.
        let index = merged(&[
            ("app", "1.0-r0", "D:blas-dev openblas-dev"),
            ("blas-dev", "3.12-r0", ""),
            ("openblas-dev", "0.3-r0", "p:blas-dev"),
        ]);
        assert_eq!(closure(&index, &["app"]), ["app", "openblas-dev"]);

        // Needed by its own name, as against for another name it answers,
        // which is the case apk refuses above.
        let index = merged(&[
            ("a", "1.0-r0", "D:x"),
            ("b", "1.0-r0", "D:p2"),
            ("x", "2.0-r0", ""),
            ("p2", "1.0-r0", "p:x"),
        ]);
        assert_eq!(closure(&index, &["a", "b"]), ["a", "b", "p2"]);
    }

    #[test]
    fn a_contender_taken_first_is_preferred_to_one_set_aside() {
        // Alpine's jack and pipewire-jack, reduced. `so:libjack` ranks `jack`
        // first and `pc:jack` ranks `pipewire-jack-dev` first, which needs
        // `pipewire-jack`, and the two contend for `jack`. Taking
        // `pipewire-jack` first settles it, since it answers `so:libjack` too;
        // apk installs exactly that, rather than keeping `jack` and setting the
        // pipewire packages aside.
        let index = merged(&[
            ("app", "1.0-r0", "D:so:libjack pc:jack"),
            ("jack", "1.9-r0", "p:so:libjack=0.999"),
            ("pipewire-jack", "1.6-r0", "p:jack=1.6-r0 so:libjack=0.3"),
            ("jack-dev", "1.9-r0", "D:jack=1.9-r0\np:pc:jack=1.9"),
            (
                "pipewire-jack-dev",
                "1.6-r0",
                "D:pipewire-jack=1.6-r0\np:jack-dev=1.6-r0 pc:jack=3.1",
            ),
        ]);
        assert_eq!(
            closure(&index, &["app"]),
            ["app", "pipewire-jack", "pipewire-jack-dev"],
        );
    }

    /// An index over `records` merged under a pin holding the versions
    /// `pinned` names, each a `(name, version)` pair of one of the records.
    fn merged_under(records: &[(&str, &str, &str)], pinned: &[(&str, &str)]) -> Index {
        let text: String = records
            .iter()
            .map(|(name, version, fields)| record(name, version, fields))
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = index::parse("the index", &text, 0)
            .unwrap_or_else(|err| panic!("the index parses: {err}"));
        let held: Vec<Record> = parsed
            .iter()
            .filter(|record| pinned.contains(&(record.name.as_str(), record.version.as_str())))
            .cloned()
            .collect();
        assert_eq!(held.len(), pinned.len(), "every pinned version is offered");
        Index::merge([parsed], "x86_64", &Pins::holding(&held))
    }

    /// The closure of `world` over a base carrying `installed`, as
    /// `name=version` entries.
    fn versions(index: &Index, world: &[&str], installed: &[Record]) -> Vec<String> {
        let world: Vec<String> = world.iter().map(|name| (*name).to_string()).collect();
        resolve(index, &world, &[], installed)
            .unwrap_or_else(|err| panic!("the closure resolves: {err}"))
            .into_iter()
            .map(|record| format!("{}={}", record.name, record.version))
            .collect()
    }

    #[test]
    fn a_pinned_name_is_held_on_every_route_to_it() {
        // A dependency, a provided name, and an `i:` condition each reach a
        // package through the one record the index keeps for its name, so the
        // pin holds on all three. Unpinned, the same closures take 2.0.
        let records = [
            ("app", "1.0-r0", "D:lib"),
            ("user", "1.0-r0", "D:so:liblib.so.1"),
            ("lib", "1.0-r0", "p:so:liblib.so.1=1.0"),
            ("lib", "2.0-r0", "p:so:liblib.so.1=2.0"),
            ("lib-tools", "1.0-r0", "i:lib"),
            ("lib-tools", "2.0-r0", "i:lib"),
        ];
        let pinned = merged_under(&records, &[("lib", "1.0-r0"), ("lib-tools", "1.0-r0")]);
        let unpinned = merged_under(&records, &[]);
        for (index, version) in [(&pinned, "1.0-r0"), (&unpinned, "2.0-r0")] {
            assert_eq!(
                versions(index, &["app"], &[]),
                [
                    "app=1.0-r0".to_string(),
                    format!("lib={version}"),
                    format!("lib-tools={version}"),
                ],
            );
            assert_eq!(
                versions(index, &["user"], &[]),
                [
                    format!("lib={version}"),
                    format!("lib-tools={version}"),
                    "user=1.0-r0".to_string(),
                ],
            );
        }
    }

    #[test]
    fn a_dependency_the_pinned_version_does_not_meet_refuses_the_pin() {
        let index = merged_under(
            &[
                ("app", "1.0-r0", "D:lib>=2.0"),
                ("lib", "1.0-r0", ""),
                ("lib", "2.0-r0", ""),
            ],
            &[("lib", "1.0-r0")],
        );
        let world = ["app".to_string()];
        let err = resolve(&index, &world, &[], []).expect_err("the pin rules out lib 2.0");
        let ResolveError::Pinned { unheld } = &err else {
            panic!("expected the pin's refusal, got {err}");
        };
        assert_eq!(
            (unheld.package.as_str(), unheld.version.as_str()),
            ("lib", "1.0-r0")
        );
        assert!(
            matches!(
                &unheld.reason,
                UnheldReason::Requirement { requirement, required_by }
                    if requirement == "lib>=2.0" && required_by == "app"
            ),
            "{unheld:?}",
        );
        assert_eq!(
            err.to_string(),
            "lib is pinned to 1.0-r0 and app requires lib>=2.0"
        );
        assert!(
            matches!(AlpineError::from(err), AlpineError::Pin { unheld } if unheld.len() == 1),
            "the refusal is the pin's, as the provisioner reports it",
        );

        // Another package answering the requirement leaves nothing to refuse,
        // and an exclusion in the way is reported as the exclusion.
        let index = merged_under(
            &[
                ("app", "1.0-r0", "D:lib>=2.0"),
                ("lib", "1.0-r0", ""),
                ("lib", "2.0-r0", ""),
                ("lib-compat", "1.0-r0", "p:lib=2.0"),
            ],
            &[("lib", "1.0-r0")],
        );
        assert_eq!(closure(&index, &["app"]), ["app", "lib-compat"]);
        assert!(matches!(
            resolved(&index, &["app"], &["lib-compat"]),
            Err(ResolveError::ExcludedButRequired { .. })
        ));
    }

    #[test]
    fn a_name_the_base_carries_keeps_the_base_s_version_under_a_pin() {
        // A layered build installs over its base rather than upgrading it, so a
        // pinned name the base carries is answered by the base wherever its
        // version will do, and one it will not is the upgrade refusal it is
        // without a pin.
        let index = merged_under(
            &[
                ("app", "1.0-r0", "D:lib"),
                ("newer-app", "1.0-r0", "D:lib>=2.0"),
                ("lib", "1.0-r0", ""),
                ("lib", "2.0-r0", ""),
            ],
            &[("lib", "2.0-r0")],
        );
        let base = carried(&[("lib", "1.0-r0", "")]);
        assert_eq!(versions(&index, &["app"], &base), ["app=1.0-r0"]);
        assert!(matches!(
            resolved_over(&index, &["newer-app"], &[], &base),
            Err(ResolveError::WouldUpgrade { name, .. }) if name == "lib"
        ));
    }
}
