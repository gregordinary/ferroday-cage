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

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;

use super::index::{Dependency, Index, Record};
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
/// and what that requires and nothing else. The returned records are ordered by
/// name, so one resolution of one archive state is one value.
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
/// no offered version satisfies, a name whose only providers cannot be chosen
/// between, a `!` entry the closure breaks, an exclusion that leaves a
/// dependency unsatisfiable, or a dependency that needs a newer version of a
/// package the base already carries.
pub(super) fn resolve<'a>(
    index: &Index,
    world: &[String],
    excludes: &[String],
    installed: impl IntoIterator<Item = &'a Record>,
) -> Result<Vec<Record>, ResolveError> {
    let excluded: Vec<&str> = excludes.iter().map(String::as_str).collect();
    let mut selection = Selection::new();
    for record in installed {
        selection.assume(record.clone());
    }
    let mut queue: VecDeque<String> = VecDeque::new();

    for name in world {
        if excluded.contains(&name.as_str()) {
            return Err(ResolveError::ExcludedAndIncluded { name: name.clone() });
        }
        // A requested name carries no constraint, so it is a dependency that
        // accepts any version — which is what makes one path serve the seed and
        // the closure alike.
        let wanted = Dependency {
            name: name.clone(),
            constraint: None,
            conflict: false,
        };
        select(index, &wanted, None, &excluded, &mut selection, &mut queue)?;
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
                &excluded,
                &mut selection,
                &mut queue,
            )?;
        }
    }

    install_if(index, &excluded, &mut selection, &mut queue)?;
    conflicts(&selection)?;
    Ok(selection.packages.into_values().collect())
}

/// Satisfies one dependency, extending the selection where it is not already
/// satisfied.
fn select(
    index: &Index,
    dependency: &Dependency,
    required_by: Option<&str>,
    excluded: &[&str],
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
        if excluded.contains(&candidate.package.name.as_str()) {
            excluded_one = true;
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
    // the entry. Such a candidate cannot be taken, so it is dropped here rather
    // than being ranked and then refused — a *different* provider that satisfies
    // the entry without an upgrade is a resolution, and one apk's own solver
    // would find. Only when every candidate would upgrade something the base
    // carries is there nothing left to do but stop, and the refusal then names
    // the highest-ranked of them, which is the one that was asked for.
    let installable: Vec<&Candidate<'_>> = accepted
        .iter()
        .copied()
        .filter(|candidate| !selection.assumed.contains_key(&candidate.package.name))
        .collect();
    let Some(best) = best(&installable) else {
        let carried = selection
            .assumed
            .get(&highest.package.name)
            .expect("no candidate is installable, so the highest is one the base carries");
        return Err(ResolveError::WouldUpgrade {
            name: highest.package.name.clone(),
            installed: carried.version.clone(),
            offered: highest.package.version.clone(),
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
    excluded: &[&str],
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
                || excluded.contains(&record.name.as_str())
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
                select(index, dependency, Some(&name), excluded, selection, queue)?;
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
    use crate::provision::alpine::index;
    use crate::provision::alpine::pin::Pins;

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
        // The base carries `lib` too old for the constraint, and the index
        // offers both a newer `lib` and a different package providing the same
        // name at a version that already satisfies it. Refusing on the
        // highest-ranked candidate alone would refuse a resolution that exists;
        // apk's own solver finds it.
        let index = merged(&[
            ("app", "1.0-r0", "D:lib>=2.0-r0"),
            ("lib", "2.0-r0", ""),
            ("other-lib", "1.0-r0", "p:lib=3.0-r0"),
        ]);
        let base = carried(&[("lib", "1.0-r0", "")]);
        assert_eq!(
            resolved_over(&index, &["app"], &[], &base).unwrap(),
            ["app", "other-lib"],
        );

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
}
