//! Holding a resolution to the versions a plan recorded.
//!
//! A [`Plan`] handed to [`AlpineBuilder::pin`](super::AlpineBuilder::pin)
//! becomes a set of constraints rather than a manifest: the resolution runs as
//! it always does — every index fetched and verified, the closure computed over
//! what the repositories offer now — and each package the pin names is offered
//! at the pinned version and with the pinned bytes alone. Everything the pin
//! does not name resolves normally.
//!
//! A pin withholds records rather than stating a request. A pinned name's other
//! versions, and other builds of its pinned version, are not offered to the
//! resolution, so every route to the name — a dependency, a provided name, an
//! `install_if` condition — reaches the pinned package or nothing. A pin does not
//! install what it names: a package the resolution does not select stays out,
//! whatever the pin says of it.
//!
//! [`Pins::check`] runs over everything the repositories offer before anything
//! is withheld, so a pin the repositories have moved past is reported with what
//! they carry instead, before the resolution runs.

use std::collections::HashMap;
use std::fmt;

use ferrata::record::Record;
use ferrata::resolve::{Refusal, RefusalKind};
use ferrata::version::Version;

use super::index::{self, Index};
use super::plan::Plan;
use super::{AlpineError, DIALECT};

/// The versions and identities a pin holds a resolution to, keyed by package
/// name.
///
/// A plan names its packages in text, so a name an index or a dependency
/// states in bytes that are not UTF-8 is one no pin holds.
#[derive(Debug, Clone, Default)]
pub(super) struct Pins {
    by_name: HashMap<String, Pinned>,
}

/// One package's pin: the version to select, and the control segment it must
/// have.
#[derive(Debug, Clone)]
struct Pinned {
    /// The version as the plan states it.
    version: String,
    /// The same version read as apk reads one, or `None` for a version outside
    /// the grammar, which a pin is refused for before it is read.
    read: Option<Version>,
    control_identity: String,
}

impl Pinned {
    /// Whether `version` is the one this pin holds its package to.
    ///
    /// Compared as apk versions rather than as strings, so a pin written with a
    /// leading zero on the first component matches an index without one, and
    /// the reverse.
    fn holds(&self, version: &Version) -> bool {
        self.read.as_ref().is_some_and(|pinned| pinned == version)
    }
}

impl Pins {
    /// No pin: every record is offered, as an unpinned resolution offers them.
    pub(super) fn none() -> Pins {
        Pins::default()
    }

    /// Reads a plan's packages as pins.
    ///
    /// # Errors
    ///
    /// [`AlpineError::Config`] when the plan names one package twice. A pin is
    /// keyed by name, since a root holds one package of a name, so two entries
    /// for one name state two versions to hold it at and there is no answer to
    /// which governs. A plan this library resolved cannot contain one; a
    /// hand-written document can.
    pub(super) fn of(plan: &Plan) -> Result<Pins, AlpineError> {
        if let Some((first, again)) =
            crate::provision::settings::named_twice(&plan.packages, |package| &package.name)
        {
            return Err(AlpineError::config(format!(
                "the pin names the package {} twice, at {} and at {}, so there is no \
                     version to hold it at",
                again.name, first.version, again.version,
            )));
        }
        let by_name = plan
            .packages
            .iter()
            .map(|package| {
                let pinned = Pinned {
                    version: package.version.clone(),
                    read: DIALECT.version(&package.version).ok(),
                    control_identity: package.control_identity.clone(),
                };
                (package.name.clone(), pinned)
            })
            .collect();
        Ok(Pins { by_name })
    }

    /// The pin on `name`, if there is one.
    fn on(&self, name: &ferrata::Name) -> Option<&Pinned> {
        self.by_name.get(name.to_str()?)
    }

    /// Whether the resolution is offered `record`: it names a package the pin
    /// does not name, or it is the pinned version with the pinned control
    /// segment.
    ///
    /// Two repositories can offer the pinned version over different bytes, and
    /// the one recording the pinned control segment is the package the pin
    /// recorded, wherever it sits in the order.
    pub(super) fn offers(&self, record: &Record) -> bool {
        self.on(record.name()).is_none_or(|pinned| {
            pinned.holds(record.version())
                && index::control_identity(record) == pinned.control_identity
        })
    }

    /// Checks that the repositories offer every pinned package at the version
    /// and with the control segment the pin records.
    ///
    /// Run before the resolution, so a pin the repositories have moved past
    /// refuses it rather than quietly resolving to something else.
    ///
    /// # Errors
    ///
    /// [`AlpineError::Pin`] naming every package that could not be held, in name
    /// order, and for each of them what the repositories offer instead.
    pub(super) fn check(&self, index: &Index) -> Result<(), AlpineError> {
        let mut unheld: Vec<UnheldPin> = Vec::new();
        for (package, pinned) in &self.by_name {
            let offered: Vec<&Record> = index
                .records()
                .filter(|record| record.name() == package)
                .collect();
            let at_version: Vec<&Record> = offered
                .iter()
                .copied()
                .filter(|record| pinned.holds(record.version()))
                .collect();
            let reason = if offered.is_empty() {
                Some(UnheldReason::Absent)
            } else if at_version.is_empty() {
                // The latest, where several are offered: what a pin taken now
                // would most likely hold.
                let latest = offered
                    .iter()
                    .map(|record| record.version())
                    .max()
                    .map(Version::to_string)
                    .unwrap_or_default();
                Some(UnheldReason::Version { repository: latest })
            } else if at_version
                .iter()
                .all(|record| index::control_identity(record) != pinned.control_identity)
            {
                // Compared exactly, unlike the Debian layer's hex digest: a
                // control identity is base64, where case is part of the value.
                Some(UnheldReason::Identity {
                    pin: pinned.control_identity.clone(),
                    repository: index::control_identity(at_version[0]),
                })
            } else {
                None
            };
            if let Some(reason) = reason {
                unheld.push(UnheldPin {
                    package: package.clone(),
                    version: pinned.version.clone(),
                    reason,
                });
            }
        }
        if unheld.is_empty() {
            return Ok(());
        }
        // The pins are held in a HashMap, whose iteration order is not
        // reproducible; a caller reading the failures of one publication against
        // another needs them in a stable order.
        unheld.sort_by(|a, b| a.package.cmp(&b.package));
        Err(AlpineError::Pin { unheld })
    }

    /// The pin a refusal is about, where it is one: a requirement on a pinned
    /// package that the pinned version does not meet, and that a version the
    /// pin withheld would have.
    ///
    /// The refusal is then the pin's rather than the repositories', and it is
    /// reported as [`UnheldReason::Requirement`], naming the requirement as the
    /// requiring package declares it.
    pub(super) fn unheld(&self, refusal: &Refusal, index: &Index) -> Option<UnheldPin> {
        if refusal.kind() != RefusalKind::Unmet {
            return None;
        }
        let requirement = refusal.requirement();
        let entry = requirement.entry().filter(|entry| !entry.is_conflict())?;
        let pinned = self.on(entry.name())?;
        if pinned.read.as_ref().is_some_and(|read| entry.admits(read)) {
            return None;
        }
        let withheld = index.records().any(|record| {
            record.name() == entry.name() && !self.offers(record) && entry.admits(record.version())
        });
        // The entry's name is a pinned one, so text, and its version is in the
        // grammar: each is written as the bytes it is.
        withheld.then(|| UnheldPin {
            package: entry.name().to_string(),
            version: pinned.version.clone(),
            reason: UnheldReason::Requirement {
                requirement: entry.to_string(),
                required_by: requirement.by().to_string(),
            },
        })
    }
}

/// One package a [`pin`](super::AlpineBuilder::pin) could not be held to.
///
/// Carried by [`AlpineError::Pin`]. Every field describes the pin; what the
/// repositories offer instead is in [`reason`](Self::reason).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnheldPin {
    /// The package the pin names.
    pub package: String,
    /// The version the pin holds it to.
    pub version: String,
    /// Why the repositories could not supply it.
    pub reason: UnheldReason,
}

/// Why a pinned package could not be supplied at its pinned version.
///
/// The four are worth telling apart. A [`Version`](Self::Version) is a
/// repository that has published since the pin was taken; an
/// [`Absent`](Self::Absent) is a package the repositories no longer carry at
/// all; an [`Identity`](Self::Identity) is one version of one package with two
/// sets of bytes, which is the event a recorded identity exists to catch; and a
/// [`Requirement`](Self::Requirement) is a resolution that asks for the package
/// at a version other than the pinned one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnheldReason {
    /// The repositories offer the package, and only at other versions.
    #[non_exhaustive]
    Version {
        /// The latest version the repositories offer.
        repository: String,
    },
    /// The repositories offer no version of the package at all.
    Absent,
    /// The repositories offer the pinned version, recording a different control
    /// segment for it.
    #[non_exhaustive]
    Identity {
        /// The identity the pin records.
        pin: String,
        /// The identity the repositories record.
        repository: String,
    },
    /// The resolution requires the package at a version the pinned one does
    /// not meet, and that another version the repositories offer would.
    #[non_exhaustive]
    Requirement {
        /// The requirement as the requiring package declares it.
        requirement: String,
        /// What declares it, as the resolution names it: a package, as
        /// `name-version`, or the request.
        required_by: String,
    },
}

impl fmt::Display for UnheldPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            UnheldReason::Version { repository } => write!(
                f,
                "{} is pinned to {} and the repositories offer {repository}",
                self.package, self.version,
            ),
            UnheldReason::Absent => write!(
                f,
                "{} is pinned to {} and the repositories offer no version of it",
                self.package, self.version,
            ),
            UnheldReason::Identity { pin, repository } => write!(
                f,
                "{} {} is pinned to the control segment {pin} and the repositories record \
                 {repository}",
                self.package, self.version,
            ),
            UnheldReason::Requirement {
                requirement,
                required_by,
            } => write!(
                f,
                "{} is pinned to {} and {required_by} requires {requirement:?}",
                self.package, self.version,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::alpine::index::{self, fixture};
    use crate::provision::alpine::sign::identity_for_test as identity;

    /// An index over `records`, each a `(name, version, identity seed)` triple.
    fn merged(records: &[(&str, &str, &str)]) -> Index {
        let records: Vec<String> = records
            .iter()
            .map(|(name, version, seed)| fixture::record(name, version, "x86_64", seed, ""))
            .collect();
        fixture::merged(&records)
    }

    /// What `pins` offers of `index`, as `name version` pairs.
    fn offered(index: &Index, pins: &Pins) -> Vec<String> {
        index
            .records()
            .filter(|record| pins.offers(record))
            .map(|record| format!("{} {}", record.name(), record.version()))
            .collect()
    }

    /// A plan holding exactly the given packages, as a pin is read from.
    fn plan_of(packages: &[(&str, &str, &str)]) -> Plan {
        let text: String = packages
            .iter()
            .map(|(name, version, seed)| {
                format!(
                    "Package: {name}\nVersion: {version}\nArchitecture: x86_64\n\
                     Control-Identity: {}\nIndex: 0\n\n",
                    identity(seed),
                )
            })
            .collect();
        Plan::parse_document(&format!(
            "Format: ferroday-cage-alpine-plan 1\nRelease: v3.23\nArchitecture: x86_64\n\n\
             Index: 0\nMirror: http://mirror.invalid\nRelease: v3.23\nSHA256: {}\n\
             Signed-By: key\n\n{text}",
            "0".repeat(64),
        ))
        .expect("the document reads")
    }

    /// The pins of a plan holding `packages`.
    fn pins(packages: &[(&str, &str, &str)]) -> Pins {
        Pins::of(&plan_of(packages)).expect("the plan has no duplicate")
    }

    #[test]
    fn a_pin_offers_its_version_alone() {
        // The whole of what a pin does to a resolution: the repository has
        // published 2.0 since the pin was taken, and only 1.0 is offered.
        let pins = pins(&[("p", "1.0-r0", "p")]);
        let index = merged(&[("p", "1.0-r0", "p"), ("p", "2.0-r0", "q")]);
        assert_eq!(offered(&index, &pins), ["p 1.0-r0"]);
        pins.check(&index).expect("the pinned version is offered");
    }

    #[test]
    fn an_unpinned_name_is_offered_at_every_version() {
        let pins = pins(&[("p", "1.0-r0", "p")]);
        let index = merged(&[
            ("p", "1.0-r0", "p"),
            ("p", "2.0-r0", "q"),
            ("q", "1.0-r0", "q"),
            ("q", "3.0-r0", "r"),
        ]);
        assert_eq!(offered(&index, &pins), ["p 1.0-r0", "q 1.0-r0", "q 3.0-r0"]);
    }

    #[test]
    fn a_version_the_repositories_have_moved_past_names_what_they_offer() {
        let pins = pins(&[("p", "1.0-r0", "p")]);
        let index = merged(&[("p", "3.0-r0", "p"), ("p", "2.0-r0", "q")]);
        match pins.check(&index) {
            Err(AlpineError::Pin { unheld }) => {
                assert_eq!(unheld.len(), 1, "{unheld:?}");
                assert_eq!(unheld[0].package, "p");
                assert_eq!(
                    unheld[0].reason,
                    UnheldReason::Version {
                        repository: "3.0-r0".to_string(),
                    },
                    "the latest of what is offered",
                );
            }
            other => panic!("expected a pin refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_package_the_repositories_dropped_is_reported_as_absent() {
        let pins = pins(&[("p", "1.0-r0", "p")]);
        let index = merged(&[("q", "1.0-r0", "q")]);
        match pins.check(&index) {
            Err(AlpineError::Pin { unheld }) => {
                assert_eq!(unheld[0].reason, UnheldReason::Absent);
            }
            other => panic!("expected a pin refusal, got {other:?}"),
        }
    }

    #[test]
    fn one_version_with_two_control_segments_is_refused() {
        // The event a recorded identity exists to catch: the repository
        // republished the same version over different bytes. The version
        // matches, so only the identity says so.
        let pins = pins(&[("p", "1.0-r0", "p")]);
        let index = merged(&[("p", "1.0-r0", "other")]);
        assert!(offered(&index, &pins).is_empty());
        match pins.check(&index) {
            Err(AlpineError::Pin { unheld }) => {
                assert_eq!(
                    unheld[0].reason,
                    UnheldReason::Identity {
                        pin: identity("p"),
                        repository: identity("other"),
                    },
                );
            }
            other => panic!("expected a pin refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_pinned_bytes_are_offered_whichever_order_they_come_in() {
        // Two repositories offer the pinned version, one over the bytes the
        // pin recorded and one over others. The pin holds whichever order they
        // are configured in, since one of them serves exactly what it names.
        for seeds in [["p", "other"], ["other", "p"]] {
            let pins = pins(&[("p", "1.0-r0", "p")]);
            let index = merged(&[("p", "1.0-r0", seeds[0]), ("p", "1.0-r0", seeds[1])]);
            let held: Vec<String> = index
                .records()
                .filter(|record| pins.offers(record))
                .map(index::control_identity)
                .collect();
            assert_eq!(held, [identity("p")], "offered in the order {seeds:?}");
            pins.check(&index).expect("the pinned package is offered");
        }
    }

    #[test]
    fn a_pin_written_with_a_leading_zero_matches_an_index_without_one() {
        // apk version comparison, not string comparison: `01.0-r0` and `1.0-r0`
        // are the same version, and a hand-written pin may spell either.
        let pins = pins(&[("p", "01.0-r0", "p")]);
        let index = merged(&[("p", "1.0-r0", "p")]);
        assert_eq!(offered(&index, &pins), ["p 1.0-r0"]);
        pins.check(&index)
            .expect("the leading zero is not a difference");
    }

    #[test]
    fn every_package_that_could_not_be_held_is_reported_at_once_in_name_order() {
        // A repository publish moves many packages together, so reporting one at
        // a time would be a queue of rebuilds rather than one answer.
        let pins = pins(&[
            ("c", "1.0-r0", "c"),
            ("a", "1.0-r0", "a"),
            ("b", "1.0-r0", "b"),
        ]);
        let index = merged(&[("b", "2.0-r0", "b"), ("c", "1.0-r0", "other")]);
        match pins.check(&index) {
            Err(AlpineError::Pin { unheld }) => {
                let names: Vec<&str> = unheld.iter().map(|one| one.package.as_str()).collect();
                assert_eq!(names, ["a", "b", "c"]);
                assert_eq!(unheld[0].reason, UnheldReason::Absent);
                assert!(matches!(unheld[1].reason, UnheldReason::Version { .. }));
                assert!(matches!(unheld[2].reason, UnheldReason::Identity { .. }));
            }
            other => panic!("expected a pin refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_plan_naming_one_package_twice_is_refused() {
        match Pins::of(&plan_of(&[("p", "1.0-r0", "p"), ("p", "2.0-r0", "q")])) {
            Err(AlpineError::Config { reason }) => {
                assert!(reason.contains("twice"), "{reason}");
                assert!(reason.contains('p'), "{reason}");
            }
            other => panic!("expected a duplicate refusal, got {other:?}"),
        }
    }

    #[test]
    fn no_pin_offers_everything() {
        let pins = Pins::none();
        let index = merged(&[("p", "1.0-r0", "p"), ("p", "2.0-r0", "q")]);
        assert_eq!(offered(&index, &pins), ["p 1.0-r0", "p 2.0-r0"]);
        pins.check(&index).expect("an empty pin holds vacuously");
    }
}
