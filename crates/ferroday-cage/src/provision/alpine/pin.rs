//! Holding a resolution to the versions a plan recorded.
//!
//! A [`Plan`] handed to [`AlpineBuilder::pin`](super::AlpineBuilder::pin)
//! becomes a set of constraints rather than a manifest: the resolution runs as
//! it always does — every index fetched and verified, the closure computed over
//! what the repositories offer now — and each package the pin names is selected
//! at the pinned version instead of the highest. Everything the pin does not
//! name resolves normally.
//!
//! The constraint is applied where the index is built, in
//! [`Index::merge`](super::index::Index::merge), because that is the one place a
//! version is chosen. A pinned name whose version no repository offers keeps the
//! highest instead, so [`Pins::check`] can report what the repositories carry
//! rather than only that something is missing; the check runs before the closure
//! is computed, so the fallback is never resolved against.

use std::collections::HashMap;
use std::fmt;

use super::AlpineError;
use super::index::Index;
use super::plan::Plan;
use super::version;

/// The versions and identities a pin holds a resolution to, keyed by package
/// name.
#[derive(Debug, Clone, Default)]
pub(super) struct Pins {
    by_name: HashMap<String, Pinned>,
}

/// One package's pin: the version to select, and the control segment it must
/// have.
#[derive(Debug, Clone)]
struct Pinned {
    version: String,
    control_identity: String,
}

impl Pins {
    /// No pin: every name resolves to the highest version offered, as an
    /// unpinned resolution does.
    pub(super) fn none() -> Pins {
        Pins::default()
    }

    /// Reads a plan's packages as pins.
    ///
    /// # Errors
    ///
    /// [`AlpineError::Config`] when the plan names one package twice. A pin is
    /// keyed by name, since the index a resolution selects from is, so two
    /// entries for one name state two versions to hold it at and there is no
    /// answer to which governs. A plan this library resolved cannot contain one;
    /// a hand-written document can.
    pub(super) fn of(plan: &Plan) -> Result<Pins, AlpineError> {
        let mut by_name: HashMap<String, Pinned> = HashMap::with_capacity(plan.packages.len());
        for package in &plan.packages {
            let pinned = Pinned {
                version: package.version.clone(),
                control_identity: package.control_identity.clone(),
            };
            if let Some(first) = by_name.insert(package.name.clone(), pinned) {
                return Err(AlpineError::Config {
                    reason: format!(
                        "the pin names the package {} twice, at {} and at {}, so there is no \
                         version to hold it at",
                        package.name, first.version, package.version,
                    ),
                });
            }
        }
        Ok(Pins { by_name })
    }

    /// Whether this pin names `package` at all.
    pub(super) fn names(&self, package: &str) -> bool {
        self.by_name.contains_key(package)
    }

    /// Whether `version` is the one this pin holds `package` to.
    ///
    /// Compared as apk versions rather than as strings, so a pin written with a
    /// leading zero on the first component matches an index without one, and the
    /// reverse. Answers `false` for a package the pin does not name.
    pub(super) fn holds(&self, package: &str, version: &str) -> bool {
        self.by_name
            .get(package)
            .and_then(|pinned| version::compare(&pinned.version, version))
            .is_some_and(|order| order.is_eq())
    }

    /// How closely a candidate for `package` meets the pin on that name.
    ///
    /// What [`Index::merge`] chooses among a pinned name's candidates by. Two
    /// repositories can offer the pinned version over different bytes, and
    /// the one recording the pinned control segment is the package the pin
    /// recorded, wherever it sits in the order. Answers [`Fit::Neither`] for a
    /// package the pin does not name.
    pub(super) fn fit(&self, package: &str, version: &str, control_identity: &str) -> Fit {
        match self.by_name.get(package) {
            Some(pinned) if self.holds(package, version) => {
                if pinned.control_identity == control_identity {
                    Fit::Exact
                } else {
                    Fit::Version
                }
            }
            _ => Fit::Neither,
        }
    }

    /// Checks that the merged index can supply every pinned package at the
    /// version and with the control segment the pin records.
    ///
    /// Run before the closure is computed, so a pin the repositories have moved
    /// past refuses the resolution rather than quietly resolving to something
    /// else.
    ///
    /// # Errors
    ///
    /// [`AlpineError::Pin`] naming every package that could not be held, in name
    /// order, and for each of them what the repositories offer instead.
    pub(super) fn check(&self, index: &Index) -> Result<(), AlpineError> {
        let mut unheld: Vec<UnheldPin> = Vec::new();
        for (package, pinned) in &self.by_name {
            let reason = match index.get(package) {
                None => Some(UnheldReason::Absent),
                Some(offered) if !self.holds(package, &offered.version) => {
                    Some(UnheldReason::Version {
                        repository: offered.version.clone(),
                    })
                }
                // Compared exactly, unlike the Debian layer's hex digest: a
                // control identity is base64, where case is part of the value.
                Some(offered) if offered.control_identity != pinned.control_identity => {
                    Some(UnheldReason::Identity {
                        pin: pinned.control_identity.clone(),
                        repository: offered.control_identity.clone(),
                    })
                }
                Some(_) => None,
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
}

/// How closely one candidate meets a pin, from least to most: the order is the
/// preference [`Index::merge`] chooses by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Fit {
    /// Another version than the pinned one.
    Neither,
    /// The pinned version, recording another control segment.
    Version,
    /// The pinned version and control segment: the package the pin recorded.
    Exact,
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
/// The three are worth telling apart. A [`Version`](Self::Version) is a
/// repository that has published since the pin was taken; an
/// [`Absent`](Self::Absent) is a package the repositories no longer carry at
/// all; and an [`Identity`](Self::Identity) is one version of one package with
/// two sets of bytes, which is the event a recorded identity exists to catch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnheldReason {
    /// The repositories offer the package, and only at another version.
    #[non_exhaustive]
    Version {
        /// The version the repositories offer.
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::alpine::index;

    /// A control identity of the shape a record carries, distinct per `seed`.
    fn identity(seed: &str) -> String {
        let mut value = String::from("Q1");
        for byte in seed.bytes().cycle().take(27) {
            value.push(char::from(b'a' + byte % 26));
        }
        value.push('=');
        value
    }

    /// A merged index over `records`, each a `(name, version, identity seed)`
    /// triple, under `pins`.
    fn merged(records: &[(&str, &str, &str)], pins: &Pins) -> Index {
        let text: String = records
            .iter()
            .map(|(name, version, seed)| {
                format!(
                    "C:{}\nP:{name}\nV:{version}\nA:x86_64\nS:1024\n",
                    identity(seed),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = index::parse("the index", &text, 0)
            .unwrap_or_else(|err| panic!("the index parses: {err}"));
        Index::merge([parsed], "x86_64", pins)
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
    fn a_pin_selects_its_version_rather_than_the_highest() {
        // The whole of what a pin does to a resolution: the repository has
        // published 2.0 since the pin was taken, and the pin still resolves 1.0.
        let pins = pins(&[("p", "1.0-r0", "p")]);
        let index = merged(&[("p", "1.0-r0", "p"), ("p", "2.0-r0", "q")], &pins);

        assert_eq!(index.get("p").expect("p is in the index").version, "1.0-r0");
        pins.check(&index).expect("the pinned version is offered");
    }

    #[test]
    fn the_pinned_version_wins_whichever_order_the_repositories_offer_it_in() {
        for order in [["1.0-r0", "2.0-r0"], ["2.0-r0", "1.0-r0"]] {
            let pins = pins(&[("p", "1.0-r0", "p")]);
            let index = merged(&[("p", order[0], "p"), ("p", order[1], "p")], &pins);
            assert_eq!(
                index.get("p").expect("p is in the index").version,
                "1.0-r0",
                "offered in the order {order:?}",
            );
        }
    }

    #[test]
    fn an_unpinned_name_still_resolves_to_the_highest() {
        let pins = pins(&[("p", "1.0-r0", "p")]);
        let index = merged(
            &[
                ("p", "1.0-r0", "p"),
                ("p", "2.0-r0", "q"),
                ("q", "1.0-r0", "q"),
                ("q", "3.0-r0", "r"),
            ],
            &pins,
        );
        assert_eq!(index.get("p").expect("p is pinned").version, "1.0-r0");
        assert_eq!(index.get("q").expect("q is not pinned").version, "3.0-r0");
    }

    #[test]
    fn a_version_the_repositories_have_moved_past_names_what_they_offer() {
        let pins = pins(&[("p", "1.0-r0", "p")]);
        let index = merged(&[("p", "2.0-r0", "p")], &pins);

        // The fallback keeps the highest so the failure can say what is there,
        // and the check refuses before anything resolves against it.
        match pins.check(&index) {
            Err(AlpineError::Pin { unheld }) => {
                assert_eq!(unheld.len(), 1, "{unheld:?}");
                assert_eq!(unheld[0].package, "p");
                assert_eq!(
                    unheld[0].reason,
                    UnheldReason::Version {
                        repository: "2.0-r0".to_string(),
                    },
                );
            }
            other => panic!("expected a pin refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_package_the_repositories_dropped_is_reported_as_absent() {
        let pins = pins(&[("p", "1.0-r0", "p")]);
        let index = merged(&[("q", "1.0-r0", "q")], &pins);
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
        let index = merged(&[("p", "1.0-r0", "other")], &pins);
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
    fn the_pinned_bytes_win_over_the_pinned_version_republished() {
        // Two repositories offer the pinned version, one over the bytes the
        // pin recorded and one over others. The pin holds whichever order they
        // are configured in, since one of them serves exactly what it names.
        for seeds in [["p", "other"], ["other", "p"]] {
            let pins = pins(&[("p", "1.0-r0", "p")]);
            let index = merged(
                &[("p", "1.0-r0", seeds[0]), ("p", "1.0-r0", seeds[1])],
                &pins,
            );
            assert_eq!(
                index.get("p").expect("p is in the index").control_identity,
                identity("p"),
                "offered in the order {seeds:?}",
            );
            pins.check(&index).expect("the pinned package is offered");
        }
        // Where neither is the recorded one, the later shadows as it always
        // does, and the refusal names what it records.
        let pins = pins(&[("p", "1.0-r0", "p")]);
        let index = merged(&[("p", "1.0-r0", "one"), ("p", "1.0-r0", "two")], &pins);
        assert_eq!(index.get("p").unwrap().control_identity, identity("two"));
    }

    #[test]
    fn a_pin_written_with_a_leading_zero_matches_an_index_without_one() {
        // apk version comparison, not string comparison: `01.0-r0` and `1.0-r0`
        // are the same version, and a hand-written pin may spell either.
        let pins = pins(&[("p", "01.0-r0", "p")]);
        let index = merged(&[("p", "1.0-r0", "p")], &pins);
        assert_eq!(index.get("p").expect("p is in the index").version, "1.0-r0");
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
        let index = merged(&[("b", "2.0-r0", "b"), ("c", "1.0-r0", "other")], &pins);
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
    fn no_pin_leaves_the_resolution_alone() {
        let pins = Pins::none();
        let index = merged(&[("p", "1.0-r0", "p"), ("p", "2.0-r0", "q")], &pins);
        assert_eq!(index.get("p").expect("p is in the index").version, "2.0-r0");
        pins.check(&index).expect("an empty pin holds vacuously");
    }
}
