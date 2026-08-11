//! Holding a resolution to the versions a plan recorded.
//!
//! A [`Plan`] handed to [`DebianBuilder::pin`](super::DebianBuilder::pin)
//! becomes a set of constraints rather than a manifest: the resolution runs as
//! it always does — every release verified, every index verified, the closure
//! computed over what the archives offer now — and each package the pin names
//! is selected at the pinned version instead of the highest. Everything the pin
//! does not name resolves normally.
//!
//! The constraint is applied where the index is built, in
//! [`Index::merge`](super::index::Index::merge), because that is the one place
//! a version is chosen. A pinned name whose version no repository offers keeps
//! the highest instead, so [`Pins::check`] can report what the archives carry
//! rather than only that something is missing; the check runs before the
//! closure is computed, so the fallback is never resolved against.

use std::collections::HashMap;
use std::fmt;

use super::DebianError;
use super::index::Index;
use super::plan::Plan;
use super::version;

/// The versions and digests a pin holds a resolution to, keyed by package name.
#[derive(Debug, Clone, Default)]
pub(crate) struct Pins {
    by_name: HashMap<String, Pinned>,
}

/// One package's pin: the version to select, and the bytes it must have.
#[derive(Debug, Clone)]
struct Pinned {
    version: String,
    sha256: String,
}

impl Pins {
    /// No pin: every name resolves to the highest version offered, as an
    /// unpinned resolution does.
    pub(crate) fn none() -> Pins {
        Pins::default()
    }

    /// Reads a plan's packages as pins.
    ///
    /// # Errors
    ///
    /// [`DebianError::Config`] when the plan names one package twice. A pin is
    /// keyed by name, since the index a resolution selects from is, so two
    /// entries for one name state two versions to hold it at and there is no
    /// answer to which governs. A plan this library resolved cannot contain
    /// one; a hand-written document can.
    pub(crate) fn of(plan: &Plan) -> Result<Pins, DebianError> {
        let mut by_name: HashMap<String, Pinned> = HashMap::with_capacity(plan.packages.len());
        for package in &plan.packages {
            let pinned = Pinned {
                version: package.version.clone(),
                sha256: package.sha256.clone(),
            };
            if let Some(first) = by_name.insert(package.name.clone(), pinned) {
                return Err(DebianError::Config {
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
    pub(crate) fn names(&self, package: &str) -> bool {
        self.by_name.contains_key(package)
    }

    /// Whether `version` is the one this pin holds `package` to.
    ///
    /// Compared as Debian versions rather than as strings, so a pin written
    /// with an explicit zero epoch matches an index that omits it, and the
    /// reverse. Answers `false` for a package the pin does not name.
    pub(crate) fn holds(&self, package: &str, version: &str) -> bool {
        self.by_name
            .get(package)
            .is_some_and(|pinned| version::compare(&pinned.version, version).is_eq())
    }

    /// Checks that the merged index can supply every pinned package at the
    /// version and with the bytes the pin records.
    ///
    /// Run before the closure is computed, so a pin the archives have moved
    /// past refuses the bootstrap rather than quietly resolving to something
    /// else.
    ///
    /// # Errors
    ///
    /// [`DebianError::Pin`] naming every package that could not be held, in
    /// name order, and for each of them what the archives offer instead.
    pub(crate) fn check(&self, index: &Index) -> Result<(), DebianError> {
        let mut unheld: Vec<UnheldPin> = Vec::new();
        for (package, pinned) in &self.by_name {
            let reason = match index.get(package) {
                None => Some(UnheldReason::Absent),
                Some(offered) if !version::compare(&pinned.version, &offered.version).is_eq() => {
                    Some(UnheldReason::Version {
                        archive: offered.version.clone(),
                    })
                }
                // Compared case-insensitively because the digest is hex: a
                // document written by hand in the case the OpenPGP tools print
                // records the same bytes as the index's lowercase.
                Some(offered) if !offered.sha256.eq_ignore_ascii_case(&pinned.sha256) => {
                    Some(UnheldReason::Digest {
                        pin: pinned.sha256.clone(),
                        archive: offered.sha256.clone(),
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
        // reproducible; a caller reading the failures of one archive publish
        // against another needs them in a stable order.
        unheld.sort_by(|a, b| a.package.cmp(&b.package));
        Err(DebianError::Pin { unheld })
    }
}

/// One package a [`pin`](super::DebianBuilder::pin) could not be held to.
///
/// Carried by [`DebianError::Pin`]. Every field describes the pin; what the
/// archives offer instead is in [`reason`](Self::reason).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnheldPin {
    /// The package the pin names.
    pub package: String,
    /// The version the pin holds it to.
    pub version: String,
    /// Why the archives could not supply it.
    pub reason: UnheldReason,
}

/// Why a pinned package could not be supplied at its pinned version.
///
/// The three are worth telling apart. A [`Version`](Self::Version) is an
/// archive that has published since the pin was taken, which a snapshot mirror
/// resolves; an [`Absent`](Self::Absent) is a package the archives no longer
/// carry at all; and a [`Digest`](Self::Digest) is one version of one package
/// with two sets of bytes, which is the event a recorded digest exists to
/// catch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnheldReason {
    /// The archives offer the package, but only at another version.
    Version {
        /// The version the archives offer.
        archive: String,
    },
    /// The archives offer no version of the package at all.
    Absent,
    /// The archives offer the pinned version, recording different bytes for it.
    Digest {
        /// The digest the pin records, lowercase hex.
        pin: String,
        /// The digest the archives record, lowercase hex.
        archive: String,
    },
}

impl fmt::Display for UnheldPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            UnheldReason::Version { archive } => write!(
                f,
                "{} is pinned to {} and the archives offer {archive}",
                self.package, self.version,
            ),
            UnheldReason::Absent => write!(
                f,
                "{} is pinned to {} and the archives offer no version of it",
                self.package, self.version,
            ),
            UnheldReason::Digest { pin, archive } => write!(
                f,
                "{} {} is pinned to the digest {pin} and the archives record {archive}",
                self.package, self.version,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::index::Package;
    use super::*;

    /// A one-package index stanza at `version` with `sha256`.
    fn stanza(name: &str, version: &str, sha256: &str) -> String {
        format!(
            "Package: {name}\nVersion: {version}\nArchitecture: amd64\n\
             Filename: pool/{name}_{version}_amd64.deb\nSHA256: {sha256}\n\n",
        )
    }

    /// A plan holding exactly the given packages, as a pin is read from.
    ///
    /// Built through the projection a resolution uses, so the pin is read from
    /// the same shape a live plan presents.
    fn plan_of(packages: &[(&str, &str, &str)]) -> Plan {
        let resolved: Vec<Package> = packages
            .iter()
            .map(|(name, version, sha256)| Package {
                name: (*name).to_string(),
                version: (*version).to_string(),
                architecture: "amd64".to_string(),
                filename: format!("pool/{name}_{version}_amd64.deb"),
                size: None,
                sha256: (*sha256).to_string(),
                depends: Vec::new(),
                pre_depends: Vec::new(),
                provides: Vec::new(),
                essential: false,
                priority: None,
                installed_size: None,
                source: None,
                origin: 0,
            })
            .collect();
        Plan::project("trixie", "amd64", &resolved, &[])
    }

    const A: &str = "aaaa000000000000000000000000000000000000000000000000000000000000";
    const B: &str = "bbbb000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn a_pin_selects_its_version_rather_than_the_highest() {
        // The whole of what a pin does to a resolution: the archive has
        // published 2.0 since the pin was taken, and the pin still resolves 1.0.
        let text = format!("{}{}", stanza("p", "1.0", A), stanza("p", "2.0", B));
        let pins = Pins::of(&plan_of(&[("p", "1.0", A)])).expect("the plan has no duplicate");
        let index = Index::merge([(0, text.as_str())], "amd64", &pins);

        assert_eq!(index.get("p").expect("p is in the index").version, "1.0");
        pins.check(&index).expect("the pinned version is offered");
    }

    #[test]
    fn an_unpinned_name_still_resolves_to_the_highest() {
        let text = format!("{}{}", stanza("p", "1.0", A), stanza("q", "2.0", B));
        let higher = stanza("q", "3.0", A);
        let pins = Pins::of(&plan_of(&[("p", "1.0", A)])).expect("the plan has no duplicate");
        let index = Index::merge([(0, text.as_str()), (1, higher.as_str())], "amd64", &pins);

        assert_eq!(index.get("p").expect("p is pinned").version, "1.0");
        assert_eq!(index.get("q").expect("q is not pinned").version, "3.0");
    }

    #[test]
    fn the_pinned_version_wins_whichever_order_the_repositories_offer_it_in() {
        // The pin selects across the merged union, so it must not depend on
        // whether the pinned version was seen before or after a higher one.
        for order in [["1.0", "2.0"], ["2.0", "1.0"]] {
            let text = format!("{}{}", stanza("p", order[0], A), stanza("p", order[1], A));
            let pins = Pins::of(&plan_of(&[("p", "1.0", A)])).expect("the plan has no duplicate");
            let index = Index::merge([(0, text.as_str())], "amd64", &pins);
            assert_eq!(
                index.get("p").expect("p is in the index").version,
                "1.0",
                "offered in the order {order:?}",
            );
        }
    }

    #[test]
    fn a_version_the_archives_have_moved_past_names_what_they_offer() {
        let text = stanza("p", "2.0", A);
        let pins = Pins::of(&plan_of(&[("p", "1.0", A)])).expect("the plan has no duplicate");
        let index = Index::merge([(0, text.as_str())], "amd64", &pins);

        // The fallback keeps the highest so the failure can say what is there,
        // and the check refuses before anything resolves against it.
        match pins.check(&index) {
            Err(DebianError::Pin { unheld }) => {
                assert_eq!(unheld.len(), 1, "{unheld:?}");
                assert_eq!(unheld[0].package, "p");
                assert_eq!(unheld[0].version, "1.0");
                assert_eq!(
                    unheld[0].reason,
                    UnheldReason::Version {
                        archive: "2.0".to_string(),
                    },
                );
            }
            other => panic!("expected a pin refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_package_the_archives_dropped_is_reported_as_absent() {
        let text = stanza("q", "1.0", A);
        let pins = Pins::of(&plan_of(&[("p", "1.0", A)])).expect("the plan has no duplicate");
        let index = Index::merge([(0, text.as_str())], "amd64", &pins);

        match pins.check(&index) {
            Err(DebianError::Pin { unheld }) => {
                assert_eq!(unheld.len(), 1, "{unheld:?}");
                assert_eq!(unheld[0].reason, UnheldReason::Absent);
            }
            other => panic!("expected a pin refusal, got {other:?}"),
        }
    }

    #[test]
    fn one_version_with_two_sets_of_bytes_is_refused() {
        // The event a recorded digest exists to catch: the archive republished
        // the same version over different bytes. The version matches, so only
        // the digest says so.
        let text = stanza("p", "1.0", B);
        let pins = Pins::of(&plan_of(&[("p", "1.0", A)])).expect("the plan has no duplicate");
        let index = Index::merge([(0, text.as_str())], "amd64", &pins);

        match pins.check(&index) {
            Err(DebianError::Pin { unheld }) => {
                assert_eq!(
                    unheld[0].reason,
                    UnheldReason::Digest {
                        pin: A.to_string(),
                        archive: B.to_string(),
                    },
                );
            }
            other => panic!("expected a pin refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_digest_recorded_in_the_other_case_is_the_same_digest() {
        let text = stanza("p", "1.0", A);
        let pins =
            Pins::of(&plan_of(&[("p", "1.0", &A.to_uppercase())])).expect("no duplicate name");
        let index = Index::merge([(0, text.as_str())], "amd64", &pins);
        pins.check(&index).expect("hex case is not a difference");
    }

    #[test]
    fn a_pin_written_with_an_explicit_zero_epoch_matches_an_index_without_one() {
        // Debian version comparison, not string comparison: `0:1.0` and `1.0`
        // are the same version, and a hand-written pin may spell either.
        let text = stanza("p", "1.0", A);
        let pins = Pins::of(&plan_of(&[("p", "0:1.0", A)])).expect("the plan has no duplicate");
        let index = Index::merge([(0, text.as_str())], "amd64", &pins);

        assert_eq!(index.get("p").expect("p is in the index").version, "1.0");
        pins.check(&index).expect("the epoch is not a difference");
    }

    #[test]
    fn every_package_that_could_not_be_held_is_reported_at_once_in_name_order() {
        // An archive publish moves many packages together, so reporting one at
        // a time would be a queue of rebuilds rather than one answer.
        let text = format!("{}{}", stanza("b", "2.0", A), stanza("c", "1.0", B));
        let pins = Pins::of(&plan_of(&[
            ("c", "1.0", A),
            ("a", "1.0", A),
            ("b", "1.0", A),
        ]))
        .expect("the plan has no duplicate");
        let index = Index::merge([(0, text.as_str())], "amd64", &pins);

        match pins.check(&index) {
            Err(DebianError::Pin { unheld }) => {
                let names: Vec<_> = unheld.iter().map(|u| u.package.as_str()).collect();
                assert_eq!(names, ["a", "b", "c"]);
                assert_eq!(unheld[0].reason, UnheldReason::Absent);
                assert_eq!(
                    unheld[1].reason,
                    UnheldReason::Version {
                        archive: "2.0".to_string(),
                    },
                );
                assert!(
                    matches!(unheld[2].reason, UnheldReason::Digest { .. }),
                    "{:?}",
                    unheld[2],
                );
            }
            other => panic!("expected a pin refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_plan_naming_one_package_twice_is_refused() {
        match Pins::of(&plan_of(&[("p", "1.0", A), ("p", "2.0", A)])) {
            Err(DebianError::Config { reason }) => {
                assert!(reason.contains("twice"), "{reason}");
                assert!(reason.contains('p'), "{reason}");
            }
            other => panic!("expected a duplicate refusal, got {other:?}"),
        }
    }

    #[test]
    fn no_pin_leaves_the_resolution_alone() {
        let text = format!("{}{}", stanza("p", "1.0", A), stanza("p", "2.0", B));
        let pins = Pins::none();
        let index = Index::merge([(0, text.as_str())], "amd64", &pins);

        assert_eq!(index.get("p").expect("p is in the index").version, "2.0");
        pins.check(&index).expect("an empty pin holds vacuously");
    }
}
