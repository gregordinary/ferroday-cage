//! Resolution: the packages `apk add` installs for a request, as ferrata
//! answers it, and what this layer refuses of the answer.
//!
//! ferrata ([`ferrata::resolve`]) chooses the packages apk installs for a
//! request, by apk's rules as measured, and the order apk installs them in.
//! This module states the provisioner's request and the repositories' records
//! to it, and holds its answer to what a provisioner promises:
//!
//! - **Every version offered.** Each record of every authenticated index of the
//!   root's architecture is a candidate, the indexes in the order the
//!   repositories are configured and each index's records in the order it lists
//!   them. Of two candidates apk ranks equal, the one listed first is chosen, so
//!   a repository configured first wins a tie with one configured after it.
//! - **Excludes and pins withhold records.** An excluded package's records are
//!   not offered, and a pinned name is offered at its pinned version and bytes
//!   alone ([`Pins::offers`]). Neither is a request: a dependency only an
//!   excluded package could answer is refused, and a pin does not install what
//!   it names.
//! - **A base is installed, not changed.** A layered build's base is the root
//!   resolved over: its installed records and its world. apk may answer a
//!   request over a root by upgrading, replacing or removing what it holds. An
//!   increment installs over a base it cannot change, so an answer that changes
//!   a base package is refused, naming the package and why apk would change it.
//!
//! Every release is resolved by the rules of one apk series, [`DIALECT`]'s.

use ferrata::dependency::Dependency;
use ferrata::record::Record;
use ferrata::resolve::{Change, Explanation, Refusal, Request, Resolution, Resolver};

use super::index::Index;
use super::layer::Base;
use super::pin::Pins;
use super::{AlpineError, DIALECT};

/// Resolves `world`, the names a provisioner includes, over `index`, with
/// `excludes` and `pins` withheld, over the root `base` where there is one.
///
/// Returns the packages to install, in the order apk installs them: for a whole
/// root, the resolution; over a base, the packages it adds to it. Each comes
/// with the position among `index`'s indexes of the one it is fetched from, and
/// every record returned is one of `index`'s own.
///
/// # Errors
///
/// [`AlpineError::Resolve`] for a name both included and excluded, a requested
/// name nothing offers, a request apk refuses, or one that would change a
/// package the base holds; [`AlpineError::Pin`] for a requirement the pin
/// keeps from being met; [`AlpineError::Config`] for an included name that is
/// not one a request can carry.
pub(super) fn resolve<'i>(
    index: &'i Index,
    world: &[String],
    excludes: &[String],
    pins: &Pins,
    base: Option<&'i Base>,
) -> Result<Vec<(usize, &'i Record)>, AlpineError> {
    if let Some(name) = world.iter().find(|name| excludes.contains(name)) {
        return Err(AlpineError::Resolve {
            reason: format!("{name} is both included and excluded"),
        });
    }
    let request = request_of(world.iter().map(String::as_str)).map_err(AlpineError::config)?;
    // Before resolving, so a misspelt name reads as what it is rather than as
    // a requirement nothing can answer.
    let offers = |entry: &Dependency| {
        let carried = base.into_iter().flat_map(Base::records);
        index
            .records()
            .chain(carried)
            .any(|record| record.answers(entry))
    };
    if let Some(entry) = request.entries().find(|entry| !offers(entry)) {
        return Err(AlpineError::Resolve {
            reason: format!("no repository offers {}", entry.name()),
        });
    }

    let offered = |record: &&Record| {
        !excludes.iter().any(|name| name == record.name()) && pins.offers(record)
    };
    // The root first: apk takes its names and packages before the
    // repositories', so a resolver given it after them builds again.
    let mut resolver = Resolver::new(DIALECT);
    if let Some(base) = base {
        resolver = resolver.installed(base.records(), base.entries());
    }
    // One repository to the resolver per index, an index whose every record is
    // withheld included, so the resolution's repository numbers are positions
    // among the indexes.
    for records in index.indexes() {
        resolver = resolver.repository(records.iter().filter(offered));
    }
    let resolution = resolver
        .resolve(&request)
        .map_err(|refusal| refused(&refusal, index, excludes, pins))?;

    let mut installs = Vec::new();
    let mut changed = Vec::new();
    for change in resolution.changes() {
        let (from, to, done) = match *change {
            Change::Install {
                package,
                repository,
            } => {
                installs.push((repository, package));
                continue;
            }
            Change::Upgrade { from, to, .. } => (from, Some(to), "upgrade"),
            Change::Downgrade { from, to, .. } => (from, Some(to), "downgrade"),
            Change::Replace { from, to, .. } => (from, Some(to), "replace"),
            Change::Remove(from) => (from, None, "remove"),
        };
        changed.push(change_of_base(&resolution, from, to, done));
    }
    if !changed.is_empty() {
        return Err(AlpineError::Resolve {
            reason: format!(
                "{}; an increment installs over a base rather than changing it, so rebuild the \
                 base against the repositories as they stand now",
                changed.join("; "),
            ),
        });
    }
    Ok(installs)
}

/// What apk would do to `from`, a base package, for this resolution, and why,
/// as a refusal states it: `done` to it, putting `to` in its place where it is
/// replaced rather than removed.
///
/// Only a root that holds packages already has a change other than an install,
/// and the only such root a resolution here is over is a base.
fn change_of_base(
    resolution: &Resolution<'_>,
    from: &Record,
    to: Option<&Record>,
    done: &str,
) -> String {
    let held = format!(
        "the base layer carries {} at {}",
        from.name(),
        from.version()
    );
    match to {
        Some(to) if to.version() == from.version() => format!(
            "{held}, and the resolution would {done} it with another build of that version, {}",
            because(resolution.explain(to).as_ref()),
        ),
        Some(to) => format!(
            "{held}, and the resolution would {done} it to {}, {}",
            to.version(),
            because(resolution.explain(to).as_ref()),
        ),
        None => format!(
            "{held}, and the resolution would {done} it, {}",
            because(resolution.explain(from).as_ref()),
        ),
    }
}

/// The refusal a request apk refuses is reported as.
///
/// A requirement a pinned version does not meet, where a version the pin
/// withheld would, is the pin's refusal ([`Pins::unheld`]). Otherwise apk's
/// own, with how it came about, and the excluded packages that would have
/// answered the requirement: excluding them is what may have left it unmet.
///
/// ferrata writes a refusal and each step of its explanation with every byte
/// that is not UTF-8 escaped, and a backslash, so no two names read alike;
/// each is quoted all the same, since the names in it are an index's or a
/// base's strings, held to no alphabet, and a control character among them
/// is written as it is.
fn refused(refusal: &Refusal, index: &Index, excludes: &[String], pins: &Pins) -> AlpineError {
    if let Some(unheld) = pins.unheld(refusal, index) {
        return AlpineError::Pin {
            unheld: vec![unheld],
        };
    }
    let mut reason = format!("apk refuses {:?}", refusal.to_string());
    let explanation = refusal.explanation();
    if !explanation.is_empty() {
        reason.push_str(", ");
        reason.push_str(&because(Some(explanation)));
    }
    // A `!` entry is answered by nothing, only forbids.
    let requirement = refusal.requirement();
    if !requirement.entry().is_some_and(Dependency::is_conflict) {
        // Each an index's record, whose name `unusable` admitted as text.
        let mut excluded: Vec<String> = index
            .records()
            .filter(|record| excludes.iter().any(|excluded| excluded == record.name()))
            .filter(|record| requirement.answered_by(record))
            .map(|record| record.name().to_string())
            .collect();
        excluded.sort_unstable();
        excluded.dedup();
        if !excluded.is_empty() {
            let wanted = match requirement.entry() {
                Some(entry) => entry.to_string(),
                None => requirement.name().to_string(),
            };
            reason.push_str(&format!(
                "; the excluded {} would answer {wanted:?}",
                excluded.join(", "),
            ));
        }
    }
    AlpineError::Resolve { reason }
}

/// An explanation, as the clause a refusal ends with: each of its steps,
/// quoted, since each names entries an index or a base wrote, as [`refused`]
/// quotes the refusal.
fn because(explanation: Option<&Explanation>) -> String {
    let steps: Vec<String> = explanation
        .into_iter()
        .flat_map(Explanation::steps)
        .map(|step| format!("{:?}", step.to_string()))
        .collect();
    if steps.is_empty() {
        return "for a reason apk does not state".to_string();
    }
    format!("because {}", steps.join("; "))
}

/// The request for `names`: each read as a dependency entry, as a resolution
/// asks for its included names and a plan's install order for its packages'.
///
/// # Errors
///
/// Returns the reason a name does not read as one.
pub(super) fn request_of<'n>(names: impl IntoIterator<Item = &'n str>) -> Result<Request, String> {
    names
        .into_iter()
        .map(|name| {
            DIALECT
                .dependency(name)
                .map_err(|err| format!("{name:?} is not a name a request can carry: {err}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::alpine::index::{self, fixture};
    use crate::provision::alpine::plan::Plan;
    use crate::provision::alpine::sign::identity_for_test as identity;

    /// One index of `records`, each `(name, version, identity seed, fields)`.
    fn listing(records: &[(&str, &str, &str, &str)]) -> Vec<Record> {
        let text: Vec<String> = records
            .iter()
            .map(|(name, version, seed, fields)| {
                fixture::record(name, version, "x86_64", seed, fields)
            })
            .collect();
        index::parse("the index", text.join("\n").as_bytes())
            .unwrap_or_else(|err| panic!("the index reads: {err}"))
    }

    /// `world` resolved over `indexes`, as `name version index` in install
    /// order.
    fn resolved(
        indexes: Vec<Vec<Record>>,
        world: &[&str],
        excludes: &[&str],
        pins: &Pins,
    ) -> Result<Vec<String>, AlpineError> {
        let index = Index::merge(indexes, "x86_64");
        let world: Vec<String> = world.iter().map(ToString::to_string).collect();
        let excludes: Vec<String> = excludes.iter().map(ToString::to_string).collect();
        let installs = resolve(&index, &world, &excludes, pins, None)?;
        Ok(installs
            .iter()
            .map(|(at, record)| format!("{} {} {at}", record.name(), record.version()))
            .collect())
    }

    /// The pins of a plan holding `packages`, each `(name, version, seed)`.
    fn pins(packages: &[(&str, &str, &str)]) -> Pins {
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
        let plan = Plan::parse_document(&format!(
            "Format: ferroday-cage-alpine-plan 1\nRelease: v3.23\nArchitecture: x86_64\n\n\
             Index: 0\nMirror: http://mirror.invalid\nRelease: v3.23\nSHA256: {}\n\
             Signed-By: key\n\n{text}",
            "0".repeat(64),
        ))
        .expect("the document reads");
        Pins::of(&plan).expect("the plan names each package once")
    }

    #[test]
    fn packages_come_back_in_the_order_apk_installs_them() {
        let installs = resolved(
            vec![listing(&[
                ("app", "1.0-r0", "app", "D:so:libz.so.1"),
                ("zlib", "1.3-r0", "zlib", "p:so:libz.so.1=1.3"),
            ])],
            &["app"],
            &[],
            &Pins::none(),
        )
        .expect("the request resolves");
        assert_eq!(installs, ["zlib 1.3-r0 0", "app 1.0-r0 0"]);
    }

    #[test]
    fn a_tie_goes_to_the_repository_configured_first() {
        // Two builds of one version, one from each repository: apk installs
        // the one listed first, so the first repository configured wins,
        // whichever builds the two are.
        for (first, second) in [("one", "two"), ("two", "one")] {
            let installs = resolved(
                vec![
                    listing(&[("a", "1.0-r0", first, "")]),
                    listing(&[("a", "1.0-r0", second, "")]),
                ],
                &["a"],
                &[],
                &Pins::none(),
            )
            .expect("the request resolves");
            assert_eq!(installs, ["a 1.0-r0 0"], "{first} first");
        }
        // A later version wins wherever it is offered.
        let installs = resolved(
            vec![
                listing(&[("a", "1.0-r0", "one", "")]),
                listing(&[("a", "1.0-r1", "two", "")]),
            ],
            &["a"],
            &[],
            &Pins::none(),
        )
        .expect("the request resolves");
        assert_eq!(installs, ["a 1.0-r1 1"]);
    }

    #[test]
    fn a_package_two_indexes_offer_is_fetched_from_the_first() {
        // One package, by its identity, wherever it is listed.
        let installs = resolved(
            vec![
                listing(&[("a", "1.0-r0", "one", "")]),
                listing(&[("a", "1.0-r0", "one", "")]),
            ],
            &["a"],
            &[],
            &Pins::none(),
        )
        .expect("the request resolves");
        assert_eq!(installs, ["a 1.0-r0 0"]);
    }

    #[test]
    fn an_index_whose_every_record_is_withheld_still_counts_among_the_indexes() {
        let installs = resolved(
            vec![
                listing(&[("b", "1.0-r0", "b", "")]),
                listing(&[("a", "1.0-r0", "a", "")]),
            ],
            &["a"],
            &["b"],
            &Pins::none(),
        )
        .expect("the request resolves");
        assert_eq!(installs, ["a 1.0-r0 1"]);
    }

    #[test]
    fn an_older_version_answers_a_constraint_the_latest_does_not() {
        let installs = resolved(
            vec![listing(&[
                ("app", "1.0-r0", "app", "D:lib<2"),
                ("lib", "1.5-r0", "old", ""),
                ("lib", "2.1-r0", "new", ""),
            ])],
            &["app"],
            &[],
            &Pins::none(),
        )
        .expect("the request resolves");
        assert_eq!(installs, ["lib 1.5-r0 0", "app 1.0-r0 0"]);
    }

    #[test]
    fn an_excluded_package_is_not_offered() {
        let index = || {
            vec![listing(&[
                ("app", "1.0-r0", "app", "D:cmd:awk"),
                ("gawk", "5.0-r0", "gawk", "p:cmd:awk\nk:20"),
                ("mawk", "1.3-r0", "mawk", "p:cmd:awk\nk:10"),
            ])]
        };
        let installs = resolved(index(), &["app"], &[], &Pins::none()).expect("resolves");
        assert_eq!(installs, ["gawk 5.0-r0 0", "app 1.0-r0 0"]);
        let installs = resolved(index(), &["app"], &["gawk"], &Pins::none()).expect("resolves");
        assert_eq!(installs, ["mawk 1.3-r0 0", "app 1.0-r0 0"]);

        // Where only excluded packages could answer, the refusal says so.
        let err = resolved(index(), &["app"], &["gawk", "mawk"], &Pins::none())
            .expect_err("nothing is left to answer cmd:awk");
        assert!(
            matches!(&err, AlpineError::Resolve { reason }
                if reason.contains("the excluded gawk, mawk would answer \"cmd:awk\"")),
            "{err}",
        );
    }

    #[test]
    fn a_refusal_names_only_the_excluded_packages_that_would_answer_the_requirement() {
        // mawk provides cmd:awk at no version, which an entry asking for a
        // version does not admit, and busybox is not excluded.
        let index = vec![listing(&[
            ("app", "1.0-r0", "app", "D:cmd:awk>=2"),
            ("gawk", "5.0-r0", "gawk", "p:cmd:awk=5.0"),
            ("mawk", "1.3-r0", "mawk", "p:cmd:awk\nk:10"),
            ("busybox", "1.37-r0", "busybox", "p:cmd:awk=1.37"),
        ])];
        let err = resolved(index, &["app"], &["gawk", "mawk"], &Pins::none())
            .expect_err("nothing left answers cmd:awk>=2");
        assert!(
            matches!(&err, AlpineError::Resolve { reason }
                if reason.contains("the excluded gawk would answer \"cmd:awk>=2\"")),
            "{err}",
        );
    }

    #[test]
    fn a_refusal_of_a_name_every_candidate_needs_names_the_excluded_packages_that_would_answer() {
        // Both candidates for cmd:awk need libawk, which is required with no
        // entry: apk cannot install libawk's record, and libawk-compat, which
        // would answer it at any version, is excluded.
        let index = vec![listing(&[
            ("app", "1.0-r0", "app", "D:cmd:awk"),
            ("gawk", "5.0-r0", "gawk", "p:cmd:awk\nk:20\nD:libawk"),
            ("mawk", "1.3-r0", "mawk", "p:cmd:awk\nk:10\nD:libawk"),
            ("libawk", "1.0-r0", "libawk", "X:1"),
            ("libawk-compat", "1.0-r0", "libawk-compat", "p:libawk"),
            ("other", "1.0-r0", "other", "p:libawk2"),
        ])];
        let err = resolved(index, &["app"], &["libawk-compat", "other"], &Pins::none())
            .expect_err("nothing left answers libawk");
        assert!(
            matches!(&err, AlpineError::Resolve { reason }
                if reason.contains("every candidate for cmd:awk")
                    && reason.contains("; the excluded libawk-compat would answer \"libawk\"")),
            "{err}",
        );
    }

    #[test]
    fn a_refusal_names_each_name_apart_from_every_other() {
        // Nothing provides `lib` followed by the byte 0xFF, only `lib` and
        // 0xFE, and `lib\xff` spelled out in four bytes: the refusal names the
        // first as ferrata writes it, escaped, and quotes that.
        let text = [
            &b"C:"[..],
            identity("app").as_bytes(),
            b"\nP:app\nV:1.0-r0\nA:x86_64\nD:lib\xff\n\nC:",
            identity("x").as_bytes(),
            b"\nP:x\nV:1.0-r0\nA:x86_64\np:lib\xfe\n\nC:",
            identity("y").as_bytes(),
            b"\nP:y\nV:1.0-r0\nA:x86_64\np:lib\\xff\n",
        ]
        .concat();
        let records = index::parse("the index", &text).expect("the index reads");
        let err = resolved(vec![records], &["app"], &[], &Pins::none())
            .expect_err("nothing provides the name");
        assert!(
            matches!(&err, AlpineError::Resolve { reason }
            if reason.starts_with(
                r#"apk refuses "lib\\xff, required by app-1.0-r0, which nothing can answer""#
            )),
            "{err}",
        );
    }

    #[test]
    fn a_name_both_included_and_excluded_is_refused() {
        let err = resolved(
            vec![listing(&[("a", "1.0-r0", "a", "")])],
            &["a"],
            &["a"],
            &Pins::none(),
        )
        .expect_err("a request cannot both want and refuse a package");
        assert!(
            err.to_string().contains("both included and excluded"),
            "{err}"
        );
    }

    #[test]
    fn a_requested_name_nothing_offers_is_refused_as_that() {
        let err = resolved(
            vec![listing(&[("a", "1.0-r0", "a", "p:virtual")])],
            &["nonesuch"],
            &[],
            &Pins::none(),
        )
        .expect_err("nothing offers it");
        assert!(
            err.to_string().contains("no repository offers nonesuch"),
            "{err}"
        );
        // A provided name is offered.
        resolved(
            vec![listing(&[("a", "1.0-r0", "a", "p:virtual=1")])],
            &["virtual"],
            &[],
            &Pins::none(),
        )
        .expect("a provided name is requested as any other");
    }

    #[test]
    fn a_pin_holds_what_the_resolution_selects_and_installs_nothing_itself() {
        let index = || {
            vec![listing(&[
                ("app", "1.0-r0", "app", "D:lib"),
                ("lib", "1.0-r0", "lib1", ""),
                ("lib", "2.0-r0", "lib2", ""),
                ("other", "1.0-r0", "other", ""),
            ])]
        };
        let pinned = pins(&[("lib", "1.0-r0", "lib1"), ("other", "1.0-r0", "other")]);
        let installs = resolved(index(), &["app"], &[], &pinned).expect("resolves");
        assert_eq!(installs, ["lib 1.0-r0 0", "app 1.0-r0 0"], "and no other");
    }

    #[test]
    fn a_requirement_only_a_withheld_version_meets_is_the_pin_s_refusal() {
        let index = vec![listing(&[
            ("app", "1.0-r0", "app", "D:lib>=2"),
            ("lib", "1.0-r0", "lib1", ""),
            ("lib", "2.0-r0", "lib2", ""),
        ])];
        let err = resolved(index, &["app"], &[], &pins(&[("lib", "1.0-r0", "lib1")]))
            .expect_err("the pin holds lib below what app needs");
        let AlpineError::Pin { unheld } = &err else {
            panic!("expected a pin refusal, got {err}");
        };
        assert_eq!(unheld.len(), 1);
        assert_eq!(unheld[0].package, "lib");
        assert_eq!(
            unheld[0].reason,
            crate::provision::alpine::UnheldReason::Requirement {
                requirement: "lib>=2".to_string(),
                required_by: "app-1.0-r0".to_string(),
            },
        );
    }

    #[test]
    fn a_refusal_names_what_an_index_wrote_with_its_control_characters_escaped() {
        // A dependency's name is held to no alphabet, so the name a refusal
        // quotes is the index's string, whoever signed it.
        let hostile = crate::failure::hostile::TEXT.replace(' ', "");
        let wants = format!("D:{hostile}");
        let err = resolved(
            vec![listing(&[("app", "1.0-r0", "app", &wants)])],
            &["app"],
            &[],
            &Pins::none(),
        )
        .expect_err("nothing provides the name");
        crate::failure::hostile::assert_escaped(&err.to_string());
    }
}
