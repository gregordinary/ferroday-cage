//! The version algebra the Package Manager Specification defines, and the
//! `category/name-version` split it implies.
//!
//! A Gentoo version is a dotted numeric run, an optional single letter, any
//! number of named suffixes, and an optional revision:
//!
//! ```text
//! 1.2.3b_rc2_p1-r4
//! ^^^^^ ^ ^^^^^^^^ ^^
//! |     | |        the revision, `-r` and digits; absent is `-r0`
//! |     | zero or more `_name` suffixes, each with an optional number
//! |     a single lowercase letter
//! the dotted numeric components, at least one
//! ```
//!
//! # The suffix ladder puts the unsuffixed version in the middle
//!
//! ```text
//! _alpha < _beta < _pre < _rc < (no suffix) < _p
//! ```
//!
//! So `1.0_rc1` precedes `1.0`, and `1.0_p1` follows it. A version that runs
//! out of suffixes before the other is compared as though its next suffix were
//! `_p` with a number below every real one, which is what places an unsuffixed
//! version above `_rc` and below `_p` in one rule rather than two, and what
//! makes `1.0_p` sit above `1.0_p_alpha` and below `1.0_p_p`.
//!
//! # Numbers are compared as written
//!
//! The first component is compared numerically, so `01.0` and `1.0` are one
//! version. Every later one is compared numerically *unless* either side
//! carries a leading zero, in which case both have their trailing zeros removed
//! and are compared as text: `1.01` is below `1.1`, a leading zero reading as a
//! decimal fraction rather than as padding. Nothing is parsed into an integer,
//! so a version with a forty-digit component orders rather than overflowing.
//!
//! A version with more components than another, the shared ones being equal, is
//! the greater: `1.0.0` is above `1.0`.
//!
//! # Why this is a third comparator
//!
//! The crate already has [`debian::version`](super::super::debian::version) and
//! [`alpine::version`](super::super::alpine::version), and this is a third
//! answer to "how do two versions compare" rather than a reuse of either. The
//! three archives genuinely disagree, and not at the edges: Debian's epoch has
//! no counterpart here, apk's `~commit` token and its `cvs`/`svn`/`git`/`hg`
//! suffixes are not part of this grammar, and this format's letter component is
//! in neither of the others. A comparator that tried to serve all three would
//! order versions no archive publishes and would have to choose, silently,
//! whose rule applies to a string both formats accept. Each archive's ordering
//! is defined by that archive, so each gets the comparator its own
//! specification describes.

use std::cmp::Ordering;

/// The suffixes the format defines, in ascending order.
///
/// The table is the whole of what makes a version pre- or post-release. A name
/// outside it is not a suffix, and a version carrying one is refused rather
/// than ordered by a rule the format does not state.
const SUFFIXES: [&str; 5] = ["alpha", "beta", "pre", "rc", "p"];

/// The rank of `_p`, which is the highest suffix and the one a version that has
/// run out of suffixes is compared as carrying.
const RANK_P: usize = SUFFIXES.len() - 1;

/// A parsed version, borrowing the text it was parsed from.
///
/// The fields are in comparison order and [`Ord`] compares them in that order:
/// the numeric components, then the letter, then the suffixes, then the
/// revision. That order is the format's rather than a choice.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Version<'a> {
    /// The dotted components, as written, at least one.
    numbers: Vec<&'a str>,
    /// The single trailing lowercase letter, where there is one.
    letter: Option<u8>,
    /// The `_name123` suffixes, in the order written.
    suffixes: Vec<Suffix<'a>>,
    /// The `-r` revision's digits, as written; absent reads as zero.
    revision: Option<&'a str>,
}

/// One `_name123` suffix: where it ranks, and the number it carries.
#[derive(Debug, PartialEq, Eq)]
struct Suffix<'a> {
    /// The index of the suffix name in [`SUFFIXES`].
    rank: usize,
    /// The digits as written, empty where the suffix carried none. An absent
    /// number is zero, so `1.0_alpha` and `1.0_alpha0` are one version.
    number: &'a str,
}

impl Ord for Version<'_> {
    fn cmp(&self, other: &Version<'_>) -> Ordering {
        compare_numbers(&self.numbers, &other.numbers)
            .then_with(|| self.letter.cmp(&other.letter))
            .then_with(|| compare_suffixes(&self.suffixes, &other.suffixes))
            .then_with(|| {
                compare_numeric(self.revision.unwrap_or("0"), other.revision.unwrap_or("0"))
            })
    }
}

impl PartialOrd for Version<'_> {
    fn partial_cmp(&self, other: &Version<'_>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Version<'a> {
    /// The version with its revision removed, which is what `~` matches over.
    ///
    /// A borrow rather than a clone of the whole: the operator asks whether two
    /// versions are equal but for their revisions, and dropping the revision
    /// from both sides is the whole of that question.
    fn without_revision(&self) -> Version<'_> {
        Version {
            numbers: self.numbers.clone(),
            letter: self.letter,
            suffixes: self
                .suffixes
                .iter()
                .map(|suffix| Suffix {
                    rank: suffix.rank,
                    number: suffix.number,
                })
                .collect(),
            revision: None,
        }
    }

    /// The components before the letter, for the caller that renders a version
    /// back. Unused outside this module's own tests today.
    #[cfg(test)]
    fn numbers(&self) -> &[&'a str] {
        &self.numbers
    }
}

/// Compares two dotted numeric runs.
///
/// The first components are compared numerically whatever their leading zeros;
/// every later pair is compared numerically unless either carries a leading
/// zero, in which case both are stripped of trailing zeros and compared as
/// text. A run that continues past the other is the greater, the shared
/// components being equal.
fn compare_numbers(a: &[&str], b: &[&str]) -> Ordering {
    // Both runs are non-empty: the grammar requires at least one component.
    let first = compare_numeric(a[0], b[0]);
    if first != Ordering::Equal {
        return first;
    }
    for at in 1..a.len().min(b.len()) {
        let (left, right) = (a[at], b[at]);
        let order = if left.starts_with('0') || right.starts_with('0') {
            // A leading zero reads as a decimal fraction, so the pair is
            // compared as text with trailing zeros removed: `1.01` and `1.010`
            // are one version, and both sit below `1.1`.
            left.trim_end_matches('0').cmp(right.trim_end_matches('0'))
        } else {
            compare_numeric(left, right)
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    a.len().cmp(&b.len())
}

/// Compares two runs of decimal digits by value, without parsing either.
///
/// Leading zeros are insignificant, so they are dropped and the longer run
/// wins; equal lengths compare lexically, which for digits is the same as
/// numerically. A component of any length orders, where an integer parse would
/// overflow.
fn compare_numeric(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Compares two suffix runs.
///
/// A run that has ended is compared as though its next suffix were `_p`
/// carrying a number below every real one. That single rule places an
/// unsuffixed version above `_rc` and below `_p1`, and orders two versions that
/// share a prefix of suffixes.
fn compare_suffixes(a: &[Suffix<'_>], b: &[Suffix<'_>]) -> Ordering {
    for at in 0..a.len().max(b.len()) {
        let left = a.get(at);
        let right = b.get(at);
        let order = left
            .map_or(RANK_P, |suffix| suffix.rank)
            .cmp(&right.map_or(RANK_P, |suffix| suffix.rank))
            .then_with(|| match (left, right) {
                // Both present: an absent number is zero.
                (Some(left), Some(right)) => compare_numeric(
                    if left.number.is_empty() {
                        "0"
                    } else {
                        left.number
                    },
                    if right.number.is_empty() {
                        "0"
                    } else {
                        right.number
                    },
                ),
                // One run has ended. Its stand-in `_p` carries a number below
                // every real one, so the run that continues wins whatever
                // number its `_p` states -- including none, which is zero.
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            });
        if order != Ordering::Equal {
            return order;
        }
    }
    Ordering::Equal
}

/// Parses `text` as a version, or `None` where it is not one.
///
/// The grammar is exact: a version with a component that is not digits, a
/// second letter, a suffix the format does not define, or anything after the
/// revision is refused rather than coerced into something orderable. A version
/// that cannot be ordered cannot be resolved against safely, and an unsigned
/// index is what publishes it.
pub(super) fn parse(text: &str) -> Option<Version<'_>> {
    // The revision comes off first: `-r` is the only hyphen a version carries,
    // so finding it before anything else keeps the rest of the parse free of
    // the separator.
    let (rest, revision) = match text.rsplit_once("-r") {
        Some((rest, digits)) if is_digits(digits) => (rest, Some(digits)),
        _ => (text, None),
    };

    // Then the suffixes, from the right, so the numeric run and its letter are
    // what remains.
    let mut suffixes = Vec::new();
    let mut head = rest;
    while let Some((before, suffix)) = head.rsplit_once('_') {
        let (name, number) = suffix.split_at(
            suffix
                .find(|character: char| character.is_ascii_digit())
                .unwrap_or(suffix.len()),
        );
        let rank = SUFFIXES.iter().position(|known| *known == name)?;
        if !number.is_empty() && !is_digits(number) {
            return None;
        }
        suffixes.push(Suffix { rank, number });
        head = before;
    }
    suffixes.reverse();

    // The letter, which is a single lowercase one and only ever the last
    // character of the numeric run.
    let (head, letter) = match head.as_bytes().last() {
        Some(last) if last.is_ascii_lowercase() => (&head[..head.len() - 1], Some(*last)),
        _ => (head, None),
    };

    // `split` always yields at least one part, so an empty head arrives here as
    // a single empty component and is refused by the digit check rather than by
    // a length test of its own.
    let numbers: Vec<&str> = head.split('.').collect();
    if !numbers.iter().all(|component| is_digits(component)) {
        return None;
    }
    Some(Version {
        numbers,
        letter,
        suffixes,
        revision,
    })
}

/// Whether `text` is a non-empty run of ASCII digits.
fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Orders two versions, or `None` where either is not one this format defines.
pub(super) fn compare(a: &str, b: &str) -> Option<Ordering> {
    Some(parse(a)?.cmp(&parse(b)?))
}

/// Whether `candidate` is `wanted` but for its revision, which is what the `~`
/// operator asks.
///
/// Both are parsed rather than compared as text: `1.0-r0`, `1.0` and `1.0.0`
/// are two versions and three spellings, and the operator is about the first
/// distinction rather than the second.
pub(super) fn same_but_revision(candidate: &str, wanted: &str) -> bool {
    match (parse(candidate), parse(wanted)) {
        (Some(candidate), Some(wanted)) => {
            candidate.without_revision() == wanted.without_revision()
        }
        _ => false,
    }
}

/// Splits `cpv` into its category, package name and version.
///
/// A `CPV` is `category/name-version`, and the separator between the name and
/// the version is a hyphen the name may also contain. The split is nonetheless
/// unambiguous, because the format forbids a package name that ends in a hyphen
/// followed by something that parses as a version: the first hyphen whose
/// remainder is a whole version is therefore the one, and this scans from the
/// left for it.
///
/// Returns `None` for a value that is not one — no category separator, an empty
/// part, or no hyphen with a version after it.
pub(super) fn split_cpv(cpv: &str) -> Option<(&str, &str, &str)> {
    let (category, rest) = cpv.split_once('/')?;
    if category.is_empty() || rest.is_empty() || category.contains('/') {
        return None;
    }
    let mut at = 0;
    while let Some(offset) = rest[at..].find('-') {
        let hyphen = at + offset;
        let (name, version) = (&rest[..hyphen], &rest[hyphen + 1..]);
        if !name.is_empty() && parse(version).is_some() {
            return Some((category, name, version));
        }
        at = hyphen + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asserts that `a` compares to `b` as `expected`, and that the reverse
    /// holds too — an ordering that is not antisymmetric would sort
    /// nondeterministically.
    #[track_caller]
    fn ordered(a: &str, expected: Ordering, b: &str) {
        let order = compare(a, b).unwrap_or_else(|| panic!("{a:?} and {b:?} are versions"));
        assert_eq!(order, expected, "{a:?} cmp {b:?}");
        assert_eq!(
            compare(b, a).expect("both parse"),
            expected.reverse(),
            "{b:?} cmp {a:?}",
        );
    }

    #[test]
    fn the_suffix_ladder_puts_an_unsuffixed_version_in_the_middle() {
        // The single rule the module rests on: `_p` is above the bare version
        // and everything else is below it.
        let ladder = ["1.0_alpha", "1.0_beta", "1.0_pre", "1.0_rc", "1.0", "1.0_p"];
        for (at, lower) in ladder.iter().enumerate() {
            for higher in &ladder[at + 1..] {
                ordered(lower, Ordering::Less, higher);
            }
        }
    }

    #[test]
    fn a_suffix_number_orders_within_its_rank_and_an_absent_one_is_zero() {
        ordered("1.0_alpha1", Ordering::Less, "1.0_alpha2");
        ordered("1.0_alpha", Ordering::Equal, "1.0_alpha0");
        ordered("1.0_p1", Ordering::Less, "1.0_p2");
        // A run that ends is compared as `_p` below every real number, so the
        // run that continues wins whatever it carries.
        ordered("1.0_p", Ordering::Greater, "1.0_p_alpha");
        ordered("1.0_p", Ordering::Less, "1.0_p_p");
        ordered("1.0_p", Ordering::Less, "1.0_p_p0");
    }

    #[test]
    fn numeric_components_compare_by_value_except_where_a_zero_leads() {
        // The first component is numeric whatever leads it.
        ordered("01.0", Ordering::Equal, "1.0");
        ordered("2.0", Ordering::Less, "10.0");
        // A later component with a leading zero reads as a fraction.
        ordered("1.01", Ordering::Less, "1.1");
        ordered("1.01", Ordering::Equal, "1.010");
        ordered("1.001", Ordering::Less, "1.01");
        // Without one, later components are numeric, so a trailing zero is a
        // digit rather than padding to discard.
        ordered("1.2", Ordering::Less, "1.10");
        ordered("1.1", Ordering::Less, "1.10");
        // A longer run wins where the shared components agree.
        ordered("1.0", Ordering::Less, "1.0.0");
        ordered("1.0.1", Ordering::Greater, "1.0");
        // Nothing is parsed into an integer, so a component wider than any
        // integer type still orders.
        let wide = format!("1.{}", "9".repeat(40));
        let wider = format!("1.{}", "9".repeat(41));
        ordered(&wide, Ordering::Less, &wider);
    }

    #[test]
    fn the_letter_sits_above_the_numbers_and_below_the_suffixes() {
        ordered("1.0", Ordering::Less, "1.0a");
        ordered("1.0a", Ordering::Less, "1.0b");
        // The letter is compared before the suffixes, so a lettered
        // pre-release outranks an unlettered final version.
        ordered("1.0", Ordering::Less, "1.0a_alpha");
    }

    #[test]
    fn a_revision_is_the_last_thing_compared_and_an_absent_one_is_zero() {
        ordered("1.0", Ordering::Equal, "1.0-r0");
        ordered("1.0-r1", Ordering::Greater, "1.0");
        ordered("1.0-r2", Ordering::Greater, "1.0-r1");
        // Below every earlier field, so a revision cannot lift a version past
        // the next one.
        ordered("1.0-r99", Ordering::Less, "1.1");
        ordered("1.0_alpha-r99", Ordering::Less, "1.0");
    }

    #[test]
    fn the_tilde_operator_asks_about_the_revision_and_nothing_else() {
        assert!(same_but_revision("1.0-r3", "1.0"));
        assert!(same_but_revision("1.0", "1.0-r3"));
        assert!(same_but_revision("1.0-r0", "1.0"));
        assert!(!same_but_revision("1.0.0", "1.0"));
        assert!(!same_but_revision("1.1", "1.0"));
        assert!(!same_but_revision("1.0_p1", "1.0"));
    }

    #[test]
    fn a_shape_the_format_does_not_define_is_refused_rather_than_ordered() {
        for text in [
            "",
            "1.0.",
            ".1.0",
            "1.0-r",
            "1.0-rx",
            "1.0_gamma",
            "1.0_alphax",
            "1.0ab",
            "1.0A",
            "1..0",
            "v1.0",
            "1.0+2",
        ] {
            assert!(parse(text).is_none(), "{text:?} was accepted");
        }
    }

    #[test]
    fn an_ordinary_version_parses_into_its_parts() {
        let version = parse("1.2.3b_rc2_p1-r4").expect("a version");
        assert_eq!(version.numbers(), ["1", "2", "3"]);
        assert_eq!(version.letter, Some(b'b'));
        assert_eq!(version.suffixes.len(), 2);
        assert_eq!(version.revision, Some("4"));
    }

    /// One real version per shape the live index publishes, taken from a
    /// census over all 15,773 of its records.
    ///
    /// The census reduced 4,377 distinct versions to the 52 structural shapes
    /// below — the number of dotted components, whether a letter is present,
    /// which suffixes appear and whether each carries a number, whether a
    /// suffix number leads with a zero, and whether a revision is present. A
    /// shape absent here is one the archive did not publish.
    const PUBLISHED: [&str; 52] = [
        "0",
        "0-r1",
        "0_p20260213",
        "2023_p59159-r4",
        "0_pre20220804",
        "0_pre20130223-r3",
        "0_pre063_p1",
        "59c",
        "9100h-r3",
        "11b_p20160615-r2",
        "6.8",
        "60.0-r1",
        "3.02_alpha09-r5",
        "0.3_beta15-r29",
        "7.1_beta-r1",
        "2.0_p20230622",
        "2.5_p20181227-r3",
        "5.1_pre20240617",
        "1.10_pre20250206-r1",
        "4.2_rc1",
        "1.4_rc5-r11",
        "0.09_rc9_p20191120",
        "5.21q",
        "1.4a-r5",
        "1.3e_p20220623",
        "0.32h_pre20181117064816",
        "3.48.0",
        "1.2.2-r3",
        "2.0.0_alpha2",
        "0.9.99_alpha-r8",
        "3.3.13_beta-r1",
        "1.9.17_p2",
        "2.0.4_p20200224-r2",
        "2.7.0_p17_p3",
        "1.7.0_p5_p4-r3",
        "1.99.96_pre20180209",
        "1.4.1_pre20130107-r7",
        "2.4.1_pre0910052249-r2",
        "3.0.0_rc3",
        "3.20.10_rc",
        "0.0.12_rc5-r1",
        "0.460.0_rc-r2",
        "6.0.0_rc1_p20230723-r1",
        "0.3.1a",
        "0.1.7e-r1",
        "2.4.3.7",
        "4.4.0.1-r1",
        "2020.2.8.1_alpha6",
        "5.202.504.134_rc",
        "2.7.7.3.23",
        "1.8.0.0.498-r1",
        "1.4.0.2025.12.10-r1",
    ];

    #[test]
    fn every_version_shape_the_archive_publishes_parses_and_orders() {
        for text in PUBLISHED {
            assert!(parse(text).is_some(), "the archive publishes {text:?}");
        }
        // The ordering is total over them, which is what a resolver needs of a
        // comparator before it can take "the highest version satisfying an
        // atom" to mean anything.
        for (at, a) in PUBLISHED.iter().enumerate() {
            for b in &PUBLISHED[at..] {
                let forward = compare(a, b).expect("both parse");
                assert_eq!(
                    compare(b, a).expect("both parse"),
                    forward.reverse(),
                    "{a:?} and {b:?} do not order antisymmetrically",
                );
            }
        }
    }

    #[test]
    fn a_cpv_splits_at_the_first_hyphen_a_whole_version_follows() {
        assert_eq!(
            split_cpv("dev-vcs/git-2.54.0"),
            Some(("dev-vcs", "git", "2.54.0")),
        );
        // A name that carries hyphens and digits: the split is the first
        // hyphen the *whole* remainder parses as a version after.
        assert_eq!(
            split_cpv("sys-apps/util-linux-2.41.2-r1"),
            Some(("sys-apps", "util-linux", "2.41.2-r1")),
        );
        assert_eq!(
            split_cpv("acct-group/_cron-failure-0-r1"),
            Some(("acct-group", "_cron-failure", "0-r1")),
        );
        // A name whose own hyphen is followed by digits that are not a whole
        // version: `3-r1` would parse, so the scan must reach the later
        // hyphen only when the earlier remainder does not parse whole.
        assert_eq!(
            split_cpv("dev-libs/libressl-3.9.2"),
            Some(("dev-libs", "libressl", "3.9.2")),
        );
        for text in ["git-2.54.0", "dev-vcs/git", "dev-vcs/", "/git-1.0", ""] {
            assert!(split_cpv(text).is_none(), "{text:?} was accepted");
        }
    }
}
