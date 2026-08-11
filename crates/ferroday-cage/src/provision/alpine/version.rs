//! apk version ordering.
//!
//! An apk version is a token sequence rather than a string with separators, and
//! the tokens must appear in one order:
//!
//! ```text
//! 1.2.3a_rc2~0ff1ce-r4
//! ^^^^^ ^^^^ ^^^^^^ ^^
//! |     |    |      the package revision, `-r` and digits
//! |     |    the upstream commit the build came from, `~` and lowercase hex
//! |     zero or more suffixes, `_` and a name from the table below
//! |     (and a letter, here `a`, before them)
//! the dotted numeric components
//! ```
//!
//! A version whose tokens appear out of that order is invalid rather than merely
//! unusual — `1.0-r1_p1` and `1.0a1` are both refused — and this module refuses
//! it rather than coercing it into something orderable. An unorderable version
//! cannot be merged against another safely, and a mirror is the one publishing
//! it.
//!
//! # The suffix table is what makes a version pre- or post-release
//!
//! ```text
//! alpha < beta < pre < rc < (no suffix) < cvs < svn < git < hg < p
//! ```
//!
//! So `1.0_rc1` precedes `1.0`, and `1.0_p1` follows it: the absence of a suffix
//! sits in the middle of the table rather than at either end, which is why
//! [`NO_SUFFIX`] occupies a rank of its own and the table has a gap where it
//! sits. Suffixes repeat, and a shorter run is compared against that rank —
//! `1.0_p` is above `1.0_p_alpha` and below `1.0_p_p`.
//!
//! # Numbers are compared as written
//!
//! The first component is compared numerically, so `01.0` and `1.0` are the same
//! version. Every later one is compared numerically *unless* either side carries
//! a leading zero, in which case both are compared as text: `1.01` is below
//! `1.1`, since a leading zero reads as a decimal fraction rather than as a
//! padded integer. No component is parsed into an integer, so a version with a
//! forty-digit component orders rather than overflowing.
//!
//! # A constraint is a set of orderings
//!
//! [`Constraint`] is the other half of the module: what a dependency states
//! about the version it will accept. The operator is not one of a fixed list of
//! spellings but a *set*, built one character at a time — `<` admits a lesser
//! version, `>` a greater, `=` an equal, and `~` an equal one over a prefix
//! comparison. So the characters may appear in any order and any combination,
//! `<=` and `=<` are one operator, and `<>=` is the one that admits everything.

use std::cmp::Ordering;
use std::fmt;

/// The characters an operator is spelled from.
const OPERATOR_CHARACTERS: [char; 4] = ['<', '>', '=', '~'];

/// The operator bit admitting a candidate below the constraint's version.
const ACCEPT_LESS: u8 = 1;
/// The operator bit admitting a candidate equal to the constraint's version.
const ACCEPT_EQUAL: u8 = 2;
/// The operator bit admitting a candidate above the constraint's version.
const ACCEPT_GREATER: u8 = 4;

/// The rank of a version carrying no suffix at a given position.
///
/// The pre-release suffixes rank below it and the post-release ones above, which
/// is the whole of what makes `1.0_rc1 < 1.0 < 1.0_p1`.
const NO_SUFFIX: u8 = 4;

/// The rank of the suffix `name`, or `None` for a name the format does not
/// define.
///
/// The ranks skip [`NO_SUFFIX`], which is the rank of an absent suffix rather
/// than of a spelled one.
fn suffix_rank(name: &str) -> Option<u8> {
    Some(match name {
        "alpha" => 0,
        "beta" => 1,
        "pre" => 2,
        "rc" => 3,
        "cvs" => 5,
        "svn" => 6,
        "git" => 7,
        "hg" => 8,
        "p" => 9,
        _ => return None,
    })
}

/// One `_name123` suffix: where it ranks, and the number it carries.
#[derive(Debug, PartialEq, Eq)]
struct Suffix<'a> {
    rank: u8,
    /// The digits as written, empty where the suffix carried none. An absent
    /// number is zero, so `1.0_alpha` and `1.0_alpha0` are the same version.
    number: &'a str,
}

/// A parsed apk version, borrowing the text it was parsed from.
///
/// The fields are in comparison order, and [`Ord`] compares them in that order:
/// the numeric components, then the letter, then the suffixes, then the commit,
/// then the revision. That order is the format's, not a choice — it is what puts
/// `1.0a` above `1.0_p1` and `1.0~ff` above `1.0-r1`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Version<'a> {
    /// The dotted components, as written, at least one.
    numbers: Vec<&'a str>,
    /// The single trailing lowercase letter, when there is one.
    letter: Option<u8>,
    /// The `_name123` suffixes, in the order written.
    suffixes: Vec<Suffix<'a>>,
    /// The `~` commit hash, lowercase hex.
    commit: Option<&'a str>,
    /// The `-r` revision's digits, as written.
    revision: Option<&'a str>,
}

impl Ord for Version<'_> {
    fn cmp(&self, other: &Version<'_>) -> Ordering {
        compare_numbers(&self.numbers, &other.numbers)
            .then_with(|| self.letter.cmp(&other.letter))
            .then_with(|| compare_suffixes(&self.suffixes, &other.suffixes))
            .then_with(|| self.commit.cmp(&other.commit))
            .then_with(|| compare_optional_numbers(self.revision, other.revision))
    }
}

impl PartialOrd for Version<'_> {
    fn partial_cmp(&self, other: &Version<'_>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One token of a version, in the order the grammar emits them.
///
/// This view exists for one job: the prefix comparison a `~` constraint is.
/// Ordinary comparison needs no token stream, so [`Ord`] above remains the sole
/// definition of how two versions order, and this is never consulted for it.
#[derive(Debug)]
enum Token<'a> {
    /// One dotted component. `dotted` is false for the first, the only one a
    /// leading zero does not make textual.
    Number { text: &'a str, dotted: bool },
    /// The single trailing lowercase letter.
    Letter(u8),
    /// A suffix's rank, without its digits.
    Suffix(u8),
    /// A suffix's digits, emitted only where the suffix carried some.
    ///
    /// The split is what makes `1.0_p` a prefix of `1.0_p1`: one token against
    /// two, rather than one token whose value differs.
    SuffixNumber(&'a str),
    /// The `~` commit hash.
    Commit(&'a str),
    /// The `-r` revision's digits.
    Revision(&'a str),
}

impl PartialEq for Token<'_> {
    /// Whether two tokens are the same token: the same kind, equal by the rule
    /// that kind is compared by.
    ///
    /// A number is equal here exactly when [`Ord`] would call it equal, so
    /// `1.0` and `01.0` are one version to a prefix comparison as well.
    fn eq(&self, other: &Token<'_>) -> bool {
        match (self, other) {
            (
                Token::Number { text: a, dotted },
                Token::Number {
                    text: b,
                    dotted: also,
                },
            ) => compare_component(a, b, *dotted || *also) == Ordering::Equal,
            (Token::Letter(a), Token::Letter(b)) => a == b,
            (Token::Suffix(a), Token::Suffix(b)) => a == b,
            (Token::SuffixNumber(a), Token::SuffixNumber(b)) => compare_numerically(a, b).is_eq(),
            (Token::Commit(a), Token::Commit(b)) => a == b,
            (Token::Revision(a), Token::Revision(b)) => compare_numerically(a, b).is_eq(),
            _ => false,
        }
    }
}

impl<'a> Version<'a> {
    /// The version's tokens, in the order the grammar emits them.
    fn tokens(&self) -> Vec<Token<'a>> {
        let mut tokens: Vec<Token<'a>> = self
            .numbers
            .iter()
            .enumerate()
            .map(|(index, text)| Token::Number {
                text,
                dotted: index > 0,
            })
            .collect();
        tokens.extend(self.letter.map(Token::Letter));
        for suffix in &self.suffixes {
            tokens.push(Token::Suffix(suffix.rank));
            // An absent number is not a token. `1.0_p` and `1.0_p0` are the same
            // version, but only the second states a token where a prefix
            // comparison could stop.
            if !suffix.number.is_empty() {
                tokens.push(Token::SuffixNumber(suffix.number));
            }
        }
        tokens.extend(self.commit.map(Token::Commit));
        tokens.extend(self.revision.map(Token::Revision));
        tokens
    }
}

/// Parses `text` as an apk version, or reports `None` for one the format does
/// not define.
///
/// What is refused is as much the point as what is accepted: a version whose
/// tokens appear out of order, that carries a token twice, that names a suffix
/// the table does not hold, or that trails anything at all.
pub(super) fn parse(text: &str) -> Option<Version<'_>> {
    let bytes = text.as_bytes();
    let mut at = 0;

    let mut numbers = vec![take_digits(bytes, &mut at)?];
    while bytes.get(at) == Some(&b'.') {
        at += 1;
        numbers.push(take_digits(bytes, &mut at)?);
    }

    let letter = bytes.get(at).copied().filter(u8::is_ascii_lowercase);
    if letter.is_some() {
        at += 1;
    }

    let mut suffixes = Vec::new();
    while bytes.get(at) == Some(&b'_') {
        at += 1;
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_lowercase) {
            at += 1;
        }
        let rank = suffix_rank(&text[start..at])?;
        // The digits are optional here, unlike everywhere else a digit run
        // appears: `_p` and `_p0` are the same suffix.
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        suffixes.push(Suffix {
            rank,
            number: &text[start..at],
        });
    }

    let mut commit = None;
    if bytes.get(at) == Some(&b'~') {
        at += 1;
        let start = at;
        while bytes
            .get(at)
            .is_some_and(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            at += 1;
        }
        if at == start {
            return None;
        }
        commit = Some(&text[start..at]);
    }

    let mut revision = None;
    if bytes.get(at) == Some(&b'-') {
        at += 1;
        if bytes.get(at) != Some(&b'r') {
            return None;
        }
        at += 1;
        revision = Some(take_digits(bytes, &mut at)?);
    }

    // Anything left is a token the grammar has no place for at this point,
    // which is exactly the out-of-order version this refuses.
    (at == bytes.len()).then_some(Version {
        numbers,
        letter,
        suffixes,
        commit,
        revision,
    })
}

/// Compares two versions, or reports `None` where either is not a version.
///
/// A caller holding records from an index has already refused the malformed
/// ones, so this reports `None` only for a version that reached it unchecked —
/// and reporting it is what keeps such a version from silently ordering above or
/// below a real one.
pub(super) fn compare(a: &str, b: &str) -> Option<Ordering> {
    Some(parse(a)?.cmp(&parse(b)?))
}

/// What a dependency states about the version it accepts.
///
/// Built by [`split`], which is the whole of the grammar: a dependency is a
/// name, optionally followed by an operator and a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Constraint {
    /// The orderings this accepts, as [`ACCEPT_LESS`], [`ACCEPT_EQUAL`] and
    /// [`ACCEPT_GREATER`].
    accepts: u8,
    /// Whether the comparison stops where this constraint's tokens do, which is
    /// what `~` adds.
    fuzzy: bool,
    /// The version a candidate is compared against, as written.
    version: String,
}

impl fmt::Display for Constraint {
    /// Writes the operator and the version, as a dependency spells them.
    ///
    /// The operator is rebuilt from its bits rather than remembered, so the
    /// rendering is canonical: `=<1.0` and `<=1.0` both render `<=1.0`, and
    /// every rendering parses back to the constraint that produced it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.accepts & ACCEPT_LESS != 0 {
            f.write_str("<")?;
        }
        if self.accepts & ACCEPT_GREATER != 0 {
            f.write_str(">")?;
        }
        if self.fuzzy {
            f.write_str("~")?;
        } else if self.accepts & ACCEPT_EQUAL != 0 {
            f.write_str("=")?;
        }
        f.write_str(&self.version)
    }
}

impl Constraint {
    /// The version this states as a plain equality, or `None` for any other
    /// comparison.
    ///
    /// A `p:` entry states the version it provides a name at this way and no
    /// other, so this is how one is read back out of the shared grammar.
    pub(super) fn exact_version(&self) -> Option<&str> {
        (self.accepts == ACCEPT_EQUAL && !self.fuzzy).then_some(&self.version)
    }

    /// Whether `candidate` is a version this constraint accepts.
    ///
    /// A candidate that is not a version accepts nothing: a caller holding
    /// records from an index has already refused those, so this only fires for
    /// one that reached here unchecked.
    pub(super) fn satisfied_by(&self, candidate: &str) -> bool {
        let (Some(candidate), Some(against)) = (parse(candidate), parse(&self.version)) else {
            return false;
        };
        let order = if self.fuzzy && is_prefix(&against, &candidate) {
            Ordering::Equal
        } else {
            candidate.cmp(&against)
        };
        let bit = match order {
            Ordering::Less => ACCEPT_LESS,
            Ordering::Equal => ACCEPT_EQUAL,
            Ordering::Greater => ACCEPT_GREATER,
        };
        self.accepts & bit != 0
    }
}

/// Whether `constraint`'s tokens are a prefix of `candidate`'s, which is what a
/// fuzzy comparison calls equal.
///
/// A fuzzy comparison walks both token streams and stops as soon as the
/// *constraint* runs out, so `~3.12` accepts `3.12.11-r0` and `~1.0` accepts
/// `1.0a`, `1.0-r5` and `1.0_rc1` alike — it is a prefix rule and not an
/// ordering, which is why `~1.0` accepts a version below `1.0`. It is not a
/// truncation either: `~1.0a` refuses `1.0.1a`, because the token after the
/// constraint's `0` is a letter where the candidate's is a further component.
fn is_prefix(constraint: &Version<'_>, candidate: &Version<'_>) -> bool {
    let constraint = constraint.tokens();
    let candidate = candidate.tokens();
    constraint.len() <= candidate.len() && constraint == candidate[..constraint.len()]
}

/// Splits a dependency's `name[<operator><version>]` into the two.
///
/// `None` for the constraint means the dependency accepts any version, which is
/// how a dependency with no operator at all is spelled.
///
/// # Errors
///
/// Returns the reason where the operator is not one the format defines, where
/// it is followed by no version or by something that is not one, or where it
/// is the legacy `><` form. That form names a package by the digest of its
/// contents rather than by a version, and no repository this layer reads
/// publishes one; accepting it would mean reading the version field as a digest.
pub(super) fn split(text: &str) -> Result<(&str, Option<Constraint>), String> {
    let Some(at) = text.find(OPERATOR_CHARACTERS) else {
        return Ok((text, None));
    };
    let (name, rest) = text.split_at(at);
    let operator_len = rest
        .find(|character| !OPERATOR_CHARACTERS.contains(&character))
        .unwrap_or(rest.len());
    let (operator, version) = rest.split_at(operator_len);

    let mut accepts = 0;
    let mut fuzzy = false;
    for character in operator.chars() {
        match character {
            '<' => accepts |= ACCEPT_LESS,
            '>' => accepts |= ACCEPT_GREATER,
            '=' => accepts |= ACCEPT_EQUAL,
            // `~` admits an equal version over a prefix comparison, so it sets
            // the equality bit as well as the flag. That is why `=~` and `~`
            // are one operator.
            '~' => {
                accepts |= ACCEPT_EQUAL;
                fuzzy = true;
            }
            // `find` located a character of the set and the run stops at the
            // first that is not one, so every character here is one of the four.
            _ => unreachable!("the operator run holds only operator characters"),
        }
    }
    if accepts == ACCEPT_LESS | ACCEPT_GREATER {
        return Err(format!(
            "{text:?} carries the operator {operator:?}, which names a package by the digest of \
             its contents rather than by a version",
        ));
    }
    if parse(version).is_none() {
        return Err(format!(
            "{text:?} constrains a version to {version:?}, which is not a version this format \
             defines",
        ));
    }
    Ok((
        name,
        Some(Constraint {
            accepts,
            fuzzy,
            version: version.to_string(),
        }),
    ))
}

/// Consumes a run of at least one digit, or reports `None`.
fn take_digits<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a str> {
    let start = *at;
    while bytes.get(*at).is_some_and(u8::is_ascii_digit) {
        *at += 1;
    }
    (*at > start).then(|| {
        // The run is ASCII digits, so the slice is a `str` boundary to boundary.
        std::str::from_utf8(&bytes[start..*at]).unwrap_or_default()
    })
}

/// Compares two digit runs as numbers of unbounded length.
fn compare_numerically(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Compares two optional digit runs, an absent one below any present one.
fn compare_optional_numbers(a: Option<&str>, b: Option<&str>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => compare_numerically(a, b),
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
    }
}

/// Compares two dotted component lists.
///
/// Where one list runs out and the other continues, the longer is the greater
/// version: `1.0.0` follows `1.0`.
fn compare_numbers(a: &[&str], b: &[&str]) -> Ordering {
    for (index, (a, b)) in a.iter().zip(b).enumerate() {
        let order = compare_component(a, b, index > 0);
        if order != Ordering::Equal {
            return order;
        }
    }
    a.len().cmp(&b.len())
}

/// Compares two dotted components, `dotted` being false only for the first.
///
/// A leading zero on either side after the first component reads as a decimal
/// fraction rather than as padding, so both sides are compared as text and
/// `1.01` falls below `1.1`. The first component carries no such reading: `01.0`
/// and `1.0` are one version.
fn compare_component(a: &str, b: &str, dotted: bool) -> Ordering {
    if dotted && (a.starts_with('0') || b.starts_with('0')) {
        a.cmp(b)
    } else {
        compare_numerically(a, b)
    }
}

/// Compares two suffix runs, padding the shorter with the rank of an absent
/// suffix.
///
/// That padding is what makes a run's length meaningful in both directions:
/// `1.0_p_p` is above `1.0_p`, and `1.0_p_alpha` is below it.
fn compare_suffixes(a: &[Suffix<'_>], b: &[Suffix<'_>]) -> Ordering {
    let absent = Suffix {
        rank: NO_SUFFIX,
        number: "",
    };
    for index in 0..a.len().max(b.len()) {
        let a = a.get(index).unwrap_or(&absent);
        let b = b.get(index).unwrap_or(&absent);
        let order = a
            .rank
            .cmp(&b.rank)
            .then_with(|| compare_numerically(a.number, b.number));
        if order != Ordering::Equal {
            return order;
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asserts `a` orders below `b`, and that the reverse comparison agrees.
    fn lt(a: &str, b: &str) {
        assert_eq!(compare(a, b), Some(Ordering::Less), "{a} < {b}");
        assert_eq!(compare(b, a), Some(Ordering::Greater), "{b} > {a}");
    }

    /// Asserts `a` and `b` are the same version despite being spelled apart.
    fn eq(a: &str, b: &str) {
        assert_eq!(compare(a, b), Some(Ordering::Equal), "{a} == {b}");
    }

    #[test]
    fn the_suffix_table_orders_pre_and_post_releases_around_a_bare_version() {
        // The ladder, in one chain. The bare version sits in the middle of it,
        // which is the property the whole table exists for.
        let ladder = [
            "1.0_alpha",
            "1.0_beta",
            "1.0_pre",
            "1.0_rc",
            "1.0",
            "1.0_cvs",
            "1.0_svn",
            "1.0_git",
            "1.0_hg",
            "1.0_p",
        ];
        for pair in ladder.windows(2) {
            lt(pair[0], pair[1]);
        }
    }

    #[test]
    fn a_suffix_number_orders_within_its_rank() {
        lt("1.0_alpha1", "1.0_alpha2");
        lt("1.0_alpha2", "1.0_alpha10");
        // An absent number is zero rather than a distinct value.
        eq("1.0_alpha", "1.0_alpha0");
        eq("1.0_p1", "1.0_p01");
    }

    #[test]
    fn a_repeated_suffix_is_compared_against_the_absent_rank() {
        // The shorter run is padded with "no suffix", so a trailing
        // post-release raises the version and a trailing pre-release lowers it.
        lt("1.0_p", "1.0_p_p");
        lt("1.0_p_alpha", "1.0_p");
        lt("1.0_alpha_beta", "1.0_alpha");
        lt("1.0_alpha", "1.0_alpha_p");
    }

    #[test]
    fn the_token_kinds_order_by_their_place_in_the_grammar() {
        // Every pair here is a boundary between two token kinds at the same
        // position, and the whole ordering falls out of them: a pre-release
        // suffix, then the bare version, the revision, the commit, a
        // post-release suffix, the letter, and a further dotted component.
        let ladder = [
            "1.0_rc1", "1.0", "1.0-r1", "1.0~abc", "1.0_p1", "1.0a", "1.0.1",
        ];
        for pair in ladder.windows(2) {
            lt(pair[0], pair[1]);
        }
    }

    #[test]
    fn dotted_components_compare_numerically_and_by_length() {
        lt("1.9", "1.10");
        lt("1.0", "1.0.0");
        lt("1.0.0", "1.0.0.0");
        lt("1.0.1", "1.1");
        lt("1.0z", "1.1");
    }

    #[test]
    fn a_leading_zero_reads_as_a_fraction_after_the_first_component() {
        // `1.01` is below `1.1` because the zero is significant, while the
        // first component carries no such reading and `01.0` is `1.0`.
        lt("1.01", "1.1");
        lt("1.010", "1.1");
        lt("1.01", "1.010");
        eq("01.0", "1.0");
        eq("0010", "10");
        eq("0", "00");
    }

    #[test]
    fn a_component_no_integer_could_hold_still_orders() {
        // Nothing here is parsed into an integer, so a version whose digits
        // overflow every width the language has still compares.
        lt("1.0-r99999999999999999999", "1.0-r99999999999999999999999");
        lt("999999999999999999999999.0", "9999999999999999999999999.0");
    }

    #[test]
    fn the_revision_and_the_commit_order_after_everything_else() {
        lt("1.0-r0", "1.0-r1");
        lt("1.0-r9", "1.0-r10");
        lt("1.0~ff", "1.0~ff0");
        lt("1.0~0", "1.0~f");
        lt("1.0~ff", "1.0~ff-r1");
        lt("1.0-r2", "1.0~ff-r1");
    }

    #[test]
    fn real_archive_versions() {
        lt("1.2.5-r22", "1.2.5-r23");
        lt("3.23.4-r0", "3.23.5-r0");
        lt("25.01-r0", "25.02-r0");
        lt("1.34.1-r1", "1.34.2-r0");
        lt("6.9_git20240101-r0", "6.9_git20240102-r0");
        lt("2.0_rc1-r0", "2.0-r0");
    }

    #[test]
    fn a_version_whose_tokens_are_out_of_order_is_refused() {
        // Each of these is a token the grammar has no place for where it
        // appears, rather than an unknown character: a suffix after the
        // revision, digits after the letter, a second commit, a component after
        // the letter.
        for text in [
            "1.0-r1_p1",
            "1.0a1",
            "1.0a.1",
            "1.0~ff_p",
            "1.0~ab~cd",
            "1.0_p.1",
            "1.0_p1a",
        ] {
            assert!(parse(text).is_none(), "{text} was accepted");
        }
    }

    #[test]
    fn a_version_the_format_does_not_define_is_refused() {
        for text in [
            "",
            "abc",
            "1.",
            "1..0",
            "1.0.",
            "_p",
            "~abc",
            "1.0-r",
            "1.0-1",
            "1.0+1",
            "1:1.0",
            "1.0-R0",
            "1.0A",
            "1.0ab",
            "1.0_foo",
            "1.0_alphaX",
            "1.0~",
            "1.0~ABCDEF",
            "1.0~xyz",
            "1.0 ",
        ] {
            assert!(parse(text).is_none(), "{text:?} was accepted");
        }
    }

    #[test]
    fn every_shape_the_grammar_defines_is_accepted() {
        for text in [
            "1",
            "1.0",
            "20200101",
            "1.0.0.0.0",
            "1a",
            "1.0.0a",
            "1.0_alpha",
            "1.0_alpha01",
            "1.0_alpha1_beta2",
            "1.0_cvs20200101",
            "1.0~abcdef",
            "1.0-r0",
            "1.0-r01",
            "1.0a_p1~ff-r3",
        ] {
            assert!(parse(text).is_some(), "{text} was refused");
        }
    }

    /// The constraint `text` states, or a panic naming the refusal.
    ///
    /// The name is asserted away, since every case below constrains `lib`.
    fn constraint(text: &str) -> Constraint {
        let (name, constraint) =
            split(text).unwrap_or_else(|reason| panic!("{text} is a dependency: {reason}"));
        assert_eq!(name, "lib", "{text}");
        constraint.unwrap_or_else(|| panic!("{text} states a constraint"))
    }

    #[test]
    fn a_dependency_without_an_operator_constrains_nothing() {
        for text in [
            "lib",
            "so:libc.musl-x86_64.so.1",
            "cmd:awk",
            "/bin/sh",
            "cmd:[",
        ] {
            let (name, constraint) = split(text).expect("a bare name is a dependency");
            assert_eq!(name, text);
            assert!(constraint.is_none(), "{text}");
        }
    }

    #[test]
    fn the_operator_is_a_set_of_orderings_rather_than_a_spelling() {
        // Every row was measured against apk.static 3.0.7 with a dependency on
        // a package published at 2.5-r0.
        for (text, accepted) in [
            ("lib=2.5-r0", true),
            ("lib=2.0", false),
            ("lib>2.0", true),
            ("lib<2.0", false),
            ("lib>=2.0", true),
            ("lib<=2.0", false),
            // The characters may appear in any order: `=<` is `<=`.
            ("lib=<2.0", false),
            ("lib=>2.0", true),
            // And in any combination: this one admits every ordering.
            ("lib<=>2.0", true),
            // `~` sets the equality bit as well as the flag, so `=~` is `~`.
            ("lib=~2.0", false),
            ("lib~2.0", false),
            ("lib~2.5", true),
            // A fuzzy comparison narrows what an ordering bit is tested
            // against; it does not replace the bit.
            ("lib>~2.0", true),
            ("lib<~2.0", false),
        ] {
            assert_eq!(
                constraint(text).satisfied_by("2.5-r0"),
                accepted,
                "{text} against 2.5-r0",
            );
        }
    }

    #[test]
    fn a_fuzzy_constraint_accepts_a_version_that_begins_with_it() {
        // Each row measured against apk.static. The rule is a prefix over the
        // token stream, so it accepts versions on both sides of its own: `~1.0`
        // takes `1.0_rc1`, which is *below* 1.0.
        for (text, candidate, accepted) in [
            ("lib~1.0", "1.0.5-r0", true),
            ("lib~1.0", "1.1.0-r0", false),
            ("lib~3.12", "3.12.11-r0", true),
            ("lib~1", "1.5-r0", true),
            ("lib~1.0", "1.0a-r0", true),
            ("lib~1.0", "1.0_rc1-r0", true),
            ("lib~1.0", "1.0-r5", true),
            ("lib~1.0-r1", "1.0-r1", true),
            ("lib~1.0-r1", "1.0-r2", false),
            // A suffix with no digits is one token where a suffix with digits
            // is two, so the shorter is a prefix of the longer.
            ("lib~1.0_p", "1.0_p1-r0", true),
            ("lib~1.0_p1", "1.0_p2-r0", false),
            // Not a truncation: the constraint's letter meets a further dotted
            // component, which is a different token rather than an absent one.
            ("lib~1.0a", "1.0.1a-r0", false),
            // A leading zero is not a difference in the first component here
            // either, since a token compares as the ordering compares it.
            ("lib~01.0", "1.0.5-r0", true),
        ] {
            assert_eq!(
                constraint(text).satisfied_by(candidate),
                accepted,
                "{text} against {candidate}",
            );
        }
    }

    #[test]
    fn an_operator_naming_a_digest_rather_than_a_version_is_refused() {
        // `><` is apk's legacy checksum dependency: the field after it is the
        // digest of a package's contents, not a version. No repository this
        // layer reads publishes one, and reading the field as a version would
        // silently accept whatever the mirror put there.
        for text in ["lib><2.0", "lib<>2.0"] {
            let reason = split(text).expect_err("the checksum form is refused");
            assert!(reason.contains("digest"), "{text}: {reason}");
        }
    }

    #[test]
    fn a_constraint_on_something_that_is_not_a_version_is_refused() {
        for text in ["lib>=", "lib=nonesuch", "lib~", "lib>1.0-R0"] {
            let reason = split(text).expect_err("the constraint states no version");
            assert!(reason.contains("not a version"), "{text}: {reason}");
        }
    }

    #[test]
    fn a_rendering_is_canonical_and_parses_back() {
        // The operator is rebuilt from its bits, so two spellings of one
        // operator render alike and every rendering reads back as itself.
        for (text, rendered) in [
            ("lib=<2.0", "<=2.0"),
            ("lib<=2.0", "<=2.0"),
            ("lib=~1.0", "~1.0"),
            ("lib~1.0", "~1.0"),
            ("lib>~1.0", ">~1.0"),
            ("lib<=>1.0", "<>=1.0"),
            ("lib=1.0", "=1.0"),
        ] {
            assert_eq!(constraint(text).to_string(), rendered, "{text}");
            assert_eq!(
                constraint(&format!("lib{rendered}")).to_string(),
                rendered,
                "{rendered} reads back as itself",
            );
        }
    }

    #[test]
    fn an_unorderable_version_reports_no_ordering() {
        // Rather than a fallback that would let a malformed version from a
        // mirror sort above or below a real one.
        assert_eq!(compare("1.0", "not a version"), None);
        assert_eq!(compare("not a version", "1.0"), None);
    }
}
