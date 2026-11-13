//! Debian package version comparison.
//!
//! Implements dpkg's algorithm (Debian Policy 5.6.12, `lib/dpkg/version.c`):
//! a version is `[epoch:]upstream[-revision]`, compared field by field, with
//! each field compared in alternating non-digit and digit runs. The one
//! subtlety worth stating is the character ordering: `~` sorts before
//! everything, including the end of a string, so `1.0~rc1` precedes `1.0`.
//!
//! Comparison keeps the highest version when the same package name appears
//! more than once across an index. [`Constraint`] builds on it to answer the
//! resolver's question: whether a candidate version satisfies what a
//! dependency declares. The Alpine layer's answer, ferrata's `version` and
//! `dependency` modules, holds that format's comparison and its matching
//! together for the same reason — a constraint is meaningless apart from the
//! ordering it is evaluated under.
//!
//! # This comparison is total, and the other two are not
//!
//! `compare` here answers an [`Ordering`](std::cmp::Ordering), where
//! [`gentoo::version::compare`] answers an `Option<Ordering>` and ferrata
//! declines to read a string outside apk's grammar as a version at all. That
//! is the formats speaking, not three opinions about error handling: dpkg's
//! algorithm is defined over *every* string. It reads a version as alternating
//! non-digit and digit runs, and any string at all is such a sequence, so there
//! is no input it declines to order and no refusal to report. An apk or a
//! portage version is a token grammar, and a string outside it is not a version
//! to be ordered low — it is a version the mirror should not have published,
//! which is what the other two report.
//!
//! What this layer admits is narrower than what it can order. [`is_version`]
//! holds the version an index, a plan, or a base layer's status database
//! states to the alphabet Debian policy gives one, before anything reports it.
//! That is a question of what a version may be spelled with, which dpkg also
//! asks, rather than of how two compare.
//!
//! [`gentoo::version::compare`]: crate::provision::gentoo::version::compare

use std::cmp::Ordering;
use std::fmt;

/// Compares two Debian version strings.
///
/// Total: see this module's documentation for why this format has no
/// unorderable version and the other two do.
pub(super) fn compare(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = split(as_dpkg_reads(a));
    let (eb, ub, rb) = split(as_dpkg_reads(b));
    ea.cmp(&eb)
        .then_with(|| verrevcmp(ua, ub))
        .then_with(|| verrevcmp(ra, rb))
}

/// The part of a version string dpkg itself reads.
///
/// dpkg holds a version as a NUL-terminated `char *`, so a string carrying an
/// interior NUL is to every part of dpkg the shorter string that ends there —
/// including the parser that reads a `Version:` field back out of a
/// `dpkg/status` this crate wrote. Reading the same prefix is what keeps this
/// comparison agreeing with the tool that will read the same bytes, and it is
/// what keeps it total: [`verrevcmp`] weights a byte past the end as that
/// terminator, so an interior NUL reaching it matches the weight of the end of
/// the *other* string in every branch, and neither cursor advances.
///
/// This scans for a NUL where [`path::is_ordinary_component`] is the
/// workspace's answer for refusing one, because the question is not the same:
/// that answer refuses a path whose bytes were not understood, where this one
/// reproduces how another program reads bytes that are not this crate's to
/// refuse. A version reaches here from a caller's plan document and from a base
/// layer's own database, and neither is a place this comparison may fail.
///
/// [`path::is_ordinary_component`]: crate::path::is_ordinary_component
fn as_dpkg_reads(version: &str) -> &str {
    match version.find('\0') {
        Some(nul) => &version[..nul],
        None => version,
    }
}

/// Splits a version into `(epoch, upstream, revision)`.
///
/// A missing epoch is 0; a missing revision is empty. The upstream/revision
/// boundary is the last hyphen.
fn split(version: &str) -> (u64, &str, &str) {
    let (epoch, rest) = match version.find(':') {
        Some(colon) if crate::provision::number::is_digits(&version[..colon]) => {
            // The field is all digits, so a parse failure is an overflow of a
            // pathologically large epoch. Saturate to the maximum: such an
            // epoch sorts above every real one, the correct direction, where
            // mapping it to 0 would wrongly sort it below.
            (
                version[..colon].parse().unwrap_or(u64::MAX),
                &version[colon + 1..],
            )
        }
        _ => (0, version),
    };
    match rest.rfind('-') {
        Some(hyphen) => (epoch, &rest[..hyphen], &rest[hyphen + 1..]),
        None => (epoch, rest, ""),
    }
}

/// Compares one version field (upstream or revision) by dpkg's rule.
fn verrevcmp(a: &str, b: &str) -> Ordering {
    let a = a.as_bytes();
    let b = b.as_bytes();
    // A byte past the end reads as 0, dpkg's NUL terminator, which `order`
    // weights the same as a digit position and below every real character
    // except `~`.
    let at = |i: usize| a.get(i).copied().unwrap_or(0);
    let bt = |j: usize| b.get(j).copied().unwrap_or(0);
    let (mut i, mut j) = (0, 0);

    while i < a.len() || j < b.len() {
        // Compare the leading non-digit run character by character.
        while (at(i) != 0 && !at(i).is_ascii_digit()) || (bt(j) != 0 && !bt(j).is_ascii_digit()) {
            let ac = order(at(i));
            let bc = order(bt(j));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }

        // Then the leading digit run, numerically, ignoring leading zeros.
        while at(i) == b'0' {
            i += 1;
        }
        while bt(j) == b'0' {
            j += 1;
        }
        let mut first_diff: i32 = 0;
        while at(i).is_ascii_digit() && bt(j).is_ascii_digit() {
            if first_diff == 0 {
                first_diff = i32::from(at(i)) - i32::from(bt(j));
            }
            i += 1;
            j += 1;
        }
        // The longer run of digits is the larger number.
        if at(i).is_ascii_digit() {
            return Ordering::Greater;
        }
        if bt(j).is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }
    Ordering::Equal
}

/// The sort weight of a version character: `~` below everything (including
/// the end of a string, weight 0), digits at 0, letters at their code, and
/// every other character above the letters.
fn order(c: u8) -> i32 {
    if c.is_ascii_digit() {
        0
    } else if c.is_ascii_alphabetic() {
        i32::from(c)
    } else if c == b'~' {
        -1
    } else if c != 0 {
        i32::from(c) + 256
    } else {
        0
    }
}

/// Whether `version` is spelled in the alphabet Debian policy gives a version.
///
/// Policy 5.6.12's alphabet is alphanumerics and `.`, `+`, `-`, `:`, `~`, and
/// dpkg refuses to install a package whose version holds anything else. It
/// holds no separator, whitespace, or control character, so a version is one
/// file name segment where the pool interpolates it, and carries no escape
/// sequence onto the terminal a refusal naming it is printed on.
///
/// A stanza stating a version outside it is malformed and dropped as the index
/// is read, a plan stating one is refused
/// ([`PlannedPackage::unaddressable`](super::plan::PlannedPackage::unaddressable)),
/// a base layer's status database stating one is read as stating none
/// ([`read_installed_set`](super::layer::read_installed_set)), and the pool
/// refuses a `.deb` whose control file states one
/// ([`checked_version`](super::pool::checked_version)).
///
/// The grammar around the alphabet, where an epoch's colon and a revision's
/// hyphen may fall and that the version begins with a digit, is dpkg's to
/// enforce at install time and is not repeated.
pub(super) fn is_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | ':' | '~'))
}

/// A version constraint on a dependency: `(>= 2.43)` and its siblings.
///
/// The constraint is kept rather than dropped at parse time because the
/// resolver cannot assume a single coherent archive state. A layered resolve
/// closes over an increment against a base provisioned earlier, possibly from
/// an older archive, so `libc6 (>= 2.43)` is a question the base's actual
/// version has to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Constraint {
    /// The relation a candidate must bear to [`version`](Self::version).
    pub relation: Relation,
    /// The version named in the relationship, verbatim.
    pub version: String,
}

impl fmt::Display for Constraint {
    /// Writes the operator and the version as a dependency spells them, so an
    /// error naming a group renders it the way the archive declares it. The
    /// deprecated `<` and `>` render as the `<=` and `>=` they mean.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.relation.as_str(), self.version)
    }
}

impl Constraint {
    /// Reads the inside of a dependency's `(...)` clause — `">= 2.43"` — or
    /// `None` when it is not a constraint dpkg defines.
    ///
    /// A clause that cannot be read yields `None` rather than failing the
    /// parse, leaving an unversioned dependency on the name. The alternative
    /// would be to drop the whole atom, which turns a malformed constraint into
    /// a silently missing dependency; the resolver's job is to report what it
    /// cannot satisfy, not to lose the relationship.
    pub(crate) fn parse(inner: &str) -> Option<Constraint> {
        let inner = inner.trim();
        // The operator is the leading run of relation characters; the version is
        // the rest. Splitting on the first character that starts neither keeps a
        // version like `1.0~rc1` intact whether or not a space follows the
        // operator.
        let split = inner
            .find(|c: char| !matches!(c, '<' | '>' | '='))
            .unwrap_or(inner.len());
        let (operator, version) = inner.split_at(split);
        let relation = Relation::parse(operator.trim())?;
        let version = version.trim();
        (!version.is_empty()).then(|| Constraint {
            relation,
            version: version.to_string(),
        })
    }

    /// The version this states as a plain equality, or `None` for any other
    /// relation.
    ///
    /// A `Provides` states the version it supplies a name at this way and no
    /// other — Debian Policy 7.5 permits no other relation there — so this is
    /// how one is read back out of the shared grammar.
    pub(crate) fn exact_version(&self) -> Option<&str> {
        (self.relation == Relation::Exactly).then_some(self.version.as_str())
    }

    /// Whether `candidate` satisfies this constraint under dpkg's version
    /// ordering.
    pub(crate) fn satisfied_by(&self, candidate: &str) -> bool {
        self.relation.holds(compare(candidate, &self.version))
    }
}

/// The relation of a version constraint.
///
/// Debian Policy 7.1 defines `<<`, `<=`, `=`, `>=` and `>>`. The bare `<` and
/// `>` are deprecated spellings dpkg still accepts, meaning `<=` and `>=` — not
/// the strict comparisons their spelling suggests — so they are read that way
/// rather than rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Relation {
    /// `<<`: strictly earlier.
    Earlier,
    /// `<=`, and the deprecated `<`.
    EarlierEqual,
    /// `=`: exactly.
    Exactly,
    /// `>=`, and the deprecated `>`.
    LaterEqual,
    /// `>>`: strictly later.
    Later,
}

impl Relation {
    /// The canonical spelling. The deprecated `<` and `>` render as the `<=`
    /// and `>=` they mean.
    fn as_str(self) -> &'static str {
        match self {
            Self::Earlier => "<<",
            Self::EarlierEqual => "<=",
            Self::Exactly => "=",
            Self::LaterEqual => ">=",
            Self::Later => ">>",
        }
    }

    /// Reads a relation operator, or `None` when it is not one dpkg defines.
    fn parse(text: &str) -> Option<Self> {
        match text {
            "<<" => Some(Self::Earlier),
            "<=" | "<" => Some(Self::EarlierEqual),
            "=" => Some(Self::Exactly),
            ">=" | ">" => Some(Self::LaterEqual),
            ">>" => Some(Self::Later),
            _ => None,
        }
    }

    /// Whether the ordering of a candidate against the constrained version
    /// satisfies this relation.
    fn holds(self, ordering: Ordering) -> bool {
        match self {
            Self::Earlier => ordering == Ordering::Less,
            Self::EarlierEqual => ordering != Ordering::Greater,
            Self::Exactly => ordering == Ordering::Equal,
            Self::LaterEqual => ordering != Ordering::Less,
            Self::Later => ordering == Ordering::Greater,
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn policy_admits_every_shape_an_archive_version_takes() {
        for version in [
            "1.0",
            "1:2.41-12+deb13u1",
            "1.0~rc1-1",
            "0.14.0-1ubuntu1",
            "20240101.1+dfsg-2~bpo13+1",
            "2.4-1",
        ] {
            assert!(super::is_version(version), "{version:?}");
        }
        for version in ["", "1.0_1", "1.0/1", "1 0", "1.0\u{1b}"] {
            assert!(!super::is_version(version), "{version:?}");
        }
    }

    #[test]
    fn a_constraint_reads_every_relation_dpkg_defines() {
        for (text, relation) in [
            ("<< 1.0", Relation::Earlier),
            ("<= 1.0", Relation::EarlierEqual),
            ("= 1.0", Relation::Exactly),
            (">= 1.0", Relation::LaterEqual),
            (">> 1.0", Relation::Later),
        ] {
            let constraint = Constraint::parse(text).expect("a defined relation parses");
            assert_eq!(constraint.relation, relation);
            assert_eq!(constraint.version, "1.0");
        }
    }

    #[test]
    fn the_deprecated_operators_mean_the_inclusive_comparisons() {
        // dpkg reads a bare `<` as `<=` and `>` as `>=`, not as the strict
        // comparisons they look like, so 1.0 satisfies both.
        assert!(Constraint::parse("< 1.0").unwrap().satisfied_by("1.0"));
        assert!(Constraint::parse("> 1.0").unwrap().satisfied_by("1.0"));
        assert!(!Constraint::parse("<< 1.0").unwrap().satisfied_by("1.0"));
        assert!(!Constraint::parse(">> 1.0").unwrap().satisfied_by("1.0"));
    }

    #[test]
    fn a_constraint_is_evaluated_under_the_formats_own_ordering() {
        // `~` sorts before the end of a string, so 1.0~rc1 precedes 1.0 --
        // the subtlety a lexical comparison would get backwards.
        let constraint = Constraint::parse(">= 1.0").expect("it parses");
        assert!(constraint.satisfied_by("1.0"));
        assert!(constraint.satisfied_by("1.0-1"));
        assert!(!constraint.satisfied_by("1.0~rc1"));
        // An epoch outranks the upstream version entirely.
        assert!(constraint.satisfied_by("1:0.1"));
    }

    #[test]
    fn a_constraint_needs_no_space_after_its_operator() {
        let constraint = Constraint::parse(">=2.43").expect("it parses");
        assert_eq!(constraint.relation, Relation::LaterEqual);
        assert_eq!(constraint.version, "2.43");
    }

    #[test]
    fn an_unreadable_constraint_is_no_constraint_rather_than_an_error() {
        // Degrading to `None` leaves an unversioned dependency on the name.
        // Failing instead would turn a malformed clause into a silently missing
        // dependency, which is the failure this whole mechanism exists to stop.
        assert_eq!(Constraint::parse(">>>= 1.0"), None);
        assert_eq!(Constraint::parse(">="), None);
        assert_eq!(Constraint::parse(""), None);
        assert_eq!(Constraint::parse("1.0"), None);
    }

    #[test]
    fn only_an_equality_reads_back_as_a_provided_version() {
        // Policy 7.5 permits only `=` in a Provides, so any other relation has
        // no version to hand back and satisfies no versioned dependency.
        assert_eq!(
            Constraint::parse("= 1.2").unwrap().exact_version(),
            Some("1.2")
        );
        assert_eq!(Constraint::parse(">= 1.2").unwrap().exact_version(), None);
    }

    #[test]
    fn a_constraint_renders_the_way_a_dependency_spells_it() {
        assert_eq!(Constraint::parse(">= 2.43").unwrap().to_string(), ">= 2.43");
        // The deprecated spellings render as what they mean.
        assert_eq!(Constraint::parse("> 2.43").unwrap().to_string(), ">= 2.43");
    }

    use super::*;

    fn lt(a: &str, b: &str) {
        assert_eq!(compare(a, b), Ordering::Less, "{a} < {b}");
        assert_eq!(compare(b, a), Ordering::Greater, "{b} > {a}");
    }

    fn eq(a: &str, b: &str) {
        assert_eq!(compare(a, b), Ordering::Equal, "{a} == {b}");
    }

    #[test]
    fn equal_versions() {
        eq("1.0", "1.0");
        eq("2.41-5", "2.41-5");
        // Leading zeros are numerically insignificant.
        eq("0", "00");
        eq("1.0-00", "1.00-0");
    }

    #[test]
    fn epoch_dominates() {
        lt("1:0", "2:0");
        // A larger epoch beats a larger upstream.
        lt("1:9.9", "2:1.0");
        eq("0:1.0", "1.0");
    }

    #[test]
    fn an_overflowing_epoch_saturates_high() {
        // An all-digit epoch too large for u64 saturates to the maximum, so it
        // sorts above a normal epoch rather than below it (as mapping to 0
        // would have).
        let huge = "99999999999999999999999999:1.0";
        lt("9:1.0", huge);
        lt("1.0", huge);
    }

    #[test]
    fn tilde_sorts_before_everything() {
        lt("1.0~rc1", "1.0");
        lt("1.0~~", "1.0~");
        lt("1.0~rc1", "1.0~rc2");
        lt("1.0~beta", "1.0");
    }

    #[test]
    fn numeric_and_lexical_runs() {
        lt("1.0.0", "1.0.1");
        lt("1.0", "1.0.0");
        lt("1.9", "1.10");
        lt("a", "b");
        // Letters sort before non-letter punctuation like `.` and `+`.
        lt("1.0a", "1.0.");
    }

    #[test]
    fn a_version_is_compared_as_far_as_dpkg_would_read_it() {
        // An interior NUL ends the string dpkg holds, so everything past one is
        // not part of the version being compared. Reading further here would
        // not terminate: the field comparison weights a byte past the end as
        // dpkg's terminator, which an interior NUL matches without advancing
        // either cursor.
        eq("1.0\0-evil", "1.0");
        eq("1.0\0", "1.0");
        lt("1.0\0zzz", "1.1");
        // The epoch and revision boundaries are found in that same prefix, so a
        // hyphen or a colon past the NUL is not a boundary at all.
        eq("1:2.0\0:9", "1:2.0");
        eq("2.0-1\0-9", "2.0-1");
    }

    #[test]
    fn real_archive_versions() {
        lt("2.41-4", "2.41-5");
        lt("1.22.21", "1.22.22");
        lt("5.2.37-2+b9", "5.2.37-2+b10");
        lt("9.7-3", "9.7-3+deb13u1");
    }
}
