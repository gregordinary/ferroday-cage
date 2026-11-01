//! The dependency-atom grammar, and what it means to satisfy one.
//!
//! An atom names a package and states what a candidate must be to answer it:
//!
//! ```text
//! !!>=dev-libs/openssl-3.0.0:0/3=[abi_x86_64(-),-bindist]
//! ^^ ^^ ^^^^^^^^^^^^^^^^^^^^ ^^^^ ^^^^^^^^^^^^^^^^^^^^^^
//! |  |  |                    |    the USE dependencies
//! |  |  |                    the slot dependency, with its operator
//! |  |  the package, and the version the operator applies to
//! |  the version operator
//! the blocker, `!` soft or `!!` hard
//! ```
//!
//! Matching runs version, then slot, then USE, and a candidate that fails any
//! of the three does not answer the atom. The order is the cheapest test first;
//! the outcome does not depend on it.
//!
//! # The USE-dependency defaults decide the outcome
//!
//! `[flag]` asks for a candidate with `flag` enabled and `[-flag]` for one
//! without it, which is the easy half. The subtlety is what to do when the
//! candidate does not know the flag at all — when it is in neither the
//! candidate's `USE` nor its `IUSE`. That is what the `(+)` and `(-)` suffixes
//! answer: `(+)` says to read the absent flag as enabled, `(-)` as disabled. An
//! atom that states neither cannot be evaluated against such a candidate, and
//! the candidate does not match.
//!
//! Reading the suffixes as decoration and requiring the flag to be present
//! instead is a mistake that does not look like one. Over four hundred sampled
//! package names it reports six hundred atoms that no published build can
//! satisfy, which reads as an archive too sparse to resolve against rather than
//! as a misread grammar; implementing the defaults leaves seven.
//!
//! # What the index does not carry
//!
//! Gentoo's binary-package index is USE-evaluated: its dependency strings are
//! the ones that survived the conditionals at build time, so no `flag? ( ... )`
//! group appears in any of them and no ebuild tree or EAPI evaluator is needed
//! to read one. What remains is plain atoms, `|| ( ... )` any-of groups, and
//! blockers.

use std::cmp::Ordering;
use std::fmt;

use super::version;

/// What a candidate's version must be for the atom to admit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    /// `<`: strictly below the atom's version.
    Less,
    /// `<=`: at or below it.
    AtMost,
    /// `=`: exactly it.
    Equal,
    /// `=...*`: a version whose text begins with the atom's, at a boundary
    /// between two of its parts.
    ///
    /// `=dev-lang/python-3.1*` admits `3.1` and `3.1.4` and refuses `3.12`.
    /// [`version::has_prefix`] states the boundary, which is portage's.
    EqualPrefix,
    /// `~`: the atom's version at any revision.
    AnyRevision,
    /// `>=`: at or above it.
    AtLeast,
    /// `>`: strictly above it.
    Greater,
}

/// How strongly an atom refuses the package it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Blocker {
    /// `!`: the package must not be installed at the same time, though portage
    /// may install this one first and remove the other after.
    Soft,
    /// `!!`: the package must be gone before this one is merged.
    Hard,
}

/// What a slot dependency requires of the candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SlotDep {
    /// `:name`, or `:name=`: the slot must be `name`.
    Slot(String),
    /// `:name/sub`: the slot and the sub-slot must both match.
    SubSlot(String, String),
    /// `:*` or `:=`: any slot answers.
    ///
    /// The two spellings differ for portage, which records `:=` so it can
    /// rebuild the dependent when the sub-slot moves. This layer installs into
    /// a root it is building and never rebuilds, so both read as "any".
    Any,
}

/// One `[flag]` entry of a USE dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UseDep {
    /// The flag's name.
    flag: String,
    /// Whether the candidate must have it enabled or disabled.
    wanted: bool,
    /// What to assume when the candidate knows nothing of the flag: `Some(true)`
    /// for `(+)`, `Some(false)` for `(-)`, `None` where the atom states no
    /// default and such a candidate therefore does not match.
    default: Option<bool>,
}

/// One dependency atom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Atom {
    /// The atom as it was written, which is how a refusal names it.
    ///
    /// Kept rather than rendered back from the parts: an atom appears in a
    /// message a caller reads against their own install list or against an
    /// index record, and a re-rendering that normalized `:=` or dropped a
    /// redundant `(+)` would name something they did not write.
    text: String,
    blocker: Option<Blocker>,
    operator: Option<Operator>,
    /// `category/name`, as written.
    name: String,
    /// The version the operator applies to, where the atom carries one.
    version: Option<String>,
    slot: Option<SlotDep>,
    use_deps: Vec<UseDep>,
}

/// What an atom is matched against: a record of the index, or an entry of a
/// root's own package database.
///
/// A trait rather than one concrete type because both sides of resolution
/// answer the same four questions, and the resolver asks them of whichever it
/// is holding: an atom already satisfied by what the root has must not send the
/// resolver to the archive.
pub(super) trait Candidate {
    /// The `category/name` the candidate publishes itself under.
    fn name(&self) -> &str;
    /// The version, without the category or the name.
    fn version(&self) -> &str;
    /// The slot, which the caller defaults where its source states none. A
    /// `slot/subslot` compound is carried whole and split here.
    fn slot(&self) -> &str;
    /// Whether `flag` is enabled, disabled, or unknown to the candidate.
    ///
    /// `None` is what the atom's `(+)` and `(-)` defaults answer, and it is the
    /// common case rather than an edge: a package's `IUSE` names the flags it
    /// was written with, and an atom routinely asks about one another package
    /// defines.
    fn use_flag(&self, flag: &str) -> Option<bool>;

    /// The candidate as `category/name-version`, which is how a refusal or a
    /// report names it, whichever side of resolution it comes from.
    fn cpv(&self) -> String {
        format!("{}-{}", self.name(), self.version())
    }
}

impl fmt::Display for Atom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl Atom {
    /// The `category/name` the atom names.
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// The atom as it was written, which is also what it is displayed as.
    ///
    /// Two atoms written alike are the same atom, so this is what a resolver
    /// keys anything it works out once per atom by.
    pub(super) fn text(&self) -> &str {
        &self.text
    }

    /// How strongly the atom refuses the package, or `None` where it requires
    /// it instead.
    pub(super) fn blocker(&self) -> Option<Blocker> {
        self.blocker
    }

    /// Whether `candidate` answers the atom.
    ///
    /// The name is not compared here: the caller has already found the
    /// candidates published under [`name`](Self::name), and comparing it again
    /// would make every candidate of every other package a caller's mistake
    /// rather than a compile-time impossibility. What is compared is the
    /// version, the slot, and the USE dependencies.
    pub(super) fn matches(&self, candidate: &impl Candidate) -> bool {
        debug_assert_eq!(
            candidate.name(),
            self.name,
            "matched against another package"
        );
        self.version_matches(candidate.version())
            && self.slot_matches(candidate.slot())
            && self.use_matches(candidate)
    }

    /// Which part of the atom `candidate` fails, or `None` where it answers.
    ///
    /// The resolver reports an unsatisfiable atom by naming the wall it hit,
    /// and the walls are these: the four an atom can put up, plus the archive
    /// publishing the name at all, which the caller answers rather than this.
    pub(super) fn unmet_by(&self, candidate: &impl Candidate) -> Unmet {
        if !self.version_matches(candidate.version()) {
            Unmet::Version
        } else if !self.slot_matches(candidate.slot()) {
            Unmet::Slot
        } else if !self.use_matches(candidate) {
            Unmet::UseFlag
        } else {
            Unmet::Nothing
        }
    }

    /// Whether `candidate` satisfies the version part.
    fn version_matches(&self, candidate: &str) -> bool {
        let (Some(operator), Some(wanted)) = (self.operator, self.version.as_deref()) else {
            // No operator is no constraint: any version of the package answers.
            return true;
        };
        if operator == Operator::EqualPrefix {
            return version::has_prefix(candidate, wanted);
        }
        if operator == Operator::AnyRevision {
            return version::same_but_revision(candidate, wanted);
        }
        let Some(order) = version::compare(candidate, wanted) else {
            // A candidate whose version this format does not define cannot be
            // held to an ordering, so it does not answer an atom that states
            // one. The index is unsigned, so such a version is a thing a mirror
            // can publish rather than an impossibility.
            return false;
        };
        match operator {
            Operator::Less => order == Ordering::Less,
            Operator::AtMost => order != Ordering::Greater,
            Operator::Equal => order == Ordering::Equal,
            Operator::AtLeast => order != Ordering::Less,
            Operator::Greater => order == Ordering::Greater,
            // Both are handled above; naming them keeps the match exhaustive
            // without a wildcard that would swallow a variant added later.
            Operator::EqualPrefix | Operator::AnyRevision => unreachable!(),
        }
    }

    /// Whether `candidate` satisfies the slot part.
    ///
    /// A candidate that states no sub-slot has one all the same: the format
    /// makes it implicitly the slot, and the archive relies on that everywhere.
    /// `dev-db/sqlite` publishes `SLOT: 3` and every dependency on it is
    /// written `:3/3=`; `dev-libs/expat` states no `SLOT` at all — so slot `0`
    /// — and is depended on as `:0/0=`. Reading an absent sub-slot as "no
    /// sub-slot" makes those atoms match nothing, which reads as an archive
    /// whose own packages cannot depend on each other.
    fn slot_matches(&self, candidate: &str) -> bool {
        let (slot, subslot) = match candidate.split_once('/') {
            Some((slot, subslot)) => (slot, subslot),
            None => (candidate, candidate),
        };
        match &self.slot {
            None | Some(SlotDep::Any) => true,
            Some(SlotDep::Slot(wanted)) => slot == wanted,
            Some(SlotDep::SubSlot(wanted, wanted_sub)) => slot == wanted && subslot == wanted_sub,
        }
    }

    /// Whether `candidate` satisfies every USE dependency.
    ///
    /// A flag the candidate knows nothing about is answered by the atom's own
    /// default, and by nothing else: an atom that states none cannot say what
    /// such a candidate is, so the candidate does not match.
    fn use_matches(&self, candidate: &impl Candidate) -> bool {
        self.use_deps
            .iter()
            .all(|dep| match candidate.use_flag(&dep.flag).or(dep.default) {
                Some(held) => held == dep.wanted,
                None => false,
            })
    }
}

/// Which part of an atom a candidate failed.
///
/// Reported so an unsatisfiable atom says which wall was hit rather than only
/// that one was. The four are separated because they call for different
/// answers: a missing name is an archive that does not publish the package, a
/// missing flag is a build nobody produced, and a slot or a version is a
/// request for something the archive has moved past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unmet {
    /// The candidate answers the atom.
    Nothing,
    /// No candidate's version satisfies the operator.
    Version,
    /// No candidate is in the slot the atom names.
    Slot,
    /// No candidate carries the USE flags the atom requires.
    UseFlag,
}

impl Unmet {
    /// How far a candidate got before it failed, greater being further.
    ///
    /// A refusal names the wall the *closest* candidate hit rather than the
    /// first: a package with one build whose version is too low and another
    /// whose USE flags are wrong is better described by the flags, because that
    /// is the constraint a caller can act on.
    pub(super) fn ordinal(self) -> u8 {
        match self {
            Unmet::Version => 0,
            Unmet::Slot => 1,
            Unmet::UseFlag => 2,
            Unmet::Nothing => 3,
        }
    }

    /// How a refusal names this wall, in the sentence "no build ...".
    pub(super) fn describe(self) -> &'static str {
        match self {
            Unmet::Nothing => "answers it",
            Unmet::Version => "has a version the atom admits",
            Unmet::Slot => "is in the slot the atom names",
            Unmet::UseFlag => "carries the USE flags the atom requires",
        }
    }
}

/// Parses one atom, reporting the reason where it is not one.
///
/// The reason is a string rather than an error type, for the reason
/// [`coordinate::check`](super::super::coordinate::check) gives: an atom is not
/// this layer's alone to name a failure of, and the caller wraps the reason in
/// whichever of its own failures the atom arrived through — a caller's install
/// list is a configuration failure, an index record's `RDEPEND` is a document
/// one.
pub(super) fn parse(text: &str) -> Result<Atom, String> {
    let refuse = |reason: &str| Err(format!("the atom {text:?} {reason}"));
    let mut rest = text;

    let blocker = if let Some(after) = rest.strip_prefix("!!") {
        rest = after;
        Some(Blocker::Hard)
    } else if let Some(after) = rest.strip_prefix('!') {
        rest = after;
        Some(Blocker::Soft)
    } else {
        None
    };

    // The `=` of `=cat/pkg-1*` is one character and the `>=` of `>=cat/pkg-1`
    // is two, so the two-character forms are tried first.
    let operator = if let Some(after) = rest.strip_prefix(">=") {
        rest = after;
        Some(Operator::AtLeast)
    } else if let Some(after) = rest.strip_prefix("<=") {
        rest = after;
        Some(Operator::AtMost)
    } else if let Some(after) = rest.strip_prefix('>') {
        rest = after;
        Some(Operator::Greater)
    } else if let Some(after) = rest.strip_prefix('<') {
        rest = after;
        Some(Operator::Less)
    } else if let Some(after) = rest.strip_prefix('=') {
        rest = after;
        Some(Operator::Equal)
    } else if let Some(after) = rest.strip_prefix('~') {
        rest = after;
        Some(Operator::AnyRevision)
    } else {
        None
    };

    // The USE dependencies come off the tail first, then the slot, so what is
    // left is the package and its version and neither bracket nor colon can be
    // mistaken for part of one.
    let mut use_deps = Vec::new();
    if let Some(open) = rest.find('[') {
        let Some(close) = rest.strip_suffix(']') else {
            return refuse("opens a USE dependency that nothing closes");
        };
        for entry in close[open + 1..].split(',') {
            use_deps.push(parse_use_dep(entry).map_err(|reason| {
                format!("the atom {text:?} states a USE dependency that {reason}")
            })?);
        }
        rest = &rest[..open];
    }

    // `::repo` names the repository a package must come from. It is portage's
    // own extension rather than part of the grammar the package manager
    // specification defines, and a binhost index carries none, so it is refused
    // for what it is rather than read as a slot named `:repo`.
    if rest.contains("::") {
        return refuse(
            "names a repository with `::`, which is not part of the atom grammar the package \
             manager specification defines",
        );
    }

    let slot = match rest.split_once(':') {
        Some((before, spec)) => {
            rest = before;
            Some(parse_slot(spec).map_err(|reason| {
                format!("the atom {text:?} states a slot dependency that {reason}")
            })?)
        }
        None => None,
    };

    // A trailing `*` belongs to the `=` operator and to no other, so it is read
    // before the version is split off.
    let mut operator = operator;
    if let Some(before) = rest.strip_suffix('*') {
        if operator != Some(Operator::Equal) {
            return refuse("ends in `*`, which only the `=` operator takes");
        }
        operator = Some(Operator::EqualPrefix);
        rest = before;
    }

    let (name, version) = match operator {
        // An operator states a version, so the remainder is a whole `CPV` and
        // the version is what follows the package name.
        Some(_) => match version::split_cpv(rest) {
            Some((category, package, version)) => {
                (format!("{category}/{package}"), Some(version.to_string()))
            }
            None => return refuse("carries a version operator but names no version"),
        },
        None => (rest.to_string(), None),
    };
    if !is_package(&name) {
        return refuse("does not name a package as `category/name`");
    }
    Ok(Atom {
        text: text.to_string(),
        blocker,
        operator,
        name,
        version,
        slot,
        use_deps,
    })
}

/// Parses one `[flag]` entry.
fn parse_use_dep(entry: &str) -> Result<UseDep, String> {
    let mut rest = entry;
    // `!flag=` and `flag?` are the conditional forms, which state what to do
    // with the *dependent's* own flag. They cannot appear in a USE-evaluated
    // index, and this layer has no profile to evaluate them against, so they
    // are refused rather than read as something they are not.
    if rest.ends_with('=') || rest.ends_with('?') {
        return Err(format!(
            "{entry:?} is a conditional form, which needs a profile's own USE and which a \
             USE-evaluated index does not publish",
        ));
    }
    let default = if let Some(before) = rest.strip_suffix("(+)") {
        rest = before;
        Some(true)
    } else if let Some(before) = rest.strip_suffix("(-)") {
        rest = before;
        Some(false)
    } else {
        None
    };
    let wanted = match rest.strip_prefix('-') {
        Some(after) => {
            rest = after;
            false
        }
        None => true,
    };
    if !is_flag(rest) {
        return Err(format!("{entry:?} does not name a USE flag"));
    }
    Ok(UseDep {
        flag: rest.to_string(),
        wanted,
        default,
    })
}

/// Parses the part after the `:` of a slot dependency.
fn parse_slot(spec: &str) -> Result<SlotDep, String> {
    // `:=` and `:*` say "any slot"; `:name=` says "this slot, and rebuild me
    // when its sub-slot moves", which is this slot as far as an install goes.
    let spec = match spec {
        "*" | "=" => return Ok(SlotDep::Any),
        _ => spec.strip_suffix('=').unwrap_or(spec),
    };
    let (slot, subslot) = match spec.split_once('/') {
        Some((slot, subslot)) => (slot, Some(subslot)),
        None => (spec, None),
    };
    if !is_name(slot) {
        return Err(format!("{spec:?} does not name a slot"));
    }
    match subslot {
        Some(subslot) if !is_name(subslot) => Err(format!("{spec:?} does not name a sub-slot")),
        Some(subslot) => Ok(SlotDep::SubSlot(slot.to_string(), subslot.to_string())),
        None => Ok(SlotDep::Slot(slot.to_string())),
    }
}

/// Whether `text` is `category/name` with both parts spelled as the package
/// manager specification allows.
///
/// The check is what stands between an index record and a URL: the package name
/// becomes two path segments of a fetch, and a name carrying a separator or a
/// traversal would name a directory other than the archive's.
pub(super) fn is_package(text: &str) -> bool {
    let Some((category, name)) = text.split_once('/') else {
        return false;
    };
    is_name(category) && is_package_name(name)
}

/// Whether `text` is a category name or a slot name.
///
/// The specification gives the two one rule: letters, digits, `+`, `_`, `.` and
/// `-`, with no name beginning with `-`, `.` or `+`. The first-character rule is
/// what keeps a category from being `.`, `..`, or a hidden entry.
fn is_name(text: &str) -> bool {
    let Some(first) = text.bytes().next() else {
        return false;
    };
    !matches!(first, b'-' | b'.' | b'+')
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'_' | b'.' | b'-'))
}

/// Whether `text` is a package name.
///
/// The specification's rule for one is [`is_name`]'s without the dot.
///
/// It also forbids a name that ends in a hyphen followed by something that
/// parses as a version, which is the rule that makes a `CPV` split
/// unambiguously and is what [`version::split_cpv`] rests on. The rule earns its
/// place here rather than only there: without it a versionless atom spelled
/// `dev-vcs/git-2.54.0` would be read as naming a package called `git-2.54.0`,
/// and the resolver would report an archive that does not publish it instead of
/// an atom that is not one.
fn is_package_name(text: &str) -> bool {
    is_name(text) && !text.contains('.') && version::version_hyphen(text).is_none()
}

/// Whether `text` is a USE flag's name.
///
/// The specification allows letters, digits, `+`, `_`, `@` and `-`, and
/// requires the first character to be a letter or a digit.
///
/// Reachable from the rest of the layer because a flag's name is spelled in more
/// than one place -- an atom's USE dependency and a caller's build preference —
/// and the two must admit the same names: a preference naming a flag an atom
/// could not name would silently never be met.
pub(super) fn is_flag(text: &str) -> bool {
    text.bytes()
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && text.bytes().all(is_flag_byte)
}

/// Whether `byte` may appear in a USE flag's name, at any position but the
/// first. [`is_flag`] is the whole rule.
fn is_flag_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'_' | b'-' | b'@')
}

/// Whether the space-separated USE list `flags` holds `flag`.
///
/// Both sides of resolution spell their flags this way — an index record's
/// `USE`, a database entry's — and both are asked only membership and a count,
/// so the list stays the string its source published and the questions are asked
/// over it.
pub(super) fn holds(flags: &str, flag: &str) -> bool {
    flags.split_ascii_whitespace().any(|held| held == flag)
}

/// Whether the space-separated `iuse` list declares `flag`, whether or not it is
/// enabled.
///
/// The `+` and `-` prefixes an entry may carry state the ebuild's own default
/// and are not part of the name, so they are stripped here.
pub(super) fn declares(iuse: &str, flag: &str) -> bool {
    iuse.split_ascii_whitespace()
        .any(|held| held.trim_start_matches(['+', '-']) == flag)
}

/// What a candidate holding these two flag lists answers for `flag`: enabled,
/// disabled, or unknown.
///
/// The one rule both sides of resolution answer by, and it has to be one: an
/// atom is one grammar, and a root that answered a USE dependency differently
/// from the archive would reinstall what it already has.
///
/// **Enabled beats known.** A build's `USE` carries flags its `IUSE` does not —
/// `amd64`, `elibc_glibc` and `kernel_linux` are in every index record's `USE`
/// and in no package's `IUSE` — so asking the declared list first would report
/// an enabled flag as unknown and hand the answer to the atom's own
/// `(+)`/`(-)` default.
///
/// `None` is the common case rather than an edge, and it is what those defaults
/// exist to answer: a package's declared list names the flags it was written
/// with, and an atom routinely asks about one another package defines.
pub(super) fn use_flag(flags: &str, iuse: &str, flag: &str) -> Option<bool> {
    if holds(flags, flag) {
        Some(true)
    } else if declares(iuse, flag) {
        Some(false)
    } else {
        None
    }
}

/// One dependency in a class: a plain atom, or an any-of group of
/// alternatives.
///
/// The index publishes no other shape. It is USE-evaluated, so no conditional
/// group survives into it, and `RDEPEND`/`PDEPEND` were confirmed over the
/// whole index to carry none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Dependency {
    /// One atom, which must be satisfied.
    One(Atom),
    /// `|| ( a ( b c ) )`: any one alternative satisfies it, and an alternative
    /// is satisfied when every atom in it is — `a` alone, or `b` and `c`
    /// together.
    ///
    /// Never empty, and no alternative is empty: a group with nothing in it, or
    /// with an alternative that has nothing in it, asks for nothing and is
    /// dropped where it is parsed. A resolver reading one of these has an
    /// alternative to consider, and each alternative names an atom.
    ///
    /// A group nested inside another of its own kind is flattened away by the
    /// parser, since it means the same as its contents spliced in. An all-of
    /// group inside this one is an alternative of its own, and an any-of group
    /// inside that is refused; see [`parse_any_of`].
    AnyOf(Vec<Vec<Atom>>),
}

impl Dependency {
    /// How many atoms it names, across every alternative of a group.
    pub(super) fn atoms(&self) -> usize {
        match self {
            Dependency::One(_) => 1,
            Dependency::AnyOf(alternatives) => alternatives.iter().map(Vec::len).sum(),
        }
    }
}

/// How deeply one group may nest inside others in a dependency class.
///
/// The index is USE-evaluated, so the conditionals that would nest one group in
/// another are gone by the time it is written: no `RDEPEND` or `PDEPEND` in the
/// live index nests deeper than two, an all-of inside an any-of. The bound is
/// far above that and far below the depth at which the parser's recursion would
/// exhaust the stack. Nothing signs the index, and a stack overflow aborts the
/// process rather than returning a failure: without the bound, forty kilobytes
/// of parentheses in one stanza are enough to take down whatever embeds this
/// crate.
const MAX_GROUP_DEPTH: usize = 16;

/// Parses a whole dependency class — an `RDEPEND` or a `PDEPEND` value.
///
/// # Errors
///
/// Returns the reason where a token is not an atom, where an `||` is not
/// followed by a group, where the parentheses do not balance, where an all-of
/// group holds an `||` group, or where groups nest more than
/// [`MAX_GROUP_DEPTH`] deep.
pub(super) fn parse_class(text: &str) -> Result<Vec<Dependency>, String> {
    let mut tokens = text.split_ascii_whitespace();
    let mut out = Vec::new();
    while let Some(token) = tokens.next() {
        match token {
            "||" => {
                if tokens.next() != Some("(") {
                    return Err("an `||` is not followed by a group".to_string());
                }
                // A group that asks for nothing is dropped, exactly as the
                // empty all-of group below is: that arm splices its contents,
                // and an empty one contributes none. Kept, it would reach the
                // resolver as a dependency with no alternative to try, refusing
                // the whole run over an atom with no name in the message.
                //
                // The index is USE-evaluated, so a group whose every
                // alternative was conditioned out is how an empty one arrives.
                if let Some(alternatives) = parse_any_of(&mut tokens, 1)? {
                    out.push(Dependency::AnyOf(alternatives));
                }
            }
            // A bare group with no operator is an all-of group, which means
            // the same as its contents written out, so it is spliced in.
            "(" => {
                for atom in parse_all_of(&mut tokens, 1)? {
                    out.push(Dependency::One(atom));
                }
            }
            ")" => return Err("a group is closed that nothing opened".to_string()),
            _ => out.push(Dependency::One(parse(token)?)),
        }
    }
    Ok(out)
}

/// Reads the alternatives of an `|| ( ... )` group up to its closing
/// parenthesis, or `None` where the group asks for nothing.
///
/// A group nested inside it keeps the meaning the archive wrote:
///
/// - `|| ( a || ( b c ) )` — an any-of inside an any-of. Its alternatives are
///   spliced in, which is exact: either way any one of `a`, `b` and `c` is
///   enough.
/// - `|| ( a ( b c ) )` — an all-of inside an any-of. It is one alternative,
///   `b` and `c` together. Splicing it would offer `b` alone, which satisfies
///   the group and leaves `c` uninstalled although nothing asked for less than
///   both.
/// - `|| ( a ( b || ( c d ) ) )` — an any-of inside that all-of. Refused, as
///   [`parse_all_of`] refuses one anywhere.
///
/// Of these shapes the index publishes the second, and rarely, in two of its
/// `RDEPEND`s: `virtual/zlib` offers `sys-libs/zlib`, or `zlib-ng` and
/// `minizip-ng` together, and `media-gfx/evoluspencil` offers `at-spi2-core`, or
/// `at-spi2-atk` and `atk` together. The index is USE-evaluated, so the
/// conditionals that would produce the third are gone by the time it is
/// written.
///
/// A group with no alternatives asks for nothing, and so does one holding an
/// alternative with nothing in it: an empty all-of is satisfied by anything,
/// so the group holding it is too.
///
/// `depth` is how many groups are open, this one included, and a group past
/// [`MAX_GROUP_DEPTH`] is refused before anything inside it is read.
fn parse_any_of<'t>(
    tokens: &mut impl Iterator<Item = &'t str>,
    depth: usize,
) -> Result<Option<Vec<Vec<Atom>>>, String> {
    if depth > MAX_GROUP_DEPTH {
        return Err(format!("its groups nest more than {MAX_GROUP_DEPTH} deep"));
    }
    let mut alternatives = Vec::new();
    // Read to the closing parenthesis whatever is found, so the rest of the
    // class is parsed from where this group ends.
    let mut asks_nothing = false;
    loop {
        match tokens.next() {
            None => return Err("a group is opened that nothing closes".to_string()),
            Some(")") => break,
            Some("(") => {
                let together = parse_all_of(tokens, depth + 1)?;
                if together.is_empty() {
                    asks_nothing = true;
                } else {
                    alternatives.push(together);
                }
            }
            Some("||") => {
                if tokens.next() != Some("(") {
                    return Err("an `||` is not followed by a group".to_string());
                }
                match parse_any_of(tokens, depth + 1)? {
                    Some(nested) => alternatives.extend(nested),
                    None => asks_nothing = true,
                }
            }
            Some(token) => alternatives.push(vec![parse(token)?]),
        }
    }
    Ok((!asks_nothing && !alternatives.is_empty()).then_some(alternatives))
}

/// Reads the atoms of an all-of group up to its closing parenthesis.
///
/// An all-of group nested inside it is spliced in, which is exact: both mean
/// everything is required. An any-of group nested inside it is refused. Its
/// meaning, `( a || ( b c ) )` asking for `a` and either of the others, is not
/// a list of atoms all of which are required, and splicing it would make `b` and
/// `c` both required: an unsatisfiable atom manufactured out of a satisfiable
/// one. The index publishes no such shape, and refusing it turns an archive that
/// ever does into a diagnostic rather than a silently different meaning.
///
/// `depth` is counted as [`parse_any_of`] counts it.
fn parse_all_of<'t>(
    tokens: &mut impl Iterator<Item = &'t str>,
    depth: usize,
) -> Result<Vec<Atom>, String> {
    if depth > MAX_GROUP_DEPTH {
        return Err(format!("its groups nest more than {MAX_GROUP_DEPTH} deep"));
    }
    let mut atoms = Vec::new();
    loop {
        match tokens.next() {
            None => return Err("a group is opened that nothing closes".to_string()),
            Some(")") => return Ok(atoms),
            Some("(") => atoms.extend(parse_all_of(tokens, depth + 1)?),
            Some("||") => {
                return Err(
                    "an all-of group holds an `||` group, which cannot be flattened into it"
                        .to_string(),
                );
            }
            Some(token) => atoms.push(parse(token)?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A candidate spelled the way an index record spells itself.
    struct Record {
        name: &'static str,
        version: &'static str,
        slot: &'static str,
        /// The flags the build was compiled with.
        use_flags: &'static [&'static str],
        /// The flags the package knows, whether or not they are enabled.
        iuse: &'static [&'static str],
    }

    impl Candidate for Record {
        fn name(&self) -> &str {
            self.name
        }

        fn version(&self) -> &str {
            self.version
        }

        fn slot(&self) -> &str {
            self.slot
        }

        fn use_flag(&self, flag: &str) -> Option<bool> {
            if self.use_flags.contains(&flag) {
                Some(true)
            } else if self.iuse.contains(&flag) {
                Some(false)
            } else {
                None
            }
        }
    }

    /// A record of `dev-vcs/git` at 2.54.0, slot 0, with `curl` on and
    /// `keyring` known but off.
    fn git() -> Record {
        Record {
            name: "dev-vcs/git",
            version: "2.54.0",
            slot: "0",
            use_flags: &["curl", "perl"],
            iuse: &["curl", "perl", "keyring", "cgi"],
        }
    }

    /// Whether the atom spelled `text` admits `candidate`.
    #[track_caller]
    fn admits(text: &str, candidate: &Record) -> bool {
        parse(text)
            .unwrap_or_else(|reason| panic!("{text:?}: {reason}"))
            .matches(candidate)
    }

    #[test]
    fn a_version_operator_admits_the_versions_it_names() {
        let git = git();
        for text in [
            "dev-vcs/git",
            ">=dev-vcs/git-2.54.0",
            ">=dev-vcs/git-2.0",
            ">dev-vcs/git-2.53.0",
            "<=dev-vcs/git-2.54.0",
            "<dev-vcs/git-2.55.0",
            "=dev-vcs/git-2.54.0",
            "~dev-vcs/git-2.54.0",
            "=dev-vcs/git-2.54*",
        ] {
            assert!(admits(text, &git), "{text} should admit 2.54.0");
        }
        for text in [
            ">dev-vcs/git-2.54.0",
            ">=dev-vcs/git-2.55",
            "<dev-vcs/git-2.54.0",
            "=dev-vcs/git-2.53.0",
            "~dev-vcs/git-2.53.0",
            "=dev-vcs/git-2.53*",
        ] {
            assert!(!admits(text, &git), "{text} should refuse 2.54.0");
        }
    }

    #[test]
    fn the_tilde_operator_admits_any_revision_of_one_version() {
        let revised = Record {
            version: "2.54.0-r2",
            ..git()
        };
        assert!(admits("~dev-vcs/git-2.54.0", &revised));
        assert!(admits("=dev-vcs/git-2.54.0-r2", &revised));
        assert!(!admits("=dev-vcs/git-2.54.0", &revised));
    }

    #[test]
    fn a_slot_dependency_matches_the_slot_and_the_sub_slot() {
        let openssl = Record {
            name: "dev-libs/openssl",
            version: "3.5.4",
            slot: "0/3",
            use_flags: &[],
            iuse: &[],
        };
        for text in [
            "dev-libs/openssl:0",
            "dev-libs/openssl:0/3",
            "dev-libs/openssl:0=",
            "dev-libs/openssl:0/3=",
            "dev-libs/openssl:*",
            "dev-libs/openssl:=",
            "dev-libs/openssl",
        ] {
            assert!(admits(text, &openssl), "{text} should admit 0/3");
        }
        for text in ["dev-libs/openssl:1", "dev-libs/openssl:0/4"] {
            assert!(!admits(text, &openssl), "{text} should refuse 0/3");
        }
        // A record with no sub-slot has one implicitly, and it is the slot.
        // The archive depends on this everywhere: dev-libs/expat states no
        // SLOT at all and every dependency on it is written `:0/0=`.
        let plain = Record {
            slot: "0",
            ..openssl
        };
        assert!(admits("dev-libs/openssl:0", &plain));
        assert!(admits("dev-libs/openssl:0/0", &plain));
        assert!(admits("dev-libs/openssl:0/0=", &plain));
        assert!(!admits("dev-libs/openssl:0/3", &plain));
        let three = Record {
            slot: "3",
            ..openssl
        };
        assert!(admits("dev-libs/openssl:3/3=", &three));
        assert!(!admits("dev-libs/openssl:3/0", &three));
    }

    #[test]
    fn a_use_dependency_reads_the_candidates_own_flags() {
        let git = git();
        assert!(admits("dev-vcs/git[curl]", &git));
        assert!(admits("dev-vcs/git[-keyring]", &git));
        assert!(admits("dev-vcs/git[curl,-keyring,perl]", &git));
        assert!(!admits("dev-vcs/git[keyring]", &git));
        assert!(!admits("dev-vcs/git[-curl]", &git));
    }

    #[test]
    fn the_defaults_decide_a_flag_the_candidate_does_not_know() {
        // The finding the module rests on. `bindist` is in neither the
        // candidate's USE nor its IUSE, so only the atom's default can say
        // what it is -- and an atom with no default cannot say at all.
        let git = git();
        assert!(admits("dev-vcs/git[bindist(+)]", &git), "(+) reads enabled");
        assert!(
            !admits("dev-vcs/git[-bindist(+)]", &git),
            "(+) reads enabled, so -flag fails",
        );
        assert!(
            admits("dev-vcs/git[-bindist(-)]", &git),
            "(-) reads disabled",
        );
        assert!(
            !admits("dev-vcs/git[bindist(-)]", &git),
            "(-) reads disabled, so flag fails",
        );
        assert!(
            !admits("dev-vcs/git[bindist]", &git),
            "no default cannot answer an unknown flag",
        );
        assert!(
            !admits("dev-vcs/git[-bindist]", &git),
            "no default cannot answer an unknown flag, either way",
        );
        // A default never overrides a flag the candidate does know.
        assert!(!admits("dev-vcs/git[keyring(+)]", &git));
        assert!(admits("dev-vcs/git[curl(-)]", &git));
    }

    #[test]
    fn a_blocker_is_parsed_as_one_rather_than_as_part_of_the_name() {
        assert_eq!(
            parse("!sys-apps/systemd").unwrap().blocker(),
            Some(Blocker::Soft)
        );
        assert_eq!(
            parse("!!sys-apps/systemd").unwrap().blocker(),
            Some(Blocker::Hard)
        );
        assert_eq!(parse("sys-apps/systemd").unwrap().blocker(), None);
        // The operator sits between the blocker and the name.
        let atom = parse("!<sys-libs/zlib-1.3").expect("a blocked range");
        assert_eq!(atom.blocker(), Some(Blocker::Soft));
        assert_eq!(atom.name(), "sys-libs/zlib");
    }

    #[test]
    fn an_unmet_atom_names_the_wall_it_hit() {
        let git = git();
        assert_eq!(parse("dev-vcs/git").unwrap().unmet_by(&git), Unmet::Nothing);
        assert_eq!(
            parse(">=dev-vcs/git-3.0").unwrap().unmet_by(&git),
            Unmet::Version,
        );
        assert_eq!(parse("dev-vcs/git:9").unwrap().unmet_by(&git), Unmet::Slot);
        assert_eq!(
            parse("dev-vcs/git[keyring]").unwrap().unmet_by(&git),
            Unmet::UseFlag,
        );
    }

    #[test]
    fn a_shape_the_grammar_does_not_define_is_refused() {
        for text in [
            "",
            "git",
            ">=dev-vcs/git",
            ">dev-vcs/git",
            "dev-vcs/git-2.54.0",
            "dev-vcs/git[",
            "dev-vcs/git[]",
            "dev-vcs/git[curl",
            "dev-vcs/git:",
            "dev-vcs/git:0/",
            ">=dev-vcs/git-2.0*",
            "dev-vcs/git*",
            "../etc/passwd",
            "dev-vcs/../git",
            "dev-vcs/git[curl?]",
            "dev-vcs/git[curl=]",
        ] {
            assert!(parse(text).is_err(), "{text:?} was accepted");
        }
        // A bare atom with no operator carries no version, so a name that
        // looks like a `CPV` is a name.
        assert_eq!(parse("dev-vcs/git").unwrap().name(), "dev-vcs/git");
    }

    #[test]
    fn names_are_held_to_the_rules_the_specification_states_for_each() {
        // A category may carry a dot and a package name may not; neither may
        // begin with the characters each forbids, and neither may a slot.
        for text in [
            "dev-vcs/gi.t",
            "dev-vcs/.git",
            ".dev/git",
            "+dev/git",
            "-dev/git",
            "dev-vcs/+git",
            "dev-vcs/-git",
            "dev-vcs/git:.0",
            "dev-vcs/git:-0",
            "dev-vcs/git:+0",
            "dev-vcs/git:0/.1",
            // A flag begins with a letter or a digit.
            "dev-vcs/git[_curl]",
            "dev-vcs/git[@curl]",
            "dev-vcs/git[-+curl]",
        ] {
            assert!(parse(text).is_err(), "{text:?} was accepted");
        }
        for text in [
            "dev.extra/git",
            "dev-vcs/git_2",
            "dev-vcs/git+",
            "dev-vcs/git:0.1",
            "dev-vcs/git[curl_2,-net@x]",
        ] {
            parse(text).unwrap_or_else(|reason| panic!("{text:?}: {reason}"));
        }
    }

    #[test]
    fn a_repository_dependency_is_refused_for_what_it_is() {
        // `::repo` is portage's own extension. Read as a slot dependency, it
        // would be refused as a slot named `:gentoo`, which names nothing a
        // caller could act on.
        for text in ["dev-vcs/git::gentoo", "dev-vcs/git:0::gentoo"] {
            let reason = parse(text).expect_err("a repository dependency is refused");
            assert!(reason.contains("names a repository"), "{text}: {reason}");
        }
    }

    #[test]
    fn a_glob_matches_at_a_boundary_between_version_parts() {
        let python = |version: &'static str| Record {
            name: "dev-lang/python",
            version,
            slot: "3.1",
            use_flags: &[],
            iuse: &[],
        };
        for version in ["3.1", "3.1.4", "3.1_rc1", "3.1-r2", "3.1a"] {
            assert!(
                admits("=dev-lang/python-3.1*", &python(version)),
                "3.1* should admit {version}",
            );
        }
        // The whole reason for the boundary: 3.12 is not a 3.1.
        for version in ["3.12", "3.10", "3", "3.2", "13.1"] {
            assert!(
                !admits("=dev-lang/python-3.1*", &python(version)),
                "3.1* should refuse {version}",
            );
        }
        // A prefix ending in a letter meets a digit at a boundary too.
        assert!(admits("=dev-lang/python-3.1_rc*", &python("3.1_rc1")));
        assert!(admits("=dev-lang/python-3.1_rc*", &python("3.1_rc")));
        // The first component is compared by value, so its leading zeros are
        // not part of the prefix on either side.
        assert!(admits("=dev-lang/python-3*", &python("03.1")));
        assert!(admits("=dev-lang/python-03*", &python("3.1")));
        assert!(!admits("=dev-lang/python-3*", &python("30.1")));
    }

    /// A class holding one atom inside `depth` all-of groups.
    fn nested(depth: usize) -> String {
        format!("{}a-b/c{}", "( ".repeat(depth), " )".repeat(depth))
    }

    #[test]
    fn groups_nest_as_deep_as_the_bound_and_no_deeper() {
        let at = parse_class(&nested(MAX_GROUP_DEPTH)).expect("a class at the bound");
        assert_eq!(at.len(), 1);
        let past = parse_class(&nested(MAX_GROUP_DEPTH + 1)).expect_err("a class past the bound");
        assert!(past.contains("nest more than"), "{past}");

        // An any-of group counts the same as an all-of one.
        let any_of = |depth: usize| format!("{}a-b/c{}", "|| ( ".repeat(depth), " )".repeat(depth));
        alternatives(&any_of(MAX_GROUP_DEPTH), 1);
        assert!(parse_class(&any_of(MAX_GROUP_DEPTH + 1)).is_err());
    }

    #[test]
    fn a_nest_deep_enough_to_exhaust_the_stack_is_refused_rather_than_followed() {
        // Far past the depth at which an unbounded recursion overflows the
        // stack, which aborts the process instead of returning anything. The
        // bound refuses it before the recursion is more than a few frames deep,
        // so this is as cheap as a class of ordinary length.
        let reason = parse_class(&nested(100_000)).expect_err("the nest is refused");
        assert!(reason.contains("nest more than"), "{reason}");
    }

    #[test]
    fn a_dependency_class_reads_plain_atoms_and_any_of_groups() {
        let parsed = parse_class(
            "dev-libs/openssl:0/3= || ( >=dev-build/autoconf-2.72:2.72 dev-build/autoconf:2.71 ) \
             !sys-libs/zlib-ng[compat]",
        )
        .expect("a class");
        assert_eq!(parsed.len(), 3);
        assert!(matches!(parsed[0], Dependency::One(_)));
        match &parsed[1] {
            Dependency::AnyOf(atoms) => assert_eq!(atoms.len(), 2),
            other => panic!("expected an any-of group, got {other:?}"),
        }
        match &parsed[2] {
            Dependency::One(atom) => assert_eq!(atom.blocker(), Some(Blocker::Soft)),
            other => panic!("expected a blocker, got {other:?}"),
        }
        // An all-of group is spliced in rather than kept as a shape of its own.
        let flat = parse_class("( a-b/c d-e/f )").expect("an all-of group");
        assert_eq!(flat.len(), 2);
        assert!(flat.iter().all(|dep| matches!(dep, Dependency::One(_))));
        // Unbalanced parentheses are refused rather than half-read.
        assert!(parse_class("|| ( a-b/c").is_err());
        assert!(parse_class("a-b/c )").is_err());
        assert!(parse_class("|| a-b/c").is_err());
        // An empty class is no dependencies rather than a failure.
        assert!(parse_class("").expect("an empty class").is_empty());
        // So is a group with nothing in it, of either kind: it asks for
        // nothing. An empty any-of kept as a dependency has no alternative for
        // the resolver to try, so it refuses the whole run over an atom with no
        // name -- and the index is USE-evaluated, so a group whose every
        // alternative was conditioned out is how one arrives.
        assert!(parse_class("|| ( )").expect("an empty any-of").is_empty());
        assert!(parse_class("( )").expect("an empty all-of").is_empty());
        let with_empty = parse_class("a-b/c || ( ) d-e/f").expect("a class holding an empty group");
        assert_eq!(with_empty.len(), 2);
        assert!(
            with_empty
                .iter()
                .all(|dep| matches!(dep, Dependency::One(_)))
        );
    }

    /// Asserts that `class` reads as one any-of group offering `count`
    /// alternatives.
    #[track_caller]
    fn alternatives(class: &str, count: usize) {
        assert_eq!(any_of(class).len(), count, "{class}");
    }

    /// The alternatives of the any-of group `class` reads as, each the names of
    /// the atoms it requires together.
    #[track_caller]
    fn any_of(class: &str) -> Vec<Vec<String>> {
        match &parse_class(class).expect("a class")[..] {
            [Dependency::AnyOf(alternatives)] => alternatives
                .iter()
                .map(|together| {
                    together
                        .iter()
                        .map(|atom| atom.name().to_string())
                        .collect()
                })
                .collect(),
            other => panic!("expected one any-of group from {class}, got {other:?}"),
        }
    }

    #[test]
    fn a_nested_group_keeps_the_meaning_the_archive_wrote() {
        // A group inside one of its own kind means its contents written out, so
        // both directions of that are flattened and neither changes meaning.
        let all_of = parse_class("( a-b/c ( d-e/f g-h/i ) )").expect("an all-of in an all-of");
        assert_eq!(all_of.len(), 3);
        assert!(all_of.iter().all(|dep| matches!(dep, Dependency::One(_))));
        alternatives("|| ( a-b/c || ( d-e/f g-h/i ) )", 3);

        // An all-of inside an any-of is one alternative: `a`, or `d` and `g`
        // together. Flattened it would offer `d` alone, which satisfies the
        // group and leaves `g` uninstalled.
        assert_eq!(
            any_of("|| ( a-b/c ( d-e/f g-h/i ) )"),
            [vec!["a-b/c"], vec!["d-e/f", "g-h/i"]],
        );
        // The shape the live index publishes, for `virtual/zlib`: the
        // compatibility build of zlib-ng answers only together with
        // minizip-ng's.
        assert_eq!(
            any_of(
                "|| ( >=sys-libs/zlib-1.3.1[abi_x86_64(-),minizip] \
                 ( sys-libs/zlib-ng[abi_x86_64(-),compat] \
                 sys-libs/minizip-ng[abi_x86_64(-),compat] ) )",
            ),
            [
                vec!["sys-libs/zlib"],
                vec!["sys-libs/zlib-ng", "sys-libs/minizip-ng"],
            ],
        );
        // An all-of inside that alternative is spliced into it, and an any-of
        // inside the all-of is refused there too.
        assert_eq!(
            any_of("|| ( a-b/c ( d-e/f ( g-h/i ) ) )"),
            [vec!["a-b/c"], vec!["d-e/f", "g-h/i"]],
        );
        assert!(parse_class("|| ( a-b/c ( d-e/f || ( g-h/i j-k/l ) ) )").is_err());

        // An any-of inside an all-of would tighten -- both required where the
        // archive asked for either -- which manufactures an unsatisfiable atom
        // out of a satisfiable one. Refused, so an archive that ever publishes
        // the shape is a diagnostic rather than a different meaning.
        let refused = parse_class("( a-b/c || ( d-e/f g-h/i ) )")
            .expect_err("an `||` inside an all-of group is refused");
        assert!(
            refused.contains("all-of group holds an `||` group"),
            "{refused}"
        );
    }

    #[test]
    fn an_any_of_group_holding_an_alternative_that_asks_for_nothing_asks_for_nothing() {
        // An empty all-of is satisfied by anything, so a group offering one is
        // satisfied too, and an empty any-of nested in another is the same.
        // Dropping only the empty alternative would turn `a` from one choice
        // among two into a requirement.
        for class in ["|| ( a-b/c ( ) )", "|| ( a-b/c || ( ) )", "|| ( ( ) )"] {
            assert!(parse_class(class).expect("a class").is_empty(), "{class}");
        }
        // Read to its end all the same, so what follows it is still read.
        let after = parse_class("|| ( ( ) a-b/c ) d-e/f").expect("a class");
        assert_eq!(after.len(), 1);
        assert!(matches!(&after[0], Dependency::One(atom) if atom.name() == "d-e/f"));
    }
}
