//! `APKINDEX`: the flat, line-prefixed catalogue a repository publishes.
//!
//! The whole grammar is a blank line between records and, within one, a single
//! letter, a colon, and a value:
//!
//! ```text
//! C:Q1LSohzMjVRmn08215M0mwFPRtsg8=
//! P:7zip
//! V:25.01-r0
//! A:x86_64
//! D:so:libc.musl-x86_64.so.1 so:libstdc++.so.6
//! p:7zip-virtual p7zip=25.01-r0 cmd:7z=25.01-r0
//! ```
//!
//! There is no continuation syntax, no folded field, and no comment, so a line
//! that is not `X:value` is a malformed index rather than something to skip. A
//! *letter* this reader does not know is another matter: apk may define one, and
//! an index carrying it is still the index this reader can use, so unknown
//! letters are ignored and unknown syntax is refused.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;

use super::AlpineError;
use super::pin::{Fit, Pins};
use super::sign::IDENTITY_PREFIX;
use super::version::{self, Constraint};
use crate::provision::Available;

/// The architecture value a package carries when it belongs to every
/// architecture the repository serves: in an index's `A:`, a `.PKGINFO`'s
/// `arch`, and a plan's `Architecture`.
pub(super) const NOARCH: &str = "noarch";

/// The length of a `C:` value: [`IDENTITY_PREFIX`] and the base64 of twenty
/// bytes.
const IDENTITY_LENGTH: usize = IDENTITY_PREFIX.len() + 28;

/// One package's record, as much of it as the reader has a use for.
#[derive(Debug, Clone)]
pub(super) struct Record {
    /// `P:`, the package name, checked to be one a URL can carry.
    pub(super) name: String,
    /// `V:`, the version, which has been checked to parse.
    pub(super) version: String,
    /// `A:`, the architecture, or [`NOARCH`].
    pub(super) architecture: String,
    /// `C:`, the identity of the package's control segment: `Q1` and the base64
    /// of its SHA-1. This is the link that binds a package to the index that
    /// named it.
    pub(super) control_identity: String,
    /// `S:`, the size of the `.apk` on the wire, when the record states a
    /// usable one. It bounds what a download may spend before its digest is
    /// checked.
    pub(super) size: Option<u64>,
    /// `I:`, the archive's estimate of the space the package occupies once
    /// installed, in bytes.
    pub(super) installed_size: Option<u64>,
    /// `o:`, the source package this one was built from, when it differs from
    /// the name.
    pub(super) origin: Option<String>,
    /// `D:`, what this package needs, including what it refuses.
    pub(super) depends: Vec<Dependency>,
    /// `p:`, the names this package provides, each with the version it provides
    /// them at when it states one.
    pub(super) provides: Vec<Provided>,
    /// `i:`, the conditions under which this package installs itself.
    pub(super) install_if: Vec<Dependency>,
    /// `k:`, the priority that ranks this package against another providing the
    /// same name, and the flag that makes an unversioned `p:` entry selectable
    /// at all.
    ///
    /// Only ever *greater than zero*. `apk` declines to choose between a
    /// provider that states `k:0` and one that states no `k:` at all, exactly as
    /// it declines between two that state none, so the two are one case and are
    /// held as one value here rather than being told apart and then treated
    /// alike everywhere downstream.
    pub(super) provider_priority: Option<u32>,
    /// Which of the caller's indexes this record was retained from, so a
    /// package is fetched from the repository that published it.
    pub(super) from: usize,
}

/// One entry of a `D:` or `i:` field: a name, what it accepts, and whether it
/// is a refusal rather than a requirement.
#[derive(Debug, Clone)]
pub(super) struct Dependency {
    /// The name required, which may be a real package or a provided one.
    pub(super) name: String,
    /// What the entry accepts, or `None` where it accepts any version.
    pub(super) constraint: Option<Constraint>,
    /// Whether a leading `!` made this a refusal.
    ///
    /// A refusal is the negation of the requirement rather than a bare "this
    /// package must be absent": `!alsa-lib<1.2.14-r2` together with
    /// `!alsa-lib>1.2.14-r2` is how a package says it needs exactly that
    /// version, and both are satisfied when `alsa-lib` is present at it.
    pub(super) conflict: bool,
}

impl Dependency {
    /// Whether a candidate offering `version` is one this entry accepts,
    /// leaving [`conflict`](Self::conflict) to the caller.
    ///
    /// `None` is a candidate that offers no version at all, which is a `p:`
    /// entry with no `=`. Such a candidate satisfies an unconstrained entry and
    /// no constrained one: there is no version to compare, so a mirror could
    /// otherwise satisfy `python3>=3.12` with a package that merely says
    /// `provides = python3`.
    pub(super) fn accepts(&self, version: Option<&str>) -> bool {
        match (&self.constraint, version) {
            (None, _) => true,
            (Some(constraint), Some(version)) => constraint.satisfied_by(version),
            (Some(_), None) => false,
        }
    }

    /// Parses one whitespace-separated entry of a `D:` or `i:` field.
    ///
    /// Also of `.PKGINFO`'s `replaces`, which is the same grammar: an entry
    /// there may carry a version, and reading it as a bare name would widen
    /// which packages a file may be taken from.
    pub(super) fn parse(entry: &str) -> Result<Dependency, String> {
        let (text, conflict) = match entry.strip_prefix('!') {
            Some(rest) => (rest, true),
            None => (entry, false),
        };
        let (name, constraint) = version::split(text)?;
        if name.is_empty() {
            // The entry as it was written rather than what is left after the
            // `!`, so a bare `!` is quoted as itself and not as an empty string.
            return Err(format!("{entry:?} names no package"));
        }
        Ok(Dependency {
            name: name.to_string(),
            constraint,
            conflict,
        })
    }
}

impl fmt::Display for Dependency {
    /// Writes the entry as an index spells it, for the refusals that quote one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.conflict {
            f.write_str("!")?;
        }
        f.write_str(&self.name)?;
        match &self.constraint {
            Some(constraint) => write!(f, "{constraint}"),
            None => Ok(()),
        }
    }
}

/// One entry of a `p:` field: a name this package provides, and the version it
/// provides it at.
#[derive(Debug, Clone)]
pub(super) struct Provided {
    /// The name provided. It need not look like a package name — `so:` and
    /// `cmd:` namespaces, bare paths such as `/bin/sh`, and `cmd:[` are all
    /// published — so it is never used as anything but a key.
    pub(super) name: String,
    /// The version stated after an `=`, when the entry states one.
    pub(super) version: Option<String>,
}

impl Provided {
    /// Parses one whitespace-separated entry of a `p:` field.
    fn parse(text: &str) -> Result<Provided, String> {
        let (name, constraint) = version::split(text)?;
        if name.is_empty() {
            return Err(format!("{text:?} names nothing"));
        }
        let version = match constraint {
            None => None,
            // An entry states a version by equality and no other way. Anything
            // else is a comparison, and a provided name that is only *greater
            // than* something has no version for a constraint to be checked
            // against.
            Some(constraint) => Some(
                constraint
                    .exact_version()
                    .ok_or_else(|| {
                        format!("{text:?} provides a name at a comparison rather than a version")
                    })?
                    .to_string(),
            ),
        };
        Ok(Provided {
            name: name.to_string(),
            version,
        })
    }
}

/// Parses one whitespace-separated list field, entry by entry.
///
/// One entry the format does not define refuses the whole index rather than
/// being skipped: a dependency that cannot be read is one the closure would
/// silently omit, and a `p:` entry that cannot be read is a name something else
/// may be relying on.
fn list<T>(value: Option<&str>, parse: fn(&str) -> Result<T, String>) -> Result<Vec<T>, String> {
    value
        .unwrap_or_default()
        .split_ascii_whitespace()
        .map(parse)
        .collect()
}

/// Whether `name` is a package name that can be addressed.
///
/// This is deliberately not [`coordinate::check`](super::super::coordinate),
/// and the difference is where the value came from. A release, a component and
/// an architecture are the *caller's*, and are checked for the shape a path and
/// an index field can carry. A package name arrives from the mirror, and goes on
/// to become a path segment of the URL its `.apk` is fetched from and a word of
/// the records this layer writes into the finished rootfs — so it is held to the
/// character set apk names are drawn from rather than merely to a safe shape,
/// which leaves nothing that could end a request line, start a query, or name a
/// directory other than itself.
///
/// A plan document is held to this too, in [`PlannedPackage::unaddressable`](super::plan::PlannedPackage::unaddressable):
/// a plan reaches the same URL and the same cache path without passing an index.
pub(super) fn is_package_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['-', '.'])
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

/// Whether `value` has the shape of a `C:` field: [`IDENTITY_PREFIX`] and the
/// base64 of a SHA-1.
///
/// The value is recomputed and compared when a package is fetched, and written
/// into a plan document meanwhile, so a record carrying anything else is
/// malformed rather than merely unfamiliar. A plan document is held to this
/// too, in [`PlannedPackage::unaddressable`](super::plan::PlannedPackage::unaddressable).
///
/// The padding is where it has to be rather than merely allowed: twenty bytes
/// of base64 is twenty-seven alphabet characters and exactly one `=`, so a value
/// with padding anywhere else is one [`sign::identity`](super::sign) can never
/// render. Admitting it would put the refusal in the wrong place — a fetch-time
/// digest mismatch, worded as a mirror serving something else, for an index that
/// was malformed before anything was fetched.
///
/// The whole index is refused rather than the record dropped, which is stricter
/// than `apk`: `apk.static` silently skips a record whose `C:` will not decode
/// and uses the rest of the index. A mirror that
/// serves a malformed record has served something this reader cannot account
/// for, and a root assembled from the remainder would be missing whatever that
/// record named, without saying so.
pub(super) fn is_control_identity(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix(IDENTITY_PREFIX) else {
        return false;
    };
    let Some(digest) = encoded.strip_suffix('=') else {
        return false;
    };
    value.len() == IDENTITY_LENGTH
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

/// Parses an `APKINDEX` into its records.
///
/// `subject` names the index, for the errors — the URL it came from.
///
/// # Errors
///
/// Returns [`AlpineError::Index`] for a line that is not `X:value`, a record
/// carrying a letter twice, a record without a name, version and architecture,
/// or a version the format does not define. None of these occurs in a published
/// index; all of them are what a mirror serving something else looks like, and a
/// version that cannot be ordered is one that cannot be merged safely.
pub(super) fn parse(subject: &str, text: &str, from: usize) -> Result<Vec<Record>, AlpineError> {
    parse_records(text, from).map_err(|reason| AlpineError::index(subject, reason))
}

/// The body of [`parse`], reporting a reason rather than an error.
///
/// The split is what lets a base layer's `installed` database be read through
/// this same grammar: an installed record opens with exactly the fields an index
/// record carries, but a database is not an index, and a refusal that called it
/// one would name the wrong thing.
///
/// A letter repeated within one record is refused through a set of the letters
/// that record has carried. Unknown letters are admitted, and a letter is any
/// character, so one record can carry as many letters as it has lines. A base
/// layer's `installed` header reaches here from a tree its own scripts wrote,
/// and a walk of the record's fields for every line would make such a header
/// cost the square of its length.
pub(super) fn parse_records(text: &str, from: usize) -> Result<Vec<Record>, String> {
    let mut records = Vec::new();
    let mut fields: Vec<(char, &str)> = Vec::new();
    let mut letters: HashSet<char> = HashSet::new();
    for (number, line) in text.lines().enumerate() {
        if line.is_empty() {
            if let Some(record) = record(&fields, number, from)? {
                records.push(record);
            }
            fields.clear();
            letters.clear();
            continue;
        }
        let mut characters = line.chars();
        let (Some(key), Some(':')) = (characters.next(), characters.next()) else {
            return Err(format!("line {} is not a field: {line:?}", number + 1));
        };
        if !letters.insert(key) {
            return Err(format!(
                "the record ending at line {} carries {key}: twice",
                number + 1
            ));
        }
        fields.push((key, &line[key.len_utf8() + 1..]));
    }
    // A final record needs no blank line after it, and an index that ends with
    // one has nothing left in hand.
    if let Some(record) = record(&fields, text.lines().count(), from)? {
        records.push(record);
    }
    Ok(records)
}

/// Assembles one record from the fields read for it, or `None` where there were
/// none — the blank line between two records, or a trailing one.
///
/// `line` is where the record ended, for the errors.
fn record(fields: &[(char, &str)], line: usize, from: usize) -> Result<Option<Record>, String> {
    if fields.is_empty() {
        return Ok(None);
    }
    let value = |key: char| {
        fields
            .iter()
            .find(|(seen, _)| *seen == key)
            .map(|(_, value)| *value)
    };
    let required = |key: char, what: &str| {
        value(key)
            .ok_or_else(|| format!("the record ending at line {line} names no {what} ({key}:)"))
    };

    let name = required('P', "package")?;
    let version = required('V', "version")?;
    let architecture = required('A', "architecture")?;
    let control_identity = required('C', "control identity")?;
    let malformed = |reason: String| format!("{name}: {reason}");

    if !is_package_name(name) {
        return Err(malformed(format!(
            "{name:?} is not a name a package can be addressed by",
        )));
    }
    if version::parse(version).is_none() {
        return Err(malformed(format!(
            "it carries {version:?}, which is not a version this format defines",
        )));
    }
    if !is_control_identity(control_identity) {
        return Err(malformed(format!(
            "its control identity {control_identity:?} is not a {IDENTITY_PREFIX} digest",
        )));
    }

    Ok(Some(Record {
        name: name.to_string(),
        version: version.to_string(),
        architecture: architecture.to_string(),
        control_identity: control_identity.to_string(),
        // A record that states no size, or one that does not parse, leaves the
        // download bounded by the fetcher's own ceiling rather than being
        // dropped: the digest is what decides whether the bytes are the package,
        // and a missing bound is a weaker fetch rather than a wrong one.
        size: value('S').and_then(|value| value.parse().ok()),
        installed_size: value('I').and_then(|value| value.parse().ok()),
        // Stated by every published record, and equal to the name for most of
        // them; kept only where it says something the name does not.
        origin: value('o')
            .filter(|origin| *origin != name)
            .map(str::to_string),
        depends: list(value('D'), Dependency::parse).map_err(malformed)?,
        provides: list(value('p'), Provided::parse).map_err(malformed)?,
        install_if: list(value('i'), Dependency::parse).map_err(malformed)?,
        // A `k:` that is not a number greater than zero is no priority, which is
        // `apk`'s own reading rather than a lenient one: `apk.static` 3.0.7
        // refuses to choose between a provider stating `k:0`, `k:-1` or
        // `k:abc` and one stating no `k:` at all, and picks a `k:1` provider
        // over it. It keeps the record either way, so refusing one here would
        // refuse an index apk itself reads.
        provider_priority: value('k')
            .and_then(|value| value.parse().ok())
            .filter(|priority| *priority > 0),
        from,
    }))
}

/// The package set of one or more repositories, merged: one record per name,
/// plus each provided name's providers.
pub(super) struct Index {
    by_name: HashMap<String, Record>,
    providers: HashMap<String, Vec<String>>,
    /// The pin the index was merged under, which chose each pinned name's
    /// record.
    pins: Pins,
}

impl fmt::Debug for Index {
    /// Reports how much was merged rather than what. A merged Alpine
    /// `main`+`community` is around 25,000 records, which no reader of a
    /// rendering can act on.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Index")
            .field("packages", &self.by_name.len())
            .field("virtual_names", &self.providers.len())
            .finish()
    }
}

impl Index {
    /// Merges each repository's records into one set, keeping the highest
    /// version of each name and dropping what the architecture does not serve.
    ///
    /// `inputs` are the repositories' record lists in the order the caller
    /// configured them, and that order decides an exact tie: a later repository
    /// shadows an earlier one at *equal* version. This is what makes a
    /// repository an overlay — a postmarketOS root is Alpine's repositories plus
    /// postmarketOS's, and a package it republishes at the same version is the
    /// one that must win. A higher version wins wherever it comes from, so the
    /// ordering never installs an older package than the archives offer.
    ///
    /// A record whose architecture is neither `architecture` nor [`NOARCH`] is
    /// dropped. An index is published per architecture, so this only ever fires
    /// for a mirror serving something other than what its path says.
    ///
    /// `pins` overrides the choice for the names it holds: a pinned name selects
    /// the pinned version wherever it is offered, and the pinned control segment
    /// over another copy of that version, by [`Pins::fit`]. It keeps the highest
    /// version where the pinned one is not offered, so [`Pins::check`] can report
    /// what the repositories carry instead of only that the pin failed.
    pub(super) fn merge(
        inputs: impl IntoIterator<Item = Vec<Record>>,
        architecture: &str,
        pins: &Pins,
    ) -> Index {
        let mut by_name: HashMap<String, Record> = HashMap::new();
        for records in inputs {
            for record in records {
                if record.architecture != architecture && record.architecture != NOARCH {
                    continue;
                }
                // A version that does not order never displaces one that does.
                // Every record here parsed, so this is unreachable rather than a
                // policy; stating it as one keeps the unreachable case from
                // silently becoming "shadow it".
                let not_lower = |candidate: &Record, existing: &Record| {
                    version::compare(&candidate.version, &existing.version)
                        .is_some_and(|order| order != Ordering::Less)
                };
                let keep = match by_name.get(&record.name) {
                    None => true,
                    // The candidate that fits the pin better wins. One that fits
                    // it as well as an earlier one also wins, which is the
                    // overlay rule again, and where this differs from the Debian
                    // layer's pin: there a satisfied pin is never displaced,
                    // because there a later repository does not shadow at equal
                    // version. Where neither holds the pinned version, the
                    // highest is kept as for any other name.
                    Some(existing) if pins.names(&record.name) => {
                        let fit = |candidate: &Record| {
                            pins.fit(
                                &candidate.name,
                                &candidate.version,
                                &candidate.control_identity,
                            )
                        };
                        match fit(&record).cmp(&fit(existing)) {
                            Ordering::Greater => true,
                            Ordering::Less => false,
                            Ordering::Equal => {
                                fit(&record) != Fit::Neither || not_lower(&record, existing)
                            }
                        }
                    }
                    Some(existing) => not_lower(&record, existing),
                };
                if keep {
                    by_name.insert(record.name.clone(), record);
                }
            }
        }

        let mut providers: HashMap<String, Vec<String>> = HashMap::new();
        for record in by_name.values() {
            for provided in &record.provides {
                providers
                    .entry(provided.name.clone())
                    .or_default()
                    .push(record.name.clone());
            }
        }
        // The lists are built by iterating a HashMap, so their order is not
        // reproducible; a resolution that picks among providers must be, so
        // each is sorted into a stable one.
        for names in providers.values_mut() {
            names.sort();
        }

        Index {
            by_name,
            providers,
            pins: pins.clone(),
        }
    }

    /// The pin the index was merged under, for the resolver to hold a
    /// dependency nothing answers to.
    pub(super) fn pins(&self) -> &Pins {
        &self.pins
    }

    /// The record for `name`, if it is a real package in this index.
    pub(super) fn get(&self, name: &str) -> Option<&Record> {
        self.by_name.get(name)
    }

    /// The names of the packages whose `p:` field names `name`, in a stable
    /// order.
    ///
    /// A package is not a provider of itself here: it provides its own name by
    /// being it, which the resolver accounts for separately, and only a `p:`
    /// entry puts a name in this map.
    pub(super) fn providers(&self, name: &str) -> &[String] {
        self.providers.get(name).map_or(&[][..], Vec::as_slice)
    }

    /// Every record in the merged set, in no particular order.
    ///
    /// For the one question that is asked of the whole set rather than of a
    /// name: which packages' `i:` conditions the selection has come to satisfy.
    pub(super) fn records(&self) -> impl Iterator<Item = &Record> {
        self.by_name.values()
    }

    /// Projects the index into the names it offers, consuming it.
    ///
    /// The records go: what a caller asking about availability wants is the name
    /// set and the provider map, and retaining a merged archive's worth of
    /// records to back a membership question would be the wrong trade.
    pub(super) fn into_available(self) -> Available {
        Available::new(self.by_name.into_keys().collect(), self.providers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A control identity of the shape a record carries, distinct per `name`.
    fn identity(name: &str) -> String {
        let mut value = String::from(IDENTITY_PREFIX);
        for byte in name.bytes().cycle().take(27) {
            value.push(char::from(b'a' + byte % 26));
        }
        value.push('=');
        value
    }

    /// A record, spelled the way an index spells one.
    fn record(name: &str, version: &str, architecture: &str, provides: &str) -> String {
        let mut text = format!(
            "C:{}\nP:{name}\nV:{version}\nA:{architecture}\nS:1024\n",
            identity(name),
        );
        if !provides.is_empty() {
            text.push_str(&format!("p:{provides}\n"));
        }
        text
    }

    /// The records of `text`, or a panic naming the refusal.
    fn parsed(text: &str) -> Vec<Record> {
        parse("the index", text, 0).unwrap_or_else(|err| panic!("the index parses: {err}"))
    }

    /// The names a record provides, for the assertions that only care about
    /// those.
    fn provided(record: &Record) -> Vec<&str> {
        record
            .provides
            .iter()
            .map(|provided| provided.name.as_str())
            .collect()
    }

    #[test]
    fn a_record_is_read_from_the_letters_that_carry_it() {
        let records = parsed(&format!(
            "C:{}\nP:7zip\nV:25.01-r0\nA:x86_64\nS:915485\nI:1784184\no:p7zip\nk:100\n\
             D:so:libc.musl-x86_64.so.1 !p7zip-old\np:p7zip=25.01-r0 cmd:7z\ni:docs 7zip=25.01-r0\n",
            identity("7zip"),
        ));
        let [record] = &records[..] else {
            panic!("one record: {records:?}");
        };
        assert_eq!(record.name, "7zip");
        assert_eq!(record.version, "25.01-r0");
        assert_eq!(record.architecture, "x86_64");
        assert_eq!(record.control_identity, identity("7zip"));
        assert_eq!(record.size, Some(915_485));
        assert_eq!(record.installed_size, Some(1_784_184));
        assert_eq!(record.origin.as_deref(), Some("p7zip"));
        assert_eq!(record.provider_priority, Some(100));
        assert_eq!(record.from, 0);

        assert_eq!(
            record
                .depends
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["so:libc.musl-x86_64.so.1", "!p7zip-old"],
        );
        assert!(!record.depends[0].conflict);
        assert!(record.depends[1].conflict, "a leading ! is a refusal");
        assert_eq!(provided(record), ["p7zip", "cmd:7z"]);
        assert_eq!(record.provides[0].version.as_deref(), Some("25.01-r0"));
        assert_eq!(
            record.provides[1].version, None,
            "an entry may provide a name at no version",
        );
        assert_eq!(
            record
                .install_if
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["docs", "7zip=25.01-r0"],
        );
    }

    #[test]
    fn a_source_package_equal_to_the_name_says_nothing_and_is_dropped() {
        let text = format!(
            "C:{}\nP:musl\nV:1.0-r0\nA:x86_64\no:musl\n",
            identity("musl")
        );
        assert_eq!(parsed(&text)[0].origin, None);
    }

    #[test]
    fn a_name_a_package_cannot_be_addressed_by_is_refused() {
        // The name becomes a path segment of the URL its .apk is fetched from
        // and a word of the records written into the finished rootfs, and it
        // comes from the mirror rather than from the caller.
        for name in [
            "../escape",
            "a/b",
            "with space",
            "-leading",
            ".leading",
            "quer?y",
            "frag#ment",
            "per%cent",
            "new\tline",
        ] {
            let text = format!("C:{}\nP:{name}\nV:1.0-r0\nA:x86_64\n", identity("x"));
            let err = parse("the index", &text, 0).expect_err("the name is not addressable");
            assert!(matches!(err, AlpineError::Index { .. }), "{name:?}: {err}");
        }
        // And the shapes real names take are accepted.
        for name in [
            "7zip",
            "libstdc++",
            "py3-cffi",
            "alpine-base",
            "musl_1",
            "R",
        ] {
            let text = format!("C:{}\nP:{name}\nV:1.0-r0\nA:x86_64\n", identity(name));
            parse("the index", &text, 0)
                .unwrap_or_else(|err| panic!("{name} is a real Alpine name: {err}"));
        }
    }

    #[test]
    fn a_control_identity_that_is_not_one_is_refused() {
        // It is recomputed and compared when the package is fetched, so a
        // record carrying anything else is malformed rather than unfamiliar.
        let right_length_wrong_alphabet = format!("{}!", &identity("a")[..IDENTITY_LENGTH - 1]);
        // Twenty bytes of base64 is twenty-seven alphabet characters and one
        // trailing `=`, so padding anywhere else is a value the encoder can
        // never produce. Admitting it would move the refusal to fetch time and
        // word it as a mirror serving the wrong bytes.
        let padded_throughout = format!("{IDENTITY_PREFIX}{}", "=".repeat(28));
        let padded_early = format!("{}={}", &identity("a")[..IDENTITY_LENGTH - 2], "A");
        for value in [
            "",
            "Q1",
            "Q2abc",
            &right_length_wrong_alphabet,
            &padded_throughout,
            &padded_early,
            &format!("{}x", identity("a")),
        ] {
            let text = format!("C:{value}\nP:musl\nV:1.0-r0\nA:x86_64\n");
            let err = parse("the index", &text, 0).expect_err("the identity is malformed");
            assert!(matches!(err, AlpineError::Index { .. }), "{value:?}: {err}");
        }
        // And what the encoder does produce is accepted, over inputs whose
        // final base64 group varies.
        for seed in ["a", "bb", "ccc", "dddd"] {
            let text = format!("C:{}\nP:musl\nV:1.0-r0\nA:x86_64\n", identity(seed));
            parse("the index", &text, 0)
                .unwrap_or_else(|err| panic!("{seed}'s identity is one this crate renders: {err}"));
        }
    }

    #[test]
    fn a_dependency_entry_the_format_does_not_define_refuses_the_index() {
        // A dependency that cannot be read is one the closure would silently
        // omit, which is worse than refusing the index it came in.
        for field in [
            "D:lib>=nonesuch",
            "D:lib><2.0",
            "D:=1.0",
            "i:!",
            "p:virt>=1.0",
            "p:=1.0",
        ] {
            let text = format!(
                "C:{}\nP:musl\nV:1.0-r0\nA:x86_64\n{field}\n",
                identity("musl")
            );
            let err = parse("the index", &text, 0).expect_err("the entry is malformed");
            assert!(matches!(err, AlpineError::Index { .. }), "{field}: {err}");
        }
    }

    #[test]
    fn records_are_separated_by_a_blank_line_and_the_last_needs_none() {
        let text = format!(
            "{}\n{}",
            record("a", "1.0-r0", "x86_64", ""),
            record("b", "2.0-r0", "noarch", ""),
        );
        assert_eq!(parsed(&text).len(), 2);
        assert_eq!(
            parsed(&format!("{text}\n")).len(),
            2,
            "a trailing blank line"
        );
        assert_eq!(
            parsed(&format!("\n\n{text}\n\n\n")).len(),
            2,
            "runs of blank lines carry no record",
        );
    }

    #[test]
    fn a_letter_this_reader_does_not_know_is_ignored() {
        // apk may define one, and an index carrying it is still readable.
        let text = format!("{}Z:something new\n", record("a", "1.0-r0", "x86_64", ""));
        assert_eq!(parsed(&text)[0].name, "a");
    }

    #[test]
    fn a_line_that_is_not_a_field_is_refused() {
        // There is no continuation syntax and no comment, so this is a mirror
        // serving something other than an index rather than something to skip.
        for line in [
            "not a field",
            " P:leading space",
            "#a comment",
            "PP:two letters",
        ] {
            let text = format!("{}{line}\n", record("a", "1.0-r0", "x86_64", ""));
            let err = parse("the index", &text, 0).expect_err("{line} is not a field");
            assert!(matches!(err, AlpineError::Index { .. }), "{line}: {err}");
        }
    }

    #[test]
    fn a_record_missing_what_identifies_it_is_refused() {
        let full = record("a", "1.0-r0", "x86_64", "");
        for missing in ['P', 'V', 'A', 'C'] {
            let text: String = full
                .lines()
                .filter(|line| !line.starts_with(missing))
                .map(|line| format!("{line}\n"))
                .collect();
            let err = parse("the index", &text, 0).expect_err("the record is incomplete");
            assert!(matches!(err, AlpineError::Index { .. }), "{err}");
        }
    }

    #[test]
    fn a_repeated_letter_in_one_record_is_refused() {
        // Two names in one record is a record that says two things, and which
        // one a reader takes is exactly the ambiguity to refuse.
        let text = format!("{}P:b\n", record("a", "1.0-r0", "x86_64", ""));
        let err = parse("the index", &text, 0).expect_err("the record names itself twice");
        assert!(matches!(err, AlpineError::Index { .. }), "{err}");
    }

    #[test]
    fn a_record_of_many_distinct_letters_is_read_in_one_pass() {
        // Unknown letters are admitted, and any character is a letter, so
        // nothing bounds how many one record carries but its length. A base's
        // database is a tree its own scripts wrote. The letters are told apart
        // through a set, so this reads in a pass over the record rather than in
        // one per line, and the record still reads as the one package it names.
        let mut text = record("a", "1.0-r0", "x86_64", "");
        let letters: Vec<char> = (0x4e00..0x4e00 + 0x3_0000)
            .filter_map(char::from_u32)
            .take(150_000)
            .collect();
        assert_eq!(letters.len(), 150_000);
        for letter in &letters {
            text.push_str(&format!("{letter}:x\n"));
        }
        let records = parsed(&text);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "a");

        // And the set is the record's own: the next record may carry the same
        // letters again.
        let twice = format!("{text}\n{text}");
        assert_eq!(parsed(&twice).len(), 2);
        // While a letter repeated within one record is still refused, at the
        // end of the run of letters as at its start.
        let repeated = format!("{text}{}:y\n", letters[letters.len() - 1]);
        let err = parse("the index", &repeated, 0).expect_err("the last letter appears twice");
        assert!(matches!(err, AlpineError::Index { .. }), "{err}");
    }

    #[test]
    fn a_version_the_format_does_not_define_is_refused() {
        let text = record("a", "not a version", "x86_64", "");
        let err = parse("the index", &text, 0).expect_err("the version does not parse");
        assert!(
            matches!(&err, AlpineError::Index { reason, .. } if reason.contains("not a version")),
            "{err}",
        );
    }

    #[test]
    fn the_highest_version_wins_wherever_it_comes_from() {
        let old = parsed(&record("a", "1.0-r0", "x86_64", ""));
        let new = parsed(&record("a", "1.0-r1", "x86_64", ""));
        let index = Index::merge([old, new], "x86_64", &Pins::none());
        assert_eq!(index.get("a").expect("a is present").version, "1.0-r1");

        let new = parsed(&record("a", "1.0-r1", "x86_64", ""));
        let old = parsed(&record("a", "1.0-r0", "x86_64", ""));
        let index = Index::merge([new, old], "x86_64", &Pins::none());
        assert_eq!(
            index.get("a").expect("a is present").version,
            "1.0-r1",
            "a later repository does not install an older package",
        );
    }

    #[test]
    fn a_later_repository_shadows_an_earlier_one_at_equal_version() {
        // The mechanism an overlay repository needs: postmarketOS republishing
        // an Alpine package at the same version is the one that must win.
        let alpine = parsed(&record("a", "1.0-r0", "x86_64", "from-alpine"));
        let overlay = parsed(&record("a", "1.0-r0", "x86_64", "from-overlay"));
        let index = Index::merge([alpine, overlay], "x86_64", &Pins::none());
        assert_eq!(
            provided(index.get("a").expect("a is present")),
            ["from-overlay"],
        );
    }

    #[test]
    fn a_record_for_another_architecture_is_dropped() {
        // An index is published per architecture, so this only fires for a
        // mirror serving something other than what its path says.
        let records = parsed(&format!(
            "{}\n{}\n{}",
            record("native", "1.0-r0", "x86_64", ""),
            record("every", "1.0-r0", "noarch", ""),
            record("foreign", "1.0-r0", "aarch64", ""),
        ));
        let index = Index::merge([records], "x86_64", &Pins::none());
        assert!(index.get("native").is_some());
        assert!(index.get("every").is_some(), "noarch belongs to every one");
        assert!(index.get("foreign").is_none());
    }

    #[test]
    fn availability_covers_the_real_names_and_the_provided_ones() {
        let records = parsed(&format!(
            "{}\n{}",
            record("musl", "1.2.5-r23", "x86_64", "so:libc.musl-x86_64.so.1"),
            record("busybox", "1.37.0-r0", "x86_64", "cmd:sh /bin/sh"),
        ));
        let available = Index::merge([records], "x86_64", &Pins::none()).into_available();
        assert!(available.contains("musl"), "a real package");
        assert!(
            available.contains("so:libc.musl-x86_64.so.1"),
            "a name only provided",
        );
        assert!(!available.contains("glibc"));
        assert_eq!(
            available
                .providers("so:libc.musl-x86_64.so.1")
                .collect::<Vec<_>>(),
            ["musl"],
        );
        assert_eq!(
            available.providers("musl").count(),
            0,
            "not its own provider"
        );
    }

    #[test]
    fn providers_of_one_name_are_reported_in_a_stable_order() {
        let records = parsed(&format!(
            "{}\n{}\n{}",
            record("mawk", "1.0-r0", "x86_64", "cmd:awk"),
            record("gawk", "1.0-r0", "x86_64", "cmd:awk"),
            record("busybox", "1.0-r0", "x86_64", "cmd:awk"),
        ));
        let available = Index::merge([records], "x86_64", &Pins::none()).into_available();
        assert_eq!(
            available.providers("cmd:awk").collect::<Vec<_>>(),
            ["busybox", "gawk", "mawk"],
        );
    }

    #[test]
    fn a_rendering_reports_how_much_was_read_rather_than_what() {
        let records = parsed(&record("musl", "1.2.5-r23", "x86_64", "so:libc.musl"));
        let index = Index::merge([records], "x86_64", &Pins::none());
        let rendering = format!("{index:?}");
        assert!(
            rendering.contains("packages: 1") && rendering.contains("virtual_names: 1"),
            "{rendering}",
        );
        assert!(!rendering.contains("musl"), "{rendering}");
        let rendering = format!("{:?}", index.into_available());
        assert!(rendering.contains("names: 2"), "{rendering}");
        assert!(!rendering.contains("musl"), "{rendering}");
    }
}
