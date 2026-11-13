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
//! ferrata reads it ([`ferrata::index::read`]) as apk does, lenient where apk is
//! lenient: a repeated letter replaces or adds to the one before, a letter apk
//! does not know is a flaw of the record rather than of the index, and an entry
//! apk cannot read leaves the record one it cannot install rather than
//! unreadable. What apk cannot read at all, a line that is not a field or a
//! record without a version or an identity it can decode, refuses the index
//! here, where apk would keep the records before it: a root assembled from part
//! of an index would be missing whatever the rest named, without saying so.
//!
//! An index is bytes to apk, and to ferrata: no field is held to UTF-8, and a
//! description or a name a dependency states may hold bytes that are not. On
//! top of apk's reading, this layer holds each record to what it does with one.
//! The name and the version become a path segment of the URL the package is
//! fetched from, the identity is recomputed over what a mirror serves, the
//! architecture becomes the installed record's `A:`, and the origin is recorded
//! in a plan, so a record whose name is not one a package can be addressed by,
//! whose version is outside the grammar, whose identity is not a SHA-1 spelled
//! as apk writes one, which states no architecture, or whose origin is not text
//! refuses the index.

use std::collections::{HashMap, HashSet};
use std::fmt;

use ferrata::record::Record;

use super::{AlpineError, DIALECT};
use crate::provision::Available;

/// The architecture value a package carries when it belongs to every
/// architecture the repository serves: in an index's `A:`, a `.PKGINFO`'s
/// `arch`, and a plan's `Architecture`.
pub(super) const NOARCH: &str = "noarch";

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

/// Whether `value` is a well-formed `C:` field: `Q1` and the base64 of a
/// SHA-1, spelled as apk writes it.
///
/// The identity is recomputed and compared when the package is fetched, so a
/// value that is not one is malformed rather than merely unfamiliar. A plan
/// document is held to this too, in
/// [`PlannedPackage::unaddressable`](super::plan::PlannedPackage::unaddressable).
///
/// The value is read as [`sign::identity_digest`] reads it, which admits only
/// the spelling [`sign::identity`] writes: twenty bytes of base64 is
/// twenty-seven alphabet characters and exactly one `=`, and the two bits the
/// last character carries past the digest are zero. `apk.static` 3.0.9 reads
/// a `Q2` digest, text after the digest, and a last character whose bits past
/// it are not zero, and records the spelling its encoder writes; no encoder
/// writes the others, so this layer refuses them with the rest of what a
/// mirror serving something else looks like.
///
/// [`sign::identity_digest`]: super::sign::identity_digest
/// [`sign::identity`]: super::sign::identity
pub(super) fn is_control_identity(value: &str) -> bool {
    super::sign::identity_digest(value).is_some()
}

/// A record's control identity, as a plan records it and a fetch compares it.
///
/// apk's own spelling of the digest the record's `C:` names, which is the one
/// [`sign::control_identity`](super::sign::control_identity) computes over
/// what a mirror serves. For a record [`unusable`] admits it is the `C:` field
/// as the index wrote it.
pub(super) fn control_identity(record: &Record) -> String {
    record.identity().to_string()
}

/// Reads an `APKINDEX` into its records, in the order it lists them.
///
/// `subject` names the index, for the errors — the URL it came from.
///
/// # Errors
///
/// Returns [`AlpineError::Index`] for text apk cannot read on from, naming the
/// line, and for a record this layer cannot fetch or record: a name a package
/// cannot be addressed by, a version outside the grammar, an identity that is
/// not a SHA-1 spelled as apk writes one, no architecture, or an origin that is
/// not text.
pub(super) fn parse(subject: &str, index: &[u8]) -> Result<Vec<Record>, AlpineError> {
    let mut records = Vec::new();
    for located in ferrata::index::read(DIALECT, index) {
        let located = located.map_err(|err| AlpineError::index(subject, err.to_string()))?;
        let line = located.line();
        let record = located.into_record();
        if let Some(reason) = unusable(&record).or_else(|| unplannable(&record)) {
            return Err(AlpineError::index(
                subject,
                format!("the record from line {line}: {reason}"),
            ));
        }
        records.push(record);
    }
    Ok(records)
}

/// Why this layer cannot fetch or record the package `record` describes, or
/// `None` where it can.
///
/// A base layer's installed records are held to it too: they are carried into
/// the database an increment writes and named in what it reports, and the
/// alphabets checked here are what let a name and a version be named bare and
/// written as the text they are. Both alphabets are ASCII, so a record this
/// admits has a name [`to_str`](ferrata::Name::to_str) reads, and a name and a
/// version whose `Display` is their bytes.
pub(super) fn unusable(record: &Record) -> Option<String> {
    // A name that is not UTF-8 is none a URL or a plan can carry, whatever
    // apk makes of it.
    let Some(name) = record.name().to_str().filter(|name| is_package_name(name)) else {
        return Some(format!(
            "it names the package {:?}, which is not a name a package can be addressed by",
            record.name(),
        ));
    };
    // Named bare from here on: the name has passed the alphabet above, which
    // holds no control character. The version has passed none, and is quoted
    // as ferrata writes it, each byte that is not UTF-8 escaped.
    let version = record.version();
    if !version.is_valid() {
        return Some(format!(
            "{name} carries {:?}, which is not a version this format defines",
            version.to_string(),
        ));
    }
    let spelled = record.field(b'C').unwrap_or_default();
    if !std::str::from_utf8(spelled).is_ok_and(is_control_identity) {
        return Some(format!(
            "{name}'s control identity {:?} is not a SHA-1 spelled as apk writes one, which is \
             the digest a package is verified against",
            String::from_utf8_lossy(spelled),
        ));
    }
    if record.architecture().is_none() {
        return Some(format!("{name} names no architecture (A:)"));
    }
    None
}

/// Why a plan cannot record what an index states of the package `record`
/// describes, or `None` where it can.
///
/// The origin is the one field a plan carries that no alphabet holds, and a
/// plan is text. Asked of an index's records only: a base's are carried as the
/// bytes they are, and no plan records them.
fn unplannable(record: &Record) -> Option<String> {
    let origin = record.origin()?;
    std::str::from_utf8(origin).is_err().then(|| {
        format!(
            "{} states the origin {:?}, which is not text a plan can record",
            record.name(),
            String::from_utf8_lossy(origin),
        )
    })
}

/// Whether `record` is a package built for `architecture`: that one, or
/// [`NOARCH`].
fn is_for(record: &Record, architecture: &str) -> bool {
    record.architecture().is_some_and(|built_for| {
        built_for == architecture.as_bytes() || built_for == NOARCH.as_bytes()
    })
}

/// Why `records`, an index fetched for `architecture`, are not an index of that
/// architecture's, or `None` where they are.
///
/// A repository publishes one index per architecture, and every record in it
/// states that architecture: a package built for every architecture is
/// recorded with the index's rather than as [`NOARCH`]. One key signs several
/// architectures' indexes (every postmarketOS architecture, Alpine's x86 and
/// x86_64 through v3.14, its armhf and armv7), so another architecture's index
/// verifies where this one's was asked for. [`Index::merge`] drops every
/// record of it, and the index would contribute nothing: a postmarketOS
/// overlay would vanish from the resolution without a word. So an index that
/// carries records and none of them for `architecture` or [`NOARCH`] is
/// refused. `apk.static` 3.0.9 reads such an index, and refuses to install any
/// of its records, as `uninstallable`.
///
/// An index with no records at all is not refused: it is what a repository
/// with nothing to offer an architecture publishes.
pub(super) fn foreign_to(records: &[Record], architecture: &str) -> Option<String> {
    let first = records.first()?;
    if records.iter().any(|record| is_for(record, architecture)) {
        return None;
    }
    // Every record `parse` admits states an architecture.
    Some(format!(
        "none of its {} records is for {architecture:?}, the first being for {:?}, so it is \
         an index of another architecture",
        records.len(),
        String::from_utf8_lossy(first.architecture().unwrap_or_default()),
    ))
}

/// Every configured index's records of one architecture, each index's in the
/// order it lists them.
///
/// Every version an index offers is kept, since apk chooses among all of them:
/// a dependency on `foo<2` installs `foo` 1.5 where 1.5 and 2.1 are both
/// offered. The indexes stay apart, in the order the repositories are
/// configured, because that order decides a tie and because a package is
/// fetched from the index that offered it: each is one repository to the
/// resolution, which names the one a package comes from by its position.
pub(super) struct Index {
    indexes: Vec<Vec<Record>>,
}

impl fmt::Debug for Index {
    /// Reports how much was read rather than what. A merged Alpine
    /// `main`+`community` is around 28,000 records, which no reader of a
    /// rendering can act on.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Index")
            .field("indexes", &self.indexes.len())
            .field("packages", &self.records().count())
            .finish()
    }
}

impl Index {
    /// Keeps each index's records of `architecture`.
    ///
    /// `inputs` are the indexes' record lists in the order the repositories
    /// were configured, component by component. A record whose architecture is
    /// neither `architecture` nor [`NOARCH`] is dropped, which is what `apk`'s
    /// selection makes of it: `apk.static` 3.0.9 lists such a record and
    /// refuses to install it, as `uninstallable`, so a name only such records
    /// answer is refused either way, and one another record answers is answered
    /// by that record whatever the version. An index made of nothing else was
    /// refused as it was read, by [`foreign_to`].
    pub(super) fn merge(
        inputs: impl IntoIterator<Item = Vec<Record>>,
        architecture: &str,
    ) -> Index {
        let indexes = inputs
            .into_iter()
            .map(|records| {
                records
                    .into_iter()
                    .filter(|record| is_for(record, architecture))
                    .collect()
            })
            .collect();
        Index { indexes }
    }

    /// Each index's records, in the order the indexes were read.
    pub(super) fn indexes(&self) -> &[Vec<Record>] {
        &self.indexes
    }

    /// Every record of every index, in order.
    pub(super) fn records(&self) -> impl Iterator<Item = &Record> {
        self.indexes.iter().flatten()
    }

    /// Projects the index into the names it offers, consuming it.
    ///
    /// The records go: what a caller asking about availability wants is the name
    /// set and the provider map, and retaining a merged archive's worth of
    /// records to back a membership question would be the wrong trade.
    pub(super) fn into_available(self) -> Available {
        let mut real = HashSet::new();
        let mut providers: HashMap<String, Vec<String>> = HashMap::new();
        for record in self.records() {
            // A record's own name is one `unusable` admitted, so it is text.
            real.insert(record.name().to_string());
            for provided in record.provides() {
                // A caller asks after a name as text, so a provided name that
                // is not is one no caller can name.
                let Some(provided) = provided.name().to_str() else {
                    continue;
                };
                providers
                    .entry(provided.to_string())
                    .or_default()
                    .push(record.name().to_string());
            }
        }
        // A name offered at several versions, or by several indexes, is one
        // provider; and a resolution's report has to be reproducible, so each
        // list is put in one order.
        for names in providers.values_mut() {
            names.sort();
            names.dedup();
        }
        Available::new(real, providers)
    }
}

/// Index records for the layer's unit tests, as an `APKINDEX` spells them.
#[cfg(test)]
pub(crate) mod fixture {
    use super::{Index, parse};
    use crate::provision::alpine::sign::identity_for_test;

    /// A record offering `name` at `version` for `architecture`, its control
    /// identity derived from `seed`, with `fields` after it, one or more lines,
    /// where there are any. Each field ends its line, and records are
    /// separated by a blank line where they are joined.
    pub(crate) fn record(
        name: &str,
        version: &str,
        architecture: &str,
        seed: &str,
        fields: &str,
    ) -> String {
        let mut text = format!(
            "C:{}\nP:{name}\nV:{version}\nA:{architecture}\nS:1024\n",
            identity_for_test(seed),
        );
        if !fields.is_empty() {
            text.push_str(fields);
            text.push('\n');
        }
        text
    }

    /// An x86_64 index of `records`, read as one repository's.
    pub(crate) fn merged(records: &[String]) -> Index {
        let parsed = parse("the index", records.join("\n").as_bytes())
            .unwrap_or_else(|err| panic!("the index parses: {err}"));
        Index::merge([parsed], "x86_64")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::alpine::sign::identity_for_test as identity;

    /// A record, spelled the way an index spells one, providing `provides`
    /// where it is not empty.
    fn record(name: &str, version: &str, architecture: &str, provides: &str) -> String {
        let provides = match provides {
            "" => String::new(),
            provides => format!("p:{provides}"),
        };
        fixture::record(name, version, architecture, name, &provides)
    }

    /// The records of `text`, or a panic naming the refusal.
    fn parsed(text: &str) -> Vec<Record> {
        parse("the index", text.as_bytes()).unwrap_or_else(|err| panic!("the index parses: {err}"))
    }

    /// The refusal of `index`, or a panic naming what it read.
    fn refused(index: &[u8]) -> AlpineError {
        match parse("the index", index) {
            Ok(records) => panic!("expected a refusal, read {} records", records.len()),
            Err(err) => err,
        }
    }

    #[test]
    fn a_record_an_index_malforms_is_refused_with_its_control_characters_escaped() {
        // The name is refused before anything has admitted it. A line that is
        // not a field is refused by its number, and its text is not repeated.
        let hostile = crate::failure::hostile::TEXT;
        let refused = refused(record(hostile, "1.0-r0", "x86_64", "").as_bytes());
        crate::failure::hostile::assert_escaped(&refused.to_string());
    }

    #[test]
    fn bytes_that_are_not_utf8_are_read_where_this_layer_records_nothing() {
        // A description and a name a dependency states are bytes to apk, and an
        // index holding such bytes is one it reads.
        let mut index = record("a", "1.0-r0", "x86_64", "").into_bytes();
        index.extend_from_slice(b"T:caf\xe9\nD:lib\xff\n");
        let records = parse("the index", &index).expect("the index reads");
        assert_eq!(records[0].field(b'T'), Some(b"caf\xe9".as_slice()));
        assert_eq!(records[0].depends()[0].name(), b"lib\xff");
    }

    #[test]
    fn a_name_or_an_origin_that_is_not_utf8_is_refused() {
        // A name becomes a URL's path segment and an origin is recorded in a
        // plan, and both are text there. The refusal writes the bytes escaped.
        let name = format!("C:{}\nP:a", identity("a")).into_bytes();
        let unnamed = [&name[..], b"\xff\nV:1.0-r0\nA:x86_64\n"].concat();
        let reason = refused(&unnamed).to_string();
        assert!(reason.contains(r#""a\xff""#), "{reason}");

        let mut unrecorded = record("a", "1.0-r0", "x86_64", "").into_bytes();
        unrecorded.extend_from_slice(b"o:caf\xe9\n");
        let reason = refused(&unrecorded).to_string();
        assert!(reason.contains("origin"), "{reason}");
    }

    #[test]
    fn a_record_is_read_as_apk_reads_it() {
        let records = parsed(&format!(
            "C:{}\nP:7zip\nV:25.01-r0\nA:x86_64\nS:915485\nI:1784184\no:p7zip\nk:100\n\
             D:so:libc.musl-x86_64.so.1 !p7zip-old\np:p7zip=25.01-r0 cmd:7z\ni:docs 7zip=25.01-r0\n",
            identity("7zip"),
        ));
        let [record] = &records[..] else {
            panic!("one record: {records:?}");
        };
        assert_eq!(record.name(), "7zip");
        assert_eq!(record.version().to_str(), Some("25.01-r0"));
        assert_eq!(record.architecture(), Some(b"x86_64".as_slice()));
        assert_eq!(control_identity(record), identity("7zip"));
        assert_eq!(record.field(b'S'), Some(b"915485".as_slice()));
        assert_eq!(record.origin(), Some(b"p7zip".as_slice()));
        assert_eq!(record.priority(), 100);
        assert_eq!(record.depends().len(), 2);
        assert!(
            record.depends()[1].is_conflict(),
            "a leading ! is a refusal"
        );
        assert_eq!(record.provides().len(), 2);
        assert_eq!(record.install_if().len(), 2);
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
            let err = refused(text.as_bytes());
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
            parse("the index", text.as_bytes())
                .unwrap_or_else(|err| panic!("{name} is a real Alpine name: {err}"));
        }
    }

    #[test]
    fn an_identity_that_does_not_read_or_is_not_a_sha1_is_refused() {
        // It is recomputed and compared when the package is fetched, so a
        // record carrying anything else is one no package can be bound to.
        let length = identity("a").len();
        let wrong_alphabet = format!("{}!", &identity("a")[..length - 1]);
        // Twenty bytes of base64 is twenty-seven alphabet characters and one
        // trailing `=`, so padding anywhere else is a value the encoder can
        // never produce.
        let padded_throughout = format!("Q1{}", "=".repeat(28));
        let padded_early = format!("{}={}", &identity("a")[..length - 2], "A");
        // So is a last character whose bits past the digest are not zero, and
        // text after the digest: apk reads both as the digest, and writes
        // neither.
        let unpadded_bits = "Q1G2xQQm08BlbpxaVnpaWWAcf0MHp=";
        let trailing = format!("{}x", identity("a"));
        let sha256 = format!("Q2{}=", "A".repeat(43));
        for value in [
            "",
            "Q1",
            "Q2abc",
            &wrong_alphabet,
            &padded_throughout,
            &padded_early,
            unpadded_bits,
            &trailing,
            &sha256,
        ] {
            let text = format!("C:{value}\nP:musl\nV:1.0-r0\nA:x86_64\n");
            let err = refused(text.as_bytes());
            assert!(matches!(err, AlpineError::Index { .. }), "{value:?}: {err}");
        }
        let text = format!("C:{}\nP:musl\nV:1.0-r0\nA:x86_64\n", identity("a"));
        assert_eq!(control_identity(&parsed(&text)[0]), identity("a"));
    }

    #[test]
    fn a_plan_s_identity_is_held_to_the_spelling_apk_writes() {
        assert!(is_control_identity(&identity("a")));
        for value in [
            format!("{}x", identity("a")),
            "Q1G2xQQm08BlbpxaVnpaWWAcf0MHp=".to_string(),
            format!("Q2{}=", "A".repeat(43)),
            "Q1".to_string(),
            String::new(),
        ] {
            assert!(!is_control_identity(&value), "{value:?}");
        }
    }

    #[test]
    fn a_dependency_entry_apk_cannot_read_leaves_a_record_it_cannot_install() {
        // apk loads the record and will not install it, which is what a
        // resolution then answers; the index is still the index apk reads.
        for field in ["D:lib>=nonesuch", "D:=1.0"] {
            let text = format!(
                "C:{}\nP:musl\nV:1.0-r0\nA:x86_64\n{field}\n",
                identity("musl")
            );
            let records = parsed(&text);
            assert!(!records[0].is_installable(), "{field}");
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
            let err = refused(text.as_bytes());
            assert!(
                matches!(&err, AlpineError::Index { reason, .. } if reason.contains("line 6")),
                "{line}: {err}",
            );
        }
    }

    #[test]
    fn a_record_missing_what_identifies_it_is_refused() {
        let full = record("a", "1.0-r0", "x86_64", "");
        for missing in ['V', 'A', 'C'] {
            let text: String = full
                .lines()
                .filter(|line| !line.starts_with(missing))
                .map(|line| format!("{line}\n"))
                .collect();
            let err = refused(text.as_bytes());
            assert!(matches!(err, AlpineError::Index { .. }), "{err}");
        }
        // Fields with no name to end them are not a record, as apk reads them.
        let nameless: String = full
            .lines()
            .filter(|line| !line.starts_with('P'))
            .map(|line| format!("{line}\n"))
            .collect();
        assert!(parsed(&nameless).is_empty());
    }

    #[test]
    fn a_version_the_format_does_not_define_is_refused() {
        let text = record("a", "not a version", "x86_64", "");
        let err = refused(text.as_bytes());
        assert!(
            matches!(&err, AlpineError::Index { reason, .. } if reason.contains("not a version")),
            "{err}",
        );
    }

    #[test]
    fn every_version_an_index_offers_is_kept() {
        let first = parsed(&format!(
            "{}\n{}",
            record("a", "1.0-r0", "x86_64", ""),
            record("a", "2.0-r0", "x86_64", ""),
        ));
        let second = parsed(&record("a", "1.0-r1", "x86_64", ""));
        let index = Index::merge([first, second], "x86_64");
        let versions: Vec<String> = index
            .records()
            .map(|record| record.version().to_string())
            .collect();
        assert_eq!(versions, ["1.0-r0", "2.0-r0", "1.0-r1"]);
        assert_eq!(index.indexes().len(), 2);
    }

    #[test]
    fn a_record_for_another_architecture_is_dropped() {
        // An index is published per architecture, so this only fires for a
        // mirror serving something other than what its path says. `apk` lists
        // the record and will not install it, and a newer version of it does
        // not displace the record that can be installed.
        let records = parsed(&format!(
            "{}\n{}\n{}\n{}",
            record("native", "1.0-r0", "x86_64", ""),
            record("native", "2.0-r0", "aarch64", ""),
            record("every", "1.0-r0", "noarch", ""),
            record("foreign", "1.0-r0", "aarch64", ""),
        ));
        assert_eq!(foreign_to(&records, "x86_64"), None, "it holds x86_64's");
        let index = Index::merge([records], "x86_64");
        let kept: Vec<String> = index
            .records()
            .map(|record| format!("{} {}", record.name(), record.version()))
            .collect();
        assert_eq!(
            kept,
            ["native 1.0-r0", "every 1.0-r0"],
            "noarch belongs to every one"
        );
    }

    #[test]
    fn an_index_of_another_architecture_alone_is_refused() {
        // What one key signing several architectures lets a mirror serve: the
        // index verifies, and every record of it would be dropped.
        let foreign = parsed(&format!(
            "{}\n{}",
            record("one", "1.0-r0", "aarch64", ""),
            record("two", "1.0-r0", "aarch64", ""),
        ));
        let reason = foreign_to(&foreign, "x86_64").expect("nothing in it is x86_64's");
        assert!(
            reason.contains("\"x86_64\"") && reason.contains("\"aarch64\""),
            "{reason}",
        );
        // One record the architecture can install makes it that
        // architecture's index, and so does one built for every architecture.
        assert_eq!(foreign_to(&foreign, "aarch64"), None);
        let every = parsed(&record("every", "1.0-r0", "noarch", ""));
        assert_eq!(foreign_to(&every, "x86_64"), None);
        // An index with nothing in it offers nothing to any architecture.
        assert_eq!(foreign_to(&[], "x86_64"), None);
        // The architecture is the index's text, and is quoted.
        let hostile = parsed(&record("one", "1.0-r0", crate::failure::hostile::TEXT, ""));
        crate::failure::hostile::assert_escaped(
            &foreign_to(&hostile, "x86_64").expect("it is no x86_64 index"),
        );
    }

    #[test]
    fn availability_covers_the_real_names_and_the_provided_ones() {
        let records = parsed(&format!(
            "{}\n{}",
            record("musl", "1.2.5-r23", "x86_64", "so:libc.musl-x86_64.so.1"),
            record("busybox", "1.37.0-r0", "x86_64", "cmd:sh /bin/sh"),
        ));
        let available = Index::merge([records], "x86_64").into_available();
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
    fn providers_of_one_name_are_reported_once_in_a_stable_order() {
        let records = parsed(&format!(
            "{}\n{}\n{}\n{}",
            record("mawk", "1.0-r0", "x86_64", "cmd:awk"),
            record("gawk", "1.0-r0", "x86_64", "cmd:awk"),
            record("busybox", "1.0-r0", "x86_64", "cmd:awk"),
            record("gawk", "1.1-r0", "x86_64", "cmd:awk"),
        ));
        let available = Index::merge([records], "x86_64").into_available();
        assert_eq!(
            available.providers("cmd:awk").collect::<Vec<_>>(),
            ["busybox", "gawk", "mawk"],
        );
    }

    #[test]
    fn a_rendering_reports_how_much_was_read_rather_than_what() {
        let records = parsed(&record("musl", "1.2.5-r23", "x86_64", "so:libc.musl"));
        let index = Index::merge([records], "x86_64");
        let rendering = format!("{index:?}");
        assert!(
            rendering.contains("indexes: 1") && rendering.contains("packages: 1"),
            "{rendering}",
        );
        assert!(!rendering.contains("musl"), "{rendering}");
        let rendering = format!("{:?}", index.into_available());
        assert!(rendering.contains("names: 2"), "{rendering}");
        assert!(!rendering.contains("musl"), "{rendering}");
    }
}
