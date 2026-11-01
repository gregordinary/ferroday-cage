//! The signed pointer: which build of each variant the archive publishes now,
//! and how current the answer is.
//!
//! `latest-stage3.txt` is one cleartext-signed document per architecture,
//! enumerating every stage3 that architecture currently offers. It is the
//! authoritative, machine-readable list — from the same key as everything else
//! — which is what lets a caller's variant be checked against what Gentoo
//! publishes today rather than against a compiled-in vocabulary that goes stale
//! between releases of this crate.
//!
//! # The regeneration timestamp is the freshness bound
//!
//! Gentoo publishes no deadline of any kind: no `Valid-Until`, and no
//! expiration on the signature itself. Without a bound, a mirror serving a
//! genuinely signed but months-old pointer and its matching digest document
//! passes every check there is — the signature verifies, the key that made it is
//! still in force, the digest matches the bytes — which is a rollback, and the
//! standard attack on a chain with no deadline.
//!
//! The document closes it itself. Inside the signed body, above the entries:
//!
//! ```text
//! # Latest as of Mon, 10 Aug 2026 23:30:01 +0000
//! # ts=1786404601
//! ```
//!
//! Every architecture carries the line, and the documents are regenerated on a
//! common schedule whether or not new builds landed — amd64's `x32` entries were
//! two months old while its own `ts` was minutes old — so the value measures the
//! pointer's currency rather than the age of what it points at. That is the
//! `Valid-Until` analogue, and it is inside the signature.

use super::GentooError;
use crate::provision::coordinate::{self, Nesting};

/// The suffix every published stage3 carries. Checked rather than assumed: the
/// build id is read back out of the file name, and the name has to end in
/// something.
const TARBALL_SUFFIX: &str = ".tar.xz";

/// The prefix every published stage3 file name carries, before the variant.
const TARBALL_PREFIX: &str = "stage3-";

/// One entry of the pointer: a variant, the build it points at, where that
/// build's tarball sits, and what it weighs.
#[derive(Debug, Clone)]
pub(super) struct Entry {
    /// The variant as the document spells it — the whole compound between
    /// `stage3-` and the build id, such as `amd64-openrc` or `x32-openrc`.
    pub(super) variant: String,
    /// The build directory the entry names, such as `20260810T204554Z`.
    pub(super) build_id: String,
    /// The path under `autobuilds/`, as the document wrote it.
    pub(super) path: String,
    /// The tarball's size in bytes, which bounds the fetch of it.
    pub(super) size: u64,
}

/// A parsed pointer document: what the architecture offers, and when the
/// answer was assembled.
#[derive(Debug)]
pub(super) struct Pointer {
    /// The epoch the document states it was regenerated at, or `None` where it
    /// states none. Absence is not permission; see
    /// [`Gentoo::max_pointer_age`](super::GentooBuilder::max_pointer_age).
    published: Option<i64>,
    /// Every entry the document names, in the order it names them.
    entries: Vec<Entry>,
}

impl Pointer {
    /// Reads a verified pointer body.
    ///
    /// The body is comment lines and entries, an entry being a path relative to
    /// the `autobuilds/` tree and a size in bytes. A line the reader cannot use
    /// is dropped rather than failing the document — the same rule the Debian
    /// release parser applies to an index line it has no use for — because an
    /// entry whose file name does not decompose into a variant is one this layer
    /// could not name anyway, and refusing the whole architecture over it would
    /// take away the nineteen variants that did parse. A document with no usable
    /// entry at all is refused, since there is nothing left to choose from.
    ///
    /// `subject` names the document in a refusal.
    pub(super) fn parse(subject: &str, body: &str) -> Result<Pointer, GentooError> {
        let mut published = None;
        let mut entries = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            if let Some(stamp) = line.strip_prefix("# ts=") {
                published = stamp.trim().parse().ok();
                continue;
            }
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            if let (Some(path), Some(size), None) = (fields.next(), fields.next(), fields.next())
                && let Ok(size) = size.parse()
                && let Some(entry) = entry_at(path, size)
            {
                entries.push(entry);
            }
        }
        if entries.is_empty() {
            return Err(GentooError::document(
                subject,
                "it names no stage3 this crate can address",
            ));
        }
        Ok(Pointer { published, entries })
    }

    /// The epoch the document states it was regenerated at.
    pub(super) fn published(&self) -> Option<i64> {
        self.published
    }

    /// Every entry, in the order the document names them.
    pub(super) fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry for `variant`, matched exactly.
    ///
    /// Exactly, not by prefix: `amd64-openrc-splitusr` sits beside
    /// `amd64-openrc` in the same document, and a prefix match would hand a
    /// caller who asked for one the other.
    pub(super) fn entry(&self, variant: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.variant == variant)
    }

    /// Every variant the document names, in the order it names them, for a
    /// refusal that says what is on offer.
    pub(super) fn variants(&self) -> Vec<&str> {
        self.entries
            .iter()
            .map(|entry| entry.variant.as_str())
            .collect()
    }
}

/// Decomposes one entry path into the build and variant it names, or `None`
/// where it is not a path this layer can address.
///
/// The path is `<build id>/stage3-<variant>-<build id><suffix>`, and every part
/// of that is checked rather than assumed. What the check buys is not tidiness:
/// the path becomes directory segments of a request line, so a signed but
/// hostile document naming `../../etc` must not be followed. The crate's own
/// precedent is the Debian index reader, which checks a pool path out of an
/// already-signed index rather than trusting the signature to have covered the
/// question.
///
/// Requiring the file name to end in the build directory it sits in is what
/// pins the entry to one place: the name alone decides both segments, so there
/// is no second value that could disagree with the first.
fn entry_at(path: &str, size: u64) -> Option<Entry> {
    coordinate::check("the pointer's entry", path, Nesting::Nested).ok()?;
    let (build_id, file) = path.split_once('/')?;
    let variant = file
        .strip_prefix(TARBALL_PREFIX)?
        .strip_suffix(TARBALL_SUFFIX)?
        .strip_suffix(build_id)?
        .strip_suffix('-')?;
    if variant.is_empty() {
        return None;
    }
    Some(Entry {
        variant: variant.to_string(),
        build_id: build_id.to_string(),
        path: path.to_string(),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pointer body shaped as the archive publishes one.
    const BODY: &str = "\
# Latest as of Mon, 10 Aug 2026 23:30:01 +0000
# ts=1786404601
20260810T204554Z/stage3-amd64-openrc-20260810T204554Z.tar.xz 495865168
20260810T204554Z/stage3-amd64-openrc-splitusr-20260810T204554Z.tar.xz 494479304
20260610T214636Z/stage3-x32-openrc-20260610T214636Z.tar.xz 323925596
";

    fn parsed() -> Pointer {
        Pointer::parse("the pointer", BODY).expect("the body is a pointer")
    }

    #[test]
    fn a_variant_is_the_whole_compound_the_document_spells() {
        // The sub-architecture is part of the variant rather than relative to
        // the architecture the document was fetched under: amd64's own document
        // lists `amd64-openrc` and `x32-openrc` as siblings, so a spelling
        // relative to `amd64` could not name the second at all.
        assert_eq!(
            parsed().variants(),
            ["amd64-openrc", "amd64-openrc-splitusr", "x32-openrc"],
        );
        assert_eq!(parsed().published(), Some(1_786_404_601));
    }

    #[test]
    fn a_variant_matches_exactly_rather_than_by_prefix() {
        // `amd64-openrc-splitusr` sits beside `amd64-openrc` in one document,
        // so a prefix match would hand a caller who asked for one the other.
        let pointer = parsed();
        let openrc = pointer.entry("amd64-openrc").expect("the variant is named");
        assert_eq!(openrc.build_id, "20260810T204554Z");
        assert_eq!(openrc.size, 495_865_168);
        assert_eq!(
            openrc.path,
            "20260810T204554Z/stage3-amd64-openrc-20260810T204554Z.tar.xz",
        );
        assert_eq!(
            pointer.entry("amd64-openrc-splitusr").map(|e| e.size),
            Some(494_479_304),
        );
        assert!(pointer.entry("amd64").is_none(), "no prefix match");
        assert!(pointer.entry("openrc").is_none(), "no suffix match");
    }

    #[test]
    fn each_variant_keeps_the_build_its_own_entry_names() {
        // A sub-architecture is built on its own cadence, so one document
        // routinely points different variants at different builds. The x32
        // entry here is two months older than the amd64 ones.
        let pointer = parsed();
        assert_eq!(
            pointer.entry("x32-openrc").map(|e| e.build_id.as_str()),
            Some("20260610T214636Z"),
        );
    }

    #[test]
    fn an_entry_that_reaches_outside_its_build_directory_is_dropped() {
        // The refusals that matter: the path becomes directory segments of a
        // request line, and a signature over the document does not make its
        // contents a safe path. Each of these is dropped, leaving the one good
        // entry behind rather than being followed.
        let hostile = "# ts=1786404601\n\
             ../../etc/stage3-evil-x.tar.xz 1\n\
             /etc/stage3-evil-x.tar.xz 1\n\
             20260810T204554Z/../stage3-evil-20260810T204554Z.tar.xz 1\n\
             20260810T204554Z/sub/stage3-evil-20260810T204554Z.tar.xz 1\n\
             20260810T204554Z/stage3-evil-20260899T999999Z.tar.xz 1\n\
             20260810T204554Z/stage3-20260810T204554Z.tar.xz 1\n\
             20260810T204554Z/evil-20260810T204554Z.tar.xz 1\n\
             20260810T204554Z/stage3-evil-20260810T204554Z.tar.gz 1\n\
             20260810T204554Z/stage3-good-20260810T204554Z.tar.xz 7\n";
        let pointer = Pointer::parse("the pointer", hostile).expect("one entry survives");
        assert_eq!(pointer.variants(), ["good"]);
    }

    #[test]
    fn a_line_that_is_not_an_entry_is_not_one() {
        // A size that is not a number, a third field, and a missing size are
        // each dropped rather than read as an entry with a guessed length: the
        // size is what bounds the fetch.
        let odd = "\
# ts=1786404601
20260810T204554Z/stage3-nosize-20260810T204554Z.tar.xz
20260810T204554Z/stage3-notanumber-20260810T204554Z.tar.xz twelve
20260810T204554Z/stage3-extra-20260810T204554Z.tar.xz 1 2
20260810T204554Z/stage3-negative-20260810T204554Z.tar.xz -1
20260810T204554Z/stage3-good-20260810T204554Z.tar.xz 7
";
        assert_eq!(
            Pointer::parse("the pointer", odd)
                .expect("one entry survives")
                .variants(),
            ["good"],
        );
    }

    #[test]
    fn a_pointer_with_nothing_addressable_in_it_is_refused() {
        // Rather than reported as an architecture that offers nothing, which
        // reads as a fact about Gentoo instead of about the document.
        let err = Pointer::parse("the pointer", "# ts=1786404601\n")
            .expect_err("an empty pointer is refused");
        assert!(matches!(err, GentooError::Document { .. }), "{err}");
    }

    #[test]
    fn a_pointer_without_a_timestamp_reports_none() {
        // Read here and judged by the caller, which is what lets a caller who
        // has deliberately cleared the age bound provision from an archived
        // mirror while leaving absence a refusal for everyone else.
        let undated = "20260810T204554Z/stage3-good-20260810T204554Z.tar.xz 7\n";
        let pointer = Pointer::parse("the pointer", undated).expect("the entry parses");
        assert_eq!(pointer.published(), None);
        assert_eq!(pointer.entries().len(), 1);

        // An unparseable stamp is the same case: nothing was stated.
        let garbled = format!("# ts=yesterday\n{undated}");
        assert_eq!(
            Pointer::parse("the pointer", &garbled)
                .expect("the entry parses")
                .published(),
            None,
        );
    }
}
