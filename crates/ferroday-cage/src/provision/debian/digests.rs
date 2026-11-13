//! The digests a Debian archive records for one file, and the rule they are
//! checked under.
//!
//! An archive records a file's digest under each algorithm it publishes one
//! for: Debian's releases and stanzas carry SHA-256, Ubuntu's carry SHA-256 and
//! SHA-512, and Ubuntu's development series carries SHA-512 alone. [`Digests`]
//! holds whichever of the two the archive recorded, and at least one.
//!
//! The check is apt's, as apt 2.8 measurably applies it to an index and to a
//! `.deb` alike: every recorded digest of an algorithm this layer computes is
//! compared, a mismatch in any one refuses the bytes, and SHA-512 alone
//! suffices. MD5 and SHA-1, which some releases still list, are not read.
//!
//! A plan records one of them, [`Digests::planned`], so what a fresh
//! resolution checks a download against is every digest the index offers, and
//! what a replayed plan checks it against is the one the plan recorded.

use std::io::{self, Read};

use crate::provision::digest::{self, Algorithm, Digest};

/// The algorithms a Debian archive records a digest under that this layer
/// computes, each with the field name the archive spells it as: the section of
/// a release, the field of a stanza or a plan, and the directory of a
/// `by-hash` path. Weakest first, which is the order [`Digests`] holds them in.
pub(super) const RECORDED: [(Algorithm, &str); 2] =
    [(Algorithm::Sha256, "SHA256"), (Algorithm::Sha512, "SHA512")];

/// The field name the archive spells `algorithm` as.
pub(super) fn field_name(algorithm: Algorithm) -> &'static str {
    RECORDED
        .iter()
        .find(|(recorded, _)| *recorded == algorithm)
        .map(|(_, name)| *name)
        .expect("every algorithm a plan records is one an archive records")
}

/// The digests an archive records for one file: its SHA-256, its SHA-512, or
/// both, and never neither.
///
/// Each is a [`Digest`], so each was held to its algorithm's shape where it
/// arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Digests {
    /// The SHA-256, where the archive records one.
    sha256: Option<Digest>,
    /// The SHA-512, where the archive records one.
    sha512: Option<Digest>,
}

impl From<Digest> for Digests {
    /// The one digest a plan recorded, as the set a replay checks a download
    /// against.
    fn from(digest: Digest) -> Digests {
        match digest.algorithm() {
            Algorithm::Sha256 => Digests {
                sha256: Some(digest),
                sha512: None,
            },
            Algorithm::Sha512 => Digests {
                sha256: None,
                sha512: Some(digest),
            },
        }
    }
}

impl Digests {
    /// The digests a record states in its `SHA256` and `SHA512` fields.
    ///
    /// `Ok(None)` where it states neither. A stated digest that is not
    /// lowercase hex of its algorithm's width is an error naming its field, so
    /// a record carrying one is refused rather than read as carrying none.
    pub(crate) fn from_fields(
        sha256: Option<&str>,
        sha512: Option<&str>,
    ) -> Result<Option<Digests>, &'static str> {
        let checked = |algorithm: Algorithm, value: Option<&str>| match value {
            Some(value) => Digest::new(algorithm, value)
                .map(Some)
                .ok_or(field_name(algorithm)),
            None => Ok(None),
        };
        let sha256 = checked(Algorithm::Sha256, sha256)?;
        let sha512 = checked(Algorithm::Sha512, sha512)?;
        Ok((sha256.is_some() || sha512.is_some()).then_some(Digests { sha256, sha512 }))
    }

    /// Each recorded digest with the field name the archive spells its
    /// algorithm under, SHA-256 first.
    pub(crate) fn each(&self) -> impl Iterator<Item = (&'static str, &Digest)> {
        [&self.sha256, &self.sha512]
            .into_iter()
            .flatten()
            .map(|digest| (field_name(digest.algorithm()), digest))
    }

    /// The recorded digest under `algorithm`, if the archive records one.
    pub(crate) fn under(&self, algorithm: Algorithm) -> Option<&Digest> {
        match algorithm {
            Algorithm::Sha256 => self.sha256.as_ref(),
            Algorithm::Sha512 => self.sha512.as_ref(),
        }
    }

    /// The digest a plan records for a package with these digests: the
    /// SHA-256 where the archive records one, and otherwise the SHA-512.
    ///
    /// The SHA-256 first, so a plan resolved against an archive recording
    /// both, as Ubuntu's do, reads as one resolved against Debian's, and
    /// names the cache entry an earlier run left.
    pub(crate) fn planned(&self) -> &Digest {
        self.each()
            .next()
            .map(|(_, digest)| digest)
            .expect("a value of this type records at least one digest")
    }

    /// The strongest recorded digest with the field name it is spelled under:
    /// the SHA-512 where there is one, and otherwise the SHA-256.
    ///
    /// What an index is asked for by under `by-hash`, as apt asks for one.
    pub(crate) fn strongest(&self) -> (&'static str, &Digest) {
        self.each()
            .last()
            .expect("a value of this type records at least one digest")
    }

    /// Holds `bytes` to every recorded digest.
    pub(crate) fn check_bytes(&self, bytes: &[u8]) -> Result<(), Mismatch<'_>> {
        self.each()
            .map(|(_, expected)| (expected, expected.algorithm().hex_of(bytes)))
            .try_for_each(|(expected, actual)| Mismatch::unless(expected, actual))
    }

    /// Holds everything `reader` yields to every recorded digest, reading it
    /// once.
    pub(crate) fn check_stream(
        &self,
        reader: &mut impl Read,
    ) -> io::Result<Result<(), Mismatch<'_>>> {
        let recorded: Vec<&Digest> = self.each().map(|(_, digest)| digest).collect();
        let algorithms: Vec<Algorithm> = recorded.iter().map(|digest| digest.algorithm()).collect();
        let (actual, _) = digest::stream_each(&algorithms, reader)?;
        Ok(recorded
            .into_iter()
            .zip(actual)
            .try_for_each(|(expected, actual)| Mismatch::unless(expected, actual)))
    }
}

#[cfg(test)]
impl Digests {
    /// The digests from a SHA-256 and a SHA-512 a test states, either of which
    /// may be absent, or `None` where both are.
    pub(crate) fn new(sha256: Option<String>, sha512: Option<String>) -> Option<Digests> {
        Digests::from_fields(sha256.as_deref(), sha512.as_deref()).expect("well-formed digests")
    }

    /// The recorded SHA-256, as lowercase hex.
    pub(crate) fn sha256(&self) -> Option<&str> {
        self.sha256.as_ref().map(Digest::hex)
    }

    /// The recorded SHA-512, as lowercase hex.
    pub(crate) fn sha512(&self) -> Option<&str> {
        self.sha512.as_ref().map(Digest::hex)
    }
}

/// A recorded digest the bytes did not match: the first, SHA-256 first.
#[derive(Debug)]
pub(crate) struct Mismatch<'a> {
    /// The digest the archive recorded.
    pub(crate) expected: &'a Digest,
    /// The digest the bytes have under the same algorithm, lowercase hex.
    pub(crate) actual: String,
}

impl<'a> Mismatch<'a> {
    /// `Ok` where `actual` is `expected`, and the mismatch otherwise.
    fn unless(expected: &'a Digest, actual: String) -> Result<(), Mismatch<'a>> {
        if actual == expected.hex() {
            Ok(())
        } else {
            Err(Mismatch { expected, actual })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn empty_sha512() -> String {
        Algorithm::Sha512.hex_of(b"")
    }

    fn digests(sha256: Option<&str>, sha512: Option<&str>) -> Digests {
        Digests::from_fields(sha256, sha512)
            .expect("both are well formed")
            .expect("one is given")
    }

    #[test]
    fn a_plan_records_the_sha256_where_there_is_one() {
        let sha512 = empty_sha512();
        let alone = digests(None, Some(&sha512));
        assert_eq!(alone.planned().hex(), sha512);
        assert_eq!(alone.strongest().0, "SHA512");
        let both = digests(Some(EMPTY_SHA256), Some(&sha512));
        assert_eq!(both.planned().algorithm(), Algorithm::Sha256);
        assert_eq!(both.strongest().0, "SHA512");
        assert_eq!(
            both.under(Algorithm::Sha512).map(Digest::hex),
            Some(sha512.as_str())
        );
        assert_eq!(
            Digests::from(both.planned().clone()),
            digests(Some(EMPTY_SHA256), None)
        );
    }

    #[test]
    fn every_recorded_digest_is_checked() {
        let sha512 = empty_sha512();
        let both = digests(Some(EMPTY_SHA256), Some(&sha512));
        both.check_bytes(b"").expect("both match");
        both.check_stream(&mut &b""[..])
            .unwrap()
            .expect("both match");

        // Either one wrong refuses the bytes, as apt refuses them.
        let wrong256 = "0".repeat(64);
        let bad256 = digests(Some(&wrong256), Some(&sha512));
        assert_eq!(
            bad256.check_bytes(b"").unwrap_err().expected.hex(),
            wrong256
        );
        assert!(bad256.check_stream(&mut &b""[..]).unwrap().is_err());
        let bad512 = digests(Some(EMPTY_SHA256), Some(&"0".repeat(128)));
        assert!(bad512.check_bytes(b"").is_err());
        assert!(bad512.check_stream(&mut &b""[..]).unwrap().is_err());
    }

    #[test]
    fn a_stated_digest_of_the_wrong_shape_is_named() {
        let read = Digests::from_fields;
        assert_eq!(read(None, None), Ok(None));
        assert_eq!(read(Some("AB"), None), Err("SHA256"));
        assert_eq!(read(Some(EMPTY_SHA256), Some(EMPTY_SHA256)), Err("SHA512"));
        assert!(read(None, Some(&empty_sha512())).unwrap().is_some());
        assert_eq!(
            read(Some(&EMPTY_SHA256.to_uppercase()), None),
            Err("SHA256")
        );
    }
}
