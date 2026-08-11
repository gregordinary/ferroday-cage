//! The signed digest document beside a build: what the tarball's bytes must
//! hash to.
//!
//! A `.DIGESTS` file sits beside every published stage3 and is itself a
//! cleartext-signed OpenPGP message. It records two algorithms over two files —
//! the tarball and its `.CONTENTS.gz` sidecar — as a header line naming the
//! algorithm followed by the digest and the file it belongs to:
//!
//! ```text
//! # SHA512 HASH
//! 1264a5a2...b99415  stage3-amd64-openrc-20260810T204554Z.tar.xz
//! # BLAKE2B HASH
//! 3fde3566...91accc  stage3-amd64-openrc-20260810T204554Z.tar.xz
//! # SHA512 HASH
//! 26e8184b...f7f7578  stage3-amd64-openrc-20260810T204554Z.tar.xz.CONTENTS.gz
//! ```
//!
//! SHA-512 is taken and BLAKE2B ignored: the document carries both, one
//! suffices, and reading the second would add a dependency to strengthen
//! nothing.
//!
//! There is also a `.sha256` sidecar beside each tarball, and it is a trap. It
//! is not named in this document, nothing signs it, and reading it would leave
//! the chain resting on an unauthenticated file. It is never fetched.

use super::GentooError;
use crate::provision::digest::Algorithm;

/// The header token naming the algorithm this layer reads.
const SHA512: &str = "SHA512";

/// The SHA-512 the document records for `file`, as lowercase hex.
///
/// The algorithm alone does not select a line: the document records SHA-512 for
/// the tarball *and* for its sidecar, so a reader keying on the algorithm would
/// take whichever came first and hold the tarball to the sidecar's digest. The
/// file name decides which line is wanted, and the header decides which
/// algorithm, so neither the order of the pairs nor the order within one is
/// relied on.
///
/// The value is held to [`Algorithm::Sha512::is_hex`](Algorithm::is_hex) before
/// it is returned. A digest out of a document is compared against bytes and, in
/// other layers, becomes a path segment; holding it to a shape at the boundary
/// is what keeps every comparison in the crate a plain `==` and keeps a digest
/// from reaching anywhere as something other than a digest.
///
/// `subject` names the document in a refusal.
pub(super) fn sha512_of(subject: &str, body: &str, file: &str) -> Result<String, GentooError> {
    let mut algorithm = None;
    for line in body.lines() {
        let line = line.trim();
        if let Some(header) = line.strip_prefix('#') {
            // `# <ALGO> HASH`, read by its algorithm token so that spacing and
            // any trailing words are not part of the grammar.
            algorithm = header.split_whitespace().next().map(str::to_string);
            continue;
        }
        if algorithm.as_deref() != Some(SHA512) {
            continue;
        }
        let mut fields = line.split_whitespace();
        if let (Some(digest), Some(named), None) = (fields.next(), fields.next(), fields.next())
            && named == file
            && Algorithm::Sha512.is_hex(digest)
        {
            return Ok(digest.to_string());
        }
    }
    Err(GentooError::document(
        subject,
        format!("it records no usable SHA-512 for {file}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four records the archive publishes, in the order it publishes them.
    fn body() -> String {
        format!(
            "# SHA512 HASH\n{tarball}  s.tar.xz\n\
             # BLAKE2B HASH\n{blake}  s.tar.xz\n\
             # SHA512 HASH\n{sidecar}  s.tar.xz.CONTENTS.gz\n\
             # BLAKE2B HASH\n{blake}  s.tar.xz.CONTENTS.gz\n",
            tarball = "1".repeat(128),
            sidecar = "2".repeat(128),
            blake = "3".repeat(128),
        )
    }

    #[test]
    fn the_filename_decides_which_record_is_read() {
        // The defect this exists to refuse: the algorithm alone selects two
        // lines, and the sidecar's is the wrong one. Holding a 500 MB tarball to
        // the digest of a one-megabyte file index would fail every provision.
        assert_eq!(
            sha512_of("the digests", &body(), "s.tar.xz").unwrap(),
            "1".repeat(128),
        );
        assert_eq!(
            sha512_of("the digests", &body(), "s.tar.xz.CONTENTS.gz").unwrap(),
            "2".repeat(128),
        );
    }

    #[test]
    fn blake2b_is_ignored_wherever_it_sits() {
        // One algorithm suffices and the other would cost a dependency, so the
        // header has to decide rather than position. The pairs are reordered
        // here so that a reader taking the first digest line would take BLAKE2B.
        let reordered = format!(
            "# BLAKE2B HASH\n{blake}  s.tar.xz\n# SHA512 HASH\n{sha}  s.tar.xz\n",
            blake = "3".repeat(128),
            sha = "1".repeat(128),
        );
        assert_eq!(
            sha512_of("the digests", &reordered, "s.tar.xz").unwrap(),
            "1".repeat(128),
        );
        // A document offering only BLAKE2B records nothing this layer can use.
        let blake_only = format!("# BLAKE2B HASH\n{}  s.tar.xz\n", "3".repeat(128));
        assert!(sha512_of("the digests", &blake_only, "s.tar.xz").is_err());
    }

    #[test]
    fn a_digest_that_is_not_one_hundred_and_twenty_eight_lowercase_hex_is_refused() {
        // The boundary a repository-supplied digest passes: what comes back is
        // held to a shape before anything is compared against it.
        for spelling in [
            "1".repeat(127),
            "1".repeat(129),
            "A".repeat(128),
            "../../../etc/passwd".to_string(),
            "z".repeat(128),
        ] {
            let body = format!("# SHA512 HASH\n{spelling}  s.tar.xz\n");
            let err = sha512_of("the digests", &body, "s.tar.xz")
                .expect_err("a malformed digest is refused");
            assert!(matches!(err, GentooError::Document { .. }), "{spelling}");
        }
    }

    #[test]
    fn a_document_naming_another_build_records_nothing_for_this_one() {
        // The pairing between a build and its digests is the file name, so a
        // document served for a different build supplies no digest rather than
        // supplying the wrong one.
        let err = sha512_of("the digests", &body(), "other.tar.xz")
            .expect_err("the document names no such file");
        assert!(err.to_string().contains("other.tar.xz"), "{err}");
    }
}
