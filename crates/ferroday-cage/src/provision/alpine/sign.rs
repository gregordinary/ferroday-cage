//! Signature verification: the `.SIGN.` member, and the key it names.
//!
//! An apk container's first segment holds one tar member per signature — every
//! published artifact carries one, and a key rotation is what makes it more —
//! whose *name* carries the whole scheme:
//!
//! ```text
//! .SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub
//! ^^^^^ ^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//! fixed  |  the key that made it
//!        the algorithm, which names the digest
//! ```
//!
//! and whose contents are the signature itself: PKCS#1 v1.5 over the *raw
//! compressed bytes of the following segment*. Not the file, not the
//! decompressed form, and not the segment the member sits in.
//!
//! # What this chain rests on
//!
//! Alpine publishes `.SIGN.RSA.`, which is SHA-1. The format defines
//! `.SIGN.RSA256.` and `.SIGN.RSA512.` for stronger digests, and this reader
//! refuses both by name; see [`Algorithm`] for why. So an index is bound to its
//! signing key by RSA-4096 over SHA-1, and a package is bound to that index by
//! SHA-1 again, through the `C:` field. Only the last link — a package's control
//! segment to its file tree, through `.PKGINFO`'s `datahash` — is SHA-256.
//!
//! There is nothing stronger available in the published format, and verifying
//! less than `apk` does would be worse rather than safer, so the layer verifies
//! exactly this and the guide states the ceiling plainly. Forging a package
//! against it requires a chosen-prefix SHA-1 collision whose second preimage is
//! a well-formed gzip of a tar of a `.PKGINFO`: expensive, but no longer
//! theoretical.
//!
//! # Which signatures are part of that chain
//!
//! Only an index's. A package's own signature is read for what it names and is
//! not verified, because the chain above already fixes the bytes it covers: `C:`
//! is a digest of exactly the segment the signature is taken over, and it
//! arrives under the index signature or in a plan. The signature itself sits in
//! the segment *before* that one, which no digest in the format accounts for, so
//! whoever served the file may replace it freely and nothing downstream would
//! differ.
//!
//! This is `apk`'s rule rather than a relaxation of it, and it was measured: a
//! root trusting only postmarketOS's index key installs postmarketOS packages,
//! which are signed by per-builder keys published as a trust anchor nowhere,
//! while the same package offered to `apk add` as a bare file — where no index
//! vouches for it and its own signature is all there is — is refused as
//! `UNTRUSTED signature`. This layer installs from an index or from a plan and
//! never from a bare file, so the first rule is the one that applies to it.
//!
//! See [`Anchor`](super::apk::Anchor), which is where a caller states which of
//! the two it holds a container to.

use rsa::pkcs1v15::Pkcs1v15Sign;
use sha1::{Digest as _, Sha1};

use super::AlpineError;
use super::apk::Member;
use super::keyring::KeySet;

/// The prefix every signature member's name carries.
const SIGN_PREFIX: &str = ".SIGN.";

/// The tag an apk identity carries before its base64: a SHA-1, and the only
/// digest the format spells this way. An index's `C:` field and apk's file
/// checksums both carry it.
pub(super) const IDENTITY_PREFIX: &str = "Q1";

/// The tag the same digest carries when it is spelled in hexadecimal, which is
/// how the installed database's script archive names a package.
const IDENTITY_HEX_PREFIX: &str = "X1";

/// The identity apk gives a package's control segment: `Q1` and the base64 of
/// its SHA-1.
///
/// This is the value an index record's `C:` field carries, and recomputing it
/// over what a mirror served is what binds a downloaded package to the index
/// that named it. `payload` is the segment's *raw compressed bytes*, as they
/// lie in the file — the same payload the signature covers.
pub(super) fn control_identity(payload: &[u8]) -> String {
    identity(Sha1::digest(payload).as_slice())
}

/// The same spelling over a SHA-1 that is already in hand: `Q1` and its base64.
///
/// An installed-database record identifies every file it lists this way, and
/// those digests arrive from the package's own archive rather than from a
/// payload this crate hashes, so the two callers meet here rather than each
/// spelling the prefix.
pub(super) fn identity(digest: &[u8]) -> String {
    format!("{IDENTITY_PREFIX}{}", base64(digest))
}

/// The same identity in hexadecimal: `X1` and the SHA-1.
///
/// The installed database's `scripts.tar` names each member
/// `<package>-<version>.<this>.<script>`, and apk reads the package back out of
/// that name, so the spelling is the format's rather than a choice.
pub(super) fn control_identity_hex(payload: &[u8]) -> String {
    format!(
        "{IDENTITY_HEX_PREFIX}{}",
        crate::provision::digest::hex(Sha1::digest(payload).as_slice()),
    )
}

/// The `Q1` identity an `X1` spelling names, or `None` for anything but `X1`
/// and the forty lowercase hex digits of a SHA-1.
///
/// The inverse of [`control_identity_hex`]'s spelling. The installed database
/// names a package by `Q1`, and its script archive names the same package by
/// `X1`, so a reader holding one of each compares them as one identity, which
/// is how `apk` itself finds the record an archived script belongs to.
pub(super) fn identity_of_hex(spelled: &str) -> Option<String> {
    let hex = spelled.strip_prefix(IDENTITY_HEX_PREFIX)?.as_bytes();
    if hex.len() != 2 * Sha1::output_size() {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let digest = hex
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| Some((nibble(high)? << 4) | nibble(low)?))
        .collect::<Option<Vec<u8>>>()?;
    Some(identity(&digest))
}

/// Encodes `bytes` as base64, RFC 4648 section 4: the standard alphabet, and
/// padded.
///
/// Written here rather than taken from a crate because it is twenty lines and
/// this is the workspace's only caller — irongall decodes the OpenPGP side's
/// armor itself, and every other digest the crate renders is hexadecimal.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let mut packed = 0u32;
        for (at, byte) in group.iter().enumerate() {
            packed |= u32::from(*byte) << (16 - 8 * at);
        }
        // One output character per six bits of input, and a pad character for
        // each whole character the group has no bits for.
        for at in 0..=group.len() {
            out.push(ALPHABET[(packed >> (18 - 6 * at)) as usize & 0x3f] as char);
        }
        for _ in group.len()..3 {
            out.push('=');
        }
    }
    out
}

/// The digest an apk signature is taken over, named by the signature member.
///
/// Only one variant exists, and that is the point: the enum is here so that an
/// algorithm the reader does not implement is refused *by name*, with the
/// reason, rather than silently treated as the one it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    /// `.SIGN.RSA.`: PKCS#1 v1.5 over SHA-1. What Alpine and postmarketOS
    /// publish.
    RsaSha1,
}

impl Algorithm {
    /// The algorithm `token` names, or `None` for one this reader does not
    /// implement.
    ///
    /// `RSA256` and `RSA512` are defined by the format and refused here. They
    /// are not published for any release, and implementing them would put a
    /// second, older generation of `sha2` into an `alpine`-only build purely
    /// for a DER prefix: the crate's own SHA-256 is `sha2` 0.11 on `digest`
    /// 0.11, while `rsa` 0.9 needs a digest on `digest` 0.10. When a repository
    /// publishes one, that cost becomes worth paying and this is where it is
    /// paid.
    fn parse(token: &str) -> Option<Algorithm> {
        match token {
            "RSA" => Some(Algorithm::RsaSha1),
            _ => None,
        }
    }
}

/// A signature read out of a container's first segment: what made it, and over
/// what digest.
#[derive(Debug)]
pub(super) struct Signature {
    /// The key name the member's own name carries.
    key: String,
    /// The algorithm token the member's name carries, kept as it was spelled so
    /// that one this reader does not implement can be refused by name.
    token: String,
    /// The algorithm that token names, where this reader implements it.
    ///
    /// An unimplemented one is not refused here, because a container anchored by
    /// its control identity never reads this signature at all and an algorithm
    /// nothing consults is no reason to refuse a package. [`Signature::verify`]
    /// refuses it, which is every path that would have used it.
    algorithm: Option<Algorithm>,
    bytes: Vec<u8>,
}

impl Signature {
    /// The name of the key that made this signature, as the repository
    /// publishes the key.
    pub(super) fn key(&self) -> &str {
        &self.key
    }

    /// Reads one `.SIGN.<algorithm>.<key>` member.
    ///
    /// `subject` names what is being verified, for the error.
    fn parse(subject: &str, member: &Member) -> Result<Signature, AlpineError> {
        let Some(rest) = member.name.strip_prefix(SIGN_PREFIX) else {
            return Err(AlpineError::signature(
                subject,
                format!(
                    "its first segment holds {}, which is not a signature member",
                    member.name,
                ),
            ));
        };
        let Some((token, key)) = rest.split_once('.') else {
            return Err(AlpineError::signature(
                subject,
                format!("the signature member {} names no key", member.name),
            ));
        };
        Ok(Signature {
            key: key.to_string(),
            token: token.to_string(),
            algorithm: Algorithm::parse(token),
            bytes: member.data.clone(),
        })
    }

    /// Verifies this signature over `payload` against `keys`.
    ///
    /// `payload` is the *raw compressed bytes* of the segment that follows the
    /// signature segment — the control segment of a package, or the record
    /// segment of an index.
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Signature`] where the algorithm is one this reader
    /// does not implement, where the key set does not hold the named key, or
    /// where the signature does not verify against it.
    pub(super) fn verify(
        &self,
        subject: &str,
        keys: &KeySet,
        payload: &[u8],
    ) -> Result<(), AlpineError> {
        let Some(algorithm) = self.algorithm else {
            return Err(AlpineError::signature(
                subject,
                format!(
                    "the signature algorithm {} is not one this reader implements",
                    self.token,
                ),
            ));
        };
        let Some(key) = keys.get(&self.key) else {
            return Err(AlpineError::signature(
                subject,
                format!(
                    "it is signed by {}, which is not a key this repository trusts (held: {})",
                    self.key,
                    if keys.is_empty() {
                        "none".to_string()
                    } else {
                        keys.names().collect::<Vec<_>>().join(", ")
                    },
                ),
            ));
        };

        let Algorithm::RsaSha1 = algorithm;
        let digest = Sha1::digest(payload);
        key.verify(Pkcs1v15Sign::new::<Sha1>(), &digest, &self.bytes)
            .map_err(|err| {
                AlpineError::signature(
                    subject,
                    format!("its signature by {} does not verify: {err}", self.key),
                )
            })
    }
}

/// Every signature a container's first segment carries, in the order it carries
/// them.
///
/// A segment usually holds one member, and every artifact Alpine and
/// postmarketOS publish today holds exactly one. It may hold several: that is
/// what an artifact signed during a key rotation looks like, one member per key,
/// so that readers holding either key can verify it. Refusing such a segment
/// would refuse a container `apk` reads, and reading only its first member would
/// refuse one whose first signature happens to be by the key this reader does
/// not hold.
#[derive(Debug)]
pub(super) struct Signatures(Vec<Signature>);

impl Signatures {
    /// Reads a container's signature segment.
    ///
    /// `segment` is that segment's members, of which there is at least one and
    /// every one is a `.SIGN.<algorithm>.<key>`. `subject` names what is being
    /// verified, for the errors.
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Signature`] where the segment is empty or holds a
    /// member that is not a signature. An algorithm this reader does not
    /// implement is carried rather than refused, and refused by
    /// [`verify`](Self::verify) — and only where no other member verified.
    pub(super) fn parse(subject: &str, segment: &[Member]) -> Result<Signatures, AlpineError> {
        if segment.is_empty() {
            return Err(AlpineError::signature(
                subject,
                "its signature segment holds no members".to_string(),
            ));
        }
        segment
            .iter()
            .map(|member| Signature::parse(subject, member))
            .collect::<Result<Vec<_>, _>>()
            .map(Signatures)
    }

    /// The key the first member names, for a container nothing verifies.
    ///
    /// Only [`Anchor::ControlIdentity`](super::apk::Anchor::ControlIdentity)
    /// reaches this: the segment is read so the container's shape is known, and
    /// its signature is not what binds the package. The key that *verified* is
    /// [`verify`](Self::verify)'s answer, and that is the one a plan records.
    pub(super) fn first_key(&self) -> &str {
        self.0
            .first()
            .expect("a signature segment holds at least one member")
            .key()
    }

    /// Verifies `payload` against `keys`, answering with the signature that did.
    ///
    /// The members are tried in order and the first that both names a held key
    /// and verifies is the answer, which is `apk`'s own rule. A member naming a
    /// key the repository does not trust is passed over rather than refused —
    /// that is the whole of what makes a rotation-era container readable — so a
    /// segment nothing verifies is reported against the last member that got as
    /// far as being checked, and against the whole segment where none did.
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Signature`] where no member verifies: naming the
    /// failure of the last one that could be attempted, or reporting that no
    /// member names a key this repository holds.
    pub(super) fn verify(
        &self,
        subject: &str,
        keys: &KeySet,
        payload: &[u8],
    ) -> Result<&Signature, AlpineError> {
        let mut attempted = None;
        for signature in &self.0 {
            if signature.algorithm.is_none() || keys.get(&signature.key).is_none() {
                // Kept as the failure to report only where nothing else is
                // tried, so a rotation-era container whose other member verifies
                // does not report this one.
                attempted.get_or_insert_with(|| signature.verify(subject, keys, payload));
                continue;
            }
            match signature.verify(subject, keys, payload) {
                Ok(()) => return Ok(signature),
                Err(err) => attempted = Some(Err(err)),
            }
        }
        match attempted {
            Some(Err(err)) => Err(err),
            // Every member both named a held key and verified, which the loop
            // above returns from, so this is unreachable; it is written as an
            // error rather than a panic because a `Signatures` is built from
            // whatever a mirror served.
            _ => Err(AlpineError::signature(
                subject,
                "its signature segment holds no member that could be checked".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::alpine::fixtures;

    #[test]
    fn the_encoder_agrees_with_rfc_4648() {
        // The section 10 test vectors, which is where the padding cases are.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded, "{plain:?}");
        }
        // And the whole alphabet, so a transposed table is caught.
        let all: Vec<u8> = (0u8..=255).collect();
        assert!(base64(&all).starts_with("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"));
    }

    #[test]
    fn a_control_identity_is_the_one_the_published_index_records() {
        // The chain's second link, checked against the archive rather than
        // against this crate: `C:` is what an index states for a package, and
        // the value here is recomputed from the package's own bytes.
        let mut segments = crate::provision::alpine::apk::Segments::new(fixtures::MUSL);
        let keys = crate::provision::alpine::KeySet::alpine("x86_64").expect("x86_64 is bundled");
        let metadata = crate::provision::alpine::apk::read_metadata(
            "musl",
            &mut segments,
            crate::provision::alpine::apk::Anchor::Signature(&keys),
            1 << 24,
        )
        .expect("the fixture verifies");
        assert_eq!(
            control_identity(&metadata.compressed),
            "Q1G2xQQm08BlbpxaVnpaWWAcf0MHo=",
        );
        assert_eq!(
            control_identity_hex(&metadata.compressed),
            "X11b6c50426d3c0656e9c5a567a5a59601c7f4307a",
        );
    }

    #[test]
    fn an_x1_spelling_names_the_identity_its_q1_spelling_does() {
        assert_eq!(
            identity_of_hex("X11b6c50426d3c0656e9c5a567a5a59601c7f4307a").as_deref(),
            Some("Q1G2xQQm08BlbpxaVnpaWWAcf0MHo="),
        );
        // Only the spelling apk writes: its prefix, lowercase, a SHA-1's length.
        for spelled in [
            "Q11b6c50426d3c0656e9c5a567a5a59601c7f4307a",
            "X11B6C50426D3C0656E9C5A567A5A59601C7F4307A",
            "X11b6c50426d3c0656e9c5a567a5a59601c7f4307",
            "X11b6c50426d3c0656e9c5a567a5a59601c7f4307a0",
            "X11b6c50426d3c0656e9c5a567a5a59601c7f4307g",
            "",
        ] {
            assert_eq!(identity_of_hex(spelled), None, "{spelled}");
        }
    }
}
