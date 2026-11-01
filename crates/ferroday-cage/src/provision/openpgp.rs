//! Is this cleartext-signed document authentic against this keyring?
//!
//! One question, asked by every archive whose trust chain begins with an
//! OpenPGP signature: a keyring of public certificates, a document carrying the
//! signature inline, and a body that is worth acting on only once the signature
//! over it verifies. Debian asks it of an `InRelease`; the answer is nobody's in
//! particular, so it lives here rather than inside the layer that asked first.
//!
//! irongall answers it: it reads the keyring and the document, verifies the
//! signatures, and judges what each is worth -- whether the key that made it
//! was allowed to, was in force at the time, and rests on algorithms worth a
//! trust decision. Its `policy` module records the rules. What this module adds
//! is the bounds a document is held to before any of it is read, the policy
//! settings this crate chooses, and the shape the layers consume.

use irongall::cert;
use irongall::document;
use irongall::keyring::Refusal;
use irongall::packet::PacketError;
#[cfg(feature = "gentoo")]
use irongall::policy::Authority;
use irongall::policy::{Policy, Reason};

use crate::provision::now_epoch;

/// The largest signed document [`Keyring::verify`] reads, in bytes, and the
/// ceiling a layer fetches an unsized signed document under.
///
/// A trust root has nothing signed to declare its length, so what bounds one
/// is a ceiling of this crate's choosing, and every layer that fetches one
/// uses this ceiling or a tighter one of its own. The largest such document an
/// archive serves is Ubuntu's release file, at about 250 KB; Debian's are under
/// 200 KB. One mebibyte is four times the first. A document past it is refused
/// whole, never read short.
pub(crate) const MAX_SIGNED_DOCUMENT_BYTES: u64 = 1024 * 1024;

/// The most signatures a signed document may carry.
///
/// Each signature is hashed over the whole document and checked against every
/// key in the keyring it might have been made with, which is every key when
/// its issuer subpackets name none. A Debian release carries two or three
/// signatures, one per archive key in rotation.
///
/// irongall's default policy bounds a document to the same count. The bound
/// is stated here regardless, since it is this crate's documented one, and a
/// change to that default must not move it.
const MAX_DOCUMENT_SIGNATURES: usize = 16;

/// A failure establishing a document's authenticity.
///
/// The two halves of the question, kept apart because a caller can act on the
/// difference: a keyring that will not parse is a packaging or transport fault
/// on this side, while a signature that will not verify is a statement about
/// what the archive served.
///
/// Each layer wraps this in its own error rather than sharing one, for the
/// reason [`coordinate::check`](crate::provision::coordinate::check) records:
/// the layers do not share an error type.
#[derive(Debug)]
pub(crate) enum OpenPgpError {
    /// The keyring could not be parsed.
    Keyring(String),
    /// No signature on the document was acceptable: either none verified
    /// against a key in the keyring, or one that did was refused under the
    /// policy, with the reason irongall gives. A document past the bounds
    /// verification is held to is refused the same way, before any signature
    /// on it is examined.
    Signature(String),
}

impl std::fmt::Display for OpenPgpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenPgpError::Keyring(reason) | OpenPgpError::Signature(reason) => f.write_str(reason),
        }
    }
}

/// The policy every document is judged under: irongall's defaults, with the
/// signature count this crate bounds a document to, and the freshness the
/// caller asks for.
///
/// The defaults are the rules this crate holds a trust decision to: SHA-2
/// and SHA-3, RSA from 2048 bits, Ed25519, text signatures accepted.
fn policy(require_fresh: bool) -> Policy {
    Policy::new()
        .with_max_signatures(MAX_DOCUMENT_SIGNATURES)
        .with_fresh_signatures(require_fresh)
}

/// The time a judgement is made at, in seconds since the epoch, or `None` on a
/// clock that reads before it.
fn now() -> Option<u64> {
    now_epoch().and_then(|now| u64::try_from(now).ok())
}

/// The trust anchor: the certificates a document's signature may be made with.
pub(crate) struct Keyring {
    certificates: irongall::keyring::Keyring,
}

impl Keyring {
    /// Parses a binary keyring of concatenated public keys.
    ///
    /// No certificate is judged here. A revoked one is kept, and
    /// [`verify`](Self::verify) refuses a signature it made, naming the
    /// revocation and the key. So is an expired one, even for a signature
    /// dated while it was in force: the date is its signer's claim.
    ///
    /// A keyring holding no key whose signatures can be verified at all is
    /// refused: one that is empty, or whose every key is of an algorithm
    /// irongall does not verify with, such as DSA, could vouch for nothing.
    /// That is a property of the keys alone, so asking it verifies no
    /// signature.
    ///
    /// One certificate that fails to parse fails the whole keyring, where `gpg`
    /// would skip the bad entry and use the rest. irongall already reads a key
    /// of a version or algorithm it does not implement as opaque, so an error
    /// surviving to here means the bytes are damaged rather than exotic. A
    /// damaged keyring is a packaging or transport fault worth telling the
    /// caller about directly; continuing with silently fewer trust anchors
    /// would report it much later, as an archive whose signature does not
    /// verify.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Keyring, OpenPgpError> {
        let certificates: irongall::keyring::Keyring = cert::certificates(bytes)
            .collect::<Result<_, _>>()
            .map_err(|err| OpenPgpError::Keyring(err.to_string()))?;
        let policy = policy(true);
        let verifiable = certificates
            .certificates()
            .iter()
            .flat_map(|certificate| {
                std::iter::once(certificate.primary())
                    .chain(certificate.subkeys().iter().map(|subkey| subkey.key()))
            })
            .any(|key| policy.accepts_key(key));
        if !verifiable {
            return Err(OpenPgpError::Keyring(
                "the keyring holds no key whose signatures can be verified".to_string(),
            ));
        }
        Ok(Keyring { certificates })
    }

    /// Verifies a cleartext-signed document and returns its body.
    ///
    /// The signature must verify against at least one certificate in the
    /// keyring; signatures from keys the keyring does not hold are ignored, as
    /// apt does. A document may be signed by a certificate's primary key or by
    /// one of its signing subkeys -- Debian's archive automatic signing keys
    /// sign with a subkey -- and irongall's policy decides whether the key
    /// that made it may: see its `policy` module for the rules.
    ///
    /// The document is held to [`MAX_SIGNED_DOCUMENT_BYTES`] before any of it
    /// is read, and, once parsed, to [`MAX_DOCUMENT_SIGNATURES`] signatures. Unless
    /// `require_fresh` is cleared for a deliberately pinned snapshot, the
    /// signature must not itself have expired.
    ///
    /// The returned text is the signed body, with the cleartext framing removed
    /// and its lines joined with CR LF, in the form the signature covers.
    pub(crate) fn verify(
        &self,
        document: &[u8],
        require_fresh: bool,
    ) -> Result<Verified, OpenPgpError> {
        check_document_size(document)?;
        let message = document::cleartext(document)
            .map_err(|err| OpenPgpError::Signature(err.to_string()))?;
        // Every judgement is relative to the time it is made at, so a clock that
        // cannot say when that is cannot verify anything.
        let now = now().ok_or_else(|| {
            OpenPgpError::Signature(
                "the clock reads before the epoch, so no signature can be judged".to_string(),
            )
        })?;
        let verified = self
            .certificates
            .verify(
                &policy(require_fresh),
                now,
                message.signatures(),
                message.text(),
            )
            .map_err(|refusal| OpenPgpError::Signature(refused(&refusal, message.skipped())))?;
        let body = String::from_utf8(message.text().to_vec())
            .map_err(|_| OpenPgpError::Signature("the signed text is not UTF-8".to_string()))?;
        Ok(Verified {
            body,
            certificate: verified.certificate().primary().fingerprint().to_string(),
            signing_key: verified.key().fingerprint().to_string(),
        })
    }

    /// What each certificate in the keyring can still be trusted to do, and
    /// until when, in the order the keyring holds them.
    ///
    /// A vendored keyring is a trust anchor with a shelf life: every certificate
    /// in it expires, and once the ones that sign have, the layer resting on it
    /// stops being able to verify anything. Reporting the dates is how a caller
    /// learns that before an archive fetch does.
    ///
    /// The judgement is [`verify`](Self::verify)'s own rather than a second
    /// reading of the same certificates, which is what keeps the answer from
    /// drifting away from what verification would actually accept. See
    /// [`Horizon::expires`] for what the epoch is, and why it is not simply the
    /// primary's own expiry.
    ///
    /// A clock that reads before the epoch judges every certificate as of the
    /// epoch itself, before any of them existed, so each reports that it
    /// cannot sign: on such a clock [`verify`](Self::verify) refuses every
    /// document.
    #[cfg(feature = "gentoo")]
    pub(crate) fn horizon(&self) -> Vec<Horizon> {
        let policy = policy(true);
        let now = now().unwrap_or(0);
        self.certificates
            .certificates()
            .iter()
            .map(|certificate| Horizon::of(&Authority::new(certificate, &policy, now)))
            .collect()
    }
}

/// What one certificate of a keyring can still be trusted to do, and until when.
#[cfg(feature = "gentoo")]
pub(crate) struct Horizon {
    /// The primary key's fingerprint, uppercase hex.
    pub(crate) fingerprint: String,
    /// The certificate's primary user id, as it spells itself, or `None` where
    /// it carries none this crate can read: none that is UTF-8, or none whose
    /// certification by the certificate's own key irongall can verify.
    pub(crate) user_id: Option<String>,
    /// The epoch at which the certificate's authority lapses, or `None` when
    /// nothing bounds it.
    ///
    /// Where the certificate can sign, this is the last moment at which a
    /// signature from it would still be accepted: the latest lapse among the
    /// keys under it that [`Keyring::verify`] would take a signature from, each
    /// bounded by the primary's own expiry. That is not the primary's expiry
    /// alone -- a subkey's binding may lapse before the certificate does, and a
    /// certificate whose primary may not sign is worth only what its subkeys
    /// are.
    ///
    /// Where it cannot sign -- [`signs`](Self::signs) is `false` -- this is
    /// when the certificate itself lapses, whether or not that ever mattered,
    /// or `None` where the certificate grants nothing at all, so that no date of
    /// it is established: one whose primary key irongall does not verify with,
    /// or with no self-signature in force.
    pub(crate) expires: Option<i64>,
    /// Whether any key under the certificate could make a signature
    /// [`Keyring::verify`] would accept.
    pub(crate) signs: bool,
}

#[cfg(feature = "gentoo")]
impl Horizon {
    /// Reads one certificate's horizon off its authority.
    fn of(authority: &Authority<'_>) -> Horizon {
        // Every key under the certificate a signature could legitimately come
        // from, each with the epoch its authority lapses at.
        let lapses: Vec<Option<u64>> = authority
            .signers()
            .filter_map(|(_, standing)| standing.ok())
            .map(|window| window.expires())
            .collect();
        // The certificate keeps working while any one of them does, so the
        // latest governs. A key nothing bounds outlasts every epoch, which is
        // what makes an unbounded lapse win outright rather than compare as a
        // number. With none, what is left to report is the certificate's own.
        let expires = if lapses.is_empty() {
            authority.lapse().ok().flatten()
        } else if lapses.contains(&None) {
            None
        } else {
            lapses.iter().copied().flatten().max()
        };
        Horizon {
            fingerprint: authority.certificate().primary().fingerprint().to_string(),
            user_id: authority
                .primary_user_id()
                .and_then(|user_id| std::str::from_utf8(user_id.value()).ok())
                .map(str::to_string),
            expires: expires.and_then(|epoch| i64::try_from(epoch).ok()),
            signs: !lapses.is_empty(),
        }
    }
}

/// A document whose signature verified: the signed bytes, the certificate that
/// vouched for them, and the key within it that made the signature.
#[derive(Debug)]
pub(crate) struct Verified {
    /// The cleartext the signature covers — the document's own body, with the
    /// armor and the signature stripped.
    pub(crate) body: String,
    /// The verifying certificate's primary-key fingerprint, uppercase hex.
    ///
    /// The archive key's stable identity: it names the keyring entry, it is
    /// what a policy pinning an archive would pin, and it does not move when
    /// the certificate rotates its signing subkey.
    pub(crate) certificate: String,
    /// The fingerprint of the component key that made the signature, uppercase
    /// hex.
    ///
    /// The primary's own fingerprint when the primary signed, and the subkey's
    /// when a signing subkey did; equal to `certificate` in the first case.
    ///
    /// A layer that records only the stable identity a policy would pin has no
    /// use for it, and reports `certificate` alone.
    #[cfg_attr(not(feature = "debian"), allow(dead_code))]
    pub(crate) signing_key: String,
}

/// Why a document's signatures were refused: irongall's refusal, and, where no
/// signature verified at all, the signatures the cleartext reader passed over.
///
/// A binary or standalone signature on a cleartext document is no statement
/// about its text, so the reader sets it aside before any key is tried, and
/// irongall's refusal then says only that nothing verified, as it does for a
/// signature by a key the keyring does not hold. Naming the one passed over is
/// what tells the two apart.
fn refused(refusal: &Refusal, skipped: &[PacketError]) -> String {
    match skipped {
        [first, rest @ ..] if refusal.reason() == Reason::Unverified => {
            if rest.is_empty() {
                format!("{refusal}, and one signature was passed over: {first}")
            } else {
                format!(
                    "{refusal}, and {} signatures were passed over, the first: {first}",
                    skipped.len()
                )
            }
        }
        _ => refusal.to_string(),
    }
}

/// Refuses a document larger than [`Keyring::verify`] reads, before any of
/// it is read: the document as it arrived, armor and all.
fn check_document_size(document: &[u8]) -> Result<(), OpenPgpError> {
    if document.len() as u64 > MAX_SIGNED_DOCUMENT_BYTES {
        return Err(OpenPgpError::Signature(format!(
            "the document is {} bytes, over the {MAX_SIGNED_DOCUMENT_BYTES} a signed document may \
             be",
            document.len(),
        )));
    }
    Ok(())
}

/// Signed documents to verify, for the tests of the layers that read one.
///
/// A throwaway key generated in the test and a document clear-signed with it is
/// the only way to exercise a refusal: an archive publishes nothing that fails
/// its own chain, so a fixture that came from one can only ever prove the happy
/// path. The helpers are here rather than in each layer's test module because
/// what they build -- a signer, a signature, a keyring that holds it -- belongs
/// to the verification rather than to any archive's document format.
#[cfg(test)]
pub(crate) mod fixture {
    use pgp::composed::{
        CleartextSignedMessage, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
    };

    use super::Keyring;

    /// Generates a throwaway Ed25519 signing key with `user_id` as its primary
    /// user id.
    pub(crate) fn signing_key(user_id: &str) -> SignedSecretKey {
        SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(user_id.to_string())
            .build()
            .expect("valid key params")
            .generate(rand::thread_rng())
            .expect("key generation")
    }

    /// Clear-signs `body` with `key`'s primary key, producing an armored
    /// document of the shape an archive publishes.
    pub(crate) fn clearsign(key: &SignedSecretKey, body: &str) -> String {
        use pgp::types::Password;
        // A `SignedSecretKey` derefs to the `SecretKey` packet, which is the
        // signer.
        CleartextSignedMessage::sign(rand::thread_rng(), body, &**key, &Password::empty())
            .expect("signing")
            .to_armored_string(None.into())
            .expect("armoring")
    }

    /// A keyring trusting the public half of `key` and nothing else.
    ///
    /// Built through [`Keyring::parse`] over the serialized certificate rather
    /// than from the key value directly, so what a test verifies against came
    /// through the same reader a vendored keyring does -- binary, which is the
    /// form both vendored keyrings ship in.
    ///
    /// The Gentoo layer's tests are its only callers: a Debian `Release` is
    /// verified against a keyring a fixture builds through
    /// [`Keyring::parse`] itself, where a gpkg container's `Manifest` is
    /// verified through a `Keyring` the container fixture has to hand over. So
    /// a build without that feature has no caller, where its sibling
    /// [`clearsign`] has one in both layers.
    #[cfg_attr(not(feature = "gentoo"), allow(dead_code))]
    pub(crate) fn keyring(key: &SignedSecretKey) -> Keyring {
        keyring_of([key.to_public_key()])
    }

    /// A keyring trusting `certificates`, built as [`keyring`] builds one: rPGP
    /// writes them, and [`Keyring::parse`] reads them back.
    pub(crate) fn keyring_of(certificates: impl IntoIterator<Item = SignedPublicKey>) -> Keyring {
        Keyring::parse(&binary(certificates)).expect("the certificates parse")
    }

    /// The binary keyring of `certificates`, as rPGP writes them, for a test
    /// that reads it with [`Keyring::parse`] itself.
    pub(crate) fn binary(certificates: impl IntoIterator<Item = SignedPublicKey>) -> Vec<u8> {
        let mut binary = Vec::new();
        for certificate in certificates {
            pgp::ser::Serialize::to_writer(&certificate, &mut binary)
                .expect("serializing the certificate");
        }
        binary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixture::keyring_of;
    #[cfg(feature = "debian")]
    use irongall::cert::Certificate;
    use irongall::packet::PacketErrorKind;
    #[cfg(feature = "debian")]
    use irongall::policy::Authority;
    use pgp::composed::CleartextSignedMessage;
    #[cfg(feature = "debian")]
    use pgp::composed::{Deserializable, SignedPublicKey};
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::packet::{Signature, SignatureType, SubpacketData};
    use pgp::types::{Duration, KeyDetails, Timestamp};

    // The real archive keyring is the Debian layer's.
    #[cfg(feature = "debian")]
    #[test]
    fn embedded_keys_are_valid_and_unrevoked() {
        // The vendored keyring parses to a non-empty set of certificates, none
        // of them revoked or otherwise granting nothing, and the key-expiry
        // computation reads an expiration for every key that may sign — a bug
        // that misread the self-signatures would surface as a missing expiry
        // here. At least one key is still valid, so the keyring
        // can verify a current release; when that stops holding, the vendored
        // debian-archive-keyring has gone fully stale and must be refreshed.
        // (A single aged-out key is not a failure: expired keys are kept and
        // judged per signature at verify time.) This pins the key-validity
        // computation against the real keyring.
        let keyring = Keyring::parse(crate::provision::debian::EMBEDDED_KEYRING).unwrap();
        let now = now().expect("the clock is after the epoch");
        let certificates = keyring.certificates.certificates();
        assert!(!certificates.is_empty());
        let mut valid_now = 0;
        for certificate in certificates {
            let authority = Authority::new(certificate, &policy(true), now);
            assert!(
                authority.lapse().is_ok(),
                "{}: {:?}",
                certificate.primary().fingerprint(),
                authority.lapse(),
            );
            let lapses: Vec<u64> = authority
                .signers()
                .filter_map(|(_, standing)| standing.ok())
                .map(|window| {
                    window
                        .expires()
                        .expect("each archive key records a key-expiration time")
                })
                .collect();
            if lapses.iter().any(|lapse| *lapse > now) {
                valid_now += 1;
            }
        }
        assert!(
            valid_now > 0,
            "no embedded archive key is currently valid; refresh the vendored keyring",
        );
    }

    /// Generates a throwaway Ed25519 signing key with the given user id.
    #[cfg(test)]
    fn test_key(user_id: &str) -> pgp::composed::SignedSecretKey {
        fixture::signing_key(user_id)
    }

    /// Generates a throwaway Ed25519 signing key created at `created`, with
    /// `user_id` as its primary user id and `also` as any further ones. The
    /// creation time matters to the key-expiry tests, an expiration being a
    /// duration from it.
    #[cfg(test)]
    fn test_key_created_at(
        user_id: &str,
        created: Timestamp,
        also: &[&str],
    ) -> pgp::composed::SignedSecretKey {
        use pgp::composed::{KeyType, SecretKeyParamsBuilder};
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .can_certify(true)
            .created_at(created)
            .primary_user_id(user_id.to_string());
        for id in also {
            params.user_id(*id);
        }
        params
            .build()
            .expect("valid key params")
            .generate(rand::thread_rng())
            .expect("key generation")
    }

    /// Clear-signs `body` with `key`'s primary key, producing an armored
    /// InRelease document.
    #[cfg(test)]
    fn clearsign(key: &pgp::composed::SignedSecretKey, body: &str) -> String {
        fixture::clearsign(key, body)
    }

    /// Clear-signs `body` with an arbitrary signer — a primary key or a secret
    /// subkey — producing an armored InRelease document. Debian signs with a
    /// subkey, so the subkey tests reach for this rather than [`clearsign`].
    #[cfg(test)]
    fn clearsign_with(signer: &impl pgp::types::SigningKey, body: &str) -> String {
        use pgp::types::Password;
        CleartextSignedMessage::sign(rand::thread_rng(), body, signer, &Password::empty())
            .expect("signing")
            .to_armored_string(None.into())
            .expect("armoring")
    }

    /// Generates a throwaway cert whose Ed25519 primary certifies one Ed25519
    /// signing subkey created at `subkey_created`. This mirrors Debian's archive
    /// keys, which sign releases with a dedicated signing subkey rather than the
    /// primary.
    #[cfg(test)]
    fn test_key_with_signing_subkey(
        user_id: &str,
        subkey_created: pgp::types::Timestamp,
    ) -> pgp::composed::SignedSecretKey {
        use pgp::composed::{KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
        let signing_subkey = SubkeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .created_at(subkey_created)
            .build()
            .expect("valid signing subkey params");
        SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(user_id.to_string())
            .subkey(signing_subkey)
            .build()
            .expect("valid key params")
            .generate(rand::thread_rng())
            .expect("key generation")
    }

    #[test]
    fn a_good_signature_verifies_and_a_tampered_or_foreign_one_is_rejected() {
        // The hermetic Debian tests all take the unsigned path; this exercises
        // the verification path adversarially, without a network, so a
        // regression that accepted a tampered body or a foreign key's signature
        // is caught. A key not in the keyring stands in for an untrusted signer.
        let archive = test_key("archive <archive@test.invalid>");
        let foreign = test_key("foreign <foreign@test.invalid>");
        let body = "Suite: test\nComponents: main\nSHA256:\n abc 10 main/binary-amd64/Packages\n";

        // The keyring trusts only the archive key.
        let keyring = keyring_of([archive.to_public_key()]);

        // A good signature verifies and returns the signed body.
        let good = clearsign(&archive, body);
        let verified = keyring.verify(good.as_bytes(), false).expect("verifies");
        assert!(
            verified.body.contains("Suite: test"),
            "body was {verified:?}"
        );

        // A signature by a key the keyring does not hold is refused.
        let foreign_signed = clearsign(&foreign, body);
        assert!(
            matches!(
                keyring.verify(foreign_signed.as_bytes(), false),
                Err(OpenPgpError::Signature(_))
            ),
            "a foreign key's signature must not verify",
        );

        // A body altered after signing no longer matches the signature.
        let tampered = good.replace("Suite: test", "Suite: evil");
        assert_ne!(tampered, good, "the tamper must actually change the body");
        assert!(
            matches!(
                keyring.verify(tampered.as_bytes(), false),
                Err(OpenPgpError::Signature(_))
            ),
            "a tampered body must not verify",
        );
    }

    #[test]
    fn a_subkey_signed_release_verifies() {
        // The regression under test: Debian signs InRelease with a dedicated
        // signing subkey, not the primary. A release clear-signed by a cert's
        // signing subkey must verify against a keyring holding that cert — the
        // whole-archive case the primary-only path used to reject.
        let archive =
            test_key_with_signing_subkey("archive <archive@test.invalid>", Timestamp::now());
        let subkey_secret = archive.secret_subkeys.first().expect("a signing subkey");
        let body = "Suite: test\nComponents: main\nSHA256:\n abc 10 main/binary-amd64/Packages\n";
        let signed = clearsign_with(&**subkey_secret, body);

        let keyring = keyring_of([archive.to_public_key()]);
        let verified = keyring
            .verify(signed.as_bytes(), false)
            .expect("a subkey signature verifies");
        assert!(
            verified.body.contains("Suite: test"),
            "body was {verified:?}"
        );
    }

    // The real archive keyring is the Debian layer's.
    #[cfg(feature = "debian")]
    #[test]
    fn a_real_subkey_signed_debian_release_verifies() {
        // A frozen, real Debian `forky` InRelease verifies against the embedded
        // archive keyring. Debian signs it with the archive automatic signing
        // subkeys, not a primary, so this is the exact shape the primary-only
        // path rejected. Freezing it pins the subkey path against genuine
        // archive bytes in a way the synthetic tests cannot.
        //
        // `require_fresh` is cleared because the snapshot's `Valid-Until` has
        // passed: this exercises the signature path, not the freshness gate. The
        // fixture stays valid until the vendored keyring drops the archive
        // signing subkey that made it, at which point it is refreshed alongside
        // the keyring.
        let inrelease = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/debian-archive/forky-InRelease"),
        )
        .expect("read the vendored forky InRelease fixture");
        let keyring = Keyring::parse(crate::provision::debian::EMBEDDED_KEYRING).unwrap();

        // The fixture is signed only by a subkey: the primary-only path that
        // predated subkey support cannot verify it, so this genuinely exercises
        // the subkey candidate set rather than passing through a co-signing
        // primary.
        let (message, _) = CleartextSignedMessage::from_armor(&inrelease[..]).unwrap();
        let certificates =
            SignedPublicKey::from_bytes_many(crate::provision::debian::EMBEDDED_KEYRING)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        assert!(
            !certificates.iter().any(|cert| message.verify(cert).is_ok()),
            "the fixture must be subkey-signed, or it does not exercise the fix",
        );

        let verified = keyring
            .verify(&inrelease, false)
            .expect("a real subkey-signed Debian release must verify");
        assert!(
            verified.body.contains("Codename: forky"),
            "the verified body is the forky release",
        );
        // Both identities are reported, and for a subkey-signed release they
        // differ: the subkey made the signature, and the certificate it belongs
        // to is the archive key a caller would pin.
        for fingerprint in [&verified.certificate, &verified.signing_key] {
            assert_eq!(
                fingerprint.len(),
                40,
                "an uppercase v4 fingerprint: {fingerprint}",
            );
            assert!(
                fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase()),
                "uppercase hex, as the OpenPGP tools present one: {fingerprint}",
            );
        }
        assert_ne!(
            verified.certificate, verified.signing_key,
            "the fixture is subkey-signed, so the signing key is not the certificate",
        );
        // The certificate is one the keyring actually holds, which is what
        // makes it the identity worth pinning.
        let held = |cert: &Certificate| cert.primary().fingerprint().to_string();
        assert!(
            keyring
                .certificates
                .certificates()
                .iter()
                .any(|cert| held(cert) == verified.certificate),
            "the reported certificate names a keyring entry: {}",
            verified.certificate,
        );
    }

    // The real archive keyring is the Debian layer's.
    #[cfg(feature = "debian")]
    #[test]
    fn the_embedded_keyring_exposes_verifiable_signing_subkeys() {
        // Debian's archive automatic signing keys sign with a dedicated signing
        // subkey, so the embedded keyring must expose at least one signing
        // subkey whose binding verifies against its primary. This pins the
        // subkey path against the real archive keys: were binding verification
        // too strict for a genuine Debian key, no candidate would surface here
        // and every real InRelease would fail to verify.
        let keyring = Keyring::parse(crate::provision::debian::EMBEDDED_KEYRING).unwrap();
        let now = now().expect("the clock is after the epoch");
        let signing: usize = keyring
            .certificates
            .certificates()
            .iter()
            .map(|cert| {
                Authority::new(cert, &policy(true), now)
                    .signers()
                    .skip(1)
                    .filter(|(_, standing)| standing.is_ok())
                    .count()
            })
            .sum();
        assert!(
            signing > 0,
            "the embedded keyring exposes no verifiable signing subkeys; the subkey \
             verification path would reject every real Debian release",
        );
    }

    /// Clear-signs `body` with `signer`, overriding the hash algorithm and the
    /// signature creation time and adding `extra` to the hashed area. The
    /// high-level signer always stamps a creation time, picks its own hash and
    /// adds nothing else, so the malformed, weakly-hashed and uninterpretable
    /// documents the validity gates exist to reject are built here.
    #[cfg(test)]
    fn clearsign_crafted(
        signer: &impl pgp::types::SigningKey,
        body: &str,
        hash: Option<HashAlgorithm>,
        created: Option<Timestamp>,
        extra: &[pgp::packet::Subpacket],
    ) -> String {
        use pgp::packet::{SignatureConfig, Subpacket};
        use pgp::types::Password;
        let mut config = SignatureConfig::from_key(rand::thread_rng(), signer, SignatureType::Text)
            .expect("signature config");
        if let Some(hash) = hash {
            config.hash_alg = hash;
        }
        let mut hashed = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))
                .expect("issuer subpacket"),
        ];
        if let Some(created) = created {
            hashed.push(
                Subpacket::regular(SubpacketData::SignatureCreationTime(created))
                    .expect("creation-time subpacket"),
            );
        }
        hashed.extend_from_slice(extra);
        config.hashed_subpackets = hashed;
        CleartextSignedMessage::new(body, config, signer, &Password::empty())
            .expect("signing")
            .to_armored_string(None.into())
            .expect("armoring")
    }

    /// The release body the signature-path tests sign.
    #[cfg(test)]
    const SIGNED_BODY: &str = "Suite: test\nComponents: main\nSHA256:\n abc 10 main/Packages\n";

    /// Generates a throwaway RSA signing key of the given modulus size. RSA
    /// because rPGP refuses to make an Ed25519 signature over a hash it
    /// considers too weak for the curve, which would stop a SHA-1 fixture being
    /// built at all; RSA carries no such restriction, and that asymmetry is why
    /// the hash floor cannot be left to the library. The size is a parameter
    /// because the public-key floor is expressed in modulus bits.
    #[cfg(test)]
    fn test_rsa_key_of(user_id: &str, bits: u32) -> pgp::composed::SignedSecretKey {
        use pgp::composed::{KeyType, SecretKeyParamsBuilder};
        SecretKeyParamsBuilder::default()
            .key_type(KeyType::Rsa(bits))
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(user_id.to_string())
            .build()
            .expect("valid key params")
            .generate(rand::thread_rng())
            .expect("key generation")
    }

    /// Generates a throwaway RSA signing key at the smallest modulus the
    /// public-key floor accepts. See [`test_rsa_key_of`].
    #[cfg(test)]
    fn test_rsa_key(user_id: &str) -> pgp::composed::SignedSecretKey {
        test_rsa_key_of(
            user_id,
            u32::try_from(policy(true).rsa_minimum_bits()).expect("a modulus size"),
        )
    }

    #[test]
    fn a_release_signed_with_a_broken_hash_is_refused() {
        // A signature binds its signer to a digest, so it is worth no more than
        // that digest. SHA-1 is collision-broken, and a SHA-1 release
        // signature is cryptographically valid, so the policy this crate
        // verifies under is what refuses it.
        let archive = test_rsa_key("archive <archive@test.invalid>");
        let signed = clearsign_crafted(
            &*archive,
            SIGNED_BODY,
            Some(HashAlgorithm::Sha1),
            Some(Timestamp::now()),
            &[],
        );
        let public = archive.to_public_key();

        let (message, _) =
            CleartextSignedMessage::from_armor(signed.as_bytes()).expect("armored document");
        let signature = message.verify(&public).expect("cryptographically valid");
        assert_eq!(
            signature.config().map(|config| config.hash_alg),
            Some(HashAlgorithm::Sha1),
            "the fixture must actually use SHA-1",
        );

        let keyring = keyring_of([public]);
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("a SHA-1 release signature must be refused");
        assert!(
            matches!(err, OpenPgpError::Signature(_)),
            "a refused hash is a Signature error, got {err:?}",
        );
    }

    /// Clear-signs `body` with `signer` once per entry in `hashes`, producing a
    /// document carrying several signatures from the same key. The high-level
    /// signer makes exactly one, so the re-signed shape is built here.
    #[cfg(test)]
    fn clearsign_many(
        signer: &impl pgp::types::SigningKey,
        body: &str,
        hashes: &[HashAlgorithm],
    ) -> String {
        use pgp::packet::{SignatureConfig, Subpacket};
        use pgp::types::Password;
        CleartextSignedMessage::new_many(body, |text| {
            hashes
                .iter()
                .map(|hash| {
                    let mut config =
                        SignatureConfig::from_key(rand::thread_rng(), signer, SignatureType::Text)?;
                    config.hash_alg = *hash;
                    config.hashed_subpackets = vec![
                        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
                        Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
                    ];
                    config.sign(signer, &Password::empty(), text.as_bytes())
                })
                .collect()
        })
        .expect("signing")
        .to_armored_string(None.into())
        .expect("armoring")
    }

    /// Generates a throwaway DSA signing key. DSA is the one algorithm the
    /// public-key floor refuses that rPGP will still generate and sign with, so
    /// it is what the end-to-end refusal is built on. At the smallest parameter
    /// size, which is both the archetype of what the floor is for and by far the
    /// cheapest to generate.
    #[cfg(test)]
    fn test_dsa_key(user_id: &str) -> pgp::composed::SignedSecretKey {
        use pgp::composed::{DsaKeySize, KeyType, SecretKeyParamsBuilder};
        SecretKeyParamsBuilder::default()
            .key_type(KeyType::Dsa(DsaKeySize::B1024))
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(user_id.to_string())
            .build()
            .expect("valid key params")
            .generate(rand::thread_rng())
            .expect("key generation")
    }

    #[test]
    fn the_public_key_floor_is_rfc_9580s() {
        // 2048 bits, the narrowest RSA modulus RFC 9580 section 12.4 permits
        // verifying with.
        assert_eq!(policy(true).rsa_minimum_bits(), 2048);
    }

    #[test]
    fn a_key_the_public_key_floor_refuses_cannot_verify_a_release() {
        // A signature is worth no more than the key material behind it, so the
        // floor on the digest has a companion on the key. rPGP verifies a DSA
        // signature as readily as any other; irongall implements no DSA.
        let archive = test_dsa_key("archive <archive@test.invalid>");
        let signed = clearsign(&archive, SIGNED_BODY);
        let public = archive.to_public_key();

        let (message, _) =
            CleartextSignedMessage::from_armor(signed.as_bytes()).expect("armored document");
        message
            .verify(&public)
            .expect("rPGP verifies a DSA signature");

        // A keyring holding nothing else could vouch for nothing, and is
        // refused as it is read.
        assert!(matches!(
            Keyring::parse(&fixture::binary([public.clone()])),
            Err(OpenPgpError::Keyring(_))
        ));

        // Beside a key the floor accepts, the signature is refused, naming the
        // key it claims.
        let other = test_key("other <other@test.invalid>").to_public_key();
        let keyring = keyring_of([public, other]);
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("a DSA archive key must be refused");
        let OpenPgpError::Signature(reason) = &err else {
            panic!("a refused key is a Signature error, got {err:?}");
        };
        assert!(
            reason.starts_with(&Reason::UnsupportedKey.to_string()),
            "{reason}"
        );
    }

    #[test]
    fn an_expired_signature_is_refused_only_when_freshness_is_required() {
        // `require_fresh` is the caller's: a release fetched today must carry a
        // signature that has not expired, and a deliberately pinned snapshot's
        // may have expired since. A signature made two days ago that expired a
        // day later is refused on the first path and accepted on the second.
        use pgp::packet::Subpacket;
        const DAY: u32 = 86_400;
        let now = Timestamp::now().as_secs();
        let archive = test_key_created_at(
            "archive <archive@test.invalid>",
            Timestamp::from_secs(now - 3 * DAY),
            &[],
        );
        let signed = clearsign_crafted(
            &*archive,
            SIGNED_BODY,
            None,
            Some(Timestamp::from_secs(now - 2 * DAY)),
            &[
                Subpacket::regular(SubpacketData::SignatureExpirationTime(Duration::from_secs(
                    DAY,
                )))
                .expect("signature-expiration subpacket"),
            ],
        );
        let keyring = keyring_of([archive.to_public_key()]);
        assert!(refused_for(
            &keyring.verify(signed.as_bytes(), true),
            Reason::SignatureExpired
        ));
        keyring
            .verify(signed.as_bytes(), false)
            .expect("a pinned snapshot's signature may have expired");
    }

    /// Whether `result` is a refusal for `reason`, whose message a refusal's
    /// begins with.
    #[cfg(test)]
    fn refused_for(result: &Result<Verified, OpenPgpError>, reason: Reason) -> bool {
        matches!(
            result,
            Err(OpenPgpError::Signature(given)) if given.starts_with(&reason.to_string())
        )
    }

    /// Clear-signs `body` with `signer`, as a signature of type `typ`.
    ///
    /// rPGP signs a document only as a binary or a text signature, so the
    /// signature is assembled here from the steps its own signer takes: the
    /// document hashed as `typ` hashes it, then the signature's own fields and
    /// trailer, then the key's raw signature over the digest.
    #[cfg(test)]
    fn clearsign_as(
        signer: &impl pgp::types::SigningKey,
        body: &str,
        typ: SignatureType,
    ) -> String {
        use pgp::packet::{SignatureConfig, Subpacket};
        use pgp::types::Password;
        CleartextSignedMessage::new_many(body, |text| {
            let mut config = SignatureConfig::from_key(rand::thread_rng(), signer, typ)?;
            config.hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
            ];
            let mut hasher = config.hash_alg.new_hasher()?;
            config.hash_data_to_sign(&mut hasher, text.as_bytes())?;
            let length = config.hash_signature_data(&mut hasher)?;
            hasher.update(&config.trailer(length)?);
            let digest = hasher.finalize();
            let signature = signer.sign(&Password::empty(), config.hash_alg, &digest)?;
            Ok(vec![Signature::from_config(
                config,
                [digest[0], digest[1]],
                signature,
            )?])
        })
        .expect("signing")
        .to_armored_string(None.into())
        .expect("armoring")
    }

    #[test]
    fn only_a_text_signature_verifies_a_document() {
        // A cleartext-signed document is signed as text. A binary signature
        // covers bytes rather than lines, and a standalone signature covers no
        // document at all, so either one by the archive key is a statement
        // about something other than the body in front of the reader.
        let archive = test_key("archive <archive@test.invalid>");
        let public = archive.to_public_key();
        let keyring = keyring_of([public.clone()]);
        let refusal = Reason::Unverified;
        for typ in [SignatureType::Binary, SignatureType::Standalone] {
            let signed = clearsign_as(&*archive, SIGNED_BODY, typ);
            let (message, _) =
                CleartextSignedMessage::from_armor(signed.as_bytes()).expect("armored document");
            message.verify(&public).expect("cryptographically valid");
            let result = keyring.verify(signed.as_bytes(), false);
            assert!(refused_for(&result, refusal), "{typ:?}");
            // The refusal says why the archive key's signature was never tried,
            // which "nothing verified" alone does not.
            let reason = result.expect_err("refused").to_string();
            assert!(
                reason.contains("one signature was passed over")
                    && reason.contains(&PacketErrorKind::MisplacedSignature.to_string()),
                "{typ:?}: {reason}",
            );
        }

        // What a standalone signature is worth over a document: rPGP hashes
        // only the body's first byte for one, so a signature made over one body
        // verifies another that starts the same way.
        let standalone = clearsign_as(&*archive, SIGNED_BODY, SignatureType::Standalone);
        let substituted = standalone.replace("Suite: test", "Suite: evil");
        assert_ne!(substituted, standalone, "the body is replaced");
        let (message, _) =
            CleartextSignedMessage::from_armor(substituted.as_bytes()).expect("armored document");
        message
            .verify(&public)
            .expect("rPGP accepts it over a body it was not made over");
        assert!(refused_for(
            &keyring.verify(substituted.as_bytes(), false),
            refusal
        ));

        keyring
            .verify(
                clearsign_as(&*archive, SIGNED_BODY, SignatureType::Text).as_bytes(),
                false,
            )
            .expect("a text signature verifies");
    }

    #[test]
    fn a_document_past_the_size_bound_is_refused_unread() {
        // The size is bounded before irongall reads a byte. A refusal names the
        // bound rather than whatever the reader would have said about the bytes.
        let archive = test_key("archive <archive@test.invalid>");
        let keyring = keyring_of([archive.to_public_key()]);
        let oversized = vec![b'x'; usize::try_from(MAX_SIGNED_DOCUMENT_BYTES).unwrap() + 1];
        match keyring.verify(&oversized, false) {
            Err(OpenPgpError::Signature(reason)) => assert!(reason.contains("bytes")),
            other => panic!("expected a refusal, got {other:?}"),
        }

        // The line count is not bounded: irongall frames a cleartext document
        // in time linear in its length, so a document of many short lines is
        // only as costly as its size.
        let signed = clearsign(&archive, &"a\n".repeat(64 * 1024));
        keyring
            .verify(signed.as_bytes(), false)
            .expect("a document of many short lines verifies");
    }

    #[test]
    fn a_document_carrying_too_many_signatures_is_refused() {
        // Every signature is checked against every key it might be from, and
        // each check hashes the whole document, so the count is bounded once
        // the document is parsed and before any signature is checked.
        let archive = test_key("archive <archive@test.invalid>");
        let keyring = keyring_of([archive.to_public_key()]);
        let mut hashes = vec![HashAlgorithm::Sha256; MAX_DOCUMENT_SIGNATURES];
        keyring
            .verify(
                clearsign_many(&*archive, SIGNED_BODY, &hashes).as_bytes(),
                false,
            )
            .expect("a document at the bound verifies");
        hashes.push(HashAlgorithm::Sha256);
        match keyring.verify(
            clearsign_many(&*archive, SIGNED_BODY, &hashes).as_bytes(),
            false,
        ) {
            Err(OpenPgpError::Signature(reason)) => assert!(reason.contains("signatures")),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A version 6 signature packet body of type `typ`, whose hashed area holds
    /// `inner` as an embedded-signature subpacket where it is given. The
    /// signature itself is zeros: the document it builds is refused before
    /// anything would check one.
    #[cfg(test)]
    fn v6_signature_embedding(typ: u8, inner: Option<&[u8]>) -> Vec<u8> {
        const EMBEDDED_SIGNATURE: u8 = 32;
        let mut hashed = Vec::new();
        if let Some(inner) = inner {
            // A subpacket's length counts its type octet; the five-octet form
            // holds any length.
            hashed.push(0xFF);
            hashed.extend_from_slice(&(inner.len() as u32 + 1).to_be_bytes());
            hashed.push(EMBEDDED_SIGNATURE);
            hashed.extend_from_slice(inner);
        }
        // Version, type, Ed25519, SHA-256, then the four-octet area lengths.
        let mut body = vec![6, typ, 27, 8];
        body.extend_from_slice(&(hashed.len() as u32).to_be_bytes());
        body.extend_from_slice(&hashed);
        body.extend_from_slice(&0u32.to_be_bytes());
        // The left sixteen bits of the hash, the salt, and the signature.
        body.extend_from_slice(&[0, 0, 16]);
        body.extend_from_slice(&[0; 16]);
        body.extend_from_slice(&[0; 64]);
        body
    }

    #[test]
    fn a_nested_embedded_signature_is_refused_rather_than_recursed_into() {
        // An embedded-signature subpacket holds a whole signature, whose own
        // hashed area may hold another. A reader that follows the nesting by
        // recursion, with no bound, runs out of stack a few thousand levels
        // down, which aborts the process rather than failing the verification.
        // A version 6 signature's areas take four-octet lengths, so a document
        // of a few hundred kilobytes, well inside the bounds a document is
        // held to, reaches that depth.
        let mut nested = v6_signature_embedding(0x19, None);
        for _ in 0..2_000 {
            nested = v6_signature_embedding(0x19, Some(&nested));
        }
        let outer = v6_signature_embedding(0x01, Some(&nested));
        let mut packet = vec![0xC2, 0xFF];
        packet.extend_from_slice(&(outer.len() as u32).to_be_bytes());
        packet.extend_from_slice(&outer);

        const BASE64: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut armor = String::new();
        for (index, chunk) in packet.chunks(3).enumerate() {
            if index > 0 && index % 16 == 0 {
                armor.push('\n');
            }
            let triple = chunk.iter().enumerate().fold(0u32, |triple, (at, byte)| {
                triple | u32::from(*byte) << (16 - 8 * at)
            });
            for sextet in 0..4 {
                armor.push(if sextet <= chunk.len() {
                    char::from(BASE64[(triple >> (18 - 6 * sextet) & 63) as usize])
                } else {
                    '='
                });
            }
        }
        let document = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{SIGNED_BODY}\
             -----BEGIN PGP SIGNATURE-----\n\n{armor}\n-----END PGP SIGNATURE-----\n"
        );
        assert!(document.len() as u64 <= MAX_SIGNED_DOCUMENT_BYTES);

        let keyring = keyring_of([test_key("archive <archive@test.invalid>").to_public_key()]);
        assert!(matches!(
            keyring.verify(document.as_bytes(), false),
            Err(OpenPgpError::Signature(_))
        ));
    }

    #[test]
    fn a_keyring_with_nothing_usable_in_it_is_refused() {
        // A keyring that yields no key is an error rather than an empty set of
        // trust anchors, so a missing or damaged keyring is reported where it
        // happened instead of much later, as an archive whose signature does not
        // verify against nothing.
        assert!(matches!(Keyring::parse(b""), Err(OpenPgpError::Keyring(_))));
        assert!(matches!(
            Keyring::parse(b"this is not a keyring"),
            Err(OpenPgpError::Keyring(_))
        ));
    }

    #[test]
    fn a_revoked_certificate_is_kept_and_refuses_with_its_reason() {
        // A revocation is the certificate's own statement, weighed when the
        // certificate signs: the keyring keeps it, and a release it signed is
        // refused with the reason, naming the key, where a certificate dropped
        // as the keyring was read would leave only "nothing verified".
        use pgp::packet::{SignatureConfig, Subpacket};
        use pgp::types::Password;
        let archive = test_key("archive <archive@test.invalid>");
        let signed = clearsign(&archive, SIGNED_BODY);
        let mut config =
            SignatureConfig::from_key(rand::thread_rng(), &*archive, SignatureType::KeyRevocation)
                .expect("signature config");
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                .expect("creation-time subpacket"),
            Subpacket::regular(SubpacketData::IssuerFingerprint(archive.fingerprint()))
                .expect("issuer subpacket"),
        ];
        let revocation = config
            .sign_key(&*archive, &Password::empty(), archive.public_key())
            .expect("signing the revocation");
        let mut revoked = archive.to_public_key();
        revoked.details.revocation_signatures.push(revocation);

        let keyring = keyring_of([revoked]);
        let [certificate] = keyring.certificates.certificates() else {
            panic!("the keyring holds the revoked certificate");
        };
        let fingerprint = certificate.primary().fingerprint().to_string();
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("a revoked certificate's release must not verify");
        let OpenPgpError::Signature(reason) = &err else {
            panic!("a revoked certificate is a Signature error, got {err:?}");
        };
        assert!(
            reason.starts_with(&Reason::CertificateRevoked.to_string()),
            "{reason}"
        );
        assert!(reason.contains(&fingerprint), "{reason}");
    }
}
