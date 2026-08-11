//! Is this cleartext-signed document authentic against this keyring?
//!
//! One question, asked by every archive whose trust chain begins with an
//! OpenPGP signature: a keyring of public certificates, a document carrying the
//! signature inline, and a body that is worth acting on only once the signature
//! over it verifies. Debian asks it of an `InRelease`; the answer is nobody's in
//! particular, so it lives here rather than inside the layer that asked first.
//!
//! What the module adds to rPGP's cryptographic verification is the judgement
//! around it. rPGP will tell you that a signature was made by a key; it will not
//! tell you that the key was allowed to make it, that the key was still in
//! force at the time, that the certificate ever delegated the authority to a
//! subkey, or that the algorithms involved are ones worth resting a trust
//! decision on. [`Keyring::verify`] is where those are decided, and the rules
//! and their reasoning are recorded on the checks themselves.

use pgp::composed::{CleartextSignedMessage, Deserializable, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{Signature, SignatureType, SubpacketData};
use pgp::types::{KeyDetails, PublicParams, RsaPublicParams, Tag, Timestamp, VerifyingKey};

use crate::provision::now_epoch;

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
    /// against a key in the keyring, or one that did was refused by a validity
    /// gate — a hash or public-key algorithm this crate does not trust, a
    /// missing creation time, a retired signing key, or a signature that has
    /// itself expired.
    Signature(String),
}

impl std::fmt::Display for OpenPgpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenPgpError::Keyring(reason) | OpenPgpError::Signature(reason) => f.write_str(reason),
        }
    }
}

/// The trust anchor: the certificates a document's signature may be made with.
pub(crate) struct Keyring {
    keys: Vec<SignedPublicKey>,
}

impl Keyring {
    /// Parses a binary keyring of concatenated public keys, dropping any the
    /// archive has revoked.
    ///
    /// A revoked key is retired: the archive has published a self-revocation
    /// for it, so it must no longer verify a document even though its material
    /// is still present in the vendored keyring. Expired keys are kept here
    /// and judged per-signature at [`verify`](Self::verify) time, since a key
    /// that has since expired may still legitimately have signed an older,
    /// deliberately pinned artifact.
    ///
    /// One certificate that fails to parse fails the whole keyring, where `gpg`
    /// would skip the bad entry and use the rest. rPGP already drops the packets
    /// it merely does not support — an unknown version, an unimplemented
    /// algorithm, unreadable curve parameters — so an error surviving to here
    /// means the bytes are damaged rather than exotic. A damaged keyring is a
    /// packaging or transport fault worth telling the caller about directly;
    /// continuing with silently fewer trust anchors would report it much later,
    /// as an archive whose signature does not verify.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Keyring, OpenPgpError> {
        let keys: Vec<_> = SignedPublicKey::from_bytes_many(bytes)
            .map_err(|err| OpenPgpError::Keyring(err.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| OpenPgpError::Keyring(err.to_string()))?
            .into_iter()
            .filter(|key| !key_is_revoked(key))
            .collect();
        if keys.is_empty() {
            return Err(OpenPgpError::Keyring(
                "the keyring holds no usable keys".to_string(),
            ));
        }
        Ok(Keyring { keys })
    }

    /// Verifies a cleartext-signed document and returns its body.
    ///
    /// The signature must verify against at least one certificate in the
    /// keyring; signatures from keys the keyring does not hold are ignored, as
    /// apt does. A document may be signed either by a certificate's primary key
    /// or by one of its signing-capable subkeys, and both are tried: an archive
    /// that signs with a dedicated signing subkey rather than with the primary
    /// — Debian's archive automatic signing keys do — would otherwise have
    /// every genuine document of its own rejected. A subkey is admitted as a
    /// candidate only when a binding
    /// signature the primary issued over it cryptographically verifies, carries
    /// the subkey's own back signature, grants the signing key flag, and has not
    /// been revoked; an encryption subkey is never a candidate. See
    /// [`subkey_candidates`].
    ///
    /// Several checks are layered over rPGP's cryptographic verification, which
    /// on its own accepts a signature regardless of key or signature validity:
    ///
    /// - The signing key's public-key algorithm must be one this crate trusts,
    ///   and so must the algorithm of the primary key that vouches for it. See
    ///   [`key_is_acceptable`].
    /// - The signature must carry a creation time, must not use a hash this
    ///   crate refuses, and must not carry a critical subpacket this crate
    ///   cannot interpret. See [`check_signature_valid`].
    /// - The signing key must have existed, and must not yet have expired, when
    ///   the signature was made. For a subkey that means neither its own
    ///   binding's expiry nor the primary's had passed: an expired primary
    ///   retires the whole certificate, its subkeys with it, so the governing
    ///   expiry is the earlier of the two.
    /// - Unless `require_fresh` is cleared for a deliberately pinned snapshot,
    ///   the signature must not itself have expired.
    ///
    /// The returned text is the signed body, with the cleartext framing removed.
    ///
    /// Validity is judged per signature, not only for the first signature a key
    /// made or the first candidate that matched. A document may carry signatures
    /// from several archive keys during a key rotation, and one key re-signing a
    /// document can leave the superseded signature alongside the new one;
    /// verification succeeds if any signature is both cryptographically valid
    /// and passes the checks, so an acceptable signature is never masked by a
    /// refused one that happened to be tried first. When none is fully valid,
    /// the specific reason from a cryptographically matching but refused key is
    /// preferred over the generic "nothing matched".
    pub(crate) fn verify(
        &self,
        document: &[u8],
        require_fresh: bool,
    ) -> Result<Verified, OpenPgpError> {
        let (message, _headers) = CleartextSignedMessage::from_armor(document)
            .map_err(|err| OpenPgpError::Signature(err.to_string()))?;
        // The normalized text every signature on the document is checked
        // against, and the body a successful verification returns. Computed once
        // here rather than by each call that takes a key, as rPGP's own entry
        // points do.
        let signed_text = message.signed_text();
        // For each keyring cert, try its primary key and then each of its
        // subkeys. A candidate that verifies cryptographically but is expired or
        // whose signature is stale does not end the search; a later signature,
        // candidate or co-signer may still be valid.
        let mut deferred: Option<OpenPgpError> = None;
        for cert in &self.keys {
            let certificate = fingerprint_hex(&cert.fingerprint());
            // Read once and applied to every candidate the cert offers: the
            // primary's validity window bounds the certificate as a whole.
            // Read at most once per cert, and only once something has actually
            // signed: computing it verifies every self-signature the cert
            // carries, which is wasted work for the keyring entries that did
            // not sign this document — most of them, on every verification.
            let mut primary_expiry = None;
            let mut primary_expiry =
                || *primary_expiry.get_or_insert_with(|| key_expiry_epoch(cert));
            // A certificate is worth no more than the key that anchors it, so a
            // primary this crate refuses takes its subkeys down with it: their
            // authority is delegated by a binding only that primary could issue.
            let anchored = key_is_acceptable(&cert.primary_key);

            // The primary, judged against its own validity window.
            for signature in signatures_by(&message, &signed_text, &cert.primary_key) {
                let signer = if anchored {
                    Ok(SigningWindow::of(&cert.primary_key, primary_expiry()))
                } else {
                    Err(WEAK_CERTIFICATE)
                };
                match check_signature_valid(signature, signer, require_fresh) {
                    Ok(()) => {
                        return Ok(Verified {
                            body: signed_text.clone(),
                            signing_key: certificate.clone(),
                            certificate,
                        });
                    }
                    Err(err) => {
                        deferred.get_or_insert(err);
                    }
                }
            }
            // Each subkey, judged against whichever expires first: its own
            // binding's grant, or the primary's expiry. A subkey the certificate
            // has not properly delegated to stays in the walk carrying its
            // reason rather than being dropped, so a document it signed is
            // refused with that reason instead of the generic "nothing matched".
            for candidate in subkey_candidates(cert) {
                for signature in signatures_by(&message, &signed_text, candidate.subkey) {
                    let signer = match (anchored, candidate.verdict) {
                        (false, _) => Err(WEAK_CERTIFICATE),
                        (true, Err(reason)) => Err(reason),
                        (true, Ok(expiry)) => Ok(SigningWindow::of(
                            &candidate.subkey.key,
                            earlier(primary_expiry(), expiry),
                        )),
                    };
                    match check_signature_valid(signature, signer, require_fresh) {
                        Ok(()) => {
                            return Ok(Verified {
                                body: signed_text.clone(),
                                // The subkey's own fingerprint: it is the key
                                // that made the signature, and it is what a
                                // caller comparing against `gpg --list-keys`
                                // output on the signing subkey will see. The
                                // certificate it belongs to is recorded
                                // alongside it, being the stable identity.
                                signing_key: fingerprint_hex(&candidate.subkey.fingerprint()),
                                certificate: certificate.clone(),
                            });
                        }
                        Err(err) => {
                            deferred.get_or_insert(err);
                        }
                    }
                }
            }
        }
        Err(deferred.unwrap_or_else(|| {
            OpenPgpError::Signature("no signature verified against the keyring".to_string())
        }))
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
    #[cfg(feature = "gentoo")]
    pub(crate) fn horizon(&self) -> Vec<Horizon> {
        self.keys.iter().map(Horizon::of).collect()
    }
}

/// What one certificate of a keyring can still be trusted to do, and until when.
#[cfg(feature = "gentoo")]
pub(crate) struct Horizon {
    /// The primary key's fingerprint, uppercase hex.
    pub(crate) fingerprint: String,
    /// The certificate's primary user id, as it spells itself, or `None` where
    /// it carries none this crate can read.
    pub(crate) user_id: Option<String>,
    /// The epoch at which the certificate's authority lapses, or `None` when
    /// nothing bounds it.
    ///
    /// Where the certificate can sign, this is the last moment at which a
    /// signature from it would still be accepted: the latest lapse among the
    /// keys under it that [`Keyring::verify`] would take a signature from, each
    /// bounded by the primary's own expiry. That is not the primary's expiry
    /// alone — a subkey's binding may lapse before the certificate does, and a
    /// certificate whose primary may not sign is worth only what its subkeys
    /// are.
    ///
    /// Where it cannot sign — [`signs`](Self::signs) is `false` — this is the
    /// primary's expiry, which is when the certificate lapses whether or not
    /// that ever mattered.
    pub(crate) expires: Option<i64>,
    /// Whether any key under the certificate could make a signature
    /// [`Keyring::verify`] would accept.
    ///
    /// `false` for a certificate that is in the keyring but cannot vouch for
    /// anything: its primary rests on an algorithm this crate refuses and it
    /// delegates to no signing subkey that does. Such a certificate is harmless
    /// — nothing rests on a key until it produces a signature that passes the
    /// gates — but its expiry says nothing about the keyring's shelf life, and
    /// reading the two together is what keeps it from being mistaken for a
    /// working anchor.
    pub(crate) signs: bool,
}

#[cfg(feature = "gentoo")]
impl Horizon {
    /// Reads one certificate's horizon.
    fn of(cert: &SignedPublicKey) -> Horizon {
        let primary_expiry = key_expiry_epoch(cert);
        // Every key under the certificate a signature could legitimately come
        // from, each paired with the epoch its own authority lapses at. The
        // primary qualifies unless its algorithm is refused; a subkey qualifies
        // on the same terms `verify` admits it as a candidate on.
        let mut lapses: Vec<Option<i64>> = Vec::new();
        if key_is_acceptable(&cert.primary_key) {
            lapses.push(primary_expiry);
        }
        for candidate in subkey_candidates(cert) {
            if let Ok(granted) = candidate.verdict {
                lapses.push(earlier(primary_expiry, granted));
            }
        }
        // The certificate keeps working while any one of them does, so the
        // latest governs. A key nothing bounds outlasts every epoch, which is
        // what makes an unbounded lapse win outright rather than compare as a
        // number.
        let expires = match lapses.first() {
            None => primary_expiry,
            Some(_) if lapses.contains(&None) => None,
            Some(_) => lapses.iter().copied().flatten().max(),
        };
        Horizon {
            fingerprint: fingerprint_hex(&cert.fingerprint()),
            user_id: primary_user_id(cert).map(str::to_string),
            expires,
            signs: !lapses.is_empty(),
        }
    }
}

/// The newest certification over `user` that verifies as issued by `primary`,
/// which is the one that governs what that user id currently says.
///
/// A certification revocation is not a statement of validity and never governs,
/// and an unverified packet governs nothing at all — the rule
/// [`key_expiry_epoch`] records, where absence carries as much meaning as
/// presence.
fn governing_certification<'a>(
    primary: &pgp::packet::PublicKey,
    user: &'a pgp::types::SignedUser,
) -> Option<&'a Signature> {
    governing_signature(user.signatures.iter().filter(|signature| {
        is_positive_certification(signature)
            && signature
                .verify_certification(primary, Tag::UserId, &user.id)
                .is_ok()
    }))
}

/// A certificate's primary user id, as it spells itself.
///
/// The one whose governing certification flags it primary. RFC 9580 leaves the
/// choice to the implementation when none is flagged, and a certificate carrying
/// several unflagged user ids is the ordinary case — Gentoo's ebuild repository
/// key has two — so the most recently certified one is preferred, and a tie
/// there falls to the order the certificate lists them in. A tie is not
/// hypothetical: that key's two user ids were last certified in the same second,
/// and `gpg` resolves such a pair by a rule of its own that is not a contract.
/// What matters for a value whose use is display is that one certificate always
/// reports the same user id, which this gives.
///
/// A user id with no verified certification at all is not eligible: the
/// certificate has said nothing about it, and an unverified packet must not be
/// able to relabel a key. A user id that is not UTF-8 is reported as absent
/// rather than lossily transcoded, for the same reason — the value's whole use
/// is comparison.
#[cfg(feature = "gentoo")]
fn primary_user_id(cert: &SignedPublicKey) -> Option<&str> {
    let certified = cert.details.users.iter().filter_map(|user| {
        governing_certification(&cert.primary_key, user).map(|certification| (user, certification))
    });
    let mut best: Option<(&pgp::types::SignedUser, &Signature)> = None;
    for (user, certification) in certified {
        let better = match best {
            None => true,
            Some((_, held)) => match (certification.is_primary(), held.is_primary()) {
                (true, false) => true,
                (false, true) => false,
                // Neither flagged, or both: the newest certification governs,
                // as it does everywhere else here.
                _ => certification.created() > held.created(),
            },
        };
        if better {
            best = Some((user, certification));
        }
    }
    best.and_then(|(user, _)| user.id.as_str())
}

/// Every signature on the document that cryptographically verifies against
/// `key`, checked against the already-normalized `signed_text`.
///
/// rPGP's own `CleartextSignedMessage::verify` returns the first such signature
/// and stops. One key may sign a document more than once — an archive re-signing
/// one can leave the superseded signature alongside the new one — and judging
/// only the first would refuse the document whenever the weaker of the two
/// happened to come first in it.
fn signatures_by<'a, K: VerifyingKey>(
    message: &'a CleartextSignedMessage,
    signed_text: &'a str,
    key: &'a K,
) -> impl Iterator<Item = &'a Signature> + 'a {
    message
        .signatures()
        .iter()
        .filter(move |signature| signature.verify(key, signed_text.as_bytes()).is_ok())
}

/// The span within which a key's signatures are legitimate: the key's own
/// creation, and the epoch at which its authority lapses (`None` when nothing
/// bounds it).
struct SigningWindow {
    created: i64,
    expires: Option<i64>,
}

impl SigningWindow {
    /// The window `key` opens at its creation and `expires` closes.
    fn of(key: &impl KeyDetails, expires: Option<i64>) -> SigningWindow {
        SigningWindow {
            created: i64::from(key.created_at().as_secs()),
            expires,
        }
    }
}

/// Refused because the certificate's primary key — the anchor every key under it
/// derives its authority from — rests on an algorithm this crate does not trust.
const WEAK_CERTIFICATE: &str =
    "the signing key's certificate rests on a public-key algorithm that is no longer trusted";
/// Refused because the signing subkey itself rests on such an algorithm.
const WEAK_SIGNING_KEY: &str =
    "the signature was made with a public-key algorithm that is no longer trusted";
/// Refused because no subkey-binding signature over the subkey survives
/// [`governing_binding`].
const UNBOUND_SUBKEY: &str =
    "the subkey that made the signature carries no valid binding from its certificate";
/// Refused because the governing binding grants no signing capability.
const NON_SIGNING_SUBKEY: &str = "the subkey that made the signature is not certified for signing";
/// Refused because the governing binding carries no usable back signature, so
/// the certificate's claim over the subkey is unilateral. See [`binds_back`].
const UNCONSENTED_SUBKEY: &str =
    "the subkey that made the signature has not counter-signed its binding";
/// Refused because the primary has published a verified revocation of the subkey.
const REVOKED_SUBKEY: &str =
    "the subkey that made the signature has been revoked by its certificate";

/// The earlier of two expiry epochs, or whichever one is set, or `None` when
/// neither is.
///
/// Two independent expiries both bound a subkey — its binding's and its
/// primary's — and a key is retired as soon as the first of them passes.
fn earlier(one: Option<i64>, other: Option<i64>) -> Option<i64> {
    match (one, other) {
        (Some(one), Some(other)) => Some(one.min(other)),
        (only, None) | (None, only) => only,
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

/// A fingerprint as the OpenPGP tools present one: uppercase hex, undelimited.
///
/// The spelling matters because the value's whole use is comparison — against
/// `gpg --fingerprint` output, or against a fingerprint a policy pins — and
/// uppercase is what those produce.
fn fingerprint_hex(fingerprint: &pgp::types::Fingerprint) -> String {
    format!("{fingerprint:X}")
}

/// Applies the validity gates layered over rPGP's cryptographic verification: a
/// signature is accepted only if the key that made it may sign at all, it is
/// well-formed enough to judge, that key was within its validity window when
/// the signature was made, and — when `require_fresh` — the signature has not
/// itself expired.
///
/// `signer` is the verdict on the key whose signature this is: the window
/// within which its signatures are legitimate, or the reason it may not sign. A
/// refused signer is reported here rather than where it was refused, so that a
/// key which did cryptographically match still yields its own reason instead of
/// the walk falling through to the generic "no signature verified".
///
/// A signature with no creation time is refused outright rather than waved
/// through. The creation time is what every check below is relative to, and it
/// is chosen by whoever holds the signing key, so reading its absence as
/// permission would let the very party [`check_key_valid_at_signing`] guards
/// against — someone signing with retired key material — disable that check by
/// omitting a subpacket.
fn check_signature_valid(
    signature: &Signature,
    signer: Result<SigningWindow, &'static str>,
    require_fresh: bool,
) -> Result<(), OpenPgpError> {
    let window = signer.map_err(|reason| OpenPgpError::Signature(reason.to_string()))?;
    if !hash_is_acceptable(signature) {
        return Err(OpenPgpError::Signature(
            "the signature uses a hash that is no longer trusted".to_string(),
        ));
    }
    if has_unknown_critical_subpacket(signature) {
        return Err(OpenPgpError::Signature(
            "the signature carries a critical subpacket that cannot be interpreted".to_string(),
        ));
    }
    let Some(signed_at) = signature.created() else {
        return Err(OpenPgpError::Signature(
            "the signature carries no creation time".to_string(),
        ));
    };
    check_key_valid_at_signing(&window, signed_at)?;
    if require_fresh {
        check_signature_fresh(signature)?;
    }
    Ok(())
}

/// Whether a signature's hash is one this crate is willing to rest a trust
/// decision on.
///
/// MD5, SHA-1 and RIPEMD-160 are refused: collisions against all three are
/// within reach, and a signature is only as binding as the digest it covers.
/// The floor is flat rather than relative to the signature's claimed creation
/// time, because nothing here needs to validate decade-old artifacts — the
/// archive re-signs its documents on every publish — and a date the signer
/// chooses is a poor gate on the strength demanded of it.
///
/// A signature whose format rPGP does not recognize reports no hash at all, and
/// is refused for the same reason: its strength cannot be established.
///
/// Deliberately not applied to revocations, nor to the self-signatures
/// [`key_expiry_epoch`] reads. A revocation retires a key, so refusing a weakly
/// hashed one would keep a key the archive has disowned in service. And an
/// expiry is computed by taking the earliest a set of self-signatures sets, so
/// dropping one can only lengthen a key's life: a key whose sole certification
/// used a weak hash would become immortal rather than suspect. In both places
/// the floor would fail open, which is the opposite of what it is for.
fn hash_is_acceptable(signature: &Signature) -> bool {
    signature.config().is_some_and(|config| {
        !matches!(
            config.hash_alg,
            HashAlgorithm::Md5 | HashAlgorithm::Sha1 | HashAlgorithm::Ripemd160
        )
    })
}

/// The smallest RSA modulus this crate will rest a trust decision on.
const RSA_MINIMUM_BITS: u16 = 2048;

/// Whether a key's public-key algorithm is one this crate is willing to rest a
/// trust decision on.
///
/// The companion to [`hash_is_acceptable`], and flat for the same reason: a
/// signature is worth no more than the weaker of the digest it covers and the
/// key material that binds it.
///
/// The accepted set is named rather than the refused one, so key material this
/// crate has never heard of is refused rather than admitted by default. What it
/// holds is the signature algorithms still considered sound: RSA at
/// [`RSA_MINIMUM_BITS`] or wider, ECDSA, and the two EdDSA encodings. A
/// narrower RSA modulus is refused, 2048 bits being the narrowest still out of
/// reach of a public factoring effort. So is DSA: the keys of it in circulation
/// are 1024-bit with a 160-bit subgroup, which puts them at SHA-1's strength,
/// and the algorithm discloses its private key outright on a repeated nonce.
/// Everything else is refused too — an encryption algorithm cannot sign in the
/// first place, and a signature algorithm this crate has not weighed is not one
/// to rest an archive on.
///
/// Applied to the key that made a document's signature and to the primary key of
/// the certificate vouching for it, both of which a signature depends on;
/// deliberately not applied to the self-signatures [`key_expiry_epoch`] reads,
/// for the reason recorded on [`hash_is_acceptable`].
fn key_is_acceptable(key: &impl KeyDetails) -> bool {
    match key.public_params() {
        PublicParams::RSA(params) => {
            rsa_modulus_bits(params).is_some_and(|bits| bits >= RSA_MINIMUM_BITS)
        }
        PublicParams::ECDSA(_)
        | PublicParams::EdDSALegacy(_)
        | PublicParams::Ed25519(_)
        | PublicParams::Ed448(_) => true,
        _ => false,
    }
}

/// The bit length of an RSA public key's modulus, or `None` if it cannot be
/// read — which [`key_is_acceptable`] treats as a refusal.
///
/// rPGP holds the modulus in the `rsa` crate's own type, which is not a
/// dependency here, so the length is read back off the wire form instead: an
/// OpenPGP multiprecision integer is a two-octet big-endian count of its
/// significant bits followed by the value (RFC 9580 section 3.2), and the
/// modulus is the first integer an RSA public key serializes.
fn rsa_modulus_bits(params: &RsaPublicParams) -> Option<u16> {
    let mut wire = Vec::new();
    pgp::ser::Serialize::to_writer(params, &mut wire).ok()?;
    let bits: [u8; 2] = wire.get(..2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bits))
}

/// Whether a signature's hashed area carries a critical subpacket that cannot be
/// interpreted.
///
/// RFC 9580 section 5.2.3.7 requires a verifier meeting a critical subpacket it
/// does not recognize to treat the signature as invalid: the critical bit is the
/// signer saying that the subpacket changes what the signature means, so
/// honoring the signature while ignoring the subpacket would honor something
/// other than what was signed. rPGP parses an unrecognized subpacket into an
/// opaque form and accepts it, leaving the rule to be applied here. A critical
/// notation counts as unrecognized: this crate implements no notation semantics,
/// so there is none it could satisfy.
///
/// Only the hashed area is read. A subpacket in the unhashed area is not covered
/// by the signature, so anyone relaying the document could append one; reading
/// it would hand a network attacker a way to fail every archive fetch.
fn has_unknown_critical_subpacket(signature: &Signature) -> bool {
    signature.config().is_some_and(|config| {
        config.hashed_subpackets().any(|subpacket| {
            subpacket.is_critical
                && matches!(
                    subpacket.data,
                    SubpacketData::Other(..)
                        | SubpacketData::Experimental(..)
                        | SubpacketData::Notation(_)
                )
        })
    })
}

/// Whether a keyring key carries a verified self-revocation.
///
/// A revocation signature counts only if it cryptographically verifies as
/// issued by the key's own primary key, so a stray or malformed packet cannot
/// suppress a still-valid key.
fn key_is_revoked(key: &SignedPublicKey) -> bool {
    key.details
        .revocation_signatures
        .iter()
        .any(|signature| signature.verify_key(&key.primary_key).is_ok())
}

/// A subkey of a keyring cert and the verdict on its use as a document signer:
/// the epoch its authority lapses at (`None` when nothing bounds it), or why it
/// may not sign at all.
struct SubkeyCandidate<'a> {
    subkey: &'a SignedPublicSubKey,
    verdict: Result<Option<i64>, &'static str>,
}

/// Every subkey of a keyring cert, each carrying the verdict on its use as a
/// document signer.
///
/// An archive commonly signs with a dedicated signing subkey rather than with
/// the primary — Debian's archive automatic signing keys do — so a subkey must
/// be admitted as a verification candidate for any real archive to verify. A
/// subkey qualifies
/// only when the primary has cryptographically bound it with the signing
/// capability and has not revoked it:
///
/// - The governing binding is the newest subkey-binding signature that verifies
///   as issued by the primary over this subkey (see [`governing_binding`]).
///   Verifying it establishes the link from the subkey — the key that verified
///   the document — back to the trusted primary, just as the document's
///   signature is verified against the primary; a subkey with no valid binding
///   is not
///   trusted. This is a stronger check than the primary's own self-signatures
///   receive, because a subkey is only as trustworthy as its attested link to
///   the anchor, whereas the primary is the anchor.
/// - The binding must grant the signing key flag. An encryption subkey, whose
///   binding carries no signing flag, never qualifies, so its presence in the
///   keyring cannot be turned into a signature over a document.
/// - The binding must carry the subkey's own back signature, which is what makes
///   it two-sided (see [`binds_back`]). Checked after the signing flag, because
///   that is the only capability the requirement attaches to: an encryption
///   subkey legitimately counter-signs nothing.
/// - A subkey the primary has revoked is retired, exactly as a revoked primary
///   is dropped at [`Keyring::parse`] time (see [`subkey_is_revoked`]).
/// - The subkey's own public-key algorithm must be one this crate trusts (see
///   [`key_is_acceptable`]).
///
/// A subkey failing one of these is returned carrying its reason rather than
/// dropped, so a document signed with it is refused with that reason rather than
/// with the generic "nothing in the keyring matched". The verdict on a subkey
/// that does qualify is the epoch its authority lapses at, from
/// [`binding_expiry`]; it gates reuse of an aged-out subkey at
/// [`Keyring::verify`] time.
fn subkey_candidates(cert: &SignedPublicKey) -> Vec<SubkeyCandidate<'_>> {
    cert.public_subkeys
        .iter()
        .map(|subkey| SubkeyCandidate {
            subkey,
            verdict: subkey_verdict(cert, subkey),
        })
        .collect()
}

/// The verdict on one subkey: the epoch its authority lapses at, or the first
/// rule it fails. See [`subkey_candidates`] for the rules and their reasoning.
fn subkey_verdict(
    cert: &SignedPublicKey,
    subkey: &SignedPublicSubKey,
) -> Result<Option<i64>, &'static str> {
    let binding = governing_binding(cert, subkey).ok_or(UNBOUND_SUBKEY)?;
    if !binding.key_flags().sign() {
        return Err(NON_SIGNING_SUBKEY);
    }
    if !binds_back(cert, subkey, binding) {
        return Err(UNCONSENTED_SUBKEY);
    }
    if subkey_is_revoked(cert, subkey) {
        return Err(REVOKED_SUBKEY);
    }
    if !key_is_acceptable(&subkey.key) {
        return Err(WEAK_SIGNING_KEY);
    }
    Ok(binding_expiry(subkey, binding))
}

/// The newest subkey-binding signature that cryptographically verifies as
/// issued by `cert`'s primary key over `subkey`, or `None` if the subkey carries
/// no such binding.
///
/// A subkey may have been re-bound over time; the newest binding (by creation)
/// carries the current capability flags and expiration, exactly as
/// [`key_expiry_epoch`] takes the newest self-signature over each object the
/// primary signs. The remaining conditions on a binding are applied to whichever
/// one governs rather than used to choose it, so that a defective newest binding
/// refuses the subkey instead of handing authority back to a superseded one.
fn governing_binding<'a>(
    cert: &SignedPublicKey,
    subkey: &'a SignedPublicSubKey,
) -> Option<&'a Signature> {
    governing_signature(subkey.signatures.iter().filter(|signature| {
        signature.typ() == Some(SignatureType::SubkeyBinding)
            && hash_is_acceptable(signature)
            && !has_unknown_critical_subpacket(signature)
            && signature
                .verify_subkey_binding(&cert.primary_key, &subkey.key)
                .is_ok()
    }))
}

/// Whether a subkey binding carries the embedded back signature the subkey made
/// over the primary, and that signature is one this crate will read.
///
/// RFC 9580 section 5.2.3.26 requires one on the binding of any subkey capable
/// of signing, and the requirement is what makes a binding two-sided. The
/// binding alone is only the primary's claim over the subkey, which anyone
/// holding a primary can make about any public key they have seen; the back
/// signature is the subkey's own claim, which only its holder can make. Without
/// it a certificate could adopt a signing subkey it does not hold the secret
/// for, and present that key's signatures — genuine ones, made for another
/// archive — as issued under its own identity.
///
/// Being a statement this crate acts on, the back signature is held to the same
/// terms as the binding around it: a hash and critical subpackets it can judge,
/// and a creation time. That time must also be no earlier than either key it
/// speaks about, since a signature predating its own signer, or claiming to
/// consent to a binding with a key that did not yet exist, cannot have been made
/// when it says it was. The back signature's own expiration bounds the grant
/// rather than voiding it here; see [`binding_expiry`].
fn binds_back(cert: &SignedPublicKey, subkey: &SignedPublicSubKey, binding: &Signature) -> bool {
    binding.embedded_signature().is_some_and(|backsig| {
        hash_is_acceptable(backsig)
            && !has_unknown_critical_subpacket(backsig)
            && backsig.created().is_some_and(|created| {
                created >= cert.primary_key.created_at() && created >= subkey.key.created_at()
            })
            && backsig
                .verify_primary_key_binding(&subkey.key, &cert.primary_key)
                .is_ok()
    })
}

/// The epoch at which a subkey binding's grant lapses: the earlier of the key
/// expiration the binding sets for the subkey and the expiration of the subkey's
/// own back signature, or `None` when neither expires.
///
/// The back signature is the subkey holder's consent to the binding, so
/// time-limiting it time-limits the grant. Past that point the binding is once
/// again only the primary's unilateral claim over a key it may not hold, which
/// is exactly what [`binds_back`] exists to refuse. Reading the lapse as an
/// expiry rather than as a check against the clock keeps the whole judgement
/// relative to the signature's creation time, so a deliberately pinned snapshot
/// signed while the consent stood still verifies.
///
/// Both durations are read from areas their own signature covers, and the back
/// signature this reads one of is the one [`binds_back`] verified, so neither
/// bound is something a relay could have appended.
fn binding_expiry(subkey: &SignedPublicSubKey, binding: &Signature) -> Option<i64> {
    earlier(
        subkey_expiry_epoch(subkey, binding),
        binding
            .embedded_signature()
            .and_then(signature_expiry_epoch),
    )
}

/// The newest of a set of signatures over one object, which is the one that
/// governs that object's current validity.
///
/// A signature with no creation time cannot be ordered by recency and is not
/// eligible to govern. Neither is one dated in the future: it describes a state
/// that is not yet in effect, and admitting it would let a signer with a skewed
/// clock hand a key an expiry — or, through an absent key-expiration subpacket,
/// the removal of one — that outlives every signature actually in force. When
/// the clock cannot be read the bound is not applied, leaving recency to decide
/// as it otherwise would.
///
/// A signature that has passed its own signature-expiration is deliberately
/// still eligible. Dropping one from a competition the newest wins does not
/// retire the statement it made; it promotes the next-newest, which may set a
/// longer key expiration or none at all. The rule would therefore lengthen a
/// key's life exactly where it looks like it shortens it — the fail direction
/// [`hash_is_acceptable`] records, arrived at from the other side.
fn governing_signature<'a>(
    signatures: impl Iterator<Item = &'a Signature>,
) -> Option<&'a Signature> {
    let now = now_epoch();
    signatures
        .filter_map(|signature| Some((signature.created()?, signature)))
        .filter(|(created, _)| now.is_none_or(|now| i64::from(created.as_secs()) <= now))
        .max_by_key(|(created, _)| *created)
        .map(|(_, signature)| signature)
}

/// Whether the primary has published a verified revocation of `subkey`.
///
/// A revocation counts only if it cryptographically verifies as issued by the
/// primary over this subkey, so a stray or malformed packet cannot retire a
/// still-valid subkey — the same rule [`key_is_revoked`] applies to a primary.
fn subkey_is_revoked(cert: &SignedPublicKey, subkey: &SignedPublicSubKey) -> bool {
    subkey
        .signatures
        .iter()
        .filter(|signature| signature.typ() == Some(SignatureType::SubkeyRevocation))
        .any(|signature| {
            signature
                .verify_subkey_binding(&cert.primary_key, &subkey.key)
                .is_ok()
        })
}

/// The Unix time at which a subkey expires: its own creation plus the
/// key-expiration duration carried by its binding signature, or `None` if the
/// binding sets no expiration.
///
/// A subkey's key-expiration subpacket is relative to the subkey's own creation
/// time, not the primary's, so the epoch is computed from the subkey.
fn subkey_expiry_epoch(subkey: &SignedPublicSubKey, binding: &Signature) -> Option<i64> {
    expiry_epoch(i64::from(subkey.key.created_at().as_secs()), binding)
}

/// The expiration a signature sets for a (sub)key created at `key_created`:
/// that creation plus the key-expiration duration the signature carries, or
/// `None` if it sets no expiration.
///
/// The subpacket's absence and a zero duration are the two wire forms of "this
/// key does not expire", and both yield `None`.
fn expiry_epoch(key_created: i64, signature: &Signature) -> Option<i64> {
    let seconds = signature.key_expiration_time()?.as_secs();
    (seconds > 0).then(|| key_created.saturating_add(i64::from(seconds)))
}

/// The epoch at which a signature's own validity ends: its creation plus the
/// signature-expiration duration it carries, or `None` if it does not expire.
///
/// The subpacket's absence and a zero duration are the two wire forms of "this
/// signature does not expire", and both yield `None`, exactly as they do for a
/// key expiration. A signature carrying no creation time has nothing to measure
/// from, so nothing can be said about its expiry; the gates that care about a
/// missing creation time refuse it on those grounds instead.
fn signature_expiry_epoch(signature: &Signature) -> Option<i64> {
    let created = i64::from(signature.created()?.as_secs());
    let seconds = signature.signature_expiration_time()?.as_secs();
    (seconds > 0).then(|| created.saturating_add(i64::from(seconds)))
}

/// Rejects a signature made outside its signing key's validity window: before
/// the key existed, or after its authority had lapsed.
///
/// OpenPGP key validity is time-relative: a signature is legitimate if the
/// key was within its validity window when the signature was made. This
/// refuses a key retired by expiry whose material is reused to sign a fresh
/// document — the signature time is now, past the key's expiry — while leaving a
/// genuinely old signature (made while the key was valid) acceptable, so a
/// pinned snapshot still verifies.
///
/// The lower bound closes the window at the other end: a signature dated before
/// its own key existed cannot have been made when it claims, and that claimed
/// date is what every other gate here measures against.
///
/// `window.expires` is the epoch at which authority lapses: [`key_expiry_epoch`]
/// for a primary, and for a subkey the [`earlier`] of the primary's and the one
/// [`binding_expiry`] reads from its binding. A key that nothing bounds leaves
/// the judgement to the other checks.
fn check_key_valid_at_signing(
    window: &SigningWindow,
    signed_at: Timestamp,
) -> Result<(), OpenPgpError> {
    let signed_at = i64::from(signed_at.as_secs());
    if signed_at < window.created {
        return Err(OpenPgpError::Signature(
            "the signature is dated before its signing key existed".to_string(),
        ));
    }
    if window.expires.is_some_and(|expiry| signed_at > expiry) {
        return Err(OpenPgpError::Signature(
            "the signature was made after its signing key expired".to_string(),
        ));
    }
    Ok(())
}

/// The Unix time at which a key expires, relative to the primary key's
/// creation, or `None` if the key does not expire.
///
/// OpenPGP key validity is time-relative: a later self-signature re-dates the
/// key, and the expiration one carries is a duration from the primary's
/// creation. The current expiry is whatever the *governing* self-signature
/// sets, and a signature governs the object it was made over: the key itself,
/// for a direct-key signature, or one user id, for a certification. RFC 4880
/// section 5.2.3.3 gives priority to the most recent self-signature over the
/// same object, so recency is compared within an object rather than across
/// objects — a user id added later governs only itself.
///
/// The governing signature's key-expiration subpacket is then read for what it
/// says: present means the key expires then, absent means it does not. Both a
/// deliberate shortening and a deliberate removal therefore take effect, the
/// removal being how a project extends a key rather than rotating it, and a key
/// retired by re-dating is still judged expired at the intended time — the
/// retiring signature is the newest over its object. Where objects disagree the
/// earliest expiry governs, so an expiry set on one user id is not lifted by a
/// second user id whose certification simply says nothing about it.
///
/// Only self-signatures that cryptographically verify as issued by the primary
/// over the object they cover are authoritative, the same rule
/// [`governing_binding`] applies to a subkey binding. Absence carries meaning
/// here as much as presence does, so an unverified packet could otherwise lift
/// an expiry as readily as impose one.
///
/// A certificate carrying no such self-signature at all is therefore unbounded
/// rather than refused. Requiring one would be the stricter reading, but a bare
/// key with neither a user id nor a direct-key signature is not a shape any
/// producer emits: it can only reach here by having been put in the keyring,
/// which is already the decision to trust it wholesale.
fn key_expiry_epoch(key: &SignedPublicKey) -> Option<i64> {
    let primary = &key.primary_key;
    let primary_created = i64::from(primary.created_at().as_secs());

    // The key itself, as covered by direct-key signatures.
    let direct = governing_signature(key.details.direct_signatures.iter().filter(|signature| {
        signature.typ() == Some(SignatureType::Key) && signature.verify_key(primary).is_ok()
    }));
    // Each user id, as covered by the certifications over it.
    let certified = key
        .details
        .users
        .iter()
        .map(|user| governing_certification(primary, user));

    std::iter::once(direct)
        .chain(certified)
        .flatten()
        .filter_map(|signature| expiry_epoch(primary_created, signature))
        .min()
}

/// Whether a signature is a certification of a user id, as opposed to a
/// revocation of one. rPGP's own predicate counts a certification revocation as
/// a certification, which is not the question asked here.
fn is_positive_certification(signature: &Signature) -> bool {
    matches!(
        signature.typ(),
        Some(
            SignatureType::CertGeneric
                | SignatureType::CertPersona
                | SignatureType::CertCasual
                | SignatureType::CertPositive
        )
    )
}

/// Rejects a signature that has passed its own expiration.
///
/// A secondary bound, and an optional one: the subpacket is the signer's to
/// include, and a signature carrying none passes here. What bounds replay of a
/// document whose signature does not expire is the deadline the archive itself
/// publishes — Debian's `Valid-Until` is one — and reading that is the layer's
/// business rather than this module's.
///
/// A clock before the epoch passes here, where such a published deadline is
/// refused on one. The asymmetry is deliberate and neither gate is the other's
/// fallback: a deadline an archive published because it wanted a bound must
/// never be evaluated blind, while a signature expiration is a bound whose
/// absence is already accepted.
fn check_signature_fresh(signature: &Signature) -> Result<(), OpenPgpError> {
    let Some(expires_at) = signature_expiry_epoch(signature) else {
        return Ok(());
    };
    let Some(now) = now_epoch() else {
        return Ok(());
    };
    if now > expires_at {
        return Err(OpenPgpError::Signature(
            "the signature has expired".to_string(),
        ));
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
    use pgp::composed::{KeyType, SecretKeyParamsBuilder, SignedSecretKey};

    use super::{CleartextSignedMessage, Keyring};

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
    pub(crate) fn keyring(key: &SignedSecretKey) -> Keyring {
        let mut binary = Vec::new();
        pgp::ser::Serialize::to_writer(&key.to_public_key(), &mut binary)
            .expect("serializing the certificate");
        Keyring::parse(&binary).expect("the certificate parses")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::types::{Duration, Timestamp};

    #[test]
    fn embedded_keys_are_valid_and_unrevoked() {
        // The vendored keyring parses to a non-empty set of unrevoked keys,
        // and the key-expiry computation reads an expiration for every one of
        // them — a bug that misread the self-signatures would surface as a
        // missing expiry here. At least one key is still valid, so the keyring
        // can verify a current release; when that stops holding, the vendored
        // debian-archive-keyring has gone fully stale and must be refreshed.
        // (A single aged-out key is not a failure: expired keys are kept and
        // judged per signature at verify time.) This pins the key-validity
        // computation against the real keyring.
        let keyring = Keyring::parse(crate::provision::debian::EMBEDDED_KEYRING).unwrap();
        let now = now_epoch().expect("the clock is after the epoch");
        assert!(!keyring.keys.is_empty());
        let mut valid_now = 0;
        for key in &keyring.keys {
            assert!(!key_is_revoked(key), "an embedded key parses as revoked");
            let expiry =
                key_expiry_epoch(key).expect("each archive key records a key-expiration time");
            if expiry > now {
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

    /// Generates a throwaway cert with one Ed25519 signing subkey (first) and
    /// one X25519 encryption subkey (second), to exercise the signing-capability
    /// gate.
    #[cfg(test)]
    fn test_key_with_signing_and_encryption_subkeys(
        user_id: &str,
    ) -> pgp::composed::SignedSecretKey {
        use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
        let signing_subkey = SubkeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .build()
            .expect("valid signing subkey params");
        let encryption_subkey = SubkeyParamsBuilder::default()
            .key_type(KeyType::X25519)
            .can_encrypt(EncryptionCaps::All)
            .build()
            .expect("valid encryption subkey params");
        SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(user_id.to_string())
            .subkey(signing_subkey)
            .subkey(encryption_subkey)
            .build()
            .expect("valid key params")
            .generate(rand::thread_rng())
            .expect("key generation")
    }

    /// How a crafted subkey binding carries the subkey's back signature.
    ///
    /// A genuine signing-subkey binding carries one stamped at binding time, so
    /// [`BackSignature::Embed`] is what a test wanting a realistic binding asks
    /// for; the rest build the malformed or time-limited back signatures the
    /// rules on [`binds_back`] reject.
    #[cfg(test)]
    #[derive(Clone, Copy)]
    enum BackSignature {
        /// Stamped at the binding's own creation, as a real one is.
        Embed,
        /// Absent entirely.
        Omit,
        /// Present, but carrying no creation time, so it cannot be placed in
        /// time at all.
        Undated,
        /// Present, but stamped at the given time rather than the binding's.
        DatedAt(pgp::types::Timestamp),
        /// Present and stamped at the binding's creation, but expiring the given
        /// duration later.
        ExpiringAfter(pgp::types::Duration),
    }

    /// Signs a subkey binding or revocation of `subkey` with `primary`'s primary
    /// key, carrying the given creation time, key flags, and optional
    /// key-expiration. The high-level builder emits only a plain, non-expiring
    /// binding, so tests that need a revocation or an expiration craft the
    /// signature packet here.
    ///
    /// For a binding, `backsig` decides whether the subkey counter-signs the
    /// primary as RFC 9580 requires. A revocation carries no back signature and
    /// passes [`BackSignature::Omit`].
    #[cfg(test)]
    fn craft_subkey_signature(
        primary: &pgp::composed::SignedSecretKey,
        subkey: &pgp::composed::SignedSecretSubKey,
        typ: SignatureType,
        created: pgp::types::Timestamp,
        key_flags: pgp::packet::KeyFlags,
        key_expiration: Option<pgp::types::Duration>,
        backsig: BackSignature,
    ) -> Signature {
        use pgp::packet::{SignatureConfig, Subpacket, SubpacketData};
        use pgp::types::Password;
        let mut config = SignatureConfig::from_key(rand::thread_rng(), &**primary, typ)
            .expect("signature config");
        let mut hashed = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(created))
                .expect("creation-time subpacket"),
            Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint()))
                .expect("issuer subpacket"),
            Subpacket::regular(SubpacketData::KeyFlags(key_flags)).expect("key-flags subpacket"),
        ];
        if let Some(duration) = key_expiration {
            hashed.push(
                Subpacket::regular(SubpacketData::KeyExpirationTime(duration))
                    .expect("key-expiration subpacket"),
            );
        }
        // The subkey's own signature over the primary, which is what makes the
        // binding two-sided. The stamps are set here rather than left to the
        // signature config, which starts with an empty hashed area.
        let stamps = match backsig {
            BackSignature::Omit => None,
            BackSignature::Embed => Some((Some(created), None)),
            BackSignature::Undated => Some((None, None)),
            BackSignature::DatedAt(at) => Some((Some(at), None)),
            BackSignature::ExpiringAfter(after) => Some((Some(created), Some(after))),
        };
        if let Some((back_created, back_expires)) = stamps {
            let mut back =
                SignatureConfig::from_key(rand::thread_rng(), &**subkey, SignatureType::KeyBinding)
                    .expect("back signature config");
            back.hashed_subpackets = back_created
                .map(|at| {
                    Subpacket::regular(SubpacketData::SignatureCreationTime(at))
                        .expect("creation-time subpacket")
                })
                .into_iter()
                .chain(back_expires.map(|after| {
                    Subpacket::regular(SubpacketData::SignatureExpirationTime(after))
                        .expect("signature-expiration subpacket")
                }))
                .collect();
            let back = back
                .sign_primary_key_binding(
                    &**subkey,
                    subkey.public_key(),
                    &Password::empty(),
                    primary.public_key(),
                )
                .expect("signing the primary key binding");
            hashed.push(
                Subpacket::regular(SubpacketData::EmbeddedSignature(Box::new(back)))
                    .expect("embedded-signature subpacket"),
            );
        }
        config.hashed_subpackets = hashed;
        config
            .sign_subkey_binding(
                &**primary,
                primary.public_key(),
                &Password::empty(),
                subkey.public_key(),
            )
            .expect("signing subkey binding")
    }

    /// Certifies `user`'s id with `signer`'s primary key, carrying the given
    /// creation time and optional key-expiration. Key generation emits a single
    /// certification per user id, so a test that needs a re-dating — the shape
    /// a key extended or shortened in place has — crafts the packet here.
    #[cfg(test)]
    fn craft_certification(
        signer: &pgp::composed::SignedSecretKey,
        user: &pgp::types::SignedUser,
        created: pgp::types::Timestamp,
        key_expiration: Option<pgp::types::Duration>,
    ) -> Signature {
        use pgp::packet::{SignatureConfig, Subpacket, SubpacketData};
        use pgp::types::Password;
        let mut config =
            SignatureConfig::from_key(rand::thread_rng(), &**signer, SignatureType::CertPositive)
                .expect("signature config");
        let mut hashed = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(created))
                .expect("creation-time subpacket"),
            Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))
                .expect("issuer subpacket"),
        ];
        if let Some(duration) = key_expiration {
            hashed.push(
                Subpacket::regular(SubpacketData::KeyExpirationTime(duration))
                    .expect("key-expiration subpacket"),
            );
        }
        config.hashed_subpackets = hashed;
        config
            .sign_certification(
                &**signer,
                signer.public_key(),
                &Password::empty(),
                Tag::UserId,
                &user.id,
            )
            .expect("signing the certification")
    }

    /// Key flags with only the signing capability set.
    #[cfg(test)]
    fn signing_key_flags() -> pgp::packet::KeyFlags {
        let mut flags = pgp::packet::KeyFlags::default();
        flags.set_sign(true);
        flags
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
        let keyring = Keyring {
            keys: vec![archive.to_public_key()],
        };

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

        let keyring = Keyring {
            keys: vec![archive.to_public_key()],
        };
        let verified = keyring
            .verify(signed.as_bytes(), false)
            .expect("a subkey signature verifies");
        assert!(
            verified.body.contains("Suite: test"),
            "body was {verified:?}"
        );
    }

    /// The subkeys of `cert` that qualify as release signers, each paired with
    /// the epoch its authority lapses at. The tests below assert over the
    /// qualifying set far more often than over the refusals, which they read off
    /// [`subkey_candidates`] directly.
    #[cfg(test)]
    fn qualifying_subkeys(cert: &SignedPublicKey) -> Vec<(&SignedPublicSubKey, Option<i64>)> {
        subkey_candidates(cert)
            .into_iter()
            .filter_map(|candidate| {
                candidate
                    .verdict
                    .ok()
                    .map(|expiry| (candidate.subkey, expiry))
            })
            .collect()
    }

    #[test]
    fn only_signing_subkeys_are_verification_candidates() {
        // A cert with a signing subkey (first) and an encryption subkey (second):
        // only the signing subkey is a candidate, so an encryption subkey present
        // in a keyring can never be turned into a release signature.
        let cert = test_key_with_signing_and_encryption_subkeys("archive <archive@test.invalid>");
        let public = cert.to_public_key();
        assert_eq!(
            public.public_subkeys.len(),
            2,
            "the fixture carries a signing and an encryption subkey",
        );
        let candidates = qualifying_subkeys(&public);
        assert_eq!(candidates.len(), 1, "only the signing subkey qualifies");
        assert_eq!(
            candidates[0].0.fingerprint(),
            public.public_subkeys[0].fingerprint(),
            "the surviving candidate is the signing subkey, not the encryption one",
        );
        // The encryption subkey is refused with a reason rather than silently
        // dropped, so a release signed with it says why it was not accepted.
        assert_eq!(
            subkey_candidates(&public)[1].verdict,
            Err(NON_SIGNING_SUBKEY),
        );
    }

    #[test]
    fn a_revoked_signing_subkey_is_refused() {
        // A subkey the primary has revoked is retired: a release it signed must
        // not verify, even though the signature is cryptographically intact.
        let archive =
            test_key_with_signing_subkey("archive <archive@test.invalid>", Timestamp::now());
        let subkey_secret = archive.secret_subkeys.first().expect("a signing subkey");
        let body = "Suite: test\nComponents: main\nSHA256:\n abc 10 main/binary-amd64/Packages\n";
        let signed = clearsign_with(&**subkey_secret, body);

        // Before revocation the subkey-signed release verifies.
        let public = archive.to_public_key();
        let keyring = Keyring {
            keys: vec![public.clone()],
        };
        keyring
            .verify(signed.as_bytes(), false)
            .expect("verifies before revocation");

        // Publishing a verified subkey revocation retires it, and the same
        // release no longer verifies.
        let mut revoked = public;
        let revocation = craft_subkey_signature(
            &archive,
            subkey_secret,
            SignatureType::SubkeyRevocation,
            Timestamp::now(),
            signing_key_flags(),
            None,
            BackSignature::Omit,
        );
        revoked.public_subkeys[0].signatures.push(revocation);
        let revoked_keyring = Keyring {
            keys: vec![revoked],
        };
        assert!(
            matches!(
                revoked_keyring.verify(signed.as_bytes(), false),
                Err(OpenPgpError::Signature(_)),
            ),
            "a release signed by a revoked subkey must not verify",
        );
    }

    #[test]
    fn a_release_signed_after_subkey_expiry_is_refused() {
        // A signing subkey created in the past, bound with only a short
        // lifetime: a release signed now falls past the subkey's expiry, so —
        // exactly as for an expired primary — it is refused. The subkey expiry
        // is read from its own binding signature, not the primary's.
        let subkey_created = Timestamp::from_secs(1_600_000_000); // 2020-09-13 UTC.
        let archive =
            test_key_with_signing_subkey("archive <archive@test.invalid>", subkey_created);
        let subkey_secret = archive.secret_subkeys.first().expect("a signing subkey");
        let body = "Suite: test\nComponents: main\nSHA256:\n abc 10 main/binary-amd64/Packages\n";
        let signed = clearsign_with(&**subkey_secret, body);

        // Re-date the subkey's binding to one that expired a day after the
        // subkey's 2020 creation, long before now.
        let mut public = archive.to_public_key();
        let expiring_binding = craft_subkey_signature(
            &archive,
            subkey_secret,
            SignatureType::SubkeyBinding,
            Timestamp::now(),
            signing_key_flags(),
            Some(Duration::from_secs(86_400)),
            BackSignature::Embed,
        );
        public.public_subkeys[0].signatures = vec![expiring_binding];

        let keyring = Keyring { keys: vec![public] };
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("an expired signing subkey must be refused");
        assert!(
            matches!(err, OpenPgpError::Signature(_)),
            "an unusable signing key is a Signature error, got {err:?}",
        );
    }

    /// The 2018 creation the key-expiry tests date their keys to, and the
    /// two-year lifetime an early self-signature grants: together an expiry in
    /// 2020, comfortably in the past.
    #[cfg(test)]
    const KEY_CREATED: u32 = 1_544_987_117;
    #[cfg(test)]
    const TWO_YEARS: u32 = 63_072_000;

    #[test]
    fn an_expiry_a_later_self_signature_drops_is_lifted() {
        // The shape of a key created with a finite lifetime and later made
        // non-expiring: an early self-signature sets a two-year expiry, and a
        // later one re-dates the key carrying no key-expiration subpacket at
        // all, which is how an expiry is removed. The later signature governs,
        // so the key does not expire and a release signed today verifies.
        let archive = test_key_created_at(
            "archive <archive@test.invalid>",
            Timestamp::from_secs(KEY_CREATED),
            &[],
        );
        let user = archive.details.users[0].clone();
        let expiring = craft_certification(
            &archive,
            &user,
            Timestamp::from_secs(KEY_CREATED),
            Some(Duration::from_secs(TWO_YEARS)),
        );
        let lifting = craft_certification(
            &archive,
            &user,
            Timestamp::from_secs(1_606_071_634), // 2020-11-22, after the expiry.
            None,
        );

        let body = "Suite: test\nComponents: main\nSHA256:\n abc 10 main/binary-amd64/Packages\n";
        let signed = clearsign(&archive, body);

        // With only the early self-signature the key is genuinely expired and
        // the release is refused, which is what makes the case below a test of
        // the removal rather than of a key that never expired.
        let mut public = archive.to_public_key();
        public.details.users[0].signatures = vec![expiring.clone()];
        assert_eq!(
            key_expiry_epoch(&public),
            Some(i64::from(KEY_CREATED) + i64::from(TWO_YEARS)),
        );
        let keyring = Keyring {
            keys: vec![public.clone()],
        };
        keyring
            .verify(signed.as_bytes(), false)
            .expect_err("a key whose only self-signature has expired must be refused");

        // Adding the later, expiry-less self-signature lifts the expiry.
        public.details.users[0].signatures = vec![expiring, lifting];
        assert_eq!(
            key_expiry_epoch(&public),
            None,
            "the newest self-signature sets no expiration, so the key does not expire",
        );
        let keyring = Keyring { keys: vec![public] };
        keyring
            .verify(signed.as_bytes(), false)
            .expect("a key whose expiry a later self-signature removed must verify");
    }

    #[test]
    fn a_later_self_signature_that_shortens_the_expiry_governs() {
        // The converse re-dating: the newest self-signature is authoritative
        // whichever way it moves the expiry, so a deliberate shortening is not
        // masked by an earlier, more generous one.
        let archive = test_key_created_at(
            "archive <archive@test.invalid>",
            Timestamp::from_secs(KEY_CREATED),
            &[],
        );
        let user = archive.details.users[0].clone();
        let generous = craft_certification(
            &archive,
            &user,
            Timestamp::from_secs(KEY_CREATED),
            Some(Duration::from_secs(10 * TWO_YEARS)),
        );
        let shortening = craft_certification(
            &archive,
            &user,
            Timestamp::from_secs(1_606_071_634),
            Some(Duration::from_secs(TWO_YEARS)),
        );

        let mut public = archive.to_public_key();
        public.details.users[0].signatures = vec![generous, shortening];
        assert_eq!(
            key_expiry_epoch(&public),
            Some(i64::from(KEY_CREATED) + i64::from(TWO_YEARS)),
        );
    }

    #[test]
    fn an_expiry_is_not_lifted_by_a_certification_over_another_user_id() {
        // Recency is compared within one certified object. A user id added
        // later says nothing about the expiry another user id's certification
        // set, so its silence must not be read as a removal — otherwise adding
        // an address would quietly make a key immortal.
        let archive = test_key_created_at(
            "archive <archive@test.invalid>",
            Timestamp::from_secs(KEY_CREATED),
            &["archive <second@test.invalid>"],
        );
        let (first, second) = (
            archive.details.users[0].clone(),
            archive.details.users[1].clone(),
        );
        let expiring = craft_certification(
            &archive,
            &first,
            Timestamp::from_secs(KEY_CREATED),
            Some(Duration::from_secs(TWO_YEARS)),
        );
        let silent =
            craft_certification(&archive, &second, Timestamp::from_secs(1_606_071_634), None);

        let mut public = archive.to_public_key();
        public.details.users[0].signatures = vec![expiring];
        public.details.users[1].signatures = vec![silent];
        assert_eq!(
            key_expiry_epoch(&public),
            Some(i64::from(KEY_CREATED) + i64::from(TWO_YEARS)),
        );
    }

    #[test]
    fn a_certification_the_primary_did_not_issue_cannot_lift_an_expiry() {
        // Absence of a key-expiration subpacket now carries meaning, so a
        // self-signature is authoritative only once it verifies as issued by
        // the primary. A packet appended to the keyring by anyone else must not
        // be able to extend a key's life.
        let archive = test_key_created_at(
            "archive <archive@test.invalid>",
            Timestamp::from_secs(KEY_CREATED),
            &[],
        );
        let foreign = test_key("foreign <foreign@test.invalid>");
        let user = archive.details.users[0].clone();
        let expiring = craft_certification(
            &archive,
            &user,
            Timestamp::from_secs(KEY_CREATED),
            Some(Duration::from_secs(TWO_YEARS)),
        );
        let forged =
            craft_certification(&foreign, &user, Timestamp::from_secs(1_606_071_634), None);

        let mut public = archive.to_public_key();
        public.details.users[0].signatures = vec![expiring, forged];
        assert_eq!(
            key_expiry_epoch(&public),
            Some(i64::from(KEY_CREATED) + i64::from(TWO_YEARS)),
            "a certification the primary did not issue must not govern",
        );
    }

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
        assert!(
            !keyring.keys.iter().any(|cert| message.verify(cert).is_ok()),
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
        assert!(
            keyring
                .keys
                .iter()
                .any(|cert| fingerprint_hex(&cert.fingerprint()) == verified.certificate),
            "the reported certificate names a keyring entry: {}",
            verified.certificate,
        );
    }

    #[test]
    fn the_embedded_keyring_exposes_verifiable_signing_subkeys() {
        // Debian's archive automatic signing keys sign with a dedicated signing
        // subkey, so the embedded keyring must expose at least one signing
        // subkey whose binding verifies against its primary. This pins the
        // subkey path against the real archive keys: were binding verification
        // too strict for a genuine Debian key, no candidate would surface here
        // and every real InRelease would fail to verify.
        let keyring = Keyring::parse(crate::provision::debian::EMBEDDED_KEYRING).unwrap();
        let signing: usize = keyring
            .keys
            .iter()
            .map(|cert| qualifying_subkeys(cert).len())
            .sum();
        assert!(
            signing > 0,
            "the embedded keyring exposes no verifiable signing subkeys; the subkey \
             verification path would reject every real Debian release",
        );
    }

    /// Generates a throwaway cert whose primary and signing subkey are both
    /// created at `created`. Dating the primary is what lets a test expire it,
    /// an expiration being a duration from its creation.
    #[cfg(test)]
    fn dated_key_with_signing_subkey(
        user_id: &str,
        created: Timestamp,
    ) -> pgp::composed::SignedSecretKey {
        use pgp::composed::{KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
        let signing_subkey = SubkeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .created_at(created)
            .build()
            .expect("valid signing subkey params");
        SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .can_certify(true)
            .created_at(created)
            .primary_user_id(user_id.to_string())
            .subkey(signing_subkey)
            .build()
            .expect("valid key params")
            .generate(rand::thread_rng())
            .expect("key generation")
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

    #[test]
    fn an_expired_primary_cannot_verify_through_its_signing_subkey() {
        // A certificate is retired as a whole when its primary expires, its
        // subkeys with it: a subkey's authority is delegated from the primary,
        // so it cannot outlive the anchor that granted it. Without this the
        // primary and subkey paths disagree — the same retired archive key is
        // refused when it signs directly and accepted when it signs through a
        // subkey whose binding happens to set no expiry of its own.
        let archive = dated_key_with_signing_subkey(
            "archive <archive@test.invalid>",
            Timestamp::from_secs(KEY_CREATED),
        );
        let subkey_secret = archive.secret_subkeys.first().expect("a signing subkey");
        let signed = clearsign_with(&**subkey_secret, SIGNED_BODY);

        let mut public = archive.to_public_key();
        // The primary expired in 2020.
        let user = archive.details.users[0].clone();
        public.details.users[0].signatures = vec![craft_certification(
            &archive,
            &user,
            Timestamp::from_secs(KEY_CREATED),
            Some(Duration::from_secs(TWO_YEARS)),
        )];
        // The subkey's own binding sets no expiration at all, so only the
        // primary's expiry can refuse this release.
        public.public_subkeys[0].signatures = vec![craft_subkey_signature(
            &archive,
            subkey_secret,
            SignatureType::SubkeyBinding,
            Timestamp::from_secs(KEY_CREATED),
            signing_key_flags(),
            None,
            BackSignature::Embed,
        )];

        // The fixture is the shape under test: a live subkey on a dead primary.
        let candidates = qualifying_subkeys(&public);
        assert_eq!(candidates.len(), 1, "the subkey is still a candidate");
        assert_eq!(candidates[0].1, None, "its binding sets no expiry");
        assert_eq!(
            key_expiry_epoch(&public),
            Some(i64::from(KEY_CREATED) + i64::from(TWO_YEARS)),
            "the primary expired long ago",
        );

        let keyring = Keyring { keys: vec![public] };
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("an expired primary must not verify through its subkey");
        assert!(
            matches!(err, OpenPgpError::Signature(_)),
            "an unusable signing key is a Signature error, got {err:?}",
        );
    }

    #[test]
    fn a_signature_without_a_creation_time_is_refused() {
        // Every validity gate is relative to the signature's creation time, and
        // that time is chosen by whoever holds the key. Reading its absence as
        // permission would let the party `check_key_valid_at_signing` guards
        // against — someone signing with retired key material — disable the
        // check by omitting a subpacket.
        let archive = test_key("archive <archive@test.invalid>");
        let signed = clearsign_crafted(&*archive, SIGNED_BODY, None, None, &[]);
        let public = archive.to_public_key();

        // rPGP accepts it: the signature is cryptographically sound, and the
        // missing subpacket is not its concern. Only this crate's gate refuses.
        let (message, _) =
            CleartextSignedMessage::from_armor(signed.as_bytes()).expect("armored document");
        let signature = message.verify(&public).expect("cryptographically valid");
        assert_eq!(
            signature.created(),
            None,
            "the fixture carries no creation time"
        );

        let keyring = Keyring { keys: vec![public] };
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("a signature with no creation time must be refused");
        assert!(
            matches!(err, OpenPgpError::Signature(_)),
            "a signature refused by a validity gate is a Signature error, got {err:?}",
        );
    }

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
        test_rsa_key_of(user_id, u32::from(RSA_MINIMUM_BITS))
    }

    #[test]
    fn a_release_signed_with_a_broken_hash_is_refused() {
        // A signature binds its signer to a digest, so it is worth no more than
        // that digest. SHA-1 is collision-broken, and rPGP applies no policy of
        // its own for RSA, so a SHA-1 release signature verifies unless this
        // crate refuses it.
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

        let keyring = Keyring { keys: vec![public] };
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("a SHA-1 release signature must be refused");
        assert!(
            matches!(err, OpenPgpError::Signature(_)),
            "a refused hash is a Signature error, got {err:?}",
        );
    }

    #[test]
    fn a_signing_subkey_without_a_back_signature_is_refused() {
        // The binding alone is only the primary's claim over the subkey, and
        // any primary can make that claim about any public key it has seen. The
        // back signature is the subkey's own claim, which only its holder can
        // make; without one a certificate could adopt a signing subkey it does
        // not hold and present that key's signatures as its own.
        let archive =
            test_key_with_signing_subkey("archive <archive@test.invalid>", Timestamp::now());
        let subkey_secret = archive.secret_subkeys.first().expect("a signing subkey");
        let signed = clearsign_with(&**subkey_secret, SIGNED_BODY);

        // The generated cert's own binding is two-sided, and verifies.
        let mut public = archive.to_public_key();
        assert_eq!(
            qualifying_subkeys(&public).len(),
            1,
            "a well-formed binding admits the subkey",
        );
        Keyring {
            keys: vec![public.clone()],
        }
        .verify(signed.as_bytes(), false)
        .expect("verifies with the back signature in place");

        // The same binding, minus the subkey's counter-signature.
        public.public_subkeys[0].signatures = vec![craft_subkey_signature(
            &archive,
            subkey_secret,
            SignatureType::SubkeyBinding,
            Timestamp::now(),
            signing_key_flags(),
            None,
            BackSignature::Omit,
        )];
        assert_eq!(
            subkey_candidates(&public)[0].verdict,
            Err(UNCONSENTED_SUBKEY),
            "a binding with no back signature must not admit the subkey",
        );

        // The refusal reaches the caller as the reason the subkey was refused,
        // not as the generic "nothing in the keyring matched": the subkey did
        // make the signature, and saying so is the whole diagnostic value.
        let keyring = Keyring { keys: vec![public] };
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("a subkey with no back signature must not verify");
        let OpenPgpError::Signature(reason) = &err else {
            panic!("an unusable signing key is a Signature error, got {err:?}");
        };
        assert_eq!(reason, UNCONSENTED_SUBKEY);
    }

    #[test]
    fn a_future_dated_self_signature_does_not_govern() {
        // Recency decides which self-signature governs, so a signature dated
        // ahead of the clock would win outright. It describes a state not yet
        // in effect, and because an absent key-expiration subpacket means "does
        // not expire", letting it govern would lift a live expiry rather than
        // merely postpone it.
        let archive = test_key_created_at(
            "archive <archive@test.invalid>",
            Timestamp::from_secs(KEY_CREATED),
            &[],
        );
        let user = archive.details.users[0].clone();
        let expiring = craft_certification(
            &archive,
            &user,
            Timestamp::from_secs(KEY_CREATED),
            Some(Duration::from_secs(TWO_YEARS)),
        );
        // Ten years ahead of the clock, and silent about key expiration.
        let ahead = u32::try_from(now_epoch().expect("the clock is after the epoch"))
            .expect("the clock fits a v4 timestamp")
            .saturating_add(10 * TWO_YEARS / 2);
        let future = craft_certification(&archive, &user, Timestamp::from_secs(ahead), None);

        let mut public = archive.to_public_key();
        public.details.users[0].signatures = vec![expiring, future];
        assert_eq!(
            key_expiry_epoch(&public),
            Some(i64::from(KEY_CREATED) + i64::from(TWO_YEARS)),
            "a self-signature dated in the future must not govern",
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

    #[test]
    fn a_refused_signature_does_not_mask_an_acceptable_one_from_the_same_key() {
        // A key that re-signs a release can leave the superseded signature in
        // the document alongside the new one. rPGP's own verify returns the
        // first signature that matches a key and stops, so judging only that one
        // would refuse the whole release whenever the weaker of the two happened
        // to come first — even though the key made an acceptable signature too.
        let archive = test_rsa_key("archive <archive@test.invalid>");
        let signed = clearsign_many(
            &*archive,
            SIGNED_BODY,
            &[HashAlgorithm::Sha1, HashAlgorithm::Sha256],
        );
        let public = archive.to_public_key();

        // The fixture is the shape under test: two signatures from one key, the
        // refused one first, and rPGP hands back the refused one.
        let (message, _) =
            CleartextSignedMessage::from_armor(signed.as_bytes()).expect("armored document");
        assert_eq!(message.signatures().len(), 2, "two signatures on the body");
        assert_eq!(
            message
                .verify(&public)
                .expect("cryptographically valid")
                .config()
                .map(|config| config.hash_alg),
            Some(HashAlgorithm::Sha1),
            "rPGP returns the SHA-1 signature first, or the test proves nothing",
        );

        let keyring = Keyring { keys: vec![public] };
        let verified = keyring
            .verify(signed.as_bytes(), false)
            .expect("the acceptable signature must be found behind the refused one");
        assert!(
            verified.body.contains("Suite: test"),
            "body was {verified:?}"
        );
    }

    #[test]
    fn a_back_signature_that_cannot_be_placed_in_time_does_not_bind() {
        // The back signature is the subkey holder's consent to the binding, and
        // consent that cannot be placed in time is not consent: a signature with
        // no creation time, or one claiming to predate the keys it speaks about,
        // could not have been made when it says it was.
        let created = Timestamp::from_secs(KEY_CREATED);
        let archive = dated_key_with_signing_subkey("archive <archive@test.invalid>", created);
        let subkey_secret = archive.secret_subkeys.first().expect("a signing subkey");
        let public = archive.to_public_key();

        let bind_with = |backsig| {
            let mut cert = public.clone();
            cert.public_subkeys[0].signatures = vec![craft_subkey_signature(
                &archive,
                subkey_secret,
                SignatureType::SubkeyBinding,
                Timestamp::now(),
                signing_key_flags(),
                None,
                backsig,
            )];
            subkey_candidates(&cert)[0].verdict
        };

        // A back signature stamped as a real one is binds.
        assert!(bind_with(BackSignature::Embed).is_ok());
        // One with no creation time at all does not.
        assert_eq!(bind_with(BackSignature::Undated), Err(UNCONSENTED_SUBKEY));
        // Nor does one dated a day before the keys it speaks about existed.
        assert_eq!(
            bind_with(BackSignature::DatedAt(Timestamp::from_secs(
                KEY_CREATED - 86_400
            ))),
            Err(UNCONSENTED_SUBKEY),
        );
    }

    #[test]
    fn an_expiring_back_signature_bounds_the_subkeys_authority() {
        // A subkey holder who time-limits their consent time-limits the grant:
        // past the back signature's expiration the binding is once again only
        // the primary's unilateral claim. The bound lands as an expiry on the
        // candidate rather than as a check against the clock, so it is judged
        // against the release signature's creation time like every other one.
        let created = Timestamp::from_secs(KEY_CREATED);
        let archive = dated_key_with_signing_subkey("archive <archive@test.invalid>", created);
        let subkey_secret = archive.secret_subkeys.first().expect("a signing subkey");
        let signed = clearsign_with(&**subkey_secret, SIGNED_BODY);

        let mut public = archive.to_public_key();
        // The binding itself sets no key expiration, so only the consent's own
        // expiry — a day after the 2018 creation — can refuse this release.
        public.public_subkeys[0].signatures = vec![craft_subkey_signature(
            &archive,
            subkey_secret,
            SignatureType::SubkeyBinding,
            created,
            signing_key_flags(),
            None,
            BackSignature::ExpiringAfter(Duration::from_secs(86_400)),
        )];
        assert_eq!(
            subkey_candidates(&public)[0].verdict,
            Ok(Some(i64::from(KEY_CREATED) + 86_400)),
            "the subkey still binds, but only until its consent lapses",
        );

        let keyring = Keyring { keys: vec![public] };
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("a release signed after the consent lapsed must be refused");
        assert!(
            matches!(err, OpenPgpError::Signature(_)),
            "an unusable signing key is a Signature error, got {err:?}",
        );
    }

    /// A public key packet carrying an RSA modulus of the given bit size.
    ///
    /// rPGP's key builder refuses to generate below 2048 bits, so a key under
    /// the floor cannot be produced the way the other fixtures are; its material
    /// is assembled from the wire form instead. An OpenPGP multiprecision
    /// integer is a two-octet big-endian count of its significant bits followed
    /// by the value, and an RSA public key is the modulus followed by the
    /// exponent.
    #[cfg(test)]
    fn rsa_key_of_size(bits: u16) -> pgp::packet::PublicKey {
        use pgp::crypto::public_key::PublicKeyAlgorithm;
        use pgp::packet::{PubKeyInner, PublicKey};
        use pgp::types::KeyVersion;
        // A modulus with its top and bottom bits set: the full bit count, and
        // odd, as a product of two odd primes is.
        let mut modulus = vec![0u8; usize::from(bits / 8)];
        *modulus.first_mut().expect("a non-empty modulus") = 0x80;
        *modulus.last_mut().expect("a non-empty modulus") = 0x01;
        let mut wire = bits.to_be_bytes().to_vec();
        wire.extend(modulus);
        // The customary public exponent, 65537, which is 17 bits wide.
        wire.extend([0x00, 0x11, 0x01, 0x00, 0x01]);
        let params =
            RsaPublicParams::try_from_reader(&mut &wire[..]).expect("RSA public parameters");
        PublicKey::from_inner(
            PubKeyInner::new(
                KeyVersion::V4,
                PublicKeyAlgorithm::RSA,
                Timestamp::now(),
                None,
                PublicParams::RSA(params),
            )
            .expect("valid public key material"),
        )
        .expect("a public key packet")
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
    fn the_public_key_floor_reads_an_rsa_modulus() {
        // The floor is expressed in modulus bits, so what it rests on is that
        // the bit count is read correctly off the wire form — including at the
        // boundary, where an off-by-one either refuses every archive key or
        // admits a key half the intended width.
        for bits in [1024, 2048, 4096] {
            let key = rsa_key_of_size(bits);
            let PublicParams::RSA(params) = key.public_params() else {
                panic!("the fixture is an RSA key");
            };
            assert_eq!(rsa_modulus_bits(params), Some(bits));
            assert_eq!(key_is_acceptable(&key), bits >= RSA_MINIMUM_BITS);
        }
    }

    #[test]
    fn a_key_the_public_key_floor_refuses_cannot_verify_a_release() {
        // A signature is worth no more than the key material behind it, so the
        // floor on the digest has a companion on the key. rPGP applies no
        // policy of its own — it verifies a DSA signature as readily as any
        // other — so the refusal is this crate's.
        let archive = test_dsa_key("archive <archive@test.invalid>");
        let signed = clearsign(&archive, SIGNED_BODY);
        let public = archive.to_public_key();

        let (message, _) =
            CleartextSignedMessage::from_armor(signed.as_bytes()).expect("armored document");
        message
            .verify(&public)
            .expect("rPGP verifies a DSA signature");
        assert!(!key_is_acceptable(&public.primary_key));

        let keyring = Keyring { keys: vec![public] };
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("a DSA archive key must be refused");
        let OpenPgpError::Signature(reason) = &err else {
            panic!("a refused key is a Signature error, got {err:?}");
        };
        assert_eq!(reason, WEAK_CERTIFICATE);

        // An encryption algorithm reaches the same refusing arm, the accepted
        // set being named rather than the refused one. Nothing rests on it —
        // such a key cannot sign, and its binding grants no signing flag — but
        // it is what makes the list a list of signature algorithms.
        let encrypting =
            test_key_with_signing_and_encryption_subkeys("a <a@test.invalid>").to_public_key();
        assert!(!key_is_acceptable(&encrypting.public_subkeys[1].key));
    }

    #[test]
    fn a_signature_carrying_an_unknown_critical_subpacket_is_refused() {
        // The critical bit is the signer saying a subpacket changes what the
        // signature means. RFC 9580 section 5.2.3.7 requires a verifier that
        // cannot interpret one to treat the signature as invalid. rPGP applies
        // that rule only to subpackets of an unknown type, and only while
        // signing; a critical notation, whose meaning is named by the signer
        // rather than by the format, and a critical subpacket from the
        // experimental range both pass it. This crate implements no notation, so
        // there is none it could satisfy.
        use pgp::bytes::Bytes;
        use pgp::packet::{Notation, Subpacket};
        let archive = test_key("archive <archive@test.invalid>");
        let public = archive.to_public_key();

        let uninterpretable = [
            SubpacketData::Notation(Notation {
                readable: true,
                name: Bytes::from_static(b"policy@test.invalid"),
                value: Bytes::from_static(b"strict"),
            }),
            SubpacketData::Experimental(101, Bytes::from_static(b"what")),
        ];
        for data in uninterpretable {
            for critical in [false, true] {
                let subpacket = if critical {
                    Subpacket::critical(data.clone())
                } else {
                    Subpacket::regular(data.clone())
                }
                .expect("a subpacket");
                let signed = clearsign_crafted(
                    &*archive,
                    SIGNED_BODY,
                    None,
                    Some(Timestamp::now()),
                    &[subpacket],
                );
                // rPGP signs and verifies it either way, and the subpacket
                // survives the armor round trip; only this crate's gate reads
                // the critical bit.
                let (message, _) = CleartextSignedMessage::from_armor(signed.as_bytes())
                    .expect("armored document");
                let signature = message.verify(&public).expect("cryptographically valid");
                assert_eq!(
                    has_unknown_critical_subpacket(signature),
                    critical,
                    "the fixture must carry {data:?}, critical={critical}",
                );

                let verified = Keyring {
                    keys: vec![public.clone()],
                }
                .verify(signed.as_bytes(), false);
                assert_eq!(
                    verified.is_ok(),
                    !critical,
                    "critical={critical} on {data:?}, got {verified:?}",
                );
            }
        }
    }

    #[test]
    fn a_signature_dated_before_its_signing_key_existed_is_refused() {
        // The key's validity window is closed at both ends. A signature dated
        // before its own key existed cannot have been made when it claims, and
        // that claimed date is what every other gate here measures against.
        let archive = test_key("archive <archive@test.invalid>");
        let public = archive.to_public_key();
        let key_created = i64::from(public.primary_key.created_at().as_secs());
        let signed = clearsign_crafted(
            &*archive,
            SIGNED_BODY,
            None,
            Some(Timestamp::from_secs(
                u32::try_from(key_created - 86_400).expect("a v4 timestamp"),
            )),
            &[],
        );

        let keyring = Keyring { keys: vec![public] };
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("a signature predating its key must be refused");
        let OpenPgpError::Signature(reason) = &err else {
            panic!("a refused signature is a Signature error, got {err:?}");
        };
        assert!(
            reason.contains("before its signing key existed"),
            "the reason names the lower bound: {reason}",
        );
    }

    #[test]
    fn a_zero_signature_expiration_means_the_signature_never_expires() {
        // Zero and absent are the two wire forms of "does not expire", exactly
        // as they are for a key expiration. Reading a zero duration literally
        // would place the deadline at the creation instant and expire every such
        // signature the moment it was made.
        use pgp::packet::Subpacket;
        let archive = test_key("archive <archive@test.invalid>");
        let signed = clearsign_crafted(
            &*archive,
            SIGNED_BODY,
            None,
            Some(Timestamp::now()),
            &[
                Subpacket::regular(SubpacketData::SignatureExpirationTime(Duration::from_secs(
                    0,
                )))
                .expect("signature-expiration subpacket"),
            ],
        );
        let keyring = Keyring {
            keys: vec![archive.to_public_key()],
        };
        // On the freshness-requiring path, which is the only one that reads it.
        keyring
            .verify(signed.as_bytes(), true)
            .expect("a zero expiration does not expire the signature");
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
}
