//! The signed release: verifying `InRelease` and reading its index digests.
//!
//! Authenticity of a Debian archive rests on the OpenPGP signature over the
//! `InRelease` file, which in turn carries the SHA-256 digest of every index.
//! This module verifies that signature against a keyring and parses the
//! result: every fetch below the release is checked against a digest that
//! chains back to the signature.

use std::collections::HashMap;

use pgp::composed::{CleartextSignedMessage, Deserializable, SignedPublicKey, SignedPublicSubKey};
use pgp::packet::{Signature, SignatureType};
use pgp::types::KeyDetails;

use super::index::parse_stanzas;

/// A failure verifying or reading the release.
#[derive(Debug)]
pub(crate) enum ReleaseError {
    /// The keyring could not be parsed.
    Keyring(String),
    /// The `InRelease` signature did not verify against the keyring.
    Signature(String),
    /// The release is well-signed but malformed, expired, or does not offer
    /// the requested architecture or component.
    Release(String),
}

/// The archive keyring: the public keys a release signature may be made with.
pub(crate) struct Keyring {
    keys: Vec<SignedPublicKey>,
}

impl Keyring {
    /// Parses a binary keyring of concatenated public keys, dropping any the
    /// archive has revoked.
    ///
    /// A revoked key is retired: the archive has published a self-revocation
    /// for it, so it must no longer verify a release even though its material
    /// is still present in the vendored keyring. Expired keys are kept here
    /// and judged per-signature at [`verify`](Self::verify) time, since a key
    /// that has since expired may still legitimately have signed an older,
    /// deliberately pinned release.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Keyring, ReleaseError> {
        let keys: Vec<_> = SignedPublicKey::from_bytes_many(bytes)
            .map_err(|err| ReleaseError::Keyring(err.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ReleaseError::Keyring(err.to_string()))?
            .into_iter()
            .filter(|key| !key_is_revoked(key))
            .collect();
        if keys.is_empty() {
            return Err(ReleaseError::Keyring(
                "the keyring holds no usable keys".to_string(),
            ));
        }
        Ok(Keyring { keys })
    }

    /// Verifies a cleartext-signed `InRelease` document and returns its body.
    ///
    /// The signature must verify against at least one key in the keyring;
    /// signatures from keys not in the keyring are ignored, as apt does. A
    /// release may be signed either by a keyring cert's primary key or by one
    /// of its signing-capable subkeys, and both are tried: Debian's archive
    /// automatic signing keys sign with a dedicated signing subkey rather than
    /// the primary, so verifying only the primary would reject every genuine
    /// Debian release. A subkey is admitted as a candidate only when a binding
    /// signature the primary issued over it cryptographically verifies, grants
    /// the signing key flag, and has not been revoked; an encryption subkey is
    /// never a candidate. See [`signing_subkeys`].
    ///
    /// Two checks are layered over rPGP's cryptographic verification, which on
    /// its own accepts a signature regardless of key or signature validity: the
    /// signing (sub)key must not have been expired when the signature was made,
    /// and — unless `require_fresh` is cleared for a deliberately pinned
    /// snapshot — the signature must not itself have expired. Expiry is judged
    /// against whichever (sub)key made the signature; for a subkey the
    /// authoritative window is its own binding signature, not the primary's
    /// self-signature. The returned text is the signed body, with the cleartext
    /// framing removed.
    ///
    /// Validity is judged per candidate, not only for the first candidate whose
    /// signature cryptographically verifies. A release may carry signatures
    /// from several archive keys during a key rotation; verification succeeds if
    /// any candidate yields a signature that is both cryptographically valid and
    /// passes the checks, so a valid co-signer is not masked by an expired one
    /// that happened to match first. When no candidate yields a fully valid
    /// signature, the specific reason from a cryptographically matching but
    /// invalid key is preferred over the generic "nothing matched".
    pub(crate) fn verify(
        &self,
        inrelease: &[u8],
        require_fresh: bool,
    ) -> Result<Verified, ReleaseError> {
        let (message, _headers) = CleartextSignedMessage::from_armor(inrelease)
            .map_err(|err| ReleaseError::Signature(err.to_string()))?;
        // For each keyring cert, try its primary key and then each of its
        // signing-capable subkeys. A candidate that verifies cryptographically
        // but is expired or whose signature is stale does not end the search; a
        // later candidate or co-signer may still be valid.
        let mut deferred: Option<ReleaseError> = None;
        for cert in &self.keys {
            // The primary, judged against its own expiry.
            if let Ok(signature) = message.verify(cert) {
                match check_signature_valid(signature, key_expiry_epoch(cert), require_fresh) {
                    Ok(()) => {
                        return Ok(Verified {
                            body: message.signed_text(),
                            signed_by: fingerprint_hex(&cert.fingerprint()),
                        });
                    }
                    Err(err) => {
                        deferred.get_or_insert(err);
                    }
                }
            }
            // Each signing-capable, unrevoked subkey, judged against the expiry
            // from its own binding signature.
            for candidate in signing_subkeys(cert) {
                if let Ok(signature) = message.verify(candidate.subkey) {
                    match check_signature_valid(signature, candidate.expiry, require_fresh) {
                        Ok(()) => {
                            return Ok(Verified {
                                body: message.signed_text(),
                                // The subkey's own fingerprint, not the
                                // primary's: it is the key that made the
                                // signature, and it is what a caller comparing
                                // against `gpg --list-keys` output on the
                                // signing subkey will see.
                                signed_by: fingerprint_hex(&candidate.subkey.fingerprint()),
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
            ReleaseError::Signature("no signature verified against the archive keyring".to_string())
        }))
    }
}

/// A release whose signature verified: the signed bytes, and the key that
/// signed them.
#[derive(Debug)]
pub(crate) struct Verified {
    /// The cleartext the signature covers — the release body itself, with the
    /// armor and the signature stripped.
    pub(crate) body: String,
    /// The verifying key's fingerprint, uppercase hex.
    pub(crate) signed_by: String,
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
/// signature is accepted only if its signing (sub)key was within its validity
/// window when the signature was made and — when `require_fresh` — the
/// signature has not itself expired. `signing_key_expiry` is the expiry epoch
/// of whichever (sub)key produced the signature, or `None` if it records none.
fn check_signature_valid(
    signature: &Signature,
    signing_key_expiry: Option<i64>,
    require_fresh: bool,
) -> Result<(), ReleaseError> {
    check_key_valid_at_signing(signing_key_expiry, signature)?;
    if require_fresh {
        check_signature_fresh(signature)?;
    }
    Ok(())
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

/// A signing-capable subkey of a keyring cert, paired with the expiry its
/// binding signature sets (if any).
struct SigningSubkey<'a> {
    subkey: &'a SignedPublicSubKey,
    expiry: Option<i64>,
}

/// The signing-capable, unrevoked subkeys of a keyring cert, each paired with
/// the expiry from its governing binding signature.
///
/// Debian's archive automatic signing keys sign releases with a dedicated
/// signing subkey rather than the primary, so a subkey must be admitted as a
/// verification candidate for any real archive to verify. A subkey qualifies
/// only when the primary has cryptographically bound it with the signing
/// capability and has not revoked it:
///
/// - The governing binding is the newest subkey-binding signature that
///   verifies as issued by the primary over this subkey (see
///   [`governing_binding`]). Verifying it establishes the link from the subkey
///   — the key that verified the release — back to the trusted primary, just as
///   the release signature is verified against the primary; a subkey with no
///   valid binding is not trusted. This is a stronger check than the primary's
///   own self-signatures receive, because a subkey is only as trustworthy as
///   its attested link to the anchor, whereas the primary is the anchor.
/// - The binding must grant the signing key flag. An encryption subkey, whose
///   binding carries no signing flag, is never a candidate, so its presence in
///   the keyring cannot be turned into a release signature.
/// - A subkey the primary has revoked is retired, exactly as a revoked primary
///   is dropped at [`Keyring::parse`] time (see [`subkey_is_revoked`]).
///
/// The paired expiry is read from the governing binding's key-expiration
/// subpacket and gates reuse of an aged-out subkey at [`Keyring::verify`] time.
fn signing_subkeys(cert: &SignedPublicKey) -> Vec<SigningSubkey<'_>> {
    cert.public_subkeys
        .iter()
        .filter_map(|subkey| {
            let binding = governing_binding(cert, subkey)?;
            if !binding.key_flags().sign() {
                return None;
            }
            if subkey_is_revoked(cert, subkey) {
                return None;
            }
            Some(SigningSubkey {
                subkey,
                expiry: subkey_expiry_epoch(subkey, binding),
            })
        })
        .collect()
}

/// The newest subkey-binding signature that cryptographically verifies as
/// issued by `cert`'s primary key over `subkey`, or `None` if the subkey
/// carries no valid binding.
///
/// A subkey may have been re-bound over time; the newest binding (by creation)
/// carries the current capability flags and expiration, mirroring how
/// [`key_expiry_epoch`] takes the newest expiration-bearing self-signature. A
/// binding with no creation time cannot be ordered by recency and is not
/// eligible to govern.
fn governing_binding<'a>(
    cert: &SignedPublicKey,
    subkey: &'a SignedPublicSubKey,
) -> Option<&'a Signature> {
    subkey
        .signatures
        .iter()
        .filter(|signature| signature.typ() == Some(SignatureType::SubkeyBinding))
        .filter(|signature| {
            signature
                .verify_subkey_binding(&cert.primary_key, &subkey.key)
                .is_ok()
        })
        .filter_map(|signature| Some((signature.created()?, signature)))
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
/// time, not the primary's, so the epoch is computed from the subkey. A zero
/// duration is the wire form for "no expiration" and yields `None`, left to the
/// other checks.
fn subkey_expiry_epoch(subkey: &SignedPublicSubKey, binding: &Signature) -> Option<i64> {
    let created = i64::from(subkey.key.created_at().as_secs());
    let seconds = binding.key_expiration_time()?.as_secs();
    (seconds > 0).then(|| created.saturating_add(i64::from(seconds)))
}

/// Rejects a signature made after its signing (sub)key had expired.
///
/// OpenPGP key validity is time-relative: a signature is legitimate if the
/// key was within its validity window when the signature was made. This
/// refuses a (sub)key retired by expiry whose material is reused to sign a
/// fresh release — the signature time is now, past the key's expiry — while
/// leaving a genuinely old signature (made while the key was valid) acceptable,
/// so a pinned snapshot still verifies. `expiry` is the signing (sub)key's
/// expiration epoch, from [`key_expiry_epoch`] for a primary or
/// [`subkey_expiry_epoch`] for a subkey; `None` there, or a signature with no
/// creation time, leaves the judgement to the other checks.
fn check_key_valid_at_signing(
    expiry: Option<i64>,
    signature: &Signature,
) -> Result<(), ReleaseError> {
    let (Some(expiry), Some(signed_at)) = (expiry, signature.created()) else {
        return Ok(());
    };
    if i64::from(signed_at.as_secs()) > expiry {
        return Err(ReleaseError::Release(
            "the release signature was made after its signing key expired".to_string(),
        ));
    }
    Ok(())
}

/// The Unix time at which a key expires, from the key-expiration subpacket of
/// its most recent expiration-bearing self-signature relative to the primary
/// key's creation, or `None` if no self-signature sets an expiration.
///
/// OpenPGP key validity is time-relative: a later self-signature re-dates the
/// key. Among the self-signatures that set an expiration, the one made most
/// recently governs, so a re-dating that shortens the key's lifetime supersedes
/// an earlier, more generous one. Taking the newest such signature rather than
/// the maximum expiry across all of them is what honors a deliberate
/// shortening, so a key retired by a re-dating is judged expired at the
/// intended time. A self-signature carrying no expiration does not itself grant
/// unlimited validity here — it simply does not define the current expiry, so
/// it is skipped rather than read as "never expires", the conservative reading.
/// Only signatures the primary key issued over itself are authoritative; the
/// keyring is vendored and trusted, so a self-signature is taken by its issuer
/// key id without a separate cryptographic check.
fn key_expiry_epoch(key: &SignedPublicKey) -> Option<i64> {
    let primary_created = i64::from(key.primary_key.created_at().as_secs());
    let primary_id = key.primary_key.legacy_key_id();
    // The authoritative self-signatures live on the key's direct signatures and
    // on each user id's binding signatures.
    let self_signatures = key
        .details
        .direct_signatures
        .iter()
        .chain(
            key.details
                .users
                .iter()
                .flat_map(|user| user.signatures.iter()),
        )
        .filter(|signature| {
            signature
                .issuer_key_id()
                .iter()
                .any(|id| **id == primary_id)
        });

    // The current expiry is the one carried by the newest self-signature that
    // sets an expiration. A signature with no creation time cannot be ordered
    // by recency, so it is not eligible to define the current validity.
    let newest_expiry = self_signatures
        .filter_map(|signature| {
            let created = signature.created()?;
            let seconds = signature.key_expiration_time()?.as_secs();
            (seconds > 0).then_some((created, seconds))
        })
        .max_by_key(|(created, _)| *created)?
        .1;

    Some(primary_created.saturating_add(newest_expiry as i64))
}

/// Rejects a release signature that has passed its own expiration.
///
/// A Debian archive signature is short-lived; its expiration pairs with the
/// release's `Valid-Until` to bound replay. A signature with no expiration,
/// or a clock before the epoch, is left to the `Valid-Until` check, which is
/// the primary freshness gate.
fn check_signature_fresh(signature: &Signature) -> Result<(), ReleaseError> {
    let (Some(created), Some(duration)) =
        (signature.created(), signature.signature_expiration_time())
    else {
        return Ok(());
    };
    let Some(now) = now_epoch() else {
        return Ok(());
    };
    let expires_at = i64::from(created.as_secs()).saturating_add(duration.as_secs() as i64);
    if now > expires_at {
        return Err(ReleaseError::Release(
            "the release signature has expired".to_string(),
        ));
    }
    Ok(())
}

/// A parsed `Release` body: the index digests and the release's own claims.
pub(crate) struct Release {
    /// Index path (relative to `dists/<suite>/`) to `(size, sha256)`.
    hashes: HashMap<String, (u64, String)>,
    acquire_by_hash: bool,
    architectures: Vec<String>,
    components: Vec<String>,
    valid_until: Option<String>,
    /// The release's own `Date:` field, as written. Read for provenance rather
    /// than for any check: freshness is judged against `Valid-Until`.
    date: Option<String>,
    /// The release's own `Suite:` field (for example `stable`), if present.
    suite: Option<String>,
    /// The release's own `Codename:` field (for example `trixie`), if present.
    codename: Option<String>,
    /// The SHA-256 of the body this was parsed from, lowercase hex.
    ///
    /// Computed here rather than by the caller so it is unambiguously the
    /// digest of the bytes that were verified: for a signed repository that is
    /// the cleartext the signature covers, not the `InRelease` armor around it
    /// and not a re-fetch.
    sha256: String,
}

impl Release {
    /// Parses a release body (the verified `InRelease` text, or a trusted
    /// `Release`).
    pub(crate) fn parse(body: &str) -> Result<Release, ReleaseError> {
        let stanza = parse_stanzas(body)
            .into_iter()
            .next()
            .ok_or_else(|| ReleaseError::Release("the release file is empty".to_string()))?;

        let mut hashes = HashMap::new();
        if let Some(list) = stanza.get("SHA256") {
            for line in list.lines() {
                let mut fields = line.split_whitespace();
                if let (Some(digest), Some(size), Some(path)) =
                    (fields.next(), fields.next(), fields.next())
                    && let Ok(size) = size.parse()
                {
                    hashes.insert(path.to_string(), (size, digest.to_string()));
                }
            }
        }

        Ok(Release {
            hashes,
            acquire_by_hash: stanza
                .get("Acquire-By-Hash")
                .is_some_and(|value| value.eq_ignore_ascii_case("yes")),
            architectures: split_ws(stanza.get("Architectures")),
            components: split_ws(stanza.get("Components")),
            valid_until: stanza.get("Valid-Until").map(str::to_string),
            date: stanza.get("Date").map(|value| value.trim().to_string()),
            suite: stanza.get("Suite").map(|value| value.trim().to_string()),
            codename: stanza.get("Codename").map(|value| value.trim().to_string()),
            sha256: super::deb::sha256_hex(body.as_bytes()),
        })
    }

    /// The release's `Date` field, as written.
    pub(crate) fn date(&self) -> Option<&str> {
        self.date.as_deref()
    }

    /// The release's `Valid-Until` field, as written.
    pub(crate) fn valid_until(&self) -> Option<&str> {
        self.valid_until.as_deref()
    }

    /// The SHA-256 of the verified body, lowercase hex.
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Checks that the release binds to the requested `suite`, offers
    /// `architecture` and every requested component, and — when
    /// `require_valid_until` is set — carries a parseable `Valid-Until` that
    /// has not passed.
    pub(crate) fn check(
        &self,
        suite: &str,
        architecture: &str,
        components: &[String],
        require_valid_until: bool,
    ) -> Result<(), ReleaseError> {
        self.check_suite(suite)?;
        if !self.architectures.iter().any(|arch| arch == architecture) {
            return Err(ReleaseError::Release(format!(
                "the suite does not offer architecture {architecture} (offers {})",
                self.architectures.join(", "),
            )));
        }
        for component in components {
            if !self.components.iter().any(|offered| offered == component) {
                return Err(ReleaseError::Release(format!(
                    "the suite does not offer component {component} (offers {})",
                    self.components.join(", "),
                )));
            }
        }
        self.check_freshness(require_valid_until)?;
        Ok(())
    }

    /// Requires the release's own `Suite:` or `Codename:` to equal the
    /// requested suite.
    ///
    /// A single archive key signs the release of every Debian suite, so the
    /// signature alone does not establish which suite was delivered. Without
    /// this binding a mirror (or a man-in-the-middle on the default plaintext
    /// transport) could answer a request for one suite with a genuine,
    /// validly-signed release for another — a silent cross-suite or downgrade
    /// substitution. This is the binding `debootstrap` and `apt` enforce.
    fn check_suite(&self, requested: &str) -> Result<(), ReleaseError> {
        let identifies_as = |field: &Option<String>| field.as_deref() == Some(requested);
        if identifies_as(&self.suite) || identifies_as(&self.codename) {
            return Ok(());
        }
        Err(ReleaseError::Release(format!(
            "the release does not identify as suite {requested} (its Suite is {}, its Codename is {})",
            self.suite.as_deref().unwrap_or("absent"),
            self.codename.as_deref().unwrap_or("absent"),
        )))
    }

    /// Enforces release freshness when `require_valid_until` is set: a
    /// `Valid-Until` the release carries must be parseable and not in the
    /// past.
    ///
    /// A present field is enforced strictly — an unparseable value is a hard
    /// failure rather than a silent skip, and a passed deadline is a rejection
    /// — so a stale (but validly-signed) release cannot be replayed to deliver
    /// superseded, potentially vulnerable packages, and a format quirk cannot
    /// quietly disable the check. When the deadline cannot be evaluated because
    /// the system clock is before the epoch, the release is rejected rather
    /// than trusted blind.
    ///
    /// An *absent* `Valid-Until` is accepted, as `apt` accepts it: the Debian
    /// stable suite deliberately omits the field so its release does not expire
    /// between point releases, and rejecting that would break bootstrapping
    /// stable. Such a release simply carries no freshness bound. The caller
    /// relaxes the check entirely on a trusted local mirror, or when
    /// deliberately pinning a historical snapshot whose deadline has passed.
    fn check_freshness(&self, require_valid_until: bool) -> Result<(), ReleaseError> {
        if !require_valid_until {
            return Ok(());
        }
        let Some(valid_until) = self.valid_until.as_deref() else {
            return Ok(());
        };
        let deadline = parse_rfc5322(valid_until).ok_or_else(|| {
            ReleaseError::Release(format!(
                "the release Valid-Until {valid_until} is unparseable"
            ))
        })?;
        let now = now_epoch().ok_or_else(|| {
            ReleaseError::Release(
                "the system clock is before the Unix epoch, so release freshness cannot be \
                 established"
                    .to_string(),
            )
        })?;
        if now > deadline {
            return Err(ReleaseError::Release(format!(
                "the release expired at {valid_until}"
            )));
        }
        Ok(())
    }

    /// The `(size, sha256)` recorded for an index path, if any.
    pub(crate) fn digest(&self, path: &str) -> Option<(u64, &str)> {
        self.hashes
            .get(path)
            .map(|(size, digest)| (*size, digest.as_str()))
    }

    /// Whether the archive publishes indexes under `by-hash/SHA256/<digest>`.
    pub(crate) fn acquire_by_hash(&self) -> bool {
        self.acquire_by_hash
    }
}

/// Splits a whitespace-separated field into owned tokens.
fn split_ws(value: Option<&str>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(str::split_whitespace)
        .map(str::to_string)
        .collect()
}

/// The current time as a Unix timestamp, or `None` if the clock is before
/// the epoch (which would make a freshness check meaningless).
pub(super) fn now_epoch() -> Option<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|since| since.as_secs() as i64)
}

/// Parses an RFC 5322 date (`Sat, 11 Jul 2026 09:02:23 UTC`) to a Unix
/// timestamp.
///
/// The trailing zone is honored: the Debian archive stamps `UTC`, but a
/// numeric offset such as `+0000` or `-0500` is applied so a format change
/// does not misread the time by the offset. A value that does not parse —
/// including one with an unrecognized zone — returns `None`, which the
/// caller treats as a freshness failure rather than a silent pass.
pub(super) fn parse_rfc5322(text: &str) -> Option<i64> {
    let mut fields = text.split_whitespace();
    // Optional "Dow," leader.
    let mut first = fields.next()?;
    if first.ends_with(',') {
        first = fields.next()?;
    }
    let day: i64 = first.parse().ok()?;
    let month = match fields.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = fields.next()?.parse().ok()?;
    let mut time = fields.next()?.split(':');
    let hour: i64 = time.next()?.parse().ok()?;
    let minute: i64 = time.next()?.parse().ok()?;
    let second: i64 = time.next().unwrap_or("0").parse().ok()?;
    // The civil-date arithmetic below is happy to roll an out-of-range field
    // over — `32 Jan` would land in February — which would read a malformed
    // deadline as a slightly wrong one instead of the documented hard failure.
    // A leap second is the one deliberate tolerance, since a stamp may carry
    // `:60`.
    if !(1..=days_in_month(year, month)).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        // A stamp may carry a leap second, so 60 is the ceiling here.
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let offset = parse_zone(fields.next()?)?;
    // Checked throughout: an absurd year, hour, or minute overflows to `None`,
    // which the caller treats as a freshness failure rather than a wrapped,
    // bogus deadline.
    let local = days_from_civil(year, month, day)?
        .checked_mul(86400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    // The parsed fields name a wall-clock time in the given zone; subtract the
    // zone's offset from UTC to reach the Unix timestamp.
    local.checked_sub(offset)
}

/// Parses an RFC 5322 zone into its offset from UTC in seconds. Handles the
/// `UTC`/`GMT`/`UT`/`Z` forms and a numeric `+HHMM`/`-HHMM` offset; any other
/// token is unrecognized and returns `None`.
fn parse_zone(token: &str) -> Option<i64> {
    match token {
        "UTC" | "GMT" | "UT" | "Z" => Some(0),
        _ => {
            let bytes = token.as_bytes();
            if bytes.len() != 5 {
                return None;
            }
            let sign = match bytes[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let hours: i64 = token.get(1..3)?.parse().ok()?;
            let minutes: i64 = token.get(3..5)?.parse().ok()?;
            if hours >= 24 || minutes >= 60 {
                return None;
            }
            Some(sign * (hours * 3600 + minutes * 60))
        }
    }
}

/// Formats a Unix timestamp as the RFC 5322 date a `Release` stamps, for
/// example `Sat, 11 Jul 2026 09:02:23 UTC`.
///
/// The zone is spelled `UTC` rather than `+0000`, which is what the Debian
/// archive stamps and what every client that reads one therefore accepts;
/// [`parse_rfc5322`] reads either. The result round-trips through it.
///
/// Every timestamp formats, including one before the epoch: the field records
/// when a pool was published rather than gating anything, so an odd clock
/// yields an odd date instead of failing the publish that carries it.
pub(super) fn format_rfc5322(epoch: i64) -> String {
    // Floored division throughout, so a pre-epoch timestamp borrows into the
    // previous day rather than truncating toward zero into the next one.
    let days = epoch.div_euclid(86400);
    let seconds = epoch.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday, the fourth day of a week starting Sunday.
    let weekday =
        ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][(days + 4).rem_euclid(7) as usize];
    let month_name = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(month - 1) as usize];
    format!(
        "{weekday}, {day:02} {month_name} {year:04} {:02}:{:02}:{:02} UTC",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60,
    )
}

/// The civil date for a count of days since the Unix epoch (Howard Hinnant's
/// algorithm), the inverse of [`days_from_civil`].
///
/// Total where its inverse is checked: the input is a day count derived from a
/// timestamp rather than parsed from a document, so there is no absurd year to
/// reject, and the arithmetic cannot overflow for any `i64` a clock produces.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719468;
    let era = shifted.div_euclid(146097);
    let day_of_era = shifted.rem_euclid(146097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    // The algorithm counts years from March, so January and February belong to
    // the following civil year.
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's algorithm),
/// or `None` if the arithmetic overflows for an absurd year — treated by the
/// caller as an unparseable, and therefore stale, date.
/// The number of days in `month` of `year`, for bounding a parsed date. The
/// Gregorian leap rule applies, so February is 29 days only in a leap year.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            if leap { 29 } else { 28 }
        }
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let year = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = if year >= 0 {
        year
    } else {
        year.checked_sub(399)?
    } / 400;
    let year_of_era = year.checked_sub(era.checked_mul(400)?)?;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = ((153 * month_index + 2) / 5)
        .checked_add(day)?
        .checked_sub(1)?;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era / 4)?
        .checked_sub(year_of_era / 100)?
        .checked_add(day_of_year)?;
    era.checked_mul(146097)?
        .checked_add(day_of_era)?
        .checked_sub(719468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::types::{Duration, Timestamp};

    #[test]
    fn release_parses_hashes_and_claims() {
        let body = "\
Suite: stable
Codename: trixie
Architectures: all amd64 arm64
Components: main contrib
Acquire-By-Hash: yes
SHA256:
 aaa 111 main/binary-amd64/Packages
 bbb 222 main/binary-amd64/Packages.xz
";
        let release = Release::parse(body).unwrap();
        assert!(release.acquire_by_hash());
        assert_eq!(
            release.digest("main/binary-amd64/Packages.xz"),
            Some((222, "bbb"))
        );
        // The requested suite may match either the Suite or the Codename.
        release
            .check("stable", "amd64", &["main".to_string()], false)
            .unwrap();
        release
            .check("trixie", "amd64", &["main".to_string()], false)
            .unwrap();
        assert!(release.check("stable", "riscv64", &[], false).is_err());
        assert!(
            release
                .check("stable", "amd64", &["nonfree".to_string()], false)
                .is_err()
        );
    }

    #[test]
    fn a_release_for_the_wrong_suite_is_rejected() {
        // A genuine, well-formed release whose Suite and Codename are both a
        // different suite than requested is refused: a single archive key
        // signs every suite, so only this binding stops a cross-suite swap.
        let body = "\
Suite: oldstable
Codename: bookworm
Architectures: amd64
Components: main
";
        let release = Release::parse(body).unwrap();
        let err = release
            .check("trixie", "amd64", &["main".to_string()], false)
            .unwrap_err();
        assert!(matches!(err, ReleaseError::Release(_)));
        // The matching suite passes the same check.
        release
            .check("bookworm", "amd64", &["main".to_string()], false)
            .unwrap();
    }

    #[test]
    fn a_release_without_a_suite_identity_is_rejected() {
        // A release that names neither Suite nor Codename cannot be bound to
        // the request, so it is refused rather than trusted.
        let body = "\
Architectures: amd64
Components: main
";
        let release = Release::parse(body).unwrap();
        assert!(
            release
                .check("trixie", "amd64", &["main".to_string()], false)
                .is_err()
        );
    }

    #[test]
    fn civil_dates_match_known_epochs() {
        // 1970-01-01 and 2000-01-01.
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2000, 1, 1), Some(10957));
        // 2026-07-11 09:02:23 UTC.
        assert_eq!(
            parse_rfc5322("Sat, 11 Jul 2026 09:02:23 UTC"),
            Some(1_783_760_543)
        );
        // A leading day-of-week is optional.
        assert_eq!(
            parse_rfc5322("11 Jul 2026 09:02:23 GMT"),
            Some(1_783_760_543)
        );
        assert_eq!(parse_rfc5322("not a date"), None);
    }

    #[test]
    fn formatting_names_the_instant_the_parser_reads_back() {
        // The dates a pool stamps, spelled the way the Debian archive spells
        // them. The cases are the ones the civil-date arithmetic can get wrong:
        // the epoch itself, a leap day, the day after a century that is not a
        // leap year, and a pre-epoch instant, where flooring toward the
        // previous day is what keeps the time of day from running backwards.
        for (epoch, text) in [
            (0, "Thu, 01 Jan 1970 00:00:00 UTC"),
            (1_709_210_096, "Thu, 29 Feb 2024 12:34:56 UTC"),
            (4_107_542_400, "Mon, 01 Mar 2100 00:00:00 UTC"),
            (-1, "Wed, 31 Dec 1969 23:59:59 UTC"),
            (1_783_760_543, "Sat, 11 Jul 2026 09:02:23 UTC"),
        ] {
            assert_eq!(format_rfc5322(epoch), text);
            // The pair is a round trip: what the writer stamps is what the
            // reader — this crate's own, and apt's — resolves back to.
            assert_eq!(parse_rfc5322(text), Some(epoch));
        }
        // The date is caller-supplied, so the extremes are reachable. Dividing
        // to days bounds every intermediate well inside i64, and each formats
        // rather than overflowing one — however absurd the year it names.
        for extreme in [i64::MIN, i64::MAX] {
            assert!(format_rfc5322(extreme).ends_with(" UTC"));
        }
    }

    #[test]
    fn every_civil_date_round_trips_through_both_directions() {
        // A day-by-day sweep either side of the epoch, across the 2024 leap
        // day, and across 2100 — a century that is not a leap year. Those are
        // where an off-by-one in either direction of the conversion shows up
        // and a spot check does not.
        let spans = [-400..400, 19_650..20_150, 47_300..47_800];
        for day in spans.into_iter().flatten() {
            let epoch = day * 86400 + 3661;
            let (year, month, date) = civil_from_days(day);
            assert_eq!(days_from_civil(year, month, date), Some(day));
            assert_eq!(parse_rfc5322(&format_rfc5322(epoch)), Some(epoch));
        }
    }

    #[test]
    fn an_absurd_year_does_not_overflow() {
        // A year large enough to overflow the day arithmetic parses to None
        // rather than panicking or wrapping to a bogus deadline.
        assert_eq!(days_from_civil(i64::MAX, 7, 11), None);
        // A 19-digit year within i64's range parses, then overflows the day
        // arithmetic; the checked path returns None rather than wrapping.
        assert_eq!(parse_rfc5322("11 Jul 9000000000000000000 UTC"), None);
    }

    #[test]
    fn an_out_of_range_field_does_not_roll_over() {
        // The civil-date arithmetic would happily read `32 Jan` as 1 February
        // and `25:00` as the next day, turning a malformed Valid-Until into a
        // deadline that is merely wrong. A malformed stamp is a freshness
        // failure instead.
        for text in [
            "32 Jan 2026 09:02:23 UTC",
            "0 Jan 2026 09:02:23 UTC",
            "30 Feb 2026 09:02:23 UTC",
            "29 Feb 2026 09:02:23 UTC",
            "31 Apr 2026 09:02:23 UTC",
            "11 Jul 2026 24:02:23 UTC",
            "11 Jul 2026 09:60:23 UTC",
            "11 Jul 2026 09:02:61 UTC",
            "11 Jul 2026 09:02:23 +2400",
        ] {
            assert_eq!(parse_rfc5322(text), None, "{text}");
        }
        // The boundaries that are legal stay legal: a leap day in a leap year,
        // and the leap second a stamp may carry.
        assert!(parse_rfc5322("29 Feb 2028 09:02:23 UTC").is_some());
        assert!(parse_rfc5322("31 Dec 2026 23:59:60 UTC").is_some());
    }

    #[test]
    fn rfc5322_applies_the_zone_offset() {
        // A numeric +0000 offset is the same instant as UTC.
        assert_eq!(
            parse_rfc5322("Sat, 11 Jul 2026 09:02:23 +0000"),
            Some(1_783_760_543)
        );
        // A positive offset names an earlier UTC instant, a negative one a
        // later instant, each by the offset.
        assert_eq!(
            parse_rfc5322("Sat, 11 Jul 2026 09:02:23 +0100"),
            Some(1_783_760_543 - 3600)
        );
        assert_eq!(
            parse_rfc5322("Sat, 11 Jul 2026 09:02:23 -0530"),
            Some(1_783_760_543 + 5 * 3600 + 30 * 60)
        );
        // A missing or unrecognized zone does not parse, so freshness fails
        // loudly rather than silently reading the time as UTC.
        assert_eq!(parse_rfc5322("11 Jul 2026 09:02:23"), None);
        assert_eq!(parse_rfc5322("11 Jul 2026 09:02:23 EST"), None);
    }

    #[test]
    fn an_expired_release_is_rejected_when_freshness_is_required() {
        let body = "\
Suite: trixie
Architectures: amd64
Components: main
Valid-Until: Mon, 01 Jan 1990 00:00:00 UTC
";
        let release = Release::parse(body).unwrap();
        let err = release
            .check("trixie", "amd64", &["main".to_string()], true)
            .unwrap_err();
        assert!(matches!(err, ReleaseError::Release(_)));
        // The same stale release is accepted when freshness is not required
        // (a trusted local mirror, or a deliberately pinned snapshot).
        release
            .check("trixie", "amd64", &["main".to_string()], false)
            .unwrap();
    }

    #[test]
    fn a_missing_valid_until_is_accepted() {
        // The Debian stable suite omits Valid-Until so its release does not
        // expire between point releases; an absent field is accepted (it
        // carries no freshness bound), even on the required path, as apt
        // accepts it. Only a present field is enforced.
        let body = "\
Suite: trixie
Architectures: amd64
Components: main
";
        let release = Release::parse(body).unwrap();
        release
            .check("trixie", "amd64", &["main".to_string()], true)
            .unwrap();
    }

    #[test]
    fn an_unparseable_valid_until_is_rejected_when_freshness_is_required() {
        let body = "\
Suite: trixie
Architectures: amd64
Components: main
Valid-Until: sometime next week
";
        let release = Release::parse(body).unwrap();
        assert!(
            release
                .check("trixie", "amd64", &["main".to_string()], true)
                .is_err()
        );
    }

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
        let keyring = Keyring::parse(super::super::EMBEDDED_KEYRING).unwrap();
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
        use pgp::composed::{KeyType, SecretKeyParamsBuilder};
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(user_id.to_string());
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
        // A `SignedSecretKey` derefs to the `SecretKey` packet, which is the
        // signer.
        clearsign_with(&**key, body)
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
    /// one RSA encryption subkey (second), to exercise the signing-capability
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
            .key_type(KeyType::Rsa(2048))
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

    /// Signs a subkey binding or revocation of `subkey` with `primary`'s primary
    /// key, carrying the given creation time, key flags, and optional
    /// key-expiration. The high-level builder emits only a plain, non-expiring
    /// binding, so tests that need a revocation or an expiration craft the
    /// signature packet here.
    #[cfg(test)]
    fn craft_subkey_signature(
        primary: &pgp::composed::SignedSecretKey,
        subkey: &pgp::composed::SignedSecretSubKey,
        typ: SignatureType,
        created: pgp::types::Timestamp,
        key_flags: pgp::packet::KeyFlags,
        key_expiration: Option<pgp::types::Duration>,
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
                Err(ReleaseError::Signature(_))
            ),
            "a foreign key's signature must not verify",
        );

        // A body altered after signing no longer matches the signature.
        let tampered = good.replace("Suite: test", "Suite: evil");
        assert_ne!(tampered, good, "the tamper must actually change the body");
        assert!(
            matches!(
                keyring.verify(tampered.as_bytes(), false),
                Err(ReleaseError::Signature(_))
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
        let candidates = signing_subkeys(&public);
        assert_eq!(candidates.len(), 1, "only the signing subkey qualifies");
        assert_eq!(
            candidates[0].subkey.fingerprint(),
            public.public_subkeys[0].fingerprint(),
            "the surviving candidate is the signing subkey, not the encryption one",
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
        );
        revoked.public_subkeys[0].signatures.push(revocation);
        let revoked_keyring = Keyring {
            keys: vec![revoked],
        };
        assert!(
            matches!(
                revoked_keyring.verify(signed.as_bytes(), false),
                Err(ReleaseError::Signature(_)),
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
        );
        public.public_subkeys[0].signatures = vec![expiring_binding];

        let keyring = Keyring { keys: vec![public] };
        let err = keyring
            .verify(signed.as_bytes(), false)
            .expect_err("an expired signing subkey must be refused");
        assert!(
            matches!(err, ReleaseError::Release(_)),
            "expiry is a Release error, got {err:?}",
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
        let keyring = Keyring::parse(super::super::EMBEDDED_KEYRING).unwrap();

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
        // The subkey that signed it, not the primary that bound the subkey: it
        // is the key that made the signature, so it is the one a caller pinning
        // a fingerprint would pin.
        assert_eq!(
            verified.signed_by.len(),
            40,
            "an uppercase v4 fingerprint: {}",
            verified.signed_by,
        );
        assert!(
            verified
                .signed_by
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase()),
            "uppercase hex, as the OpenPGP tools present one: {}",
            verified.signed_by,
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
        let keyring = Keyring::parse(super::super::EMBEDDED_KEYRING).unwrap();
        let signing: usize = keyring
            .keys
            .iter()
            .map(|cert| signing_subkeys(cert).len())
            .sum();
        assert!(
            signing > 0,
            "the embedded keyring exposes no verifiable signing subkeys; the subkey \
             verification path would reject every real Debian release",
        );
    }
}
