//! Reading an apk signing key: an RSA public key (RFC 8017 appendix A.1.1) in
//! a `SubjectPublicKeyInfo` (RFC 5280 section 4.1.2.7), PEM-encoded under the
//! `PUBLIC KEY` label (RFC 7468 section 13). That is what `openssl rsa -pubout`
//! writes, what `abuild-keygen` publishes, and what `alpine-keys` ships.
//!
//! Only that one shape is read, and it is read as DER requires: definite
//! lengths in the fewest octets, positive integers in the fewest octets, and
//! nothing left over at any level. A key spelled any other way, such as a
//! PKCS #1 `RSA PUBLIC KEY` block, is refused rather than guessed at.

use irongall::rsa::PublicKey;

use super::super::base64;

/// The line a PEM `PUBLIC KEY` block opens with.
const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";

/// The line a PEM `PUBLIC KEY` block closes with.
const END: &str = "-----END PUBLIC KEY-----";

/// The DER tag of an `INTEGER`.
const INTEGER: u8 = 0x02;

/// The DER tag of a `BIT STRING`.
const BIT_STRING: u8 = 0x03;

/// The DER tag of a `SEQUENCE`.
const SEQUENCE: u8 = 0x30;

/// The `AlgorithmIdentifier` of an RSA key as DER spells it: `rsaEncryption`
/// (1.2.840.113549.1.1.1), with the NULL parameters RFC 3279 section 2.3.1
/// requires.
const RSA_ENCRYPTION: [u8; 15] = [
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/// The RSA public key `pem` holds, or why it holds none: a phrase that
/// completes "the key is not a usable RSA public key".
///
/// irongall decides what an RSA key may be, so a key it would not verify with
/// is refused here, with its reason: a modulus outside 2048 to 8192 bits, or
/// an exponent that is even, below 3, or above 2^33 - 1.
pub(super) fn rsa_public_key(pem: &str) -> Result<PublicKey, String> {
    let der = der(pem)?;
    let (modulus, exponent) = components(&der)?;
    PublicKey::new(modulus, exponent).map_err(|err| err.to_string())
}

/// The DER a PEM `PUBLIC KEY` block carries.
///
/// Whitespace may surround the block and break its body into lines of any
/// length, with either line ending. Nothing else may surround it.
fn der(pem: &str) -> Result<Vec<u8>, String> {
    let body = pem
        .trim()
        .strip_prefix(BEGIN)
        .and_then(|rest| rest.strip_suffix(END))
        .ok_or_else(|| "it is not a PEM block labelled PUBLIC KEY".to_string())?;
    let body: String = body.split_ascii_whitespace().collect();
    base64::decode(&body).ok_or_else(|| "its PEM body is not base64".to_string())
}

/// The modulus and the public exponent a DER `SubjectPublicKeyInfo` holds,
/// each big-endian and without leading zeros.
fn components(der: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let malformed = || "its SubjectPublicKeyInfo is not well-formed DER".to_string();
    let info = whole(der, SEQUENCE).ok_or_else(malformed)?;
    let Some(info) = info.strip_prefix(&RSA_ENCRYPTION[..]) else {
        return Err("it is not an RSA key".to_string());
    };
    let bits = whole(info, BIT_STRING).ok_or_else(malformed)?;
    // A key is a whole number of octets, so the bit string's first octet, the
    // count of unused bits in its last, is zero.
    let key = bits.strip_prefix(&[0]).ok_or_else(malformed)?;
    let key = whole(key, SEQUENCE).ok_or_else(malformed)?;
    let (modulus, key) = element(key, INTEGER).ok_or_else(malformed)?;
    let exponent = whole(key, INTEGER).ok_or_else(malformed)?;
    Ok((
        positive(modulus).ok_or_else(malformed)?,
        positive(exponent).ok_or_else(malformed)?,
    ))
}

/// The contents of the DER element tagged `tag` that `input` holds exactly,
/// with nothing after it.
fn whole(input: &[u8], tag: u8) -> Option<&[u8]> {
    element(input, tag).and_then(|(contents, rest)| rest.is_empty().then_some(contents))
}

/// The contents of the DER element tagged `tag` at the start of `input`, and
/// what follows it, or `None` where `input` does not begin with one: another
/// tag, a length DER does not spell that way, or contents running past the
/// input.
///
/// DER spells a length definitely and in the fewest octets. Lengths up to
/// 65535 are read, past the largest key irongall verifies with.
fn element(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&found, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = match first {
        0x00..=0x7F => (usize::from(first), rest),
        0x81 => {
            let (&length, rest) = rest.split_first()?;
            (length >= 0x80).then_some((usize::from(length), rest))?
        }
        0x82 => {
            let (length, rest) = rest.split_first_chunk::<2>()?;
            let length = u16::from_be_bytes(*length);
            (length >= 0x100).then_some((usize::from(length), rest))?
        }
        _ => return None,
    };
    if found != tag {
        return None;
    }
    rest.split_at_checked(length)
}

/// The magnitude of a DER `INTEGER` from its contents, or `None` for a
/// negative integer or one not spelled in the fewest octets.
///
/// DER prefixes a zero octet only where the magnitude's top bit is set, since
/// the integer would read as negative without it.
fn positive(contents: &[u8]) -> Option<&[u8]> {
    match contents {
        [] => None,
        [0x00, next, ..] if next & 0x80 == 0 => None,
        [0x00, magnitude @ ..] if !magnitude.is_empty() => Some(magnitude),
        [first, ..] if first & 0x80 != 0 => None,
        _ => Some(contents),
    }
}

#[cfg(test)]
mod tests {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    use super::super::{ALPINE, POSTMARKETOS};
    use super::*;

    /// A DER element: `tag`, its length in the fewest octets, and `contents`.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let length = contents.len();
        let mut out = vec![tag];
        match length {
            0..=0x7F => out.push(length as u8),
            0x80..=0xFF => out.extend([0x81, length as u8]),
            _ => out.extend([0x82, (length >> 8) as u8, length as u8]),
        }
        out.extend_from_slice(contents);
        out
    }

    /// The `SubjectPublicKeyInfo` of the key whose `INTEGER` contents are
    /// `modulus` and `exponent`, as given.
    fn spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        let key = tlv(
            SEQUENCE,
            &[tlv(INTEGER, modulus), tlv(INTEGER, exponent)].concat(),
        );
        tlv(
            SEQUENCE,
            &[
                &RSA_ENCRYPTION[..],
                &tlv(BIT_STRING, &[&[0][..], &key].concat()),
            ]
            .concat(),
        )
    }

    /// `der` as a PEM `PUBLIC KEY` block, its body in lines of 64.
    fn pem_of(der: &[u8]) -> String {
        let body = base64::encode(der);
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect();
        format!("{BEGIN}\n{}\n{END}\n", lines.join("\n"))
    }

    /// The `INTEGER` contents of an odd modulus of `bits` bits, its top bit
    /// set and so prefixed by the zero octet DER requires.
    fn modulus_of(bits: usize) -> Vec<u8> {
        let mut magnitude = vec![0x5A; bits / 8];
        magnitude[0] = 0xC5;
        *magnitude.last_mut().unwrap() |= 1;
        [&[0][..], &magnitude].concat()
    }

    #[test]
    fn every_bundled_key_reads_as_the_rsa_crate_reads_it() {
        let mut keys: Vec<&str> = ALPINE
            .iter()
            .flat_map(|(_, keys)| keys.iter().map(|key| key.pem))
            .collect();
        keys.push(POSTMARKETOS.pem);
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 19, "eighteen Alpine keys and postmarketOS's");
        for pem in keys {
            let reference = rsa::RsaPublicKey::from_public_key_pem(pem).unwrap();
            let der = der(pem).unwrap();
            let (modulus, exponent) = components(&der).unwrap();
            assert_eq!(modulus, reference.n().to_bytes_be());
            assert_eq!(exponent, reference.e().to_bytes_be());
            rsa_public_key(pem).expect("irongall verifies with every bundled key");
        }
    }

    #[test]
    fn a_body_in_any_lines_with_either_line_ending_reads() {
        let der = der(POSTMARKETOS.pem).unwrap();
        let one_line = format!("{BEGIN}{}{END}", base64::encode(&der));
        let crlf = POSTMARKETOS.pem.replace('\n', "\r\n");
        let surrounded = format!("\n\n  {}  \n\n", POSTMARKETOS.pem);
        for pem in [one_line, crlf, surrounded] {
            assert_eq!(super::der(&pem).as_ref(), Ok(&der), "{pem:?}");
        }
    }

    #[test]
    fn a_key_irongall_verifies_with_reads_from_2048_to_8192_bits() {
        for bits in [2048, 4096, 8192] {
            let pem = pem_of(&spki(&modulus_of(bits), &[0x01, 0x00, 0x01]));
            rsa_public_key(&pem).unwrap_or_else(|err| panic!("{bits} bits: {err}"));
        }
    }

    #[test]
    fn what_is_not_an_rsa_spki_in_der_is_refused_with_its_reason() {
        let modulus = modulus_of(2048);
        let e = [0x01, 0x00, 0x01];
        let good = spki(&modulus, &e);
        // The control: the well-formed key every case below departs from.
        rsa_public_key(&pem_of(&good)).expect("the well-formed key reads");

        let mut trailing = good.clone();
        trailing.push(0);
        // The outer SEQUENCE's length written in long form, 0x81 and an
        // octet, though it fits the short form.
        let short = spki(&[0x03], &e);
        let mut long_form = vec![SEQUENCE, 0x81];
        long_form.extend_from_slice(&short[1..]);
        let unused_bits = {
            let key = tlv(
                SEQUENCE,
                &[tlv(INTEGER, &modulus), tlv(INTEGER, &e)].concat(),
            );
            tlv(
                SEQUENCE,
                &[
                    &RSA_ENCRYPTION[..],
                    &tlv(BIT_STRING, &[&[1][..], &key].concat()),
                ]
                .concat(),
            )
        };
        let unprefixed = spki(&modulus[1..], &e); // reads as negative
        let padded = spki(&[&[0][..], &modulus].concat(), &e); // a needless zero octet
        // RFC 8410's example Ed25519 key.
        let ed25519 = "-----BEGIN PUBLIC KEY-----\n\
                       MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
                       -----END PUBLIC KEY-----\n";
        let good_pem = pem_of(&good);
        let pkcs1 = good_pem.replace("PUBLIC KEY", "RSA PUBLIC KEY");

        for (pem, reason) in [
            (pkcs1, "labelled PUBLIC KEY"),
            (format!("a comment\n{good_pem}"), "labelled PUBLIC KEY"),
            (format!("{good_pem}a comment\n"), "labelled PUBLIC KEY"),
            (good_pem.replacen('M', "!", 1), "not base64"),
            (ed25519.to_string(), "not an RSA key"),
            (pem_of(&trailing), "not well-formed DER"),
            (pem_of(&long_form), "not well-formed DER"),
            (pem_of(&unused_bits), "not well-formed DER"),
            (pem_of(&unprefixed), "not well-formed DER"),
            (pem_of(&padded), "not well-formed DER"),
            (
                pem_of(&spki(&modulus_of(1024), &e)),
                "narrower than 2048 bits",
            ),
            (pem_of(&spki(&modulus_of(8200), &e)), "wider than 8192 bits"),
            (pem_of(&spki(&modulus, &[0x02])), "not an RSA public key"),
        ] {
            let err = rsa_public_key(&pem).expect_err(reason);
            assert!(err.contains(reason), "{reason}: {err}");
        }
    }
}
