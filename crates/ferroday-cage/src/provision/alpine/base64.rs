//! Base64 as RFC 4648 section 4 defines it: the standard alphabet, padded.
//!
//! The Alpine layer spells a package's identity in it and reads a signing
//! key's PEM in it. Written here rather than taken from a crate because it is
//! fifty lines and this layer is the workspace's only user: irongall decodes
//! the OpenPGP side's armor itself, and every other digest the crate renders is
//! hexadecimal.

/// The alphabet, in the order of the six-bit values it spells.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `bytes` in base64, padded.
pub(super) fn encode(bytes: &[u8]) -> String {
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

/// The bytes `text` spells, or `None` for text that is not padded base64: a
/// character outside the alphabet, a length that is not a multiple of four, a
/// pad character anywhere but the end, or a pad character standing for bits
/// that are not zero.
///
/// The last refusal keeps one value to one spelling, as an encoder writes it
/// (RFC 4648 section 3.5). The text is taken whole, so a caller strips what
/// surrounds it, such as a PEM body's line breaks, first.
pub(super) fn decode(text: &str) -> Option<Vec<u8>> {
    let (groups, rest) = text.as_bytes().as_chunks::<4>();
    if !rest.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(groups.len() * 3);
    for (at, group) in groups.iter().enumerate() {
        let pads = group.iter().rev().take_while(|&&c| c == b'=').count();
        if pads > 2 || (pads > 0 && at + 1 != groups.len()) {
            return None;
        }
        let mut packed = 0u32;
        for &character in &group[..4 - pads] {
            let value = ALPHABET.iter().position(|&a| a == character)?;
            packed = (packed << 6) | value as u32;
        }
        let [_, bytes @ ..] = (packed << (6 * pads)).to_be_bytes();
        let (kept, padded) = bytes.split_at(3 - pads);
        if padded.iter().any(|&byte| byte != 0) {
            return None;
        }
        out.extend_from_slice(kept);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors_encode_and_decode() {
        // RFC 4648 section 10.
        for (bytes, text) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(bytes.as_bytes()), text);
            assert_eq!(decode(text).as_deref(), Some(bytes.as_bytes()), "{text}");
        }
    }

    #[test]
    fn every_byte_round_trips_through_the_alphabet_in_order() {
        let bytes: Vec<u8> = (0..=255).collect();
        // The encoding's start, so a table transposed in both directions,
        // which a round trip alone would pass, is caught.
        assert!(encode(&bytes).starts_with("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"));
        assert_eq!(decode(&encode(&bytes)), Some(bytes));
    }

    #[test]
    fn text_that_is_not_padded_base64_is_refused() {
        for text in [
            "Zg",        // unpadded
            "Zm9",       // a partial group
            "Zg==Zm9v",  // padding before the end
            "Z===",      // three pad characters
            "====",      // a group of nothing but padding
            "Zm9v Zg==", // a space
            "Zm9v\nZg==",
            "Zm-v", // the URL-safe alphabet
            "Zh==", // pad bits that are not zero: also "f"
            "Zm9=", // the same: also "fo"
        ] {
            assert_eq!(decode(text), None, "{text:?}");
        }
    }
}
