//! Hex encoding for fixture digests.

use sha2::{Digest, Sha256};

/// The lowercase hex SHA-256 of `bytes`.
///
/// The library has the same pair internally and keeps it private, so a fixture
/// that has to state a digest the provisioner will check needs its own. One,
/// here, rather than one per test suite.
pub fn sha256_hex(bytes: &[u8]) -> String {
    encode(&Sha256::digest(bytes))
}

/// Lowercase hex for arbitrary bytes.
pub fn encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
