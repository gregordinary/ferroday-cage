//! Digesting a byte stream on its way past.
//!
//! Every userland layer verifies what it fetched against a digest a signed
//! source recorded, and none of them may hold what they are verifying: a
//! package is a file that can run to hundreds of megabytes. So the digest is
//! taken as the bytes move — [`stream`] on a read, [`DigestWriter`] on a write
//! — and a 90 MB kernel package costs what a shell script costs, in whichever
//! direction it is travelling.
//!
//! Which digest is the archive's business rather than this module's, so
//! [`Algorithm`] names it and every entry point takes one.

use std::io::{self, Read, Write};

use sha2::{Digest, Sha256, Sha512};

// `md-5` is on `digest 0.10` and `sha2` is on `digest 0.11`, so the two
// `Digest` traits are distinct types and cannot be imported under one name. The
// MD5 hasher therefore names its trait through this alias at each call rather
// than through a bare `Digest` in scope.
#[cfg(feature = "gentoo")]
use md5::Digest as Md5Digest;

/// The chunk size the streaming reads work in.
#[cfg_attr(not(any(feature = "debian", feature = "gentoo")), allow(dead_code))]
const CHUNK: usize = 64 * 1024;

/// A digest algorithm an archive records its artifacts under.
///
/// The archives do not agree on one. Debian records SHA-256 throughout its
/// release chain and Alpine's apk index is defined over it; Gentoo's signed
/// digest documents carry SHA-512 and BLAKE2B, and never SHA-256. So the
/// algorithm is a parameter of the digester rather than a property of it, and
/// one archive's choice cannot quietly become another's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    /// SHA-256, written as 64 hex characters. What the Debian release chain and
    /// the apk index both record, and what Gentoo never publishes.
    #[cfg_attr(not(any(feature = "debian", feature = "alpine")), allow(dead_code))]
    Sha256,
    /// SHA-512, written as 128 hex characters. What Gentoo's signed digest
    /// documents record, SHA-256 not being on offer there at all.
    #[cfg_attr(not(feature = "gentoo"), allow(dead_code))]
    Sha512,
    /// MD5, written as 32 hex characters. Portage's bookkeeping checksum, and
    /// nothing this crate rests a trust decision on.
    ///
    /// It is here because portage's own package database is written in it: a
    /// merged package's `CONTENTS` records an MD5 per file so portage can tell
    /// whether a file has been edited since it was merged, and its `BINPKGMD5`
    /// records the binary package's own. Both are notes a package manager
    /// keeps about a root it owns.
    ///
    /// It is never compared to decide whether to trust bytes, and it must not
    /// be: MD5 has been unusable for that for twenty years. Every trust
    /// decision in this crate is SHA-256 or SHA-512, and a Gentoo binary
    /// package's bytes are held to the SHA-512 of the cleartext-signed
    /// `Manifest` inside it.
    ///
    /// The variant is gated rather than merely unused without the layer that
    /// writes it: naming an algorithm a build cannot compute would leave a
    /// hasher with a case it could only panic on.
    #[cfg(feature = "gentoo")]
    Md5,
}

impl Algorithm {
    /// The lowercase hex digest of `bytes`.
    ///
    /// For a value small enough to hold. What a Gentoo digest document is
    /// compared against is a half-gigabyte tarball, which goes through
    /// [`stream`] instead, so a build of that layer alone has no caller.
    #[cfg_attr(not(any(feature = "debian", feature = "alpine")), allow(dead_code))]
    pub(crate) fn hex_of(self, bytes: &[u8]) -> String {
        let mut hasher = Hasher::new(self);
        hasher.update(bytes);
        hasher.finish()
    }

    /// Whether `digest` has the shape this algorithm writes: exactly as many
    /// lowercase hex characters as its output is wide.
    ///
    /// This is the only form a repository-supplied digest is ever used in — a
    /// cache filename, a `by-hash` URL segment, and the value a fetch is
    /// verified against — so one carrying anything else is malformed, and
    /// refusing it keeps such a digest from reaching a filesystem path or a
    /// request line as, say, a traversal.
    ///
    /// The length is the algorithm's, so a SHA-256 where a SHA-512 belongs is
    /// refused at the boundary rather than compared and found unequal much
    /// later. The lowercase-only rule is flat across algorithms, and that is
    /// what makes every comparison in the crate a plain `==`: both sides passed
    /// through here or came out of [`hex`], so two spellings of one digest never
    /// meet. Folding at the comparison instead would leave the shape unchecked
    /// at the boundary, which is where the traversal question is asked.
    ///
    /// There are two boundaries, one per way a digest arrives, and a digest that
    /// reaches a comparison came through one of them: an index stanza, as it is
    /// parsed, and a plan document, as it is read and again when a plan is handed
    /// to a bootstrap. A digest a plan carries for provenance alone — the one
    /// naming the archive state a resolution happened against — is written back
    /// verbatim and never compared, so it is not held to this.
    pub(crate) fn is_hex(self, digest: &str) -> bool {
        digest.len() == self.hex_len()
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    /// How many hex characters the algorithm's output is written as.
    fn hex_len(self) -> usize {
        match self {
            Algorithm::Sha256 => 64,
            Algorithm::Sha512 => 128,
            #[cfg(feature = "gentoo")]
            Algorithm::Md5 => 32,
        }
    }
}

/// A digest in flight, over whichever algorithm was asked for.
///
/// `sha2` gives each algorithm its own type rather than one type carrying its
/// width, so the choice is an enum here rather than a boxed `dyn Digest`: the
/// two hashers differ in size but neither is large, and keeping them on the
/// stack costs an allocation less per digest than the trait object would.
enum Hasher {
    Sha256(Sha256),
    Sha512(Sha512),
    #[cfg(feature = "gentoo")]
    Md5(md5::Md5),
}

impl Hasher {
    /// A fresh hasher for `algorithm`.
    fn new(algorithm: Algorithm) -> Hasher {
        match algorithm {
            Algorithm::Sha256 => Hasher::Sha256(Sha256::new()),
            Algorithm::Sha512 => Hasher::Sha512(Sha512::new()),
            #[cfg(feature = "gentoo")]
            Algorithm::Md5 => Hasher::Md5(Md5Digest::new()),
        }
    }

    /// Feeds `bytes` to the digest.
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Hasher::Sha256(hasher) => hasher.update(bytes),
            Hasher::Sha512(hasher) => hasher.update(bytes),
            #[cfg(feature = "gentoo")]
            Hasher::Md5(hasher) => Md5Digest::update(hasher, bytes),
        }
    }

    /// Consumes the hasher and formats what it accumulated as lowercase hex.
    fn finish(self) -> String {
        match self {
            Hasher::Sha256(hasher) => hex(&hasher.finalize()),
            Hasher::Sha512(hasher) => hex(&hasher.finalize()),
            #[cfg(feature = "gentoo")]
            Hasher::Md5(hasher) => hex(&Md5Digest::finalize(hasher)),
        }
    }
}

/// The lowercase hex digest of everything `reader` yields, with the number of
/// bytes it yielded.
///
/// The digest is taken in fixed-size chunks, so it costs the same memory for a
/// kernel package as for a shell script. The size is counted from what was
/// actually read rather than taken from a stat, so it describes the same bytes
/// the digest does.
///
/// A layer whose downloads are digested at the sink as they arrive never reads
/// one back, so such a build has no caller.
#[cfg_attr(not(any(feature = "debian", feature = "gentoo")), allow(dead_code))]
pub(crate) fn stream(algorithm: Algorithm, reader: &mut impl Read) -> io::Result<(String, u64)> {
    let mut hasher = Hasher::new(algorithm);
    let mut chunk = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(got) => {
                hasher.update(&chunk[..got]);
                size += got as u64;
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok((hasher.finish(), size))
}

/// A writer that digests everything written through it on its way to `inner`.
///
/// The write-side counterpart of [`stream`]. A [`Fetch`](super::Fetch) writes a
/// resource to a sink as it arrives, so a download that digests at the sink
/// learns what it received without holding it: the bytes go to their file and to
/// the hasher in one pass, and the caller decides whether to publish the file
/// only after the digest is known.
///
/// A layer that keeps what it downloads in a cache verifies on the read instead,
/// so that a file the cache already held and one this run fetched go through the
/// same check; such a build has no caller for this.
#[cfg_attr(not(any(feature = "debian", feature = "alpine")), allow(dead_code))]
pub(crate) struct DigestWriter<W> {
    inner: W,
    hasher: Hasher,
    written: u64,
}

#[cfg_attr(not(any(feature = "debian", feature = "alpine")), allow(dead_code))]
impl<W: Write> DigestWriter<W> {
    /// Wraps `inner`, digesting what passes through under `algorithm`.
    pub(crate) fn new(algorithm: Algorithm, inner: W) -> DigestWriter<W> {
        DigestWriter {
            inner,
            hasher: Hasher::new(algorithm),
            written: 0,
        }
    }

    /// Flushes the wrapped writer and reports the lowercase hex digest of
    /// everything written through it, with the number of bytes that was.
    ///
    /// The count comes from what was actually written rather than from a stat,
    /// so it describes the same bytes the digest does.
    pub(crate) fn finish(mut self) -> io::Result<(String, u64)> {
        self.inner.flush()?;
        Ok((self.hasher.finish(), self.written))
    }
}

impl<W: Write> Write for DigestWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Only what the inner writer accepted is digested, so a short write
        // cannot put the digest and the file out of step.
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Formats a digest as lowercase hex.
pub(crate) fn hex(digest: &[u8]) -> String {
    let mut text = String::with_capacity(digest.len() * 2);
    for byte in digest {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn the_empty_input_digests_to_each_algorithms_known_value() {
        assert_eq!(
            Algorithm::Sha256.hex_of(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            Algorithm::Sha512.hex_of(b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn a_digest_shape_is_the_algorithms_own_length_in_lowercase_hex() {
        for algorithm in [Algorithm::Sha256, Algorithm::Sha512] {
            let digest = algorithm.hex_of(b"");
            assert!(algorithm.is_hex(&digest));
            assert!(!algorithm.is_hex(&digest[1..]), "too short");
            assert!(!algorithm.is_hex(&format!("{digest}a")), "too long");
            // Refused rather than folded, so that every comparison in the crate
            // can be a plain `==` between two values that both came through
            // here.
            assert!(
                !algorithm.is_hex(&digest.to_uppercase()),
                "uppercase is not accepted",
            );
            assert!(!algorithm.is_hex("../../../etc/foo"));
        }
        // The length is the algorithm's own, so a well-formed digest of the
        // other one is refused at the boundary rather than compared and found
        // unequal later.
        assert!(!Algorithm::Sha512.is_hex(&Algorithm::Sha256.hex_of(b"")));
        assert!(!Algorithm::Sha256.is_hex(&Algorithm::Sha512.hex_of(b"")));
    }

    #[test]
    fn a_streamed_digest_matches_the_buffered_one() {
        // The streaming digest spans several chunks, so the chunk boundaries
        // are exercised rather than assumed away by a small input.
        let bytes: Vec<u8> = (0..CHUNK * 3 + 17).map(|i| (i % 251) as u8).collect();
        for algorithm in [Algorithm::Sha256, Algorithm::Sha512] {
            let (digest, size) =
                stream(algorithm, &mut Cursor::new(&bytes)).expect("the stream is digested");
            assert_eq!(digest, algorithm.hex_of(&bytes));
            assert_eq!(size, bytes.len() as u64);

            // An empty stream is the empty digest, not a failure.
            let (digest, size) =
                stream(algorithm, &mut Cursor::new(Vec::new())).expect("empty digests");
            assert_eq!(digest, algorithm.hex_of(b""));
            assert_eq!(size, 0);
        }
    }

    #[test]
    fn a_digest_writer_reports_what_passed_through_it() {
        // The write side has to agree with the read side byte for byte, since
        // a download digests at the sink and is then verified against a source
        // that digested the same bytes on the way in.
        let bytes: Vec<u8> = (0..CHUNK + 3).map(|i| (i % 251) as u8).collect();
        for algorithm in [Algorithm::Sha256, Algorithm::Sha512] {
            let mut received = Vec::new();
            let mut writer = DigestWriter::new(algorithm, &mut received);
            writer
                .write_all(&bytes)
                .expect("the sink accepts the bytes");
            let (digest, written) = writer.finish().expect("the sink flushes");
            assert_eq!(digest, algorithm.hex_of(&bytes));
            assert_eq!(written, bytes.len() as u64);
            assert_eq!(received, bytes);
        }
    }
}
