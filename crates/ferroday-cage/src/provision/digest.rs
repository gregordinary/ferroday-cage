//! Digesting a byte stream on its way past.
//!
//! Every userland layer verifies what it fetched against a digest a signed
//! source recorded, and none of them may hold what they are verifying: a
//! package is a file that can run to hundreds of megabytes. So the digest is
//! taken as the bytes move, on a read or on a write, and a 90 MB kernel
//! package costs what a shell script costs, in whichever direction it is
//! travelling.
//!
//! Which digest is the archive's business rather than this module's, so
//! [`Algorithm`] names it and every entry point takes one. A digest a plan
//! records, or a refusal names, is a [`Digest`]: an algorithm and a value held
//! to its shape. A digest this module takes under an [`Algorithm`] is one too.

use std::io::{self, Read, Write};

use sha2::{Sha256, Sha512};

/// The chunk size the streaming reads work in.
#[cfg_attr(not(any(feature = "debian", feature = "gentoo")), allow(dead_code))]
const CHUNK: usize = 64 * 1024;

/// A digest algorithm an archive records its artifacts under.
///
/// The archives do not agree on one. Debian records SHA-256 throughout its
/// release chain, Ubuntu SHA-256 and SHA-512, and its development series
/// SHA-512 alone; Alpine's apk index is defined over SHA-256; Gentoo's signed
/// digest documents carry SHA-512 and BLAKE2B, and never SHA-256. So the
/// algorithm is a parameter of the digester rather than a property of it, and
/// one archive's choice cannot quietly become another's.
///
/// Every trust decision in this crate is one of these. Portage's MD5, which
/// its package database is written in and which decides nothing, is computed
/// apart from them, so it cannot be named where a trust decision is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// SHA-256, written as 64 hex characters.
    Sha256,
    /// SHA-512, written as 128 hex characters.
    Sha512,
}

impl Algorithm {
    /// The lowercase hex digest of `bytes`.
    ///
    /// For a value small enough to hold. What a Gentoo digest document is
    /// compared against is a half-gigabyte tarball, which goes through
    /// [`stream`] instead.
    pub(crate) fn hex_of(self, bytes: &[u8]) -> String {
        Hasher::new(self).over(bytes)
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
    /// parsed, and a plan document, as it is read, where every digest is made a
    /// [`Digest`], which cannot be made of anything else.
    pub(crate) fn is_hex(self, digest: &str) -> bool {
        is_lowercase_hex(digest, self.hex_len())
    }

    /// How many hex characters the algorithm's output is written as.
    fn hex_len(self) -> usize {
        match self {
            Algorithm::Sha256 => 64,
            Algorithm::Sha512 => 128,
        }
    }

    /// The algorithm's name as a message names it: `SHA-256`, `SHA-512`.
    #[cfg_attr(not(any(feature = "debian", feature = "gentoo")), allow(dead_code))]
    pub(crate) fn name(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "SHA-256",
            Algorithm::Sha512 => "SHA-512",
        }
    }
}

/// What a planned package must hash to, or what the release or the index a
/// plan records hashed to: an [`Algorithm`] and the digest under it, as
/// lowercase hex.
///
/// [`new`](Self::new) holds the value to its algorithm's shape, exactly as many
/// lowercase hex characters as the algorithm's output is wide, and it is the
/// only way to make one, so a value of this type is never malformed: a digest
/// spelled any other way is refused where it arrives rather than compared and
/// found unequal later, or carried into a cache file name or a URL.
///
/// It is what a Debian plan's package records (`PlannedPackage::digest`): the
/// SHA-256 its index offers, or the SHA-512 where it offers no SHA-256. It is
/// also what a Debian plan records for each release it resolved against
/// (`ResolvedArchive::release_sha256`), and an Alpine plan for each index
/// (`ResolvedIndex::sha256`), both SHA-256 of the bytes that were verified, and
/// what a Gentoo stage3 must hash to (`Stage3::sha512`).
///
/// A refusal names one the same way: both digests of a pin the archives no
/// longer hold (`debian::UnheldReason::Digest`), and what was recorded and what
/// the bytes hashed to where they differ (`DebianError::Digest`,
/// `GentooError::Digest`).
///
/// Two digests a plan carries are deliberately not this. An Alpine package's
/// `control_identity` is `Q1` and the base64 of a SHA-1 over the package's
/// control segment: another algorithm, another encoding, and a segment rather
/// than the file. A Gentoo package's `md5` is portage's bookkeeping digest of
/// the container, which decides nothing about whether to trust it. What names
/// a control identity is text for the same reason: `alpine::UnheldReason`'s
/// `Identity`, and `AlpineError::Digest`, which reports a control identity or,
/// through the same fields, the data segment's SHA-256 as the package's
/// `.PKGINFO` spells it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    /// Which algorithm the value is a digest under.
    algorithm: Algorithm,
    /// The digest, lowercase hex of the algorithm's width.
    hex: Box<str>,
}

impl Digest {
    /// The digest `hex` under `algorithm`, or `None` where `hex` is not
    /// lowercase hex of the algorithm's width: 64 characters for SHA-256, 128
    /// for SHA-512.
    ///
    /// # Example
    ///
    /// ```
    /// use ferroday_cage::provision::digest::{Algorithm, Digest};
    ///
    /// let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// let digest = Digest::new(Algorithm::Sha256, empty).expect("a SHA-256 in lowercase hex");
    /// assert_eq!(digest.algorithm(), Algorithm::Sha256);
    /// assert_eq!(digest.hex(), empty);
    /// assert_eq!(Digest::new(Algorithm::Sha512, empty), None);
    /// assert_eq!(Digest::new(Algorithm::Sha256, &empty.to_uppercase()), None);
    /// ```
    pub fn new(algorithm: Algorithm, hex: &str) -> Option<Digest> {
        algorithm.is_hex(hex).then(|| Digest {
            algorithm,
            hex: hex.into(),
        })
    }

    /// The digest of `bytes` under `algorithm`.
    pub(crate) fn of(algorithm: Algorithm, bytes: &[u8]) -> Digest {
        Digest::taken(algorithm, algorithm.hex_of(bytes))
    }

    /// The digest `hex` under `algorithm`, as one of this module's hashers
    /// wrote it.
    ///
    /// Not held to the shape [`new`](Self::new) holds a value to, since a
    /// hasher writes lowercase hex of its algorithm's width and nothing else.
    /// A value from anywhere else goes through `new`.
    fn taken(algorithm: Algorithm, hex: String) -> Digest {
        debug_assert!(algorithm.is_hex(&hex), "a hasher wrote {hex:?}");
        Digest {
            algorithm,
            hex: hex.into(),
        }
    }

    /// The algorithm the value is a digest under.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The digest, as lowercase hex of the algorithm's width.
    pub fn hex(&self) -> &str {
        &self.hex
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
    Md5(::md5::Md5),
}

impl Hasher {
    /// A fresh hasher for `algorithm`.
    fn new(algorithm: Algorithm) -> Hasher {
        use sha2::Digest as _;
        match algorithm {
            Algorithm::Sha256 => Hasher::Sha256(Sha256::new()),
            Algorithm::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }

    /// The lowercase hex digest of `bytes`, consuming the hasher.
    fn over(mut self, bytes: &[u8]) -> String {
        self.update(bytes);
        self.finish()
    }

    /// Feeds `bytes` to the digest.
    fn update(&mut self, bytes: &[u8]) {
        use sha2::Digest as _;
        match self {
            Hasher::Sha256(hasher) => hasher.update(bytes),
            Hasher::Sha512(hasher) => hasher.update(bytes),
            #[cfg(feature = "gentoo")]
            Hasher::Md5(hasher) => hasher.update(bytes),
        }
    }

    /// Consumes the hasher and formats what it accumulated as lowercase hex.
    fn finish(self) -> String {
        use sha2::Digest as _;
        match self {
            Hasher::Sha256(hasher) => hex(&hasher.finalize()),
            Hasher::Sha512(hasher) => hex(&hasher.finalize()),
            #[cfg(feature = "gentoo")]
            Hasher::Md5(hasher) => hex(&hasher.finalize()),
        }
    }
}

/// The digest of everything `reader` yields under `algorithm`, with the number
/// of bytes it yielded.
///
/// The digest is taken in fixed-size chunks, so it costs the same memory for a
/// kernel package as for a shell script. The size is counted from what was
/// actually read rather than taken from a stat, so it describes the same bytes
/// the digest does.
///
/// A layer whose downloads are digested at the sink as they arrive never reads
/// one back, so such a build has no caller.
#[cfg_attr(not(any(feature = "debian", feature = "gentoo")), allow(dead_code))]
pub(crate) fn stream(algorithm: Algorithm, reader: &mut impl Read) -> io::Result<(Digest, u64)> {
    let (mut taken, size) = stream_into(vec![Hasher::new(algorithm)], reader)?;
    let hex = taken
        .pop()
        .expect("one algorithm asked for, one digest taken");
    Ok((Digest::taken(algorithm, hex), size))
}

/// The digest of everything `reader` yields under each of `algorithms`, in
/// their order, with the number of bytes it yielded.
///
/// [`stream`] for a file held to more than one digest at once, as a Debian
/// package is to every digest its archive records: the bytes are read once
/// whatever the number of digests taken of them.
#[cfg(feature = "debian")]
pub(crate) fn stream_each(
    algorithms: &[Algorithm],
    reader: &mut impl Read,
) -> io::Result<(Vec<Digest>, u64)> {
    let hashers = algorithms
        .iter()
        .map(|algorithm| Hasher::new(*algorithm))
        .collect();
    let (taken, size) = stream_into(hashers, reader)?;
    let digests = algorithms
        .iter()
        .zip(taken)
        .map(|(algorithm, hex)| Digest::taken(*algorithm, hex))
        .collect();
    Ok((digests, size))
}

/// The one streaming loop every digest of a reader goes through: feeds each of
/// `hashers` everything `reader` yields, in fixed-size chunks, and reports what
/// each accumulated, in their order, with the number of bytes read.
#[cfg_attr(not(any(feature = "debian", feature = "gentoo")), allow(dead_code))]
fn stream_into(mut hashers: Vec<Hasher>, reader: &mut impl Read) -> io::Result<(Vec<String>, u64)> {
    let mut chunk = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(got) => {
                for hasher in &mut hashers {
                    hasher.update(&chunk[..got]);
                }
                size += got as u64;
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok((hashers.into_iter().map(Hasher::finish).collect(), size))
}

/// A writer that digests everything written through it on its way to `inner`.
///
/// The write-side counterpart of [`stream`], for bytes a copy is moving anyway:
/// a reader that hands one segment of a container to a sink learns the
/// segment's digest in the same pass, as the Alpine container reader does.
///
/// A download is not digested this way. What a download leaves in a cache is
/// checked by reading it back, through the check a cache hit goes through, so a
/// file this run fetched and one an earlier run left are held to one rule.
#[cfg_attr(not(feature = "alpine"), allow(dead_code))]
pub(crate) struct DigestWriter<W> {
    inner: W,
    algorithm: Algorithm,
    hasher: Hasher,
    written: u64,
}

#[cfg_attr(not(feature = "alpine"), allow(dead_code))]
impl<W: Write> DigestWriter<W> {
    /// Wraps `inner`, digesting what passes through under `algorithm`.
    pub(crate) fn new(algorithm: Algorithm, inner: W) -> DigestWriter<W> {
        DigestWriter {
            inner,
            algorithm,
            hasher: Hasher::new(algorithm),
            written: 0,
        }
    }

    /// Flushes the wrapped writer and reports the digest of everything written
    /// through it, with the number of bytes that was.
    ///
    /// The count comes from what was actually written rather than from a stat,
    /// so it describes the same bytes the digest does.
    pub(crate) fn finish(mut self) -> io::Result<(Digest, u64)> {
        self.inner.flush()?;
        Ok((
            Digest::taken(self.algorithm, self.hasher.finish()),
            self.written,
        ))
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

/// Portage's MD5, computed apart from [`Algorithm`].
///
/// Portage's own package database is written in it: a merged package's
/// `CONTENTS` records an MD5 per file so portage can tell whether a file has
/// been edited since it was merged, and its `BINPKGMD5` records the binary
/// package's own. Both are notes a package manager keeps about a root it owns,
/// and a binary-package index states one per container, which a download is
/// held to as portage holds it.
///
/// It is never what decides whether to trust bytes, and it must not be: MD5
/// has been unusable for that for twenty years. A Gentoo binary package's
/// bytes are trusted for the SHA-512 of the cleartext-signed `Manifest` inside
/// it. That is why MD5 is not an [`Algorithm`]: a value an archive's trust
/// rests on cannot be named in it.
#[cfg(feature = "gentoo")]
pub(crate) mod md5 {
    use std::io::{self, Read};

    use super::{Hasher, stream_into};

    /// The width of an MD5 written as lowercase hex.
    const HEX_LEN: usize = 32;

    /// The lowercase hex MD5 of `bytes`, for a test to state what a container
    /// or a file it builds hashes to.
    #[cfg(test)]
    pub(crate) fn hex_of(bytes: &[u8]) -> String {
        hasher().over(bytes)
    }

    /// The lowercase hex MD5 of everything `reader` yields, with the number of
    /// bytes it yielded, as [`stream`](super::stream) takes another digest.
    pub(crate) fn stream(reader: &mut impl Read) -> io::Result<(String, u64)> {
        let (mut digests, size) = stream_into(vec![hasher()], reader)?;
        Ok((digests.pop().expect("one digest taken"), size))
    }

    /// Whether `digest` is an MD5 as lowercase hex, held to the rule
    /// [`Algorithm::is_hex`](super::Algorithm::is_hex) holds every other digest
    /// to.
    pub(crate) fn is_hex(digest: &str) -> bool {
        super::is_lowercase_hex(digest, HEX_LEN)
    }

    /// A fresh MD5 hasher.
    fn hasher() -> Hasher {
        use ::md5::Digest as _;
        Hasher::Md5(::md5::Md5::new())
    }
}

/// Whether `digest` is exactly `len` lowercase hex characters: the shape every
/// digest this crate compares is held to, whatever its algorithm.
fn is_lowercase_hex(digest: &str, len: usize) -> bool {
    digest.len() == len
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        #[cfg(feature = "gentoo")]
        assert_eq!(md5::hex_of(b""), "d41d8cd98f00b204e9800998ecf8427e");
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
            assert_eq!(digest, Digest::of(algorithm, &bytes));
            assert_eq!(size, bytes.len() as u64);

            // An empty stream is the empty digest, not a failure.
            let (digest, size) =
                stream(algorithm, &mut Cursor::new(Vec::new())).expect("empty digests");
            assert_eq!(digest, Digest::of(algorithm, b""));
            assert_eq!(size, 0);
        }
    }

    #[test]
    fn a_digest_writer_reports_what_passed_through_it() {
        // The write side has to agree with the read side byte for byte, since
        // a segment digested as a copy moves it is compared against a digest
        // its source took of the same bytes.
        let bytes: Vec<u8> = (0..CHUNK + 3).map(|i| (i % 251) as u8).collect();
        for algorithm in [Algorithm::Sha256, Algorithm::Sha512] {
            let mut received = Vec::new();
            let mut writer = DigestWriter::new(algorithm, &mut received);
            writer
                .write_all(&bytes)
                .expect("the sink accepts the bytes");
            let (digest, written) = writer.finish().expect("the sink flushes");
            assert_eq!(digest, Digest::of(algorithm, &bytes));
            assert_eq!(written, bytes.len() as u64);
            assert_eq!(received, bytes);
        }
    }
}
