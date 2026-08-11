//! Digesting a byte stream on its way past.
//!
//! Every userland layer verifies what it fetched against a digest a signed
//! source recorded, and none of them may hold what they are verifying: a
//! package is a file that can run to hundreds of megabytes. So the digest is
//! taken as the bytes move — [`sha256_stream`] on a read, [`DigestWriter`] on a
//! write — and a 90 MB kernel package costs what a shell script costs, in
//! whichever direction it is travelling.

use std::io::{self, Read, Write};

use sha2::{Digest, Sha256};

/// The chunk size the streaming reads work in.
const CHUNK: usize = 64 * 1024;

/// The lowercase hex SHA-256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The lowercase hex SHA-256 of everything `reader` yields, with the number of
/// bytes it yielded.
///
/// The digest is taken in fixed-size chunks, so it costs the same memory for a
/// kernel package as for a shell script. The size is counted from what was
/// actually read rather than taken from a stat, so it describes the same bytes
/// the digest does.
pub(crate) fn sha256_stream(reader: &mut impl Read) -> io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
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
    Ok((hex(&hasher.finalize()), size))
}

/// A writer that digests everything written through it on its way to `inner`.
///
/// The write-side counterpart of [`sha256_stream`]. A [`Fetch`](super::Fetch)
/// writes a resource to a sink as it arrives, so a download that digests at the
/// sink learns what it received without holding it: the bytes go to their file
/// and to the hasher in one pass, and the caller decides whether to publish the
/// file only after the digest is known.
pub(crate) struct DigestWriter<W> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> DigestWriter<W> {
    /// Wraps `inner`, digesting what passes through.
    pub(crate) fn new(inner: W) -> DigestWriter<W> {
        DigestWriter {
            inner,
            hasher: Sha256::new(),
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
        Ok((hex(&self.hasher.finalize()), self.written))
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
    fn sha256_of_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn a_streamed_digest_matches_the_buffered_one() {
        // The streaming digest spans several chunks, so the chunk boundaries
        // are exercised rather than assumed away by a small input.
        let bytes: Vec<u8> = (0..CHUNK * 3 + 17).map(|i| (i % 251) as u8).collect();
        let (digest, size) =
            sha256_stream(&mut Cursor::new(&bytes)).expect("the stream is digested");
        assert_eq!(digest, sha256_hex(&bytes));
        assert_eq!(size, bytes.len() as u64);

        // An empty stream is the empty digest, not a failure.
        let (digest, size) = sha256_stream(&mut Cursor::new(Vec::new())).expect("empty digests");
        assert_eq!(digest, sha256_hex(b""));
        assert_eq!(size, 0);
    }

    #[test]
    fn a_digest_writer_reports_what_passed_through_it() {
        // The write side has to agree with the read side byte for byte, since
        // a download digests at the sink and is then verified against a source
        // that digested the same bytes on the way in.
        let bytes: Vec<u8> = (0..CHUNK + 3).map(|i| (i % 251) as u8).collect();
        let mut received = Vec::new();
        let mut writer = DigestWriter::new(&mut received);
        writer
            .write_all(&bytes)
            .expect("the sink accepts the bytes");
        let (digest, written) = writer.finish().expect("the sink flushes");
        assert_eq!(digest, sha256_hex(&bytes));
        assert_eq!(written, bytes.len() as u64);
        assert_eq!(received, bytes);
    }
}
