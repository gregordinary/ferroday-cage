//! Compression sniffing for tar streams.
//!
//! A rootfs tarball and a `.deb`'s `data.tar` member are both a tar stream
//! optionally wrapped in gzip, xz, or zstd. The wrapper is identified from
//! the leading magic bytes, never a file name, and unwrapped through the
//! pure-Rust streaming decoders.
//!
//! Each wrapper's multi-member form is handled: concatenated gzip members (as
//! `pigz` and a plain `cat` of two `.gz` files produce), concatenated xz
//! streams, and multi-frame zstd (as `pzstd` emits, including a leading
//! skippable frame). `ruzstd`'s `StreamingDecoder` decodes a single frame, so
//! [`ZstdReader`] drives one decoder per frame, each bounded by
//! [`MAX_ZSTD_WINDOW`].

use std::io::{self, Read};

use ruzstd::decoding::{FrameDecoder, StreamingDecoder};

use super::ProvisionError;

/// The number of leading bytes read to sniff the compression format. The
/// longest magic is xz's six-byte signature.
const MAGIC_LEN: usize = 6;

/// The largest zstd window this provisioner decodes, bounding the memory the
/// streaming decoder retains for back-references.
///
/// A zstd frame declares its window size, and the decoder buffers up to that
/// many bytes before yielding output; its ring buffer allocates infallibly,
/// aborting the process on OOM. Without a bound a tiny hostile archive could
/// declare a multi-gigabyte window over a highly compressible payload and
/// exhaust memory. Every frame is decoded under this bound, which `ruzstd`
/// enforces from the frame header before allocating anything.
///
/// 128 MiB admits archives compressed with zstd's long-distance matching up to
/// a window log of 27 while keeping the bound fixed and modest. It is above
/// `ruzstd`'s own 100 MiB default, so it is set explicitly on every decoder.
const MAX_ZSTD_WINDOW: u64 = 128 * 1024 * 1024;

/// The most bytes of a zstd frame this provisioner buffers before deciding what
/// the frame is: the four-byte magic plus the largest possible frame header (a
/// descriptor byte, a window descriptor, a four-byte dictionary id, and an
/// eight-byte frame content size). Peeking a whole header keeps a short
/// skippable frame from needing a second pass to consume.
const ZSTD_HEADER_PEEK: usize = 4 + 14;

/// Reads up to [`MAGIC_LEN`] leading bytes for format sniffing.
///
/// Fewer bytes are returned only at end of stream; a real tar stream is at
/// least one 512-byte block, so a short read simply falls through to the
/// plain-tar path.
pub(crate) fn sniff_head<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut head = [0u8; MAGIC_LEN];
    let mut filled = 0;
    while filled < head.len() {
        let got = reader.read(&mut head[filled..])?;
        if got == 0 {
            break;
        }
        filled += got;
    }
    Ok(head[..filled].to_vec())
}

/// Wraps `rest` in the decoder selected by `head`, reconstructing the full
/// stream with `head` prepended.
///
/// `head` is the bytes [`sniff_head`] read from the front of the same
/// stream; `rest` is that stream with those bytes already consumed. gzip,
/// xz, and zstd are detected by magic; anything else is treated as a plain
/// tar stream and the caller's tar reader decides whether it truly is one.
pub(crate) fn decompress<'r, R: Read + 'r>(
    head: &[u8],
    rest: R,
) -> Result<Box<dyn Read + 'r>, ProvisionError> {
    let stream = io::Cursor::new(head.to_vec()).chain(rest);
    Ok(if head.starts_with(&[0x1f, 0x8b]) {
        // Several concatenated gzip members are one legal gzip file, and a
        // single-member decoder stops silently at the first member's end. A tar
        // reader tolerates a missing terminator at end of input, so a truncated
        // read there provisions an incomplete rootfs without an error.
        Box::new(flate2::read::MultiGzDecoder::new(stream))
    } else if head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        // Multiple concatenated xz streams are legal in one file and some
        // producers emit them.
        Box::new(lzma_rust2::XzReader::new(stream, true))
    } else if is_zstd_start(head) {
        // zstd is framed, and a producer such as `pzstd` emits several frames
        // (often behind a leading skippable frame). Decode every frame, each
        // under the window cap: an uncapped decoder would buffer a hostile
        // window into an OOM.
        Box::new(ZstdReader::new(Box::new(stream))?)
    } else {
        // Not a recognized compression: assume plain tar and let the header
        // check decide.
        Box::new(stream)
    })
}

/// Reads up to `limit` bytes from `reader` into `buf`, stopping early only at
/// end of stream. Used to buffer a zstd frame header before decoding.
fn read_up_to<R: Read>(reader: &mut R, buf: &mut Vec<u8>, limit: usize) -> io::Result<()> {
    let mut chunk = [0u8; ZSTD_HEADER_PEEK];
    while buf.len() < limit {
        let want = (limit - buf.len()).min(chunk.len());
        let got = reader.read(&mut chunk[..want])?;
        if got == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..got]);
    }
    Ok(())
}

/// The four-byte zstd frame magic, little-endian.
const ZSTD_FRAME_MAGIC: u32 = 0xFD2F_B528;

/// The inclusive range of skippable-frame magics (RFC 8878 section 3.1.2).
const SKIPPABLE_MAGIC: std::ops::RangeInclusive<u32> = 0x184D_2A50..=0x184D_2A5F;

/// Whether `head` begins a zstd stream: a data frame or a skippable frame.
fn is_zstd_start(head: &[u8]) -> bool {
    let Some(magic) = head
        .get(0..4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    else {
        return false;
    };
    magic == ZSTD_FRAME_MAGIC || SKIPPABLE_MAGIC.contains(&magic)
}

/// A single-frame decoder over a boxed reader: one frame of the stream. Boxing
/// the reader keeps its type from growing as [`ZstdReader`] re-wraps it frame
/// after frame.
type FrameReader<'r> = StreamingDecoder<Box<dyn Read + 'r>, FrameDecoder>;

/// A zstd reader that decodes every frame of a possibly multi-frame stream.
///
/// `ruzstd`'s [`StreamingDecoder`] decodes a single frame, so a `.tar.zst` from
/// a multi-frame producer such as `pzstd` would otherwise be truncated after
/// the first frame and rejected downstream as a malformed tar. This drives one
/// decoder per frame: when a frame ends it recovers the underlying reader and,
/// if another frame follows, decodes that one too, until the input is
/// exhausted. Every frame's decoder carries the same window cap, so a later
/// frame is bounded exactly as the first is. Skippable frames between or before
/// data frames are consumed and ignored.
struct ZstdReader<'r> {
    /// The decoder for the frame currently being read, or `None` once every
    /// frame has been decoded.
    decoder: Option<FrameReader<'r>>,
}

impl<'r> ZstdReader<'r> {
    /// Builds a reader positioned on the first frame. A stream with no frame at
    /// all, or a first frame whose window is over the cap, is an error.
    fn new(source: Box<dyn Read + 'r>) -> Result<ZstdReader<'r>, ProvisionError> {
        let decoder =
            start_frame(source)?.ok_or_else(|| archive_error("the zstd stream has no frame"))?;
        Ok(ZstdReader {
            decoder: Some(decoder),
        })
    }
}

impl Read for ZstdReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // A zero-length request is not end of stream, and the frame handover
        // below reads a zero-byte decoder read as one. In-crate callers always
        // pass a real buffer, but this reader is handed out as a
        // `Box<dyn Read>`, and the `Read` contract is the caller's to rely on.
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let Some(decoder) = self.decoder.as_mut() else {
                return Ok(0);
            };
            let read = decoder.read(buf)?;
            if read > 0 {
                return Ok(read);
            }
            // The frame is exhausted (its decoder yields zero only at its end).
            // Recover the reader and start the next frame, if any.
            let source = self
                .decoder
                .take()
                .expect("the decoder is present")
                .into_inner();
            self.decoder = start_frame(source).map_err(io::Error::other)?;
            if self.decoder.is_none() {
                return Ok(0);
            }
        }
    }
}

/// Peeks the next frame in `source` and builds a decoder for it, or `None` at a
/// clean end of input. A skippable frame is consumed and the search continues;
/// a data frame is refused if its header declares a window over
/// [`MAX_ZSTD_WINDOW`], before any of it is decoded.
fn start_frame<'r>(
    mut source: Box<dyn Read + 'r>,
) -> Result<Option<FrameReader<'r>>, ProvisionError> {
    loop {
        let mut header = Vec::with_capacity(ZSTD_HEADER_PEEK);
        read_up_to(&mut source, &mut header, ZSTD_HEADER_PEEK)
            .map_err(|err| archive_error(format!("reading zstd header: {err}")))?;
        if header.is_empty() {
            // The previous frame was the last: a clean end of the stream.
            return Ok(None);
        }
        let Some(magic) = header
            .get(0..4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        else {
            return Err(archive_error(
                "trailing bytes are too short to be a zstd frame",
            ));
        };
        if SKIPPABLE_MAGIC.contains(&magic) {
            source = skip_skippable(source, &header)?;
            continue;
        }
        if magic != ZSTD_FRAME_MAGIC {
            return Err(archive_error(
                "trailing bytes after the last zstd frame are not a frame",
            ));
        }
        // Reconstruct the frame with the peeked header prepended so nothing is
        // lost, then hand it to a single-frame decoder bounded by the window
        // cap. The decoder reads the header and refuses an over-large window
        // before it allocates its ring buffer.
        let framed: Box<dyn Read + 'r> = Box::new(io::Cursor::new(header).chain(source));
        let decoder = StreamingDecoder::new_with_max_window_size(framed, MAX_ZSTD_WINDOW)
            .map_err(|err| archive_error(format!("invalid zstd stream: {err}")))?;
        return Ok(Some(decoder));
    }
}

/// Consumes a skippable frame whose header (magic and, ideally, size) has been
/// peeked into `header`, returning the source positioned at the next frame.
///
/// A skippable frame is a four-byte magic, a four-byte little-endian content
/// size, and that many content bytes. Because the peek may have read past the
/// frame's end (small skippable frames) or stopped before it, the leftover
/// peeked bytes are pushed back ahead of the source.
fn skip_skippable<'r>(
    mut source: Box<dyn Read + 'r>,
    header: &[u8],
) -> Result<Box<dyn Read + 'r>, ProvisionError> {
    let size = read_le(header, 4, 4)
        .ok_or_else(|| archive_error("a skippable zstd frame has a truncated size"))?
        as usize;
    // Content begins after the eight-byte magic-and-size prefix.
    const PREFIX: usize = 8;
    let peeked_content = header.len().saturating_sub(PREFIX);
    if peeked_content >= size {
        // The whole frame — and possibly the start of the next — is in `header`.
        let leftover = header[PREFIX + size..].to_vec();
        Ok(Box::new(io::Cursor::new(leftover).chain(source)))
    } else {
        discard_exact(&mut source, size - peeked_content)
            .map_err(|err| archive_error(format!("skipping a skippable zstd frame: {err}")))?;
        Ok(source)
    }
}

/// Reads and discards exactly `count` bytes, failing on a short read: a
/// skippable frame that runs off the end of the stream is malformed.
fn discard_exact<R: Read>(reader: &mut R, mut count: usize) -> io::Result<()> {
    let mut scratch = [0u8; 4096];
    while count > 0 {
        let want = count.min(scratch.len());
        let got = reader.read(&mut scratch[..want])?;
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the frame ended before its declared size",
            ));
        }
        count -= got;
    }
    Ok(())
}

/// A tar/archive error at offset zero, for the compression layer's failures.
fn archive_error(reason: impl Into<String>) -> ProvisionError {
    ProvisionError::Archive {
        offset: 0,
        reason: reason.into(),
    }
}

/// Reads `size` little-endian bytes of `header` at `offset` as a `u64`, or
/// `None` if the slice is too short.
fn read_le(header: &[u8], offset: usize, size: usize) -> Option<u64> {
    let bytes = header.get(offset..offset + size)?;
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (8 * index);
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

    /// A tar stream of one file, plus the two terminator blocks. Used to prove
    /// that a multi-member wrapper delivers every member's bytes.
    fn tar_of(name: &str, contents: &[u8]) -> Vec<u8> {
        let mut block = [0u8; 512];
        block[..name.len()].copy_from_slice(name.as_bytes());
        for (field, value) in [
            (100..108, 0o644u64),
            (108..116, 0),
            (116..124, 0),
            (124..136, contents.len() as u64),
            (136..148, 0),
        ] {
            let width = field.len() - 1;
            let text = format!("{value:0width$o}");
            block[field.start..field.start + text.len()].copy_from_slice(text.as_bytes());
        }
        block[156] = b'0';
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        let sum: u64 = block
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*b)
                }
            })
            .sum();
        let text = format!("{sum:06o}");
        block[148..148 + text.len()].copy_from_slice(text.as_bytes());
        let mut out = block.to_vec();
        out.extend_from_slice(contents);
        out.resize(out.len() + (512 - contents.len() % 512) % 512, 0);
        out
    }

    #[test]
    fn concatenated_gzip_members_all_decode() {
        // Two gzip members in one file is one legal gzip stream — `pigz` emits
        // them, and so does `cat a.gz b.gz`. A single-member decoder stops
        // silently at the first, and the tar reader tolerates a missing
        // terminator at end of input, so the result would be a rootfs missing
        // everything past the first member with no error anywhere.
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write as _;

        let gzip = |bytes: &[u8]| {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(bytes).unwrap();
            encoder.finish().unwrap()
        };
        let first = tar_of("first", b"one\n");
        let second = tar_of("second", b"two\n");
        let mut stream = gzip(&first);
        stream.extend_from_slice(&gzip(&second));

        let head = sniff_head(&mut stream.as_slice()).expect("the head sniffs");
        let mut reader = decompress(&head, &stream[head.len()..]).expect("the wrapper is gzip");
        let mut decoded = Vec::new();
        reader
            .read_to_end(&mut decoded)
            .expect("the stream decodes");
        let mut expected = first.clone();
        expected.extend_from_slice(&second);
        assert_eq!(decoded, expected, "both members decoded");
    }

    #[test]
    fn concatenated_xz_streams_all_decode() {
        // The same shape for xz, which the module claims to handle and no test
        // pinned.
        let xz = |bytes: &[u8]| {
            let mut out = Vec::new();
            let mut writer = lzma_rust2::XzWriter::new(&mut out, lzma_rust2::XzOptions::default())
                .expect("an xz writer");
            std::io::Write::write_all(&mut writer, bytes).unwrap();
            writer.finish().expect("the xz stream finishes");
            out
        };
        let first = tar_of("first", b"one\n");
        let second = tar_of("second", b"two\n");
        let mut stream = xz(&first);
        stream.extend_from_slice(&xz(&second));

        let head = sniff_head(&mut stream.as_slice()).expect("the head sniffs");
        let mut reader = decompress(&head, &stream[head.len()..]).expect("the wrapper is xz");
        let mut decoded = Vec::new();
        reader
            .read_to_end(&mut decoded)
            .expect("the stream decodes");
        let mut expected = first.clone();
        expected.extend_from_slice(&second);
        assert_eq!(decoded, expected, "both streams decoded");
    }

    /// Compresses `data` into a single zstd frame.
    fn zstd_frame(data: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
    }

    /// Builds a skippable frame carrying `content`.
    fn skippable_frame(content: &[u8]) -> Vec<u8> {
        let mut frame = 0x184D_2A50u32.to_le_bytes().to_vec();
        frame.extend_from_slice(&(content.len() as u32).to_le_bytes());
        frame.extend_from_slice(content);
        frame
    }

    /// Sniffs and fully decodes `bytes` through [`decompress`].
    fn decode_all(bytes: &[u8]) -> Result<Vec<u8>, io::Error> {
        let head = sniff_head(&mut &bytes[..]).unwrap();
        let mut reader = decompress(&head, &bytes[head.len()..])
            .map_err(|err| io::Error::other(err.to_string()))?;
        let mut out = Vec::new();
        reader.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn multi_frame_zstd_decodes_every_frame() {
        // Two concatenated frames, as `pzstd` emits: both must be decoded, not
        // just the first.
        let mut stream = zstd_frame(b"first frame ");
        stream.extend_from_slice(&zstd_frame(b"second frame"));
        assert_eq!(decode_all(&stream).unwrap(), b"first frame second frame");
    }

    #[test]
    fn a_leading_skippable_frame_is_skipped() {
        // A skippable frame ahead of the data frame, the shape `pzstd` writes.
        let mut stream = skippable_frame(b"pzstd metadata here");
        stream.extend_from_slice(&zstd_frame(b"payload"));
        assert_eq!(decode_all(&stream).unwrap(), b"payload");
    }

    #[test]
    fn a_small_skippable_frame_does_not_consume_the_next_frame() {
        // A skippable frame shorter than the header peek: the pushback path must
        // return the over-read bytes so the following data frame still decodes.
        let mut stream = skippable_frame(b"xy");
        stream.extend_from_slice(&zstd_frame(b"payload"));
        assert_eq!(decode_all(&stream).unwrap(), b"payload");
    }

    /// Window descriptor 0x90: exponent 18, mantissa 0, so a window of 2^28 --
    /// twice [`MAX_ZSTD_WINDOW`], and well inside what the format allows, so it
    /// is this provisioner's cap that refuses it and not zstd's own ceiling.
    const OVER_CAP_WINDOW: u8 = 0x90;

    #[test]
    fn a_later_frames_window_is_also_capped() {
        // A valid first frame followed by a second frame whose header declares
        // a window over the cap: the per-frame cap must reject it, not only the
        // first frame's.
        let mut stream = zstd_frame(b"ok");
        stream.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x00, OVER_CAP_WINDOW]);
        let err = decode_all(&stream).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("window"), "{err}");
    }

    #[test]
    fn decompress_rejects_an_oversized_zstd_window() {
        // A frame declaring a window over the cap on an empty body: the decoder
        // refuses it from the header, before any of the frame is decoded.
        let bytes = [
            ZSTD_MAGIC[0],
            ZSTD_MAGIC[1],
            ZSTD_MAGIC[2],
            ZSTD_MAGIC[3],
            0x00,
            OVER_CAP_WINDOW,
        ];
        let head = sniff_head(&mut &bytes[..]).unwrap();
        match decompress(&head, &bytes[head.len()..]) {
            Err(ProvisionError::Archive { reason, .. }) => {
                assert!(reason.to_lowercase().contains("window"), "{reason}");
            }
            Err(other) => panic!("expected a window error, got {other:?}"),
            Ok(_) => panic!("an oversized window must be rejected"),
        }
    }

    #[test]
    fn decompress_admits_a_window_of_exactly_the_cap() {
        // Window descriptor 0x88: exponent 17, mantissa 0, so a window of
        // exactly 2^27 -- [`MAX_ZSTD_WINDOW`]. The decoder's own default bound
        // is lower than that, so this fails the moment the cap stops being set
        // explicitly, which is the regression the cap exists to prevent.
        assert_eq!(MAX_ZSTD_WINDOW, 1 << 27, "the descriptor encodes the cap");
        let bytes = [
            ZSTD_MAGIC[0],
            ZSTD_MAGIC[1],
            ZSTD_MAGIC[2],
            ZSTD_MAGIC[3],
            0x00,
            0x88,
        ];
        let head = sniff_head(&mut &bytes[..]).unwrap();
        decompress(&head, &bytes[head.len()..])
            .map(|_| ())
            .expect("a window at the cap is admitted");
    }
}
