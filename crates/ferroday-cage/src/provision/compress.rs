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
//! [`ZstdReader`] drives one decoder per frame.
//!
//! Two of the three formats let a hostile archive name its own memory cost, in
//! a header far smaller than the allocation it asks for. A zstd frame declares
//! the window the decoder buffers, and an xz block declares the dictionary the
//! decoder allocates and zeroes; both are bounded here, at
//! [`MAX_ZSTD_WINDOW`] and [`MAX_XZ_DICTIONARY`], and each decoder is told its
//! bound and checks it against the header before allocating anything. `ruzstd`
//! takes the cap as a constructor argument; `lzma-rust2` takes it on the
//! sans-I/O decoder alone, which is why [`XzReader`] drives that one rather
//! than the crate's own `Read` wrapper.

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

/// The largest LZMA2 dictionary this provisioner decodes, bounding the memory
/// one xz block costs before any of it is decompressed.
///
/// Every block of an xz stream declares the dictionary its LZMA2 filter wants,
/// in a single header byte that can ask for anything from 4 KiB to 4 GiB. The
/// decoder allocates it when it starts the block and zeroes the whole
/// allocation, so the cost is resident memory rather than an address-space
/// reservation. Unbounded, a 69-byte input whose one block declares 2 GiB takes
/// 2 GiB of it — and so does a valid multi-block archive whose *hundred and
/// seventy-third* block declares it, which then decodes successfully and reports
/// nothing, the cost having been paid on the way. Every block is therefore
/// bounded, not the first: the decoder is given [`MAX_XZ_MEMORY_KB`] and checks
/// each block header against it as it parses one.
///
/// 128 MiB is twice the largest dictionary observed in the archives this crate
/// reads. Measured 2026-08-22 over the Debian trixie amd64 pool — including its
/// twenty largest packages — a Gentoo stage3, and packages built at every
/// compression level: 8 MiB is what `xz -6` writes and what nearly everything
/// carries, and 64 MiB is what `xz -9` writes, which two packages in that
/// sample use. Sharing [`MAX_ZSTD_WINDOW`]'s value is deliberate; the two
/// constants bound the same kind of hazard and there is no reason for a reader
/// to hold two numbers.
const MAX_XZ_DICTIONARY: u64 = MAX_ZSTD_WINDOW;

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
    } else if head.starts_with(&XZ_MAGIC) {
        // Every block of every stream declares its own dictionary and every one
        // is allocated, so the decode runs under a memory budget the decoder
        // checks against each block header before it allocates. Multiple
        // concatenated xz streams are legal in one file and some producers emit
        // them; the reader decodes them as one.
        Box::new(XzReader::new(stream))
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

/// The six-byte signature every xz stream begins with.
const XZ_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];

/// The memory budget an xz decode runs under, in kibibytes.
///
/// `lzma-rust2` checks a *memory* figure against this -- the block's dictionary
/// rounded up, plus a constant for the decoder's own tables -- as it parses each
/// block header, before allocating anything. The budget is therefore the
/// dictionary cap plus slack for those tables: sized at the cap alone it would
/// refuse a dictionary of exactly [`MAX_XZ_DICTIONARY`], which the tables push
/// over.
///
/// One mebibyte of slack admits nothing a tighter figure would not. Dictionary
/// sizes step in halvings and doublings, so the next one up from 128 MiB is
/// 192 MiB, and the slack would have to be sixty-four times this to reach it.
/// Stating it as slack rather than as the decoder's exact constant also means
/// an upstream change to that constant moves nothing here.
const MAX_XZ_MEMORY_KB: u32 = (MAX_XZ_DICTIONARY / 1024) as u32 + 1024;

/// The bytes of compressed input handed to the decoder at a time.
const XZ_CHUNK: usize = 64 * 1024;

/// An xz decoder bounded by [`MAX_XZ_DICTIONARY`].
///
/// `lzma-rust2` offers the bound on its sans-I/O decoder and not on its
/// `Read` one, so this drives the sans-I/O decoder and is the `Read` half:
/// compressed bytes in from `source` a chunk at a time, decoded bytes out to
/// the caller's buffer, and the memory limit set once at construction. The
/// decoder checks it against each block header as it parses one, which is both
/// before the allocation and inside the parser that decides what to allocate --
/// the two properties a bound applied from outside could not have.
///
/// Concatenated streams are decoded as one, which several producers emit and
/// the format permits.
///
/// # What this does not decode
///
/// A block whose filter chain holds more than one filter before LZMA2. The xz
/// format allows up to four, and the sans-I/O decoder supports one; `xz` itself
/// writes at most one (a BCJ or a delta), and no archive this crate reads
/// carries two. Such a block is refused rather than mis-decoded, and the
/// refusal names the decoder's own reason.
struct XzReader<R> {
    source: R,
    stream: lzma_rust2::XzStream,
    /// The buffer compressed bytes are read into.
    input: Vec<u8>,
    /// How much of `input` holds bytes read from `source`.
    filled: usize,
    /// How much of that the decoder has taken.
    taken: usize,
    /// Set once `source` has reported end of input.
    drained: bool,
    /// Set once the decoder has reported the end of the last stream.
    finished: bool,
}

impl<R: Read> XzReader<R> {
    /// Wraps `source`, positioned at the start of the first stream header.
    fn new(source: R) -> XzReader<R> {
        XzReader {
            source,
            // `true`: several concatenated xz streams are one legal file.
            stream: lzma_rust2::XzStream::new_mem_limit(true, MAX_XZ_MEMORY_KB),
            input: vec![0; XZ_CHUNK],
            filled: 0,
            taken: 0,
            drained: false,
            finished: false,
        }
    }
}

impl<R: Read> Read for XzReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.finished {
            return Ok(0);
        }
        loop {
            // Both start at zero, so the first pass reads before it decodes.
            if self.taken == self.filled && !self.drained {
                self.filled = self.source.read(&mut self.input)?;
                self.taken = 0;
                self.drained = self.filled == 0;
            }
            let action = if self.drained {
                lzma_rust2::Action::Finish
            } else {
                lzma_rust2::Action::Run
            };
            let result = self
                .stream
                .process(&self.input[self.taken..self.filled], buf, action)
                .map_err(refused_memory)?;
            self.taken += result.bytes_consumed;
            if result.bytes_produced > 0 {
                return Ok(result.bytes_produced);
            }
            if result.status == lzma_rust2::Status::StreamEnd {
                self.finished = true;
                return Ok(0);
            }
            // Neither output nor an ending, so the decoder wants more input. If
            // the source has none left and the decoder took nothing either, no
            // further call can make progress: return rather than spin. Reached
            // only if the decoder stops short of both an ending and an error on
            // a truncated stream, which it is not documented to do -- but a loop
            // whose termination rests on a dependency's documentation is one
            // this crate would rather not have.
            if self.drained && result.bytes_consumed == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the xz stream ends mid-decode",
                ));
            }
        }
    }
}

/// Rewrites the decoder's memory refusal to name the bound in force.
///
/// `lzma-rust2` reports both a block over the budget and a host that would not
/// give it an allocation within the budget as [`io::ErrorKind::OutOfMemory`],
/// and its own words for the first -- "needed memory too big for mem_limit_kb"
/// -- name a parameter the caller never set and cannot see. The rewrite states
/// the cap as the bound in force rather than as the cause, which is true of
/// both, and keeps the decoder's reason after it for whoever needs to tell them
/// apart. Every other failure passes through as it arrives.
fn refused_memory(err: io::Error) -> io::Error {
    if err.kind() != io::ErrorKind::OutOfMemory {
        return err;
    }
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        format!(
            "an xz decode is capped at {} MiB of memory here and this stream's could not be \
             satisfied: {err}",
            MAX_XZ_DICTIONARY / (1024 * 1024),
        ),
    )
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
    fn a_fixture_declares_the_dictionary_it_names() {
        // The tests below name a dictionary in mebibytes and assert what the
        // decoder does about it, which is only meaningful if the byte written
        // into the header declares that dictionary and not a neighbouring one.
        // Each step of the encoding is half a doubling, so a byte one out
        // declares half or twice what was meant, and the refusal tests would
        // still pass while covering a different number.
        //
        // The format's own table: property `p` under 40 declares
        // `(2 | (p & 1)) << (p / 2 + 11)`, and 40 declares `0xFFFFFFFF`.
        for (bytes, property) in [
            (4 * 1024_u64, 0_u8),
            (8 * 1024 * 1024, 22),
            (64 * 1024 * 1024, 28),
            (128 * 1024 * 1024, 30),
            (2048 * 1024 * 1024, 38),
        ] {
            assert_eq!(dictionary_property(bytes), property, "{bytes} bytes");
        }
    }

    /// The LZMA2 dictionary property byte that declares `bytes`.
    ///
    /// Only the even properties, which are the powers of two: property `p`
    /// declares `2^(p / 2 + 12)`, so `p` is `(log2(bytes) - 12) * 2`. The odd
    /// ones are the halfway steps, which no fixture here needs.
    fn dictionary_property(bytes: u64) -> u8 {
        assert!(bytes.is_power_of_two(), "{bytes} is a power of two");
        (bytes.trailing_zeros() as u8 - 12) * 2
    }

    /// The LZMA2 filter's id in a block header's filter chain.
    const LZMA2_FILTER_ID: u64 = 0x21;

    /// A CRC32 over `bytes`, which every xz header carries one of.
    fn crc32(bytes: &[u8]) -> [u8; 4] {
        let mut crc = flate2::Crc::new();
        crc.update(bytes);
        crc.sum().to_le_bytes()
    }

    /// `value` as the format's variable-length integer.
    fn vli(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 0x80 {
            out.push((value as u8 & 0x7F) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    /// `data` as an LZMA2 stream of one uncompressed chunk.
    ///
    /// LZMA2 admits uncompressed chunks — control byte, a big-endian size less
    /// one, then the bytes — so a fixture needs no encoder to be a real stream
    /// a real decoder decodes. `0x01` resets the dictionary, which the first
    /// chunk must, and `0x00` ends the stream.
    fn lzma2_uncompressed(data: &[u8]) -> Vec<u8> {
        assert!(!data.is_empty() && data.len() <= 0x10000);
        let mut out = vec![0x01];
        out.extend_from_slice(&((data.len() - 1) as u16).to_be_bytes());
        out.extend_from_slice(data);
        out.push(0x00);
        out
    }

    /// One block of an xz fixture: what dictionary it declares, what it holds,
    /// and whether its header declares the compressed size the walk needs to
    /// step over it.
    struct Block<'a> {
        dictionary: u64,
        data: &'a [u8],
        declare_size: bool,
    }

    impl<'a> Block<'a> {
        /// A block declaring `dictionary` over `data`, with its compressed size
        /// stated as every threaded encoder states it.
        fn new(dictionary: u64, data: &'a [u8]) -> Block<'a> {
            Block {
                dictionary,
                data,
                declare_size: true,
            }
        }
    }

    /// An xz stream carrying `blocks`, checked the way `check` says.
    ///
    /// Built by hand rather than by an encoder because the point of every test
    /// below is a block the encoder would not write: a second block declaring a
    /// different dictionary from the first, or a header that declines to say
    /// how long its block is.
    ///
    /// The check is a parameter because it is what separates one block from the
    /// next, and a fixture written with only one of the format's check sizes
    /// could not catch a reader that placed the following header wrongly. The
    /// archives this crate reads use CRC32 and CRC64.
    fn xz_stream(check: Check, blocks: &[Block<'_>]) -> Vec<u8> {
        let flags = [0x00u8, check.id()];
        let mut out = XZ_MAGIC.to_vec();
        out.extend_from_slice(&flags);
        out.extend_from_slice(&crc32(&flags));

        let mut records: Vec<(u64, u64)> = Vec::new();
        for block in blocks {
            let payload = lzma2_uncompressed(block.data);
            // Flags: one filter, and the compressed size where it is declared.
            let mut body = vec![if block.declare_size { 0x40 } else { 0x00 }];
            if block.declare_size {
                body.extend_from_slice(&vli(payload.len() as u64));
            }
            body.extend_from_slice(&vli(LZMA2_FILTER_ID));
            body.extend_from_slice(&vli(1));
            body.push(dictionary_property(block.dictionary));
            // The header is a multiple of four including its size byte and
            // CRC32, and is zero-padded up to it.
            let size = (body.len() + 1 + 4).div_ceil(4) * 4;
            body.resize(size - 1 - 4, 0);
            let mut header = vec![(size / 4 - 1) as u8];
            header.extend_from_slice(&body);
            header.extend_from_slice(&crc32(&header));

            out.extend_from_slice(&header);
            out.extend_from_slice(&payload);
            // Block padding to a four-byte multiple of the compressed data,
            // and then the check over what the block decodes to.
            out.resize(out.len() + (4 - payload.len() % 4) % 4, 0);
            out.extend_from_slice(&check.over(block.data));
            // The index records the block unpadded: header, data, and check.
            records.push((
                (header.len() + payload.len()) as u64 + check.size(),
                block.data.len() as u64,
            ));
        }

        // The index: the indicator, the record count, two integers per record,
        // padding to a multiple of four, and a CRC32 over all of it.
        let mut index = vec![0x00];
        index.extend_from_slice(&vli(records.len() as u64));
        for (unpadded, uncompressed) in &records {
            index.extend_from_slice(&vli(*unpadded));
            index.extend_from_slice(&vli(*uncompressed));
        }
        index.resize(index.len() + (4 - index.len() % 4) % 4, 0);
        let index_size = index.len() + 4;
        index.extend_from_slice(&crc32(&index));
        out.extend_from_slice(&index);

        // The footer: a CRC32 over the backward size and the flags, then both,
        // then the closing signature.
        let mut footer = ((index_size / 4 - 1) as u32).to_le_bytes().to_vec();
        footer.extend_from_slice(&flags);
        out.extend_from_slice(&crc32(&footer));
        out.extend_from_slice(&footer);
        out.extend_from_slice(b"YZ");
        out
    }

    /// The check a fixture's blocks carry.
    #[derive(Clone, Copy)]
    enum Check {
        /// No check at all, which the format allows and which keeps a fixture
        /// about something else from also being about a checksum.
        None,
        /// What a Gentoo stage3 and most of the Debian pool carry.
        Crc32,
    }

    impl Check {
        /// The id the stream flags carry.
        fn id(self) -> u8 {
            match self {
                Check::None => 0x00,
                Check::Crc32 => 0x01,
            }
        }

        /// How many bytes follow each block, which is what places the next
        /// block header. The format sizes checks in threes: id 0 is none, 1 to
        /// 3 are four bytes, 4 to 6 are eight, and so on.
        fn size(self) -> u64 {
            match self.id() {
                0 => 0,
                id => 4 << ((u64::from(id) - 1) / 3),
            }
        }

        /// The check itself, over what the block decodes to.
        fn over(self, data: &[u8]) -> Vec<u8> {
            match self {
                Check::None => Vec::new(),
                Check::Crc32 => crc32(data).to_vec(),
            }
        }
    }

    const MIB: u64 = 1024 * 1024;

    /// The message an over-budget decode is refused with, or a panic naming
    /// what happened instead.
    ///
    /// Driven through [`decompress`], so what is asserted is the path a
    /// provisioning run takes rather than a component of it. A refused block is
    /// refused as its header is parsed, before anything it declared is
    /// allocated, so a fixture may name any dictionary it likes.
    fn refusal(bytes: &[u8]) -> String {
        match decode_all(bytes) {
            Err(err) if err.kind() == io::ErrorKind::OutOfMemory => err.to_string(),
            Err(err) => panic!("expected a memory refusal, got {err}"),
            Ok(decoded) => panic!("expected a memory refusal, decoded {} bytes", decoded.len()),
        }
    }

    #[test]
    fn a_fixture_stream_is_one_a_real_decoder_decodes() {
        // The fixtures are hand-built, so this is what keeps the tests below
        // honest: what `xz_stream` writes is a stream the decoder accepts, and a
        // bound that refused everything could not hide behind a bad fixture.
        let bytes = xz_stream(
            Check::Crc32,
            &[
                Block::new(4096, b"one\n"),
                Block::new(4096, b"two\n"),
                Block::new(4096, b"three\n"),
            ],
        );
        assert_eq!(
            decode_all(&bytes).expect("the fixture decodes"),
            b"one\ntwo\nthree\n"
        );
    }

    #[test]
    fn an_over_budget_dictionary_is_refused() {
        // The whole point, on the simplest shape: one block asking for more
        // than the budget, refused as its header is parsed.
        let bytes = xz_stream(Check::Crc32, &[Block::new(256 * MIB, b"payload")]);
        let err = refusal(&bytes);
        assert!(
            err.contains("128 MiB"),
            "the bound in force is named: {err}"
        );
        assert!(
            err.contains("mem_limit_kb"),
            "the decoder's own reason survives: {err}",
        );
    }

    #[test]
    fn a_later_blocks_dictionary_is_also_capped() {
        // Every block declares its own dictionary and every one is allocated,
        // so a file whose first block is ordinary and whose second asks for 2
        // GiB costs the 2 GiB -- and then decodes successfully, reporting
        // nothing. A check of the front of the file admits exactly this file.
        let bytes = xz_stream(
            Check::Crc32,
            &[
                Block::new(8 * MIB, b"an ordinary first block"),
                Block::new(2048 * MIB, b"and a hostile second one"),
            ],
        );
        refusal(&bytes);
    }

    #[test]
    fn the_last_of_many_blocks_is_still_checked() {
        // A real archive is not two blocks. A Gentoo stage3 is one stream of
        // seventy-five, each declaring 8 MiB, and every one of them is
        // allocated in turn -- so the bound has to still apply at the end of a
        // long stream, not only just after the front of it.
        let mut blocks: Vec<Block<'_>> =
            (0..75).map(|_| Block::new(8 * MIB, b"ordinary")).collect();
        decode_all(&xz_stream(Check::Crc32, &blocks)).expect("seventy-five decode clean");

        blocks.push(Block::new(512 * MIB, b"hostile"));
        refusal(&xz_stream(Check::Crc32, &blocks));
    }

    #[test]
    fn a_stream_carrying_no_check_is_bounded_too() {
        // Zero is one of the check sizes the format allows, and the check is
        // what separates one block from the next. A reader that sized it wrongly
        // would look for the second header in the wrong place.
        let bytes = xz_stream(
            Check::None,
            &[
                Block::new(8 * MIB, b"an ordinary first block"),
                Block::new(512 * MIB, b"and a hostile second one"),
            ],
        );
        refusal(&bytes);
    }

    #[test]
    fn a_dictionary_in_a_second_stream_is_also_capped() {
        // Concatenated streams are legal and the decoder is told to read them
        // all, so the bound has to survive an index and a footer.
        let mut bytes = xz_stream(Check::Crc32, &[Block::new(8 * MIB, b"an ordinary stream")]);
        bytes.extend_from_slice(&xz_stream(
            Check::Crc32,
            &[Block::new(512 * MIB, b"a hostile one")],
        ));
        refusal(&bytes);
    }

    #[test]
    fn stream_padding_between_streams_does_not_lose_the_bound() {
        // Four zero bytes may sit between two streams. Mistaking them for the
        // start of a header, or for the end of the file, would stop one stream
        // early and silently.
        let mut bytes = xz_stream(Check::Crc32, &[Block::new(8 * MIB, b"an ordinary stream")]);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(&xz_stream(
            Check::Crc32,
            &[Block::new(512 * MIB, b"a hostile one")],
        ));
        refusal(&bytes);
    }

    #[test]
    fn a_block_declaring_no_compressed_size_is_bounded_too() {
        // `xz -T1 --block-size=...` writes headers without a compressed size,
        // and the next header is then findable only by decoding this block to
        // its LZMA2 end marker. A bound applied by walking the container from
        // outside stops at such a header, having no way to find what follows;
        // the decoder is already inside and does not have to look. The legal
        // stream still decodes, and the hostile one is still refused.
        let ordinary = xz_stream(
            Check::Crc32,
            &[Block {
                dictionary: 8 * MIB,
                data: b"payload",
                declare_size: false,
            }],
        );
        assert_eq!(
            decode_all(&ordinary).expect("a legal stream decodes"),
            b"payload"
        );

        let hostile = xz_stream(
            Check::Crc32,
            &[
                Block {
                    dictionary: 8 * MIB,
                    data: b"payload",
                    declare_size: false,
                },
                Block {
                    dictionary: 512 * MIB,
                    data: b"hostile",
                    declare_size: false,
                },
            ],
        );
        refusal(&hostile);
    }

    #[test]
    fn a_dictionary_of_exactly_the_cap_is_admitted() {
        // The boundary is inclusive, which is what the budget's slack over
        // [`MAX_XZ_DICTIONARY`] buys: the decoder counts its own tables against
        // the budget as well as the dictionary, so a budget of the cap exactly
        // would refuse a block declaring the cap exactly. 64 MiB -- what `xz -9`
        // writes, and the largest observed in the archives this crate reads --
        // is well inside it.
        //
        // Decoding the second of these really does allocate 128 MiB for as long
        // as the block lasts. That is the cost of proving the boundary through
        // the decoder rather than against a comparison of this crate's own.
        for dictionary in [64 * MIB, MAX_XZ_DICTIONARY] {
            let bytes = xz_stream(Check::Crc32, &[Block::new(dictionary, b"payload")]);
            assert_eq!(
                decode_all(&bytes).expect("a dictionary at or under the cap is admitted"),
                b"payload",
                "dictionary {dictionary}",
            );
        }
    }

    #[test]
    fn a_truncated_stream_ends_rather_than_spinning() {
        // Every prefix of a real stream. Each is a decode that runs out of
        // input, and what matters is that each *returns*: a decoder still asking
        // for input a drained source cannot give would otherwise be called
        // forever. What each prefix answers is the decoder's to decide.
        let bytes = xz_stream(
            Check::Crc32,
            &[
                Block::new(8 * MIB, b"first block"),
                Block::new(8 * MIB, b"second block"),
            ],
        );
        for cut in 0..bytes.len() {
            if let Err(err) = decode_all(&bytes[..cut]) {
                assert_ne!(
                    err.kind(),
                    io::ErrorKind::OutOfMemory,
                    "cut at {cut}: a truncation is not a memory refusal",
                );
            }
        }
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
