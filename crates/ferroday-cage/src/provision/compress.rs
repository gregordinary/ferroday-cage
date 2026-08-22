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
//! [`MAX_ZSTD_WINDOW`] and [`MAX_XZ_DICTIONARY`], and both are checked from the
//! header before anything is allocated. The bounds are enforced differently
//! because the decoders differ: `ruzstd` takes the cap as a constructor
//! argument, while `lzma-rust2` offers none, so [`XzDictionaryGuard`] walks the
//! xz container ahead of the decoder to apply it.

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
/// reservation. `lzma-rust2` reserves it fallibly, which means a host that
/// refuses the allocation gets a clean error rather than an abort — but a host
/// with the memory free simply hands it over. Measured: a 69-byte input whose
/// one block declares 2 GiB takes 2 GiB of resident memory, and a valid
/// multi-block file whose *second* block declares it decodes successfully,
/// reporting nothing, having taken the same 2 GiB on the way.
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
        // Multiple concatenated xz streams are legal in one file and some
        // producers emit them. Every block of every stream declares its own
        // dictionary and every one is allocated, so the guard walks the
        // container ahead of the decoder and refuses one over the cap before
        // the decoder reads the header that would allocate it.
        Box::new(lzma_rust2::XzReader::new(
            XzDictionaryGuard::new(stream),
            true,
        ))
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

/// An xz stream header: the magic, two stream flags, and a CRC32 over them.
const XZ_STREAM_HEADER: usize = 12;

/// An xz stream footer: a CRC32, the index's backward size, the stream flags
/// again, and the two-byte `YZ` signature.
const XZ_STREAM_FOOTER: u64 = 12;

/// The LZMA2 filter's id in a block header's filter chain.
const LZMA2_FILTER_ID: u64 = 0x21;

/// The dictionary size an LZMA2 property byte declares.
///
/// The encoding is one byte: `40` means `0xFFFFFFFF`, and every smaller value
/// means `(2 | (byte & 1)) << (byte / 2 + 11)` — so `0` is 4 KiB, `22` is 8 MiB,
/// `30` is 64 MiB, and `39` is 3 GiB. Values above `40` are not dictionary
/// sizes at all, and the caller refuses them before asking.
fn lzma2_dictionary(property: u8) -> u64 {
    if property == 40 {
        u64::from(u32::MAX)
    } else {
        u64::from(2 | (property & 1)) << (property / 2 + 11)
    }
}

/// The size of the check that follows every block, from the stream flags.
///
/// The format assigns sizes in threes: id 0 is no check, 1 to 3 are four bytes
/// (CRC32 and two reserved), 4 to 6 are eight (CRC64 and two reserved), and so
/// on to 64. The reserved ids are sized here as well as the defined ones,
/// because the walk needs to know where the next block header starts even for a
/// stream the decoder will go on to reject.
fn xz_check_size(flags: u8) -> u64 {
    match flags & 0x0F {
        0 => 0,
        id => 4 << ((id - 1) / 3),
    }
}

/// Reads one variable-length integer from `bytes` at `at`, advancing it.
///
/// The format's integers are little-endian seven bits at a time, the high bit
/// marking that another byte follows, and at most nine bytes long. `None` for
/// an integer that is truncated or runs past that.
fn read_vli(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..9).map(|index| index * 7) {
        let byte = *bytes.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// What one xz block header declares that the walk needs.
struct XzBlock {
    /// The dictionary its LZMA2 filter asks the decoder to allocate.
    dictionary: u64,
    /// The compressed size it declares, where it declares one. Without it the
    /// walk cannot find the next block header: the decoder locates that by
    /// decoding to the LZMA2 end marker, which is not something to reproduce
    /// here.
    compressed: Option<u64>,
}

/// Reads what the walk needs out of a complete block header — the size byte,
/// the flags, the optional sizes, the filter chain, the padding and the CRC32.
///
/// `None` for anything this walk cannot follow: a reserved flag bit, a
/// malformed integer, a chain with no LZMA2 filter, a dictionary property that
/// is not one. The caller reads `None` as "stop checking", never as "refuse" —
/// the decoder is the authority on whether a stream is valid, and a guard that
/// refused what the decoder would have accepted would break real archives to
/// bound a hypothetical one.
fn parse_xz_block(header: &[u8]) -> Option<XzBlock> {
    // Everything between the size byte and the trailing CRC32.
    let body = header.get(1..header.len().checked_sub(4)?)?;
    let flags = *body.first()?;
    if flags & 0x3C != 0 {
        return None; // A reserved bit is set; the layout is not this one.
    }
    let filters = usize::from(flags & 0x03) + 1;
    let mut at = 1;
    let compressed = if flags & 0x40 != 0 {
        Some(read_vli(body, &mut at)?)
    } else {
        None
    };
    if flags & 0x80 != 0 {
        // The uncompressed size, which the walk does not need but must step over.
        read_vli(body, &mut at)?;
    }
    // A chain of up to four filters, of which the last must be LZMA2 — so a BCJ
    // or Delta filter can precede the one that declares the dictionary.
    let mut dictionary = None;
    for _ in 0..filters {
        let id = read_vli(body, &mut at)?;
        let properties = usize::try_from(read_vli(body, &mut at)?).ok()?;
        let declared = body.get(at..at.checked_add(properties)?)?;
        at += properties;
        if id == LZMA2_FILTER_ID {
            match declared {
                [property] if *property <= 40 => dictionary = Some(lzma2_dictionary(*property)),
                _ => return None,
            }
        }
    }
    Some(XzBlock {
        dictionary: dictionary?,
        compressed,
    })
}

/// Where in the xz container [`XzDictionaryGuard`] is.
enum XzStage {
    /// Before a stream's header, at the start of the file.
    StreamHeader,
    /// Before the byte that says whether a block header or the index follows.
    BlockBoundary,
    /// Inside the index, before the integer giving its record count.
    IndexCount,
    /// Inside the index's records, with this many variable-length integers left
    /// to step over: two per record.
    IndexIntegers(u64),
    /// After a stream's footer, where zero padding, another stream, or the end
    /// of the file may follow.
    StreamBoundary,
    /// Not tracking any more. Whatever the source yields is forwarded as it is,
    /// and no further block is checked.
    PassThrough,
}

/// A reader that refuses an xz stream declaring a dictionary over
/// [`MAX_XZ_DICTIONARY`], before the decoder reads the header that would
/// allocate it.
///
/// It sits between the source and `lzma_rust2::XzReader` and yields exactly the
/// bytes it was given. What it adds is a walk of the container structure — the
/// stream header, each block header, the index, the footer — carried out as the
/// bytes go past rather than over the whole file first, so a 500 MB stage3
/// arriving from a mirror still streams and the guard's own memory stays at one
/// block header, at most 1024 bytes.
///
/// # What it covers
///
/// Every block header the walk can reach, in every stream. That is every block
/// of every archive this crate has been measured against, the 75-block Gentoo
/// stage3 included. Checking only the first block would not be worth having:
/// each block declares its own dictionary and each is allocated, so a file
/// whose first block declares 8 MiB and whose second declares 2 GiB costs the
/// 2 GiB and then decodes successfully, reporting nothing.
///
/// The walk stops, and everything after it goes unchecked, at a block header
/// that declares no compressed size. Such a header leaves the next one findable
/// only by decoding this block to its LZMA2 end marker, which is the decoder's
/// job and not worth reproducing. `xz -T1 --block-size=...` writes exactly that
/// shape, so this is a real limit and not a theoretical one; single-block
/// producers that omit the size, `xz` reading a pipe among them, are fully
/// covered because there is nothing after the block that was checked.
///
/// This bounds an archive that is hostile by accident and one that is hostile
/// without trying hard. It is not a guarantee against an attacker who knows it
/// is here, who need only omit a compressed size to stop the walk. The sound
/// fix is a memory limit inside the decoder, where the allocation is;
/// `lzma-rust2` 0.18 offers none, and `XzReader::new` is its only constructor.
///
/// # What it refuses
///
/// Only an LZMA2 filter declaring more than the cap. Anything the walk cannot
/// make sense of — a reserved flag, an unfamiliar filter chain, a short read —
/// stops the tracking rather than failing the archive. The decoder decides what
/// is valid; a guard that refused what the decoder would have accepted would
/// break real archives in order to bound a hypothetical one.
///
/// # It is a second xz parser, and the two are not held to each other
///
/// A reader meeting this module cold finds two parsers of the same container in
/// one process: `lzma-rust2`'s, which decodes, and this one, which polices.
/// Nothing holds them to reading a container the same way, and nothing could
/// without reimplementing the decoder — so where they disagree, the disagreement
/// is a hole in the bound rather than a decode error, which is the fail-open
/// posture the section above describes from the other side.
///
/// That is the cost of the arrangement, and it is worth paying only for as long
/// as the decoder offers no bound of its own. The durable fix is upstream: a
/// maximum dictionary size on `lzma-rust2`'s decoder, applied where the
/// allocation happens, after which everything here but [`MAX_XZ_DICTIONARY`]
/// deletes.
struct XzDictionaryGuard<R> {
    source: R,
    stage: XzStage,
    /// Bytes read to inspect and not yet handed downstream.
    pending: Vec<u8>,
    /// How much of `pending` has been handed downstream already.
    handed: usize,
    /// Bytes still to forward without inspecting: a block's compressed data,
    /// its padding and its check, or a footer.
    forward: u64,
    /// The size of this stream's check, needed to find the next block header.
    check: u64,
    /// How many bytes of the current index have gone past, for its padding.
    index_bytes: u64,
}

impl<R: Read> XzDictionaryGuard<R> {
    /// Wraps `source`, positioned at the start of the first stream header.
    fn new(source: R) -> XzDictionaryGuard<R> {
        XzDictionaryGuard {
            source,
            stage: XzStage::StreamHeader,
            pending: Vec::new(),
            handed: 0,
            forward: 0,
            check: 0,
            index_bytes: 0,
        }
    }

    /// Reads `want` bytes onto the end of `pending`, returning how many
    /// arrived. Fewer than asked for only at end of input.
    fn buffer(&mut self, want: usize) -> io::Result<usize> {
        let from = self.pending.len();
        self.pending.resize(from + want, 0);
        let mut filled = 0;
        while filled < want {
            let got = self.source.read(&mut self.pending[from + filled..])?;
            if got == 0 {
                break;
            }
            filled += got;
        }
        self.pending.truncate(from + filled);
        Ok(filled)
    }

    /// Reads and inspects one structural element, leaving its bytes in
    /// `pending` for the caller to hand downstream and setting what comes next.
    fn inspect(&mut self) -> io::Result<()> {
        match self.stage {
            XzStage::StreamHeader | XzStage::StreamBoundary => self.inspect_stream_start(),
            XzStage::BlockBoundary => self.inspect_block(),
            XzStage::IndexCount => self.inspect_index_count(),
            XzStage::IndexIntegers(remaining) => self.inspect_index(remaining),
            XzStage::PassThrough => Ok(()),
        }
    }

    /// Reads a stream header, or decides there is not one here.
    ///
    /// At [`XzStage::StreamBoundary`] the four bytes may be stream padding —
    /// zeroes in multiples of four — rather than the start of a header, so they
    /// are read first and only then told apart. The end of the file is the
    /// ordinary way for this to finish.
    fn inspect_stream_start(&mut self) -> io::Result<()> {
        let at_boundary = matches!(self.stage, XzStage::StreamBoundary);
        if at_boundary {
            if self.buffer(4)? < 4 {
                // The file ends here, cleanly or short; either way there is no
                // further header to read.
                self.stage = XzStage::PassThrough;
                return Ok(());
            }
            let group = &self.pending[self.pending.len() - 4..];
            if group.iter().all(|byte| *byte == 0) {
                return Ok(()); // Stream padding; stay at the boundary.
            }
            if group != &XZ_MAGIC[..4] {
                self.stage = XzStage::PassThrough;
                return Ok(());
            }
        }
        let want = if at_boundary {
            XZ_STREAM_HEADER - 4
        } else {
            XZ_STREAM_HEADER
        };
        if self.buffer(want)? < want {
            self.stage = XzStage::PassThrough;
            return Ok(());
        }
        let header = &self.pending[self.pending.len() - XZ_STREAM_HEADER..];
        // The second flag byte carries the check id; the first is reserved and
        // must be zero, and a stream where it is not is one the decoder refuses
        // anyway.
        if header[..6] != XZ_MAGIC || header[6] != 0 {
            self.stage = XzStage::PassThrough;
            return Ok(());
        }
        self.check = xz_check_size(header[7]);
        self.stage = XzStage::BlockBoundary;
        Ok(())
    }

    /// Reads either the next block header or the index indicator that ends the
    /// stream's blocks.
    fn inspect_block(&mut self) -> io::Result<()> {
        if self.buffer(1)? < 1 {
            self.stage = XzStage::PassThrough;
            return Ok(());
        }
        let size_byte = self.pending[self.pending.len() - 1];
        if size_byte == 0 {
            // The index indicator, not a block header. One integer for the
            // record count follows, and then two per record.
            self.index_bytes = 1;
            self.stage = XzStage::IndexCount;
            return Ok(());
        }
        let header_size = (usize::from(size_byte) + 1) * 4;
        if self.buffer(header_size - 1)? < header_size - 1 {
            self.stage = XzStage::PassThrough;
            return Ok(());
        }
        let header = &self.pending[self.pending.len() - header_size..];
        let Some(block) = parse_xz_block(header) else {
            // Not a shape this walk follows. The decoder decides whether it is
            // valid; the guard stops checking rather than refusing.
            self.stage = XzStage::PassThrough;
            return Ok(());
        };
        if block.dictionary > MAX_XZ_DICTIONARY {
            return Err(io::Error::other(archive_error(format!(
                "the xz stream declares a {} MiB LZMA2 dictionary, over the {} MiB this \
                 provisioner decodes; the decoder would allocate and zero all of it before \
                 reading any of the block",
                block.dictionary / (1024 * 1024),
                MAX_XZ_DICTIONARY / (1024 * 1024),
            ))));
        }
        match block.compressed {
            // Compressed data, then padding to a four-byte multiple of it, then
            // the check: past all three is the next block header.
            Some(compressed) => {
                self.forward = compressed + (4 - compressed % 4) % 4 + self.check;
                self.stage = XzStage::BlockBoundary;
            }
            // Without a declared size the next header is findable only by
            // decoding this block, so tracking ends here.
            None => self.stage = XzStage::PassThrough,
        }
        Ok(())
    }

    /// Steps over the index's record count, which says how many integers
    /// follow it: two per record.
    fn inspect_index_count(&mut self) -> io::Result<()> {
        let Some(length) = self.step_over_index_integer()? else {
            return Ok(());
        };
        // A count large enough to overflow the doubling is not a count.
        let count = decode_vli(&self.pending[self.pending.len() - length..]);
        self.stage = match count.and_then(|count| count.checked_mul(2)) {
            Some(integers) => XzStage::IndexIntegers(integers),
            None => XzStage::PassThrough,
        };
        Ok(())
    }

    /// Steps over one of the index's record integers, and over the index's
    /// padding, CRC32 and stream footer once they are all gone.
    fn inspect_index(&mut self, remaining: u64) -> io::Result<()> {
        if remaining == 0 {
            // Padding to a four-byte multiple, the index's own CRC32, and the
            // stream footer; past all three is where another stream may begin.
            self.forward = (4 - self.index_bytes % 4) % 4 + 4 + XZ_STREAM_FOOTER;
            self.stage = XzStage::StreamBoundary;
            return Ok(());
        }
        if self.step_over_index_integer()?.is_some() {
            self.stage = XzStage::IndexIntegers(remaining - 1);
        }
        Ok(())
    }

    /// Buffers one of the index's variable-length integers, returning how many
    /// bytes long it was, or `None` having stopped the walk.
    ///
    /// A byte at a time: the high bit clear ends the integer, and nine bytes is
    /// the format's longest.
    fn step_over_index_integer(&mut self) -> io::Result<Option<usize>> {
        for length in 1..=9 {
            if self.buffer(1)? < 1 {
                self.stage = XzStage::PassThrough;
                return Ok(None);
            }
            self.index_bytes += 1;
            if self.pending[self.pending.len() - 1] & 0x80 == 0 {
                return Ok(Some(length));
            }
        }
        self.stage = XzStage::PassThrough;
        Ok(None)
    }
}

/// Decodes a variable-length integer that is exactly `bytes` long.
fn decode_vli(bytes: &[u8]) -> Option<u64> {
    let mut at = 0;
    let value = read_vli(bytes, &mut at)?;
    (at == bytes.len()).then_some(value)
}

impl<R: Read> Read for XzDictionaryGuard<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // Anything inspected and waiting goes downstream first, unchanged.
            if self.handed < self.pending.len() {
                let taken = (self.pending.len() - self.handed).min(buf.len());
                buf[..taken].copy_from_slice(&self.pending[self.handed..self.handed + taken]);
                self.handed += taken;
                return Ok(taken);
            }
            self.pending.clear();
            self.handed = 0;
            // A block's payload is forwarded without being looked at.
            if self.forward > 0 {
                let want = usize::try_from(self.forward)
                    .unwrap_or(usize::MAX)
                    .min(buf.len());
                let got = self.source.read(&mut buf[..want])?;
                if got == 0 {
                    // The payload ends short. The decoder reports that; the
                    // guard has nothing left to find.
                    self.stage = XzStage::PassThrough;
                    self.forward = 0;
                    return Ok(0);
                }
                self.forward -= got as u64;
                return Ok(got);
            }
            if matches!(self.stage, XzStage::PassThrough) {
                return self.source.read(buf);
            }
            let before = self.pending.len();
            self.inspect()?;
            if self.pending.len() == before && self.forward == 0 {
                // Nothing was read and nothing was queued: the walk has run out
                // of container to follow, so the rest is the source's.
                debug_assert!(matches!(self.stage, XzStage::PassThrough));
                return self.source.read(buf);
            }
        }
    }
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

    /// The LZMA2 dictionary property byte that declares `bytes`.
    ///
    /// The inverse of [`lzma2_dictionary`] over the even properties, which are
    /// the powers of two: property `p` declares `2^(p / 2 + 12)`.
    fn dictionary_property(bytes: u64) -> u8 {
        let property = (bytes.trailing_zeros() as u8 - 12) * 2;
        assert_eq!(
            lzma2_dictionary(property),
            bytes,
            "{bytes} is a power of two"
        );
        property
    }

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
    /// next. A walk that sized it wrongly would step into the middle of the
    /// following header, fail to recognise it, and quietly stop checking --
    /// which no fixture written without one could catch, and which would mean
    /// the guard covered nothing at all in production. The archives this crate
    /// reads use CRC32 and CRC64.
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

        /// How many bytes follow each block, which is what the walk must know.
        fn size(self) -> u64 {
            xz_check_size(self.id())
        }

        /// The check itself, over what the block decodes to.
        fn over(self, data: &[u8]) -> Vec<u8> {
            match self {
                Check::None => Vec::new(),
                Check::Crc32 => crc32(data).to_vec(),
            }
        }
    }

    /// Reads `bytes` through [`XzDictionaryGuard`] alone, decoding nothing.
    ///
    /// The guard is what these tests are about, and driving it directly keeps
    /// them from allocating the dictionaries they name: a fixture declaring the
    /// cap would otherwise cost 128 MiB of zeroed memory to admit.
    fn guard_all(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut guard = XzDictionaryGuard::new(bytes);
        let mut out = Vec::new();
        // A small buffer on purpose: it splits headers across reads, which is
        // the case a guard that buffers is most likely to get wrong.
        let mut chunk = [0u8; 7];
        loop {
            match guard.read(&mut chunk)? {
                0 => return Ok(out),
                got => out.extend_from_slice(&chunk[..got]),
            }
        }
    }

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn the_guard_hands_back_exactly_what_it_was_given() {
        // The property everything else rests on: the guard is transparent. Two
        // streams, four blocks between them, read seven bytes at a time so
        // every header is split across reads.
        let mut bytes = xz_stream(
            Check::Crc32,
            &[
                Block::new(8 * MIB, b"first block"),
                Block::new(8 * MIB, b"second block"),
            ],
        );
        bytes.extend_from_slice(&xz_stream(
            Check::Crc32,
            &[
                Block::new(4096, b"third block"),
                Block::new(64 * MIB, b"fourth block"),
            ],
        ));
        assert_eq!(guard_all(&bytes).expect("the walk completes"), bytes);
    }

    #[test]
    fn a_fixture_stream_is_one_a_real_decoder_decodes() {
        // The fixtures are hand-built, so this is what keeps the tests below
        // honest: what `xz_stream` writes is a stream `lzma-rust2` accepts, and
        // a guard bug therefore cannot hide behind a bad fixture.
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
    fn an_over_cap_dictionary_is_refused() {
        // The whole point, on the simplest shape: one block asking for more
        // than the cap, refused from its header.
        let bytes = xz_stream(Check::Crc32, &[Block::new(256 * MIB, b"payload")]);
        let err = guard_all(&bytes).expect_err("an over-cap dictionary is refused");
        assert!(err.to_string().contains("dictionary"), "{err}");
        assert!(err.to_string().contains("256 MiB"), "{err}");
    }

    #[test]
    fn a_later_blocks_dictionary_is_also_capped() {
        // The reason the guard walks rather than checking the front of the
        // file. Every block declares its own dictionary and every one is
        // allocated, so a file whose first block is ordinary and whose second
        // asks for 4 GiB costs the 4 GiB -- and then decodes successfully,
        // reporting nothing. A first-block check admits exactly this file.
        let bytes = xz_stream(
            Check::Crc32,
            &[
                Block::new(8 * MIB, b"an ordinary first block"),
                Block::new(2048 * MIB, b"and a hostile second one"),
            ],
        );
        let err = guard_all(&bytes).expect_err("the second block is refused too");
        assert!(err.to_string().contains("2048 MiB"), "{err}");
    }

    #[test]
    fn the_last_of_many_blocks_is_still_checked() {
        // A real archive is not two blocks. A Gentoo stage3 is one stream of
        // seventy-five, each declaring 8 MiB, and every one of them is
        // allocated in turn -- so the walk has to still be tracking at the end
        // of a long stream, not only just after the front of it.
        let mut blocks: Vec<Block<'_>> =
            (0..75).map(|_| Block::new(8 * MIB, b"ordinary")).collect();
        let ordinary = xz_stream(Check::Crc32, &blocks);
        assert_eq!(
            guard_all(&ordinary).expect("seventy-five walk clean"),
            ordinary
        );

        blocks.push(Block::new(512 * MIB, b"hostile"));
        let err = guard_all(&xz_stream(Check::Crc32, &blocks))
            .expect_err("the seventy-sixth block is checked too");
        assert!(err.to_string().contains("512 MiB"), "{err}");
    }

    #[test]
    fn a_stream_carrying_no_check_is_walked_too() {
        // The check's size is what separates one block from the next, and zero
        // is one of the sizes the format allows. Getting it wrong would not
        // fail anything -- the walk would step into the next header, not
        // recognise it, and quietly stop -- so it is asserted rather than
        // assumed.
        let bytes = xz_stream(
            Check::None,
            &[
                Block::new(8 * MIB, b"an ordinary first block"),
                Block::new(512 * MIB, b"and a hostile second one"),
            ],
        );
        let err = guard_all(&bytes).expect_err("the second block is checked here too");
        assert!(err.to_string().contains("512 MiB"), "{err}");
    }

    #[test]
    fn a_dictionary_in_a_second_stream_is_also_capped() {
        // Concatenated streams are legal and the decoder is told to read them
        // all, so the walk steps over an index and a footer to keep checking.
        let mut bytes = xz_stream(Check::Crc32, &[Block::new(8 * MIB, b"an ordinary stream")]);
        bytes.extend_from_slice(&xz_stream(
            Check::Crc32,
            &[Block::new(512 * MIB, b"a hostile one")],
        ));
        let err = guard_all(&bytes).expect_err("the second stream is checked too");
        assert!(err.to_string().contains("512 MiB"), "{err}");
    }

    #[test]
    fn stream_padding_between_streams_does_not_lose_the_walk() {
        // Four zero bytes may sit between two streams. Mistaking them for the
        // start of a header, or for the end of the file, would stop the walk
        // one stream early and silently.
        let mut bytes = xz_stream(Check::Crc32, &[Block::new(8 * MIB, b"an ordinary stream")]);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(&xz_stream(
            Check::Crc32,
            &[Block::new(512 * MIB, b"a hostile one")],
        ));
        let err = guard_all(&bytes).expect_err("the padded second stream is checked too");
        assert!(err.to_string().contains("512 MiB"), "{err}");
    }

    #[test]
    fn a_dictionary_of_exactly_the_cap_is_admitted() {
        // The boundary is inclusive, and 64 MiB -- what `xz -9` writes, and the
        // largest observed in the archives this crate reads -- is well inside
        // it. Neither is decoded: admitting the cap would otherwise cost 128
        // MiB of zeroed memory to prove a comparison.
        for dictionary in [64 * MIB, MAX_XZ_DICTIONARY] {
            let bytes = xz_stream(Check::Crc32, &[Block::new(dictionary, b"payload")]);
            assert_eq!(
                guard_all(&bytes).expect("a dictionary at or under the cap is admitted"),
                bytes,
            );
        }
    }

    #[test]
    fn a_block_declaring_no_compressed_size_stops_the_walk_rather_than_failing_it() {
        // `xz -T1 --block-size=...` writes headers without a compressed size,
        // and the next header is then findable only by decoding this block to
        // its LZMA2 end marker. The walk stops there. What it must not do is
        // refuse: the file is legal, and the decoder reads it.
        let bytes = xz_stream(
            Check::Crc32,
            &[Block {
                dictionary: 8 * MIB,
                data: b"payload",
                declare_size: false,
            }],
        );
        assert_eq!(
            guard_all(&bytes).expect("a legal stream is not refused"),
            bytes
        );
    }

    #[test]
    fn the_walk_stops_at_a_shape_it_cannot_follow_rather_than_refusing() {
        // The same rule for a header the walk does not understand. A reserved
        // flag bit is the stand-in: the decoder is the authority on whether a
        // stream is valid, and refusing here would break real archives to bound
        // a hypothetical one.
        let mut bytes = xz_stream(Check::Crc32, &[Block::new(8 * MIB, b"payload")]);
        bytes[XZ_STREAM_HEADER + 1] |= 0x04;
        assert_eq!(
            guard_all(&bytes).expect("an odd shape is not refused"),
            bytes
        );
    }

    #[test]
    fn a_truncated_stream_is_handed_back_rather_than_refused() {
        // Every prefix of a real stream: the walk runs out of container at some
        // point in each, and must hand back what it read and stop. Reporting
        // the truncation is the decoder's, and a guard that lost bytes here
        // would corrupt an archive rather than bound one.
        let bytes = xz_stream(
            Check::Crc32,
            &[
                Block::new(8 * MIB, b"first block"),
                Block::new(8 * MIB, b"second block"),
            ],
        );
        for cut in 0..bytes.len() {
            assert_eq!(
                guard_all(&bytes[..cut]).unwrap_or_else(|err| panic!("cut at {cut}: {err}")),
                bytes[..cut],
                "cut at {cut}",
            );
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
