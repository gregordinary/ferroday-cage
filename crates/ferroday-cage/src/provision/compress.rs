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
//! [`ZstdReader`] drives one decoder per frame, and compares a frame's
//! content checksum, where the frame carries one, as the frame ends.
//! [`GzipReader`] walks gzip's members itself, so the zero padding a writer
//! leaves after the last one reads as `gzip` reads it.
//!
//! Two of the three formats let a hostile archive name its own memory cost, in
//! a header far smaller than the allocation it asks for. A zstd frame declares
//! the window the decoder buffers, and an xz block declares the dictionary the
//! decoder allocates and zeroes; both are bounded here, at
//! [`MAX_ZSTD_WINDOW`] and [`MAX_XZ_DICTIONARY`]. Each decoder is given its
//! bound at construction and checks it against the header before allocating
//! anything.
//!
//! A decoder fails for one of two reasons, and they are not one failure. It
//! refuses the stream, which is malformed or truncated, and that is the
//! stream's; or the source it reads from fails, an OS error or a transport's,
//! and that is the host's, which a caller may retry. `Read` carries both as an
//! `io::Error`, so every decoder here marks a refusal of its own as a
//! [`Refusal`] and passes a failure of its source through as the source
//! returned it.

use std::cell::Cell;
use std::fmt;
use std::io::{self, BufRead, Read};
use std::rc::Rc;

use ruzstd::decoding::{FrameDecoder, StreamingDecoder};

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
/// `ruzstd`'s own 100 MiB default, so it is set explicitly on the decoder.
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

/// Fills `buf` from `reader`, returning how much was filled: all of it, unless
/// the input ends first.
///
/// A `read` is free to return less than was asked for while more is coming --
/// a buffered reader does whenever a request straddles a refill, and a pipe or
/// a socket does as data arrives -- so a caller that takes a short read for the
/// end of its input has to loop. This is that loop, with an interrupted read
/// retried rather than reported. [`std::io::Read::read_exact`] is the same loop
/// for a caller to whom a short input is always an error.
///
/// A failure part way through is reported, and whatever the failed fill had
/// already read is lost with it: nothing that reads through this can continue
/// past an error in its input, so there is no later read to give it to.
pub(crate) fn read_fully(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

/// A compression [`decoder`] recognizes by its magic, or none.
///
/// Named so that a caller reading a document published in only some of these
/// can refuse the others before any decoder runs. A decoder that never runs
/// costs nothing, whatever its input would have asked of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Codec {
    /// gzip, one member or several.
    Gzip,
    /// xz, one stream or several.
    Xz,
    /// zstd, one frame or several, skippable frames included.
    Zstd,
    /// No compression this module recognizes.
    Plain,
}

impl Codec {
    /// The compression `head` begins, as [`decoder`] selects it.
    ///
    /// `head` is the front of a stream, any length: what is checked is the
    /// magic it starts with, so a whole document held in memory answers as its
    /// first bytes would.
    pub(crate) fn of(head: &[u8]) -> Codec {
        if head.starts_with(&[0x1f, 0x8b]) {
            Codec::Gzip
        } else if head.starts_with(&XZ_MAGIC) {
            Codec::Xz
        } else if is_zstd_start(head) {
            Codec::Zstd
        } else {
            Codec::Plain
        }
    }
}

/// The compression `source` begins with, and the stream it decodes to.
///
/// The first bytes are read to name the compression ([`Codec::of`]) and are
/// put back in front of the rest, so what is decoded is the whole of `source`.
/// gzip, xz, and zstd are decoded, each in its multi-member form; anything else
/// is passed through as it stands, and whoever reads it decides whether it is
/// what it should be, as a tar reader decides whether a stream is a tar.
///
/// The one failure here is a failure to read those first bytes. A stream
/// shorter than a magic is not one: it is read as the plain stream it is.
/// Everything a decoder finds wrong with what follows, the frame or the block
/// it refuses, arrives through the stream's own reads.
pub(crate) fn decoder<'r>(mut source: impl Read + 'r) -> io::Result<(Codec, Box<dyn Read + 'r>)> {
    let mut head = [0u8; MAGIC_LEN];
    let filled = read_fully(&mut source, &mut head)?;
    let codec = Codec::of(&head[..filled]);
    let stream = io::Cursor::new(head[..filled].to_vec()).chain(source);
    let decoded: Box<dyn Read + 'r> = match codec {
        // Several concatenated gzip members are one legal gzip file, and a
        // single-member decoder stops silently at the first member's end. A tar
        // reader tolerates a missing terminator at end of input, so a truncated
        // read there provisions an incomplete rootfs without an error.
        Codec::Gzip => Box::new(guard("the gzip stream does not decode", stream, |source| {
            GzipReader::new(io::BufReader::with_capacity(GZIP_BUFFER, source))
        })),
        // Every block of every stream declares its own dictionary and every one
        // is allocated, so the decode runs under a memory budget the decoder
        // checks against each block header before it allocates. Multiple
        // concatenated xz streams are legal in one file and some producers emit
        // them; the reader decodes them as one.
        Codec::Xz => Box::new(guard(
            "the xz stream does not decode",
            stream,
            XzReader::new,
        )),
        // zstd is framed, and a producer such as `pzstd` emits several frames
        // (often behind a leading skippable frame). Decode every frame, each
        // under the window cap: an uncapped decoder would buffer a hostile
        // window into an OOM.
        Codec::Zstd => Box::new(guard("the zstd stream does not decode", stream, |source| {
            ZstdReader::new(Box::new(source))
        })),
        Codec::Plain => Box::new(stream),
    };
    Ok((codec, decoded))
}

/// Why [`inflate`] gave back no document.
#[cfg_attr(
    not(any(feature = "debian", feature = "alpine", feature = "gentoo")),
    allow(dead_code)
)]
#[derive(Debug)]
pub(crate) enum Inflate {
    /// The decoder refused the bytes, and this is its own failure.
    Undecodable(io::Error),
    /// The bytes decode to more than the bound, which nothing beneath them
    /// caused.
    Overlong,
}

/// `bytes`, decoded as their leading bytes say ([`decoder`]), or refused where
/// they decode to more than `limit` bytes rather than cut at it.
///
/// For a document a layer fetched whole, such as a package index, held in
/// memory before it is read. Nothing can fail to read a slice, so every failure
/// is the decoder's refusal or the length, and the two are told apart: a caller
/// reports the first with the decoder's failure as its cause and the second
/// with no cause at all. The decoder is read one byte past the limit rather
/// than written through a writer that refuses at it, since a writer's refusal
/// and a decoder's arrive as the same kind of error.
#[cfg_attr(
    not(any(feature = "debian", feature = "alpine", feature = "gentoo")),
    allow(dead_code)
)]
pub(crate) fn inflate(bytes: &[u8], limit: u64) -> Result<Vec<u8>, Inflate> {
    let undecodable = |err: io::Error| {
        Inflate::Undecodable(match Refusal::of(err) {
            Ok(refusal) => refusal.into_cause(),
            Err(err) => err,
        })
    };
    let (_, decoded) = decoder(bytes).map_err(undecodable)?;
    let mut text = Vec::new();
    decoded
        .take(limit.saturating_add(1))
        .read_to_end(&mut text)
        .map_err(undecodable)?;
    if text.len() as u64 > limit {
        return Err(Inflate::Overlong);
    }
    Ok(text)
}

/// A decoder's refusal of the stream it was given, carried through `Read`.
///
/// A decoder can report a refusal only as an `io::Error`, the type its
/// source's own failures arrive as, so the refusal is marked with this as it
/// leaves the decoder ([`guard`]) and an error that arrives unmarked is the
/// source's. [`tar::read_failure`](super::tar::read_failure) is where an archive
/// reader tells the two apart again.
#[derive(Debug)]
pub(crate) struct Refusal {
    /// What refused, as a reason states it.
    what: &'static str,
    /// The decoder's own failure.
    cause: io::Error,
}

impl Refusal {
    /// `cause`, marked as `what`'s refusal of its input, of the kind `cause` is.
    pub(crate) fn mark(what: &'static str, cause: io::Error) -> io::Error {
        io::Error::new(cause.kind(), Refusal { what, cause })
    }

    /// The refusal `err` was marked as, or `err` as it stands where it is not
    /// one.
    pub(crate) fn of(err: io::Error) -> Result<Refusal, io::Error> {
        if !err.get_ref().is_some_and(|inner| inner.is::<Refusal>()) {
            return Err(err);
        }
        let inner = err
            .into_inner()
            .expect("a marked error carries its refusal");
        Ok(*inner
            .downcast::<Refusal>()
            .expect("the refusal was checked for"))
    }

    /// What refused, as a reason states it: `the gzip stream does not decode`.
    pub(crate) fn what(&self) -> &'static str {
        self.what
    }

    /// The decoder's own failure.
    pub(crate) fn into_cause(self) -> io::Error {
        self.cause
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.what)
    }
}

impl std::error::Error for Refusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// `build`'s decoder over `source`, with its refusals marked as [`Refusal`]s of
/// `what` and a failure of `source` passed through as `source` returned it.
///
/// What the decoder returns cannot say which of the two it is: one passes its
/// source's error up as it arrived, another wraps it in an error of its own. So
/// the source is watched instead ([`Watched`]): a failure there is held aside,
/// and handed on in place of whatever the decoder made of it. Any other failure
/// is the decoder's. An interrupted read is neither, and is passed through to
/// be retried.
///
/// Every decoder [`decoder`] selects is one of these. A layer that needs a
/// decoder of its own builds it here, so the same two failures arrive the same
/// way whoever chose the decoder.
pub(crate) fn guard<R: Read, D: Read>(
    what: &'static str,
    source: R,
    build: impl FnOnce(Watched<R>) -> D,
) -> Guarded<D> {
    let failed = Rc::new(Cell::new(None));
    Guarded {
        decoder: build(Watched {
            source,
            failed: Rc::clone(&failed),
        }),
        failed,
        what,
    }
}

/// A decoder [`guard`] watches the source of.
pub(crate) struct Guarded<D> {
    decoder: D,
    /// The failure the source last returned, held for the read it ends.
    failed: Rc<Cell<Option<io::Error>>>,
    what: &'static str,
}

impl<D: Read> Read for Guarded<D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.decoder.read(buf).map_err(|err| {
            if let Some(failure) = self.failed.take() {
                return failure;
            }
            if err.kind() == io::ErrorKind::Interrupted {
                return err;
            }
            Refusal::mark(self.what, err)
        })
    }
}

/// The source of a [`Guarded`] decoder, holding aside a failure to read it.
pub(crate) struct Watched<R> {
    source: R,
    failed: Rc<Cell<Option<io::Error>>>,
}

impl<R: Read> Read for Watched<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.source.read(buf).map_err(|err| {
            if err.kind() == io::ErrorKind::Interrupted {
                return err;
            }
            // The decoder is told what kind of failure it met, and the failure
            // itself waits for the read the decoder fails in turn.
            let stand_in = io::Error::new(err.kind(), "the stream beneath the decoder failed");
            self.failed.set(Some(err));
            stand_in
        })
    }
}

/// The buffer a gzip stream's compressed bytes are read through, the size
/// `flate2`'s own readers use.
const GZIP_BUFFER: usize = 32 * 1024;

/// A gzip reader that decodes every member of a stream, and reads the zero
/// padding a writer may leave after the last one as `gzip` reads it.
///
/// A member decodes through `flate2`'s single-member decoder, which consumes
/// no more of `source` than the member holds, so where the member ends is where
/// the walk looks for what follows. `gzip` reads any run of zero bytes from
/// there to the end of the stream as padding and says nothing about it, and
/// `bsdtar` leaves exactly that when it writes a compressed archive through a
/// pipe: it fills its last ten-kibibyte record with zeros after compressing.
/// `flate2`'s own multi-member reader takes the first zero for the start of
/// another member and refuses the stream.
///
/// What is accepted is what `gzip` 1.12 accepts without a word, as measured,
/// and nothing more. Zeros, however many, to the end of the stream are read
/// past. A zero followed by anything else, zeros between two members, and any
/// other bytes after a member are each a stream `gzip` exits nonzero on, and
/// each is refused here: the zeros as padding that ends before the stream does,
/// the rest as the member header they fail to be.
struct GzipReader<R: BufRead> {
    state: Gzip<R>,
}

/// Where a [`GzipReader`] is in its stream.
enum Gzip<R: BufRead> {
    /// Before a member: at the start of the stream, or past the end of one.
    Between {
        source: R,
        /// Whether no member has been read yet, where nothing can be padding.
        first: bool,
    },
    /// Inside a member. The decoder is far larger than the other states, so it
    /// is boxed rather than sizing every state by it.
    Member(Box<flate2::bufread::GzDecoder<R>>),
    /// Every member has been read, and whatever followed them was padding.
    Done,
    /// A failure ended the stream. A read after one fails again rather than
    /// answering the end of input that the stream did not reach.
    Failed,
}

/// What follows the end of a gzip member, or the start of the stream.
enum Next {
    /// Nothing: the stream ends.
    End,
    /// A zero byte, which is padding to the end of the stream or nothing.
    Padding,
    /// Anything else, which is a member or a malformed stream.
    Member,
}

impl<R: BufRead> GzipReader<R> {
    /// A reader positioned at the start of `source`'s first member.
    fn new(source: R) -> GzipReader<R> {
        GzipReader {
            state: Gzip::Between {
                source,
                first: true,
            },
        }
    }
}

impl<R: BufRead> Read for GzipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // A zero-length request is not end of stream, and the member handover
        // below reads a zero-byte decoder read as one.
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let next = match &mut self.state {
                Gzip::Done => return Ok(0),
                Gzip::Failed => {
                    return Err(io::Error::other(
                        "the gzip stream ended at an earlier failure",
                    ));
                }
                // A failed read leaves the member in place: an interrupted one
                // is retried by whoever reads this, from where it stopped.
                Gzip::Member(member) => {
                    let read = member.read(buf)?;
                    if read > 0 {
                        return Ok(read);
                    }
                    // The member has ended, its checksum and length held, and
                    // its source is positioned just past it.
                    let Gzip::Member(member) = std::mem::replace(&mut self.state, Gzip::Failed)
                    else {
                        unreachable!("the state was just matched as a member");
                    };
                    self.state = Gzip::Between {
                        source: member.into_inner(),
                        first: false,
                    };
                    continue;
                }
                Gzip::Between { source, first } => match source.fill_buf()?.first() {
                    None => Next::End,
                    Some(0) if !*first => Next::Padding,
                    Some(_) => Next::Member,
                },
            };
            match next {
                Next::End => self.state = Gzip::Done,
                Next::Padding => {
                    let Gzip::Between { source, .. } = &mut self.state else {
                        unreachable!("padding is found between members");
                    };
                    loop {
                        let held = source.fill_buf()?;
                        if held.is_empty() {
                            break;
                        }
                        if held.iter().any(|byte| *byte != 0) {
                            self.state = Gzip::Failed;
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "zero bytes after the last gzip member are followed by more than \
                                 zeros",
                            ));
                        }
                        let read = held.len();
                        source.consume(read);
                    }
                    self.state = Gzip::Done;
                }
                Next::Member => {
                    let Gzip::Between { source, .. } =
                        std::mem::replace(&mut self.state, Gzip::Failed)
                    else {
                        unreachable!("a member is found between members");
                    };
                    self.state = Gzip::Member(Box::new(flate2::bufread::GzDecoder::new(source)));
                }
            }
        }
    }
}

/// The four-byte zstd frame magic, little-endian.
const ZSTD_FRAME_MAGIC: u32 = 0xFD2F_B528;

/// The inclusive range of skippable-frame magics (RFC 8878 section 3.1.2).
const SKIPPABLE_MAGIC: std::ops::RangeInclusive<u32> = 0x184D_2A50..=0x184D_2A5F;

/// The length of a skippable frame's prefix: the four-byte magic, then the
/// four-byte little-endian length of the content that follows it.
const SKIPPABLE_PREFIX: usize = 8;

/// The frame magic `head` begins with, or `None` if it is too short to hold one.
fn frame_magic(head: &[u8]) -> Option<u32> {
    read_le(head, 0, 4).map(|magic| magic as u32)
}

/// Whether `head` begins a zstd stream: a data frame or a skippable frame.
fn is_zstd_start(head: &[u8]) -> bool {
    frame_magic(head)
        .is_some_and(|magic| magic == ZSTD_FRAME_MAGIC || SKIPPABLE_MAGIC.contains(&magic))
}

/// One frame of the stream being decoded, read from the stream's one source.
///
/// The decoder is handed back with the source when the frame ends and is reset
/// for the next frame, so the buffers it sized for one frame serve the next.
type Frame<'r> = StreamingDecoder<Source<'r>, FrameDecoder>;

/// A zstd reader that decodes every frame of a possibly multi-frame stream.
///
/// `ruzstd`'s [`StreamingDecoder`] decodes a single frame, so a `.tar.zst` from
/// a multi-frame producer such as `pzstd` would otherwise be truncated after
/// the first frame and rejected downstream as a malformed tar. This drives one
/// frame at a time: when a frame ends it takes the source and the decoder back
/// and, if another frame follows, decodes that one too, until the input is
/// exhausted. The decoder carries the window cap, so a later frame is bounded
/// exactly as the first is. Skippable frames between or before data frames are
/// consumed and ignored.
///
/// The first frame is started by the first read rather than at construction,
/// so whatever is wrong with it is reported where whatever is wrong with a
/// later one is: as a read's failure.
///
/// A frame that carries a content checksum is held to it as it ends. `ruzstd`
/// computes the checksum while decoding but leaves the comparison to its
/// caller, and a frame whose content does not match it is a corrupt stream:
/// for an archive nothing else vouches for, the checksum is the only thing
/// that says so.
struct ZstdReader<'r> {
    state: Zstd<'r>,
}

/// Where a [`ZstdReader`] is in its stream.
enum Zstd<'r> {
    /// Between frames: before the first, or past the end of one, with the
    /// source and the decoder that next frame is read with.
    Between {
        source: Source<'r>,
        decoder: FrameDecoder,
        /// Whether no frame has been started yet, where a stream with none is
        /// refused rather than read as empty.
        first: bool,
    },
    /// Inside a frame.
    Frame(Frame<'r>),
    /// Every frame has been read.
    Done,
    /// A failure ended the stream. A read after one fails again rather than
    /// answering the end of input that the stream did not reach.
    Failed,
}

impl<'r> ZstdReader<'r> {
    /// A reader positioned before the first frame of `source`.
    fn new(source: Box<dyn Read + 'r>) -> ZstdReader<'r> {
        let mut decoder = FrameDecoder::new();
        decoder.set_max_window_size(MAX_ZSTD_WINDOW);
        ZstdReader {
            state: Zstd::Between {
                source: Source::new(source),
                decoder,
                first: true,
            },
        }
    }

    /// Moves past the frame just exhausted, or onto the first, holding the one
    /// ended to its checksum: the next state, or the failure that ends the
    /// stream.
    fn advance(state: Zstd<'r>) -> io::Result<Zstd<'r>> {
        let (source, decoder, first) = match state {
            Zstd::Between {
                source,
                decoder,
                first,
            } => (source, decoder, first),
            Zstd::Frame(frame) => {
                // The frame is exhausted: its decoder yields zero only at its
                // end, with everything it decoded read out.
                let (source, decoder) = frame.into_parts();
                check_content(&decoder)?;
                (source, decoder, false)
            }
            Zstd::Done | Zstd::Failed => unreachable!("only a frame or a gap advances"),
        };
        match start_frame(source, decoder)? {
            Some(frame) => Ok(Zstd::Frame(frame)),
            None if first => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the zstd stream has no frame",
            )),
            None => Ok(Zstd::Done),
        }
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
            match &mut self.state {
                Zstd::Done => return Ok(0),
                Zstd::Failed => {
                    return Err(io::Error::other(
                        "the zstd stream ended at an earlier failure",
                    ));
                }
                // A failed read leaves the frame in place: an interrupted one
                // is retried by whoever reads this, from where it stopped.
                Zstd::Frame(frame) => {
                    let read = frame.read(buf)?;
                    if read > 0 {
                        return Ok(read);
                    }
                }
                Zstd::Between { .. } => {}
            }
            let state = std::mem::replace(&mut self.state, Zstd::Failed);
            self.state = ZstdReader::advance(state)?;
        }
    }
}

/// Refuses a frame whose content does not match the checksum it carries.
///
/// Called once the frame has been read out, which is when the decoder's own
/// running checksum covers everything it produced. A frame carrying no
/// checksum, which the format permits, passes.
fn check_content(decoder: &FrameDecoder) -> io::Result<()> {
    match decoder.get_checksum_from_data() {
        Some(stated) if decoder.get_calculated_checksum() != Some(stated) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a zstd frame's content does not match its checksum",
        )),
        _ => Ok(()),
    }
}

/// Peeks the next frame in `source` and starts `decoder` on it, or answers
/// `None` at a clean end of input. A skippable frame is consumed and the search
/// continues; a data frame is refused if its header declares a window over the
/// decoder's cap, before any of it is decoded.
///
/// A failure to read `source` is returned as it arrived; everything else is the
/// stream's, as an [`io::ErrorKind::InvalidData`] naming what is wrong.
fn start_frame<'r>(mut source: Source<'r>, decoder: FrameDecoder) -> io::Result<Option<Frame<'r>>> {
    let malformed = |reason: &str| io::Error::new(io::ErrorKind::InvalidData, reason);
    loop {
        let header = source.peek(ZSTD_HEADER_PEEK)?;
        if header.is_empty() {
            // The previous frame was the last: a clean end of the stream.
            return Ok(None);
        }
        let Some(magic) = frame_magic(header) else {
            return Err(malformed("trailing bytes are too short to be a zstd frame"));
        };
        if SKIPPABLE_MAGIC.contains(&magic) {
            let size = read_le(header, 4, 4)
                .ok_or_else(|| malformed("a skippable zstd frame has a truncated size"))?;
            source.skip(SKIPPABLE_PREFIX as u64 + size)?;
            continue;
        }
        if magic != ZSTD_FRAME_MAGIC {
            return Err(malformed(
                "trailing bytes after the last zstd frame are not a frame",
            ));
        }
        // The peeked header is still in front of the source, so the decoder
        // reads the frame whole. It parses the header and refuses an
        // over-large window before it allocates its ring buffer.
        let frame = StreamingDecoder::new_with_decoder(source, decoder)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        return Ok(Some(frame));
    }
}

/// The compressed side of a zstd stream: the one reader every frame is read
/// from, with the bytes a peek at the next frame read ahead held in front of it.
///
/// The frame walk reads each frame's header before deciding what the frame is,
/// and the decoder then needs those bytes again. Putting them back by chaining
/// them in front of the reader would add one layer per frame, and every read
/// would pass through all of them, so a stream of many small frames would
/// decode in time quadratic in their number. Holding them here keeps one
/// layer however many frames there are, in one small buffer that is reused.
struct Source<'r> {
    inner: Box<dyn Read + 'r>,
    /// Bytes read from `inner` ahead of whoever reads this, at most a header
    /// peek's worth.
    held: Vec<u8>,
    /// How many of `held` have since been read.
    taken: usize,
}

impl<'r> Source<'r> {
    fn new(inner: Box<dyn Read + 'r>) -> Source<'r> {
        Source {
            inner,
            held: Vec::with_capacity(ZSTD_HEADER_PEEK),
            taken: 0,
        }
    }

    /// The next `want` bytes of the stream, left unread; fewer only where the
    /// stream ends first.
    fn peek(&mut self, want: usize) -> io::Result<&[u8]> {
        self.held.drain(..self.taken);
        self.taken = 0;
        let have = self.held.len();
        if have < want {
            self.held.resize(want, 0);
            let filled = read_fully(&mut self.inner, &mut self.held[have..]);
            self.held
                .truncate(have + filled.as_ref().map_or(0, |filled| *filled));
            filled?;
        }
        Ok(&self.held[..want.min(self.held.len())])
    }

    /// Consumes the next `count` bytes, failing if the stream ends first: a
    /// skippable frame that runs off the end of the stream is malformed.
    fn skip(&mut self, count: u64) -> io::Result<()> {
        let from_held =
            (self.held.len() - self.taken).min(usize::try_from(count).unwrap_or(usize::MAX));
        self.taken += from_held;
        let remaining = count - from_held as u64;
        let skipped = io::copy(&mut (&mut self.inner).take(remaining), &mut io::sink())?;
        if skipped < remaining {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the frame ended before its declared size",
            ));
        }
        Ok(())
    }
}

impl Read for Source<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let held = &self.held[self.taken..];
        if held.is_empty() {
            return self.inner.read(buf);
        }
        let count = held.len().min(buf.len());
        buf[..count].copy_from_slice(&held[..count]);
        self.taken += count;
        Ok(count)
    }
}

/// The six-byte signature every xz stream begins with.
const XZ_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];

/// The memory budget an xz decode runs under, in kibibytes.
///
/// `lzma-rust2` checks a *memory* figure against this -- the block's dictionary
/// rounded up, plus the decoder's own tables and the buffer it reads a
/// compressed chunk into -- as it parses each block header, before allocating
/// anything. The budget is therefore the dictionary cap plus slack for those:
/// sized at the cap alone it would refuse a dictionary of exactly
/// [`MAX_XZ_DICTIONARY`], which they push over.
///
/// One mebibyte of slack admits nothing a tighter figure would not. Dictionary
/// sizes step in halvings and doublings, so the next one up from 128 MiB is
/// 192 MiB, and the slack would have to be sixty-four times this to reach it.
/// Stating it as slack rather than as the decoder's exact constant also means
/// an upstream change to that constant moves nothing here.
const MAX_XZ_MEMORY_KB: u32 = (MAX_XZ_DICTIONARY / 1024) as u32 + 1024;

/// The buffer compressed input is read through.
///
/// The decoder reads each LZMA2 chunk whole, but a header, an index, and the
/// padding between streams a few bytes at a time. Buffering keeps those from
/// becoming a read of the source each.
const XZ_CHUNK: usize = 64 * 1024;

/// An xz decoder bounded by [`MAX_XZ_DICTIONARY`].
///
/// `lzma-rust2`'s own reader, given [`MAX_XZ_MEMORY_KB`] at construction. It
/// checks each block header against the budget as it parses one, which is both
/// before the allocation and inside the parser that decides what to allocate --
/// the two properties a bound applied from outside could not have. Concatenated
/// streams are decoded as one, which several producers emit and the format
/// permits.
///
/// Two things are this type's rather than the decoder's. A refusal is rewritten
/// to name the bound in force, by [`refused_memory`]. And an empty buffer is
/// answered here, without reaching the decoder: it takes a read that produces
/// nothing for the end of the block in progress, which is what a read into no
/// space always produces.
struct XzReader<R: Read>(lzma_rust2::XzReader<io::BufReader<R>>);

impl<R: Read> XzReader<R> {
    /// Wraps `source`, positioned at the start of the first stream header.
    fn new(source: R) -> XzReader<R> {
        XzReader(lzma_rust2::XzReader::new_mem_limit(
            io::BufReader::with_capacity(XZ_CHUNK, source),
            // Several concatenated xz streams are one legal file.
            true,
            MAX_XZ_MEMORY_KB,
        ))
    }
}

impl<R: Read> Read for XzReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.0.read(buf).map_err(refused_memory)
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

    /// A tar stream of one file, without the two blocks that end a stream, so
    /// that two of them joined read as one stream. Used to prove that a
    /// multi-member wrapper delivers every member's bytes.
    fn tar_of(name: &str, contents: &[u8]) -> Vec<u8> {
        ferroday_cage_testkit::tar::Tar::new()
            .file(name, 0o644, contents)
            .unterminated()
    }

    #[test]
    fn concatenated_gzip_members_all_decode() {
        // Two gzip members in one file is one legal gzip stream — `pigz` emits
        // them, and so does `cat a.gz b.gz`. A single-member decoder stops
        // silently at the first, and the tar reader tolerates a missing
        // terminator at end of input, so the result would be a rootfs missing
        // everything past the first member with no error anywhere.
        use ferroday_cage_testkit::compress::gzip;

        let first = tar_of("first", b"one\n");
        let second = tar_of("second", b"two\n");
        let mut stream = gzip(&first);
        stream.extend_from_slice(&gzip(&second));

        let (codec, mut reader) = decoder(stream.as_slice()).expect("the head reads");
        assert_eq!(codec, Codec::Gzip);
        let mut decoded = Vec::new();
        reader
            .read_to_end(&mut decoded)
            .expect("the stream decodes");
        let mut expected = first.clone();
        expected.extend_from_slice(&second);
        assert_eq!(decoded, expected, "both members decoded");
    }

    #[test]
    fn zero_padding_after_the_last_gzip_member_is_read_as_gzip_reads_it() {
        // What gzip 1.12 reads silently, measured: any run of zeros from the
        // last member's end to the end of the stream, which bsdtar leaves when
        // it fills a record after compressing.
        let first = tar_of("first", b"one\n");
        let second = tar_of("second", b"two\n");
        for zeros in [1, 4, 10_117] {
            let mut stream = ferroday_cage_testkit::compress::gzip(&first);
            stream.resize(stream.len() + zeros, 0);
            assert_eq!(
                decode_all(&stream).expect("padding is read past"),
                first,
                "{zeros}"
            );

            let mut stream = ferroday_cage_testkit::compress::gzip(&first);
            stream.extend_from_slice(&ferroday_cage_testkit::compress::gzip(&second));
            stream.resize(stream.len() + zeros, 0);
            assert_eq!(
                decode_all(&stream).expect("both members, then padding"),
                [&first[..], &second].concat(),
                "{zeros}",
            );
        }
    }

    #[test]
    fn bytes_after_a_gzip_member_that_gzip_complains_of_are_refused() {
        // Each of these makes gzip 1.12 exit nonzero, as "trailing garbage
        // ignored" or "unexpected end of file": zeros that a member follows,
        // zeros that anything but zeros follows, and bytes that are not zeros
        // and not a member.
        let member = ferroday_cage_testkit::compress::gzip(&tar_of("first", b"one\n"));
        let between = [&member[..], &[0u8; 16], &member].concat();
        let then_junk = [&member[..], &[0u8; 16], b"x"].concat();
        let junk = [&member[..], b"ABCD"].concat();
        let lone = [&member[..], &[0xff]].concat();
        for (case, stream) in [
            ("zeros between members", between),
            ("zeros then junk", then_junk),
            ("junk", junk),
            ("one stray byte", lone),
        ] {
            decode_all(&stream).expect_err(case);
        }
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
    /// Driven through [`decoder`], so what is asserted is the path a
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
    fn trailing_stream_padding_comes_in_whole_words() {
        // Padding after the last stream is a multiple of four zero bytes. Two
        // are neither padding nor the start of a stream, so the file is not a
        // valid xz file and is refused rather than read as complete.
        let stream = xz_stream(Check::Crc32, &[Block::new(4096, b"payload")]);
        let mut aligned = stream.clone();
        aligned.extend_from_slice(&[0; 4]);
        assert_eq!(
            decode_all(&aligned).expect("whole-word padding decodes"),
            b"payload"
        );
        let mut unaligned = stream;
        unaligned.extend_from_slice(&[0; 2]);
        decode_all(&unaligned).expect_err("two bytes of padding are refused");
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
    fn a_truncated_stream_is_refused_rather_than_decoded_short() {
        // Every prefix of a real stream long enough to be sniffed as xz. Each is
        // a decode that runs out of input, and each must return and fail: a
        // prefix decoded as though it were whole hands the tar reader a short
        // archive, which it can accept without a terminator. None of them is a
        // memory refusal.
        let bytes = xz_stream(
            Check::Crc32,
            &[
                Block::new(8 * MIB, b"first block"),
                Block::new(8 * MIB, b"second block"),
            ],
        );
        for cut in XZ_MAGIC.len()..bytes.len() {
            match decode_all(&bytes[..cut]) {
                Ok(decoded) => panic!("cut at {cut}: decoded {decoded:?}"),
                Err(err) => assert_ne!(
                    err.kind(),
                    io::ErrorKind::OutOfMemory,
                    "cut at {cut}: a truncation is not a memory refusal",
                ),
            }
        }
    }

    #[test]
    fn an_empty_read_mid_block_loses_nothing() {
        // A read into no space asks for nothing and must change nothing. The
        // decoder beneath takes a read that produces nothing for the end of the
        // block in progress, so the reader answers this one itself.
        let bytes = xz_stream(Check::Crc32, &[Block::new(4096, b"one block of payload")]);
        let (codec, mut reader) = decoder(&bytes[..]).expect("the head reads");
        assert_eq!(codec, Codec::Xz);
        let mut first = [0u8; 4];
        reader.read_exact(&mut first).expect("the block starts");
        assert_eq!(reader.read(&mut []).expect("an empty read"), 0);
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).expect("the block continues");
        assert_eq!([&first[..], &rest].concat(), b"one block of payload");
    }

    /// A reader that hands out one byte per read, the shortest answer short of
    /// end of input that `Read` allows. A pipe or a socket delivering bytes as
    /// they arrive answers this way, and so does a buffered reader at the end
    /// of each refill.
    struct OneByte<'a>(&'a [u8]);

    impl Read for OneByte<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match (buf.first_mut(), self.0.split_first()) {
                (Some(slot), Some((byte, rest))) => {
                    *slot = *byte;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    /// Fully decodes `bytes` through [`decoder`], read from a source that
    /// answers one byte at a time.
    fn decode_one_byte_at_a_time(bytes: &[u8]) -> Result<Vec<u8>, io::Error> {
        let (_, mut reader) = decoder(OneByte(bytes))?;
        let mut out = Vec::new();
        reader.read_to_end(&mut out).map_err(refused)?;
        Ok(out)
    }

    /// The decoder's own failure, from a read whose source cannot fail: every
    /// failure there is a refusal, and arrives marked as one.
    fn refused(err: io::Error) -> io::Error {
        match Refusal::of(err) {
            Ok(refusal) => refusal.into_cause(),
            Err(err) => panic!("a source held in memory failed: {err}"),
        }
    }

    #[test]
    fn block_padding_split_across_reads_still_decodes() {
        // Each block's compressed data is padded to a four-byte boundary with
        // one to three zero bytes. A source that answers a byte at a time
        // splits every padding of two or three bytes across reads, which is
        // where a buffered source splits one whenever a refill falls inside
        // it. These blocks carry every padding width, including none, and none
        // of it may decide whether a valid archive decodes.
        let data: [&[u8]; 6] = [b"a", b"ab", b"abc", b"abcd", b"abcde", b"abcdef"];
        let blocks: Vec<Block<'_>> = data.iter().map(|data| Block::new(4096, data)).collect();
        let bytes = xz_stream(Check::Crc32, &blocks);
        assert_eq!(
            decode_one_byte_at_a_time(&bytes).expect("a valid multi-block stream decodes"),
            data.concat(),
        );
    }

    #[test]
    fn a_long_run_of_empty_streams_decodes() {
        // An empty xz stream is thirty-two bytes, and concatenated streams are
        // one legal file. A decoder that took each next stream by recursing
        // would exhaust its stack on a run of them a megabyte long, aborting
        // the process rather than failing the decode; this run is several
        // times what that takes on a test thread's stack.
        let empty = xz_stream(Check::None, &[]);
        assert_eq!(
            empty.len(),
            32,
            "the fixture is the smallest stream there is"
        );
        let mut bytes = empty.repeat(20_000);
        bytes.extend_from_slice(&xz_stream(Check::Crc32, &[Block::new(4096, b"payload")]));
        assert_eq!(
            decode_all(&bytes).expect("every stream decodes"),
            b"payload"
        );
    }

    #[test]
    fn concatenated_xz_streams_all_decode() {
        // The same shape for xz, which the module claims to handle and no test
        // pinned.
        use ferroday_cage_testkit::compress::xz;
        let first = tar_of("first", b"one\n");
        let second = tar_of("second", b"two\n");
        let mut stream = xz(&first);
        stream.extend_from_slice(&xz(&second));

        let (codec, mut reader) = decoder(stream.as_slice()).expect("the head reads");
        assert_eq!(codec, Codec::Xz);
        let mut decoded = Vec::new();
        reader
            .read_to_end(&mut decoded)
            .expect("the stream decodes");
        let mut expected = first.clone();
        expected.extend_from_slice(&second);
        assert_eq!(decoded, expected, "both streams decoded");
    }

    #[test]
    fn a_block_chaining_two_filters_before_lzma2_decodes() {
        // The format allows up to three filters before LZMA2, where `xz` writes
        // at most one. A chain of two, delta then x86, is decoded rather than
        // refused.
        let payload: Vec<u8> = (0..16 * 1024u32).flat_map(u32::to_le_bytes).collect();
        let mut options = lzma_rust2::XzOptions::with_preset(1);
        options.prepend_pre_filter(lzma_rust2::FilterType::BcjX86, 0);
        options.prepend_pre_filter(lzma_rust2::FilterType::Delta, 4);
        let mut out = Vec::new();
        let mut writer = lzma_rust2::XzWriter::new(&mut out, options).expect("an xz writer");
        std::io::Write::write_all(&mut writer, &payload).unwrap();
        writer.finish().expect("the xz stream finishes");

        assert_eq!(decode_all(&out).expect("the chain decodes"), payload);
    }

    /// Builds a skippable frame carrying `content`.
    fn skippable_frame(content: &[u8]) -> Vec<u8> {
        let mut frame = 0x184D_2A50u32.to_le_bytes().to_vec();
        frame.extend_from_slice(&(content.len() as u32).to_le_bytes());
        frame.extend_from_slice(content);
        frame
    }

    /// Fully decodes `bytes` through [`decoder`], answering a refusal with the
    /// decoder's own failure.
    fn decode_all(bytes: &[u8]) -> Result<Vec<u8>, io::Error> {
        let (_, mut reader) = decoder(bytes)?;
        let mut out = Vec::new();
        reader.read_to_end(&mut out).map_err(refused)?;
        Ok(out)
    }

    /// A source that serves `bytes` and then fails as a reset connection does.
    struct Reset<'a>(&'a [u8]);

    impl Read for Reset<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Err(io::ErrorKind::ConnectionReset.into());
            }
            self.0.read(buf)
        }
    }

    #[test]
    fn a_failing_source_reaches_the_reader_as_itself() {
        // Each decoder fails the read its source failed, and what arrives is
        // the source's failure, unmarked: a caller that retries a transport
        // failure has to be able to see one, and not a corrupt stream.
        let gzip = ferroday_cage_testkit::compress::gzip(&[7u8; 4096]);
        let xz = xz_stream(Check::Crc32, &[Block::new(4096, b"payload")]);
        let zstd = ferroday_cage_testkit::compress::zstd(&[7u8; 4096]);
        for (codec, stream) in [("gzip", gzip), ("xz", xz), ("zstd", zstd)] {
            // Cut short of its end, so the decoder needs a read past the cut.
            let (_, mut reader) =
                decoder(Reset(&stream[..stream.len() / 2])).expect("the head reads");
            let err = reader
                .read_to_end(&mut Vec::new())
                .expect_err("the source fails");
            assert_eq!(err.kind(), io::ErrorKind::ConnectionReset, "{codec}: {err}");
            let err = Refusal::of(err).expect_err("a source's failure is not a refusal");
            assert!(err.get_ref().is_none(), "{codec}: {err:?} is the OS's own");
        }
    }

    #[test]
    fn inflating_tells_a_refused_stream_from_an_overlong_one() {
        // At the bound exactly the document is whole; one byte under it, the
        // same bytes are refused for their length, which nothing beneath them
        // caused; and a stream the decoder refuses carries the decoder's own
        // reason. A plain document is held to the bound as a compressed one is.
        let text = b"a document of thirty-two bytes!\n";
        let gzip = ferroday_cage_testkit::compress::gzip(text);
        for bytes in [&text[..], &gzip] {
            assert_eq!(inflate(bytes, 32).expect("at the bound"), text);
            assert!(matches!(inflate(bytes, 31), Err(Inflate::Overlong)));
        }
        let mut corrupt = gzip.clone();
        corrupt[12..20].fill(0xff);
        match inflate(&corrupt, 1024) {
            Err(Inflate::Undecodable(err)) => {
                assert!(Refusal::of(err).is_err(), "the cause is the decoder's own");
            }
            other => panic!("expected the decoder's refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_refusal_is_marked_as_the_decoders() {
        let mut corrupt =
            ferroday_cage_testkit::compress::zstd(b"a frame that states its checksum");
        *corrupt.last_mut().unwrap() ^= 0x01;
        let (_, mut reader) = decoder(&corrupt[..]).expect("the head reads");
        let err = reader.read_to_end(&mut Vec::new()).expect_err("refused");
        let refusal = Refusal::of(err).expect("the decoder's own refusal");
        assert_eq!(refusal.what(), "the zstd stream does not decode");
        assert!(
            refusal.into_cause().to_string().contains("checksum"),
            "the decoder's reason is the cause",
        );
    }

    #[test]
    fn multi_frame_zstd_decodes_every_frame() {
        // Two concatenated frames, as `pzstd` emits: both must be decoded, not
        // just the first.
        let mut stream = ferroday_cage_testkit::compress::zstd(b"first frame ");
        stream.extend_from_slice(&ferroday_cage_testkit::compress::zstd(b"second frame"));
        assert_eq!(decode_all(&stream).unwrap(), b"first frame second frame");
    }

    #[test]
    fn a_leading_skippable_frame_is_skipped() {
        // A skippable frame ahead of the data frame, the shape `pzstd` writes.
        let mut stream = skippable_frame(b"pzstd metadata here");
        stream.extend_from_slice(&ferroday_cage_testkit::compress::zstd(b"payload"));
        assert_eq!(decode_all(&stream).unwrap(), b"payload");
    }

    #[test]
    fn many_skippable_frames_decode_in_linear_time() {
        // Each frame is peeked before it is decoded, and the peeked bytes are
        // put back in front of the source. Putting them back by wrapping the
        // source once per frame made every read pass through every earlier
        // frame's wrapper: a hundred thousand empty skippable frames, 800 KB of
        // input, took seconds in an optimized build and far longer here. One
        // source with one reusable buffer decodes them in a small fraction of
        // the bound below, which is generous so as to hold on a loaded machine.
        let mut stream = skippable_frame(b"").repeat(100_000);
        stream.extend_from_slice(&ferroday_cage_testkit::compress::zstd(b"payload"));
        let started = std::time::Instant::now();
        assert_eq!(decode_all(&stream).unwrap(), b"payload");
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(10),
            "100000 skippable frames took {took:?}",
        );
    }

    #[test]
    fn frames_read_one_byte_at_a_time_still_decode() {
        // The frame walk peeks a header's worth of bytes and puts back what
        // it does not consume, and a source answering a byte per read gives it
        // the most chances to lose one. A small skippable frame, two data
        // frames, and a larger skippable frame between them.
        let mut stream = skippable_frame(b"xy");
        stream.extend_from_slice(&ferroday_cage_testkit::compress::zstd(b"first frame "));
        stream.extend_from_slice(&skippable_frame(&[7; 100]));
        stream.extend_from_slice(&ferroday_cage_testkit::compress::zstd(b"second frame"));
        assert_eq!(
            decode_one_byte_at_a_time(&stream).unwrap(),
            b"first frame second frame",
        );
    }

    /// The frame header descriptor's content-checksum flag.
    const CONTENT_CHECKSUM_FLAG: u8 = 0x04;

    #[test]
    fn a_frame_whose_content_does_not_match_its_checksum_is_refused() {
        // A frame may end in a checksum of what it decodes to. The decoder
        // computes its own as it goes and compares nothing, so a corrupt
        // frame decodes to whatever the corruption makes of it unless the two
        // are compared here. Altering the stated checksum is the corruption
        // that leaves everything else about the frame intact.
        let frame = ferroday_cage_testkit::compress::zstd(b"a frame that states its checksum");
        assert_ne!(
            frame[4] & CONTENT_CHECKSUM_FLAG,
            0,
            "the fixture carries a checksum"
        );
        assert_eq!(
            decode_all(&frame).unwrap(),
            b"a frame that states its checksum",
        );

        let mut corrupt = frame.clone();
        *corrupt.last_mut().unwrap() ^= 0x01;
        let err = decode_all(&corrupt).expect_err("a checksum mismatch is refused");
        assert!(err.to_string().contains("checksum"), "{err}");

        // Every frame is held to its own, not only the last: a mismatch in
        // the first of two is refused as the second begins.
        corrupt.extend_from_slice(&frame);
        let err = decode_all(&corrupt).expect_err("an early frame's mismatch is refused");
        assert!(err.to_string().contains("checksum"), "{err}");
    }

    #[test]
    fn a_small_skippable_frame_does_not_consume_the_next_frame() {
        // A skippable frame shorter than the header peek: the pushback path must
        // return the over-read bytes so the following data frame still decodes.
        let mut stream = skippable_frame(b"xy");
        stream.extend_from_slice(&ferroday_cage_testkit::compress::zstd(b"payload"));
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
        let mut stream = ferroday_cage_testkit::compress::zstd(b"ok");
        stream.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x00, OVER_CAP_WINDOW]);
        let err = decode_all(&stream).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("window"), "{err}");
    }

    /// A zstd frame declaring the window `descriptor` encodes, holding
    /// `data` in one raw block.
    ///
    /// Built by hand because the encoder chooses its own window, and these
    /// fixtures are about the one the header declares.
    fn zstd_frame_declaring(descriptor: u8, data: &[u8]) -> Vec<u8> {
        // No checksum, no dictionary, no content size, and not a single
        // segment, so the window descriptor is present and is the only bound.
        let mut frame = ZSTD_MAGIC.to_vec();
        frame.extend_from_slice(&[0x00, descriptor]);
        // A raw block, and the last: its size, then its type, then the flag.
        let block = ((data.len() as u32) << 3) | 1;
        frame.extend_from_slice(&block.to_le_bytes()[..3]);
        frame.extend_from_slice(data);
        frame
    }

    #[test]
    fn an_oversized_zstd_window_is_refused() {
        // A frame declaring a window over the cap: the decoder refuses it from
        // the header, before any of the frame is decoded.
        let err = decode_all(&zstd_frame_declaring(OVER_CAP_WINDOW, b"payload"))
            .expect_err("an oversized window is refused");
        assert!(err.to_string().to_lowercase().contains("window"), "{err}");
    }

    #[test]
    fn a_window_of_exactly_the_cap_is_admitted() {
        // Window descriptor 0x88: exponent 17, mantissa 0, so a window of
        // exactly 2^27 -- [`MAX_ZSTD_WINDOW`]. The decoder's own default bound
        // is lower than that, so this fails the moment the cap stops being set
        // explicitly, which is the regression the cap exists to prevent.
        assert_eq!(MAX_ZSTD_WINDOW, 1 << 27, "the descriptor encodes the cap");
        assert_eq!(
            decode_all(&zstd_frame_declaring(0x88, b"payload")).expect("a window at the cap"),
            b"payload",
        );
    }

    #[test]
    fn a_zstd_stream_of_skippable_frames_alone_is_refused() {
        // The magic says zstd, and no frame carries anything: a stream with no
        // data frame is refused at its first read rather than read as empty.
        let err = decode_all(&skippable_frame(b"metadata")).expect_err("no frame");
        assert!(err.to_string().contains("no frame"), "{err}");
    }
}
