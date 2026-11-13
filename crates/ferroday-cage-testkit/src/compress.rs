//! A document compressed whole, as a test hands one to a reader.
//!
//! Each at its fastest setting, since a test compresses only to have something
//! to decompress. A test that asserts how small the result is compresses at
//! the level the assertion needs instead.

use std::io::Write;

/// `data` as one gzip member.
pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).expect("a vector takes the stream");
    encoder.finish().expect("the gzip member closes")
}

/// `data` as one xz stream.
pub fn xz(data: &[u8]) -> Vec<u8> {
    let mut writer = lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1))
        .expect("an xz writer");
    writer.write_all(data).expect("a vector takes the stream");
    writer.finish().expect("the xz stream closes")
}

/// `data` as one zstd frame.
pub fn zstd(data: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
}
