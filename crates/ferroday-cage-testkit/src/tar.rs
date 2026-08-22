//! One ustar writer for every fixture that needs a tar stream.
//!
//! The library's production writer is `provision::export`'s, which is pax-aware
//! and checked; this is the fixture counterpart, deliberately minimal, and it
//! is the only one. Per-entry ownership is a parameter rather than a second
//! writer: a `.deb`'s `data.tar` carries uid and gid so the statoverride
//! derivation can be exercised, and an extraction fixture does not care.

/// A minimal ustar stream writer.
#[derive(Default)]
pub struct Tar {
    data: Vec<u8>,
}

impl Tar {
    /// An empty stream.
    pub fn new() -> Tar {
        Tar::default()
    }

    /// A regular file owned by root.
    pub fn file(&mut self, path: &str, mode: u32, content: &[u8]) -> &mut Tar {
        self.entry(path, b'0', mode, 0, 0, "", content)
    }

    /// A regular file owned by `uid` and `gid`.
    pub fn file_owned(
        &mut self,
        path: &str,
        mode: u32,
        uid: u32,
        gid: u32,
        content: &[u8],
    ) -> &mut Tar {
        self.entry(path, b'0', mode, uid, gid, "", content)
    }

    /// A directory owned by root.
    pub fn dir(&mut self, path: &str, mode: u32) -> &mut Tar {
        self.entry(path, b'5', mode, 0, 0, "", b"")
    }

    /// A directory owned by `uid` and `gid`.
    pub fn dir_owned(&mut self, path: &str, mode: u32, uid: u32, gid: u32) -> &mut Tar {
        self.entry(path, b'5', mode, uid, gid, "", b"")
    }

    /// A symbolic link holding `target` verbatim.
    pub fn symlink(&mut self, path: &str, target: &str) -> &mut Tar {
        self.entry(path, b'2', 0o777, 0, 0, target, b"")
    }

    /// A hard link to `target`.
    pub fn hardlink(&mut self, path: &str, target: &str) -> &mut Tar {
        self.entry(path, b'1', 0o644, 0, 0, target, b"")
    }

    /// An entry of any type, for a fixture that needs one this has no name for.
    ///
    /// The escape hatch under the named builders above, and its parameters are
    /// the tar header's own fields; a fixture that wants them named reaches for
    /// `file`, `dir`, `symlink` or `hardlink` instead.
    #[expect(clippy::too_many_arguments)]
    pub fn entry(
        &mut self,
        path: &str,
        typeflag: u8,
        mode: u32,
        uid: u32,
        gid: u32,
        link: &str,
        content: &[u8],
    ) -> &mut Tar {
        let mut block = [0u8; 512];
        block[..path.len()].copy_from_slice(path.as_bytes());
        octal(&mut block[100..108], u64::from(mode));
        octal(&mut block[108..116], u64::from(uid));
        octal(&mut block[116..124], u64::from(gid));
        octal(&mut block[124..136], content.len() as u64);
        octal(&mut block[136..148], 0);
        block[156] = typeflag;
        block[157..157 + link.len()].copy_from_slice(link.as_bytes());
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        // The checksum is computed with its own field read as spaces, which is
        // the format's own rule.
        let sum: u64 = block
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*byte)
                }
            })
            .sum();
        octal(&mut block[148..156], sum);
        self.data.extend_from_slice(&block);
        self.data.extend_from_slice(content);
        let pad = (512 - content.len() % 512) % 512;
        self.data.resize(self.data.len() + pad, 0);
        self
    }

    /// The stream, with the two zero blocks that end it.
    pub fn finish(&self) -> Vec<u8> {
        let mut data = self.data.clone();
        data.resize(data.len() + 1024, 0);
        data
    }
}

/// Writes a zero-padded, NUL-terminated octal tar field.
pub fn octal(field: &mut [u8], value: u64) {
    let text = format!("{value:0width$o}", width = field.len() - 1);
    field[..text.len()].copy_from_slice(text.as_bytes());
}

/// Reads a space- or NUL-terminated octal tar field.
///
/// The decoder side of [`octal`], for a test that reads back what a writer
/// produced.
pub fn read_octal(field: &[u8]) -> u64 {
    let text = field
        .split(|byte| *byte == 0 || *byte == b' ')
        .next()
        .unwrap_or(b"");
    let text = std::str::from_utf8(text).expect("an octal field is ASCII");
    if text.is_empty() {
        return 0;
    }
    u64::from_str_radix(text, 8).expect("an octal field parses")
}
