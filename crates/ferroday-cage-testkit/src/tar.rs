//! The tar writer every fixture builds its archives with.
//!
//! The library's production writer is `provision::export`'s, which is pax-aware
//! and checked; this is the fixture counterpart. It is deliberately byte-level:
//! a path or a link target is written verbatim and unvalidated, so a test can
//! produce what no well-behaved tar tool writes (an absolute path, a `..`
//! component, a header whose size its body does not match). Per-entry ownership,
//! modification time, and the pre-POSIX v7 header layout are parameters rather
//! than further writers.

/// A tar stream writer.
///
/// Entries are appended through `&mut self`, so a stream is built either on a
/// binding or in one chain on a temporary:
/// `Tar::new().dir("d", 0o755).file("d/f", 0o644, b"x").finish()`.
#[derive(Debug, Default)]
pub struct Tar {
    data: Vec<u8>,
    v7: bool,
    mtime: u64,
    /// The `uname` and `gname` every header states, where a fixture set them.
    names: Option<(String, String)>,
}

impl Tar {
    /// An empty ustar stream whose entries carry modification time 0.
    pub fn new() -> Tar {
        Tar::default()
    }

    /// The same stream writing pre-POSIX v7 headers: everything past the link
    /// name left zero, so no magic, no version, and no prefix field.
    pub fn v7(mut self) -> Tar {
        self.v7 = true;
        self
    }

    /// The same stream stamping `mtime` on every entry the named builders
    /// append. [`header`](Self::header) and [`file_mtime`](Self::file_mtime)
    /// take a time of their own.
    pub fn stamped(mut self, mtime: u64) -> Tar {
        self.mtime = mtime;
        self
    }

    /// The same stream naming `uname` and `gname` as the owner in every
    /// header appended after this, the ids staying whatever each entry states.
    ///
    /// A ustar header carries an owner by name as well as by id, and a reader
    /// that resolves names, as `apk` does, takes the name first. Without this a
    /// header names no one, as a v7 header cannot.
    pub fn owner_names(&mut self, uname: &str, gname: &str) -> &mut Tar {
        self.names = Some((uname.to_string(), gname.to_string()));
        self
    }

    /// A regular file owned by root.
    pub fn file(&mut self, path: &str, mode: u32, content: &[u8]) -> &mut Tar {
        self.entry(path, b'0', mode, 0, 0, "", content)
    }

    /// A regular file owned by root, with a modification time of its own.
    pub fn file_mtime(&mut self, path: &str, mode: u32, content: &[u8], mtime: u64) -> &mut Tar {
        self.block(
            path.as_bytes(),
            b'0',
            mode,
            (0, 0),
            content.len() as u64,
            mtime,
            b"",
        );
        self.body(content)
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

    /// A named pipe.
    pub fn fifo(&mut self, path: &str, mode: u32) -> &mut Tar {
        self.entry(path, b'6', mode, 0, 0, "", b"")
    }

    /// A character device, with no device numbers.
    pub fn char_device(&mut self, path: &str) -> &mut Tar {
        self.entry(path, b'3', 0o666, 0, 0, "", b"")
    }

    /// A GNU long-name entry carrying `path`, followed by the file it names,
    /// whose own header holds the first hundred bytes of the name.
    pub fn gnu_longname_file(&mut self, path: &str, content: &[u8]) -> &mut Tar {
        let name = path.as_bytes();
        self.header(b"././@LongLink", b'L', 0, name.len() as u64, 0, b"");
        self.body(name);
        let truncated = &name[..name.len().min(100)];
        self.header(truncated, b'0', 0o644, content.len() as u64, 0, b"");
        self.body(content)
    }

    /// A pax extended header renaming the file after it to `path`.
    pub fn pax_file(&mut self, path: &str, content: &[u8]) -> &mut Tar {
        let record = pax_record("path", path);
        self.header(b"pax-header", b'x', 0o644, record.len() as u64, 0, b"");
        self.body(record.as_bytes());
        self.header(
            b"pax-placeholder",
            b'0',
            0o644,
            content.len() as u64,
            0,
            b"",
        );
        self.body(content)
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
        let mtime = self.mtime;
        let size = content.len() as u64;
        self.block(
            path.as_bytes(),
            typeflag,
            mode,
            (uid, gid),
            size,
            mtime,
            link.as_bytes(),
        );
        self.body(content)
    }

    /// A bare header, owned by root, with `path` and `link` written verbatim
    /// and `size` stated whatever follows it.
    ///
    /// For an archive no tool writes: a header whose size is not what its body
    /// holds, an unknown type, a name the extractor must refuse. The body, if
    /// any, is [`body`](Self::body)'s.
    pub fn header(
        &mut self,
        path: &[u8],
        typeflag: u8,
        mode: u32,
        size: u64,
        mtime: u64,
        link: &[u8],
    ) -> &mut Tar {
        self.block(path, typeflag, mode, (0, 0), size, mtime, link);
        self
    }

    /// Appends `data`, padded to the block boundary.
    pub fn body(&mut self, data: &[u8]) -> &mut Tar {
        self.data.extend_from_slice(data);
        self.data.resize(self.data.len().next_multiple_of(512), 0);
        self
    }

    /// The stream, with the two zero blocks that end it.
    pub fn finish(&self) -> Vec<u8> {
        let mut data = self.unterminated();
        data.resize(data.len() + 1024, 0);
        data
    }

    /// The entries alone, without the two zero blocks that end a stream, for
    /// a test that joins streams or holds a reader to a missing terminator.
    pub fn unterminated(&self) -> Vec<u8> {
        self.data.clone()
    }

    #[expect(clippy::too_many_arguments)]
    fn block(
        &mut self,
        path: &[u8],
        typeflag: u8,
        mode: u32,
        (uid, gid): (u32, u32),
        size: u64,
        mtime: u64,
        link: &[u8],
    ) {
        assert!(path.len() <= 100, "a fixture path fits the name field");
        assert!(link.len() <= 100, "a fixture link fits the linkname field");
        let mut block = [0u8; 512];
        block[..path.len()].copy_from_slice(path);
        octal(&mut block[100..108], u64::from(mode));
        octal(&mut block[108..116], u64::from(uid));
        octal(&mut block[116..124], u64::from(gid));
        octal(&mut block[124..136], size);
        octal(&mut block[136..148], mtime);
        block[156] = typeflag;
        block[157..157 + link.len()].copy_from_slice(link);
        if !self.v7 {
            block[257..263].copy_from_slice(b"ustar\0");
            block[263..265].copy_from_slice(b"00");
            if let Some((uname, gname)) = &self.names {
                assert!(
                    uname.len() < 32 && gname.len() < 32,
                    "a fixture owner name fits its field",
                );
                block[265..265 + uname.len()].copy_from_slice(uname.as_bytes());
                block[297..297 + gname.len()].copy_from_slice(gname.as_bytes());
            }
        }
        // The checksum is computed with its own field read as spaces, which is
        // the format's own rule.
        let sum: u64 = block
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                if (148..156).contains(&i) {
                    u64::from(b' ')
                } else {
                    u64::from(*byte)
                }
            })
            .sum();
        octal(&mut block[148..156], sum);
        self.data.extend_from_slice(&block);
    }
}

/// A pax record: `"<length> <key>=<value>\n"`, where the decimal length counts
/// the whole record, its own digits included. That is a fixed point, reached by
/// iteration.
pub fn pax_record(key: &str, value: &str) -> String {
    let content = format!(" {key}={value}\n");
    let mut length = content.len();
    loop {
        let total = length.to_string().len() + content.len();
        if total == length {
            break;
        }
        length = total;
    }
    format!("{length}{content}")
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
