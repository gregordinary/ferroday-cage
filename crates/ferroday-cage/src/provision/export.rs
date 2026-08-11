//! Ownership-preserving rootfs export: write a provisioned tree to a POSIX/pax
//! tar whose entries carry the ownership the rootfs intends.
//!
//! A range-mapped sandbox writes real ownership, so the finished tree holds
//! files stored on the host at offset subordinate ids: a file the rootfs means
//! as uid 42 is owned `100000 + 42`. A host-side `tar` would record the offset
//! id, and could not read the `security.*` xattrs a setcap'd binary carries at
//! all. [`export_tar`] instead re-enters the identity map the tree was built
//! under — the machinery [`provision::remove`](super::remove) already runs —
//! so a forked child reads every entry as root of the mapped namespace, where
//! the ids and xattrs are its own.
//!
//! The child ([`mechanism::export`](crate::mechanism)) does only the
//! privileged, in-map reads and streams a flat frame protocol to this module,
//! which runs in ordinary `std` context. Here the frames are reassembled into
//! paths, hardlinks are coalesced by `(device, inode)`, and the pax/ustar
//! archive is encoded — all the heap-bearing work the post-fork child cannot
//! do. The encoder is hand-rolled, symmetric with the [reader](super::tar),
//! and adds no tar dependency.

use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::identity::compose_child_map;
use super::tar::{
    BLOCK, MAX_USTAR_MTIME, MAX_USTAR_NAME, MAX_USTAR_PREFIX, MAX_USTAR_SIZE, pad, ustar_block,
};
use super::{Delegate, ProvisionError};
use crate::mechanism::{
    ExportStep, FRAME_DIR, FRAME_END, FRAME_ERROR, FRAME_FILE, FRAME_LEAVE, FRAME_SYMLINK,
    StartError, kill_export, start_export,
};
use crate::{IdMapper, IdentityMap};

/// An ownership-preserving rootfs export, configured then written.
///
/// The archive is the range-map-correct equivalent of `tar -C rootfs .` run
/// inside the sandbox's user namespace: a file a subordinate-mapped bootstrap
/// chowned to a system id appears at that id, not the host subordinate id it is
/// stored as, and a setcap'd binary's `security.capability` xattr survives.
/// Regular files, directories, symlinks, and hardlinks are emitted, with their
/// mode, ownership, and modification time. Extended attributes are emitted for
/// everything but symlinks — ACLs and file capabilities included — since the
/// kernel confines a symlink's attributes to the `security` and `trusted`
/// namespaces, which an unprivileged export can neither read in full nor an
/// unprivileged extraction restore. Character and block devices, FIFOs, and
/// sockets are skipped, as a deployed image's runtime provides its own.
///
/// Entries are emitted in sorted order — directory children by name, extended
/// attributes by name — so the output does not depend on the order the source
/// filesystem stores entries in. With [`clamp_mtime`](Self::clamp_mtime) set,
/// the archive is byte-reproducible given the tree.
///
/// [`export_tar`] is the shorthand for the common case.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
/// use ferroday_cage::IdentityMap;
/// use ferroday_cage::provision::Export;
///
/// let mut archive = Vec::new();
/// Export::new("/var/lib/myapp/rootfs")
///     .map(IdentityMap::Subordinate)
///     .clamp_mtime(1_700_000_000)
///     .write_to(&mut archive)?;
/// # Ok(())
/// # }
/// ```
pub struct Export<'a> {
    rootfs: PathBuf,
    map: IdentityMap,
    mapper: Option<&'a dyn IdMapper>,
    clamp_mtime: Option<i64>,
}

impl fmt::Debug for Export<'_> {
    /// Renders every setting, and the mapper by its presence rather than its
    /// contents: it is a caller's trait object, with nothing useful to show.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Export")
            .field("rootfs", &self.rootfs)
            .field("map", &self.map)
            .field(
                "mapper",
                &self.mapper.as_ref().map(|_| Delegate("dyn IdMapper")),
            )
            .field("clamp_mtime", &self.clamp_mtime)
            .finish()
    }
}

impl<'a> Export<'a> {
    /// Returns an export of the finished rootfs at `rootfs`.
    ///
    /// The identity map defaults to [`IdentityMap::Single`], under which the
    /// in-map child writes its own one-id map and every entry is recorded as
    /// root — the identity a single-mapped sandbox ran everything as.
    pub fn new(rootfs: impl AsRef<Path>) -> Export<'a> {
        Export {
            rootfs: rootfs.as_ref().to_path_buf(),
            map: IdentityMap::Single,
            mapper: None,
            clamp_mtime: None,
        }
    }

    /// Sets the identity map the tree was built under.
    ///
    /// It must be the map the tree was built under. Naming it, rather than
    /// resolving the subordinate chain internally, is deliberate: a bootstrap
    /// done under an explicit [`IdentityMap::Ranges`] must be exported through
    /// the identical map, or the host subordinate ids will not round-trip to
    /// the ids the tree was built with.
    pub fn map(mut self, map: IdentityMap) -> Export<'a> {
        self.map = map;
        self
    }

    /// Exports through a caller-supplied identity-map delegate, for a tree
    /// built under [`CageBuilder::id_mapper`].
    ///
    /// Without one, the export resolves the bundled delegate chain, which
    /// covers a [`Subordinate`](IdentityMap::Subordinate) tree and a
    /// bundled-delegate [`Ranges`](IdentityMap::Ranges) one. A tree whose
    /// ownership a site-specific mapper established — one allocating ids the
    /// bundled delegates would not — must be exported through that same mapper,
    /// so its ids round-trip. The mapper and the [`map`](Self::map) must be the
    /// pair the tree was built under; a [`Single`](IdentityMap::Single) map
    /// self-establishes and ignores the mapper, as the launch does.
    ///
    /// [`CageBuilder::id_mapper`]: crate::CageBuilder::id_mapper
    pub fn mapper(mut self, mapper: &'a dyn IdMapper) -> Export<'a> {
        self.mapper = Some(mapper);
        self
    }

    /// Caps every recorded modification time at `epoch`, a `SOURCE_DATE_EPOCH`
    /// ceiling in Unix seconds.
    ///
    /// Each entry's time is recorded as `min(mtime, epoch)`, pulling a
    /// bootstrap's wall-clock stamps down to the epoch while preserving any
    /// intrinsically earlier time. Unset, the real time is recorded and the
    /// archive is not byte-reproducible across runs.
    pub fn clamp_mtime(mut self, epoch: i64) -> Export<'a> {
        self.clamp_mtime = Some(epoch);
        self
    }

    /// Writes the archive to `writer`.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::ExportUnprivileged`] when the tree needs a range map
    /// and no delegate can establish one; [`ProvisionError::Io`] for a failure
    /// of the export machinery, of the in-map reader, or of `writer`.
    pub fn write_to<W: Write>(self, writer: W) -> Result<(), ProvisionError> {
        export_inner(
            &self.rootfs,
            writer,
            &self.map,
            self.mapper,
            self.clamp_mtime,
        )
    }
}

/// Writes the finished rootfs at `rootfs` to `writer` as a POSIX/pax tar whose
/// entries carry the ownership the rootfs intends, read from inside the
/// identity `map` that produced it.
///
/// The shorthand for [`Export`], carrying only the inputs every export needs.
/// Reach for the builder to clamp modification times, or to name a
/// caller-supplied identity-map delegate.
///
/// # Errors
///
/// As [`Export::write_to`].
pub fn export_tar<W: Write>(
    rootfs: impl AsRef<Path>,
    writer: W,
    map: IdentityMap,
) -> Result<(), ProvisionError> {
    Export::new(rootfs).map(map).write_to(writer)
}

/// Exports `rootfs`, resolving a range map through `mapper` when given and the
/// bundled delegate chain otherwise.
fn export_inner<W: Write>(
    rootfs: &Path,
    writer: W,
    map: &IdentityMap,
    mapper: Option<&dyn IdMapper>,
    clamp_mtime: Option<i64>,
) -> Result<(), ProvisionError> {
    let rootfs_c = CString::new(rootfs.as_os_str().as_bytes()).map_err(|_| {
        ProvisionError::io(
            "exporting",
            rootfs,
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;

    let source =
        compose_child_map(map, mapper).map_err(|reason| ProvisionError::ExportUnprivileged {
            path: rootfs.to_path_buf(),
            reason,
        })?;

    let child = match start_export(&rootfs_c, source.child_map()) {
        Ok(child) => child,
        Err(StartError::Spawn(errno)) => {
            return Err(ProvisionError::io("exporting", rootfs, errno.into()));
        }
        // The child's own account of what stopped it, reported exactly as the
        // same failure arriving mid-walk as a `FRAME_ERROR` would be.
        Err(StartError::Reported { step, errno }) => {
            return Err(ProvisionError::io(step.describe(), rootfs, errno.into()));
        }
        Err(StartError::Map(err)) => {
            return Err(ProvisionError::ExportUnprivileged {
                path: rootfs.to_path_buf(),
                reason: err.to_string(),
            });
        }
    };

    let result = drive(child.stream(), writer, rootfs, clamp_mtime);

    // Reap the child regardless. A walk failure already surfaced as a frame; a
    // failure to reap is not worth masking the export's own outcome.
    if result.is_err() {
        kill_export(&child);
    }
    let _ = child.finish();
    result
}

/// Reads the child's frame stream and encodes the archive into `writer`.
fn drive<W: Write>(
    stream: BorrowedFd<'_>,
    writer: W,
    rootfs: &Path,
    clamp_mtime: Option<i64>,
) -> Result<(), ProvisionError> {
    // The stream is duplicated so it can be owned by a buffered reader while the
    // child retains its own descriptor for reaping.
    let dup = rustix::io::dup(stream)
        .map_err(|errno| ProvisionError::io("exporting", rootfs, errno.into()))?;
    let mut reader = BufReader::new(std::fs::File::from(dup));
    let mut tar = TarWriter::new(BufWriter::new(writer), clamp_mtime);

    let read_err = |e: io::Error| ProvisionError::io("reading the exported tree", rootfs, e);
    let write_err = |e: io::Error| ProvisionError::io("writing the archive", rootfs, e);

    loop {
        let tag = match read_u8(&mut reader) {
            Ok(tag) => tag,
            Err(e) => return Err(read_err(e)),
        };
        match tag {
            FRAME_DIR => {
                let meta = read_meta(&mut reader, false).map_err(read_err)?;
                tar.enter_dir(&meta).map_err(write_err)?;
            }
            FRAME_FILE => {
                let meta = read_meta(&mut reader, true).map_err(read_err)?;
                tar.file(&meta, &mut reader)
                    .map_err(|e| classify(e, read_err, write_err))?;
            }
            FRAME_SYMLINK => {
                let meta = read_symlink(&mut reader).map_err(read_err)?;
                tar.symlink(&meta).map_err(write_err)?;
            }
            FRAME_LEAVE => tar.leave_dir(),
            FRAME_END => {
                tar.finish().map_err(write_err)?;
                return Ok(());
            }
            FRAME_ERROR => {
                let (step, errno) = read_error(&mut reader).map_err(read_err)?;
                let Some(step) = ExportStep::from_wire(step) else {
                    // The child is this same build, so a step it does not
                    // carry means the stream is malformed rather than newer.
                    return Err(read_err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected export failure step {step}"),
                    )));
                };
                return Err(ProvisionError::io(
                    step.describe(),
                    rootfs,
                    io::Error::from_raw_os_error(errno),
                ));
            }
            other => {
                return Err(read_err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected export frame tag {other}"),
                )));
            }
        }
    }
}

/// Distinguishes a read failure (the stream half of a file copy) from a write
/// failure (the archive half), so each is attributed correctly.
fn classify(
    e: CopyError,
    read_err: impl Fn(io::Error) -> ProvisionError,
    write_err: impl Fn(io::Error) -> ProvisionError,
) -> ProvisionError {
    match e {
        CopyError::Read(e) => read_err(e),
        CopyError::Write(e) => write_err(e),
    }
}

/// One entry's metadata, decoded from a frame.
struct Meta {
    name: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    size: u64,
    dev: u64,
    ino: u64,
    nlink: u64,
    link_target: Vec<u8>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Encodes the frame stream into a tar, maintaining the path stack and the
/// hardlink table the post-fork child could not.
struct TarWriter<W: Write> {
    out: W,
    /// Directory name components from the root to the current directory.
    stack: Vec<Vec<u8>>,
    /// The recorded path of the first link seen for each `(device, inode)` with
    /// more than one link, so a later link coalesces onto it.
    hardlinks: HashMap<(u64, u64), Vec<u8>>,
    /// A `SOURCE_DATE_EPOCH` ceiling in Unix seconds. An entry's modification
    /// time is recorded as `min(mtime, epoch)`; `None` records the real time.
    epoch: Option<i64>,
}

impl<W: Write> TarWriter<W> {
    fn new(out: W, epoch: Option<i64>) -> TarWriter<W> {
        TarWriter {
            out,
            stack: Vec::new(),
            hardlinks: HashMap::new(),
            epoch,
        }
    }

    /// Clamps a modification time to the configured epoch: the
    /// reproducible-builds `SOURCE_DATE_EPOCH` rule, a ceiling that leaves a time
    /// already at or before the epoch untouched.
    fn clamp(&self, mtime: i64) -> i64 {
        match self.epoch {
            Some(epoch) => mtime.min(epoch),
            None => mtime,
        }
    }

    /// The path of a child named `name` in the current directory.
    fn child_path(&self, name: &[u8]) -> Vec<u8> {
        if self.stack.is_empty() {
            return name.to_vec();
        }
        let mut path = self.stack.join(&b'/');
        path.push(b'/');
        path.extend_from_slice(name);
        path
    }

    /// Emits a directory entry and descends: later frames name its children
    /// until the matching [`leave_dir`](Self::leave_dir).
    fn enter_dir(&mut self, meta: &Meta) -> io::Result<()> {
        let mut path = self.child_path(&meta.name);
        self.stack.push(meta.name.clone());
        path.push(b'/');
        self.write_entry(&path, b'5', meta, 0, &[], &meta.xattrs)
    }

    /// Ascends out of the current directory.
    fn leave_dir(&mut self) {
        self.stack.pop();
    }

    /// Emits a file entry: a full regular file the first time its inode is
    /// seen, a hardlink onto the first path afterward. The `size` bytes of data
    /// the child streams are copied to the archive for a regular file and
    /// discarded for a coalesced hardlink, so the stream stays in step either
    /// way.
    fn file(&mut self, meta: &Meta, reader: &mut impl Read) -> Result<(), CopyError> {
        let path = self.child_path(&meta.name);
        if meta.nlink > 1 {
            if let Some(first) = self.hardlinks.get(&(meta.dev, meta.ino)) {
                let first = first.clone();
                self.write_entry(&path, b'1', meta, 0, &first, &meta.xattrs)
                    .map_err(CopyError::Write)?;
                discard(reader, meta.size)?;
                return Ok(());
            }
            self.hardlinks.insert((meta.dev, meta.ino), path.clone());
        }
        self.write_entry(&path, b'0', meta, meta.size, &[], &meta.xattrs)
            .map_err(CopyError::Write)?;
        copy_data(reader, &mut self.out, meta.size)?;
        pad(&mut self.out, meta.size).map_err(CopyError::Write)
    }

    /// Emits a symlink entry.
    fn symlink(&mut self, meta: &Meta) -> io::Result<()> {
        let path = self.child_path(&meta.name);
        self.write_entry(&path, b'2', meta, 0, &meta.link_target, &meta.xattrs)
    }

    /// Writes two zero blocks: the archive terminator.
    fn finish(&mut self) -> io::Result<()> {
        self.out.write_all(&[0u8; BLOCK as usize * 2])?;
        self.out.flush()
    }

    /// Writes an entry's header(s): a pax extended header when the ustar fields
    /// cannot hold the path, link target, size, or any extended attribute, then
    /// the ustar header itself.
    fn write_entry(
        &mut self,
        path: &[u8],
        typeflag: u8,
        meta: &Meta,
        size: u64,
        linkname: &[u8],
        xattrs: &[(Vec<u8>, Vec<u8>)],
    ) -> io::Result<()> {
        let mtime = self.clamp(meta.mtime);
        let split = split_name(path);
        let link_fits = linkname.len() <= 100;
        let size_fits = size <= MAX_USTAR_SIZE;
        let mtime_fits = (0..=MAX_USTAR_MTIME).contains(&mtime);

        // Assemble any pax records the ustar header cannot express.
        let mut pax = Vec::new();
        if split.is_none() {
            pax.extend_from_slice(&pax_record(b"path", path));
        }
        if !link_fits {
            pax.extend_from_slice(&pax_record(b"linkpath", linkname));
        }
        if !size_fits {
            pax.extend_from_slice(&pax_record(b"size", size.to_string().as_bytes()));
        }
        if !mtime_fits {
            // A pre-1970 or far-future time the ustar field cannot hold: record
            // the real seconds-since-epoch, negative or large, rather than
            // clamp it silently or abort the whole export on one exotic stamp.
            pax.extend_from_slice(&pax_record(b"mtime", mtime.to_string().as_bytes()));
        }
        for (name, value) in xattrs {
            let mut key = Vec::with_capacity(b"SCHILY.xattr.".len() + name.len());
            key.extend_from_slice(b"SCHILY.xattr.");
            key.extend_from_slice(name);
            pax.extend_from_slice(&pax_record(&key, value));
        }

        if !pax.is_empty() {
            self.write_pax_header(path, mtime, pax.len())?;
            self.out.write_all(&pax)?;
            pad(&mut self.out, pax.len() as u64)?;
        }

        // The ustar header. When a pax record overrides a field, the ustar
        // field holds a truncated form the reader ignores.
        let (name_field, prefix_field) =
            split.unwrap_or((&path[..path.len().min(MAX_USTAR_NAME)], &[][..]));
        let ustar_size = if size_fits { size } else { 0 };
        let link_field = &linkname[..linkname.len().min(MAX_USTAR_NAME)];
        let block = ustar_block(
            name_field,
            prefix_field,
            meta.mode,
            meta.uid,
            meta.gid,
            ustar_size,
            mtime,
            typeflag,
            link_field,
        )?;
        self.out.write_all(&block)
    }

    /// Writes the header of a pax extended-header entry (typeflag `x`).
    fn write_pax_header(&mut self, path: &[u8], mtime: i64, size: usize) -> io::Result<()> {
        // The name is cosmetic — the reader keys on the typeflag — but a
        // path-derived one keeps `tar tvf` legible.
        let mut name = b"PaxHeaders/".to_vec();
        name.extend_from_slice(path);
        let name = &name[..name.len().min(MAX_USTAR_NAME)];
        let block = ustar_block(name, &[], 0o644, 0, 0, size as u64, mtime, b'x', &[])?;
        self.out.write_all(&block)
    }
}

/// A failed file-data copy, tagged with which side failed.
#[derive(Debug)]
enum CopyError {
    Read(io::Error),
    Write(io::Error),
}

/// Copies exactly `n` bytes from the stream to the archive.
fn copy_data(reader: &mut impl Read, out: &mut impl Write, n: u64) -> Result<(), CopyError> {
    let mut remaining = n;
    let mut buf = [0u8; 1 << 16];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        reader
            .read_exact(&mut buf[..want])
            .map_err(CopyError::Read)?;
        out.write_all(&buf[..want]).map_err(CopyError::Write)?;
        remaining -= want as u64;
    }
    Ok(())
}

/// Reads and discards exactly `n` bytes from the stream (a coalesced
/// hardlink's data).
fn discard(reader: &mut impl Read, n: u64) -> Result<(), CopyError> {
    let mut remaining = n;
    let mut buf = [0u8; 1 << 16];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        reader
            .read_exact(&mut buf[..want])
            .map_err(CopyError::Read)?;
        remaining -= want as u64;
    }
    Ok(())
}

/// Splits a path into the ustar `name` and `prefix` fields, joined by an
/// implicit `/`, or `None` when no split fits and a pax `path` record is needed.
fn split_name(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.len() <= MAX_USTAR_NAME {
        return Some((path, &[]));
    }
    // name = path[i+1..] must fit `name`, so i >= len-(MAX_USTAR_NAME+1);
    // prefix = path[..i] must fit `prefix`, so i <= MAX_USTAR_PREFIX. Prefer the
    // largest such split point.
    let lo = path.len().saturating_sub(MAX_USTAR_NAME + 1);
    let hi = path.len().saturating_sub(1).min(MAX_USTAR_PREFIX);
    for i in (lo..=hi).rev() {
        if path[i] == b'/' {
            let (prefix, rest) = (&path[..i], &path[i + 1..]);
            if !rest.is_empty() && rest.len() <= MAX_USTAR_NAME && prefix.len() <= MAX_USTAR_PREFIX
            {
                return Some((rest, prefix));
            }
        }
    }
    None
}

/// Builds a pax extended-header record: `"<len> key=value\n"`, where `len`
/// counts the whole record including its own digits.
fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
    // Everything but the leading length digits: a space, the key, `=`, the
    // value, and a newline.
    let content = 1 + key.len() + 1 + value.len() + 1;
    let mut len = content + 1;
    loop {
        let total = decimal_len(len) + content;
        if total == len {
            break;
        }
        len = total;
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(len.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(key);
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

/// The number of decimal digits in `n`.
fn decimal_len(n: usize) -> usize {
    let mut digits = 1;
    let mut v = n;
    while v >= 10 {
        v /= 10;
        digits += 1;
    }
    digits
}

// Frame decoding: the little-endian shapes the child emits.

fn read_u8(reader: &mut impl Read) -> io::Result<u8> {
    let mut b = [0u8; 1];
    reader.read_exact(&mut b)?;
    Ok(b[0])
}

fn read_u16(reader: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    reader.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    reader.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_i32(reader: &mut impl Read) -> io::Result<i32> {
    let mut b = [0u8; 4];
    reader.read_exact(&mut b)?;
    Ok(i32::from_le_bytes(b))
}

fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    let mut b = [0u8; 8];
    reader.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn read_i64(reader: &mut impl Read) -> io::Result<i64> {
    let mut b = [0u8; 8];
    reader.read_exact(&mut b)?;
    Ok(i64::from_le_bytes(b))
}

/// Reads a `u16`-length-prefixed byte string.
///
/// Named for the shape rather than for this side of the pipe, so it matches the
/// child's `frame::read_bytes_u16` that wrote it. The `Read` bound is what
/// keeps these separate from the child's descriptor-based readers: the archive
/// writer is fed from a reader in the tests as well as from the child's pipe.
fn read_bytes_u16(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let len = read_u16(reader)? as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Reads the xattr block — a count, then each name and its value — and sorts it
/// by name so the emitted `SCHILY.xattr.*` records do not depend on the order
/// the source filesystem lists attributes in.
fn read_xattrs(reader: &mut impl Read) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let count = read_u16(reader)? as usize;
    let mut xattrs = Vec::with_capacity(count);
    for _ in 0..count {
        let name = read_bytes_u16(reader)?;
        let value_len = read_u32(reader)? as usize;
        let mut value = vec![0u8; value_len];
        reader.read_exact(&mut value)?;
        xattrs.push((name, value));
    }
    xattrs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(xattrs)
}

/// Reads a directory or file metadata frame (the tag already consumed).
fn read_meta(reader: &mut impl Read, is_file: bool) -> io::Result<Meta> {
    let name = read_bytes_u16(reader)?;
    let mode = read_u32(reader)?;
    let uid = read_u32(reader)?;
    let gid = read_u32(reader)?;
    let mtime = read_i64(reader)?;
    let (size, dev, ino, nlink) = if is_file {
        (
            read_u64(reader)?,
            read_u64(reader)?,
            read_u64(reader)?,
            read_u64(reader)?,
        )
    } else {
        (0, 0, 0, 0)
    };
    let xattrs = read_xattrs(reader)?;
    Ok(Meta {
        name,
        mode,
        uid,
        gid,
        mtime,
        size,
        dev,
        ino,
        nlink,
        link_target: Vec::new(),
        xattrs,
    })
}

/// Reads a symlink metadata frame (the tag already consumed).
fn read_symlink(reader: &mut impl Read) -> io::Result<Meta> {
    let name = read_bytes_u16(reader)?;
    let mode = read_u32(reader)?;
    let uid = read_u32(reader)?;
    let gid = read_u32(reader)?;
    let mtime = read_i64(reader)?;
    let link_target = read_bytes_u16(reader)?;
    Ok(Meta {
        name,
        mode,
        uid,
        gid,
        mtime,
        size: 0,
        dev: 0,
        ino: 0,
        nlink: 0,
        link_target,
        // A symlink frame carries no attribute block; the child emits none for
        // the reason `Export`'s documentation gives.
        xattrs: Vec::new(),
    })
}

/// Reads an error frame: a step discriminant and an errno.
fn read_error(reader: &mut impl Read) -> io::Result<(u32, i32)> {
    let step = read_u32(reader)?;
    let errno = read_i32(reader)?;
    Ok((step, errno))
}

#[cfg(test)]
mod tests {
    use super::super::tar::TarReader;
    use super::*;

    /// Encodes one entry through a `TarWriter` and parses it back with the
    /// crate's own reader, so the writer is checked against the reader it is
    /// symmetric with.
    fn meta(name: &str, mode: u32, uid: u32, gid: u32) -> Meta {
        Meta {
            name: name.as_bytes().to_vec(),
            mode,
            uid,
            gid,
            mtime: 1_700_000_000,
            size: 0,
            dev: 0,
            ino: 0,
            nlink: 0,
            link_target: Vec::new(),
            xattrs: Vec::new(),
        }
    }

    #[test]
    fn ownership_and_mode_round_trip() {
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None);
            let m = meta("etc", 0o755, 0, 0);
            tar.enter_dir(&m).unwrap();
            let mut f = meta("shadow", 0o640, 0, 42);
            f.size = 5;
            f.nlink = 1;
            tar.file(&f, &mut &b"1234\n"[..]).unwrap();
            tar.leave_dir();
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        let dir = reader.next_entry().unwrap().unwrap();
        assert_eq!(dir.path, b"etc/");
        assert_eq!(dir.typeflag, b'5');
        let file = reader.next_entry().unwrap().unwrap();
        assert_eq!(file.path, b"etc/shadow");
        assert_eq!(file.uid, 0);
        assert_eq!(file.gid, 42);
        assert_eq!(file.mode, 0o640);
        assert_eq!(file.size, 5);
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn a_symlink_round_trips_its_target() {
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None);
            let mut m = meta("sh", 0o777, 0, 0);
            m.link_target = b"bin/busybox".to_vec();
            tar.symlink(&m).unwrap();
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        let link = reader.next_entry().unwrap().unwrap();
        assert_eq!(link.path, b"sh");
        assert_eq!(link.typeflag, b'2');
        assert_eq!(link.link_target, b"bin/busybox");
    }

    #[test]
    fn a_second_link_becomes_a_hardlink() {
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None);
            let mut a = meta("a", 0o644, 0, 0);
            a.size = 3;
            a.dev = 7;
            a.ino = 99;
            a.nlink = 2;
            tar.file(&a, &mut &b"abc"[..]).unwrap();
            let mut b = meta("b", 0o644, 0, 0);
            b.size = 3;
            b.dev = 7;
            b.ino = 99;
            b.nlink = 2;
            tar.file(&b, &mut &b"abc"[..]).unwrap();
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        let first = reader.next_entry().unwrap().unwrap();
        assert_eq!(first.path, b"a");
        assert_eq!(first.typeflag, b'0');
        let second = reader.next_entry().unwrap().unwrap();
        assert_eq!(second.path, b"b");
        assert_eq!(second.typeflag, b'1');
        assert_eq!(second.link_target, b"a");
    }

    #[test]
    fn a_long_path_round_trips_through_a_pax_record() {
        let long = format!("{}/leaf", "d".repeat(200));
        let mut buf = Vec::new();
        {
            let mut tar = TarWriter::new(&mut buf, None);
            let mut f = meta("leaf", 0o644, 0, 0);
            // Bypass the stack to force a path longer than the ustar fields.
            f.name = long.as_bytes().to_vec();
            f.size = 0;
            f.nlink = 1;
            tar.write_entry(long.as_bytes(), b'0', &f, 0, &[], &[])
                .unwrap();
            tar.finish().unwrap();
        }
        let mut reader = TarReader::new(&buf[..]);
        let entry = reader.next_entry().unwrap().unwrap();
        assert_eq!(entry.path, long.as_bytes());
    }

    #[test]
    fn pax_record_length_is_self_counting() {
        // "SCHILY.xattr.security.capability" = 32-byte value, per the spec's
        // self-referential length.
        let record = pax_record(b"path", b"x");
        // "9 path=x\n" — the 9 counts the whole record, itself included.
        assert_eq!(record, b"9 path=x\n");
        // A record whose length crosses a digit boundary still self-counts.
        let value = "y".repeat(90);
        let record = pax_record(b"path", value.as_bytes());
        let space = record.iter().position(|b| *b == b' ').unwrap();
        let declared: usize = std::str::from_utf8(&record[..space])
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(declared, record.len());
    }

    #[test]
    fn split_name_prefers_a_fitting_split() {
        let short = b"etc/passwd";
        assert_eq!(split_name(short), Some((&short[..], &[][..])));
        let long = format!("{}/{}", "a".repeat(120), "b".repeat(50));
        let (name, prefix) = split_name(long.as_bytes()).unwrap();
        assert_eq!(prefix.len(), 120);
        assert_eq!(name.len(), 50);
        // No interior slash within reach: no split.
        let unsplittable = "c".repeat(160);
        assert!(split_name(unsplittable.as_bytes()).is_none());
    }

    #[test]
    fn mtime_clamps_to_the_epoch() {
        // A modification time later than the epoch is pulled down to it; an
        // earlier one is preserved; no epoch records the real time.
        fn exported_mtime(entry_mtime: i64, epoch: Option<i64>) -> i64 {
            let mut buf = Vec::new();
            {
                let mut tar = TarWriter::new(&mut buf, epoch);
                let mut f = meta("f", 0o644, 0, 0);
                f.mtime = entry_mtime;
                f.nlink = 1;
                tar.file(&f, &mut &b""[..]).unwrap();
                tar.finish().unwrap();
            }
            TarReader::new(&buf[..])
                .next_entry()
                .unwrap()
                .unwrap()
                .mtime
        }
        let epoch = 1_600_000_000;
        assert_eq!(exported_mtime(1_700_000_000, Some(epoch)), epoch);
        assert_eq!(exported_mtime(1_500_000_000, Some(epoch)), 1_500_000_000);
        assert_eq!(exported_mtime(1_700_000_000, None), 1_700_000_000);
    }

    #[test]
    fn an_out_of_range_mtime_survives_through_a_pax_record() {
        // A time the ustar field cannot hold — far past 2242, or pre-1970 and
        // negative — is carried in a pax `mtime` record rather than aborting the
        // export or silently clamping to the epoch.
        fn exported_mtime(entry_mtime: i64) -> i64 {
            let mut buf = Vec::new();
            {
                let mut tar = TarWriter::new(&mut buf, None);
                let mut f = meta("f", 0o644, 0, 0);
                f.mtime = entry_mtime;
                f.nlink = 1;
                tar.file(&f, &mut &b""[..]).unwrap();
                tar.finish().unwrap();
            }
            TarReader::new(&buf[..])
                .next_entry()
                .unwrap()
                .unwrap()
                .mtime
        }
        let far_future = MAX_USTAR_MTIME + 1_000;
        assert_eq!(exported_mtime(far_future), far_future);
        assert_eq!(exported_mtime(-100_000), -100_000);
        // A time exactly at the field ceiling still fits the ustar header.
        assert_eq!(exported_mtime(MAX_USTAR_MTIME), MAX_USTAR_MTIME);
    }

    #[test]
    fn xattrs_decode_in_sorted_order() {
        // The child lists attributes in the filesystem's order; the decoder
        // sorts them by name so the emitted records are deterministic.
        let mut frame = Vec::new();
        frame.extend_from_slice(&2u16.to_le_bytes());
        for (name, value) in [(&b"user.zzz"[..], &b"1"[..]), (b"user.aaa", b"2")] {
            frame.extend_from_slice(&(name.len() as u16).to_le_bytes());
            frame.extend_from_slice(name);
            frame.extend_from_slice(&(value.len() as u32).to_le_bytes());
            frame.extend_from_slice(value);
        }
        let xattrs = read_xattrs(&mut &frame[..]).unwrap();
        let names: Vec<&[u8]> = xattrs.iter().map(|(n, _)| n.as_slice()).collect();
        assert_eq!(names, [&b"user.aaa"[..], &b"user.zzz"[..]]);
    }
}
