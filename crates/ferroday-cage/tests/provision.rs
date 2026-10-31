//! Integration tests for the tarball provisioner: extraction semantics,
//! compression handling, and containment against hostile archives.
//!
//! Archives are built byte-by-byte by the `TarBuilder` below, so the tests
//! can produce entries no well-behaved tar tool writes — absolute paths,
//! `..` components, links pointing out of the tree.

mod common;

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ferroday_cage::provision::{
    Provision, ProvisionError, ProvisionEvent, ProvisionObserver, Provisioned, Tarball, ensure,
};

/// A byte-level tar writer for test archives.
struct TarBuilder {
    data: Vec<u8>,
    /// Emit pre-POSIX v7 headers: everything past byte 257 left zero, so no
    /// magic, no version, and no prefix field.
    v7: bool,
}

impl TarBuilder {
    fn new() -> Self {
        TarBuilder {
            data: Vec::new(),
            v7: false,
        }
    }

    /// The same writer emitting v7 headers, so one fixture can be produced in
    /// both formats and the two trees compared.
    fn v7() -> Self {
        TarBuilder {
            data: Vec::new(),
            v7: true,
        }
    }

    /// Appends a 512-byte header. `path` and `link` are written
    /// verbatim, unvalidated — that is the point.
    fn header(&mut self, path: &[u8], typeflag: u8, mode: u32, size: u64, mtime: u64, link: &[u8]) {
        assert!(path.len() <= 100, "test paths fit the name field");
        assert!(
            link.len() <= 100,
            "test link targets fit the linkname field"
        );
        let mut block = [0u8; 512];
        block[..path.len()].copy_from_slice(path);
        write_octal(&mut block[100..108], u64::from(mode));
        write_octal(&mut block[108..116], 0); // uid
        write_octal(&mut block[116..124], 0); // gid
        write_octal(&mut block[124..136], size);
        write_octal(&mut block[136..148], mtime);
        block[156] = typeflag;
        block[157..157 + link.len()].copy_from_slice(link);
        if !self.v7 {
            block[257..263].copy_from_slice(b"ustar\0");
            block[263..265].copy_from_slice(b"00");
        }
        let checksum: u64 = block
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    u64::from(b' ')
                } else {
                    u64::from(*b)
                }
            })
            .sum();
        write_octal(&mut block[148..156], checksum);
        self.data.extend_from_slice(&block);
    }

    /// Appends `data` padded to the block boundary.
    fn body(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
        self.data.resize(self.data.len().next_multiple_of(512), 0);
    }

    fn file(&mut self, path: &str, mode: u32, content: &[u8]) -> &mut Self {
        self.file_mtime(path, mode, content, 1_000_000_000)
    }

    fn file_mtime(&mut self, path: &str, mode: u32, content: &[u8], mtime: u64) -> &mut Self {
        self.header(
            path.as_bytes(),
            b'0',
            mode,
            content.len() as u64,
            mtime,
            b"",
        );
        self.body(content);
        self
    }

    fn dir(&mut self, path: &str, mode: u32) -> &mut Self {
        self.header(path.as_bytes(), b'5', mode, 0, 1_000_000_000, b"");
        self
    }

    fn symlink(&mut self, path: &str, target: &str) -> &mut Self {
        self.header(
            path.as_bytes(),
            b'2',
            0o777,
            0,
            1_000_000_000,
            target.as_bytes(),
        );
        self
    }

    fn hardlink(&mut self, path: &str, target: &str) -> &mut Self {
        self.header(
            path.as_bytes(),
            b'1',
            0o644,
            0,
            1_000_000_000,
            target.as_bytes(),
        );
        self
    }

    fn fifo(&mut self, path: &str, mode: u32) -> &mut Self {
        self.header(path.as_bytes(), b'6', mode, 0, 1_000_000_000, b"");
        self
    }

    fn char_device(&mut self, path: &str) -> &mut Self {
        self.header(path.as_bytes(), b'3', 0o666, 0, 1_000_000_000, b"");
        self
    }

    /// A GNU long-name entry followed by the entry it names.
    fn gnu_longname_file(&mut self, path: &str, content: &[u8]) -> &mut Self {
        self.header(b"././@LongLink", b'L', 0, path.len() as u64, 0, b"");
        self.body(path.as_bytes());
        self.header(
            &path.as_bytes()[..path.len().min(100)],
            b'0',
            0o644,
            content.len() as u64,
            0,
            b"",
        );
        self.body(content);
        self
    }

    /// A pax `x` header followed by the entry it describes.
    fn pax_file(&mut self, pax_path: &str, content: &[u8]) -> &mut Self {
        let record = pax_record("path", pax_path);
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
        self.body(content);
        self
    }

    /// Ends the archive with the two-block terminator.
    fn finish(&self) -> Vec<u8> {
        let mut data = self.data.clone();
        data.extend_from_slice(&[0u8; 1024]);
        data
    }
}

/// A pax record: `"%d key=value\n"` where the decimal length counts the
/// whole record, its own digits included — a fixed point reached by
/// iteration.
fn pax_record(key: &str, value: &str) -> String {
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

fn write_octal(field: &mut [u8], value: u64) {
    ferroday_cage_testkit::tar::octal(field, value);
}

/// Writes `archive` to disk and provisions a rootfs from it, returning
/// the rootfs path.
fn provision(name: &str, archive: &[u8]) -> PathBuf {
    let dir = common::scratch_dir(name);
    let tarball = dir.join("archive.tar");
    fs::write(&tarball, archive).unwrap();
    let dest = dir.join("rootfs");
    assert_eq!(
        ensure(&dest, &mut Tarball::new(&tarball)).unwrap(),
        Provisioned::Created
    );
    dest
}

/// Provisions expecting failure, returning the error and asserting the
/// destination was not published.
fn provision_err(name: &str, archive: &[u8]) -> ProvisionError {
    provision_err_at(name, archive).0
}

/// Like [`provision_err`], but also returns the destination the extraction
/// targeted, so a test can check the true location a hostile entry aimed at.
fn provision_err_at(name: &str, archive: &[u8]) -> (ProvisionError, PathBuf) {
    let dir = common::scratch_dir(name);
    let tarball = dir.join("archive.tar");
    fs::write(&tarball, archive).unwrap();
    let dest = dir.join("rootfs");
    let err = ensure(&dest, &mut Tarball::new(&tarball)).unwrap_err();
    assert!(
        !dest.exists(),
        "a failed extraction must not publish a rootfs"
    );
    (err, dest)
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn files_directories_and_modes_extract() {
    let mut tar = TarBuilder::new();
    tar.dir("./", 0o711)
        .dir("locked", 0o555)
        .file("locked/data", 0o640, b"inside a read-only directory")
        .file("bin/tool", 0o4755, b"#!/bin/true\n")
        .file("empty", 0o600, b"");
    let rootfs = provision("extract-basic", &tar.finish());

    assert_eq!(
        fs::read(rootfs.join("locked/data")).unwrap(),
        b"inside a read-only directory"
    );
    assert_eq!(mode_of(&rootfs.join("locked")), 0o555);
    assert_eq!(mode_of(&rootfs.join("locked/data")), 0o640);
    // The setuid bit survives; the implied bin/ directory defaults to 755.
    assert_eq!(mode_of(&rootfs.join("bin/tool")), 0o4755);
    assert_eq!(mode_of(&rootfs.join("bin")), 0o755);
    assert_eq!(fs::read(rootfs.join("empty")).unwrap(), b"");
    // The ./ entry describes the rootfs directory itself.
    assert_eq!(mode_of(&rootfs), 0o711);

    // Make the read-only directory writable again so the next run's
    // scratch cleanup can remove the tree.
    fs::set_permissions(rootfs.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn mtimes_apply_to_files_and_directories() {
    let mut tar = TarBuilder::new();
    tar.dir("d", 0o755)
        .file_mtime("d/f", 0o644, b"content", 1_234_567_890);
    let rootfs = provision("extract-mtime", &tar.finish());

    assert_eq!(
        fs::metadata(rootfs.join("d/f")).unwrap().mtime(),
        1_234_567_890
    );
    // The directory keeps its own (older) time even though its child was
    // written afterward: directory times are applied last.
    assert_eq!(
        fs::metadata(rootfs.join("d")).unwrap().mtime(),
        1_000_000_000
    );
}

#[test]
fn symlinks_store_targets_verbatim() {
    let mut tar = TarBuilder::new();
    tar.symlink("absolute", "/usr/share/zoneinfo/UTC")
        .symlink("relative", "../sibling")
        .file("through/real", 0o644, b"x");
    let rootfs = provision("extract-symlink", &tar.finish());

    assert_eq!(
        fs::read_link(rootfs.join("absolute")).unwrap(),
        Path::new("/usr/share/zoneinfo/UTC")
    );
    // A symlink whose target points out of the tree is data, not a
    // traversal: it extracts verbatim and is never followed.
    assert_eq!(
        fs::read_link(rootfs.join("relative")).unwrap(),
        Path::new("../sibling")
    );
}

#[test]
fn hardlinks_share_the_inode() {
    let mut tar = TarBuilder::new();
    tar.file("original", 0o644, b"shared")
        .hardlink("copy", "original");
    let rootfs = provision("extract-hardlink", &tar.finish());

    let a = fs::metadata(rootfs.join("original")).unwrap();
    let b = fs::metadata(rootfs.join("copy")).unwrap();
    assert_eq!(a.ino(), b.ino());
    assert_eq!(fs::read(rootfs.join("copy")).unwrap(), b"shared");
}

#[test]
fn fifos_extract_devices_and_labels_skip() {
    let mut tar = TarBuilder::new();
    tar.dir("dev", 0o755)
        .char_device("dev/console")
        .fifo("pipe", 0o666)
        .header(b"volume-label", b'V', 0, 0, 0, b"");
    let rootfs = provision("extract-fifo-dev", &tar.finish());

    assert!(
        fs::symlink_metadata(rootfs.join("pipe"))
            .unwrap()
            .file_type()
            .is_fifo()
    );
    assert_eq!(mode_of(&rootfs.join("pipe")), 0o666);
    // The /dev directory extracts; the node inside it does not.
    assert!(rootfs.join("dev").is_dir());
    assert!(!rootfs.join("dev/console").exists());
    assert!(!rootfs.join("volume-label").exists());
}

#[test]
fn later_entries_replace_earlier_ones() {
    let mut tar = TarBuilder::new();
    tar.file("x", 0o644, b"old")
        .file("x", 0o600, b"new")
        .symlink("y", "x")
        .file("y", 0o644, b"now a file");
    let rootfs = provision("extract-replace", &tar.finish());

    assert_eq!(fs::read(rootfs.join("x")).unwrap(), b"new");
    assert_eq!(mode_of(&rootfs.join("x")), 0o600);
    assert!(
        !fs::symlink_metadata(rootfs.join("y"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(rootfs.join("y")).unwrap(), b"now a file");
}

#[test]
fn a_file_entry_landing_on_a_non_empty_directory_is_an_error() {
    // The replacement path removes what is in the way. A non-empty directory
    // cannot be removed, and extraction must say so rather than skip the entry
    // or leave a half-replaced tree: the two differ in what the finished rootfs
    // contains, and only one of them is reportable.
    let mut tar = TarBuilder::new();
    tar.dir("collide", 0o755)
        .file("collide/inside", 0o644, b"occupant")
        .file("collide", 0o644, b"now a file");
    let error = provision_err("extract-onto-non-empty", &tar.finish());
    assert!(
        matches!(error, ProvisionError::Io { .. }),
        "an unremovable obstruction is an I/O failure: {error}",
    );
    assert!(
        error.to_string().contains("collide"),
        "the report names the entry: {error}",
    );
}

#[test]
fn deferred_directory_metadata_does_not_follow_a_replacing_symlink() {
    // A directory records its deferred mode, then, while empty, is replaced by
    // a symlink to another in-tree directory. Finalizing the recorded metadata
    // must not follow that symlink and stamp the archive's mode onto the
    // target: the leaf is no longer the directory it described.
    let mut tar = TarBuilder::new();
    tar.dir("target", 0o755)
        .file("target/keep", 0o644, b"untouched")
        .dir("d", 0o700)
        .symlink("d", "target");
    let rootfs = provision("extract-dir-meta-symlink", &tar.finish());

    // `d` ends as the symlink, and `target` keeps its own mode rather than
    // inheriting `d`'s recorded 0o700.
    assert!(
        fs::symlink_metadata(rootfs.join("d"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(mode_of(&rootfs.join("target")), 0o755);
    assert_eq!(fs::read(rootfs.join("target/keep")).unwrap(), b"untouched");
}

#[test]
fn gnu_long_names_and_pax_paths_apply() {
    let long = format!("deep/{}/leaf", "x".repeat(120));
    let mut tar = TarBuilder::new();
    tar.gnu_longname_file(&long, b"long-name content")
        .pax_file("pax/renamed", b"pax content");
    let rootfs = provision("extract-longname", &tar.finish());

    assert_eq!(fs::read(rootfs.join(&long)).unwrap(), b"long-name content");
    // The pax path record overrides the placeholder header name.
    assert_eq!(
        fs::read(rootfs.join("pax/renamed")).unwrap(),
        b"pax content"
    );
    assert!(!rootfs.join("pax-placeholder").exists());
}

#[test]
fn merged_usr_style_symlink_traversal_extracts() {
    // A tarball from a merged-usr system: bin is a symlink to usr/bin,
    // and later entries pass through it. In-tree traversal must work.
    let mut tar = TarBuilder::new();
    tar.dir("usr", 0o755)
        .dir("usr/bin", 0o755)
        .symlink("bin", "usr/bin")
        .file("bin/sh", 0o755, b"#!");
    let rootfs = provision("extract-merged-usr", &tar.finish());

    assert_eq!(fs::read(rootfs.join("usr/bin/sh")).unwrap(), b"#!");
    assert!(
        fs::symlink_metadata(rootfs.join("bin"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn a_directory_entry_does_not_replace_a_merged_usr_alias() {
    // The merged-usr alias `lib -> usr/lib` is laid first (as a base's
    // base-files ships it), then a later package carries a bare `lib/`
    // directory entry of its own — a kernel image's `/lib/modules`, say. That
    // directory entry must pass through the alias, not replace the symlink with
    // a real directory: the dynamic linker under `usr/lib` is reachable only as
    // `lib/...`, so clobbering the symlink orphans it and nothing dynamically
    // linked in the tree can start.
    let mut tar = TarBuilder::new();
    tar.dir("usr", 0o755)
        .dir("usr/lib", 0o755)
        .symlink("lib", "usr/lib")
        .file("usr/lib/ld.so", 0o755, b"the dynamic linker")
        .dir("lib", 0o755) // the aliased directory entry: must not clobber
        .file("lib/modules/mod", 0o644, b"a kernel module");
    let rootfs = provision("extract-alias-dir", &tar.finish());

    // The alias survives as a symlink.
    assert!(
        fs::symlink_metadata(rootfs.join("lib"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the merged-usr alias must remain a symlink, not become a real directory",
    );
    // The linker is still reachable through it.
    assert_eq!(
        fs::read(rootfs.join("lib/ld.so")).unwrap(),
        b"the dynamic linker",
    );
    // The aliased entry's own child landed under the alias target.
    assert_eq!(
        fs::read(rootfs.join("usr/lib/modules/mod")).unwrap(),
        b"a kernel module",
    );
}

#[test]
fn a_directory_entry_replaces_a_symlink_to_a_nondirectory() {
    // The alias exception is precise: only a symlink resolving in-tree to a
    // directory is preserved. A symlink to a non-directory, or a dangling one,
    // is still replaced by a directory entry, per the tar supersede convention.
    let mut tar = TarBuilder::new();
    tar.file("afile", 0o644, b"a regular file")
        .symlink("to_file", "afile") // resolves to a non-directory
        .symlink("dangling", "nowhere") // resolves to nothing
        .dir("to_file", 0o755)
        .dir("dangling", 0o755)
        .file("to_file/child", 0o644, b"under the replaced link")
        .file("dangling/child", 0o644, b"under the replaced link");
    let rootfs = provision("extract-alias-replace", &tar.finish());

    for name in ["to_file", "dangling"] {
        assert!(
            fs::symlink_metadata(rootfs.join(name))
                .unwrap()
                .file_type()
                .is_dir(),
            "a symlink not resolving to a directory must be replaced by the directory entry ({name})",
        );
        assert_eq!(
            fs::read(rootfs.join(name).join("child")).unwrap(),
            b"under the replaced link",
        );
    }
    // The regular file the first link pointed at is untouched by the replace.
    assert_eq!(fs::read(rootfs.join("afile")).unwrap(), b"a regular file");
}

#[test]
fn gzip_xz_zstd_and_plain_all_extract() {
    use std::io::Write;

    let mut tar = TarBuilder::new();
    tar.dir("d", 0o755)
        .file("d/f", 0o644, b"compressed content");
    let plain = tar.finish();

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&plain).unwrap();
    let gz = gz.finish().unwrap();

    let mut xz =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
    xz.write_all(&plain).unwrap();
    let xz = xz.finish().unwrap();

    let zst = ruzstd::encoding::compress_to_vec(
        plain.as_slice(),
        ruzstd::encoding::CompressionLevel::Fastest,
    );

    for (name, bytes) in [("plain", plain), ("gz", gz), ("xz", xz), ("zst", zst)] {
        let rootfs = provision(&format!("extract-comp-{name}"), &bytes);
        assert_eq!(
            fs::read(rootfs.join("d/f")).unwrap(),
            b"compressed content",
            "format {name}"
        );
    }
}

#[test]
fn a_damaged_check_after_the_archive_ends_is_refused() {
    // Each format closes a compressed stream with a check over the last part
    // of it: a gzip member's CRC, an xz index and footer, a zstd frame's
    // content checksum. The tar terminator sits inside that last part, so a
    // reader stopping at the terminator never compares the check, and a
    // damaged final block would extract as though it were sound. Damaging the
    // check itself leaves every byte the archive decodes to intact, which is
    // what makes it the case only the check can catch.
    use std::io::Write;

    let mut tar = TarBuilder::new();
    tar.file("f", 0o644, b"the last file in the archive");
    let plain = tar.finish();

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&plain).unwrap();
    let gz = gz.finish().unwrap();

    let mut xz =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
    xz.write_all(&plain).unwrap();
    let xz = xz.finish().unwrap();

    let zst = ruzstd::encoding::compress_to_vec(
        plain.as_slice(),
        ruzstd::encoding::CompressionLevel::Fastest,
    );

    // gzip's trailer is the CRC and the length, xz's footer ends with the
    // closing magic, and a zstd frame ends with its checksum.
    for (name, mut bytes, from_end) in [("gz", gz, 8), ("xz", xz, 1), ("zst", zst, 1)] {
        let rootfs = provision(&format!("extract-check-{name}"), &bytes);
        assert_eq!(
            fs::read(rootfs.join("f")).unwrap(),
            b"the last file in the archive",
            "format {name}: the undamaged stream extracts",
        );

        let at = bytes.len() - from_end;
        bytes[at] ^= 0x01;
        let err = provision_err(&format!("extract-check-{name}-damaged"), &bytes);
        assert!(
            matches!(err, ProvisionError::Archive { .. }),
            "format {name}: {err}"
        );
    }
}

#[test]
fn record_padding_after_the_archive_is_read_past_but_more_is_refused() {
    // `tar` pads an archive to whole records, ten kibibytes by default, so
    // zeros after the terminator are ordinary. The stream is read to its end
    // so that a compressed one's closing check is compared, and what follows
    // the terminator is decoded only to be discarded: past a mebibyte of it,
    // the stream is refused rather than decoded on.
    use std::io::Write;

    let gzip = |bytes: &[u8]| {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(bytes).unwrap();
        gz.finish().unwrap()
    };
    let mut tar = TarBuilder::new();
    tar.file("f", 0o644, b"content");

    let mut padded = tar.finish();
    padded.resize(10 * 1024, 0);
    let rootfs = provision("extract-record-padding", &gzip(&padded));
    assert_eq!(fs::read(rootfs.join("f")).unwrap(), b"content");

    let mut overlong = tar.finish();
    overlong.resize(overlong.len() + (1 << 20) + 1, 0);
    let err = provision_err("extract-overlong-trailer", &gzip(&overlong));
    assert!(
        matches!(&err, ProvisionError::Archive { reason, .. } if reason.contains("follow the end")),
        "{err}"
    );
}

/// The fixture the v7 tests extract, written into whichever builder is given.
///
/// A file, a nested directory with a file under it, and a symlink: enough that
/// the two formats' trees can differ if the v7 path reads any field wrong, and
/// nothing that only ustar can express.
fn v7_comparable_fixture(tar: &mut TarBuilder) {
    tar.dir("nested", 0o755)
        .file("nested/data", 0o640, b"under a directory")
        .file("top", 0o644, b"at the root")
        .symlink("alias", "top");
}

#[test]
fn a_v7_archive_extracts_the_tree_a_ustar_one_does() {
    // v7 is the subset: the first 257 bytes are laid out identically and what
    // it lacks is everything after them. So the same fixture in both formats
    // has to produce the same tree, byte for byte and mode for mode -- that is
    // the whole claim the format support makes.
    let mut ustar = TarBuilder::new();
    v7_comparable_fixture(&mut ustar);
    let mut old = TarBuilder::v7();
    v7_comparable_fixture(&mut old);

    let from_ustar = provision("extract-v7-control", &ustar.finish());
    let from_v7 = provision("extract-v7", &old.finish());

    for entry in ["nested", "nested/data", "top", "alias"] {
        let (a, b) = (from_ustar.join(entry), from_v7.join(entry));
        let (ma, mb) = (
            fs::symlink_metadata(&a).unwrap(),
            fs::symlink_metadata(&b).unwrap(),
        );
        assert_eq!(
            ma.file_type(),
            mb.file_type(),
            "{entry} is a different kind"
        );
        assert_eq!(mode_of(&a), mode_of(&b), "{entry} has a different mode");
        if ma.file_type().is_file() {
            assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap(), "{entry}");
        }
        if ma.file_type().is_symlink() {
            assert_eq!(fs::read_link(&a).unwrap(), fs::read_link(&b).unwrap());
        }
    }
}

#[test]
fn an_archive_a_real_tar_wrote_as_v7_extracts() {
    // The fixtures above are written byte by byte, which is what lets this file
    // produce headers no tool would; the cost is that they prove the parser
    // agrees with this file's model of v7 rather than with a producer's. This
    // one closes that gap by asking GNU tar for the archive. It is skipped
    // where `tar` is absent or does not know the format, since the parser's
    // correctness is not conditional on a host tool being installed.
    let dir = common::scratch_dir("extract-v7-real");
    let source = dir.join("source");
    fs::create_dir_all(source.join("nested")).unwrap();
    fs::write(source.join("top"), b"at the root").unwrap();
    fs::write(source.join("nested/data"), b"under a directory").unwrap();
    std::os::unix::fs::symlink("top", source.join("alias")).unwrap();

    let archive = dir.join("v7.tar");
    let made = std::process::Command::new("tar")
        .arg("--format=v7")
        .arg("-cf")
        .arg(&archive)
        .arg("-C")
        .arg(&source)
        .arg(".")
        .status();
    match made {
        Ok(status) if status.success() => {}
        _ => return,
    }

    let dest = dir.join("rootfs");
    assert_eq!(
        ensure(&dest, &mut Tarball::new(&archive)).unwrap(),
        Provisioned::Created
    );
    assert_eq!(fs::read(dest.join("top")).unwrap(), b"at the root");
    assert_eq!(
        fs::read(dest.join("nested/data")).unwrap(),
        b"under a directory"
    );
    assert!(dest.join("nested").is_dir());
    assert_eq!(fs::read_link(dest.join("alias")).unwrap(), Path::new("top"));
}

#[test]
fn a_v7_directory_marked_only_by_a_trailing_slash_extracts_as_one() {
    // An archive old enough to be v7 is old enough to have been written by
    // something that did not set the typeflag reliably, and the convention it
    // used instead was a trailing separator on the name.
    let mut tar = TarBuilder::v7();
    tar.header(b"olddir/", b'0', 0o755, 0, 1_000_000_000, b"");
    tar.file("olddir/inside", 0o644, b"beneath a slash-marked directory");
    let rootfs = provision("extract-v7-trailing-slash", &tar.finish());

    assert!(rootfs.join("olddir").is_dir(), "the entry made a directory");
    assert_eq!(
        fs::read(rootfs.join("olddir/inside")).unwrap(),
        b"beneath a slash-marked directory",
    );
}

#[test]
fn a_v7_entry_is_held_to_the_same_containment_rules() {
    // The rules are properties of the resolved path, not of the header format,
    // so accepting a new format must not open a new way through them.
    let mut absolute = TarBuilder::v7();
    absolute.file("/etc/evil-v7", 0o644, b"outside");
    let err = provision_err("attack-v7-absolute", &absolute.finish());
    assert!(matches!(err, ProvisionError::EntryUnsafe { .. }), "{err}");
    assert!(!Path::new("/etc/evil-v7").exists());

    let mut dotdot = TarBuilder::v7();
    dotdot.file("../escapee-v7", 0o644, b"outside");
    let (err, dest) = provision_err_at("attack-v7-dotdot", &dotdot.finish());
    assert!(matches!(err, ProvisionError::EntryUnsafe { .. }), "{err}");
    let escapee = dest.parent().unwrap().join("escapee-v7");
    assert!(!escapee.exists(), "the dotdot entry escaped to {escapee:?}");

    // A link resolves inside the root as the root resolves it, so one climbing
    // out names the root's own `outside`, which this archive never made: the
    // entry beneath it is refused as one beneath any dangling link is, and
    // nothing lands outside.
    let mut escape = TarBuilder::v7();
    escape
        .symlink("esc", "../../outside")
        .file("esc/pwn", 0o644, b"escaped");
    let (err, dest) = provision_err_at("attack-v7-symlink", &escape.finish());
    assert!(matches!(err, ProvisionError::EntryRefused { .. }), "{err}");
    assert!(!dest.parent().unwrap().join("outside").exists());
}

#[test]
fn a_malformed_archive_is_not_reported_as_an_escape_attempt() {
    // EntryUnsafe asserts that an entry reached outside the extraction root,
    // which is a claim about the caller's input worth keeping true. An archive
    // that ships `foo` as a file and `foo/bar` after it is an ordinary malformed
    // archive, and so is a symlink entry with no target; neither tried to escape
    // anything, and both are refused as what they are.
    let mut through_a_file = TarBuilder::new();
    through_a_file
        .file("foo", 0o644, b"a file, not a directory")
        .file("foo/bar", 0o644, b"beneath it");
    let err = provision_err("malformed-parent-not-a-dir", &through_a_file.finish());
    assert!(matches!(err, ProvisionError::EntryRefused { .. }), "{err}");
    assert!(
        err.to_string().contains("not a directory"),
        "the reason is carried through: {err}",
    );

    let mut empty_target = TarBuilder::new();
    empty_target.symlink("link", "");
    let err = provision_err("malformed-empty-symlink", &empty_target.finish());
    assert!(matches!(err, ProvisionError::EntryRefused { .. }), "{err}");
}

#[test]
fn garbage_is_reported_as_unrecognized() {
    let err = provision_err(
        "extract-garbage",
        b"this is not a tar archive, nor anything else",
    );
    assert!(
        matches!(err, ProvisionError::FormatUnrecognized { .. }),
        "{err}"
    );
}

#[test]
fn an_empty_stream_is_unrecognized_rather_than_published_as_an_empty_rootfs() {
    use std::io::Write;

    // A tar reader tolerates a missing terminator, which is what lets an
    // archive whose last two blocks never arrived still extract. Applied to a
    // stream that ended before its *first* header, the same tolerance reports a
    // complete archive of nothing: `ensure` then publishes the empty staging
    // tree, and every later call answers `Provisioned::Existing` without
    // consulting the source again. A failed producer, an empty download, and a
    // truncated cache entry all arrive as such a stream.
    let err = provision_err("extract-empty-plain", b"");
    assert!(
        matches!(err, ProvisionError::FormatUnrecognized { .. }),
        "{err}"
    );

    // The same holds one layer down: a well-formed compression stream whose
    // decoded payload is empty is not an archive either, and the emptiness is
    // only visible after the decoder has run.
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(b"").unwrap();
    let gz = gz.finish().unwrap();

    let xz = lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1))
        .unwrap()
        .finish()
        .unwrap();

    let zst =
        ruzstd::encoding::compress_to_vec(&b""[..], ruzstd::encoding::CompressionLevel::Fastest);

    for (name, bytes) in [("gz", gz), ("xz", xz), ("zst", zst)] {
        let err = provision_err(&format!("extract-empty-{name}"), &bytes);
        assert!(
            matches!(err, ProvisionError::FormatUnrecognized { .. }),
            "format {name}: {err}"
        );
    }
}

#[test]
fn a_terminated_empty_archive_publishes_an_empty_rootfs() {
    // The counterpart the rejection above must not take with it: two zero
    // blocks are what `tar cf empty.tar --files-from /dev/null` writes, and an
    // archive that says it holds nothing is an archive.
    let rootfs = provision("extract-empty-terminated", &[0u8; 1024]);
    assert_eq!(fs::read_dir(&rootfs).unwrap().count(), 0);
}

#[test]
fn truncation_is_reported_as_malformed() {
    let mut tar = TarBuilder::new();
    tar.file("f", 0o644, b"some content");
    let mut bytes = tar.finish();
    bytes.truncate(600); // inside f's data block
    let err = provision_err("extract-truncated", &bytes);
    assert!(matches!(err, ProvisionError::Archive { .. }), "{err}");
}

#[test]
fn sparse_entries_are_unsupported() {
    let mut tar = TarBuilder::new();
    tar.header(b"sparse-file", b'S', 0o644, 0, 0, b"");
    let err = provision_err("extract-sparse", &tar.finish());
    assert!(
        matches!(err, ProvisionError::EntryUnsupported { kind: b'S', .. }),
        "{err}"
    );
}

#[test]
fn pax_overflowing_sizes_are_rejected() {
    // A pax size in the top block-sized band of the u64 range has no
    // representable block-padded length; the parser must reject it as a
    // malformed archive rather than overflow.
    let record = pax_record("size", &u64::MAX.to_string());
    let mut tar = TarBuilder::new();
    tar.header(b"pax-header", b'x', 0o644, record.len() as u64, 0, b"");
    tar.body(record.as_bytes());
    tar.header(b"victim", b'0', 0o644, 0, 0, b"");
    let err = provision_err("attack-pax-size", &tar.finish());
    assert!(matches!(err, ProvisionError::Archive { .. }), "{err}");
}

#[test]
fn dotdot_paths_are_rejected() {
    let mut tar = TarBuilder::new();
    tar.file("../escapee", 0o644, b"outside");
    let (err, dest) = provision_err_at("attack-dotdot", &tar.finish());
    assert!(matches!(err, ProvisionError::EntryUnsafe { .. }), "{err}");

    // A `..` entry aims at the extraction root's parent — the staging
    // directory's parent, i.e. the destination's parent — so check there, the
    // location the extraction actually used, not an unrelated scratch dir.
    let escapee = dest.parent().unwrap().join("escapee");
    assert!(!escapee.exists(), "the dotdot entry escaped to {escapee:?}");
}

#[test]
fn absolute_paths_are_rejected() {
    let mut tar = TarBuilder::new();
    tar.file("/etc/evil", 0o644, b"outside");
    let err = provision_err("attack-absolute", &tar.finish());
    assert!(matches!(err, ProvisionError::EntryUnsafe { .. }), "{err}");
    assert!(!Path::new("/etc/evil").exists());
}

#[test]
fn writes_through_links_naming_host_paths_stay_in_the_root() {
    // The classic: plant a symlink pointing out of the tree, then write a file
    // through it. The symlink itself extracts (it is data). It resolves as the
    // root filesystem resolves it, inside the root, so the write lands in the
    // root's own path of that name, or is refused where the root holds none.
    for (name, target) in [("relative", "../../outside"), ("absolute", "/tmp")] {
        let mut tar = TarBuilder::new();
        tar.symlink("esc", target)
            .file("esc/pwn", 0o644, b"escaped");
        let (err, dest) = provision_err_at(&format!("attack-symlink-{name}"), &tar.finish());
        assert!(
            matches!(err, ProvisionError::EntryRefused { .. }),
            "{name}: {err}"
        );
        assert!(!dest.parent().unwrap().join("outside").exists(), "{name}");
    }
    assert!(!Path::new("/tmp/pwn").exists());

    // An absolute link to a directory the root holds is a link of the root,
    // and the write goes where the root itself would put it.
    let mut tar = TarBuilder::new();
    tar.dir("tmp", 0o1777)
        .symlink("esc", "/tmp")
        .file("esc/pwn", 0o644, b"in the root");
    let rootfs = provision("symlink-absolute-in-root", &tar.finish());
    assert_eq!(fs::read(rootfs.join("tmp/pwn")).unwrap(), b"in the root");
    assert!(!Path::new("/tmp/pwn").exists());
}

#[test]
fn escaping_hardlink_targets_are_rejected() {
    for (name, target) in [("dotdot", "../outside-file"), ("absolute", "/etc/passwd")] {
        let mut tar = TarBuilder::new();
        tar.hardlink("grab", target);
        let err = provision_err(&format!("attack-hardlink-{name}"), &tar.finish());
        assert!(
            matches!(err, ProvisionError::EntryUnsafe { .. }),
            "{name}: {err}"
        );
    }
}

#[test]
fn hardlinks_resolved_through_links_to_host_paths_stay_in_the_root() {
    // A hardlink whose target path passes through a link naming a host path:
    // the target resolves inside the root, so it names the root's own
    // `etc/passwd`, never the host's. An archive that never made one has
    // nothing there to link to.
    let mut tar = TarBuilder::new();
    tar.symlink("esc", "/etc").hardlink("grab", "esc/passwd");
    provision_err("attack-hardlink-symlink", &tar.finish());

    let mut tar = TarBuilder::new();
    tar.dir("etc", 0o755)
        .file("etc/passwd", 0o644, b"root:x:0:0::/root:/bin/sh\n")
        .symlink("esc", "/etc")
        .hardlink("grab", "esc/passwd");
    let rootfs = provision("hardlink-symlink-in-root", &tar.finish());
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        fs::metadata(rootfs.join("grab")).unwrap().ino(),
        fs::metadata(rootfs.join("etc/passwd")).unwrap().ino(),
    );
}

#[test]
fn provisioned_rootfs_runs_in_a_sandbox() {
    // End to end: provision a rootfs from a generated tarball and run a
    // command inside it. The "userland" is the statically-linked test
    // support binary alone.
    let Some(fixture) = common::fixture_rootfs() else {
        return;
    };

    // Borrow busybox and the musl loader it links against from the
    // fixture rootfs, so the generated tarball is a runnable userland.
    let busybox = fs::read(fixture.join("bin/busybox")).unwrap();
    let loader = fs::read_dir(fixture.join("lib"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_name().to_string_lossy().starts_with("ld-musl-"))
        .expect("the fixture rootfs carries the musl loader");
    let loader_bytes = fs::read(loader.path()).unwrap();
    let loader_path = format!("lib/{}", loader.file_name().to_string_lossy());

    let mut tar = TarBuilder::new();
    tar.dir("bin", 0o755).dir("lib", 0o755);
    tar.header(b"bin/busybox", b'0', 0o755, busybox.len() as u64, 0, b"");
    tar.body(&busybox);
    tar.header(
        loader_path.as_bytes(),
        b'0',
        0o755,
        loader_bytes.len() as u64,
        0,
        b"",
    );
    tar.body(&loader_bytes);
    tar.symlink("bin/cat", "busybox");
    tar.file("etc/greeting", 0o644, b"hello from a provisioned rootfs\n");

    let dir = common::scratch_dir("provision-e2e");
    let tarball = dir.join("rootfs.tar");
    fs::write(&tarball, tar.finish()).unwrap();
    let rootfs = dir.join("rootfs");
    ensure(&rootfs, &mut Tarball::new(&tarball)).unwrap();

    let mut output = Vec::new();
    struct Collect<'a>(&'a mut Vec<u8>);
    impl ferroday_cage::Observer for Collect<'_> {
        fn stdout(&mut self, chunk: &[u8]) {
            self.0.extend_from_slice(chunk);
        }
    }
    let mut observer = Collect(&mut output);
    let status = ferroday_cage::Cage::builder()
        .rootfs(&rootfs)
        .command("/bin/cat")
        .args(["/etc/greeting"])
        .build()
        .unwrap()
        .run_with(&mut observer)
        .unwrap();
    assert!(status.success());
    assert_eq!(output, b"hello from a provisioned rootfs\n");
}

#[test]
fn extraction_reports_entries_and_byte_progress() {
    let mut tar = TarBuilder::new();
    tar.file("./etc/hostname", 0o644, b"cage\n")
        .dir("./usr/", 0o755)
        .file("./usr/marker", 0o600, b"x");
    let archive = tar.finish();

    let dir = common::scratch_dir("observe-progress");
    let source = dir.join("rootfs.tar");
    fs::write(&source, &archive).unwrap();

    #[derive(Default)]
    struct Record {
        entries: Vec<PathBuf>,
        reads: Vec<(u64, Option<u64>)>,
    }

    impl ProvisionObserver for Record {
        fn progress(&mut self, event: ProvisionEvent<'_>) {
            match event {
                ProvisionEvent::Entry { path, .. } => self.entries.push(path.to_path_buf()),
                ProvisionEvent::Read { done, total, .. } => self.reads.push((done, total)),
                _ => {}
            }
        }
    }

    let mut record = Record::default();
    let outcome = Provision::new(dir.join("rootfs"))
        .observe(&mut record)
        .run(&mut Tarball::new(&source))
        .expect("the archive extracts");
    assert_eq!(outcome, Provisioned::Created);

    assert_eq!(
        record.entries,
        [
            PathBuf::from("etc/hostname"),
            PathBuf::from("usr"),
            PathBuf::from("usr/marker"),
        ],
        "every extracted entry is reported, the ./ root excepted"
    );
    // The final report lands at end-of-file with the whole archive counted and
    // the file's own size as the total.
    let (done, total) = *record.reads.last().expect("progress is reported");
    assert_eq!(done, archive.len() as u64);
    assert_eq!(total, Some(archive.len() as u64));

    common::force_remove_dir_all(&dir);
}

#[test]
fn a_cancelled_extraction_leaves_no_destination() {
    let mut tar = TarBuilder::new();
    tar.file("./first", 0o644, b"a")
        .file("./second", 0o644, b"b");
    let archive = tar.finish();

    let dir = common::scratch_dir("observe-cancel");
    let source = dir.join("rootfs.tar");
    fs::write(&source, &archive).unwrap();

    /// Cancels as soon as the first entry has been reported.
    #[derive(Default)]
    struct StopAfterFirst {
        seen: usize,
    }

    impl ProvisionObserver for StopAfterFirst {
        fn progress(&mut self, event: ProvisionEvent<'_>) {
            if matches!(event, ProvisionEvent::Entry { .. }) {
                self.seen += 1;
            }
        }

        fn cancelled(&mut self) -> bool {
            self.seen >= 1
        }
    }

    let dest = dir.join("rootfs");
    let mut observer = StopAfterFirst::default();
    let err = Provision::new(&dest)
        .observe(&mut observer)
        .run(&mut Tarball::new(&source))
        .unwrap_err();
    assert!(matches!(err, ProvisionError::Cancelled), "{err}");
    // A cancelled run is a failed run: the staging tree is removed and the
    // destination never appears.
    assert!(!dest.exists());
    assert!(!dir.join(".rootfs.staging").exists());

    common::force_remove_dir_all(&dir);
}

#[test]
fn a_tarball_extracts_from_a_reader() {
    let mut tar = TarBuilder::new();
    tar.file("./etc/greeting", 0o644, b"from a stream\n");
    let archive = tar.finish();

    let dir = common::scratch_dir("reader-source");
    let dest = dir.join("rootfs");
    let mut tarball = Tarball::from_reader(std::io::Cursor::new(archive));
    assert_eq!(ensure(&dest, &mut tarball).unwrap(), Provisioned::Created);
    assert_eq!(
        fs::read_to_string(dest.join("etc/greeting")).unwrap(),
        "from a stream\n"
    );

    // The stream is spent; a second run says so rather than publishing an
    // empty rootfs.
    let err = ensure(dir.join("second"), &mut tarball).unwrap_err();
    assert!(err.to_string().contains("consumed by an earlier"), "{err}");
    assert!(!dir.join("second").exists());

    common::force_remove_dir_all(&dir);
}

#[test]
fn a_reader_source_reports_progress_without_a_total() {
    let mut tar = TarBuilder::new();
    tar.file("./marker", 0o644, b"x");
    let archive = tar.finish();

    let dir = common::scratch_dir("reader-progress");
    let mut totals: Vec<Option<u64>> = Vec::new();
    let mut sink = |event: ProvisionEvent<'_>| {
        if let ProvisionEvent::Read { total, .. } = event {
            totals.push(total);
        }
    };
    Provision::new(dir.join("rootfs"))
        .observe(&mut sink)
        .run(&mut Tarball::from_reader(std::io::Cursor::new(archive)))
        .expect("the archive extracts");

    assert!(!totals.is_empty(), "a reader source still reports progress");
    assert!(
        totals.iter().all(Option::is_none),
        "a reader's length is unknown, so no total is claimed"
    );

    common::force_remove_dir_all(&dir);
}

/// A single-identity map is worth re-entering too: the tree's ids are the
/// caller's own, but a directory whose mode denies the write the deletion
/// needs refuses the plain path, and root of the mapped namespace holds the
/// `CAP_DAC_OVERRIDE` that clears it.
///
/// The counterpart of the range-mapped removal in the identity tests, and the
/// case that arises without any sandbox at all: an extraction of an archive
/// carrying a read-only directory leaves exactly this shape behind.
#[test]
fn a_single_mapped_removal_clears_a_directory_its_own_mode_locks() {
    if let Some(blocker) = ferroday_cage::host::userns_blocker() {
        assert!(
            std::env::var_os("FERRODAY_CAGE_REQUIRE_USERNS").is_none(),
            "unprivileged user namespaces are required but unavailable: {blocker}"
        );
        eprintln!("skipping: unprivileged user namespaces are unavailable: {blocker}");
        return;
    }

    let dir = common::scratch_dir("single-map-remove");
    let tree = dir.join("tree");
    let locked = tree.join("locked");
    fs::create_dir_all(&locked).expect("the scratch tree is creatable");
    fs::write(locked.join("file"), b"x").expect("the entry is creatable");
    // Readable and searchable but not writable: the entry inside it cannot be
    // unlinked, so the tree cannot be removed by its own owner.
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).expect("the mode is settable");

    // The plain recursive removal is the baseline: the test is about the case
    // where the caller's own attempt is refused.
    #[expect(clippy::disallowed_methods)]
    let plain = fs::remove_dir_all(&tree);
    if plain.is_ok() {
        // A privileged runner overrides the mode outright, leaving nothing for
        // the escalation to do.
        eprintln!("skipping: the caller can remove a mode-0500 directory's contents outright");
        common::force_remove_dir_all(&dir);
        return;
    }

    ferroday_cage::provision::Remove::new(&tree)
        .map(ferroday_cage::IdentityMap::Single)
        .run()
        .expect("the map-assisted removal succeeds");
    assert!(!tree.exists(), "the tree is gone");

    common::force_remove_dir_all(&dir);
}
