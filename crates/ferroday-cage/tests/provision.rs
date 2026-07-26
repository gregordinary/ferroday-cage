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
}

impl TarBuilder {
    fn new() -> Self {
        TarBuilder { data: Vec::new() }
    }

    /// Appends a 512-byte ustar header. `path` and `link` are written
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
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
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
    let text = format!("{value:0width$o}", width = field.len() - 1);
    assert!(text.len() < field.len(), "octal value fits the field");
    field[..text.len()].copy_from_slice(text.as_bytes());
    field[text.len()] = 0;
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
fn writes_through_escaping_symlinks_are_rejected() {
    // The classic: plant a symlink pointing out of the tree, then write
    // a file through it. The symlink itself extracts (it is data); the
    // write through it must be stopped by the kernel.
    for (name, target) in [("relative", "../../outside"), ("absolute", "/tmp")] {
        let mut tar = TarBuilder::new();
        tar.symlink("esc", target)
            .file("esc/pwn", 0o644, b"escaped");
        let err = provision_err(&format!("attack-symlink-{name}"), &tar.finish());
        assert!(
            matches!(err, ProvisionError::EntryUnsafe { .. }),
            "{name}: {err}"
        );
    }
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
fn hardlinks_resolved_through_escaping_symlinks_are_rejected() {
    // A hardlink whose target path passes through an out-of-tree symlink:
    // the target resolution itself must be contained.
    let mut tar = TarBuilder::new();
    tar.symlink("esc", "/etc").hardlink("grab", "esc/passwd");
    let err = provision_err("attack-hardlink-symlink", &tar.finish());
    assert!(matches!(err, ProvisionError::EntryUnsafe { .. }), "{err}");
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

    fs::remove_dir_all(&dir).unwrap();
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

    fs::remove_dir_all(&dir).unwrap();
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

    fs::remove_dir_all(&dir).unwrap();
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

    fs::remove_dir_all(&dir).unwrap();
}
