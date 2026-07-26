//! Shared helpers for the sandbox integration tests.
//!
//! Compiled into each integration-test binary; not every binary uses every
//! helper.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Returns the Alpine minirootfs fixture, or `None` when the host cannot
/// create unprivileged user namespaces and the sandbox tests should skip.
///
/// A skip is always explicit: it is reported on stderr, and setting
/// `FERRODAY_CAGE_REQUIRE_USERNS` turns it into a failure so that CI can
/// assert the sandbox tests actually ran.
pub fn fixture_rootfs() -> Option<&'static Path> {
    if let Some(blocker) = ferroday_cage::host::userns_blocker() {
        assert!(
            std::env::var_os("FERRODAY_CAGE_REQUIRE_USERNS").is_none(),
            "unprivileged user namespaces are required but unavailable: {blocker}"
        );
        eprintln!("skipping: unprivileged user namespaces are unavailable: {blocker}");
        return None;
    }
    Some(fixture())
}

/// Returns whether `/dev/net/tun` is present and openable, the additional
/// host requirement of the native network stack; the tests that need it
/// skip when it is unavailable.
///
/// The skip is always explicit: it is reported on stderr, and setting
/// `FERRODAY_CAGE_REQUIRE_TUN` turns it into a failure so that CI can
/// assert the network-stack tests actually ran.
pub fn tun_available() -> bool {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
    {
        Ok(_) => true,
        Err(err) => {
            assert!(
                std::env::var_os("FERRODAY_CAGE_REQUIRE_TUN").is_none(),
                "/dev/net/tun is required but unavailable: {err}"
            );
            eprintln!("skipping: /dev/net/tun is unavailable: {err}");
            false
        }
    }
}

/// Fetches the fixture once per process and returns the cached rootfs.
///
/// The fixture script downloads and verifies the pinned minirootfs
/// tarball; the rootfs is then provisioned from it through the library's
/// own tarball provisioner, so every integration test also exercises the
/// extraction path. The fixture is shared by every test and must be
/// treated as read-only.
fn fixture() -> &'static Path {
    static ROOTFS: OnceLock<PathBuf> = OnceLock::new();
    ROOTFS.get_or_init(|| {
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alpine-minirootfs.sh");
        let output = Command::new("sh")
            .arg(script)
            .arg(cache_dir())
            .output()
            .expect("failed to run the fixture script");
        assert!(
            output.status.success(),
            "the fixture script failed:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        let path = String::from_utf8(output.stdout).expect("the fixture path is UTF-8");
        let tarball = PathBuf::from(path.trim());
        let name = tarball
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".tar.gz"))
            .expect("the fixture tarball is named *.tar.gz");
        let rootfs = tarball.with_file_name(name);
        ferroday_cage::provision::ensure(
            &rootfs,
            &mut ferroday_cage::provision::Tarball::new(&tarball),
        )
        .expect("the fixture rootfs is provisionable");
        rootfs
    })
}

/// Creates an empty scratch directory for one test, under `target` so
/// `cargo clean` clears it. Any previous run's directory is removed first.
pub fn scratch_dir(name: &str) -> PathBuf {
    let dir = cache_dir().join(format!("scratch-{name}"));
    if dir.exists() {
        force_remove_dir_all(&dir);
        assert!(!dir.exists(), "the previous scratch directory is removable");
    }
    std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
    dir
}

/// Removes a directory tree, restoring traversable permissions as it descends.
///
/// An overlay-rooted cage leaves a mode-`0` `work/work` directory in its work
/// area, which a plain recursive removal cannot read into; a scratch directory
/// that hosted one is otherwise unremovable on the next run. Every entry was
/// created by the test process, so making each directory traversable first lets
/// the removal complete.
fn force_remove_dir_all(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                force_remove_dir_all(&entry.path());
            }
        }
        let _ = std::fs::remove_dir(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

/// Copies the fixture rootfs into a scratch directory, for tests whose
/// sandboxes write into the rootfs (the shared fixture is read-only).
/// Returns `None` when the sandbox tests should skip.
pub fn scratch_rootfs(name: &str) -> Option<PathBuf> {
    let fixture = fixture_rootfs()?;
    let rootfs = scratch_dir(name).join("rootfs");
    let status = Command::new("cp")
        .arg("-a")
        .arg(fixture)
        .arg(&rootfs)
        .status()
        .expect("failed to run cp");
    assert!(status.success(), "copying the fixture rootfs failed");
    Some(rootfs)
}

/// Builders for hermetic Debian fixtures: tar streams, `.deb` archives, and
/// a `file://` repository, all with correct digests, so the Debian
/// provisioner can be tested end to end without a network.
pub mod deb_repo {
    use std::path::Path;

    use sha2::{Digest, Sha256};

    /// A minimal tar stream writer, for a `.deb`'s `data.tar` member. Unlike
    /// the sandbox tests' writer, it records per-entry uid and gid, so the
    /// statoverride derivation can be exercised.
    #[derive(Default)]
    pub struct Tar {
        data: Vec<u8>,
    }

    impl Tar {
        pub fn new() -> Self {
            Tar::default()
        }

        #[allow(clippy::too_many_arguments)]
        fn entry(
            &mut self,
            path: &str,
            typeflag: u8,
            mode: u32,
            uid: u32,
            gid: u32,
            link: &str,
            content: &[u8],
        ) -> &mut Self {
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
            octal(&mut block[148..156], sum);
            self.data.extend_from_slice(&block);
            self.data.extend_from_slice(content);
            let pad = (512 - content.len() % 512) % 512;
            self.data.resize(self.data.len() + pad, 0);
            self
        }

        pub fn file(&mut self, path: &str, mode: u32, content: &[u8]) -> &mut Self {
            self.entry(path, b'0', mode, 0, 0, "", content)
        }

        pub fn file_owned(
            &mut self,
            path: &str,
            mode: u32,
            uid: u32,
            gid: u32,
            content: &[u8],
        ) -> &mut Self {
            self.entry(path, b'0', mode, uid, gid, "", content)
        }

        pub fn dir(&mut self, path: &str, mode: u32) -> &mut Self {
            self.entry(path, b'5', mode, 0, 0, "", b"")
        }

        pub fn symlink(&mut self, path: &str, target: &str) -> &mut Self {
            self.entry(path, b'2', 0o777, 0, 0, target, b"")
        }

        pub fn finish(&self) -> Vec<u8> {
            let mut data = self.data.clone();
            data.resize(data.len() + 1024, 0);
            data
        }
    }

    /// Writes a space-padded, NUL-terminated octal tar field.
    fn octal(field: &mut [u8], value: u64) {
        let text = format!("{value:0width$o}", width = field.len() - 1);
        field[..text.len()].copy_from_slice(text.as_bytes());
    }

    /// Wraps named members in an `ar` archive.
    pub fn ar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (name, data) in members {
            let mut header = [b' '; 60];
            header[..name.len()].copy_from_slice(name.as_bytes());
            let size = data.len().to_string();
            header[48..48 + size.len()].copy_from_slice(size.as_bytes());
            header[58] = b'`';
            header[59] = b'\n';
            out.extend_from_slice(&header);
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    /// Builds a `.deb` from an (uncompressed) `data.tar` payload.
    pub fn deb(data_tar: &[u8]) -> Vec<u8> {
        let control = Tar::new().finish();
        ar(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar", &control),
            ("data.tar", data_tar),
        ])
    }

    /// The lowercase hex SHA-256 of `bytes`.
    pub fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// One package in a fixture repository.
    pub struct Pkg {
        pub name: String,
        pub version: String,
        pub deb: Vec<u8>,
        pub depends: String,
        pub priority: String,
        pub essential: bool,
    }

    impl Pkg {
        /// A required package (in the base seed) with the given payload.
        pub fn required(name: &str, deb: Vec<u8>, depends: &str) -> Pkg {
            Pkg {
                name: name.to_string(),
                version: "1.0".to_string(),
                deb,
                depends: depends.to_string(),
                priority: "required".to_string(),
                essential: false,
            }
        }

        /// An ordinary (non-seed) package with the given payload.
        pub fn ordinary(name: &str, deb: Vec<u8>) -> Pkg {
            Pkg {
                name: name.to_string(),
                version: "1.0".to_string(),
                deb,
                depends: String::new(),
                priority: String::new(),
                essential: false,
            }
        }
    }

    /// Writes an unsigned `file://` repository and returns its mirror URL.
    pub fn write_repo(dir: &Path, suite: &str, arch: &str, packages: &[Pkg]) -> String {
        let dists = dir.join(format!("dists/{suite}"));
        let binary = dists.join(format!("main/binary-{arch}"));
        std::fs::create_dir_all(&binary).unwrap();
        std::fs::create_dir_all(dir.join("pool")).unwrap();

        let mut index = String::new();
        for package in packages {
            let filename = format!("pool/{}_{}_{arch}.deb", package.name, package.version);
            std::fs::write(dir.join(&filename), &package.deb).unwrap();
            index.push_str(&format!(
                "Package: {}\nVersion: {}\nArchitecture: {arch}\nFilename: {filename}\n\
                 Size: {}\nSHA256: {}\n",
                package.name,
                package.version,
                package.deb.len(),
                sha256_hex(&package.deb),
            ));
            if !package.depends.is_empty() {
                index.push_str(&format!("Depends: {}\n", package.depends));
            }
            if !package.priority.is_empty() {
                index.push_str(&format!("Priority: {}\n", package.priority));
            }
            if package.essential {
                index.push_str("Essential: yes\n");
            }
            index.push('\n');
        }
        std::fs::write(binary.join("Packages"), &index).unwrap();

        let release = format!(
            "Suite: {suite}\nArchitectures: {arch}\nComponents: main\n\
             SHA256:\n {} {} main/binary-{arch}/Packages\n",
            sha256_hex(index.as_bytes()),
            index.len(),
        );
        std::fs::write(dists.join("Release"), release).unwrap();

        format!("file://{}", dir.display())
    }
}

/// The fixture cache directory: `FERRODAY_CAGE_FIXTURE_DIR` when set,
/// otherwise a directory inside `target` so `cargo clean` clears it.
fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("FERRODAY_CAGE_FIXTURE_DIR") {
        return PathBuf::from(dir);
    }
    // The test binary lives at target/<profile>/deps/<name>; the fixture
    // cache sits beside the profile directories.
    let exe = std::env::current_exe().expect("the test binary has a path");
    exe.ancestors()
        .nth(3)
        .expect("the test binary lives under target/")
        .join("test-fixtures")
}
