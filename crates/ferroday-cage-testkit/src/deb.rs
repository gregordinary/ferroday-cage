//! Hermetic Debian fixtures: `ar` archives, `.deb` packages, and an unsigned
//! `file://` repository with correct digests, so the Debian provisioner can be
//! tested end to end without a network.
//!
//! The archive writers need nothing. The repository needs SHA-256 for the
//! digests its index states, which is this crate's `hex` feature.

#[cfg(feature = "hex")]
use std::path::Path;

#[cfg(feature = "hex")]
use crate::hex::sha256_hex;
use crate::tar::Tar;

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
        // Members are two-byte aligned.
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

/// Builds a `.deb` from an uncompressed `data.tar` payload and an empty
/// `control.tar`.
pub fn deb(data_tar: &[u8]) -> Vec<u8> {
    package(&Tar::new().finish(), data_tar)
}

/// Builds a `.deb` whose `control.tar` holds `./control` with `control` as its
/// text, for a test that reads the package's control stanza back.
pub fn deb_with_control(control: &str, data_tar: &[u8]) -> Vec<u8> {
    let control_tar = Tar::new()
        .file("./control", 0o644, control.as_bytes())
        .finish();
    package(&control_tar, data_tar)
}

/// A `.deb` from its two uncompressed members.
fn package(control_tar: &[u8], data_tar: &[u8]) -> Vec<u8> {
    ar(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar", control_tar),
        ("data.tar", data_tar),
    ])
}

/// One package in a fixture repository.
#[cfg(feature = "hex")]
pub struct Pkg {
    /// The `Package` field.
    pub name: String,
    /// The `Version` field.
    pub version: String,
    /// The `.deb` bytes the index's `Size` and `SHA256` are taken from.
    pub deb: Vec<u8>,
    /// The `Depends` field, empty where the package declares none.
    pub depends: String,
    /// The `Priority` field, empty where the package declares none.
    pub priority: String,
    /// Whether the package declares `Essential: yes`.
    pub essential: bool,
    /// The `Provides` field, when the package declares one.
    pub provides: String,
    /// The `Architecture` field, when it is not the repository's own.
    pub architecture: Option<String>,
}

#[cfg(feature = "hex")]
impl Pkg {
    /// A required package (in the base seed) with the given payload.
    pub fn required(name: &str, deb: Vec<u8>, depends: &str) -> Pkg {
        Pkg {
            priority: "required".to_string(),
            ..Pkg::ordinary(name, deb)
        }
        .depending_on(depends)
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
            provides: String::new(),
            architecture: None,
        }
    }

    /// The same package with a `Depends` field.
    pub fn depending_on(mut self, depends: &str) -> Pkg {
        self.depends = depends.to_string();
        self
    }

    /// The same package declaring `Provides`, so a virtual name resolves to it.
    pub fn providing(mut self, provides: &str) -> Pkg {
        self.provides = provides.to_string();
        self
    }

    /// The same package published for another architecture, which the
    /// repository's own index still lists.
    pub fn for_architecture(mut self, architecture: &str) -> Pkg {
        self.architecture = Some(architecture.to_string());
        self
    }
}

/// Writes an unsigned repository into `dir`.
///
/// The mirror URL is the caller's to make, with the library's
/// `provision::file_url`: it needs a provisioner feature of the library, and
/// this crate enables none (see the crate documentation).
#[cfg(feature = "hex")]
pub fn write_repo(dir: &Path, suite: &str, arch: &str, packages: &[Pkg]) {
    let dists = dir.join(format!("dists/{suite}"));
    let binary = dists.join(format!("main/binary-{arch}"));
    std::fs::create_dir_all(&binary).unwrap();
    std::fs::create_dir_all(dir.join("pool")).unwrap();

    let mut index = String::new();
    for package in packages {
        // A package published for another architecture still appears in this
        // index; the reader is what filters it out.
        let listed = package.architecture.as_deref().unwrap_or(arch);
        let filename = format!("pool/{}_{}_{listed}.deb", package.name, package.version);
        std::fs::write(dir.join(&filename), &package.deb).unwrap();
        index.push_str(&format!(
            "Package: {}\nVersion: {}\nArchitecture: {listed}\nFilename: {filename}\n\
             Size: {}\nSHA256: {}\n",
            package.name,
            package.version,
            package.deb.len(),
            sha256_hex(&package.deb),
        ));
        if !package.depends.is_empty() {
            index.push_str(&format!("Depends: {}\n", package.depends));
        }
        if !package.provides.is_empty() {
            index.push_str(&format!("Provides: {}\n", package.provides));
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
}
