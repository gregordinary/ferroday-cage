//! The gpkg container: what a binary package is, and what makes it answer for
//! itself.
//!
//! A `.gpkg.tar` is an uncompressed tar holding six members under one directory:
//!
//! ```text
//! git-2.54.0-6/gpkg-1              zero bytes; the format marker
//! git-2.54.0-6/metadata.tar.xz     the package's own metadata files
//! git-2.54.0-6/metadata.tar.xz.sig a detached signature over it
//! git-2.54.0-6/image.tar.xz        the files that are merged into the root
//! git-2.54.0-6/image.tar.xz.sig    a detached signature over it
//! git-2.54.0-6/Manifest            cleartext-signed; the digests of the rest
//! ```
//!
//! # The Manifest proves authorship, not identity
//!
//! Its lines are `DATA <member> <size> SHA512 <hex> BLAKE2B <hex>`, one per
//! member. **There is no field naming the package.** And the container's
//! directory prefix cannot supply the identity either: GLEP 78 says the name
//! "should" match the file name, and that "the implementation must be able to
//! process an archive where the directory name is mismatched", so a conforming
//! reader cannot treat the prefix as a claim.
//!
//! That leaves a real attack. A hostile mirror that answers a request for one
//! package with a genuine, correctly signed *other* package passes every
//! signature check there is: the bytes were signed by Gentoo, and nothing in
//! the signed material says which package was asked for. So identity is
//! established after verification, from the metadata inside — `CATEGORY`, `PF`
//! and `BUILD_ID` — against the index record the resolution chose. A mismatch
//! is a refusal rather than a warning.
//!
//! This is the same question `debian/index.rs` answers when it checks a pool
//! path out of an already-signed index rather than trusting the signature to
//! have covered it.
//!
//! # The Manifest is last, so verification is two passes
//!
//! GLEP 78 fixes the member order with the Manifest at the end, and requires
//! readers to tolerate a different one. Either way the digests can arrive after
//! the bytes they cover, so a single forward pass cannot verify before
//! extracting.
//!
//! The container is already in a cache, so this costs a second pass over a
//! local file rather than a second fetch. The first reads the whole container,
//! digesting each member as it streams past and buffering only the small ones;
//! the Manifest is verified and compared against what that pass recorded. The
//! second extracts the image, which by then is bytes a signed document vouched
//! for. Nothing is decompressed before its digest matches, which is what GLEP
//! 78 asks of a reader that finds a bad signature.
//!
//! # The cache directory is inside the trust boundary
//!
//! What the two passes establish is that the *bytes the first pass read* were
//! the ones the Manifest vouched for. The second pass opens the file again, so
//! anything able to write the cache between them substitutes content nothing
//! verified into the merge.
//!
//! In normal use nobody else can: the cache is
//! [`cache_dir`](super::GentooBuilder::cache_dir), or a sibling of the tree
//! being built where the caller named none. A caller who points `cache_dir` at a
//! world-writable or shared location is extending the trust boundary to whoever
//! can write there, and is entitled to know that is the decision they are
//! making.
//!
//! # What is deliberately not read
//!
//! The two `.sig` members. The cleartext-signed Manifest binds the same bytes,
//! and this crate implements no detached-signature verification because it has
//! never needed any — the same reason the stage3's `.asc` goes unread. They are
//! digested by the Manifest like every other member, so they are verified *as
//! data* even though they are not used as signatures.
//!
//! BLAKE2B, which sits beside SHA-512 on every line. A second algorithm
//! agreeing with the first buys nothing the first does not already give, and
//! BLAKE2B is not otherwise in this crate.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::Path;

use super::plan::PlannedPackage;
use super::{GentooError, MAX_METADATA_BYTES};
use crate::provision::compress;
use crate::provision::digest::{self, Algorithm};
use crate::provision::openpgp::Keyring;
use crate::provision::tar::TarReader;

/// The member every container must carry, and the marker that says which format
/// it is.
///
/// GLEP 78 says a reader should reject a container without it. It is zero bytes
/// and its whole content is its name.
const FORMAT_MEMBER: &str = "gpkg-1";

/// The member carrying the digests of all the others.
const MANIFEST_MEMBER: &str = "Manifest";

/// The member prefix the metadata archive is named by, before its compression
/// suffix.
const METADATA_MEMBER: &str = "metadata.tar";

/// The member prefix the image archive is named by, before its compression
/// suffix.
const IMAGE_MEMBER: &str = "image.tar";

/// The directory the metadata archive holds its files under.
const METADATA_DIR: &str = "metadata/";

/// The directory the image archive holds the root's files under.
pub(super) const IMAGE_DIR: &str = "image/";

/// The ceiling on the Manifest, which the container declares no size for until
/// the Manifest itself is read.
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

/// A verified container: its metadata, and where its image sits.
///
/// Holding one means the Manifest verified against the vendored keyring, every
/// member matched the size and SHA-512 it recorded, the member set was exactly
/// the one it lists, and the metadata inside names the package the index record
/// named.
///
/// The rendering names its members rather than holding them out: the metadata
/// is a couple of dozen small files and the image is the whole package.
#[derive(Debug)]
pub(super) struct Package {
    /// The metadata files, keyed by their name inside `metadata/`.
    ///
    /// Buffered because they are small — a few kilobytes across a couple of
    /// dozen files — and because the merge writes most of them out again as the
    /// root's own database entry.
    metadata: BTreeMap<String, Vec<u8>>,
    /// The member holding the image archive, with its prefix, so the second
    /// pass can find it again.
    image: Vec<u8>,
}

impl Package {
    /// Opens the container at `path` and holds it to everything above.
    ///
    /// `planned` is what the resolution chose, and what the container's own
    /// metadata is checked against. It is the plan's entry rather than the
    /// index record because both ways of reaching an install go through a plan:
    /// one resolved here, and one a caller kept and handed back.
    ///
    /// # Errors
    ///
    /// Returns [`GentooError::Signature`] where the Manifest does not verify,
    /// [`GentooError::Digest`] where a member is not the bytes it vouched for,
    /// [`GentooError::Container`] for a container that is not one this layer
    /// can read — no format marker, a member the Manifest does not list or one
    /// it lists that is absent, no image or metadata archive, or metadata that
    /// names a different package — and [`GentooError::Io`] where the file could
    /// not be read.
    pub(super) fn open(
        path: &Path,
        planned: &PlannedPackage,
        keyring: &Keyring,
    ) -> Result<Package, GentooError> {
        let scan = scan(path)?;
        let manifest = Manifest::verify(path, &scan, keyring)?;
        manifest.hold(path, &scan)?;
        let metadata = read_metadata(path, &scan)?;
        check_identity(path, planned, &metadata)?;
        Ok(Package {
            metadata,
            image: scan.image.clone(),
        })
    }

    /// Every metadata file, by name, in name order.
    pub(super) fn metadata_files(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.metadata
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
    }

    /// Opens the image archive for reading, decompressed.
    ///
    /// The second pass. Everything it yields was covered by the verified
    /// Manifest, so this is where a caller may act on the container's contents
    /// and the first place it may.
    pub(super) fn image(&self, path: &Path) -> Result<TarReader<Box<dyn Read>>, GentooError> {
        let file = std::fs::File::open(path).map_err(GentooError::at("opening", path))?;
        let mut archive = TarReader::new(io::BufReader::new(file));
        while let Some(entry) = archive
            .next_entry()
            .map_err(|err| container(path, err.to_string()))?
        {
            if entry.path != self.image {
                continue;
            }
            let mut member = Member {
                archive,
                left: entry.size,
            };
            let head = compress::sniff_head(&mut member)
                .map_err(GentooError::at("reading the image archive", path))?;
            let inner = compress::decompress(&head, member)
                .map_err(|err| container(path, err.to_string()))?;
            return Ok(TarReader::new(inner));
        }
        Err(container(
            path,
            "the image archive is no longer in the container it was verified in",
        ))
    }
}

/// A container's members as one pass over it saw them.
struct Scan {
    /// Each member's name, its length, and the SHA-512 of its bytes, in
    /// container order.
    members: Vec<Seen>,
    /// The Manifest's bytes.
    manifest: Vec<u8>,
    /// The image archive's member name, with its prefix, so the second pass
    /// can find it again. The bytes are not held: an image runs to hundreds of
    /// megabytes.
    image: Vec<u8>,
    /// The metadata archive's bytes, still compressed.
    ///
    /// Held from the first pass rather than read again, and held *compressed*:
    /// that is what lets the digest be checked before anything decompresses it,
    /// which is what GLEP 78 asks of a reader. It is a few kilobytes.
    metadata: Vec<u8>,
    /// Whether a metadata archive was seen at all, which an empty one would
    /// otherwise be indistinguishable from.
    has_metadata: bool,
    /// Whether the format marker was present.
    marked: bool,
}

/// One member as the scan saw it.
struct Seen {
    /// The name inside the container's directory, which is what the Manifest
    /// spells.
    name: String,
    size: u64,
    sha512: String,
}

/// Reads the whole container once, digesting every member.
///
/// The prefix is read to find the members and is never trusted as a name: GLEP
/// 78 says a conforming writer may mismatch it, so what it is used for is
/// stripping, and what a member *is* comes from its own name below the prefix.
fn scan(path: &Path) -> Result<Scan, GentooError> {
    let file = std::fs::File::open(path).map_err(GentooError::at("opening", path))?;
    let mut archive = TarReader::new(io::BufReader::new(file));
    let mut scan = Scan {
        members: Vec::new(),
        manifest: Vec::new(),
        image: Vec::new(),
        metadata: Vec::new(),
        has_metadata: false,
        marked: false,
    };
    let mut prefix: Option<Vec<u8>> = None;
    while let Some(entry) = archive
        .next_entry()
        .map_err(|err| container(path, err.to_string()))?
    {
        // Directory entries describe the container's own layout rather than
        // being members of it, and the Manifest does not list them.
        if entry.typeflag == b'5' {
            continue;
        }
        let full = entry.path.clone();
        let Some((held, name)) = split_member(&full) else {
            return Err(container(
                path,
                format!(
                    "holds {:?}, which is not a member of a single directory",
                    String::from_utf8_lossy(&full),
                ),
            ));
        };
        match &prefix {
            None => prefix = Some(held.to_vec()),
            Some(first) if first == held => {}
            Some(first) => {
                return Err(container(
                    path,
                    format!(
                        "holds members under two directories, {:?} and {:?}",
                        String::from_utf8_lossy(first),
                        String::from_utf8_lossy(held),
                    ),
                ));
            }
        }
        let Ok(name) = std::str::from_utf8(name) else {
            return Err(container(path, "holds a member whose name is not UTF-8"));
        };
        let name = name.to_string();

        // The Manifest and the metadata archive are held in memory: the first
        // to verify, the second because the merge writes most of it back out.
        // Both are small and both are bounded, since the container arrives with
        // no length for either until the Manifest has been read.
        let held = match name.as_str() {
            MANIFEST_MEMBER => Some(MAX_MANIFEST_BYTES),
            _ if name.starts_with(METADATA_MEMBER) => Some(MAX_METADATA_BYTES),
            _ => None,
        };
        let mut buffered = Vec::new();
        let mut member = Member {
            archive,
            left: entry.size,
        };
        let (sha512, size) = match held {
            Some(limit) => {
                let taken = io::copy(&mut (&mut member).take(limit), &mut buffered)
                    .map_err(GentooError::at("reading a container member", path))?;
                if taken == limit {
                    return Err(container(
                        path,
                        format!("holds a {name} of more than {limit} bytes"),
                    ));
                }
                (Algorithm::Sha512.hex_of(&buffered), taken)
            }
            None => digest::stream(Algorithm::Sha512, &mut member)
                .map_err(GentooError::at("digesting a container member", path))?,
        };
        archive = member.archive;

        match name.as_str() {
            FORMAT_MEMBER => scan.marked = true,
            MANIFEST_MEMBER => scan.manifest = buffered,
            // A `.sig` is a member like any other here: it is digested by the
            // Manifest and never read as a signature.
            _ if name.starts_with(IMAGE_MEMBER) && !name.ends_with(".sig") => {
                scan.image = full.clone();
            }
            _ if name.starts_with(METADATA_MEMBER) && !name.ends_with(".sig") => {
                scan.metadata = buffered;
                scan.has_metadata = true;
            }
            _ => {}
        }
        scan.members.push(Seen { name, size, sha512 });
    }

    if !scan.marked {
        return Err(container(
            path,
            format!("carries no {FORMAT_MEMBER} member, so it is not a gpkg container"),
        ));
    }
    if scan.manifest.is_empty() {
        return Err(container(
            path,
            format!("carries no {MANIFEST_MEMBER}, so nothing vouches for its members"),
        ));
    }
    if scan.image.is_empty() || !scan.has_metadata {
        return Err(container(
            path,
            "carries no image archive or no metadata archive",
        ));
    }
    Ok(scan)
}

/// Splits a member path into its directory prefix and the name below it.
///
/// A member is exactly one level down. A path with no separator, or with more
/// than one, is not a member of a gpkg container.
fn split_member(path: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = path.iter().position(|byte| *byte == b'/')?;
    let (prefix, rest) = (&path[..at], &path[at + 1..]);
    if prefix.is_empty() || rest.is_empty() || rest.contains(&b'/') {
        return None;
    }
    Some((prefix, rest))
}

/// A container member's data, as a reader bounded by the member's length.
///
/// The tar reader yields a member's bytes through `read_data` and skips the
/// rest at the next entry, so this is what lets a digest and a decompressor see
/// one member as an ordinary stream.
struct Member<R: Read> {
    archive: TarReader<R>,
    left: u64,
}

impl<R: Read> Read for Member<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let got = self
            .archive
            .read_data(&mut buf[..want])
            .map_err(io::Error::other)?;
        self.left -= got as u64;
        Ok(got)
    }
}

/// What the container's Manifest vouches for.
struct Manifest {
    /// Each member's stated length and SHA-512, by name.
    entries: BTreeMap<String, (u64, String)>,
}

impl Manifest {
    /// Verifies the Manifest against the keyring and reads its `DATA` lines.
    fn verify(path: &Path, scan: &Scan, keyring: &Keyring) -> Result<Manifest, GentooError> {
        let subject = format!("the Manifest of {}", path.display());
        let verified = keyring
            .verify(&scan.manifest, true)
            .map_err(|err| GentooError::signature(&subject, err))?;
        let mut entries = BTreeMap::new();
        for line in verified.body.lines() {
            let mut fields = line.split_ascii_whitespace();
            if fields.next() != Some("DATA") {
                // GLEP 74 defines several other line types and a reader is
                // expected to pass over the ones it does not act on. What this
                // layer acts on is `DATA`, and a member the Manifest does not
                // cover with one is caught by the set comparison below rather
                // than by reading a line type this does not understand.
                continue;
            }
            let (Some(name), Some(size)) = (fields.next(), fields.next()) else {
                continue;
            };
            let Ok(size) = size.parse::<u64>() else {
                return Err(container(
                    path,
                    format!("states a length of {size:?} for {name}, which is not a number"),
                ));
            };
            // The digests are `<algorithm> <hex>` pairs and the Manifest states
            // several. SHA-512 is the one read; a pair whose algorithm this
            // layer does not know is stepped over rather than refused, since a
            // Manifest gaining an algorithm is not a Manifest this layer stops
            // being able to read.
            let mut sha512 = None;
            let mut fields = fields.peekable();
            while let (Some(algorithm), Some(hex)) = (fields.next(), fields.next()) {
                if algorithm.eq_ignore_ascii_case("SHA512") {
                    sha512 = Some(hex.to_ascii_lowercase());
                }
            }
            let Some(sha512) = sha512.filter(|hex| Algorithm::Sha512.is_hex(hex)) else {
                return Err(container(
                    path,
                    format!("states no usable SHA-512 for the member {name}"),
                ));
            };
            entries.insert(name.to_string(), (size, sha512));
        }
        if entries.is_empty() {
            return Err(container(
                path,
                "has a Manifest that verified and vouches for no member",
            ));
        }
        Ok(Manifest { entries })
    }

    /// Holds every member the scan saw to what the Manifest states for it.
    ///
    /// The member set is compared both ways. A member the Manifest does not
    /// list is one nothing vouches for, and a member it lists that is absent is
    /// one that was taken away; either is a container that is not the one the
    /// Manifest was written for.
    fn hold(&self, path: &Path, scan: &Scan) -> Result<(), GentooError> {
        for seen in &scan.members {
            // The Manifest does not vouch for itself: it is the thing the
            // signature covers.
            if seen.name == MANIFEST_MEMBER {
                continue;
            }
            let Some((size, sha512)) = self.entries.get(&seen.name) else {
                return Err(container(
                    path,
                    format!(
                        "holds a member {} that its Manifest does not list",
                        seen.name
                    ),
                ));
            };
            if seen.size != *size {
                return Err(container(
                    path,
                    format!(
                        "holds a member {} of {} bytes where its Manifest states {size}",
                        seen.name, seen.size,
                    ),
                ));
            }
            if seen.sha512 != *sha512 {
                return Err(GentooError::Digest {
                    subject: format!("the member {} of {}", seen.name, path.display()),
                    expected: sha512.clone(),
                    actual: seen.sha512.clone(),
                });
            }
        }
        for name in self.entries.keys() {
            if !scan.members.iter().any(|seen| seen.name == *name) {
                return Err(container(
                    path,
                    format!("is missing the member {name} that its Manifest lists"),
                ));
            }
        }
        Ok(())
    }
}

/// Reads the metadata archive the scan buffered, once its digest has held.
///
/// The bytes were kept compressed through the first pass precisely so that this
/// -- the decompression -- happens after the Manifest has vouched for them, and
/// not before.
fn read_metadata(path: &Path, scan: &Scan) -> Result<BTreeMap<String, Vec<u8>>, GentooError> {
    let mut files = BTreeMap::new();
    let mut compressed = scan.metadata.as_slice();
    let head = compress::sniff_head(&mut compressed)
        .map_err(GentooError::at("reading the metadata archive", path))?;
    let inner =
        compress::decompress(&head, compressed).map_err(|err| container(path, err.to_string()))?;
    let mut inner = TarReader::new(inner);
    let mut read = 0u64;
    {
        while let Some(entry) = inner
            .next_entry()
            .map_err(|err| container(path, err.to_string()))?
        {
            if entry.typeflag == b'5' {
                continue;
            }
            let Some(name) = std::str::from_utf8(&entry.path)
                .ok()
                .and_then(|name| name.strip_prefix(METADATA_DIR))
                .filter(|name| !name.is_empty() && !name.contains('/'))
            else {
                // Anything that is not a plain file directly under
                // `metadata/` is not a metadata file, and the layer writes
                // out only what it recognizes.
                continue;
            };
            read += entry.size;
            if read > MAX_METADATA_BYTES {
                return Err(container(
                    path,
                    format!("holds more than {MAX_METADATA_BYTES} bytes of metadata"),
                ));
            }
            let mut bytes = vec![0u8; usize::try_from(entry.size).unwrap_or(usize::MAX)];
            let mut filled = 0;
            while filled < bytes.len() {
                let got = inner
                    .read_data(&mut bytes[filled..])
                    .map_err(|err| container(path, err.to_string()))?;
                if got == 0 {
                    break;
                }
                filled += got;
            }
            bytes.truncate(filled);
            files.insert(name.to_string(), bytes);
        }
    }
    Ok(files)
}

/// Holds the container's own metadata to the index record it was fetched for.
///
/// The step the module documentation argues for: a signature says Gentoo built
/// these bytes, and this says they are the package that was asked for.
fn check_identity(
    path: &Path,
    planned: &PlannedPackage,
    metadata: &BTreeMap<String, Vec<u8>>,
) -> Result<(), GentooError> {
    let field = |name: &str| {
        metadata
            .get(name)
            .map(|bytes| String::from_utf8_lossy(bytes).trim().to_string())
    };
    let (Some(category), Some(pf), Some(build_id)) =
        (field("CATEGORY"), field("PF"), field("BUILD_ID"))
    else {
        return Err(container(
            path,
            "carries no CATEGORY, PF or BUILD_ID, so it cannot say which package it is",
        ));
    };
    // Field by field rather than as one joined string, because where the splits
    // fall is the container's to choose and the joins are ambiguous: a container
    // with `PF = "pkg"` and `BUILD_ID = "1.0-5"` joins to the same text as a
    // planned `pkg`, `1.0`, `5`. Nothing today reaches that — the plan's own
    // version has to parse under the Gentoo grammar, two modules away — but this
    // step is the one thing standing between a correctly signed package and the
    // wrong package, and it should not rest on a property established elsewhere.
    //
    // `PF` is the name and the version with no category and no build id, so it
    // is split at the same place the plan holds the two halves apart.
    let named = format!("{category}/{pf}-{build_id}");
    let wanted = format!("{}-{}-{}", planned.name, planned.version, planned.build_id);
    let matched = planned
        .name
        .split_once('/')
        .is_some_and(|(want_cat, name)| {
            category == want_cat
                && pf
                    .strip_prefix(name)
                    .and_then(|rest| rest.strip_prefix('-'))
                    .is_some_and(|version| version == planned.version)
                && build_id.parse::<u64>() == Ok(planned.build_id)
        });
    if !matched {
        return Err(container(
            path,
            format!(
                "is {named}, and what was asked for is {wanted}; the signature holds and the \
                 package is not the one the index named",
            ),
        ));
    }
    Ok(())
}

/// A container that is not one this layer can read.
fn container(path: &Path, reason: impl Into<String>) -> GentooError {
    GentooError::Container {
        subject: path.display().to_string(),
        reason: reason.into(),
    }
}

/// Building a container, for the tests of this module and of the merge that
/// reads one.
///
/// Beside the tests rather than inside them, for the reason
/// [`openpgp::fixture`](super::super::openpgp::fixture) is: what a merge test
/// needs is a container that is *correct*, and what a container test needs is
/// one bent in a named way, and both are the same builder.
#[cfg(test)]
pub(super) mod fixture {
    use pgp::composed::SignedSecretKey;

    use super::*;
    use crate::provision::digest::hex;
    use crate::provision::openpgp::fixture;
    use crate::provision::tar;

    /// The package every container below claims to be.
    pub(in crate::provision::gentoo) const CPV: &str = "sys-libs/zlib-1.3.2";

    /// A tar archive of `entries`, each a name and its bytes.
    fn tarball(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, body) in entries {
            let typeflag = if name.ends_with('/') { b'5' } else { b'0' };
            let size = if typeflag == b'5' {
                0
            } else {
                body.len() as u64
            };
            out.extend_from_slice(
                &tar::ustar_block(name.as_bytes(), b"", 0o644, 0, 0, size, 0, typeflag, b"")
                    .expect("a ustar header"),
            );
            if size > 0 {
                out.extend_from_slice(body);
                tar::pad(&mut out, size).expect("padding a member");
            }
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    /// The metadata archive a container carries, naming `cpv` at `build_id`.
    fn metadata(cpv: &str, build_id: u64) -> Vec<u8> {
        let (category, package, version) =
            super::super::version::split_cpv(cpv).expect("a fixture CPV");
        metadata_named(
            category,
            &format!("{package}-{version}"),
            &build_id.to_string(),
        )
    }

    /// The same, with the three identity fields spelled out.
    ///
    /// What a test needs to bend where the container's *splits* fall rather
    /// than what it says: `PF` and `BUILD_ID` are the container's own to divide
    /// as it likes, and a test for the identity check has to be able to divide
    /// them somewhere else.
    pub(in crate::provision::gentoo) fn metadata_named(
        category: &str,
        pf: &str,
        build_id: &str,
    ) -> Vec<u8> {
        tarball(&[
            ("metadata/", Vec::new()),
            ("metadata/CATEGORY", format!("{category}\n").into_bytes()),
            ("metadata/PF", format!("{pf}\n").into_bytes()),
            ("metadata/BUILD_ID", build_id.as_bytes().to_vec()),
            ("metadata/SLOT", b"0/1\n".to_vec()),
            ("metadata/USE", b"amd64 minizip\n".to_vec()),
        ])
    }

    /// The image archive a container carries: one directory, one file, one
    /// symbolic link, and a named pipe where `fifo` asks for one.
    ///
    /// The fifo is optional because it is what a package ships rarely and the
    /// merge has to answer for anyway: the layer records portage's own `fif`
    /// line for it and never opens it, where reading it as an ordinary file
    /// would block until something opened the write end -- and inside a
    /// provisioning run nothing will.
    fn image(fifo: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut entries: Vec<(&str, &str, u32, u64, u8)> = vec![
            ("image/", "", 0o755, 0u64, b'5'),
            ("image/usr/", "", 0o755, 0, b'5'),
            ("image/usr/lib/", "", 0o755, 0, b'5'),
            ("image/usr/lib/libz.so.1.3.2", "", 0o755, 4, b'0'),
            ("image/usr/lib/libz.so", "libz.so.1.3.2", 0o777, 0, b'2'),
        ];
        if fifo {
            entries.push(("image/usr/lib/zlib.pipe", "", 0o644, 0, b'6'));
        }
        for (name, target, mode, size, typeflag) in entries {
            out.extend_from_slice(
                &tar::ustar_block(
                    name.as_bytes(),
                    b"",
                    mode,
                    0,
                    0,
                    size,
                    1_700_000_000,
                    typeflag,
                    target.as_bytes(),
                )
                .expect("a ustar header"),
            );
            if size > 0 {
                out.extend_from_slice(b"ELF\n");
                tar::pad(&mut out, size).expect("padding a member");
            }
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    /// How a container is put together, so a test can bend one part of it.
    pub(in crate::provision::gentoo) struct Built {
        /// The container's directory prefix, which GLEP 78 says a reader must
        /// not treat as the package's name.
        pub prefix: String,
        /// The metadata archive's bytes.
        pub metadata: Vec<u8>,
        /// Members to leave out of the Manifest, by name.
        pub unlisted: Vec<&'static str>,
        /// Members to list in the Manifest that the container does not carry.
        pub phantom: Vec<&'static str>,
        /// Whether the format marker is present.
        pub marked: bool,
        /// A member whose recorded SHA-512 is wrong, by name.
        pub corrupt: Option<&'static str>,
        /// Whether the image ships a named pipe beside its ordinary files.
        pub fifo: bool,
    }

    impl Built {
        /// A container that is exactly what it should be.
        pub(in crate::provision::gentoo) fn ordinary() -> Built {
            Built {
                prefix: "zlib-1.3.2-1".to_string(),
                metadata: metadata(CPV, 1),
                unlisted: Vec::new(),
                phantom: Vec::new(),
                marked: true,
                corrupt: None,
                fifo: false,
            }
        }

        /// Writes the container to `path`, signed by `key`.
        pub(in crate::provision::gentoo) fn write(self, path: &Path, key: &SignedSecretKey) {
            let mut members: Vec<(String, Vec<u8>)> = Vec::new();
            if self.marked {
                members.push((FORMAT_MEMBER.to_string(), Vec::new()));
            }
            members.push(("metadata.tar".to_string(), self.metadata));
            members.push(("metadata.tar.sig".to_string(), b"not read\n".to_vec()));
            members.push(("image.tar".to_string(), image(self.fifo)));
            members.push(("image.tar.sig".to_string(), b"not read\n".to_vec()));

            let mut manifest = String::new();
            for (name, body) in &members {
                if self.unlisted.contains(&name.as_str()) {
                    continue;
                }
                let mut sha512 = Algorithm::Sha512.hex_of(body);
                if self.corrupt == Some(name.as_str()) {
                    sha512 = hex(&[0u8; 64]);
                }
                manifest.push_str(&format!(
                    "DATA {name} {} SHA512 {sha512} BLAKE2B {}\n",
                    body.len(),
                    hex(&[0u8; 64]),
                ));
            }
            for name in &self.phantom {
                manifest.push_str(&format!("DATA {name} 0 SHA512 {}\n", hex(&[0u8; 64])));
            }
            members.push((
                MANIFEST_MEMBER.to_string(),
                fixture::clearsign(key, &manifest).into_bytes(),
            ));

            let prefixed: Vec<(String, Vec<u8>)> = members
                .into_iter()
                .map(|(name, body)| (format!("{}/{name}", self.prefix), body))
                .collect();
            let entries: Vec<(&str, Vec<u8>)> = prefixed
                .iter()
                .map(|(name, body)| (name.as_str(), body.clone()))
                .collect();
            std::fs::write(path, tarball(&entries)).expect("the container is written");
        }
    }

    /// The plan entry a container is checked against.
    pub(in crate::provision::gentoo) fn planned(cpv: &str, build_id: u64) -> PlannedPackage {
        let (category, package, version) =
            super::super::version::split_cpv(cpv).expect("a fixture CPV");
        let mut plan = super::super::Plan::parse_document(&format!(
            "Format: ferroday-cage-gentoo-plan 1\nArchitecture: amd64\nBinhost: x86-64\n\n\
             Package: {category}/{package}\nVersion: {version}\nBuild-Id: {build_id}\n\
             Path: a/b/c.gpkg.tar\nSize: 1\nMD5: 3a61f698748c7323c87081584f383b3c\n",
        ))
        .expect("a fixture plan");
        plan.packages.remove(0)
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{Built, CPV, metadata_named, planned};
    use super::*;
    use crate::provision::openpgp::fixture;
    use crate::scratch::Scratch;

    /// Opens `built` and reports what happened.
    #[track_caller]
    fn open(tag: &str, built: Built, wanted: &PlannedPackage) -> Result<Package, GentooError> {
        let dir = Scratch::for_test("gentoo-gpkg", tag);
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let path = dir.join("package.gpkg.tar");
        built.write(&path, &key);
        Package::open(&path, wanted, &fixture::keyring(&key))
    }

    #[test]
    fn a_container_that_is_what_it_says_opens() {
        let package = open("ordinary", Built::ordinary(), &planned(CPV, 1))
            .expect("an ordinary container opens");
        assert_eq!(
            package
                .metadata_files()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            ["BUILD_ID", "CATEGORY", "PF", "SLOT", "USE"],
        );
        assert_eq!(
            package
                .metadata_files()
                .find(|(name, _)| *name == "CATEGORY")
                .map(|(_, bytes)| String::from_utf8_lossy(bytes)),
            Some("sys-libs\n".into()),
        );
    }

    #[test]
    fn the_directory_prefix_is_not_the_packages_name() {
        // GLEP 78 requires a reader to process a container whose directory does
        // not match, so the prefix is used to find the members and for nothing
        // else. A reader that took it for the identity would refuse this.
        let mismatched = Built {
            prefix: "something-else-entirely-9".to_string(),
            ..Built::ordinary()
        };
        open("prefix", mismatched, &planned(CPV, 1))
            .expect("a mismatched prefix is not a mismatched package");
    }

    #[test]
    fn a_correctly_signed_package_that_is_not_the_one_asked_for_is_refused() {
        // The attack the identity check exists for: a hostile mirror answering
        // a request for one package with a genuine, correctly signed other one.
        // Every signature holds; nothing in the signed material says which
        // package was asked for.
        let err = open(
            "identity",
            Built::ordinary(),
            &planned("app-misc/other-1.0", 1),
        )
        .expect_err("another package is refused");
        assert!(matches!(err, GentooError::Container { .. }), "{err:?}");
        assert!(err.to_string().contains("the signature holds"), "{err}");

        // The build id is part of the identity, because two builds of one
        // version differ in what they were compiled with.
        let err = open("build-id", Built::ordinary(), &planned(CPV, 7))
            .expect_err("another build is refused");
        assert!(matches!(err, GentooError::Container { .. }), "{err:?}");
    }

    #[test]
    fn the_identity_is_compared_field_by_field_rather_than_as_one_string() {
        // Where the container's own splits fall is the container's to choose,
        // and the joined spellings are ambiguous: `PF = "zlib-1.3"` with
        // `BUILD_ID = "2-1"` joins to `sys-libs/zlib-1.3-2-1`, which is what
        // the planned `sys-libs/zlib`, `1.3.2`, `1` joins to as well. Comparing
        // the joined strings would accept it, and this step is the one thing
        // standing between a correctly signed package and the wrong package.
        let err = open(
            "ambiguous-split",
            Built {
                metadata: metadata_named("sys-libs", "zlib-1.3", "2-1"),
                ..Built::ordinary()
            },
            &planned(CPV, 1),
        )
        .expect_err("a container whose splits fall elsewhere is refused");
        assert!(matches!(err, GentooError::Container { .. }), "{err:?}");
        assert!(err.to_string().contains("the signature holds"), "{err}");

        // The build id is compared as the number the plan holds, so a container
        // that spells it with a leading zero is the same build and opens.
        open(
            "padded-build-id",
            Built {
                metadata: metadata_named("sys-libs", "zlib-1.3.2", "01"),
                ..Built::ordinary()
            },
            &planned(CPV, 1),
        )
        .expect("a build id spelled 01 is build 1");

        // And one that is not a number is not the plan's build id, whatever it
        // renders as beside the other two fields.
        let err = open(
            "unnumbered-build-id",
            Built {
                metadata: metadata_named("sys-libs", "zlib-1.3.2", "1st"),
                ..Built::ordinary()
            },
            &planned(CPV, 1),
        )
        .expect_err("a build id that is not a number is refused");
        assert!(matches!(err, GentooError::Container { .. }), "{err:?}");
    }

    #[test]
    fn the_manifest_must_account_for_exactly_the_members_present() {
        // Both directions. A member the Manifest does not list is one nothing
        // vouches for; one it lists that is absent was taken away.
        let err = open(
            "unlisted",
            Built {
                unlisted: vec!["image.tar"],
                ..Built::ordinary()
            },
            &planned(CPV, 1),
        )
        .expect_err("an unvouched-for member is refused");
        assert!(err.to_string().contains("does not list"), "{err}");

        let err = open(
            "phantom",
            Built {
                phantom: vec!["extra.tar"],
                ..Built::ordinary()
            },
            &planned(CPV, 1),
        )
        .expect_err("a missing member is refused");
        assert!(err.to_string().contains("is missing"), "{err}");
    }

    #[test]
    fn a_member_that_is_not_the_bytes_the_manifest_vouched_for_is_refused() {
        let err = open(
            "digest",
            Built {
                corrupt: Some("image.tar"),
                ..Built::ordinary()
            },
            &planned(CPV, 1),
        )
        .expect_err("a bad digest is refused");
        assert!(matches!(err, GentooError::Digest { .. }), "{err:?}");
    }

    #[test]
    fn a_container_with_no_format_marker_is_not_one() {
        let err = open(
            "unmarked",
            Built {
                marked: false,
                ..Built::ordinary()
            },
            &planned(CPV, 1),
        )
        .expect_err("an unmarked container is refused");
        assert!(err.to_string().contains(FORMAT_MEMBER), "{err}");
    }

    #[test]
    fn a_manifest_signed_by_a_key_the_keyring_does_not_hold_is_refused() {
        let dir = Scratch::for_test("gentoo-gpkg", "forged");
        let path = dir.join("package.gpkg.tar");
        Built::ordinary().write(&path, &fixture::signing_key("forger <f@test.invalid>"));
        let trusted = fixture::signing_key("releng <releng@test.invalid>");
        let err = Package::open(&path, &planned(CPV, 1), &fixture::keyring(&trusted))
            .expect_err("a forged Manifest is refused");
        assert!(matches!(err, GentooError::Signature { .. }), "{err:?}");
    }

    #[test]
    fn the_image_reads_back_as_the_tree_it_describes() {
        let dir = Scratch::for_test("gentoo-gpkg", "image");
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let path = dir.join("package.gpkg.tar");
        Built::ordinary().write(&path, &key);
        let package = Package::open(&path, &planned(CPV, 1), &fixture::keyring(&key))
            .expect("the container opens");

        let mut archive = package.image(&path).expect("the image opens");
        let mut names = Vec::new();
        while let Some(entry) = archive.next_entry().expect("the image reads") {
            names.push(String::from_utf8_lossy(&entry.path).into_owned());
        }
        assert_eq!(
            names,
            [
                "image/",
                "image/usr/",
                "image/usr/lib/",
                "image/usr/lib/libz.so.1.3.2",
                "image/usr/lib/libz.so",
            ],
        );
        // The prefix is still on the paths here: stripping it is the
        // extractor's, so that what the containment rules see is the path as it
        // will be written.
    }
}
