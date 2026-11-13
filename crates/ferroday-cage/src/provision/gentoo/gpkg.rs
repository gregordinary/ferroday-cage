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
//! established after verification, from the metadata inside, against the plan
//! entry the resolution chose:
//!
//! - `CATEGORY`, `PF` and `BUILD_ID` name the package and the build.
//! - `CHOST` names the target it was built for, which must be one the root's
//!   own packages were built for.
//! - `SLOT`, `USE`, `IUSE`, `RDEPEND`, `PDEPEND` and `BUILD_TIME` are what the
//!   resolution read from the index, which nothing signs, and must say the
//!   same.
//!
//! The container's own MD5 must be the one the index stated, too, which pins a
//! plan to the containers it resolved. A mismatch is a refusal rather than a
//! warning.
//!
//! What the metadata cannot establish is which binhost a build came from.
//! Every binhost of an architecture is signed by one key, none is named in
//! what is signed, and binhosts that share a target differ only in compiler
//! flags. [`check_target`] says why the binding stops at the target.
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
//! 78 asks of a reader that finds a bad signature. A pass ahead of both takes
//! the container's MD5, which covers the whole file where the member reader
//! stops at the archive's end.
//!
//! # One descriptor, both passes
//!
//! What the two passes establish is that the *bytes the first pass read* were
//! the ones the Manifest vouched for, so the second pass reads them again
//! through the descriptor the first one read rather than opening the path a
//! second time. A cache entry is published by renaming a staging file over its
//! name, which is how two runs sharing a cache write into it, and a rename
//! leaves a descriptor already open on the file it held.
//!
//! What a held descriptor cannot answer is a write *into* that file between the
//! passes. Nothing in this crate writes a cache entry in place, so only
//! something outside it can, holding write access to the file itself. The cache
//! is [`cache_dir`](super::GentooBuilder::cache_dir), or a sibling of the tree
//! being built where the caller named none. A caller who points `cache_dir` at
//! a location others can write to is extending the trust boundary to them, and
//! is entitled to know that is the decision they are making.
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

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::Path;

use super::plan::PlannedPackage;
use super::{GentooError, MAX_METADATA_BYTES, atom, installed};
use crate::ErrorChain;
use crate::path;
use crate::provision::compress;
use crate::provision::digest::{self, Algorithm, Digest};
use crate::provision::openpgp::{Keyring, MAX_SIGNED_DOCUMENT_BYTES};
use crate::provision::tar::{self, TarReader};

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
///
/// The shared ceiling on a signed document, which is also the most that
/// verifying one reads, so a Manifest past it is refused as it arrives rather
/// than held and then refused. A real one is a few lines, one per member.
const MAX_MANIFEST_BYTES: u64 = MAX_SIGNED_DOCUMENT_BYTES;

/// The token a Manifest line names its SHA-512 by, spelled as GLEP 74 spells
/// it.
const SHA512: &str = "SHA512";

/// What one member of a container is, by its name below the directory prefix.
///
/// The one rule both passes select members by. The first pass records what it
/// verified under it, and the second finds the image archive by it again, so
/// the member the second pass extracts is the one the first pass digested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The format marker.
    Format,
    /// The cleartext-signed digests of every other member.
    Manifest,
    /// The archive of the files merged into the root.
    Image,
    /// The archive of the package's own metadata files.
    Metadata,
    /// Anything else, the two detached signatures included: digested by the
    /// Manifest like every member, and otherwise not read.
    Other,
}

impl Role {
    /// The role of the member named `name`.
    ///
    /// The archives are named by a prefix, since their compression is a suffix
    /// of the name. A `.sig` beside one is a signature over it rather than a
    /// second archive.
    fn of(name: &str) -> Role {
        match name {
            FORMAT_MEMBER => Role::Format,
            MANIFEST_MEMBER => Role::Manifest,
            _ if name.ends_with(".sig") => Role::Other,
            _ if name.starts_with(IMAGE_MEMBER) => Role::Image,
            _ if name.starts_with(METADATA_MEMBER) => Role::Metadata,
            _ => Role::Other,
        }
    }
}

/// A verified container: its metadata, and where its image sits.
///
/// Holding one means the Manifest verified against the vendored keyring, every
/// member matched the size and SHA-512 it recorded, and the member set was
/// exactly the one it lists. It also means the metadata inside names the
/// package and build the plan named, was built for a target the root runs, and
/// states what the plan says the index stated about it, and that the container
/// is the one whose MD5 the plan records.
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
    /// The container itself, held open from the pass that verified it.
    ///
    /// The second pass rewinds this rather than opening the path again. The
    /// cache directory is a caller's, and a caller may point two builds at one:
    /// a cache entry is published by renaming a staging file over its name, so
    /// re-opening reads whatever that name now binds and need not be the bytes
    /// the Manifest was checked against. Holding the descriptor keeps the file
    /// that was verified the file that is extracted, which is the answer the
    /// Alpine layer's `Acquired` gives by carrying its own.
    container: std::fs::File,
    /// The container's MD5, lowercase hex, which a merged package's
    /// `BINPKGMD5` records.
    md5: String,
    /// The target triple the package was built for, from its `CHOST`.
    chost: String,
}

impl Package {
    /// Reads the container `container`, from its start, and holds it to
    /// everything above.
    ///
    /// `path` names it in a failure. `planned` is what the resolution chose,
    /// and what the container's own metadata is checked against. It is the
    /// plan's entry rather than the index record because both ways of reaching
    /// an install go through a plan: one resolved here, and one a caller kept
    /// and handed back.
    ///
    /// `targets` are the `CHOST`s the root's own packages were built for, which
    /// the container's must be one of; an empty set is a root that states none
    /// yet, and holds the container to nothing. See [`check_target`] for why
    /// the target is what is bound and the binhost is not.
    ///
    /// The descriptor is the caller's, so the container checked is the one the
    /// caller holds: a cache entry it opened, or a download not yet published.
    ///
    /// # Errors
    ///
    /// Returns [`GentooError::Signature`] where the Manifest does not verify,
    /// [`GentooError::Digest`] where a member is not the bytes it vouched for,
    /// and [`GentooError::Io`] where the file could not be read. Returns
    /// [`GentooError::Container`] for a container that is not one this layer
    /// can read: cut short, more entries than the format has room for, no
    /// format marker, a member the Manifest does not list or one it lists that
    /// is absent, or no image or metadata archive. It also
    /// reports one whose signed metadata disagrees with the plan, naming a
    /// different package or build, a target the root does not run, or a slot,
    /// flags or dependencies other than the index stated, and one whose MD5 is
    /// not the plan's.
    pub(super) fn read(
        mut container: std::fs::File,
        path: &Path,
        planned: &PlannedPackage,
        targets: &BTreeSet<String>,
        keyring: &Keyring,
    ) -> Result<Package, GentooError> {
        // A pass of its own over the file, ahead of the one that reads the
        // members: the MD5 is over the whole container, padding included, and
        // the tar reader stops at the archive's end.
        let (md5, _) = digest::md5::stream(&mut container)
            .map_err(GentooError::at("digesting the container", path))?;
        io::Seek::rewind(&mut container)
            .map_err(GentooError::at("rewinding the container", path))?;
        let scan = scan(path, &mut container)?;
        let manifest = Manifest::verify(path, &scan, keyring)?;
        manifest.hold(path, &scan)?;
        let metadata = read_metadata(path, &scan)?;
        check_identity(path, planned, &metadata)?;
        let chost = check_target(path, &metadata, targets)?;
        check_record(path, planned, &metadata)?;
        // Last, because every refusal above says more about what arrived than
        // this one does: a container that is a different package, or no
        // package at all, also has a different MD5.
        if md5 != planned.md5 {
            return Err(GentooError::container(
                path,
                format!(
                    "has the MD5 {md5}, and the index states {} for the container it named; the \
                     signature holds and the container is not the one the plan records",
                    planned.md5,
                ),
            ));
        }
        Ok(Package {
            metadata,
            container,
            md5,
            chost,
        })
    }

    /// The container's MD5, lowercase hex.
    pub(super) fn md5(&self) -> &str {
        &self.md5
    }

    /// The target triple the package was built for, from its signed `CHOST`.
    pub(super) fn chost(&self) -> &str {
        &self.chost
    }

    /// Every metadata file, by name, in name order.
    pub(super) fn metadata_files(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.metadata
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
    }

    /// Opens the image archive for reading, decompressed.
    ///
    /// The second pass, over the descriptor the first one verified: `path` names
    /// the container in a failure and is not opened again. See
    /// [`container`](Self::container) for why.
    ///
    /// Everything this yields was covered by the verified Manifest, so it is
    /// where a caller may act on the container's contents and the first place it
    /// may.
    ///
    /// The image is the member [`Role::of`] names the image archive, which the
    /// first pass refused a container to hold more than one of.
    pub(super) fn image(&self, path: &Path) -> Result<TarReader<Box<dyn Read + '_>>, GentooError> {
        let mut file = &self.container;
        io::Seek::rewind(&mut file).map_err(GentooError::at("rewinding the container", path))?;
        let mut archive = TarReader::new(io::BufReader::new(file), path);
        while let Some(entry) = archive
            .next_entry()
            .map_err(|err| GentooError::container(path, ErrorChain::new(&err).to_string()))?
        {
            let is_image = entry.typeflag != b'5'
                && split_member(&entry.path)
                    .and_then(|(_, name)| std::str::from_utf8(name).ok())
                    .is_some_and(|name| Role::of(name) == Role::Image);
            if !is_image {
                continue;
            }
            let member = Member {
                archive,
                left: entry.size,
            };
            // As in the first pass, a failure under the member is the tar
            // reader's, and says the container is cut short or unreadable.
            let (_, inner) = compress::decoder(member).map_err(|err| {
                let err = tar::read_failure(path, 0, err);
                GentooError::container(path, ErrorChain::new(&err).to_string())
            })?;
            return Ok(TarReader::new(inner, path));
        }
        Err(GentooError::container(
            path,
            "the image archive is no longer in the container it was verified in",
        ))
    }
}

/// A container's members as one pass over it saw them.
struct Scan {
    /// Each member's length and the SHA-512 of its bytes, by its name.
    ///
    /// Keyed by the name because every question asked of the set is one of
    /// membership: whether a name has been seen already, and whether a name the
    /// Manifest lists is present.
    members: BTreeMap<String, Seen>,
    /// The Manifest's bytes.
    manifest: Vec<u8>,
    /// Whether an image archive was seen. Its bytes are not held: an image
    /// runs to hundreds of megabytes, and the second pass reads it again.
    has_image: bool,
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

/// One member as the scan saw it, under the name inside the container's
/// directory, which is what the Manifest spells.
struct Seen {
    size: u64,
    sha512: Digest,
}

/// The most entries a container may hold.
///
/// The first pass reads every entry before anything vouches for one, and the
/// index's `SIZE`, which is all that bounds the download, admits millions of
/// empty entries in a gigabyte. So the count is bounded as the entries arrive.
/// GLEP 78 defines six members, and says the format may gain more that a reader
/// should pass over, so the bound leaves room for that rather than being six.
/// Directory entries count too: GLEP 78 says a container carries none.
const MAX_ENTRIES: usize = 16;

/// Reads the whole container once, digesting every member.
///
/// The prefix is read to find the members and is never trusted as a name: GLEP
/// 78 says a conforming writer may mismatch it, so what it is used for is
/// stripping, and what a member *is* comes from its own name below the prefix.
fn scan(path: &Path, file: &mut std::fs::File) -> Result<Scan, GentooError> {
    let mut archive = TarReader::new(io::BufReader::new(file), path);
    let mut scan = Scan {
        members: BTreeMap::new(),
        manifest: Vec::new(),
        has_image: false,
        metadata: Vec::new(),
        has_metadata: false,
        marked: false,
    };
    let mut prefix: Option<Vec<u8>> = None;
    let mut entries = 0usize;
    while let Some(entry) = archive
        .next_entry()
        .map_err(|err| GentooError::container(path, ErrorChain::new(&err).to_string()))?
    {
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err(GentooError::container(
                path,
                format!("holds more than {MAX_ENTRIES} entries, where GLEP 78 defines six"),
            ));
        }
        // Directory entries describe the container's own layout rather than
        // being members of it, and the Manifest does not list them.
        if entry.typeflag == b'5' {
            continue;
        }
        let full = entry.path.clone();
        let Some((held, name)) = split_member(&full) else {
            return Err(GentooError::container(
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
                return Err(GentooError::container(
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
            return Err(GentooError::container(
                path,
                "holds a member whose name is not UTF-8",
            ));
        };
        let name = name.to_string();
        // One member per name, since the Manifest has one line per name and
        // cannot vouch for two members under it. And one image archive and one
        // metadata archive, whatever their compression suffixes: a second image
        // is one the two passes could each take for the image.
        let role = Role::of(&name);
        if scan.members.contains_key(&name) {
            return Err(GentooError::container(
                path,
                format!("holds the member {name:?} twice"),
            ));
        }
        let repeated = match role {
            Role::Image if scan.has_image => Some("image"),
            Role::Metadata if scan.has_metadata => Some("metadata"),
            _ => None,
        };
        if let Some(archive) = repeated {
            return Err(GentooError::container(
                path,
                format!("holds a second {archive} archive, {name:?}"),
            ));
        }

        // The Manifest and the metadata archive are held in memory: the first
        // to verify, the second because the merge writes most of it back out.
        // Both are small and both are bounded, since the container arrives with
        // no length for either until the Manifest has been read.
        let held = match role {
            Role::Manifest => Some(MAX_MANIFEST_BYTES),
            Role::Metadata => Some(MAX_METADATA_BYTES),
            Role::Format | Role::Image | Role::Other => None,
        };
        let mut buffered = Vec::new();
        let (sha512, size) = match held {
            // Refused on the length the entry declares, before a byte of it is
            // held, and never cut at the ceiling: a member that fits is read
            // whole and one past it is refused as what it is.
            Some(limit) => {
                buffered = archive.read_entry(limit).map_err(|err| {
                    GentooError::container(path, ErrorChain::new(&err).to_string())
                })?;
                (
                    Digest::of(Algorithm::Sha512, &buffered),
                    buffered.len() as u64,
                )
            }
            None => {
                let mut member = Member {
                    archive,
                    left: entry.size,
                };
                // What fails here is the tar reader under the member, which
                // reports a container cut short or unreadable the way the
                // entry headers above report one.
                let digested = digest::stream(Algorithm::Sha512, &mut member).map_err(|err| {
                    GentooError::container(path, ErrorChain::new(&err).to_string())
                })?;
                archive = member.archive;
                digested
            }
        };

        match role {
            Role::Format => scan.marked = true,
            Role::Manifest => scan.manifest = buffered,
            Role::Image => scan.has_image = true,
            Role::Metadata => {
                scan.metadata = buffered;
                scan.has_metadata = true;
            }
            Role::Other => {}
        }
        scan.members.insert(name, Seen { size, sha512 });
    }

    if !scan.marked {
        return Err(GentooError::container(
            path,
            format!("carries no {FORMAT_MEMBER} member, so it is not a gpkg container"),
        ));
    }
    if scan.manifest.is_empty() {
        return Err(GentooError::container(
            path,
            format!("carries no {MANIFEST_MEMBER}, so nothing vouches for its members"),
        ));
    }
    if !scan.has_image || !scan.has_metadata {
        return Err(GentooError::container(
            path,
            "carries no image archive or no metadata archive",
        ));
    }
    Ok(scan)
}

/// Splits a member path into its directory prefix and the name below it.
///
/// A member is exactly one level down, and both halves are ordinary path
/// components. A path with no separator or with more than one, or a half that
/// is empty, `.` or `..`, is not a member of a gpkg container.
fn split_member(path: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = path.iter().position(|byte| *byte == b'/')?;
    let (prefix, rest) = (&path[..at], &path[at + 1..]);
    if !path::is_ordinary_component(prefix) || !path::is_ordinary_component(rest) {
        return None;
    }
    Some((prefix, rest))
}

/// A container member's data, as a reader bounded by the member's length.
///
/// The tar reader yields a member's bytes through `read_data` and skips the
/// rest at the next entry, so this is what lets a digest and a decompressor see
/// one member as an ordinary stream. A failure of the reader is carried through
/// [`tar::into_io`], so a tar reader over a member reports the container's
/// failure as the container's.
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
            .map_err(tar::into_io)?;
        self.left -= got as u64;
        Ok(got)
    }
}

/// What the container's Manifest vouches for.
struct Manifest {
    /// Each member's stated length and SHA-512, by name.
    entries: BTreeMap<String, (u64, Digest)>,
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
                return Err(GentooError::container(
                    path,
                    format!("states a length of {size:?} for {name:?}, which is not a number"),
                ));
            };
            // The digests are `<algorithm> <hex>` pairs and the Manifest states
            // several. SHA-512 is the one read; a pair whose algorithm this
            // layer does not know is stepped over rather than refused, since a
            // Manifest gaining an algorithm is not a Manifest this layer stops
            // being able to read. The value is taken as written and made a
            // `Digest` below, which holds it to the algorithm's own lowercase
            // alphabet as every digest in the crate is held, so a comparison
            // with it is a plain `==`.
            let mut sha512 = None;
            while let (Some(algorithm), Some(hex)) = (fields.next(), fields.next()) {
                if algorithm == SHA512 {
                    sha512 = Some(hex);
                }
            }
            let Some(sha512) = sha512.and_then(|hex| Digest::new(Algorithm::Sha512, hex)) else {
                return Err(GentooError::container(
                    path,
                    format!("states no usable SHA-512 for the member {name:?}"),
                ));
            };
            entries.insert(name.to_string(), (size, sha512));
        }
        if entries.is_empty() {
            return Err(GentooError::container(
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
        for (name, seen) in &scan.members {
            // The Manifest does not vouch for itself: it is the thing the
            // signature covers.
            if name == MANIFEST_MEMBER {
                continue;
            }
            let Some((size, sha512)) = self.entries.get(name) else {
                return Err(GentooError::container(
                    path,
                    format!("holds a member {name:?} that its Manifest does not list"),
                ));
            };
            if seen.size != *size {
                return Err(GentooError::container(
                    path,
                    format!(
                        "holds a member {name:?} of {} bytes where its Manifest states {size}",
                        seen.size,
                    ),
                ));
            }
            if seen.sha512 != *sha512 {
                return Err(GentooError::Digest {
                    subject: format!("the member {name:?} of {}", path.display()),
                    expected: sha512.clone(),
                    actual: seen.sha512.clone(),
                });
            }
        }
        for name in self.entries.keys() {
            if !scan.members.contains_key(name) {
                return Err(GentooError::container(
                    path,
                    format!("is missing the member {name:?} that its Manifest lists"),
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
    let (_, inner) = compress::decoder(scan.metadata.as_slice())
        .map_err(|err| GentooError::container(path, ErrorChain::new(&err).to_string()))?;
    let mut inner = TarReader::new(inner, path);
    // What the entries may hold between them, which is what each is read
    // under: the metadata is one budget, however the archive divides it. An
    // entry the layer does not keep is read under it too, since decompressing
    // it costs what decompressing a kept one does.
    let mut left = MAX_METADATA_BYTES;
    while let Some(entry) = inner
        .next_entry()
        .map_err(|err| GentooError::container(path, ErrorChain::new(&err).to_string()))?
    {
        if entry.typeflag == b'5' {
            continue;
        }
        let bytes = inner
            .read_entry(left)
            .map_err(|err| GentooError::container(path, ErrorChain::new(&err).to_string()))?;
        left -= bytes.len() as u64;
        // Anything that is not a plain file directly under `metadata/` is not a
        // metadata file, and the layer writes out only what it recognizes.
        if let Some(name) = std::str::from_utf8(&entry.path)
            .ok()
            .and_then(|name| name.strip_prefix(METADATA_DIR))
            .filter(|name| path::is_ordinary_component(name.as_bytes()))
        {
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
    let (Some(category), Some(pf), Some(build_id)) = (
        field(metadata, "CATEGORY"),
        field(metadata, "PF"),
        field(metadata, "BUILD_ID"),
    ) else {
        return Err(GentooError::container(
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
        return Err(GentooError::container(
            path,
            format!(
                "is {named:?}, and what was asked for is {wanted}; the signature holds and the \
                 package is not the one the index named",
            ),
        ));
    }
    Ok(())
}

/// One metadata file's value, read as [`installed::field_text`] reads one, or
/// `None` where the container carries no such file.
fn field(metadata: &BTreeMap<String, Vec<u8>>, name: &str) -> Option<String> {
    metadata.get(name).map(|bytes| installed::field_text(bytes))
}

/// Holds the container's signed `CHOST` to the targets the root's packages were
/// built for, returning it.
///
/// The target triple names the instruction set, the byte order, the ABI and the
/// C library: `x86_64-pc-linux-gnu`, `x86_64-pc-linux-musl`,
/// `x86_64-pc-linux-gnux32`, `aarch64-unknown-linux-gnu`. Every architecture's
/// containers are signed by one key, so without this a mirror could answer for
/// one architecture or C library with another's genuine build, and the root
/// would gain programs it cannot run. Portage refuses the same mismatch, holding
/// a binary package's `CHOST` to the system's own.
///
/// It is the target that is bound and not the binhost, because nothing Gentoo
/// signs names the binhost. Binhosts that share a target differ only in their
/// compiler flags, and in no uniform way: `x86-64` builds with
/// `-march=x86-64`, `x86-64-v3` with `-march=x86-64-v3`, and `x86-64_hardened`
/// and `x86-64_llvm` with neither. A container from one of those in place of
/// another is genuine, signed and built for this root's target, and nothing in
/// it says it came from a different directory than the one asked for.
///
/// An empty `targets` is a root whose database states no `CHOST`, which binds
/// nothing yet.
fn check_target(
    path: &Path,
    metadata: &BTreeMap<String, Vec<u8>>,
    targets: &BTreeSet<String>,
) -> Result<String, GentooError> {
    let Some(chost) = field(metadata, "CHOST").filter(|chost| !chost.is_empty()) else {
        return Err(GentooError::container(
            path,
            "carries no CHOST, so it cannot say what it was built for",
        ));
    };
    // Both sides are quoted: the container's is a field of metadata nothing
    // holds to an alphabet, and the root's are what its database's `CHOST`
    // files say, which anything run in the root may have written.
    if !targets.is_empty() && !targets.contains(&chost) {
        let root = targets
            .iter()
            .map(|target| format!("{target:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(GentooError::container(
            path,
            format!(
                "was built for {chost:?}, and the root's packages were built for {root}; the \
                 signature holds and the package is not one this root can run",
            ),
        ));
    }
    Ok(chost)
}

/// Holds the container's signed metadata to what the plan says the index
/// stated about the build.
///
/// The index is what the resolution read, and nothing signs it: the slot that
/// decided which installed package a build would sit beside, the flags a USE
/// dependency was answered from, the dependencies that decided the closure and
/// the order, and the build time that ranked one build above another. Each is
/// in the container's metadata too, where the Manifest vouches for it. A
/// disagreement is an index that described a different build than the one it
/// pointed at, and the resolution acted on that description, so it is
/// refused.
///
/// Each value is read as the index reader reads its own: a slot as one string,
/// flags as a sequence of tokens, dependencies through the dependency grammar,
/// and a build time as a number, zero where it is absent or unreadable.
fn check_record(
    path: &Path,
    planned: &PlannedPackage,
    metadata: &BTreeMap<String, Vec<u8>>,
) -> Result<(), GentooError> {
    let text = |name: &str| field(metadata, name).unwrap_or_default();
    let differs = |what: &str, signed: &str, stated: &str| {
        GentooError::container(
            path,
            format!(
                "states {what} {signed:?}, and the index stated {stated:?}; the signature holds \
                 and the index described another build than the one it named",
            ),
        )
    };

    let Some(slot) = field(metadata, "SLOT").filter(|slot| !slot.is_empty()) else {
        return Err(GentooError::container(
            path,
            "carries no SLOT, so it cannot say where it is installed",
        ));
    };
    if slot != planned.slot {
        return Err(differs("the slot", &slot, &planned.slot));
    }
    for (what, name, stated) in [
        ("the USE flags", "USE", &planned.use_flags),
        ("the IUSE", "IUSE", &planned.iuse),
    ] {
        let signed = text(name);
        if !signed
            .split_ascii_whitespace()
            .eq(stated.split_ascii_whitespace())
        {
            return Err(differs(what, &signed, stated));
        }
    }
    for (what, name, stated) in [
        ("the runtime dependencies", "RDEPEND", &planned.rdepend),
        ("the post-merge dependencies", "PDEPEND", &planned.pdepend),
    ] {
        let signed = text(name);
        let read = atom::parse_class(&signed).map_err(|reason| {
            GentooError::container(path, format!("states {what} that cannot be read: {reason}"))
        })?;
        if atom::parse_class(stated) != Ok(read) {
            return Err(differs(what, &signed, stated));
        }
    }
    let built = text("BUILD_TIME").parse::<i64>().unwrap_or(0);
    if built != planned.build_time {
        return Err(differs(
            "the build time",
            &built.to_string(),
            &planned.build_time.to_string(),
        ));
    }
    Ok(())
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

    /// The package every container below claims to be.
    pub(in crate::provision::gentoo) const CPV: &str = "sys-libs/zlib-1.3.2";

    /// The target every container below was built for.
    pub(in crate::provision::gentoo) const CHOST: &str = "x86_64-pc-linux-gnu";

    /// What every container below states about its build, and the plan's
    /// fixture entry states it as.
    const SLOT: &str = "0/1";
    const USE: &str = "amd64 minizip";
    const RDEPEND: &str = ">=sys-libs/glibc-2.40 || ( app-arch/xz-utils app-arch/zstd )";
    const BUILD_TIME: &str = "1700000000";

    /// The metadata files besides the identity that every container below
    /// carries, each a name and its value.
    const RECORD: [(&str, &str); 5] = [
        ("CHOST", CHOST),
        ("SLOT", SLOT),
        ("USE", USE),
        ("RDEPEND", RDEPEND),
        ("BUILD_TIME", BUILD_TIME),
    ];

    /// A tar archive of `entries`, each a name and its bytes.
    pub(in crate::provision::gentoo) fn tarball(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = ferroday_cage_testkit::tar::Tar::new();
        for (name, body) in entries {
            if name.ends_with('/') {
                out.dir(name, 0o644);
            } else {
                out.file(name, 0o644, body);
            }
        }
        out.finish()
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
        metadata_archive(&files_named(category, pf, build_id))
    }

    /// The metadata files naming `category`, `pf` and `build_id`, each a name
    /// inside `metadata/` and its contents.
    fn files_named(category: &str, pf: &str, build_id: &str) -> Vec<(String, String)> {
        let mut files = vec![
            ("CATEGORY".to_string(), format!("{category}\n")),
            ("PF".to_string(), format!("{pf}\n")),
            ("BUILD_ID".to_string(), build_id.to_string()),
        ];
        files.extend(
            RECORD
                .iter()
                .map(|(name, value)| (name.to_string(), format!("{value}\n"))),
        );
        files
    }

    /// The fixture package's metadata archive with some files changed: each a
    /// name and its new value, or `None` to leave the file out.
    ///
    /// What a test of the checks against the plan needs: one field of the
    /// signed metadata saying something other than the plan does.
    pub(in crate::provision::gentoo) fn metadata_with(changes: &[(&str, Option<&str>)]) -> Vec<u8> {
        let (category, package, version) =
            super::super::version::split_cpv(CPV).expect("a fixture CPV");
        let mut files = files_named(category, &format!("{package}-{version}"), "1");
        for (name, value) in changes {
            files.retain(|(held, _)| held != name);
            if let Some(value) = value {
                files.push((name.to_string(), format!("{value}\n")));
            }
        }
        metadata_archive(&files)
    }

    /// A metadata archive holding `files` under `metadata/`, each a name and
    /// its contents.
    fn metadata_archive(files: &[(String, String)]) -> Vec<u8> {
        metadata_archive_beside(files, &[])
    }

    /// The same, followed by `beside`, each an archive path and its contents.
    fn metadata_archive_beside(files: &[(String, String)], beside: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let named: Vec<(String, Vec<u8>)> = files
            .iter()
            .map(|(name, value)| (format!("{METADATA_DIR}{name}"), value.clone().into_bytes()))
            .collect();
        let mut entries: Vec<(&str, Vec<u8>)> = vec![(METADATA_DIR, Vec::new())];
        entries.extend(
            named
                .iter()
                .map(|(name, value)| (name.as_str(), value.clone())),
        );
        entries.extend(beside.iter().map(|(name, value)| (*name, value.clone())));
        tarball(&entries)
    }

    /// The fixture package's metadata archive with `beside` added, each an
    /// archive path outside `metadata/` and its contents.
    pub(in crate::provision::gentoo) fn metadata_beside(beside: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let (category, package, version) =
            super::super::version::split_cpv(CPV).expect("a fixture CPV");
        metadata_archive_beside(
            &files_named(category, &format!("{package}-{version}"), "1"),
            beside,
        )
    }

    /// The image archive a container carries: one directory, one file, one
    /// symbolic link, a named pipe where `fifo` asks for one, and a file under
    /// each of `lib64/` and `sbin/` where `aliased` does.
    ///
    /// The fifo is optional because it is what a package ships rarely and the
    /// merge has to answer for anyway: the layer records portage's own `fif`
    /// line for it and never opens it, where reading it as an ordinary file
    /// would block until something opened the write end -- and inside a
    /// provisioning run nothing will.
    ///
    /// The aliased paths are the ones a merged-usr root holds as links into
    /// `usr`, which the binhost's own packages still ship (lvm2's
    /// `lib64/libdevmapper.so.1.02` and `sbin/dmsetup`).
    ///
    /// `raw` are entries added after those, each a path, a type and a link
    /// target spelled as bytes, for what no string can spell.
    fn image(fifo: bool, aliased: bool, raw: &[RawEntry]) -> Vec<u8> {
        let mut out = ferroday_cage_testkit::tar::Tar::new().stamped(1_700_000_000);
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
        if aliased {
            entries.extend([
                ("image/lib64/", "", 0o755, 0, b'5'),
                ("image/lib64/libz.so.1", "", 0o755, 4, b'0'),
                ("image/sbin/", "", 0o755, 0, b'5'),
                ("image/sbin/zpipe", "", 0o755, 4, b'0'),
            ]);
        }
        for (name, target, mode, size, typeflag) in entries {
            let body: &[u8] = if size > 0 { b"ELF\n" } else { b"" };
            out.entry(name, typeflag, mode, 0, 0, target, body);
        }
        for (name, typeflag, target) in raw {
            out.header(name, *typeflag, 0o644, 0, 1_700_000_000, target);
        }
        out.finish()
    }

    /// An image entry spelled as bytes: its path, its type, and its link
    /// target.
    pub(in crate::provision::gentoo) type RawEntry = (&'static [u8], u8, &'static [u8]);

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
        /// Whether the image ships paths under `lib64/` and `sbin/` too.
        pub aliased: bool,
        /// Members added after the ordinary ones and before the Manifest, each
        /// a name and its bytes, listed in the Manifest unless `unlisted`
        /// names them.
        pub extra: Vec<(&'static str, Vec<u8>)>,
        /// Whether the Manifest spells its SHA-512 digests in uppercase.
        pub uppercase: bool,
        /// Entries the image carries after its ordinary ones, spelled as bytes.
        pub raw: Vec<RawEntry>,
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
                aliased: false,
                extra: Vec::new(),
                uppercase: false,
                raw: Vec::new(),
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
            members.push((
                "image.tar".to_string(),
                image(self.fifo, self.aliased, &self.raw),
            ));
            members.push(("image.tar.sig".to_string(), b"not read\n".to_vec()));
            for (name, body) in self.extra {
                members.push((name.to_string(), body));
            }

            let mut manifest = String::new();
            for (name, body) in &members {
                if self.unlisted.contains(&name.as_str()) {
                    continue;
                }
                let mut sha512 = Algorithm::Sha512.hex_of(body);
                if self.corrupt == Some(name.as_str()) {
                    sha512 = hex(&[0u8; 64]);
                }
                if self.uppercase {
                    sha512 = sha512.to_ascii_uppercase();
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
    ///
    /// It states what every fixture container's metadata states, and an MD5
    /// that is no container's: [`planned_for`] is the entry for one container
    /// in particular.
    pub(in crate::provision::gentoo) fn planned(cpv: &str, build_id: u64) -> PlannedPackage {
        let (category, package, version) =
            super::super::version::split_cpv(cpv).expect("a fixture CPV");
        let mut plan = super::super::Plan::parse_document(&format!(
            "Format: ferroday-cage-gentoo-plan 2\nArchitecture: amd64\nBinhost: x86-64\n\n\
             Package: {category}/{package}\nVersion: {version}\nBuild-Id: {build_id}\n\
             Path: a/b/c.gpkg.tar\nSize: 1\nMD5: 3a61f698748c7323c87081584f383b3c\n\
             Slot: {SLOT}\nUse: {USE}\nRdepend: {RDEPEND}\nBuild-Time: {BUILD_TIME}\n",
        ))
        .expect("a fixture plan");
        plan.packages.remove(0)
    }

    /// The same entry, naming the container at `container` by its MD5.
    pub(in crate::provision::gentoo) fn planned_for(
        cpv: &str,
        build_id: u64,
        container: &Path,
    ) -> PlannedPackage {
        let bytes = std::fs::read(container).expect("the container reads");
        let mut planned = planned(cpv, build_id);
        planned.md5 = digest::md5::hex_of(&bytes);
        planned
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{
        Built, CHOST, CPV, metadata_beside, metadata_named, metadata_with, planned, planned_for,
    };
    use super::*;
    use crate::provision::openpgp::fixture;
    use crate::scratch::Scratch;

    /// The targets of a root the fixture containers were built for.
    fn root_targets() -> BTreeSet<String> {
        BTreeSet::from([CHOST.to_string()])
    }

    /// Opens `built` and reports what happened, as the plan entry `wanted`
    /// naming the container by its MD5 would.
    #[track_caller]
    fn open(tag: &str, built: Built, wanted: &PlannedPackage) -> Result<Package, GentooError> {
        open_into(tag, built, wanted, &root_targets())
    }

    /// The same, for a root built for `targets`.
    #[track_caller]
    fn open_into(
        tag: &str,
        built: Built,
        wanted: &PlannedPackage,
        targets: &BTreeSet<String>,
    ) -> Result<Package, GentooError> {
        let dir = Scratch::for_test("gentoo-gpkg", tag);
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let path = dir.join("package.gpkg.tar");
        built.write(&path, &key);
        let mut wanted = wanted.clone();
        wanted.md5 = digest::md5::hex_of(&std::fs::read(&path).expect("the container reads"));
        Package::read(
            std::fs::File::open(&path).expect("the container opens"),
            &path,
            &wanted,
            targets,
            &fixture::keyring(&key),
        )
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
            [
                "BUILD_ID",
                "BUILD_TIME",
                "CATEGORY",
                "CHOST",
                "PF",
                "RDEPEND",
                "SLOT",
                "USE"
            ],
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
    fn the_second_pass_reads_the_container_the_first_one_verified() {
        // The cache directory is a caller's and a caller may point two builds
        // at one, so a container replaced between the two passes is a real
        // race. Re-opening the path reads whatever is there now; holding the
        // descriptor reads the bytes the Manifest was checked against.
        let dir = Scratch::for_test("gentoo-gpkg", "verified-bytes");
        let path = dir.join("zlib.gpkg.tar");
        let key = fixture::signing_key("gentoo <infra@test.invalid>");
        Built::ordinary().write(&path, &key);
        let keyring = fixture::keyring(&key);
        let package = Package::read(
            std::fs::File::open(&path).expect("the container opens"),
            &path,
            &planned_for(CPV, 1, &path),
            &root_targets(),
            &keyring,
        )
        .expect("the container verifies");

        // What another build publishing its own container at the same path
        // does: a staging file renamed over it, which is how every one of the
        // three layers writes a cache entry. The rename rebinds the name and
        // leaves this descriptor on the bytes that were verified.
        let staged = dir.join("zlib.gpkg.tar.staged");
        let mut swapped = Built::ordinary();
        swapped.prefix = "somethingelse-9.9-1".to_string();
        swapped.write(&staged, &key);
        std::fs::rename(&staged, &path).expect("the other build publishes its container");

        let mut image = package.image(&path).expect("the image archive still opens");
        assert!(
            image
                .next_entry()
                .expect("the verified image reads")
                .is_some(),
            "the second pass reads the container the first one verified",
        );
    }

    #[test]
    fn a_member_of_exactly_the_ceiling_is_not_over_it() {
        // The copy stops at the ceiling whether the member ends there or runs
        // past it, so reading the count taken refuses one that fits with a
        // reason that is not true of it. What the member still holds is what
        // tells the two apart.
        let mut built = Built::ordinary();
        built.metadata = vec![b'm'; MAX_METADATA_BYTES as usize];
        let err = open("gpkg-ceiling", built, &planned(CPV, 1))
            .expect_err("the fixture's metadata is not a metadata archive");
        assert!(
            !err.to_string().contains("more than"),
            "a member that fits was refused for its size: {err}",
        );

        // One byte more is over it, and says so.
        let mut built = Built::ordinary();
        built.metadata = vec![b'm'; MAX_METADATA_BYTES as usize + 1];
        let err = open("gpkg-over-ceiling", built, &planned(CPV, 1))
            .expect_err("a member past the ceiling is refused");
        assert!(err.to_string().contains("more than"), "{err}");
    }

    #[test]
    fn what_the_metadata_archive_inflates_to_is_one_budget_kept_or_not() {
        // An entry outside `metadata/` is not written out, and is decompressed
        // all the same, so it is read under the budget the kept files are. A
        // few kilobytes of gzip here inflate past it.
        let archive = metadata_beside(&[("padding", vec![0u8; MAX_METADATA_BYTES as usize + 1])]);
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        io::Write::write_all(&mut gzip, &archive).expect("gzip accepts it");
        let compressed = gzip.finish().expect("the member closes");
        assert!((compressed.len() as u64) < MAX_METADATA_BYTES / 64);
        let err = open(
            "metadata-budget",
            Built {
                metadata: compressed,
                ..Built::ordinary()
            },
            &planned(CPV, 1),
        )
        .expect_err("an archive inflating past the budget is refused");
        assert!(matches!(err, GentooError::Container { .. }), "{err:?}");
        assert!(err.to_string().contains("more than"), "{err}");
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
    fn a_member_name_reaches_an_error_with_its_control_characters_escaped() {
        // Nothing vouches for a member's name until the Manifest is held to the
        // members, and that comparison is what refuses this one: the name is
        // the mirror's string when the error names it.
        let hostile = crate::failure::hostile::TEXT;
        for built in [
            Built {
                extra: vec![(hostile, b"vouched for by nothing".to_vec())],
                unlisted: vec![hostile],
                ..Built::ordinary()
            },
            Built {
                phantom: vec![hostile],
                ..Built::ordinary()
            },
        ] {
            let err = open("hostile", built, &planned(CPV, 1)).expect_err("the member is refused");
            crate::failure::hostile::assert_escaped(&crate::ErrorChain::new(&err).to_string());
        }
    }

    #[test]
    fn a_member_present_twice_is_refused_whatever_the_manifest_says() {
        // The Manifest has one line per name, so a second copy of a member is
        // one nothing vouches for separately; and a second image archive under
        // another name is one each pass could take for the image.
        for (extra, reason) in [
            ("image.tar", "holds the member \"image.tar\" twice"),
            ("metadata.tar", "holds the member \"metadata.tar\" twice"),
            ("Manifest", "holds the member \"Manifest\" twice"),
            (
                "image.tar.zst",
                "holds a second image archive, \"image.tar.zst\"",
            ),
            (
                "metadata.tar.gz",
                "holds a second metadata archive, \"metadata.tar.gz\"",
            ),
        ] {
            let built = Built {
                extra: vec![(extra, b"listed in the signed Manifest".to_vec())],
                ..Built::ordinary()
            };
            let err = open(extra, built, &planned(CPV, 1)).expect_err("the container is refused");
            assert!(
                matches!(err, GentooError::Container { .. }),
                "{extra}: {err:?}"
            );
            assert!(err.to_string().contains(reason), "{extra}: {err}");
        }
        // A member of no role the layer reads, listed in the Manifest, is
        // digested like any other and is not a second anything.
        let built = Built {
            extra: vec![("NOTES", b"listed in the signed Manifest".to_vec())],
            ..Built::ordinary()
        };
        open("other-member", built, &planned(CPV, 1)).expect("an extra listed member is read");
    }

    #[test]
    fn a_container_holding_more_entries_than_the_format_has_room_for_is_refused() {
        // The scan reads every entry before the Manifest says anything, and the
        // index's SIZE admits millions of empty ones in a gigabyte. The count
        // is refused as the entries arrive, so this one stops at the bound
        // rather than reading on to find there is no format marker.
        let dir = Scratch::for_test("gentoo-gpkg", "many-entries");
        let path = dir.join("package.gpkg.tar");
        let names: Vec<String> = (0..5_000)
            .map(|at| format!("zlib-1.3.2-1/m{at:05}"))
            .collect();
        let entries: Vec<(&str, Vec<u8>)> = names
            .iter()
            .map(|name| (name.as_str(), Vec::new()))
            .collect();
        std::fs::write(&path, super::fixture::tarball(&entries)).expect("the container is written");
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let err = Package::read(
            std::fs::File::open(&path).expect("the container opens"),
            &path,
            &planned_for(CPV, 1, &path),
            &root_targets(),
            &fixture::keyring(&key),
        )
        .expect_err("a container of thousands of entries is refused");
        assert!(matches!(err, GentooError::Container { .. }), "{err:?}");
        assert!(
            err.to_string()
                .contains(&format!("more than {MAX_ENTRIES} entries")),
            "{err}",
        );
    }

    #[test]
    fn room_is_left_for_members_the_format_may_gain() {
        // GLEP 78 defines six members and says a reader should pass over ones
        // it does not know, so the bound sits above six. Members past it are
        // refused however the Manifest lists them.
        const EXTRA: [&str; MAX_ENTRIES - 5] = [
            "e00", "e01", "e02", "e03", "e04", "e05", "e06", "e07", "e08", "e09", "e10",
        ];
        let listed = |count: usize| Built {
            extra: EXTRA[..count]
                .iter()
                .map(|name| (*name, b"listed in the signed Manifest".to_vec()))
                .collect(),
            ..Built::ordinary()
        };
        open("room", listed(MAX_ENTRIES - 6), &planned(CPV, 1))
            .expect("a container of exactly the bound opens");
        let err = open("no-room", listed(MAX_ENTRIES - 5), &planned(CPV, 1))
            .expect_err("one entry past the bound is refused");
        assert!(err.to_string().contains("more than"), "{err}");
    }

    #[test]
    fn a_container_cut_short_is_the_containers_failure_and_not_the_hosts() {
        // Cut inside the image archive, which the first pass streams through
        // a digest rather than holding: what fails there is the tar reader
        // under the member, and it says what the container is.
        let dir = Scratch::for_test("gentoo-gpkg", "cut-short");
        let path = dir.join("package.gpkg.tar");
        let key = fixture::signing_key("releng <releng@test.invalid>");
        Built::ordinary().write(&path, &key);
        let bytes = std::fs::read(&path).expect("the container reads");
        let image = bytes
            .windows(b"zlib-1.3.2-1/image.tar\0".len())
            .position(|window| window == b"zlib-1.3.2-1/image.tar\0")
            .expect("the container holds the image archive");
        std::fs::write(&path, &bytes[..image + 512 + 100]).expect("the container is cut");
        let err = Package::read(
            std::fs::File::open(&path).expect("the container opens"),
            &path,
            &planned_for(CPV, 1, &path),
            &root_targets(),
            &fixture::keyring(&key),
        )
        .expect_err("a container cut short is refused");
        assert!(matches!(err, GentooError::Container { .. }), "{err:?}");
    }

    #[test]
    fn an_identity_or_a_target_reaches_a_refusal_with_its_control_characters_escaped() {
        // The container's identity and target are fields of its metadata,
        // which nothing holds to an alphabet, and the root's targets are what
        // its database's `CHOST` files say.
        let hostile = crate::failure::hostile::TEXT;
        let category = format!("sys-libs{hostile}");
        for (tag, metadata, targets) in [
            (
                "hostile-category",
                metadata_with(&[("CATEGORY", Some(&category))]),
                root_targets(),
            ),
            (
                "hostile-chost",
                metadata_with(&[("CHOST", Some(hostile))]),
                root_targets(),
            ),
            (
                "hostile-root-target",
                Built::ordinary().metadata,
                BTreeSet::from([hostile.to_string()]),
            ),
        ] {
            let built = Built {
                metadata,
                ..Built::ordinary()
            };
            let err = open_into(tag, built, &planned(CPV, 1), &targets)
                .expect_err("the container is refused");
            assert!(
                matches!(err, GentooError::Container { .. }),
                "{tag}: {err:?}"
            );
            crate::failure::hostile::assert_escaped(&crate::ErrorChain::new(&err).to_string());
        }
    }

    #[test]
    fn a_container_built_for_another_target_than_the_roots_is_refused() {
        // One key signs every architecture's containers, so a genuine build for
        // another one passes every signature check. The root's own packages
        // say what it runs.
        let arm = "aarch64-unknown-linux-gnu".to_string();
        let err = open_into(
            "other-target",
            Built::ordinary(),
            &planned(CPV, 1),
            &BTreeSet::from([arm.clone()]),
        )
        .expect_err("a build for another target is refused");
        assert!(matches!(err, GentooError::Container { .. }), "{err:?}");
        assert!(
            err.to_string().contains("not one this root can run"),
            "{err}"
        );

        // A root whose packages state several targets admits a build for any
        // of them, and one whose database states none binds nothing yet.
        open_into(
            "either-target",
            Built::ordinary(),
            &planned(CPV, 1),
            &BTreeSet::from([arm, CHOST.to_string()]),
        )
        .expect("a build for one of the root's targets opens");
        let package = open_into(
            "no-target",
            Built::ordinary(),
            &planned(CPV, 1),
            &BTreeSet::new(),
        )
        .expect("a root that states no target binds nothing");
        assert_eq!(package.chost(), CHOST);

        // A container that does not say what it was built for is refused
        // whatever the root states.
        let err = open_into(
            "unstated-target",
            Built {
                metadata: metadata_with(&[("CHOST", None)]),
                ..Built::ordinary()
            },
            &planned(CPV, 1),
            &BTreeSet::new(),
        )
        .expect_err("a container stating no target is refused");
        assert!(err.to_string().contains("no CHOST"), "{err}");
    }

    #[test]
    fn a_container_whose_signed_metadata_is_not_what_the_index_described_is_refused() {
        // The resolution acted on what the index stated, and nothing signs the
        // index. Each field it read is in the container's metadata too, where
        // the Manifest vouches for it.
        for (at, (name, value, why)) in [
            ("SLOT", Some("0/2"), "the slot"),
            ("SLOT", None, "no SLOT"),
            ("USE", Some("amd64"), "the USE flags"),
            ("IUSE", Some("minizip"), "the IUSE"),
            (
                "RDEPEND",
                Some(">=sys-libs/glibc-2.40"),
                "the runtime dependencies",
            ),
            ("RDEPEND", Some("|| ("), "cannot be read"),
            (
                "PDEPEND",
                Some("app-misc/other"),
                "the post-merge dependencies",
            ),
            ("BUILD_TIME", Some("1700000001"), "the build time"),
        ]
        .into_iter()
        .enumerate()
        {
            let err = open(
                &format!("record-{at}"),
                Built {
                    metadata: metadata_with(&[(name, value)]),
                    ..Built::ordinary()
                },
                &planned(CPV, 1),
            )
            .expect_err(why);
            assert!(
                matches!(err, GentooError::Container { .. }),
                "{why}: {err:?}"
            );
            assert!(err.to_string().contains(why), "{why}: {err}");
        }

        // What is compared is what the resolution read, so a field spelled with
        // other whitespace is the same field.
        open(
            "respelled",
            Built {
                metadata: metadata_with(&[
                    ("USE", Some("amd64   minizip")),
                    (
                        "RDEPEND",
                        Some(">=sys-libs/glibc-2.40\t||  (  app-arch/xz-utils app-arch/zstd  )"),
                    ),
                ]),
                ..Built::ordinary()
            },
            &planned(CPV, 1),
        )
        .expect("a field spelled with other whitespace is the same field");
    }

    #[test]
    fn a_container_that_is_not_the_one_the_plan_records_is_refused_by_its_md5() {
        // Everything else about it holds: the right package, built for this
        // root, stating what the index stated. The plan named one container by
        // its MD5 and this is another.
        let dir = Scratch::for_test("gentoo-gpkg", "md5");
        let path = dir.join("package.gpkg.tar");
        let key = fixture::signing_key("releng <releng@test.invalid>");
        Built::ordinary().write(&path, &key);
        let err = Package::read(
            std::fs::File::open(&path).expect("the container opens"),
            &path,
            &planned(CPV, 1),
            &root_targets(),
            &fixture::keyring(&key),
        )
        .expect_err("another container is refused");
        assert!(matches!(err, GentooError::Container { .. }), "{err:?}");
        assert!(
            err.to_string().contains("not the one the plan records"),
            "{err}"
        );
    }

    #[test]
    fn a_member_name_that_is_not_one_path_component_is_refused() {
        // Listed in the signed Manifest, so nothing but the name's own shape
        // stands against it.
        for name in ["..", "."] {
            let built = Built {
                extra: vec![(name, b"listed".to_vec())],
                ..Built::ordinary()
            };
            let err =
                open("odd-member", built, &planned(CPV, 1)).expect_err("the member is refused");
            assert!(
                err.to_string()
                    .contains("not a member of a single directory"),
                "{name:?}: {err}",
            );
        }
    }

    #[test]
    fn a_metadata_file_whose_name_is_not_one_path_component_is_not_read() {
        // Its name becomes the leaf of a database entry's path, so only an
        // ordinary component is a metadata file at all.
        let metadata = metadata_with(&[("..", Some("not a metadata file"))]);
        let package = open(
            "dotdot-metadata",
            Built {
                metadata,
                ..Built::ordinary()
            },
            &planned(CPV, 1),
        )
        .expect("the container opens");
        assert_eq!(
            package
                .metadata_files()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            [
                "BUILD_ID",
                "BUILD_TIME",
                "CATEGORY",
                "CHOST",
                "PF",
                "RDEPEND",
                "SLOT",
                "USE"
            ],
        );
    }

    #[test]
    fn a_manifest_digest_is_read_exactly_as_it_is_spelled() {
        // Lowercase hex is the one spelling every digest in the crate is held
        // to, so a comparison is a plain `==`. A Manifest spelling another is
        // not one this layer reads, rather than one it quietly rewrites.
        let err = open(
            "uppercase",
            Built {
                uppercase: true,
                ..Built::ordinary()
            },
            &planned(CPV, 1),
        )
        .expect_err("an uppercase digest is refused");
        assert!(err.to_string().contains("no usable SHA-512"), "{err}");
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
        let err = Package::read(
            std::fs::File::open(&path).expect("the container opens"),
            &path,
            &planned_for(CPV, 1, &path),
            &root_targets(),
            &fixture::keyring(&trusted),
        )
        .expect_err("a forged Manifest is refused");
        assert!(matches!(err, GentooError::Signature { .. }), "{err:?}");
    }

    #[test]
    fn the_image_reads_back_as_the_tree_it_describes() {
        let dir = Scratch::for_test("gentoo-gpkg", "image");
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let path = dir.join("package.gpkg.tar");
        Built::ordinary().write(&path, &key);
        let package = Package::read(
            std::fs::File::open(&path).expect("the container opens"),
            &path,
            &planned_for(CPV, 1, &path),
            &root_targets(),
            &fixture::keyring(&key),
        )
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
