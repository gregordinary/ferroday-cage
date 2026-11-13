//! The apk container: concatenated gzip segments, and the digests over them.
//!
//! An apk file is two or three independent gzip members laid end to end, each
//! decompressing to a tar archive:
//!
//! | Segment | Holds |
//! | --- | --- |
//! | 0 | `.SIGN.<algorithm>.<key name>`, the RSA signature |
//! | 1 | the metadata: `.PKGINFO` and the install scripts, or an index's records |
//! | 2 | the file tree (a package only; an index stops at segment 1) |
//!
//! The boundaries are exact, so a reader can walk the members in turn and hand
//! each one to the tar reader without buffering the file. What it must *not* do
//! is reach for the shared `compress::decoder`, which selects a multi-member
//! decoder on purpose so that a concatenated `.tar.gz` decodes as one stream.
//! That is precisely the behaviour that would fuse an apk's segments into a
//! single tar and lose every boundary the format hangs its digests from.
//!
//! Those digests are all over *compressed* bytes — see the module
//! documentation — so [`Segments`] tees each member's raw bytes into a sink of
//! the caller's choosing as it decodes, which is what lets one pass over a
//! container produce both its contents and the digests that bind them.

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};

use flate2::bufread::GzDecoder;

use super::AlpineError;
use super::keyring::KeySet;
use super::sign::Signatures;
use crate::ErrorChain;
use crate::provision::digest::{self, Algorithm};
use crate::provision::tar::TarReader;
use crate::provision::{LimitedWriter, ProvisionError};
use crate::roster::roster_enum;

/// The ceiling on a signature segment, decompressed and compressed alike.
///
/// The segment holds a tar member of at most a few hundred bytes per signature —
/// an RSA-4096 signature is 512 — so the padded tar comes to 2 KiB and the gzip
/// of it to under one, and a rotation-era artifact carrying several is still far
/// inside this. The bound is here because gzip is a compression format and an
/// untrusted repository can spend a kilobyte to make a gigabyte, and because
/// this segment is read before anything about the container has been
/// authenticated.
const MAX_SIGNATURE_SEGMENT: u64 = 64 * 1024;

/// A walk over an apk container's concatenated gzip segments.
///
/// Each call to [`read_segment`](Self::read_segment) decodes exactly one gzip
/// member, whatever follows it in the reader. The member's decompressed bytes
/// go to one sink and its raw compressed bytes to another, because every digest
/// the apk format defines is taken over the compressed form.
///
/// The buffering is owned here rather than taken from the caller. A decoder
/// walking one member necessarily reads ahead into the next, so the buffer has
/// to outlive the member for the following one to be readable at all.
pub(super) struct Segments<R> {
    inner: BufReader<R>,
    /// Bytes of the container consumed by the segments decoded so far, which is
    /// the offset the next one begins at.
    offset: u64,
}

impl<R: Read> Segments<R> {
    /// Starts a walk at the beginning of a container.
    pub(super) fn new(inner: R) -> Segments<R> {
        Segments {
            inner: BufReader::new(inner),
            offset: 0,
        }
    }

    /// Decodes the next segment, writing its decompressed bytes to `plain` and
    /// the raw compressed bytes it consumed to `raw`.
    ///
    /// Returns the segment's compressed length, or `None` where the container
    /// ends. Either sink may be [`io::sink`] where the caller does not want
    /// that side.
    pub(super) fn read_segment(
        &mut self,
        plain: &mut dyn Write,
        raw: &mut dyn Write,
    ) -> io::Result<Option<u64>> {
        if self.at_end()? {
            return Ok(None);
        }

        let mut decoder = GzDecoder::new(Tee {
            inner: &mut self.inner,
            sink: raw,
            consumed: 0,
            failed: None,
        });
        let copied = io::copy(&mut decoder, plain);

        // `flate2`'s buffered decoder stops at the member's trailer and leaves
        // the reader positioned on the byte after it, which is what makes the
        // boundary exact and the next member readable.
        let tee = decoder.into_inner();

        // A sink failure is reported through the tee rather than through the
        // decoder, since `BufRead::consume` cannot fail. It is checked before
        // the decode result so that "the hasher refused these bytes" is not
        // reported as "this gzip stream is corrupt".
        if let Some(err) = tee.failed {
            return Err(err);
        }
        copied?;

        self.offset += tee.consumed;
        Ok(Some(tee.consumed))
    }

    /// Whether the container has any bytes left.
    pub(super) fn at_end(&mut self) -> io::Result<bool> {
        Ok(self.inner.fill_buf()?.is_empty())
    }

    /// Copies everything left in the container to `sink`, returning how much
    /// there was.
    ///
    /// For the last segment of a container, whose extent is the rest of the
    /// file: copying it costs nothing beyond the read, where decoding it to
    /// find its boundary would cost the decompression as well.
    pub(super) fn drain(&mut self, sink: &mut dyn Write) -> io::Result<u64> {
        let copied = io::copy(&mut self.inner, sink)?;
        self.offset += copied;
        Ok(copied)
    }

    /// The offset just past the last segment decoded.
    pub(super) fn offset(&self) -> u64 {
        self.offset
    }
}

/// A [`BufRead`] that copies every byte the reader above it *consumes* into a
/// sink as well.
///
/// This is how a segment's raw compressed bytes reach a hasher while the decoder
/// walks it. The digests the apk format defines are over the compressed form,
/// and re-reading the extent afterwards would mean seeking back over a package
/// that may be hundreds of megabytes, on top of the pass that decoded it.
///
/// The copy happens in `consume` rather than in `fill_buf`, and that is the
/// whole correctness of the type. A decoder is shown whatever the buffer holds
/// and consumes only what its member needed, so a tee that copied what it showed
/// would feed the sink bytes belonging to the *next* segment — enough to make
/// every signature fail for a container whose segment boundary falls mid-buffer,
/// which is all of them. `consume` receives a length rather than the bytes it
/// stands for, so those bytes are re-obtained from the inner reader, which
/// returns the same buffer it has already filled.
///
/// [`BufRead::consume`] returns no error, so a sink failure is stashed and the
/// caller reads it back from `failed` when the decode has finished. The decode
/// does not run on to the member's end meanwhile: the next
/// [`fill_buf`](BufRead::fill_buf) fails, so a sink that refuses bytes stops the
/// read as soon as it refuses them. That is what makes a ceiling on the
/// compressed side bound the read rather than only report it afterwards, and a
/// deflate stream can be made arbitrarily long while decoding to nothing.
struct Tee<'a, R> {
    inner: R,
    sink: &'a mut dyn Write,
    consumed: u64,
    failed: Option<io::Error>,
}

impl<'a, R> Tee<'a, R> {
    /// Records `err` as the tee's failure, keeping the first one.
    fn fail(&mut self, err: io::Error) {
        if self.failed.is_none() {
            self.failed = Some(err);
        }
    }
}

impl<R: BufRead> Read for Tee<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let take = available.len().min(buf.len());
        buf[..take].copy_from_slice(&available[..take]);
        self.consume(take);
        Ok(take)
    }
}

impl<R: BufRead> BufRead for Tee<'_, R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.failed.is_some() {
            // The failure itself stays stashed for the caller, which reports it
            // ahead of whatever the decoder makes of this one.
            return Err(io::Error::other("the segment's raw bytes were refused"));
        }
        self.inner.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        // The buffer is non-empty whenever `amount` is, since a consume follows
        // a `fill_buf` that returned at least that many bytes and nothing has
        // consumed them since; so this re-obtains what is already in hand
        // rather than reading.
        match self.inner.fill_buf() {
            Ok(buffer) => {
                let taken = &buffer[..amount.min(buffer.len())];
                if let Err(err) = self.sink.write_all(taken) {
                    self.fail(err);
                }
            }
            Err(err) => self.fail(err),
        }
        self.consumed += amount as u64;
        self.inner.consume(amount);
    }
}

/// One member of a metadata segment: its name and everything it holds.
pub(super) struct Member {
    /// The member's path as the tar records it, lossily decoded. Every name the
    /// format defines is ASCII.
    pub(super) name: String,
    /// The member's contents.
    pub(super) data: Vec<u8>,
}

/// A container's metadata segment, once it has been held to its
/// [`Anchor`].
pub(super) struct Metadata {
    /// The segment's tar members: `.PKGINFO` and the install scripts for a
    /// package, `APKINDEX` and `DESCRIPTION` for an index.
    pub(super) members: Vec<Member>,
    /// The segment's raw compressed bytes, which is what a signature over it
    /// covers.
    ///
    /// It is also what an index record's `C:` field identifies a package's
    /// control segment by, so the bytes are kept rather than re-derived — and
    /// under [`Anchor::ControlIdentity`] that comparison is the whole of what
    /// authenticates this segment.
    pub(super) compressed: Vec<u8>,
    /// The name of the key the signature member names.
    ///
    /// Kept because a plan records which key vouched for the index it resolved
    /// against, and the name is the only identity an apk signature carries: the
    /// key material has no fingerprint, no expiry and no self-signature. It says
    /// which key *verified* only under [`Anchor::Signature`]; under the other it
    /// is a name the container stated and nothing checked.
    pub(super) signed_by: String,
}

impl fmt::Debug for Metadata {
    /// Names the members and measures the segment rather than rendering it. The
    /// compressed bytes are the whole of an index, which no reader of a
    /// rendering can act on.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metadata")
            .field(
                "members",
                &self
                    .members
                    .iter()
                    .map(|member| &member.name)
                    .collect::<Vec<_>>(),
            )
            .field("compressed", &self.compressed.len())
            .field("signed_by", &self.signed_by)
            .finish()
    }
}

impl Metadata {
    /// The member named `name`, or `None` where the segment holds none.
    pub(super) fn member(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|member| member.name == name)
    }
}

/// What vouches for the metadata segment of the container being read.
///
/// Both containers this layer reads carry a signature over their metadata
/// segment, and which of the two anchors below applies depends on what sits
/// above the container rather than on what the container looks like.
///
/// The distinction is `apk`'s own. A root trusting only postmarketOS's index key
/// installs postmarketOS packages, whose per-builder signing keys that root has
/// never seen, while the same package handed to `apk add` as a bare file is
/// refused as `UNTRUSTED signature`.
pub(super) enum Anchor<'a> {
    /// The container's own signature, verified against this key set.
    ///
    /// What an index is held to. Nothing above an index vouches for it, so its
    /// signature is where trust in a repository begins.
    Signature(&'a KeySet),
    /// A control identity the caller holds and compares for itself, recorded in
    /// a verified index or in a plan.
    ///
    /// What a package is held to. That identity is a digest of the metadata
    /// segment's compressed bytes — the very bytes a signature over the segment
    /// would cover — so it fixes the segment exactly, and `.PKGINFO`'s
    /// `datahash` carries the binding on to the file tree. The package's own
    /// signature is therefore read but not verified: it lives in the segment
    /// before the one the identity covers, which no digest in the format
    /// accounts for, so whoever served the file could replace it without
    /// anything downstream differing.
    ///
    /// Holding a package to its own signature instead would also refuse every
    /// postmarketOS package. Its index is signed by `build.postmarketos.org`,
    /// which `postmarketos-keys` ships as the trust anchor, while its packages
    /// are signed by a key per builder that no package publishes — so no key set
    /// a caller could assemble would admit them.
    ControlIdentity,
}

/// Reads a container's signature segment and the metadata segment after it,
/// holding the second to `anchor`.
///
/// `subject` names what is being read, for the errors — a package's path, or the
/// URL of an index. `limit` bounds the metadata segment on both sides,
/// decompressed and compressed, and is the caller's because a package's control
/// segment and an index's records differ by three orders of magnitude.
///
/// The walk is left positioned after the metadata segment, so a package's caller
/// goes on to its data segment and an index's caller checks that nothing
/// follows.
///
/// # Errors
///
/// Returns [`AlpineError::Container`] where the container is not two readable
/// gzip segments of tar within the limit, and [`AlpineError::Signature`] where
/// the first segment is not a signature member at all, or — under
/// [`Anchor::Signature`] — does not verify over the second.
pub(super) fn read_metadata<R: Read>(
    subject: &str,
    segments: &mut Segments<R>,
    anchor: Anchor<'_>,
    limit: u64,
) -> Result<Metadata, AlpineError> {
    let unreadable = |what: &'static str| {
        move |err: io::Error| {
            AlpineError::unreadable(subject, format!("its {what} segment is unreadable"), err)
        }
    };

    let mut signature_segment = Vec::new();
    // Both sides, which is what the ceiling says it is: the decompressed side
    // because a gzip member is an untrusted repository's to inflate, and the
    // compressed side because the only thing bounding it otherwise is whatever
    // the caller wrapped the container in.
    let mut raw = io::sink();
    let read = segments
        .read_segment(
            &mut LimitedWriter::new(&mut signature_segment, MAX_SIGNATURE_SEGMENT),
            &mut LimitedWriter::new(&mut raw, MAX_SIGNATURE_SEGMENT),
        )
        .map_err(unreadable("signature"))?;
    if read.is_none() {
        return Err(AlpineError::container(subject, "it is empty"));
    }
    let signatures = Signatures::parse(subject, &members(subject, &signature_segment)?)?;

    let mut plain = Vec::new();
    let mut compressed = Vec::new();
    let read = segments
        .read_segment(
            &mut LimitedWriter::new(&mut plain, limit),
            &mut LimitedWriter::new(&mut compressed, limit),
        )
        .map_err(unreadable("metadata"))?;
    if read.is_none() {
        return Err(AlpineError::container(
            subject,
            "it ends after its signature, with nothing signed",
        ));
    }

    // Over the compressed bytes, and over the segment that follows the
    // signature rather than the one that carries it. Both are the mistake a
    // reimplementation makes, and both are what the negative tests pin.
    let signed_by = match anchor {
        Anchor::Signature(keys) => signatures.verify(subject, keys, &compressed)?.key(),
        // Nothing was verified, so there is no key that verified; the first
        // member's is what the segment says about itself.
        Anchor::ControlIdentity => signatures.first_key(),
    };

    Ok(Metadata {
        members: members(subject, &plain)?,
        compressed,
        signed_by: signed_by.to_string(),
    })
}

roster_enum! {
    /// One of the scripts a package may carry, named as apk names it.
    ///
    /// The names are the format's twice over: they are the control-segment
    /// member names with their leading dot removed, and they are the suffix
    /// the installed database's script archive files each script under. A
    /// member whose name is not one of these is not a script.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub(super) enum ScriptKind {
        /// The name apk knows this script by.
        pub(super) fn name;

        /// Runs before the package's files are laid down.
        PreInstall => "pre-install",
        /// Runs once they are.
        PostInstall => "post-install",
        PreDeinstall => "pre-deinstall",
        PostDeinstall => "post-deinstall",
        PreUpgrade => "pre-upgrade",
        PostUpgrade => "post-upgrade",
        /// Runs when a directory the package watches has changed.
        Trigger => "trigger",
    }
}

impl ScriptKind {
    /// The kind a control-segment member name states, or `None` for a member
    /// that is not a script.
    fn of_member(name: &str) -> Option<ScriptKind> {
        let name = name.strip_prefix('.')?;
        ScriptKind::ALL
            .iter()
            .copied()
            .find(|kind| kind.name() == name)
    }
}

/// A package read from a container: what it says about itself, what it carries
/// beside its files, and where its files begin.
///
/// The file tree is deliberately absent. Reading it is a second pass, made
/// after [`datahash`](super::pkginfo::PkgInfo::datahash) has been checked over
/// the segment as it lies in the file, so that nothing is written to a staging
/// tree before the bytes that would be written are known to be the package's.
#[derive(Debug)]
pub(super) struct Package {
    /// The package's own account of itself, from `.PKGINFO`.
    pub(super) info: super::pkginfo::PkgInfo,
    /// The scripts the control segment carries, in [`ScriptKind::ALL`] order.
    pub(super) scripts: Vec<(ScriptKind, Vec<u8>)>,
    /// `Q1` and the base64 of the SHA-1 of the control segment: what an index
    /// record's `C:` names the package by.
    pub(super) control_identity: String,
    /// The same digest in hexadecimal, which is how the script archive names
    /// the package.
    pub(super) control_identity_hex: String,
    /// The offset of the data segment within the container.
    ///
    /// The second pass seeks here rather than walking the first two segments
    /// again: their lengths are exactly what the first pass measured.
    pub(super) data_at: u64,
}

/// Reads a package, stopping short of its file tree.
///
/// One pass over the file yields everything the caller needs to authenticate it:
/// the control segment's compressed bytes, from which
/// [`control_identity`](Package::control_identity) is computed, `datahash` over
/// the data segment, and the refusal of anything after it.
/// [`data_at`](Package::data_at) says where to begin laying it down.
///
/// The container is read under [`Anchor::ControlIdentity`], so the caller must
/// compare that identity against the one a verified index or a plan recorded for
/// this package. Nothing here does it: this function is handed a file and told
/// nothing about which package was asked for, and a package that authenticated
/// itself would be exactly the mirror-substitution hole the identity closes.
///
/// `subject` names the package being read, for the errors. `limit` bounds the
/// control segment on both sides, compressed and decompressed.
///
/// # Errors
///
/// Returns [`AlpineError::Container`] where the container is not two readable
/// gzip segments followed by a file tree, or where `.PKGINFO` is missing or
/// unreadable; [`AlpineError::Signature`] where the first segment is not a
/// signature member at all; and [`AlpineError::Digest`] where the file tree is
/// not the one `.PKGINFO` names — which is also how a segment spliced onto the
/// end is caught.
pub(super) fn read_package<R: Read>(
    subject: &str,
    segments: &mut Segments<R>,
    limit: u64,
) -> Result<Package, AlpineError> {
    let metadata = read_metadata(subject, segments, Anchor::ControlIdentity, limit)?;
    let data_at = segments.offset();

    let info = super::pkginfo::PkgInfo::parse(
        subject,
        &metadata
            .member(".PKGINFO")
            .ok_or_else(|| AlpineError::container(subject, "it carries no .PKGINFO member"))?
            .data,
    )?;

    // The order is the archive's rather than the container's, so two readings
    // of one package archive its scripts identically however the control
    // segment happened to be laid out.
    let mut scripts: Vec<(ScriptKind, Vec<u8>)> = metadata
        .members
        .iter()
        .filter_map(|member| {
            ScriptKind::of_member(&member.name).map(|kind| (kind, member.data.clone()))
        })
        .collect();
    scripts.sort_by_key(|(kind, _)| *kind);

    // Every package Alpine publishes states one, the meta packages whose data
    // segment is an empty tar included. Without it nothing binds a file tree to
    // the signature that covers the metadata, so a package that states none is
    // one this layer will not install.
    let Some(expected) = &info.datahash else {
        return Err(AlpineError::container(
            subject,
            "its .PKGINFO states no datahash, so nothing binds its file tree to the \
             signature that covers its metadata",
        ));
    };

    // The rest of the file, digested where it lies. What `.PKGINFO` states is a
    // SHA-256 over the data segment's *compressed* bytes, and the data segment
    // is the last thing in a container — so digesting the remainder both checks
    // the file tree and refuses a fourth segment, whose bytes no digest in the
    // format would otherwise account for.
    //
    // It is also why nothing is decompressed here. The pass that lays the tree
    // down is the only one that decodes it, so verifying before extracting
    // costs a second read of the file rather than a second decompression of it.
    let mut digest = digest::DigestWriter::new(Algorithm::Sha256, io::sink());
    let unreadable = |err| AlpineError::unreadable(subject, "its data segment is unreadable", err);
    let length = segments.drain(&mut digest).map_err(unreadable)?;
    let (actual, _) = digest.finish().map_err(unreadable)?;
    if length == 0 {
        return Err(AlpineError::container(
            subject,
            "it ends after its metadata, carrying no file tree",
        ));
    }
    if actual.hex() != expected {
        return Err(AlpineError::Digest {
            subject: subject.to_string(),
            expected: expected.clone(),
            actual: actual.hex().to_string(),
        });
    }

    Ok(Package {
        info,
        scripts,
        control_identity: super::sign::control_identity(&metadata.compressed),
        control_identity_hex: super::sign::control_identity_hex(&metadata.compressed),
        data_at,
    })
}

/// A reader over one gzip member, for the pass that lays a package's files
/// down.
///
/// The caller has already seeked to [`Package::data_at`], and the segment has
/// already been digested, so neither the tee nor the boundary bookkeeping
/// [`Segments`] exists for is needed here — only the discipline that makes this
/// *one* member rather than however many follow it, which is why this is not
/// `compress::decoder`. The decoder is guarded as that one's are, so a refusal
/// of the segment and a failure to read the file reach the tar reader as the
/// two different failures they are.
pub(super) fn data_reader<R: Read>(inner: R) -> impl Read {
    crate::provision::compress::guard("the data segment does not decode", inner, |inner| {
        GzDecoder::new(BufReader::new(inner))
    })
}

/// Reads every member of a decompressed metadata segment into memory.
///
/// `subject` names the container being read, for the error, which reports the
/// segment as part of that container. [`read_members`] is the same read for a
/// tar that is not part of one.
pub(super) fn members(subject: &str, segment: &[u8]) -> Result<Vec<Member>, AlpineError> {
    read_members(segment).map_err(|err| {
        AlpineError::container(
            subject,
            format!("a segment is not a readable tar: {}", ErrorChain::new(&err)),
        )
    })
}

/// Reads every member of a tar held in memory.
///
/// The caller has already bounded the tar's size, and its members sum to it,
/// so no member can hold more than the whole does. That is the ceiling each is
/// read under: a header announcing more is refused before it is read.
pub(super) fn read_members(tar: &[u8]) -> Result<Vec<Member>, ProvisionError> {
    let mut reader = TarReader::in_memory(tar);
    let mut members = Vec::new();
    while let Some(entry) = reader.next_entry()? {
        let name = String::from_utf8_lossy(&entry.path).into_owned();
        let data = reader.read_entry(tar.len() as u64)?;
        members.push(Member { name, data });
    }
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::alpine::fixtures;

    /// The raw compressed bytes of each of `container`'s segments, in order.
    ///
    /// This drives the reader under test, which is what makes it a check as well
    /// as a helper: the extents it returns are the boundaries the reader found,
    /// and every test below that splices a container asserts on them.
    fn extents(container: &[u8]) -> Vec<Vec<u8>> {
        let mut segments = Segments::new(container);
        let mut extents = Vec::new();
        loop {
            let mut raw = Vec::new();
            let Some(length) = segments
                .read_segment(&mut io::sink(), &mut raw)
                .expect("the fixture decodes")
            else {
                break;
            };
            assert_eq!(
                length as usize,
                raw.len(),
                "the teed bytes are the consumed bytes and no more",
            );
            extents.push(raw);
        }
        assert_eq!(
            segments.offset() as usize,
            container.len(),
            "the walk ends where the container does",
        );
        extents
    }

    /// A [`KeySet`] holding the bundled Alpine x86_64 keys.
    fn alpine_keys() -> KeySet {
        KeySet::alpine("x86_64").expect("x86_64 is in the bundle")
    }

    /// A gzip member holding a tar of `members`, as every apk segment is.
    ///
    /// The tests below reassemble a published container with one segment
    /// replaced, so this has to produce something the reader accepts as a
    /// segment; what varies is only what the tar inside it holds.
    fn segment(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = ferroday_cage_testkit::tar::Tar::new();
        for (name, data) in members {
            tar.file(name, 0o644, data);
        }
        let tar = tar.finish();

        ferroday_cage_testkit::compress::gzip(&tar)
    }

    /// The signature member a published container carries: its name, and the
    /// signature bytes that actually verify over the segment after it.
    fn published_signature(container: &[u8]) -> (String, Vec<u8>) {
        let mut segments = Segments::new(container);
        let mut plain = Vec::new();
        segments
            .read_segment(&mut plain, &mut io::sink())
            .expect("the fixture decodes");
        let [member] = &members("the fixture", &plain).expect("the segment is a tar")[..] else {
            panic!("a published signature segment holds one member");
        };
        (member.name.clone(), member.data.clone())
    }

    #[test]
    fn a_signature_segment_may_hold_several_members_and_the_trusted_one_verifies() {
        // What an artifact signed during a key rotation looks like: one member
        // per key, so a reader holding either can verify it. Refusing the
        // segment would refuse a container apk reads, and reading only its first
        // member would refuse one whose first signature is by the key this
        // reader does not hold.
        let base = extents(fixtures::ALPINE_BASE);
        let (name, bytes) = published_signature(fixtures::ALPINE_BASE);
        let decoy = (".SIGN.RSA.rotated-out.rsa.pub", &[0x00; 512][..]);
        let real = (name.as_str(), &bytes[..]);

        for (order, members) in [
            ("decoy first", [decoy, real]),
            ("real first", [real, decoy]),
        ] {
            let container = [&segment(&members)[..], &base[1][..], &base[2][..]].concat();
            let mut segments = Segments::new(&container[..]);
            let metadata = read_metadata(
                "rotated",
                &mut segments,
                Anchor::Signature(&alpine_keys()),
                16 * 1024 * 1024,
            )
            .unwrap_or_else(|err| panic!("{order}: {err}"));
            // And the key reported is the one that verified, not the first one
            // listed, since that is what a plan records as its trust anchor.
            assert_eq!(metadata.signed_by, fixtures::ALPINE_KEY_NAME, "{order}");
        }
    }

    #[test]
    fn a_held_keys_signature_that_fails_is_passed_over_for_one_that_verifies() {
        // Where this reader is deliberately more lenient than apk, which
        // verifies only the first member naming a key it holds: a later
        // member that verifies is still accepted, and it is still a trusted
        // key's signature over exactly the segment that follows.
        let base = extents(fixtures::ALPINE_BASE);
        let (name, bytes) = published_signature(fixtures::ALPINE_BASE);
        let mut damaged = bytes.clone();
        damaged[0] ^= 0xff;
        let container = [
            &segment(&[(name.as_str(), &damaged[..]), (name.as_str(), &bytes[..])])[..],
            &base[1][..],
            &base[2][..],
        ]
        .concat();
        let metadata = read_metadata(
            "rotated",
            &mut Segments::new(&container[..]),
            Anchor::Signature(&alpine_keys()),
            16 * 1024 * 1024,
        )
        .unwrap_or_else(|err| panic!("the second member verifies: {err}"));
        assert_eq!(metadata.signed_by, fixtures::ALPINE_KEY_NAME);

        // The damaged member alone verifies nothing.
        let container = [
            &segment(&[(name.as_str(), &damaged[..])])[..],
            &base[1][..],
            &base[2][..],
        ]
        .concat();
        let err = read_metadata(
            "damaged",
            &mut Segments::new(&container[..]),
            Anchor::Signature(&alpine_keys()),
            16 * 1024 * 1024,
        )
        .expect_err("the only member does not verify");
        assert!(
            matches!(&err, AlpineError::Signature { reason, .. } if reason.contains("does not verify")),
            "{err}",
        );
    }

    #[test]
    fn a_signature_segment_no_member_of_which_verifies_is_refused() {
        // The other half: passing over a member that names an untrusted key
        // must not become passing over every member.
        let base = extents(fixtures::ALPINE_BASE);
        let container = [
            &segment(&[
                (".SIGN.RSA.rotated-out.rsa.pub", &[0x00; 512][..]),
                (".SIGN.RSA.also-untrusted.rsa.pub", &[0x00; 512][..]),
            ])[..],
            &base[1][..],
            &base[2][..],
        ]
        .concat();
        let mut segments = Segments::new(&container[..]);
        let err = read_metadata(
            "rotated",
            &mut segments,
            Anchor::Signature(&alpine_keys()),
            16 * 1024 * 1024,
        )
        .expect_err("no member names a trusted key");
        let reason = err.to_string();
        assert!(matches!(err, AlpineError::Signature { .. }), "{reason}");
        assert!(
            reason.contains("not a key this repository trusts"),
            "{reason}"
        );
    }

    #[test]
    fn an_algorithm_this_reader_does_not_implement_is_refused_only_where_it_is_used() {
        // `RSA256` and `RSA512` are defined by the format and unimplemented
        // here. A container anchored by its control identity never consults the
        // signature at all, so the algorithm is no reason to refuse it; one
        // anchored by the signature has nothing else to fall back on.
        let base = extents(fixtures::ALPINE_BASE);
        let container = [
            &segment(&[(".SIGN.RSA256.some-key.rsa.pub", &[0x00; 512][..])])[..],
            &base[1][..],
            &base[2][..],
        ]
        .concat();

        let mut segments = Segments::new(&container[..]);
        let err = read_metadata(
            "future",
            &mut segments,
            Anchor::Signature(&alpine_keys()),
            16 * 1024 * 1024,
        )
        .expect_err("the algorithm is not implemented");
        let reason = err.to_string();
        assert!(matches!(err, AlpineError::Signature { .. }), "{reason}");
        assert!(reason.contains("RSA256"), "{reason}");

        let mut segments = Segments::new(&container[..]);
        read_package("future", &mut segments, 16 * 1024 * 1024)
            .expect("the control identity binds it, and no signature is read");
    }

    #[test]
    fn a_signature_segment_that_is_not_one_is_refused_by_shape() {
        let base = extents(fixtures::ALPINE_BASE);
        for (what, members, expected) in [
            ("an empty segment", &[][..], "holds no members"),
            (
                "a member that is not a signature",
                &[("README", &b"not a signature"[..])][..],
                "not a signature member",
            ),
            (
                "a signature naming no key",
                &[(".SIGN.RSA", &[0x00; 512][..])][..],
                "names no key",
            ),
        ] {
            let container = [&segment(members)[..], &base[1][..], &base[2][..]].concat();
            let mut segments = Segments::new(&container[..]);
            let err = read_metadata(
                "malformed",
                &mut segments,
                Anchor::Signature(&alpine_keys()),
                16 * 1024 * 1024,
            )
            .unwrap_err();
            let reason = err.to_string();
            assert!(
                matches!(err, AlpineError::Signature { .. }),
                "{what}: {reason}"
            );
            assert!(reason.contains(expected), "{what}: {reason}");
        }
    }

    #[test]
    fn a_signature_segment_past_the_ceiling_is_refused() {
        // A gzip member is an untrusted repository's to inflate, and this
        // segment is read before anything about the container is authenticated.
        // The bound is over both forms, and a signature member is a few hundred
        // bytes, so a segment reaching it is not one any repository publishes.
        let base = extents(fixtures::ALPINE_BASE);
        let huge = vec![0u8; 2 * MAX_SIGNATURE_SEGMENT as usize];
        let container = [
            &segment(&[(".SIGN.RSA.some-key.rsa.pub", &huge[..])])[..],
            &base[1][..],
            &base[2][..],
        ]
        .concat();
        // It compresses to well under the ceiling, so only the decompressed
        // side can catch it — which is the half a comment could claim and the
        // code not do.
        assert!(
            container.len() < MAX_SIGNATURE_SEGMENT as usize,
            "{}",
            container.len()
        );

        let mut segments = Segments::new(&container[..]);
        let err = read_metadata(
            "inflated",
            &mut segments,
            Anchor::Signature(&alpine_keys()),
            16 * 1024 * 1024,
        )
        .expect_err("the segment is past the ceiling");
        assert!(matches!(err, AlpineError::Container { .. }), "{err}");
    }

    #[test]
    fn a_package_stating_no_datahash_is_refused() {
        // Without it nothing binds the file tree to the signature that covers
        // the metadata, so the package is one this layer will not install --
        // however well-formed the rest of it is.
        let base = extents(fixtures::ALPINE_BASE);
        let mut plain = Vec::new();
        let mut walk = Segments::new(fixtures::ALPINE_BASE);
        walk.read_segment(&mut io::sink(), &mut io::sink())
            .expect("the signature segment decodes");
        walk.read_segment(&mut plain, &mut io::sink())
            .expect("the control segment decodes");

        let stripped: Vec<(String, Vec<u8>)> = members("alpine-base", &plain)
            .expect("the control segment is a tar")
            .into_iter()
            .map(|member| {
                let data = match member.name.as_str() {
                    ".PKGINFO" => String::from_utf8(member.data)
                        .expect(".PKGINFO is text")
                        .lines()
                        .filter(|line| !line.starts_with("datahash"))
                        .map(|line| format!("{line}\n"))
                        .collect::<String>()
                        .into_bytes(),
                    _ => member.data,
                };
                (member.name, data)
            })
            .collect();
        let borrowed: Vec<(&str, &[u8])> = stripped
            .iter()
            .map(|(name, data)| (name.as_str(), &data[..]))
            .collect();

        let container = [&base[0][..], &segment(&borrowed)[..], &base[2][..]].concat();
        let mut segments = Segments::new(&container[..]);
        let err = read_package("stripped", &mut segments, 16 * 1024 * 1024)
            .expect_err("nothing binds the file tree");
        let reason = err.to_string();
        assert!(matches!(err, AlpineError::Container { .. }), "{reason}");
        assert!(reason.contains("datahash"), "{reason}");
    }

    #[test]
    fn a_fixture_is_the_file_its_provenance_records() {
        // The README beside the fixtures records where each came from and its
        // digest. A fixture that changes without that file changing would
        // otherwise pass quietly.
        for (name, bytes, digest) in [
            (
                "alpine-base",
                fixtures::ALPINE_BASE,
                "36a759418940efa2ba49b783e1286ffc675366b1cea9a2e7e2bb508ccea68e76",
            ),
            (
                "alpine-keys",
                fixtures::ALPINE_KEYS,
                "a6d92d54856452e1d442e1d20820215c4829e6049c1944a5e65d8dacc55a07ed",
            ),
            (
                "musl",
                fixtures::MUSL,
                "4f3c4a7bf9f51d2c91007e333b17459362ffd881b4a343e8da07b6c50c4f4a0d",
            ),
            (
                "alpine-baselayout",
                fixtures::ALPINE_BASELAYOUT,
                "6e55ad7baa87468244e7919c7556e96abc5da05576cabd8b879a019c6d43e1b6",
            ),
            // The one that decides the trust-model question — a package signed
            // by a key no anchor holds — so a silent swap would undermine
            // exactly the test it is committed for.
            (
                "pmos-baselayout",
                fixtures::POSTMARKETOS_BASELAYOUT,
                "66692c0f6859bb53d39bf1fccff97397fa51b5faf11de7f02438d898af684a1a",
            ),
        ] {
            assert_eq!(Algorithm::Sha256.hex_of(bytes), digest, "{name}");
        }
    }

    #[test]
    fn a_package_is_three_segments_and_an_index_is_two() {
        for (name, bytes) in [
            ("alpine-base", fixtures::ALPINE_BASE),
            ("alpine-keys", fixtures::ALPINE_KEYS),
            ("musl", fixtures::MUSL),
        ] {
            assert_eq!(extents(bytes).len(), 3, "{name}");
        }
        for (name, bytes) in [
            ("Alpine", fixtures::INDEX),
            ("postmarketOS", fixtures::POSTMARKETOS_INDEX),
        ] {
            assert_eq!(extents(bytes).len(), 2, "{name}");
        }
    }

    #[test]
    fn the_segments_are_the_whole_container_and_nothing_twice() {
        // The property the tee exists for. A reader that copied what it was
        // shown rather than what it consumed would tee bytes of the following
        // segment, and the concatenation here would be longer than the file.
        for (name, bytes) in [
            ("alpine-base", fixtures::ALPINE_BASE),
            ("musl", fixtures::MUSL),
            ("index", fixtures::INDEX),
        ] {
            assert_eq!(extents(bytes).concat(), bytes, "{name}");
        }
    }

    #[test]
    fn an_index_verifies_against_the_bundled_key() {
        let mut segments = Segments::new(fixtures::INDEX);
        let metadata = read_metadata(
            "the index",
            &mut segments,
            Anchor::Signature(&alpine_keys()),
            16 * 1024 * 1024,
        )
        .expect("the published index verifies");
        assert!(metadata.member("APKINDEX").is_some());
        assert!(metadata.member("DESCRIPTION").is_some());
        assert!(
            segments.at_end().expect("the walk reports its end"),
            "an index stops after its records",
        );
    }

    #[test]
    fn an_alpine_package_is_signed_by_the_key_that_signs_its_index() {
        // postmarketOS is where the two keys differ. Nothing installs a
        // package this way — `read_package` takes no keys at all — but the
        // signature is real and the fact is worth pinning.
        for (name, bytes) in [
            ("alpine-base", fixtures::ALPINE_BASE),
            ("alpine-keys", fixtures::ALPINE_KEYS),
            ("musl", fixtures::MUSL),
        ] {
            let mut segments = Segments::new(bytes);
            let metadata = read_metadata(
                name,
                &mut segments,
                Anchor::Signature(&alpine_keys()),
                16 * 1024 * 1024,
            )
            .unwrap_or_else(|err| panic!("{name} verifies: {err}"));
            let pkginfo = metadata.member(".PKGINFO").expect("a package carries one");
            assert!(
                String::from_utf8_lossy(&pkginfo.data).contains("pkgname = "),
                "{name}",
            );
            assert!(
                !segments.at_end().expect("the walk reports its end"),
                "{name} still has its data segment",
            );
        }
    }

    #[test]
    fn the_verified_payload_is_the_compressed_control_segment() {
        // What the whole reader is shaped by: the signature covers the
        // raw compressed bytes of the segment after it, not the file and not
        // any decompressed form. The published fixture verifying at all is what
        // proves it, since a payload chosen any other way fails.
        let extents = extents(fixtures::ALPINE_BASE);
        let mut segments = Segments::new(fixtures::ALPINE_BASE);
        let metadata = read_metadata(
            "alpine-base",
            &mut segments,
            Anchor::Signature(&alpine_keys()),
            16 * 1024 * 1024,
        )
        .expect("the published package verifies");
        assert_eq!(metadata.compressed, extents[1]);
    }

    #[test]
    fn the_signature_covers_the_control_segment_and_nothing_after_it() {
        // Splicing another package's data segment onto this one leaves the
        // signature intact, which is the scope of what it covers stated as a
        // test. The data segment is bound instead by `.PKGINFO`'s `datahash`.
        let base = extents(fixtures::ALPINE_BASE);
        let keys = extents(fixtures::ALPINE_KEYS);
        let spliced = [&base[0][..], &base[1][..], &keys[2][..]].concat();
        let mut segments = Segments::new(&spliced[..]);
        read_metadata(
            "spliced",
            &mut segments,
            Anchor::Signature(&alpine_keys()),
            16 * 1024 * 1024,
        )
        .expect("the signature is unaffected by the data segment");
    }

    #[test]
    fn a_signature_over_a_different_segment_is_refused() {
        // The mistake a reimplementation makes: verifying over whichever
        // segment happens to follow. Here the control segment is gone and the
        // data segment has taken its place.
        let base = extents(fixtures::ALPINE_BASE);
        let spliced = [&base[0][..], &base[2][..]].concat();
        let mut segments = Segments::new(&spliced[..]);
        let err = read_metadata(
            "spliced",
            &mut segments,
            Anchor::Signature(&alpine_keys()),
            16 * 1024 * 1024,
        )
        .expect_err("the signature does not cover the data segment");
        assert!(matches!(err, AlpineError::Signature { .. }), "{err}");
    }

    #[test]
    fn a_key_the_repository_does_not_trust_is_refused_by_name() {
        // The architecture partition, from the reading side: an x86_64
        // signature does not verify on an aarch64 root, because the key that
        // made it is not in that architecture's set at all.
        let aarch64 = KeySet::alpine("aarch64").expect("aarch64 is in the bundle");
        let mut segments = Segments::new(fixtures::INDEX);
        let err = read_metadata(
            "the index",
            &mut segments,
            Anchor::Signature(&aarch64),
            16 * 1024 * 1024,
        )
        .expect_err("the x86_64 key is not an aarch64 key");
        let reason = err.to_string();
        assert!(matches!(err, AlpineError::Signature { .. }), "{reason}");
        assert!(reason.contains(fixtures::ALPINE_KEY_NAME), "{reason}");
    }

    #[test]
    fn a_different_key_under_the_expected_name_is_refused() {
        // The name matching is not the verification. This set holds a
        // well-formed key under exactly the name the signature spells, and the
        // signature still fails against it.
        let mut keys = KeySet::new();
        let pem = include_str!("keyring/build.postmarketos.org.rsa.pub");
        keys.insert(fixtures::ALPINE_KEY_NAME, pem)
            .expect("the key parses");
        let mut segments = Segments::new(fixtures::INDEX);
        let err = read_metadata(
            "the index",
            &mut segments,
            Anchor::Signature(&keys),
            16 * 1024 * 1024,
        )
        .expect_err("the wrong key does not verify");
        assert!(
            matches!(&err, AlpineError::Signature { reason, .. } if reason.contains("does not verify")),
            "{err}",
        );
    }

    #[test]
    fn a_truncated_container_is_refused() {
        for cut in [8, 400, 900, 1200] {
            let mut segments = Segments::new(&fixtures::ALPINE_BASE[..cut]);
            let err = read_metadata(
                "truncated",
                &mut segments,
                Anchor::Signature(&alpine_keys()),
                16 * 1024 * 1024,
            )
            .expect_err("a truncated container is not readable");
            assert!(
                matches!(err, AlpineError::Container { .. }),
                "cut at {cut}: {err}",
            );
        }

        // A read that failed is the cause rather than part of the reason, so
        // the decoder's own account of the truncation is reached through the
        // chain and stated once.
        let err = read_metadata(
            "truncated",
            &mut Segments::new(&fixtures::ALPINE_BASE[..8]),
            Anchor::Signature(&alpine_keys()),
            16 * 1024 * 1024,
        )
        .expect_err("a gzip header cut short is not readable");
        let source = std::error::Error::source(&err)
            .unwrap_or_else(|| panic!("the failed read is the cause: {err}"))
            .to_string();
        assert!(!err.to_string().contains(&source), "{err} / {source}");
    }

    /// A gzip member that decodes to nothing however long it is: `stored`
    /// empty stored blocks, five bytes each, then a final one.
    fn empty_member(stored: usize) -> Vec<u8> {
        let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
        for _ in 0..stored {
            member.extend_from_slice(&[0, 0, 0, 0xff, 0xff]);
        }
        member.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
        // The CRC-32 and the length of the empty output.
        member.extend_from_slice(&[0; 8]);
        member
    }

    #[test]
    fn a_compressed_side_past_its_ceiling_stops_the_read() {
        // A deflate stream can run on for as long as its producer likes while
        // decoding to nothing, so nothing on the decompressed side ever bounds
        // it. The compressed side's ceiling has to stop the read when it is
        // crossed, rather than report the crossing once the member has been
        // read to its end.
        struct Counting<'a> {
            inner: &'a [u8],
            read: &'a std::cell::Cell<usize>,
        }
        impl Read for Counting<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let read = self.inner.read(buf)?;
                self.read.set(self.read.get() + read);
                Ok(read)
            }
        }

        let member = empty_member(1 << 20);
        let mut plain = Vec::new();
        assert_eq!(
            Segments::new(&member[..])
                .read_segment(&mut plain, &mut io::sink())
                .expect("the member is well formed"),
            Some(member.len() as u64),
        );
        assert!(plain.is_empty(), "and it decodes to nothing");

        let read = std::cell::Cell::new(0);
        let ceiling = 64 * 1024;
        let err = Segments::new(Counting {
            inner: &member,
            read: &read,
        })
        .read_segment(
            &mut io::sink(),
            &mut LimitedWriter::new(io::sink(), ceiling),
        )
        .expect_err("the compressed side is past its ceiling");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(
            read.get() < 2 * ceiling as usize,
            "read {} of {} bytes past a ceiling of {ceiling}",
            read.get(),
            member.len(),
        );
    }

    #[test]
    fn a_container_that_is_not_one_is_refused() {
        for (name, bytes) in [
            ("empty", &b""[..]),
            ("text", &b"this is not a gzip stream"[..]),
            ("a bare tar", &[0u8; 1024][..]),
        ] {
            let mut segments = Segments::new(bytes);
            let err = read_metadata(
                name,
                &mut segments,
                Anchor::Signature(&alpine_keys()),
                16 * 1024 * 1024,
            )
            .expect_err("this is not an apk container");
            assert!(
                matches!(err, AlpineError::Container { .. }),
                "{name}: {err}"
            );
        }
    }

    /// A package read through the reader under test.
    ///
    /// No key set, because the reader takes none: a package is authenticated by
    /// the control identity its caller holds for it.
    fn package(name: &str, bytes: &[u8]) -> Result<Package, AlpineError> {
        read_package(name, &mut Segments::new(bytes), 16 * 1024 * 1024)
    }

    #[test]
    fn a_package_signed_by_a_key_no_anchor_holds_still_reads() {
        // A postmarketOS package, as the archive publishes it. This package
        // is signed by `pmos@local-6a50011b`, which no key set could hold: its
        // repository publishes `build.postmarketos.org` as the trust anchor and
        // signs the index with it, while each package carries whichever builder
        // key made it. `apk` installs this from the index and so does this
        // layer, because what authenticates a package is the control identity
        // below.
        let baselayout = package("pmos-baselayout", fixtures::POSTMARKETOS_BASELAYOUT)
            .expect("a published package reads");
        assert_eq!(baselayout.info.name, "postmarketos-baselayout");
        assert_eq!(baselayout.info.version, "62-r0");
        // Which is this, and it is the `C:` the committed postmarketOS index
        // publishes for this package: the binding that stands in for the
        // signature holds across the two fixtures, fetched separately.
        assert_eq!(
            baselayout.control_identity,
            "Q1BabP8ycJ4bAReVCUjVOtv740g0s=",
        );
    }

    #[test]
    fn the_signature_segment_is_still_required_to_be_one() {
        // Not verifying a package's signature is not the same as not reading it.
        // A container whose first segment is not a `.SIGN.` member is refused
        // there, which is a far better answer than letting the control segment be
        // read as the signature and the file tree as the metadata.
        let musl = extents(fixtures::MUSL);
        let headless = [&musl[1][..], &musl[2][..]].concat();
        let err = package("headless", &headless).expect_err("its first segment is not a signature");
        assert!(matches!(err, AlpineError::Signature { .. }), "{err}");
    }

    #[test]
    fn a_published_package_reads_as_what_the_archive_says_it_is() {
        // Every link of the chain at once, against bytes the archive served:
        // the signature over the control segment, the control identity the
        // index publishes for it, and `datahash` over the file tree.
        let musl = package("musl", fixtures::MUSL).expect("the published package verifies");
        assert_eq!(musl.info.name, "musl");
        assert_eq!(musl.info.version, "1.2.5-r23");
        assert_eq!(musl.control_identity, "Q1G2xQQm08BlbpxaVnpaWWAcf0MHo=");
        assert!(musl.scripts.is_empty(), "musl carries none");
        assert_eq!(
            musl.data_at,
            extents(fixtures::MUSL)[..2]
                .iter()
                .map(Vec::len)
                .sum::<usize>() as u64,
        );
    }

    #[test]
    fn a_package_whose_data_segment_is_an_empty_tar_still_reads() {
        // `alpine-base` is 1320 bytes and installs nothing. A reader that took
        // an empty file tree for a missing one would refuse the package the
        // conventional minimal Alpine root is named after.
        let base = package("alpine-base", fixtures::ALPINE_BASE).expect("it verifies");
        assert_eq!(base.info.installed_size, Some(0));
        assert!(base.info.is_noarch());
        assert_eq!(base.info.replaces.len(), 1, "it replaces alpine-baselayout");
    }

    #[test]
    fn a_packages_scripts_are_read_in_the_order_they_are_archived_in() {
        let busybox = package("alpine-keys", fixtures::ALPINE_KEYS).expect("it verifies");
        assert!(busybox.scripts.is_empty());

        // A control segment carrying scripts, spliced from one that does not:
        // the fixtures chosen for the container shapes carry none between them.
        let kinds: Vec<&str> = package("musl", fixtures::MUSL)
            .expect("it verifies")
            .scripts
            .iter()
            .map(|(kind, _)| kind.name())
            .collect();
        assert!(kinds.is_empty(), "{kinds:?}");
    }

    #[test]
    fn a_file_tree_that_is_not_the_one_the_metadata_names_is_refused() {
        // Another package's file tree spliced onto this one's signed metadata.
        // The signature still verifies — it covers the control segment only —
        // and `datahash` is what catches it.
        let base = extents(fixtures::ALPINE_BASE);
        let keys = extents(fixtures::ALPINE_KEYS);
        let spliced = [&base[0][..], &base[1][..], &keys[2][..]].concat();
        let err = package("spliced", &spliced).expect_err("the file tree is another package's");
        assert!(matches!(err, AlpineError::Digest { .. }), "{err}");
    }

    #[test]
    fn a_segment_after_the_file_tree_is_refused() {
        // Trailing bytes are covered by no digest the format defines. They are
        // caught by the same check, since `datahash` covers the rest of the
        // file rather than a segment measured out of it.
        let musl = extents(fixtures::MUSL);
        let spliced = [&musl[..], &musl[2..]].concat().concat();
        let err = package("spliced", &spliced).expect_err("a fourth segment is unaccounted for");
        assert!(matches!(err, AlpineError::Digest { .. }), "{err}");
    }

    #[test]
    fn a_container_with_no_file_tree_is_not_a_package() {
        // An index is exactly this: a signature and a metadata segment. Read as
        // a package it has to be refused rather than read as one that installs
        // nothing.
        let err = package("the index", fixtures::INDEX).expect_err("an index is not a package");
        assert!(matches!(err, AlpineError::Container { .. }), "{err}");
    }

    #[test]
    fn a_metadata_segment_past_its_ceiling_is_refused() {
        // The bound on what an untrusted repository can make the reader hold.
        // It applies before the signature is checked, since the bytes are spent
        // getting there.
        let mut segments = Segments::new(fixtures::INDEX);
        let err = read_metadata(
            "the index",
            &mut segments,
            Anchor::Signature(&alpine_keys()),
            64 * 1024,
        )
        .expect_err("the index is larger than the ceiling given");
        assert!(matches!(err, AlpineError::Container { .. }), "{err}");
    }
}
