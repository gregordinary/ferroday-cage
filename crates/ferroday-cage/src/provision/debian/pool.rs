//! Writing a local package pool: the inverse of the release-and-index reader.
//!
//! A build pipeline that produces `.deb`s in dependency order feeds each
//! component's output into the next component's resolution through a local
//! pool: a `dists/`-structured repository of the build's own packages, merged
//! into the bootstrap as a trusted `file://` [`Repository`](super::Repository).
//! The provisioner already consumes such a pool; [`Pool`] produces one.
//!
//! The pool is trusted, not signed: it is a `file://` repository under the
//! caller's control, apt's `[trusted=yes]` case, so no OpenPGP signature is
//! written and none is expected. Authenticity of the pool rests on the caller
//! owning the directory, exactly as the consume side documents for
//! [`trust_unsigned`](super::RepositoryBuilder::trust_unsigned).
//!
//! # Signing
//!
//! A caller that distributes its pool beyond the machine that built it signs it
//! itself: [`Pool::release_path`] names the document to sign and
//! [`Pool::dists_dir`] the directory the signature belongs in, so a signer needs
//! no knowledge of the archive layout. The signature must be an inline
//! cleartext-signed `InRelease`; a detached `Release.gpg` is not read.
//!
//! A signature is only ever as current as the `Release` it was made over, so a
//! publish removes any the pool carries before it writes a new one. A pool
//! between a publish and its signature is unsigned rather than stale-signed: a
//! reader that requires a signature finds none and moves on, instead of
//! verifying a release that a later publish superseded. Signing therefore
//! follows every publish, not just the first.
//!
//! # Copying
//!
//! Publishing does not buffer packages. A `.deb`'s control member is reached by
//! seeking to it, its digest is taken in chunks, and its payload is cloned with
//! [`FICLONE`](rustix::fs::ioctl_ficlone) when the build tree and the pool share
//! a filesystem that can share extents, or streamed through when they cannot.
//! Publishing kernel packages costs the memory of publishing shell scripts, and
//! where the clone applies it costs no additional disk.
//!
//! A clone rather than a hard link is what keeps the pool's promise that a
//! published file's bytes do not change under a reader. A clone has its own
//! inode and shares only storage, so a caller that rewrites its `.deb` in place
//! leaves the pool's copy alone; a hard link would alias the caller's inode and
//! rewrite the pool with it, breaking the digest the `Release` recorded.
//!
//! # Concurrency
//!
//! A build pipeline publishes components in parallel and resolves against the
//! pool while doing so, which makes a publish concurrent with both other
//! publishes and with readers. The two are guarded differently, because a
//! reader cannot be made to participate: it reaches the pool through the
//! [`Fetch`](super::Fetch) seam as an ordinary repository and does not know a
//! pool is what it is reading.
//!
//! Publishes exclude each other with an [`flock`](rustix::fs::flock) on
//! `.lock` in the pool root, held for the whole call. The index is rebuilt by
//! reading what the pool already holds and merging, so without the lock two
//! publishes would each start from the same prior index and the later would
//! drop the earlier's packages.
//!
//! Readers need no lock, because a publish becomes visible to them all at
//! once. Every file is written atomically, and the indexes are additionally
//! written under `by-hash/SHA256/<digest>`, where they are immutable and are
//! never rewritten or removed. The suite's `Release` — the one file a reader
//! consults before it knows which digests to ask for — is written last, with a
//! rename. A reader that has read a `Release` therefore resolves digests that
//! still name the bytes that `Release` described, however many publishes land
//! while it works.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

use rustix::fs::FileType;

use flate2::Compression;
use flate2::write::GzEncoder;

use super::{DebianError, MAX_UNSIZED_INDEX, arch, deb, release, version};
use crate::ErrorChain;
use crate::provision::ProvisionError;
use crate::provision::cache;
use crate::provision::coordinate;
use crate::provision::coordinate::Nesting;
use crate::provision::digest::{self, Algorithm, Digest};
use crate::provision::document::{self, Stanza};
use crate::provision::rooted::Rooted;
use crate::provision::{Staged, file_url, write_atomically};

/// A trusted local package pool, configured then published to.
///
/// `Pool::at` names the repository root — the directory a `file://` mirror URL
/// points at, holding `dists/` and `pool/`. It is created if absent and updated
/// in place otherwise, so [`publish`](Self::publish) is idempotent and
/// incremental: each `.deb` is copied into `pool/`, and
/// `dists/<suite>/<component>/binary-<architecture>/Packages` (with its `.gz`)
/// and `dists/<suite>/Release` are regenerated to describe the pool's current
/// contents.
///
/// A suite accumulates. Its `Release` describes every component and
/// architecture the suite holds, not the one publish that wrote it, so a
/// pipeline that publishes several components into one suite — or one component
/// for several architectures — can reach all of them. Each publish rescans the
/// suite and rewrites the release from what it finds, so
/// [`component`](Self::component) and [`architecture`](Self::architecture)
/// select what this call writes rather than what the suite offers.
///
/// The pool owns its layout, and reports it rather than leaving a caller to
/// rebuild it: [`mirror_url`](Self::mirror_url) is the URL that declares the
/// pool as a [`Repository`](super::Repository), and
/// [`release_path`](Self::release_path) and [`dists_dir`](Self::dists_dir) are
/// what a caller signing the pool needs. All three are available before the
/// first publish.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use ferroday_cage::provision::debian::Pool;
///
/// Pool::at("/srv/pool")
///     .suite("local")
///     .publish(["target/hello_2.10-5_amd64.deb"])?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Pool {
    dir: PathBuf,
    suite: Option<String>,
    component: String,
    architecture: Option<String>,
    date: Option<i64>,
    origin: Option<String>,
    label: Option<String>,
    description: Option<String>,
}

impl Pool {
    /// Returns a pool rooted at `dir`.
    ///
    /// The component defaults to `main`, the architecture to the host's, and
    /// the publication date to the time of the publish; the suite has no
    /// default and must be set. The release's identity fields — `Origin`,
    /// `Label`, and `Description` — have no default and are emitted only when
    /// set.
    pub fn at(dir: impl AsRef<Path>) -> Pool {
        Pool {
            dir: dir.as_ref().to_path_buf(),
            suite: None,
            component: "main".to_string(),
            architecture: None,
            date: None,
            origin: None,
            label: None,
            description: None,
        }
    }

    /// Sets the suite the pool publishes under, for example `local`.
    ///
    /// The emitted `Release` declares it as both `Suite` and `Codename`, so a
    /// repository declaration naming either matches.
    ///
    /// A suite may name a subtree: `dists/<suite>` is a path rather than a
    /// single directory name, which is how Debian's security archive published
    /// `buster/updates` for years and why apt accepts a slashed suite in a
    /// `sources.list` entry. A suite that would write outside the pool is
    /// refused; see [`publish`](Self::publish).
    pub fn suite(mut self, suite: impl Into<String>) -> Pool {
        self.suite = Some(suite.into());
        self
    }

    /// Sets the archive component this publish writes into. The default is
    /// `main`.
    ///
    /// The component selects where this call's packages are indexed, not what
    /// the suite offers: publishing a second component into one suite adds it,
    /// and the release goes on describing both.
    ///
    /// A component may nest, which is how `main/debian-installer` is laid out.
    /// It records in `Components` under its full path, since that is the name a
    /// reader has to ask for to reach it. A component that would write outside
    /// the suite is refused; see [`publish`](Self::publish).
    pub fn component(mut self, component: impl Into<String>) -> Pool {
        self.component = component.into();
        self
    }

    /// Sets the architecture this publish indexes. The default is the host's.
    ///
    /// As with the component, this selects what the call writes rather than what
    /// the suite offers: publishing a second architecture into one suite adds
    /// it, and the release goes on describing both.
    ///
    /// An architecture is always a single path segment, so unlike the suite and
    /// the component it may not contain a slash.
    pub fn architecture(mut self, architecture: impl Into<String>) -> Pool {
        self.architecture = Some(architecture.into());
        self
    }

    /// Pins the `Date` the emitted `Release` carries, in Unix seconds. The
    /// default is the time of the publish.
    ///
    /// The release always carries a `Date`, which is what makes its bytes vary
    /// between two publishes of the same packages. Pinning it makes a publish
    /// byte-reproducible: the indexes are a function of the package set, and
    /// the release is then a function of the indexes and this value.
    ///
    /// The pinned value is a plain timestamp rather than something read from
    /// the environment, so a pipeline that pins a build date pins the pool's
    /// with the same number it gives
    /// [`Export::clamp_mtime`](crate::provision::Export::clamp_mtime).
    ///
    /// Pinning a date does not make the release expire. Expiry is
    /// `Valid-Until`, which the pool does not write; see
    /// [`publish`](Self::publish). A date more than 10 seconds after a
    /// reader's clock is refused, by apt and by a bootstrap reading the pool
    /// alike, as a release that is not valid yet.
    pub fn date(mut self, epoch: i64) -> Pool {
        self.date = Some(epoch);
        self
    }

    /// Sets the release's `Origin`, naming who produced the archive.
    ///
    /// Emitted only when set, and with no default: inventing one would put a
    /// name in an archive the caller did not choose. It is the field apt's own
    /// documentation leads with for pinning — `Pin: release o=Example` — and
    /// the one `apt policy` renders a repository under, so an archive that
    /// leaves it unset is pinned by suite or codename instead.
    ///
    /// Conventionally a short name for the producing organization or build.
    pub fn origin(mut self, origin: impl Into<String>) -> Pool {
        self.origin = Some(origin.into());
        self
    }

    /// Sets the release's `Label`, a short name for the archive itself.
    ///
    /// Emitted only when set. Where [`origin`](Self::origin) names who produced
    /// the archive, the label names the archive, and pins as `Pin: release
    /// l=Example`.
    pub fn label(mut self, label: impl Into<String>) -> Pool {
        self.label = Some(label.into());
        self
    }

    /// Sets the release's `Description`, a one-line summary of the archive.
    ///
    /// Emitted only when set. It is what a client shows a reader who asks what
    /// a repository is, and is informational: nothing resolves or pins on it.
    ///
    /// One line. A release field ends at a newline, so a value carrying one is
    /// refused rather than allowed to continue into the release as further
    /// fields; see [`publish`](Self::publish).
    pub fn description(mut self, description: impl Into<String>) -> Pool {
        self.description = Some(description.into());
        self
    }

    /// The pool's root: the directory it was opened at, holding `dists/` and
    /// `pool/`.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The suite directory, `dists/<suite>` beneath the root.
    ///
    /// This is where the suite's `Release` lives and where a signature over it
    /// belongs, so a caller signing the pool needs this path rather than a
    /// reconstruction of the archive layout.
    ///
    /// The path is what a publish would write, and does not depend on the pool
    /// existing: it is available before the first [`publish`](Self::publish), so
    /// a pipeline can settle where it will sign before it has anything to sign.
    ///
    /// # Errors
    ///
    /// Returns [`DebianError::Config`] when no suite was set, or the suite is
    /// one the pool cannot write; [`publish`](Self::publish) lists the shapes
    /// that are refused.
    pub fn dists_dir(&self) -> Result<PathBuf, DebianError> {
        Ok(self.dir.join("dists").join(self.checked_suite()?))
    }

    /// The path of the suite's `Release`, the document a signature is made over.
    ///
    /// A signature belongs beside it as an inline cleartext-signed `InRelease`,
    /// which is the form the provisioner reads; a detached `Release.gpg` is
    /// ignored. A publish removes either before writing a new `Release`, so a
    /// pool is signed after each publish rather than once.
    ///
    /// # Errors
    ///
    /// Returns [`DebianError::Config`] when no suite was set, or the suite is
    /// one the pool cannot write; [`publish`](Self::publish) lists the shapes
    /// that are refused.
    pub fn release_path(&self) -> Result<PathBuf, DebianError> {
        Ok(self.dists_dir()?.join("Release"))
    }

    /// The `file://` mirror URL naming this pool, ready to hand to
    /// [`RepositoryBuilder::mirror`](super::RepositoryBuilder::mirror).
    ///
    /// The URL addresses the pool root, the directory `dists/` and `pool/` sit
    /// under. A relative root is made absolute against the current directory,
    /// since a `file://` URL cannot carry a relative path; the pool need not
    /// exist yet, so the URL is available before the first
    /// [`publish`](Self::publish). A byte of the root a URL cannot hold as
    /// written, a space among them, is written as a percent escape, as
    /// [`file_url`] writes it.
    ///
    /// # Errors
    ///
    /// Returns [`DebianError::Fetch`] for a current directory that cannot be
    /// read to make a relative root absolute. A path that cannot be named is a
    /// resource that cannot be addressed, so the failure is the transport's.
    pub fn mirror_url(&self) -> Result<String, DebianError> {
        Ok(file_url(&self.dir)?)
    }

    /// The suite the pool publishes under, the one setting with no default,
    /// checked as the path it becomes.
    fn checked_suite(&self) -> Result<&str, DebianError> {
        let Some(suite) = self.suite.as_deref() else {
            return Err(DebianError::config("no suite was given for the pool"));
        };
        coordinate::check("the pool's suite", suite, Nesting::Nested)
            .map_err(DebianError::config)?;
        Ok(suite)
    }

    /// Writes or updates the pool from a set of freshly-built `.deb`s.
    ///
    /// The index keeps the highest version of each package name across what the
    /// pool already held and the newly-added `.deb`s — the rule resolution
    /// applies within one repository — so the pool a caller
    /// writes and the set the resolver later draws from it cannot disagree. A
    /// `.deb` republished at the same version replaces its own entry, so
    /// re-running the call over a superset of a prior run is well-defined. A
    /// `.deb` below the version the index keeps for its name is neither indexed
    /// nor copied into the pool. A version differing from the kept one only by
    /// an epoch is stored at the same path, and copying it would replace the
    /// file the kept entry describes.
    ///
    /// Publishing no `.deb`s to a fresh pool writes a valid, empty repository:
    /// an empty `Packages` and a `Release` that still declares the architecture
    /// and component. The provisioner validates every declared repository's
    /// release at bootstrap, so this lets a pipeline create the pool up front —
    /// before the first component that references it has produced anything —
    /// and have the reference resolve against an empty package set rather than a
    /// missing repository.
    ///
    /// Publishing is safe to run concurrently, in one process or several, and
    /// safe to run while the pool is being resolved against: publishes exclude
    /// each other, and a publish becomes visible to a reader all at once. A
    /// pipeline that builds components in parallel can therefore publish each
    /// one as it finishes, with no coordination of its own. The module
    /// documentation describes how each half is guarded.
    ///
    /// The exception is republishing a package at a version the pool already
    /// holds with *different* bytes, or at a higher one differing from it only
    /// by an epoch: the archive layout stores both at one path, so a reader
    /// partway through resolving the older bytes fails its digest check. In a
    /// build pipeline that means two components produced the same package
    /// version.
    ///
    /// A pool path is not one index's alone. Every suite that publishes a
    /// package into one component stores it at the same path, and so does every
    /// architecture's index for an `Architecture: all` package. A publish that
    /// would replace such a file with other bytes is refused where another
    /// index names the bytes the file holds now, since that index would go on
    /// naming them once they were gone. A refused publish changes nothing: no
    /// `.deb` it was given lands in the pool.
    ///
    /// Each path in `debs` is opened as a file in a tree that is not fully
    /// trusted, because that is where a pipeline takes them from: the output
    /// directory its build sandbox wrote. A symbolic link at the path is
    /// refused rather than followed, so a sandbox cannot have the pool copy a
    /// host file it chose. Anything else that is not a regular file is refused
    /// without being opened, so a named pipe cannot hold the publish waiting
    /// for a writer. The directories above each path are the caller's, and
    /// resolve as any path a caller names does.
    ///
    /// A publish discards any signature the pool carries — an `InRelease` or a
    /// `Release.gpg` a caller wrote over an earlier release — since a signature
    /// describes the `Release` it was made over and this call replaces it. A
    /// caller that signs its pool signs it again after each publish; see the
    /// module documentation.
    ///
    /// The `Release` describes the whole suite. After this call's indexes are
    /// written, the suite is scanned for every `binary-<architecture>` directory
    /// it holds, and the release names one section per index found, with
    /// `Architectures` and `Components` as the unions those sections cover. A
    /// publish therefore adds to what the suite offers instead of replacing it:
    /// a second architecture or a second component published into one suite
    /// leaves the first reachable, and republishing one leaves the other's
    /// sections and digests as they were.
    ///
    /// The scan costs the digest of every index in the suite rather than only
    /// this call's. Indexes are small beside the packages they describe, and the
    /// scan runs under the same lock the rest of the publish does, so a pipeline
    /// publishing components in parallel serializes on it exactly as it already
    /// does.
    ///
    /// The `Release` is stamped with the time of the publish, or with the value
    /// [`date`](Self::date) pinned. It carries no `Valid-Until`, so it never
    /// expires: a pool stays usable for as long as its packages are wanted,
    /// however long after the build that wrote it that is.
    ///
    /// # Errors
    ///
    /// Returns [`DebianError::Config`] when no suite was set, or when the suite,
    /// component, or architecture is one the pool cannot write: an empty value,
    /// one containing whitespace or a control character — neither of which a
    /// release field can name — or another character a URL path cannot carry
    /// as written (such as `%`, `?`, `#`, or one outside ASCII), or one that
    /// would resolve outside the pool through a leading `/`, a `..` segment, or
    /// an empty or `.` segment. The suite and the component may otherwise
    /// contain slashes, since both may name a subtree; the architecture may
    /// not.
    ///
    /// [`origin`](Self::origin), [`label`](Self::label), and
    /// [`description`](Self::description) are free text and take a space, but
    /// are refused empty or carrying a control character: a release field ends
    /// at a newline, so a value holding one would continue into the release as
    /// further fields.
    ///
    /// Returns [`DebianError::Deb`] for a `.deb` the pool cannot index: one that
    /// cannot be read; one whose architecture belongs in neither this pool nor
    /// `all`; one whose `Package` or `Version` is outside the alphabet Debian
    /// policy gives it, since both decide where in the pool the file is written;
    /// one whose control file holds more than one paragraph or names `Filename`,
    /// `Size`, `SHA256`, or `SHA512`, which an index entry takes from the
    /// archive and a package may not claim for itself; one that was rewritten
    /// into a different package while it was being published; and one whose
    /// bytes would replace a pool file another index names at the bytes it
    /// holds.
    /// Returns [`DebianError::Io`] for a path that cannot be opened, one
    /// holding anything but a regular file included, and for a failure writing,
    /// locking, or scanning the pool.
    pub fn publish<P: AsRef<Path>>(
        &self,
        debs: impl IntoIterator<Item = P>,
    ) -> Result<(), DebianError> {
        let suite = self.checked_suite()?;
        let architecture = match self.architecture.clone() {
            Some(architecture) => architecture,
            None => arch::host_architecture(),
        };
        coordinate::check("the pool's component", &self.component, Nesting::Nested)
            .map_err(DebianError::config)?;
        coordinate::check("the pool's architecture", &architecture, Nesting::Single)
            .map_err(DebianError::config)?;
        for (label, value) in [
            ("origin", &self.origin),
            ("label", &self.label),
            ("description", &self.description),
        ] {
            if let Some(value) = value.as_deref() {
                checked_identity(label, value)?;
            }
        }
        let date = match self.date {
            Some(pinned) => pinned,
            // A clock before the epoch stamps the epoch rather than failing:
            // the field records when the pool was published and gates nothing,
            // so an odd clock is not a reason to refuse to publish.
            None => crate::provision::now_epoch().unwrap_or(0),
        };
        let claims = Claims {
            suite,
            date,
            origin: self.origin.as_deref(),
            label: self.label.as_deref(),
            description: self.description.as_deref(),
        };
        write_pool(&self.dir, debs, &claims, &self.component, &architecture)
    }
}

/// What a release says about itself, as distinct from the sections it names.
///
/// The sections are scanned from the suite; these come from the [`Pool`] the
/// publish was configured on, and travel together because every one of them is
/// emitted at the same point by the same call.
struct Claims<'a> {
    suite: &'a str,
    date: i64,
    origin: Option<&'a str>,
    label: Option<&'a str>,
    description: Option<&'a str>,
}

/// Checks one of the release's free-text identity fields.
///
/// These are neither paths nor lists, so a space is ordinary in them and the
/// path checks do not apply. What they cannot carry is a line break: a deb822
/// field ends at a newline, so one embedded in a value would close the field
/// and let whatever followed be read as further fields of the release. Every
/// control character is refused rather than newlines alone, since none of them
/// belongs in a field a client displays.
///
/// An empty value is refused too. A field set to nothing is a mistake at the
/// call site, and the way to have no `Origin` is not to set one.
fn checked_identity(label: &str, value: &str) -> Result<(), DebianError> {
    if value.trim().is_empty() {
        return Err(DebianError::config(format!(
            "the pool's {label} is empty; leave it unset instead"
        )));
    }
    if value.chars().any(|character| character.is_ascii_control()) {
        return Err(DebianError::config(format!(
            "the pool's {label} {value:?} contains a control character, which would end \
                 the release field it is written into",
        )));
    }
    Ok(())
}

/// Writes the pool's files: the copied `.deb`s, the regenerated `Packages` pair
/// under both its plain and its by-hash name, and the `Release` naming their
/// digests.
///
/// The order is what makes a publish atomic to a reader. Every `.deb` lands
/// before any index names it; every index lands before the `Release` that
/// records its digest; and the `Release` is renamed into place last, so the
/// publish becomes visible at that single step.
///
/// No `.deb` lands until every one the call was given has been checked and
/// staged, so a publish that refuses one replaces no file the pool holds.
///
/// Any signature a caller wrote over the previous release is removed first, so
/// the pool is unsigned for the whole of a publish rather than carrying a
/// signature that stops describing it partway through.
fn write_pool<P: AsRef<Path>>(
    pool_dir: &Path,
    debs: impl IntoIterator<Item = P>,
    claims: &Claims<'_>,
    component: &str,
    architecture: &str,
) -> Result<(), DebianError> {
    // The lock lives in the pool root, so the root must exist before it can be
    // taken. Everything from here to the end of the call is one publish.
    mkdir_all(pool_dir)?;
    let _lock = lock_pool(pool_dir)?;
    // Every file the pool already holds is read through this rather than by
    // its host path. The pool is the caller's own output, but a name in it can
    // still hold something its writer did not leave there: a symbolic link is
    // refused rather than followed, and a named pipe rather than waited on.
    let tree = Rooted::open(pool_dir).map_err(DebianError::at("opening the pool", pool_dir))?;

    // Each path is spelled once relative to the pool, for the reads through
    // `tree`, and joined onto the pool for the writes beside them.
    let suite_rel = Path::new("dists").join(claims.suite);
    let binary_rel = suite_rel
        .join(component)
        .join(format!("binary-{architecture}"));
    let suite_dir = pool_dir.join(&suite_rel);
    let binary_dir = pool_dir.join(&binary_rel);
    mkdir_all(&binary_dir)?;

    // Before anything this call writes can be described by it, whatever signed
    // the release this call replaces is gone.
    remove_signatures(&suite_dir)?;

    // Start from whatever the pool already indexes, so the call is incremental.
    // The read is under the lock, so no other publish can merge against the
    // same prior index and drop this one's packages.
    let mut by_name: BTreeMap<String, Entry> = BTreeMap::new();
    let packages_path = binary_dir.join("Packages");
    if let Some(existing) = read_if_present(&tree, &binary_rel.join("Packages"), &packages_path)? {
        for stanza in document::parse(&existing) {
            if let Some(entry) = Entry::from_stanza(&stanza) {
                insert_highest(&mut by_name, entry);
            }
        }
    }

    // Add each freshly-built .deb: stage it beside its pool path and index it,
    // unless the index keeps a higher version of its name. Nothing staged is
    // published until every .deb has been placed, so a publish that refuses one
    // leaves every pool file as it was, its staged copies removed as they drop.
    let mut others = OtherIndexes::beside(&binary_rel);
    let mut staged = Vec::new();
    for deb_path in debs {
        let deb_path = deb_path.as_ref();
        if let Some(Placed { entry, pending }) = index_deb(
            &tree,
            pool_dir,
            component,
            architecture,
            deb_path,
            &by_name,
            &mut others,
        )? {
            insert_highest(&mut by_name, entry);
            staged.extend(pending);
        }
    }
    // In the order the .debs were given, so where two share a path the later
    // one's bytes are the ones the pool keeps, as the index's entry is.
    for (file, dest) in staged {
        file.publish()
            .map_err(DebianError::at("publishing a .deb into the pool", &dest))?;
    }

    // The index is the retained stanzas in name order, deb822 paragraphs
    // separated by a blank line. An empty pool yields an empty Packages, which
    // is a valid (zero-package) index.
    let packages = if by_name.is_empty() {
        String::new()
    } else {
        let blocks: Vec<&str> = by_name.values().map(|entry| entry.text.as_str()).collect();
        let mut text = blocks.join("\n\n");
        text.push('\n');
        text
    };
    let packages_bytes = packages.into_bytes();
    let packages_gz = gzip(&packages_bytes)?;

    // The by-hash copies are what a reader holding an older Release resolves
    // against, so they are written before the Release that supersedes it.
    let by_hash_rel = binary_rel.join("by-hash").join("SHA256");
    mkdir_all(&pool_dir.join(&by_hash_rel))?;
    write_by_hash(&tree, pool_dir, &by_hash_rel, &packages_bytes)?;
    write_by_hash(&tree, pool_dir, &by_hash_rel, &packages_gz)?;

    // The conventional names, for a reader that does not ask by hash.
    write_file(&packages_path, &packages_bytes)?;
    write_file(&binary_dir.join("Packages.gz"), &packages_gz)?;

    // The Release names the section digests, so the provisioner verifies each
    // index against a value the release records. An unsigned pool carries no
    // Valid-Until: it is never freshness-checked.
    //
    // The sections are scanned from the suite rather than taken from this call,
    // so the release describes everything the suite holds. This call's own
    // indexes are already on disk by now, so the scan picks them up with the
    // rest and needs no special case for them.
    let sections = scan_sections(&tree, pool_dir, &suite_rel)?;
    let release = build_release(claims, &sections);
    write_file(&suite_dir.join("Release"), release.as_bytes())?;

    Ok(())
}

/// Removes any signature the suite carries, so one made over a superseded
/// `Release` cannot outlive it.
///
/// A signature is written by the caller, not by the pool, and it describes the
/// exact release bytes it was made over. Leaving one in place across a publish
/// would leave a document that still verifies but no longer describes the pool,
/// and — because the by-hash index copies are immutable and never removed — a
/// reader following it would successfully resolve the superseded package set
/// rather than fail. Removing it makes the pool unsigned instead: a reader that
/// requires a signature finds none, which fails over to another mirror or
/// reports a missing release, both of which are recoverable.
///
/// Both spellings go: `InRelease` is the inline form the provisioner reads, and
/// `Release.gpg` the detached form other clients accept.
///
/// A removal that fails for any reason other than the file's absence fails the
/// publish, since continuing would publish a release under a signature for
/// different bytes.
fn remove_signatures(suite_dir: &Path) -> Result<(), DebianError> {
    for name in ["InRelease", "Release.gpg"] {
        let path = suite_dir.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(DebianError::Io {
                    op: "removing a superseded pool signature",
                    path,
                    source,
                });
            }
        }
    }
    Ok(())
}

/// Takes the pool's exclusive publish lock, returning the descriptor that holds
/// it; dropping the descriptor releases it, on the error paths as on success.
///
/// [`lock_exclusive`](crate::provision::lock_exclusive) is the lock, with what
/// it guarantees: a symbolic link planted at the path redirects nothing, and a
/// process spawned during the publish does not keep the pool locked after the
/// publish returns. The wait is unbounded: a publish is short, and a caller
/// that meets contention wants the pool rather than an error.
fn lock_pool(pool_dir: &Path) -> Result<std::os::fd::OwnedFd, DebianError> {
    let lock_path = pool_dir.join(".lock");
    crate::provision::lock_exclusive(&lock_path).map_err(|source| DebianError::Io {
        op: "locking the pool",
        path: lock_path,
        source,
    })
}

/// Writes an index body under its own digest, the name a reader asks for when
/// the release declares `Acquire-By-Hash`.
///
/// The path is the content, so a regular file already there holds these bytes
/// and the write is skipped. Nothing here is ever rewritten or removed: an
/// entry a later publish supersedes is what a reader still working from the
/// release that named it resolves against. Anything else at the name, a link or
/// a named pipe, holds no index, and is replaced by the rename that publishes
/// one.
fn write_by_hash(
    tree: &Rooted,
    pool_dir: &Path,
    by_hash_rel: &Path,
    bytes: &[u8],
) -> Result<(), DebianError> {
    let rel = by_hash_rel.join(Algorithm::Sha256.hex_of(bytes));
    let path = pool_dir.join(&rel);
    let held = tree
        .stat(&rel)
        .map_err(DebianError::at("writing a pool file", &path))?;
    if held.is_some_and(|stat| is_regular(&stat)) {
        return Ok(());
    }
    write_file(&path, bytes)
}

/// Whether `stat` describes a regular file, the one kind of entry the pool
/// writes at the names it reads back.
fn is_regular(stat: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
}

/// A retained pool entry: the identity the highest-version dedupe keys on, plus
/// the verbatim `Packages` stanza text to emit (its fields, no trailing blank
/// line).
struct Entry {
    name: String,
    version: String,
    text: String,
}

impl Entry {
    /// Builds an entry from a stanza of an existing `Packages` file, reading its
    /// name and version and keeping its text verbatim. Returns `None` for a
    /// stanza missing either field, which is dropped rather than carried
    /// forward malformed.
    fn from_stanza(stanza: &Stanza<'_>) -> Option<Entry> {
        Some(Entry {
            name: stanza.get("Package")?.to_string(),
            version: stanza.get("Version")?.to_string(),
            text: stanza.text().trim_end().to_string(),
        })
    }
}

/// The control fields that place a `.deb` in the pool.
#[derive(PartialEq, Eq)]
struct Identity {
    name: String,
    version: String,
    architecture: String,
}

/// The fields a `Packages` entry takes from the archive rather than from the
/// package: the three the pool appends to a control stanza to make the entry,
/// and `SHA512`, which the pool does not write and an index reader checks a
/// package against all the same.
///
/// A control member carrying one of these would shadow the archive's value, or
/// stand where the archive states none: the index reader resolves a field by
/// its first occurrence, so the package's own text would win over the
/// archive's. See [`identity`].
const ARCHIVE_FIELDS: [&str; 4] = ["Filename", "Size", "SHA256", "SHA512"];

/// Reads the identity a control stanza carries, checking that the `.deb` is one
/// the pool can index.
///
/// Three things are established here, all before the `.deb`'s bytes influence
/// anything the pool writes.
///
/// A pool is per-architecture; an arch-independent package (`all`) belongs in
/// every architecture's index, but a package built for a different architecture
/// does not belong here at all.
///
/// `Package` and `Version` decide where in the pool the `.deb` is stored and
/// what its `Filename` field records, so both are held to the alphabet Debian
/// policy gives them; [`checked_name`] and [`checked_version`] say what each
/// admits and why the path question rests on it.
///
/// The control member is one stanza, and it carries none of the fields an index
/// entry takes from the archive. Both would otherwise let a `.deb` write its
/// own index entry:
/// [`Stanza::get`](crate::provision::document::Stanza::get) resolves a field by its first
/// occurrence, so a control file carrying `SHA256` would shadow the digest taken
/// from the bytes on disk and a control file carrying `Filename` would name any
/// other file in the pool; and a control member of two paragraphs would be
/// emitted whole, with the appended fields landing on the second — which then
/// reads back as the index entry, under whatever name and version that paragraph
/// declares, while the dedupe that placed it keyed on the first. A pool is
/// consumed as `[trusted=yes]` and ranks alongside the primary archive, where
/// the higher version wins, so an entry a package chose for itself supersedes
/// the primary archive's.
///
/// The failure is a bare reason, which the caller attributes to whichever file
/// it read the stanza from.
fn identity(control: &str, architecture: &str) -> Result<Identity, String> {
    let mut stanzas = document::parse(control);
    let stanza = stanzas
        .next()
        .ok_or_else(|| "the control file has no stanza".to_string())?;
    let more = stanzas.count();
    if more > 0 {
        return Err(format!(
            "its control file holds {} paragraphs, and a control file is one",
            1 + more,
        ));
    }
    for field in ARCHIVE_FIELDS {
        if stanza.get(field).is_some() {
            return Err(format!(
                "its control file carries a {field} field, which an index entry takes from \
                 the archive and a package may not name for itself",
            ));
        }
    }
    let field = |name: &str| {
        stanza
            .get(name)
            .map(|value| value.to_string())
            .ok_or_else(|| format!("the control file has no {name} field"))
    };
    let found = Identity {
        name: field("Package")?,
        version: field("Version")?,
        architecture: field("Architecture")?,
    };
    checked_name(&found.name)?;
    checked_version(&found.version)?;
    if found.architecture != architecture && found.architecture != "all" {
        return Err(format!(
            "its architecture {:?} is neither {architecture} nor all",
            found.architecture,
        ));
    }
    Ok(found)
}

/// Checks a control file's `Package` against the alphabet Debian policy gives a
/// package name.
///
/// The name is a path segment of [`pool_path`] twice over — the prefix
/// directory and the package directory — and `Path::join` does not normalize, so
/// a `..` there would survive into the syscall and the kernel would resolve it:
/// a `.deb` naming itself `../../..` would create directories and write a file
/// outside the pool root, as the publishing user. The consume side validates an
/// archive-supplied pool path for exactly this reason
/// ([`is_safe_pool_path`](super::index::is_safe_pool_path)); this is the produce
/// side of it.
///
/// The rule is policy 5.6.1 rather than a traversal filter, and it is the one
/// the index reader holds a stanza's name to:
/// [`is_package_name`](super::index::is_package_name). That admits every name
/// the archive holds and excludes `.` and `..` outright, along with the
/// separator, whitespace, and every control character — so checking the
/// alphabet settles the path question and rejects a `.deb` no archive would
/// accept, and that the pool's own consumers would not read back, in the same
/// step.
fn checked_name(name: &str) -> Result<(), String> {
    if super::index::is_package_name(name) {
        return Ok(());
    }
    Err(format!(
        "its package name {name:?} is not one Debian policy permits: at least two characters \
         of lowercase letters, digits, `+`, `-`, and `.`, starting with a letter or a digit",
    ))
}

/// Checks a control file's `Version` against the alphabet Debian policy gives a
/// version.
///
/// The version is interpolated into the file name [`pool_path`] stores the
/// `.deb` under, so a `/` in it would make the single name a path and put the
/// file wherever the rest of it led. Policy 5.6.12's alphabet — alphanumerics
/// and `.`, `+`, `-`, `:`, `~` — is what dpkg itself enforces, and it contains
/// no separator, no whitespace, and no control character, so the file name stays
/// one component. The version is never a segment of its own, so the `.` and `..`
/// cases the name has do not arise here.
///
/// The alphabet is the one the index reader holds a stanza's version to,
/// [`version::is_version`](super::version::is_version), so the pool publishes
/// no version its own consumers would not read back.
fn checked_version(version: &str) -> Result<(), String> {
    if super::version::is_version(version) {
        return Ok(());
    }
    Err(format!(
        "its version {version:?} is not one Debian policy permits: alphanumerics and `.`, \
         `+`, `-`, `:`, `~`",
    ))
}

/// Stages one `.deb` for the pool and builds its `Packages` stanza.
///
/// The stanza is the `.deb`'s control file verbatim — preserving deb822 folding,
/// so a multi-line `Description` round-trips exactly — with the archive-supplied
/// `Filename`, `Size`, and `SHA256` appended. Carrying the whole control stanza
/// rather than a curated subset keeps every relation the resolver reads
/// (`Depends`, `Pre-Depends`, `Provides`) intact. What makes carrying it
/// verbatim safe is that [`identity`] has already refused a control file that
/// would read back as something other than what it says: one of several
/// paragraphs, or one naming a field the pool appends.
///
/// Nothing here holds a `.deb` in memory. The control member is read by seeking
/// to it, the digest is taken in chunks, and the payload is cloned or streamed
/// rather than buffered, so publishing a 90 MB kernel package costs what
/// publishing a shell script costs.
///
/// The stanza describes the bytes the pool holds, not the bytes the caller
/// offered. The `.deb` is read twice — once to learn where in the pool it
/// belongs, and again from the pool's own copy to describe it — because the two
/// reads are the only way to keep the recorded digest and the stored bytes the
/// same bytes without holding them. A caller that rewrites its `.deb` while it
/// is being published is refused rather than indexed under a digest for content
/// that is not there.
///
/// Whether the `.deb` is written at all is decided before anything is.
/// `retained` is the index as it stands, and a `.deb` below the version it
/// keeps for the name answers `None`, written nowhere: the index keeps the
/// higher version, so nothing would name the file. Writing it would not be
/// harmless either. A version and one differing from it only by an epoch share
/// a [`pool_path`], so the lower one's bytes would replace the file whose
/// digest the kept entry records.
///
/// Nothing is published here. A `.deb` whose bytes the pool does not already
/// hold comes back staged beside its pool path, and the caller renames every
/// staged file once each `.deb` has been placed, so one refused later leaves
/// the pool as it was.
fn index_deb(
    tree: &Rooted,
    pool_dir: &Path,
    component: &str,
    architecture: &str,
    deb_path: &Path,
    retained: &BTreeMap<String, Entry>,
    others: &mut OtherIndexes<'_>,
) -> Result<Option<Placed>, DebianError> {
    let bad = |reason: String| DebianError::Deb {
        path: deb_path.to_path_buf(),
        reason,
    };

    // Opened as a cache entry is: a pipeline's `.deb`s sit in a directory a
    // build sandbox wrote, whose names the host must not follow or wait on.
    let mut source = cache::open_entry(deb_path)
        .map_err(DebianError::at("opening a .deb to publish", deb_path))?;

    // Where the .deb belongs in the pool is what its own control stanza says it
    // is, so the location is settled before anything is written.
    let control =
        deb::read_control_from(deb_path, &mut source).map_err(|err| unreadable(deb_path, err))?;
    let offered = identity(&control, architecture).map_err(bad)?;
    if retained.get(&offered.name).is_some_and(|kept| {
        version::compare(&offered.version, &kept.version) == std::cmp::Ordering::Less
    }) {
        return Ok(None);
    }
    let rel = pool_path(
        component,
        &offered.name,
        &offered.version,
        &offered.architecture,
    );
    let dest = pool_dir.join(&rel);
    if let Some(parent) = dest.parent() {
        mkdir_all(parent)?;
        // A publish killed outright leaves the `.deb` it was staging beside
        // the name it was to take, and the next publish into the directory is
        // the one that can tell it is nobody's, as the package cache's next run
        // can of a download.
        Staged::sweep(parent);
    }

    // Republishing a `.deb` the pool already holds is the common incremental
    // case, and copying identical bytes over themselves would be the only
    // routine rewrite of a file a reader may be fetching. Comparing first makes
    // it a no-op instead. A `.deb` whose bytes differ at the same version is
    // still written, the documented republish case.
    if let Some((mut published, digest, size)) = already_published(tree, &rel, &mut source) {
        // The published file is the offered one byte for byte, so the stanza is
        // read from the file the index will name, through the descriptor the
        // comparison read, and the digest already taken from it stands.
        let control = control_of(&mut published, &dest, deb_path, architecture, &offered)?;
        return Ok(Some(Placed {
            entry: Entry {
                name: offered.name,
                version: offered.version,
                text: stanza_text(&control, &rel, size, &digest),
            },
            pending: None,
        }));
    }

    // What the pool holds at the path, if anything, is about to be replaced.
    // The index this publish writes follows the replacement; another naming
    // the bytes there now would not.
    others.refuse_stranding(tree, pool_dir, &rel, deb_path)?;

    // Stage beside the destination and describe what was staged. The rename
    // that makes the new bytes visible is the caller's, once the stanza that
    // will name them has been read back from them.
    let (staged, mut copy) = stage(&dest, &mut source)?;
    let (control, (digest, size)) =
        describe(&mut copy, staged.path(), deb_path, architecture, &offered)?;

    Ok(Some(Placed {
        entry: Entry {
            name: offered.name,
            version: offered.version,
            text: stanza_text(&control, &rel, size, &digest),
        },
        pending: Some((staged, dest)),
    }))
}

/// A `.deb` a publish has placed: its index entry, and the staging file still
/// to be renamed onto its pool path, with that path, where the pool did not
/// already hold its bytes.
struct Placed {
    entry: Entry,
    pending: Option<(Staged, PathBuf)>,
}

/// The `Packages` stanza for a pool file: its control stanza verbatim, with the
/// archive-supplied fields appended.
///
/// Appending is what preserves the control file's own folding, and it is well
/// defined only because [`identity`] refused a control file carrying any of
/// [`ARCHIVE_FIELDS`] or more than one paragraph: a reader resolves a field by
/// its first occurrence and reads an entry from the paragraph that carries
/// `Filename`, so either shape would let the package decide what the index says
/// about it.
///
/// What is carried is the control file's one stanza as [`document::parse`]
/// reads it, and not the file whole. A run of lines holding no field after the
/// stanza is no paragraph to [`identity`], and carried on, it would separate
/// the appended fields from the stanza: they would land in a paragraph naming
/// no package, and the package would drop out of the index.
fn stanza_text(control: &str, rel: &str, size: u64, digest: &Digest) -> String {
    let stanza = document::parse(control)
        .next()
        .map_or("", |stanza| stanza.text());
    format!(
        "{}\nFilename: {rel}\nSize: {size}\nSHA256: {}",
        stanza.trim_end(),
        digest.hex(),
    )
}

/// Reads the control member of a `.deb` the pool holds, checking that it is
/// still the package the destination path was derived from.
///
/// `file` is the pool's copy, read from its start, and `path` is where it sits,
/// to name a failure of the descriptor itself. `expected` differs from what the
/// file carries only if the `.deb` was rewritten between being located and
/// being copied, which would otherwise file one package under another package's
/// name. Errors about the package are attributed to `deb_path`, the file the
/// caller offered, since that is the file at fault.
fn control_of(
    file: &mut File,
    path: &Path,
    deb_path: &Path,
    architecture: &str,
    expected: &Identity,
) -> Result<String, DebianError> {
    let bad = |reason: String| DebianError::Deb {
        path: deb_path.to_path_buf(),
        reason,
    };
    file.rewind()
        .map_err(DebianError::at("reading a .deb in the pool", path))?;
    let control = deb::read_control_from(path, file).map_err(|err| unreadable(deb_path, err))?;
    if identity(&control, architecture).map_err(bad)? != *expected {
        return Err(bad(
            "it changed while it was being published, and now names a different package"
                .to_string(),
        ));
    }
    Ok(control)
}

/// A failure to read a `.deb`'s control member, as the pool reports it.
///
/// A read of the file that failed is the host's, [`DebianError::Io`], naming the
/// file it was reading. Anything else is the package's, [`DebianError::Deb`],
/// naming `deb_path`, the `.deb` the caller offered, since that is the file at
/// fault.
fn unreadable(deb_path: &Path, err: ProvisionError) -> DebianError {
    match err {
        ProvisionError::Io { op, path, source } => DebianError::io(op, path, source),
        other => DebianError::Deb {
            path: deb_path.to_path_buf(),
            reason: ErrorChain::new(&other.named_by_caller(deb_path)).to_string(),
        },
    }
}

/// Reads back what the pool's own copy of a `.deb` says about itself: its
/// control member, its digest, and its size.
///
/// `file` is the staging copy's own descriptor, which [`Staged::beside`] opens
/// for reading as well as writing so the copy is checked through the descriptor
/// that wrote it rather than through a second open of its name.
fn describe(
    file: &mut File,
    path: &Path,
    deb_path: &Path,
    architecture: &str,
    expected: &Identity,
) -> Result<(String, (Digest, u64)), DebianError> {
    let control = control_of(file, path, deb_path, architecture, expected)?;
    let digest = file
        .rewind()
        .and_then(|()| digest::stream(Algorithm::Sha256, file))
        .map_err(DebianError::at("digesting a .deb in the pool", path))?;
    Ok((control, digest))
}

/// Reports whether the pool already holds `source` byte for byte at `rel`,
/// returning the published file with its digest and size when it does.
///
/// Sizes are compared first, so a `.deb` that changed length is recognised
/// without reading either file. The digest returned is taken from the published
/// file rather than from the one the caller offered, so the index names a digest
/// of what the pool holds, and the file comes back so the stanza is read from
/// the same descriptor.
///
/// The published file is opened through the pool's [`Rooted`], so only a
/// regular file is read: a symbolic link at the name is not followed out of the
/// pool, and a named pipe is not waited on.
///
/// Anything that makes the answer unclear — an absent file, one that is not a
/// regular file, an unreadable one, a read that fails partway — is answered no,
/// and the publish proceeds to write the destination. That is the same answer
/// the whole-file comparison this replaced gave, and it is the right one:
/// rewriting is how a pool file damaged out of band is repaired, the rename that
/// publishes it replacing whatever held the name, and a genuine problem with the
/// caller's own `.deb` surfaces when it is copied.
fn already_published(tree: &Rooted, rel: &str, source: &mut File) -> Option<(File, Digest, u64)> {
    let mut published = tree.reader(rel).ok()?;
    if published.metadata().ok()?.len() != source.metadata().ok()?.len() {
        return None;
    }

    source.rewind().ok()?;
    let (offered, _) = digest::stream(Algorithm::Sha256, source).ok()?;
    let (held, size) = digest::stream(Algorithm::Sha256, &mut published).ok()?;
    (offered == held).then_some((published, held, size))
}

/// What the pool's other indexes record of the files they name, read the first
/// time a publish is about to replace a file.
///
/// A pool path is not one index's alone. Every suite that publishes a package
/// into one component stores it at the same path, and so does every
/// architecture's index for an `Architecture: all` package. Replacing the file
/// changes the bytes each of those indexes describes, and only the index the
/// publish writes follows the change.
struct OtherIndexes<'a> {
    /// The index directory the publish writes, which is not another.
    own: &'a Path,
    /// Each file another index names, by its pool-relative path, with what
    /// every index naming it records. Read on first use.
    named: Option<BTreeMap<String, Vec<Recorded>>>,
}

/// One index's record of a pool file: the index, and the digest it names the
/// file at.
struct Recorded {
    /// The index's path within the pool.
    index: PathBuf,
    /// The SHA-256 the index records for the file.
    digest: String,
}

impl OtherIndexes<'_> {
    /// The indexes beside `own`, the pool-relative `binary-<architecture>`
    /// directory a publish writes. Nothing is read until a file is about to be
    /// replaced.
    fn beside(own: &Path) -> OtherIndexes<'_> {
        OtherIndexes { own, named: None }
    }

    /// Refuses to replace the file at `rel`, a pool-relative path, where
    /// another index names the bytes the pool holds there now.
    ///
    /// That index is correct until the replacement and wrong after it, naming
    /// a digest the file no longer has, so every bootstrap selecting the
    /// package from it would fail. An index already naming other bytes is not
    /// made worse, and does not refuse it: a file damaged out of band stays
    /// repairable by publishing. Only a regular file is something an index can
    /// describe, so anything else at `rel` refuses nothing.
    fn refuse_stranding(
        &mut self,
        tree: &Rooted,
        pool_dir: &Path,
        rel: &str,
        deb_path: &Path,
    ) -> Result<(), DebianError> {
        let path = pool_dir.join(rel);
        let reading = || DebianError::at("reading a .deb in the pool", &path);
        let held = tree.stat(rel).map_err(reading())?;
        if !held.is_some_and(|stat| is_regular(&stat)) {
            return Ok(());
        }
        let Some(naming) = self.named(tree, pool_dir)?.get(rel) else {
            return Ok(());
        };
        let mut file = tree.reader(rel).map_err(reading())?;
        let (digest, _) = digest::stream(Algorithm::Sha256, &mut file).map_err(reading())?;
        let Some(Recorded { index, .. }) = naming
            .iter()
            .find(|recorded| recorded.digest.eq_ignore_ascii_case(digest.hex()))
        else {
            return Ok(());
        };
        Err(DebianError::Deb {
            path: deb_path.to_path_buf(),
            reason: format!(
                "the pool holds other bytes at {rel}, and {} names them; replacing them would \
                 leave that index naming a file the pool no longer holds",
                index.display(),
            ),
        })
    }

    /// The files the other indexes name, read from every `Packages` under
    /// `dists/` but the publish's own the first time it is asked for.
    ///
    /// Read as the suite scan reads, by the same walk: an index that is not a
    /// regular file is not an index, and is passed over. The indexes are read
    /// in path order, so a refusal names the same index on every filesystem.
    fn named(
        &mut self,
        tree: &Rooted,
        pool_dir: &Path,
    ) -> Result<&BTreeMap<String, Vec<Recorded>>, DebianError> {
        if self.named.is_none() {
            let mut named: BTreeMap<String, Vec<Recorded>> = BTreeMap::new();
            let mut found = index_directories(
                pool_dir,
                Path::new("dists"),
                "scanning the pool for its other indexes",
            )?;
            found.sort_by(|left, right| left.rel.cmp(&right.rel));
            for index_dir in found.iter().filter(|index_dir| index_dir.rel != self.own) {
                let rel = index_dir.rel.join("Packages");
                let path = index_dir.host.join("Packages");
                let reading = || DebianError::at("reading another index in the pool", &path);
                let held = tree.stat(&rel).map_err(reading())?;
                if !held.is_some_and(|stat| is_regular(&stat)) {
                    continue;
                }
                let text = tree.read_text(&rel, MAX_UNSIZED_INDEX).map_err(reading())?;
                for stanza in document::parse(&text) {
                    if let (Some(filename), Some(digest)) =
                        (stanza.get("Filename"), stanza.get("SHA256"))
                    {
                        named
                            .entry(filename.into_owned())
                            .or_default()
                            .push(Recorded {
                                index: rel.clone(),
                                digest: digest.into_owned(),
                            });
                    }
                }
            }
            self.named = Some(named);
        }
        Ok(self
            .named
            .as_ref()
            .expect("the record was read above if it was not already held"))
    }
}

/// Places a copy of `source` beside `dest` as a [`Staged`] file, ready to be
/// renamed onto it, returned with the staging file's own descriptor.
///
/// The payload is cloned with `FICLONE` when the source and the pool sit on one
/// filesystem that can share extents. The clone is a metadata operation: it
/// costs no time proportional to the package, no additional space, and — unlike
/// a hard link — it gives the pool its own inode. That independence is the
/// pool's contract. A published file's bytes must not change under a reader
/// resolving against them, and a hard link would alias the caller's inode, so a
/// caller that rewrote its `.deb` in place would rewrite the pool's copy with
/// it and break the digest the `Release` recorded. A clone shares the storage
/// and nothing else.
///
/// Every other case — a source on a different filesystem, a filesystem without
/// reflink support, a kernel that declines — falls back to streaming the bytes
/// through, which is always correct and never holds more than a chunk. The
/// fallback is the common one for a pool that does not share a filesystem with
/// the build tree, so it is a path taken rather than a path of last resort.
fn stage(dest: &Path, source: &mut File) -> Result<(Staged, File), DebianError> {
    let (staged, mut file) =
        Staged::beside(dest).map_err(DebianError::at("staging a .deb for", dest))?;

    // A declined clone leaves the staging file as it was created — empty — so
    // the fallback writes it from the start. Every failure is a fallback: the
    // copy is correct wherever the clone would have been.
    if rustix::fs::ioctl_ficlone(&file, &*source).is_err() {
        source
            .rewind()
            .and_then(|()| std::io::copy(source, &mut file))
            .map_err(DebianError::at(
                "copying a .deb into the pool",
                staged.path(),
            ))?;
    }
    Ok((staged, file))
}

/// Inserts an entry, keeping the higher version when the name recurs. A
/// same-version re-insertion replaces the prior entry, so republishing a `.deb`
/// refreshes its stanza; this matches the resolver, which keeps the highest
/// version of a name within one repository.
///
/// A published `.deb` reaches here only where [`index_deb`] wrote it, which it
/// does only where this keeps it, so the file the kept entry names is the file
/// the pool holds.
fn insert_highest(by_name: &mut BTreeMap<String, Entry>, entry: Entry) {
    match by_name.get(&entry.name) {
        Some(existing)
            if version::compare(&entry.version, &existing.version) == std::cmp::Ordering::Less => {}
        _ => {
            by_name.insert(entry.name.clone(), entry);
        }
    }
}

/// The pool-relative path a `.deb` is stored at: the conventional
/// `pool/<component>/<prefix>/<name>/<file>` layout, where the prefix is the
/// package's first letter (or `lib` plus the fourth letter for a `lib*`
/// package). The same path is what the `Filename` field records, so the file the
/// resolver fetches is the file written here.
fn pool_path(component: &str, name: &str, version: &str, architecture: &str) -> String {
    let prefix = if let Some(rest) = name.strip_prefix("lib") {
        format!("lib{}", rest.chars().next().unwrap_or('_'))
    } else {
        name.chars().next().unwrap_or('_').to_string()
    };
    let file = format!("{name}_{}_{architecture}.deb", filename_version(version),);
    format!("pool/{component}/{prefix}/{name}/{file}")
}

/// The version as an archive file name records it: without the epoch.
///
/// Archive convention omits the epoch — `2:1.3-1` is stored as `..._1.3-1_...` —
/// and an epoch is the only place a Debian version may carry a colon, so
/// everything up to the first colon is the whole of it. A pool that encoded the
/// colon instead, as apt's local cache does, would be laid out unlike every
/// archive a client has seen, and would rest on each of them treating the
/// `Filename` field as a literal string. Following the convention asks nothing
/// of the client.
///
/// Two versions differing only by an epoch therefore share a path. An index
/// keeps one version per package, and [`index_deb`] writes a `.deb` only where
/// its version is the one kept, so the file at a shared path is the one the
/// index names.
fn filename_version(version: &str) -> &str {
    match version.split_once(':') {
        Some((epoch, rest)) if crate::provision::number::is_digits(epoch) => rest,
        _ => version,
    }
}

/// One index a suite holds, as the `Release` names it.
struct Section {
    /// The component the index belongs to: the path between the suite directory
    /// and the `binary-<architecture>` directory, so a nested component is
    /// `main/debian-installer` rather than `main`.
    component: String,
    /// The architecture the index describes.
    architecture: String,
    /// The index's path relative to the suite directory — the name a reader
    /// resolves against — as `<component>/binary-<architecture>/<file>`.
    path: String,
    size: u64,
    digest: Digest,
}

/// Scans a suite directory for every index it holds.
///
/// A release names the sections a reader may resolve, and a reader consults it
/// before it knows which digests to ask for, so a section the release omits is
/// unreachable however intact it is on disk. Deriving the sections from the
/// suite rather than from the call that happens to be publishing is what lets
/// one suite hold several components and architectures: each publish rewrites
/// the release to describe all of them, including the ones other publishes
/// wrote.
///
/// The index directories are those [`index_directories`] finds beneath the
/// suite, where the path above each is its component.
///
/// `suite_rel` is the suite's path within the pool, which `tree` holds.
fn scan_sections(
    tree: &Rooted,
    pool_dir: &Path,
    suite_rel: &Path,
) -> Result<Vec<Section>, DebianError> {
    let mut sections = Vec::new();
    let found = index_directories(pool_dir, suite_rel, "scanning the suite for its indexes")?;
    for index_dir in &found {
        read_indexes(tree, index_dir, &mut sections)?;
    }
    // The walk order follows the filesystem, so the release is sorted here
    // instead: two pools holding the same indexes emit the same release.
    sections.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(sections)
}

/// One `binary-<architecture>` directory a walk found, by both of its names.
struct IndexDir {
    /// The directory's path within the pool, which reads through the pool's
    /// [`Rooted`] resolve.
    rel: PathBuf,
    /// Its host path, which a failure names.
    host: PathBuf,
    /// The path between the walk's root and the directory. Beneath a suite,
    /// that is the component, so a nested component is
    /// `main/debian-installer` rather than `main`.
    prefix: String,
    /// The architecture it describes.
    architecture: String,
}

/// Finds every `binary-<architecture>` directory beneath `root_rel`, a path
/// within the pool, naming a failure to list one as `op`.
///
/// The walk descends every real directory until it meets one named `binary-*`,
/// which is an index directory rather than a component, and is not descended
/// into. That is what keeps the `by-hash` directory beside an index from being
/// read as a component: it is only ever reachable through the `binary-*`
/// directory the walk stops at. A component named `by-hash` in its own right
/// is an ordinary component and is walked as one.
///
/// A symlinked directory is not descended. The pool is a tree it wrote, so
/// every directory in it is a real one; refusing to follow a link is what keeps
/// a link planted in the tree from sending the walk out of the pool or around
/// a loop.
///
/// A `binary-*` directory sitting directly in the root is skipped. Beneath a
/// suite, that is the flat-repository layout, which has no component, and a
/// release has no way to name a section that belongs to none.
fn index_directories(
    pool_dir: &Path,
    root_rel: &Path,
    op: &'static str,
) -> Result<Vec<IndexDir>, DebianError> {
    let mut found = Vec::new();
    // Each entry is a directory to walk and the path above it from the root.
    // The root itself stands for no path, hence the empty string.
    let mut pending = vec![(pool_dir.join(root_rel), String::new())];
    while let Some((dir, prefix)) = pending.pop() {
        let entries = std::fs::read_dir(&dir).map_err(DebianError::at(op, &dir))?;
        for entry in entries {
            let entry = entry.map_err(DebianError::at(op, &dir))?;
            let is_dir = entry
                .file_type()
                .map_err(DebianError::at(op, &dir))?
                .is_dir();
            // A regular file in a component directory is not an index; an index
            // is only ever read from inside a `binary-*` directory.
            if !is_dir {
                continue;
            }
            // A name that is not UTF-8 cannot be spelled in a release, so it
            // cannot be a component or an architecture this pool describes.
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            match name.strip_prefix("binary-") {
                Some(architecture) if !architecture.is_empty() && !prefix.is_empty() => {
                    found.push(IndexDir {
                        rel: root_rel.join(&prefix).join(&name),
                        host: entry.path(),
                        architecture: architecture.to_string(),
                        prefix: prefix.clone(),
                    });
                }
                // `binary-` with no architecture, or one in the root.
                Some(_) => {}
                None if prefix.is_empty() => pending.push((entry.path(), name)),
                None => pending.push((entry.path(), format!("{prefix}/{name}"))),
            }
        }
    }
    Ok(found)
}

/// Digests the indexes directly inside one `binary-<architecture>` directory.
///
/// Only `Packages` and `Packages.gz` are read, so the by-hash copies beside them
/// are not named a second time: they are the same bytes under their own digests,
/// and a release names each section once, by its conventional path.
///
/// An index that is absent is not named, and neither is one that is not a
/// regular file, which is not an index whatever else it is: a symbolic link is
/// looked at rather than followed, and a named pipe is never opened. Both are
/// quiet rather than fatal, because the suite is scanned as it is found and a
/// publish describes what is there.
fn read_indexes(
    tree: &Rooted,
    index_dir: &IndexDir,
    sections: &mut Vec<Section>,
) -> Result<(), DebianError> {
    let IndexDir {
        rel,
        host,
        prefix: component,
        architecture,
    } = index_dir;
    for name in ["Packages", "Packages.gz"] {
        let rel = rel.join(name);
        let path = host.join(name);
        let digesting = || DebianError::at("digesting a pool index", &path);
        let held = tree.stat(&rel).map_err(digesting())?;
        if !held.is_some_and(|stat| is_regular(&stat)) {
            continue;
        }
        let mut file = tree.reader(&rel).map_err(digesting())?;
        let (digest, size) = digest::stream(Algorithm::Sha256, &mut file).map_err(digesting())?;
        sections.push(Section {
            component: component.clone(),
            architecture: architecture.clone(),
            path: format!("{component}/binary-{architecture}/{name}"),
            size,
            digest,
        });
    }
    Ok(())
}

/// Builds a `Release` describing a suite, naming each section's size and
/// SHA-256.
///
/// The release declares the suite (as both `Suite` and `Codename`, so a request
/// for either matches) and, as `Architectures` and `Components`, the unions of
/// what its sections cover. A suite that holds one component and one
/// architecture therefore names exactly those, and one that has had several
/// published into it names them all, so a reader can resolve any of them. Both
/// lists are sorted, and a nested component records under its full path, which
/// is the name a reader has to ask for to reach it.
///
/// A suite with no indexes at all yields empty lists. A publish cannot produce
/// one — it writes its own indexes before the scan reads them — so this is the
/// degenerate case of describing a suite rather than a state the pool reaches.
///
/// It is stamped with `Date`, the required field naming when the pool was
/// published: a reader has no other way to tell how old a snapshot is, and a
/// client that checks for clock skew has nothing to evaluate without it.
///
/// It carries no `Valid-Until`, which is the separate, optional field: a
/// trusted pool is never freshness-checked, and a release that cannot expire is
/// what lets a pool outlive the build that wrote it. Stamping the one does not
/// imply the other — expiry is enforced on `Valid-Until` alone.
///
/// `Origin`, `Label`, and `Description` are emitted only where the caller set
/// them. There is no default for any of the three: an absent optional field is
/// valid, and inventing one would put a name in an archive its owner did not
/// choose.
///
/// It declares `Acquire-By-Hash`, directing a reader at the index copy named by
/// its digest. That copy is immutable, so a reader working from this release
/// keeps resolving the indexes this release describes however many publishes
/// land in the meantime.
fn build_release(claims: &Claims<'_>, sections: &[Section]) -> String {
    let union = |values: BTreeSet<&str>| values.into_iter().collect::<Vec<&str>>().join(" ");
    let architectures = union(
        sections
            .iter()
            .map(|section| section.architecture.as_str())
            .collect(),
    );
    let components = union(
        sections
            .iter()
            .map(|section| section.component.as_str())
            .collect(),
    );

    // The order the archive's own releases use: who produced it, what it is,
    // which suite it is, what it holds, when it was made, and what it is for.
    let mut release = String::new();
    for (field, value) in [("Origin", claims.origin), ("Label", claims.label)] {
        if let Some(value) = value {
            release.push_str(&format!("{field}: {value}\n"));
        }
    }
    let suite = claims.suite;
    release.push_str(&format!("Suite: {suite}\n"));
    release.push_str(&format!("Codename: {suite}\n"));
    release.push_str(&format!("Architectures: {architectures}\n"));
    release.push_str(&format!("Components: {components}\n"));
    release.push_str(&format!("Date: {}\n", release::format_rfc5322(claims.date)));
    if let Some(description) = claims.description {
        release.push_str(&format!("Description: {description}\n"));
    }
    release.push_str("Acquire-By-Hash: yes\n");
    release.push_str("SHA256:\n");
    for section in sections {
        release.push_str(&format!(
            " {} {} {}\n",
            section.digest.hex(),
            section.size,
            section.path,
        ));
    }
    release
}

/// gzip-compresses bytes, for the `Packages.gz` index.
fn gzip(bytes: &[u8]) -> Result<Vec<u8>, DebianError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bytes)
        .and_then(|()| encoder.finish())
        .map_err(|source| DebianError::Io {
            op: "compressing the package index",
            path: PathBuf::from("Packages.gz"),
            source,
        })
}

/// Reads the index the pool already holds at `rel` as text, returning `None`
/// when there is none. `path` is its host path, which a failure names.
///
/// Read through the pool's [`Rooted`], so anything at the name that is not a
/// regular file fails the publish rather than being followed or waited on: the
/// index is what the publish merges into, and one it cannot read would drop
/// every package published before. It is held to [`MAX_UNSIZED_INDEX`], the
/// most the provisioner reads of an index whose size nothing has vouched for,
/// which a prior index is until this publish's own release records it.
fn read_if_present(tree: &Rooted, rel: &Path, path: &Path) -> Result<Option<String>, DebianError> {
    tree.read_text_if_present(rel, MAX_UNSIZED_INDEX)
        .map_err(DebianError::at("reading the existing index", path))
}

/// Creates a directory and its parents.
fn mkdir_all(path: &Path) -> Result<(), DebianError> {
    std::fs::create_dir_all(path).map_err(|source| DebianError::Io {
        op: "creating a pool directory",
        path: path.to_path_buf(),
        source,
    })
}

/// Writes bytes to a file, replacing any existing content atomically, so a
/// reader sees either the whole prior content or the whole new content.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), DebianError> {
    write_atomically(path, bytes).map_err(|source| DebianError::Io {
        op: "writing a pool file",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    use crate::scratch::Scratch;
    #[test]
    fn staging_copies_the_whole_source_from_wherever_it_was_left() {
        // index_deb reads the control member before it stages, so the source's
        // offset is mid-file by the time staging runs. The clone ignores the
        // offset and the fallback rewinds, so both must produce the whole file:
        // a fallback that copied from the current position would silently
        // publish a truncated package.
        let dir = Scratch::for_test("pool", "stage");
        let bytes: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        let source_path = dir.join("source.deb");
        std::fs::write(&source_path, &bytes).unwrap();

        let mut source = File::open(&source_path).unwrap();
        let mut head = [0u8; 4096];
        source.read_exact(&mut head).unwrap();

        let (staged, _) = stage(&dir.join("published.deb"), &mut source).expect("staging succeeds");
        assert_eq!(
            std::fs::read(staged.path()).unwrap(),
            bytes,
            "staging did not reproduce the whole source",
        );
    }

    #[test]
    fn the_clone_is_well_formed_even_where_it_cannot_be_performed() {
        // A filesystem without reflink support declines the clone, and this one
        // may well be such a filesystem. But a declined clone and a malformed
        // one are different things: `EBADF` would mean the descriptors were
        // passed the wrong way round or opened the wrong way, and on every
        // filesystem that cannot clone at all that mistake would look exactly
        // like ordinary non-support. Pinning the errno is what distinguishes
        // them without a filesystem that can share extents.
        let dir = Scratch::for_test("pool", "clone");
        let bytes = vec![0x5a; 128 * 1024];
        let source_path = dir.join("source.deb");
        std::fs::write(&source_path, &bytes).unwrap();
        let source = File::open(&source_path).unwrap();

        let clone_path = dir.join("clone.deb");
        let target = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&clone_path)
            .unwrap();

        match rustix::fs::ioctl_ficlone(&target, &source) {
            // Where the clone lands, it must land completely.
            Ok(()) => assert_eq!(std::fs::read(&clone_path).unwrap(), bytes),
            Err(errno) => assert_ne!(
                errno,
                rustix::io::Errno::BADF,
                "the clone was refused for a bad descriptor, not for lack of support",
            ),
        }
    }

    #[test]
    fn the_pool_reports_the_layout_it_owns() {
        // The paths a caller would otherwise hardcode: the release to sign, the
        // directory to sign it into, and the URL that declares the pool as a
        // repository. None of them requires the pool to exist, so a pipeline can
        // wire itself up before its first publish.
        let pool = Pool::at("/srv/pool").suite("local");
        assert_eq!(pool.dir(), Path::new("/srv/pool"));
        assert_eq!(
            pool.dists_dir().expect("the suite directory"),
            Path::new("/srv/pool/dists/local"),
        );
        assert_eq!(
            pool.release_path().expect("the release path"),
            Path::new("/srv/pool/dists/local/Release"),
        );
        assert_eq!(
            pool.mirror_url().expect("the mirror URL"),
            "file:///srv/pool",
        );
        // The layout does not move with the component or the architecture: a
        // release describes the whole suite.
        let pool = pool.component("contrib").architecture("riscv64");
        assert_eq!(
            pool.release_path().expect("the release path"),
            Path::new("/srv/pool/dists/local/Release"),
        );
    }

    #[test]
    fn a_relative_pool_yields_an_absolute_mirror_url() {
        // A file:// URL names an absolute path, and a pool opened at a relative
        // one is the ordinary case for a build run from its own tree.
        let url = Pool::at("build/pool")
            .suite("local")
            .mirror_url()
            .expect("the mirror URL");
        let expected = std::env::current_dir().unwrap().join("build/pool");
        assert_eq!(url, format!("file://{}", expected.display()));
    }

    #[test]
    fn the_layout_getters_require_a_suite() {
        // The suite is the one setting with no default, and the getters report
        // its absence the same way publishing does rather than inventing one.
        let pool = Pool::at("/srv/pool");
        for reason in [
            pool.dists_dir().unwrap_err().to_string(),
            pool.release_path().unwrap_err().to_string(),
        ] {
            assert!(reason.contains("no suite"), "unexpected reason: {reason}");
        }
        let blank = Pool::at("/srv/pool").suite("  ");
        assert!(
            blank
                .release_path()
                .unwrap_err()
                .to_string()
                .contains("empty"),
            "a blank suite must be refused, not joined into the path",
        );
        // The URL names the root, which no suite is part of.
        assert!(pool.mirror_url().is_ok());
    }

    #[test]
    fn publishing_discards_a_signature_made_over_the_previous_release() {
        // A signature describes the release bytes it was made over. Carrying one
        // across a publish would leave a document that still verifies but names
        // superseded indexes — and since by-hash copies are never removed, a
        // reader would resolve them successfully instead of failing.
        let dir = Scratch::for_test("pool", "signature");
        let pool = Pool::at(&dir).suite("local");
        pool.publish::<&Path>([]).expect("the first publish");

        let suite_dir = pool.dists_dir().unwrap();
        std::fs::write(suite_dir.join("InRelease"), b"signed over the old release").unwrap();
        std::fs::write(suite_dir.join("Release.gpg"), b"detached, over the same").unwrap();

        pool.publish::<&Path>([]).expect("the second publish");
        assert!(
            !suite_dir.join("InRelease").exists(),
            "a superseded InRelease outlived the Release it signed",
        );
        assert!(
            !suite_dir.join("Release.gpg").exists(),
            "a superseded Release.gpg outlived the Release it signed",
        );
        // The publish itself is unaffected: the release it wrote is there.
        assert!(pool.release_path().unwrap().exists());
    }

    #[test]
    fn pool_paths_follow_the_debian_prefix_convention() {
        // An ordinary package indexes under its first letter; a lib package
        // under `lib` plus its fourth letter, as the archive lays out its pool.
        assert_eq!(
            pool_path("main", "hello", "2.10-5", "amd64"),
            "pool/main/h/hello/hello_2.10-5_amd64.deb",
        );
        assert_eq!(
            pool_path("main", "libfoo", "1.0", "amd64"),
            "pool/main/libf/libfoo/libfoo_1.0_amd64.deb",
        );
        // The epoch is dropped from the file name, as the archive lays it out,
        // so a pool is laid out the way every client has already seen and a
        // colon stays out of a path a web server serves.
        assert_eq!(
            pool_path("main", "tool", "2:1.3-1", "amd64"),
            "pool/main/t/tool/tool_1.3-1_amd64.deb",
        );
        // Only a leading numeric epoch is dropped; a colon anywhere else — which
        // policy permits only alongside an epoch — is part of the version.
        assert_eq!(filename_version("1.0-1"), "1.0-1");
        assert_eq!(filename_version("2:1:3-1"), "1:3-1");
        assert_eq!(filename_version("weird:1.0"), "weird:1.0");
    }

    #[test]
    fn insert_highest_keeps_the_greater_version_and_replaces_ties() {
        let entry = |name: &str, version: &str, tag: &str| Entry {
            name: name.to_string(),
            version: version.to_string(),
            text: format!("Package: {name}\nVersion: {version}\n{tag}"),
        };
        let mut by_name = BTreeMap::new();
        insert_highest(&mut by_name, entry("p", "1.0", "old"));
        // A higher version supersedes.
        insert_highest(&mut by_name, entry("p", "2.0", "new"));
        assert!(by_name["p"].text.ends_with("new"));
        // A lower version does not regress the retained entry.
        insert_highest(&mut by_name, entry("p", "1.5", "regress"));
        assert_eq!(by_name["p"].version, "2.0");
        assert!(by_name["p"].text.ends_with("new"));
        // A tie replaces, so a republish refreshes the stanza.
        insert_highest(&mut by_name, entry("p", "2.0", "refreshed"));
        assert!(by_name["p"].text.ends_with("refreshed"));
    }

    /// A suite's claims with nothing optional set, for the tests that are not
    /// about the identity fields.
    fn claims(suite: &str, date: i64) -> Claims<'_> {
        Claims {
            suite,
            date,
            origin: None,
            label: None,
            description: None,
        }
    }

    /// A section over `bytes`, as the scan would have found it.
    fn section(component: &str, architecture: &str, name: &str, bytes: &[u8]) -> Section {
        Section {
            component: component.to_string(),
            architecture: architecture.to_string(),
            path: format!("{component}/binary-{architecture}/{name}"),
            size: bytes.len() as u64,
            digest: Digest::of(Algorithm::Sha256, bytes),
        }
    }

    #[test]
    fn a_release_declares_the_arch_and_component_and_parses_back() {
        // The Release the writer emits must round-trip through the reader's own
        // parser and satisfy its check for the pool's suite, architecture, and
        // component — the property that lets a published pool be declared as a
        // repository, empty or not.
        let packages = b"Package: p\nVersion: 1\n";
        let release = build_release(
            &claims("trixie", 1_783_760_543),
            &[section("main", "amd64", "Packages", packages)],
        );
        let parsed = release::Release::parse(&release).expect("the emitted Release parses");
        parsed
            .check("trixie", "amd64", &["main".to_string()], false)
            .expect("the Release satisfies the pool's own check");
        // The by-hash declaration is what points a reader at the immutable
        // index copy, so a publish stays resolvable across later publishes.
        assert!(
            parsed.acquire_by_hash(),
            "the emitted Release must declare Acquire-By-Hash",
        );
        // The section digest the writer recorded is the digest of the bytes.
        assert_eq!(
            parsed
                .digest("main/binary-amd64/Packages")
                .map(|(size, digests)| (size, digests.sha256())),
            Some((
                packages.len() as u64,
                Some(Algorithm::Sha256.hex_of(packages).as_str())
            )),
        );
    }

    /// The `Date` a release carries, as the Unix timestamp it names.
    fn release_date(release: &str) -> i64 {
        let stanza = document::parse(release)
            .next()
            .expect("the release has a stanza");
        let date = stanza.get("Date").expect("the release carries a Date");
        release::parse_rfc5322(&date).expect("the Date parses as an RFC 5322 date")
    }

    #[test]
    fn a_release_is_stamped_with_the_date_it_was_published() {
        // Date is a required field of a Release, and the field a client reads
        // to tell how old a snapshot is. It must survive the round trip through
        // the reader's own parser, since a client that cannot parse it reports
        // the release as malformed rather than as merely undated.
        let release = build_release(
            &claims("trixie", 1_783_760_543),
            &[section("main", "amd64", "Packages", b"")],
        );
        assert!(release.contains("Date: Sat, 11 Jul 2026 09:02:23 UTC\n"));
        assert_eq!(release_date(&release), 1_783_760_543);
        // The optional field is the one that expires a release, and the pool
        // still does not write it: stamping a date must not bound freshness.
        assert!(
            !release.contains("Valid-Until"),
            "a trusted pool's release must not expire",
        );
        // Stamping does not disturb the digest list the field sits above.
        let parsed = release::Release::parse(&release).expect("the stamped Release parses");
        let empty = Algorithm::Sha256.hex_of(b"");
        assert_eq!(
            parsed
                .digest("main/binary-amd64/Packages")
                .map(|(size, digests)| (size, digests.sha256())),
            Some((0, Some(empty.as_str()))),
        );
    }

    #[test]
    fn an_empty_pool_is_stamped_too() {
        // The empty publish is what a pipeline creates up front so a reference
        // to the pool resolves before anything has been built, which makes it
        // the first release a bootstrap validates — and the one most likely to
        // be missed by a stamp applied only where there are packages.
        let dir = Scratch::for_test("pool", "empty-date");
        let pool = Pool::at(&dir).suite("local").date(1_700_000_000);
        pool.publish::<&Path>([]).expect("the empty publish");
        let release = std::fs::read_to_string(pool.release_path().unwrap()).unwrap();
        assert_eq!(release_date(&release), 1_700_000_000);
    }

    #[test]
    fn a_pinned_date_makes_a_publish_byte_reproducible() {
        // The indexes are a function of the package set, so the release is the
        // only part of a pool that would otherwise vary between two publishes
        // of the same packages. Pinning the date is what closes that gap for a
        // caller building a reproducible archive.
        let dir = Scratch::for_test("pool", "pinned-date");
        let pool = Pool::at(&dir).suite("local").date(1_700_000_000);
        pool.publish::<&Path>([]).expect("the first publish");
        let first = std::fs::read(pool.release_path().unwrap()).unwrap();
        pool.publish::<&Path>([]).expect("the second publish");
        let second = std::fs::read(pool.release_path().unwrap()).unwrap();
        assert_eq!(first, second, "a pinned publish was not byte-reproducible");

        // Left unpinned, the same pool stamps the clock instead. The two need
        // not differ — a second publish within the same second stamps the same
        // date — but the field must be present and current either way.
        let now = crate::provision::now_epoch().expect("the clock is after the epoch");
        let unpinned = Pool::at(&dir).suite("local");
        unpinned.publish::<&Path>([]).expect("the unpinned publish");
        let release = std::fs::read_to_string(unpinned.release_path().unwrap()).unwrap();
        assert!(
            (release_date(&release) - now).abs() < 60,
            "an unpinned publish did not stamp the current time",
        );
    }

    /// The section paths a release names, in the order it names them.
    fn release_sections(release: &str) -> Vec<String> {
        let stanza = document::parse(release)
            .next()
            .expect("the release has a stanza");
        stanza
            .get("SHA256")
            .expect("the release names its sections")
            .lines()
            .filter_map(|line| line.split_whitespace().nth(2).map(str::to_string))
            .collect()
    }

    #[test]
    fn a_suite_holds_every_component_and_architecture_published_into_it() {
        // A reader consults the release before it knows which digests to ask
        // for, so a section the release does not name is unreachable however
        // intact its index is on disk. A second architecture or component
        // published into one suite therefore has to add to the release rather
        // than replace what it named, or publishing one silently retires the
        // other.
        let dir = Scratch::for_test("pool", "accumulate");
        let pool = |component: &str, architecture: &str| {
            Pool::at(&dir)
                .suite("local")
                .component(component)
                .architecture(architecture)
                .date(1_700_000_000)
        };
        let published = [("main", "amd64"), ("main", "arm64"), ("contrib", "amd64")];
        for (component, architecture) in published {
            pool(component, architecture)
                .publish::<&Path>([])
                .unwrap_or_else(|err| panic!("publishing {component}/{architecture}: {err}"));
        }

        let release = std::fs::read_to_string(dir.join("dists/local/Release")).unwrap();
        // The unions of what the suite holds, each sorted, so two pools holding
        // the same sections describe themselves identically.
        assert!(
            release.contains("Architectures: amd64 arm64\n"),
            "the release does not offer both architectures: {release}",
        );
        assert!(
            release.contains("Components: contrib main\n"),
            "the release does not offer both components: {release}",
        );
        // Every index on disk is named, both compressions of each.
        assert_eq!(
            release_sections(&release),
            [
                "contrib/binary-amd64/Packages",
                "contrib/binary-amd64/Packages.gz",
                "main/binary-amd64/Packages",
                "main/binary-amd64/Packages.gz",
                "main/binary-arm64/Packages",
                "main/binary-arm64/Packages.gz",
            ],
        );
        // Reachability is what the section list buys, and the reader's own
        // check is the thing a declared repository has to pass.
        let parsed = release::Release::parse(&release).expect("the release parses");
        for (component, architecture) in published {
            parsed
                .check("local", architecture, &[component.to_string()], false)
                .unwrap_or_else(|err| panic!("{component}/{architecture} is unreachable: {err:?}"));
        }
    }

    #[test]
    fn a_nested_component_records_under_its_full_path() {
        // A component may be laid out as a subtree, which is how
        // main/debian-installer sits in the archive. The full path is the name
        // a reader has to ask for, and the reader matches a component by exact
        // string, so recording only the first segment would name a component
        // whose index is somewhere the reader will not look.
        let dir = Scratch::for_test("pool", "nested-component");
        let architecture = arch::host_architecture();
        for component in ["main", "main/debian-installer"] {
            Pool::at(&dir)
                .suite("local")
                .component(component)
                .date(1_700_000_000)
                .publish::<&Path>([])
                .unwrap_or_else(|err| panic!("publishing {component}: {err}"));
        }

        let release = std::fs::read_to_string(dir.join("dists/local/Release")).unwrap();
        assert!(
            release.contains("Components: main main/debian-installer\n"),
            "the nested component did not record under its full path: {release}",
        );
        assert_eq!(
            release_sections(&release),
            [
                format!("main/binary-{architecture}/Packages"),
                format!("main/binary-{architecture}/Packages.gz"),
                format!("main/debian-installer/binary-{architecture}/Packages"),
                format!("main/debian-installer/binary-{architecture}/Packages.gz"),
            ],
        );
        release::Release::parse(&release)
            .expect("the release parses")
            .check(
                "local",
                &architecture,
                &["main/debian-installer".to_string()],
                false,
            )
            .expect("the nested component is reachable");
    }

    #[test]
    fn a_by_hash_directory_is_not_read_as_a_component() {
        // by-hash holds a copy of each index under its own digest, and it sits
        // inside the binary directory rather than beside it. The walk stops at
        // a binary-* directory, which is what keeps by-hash out of the
        // component list; a walk that descended past it would name a component
        // that does not exist and list every index a second time.
        let dir = Scratch::for_test("pool", "by-hash-component");
        let architecture = arch::host_architecture();
        Pool::at(&dir)
            .suite("local")
            .date(1_700_000_000)
            .publish::<&Path>([])
            .expect("the publish");

        let by_hash = dir
            .join("dists/local/main")
            .join(format!("binary-{architecture}"))
            .join("by-hash/SHA256");
        assert!(
            by_hash.is_dir(),
            "the publish wrote no by-hash directory for the walk to step over",
        );

        let release = std::fs::read_to_string(dir.join("dists/local/Release")).unwrap();
        assert!(
            release.contains("Components: main\n"),
            "by-hash was read as a component: {release}",
        );
        assert_eq!(
            release_sections(&release),
            [
                format!("main/binary-{architecture}/Packages"),
                format!("main/binary-{architecture}/Packages.gz"),
            ],
        );
    }

    #[test]
    fn a_field_that_the_pool_cannot_write_is_refused() {
        // Each of the three settings becomes a path under the pool root and a
        // field in the release. The check refuses what would resolve outside
        // the pool, and what the release format cannot name, but not the
        // separator itself: a slashed suite and a slashed component are both
        // legitimate layouts.
        let dir = Scratch::for_test("pool", "refused-fields");
        let base = || Pool::at(&dir).suite("local").date(1_700_000_000);
        let refused = |pool: Pool, field: &str, note: &str| {
            let reason = pool.publish::<&Path>([]).expect_err(note).to_string();
            assert!(
                reason.contains(field),
                "the refusal of {note} does not name the field: {reason}",
            );
        };

        // Traversal, in each field that becomes a path. These are the two that
        // make the check worth having: both write outside the pool.
        refused(base().suite("../escape"), "suite", "a climbing suite");
        refused(
            base().component("../.."),
            "component",
            "a climbing component",
        );
        refused(base().architecture(".."), "architecture", "a climbing arch");
        refused(base().suite("/etc"), "suite", "an absolute suite");

        // A path that does not say what it means.
        refused(base().component("main//x"), "component", "an empty segment");
        refused(base().suite("local/"), "suite", "a trailing separator");
        refused(base().component("./main"), "component", "a `.` segment");

        // Shapes the release format cannot express. Architectures and
        // Components are whitespace-delimited, so a component with a space in
        // it reads back as two components, neither of them the published one.
        refused(
            base().component("my main"),
            "component",
            "a spaced component",
        );
        refused(
            base().suite("a\nSuite: b"),
            "suite",
            "a suite with a newline",
        );
        refused(base().architecture(""), "architecture", "an empty arch");

        // An architecture is always one directory name; the other two are not.
        refused(
            base().architecture("linux/amd64"),
            "architecture",
            "a slashed architecture",
        );

        // The separator itself is legitimate in both fields that may name a
        // subtree, and neither is caught by the check that refuses traversal.
        base()
            .suite("buster/updates")
            .publish::<&Path>([])
            .expect("a slashed suite publishes");
        base()
            .component("main/debian-installer")
            .publish::<&Path>([])
            .expect("a slashed component publishes");
    }

    #[test]
    fn a_publish_sweeps_the_staging_files_a_killed_one_left() {
        // A staging `.deb` whose holder is gone is removed by the next publish
        // into its directory; one being written is not, which `Staged::sweep`
        // decides by its lock.
        let dir = Scratch::for_test("pool", "staging-sweep");
        let package_dir = dir.join("pool/main/t/tool");
        std::fs::create_dir_all(&package_dir).unwrap();
        let orphan = package_dir.join(".tool_0.9_amd64.deb.0123456789abcdef.partial");
        std::fs::write(&orphan, b"half a package").unwrap();
        let (held, _file) = Staged::beside(&package_dir.join("tool_0.8_amd64.deb")).unwrap();

        let deb = dir.join("tool.deb");
        std::fs::write(
            &deb,
            ferroday_cage_testkit::deb::deb_with_control(
                "Package: tool\nVersion: 1.0\nArchitecture: amd64\n",
                &ferroday_cage_testkit::tar::Tar::new().finish(),
            ),
        )
        .unwrap();
        Pool::at(&dir)
            .suite("local")
            .architecture("amd64")
            .date(1_700_000_000)
            .publish([&deb])
            .expect("the package is published");

        assert!(!orphan.exists(), "the leftover was kept");
        assert!(
            held.path().exists(),
            "a staging file being written was swept"
        );
        assert!(package_dir.join("tool_1.0_amd64.deb").is_file());
    }

    #[test]
    fn a_control_file_ending_in_lines_that_hold_no_field_is_indexed_whole() {
        // A run of lines holding no field is no paragraph, so the control file
        // is one stanza; carried on whole, it would put the fields the pool
        // appends in a paragraph of their own, naming no package. A second
        // publish reads the index back and keeps the entry as it was written.
        let dir = Scratch::for_test("pool", "trailing-run");
        let data = ferroday_cage_testkit::tar::Tar::new().finish();
        let controls = [
            (
                "tool",
                "Package: tool\nVersion: 1.0\nArchitecture: amd64\n\n  stray\nnot a field\n",
            ),
            (
                "other",
                "Package: other\nVersion: 1.0\nArchitecture: amd64\n",
            ),
        ];
        let pool = Pool::at(&dir)
            .suite("local")
            .architecture("amd64")
            .date(1_700_000_000);
        for (name, control) in controls {
            let deb = dir.join(format!("{name}.deb"));
            std::fs::write(
                &deb,
                ferroday_cage_testkit::deb::deb_with_control(control, &data),
            )
            .expect("the package is written");
            pool.publish([&deb]).expect("the package is published");
        }

        let packages =
            std::fs::read_to_string(dir.join("dists/local/main/binary-amd64/Packages")).unwrap();
        assert!(!packages.contains("stray"), "{packages}");
        let index = super::super::index::Index::parse(&packages, "amd64");
        for (name, _) in controls {
            let entry = index
                .get(name)
                .unwrap_or_else(|| panic!("{name}: {packages}"));
            assert_eq!(
                entry.filename,
                format!("pool/main/{}/{name}/{name}_1.0_amd64.deb", &name[..1])
            );
        }
    }

    #[test]
    fn the_identity_fields_round_trip_and_are_absent_until_set() {
        // Origin, Label, and Description are what apt policy renders a
        // repository under and what `Pin: release o=` selects it by. They have
        // no default, because inventing one would put a name in an archive its
        // owner did not choose.
        let dir = Scratch::for_test("pool", "identity");
        let bare = Pool::at(&dir).suite("local").date(1_700_000_000);
        bare.publish::<&Path>([]).expect("the unnamed publish");
        let release = std::fs::read_to_string(bare.release_path().unwrap()).unwrap();
        for field in ["Origin:", "Label:", "Description:"] {
            assert!(
                !release.contains(field),
                "an unset {field} was emitted anyway: {release}",
            );
        }
        // An unnamed release is still a valid one.
        release::Release::parse(&release).expect("the unnamed release parses");

        let named = Pool::at(&dir)
            .suite("local")
            .date(1_700_000_000)
            .origin("Example")
            .label("Example build pool")
            .description("Packages built by the example pipeline");
        named.publish::<&Path>([]).expect("the named publish");
        let release = std::fs::read_to_string(named.release_path().unwrap()).unwrap();
        let stanza = document::parse(&release)
            .next()
            .expect("the release has a stanza");
        assert_eq!(stanza.get("Origin").as_deref(), Some("Example"));
        assert_eq!(stanza.get("Label").as_deref(), Some("Example build pool"));
        assert_eq!(
            stanza.get("Description").as_deref(),
            Some("Packages built by the example pipeline"),
        );
        // The fields are informational, so nothing the reader checks moves.
        release::Release::parse(&release)
            .expect("the named release parses")
            .check(
                "local",
                &arch::host_architecture(),
                &["main".to_string()],
                false,
            )
            .expect("the named release still satisfies the pool's own check");
    }

    #[test]
    fn an_architecture_a_package_states_reaches_the_refusal_with_its_control_characters_escaped() {
        // The control file is the package's own text, and a package built in a
        // sandbox wrote it there.
        let hostile = crate::failure::hostile::TEXT;
        let control = format!("Package: app\nVersion: 1.0\nArchitecture: {hostile}\n");
        let Err(refused) = identity(&control, "amd64") else {
            panic!("the architecture is refused");
        };
        crate::failure::hostile::assert_escaped(&refused);
    }

    #[test]
    fn an_identity_field_cannot_end_the_release_field_it_sits_in() {
        // These are free text, so a space is ordinary in them and the path
        // checks do not apply. A newline is the one thing they cannot carry: a
        // deb822 field ends at one, so a value holding it would continue into
        // the release as fields the caller never wrote -- which for a field
        // taken from a build description is reachable without anyone meaning
        // it.
        let dir = Scratch::for_test("pool", "identity-refused");
        let base = || Pool::at(&dir).suite("local").date(1_700_000_000);
        let refused = |pool: Pool, field: &str, note: &str| {
            let reason = pool.publish::<&Path>([]).expect_err(note).to_string();
            assert!(
                reason.contains(field),
                "the refusal of {note} does not name the field: {reason}",
            );
        };
        refused(
            base().origin("Example\nSuite: other"),
            "origin",
            "an origin carrying a newline",
        );
        refused(
            base().description("a\tdescription"),
            "description",
            "a description carrying a tab",
        );
        // A field set to nothing is a mistake at the call site; the way to have
        // no Origin is not to set one.
        refused(base().label("   "), "label", "a blank label");

        // Spaces and punctuation are what these fields are for.
        base()
            .origin("Example Ltd.")
            .description("Packages built by CI, for internal use")
            .publish::<&Path>([])
            .expect("ordinary free text publishes");
    }

    #[test]
    fn the_layout_getters_refuse_the_same_suites_publishing_does() {
        // dists_dir and release_path join the suite onto the pool root, so a
        // suite that would climb out has to be refused before it is joined
        // rather than only when something is published under it.
        for suite in ["../escape", "/etc", "a//b", "with space"] {
            let pool = Pool::at("/srv/pool").suite(suite);
            assert!(
                pool.dists_dir().is_err() && pool.release_path().is_err(),
                "the suite {suite:?} was joined onto the pool root",
            );
        }
    }
}
