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

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use rustix::fs::{FlockOperation, Mode, OFlags};
use rustix::io::Errno;

use super::index::parse_stanzas;
use super::{DebianError, arch, deb, staging_path, version, write_atomically};

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
pub struct Pool {
    dir: PathBuf,
    suite: Option<String>,
    component: String,
    architecture: Option<String>,
}

impl Pool {
    /// Returns a pool rooted at `dir`.
    ///
    /// The component defaults to `main` and the architecture to the host's;
    /// the suite has no default and must be set.
    pub fn at(dir: impl AsRef<Path>) -> Pool {
        Pool {
            dir: dir.as_ref().to_path_buf(),
            suite: None,
            component: "main".to_string(),
            architecture: None,
        }
    }

    /// Sets the suite the pool publishes under, for example `local`.
    ///
    /// The emitted `Release` declares it as both `Suite` and `Codename`, so a
    /// repository declaration naming either matches.
    pub fn suite(mut self, suite: impl Into<String>) -> Pool {
        self.suite = Some(suite.into());
        self
    }

    /// Sets the archive component. The default is `main`.
    pub fn component(mut self, component: impl Into<String>) -> Pool {
        self.component = component.into();
        self
    }

    /// Sets the architecture the pool indexes. The default is the host's.
    pub fn architecture(mut self, architecture: impl Into<String>) -> Pool {
        self.architecture = Some(architecture.into());
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
    /// empty.
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
    /// empty.
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
    /// [`publish`](Self::publish).
    ///
    /// # Errors
    ///
    /// Returns [`DebianError::Config`] for a root that is not valid UTF-8, which
    /// cannot be spelled in a URL, and [`DebianError::Io`] when the current
    /// directory cannot be read to make a relative root absolute.
    pub fn mirror_url(&self) -> Result<String, DebianError> {
        let absolute = std::path::absolute(&self.dir).map_err(|source| DebianError::Io {
            op: "resolving the pool's path for its mirror URL",
            path: self.dir.clone(),
            source,
        })?;
        let path = absolute.to_str().ok_or_else(|| DebianError::Config {
            reason: format!(
                "the pool path {} is not valid UTF-8 and cannot be named by a file:// URL",
                absolute.display(),
            ),
        })?;
        Ok(format!("file://{path}"))
    }

    /// The suite the pool publishes under, the one setting with no default.
    fn checked_suite(&self) -> Result<&str, DebianError> {
        let Some(suite) = self.suite.as_deref() else {
            return Err(DebianError::Config {
                reason: "no suite was given for the pool".to_string(),
            });
        };
        if suite.trim().is_empty() {
            return Err(DebianError::Config {
                reason: "the pool's suite is empty".to_string(),
            });
        }
        Ok(suite)
    }

    /// Writes or updates the pool from a set of freshly-built `.deb`s.
    ///
    /// The index keeps the highest version of each package name across what the
    /// pool already held and the newly-added `.deb`s — the same
    /// highest-version-wins rule resolution applies — so the pool a caller
    /// writes and the set the resolver later draws from it cannot disagree. A
    /// `.deb` republished at the same version replaces its own entry, so
    /// re-running the call over a superset of a prior run is well-defined.
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
    /// holds with *different* bytes: the archive layout stores both at one
    /// path, so a reader partway through resolving the older bytes fails its
    /// digest check. In a build pipeline that means two components produced the
    /// same package version.
    ///
    /// A publish discards any signature the pool carries — an `InRelease` or a
    /// `Release.gpg` a caller wrote over an earlier release — since a signature
    /// describes the `Release` it was made over and this call replaces it. A
    /// caller that signs its pool signs it again after each publish; see the
    /// module documentation.
    ///
    /// # Errors
    ///
    /// Returns [`DebianError::Config`] when no suite was set or the suite,
    /// component, or architecture is empty; [`DebianError::Deb`] for a `.deb`
    /// that cannot be read, whose architecture belongs in neither this pool nor
    /// `all`, or that was rewritten into a different package while it was being
    /// published; and [`DebianError::Io`] for a failure writing or locking the
    /// pool.
    pub fn publish<P: AsRef<Path>>(
        &self,
        debs: impl IntoIterator<Item = P>,
    ) -> Result<(), DebianError> {
        let suite = self.checked_suite()?;
        let architecture = match self.architecture.clone() {
            Some(architecture) => architecture,
            None => arch::host_architecture(),
        };
        for (label, value) in [
            ("component", self.component.as_str()),
            ("architecture", architecture.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(DebianError::Config {
                    reason: format!("the pool's {label} is empty"),
                });
            }
        }
        write_pool(&self.dir, debs, suite, &self.component, &architecture)
    }
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
/// Any signature a caller wrote over the previous release is removed first, so
/// the pool is unsigned for the whole of a publish rather than carrying a
/// signature that stops describing it partway through.
fn write_pool<P: AsRef<Path>>(
    pool_dir: &Path,
    debs: impl IntoIterator<Item = P>,
    suite: &str,
    component: &str,
    architecture: &str,
) -> Result<(), DebianError> {
    // The lock lives in the pool root, so the root must exist before it can be
    // taken. Everything from here to the end of the call is one publish.
    mkdir_all(pool_dir)?;
    let _lock = lock_pool(pool_dir)?;

    let suite_dir = pool_dir.join("dists").join(suite);
    let binary_dir = suite_dir
        .join(component)
        .join(format!("binary-{architecture}"));
    mkdir_all(&binary_dir)?;

    // Before anything this call writes can be described by it, whatever signed
    // the release this call replaces is gone.
    remove_signatures(&suite_dir)?;

    // Start from whatever the pool already indexes, so the call is incremental.
    // The read is under the lock, so no other publish can merge against the
    // same prior index and drop this one's packages.
    let mut by_name: BTreeMap<String, Entry> = BTreeMap::new();
    let packages_path = binary_dir.join("Packages");
    if let Some(existing) = read_if_present(&packages_path)? {
        for block in split_paragraphs(&existing) {
            if let Some(entry) = Entry::from_stanza(block) {
                insert_highest(&mut by_name, entry);
            }
        }
    }

    // Add each freshly-built .deb: copy it into the pool and index it.
    for deb_path in debs {
        let entry = index_deb(pool_dir, component, architecture, deb_path.as_ref())?;
        insert_highest(&mut by_name, entry);
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
    let by_hash_dir = binary_dir.join("by-hash").join("SHA256");
    mkdir_all(&by_hash_dir)?;
    write_by_hash(&by_hash_dir, &packages_bytes)?;
    write_by_hash(&by_hash_dir, &packages_gz)?;

    // The conventional names, for a reader that does not ask by hash.
    write_file(&packages_path, &packages_bytes)?;
    write_file(&binary_dir.join("Packages.gz"), &packages_gz)?;

    // The Release names the section digests, so the provisioner verifies each
    // index against a value the release records. An unsigned pool carries no
    // Valid-Until: it is never freshness-checked.
    let release = build_release(
        suite,
        component,
        architecture,
        &[("Packages", &packages_bytes), ("Packages.gz", &packages_gz)],
    );
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
/// `NOFOLLOW` so a symlink pre-planted at the lock path cannot redirect the
/// lock, and with it the publish it serializes, elsewhere. The wait is
/// unbounded: a publish is short, and a caller that meets contention wants the
/// pool rather than an error.
fn lock_pool(pool_dir: &Path) -> Result<std::os::fd::OwnedFd, DebianError> {
    let lock_path = pool_dir.join(".lock");
    let io = |source: std::io::Error| DebianError::Io {
        op: "locking the pool",
        path: lock_path.clone(),
        source,
    };
    let lock = rustix::fs::open(
        &lock_path,
        OFlags::CREATE | OFlags::WRONLY | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
    )
    .map_err(|errno| io(errno.into()))?;
    loop {
        match rustix::fs::flock(&lock, FlockOperation::LockExclusive) {
            Ok(()) => return Ok(lock),
            Err(Errno::INTR) => continue,
            Err(errno) => return Err(io(errno.into())),
        }
    }
}

/// Writes an index body under its own digest, the name a reader asks for when
/// the release declares `Acquire-By-Hash`.
///
/// The path is the content, so an existing file already holds these bytes and
/// the write is skipped. Nothing here is ever rewritten or removed: an entry a
/// later publish supersedes is what a reader still working from the release
/// that named it resolves against.
fn write_by_hash(by_hash_dir: &Path, bytes: &[u8]) -> Result<(), DebianError> {
    let path = by_hash_dir.join(deb::sha256_hex(bytes));
    if path.exists() {
        return Ok(());
    }
    write_file(&path, bytes)
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
    /// Builds an entry from an existing `Packages` paragraph, reading its name
    /// and version and keeping the paragraph text verbatim. Returns `None` for a
    /// paragraph missing either field, which is dropped rather than carried
    /// forward malformed.
    fn from_stanza(text: String) -> Option<Entry> {
        let stanza = parse_stanzas(&text).into_iter().next()?;
        Some(Entry {
            name: stanza.get("Package")?.to_string(),
            version: stanza.get("Version")?.to_string(),
            text,
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

/// Reads the identity a control stanza carries, checking that the package
/// belongs in a pool indexing `architecture`.
///
/// A pool is per-architecture; an arch-independent package (`all`) belongs in
/// every architecture's index, but a package built for a different architecture
/// does not belong here at all.
///
/// The failure is a bare reason, which the caller attributes to whichever file
/// it read the stanza from.
fn identity(control: &str, architecture: &str) -> Result<Identity, String> {
    let stanza = parse_stanzas(control)
        .into_iter()
        .next()
        .ok_or_else(|| "the control file has no stanza".to_string())?;
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
    if found.architecture != architecture && found.architecture != "all" {
        return Err(format!(
            "its architecture {} is neither {architecture} nor all",
            found.architecture,
        ));
    }
    Ok(found)
}

/// Copies one `.deb` into the pool and builds its `Packages` stanza.
///
/// The stanza is the `.deb`'s control file verbatim — preserving deb822 folding,
/// so a multi-line `Description` round-trips exactly — with the archive-supplied
/// `Filename`, `Size`, and `SHA256` appended. Carrying the whole control stanza
/// rather than a curated subset keeps every relation the resolver reads
/// (`Depends`, `Pre-Depends`, `Provides`) intact.
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
fn index_deb(
    pool_dir: &Path,
    component: &str,
    architecture: &str,
    deb_path: &Path,
) -> Result<Entry, DebianError> {
    let bad = |reason: String| DebianError::Deb {
        path: deb_path.to_path_buf(),
        reason,
    };

    let mut source = File::open(deb_path).map_err(io_err("opening a .deb to publish", deb_path))?;

    // Where the .deb belongs in the pool is what its own control stanza says it
    // is, so the location is settled before anything is written.
    let control = deb::read_control_from(&mut source).map_err(|err| bad(err.to_string()))?;
    let offered = identity(&control, architecture).map_err(&bad)?;
    let rel = pool_path(
        component,
        &offered.name,
        &offered.version,
        &offered.architecture,
    );
    let dest = pool_dir.join(&rel);
    if let Some(parent) = dest.parent() {
        mkdir_all(parent)?;
    }

    // Republishing a `.deb` the pool already holds is the common incremental
    // case, and copying identical bytes over themselves would be the only
    // routine rewrite of a file a reader may be fetching. Comparing first makes
    // it a no-op instead. A `.deb` whose bytes differ at the same version is
    // still written, the documented republish case.
    if let Some((digest, size)) = already_published(&dest, &mut source) {
        // The published file is the offered one byte for byte, so the stanza is
        // read from the file the index will name, and the digest already taken
        // from it stands.
        let control = control_of(&dest, deb_path, architecture, &offered)?;
        return Ok(Entry {
            name: offered.name,
            version: offered.version,
            text: stanza_text(&control, &rel, size, &digest),
        });
    }

    // Stage beside the destination, describe what was staged, then rename: the
    // rename is what makes the new bytes visible, and it happens only once the
    // stanza that will name them has been read back from them.
    let staged = stage(&dest, &mut source)?;
    let described = describe(&staged, deb_path, architecture, &offered);
    let (control, digest, size) = match described {
        Ok((control, (digest, size))) => (control, digest, size),
        Err(err) => {
            let _ = std::fs::remove_file(&staged);
            return Err(err);
        }
    };
    std::fs::rename(&staged, &dest)
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&staged);
        })
        .map_err(io_err("publishing a .deb into the pool", &dest))?;

    Ok(Entry {
        name: offered.name,
        version: offered.version,
        text: stanza_text(&control, &rel, size, &digest),
    })
}

/// The `Packages` stanza for a pool file: its control stanza verbatim, with the
/// archive-supplied fields appended.
fn stanza_text(control: &str, rel: &str, size: u64, digest: &str) -> String {
    format!(
        "{}\nFilename: {rel}\nSize: {size}\nSHA256: {digest}",
        control.trim_end(),
    )
}

/// Reads the control member of a `.deb` the pool holds, checking that it is
/// still the package the destination path was derived from.
///
/// `expected` differs from what the file carries only if the `.deb` was
/// rewritten between being located and being copied, which would otherwise file
/// one package under another package's name. Errors are attributed to
/// `deb_path`, the file the caller offered, since that is the file at fault.
fn control_of(
    path: &Path,
    deb_path: &Path,
    architecture: &str,
    expected: &Identity,
) -> Result<String, DebianError> {
    let bad = |reason: String| DebianError::Deb {
        path: deb_path.to_path_buf(),
        reason,
    };
    let mut file = File::open(path).map_err(io_err("reading a .deb in the pool", path))?;
    let control = deb::read_control_from(&mut file).map_err(|err| bad(err.to_string()))?;
    if identity(&control, architecture).map_err(&bad)? != *expected {
        return Err(bad(
            "it changed while it was being published, and now names a different package"
                .to_string(),
        ));
    }
    Ok(control)
}

/// Reads back what the pool's own copy of a `.deb` says about itself: its
/// control member, its digest, and its size.
fn describe(
    path: &Path,
    deb_path: &Path,
    architecture: &str,
    expected: &Identity,
) -> Result<(String, (String, u64)), DebianError> {
    let control = control_of(path, deb_path, architecture, expected)?;
    let mut file = File::open(path).map_err(io_err("digesting a .deb in the pool", path))?;
    let digest =
        deb::sha256_stream(&mut file).map_err(io_err("digesting a .deb in the pool", path))?;
    Ok((control, digest))
}

/// Reports whether the pool already holds `source` byte for byte at `dest`,
/// returning the published file's digest and size when it does.
///
/// Sizes are compared first, so a `.deb` that changed length is recognised
/// without reading either file. The digest returned is taken from the published
/// file rather than from the one the caller offered, so the index names a digest
/// of what the pool holds.
///
/// Anything that makes the answer unclear — an absent file, an unreadable one, a
/// read that fails partway — is answered no, and the publish proceeds to write
/// the destination. That is the same answer the whole-file comparison this
/// replaced gave, and it is the right one: rewriting is how a pool file damaged
/// out of band is repaired, and a genuine problem with the caller's own `.deb`
/// surfaces when it is copied.
fn already_published(dest: &Path, source: &mut File) -> Option<(String, u64)> {
    let mut published = File::open(dest).ok()?;
    if published.metadata().ok()?.len() != source.metadata().ok()?.len() {
        return None;
    }

    source.rewind().ok()?;
    let (offered, _) = deb::sha256_stream(source).ok()?;
    let (held, size) = deb::sha256_stream(&mut published).ok()?;
    (offered == held).then_some((held, size))
}

/// Places a copy of `source` beside `dest` under a staging name, ready to be
/// renamed onto it.
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
fn stage(dest: &Path, source: &mut File) -> Result<PathBuf, DebianError> {
    let staged = staging_path(dest);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(io_err("staging a .deb", &staged))?;

    // A declined clone leaves the staging file as it was created — empty — so
    // the fallback writes it from the start. Every failure is a fallback: the
    // copy is correct wherever the clone would have been.
    if rustix::fs::ioctl_ficlone(&file, &*source).is_err() {
        let copied = source
            .rewind()
            .and_then(|()| std::io::copy(source, &mut file))
            .map(|_| ());
        if let Err(err) = copied {
            let _ = std::fs::remove_file(&staged);
            return Err(io_err("copying a .deb into the pool", &staged)(err));
        }
    }
    drop(file);
    Ok(staged)
}

/// Builds an I/O failure against the path it happened to.
fn io_err(op: &'static str, path: &Path) -> impl FnOnce(std::io::Error) -> DebianError {
    let path = path.to_path_buf();
    move |source| DebianError::Io { op, path, source }
}

/// Inserts an entry, keeping the higher version when the name recurs. A
/// same-version re-insertion replaces the prior entry, so republishing a `.deb`
/// refreshes its stanza; this matches the resolver's highest-version-wins.
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
/// package). The `.deb`'s name encodes the version's epoch colon as `%3a`, and
/// the same encoded path is what the `Filename` field records, so the file the
/// resolver fetches is the file written here.
fn pool_path(component: &str, name: &str, version: &str, architecture: &str) -> String {
    let prefix = if let Some(rest) = name.strip_prefix("lib") {
        format!("lib{}", rest.chars().next().unwrap_or('_'))
    } else {
        name.chars().next().unwrap_or('_').to_string()
    };
    let file = format!("{name}_{}_{architecture}.deb", version.replace(':', "%3a"),);
    format!("pool/{component}/{prefix}/{name}/{file}")
}

/// Builds a `Release` naming each section's size and SHA-256.
///
/// The release declares the suite (as both `Suite` and `Codename`, so a request
/// for either matches), the architecture, and the component, so the
/// provisioner's release check passes for the pool even when it is empty. It
/// carries no `Valid-Until`: a trusted pool is never freshness-checked.
///
/// It declares `Acquire-By-Hash`, directing a reader at the index copy named by
/// its digest. That copy is immutable, so a reader working from this release
/// keeps resolving the indexes this release describes however many publishes
/// land in the meantime.
fn build_release(
    suite: &str,
    component: &str,
    architecture: &str,
    sections: &[(&str, &[u8])],
) -> String {
    let mut release = String::new();
    release.push_str(&format!("Suite: {suite}\n"));
    release.push_str(&format!("Codename: {suite}\n"));
    release.push_str(&format!("Architectures: {architecture}\n"));
    release.push_str(&format!("Components: {component}\n"));
    release.push_str("Acquire-By-Hash: yes\n");
    release.push_str("SHA256:\n");
    for (name, bytes) in sections {
        release.push_str(&format!(
            " {} {} {component}/binary-{architecture}/{name}\n",
            deb::sha256_hex(bytes),
            bytes.len(),
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

/// Splits a `Packages` file into its deb822 paragraphs, each returned as its
/// field lines joined by newlines with no trailing blank line, ready to re-emit.
fn split_paragraphs(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        if line.is_empty() {
            if !current.trim().is_empty() {
                blocks.push(current.trim_end().to_string());
            }
            current.clear();
            continue;
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.trim().is_empty() {
        blocks.push(current.trim_end().to_string());
    }
    blocks
}

/// Reads a file to a string if it exists, returning `None` when it is absent.
fn read_if_present(path: &Path) -> Result<Option<String>, DebianError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(DebianError::Io {
            op: "reading the existing index",
            path: path.to_path_buf(),
            source,
        }),
    }
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

    fn tempdir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ferroday-cage-pool-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn staging_copies_the_whole_source_from_wherever_it_was_left() {
        // index_deb reads the control member before it stages, so the source's
        // offset is mid-file by the time staging runs. The clone ignores the
        // offset and the fallback rewinds, so both must produce the whole file:
        // a fallback that copied from the current position would silently
        // publish a truncated package.
        let dir = tempdir("stage");
        let bytes: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        let source_path = dir.join("source.deb");
        std::fs::write(&source_path, &bytes).unwrap();

        let mut source = File::open(&source_path).unwrap();
        let mut head = [0u8; 4096];
        source.read_exact(&mut head).unwrap();

        let staged = stage(&dir.join("published.deb"), &mut source).expect("staging succeeds");
        assert_eq!(
            std::fs::read(&staged).unwrap(),
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
        let dir = tempdir("clone");
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
                Errno::BADF,
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
        let dir = tempdir("signature");
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
        // A version epoch's colon is encoded, so the pool path stays a plain
        // relative path — the same encoding the Filename records, so the file
        // the resolver fetches is the file written.
        assert_eq!(
            pool_path("main", "tool", "2:1.3-1", "amd64"),
            "pool/main/t/tool/tool_2%3a1.3-1_amd64.deb",
        );
    }

    #[test]
    fn paragraphs_split_on_blank_lines_and_drop_trailing_newlines() {
        let text = "Package: a\nVersion: 1\n\nPackage: b\nVersion: 2\n\n";
        assert_eq!(
            split_paragraphs(text),
            ["Package: a\nVersion: 1", "Package: b\nVersion: 2"],
        );
        // An empty index yields no paragraphs.
        assert!(split_paragraphs("").is_empty());
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

    #[test]
    fn a_release_declares_the_arch_and_component_and_parses_back() {
        // The Release the writer emits must round-trip through the reader's own
        // parser and satisfy its check for the pool's suite, architecture, and
        // component — the property that lets a published pool be declared as a
        // repository, empty or not.
        let packages = b"Package: p\nVersion: 1\n";
        let release = build_release("trixie", "main", "amd64", &[("Packages", packages)]);
        let parsed =
            super::super::release::Release::parse(&release).expect("the emitted Release parses");
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
            parsed.digest("main/binary-amd64/Packages"),
            Some((packages.len() as u64, deb::sha256_hex(packages).as_str())),
        );
    }
}
