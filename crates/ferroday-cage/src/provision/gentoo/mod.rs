//! The Gentoo userland provisioner: bootstrap a rootfs from a signed stage3,
//! and install prebuilt packages into it.
//!
//! A run is two waves, and a run that asks for no package is the first alone,
//! byte for byte:
//!
//! 1. Resolve a stage3 variant to the build the archive currently publishes,
//!    verify the signed documents that vouch for it, and extract the tarball.
//! 2. Read the extracted root's own package database, resolve the caller's
//!    atoms against it and the binary-package index, and fetch, verify and
//!    merge what is missing.
//!
//! # Resolution starts from a populated root
//!
//! That is the shape neither of the other two userlands has, and it decides the
//! resolver's inputs rather than being a detail of them. Debian and Alpine
//! bootstrap from nothing, so their resolvers start with an empty root and the
//! archive is the only source of truth. A stage3 arrives with 296 packages
//! already installed and a database describing them, so resolution here asks
//! what is *missing* — and it is measurably load-bearing, because one of those
//! 296 has no binary package in the archive at all.
//!
//! # What binds the archive together
//!
//! One key, vouching for cleartext-signed documents that vouch for the bytes:
//!
//! ```text
//! vendored service keyring
//!   -> latest-stage3.txt      (cleartext-signed)  the variants, their sizes
//!   -> <tarball>.DIGESTS      (cleartext-signed)  the tarball's SHA-512
//!   -> <tarball>              (bytes)             verified, then extracted
//!
//! vendored service keyring
//!   -> <package>/Manifest     (cleartext-signed)  each member's SHA-512
//!   -> the members            (bytes)             verified, then read
//! ```
//!
//! The subkey that signs a package's `Manifest` is the one that signs the
//! pointer and the digest documents, so the binary-package half adds no trust
//! anchor: the crate's OpenPGP verification is called on one more document.
//!
//! That is the same shape Debian's release chain has, and it is verified with
//! the same machinery: the crate's OpenPGP verification establishes each
//! document's authenticity, and the digest it carries is what the fetched bytes
//! are held to. A `.sha256` sidecar sits beside every tarball and is never read
//! — nothing signs it, and a chain resting on an unauthenticated file is not a
//! chain.
//!
//! What no signature covers is the binary-package index, in any form, and the
//! two consequences are answered in different places. That a mirror can decide
//! *which* package a resolution asks for is closed after verification, by
//! comparing the metadata inside a container against the record the resolution
//! chose -- a `Manifest` carries no field naming the package, so a genuine,
//! correctly signed *other* package would otherwise pass every check. That
//! nothing vouches for the index's own freshness is not closed at all, and the
//! rollback the stage3's signed timestamp shuts is open here — which is a fact
//! about the archive rather than about this layer.

mod atom;
mod digests;
mod gpkg;
mod index;
mod installed;
mod plan;
mod pointer;
mod resolve;
mod vdb;
mod version;

use std::fmt;
use std::io;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use index::Catalogue;
pub use installed::{Installed, InstalledPackage, installed};
pub use plan::{Plan, PlannedPackage};

use pointer::Pointer;

use super::compress;
use super::coordinate::{self, Nesting};
use super::digest::{self, Algorithm};
use super::layer::BuildLayer;
use super::openpgp::{Keyring, OpenPgpError};
use super::rooted::Rooted;
use super::{
    Delegate, Fetch, FetchError, FetchRequest, HttpFetch, LimitedWriter, PackageCache,
    ProvisionError, ProvisionEvent, ProvisionRequest, Provisioner, Tarball,
};
use crate::IdentityMap;

/// The archive the layer reads unless the caller names another.
const DEFAULT_MIRROR: &str = "http://distfiles.gentoo.org";

/// How old a pointer may be before the layer refuses to act on it, unless the
/// caller says otherwise.
///
/// About four regeneration cycles. The document is rebuilt for every
/// architecture on a weekly schedule whether or not new builds landed in it, so
/// a live archive never approaches this; what it bounds is a mirror replaying a
/// correctly signed document long after it stopped being current.
const DEFAULT_MAX_POINTER_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The ceiling on a pointer document, which declares no size of its own.
const MAX_POINTER_BYTES: u64 = 1024 * 1024;

/// The ceiling on a digest document, which declares no size of its own.
const MAX_DIGESTS_BYTES: u64 = 64 * 1024;

/// The ceiling on a binary-package index, which declares no size of its own.
///
/// Sized against today's 19.1 MB with room for the archive to grow. It applies
/// to the plain and the compressed form alike -- for the compressed one, to the
/// decompressed stream, since that is what a decompression bomb inflates.
const MAX_INDEX_BYTES: u64 = 256 * 1024 * 1024;

/// The ceiling on a binary package's metadata archive, which the container
/// declares no length for until its Manifest has been read.
///
/// The largest a real one runs to is a few tens of kilobytes; this is far above
/// that and far below a bound that means nothing. It applies to the compressed
/// member and again to what it inflates to, since a decompression bomb spends
/// its bytes in the second.
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;

/// The most paths one binary package may ship.
///
/// Every one becomes a line of the database entry's `CONTENTS`, held in memory
/// until the entry is written. The largest package Gentoo publishes ships tens
/// of thousands; this is an order above that, and it bounds what a container
/// whose length passed the index's `SIZE` can still make the merge spend.
const MAX_CONTENTS_ENTRIES: usize = 1_000_000;

/// The suffix of the cache binary packages are downloaded into when the caller
/// named no directory of their own.
const PACKAGE_CACHE: &str = ".fcage-binpkgs";

/// Where portage keeps its database inside a root.
///
/// Here rather than in either half that names it, because the pair is what must
/// agree: [`vdb`] writes an entry under this path and [`installed`] reads one
/// back, and a spelling that moved in one alone would register packages where
/// the layer will not find them — resolution would report a populated root as
/// empty and install every dependency it already had.
pub(super) const DB_DIR: &str = "var/db/pkg";

/// The ceiling on a stage3 tarball where nothing declares its size.
///
/// A fetch is normally bounded by the exact size the signed enumeration
/// recorded. One path has no such number: a build id pin, which skips the
/// enumeration -- and, with it, a [`Stage3`] carried over from a pinned
/// resolution, which is that same answer again. The largest stage3 published
/// today is 796 MB, so this is far above anything real and far below a bound
/// that means nothing.
///
/// It is this layer's own ceiling rather than the effective one. A transport
/// applies whatever bound it has of its own, and the bundled client's is half
/// this, so a default build stops a pinned download at 2 GiB. Both are far above
/// any published stage3; where they differ, the smaller wins, as a ceiling
/// should.
const MAX_STAGE3_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// The ceiling on one binary package, over and above the size the index
/// published for it.
///
/// The index's own `SIZE` bounds the download, and for an understated one that
/// is enough: the fetch stops short and fails closed. An *overstated* one only
/// relaxes the bound, because a transport caps at the smaller of the declared
/// size and its own ceiling — so an index declaring `SIZE:
/// 18446744073709551615` for each of a hundred packages buys whatever the
/// transport's ceiling is, a hundred times over, before anything is verified.
///
/// Nothing signs the index, ever, which puts the binary-package path
/// permanently where a build-id pin puts the stage3 path: holding a number no
/// signature stands behind. [`MAX_STAGE3_BYTES`] is that path's answer and this
/// is this one's.
///
/// The value is this layer's judgement rather than a measurement of the
/// archive. What it has to be is smaller than the transport's own ceiling —
/// the bundled client's is 2 GiB, and a bound above it would never bind — and
/// larger than any package the archive publishes. A stage3 is a whole base
/// system at 796 MB, and this is above that, so a single package reaching it
/// would be a bound to raise rather than a package to refuse.
const MAX_PACKAGE_BYTES: u64 = 1024 * 1024 * 1024;

/// The suffix of the cache a run downloads into when the caller named no
/// directory of their own.
const STAGE3_CACHE: &str = ".fcage-stage3";

/// The Gentoo service keyring shipped with the crate, mirroring what Gentoo
/// publishes at `qa-reports.gentoo.org/output/service-keys.gpg`.
///
/// Vendored rather than fetched, and that is a security property rather than a
/// saved round trip: a trust anchor fetched over the same channel as the
/// artifact it authenticates authenticates nothing, because whoever can serve a
/// forged stage3 can serve the key that signs it.
///
/// Mirrored mechanically, certificates this layer never meets included. An
/// unusable key in the anchor weakens nothing — nothing rests on a key until it
/// produces a signature that passes the gates — while a hand-picked subset would
/// be a judgement a later reader has to reconstruct instead of a rule they can
/// check.
const EMBEDDED_KEYRING: &[u8] = include_bytes!("keyring/service-keys.gpg");

/// A failure provisioning a Gentoo rootfs.
#[derive(Debug)]
#[non_exhaustive]
pub enum GentooError {
    /// The configuration cannot be provisioned from as it stands.
    #[non_exhaustive]
    Config {
        /// What is wrong with it, and what to do instead.
        reason: String,
    },
    /// A signed document was not accepted: it did not verify against the
    /// keyring, or the keyring itself could not be read.
    #[non_exhaustive]
    Signature {
        /// What was being verified: the URL a document was served from, or the
        /// keyring.
        subject: String,
        /// Why it was not accepted.
        reason: String,
    },
    /// A signed document verified but does not say what the layer needs.
    ///
    /// The signature held; what it covers is not a document this crate can act
    /// on — a pointer naming no addressable stage3, or a digest document
    /// recording no usable SHA-512 for the tarball beside it.
    #[non_exhaustive]
    Document {
        /// The URL the document was served from, mirror included, so a walk
        /// over several of them names the one that answered.
        subject: String,
        /// What was wrong with it.
        reason: String,
    },
    /// The pointer verified but is too old to act on.
    ///
    /// Gentoo publishes no `Valid-Until` and no signature expiration, so the
    /// regeneration timestamp inside the signed body is the only bound on how
    /// stale a correctly signed document may be. Without it, a mirror could
    /// replay a months-old pointer indefinitely and pass every other check.
    /// Clear the bound with
    /// [`max_pointer_age`](GentooBuilder::max_pointer_age) to provision from a
    /// deliberately archived mirror.
    #[non_exhaustive]
    Stale {
        /// The epoch the pointer states it was regenerated at, or `None` where
        /// it states none — which is refused rather than read as permission,
        /// since deleting a line would otherwise disable the check.
        published: Option<i64>,
        /// How long ago that was, where it said.
        age: Option<Duration>,
        /// The bound it exceeded.
        limit: Duration,
    },
    /// The binary-package index was fetched but does not say what the layer
    /// needs.
    ///
    /// Nothing signs the index, so this is not a signature failure and never
    /// can be: no `Packages.gpg`, `.asc`, `.sig`, `Manifest` or `.DIGESTS` is
    /// published beside it in any form. What it reports is a document that
    /// arrived and could not be read as one — an empty index, or one whose
    /// stanzas this layer could not act on.
    #[non_exhaustive]
    Index {
        /// The URL the index was served from, mirror included.
        subject: String,
        /// What was wrong with it.
        reason: String,
    },
    /// A plan document cannot be read, or cannot be written.
    ///
    /// Reading: the document is not one this library reads, or it states
    /// something an index would never have published — a name that is not a
    /// package, a version this format does not define, a path that would not
    /// stay inside the archive. Writing: the plan holds a value the format
    /// cannot carry back unchanged, which is refused rather than written as
    /// something that reads back differently.
    #[non_exhaustive]
    PlanDocument {
        /// What was wrong with it.
        reason: String,
    },
    /// The closure the binhost offers is not one that can be installed.
    ///
    /// An atom nothing published answers, or a blocker that matches something
    /// the root has or the resolution chose. Both sides of every refusal are
    /// named: which atom, who asked for it, and what stopped it.
    #[non_exhaustive]
    Resolve {
        /// What could not be resolved, and what the binhost offers instead.
        reason: String,
    },
    /// A binary package's container is not one this layer can read.
    ///
    /// Not a signature failure and not a digest one: those have variants of
    /// their own. This is a container whose *shape* is wrong — no format
    /// marker, a member its Manifest does not list or one it lists that is
    /// absent, no image or metadata archive — or one whose metadata names a
    /// different package than the index did.
    ///
    /// That last is the one worth naming. A Manifest carries no field saying
    /// which package it is, and GLEP 78 forbids trusting the container's
    /// directory prefix for it, so a hostile mirror answering a request for one
    /// package with a genuine, correctly signed *other* package passes every
    /// signature check there is. The identity check inside the container is
    /// what closes that, and this is what it reports.
    #[non_exhaustive]
    Container {
        /// The container concerned, in the cache.
        subject: String,
        /// What was wrong with it.
        reason: String,
    },
    /// A root's own package database holds something that is not a package
    /// entry.
    ///
    /// The database is read to learn what a root already has, so an entry that
    /// cannot be read is a gap in that answer rather than a detail to pass
    /// over: resolving against a set that is missing a package asks the archive
    /// for something the root already satisfies, or -- where the archive does
    /// not publish it -- refuses an install that would have worked.
    #[non_exhaustive]
    Database {
        /// The root whose database was being read.
        root: PathBuf,
        /// What was wrong with it.
        reason: String,
    },
    /// The tarball does not have the digest the signed document recorded for
    /// it.
    ///
    /// The chain held as far as the document; what a mirror served is not what
    /// the document vouched for. The bytes are not extracted, and the cached
    /// file is removed so a later run downloads afresh rather than meeting the
    /// same refusal from its own cache.
    #[non_exhaustive]
    Digest {
        /// The tarball the digest was taken over.
        subject: String,
        /// The SHA-512 the signed document recorded, as it spells it.
        expected: String,
        /// The SHA-512 the bytes actually have.
        actual: String,
    },
    /// The run's observer asked the bootstrap to stop.
    ///
    /// Surfaces to a caller as [`super::ProvisionError::Cancelled`].
    Cancelled,
    /// Fetching from the archive failed.
    Fetch(FetchError),
    /// A host I/O operation failed.
    #[non_exhaustive]
    Io {
        /// What the operation was doing.
        op: &'static str,
        /// The path concerned.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
}

impl GentooError {
    /// A configuration that cannot be provisioned from, naming what to do
    /// instead.
    pub(crate) fn config(reason: impl Into<String>) -> GentooError {
        GentooError::Config {
            reason: reason.into(),
        }
    }

    /// A refused signature, naming what was being verified and why it was not
    /// accepted.
    ///
    /// Arguments run subject, then cause, which is the order every constructor
    /// in the crate takes them in.
    pub(crate) fn signature(subject: impl Into<String>, err: OpenPgpError) -> GentooError {
        GentooError::Signature {
            subject: subject.into(),
            reason: err.to_string(),
        }
    }

    /// A verified document that does not say what the layer needs, naming what
    /// was being read and what was wrong.
    pub(crate) fn document(subject: impl Into<String>, reason: impl Into<String>) -> GentooError {
        GentooError::Document {
            subject: subject.into(),
            reason: reason.into(),
        }
    }

    /// A package database holding something that is not an entry, naming the
    /// root and what was wrong.
    pub(crate) fn database(root: impl Into<PathBuf>, reason: impl Into<String>) -> GentooError {
        GentooError::Database {
            root: root.into(),
            reason: reason.into(),
        }
    }

    /// An index that arrived and could not be read, naming where it came from
    /// and what was wrong.
    pub(crate) fn index(subject: impl Into<String>, reason: impl Into<String>) -> GentooError {
        GentooError::Index {
            subject: subject.into(),
            reason: reason.into(),
        }
    }

    /// A host I/O failure, naming what the operation was doing and the path it
    /// concerned.
    ///
    /// Arguments run operation, then locator, then cause, which is the order
    /// every constructor in the crate takes them in.
    pub fn io(op: &'static str, path: impl Into<PathBuf>, source: io::Error) -> GentooError {
        GentooError::Io {
            op,
            path: path.into(),
            source,
        }
    }

    /// The same failure as a [`map_err`](Result::map_err) argument: names the
    /// operation and the path now, and takes the cause when it arrives.
    pub fn at(op: &'static str, path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> GentooError {
        let path = path.into();
        move |source| GentooError::Io { op, path, source }
    }
}

impl From<FetchError> for GentooError {
    fn from(err: FetchError) -> GentooError {
        GentooError::Fetch(err)
    }
}

impl fmt::Display for GentooError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GentooError::Config { reason } => {
                write!(f, "the Gentoo provisioner is misconfigured: {reason}")
            }
            GentooError::Signature { subject, reason } => {
                write!(f, "{subject} was not accepted: {reason}")
            }
            GentooError::Document { subject, reason } => {
                write!(f, "{subject} verified but {reason}")
            }
            GentooError::Index { subject, reason } => {
                write!(f, "the index at {subject} {reason}")
            }
            GentooError::PlanDocument { reason } => {
                write!(f, "the plan document cannot be used: {reason}")
            }
            GentooError::Resolve { reason } => {
                write!(f, "the binhost cannot satisfy what was asked for: {reason}")
            }
            GentooError::Container { subject, reason } => {
                write!(f, "the package at {subject} {reason}")
            }
            GentooError::Database { root, reason } => write!(
                f,
                "the package database of the root at {} cannot be read: {reason}",
                root.display(),
            ),
            GentooError::Stale {
                published,
                age,
                limit,
            } => match (published, age) {
                (Some(published), Some(age)) => write!(
                    f,
                    "the pointer was regenerated at {published}, which is {} days ago, past the \
                     {} days this provisioner accepts",
                    age.as_secs() / 86_400,
                    limit.as_secs() / 86_400,
                ),
                _ => write!(
                    f,
                    "the pointer states no regeneration timestamp, which is the only bound on how \
                     old it may be; clear the bound with max_pointer_age to accept one anyway",
                ),
            },
            GentooError::Digest {
                subject,
                expected,
                actual,
            } => write!(
                f,
                "{subject} does not have the digest the archive recorded for it: the signed \
                 document states {expected}, the bytes are {actual}",
            ),
            GentooError::Cancelled => f.write_str("the bootstrap was cancelled"),
            GentooError::Fetch(err) => write!(f, "{err}"),
            GentooError::Io { op, path, source } => {
                write!(
                    f,
                    "provisioning failed while {op} {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for GentooError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GentooError::Fetch(err) => Some(err),
            GentooError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<GentooError> for super::ProvisionError {
    /// A cancellation is the run's own outcome rather than a layer failure, so
    /// it surfaces as the shared variant a caller matches on whichever
    /// provisioner they drove; everything else is this layer's.
    fn from(err: GentooError) -> super::ProvisionError {
        match err {
            GentooError::Cancelled => super::ProvisionError::Cancelled,
            other => super::ProvisionError::other(other),
        }
    }
}

/// What one certificate of the keyring can still be trusted to do, and until
/// when.
///
/// The vendored keyring is a trust anchor with a shelf life, and Gentoo's
/// certificates do not share one date: two of the eleven lapse well before the
/// rest. Reporting per certificate rather than as a single earliest expiry is
/// what keeps a keyring whose signing key is good for years from reading as
/// nearly expired because a certificate it never meets is. Reducing the list to
/// one number is the caller's judgement, and it needs [`signs`](Self::signs) to
/// make it well.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CertificateHorizon {
    /// The primary key's fingerprint, uppercase hex and undelimited, as the
    /// OpenPGP tools present one.
    pub fingerprint: String,
    /// The certificate's primary user id, as it spells itself, or `None` where
    /// it carries none that is UTF-8.
    pub user_id: Option<String>,
    /// The epoch at which the certificate's authority lapses, or `None` when
    /// nothing bounds it.
    ///
    /// Where the certificate can sign, this is the last moment at which a
    /// signature from it would still be accepted — which is not simply the
    /// primary's own expiry, since a subkey's binding may lapse first and a
    /// certificate whose primary may not sign is worth only what its subkeys
    /// are. Where it cannot sign, this is the primary's expiry, which is when
    /// the certificate lapses whether or not that ever mattered.
    pub expires: Option<i64>,
    /// Whether any key under the certificate could make a signature this crate
    /// would accept.
    ///
    /// `false` for a certificate that is in the keyring but can vouch for
    /// nothing: its primary rests on an algorithm this crate refuses and it
    /// delegates to no signing subkey that does. Gentoo's keyring holds one such
    /// certificate, a DSA-1024 release key from 2004. It is harmless — nothing
    /// rests on a key until it produces a signature that passes the gates — but
    /// its expiry says nothing about how long the keyring remains usable, so a
    /// caller reducing the list to one number reads this first.
    pub signs: bool,
}

/// The stage3 a resolution chose: which build, and the digest its bytes are
/// held to.
///
/// This layer's answer to the other userlands' plan, and deliberately a record
/// rather than a document format. A single tarball does not need a versioned
/// serialization, and one would outlive what it describes: the archive keeps
/// about five weeks of builds and publishes no snapshot service, so a document
/// naming a build id would routinely name a build that is gone. A caller who
/// wants to provision the same root again records the
/// [`build_id`](Self::build_id) and [`variant`](Self::variant) however they
/// already record configuration, and
/// [`GentooBuilder::build_id`] takes them back; within one process,
/// [`GentooBuilder::stage3`] carries the whole answer over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage3 {
    build_id: String,
    variant: String,
    path: String,
    size: u64,
    sha512: String,
    certificate: String,
}

impl Stage3 {
    /// The build directory the tarball sits in, such as `20260810T204554Z`.
    pub fn build_id(&self) -> &str {
        &self.build_id
    }

    /// The variant, as the pointer document spells it.
    pub fn variant(&self) -> &str {
        &self.variant
    }

    /// The tarball's path under the architecture's `autobuilds/` tree.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The most bytes the tarball may weigh, and what the download is bounded
    /// by.
    ///
    /// A mirror that answers with more than this is not serving the resource
    /// that was asked for, and the digest that would catch the substitution runs
    /// only after the bytes have been spent.
    ///
    /// Where the resolution read the signed enumeration, this is the exact
    /// length it recorded. Where it acted on a
    /// [`build_id`](GentooBuilder::build_id) pin it is a fixed ceiling instead,
    /// several times the largest stage3 Gentoo publishes: a pin names the build
    /// directly, and nothing Gentoo signs states the length of a tarball inside
    /// one. So this is a bound in both cases and a size in one, and a caller
    /// showing a download's size or preallocating for it wants the resolution
    /// they got it from to be an unpinned one.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The SHA-512 the signed digest document records for the tarball,
    /// lowercase hex.
    pub fn sha512(&self) -> &str {
        &self.sha512
    }

    /// The tarball's file name, which is what the digest document names it by
    /// and what the cache holds it under.
    fn file_name(&self) -> &str {
        file_name_of(&self.path)
    }

    /// The fingerprint of the certificate that vouched for the digest document,
    /// uppercase hex.
    ///
    /// The stable identity of the key the chain rests on: it names a keyring
    /// entry, it is what a policy pinning the archive would pin, and it does not
    /// move when the certificate rotates its signing subkey.
    pub fn certificate(&self) -> &str {
        &self.certificate
    }
}

/// The file name at the end of an archive-relative path.
///
/// The tarball is named by its file name in two places that have to agree: the
/// digest document records it that way, and the cache holds it under it.
fn file_name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The stage3 variants an architecture publishes.
///
/// Produced by [`Gentoo::available`], and read out of the signed pointer
/// document, so this is what Gentoo publishes now rather than what this crate
/// was compiled knowing. It is a snapshot: the archive regenerates the document
/// on a schedule, so a build id reported here is the one that was current when
/// it was read.
pub struct Available {
    published: Option<i64>,
    entries: Vec<pointer::Entry>,
}

impl fmt::Debug for Available {
    /// Renders how many variants were read and when the document was
    /// regenerated, rather than the whole enumeration: an architecture can
    /// publish forty of them, and the counts are what a reader of a rendering
    /// can act on.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Available")
            .field("variants", &self.entries.len())
            .field("published", &self.published)
            .finish()
    }
}

impl Available {
    /// Every variant the architecture publishes, as the document spells them,
    /// in the order it lists them.
    pub fn variants(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.variant.as_str())
    }

    /// Whether `variant` is one of them, matched exactly.
    pub fn contains(&self, variant: &str) -> bool {
        self.entries.iter().any(|entry| entry.variant == variant)
    }

    /// The build `variant` currently points at, such as `20260810T204554Z`.
    ///
    /// Not one build id for the architecture: a sub-architecture is built on its
    /// own cadence, so one document routinely points different variants at
    /// different builds.
    pub fn build_id(&self, variant: &str) -> Option<&str> {
        self.entry(variant).map(|entry| entry.build_id.as_str())
    }

    /// The size in bytes of the tarball `variant` currently points at.
    pub fn size(&self, variant: &str) -> Option<u64> {
        self.entry(variant).map(|entry| entry.size)
    }

    /// The epoch the pointer states it was regenerated at, or `None` where it
    /// states none.
    ///
    /// Gentoo's only published measure of how current the enumeration is. It
    /// measures the document rather than the builds it names, being rebuilt on a
    /// schedule whether or not anything new landed.
    pub fn published(&self) -> Option<i64> {
        self.published
    }

    /// The entry for `variant`.
    fn entry(&self, variant: &str) -> Option<&pointer::Entry> {
        self.entries.iter().find(|entry| entry.variant == variant)
    }
}

/// A Gentoo stage3 bootstrap, configured then run.
///
/// The architecture is the tree the archive publishes under — `amd64`, `arm64`,
/// `x86` — and names a directory in every URL the layer fetches.
///
/// # Example
///
/// ```
/// use ferroday_cage::provision::gentoo::Gentoo;
///
/// # fn main() -> Result<(), ferroday_cage::provision::gentoo::GentooError> {
/// let gentoo = Gentoo::builder("amd64").build()?;
/// // Every certificate the crate would verify a document against, with the
/// // date its authority lapses.
/// assert!(gentoo.keyring_horizon().iter().any(|held| held.signs));
/// # Ok(())
/// # }
/// ```
pub struct Gentoo {
    /// The architecture every document is read for, and a directory in each
    /// URL the layer fetches.
    architecture: String,
    /// The variant to resolve, where the caller named one.
    variant: Option<String>,
    /// The binhost sub-architecture to install binary packages from, where the
    /// caller named one.
    binhost: Option<String>,
    /// The atoms to install from the binhost, parsed at build time so a
    /// misspelled one is refused before anything is fetched.
    install: Vec<atom::Atom>,
    /// The USE flags the caller would rather a build carried, in the order they
    /// were named.
    prefer_use: Vec<resolve::Preference>,
    /// A resolution to install instead of performing one, where the caller
    /// supplied a plan.
    plan: Option<Plan>,
    /// The root a layered build stages its increment over, where the caller
    /// named one.
    base_layer: Option<PathBuf>,
    /// The build directory to resolve within instead of the one the pointer
    /// currently names, where the caller pinned one.
    build_id: Option<String>,
    /// A resolution to act on instead of performing one, where the caller
    /// carried one over from an earlier call.
    stage3: Option<Stage3>,
    /// How old a pointer may be, or `None` where the caller cleared the bound.
    max_pointer_age: Option<Duration>,
    /// The archives to read, the primary first.
    mirrors: Vec<String>,
    /// Where the tarball is kept across runs, where the caller named a place.
    cache_dir: Option<PathBuf>,
    /// The certificates every signed document is verified against.
    keyring: Keyring,
    /// The transport every fetch goes through.
    fetcher: Box<dyn Fetch>,
}

impl fmt::Debug for Gentoo {
    /// Renders the configuration. The keyring is not rendered: it is a fixed
    /// trust anchor, and what a reader can act on about it is
    /// [`keyring_horizon`](Gentoo::keyring_horizon) rather than its bytes. The
    /// transport is named by neither its type nor its state, a `Fetch` being a
    /// caller's value this crate knows nothing renderable about.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gentoo")
            .field("architecture", &self.architecture)
            .field("variant", &self.variant)
            .field("binhost", &self.binhost)
            .field("install", &self.install)
            .field("prefer_use", &self.prefer_use)
            .field("plan", &self.plan)
            .field("base_layer", &self.base_layer)
            .field("build_id", &self.build_id)
            .field("stage3", &self.stage3)
            .field("max_pointer_age", &self.max_pointer_age)
            .field("mirrors", &self.mirrors)
            .field("cache_dir", &self.cache_dir)
            .field("fetcher", &Delegate("dyn Fetch"))
            .finish_non_exhaustive()
    }
}

impl Gentoo {
    /// Returns a builder for a bootstrap of `architecture` — the tree the
    /// archive publishes under, such as `amd64`, `arm64` or `x86`.
    pub fn builder(architecture: impl Into<String>) -> GentooBuilder {
        GentooBuilder {
            architecture: architecture.into(),
            variant: None,
            binhost: None,
            install: Vec::new(),
            prefer_use: Vec::new(),
            plan: None,
            base_layer: None,
            build_id: None,
            stage3: None,
            max_pointer_age: Some(DEFAULT_MAX_POINTER_AGE),
            mirror: None,
            fallbacks: Vec::new(),
            cache_dir: None,
            fetcher: None,
        }
    }

    /// The architecture the layer reads the archive for.
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// What each certificate of the keyring can still be trusted to do, and
    /// until when, in the order the keyring holds them.
    ///
    /// Gentoo publishes no deadline on the keyring itself, and its certificates
    /// expire on several different dates, so this is how a caller learns the
    /// anchor is ageing before an archive fetch tells them. The judgement is the
    /// verification's own rather than a second reading of the same certificates,
    /// so what is reported here is what a signature would actually be held to.
    ///
    /// Reducing the list to one number is the caller's: the earliest expiry
    /// among the certificates that [can sign](CertificateHorizon::signs) is the
    /// one worth acting on.
    pub fn keyring_horizon(&self) -> Vec<CertificateHorizon> {
        self.keyring
            .horizon()
            .into_iter()
            .map(|held| CertificateHorizon {
                fingerprint: held.fingerprint,
                user_id: held.user_id,
                expires: held.expires,
                signs: held.signs,
            })
            .collect()
    }

    /// The stage3 variants the architecture publishes, from the signed
    /// enumeration.
    ///
    /// The read half of a resolution: it fetches the pointer document, verifies
    /// it against the keyring, and reports what it names. Nothing is downloaded.
    ///
    /// # Errors
    ///
    /// Returns [`GentooError::Fetch`] when no mirror serves the pointer,
    /// [`GentooError::Signature`] when what one served does not verify,
    /// [`GentooError::Stale`] when the pointer is older than
    /// [`max_pointer_age`](GentooBuilder::max_pointer_age), and
    /// [`GentooError::Document`] when it names no stage3 this crate can address.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ferroday_cage::provision::gentoo::Gentoo;
    ///
    /// # fn main() -> Result<(), ferroday_cage::provision::gentoo::GentooError> {
    /// let mut gentoo = Gentoo::builder("amd64").build()?;
    /// let available = gentoo.available()?;
    /// assert!(available.contains("amd64-openrc"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn available(&mut self) -> Result<Available, GentooError> {
        let pointer = self.read_pointer(None)?;
        Ok(Available {
            published: pointer.published(),
            entries: pointer.entries().to_vec(),
        })
    }

    /// What the configured binhost publishes.
    ///
    /// The read half of an install: it fetches the binary-package index,
    /// parses it, and reports the names and versions it names. Nothing is
    /// downloaded, so this serves an architecture the host could never run.
    ///
    /// Nothing signs the index, and no amount of asking would change that —
    /// Gentoo publishes no signature over it in any form. Every package it
    /// names carries a cleartext-signed `Manifest` of its own, which is what an
    /// install verifies; the index decides which package is asked for, and a
    /// hostile mirror can therefore decide that. What the identity check inside
    /// each container closes is the substitution that would otherwise follow.
    ///
    /// # Errors
    ///
    /// Returns [`GentooError::Config`] when no binhost sub-architecture was
    /// named, [`GentooError::Fetch`] when no mirror serves the index, and
    /// [`GentooError::Index`] when what one served could not be read as one.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ferroday_cage::provision::gentoo::Gentoo;
    ///
    /// # fn main() -> Result<(), ferroday_cage::provision::gentoo::GentooError> {
    /// let mut gentoo = Gentoo::builder("amd64").binhost("x86-64").build()?;
    /// let catalogue = gentoo.packages()?;
    /// println!("{} packages in {} builds", catalogue.len(), catalogue.builds());
    /// # Ok(())
    /// # }
    /// ```
    pub fn packages(&mut self) -> Result<Catalogue, GentooError> {
        Ok(self.read_index(None)?.into_catalogue())
    }

    /// What installing the configured atoms into the root at `root` would
    /// install.
    ///
    /// The read half of an install wave: it fetches the index, reads what
    /// `root` already has, resolves the two against each other and reports the
    /// [`Plan`]. Nothing is downloaded and nothing is merged.
    ///
    /// # Why this takes a root
    ///
    /// Because on this archive the answer has no meaning without one, and that
    /// is the shape neither of the other userlands has. A stage3 arrives with
    /// 296 packages already installed, and one of them — `app-crypt/pinentry` —
    /// the binhost does not publish in any version. It is in `dev-vcs/git`'s
    /// runtime closure, so resolving git against an empty root does not merely
    /// produce a larger plan: it fails, on an atom the real root answers.
    ///
    /// So `root` is the root the packages would be installed into: the one a
    /// bootstrap has already published, or the base of a layered build. A
    /// resolution against a root that does not exist yet is a resolution
    /// against nothing, which this archive does not support and which a
    /// signature that defaulted the root would quietly produce.
    ///
    /// # Errors
    ///
    /// Returns [`GentooError::Config`] when no binhost or no atom was named,
    /// [`GentooError::Fetch`] or [`GentooError::Index`] for an index that
    /// cannot be read, [`GentooError::Database`] for a root whose own database
    /// cannot be, and [`GentooError::Resolve`] for a request the binhost cannot
    /// satisfy — naming every atom it could not answer and every conflict it
    /// met, rather than only the first.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ferroday_cage::provision::gentoo::Gentoo;
    ///
    /// # fn main() -> Result<(), ferroday_cage::provision::gentoo::GentooError> {
    /// let mut gentoo = Gentoo::builder("amd64")
    ///     .binhost("x86-64")
    ///     .install(["dev-vcs/git"])
    ///     .build()?;
    /// let plan = gentoo.resolve_packages("/var/lib/machines/gentoo")?;
    /// for package in &plan.packages {
    ///     println!("{}-{} build {}", package.name, package.version, package.build_id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn resolve_packages(&mut self, root: impl AsRef<Path>) -> Result<Plan, GentooError> {
        let installed = installed::installed(root)?;
        self.resolve_install(&installed, None)
    }

    /// The resolution, with somewhere to report to.
    ///
    /// Shared by [`resolve_packages`](Self::resolve_packages) and the install
    /// wave, so the answer a caller previews and the answer a run installs come
    /// from one code path and cannot drift apart.
    fn resolve_install(
        &mut self,
        installed: &Installed,
        to: Reporting<'_, '_>,
    ) -> Result<Plan, GentooError> {
        // A plan is a caller saying what to install, so there is nothing to
        // resolve and no index to fetch.
        if let Some(plan) = &self.plan {
            return Ok(plan.clone());
        }
        let Some(binhost) = self.binhost.clone() else {
            return Err(GentooError::config(
                "no binhost sub-architecture was named; call GentooBuilder::binhost with one of \
                 the trees the architecture publishes, such as \"x86-64\"",
            ));
        };
        if self.install.is_empty() {
            return Err(GentooError::config(
                "no package was asked for; call GentooBuilder::install with an atom such as \
                 \"dev-vcs/git\"",
            ));
        }
        let index = self.read_index(to)?;
        report(
            to,
            GentooEvent::Index {
                builds: index.records().len(),
                skipped: index.skipped(),
                generated: index.preamble().generated,
            },
        );
        let (resolved, refusals) =
            resolve::resolve(&index, installed, &self.install, &self.prefer_use);
        for cycle in &resolved.cycles {
            report(to, GentooEvent::DependencyCycle { packages: cycle });
        }
        if !refusals.is_empty() {
            for unmet in &refusals.unsatisfied {
                report(
                    to,
                    GentooEvent::Unsatisfiable {
                        atom: &unmet.atom,
                        wanted_by: &unmet.wanted_by,
                        reason: &unmet.reason,
                    },
                );
            }
            for conflict in &refusals.conflicts {
                report(
                    to,
                    GentooEvent::Conflict {
                        atom: &conflict.atom,
                        stated_by: &conflict.stated_by,
                        blocks: &conflict.blocks,
                        installed: conflict.installed,
                    },
                );
            }
            for taken in &refusals.occupied {
                report(
                    to,
                    GentooEvent::Occupied {
                        package: &taken.name,
                        slot: &taken.slot,
                        held: &taken.held,
                        second: &taken.second,
                        atom: &taken.atom,
                        wanted_by: &taken.wanted_by,
                    },
                );
            }
            return Err(GentooError::Resolve {
                reason: refusals.describe(),
            });
        }
        Ok(Plan::project(
            &self.architecture,
            &binhost,
            index.preamble().generated,
            &resolved.packages,
        ))
    }

    /// Fetches and parses the binary-package index.
    fn read_index(&mut self, to: Reporting<'_, '_>) -> Result<index::Index, GentooError> {
        let Some(binhost) = self.binhost.clone() else {
            return Err(GentooError::config(
                "no binhost sub-architecture was named; call GentooBuilder::binhost with one of \
                 the trees the architecture publishes, such as \"x86-64\"",
            ));
        };
        let directory = index::directory(&self.architecture, &binhost);
        let mut unserved = None;
        // The compressed form first and the plain one behind it, each walked
        // across every mirror: a mirror that publishes only the plain form is a
        // mirror to fall back to rather than one to give up on.
        for name in index::NAMES {
            let suffix = format!("{directory}/{name}");
            match self.read_bytes(&suffix, MAX_INDEX_BYTES, to) {
                Ok(served) => return read_index_body(&served),
                Err(GentooError::Fetch(err)) if err.is_failover() => unserved = Some(err),
                Err(err) => return Err(err),
            }
        }
        Err(GentooError::Fetch(
            unserved.unwrap_or_else(|| no_mirror(&directory)),
        ))
    }

    /// Fetches one unsigned document, walking the mirrors as
    /// [`read_signed`](Self::read_signed) does but stopping short of a
    /// verification there is nothing to perform.
    ///
    /// Kept apart from that walk rather than folded into it, because the two
    /// differ in what a failure means and not only in a step: a document that
    /// does not verify is fatal there and there is no such outcome here, so a
    /// shared body would carry a flag that decides whether the layer is
    /// checking a signature. The index has none to check.
    fn read_bytes(
        &mut self,
        suffix: &str,
        limit: u64,
        to: Reporting<'_, '_>,
    ) -> Result<Fetched, GentooError> {
        let mut unserved = None;
        for mirror in &self.mirrors {
            stop_if_cancelled(to)?;
            let url = format!("{}/{suffix}", mirror.trim_end_matches('/'));
            report(to, GentooEvent::Fetching { url: &url });
            let mut bytes = Vec::new();
            match self.fetcher.fetch(
                &FetchRequest::new(&url).sized(limit),
                &mut LimitedWriter::new(&mut bytes, limit),
            ) {
                Ok(()) => return Ok(Fetched { url, body: bytes }),
                Err(err) if err.is_failover() => unserved = Some(err),
                Err(err) => return Err(GentooError::Fetch(err)),
            }
        }
        Err(GentooError::Fetch(
            unserved.unwrap_or_else(|| no_mirror(suffix)),
        ))
    }

    /// Resolves the configured variant to a build, and that build to the digest
    /// its bytes will be held to.
    ///
    /// The whole read half of a bootstrap: it fetches and verifies the pointer,
    /// matches the variant against what that names, then fetches and verifies
    /// the digest document beside the chosen build and reads the SHA-512 out of
    /// it. Nothing is downloaded, so this serves an architecture the host could
    /// never run.
    ///
    /// A [`build_id`](GentooBuilder::build_id) resolves within that build
    /// directory instead of the one the pointer names, and skips the pointer
    /// entirely: a pin is a caller saying which build they want, and asking the
    /// archive which is current would not change the answer.
    ///
    /// # Errors
    ///
    /// As [`available`](Self::available), plus [`GentooError::Config`] when no
    /// variant was named or the named one is not in the enumeration — which
    /// names what the architecture does offer.
    pub fn resolve(&mut self) -> Result<Stage3, GentooError> {
        self.resolve_reporting(None)
    }

    /// The resolution, with somewhere to report to.
    ///
    /// Shared by [`resolve`](Self::resolve) and the bootstrap, so the answer a
    /// caller previews and the answer a bootstrap installs come from one code
    /// path and cannot drift apart.
    fn resolve_reporting(&mut self, to: Reporting<'_, '_>) -> Result<Stage3, GentooError> {
        if let Some(stage3) = &self.stage3 {
            return Ok(stage3.clone());
        }
        let Some(variant) = self.variant.clone() else {
            return Err(GentooError::config(
                "no variant was named; call GentooBuilder::variant with one of the names \
                 Gentoo::available reports, such as \"amd64-openrc\"",
            ));
        };
        // A pinned build id is the caller saying which build they want, so the
        // enumeration -- which only ever reports the current one -- has no say.
        // The tarball's name is composed rather than read from a document, and
        // it is the one shape the archive publishes; it is checked on the way
        // out for the same reason every other segment is.
        let (build_id, path, size) = match &self.build_id {
            Some(build_id) => {
                let file = format!("stage3-{variant}-{build_id}.tar.xz");
                let path = format!("{build_id}/{file}");
                coordinate::check("the pinned stage3 path", &path, Nesting::Nested)
                    .map_err(GentooError::config)?;
                (build_id.clone(), path, MAX_STAGE3_BYTES)
            }
            None => {
                let pointer = self.read_pointer(to)?;
                let Some(entry) = pointer.entry(&variant) else {
                    return Err(GentooError::config(format!(
                        "the architecture {} publishes no stage3 variant {variant:?}; it offers {}",
                        self.architecture,
                        pointer.variants().join(", "),
                    )));
                };
                (entry.build_id.clone(), entry.path.clone(), entry.size)
            }
        };

        let suffix = self.url(&format!("{path}.DIGESTS"));
        let digests = self.read_signed(&suffix, MAX_DIGESTS_BYTES, to)?;
        let sha512 = digests::sha512_of(&digests.url, &digests.body, file_name_of(&path))?;
        Ok(Stage3 {
            build_id,
            variant,
            path,
            size,
            sha512,
            certificate: digests.certificate,
        })
    }

    /// Fetches the pointer document, verifies it, and holds it to the age bound.
    fn read_pointer(&mut self, to: Reporting<'_, '_>) -> Result<Pointer, GentooError> {
        let suffix = self.url("latest-stage3.txt");
        let served = self.read_signed(&suffix, MAX_POINTER_BYTES, to)?;
        let pointer = Pointer::parse(&served.url, &served.body)?;
        self.check_fresh(&pointer)?;
        Ok(pointer)
    }

    /// Refuses a pointer older than the configured bound.
    ///
    /// A pointer stating no timestamp is refused on the same terms rather than
    /// waved through: it is the only bound the layer has, so reading its absence
    /// as permission would let whoever serves the document disable the check by
    /// deleting a line. That is the reasoning the signature checks apply to a
    /// missing creation time, arrived at from the same direction.
    ///
    /// When the clock cannot be read the bound is not applied, since a deadline
    /// evaluated against an unreadable clock decides nothing.
    fn check_fresh(&self, pointer: &Pointer) -> Result<(), GentooError> {
        let Some(limit) = self.max_pointer_age else {
            return Ok(());
        };
        let stale = |age| GentooError::Stale {
            published: pointer.published(),
            age,
            limit,
        };
        let Some(published) = pointer.published() else {
            return Err(stale(None));
        };
        let Some(now) = super::now_epoch() else {
            return Ok(());
        };
        let age = Duration::from_secs(now.saturating_sub(published).max(0) as u64);
        if age > limit {
            return Err(stale(Some(age)));
        }
        Ok(())
    }

    /// Fetches a cleartext-signed document and returns it as the mirror that
    /// answered served it.
    ///
    /// The mirror list is walked in order, advancing past a mirror that could
    /// not serve the document. One that serves something that does not verify is
    /// fatal rather than a reason to try the next: what it served was answered
    /// for by the URL that was asked for, and the answer to a refused signature
    /// is never to ask somewhere else. A URL the transport will not accept is
    /// fatal for the same reason -- it is the configuration rather than the
    /// mirror, and walking past it would report the failure against a mirror
    /// that was spelled fine.
    fn read_signed(
        &mut self,
        suffix: &str,
        limit: u64,
        to: Reporting<'_, '_>,
    ) -> Result<Served, GentooError> {
        let mut unserved = None;
        for mirror in &self.mirrors {
            // Before each mirror rather than before the walk: an unreachable
            // mirror costs a connect timeout, so a list of them is a step long
            // enough to want stopping in the middle of.
            stop_if_cancelled(to)?;
            let url = format!("{}/{suffix}", mirror.trim_end_matches('/'));
            // Reported per mirror rather than per document: this walk spends one
            // mirror timeout per unreachable mirror, and an observer that saw
            // only the resolution would watch a bootstrap that looks stopped.
            report(to, GentooEvent::Fetching { url: &url });
            let mut bytes = Vec::new();
            match self.fetcher.fetch(
                &FetchRequest::new(&url).sized(limit),
                &mut LimitedWriter::new(&mut bytes, limit),
            ) {
                Ok(()) => {
                    let verified = self
                        .keyring
                        .verify(&bytes, true)
                        .map_err(|err| GentooError::signature(&url, err))?;
                    return Ok(Served {
                        url,
                        body: verified.body,
                        certificate: verified.certificate,
                    });
                }
                Err(err) if err.is_failover() => unserved = Some(err),
                Err(err) => return Err(GentooError::Fetch(err)),
            }
        }
        Err(GentooError::Fetch(
            unserved.unwrap_or_else(|| no_mirror(suffix)),
        ))
    }

    /// The mirror-relative path of something in this architecture's autobuilds
    /// tree.
    fn url(&self, suffix: &str) -> String {
        format!("releases/{}/autobuilds/{suffix}", self.architecture)
    }
}

/// An unsigned document as it arrived, and the URL that served it.
///
/// The URL is the whole one, as [`Served`]'s is and for the same reason: a walk
/// over several mirrors is exactly when a refusal has to name which one
/// answered.
struct Fetched {
    /// The URL the document arrived from.
    url: String,
    /// The bytes, in whatever compression the archive served them.
    body: Vec<u8>,
}

/// Reads a fetched index body into a parsed index.
///
/// The compression is selected from the bytes rather than from the file name,
/// so the plain form and the compressed one go through one path — and a mirror
/// serving one under the other's name is read for what it is rather than for
/// what it is called.
///
/// The decompressed stream is bounded as well as the fetch: the fetch's ceiling
/// bounds what arrived, and this one bounds what that inflates to, which is the
/// only place a decompression bomb could spend anything.
fn read_index_body(served: &Fetched) -> Result<index::Index, GentooError> {
    let mut body = served.body.as_slice();
    let head = compress::sniff_head(&mut body)
        .map_err(|err| GentooError::index(&served.url, format!("could not be read: {err}")))?;
    let mut reader = compress::decompress(&head, body)
        .map_err(|err| GentooError::index(&served.url, format!("could not be read: {err}")))?;
    let mut bytes = Vec::new();
    io::copy(&mut reader.by_ref().take(MAX_INDEX_BYTES), &mut bytes)
        .map_err(|err| GentooError::index(&served.url, format!("could not be read: {err}")))?;
    // Lossy rather than strict: the index is fifteen thousand stanzas of which
    // this layer reads a dozen fields, and one package's description holding a
    // byte sequence that is not UTF-8 is not a reason to refuse the archive.
    // Every field this layer acts on is held to its own grammar afterwards.
    let parsed = index::Index::parse(&String::from_utf8_lossy(&bytes));
    if parsed.records().is_empty() {
        return Err(GentooError::index(
            &served.url,
            "names no package this layer can act on",
        ));
    }
    // The index's own count against what arrived. Not a security property --
    // the count is in the same unsigned document as the stanzas, so a mirror
    // composing one composes both -- but a plain-text index cut short otherwise
    // parses perfectly and resolves against a silently smaller archive, and
    // this is the only thing that would notice.
    let read = (parsed.records().len() + parsed.skipped()) as u64;
    if let Some(declared) = parsed.preamble().declared
        && read < declared
    {
        return Err(GentooError::index(
            &served.url,
            format!("states that it holds {declared} packages and carries {read}"),
        ));
    }
    Ok(parsed)
}

/// A verified document, and the URL that served it.
///
/// The URL is the whole one, mirror included, rather than the archive-relative
/// path the walk was asked for: it is what tells a caller reading a refusal
/// which mirror answered, and a walk over several of them is exactly when that
/// matters.
struct Served {
    /// The URL the document arrived from.
    url: String,
    /// The cleartext the signature covers.
    body: String,
    /// The verifying certificate's primary-key fingerprint, uppercase hex.
    certificate: String,
}

/// The failure a mirror walk reports when it had nowhere to walk.
///
/// Unreachable as the layer is configured — [`GentooBuilder::build`] composes at
/// least the default archive, so every walk has a mirror and either returns or
/// records that mirror's failure. It is a configuration failure rather than a
/// missing resource, which is also what keeps it out of the failover class:
/// there is nothing to advance to.
fn no_mirror(path: &str) -> FetchError {
    FetchError::url(path, "no mirror is configured to fetch it from")
}

impl Provisioner for Gentoo {
    /// Provisions the configured variant into the request's staging directory.
    ///
    /// Reached through [`provision::ensure`](super::ensure), which supplies the
    /// staging directory, serializes concurrent callers, publishes the finished
    /// tree atomically and removes it on any failure — exactly as it does for
    /// every other provisioner.
    ///
    /// A run that has not resolved resolves as its first step, so a caller who
    /// only wants a root never has to.
    ///
    /// [`ProvisionRequest::cancelled`] is consulted at every step boundary and
    /// while the tarball is being written, which is where the time goes: one
    /// file of several hundred megabytes, with no package boundary to break it
    /// up.
    fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError> {
        let stage3 = self.resolve_reporting(Some(request))?;
        report(Some(request), GentooEvent::Resolved { stage3: &stage3 });
        // The resolution is two small documents and the download is not, so a
        // caller who cancelled during it should not be committed to the
        // download by having asked what would be downloaded.
        stop_if_cancelled(Some(request))?;

        // The cache is the caller's if they named one, and otherwise a sibling
        // of the tree being built that goes with this frame however it ends: a
        // half-gigabyte download beside a root that was never published is not
        // something a later run would find and clear.
        let cache =
            PackageCache::beside(request.staging(), self.cache_dir.as_deref(), STAGE3_CACHE);
        std::fs::create_dir_all(cache.path())
            .map_err(GentooError::at("creating the download cache", cache.path()))?;
        let file = stage3.file_name();
        let tarball = cache.path().join(file);

        // A cached tarball is bytes on a disk this crate does not own, so it is
        // verified on the read rather than trusted for having been verified
        // once. That makes the cache-hit path and the fresh-download path one
        // code path, whichever produced the file.
        if !tarball.is_file() {
            self.download(&stage3, &tarball, Some(request))?;
        }
        // A digest pass over the whole tarball is the second long step, and
        // what precedes it is a complete file in a cache that outlives the run,
        // so stopping here costs the download nothing.
        stop_if_cancelled(Some(request))?;
        report(
            Some(request),
            GentooEvent::Verifying {
                path: tarball.as_path(),
            },
        );
        verify(&tarball, stage3.sha512())?;

        report(
            Some(request),
            GentooEvent::Extracting {
                path: tarball.as_path(),
            },
        );
        // The bytes are verified before the extractor sees them, rather than
        // streamed through it as they arrive: an archive that turns out not to
        // be the one the signed document named would otherwise already have
        // written most of a root filesystem.
        Tarball::new(&tarball).provision(request)?;

        // The second wave. A run that asked for no package stops here and has
        // done exactly what a stage3 bootstrap does, byte for byte.
        if self.install.is_empty() && self.plan.is_none() {
            return Ok(());
        }
        self.install_wave(request.staging(), None, Some(request))?;
        Ok(())
    }
}

impl Gentoo {
    /// Stages the configured install as a disposable overlay upper over the
    /// [`base_layer`](GentooBuilder::base_layer).
    ///
    /// A layered build provisions one base and stages each increment over it:
    /// the base is read-only, the increment lives in `upper`, and the
    /// [`BuildLayer`] returned removes the upper when it is dropped. Root a
    /// cage on
    /// [`overlay_rootfs(base, layer.path())`](crate::CageBuilder::overlay_rootfs)
    /// to build against the merged view.
    ///
    /// Resolution reads the merged view — the base's own database and whatever
    /// the upper already holds — so an increment installs what the base is
    /// missing and no more. The entries it writes land in the upper, and
    /// portage reading the merged root sees the base's and the increment's
    /// together.
    ///
    /// # Errors
    ///
    /// Returns [`ProvisionError`] wrapping [`GentooError::Config`] when no base
    /// layer is set, and the same failures an install wave reports otherwise.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ferroday_cage::provision::gentoo::Gentoo;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut increment = Gentoo::builder("amd64")
    ///     .binhost("x86-64")
    ///     .install(["dev-vcs/git"])
    ///     .base_layer("/var/lib/machines/gentoo")
    ///     .build()?;
    /// let layer = increment.stage_layer("/var/tmp/build-upper")?;
    /// // Root a cage on the merged view; drop `layer` to revert the increment.
    /// # let _ = layer;
    /// # Ok(())
    /// # }
    /// ```
    pub fn stage_layer(&mut self, upper: impl AsRef<Path>) -> Result<BuildLayer, ProvisionError> {
        let upper = upper.as_ref();
        let Some(base) = self.base_layer.clone() else {
            return Err(GentooError::config(
                "no base layer was named; call GentooBuilder::base_layer with the Gentoo root the \
                 increment is staged over",
            )
            .into());
        };
        std::fs::create_dir_all(upper)
            .map_err(|err| ProvisionError::io("creating the overlay upper", upper, err))?;
        // The handle that owns the upper is taken as soon as the upper exists,
        // not on the way out, so a failure below disposes of a partly-installed
        // increment instead of orphaning it: there is no handle in an `Err` for
        // the caller to drop.
        let layer = BuildLayer::new(upper, IdentityMap::Single);
        self.install_wave(upper, Some(&base), None)?;
        Ok(layer)
    }

    /// Installs the configured atoms into `root`, merging each package and
    /// registering its database entry.
    ///
    /// `over` is the base an increment is staged over, where this is a layered
    /// build: resolution then describes the merged view rather than the upper
    /// alone, because that is what a package manager inside the finished
    /// sandbox sees.
    ///
    /// Cancellation is consulted between packages and while each one is being
    /// downloaded. A wave installing a hundred packages is the longest thing
    /// this layer does, and a check that ran only around it would answer a
    /// caller who asked to stop once all of it had arrived.
    fn install_wave(
        &mut self,
        root: &Path,
        over: Option<&Path>,
        to: Reporting<'_, '_>,
    ) -> Result<(), ProvisionError> {
        let installed = match over {
            Some(base) => installed::merged(base, root)?,
            None => installed::installed(root)?,
        };
        let plan = self.resolve_install(&installed, to)?;
        report(
            to,
            GentooEvent::Planned {
                packages: plan.packages.len(),
                bytes: plan.packages.iter().map(|package| package.size).sum(),
            },
        );
        // The resolution is one document and the downloads are not, so a caller
        // who cancelled during it is not committed to them by having asked what
        // would be installed.
        stop_if_cancelled(to)?;
        if plan.packages.is_empty() {
            return Ok(());
        }

        let cache = PackageCache::beside(root, self.cache_dir.as_deref(), PACKAGE_CACHE);
        let directory = index::directory(&self.architecture, &plan.binhost);
        let rooted = Rooted::open(root).map_err(GentooError::at("opening the root", root))?;
        // The merge ordinal continues the root's own sequence, and for a
        // layered build that sequence is the base's: an increment that started
        // again at one would give two packages the same ordinal, and the
        // database could no longer say which was merged first.
        let mut counter = vdb::counter_of(root, &rooted)?;
        if let Some(base) = over {
            let below = Rooted::open(base).map_err(GentooError::at("opening the base", base))?;
            counter = counter.max(vdb::counter_of(base, &below)?);
        }
        for planned in &plan.packages {
            stop_if_cancelled(to)?;
            // The path came out of an index or a plan document and passed
            // `coordinate::check` either way, so it names something under the
            // cache and under the binhost directory and nothing else.
            let cached = cache.path().join(&planned.path);
            if let Some(parent) = cached.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(GentooError::at("creating the download cache", parent))?;
            }
            // A cached container is bytes on a disk this crate does not own, so
            // it is verified on the read rather than trusted for having been
            // verified once -- which makes the cache-hit path and the
            // fresh-download path one code path.
            if !cached.is_file() {
                self.download_package(&directory, planned, &cached, to)?;
            }
            report(
                to,
                GentooEvent::Merging {
                    package: &planned.name,
                    version: &planned.version,
                },
            );
            let package = match gpkg::Package::open(&cached, planned, &self.keyring) {
                Ok(package) => package,
                Err(err) => {
                    // A container that is not what it should be is not the
                    // archive's file whatever it is, and leaving it would make
                    // every later run fail identically out of its own cache --
                    // which reads as a permanent failure rather than as a
                    // mirror that served the wrong bytes once. The same rule
                    // the stage3's digest check applies.
                    let _ = std::fs::remove_file(&cached);
                    return Err(err.into());
                }
            };
            counter += 1;
            vdb::merge(root, &rooted, &cached, &package, planned, counter)?;
        }
        Ok(())
    }

    /// Downloads one binary package into the cache, atomically.
    ///
    /// Bounded by the length the index published for it *and* by
    /// [`MAX_PACKAGE_BYTES`], because the index's number can be wrong in both
    /// directions and only one of them fails closed. Understated, it stops the
    /// download short and the container fails its digest. Overstated, it merely
    /// relaxes the bound — a transport caps at the smaller of the declared size
    /// and its own ceiling — so a hostile or damaged index buys whatever that
    /// ceiling is, once per package. Nothing signs the index, so this layer
    /// keeps a ceiling of its own and the smaller of the two wins.
    fn download_package(
        &mut self,
        directory: &str,
        planned: &PlannedPackage,
        dest: &Path,
        to: Reporting<'_, '_>,
    ) -> Result<(), GentooError> {
        let mut unserved = None;
        for mirror in &self.mirrors {
            stop_if_cancelled(to)?;
            let url = format!(
                "{}/{directory}/{}",
                mirror.trim_end_matches('/'),
                planned.path,
            );
            report(to, GentooEvent::Fetching { url: &url });
            let bound = planned.size.min(MAX_PACKAGE_BYTES);
            match fetch_to(self.fetcher.as_mut(), &url, bound, dest, BINARY_PACKAGE, to) {
                Ok(()) => return Ok(()),
                Err(GentooError::Fetch(err)) if err.is_failover() => unserved = Some(err),
                Err(err) => return Err(err),
            }
        }
        Err(GentooError::Fetch(
            unserved.unwrap_or_else(|| no_mirror(&planned.path)),
        ))
    }

    /// Downloads a stage3 into the cache, atomically.
    ///
    /// The body is written to a staging file beside the destination and renamed
    /// onto it, so a partial download is never visible at the cache path and a
    /// concurrent download of the same build publishes its own file rather than
    /// consuming this one. What the rename publishes is a complete body rather
    /// than a verified one; the verification is the read that follows.
    ///
    /// The size the signed enumeration recorded bounds what the download may
    /// spend. It is a length a verified source declared, so it travels as
    /// [`FetchRequest::sized`] as well as capping the writer.
    fn download(
        &mut self,
        stage3: &Stage3,
        dest: &Path,
        to: Reporting<'_, '_>,
    ) -> Result<(), GentooError> {
        let mut unserved = None;
        for mirror in &self.mirrors {
            stop_if_cancelled(to)?;
            let url = format!(
                "{}/releases/{}/autobuilds/{}",
                mirror.trim_end_matches('/'),
                self.architecture,
                stage3.path,
            );
            report(to, GentooEvent::Fetching { url: &url });
            match fetch_to(self.fetcher.as_mut(), &url, stage3.size, dest, STAGE3, to) {
                Ok(()) => return Ok(()),
                Err(GentooError::Fetch(err)) if err.is_failover() => unserved = Some(err),
                Err(err) => return Err(err),
            }
        }
        Err(GentooError::Fetch(
            unserved.unwrap_or_else(|| no_mirror(&stage3.path)),
        ))
    }
}

/// What a download is of, so the three operations [`fetch_to`] can fail at name
/// their subject.
///
/// Spelled out per caller rather than composed from one noun, because an error's
/// operation is a `&'static str` throughout this crate: naming what failed is
/// part of the convention, and formatting the subject in would make each
/// operation a `String` that outlives nothing.
#[derive(Clone, Copy)]
struct Downloading {
    /// Creating the staging file beside the destination.
    staging: &'static str,
    /// Writing the body into it.
    writing: &'static str,
    /// Renaming it onto the destination.
    publishing: &'static str,
}

/// A stage3 tarball.
const STAGE3: Downloading = Downloading {
    staging: "staging a stage3",
    writing: "writing a stage3",
    publishing: "publishing a stage3",
};

/// A binary package's container.
const BINARY_PACKAGE: Downloading = Downloading {
    staging: "staging a binary package",
    writing: "writing a binary package",
    publishing: "publishing a binary package",
};

/// Writes one URL's body to `dest` through a staging file beside it.
///
/// A cancelled run stops mid-body rather than at the end of it: the write is
/// where a bootstrap spends its time, and a check that only ran between mirrors
/// would leave a caller who asked to stop waiting for the whole tarball.
fn fetch_to(
    fetcher: &mut dyn Fetch,
    url: &str,
    size: u64,
    dest: &Path,
    what: Downloading,
    to: Reporting<'_, '_>,
) -> Result<(), GentooError> {
    let staged = super::staging_path(dest);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(GentooError::at(what.staging, &staged))?;

    let mut sink = io::BufWriter::new(file);
    let (fetched, cancelled) = {
        let mut body = CancellableWriter {
            inner: LimitedWriter::new(&mut sink, size),
            to,
            cancelled: false,
        };
        let fetched = fetcher.fetch(&FetchRequest::new(url).sized(size), &mut body);
        (fetched, body.cancelled)
    };
    // The last buffer is written here rather than by `BufWriter`'s own `Drop`,
    // which has nowhere to report a failure and so swallows it. A body whose
    // tail never reached the disk would otherwise be renamed into the cache and
    // reported by the read that follows as a digest failure -- an authenticity
    // answer to a local write failure, which is the wrong thing to tell a caller
    // and the wrong thing for them to act on.
    let flushed = sink
        .into_inner()
        .map(|_| ())
        .map_err(|err| GentooError::at(what.writing, &staged)(err.into_error()));

    // A stopped write reaches the transport as a write failure, which is what
    // the sink has to answer it with; what it means is the run's own outcome,
    // and reporting it as a transport failure would send a mirror walk to the
    // next mirror to do the same thing again.
    let published = if cancelled {
        Err(GentooError::Cancelled)
    } else {
        fetched
            .map_err(GentooError::Fetch)
            .and(flushed)
            .and_then(|()| {
                std::fs::rename(&staged, dest).map_err(GentooError::at(what.publishing, dest))
            })
    };
    if published.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    published
}

/// A sink that stops accepting bytes once the run has been cancelled.
///
/// The other userlands need nothing like it: they download packages, so a check
/// between two of them stops a bootstrap within one package's worth of bytes. A
/// stage3 is a single file of several hundred megabytes, and a check that ran
/// only at the step boundaries around it would answer a caller who asked to stop
/// once the whole thing had arrived.
///
/// The binary packages go through it too, since they share [`fetch_to`]. There
/// the argument is weaker per file and stronger per run: a package is a few
/// megabytes, and an install wave is a hundred of them.
///
/// The stop is recorded here rather than read back out of the [`io::Error`] the
/// transport returns: a `Fetch` implementation is a caller's own and may report
/// a failed write however it likes, and this is the one thing about it this
/// crate knows first-hand.
struct CancellableWriter<'a, 'r, W> {
    inner: W,
    to: Reporting<'a, 'r>,
    cancelled: bool,
}

impl<W: io::Write> io::Write for CancellableWriter<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(request) = self.to
            && request.cancelled()
        {
            self.cancelled = true;
            // Not `Interrupted`, which `io::copy` and `write_all` retry: a
            // cancellation is the one write failure that must not be retried.
            return Err(io::Error::other("the bootstrap was cancelled"));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Holds a downloaded tarball to the SHA-512 the signed document recorded.
///
/// A tarball that does not match is removed rather than left in the cache. It
/// is not the archive's file whatever it is, and leaving it would make every
/// later run of the same build fail identically out of its own cache, which
/// reads as a permanent failure rather than as a mirror that served the wrong
/// bytes once.
fn verify(tarball: &Path, expected: &str) -> Result<(), GentooError> {
    let mut file = std::fs::File::open(tarball).map_err(GentooError::at("opening", tarball))?;
    let (actual, _) = digest::stream(Algorithm::Sha512, &mut file)
        .map_err(GentooError::at("digesting", tarball))?;
    if actual != expected {
        let _ = std::fs::remove_file(tarball);
        return Err(GentooError::Digest {
            subject: tarball.display().to_string(),
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(())
}

/// Something the Gentoo provisioner is doing, reported to a run's observer.
///
/// Nested in [`ProvisionEvent::Gentoo`], so one observer attached with
/// [`Provision::observe`](super::Provision::observe) covers every provisioner.
/// The set is small because the work is: there is no dependency closure to
/// resolve, no configure wave, and nothing running in a cage, so a bootstrap is
/// a fetch, a digest and an extraction.
#[derive(Debug)]
#[non_exhaustive]
pub enum GentooEvent<'a> {
    /// A URL is being fetched: one of the two signed documents, or the tarball.
    #[non_exhaustive]
    Fetching {
        /// The URL.
        url: &'a str,
    },
    /// The variant has been resolved to a build, carrying what a bootstrap will
    /// install.
    ///
    /// Emitted mid-bootstrap, once the resolution has produced an answer and
    /// before the tarball is downloaded, so a consumer sees exactly what
    /// [`provision::ensure`](super::ensure) chose without a separate
    /// [`Gentoo::resolve`] pass. Where the caller carried a [`Stage3`] over with
    /// [`GentooBuilder::stage3`] that answer is the one they supplied, and
    /// nothing was fetched or verified to arrive at it.
    #[non_exhaustive]
    Resolved {
        /// The stage3 the bootstrap will install.
        stage3: &'a Stage3,
    },
    /// A tarball is being digested and compared against the signed document.
    ///
    /// Reported for a fresh download and a cache hit alike, both going through
    /// the same check: a file in the cache is bytes on a disk this crate does
    /// not own, so it is verified on the read rather than trusted for having
    /// been verified once.
    #[non_exhaustive]
    Verifying {
        /// The tarball, in the cache.
        path: &'a Path,
    },
    /// A verified tarball is being extracted into the root.
    #[non_exhaustive]
    Extracting {
        /// The tarball, in the cache.
        path: &'a Path,
    },
    /// The binary-package index has been read.
    #[non_exhaustive]
    Index {
        /// How many published builds it names.
        builds: usize,
        /// How many stanzas were read and not kept: a record whose `CPV` this
        /// layer could not split, whose path would not stay inside the archive,
        /// or whose dependency classes it could not read. A live archive
        /// reports zero.
        skipped: usize,
        /// The epoch the index states it was generated at, where it states one.
        ///
        /// Nothing signs the index, so this is a mirror's claim rather than a
        /// verified fact.
        generated: Option<i64>,
    },
    /// A runtime-dependency cycle was broken to produce an install order.
    ///
    /// Gentoo's runtime graph has them, and portage breaks them too. The rule
    /// is stable — the first package still waiting, in name order — so a cycle
    /// broken in one run is broken the same way in the next.
    #[non_exhaustive]
    DependencyCycle {
        /// The packages still waiting on each other, as `category/name-version`.
        packages: &'a [String],
    },
    /// An atom nothing published can satisfy.
    ///
    /// Reported for every such atom before the run fails, so a caller fixing an
    /// install list sees the whole list rather than the first entry of it.
    #[non_exhaustive]
    Unsatisfiable {
        /// The atom, as it was written.
        atom: &'a str,
        /// Who asked for it: the install list, or the package whose dependency
        /// it is.
        wanted_by: &'a str,
        /// What the wall was, in the sentence "no build ...": the name, the
        /// version, the slot, or a USE flag.
        reason: &'a str,
    },
    /// The install set has been resolved, and the wave is about to download it.
    #[non_exhaustive]
    Planned {
        /// How many packages it holds, which is what the root is missing rather
        /// than what the request names: a stage3 already answers most of a
        /// closure.
        packages: usize,
        /// What they weigh on the wire in total, from the sizes the index
        /// published.
        bytes: u64,
    },
    /// A verified package is being merged into the root and registered.
    #[non_exhaustive]
    Merging {
        /// The package, as `category/name`.
        package: &'a str,
        /// The version being merged.
        version: &'a str,
    },
    /// A blocker matched something the root has or the resolution chose.
    #[non_exhaustive]
    Conflict {
        /// The blocker atom, as it was written.
        atom: &'a str,
        /// The package that states it.
        stated_by: &'a str,
        /// What it matched, as `category/name-version`.
        blocks: &'a str,
        /// Whether what it matched is already in the root, rather than
        /// something this same resolution would install.
        installed: bool,
    },
    /// Two builds the resolution would have chosen occupy one slot of one
    /// package.
    ///
    /// Portage keeps one instance per `(package, slot)` and reports a root
    /// holding two as a conflict, so this is refused rather than merged. It is
    /// reached whenever the closure constrains one package from two directions
    /// at once — an atom holding it below a version and another holding it at or
    /// above one.
    #[non_exhaustive]
    Occupied {
        /// The package, as `category/name`.
        package: &'a str,
        /// The slot both would occupy, without a sub-slot.
        slot: &'a str,
        /// The build already chosen, as `category/name-version build N`.
        held: &'a str,
        /// The build that would have joined it, spelled the same way.
        second: &'a str,
        /// The atom that asked for the second, as it was written.
        atom: &'a str,
        /// Who asked for it: the caller, or the package whose dependency it is.
        wanted_by: &'a str,
    },
}

/// Where a step reports to, when anything is listening.
///
/// A resolve reached directly has nothing to report to: this layer offers no
/// observer of its own, its read half being two small fetches rather than the
/// long resolve the other userlands attach one for. One reached through
/// [`provision::ensure`](super::ensure) reports into that run's observer.
type Reporting<'a, 'r> = Option<&'a ProvisionRequest<'r>>;

/// Reports `event` where anything is listening.
fn report(to: Reporting<'_, '_>, event: GentooEvent<'_>) {
    if let Some(request) = to {
        request.report(ProvisionEvent::Gentoo(&event));
    }
}

/// Stops where the run has been cancelled.
///
/// Consulted at the boundaries where stopping is clean: nothing has been
/// published, and the staging tree [`provision::ensure`](super::ensure) removes
/// on any failure is what a partial bootstrap amounts to. A read half reached
/// directly has no request to ask, which is the same thing [`Reporting`] models
/// for progress — nothing is driving the call, so nothing can have cancelled
/// it.
fn stop_if_cancelled(to: Reporting<'_, '_>) -> Result<(), GentooError> {
    match to {
        Some(request) if request.cancelled() => Err(GentooError::Cancelled),
        _ => Ok(()),
    }
}

/// A [`Gentoo`] under construction.
pub struct GentooBuilder {
    architecture: String,
    variant: Option<String>,
    binhost: Option<String>,
    /// The atoms as the caller wrote them, parsed at
    /// [`build`](GentooBuilder::build) so a refusal names the whole
    /// configuration rather than the call that added a line to it.
    install: Vec<String>,
    prefer_use: Vec<String>,
    plan: Option<Plan>,
    base_layer: Option<PathBuf>,
    build_id: Option<String>,
    stage3: Option<Stage3>,
    max_pointer_age: Option<Duration>,
    /// The archive to read, or `None` for the default one.
    ///
    /// Kept apart from the backstops, as the other two userlands keep theirs,
    /// so that the two methods compose whichever order a caller writes them in.
    /// The walk list is assembled in [`build`](GentooBuilder::build).
    mirror: Option<String>,
    fallbacks: Vec<String>,
    cache_dir: Option<PathBuf>,
    fetcher: Option<Box<dyn Fetch>>,
}

impl fmt::Debug for GentooBuilder {
    /// Renders the configuration, with the transport named by its presence
    /// rather than its contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GentooBuilder")
            .field("architecture", &self.architecture)
            .field("variant", &self.variant)
            .field("binhost", &self.binhost)
            .field("install", &self.install)
            .field("prefer_use", &self.prefer_use)
            .field("plan", &self.plan)
            .field("base_layer", &self.base_layer)
            .field("build_id", &self.build_id)
            .field("stage3", &self.stage3)
            .field("max_pointer_age", &self.max_pointer_age)
            .field("mirror", &self.mirror)
            .field("fallbacks", &self.fallbacks)
            .field("cache_dir", &self.cache_dir)
            .field(
                "fetcher",
                &self.fetcher.as_ref().map(|_| Delegate("dyn Fetch")),
            )
            .finish_non_exhaustive()
    }
}

impl GentooBuilder {
    /// The variant to provision, as the pointer document spells it —
    /// `amd64-openrc`, `amd64-hardened-systemd`, `x32-openrc`.
    ///
    /// The spelling is the whole compound the archive publishes, not a variant
    /// relative to the architecture: amd64's own document lists `amd64-openrc`
    /// and `x32-openrc` as siblings, so a name relative to `amd64` could not
    /// reach the second at all. It is matched exactly against the signed
    /// enumeration, so an unknown one is refused before anything is fetched,
    /// naming what the architecture does offer. [`Gentoo::available`] lists them.
    pub fn variant(mut self, variant: impl Into<String>) -> GentooBuilder {
        self.variant = Some(variant.into());
        self
    }

    /// Install binary packages from the binhost for this sub-architecture —
    /// `x86-64`, `x86-64-v3`, `x86-64_hardened`, `x32`.
    ///
    /// The binhost publishes one tree per sub-architecture under the
    /// architecture's own, and there is no default: the set moves — amd64
    /// publishes four today where it published eight — and the only thing that
    /// enumerates it is an unsigned directory listing. Reading that listing as
    /// discovery would put an unauthenticated document at the head of the trust
    /// chain, which is the reason the keyring is vendored, so the
    /// sub-architecture is the caller's and a wrong one is a 404 rather than a
    /// silently different userland.
    ///
    /// This selects the archive to read. What to install from it is
    /// [`install`](Self::install), and a builder that names a binhost and asks
    /// for no package bootstraps exactly as one that names neither.
    pub fn binhost(mut self, sub_architecture: impl Into<String>) -> GentooBuilder {
        self.binhost = Some(sub_architecture.into());
        self
    }

    /// Install these atoms and their runtime dependencies from the binhost.
    ///
    /// An atom is the dependency grammar Gentoo itself writes:
    /// `dev-vcs/git`, `>=dev-lang/python-3.12`, `dev-libs/openssl:0`,
    /// `dev-vcs/git[keyring]`. Repeating this adds to the list.
    ///
    /// **A USE dependency in an atom is a constraint.** `dev-vcs/git[keyring]`
    /// removes every build that was not compiled with the flag, and if the
    /// binhost publishes none the atom is unsatisfiable and says so. That is
    /// the difference from [`prefer_use`](Self::prefer_use), which reorders the
    /// candidates and can never refuse: state a flag the install *must* have
    /// here, and a flag you would rather it had there.
    ///
    /// A blocker — an atom written `!` or `!!` — is refused. It says what must
    /// not be installed alongside a package rather than what to install, and
    /// this layer installs into a root it is building rather than removing from
    /// one.
    ///
    /// Resolution starts from what the root already has, so an atom the stage3
    /// already satisfies costs nothing and pulls nothing.
    pub fn install<I, S>(mut self, atoms: I) -> GentooBuilder
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.install.extend(atoms.into_iter().map(Into::into));
        self
    }

    /// Prefer builds carrying these USE flags, and builds without the ones
    /// written `-flag`.
    ///
    /// A preference, never a constraint. The archive publishes a version more
    /// than once — up to twenty-four times — and the builds differ in the flags
    /// they were compiled with; this reorders those candidates and removes
    /// none, so it provably cannot turn a resolvable request into an
    /// unresolvable one. Measured over four hundred package names, the count of
    /// unsatisfiable atoms is the same under every preference as under none.
    ///
    /// What a broad preference does cost is a larger closure, and a larger
    /// closure meets more of the archive's own conflicts: preferring `X`,
    /// `gtk`, `qt6` and `systemd` together doubles them. A narrow one costs
    /// nothing measurable.
    ///
    /// State a flag an install must have in the atom instead, where
    /// [`install`](Self::install) explains why.
    pub fn prefer_use<I, S>(mut self, flags: I) -> GentooBuilder
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.prefer_use.extend(flags.into_iter().map(Into::into));
        self
    }

    /// Stage the install as an increment over the Gentoo root at `base`,
    /// rather than into a root being bootstrapped.
    ///
    /// The base is never written to. [`Gentoo::stage_layer`] installs into an
    /// overlay upper over it, and a cage rooted on the merged view sees the
    /// base's own files and the increment's together.
    ///
    /// Resolution then describes that merged view rather than the upper alone,
    /// which is not a detail: an increment resolving against an empty upper
    /// would ask the archive for everything the base already has, and would
    /// fail on the packages the binhost does not publish at all.
    ///
    /// This is the only way to add packages to a root a caller already has,
    /// since [`provision::ensure`](super::ensure) reports a directory that
    /// exists as `Existing` and does not touch it.
    pub fn base_layer(mut self, base: impl AsRef<Path>) -> GentooBuilder {
        self.base_layer = Some(base.as_ref().to_path_buf());
        self
    }

    /// Install exactly what this plan names, resolving nothing.
    ///
    /// A [`Plan`] carries the build id, path, size and digest of every package
    /// and the order they merge in, so a run given one fetches no index and
    /// makes no choice. That is the reproducibility story for a root built from
    /// binaries: the binhost keeps a published version far longer than the five
    /// weeks the stage3 autobuilds tree keeps a build, so a plan replays for as
    /// long as the archive carries what it names.
    ///
    /// It supersedes [`install`](Self::install) and
    /// [`prefer_use`](Self::prefer_use), which describe a resolution that no
    /// longer happens.
    pub fn plan(mut self, plan: Plan) -> GentooBuilder {
        self.plan = Some(plan);
        self
    }

    /// Resolves within a named build directory instead of the one the pointer
    /// currently names — `20260810T204554Z`.
    ///
    /// What a caller records to provision the same root again later. It skips
    /// the enumeration entirely, so the digest document beside that build is
    /// what vouches for the tarball.
    ///
    /// The archive keeps about five weeks of builds and publishes no snapshot
    /// service, so a pin is reproducible against the archive for roughly a month
    /// and against a populated cache indefinitely. Past that the build id
    /// answers 404, which is a fact about Gentoo rather than about this layer.
    pub fn build_id(mut self, build_id: impl Into<String>) -> GentooBuilder {
        self.build_id = Some(build_id.into());
        self
    }

    /// Provisions a resolution already in hand, performing none.
    ///
    /// A [`Stage3`] carries everything a provision needs, digest included, so a
    /// caller who has resolved once can provision several roots from that one
    /// answer without fetching the pointer again.
    pub fn stage3(mut self, stage3: Stage3) -> GentooBuilder {
        self.stage3 = Some(stage3);
        self
    }

    /// How old the pointer document may be before it is refused, or `None` to
    /// accept one of any age.
    ///
    /// Defaults to thirty days, about four of the weekly regeneration cycles.
    /// Gentoo publishes no `Valid-Until` and no signature expiration, so the
    /// timestamp inside the signed pointer is the only thing that says when the
    /// document stopped being current; without a bound on it, a mirror can
    /// replay a correctly signed but months-old pointer forever and pass every
    /// other check the crate makes.
    ///
    /// Clearing the bound gives that up, and is the right answer for a
    /// deliberately archived mirror where a stale pointer is the point. It also
    /// accepts a pointer that states no timestamp at all, which is otherwise
    /// refused: reading its absence as permission would let whoever serves the
    /// document disable the check by deleting a line.
    pub fn max_pointer_age(mut self, age: impl Into<Option<Duration>>) -> GentooBuilder {
        self.max_pointer_age = age.into();
        self
    }

    /// The archive to read, replacing the default `distfiles.gentoo.org`.
    ///
    /// The URL names the root the `releases/` tree sits under. Repeating this
    /// takes the last value; the backstops are
    /// [`mirror_fallback`](Self::mirror_fallback)'s and are unaffected.
    pub fn mirror(mut self, url: impl Into<String>) -> GentooBuilder {
        self.mirror = Some(url.into());
        self
    }

    /// Adds a backstop mirror, tried after the primary and after the backstops
    /// already added.
    ///
    /// The list is walked in order, advancing past a mirror that could not serve
    /// a document. A mirror that serves one that does not verify is fatal rather
    /// than a reason to try the next: what it served was answered for by the URL
    /// that was asked for, and the answer to a refused signature is never to ask
    /// somewhere else.
    pub fn mirror_fallback(mut self, url: impl Into<String>) -> GentooBuilder {
        self.fallbacks.push(url.into());
        self
    }

    /// Where the downloaded tarball is kept across runs.
    ///
    /// A directory the caller owns and that survives the run. Without one the
    /// tarball is downloaded beside the tree being built and removed with it,
    /// which costs a re-download on the next provision of the same build.
    pub fn cache_dir(mut self, dir: impl AsRef<std::path::Path>) -> GentooBuilder {
        self.cache_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// The transport every fetch goes through, replacing the bundled HTTP
    /// client.
    ///
    /// The archive serves plain HTTP with no redirect to HTTPS, so the bundled
    /// client suffices; a caller wanting TLS, a proxy, or a private mirror
    /// protocol supplies their own.
    pub fn fetcher(mut self, fetcher: Box<dyn Fetch>) -> GentooBuilder {
        self.fetcher = Some(fetcher);
        self
    }

    /// Builds the provisioner.
    ///
    /// # Errors
    ///
    /// Returns [`GentooError::Config`] for an architecture or a build id a
    /// request line or a path cannot carry, and [`GentooError::Signature`] if
    /// the keyring the crate vendors does not parse — which is a defect in this
    /// crate rather than anything a caller did.
    pub fn build(self) -> Result<Gentoo, GentooError> {
        // Both become directory segments in every URL the layer fetches, so
        // both are checked before they can reach one. The build id is the one
        // worth naming: a pin skips the signed enumeration, so it is a caller's
        // string with nothing between it and a request line.
        coordinate::check(
            "the archive's architecture",
            &self.architecture,
            Nesting::Single,
        )
        .map_err(GentooError::config)?;
        if let Some(build_id) = &self.build_id {
            coordinate::check("the archive's build id", build_id, Nesting::Single)
                .map_err(GentooError::config)?;
        }
        if let Some(binhost) = &self.binhost {
            coordinate::check("the archive's binhost", binhost, Nesting::Single)
                .map_err(GentooError::config)?;
        }
        // The install list and the preferences are parsed here rather than
        // where they were set, so a misspelled atom is refused before anything
        // is fetched and the refusal names the whole configuration rather than
        // one call. It is also what makes an atom's USE dependency a real
        // constraint: it is part of the grammar the resolver matches with, so
        // parsing it is the only thing that has to happen for it to apply.
        let install = self
            .install
            .iter()
            .map(|text| atom::parse(text))
            .collect::<Result<Vec<_>, String>>()
            .map_err(GentooError::config)?;
        if let Some(blocked) = install.iter().find(|atom| atom.blocker().is_some()) {
            return Err(GentooError::config(format!(
                "the install list holds the blocker {blocked}; a blocker says what must not be \
                 installed alongside a package rather than what to install, and this layer \
                 installs into a root it is building rather than removing from one",
            )));
        }
        let prefer_use = self
            .prefer_use
            .iter()
            .map(|text| resolve::Preference::parse(text))
            .collect::<Result<Vec<_>, String>>()
            .map_err(GentooError::config)?;
        if let Some(plan) = &self.plan {
            if let Some(reason) = plan.unusable() {
                return Err(GentooError::config(reason));
            }
            // A plan names the architecture and the binhost it was resolved
            // for, and the install wave composes a URL from the builder's
            // architecture and the plan's binhost. Left unchecked, a plan
            // resolved for one architecture and replayed through a builder for
            // another fetches `releases/<builder>/binpackages/23.0/<plan>/...`
            // and 404s against a mirror that was spelled correctly -- and where
            // the two happen to publish a tree of the same name, it does not
            // fail at all. Refusing the pair here is the diagnostic that names
            // what is actually wrong.
            if plan.architecture != self.architecture {
                return Err(GentooError::config(format!(
                    "the plan was resolved for the architecture {:?} and this builder provisions \
                     {:?}; build the plan's own architecture, or resolve a plan for this one",
                    plan.architecture, self.architecture,
                )));
            }
            if let Some(binhost) = &self.binhost
                && *binhost != plan.binhost
            {
                return Err(GentooError::config(format!(
                    "the plan names the binhost {:?} and this builder names {:?}; a plan installs \
                     the containers it resolved, so the two cannot differ",
                    plan.binhost, binhost,
                )));
            }
        }
        let keyring = Keyring::parse(EMBEDDED_KEYRING)
            .map_err(|err| GentooError::signature("the vendored Gentoo keyring", err))?;
        // The walk list is the primary followed by its backstops, composed
        // here so that neither method can undo the other.
        let mut mirrors = Vec::with_capacity(1 + self.fallbacks.len());
        mirrors.push(self.mirror.unwrap_or_else(|| DEFAULT_MIRROR.to_string()));
        mirrors.extend(self.fallbacks);
        Ok(Gentoo {
            architecture: self.architecture,
            variant: self.variant,
            binhost: self.binhost,
            install,
            prefer_use,
            plan: self.plan,
            base_layer: self.base_layer,
            build_id: self.build_id,
            stage3: self.stage3,
            max_pointer_age: self.max_pointer_age,
            mirrors,
            cache_dir: self.cache_dir,
            keyring,
            fetcher: self
                .fetcher
                .unwrap_or_else(|| Box::new(HttpFetch::new()) as Box<dyn Fetch>),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;

    use pgp::composed::SignedSecretKey;
    use pgp::types::KeyDetails as _;

    use super::*;
    use crate::provision::openpgp::fixture;
    use crate::scratch::Scratch;

    /// The architecture every test below reads.
    const ARCH: &str = "amd64";

    /// The build the fixture pointer names.
    const BUILD: &str = "20260810T204554Z";

    /// A transport serving a fixed set of URLs and nothing else.
    ///
    /// Each layer keeps its own rather than sharing one from the test kit: that
    /// crate is a dev-dependency whose features forward to this one's, so
    /// reaching for it from a unit test would unify those features into every
    /// `cargo test` of the library and take the meaning out of the featureless
    /// and powerset checks.
    struct Canned {
        served: HashMap<String, Vec<u8>>,
        /// The most bytes one write to the sink carries.
        ///
        /// A real transport delivers a body in read-sized pieces, and the
        /// download consults the run's cancellation on each of them, so a
        /// fixture that wrote every body in a single call could not exercise a
        /// stop part way through one.
        chunk: usize,
    }

    impl Canned {
        /// A transport serving `served`, in pieces no real body would exceed.
        fn new(served: HashMap<String, Vec<u8>>) -> Canned {
            Canned {
                served,
                chunk: 64 * 1024,
            }
        }
    }

    impl Fetch for Canned {
        fn fetch(
            &mut self,
            request: &FetchRequest<'_>,
            sink: &mut dyn Write,
        ) -> Result<(), FetchError> {
            match self.served.get(request.url()) {
                Some(body) => body
                    .chunks(self.chunk)
                    .try_for_each(|chunk| sink.write_all(chunk))
                    .map_err(FetchError::at("writing the body", request.url())),
                None => Err(FetchError::not_found(request.url())),
            }
        }
    }

    /// A transport that refuses everything the way an unreachable mirror does.
    struct Unreachable;

    impl Fetch for Unreachable {
        fn fetch(
            &mut self,
            request: &FetchRequest<'_>,
            _sink: &mut dyn Write,
        ) -> Result<(), FetchError> {
            Err(FetchError::status(request.url(), 503))
        }
    }

    /// A one-file tar archive, as the layer will extract it.
    fn tarball_bytes() -> Vec<u8> {
        use crate::provision::tar;
        let body = b"a provisioned root\n";
        let mut out = Vec::new();
        for (name, mode, size, typeflag) in [
            ("etc/", 0o755, 0u64, b'5'),
            ("etc/marker", 0o644, body.len() as u64, b'0'),
        ] {
            out.extend_from_slice(
                &tar::ustar_block(name.as_bytes(), b"", mode, 0, 0, size, 0, typeflag, b"")
                    .expect("a ustar header"),
            );
            if size > 0 {
                out.extend_from_slice(body);
                tar::pad(&mut out, size).expect("padding a member");
            }
        }
        // Two zero blocks end the archive.
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    /// The digest the fixture digest document records for the tarball.
    fn tarball_sha512() -> String {
        Algorithm::Sha512.hex_of(&tarball_bytes())
    }

    /// A pointer body naming two variants of one build, stamped `published`.
    fn pointer_body(published: Option<i64>) -> String {
        let stamp = match published {
            Some(epoch) => format!("# ts={epoch}\n"),
            None => String::new(),
        };
        format!(
            "# Latest as of some time\n{stamp}\
             {BUILD}/stage3-amd64-openrc-{BUILD}.tar.xz 495865168\n\
             {BUILD}/stage3-amd64-openrc-splitusr-{BUILD}.tar.xz 494479304\n",
        )
    }

    /// A digest document for a variant's tarball, recording the sidecar's
    /// SHA-512 first so a reader keying on the algorithm alone takes the wrong
    /// one.
    fn digests_body(variant: &str) -> String {
        format!(
            "# SHA512 HASH\n{sidecar}  stage3-{variant}-{BUILD}.tar.xz.CONTENTS.gz\n\
             # SHA512 HASH\n{tarball}  stage3-{variant}-{BUILD}.tar.xz\n\
             # BLAKE2B HASH\n{blake}  stage3-{variant}-{BUILD}.tar.xz\n",
            sidecar = "b".repeat(128),
            tarball = tarball_sha512(),
            blake = "c".repeat(128),
        )
    }

    /// The archive as the fixtures publish it, signed by `key`.
    fn archive(key: &SignedSecretKey, published: Option<i64>) -> Canned {
        let at = |suffix: &str| format!("{DEFAULT_MIRROR}/releases/{ARCH}/autobuilds/{suffix}");
        let mut served = HashMap::from([(
            at("latest-stage3.txt"),
            fixture::clearsign(key, &pointer_body(published)).into_bytes(),
        )]);
        for variant in ["amd64-openrc", "amd64-openrc-splitusr"] {
            served.insert(
                at(&format!("{BUILD}/stage3-{variant}-{BUILD}.tar.xz.DIGESTS")),
                fixture::clearsign(key, &digests_body(variant)).into_bytes(),
            );
            served.insert(
                at(&format!("{BUILD}/stage3-{variant}-{BUILD}.tar.xz")),
                tarball_bytes(),
            );
        }
        Canned::new(served)
    }

    /// A provisioner trusting `key` alone and reading `fetcher`.
    ///
    /// Built as the value rather than through the builder, because what the
    /// tests need is a keyring holding a key generated in the test, and the
    /// public surface deliberately offers no way to replace the vendored one.
    fn provisioner(key: &SignedSecretKey, fetcher: Box<dyn Fetch>) -> Gentoo {
        Gentoo {
            architecture: ARCH.to_string(),
            variant: Some("amd64-openrc".to_string()),
            binhost: None,
            install: Vec::new(),
            prefer_use: Vec::new(),
            plan: None,
            base_layer: None,
            build_id: None,
            stage3: None,
            max_pointer_age: Some(DEFAULT_MAX_POINTER_AGE),
            mirrors: vec![DEFAULT_MIRROR.to_string()],
            cache_dir: None,
            keyring: fixture::keyring(key),
            fetcher,
        }
    }

    /// A provisioner over a freshly stamped archive signed by a fresh key.
    fn current() -> (SignedSecretKey, Gentoo) {
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let now = crate::provision::now_epoch().expect("the clock is after the epoch");
        let gentoo = provisioner(&key, Box::new(archive(&key, Some(now))));
        (key, gentoo)
    }

    /// The provisioner every test below reads the keyring through.
    fn gentoo() -> Gentoo {
        Gentoo::builder("amd64")
            .build()
            .expect("amd64 is an ordinary architecture and the keyring is vendored")
    }

    #[test]
    fn the_vendored_keyring_parses_whole() {
        // `Keyring::parse` fails the entire keyring if one certificate fails,
        // by deliberate design, so this asserts every certificate Gentoo
        // publishes is one rPGP reads. The count is the shape of the published
        // set: a refresh that changes it is a change worth seeing in a diff.
        assert_eq!(gentoo().keyring_horizon().len(), 11);
    }

    #[test]
    fn the_horizon_names_each_certificate_and_its_expiry() {
        // The releng certificate is the one this layer actually meets: it signs
        // the pointer and the digest documents, through a signing subkey. Both
        // it and that subkey run to 2028-07-01.
        let horizon = gentoo().keyring_horizon();
        let releng = horizon
            .iter()
            .find(|held| held.fingerprint == "13EBBDBEDE7A12775DFDB1BABB572E0E2D182910")
            .expect("the Automated Weekly Release Key is in the vendored keyring");
        assert_eq!(releng.expires, Some(1_846_022_400), "2028-07-01");
        assert!(releng.signs);
        assert_eq!(
            releng.user_id.as_deref(),
            Some(
                "Gentoo Linux Release Engineering (Automated Weekly Release Key) <releng@gentoo.org>"
            ),
        );

        // Every certificate is bounded: Gentoo publishes no perpetual key, and
        // one appearing would be worth noticing rather than passing over.
        assert!(
            horizon.iter().all(|held| held.expires.is_some()),
            "every Gentoo certificate carries an expiry",
        );
    }

    #[test]
    fn a_certificate_that_can_vouch_for_nothing_says_so() {
        // The 2004 release signing key is DSA-1024, which the public-key floor
        // refuses, and it delegates to no signing subkey. Its expiry reads like
        // every other certificate's, so without this flag it is
        // indistinguishable from a working anchor.
        let horizon = gentoo().keyring_horizon();
        let unusable: Vec<&str> = horizon
            .iter()
            .filter(|held| !held.signs)
            .map(|held| held.fingerprint.as_str())
            .collect();
        assert_eq!(unusable, ["D99EAC7379A850BCE47DA5F29E6438C817072058"]);
    }

    #[test]
    fn the_certificates_do_not_share_one_expiry() {
        // The finding the per-certificate report exists for. Two certificates
        // lapse about twenty months before the rest and neither signs anything
        // this layer reads, so a single earliest-expiry number would report a
        // keyring as nearly stale while the key that matters is good for years.
        let horizon = gentoo().keyring_horizon();
        let mut dates: Vec<Option<i64>> = horizon.iter().map(|held| held.expires).collect();
        dates.sort_unstable();
        dates.dedup();
        assert_eq!(
            dates,
            [
                Some(1_795_718_963), // 2026-11-26, Gentoo Infra (finch)
                Some(1_795_719_147), // 2026-11-26, Gentoo Infra (petrel)
                Some(1_814_427_500), // 2027-07-01, GLSAMaker
                Some(1_846_022_400), // 2028-07-01, the remaining eight
            ],
        );
    }

    #[test]
    fn a_user_id_comes_from_a_certification_the_key_actually_made() {
        // A certificate reports one user id, always the same one, and it is one
        // the certificate itself certified -- an unverified packet must not be
        // able to relabel a key in a report a caller reads. Gentoo's ebuild
        // repository key carries two user ids, flags neither primary, and last
        // certified both in the same second, so it is the case where a rule that
        // did not decide the tie would report differently between runs.
        let ebuild = |horizon: Vec<CertificateHorizon>| {
            horizon
                .into_iter()
                .find(|held| held.fingerprint == "DCD05B71EAB94199527F44ACDB6B8C1F96D8BF6D")
                .expect("the ebuild repository signing key is in the vendored keyring")
                .user_id
        };
        let reported = ebuild(gentoo().keyring_horizon());
        assert!(
            [
                "Gentoo ebuild repository signing key (Automated Signing Key) \
                 <infrastructure@gentoo.org>",
                "Gentoo Portage Snapshot Signing Key (Automated Signing Key)",
            ]
            .contains(&reported.as_deref().expect("a UTF-8 user id")),
            "an unexpected user id: {reported:?}",
        );
        assert_eq!(reported, ebuild(gentoo().keyring_horizon()));
    }

    #[test]
    fn an_architecture_a_url_cannot_carry_is_refused_before_anything_is_fetched() {
        // The architecture becomes a directory in every URL the layer fetches,
        // so a traversal in it is refused at the boundary rather than resolved
        // against the archive root.
        for architecture in ["../etc", "/etc", "amd64/x32", "", "amd 64"] {
            let err = Gentoo::builder(architecture)
                .build()
                .expect_err("the architecture is refused");
            assert!(
                matches!(err, GentooError::Config { .. }),
                "{architecture:?}: {err}",
            );
        }
        Gentoo::builder("arm64")
            .build()
            .expect("an ordinary architecture is accepted");
    }

    #[test]
    fn a_resolution_reads_the_digest_the_document_records_for_the_tarball() {
        // The whole read half, end to end over signed documents: the pointer
        // names the build, the digest document beside it names the SHA-512, and
        // the certificate that vouched for the second is reported so a caller
        // knows what the chain rests on.
        let (key, mut gentoo) = current();
        let stage3 = gentoo.resolve().expect("the archive resolves");
        assert_eq!(stage3.variant(), "amd64-openrc");
        assert_eq!(stage3.build_id(), BUILD);
        assert_eq!(
            stage3.path(),
            format!("{BUILD}/stage3-amd64-openrc-{BUILD}.tar.xz"),
        );
        // The size comes from the enumeration, so it is the exact length the
        // archive published rather than a ceiling.
        assert_eq!(stage3.size(), 495_865_168);
        // The sidecar's digest sits first in the document, so a reader keying
        // on the algorithm alone would have taken it.
        assert_eq!(stage3.sha512(), tarball_sha512());
        assert_eq!(
            stage3.certificate(),
            format!("{:X}", key.to_public_key().fingerprint()),
            "the certificate that vouched for the digests",
        );
    }

    #[test]
    fn the_enumeration_is_what_the_architecture_publishes() {
        let (_key, mut gentoo) = current();
        let available = gentoo.available().expect("the pointer verifies");
        assert_eq!(
            available.variants().collect::<Vec<_>>(),
            ["amd64-openrc", "amd64-openrc-splitusr"],
        );
        assert!(available.contains("amd64-openrc-splitusr"));
        assert!(!available.contains("amd64"), "no prefix match");
        assert_eq!(available.build_id("amd64-openrc"), Some(BUILD));
        assert_eq!(available.size("amd64-openrc"), Some(495_865_168));
        assert!(available.published().is_some());
    }

    #[test]
    fn a_variant_the_architecture_does_not_publish_is_refused_with_the_ones_it_does() {
        // Refused against the signed list before anything is fetched, rather
        // than as a 404 on a URL composed from a name Gentoo never published.
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let now = crate::provision::now_epoch().expect("the clock is after the epoch");
        let mut gentoo = provisioner(&key, Box::new(archive(&key, Some(now))));
        gentoo.variant = Some("amd64-hardened-openrc".to_string());
        let err = gentoo.resolve().expect_err("the variant is not published");
        let message = err.to_string();
        assert!(matches!(err, GentooError::Config { .. }), "{message}");
        assert!(message.contains("amd64-hardened-openrc"), "{message}");
        assert!(message.contains("amd64-openrc-splitusr"), "{message}");
    }

    #[test]
    fn a_pointer_older_than_the_bound_is_refused() {
        // The rollback the bound exists to close: the document is correctly
        // signed by a key the keyring holds, the digests match, and every other
        // check passes. Only its own regeneration timestamp says it stopped
        // being current.
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let now = crate::provision::now_epoch().expect("the clock is after the epoch");
        let ancient = now - 400 * 24 * 60 * 60;
        let mut gentoo = provisioner(&key, Box::new(archive(&key, Some(ancient))));
        let err = gentoo.resolve().expect_err("the pointer is stale");
        assert!(
            matches!(err, GentooError::Stale { published: Some(at), .. } if at == ancient),
            "{err}",
        );

        // Clearing the bound is what a deliberately archived mirror needs, and
        // it is the only thing that accepts the same document.
        let mut archived = provisioner(&key, Box::new(archive(&key, Some(ancient))));
        archived.max_pointer_age = None;
        archived.resolve().expect("an archived mirror is accepted");
    }

    #[test]
    fn a_pointer_stating_no_timestamp_is_refused_rather_than_waved_through() {
        // Absence is not permission: the timestamp is the only bound the layer
        // has, so reading a missing line as "no limit" would let whoever serves
        // the document disable the check by deleting it.
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let mut gentoo = provisioner(&key, Box::new(archive(&key, None)));
        let err = gentoo.resolve().expect_err("an undated pointer is refused");
        assert!(
            matches!(
                err,
                GentooError::Stale {
                    published: None,
                    age: None,
                    ..
                },
            ),
            "{err}",
        );

        // A caller who has cleared the bound has said they do not care, and an
        // undated document is then no worse than an old one.
        let mut archived = provisioner(&key, Box::new(archive(&key, None)));
        archived.max_pointer_age = None;
        archived.resolve().expect("the bound is cleared");
    }

    #[test]
    fn a_document_signed_by_a_key_outside_the_keyring_is_refused() {
        // The keyring is the whole trust anchor, so a perfectly formed archive
        // signed by anyone else verifies nothing -- and the refusal is a
        // signature failure rather than a document one, since the bytes never
        // became a document at all.
        let trusted = fixture::signing_key("releng <releng@test.invalid>");
        let forger = fixture::signing_key("forger <forger@test.invalid>");
        let now = crate::provision::now_epoch().expect("the clock is after the epoch");
        let mut gentoo = provisioner(&trusted, Box::new(archive(&forger, Some(now))));
        let err = gentoo
            .resolve()
            .expect_err("a foreign signature verifies nothing");
        assert!(matches!(err, GentooError::Signature { .. }), "{err}");
    }

    #[test]
    fn an_unsigned_pointer_is_refused() {
        // Gentoo publishes no unsigned path and this layer offers none: a body
        // with no cleartext signature is not a document, however plausible its
        // contents.
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let now = crate::provision::now_epoch().expect("the clock is after the epoch");
        let at = |suffix: &str| format!("{DEFAULT_MIRROR}/releases/{ARCH}/autobuilds/{suffix}");
        let bare = Canned::new(HashMap::from([(
            at("latest-stage3.txt"),
            pointer_body(Some(now)).into_bytes(),
        )]));
        let mut gentoo = provisioner(&key, Box::new(bare));
        let err = gentoo
            .resolve()
            .expect_err("an unsigned pointer is refused");
        assert!(matches!(err, GentooError::Signature { .. }), "{err}");
    }

    #[test]
    fn a_pinned_build_id_skips_the_enumeration_and_is_checked_on_its_way_to_a_url() {
        // A pin is the caller saying which build they want, so the pointer --
        // which only ever names the current one -- is not consulted. That makes
        // the build id a caller's string with nothing between it and a request
        // line, which is why it passes the coordinate check.
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let mut pinned = provisioner(&key, Box::new(archive(&key, Some(0))));
        pinned.build_id = Some(BUILD.to_string());
        let stage3 = pinned
            .resolve()
            .expect("a pin resolves without reading the pointer");
        assert_eq!(stage3.build_id(), BUILD);
        assert_eq!(stage3.sha512(), tarball_sha512());
        // Nothing declared a size, so the fetch falls back to the fixed ceiling.
        assert_eq!(stage3.size(), MAX_STAGE3_BYTES);

        for hostile in ["../../etc", "/etc", "a/b", "", "a b"] {
            let err = Gentoo::builder(ARCH)
                .build_id(hostile)
                .build()
                .expect_err("the build id is refused");
            assert!(matches!(err, GentooError::Config { .. }), "{hostile:?}");
        }
    }

    #[test]
    fn a_resolution_already_in_hand_is_not_performed_again() {
        // What lets a caller provision several roots from one answer. The
        // transport refuses everything, so a resolve that reached it would fail.
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let (_, mut resolved) = current();
        let stage3 = resolved.resolve().expect("the archive resolves");
        let mut carried = provisioner(&key, Box::new(Unreachable));
        carried.stage3 = Some(stage3.clone());
        assert_eq!(carried.resolve().expect("the answer is carried"), stage3);
    }

    #[test]
    fn a_mirror_that_cannot_serve_is_walked_past_and_one_that_serves_a_forgery_is_not() {
        // The distinction the shared failover predicate draws. An unreachable
        // mirror is a reason to ask the next; one that answered with something
        // that does not verify is not, since what it served was answered for by
        // the URL that was asked for.
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let now = crate::provision::now_epoch().expect("the clock is after the epoch");
        let mut walked = provisioner(&key, Box::new(archive(&key, Some(now))));
        walked.mirrors = vec![
            "http://unreachable.invalid".to_string(),
            DEFAULT_MIRROR.to_string(),
        ];
        walked
            .resolve()
            .expect("the walk advances past a mirror that served nothing");

        // Every mirror unreachable reports the transport failure rather than a
        // signature one, so a caller can tell an outage from an attack.
        let mut lost = provisioner(&key, Box::new(Unreachable));
        assert!(matches!(
            lost.resolve().expect_err("no mirror answered"),
            GentooError::Fetch(_),
        ));
    }

    #[test]
    fn the_primary_leads_the_walk_whichever_order_the_two_methods_are_called_in() {
        // The two are separate settings composed at build time, as they are on
        // the other two builders, so a caller who names a backstop before the
        // mirror it backs still has both.
        let walked = |gentoo: Gentoo| gentoo.mirrors;
        let built = |builder: GentooBuilder| walked(builder.build().expect("the builder is sound"));

        assert_eq!(
            built(
                Gentoo::builder(ARCH)
                    .mirror_fallback("http://b.invalid")
                    .mirror("http://a.invalid"),
            ),
            ["http://a.invalid", "http://b.invalid"],
        );
        assert_eq!(
            built(
                Gentoo::builder(ARCH)
                    .mirror("http://a.invalid")
                    .mirror_fallback("http://b.invalid"),
            ),
            ["http://a.invalid", "http://b.invalid"],
        );

        // A backstop alone backs the default mirror rather than replacing it,
        // and repeating the primary takes the last value.
        assert_eq!(
            built(Gentoo::builder(ARCH).mirror_fallback("http://b.invalid")),
            [DEFAULT_MIRROR, "http://b.invalid"],
        );
        assert_eq!(
            built(
                Gentoo::builder(ARCH)
                    .mirror("http://a.invalid")
                    .mirror("http://c.invalid"),
            ),
            ["http://c.invalid"],
        );
        assert_eq!(built(Gentoo::builder(ARCH)), [DEFAULT_MIRROR]);
    }

    #[test]
    fn a_resolution_without_a_variant_says_what_to_name() {
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let now = crate::provision::now_epoch().expect("the clock is after the epoch");
        let mut gentoo = provisioner(&key, Box::new(archive(&key, Some(now))));
        gentoo.variant = None;
        let err = gentoo.resolve().expect_err("no variant was named");
        assert!(err.to_string().contains("Gentoo::available"), "{err}");
    }

    /// The binhost sub-architecture every index test below reads.
    const BINHOST: &str = "x86-64";

    /// A two-record index document, enough to be a package set.
    fn index_body() -> String {
        format!(
            "TIMESTAMP: 1787145736\nCHOST: x86_64-pc-linux-gnu\nPACKAGES: 1\n\n\
             BUILD_ID: 1\nCPV: sys-libs/zlib-1.3.1-r1\n\
             MD5: 3a61f698748c7323c87081584f383b3c\n\
             PATH: sys-libs/zlib/zlib-1.3.1-r1-1.gpkg.tar\nSIZE: 204800\n\
             SLOT: 0/1\nUSE: amd64 minizip\nREPO: gentoo\n\n\
             BUILD_ID: 1\nCPV: dev-vcs/git-2.54.0\n\
             MD5: 6a539af72c5577fdce267834d3dfd2f1\n\
             PATH: dev-vcs/git/git-2.54.0-1.gpkg.tar\nSIZE: 8192000\n\
             RDEPEND: >={arch}/zlib-1.3\nUSE: amd64 curl\nREPO: gentoo\n",
            arch = "sys-libs",
        )
    }

    /// `body` as a gzip member, which is how the archive publishes the index.
    fn gzipped(body: &str) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(body.as_bytes()).expect("gzip accepts it");
        encoder.finish().expect("the member closes")
    }

    /// The mirror-relative URL of `name` in the binhost this test reads.
    fn binhost_url(name: &str) -> String {
        format!(
            "{DEFAULT_MIRROR}/{}/{name}",
            index::directory(ARCH, BINHOST),
        )
    }

    /// A provisioner reading a binhost served by `fetcher`.
    fn binhost_provisioner(fetcher: Box<dyn Fetch>) -> Gentoo {
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let mut gentoo = provisioner(&key, fetcher);
        gentoo.binhost = Some(BINHOST.to_string());
        gentoo
    }

    #[test]
    fn the_index_is_read_from_the_compressed_copy_where_one_is_served() {
        // A tenth of the bytes for identical content, and the decoder is
        // selected by magic rather than by the name -- so the plain copy being
        // present too changes nothing about which is read.
        let served = HashMap::from([
            (binhost_url("Packages.gz"), gzipped(&index_body())),
            (binhost_url("Packages"), index_body().into_bytes()),
        ]);
        let mut gentoo = binhost_provisioner(Box::new(Canned::new(served)));
        let catalogue = gentoo.packages().expect("the index is served");
        assert_eq!(catalogue.len(), 2);
        assert_eq!(catalogue.builds(), 2);
        assert!(catalogue.contains("dev-vcs/git"));
        assert_eq!(
            catalogue.versions("sys-libs/zlib").collect::<Vec<_>>(),
            ["1.3.1-r1"],
        );
        assert_eq!(catalogue.generated(), Some(1_787_145_736));
        assert_eq!(catalogue.chost(), Some("x86_64-pc-linux-gnu"));
    }

    #[test]
    fn a_mirror_serving_only_the_plain_copy_is_read_from_it() {
        let served = HashMap::from([(binhost_url("Packages"), index_body().into_bytes())]);
        let mut gentoo = binhost_provisioner(Box::new(Canned::new(served)));
        assert_eq!(gentoo.packages().expect("the plain copy answers").len(), 2);
    }

    #[test]
    fn an_index_cut_short_is_refused_against_its_own_count() {
        // A truncated plain-text index parses perfectly and resolves against a
        // silently smaller archive, and its own PACKAGES field is the only
        // thing that would notice. Not a security property -- a mirror
        // composing the stanzas composes the count too -- but the shape a
        // half-written mirror actually has.
        let body = index_body();
        let short = body
            .split_once("BUILD_ID: 1\nCPV: dev-vcs/git")
            .expect("the fixture holds two records")
            .0
            .replace("PACKAGES: 1", "PACKAGES: 2");
        let served = HashMap::from([(binhost_url("Packages.gz"), gzipped(&short))]);
        let mut gentoo = binhost_provisioner(Box::new(Canned::new(served)));
        let err = gentoo.packages().expect_err("a short index is refused");
        assert!(matches!(err, GentooError::Index { .. }), "{err:?}");
        assert!(err.to_string().contains("holds 2 packages"), "{err}");

        // An index that holds more than it declares is not short, so it is not
        // this check's business. The fixture is one: its preamble says one
        // package and it carries two, which is the shape the live archive has
        // whenever a record is added between the count being written and the
        // stanzas being emitted.
        let served = HashMap::from([(binhost_url("Packages.gz"), gzipped(&body))]);
        let mut gentoo = binhost_provisioner(Box::new(Canned::new(served)));
        assert_eq!(gentoo.packages().expect("a long index reads").len(), 2);
    }

    #[test]
    fn an_index_naming_nothing_this_layer_can_act_on_is_refused() {
        // A preamble and nothing else is a document that arrived and is not an
        // index. It is refused as one rather than reported as an empty archive,
        // which a caller would read as "this binhost publishes nothing".
        let served = HashMap::from([(
            binhost_url("Packages.gz"),
            gzipped("TIMESTAMP: 1787145736\n"),
        )]);
        let mut gentoo = binhost_provisioner(Box::new(Canned::new(served)));
        let err = gentoo.packages().expect_err("an empty index is refused");
        assert!(matches!(err, GentooError::Index { .. }), "{err:?}");
        // The refusal names the mirror that answered, which is the whole point
        // of carrying the URL through the walk.
        assert!(err.to_string().contains(DEFAULT_MIRROR), "{err}");
    }

    #[test]
    fn a_binhost_that_was_never_named_is_a_configuration_failure() {
        // Not a fetch failure: there is no URL to have failed. The refusal says
        // what to call and gives a sub-architecture to call it with, since
        // nothing signed enumerates them.
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let mut gentoo = provisioner(&key, Box::new(Canned::new(HashMap::new())));
        let err = gentoo.packages().expect_err("no binhost was named");
        assert!(matches!(err, GentooError::Config { .. }), "{err:?}");
        assert!(err.to_string().contains("binhost"), "{err}");
    }

    #[test]
    fn a_plan_resolved_for_other_coordinates_is_refused_before_anything_is_fetched() {
        // The install wave composes the *builder's* architecture with the
        // *plan's* binhost, so a mismatch that reached the wave would fetch
        // `releases/<builder>/binpackages/23.0/<plan>/...` and 404 against a
        // mirror that was spelled correctly -- and where the two publish a tree
        // of the same name it would not fail at all. The refusal says which
        // pair disagrees, which is what a 404 cannot.
        let plan = Plan::parse_document(
            "Format: ferroday-cage-gentoo-plan 1\nArchitecture: arm64\nBinhost: arm64\n",
        )
        .expect("a fixture plan");

        let err = Gentoo::builder("amd64")
            .plan(plan.clone())
            .build()
            .expect_err("a plan for another architecture is refused");
        assert!(matches!(err, GentooError::Config { .. }), "{err:?}");
        assert!(err.to_string().contains("arm64"), "{err}");

        // The same for a binhost the builder named and the plan does not agree
        // with; a builder that names none takes the plan's, which is what it
        // resolved against.
        let err = Gentoo::builder("arm64")
            .binhost("x86-64")
            .plan(plan.clone())
            .build()
            .expect_err("a plan for another binhost is refused");
        assert!(matches!(err, GentooError::Config { .. }), "{err:?}");
        assert!(err.to_string().contains("binhost"), "{err}");

        Gentoo::builder("arm64")
            .plan(plan.clone())
            .build()
            .expect("a plan whose architecture is the builder's builds");
        Gentoo::builder("arm64")
            .binhost("arm64")
            .plan(plan)
            .build()
            .expect("a plan that agrees with the builder on both builds");
    }

    #[test]
    fn a_mirror_that_serves_no_index_at_all_reports_the_fetch_failure() {
        let mut gentoo = binhost_provisioner(Box::new(Canned::new(HashMap::new())));
        let err = gentoo.packages().expect_err("nothing is served");
        assert!(matches!(err, GentooError::Fetch(_)), "{err:?}");
    }

    #[test]
    fn a_bootstrap_publishes_the_verified_tarball_into_a_root() {
        // The whole write half, driven exactly as every other provisioner is:
        // `ensure` supplies the staging directory and publishes it atomically,
        // and this layer fills it.
        let scratch = Scratch::for_test("gentoo", "bootstrap");
        let (_key, mut gentoo) = current();
        gentoo.cache_dir = Some(scratch.join("cache"));
        let root = scratch.join("root");
        assert_eq!(
            crate::provision::ensure(&root, &mut gentoo).expect("the root is provisioned"),
            crate::provision::Provisioned::Created,
        );
        assert_eq!(
            std::fs::read_to_string(root.join("etc/marker")).expect("the archive was extracted"),
            "a provisioned root\n",
        );
        // The download stays in the caller's cache, which is what it is for.
        assert!(
            scratch
                .join("cache")
                .join(format!("stage3-amd64-openrc-{BUILD}.tar.xz"))
                .is_file(),
        );
    }

    #[test]
    fn a_bootstrap_resolves_first_when_the_caller_did_not() {
        // A caller who only wants a root never has to resolve, so `provision`
        // does it as its first step -- and reports what it chose, so a consumer
        // sees the exact build `ensure` installed without a second pass.
        let scratch = Scratch::for_test("gentoo", "bootstrap-resolves");
        let (_key, mut gentoo) = current();
        gentoo.cache_dir = Some(scratch.join("cache"));
        assert!(gentoo.stage3.is_none(), "nothing was resolved beforehand");

        let mut seen: Vec<String> = Vec::new();
        crate::provision::Provision::new(scratch.join("root"))
            .observe(&mut |event: ProvisionEvent<'_>| {
                if let ProvisionEvent::Gentoo(event) = event {
                    seen.push(match event {
                        GentooEvent::Fetching { .. } => "fetching".to_string(),
                        GentooEvent::Resolved { stage3 } => {
                            format!("resolved {}", stage3.build_id())
                        }
                        GentooEvent::Verifying { .. } => "verifying".to_string(),
                        GentooEvent::Extracting { .. } => "extracting".to_string(),
                        // The install wave's own events, which a bootstrap
                        // with no install list never reaches.
                        other => format!("unexpected {other:?}"),
                    });
                }
            })
            .run(&mut gentoo)
            .expect("the root is provisioned");
        assert_eq!(
            seen.iter()
                .filter(|step| *step != "fetching")
                .collect::<Vec<_>>(),
            [
                &format!("resolved {BUILD}"),
                &"verifying".to_string(),
                &"extracting".to_string(),
            ],
        );
        // Three fetches: the pointer, the digest document, and the tarball.
        assert_eq!(seen.iter().filter(|step| *step == "fetching").count(), 3);
    }

    #[test]
    fn a_run_cancelled_at_a_step_boundary_never_reaches_the_download() {
        // The resolution is two small documents; the download is most of a
        // gigabyte. A caller who cancelled while watching what was resolved
        // must not be committed to fetching it by having asked.
        struct StopOnResolve {
            resolved: bool,
        }

        impl crate::provision::ProvisionObserver for StopOnResolve {
            fn progress(&mut self, event: ProvisionEvent<'_>) {
                if let ProvisionEvent::Gentoo(GentooEvent::Resolved { .. }) = event {
                    self.resolved = true;
                }
            }

            fn cancelled(&mut self) -> bool {
                self.resolved
            }
        }

        let scratch = Scratch::for_test("gentoo", "cancel-boundary");
        let (_key, mut gentoo) = current();
        let cache = scratch.join("cache");
        gentoo.cache_dir = Some(cache.clone());
        let root = scratch.join("root");

        let mut stop = StopOnResolve { resolved: false };
        let err = crate::provision::Provision::new(&root)
            .observe(&mut stop)
            .run(&mut gentoo)
            .expect_err("the observer asked it to stop");
        assert!(
            matches!(err, crate::provision::ProvisionError::Cancelled),
            "{err}",
        );
        assert!(
            stop.resolved,
            "the Gentoo events reached the run's observer"
        );
        assert!(!root.exists(), "no root is published");
        assert!(
            !cache
                .join(format!("stage3-amd64-openrc-{BUILD}.tar.xz"))
                .exists(),
            "nothing was downloaded",
        );
    }

    #[test]
    fn a_run_cancelled_while_the_tarball_arrives_stops_part_way_through_it() {
        // The step this layer has and the others do not: one file with no
        // package boundary inside it, so the cancellation check has to reach
        // into the write. The observer counts how often it was asked once the
        // tarball started arriving, which is what tells a boundary-only check
        // from one the body itself consults.
        struct StopMidBody {
            fetches: usize,
            asked: usize,
        }

        impl crate::provision::ProvisionObserver for StopMidBody {
            fn progress(&mut self, event: ProvisionEvent<'_>) {
                if let ProvisionEvent::Gentoo(GentooEvent::Fetching { .. }) = event {
                    self.fetches += 1;
                }
            }

            fn cancelled(&mut self) -> bool {
                // The pointer and the digest document are fetched first, so the
                // third fetch is the tarball's.
                if self.fetches < 3 {
                    return false;
                }
                self.asked += 1;
                self.asked > 2
            }
        }

        let scratch = Scratch::for_test("gentoo", "cancel-download");
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let now = crate::provision::now_epoch().expect("the clock is after the epoch");
        let mut served = archive(&key, Some(now));
        // Small enough that the fixture tarball takes several writes, as a real
        // body takes thousands.
        served.chunk = 512;
        let mut gentoo = provisioner(&key, Box::new(served));
        let cache = scratch.join("cache");
        gentoo.cache_dir = Some(cache.clone());
        let root = scratch.join("root");

        let mut stop = StopMidBody {
            fetches: 0,
            asked: 0,
        };
        let err = crate::provision::Provision::new(&root)
            .observe(&mut stop)
            .run(&mut gentoo)
            .expect_err("the observer asked it to stop");
        assert!(
            matches!(err, crate::provision::ProvisionError::Cancelled),
            "{err}",
        );
        assert!(
            stop.asked > 2,
            "the body itself consulted the check, {} times",
            stop.asked,
        );
        assert!(!root.exists(), "no root is published");
        // Neither the staging file nor a published cache entry survives: a
        // partial body is not the archive's file, and a later run downloading
        // it again is cheaper than one extracting a truncated one.
        assert_eq!(
            std::fs::read_dir(&cache)
                .expect("the cache directory was created")
                .count(),
            0,
            "no partial download is left behind",
        );
    }

    #[test]
    fn a_tarball_that_is_not_what_the_document_vouched_for_is_never_extracted() {
        // The bytes are verified before the extractor sees them, so an archive
        // that is not the one the signed document named leaves no half-written
        // root behind -- and the cached file goes, so the next run downloads
        // afresh rather than meeting the same refusal out of its own cache.
        let scratch = Scratch::for_test("gentoo", "wrong-bytes");
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let now = crate::provision::now_epoch().expect("the clock is after the epoch");
        let mut served = archive(&key, Some(now));
        let tarball_url = format!(
            "{DEFAULT_MIRROR}/releases/{ARCH}/autobuilds/{BUILD}/stage3-amd64-openrc-{BUILD}.tar.xz",
        );
        served.served.insert(
            tarball_url,
            b"not the archive that was vouched for".to_vec(),
        );

        let mut gentoo = provisioner(&key, Box::new(served));
        let cache = scratch.join("cache");
        gentoo.cache_dir = Some(cache.clone());
        let root = scratch.join("root");
        let err =
            crate::provision::ensure(&root, &mut gentoo).expect_err("the digest does not match");
        let reported = err.to_string();
        assert!(reported.contains("does not have the digest"), "{reported}");
        assert!(!root.exists(), "no root is published");
        assert!(
            !cache
                .join(format!("stage3-amd64-openrc-{BUILD}.tar.xz"))
                .exists(),
            "the tarball that did not verify is not left in the cache",
        );
    }

    #[test]
    fn a_cached_tarball_is_verified_on_the_read_rather_than_trusted() {
        // A cache is bytes on a disk this crate does not own, so a file already
        // sitting at the cache path goes through the same check a fresh download
        // does. Here the transport would serve the real archive, and the planted
        // file is what is refused.
        let scratch = Scratch::for_test("gentoo", "cache-hit");
        let (_key, mut gentoo) = current();
        let cache = scratch.join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let planted = cache.join(format!("stage3-amd64-openrc-{BUILD}.tar.xz"));
        std::fs::write(&planted, b"planted in the cache by something else").unwrap();
        gentoo.cache_dir = Some(cache);

        let err = crate::provision::ensure(scratch.join("root"), &mut gentoo)
            .expect_err("the planted file does not verify");
        assert!(
            err.to_string().contains("does not have the digest"),
            "{err}"
        );
        assert!(!planted.exists(), "the refused entry is cleared");

        // With it cleared, the same provisioner downloads and succeeds.
        crate::provision::ensure(scratch.join("root"), &mut gentoo)
            .expect("the second run downloads the real archive");
        assert!(scratch.join("root/etc/marker").is_file());
    }
}
