//! The resolved install plan: the packages a bootstrap would install, and the
//! archive state it resolved them against, reported without downloading or
//! configuring any of them.
//!
//! A plan is also a document. [`Plan::to_document`] writes it in the archive's
//! own deb822 control format and [`Plan::parse_document`] reads it back, so a
//! plan resolved on one machine can be committed, reviewed in a diff, and
//! replayed on another against a snapshot mirror. That is the form the
//! reproduce case needs: the same-process handoff to
//! [`DebianBuilder::plan`](super::DebianBuilder::plan) covers resolving once
//! and installing once, and nothing else.

use std::borrow::Cow;
use std::collections::HashMap;

use super::DebianError;
use super::digests::RECORDED;
use super::index::Package;
use crate::provision::digest::{Algorithm, Digest};
use crate::provision::document::{self, Carried, Draft};

/// The document's first field, naming the format and its version.
///
/// A document carries its own version because the plan is a trust anchor: a
/// reader that cannot tell which shape it is holding cannot say what it is
/// trusting. The version is bumped only for a change a previous reader would
/// misread; adding a field is not one, since a reader carries a field it does
/// not know through untouched rather than refusing the document or dropping it.
///
/// A field that keeps its name and changes its meaning is the shape the
/// carried-field rule cannot absorb, and version 2 is what one of them
/// required: `Signed-By` names the verifying certificate, where version 1 named
/// the key that made the signature. A reader accepting both would hand back a
/// fingerprint without saying which of the two questions it answers.
///
/// A package's `SHA512` was added under version 2, in place of its `SHA256`
/// where the archive records no SHA-256 for it, and a package states exactly
/// one of the two. A reader that predates it, 0.5 and earlier, refuses a
/// package stating the `SHA512` as missing its `SHA256` rather than misreading
/// it, so it needed no new version. A package whose archive records a SHA-256
/// states it as before, so such a plan is written as it always was.
const FORMAT: &str = "ferroday-cage-plan 2";

/// The packages a [`Debian`](super::Debian) bootstrap resolves for its suite,
/// produced without downloading or unpacking anything.
///
/// Returned by [`Debian::resolve`](super::Debian::resolve). Every package's
/// digest is archive-verified: it is read from an index whose own digest the
/// signed release records, so a plan resolved from a signed archive is anchored
/// to the archive signature rather than to a mirror's unverified word. The
/// packages are ordered by name, so the plan is a stable value to cache a build
/// on or compare across runs.
///
/// [`archives`](Self::archives) records the state each package was resolved
/// against, which is what makes the plan a description of a moment in an
/// archive's life rather than only of a package set.
///
/// # Keeping a plan
///
/// [`to_document`](Self::to_document) and
/// [`parse_document`](Self::parse_document) are the plan's on-disk form, in the
/// archive's own deb822 control format:
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use ferroday_cage::provision::debian::Plan;
///
/// // Resolve now, and keep what was resolved.
/// # let plan: Plan = unimplemented!();
/// std::fs::write("trixie.plan", plan.to_document()?)?;
///
/// // Replay later, against a snapshot mirror.
/// let kept = Plan::parse_document(&std::fs::read_to_string("trixie.plan")?)?;
/// # let _ = kept;
/// # Ok(())
/// # }
/// ```
///
/// A document written by a later version of this library reads back here as
/// long as its format version is unchanged: a field this version does not know
/// is carried rather than refused, and written back out, which is what lets a
/// plan outlive the program that wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Plan {
    /// The suite the plan resolves against, as requested.
    pub suite: String,
    /// The architecture the packages target.
    pub architecture: String,
    /// The resolved install set, ordered by name.
    pub packages: Vec<PlannedPackage>,
    /// The archive state each package was resolved against, in the order the
    /// repositories were configured — the primary first.
    pub archives: Vec<ResolvedArchive>,
    /// Header fields a document carried that this version does not know.
    ///
    /// Private because they are not this version's data to interpret; they
    /// exist so that reading a document and writing it back loses nothing. See
    /// [`Plan::parse_document`].
    carried: Carried,
}

/// One repository's state at the moment a [`Plan`] resolved against it.
///
/// A reproducibility model that fixes the archive state needs this: the same
/// suite resolves to different versions a week apart, and a plan naming only
/// what it selected cannot say what it selected *from*.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedArchive {
    /// The mirror URL that served the release.
    ///
    /// The URL that answered, not the configured list: a repository with a
    /// snapshot backstop resolves against whichever mirror served, and
    /// recording the list would describe a choice rather than the choice made.
    ///
    /// This records where the release came from; it does not decide where the
    /// packages are fetched from. A bootstrap installing this plan walks the
    /// mirrors its repositories are configured with, so a plan carried to a
    /// different configuration fetches from that configuration's mirrors and
    /// still installs the packages this plan names, each held to the digest
    /// recorded here.
    pub mirror: String,
    /// The suite as the repository requested it.
    pub suite: String,
    /// The components resolved from this repository.
    pub components: Vec<String>,
    /// The SHA-256 of the release file the mirror served.
    ///
    /// For a signed repository that is the `InRelease` as fetched, signature
    /// included, and for one trusted unsigned the `Release`. It is the digest
    /// of a file the mirror publishes, so `sha256sum` over that file, fetched
    /// from [`mirror`](Self::mirror) while the archive still serves the state,
    /// gives it. Always a SHA-256, whichever digests the release itself records
    /// for its indexes: this one is taken of the release.
    pub release_sha256: Digest,
    /// The release's `Date` field, as written, when it carries one.
    pub date: Option<String>,
    /// The release's `Valid-Until` field, as written, when it carries one.
    pub valid_until: Option<String>,
    /// The fingerprint of the certificate that verified the release, uppercase
    /// hex.
    ///
    /// The archive key's primary-key fingerprint, which is the identity a
    /// keyring entry is named by and the one a policy pinning an archive would
    /// pin. It is stable across a certificate rotating its signing subkey,
    /// which [`signing_key`](Self::signing_key) is not.
    ///
    /// Empty for a repository configured as
    /// [`trust_unsigned`](super::RepositoryBuilder::trust_unsigned), where
    /// nothing was verified. A release may carry several signatures;
    /// verification stops at the first acceptable one in the order the release
    /// carries them, so this names the key that was actually used rather than
    /// every key that could have been.
    pub signed_by: Vec<String>,
    /// The fingerprint of the component key that made the signature, uppercase
    /// hex.
    ///
    /// Debian's archive keys sign with a dedicated signing subkey, so this is
    /// usually a subkey of the certificate [`signed_by`](Self::signed_by)
    /// names, and equal to it only when a primary signed directly. Recorded
    /// because the two answer different questions: which archive vouched for
    /// the release, and which key material actually produced the signature.
    ///
    /// Empty exactly when [`signed_by`](Self::signed_by) is.
    pub signing_key: Vec<String>,
    /// Fields this archive's stanza carried that this version does not know.
    ///
    /// Reachable within the layer so a live resolution can build the record as
    /// a struct literal, naming each field: the four `String` and `Vec<String>`
    /// fields above sit in transposable pairs, and a positional constructor
    /// over them compiles either way round and writes a wrong plan document.
    pub(super) carried: Carried,
}

/// One package in a [`Plan`]: enough to identify the exact `.deb` and to key a
/// cache on it, carrying no dependency or download state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlannedPackage {
    /// The package name.
    pub name: String,
    /// The exact version that would be installed.
    pub version: String,
    /// The package's architecture: the target architecture, or `all`.
    pub architecture: String,
    /// What the `.deb` must hash to: the SHA-256 the archive records for it,
    /// or its SHA-512 where the archive records no SHA-256, as Ubuntu's
    /// development series does.
    ///
    /// A resolution checks a download against every digest the index offers,
    /// as apt does; a plan records this one, and installing the plan checks
    /// the bytes against it and names the cache entry by it.
    pub digest: Digest,
    /// The pool path of the `.deb`, relative to the mirror root.
    pub filename: String,
    /// Which of [`Plan::archives`] this package's winning version came from,
    /// as an index into that list.
    ///
    /// Each name resolves to one version across the merged repositories,
    /// ranked by the release that offers it and then by version, so with more
    /// than one configured this is the only thing that says where a package
    /// will actually be fetched from.
    pub archive: usize,
    /// The archive's estimate of the space this package occupies once
    /// installed, in kibibytes, when the archive states one.
    ///
    /// An estimate, and reported as one: Debian Policy 5.6.20 defines
    /// `Installed-Size` as the size in bytes divided by 1024 and rounded up,
    /// produced at package build time from the staged tree. It is not measured
    /// against an installed filesystem and does not account for the target's
    /// block size, so a sum over a plan describes the archive's own accounting
    /// rather than what a built image will weigh.
    ///
    /// Kept in the archive's unit rather than normalized to bytes, so the value
    /// is the one the mirror publishes and can be compared against it directly.
    ///
    /// `None` when the stanza carried no `Installed-Size`, which Debian Policy
    /// permits, or when a plan document written before this field existed is
    /// read back.
    pub installed_size: Option<u64>,
    /// The source package this binary package was built from, when it differs
    /// from [`name`](Self::name).
    ///
    /// `None` means the source package carries the same name — the common case,
    /// and the one Debian encodes by omitting the field. A source version the
    /// stanza states in parentheses is dropped, since it describes the source
    /// package rather than this binary one.
    ///
    /// Several binary packages of one source share this name, which is what
    /// makes it the key to attribute a plan's weight to the thing that was
    /// built rather than to each of its outputs.
    ///
    /// A plan this library resolved holds the invariant: the field is `None`
    /// wherever the source name matches. A plan read back from a document holds
    /// it only as far as the document does — the reader takes the `Source`
    /// field verbatim, so a hand-written document stating a source equal to the
    /// package's own name reads as `Some(name)` and is written back unchanged.
    /// A consumer grouping by source should key on `source.unwrap_or(name)`
    /// rather than on the field alone, which is correct for both.
    pub source: Option<String>,
    /// The length of the `.deb` on the wire in bytes, when the archive states
    /// one.
    ///
    /// It bounds what the download may spend before its digest is checked.
    /// Installing a plan fetches no index to read the length from, so the plan
    /// carries it: without it, such a download is bounded by the fetcher's own
    /// ceiling instead, which is weaker rather than wrong, since the digest
    /// still decides whether the bytes are the package.
    ///
    /// `None` when the stanza carried no `Size`, or when a plan document
    /// written before this field existed is read back.
    pub size: Option<u64>,
    /// Fields this package's stanza carried that this version does not know.
    carried: Carried,
}

impl PlannedPackage {
    /// Why this entry cannot be addressed, or `None` where it can.
    ///
    /// [`name`](Self::name) is what a bootstrap reports the package by, in its
    /// progress and its errors, and [`version`](Self::version) is what a pin's
    /// refusals name, so each is held to the alphabet Debian policy gives it,
    /// neither of which holds a control character.
    /// [`filename`](Self::filename) is interpolated verbatim into the URL the
    /// `.deb` is fetched from and, for a `file://` mirror, into a local path, so
    /// one holding a `..`, a leading slash, or a byte a request line ends on
    /// would fetch from somewhere other than the mirror root. Its
    /// [`digest`](Self::digest) is held to its algorithm's shape by its type,
    /// so it has nothing to be refused for here.
    ///
    /// A package resolved from an index passed
    /// [`index::is_package_name`](super::index::is_package_name),
    /// [`version::is_version`](super::version::is_version),
    /// [`index::is_safe_pool_path`](super::index::is_safe_pool_path) and
    /// [`Algorithm::is_hex`](crate::provision::digest::Algorithm::is_hex) on the
    /// way in, so this is the same gate for the way a plan arrives instead: a
    /// document a caller kept and may have edited, or a [`Plan`] taken from
    /// [`resolve`](super::Debian::resolve) and modified, neither of which has an
    /// index behind it.
    pub(super) fn unaddressable(&self) -> Option<String> {
        if let Some(reason) = unpermitted_name(&self.name) {
            return Some(reason);
        }
        if !super::version::is_version(&self.version) {
            return Some(format!(
                "the plan states {} at {:?}, which is not a version Debian policy permits",
                self.name, self.version,
            ));
        }
        if !super::index::is_safe_pool_path(&self.filename) {
            return Some(format!(
                "the plan fetches {} from {:?}, which is not a path a mirror can be asked for",
                self.name, self.filename,
            ));
        }
        None
    }
}

/// Why a plan cannot name a package `name`, or `None` where it can.
///
/// The refusal quotes the name with `{:?}`, since nothing has admitted it. The
/// reader and [`validate_plan`](super::validate_plan) ask this before any other
/// message names the package, and those name it bare.
fn unpermitted_name(name: &str) -> Option<String> {
    (!super::index::is_package_name(name)).then(|| {
        format!("the plan names {name:?}, which is not a package name Debian policy permits")
    })
}

impl Plan {
    /// The first package this plan names twice, as its two entries, or `None`
    /// where every name appears once.
    ///
    /// A root holds one package of a name, and everything that reads a plan
    /// keys it by name: a pin holds each name to one version, and dpkg
    /// registers one package per name. So two entries for one name are a plan
    /// with no single reading, whether or not they agree. A plan this library
    /// resolved cannot contain one; a hand-written document or an edited
    /// `Plan` can.
    pub(super) fn named_twice(&self) -> Option<(&PlannedPackage, &PlannedPackage)> {
        let mut seen: HashMap<&str, &PlannedPackage> = HashMap::with_capacity(self.packages.len());
        self.packages.iter().find_map(|package| {
            seen.insert(&package.name, package)
                .map(|first| (first, package))
        })
    }

    /// Renders the plan as a deb822 document.
    ///
    /// The document is the plan and nothing else: one header stanza, one stanza
    /// per archive in [`archives`](Self::archives) order, then one per package
    /// in [`packages`](Self::packages) order. Since both lists are already
    /// ordered, two renderings of one plan are byte-identical, and a plan that
    /// changes shows the change as a diff rather than as a different blob.
    ///
    /// # Errors
    ///
    /// [`DebianError::PlanDocument`] when a field's value cannot be written as
    /// a single deb822 line — one holding a newline, or one empty where the
    /// format has no way to say "empty". Both mean the plan came from an
    /// archive that fed the resolver something the format cannot carry back,
    /// which is worth refusing rather than writing a document that reads back
    /// as something else.
    pub fn to_document(&self) -> Result<String, DebianError> {
        let mut out = String::new();
        let mut header = Draft::new();
        header.put("Format", FORMAT);
        header.put("Suite", &self.suite);
        header.put("Architecture", &self.architecture);
        header.put_carried(&self.carried);
        header
            .render(&mut out)
            .map_err(DebianError::plan_document)?;

        for (index, archive) in self.archives.iter().enumerate() {
            let mut stanza = Draft::new();
            stanza.put("Archive", &index.to_string());
            stanza.put("Mirror", &archive.mirror);
            stanza.put("Suite", &archive.suite);
            stanza.put_list("Components", &archive.components);
            stanza.put("Release-SHA256", archive.release_sha256.hex());
            stanza.put_optional("Date", archive.date.as_deref());
            stanza.put_optional("Valid-Until", archive.valid_until.as_deref());
            // Written even when empty: an unsigned repository is a fact about
            // the plan's trust, not an absence of information, and a reader
            // that saw no key at all could not tell the two apart.
            stanza.put_allowing_empty("Signed-By", &archive.signed_by.join(" "));
            stanza.put_allowing_empty("Signing-Key", &archive.signing_key.join(" "));
            stanza.put_carried(&archive.carried);
            stanza
                .render(&mut out)
                .map_err(DebianError::plan_document)?;
        }

        for package in &self.packages {
            if package.archive >= self.archives.len() {
                return Err(DebianError::plan_document(format!(
                    "the package {} names archive {}, and the plan records {}",
                    package.name,
                    package.archive,
                    self.archives.len(),
                )));
            }
            let mut stanza = Draft::new();
            stanza.put("Package", &package.name);
            stanza.put("Version", &package.version);
            stanza.put("Architecture", &package.architecture);
            // The field the package's digest is spelled under, and only it.
            let digest =
                |algorithm| (package.digest.algorithm() == algorithm).then(|| package.digest.hex());
            stanza.put_optional("SHA256", digest(Algorithm::Sha256));
            stanza.put("Filename", &package.filename);
            stanza.put("Archive", &package.archive.to_string());
            // Written after every field the format's first readers knew, which
            // is where those readers put them back. A reader carries a field it
            // does not know and re-emits it after the ones it does, so a field
            // added between the older ones would return from such a round trip
            // moved to the end — different bytes for an unchanged plan, which a
            // consumer pinning a plan's digest reads as the plan having
            // changed. Anything added later belongs below these, for the same
            // reason.
            let installed_size = package.installed_size.map(|kib| kib.to_string());
            stanza.put_optional("Installed-Size", installed_size.as_deref());
            stanza.put_optional("Source", package.source.as_deref());
            let size = package.size.map(|bytes| bytes.to_string());
            stanza.put_optional("Size", size.as_deref());
            stanza.put_optional("SHA512", digest(Algorithm::Sha512));
            stanza.put_carried(&package.carried);
            stanza
                .render(&mut out)
                .map_err(DebianError::plan_document)?;
        }
        Ok(out)
    }

    /// Reads a plan back from a document [`to_document`](Self::to_document)
    /// wrote.
    ///
    /// A field the reader does not know is carried rather than refused, so a
    /// document written by a later version of this library still reads, and
    /// writing it back keeps what it carried. A stanza order other than
    /// header, archives, packages is not: the archive index each package refers
    /// to is resolved as the document is read.
    ///
    /// # Errors
    ///
    /// [`DebianError::PlanDocument`] for a document with no header, a format
    /// version this library does not read, a stanza missing a field the plan
    /// cannot do without, a malformed archive index, a package naming an
    /// archive the document does not carry, a package named outside the
    /// alphabet Debian policy gives a package name, or a package whose pool
    /// path or digest is not one a fetch could be composed from.
    pub fn parse_document(text: &str) -> Result<Plan, DebianError> {
        let (header, rest) =
            document::header(document::parse(text), FORMAT).map_err(DebianError::plan_document)?;
        let mut plan = Plan {
            suite: required(header.get("Suite"), "Suite", "the header")?,
            architecture: required(header.get("Architecture"), "Architecture", "the header")?,
            packages: Vec::new(),
            archives: Vec::new(),
            carried: document::carried(&header, HEADER_FIELDS),
        };

        for stanza in rest {
            if let Some(name) = stanza.get("Package") {
                // Before the name is in any message: each one below names it.
                if let Some(reason) = unpermitted_name(&name) {
                    return Err(DebianError::plan_document(reason));
                }
                let at_package = format!("the package {name}");
                let at = number::<usize>(stanza.get("Archive"), "Archive", &at_package)?
                    .ok_or_else(|| {
                        DebianError::plan_document(format!("the package {name} names no archive"))
                    })?;
                if at >= plan.archives.len() {
                    return Err(DebianError::plan_document(format!(
                        "the package {name} names archive {at}, which the document does not \
                         carry — archive stanzas must precede the packages that refer to them",
                    )));
                }
                let package = PlannedPackage {
                    name: name.to_string(),
                    version: required(stanza.get("Version"), "Version", &at_package)?,
                    architecture: required(
                        stanza.get("Architecture"),
                        "Architecture",
                        &at_package,
                    )?,
                    digest: planned_digest(&stanza, &at_package)?,
                    filename: required(stanza.get("Filename"), "Filename", &at_package)?,
                    archive: at,
                    installed_size: number(
                        stanza.get("Installed-Size"),
                        "Installed-Size",
                        &at_package,
                    )?,
                    // Read verbatim rather than folded against the package's own
                    // name: the writer never states a source that matches, so a
                    // document that does was written by hand, and echoing it back
                    // unchanged is what keeps the round trip byte-faithful.
                    source: stanza.get("Source").map(Cow::into_owned),
                    size: number(stanza.get("Size"), "Size", &at_package)?,
                    carried: document::carried(&stanza, PACKAGE_FIELDS),
                };
                if let Some(reason) = package.unaddressable() {
                    return Err(DebianError::plan_document(reason));
                }
                plan.packages.push(package);
                continue;
            }

            let index = stanza.get("Archive").ok_or_else(|| {
                DebianError::plan_document(
                    "a stanza is neither a package nor an archive".to_string(),
                )
            })?;
            // The index is written out so the document reads on its own, and
            // checked rather than trusted: a document whose archives are out of
            // order would silently attribute packages to the wrong mirror. It is
            // held to the spelling the writer gives it, as every number is.
            let expected = plan.archives.len();
            if index != expected.to_string() {
                return Err(DebianError::plan_document(format!(
                    "the archive stanzas are numbered out of order: expected {expected}, \
                     found {index:?}",
                )));
            }
            let at_archive = format!("archive {expected}");
            plan.archives.push(ResolvedArchive {
                mirror: required(stanza.get("Mirror"), "Mirror", &at_archive)?,
                suite: required(stanza.get("Suite"), "Suite", &at_archive)?,
                components: document::list(stanza.get("Components").as_deref()),
                release_sha256: {
                    let value =
                        required(stanza.get("Release-SHA256"), "Release-SHA256", &at_archive)?;
                    Digest::new(Algorithm::Sha256, &value).ok_or_else(|| {
                        DebianError::plan_document(format!(
                            "{at_archive} states the Release-SHA256 {value:?}, which is not a \
                             SHA-256 digest in lowercase hex"
                        ))
                    })?
                },
                date: stanza.get("Date").map(Cow::into_owned),
                valid_until: stanza.get("Valid-Until").map(Cow::into_owned),
                signed_by: document::list(stanza.get("Signed-By").as_deref()),
                signing_key: document::list(stanza.get("Signing-Key").as_deref()),
                carried: document::carried(&stanza, ARCHIVE_FIELDS),
            });
        }
        Ok(plan)
    }

    /// Builds a plan from a resolved package set, projecting each package onto
    /// the public shape. Shared by [`Debian::resolve`](super::Debian::resolve)
    /// and the mid-bootstrap [`Resolved`](super::DebianEvent::Resolved) event, so
    /// the plan a caller previews and the plan an in-flight bootstrap reports are
    /// the same value built one way.
    pub(crate) fn project(
        suite: &str,
        architecture: &str,
        packages: &[Package],
        archives: &[ResolvedArchive],
    ) -> Plan {
        Plan {
            suite: suite.to_string(),
            architecture: architecture.to_string(),
            packages: packages.iter().map(PlannedPackage::from_package).collect(),
            archives: archives.to_vec(),
            // A plan built from a live resolution has no document behind it,
            // so there is nothing to carry.
            carried: Carried::new(),
        }
    }
}

impl PlannedPackage {
    /// Projects an internal [`Package`] onto the public plan shape.
    pub(crate) fn from_package(package: &Package) -> PlannedPackage {
        PlannedPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            architecture: package.architecture.clone(),
            digest: package.digests.planned().clone(),
            filename: package.filename.clone(),
            // The index tags each retained package with the repository it came
            // from, which is exactly this list's ordering.
            archive: package.origin,
            installed_size: package.installed_size,
            source: package.source.clone(),
            size: package.size,
            carried: Carried::new(),
        }
    }
}

/// The header fields this version writes and reads.
///
/// The three tables exist so that "a field this version does not know" has one
/// definition, used by both halves: the reader collects what is not here, and
/// the writer emits what is here and then what was collected. A field added to
/// a stanza has to be added to its table, or it would be both written as a
/// known field and carried as an unknown one.
const HEADER_FIELDS: &[&str] = &["Format", "Suite", "Architecture"];
/// The archive-stanza fields this version writes and reads.
const ARCHIVE_FIELDS: &[&str] = &[
    "Archive",
    "Mirror",
    "Suite",
    "Components",
    "Release-SHA256",
    "Date",
    "Valid-Until",
    "Signed-By",
    "Signing-Key",
];
/// The package-stanza fields this version writes and reads.
const PACKAGE_FIELDS: &[&str] = &[
    "Package",
    "Version",
    "Architecture",
    "SHA256",
    "Filename",
    "Archive",
    "Installed-Size",
    "Source",
    "Size",
    "SHA512",
];

/// Reads the one digest a package stanza states, under `SHA256` or `SHA512`.
///
/// A stanza stating neither has nothing to check the package's bytes against,
/// and one stating both is not a plan this library writes: a plan records one.
/// A value outside its algorithm's shape is quoted, since nothing has admitted
/// it.
fn planned_digest(stanza: &document::Stanza<'_>, at: &str) -> Result<Digest, DebianError> {
    let mut stated = RECORDED
        .iter()
        .filter_map(|(algorithm, field)| Some((*algorithm, *field, stanza.get(field)?)));
    let (algorithm, field, value) = stated.next().ok_or_else(|| {
        DebianError::plan_document(format!("{at} states neither a SHA256 nor a SHA512"))
    })?;
    if stated.next().is_some() {
        return Err(DebianError::plan_document(format!(
            "{at} states both a SHA256 and a SHA512, and a plan records one"
        )));
    }
    Digest::new(algorithm, &value).ok_or_else(|| {
        DebianError::plan_document(format!(
            "{at} states the {field} {value:?}, which is not a {} digest in lowercase hex",
            algorithm.name(),
        ))
    })
}

/// Reads a required field, reporting a refusal as this layer's document
/// failure.
///
/// The rule is [`document::required`]'s and is shared with every other layer;
/// only whose document the refusal is about belongs here.
fn required(value: Option<Cow<'_, str>>, field: &str, at: &str) -> Result<String, DebianError> {
    document::required(value.as_deref(), field, at).map_err(DebianError::plan_document)
}

/// Reads an optional numeric field, reporting a refusal the same way.
///
/// The rule is [`document::number`]'s.
fn number<T: std::str::FromStr + std::fmt::Display>(
    value: Option<Cow<'_, str>>,
    field: &str,
    at: &str,
) -> Result<Option<T>, DebianError> {
    document::number(value.as_deref(), field, at).map_err(DebianError::plan_document)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plan with two archives, a package from each, an unsigned repository,
    /// and a release carrying neither optional date.
    /// The SHA-256 spelled by repeating `fill` to its width.
    fn sha256(fill: &str) -> Digest {
        Digest::new(Algorithm::Sha256, &fill.repeat(64 / fill.len())).expect("lowercase hex")
    }

    fn sample() -> Plan {
        Plan {
            suite: "trixie".to_string(),
            architecture: "arm64".to_string(),
            archives: vec![
                ResolvedArchive {
                    mirror: "http://deb.debian.org/debian".to_string(),
                    suite: "trixie".to_string(),
                    components: vec!["main".to_string(), "contrib".to_string()],
                    release_sha256: sha256("9f3a"),
                    date: Some("Sat, 02 Aug 2026 08:14:33 UTC".to_string()),
                    valid_until: Some("Sat, 09 Aug 2026 08:14:33 UTC".to_string()),
                    // A real archive key pair: the trixie certificate, and the
                    // dedicated signing subkey it signs releases with.
                    signed_by: vec!["04B54C3CDCA79751B16BC6B5225629DF75B188BD".to_string()],
                    signing_key: vec!["B8E5F13176D2A7A75220028078DBA3BC47EF2265".to_string()],
                    carried: Carried::new(),
                },
                ResolvedArchive {
                    mirror: "http://mirror.invalid/local".to_string(),
                    suite: "trixie".to_string(),
                    components: vec!["main".to_string()],
                    release_sha256: sha256("1c0f"),
                    date: None,
                    valid_until: None,
                    signed_by: Vec::new(),
                    signing_key: Vec::new(),
                    carried: Carried::new(),
                },
            ],
            packages: vec![
                PlannedPackage {
                    name: "base-files".to_string(),
                    version: "13.6".to_string(),
                    architecture: "arm64".to_string(),
                    digest: sha256("aa"),
                    filename: "pool/main/b/base-files/base-files_13.6_arm64.deb".to_string(),
                    archive: 0,
                    installed_size: Some(340),
                    // Its own source, as most packages are.
                    source: None,
                    size: Some(69_412),
                    carried: Carried::new(),
                },
                PlannedPackage {
                    name: "local-tool".to_string(),
                    // An epoch, whose colon the document carries verbatim.
                    version: "1:2.4-1".to_string(),
                    architecture: "all".to_string(),
                    digest: sha256("bb"),
                    filename: "pool/main/l/local-tool/local-tool_2.4-1_all.deb".to_string(),
                    archive: 1,
                    // A package the archive states no size for, which Debian
                    // Policy permits.
                    installed_size: None,
                    source: Some("local-suite".to_string()),
                    size: None,
                    carried: Carried::new(),
                },
            ],
            carried: Carried::new(),
        }
    }

    /// What [`sample`] renders to, spelled out.
    ///
    /// A round trip proves the reader and the writer agree with each other; it
    /// cannot notice the two of them moving together. This is the format itself:
    /// which fields are written, in which order, how an absent optional differs
    /// from an empty list, and where the blank lines fall. A change to any of
    /// those is a change to the format, and the format carries a version because
    /// a reader that cannot tell which shape it is holding cannot say what it is
    /// trusting — so this failing is the prompt to decide whether that version
    /// has to move.
    const GOLDEN: &str = "\
Format: ferroday-cage-plan 2
Suite: trixie
Architecture: arm64

Archive: 0
Mirror: http://deb.debian.org/debian
Suite: trixie
Components: main contrib
Release-SHA256: 9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a
Date: Sat, 02 Aug 2026 08:14:33 UTC
Valid-Until: Sat, 09 Aug 2026 08:14:33 UTC
Signed-By: 04B54C3CDCA79751B16BC6B5225629DF75B188BD
Signing-Key: B8E5F13176D2A7A75220028078DBA3BC47EF2265

Archive: 1
Mirror: http://mirror.invalid/local
Suite: trixie
Components: main
Release-SHA256: 1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f
Signed-By:
Signing-Key:

Package: base-files
Version: 13.6
Architecture: arm64
SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Filename: pool/main/b/base-files/base-files_13.6_arm64.deb
Archive: 0
Installed-Size: 340
Size: 69412

Package: local-tool
Version: 1:2.4-1
Architecture: all
SHA256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
Filename: pool/main/l/local-tool/local-tool_2.4-1_all.deb
Archive: 1
Source: local-suite

";

    #[test]
    fn the_document_is_the_format_this_version_writes() {
        assert_eq!(sample().to_document().expect("the plan renders"), GOLDEN);
        // And it reads back as the plan it came from, so the literal above is a
        // document rather than only a string that happens to match.
        assert_eq!(
            Plan::parse_document(GOLDEN).expect("the golden reads"),
            sample()
        );
    }

    #[test]
    fn a_plan_survives_a_document_round_trip() {
        let plan = sample();
        let document = plan.to_document().expect("the plan renders");
        let read = Plan::parse_document(&document).expect("the document reads");
        assert_eq!(read, plan, "\n{document}");
    }

    #[test]
    fn a_rendering_is_stable_and_a_reread_renders_identically() {
        // The plan's lists are already ordered, so the document is a value a
        // consumer can commit and diff rather than a blob that churns.
        let plan = sample();
        let first = plan.to_document().unwrap();
        assert_eq!(first, plan.to_document().unwrap());
        assert_eq!(
            first,
            Plan::parse_document(&first).unwrap().to_document().unwrap(),
        );
    }

    #[test]
    fn the_document_is_readable_deb822() {
        let document = sample().to_document().unwrap();
        assert!(
            document.starts_with("Format: ferroday-cage-plan 2\n"),
            "{document}",
        );
        // Every stanza is separated by a blank line and no field is folded, so
        // a plain deb822 reader — apt's included — parses it.
        for line in document.lines() {
            assert!(
                line.is_empty() || line.contains(": ") || line.ends_with(':'),
                "{line:?} is neither blank nor a field",
            );
            assert!(!line.starts_with(' '), "{line:?} reads as a continuation");
        }
        // The absent optional fields are absent, not empty.
        assert!(!document.contains("Valid-Until:\n"), "{document}");
        // The empty list is present, because unsigned is an answer -- written
        // bare, with nothing after the colon.
        assert!(document.contains("\nSigned-By:\n"), "{document}");
    }

    #[test]
    fn no_line_the_format_can_produce_ends_in_whitespace() {
        // A committed plan must survive the editors and pre-commit hooks that
        // strip trailing whitespace. `Signed-By: ` was the one line the format
        // could produce that would not, and it appeared exactly where a
        // repository is trusted unsigned -- so stripping it changed a
        // committed plan's bytes, and its digest, without the plan changing.
        let mut plan = sample();
        plan.archives[0].signed_by.clear();
        plan.archives[0].components.clear();
        let document = plan.to_document().unwrap();
        for line in document.lines() {
            assert_eq!(line.trim_end(), line, "{line:?} ends in whitespace");
        }
        // Stripping is now a no-op, so a hook cannot change the bytes.
        let stripped: String = document
            .lines()
            .map(|line| format!("{}\n", line.trim_end()))
            .collect();
        assert_eq!(stripped, document);
        assert_eq!(Plan::parse_document(&document).unwrap(), plan);
    }

    #[test]
    fn a_value_whose_whitespace_a_reader_would_strip_is_refused() {
        // A reader trims a value, so a value carrying its own whitespace would
        // read back as a different string. Refusing is what keeps the round
        // trip total; a leading one would additionally fold into the field
        // above it, deb822's continuation marker being a leading space.
        for suite in [" trixie", "trixie "] {
            let mut plan = sample();
            plan.suite = suite.to_string();
            match plan.to_document() {
                Err(DebianError::PlanDocument { reason }) => {
                    assert!(reason.contains("whitespace"), "{reason}");
                }
                other => panic!("expected a whitespace refusal for {suite:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_document_from_a_format_this_library_does_not_read_is_refused() {
        // Both directions, because a superseded version is refused for the same
        // reason a later one is: the reader cannot say what the fields mean. In
        // version 1 `Signed-By` named the key that made the signature rather
        // than the certificate, so reading one would answer a question the
        // caller did not ask.
        for version in ["ferroday-cage-plan 1", "ferroday-cage-plan 3"] {
            let document = sample()
                .to_document()
                .unwrap()
                .replace("ferroday-cage-plan 2", version);
            match Plan::parse_document(&document) {
                Err(DebianError::PlanDocument { reason }) => {
                    assert!(reason.contains("format"), "{reason}");
                }
                other => panic!("expected a format refusal for {version:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_field_this_library_does_not_know_survives_a_round_trip() {
        // The forward-compatibility promise, and the half of it that is easy to
        // leave out: a document written by a later version, with fields added
        // but the format version unchanged, both reads *and writes back*.
        //
        // Ignoring a field on the way in and dropping it on the way out are
        // different things. A consumer that reads a plan and writes it back --
        // into a provenance record, or to normalize a file it commits -- would
        // otherwise silently discard whatever the newer writer had added, which
        // is the one thing a plan kept for reproducibility must not do.
        // One of them folded, which a deb822 writer does for a list and which
        // the reader accepts: a carried field refused on the way out is a
        // document this crate reads and cannot re-emit, which is the failure
        // carrying one exists to prevent.
        let document = sample()
            .to_document()
            .unwrap()
            .replace(
                "Suite: trixie\n",
                "Suite: trixie\nFuture-Header: h\nFuture-List:\n first\n second\n",
            )
            .replace(
                "Mirror: http://deb.debian.org/debian\n",
                "Mirror: http://deb.debian.org/debian\nFuture-Archive: a\n",
            )
            .replace(
                "Package: base-files\n",
                "Package: base-files\nFuture-Package: p\n",
            );

        let plan = Plan::parse_document(&document).expect("a newer document reads");
        let rewritten = plan.to_document().expect("and writes back");
        for carried in [
            "Future-Header: h",
            "Future-List:\n first\n second\n",
            "Future-Archive: a",
            "Future-Package: p",
        ] {
            assert!(
                rewritten.contains(carried),
                "{carried} was dropped:\n{rewritten}"
            );
        }
        // And the carried fields are themselves stable: a second round trip is
        // byte-identical, so re-emitting a plan does not churn a committed file.
        assert_eq!(
            Plan::parse_document(&rewritten)
                .unwrap()
                .to_document()
                .unwrap(),
            rewritten,
        );
        assert_eq!(Plan::parse_document(&rewritten).unwrap(), plan);
    }

    #[test]
    fn a_plan_from_a_resolution_carries_nothing() {
        // Only a document can put a field in the carry list, so a plan built
        // from a live resolution compares equal to one read back from its own
        // document.
        let plan = sample();
        assert_eq!(
            Plan::parse_document(&plan.to_document().unwrap()).unwrap(),
            plan
        );
    }

    #[test]
    fn a_resolution_plans_the_sha256_where_the_index_offers_one() {
        let sha256 = "aa".repeat(32);
        let sha512 = "cc".repeat(64);
        let planned = |digests: &str| {
            let text = format!(
                "Package: held\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/p.deb\n\
                 {digests}\n"
            );
            let index = super::super::index::Index::parse(&text, "amd64");
            let package = index.get("held").expect("the stanza reads").clone();
            Plan::project("trixie", "amd64", &[package], &[]).packages[0]
                .digest
                .clone()
        };
        // As Ubuntu's archives record: the plan keeps the SHA-256, so it reads
        // as a Debian plan does.
        let both = planned(&format!("SHA256: {sha256}\nSHA512: {sha512}"));
        assert_eq!(
            (both.algorithm(), both.hex()),
            (Algorithm::Sha256, sha256.as_str())
        );
        // As Ubuntu's development series records.
        let alone = planned(&format!("SHA512: {sha512}"));
        assert_eq!(
            (alone.algorithm(), alone.hex()),
            (Algorithm::Sha512, sha512.as_str())
        );
    }

    #[test]
    fn a_package_naming_an_archive_the_document_does_not_carry_is_refused() {
        // Silently attributing a package to the wrong mirror is the failure
        // this prevents, and it is exactly what a plan is kept to avoid.
        let document = sample().to_document().unwrap().replace(
            "Filename: pool/main/b/base-files/base-files_13.6_arm64.deb\nArchive: 0",
            "Filename: pool/main/b/base-files/base-files_13.6_arm64.deb\nArchive: 7",
        );
        match Plan::parse_document(&document) {
            Err(DebianError::PlanDocument { reason }) => {
                assert!(reason.contains("archive 7"), "{reason}");
            }
            other => panic!("expected an archive refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_filename_no_mirror_could_be_asked_for_is_refused() {
        // The pool path is interpolated verbatim into the fetch URL and, for a
        // `file://` mirror, into a local path. A document is a trust anchor, but
        // it is also a file a caller may have edited, and the index path refuses
        // exactly these for exactly these reasons.
        for filename in [
            "../../../etc/passwd",
            "/etc/passwd",
            "pool/%2e%2e/%2e%2e/etc/passwd",
            // Folded across a continuation line, which is how a value carrying
            // a newline reaches the reader at all.
            "pool/main/b/base-files.deb\n GET /elsewhere HTTP/1.1",
        ] {
            let document = sample().to_document().unwrap().replace(
                "Filename: pool/main/b/base-files/base-files_13.6_arm64.deb",
                &format!("Filename: {filename}"),
            );
            match Plan::parse_document(&document) {
                Err(DebianError::PlanDocument { reason }) => {
                    assert!(reason.contains("base-files"), "{filename:?}: {reason}");
                    assert!(reason.contains("asked for"), "{filename:?}: {reason}");
                }
                other => panic!("expected a pool-path refusal for {filename:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_package_recording_a_sha512_round_trips_and_one_digest_is_read() {
        // As Ubuntu's development series records, which states no SHA-256. The
        // SHA-256 is the golden document.
        let sha512 = "cc".repeat(64);
        let mut plan = sample();
        plan.packages[0].digest = Digest::new(Algorithm::Sha512, &sha512).unwrap();
        let document = plan.to_document().unwrap();
        assert!(!document.contains("\nSHA256: aa"), "{document}");
        // Written after every field a reader before it knew.
        assert!(
            document.contains(&format!("Size: 69412\nSHA512: {sha512}\n")),
            "{document}"
        );
        let read = Plan::parse_document(&document).expect("the document reads back");
        assert_eq!(read, plan);
        assert_eq!(read.to_document().unwrap(), document);

        // A plan records one digest: neither is nothing to check the bytes
        // against, and both is not a plan this library writes.
        let golden = sample().to_document().unwrap();
        let line = format!("SHA256: {}\n", "aa".repeat(32));
        for (document, expected) in [
            (golden.replace(&line, ""), "neither a SHA256 nor a SHA512"),
            (
                golden.replace(&line, &format!("{line}SHA512: {sha512}\n")),
                "both a SHA256 and a SHA512",
            ),
        ] {
            match Plan::parse_document(&document) {
                Err(DebianError::PlanDocument { reason }) => {
                    assert!(reason.contains(expected), "{reason}");
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
        }

        // A release's digest is held to its shape as a package's is.
        let document = golden.replace(&"9f3a".repeat(16), &"9F3A".repeat(16));
        match Plan::parse_document(&document) {
            Err(DebianError::PlanDocument { reason }) => {
                assert!(reason.contains("Release-SHA256"), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_digest_that_is_not_lowercase_hex_is_refused() {
        // The digest is compared with a plain `==` against what the archive
        // publishes, so an uppercase one could only ever mismatch — and would be
        // reported as bytes that were not the package rather than as the
        // malformed document it came from.
        let document = sample()
            .to_document()
            .unwrap()
            .replace(&"aa".repeat(32), &"AA".repeat(32));
        match Plan::parse_document(&document) {
            Err(DebianError::PlanDocument { reason }) => {
                assert!(reason.contains("base-files"), "{reason}");
                assert!(reason.contains("lowercase hex"), "{reason}");
            }
            other => panic!("expected a digest refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_package_named_outside_policy_is_refused_before_any_message_names_it() {
        // A bootstrap reports a planned package by its name, so a document is
        // held to the alphabet an index is. The archive index is dropped too, so
        // the refusal that would otherwise come first names the package as well.
        let hostile = crate::failure::hostile::TEXT;
        for name in [hostile, "Base-files", "base_files", "b"] {
            let document = sample()
                .to_document()
                .unwrap()
                .replace("Package: base-files", &format!("Package: {name}"))
                .replace("Archive: 0\nInstalled-Size", "Installed-Size");
            match Plan::parse_document(&document) {
                Err(DebianError::PlanDocument { reason }) => {
                    assert!(reason.contains("Debian policy"), "{name:?}: {reason}");
                    if name == hostile {
                        crate::failure::hostile::assert_escaped(&reason);
                    }
                }
                other => panic!("expected a name refusal for {name:?}, got {other:?}"),
            }
        }

        // A version reaches a pin's refusals, so a plan's is held to policy's
        // alphabet too.
        let document = sample()
            .to_document()
            .unwrap()
            .replace("Version: 13.6", &format!("Version: {hostile}"));
        match Plan::parse_document(&document) {
            Err(DebianError::PlanDocument { reason }) => {
                assert!(reason.contains("base-files at"), "{reason}");
                crate::failure::hostile::assert_escaped(&reason);
            }
            other => panic!("expected a version refusal, got {other:?}"),
        }

        // A plan held in memory reaches a bootstrap without a document, and is
        // held to the same alphabet, before the archive it names is.
        let mut plan = sample();
        plan.packages[0].name = hostile.to_string();
        plan.packages[0].archive = 7;
        match super::super::validate_plan(&plan, "trixie", "arm64", 2, false, &[], &[]) {
            Err(DebianError::Config { reason }) => {
                assert!(reason.contains("Debian policy"), "{reason}");
                crate::failure::hostile::assert_escaped(&reason);
            }
            other => panic!("expected a name refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_plan_header_reaches_a_refusal_with_its_control_characters_escaped() {
        // A document is a file the caller may have taken from elsewhere, and
        // nothing holds its header to an alphabet.
        let hostile = crate::failure::hostile::TEXT;
        for field in ["suite", "architecture"] {
            let mut plan = sample();
            match field {
                "suite" => plan.suite = hostile.to_string(),
                _ => plan.architecture = hostile.to_string(),
            }
            let refusals = [
                super::super::validate_plan(&plan, "trixie", "arm64", 2, false, &[], &[]),
                super::super::validate_pin(&plan, "trixie", "arm64", false),
            ];
            for refused in refusals {
                match refused {
                    Err(DebianError::Config { reason }) => {
                        assert!(reason.contains(field), "{reason}");
                        crate::failure::hostile::assert_escaped(&reason);
                    }
                    other => panic!("expected a {field} refusal, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn a_missing_required_field_names_the_stanza_it_is_missing_from() {
        let document = sample()
            .to_document()
            .unwrap()
            .replace("SHA256: aa", "Sha-Was-Here: aa");
        match Plan::parse_document(&document) {
            Err(DebianError::PlanDocument { reason }) => {
                assert!(reason.contains("base-files"), "{reason}");
                assert!(reason.contains("SHA256"), "{reason}");
            }
            other => panic!("expected a missing-field refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_value_the_format_cannot_carry_refuses_the_whole_document() {
        // A hostile mirror can fold a value across lines, and a document that
        // wrote it out would read back as a different plan. Refusing is the
        // only answer that keeps the round trip honest.
        let mut plan = sample();
        plan.packages[0].filename = "pool/main/b/base-files\nArchive: 1".to_string();
        match plan.to_document() {
            Err(DebianError::PlanDocument { reason }) => {
                assert!(reason.contains("more than one line"), "{reason}");
            }
            other => panic!("expected a rendering refusal, got {other:?}"),
        }
    }

    #[test]
    fn archives_numbered_out_of_order_are_refused() {
        let document = sample().to_document().unwrap().replace(
            "Archive: 1\nMirror: http://mirror.invalid/local",
            "Archive: 5\nMirror: http://mirror.invalid/local",
        );
        match Plan::parse_document(&document) {
            Err(DebianError::PlanDocument { reason }) => {
                assert!(reason.contains("out of order"), "{reason}");
            }
            other => panic!("expected an ordering refusal, got {other:?}"),
        }
    }

    /// The package-stanza fields the format's first readers knew, before
    /// `Installed-Size`, `Source`, and `Size` joined them.
    const PACKAGE_FIELDS_AS_FIRST_WRITTEN: &[&str] = &[
        "Package",
        "Version",
        "Architecture",
        "SHA256",
        "Filename",
        "Archive",
    ];

    /// Rewrites a document the way a reader holding an older field list would:
    /// each stanza's known fields in that reader's own order, then every other
    /// field in document order, which is where `put_carried` appends what it
    /// carried.
    fn as_an_older_reader_rewrites(document: &str) -> String {
        let mut out = String::new();
        for stanza in document::parse(document) {
            let known: &[&str] = if stanza.get("Package").is_some() {
                PACKAGE_FIELDS_AS_FIRST_WRITTEN
            } else if stanza.get("Archive").is_some() {
                ARCHIVE_FIELDS
            } else {
                HEADER_FIELDS
            };
            let line = |name: &str, value: &str| {
                if value.is_empty() {
                    format!("{name}:\n")
                } else {
                    format!("{name}: {value}\n")
                }
            };
            for name in known {
                if let Some(value) = stanza.get(name) {
                    out.push_str(&line(name, &value));
                }
            }
            for (name, value) in stanza
                .fields()
                .filter(|(name, _)| !known.iter().any(|known| known.eq_ignore_ascii_case(name)))
            {
                out.push_str(&line(name, &value));
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn a_field_added_since_the_format_was_first_written_survives_an_older_reader() {
        // Why Installed-Size, Source, and Size are written after Archive rather
        // than beside the fields they describe. An older reader carries a field it
        // does not know and re-emits it after the ones it does, so a field
        // written between the older ones comes back from that reader with the
        // stanza's lines reordered -- and a record pinning the document's
        // digest reports a change to a plan that did not change. Written last,
        // the two renderings agree byte for byte.
        let document = sample().to_document().unwrap();
        assert!(document.contains("\nInstalled-Size: 340\n"), "{document}");
        assert!(document.contains("\nSource: local-suite\n"), "{document}");
        assert!(document.contains("\nSize: 69412\n"), "{document}");
        assert_eq!(as_an_older_reader_rewrites(&document), document);
    }

    #[test]
    fn a_document_written_before_these_fields_existed_still_reads() {
        // Every plan document written so far lacks both fields, and one pinned
        // by digest in a record that vouches for it cannot be regenerated to
        // add them. Neither field may become required.
        let mut plan = sample();
        for package in &mut plan.packages {
            package.installed_size = None;
            package.source = None;
            package.size = None;
        }
        let document = plan.to_document().unwrap();
        assert!(!document.contains("Installed-Size"), "{document}");
        assert!(!document.contains("Source"), "{document}");
        assert!(!document.contains("Size"), "{document}");
        assert_eq!(Plan::parse_document(&document).unwrap(), plan);
    }

    #[test]
    fn a_malformed_size_is_refused_rather_than_read_as_absent() {
        // Reading it as absent would drop the line on the way out, which is
        // the loss the carried fields exist to prevent.
        for (field, from, to) in [
            (
                "Installed-Size",
                "Installed-Size: 340",
                "Installed-Size: 340 kB",
            ),
            ("Size", "Size: 69412", "Size: 69 kB"),
        ] {
            let document = sample().to_document().unwrap().replace(from, to);
            match Plan::parse_document(&document) {
                Err(DebianError::PlanDocument { reason }) => {
                    assert!(reason.contains("base-files"), "{reason}");
                    assert!(reason.contains(field), "{reason}");
                    assert!(reason.contains("not a number"), "{reason}");
                }
                other => panic!("expected a {field} refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_empty_document_is_refused_rather_than_read_as_an_empty_plan() {
        assert!(matches!(
            Plan::parse_document(""),
            Err(DebianError::PlanDocument { .. }),
        ));
        assert!(matches!(
            Plan::parse_document("Suite: trixie\nArchitecture: arm64\n"),
            Err(DebianError::PlanDocument { .. }),
        ));
    }
}
