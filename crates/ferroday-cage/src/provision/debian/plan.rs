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

use super::DebianError;
use super::index::Package;
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
    /// The mirror URL that served the release, which is the one the packages
    /// will be fetched from.
    ///
    /// The URL that answered, not the configured list: a repository with a
    /// snapshot backstop resolves against whichever mirror served, and
    /// recording the list would describe a choice rather than the choice made.
    pub mirror: String,
    /// The suite as the repository requested it.
    pub suite: String,
    /// The components resolved from this repository.
    pub components: Vec<String>,
    /// The SHA-256 of the release body that was verified, lowercase hex.
    ///
    /// For a signed repository this is the digest of the cleartext the
    /// signature covers, so it identifies the exact archive state the
    /// signature vouched for.
    pub release_sha256: String,
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
    /// verification stops at the first valid one, so this names the key that
    /// was actually used rather than every key that could have been.
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
    carried: Carried,
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
    /// The SHA-256 the archive records for the `.deb`, as lowercase hex.
    pub sha256: String,
    /// The pool path of the `.deb`, relative to the mirror root.
    pub filename: String,
    /// Which of [`Plan::archives`] this package's winning version came from,
    /// as an index into that list.
    ///
    /// Resolution is highest-version-wins across the merged repositories, so
    /// with more than one configured this is the only thing that says where a
    /// package will actually be fetched from.
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
    /// Fields this package's stanza carried that this version does not know.
    carried: Carried,
}

impl Plan {
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
        header.render(&mut out).map_err(document)?;

        for (index, archive) in self.archives.iter().enumerate() {
            let mut stanza = Draft::new();
            stanza.put("Archive", &index.to_string());
            stanza.put("Mirror", &archive.mirror);
            stanza.put("Suite", &archive.suite);
            stanza.put_list("Components", &archive.components);
            stanza.put("Release-SHA256", &archive.release_sha256);
            stanza.put_optional("Date", archive.date.as_deref());
            stanza.put_optional("Valid-Until", archive.valid_until.as_deref());
            // Written even when empty: an unsigned repository is a fact about
            // the plan's trust, not an absence of information, and a reader
            // that saw no key at all could not tell the two apart.
            stanza.put_allowing_empty("Signed-By", &archive.signed_by.join(" "));
            stanza.put_allowing_empty("Signing-Key", &archive.signing_key.join(" "));
            stanza.put_carried(&archive.carried);
            stanza.render(&mut out).map_err(document)?;
        }

        for package in &self.packages {
            if package.archive >= self.archives.len() {
                return Err(document(format!(
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
            stanza.put("SHA256", &package.sha256);
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
            stanza.put_carried(&package.carried);
            stanza.render(&mut out).map_err(document)?;
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
    /// cannot do without, a malformed archive index, or a package naming an
    /// archive the document does not carry.
    pub fn parse_document(text: &str) -> Result<Plan, DebianError> {
        let stanzas = document::parse(text);
        let (header, rest) = stanzas
            .split_first()
            .ok_or_else(|| document("the document holds no stanzas".to_string()))?;

        let format = header
            .get("Format")
            .ok_or_else(|| document("the first stanza has no Format field".to_string()))?;
        if format != FORMAT {
            return Err(document(format!(
                "the document is in format {format:?}, and this library reads {FORMAT:?}"
            )));
        }
        let mut plan = Plan {
            suite: required(header.get("Suite"), "Suite", "the header")?,
            architecture: required(header.get("Architecture"), "Architecture", "the header")?,
            packages: Vec::new(),
            archives: Vec::new(),
            carried: document::carried(header, HEADER_FIELDS),
        };

        for stanza in rest {
            if let Some(name) = stanza.get("Package") {
                let at = stanza
                    .get("Archive")
                    .ok_or_else(|| document(format!("the package {name} names no archive")))?
                    .parse::<usize>()
                    .map_err(|_| {
                        document(format!("the package {name} has a malformed archive index"))
                    })?;
                if at >= plan.archives.len() {
                    return Err(document(format!(
                        "the package {name} names archive {at}, which the document does not \
                         carry — archive stanzas must precede the packages that refer to them",
                    )));
                }
                let at_package = format!("the package {name}");
                plan.packages.push(PlannedPackage {
                    name: name.to_string(),
                    version: required(stanza.get("Version"), "Version", &at_package)?,
                    architecture: required(
                        stanza.get("Architecture"),
                        "Architecture",
                        &at_package,
                    )?,
                    sha256: required(stanza.get("SHA256"), "SHA256", &at_package)?,
                    filename: required(stanza.get("Filename"), "Filename", &at_package)?,
                    archive: at,
                    installed_size: kibibytes(stanza.get("Installed-Size"), &at_package)?,
                    // Read verbatim rather than folded against the package's own
                    // name: the writer never states a source that matches, so a
                    // document that does was written by hand, and echoing it back
                    // unchanged is what keeps the round trip byte-faithful.
                    source: stanza.get("Source").map(str::to_string),
                    carried: document::carried(stanza, PACKAGE_FIELDS),
                });
                continue;
            }

            let index = stanza.get("Archive").ok_or_else(|| {
                document("a stanza is neither a package nor an archive".to_string())
            })?;
            // The index is written out so the document reads on its own, and
            // checked rather than trusted: a document whose archives are out of
            // order would silently attribute packages to the wrong mirror.
            let expected = plan.archives.len();
            if index.parse::<usize>().ok() != Some(expected) {
                return Err(document(format!(
                    "the archive stanzas are numbered out of order: expected {expected}, \
                     found {index:?}",
                )));
            }
            let at_archive = format!("archive {expected}");
            plan.archives.push(ResolvedArchive {
                mirror: required(stanza.get("Mirror"), "Mirror", &at_archive)?,
                suite: required(stanza.get("Suite"), "Suite", &at_archive)?,
                components: document::list(stanza.get("Components")),
                release_sha256: required(
                    stanza.get("Release-SHA256"),
                    "Release-SHA256",
                    &at_archive,
                )?,
                date: stanza.get("Date").map(str::to_string),
                valid_until: stanza.get("Valid-Until").map(str::to_string),
                signed_by: document::list(stanza.get("Signed-By")),
                signing_key: document::list(stanza.get("Signing-Key")),
                carried: document::carried(stanza, ARCHIVE_FIELDS),
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

impl ResolvedArchive {
    /// Records one repository's state as a live resolution observed it.
    ///
    /// A constructor rather than a struct literal because the carried-field
    /// list is private: a record built from a resolution has no document behind
    /// it, so there is nothing to carry.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resolved(
        mirror: String,
        suite: String,
        components: Vec<String>,
        release_sha256: String,
        date: Option<String>,
        valid_until: Option<String>,
        signed_by: Vec<String>,
        signing_key: Vec<String>,
    ) -> ResolvedArchive {
        ResolvedArchive {
            mirror,
            suite,
            components,
            release_sha256,
            date,
            valid_until,
            signed_by,
            signing_key,
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
            sha256: package.sha256.clone(),
            filename: package.filename.clone(),
            // The index tags each retained package with the repository it came
            // from, which is exactly this list's ordering.
            archive: package.origin,
            installed_size: package.installed_size,
            source: package.source.clone(),
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
];

/// Reads an optional size field, absent giving no value.
///
/// A value that is not a number refuses the document rather than reading as
/// absent. Reading it as absent would drop it on the way out, and a document
/// that came back missing a line it was given is the one failure the carried
/// fields exist to prevent.
fn kibibytes(value: Option<&str>, at: &str) -> Result<Option<u64>, DebianError> {
    match value {
        Some(value) => value.parse::<u64>().map(Some).map_err(|_| {
            document(format!(
                "{at} has an Installed-Size of {value:?}, which is not a size in kibibytes",
            ))
        }),
        None => Ok(None),
    }
}

/// Reads a required field, reporting a refusal as this layer's document
/// failure.
///
/// The rule is [`document::required`]'s and is shared with every other layer;
/// only whose document the refusal is about belongs here.
fn required(value: Option<&str>, field: &str, at: &str) -> Result<String, DebianError> {
    document::required(value, field, at).map_err(document)
}

/// Builds the document error.
fn document(reason: String) -> DebianError {
    DebianError::PlanDocument { reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plan with two archives, a package from each, an unsigned repository,
    /// and a release carrying neither optional date.
    fn sample() -> Plan {
        Plan {
            suite: "trixie".to_string(),
            architecture: "arm64".to_string(),
            archives: vec![
                ResolvedArchive {
                    mirror: "http://deb.debian.org/debian".to_string(),
                    suite: "trixie".to_string(),
                    components: vec!["main".to_string(), "contrib".to_string()],
                    release_sha256: "9f3a".repeat(16),
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
                    release_sha256: "1c0f".repeat(16),
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
                    sha256: "aa".repeat(32),
                    filename: "pool/main/b/base-files/base-files_13.6_arm64.deb".to_string(),
                    archive: 0,
                    installed_size: Some(340),
                    // Its own source, as most packages are.
                    source: None,
                    carried: Carried::new(),
                },
                PlannedPackage {
                    name: "local-tool".to_string(),
                    // An epoch, whose colon the document carries verbatim.
                    version: "1:2.4-1".to_string(),
                    architecture: "all".to_string(),
                    sha256: "bb".repeat(32),
                    filename: "pool/main/l/local-tool/local-tool_2.4-1_all.deb".to_string(),
                    archive: 1,
                    // A package the archive states no size for, which Debian
                    // Policy permits.
                    installed_size: None,
                    source: Some("local-suite".to_string()),
                    carried: Carried::new(),
                },
            ],
            carried: Carried::new(),
        }
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
        let document = sample()
            .to_document()
            .unwrap()
            .replace("Suite: trixie\n", "Suite: trixie\nFuture-Header: h\n")
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
        for carried in ["Future-Header: h", "Future-Archive: a", "Future-Package: p"] {
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
    /// `Installed-Size` and `Source` joined them.
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
                    out.push_str(&line(name, value));
                }
            }
            for (name, value) in stanza
                .fields()
                .iter()
                .filter(|(name, _)| !known.iter().any(|known| known.eq_ignore_ascii_case(name)))
            {
                out.push_str(&line(name, value));
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn a_field_added_since_the_format_was_first_written_survives_an_older_reader() {
        // Why Installed-Size and Source are written after Archive rather than
        // beside the fields they describe. An older reader carries a field it
        // does not know and re-emits it after the ones it does, so a field
        // written between the older ones comes back from that reader with the
        // stanza's lines reordered -- and a record pinning the document's
        // digest reports a change to a plan that did not change. Written last,
        // the two renderings agree byte for byte.
        let document = sample().to_document().unwrap();
        assert!(document.contains("\nInstalled-Size: 340\n"), "{document}");
        assert!(document.contains("\nSource: local-suite\n"), "{document}");
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
        }
        let document = plan.to_document().unwrap();
        assert!(!document.contains("Installed-Size"), "{document}");
        assert!(!document.contains("Source"), "{document}");
        assert_eq!(Plan::parse_document(&document).unwrap(), plan);
    }

    #[test]
    fn a_malformed_installed_size_is_refused_rather_than_read_as_absent() {
        // Reading it as absent would drop the line on the way out, which is
        // the loss the carried fields exist to prevent.
        let document = sample()
            .to_document()
            .unwrap()
            .replace("Installed-Size: 340", "Installed-Size: 340 kB");
        match Plan::parse_document(&document) {
            Err(DebianError::PlanDocument { reason }) => {
                assert!(reason.contains("base-files"), "{reason}");
                assert!(reason.contains("kibibytes"), "{reason}");
            }
            other => panic!("expected a size refusal, got {other:?}"),
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
