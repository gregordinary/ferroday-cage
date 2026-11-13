//! The resolved install plan: the packages a bootstrap would install, and the
//! repository state it resolved them against, reported without downloading
//! anything.
//!
//! A plan is also a document. [`Plan::to_document`] writes it in the crate's
//! own field-and-stanza syntax and [`Plan::parse_document`] reads it back, so a
//! plan resolved on one machine can be committed, reviewed in a diff, and
//! replayed on another against a mirror that still serves those versions.
//!
//! The format is the Alpine layer's own, sharing only the syntax with the
//! Debian layer's: its fields describe an apk repository and its version
//! numbering is independent, so neither can be read as the other and neither
//! moves when the other does.

use std::borrow::Cow;
use std::collections::HashMap;

use super::AlpineError;
use super::index::{NOARCH, Record};
use super::version;
use crate::provision::digest::{Algorithm, Digest};
use crate::provision::document::{self, Carried, Draft};
use crate::provision::mirror_url;

/// The suffix every apk file carries.
const PACKAGE_SUFFIX: &str = ".apk";

/// The document's first field, naming the format and its version.
///
/// A document carries its own version because the plan is a trust anchor: a
/// reader that cannot tell which shape it is holding cannot say what it is
/// trusting. The version is bumped only for a change a previous reader would
/// misread; adding a field is not one, since a reader carries a field it does
/// not know through untouched rather than refusing the document or dropping it.
const FORMAT: &str = "ferroday-cage-alpine-plan 1";

/// The header fields this version writes and reads.
///
/// The three tables exist so that "a field this version does not know" has one
/// definition, used by both halves: the reader collects what is not here, and
/// the writer emits what is here and then what was collected. A field added to
/// a stanza has to be added to its table, or it would be both written as a
/// known field and carried as an unknown one.
const HEADER_FIELDS: &[&str] = &["Format", "Release", "Architecture"];
/// The index-stanza fields this version writes and reads.
const INDEX_FIELDS: &[&str] = &[
    "Index",
    "Mirror",
    "Release",
    "Component",
    "SHA256",
    "Signed-By",
    "Description",
];
/// The package-stanza fields this version writes and reads.
const PACKAGE_FIELDS: &[&str] = &[
    "Package",
    "Version",
    "Architecture",
    "Control-Identity",
    "Index",
    "Size",
    "Installed-Size",
    "Origin",
];

/// The packages an [`Alpine`](super::Alpine) bootstrap resolves for its release,
/// produced without downloading or unpacking anything.
///
/// Returned by [`Alpine::resolve`](super::Alpine::resolve). Every package's
/// control identity is repository-verified: it is read from an index whose own
/// signature was checked against the repository's keys, so a plan resolved from
/// a signed repository is anchored to that signature rather than to a mirror's
/// unverified word. The packages are ordered by name, so the plan is a stable
/// value to cache a build on or compare across runs.
///
/// [`indexes`](Self::indexes) records the state each package was resolved
/// against, which is what makes the plan a description of a moment in a
/// repository's life rather than only of a package set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Plan {
    /// The release the plan resolves against, as requested.
    pub release: String,
    /// The architecture the packages target.
    pub architecture: String,
    /// The resolved install set, ordered by name.
    pub packages: Vec<PlannedPackage>,
    /// The index each package was resolved against, in the order they were
    /// read: each repository's, component by component, the primary repository
    /// first.
    pub indexes: Vec<ResolvedIndex>,
    /// Header fields a document carried that this version does not know.
    ///
    /// Private because they are not this version's data to interpret; they
    /// exist so that reading a document and writing it back loses nothing. See
    /// [`Plan::parse_document`].
    carried: Carried,
}

/// One index's state at the moment a [`Plan`] resolved against it.
///
/// The unit here is the index rather than the repository, which is where this
/// departs from what a reader of the Debian layer might expect. An apk
/// repository publishes one index per component and a package is fetched from
/// the directory its own index sits in, so the index is both the thing whose
/// signature was verified and the thing a package's bytes are addressed
/// relative to. A repository configured with `main` and `community` therefore
/// contributes two of these.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedIndex {
    /// The mirror URL that served this index.
    ///
    /// The URL that answered, not the configured list: a repository with a
    /// backstop resolves against whichever mirror served, and recording the
    /// list would describe a choice rather than the choice made.
    ///
    /// This records where the index came from; it does not decide where the
    /// packages are fetched from. A bootstrap installing this plan walks the
    /// mirrors its repositories are configured with, so a plan carried to a
    /// different configuration fetches from that configuration's mirrors and
    /// still installs the packages this plan names, each held to the identity
    /// recorded here.
    pub mirror: String,
    /// The release, as the repository requested it.
    pub release: String,
    /// The component this index publishes, or `None` for a repository that
    /// publishes none — the `<release>/<architecture>` layout.
    pub component: Option<String>,
    /// The SHA-256 of the index container as it was fetched.
    ///
    /// The whole `APKINDEX.tar.gz`, signature segment included, so it
    /// identifies the exact bytes whose signature was checked. An apk
    /// repository publishes no signed release above its indexes, so this is the
    /// most an archive state can be pinned to. Always a SHA-256, taken of the
    /// container here rather than read from anywhere.
    pub sha256: Digest,
    /// The name of the key whose signature over this index verified.
    ///
    /// The name the repository publishes the key under, which is what the
    /// signature member itself carries — `alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub`.
    /// An index may carry more than one signature, one per key, which is what a
    /// key rotation looks like; this names the one that actually verified rather
    /// than the first the container happens to list.
    pub signed_by: String,
    /// The index's `DESCRIPTION` member, as written, when it carries one.
    ///
    /// A build string rather than a date or a validity window: Alpine writes
    /// `git describe` of the tree the index was built from, of the form
    /// `v3.23.5-111-g2a2e55ba802`, and postmarketOS an ISO timestamp. It is the
    /// only thing an index says about which publication it is, and it is *not*
    /// a freshness signal. An index Alpine signed is held to describe the
    /// release it was fetched as before it is read; what another publisher
    /// writes here is recorded and not read.
    pub description: Option<String>,
    /// Fields this index's stanza carried that this version does not know.
    ///
    /// Reachable within the layer so a live resolution can build the record as
    /// a struct literal, naming each field: the fields above sit in
    /// transposable runs of one type, and a positional constructor over them
    /// compiles either way round and writes a wrong plan document.
    pub(super) carried: Carried,
}

/// One package in a [`Plan`]: enough to identify the exact `.apk` and to key a
/// cache on it, carrying no dependency or download state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlannedPackage {
    /// The package name.
    pub name: String,
    /// The exact version that would be installed.
    pub version: String,
    /// The package's architecture: the target architecture, or `noarch`.
    pub architecture: String,
    /// The identity the index records for the package's control segment: `Q1`
    /// and the base64 of its SHA-1.
    ///
    /// This is what binds a downloaded package to the index that named it. A
    /// package's own signature says that some repository signed *a* package; it
    /// is this value, recomputed over what arrives, that says the package is the
    /// one that was asked for.
    pub control_identity: String,
    /// The size of the `.apk` on the wire in bytes, when the index states one.
    ///
    /// It bounds what the download may spend before its digest is checked. An
    /// index that states none leaves the download bounded by the fetcher's own
    /// ceiling, which is weaker rather than wrong.
    pub size: Option<u64>,
    /// The repository's estimate of the space this package occupies once
    /// installed, in bytes, when the index states one.
    ///
    /// An estimate, and reported as one: it is produced at package build time
    /// from the staged tree, is not measured against an installed filesystem,
    /// and does not account for the target's block size. A sum over a plan
    /// describes the repository's own accounting rather than what a built image
    /// will weigh.
    ///
    /// In bytes, which is the unit the index states it in — unlike Debian's
    /// `Installed-Size`, which is kibibytes.
    pub installed_size: Option<u64>,
    /// The source package this one was built from, when it differs from
    /// [`name`](Self::name).
    ///
    /// `None` means the source package carries the same name, which is the
    /// common case. Several binary packages of one source share this name,
    /// which is what makes it the key to attribute a plan's weight to the thing
    /// that was built rather than to each of its outputs.
    pub origin: Option<String>,
    /// Which of [`Plan::indexes`] this package's winning version came from, as
    /// an index into that list.
    ///
    /// Resolution is highest-version-wins across the merged repositories, so
    /// with more than one configured this is the only thing that says where a
    /// package will actually be fetched from — and an apk package is addressed
    /// relative to its own index's directory, so it is what says that even for a
    /// single repository with two components.
    pub index: usize,
    /// Fields this package's stanza carried that this version does not know.
    ///
    /// Reachable within the layer so a live resolution can build the record as
    /// a struct literal, naming each field: the fields above sit in
    /// transposable runs of one type, and a positional constructor over them
    /// compiles either way round and writes a wrong plan document.
    pub(super) carried: Carried,
}

impl ResolvedIndex {
    /// The directory this index's packages are addressed from under `mirror`,
    /// as a URL without a trailing slash.
    ///
    /// An apk package sits beside its own index, so the whole of a package's
    /// location is this and its file name — with the architecture between them,
    /// since a repository serves one directory per architecture.
    ///
    /// The mirror is supplied rather than taken from [`mirror`](Self::mirror),
    /// because a download walks the mirrors its repository is configured with
    /// and the recorded one names only where the index came from.
    pub(super) fn directory_under(&self, mirror: &str) -> String {
        match &self.component {
            Some(component) => mirror_url(mirror, &format!("{}/{component}", self.release)),
            None => mirror_url(mirror, &self.release),
        }
    }
}

impl PlannedPackage {
    /// The file name this package is published under.
    ///
    /// A repository names an apk file for the package and version it holds and
    /// nothing else, so the name follows from the plan rather than being
    /// recorded in it. It sits in the directory of the index that named the
    /// package, which [`index`](Self::index) identifies.
    ///
    /// The name and version are held to the index grammar before a plan is used
    /// — as a document is read, and again at
    /// [`build`](super::AlpineBuilder::build) — so this is one path segment and
    /// never a path.
    ///
    /// # Example
    ///
    /// ```
    /// # use ferroday_cage::provision::alpine::PlannedPackage;
    /// # fn show(package: &PlannedPackage) {
    /// assert_eq!(package.file_name(), "busybox-1.37.0-r30.apk");
    /// # }
    /// ```
    pub fn file_name(&self) -> String {
        format!("{}-{}{PACKAGE_SUFFIX}", self.name, self.version)
    }

    /// The name this package is kept under in a package cache, or `None` where
    /// its [`control_identity`](Self::control_identity) is not one.
    ///
    /// The [`file_name`](Self::file_name), with the SHA-1 the control identity
    /// names in hexadecimal before its suffix:
    /// `musl-1.2.5-r23.1b6c50426d3c0656e9c5a567a5a59601c7f4307a.apk`. A file
    /// name names a package
    /// and a version and nothing else, so two packages can share one: one
    /// architecture's build and another's, or an Alpine package and the
    /// postmarketOS republish of it at the same version. Under one name in a
    /// cache two runs share, each would replace the other's entry. The control
    /// identity is a digest of the control segment, whose `.PKGINFO` states the
    /// architecture and binds the file tree through `datahash`, so two packages
    /// differing in either are kept apart, and two copies of one package share an
    /// entry.
    ///
    /// The identity is held to its spelling before a plan is used, by
    /// [`unaddressable`](Self::unaddressable) or by the index reader, so `None`
    /// is a plan that reached a cache unchecked.
    pub(super) fn cache_name(&self) -> Option<String> {
        let digest = super::sign::identity_digest(&self.control_identity)?;
        Some(format!(
            "{}-{}.{}{PACKAGE_SUFFIX}",
            self.name,
            self.version,
            crate::provision::digest::hex(&digest),
        ))
    }

    /// Why this entry cannot be addressed, or `None` where it can.
    ///
    /// [`file_name`](Self::file_name) interpolates the name and the version and
    /// nothing else, and that file name becomes both a path segment of the URL
    /// the package is fetched from and the entry it is cached under. A name
    /// holding a separator or a `..` would therefore name a directory other than
    /// the cache, and the bytes would land there before the identity binding that
    /// rejects them ever runs. And [`control_identity`](Self::control_identity)
    /// is what the fetched control segment's is compared against, exactly, so
    /// one of any other shape can only ever mismatch.
    ///
    /// A package resolved from an index passed [`index::is_package_name`], the
    /// version grammar and [`index::is_control_identity`] on the way in, so this
    /// is the same gate for the way a plan arrives instead: a document a caller
    /// kept and may have edited, or a [`Plan`] taken from
    /// [`resolve`](super::Alpine::resolve) and modified, neither of which has an
    /// index behind it.
    ///
    /// [`index::is_package_name`]: super::index::is_package_name
    /// [`index::is_control_identity`]: super::index::is_control_identity
    pub(super) fn unaddressable(&self) -> Option<String> {
        if !super::index::is_package_name(&self.name) {
            return Some(format!(
                "the plan names {:?}, which is not a name a package can be addressed by",
                self.name,
            ));
        }
        if version::parse(&self.version).is_none() {
            return Some(format!(
                "the plan states {} at {:?}, which is not a version this format defines",
                self.name, self.version,
            ));
        }
        if !super::index::is_control_identity(&self.control_identity) {
            return Some(format!(
                "the plan states {} with the control identity {:?}, which is not a {} digest",
                self.name,
                self.control_identity,
                super::sign::IDENTITY_PREFIX,
            ));
        }
        None
    }

    /// Why this entry does not belong to a plan for `architecture`, or `None`
    /// where it does.
    ///
    /// A package is the plan's architecture or [`NOARCH`], which is all an index
    /// for that architecture publishes and all [`Index::merge`] keeps. The value
    /// becomes the package's `A:` in the installed database verbatim, so any
    /// other would record a package the root cannot hold.
    ///
    /// The refusal quotes both architectures, since `architecture` is the one a
    /// plan document states where its reader asks this, which nothing has held
    /// to an alphabet. It names the package bare, and is asked only once
    /// [`unaddressable`](Self::unaddressable) has admitted the name.
    ///
    /// [`Index::merge`]: super::index::Index::merge
    pub(super) fn foreign_to(&self, architecture: &str) -> Option<String> {
        (self.architecture != architecture && self.architecture != NOARCH).then(|| {
            format!(
                "the plan states {} for architecture {:?}, in a plan for {architecture:?}, and a \
                 package is the plan's architecture or {NOARCH}",
                self.name, self.architecture,
            )
        })
    }
}

impl Plan {
    /// Renders the plan as a document.
    ///
    /// The document is the plan and nothing else: one header stanza, one stanza
    /// per index in [`indexes`](Self::indexes) order, then one per package in
    /// [`packages`](Self::packages) order. Since both lists are already ordered,
    /// two renderings of one plan are byte-identical, and a plan that changes
    /// shows the change as a diff rather than as a different blob.
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use ferroday_cage::provision::alpine::Plan;
    ///
    /// // Resolve now, and keep what was resolved.
    /// # let plan: Plan = unimplemented!();
    /// std::fs::write("v3.23.plan", plan.to_document()?)?;
    ///
    /// // Replay later.
    /// let kept = Plan::parse_document(&std::fs::read_to_string("v3.23.plan")?)?;
    /// # let _ = kept;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`AlpineError::PlanDocument`] when a field's value cannot be written as a
    /// single line — one holding a newline, or one empty where the format has no
    /// way to say "empty" — or when a package names an index the plan does not
    /// carry. Both mean the plan holds something the format cannot carry back,
    /// which is worth refusing rather than writing a document that reads back as
    /// something else.
    pub fn to_document(&self) -> Result<String, AlpineError> {
        let mut out = String::new();
        let mut header = Draft::new();
        header.put("Format", FORMAT);
        header.put("Release", &self.release);
        header.put("Architecture", &self.architecture);
        header.put_carried(&self.carried);
        render(&header, &mut out)?;

        for (at, index) in self.indexes.iter().enumerate() {
            let mut stanza = Draft::new();
            stanza.put("Index", &at.to_string());
            stanza.put("Mirror", &index.mirror);
            stanza.put("Release", &index.release);
            // Absent rather than empty for the componentless layout, since a
            // repository that publishes no component and one that publishes an
            // unnamed one are not the same repository.
            stanza.put_optional("Component", index.component.as_deref());
            stanza.put("SHA256", index.sha256.hex());
            stanza.put("Signed-By", &index.signed_by);
            stanza.put_optional("Description", index.description.as_deref());
            stanza.put_carried(&index.carried);
            render(&stanza, &mut out)?;
        }

        for package in &self.packages {
            if package.index >= self.indexes.len() {
                return Err(plan_document(format!(
                    "the package {} names index {}, and the plan records {}",
                    package.name,
                    package.index,
                    self.indexes.len(),
                )));
            }
            let mut stanza = Draft::new();
            stanza.put("Package", &package.name);
            stanza.put("Version", &package.version);
            stanza.put("Architecture", &package.architecture);
            stanza.put("Control-Identity", &package.control_identity);
            stanza.put("Index", &package.index.to_string());
            // Anything added to this stanza in a later version belongs below
            // these, not beside the field it describes. A reader carries a field
            // it does not know and re-emits it after the ones it does, so a
            // field written between the older ones comes back from such a reader
            // with the stanza's lines reordered — and a record pinning the
            // document's digest reads that as the plan having changed.
            stanza.put_optional("Size", package.size.map(|size| size.to_string()).as_deref());
            stanza.put_optional(
                "Installed-Size",
                package
                    .installed_size
                    .map(|size| size.to_string())
                    .as_deref(),
            );
            stanza.put_optional("Origin", package.origin.as_deref());
            stanza.put_carried(&package.carried);
            render(&stanza, &mut out)?;
        }
        Ok(out)
    }

    /// Reads a plan back from a document [`to_document`](Self::to_document)
    /// wrote.
    ///
    /// A field the reader does not know is carried rather than refused, so a
    /// document written by a later version of this library still reads, and
    /// writing it back keeps what it carried. A stanza order other than header,
    /// indexes, packages is not: the index each package refers to is resolved as
    /// the document is read.
    ///
    /// # Errors
    ///
    /// [`AlpineError::PlanDocument`] for a document with no header, a format
    /// version this library does not read, a stanza missing a field the plan
    /// cannot do without, a malformed number, an index whose `SHA256` is not a
    /// SHA-256 in lowercase hex, a package naming an index the
    /// document does not carry, or a package an apk index for the plan's
    /// architecture could not have published. That last is a name or a version
    /// outside the format's grammar, a control identity of any shape but a
    /// `Q1` digest, or an architecture other than the plan's or `noarch`. It is
    /// the shape an index guarantees a resolved plan and a document guarantees
    /// nothing about: the name and version compose the file name a package is
    /// fetched and cached under, the identity is what the package is bound by,
    /// and the architecture is recorded in the root's installed database.
    pub fn parse_document(text: &str) -> Result<Plan, AlpineError> {
        let (header, rest) =
            document::header(document::parse(text), FORMAT).map_err(plan_document)?;
        let mut plan = Plan {
            release: required(header.get("Release"), "Release", "the header")?,
            architecture: required(header.get("Architecture"), "Architecture", "the header")?,
            packages: Vec::new(),
            indexes: Vec::new(),
            carried: document::carried(&header, HEADER_FIELDS),
        };

        for stanza in rest {
            if let Some(name) = stanza.get("Package") {
                // Quoted until `unaddressable` below has admitted the name.
                let at_package = format!("the package {name:?}");
                let at = number::<usize>(stanza.get("Index"), "Index", &at_package)?
                    .ok_or_else(|| plan_document(format!("{at_package} names no index")))?;
                if at >= plan.indexes.len() {
                    return Err(plan_document(format!(
                        "{at_package} names index {at}, which the document does not carry — \
                         index stanzas must precede the packages that refer to them",
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
                    control_identity: required(
                        stanza.get("Control-Identity"),
                        "Control-Identity",
                        &at_package,
                    )?,
                    index: at,
                    size: number(stanza.get("Size"), "Size", &at_package)?,
                    installed_size: number(
                        stanza.get("Installed-Size"),
                        "Installed-Size",
                        &at_package,
                    )?,
                    origin: stanza.get("Origin").map(Cow::into_owned),
                    carried: document::carried(&stanza, PACKAGE_FIELDS),
                };
                // The document is the only thing behind a plan read this way, so
                // the shape an index would have guaranteed is checked here.
                if let Some(reason) = package
                    .unaddressable()
                    .or_else(|| package.foreign_to(&plan.architecture))
                {
                    return Err(plan_document(reason));
                }
                plan.packages.push(package);
                continue;
            }

            let at = stanza.get("Index").ok_or_else(|| {
                plan_document("a stanza is neither a package nor an index".to_string())
            })?;
            // The number is written out so the document reads on its own, and
            // checked rather than trusted: a document whose indexes are out of
            // order would silently attribute packages to the wrong mirror. It is
            // held to the spelling the writer gives it, as every number is.
            let expected = plan.indexes.len();
            if at != expected.to_string() {
                return Err(plan_document(format!(
                    "the index stanzas are numbered out of order: expected {expected}, found \
                     {at:?}",
                )));
            }
            let at_index = format!("index {expected}");
            plan.indexes.push(ResolvedIndex {
                mirror: required(stanza.get("Mirror"), "Mirror", &at_index)?,
                release: required(stanza.get("Release"), "Release", &at_index)?,
                component: stanza.get("Component").map(Cow::into_owned),
                sha256: {
                    let value = required(stanza.get("SHA256"), "SHA256", &at_index)?;
                    Digest::new(Algorithm::Sha256, &value).ok_or_else(|| {
                        plan_document(format!(
                            "{at_index} states the SHA256 {value:?}, which is not a SHA-256 \
                             digest in lowercase hex"
                        ))
                    })?
                },
                signed_by: required(stanza.get("Signed-By"), "Signed-By", &at_index)?,
                description: stanza.get("Description").map(Cow::into_owned),
                carried: document::carried(&stanza, INDEX_FIELDS),
            });
        }
        Ok(plan)
    }

    /// The first package this plan names twice, as its two entries, or `None`
    /// where every name appears once.
    ///
    /// A root holds one package of a name, and everything that reads a plan
    /// keys it by name: a pin holds each name to one version, and an install
    /// writes one installed record and one set of scripts per name. So two
    /// entries for one name are a plan with no single reading, whether or not
    /// they agree. A plan this library resolved cannot contain one; a
    /// hand-written document or an edited `Plan` can.
    pub(super) fn named_twice(&self) -> Option<(&PlannedPackage, &PlannedPackage)> {
        let mut seen: HashMap<&str, &PlannedPackage> = HashMap::with_capacity(self.packages.len());
        self.packages.iter().find_map(|package| {
            seen.insert(&package.name, package)
                .map(|first| (first, package))
        })
    }

    /// Builds a plan from a resolved package set, projecting each record onto
    /// the public shape.
    pub(super) fn project(
        release: &str,
        architecture: &str,
        packages: &[Record],
        indexes: &[ResolvedIndex],
    ) -> Plan {
        Plan {
            release: release.to_string(),
            architecture: architecture.to_string(),
            packages: packages
                .iter()
                .map(|record| {
                    PlannedPackage {
                        name: record.name.clone(),
                        version: record.version.clone(),
                        architecture: record.architecture.clone(),
                        control_identity: record.control_identity.clone(),
                        size: record.size,
                        installed_size: record.installed_size,
                        origin: record.origin.clone(),
                        // The merge tags each retained record with the index it
                        // was read from, which is exactly this list's ordering.
                        index: record.from,
                        carried: Carried::new(),
                    }
                })
                .collect(),
            indexes: indexes.to_vec(),
            carried: Carried::new(),
        }
    }
}

/// Writes one stanza, reporting a refusal as this layer's document failure.
///
/// The rule is [`Draft::render`]'s and is shared with every other layer; only
/// whose document the refusal is about belongs here.
fn render(stanza: &Draft, out: &mut String) -> Result<(), AlpineError> {
    stanza.render(out).map_err(plan_document)
}

/// Reads a required field, reporting a refusal the same way.
fn required(value: Option<Cow<'_, str>>, field: &str, at: &str) -> Result<String, AlpineError> {
    document::required(value.as_deref(), field, at).map_err(plan_document)
}

/// Reads an optional numeric field, reporting a refusal the same way.
///
/// The rule is [`document::number`]'s.
fn number<T: std::str::FromStr + std::fmt::Display>(
    value: Option<Cow<'_, str>>,
    field: &str,
    at: &str,
) -> Result<Option<T>, AlpineError> {
    document::number(value.as_deref(), field, at).map_err(plan_document)
}

/// Builds the document error.
fn plan_document(reason: String) -> AlpineError {
    AlpineError::PlanDocument { reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plan with two indexes -- one with a component and one without -- and a
    /// package from each, one of them stating neither optional size.
    fn sample() -> Plan {
        Plan {
            release: "v3.23".to_string(),
            architecture: "x86_64".to_string(),
            indexes: vec![
                ResolvedIndex {
                    mirror: "http://dl-cdn.alpinelinux.org/alpine".to_string(),
                    release: "v3.23".to_string(),
                    component: Some("main".to_string()),
                    sha256: Digest::new(Algorithm::Sha256, &"9f3a".repeat(16)).unwrap(),
                    signed_by: "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub".to_string(),
                    description: Some("v3.23.5-111-g2a2e55ba802".to_string()),
                    carried: Carried::new(),
                },
                // postmarketOS's shape: no component, and a timestamp where
                // Alpine writes a build string.
                ResolvedIndex {
                    mirror: "http://mirror.postmarketos.org/postmarketos".to_string(),
                    release: "v26.06".to_string(),
                    component: None,
                    sha256: Digest::new(Algorithm::Sha256, &"1c0f".repeat(16)).unwrap(),
                    signed_by: "build.postmarketos.org.rsa.pub".to_string(),
                    description: None,
                    carried: Carried::new(),
                },
            ],
            packages: vec![
                PlannedPackage {
                    name: "busybox".to_string(),
                    version: "1.37.0-r30".to_string(),
                    architecture: "x86_64".to_string(),
                    control_identity: "Q18TR4AbuWsapA0X+CI3w/T/AqRyU=".to_string(),
                    size: Some(504_726),
                    installed_size: Some(813_480),
                    origin: None,
                    index: 0,
                    carried: Carried::new(),
                },
                PlannedPackage {
                    name: "postmarketos-baselayout".to_string(),
                    version: "1.0-r0".to_string(),
                    // A package belonging to every architecture the repository
                    // serves.
                    architecture: "noarch".to_string(),
                    control_identity: "Q1LSohzMjVRmn08215M0mwFPRtsg8=".to_string(),
                    size: None,
                    installed_size: None,
                    origin: Some("postmarketos-base".to_string()),
                    index: 1,
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
    /// from an empty one, and where the blank lines fall. A change to any of
    /// those is a change to the format, and the format carries a version because
    /// a reader that cannot tell which shape it is holding cannot say what it is
    /// trusting — so this failing is the prompt to decide whether that version
    /// has to move.
    const GOLDEN: &str = "\
Format: ferroday-cage-alpine-plan 1
Release: v3.23
Architecture: x86_64

Index: 0
Mirror: http://dl-cdn.alpinelinux.org/alpine
Release: v3.23
Component: main
SHA256: 9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a
Signed-By: alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub
Description: v3.23.5-111-g2a2e55ba802

Index: 1
Mirror: http://mirror.postmarketos.org/postmarketos
Release: v26.06
SHA256: 1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f
Signed-By: build.postmarketos.org.rsa.pub

Package: busybox
Version: 1.37.0-r30
Architecture: x86_64
Control-Identity: Q18TR4AbuWsapA0X+CI3w/T/AqRyU=
Index: 0
Size: 504726
Installed-Size: 813480

Package: postmarketos-baselayout
Version: 1.0-r0
Architecture: noarch
Control-Identity: Q1LSohzMjVRmn08215M0mwFPRtsg8=
Index: 1
Origin: postmarketos-base

";

    #[test]
    fn the_document_is_the_format_this_version_writes() {
        assert_eq!(sample().to_document().expect("the plan renders"), GOLDEN);
        // And it reads back as the plan it came from, so the literal above is a
        // document rather than only a string that happens to match.
        assert_eq!(
            Plan::parse_document(GOLDEN).expect("the golden reads"),
            sample(),
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
    fn the_document_is_a_readable_field_and_stanza_document() {
        let document = sample().to_document().unwrap();
        assert!(
            document.starts_with("Format: ferroday-cage-alpine-plan 1\n"),
            "{document}",
        );
        for line in document.lines() {
            assert!(
                line.is_empty() || line.contains(": ") || line.ends_with(':'),
                "{line:?} is neither blank nor a field",
            );
            assert!(!line.starts_with(' '), "{line:?} reads as a continuation");
            assert_eq!(line.trim_end(), line, "{line:?} ends in whitespace");
        }
        // The absent optional fields are absent, not empty: an index that
        // publishes no component and one that publishes an unnamed one are not
        // the same index.
        assert!(!document.contains("Component:\n"), "{document}");
        assert!(!document.contains("Size:\n"), "{document}");
    }

    // Needs the Debian layer beside this one, which an Alpine build alone
    // does not have.
    #[cfg(feature = "debian")]
    #[test]
    fn the_alpine_format_and_the_debian_one_cannot_be_read_as_each_other() {
        // Two independent formats, and the reason each document names its own:
        // the fields describe different archives, and a reader that took one for
        // the other would report a plan that was never resolved.
        let debian = crate::provision::debian::Plan::parse_document(
            "Format: ferroday-cage-plan 2\nSuite: trixie\nArchitecture: amd64\n\n",
        )
        .expect("a Debian plan reads there");
        assert!(
            Plan::parse_document(&debian.to_document().unwrap()).is_err(),
            "a Debian plan is not an Alpine one",
        );
        assert!(
            crate::provision::debian::Plan::parse_document(&sample().to_document().unwrap())
                .is_err(),
            "and an Alpine plan is not a Debian one",
        );
    }

    #[test]
    fn a_document_from_a_format_this_library_does_not_read_is_refused() {
        for version in ["ferroday-cage-alpine-plan 0", "ferroday-cage-alpine-plan 2"] {
            let document = sample()
                .to_document()
                .unwrap()
                .replace("ferroday-cage-alpine-plan 1", version);
            match Plan::parse_document(&document) {
                Err(AlpineError::PlanDocument { reason }) => {
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
        // but the format version unchanged, both reads *and writes back*. A
        // consumer that reads a plan and writes it back would otherwise silently
        // discard whatever the newer writer had added.
        let document = sample()
            .to_document()
            .unwrap()
            .replace(
                "Release: v3.23\nArchitecture",
                "Release: v3.23\nFuture-Header: h\nArchitecture",
            )
            .replace(
                "Mirror: http://dl-cdn.alpinelinux.org/alpine\n",
                "Mirror: http://dl-cdn.alpinelinux.org/alpine\nFuture-Index: i\n",
            )
            .replace(
                "Package: busybox\n",
                "Package: busybox\nFuture-Package: p\n",
            );

        let plan = Plan::parse_document(&document).expect("a newer document reads");
        let rewritten = plan.to_document().expect("and writes back");
        for carried in ["Future-Header: h", "Future-Index: i", "Future-Package: p"] {
            assert!(
                rewritten.contains(carried),
                "{carried} was dropped:\n{rewritten}",
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
    fn a_package_naming_an_index_the_document_does_not_carry_is_refused() {
        // Silently attributing a package to the wrong mirror is the failure this
        // prevents, and it is exactly what a plan is kept to avoid.
        let document = sample().to_document().unwrap().replace(
            "Control-Identity: Q18TR4AbuWsapA0X+CI3w/T/AqRyU=\nIndex: 0",
            "Control-Identity: Q18TR4AbuWsapA0X+CI3w/T/AqRyU=\nIndex: 7",
        );
        match Plan::parse_document(&document) {
            Err(AlpineError::PlanDocument { reason }) => {
                assert!(reason.contains("index 7"), "{reason}");
            }
            other => panic!("expected an index refusal, got {other:?}"),
        }
    }

    #[test]
    fn what_a_document_states_reaches_a_refusal_with_its_control_characters_escaped() {
        // Nothing holds a document's header to an alphabet, and nothing holds a
        // package's name to one until the reader has asked, so each refusal
        // naming either before then quotes it.
        let hostile = crate::failure::hostile::TEXT;
        let document = sample().to_document().unwrap();
        let misnamed = document
            .replace("Package: busybox", &format!("Package: {hostile}"))
            .replace(
                "Control-Identity: Q18TR4AbuWsapA0X+CI3w/T/AqRyU=\nIndex: 0",
                "Control-Identity: Q18TR4AbuWsapA0X+CI3w/T/AqRyU=\nIndex: 7",
            );
        let foreign = document.replacen(
            "Architecture: x86_64",
            &format!("Architecture: {hostile}"),
            1,
        );
        for (refused, says) in [(misnamed, "index 7"), (foreign, "in a plan for")] {
            match Plan::parse_document(&refused) {
                Err(AlpineError::PlanDocument { reason }) => {
                    assert!(reason.contains(says), "{reason}");
                    crate::failure::hostile::assert_escaped(&reason);
                }
                other => panic!("expected a refusal saying {says:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn index_stanzas_numbered_out_of_order_are_refused() {
        let document = sample().to_document().unwrap().replace(
            "Index: 1\nMirror: http://mirror.postmarketos.org/postmarketos",
            "Index: 5\nMirror: http://mirror.postmarketos.org/postmarketos",
        );
        match Plan::parse_document(&document) {
            Err(AlpineError::PlanDocument { reason }) => {
                assert!(reason.contains("out of order"), "{reason}");
            }
            other => panic!("expected an ordering refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_required_field_names_the_stanza_it_is_missing_from() {
        let document = sample()
            .to_document()
            .unwrap()
            .replace("Control-Identity: Q18TR4", "Was-Here: Q18TR4");
        match Plan::parse_document(&document) {
            Err(AlpineError::PlanDocument { reason }) => {
                assert!(reason.contains("busybox"), "{reason}");
                assert!(reason.contains("Control-Identity"), "{reason}");
            }
            other => panic!("expected a missing-field refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_size_is_refused_rather_than_read_as_absent() {
        // Reading it as absent would drop the line on the way out, which is the
        // loss the carried fields exist to prevent.
        let document = sample()
            .to_document()
            .unwrap()
            .replace("Size: 504726", "Size: 504 kB");
        match Plan::parse_document(&document) {
            Err(AlpineError::PlanDocument { reason }) => {
                assert!(reason.contains("busybox"), "{reason}");
                assert!(reason.contains("not a number"), "{reason}");
            }
            other => panic!("expected a size refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_index_digest_in_another_shape_is_refused_rather_than_carried() {
        // The digest is a `Digest`, which only its algorithm's lowercase hex
        // makes; the refusal quotes the value, since nothing has admitted it.
        let hostile = crate::failure::hostile::TEXT;
        for written in ["9F3A".repeat(16), "9f3a".repeat(15), hostile.to_string()] {
            let document = sample()
                .to_document()
                .unwrap()
                .replace(&"9f3a".repeat(16), &written);
            match Plan::parse_document(&document) {
                Err(AlpineError::PlanDocument { reason }) => {
                    assert!(reason.contains("index 0"), "{reason}");
                    assert!(reason.contains("not a SHA-256"), "{reason}");
                    if written == hostile {
                        crate::failure::hostile::assert_escaped(&reason);
                    }
                }
                other => panic!("expected a digest refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_value_the_format_cannot_carry_refuses_the_whole_document() {
        // A hostile mirror can fold a value across lines, and a document that
        // wrote it out would read back as a different plan.
        let mut plan = sample();
        plan.packages[0].name = "busybox\nIndex: 1".to_string();
        match plan.to_document() {
            Err(AlpineError::PlanDocument { reason }) => {
                assert!(reason.contains("more than one line"), "{reason}");
            }
            other => panic!("expected a rendering refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_document_is_refused_rather_than_read_as_an_empty_plan() {
        assert!(matches!(
            Plan::parse_document(""),
            Err(AlpineError::PlanDocument { .. }),
        ));
        assert!(matches!(
            Plan::parse_document("Release: v3.23\nArchitecture: x86_64\n"),
            Err(AlpineError::PlanDocument { .. }),
        ));
    }

    #[test]
    fn a_package_name_that_is_not_one_is_refused() {
        // The name composes the file the package is fetched to and cached
        // under, so a name that is a path names a directory other than the
        // cache — and the bytes would land there before the identity binding
        // that rejects them ever runs. A resolved plan passes the index's own
        // gate on the way in; a document has no index behind it.
        for name in [
            "/etc/cron.d/x",
            "../../foo",
            "..",
            "foo/bar",
            "foo bar",
            "-leading-dash",
            "foo?query",
        ] {
            let document = sample()
                .to_document()
                .unwrap()
                .replace("Package: busybox", &format!("Package: {name}"));
            match Plan::parse_document(&document) {
                Err(AlpineError::PlanDocument { reason }) => {
                    assert!(reason.contains("addressed by"), "{name:?}: {reason}");
                }
                other => panic!("expected a name refusal for {name:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_version_that_is_not_one_is_refused() {
        // The other half of the file name, and the same reasoning: `..` is a
        // version the grammar does not define, and it is also a directory.
        for version in ["..", "1.0-r0/../..", "not a version", "1.0-r0+"] {
            let document = sample()
                .to_document()
                .unwrap()
                .replace("Version: 1.37.0-r30", &format!("Version: {version}"));
            match Plan::parse_document(&document) {
                Err(AlpineError::PlanDocument { reason }) => {
                    assert!(reason.contains("not a version"), "{version:?}: {reason}");
                }
                other => panic!("expected a version refusal for {version:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_package_of_another_architecture_is_refused() {
        // The value becomes the installed database's `A:` verbatim, and an
        // index for the plan's architecture publishes nothing but that
        // architecture and `noarch`, which the sample already holds.
        for architecture in ["aarch64", "x86", "noarch2", "X86_64"] {
            let document = sample().to_document().unwrap().replacen(
                "Architecture: x86_64\nControl-Identity",
                &format!("Architecture: {architecture}\nControl-Identity"),
                1,
            );
            match Plan::parse_document(&document) {
                Err(AlpineError::PlanDocument { reason }) => {
                    assert!(reason.contains("busybox"), "{architecture:?}: {reason}");
                    assert!(reason.contains("noarch"), "{architecture:?}: {reason}");
                    // One sentence, spaced as one: a refusal is read by a
                    // person, and the line it is split over in the source is
                    // not part of it.
                    assert!(
                        reason.contains(", and a package is the plan's architecture"),
                        "{architecture:?}: {reason}",
                    );
                }
                other => {
                    panic!("expected an architecture refusal for {architecture:?}, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn a_control_identity_that_is_not_one_is_refused() {
        // The identity is compared exactly against the one recomputed over what
        // arrives, so any other shape could only ever mismatch, after a download.
        let valid = "Q18TR4AbuWsapA0X+CI3w/T/AqRyU=";
        for identity in [
            "",
            "Q1",
            "Q28TR4AbuWsapA0X+CI3w/T/AqRyU=",
            "Q18TR4AbuWsapA0X+CI3w/T/AqRyU",
            "Q18TR4AbuWsapA0X+CI3w/T/AqRy!=",
            "8TR4AbuWsapA0X+CI3w/T/AqRyU=",
        ] {
            let document = sample().to_document().unwrap().replace(
                &format!("Control-Identity: {valid}"),
                &format!("Control-Identity: {identity}"),
            );
            match Plan::parse_document(&document) {
                Err(AlpineError::PlanDocument { reason }) => {
                    assert!(reason.contains("busybox"), "{identity:?}: {reason}");
                }
                other => panic!("expected an identity refusal for {identity:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_package_is_named_for_the_version_the_plan_holds() {
        let plan = sample();
        assert_eq!(plan.packages[0].file_name(), "busybox-1.37.0-r30.apk");
        assert_eq!(
            plan.packages[1].file_name(),
            "postmarketos-baselayout-1.0-r0.apk",
        );
    }

    #[test]
    fn a_cached_package_is_named_for_its_control_identity_as_well() {
        let busybox = sample().packages.remove(0);
        assert_eq!(
            busybox.cache_name().as_deref(),
            Some("busybox-1.37.0-r30.f1347801bb96b1aa40d17f82237c3f4ff02a4725.apk"),
        );
        // Another build of the same package and version, such as another
        // architecture's or a republish, shares the file name and not the entry.
        let mut other = busybox.clone();
        other.control_identity = super::super::sign::identity_for_test("another build");
        assert_eq!(other.file_name(), busybox.file_name());
        assert_ne!(other.cache_name(), busybox.cache_name());
        // An identity that is not one names no entry.
        other.control_identity = "Q1".to_string();
        assert_eq!(other.cache_name(), None);
    }
}
