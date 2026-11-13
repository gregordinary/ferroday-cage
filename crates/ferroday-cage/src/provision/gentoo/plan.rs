//! The resolved install plan: which builds a run would merge, in what order,
//! reported without downloading anything.
//!
//! A plan is also a document. [`Plan::to_document`] writes it in the crate's
//! own field-and-stanza syntax and [`Plan::parse_document`] reads it back, so a
//! plan resolved on one machine can be committed, reviewed in a diff, and
//! replayed on another.
//!
//! This is the one thing the stage3 half of the layer deliberately does not
//! have. A single tarball needs no versioned serialization, and a document
//! naming a build id would outlive what it describes — the autobuilds tree
//! keeps about five weeks. A binary-package plan is the opposite: the binhost
//! keeps a version far longer than that, and the plan is the reproducibility
//! story for a root built from binaries.
//!
//! A plan is not a signed document and does not outlive the key that signs the
//! containers it names. Each container's `Manifest` is verified when the plan
//! is installed, at the current time, so a plan stops replaying when that key
//! lapses, as it does when the binhost drops a build it names.
//!
//! # A plan records what the resolution read
//!
//! Each package's stanza names the container, and states what the index said
//! about the build: its slot, USE flags, dependencies and build time. Nothing
//! signs the index, and those are what the resolution decided from. The
//! container's signed metadata is held to them when it is installed, so a
//! replay installs the resolution the plan records or refuses.
//!
//! The format is the Gentoo layer's own, sharing only the syntax with the
//! Debian and Alpine layers'. Its fields describe a binhost and its version
//! numbering is independent, so neither can be read as the other and neither
//! moves when the other does.
//!
//! # The stanza order is the install order
//!
//! Unlike the other two layers' plans, whose packages are sorted by name, this
//! one's are in the order they merge. That order is a resolution's own output —
//! a topological sort over runtime dependencies, with a stable rule where the
//! graph has a cycle — and a plan that lost it would have to derive it again
//! from an index the plan exists to avoid needing.
//!
//! The order is deterministic, so two renderings of one plan are byte-identical
//! and a plan that changes shows the change as a diff.

use std::borrow::Cow;

use super::index::{self, Record};
use super::{GentooError, atom, version};
use crate::provision::coordinate::{self, Nesting};
use crate::provision::digest::Algorithm;
use crate::provision::document::{self, Carried, Draft};

/// The document's first field, naming the format and its version.
///
/// A document carries its own version because the plan is a trust anchor: a
/// reader that cannot tell which shape it is holding cannot say what it is
/// trusting. The version is bumped only for a change a previous reader would
/// misread; adding a field is not one, since a reader carries a field it does
/// not know through untouched rather than refusing the document or dropping it.
///
/// Adding a field every document must carry is one, from the other side, and
/// version 2 is what one required. A package stanza states the slot and the
/// build time the index gave, and a container is held to both. A version 1
/// document states neither, so it is refused for its format, which names what
/// is wrong, rather than for the first field it happens to lack.
const FORMAT: &str = "ferroday-cage-gentoo-plan 2";

/// The header fields this version writes and reads.
///
/// The two tables exist so that "a field this version does not know" has one
/// definition, used by both halves: the reader collects what is not here, and
/// the writer emits what is here and then what was collected. A field added to
/// a stanza has to be added to its table, or it would be both written as a
/// known field and carried as an unknown one.
const HEADER_FIELDS: &[&str] = &["Format", "Architecture", "Binhost", "Index-Timestamp"];

/// The package-stanza fields this version writes and reads.
const PACKAGE_FIELDS: &[&str] = &[
    "Package",
    "Version",
    "Build-Id",
    "Path",
    "Size",
    "MD5",
    "Slot",
    "Use",
    "Iuse",
    "Rdepend",
    "Pdepend",
    "Build-Time",
];

/// What a [`Gentoo`](super::Gentoo) run would install from the binhost, and in
/// what order.
///
/// Returned by [`Gentoo::resolve_packages`](super::Gentoo::resolve_packages)
/// and taken back by [`GentooBuilder::plan`](super::GentooBuilder::plan), which
/// installs what it names and resolves nothing. A replay is held to the root it
/// installs into: a package that root already has at the planned version is
/// skipped, and one whose slot it already holds, or whose dependencies neither
/// it nor the plan answers, is refused.
///
/// Every package is index-resolved: it names a container the archive published,
/// with the size that bounds its download, the container's MD5, and what the
/// index stated about the build that the resolution acted on. None of that is
/// what makes the package trustworthy. Each container carries a
/// cleartext-signed `Manifest` of its own, verified as it is opened, and its
/// signed metadata is then held to these fields: the package and build they
/// name, and everything the resolution read from the index about it. A
/// container that disagrees with its plan entry is refused, so a plan replays
/// as the resolution it records or not at all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Plan {
    /// The architecture the packages target, as requested.
    pub architecture: String,
    /// The binhost sub-architecture they came from.
    pub binhost: String,
    /// The epoch the index stated it was generated at, where it stated one.
    ///
    /// Provenance and nothing else. Nothing signs the index, so this records
    /// which publication a resolution happened against as the mirror described
    /// it, and no check rests on it.
    pub index_timestamp: Option<i64>,
    /// The packages, in the order they merge.
    pub packages: Vec<PlannedPackage>,
    /// Header fields a document carried that this version does not know.
    ///
    /// Private because they are not this version's data to interpret; they
    /// exist so that reading a document and writing it back loses nothing. See
    /// [`Plan::parse_document`].
    carried: Carried,
}

/// One package in a [`Plan`]: which build, where it sits, and what it weighs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlannedPackage {
    /// The package, as `category/name`.
    pub name: String,
    /// The exact version that would be installed.
    pub version: String,
    /// Which build of that version, from the index's `BUILD_ID`.
    ///
    /// The archive publishes a version more than once, the builds differing in
    /// the USE flags they were compiled with and so in what they depend on. A
    /// plan that named only the version would replay as a different closure.
    pub build_id: u64,
    /// The container's path under the binhost directory, from the index's
    /// `PATH`.
    pub path: String,
    /// The container's length in bytes, which bounds its download.
    pub size: u64,
    /// The MD5 the index records for the container, lowercase hex.
    ///
    /// The container's MD5 is held to it, as portage holds a downloaded binary
    /// package to its index's digests, and is what a merged package's
    /// `BINPKGMD5` records. It pins the plan to the exact container the
    /// resolution named. It is not what makes the container trustworthy: that
    /// is the cleartext-signed `Manifest` inside it, over SHA-512.
    pub md5: String,
    /// The slot the index states for the build, `slot` or `slot/subslot`.
    ///
    /// This field and the five after it are what the resolution read from the
    /// index about the build, which nothing signs. The container's own signed
    /// metadata is held to each of them before anything of it is merged.
    pub slot: String,
    /// The USE flags the index states the build was compiled with,
    /// space-separated.
    pub use_flags: String,
    /// The flags the index states the package knows, space-separated, each
    /// possibly carrying the `+` or `-` that states the ebuild's own default.
    pub iuse: String,
    /// The runtime dependencies the index states, as it writes them.
    pub rdepend: String,
    /// The post-merge dependencies the index states, as it writes them.
    pub pdepend: String,
    /// When the index states the build was made, in seconds since the epoch,
    /// or zero where it states nothing.
    pub build_time: i64,
    /// Fields this package's stanza carried that this version does not know.
    carried: Carried,
}

impl PlannedPackage {
    /// Records one package as a live resolution selected it.
    ///
    /// A constructor rather than a struct literal because the carried-field
    /// list is private: a package selected from an index has no document behind
    /// it to carry anything from.
    fn resolved(record: &Record) -> PlannedPackage {
        PlannedPackage {
            name: record.name().to_string(),
            version: record.version().to_string(),
            build_id: record.build_id,
            path: record.path().to_string(),
            size: record.size,
            md5: record.md5().to_string(),
            slot: record.slot().to_string(),
            use_flags: record.use_flags().to_string(),
            iuse: record.iuse().to_string(),
            rdepend: record.rdepend().to_string(),
            pdepend: record.pdepend().to_string(),
            build_time: record.build_time,
            carried: Carried::new(),
        }
    }

    /// Why this entry cannot be acted on, or `None` where it can.
    ///
    /// A package resolved from an index passed the atom grammar, the version
    /// grammar and [`coordinate::check`] on the way in. This is the same gate
    /// for the way a plan arrives instead: a document a caller kept and may
    /// have edited, which has no index behind it at all.
    ///
    /// The path is the one that matters. It becomes directory segments of the
    /// URL the container is fetched from and of the entry it is cached under,
    /// and the bytes land there before the signed `Manifest` inside them is
    /// ever read.
    pub(super) fn unusable(&self) -> Option<String> {
        // First, so nothing below parses a field longer than an index record
        // may state it, and a refusal naming the package names a bounded one.
        if let Some((field, length, max)) = index::overlong(
            self.name.len() + 1 + self.version.len(),
            &self.slot,
            &self.use_flags,
            &self.iuse,
            &self.path,
        ) {
            return Some(match field {
                "CPV" => format!(
                    "the plan names a package and version {length} bytes long, past the {max} \
                     an index record may state",
                ),
                _ => format!(
                    "the plan states {length} bytes of {field} for {}, past the {max} an index \
                     record may state",
                    self.name,
                ),
            });
        }
        if !atom::is_package(&self.name) {
            return Some(format!(
                "the plan names {:?}, which is not a package a binhost can publish",
                self.name,
            ));
        }
        if version::parse(&self.version).is_none() {
            return Some(format!(
                "the plan states {} at {:?}, which is not a version this format defines",
                self.name, self.version,
            ));
        }
        if let Err(reason) =
            coordinate::check("the plan's package path", &self.path, Nesting::Nested)
        {
            return Some(reason);
        }
        if !Algorithm::Md5.is_hex(&self.md5) {
            return Some(format!(
                "the plan states an MD5 of {:?} for {}, which is not one this format writes",
                self.md5, self.name,
            ));
        }
        if self.slot.is_empty() {
            return Some(format!("the plan states no slot for {}", self.name));
        }
        // Held to the rule the index reader holds a record's dependency classes
        // to, since a plan states them where an index would have.
        for (class, text) in [("runtime", &self.rdepend), ("post-merge", &self.pdepend)] {
            if let Err(reason) = index::read_class(text) {
                return Some(format!(
                    "the plan states {class} dependencies for {} that cannot be read: {reason}",
                    self.name,
                ));
            }
        }
        None
    }
}

impl Plan {
    /// Builds a plan from a resolved package set, in the order it resolved
    /// them.
    pub(super) fn project(
        architecture: &str,
        binhost: &str,
        index_timestamp: Option<i64>,
        packages: &[Record],
    ) -> Plan {
        Plan {
            architecture: architecture.to_string(),
            binhost: binhost.to_string(),
            index_timestamp,
            packages: packages.iter().map(PlannedPackage::resolved).collect(),
            carried: Carried::new(),
        }
    }

    /// Renders the plan as a document.
    ///
    /// One header stanza and one stanza per package, in install order. Two
    /// renderings of one plan are byte-identical, so a plan that changes shows
    /// the change as a diff rather than as a different blob.
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use ferroday_cage::provision::gentoo::Plan;
    ///
    /// // Resolve now, and keep what was resolved.
    /// # let plan: Plan = unimplemented!();
    /// std::fs::write("binhost.plan", plan.to_document()?)?;
    ///
    /// // Replay later.
    /// let kept = Plan::parse_document(&std::fs::read_to_string("binhost.plan")?)?;
    /// # let _ = kept;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`GentooError::PlanDocument`] when a field's value cannot be written as
    /// a single line and read back as itself. That means the plan holds
    /// something the format cannot carry, which is worth refusing rather than
    /// writing a document that reads back as something else.
    pub fn to_document(&self) -> Result<String, GentooError> {
        let mut out = String::new();
        let mut header = Draft::new();
        header.put("Format", FORMAT);
        header.put("Architecture", &self.architecture);
        header.put("Binhost", &self.binhost);
        header.put_optional(
            "Index-Timestamp",
            self.index_timestamp.map(|at| at.to_string()).as_deref(),
        );
        header.put_carried(&self.carried);
        render(&header, &mut out)?;

        for package in &self.packages {
            let mut stanza = Draft::new();
            stanza.put("Package", &package.name);
            stanza.put("Version", &package.version);
            stanza.put("Build-Id", &package.build_id.to_string());
            stanza.put("Path", &package.path);
            // Anything added to this stanza in a later version belongs below
            // these, not beside the field it describes. A reader carries a
            // field it does not know and re-emits it after the ones it does, so
            // a field written between the older ones comes back from such a
            // reader with the stanza's lines reordered -- and a record pinning
            // the document's digest reads that as the plan having changed.
            stanza.put("Size", &package.size.to_string());
            stanza.put("MD5", &package.md5);
            // What the resolution read from the index. A field that is empty
            // is left out, as the index leaves it out, and reads back empty.
            stanza.put("Slot", &package.slot);
            stanza.put_optional("Use", non_empty(&package.use_flags));
            stanza.put_optional("Iuse", non_empty(&package.iuse));
            stanza.put_optional("Rdepend", non_empty(&package.rdepend));
            stanza.put_optional("Pdepend", non_empty(&package.pdepend));
            stanza.put("Build-Time", &package.build_time.to_string());
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
    /// writing it back keeps what it carried. The package order is the install
    /// order and is preserved exactly.
    ///
    /// # Errors
    ///
    /// [`GentooError::PlanDocument`] for a document with no header, a format
    /// version this library does not read, a stanza missing a field the plan
    /// cannot do without, a malformed number, or a package this layer could not
    /// address — a name that is not a package, a version this format does not
    /// define, a path that would not stay inside the archive, an MD5 that is
    /// not one, dependencies the index reader could not have read, or a field
    /// longer than an index record may state it. The
    /// document is the only thing behind a plan read this way, so the shape an
    /// index would have guaranteed is checked here.
    pub fn parse_document(text: &str) -> Result<Plan, GentooError> {
        let (header, rest) =
            document::header(document::parse(text), FORMAT).map_err(plan_document)?;
        let mut plan = Plan {
            architecture: required(header.get("Architecture"), "Architecture", "the header")?,
            binhost: required(header.get("Binhost"), "Binhost", "the header")?,
            // Signed because the field it reads is: an index states its
            // `TIMESTAMP` as an unsigned number and a mirror may state one above
            // `i64::MAX`, which `Preamble::generated` carries as the negative it
            // became. The field is provenance and nothing rests on it, so a plan
            // that recorded such a timestamp must read back as itself rather
            // than refusing the whole document over a line no decision consults.
            index_timestamp: number::<i64>(
                header.get("Index-Timestamp"),
                "Index-Timestamp",
                "the header",
            )?,
            packages: Vec::new(),
            carried: document::carried(&header, HEADER_FIELDS),
        };

        for stanza in rest {
            let name = stanza
                .get("Package")
                .ok_or_else(|| plan_document("a stanza after the header names no package"))?;
            let at = format!("the package {name}");
            let package = PlannedPackage {
                name: name.to_string(),
                version: required(stanza.get("Version"), "Version", &at)?,
                build_id: number::<u64>(stanza.get("Build-Id"), "Build-Id", &at)?
                    .ok_or_else(|| plan_document(format!("{at} states no Build-Id")))?,
                path: required(stanza.get("Path"), "Path", &at)?,
                size: number::<u64>(stanza.get("Size"), "Size", &at)?
                    .ok_or_else(|| plan_document(format!("{at} states no Size")))?,
                md5: required(stanza.get("MD5"), "MD5", &at)?,
                slot: required(stanza.get("Slot"), "Slot", &at)?,
                use_flags: stanza.get("Use").unwrap_or_default().to_string(),
                iuse: stanza.get("Iuse").unwrap_or_default().to_string(),
                rdepend: stanza.get("Rdepend").unwrap_or_default().to_string(),
                pdepend: stanza.get("Pdepend").unwrap_or_default().to_string(),
                build_time: number::<i64>(stanza.get("Build-Time"), "Build-Time", &at)?
                    .ok_or_else(|| plan_document(format!("{at} states no Build-Time")))?,
                carried: document::carried(&stanza, PACKAGE_FIELDS),
            };
            if let Some(reason) = package.unusable() {
                return Err(plan_document(reason));
            }
            plan.packages.push(package);
        }
        Ok(plan)
    }

    /// Why this plan cannot be installed, or `None` where it can.
    ///
    /// Applied again at [`GentooBuilder::build`](super::GentooBuilder::build),
    /// because a plan reaches a bootstrap two ways: read from a document, which
    /// checks each package as it is read, and taken from a resolution and then
    /// modified in the caller's own code, which nothing has checked.
    pub(super) fn unusable(&self) -> Option<String> {
        coordinate::check("the plan's binhost", &self.binhost, Nesting::Single)
            .err()
            .or_else(|| {
                coordinate::check(
                    "the plan's architecture",
                    &self.architecture,
                    Nesting::Single,
                )
                .err()
            })
            .or_else(|| self.packages.iter().find_map(PlannedPackage::unusable))
    }
}

/// `value`, or `None` where it is empty.
fn non_empty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

/// Renders one stanza, reporting a value the format cannot carry.
fn render(stanza: &Draft, out: &mut String) -> Result<(), GentooError> {
    stanza.render(out).map_err(plan_document)
}

/// Reads a required field, or reports which stanza it was missing from.
fn required(value: Option<Cow<'_, str>>, field: &str, at: &str) -> Result<String, GentooError> {
    document::required(value.as_deref(), field, at).map_err(plan_document)
}

/// Reads an optional numeric field, refusing one that is present and
/// malformed.
///
/// The rule is [`document::number`]'s; only whose document the refusal is
/// about belongs here.
fn number<T: std::str::FromStr + std::fmt::Display>(
    value: Option<Cow<'_, str>>,
    field: &str,
    at: &str,
) -> Result<Option<T>, GentooError> {
    document::number(value.as_deref(), field, at).map_err(plan_document)
}

/// A document this library cannot read or write.
fn plan_document(reason: impl Into<String>) -> GentooError {
    GentooError::PlanDocument {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plan holding two packages, in install order.
    fn plan() -> Plan {
        Plan {
            architecture: "amd64".to_string(),
            binhost: "x86-64".to_string(),
            index_timestamp: Some(1_787_145_736),
            packages: vec![
                PlannedPackage {
                    name: "sys-libs/zlib".to_string(),
                    version: "1.3.2".to_string(),
                    build_id: 1,
                    path: "sys-libs/zlib/zlib-1.3.2-1.gpkg.tar".to_string(),
                    size: 204_800,
                    md5: "b3ae71ef373f5aa4405e637a2d263f51".to_string(),
                    slot: "0/1".to_string(),
                    use_flags: "amd64 minizip".to_string(),
                    iuse: "minizip static-libs".to_string(),
                    rdepend: ">=sys-libs/glibc-2.38-r13".to_string(),
                    pdepend: String::new(),
                    build_time: 1_714_470_376,
                    carried: Carried::new(),
                },
                PlannedPackage {
                    name: "dev-vcs/git".to_string(),
                    version: "2.54.0".to_string(),
                    build_id: 5,
                    path: "dev-vcs/git/git-2.54.0-5.gpkg.tar".to_string(),
                    size: 8_192_000,
                    md5: "6a539af72c5577fdce267834d3dfd2f1".to_string(),
                    slot: "0".to_string(),
                    use_flags: "amd64 curl perl".to_string(),
                    iuse: "+curl keyring +perl".to_string(),
                    rdepend: "dev-libs/openssl:0/3= || ( dev-lang/perl virtual/perl )".to_string(),
                    pdepend: "app-eselect/eselect-git".to_string(),
                    build_time: 1_783_070_070,
                    carried: Carried::new(),
                },
            ],
            carried: Carried::new(),
        }
    }

    #[test]
    fn a_plan_round_trips_through_its_document() {
        let plan = plan();
        let document = plan.to_document().expect("the plan renders");
        assert_eq!(
            Plan::parse_document(&document).expect("it reads back"),
            plan
        );
        // Two renderings are byte-identical, so a plan that changes shows the
        // change as a diff.
        assert_eq!(
            Plan::parse_document(&document)
                .expect("it reads back")
                .to_document()
                .expect("it renders again"),
            document,
        );
    }

    #[test]
    fn an_index_timestamp_round_trips_whatever_the_index_stated() {
        // The field is signed because what it carries is: an index states its
        // `TIMESTAMP` as an unsigned number and a mirror may state one above
        // `i64::MAX`, which the preamble carries as the negative it became.
        // Nothing rests on the value -- it is provenance and the module says so
        // -- which makes refusing the whole document over it exactly the wrong
        // response.
        for stated in [Some(0), Some(-1), Some(i64::MIN), Some(i64::MAX), None] {
            let plan = Plan {
                index_timestamp: stated,
                ..plan()
            };
            let document = plan.to_document().expect("the plan renders");
            assert_eq!(
                Plan::parse_document(&document)
                    .unwrap_or_else(|err| panic!("{stated:?}: {err}"))
                    .index_timestamp,
                stated,
            );
        }
        // A value that is not a number at all is still refused, because a
        // document stating one was not written by this library.
        let document = plan()
            .to_document()
            .expect("the plan renders")
            .replace("Index-Timestamp: 1787145736", "Index-Timestamp: whenever");
        assert!(Plan::parse_document(&document).is_err());
    }

    #[test]
    fn the_stanza_order_is_the_install_order() {
        // Unlike the other layers' plans, which sort by name: this order is a
        // resolution's own output, and a plan that lost it would have to derive
        // it again from an index the plan exists to avoid needing.
        let document = plan().to_document().expect("the plan renders");
        let zlib = document.find("sys-libs/zlib").expect("zlib is named");
        let git = document.find("dev-vcs/git").expect("git is named");
        assert!(zlib < git, "zlib merges first and is written first");
        assert_eq!(
            Plan::parse_document(&document)
                .expect("it reads back")
                .packages[0]
                .name,
            "sys-libs/zlib",
        );
    }

    #[test]
    fn a_field_this_version_does_not_know_survives_a_round_trip() {
        // A plan outlives the program that wrote it, so a reader carries what
        // it does not understand rather than dropping it.
        let mut document = plan().to_document().expect("the plan renders");
        document = document.replace("Binhost: x86-64\n", "Binhost: x86-64\nGeneration: 24.0\n");
        document = document.replace(
            "MD5: b3ae71ef373f5aa4405e637a2d263f51\n",
            "MD5: b3ae71ef373f5aa4405e637a2d263f51\nSHA512: cafe\n",
        );
        let read = Plan::parse_document(&document).expect("it reads");
        let written = read.to_document().expect("it writes back");
        assert!(written.contains("Generation: 24.0"), "{written}");
        assert!(written.contains("SHA512: cafe"), "{written}");
    }

    #[test]
    fn a_document_this_library_does_not_read_is_refused() {
        for (document, why) in [
            ("", "no stanzas"),
            ("Architecture: amd64\n", "no Format field"),
            (
                "Format: ferroday-cage-gentoo-plan 3\nArchitecture: amd64\nBinhost: x86-64\n",
                "a version this library does not read",
            ),
            (
                "Format: ferroday-cage-gentoo-plan 2\nBinhost: x86-64\n",
                "a header with no architecture",
            ),
            (
                "Format: ferroday-cage-gentoo-plan 2\nArchitecture: amd64\nBinhost: x86-64\n\n\
                 Version: 1.0\n",
                "a stanza naming no package",
            ),
            (
                "Format: ferroday-cage-gentoo-plan 2\nArchitecture: amd64\nBinhost: x86-64\n\n\
                 Package: sys-libs/zlib\nVersion: 1.3.2\nBuild-Id: x\n\
                 Path: a/b.gpkg.tar\nSize: 1\nMD5: b3ae71ef373f5aa4405e637a2d263f51\n",
                "a build id that is not a number",
            ),
        ] {
            let err =
                Plan::parse_document(document).expect_err(&format!("{why} should be refused"));
            assert!(
                matches!(err, GentooError::PlanDocument { .. }),
                "{why}: {err:?}"
            );
        }

        // A version 1 document states no slot and no build time, which every
        // container is held to. It is refused for its format, which names what
        // is wrong with it, before any stanza is read.
        let first = "Format: ferroday-cage-gentoo-plan 1\nArchitecture: amd64\nBinhost: x86-64\n\n\
                     Package: sys-libs/zlib\nVersion: 1.3.2\nBuild-Id: 1\n\
                     Path: sys-libs/zlib/zlib-1.3.2-1.gpkg.tar\nSize: 1\n\
                     MD5: b3ae71ef373f5aa4405e637a2d263f51\n";
        let err = Plan::parse_document(first).expect_err("a version 1 document is refused");
        assert!(
            err.to_string().contains("\"ferroday-cage-gentoo-plan 1\""),
            "{err}"
        );
    }

    #[test]
    fn a_package_a_document_states_is_held_to_what_an_index_would_have_guaranteed() {
        // The path is the one that matters: it becomes directory segments of
        // the URL the container is fetched from and of the entry it is cached
        // under, and the bytes land there before the signed Manifest inside
        // them is ever read.
        let longer_than_a_record_states = format!(
            "Rdepend: {}",
            "a/b ".repeat(index::MAX_CLASS_BYTES / 4 + 1).trim_end()
        );
        // So is every other field an index record is held to a length in, and
        // a plan stating one longer is refused before its fields are parsed.
        let iuse_past = format!("Iuse: {}", "f".repeat(index::MAX_FLAGS_BYTES + 1));
        let slot_past = format!("Slot: {}", "s".repeat(index::MAX_SLOT_BYTES + 1));
        let version_past = format!("Version: 1{}", ".1".repeat(version::MAX_CPV_BYTES / 2));
        let cases = [
            (iuse_past.as_str(), "16385 bytes of IUSE for"),
            (slot_past.as_str(), "257 bytes of SLOT for"),
            (version_past.as_str(), "bytes long, past the 512"),
            ("Path: ../../../etc/passwd", "outside the archive"),
            ("Package: zlib", "not a package"),
            ("Version: not-a-version", "not a version"),
            ("MD5: nothex", "not one this format writes"),
            ("Slot:", "empty Slot"),
            ("Rdepend: || ( dev-libs/a", "cannot be read"),
            (longer_than_a_record_states.as_str(), "cannot be read"),
            ("Build-Time: recently", "not a number"),
        ];
        for (line, why) in cases {
            let (field, _) = line.split_once(':').expect("a fixture line");
            let mut document = plan().to_document().expect("the plan renders");
            let existing = document
                .lines()
                .find(|held| held.starts_with(&format!("{field}: ")))
                .expect("the field is written")
                .to_string();
            document = document.replacen(&existing, line, 1);
            let err = Plan::parse_document(&document).expect_err(why);
            assert!(err.to_string().contains(why), "{why}: {err}");
        }
    }

    #[test]
    fn a_plan_records_what_the_resolution_read_and_leaves_out_what_is_empty() {
        // The fields the container's signed metadata is held to. One the index
        // left out is left out here too, and reads back as empty.
        let document = plan().to_document().expect("the plan renders");
        for line in [
            "Slot: 0/1",
            "Use: amd64 minizip",
            "Iuse: +curl keyring +perl",
            "Rdepend: dev-libs/openssl:0/3= || ( dev-lang/perl virtual/perl )",
            "Pdepend: app-eselect/eselect-git",
            "Build-Time: 1714470376",
        ] {
            assert!(
                document.lines().any(|held| held == line),
                "{line} in {document}"
            );
        }
        let zlib = document
            .split("\n\n")
            .find(|stanza| stanza.contains("sys-libs/zlib"))
            .expect("zlib's stanza");
        assert!(!zlib.contains("Pdepend:"), "{zlib}");

        // A stanza that does not say where the build is installed was not
        // written by this version, and is refused rather than read as slot 0.
        let unslotted = document.replacen("Slot: 0/1\n", "", 1);
        let err = Plan::parse_document(&unslotted).expect_err("a stanza with no slot");
        assert!(err.to_string().contains("no Slot"), "{err}");
    }

    #[test]
    fn a_plan_a_caller_built_by_hand_is_checked_before_it_is_installed() {
        // A plan reaches a bootstrap two ways, and only one of them went
        // through the reader.
        assert!(plan().unusable().is_none());
        let mut edited = plan();
        edited.binhost = "../x86-64".to_string();
        assert!(edited.unusable().is_some());
        let mut edited = plan();
        edited.packages[0].path = "/etc/passwd".to_string();
        assert!(edited.unusable().is_some());
    }
}
