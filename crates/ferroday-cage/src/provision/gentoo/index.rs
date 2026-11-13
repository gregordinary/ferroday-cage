//! The binary-package index: what the binhost publishes, and in what builds.
//!
//! `binpackages/<generation>/<sub-architecture>/Packages` is a field-and-stanza
//! document — the syntax [`document`](super::super::document) reads for every
//! layer — with a preamble stanza and one stanza per published build. The
//! archive serves a `Packages.gz` beside it holding the same content in a tenth
//! of the bytes, so that is what is fetched and the plain form is the fallback.
//!
//! The transport is not here. The mirror walk, its ceiling and its failover are
//! [`Gentoo`](super::Gentoo)'s, as they are for the signed documents; this
//! module composes the two URLs, in preference order, and reads what comes
//! back.
//!
//! # One version, several builds
//!
//! The archive publishes more than one build of a version. `BUILD_ID` numbers
//! them and they differ in the USE flags they were compiled with, and therefore
//! in what they depend on: two builds of one `dev-vcs/git` version differ by
//! twelve packages against a hundred and six in what they pull in. So the unit
//! here is the build rather than the version, and choosing among the builds of
//! a version is the resolver's decision rather than a tie-break.
//!
//! # The preamble describes the machine that built the index
//!
//! Its `ARCH`, `ACCEPT_KEYWORDS` and `PROFILE` are the autobuilder host's own
//! environment copied into every index it generates: the arm64 index says
//! `ARCH: amd64` and lists `llvm_targets_X86` in its `USE`, while its package
//! stanzas are correctly `arm64`. An index therefore cannot be validated
//! against its own preamble, and the target architecture cannot be read from
//! one. The URL is the coordinate. `CHOST` is the one preamble field that
//! tracks the target, and it is reported rather than acted on.
//!
//! `TIMESTAMP` and `TTL` are read for the same reason and with the same
//! standing: nothing signs the index in any form — no `Packages.gpg`, `.asc`,
//! `.sig`, `Manifest` or `.DIGESTS` is published beside it — so a timestamp it
//! carries says when a mirror claims it was generated and not when it was.

use std::borrow::Cow;

use super::atom::{self, Dependency};
use super::version;
use crate::provision::coordinate::{self, Nesting};
use crate::provision::document::{self, Stanza};

/// The binary-package generation the archive publishes under.
///
/// A directory between the architecture and the sub-architecture, and the only
/// one on offer: `17.1` and `24.0` are both 404 today. It is a constant rather
/// than a setting because a caller has nothing to choose between, and a second
/// generation is a builder method when the archive publishes one.
pub(super) const GENERATION: &str = "23.0";

/// The slot a record carries when it states none.
///
/// The index omits `SLOT` for the default slot rather than spelling it: under a
/// third of the stanzas carry the field and the rest are slot `0`.
const DEFAULT_SLOT: &str = "0";

/// The longest dependency class a record may state, in bytes.
///
/// A class is kept as the index writes it and parsed when a resolution chooses
/// the build, so reading the index parses each one only to check it. What that
/// check holds at once is one class's atoms, and the class's length is what
/// bounds them. The longest the live index states is 3,373 bytes, the `RDEPEND`
/// of `kde-plasma/plasma-workspace`; this is nineteen times that. A record
/// stating a longer one is not one this layer can act on.
pub(super) const MAX_CLASS_BYTES: usize = 64 * 1024;

/// The longest `SLOT` a record may state, in bytes.
///
/// Nothing signs the index, so every text field a record keeps is held to a
/// length, as its dependency classes are to [`MAX_CLASS_BYTES`] and its `CPV`
/// to [`version::MAX_CPV_BYTES`]. A refusal of a contended slot names it. The
/// longest the live index states is 26 bytes; this is nearly ten times that.
pub(super) const MAX_SLOT_BYTES: usize = 256;

/// The longest flag list, `USE` or `IUSE`, a record may state, in bytes.
///
/// A USE dependency is answered by scanning both lists of the candidate it is
/// held to, so their length is what one such comparison reads. The longest
/// the live index states are 1,827 bytes of `USE`, `media-gfx/sane-backends`',
/// and 2,795 of `IUSE`, `www-servers/apache`'s; this is over five times the
/// longer.
pub(super) const MAX_FLAGS_BYTES: usize = 16 * 1024;

/// The longest `PATH` a record may state, in bytes.
///
/// It becomes a URL and a cache entry's path. The longest the live index
/// states is 145 bytes; this is seven times that, and short enough that the
/// cache directory a caller names leaves room for it beneath a filesystem's
/// own limit on a path.
pub(super) const MAX_PATH_BYTES: usize = 1024;

/// One published build: what the resolver chooses between, and what the merge
/// needs to fetch and register it.
///
/// The fields are those two sets and nothing else. A stanza carries a good deal
/// more — `LICENSE`, `DESCRIPTION`, `RESTRICT`, the build-time dependency
/// classes — and the whole index is fifteen thousand of them, so what is not
/// read is not kept.
///
/// # Held compactly
///
/// Nothing signs the index, so a mirror decides how many records it holds and
/// how each is laid out. A record therefore costs its kept text and a fixed few
/// words, whatever the layout. Its text fields sit end to end in one
/// allocation, and its dependency classes are kept as the index writes them
/// and parsed when a resolution chooses the build: a parsed atom is several
/// times the four bytes `a/b ` takes to write one.
///
/// Each kept field is held to a length as well: the `CPV` to
/// [`version::MAX_CPV_BYTES`], and the rest to [`MAX_SLOT_BYTES`],
/// [`MAX_FLAGS_BYTES`], [`MAX_PATH_BYTES`] and [`MAX_CLASS_BYTES`]. That
/// bounds what anything copied out of one record costs, and a resolution
/// copies the `CPV` and the slot into what it reports.
#[derive(Debug, Clone)]
pub(super) struct Record {
    /// The text fields, end to end, in the order [`Text`] names them.
    text: Box<str>,
    /// Where each text field ends in [`text`](Self::text).
    ///
    /// Thirty-two bits, since a record is part of an index held to
    /// [`MAX_INDEX_BYTES`](super::MAX_INDEX_BYTES).
    ends: [u32; Text::COUNT],
    /// Which build of that version this is, from `BUILD_ID`.
    pub build_id: u64,
    /// When it was built, from `BUILD_TIME`, seconds since the epoch.
    pub build_time: i64,
    /// The container's length in bytes, from `SIZE`, which bounds its download.
    pub size: u64,
}

/// A record's text fields, in the order [`Record`] holds them.
#[derive(Clone, Copy)]
enum Text {
    Name,
    Version,
    Slot,
    UseFlags,
    Iuse,
    Rdepend,
    Pdepend,
    Path,
    Md5,
}

impl Text {
    /// How many there are.
    const COUNT: usize = Text::Md5 as usize + 1;
}

impl Record {
    /// Assembles a record from its text fields, in [`Text`]'s order, or `None`
    /// where they do not fit the offsets it holds them at.
    fn compose(
        fields: [&str; Text::COUNT],
        build_id: u64,
        build_time: i64,
        size: u64,
    ) -> Option<Record> {
        let mut text = String::with_capacity(fields.iter().map(|field| field.len()).sum());
        let mut ends = [0; Text::COUNT];
        for (end, field) in ends.iter_mut().zip(fields) {
            text.push_str(field);
            *end = u32::try_from(text.len()).ok()?;
        }
        Some(Record {
            text: text.into_boxed_str(),
            ends,
            build_id,
            build_time,
            size,
        })
    }

    /// One text field.
    fn field(&self, which: Text) -> &str {
        let at = which as usize;
        let start = at.checked_sub(1).map_or(0, |before| self.ends[before]);
        &self.text[start as usize..self.ends[at] as usize]
    }

    /// `category/name`, as the archive publishes it.
    pub(super) fn name(&self) -> &str {
        self.field(Text::Name)
    }

    /// The version, without the category or the name.
    pub(super) fn version(&self) -> &str {
        self.field(Text::Version)
    }

    /// The slot, `slot` or `slot/subslot`, defaulting to [`DEFAULT_SLOT`].
    pub(super) fn slot(&self) -> &str {
        self.field(Text::Slot)
    }

    /// The flags the build was compiled with, space-separated as the index
    /// writes them.
    ///
    /// Held as the index's own string rather than as a parsed list: the index
    /// carries a quarter of a million flag tokens across its stanzas, and every
    /// question asked of them is membership or a count.
    pub(super) fn use_flags(&self) -> &str {
        self.field(Text::UseFlags)
    }

    /// The flags the package knows, space-separated, each possibly carrying the
    /// `+` or `-` prefix that states the ebuild's own default.
    ///
    /// The prefixes are stripped on the way out rather than on the way in, so
    /// what is held is what the archive published.
    pub(super) fn iuse(&self) -> &str {
        self.field(Text::Iuse)
    }

    /// `RDEPEND` as the index writes it.
    ///
    /// The plan records it this way, so that the container's signed metadata
    /// can be held to what the resolution read; [`runtime`](Self::runtime) is
    /// the parsed form.
    pub(super) fn rdepend(&self) -> &str {
        self.field(Text::Rdepend)
    }

    /// `PDEPEND` as the index writes it, for the same reason.
    pub(super) fn pdepend(&self) -> &str {
        self.field(Text::Pdepend)
    }

    /// The runtime dependencies, from `RDEPEND`, parsed.
    pub(super) fn runtime(&self) -> Vec<Dependency> {
        read_class(self.rdepend()).expect("a kept record's dependency classes were read")
    }

    /// The post-merge dependencies, from `PDEPEND`, parsed.
    ///
    /// Kept apart from [`runtime`](Self::runtime) rather than folded into it,
    /// because the distinction is what breaks a cycle: a `PDEPEND` is satisfied
    /// after the package is merged rather than before, so it belongs to the
    /// closure and not to the install order.
    pub(super) fn post_merge(&self) -> Vec<Dependency> {
        read_class(self.pdepend()).expect("a kept record's dependency classes were read")
    }

    /// The container's path under the binhost directory, from `PATH`.
    pub(super) fn path(&self) -> &str {
        self.field(Text::Path)
    }

    /// The container's MD5, from `MD5`, lowercase hex.
    ///
    /// The container is held to it as portage holds a downloaded binary
    /// package to its index's digests, which pins a plan to the containers it
    /// resolved. It is not what makes the bytes trustworthy: that is the signed
    /// `Manifest` inside the container.
    pub(super) fn md5(&self) -> &str {
        self.field(Text::Md5)
    }

    /// How many flags the build was compiled with, which is the resolver's
    /// default preference among the builds of one version.
    pub(super) fn use_count(&self) -> usize {
        self.use_flags().split_ascii_whitespace().count()
    }

    /// Whether the build was compiled with `flag`.
    pub(super) fn has_use(&self, flag: &str) -> bool {
        atom::holds(self.use_flags(), flag)
    }

    /// Why this record's `PATH` cannot be fetched, or `None` where it can.
    ///
    /// Nothing signs the index, so the path is a mirror's string with nothing
    /// vouching for it, and it becomes directory segments of a URL and of a
    /// cache entry. It is held to the same nested-coordinate rule the stage3's
    /// own archive path is, and it must stay under the binhost directory
    /// rather than climbing out of it.
    fn unaddressable(&self) -> Option<String> {
        coordinate::check("the index's package path", self.path(), Nesting::Nested).err()
    }
}

impl atom::Candidate for Record {
    fn name(&self) -> &str {
        Record::name(self)
    }

    fn version(&self) -> &str {
        Record::version(self)
    }

    fn slot(&self) -> &str {
        Record::slot(self)
    }

    fn flag_lists(&self) -> (&str, &str) {
        (self.use_flags(), self.iuse())
    }
}

/// Reads one dependency class as a record states it.
///
/// [`atom::parse_class`]'s grammar, held to [`MAX_CLASS_BYTES`] first. A plan
/// states the classes a record did, so it is held to the same.
///
/// # Errors
///
/// Returns the reason where the class is longer than [`MAX_CLASS_BYTES`], or
/// where [`atom::parse_class`] refuses it.
pub(super) fn read_class(text: &str) -> Result<Vec<Dependency>, String> {
    if text.len() > MAX_CLASS_BYTES {
        return Err(format!(
            "it is {} bytes long, past the {MAX_CLASS_BYTES} a dependency class may run to",
            text.len(),
        ));
    }
    atom::parse_class(text)
}

/// The first of a build's text fields that is longer than a record may state
/// it, as the index names the field, its length and its bound; or `None` where
/// none is.
///
/// The fields a record keeps besides its dependency classes, which
/// [`read_class`] holds, and its MD5, which is a fixed length: the `CPV`, given
/// as its length, the slot, the two flag lists, and the path. A plan states
/// each of them where an index would have, so it is held to the same.
pub(super) fn overlong(
    cpv: usize,
    slot: &str,
    use_flags: &str,
    iuse: &str,
    path: &str,
) -> Option<(&'static str, usize, usize)> {
    [
        ("CPV", cpv, version::MAX_CPV_BYTES),
        ("SLOT", slot.len(), MAX_SLOT_BYTES),
        ("USE", use_flags.len(), MAX_FLAGS_BYTES),
        ("IUSE", iuse.len(), MAX_FLAGS_BYTES),
        ("PATH", path.len(), MAX_PATH_BYTES),
    ]
    .into_iter()
    .find(|(_, length, max)| length > max)
}

/// What the index's preamble says about itself.
///
/// Reported rather than acted on, for the reason the module documentation
/// gives: its architecture fields describe the autobuilder host, and nothing
/// signs any of it.
#[derive(Debug, Clone, Default)]
pub(super) struct Preamble {
    /// `TIMESTAMP`: when the index states it was generated, seconds since the
    /// epoch.
    pub generated: Option<i64>,
    /// `TTL`: how long the index states it stays current, in seconds.
    ///
    /// Reported beside [`generated`](Self::generated) and acted on no more than
    /// it is. Nothing signs the index, so a claim about its own currency is
    /// worth showing a caller and worth resting nothing on.
    pub ttl: Option<i64>,
    /// `CHOST`: the target triple the packages were built for. The one preamble
    /// field that tracks the target rather than the builder.
    pub chost: Option<String>,
    /// `PACKAGES`: how many stanzas the index states it holds.
    ///
    /// The one preamble field a decision rests on, and a narrow decision: an
    /// index holding fewer stanzas than it says it does arrived short. That
    /// catches a mirror that truncated the file and not one that composed it —
    /// the count is the same unsigned document as the stanzas — so it is an
    /// integrity check rather than a security property. It is worth having
    /// because a truncated plain-text index otherwise parses perfectly and
    /// resolves against a silently smaller archive.
    pub declared: Option<u64>,
}

/// The parsed index: every published build, and what the preamble said.
#[derive(Debug)]
pub(super) struct Index {
    preamble: Preamble,
    /// Every build kept, in name order, and in index order within a name.
    ///
    /// Sorted rather than indexed by a map, so that finding a name's builds is
    /// a binary search and costs nothing per record beyond the record itself.
    records: Vec<Record>,
    /// How many stanzas were read but not kept.
    skipped: usize,
}

impl Index {
    /// Parses an index document.
    ///
    /// The first stanza is the preamble and every stanza after it is a build. A
    /// stanza that is not one this layer can act on, or one a plan could not
    /// record, is left out and counted rather than failing the whole index:
    /// [`read_record`] says which those are. An unsigned document is one a
    /// mirror composes, and letting a single stanza refuse fifteen thousand
    /// others would make a denial of service out of a typo.
    ///
    /// The stanzas are read one at a time and only the records are kept, so
    /// what parsing holds beyond the text is the records themselves.
    pub(super) fn parse(text: &str) -> Index {
        let mut stanzas = document::parse(text);
        let preamble = stanzas
            .next()
            .map(|first| read_preamble(&first))
            .unwrap_or_default();
        let mut records = Vec::new();
        let mut skipped = 0;
        for stanza in stanzas {
            match read_record(&stanza) {
                Some(record) if record.unaddressable().is_none() => records.push(record),
                _ => skipped += 1,
            }
        }
        // Stable, so the builds of one name keep the order the index published
        // them in.
        records.sort_by(|a, b| a.name().cmp(b.name()));
        Index {
            preamble,
            records,
            skipped,
        }
    }

    /// What the preamble said.
    pub(super) fn preamble(&self) -> &Preamble {
        &self.preamble
    }

    /// Every build the index publishes, in name order, and in the order the
    /// index published them within a name.
    pub(super) fn records(&self) -> &[Record] {
        &self.records
    }

    /// Every build published under `name`, in index order.
    pub(super) fn builds(&self, name: &str) -> &[Record] {
        let start = self.records.partition_point(|record| record.name() < name);
        let count = self.records[start..].partition_point(|record| record.name() == name);
        &self.records[start..start + count]
    }

    /// How many stanzas were read but not kept.
    pub(super) fn skipped(&self) -> usize {
        self.skipped
    }

    /// Projects the index onto the public discovery surface, consuming it.
    ///
    /// What a caller asking what is on offer wants is the names and their
    /// versions, so that is all the catalogue keeps.
    pub(super) fn into_catalogue(self) -> Catalogue {
        let mut names = Vec::new();
        let mut versions = Vec::new();
        for builds in self.records.chunk_by(|a, b| a.name() == b.name()) {
            let mut published: Vec<String> = builds
                .iter()
                .map(|record| record.version().to_string())
                .collect();
            // One version published as several builds appears once here: the
            // builds differ in USE rather than in what they are a version of,
            // and choosing among them is the resolver's question rather than a
            // reader's.
            published.sort_by(|a, b| {
                version::compare(a, b).expect("a record's version is one split_cpv found to parse")
            });
            published.dedup();
            names.push(builds[0].name().to_string());
            versions.push(published);
        }
        Catalogue {
            names,
            versions,
            builds: self.records.len(),
            generated: self.preamble.generated,
            ttl: self.preamble.ttl,
            chost: self.preamble.chost,
        }
    }
}

/// Reads the preamble's fields, each absent where it does not parse.
///
/// A preamble that says nothing is a preamble that says nothing: none of these
/// fields decides anything, so an unreadable one is reported as absent rather
/// than refusing an index whose package stanzas are fine.
fn read_preamble(stanza: &Stanza<'_>) -> Preamble {
    Preamble {
        generated: stanza.get("TIMESTAMP").and_then(|text| text.parse().ok()),
        ttl: stanza.get("TTL").and_then(|text| text.parse().ok()),
        chost: stanza.get("CHOST").map(Cow::into_owned),
        declared: stanza.get("PACKAGES").and_then(|text| text.parse().ok()),
    }
}

/// Reads one build's stanza, or `None` where it is not one.
///
/// It is not one where it lacks a field a build needs (`CPV`, `MD5`,
/// `BUILD_ID`, `PATH`, `SIZE`), or states one this layer cannot act on or a
/// plan cannot record: a `CPV` that does not split or names a package the
/// specification does not permit, an MD5, a build id or a size that is not
/// one, a dependency class [`read_class`] refuses, an empty slot, a value
/// folded over several lines, or a field longer than [`overlong`] admits. A
/// path that would not stay inside the archive is refused by the caller,
/// through [`Record::unaddressable`].
fn read_record(stanza: &Stanza<'_>) -> Option<Record> {
    let [
        cpv,
        md5,
        build_id,
        build_time,
        slot,
        use_flags,
        iuse,
        rdepend,
        pdepend,
        path,
        size,
    ] = stanza.get_each([
        "CPV",
        "MD5",
        "BUILD_ID",
        "BUILD_TIME",
        "SLOT",
        "USE",
        "IUSE",
        "RDEPEND",
        "PDEPEND",
        "PATH",
        "SIZE",
    ]);
    let cpv = cpv?;
    let slot = slot.unwrap_or(Cow::Borrowed(DEFAULT_SLOT));
    let use_flags = use_flags.unwrap_or_default();
    let iuse = iuse.unwrap_or_default();
    let path = path?;
    // Before anything parses a field, so splitting the `CPV` is no more work
    // than its bound allows.
    if overlong(cpv.len(), &slot, &use_flags, &iuse, &path).is_some() {
        return None;
    }
    let (category, package, version) = version::split_cpv(&cpv)?;
    let name = format!("{category}/{package}");
    if !atom::is_package(&name) {
        return None;
    }
    // The MD5 a plan document carries and a container is held to, as
    // `Record::md5` says. Held to the algorithm's own alphabet here, where the
    // record is built, because `Plan::parse_document` refuses a value outside
    // it, so a plan projected from such a record would be a document this
    // crate emits and will not read back.
    let md5 = md5?;
    if !crate::provision::digest::md5::is_hex(&md5) {
        return None;
    }
    let build_id = build_id?.parse().ok()?;
    // Absent or unreadable is the epoch rather than a refusal: the value is the
    // last of three ranking keys, so a record without one ranks last among
    // equals instead of not being a candidate.
    let build_time = build_time.and_then(|text| text.parse().ok()).unwrap_or(0);
    let rdepend = rdepend.unwrap_or_default();
    let pdepend = pdepend.unwrap_or_default();
    // A plan states each of these on one line, and the slot as a value of its
    // own, so a record a plan could not carry is left out here, as one with an
    // MD5 a plan would refuse is: an empty `SLOT:` or a value folded over
    // several lines would be resolved to and then refused by the plan that
    // records the resolution. Portage writes every field on one line.
    if slot.is_empty()
        || [&slot, &use_flags, &iuse, &rdepend, &pdepend]
            .iter()
            .any(|field| field.contains('\n'))
    {
        return None;
    }
    // Read to be checked, and the parsed form dropped: a resolution parses the
    // classes of the builds it chooses, and those alone.
    read_class(&rdepend).ok()?;
    read_class(&pdepend).ok()?;
    let size = size?.parse().ok()?;
    Record::compose(
        [
            &name, version, &slot, &use_flags, &iuse, &rdepend, &pdepend, &path, &md5,
        ],
        build_id,
        build_time,
        size,
    )
}

/// The two names the index is published under, in preference order.
///
/// The compressed form first: it is a tenth of the bytes for identical content,
/// and reading it costs nothing to implement because
/// [`compress::decompress`](super::super::compress::decompress) selects a
/// decoder by magic rather than by file name. No other compression is
/// published, on any architecture: `.xz`, `.bz2` and `.zst` are all 404. The
/// reader holds a body to that, refusing any other compression it finds.
pub(super) const NAMES: [&str; 2] = ["Packages.gz", "Packages"];

/// The mirror-relative directory the binhost for `architecture` and
/// `sub_architecture` publishes under.
///
/// Both segments were held to [`coordinate::check`] before they could reach
/// here — the architecture at [`GentooBuilder::build`](super::GentooBuilder::build)
/// and the sub-architecture beside it — so this composes rather than validates.
pub(super) fn directory(architecture: &str, sub_architecture: &str) -> String {
    format!("releases/{architecture}/binpackages/{GENERATION}/{sub_architecture}")
}

/// What a binhost publishes: its package names, and the versions of each.
///
/// Produced by [`Gentoo::packages`](super::Gentoo::packages), and read from the
/// index the archive serves now rather than from anything compiled into this
/// crate. It is the binhost's counterpart to
/// [`Variants`](super::Variants), and it answers the question a caller has
/// before they commit to a resolution: whether the archive publishes the thing
/// they mean to install.
///
/// Coverage is a property of the archive rather than of this crate. Around
/// seven thousand distinct names are published across fifteen thousand builds,
/// which is most of the tree and not all of it — `dev-build/cmake` is there and
/// `app-misc/jq` is not, in any version.
///
/// # Example
///
/// ```no_run
/// use ferroday_cage::provision::gentoo::Gentoo;
///
/// # fn main() -> Result<(), ferroday_cage::provision::gentoo::GentooError> {
/// let mut gentoo = Gentoo::builder("amd64").binhost("x86-64").build()?;
/// let catalogue = gentoo.packages()?;
/// assert!(catalogue.contains("dev-vcs/git"));
/// for version in catalogue.versions("dev-vcs/git") {
///     println!("{version}");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Catalogue {
    /// Every package name, sorted.
    names: Vec<String>,
    /// The versions of each name, at the name's place in
    /// [`names`](Self::names), ordered lowest first and deduplicated across
    /// the builds of one version.
    versions: Vec<Vec<String>>,
    /// How many builds the index published, which exceeds the number of
    /// versions wherever a version is published more than once.
    builds: usize,
    generated: Option<i64>,
    ttl: Option<i64>,
    chost: Option<String>,
}

impl Catalogue {
    /// Every package name the binhost publishes, as `category/name`, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(String::as_str)
    }

    /// The versions of `name` the binhost publishes, lowest first, or nothing
    /// where it publishes none.
    ///
    /// One version appears once however many builds of it the archive
    /// publishes: the builds differ in the USE flags they were compiled with
    /// rather than in what version they are, and choosing among them belongs to
    /// a resolution rather than to a listing.
    pub fn versions(&self, name: &str) -> impl Iterator<Item = &str> {
        self.place(name)
            .map_or(&[][..], |at| self.versions[at].as_slice())
            .iter()
            .map(String::as_str)
    }

    /// Whether the binhost publishes `name` in any version.
    pub fn contains(&self, name: &str) -> bool {
        self.place(name).is_some()
    }

    /// Where `name` sits in [`names`](Self::names), if it is there.
    fn place(&self, name: &str) -> Option<usize> {
        self.names
            .binary_search_by(|held| held.as_str().cmp(name))
            .ok()
    }

    /// The epoch the index states it was generated at, or `None` where it
    /// states none.
    ///
    /// Nothing signs the index, so this is a mirror's claim rather than a
    /// verified fact. It is worth reporting and not worth resting a decision
    /// on: the rollback the stage3's signed timestamp closes cannot be closed
    /// the same way here, not because there is nothing to read but because
    /// nothing vouches for what is read.
    pub fn generated(&self) -> Option<i64> {
        self.generated
    }

    /// How long the index states it stays current, in seconds, or `None` where
    /// it states nothing.
    ///
    /// Read beside [`generated`](Self::generated) and standing exactly as far:
    /// nothing signs the index, so this is what a mirror says about how long
    /// its own answer is good for.
    pub fn ttl(&self) -> Option<i64> {
        self.ttl
    }

    /// The target triple the index's preamble states its packages were built
    /// for, such as `x86_64-pc-linux-gnu`.
    ///
    /// The one preamble field that tracks the target rather than the machine
    /// that generated the index — whose architecture fields are its own, so
    /// that the arm64 index reads `ARCH: amd64`. Reported for the same reason
    /// [`generated`](Self::generated) is, and acted on for no more.
    pub fn chost(&self) -> Option<&str> {
        self.chost.as_deref()
    }

    /// How many package names the binhost publishes.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether it publishes none, which a live archive never does.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// How many builds the binhost publishes, counting each build of a version
    /// separately.
    ///
    /// Above [`len`](Self::len) by a wide margin, and above the number of
    /// versions too: the archive publishes some versions more than twenty
    /// times, differing only in the flags they were compiled with.
    pub fn builds(&self) -> usize {
        self.builds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture index: a preamble whose architecture fields lie, and four
    /// builds — two of one version, differing in USE.
    const FIXTURE: &str = "\
ARCH: amd64
CHOST: aarch64-unknown-linux-gnu
PACKAGES: 4
PROFILE: default/linux/amd64/17.0/hardened
TIMESTAMP: 1787145736
TTL: 3600
USE: llvm_targets_X86 cpu_flags_x86_sse2

BUILD_ID: 5
BUILD_TIME: 1783070070
CPV: dev-vcs/git-2.54.0
IUSE: +curl keyring +perl
MD5: 6a539af72c5577fdce267834d3dfd2f1
PATH: dev-vcs/git/git-2.54.0-5.gpkg.tar
RDEPEND: dev-libs/openssl:0/3= >=sys-libs/glibc-2.43-r2
SIZE: 8192000
USE: amd64 curl perl
REPO: gentoo

BUILD_ID: 7
BUILD_TIME: 1783073545
CPV: dev-vcs/git-2.54.0
IUSE: +curl keyring +perl
MD5: 49c242775827cc9cdb5e308933d97d18
PATH: dev-vcs/git/git-2.54.0-7.gpkg.tar
RDEPEND: dev-libs/openssl:0/3= app-crypt/libsecret >=sys-libs/glibc-2.43-r2
SIZE: 8192000
USE: amd64 curl keyring perl
REPO: gentoo

BUILD_ID: 1
BUILD_TIME: 1714470376
CPV: sys-libs/zlib-1.3.1-r1
IUSE: minizip static-libs
MD5: 3a61f698748c7323c87081584f383b3c
PATH: sys-libs/zlib/zlib-1.3.1-r1-1.gpkg.tar
RDEPEND: !sys-libs/zlib-ng[compat] >=sys-libs/glibc-2.38-r13
SIZE: 204800
SLOT: 0/1
USE: amd64 minizip
REPO: gentoo

BUILD_ID: 1
BUILD_TIME: 1783330310
CPV: acct-group/3proxy-0
MD5: 1fea75aab3015c66c56ca3efe50f0b9b
PATH: acct-group/3proxy/3proxy-0-1.gpkg.tar
SIZE: 20480
USE: amd64
REPO: gentoo
";

    #[test]
    fn a_stanza_becomes_a_build_with_its_version_split_out() {
        use super::atom::Candidate as _;

        let index = Index::parse(FIXTURE);
        assert_eq!(index.records().len(), 4);
        assert_eq!(index.skipped(), 0);

        let zlib = index
            .builds("sys-libs/zlib")
            .first()
            .expect("zlib is published");
        assert_eq!(zlib.version(), "1.3.1-r1");
        assert_eq!(zlib.slot(), "0/1");
        assert_eq!(zlib.size, 204_800);
        assert_eq!(zlib.build_id, 1);
        assert_eq!(zlib.cpv(), "sys-libs/zlib-1.3.1-r1");
        assert_eq!(zlib.path(), "sys-libs/zlib/zlib-1.3.1-r1-1.gpkg.tar");
        assert_eq!(zlib.md5(), "3a61f698748c7323c87081584f383b3c");
        assert_eq!(zlib.iuse(), "minizip static-libs");
        assert_eq!(zlib.use_flags(), "amd64 minizip");
        assert_eq!(
            zlib.rdepend(),
            "!sys-libs/zlib-ng[compat] >=sys-libs/glibc-2.38-r13"
        );
        assert_eq!(zlib.runtime().len(), 2);
        assert!(zlib.post_merge().is_empty());

        // A stanza with no SLOT is the default slot rather than no slot.
        let group = index
            .builds("acct-group/3proxy")
            .first()
            .expect("the group is published");
        assert_eq!(group.slot(), DEFAULT_SLOT);
        assert!(group.runtime().is_empty());
    }

    #[test]
    fn one_version_published_twice_is_two_builds() {
        let index = Index::parse(FIXTURE);
        let builds = index.builds("dev-vcs/git");
        assert_eq!(builds.len(), 2);
        assert!(builds.iter().all(|build| build.version() == "2.54.0"));
        // The builds differ in USE, and therefore in what they pull in: that is
        // the whole reason the unit here is the build.
        assert_eq!(builds[0].use_count(), 3);
        assert_eq!(builds[1].use_count(), 4);
        assert!(!builds[0].has_use("keyring"));
        assert!(builds[1].has_use("keyring"));
        assert_ne!(builds[0].runtime().len(), builds[1].runtime().len());
        // In the order the index published them, whatever order the records
        // are held in.
        assert_eq!([builds[0].build_id, builds[1].build_id], [5, 7]);
    }

    #[test]
    fn a_records_use_answers_before_its_iuse_does() {
        use super::atom::Candidate as _;

        let index = Index::parse(FIXTURE);
        let git = index
            .builds("dev-vcs/git")
            .first()
            .expect("git is published");
        // `amd64` is in USE and in no IUSE, so asking IUSE first would report
        // an enabled flag as unknown.
        assert_eq!(git.use_flag("amd64"), Some(true));
        assert_eq!(git.use_flag("curl"), Some(true));
        // Known and off: the `+`/`-` prefixes of an IUSE entry are not part of
        // the flag's name.
        assert_eq!(git.use_flag("keyring"), Some(false));
        // Neither: only an atom's own default can answer.
        assert_eq!(git.use_flag("bindist"), None);
    }

    #[test]
    fn the_preamble_is_read_and_its_architecture_is_not_believed() {
        let index = Index::parse(FIXTURE);
        let preamble = index.preamble();
        assert_eq!(preamble.generated, Some(1_787_145_736));
        assert_eq!(preamble.ttl, Some(3600));
        assert_eq!(preamble.declared, Some(4));
        // CHOST tracks the target; ARCH and PROFILE describe the builder and
        // are not read at all, which is what keeps an index from being
        // validated against a lie about itself.
        assert_eq!(preamble.chost.as_deref(), Some("aarch64-unknown-linux-gnu"));
    }

    #[test]
    fn a_stanza_the_layer_cannot_act_on_is_left_out_and_counted() {
        let refused = "\
TIMESTAMP: 1

BUILD_ID: 1
CPV: not-a-cpv
MD5: d41d8cd98f00b204e9800998ecf8427e
PATH: a/b/c.gpkg.tar
SIZE: 1

BUILD_ID: 1
CPV: sys-libs/zlib-1.3.1
MD5: d41d8cd98f00b204e9800998ecf8427e
PATH: ../../../etc/passwd
SIZE: 1

BUILD_ID: 1
CPV: sys-libs/zlib-1.3.1
MD5: d41d8cd98f00b204e9800998ecf8427e
PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar
RDEPEND: || ( dev-libs/a
SIZE: 1

BUILD_ID: 1
CPV: sys-libs/zlib-1.3.1
MD5: not a digest
PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar
SIZE: 1

BUILD_ID: 1
CPV: sys-libs/zlib-1.3.1
MD5: d41d8cd98f00b204e9800998ecf8427e
PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar
SIZE: 1
SLOT:

BUILD_ID: 1
CPV: sys-libs/zlib-1.3.1
MD5: d41d8cd98f00b204e9800998ecf8427e
PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar
RDEPEND: dev-libs/a
 dev-libs/b
SIZE: 1

BUILD_ID: 1
CPV: sys-libs/zlib-1.3.1
MD5: d41d8cd98f00b204e9800998ecf8427e
PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar
SIZE: 1
";
        let index = Index::parse(refused);
        // The traversal is the one that matters: nothing signs the index, so
        // its PATH is a mirror's string and it becomes a URL and a cache entry.
        // The digest matters for a second reason: a record carrying something
        // that is not one can pass no verification, and projects a plan
        // document this crate emits and refuses to read back. So does an empty
        // slot, and a value folded over two lines.
        assert_eq!(index.records().len(), 1);
        assert_eq!(index.skipped(), 6);
        assert_eq!(index.builds("sys-libs/zlib").len(), 1);
    }

    #[test]
    fn a_stanza_built_to_exhaust_the_parser_is_left_out_like_any_other() {
        // Nothing signs the index, so a stanza can be shaped to cost the reader
        // rather than to describe a package: groups nested past the depth the
        // stack can follow, and a `CPV` that is a megabyte of hyphens. Each is
        // a stanza this layer cannot act on, and is counted as one.
        let nest = 100_000;
        let body = format!(
            "TIMESTAMP: 1\n\n\
             BUILD_ID: 1\nCPV: sys-libs/zlib-1.3.1\n\
             MD5: d41d8cd98f00b204e9800998ecf8427e\n\
             PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar\n\
             RDEPEND: {}dev-libs/a{}\nSIZE: 1\n\n\
             BUILD_ID: 1\nCPV: a/b{}\n\
             MD5: d41d8cd98f00b204e9800998ecf8427e\n\
             PATH: a/b/b-1-1.gpkg.tar\nSIZE: 1\n\n\
             BUILD_ID: 1\nCPV: sys-libs/zlib-1.3.1\n\
             MD5: d41d8cd98f00b204e9800998ecf8427e\n\
             PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar\nSIZE: 1\n",
            "( ".repeat(nest),
            " )".repeat(nest),
            "-".repeat(1 << 20),
        );
        let index = Index::parse(&body);
        assert_eq!(index.records().len(), 1);
        assert_eq!(index.skipped(), 2);
    }

    #[test]
    fn a_record_costs_its_kept_text_and_a_few_words() {
        // Nothing signs the index, so a mirror chooses how its records are laid
        // out, and a record's cost must not depend on that: its text fields
        // share one allocation and its classes stay text, so the rest of it is
        // fixed. Ten words, where a field each and parsed classes were forty.
        assert!(size_of::<Record>() <= 10 * size_of::<usize>());
        // The builds of a name keep the order the index published them in,
        // however the names are interleaved.
        let stanza = |name: &str, build: u64| {
            format!(
                "BUILD_ID: {build}\nCPV: {name}-1\nMD5: d41d8cd98f00b204e9800998ecf8427e\n\
                 PATH: a/b.gpkg.tar\nSIZE: 1\n\n"
            )
        };
        let index = Index::parse(&format!(
            "TIMESTAMP: 1\n\n{}{}{}{}",
            stanza("b/x", 3),
            stanza("a/y", 1),
            stanza("b/x", 1),
            stanza("b/x", 2),
        ));
        let builds: Vec<u64> = index
            .builds("b/x")
            .iter()
            .map(|build| build.build_id)
            .collect();
        assert_eq!(builds, [3, 1, 2]);
        assert_eq!(index.builds("a/y").len(), 1);
        assert!(index.builds("a/x").is_empty());
        assert!(index.builds("c/z").is_empty());
    }

    #[test]
    fn a_dependency_class_past_its_bound_is_left_out_and_counted() {
        // A class is parsed to be checked as it is read, and what that holds at
        // once is bounded by the class's length.
        let stanza = |rdepend: &str| {
            format!(
                "BUILD_ID: 1\nCPV: sys-libs/zlib-1.3.1\nMD5: d41d8cd98f00b204e9800998ecf8427e\n\
                 PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar\nRDEPEND: {rdepend}\nSIZE: 1\n\n"
            )
        };
        let at_bound = "a/b ".repeat(MAX_CLASS_BYTES / 4);
        let at_bound = at_bound.trim_end();
        let past_bound = format!("{at_bound} a/bc");
        assert!(at_bound.len() <= MAX_CLASS_BYTES && past_bound.len() > MAX_CLASS_BYTES);
        let index = Index::parse(&format!(
            "TIMESTAMP: 1\n\n{}{}",
            stanza(at_bound),
            stanza(&past_bound),
        ));
        assert_eq!(index.records().len(), 1);
        assert_eq!(index.skipped(), 1);
        assert_eq!(index.records()[0].runtime().len(), MAX_CLASS_BYTES / 4);
        assert!(read_class(&past_bound).is_err());
    }

    #[test]
    fn a_field_past_its_bound_is_left_out_and_counted() {
        // Nothing signs the index, so each field a record keeps is held to a
        // length before anything parses it: what a record costs, and what a
        // resolution copies out of one into a refusal, cannot be a mirror's to
        // decide. A field at its bound is kept; one byte past it is not.
        let stanza = |cpv: &str, slot: &str, flags: &str, iuse: &str, path: &str| {
            format!(
                "BUILD_ID: 1\nCPV: {cpv}\nIUSE: {iuse}\nMD5: d41d8cd98f00b204e9800998ecf8427e\n\
                 PATH: {path}\nSIZE: 1\nSLOT: {slot}\nUSE: {flags}\n\n"
            )
        };
        let cpv = |length: usize| format!("a/b-1{}", "0".repeat(length - "a/b-1".len()));
        let text = |length: usize| "f".repeat(length);
        let path = |length: usize| format!("a/b/{}", "c".repeat(length - "a/b/".len()));
        let at = |field: &str, length: usize| {
            stanza(
                &cpv(if field == "CPV" { length } else { 8 }),
                &text(if field == "SLOT" { length } else { 1 }),
                &text(if field == "USE" { length } else { 1 }),
                &text(if field == "IUSE" { length } else { 1 }),
                &path(if field == "PATH" { length } else { 16 }),
            )
        };
        for (field, max) in [
            ("CPV", version::MAX_CPV_BYTES),
            ("SLOT", MAX_SLOT_BYTES),
            ("USE", MAX_FLAGS_BYTES),
            ("IUSE", MAX_FLAGS_BYTES),
            ("PATH", MAX_PATH_BYTES),
        ] {
            let index = Index::parse(&format!(
                "TIMESTAMP: 1\n\n{}{}",
                at(field, max),
                at(field, max + 1),
            ));
            assert_eq!(index.records().len(), 1, "{field}");
            assert_eq!(index.skipped(), 1, "{field}");
            let kept = &index.records()[0];
            let length = match field {
                "CPV" => kept.name().len() + 1 + kept.version().len(),
                "SLOT" => kept.slot().len(),
                "USE" => kept.use_flags().len(),
                "IUSE" => kept.iuse().len(),
                _ => kept.path().len(),
            };
            assert_eq!(length, max, "{field}: the one at its bound is the one kept");
        }
    }

    #[test]
    fn the_catalogue_lists_names_once_and_versions_in_order() {
        let catalogue = Index::parse(FIXTURE).into_catalogue();
        assert_eq!(catalogue.len(), 3);
        assert_eq!(catalogue.builds(), 4);
        assert!(!catalogue.is_empty());
        assert_eq!(
            catalogue.names().collect::<Vec<_>>(),
            ["acct-group/3proxy", "dev-vcs/git", "sys-libs/zlib"],
        );
        // Two builds of one version list that version once.
        assert_eq!(
            catalogue.versions("dev-vcs/git").collect::<Vec<_>>(),
            ["2.54.0"]
        );
        assert!(catalogue.contains("sys-libs/zlib"));
        assert!(!catalogue.contains("app-misc/jq"));
        assert_eq!(catalogue.versions("app-misc/jq").count(), 0);
        assert_eq!(catalogue.generated(), Some(1_787_145_736));
        assert_eq!(catalogue.ttl(), Some(3600));
        assert_eq!(catalogue.chost(), Some("aarch64-unknown-linux-gnu"));
    }

    #[test]
    fn the_index_directory_is_composed_from_the_two_coordinates() {
        assert_eq!(
            directory("amd64", "x86-64"),
            "releases/amd64/binpackages/23.0/x86-64",
        );
    }
}
