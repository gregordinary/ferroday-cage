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

use std::collections::HashMap;

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

/// One published build: what the resolver chooses between, and what the merge
/// needs to fetch and register it.
///
/// The fields are those two sets and nothing else. A stanza carries a good deal
/// more — `LICENSE`, `DESCRIPTION`, `RESTRICT`, the build-time dependency
/// classes — and the whole index is fifteen thousand of them, so what is not
/// read is not kept.
#[derive(Debug, Clone)]
pub(super) struct Record {
    /// `category/name`, as the archive publishes it.
    pub name: String,
    /// The version, without the category or the name.
    pub version: String,
    /// Which build of that version this is, from `BUILD_ID`.
    pub build_id: u64,
    /// When it was built, from `BUILD_TIME`, seconds since the epoch.
    pub build_time: i64,
    /// The slot, `slot` or `slot/subslot`, defaulting to [`DEFAULT_SLOT`].
    pub slot: String,
    /// The flags the build was compiled with, space-separated as the index
    /// writes them.
    ///
    /// Held as the index's own string rather than as a parsed list: the index
    /// carries a quarter of a million flag tokens across its stanzas, and every
    /// question asked of them is membership or a count.
    pub use_flags: String,
    /// The flags the package knows, space-separated, each possibly carrying the
    /// `+` or `-` prefix that states the ebuild's own default.
    ///
    /// The prefixes are stripped on the way out rather than on the way in, so
    /// what is held is what the archive published.
    pub iuse: String,
    /// The runtime dependencies, from `RDEPEND`.
    pub rdepend: Vec<Dependency>,
    /// The post-merge dependencies, from `PDEPEND`.
    ///
    /// Kept apart from [`rdepend`](Self::rdepend) rather than folded into it,
    /// because the distinction is what breaks a cycle: a `PDEPEND` is satisfied
    /// after the package is merged rather than before, so it belongs to the
    /// closure and not to the install order.
    pub pdepend: Vec<Dependency>,
    /// The container's path under the binhost directory, from `PATH`.
    pub path: String,
    /// The container's length in bytes, from `SIZE`, which bounds its download.
    pub size: u64,
    /// The container's MD5, from `MD5`, lowercase hex.
    ///
    /// Not a trust decision and never used as one: it is what portage records
    /// as a merged package's `BINPKGMD5`, its own bookkeeping note of which
    /// binary package a database entry came from. What holds the bytes to the
    /// archive is the signed `Manifest` inside the container.
    pub md5: String,
}

impl Record {
    /// The `CPV` the archive publishes this build under.
    pub(super) fn cpv(&self) -> String {
        format!("{}-{}", self.name, self.version)
    }

    /// How many flags the build was compiled with, which is the resolver's
    /// default preference among the builds of one version.
    pub(super) fn use_count(&self) -> usize {
        self.use_flags.split_ascii_whitespace().count()
    }

    /// Whether the build was compiled with `flag`.
    pub(super) fn has_use(&self, flag: &str) -> bool {
        self.use_flags
            .split_ascii_whitespace()
            .any(|held| held == flag)
    }

    /// Whether the package knows `flag` at all, whether or not it is enabled.
    ///
    /// The `+` and `-` prefixes an `IUSE` entry may carry state the ebuild's
    /// own default and are not part of the name, so they are stripped here.
    fn knows_use(&self, flag: &str) -> bool {
        self.iuse
            .split_ascii_whitespace()
            .any(|held| held.trim_start_matches(['+', '-']) == flag)
    }

    /// Why this record's `PATH` cannot be fetched, or `None` where it can.
    ///
    /// Nothing signs the index, so the path is a mirror's string with nothing
    /// vouching for it, and it becomes directory segments of a URL and of a
    /// cache entry. It is held to the same nested-coordinate rule the stage3's
    /// own archive path is, and it must stay under the binhost directory
    /// rather than climbing out of it.
    fn unaddressable(&self) -> Option<String> {
        coordinate::check("the index's package path", &self.path, Nesting::Nested).err()
    }
}

impl atom::Candidate for Record {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn slot(&self) -> &str {
        &self.slot
    }

    fn use_flag(&self, flag: &str) -> Option<bool> {
        // Enabled beats known: a build's `USE` carries flags its `IUSE` does
        // not — `amd64`, `elibc_glibc`, `kernel_linux` are in every record's
        // `USE` and in no package's `IUSE` — so asking `IUSE` first would
        // report an enabled flag as unknown and hand the answer to the atom's
        // default.
        if self.has_use(flag) {
            Some(true)
        } else if self.knows_use(flag) {
            Some(false)
        } else {
            None
        }
    }
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
    records: Vec<Record>,
    /// Where each package name's builds sit in [`records`](Self::records), in
    /// index order.
    by_name: HashMap<String, Vec<usize>>,
    /// How many stanzas were read but not kept.
    skipped: usize,
}

impl Index {
    /// Parses an index document.
    ///
    /// The first stanza is the preamble and every stanza after it is a build. A
    /// stanza that is not one this layer can act on — no `CPV` it can split, a
    /// `PATH` that would not stay inside the archive, a dependency class it
    /// cannot read — is left out and counted rather than failing the whole
    /// index: an unsigned document is one a mirror composes, and letting a
    /// single stanza refuse fifteen thousand others would make a denial of
    /// service out of a typo.
    pub(super) fn parse(text: &str) -> Index {
        let stanzas = document::parse(text);
        let (preamble, rest) = match stanzas.split_first() {
            Some((first, rest)) => (read_preamble(first), rest),
            None => (Preamble::default(), &[][..]),
        };
        let mut records = Vec::with_capacity(rest.len());
        let mut skipped = 0;
        for stanza in rest {
            match read_record(stanza) {
                Some(record) if record.unaddressable().is_none() => records.push(record),
                _ => skipped += 1,
            }
        }
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (at, record) in records.iter().enumerate() {
            by_name.entry(record.name.clone()).or_default().push(at);
        }
        Index {
            preamble,
            records,
            by_name,
            skipped,
        }
    }

    /// What the preamble said.
    pub(super) fn preamble(&self) -> &Preamble {
        &self.preamble
    }

    /// Every build the index publishes, in the order it published them.
    pub(super) fn records(&self) -> &[Record] {
        &self.records
    }

    /// Every build published under `name`, in index order.
    pub(super) fn builds(&self, name: &str) -> impl Iterator<Item = &Record> {
        self.by_name
            .get(name)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(|at| &self.records[*at])
    }

    /// Whether the index publishes `name` in any version.
    pub(super) fn publishes(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// How many stanzas were read but not kept.
    pub(super) fn skipped(&self) -> usize {
        self.skipped
    }

    /// Projects the index onto the public discovery surface, consuming it.
    ///
    /// The dependency vectors go: what a caller asking what is on offer wants
    /// is the names and their versions, and keeping ninety thousand parsed
    /// atoms to back a membership question would be the wrong trade.
    pub(super) fn into_catalogue(self) -> Catalogue {
        let mut names: Vec<String> = Vec::with_capacity(self.by_name.len());
        let mut versions: HashMap<String, Vec<String>> = HashMap::new();
        for (name, at) in self.by_name {
            let mut published: Vec<String> = at
                .into_iter()
                .map(|at| self.records[at].version.clone())
                .collect();
            // One version published as several builds appears once here: the
            // builds differ in USE rather than in what they are a version of,
            // and choosing among them is the resolver's question rather than a
            // reader's.
            published.sort_by(|a, b| version::compare(a, b).unwrap_or_else(|| a.cmp(b)));
            published.dedup();
            names.push(name.clone());
            versions.insert(name, published);
        }
        names.sort();
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
fn read_preamble(stanza: &Stanza) -> Preamble {
    Preamble {
        generated: stanza.get("TIMESTAMP").and_then(|text| text.parse().ok()),
        ttl: stanza.get("TTL").and_then(|text| text.parse().ok()),
        chost: stanza.get("CHOST").map(str::to_string),
        declared: stanza.get("PACKAGES").and_then(|text| text.parse().ok()),
    }
}

/// Reads one build's stanza, or `None` where it is not one.
fn read_record(stanza: &Stanza) -> Option<Record> {
    let cpv = stanza.get("CPV")?;
    let (category, package, version) = version::split_cpv(cpv)?;
    let name = format!("{category}/{package}");
    if !atom::is_package(&name) {
        return None;
    }
    Some(Record {
        name,
        version: version.to_string(),
        build_id: stanza.get("BUILD_ID")?.parse().ok()?,
        // Absent or unreadable is the epoch rather than a refusal: the value is
        // the last of three ranking keys, so a record without one ranks last
        // among equals instead of not being a candidate.
        build_time: stanza
            .get("BUILD_TIME")
            .and_then(|text| text.parse().ok())
            .unwrap_or(0),
        slot: stanza.get("SLOT").unwrap_or(DEFAULT_SLOT).to_string(),
        use_flags: stanza.get("USE").unwrap_or_default().to_string(),
        iuse: stanza.get("IUSE").unwrap_or_default().to_string(),
        rdepend: atom::parse_class(stanza.get("RDEPEND").unwrap_or_default()).ok()?,
        pdepend: atom::parse_class(stanza.get("PDEPEND").unwrap_or_default()).ok()?,
        path: stanza.get("PATH")?.to_string(),
        size: stanza.get("SIZE")?.parse().ok()?,
        md5: stanza.get("MD5")?.to_string(),
    })
}

/// The two names the index is published under, in preference order.
///
/// The compressed form first: it is a tenth of the bytes for identical content,
/// and reading it costs nothing to implement because
/// [`compress::decompress`](super::super::compress::decompress) selects a
/// decoder by magic rather than by file name. No other compression is
/// published: `.xz`, `.bz2` and `.zst` are all 404.
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
/// [`Available`](super::Available), and it answers the question a caller has
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
    /// The versions of each name, ordered lowest first and deduplicated across
    /// the builds of one version.
    versions: HashMap<String, Vec<String>>,
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
        self.versions
            .get(name)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(String::as_str)
    }

    /// Whether the binhost publishes `name` in any version.
    pub fn contains(&self, name: &str) -> bool {
        self.versions.contains_key(name)
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
        let index = Index::parse(FIXTURE);
        assert_eq!(index.records().len(), 4);
        assert_eq!(index.skipped(), 0);

        let zlib = index
            .builds("sys-libs/zlib")
            .next()
            .expect("zlib is published");
        assert_eq!(zlib.version, "1.3.1-r1");
        assert_eq!(zlib.slot, "0/1");
        assert_eq!(zlib.size, 204_800);
        assert_eq!(zlib.build_id, 1);
        assert_eq!(zlib.cpv(), "sys-libs/zlib-1.3.1-r1");
        assert_eq!(zlib.rdepend.len(), 2);

        // A stanza with no SLOT is the default slot rather than no slot.
        let group = index
            .builds("acct-group/3proxy")
            .next()
            .expect("the group is published");
        assert_eq!(group.slot, DEFAULT_SLOT);
        assert!(group.rdepend.is_empty());
    }

    #[test]
    fn one_version_published_twice_is_two_builds() {
        let index = Index::parse(FIXTURE);
        let builds: Vec<&Record> = index.builds("dev-vcs/git").collect();
        assert_eq!(builds.len(), 2);
        assert!(builds.iter().all(|build| build.version == "2.54.0"));
        // The builds differ in USE, and therefore in what they pull in: that is
        // the whole reason the unit here is the build.
        assert_eq!(builds[0].use_count(), 3);
        assert_eq!(builds[1].use_count(), 4);
        assert!(!builds[0].has_use("keyring"));
        assert!(builds[1].has_use("keyring"));
        assert_ne!(builds[0].rdepend.len(), builds[1].rdepend.len());
    }

    #[test]
    fn a_records_use_answers_before_its_iuse_does() {
        use super::atom::Candidate as _;

        let index = Index::parse(FIXTURE);
        let git = index
            .builds("dev-vcs/git")
            .next()
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
MD5: d41d8cd98f00b204e9800998ecf8427e
PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar
SIZE: 1
";
        let index = Index::parse(refused);
        // The traversal is the one that matters: nothing signs the index, so
        // its PATH is a mirror's string and it becomes a URL and a cache entry.
        assert_eq!(index.records().len(), 1);
        assert_eq!(index.skipped(), 3);
        assert!(index.publishes("sys-libs/zlib"));
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
