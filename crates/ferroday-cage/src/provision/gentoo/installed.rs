//! `/var/db/pkg`: what a Gentoo root already has, read from its own package
//! database.
//!
//! This is where the layer departs from the other two, and the departure is
//! structural rather than a detail. A Debian or Alpine bootstrap starts with an
//! empty root and the archive is the only source of truth, so resolution asks
//! what is *needed*. A Gentoo root arrives as a stage3, which unpacks with 296
//! packages already installed and a database describing them, so resolution
//! here asks what is *missing*.
//!
//! That is load-bearing rather than an optimisation. Of the 296 packages an
//! `amd64-openrc` stage3 ships, 295 are exact `CPV` matches in the binhost
//! index and one — `app-crypt/pinentry` — the binhost does not publish in any
//! version at all. It is in `dev-vcs/git`'s runtime closure, so a resolver that
//! read only the index would refuse to install git into a root that already
//! satisfies the dependency. The general case is the same one: the median
//! closure over four hundred sampled packages is five, because everything else
//! is already there.
//!
//! # The layout
//!
//! ```text
//! /var/db/pkg/sys-libs/zlib-1.3.1-r1/
//!             ^^^^^^^^ ^^^^^^^^^^^^^
//!             |        the entry directory, which is the package's `PF`
//!             the category, which is the parent directory
//! ```
//!
//! The category and the version are the directory names; `SLOT` and `USE` are
//! one-line files inside the entry. That is everything an atom is matched
//! against. `RDEPEND` and `PDEPEND` beside them carry the blockers the package
//! states, which bind what a resolution may install into the same root.
//!
//! # The tree is read as an untrusted one
//!
//! Through [`Rooted`], which resolves every path against the root's own
//! descriptor. The tree was written by an extractor from an archive a mirror
//! served, and a root this crate did not build may have had anything run in it,
//! so a symbolic link at `var/db/pkg` is a thing that can be there. Resolved
//! this way it names something inside the tree or nothing at all.

use std::collections::BTreeSet;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use rustix::fs::{OFlags, ResolveFlags};
use rustix::io::Errno;

use super::atom::{self, Atom, Candidate, Dependency};
use super::version;
use super::{COUNTER_FILE, DB_DIR, GentooError, MAX_METADATA_BYTES};
use crate::provision::containment;
use crate::provision::rooted::Rooted;

/// The file inside an entry naming its slot.
const SLOT_FILE: &str = "SLOT";

/// The file inside an entry naming the flags it was built with.
const USE_FILE: &str = "USE";

/// The file inside an entry naming every flag the package knows, implicit ones
/// included.
///
/// Preferred over `IUSE` because it is what portage evaluates a USE dependency
/// against: `IUSE` names what the ebuild declared, and this adds the flags the
/// profile makes implicit — the architecture names, `elibc_*`, `kernel_*` —
/// which an atom is entitled to ask about.
const IUSE_EFFECTIVE_FILE: &str = "IUSE_EFFECTIVE";

/// The file naming what the ebuild itself declared, read where an entry carries
/// no `IUSE_EFFECTIVE`.
const IUSE_FILE: &str = "IUSE";

/// The file inside an entry naming the target triple the package was built for.
const CHOST_FILE: &str = "CHOST";

/// The two files holding an entry's runtime dependencies, the classes whose
/// blockers bind for as long as the package is installed.
///
/// The same two the resolver reads of an index record. Portage writes both
/// USE-evaluated, as the index publishes them, so they are read with the same
/// grammar.
const RUNTIME_DEPENDENCY_FILES: [&str; 2] = ["RDEPEND", "PDEPEND"];

/// The prefix portage gives an entry it is part way through merging.
///
/// An interrupted merge leaves one behind, and it describes a package that is
/// not installed. It is skipped rather than read or refused: the marker is
/// portage's own and says exactly what the directory is, and a root that has
/// one is a root a merge was interrupted in rather than a malformed one.
const MERGING_PREFIX: &str = "-MERGING-";

/// One package a root already has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    /// `category/name`.
    name: String,
    /// The version, without the category or the name.
    version: String,
    /// The slot, `slot` or `slot/subslot`, as the entry's `SLOT` file spells
    /// it.
    slot: String,
    /// The flags the package was built with, space-separated as its `USE` file
    /// spells them.
    use_flags: String,
    /// Every flag the package knows, whether or not it is enabled, from its
    /// `IUSE_EFFECTIVE` or its `IUSE`.
    ///
    /// Not exposed: what a caller asks of an installed package is what it *is*,
    /// and this is what an atom is matched against. Reading it is what tells
    /// "the package knows this flag and it is off" from "the package has never
    /// heard of it", and the difference decides whether an atom with no
    /// `(+)`/`(-)` default can be answered at all.
    iuse: String,
    /// The blockers its runtime dependencies state: what must not be installed
    /// beside it.
    ///
    /// Not exposed, for the reason [`iuse`](Self::iuse) is not: it is what a
    /// resolution holds its choices to, rather than what a caller asks of an
    /// installed package. A blocker inside an any-of group is one alternative
    /// among several and binds nothing on its own, so only the plain ones are
    /// kept, which is the reading the resolver gives a chosen build's own.
    blockers: Vec<Atom>,
    /// The ordinal its merge was stamped with, where the entry records one
    /// that parses.
    ///
    /// Not exposed: it is the root's bookkeeping rather than anything about
    /// the package, and the one question asked of it is which is greatest; see
    /// [`Installed::last_counter`].
    counter: Option<u64>,
    /// The target triple the package was built for, from its `CHOST` file,
    /// where the entry carries one.
    ///
    /// Not exposed, for the reason [`iuse`](Self::iuse) is not: it is what a
    /// binary package merged into the root is held to, through
    /// [`Installed::targets`].
    chost: Option<String>,
}

impl InstalledPackage {
    /// The package, as `category/name`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The version that is installed.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The slot it occupies: `slot`, or `slot/subslot` where the package
    /// states a sub-slot.
    ///
    /// Spelled as the entry does, sub-slot included, because that is what an
    /// atom's slot dependency is matched against — `dev-libs/openssl:0/3=`
    /// answers only for a package whose sub-slot is `3`.
    pub fn slot(&self) -> &str {
        &self.slot
    }

    /// The USE flags the package was built with.
    pub fn use_flags(&self) -> impl Iterator<Item = &str> {
        self.use_flags.split_ascii_whitespace()
    }

    /// The blockers the package's runtime dependencies state.
    pub(super) fn blockers(&self) -> &[Atom] {
        &self.blockers
    }
}

impl Candidate for InstalledPackage {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn slot(&self) -> &str {
        &self.slot
    }

    fn flag_lists(&self) -> (&str, &str) {
        // The index's records answer through the same rule, which is what
        // keeps the two ends of resolution reading one grammar.
        //
        // What is this end's own is which file fills `iuse`. Reading
        // `IUSE_EFFECTIVE` rather than `IUSE` is not a small difference: every
        // `dev-perl` package depends on
        // `>=dev-lang/perl-5.38.2-r3[-perl_features_debug,...]` with no
        // `(+)`/`(-)` default, and a stage3's perl carries none of those flags
        // in its `USE` and all of them in its `IUSE_EFFECTIVE`. Without the
        // second file the atom cannot be answered, and a root that already has
        // perl installs it again.
        (&self.use_flags, &self.iuse)
    }
}

/// What a Gentoo root already has installed.
///
/// Produced by [`installed`], and read from the root's own `/var/db/pkg` rather
/// than from anything this crate recorded when it built the root — so a root
/// this crate never touched reads the same as one it bootstrapped.
#[derive(Debug, Clone, Default)]
pub struct Installed {
    /// The packages, ordered by `category/name` and then by slot, so two reads
    /// of one root are the same read.
    packages: Vec<InstalledPackage>,
}

impl Installed {
    /// Every package the root has, ordered by name and then by slot.
    pub fn packages(&self) -> impl Iterator<Item = &InstalledPackage> {
        self.packages.iter()
    }

    /// How many there are. A stage3 has around three hundred.
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    /// Whether the root has none, which a provisioned Gentoo root never does.
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// The target triples the root's packages were built for: every `CHOST`
    /// its database states, which a stage3's states as one.
    ///
    /// What a binary package merged into the root is held to. A root built for
    /// one target holds packages built for it, and a package built for another
    /// is one its programs cannot run beside. Empty for a root whose database
    /// states none.
    pub(super) fn targets(&self) -> BTreeSet<String> {
        self.packages
            .iter()
            .filter_map(|package| package.chost.clone())
            .collect()
    }

    /// Every installed package published under `name`, which is more than one
    /// where the root holds several slots of it.
    ///
    /// Found by halving rather than by a walk, since the packages are held in
    /// name order: the resolver asks this of every atom it meets, and a walk
    /// would make each question cost the whole root.
    pub(super) fn under(&self, name: &str) -> impl Iterator<Item = &InstalledPackage> {
        let first = self
            .packages
            .partition_point(|package| package.name.as_str() < name);
        self.packages[first..]
            .iter()
            .take_while(move |package| package.name == name)
    }

    /// The greatest ordinal any entry records a merge was stamped with, or zero
    /// where none records one.
    ///
    /// Half of where a merge's own ordinal continues from, the root's counter
    /// file being the other: portage takes the greater of the two, because a
    /// counter file that was removed or rolled back would otherwise reissue
    /// ordinals the database already holds. An entry recording none, or one
    /// that does not parse, is passed over, as portage passes it over.
    pub(super) fn last_counter(&self) -> u64 {
        self.packages
            .iter()
            .filter_map(|package| package.counter)
            .max()
            .unwrap_or(0)
    }

    /// A set of packages spelled out, for a test that needs a root without a
    /// tree to read one from.
    ///
    /// Each entry is its name, version, slot, and the flags it was built with —
    /// which stand in for the flags it knows as well, since a fixture that has
    /// to state both twice states neither clearly.
    #[cfg(test)]
    pub(super) fn of(entries: Vec<(String, String, String, String)>) -> Installed {
        Installed::sorted(
            entries
                .into_iter()
                .map(|(name, version, slot, use_flags)| InstalledPackage {
                    name,
                    version,
                    slot,
                    iuse: use_flags.clone(),
                    use_flags,
                    blockers: Vec::new(),
                    counter: None,
                    chost: None,
                })
                .collect(),
        )
    }

    /// The same set, with the package published under `name` stating
    /// `blockers` as its runtime dependencies would.
    #[cfg(test)]
    pub(super) fn blocking(mut self, name: &str, blockers: &[&str]) -> Installed {
        let package = self
            .packages
            .iter_mut()
            .find(|package| package.name == name)
            .expect("the fixture root holds the package");
        package.blockers = blockers
            .iter()
            .map(|text| atom::parse(text).expect("a fixture blocker"))
            .collect();
        self
    }

    /// Puts the entries in the order the type promises.
    ///
    /// The version is the last tiebreak and is compared as a version rather than
    /// as text, through the layer's own comparator. Only determinism rests on
    /// it — the type promises `category/name` and then slot, and two entries
    /// reaching the third key differ only in version — but a root holding
    /// `1.9` and `1.10` of one package in one slot is a root portage can
    /// produce, and reporting them the wrong way round would be a listing a
    /// reader has to distrust.
    ///
    /// Every version here is one the comparator orders: an entry's version is
    /// what [`version::split_cpv`] split off its directory name, and that split
    /// is made only where what follows parses as a version.
    fn sorted(mut packages: Vec<InstalledPackage>) -> Installed {
        packages.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.slot.cmp(&b.slot))
                .then_with(|| {
                    version::compare(&a.version, &b.version)
                        .expect("an installed version is one split_cpv found to parse")
                })
        });
        Installed { packages }
    }
}

/// What the Gentoo root at `root` already has installed.
///
/// A free function rather than a method on [`Gentoo`](super::Gentoo), because
/// the question needs no configured provisioner: any Gentoo root can be asked,
/// including one this crate did not build. It reaches no network and downloads
/// nothing.
///
/// # Errors
///
/// Returns [`GentooError::Database`] for a tree whose `/var/db/pkg` holds
/// something that is not a package entry — a directory that does not name a
/// `name-version`, one naming a category or a package the package manager
/// specification does not permit, one carrying no `SLOT`, or one whose runtime
/// dependencies do not parse — and [`GentooError::Io`] where the tree could
/// not be read. A root with no `/var/db/pkg` at all reports no packages rather
/// than failing: an empty answer is a true one about a directory that is not
/// there.
///
/// # Example
///
/// ```no_run
/// use ferroday_cage::provision::gentoo;
///
/// # fn main() -> Result<(), ferroday_cage::provision::gentoo::GentooError> {
/// let installed = gentoo::installed("/var/lib/machines/gentoo")?;
/// println!("{} packages", installed.len());
/// for package in installed.packages() {
///     println!("{}-{} :{}", package.name(), package.version(), package.slot());
/// }
/// # Ok(())
/// # }
/// ```
pub fn installed(root: impl AsRef<Path>) -> Result<Installed, GentooError> {
    let root = root.as_ref();
    let rooted = Rooted::open(root).map_err(GentooError::at("opening the root", root))?;
    Ok(Installed::sorted(read_database(&rooted, root)?))
}

/// Reads every entry of the database, or reports the first that is not one.
///
/// `at` names the root in a failure; nothing resolves through it.
fn read_database(rooted: &Rooted, at: &Path) -> Result<Vec<InstalledPackage>, GentooError> {
    entries(rooted, at)?
        .iter()
        .map(|(category, pf)| read_entry(&Layers::Plain(rooted), at, category, pf))
        .collect()
}

/// Every entry directory the database holds, as its category and its `PF`, in
/// a stable order.
///
/// An interrupted merge's entry is skipped: see [`MERGING_PREFIX`].
fn entries(rooted: &Rooted, at: &Path) -> Result<Vec<(String, String)>, GentooError> {
    let mut found = Vec::new();
    let categories = rooted
        .directories(DB_DIR)
        .map_err(GentooError::at("reading the package database", at))?;
    for category in categories {
        let Ok(category) = String::from_utf8(category) else {
            // A category is a path segment of an atom, so one that is not UTF-8
            // is not a category whatever else it is.
            return Err(GentooError::database(
                at,
                "the package database holds a category whose name is not UTF-8",
            ));
        };
        let dir = format!("{DB_DIR}/{category}");
        let entries = rooted
            .directories(&dir)
            .map_err(GentooError::at("reading a package database category", at))?;
        for entry in entries {
            let Ok(pf) = String::from_utf8(entry) else {
                return Err(GentooError::database(
                    at,
                    format!("{dir:?} holds an entry whose name is not UTF-8"),
                ));
            };
            if pf.starts_with(MERGING_PREFIX) {
                continue;
            }
            found.push((category.clone(), pf));
        }
    }
    Ok(found)
}

/// The layers one entry's files are read from.
///
/// A plain root holds each entry whole. An overlay's merged view need not: an
/// entry directory the upper holds and the base holds too is the union of the
/// two, because overlayfs copies up only what changes. An entry one file of
/// which a command inside the sandbox rewrote holds that file alone in the
/// upper, and every other file of it in the base.
enum Layers<'a> {
    /// One tree, holding every entry whole.
    Plain(&'a Rooted),
    /// An overlay upper over a base: each file is the upper's where the upper
    /// names it, and otherwise the base's, where `lower` is given because the
    /// upper does not hide the base's entry as a whole.
    Over {
        /// The upper.
        upper: &'a Rooted,
        /// The base, where its entry shows through.
        lower: Option<&'a Rooted>,
    },
}

impl Layers<'_> {
    /// The file at `path`, or `None` where the entry holds none.
    ///
    /// A whiteout in the upper is the file removed, so the base's copy beneath
    /// it is not read; [`Rooted::is_whiteout`] tells one from a file.
    fn read(&self, path: &str) -> io::Result<Option<Vec<u8>>> {
        match *self {
            Layers::Plain(tree) => tree.read_if_present(path, MAX_METADATA_BYTES),
            Layers::Over { upper, lower } => match upper.stat(path)? {
                Some(stat) if Rooted::is_whiteout(&stat) => Ok(None),
                Some(_) => upper.read_if_present(path, MAX_METADATA_BYTES),
                None => match lower {
                    Some(lower) => lower.read_if_present(path, MAX_METADATA_BYTES),
                    None => Ok(None),
                },
            },
        }
    }
}

/// Reads one entry: its name and version from the two directory names, its slot
/// and flags from the files inside, each read through `layers`.
fn read_entry(
    layers: &Layers<'_>,
    at: &Path,
    category: &str,
    pf: &str,
) -> Result<InstalledPackage, GentooError> {
    let dir = format!("{DB_DIR}/{category}/{pf}");
    // The entry's own two directory names spell a `CPV`, and splitting that is
    // what tells the package name from the version -- the entry directory holds
    // both with a hyphen between them and no marker for where it is.
    let cpv = format!("{category}/{pf}");
    let Some((category, package, version)) = version::split_cpv(&cpv) else {
        return Err(GentooError::database(
            at,
            format!("{dir:?} does not name a package and a version"),
        ));
    };
    // The two directory names are whatever the tree holds, and the name they
    // spell is what a resolution reports a package by, bare. Holding it to the
    // specification's alphabet is what lets it be named so: none of its
    // characters is a control character. The version is held by the split.
    let name = format!("{category}/{package}");
    if !atom::is_package(&name) {
        return Err(GentooError::database(
            at,
            format!("{dir:?} names a package the package manager specification does not permit"),
        ));
    }
    // Each file of an entry is one of a binary package's metadata files, which
    // a container holds to `MAX_METADATA_BYTES` together; one past that alone
    // is not one portage wrote.
    let field = |file: &str| -> Result<Option<String>, GentooError> {
        layers
            .read(&format!("{dir}/{file}"))
            .map(|bytes| bytes.as_deref().map(field_text))
            .map_err(|err| GentooError::io("reading a package database entry", at, err))
    };
    // What an installed package requires is the state the root arrived in,
    // and not this layer's to hold it to.
    let (package, _) = read_package(name, version, field, |unreadable| {
        GentooError::database(
            at,
            match unreadable {
                Unreadable::NoSlot => {
                    format!("{dir:?} names a package but carries no {SLOT_FILE} file")
                }
                Unreadable::Dependencies { file, reason } => {
                    format!("{dir:?} states a {file} that cannot be read: {reason}")
                }
            },
        )
    })?;
    Ok(package)
}

impl InstalledPackage {
    /// The package a binary package's own metadata describes: what the root's
    /// database will say of `name` at `version` once the package is merged.
    /// And what it requires of the root it lands in: every dependency of its
    /// runtime and post-merge classes but its blockers, which the package
    /// carries.
    ///
    /// The merge writes a container's metadata files out as the entry
    /// verbatim, so the entry [`installed`] would read back afterwards is these
    /// files read the same way, with no merge ordinal yet. That is what lets a
    /// plan's packages be held to the root before any of them is merged.
    ///
    /// `file` answers a metadata file's bytes by its name. `name` and `version`
    /// are the plan's, which the container's own `CATEGORY` and `PF` were held
    /// to as it was read.
    ///
    /// # Errors
    ///
    /// Returns the reason where the metadata states no `SLOT`, or a runtime
    /// dependency class that does not parse, in the sentence "the package at
    /// `<path>` ..." that [`GentooError::Container`] renders.
    pub(super) fn from_metadata<'f>(
        name: &str,
        version: &str,
        file: impl Fn(&str) -> Option<&'f [u8]>,
    ) -> Result<(InstalledPackage, Vec<Dependency>), String> {
        let field =
            |name: &str| -> Result<Option<String>, String> { Ok(file(name).map(field_text)) };
        read_package(
            name.to_string(),
            version,
            field,
            |unreadable| match unreadable {
                Unreadable::NoSlot => {
                    format!(
                        "states no {SLOT_FILE} in its metadata, so it names no slot to merge into"
                    )
                }
                Unreadable::Dependencies { file, reason } => {
                    format!("states a {file} in its metadata that cannot be read: {reason}")
                }
            },
        )
    }
}

/// One file of an entry or of a container's metadata, as the value it holds:
/// its text, with the surrounding whitespace and the trailing newline dropped.
///
/// The one reading of such a file. The merge writes a container's metadata
/// out as the entry, so a container's reader (`gpkg`) and this module's read
/// the same files, and both read them through this.
pub(super) fn field_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

/// Why a set of metadata files does not describe a package.
enum Unreadable {
    /// No `SLOT`: what tells an entry from something merely shaped like one.
    NoSlot,
    /// A runtime dependency class that does not parse.
    Dependencies {
        /// Which of [`RUNTIME_DEPENDENCY_FILES`].
        file: &'static str,
        /// Why the grammar refused it.
        reason: String,
    },
}

/// Reads the package `name` at `version` out of its metadata files, each asked
/// of `field` by name, reporting files that do not describe one through
/// `refuse`. Beside the package, the dependencies it requires: those of its
/// runtime classes that are not the blockers it keeps.
///
/// The one reading of a package's files, whether they sit in a root's database
/// or in a binary package not yet merged: the merge writes the second out as the
/// first, so two readings would be two answers to what one set of files says.
fn read_package<E>(
    name: String,
    version: &str,
    field: impl Fn(&str) -> Result<Option<String>, E>,
    refuse: impl Fn(Unreadable) -> E,
) -> Result<(InstalledPackage, Vec<Dependency>), E> {
    // A missing `SLOT` is what tells an entry directory from something else
    // that happens to be shaped like one: portage writes the file for every
    // package it merges, and so does this layer.
    let Some(slot) = field(SLOT_FILE)? else {
        return Err(refuse(Unreadable::NoSlot));
    };
    // A package with no runtime dependencies may carry neither file, so their
    // absence is no blockers. One that does not parse is a gap in what the
    // root forbids, and resolving past it could install what it blocks.
    let mut blockers = Vec::new();
    let mut requires = Vec::new();
    for file in RUNTIME_DEPENDENCY_FILES {
        let class = field(file)?.unwrap_or_default();
        let parsed = atom::parse_class(&class)
            .map_err(|reason| refuse(Unreadable::Dependencies { file, reason }))?;
        for dependency in parsed {
            match dependency {
                Dependency::One(atom) if atom.blocker().is_some() => blockers.push(atom),
                requirement => requires.push(requirement),
            }
        }
    }
    let package = InstalledPackage {
        name,
        version: version.to_string(),
        slot,
        // A package built with no flags writes an empty `USE`, and portage does
        // not always write the file at all, so its absence is no flags rather
        // than a malformed entry.
        use_flags: field(USE_FILE)?.unwrap_or_default(),
        iuse: match field(IUSE_EFFECTIVE_FILE)? {
            Some(effective) => effective,
            None => field(IUSE_FILE)?.unwrap_or_default(),
        },
        blockers,
        counter: field(COUNTER_FILE)?.and_then(|text| text.parse().ok()),
        chost: field(CHOST_FILE)?.filter(|chost| !chost.is_empty()),
    };
    Ok((package, requires))
}

/// What a base root and an increment staged over it hold together.
///
/// An overlay unions its layers, so what a package manager sees inside the
/// finished sandbox is the merged view and not the upper alone. Resolution has
/// to describe that view: an increment resolving against its own upper would
/// ask the archive for everything the base already has, and would fail on the
/// packages the binhost does not publish at all.
///
/// The upper wins where both describe one package in one slot, which is what an
/// overlay does with two entries of a name. Two *slots* of one package are two
/// installed packages, so an increment that added a second slot has not
/// replaced the first — but a sub-slot is not a slot, so a package rebuilt
/// against a new one replaces what the base had rather than joining it. Matched
/// through [`slot_of`] for that reason.
///
/// A base entry the upper hides is not in the merged view at all. A package
/// removed inside a sandbox rooted on the overlay leaves a whiteout in the
/// upper where its entry was, and an entry or a category recreated there is
/// marked opaque; [`Upper::hides`] reads both the way overlayfs does.
///
/// An entry both layers hold is read file by file through the two, as
/// [`Layers`] describes. That is the shape a base entry takes once something in
/// the sandbox has changed one of its files, and the upper's directory alone
/// would read as an entry missing its `SLOT`.
pub(super) fn merged(lower: &Path, upper: &Path) -> Result<Installed, GentooError> {
    let base = Rooted::open(lower).map_err(GentooError::at("opening the root", lower))?;
    let top = Rooted::open(upper).map_err(GentooError::at("opening the overlay upper", upper))?;
    let layer = Upper::open(upper).map_err(GentooError::at("opening the overlay upper", upper))?;
    // Whether the base's entry of this name shows through the upper.
    let shows = |category: &str, pf: &str| {
        layer
            .hides(&format!("{DB_DIR}/{category}/{pf}"))
            .map(|hidden| !hidden)
            .map_err(|err| GentooError::io("reading the overlay upper", upper, err))
    };
    let held: BTreeSet<(String, String)> = entries(&top, upper)?.into_iter().collect();

    let mut packages = Vec::new();
    for (category, pf) in entries(&base, lower)? {
        if held.contains(&(category.clone(), pf.clone())) || !shows(&category, &pf)? {
            continue;
        }
        packages.push(read_entry(&Layers::Plain(&base), lower, &category, &pf)?);
    }
    for (category, pf) in &held {
        let layers = Layers::Over {
            upper: &top,
            lower: shows(category, pf)?.then_some(&base),
        };
        let above = read_entry(&layers, upper, category, pf)?;
        packages.retain(|below| {
            !(below.name == above.name && slot_of(&below.slot) == slot_of(&above.slot))
        });
        packages.push(above);
    }
    Ok(Installed::sorted(packages))
}

/// The upper layer of an overlay, read for what it hides of the layer beneath.
///
/// Read through descriptors with no symbolic link followed, since overlayfs
/// follows none inside a layer: a link in the upper at a directory's name is a
/// non-directory there, whatever it points at.
struct Upper {
    /// The upper's root. `O_PATH`: it is only ever the anchor of an `openat2`.
    fd: OwnedFd,
}

impl Upper {
    /// Opens the upper at `path`.
    fn open(path: &Path) -> io::Result<Upper> {
        let fd = rustix::fs::open(
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        Ok(Upper { fd })
    }

    /// Whether the upper hides what the lower holds at `path`, a `/`-separated
    /// path of ordinary components.
    ///
    /// Overlayfs looks a path up one component at a time, the upper first. The
    /// lower shows through while each component is, in the upper, absent or a
    /// directory that is not opaque. From the first absent one on, nothing in
    /// the upper speaks for the rest of the path. A whiteout, the character
    /// device overlayfs leaves where something of the lower was removed, hides
    /// it. So does any other non-directory, since only a directory merges with
    /// what lies beneath it. An opaque directory hides everything beneath it.
    ///
    /// The rule the layered walk (`containment::copy_up`) reads each name by,
    /// and one marker answer, `containment::is_opaque`. Where that walk resolves
    /// a path through a link, this asks about the path as spelled, since a
    /// database entry is named rather than resolved, so a link here hides.
    fn hides(&self, path: &str) -> io::Result<bool> {
        let components: Vec<&str> = path.split('/').collect();
        for depth in 1..=components.len() {
            let dir = match containment::open_dir(
                self.fd.as_fd(),
                &components[..depth],
                OFlags::RDONLY | OFlags::NOFOLLOW,
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            ) {
                Ok(dir) => dir,
                Err(Errno::NOENT) => return Ok(false),
                // The upper holds something at the name that is not a
                // directory: a whiteout, a file, or a symbolic link.
                Err(Errno::NOTDIR | Errno::LOOP) => return Ok(true),
                Err(errno) => return Err(errno.into()),
            };
            if containment::is_opaque(dir.as_fd())? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// The slot proper of a `slot` or `slot/subslot` spelling.
///
/// The sub-slot records what a dependent must be rebuilt against and is not part
/// of what a slot *is*: portage installs one instance per `(package, slot)`, and
/// two builds differing only in their sub-slot are two versions of one instance
/// rather than two. Every question about which instance a package *is* asks
/// through this — the merged view above, and the resolver's one-instance-per-slot
/// guard — where a question about what a dependent was built against reads the
/// value whole.
pub(super) fn slot_of(slot: &str) -> &str {
    slot.split_once('/').map_or(slot, |(slot, _)| slot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    /// Writes a vdb entry into `root`.
    fn entry(root: &Path, category: &str, pf: &str, slot: Option<&str>, use_flags: &str) {
        entry_knowing(root, category, pf, slot, use_flags, use_flags);
    }

    /// Writes a vdb entry whose `IUSE_EFFECTIVE` differs from its `USE`, which
    /// is every real entry: a package knows more flags than it was built with.
    fn entry_knowing(
        root: &Path,
        category: &str,
        pf: &str,
        slot: Option<&str>,
        use_flags: &str,
        iuse: &str,
    ) {
        let dir = root.join(DB_DIR).join(category).join(pf);
        std::fs::create_dir_all(&dir).expect("the entry directory is created");
        if let Some(slot) = slot {
            std::fs::write(dir.join(SLOT_FILE), format!("{slot}\n")).expect("SLOT is written");
        }
        std::fs::write(dir.join(USE_FILE), format!("{use_flags}\n")).expect("USE is written");
        std::fs::write(dir.join(IUSE_EFFECTIVE_FILE), format!("{iuse}\n"))
            .expect("IUSE_EFFECTIVE is written");
    }

    /// A root holding three packages, one of them slotted.
    fn stage3(name: &str) -> Scratch {
        let dir = Scratch::for_test("gentoo-installed", name);
        entry(
            &dir,
            "sys-libs",
            "zlib-1.3.1-r1",
            Some("0/1"),
            "amd64 minizip",
        );
        entry(&dir, "sys-apps", "util-linux-2.41.2", Some("0"), "amd64");
        entry(
            &dir,
            "app-crypt",
            "pinentry-1.3.2-r1",
            Some("0"),
            "amd64 ncurses",
        );
        dir
    }

    #[test]
    fn an_entry_is_its_two_directory_names_and_the_files_inside_it() {
        let root = stage3("read");
        let installed = installed(&*root).expect("the database is read");
        assert_eq!(installed.len(), 3);
        assert!(!installed.is_empty());

        let zlib = installed
            .packages()
            .find(|package| package.name() == "sys-libs/zlib")
            .expect("zlib is installed");
        assert_eq!(zlib.version(), "1.3.1-r1");
        // The sub-slot survives, because an atom's slot dependency is matched
        // against it.
        assert_eq!(zlib.slot(), "0/1");
        assert_eq!(zlib.use_flags().collect::<Vec<_>>(), ["amd64", "minizip"]);

        // A package name whose own hyphen precedes digits still splits at the
        // version rather than inside the name.
        let util = installed
            .packages()
            .find(|package| package.name() == "sys-apps/util-linux")
            .expect("util-linux is installed");
        assert_eq!(util.version(), "2.41.2");
    }

    #[test]
    fn the_packages_come_back_in_one_order_whatever_the_filesystem_says() {
        // Readdir order is the filesystem's, and an install order derived from
        // an unsorted read would differ between two roots holding the same
        // entries.
        let root = stage3("order");
        let installed = installed(&*root).expect("the database is read");
        let names: Vec<&str> = installed.packages().map(InstalledPackage::name).collect();
        assert_eq!(
            names,
            ["app-crypt/pinentry", "sys-apps/util-linux", "sys-libs/zlib"],
        );
    }

    #[test]
    fn a_flag_the_package_knows_and_was_not_built_with_answers_as_disabled() {
        use crate::provision::gentoo::atom;

        // The case that decides whether a root reinstalls what it has. Every
        // `dev-perl` package depends on perl with `[-perl_features_debug]` and
        // no `(+)`/`(-)` default, and a stage3's perl declares the flag and was
        // not built with it. Read from `USE` alone the atom cannot be answered;
        // read with `IUSE_EFFECTIVE` it is satisfied.
        let dir = Scratch::for_test("gentoo-installed", "iuse");
        entry_knowing(
            &dir,
            "dev-lang",
            "perl-5.42.2",
            Some("0/5.42"),
            "amd64 gdbm",
            "amd64 gdbm perl_features_debug perl_features_ithreads perl_features_quadmath",
        );
        let installed = installed(&*dir).expect("the database is read");
        let perl = installed.packages().next().expect("perl is installed");

        let admits = |text: &str| atom::parse(text).expect("a fixture atom").matches(perl);
        assert!(admits("dev-lang/perl[-perl_features_debug]"));
        assert!(!admits("dev-lang/perl[perl_features_debug]"));
        assert!(admits("dev-lang/perl[gdbm]"));
        // A flag in neither file is still only the atom's default to answer.
        assert!(!admits("dev-lang/perl[-bindist]"));
        assert!(admits("dev-lang/perl[-bindist(-)]"));
        // And the whole atom the measurement turned on.
        assert!(admits(
            ">=dev-lang/perl-5.38.2-r3[-perl_features_debug,-perl_features_ithreads,\
             -perl_features_quadmath]",
        ));
    }

    #[test]
    fn a_root_with_no_database_holds_no_packages() {
        // An empty answer is a true one about a directory that is not there,
        // and it is what lets an increment be staged over a base that has none.
        let dir = Scratch::for_test("gentoo-installed", "absent");
        let installed = installed(&*dir).expect("an absent database is not a failure");
        assert!(installed.is_empty());
    }

    #[test]
    fn an_interrupted_merge_is_skipped_and_anything_else_is_refused() {
        let dir = Scratch::for_test("gentoo-installed", "malformed");
        entry(&dir, "sys-libs", "zlib-1.3.1-r1", Some("0/1"), "amd64");
        // Portage's own marker for a merge that did not finish: it describes a
        // package that is not installed.
        entry(
            &dir,
            "sys-libs",
            "-MERGING-zlib-1.3.2",
            Some("0/1"),
            "amd64",
        );
        assert_eq!(installed(&*dir).expect("the marker is skipped").len(), 1);

        // A directory that does name a package and carries no SLOT is not an
        // entry, and is reported rather than passed over.
        entry(&dir, "sys-libs", "ncurses-6.5", None, "amd64");
        let err = installed(&*dir).expect_err("an entry with no SLOT is refused");
        assert!(matches!(err, GentooError::Database { .. }), "{err:?}");
        assert!(err.to_string().contains("SLOT"), "{err}");
    }

    #[test]
    fn a_database_name_outside_the_alphabet_is_refused_with_its_control_characters_escaped() {
        // The directory names are whatever anything run in the root left
        // there, and a resolution names the package they spell bare. One the
        // specification does not permit is refused where it is read, and the
        // refusal quotes it.
        let hostile = crate::failure::hostile::TEXT;
        for (category, pf) in [
            (hostile, "zlib-1.3.1".to_string()),
            ("sys-libs", format!("zlib{hostile}-1.3.1")),
        ] {
            let dir = Scratch::for_test("gentoo-installed", "hostile-name");
            entry(&dir, category, &pf, Some("0"), "amd64");
            let err = installed(&*dir).expect_err("the name is refused");
            assert!(matches!(err, GentooError::Database { .. }), "{err:?}");
            assert!(err.to_string().contains("does not permit"), "{err}");
            crate::failure::hostile::assert_escaped(&crate::ErrorChain::new(&err).to_string());
        }
    }

    #[test]
    fn an_increment_over_a_base_describes_the_merged_root() {
        // What an overlay shows a package manager inside the sandbox is the
        // union, so that is what resolution has to be given.
        let lower = stage3("merged-lower");
        let upper = Scratch::for_test("gentoo-installed", "merged-upper");
        entry(&upper, "dev-vcs", "git-2.54.0", Some("0"), "amd64 curl");
        // The upper wins where both describe one package in one slot -- and a
        // sub-slot bump is one slot, not two: a package rebuilt against a new
        // sub-slot replaces what the base had rather than joining it, or the
        // merged view would describe a root holding two instances of one slot.
        entry(&upper, "sys-libs", "zlib-1.3.2", Some("0/2"), "amd64");
        // A second slot of a package the lower has is a second package rather
        // than a replacement.
        entry(&upper, "sys-apps", "util-linux-2.42", Some("1"), "amd64");

        let merged = merged(&lower, &upper).expect("the merged view is read");
        assert_eq!(merged.len(), 5);
        assert_eq!(
            merged
                .under("sys-libs/zlib")
                .map(InstalledPackage::version)
                .collect::<Vec<_>>(),
            ["1.3.2"],
        );
        assert_eq!(
            merged
                .under("sys-libs/zlib")
                .map(InstalledPackage::slot)
                .collect::<Vec<_>>(),
            ["0/2"],
            "the sub-slot the upper states is what the merged view carries",
        );
        let util: Vec<&str> = merged
            .under("sys-apps/util-linux")
            .map(InstalledPackage::slot)
            .collect();
        assert_eq!(util, ["0", "1"]);
        assert!(merged.under("dev-vcs/git").next().is_some());
        assert!(merged.under("app-crypt/pinentry").next().is_some());
    }

    #[test]
    fn an_entry_carries_the_blockers_its_runtime_dependencies_state() {
        // Plain blockers bind; one inside an any-of group is an alternative
        // and binds nothing on its own; and an atom that requires rather than
        // refuses is no blocker at all.
        let dir = Scratch::for_test("gentoo-installed", "blockers");
        entry(&dir, "sys-apps", "openrc-0.62", Some("0"), "amd64");
        let at = dir.join(DB_DIR).join("sys-apps/openrc-0.62");
        std::fs::write(
            at.join("RDEPEND"),
            "!sys-apps/sysvinit >=sys-libs/glibc-2.40 || ( !app-misc/a app-misc/b )\n",
        )
        .unwrap();
        std::fs::write(at.join("PDEPEND"), "!!<sys-fs/udev-250\n").unwrap();
        let read = installed(&*dir).expect("the database is read");
        let openrc = read.packages().next().expect("openrc is installed");
        let blockers: Vec<String> = openrc.blockers().iter().map(Atom::to_string).collect();
        assert_eq!(blockers, ["!sys-apps/sysvinit", "!!<sys-fs/udev-250"]);

        // A class that does not parse is a gap in what the root forbids, and
        // is refused rather than read as forbidding nothing.
        std::fs::write(at.join("RDEPEND"), "|| ( sys-apps/a\n").unwrap();
        let err = installed(&*dir).expect_err("an unreadable class is refused");
        assert!(matches!(err, GentooError::Database { .. }), "{err:?}");
        assert!(err.to_string().contains("RDEPEND"), "{err}");
    }

    /// The names `merged` reports, in its order.
    #[test]
    fn the_last_counter_is_the_greatest_any_entry_records() {
        // Portage continues its merge ordinal from the greater of its counter
        // file and every entry's own, so a counter file that was removed does
        // not reissue an ordinal the database already holds. An entry with no
        // ordinal, or one that does not parse, is passed over.
        let dir = stage3("counter");
        let at = |pf: &str| dir.join(DB_DIR).join(pf);
        std::fs::write(at("sys-libs/zlib-1.3.1-r1").join("COUNTER"), "391").unwrap();
        std::fs::write(at("sys-apps/util-linux-2.41.2").join("COUNTER"), "17").unwrap();
        std::fs::write(at("app-crypt/pinentry-1.3.2-r1").join("COUNTER"), "x").unwrap();
        assert_eq!(installed(&*dir).expect("read").last_counter(), 391);
        assert_eq!(
            installed(&*stage3("no-counter"))
                .expect("read")
                .last_counter(),
            0
        );
    }

    #[test]
    fn a_package_reads_the_same_from_its_metadata_as_from_the_entry_it_becomes() {
        // The merge writes a container's metadata out as the entry, so the two
        // are one reading of one set of files.
        let files: [(&str, &[u8]); 4] = [
            ("SLOT", b"0/1\n"),
            ("USE", b"amd64 minizip\n"),
            ("IUSE", b"minizip static-libs\n"),
            (
                "RDEPEND",
                b"!sys-libs/zlib-ng[compat] >=sys-libs/glibc-2.40\n",
            ),
        ];
        let lookup = |name: &str| {
            files
                .iter()
                .find(|(held, _)| *held == name)
                .map(|(_, b)| *b)
        };
        let (from_metadata, requires) =
            InstalledPackage::from_metadata("sys-libs/zlib", "1.3.2", lookup)
                .expect("the metadata describes a package");
        // The blocker is the package's; what it requires of the root is the
        // rest.
        assert_eq!(
            requires,
            [Dependency::One(
                atom::parse(">=sys-libs/glibc-2.40").expect("an atom")
            )],
        );

        let dir = Scratch::for_test("gentoo-installed", "from-metadata");
        let entry = dir.join(DB_DIR).join("sys-libs/zlib-1.3.2");
        std::fs::create_dir_all(&entry).unwrap();
        for (name, bytes) in files {
            std::fs::write(entry.join(name), bytes).unwrap();
        }
        let from_entry = installed(&*dir)
            .expect("the entry reads")
            .packages()
            .next()
            .expect("one package")
            .clone();
        assert_eq!(from_metadata, from_entry);
        assert_eq!(from_metadata.slot(), "0/1");
        assert_eq!(from_metadata.use_flag("static-libs"), Some(false));
        assert_eq!(from_metadata.blockers().len(), 1);

        // Metadata naming no slot names nothing to merge into.
        let reason = InstalledPackage::from_metadata("sys-libs/zlib", "1.3.2", |_| None)
            .expect_err("no SLOT is refused");
        assert!(reason.contains("SLOT"), "{reason}");
        let reason = InstalledPackage::from_metadata("sys-libs/zlib", "1.3.2", |name| match name {
            "SLOT" => Some(&b"0"[..]),
            "PDEPEND" => Some(&b"|| ( a-b/c"[..]),
            _ => None,
        })
        .expect_err("an unreadable class is refused");
        assert!(reason.contains("PDEPEND"), "{reason}");
    }

    #[test]
    fn the_packages_under_a_name_are_that_name_s_and_no_neighbour_s() {
        // Found by halving the name-ordered list, so the names on either side
        // -- one a prefix of the asked-for name, one extending it -- are what
        // would show a boundary taken one place off.
        let installed = Installed::of(
            [
                ("dev-lang/python", "3.11.14", "3.11"),
                ("dev-lang/python", "3.12.12", "3.12"),
                ("dev-lang/python-exec", "2.4.10", "2"),
                ("dev-lang/pytho", "1", "0"),
                ("dev-lang/perl", "5.42", "0"),
            ]
            .into_iter()
            .map(|(name, version, slot)| {
                (
                    name.to_string(),
                    version.to_string(),
                    slot.to_string(),
                    String::new(),
                )
            })
            .collect(),
        );
        let under = |name: &str| -> Vec<String> {
            installed.under(name).map(|package| package.cpv()).collect()
        };
        assert_eq!(
            under("dev-lang/python"),
            ["dev-lang/python-3.11.14", "dev-lang/python-3.12.12"],
        );
        assert_eq!(
            under("dev-lang/python-exec"),
            ["dev-lang/python-exec-2.4.10"]
        );
        assert_eq!(under("dev-lang/pytho"), ["dev-lang/pytho-1"]);
        assert!(under("dev-lang/pyth").is_empty());
        assert!(under("dev-lang/ruby").is_empty());
        assert!(under("a/a").is_empty());
    }

    fn names(installed: &Installed) -> Vec<&str> {
        installed.packages().map(InstalledPackage::name).collect()
    }

    #[test]
    fn a_base_entry_the_upper_hides_is_not_in_the_merged_view() {
        // What a package manager inside the sandbox removed, the overlay
        // records in the upper: a whiteout where an entry was, or a directory
        // recreated opaque. The merged view holds neither entry, so neither may
        // count as installed.
        let lower = stage3("hidden-lower");
        let upper = Scratch::for_test("gentoo-installed", "hidden-upper");
        assert_eq!(
            names(&merged(&lower, &upper).expect("an empty upper hides nothing")),
            ["app-crypt/pinentry", "sys-apps/util-linux", "sys-libs/zlib"],
        );

        // Anything but a directory at an entry's name hides it. A whiteout is
        // the overlay's own shape for that, where the host lets one be made;
        // a regular file takes the same path through the upper.
        let zlib = upper.join(DB_DIR).join("sys-libs/zlib-1.3.1-r1");
        std::fs::create_dir_all(zlib.parent().expect("a category")).unwrap();
        let whiteout = rustix::fs::mknodat(
            rustix::fs::CWD,
            &zlib,
            rustix::fs::FileType::CharacterDevice,
            rustix::fs::Mode::empty(),
            0,
        );
        if let Err(errno) = whiteout {
            eprintln!("a whiteout cannot be made here ({errno}); hiding with a regular file");
            std::fs::write(&zlib, b"").unwrap();
        }
        assert_eq!(
            names(&merged(&lower, &upper).expect("the merged view is read")),
            ["app-crypt/pinentry", "sys-apps/util-linux"],
        );

        // A category the upper holds as an ordinary directory merges with the
        // base's, so the base's entries in it still show through.
        std::fs::create_dir_all(upper.join(DB_DIR).join("sys-apps")).unwrap();
        assert!(
            names(&merged(&lower, &upper).expect("the merged view is read"))
                .contains(&"sys-apps/util-linux")
        );

        // An opaque one does not. The marker lives in a `user.` attribute,
        // which some filesystems cannot hold.
        let crypt = upper.join(DB_DIR).join("app-crypt");
        std::fs::create_dir_all(&crypt).unwrap();
        let marked = rustix::fs::setxattr(
            &crypt,
            containment::OPAQUE,
            b"x",
            rustix::fs::XattrFlags::empty(),
        );
        if let Err(errno) = marked {
            ferroday_cage_testkit::require::OVERLAY
                .skip(format!("this filesystem refuses user attributes ({errno})"));
            return;
        }
        // `x` says the directory holds whiteouts of another form, and is not
        // opaque.
        assert!(
            names(&merged(&lower, &upper).expect("the merged view is read"))
                .contains(&"app-crypt/pinentry")
        );
        rustix::fs::setxattr(
            &crypt,
            containment::OPAQUE,
            b"y",
            rustix::fs::XattrFlags::empty(),
        )
        .expect("the marker is set");
        assert_eq!(
            names(&merged(&lower, &upper).expect("the merged view is read")),
            ["sys-apps/util-linux"],
        );
    }

    #[test]
    fn a_base_entry_changed_in_the_sandbox_is_read_through_both_layers() {
        // Overlayfs copies up what changes, so a base entry one file of which a
        // command inside the sandbox rewrote holds that file alone in the
        // upper. The merged view's entry is the union: the rewritten file from
        // the upper, every other one from the base.
        let lower = stage3("partial-lower");
        let upper = Scratch::for_test("gentoo-installed", "partial-upper");
        let zlib = upper.join(DB_DIR).join("sys-libs/zlib-1.3.1-r1");
        std::fs::create_dir_all(&zlib).unwrap();
        std::fs::write(zlib.join(USE_FILE), "amd64 minizip static-libs\n").unwrap();

        let view = merged(&lower, &upper).expect("a partly copied-up entry is read");
        assert_eq!(
            names(&view),
            ["app-crypt/pinentry", "sys-apps/util-linux", "sys-libs/zlib"],
        );
        let zlib_read = view
            .under("sys-libs/zlib")
            .next()
            .expect("zlib is installed");
        assert_eq!(zlib_read.slot(), "0/1", "the slot is the base's");
        assert_eq!(
            zlib_read.use_flags().collect::<Vec<_>>(),
            ["amd64", "minizip", "static-libs"],
            "the flags are the upper's",
        );
        assert_eq!(
            zlib_read.use_flag("static-libs"),
            Some(true),
            "a flag the base's IUSE_EFFECTIVE does not know is still answered from USE",
        );

        // A whiteout in the entry is that file removed: the base's copy beneath
        // it is not read. The overlay's own shape, where the host lets one be
        // made.
        let util = upper.join(DB_DIR).join("sys-apps/util-linux-2.41.2");
        std::fs::create_dir_all(&util).unwrap();
        if let Err(errno) = rustix::fs::mknodat(
            rustix::fs::CWD,
            util.join(USE_FILE),
            rustix::fs::FileType::CharacterDevice,
            rustix::fs::Mode::empty(),
            0,
        ) {
            ferroday_cage_testkit::require::OVERLAY.skip(format!(
                "the whiteout case: a whiteout cannot be made here ({errno})"
            ));
        } else {
            let view = merged(&lower, &upper).expect("the merged view is read");
            let util_read = view
                .under("sys-apps/util-linux")
                .next()
                .expect("util-linux is installed");
            assert_eq!(util_read.slot(), "0");
            assert_eq!(
                util_read.use_flags().count(),
                0,
                "the base's USE is removed"
            );
        }

        // An entry recreated opaque in the upper shows nothing of the base's,
        // so the upper's directory is the whole entry, and one without a SLOT is
        // what it reads as. The marker lives in a `user.` attribute.
        let pinentry = upper.join(DB_DIR).join("app-crypt/pinentry-1.3.2-r1");
        std::fs::create_dir_all(&pinentry).unwrap();
        std::fs::write(pinentry.join(USE_FILE), "amd64\n").unwrap();
        assert!(
            merged(&lower, &upper)
                .expect("an entry merged with the base's is whole")
                .under("app-crypt/pinentry")
                .next()
                .is_some()
        );
        if let Err(errno) = rustix::fs::setxattr(
            &pinentry,
            containment::OPAQUE,
            b"y",
            rustix::fs::XattrFlags::empty(),
        ) {
            ferroday_cage_testkit::require::OVERLAY.skip(format!(
                "the opaque case: this filesystem refuses user attributes ({errno})"
            ));
            return;
        }
        let err = merged(&lower, &upper).expect_err("an opaque entry is the upper's alone");
        assert!(err.to_string().contains("SLOT"), "{err}");
    }

    #[test]
    fn a_symbolic_link_in_the_upper_hides_the_base_directory_at_its_name() {
        // A layer's link is not followed by overlayfs: at a directory's name it
        // is a non-directory, and the base's directory beneath it is hidden
        // whatever the link points at.
        let lower = stage3("link-lower");
        let upper = Scratch::for_test("gentoo-installed", "link-upper");
        std::fs::create_dir_all(upper.join("var")).unwrap();
        std::os::unix::fs::symlink("/elsewhere", upper.join("var/db")).unwrap();
        assert!(
            merged(&lower, &upper)
                .expect("the merged view is read")
                .is_empty()
        );
    }

    #[test]
    fn a_directory_that_does_not_name_a_package_is_refused() {
        let dir = Scratch::for_test("gentoo-installed", "not-a-package");
        std::fs::create_dir_all(dir.join(DB_DIR).join("sys-libs").join("zlib"))
            .expect("the directory is created");
        let err = installed(&*dir).expect_err("a versionless entry is refused");
        assert!(matches!(err, GentooError::Database { .. }), "{err:?}");
    }
}
