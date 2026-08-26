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
//! against, so reading an entry is two small reads.
//!
//! # The tree is read as an untrusted one
//!
//! Through [`Rooted`], which resolves every path against the root's own
//! descriptor. The tree was written by an extractor from an archive a mirror
//! served, and a root this crate did not build may have had anything run in it,
//! so a symbolic link at `var/db/pkg` is a thing that can be there. Resolved
//! this way it names something inside the tree or nothing at all.

use std::path::Path;

use super::atom::{self, Candidate};
use super::version;
use super::{DB_DIR, GentooError};
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

    fn use_flag(&self, flag: &str) -> Option<bool> {
        // The index's records answer through the same function, which is what
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
        atom::use_flag(&self.use_flags, &self.iuse, flag)
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

    /// Every installed package published under `name`, which is more than one
    /// where the root holds several slots of it.
    pub(super) fn under(&self, name: &str) -> impl Iterator<Item = &InstalledPackage> {
        self.packages
            .iter()
            .filter(move |package| package.name == name)
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
                })
                .collect(),
        )
    }

    /// Puts the entries in the order the type promises.
    ///
    /// The version is the last tiebreak and is compared as a version rather than
    /// as text, through the layer's own comparator. Only determinism rests on
    /// it — the type promises `category/name` and then slot, and two entries
    /// reaching the third key differ only in version — but a root holding
    /// `1.9` and `1.10` of one package in one slot is a root portage can
    /// produce, and reporting them the wrong way round would be a listing a
    /// reader has to distrust. A version the format does not define falls back
    /// to text, which orders it stably rather than losing it.
    fn sorted(mut packages: Vec<InstalledPackage>) -> Installed {
        packages.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.slot.cmp(&b.slot))
                .then_with(|| {
                    version::compare(&a.version, &b.version)
                        .unwrap_or_else(|| a.version.cmp(&b.version))
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
/// `name-version`, or one carrying no `SLOT` — and [`GentooError::Io`] where
/// the tree could not be read. A root with no `/var/db/pkg` at all reports no
/// packages rather than failing: an empty answer is a true one about a
/// directory that is not there.
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
    let mut packages = Vec::new();
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
                    format!("{dir} holds an entry whose name is not UTF-8"),
                ));
            };
            if pf.starts_with(MERGING_PREFIX) {
                continue;
            }
            packages.push(read_entry(rooted, at, &category, &pf)?);
        }
    }
    Ok(packages)
}

/// Reads one entry: its name and version from the two directory names, its slot
/// and flags from the files inside.
fn read_entry(
    rooted: &Rooted,
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
            format!("{dir} does not name a package and a version"),
        ));
    };
    let name = format!("{category}/{package}");
    let field = |file: &str| -> Result<Option<String>, GentooError> {
        match rooted.read(format!("{dir}/{file}")) {
            Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).trim().to_string())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(GentooError::io("reading a package database entry", at, err)),
        }
    };
    // A missing `SLOT` is what tells an entry directory from something else
    // that happens to be shaped like one: portage writes the file for every
    // package it merges, and so does this layer.
    let Some(slot) = field(SLOT_FILE)? else {
        return Err(GentooError::database(
            at,
            format!("{dir} names a package but carries no {SLOT_FILE} file"),
        ));
    };
    Ok(InstalledPackage {
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
    })
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
pub(super) fn merged(lower: &Path, upper: &Path) -> Result<Installed, GentooError> {
    let mut packages = installed(lower)?.packages;
    for above in installed(upper)?.packages {
        packages.retain(|below| {
            !(below.name == above.name && slot_of(&below.slot) == slot_of(&above.slot))
        });
        packages.push(above);
    }
    Ok(Installed::sorted(packages))
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
    fn a_directory_that_does_not_name_a_package_is_refused() {
        let dir = Scratch::for_test("gentoo-installed", "not-a-package");
        std::fs::create_dir_all(dir.join(DB_DIR).join("sys-libs").join("zlib"))
            .expect("the directory is created");
        let err = installed(&*dir).expect_err("a versionless entry is refused");
        assert!(matches!(err, GentooError::Database { .. }), "{err:?}");
    }
}
