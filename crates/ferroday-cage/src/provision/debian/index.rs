//! Parsing of the Debian control format and the package index.
//!
//! The archive publishes metadata in the deb822 control format: stanzas
//! separated by blank lines, each a set of `Field: value` lines with
//! continuation lines folded in. The same parser reads a `Release` file (one
//! stanza) and a `Packages` index (one stanza per package). The syntax itself
//! is [`crate::provision::document`], which every layer's plan documents are
//! written in as well; [`Index`] is the package set built from a `Packages`
//! file, deduplicated to the highest version of each name.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;

use super::digests::Digests;
use super::pin::{PinMatch, Pins, UnheldPin};
use super::release::ReleasePriority;
use super::version::{self, Constraint};
use crate::provision::Available;
use crate::provision::document::{self, Stanza};
use crate::provision::fetch::percent_decode;
use crate::roster::roster_enum;

/// One package's metadata from a `Packages` index.
#[derive(Debug, Clone)]
pub(crate) struct Package {
    /// The package's name, one [`is_package_name`] admits.
    pub name: String,
    /// The package's version, one [`version::is_version`] admits.
    pub version: String,
    pub architecture: String,
    /// The pool path (`Filename:`), relative to the mirror root.
    pub filename: String,
    /// The archive's `Size:` — the length of the `.deb` on the wire, in bytes —
    /// when the stanza carries a usable one. It bounds what the download may
    /// spend before its digest is checked, so it is read from the index whose
    /// own digest the verified release records.
    pub size: Option<u64>,
    /// The digests the stanza records for the `.deb`: its `SHA256`, its
    /// `SHA512`, or both.
    pub digests: Digests,
    pub depends: Vec<Dependency>,
    pub pre_depends: Vec<Dependency>,
    /// The virtual package names this package provides, each with the version
    /// it is provided at when the stanza declares one.
    pub provides: Vec<Provided>,
    pub essential: bool,
    pub priority: Option<String>,
    /// The archive's `Installed-Size:` in kibibytes, when the stanza carries
    /// one. Kept in the archive's own unit rather than normalized to bytes, so
    /// the value can be compared against a mirror's directly.
    pub installed_size: Option<u64>,
    /// The source package this binary package was built from, when the stanza
    /// names one that differs from [`name`](Self::name). `None` is the common
    /// case, and means the source package carries the same name.
    pub source: Option<String>,
    /// The index of the repository this package was retained from, so its
    /// bytes are fetched from that repository's own mirrors rather than a
    /// single global one. The resolver ignores it.
    pub origin: usize,
}

/// One dependency relationship: a group of alternatives, any one of which
/// satisfies it. `a | b` parses to two atoms; a plain dependency to one.
pub(crate) type Dependency = Vec<DepAtom>;

/// One alternative within a dependency: a package name and, when the
/// relationship declares one, the version constraint it must meet.
///
/// The architecture qualifier (`libc6:arm64`, `python3:any`) is parsed away —
/// a bootstrap installs one architecture, so a qualifier never selects between
/// two candidates — as are build-profile restriction lists, which say *when* a
/// dependency applies rather than what satisfies it.
///
/// The constraint itself is [`version::Constraint`], which lives beside the
/// comparison it is evaluated under. A layered resolve
/// ([`resolve_seeded`](super::resolve::resolve_seeded)) closes over an
/// increment against a base that was provisioned earlier, possibly from an
/// older archive, so `libc6 (>= 2.43)` is a question the base's actual version
/// has to answer.
#[derive(Debug, Clone)]
pub(crate) struct DepAtom {
    pub name: String,
    /// The declared version constraint, when there is one. `None` is an
    /// unversioned dependency, which any version of the name satisfies.
    pub constraint: Option<Constraint>,
}

/// A virtual package name a real package provides, and the version it provides
/// it at.
///
/// Debian Policy 7.5 gives the version its meaning: a bare `Provides: foo`
/// satisfies only an *unversioned* dependency on `foo`, while
/// `Provides: foo (= 1.2)` additionally satisfies a versioned one that 1.2
/// meets. Carrying the version is what lets the resolver keep those apart
/// instead of treating every provider as satisfying everything.
#[derive(Debug, Clone)]
pub(crate) struct Provided {
    /// The virtual name.
    pub name: String,
    /// The version it is provided at, or `None` for a bare `Provides`.
    pub version: Option<String>,
}

roster_enum! {
    /// A Debian package priority, the `Priority:` field of the archive's control
    /// data.
    ///
    /// The archive assigns every package a priority. A bootstrap seeds its base
    /// system from the most essential bands, and
    /// [`base_priority`](super::DebianBuilder::base_priority) selects the least
    /// essential band the seed still reaches. The variants are ordered from most to
    /// least essential, so a smaller value is the higher priority: a floor of
    /// [`Important`](Self::Important) admits [`Required`](Self::Required) and
    /// [`Important`](Self::Important) packages but not [`Standard`](Self::Standard)
    /// ones.
    ///
    /// [`ALL`](Self::ALL) lists every band, most essential first.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[non_exhaustive]
    pub enum Priority {
        /// The archive's own spelling of the band, which
        /// [`FromStr`](std::str::FromStr) reads back.
        fn as_str;

        /// Packages without which the system does not function or cannot be
        /// installed. The base of every bootstrap.
        Required => "required",
        /// Packages present on all but the most minimal systems, expected to be
        /// installed.
        Important => "important",
        /// The result of a standard, reasonably small character-mode install.
        Standard => "standard",
        /// Packages outside the base selection, the archive's bulk.
        Optional => "optional",
        /// A deprecated band the archive folds into [`Optional`](Self::Optional);
        /// recognized for completeness.
        Extra => "extra",
    }
}

impl fmt::Display for Priority {
    /// Writes the archive's own spelling, which is what
    /// [`FromStr`](std::str::FromStr) reads back.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Priority {
    type Err = ParsePriorityError;

    /// Parses a Debian `Priority:` field value case-insensitively.
    ///
    /// The archive writes the field in lower case, but a caller naming a
    /// priority on a command line or in a profile writes whatever it likes, and
    /// one name means one band whichever way it is spelled.
    fn from_str(value: &str) -> Result<Priority, ParsePriorityError> {
        Priority::ALL
            .iter()
            .copied()
            .find(|priority| value.eq_ignore_ascii_case(priority.as_str()))
            .ok_or_else(|| ParsePriorityError {
                text: value.to_string(),
            })
    }
}

/// The error from parsing an unrecognized [`Priority`] name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePriorityError {
    text: String,
}

impl ParsePriorityError {
    /// The unrecognized name, as it was given.
    ///
    /// Named `text` on every parse error in this crate, so a caller moving
    /// between them does not have to check.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ParsePriorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown priority {:?}: expected one of ", self.text)?;
        for (index, priority) in Priority::ALL.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            f.write_str(priority.as_str())?;
        }
        Ok(())
    }
}

impl std::error::Error for ParsePriorityError {}

impl Package {
    /// Builds a package from a `Packages` stanza, or `None` when a required
    /// field is missing or malformed: among them a name [`is_package_name`]
    /// does not admit, and a version [`version::is_version`] does not.
    fn from_stanza(stanza: &Stanza<'_>) -> Option<Package> {
        let [
            name,
            version,
            architecture,
            filename,
            sha256,
            sha512,
            size,
            installed_size,
            source,
            depends,
            pre_depends,
            provides,
            essential,
            priority,
        ] = stanza.get_each([
            "Package",
            "Version",
            "Architecture",
            "Filename",
            "SHA256",
            "SHA512",
            "Size",
            "Installed-Size",
            "Source",
            "Depends",
            "Pre-Depends",
            "Provides",
            "Essential",
            "Priority",
        ]);
        let name = name?.into_owned();
        if !is_package_name(&name) {
            return None;
        }
        let version = version?.into_owned();
        if !version::is_version(&version) {
            return None;
        }
        let architecture = architecture?.into_owned();
        // A digest becomes a cache filename and a value the fetch is verified
        // against, and the pool path becomes a fetch URL and (for a `file://`
        // mirror) a local path. Neither is trusted until the archive signature
        // is checked, so validate their shape here, at the boundary where the
        // index is parsed, rather than at each use site: a stanza stating no
        // SHA-256 and no SHA-512, stating either other than as lowercase hex of
        // its width, or whose pool path could traverse out of a mirror root is
        // malformed and dropped.
        let filename = filename?.into_owned();
        if !is_safe_pool_path(&filename) {
            return None;
        }
        let digests = Digests::from_fields(sha256.as_deref(), sha512.as_deref()).ok()??;
        // A stanza that states no size, or states one that does not parse,
        // leaves the download bounded by the fetcher's own ceiling rather than
        // being dropped: the digest is what decides whether the bytes are the
        // package, and a missing bound is a weaker fetch, not a wrong one.
        let size = size.and_then(|value| value.parse::<u64>().ok());
        // Read before the literal below moves `name`, which the source name is
        // compared against. Neither field is required: a stanza missing or
        // malforming one is reported as carrying no value rather than dropped,
        // since nothing the bootstrap does depends on either.
        let installed_size = installed_size.and_then(|value| value.parse::<u64>().ok());
        let source = source.and_then(|value| source_name(&value, &name));
        Some(Package {
            name,
            version,
            architecture,
            filename,
            size,
            digests,
            depends: depends.as_deref().map(parse_relations).unwrap_or_default(),
            pre_depends: pre_depends
                .as_deref()
                .map(parse_relations)
                .unwrap_or_default(),
            provides: provides.as_deref().map(parse_provides).unwrap_or_default(),
            essential: essential.is_some_and(|value| value.eq_ignore_ascii_case("yes")),
            priority: priority.map(Cow::into_owned),
            installed_size,
            source,
            // Set by the caller as the stanza is folded into an index; the
            // repository this stanza came from is not known here.
            origin: 0,
        })
    }

    /// The package's priority as a [`Priority`], or `None` when it carries no
    /// priority or an unrecognized one.
    fn priority_band(&self) -> Option<Priority> {
        self.priority
            .as_deref()
            .and_then(|value| value.parse().ok())
    }
}

/// Whether `name` is a package name Debian policy permits.
///
/// Policy 5.6.1 gives the alphabet: lowercase letters, digits, `+`, `-`, and
/// `.`, at least two characters, starting with a letter or a digit. The archive
/// software of Debian and of Ubuntu refuses an upload outside it, so every name
/// their archives publish is within it.
///
/// A name is held to it wherever one arrives to be reported. A stanza naming a
/// package outside it is malformed and dropped as the index is read, a plan
/// naming one is refused
/// ([`PlannedPackage::unaddressable`](super::plan::PlannedPackage::unaddressable)),
/// and the pool refuses a `.deb` whose control file names one
/// ([`checked_name`](super::pool::checked_name)). An admitted name reaches
/// progress reports and errors as written, and a published one becomes two
/// segments of a pool path. The alphabet holds no control character, so a name
/// carries no escape sequence onto the terminal a report is printed on, and no
/// separator, so it stays one path segment.
///
/// dpkg itself installs a little more: an upper-case name, which it folds to
/// lower case, a name holding `_`, and a single character. None occurs in an
/// archive, and this layer compares names as written, so a name it read in
/// upper case would not be the one dpkg records.
pub(super) fn is_package_name(name: &str) -> bool {
    let lowercase_or_digit = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    name.len() >= 2
        && name.starts_with(lowercase_or_digit)
        && name
            .chars()
            .all(|c| lowercase_or_digit(c) || matches!(c, '+' | '-' | '.'))
}

/// Whether `filename` is a safe pool path: a non-empty relative path with no
/// traversal component, no leading slash, and no byte outside the printable
/// ASCII range — as written, and as a server that percent-decodes it would read
/// it.
///
/// A `Filename:` becomes a fetch URL suffix and, for a `file://` mirror, a local
/// path, so this keeps an index-supplied pool path from escaping a mirror root.
/// The character rule is what makes that claim hold for the whole shape rather
/// than the path components alone: deb822 folds a continuation line into its
/// value joined with a newline, so a value can carry `\r` and `\n` through the
/// parser, and the pool path is interpolated verbatim into the built-in HTTP
/// client's request line. Admitting only printable ASCII leaves nothing that
/// could end a request line or start a header of its own, no space to split the
/// request line's three fields, and no NUL to truncate a local path. Real pool
/// paths — `pool/main/h/hello/hello_2.10-3_amd64.deb` — are within it.
///
/// The decoded form is checked because the literal one is not what an HTTP
/// server resolves: `pool/%2e%2e/%2e%2e/etc/passwd` carries no `..` component
/// as written, and a server that decodes before resolving may serve something
/// above the mirror root. Applying the same rules to the decoded bytes closes
/// that without narrowing what a legitimate path may contain, since a real pool
/// path decodes to itself. An escape that is malformed, or that decodes to
/// another `%`, is refused outright: neither occurs in a real path, and
/// refusing the second means no amount of re-encoding can hide a traversal from
/// this single decoding pass.
pub(super) fn is_safe_pool_path(filename: &str) -> bool {
    if !is_safe_pool_shape(filename.as_bytes()) {
        return false;
    }
    // Every `%` the written form holds begins an escape, so a `%` in the decoded
    // form is one an escape produced: the byte a second pass would decode.
    match percent_decode(filename.as_bytes()) {
        Some(decoded) => !decoded.contains(&b'%') && is_safe_pool_shape(&decoded),
        None => false,
    }
}

/// The shape rule both the written and the decoded form must satisfy.
fn is_safe_pool_shape(path: &[u8]) -> bool {
    !path.is_empty()
        && path[0] != b'/'
        && path.iter().all(u8::is_ascii_graphic)
        && !path
            .split(|byte| *byte == b'/')
            .any(|component| component == b"..")
}

/// One repository's part of a merged index: its place in the configured list,
/// the release it publishes, and one component's `Packages` text.
pub(crate) struct Source<'a> {
    /// The repository's index in the configured list, the primary at zero,
    /// which every package it supplies is tagged with.
    pub(crate) origin: usize,
    /// The suite the repository is configured with, which an install list
    /// entry written `name/release` names it by.
    pub(crate) suite: &'a str,
    /// How the release ranks its versions against another release's.
    pub(crate) priority: ReleasePriority,
    /// The `Packages` text.
    pub(crate) text: &'a str,
}

/// The package set the configured repositories offer: every version kept of
/// each real name, at most one per repository, with the one a resolution takes
/// by default first; plus a virtual-package index mapping each provided name to
/// its providers.
///
/// The first version of a name is its *candidate*, chosen as apt chooses one
/// for a system that has nothing installed: the highest [`ReleasePriority`],
/// then the highest version, then the earlier repository. The others are kept
/// because an install list may ask for a name from a particular release, and a
/// layered build may upgrade a name its base has installed, and each of those
/// can settle on a version other than the candidate.
///
/// The index keeps the pin it was merged under, and every version it answers
/// with honours it: a name the pin holds is answered with its pinned version
/// by [`get`](Self::get), [`in_release`](Self::in_release), and
/// [`upgrade_over`](Self::upgrade_over) alike.
pub(crate) struct Index {
    by_name: HashMap<String, Vec<Package>>,
    providers: HashMap<String, Vec<String>>,
    /// The suite and the rank of each repository, by origin.
    releases: HashMap<usize, (String, ReleasePriority)>,
    /// The pin the index was merged under.
    pins: Pins,
    /// How many stanzas were read but not kept, as [`merge`](Self::merge)
    /// counts them.
    skipped: usize,
}

impl Index {
    /// Parses a single `Packages` index, keeping the highest version of each
    /// name and filtering to the requested architecture plus `all`. Every
    /// package is tagged with origin zero, of a default-ranked release.
    #[cfg(test)]
    pub(crate) fn parse(text: &str, architecture: &str) -> Index {
        Index::merge(sources([(0, text)]), architecture, &Pins::none())
    }

    /// Parses and merges several repositories' `Packages` indexes into one set,
    /// tagging each retained package with the origin it came from.
    ///
    /// The sources are yielded one per repository component. Within one
    /// repository the highest version of a name is kept. Across repositories
    /// each name's versions are ranked for its candidate: the higher
    /// [`ReleasePriority`] first, then the higher version, and an exact tie
    /// resolves to the repository that comes first in the configured list.
    ///
    /// A name `pins` holds selects the pinned version instead, whatever the
    /// rank of the release offering it, preferring a repository that records
    /// the pinned bytes for it and otherwise taking the first repository that
    /// offers it. Where no repository offers the pinned version the ranking
    /// above decides, so [`Pins::check`] can report what the archives carry
    /// rather than only that something is missing; that check runs before
    /// anything resolves against the index.
    ///
    /// A stanza this layer cannot act on, one [`Package::from_stanza`] reads as
    /// no package, is left out and counted in [`skipped`](Self::skipped) rather
    /// than refusing the index: a package the closure needs and the mirror
    /// malformed is still refused, by name, when nothing else answers it, and
    /// one it does not need costs nothing. A stanza for another architecture is
    /// neither kept nor counted, since it is not this bootstrap's.
    pub(crate) fn merge<'a>(
        sources: impl IntoIterator<Item = Source<'a>>,
        architecture: &str,
        pins: &Pins,
    ) -> Index {
        let mut by_name: HashMap<String, Vec<Package>> = HashMap::new();
        let mut releases = HashMap::new();
        let mut skipped = 0;
        for source in sources {
            releases.insert(source.origin, (source.suite.to_string(), source.priority));
            for stanza in document::parse(source.text) {
                let Some(mut package) = Package::from_stanza(&stanza) else {
                    skipped += 1;
                    continue;
                };
                if package.architecture != architecture && package.architecture != "all" {
                    continue;
                }
                package.origin = source.origin;
                let offers = by_name.entry(package.name.clone()).or_default();
                match offers.iter_mut().find(|held| held.origin == package.origin) {
                    None => offers.push(package),
                    // One repository, so one rank: the entry closest to the
                    // pin is kept, and otherwise the higher version.
                    Some(held) => {
                        if pin_closer(pins, &package, held)
                            .unwrap_or_else(|| higher(&package, held))
                        {
                            *held = package;
                        }
                    }
                }
            }
        }

        let rank = |package: &Package| {
            releases
                .get(&package.origin)
                .map_or(ReleasePriority::Default, |(_, priority)| *priority)
        };
        for offers in by_name.values_mut() {
            // Repository order first, so a tie below goes to the earlier one
            // and the versions after the candidate read in a stable order.
            offers.sort_by_key(|package| package.origin);
            let candidate = (1..offers.len()).fold(0, |best, at| {
                let (offered, held) = (&offers[at], &offers[best]);
                // The entry closest to the pin is the candidate whatever its
                // rank: the pinned version with the pinned bytes, then the
                // pinned version. A later repository displaces an earlier one
                // only by being closer, so among equals the first is kept.
                let displaces = pin_closer(pins, offered, held)
                    .unwrap_or_else(|| outranks((rank(offered), offered), (rank(held), held)));
                if displaces { at } else { best }
            });
            let candidate = offers.remove(candidate);
            offers.insert(0, candidate);
        }

        // Every version's provides, not only the candidates': a version an
        // install list asks for by release can provide what its candidate does
        // not. The resolver asks each provider's own version whether it
        // supplies the name, so listing a name here promises nothing.
        let mut providers: HashMap<String, Vec<String>> = HashMap::new();
        for package in by_name.values().flatten() {
            for provided in &package.provides {
                providers
                    .entry(provided.name.clone())
                    .or_default()
                    .push(package.name.clone());
            }
        }
        // The lists are built by iterating a HashMap, so their order is not
        // reproducible; resolution picks the first provider, so sort each into
        // a stable order for a deterministic selection across runs.
        for names in providers.values_mut() {
            names.sort();
            names.dedup();
        }

        Index {
            by_name,
            providers,
            releases,
            pins: pins.clone(),
            skipped,
        }
    }

    /// How many packages the index offers, each name counted once.
    pub(crate) fn package_count(&self) -> usize {
        self.by_name.len()
    }

    /// How many stanzas were read but not kept, because this layer cannot act
    /// on them.
    pub(crate) fn skipped(&self) -> usize {
        self.skipped
    }

    /// The candidate for `name`, if it is a real package in this index: the
    /// version a resolution takes when nothing asks for another.
    pub(crate) fn get(&self, name: &str) -> Option<&Package> {
        self.by_name.get(name).and_then(|offers| offers.first())
    }

    /// Every version kept of `name`, the candidate first and then the others
    /// in repository order. Empty for a name no repository offers.
    pub(crate) fn offers(&self, name: &str) -> &[Package] {
        self.by_name.get(name).map_or(&[], Vec::as_slice)
    }

    /// The real packages whose versions provide the virtual package `name`.
    pub(crate) fn providers(&self, name: &str) -> &[String] {
        self.providers.get(name).map_or(&[], Vec::as_slice)
    }

    /// The suite the repository at `origin` publishes, as configured.
    pub(crate) fn suite(&self, origin: usize) -> &str {
        self.releases
            .get(&origin)
            .map_or("", |(suite, _)| suite.as_str())
    }

    /// The pin the index was merged under, for the resolver to hold a
    /// dependency nothing answers to.
    pub(super) fn pins(&self) -> &Pins {
        &self.pins
    }

    /// The version of `name` that a repository publishing the suite `release`
    /// offers, as apt's `name/release` selects it: the highest, or for a name
    /// the pin holds, the pinned version alone.
    ///
    /// `Ok(None)` where no repository publishing `release` offers the name at
    /// all.
    ///
    /// # Errors
    ///
    /// The refusal of the pin, for a name it holds that the release offers only
    /// at another version or over other bytes. Taking the release's version
    /// would resolve the name around its pin, and taking the pinned version
    /// from another release would ignore the release the entry names, so
    /// neither is an answer.
    pub(crate) fn in_release(
        &self,
        name: &str,
        release: &str,
    ) -> Result<Option<&Package>, UnheldPin> {
        // Ranked as a merge ranks one repository's entries: the closest to
        // the pin, and otherwise the higher version.
        let Some(offered) = self
            .offers(name)
            .iter()
            .filter(|package| self.suite(package.origin) == release)
            .fold(None, |best: Option<&Package>, package| match best {
                Some(held)
                    if !pin_closer(&self.pins, package, held)
                        .unwrap_or_else(|| higher(package, held)) =>
                {
                    Some(held)
                }
                _ => Some(package),
            })
        else {
            return Ok(None);
        };
        match self.pins.refuse_release(offered, release) {
            Some(unheld) => Err(unheld),
            None => Ok(Some(offered)),
        }
    }

    /// The version a name installed at `installed` is upgraded to, where a
    /// dependency the installed version does not meet asks for one, or `None`
    /// where apt would keep the installed version.
    ///
    /// apt never downgrades without a pin above 1000, so only versions above
    /// the installed one are considered, ranked as a candidate is. The installed
    /// version stands at [`ReleasePriority::AutomaticUpgrades`], or at the rank
    /// of a release still offering it where that is higher, and is replaced
    /// only by a version ranked at least as high. A default release's newer
    /// version therefore replaces it. A backports suite's replaces it only
    /// where no default release offers the installed version, which is a
    /// package backports supplied. An `experimental` version never does.
    ///
    /// A name the pin holds is upgraded to the pinned version alone, where it
    /// is above the installed one, whatever the rank of the release offering
    /// it: that is the version a pin selects for the name anywhere else, and
    /// [`merge`](Self::merge) makes it the candidate the same way. A pinned
    /// version at or below the installed one is no upgrade, so a dependency the
    /// installed version does not meet is then the pin's to refuse.
    pub(crate) fn upgrade_over(&self, name: &str, installed: &str) -> Option<&Package> {
        let offers = self.offers(name);
        if self.pins.names(name) {
            return offers
                .iter()
                .find(|package| self.pins.matching(package) == PinMatch::VersionAndBytes)
                .filter(|pinned| {
                    version::compare(&pinned.version, installed) == Ordering::Greater
                });
        }
        let standing = offers
            .iter()
            .filter(|package| version::compare(&package.version, installed).is_eq())
            .map(|package| self.priority(package.origin))
            .fold(ReleasePriority::AutomaticUpgrades, Ord::max);
        offers
            .iter()
            .filter(|package| version::compare(&package.version, installed) == Ordering::Greater)
            .fold(None, |best: Option<&Package>, package| match best {
                Some(held)
                    if !outranks(
                        (self.priority(package.origin), package),
                        (self.priority(held.origin), held),
                    ) =>
                {
                    Some(held)
                }
                _ => Some(package),
            })
            .filter(|best| self.priority(best.origin) >= standing)
    }

    /// The rank of the release the repository at `origin` publishes.
    fn priority(&self, origin: usize) -> ReleasePriority {
        self.releases
            .get(&origin)
            .map_or(ReleasePriority::Default, |(_, priority)| *priority)
    }

    /// Projects the index into the names it offers, consuming it.
    ///
    /// The parsed packages go: what a caller asking about availability wants is
    /// the name set and the provider map, and retaining tens of megabytes of
    /// relation vectors to back a membership question would be the wrong trade.
    /// A virtual name is offered where a candidate provides it, since a name
    /// asked for without a release resolves to its candidate.
    pub(crate) fn into_available(self) -> Available {
        let mut providers: HashMap<String, Vec<String>> = HashMap::new();
        for package in self.by_name.values().filter_map(|offers| offers.first()) {
            for provided in &package.provides {
                providers
                    .entry(provided.name.clone())
                    .or_default()
                    .push(package.name.clone());
            }
        }
        for names in providers.values_mut() {
            names.sort();
        }
        Available::new(self.by_name.into_keys().collect(), providers)
    }

    /// The base seed: every essential package and every package whose priority
    /// is at least `floor` (that is, at least as essential as it), as the
    /// primary repository describes them. With the default floor
    /// [`Priority::Required`] this is `debootstrap`'s minbase set; a less
    /// essential floor such as [`Priority::Important`] additionally seeds that
    /// band, matching the corresponding bootstrap variant. `apt` and the
    /// caller's includes are added on top by the caller.
    ///
    /// The primary is origin zero, and only its stanzas are read, as
    /// `debootstrap` seeds from one archive: a pool or a vendor repository
    /// marking a package essential or required does not draw it into every
    /// bootstrap that names the repository. A seeded name still resolves to its
    /// candidate, so a higher version another repository ships of it is the
    /// one installed.
    pub(crate) fn base_seed(&self, floor: Priority) -> Vec<String> {
        let mut seed: Vec<String> = self
            .by_name
            .iter()
            .filter(|(_, offers)| {
                offers
                    .iter()
                    .find(|package| package.origin == 0)
                    .is_some_and(|package| {
                        package.essential
                            || package.priority_band().is_some_and(|band| band <= floor)
                    })
            })
            .map(|(name, _)| name.clone())
            .collect();
        seed.sort();
        seed
    }
}

/// Whether `offered` is a higher version than `held`.
fn higher(offered: &Package, held: &Package) -> bool {
    version::compare(&offered.version, &held.version) == Ordering::Greater
}

/// Whether `offered`, from a release of the given rank, is preferred to `held`
/// as a name's candidate: a higher rank, or the same rank and a higher
/// version. Neither is preferred in an exact tie, so the one held stays.
fn outranks(offered: (ReleasePriority, &Package), held: (ReleasePriority, &Package)) -> bool {
    offered.0 > held.0 || (offered.0 == held.0 && higher(offered.1, held.1))
}

/// Whether `offered` answers a pin on its name more closely than `held`, or
/// `None` where the pin does not decide: a name it does not hold, or two
/// entries neither of which is at the pinned version.
fn pin_closer(pins: &Pins, offered: &Package, held: &Package) -> Option<bool> {
    if !pins.names(&offered.name) {
        return None;
    }
    let (offered, held) = (pins.matching(offered), pins.matching(held));
    (offered != PinMatch::Neither || held != PinMatch::Neither).then_some(offered > held)
}

/// The sources of single-component, default-ranked repositories, from
/// `(origin, text)` pairs, for a test that is about something other than
/// ranking.
#[cfg(test)]
pub(crate) fn sources<'a>(
    texts: impl IntoIterator<Item = (usize, &'a str)>,
) -> impl Iterator<Item = Source<'a>> {
    texts.into_iter().map(|(origin, text)| Source {
        origin,
        suite: "",
        priority: ReleasePriority::Default,
        text,
    })
}

/// Parses a `Depends`/`Pre-Depends` value into a list of relationships.
fn parse_relations(value: &str) -> Vec<Dependency> {
    value
        .split(',')
        .filter_map(|group| {
            let atoms: Vec<DepAtom> = group.split('|').filter_map(parse_atom).collect();
            (!atoms.is_empty()).then_some(atoms)
        })
        .collect()
}

/// Parses a `Provides` value into the virtual names and the versions they are
/// provided at.
///
/// Only `=` carries meaning in a `Provides` — Policy 7.5 permits no other
/// relation there — so an entry with any other operator is read as a bare
/// provide rather than as a constraint, which is the conservative reading: it
/// satisfies unversioned dependencies and no versioned one.
pub(crate) fn parse_provides(value: &str) -> Vec<Provided> {
    value
        .split(',')
        .filter_map(parse_atom)
        .map(|atom| Provided {
            name: atom.name,
            version: atom
                .constraint
                .as_ref()
                .and_then(Constraint::exact_version)
                .map(str::to_string),
        })
        .collect()
}

/// Parses a `Source:` field into the source package's name, or `None` when it
/// names the binary package's own.
///
/// The field may carry a version the source was built at — `Source: foo
/// (1.2-3)` — which belongs to the source package rather than to this binary
/// one, and is dropped. Debian encodes "the source has the same name" by
/// omitting the field entirely, so a stanza that states it anyway is read the
/// same way, leaving one representation of that case rather than two.
fn source_name(value: &str, package: &str) -> Option<String> {
    let name: String = value
        .trim()
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '(')
        .collect();
    (!name.is_empty() && name != package).then_some(name)
}

/// Parses one dependency alternative into its package name and version
/// constraint, dropping the architecture qualifier and any restriction lists.
///
/// A constraint that cannot be read — an operator dpkg does not define, or a
/// parenthesis with no version in it — yields `None` for the constraint rather
/// than failing the parse, leaving an unversioned dependency on the name. The
/// alternative would be to drop the whole atom, which turns a malformed
/// constraint into a silently missing dependency; the resolver's job is to
/// report what it cannot satisfy, not to lose the relationship.
fn parse_atom(text: &str) -> Option<DepAtom> {
    let text = text.trim();
    let name: String = text
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, '(' | ':' | '[' | '<'))
        .collect();
    if name.is_empty() {
        return None;
    }
    let constraint = parse_constraint(text);
    Some(DepAtom { name, constraint })
}

/// Reads the `(<relation> <version>)` clause of a dependency atom, when it has
/// one that parses.
///
/// The restriction list (`<!nocheck>`) and the architecture list (`[!armhf]`)
/// are not version clauses, so only a parenthesised group is considered, and
/// only the first: Policy allows one per alternative. What is inside the
/// parentheses is the version grammar's to read, so
/// [`Constraint::parse`](version::Constraint::parse) reads it.
fn parse_constraint(text: &str) -> Option<Constraint> {
    let open = text.find('(')?;
    let close = text[open..].find(')')? + open;
    Constraint::parse(&text[open + 1..close])
}

/// The build dependencies of a source package, read from a `debian/control`
/// file, as they apply to a build for `architecture`.
///
/// Parses the `Build-Depends`, `Build-Depends-Arch`, and `Build-Depends-Indep`
/// fields of the control text's first stanza — the source stanza — and returns
/// the package names each relationship may need. Names are returned in field
/// order and deduplicated, keeping the first appearance. A line beginning with
/// `#` is a comment, as Debian Policy 5.1 allows in this file alone: it is
/// dropped before the fields are read, so it neither becomes a field nor ends
/// the continuation it interrupts.
///
/// Each alternative's architecture restriction is evaluated against
/// `architecture`, as Debian Policy 7.1 defines it: an alternative whose list
/// excludes the architecture is ignored, a relationship whose every alternative
/// is ignored contributes nothing, and the first alternative left is the name
/// returned, as the archive's build daemons choose it. A list term is a
/// literal architecture name, `any`, or an `<os>-<cpu>` wildcard with either
/// half `any` (`linux-any`, `any-amd64`). A term this does not recognize —
/// a three- or four-part wildcard naming an ABI or a C library — keeps the
/// alternative rather than dropping it.
///
/// Build profiles are not evaluated, since which ones a build activates is not
/// in the control file, so the result is a superset that is safe to install
/// into a build environment. An alternative carrying a profile restriction
/// (`<!nocheck>`) is returned, and because some build may exclude it, so is the
/// alternative after it, up to the first that carries none. Version
/// constraints and architecture qualifiers (`:native`) are stripped.
///
/// The names are meant for
/// [`DebianBuilder::include`](crate::provision::debian::DebianBuilder::include),
/// which bakes them into the bootstrap so a package build runs without
/// resolving its build dependencies at build time; `architecture` is the one
/// that bootstrap targets. The caller supplies the control text from wherever
/// the source lives — a working tree, a git checkout, or an archive `Sources`
/// stanza — so the source of the metadata is the caller's to choose.
pub fn build_depend_names(control: &str, architecture: &str) -> Vec<String> {
    // The comment rule is this file's alone: an archive's `Packages` and
    // `Release` documents, which the shared reader also reads, have no
    // comments, and a line there beginning with `#` is a field like any other.
    let uncommented: String = control
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(|line| [line, "\n"])
        .collect();
    let Some(source) = document::parse(&uncommented).next() else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for field in ["Build-Depends", "Build-Depends-Arch", "Build-Depends-Indep"] {
        let Some(value) = source.get(field) else {
            continue;
        };
        for group in value.split(',') {
            let alternatives = group
                .split('|')
                .filter(|alternative| applies_to(alternative, architecture));
            for alternative in alternatives {
                let Some(atom) = parse_atom(alternative) else {
                    continue;
                };
                if seen.insert(atom.name.clone()) {
                    names.push(atom.name);
                }
                // An alternative no profile can exclude is the one a build
                // takes whenever it gets this far, so nothing after it is.
                if !restricts_profiles(alternative) {
                    break;
                }
            }
        }
    }
    names
}

/// Whether a relationship alternative carries a build-profile restriction, a
/// `<...>` formula that a build may not satisfy.
///
/// The formula follows the version clause, whose own relations (`<<`, `<=`)
/// are not one, so only what lies outside the parentheses is looked at.
fn restricts_profiles(alternative: &str) -> bool {
    let after_version = match (alternative.find('('), alternative.find(')')) {
        (Some(open), Some(close)) if open < close => {
            format!("{}{}", &alternative[..open], &alternative[close + 1..])
        }
        _ => alternative.to_string(),
    };
    after_version.contains('<')
}

/// Whether a relationship alternative's architecture restriction admits
/// `architecture`.
///
/// An alternative with no list admits every architecture. A list of plain terms
/// admits the architectures any term matches, and a list of negated ones the
/// architectures none matches; Policy forbids mixing the two, and a list that
/// does is not read as excluding anything. Where a term is one [`arch_matches`]
/// cannot decide, the answer leans to keeping the alternative: an unneeded
/// build dependency costs space, and a missing one fails the build.
fn applies_to(alternative: &str, architecture: &str) -> bool {
    let Some(open) = alternative.find('[') else {
        return true;
    };
    let Some(close) = alternative[open..].find(']') else {
        return true;
    };
    let terms: Vec<&str> = alternative[open + 1..open + close]
        .split_whitespace()
        .collect();
    let negated = terms.iter().filter(|term| term.starts_with('!')).count();
    if terms.is_empty() || (negated != 0 && negated != terms.len()) {
        return true;
    }
    if negated == 0 {
        terms
            .iter()
            .any(|term| arch_matches(architecture, term) != Some(false))
    } else {
        terms
            .iter()
            .all(|term| arch_matches(architecture, &term[1..]) != Some(true))
    }
}

/// Whether the architecture restriction term `term` names `architecture`, or
/// `None` where the term is a wildcard of a shape this does not decide.
///
/// A term without an `any` part is a literal architecture name. Of the
/// wildcards, `any` names every architecture, and a two-part `<os>-<cpu>`
/// names those whose operating system and CPU match its halves, either of
/// which may be `any`. An architecture name carries its operating system as a
/// prefix, `hurd-amd64` or `musl-linux-amd64`, except on Linux, where it
/// carries none; its CPU is dpkg's, so `armhf` and `armel` are both `arm`.
fn arch_matches(architecture: &str, term: &str) -> Option<bool> {
    if term == architecture {
        return Some(true);
    }
    let parts: Vec<&str> = term.split('-').collect();
    if !parts.contains(&"any") {
        return Some(false);
    }
    match parts[..] {
        ["any"] => Some(true),
        [os, cpu] => {
            let (own_os, own_cpu) = os_and_cpu(architecture);
            Some((os == "any" || os == own_os) && (cpu == "any" || cpu == own_cpu))
        }
        _ => None,
    }
}

/// The operating system and the CPU an architecture name stands for, as dpkg
/// names them.
fn os_and_cpu(architecture: &str) -> (&str, &str) {
    let (prefix, cpu) = match architecture.rsplit_once('-') {
        Some((prefix, cpu)) => (prefix, cpu),
        None => ("linux", architecture),
    };
    // A prefix may name a C library ahead of the system: `musl-linux`.
    let os = prefix.rsplit('-').next().unwrap_or(prefix);
    let cpu = match cpu {
        "armhf" | "armel" => "arm",
        "x32" => "amd64",
        other => other,
    };
    (os, cpu)
}

#[cfg(test)]
mod tests {
    use super::super::pin::UnheldReason;
    use super::*;

    #[test]
    fn pool_path_shapes_are_validated() {
        assert!(is_safe_pool_path("pool/p/pkg/pkg_1.0_amd64.deb"));
        assert!(!is_safe_pool_path(""));
        assert!(!is_safe_pool_path("/etc/passwd"));
        assert!(!is_safe_pool_path("pool/../../etc/passwd"));
        assert!(!is_safe_pool_path("pool/x\0y.deb"));
        // The pool path is interpolated into an HTTP request line, so nothing
        // that could end that line, start a header, or split the line's three
        // fields may pass. A folded deb822 value carries a real newline.
        assert!(!is_safe_pool_path("pool/p.deb\r\nX-Injected: 1"));
        assert!(!is_safe_pool_path("pool/p.deb\nX-Injected: 1"));
        assert!(!is_safe_pool_path("pool/p.deb HTTP/1.1"));
        assert!(!is_safe_pool_path("pool/\u{e9}clair.deb"));
    }

    #[test]
    fn a_percent_encoded_traversal_is_refused() {
        // The literal path carries no `..` component, but the server that
        // resolves the request line decodes it first, so the check has to read
        // it the way the server will. Encoding the separator is the same trick
        // in another spelling, and `%25` is the one that would let a second
        // decoding pass reveal what this one did not see.
        for path in [
            "pool/%2e%2e/%2e%2e/etc/passwd",
            "pool/%2E%2E/etc/passwd",
            "pool/..%2fetc/passwd",
            "pool/%252e%252e/etc/passwd",
            // A malformed escape reaches a decoder that may read it either way.
            "pool/%2/x.deb",
            "pool/%zz/x.deb",
            "pool/x.deb%",
            // Decoded control characters would split the request line as surely
            // as literal ones.
            "pool/p.deb%0d%0aX-Injected:%201",
        ] {
            assert!(!is_safe_pool_path(path), "{path} should be refused");
        }
        // A path that decodes to itself is unaffected, encoded bytes included:
        // a pool path is free to carry an escape that names an ordinary
        // character.
        assert!(is_safe_pool_path("pool/p/pkg/pkg_1%3a2.0-1_amd64.deb"));
    }

    #[test]
    fn a_stanza_reports_its_installed_size_and_source_package() {
        let text = format!(
            "Package: bind9-dnsutils\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/p.deb\n\
             SHA256: {}\nSize: 158742\nInstalled-Size: 412\nSource: bind9 (1:9.20.4-1)\n",
            "a".repeat(64),
        );
        let index = Index::parse(&text, "amd64");
        let package = index.get("bind9-dnsutils").expect("the stanza parses");
        // The archive's own unit, kibibytes, rather than bytes: a value that
        // differs from the mirror's is one more thing that can disagree with it.
        assert_eq!(package.installed_size, Some(412));
        // `Size:` is the wire length of the `.deb`, in bytes, and bounds what
        // the download may spend before its digest is checked.
        assert_eq!(package.size, Some(158_742));
        // The version belongs to the source package rather than to this binary
        // one, so only the name is kept.
        assert_eq!(package.source.as_deref(), Some("bind9"));
    }

    #[test]
    fn a_source_naming_the_package_itself_reads_as_no_source() {
        // Debian says "the source package has this name" by omitting the field,
        // so a stanza that states it anyway is read the same way, leaving one
        // representation of that case rather than two.
        assert_eq!(source_name("hello", "hello"), None);
        assert_eq!(source_name("hello (2.10-3)", "hello"), None);
        assert_eq!(source_name("", "hello"), None);
        assert_eq!(source_name("hello", "hello-data").as_deref(), Some("hello"));
        assert_eq!(
            source_name("hello (2.10-3)", "libhello1").as_deref(),
            Some("hello")
        );
    }

    #[test]
    fn a_stanza_stating_no_size_or_a_malformed_one_still_parses() {
        // Neither field is required by Debian Policy and nothing the bootstrap
        // does depends on either, so their absence is reported rather than
        // dropping a package the install needs.
        let base = format!(
            "Package: pp\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/p.deb\nSHA256: {}\n",
            "a".repeat(64),
        );
        let index = Index::parse(&base, "amd64");
        let package = index.get("pp").expect("the stanza parses");
        assert_eq!(package.installed_size, None);
        assert_eq!(package.size, None);
        assert_eq!(package.source, None);

        let malformed = format!("{base}Installed-Size: unknown\nSize: huge\n");
        let index = Index::parse(&malformed, "amd64");
        let package = index.get("pp").expect("the stanza still parses");
        assert_eq!(package.installed_size, None);
        assert_eq!(package.size, None);
    }

    #[test]
    fn a_malformed_digest_or_pool_path_drops_the_stanza() {
        // A stanza whose digest is not 64 hex characters, or whose pool path
        // could traverse out of a mirror root, is dropped rather than parsed.
        let base = "Package: pp\nVersion: 1.0\nArchitecture: amd64\n";
        let traversing = format!(
            "{base}Filename: pool/../../../etc/passwd\nSHA256: {}\n",
            "a".repeat(64)
        );
        assert!(Index::parse(&traversing, "amd64").get("pp").is_none());

        let bad_digest = format!("{base}Filename: pool/p.deb\nSHA256: ../../../etc/foo\n");
        assert!(Index::parse(&bad_digest, "amd64").get("pp").is_none());

        let good = format!("{base}Filename: pool/p.deb\nSHA256: {}\n", "a".repeat(64));
        assert!(Index::parse(&good, "amd64").get("pp").is_some());
    }

    #[test]
    fn a_stanza_is_kept_under_either_digest_and_held_to_each_one_s_shape() {
        let stanza = |digests: &str| {
            format!(
                "Package: held\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/p.deb\n\
                 {digests}\n"
            )
        };
        let sha256 = "a".repeat(64);
        let sha512 = "b".repeat(128);
        let read = |digests: &str| {
            Index::parse(&stanza(digests), "amd64")
                .get("held")
                .map(|package| package.digests.clone())
        };
        let both = read(&format!("SHA256: {sha256}\nSHA512: {sha512}")).expect("both read");
        assert_eq!(
            (both.sha256(), both.sha512()),
            (Some(sha256.as_str()), Some(sha512.as_str()))
        );
        let alone = read(&format!("SHA512: {sha512}")).expect("a SHA-512 alone reads");
        assert_eq!(
            (alone.sha256(), alone.sha512()),
            (None, Some(sha512.as_str()))
        );
        // Neither, or either in the wrong shape, drops the stanza.
        assert_eq!(read("MD5sum: d41d8cd98f00b204e9800998ecf8427e"), None);
        assert_eq!(read(&format!("SHA256: {sha256}\nSHA512: {sha256}")), None);
        assert_eq!(read(&format!("SHA512: {}", sha512.to_uppercase())), None);
    }

    #[test]
    fn a_stanza_naming_a_package_outside_policy_is_dropped() {
        // The name goes on to progress reports and errors as written, so it is
        // held to policy's alphabet before anything reads it. The pool path is
        // a safe one throughout, so the name is what drops each stanza. dpkg
        // installs the upper-case, `_`, and one-character names; no archive
        // publishes one.
        let stanza = |name: &str| {
            format!(
                "Package: {name}\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/p.deb\n\
                 SHA256: {}\n\n",
                "a".repeat(64),
            )
        };
        let hostile = crate::failure::hostile::TEXT;
        for name in [
            hostile, "Upper", "lib_c", "x", "-lead", ".dot", "a/b", "a b",
        ] {
            let index = Index::parse(&format!("{}{}", stanza(name), stanza("kept")), "amd64");
            assert!(index.get(name).is_none(), "{name:?} was kept");
            assert!(
                index.get("kept").is_some(),
                "{name:?} dropped its neighbour"
            );
            assert!(!index.into_available().contains(name), "{name:?}");
        }
    }

    #[test]
    fn a_stanza_stating_a_version_outside_policy_is_dropped() {
        // A version reaches a pin's refusals as written, so it is held to
        // policy's alphabet as the index is read. dpkg refuses each of these.
        let stanza = |version: &str| {
            format!(
                "Package: held\nVersion: {version}\nArchitecture: amd64\nFilename: pool/p.deb\n\
                 SHA256: {}\n\n",
                "a".repeat(64),
            )
        };
        let hostile = crate::failure::hostile::TEXT;
        for version in [hostile, "1.0_1", "1.0/1", "1 0"] {
            let index = Index::parse(&format!("{}{}", stanza(version), stanza("1.0")), "amd64");
            let kept = index.get("held").expect("the well-formed stanza is kept");
            assert_eq!(kept.version, "1.0", "{version:?}");
            assert_eq!(index.offers("held").len(), 1, "{version:?}");
            assert_eq!(index.skipped(), 1, "{version:?}");
        }
    }

    #[test]
    fn policy_admits_every_shape_an_archive_name_takes() {
        for name in [
            "0ad",
            "g++",
            "libstdc++6",
            "lib32z1-dev",
            "python3.13",
            "x11-common",
            "e2fsprogs",
        ] {
            assert!(is_package_name(name), "{name:?}");
        }
        for name in [
            "", "a", "A", "Libc6", "lib_c", "-a", "+a", ".a", "a/b", "a\u{1b}b",
        ] {
            assert!(!is_package_name(name), "{name:?}");
        }
    }

    #[test]
    fn stanzas_split_and_fold() {
        let text = "\
Package: one
Depends: a, b
Multi-Line:
 line one
 line two

Package: two
Version: 1.0
";
        let stanzas: Vec<_> = document::parse(text).collect();
        assert_eq!(stanzas.len(), 2);
        assert_eq!(stanzas[0].get("package").as_deref(), Some("one"));
        assert_eq!(
            stanzas[0].get("multi-line").as_deref(),
            Some("\nline one\nline two")
        );
        assert_eq!(stanzas[1].get("Version").as_deref(), Some("1.0"));

        // A whitespace-only line separates too, as it does for every other
        // deb822 reader; taken as a continuation it would fold the second
        // stanza into the first.
        let padded = "Package: one\n \nPackage: two\n";
        let stanzas: Vec<_> = document::parse(padded).collect();
        assert_eq!(stanzas.len(), 2);
        assert_eq!(stanzas[1].get("Package").as_deref(), Some("two"));
    }

    #[test]
    fn relations_parse_alternatives_and_keep_constraints() {
        let deps = parse_relations("libc6 (>= 2.41), mawk | gawk | awk, foo:any");
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0][0].name, "libc6");
        // The constraint is carried, not stripped: it is the question a layered
        // resolve has to put to the base's actual version.
        assert_eq!(
            deps[0][0].constraint.as_ref().unwrap().to_string(),
            ">= 2.41"
        );
        assert_eq!(
            deps[1].iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            ["mawk", "gawk", "awk"]
        );
        // An unversioned alternative carries no constraint, which any version
        // of the name satisfies.
        assert!(deps[1][0].constraint.is_none());
        // An architecture qualifier is not a version clause.
        assert_eq!(deps[2][0].name, "foo");
        assert!(deps[2][0].constraint.is_none());
    }

    #[test]
    fn provides_carry_the_version_they_declare() {
        let provided = parse_provides("awk, libz.so (= 1.0), mail-transport-agent");
        let names: Vec<&str> = provided.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["awk", "libz.so", "mail-transport-agent"]);
        // A bare provide has no version to compare, so it answers only an
        // unversioned dependency; `= 1.0` answers a versioned one too.
        assert_eq!(provided[0].version, None);
        assert_eq!(provided[1].version.as_deref(), Some("1.0"));
        assert_eq!(provided[2].version, None);
    }

    #[test]
    fn a_provides_relation_other_than_equals_is_read_as_bare() {
        // Policy permits only `=` in a Provides. Anything else is not a
        // constraint this may act on, and reading it as bare is the
        // conservative choice: it satisfies no versioned dependency.
        let provided = parse_provides("weird (>= 2.0)");
        assert_eq!(provided[0].name, "weird");
        assert_eq!(provided[0].version, None);
    }

    #[test]
    fn index_keeps_highest_version_and_filters_arch() {
        let text = "\
Package: pkg
Version: 1.0
Architecture: amd64
Filename: pool/p/pkg/pkg_1.0_amd64.deb
Size: 100
SHA256: 6161610000000000000000000000000000000000000000000000000000000000
Priority: required

Package: pkg
Version: 2.0
Architecture: amd64
Filename: pool/p/pkg/pkg_2.0_amd64.deb
Size: 100
SHA256: 6262620000000000000000000000000000000000000000000000000000000000
Priority: required

Package: other-arch
Version: 1.0
Architecture: arm64
Filename: pool/o/other/other.deb
Size: 1
SHA256: 6363630000000000000000000000000000000000000000000000000000000000
";
        let index = Index::parse(text, "amd64");
        assert_eq!(index.get("pkg").unwrap().version, "2.0");
        assert_eq!(
            index.get("pkg").unwrap().digests.sha256(),
            Some("6262620000000000000000000000000000000000000000000000000000000000")
        );
        assert!(index.get("other-arch").is_none());
        // Priority carried on the retained (highest) version.
        assert_eq!(index.base_seed(Priority::Required), ["pkg"]);
    }

    #[test]
    fn base_seed_honors_the_priority_floor() {
        // Four packages across three priority bands plus one essential package
        // whose own priority is below every floor.
        let text = "\
Package: ess
Version: 1.0
Architecture: amd64
Filename: pool/ess.deb
SHA256: 6100000000000000000000000000000000000000000000000000000000000000
Priority: optional
Essential: yes

Package: req
Version: 1.0
Architecture: amd64
Filename: pool/req.deb
SHA256: 6200000000000000000000000000000000000000000000000000000000000000
Priority: required

Package: imp
Version: 1.0
Architecture: amd64
Filename: pool/imp.deb
SHA256: 6300000000000000000000000000000000000000000000000000000000000000
Priority: important

Package: std
Version: 1.0
Architecture: amd64
Filename: pool/std.deb
SHA256: 6400000000000000000000000000000000000000000000000000000000000000
Priority: standard
";
        let index = Index::parse(text, "amd64");
        // The default floor is required: the essential package (regardless of
        // its own low priority) and the required package seed, nothing lower.
        assert_eq!(index.base_seed(Priority::Required), ["ess", "req"]);
        // An important floor adds that band but not standard.
        assert_eq!(index.base_seed(Priority::Important), ["ess", "imp", "req"]);
        // A standard floor adds that band too.
        assert_eq!(
            index.base_seed(Priority::Standard),
            ["ess", "imp", "req", "std"],
        );
    }

    #[test]
    fn priority_parses_case_insensitively() {
        // Case-insensitive both ways, and every name round-trips through the
        // rendering the archive itself writes.
        assert_eq!("required".parse(), Ok(Priority::Required));
        assert_eq!("Important".parse(), Ok(Priority::Important));
        assert_eq!("STANDARD".parse(), Ok(Priority::Standard));
        assert_eq!("optional".parse(), Ok(Priority::Optional));
        assert_eq!("extra".parse(), Ok(Priority::Extra));
        for &priority in Priority::ALL {
            let name = priority.as_str();
            assert_eq!(priority.to_string(), name);
            assert_eq!(name.parse(), Ok(priority));
        }
        let err = "bogus"
            .parse::<Priority>()
            .expect_err("bogus is no priority");
        assert_eq!(err.text(), "bogus");
        // The ordering is most-essential-first, so a lower band compares
        // greater and a floor admits everything at least as essential.
        assert!(Priority::Required < Priority::Important);
        assert!(Priority::Important < Priority::Standard);
    }

    #[test]
    fn providers_are_indexed() {
        let text = "\
Package: mawk
Version: 1.0
Architecture: amd64
Filename: pool/m/mawk/mawk.deb
Size: 1
SHA256: 6100000000000000000000000000000000000000000000000000000000000000
Provides: awk

Package: gawk
Version: 1.0
Architecture: amd64
Filename: pool/g/gawk/gawk.deb
Size: 1
SHA256: 6200000000000000000000000000000000000000000000000000000000000000
Provides: awk
";
        let index = Index::parse(text, "amd64");
        let mut providers = index.providers("awk").to_vec();
        providers.sort();
        assert_eq!(providers, ["gawk", "mawk"]);
    }

    #[test]
    fn merge_tags_origin_and_breaks_ties_to_the_first_repository() {
        // The same name at the same version in two repositories: the first
        // repository (origin 0) wins the tie and its origin is retained. A
        // higher version in the second repository wins outright.
        let primary = "\
Package: shared
Version: 1.0
Architecture: amd64
Filename: pool/shared_1.0.deb
SHA256: 702d736861726564000000000000000000000000000000000000000000000000

Package: only-primary
Version: 1.0
Architecture: amd64
Filename: pool/only-primary.deb
SHA256: 702d6f6e6c790000000000000000000000000000000000000000000000000000
";
        let extra = "\
Package: shared
Version: 1.0
Architecture: amd64
Filename: pool/shared_1.0.deb
SHA256: 652d736861726564000000000000000000000000000000000000000000000000

Package: newer
Version: 2.0
Architecture: amd64
Filename: pool/newer_2.0.deb
SHA256: 652d6e6577657200000000000000000000000000000000000000000000000000
";
        let index = Index::merge(sources([(0, primary), (1, extra)]), "amd64", &Pins::none());
        // The tie retains origin 0's package (the primary), by its digest.
        let shared = index.get("shared").unwrap();
        assert_eq!(shared.origin, 0);
        assert_eq!(
            shared.digests.sha256(),
            Some("702d736861726564000000000000000000000000000000000000000000000000")
        );
        // A package only the second repository ships is tagged with its origin.
        assert_eq!(index.get("newer").unwrap().origin, 1);
        assert_eq!(index.get("only-primary").unwrap().origin, 0);
    }

    #[test]
    fn merge_keeps_the_highest_version_across_repositories() {
        // A higher version in the second repository supersedes the first,
        // carrying its origin.
        let primary = "\
Package: pkg
Version: 1.0
Architecture: amd64
Filename: pool/pkg_1.0.deb
SHA256: 6f6c640000000000000000000000000000000000000000000000000000000000
";
        let extra = "\
Package: pkg
Version: 2.0
Architecture: amd64
Filename: pool/pkg_2.0.deb
SHA256: 6e65770000000000000000000000000000000000000000000000000000000000
";
        let index = Index::merge(sources([(0, primary), (1, extra)]), "amd64", &Pins::none());
        let pkg = index.get("pkg").unwrap();
        assert_eq!(pkg.version, "2.0");
        assert_eq!(pkg.origin, 1);
    }

    /// A one-stanza index offering `name` at `version`, with `extra` fields.
    fn offer(name: &str, version: &str, extra: &str) -> String {
        let extra = if extra.is_empty() {
            String::new()
        } else {
            format!("{extra}\n")
        };
        let mut sha256: String = format!("{name}{version}")
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        sha256.truncate(64);
        while sha256.len() < 64 {
            sha256.push('0');
        }
        format!(
            "Package: {name}\nVersion: {version}\nArchitecture: amd64\n\
             Filename: pool/{name}_{version}.deb\nSHA256: {sha256}\n{extra}\n"
        )
    }

    /// An index over the primary trixie (origin 0) and, at origins 1 and 2, a
    /// backports suite and experimental, ranked as their releases mark them.
    fn ranked(primary: &str, backports: &str, experimental: &str) -> Index {
        ranked_under(primary, backports, experimental, &Pins::none())
    }

    /// [`ranked`], merged under `pins`.
    fn ranked_under(primary: &str, backports: &str, experimental: &str, pins: &Pins) -> Index {
        Index::merge(
            [
                Source {
                    origin: 0,
                    suite: "trixie",
                    priority: ReleasePriority::Default,
                    text: primary,
                },
                Source {
                    origin: 1,
                    suite: "trixie-backports",
                    priority: ReleasePriority::AutomaticUpgrades,
                    text: backports,
                },
                Source {
                    origin: 2,
                    suite: "experimental",
                    priority: ReleasePriority::NotAutomatic,
                    text: experimental,
                },
            ],
            "amd64",
            pins,
        )
    }

    /// The pin holding `name` at the entry `index` offers it at from `origin`.
    fn pin_of(index: &Index, name: &str, origin: usize) -> Pins {
        let held = index
            .offers(name)
            .iter()
            .find(|package| package.origin == origin)
            .expect("the index offers the name from that origin");
        Pins::holding(std::slice::from_ref(held))
    }

    #[test]
    fn a_lower_ranked_release_does_not_supersede_a_higher_one() {
        // apt's default priorities: experimental's 1 and backports' 100 lose
        // to a default release's 500 whatever the versions, so adding either to
        // reach one package does not upgrade everything it carries.
        let index = ranked(
            &format!(
                "{}{}",
                offer("libc6", "2.41-1", ""),
                offer("gcc", "14.2-1", "")
            ),
            &offer("gcc", "15.1-1~bpo13+1", ""),
            &format!(
                "{}{}{}",
                offer("libc6", "2.43-1", ""),
                offer("gcc", "16.0-1", ""),
                offer("only-experimental", "1.0", ""),
            ),
        );
        assert_eq!(index.get("libc6").unwrap().version, "2.41-1");
        assert_eq!(index.get("libc6").unwrap().origin, 0);
        assert_eq!(index.get("gcc").unwrap().version, "14.2-1");
        // A name nothing else offers is the lower release's to supply.
        assert_eq!(index.get("only-experimental").unwrap().origin, 2);
        // The other versions are kept, the candidate first, for a request that
        // names a release.
        let gcc: Vec<_> = index.offers("gcc").iter().map(|p| p.origin).collect();
        assert_eq!(gcc, [0, 1, 2]);
        assert_eq!(
            index
                .in_release("gcc", "experimental")
                .unwrap()
                .unwrap()
                .version,
            "16.0-1"
        );
        assert!(
            index
                .in_release("libc6", "trixie-backports")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn backports_outranks_experimental_where_neither_is_outranked() {
        let index = ranked("", &offer("tool", "1.0~bpo", ""), &offer("tool", "2.0", ""));
        assert_eq!(index.get("tool").unwrap().version, "1.0~bpo");
    }

    #[test]
    fn the_base_is_seeded_from_the_primary_alone() {
        // debootstrap seeds from one archive. A pool or a vendor repository
        // marking a package required does not draw it into every bootstrap
        // that names the repository; a seeded name still resolves to the
        // version that wins it.
        let primary = format!(
            "{}{}",
            offer("base-files", "13.8", "Priority: required"),
            offer("dpkg", "1.22", "Essential: yes"),
        );
        let vendor = format!(
            "{}{}",
            offer("vendor-agent", "1.0", "Priority: required"),
            offer("base-files", "13.9", "Priority: optional"),
        );
        let index = Index::merge(
            sources([(0, primary.as_str()), (1, vendor.as_str())]),
            "amd64",
            &Pins::none(),
        );
        assert_eq!(index.base_seed(Priority::Required), ["base-files", "dpkg"]);
        assert_eq!(index.get("base-files").unwrap().origin, 1);
    }

    #[test]
    fn an_installed_version_is_upgraded_only_as_apt_would() {
        // An installed version stands at 100, or higher where a release still
        // offers it, and nothing below it is ever taken.
        let index = ranked(
            &format!(
                "{}{}{}",
                offer("from-main", "1.0", ""),
                offer("from-bpo", "0.9", ""),
                offer("newer-in-main", "3.0", ""),
            ),
            &format!(
                "{}{}{}",
                offer("from-main", "1.1~bpo", ""),
                offer("from-bpo", "1.1~bpo", ""),
                offer("newer-in-main", "2.5~bpo", ""),
            ),
            &format!(
                "{}{}",
                offer("from-bpo", "2.0", ""),
                offer("from-experimental", "2.0", ""),
            ),
        );
        // Installed from main, which still offers it at 500: backports' newer
        // version at 100 does not replace it.
        assert!(index.upgrade_over("from-main", "1.0").is_none());
        // Installed from backports, which no default release offers: it stands
        // at 100, and backports' newer version, at 100 too, is the upgrade.
        // experimental's higher one at 1 is not.
        assert_eq!(
            index.upgrade_over("from-bpo", "1.0~bpo").unwrap().version,
            "1.1~bpo"
        );
        // experimental never replaces what is installed.
        assert!(index.upgrade_over("from-experimental", "1.0").is_none());
        // A default release's newer version always does, over backports'.
        assert_eq!(
            index.upgrade_over("newer-in-main", "2.0").unwrap().version,
            "3.0"
        );
        // Nothing below the installed version is a candidate: no downgrade.
        assert!(index.upgrade_over("newer-in-main", "4.0").is_none());
    }

    #[test]
    fn a_release_answers_a_pinned_name_with_its_pinned_version_alone() {
        // `name/release` takes the release's highest version, unless the pin
        // holds the name: then the release answers with the pinned version, or
        // the pin refuses, naming what the release offers instead.
        let (primary, backports) = (offer("kernel", "6.12", ""), offer("kernel", "6.16~bpo", ""));
        let unpinned = ranked(&primary, &backports, "");
        let at_trixie = pin_of(&unpinned, "kernel", 0);
        let at_backports = pin_of(&unpinned, "kernel", 1);

        let index = ranked_under(&primary, &backports, "", &at_backports);
        let taken = index.in_release("kernel", "trixie-backports").unwrap();
        assert_eq!(
            taken.map(|p| (p.version.as_str(), p.origin)),
            Some(("6.16~bpo", 1))
        );

        let index = ranked_under(&primary, &backports, "", &at_trixie);
        match index.in_release("kernel", "trixie-backports") {
            Err(unheld) => {
                assert_eq!(unheld.package, "kernel");
                assert_eq!(unheld.version, "6.12");
                assert_eq!(
                    unheld.reason,
                    UnheldReason::Release {
                        release: "trixie-backports".to_string(),
                        archive: "6.16~bpo".to_string(),
                    },
                );
            }
            other => panic!("expected the pin refused, got {other:?}"),
        }
        // A release that does not carry the name at all is not the pin's to
        // refuse: there is nothing there to resolve around it.
        assert!(matches!(
            index.in_release("kernel", "experimental"),
            Ok(None)
        ));
    }

    #[test]
    fn a_release_offering_the_pinned_version_over_other_bytes_refuses_the_pin() {
        // One version in two releases, rebuilt in the second. The release named
        // offers the pinned version, but not the pinned bytes.
        let primary = offer("tool", "1.0", "");
        let rebuilt = primary.replace(
            &format!(
                "SHA256: {}",
                &primary[primary.find("SHA256: ").unwrap() + 8..][..64]
            ),
            &format!("SHA256: {}", "f".repeat(64)),
        );
        assert_ne!(primary, rebuilt, "the rebuild records other bytes");
        let pins = pin_of(&ranked(&primary, "", ""), "tool", 0);
        let index = ranked_under(&primary, &rebuilt, "", &pins);
        match index.in_release("tool", "trixie-backports") {
            Err(unheld) => assert!(
                matches!(&unheld.reason, UnheldReason::Digest { archive, .. } if *archive == "f".repeat(64)),
                "{unheld:?}",
            ),
            other => panic!("expected the pin refused, got {other:?}"),
        }
        assert!(index.in_release("tool", "trixie").unwrap().is_some());
    }

    #[test]
    fn an_installed_pinned_name_is_upgraded_to_its_pinned_version_alone() {
        // A base holds 1.0-1, the pin holds trixie's 1.0-2, and a release of
        // the same rank offers a newer 1.0-2+deb13u1. Unpinned, the upgrade is
        // the newer one; pinned, it is the pinned one, and nothing where the
        // pin holds the installed version or one below it.
        let primary = offer("libfoo1", "1.0-2", "");
        let security = offer("libfoo1", "1.0-2+deb13u1", "");
        let merged = |pins: &Pins| {
            Index::merge(
                [
                    Source {
                        origin: 0,
                        suite: "trixie",
                        priority: ReleasePriority::Default,
                        text: primary.as_str(),
                    },
                    Source {
                        origin: 1,
                        suite: "trixie-security",
                        priority: ReleasePriority::Default,
                        text: security.as_str(),
                    },
                ],
                "amd64",
                pins,
            )
        };
        let unpinned = merged(&Pins::none());
        assert_eq!(
            unpinned.upgrade_over("libfoo1", "1.0-1").unwrap().version,
            "1.0-2+deb13u1",
        );

        let index = merged(&pin_of(&unpinned, "libfoo1", 0));
        let upgrade = index.upgrade_over("libfoo1", "1.0-1").unwrap();
        assert_eq!((upgrade.version.as_str(), upgrade.origin), ("1.0-2", 0));
        assert!(index.upgrade_over("libfoo1", "1.0-2").is_none());
        assert!(index.upgrade_over("libfoo1", "1.0-3").is_none());

        // The pin decides over the rank, as it does for the candidate: a
        // pinned backports version replaces what a default release supplied.
        let primary = offer("tool", "1.0", "");
        let backports = offer("tool", "1.1~bpo", "");
        let unpinned = ranked(&primary, &backports, "");
        assert!(unpinned.upgrade_over("tool", "1.0").is_none());
        let index = ranked_under(&primary, &backports, "", &pin_of(&unpinned, "tool", 1));
        assert_eq!(
            index.upgrade_over("tool", "1.0").unwrap().version,
            "1.1~bpo"
        );
    }

    #[test]
    fn build_depend_names_reads_source_stanza_fields() {
        // A source stanza with folded, alternative, and qualified build-deps
        // across all three fields, then a binary stanza whose runtime Depends
        // must not leak into the result.
        let control = "\
Source: hello
Build-Depends: debhelper-compat (= 13),
 libfoo-dev [amd64] <!nocheck>,
 mawk | gawk
Build-Depends-Arch: libbar-dev
Build-Depends-Indep: texinfo,
 debhelper-compat (= 13)

Package: hello
Architecture: any
Depends: libc6, should-not-appear
";
        // First alternative of each group, qualifiers stripped, deduplicated
        // across the three fields (debhelper-compat appears twice), and the
        // binary stanza's Depends ignored.
        assert_eq!(
            build_depend_names(control, "amd64"),
            [
                "debhelper-compat",
                "libfoo-dev",
                "mawk",
                "libbar-dev",
                "texinfo"
            ]
        );
        // The same control text built for another architecture drops what is
        // restricted to amd64.
        assert_eq!(
            build_depend_names(control, "arm64"),
            ["debhelper-compat", "mawk", "libbar-dev", "texinfo"]
        );
    }

    #[test]
    fn an_alternative_another_architecture_needs_is_ignored() {
        // Policy 7.1: an alternative whose list excludes the architecture is
        // ignored, so the next one is chosen, and a relationship left with no
        // alternative contributes nothing. The shape real control files use for
        // a port's own toolchain.
        let control = "\
Source: p
Build-Depends: libhurd-dev [hurd-any] | libbsd-dev,
 libselinux1-dev [linux-any],
 libkvm-dev [kfreebsd-any],
 valgrind [!armel !hurd-i386],
 gcc-multilib [any-amd64],
 libarm-dev [any-arm],
 libnot-x32 [!x32],
 libfuture [gnu-any-any-loong64]
";
        assert_eq!(
            build_depend_names(control, "amd64"),
            [
                "libbsd-dev",
                "libselinux1-dev",
                "valgrind",
                "gcc-multilib",
                "libnot-x32",
                // A four-part wildcard is not one this decides, and the
                // alternative is kept rather than dropped.
                "libfuture",
            ],
        );
        assert_eq!(
            build_depend_names(control, "armel"),
            [
                "libbsd-dev",
                "libselinux1-dev",
                "libarm-dev",
                "libnot-x32",
                "libfuture",
            ],
        );
        assert_eq!(
            build_depend_names(control, "hurd-i386"),
            ["libhurd-dev", "libnot-x32", "libfuture"],
        );
        assert_eq!(
            build_depend_names(control, "x32"),
            [
                "libbsd-dev",
                "libselinux1-dev",
                "valgrind",
                "gcc-multilib",
                "libfuture",
            ],
        );
    }

    #[test]
    fn a_comment_line_neither_becomes_a_field_nor_ends_a_continuation() {
        // Policy 5.1: a line starting `#` in debian/control is a comment, and
        // is ignored even between two continuation lines. Read as a field, it
        // would take the continuation after it and lose that dependency. Only
        // a comment holding a colon reads as a field, which prose often does.
        let control = "\
# The toolchain the build needs.
Source: hello
Build-Depends: debhelper-compat (= 13),
# Note: needed for the test suite only.
 libcheck-dev,
 texinfo
#Build-Depends-Indep: not-a-field
";
        assert_eq!(
            build_depend_names(control, "amd64"),
            ["debhelper-compat", "libcheck-dev", "texinfo"],
        );
    }

    #[test]
    fn an_alternative_a_profile_may_exclude_brings_the_next_one_too() {
        // Profiles are not evaluated, so the result is a superset: a build
        // without `stage1` skips `foo` and takes `bar`, and a build with it
        // takes `foo`. Every alternative up to the first unrestricted one may
        // be the one taken. A version clause's own `<<` is not a profile.
        let control = "\
Source: p
Build-Depends: foo <stage1> | bar | baz,
 one <!nocheck> | two <nocheck> | three,
 old (<< 2.0) | newer,
 gcc-hurd [hurd-any] <stage1> | gcc
";
        assert_eq!(
            build_depend_names(control, "amd64"),
            ["foo", "bar", "one", "two", "three", "old", "gcc"],
        );
    }

    #[test]
    fn build_depend_names_tolerates_absent_fields_and_empty_input() {
        assert!(build_depend_names("", "amd64").is_empty());
        assert!(build_depend_names("Source: x\nMaintainer: y\n", "amd64").is_empty());
    }
}
