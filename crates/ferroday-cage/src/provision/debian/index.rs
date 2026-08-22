//! Parsing of the Debian control format and the package index.
//!
//! The archive publishes metadata in the deb822 control format: stanzas
//! separated by blank lines, each a set of `Field: value` lines with
//! continuation lines folded in. The same parser reads a `Release` file (one
//! stanza) and a `Packages` index (one stanza per package). The syntax itself
//! is [`crate::provision::document`], which every layer's plan documents are
//! written in as well; [`Index`] is the package set built from a `Packages`
//! file, deduplicated to the highest version of each name.

use std::collections::HashMap;
use std::fmt;

use super::available::Available;
use super::pin::Pins;
use super::version::{self, Constraint};
use crate::provision::digest::Algorithm;
use crate::provision::document::{self, Stanza};

/// One package's metadata from a `Packages` index.
#[derive(Debug, Clone)]
pub(crate) struct Package {
    pub name: String,
    pub version: String,
    pub architecture: String,
    /// The pool path (`Filename:`), relative to the mirror root.
    pub filename: String,
    /// The archive's `Size:` — the length of the `.deb` on the wire, in bytes —
    /// when the stanza carries a usable one. It bounds what the download may
    /// spend before its digest is checked, so it is read from the index whose
    /// own digest the verified release records.
    pub size: Option<u64>,
    pub sha256: String,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Priority {
    /// Packages without which the system does not function or cannot be
    /// installed. The base of every bootstrap.
    Required,
    /// Packages present on all but the most minimal systems, expected to be
    /// installed.
    Important,
    /// The result of a standard, reasonably small character-mode install.
    Standard,
    /// Packages outside the base selection, the archive's bulk.
    Optional,
    /// A deprecated band the archive folds into [`Optional`](Self::Optional);
    /// recognized for completeness.
    Extra,
}

/// The priority names, in the order the variants declare them: the archive's
/// own spelling of each band.
const PRIORITY_NAMES: [(&str, Priority); 5] = [
    ("required", Priority::Required),
    ("important", Priority::Important),
    ("standard", Priority::Standard),
    ("optional", Priority::Optional),
    ("extra", Priority::Extra),
];

impl fmt::Display for Priority {
    /// Writes the archive's own spelling, which is what
    /// [`FromStr`](std::str::FromStr) reads back.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, _) = PRIORITY_NAMES
            .iter()
            .find(|(_, priority)| priority == self)
            .expect("every priority has a name");
        f.write_str(name)
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
        PRIORITY_NAMES
            .iter()
            .find(|(name, _)| value.eq_ignore_ascii_case(name))
            .map(|(_, priority)| *priority)
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
        write!(
            f,
            "unknown priority {:?}: expected required, important, standard, optional, or extra",
            self.text,
        )
    }
}

impl std::error::Error for ParsePriorityError {}

impl Package {
    /// Builds a package from a `Packages` stanza, or `None` when a required
    /// field is missing or malformed.
    fn from_stanza(stanza: &Stanza) -> Option<Package> {
        let name = stanza.get("Package")?.to_string();
        let version = stanza.get("Version")?.to_string();
        let architecture = stanza.get("Architecture")?.to_string();
        // The digest becomes a cache filename and the fetch verifier's expected
        // value, and the pool path becomes a fetch URL and (for a `file://`
        // mirror) a local path. Neither is trusted until the archive signature
        // is checked, so validate their shape here, at the boundary where the
        // index is parsed, rather than at each use site: a stanza whose digest
        // is not 64 lowercase hex characters or whose pool path could traverse
        // out of a mirror root is malformed and dropped.
        let filename = stanza.get("Filename")?.to_string();
        if !is_safe_pool_path(&filename) {
            return None;
        }
        let sha256 = stanza.get("SHA256")?.to_string();
        if !Algorithm::Sha256.is_hex(&sha256) {
            return None;
        }
        // A stanza that states no size, or states one that does not parse,
        // leaves the download bounded by the fetcher's own ceiling rather than
        // being dropped: the digest is what decides whether the bytes are the
        // package, and a missing bound is a weaker fetch, not a wrong one.
        let size = stanza
            .get("Size")
            .and_then(|value| value.parse::<u64>().ok());
        // Read before the literal below moves `name`, which the source name is
        // compared against. Neither field is required: a stanza missing or
        // malforming one is reported as carrying no value rather than dropped,
        // since nothing the bootstrap does depends on either.
        let installed_size = stanza
            .get("Installed-Size")
            .and_then(|value| value.parse::<u64>().ok());
        let source = stanza
            .get("Source")
            .and_then(|value| source_name(value, &name));
        Some(Package {
            name,
            version,
            architecture,
            filename,
            size,
            sha256,
            depends: stanza
                .get("Depends")
                .map(parse_relations)
                .unwrap_or_default(),
            pre_depends: stanza
                .get("Pre-Depends")
                .map(parse_relations)
                .unwrap_or_default(),
            provides: stanza
                .get("Provides")
                .map(parse_provides)
                .unwrap_or_default(),
            essential: stanza
                .get("Essential")
                .is_some_and(|value| value.eq_ignore_ascii_case("yes")),
            priority: stanza.get("Priority").map(str::to_string),
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
    match percent_decode(filename.as_bytes()) {
        Some(decoded) => is_safe_pool_shape(&decoded),
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

/// Percent-decodes `path`, or `None` where an escape is malformed or decodes to
/// a `%` — the byte that would let a second decoding pass reveal something this
/// one did not see.
fn percent_decode(path: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(path.len());
    let mut bytes = path.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            decoded.push(byte);
            continue;
        }
        let high = hex_value(bytes.next()?)?;
        let low = hex_value(bytes.next()?)?;
        let value = high * 16 + low;
        if value == b'%' {
            return None;
        }
        decoded.push(value);
    }
    Some(decoded)
}

/// The value of one hexadecimal digit, either case.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The package set of one suite: the highest version of each real name, plus
/// a virtual-package index mapping each provided name to its providers.
pub(crate) struct Index {
    by_name: HashMap<String, Package>,
    providers: HashMap<String, Vec<String>>,
}

impl Index {
    /// Parses a single `Packages` index, keeping the highest version of each
    /// name and filtering to the requested architecture plus `all`. Every
    /// package is tagged with origin zero.
    #[cfg(test)]
    pub(crate) fn parse(text: &str, architecture: &str) -> Index {
        Index::merge(std::iter::once((0, text)), architecture, &Pins::none())
    }

    /// Parses and merges several repositories' `Packages` indexes into one set,
    /// keeping the highest version of each name across the union and tagging
    /// each retained package with the origin it came from.
    ///
    /// The inputs are `(origin, text)` pairs, one per repository component,
    /// yielded in repository-then-component order. Resolution is
    /// highest-version-wins, extended across repositories; an exact-version tie
    /// resolves to the first repository in that order, since the earlier origin
    /// is retained when a later one does not compare greater.
    ///
    /// A name `pins` holds selects the pinned version instead of the highest,
    /// again taking the first repository that offers it. Where no repository
    /// offers the pinned version the highest is kept, so [`Pins::check`] can
    /// report what the archives carry rather than only that something is
    /// missing; that check runs before anything resolves against the index.
    pub(crate) fn merge<'a>(
        inputs: impl IntoIterator<Item = (usize, &'a str)>,
        architecture: &str,
        pins: &Pins,
    ) -> Index {
        let mut by_name: HashMap<String, Package> = HashMap::new();
        for (origin, text) in inputs {
            for stanza in document::parse(text) {
                let Some(mut package) = Package::from_stanza(&stanza) else {
                    continue;
                };
                if package.architecture != architecture && package.architecture != "all" {
                    continue;
                }
                package.origin = origin;
                let higher = |candidate: &Package, existing: &Package| {
                    version::compare(&candidate.version, &existing.version)
                        == std::cmp::Ordering::Greater
                };
                let keep = match by_name.get(&package.name) {
                    None => true,
                    // A pin already satisfied is not displaced, by a higher
                    // version or by a later repository offering the same one.
                    Some(existing) if pins.names(&package.name) => {
                        !pins.holds(&package.name, &existing.version)
                            && (pins.holds(&package.name, &package.version)
                                || higher(&package, existing))
                    }
                    Some(existing) => higher(&package, existing),
                };
                if keep {
                    by_name.insert(package.name.clone(), package);
                }
            }
        }

        let mut providers: HashMap<String, Vec<String>> = HashMap::new();
        for package in by_name.values() {
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
        }

        Index { by_name, providers }
    }

    /// The package with `name`, if it is a real package in this index.
    pub(crate) fn get(&self, name: &str) -> Option<&Package> {
        self.by_name.get(name)
    }

    /// The real packages that provide the virtual package `name`.
    pub(crate) fn providers(&self, name: &str) -> &[String] {
        self.providers.get(name).map_or(&[], Vec::as_slice)
    }

    /// Projects the index into the names it offers, consuming it.
    ///
    /// The parsed packages go: what a caller asking about availability wants is
    /// the name set and the provider map, and retaining tens of megabytes of
    /// relation vectors to back a membership question would be the wrong trade.
    pub(crate) fn into_available(self) -> Available {
        Available::new(self.by_name.into_keys().collect(), self.providers)
    }

    /// The base seed: every essential package and every package whose priority
    /// is at least `floor` (that is, at least as essential as it). With the
    /// default floor [`Priority::Required`] this is `debootstrap`'s minbase set;
    /// a less essential floor such as [`Priority::Important`] additionally seeds
    /// that band, matching the corresponding bootstrap variant. `apt` and the
    /// caller's includes are added on top by the caller.
    pub(crate) fn base_seed(&self, floor: Priority) -> Vec<String> {
        let mut seed: Vec<String> = self
            .by_name
            .values()
            .filter(|package| {
                package.essential || package.priority_band().is_some_and(|band| band <= floor)
            })
            .map(|package| package.name.clone())
            .collect();
        seed.sort();
        seed
    }
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
/// file.
///
/// Parses the `Build-Depends`, `Build-Depends-Arch`, and `Build-Depends-Indep`
/// fields of the control text's first stanza — the source stanza — and returns
/// one package name per relationship: the first alternative of an `a | b`
/// group, with version constraints, architecture qualifiers, and build-profile
/// restrictions stripped, matching the resolver's discipline. Names are
/// returned in field order and deduplicated, keeping the first appearance.
/// Architecture and profile restrictions are not evaluated, so the result is a
/// superset that is safe to install into a build environment.
///
/// The names are meant for
/// [`DebianBuilder::include`](crate::provision::debian::DebianBuilder::include),
/// which bakes them into the bootstrap so a package build runs without
/// resolving its build dependencies at build time. The caller supplies the
/// control text from wherever the source lives — a working tree, a git
/// checkout, or an archive `Sources` stanza — so the source of the metadata is
/// the caller's to choose.
pub fn build_depend_names(control: &str) -> Vec<String> {
    let stanzas = document::parse(control);
    let Some(source) = stanzas.first() else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for field in ["Build-Depends", "Build-Depends-Arch", "Build-Depends-Indep"] {
        let Some(value) = source.get(field) else {
            continue;
        };
        for group in parse_relations(value) {
            if let Some(atom) = group.into_iter().next()
                && seen.insert(atom.name.clone())
            {
                names.push(atom.name);
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
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
            "Package: p\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/p.deb\nSHA256: {}\n",
            "a".repeat(64),
        );
        let index = Index::parse(&base, "amd64");
        let package = index.get("p").expect("the stanza parses");
        assert_eq!(package.installed_size, None);
        assert_eq!(package.size, None);
        assert_eq!(package.source, None);

        let malformed = format!("{base}Installed-Size: unknown\nSize: huge\n");
        let index = Index::parse(&malformed, "amd64");
        let package = index.get("p").expect("the stanza still parses");
        assert_eq!(package.installed_size, None);
        assert_eq!(package.size, None);
    }

    #[test]
    fn a_malformed_digest_or_pool_path_drops_the_stanza() {
        // A stanza whose digest is not 64 hex characters, or whose pool path
        // could traverse out of a mirror root, is dropped rather than parsed.
        let base = "Package: p\nVersion: 1.0\nArchitecture: amd64\n";
        let traversing = format!(
            "{base}Filename: pool/../../../etc/passwd\nSHA256: {}\n",
            "a".repeat(64)
        );
        assert!(Index::parse(&traversing, "amd64").get("p").is_none());

        let bad_digest = format!("{base}Filename: pool/p.deb\nSHA256: ../../../etc/foo\n");
        assert!(Index::parse(&bad_digest, "amd64").get("p").is_none());

        let good = format!("{base}Filename: pool/p.deb\nSHA256: {}\n", "a".repeat(64));
        assert!(Index::parse(&good, "amd64").get("p").is_some());
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
        let stanzas = document::parse(text);
        assert_eq!(stanzas.len(), 2);
        assert_eq!(stanzas[0].get("package"), Some("one"));
        assert_eq!(stanzas[0].get("multi-line"), Some("\nline one\nline two"));
        assert_eq!(stanzas[1].get("Version"), Some("1.0"));

        // A whitespace-only line separates too, as it does for every other
        // deb822 reader; taken as a continuation it would fold the second
        // stanza into the first.
        let padded = "Package: one\n \nPackage: two\n";
        let stanzas = document::parse(padded);
        assert_eq!(stanzas.len(), 2);
        assert_eq!(stanzas[1].get("Package"), Some("two"));
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
            index.get("pkg").unwrap().sha256,
            "6262620000000000000000000000000000000000000000000000000000000000"
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
        for (name, priority) in PRIORITY_NAMES {
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
        let index = Index::merge([(0, primary), (1, extra)], "amd64", &Pins::none());
        // The tie retains origin 0's package (the primary), by its digest.
        let shared = index.get("shared").unwrap();
        assert_eq!(shared.origin, 0);
        assert_eq!(
            shared.sha256,
            "702d736861726564000000000000000000000000000000000000000000000000"
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
        let index = Index::merge([(0, primary), (1, extra)], "amd64", &Pins::none());
        let pkg = index.get("pkg").unwrap();
        assert_eq!(pkg.version, "2.0");
        assert_eq!(pkg.origin, 1);
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
            build_depend_names(control),
            [
                "debhelper-compat",
                "libfoo-dev",
                "mawk",
                "libbar-dev",
                "texinfo"
            ]
        );
    }

    #[test]
    fn build_depend_names_tolerates_absent_fields_and_empty_input() {
        assert!(build_depend_names("").is_empty());
        assert!(build_depend_names("Source: x\nMaintainer: y\n").is_empty());
    }
}
