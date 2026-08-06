//! Parsing of the Debian control format and the package index.
//!
//! The archive publishes metadata in the deb822 control format: stanzas
//! separated by blank lines, each a set of `Field: value` lines with
//! continuation lines folded in. The same parser reads a `Release` file (one
//! stanza) and a `Packages` index (one stanza per package); [`Stanza`] is the
//! shared representation, and [`Index`] is the package set built from a
//! `Packages` file, deduplicated to the highest version of each name.

use std::collections::HashMap;

use super::available::Available;
use super::version;

/// One control-format stanza: its fields in file order.
///
/// Field names are matched case-insensitively. A folded value keeps its
/// continuation lines joined with newlines, so a multi-line field such as a
/// `Release` file's `SHA256` list is read line by line by the caller.
pub(crate) struct Stanza {
    fields: Vec<(String, String)>,
}

impl Stanza {
    /// The value of `key`, matched case-insensitively, or `None`.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
    }

    /// Every field, in the order the stanza wrote them.
    ///
    /// For a reader that has to account for fields it does not itself
    /// understand, rather than only look up the ones it does.
    pub(crate) fn fields(&self) -> &[(String, String)] {
        &self.fields
    }
}

/// Splits control-format text into stanzas.
pub(crate) fn parse_stanzas(text: &str) -> Vec<Stanza> {
    let mut stanzas = Vec::new();
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        // A blank line ends a stanza. Whitespace-only counts as blank: deb822
        // readers treat it so, and a continuation line is one that starts with
        // a space *and* carries content.
        if line.trim().is_empty() {
            if !fields.is_empty() {
                stanzas.push(Stanza {
                    fields: std::mem::take(&mut fields),
                });
            }
            continue;
        }
        if line.starts_with([' ', '\t']) {
            // A continuation of the current field. deb822 removes the single
            // leading space; the newline is kept so multi-line lists split.
            if let Some((_, value)) = fields.last_mut() {
                value.push('\n');
                value.push_str(line.strip_prefix(' ').unwrap_or(line));
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            fields.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    if !fields.is_empty() {
        stanzas.push(Stanza { fields });
    }
    stanzas
}

/// One package's metadata from a `Packages` index.
#[derive(Debug, Clone)]
pub(crate) struct Package {
    pub name: String,
    pub version: String,
    pub architecture: String,
    /// The pool path (`Filename:`), relative to the mirror root.
    pub filename: String,
    pub sha256: String,
    pub depends: Vec<Dependency>,
    pub pre_depends: Vec<Dependency>,
    /// Virtual package names this package provides (versions stripped).
    pub provides: Vec<String>,
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

/// One alternative within a dependency: a package name. Version constraints
/// and architecture qualifiers are parsed away, since a single coherent
/// suite is internally consistent and the bootstrap installs one architecture.
#[derive(Debug, Clone)]
pub(crate) struct DepAtom {
    pub name: String,
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

impl Priority {
    /// Parses a Debian `Priority:` field value case-insensitively, returning
    /// `None` for an unrecognized value.
    fn parse(value: &str) -> Option<Priority> {
        for (name, priority) in [
            ("required", Priority::Required),
            ("important", Priority::Important),
            ("standard", Priority::Standard),
            ("optional", Priority::Optional),
            ("extra", Priority::Extra),
        ] {
            if value.eq_ignore_ascii_case(name) {
                return Some(priority);
            }
        }
        None
    }
}

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
        if !is_sha256_hex(&sha256) {
            return None;
        }
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
        self.priority.as_deref().and_then(Priority::parse)
    }
}

/// Whether `digest` has the shape of a SHA-256: exactly 64 lowercase hex
/// characters. This is the only form an archive-supplied digest is ever used in
/// — a cache filename, a `by-hash` URL segment, and the fetch verifier's
/// expected value — so an index or release line carrying anything else is
/// malformed, and rejecting it keeps an archive-supplied digest from reaching a
/// filesystem path or a request line as, say, a traversal.
pub(super) fn is_sha256_hex(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `filename` is a safe pool path: a non-empty relative path with no
/// traversal component, no leading slash, and no byte outside the printable
/// ASCII range.
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
pub(super) fn is_safe_pool_path(filename: &str) -> bool {
    !filename.is_empty()
        && !filename.starts_with('/')
        && filename.bytes().all(|byte| byte.is_ascii_graphic())
        && !filename.split('/').any(|component| component == "..")
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
        Index::merge(std::iter::once((0, text)), architecture)
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
    pub(crate) fn merge<'a>(
        inputs: impl IntoIterator<Item = (usize, &'a str)>,
        architecture: &str,
    ) -> Index {
        let mut by_name: HashMap<String, Package> = HashMap::new();
        for (origin, text) in inputs {
            for stanza in parse_stanzas(text) {
                let Some(mut package) = Package::from_stanza(&stanza) else {
                    continue;
                };
                if package.architecture != architecture && package.architecture != "all" {
                    continue;
                }
                package.origin = origin;
                match by_name.get(&package.name) {
                    Some(existing)
                        if version::compare(&package.version, &existing.version)
                            != std::cmp::Ordering::Greater => {}
                    _ => {
                        by_name.insert(package.name.clone(), package);
                    }
                }
            }
        }

        let mut providers: HashMap<String, Vec<String>> = HashMap::new();
        for package in by_name.values() {
            for virtual_name in &package.provides {
                providers
                    .entry(virtual_name.clone())
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

/// Parses a `Provides` value into virtual package names.
pub(crate) fn parse_provides(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter_map(parse_atom)
        .map(|atom| atom.name)
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

/// Parses one dependency alternative into its package name, dropping the
/// version constraint, architecture qualifier, and any restriction lists.
fn parse_atom(text: &str) -> Option<DepAtom> {
    let name: String = text
        .trim()
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, '(' | ':' | '[' | '<'))
        .collect();
    (!name.is_empty()).then_some(DepAtom { name })
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
    let stanzas = parse_stanzas(control);
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
    fn digest_and_pool_path_shapes_are_validated() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"a".repeat(63)), "too short");
        assert!(!is_sha256_hex(&"A".repeat(64)), "uppercase is not accepted");
        assert!(!is_sha256_hex(&"g".repeat(64)), "non-hex is not accepted");
        assert!(!is_sha256_hex("../../../etc/foo"));

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
    fn a_stanza_reports_its_installed_size_and_source_package() {
        let text = format!(
            "Package: bind9-dnsutils\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/p.deb\n\
             SHA256: {}\nInstalled-Size: 412\nSource: bind9 (1:9.20.4-1)\n",
            "a".repeat(64),
        );
        let index = Index::parse(&text, "amd64");
        let package = index.get("bind9-dnsutils").expect("the stanza parses");
        // The archive's own unit, kibibytes, rather than bytes: a value that
        // differs from the mirror's is one more thing that can disagree with it.
        assert_eq!(package.installed_size, Some(412));
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
        assert_eq!(package.source, None);

        let malformed = format!("{base}Installed-Size: unknown\n");
        let index = Index::parse(&malformed, "amd64");
        let package = index.get("p").expect("the stanza still parses");
        assert_eq!(package.installed_size, None);
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
        let stanzas = parse_stanzas(text);
        assert_eq!(stanzas.len(), 2);
        assert_eq!(stanzas[0].get("package"), Some("one"));
        assert_eq!(stanzas[0].get("multi-line"), Some("\nline one\nline two"));
        assert_eq!(stanzas[1].get("Version"), Some("1.0"));

        // A whitespace-only line separates too, as it does for every other
        // deb822 reader; taken as a continuation it would fold the second
        // stanza into the first.
        let padded = "Package: one\n \nPackage: two\n";
        let stanzas = parse_stanzas(padded);
        assert_eq!(stanzas.len(), 2);
        assert_eq!(stanzas[1].get("Package"), Some("two"));
    }

    #[test]
    fn relations_parse_alternatives_and_strip_constraints() {
        let deps = parse_relations("libc6 (>= 2.41), mawk | gawk | awk, foo:any");
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0][0].name, "libc6");
        assert_eq!(
            deps[1].iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            ["mawk", "gawk", "awk"]
        );
        assert_eq!(deps[2][0].name, "foo");
    }

    #[test]
    fn provides_strip_versions() {
        let provided = parse_provides("awk, libz.so (= 1.0), mail-transport-agent");
        assert_eq!(provided, ["awk", "libz.so", "mail-transport-agent"]);
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
        assert_eq!(Priority::parse("required"), Some(Priority::Required));
        assert_eq!(Priority::parse("Important"), Some(Priority::Important));
        assert_eq!(Priority::parse("STANDARD"), Some(Priority::Standard));
        assert_eq!(Priority::parse("optional"), Some(Priority::Optional));
        assert_eq!(Priority::parse("extra"), Some(Priority::Extra));
        assert_eq!(Priority::parse("bogus"), None);
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
        let index = Index::merge([(0, primary), (1, extra)], "amd64");
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
        let index = Index::merge([(0, primary), (1, extra)], "amd64");
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
