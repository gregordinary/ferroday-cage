//! Layered build roots: what an Alpine base layer already carries.
//!
//! A build pipeline provisions a base root once, then per component stages only
//! that component's build dependencies over it. This module reads the base: the
//! packages its database records, the state a merged root has to keep carrying,
//! and the triggers its own packages watch. The staging and configure
//! orchestration lives in the [parent module](super) beside the full-bootstrap
//! pipeline it reuses.
//!
//! # Why the base is read rather than assumed
//!
//! An increment is written into an overlay upper, and an overlay unions
//! *files*: the `lib/apk/db/installed` the increment writes shadows the base's
//! copy outright rather than merging with it. So the increment's database has to
//! describe the whole merged root, and everything the base contributed is read
//! here and carried through byte for byte.
//!
//! The same read answers the resolver's question. Unlike the Debian layer's
//! already-installed set, which is a set of names, this keeps each base
//! package's version and the versions of the names it provides: apk dependencies
//! routinely carry a constraint — `so:libc.musl-x86_64.so.1=1.2.5-r23` is how
//! the archive spells a soname — and a base treated as satisfying a name at any
//! version would produce an increment that does not close.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::apk::Member;
use super::bootstrap::{ARCH, REPOSITORIES, ScriptKind, ScriptSubject, WORLD};
use super::index::Record;
use super::installed::{Carried, DB_DIR, Existing};
use super::{AlpineError, apk};
use crate::ErrorChain;
use crate::provision::rooted::Rooted;

/// The database a base layer's packages are recorded in.
const INSTALLED: &str = "installed";

/// The paths each recorded package watches for changes.
const TRIGGERS: &str = "triggers";

/// Every install script the base's packages carried, as `apk` archives them.
const SCRIPTS: &str = "scripts.tar";

/// The same archive, compressed.
///
/// `apk` probes [`SCRIPTS`] first and falls back to this, and it writes whichever
/// it found — so which name a base carries says which tool wrote it. This layer
/// writes the plain one; Alpine's own published minirootfs carries this one. A
/// base is read from either.
const SCRIPTS_GZ: &str = "scripts.tar.gz";

/// The ceiling on a base's archived scripts, plain or once decompressed.
///
/// Alpine's minirootfs archives 15 KB of shell; this is generous by three
/// orders of magnitude and still the reason a base cannot expand without end,
/// whether through gzip's ratio or through a file grown without being written.
const MAX_SCRIPTS: u64 = 64 * 1024 * 1024;

/// The most of a base's installed database this reads.
///
/// `apk` records a few hundred bytes per package and about a hundred and forty
/// per file it installed: Alpine's own minirootfs, sixteen packages and a
/// hundred and ten files, comes to fifteen kilobytes. A root of a hundred
/// thousand files is some fifteen megabytes, and this is far past that.
const MAX_DATABASE: u64 = 256 * 1024 * 1024;

/// The most of any other file of a base's this reads: its triggers, and the
/// one-line-per-entry files under `/etc/apk`, each a few hundred bytes in a
/// real root.
const MAX_STATE: u64 = 16 * 1024 * 1024;

/// The most paths a base's triggers file may watch, a path one package watches
/// twice counted once.
///
/// Alpine's own minirootfs watches six, all of them busybox's, and a root
/// watches a few per package that has a trigger at all. The file is one a
/// base's own scripts could have rewritten, and every path it watches is
/// matched against every directory an increment creates, so this is what holds
/// that work to the size of the increment rather than to the size of the file.
const MAX_TRIGGER_PATTERNS: usize = 4096;

/// What a base layer already carries.
///
/// Read by [`Base::read`] from the base's own tree, so the packages an increment
/// resolves against and the state a merged root keeps are the base's actual
/// contents rather than anything the caller has to thread through.
pub(super) struct Base {
    /// The packages the base's database records.
    packages: Vec<Existing>,
    /// The base's `triggers` file.
    triggers: Vec<u8>,
    /// The base's `scripts.tar`.
    scripts: Vec<u8>,
    /// The base's `/etc/apk/world`: what its own root asked for.
    world: Vec<String>,
    /// The base's `/etc/apk/repositories`, one URL per line.
    repositories: Vec<String>,
    /// Where the base sits, for the refusals.
    path: PathBuf,
}

impl Base {
    /// Reads a base layer's state, refusing a tree that is not a registered apk
    /// root.
    ///
    /// The read is anchored to a descriptor for the base: it is a caller-supplied
    /// tree, and a symbolic link at one of these paths would otherwise be
    /// followed against the host's root, turning this into a read of an arbitrary
    /// host file whose contents decide what the increment resolves against.
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Config`] when the base records no installed
    /// package — a directory that was never provisioned, or one provisioned as
    /// something other than an Alpine root — when its database cannot be read as
    /// one, or when it was built for another architecture. Returns
    /// [`AlpineError::Io`] when a file that is there cannot be read.
    pub(super) fn read(path: &Path, architecture: &str) -> Result<Base, AlpineError> {
        let tree = Rooted::open(path).map_err(AlpineError::at("opening the base layer", path))?;
        let refuse = |reason: String| {
            AlpineError::config(format!("the base layer at {}: {reason}", path.display()))
        };

        let database = format!("{DB_DIR}/{INSTALLED}");
        let recorded = match tree.read_if_present(&database, MAX_DATABASE) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return Err(refuse(
                    "it records no installed packages; a base layer is a provisioned Alpine root, \
                     and this tree has no apk database"
                        .to_string(),
                ));
            }
            Err(source) => {
                return Err(AlpineError::io(
                    "reading the base layer's database",
                    tree.path(&database),
                    source,
                ));
            }
        };
        let packages = super::installed::parse(&recorded).map_err(refuse)?;
        if packages.is_empty() {
            return Err(refuse(
                "its apk database records no package; a base layer is a root an increment is \
                 installed over, and there is nothing here to layer over"
                    .to_string(),
            ));
        }

        // The architecture the base was built for, where it states one. An
        // increment's packages are laid over the base's files, so two
        // architectures in one root is a build root that cannot run.
        if let Some(built_for) = optional_text(&tree, ARCH, path, MAX_STATE)?
            && built_for.trim() != architecture
        {
            return Err(refuse(format!(
                "it was built for {:?}, and the increment is being resolved for {architecture}",
                built_for.trim(),
            )));
        }

        Ok(Base {
            packages,
            triggers: optional_bytes(&tree, &format!("{DB_DIR}/{TRIGGERS}"), path, MAX_STATE)?,
            scripts: read_scripts(&tree, path)?,
            world: lines(optional_text(&tree, WORLD, path, MAX_STATE)?),
            repositories: lines(optional_text(&tree, REPOSITORIES, path, MAX_STATE)?),
            path: path.to_path_buf(),
        })
    }

    /// The packages the base records, as the index records they are written as.
    ///
    /// What seeds a delta resolution: each one answers its own name at its own
    /// version and every name it provides at the version it provides it at.
    pub(super) fn records(&self) -> impl Iterator<Item = &Record> {
        self.packages.iter().map(|existing| &existing.record)
    }

    /// The state the increment's database carries forward, so the file it writes
    /// into the overlay upper describes the merged root.
    pub(super) fn carried(&self) -> Carried {
        Carried {
            records: self
                .packages
                .iter()
                .map(|existing| (existing.record.name.clone(), existing.raw.clone()))
                .collect(),
            triggers: self.triggers.clone(),
            scripts: self.scripts.clone(),
        }
    }

    /// What the base's own root asked for, which the increment's request is
    /// added to.
    pub(super) fn world(&self) -> &[String] {
        &self.world
    }

    /// The repositories the base records, which the increment's are added to.
    pub(super) fn repositories(&self) -> &[String] {
        &self.repositories
    }

    /// Where the base sits: the read-only lower of the overlay an increment's
    /// scripts run over.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// The base's archived trigger scripts, read out of its script archive once
    /// for [`trigger_subjects`](Self::trigger_subjects) to borrow from.
    ///
    /// Empty where the base's triggers file watches nothing, so the archive of a
    /// base no trigger reads is carried forward without being decoded.
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Config`] when the archive is not a readable tar.
    pub(super) fn trigger_scripts(&self) -> Result<Vec<Member>, AlpineError> {
        // A base that carries neither `scripts.tar` nor `scripts.tar.gz` reads
        // as no bytes at all, which is not the same as an archive holding no
        // members: no stream arrived to be one. A trigger whose script such a
        // base has nowhere to keep is refused by `trigger_subjects`, by the name
        // that is missing, rather than here as an unreadable archive.
        if self.scripts.is_empty() || self.triggers.trim_ascii().is_empty() {
            return Ok(Vec::new());
        }
        let mut archived = apk::read_members(&self.scripts).map_err(|err| {
            self.refusal(format!(
                "its archived scripts are not a readable tar: {}",
                ErrorChain::new(&err),
            ))
        })?;
        archived.retain(|member| trigger_identity(&member.name).is_some());
        Ok(archived)
    }

    /// The base's own packages as trigger subjects, so a directory the increment
    /// creates fires the base's trigger for it.
    ///
    /// This is what `apk` does and what `dpkg` does for the Debian layer: a
    /// trigger belongs to the installed root rather than to the transaction, so
    /// an increment that adds a certificate rebuilds the base's certificate
    /// bundle and one that adds a Python module byte-compiles it. Only packages
    /// that watch a path are returned; the caller matches the patterns against
    /// the directories the increment created and runs what matched.
    ///
    /// `archived` is what [`trigger_scripts`](Self::trigger_scripts) read, and
    /// each subject borrows its script from there and its patterns from the
    /// base's triggers file.
    ///
    /// # One subject per package
    ///
    /// The triggers file is one the base's own scripts could have rewritten, so
    /// it is read the way `apk` reads it rather than trusted to be the file
    /// `apk` writes. `apk` keys it by control identity, and a second line for
    /// one package adds to the paths that package watches. So one package is one
    /// subject however many lines name it, and a path it watches twice is
    /// watched once. Every lookup is by identity in a table built once, and the
    /// paths watched across the whole file are held to [`MAX_TRIGGER_PATTERNS`].
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Config`] when the base's database contradicts
    /// itself — a `triggers` line naming a package the database does not record,
    /// or a package whose archived trigger script is absent — or when its
    /// triggers file watches more than [`MAX_TRIGGER_PATTERNS`] paths. The first
    /// two would mean silently not running a trigger `apk` would have run,
    /// which is worse than refusing a base that is not whole.
    pub(super) fn trigger_subjects<'a>(
        &'a self,
        archived: &'a [Member],
    ) -> Result<Vec<ScriptSubject<'a>>, AlpineError> {
        let watched = std::str::from_utf8(&self.triggers)
            .map_err(|_| self.refusal("its triggers file is not UTF-8".to_string()))?;
        if watched.trim().is_empty() {
            return Ok(Vec::new());
        }

        // A record can be named by more than one line, and a hostile database
        // can carry one identity twice. A line belongs to the first record that
        // carries its identity, so the table keeps the first.
        let mut records: HashMap<&str, &Record> = HashMap::new();
        for record in self.records() {
            records.entry(&record.control_identity).or_insert(record);
        }
        // What each package watches, in the order its identity first appears,
        // and every path once.
        let mut watching: Vec<(&Record, Vec<&str>)> = Vec::new();
        let mut slot: HashMap<&str, usize> = HashMap::new();
        let mut seen: HashSet<(&str, &str)> = HashSet::new();
        for line in watched.lines().filter(|line| !line.trim().is_empty()) {
            // A line is the package's control identity, then the paths it
            // watches: the same identity its record opens with, which is how
            // `apk` finds the record the line belongs to.
            let (identity, patterns) = line.split_once(' ').unwrap_or((line, ""));
            let Some(&record) = records.get(identity) else {
                return Err(self.refusal(format!(
                    "its triggers file names {identity:?}, which no record in its database carries",
                )));
            };
            let at = *slot.entry(identity).or_insert_with(|| {
                watching.push((record, Vec::new()));
                watching.len() - 1
            });
            for pattern in patterns.split_ascii_whitespace() {
                if !seen.insert((identity, pattern)) {
                    continue;
                }
                if seen.len() > MAX_TRIGGER_PATTERNS {
                    return Err(self.refusal(format!(
                        "its triggers file watches more than {MAX_TRIGGER_PATTERNS} paths, which \
                         is past what this layer matches an increment against",
                    )));
                }
                watching[at].1.push(pattern);
            }
        }

        // Each archived trigger script by the identity its name files it under,
        // so a package's script is found without a walk of the archive.
        let mut scripts: HashMap<String, Vec<(&str, &Member)>> = HashMap::new();
        for member in archived {
            if let Some((filed_under, identity)) = trigger_identity(&member.name) {
                scripts
                    .entry(identity)
                    .or_default()
                    .push((filed_under, member));
            }
        }

        let mut subjects = Vec::with_capacity(watching.len());
        // A package whose lines name no path watches nothing, and `apk` lists it
        // among no trigger's subjects; nor does this.
        for (record, patterns) in watching
            .into_iter()
            .filter(|(_, patterns)| !patterns.is_empty())
        {
            let filed_under = format!("{}-{}", record.name, record.version);
            let script = scripts
                .get(&record.control_identity)
                .and_then(|candidates| {
                    candidates
                        .iter()
                        .find(|(filed, _)| *filed == filed_under)
                        .map(|(_, member)| *member)
                })
                .ok_or_else(|| {
                    // The patterns are the triggers file's, which the base's own
                    // scripts can write, so they are quoted; the name is one
                    // the database's records are held to an alphabet for.
                    self.refusal(format!(
                        "{} watches {:?} and its archived trigger script is not in \
                         {DB_DIR}/{SCRIPTS}",
                        record.name,
                        patterns.join(" "),
                    ))
                })?;
            subjects.push(ScriptSubject {
                name: record.name.clone(),
                version: record.version.clone(),
                scripts: vec![(ScriptKind::Trigger, Cow::Borrowed(script.data.as_slice()))],
                triggers: patterns.into_iter().map(Cow::Borrowed).collect(),
                declared: Vec::new(),
            });
        }
        Ok(subjects)
    }

    /// A refusal of this base as a base, naming where it sits.
    fn refusal(&self, reason: String) -> AlpineError {
        AlpineError::config(format!(
            "the base layer at {}: {reason}",
            self.path.display()
        ))
    }
}

/// The `<package>-<version>` an archived trigger script is filed under, and the
/// control identity it is filed by, or `None` for a member that is not a
/// trigger script.
///
/// `apk` archives a trigger script as `<package>-<version>.<identity>.trigger`,
/// the identity being the record's control identity spelled `X1` and
/// hexadecimal, where the record states it `Q1` and base64; this answers the
/// identity in the record's spelling. The identity holds no `.`, so the last
/// one before it is where the name and version end. Matched on the whole name,
/// so a package whose name and version merely begin another's, as `a` at `1`
/// begins `a-1.5`, is never handed that package's script.
fn trigger_identity(member: &str) -> Option<(&str, String)> {
    let stem = member.strip_suffix(&format!(".{}", ScriptKind::Trigger.name()))?;
    let (filed_under, identity) = stem.rsplit_once('.')?;
    Some((filed_under, super::sign::identity_of_hex(identity)?))
}

/// Reads a base's archived scripts, under either name `apk` maintains, as one
/// plain tar.
///
/// The compressed form is decompressed rather than carried compressed, and the
/// members inside it are not re-encoded: what comes out is the archive `apk`
/// wrote, header bytes and all, ready to be appended to the increment's own. So
/// an increment over a base that carries `scripts.tar.gz` writes a plain
/// `scripts.tar` holding both — which `apk` finds first, and which spares this
/// layer a compressor it would carry for one file.
fn read_scripts(tree: &Rooted, base: &Path) -> Result<Vec<u8>, AlpineError> {
    // Either form is held to the decompressed ceiling: the plain archive is
    // what the ceiling describes, and a compressed one is smaller than what it
    // inflates to.
    let plain = optional_bytes(tree, &format!("{DB_DIR}/{SCRIPTS}"), base, MAX_SCRIPTS)?;
    if !plain.is_empty() {
        return Ok(plain);
    }
    let compressed = optional_bytes(tree, &format!("{DB_DIR}/{SCRIPTS_GZ}"), base, MAX_SCRIPTS)?;
    if compressed.is_empty() {
        return Ok(Vec::new());
    }
    // In memory already, so a failure is the archive's: a stream the decoder
    // refuses, or one that inflates past the ceiling.
    crate::provision::compress::inflate(&compressed, MAX_SCRIPTS).map_err(|refused| {
        let why = match refused {
            crate::provision::compress::Inflate::Undecodable(err) => {
                format!("is not readable: {}", ErrorChain::new(&err))
            }
            crate::provision::compress::Inflate::Overlong => {
                format!("inflates past the {MAX_SCRIPTS} bytes it may hold")
            }
        };
        AlpineError::config(format!(
            "the base layer at {}: its {SCRIPTS_GZ} {why}",
            base.display()
        ))
    })
}

/// Reads a file of the base that need not be there, an absent one reading as
/// empty, and one past `limit` bytes refused.
///
/// The database is what says a tree is a provisioned root; everything else here
/// is state a root may not have been given. An `apk` root with no
/// `etc/apk/repositories` is one that was never told where to fetch from, which
/// is a fine base to build over.
fn optional_bytes(
    tree: &Rooted,
    relative: &str,
    base: &Path,
    limit: u64,
) -> Result<Vec<u8>, AlpineError> {
    tree.read_if_present(relative, limit)
        .map(Option::unwrap_or_default)
        .map_err(|source| AlpineError::io("reading the base layer", base.join(relative), source))
}

/// The same, for a file whose contents are text.
fn optional_text(
    tree: &Rooted,
    relative: &str,
    base: &Path,
    limit: u64,
) -> Result<Option<String>, AlpineError> {
    tree.read_text_if_present(relative, limit)
        .map(|text| text.filter(|text| !text.is_empty()))
        .map_err(|source| AlpineError::io("reading the base layer", base.join(relative), source))
}

/// The non-empty lines of an optional file, trimmed.
fn lines(text: Option<String>) -> Vec<String> {
    text.into_iter()
        .flat_map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

    /// A tree with `contents` as its apk database, and whatever else the case
    /// wants beside it.
    fn root(tag: &str, files: &[(&str, &[u8])]) -> Scratch {
        let dir = Scratch::for_test("alpine-layer", tag);
        for (relative, contents) in files {
            let path = dir.join(relative);
            std::fs::create_dir_all(path.parent().expect("a file has a parent"))
                .expect("the tree is creatable");
            std::fs::write(path, contents).expect("the file is writable");
        }
        dir
    }

    /// The base at `dir`, read for x86_64.
    fn base_of(dir: &Path) -> Base {
        Base::read(dir, "x86_64").unwrap_or_else(|err| panic!("the base reads: {err}"))
    }

    /// One base package's trigger, owned: what the borrowed subject says.
    #[derive(Debug)]
    struct Watcher {
        name: String,
        version: String,
        triggers: Vec<String>,
        scripts: Vec<(ScriptKind, Vec<u8>)>,
    }

    /// The base's trigger subjects, read as `install` reads them.
    fn watchers(base: &Base) -> Result<Vec<Watcher>, AlpineError> {
        let scripts = base.trigger_scripts()?;
        let subjects = base.trigger_subjects(&scripts)?;
        Ok(subjects
            .into_iter()
            .map(|subject| Watcher {
                name: subject.name,
                version: subject.version,
                triggers: subject.triggers.iter().map(ToString::to_string).collect(),
                scripts: subject
                    .scripts
                    .iter()
                    .map(|(kind, body)| (*kind, body.to_vec()))
                    .collect(),
            })
            .collect())
    }

    /// The two records `apk` itself wrote, which is what a real base's database
    /// looks like.
    fn minirootfs() -> &'static [u8] {
        super::super::fixtures::MINIROOTFS_INSTALLED
    }

    #[test]
    fn a_base_is_read_as_the_packages_and_the_records_it_holds() {
        let dir = root(
            "read",
            &[
                (&format!("{DB_DIR}/{INSTALLED}"), minirootfs()),
                (WORLD, b"alpine-baselayout\n"),
                (ARCH, b"x86_64\n"),
                (REPOSITORIES, b"http://mirror.invalid/alpine/v3.23/main\n"),
            ],
        );
        let base = base_of(&dir);

        let names: Vec<&str> = base.records().map(|record| record.name.as_str()).collect();
        assert_eq!(names, ["alpine-baselayout", "musl"]);
        // The version travels with the name, which is what a constrained
        // dependency on the base is answered against.
        assert!(base.records().any(|record| {
            record.name == "musl"
                && record.provides.iter().any(|provided| {
                    provided.name == "so:libc.musl-x86_64.so.1" && provided.version.is_some()
                })
        }));
        assert_eq!(base.world(), ["alpine-baselayout"]);
        assert_eq!(
            base.repositories(),
            ["http://mirror.invalid/alpine/v3.23/main"],
        );

        // And the records are carried byte for byte, so a database written over
        // this base reproduces what the base already said.
        let carried = base.carried();
        let rejoined: Vec<u8> = carried
            .records
            .iter()
            .flat_map(|(_, raw)| [raw.as_slice(), b"\n\n"].concat())
            .collect();
        assert_eq!(rejoined, minirootfs());
    }

    #[test]
    fn a_tree_that_is_not_a_provisioned_root_is_refused() {
        // No database at all: a directory that was never provisioned.
        let empty = root("no-database", &[]);
        assert!(
            matches!(
                Base::read(&empty, "x86_64").err(),
                Some(AlpineError::Config { .. }),
            ),
            "a tree with no apk database is not a base",
        );

        // A database that records nothing, which is what an empty file is.
        let nothing = root("empty-database", &[(&format!("{DB_DIR}/{INSTALLED}"), b"")]);
        assert!(matches!(
            Base::read(&nothing, "x86_64").err(),
            Some(AlpineError::Config { .. }),
        ));
    }

    #[test]
    fn a_base_built_for_another_architecture_is_refused() {
        let dir = root(
            "architecture",
            &[
                (&format!("{DB_DIR}/{INSTALLED}"), minirootfs()),
                (ARCH, b"aarch64\n"),
            ],
        );
        let Some(err) = Base::read(&dir, "x86_64").err() else {
            panic!("the base is an aarch64 root");
        };
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains("aarch64")),
            "{err}",
        );
        // A base that states no architecture is not refused: the file is state a
        // root may never have been given, and the database is what says it is a
        // root at all.
        let silent = root(
            "no-architecture",
            &[(&format!("{DB_DIR}/{INSTALLED}"), minirootfs())],
        );
        base_of(&silent);
    }

    #[test]
    fn a_triggers_line_the_database_does_not_account_for_is_refused() {
        // A trigger this layer could not run is one apk would have run, so the
        // base is refused rather than the trigger silently skipped.
        let dir = root(
            "orphan-trigger",
            &[
                (&format!("{DB_DIR}/{INSTALLED}"), minirootfs()),
                (
                    &format!("{DB_DIR}/{TRIGGERS}"),
                    b"Q1nobodyhasthisidentityatallxx= /bin\n",
                ),
            ],
        );
        let base = base_of(&dir);
        let Some(err) = watchers(&base).err() else {
            panic!("no record carries that identity");
        };
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains("Q1nobody")),
            "{err}",
        );
    }

    /// The `C:`, `P:` and `V:` of the first record of the committed database,
    /// which is a record `apk` itself wrote.
    fn first_record() -> (String, String, String) {
        let field = |key: &[u8]| {
            minirootfs()
                .split(|byte| *byte == b'\n')
                .find_map(|line| line.strip_prefix(key))
                .map(|value| String::from_utf8(value.to_vec()).expect("the field is text"))
                .unwrap_or_else(|| panic!("the first record carries {key:?}"))
        };
        (field(b"C:"), field(b"P:"), field(b"V:"))
    }

    /// The first record's control identity as `apk` spells it in a script
    /// archive's member names: `X1` and the hexadecimal of the SHA-1 its `Q1`
    /// encodes in base64.
    const FIRST_RECORD_HEX: &str = "X1545aa6f291209af89932b761d9e422c2778596cc";

    /// The name `apk` archives a trigger script under.
    fn trigger_member(name: &str, version: &str, identity_hex: &str) -> String {
        format!("{name}-{version}.{identity_hex}.trigger")
    }

    /// A `scripts.tar` archiving each named member with its body.
    fn script_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = ferroday_cage_testkit::tar::Tar::new();
        for (name, body) in members {
            archive.file(name, 0o755, body);
        }
        archive.finish()
    }

    /// The archive of the first record's trigger script alone.
    fn first_record_archive(body: &[u8]) -> Vec<u8> {
        let (identity, name, version) = first_record();
        assert_eq!(
            super::super::sign::identity_of_hex(FIRST_RECORD_HEX).as_deref(),
            Some(identity.as_str()),
            "the two spellings name one identity",
        );
        script_archive(&[(&trigger_member(&name, &version, FIRST_RECORD_HEX), body)])
    }

    #[test]
    fn a_base_package_that_watches_a_path_comes_back_as_a_subject_to_run() {
        // The identity in the triggers file names the record, and the record
        // names the archived script: two lookups, and the whole of what lets an
        // increment fire the base's trigger for a directory it created.
        let (identity, name, version) = first_record();
        let body = b"#!/bin/sh\nexit 0\n";
        let archive = first_record_archive(body);

        let dir = root(
            "base-trigger",
            &[
                (&format!("{DB_DIR}/{INSTALLED}"), minirootfs()),
                (
                    &format!("{DB_DIR}/{TRIGGERS}"),
                    format!("{identity} /bin /usr/lib/modules/*\n").as_bytes(),
                ),
                (&format!("{DB_DIR}/{SCRIPTS}"), &archive),
            ],
        );
        let base = base_of(&dir);
        let subjects =
            watchers(&base).unwrap_or_else(|err| panic!("the base's triggers read: {err}"));
        let [subject] = &subjects[..] else {
            panic!("one line, one subject: {}", subjects.len());
        };
        assert_eq!(subject.name, name);
        assert_eq!(subject.version, version);
        assert_eq!(subject.triggers, ["/bin", "/usr/lib/modules/*"]);
        assert_eq!(
            subject.scripts,
            [(ScriptKind::Trigger, body.to_vec())],
            "the archived body, ready to run",
        );

        // And a package that watches a path with no script archived for it is a
        // base that cannot be layered over, rather than a trigger silently not
        // run.
        let missing = root(
            "base-trigger-missing",
            &[
                (&format!("{DB_DIR}/{INSTALLED}"), minirootfs()),
                (
                    &format!("{DB_DIR}/{TRIGGERS}"),
                    format!("{identity} /bin\n").as_bytes(),
                ),
                (&format!("{DB_DIR}/{SCRIPTS}"), &[0u8; 1024]),
            ],
        );
        let Some(err) = watchers(&base_of(&missing)).err() else {
            panic!("the archive holds no trigger script");
        };
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains(&name)),
            "{err}",
        );
    }

    #[test]
    fn a_watched_path_reaches_a_refusal_quoted() {
        // The triggers file is one the base's own scripts can rewrite, so a
        // pattern carrying a terminal escape is named escaped when the base is
        // refused over it.
        let (identity, _, _) = first_record();
        let hostile = crate::failure::hostile::TEXT;
        let dir = root(
            "base-trigger-hostile",
            &[
                (&format!("{DB_DIR}/{INSTALLED}"), minirootfs()),
                (
                    &format!("{DB_DIR}/{TRIGGERS}"),
                    format!("{identity} /usr/{hostile}\n").as_bytes(),
                ),
                (&format!("{DB_DIR}/{SCRIPTS}"), &[0u8; 1024]),
            ],
        );
        let Some(err) = watchers(&base_of(&dir)).err() else {
            panic!("the archive holds no trigger script");
        };
        crate::failure::hostile::assert_escaped(&err.to_string());
    }

    #[test]
    fn a_base_apk_wrote_archives_its_scripts_compressed_and_is_read_either_way() {
        // `apk` probes `scripts.tar` and falls back to `scripts.tar.gz`, and
        // writes back whichever it found — so Alpine's own published root
        // carries the compressed name and no root this layer writes does. A base
        // is read from either, and what comes out is the same script.
        use std::io::Write as _;

        let (identity, _, _) = first_record();
        let body = b"#!/bin/sh\nexit 0\n";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder
            .write_all(&first_record_archive(body))
            .expect("the archive compresses");
        let compressed = encoder.finish().expect("the stream closes");

        let dir = root(
            "compressed-scripts",
            &[
                (&format!("{DB_DIR}/{INSTALLED}"), minirootfs()),
                (
                    &format!("{DB_DIR}/{TRIGGERS}"),
                    format!("{identity} /bin\n").as_bytes(),
                ),
                (&format!("{DB_DIR}/{SCRIPTS_GZ}"), &compressed),
            ],
        );
        let base = base_of(&dir);
        let subjects =
            watchers(&base).unwrap_or_else(|err| panic!("the compressed archive reads: {err}"));
        assert_eq!(
            subjects.first().map(|subject| &subject.scripts[..]),
            Some(&[(ScriptKind::Trigger, body.to_vec())][..]),
        );

        // And what is carried forward is the plain archive, so the increment's
        // own members are appended to it rather than to a compressed stream.
        assert_eq!(base.carried().scripts, first_record_archive(body));
    }

    #[test]
    fn a_base_whose_script_archive_is_not_a_tar_is_refused_as_a_base() {
        // The archive is one of the base's files, not an apk container, so the
        // refusal is the base's: it names the base and says which file.
        let (identity, _, _) = first_record();
        let dir = root(
            "unreadable-scripts",
            &[
                (&format!("{DB_DIR}/{INSTALLED}"), minirootfs()),
                (
                    &format!("{DB_DIR}/{TRIGGERS}"),
                    format!("{identity} /bin\n").as_bytes(),
                ),
                (&format!("{DB_DIR}/{SCRIPTS}"), &[b'x'; 1024]),
            ],
        );
        let Some(err) = watchers(&base_of(&dir)).err() else {
            panic!("the archive is not a tar");
        };
        assert!(
            matches!(&err, AlpineError::Config { reason }
                if reason.contains("base layer") && reason.contains("archived scripts")),
            "{err}",
        );
    }

    #[test]
    fn a_triggers_file_of_many_lines_for_one_package_is_one_subject() {
        // The file is one the base's own scripts could have rewritten. apk keys
        // it by identity, a second line adding to the first, so however many
        // lines name one package it is one trigger, watching each path once,
        // and its script is the archive's rather than a copy per line.
        let (identity, name, _) = first_record();
        let body = vec![b'#'; 64 * 1024];
        let archive = first_record_archive(&body);
        let mut watched = String::new();
        for _ in 0..50_000 {
            watched.push_str(&format!("{identity} /bin\n"));
        }
        watched.push_str(&format!("{identity} /usr/bin /bin\n"));
        let dir = root(
            "many-lines",
            &[
                (&format!("{DB_DIR}/{INSTALLED}"), minirootfs()),
                (&format!("{DB_DIR}/{TRIGGERS}"), watched.as_bytes()),
                (&format!("{DB_DIR}/{SCRIPTS}"), &archive),
            ],
        );
        let base = base_of(&dir);
        let scripts = base.trigger_scripts().expect("the archive reads");
        let subjects = base
            .trigger_subjects(&scripts)
            .unwrap_or_else(|err| panic!("the base's triggers read: {err}"));
        let [subject] = &subjects[..] else {
            panic!("one package, one subject: {}", subjects.len());
        };
        assert_eq!(subject.name, name);
        assert_eq!(subject.triggers, ["/bin", "/usr/bin"]);
        let [(ScriptKind::Trigger, Cow::Borrowed(script))] = &subject.scripts[..] else {
            panic!("the script is borrowed from the archive read");
        };
        assert_eq!(*script, &body[..]);
    }

    #[test]
    fn a_triggers_file_watching_past_the_ceiling_is_refused() {
        // A flood of one path is one path, and is read.
        let (identity, _, _) = first_record();
        let archive = first_record_archive(b"#!/bin/sh\n");
        let base_watching = |tag: &str, watched: &str| {
            root(
                tag,
                &[
                    (&format!("{DB_DIR}/{INSTALLED}"), minirootfs()),
                    (&format!("{DB_DIR}/{TRIGGERS}"), watched.as_bytes()),
                    (&format!("{DB_DIR}/{SCRIPTS}"), &archive),
                ],
            )
        };
        let flood = format!("{identity}{}\n", " /*".repeat(500_000));
        let subjects = watchers(&base_of(&base_watching("pattern-flood", &flood)))
            .unwrap_or_else(|err| panic!("one path, however often: {err}"));
        assert_eq!(subjects.len(), 1);
        assert_eq!(subjects[0].triggers, ["/*"]);

        // Distinct paths past the ceiling are refused before anything is
        // matched against them, and the ceiling itself is read.
        let paths =
            |count: usize| -> String { (0..count).map(|at| format!(" /watched/{at}")).collect() };
        let at_ceiling = format!("{identity}{}\n", paths(MAX_TRIGGER_PATTERNS));
        let subjects = watchers(&base_of(&base_watching("at-ceiling", &at_ceiling)))
            .unwrap_or_else(|err| panic!("the ceiling is admitted: {err}"));
        assert_eq!(subjects[0].triggers.len(), MAX_TRIGGER_PATTERNS);

        // Spread over lines, as over one.
        let past: String = (0..=MAX_TRIGGER_PATTERNS)
            .map(|at| format!("{identity} /watched/{at}\n"))
            .collect();
        let Some(err) = watchers(&base_of(&base_watching("past-ceiling", &past))).err() else {
            panic!("the file watches past the ceiling");
        };
        assert!(
            matches!(&err, AlpineError::Config { reason }
                if reason.contains(&MAX_TRIGGER_PATTERNS.to_string())),
            "{err}",
        );
    }

    #[test]
    fn a_trigger_script_is_found_by_its_whole_name() {
        // `a` at `1` and a package named `a-1.5`: the second's archived name
        // begins with the first's name and version, and ends as a trigger does.
        // Only the identity between the two tells them apart.
        let digest = |seed: u8| [seed; 20];
        let q1 = |seed: u8| super::super::sign::identity(&digest(seed));
        let x1 = |seed: u8| format!("X1{}", crate::provision::digest::hex(&digest(seed)));
        let database = format!(
            "C:{}\nP:a\nV:1\nA:x86_64\n\nC:{}\nP:a-1.5\nV:2\nA:x86_64\n\n",
            q1(1),
            q1(2),
        );
        let other = trigger_member("a-1.5", "2", &x1(2));
        let own = trigger_member("a", "1", &x1(1));
        let watched = format!("{} /bin\n", q1(1));
        let base_with = |tag: &str, members: &[(&str, &[u8])]| {
            root(
                tag,
                &[
                    (&format!("{DB_DIR}/{INSTALLED}"), database.as_bytes()),
                    (&format!("{DB_DIR}/{TRIGGERS}"), watched.as_bytes()),
                    (&format!("{DB_DIR}/{SCRIPTS}"), &script_archive(members)),
                ],
            )
        };

        // The other package's script alone is not `a`'s.
        let dir = base_with("whole-name-other", &[(&other, b"other\n")]);
        let Some(err) = watchers(&base_of(&dir)).err() else {
            panic!("a-1.5's script was handed to a");
        };
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains("archived trigger")),
            "{err}",
        );

        // With both archived, the other's first, `a` gets its own.
        let dir = base_with("whole-name-both", &[(&other, b"other\n"), (&own, b"own\n")]);
        let subjects = watchers(&base_of(&dir))
            .unwrap_or_else(|err| panic!("the base's triggers read: {err}"));
        assert_eq!(
            subjects.first().map(|subject| &subject.scripts[..]),
            Some(&[(ScriptKind::Trigger, b"own\n".to_vec())][..]),
        );
    }

    #[test]
    fn a_base_that_watches_nothing_has_no_triggers_to_fire() {
        let dir = root(
            "no-triggers",
            &[
                (&format!("{DB_DIR}/{INSTALLED}"), minirootfs()),
                (&format!("{DB_DIR}/{TRIGGERS}"), b""),
            ],
        );
        let base = base_of(&dir);
        assert!(
            watchers(&base)
                .unwrap_or_else(|err| panic!("nothing to read: {err}"))
                .is_empty(),
        );
    }
}
