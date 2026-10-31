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

use std::io;
use std::path::{Path, PathBuf};

use super::bootstrap::{ARCH, REPOSITORIES, ScriptKind, ScriptSubject, WORLD};
use super::index::Record;
use super::installed::{Carried, DB_DIR, Existing};
use super::{AlpineError, apk};
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
        let refuse = |reason: String| AlpineError::Config {
            reason: format!("the base layer at {}: {reason}", path.display()),
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
                "it was built for {}, and the increment is being resolved for {architecture}",
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
    /// # Errors
    ///
    /// Returns [`AlpineError::Config`] when the base's database contradicts
    /// itself — a `triggers` line naming a package the database does not record,
    /// or a package whose archived trigger script is absent. Either would mean
    /// silently not running a trigger `apk` would have run, which is worse than
    /// refusing a base that is not whole.
    pub(super) fn trigger_subjects(&self) -> Result<Vec<ScriptSubject>, AlpineError> {
        let refuse = |reason: String| AlpineError::Config {
            reason: format!("the base layer at {}: {reason}", self.path.display()),
        };
        let watched = String::from_utf8(self.triggers.clone())
            .map_err(|_| refuse("its triggers file is not UTF-8".to_string()))?;
        if watched.trim().is_empty() {
            return Ok(Vec::new());
        }

        // A base that carries neither `scripts.tar` nor `scripts.tar.gz` reads
        // as no bytes at all, which is not the same as an archive holding no
        // members: no stream arrived to be one. A trigger whose script such a
        // base has nowhere to keep is refused below, by the name that is
        // missing, rather than here as an unreadable archive.
        let archived = if self.scripts.is_empty() {
            Vec::new()
        } else {
            apk::members(&self.path.display().to_string(), &self.scripts)?
        };
        let mut subjects = Vec::new();
        for line in watched.lines().filter(|line| !line.trim().is_empty()) {
            // A line is the package's control identity, then the paths it
            // watches: the same identity its record opens with, which is how
            // `apk` finds the record the line belongs to.
            let (identity, patterns) = line.split_once(' ').unwrap_or((line, ""));
            let record = self
                .records()
                .find(|record| record.control_identity == identity)
                .ok_or_else(|| {
                    refuse(format!(
                        "its triggers file names {identity}, which no record in its database \
                         carries",
                    ))
                })?;

            let script = archived
                .iter()
                .find(|member| is_trigger_of(&member.name, record))
                .ok_or_else(|| {
                    refuse(format!(
                        "{} watches {patterns} and its archived trigger script is not in \
                         {DB_DIR}/{SCRIPTS}",
                        record.name,
                    ))
                })?;

            subjects.push(ScriptSubject {
                name: record.name.clone(),
                version: record.version.clone(),
                scripts: vec![(ScriptKind::Trigger, script.data.clone())],
                triggers: patterns
                    .split_ascii_whitespace()
                    .map(str::to_string)
                    .collect(),
            });
        }
        Ok(subjects)
    }
}

/// Whether `member` is the name `apk` archives `record`'s trigger script under.
///
/// That name is `<package>-<version>.<identity>.trigger`, the identity being
/// the record's control identity spelled `X1` and hexadecimal, where the record
/// states it `Q1` and base64. The whole name is matched, the identity as the
/// one the record carries, so a package whose name and version merely begin
/// another's, as `a` at `1` begins `a-1.5`, is never handed that package's
/// script.
fn is_trigger_of(member: &str, record: &Record) -> bool {
    member
        .strip_prefix(&format!("{}-{}.", record.name, record.version))
        .and_then(|rest| rest.strip_suffix(&format!(".{}", ScriptKind::Trigger.name())))
        .and_then(super::sign::identity_of_hex)
        .is_some_and(|identity| identity == record.control_identity)
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
    let mut scripts = Vec::new();
    let at = base.join(DB_DIR).join(SCRIPTS_GZ);
    let mut reader =
        crate::provision::compress::decompress(&compressed, io::empty()).map_err(|err| {
            AlpineError::Config {
                reason: format!(
                    "the base layer at {}: its {SCRIPTS_GZ} is not readable: {err}",
                    base.display(),
                ),
            }
        })?;
    io::copy(
        &mut reader,
        &mut crate::provision::LimitedWriter::new(&mut scripts, MAX_SCRIPTS),
    )
    .map_err(AlpineError::at("reading the base layer's scripts", at))?;
    Ok(scripts)
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
    let bytes = optional_bytes(tree, relative, base, limit)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| AlpineError::Config {
            reason: format!(
                "the base layer at {}: its {relative} is not UTF-8",
                base.display(),
            ),
        })
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
        let Some(err) = base.trigger_subjects().err() else {
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
        let mut archive = Vec::new();
        for (name, body) in members {
            archive.extend_from_slice(
                &crate::provision::tar::ustar_block(
                    name.as_bytes(),
                    &[],
                    0o755,
                    0,
                    0,
                    body.len() as u64,
                    0,
                    b'0',
                    &[],
                )
                .expect("the header is writable"),
            );
            archive.extend_from_slice(body);
            crate::provision::tar::pad(&mut archive, body.len() as u64)
                .expect("the padding is short");
        }
        archive.extend_from_slice(&[0u8; 1024]);
        archive
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
        let subjects = base
            .trigger_subjects()
            .unwrap_or_else(|err| panic!("the base's triggers read: {err}"));
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
        let Some(err) = base_of(&missing).trigger_subjects().err() else {
            panic!("the archive holds no trigger script");
        };
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains(&name)),
            "{err}",
        );
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
        let subjects = base
            .trigger_subjects()
            .unwrap_or_else(|err| panic!("the compressed archive reads: {err}"));
        assert_eq!(
            subjects.first().map(|subject| &subject.scripts[..]),
            Some(&[(ScriptKind::Trigger, body.to_vec())][..]),
        );

        // And what is carried forward is the plain archive, so the increment's
        // own members are appended to it rather than to a compressed stream.
        assert_eq!(base.carried().scripts, first_record_archive(body));
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
        let Some(err) = base_of(&dir).trigger_subjects().err() else {
            panic!("a-1.5's script was handed to a");
        };
        assert!(
            matches!(&err, AlpineError::Config { reason } if reason.contains("archived trigger")),
            "{err}",
        );

        // With both archived, the other's first, `a` gets its own.
        let dir = base_with("whole-name-both", &[(&other, b"other\n"), (&own, b"own\n")]);
        let subjects = base_of(&dir)
            .trigger_subjects()
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
            base.trigger_subjects()
                .unwrap_or_else(|err| panic!("nothing to read: {err}"))
                .is_empty(),
        );
    }
}
