//! `/lib/apk/db`: the state a finished root hands back to `apk`.
//!
//! Three files, all written here, because all three are one walk over the
//! packages as their files are laid down:
//!
//! | File | Holds |
//! | --- | --- |
//! | `installed` | one record per package: its index fields, then its file tree |
//! | `triggers` | one line per package that watches paths for changes |
//! | `scripts.tar` | every install script, named so `apk` can find it again |
//!
//! # The record is the index record, plus what only the package knows
//!
//! An installed record opens with exactly the fields an index record carries,
//! in exactly that order, because that is literally what `apk` writes: it
//! resolves a package from an index and copies that object into the database.
//! What it adds is `r:`/`q:` — read from `.PKGINFO`, which no index publishes —
//! and the file lines below.
//!
//! This layer builds the whole record from `.PKGINFO` instead, for the reason
//! [`pkginfo`](super::pkginfo) gives: a bootstrap from a [`Plan`](super::Plan)
//! fetches no index, and the two modes must produce one root. The architecture
//! is the exception and comes from the resolution, since a package built for
//! every architecture says `noarch` while the index — and so the record `apk`
//! writes — says the repository's.
//!
//! For the 27 packages of `alpine-base`, this writer reproduces the 33 KB
//! `installed` that `apk.static` writes byte for byte, with one deliberate
//! difference recorded in [`Record::header`].
//!
//! # The file lines
//!
//! ```text
//! F:etc/crontabs        a directory, path relative to the root
//! M:0:0:700             its uid, gid and octal mode, when not 0:0:755
//! R:root                a file in the directory above it
//! a:0:0:600             its uid, gid and octal mode, when not 0:0:644
//! Z:Q1vfk1apUWI4yLJ…    its content digest, from the package's own archive
//! ```
//!
//! A letter `apk` does not know is fatal to the whole database rather than
//! skipped — the reader treats an unknown field in `installed` as "this
//! apk-tools is too old" and refuses to read any of it — so this writer emits
//! the documented set and nothing else.

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};

use super::apk::ScriptKind;
use super::index::{self, Dependency};
use super::pkginfo::PkgInfo;
use super::sign;
use crate::provision::tar;

/// The uid, gid and mode a directory has when its record states none.
const DEFAULT_DIR_ACL: Acl = Acl {
    uid: 0,
    gid: 0,
    mode: 0o755,
};

/// The uid, gid and mode a file has when its record states none.
const DEFAULT_FILE_ACL: Acl = Acl {
    uid: 0,
    gid: 0,
    mode: 0o644,
};

/// Where the database lives inside the root.
pub(super) const DB_DIR: &str = "lib/apk/db";

/// Where `apk` writes a script before running it, and where this layer does
/// too.
pub(super) const EXEC_DIR: &str = "lib/apk/exec";

/// One package as the database records it.
///
/// Assembled over the package's extraction: the header is rendered once when
/// the record opens, and each entry adds its own line as it is laid down, so
/// the file tree is recorded in the order the archive states it — which is the
/// order `apk` records it in too.
pub(super) struct Record {
    /// The package name, which the collision policy and the script names read.
    pub(super) name: String,
    /// The version, which the script names read.
    version: String,
    /// The source package, which the collision policy reads.
    origin: Option<String>,
    /// What this package may take a file from.
    replaces: Vec<Dependency>,
    /// Which of two packages that each replace the other wins.
    replaces_priority: u32,
    /// `Q1` and the base64 of the SHA-1 of the control segment.
    control_identity: String,
    /// The same digest in hexadecimal, which names the package's scripts.
    control_identity_hex: String,
    /// When the package was built, which stamps its archived scripts.
    build_time: Option<u64>,
    /// The paths whose contents changing runs this package's trigger.
    triggers: Vec<String>,
    /// The scripts to archive, in [`ScriptKind::ALL`] order.
    scripts: Vec<(ScriptKind, Vec<u8>)>,
    /// Everything before the file lines, already rendered.
    header: Vec<u8>,
    /// Directories in the order the archive states them.
    directories: Vec<DirectoryLines>,
    /// Where each directory sits in the list above.
    at: HashMap<Vec<u8>, usize>,
}

/// One directory of a record: its path, what it says about itself, and what it
/// holds.
///
/// The ACL is kept beside the file lines rather than among them because it has
/// to be rendered first whenever it arrives, and because an archive that
/// describes a directory twice states one ACL for it rather than two.
struct DirectoryLines {
    path: Vec<u8>,
    /// The ownership and mode the directory's own entry stated, or `None` for
    /// a directory only its contents named.
    acl: Option<Acl>,
    files: Vec<FileLines>,
}

/// One file of a record: the name it is recorded under, and what describes it.
///
/// Held as fields rather than as rendered lines, because two things change after
/// the file is laid down. A file can be taken away again: a package that takes a
/// path over from an earlier one leaves that earlier record still claiming it
/// otherwise, and the finished root would list one path under two packages with
/// two `Z:` digests — of which at most one can match what is on disk. And its
/// owner is recorded once the package's pre-install has created the accounts the
/// owner is named by. Keeping the name apart is also what makes one package
/// shipping a path twice record it once, which is the entry the extraction
/// leaves behind.
struct FileLines {
    /// The entry name, within its directory, which is what a later claim finds
    /// it by.
    name: Vec<u8>,
    /// Its ownership and mode, which the `a:` line states where they are not
    /// the default.
    acl: Acl,
    /// The SHA-1 the package's archive states for it, which the `Z:` line
    /// carries.
    digest: Option<[u8; 20]>,
}

/// An entry's owner and mode, as the database records them.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Acl {
    uid: u32,
    gid: u32,
    mode: u32,
}

impl Record {
    /// Opens a record for a package whose files are about to be laid down.
    ///
    /// `architecture` is the resolution's rather than `.PKGINFO`'s, and `size`
    /// is the length of the `.apk` as it was fetched.
    ///
    /// # The header, field by field
    ///
    /// The order is `apk`'s own writer's and is not alphabetical, so it is
    /// spelled out rather than derived. A field the package does not state is
    /// omitted, except `S:` and `I:` which `apk` always writes.
    ///
    /// The one place this diverges from what `apk` produces: `apk` never opens
    /// the control segment of a package whose installed size is zero, so it
    /// records no `r:` for one. A meta package that replaces something
    /// therefore loses that fact in `apk`'s own database and keeps it here.
    /// Keeping it costs nothing — such a package ships no files, so no
    /// collision can ever consult it — and dropping it would mean reproducing
    /// an omission rather than a rule.
    pub(super) fn open(
        info: &PkgInfo,
        architecture: &str,
        size: u64,
        control_identity: String,
        control_identity_hex: String,
    ) -> Record {
        let mut header = Vec::new();
        let mut put = |field: &str, value: &str| {
            header.extend_from_slice(field.as_bytes());
            header.push(b':');
            header.extend_from_slice(value.as_bytes());
            header.push(b'\n');
        };
        put("C", &control_identity);
        put("P", &info.name);
        put("V", &info.version);
        put("A", architecture);
        put("S", &size.to_string());
        put("I", &info.installed_size.unwrap_or(0).to_string());
        for (field, value) in [
            ("T", &info.description),
            ("U", &info.url),
            ("L", &info.license),
            ("o", &info.origin),
            ("m", &info.maintainer),
        ] {
            if let Some(value) = value {
                put(field, value);
            }
        }
        if let Some(built) = info.build_time {
            put("t", &built.to_string());
        }
        if let Some(commit) = &info.commit {
            put("c", commit);
        }
        if let Some(priority) = info.provider_priority {
            put("k", &priority.to_string());
        }
        for (field, entries) in [
            ("D", &info.depends),
            ("p", &info.provides),
            ("i", &info.install_if),
        ] {
            if !entries.is_empty() {
                put(field, &entries.join(" "));
            }
        }
        if !info.replaces.is_empty() {
            let replaces: Vec<String> = info.replaces.iter().map(ToString::to_string).collect();
            put("r", &replaces.join(" "));
        }
        if let Some(priority) = info.replaces_priority {
            put("q", &priority.to_string());
        }

        Record {
            name: info.name.clone(),
            version: info.version.clone(),
            origin: info.origin.clone(),
            replaces: info.replaces.clone(),
            replaces_priority: info.replaces_priority.unwrap_or(0),
            control_identity,
            control_identity_hex,
            build_time: info.build_time,
            triggers: info.triggers.clone(),
            scripts: Vec::new(),
            header,
            directories: Vec::new(),
            at: HashMap::new(),
        }
    }

    /// Records the scripts the package's control segment carried.
    pub(super) fn with_scripts(mut self, scripts: Vec<(ScriptKind, Vec<u8>)>) -> Record {
        self.scripts = scripts;
        self
    }

    /// The directory `path`, opening it where it is new.
    ///
    /// A directory is opened by whichever entry mentions it first, which is its
    /// own entry in every archive `abuild` produces and a file's entry in one
    /// that omits it. Opening it either way is what keeps a file from being
    /// recorded under a directory the record never named — which `apk` treats
    /// as a broken package rather than reading on.
    fn directory_at(&mut self, path: &[u8]) -> &mut DirectoryLines {
        let at = *self.at.entry(path.to_vec()).or_insert_with(|| {
            self.directories.push(DirectoryLines {
                path: path.to_vec(),
                acl: None,
                files: Vec::new(),
            });
            self.directories.len() - 1
        });
        &mut self.directories[at]
    }

    /// Records a directory the package ships.
    ///
    /// An archive that describes one directory twice leaves the later
    /// description standing, which is the extraction's own rule and so
    /// describes the directory that survived.
    pub(super) fn directory(&mut self, path: &[u8], uid: u32, gid: u32, mode: u32) {
        self.directory_at(path).acl = Some(Acl { uid, gid, mode });
    }

    /// Records a file, symbolic link or hard link the package ships, at the
    /// root-relative `path`.
    ///
    /// `digest` is the SHA-1 the package's own archive states for it — over the
    /// contents of a file, over the target of a link. A package that states
    /// none leaves the file with no `Z:` line, exactly as `apk` does, and an
    /// audit of the finished root then has nothing to check it against.
    ///
    /// A path this record already holds is described again rather than twice:
    /// tar permits one archive to carry a path more than once, and the entry
    /// that survives on disk is the last of them.
    pub(super) fn file(
        &mut self,
        path: &[u8],
        uid: u32,
        gid: u32,
        mode: u32,
        digest: Option<[u8; 20]>,
    ) {
        let (directory, name) = split_leaf(path);
        let acl = Acl { uid, gid, mode };
        let files = &mut self.directory_at(directory).files;
        match files.iter_mut().find(|file| file.name == name) {
            Some(file) => {
                file.acl = acl;
                file.digest = digest;
            }
            None => files.push(FileLines {
                name: name.to_vec(),
                acl,
                digest,
            }),
        }
    }

    /// Records `uid` and `gid` as the owner of the entry at `path`, a directory
    /// or a file this record already holds, keeping its mode.
    ///
    /// What a bootstrap records once the entry has been given its owner, which
    /// happens after the package's pre-install rather than as the entry is laid
    /// down. An entry the record no longer holds, because a later package took
    /// it, is not this record's to describe, and nothing changes.
    pub(super) fn own(&mut self, path: &[u8], directory: bool, uid: u32, gid: u32) {
        let acl = if directory {
            self.at
                .get(path)
                .and_then(|at| self.directories[*at].acl.as_mut())
        } else {
            let (parent, name) = split_leaf(path);
            self.at.get(parent).and_then(|at| {
                self.directories[*at]
                    .files
                    .iter_mut()
                    .find(|file| file.name == name)
                    .map(|file| &mut file.acl)
            })
        };
        if let Some(acl) = acl {
            acl.uid = uid;
            acl.gid = gid;
        }
    }

    /// Stops this record from claiming `path`, where it claimed it.
    ///
    /// What a package taking a path over from an earlier one leaves behind. The
    /// directory itself stays: both packages ship it, which is what makes
    /// directories shared by construction rather than contested.
    pub(super) fn remove_file(&mut self, path: &[u8]) {
        let (directory, name) = split_leaf(path);
        if let Some(at) = self.at.get(directory) {
            self.directories[*at].files.retain(|file| file.name != name);
        }
    }

    /// The record as the database holds it: the header, then each directory
    /// and its contents.
    fn render(&self) -> Vec<u8> {
        let mut out = self.header.clone();
        for directory in &self.directories {
            out.extend_from_slice(b"F:");
            out.extend_from_slice(&directory.path);
            out.push(b'\n');
            if let Some(acl) = directory
                .acl
                .and_then(|acl| acl_line(b'M', acl, DEFAULT_DIR_ACL))
            {
                out.extend_from_slice(&acl);
            }
            for file in &directory.files {
                out.extend_from_slice(b"R:");
                out.extend_from_slice(&file.name);
                out.push(b'\n');
                if let Some(acl) = acl_line(b'a', file.acl, DEFAULT_FILE_ACL) {
                    out.extend_from_slice(&acl);
                }
                if let Some(digest) = file.digest {
                    out.extend_from_slice(b"Z:");
                    out.extend_from_slice(sign::identity(&digest).as_bytes());
                    out.push(b'\n');
                }
            }
        }
        out
    }
}

/// Splits a root-relative path into the directory that holds it and the name
/// within it, which is how the database records a file: an `R:` line under the
/// `F:` line naming its directory.
///
/// A path with no separator sits in the record's root directory, which is the
/// empty path — the `F:` line `apk` writes for the top of the tree.
fn split_leaf(path: &[u8]) -> (&[u8], &[u8]) {
    path.iter()
        .rposition(|byte| *byte == b'/')
        .map_or((&[][..], path), |slash| {
            (&path[..slash], &path[slash + 1..])
        })
}

/// The `<uid>:<gid>:<octal mode>` line for an entry whose ownership or mode
/// differs from the default, `None` where it does not.
///
/// The omission is not a space saving: `apk` writes the line only for a
/// difference, and a record that stated every default would be a record `apk`
/// did not write, which is the thing this writer is measured against.
fn acl_line(field: u8, acl: Acl, default: Acl) -> Option<Vec<u8>> {
    if acl == default {
        return None;
    }
    let Acl { uid, gid, mode } = acl;
    Some(format!("{}:{uid}:{gid}:{mode:o}\n", field as char).into_bytes())
}

/// One package as a tree's database already records it, read back.
///
/// What a layered build needs of a base: the record's opening fields, read
/// through the index grammar they are written in, and the record itself so the
/// increment's database can carry it forward without re-rendering it.
pub(super) struct Existing {
    /// The record's header, read back as the index record it is.
    pub(super) record: index::Record,
    /// The whole record as the database holds it — the header, and the file
    /// lines below it — without the blank line that ends it.
    pub(super) raw: Vec<u8>,
}

/// Reads a tree's `installed` database.
///
/// The database is bytes rather than text: a package may ship a path that is not
/// UTF-8, and this layer's own writer records one as it found it. So the record
/// is carried as bytes, and only its header — the fields above the first `F:`
/// line, which are the index fields — is required to be text.
///
/// Reports the reason a database cannot be read rather than an error, so the
/// caller names what it was reading; a database is not an index, and a refusal
/// that called it one would name the wrong thing.
pub(super) fn parse(text: &[u8]) -> Result<Vec<Existing>, String> {
    let mut existing = Vec::new();
    let mut lines: Vec<&[u8]> = Vec::new();
    // A record ends at a blank line, and the last one needs none.
    for line in text.split(|byte| *byte == b'\n').chain([&b""[..]]) {
        if !line.is_empty() {
            lines.push(line);
            continue;
        }
        if lines.is_empty() {
            continue;
        }
        existing.push(one(&lines)?);
        lines.clear();
    }
    Ok(existing)
}

/// Assembles one record from the lines read for it.
fn one(lines: &[&[u8]]) -> Result<Existing, String> {
    // Everything above the first file line is the header, and `F:` is the letter
    // that opens one.
    let files_at = lines
        .iter()
        .position(|line| line.starts_with(b"F:"))
        .unwrap_or(lines.len());
    let header = String::from_utf8(lines[..files_at].join(&b'\n')).map_err(|_| {
        let name = lines
            .iter()
            .find_map(|line| line.strip_prefix(b"P:"))
            .map_or_else(
                || "a record".to_string(),
                |name| String::from_utf8_lossy(name).into_owned(),
            );
        format!("the fields of {name} are not UTF-8")
    })?;

    // A base record came from no index this run configured. `NO_INDEX` is never
    // read — a record read back seeds a resolution and never enters a plan — and
    // it is `usize::MAX` so that a mistaken read fails the plan's index lookup
    // rather than silently attributing the package to the first repository.
    const NO_INDEX: usize = usize::MAX;
    let mut records = index::parse_records(&header, NO_INDEX)?;
    let record = match records.len() {
        1 => records.remove(0),
        _ => return Err("a record carries no package fields".to_string()),
    };
    Ok(Existing {
        record,
        raw: lines.join(&b'\n'),
    })
}

/// What a base layer's database holds, carried into the one an increment writes.
///
/// An increment's database is written into the overlay upper, where it shadows
/// the base's copy in the read-only lower — a merged root sees one file, not
/// two. So the file the increment writes has to describe the whole root, and
/// what the base contributed is carried through byte for byte rather than
/// rebuilt: these are records this layer may not have written, and re-rendering
/// them would make the increment's database a re-encoding of the base's rather
/// than the base's.
#[derive(Default)]
pub(super) struct Carried {
    /// The base's records, each with the package name it opens with.
    pub(super) records: Vec<(String, Vec<u8>)>,
    /// The base's `triggers` file.
    pub(super) triggers: Vec<u8>,
    /// The base's `scripts.tar`.
    pub(super) scripts: Vec<u8>,
}

/// Every package a bootstrap installed, and which of them owns each path.
#[derive(Default)]
pub(super) struct Database {
    records: Vec<Record>,
    /// The record that laid each path down as an entry that is not a
    /// directory, and which kind of entry it laid, for the collision policy.
    owner: HashMap<Vec<u8>, (usize, Shape)>,
    /// The record that first laid each path down as a directory. A directory
    /// is shared, so this names the first of the packages that ship it, which
    /// is the one a collision with it is reported against.
    directory: HashMap<Vec<u8>, usize>,
    /// What a base layer already held, for a database an increment writes.
    /// Empty for a full bootstrap, which has no base.
    carried: Carried,
}

/// The kind of entry a package lays a path down as, as far as the collision
/// policy tells kinds apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Shape {
    /// A directory, which every package writing into it ships, so it is
    /// shared rather than contested.
    Directory,
    /// A symbolic link, which a later directory entry may resolve through.
    Link,
    /// Anything else: a file, a hard link, or a named pipe.
    File,
}

/// What a package may do with a path another package has already laid down.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Claim {
    /// Nothing has this path, or a directory shares it with this one: lay it
    /// down.
    Free,
    /// The later package's metadata says it may take it.
    Replaces,
    /// The earlier package's metadata says it keeps it.
    Kept,
    /// Neither says anything, so the two disagree about who owns the file.
    Contested {
        /// The package that laid the path down first.
        owner: String,
    },
    /// One of the two lays the path down as a directory and the other as an
    /// entry that is not one, which no `replaces` settles.
    Unlike {
        /// The package that laid the path down first.
        owner: String,
        /// Whichever of the two laid it down as a directory.
        directory: String,
    },
    /// A directory where an earlier package laid a link, which the link
    /// satisfies where it resolves to a directory. Only the tree can say
    /// whether it does, so the caller asks it once the entry is laid down.
    Through {
        /// The package that laid the link down.
        owner: String,
    },
}

impl Database {
    /// Opens a database that carries a base layer's state forward, for the
    /// increment of a layered build.
    ///
    /// Everything below then describes the merged root: the base's packages and
    /// the increment's, in one file each.
    pub(super) fn carrying(carried: Carried) -> Database {
        Database {
            carried,
            ..Database::default()
        }
    }

    /// Opens a record and returns its number.
    pub(super) fn add(&mut self, record: Record) -> usize {
        self.records.push(record);
        self.records.len() - 1
    }

    /// The record numbered `at`.
    pub(super) fn record(&mut self, at: usize) -> &mut Record {
        &mut self.records[at]
    }

    /// Whether the package numbered `at` may lay `path` down as an entry of
    /// kind `shape`, and records it as the owner where it may.
    ///
    /// A directory and an entry that is not one never share a path, whichever
    /// is laid down first and whatever either package's `replaces` says: that
    /// is [`Claim::Unlike`], one package shipping both included. `apk` cannot
    /// lay the second of them down either, and fails the package. The one
    /// exception is a directory laid where a link is, which is
    /// [`Claim::Through`]: a link that resolves to a directory satisfies a
    /// directory entry, as it does for `apk` and for the extraction, and a link
    /// laid where a directory is stays [`Claim::Unlike`]. Two directories share
    /// a path freely, since every package writing into one ships it.
    ///
    /// Two entries that are not directories follow `apk`'s own rule, checked in
    /// `apk`'s order, with the cases a bootstrap cannot reach removed: nothing
    /// is being upgraded, so no two records share a name, and nothing is being
    /// removed. What is left is where the two packages came from and what their
    /// `replaces` say about each other:
    ///
    /// - they were built from one source package: the later takes the file,
    ///   whatever either one's `replaces` says, since one build shipping a path
    ///   twice is its own business;
    /// - the earlier package names the later one *more strongly* than the later
    ///   names it back — including where the later names it not at all: the
    ///   earlier keeps the file;
    /// - otherwise, the later package names the earlier one: it takes the file.
    ///   Equal priorities fall here, so two packages that name each other at the
    ///   same strength are settled by install order, as `apk` settles them;
    /// - otherwise the two disagree, and that is [`Claim::Contested`].
    ///
    /// `apk` warns about that last case, skips the file, and marks the package
    /// broken. This layer refuses the bootstrap instead: a root is a thing a
    /// caller goes on to build on, and one assembled from packages that
    /// disagree about its contents should not be published quietly.
    ///
    /// A replacement also takes the path out of the earlier record. One path
    /// recorded under two packages would carry two `Z:` digests, and only one
    /// file can be on disk — `apk audit` reports the other as modified. Which
    /// of the two `apk` would read is a function of the order it happens to walk
    /// the records in, which is not a thing a finished root should depend on.
    pub(super) fn claim(&mut self, at: usize, path: &[u8], shape: Shape) -> Claim {
        let name = |at: usize| self.records[at].name.clone();
        if shape == Shape::Directory {
            return match self.owner.get(path) {
                Some(&(owner, Shape::Link)) => Claim::Through { owner: name(owner) },
                Some(&(owner, _)) => Claim::Unlike {
                    owner: name(owner),
                    directory: name(at),
                },
                None => {
                    self.directory.entry(path.to_vec()).or_insert(at);
                    Claim::Free
                }
            };
        }
        if let Some(&holder) = self.directory.get(path) {
            return Claim::Unlike {
                owner: name(holder),
                directory: name(holder),
            };
        }
        let Some(&(owner, _)) = self.owner.get(path) else {
            self.owner.insert(path.to_vec(), (at, shape));
            return Claim::Free;
        };
        if owner == at {
            // The same package shipping one path twice, which tar permits. The
            // later entry is the one on disk, as it is for the extraction, and
            // `Record::file` describes it again rather than twice.
            self.owner.insert(path.to_vec(), (at, shape));
            return Claim::Replaces;
        }

        let (earlier, later) = (&self.records[owner], &self.records[at]);
        let claim = if earlier.origin.is_some() && earlier.origin == later.origin {
            Claim::Replaces
        } else {
            let earlier_claims = replaces(earlier, later).then_some(earlier.replaces_priority);
            let later_claims = replaces(later, earlier).then_some(later.replaces_priority);
            match (earlier_claims, later_claims) {
                (Some(earlier_priority), later) if Some(earlier_priority) > later => Claim::Kept,
                (_, Some(_)) => Claim::Replaces,
                _ => Claim::Contested {
                    owner: earlier.name.clone(),
                },
            }
        };
        if claim == Claim::Replaces {
            self.owner.insert(path.to_vec(), (at, shape));
            self.records[owner].remove_file(path);
        }
        claim
    }

    /// Every directory the install created, root-relative and without a leading
    /// slash.
    ///
    /// What a trigger's patterns are matched against. The database is the right
    /// source rather than a walk of the finished tree: these are the
    /// directories the *packages* laid down, which is what "changed" means for
    /// a root that did not exist before this bootstrap.
    pub(super) fn directories(&self) -> HashSet<Vec<u8>> {
        self.records
            .iter()
            .flat_map(|record| record.directories.iter().map(|entry| entry.path.clone()))
            .collect()
    }

    /// The `installed` file: every record, in package-name order, each followed
    /// by a blank line.
    ///
    /// Name order rather than install order, which is both what `apk` writes
    /// and what makes the file a function of the closure rather than of the
    /// order it happened to be laid down in. `apk` reads the records into a
    /// hash table, so the order is ours to choose.
    ///
    /// A [carried](Self::carrying) base's records sort in among this database's
    /// own, so the merged root's file is in one name order rather than in two.
    pub(super) fn installed(&self) -> Vec<u8> {
        let mut order: Vec<(&str, &[u8])> = self
            .carried
            .records
            .iter()
            .map(|(name, raw)| (name.as_str(), raw.as_slice()))
            .collect();
        let rendered: Vec<(&str, Vec<u8>)> = self
            .records
            .iter()
            .map(|record| (record.name.as_str(), record.render()))
            .collect();
        order.extend(rendered.iter().map(|(name, raw)| (*name, raw.as_slice())));
        order.sort_by(|a, b| a.0.cmp(b.0));

        let mut out = Vec::new();
        for (_, raw) in order {
            out.extend_from_slice(raw);
            // A carried record was read without the newline that ended its last
            // line, so every record is terminated here rather than some of them
            // being terminated already.
            if !raw.ends_with(b"\n") {
                out.push(b'\n');
            }
            out.push(b'\n');
        }
        out
    }

    /// The `triggers` file: the control identity of each package that watches
    /// paths, and the paths it watches.
    ///
    /// Empty when nothing does, which is a file `apk` reads as no triggers
    /// rather than one it refuses. A [carried](Self::carrying) base's lines come
    /// first, since its packages were installed first; `apk` reads the file into
    /// a table keyed by the identity each line opens with, so what the order has
    /// to be is reproducible rather than anything in particular.
    pub(super) fn triggers(&self) -> Vec<u8> {
        let mut order: Vec<&Record> = self
            .records
            .iter()
            .filter(|record| !record.triggers.is_empty())
            .collect();
        order.sort_by(|a, b| a.name.cmp(&b.name));
        let mut out = self.carried.triggers.clone();
        // The seam the carried bytes make with this layer's lines, guarded as
        // `installed` guards its own: `apk` reads this file line by line, and a
        // base whose copy did not end in a newline would have its last line
        // glued to the first written here — two packages' watches read as one
        // package's. Neither this layer nor `apk` writes such a file; what makes
        // the check worth its line is that the base is a directory a caller
        // named.
        if !out.is_empty() && !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        for record in order {
            out.extend_from_slice(record.control_identity.as_bytes());
            out.push(b' ');
            out.extend_from_slice(record.triggers.join(" ").as_bytes());
            out.push(b'\n');
        }
        out
    }

    /// The `scripts.tar` archive: one member per script.
    ///
    /// The name is the format's rather than a choice —
    /// `<package>-<version>.<X1 and the control segment's SHA-1>.<script>` —
    /// because `apk` reads the package back out of it, matching the digest
    /// against the record it has already read.
    ///
    /// Written uncompressed. `apk` looks for `scripts.tar` before
    /// `scripts.tar.gz` and keeps using whichever it found, so this is a name
    /// it maintains rather than one it replaces; what it costs is a few
    /// kilobytes of shell script left uncompressed, and what it saves is a
    /// compressor this crate would otherwise carry only for this file.
    ///
    /// A [carried](Self::carrying) base's archive is appended whole, so its
    /// terminator ends the file and its members are carried byte for byte. That
    /// is why this database's own members are written first: the base's archive
    /// is not this layer's to re-encode, and a script name can be longer than a
    /// header field it would then have to be re-encoded into.
    pub(super) fn scripts(&self) -> io::Result<Vec<u8>> {
        let mut order: Vec<&Record> = self.records.iter().collect();
        order.sort_by(|a, b| a.name.cmp(&b.name));
        let mut out = Vec::new();
        for record in order {
            for (kind, body) in &record.scripts {
                let name = script_name(record, *kind);
                // A name past the header field is refused rather than written
                // truncated: `apk` looks a script up by exactly this name, so a
                // truncated one is a script the finished root has and cannot
                // run. Nothing Alpine publishes comes near the limit — the
                // longest name in `main` is a package that carries no script at
                // all — and a refusal names the package if one ever does.
                if name.len() > tar::MAX_USTAR_NAME {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "the name apk looks {}'s {} script up by is {} bytes, past the {} a \
                             tar header holds",
                            record.name,
                            kind.name(),
                            name.len(),
                            tar::MAX_USTAR_NAME,
                        ),
                    ));
                }
                out.write_all(&tar::ustar_block(
                    name.as_bytes(),
                    &[],
                    0o755,
                    0,
                    0,
                    body.len() as u64,
                    record.build_time.unwrap_or(0) as i64,
                    b'0',
                    &[],
                )?)?;
                out.write_all(body)?;
                tar::pad(&mut out, body.len() as u64)?;
            }
        }
        if self.carried.scripts.is_empty() {
            // The terminator, which `apk`'s reader stops at. A carried archive
            // brings its own.
            out.write_all(&[0u8; 2 * tar::BLOCK as usize])?;
        } else {
            out.write_all(&self.carried.scripts)?;
        }
        Ok(out)
    }
}

/// The name a script is archived under.
fn script_name(record: &Record, kind: ScriptKind) -> String {
    format!(
        "{}-{}.{}.{}",
        record.name,
        record.version,
        record.control_identity_hex,
        kind.name(),
    )
}

/// Whether `claimant`'s `replaces` names `other`.
fn replaces(claimant: &Record, other: &Record) -> bool {
    claimant.replaces.iter().any(|entry| {
        entry.name == other.name && entry.accepts(Some(&other.version)) != entry.conflict
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A package stating `fields` on top of a minimal `.PKGINFO`.
    fn info(name: &str, version: &str, fields: &str) -> PkgInfo {
        let member = format!(
            "pkgname = {name}\npkgver = {version}\narch = noarch\n\
             pkgdesc = a package\nurl = https://example.invalid/\nlicense = MIT\n\
             size = 4096\n{fields}",
        );
        PkgInfo::parse("the package", member.as_bytes()).expect("the member parses")
    }

    /// A record over that package.
    fn record(info: &PkgInfo) -> Record {
        Record::open(
            info,
            "x86_64",
            1024,
            "Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            "X1".to_string() + &"0".repeat(40),
        )
    }

    #[test]
    fn a_carried_triggers_file_is_terminated_before_this_layers_lines() {
        // apk reads the file line by line, so a base whose copy did not end in
        // a newline would have its last line glued to the first written here --
        // two packages' watched paths read as one package's. The record
        // rendering beside this guards its own seam for the same reason.
        let info = info("busybox", "1.37.0-r30", "triggers = /bin /usr/bin\n");
        let mut database = Database::carrying(Carried {
            triggers: b"Q1BASE= /etc/init.d".to_vec(),
            ..Carried::default()
        });
        database.add(record(&info));
        let triggers = String::from_utf8(database.triggers()).expect("the file is text");
        assert_eq!(
            triggers.lines().count(),
            2,
            "the base's line and this layer's are two lines: {triggers:?}",
        );
        assert!(
            triggers.starts_with("Q1BASE= /etc/init.d\n"),
            "{triggers:?}"
        );

        // A base whose file is terminated already gains no second newline, and
        // an absent one contributes nothing at all.
        let mut database = Database::carrying(Carried {
            triggers: b"Q1BASE= /etc/init.d\n".to_vec(),
            ..Carried::default()
        });
        database.add(record(&info));
        assert_eq!(
            String::from_utf8(database.triggers())
                .expect("the file is text")
                .lines()
                .count(),
            2,
        );
        let mut database = Database::default();
        database.add(record(&info));
        assert_eq!(
            String::from_utf8(database.triggers())
                .expect("the file is text")
                .lines()
                .count(),
            1,
        );
    }

    #[test]
    fn a_header_carries_the_fields_apk_writes_in_the_order_it_writes_them() {
        // The order is apk's writer's and is not alphabetical; a record that
        // reordered them would still be read, but it would stop being the file
        // this writer is measured against.
        let info = info(
            "busybox",
            "1.37.0-r30",
            "origin = busybox\nmaintainer = Someone <a@b.invalid>\n\
             builddate = 1765894768\ncommit = 1e823a60\nprovider_priority = 100\n\
             depend = so:libc.musl-x86_64.so.1\nprovides = cmd:busybox=1.37.0-r30\n\
             replaces = busybox-initscripts\nreplaces_priority = 1000\n",
        );
        let rendered = String::from_utf8(record(&info).render()).expect("the record is text");
        assert_eq!(
            rendered,
            "C:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             P:busybox\n\
             V:1.37.0-r30\n\
             A:x86_64\n\
             S:1024\n\
             I:4096\n\
             T:a package\n\
             U:https://example.invalid/\n\
             L:MIT\n\
             o:busybox\n\
             m:Someone <a@b.invalid>\n\
             t:1765894768\n\
             c:1e823a60\n\
             k:100\n\
             D:so:libc.musl-x86_64.so.1\n\
             p:cmd:busybox=1.37.0-r30\n\
             r:busybox-initscripts\n\
             q:1000\n",
        );
    }

    #[test]
    fn the_architecture_is_the_resolutions_rather_than_the_packages() {
        // A package built for every architecture says `noarch`; the index it is
        // published in records the repository's, and that is what apk's own
        // record carries. Every one of the 6,264 records the two committed
        // index fixtures hold states an architecture, and none states `noarch`.
        let info = info("alpine-base", "3.23.5-r0", "");
        assert!(info.is_noarch());
        let rendered = String::from_utf8(record(&info).render()).expect("the record is text");
        assert!(rendered.contains("\nA:x86_64\n"), "{rendered}");
        assert!(!rendered.contains("noarch"), "{rendered}");
    }

    #[test]
    fn a_file_line_states_only_what_differs_from_the_default() {
        let info = info("a", "1-r0", "");
        let mut record = record(&info);
        record.directory(b"etc", 0, 0, 0o755);
        record.file(b"etc/plain", 0, 0, 0o644, None);
        record.file(b"etc/script", 0, 0, 0o755, Some([0xab; 20]));
        record.directory(b"root", 0, 0, 0o700);
        let rendered = String::from_utf8(record.render()).expect("the record is text");
        let (_, files) = rendered
            .split_once("F:etc\n")
            .expect("the directory is there");
        assert_eq!(
            files,
            "R:plain\n\
             R:script\n\
             a:0:0:755\n\
             Z:Q1q6urq6urq6urq6urq6urq6urq6s=\n\
             F:root\n\
             M:0:0:700\n",
        );
    }

    #[test]
    fn an_owner_recorded_after_the_entry_is_laid_down_is_the_one_written() {
        // An entry is recorded as root when it is laid down, and given its
        // package's owner once the accounts it names exist; the record states
        // the owner it was given, mode and digest kept.
        let info = info("dbus-daemon-launch-helper", "1-r0", "");
        let mut record = record(&info);
        record.directory(b"usr/libexec", 0, 0, 0o755);
        record.file(b"usr/libexec/helper", 0, 0, 0o4750, Some([0xab; 20]));
        record.directory(b"var/lib/dbus", 0, 0, 0o750);
        record.own(b"usr/libexec/helper", false, 0, 101);
        record.own(b"var/lib/dbus", true, 100, 101);
        // An entry the record does not hold is not this record's to describe.
        record.own(b"usr/libexec/other", false, 7, 7);
        record.own(b"usr/share", true, 7, 7);
        let rendered = String::from_utf8(record.render()).expect("the record is text");
        let (_, files) = rendered
            .split_once("F:usr/libexec\n")
            .expect("the directory is there");
        assert_eq!(
            files,
            "R:helper\n\
             a:0:101:4750\n\
             Z:Q1q6urq6urq6urq6urq6urq6urq6s=\n\
             F:var/lib/dbus\n\
             M:100:101:750\n",
        );
    }

    #[test]
    fn a_directory_named_by_its_contents_first_still_carries_its_own_mode() {
        // An archive may list a file before the directory holding it. The
        // directory has to be opened by the file, or the record would name a
        // file under a directory it never declared — which apk reads as a
        // broken package rather than reading on — and its own entry, when it
        // arrives, still has to place the mode above the file lines.
        let info = info("a", "1-r0", "");
        let mut record = record(&info);
        record.file(b"var/empty/keep", 0, 0, 0o644, None);
        record.directory(b"var/empty", 0, 0, 0o555);
        let rendered = String::from_utf8(record.render()).expect("the record is text");
        assert!(
            rendered.ends_with("F:var/empty\nM:0:0:555\nR:keep\n"),
            "{rendered}",
        );
    }

    #[test]
    fn records_are_written_in_name_order_whatever_order_they_were_installed_in() {
        let mut database = Database::default();
        for name in ["zlib", "musl", "busybox"] {
            let info = info(name, "1-r0", "");
            database.add(record(&info));
        }
        let installed = String::from_utf8(database.installed()).expect("the database is text");
        let names: Vec<&str> = installed
            .lines()
            .filter_map(|line| line.strip_prefix("P:"))
            .collect();
        assert_eq!(names, ["busybox", "musl", "zlib"]);
        assert!(
            installed.ends_with("\n\n"),
            "a record ends with a blank line"
        );
    }

    #[test]
    fn a_trigger_line_names_the_package_by_the_digest_the_record_carries() {
        // apk reads the triggers file by looking each digest up among the
        // records it has already read, so the two have to agree.
        let mut database = Database::default();
        database.add(record(&info(
            "busybox",
            "1-r0",
            "triggers = /bin /usr/bin\n",
        )));
        database.add(record(&info("musl", "1-r0", "")));
        assert_eq!(
            String::from_utf8(database.triggers()).expect("the file is text"),
            "Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA= /bin /usr/bin\n",
            "and nothing for the package that watches nothing",
        );
    }

    #[test]
    fn a_database_reads_back_as_the_records_it_holds() {
        // The two records `apk` itself wrote, read back through the grammar the
        // writer above emits them in.
        let existing =
            parse(super::super::fixtures::MINIROOTFS_INSTALLED).expect("the database reads");
        let names: Vec<&str> = existing
            .iter()
            .map(|one| one.record.name.as_str())
            .collect();
        assert_eq!(names, ["alpine-baselayout", "musl"]);
        // A record's file lines travel with it even though nothing parses them:
        // what is carried into a layered build's database is the record as the
        // base holds it, not a re-rendering of the fields this reader kept.
        assert!(
            existing[0].raw.windows(2).any(|pair| pair == b"F:"),
            "the file lines are in the raw record",
        );
        assert!(
            existing[0].raw.len() > existing[0].record.name.len(),
            "and the raw record is more than its header",
        );

        // A record whose header is not one is refused rather than skipped.
        assert!(parse(b"P:nameless\n\n").is_err(), "no version, no record");
    }

    #[test]
    fn a_carried_base_is_folded_into_every_file_the_database_writes() {
        // An increment's database describes the merged root: its own records
        // sort in among the base's, and the base's triggers and archived scripts
        // are carried whole.
        let mut database = Database::carrying(Carried {
            records: vec![
                ("busybox".to_string(), b"C:Q1carried\nP:busybox\n".to_vec()),
                ("zlib".to_string(), b"C:Q1carried2\nP:zlib\n".to_vec()),
            ],
            triggers: b"Q1carried= /bin\n".to_vec(),
            scripts: b"a carried archive, terminator and all".to_vec(),
        });
        database.add(record(&info("musl", "1-r0", "triggers = /lib\n")));

        let installed = String::from_utf8(database.installed()).expect("the database is text");
        let names: Vec<&str> = installed
            .lines()
            .filter_map(|line| line.strip_prefix("P:"))
            .collect();
        assert_eq!(
            names,
            ["busybox", "musl", "zlib"],
            "one name order, not two"
        );
        assert!(
            installed.starts_with("C:Q1carried\nP:busybox\n\n"),
            "a carried record is terminated as its own: {installed}",
        );

        let triggers = String::from_utf8(database.triggers()).expect("the file is text");
        assert!(
            triggers.starts_with("Q1carried= /bin\n") && triggers.contains(" /lib\n"),
            "the base's line, then this install's: {triggers}",
        );

        let scripts = database.scripts().expect("the archive is written");
        assert!(
            scripts.ends_with(b"a carried archive, terminator and all"),
            "the carried archive ends the file, so its terminator is the file's",
        );
    }

    #[test]
    fn a_script_name_past_the_header_field_is_refused_rather_than_truncated() {
        // `apk` looks a script up by exactly the name it is archived under, so a
        // truncated one is a script the finished root holds and cannot run.
        let long = "a".repeat(60);
        let mut database = Database::default();
        database.add(
            record(&info(&long, "1.0.0-r0", ""))
                .with_scripts(vec![(ScriptKind::PostInstall, b"#!/bin/sh\n".to_vec())]),
        );
        let Err(err) = database.scripts() else {
            panic!("the name is past the field");
        };
        assert!(err.to_string().contains(&long), "{err}");
    }

    #[test]
    fn a_script_is_archived_under_the_name_apk_looks_it_up_by() {
        let mut database = Database::default();
        let at = database.add(
            record(&info("busybox", "1.37.0-r30", "")).with_scripts(vec![
                (ScriptKind::PostInstall, b"#!/bin/sh\nexit 0\n".to_vec()),
                (ScriptKind::Trigger, b"#!/bin/sh\n".to_vec()),
            ]),
        );
        let _ = at;
        let archive = database.scripts().expect("the archive is written");

        // Read back through this crate's own tar reader, which is the reader
        // apk's is symmetric with.
        let mut reader = crate::provision::tar::TarReader::new(&archive[..]);
        let mut names = Vec::new();
        while let Some(entry) = reader.next_entry().expect("the archive parses") {
            assert_eq!(entry.mode, 0o755, "a script is executable");
            names.push(String::from_utf8(entry.path.clone()).expect("the name is text"));
        }
        assert_eq!(
            names,
            [
                format!("busybox-1.37.0-r30.X1{}.post-install", "0".repeat(40)),
                format!("busybox-1.37.0-r30.X1{}.trigger", "0".repeat(40)),
            ],
        );
    }

    /// Two packages, the second claiming a path the first laid down.
    fn contest(earlier: &str, later: &str) -> Claim {
        let mut database = Database::default();
        let first = database.add(record(&info("first", "1-r0", earlier)));
        let second = database.add(record(&info("second", "2-r0", later)));
        assert_eq!(
            database.claim(first, b"usr/bin/tool", Shape::File),
            Claim::Free
        );
        database.claim(second, b"usr/bin/tool", Shape::File)
    }

    #[test]
    fn two_packages_shipping_one_path_are_settled_by_what_they_replace() {
        // The later package names the earlier: it takes the file.
        assert_eq!(contest("", "replaces = first\n"), Claim::Replaces);
        // The earlier names the later: it keeps it.
        assert_eq!(contest("replaces = second\n", ""), Claim::Kept);
        // Both name each other at the same priority: the later takes it, which
        // is how a package split in two hands its files over.
        assert_eq!(
            contest("replaces = second\n", "replaces = first\n"),
            Claim::Replaces,
        );
        // The earlier's claim is stronger.
        assert_eq!(
            contest(
                "replaces = second\nreplaces_priority = 1000\n",
                "replaces = first\n",
            ),
            Claim::Kept,
        );
        // A version the replaces entry does not accept is no claim at all.
        assert_eq!(
            contest("", "replaces = first<1-r0\n"),
            Claim::Contested {
                owner: "first".to_string()
            },
        );
    }

    #[test]
    fn two_packages_of_one_source_may_share_a_path_without_saying_so() {
        assert_eq!(
            contest("origin = shared\n", "origin = shared\n"),
            Claim::Replaces,
        );
        // The source is asked first, as apk asks it: the later package takes
        // the file even where the earlier names it more strongly, which would
        // otherwise keep the file with the earlier.
        assert_eq!(
            contest(
                "origin = shared\nreplaces = second\nreplaces_priority = 1000\n",
                "origin = shared\n",
            ),
            Claim::Replaces,
        );
        // And without a shared source the same `replaces` keeps it.
        assert_eq!(
            contest(
                "origin = one\nreplaces = second\nreplaces_priority = 1000\n",
                "origin = other\n",
            ),
            Claim::Kept,
        );
    }

    #[test]
    fn two_unrelated_packages_shipping_one_path_are_contested() {
        assert_eq!(
            contest("", ""),
            Claim::Contested {
                owner: "first".to_string()
            },
        );
    }

    #[test]
    fn one_package_shipping_a_path_twice_is_not_a_contest() {
        // tar permits it, and the extraction's rule is that the later entry is
        // the file that survives.
        let mut database = Database::default();
        let only = database.add(record(&info("a", "1-r0", "")));
        assert_eq!(
            database.claim(only, b"usr/bin/tool", Shape::File),
            Claim::Free
        );
        assert_eq!(
            database.claim(only, b"usr/bin/tool", Shape::Link),
            Claim::Replaces
        );
    }

    /// The claim the second of two packages makes on one path, the first
    /// having laid it down as `first` and the second laying it as `second`.
    fn kinds(first: Shape, second: Shape, earlier: &str, later: &str) -> Claim {
        let mut database = Database::default();
        let one = database.add(record(&info("first", "1-r0", earlier)));
        let two = database.add(record(&info("second", "2-r0", later)));
        assert_eq!(database.claim(one, b"usr/lib/thing", first), Claim::Free);
        database.claim(two, b"usr/lib/thing", second)
    }

    #[test]
    fn a_directory_and_an_entry_that_is_not_one_never_share_a_path() {
        // Whichever is laid down first, and whatever `replaces` says: apk
        // cannot lay the second down either.
        for replaces in ["", "replaces = first\n"] {
            for other in [Shape::File, Shape::Link] {
                assert_eq!(
                    kinds(Shape::Directory, other, "", replaces),
                    Claim::Unlike {
                        owner: "first".to_string(),
                        directory: "first".to_string(),
                    },
                    "{other:?} over a directory, {replaces:?}",
                );
            }
            assert_eq!(
                kinds(Shape::File, Shape::Directory, "", replaces),
                Claim::Unlike {
                    owner: "first".to_string(),
                    directory: "second".to_string(),
                },
                "a directory over a file, {replaces:?}",
            );
        }
    }

    #[test]
    fn a_directory_over_a_link_is_the_tree_s_to_settle() {
        assert_eq!(
            kinds(Shape::Link, Shape::Directory, "", ""),
            Claim::Through {
                owner: "first".to_string()
            },
        );
    }

    #[test]
    fn directories_share_a_path_and_a_file_beside_them_is_still_contested() {
        assert_eq!(
            kinds(Shape::Directory, Shape::Directory, "", ""),
            Claim::Free
        );
        assert_eq!(
            kinds(Shape::File, Shape::Link, "", ""),
            Claim::Contested {
                owner: "first".to_string()
            },
        );
    }

    #[test]
    fn one_package_shipping_a_path_as_a_directory_and_a_file_is_refused() {
        let mut database = Database::default();
        let only = database.add(record(&info("a", "1-r0", "")));
        assert_eq!(
            database.claim(only, b"usr/lib/thing", Shape::File),
            Claim::Free
        );
        assert_eq!(
            database.claim(only, b"usr/lib/thing", Shape::Directory),
            Claim::Unlike {
                owner: "a".to_string(),
                directory: "a".to_string(),
            },
        );
    }
}
