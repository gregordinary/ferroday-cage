//! What `--changes` and `--apply-changes` print: a line per path as text, and
//! one document with `--json`.
//!
//! With `--json`, each of the four listings is one JSON object on a line of
//! its own. `--host-report`'s and `--print-resolved`'s are the TOML document
//! the listing prints otherwise, rendered as JSON, with the same keys. The two
//! here are `fcage`'s own, since their text lists paths, which TOML holds only
//! as UTF-8:
//!
//! - `--changes` prints `{"changes": [...]}`, a [`ChangeEntry`] per change.
//! - `--apply-changes` prints `{"applied": [...], "skipped": [...],
//!   "refused": [...]}`: the paths written and those passed over where the
//!   apply ran, or, where it was refused, a [`Refused`] per change that
//!   refused it. The document is printed in both cases, so a refused apply
//!   still exits 125 and still says so on standard error.
//!
//! Both follow the event stream's rules, which [`crate::events`] states. A
//! reader ignores the members it does not know, and a member is not renamed.
//! A path is a [`Bytes`], a JSON string where it is UTF-8. A name the library
//! enumerates is its variant in kebab case, written out here, and `other` past
//! those.

use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use ferroday_cage::provision::{
    ApplyRefusal, ApplyRefusalReason, ApplyReport, Change, ChangeKind, EntryKind, Protected,
};
use serde::Serialize;

use crate::events::Bytes;

/// `--changes`'s document.
#[derive(Debug, Serialize)]
pub struct ChangeListing {
    /// Each change, in the order the change set lists them.
    changes: Vec<ChangeEntry>,
}

impl ChangeListing {
    /// The document for `changes`.
    pub fn of<'a>(changes: impl IntoIterator<Item = &'a Change>) -> ChangeListing {
        ChangeListing {
            changes: changes.into_iter().map(ChangeEntry::of).collect(),
        }
    }
}

/// One change in [`ChangeListing`].
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ChangeEntry {
    /// `added`, `modified`, `removed` or `replaced`.
    kind: &'static str,
    /// Where the change is, relative to the top of the overlay.
    path: Bytes,
    /// What the lowers held at the path, as [`entry_kind`] names it, or
    /// nothing for an added entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<&'static str>,
    /// What the run left at the path, or nothing for a removed entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    now: Option<&'static str>,
    /// The size of the file the run left, holes included, where it left one.
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    /// What a modified entry differs in, as [`differences`] names it.
    #[serde(skip_serializing_if = "Option::is_none")]
    differs: Option<Vec<&'static str>>,
    /// Whether everything the change rests on could be read. Where not, a
    /// file's content counts as differing, a directory's entries are not
    /// listed, or its attributes were not compared.
    readable: bool,
}

impl ChangeEntry {
    fn of(change: &Change) -> ChangeEntry {
        let kind = match change.kind() {
            ChangeKind::Added => "added",
            ChangeKind::Modified => "modified",
            ChangeKind::Removed => "removed",
            ChangeKind::Replaced => "replaced",
            _ => "other",
        };
        ChangeEntry {
            kind,
            path: path_bytes(change.path()),
            before: change.before().map(entry_kind),
            now: change.now().map(entry_kind),
            size: change.size(),
            differs: (change.kind() == ChangeKind::Modified).then(|| differences(change)),
            readable: change.is_readable(),
        }
    }
}

/// One line of the change listing's text: a letter for the kind, the path
/// quoted, and what a modified entry differs in, or the types a replaced one
/// changed between.
pub fn change_line(change: &Change) -> String {
    let kind_name = |kind: Option<EntryKind>| kind.map_or("other", entry_kind);
    let mut line = match change.kind() {
        ChangeKind::Added => format!("A {:?}", change.path()),
        ChangeKind::Removed => format!("D {:?}", change.path()),
        ChangeKind::Replaced => format!(
            "T {:?} {} {}",
            change.path(),
            kind_name(change.before()),
            kind_name(change.now()),
        ),
        _ => format!("M {:?} {}", change.path(), differences(change).join(",")),
    };
    if !change.is_readable() {
        line.push_str(" unreadable");
    }
    line
}

/// The name of an entry's type, in the change listing's text and its document:
/// `file`, `directory`, `link`, or `other`.
pub fn entry_kind(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Directory => "directory",
        EntryKind::Symlink => "link",
        _ => "other",
    }
}

/// What a modified entry differs in, in the change listing's text and its
/// document: any of `content`, `mode`, `owner` and `attributes`, in that order.
pub fn differences(change: &Change) -> Vec<&'static str> {
    [
        (change.content_differs(), "content"),
        (change.mode_differs(), "mode"),
        (change.owner_differs(), "owner"),
        (change.attributes_differ(), "attributes"),
    ]
    .into_iter()
    .filter_map(|(differs, name)| differs.then_some(name))
    .collect()
}

/// `--apply-changes`'s document.
#[derive(Debug, Serialize)]
pub struct ApplyListing {
    /// The paths written, relative to the target's top.
    applied: Vec<Bytes>,
    /// The paths not written because they hold a named pipe, a socket or a
    /// device.
    skipped: Vec<Bytes>,
    /// The changes that refused the apply, where it was refused, after which
    /// nothing was written.
    refused: Vec<Refused>,
}

impl ApplyListing {
    /// The document for an apply that ran and wrote `report`.
    pub fn applied(report: &ApplyReport) -> ApplyListing {
        ApplyListing {
            applied: report
                .applied()
                .iter()
                .map(|path| path_bytes(path))
                .collect(),
            skipped: report
                .skipped()
                .iter()
                .map(|path| path_bytes(path))
                .collect(),
            refused: Vec::new(),
        }
    }

    /// The document for an apply that `refusals` refused.
    pub fn refused(refusals: &[ApplyRefusal]) -> ApplyListing {
        ApplyListing {
            applied: Vec::new(),
            skipped: Vec::new(),
            refused: refusals.iter().map(Refused::of).collect(),
        }
    }
}

/// One change that refused an apply, in [`ApplyListing`].
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Refused {
    /// The change's path, relative to the target's top.
    path: Bytes,
    /// Why: `protected`, `changed`, `occupied`, `missing`, `parent-missing`,
    /// `link`, `other-filesystem` or `unreadable`.
    reason: &'static str,
    /// Where `reason` is `protected`, the protected path the change touches,
    /// relative to the target's top.
    #[serde(skip_serializing_if = "Option::is_none")]
    protected_path: Option<Bytes>,
    /// Where `reason` is `protected`, the protected name, which is protected
    /// at any depth.
    #[serde(skip_serializing_if = "Option::is_none")]
    protected_name: Option<Bytes>,
    /// The line the listing's text says it in.
    text: String,
}

impl Refused {
    fn of(refusal: &ApplyRefusal) -> Refused {
        let mut refused = Refused {
            path: path_bytes(refusal.path()),
            reason: "other",
            protected_path: None,
            protected_name: None,
            text: refusal_line(refusal),
        };
        refused.reason = match refusal.reason() {
            ApplyRefusalReason::Protected(protected) => {
                match protected {
                    Protected::Path(path) => refused.protected_path = Some(path_bytes(path)),
                    Protected::Name(name) => {
                        refused.protected_name = Some(Bytes(name.as_bytes().to_vec()));
                    }
                    _ => {}
                }
                "protected"
            }
            ApplyRefusalReason::Changed => "changed",
            ApplyRefusalReason::Occupied => "occupied",
            ApplyRefusalReason::Missing => "missing",
            ApplyRefusalReason::ParentMissing => "parent-missing",
            ApplyRefusalReason::Link => "link",
            ApplyRefusalReason::OtherFilesystem => "other-filesystem",
            ApplyRefusalReason::Unreadable => "unreadable",
            _ => "other",
        };
        refused
    }
}

/// The line the apply's text says a refusal in.
pub fn refusal_line(refusal: &ApplyRefusal) -> String {
    format!("fcage: refused {:?}: {}", refusal.path(), refusal.reason())
}

/// `path` as the byte string it is.
fn path_bytes(path: &Path) -> Bytes {
    Bytes(path.as_os_str().as_bytes().to_vec())
}
