//! Fields and stanzas: the syntax this crate's plan documents are written in,
//! and the one Debian's control files are published in.
//!
//! A document is a sequence of stanzas separated by blank lines, each a set of
//! `Name: value` lines:
//!
//! ```text
//! Format: ferroday-cage-plan 2
//! Suite: trixie
//!
//! Package: base-files
//! Version: 13.6
//! ```
//!
//! # Whose syntax this is
//!
//! It is the crate's own. Debian's deb822 *is* this shape, so a Debian control
//! file reads here and a plan document written here reads in any deb822 tool —
//! but that is a property of field-and-stanza being the plainest way to write a
//! record, not a debt the other userland layers owe to Debian. Every layer's
//! plan is written this way, each with its own field vocabulary and its own
//! format version, and no layer's document is written in the record syntax of
//! the archive it provisions from. An apk `APKINDEX` is single letters and a
//! colon, and a plan document that looked like one would invite being fed to
//! `apk`, which is a worse failure than being unfamiliar.
//!
//! The reader is deliberately permissive and the writer deliberately strict.
//! Reading has to cope with what an archive publishes: folded continuation
//! lines, whitespace-only separators, fields in any order and any case. Writing
//! produces a document a caller may commit, diff, and pin a digest on, so a
//! value the format cannot carry back unchanged refuses the whole document
//! rather than being written and read as something else.
//!
//! # Fields a reader does not know
//!
//! A plan document is meant to outlive the program that wrote it, so a reader
//! ignores a field it does not know rather than refusing the document. Ignoring
//! it on the way in and dropping it on the way out are different things: a
//! consumer that reads a plan and writes it back would silently discard whatever
//! a newer writer had added. [`carried`] collects those fields and
//! [`Draft::put_carried`] re-emits them, so a round trip preserves every field.
//!
//! It does not promise byte identity across versions: a future writer may
//! interleave its own fields with these rather than append them, and this
//! version cannot know where they belong. What it does mean is that a field
//! added to a stanza belongs *after* every field the format's first readers
//! knew, since that is where an older reader puts back what it carried.

use std::fmt;
use std::fmt::Write as _;

/// One stanza as read: its fields in file order.
///
/// Field names are matched case-insensitively. A folded value keeps its
/// continuation lines joined with newlines, so a multi-line field such as a
/// Debian `Release` file's `SHA256` list is read line by line by the caller.
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

/// Splits a document into its stanzas.
pub(crate) fn parse(text: &str) -> Vec<Stanza> {
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
            // A continuation of the current field. The single leading space is
            // removed; the newline is kept so multi-line lists split.
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

/// The fields of one stanza that the reading version did not recognize, in the
/// order the document wrote them.
///
/// See the module documentation for why they are kept rather than dropped.
pub(crate) type Carried = Vec<(String, String)>;

/// Collects the stanza's fields that `known` does not name, in document order.
///
/// Matched case-insensitively, as every other lookup in this format is, so a
/// document spelling `sha256` does not have that field both read as known and
/// carried as unknown — which would write it out twice.
pub(crate) fn carried(stanza: &Stanza, known: &[&str]) -> Carried {
    stanza
        .fields()
        .iter()
        .filter(|(name, _)| {
            !known
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect()
}

/// Reads a required field, naming where it was missing from.
///
/// # Errors
///
/// Returns the reason where the field is absent or empty. The layers do not
/// share an error type, so each wraps the reason in its own document failure.
pub(crate) fn required(value: Option<&str>, field: &str, at: &str) -> Result<String, String> {
    match value {
        Some(value) if !value.is_empty() => Ok(value.to_string()),
        Some(_) => Err(format!("{at} has an empty {field} field")),
        None => Err(format!("{at} has no {field} field")),
    }
}

/// Reads a space-separated list field, absent or empty giving no entries.
pub(crate) fn list(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect()
}

/// A field's name: one this version writes, or one it is only passing through.
enum Name {
    Known(&'static str),
    Carried(String),
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Name::Known(name) => f.write_str(name),
            Name::Carried(name) => f.write_str(name),
        }
    }
}

/// One field of a stanza being written.
struct Field {
    name: Name,
    value: String,
    /// Whether an empty value is an answer here rather than a missing one. An
    /// unsigned repository's `Signed-By` is empty and means it; a `Suite` that
    /// came out empty is a plan that cannot be written.
    may_be_empty: bool,
}

/// One stanza being written: its fields in the order they will appear.
///
/// Collected before anything is written, so a value the format cannot carry
/// stops the whole document rather than truncating it mid-stanza.
pub(crate) struct Draft {
    fields: Vec<Field>,
}

impl Draft {
    /// A stanza with no fields yet.
    pub(crate) fn new() -> Draft {
        Draft { fields: Vec::new() }
    }

    /// Adds a field that must carry a value.
    pub(crate) fn put(&mut self, name: &'static str, value: &str) {
        self.fields.push(Field {
            name: Name::Known(name),
            value: value.to_string(),
            may_be_empty: false,
        });
    }

    /// Adds a field whose value may be empty, where empty is itself the answer.
    pub(crate) fn put_allowing_empty(&mut self, name: &'static str, value: &str) {
        self.fields.push(Field {
            name: Name::Known(name),
            value: value.to_string(),
            may_be_empty: true,
        });
    }

    /// Adds a field only when the source carries one, so an absent value reads
    /// back as absent rather than as empty.
    pub(crate) fn put_optional(&mut self, name: &'static str, value: Option<&str>) {
        if let Some(value) = value {
            self.put(name, value);
        }
    }

    /// Adds a space-separated list field, which may be empty.
    pub(crate) fn put_list(&mut self, name: &'static str, values: &[String]) {
        self.put_allowing_empty(name, &values.join(" "));
    }

    /// Appends the fields a document carried that this version does not know,
    /// after every field it does.
    ///
    /// Their names are owned rather than static, since they came off a document
    /// rather than out of this crate. An empty value is written as one, because
    /// the writer that produced it meant it.
    pub(crate) fn put_carried(&mut self, carried: &Carried) {
        for (name, value) in carried {
            self.fields.push(Field {
                name: Name::Carried(name.clone()),
                value: value.clone(),
                may_be_empty: true,
            });
        }
    }

    /// Writes the stanza and the blank line that ends it.
    ///
    /// # Errors
    ///
    /// Returns the reason where a name or a value cannot be written as a single
    /// field line and read back as itself: a name holding a colon or
    /// whitespace, a value spanning more than one line, a value carrying
    /// whitespace a reader would strip, or an empty value where empty is not an
    /// answer.
    pub(crate) fn render(&self, out: &mut String) -> Result<(), String> {
        for field in &self.fields {
            let name = &field.name;
            // A carried name came off a document rather than out of this crate,
            // so it is checked as the values are: a name holding a colon or
            // whitespace would read back as a different field, or as no field
            // at all.
            if let Name::Carried(carried) = name
                && (carried.is_empty()
                    || carried.contains([':', '\n', '\r'])
                    || carried.trim() != carried)
            {
                return Err(format!(
                    "the document carried a field named {carried:?}, which cannot be written \
                     back as a field name",
                ));
            }
            if field.value.contains(['\n', '\r']) {
                return Err(format!(
                    "the {name} value spans more than one line, which a document cannot carry",
                ));
            }
            // A reader strips the whitespace around a value, so a value
            // carrying any of its own would not survive being written and read
            // back. A leading one is worse still: the continuation marker is a
            // leading space, so such a value would be folded into the field
            // above it.
            if field.value.trim() != field.value {
                return Err(format!(
                    "the {name} value begins or ends with whitespace, which a reader strips, so \
                     the document would not read back as what wrote it",
                ));
            }
            if field.value.is_empty() && !field.may_be_empty {
                return Err(format!("the {name} value is empty"));
            }
            // An empty value is written as a bare `Name:`, with no space after
            // the colon. `Name: ` would be the only line the format can produce
            // that ends in whitespace, and it would appear exactly where a
            // repository is trusted unsigned — so a committed plan would stop
            // matching its own digest the first time an editor or a pre-commit
            // hook stripped the line, without the plan changing.
            if field.value.is_empty() {
                let _ = writeln!(out, "{name}:");
            } else {
                let _ = writeln!(out, "{name}: {}", field.value);
            }
        }
        out.push('\n');
        Ok(())
    }
}
