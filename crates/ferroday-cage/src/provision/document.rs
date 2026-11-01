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
//! A folded field is carried the same way: the reader joins its continuation
//! lines with newlines and the writer folds them back, so a document holding a
//! multi-line field a later version added reads and writes without loss. A
//! field *this* version knows is one it composed rather than read, and none of
//! them is multi-line, so a newline in one is refused rather than encoded.
//!
//! It does not promise byte identity across versions: a future writer may
//! interleave its own fields with these rather than append them, and this
//! version cannot know where they belong. What it does mean is that a field
//! added to a stanza belongs *after* every field the format's first readers
//! knew, since that is where an older reader puts back what it carried.

use std::borrow::Cow;
use std::fmt;
use std::fmt::Write as _;

/// The stanzas of a document, in order, each read only as it is reached.
///
/// Nothing is read ahead and nothing is copied out of the document, so reading
/// every stanza of a large one holds one stanza at a time, and costs only what
/// its reader keeps of each.
pub(crate) fn parse(text: &str) -> Stanzas<'_> {
    Stanzas { rest: text }
}

/// The stanzas a document holds, as [`parse`] yields them.
pub(crate) struct Stanzas<'a> {
    /// What is left of the document.
    rest: &'a str,
}

impl<'a> Iterator for Stanzas<'a> {
    type Item = Stanza<'a>;

    fn next(&mut self) -> Option<Stanza<'a>> {
        loop {
            // A blank line ends a stanza. Whitespace-only counts as blank: deb822
            // readers treat it so, and a continuation line is one that starts
            // with a space *and* carries content.
            while let Some((line, after)) = split_line(self.rest)
                && line.trim().is_empty()
            {
                self.rest = after;
            }
            if self.rest.is_empty() {
                return None;
            }
            let start = self.rest;
            while let Some((line, after)) = split_line(self.rest)
                && !line.trim().is_empty()
            {
                self.rest = after;
            }
            let stanza = Stanza {
                text: &start[..start.len() - self.rest.len()],
            };
            // A run of lines holding no field is no stanza: there is nothing in
            // it a reader could ask for.
            if stanza.spelled().next().is_some() {
                return Some(stanza);
            }
        }
    }
}

/// One stanza as read: the lines it spans, borrowed from the document.
///
/// A field is found by walking those lines when it is asked for, so holding a
/// stanza costs nothing beyond the document however its fields are laid out:
/// a stanza of a million one-character fields is the same two words as one of
/// a dozen.
///
/// Field names are matched case-insensitively. A folded value keeps its
/// continuation lines joined with newlines, so a multi-line field such as a
/// Debian `Release` file's `SHA256` list is read line by line by the caller.
#[derive(Clone, Copy)]
pub(crate) struct Stanza<'a> {
    /// The stanza's lines, each with its line ending.
    text: &'a str,
}

impl<'a> Stanza<'a> {
    /// The value of `key`, matched case-insensitively, or `None`.
    ///
    /// Where the stanza names a field twice, the first answers. The value
    /// borrows the document, and is copied only where it is folded, which
    /// joining its lines requires.
    pub(crate) fn get(&self, key: &str) -> Option<Cow<'a, str>> {
        self.spelled()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.unfolded())
    }

    /// The values of `keys`, each as [`get`](Self::get) answers it, from one
    /// walk of the stanza.
    ///
    /// For a reader taking several fields from every stanza of a large
    /// document, where asking for each in turn would walk the stanza once per
    /// field. The Debian and Gentoo index readers are those, so a build with
    /// neither layer has no caller.
    #[cfg_attr(not(any(feature = "debian", feature = "gentoo")), allow(dead_code))]
    pub(crate) fn get_each<const N: usize>(&self, keys: [&str; N]) -> [Option<Cow<'a, str>>; N] {
        let mut found: [Option<Spelling<'a>>; N] = [None; N];
        let mut missing = N;
        for (name, value) in self.spelled() {
            if missing == 0 {
                break;
            }
            if let Some(at) = keys.iter().position(|key| name.eq_ignore_ascii_case(key))
                && found[at].is_none()
            {
                found[at] = Some(value);
                missing -= 1;
            }
        }
        found.map(|value| value.map(Spelling::unfolded))
    }

    /// Every field, in the order the stanza wrote them.
    ///
    /// For a reader that has to account for fields it does not itself
    /// understand, rather than only look up the ones it does.
    pub(crate) fn fields(&self) -> impl Iterator<Item = (&'a str, Cow<'a, str>)> + use<'a> {
        self.spelled().map(|(name, value)| (name, value.unfolded()))
    }

    /// Every field, each value as the stanza spells it.
    fn spelled(&self) -> Spelled<'a> {
        Spelled { rest: self.text }
    }
}

/// The fields of a stanza in order, each value as the stanza spells it, so a
/// field passed over on the way to another is never unfolded.
///
/// A line that starts with a space or a tab continues the field above it. A
/// line that is neither that nor a field is passed over, and leaves the field
/// above it the continuation lines that follow. A continuation line with no
/// field above it continues nothing.
struct Spelled<'a> {
    /// The stanza's lines not yet read.
    rest: &'a str,
}

impl<'a> Iterator for Spelled<'a> {
    type Item = (&'a str, Spelling<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        let (name, first) = loop {
            let (line, after) = split_line(self.rest)?;
            self.rest = after;
            if line.starts_with([' ', '\t']) {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                break (name.trim(), value.trim());
            }
        };
        let below = self.rest;
        while let Some((line, after)) = split_line(self.rest)
            && (line.starts_with([' ', '\t']) || !line.contains(':'))
        {
            self.rest = after;
        }
        let below = &below[..below.len() - self.rest.len()];
        Some((name, Spelling { first, below }))
    }
}

/// A field's value as the stanza spells it.
#[derive(Clone, Copy)]
struct Spelling<'a> {
    /// The value on the field's own line, trimmed.
    first: &'a str,
    /// The lines between the field and the next, which hold its continuation
    /// lines among any that are not fields at all.
    below: &'a str,
}

impl<'a> Spelling<'a> {
    /// The value with its continuation lines joined on, each with the single
    /// leading space removed and the newline kept, so a multi-line list splits.
    fn unfolded(self) -> Cow<'a, str> {
        let mut joined: Option<String> = None;
        let mut rest = self.below;
        while let Some((line, after)) = split_line(rest) {
            rest = after;
            if line.starts_with([' ', '\t']) {
                let value = joined.get_or_insert_with(|| self.first.to_string());
                value.push('\n');
                value.push_str(line.strip_prefix(' ').unwrap_or(line));
            }
        }
        joined.map_or(Cow::Borrowed(self.first), Cow::Owned)
    }
}

/// Splits the first line off `text` as [`str::lines`] yields it, without its
/// line ending, and returns it with what follows; `None` where nothing is left.
fn split_line(text: &str) -> Option<(&str, &str)> {
    if text.is_empty() {
        return None;
    }
    Some(match text.split_once('\n') {
        Some((line, rest)) => (line.strip_suffix('\r').unwrap_or(line), rest),
        None => (text, ""),
    })
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
pub(crate) fn carried(stanza: &Stanza<'_>, known: &[&str]) -> Carried {
    stanza
        .fields()
        .filter(|(name, _)| {
            !known
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(name))
        })
        .map(|(name, value)| (name.to_string(), value.into_owned()))
        .collect()
}

/// Splits a plan document's stanzas into its header and the stanzas after it,
/// holding the header to `format`.
///
/// Every layer's plan opens with a header stanza whose `Format` names the
/// document's format and its version, and a reader reads only the one it was
/// written for: a document of another format, or of a later version of this
/// one, is refused rather than read as far as its fields happen to overlap.
///
/// # Errors
///
/// Returns the reason where the document holds no stanza, where its first
/// states no `Format`, or where the format is not `format`. Each layer wraps it
/// in its own document failure, as [`required`]'s.
pub(crate) fn header<'a>(
    mut stanzas: Stanzas<'a>,
    format: &str,
) -> Result<(Stanza<'a>, Stanzas<'a>), String> {
    let header = stanzas
        .next()
        .ok_or_else(|| "the document holds no stanzas".to_string())?;
    let found = header
        .get("Format")
        .ok_or_else(|| "the first stanza has no Format field".to_string())?;
    if found != format {
        return Err(format!(
            "the document is in format {found:?}, and this library reads {format:?}",
        ));
    }
    Ok((header, stanzas))
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

/// Reads an optional numeric field, absent giving no value, naming where a
/// malformed one was found.
///
/// A value that is not a number refuses the document rather than reading as
/// absent. Reading it as absent would drop it on the way out, and a document
/// that came back missing a line it was given is the one failure the carried
/// fields exist to prevent.
///
/// A number is read only as the writer spells one: ASCII digits with no
/// leading zero, after a `-` for a negative value of a type that has them.
/// Rust's own integer parser also takes a leading `+`, leading zeros, and
/// `-0`. A document read that way would be written back without them, as a
/// document other than the one that was read, and a committed plan's digest
/// would change with nothing in it changed. So a value is read only where
/// writing the number back gives the same text.
///
/// # Errors
///
/// Returns the reason where the field is present and is not a number of type
/// `T` in that spelling, one out of its range included. Each layer wraps it in
/// its own document failure, as [`required`]'s.
pub(crate) fn number<T: std::str::FromStr + fmt::Display>(
    value: Option<&str>,
    field: &str,
    at: &str,
) -> Result<Option<T>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value.parse::<T>() {
        Ok(number) if number.to_string() == value => Ok(Some(number)),
        _ => Err(format!(
            "{at} has a {field} of {value:?}, which is not a number"
        )),
    }
}

/// Reads a space-separated list field, absent or empty giving no entries.
///
/// Only the Debian layer's plan carries a list field — an archive's components,
/// and the keys that sign it. Alpine's names one repository per stanza and
/// Gentoo's one package per stanza, and a dependency closure is stanzas rather
/// than a list, so a build of either alone has no caller.
#[cfg_attr(not(feature = "debian"), allow(dead_code))]
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
    ///
    /// Only the Debian layer's plan has such a field: an unsigned repository's
    /// `Signed-By` is empty and means it. The Alpine and Gentoo plans write
    /// every value as something or as nothing at all, so a build without
    /// `debian` has no caller, and neither has [`put_list`](Self::put_list)
    /// below it.
    #[cfg_attr(not(feature = "debian"), allow(dead_code))]
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
    #[cfg_attr(not(feature = "debian"), allow(dead_code))]
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
    /// Returns the reason where a name or a value cannot be written and read
    /// back as itself: a name holding a colon or whitespace, a value carrying a
    /// carriage return or one of the whitespace runs a reader would strip, a
    /// folded value with a blank continuation, or an empty value where empty is
    /// not an answer.
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
            if field.value.contains('\r') {
                return Err(format!(
                    "the {name} value carries a carriage return, which a document cannot carry",
                ));
            }
            // A field this version knows is one it composed, and none of them is
            // multi-line: a newline in one is a value the layer should have
            // refused, and writing it folded would encode it rather than report
            // it. A carried field's value came off a document instead, where a
            // folded one is ordinary — the reader accepts it, so refusing to
            // write it back would read a document this crate cannot re-emit,
            // which is the one thing carrying an unknown field is for.
            if matches!(name, Name::Known(_)) && field.value.contains('\n') {
                return Err(format!(
                    "the {name} value spans more than one line, which a document cannot carry",
                ));
            }
            // A carried value the reader folded holds its continuation lines
            // joined with newlines, and is written back folded.
            let mut lines = field.value.split('\n');
            let first = lines.next().unwrap_or_default();
            // A reader strips the whitespace around a field's own line, so a
            // value carrying any of its own would not survive being written and
            // read back. A leading one is worse still: the continuation marker
            // is a leading space, so such a value would be folded into the
            // field above it.
            if first.trim() != first {
                return Err(format!(
                    "the {name} value begins or ends with whitespace, which a reader strips, so \
                     the document would not read back as what wrote it",
                ));
            }
            if first.is_empty() && !field.may_be_empty {
                return Err(format!("the {name} value is empty"));
            }
            let continuations: Vec<&str> = lines.collect();
            // A blank continuation cannot be written: a line of whitespace ends
            // the stanza, so the rest of the value would read as a stanza of its
            // own. Nothing this crate reads produces one — a blank line ends the
            // stanza there too — so this is about a value assembled rather than
            // read.
            if continuations.iter().any(|line| line.trim().is_empty()) {
                return Err(format!(
                    "the {name} value folds onto a blank line, which ends a stanza rather than \
                     continuing a field",
                ));
            }
            // An empty value is written as a bare `Name:`, with no space after
            // the colon. `Name: ` would be the only line the format can produce
            // that ends in whitespace, and it would appear exactly where a
            // repository is trusted unsigned — so a committed plan would stop
            // matching its own digest the first time an editor or a pre-commit
            // hook stripped the line, without the plan changing.
            if first.is_empty() {
                let _ = writeln!(out, "{name}:");
            } else {
                let _ = writeln!(out, "{name}: {first}");
            }
            // The single space the reader strips from a continuation, put back.
            for line in continuations {
                let _ = writeln!(out, " {line}");
            }
        }
        out.push('\n');
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_is_the_first_stanza_and_names_the_format_read() {
        let stanzas = parse("Format: plan 1\nSuite: x\n\nPackage: a\n\nPackage: b\n");
        let (first, rest) = header(stanzas, "plan 1").expect("the header reads");
        assert_eq!(first.get("Suite").as_deref(), Some("x"));
        assert_eq!(rest.count(), 2);

        let refusal = |text: &str| {
            header(parse(text), "plan 1")
                .map(|_| ())
                .expect_err("the document is refused")
        };
        assert!(refusal("").contains("holds no stanzas"));
        assert!(refusal("Suite: x\n").contains("no Format field"));
        assert!(refusal("Format: plan 2\n").contains("\"plan 2\""));
        // Matched exactly: a reader of one version does not read another's, and
        // the comparison is not loosened by case or by a suffix.
        assert!(refusal("Format: PLAN 1\n").contains("format"));
        assert!(refusal("Format: plan 10\n").contains("format"));
    }

    #[test]
    fn a_stanza_is_read_where_it_lies_and_copies_only_a_folded_value() {
        // Reading holds nothing per field: a stanza is where it lies in the
        // document, however many fields it has.
        assert_eq!(size_of::<Stanza<'_>>(), size_of::<&str>());

        let text = "\
Package: one
Depends: a,
 b,
\tc
Description: short
 first line
not a field
 second line
Package: shadowed

 \t
no field here

  stray continuation
Package: two\r
Version: 1.0\r
";
        let stanzas: Vec<Stanza<'_>> = parse(text).collect();
        // The blank and whitespace-only lines end a stanza, and a run of lines
        // holding no field is no stanza at all.
        assert_eq!(stanzas.len(), 2);
        let one = stanzas[0];
        // A value on one line borrows the document.
        assert!(matches!(one.get("package"), Some(Cow::Borrowed("one"))));
        // A folded value joins its continuation lines, each with one leading
        // space removed, and only it is copied to do so.
        assert!(matches!(one.get("Depends"), Some(Cow::Owned(_))));
        assert_eq!(one.get("Depends").as_deref(), Some("a,\nb,\n\tc"));
        // A line that is not a field leaves the field above it its
        // continuation lines.
        assert_eq!(
            one.get("Description").as_deref(),
            Some("short\nfirst line\nsecond line"),
        );
        assert_eq!(one.get("Version"), None);
        // The fields in order, a name given twice included.
        let names: Vec<&str> = one.fields().map(|(name, _)| name).collect();
        assert_eq!(names, ["Package", "Depends", "Description", "Package"]);

        // A continuation with no field above it continues nothing, and a line
        // ending CR LF reads as one ending LF.
        let two = stanzas[1];
        assert_eq!(two.fields().count(), 2);
        assert_eq!(two.get("Package").as_deref(), Some("two"));
        assert_eq!(two.get("version").as_deref(), Some("1.0"));
    }

    #[test]
    fn a_number_is_digits_spelled_as_the_writer_spells_them() {
        let read = |value: &str| number::<u64>(Some(value), "Size", "the package a");
        assert_eq!(read("0"), Ok(Some(0)));
        assert_eq!(read("1024"), Ok(Some(1024)));
        assert_eq!(read(&u64::MAX.to_string()), Ok(Some(u64::MAX)));
        assert_eq!(
            number::<u64>(None, "Size", "the package a"),
            Ok(None),
            "absent is no value"
        );

        // Rust's parser takes a leading `+` and leading zeros, neither of which
        // the writer writes, so a document reading them would not write back as
        // itself.
        for refused in [
            "+5",
            "0010",
            "00",
            "",
            "-",
            "5 ",
            "0x10",
            "1e3",
            "-5",
            "18446744073709551616",
        ] {
            let reason = read(refused).expect_err(refused);
            assert_eq!(
                reason,
                format!("the package a has a Size of {refused:?}, which is not a number"),
            );
        }

        // A signed type takes the sign it can hold, and only that one.
        let signed = |value: &str| number::<i64>(Some(value), "Index-Timestamp", "the header");
        assert_eq!(signed("-42"), Ok(Some(-42)));
        assert_eq!(signed(&i64::MIN.to_string()), Ok(Some(i64::MIN)));
        assert!(signed("+42").is_err());
        assert!(signed("--42").is_err());
        // Zero has one spelling, and a negative number none with a leading
        // zero.
        assert_eq!(signed("0"), Ok(Some(0)));
        for refused in ["-0", "-042", "007"] {
            assert!(signed(refused).is_err(), "{refused}");
        }
    }
}
