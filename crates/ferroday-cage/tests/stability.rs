//! The promises the stability chapter makes about the API's shape, checked
//! against the committed API snapshot.
//!
//! `docs/src/stability.md` says every public enum is `#[non_exhaustive]`, and
//! so is every struct variant, which is what lets a variant or a field arrive
//! in a patch release. Neither is something the compiler or a semver checker
//! insists on: a new enum or a new struct variant without the attribute
//! compiles, and is then a breaking change to mark later. The snapshot names
//! every public item with its attributes, and the CI `api` job holds it to the
//! code, so reading it here holds the code to the chapter.

use std::collections::BTreeSet;

/// The committed snapshot, which the CI `api` job regenerates and diffs.
const SNAPSHOT: &str = include_str!("../public-api.txt");

/// Whether an item line carries `#[non_exhaustive]` among its attributes.
fn non_exhaustive(attributes: &str) -> bool {
    attributes
        .split_whitespace()
        .any(|attribute| attribute == "#[non_exhaustive]")
}

/// Splits a snapshot line into its leading attributes and the item after them.
fn attributes_and_item(line: &str) -> (&str, &str) {
    match line.find("pub ") {
        Some(at) => (&line[..at], &line[at..]),
        None => ("", line),
    }
}

/// Every public enum the snapshot names without `#[non_exhaustive]`.
fn exhaustive_enums(snapshot: &str) -> Vec<String> {
    snapshot
        .lines()
        .filter_map(|line| {
            let (attributes, item) = attributes_and_item(line);
            let path = item.strip_prefix("pub enum ")?;
            (!non_exhaustive(attributes)).then(|| path.to_string())
        })
        .collect()
}

/// Every struct variant the snapshot names without `#[non_exhaustive]`.
///
/// A struct variant is one with named fields, which the snapshot lists as
/// `pub Enum::Variant::field: Type` after the variant's own line.
fn exhaustive_struct_variants(snapshot: &str) -> Vec<String> {
    let enums: BTreeSet<&str> = snapshot
        .lines()
        .filter_map(|line| attributes_and_item(line).1.strip_prefix("pub enum "))
        .map(|path| path.split('<').next().unwrap_or(path))
        .collect();
    let mut variants: Vec<(String, bool)> = Vec::new();
    let mut with_fields = BTreeSet::new();
    for line in snapshot.lines() {
        let (attributes, item) = attributes_and_item(line);
        let Some(path) = item.strip_prefix("pub ") else {
            continue;
        };
        if let Some((variant, _field)) = path
            .split_once(": ")
            .and_then(|(name, _)| name.rsplit_once("::"))
        {
            if variants.iter().any(|(known, _)| known == variant) {
                with_fields.insert(variant.to_string());
            }
            continue;
        }
        let Some((owner, _)) = path.rsplit_once("::") else {
            continue;
        };
        if enums.contains(owner) && !path.contains('(') {
            variants.push((path.to_string(), non_exhaustive(attributes)));
        }
    }
    variants
        .into_iter()
        .filter(|(variant, marked)| with_fields.contains(variant) && !marked)
        .map(|(variant, _)| variant)
        .collect()
}

#[test]
fn every_public_enum_is_non_exhaustive() {
    let exhaustive = exhaustive_enums(SNAPSHOT);
    assert!(
        exhaustive.is_empty(),
        "public enums without #[non_exhaustive]: {exhaustive:#?}",
    );
}

#[test]
fn every_struct_variant_is_non_exhaustive() {
    let exhaustive = exhaustive_struct_variants(SNAPSHOT);
    assert!(
        exhaustive.is_empty(),
        "struct variants without #[non_exhaustive]: {exhaustive:#?}",
    );
}

/// The two readings above find what they are for: a snapshot fragment written
/// the way `cargo public-api` renders one, with one of each shape left
/// unmarked.
#[test]
fn the_readings_find_an_unmarked_enum_and_struct_variant() {
    let fragment = "\
#[non_exhaustive] pub enum ferroday_cage::Marked
pub ferroday_cage::Marked::Unit
pub ferroday_cage::Marked::Tuple(u32)
#[non_exhaustive] pub ferroday_cage::Marked::Named
pub ferroday_cage::Marked::Named::field: u32
pub ferroday_cage::Marked::Bare
pub ferroday_cage::Marked::Bare::field: u32
pub enum ferroday_cage::Plain<'a>
pub ferroday_cage::Plain::Unit
impl ferroday_cage::Marked
pub fn ferroday_cage::Marked::new() -> Self
";
    assert_eq!(exhaustive_enums(fragment), ["ferroday_cage::Plain<'a>"]);
    assert_eq!(
        exhaustive_struct_variants(fragment),
        ["ferroday_cage::Marked::Bare"]
    );
}
