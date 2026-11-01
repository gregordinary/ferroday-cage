//! What a path a caller names may contain.
//!
//! A path is split into its components before it becomes anything the kernel
//! sees, and the split is where a path that cannot mean what it says is
//! refused. The crate asks that in three shapes, and each is answered once
//! here:
//!
//! - [`absolute_components`], for a path a caller configures — a mount target,
//!   a Landlock grant — which is absolute and is read as `std` reads it.
//! - [`tree_components`], for a path that names something *inside* a tree: a
//!   host-side write into a rootfs, an entry of an archive being extracted.
//!   Those are bytes rather than text, and the two callers differ on one point
//!   only, which is the argument the function takes.
//! - [`is_ordinary_component`], for a single name, which is what the two above
//!   leave behind and what a copy-in frame carries one of.
//!
//! Each caller needs a different error type, so a refusal is reported as a
//! value the caller maps into its own vocabulary.
//!
//! One question about a path's shape rather than its contents is answered here
//! too, since every module that places a file beside a path asks it:
//! [`parent_of`], the directory a path's final component is named in.
//!
//! # What is not here
//!
//! Two other kinds of path check live elsewhere, each for a reason:
//!
//! - **An archive coordinate** — a release, a component, or an architecture —
//!   is checked by `provision::coordinate`, which additionally refuses
//!   whitespace, control characters, and any other character a URL path cannot
//!   carry as written. Those refusals are about the release format's
//!   whitespace-delimited lists and about the URL every fetch interpolates the
//!   value into, neither of which a mount target has anything to do with.
//! - **A network interface name** is checked by `netstack`, against the
//!   kernel's own `dev_valid_name`: `IFNAMSIZ` is a hard 16-byte ceiling that
//!   belongs to no other path.
//!
//! The copy-in and export children check their frames post-fork, where nothing
//! may allocate, so the control flow around those checks stays in the modules
//! that state the constraint. The rule itself does not:
//! [`is_ordinary_component`] allocates nothing and is what they ask.
//!
//! [`Rooted`](crate::provision::rooted::Rooted) is the other half of the
//! subject — resolving a path inside a tree that is not fully trusted — and is
//! about what the *kernel* is asked to do rather than about what a caller may
//! write.

use std::ffi::OsStr;
use std::path::{Component, Path};

/// A path that is not an absolute path of ordinary components.
///
/// Carries nothing: each caller already holds the path it asked about and
/// reports it in its own error variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotAbsolute;

/// Splits an absolute path into its ordinary components.
///
/// Refuses a relative path and any component that is not a plain name — a `..`
/// above all, which is refused rather than resolved: nothing this is asked
/// about is composed with one on purpose, so a path that has one is a
/// composition bug rather than a traversal to honour.
///
/// The bare root splits into no components at all, which is a legitimate answer
/// for a caller that can act on the whole tree and a refusal for one that
/// cannot. Deciding that is the caller's, so it is reported as an empty slice
/// rather than as an error here.
///
/// `.` and empty components never arrive: [`Path::components`] normalizes them
/// away, so `/etc/./apt` and `/etc//apt` both split as `etc`, `apt`. A leading
/// `./` is the exception it keeps, and that is a relative path, refused above.
pub(crate) fn absolute_components(path: &Path) -> Result<Vec<&OsStr>, NotAbsolute> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(NotAbsolute);
    }
    components
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(NotAbsolute),
        })
        .collect()
}

/// What a leading `/` means on a path that names something inside a tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeadingSlash {
    /// The tree's own root, which the path is relative to already, so the slash
    /// is dropped and the rest reads as before. A tree that is a root
    /// filesystem holds files that name themselves that way, and a caller
    /// naming `/etc/apt/sources.list` in one means the file in the tree.
    TreeRoot,
    /// Refused. Where the tree is a plain directory that nothing re-roots — the
    /// destination of an extraction — an absolute path names the *host's* root,
    /// and honouring it by dropping the slash would silently answer a different
    /// question than the one the path asked.
    Refused,
}

/// Why a path does not name something inside a tree.
///
/// Carries nothing: each caller already holds the path it asked about, and
/// says so in its own vocabulary — an errno for one, a sentence naming the
/// archive entry for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// A NUL byte, which no filesystem path can hold. Refused over the whole
    /// path rather than per component, since a path carrying one is not a path
    /// that was understood: taking the part before it would name an entry the
    /// caller never asked for.
    Nul,
    /// A leading `/`, where the caller does not accept one.
    Absolute,
    /// A `..` component, which is refused rather than resolved: nothing this is
    /// asked about is composed with one on purpose, and the kernel-side
    /// containment that follows is not a licence to hand it paths that mean
    /// something other than what they say.
    Traversal,
}

/// Splits a path naming something inside a tree into its components.
///
/// The path is bytes rather than text: a mount target comes from a caller's
/// profile and an archive entry from an archive, and neither is obliged to be
/// UTF-8.
///
/// Empty and `.` components are dropped, so `etc//apt` and `etc/./apt` both
/// split as `etc`, `apt` — the normalization [`Path::components`] performs for
/// [`absolute_components`], performed here over bytes. Every component that
/// survives satisfies [`is_ordinary_component`].
///
/// A path that normalizes to nothing at all — `.`, the empty path, and under
/// [`LeadingSlash::TreeRoot`] the bare `/` too — splits into an empty slice
/// rather than a refusal, because the two callers disagree about it: an
/// archive's `./` entry describes the extraction root and is meaningful, while
/// a host-side write has nothing to write to. Deciding that is the caller's, the
/// same way the bare root is for [`absolute_components`]. `/` is on that list
/// only for the caller that admits a leading slash at all: the leading-slash
/// rule is applied first, so [`LeadingSlash::Refused`] refuses it as
/// [`Refused::Absolute`] before there is anything to normalize.
pub(crate) fn tree_components(path: &[u8], leading: LeadingSlash) -> Result<Vec<&[u8]>, Refused> {
    if path.contains(&0) {
        return Err(Refused::Nul);
    }
    if leading == LeadingSlash::Refused && path.first() == Some(&b'/') {
        return Err(Refused::Absolute);
    }
    let mut components = Vec::new();
    for component in path.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => continue,
            b".." => return Err(Refused::Traversal),
            _ => components.push(component),
        }
    }
    Ok(components)
}

/// Whether `name` is one ordinary path component: not empty, neither `.` nor
/// `..`, and holding neither a separator nor a NUL.
///
/// This is what makes a name safe to hand to an `*at` call against a directory
/// already held open: a name that is none of those five shapes names an entry
/// *in* that directory and cannot reach outside it, however the tree around it
/// is arranged. Each of the five is refused rather than resolved.
///
/// Allocation-free, and free of anything else a forked child may not do, so the
/// copy-in child applies the same rule to a frame's name that its host side
/// applies before sending it.
pub(crate) fn is_ordinary_component(name: &[u8]) -> bool {
    !matches!(name, b"" | b"." | b"..") && !name.contains(&b'/') && !name.contains(&0)
}

/// The directory `path`'s final component is named in, as a path an `open`
/// takes: its parent, or `.` for a bare relative name.
///
/// [`Path::parent`] answers a bare name's parent as the empty path, which
/// names nothing the kernel will open, create, or probe, and joining a sibling
/// onto it drops the directory altogether. Every caller that opens a path's
/// directory, creates it, or places a file beside the path asks this instead.
///
/// A path with no parent at all, the root or the empty path, answers `.` as
/// well. A caller that needs the final component refuses such a path for
/// lacking one, before it asks.
pub(crate) fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The components of `path`, or `None` where it is refused.
    fn split(path: &str) -> Option<Vec<&str>> {
        absolute_components(Path::new(path))
            .ok()
            .map(|components| components.iter().map(|c| c.to_str().unwrap()).collect())
    }

    #[test]
    fn an_absolute_path_splits_into_its_ordinary_components() {
        assert_eq!(
            split("/etc/apt/sources.list"),
            Some(vec!["etc", "apt", "sources.list"])
        );
        assert_eq!(split("/tmp"), Some(vec!["tmp"]));
    }

    #[test]
    fn the_bare_root_splits_into_nothing_rather_than_failing() {
        // Whether that is usable is the caller's question: a Landlock grant may
        // cover the whole tree, a mount target may not be it.
        assert_eq!(split("/"), Some(vec![]));
    }

    #[test]
    fn a_relative_path_and_a_traversal_are_refused() {
        for path in ["etc/apt", "./etc", "../escape", "/etc/../..", "", "/etc/.."] {
            assert_eq!(split(path), None, "{path:?} should be refused");
        }
    }

    #[test]
    fn the_components_std_normalizes_away_never_arrive() {
        // Not a rule this enforces — a rule `Path::components` already applies,
        // stated here so a reader does not look for the check.
        assert_eq!(split("/etc/./apt"), Some(vec!["etc", "apt"]));
        assert_eq!(split("/etc//apt"), Some(vec!["etc", "apt"]));
        assert_eq!(split("/etc/apt/"), Some(vec!["etc", "apt"]));
    }

    /// The components of a tree path, or the refusal.
    fn in_tree(path: &str, leading: LeadingSlash) -> Result<Vec<&str>, Refused> {
        tree_components(path.as_bytes(), leading).map(|components| {
            components
                .into_iter()
                .map(|component| std::str::from_utf8(component).unwrap())
                .collect()
        })
    }

    #[test]
    fn a_tree_path_splits_the_way_the_absolute_one_does() {
        // The same normalization, over bytes: empty and `.` components go, and
        // what is left is a sequence of ordinary names.
        for path in [
            "etc/apt/sources.list",
            "etc//apt/./sources.list",
            "etc/apt/sources.list/",
        ] {
            assert_eq!(
                in_tree(path, LeadingSlash::Refused),
                Ok(vec!["etc", "apt", "sources.list"]),
                "{path:?}",
            );
        }
    }

    #[test]
    fn a_leading_slash_is_the_callers_to_answer() {
        assert_eq!(
            in_tree("/etc/apt", LeadingSlash::TreeRoot),
            Ok(vec!["etc", "apt"]),
            "a rootfs's own files name themselves from its root",
        );
        assert_eq!(
            in_tree("/etc/apt", LeadingSlash::Refused),
            Err(Refused::Absolute),
        );
    }

    #[test]
    fn a_traversal_and_a_nul_are_refused_whatever_the_leading_slash_means() {
        for leading in [LeadingSlash::TreeRoot, LeadingSlash::Refused] {
            assert_eq!(in_tree("../escape", leading), Err(Refused::Traversal));
            assert_eq!(
                in_tree("etc/../../escape", leading),
                Err(Refused::Traversal)
            );
            assert_eq!(in_tree("etc/pas\0swd", leading), Err(Refused::Nul));
            // The NUL is answered before anything else, since a path carrying
            // one was not understood at all.
            assert_eq!(in_tree("../\0", leading), Err(Refused::Nul));
        }
    }

    #[test]
    fn a_path_that_normalizes_to_nothing_is_reported_as_nothing() {
        // Not a refusal: an archive's `./` entry describes the extraction root,
        // and a host-side write refuses the same shape itself.
        for path in ["", ".", "./", "/", "//."] {
            assert_eq!(
                in_tree(path, LeadingSlash::TreeRoot),
                Ok(vec![]),
                "{path:?}"
            );
        }

        // Except where the leading slash itself is refused, which is decided
        // before there is anything to normalize: for that caller `/` is an
        // absolute path rather than a path that came to nothing.
        for path in ["", ".", "./"] {
            assert_eq!(in_tree(path, LeadingSlash::Refused), Ok(vec![]), "{path:?}");
        }
        for path in ["/", "//."] {
            assert_eq!(
                in_tree(path, LeadingSlash::Refused),
                Err(Refused::Absolute),
                "{path:?}",
            );
        }
    }

    #[test]
    fn an_ordinary_component_is_a_name_and_nothing_else() {
        for name in ["etc", "sources.list", "...", "a b", "-"] {
            assert!(is_ordinary_component(name.as_bytes()), "{name:?}");
        }
        for name in ["", ".", "..", "etc/apt", "/", "et\0c"] {
            assert!(!is_ordinary_component(name.as_bytes()), "{name:?}");
        }
    }

    #[test]
    fn every_component_a_split_keeps_is_an_ordinary_one() {
        // What lets a caller hand each one to an `*at` call without a second
        // check of its own.
        let split = in_tree("/etc//apt/./sources.list", LeadingSlash::TreeRoot).unwrap();
        assert!(
            split
                .iter()
                .all(|component| is_ordinary_component(component.as_bytes())),
        );
    }

    #[test]
    fn a_bare_name_is_named_in_the_working_directory() {
        // The empty parent `Path::parent` gives a bare name is no path the
        // kernel opens, so it is answered as `.`.
        for (path, parent) in [
            ("rootfs", "."),
            ("./rootfs", "."),
            ("var/rootfs", "var"),
            ("/var/lib/rootfs", "/var/lib"),
            ("/rootfs", "/"),
            ("/", "."),
            ("", "."),
        ] {
            assert_eq!(parent_of(Path::new(path)), Path::new(parent), "{path:?}");
        }
    }
}
