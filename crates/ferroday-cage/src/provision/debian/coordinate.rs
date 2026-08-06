//! The coordinates an archive is addressed by: a suite, a component, and an
//! architecture.
//!
//! `dists/<suite>/<component>/binary-<architecture>` is the layout every Debian
//! archive publishes and every reader asks for, so one set of three values
//! decides a fetch URL, a directory under a pool root, a `Release` field, and a
//! line in a finished rootfs's apt sources. [`check`] is what each of them
//! passes before it reaches any of those, so the side that writes an archive and
//! the side that reads one refuse the same values.

use super::DebianError;

/// How many path segments one coordinate may name.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Nesting {
    /// A suite or a component, either of which may name a subtree: Debian's
    /// security archive published `dists/buster/updates/Release` for years, and
    /// `main/debian-installer` is a component laid out the same way. An
    /// interior slash is part of the name rather than a separator to refuse.
    Nested,
    /// An architecture, which is always exactly one directory name.
    Single,
}

/// Checks one archive coordinate, which becomes both a path and a field of a
/// deb822 document.
///
/// The check refuses a value that would resolve outside the tree it belongs to,
/// that the release format cannot name, or that a request line cannot carry. It
/// is deliberately narrow: it refuses traversal rather than the separator,
/// because a slashed suite and a slashed component are both legitimate layouts
/// and apt reads them.
///
/// What is refused, and why each one is not merely unusual:
///
/// - An empty or blank value, which names no directory at all.
/// - A `..` segment, which resolves outside the suite, and a leading `/`, which
///   resolves outside the archive root. These are the two that make the check
///   worth having.
/// - An empty interior or trailing segment, which is a path that does not say
///   what it means, and the shape a leading `/` would otherwise be caught as.
/// - A `.` segment, which the filesystem discards, so the directory written
///   would not be the one the caller spelled and a scanned release would name a
///   component the caller never asked for.
/// - Whitespace, which the release format cannot express: `Architectures` and
///   `Components` are whitespace-delimited lists, so a component named `my
///   thing` would be read back as two components, neither of them the one that
///   was published. It is also what separates the three fields of an HTTP
///   request line, which every fetch interpolates these values into.
/// - An ASCII control character, for the same reason a newline cannot appear in
///   a deb822 field without ending it — and, in a request line, without
///   starting a header of its own.
///
/// `what` names the coordinate in the refusal, in the possessive form the
/// message reads with: `the pool's suite`, `the repository's component`.
pub(super) fn check(what: &str, value: &str, nesting: Nesting) -> Result<(), DebianError> {
    let refuse = |reason: &str| {
        Err(DebianError::Config {
            reason: format!("{what} {value:?} {reason}"),
        })
    };
    if value.trim().is_empty() {
        return Err(DebianError::Config {
            reason: format!("{what} is empty"),
        });
    }
    if value.chars().any(|character| character.is_ascii_control()) {
        return refuse("contains a control character");
    }
    if value.chars().any(char::is_whitespace) {
        return refuse("contains whitespace, which a release field cannot name");
    }
    if value.starts_with('/') {
        return refuse("is an absolute path, which would resolve outside the archive");
    }
    if nesting == Nesting::Single && value.contains('/') {
        return refuse("is not a single path segment");
    }
    for segment in value.split('/') {
        match segment {
            "" => return refuse("has an empty path segment"),
            "." => return refuse("has a `.` segment"),
            ".." => return refuse("has a `..` segment, which would resolve outside the archive"),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason a refusal gives, or a panic naming what was accepted.
    fn refusal(value: &str, nesting: Nesting) -> String {
        match check("the archive's suite", value, nesting) {
            Err(err) => err.to_string(),
            Ok(()) => panic!("{value:?} was accepted"),
        }
    }

    #[test]
    fn traversal_and_absolute_paths_are_refused() {
        // The two the check exists for: both resolve outside the tree the
        // coordinate belongs to.
        for value in ["../escape", "a/../..", "/etc"] {
            let reason = refusal(value, Nesting::Nested);
            assert!(
                reason.contains("outside the archive"),
                "unexpected reason for {value:?}: {reason}",
            );
        }
    }

    #[test]
    fn a_path_that_does_not_say_what_it_means_is_refused() {
        for value in ["main//x", "local/", "./main", "", "   "] {
            refusal(value, Nesting::Nested);
        }
    }

    #[test]
    fn shapes_a_field_or_a_request_line_cannot_carry_are_refused() {
        // Whitespace splits an Architectures or Components list, and splits a
        // request line's three fields; a control character ends a deb822 field,
        // and a CRLF ends a request line or starts a header of its own.
        for value in ["my main", "a\nSuite: b", "p.deb\r\nX-Injected: 1", "a\tb"] {
            refusal(value, Nesting::Nested);
        }
    }

    #[test]
    fn only_a_single_segment_coordinate_refuses_the_separator() {
        // A suite and a component may name a subtree; an architecture is always
        // one directory name.
        check("the archive's suite", "buster/updates", Nesting::Nested)
            .expect("a slashed suite is a real layout");
        check(
            "the archive's component",
            "main/debian-installer",
            Nesting::Nested,
        )
        .expect("a slashed component is a real layout");
        let reason = refusal("linux/amd64", Nesting::Single);
        assert!(
            reason.contains("single path segment"),
            "unexpected reason: {reason}",
        );
    }

    #[test]
    fn ordinary_coordinates_are_accepted() {
        for value in ["trixie", "stable-updates", "main", "amd64", "arm64"] {
            check("the archive's suite", value, Nesting::Single)
                .unwrap_or_else(|err| panic!("{value:?} was refused: {err}"));
        }
    }

    #[test]
    fn the_refusal_names_the_coordinate() {
        // A caller reads the message to learn which of the three it set wrong,
        // so the name has to survive into it.
        let err = check("the pool's component", "../x", Nesting::Nested).unwrap_err();
        assert!(err.to_string().contains("component"), "{err}");
    }
}
