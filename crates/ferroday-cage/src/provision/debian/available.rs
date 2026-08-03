//! The names a configured set of archives offers.
//!
//! [`Available`] is the read-only counterpart to a resolve: where
//! [`Debian::resolve`](super::Debian::resolve) answers "what would a bootstrap
//! of this include set install", this answers "does this archive carry that
//! name at all". Neither resolver behaviour substitutes for it, and both are
//! correct for what they are — a top-level include naming nothing fails the
//! whole resolve, so a batch of them answers only whether they were all there,
//! and an unsatisfiable transitive dependency is dropped deliberately, since
//! dpkg configures with `--force-depends`.
//!
//! The type is a projection rather than a retained index. A merged trixie amd64
//! index is on the order of 69,000 packages with their relation vectors, which
//! is tens of megabytes to back a membership question, so the parsed packages
//! are dropped at construction and only the names survive.

use std::collections::{HashMap, HashSet};
use std::fmt;

/// The package names a configured set of archives offers.
///
/// Produced by [`Debian::available`](super::Debian::available) and
/// [`Observed::available`](super::Observed::available). It is a snapshot: the
/// archives it was built from can publish at any time, so a name it reports is
/// a name that was there when the index was read.
///
/// # Stability
///
/// Opaque, and deliberately so: what it stores is an implementation detail, and
/// a caller sees only the questions it answers.
pub struct Available {
    /// Every resolvable name: the real packages of the merged index, plus every
    /// virtual name something in it provides.
    names: HashSet<String>,
    /// Each virtual name's providers, sorted, as the index indexed them.
    providers: HashMap<String, Vec<String>>,
}

impl fmt::Debug for Available {
    /// Renders how much was read rather than what: a merged suite is tens of
    /// thousands of names, and a rendering that listed them would fill a log
    /// with something no reader can act on. The counts are what a reader wants
    /// from one — whether the query found an archive's worth of names or almost
    /// none.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Available")
            .field("names", &self.names.len())
            .field("virtual_names", &self.providers.len())
            .finish()
    }
}

impl Available {
    /// Builds the projection from a merged index's two name sets.
    ///
    /// Called by [`Index::into_available`](super::index::Index::into_available),
    /// which owns the index being consumed.
    pub(super) fn new(real: HashSet<String>, providers: HashMap<String, Vec<String>>) -> Available {
        let mut names = real;
        names.extend(providers.keys().cloned());
        Available { names, providers }
    }

    /// Whether `name` resolves in these archives, as a real package or as a
    /// virtual name something provides.
    ///
    /// Availability is answered at the level of the name, which is the level
    /// the resolver works at: a dependency's version constraint and
    /// architecture qualifier are parsed away on the grounds that a single
    /// suite is internally consistent. So this reports whether the archives
    /// offer the name, not whether they offer a version satisfying some
    /// constraint — the library does not solve version constraints.
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// The real packages that provide the virtual package `name`, in a stable
    /// order.
    ///
    /// Empty for a name nothing provides, which includes an ordinary real
    /// package: a package is not a provider of itself. Reporting them lets a
    /// caller say *what* satisfies a virtual name rather than only that
    /// something does.
    pub fn providers(&self, name: &str) -> impl Iterator<Item = &str> {
        self.providers
            .get(name)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A projection standing in for one built from a merged index.
    fn sample() -> Available {
        Available::new(
            ["mawk", "gawk", "base"]
                .into_iter()
                .map(String::from)
                .collect(),
            HashMap::from([(
                "awk".to_string(),
                vec!["gawk".to_string(), "mawk".to_string()],
            )]),
        )
    }

    #[test]
    fn a_provided_name_resolves_alongside_the_real_ones() {
        let available = sample();
        assert!(available.contains("mawk"), "a real package");
        assert!(available.contains("awk"), "a name only provided");
        assert!(!available.contains("nawk"));
    }

    #[test]
    fn a_rendering_reports_how_much_was_read_rather_than_what() {
        // A merged suite is tens of thousands of names, so the one thing this
        // rendering must never do is list them. The counts are the whole of it,
        // and this is the same view a consumer gets.
        let rendering = format!("{:?}", sample());
        assert!(
            rendering.contains("names: 4") && rendering.contains("virtual_names: 1"),
            "{rendering}",
        );
        assert!(!rendering.contains("mawk"), "{rendering}");
    }
}
