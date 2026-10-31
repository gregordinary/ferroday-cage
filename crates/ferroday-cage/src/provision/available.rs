//! The package names a configured set of repositories offers.
//!
//! [`Available`] is the read-only counterpart to a resolve. A resolve answers
//! "what would a bootstrap of this include set install", and this answers "do
//! these repositories carry that name at all". A resolve cannot substitute for
//! it, and is correct for what it is: it fails the whole closure over every
//! include or dependency nothing satisfies, so a batch of names answers only
//! whether all of them, and everything they depend on, were there.
//!
//! The Debian and Alpine layers ask the question of their own index formats and
//! answer it with the same two sets: the real packages of the merged index, and
//! the virtual names its entries provide with who provides each. That answer is
//! not either format's, so it is this one type.
//!
//! The type is a projection rather than a retained index. A merged Debian
//! index is on the order of 69,000 packages with their relation vectors, which
//! is tens of megabytes to back a membership question, so the parsed records
//! are dropped at construction and only the names survive.

use std::collections::{HashMap, HashSet};
use std::fmt;

/// The package names a configured set of repositories offers.
///
#[cfg_attr(
    all(feature = "debian", feature = "alpine"),
    doc = "Produced by [`Debian::available`](super::debian::Debian::available) and \
           [`Alpine::available`](super::alpine::Alpine::available), and by the \
           observed forms of both."
)]
#[cfg_attr(
    all(feature = "debian", not(feature = "alpine")),
    doc = "Produced by [`Debian::available`](super::debian::Debian::available) and \
           its observed form."
)]
#[cfg_attr(
    all(feature = "alpine", not(feature = "debian")),
    doc = "Produced by [`Alpine::available`](super::alpine::Alpine::available) and \
           its observed form."
)]
/// It is a snapshot: the repositories it was built from can publish at any
/// time, so a name it reports is a name that was there when the index was read.
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
    /// Renders how much was read rather than what: a merged index is tens of
    /// thousands of names, and a rendering that listed them would fill a log
    /// with something no reader can act on. The counts are what a reader wants
    /// from one: whether the query found an archive's worth of names or almost
    /// none.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Available")
            .field("names", &self.names.len())
            .field("virtual_names", &self.providers.len())
            .finish()
    }
}

impl Available {
    /// Builds the projection from a merged index's two name sets: its real
    /// packages, and each virtual name's providers.
    ///
    /// Called by the layer whose index is being consumed.
    pub(crate) fn new(real: HashSet<String>, providers: HashMap<String, Vec<String>>) -> Available {
        let mut names = real;
        names.extend(providers.keys().cloned());
        Available { names, providers }
    }

    /// Whether `name` resolves in these repositories, as a real package or as a
    /// virtual name something provides.
    ///
    /// Availability is answered at the level of the name. This reports whether
    /// the repositories offer the name, not whether they offer a version
    /// satisfying some constraint: the resolver enforces a dependency's
    /// constraint, but that is a question about one closure, and this computes
    /// none.
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// The real packages that provide the virtual name `name`, in a stable
    /// order.
    ///
    /// Empty for a name nothing provides, which includes an ordinary real
    /// package: a package is not a provider of itself unless its own entry says
    /// so. Reporting them lets a caller say *what* satisfies a virtual name, an
    /// `awk` or a `so:libc.musl-x86_64.so.1`, rather than only that something
    /// does.
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
        assert_eq!(
            available.providers("awk").collect::<Vec<_>>(),
            ["gawk", "mawk"]
        );
        assert_eq!(
            available.providers("mawk").count(),
            0,
            "a package does not provide itself",
        );
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
