//! An apk repository: a release reached through one or more interchangeable
//! mirror URLs, with its own components and its own signing keys.
//!
//! A bootstrap resolves against one or more [`Repository`] values. The first is
//! the primary — configured through the [`AlpineBuilder`](super::AlpineBuilder)
//! setters, so a single-mirror bootstrap needs no repository at all — and any
//! further ones are merged in through
//! [`AlpineBuilder::repository`](super::AlpineBuilder::repository), each with
//! its own [`KeySet`], so multiplying repositories repeats the same
//! authenticity check per source rather than weakening it.
//!
//! One repository can list several mirror URLs. They are interchangeable views
//! of the *same* source, tried in order when an earlier one reports a resource
//! missing. Several repositories are several distinct sources; several URLs in
//! one repository are one source reached several ways.
//!
//! # Two layouts, one type
//!
//! Alpine publishes `<release>/<component>/<architecture>`, and postmarketOS
//! publishes `<release>/<architecture>` — a repository with no components at
//! all. That is the whole difference between the two, so a repository with an
//! empty component list formats the shallower path and postmarketOS costs no
//! code of its own.

use crate::provision::mirror_url;
use std::fmt;

use super::AlpineError;
use super::keyring::KeySet;
use crate::provision::compose_mirrors;
use crate::provision::coordinate;
use crate::provision::coordinate::Nesting;

/// The file an apk repository publishes its catalogue as.
const INDEX_NAME: &str = "APKINDEX.tar.gz";

/// An apk repository: a release, its components, an ordered list of mirror
/// URLs, and the keys its signatures are verified against.
///
/// Built with [`Repository::builder`] for an additional source, or produced
/// internally from the [`AlpineBuilder`](super::AlpineBuilder) setters for the
/// primary.
///
/// `Clone` so a caller that assembles a set of repositories once can hand the
/// same set to more than one provisioner.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Repository {
    /// The mirror URLs, the primary first and any backstops after it.
    pub(super) mirrors: Vec<String>,
    /// The release (`v3.23`, `edge`) this repository publishes.
    pub(super) release: String,
    /// The components to read, empty for a repository that publishes none.
    pub(super) components: Vec<String>,
    /// The keys this repository's indexes are verified against. A package is
    /// bound to the index that named it rather than verified on its own.
    pub(super) keys: KeySet,
}

impl Repository {
    /// Returns a builder for a repository publishing `release`.
    ///
    /// A mirror URL and a key set are both required; the components default to
    /// none, which is the `<release>/<architecture>` layout.
    pub fn builder(release: impl Into<String>) -> RepositoryBuilder {
        RepositoryBuilder {
            release: release.into(),
            mirror: None,
            fallbacks: Vec::new(),
            components: Vec::new(),
            keys: None,
        }
    }

    /// Builds the primary repository from the flattened
    /// [`AlpineBuilder`](super::AlpineBuilder) configuration.
    pub(super) fn primary(
        release: String,
        mirrors: Vec<String>,
        components: Vec<String>,
        keys: KeySet,
    ) -> Result<Repository, AlpineError> {
        let repository = Repository {
            mirrors,
            release,
            components,
            keys,
        };
        repository.validate()?;
        Ok(repository)
    }

    /// This repository's indexes for `architecture`: the component each
    /// publishes, and the mirror-relative path it is published at, in the order
    /// the components were given.
    ///
    /// A repository with no components has one index, at the shallower path
    /// postmarketOS publishes, and reports no component for it.
    ///
    /// The component travels with the path because a package is addressed
    /// relative to the directory its own index sits in, so a resolution has to
    /// remember which component answered rather than only what it said.
    pub(super) fn indexes(&self, architecture: &str) -> Vec<(Option<&str>, String)> {
        let release = &self.release;
        if self.components.is_empty() {
            return vec![(None, format!("{release}/{architecture}/{INDEX_NAME}"))];
        }
        self.components
            .iter()
            .map(|component| {
                (
                    Some(component.as_str()),
                    format!("{release}/{component}/{architecture}/{INDEX_NAME}"),
                )
            })
            .collect()
    }

    /// The release this repository publishes, for the plan's record of it.
    pub(super) fn release(&self) -> &str {
        &self.release
    }

    /// The lines this repository contributes to the finished root's
    /// `/etc/apk/repositories`.
    ///
    /// One per component, or one for the whole repository where it publishes
    /// none. Each names the directory *above* the architecture level, because
    /// that is where `apk` starts from: it composes an index URL by appending
    /// `<architecture>/APKINDEX.tar.gz` to the line, and a package URL by
    /// appending `<architecture>/<name>-<version>.apk`. So the architecture
    /// never appears in the file, and a root built for one architecture states
    /// nothing that would have to change to read another.
    ///
    /// The primary mirror only. A backstop is where *this* bootstrap looked
    /// when the first mirror did not answer, which is a fetch-time choice
    /// rather than a configuration the installed system inherits — the same
    /// rule the Debian layer applies to a snapshot fallback.
    pub(super) fn sources(&self) -> Vec<String> {
        let Some(mirror) = self.mirrors.first() else {
            return Vec::new();
        };
        let release = &self.release;
        if self.components.is_empty() {
            return vec![mirror_url(mirror, release)];
        }
        self.components
            .iter()
            .map(|component| mirror_url(mirror, &format!("{release}/{component}")))
            .collect()
    }

    /// Rejects a configuration the repository cannot be addressed by.
    ///
    /// The release and each component become path segments of every URL this
    /// repository is fetched through, and words of the `/etc/apk/repositories`
    /// lines written into the finished rootfs, so both pass the archive
    /// coordinate check: a `..` segment climbs out of the mirror root — a local
    /// read for a `file://` mirror — and a control character splits the request
    /// line the value is interpolated into.
    ///
    /// There is no unsigned mode to check for, unlike the Debian layer's: apk
    /// has none in practice, so a repository always carries keys and the check
    /// is that the set is not empty.
    fn validate(&self) -> Result<(), AlpineError> {
        coordinate::check("the repository's release", &self.release, Nesting::Nested)
            .map_err(AlpineError::config)?;
        for component in &self.components {
            coordinate::check("the repository's component", component, Nesting::Nested)
                .map_err(AlpineError::config)?;
        }
        if self.keys.is_empty() {
            return Err(AlpineError::config(format!(
                "the repository {} has an empty key set, so nothing it serves could be \
                     verified; build one with KeySet::alpine, KeySet::postmarketos, or \
                     KeySet::insert",
                self.release,
            )));
        }
        Ok(())
    }
}

/// Builder for a [`Repository`].
pub struct RepositoryBuilder {
    release: String,
    mirror: Option<String>,
    fallbacks: Vec<String>,
    components: Vec<String>,
    keys: Option<KeySet>,
}

impl fmt::Debug for RepositoryBuilder {
    /// Renders the configuration, naming the keys rather than holding them, as
    /// [`KeySet`]'s own rendering does.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RepositoryBuilder")
            .field("release", &self.release)
            .field("mirror", &self.mirror)
            .field("fallbacks", &self.fallbacks)
            .field("components", &self.components)
            .field("keys", &self.keys)
            .finish()
    }
}

impl RepositoryBuilder {
    /// Sets the primary mirror URL, the first one every fetch tries.
    ///
    /// The URL is the archive root — the directory the releases sit under, such
    /// as `http://dl-cdn.alpinelinux.org/alpine` — not the release directory
    /// itself.
    ///
    /// The default transport speaks `http://` and `file://` only, so an
    /// `https://` mirror needs a fetcher of the caller's own, set with
    /// [`AlpineBuilder::fetcher`]. Every archive this layer is written against
    /// serves plain HTTP, and the signature rather than the transport is what
    /// authenticates what arrives.
    ///
    /// [`AlpineBuilder::fetcher`]: super::AlpineBuilder::fetcher
    pub fn mirror(mut self, url: impl Into<String>) -> Self {
        self.mirror = Some(url.into());
        self
    }

    /// Adds a backstop mirror URL, tried in order after the primary when a
    /// fetch reports the resource missing or fails at the transport.
    ///
    /// This expresses one source reached several ways: the same release and the
    /// same content behind a second URL. A distinct source is a second
    /// [`Repository`] instead.
    pub fn mirror_fallback(mut self, url: impl Into<String>) -> Self {
        self.fallbacks.push(url.into());
        self
    }

    /// Sets the repository's components, `main` and `community` for Alpine.
    ///
    /// The default is none, which is the `<release>/<architecture>` layout
    /// postmarketOS publishes. A repository that has components must name them:
    /// there is no default component, because the two layouts are told apart by
    /// whether any were given.
    pub fn components<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.components = components.into_iter().map(Into::into).collect();
        self
    }

    /// Verifies this repository's indexes against `keys`.
    ///
    /// A package is bound to the verified index that named it, by the control
    /// identity the index records for it, so a package's own signature is read
    /// and not verified.
    ///
    /// An additional repository must declare its keys: unlike the primary, it
    /// has no default, since its signing key is its own.
    /// [`KeySet::postmarketos`] is the one for postmarketOS's repositories, and
    /// [`KeySet::alpine`] the one for a second Alpine mirror.
    pub fn keys(mut self, keys: KeySet) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Validates the configuration and freezes it into a [`Repository`].
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Config`] when no mirror was set, when a mirror
    /// URL carries whitespace or a control character, when no keys were, when
    /// the key set is empty, or when the release or a component is
    /// one the repository cannot be addressed by: an empty value, one carrying
    /// whitespace, a control character, or another character a URL path cannot
    /// carry as written (such as `%`, `?`, `#`, or one outside ASCII), or one
    /// that would resolve outside the mirror root through a leading `/`, a `..`
    /// segment, or an empty or `.` segment. Either may otherwise contain
    /// slashes, since both may name a subtree — postmarketOS publishes an
    /// `extra-repos` tree of releases.
    pub fn build(self) -> Result<Repository, AlpineError> {
        let Some(primary) = self.mirror else {
            return Err(AlpineError::config(
                "a repository needs a mirror URL; set one with mirror()",
            ));
        };
        let Some(keys) = self.keys else {
            return Err(AlpineError::config(
                "a repository needs the keys its signatures are verified against; set \
                     them with keys(), from KeySet::alpine or KeySet::postmarketos",
            ));
        };
        let mirrors = compose_mirrors(primary, self.fallbacks).map_err(AlpineError::config)?;

        let repository = Repository {
            mirrors,
            release: self.release,
            components: self.components,
            keys,
        };
        repository.validate()?;
        Ok(repository)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repository over `components`, otherwise minimal.
    fn built(components: &[&str]) -> Repository {
        Repository::builder("v3.23")
            .mirror("file:///srv/alpine")
            .components(components.iter().copied())
            .keys(KeySet::postmarketos())
            .build()
            .expect("the repository validates")
    }

    #[test]
    fn components_give_the_deeper_layout_and_none_gives_the_shallower() {
        assert_eq!(
            built(&["main", "community"]).indexes("x86_64"),
            [
                (
                    Some("main"),
                    "v3.23/main/x86_64/APKINDEX.tar.gz".to_string()
                ),
                (
                    Some("community"),
                    "v3.23/community/x86_64/APKINDEX.tar.gz".to_string(),
                ),
            ],
        );
        // postmarketOS's shape: one index, one level shallower, and no
        // component to attribute a package to.
        assert_eq!(
            built(&[]).indexes("x86_64"),
            [(None, "v3.23/x86_64/APKINDEX.tar.gz".to_string())],
        );
    }

    #[test]
    fn mirrors_are_ordered_primary_first() {
        let repository = Repository::builder("v3.23")
            .mirror("file:///primary")
            .mirror_fallback("file:///backstop")
            .keys(KeySet::postmarketos())
            .build()
            .expect("the repository validates");
        assert_eq!(repository.mirrors, ["file:///primary", "file:///backstop"]);
    }

    #[test]
    fn a_mirror_and_a_key_set_are_both_required() {
        let no_mirror = Repository::builder("v3.23")
            .keys(KeySet::postmarketos())
            .build()
            .expect_err("a repository needs a mirror");
        assert!(
            matches!(no_mirror, AlpineError::Config { .. }),
            "{no_mirror}"
        );

        let no_keys = Repository::builder("v3.23")
            .mirror("file:///srv/alpine")
            .build()
            .expect_err("a repository needs keys");
        assert!(matches!(&no_keys, AlpineError::Config { reason } if reason.contains("KeySet")));
    }

    #[test]
    fn an_empty_key_set_is_refused() {
        // It would verify nothing, and the failure belongs where the set was
        // configured rather than at the first signature it cannot check.
        let err = Repository::builder("v3.23")
            .mirror("file:///srv/alpine")
            .keys(KeySet::new())
            .build()
            .expect_err("an empty set verifies nothing");
        assert!(matches!(err, AlpineError::Config { .. }), "{err}");
    }

    #[test]
    fn a_coordinate_that_would_leave_the_mirror_root_is_refused() {
        for release in ["../etc", "/etc", "", "   ", "a/../..", "v3 23", "v3.23\n"] {
            let err = Repository::builder(release)
                .mirror("file:///srv/alpine")
                .keys(KeySet::postmarketos())
                .build()
                .expect_err("the release is not addressable");
            assert!(
                matches!(err, AlpineError::Config { .. }),
                "{release:?}: {err}"
            );
        }
        let err = Repository::builder("v3.23")
            .mirror("file:///srv/alpine")
            .components(["../../etc"])
            .keys(KeySet::postmarketos())
            .build()
            .expect_err("the component is not addressable");
        assert!(matches!(err, AlpineError::Config { .. }), "{err}");
    }

    #[test]
    fn a_release_naming_a_subtree_is_accepted() {
        // postmarketOS publishes an `extra-repos` tree, so an interior slash is
        // part of the name rather than a separator to refuse.
        assert_eq!(
            Repository::builder("extra-repos/systemd/v26.06")
                .mirror("file:///srv/pmos")
                .keys(KeySet::postmarketos())
                .build()
                .expect("a slashed release is a real layout")
                .indexes("x86_64"),
            [(
                None,
                "extra-repos/systemd/v26.06/x86_64/APKINDEX.tar.gz".to_string(),
            )],
        );
    }

    #[test]
    fn a_rendering_names_the_keys_rather_than_holding_them() {
        let rendering = format!("{:?}", built(&["main"]));
        assert!(rendering.contains("build.postmarketos.org"), "{rendering}");
        assert!(!rendering.contains("BEGIN PUBLIC KEY"), "{rendering}");
    }
}
