//! An archive source: a suite reached through one or more interchangeable
//! mirror URLs, with its own components and trust anchor.
//!
//! A bootstrap resolves against one or more [`Repository`] values. The first is
//! the primary — configured through the [`DebianBuilder`](super::DebianBuilder)
//! setters, so a single-mirror bootstrap needs no repository at all — and any
//! further ones are merged in through
//! [`DebianBuilder::repository`](super::DebianBuilder::repository). Each carries
//! its own trust anchor and freshness posture, so multiplying repositories
//! repeats the same authenticity checks per source rather than weakening them.
//!
//! One repository can list several mirror URLs. They are interchangeable views
//! of the *same* source — a live mirror and a `snapshot.debian.org` backstop,
//! say — tried in order when an earlier one reports a resource missing. Several
//! repositories are several distinct sources; several URLs in one repository are
//! one source reached several ways.

use std::fmt;
use std::path::{Path, PathBuf};

use super::DebianError;

/// A repository's trust anchor: the keyring its signature is verified against,
/// or an explicit decision to trust it unsigned.
#[derive(Clone)]
pub(crate) enum Trust {
    /// The release signature is verified against these keyring bytes.
    Signed(Vec<u8>),
    /// The release is trusted without a signature, apt's `[trusted=yes]`.
    Unsigned,
}

/// An archive source: a suite, its components, an ordered list of mirror URLs,
/// and a trust anchor.
///
/// Built with [`Repository::builder`] for an additional source, or produced
/// internally from the [`DebianBuilder`](super::DebianBuilder) setters for the
/// primary. Several repositories contribute to one merged resolution; see the
/// module documentation for how the two axes — distinct sources and
/// interchangeable URLs — fall out of this one type.
///
/// `Clone` so a caller that assembles a set of repositories once can hand the
/// same set to more than one provisioner; the clone copies the keyring bytes.
#[derive(Clone)]
#[non_exhaustive]
pub struct Repository {
    /// The mirror URLs, the primary first and any backstops after it. A fetch
    /// tries them in order, advancing past one that reports the resource
    /// missing or fails at the transport.
    pub(crate) mirrors: Vec<String>,
    /// The suite (`trixie`, `stable`) this repository publishes.
    pub(crate) suite: String,
    /// The archive components to read.
    pub(crate) components: Vec<String>,
    /// How the repository's authenticity is established.
    pub(crate) trust: Trust,
    /// Whether a signed-but-expired release is accepted, repository-wide.
    pub(crate) allow_stale: bool,
    /// The `sources.list.d` entry and trust-anchor file name, for an additional
    /// repository written into the finished rootfs. `None` for the primary,
    /// which owns `sources.list` and the canonical keyring path.
    pub(crate) name: Option<String>,
}

impl fmt::Debug for Repository {
    /// Renders the repository without dumping the keyring bytes, which are bulky
    /// and uninformative; the trust posture is shown as `signed`/`unsigned`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Repository")
            .field("mirrors", &self.mirrors)
            .field("suite", &self.suite)
            .field("components", &self.components)
            .field(
                "trust",
                &if self.trust_unsigned() {
                    "unsigned"
                } else {
                    "signed"
                },
            )
            .field("allow_stale", &self.allow_stale)
            .field("name", &self.name)
            .finish()
    }
}

impl Repository {
    /// Returns a builder for a repository publishing `suite`.
    ///
    /// A mirror URL is required; the components default to `main`, and the
    /// repository must declare its trust anchor with either
    /// [`keyring`](RepositoryBuilder::keyring) or
    /// [`trust_unsigned`](RepositoryBuilder::trust_unsigned).
    pub fn builder(suite: impl Into<String>) -> RepositoryBuilder {
        RepositoryBuilder {
            suite: suite.into(),
            mirror: None,
            fallbacks: Vec::new(),
            components: Vec::new(),
            keyring_path: None,
            trust_unsigned: false,
            allow_stale: false,
            name: None,
        }
    }

    /// Builds the primary repository from the flattened
    /// [`DebianBuilder`](super::DebianBuilder) configuration.
    ///
    /// The primary owns `sources.list` and the canonical keyring path rather
    /// than a named `sources.list.d` entry, so it carries no name. Its trust
    /// anchor is the resolved keyring bytes — the embedded archive keyring, or a
    /// caller substitution — unless the caller trusts it unsigned.
    pub(crate) fn primary(
        suite: String,
        mirrors: Vec<String>,
        components: Vec<String>,
        keyring: Vec<u8>,
        trust_unsigned: bool,
        allow_stale: bool,
    ) -> Result<Repository, DebianError> {
        let trust = if trust_unsigned {
            Trust::Unsigned
        } else {
            Trust::Signed(keyring)
        };
        let repository = Repository {
            mirrors,
            suite,
            components,
            trust,
            allow_stale,
            name: None,
        };
        repository.validate()?;
        Ok(repository)
    }

    /// The file-name stem this repository's `sources.list.d` entry and keyring
    /// take in the finished rootfs: the caller's
    /// [`name`](RepositoryBuilder::name) when given, or one generated from its
    /// position in the set otherwise.
    ///
    /// Only an additional repository takes a stem; the primary owns
    /// `sources.list` and the canonical trust-anchor path. `index` is the
    /// repository's position in the resolved set, the primary at zero.
    pub(crate) fn entry_stem(&self, index: usize) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("fcage-repo-{index}"))
    }

    /// Whether the repository is trusted without a signature.
    pub(crate) fn trust_unsigned(&self) -> bool {
        matches!(self.trust, Trust::Unsigned)
    }

    /// The keyring the release is verified against, or `None` when the
    /// repository is trusted unsigned.
    pub(crate) fn keyring(&self) -> Option<&[u8]> {
        match &self.trust {
            Trust::Signed(bytes) => Some(bytes),
            Trust::Unsigned => None,
        }
    }

    /// Whether freshness is enforced: signed and not stale-relaxed. An unsigned
    /// repository is never freshness-checked.
    pub(crate) fn require_fresh(&self) -> bool {
        !self.trust_unsigned() && !self.allow_stale
    }

    /// Rejects a configuration that would install unauthenticated packages: an
    /// unsigned repository reached over a transport that offers no authenticity
    /// of its own.
    ///
    /// `trust_unsigned` skips the archive signature, so authenticity would rest
    /// on the transport alone. An `http://` mirror offers none, so the two
    /// together install fully unverified packages. A `file://` mirror is local
    /// and under the caller's control; any other scheme is a caller-supplied
    /// fetcher's responsibility. The check is per-URL: every mirror of an
    /// unsigned repository must be non-`http://`.
    fn validate(&self) -> Result<(), DebianError> {
        if self.mirrors.is_empty() {
            return Err(DebianError::Config {
                reason: "a repository needs at least one mirror URL".to_string(),
            });
        }
        if self.trust_unsigned() {
            for mirror in &self.mirrors {
                if mirror.starts_with("http://") {
                    return Err(DebianError::Config {
                        reason: format!(
                            "trust_unsigned cannot be used with the http:// mirror {mirror}: skipping \
                         the archive signature over an unauthenticated transport installs \
                         unverified packages; use a file:// mirror, or drop trust_unsigned so the \
                         signature is checked"
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Builder for a [`Repository`].
pub struct RepositoryBuilder {
    suite: String,
    mirror: Option<String>,
    fallbacks: Vec<String>,
    components: Vec<String>,
    keyring_path: Option<PathBuf>,
    trust_unsigned: bool,
    allow_stale: bool,
    name: Option<String>,
}

impl RepositoryBuilder {
    /// Sets the primary mirror URL, the first one every fetch tries.
    pub fn mirror(mut self, url: impl Into<String>) -> Self {
        self.mirror = Some(url.into());
        self
    }

    /// Adds a backstop mirror URL, tried in order after the primary when a
    /// fetch reports the resource missing or fails at the transport.
    ///
    /// This expresses a live mirror with a `snapshot.debian.org` fallback: the
    /// same suite and the same content reached through a second URL. The
    /// freshness posture is repository-wide, so a repository with a snapshot
    /// backstop normally sets
    /// [`allow_stale_release`](Self::allow_stale_release), the snapshot's
    /// release being expired by design.
    pub fn mirror_fallback(mut self, url: impl Into<String>) -> Self {
        self.fallbacks.push(url.into());
        self
    }

    /// Sets the archive components. The default is `main`.
    pub fn components<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.components = components.into_iter().map(Into::into).collect();
        self
    }

    /// Verifies the repository's release against the binary OpenPGP keyring
    /// read from `path`.
    ///
    /// A signed repository must declare a keyring: unlike the primary, an
    /// additional repository has no embedded default, since its signing key is
    /// its own.
    pub fn keyring(mut self, path: impl AsRef<Path>) -> Self {
        self.keyring_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Trusts the repository without verifying its signature, apt's
    /// `[trusted=yes]`.
    ///
    /// Appropriate for a local or `file://` repository under the caller's
    /// control — a build's own freshly-signed-nothing `.deb` pool — never for a
    /// remote one. [`build`](Self::build) refuses it against an `http://`
    /// mirror, which offers no authenticity in the signature's place.
    pub fn trust_unsigned(mut self, trust: bool) -> Self {
        self.trust_unsigned = trust;
        self
    }

    /// Accepts a signed release that is past its `Valid-Until`.
    ///
    /// The posture is repository-wide: it relaxes freshness for every mirror,
    /// which a live-plus-snapshot repository wants because the snapshot's
    /// release is expired by design. The signature is still verified. It has no
    /// effect on a [`trust_unsigned`](Self::trust_unsigned) repository, which is
    /// never freshness-checked.
    pub fn allow_stale_release(mut self, allow: bool) -> Self {
        self.allow_stale = allow;
        self
    }

    /// Names the repository, for its `/etc/apt/sources.list.d/<name>.list`
    /// entry and, when signed, its `/usr/share/keyrings/<name>.gpg` trust
    /// anchor in the finished rootfs.
    ///
    /// The name must be a portable file-name stem — ASCII letters, digits, and
    /// `.`, `-`, `_` — so it cannot escape those directories. Without one, a
    /// generated stem is used, which is enough for provisioning but rarely what
    /// a caller wants in the finished sources.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Validates the configuration and freezes it into a [`Repository`].
    ///
    /// # Errors
    ///
    /// Returns a [`DebianError::Config`] when no mirror was set, when a signed
    /// repository names no keyring, when the keyring cannot be read, when an
    /// unsigned repository is reached over `http://`, or when a supplied name
    /// is not a portable file-name stem.
    pub fn build(self) -> Result<Repository, DebianError> {
        let Some(primary) = self.mirror else {
            return Err(DebianError::Config {
                reason: "a repository needs a mirror URL; set one with mirror()".to_string(),
            });
        };
        let mut mirrors = Vec::with_capacity(1 + self.fallbacks.len());
        mirrors.push(primary);
        mirrors.extend(self.fallbacks);

        let components = if self.components.is_empty() {
            vec!["main".to_string()]
        } else {
            self.components
        };

        if let Some(name) = &self.name {
            validate_name(name)?;
        }

        let trust = if self.trust_unsigned {
            Trust::Unsigned
        } else {
            let path = self.keyring_path.ok_or_else(|| DebianError::Config {
                reason: "a signed repository needs a keyring; set one with keyring(), or trust it \
                     unsigned with trust_unsigned(true)"
                    .to_string(),
            })?;
            let bytes = std::fs::read(&path).map_err(|source| DebianError::Io {
                op: "reading the repository keyring",
                path: path.clone(),
                source,
            })?;
            Trust::Signed(bytes)
        };

        let repository = Repository {
            mirrors,
            suite: self.suite,
            components,
            trust,
            allow_stale: self.allow_stale,
            name: self.name,
        };
        repository.validate()?;
        Ok(repository)
    }
}

/// Rejects a repository name that is not a portable file-name stem, so it
/// cannot traverse out of `sources.list.d` or the keyrings directory when the
/// finished rootfs's sources are written.
fn validate_name(name: &str) -> Result<(), DebianError> {
    let portable = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && name != "."
        && name != "..";
    if portable {
        Ok(())
    } else {
        Err(DebianError::Config {
            reason: format!(
                "the repository name {name:?} is not a portable file-name stem: use ASCII letters, \
             digits, and '.', '-', '_'"
            ),
        })
    }
}

/// Rejects a repository set whose additional repositories would write over
/// each other in the finished rootfs.
///
/// Each additional repository writes `sources.list.d/<stem>.list` and its own
/// `<stem>.gpg` keyring, so two sharing a stem leave only the last one's source
/// line and keyring behind — the earlier repository would be silently absent
/// from the installed system's apt configuration even though its packages were
/// installed. Collisions arise between two caller-supplied names, and between a
/// caller-supplied name and another repository's generated stem.
pub(crate) fn validate_distinct_entries(repositories: &[Repository]) -> Result<(), DebianError> {
    let mut seen: Vec<String> = Vec::with_capacity(repositories.len());
    for (index, repository) in repositories.iter().enumerate().skip(1) {
        let stem = repository.entry_stem(index);
        if seen.contains(&stem) {
            return Err(DebianError::Config {
                reason: format!(
                    "two additional repositories would both write the apt source {stem:?}: \
                     give each repository a distinct name"
                ),
            });
        }
        seen.push(stem);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An additional repository carrying `name`, otherwise minimal.
    fn named(name: Option<&str>) -> Repository {
        let mut builder = Repository::builder("trixie")
            .mirror("file:///srv/debs")
            .trust_unsigned(true);
        if let Some(name) = name {
            builder = builder.name(name);
        }
        builder.build().expect("the repository should build")
    }

    #[test]
    fn two_repositories_sharing_a_name_are_refused() {
        let set = [named(None), named(Some("local")), named(Some("local"))];
        let err = validate_distinct_entries(&set).unwrap_err();
        assert!(
            matches!(&err, DebianError::Config { reason } if reason.contains("local")),
            "{err}"
        );
    }

    #[test]
    fn a_name_colliding_with_a_generated_stem_is_refused() {
        // The unnamed repository at index 2 generates `fcage-repo-2`, which the
        // named one at index 1 already claimed.
        let set = [named(None), named(Some("fcage-repo-2")), named(None)];
        assert!(matches!(
            validate_distinct_entries(&set),
            Err(DebianError::Config { .. })
        ));
    }

    #[test]
    fn distinct_names_and_generated_stems_are_accepted() {
        let set = [named(None), named(Some("local")), named(None), named(None)];
        assert!(validate_distinct_entries(&set).is_ok());
    }

    #[test]
    fn a_mirror_is_required() {
        assert!(matches!(
            Repository::builder("trixie").trust_unsigned(true).build(),
            Err(DebianError::Config { .. })
        ));
    }

    #[test]
    fn a_signed_repository_needs_a_keyring() {
        // Neither a keyring nor trust_unsigned: the trust anchor is undeclared.
        let err = Repository::builder("trixie")
            .mirror("https://example.invalid/debian")
            .build()
            .unwrap_err();
        assert!(matches!(err, DebianError::Config { .. }));
    }

    #[test]
    fn an_unsigned_http_repository_is_refused() {
        let err = Repository::builder("trixie")
            .mirror("http://example.invalid/debian")
            .trust_unsigned(true)
            .build()
            .unwrap_err();
        assert!(matches!(err, DebianError::Config { .. }));
    }

    #[test]
    fn an_unsigned_http_fallback_is_refused() {
        // The transport check is per-URL: a non-http primary does not excuse an
        // http backstop.
        let err = Repository::builder("trixie")
            .mirror("file:///srv/debs")
            .mirror_fallback("http://example.invalid/debian")
            .trust_unsigned(true)
            .build()
            .unwrap_err();
        assert!(matches!(err, DebianError::Config { .. }));
    }

    #[test]
    fn mirrors_are_ordered_primary_first() {
        let repo = Repository::builder("trixie")
            .mirror("file:///primary")
            .mirror_fallback("file:///backstop")
            .trust_unsigned(true)
            .build()
            .expect("the repository validates");
        assert_eq!(repo.mirrors, ["file:///primary", "file:///backstop"]);
        assert_eq!(repo.components, ["main"]);
        assert!(repo.trust_unsigned());
        assert!(repo.keyring().is_none());
    }

    #[test]
    fn a_traversing_name_is_refused() {
        let err = Repository::builder("trixie")
            .mirror("file:///srv/debs")
            .trust_unsigned(true)
            .name("../evil")
            .build()
            .unwrap_err();
        assert!(matches!(err, DebianError::Config { .. }));
    }

    #[test]
    fn a_portable_name_is_accepted() {
        let repo = Repository::builder("trixie")
            .mirror("file:///srv/debs")
            .trust_unsigned(true)
            .name("local-debs")
            .build()
            .expect("the repository validates");
        assert_eq!(repo.name.as_deref(), Some("local-debs"));
    }
}
