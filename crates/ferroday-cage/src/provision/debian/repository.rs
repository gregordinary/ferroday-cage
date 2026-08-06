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
use super::coordinate::{self, Nesting};

/// A repository's trust anchor: the keyring its signature is verified against,
/// or an explicit decision to trust it unsigned.
#[derive(Clone)]
pub(crate) enum Trust {
    /// The release signature is verified against these keyring bytes.
    Signed(Vec<u8>),
    /// The release is trusted without a signature, apt's `[trusted=yes]`.
    Unsigned,
}

impl fmt::Debug for Trust {
    /// Names the anchor rather than dumping it. A keyring is bulky and its
    /// bytes say nothing a reader of a rendering can act on; its length is kept
    /// because a truncated or empty keyring is a real misconfiguration and is
    /// otherwise indistinguishable from a whole one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Trust::Signed(keyring) => write!(f, "Signed({} bytes)", keyring.len()),
            Trust::Unsigned => f.write_str("Unsigned"),
        }
    }
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
    /// Renders the repository, naming its trust anchor by its form and length
    /// rather than dumping it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Repository")
            .field("mirrors", &self.mirrors)
            .field("suite", &self.suite)
            .field("components", &self.components)
            .field("trust", &self.trust)
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

    /// Rejects a configuration the repository cannot be addressed by, or that
    /// would install unauthenticated packages.
    ///
    /// The suite and each component become path segments of every URL this
    /// repository is fetched through, and words of the `deb` line written into
    /// the finished rootfs's apt sources, so both pass the archive-coordinate
    /// check: a `..` segment climbs out of the mirror root — a local read for a
    /// `file://` mirror — and a control character splits the request line the
    /// value is interpolated into, or adds a source line to the rootfs that the
    /// caller never wrote. It is the same check [`Pool`](super::Pool) makes of
    /// the coordinates it publishes under, so a pool this crate writes and a
    /// repository this crate reads agree on what an archive may be called.
    ///
    /// `trust_unsigned` skips the archive signature, so authenticity rests on
    /// the transport alone, and the check is that the transport provides some:
    /// every mirror of an unsigned repository must be `file://` — local, under
    /// the caller's control — or `https://`, which authenticates the server it
    /// came from. The check is per-URL.
    ///
    /// It is an allow-list rather than a refusal of `http://`, because a
    /// refusal names only the plaintext scheme the crate happened to think of:
    /// a caller-supplied fetcher speaking any other unauthenticated transport
    /// would pass, and the pairing would install wholly unverified packages
    /// over an unauthenticated wire. Schemes are case-insensitive (RFC 3986
    /// §3.1), so the comparison is too — a refusal that read `http://`
    /// literally would let `HTTP://` name the same plaintext transport and slip
    /// past.
    fn validate(&self) -> Result<(), DebianError> {
        if self.mirrors.is_empty() {
            return Err(DebianError::Config {
                reason: "a repository needs at least one mirror URL".to_string(),
            });
        }
        coordinate::check("the repository's suite", &self.suite, Nesting::Nested)?;
        for component in &self.components {
            coordinate::check("the repository's component", component, Nesting::Nested)?;
        }
        if self.trust_unsigned() {
            for mirror in &self.mirrors {
                if !is_authenticated_transport(mirror) {
                    return Err(DebianError::Config {
                        reason: format!(
                            "trust_unsigned cannot be used with the mirror {mirror}: skipping the \
                         archive signature leaves authenticity to the transport alone, and only \
                         file:// (local, under your control) and https:// (which authenticates the \
                         server) supply any; use one of those, or drop trust_unsigned so the \
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
///
/// The keyring is held as the path it will be read from, so a rendering of a
/// builder names the trust anchor without ever holding it.
#[derive(Debug)]
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
    ///
    /// The default transport speaks `http://` and `file://` only, so an
    /// `https://` mirror needs a fetcher of the caller's own, set with
    /// [`DebianBuilder::fetcher`]; without one the URL is refused when the
    /// solve first reaches for it. Carrying a TLS stack is the consumer's
    /// decision, not the crate's — the archive signature, not the transport, is
    /// what authenticates a package.
    ///
    /// [`DebianBuilder::fetcher`]: super::DebianBuilder::fetcher
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
    ///
    /// A fallback is fetched through the same transport as the primary, so the
    /// scheme constraint of [`mirror`](Self::mirror) applies to it too.
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
    /// remote one. With no signature, authenticity rests on the transport
    /// alone, so [`build`](Self::build) requires one that supplies some: every
    /// mirror must be `file://` or `https://`, and any other scheme —
    /// `http://` included — is refused.
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
    /// unsigned repository is reached over `http://`, when a supplied name is
    /// not a portable file-name stem, or when the suite or a component is one
    /// the repository cannot be addressed by: an empty value, one carrying
    /// whitespace or a control character, or one that would resolve outside the
    /// mirror root through a leading `/`, a `..` segment, or an empty or `.`
    /// segment. Either may otherwise contain slashes, since both may name a
    /// subtree.
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

/// The mirror schemes that authenticate what they serve, and so are the ones an
/// unsigned repository may be reached through.
///
/// `file://` is a local path under the caller's own control; `https://`
/// authenticates the server the bytes came from. Nothing else does, whether it
/// is `http://` or a scheme this crate has never heard of, so nothing else may
/// carry an archive whose signature is not checked.
const AUTHENTICATED_SCHEMES: [&str; 2] = ["file", "https"];

/// Whether `url` names a transport that authenticates what it serves.
///
/// A URL naming no scheme at all is not one: the built-in fetcher and every
/// caller-supplied one address a mirror by scheme, so a bare path is a
/// misconfiguration rather than a transport with a known posture.
fn is_authenticated_transport(url: &str) -> bool {
    super::fetch::scheme_of(url).is_some_and(|scheme| {
        AUTHENTICATED_SCHEMES
            .iter()
            .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
    })
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
    fn an_unsigned_repository_on_an_unauthenticated_transport_is_refused() {
        // Only file:// and https:// authenticate what they serve. Everything
        // else is refused by name, including a scheme spelled in a case the
        // guard is not written in — URI schemes are case-insensitive, so a
        // literal `http://` comparison would let `HTTP://` name the same
        // plaintext transport and pass — and including a scheme only a
        // caller-supplied fetcher would speak.
        for mirror in [
            "http://example.invalid/debian",
            "HTTP://example.invalid/debian",
            "Http://example.invalid/debian",
            "ftp://example.invalid/debian",
            "s3://bucket/debian",
            "/srv/debs",
        ] {
            let err = Repository::builder("trixie")
                .mirror(mirror)
                .trust_unsigned(true)
                .build()
                .unwrap_err();
            assert!(matches!(err, DebianError::Config { .. }), "{mirror}");
        }
    }

    #[test]
    fn an_unsigned_repository_on_an_authenticated_transport_is_accepted() {
        for mirror in [
            "file:///srv/debs",
            "FILE:///srv/debs",
            "https://packages.example/debian",
            "HTTPS://packages.example/debian",
        ] {
            assert!(
                Repository::builder("trixie")
                    .mirror(mirror)
                    .trust_unsigned(true)
                    .build()
                    .is_ok(),
                "{mirror}",
            );
        }
    }

    #[test]
    fn an_unsigned_unauthenticated_fallback_is_refused() {
        // The transport check is per-URL: an authenticated primary does not
        // excuse a plaintext backstop.
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
