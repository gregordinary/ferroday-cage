//! Which release a verified index belongs to.
//!
//! An apk index is the signed thing, and its signature names a key rather than
//! a release. Alpine signs every release of an architecture with the same key
//! for years at a time (see [`keyring`](super::keyring)), so a signature that
//! verifies does not establish which release was delivered. Without a binding,
//! a mirror, or anyone on the path of the plain-HTTP default, could answer a
//! request for `v3.23/main` with a genuine, validly signed index of an
//! end-of-life release, or of `edge`. The Debian layer refuses the same
//! substitution through the release file's `Suite` and `Codename`.
//!
//! # What binds an index to its release
//!
//! The index's `DESCRIPTION`, which sits in the signed segment. Alpine's
//! builders write `git describe` of the aports tree the index was built from:
//!
//! ```text
//! v3.23.8-18-g133b733e65d      v3.23/main: the tag v3.23.8, 18 commits on
//! v20260805-5963-gbd6dd5c256d  edge/main: the snapshot tag v20260805
//! ```
//!
//! A stable branch forks from the development branch at its release's `.0`
//! tag, and its point releases are tagged on that branch alone. So an index of
//! a stable release describes itself by one of that release's tags, and an
//! `edge` index by a snapshot, a pre-release (`v3.25.0_rc1`), or the newest
//! release's `.0`, never by a point release. Which release is the newest is a
//! fact about the archive at the moment of the fetch, which nothing signed
//! states; [`NEWEST_RELEASE`] is the newest this version knows of, and an
//! `edge` index describing a `.0` is held to that release or a later one. That
//! is the rule [`check`] applies:
//!
//! | Requested | The description's tag must be |
//! | --- | --- |
//! | `vX.Y` | a release of `X.Y`: `vX.Y.Z`, with no pre-release suffix |
//! | `edge` | a snapshot, a pre-release, or the `.0` of [`NEWEST_RELEASE`] or of a later release |
//! | `latest-stable` | a release of any version |
//!
//! Any other release name is refused for an index Alpine signed, since Alpine
//! publishes under no other name.
//!
//! # What it cannot bind
//!
//! The description names no component, and `main` and `community` of one
//! release describe themselves alike, so one cannot be told from the other.
//! Until the development branch is next tagged, an `edge` index describes
//! itself by the newest release's `.0` tag, exactly as that release's own
//! indexes do before its first point release, so in that window the two cannot
//! be told apart either. The window this version leaves open is wider by every
//! release made since [`NEWEST_RELEASE`]: a release this version cannot know of
//! may be the newest, so its `.0` is admitted as `edge`, and so is an index of
//! that release's own from before its first point release. `latest-stable` binds
//! to some stable release and not to which.
//!
//! The rule is Alpine's builders' convention, so it applies to an index a key
//! of Alpine's verified and to no other. postmarketOS describes its indexes by
//! a timestamp, and a repository of the caller's own says whatever its signer
//! wrote; neither is bound, and an `https://` transport is what keeps a
//! substitution off the path there.

use super::{AlpineError, keyring};

/// The release the development branch is published as.
const EDGE: &str = "edge";

/// The name the archive publishes its newest stable release under as well.
const LATEST_STABLE: &str = "latest-stable";

/// The newest release Alpine had made when this version was written, as its
/// series `X.Y`.
///
/// An `edge` index describes itself by the `.0` of the newest release until the
/// development branch is next tagged, and an index of any release does so too
/// until that release's first point release. Holding an `edge` index's `.0` to
/// this release or a later one keeps an older release's index from binding as
/// `edge`. Raising it with each release narrows that window back to the newest
/// release's; left as it is, it refuses nothing an `edge` index describes
/// itself by.
const NEWEST_RELEASE: (u32, u32) = (3, 24);

/// Requires an index fetched as `release` and verified by the key named
/// `signed_by` to describe itself as that release, where Alpine signed it.
///
/// `url` names the index for the error; `description` is its `DESCRIPTION`
/// member, trimmed, or `None` where it carries none. An index a key of
/// another publisher verified passes: the rule is Alpine's builders' own
/// convention and binds nothing else.
///
/// # Errors
///
/// Returns [`AlpineError::Index`] for an index Alpine signed that carries no
/// description, one that describes another release, or one fetched under a
/// release name Alpine does not publish.
pub(super) fn check(
    url: &str,
    release: &str,
    signed_by: &str,
    description: Option<&str>,
) -> Result<(), AlpineError> {
    if !keyring::is_alpine(signed_by) {
        return Ok(());
    }
    let Some(description) = description else {
        return Err(AlpineError::index(
            url,
            format!(
                "it is signed by {signed_by} and carries no DESCRIPTION, which every index \
                 Alpine publishes names its release in, so nothing binds it to release {release}"
            ),
        ));
    };
    let tag = Tag::of(description);
    let binds = match release {
        EDGE => match tag {
            Tag::Snapshot | Tag::PreRelease { .. } => true,
            Tag::Release { series, point: "0" } => {
                series_of(series).is_some_and(|series| series >= NEWEST_RELEASE)
            }
            Tag::Release { .. } | Tag::Unknown => false,
        },
        LATEST_STABLE => matches!(tag, Tag::Release { .. }),
        _ => {
            let Some(requested) = stable(release) else {
                return Err(AlpineError::index(
                    url,
                    format!(
                        "it is signed by {signed_by} and was fetched as release {release}, which \
                         is not a name Alpine publishes a release under (vX.Y, {EDGE}, \
                         {LATEST_STABLE}), so its DESCRIPTION cannot bind it to what was asked \
                         for; name the directory above the releases as the mirror"
                    ),
                ));
            };
            matches!(tag, Tag::Release { series, .. } if series == requested)
        }
    };
    if binds {
        return Ok(());
    }
    Err(AlpineError::index(
        url,
        format!(
            "it describes itself as {description:?}, which is not an index of release {release}; \
             Alpine signs every release with the same key, so the signature alone does not say \
             which release a mirror served"
        ),
    ))
}

/// The `X.Y` of a stable release name `vX.Y`, or `None` for any other name.
fn stable(release: &str) -> Option<&str> {
    let series = release.strip_prefix('v')?;
    let (major, minor) = series.split_once('.')?;
    (is_number(major) && is_number(minor)).then_some(series)
}

/// The `(X, Y)` a series `X.Y` names, or `None` for a number past `u32`.
///
/// A [`Tag`] has already held both to digits, so this only orders them.
fn series_of(series: &str) -> Option<(u32, u32)> {
    let (major, minor) = series.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Whether `text` is a non-empty run of ASCII digits.
fn is_number(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// The aports tag a description is a `git describe` of, by the kind of tag it
/// is.
#[derive(Debug, PartialEq, Eq)]
enum Tag<'a> {
    /// A release, `vX.Y.Z`: `series` is `X.Y` and `point` is `Z`.
    Release { series: &'a str, point: &'a str },
    /// A pre-release of a release, `vX.Y.Z_rc1` or `vX.Y.Z_alpha20250612`,
    /// which the development branch alone carries.
    PreRelease { series: &'a str },
    /// A snapshot of the development branch, `v20260805`.
    Snapshot,
    /// Anything else, which no index Alpine publishes describes itself by.
    Unknown,
}

impl Tag<'_> {
    /// Reads the tag out of `description`.
    ///
    /// `git describe` writes the tag alone where the tree is exactly the tagged
    /// commit, and `<tag>-<count>-g<abbreviated hash>` otherwise. Alpine's tags
    /// carry no `-` of their own, so the tag is everything before the first
    /// one.
    fn of(description: &str) -> Tag<'_> {
        let tag = match description.split_once('-') {
            Some((tag, rest)) if is_describe_suffix(rest) => tag,
            Some(_) => return Tag::Unknown,
            None => description,
        };
        let Some(version) = tag.strip_prefix('v') else {
            return Tag::Unknown;
        };
        if is_number(version) {
            return Tag::Snapshot;
        }
        let (version, pre_release) = match version.split_once('_') {
            Some((version, suffix)) if !suffix.is_empty() => (version, true),
            Some(_) => return Tag::Unknown,
            None => (version, false),
        };
        let mut parts = version.splitn(3, '.');
        let (Some(major), Some(minor), Some(point)) = (parts.next(), parts.next(), parts.next())
        else {
            return Tag::Unknown;
        };
        if !(is_number(major) && is_number(minor) && is_number(point)) {
            return Tag::Unknown;
        }
        let series = &version[..major.len() + 1 + minor.len()];
        match pre_release {
            true => Tag::PreRelease { series },
            false => Tag::Release { series, point },
        }
    }
}

/// Whether `rest` is what `git describe` appends after a tag: a commit count, a
/// `-`, and `g` before an abbreviated hash.
fn is_describe_suffix(rest: &str) -> bool {
    let Some((count, hash)) = rest.split_once('-') else {
        return false;
    };
    let Some(hash) = hash.strip_prefix('g') else {
        return false;
    };
    is_number(count) && !hash.is_empty() && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPINE: &str = "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub";

    /// Whether an index Alpine signed, describing itself as `description`, is
    /// accepted as `release`.
    fn binds(release: &str, description: &str) -> bool {
        check("the index", release, ALPINE, Some(description)).is_ok()
    }

    #[test]
    fn a_tag_is_read_out_of_a_description() {
        assert_eq!(
            Tag::of("v3.23.8-18-g133b733e65d"),
            Tag::Release {
                series: "3.23",
                point: "8"
            },
        );
        assert_eq!(
            Tag::of("v3.24.0"),
            Tag::Release {
                series: "3.24",
                point: "0"
            },
        );
        assert_eq!(Tag::of("v20260805-5963-gbd6dd5c256d"), Tag::Snapshot);
        assert_eq!(
            Tag::of("v3.25.0_rc1-12-gabc"),
            Tag::PreRelease { series: "3.25" },
        );
        assert_eq!(
            Tag::of("v3.23.0_alpha20250612-3-g9794cca5e08"),
            Tag::PreRelease { series: "3.23" },
        );
        for unknown in [
            "",
            "2026-10-22 21:29:51.413531+00:00",
            "main v3.23.8-18-g133b733e65d",
            "v3.23",
            "v3.23.8-18",
            "v3.23.8-18-gnothex",
            "v3.23.x-1-gabc",
            "v3.23.8_",
            "3.23.8-18-g133b733e65d",
        ] {
            assert_eq!(Tag::of(unknown), Tag::Unknown, "{unknown:?}");
        }
    }

    #[test]
    fn a_stable_index_is_accepted_as_its_own_release_only() {
        // Descriptions as the archive publishes them, recorded verbatim.
        for (release, description) in [
            ("v3.0", "v3.0.6-280-g2c450b4"),
            ("v3.10", "v3.10.9-43-g3feb769ea3"),
            ("v3.14", "v3.14.10-54-gc6895df0c92"),
            ("v3.15", "v3.15.11-31-g2a2ec278a7b"),
            ("v3.22", "v3.22.7-27-g8b1db4b3cf6"),
            ("v3.23", "v3.23.8-18-g133b733e65d"),
            ("v3.24", "v3.24.4-33-g3db0a46d5ef"),
            ("v3.24", "v3.24.0"),
        ] {
            assert!(binds(release, description), "{release}: {description}");
        }
        for (release, description) in [
            // An older release, which is the substitution this exists for.
            ("v3.23", "v3.22.8-11-g2235ae248c3"),
            ("v3.23", "v3.14.10-54-gc6895df0c92"),
            // A prefix of another release's series is not that release.
            ("v3.2", "v3.23.8-18-g133b733e65d"),
            ("v3.23", "v3.2.3-474-g10ee65f"),
            // The development branch.
            ("v3.24", "v20260805-5963-gbd6dd5c256d"),
            ("v3.25", "v3.25.0_rc1-12-gabc"),
        ] {
            assert!(!binds(release, description), "{release}: {description}");
        }
    }

    #[test]
    fn edge_is_accepted_by_what_the_development_branch_is_tagged_with() {
        for description in [
            "v20260805-5963-gbd6dd5c256d",
            "v3.25.0_rc1-12-gabc",
            "v3.23.0_alpha20250612-3-g9794cca5e08",
            // The window after a release, before the next snapshot.
            "v3.24.0-1200-gabc",
            // And after a release this version cannot know of.
            "v3.25.0-31-gabc",
            "v4.0.0",
        ] {
            assert!(binds("edge", description), "{description}");
        }
        for description in [
            // A point release is tagged on its stable branch alone.
            "v3.23.8-18-g133b733e65d",
            "v3.24.1-2-gabc",
            // A release older than the newest is not the newest's window: its
            // index before its first point release is a stable index.
            "v3.23.0-40-gabc",
            "v3.10.0-43-g3feb769ea3",
            // A series past what a number holds is no release.
            "v3.99999999999.0",
        ] {
            assert!(!binds("edge", description), "{description}");
        }
        let (major, minor) = NEWEST_RELEASE;
        assert!(binds("edge", &format!("v{major}.{minor}.0")));
    }

    #[test]
    fn latest_stable_is_accepted_as_some_release() {
        assert!(binds("latest-stable", "v3.24.4-33-g3db0a46d5ef"));
        assert!(!binds("latest-stable", "v20260805-5963-gbd6dd5c256d"));
        assert!(!binds("latest-stable", "v3.25.0_rc1-12-gabc"));
    }

    #[test]
    fn an_index_alpine_signed_is_refused_without_a_description_or_a_release_name() {
        let missing = check("the index", "v3.23", ALPINE, None).expect_err("nothing binds it");
        assert!(
            matches!(&missing, AlpineError::Index { reason, .. } if reason.contains("DESCRIPTION")),
            "{missing}",
        );
        for release in ["stable", "alpine/v3.23", "v3", "v3.23.8", "3.23"] {
            let err = check(
                "the index",
                release,
                ALPINE,
                Some("v3.23.8-18-g133b733e65d"),
            )
            .expect_err("Alpine publishes no release under this name");
            assert!(
                matches!(&err, AlpineError::Index { reason, .. } if reason.contains(release)),
                "{release}: {err}",
            );
        }
    }

    #[test]
    fn a_refusal_names_the_index_what_it_describes_and_what_was_asked_for() {
        let err = check(
            "http://mirror.invalid/v3.23/main/x86_64/APKINDEX.tar.gz",
            "v3.23",
            ALPINE,
            Some("v3.22.8-11-g2235ae248c3"),
        )
        .expect_err("another release");
        let rendered = err.to_string();
        for part in ["mirror.invalid", "v3.22.8-11-g2235ae248c3", "v3.23"] {
            assert!(rendered.contains(part), "{part}: {rendered}");
        }
    }

    #[test]
    fn an_index_another_publisher_signed_is_not_bound() {
        // postmarketOS describes its indexes by a timestamp, and a repository of
        // the caller's own by whatever its signer wrote.
        for (signed_by, description) in [
            (
                "build.postmarketos.org.rsa.pub",
                Some("2026-10-22 21:29:51.413531+00:00"),
            ),
            ("build@example.com-64f0c0a1.rsa.pub", Some("main v3.23.8")),
            ("build@example.com-64f0c0a1.rsa.pub", None),
        ] {
            for release in ["v26.06", "v3.23", "edge", "anything"] {
                assert!(
                    check("the index", release, signed_by, description).is_ok(),
                    "{signed_by} as {release}",
                );
            }
        }
    }
}
