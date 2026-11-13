//! The release document: what an archive publishes about a suite, and the
//! digests every fetch below it is held to.
//!
//! Authenticity rests on the OpenPGP signature over the `InRelease` file, which
//! [`openpgp`](crate::provision::openpgp) establishes; this module reads what
//! that signature covered. The body names the suite, the architectures and
//! components on offer, a deadline, and the SHA-256 digest of every index — so
//! every fetch below the release is checked against a digest that chains back to
//! the signature.

use std::borrow::Cow;
use std::collections::HashMap;

use crate::provision::digest::Algorithm;
use crate::provision::{document, now_epoch};

/// Why a release cannot be used: it is malformed, expired, or does not offer
/// what was asked.
///
/// A reason rather than an error, because the subject is the caller's: the
/// URL the release was fetched from, which this module never sees. The caller
/// reports it as [`DebianError::Release`](super::DebianError::Release) naming
/// that URL.
pub(crate) type Refusal = String;

/// How a release's versions rank against another release's when a resolution
/// picks one version of a name: the default pin priority apt gives the release,
/// as `apt_preferences(5)` states it.
///
/// The order is the rank's. A version from a higher-ranked release is taken
/// over one from a lower-ranked release whatever the two versions are, and the
/// higher version wins only between releases of one rank. A release marks its
/// own rank, with `NotAutomatic` and `ButAutomaticUpgrades`, so a repository
/// added to reach a few packages does not replace everything else it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ReleasePriority {
    /// `NotAutomatic: yes` alone, as `experimental` is marked: apt's
    /// priority of 1. Its version of a name is taken only where no other
    /// release offers the name, and never in place of a version the base has
    /// installed.
    NotAutomatic,
    /// `NotAutomatic: yes` and `ButAutomaticUpgrades: yes`, as a backports
    /// suite is marked: apt's priority 100. An installed version stands at
    /// this rank too, so such a release upgrades a package it supplied itself
    /// and no package a default release supplied.
    AutomaticUpgrades,
    /// Every other release: apt's priority 500.
    Default,
}

/// A parsed `Release` body: the index digests and the release's own claims.
pub(crate) struct Release {
    /// Index path (relative to `dists/<suite>/`) to `(size, sha256)`.
    hashes: HashMap<String, (u64, String)>,
    acquire_by_hash: bool,
    /// How the release ranks its versions, from its `NotAutomatic` and
    /// `ButAutomaticUpgrades` fields.
    priority: ReleasePriority,
    architectures: Vec<String>,
    components: Vec<String>,
    valid_until: Option<String>,
    /// The release's own `Date:` field, as written. Read for provenance rather
    /// than for any check: freshness is judged against `Valid-Until`.
    date: Option<String>,
    /// The release's own `Suite:` field (for example `stable`), if present.
    suite: Option<String>,
    /// The release's own `Codename:` field (for example `trixie`), if present.
    codename: Option<String>,
    /// The SHA-256 of the body this was parsed from, lowercase hex.
    ///
    /// Computed here rather than by the caller so it is unambiguously the
    /// digest of the bytes that were verified: for a signed repository that is
    /// the cleartext the signature covers, not the `InRelease` armor around it
    /// and not a re-fetch.
    sha256: String,
}

impl Release {
    /// Parses a release body (the verified `InRelease` text, or a trusted
    /// `Release`).
    pub(crate) fn parse(body: &str) -> Result<Release, Refusal> {
        let stanza = document::parse(body)
            .next()
            .ok_or_else(|| "the release file is empty".to_string())?;

        // A line the reader cannot use is dropped rather than failing the
        // release: a real archive's list names files this crate never asks for
        // — `Contents-amd64.gz`, the translation catalogues — and one of those
        // being unreadable is no reason to refuse the suite. An index the
        // bootstrap does want then goes missing, which is reported where it is
        // asked for.
        //
        // The digest is checked for shape as well as presence, because it is
        // not only compared: where the release declares `Acquire-By-Hash` it
        // becomes a path segment of the URL the index is fetched from. Anything
        // but 64 lowercase hex characters could climb out of the mirror root
        // there, and for a repository trusted unsigned nothing has vouched for
        // the text at all.
        let mut hashes = HashMap::new();
        if let Some(list) = stanza.get("SHA256") {
            for line in list.lines() {
                let mut fields = line.split_whitespace();
                if let (Some(digest), Some(size), Some(path)) =
                    (fields.next(), fields.next(), fields.next())
                    && Algorithm::Sha256.is_hex(digest)
                    && let Ok(size) = size.parse()
                {
                    hashes.insert(path.to_string(), (size, digest.to_string()));
                }
            }
        }

        let marked = |field: &str| {
            stanza
                .get(field)
                .is_some_and(|value| value.eq_ignore_ascii_case("yes"))
        };
        // `ButAutomaticUpgrades` qualifies `NotAutomatic` and means nothing on
        // its own: a release that is not marked lower stays at the default.
        let priority = match (marked("NotAutomatic"), marked("ButAutomaticUpgrades")) {
            (true, true) => ReleasePriority::AutomaticUpgrades,
            (true, false) => ReleasePriority::NotAutomatic,
            (false, _) => ReleasePriority::Default,
        };
        Ok(Release {
            hashes,
            acquire_by_hash: marked("Acquire-By-Hash"),
            priority,
            architectures: split_ws(stanza.get("Architectures").as_deref()),
            components: split_ws(stanza.get("Components").as_deref()),
            valid_until: stanza.get("Valid-Until").map(Cow::into_owned),
            date: stanza.get("Date").map(|value| value.trim().to_string()),
            suite: stanza.get("Suite").map(|value| value.trim().to_string()),
            codename: stanza.get("Codename").map(|value| value.trim().to_string()),
            sha256: Algorithm::Sha256.hex_of(body.as_bytes()),
        })
    }

    /// The release's `Date` field, as written.
    pub(crate) fn date(&self) -> Option<&str> {
        self.date.as_deref()
    }

    /// The release's `Valid-Until` field, as written.
    pub(crate) fn valid_until(&self) -> Option<&str> {
        self.valid_until.as_deref()
    }

    /// The SHA-256 of the verified body, lowercase hex.
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    /// How the release ranks its versions against another release's.
    pub(crate) fn priority(&self) -> ReleasePriority {
        self.priority
    }

    /// Checks that the release binds to the requested `suite`, offers
    /// `architecture` and every requested component, and — when
    /// `require_valid_until` is set — carries a parseable `Valid-Until` that
    /// has not passed.
    ///
    /// A release that lists no architectures, or no components, makes no claim
    /// about them, and is read as offering every one, as apt reads it.
    /// `apt-ftparchive release` writes neither field unless it is configured
    /// to, so a local archive whose release states only its codename lists
    /// neither. None of this widens what is fetched: an index is read only
    /// where the release lists its digest, and one it does not list is refused
    /// where it is asked for.
    pub(crate) fn check(
        &self,
        suite: &str,
        architecture: &str,
        components: &[String],
        require_valid_until: bool,
    ) -> Result<(), Refusal> {
        self.check_suite(suite)?;
        if !self.offers_architecture(architecture) {
            return Err(format!(
                "the suite does not offer architecture {architecture} (offers {})",
                self.architectures.join(", "),
            ));
        }
        for component in components {
            if !self.offers_component(component) {
                return Err(format!(
                    "the suite does not offer component {component} (offers {})",
                    self.components.join(", "),
                ));
            }
        }
        self.check_freshness(require_valid_until)?;
        Ok(())
    }

    /// Whether the release offers `architecture`: one it lists, or any where it
    /// lists none.
    fn offers_architecture(&self, architecture: &str) -> bool {
        self.architectures.is_empty()
            || self
                .architectures
                .iter()
                .any(|offered| offered == architecture)
    }

    /// Whether the release offers `component`: one it lists, or any where it
    /// lists none.
    ///
    /// A listed component is offered under its own name and, where it carries
    /// a `/`, under the part after the last one, as apt reads the field in
    /// `debReleaseIndex::Load`. The Debian security archive is the case this
    /// exists for: its release lists `updates/main`, its indexes are hashed
    /// under `main/`, and every Debian system names it `main` in its sources.
    fn offers_component(&self, component: &str) -> bool {
        self.components.is_empty()
            || self.components.iter().any(|offered| {
                offered == component
                    || offered
                        .rsplit_once('/')
                        .is_some_and(|(_, last)| last == component)
            })
    }

    /// Requires the release's own `Suite:` or `Codename:` to equal the
    /// requested suite.
    ///
    /// A single archive key signs the release of every Debian suite, so the
    /// signature alone does not establish which suite was delivered. Without
    /// this binding a mirror (or a man-in-the-middle on the default plaintext
    /// transport) could answer a request for one suite with a genuine,
    /// validly-signed release for another — a silent cross-suite or downgrade
    /// substitution. This is the binding `debootstrap` and `apt` enforce.
    fn check_suite(&self, requested: &str) -> Result<(), Refusal> {
        let identifies_as = |field: &Option<String>| field.as_deref() == Some(requested);
        if identifies_as(&self.suite) || identifies_as(&self.codename) {
            return Ok(());
        }
        let stated = |field: &Option<String>| {
            field
                .as_deref()
                .map_or_else(|| "absent".to_string(), |value| format!("{value:?}"))
        };
        Err(format!(
            "the release does not identify as suite {requested} (its Suite is {}, its Codename is {})",
            stated(&self.suite),
            stated(&self.codename),
        ))
    }

    /// Enforces release freshness when `require_valid_until` is set: a
    /// `Valid-Until` the release carries must be parseable and not in the
    /// past.
    ///
    /// A present field is enforced strictly — an unparseable value is a hard
    /// failure rather than a silent skip, and a passed deadline is a rejection
    /// — so a stale (but validly-signed) release cannot be replayed to deliver
    /// superseded, potentially vulnerable packages, and a format quirk cannot
    /// quietly disable the check. A clock before the epoch cannot evaluate the
    /// deadline, and the release is rejected rather than trusted blind. Only a
    /// signed release is held to a deadline, and verifying its signature
    /// already refuses such a clock, so in a bootstrap that branch is never
    /// reached. It stays because this check's answer should not depend on what
    /// its caller happened to check first.
    ///
    /// An *absent* `Valid-Until` is accepted, as `apt` accepts it: the Debian
    /// stable suite deliberately omits the field so its release does not expire
    /// between point releases, and rejecting that would break bootstrapping
    /// stable. Such a release simply carries no freshness bound. The caller
    /// relaxes the check entirely on a trusted local mirror, or when
    /// deliberately pinning a historical snapshot whose deadline has passed.
    fn check_freshness(&self, require_valid_until: bool) -> Result<(), Refusal> {
        if !require_valid_until {
            return Ok(());
        }
        let Some(valid_until) = self.valid_until.as_deref() else {
            return Ok(());
        };
        let deadline = parse_rfc5322(valid_until)
            .ok_or_else(|| format!("the release Valid-Until {valid_until:?} is unparseable"))?;
        let now = now_epoch().ok_or_else(|| {
            "the system clock is before the Unix epoch, so release freshness cannot be \
             established"
                .to_string()
        })?;
        if now > deadline {
            return Err(format!("the release expired at {valid_until}"));
        }
        Ok(())
    }

    /// The `(size, sha256)` recorded for an index path, if any.
    pub(crate) fn digest(&self, path: &str) -> Option<(u64, &str)> {
        self.hashes
            .get(path)
            .map(|(size, digest)| (*size, digest.as_str()))
    }

    /// Whether the archive publishes indexes under `by-hash/SHA256/<digest>`.
    pub(crate) fn acquire_by_hash(&self) -> bool {
        self.acquire_by_hash
    }
}

/// Splits a whitespace-separated field into owned tokens.
fn split_ws(value: Option<&str>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(str::split_whitespace)
        .map(str::to_string)
        .collect()
}

/// Parses an RFC 5322 date (`Sat, 11 Jul 2026 09:02:23 UTC`) to a Unix
/// timestamp.
///
/// The trailing zone is honored: the Debian archive stamps `UTC`, but a
/// numeric offset such as `+0000` or `-0500` is applied so a format change
/// does not misread the time by the offset. A value that does not parse —
/// including one with an unrecognized zone — returns `None`, which the
/// caller treats as a freshness failure rather than a silent pass.
///
/// Reading is deliberately lenient about shape where the shape cannot change
/// which instant is named: field widths are not enforced, a signed day such as
/// `+11` is accepted, and anything following the zone is ignored. Every field is
/// still range-checked, so leniency about spelling never becomes leniency about
/// the deadline: a value this accepts names exactly one instant.
pub(super) fn parse_rfc5322(text: &str) -> Option<i64> {
    let mut fields = text.split_whitespace();
    // Optional "Dow," leader.
    let mut first = fields.next()?;
    if first.ends_with(',') {
        first = fields.next()?;
    }
    let day: i64 = first.parse().ok()?;
    let month = match fields.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = fields.next()?.parse().ok()?;
    let mut time = fields.next()?.split(':');
    let hour: i64 = time.next()?.parse().ok()?;
    let minute: i64 = time.next()?.parse().ok()?;
    let second: i64 = time.next().unwrap_or("0").parse().ok()?;
    // The civil-date arithmetic below is happy to roll an out-of-range field
    // over — `32 Jan` would land in February — which would read a malformed
    // deadline as a slightly wrong one instead of the documented hard failure.
    // A leap second is the one deliberate tolerance, since a stamp may carry
    // `:60`.
    if !(1..=days_in_month(year, month)).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        // A stamp may carry a leap second, so 60 is the ceiling here.
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let offset = parse_zone(fields.next()?)?;
    // Checked throughout: an absurd year, hour, or minute overflows to `None`,
    // which the caller treats as a freshness failure rather than a wrapped,
    // bogus deadline.
    let local = days_from_civil(year, month, day)?
        .checked_mul(86400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    // The parsed fields name a wall-clock time in the given zone; subtract the
    // zone's offset from UTC to reach the Unix timestamp.
    local.checked_sub(offset)
}

/// Parses an RFC 5322 zone into its offset from UTC in seconds. Handles the
/// `UTC`/`GMT`/`UT`/`Z` forms and a numeric `+HHMM`/`-HHMM` offset; any other
/// token is unrecognized and returns `None`.
fn parse_zone(token: &str) -> Option<i64> {
    match token {
        "UTC" | "GMT" | "UT" | "Z" => Some(0),
        _ => {
            let bytes = token.as_bytes();
            if bytes.len() != 5 {
                return None;
            }
            let sign = match bytes[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let hours: i64 = token.get(1..3)?.parse().ok()?;
            let minutes: i64 = token.get(3..5)?.parse().ok()?;
            if hours >= 24 || minutes >= 60 {
                return None;
            }
            Some(sign * (hours * 3600 + minutes * 60))
        }
    }
}

/// Formats a Unix timestamp as the RFC 5322 date a `Release` stamps, for
/// example `Sat, 11 Jul 2026 09:02:23 UTC`.
///
/// The zone is spelled `UTC` rather than `+0000`, which is what the Debian
/// archive stamps and what every client that reads one therefore accepts;
/// [`parse_rfc5322`] reads either. The result round-trips through it.
///
/// Every timestamp formats, including one before the epoch: the field records
/// when a pool was published rather than gating anything, so an odd clock
/// yields an odd date instead of failing the publish that carries it.
pub(super) fn format_rfc5322(epoch: i64) -> String {
    // Floored division throughout, so a pre-epoch timestamp borrows into the
    // previous day rather than truncating toward zero into the next one.
    let days = epoch.div_euclid(86400);
    let seconds = epoch.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday, the fourth day of a week starting Sunday.
    let weekday =
        ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][(days + 4).rem_euclid(7) as usize];
    let month_name = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(month - 1) as usize];
    format!(
        "{weekday}, {day:02} {month_name} {year:04} {:02}:{:02}:{:02} UTC",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60,
    )
}

/// The civil date for a count of days since the Unix epoch (Howard Hinnant's
/// algorithm), the inverse of [`days_from_civil`].
///
/// Total where its inverse is checked: the input is a day count derived from a
/// timestamp rather than parsed from a document, so there is no absurd year to
/// reject, and the arithmetic cannot overflow for any `i64` a clock produces.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719468;
    let era = shifted.div_euclid(146097);
    let day_of_era = shifted.rem_euclid(146097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    // The algorithm counts years from March, so January and February belong to
    // the following civil year.
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The number of days in `month` of `year`, for bounding a parsed date. The
/// Gregorian leap rule applies, so February is 29 days only in a leap year.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            if leap { 29 } else { 28 }
        }
    }
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's algorithm), the
/// inverse of [`civil_from_days`], or `None` if the arithmetic overflows for an
/// absurd year — treated by the caller as an unparseable, and therefore stale,
/// date.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let year = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = if year >= 0 {
        year
    } else {
        year.checked_sub(399)?
    } / 400;
    let year_of_era = year.checked_sub(era.checked_mul(400)?)?;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = ((153 * month_index + 2) / 5)
        .checked_add(day)?
        .checked_sub(1)?;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era / 4)?
        .checked_sub(year_of_era / 100)?
        .checked_add(day_of_year)?;
    era.checked_mul(146097)?
        .checked_add(day_of_era)?
        .checked_sub(719468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_parses_hashes_and_claims() {
        let plain = "a".repeat(64);
        let compressed = "b".repeat(64);
        let body = format!(
            "\
Suite: stable
Codename: trixie
Architectures: all amd64 arm64
Components: main contrib
Acquire-By-Hash: yes
SHA256:
 {plain} 111 main/binary-amd64/Packages
 {compressed} 222 main/binary-amd64/Packages.xz
 not-a-digest 333 main/binary-amd64/Packages.gz
 ../../../../etc/passwd 444 main/binary-arm64/Packages
",
        );
        let release = Release::parse(&body).unwrap();
        assert!(release.acquire_by_hash());
        assert_eq!(
            release.digest("main/binary-amd64/Packages.xz"),
            Some((222, compressed.as_str())),
        );
        // A digest that is not 64 lowercase hex characters is dropped rather
        // than carried: where the release declares Acquire-By-Hash it becomes a
        // path segment of the URL its index is fetched from, and for a
        // repository trusted unsigned nothing has vouched for the text. The
        // index then reads as absent, which is reported where it is asked for.
        assert_eq!(release.digest("main/binary-amd64/Packages.gz"), None);
        assert_eq!(release.digest("main/binary-arm64/Packages"), None);
        // The requested suite may match either the Suite or the Codename.
        release
            .check("stable", "amd64", &["main".to_string()], false)
            .unwrap();
        release
            .check("trixie", "amd64", &["main".to_string()], false)
            .unwrap();
        assert!(release.check("stable", "riscv64", &[], false).is_err());
        assert!(
            release
                .check("stable", "amd64", &["nonfree".to_string()], false)
                .is_err()
        );
    }

    #[test]
    fn a_release_ranks_itself_by_its_automatic_fields() {
        let rank = |fields: &str| {
            Release::parse(&format!("Suite: x\n{fields}"))
                .unwrap()
                .priority()
        };
        assert_eq!(rank(""), ReleasePriority::Default);
        // experimental's marking.
        assert_eq!(rank("NotAutomatic: yes\n"), ReleasePriority::NotAutomatic);
        // A backports suite's marking.
        assert_eq!(
            rank("NotAutomatic: yes\nButAutomaticUpgrades: yes\n"),
            ReleasePriority::AutomaticUpgrades,
        );
        // The qualifier alone, and a value other than yes, leave the default.
        assert_eq!(
            rank("ButAutomaticUpgrades: yes\n"),
            ReleasePriority::Default
        );
        assert_eq!(rank("NotAutomatic: no\n"), ReleasePriority::Default);
        assert_eq!(rank("NotAutomatic: Yes\n"), ReleasePriority::NotAutomatic);
        // The ranks order as apt's priorities do: 1, 100, 500.
        assert!(ReleasePriority::NotAutomatic < ReleasePriority::AutomaticUpgrades);
        assert!(ReleasePriority::AutomaticUpgrades < ReleasePriority::Default);
    }

    #[test]
    fn a_prefixed_component_is_offered_under_its_last_segment() {
        // The Debian security archive's release, as served: the components are
        // listed with an `updates/` prefix, and the indexes are hashed without
        // one. apt accepts `main` here, and so must the provisioner.
        let body = "\
Suite: testing-security
Codename: forky-security
Architectures: amd64 arm64
Components: updates/main updates/contrib updates/non-free-firmware updates/non-free
";
        let release = Release::parse(body).unwrap();
        let wanted = ["main", "contrib", "non-free", "non-free-firmware"].map(String::from);
        release
            .check("forky-security", "arm64", &wanted, false)
            .expect("each component is offered under its last segment");
        // The listed spelling is still offered as written.
        release
            .check(
                "forky-security",
                "arm64",
                &["updates/main".to_string()],
                false,
            )
            .expect("the advertised spelling is offered too");
        // A suffix that merely ends the same way is not the segment.
        let err = release
            .check("forky-security", "arm64", &["ain".to_string()], false)
            .unwrap_err();
        assert!(err.contains("does not offer component ain"), "{err}");
        // And an unprefixed component a release does not list stays refused.
        let err = release
            .check(
                "forky-security",
                "arm64",
                &["restricted".to_string()],
                false,
            )
            .unwrap_err();
        assert!(
            err.contains("offers updates/main, updates/contrib"),
            "the refusal quotes the release's own spelling: {err}"
        );
    }

    #[test]
    fn a_release_listing_no_architectures_or_components_offers_every_one() {
        // A release naming only its codename, as `apt-ftparchive release`
        // writes one configured with nothing else.
        let release = Release::parse("Codename: local\n").unwrap();
        let wanted = ["main", "contrib"].map(String::from);
        release
            .check("local", "arm64", &wanted, false)
            .expect("a release listing neither field offers every one");
        // A listed field is a claim, and what it does not name stays refused.
        let release = Release::parse("Codename: local\nArchitectures: amd64\n").unwrap();
        let err = release.check("local", "arm64", &wanted, false).unwrap_err();
        assert!(
            err.contains("does not offer architecture arm64 (offers amd64)"),
            "{err}"
        );
        let release = Release::parse("Codename: local\nComponents: main\n").unwrap();
        let err = release.check("local", "arm64", &wanted, false).unwrap_err();
        assert!(
            err.contains("does not offer component contrib (offers main)"),
            "{err}"
        );
    }

    #[test]
    fn a_release_for_the_wrong_suite_is_rejected() {
        // A genuine, well-formed release whose Suite and Codename are both a
        // different suite than requested is refused: a single archive key
        // signs every suite, so only this binding stops a cross-suite swap.
        let body = "\
Suite: oldstable
Codename: bookworm
Architectures: amd64
Components: main
";
        let release = Release::parse(body).unwrap();
        let err = release
            .check("trixie", "amd64", &["main".to_string()], false)
            .unwrap_err();
        assert!(err.contains("does not identify as suite trixie"), "{err}");
        // The matching suite passes the same check.
        release
            .check("bookworm", "amd64", &["main".to_string()], false)
            .unwrap();
    }

    #[test]
    fn a_release_without_a_suite_identity_is_rejected() {
        // A release that names neither Suite nor Codename cannot be bound to
        // the request, so it is refused rather than trusted.
        let body = "\
Architectures: amd64
Components: main
";
        let release = Release::parse(body).unwrap();
        assert!(
            release
                .check("trixie", "amd64", &["main".to_string()], false)
                .is_err()
        );
    }

    #[test]
    fn civil_dates_match_known_epochs() {
        // 1970-01-01 and 2000-01-01.
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2000, 1, 1), Some(10957));
        // 2026-07-11 09:02:23 UTC.
        assert_eq!(
            parse_rfc5322("Sat, 11 Jul 2026 09:02:23 UTC"),
            Some(1_783_760_543)
        );
        // A leading day-of-week is optional.
        assert_eq!(
            parse_rfc5322("11 Jul 2026 09:02:23 GMT"),
            Some(1_783_760_543)
        );
        assert_eq!(parse_rfc5322("not a date"), None);
    }

    #[test]
    fn formatting_names_the_instant_the_parser_reads_back() {
        // The dates a pool stamps, spelled the way the Debian archive spells
        // them. The cases are the ones the civil-date arithmetic can get wrong:
        // the epoch itself, a leap day, the day after a century that is not a
        // leap year, and a pre-epoch instant, where flooring toward the
        // previous day is what keeps the time of day from running backwards.
        for (epoch, text) in [
            (0, "Thu, 01 Jan 1970 00:00:00 UTC"),
            (1_709_210_096, "Thu, 29 Feb 2024 12:34:56 UTC"),
            (4_107_542_400, "Mon, 01 Mar 2100 00:00:00 UTC"),
            (-1, "Wed, 31 Dec 1969 23:59:59 UTC"),
            (1_783_760_543, "Sat, 11 Jul 2026 09:02:23 UTC"),
        ] {
            assert_eq!(format_rfc5322(epoch), text);
            // The pair is a round trip: what the writer stamps is what the
            // reader — this crate's own, and apt's — resolves back to.
            assert_eq!(parse_rfc5322(text), Some(epoch));
        }
        // The date is caller-supplied, so the extremes are reachable. Dividing
        // to days bounds every intermediate well inside i64, and each formats
        // rather than overflowing one — however absurd the year it names.
        for extreme in [i64::MIN, i64::MAX] {
            assert!(format_rfc5322(extreme).ends_with(" UTC"));
        }
    }

    #[test]
    fn every_civil_date_round_trips_through_both_directions() {
        // A day-by-day sweep either side of the epoch, across the 2024 leap
        // day, and across 2100 — a century that is not a leap year. Those are
        // where an off-by-one in either direction of the conversion shows up
        // and a spot check does not.
        let spans = [-400..400, 19_650..20_150, 47_300..47_800];
        for day in spans.into_iter().flatten() {
            let epoch = day * 86400 + 3661;
            let (year, month, date) = civil_from_days(day);
            assert_eq!(days_from_civil(year, month, date), Some(day));
            assert_eq!(parse_rfc5322(&format_rfc5322(epoch)), Some(epoch));
        }
    }

    #[test]
    fn an_absurd_year_does_not_overflow() {
        // A year large enough to overflow the day arithmetic parses to None
        // rather than panicking or wrapping to a bogus deadline.
        assert_eq!(days_from_civil(i64::MAX, 7, 11), None);
        // A 19-digit year within i64's range parses, then overflows the day
        // arithmetic; the checked path returns None rather than wrapping.
        assert_eq!(parse_rfc5322("11 Jul 9000000000000000000 UTC"), None);
    }

    #[test]
    fn an_out_of_range_field_does_not_roll_over() {
        // The civil-date arithmetic would happily read `32 Jan` as 1 February
        // and `25:00` as the next day, turning a malformed Valid-Until into a
        // deadline that is merely wrong. A malformed stamp is a freshness
        // failure instead.
        for text in [
            "32 Jan 2026 09:02:23 UTC",
            "0 Jan 2026 09:02:23 UTC",
            "30 Feb 2026 09:02:23 UTC",
            "29 Feb 2026 09:02:23 UTC",
            "31 Apr 2026 09:02:23 UTC",
            "11 Jul 2026 24:02:23 UTC",
            "11 Jul 2026 09:60:23 UTC",
            "11 Jul 2026 09:02:61 UTC",
            "11 Jul 2026 09:02:23 +2400",
        ] {
            assert_eq!(parse_rfc5322(text), None, "{text}");
        }
        // The boundaries that are legal stay legal: a leap day in a leap year,
        // and the leap second a stamp may carry.
        assert!(parse_rfc5322("29 Feb 2028 09:02:23 UTC").is_some());
        assert!(parse_rfc5322("31 Dec 2026 23:59:60 UTC").is_some());
    }

    #[test]
    fn rfc5322_applies_the_zone_offset() {
        // A numeric +0000 offset is the same instant as UTC.
        assert_eq!(
            parse_rfc5322("Sat, 11 Jul 2026 09:02:23 +0000"),
            Some(1_783_760_543)
        );
        // A positive offset names an earlier UTC instant, a negative one a
        // later instant, each by the offset.
        assert_eq!(
            parse_rfc5322("Sat, 11 Jul 2026 09:02:23 +0100"),
            Some(1_783_760_543 - 3600)
        );
        assert_eq!(
            parse_rfc5322("Sat, 11 Jul 2026 09:02:23 -0530"),
            Some(1_783_760_543 + 5 * 3600 + 30 * 60)
        );
        // A missing or unrecognized zone does not parse, so freshness fails
        // loudly rather than silently reading the time as UTC.
        assert_eq!(parse_rfc5322("11 Jul 2026 09:02:23"), None);
        assert_eq!(parse_rfc5322("11 Jul 2026 09:02:23 EST"), None);
    }

    #[test]
    fn an_expired_release_is_rejected_when_freshness_is_required() {
        let body = "\
Suite: trixie
Architectures: amd64
Components: main
Valid-Until: Mon, 01 Jan 1990 00:00:00 UTC
";
        let release = Release::parse(body).unwrap();
        let err = release
            .check("trixie", "amd64", &["main".to_string()], true)
            .unwrap_err();
        assert!(err.contains("expired"), "{err}");
        // The same stale release is accepted when freshness is not required
        // (a trusted local mirror, or a deliberately pinned snapshot).
        release
            .check("trixie", "amd64", &["main".to_string()], false)
            .unwrap();
    }

    #[test]
    fn a_missing_valid_until_is_accepted() {
        // The Debian stable suite omits Valid-Until so its release does not
        // expire between point releases; an absent field is accepted (it
        // carries no freshness bound), even on the required path, as apt
        // accepts it. Only a present field is enforced.
        let body = "\
Suite: trixie
Architectures: amd64
Components: main
";
        let release = Release::parse(body).unwrap();
        release
            .check("trixie", "amd64", &["main".to_string()], true)
            .unwrap();
    }

    #[test]
    fn an_unparseable_valid_until_is_rejected_when_freshness_is_required() {
        let body = "\
Suite: trixie
Architectures: amd64
Components: main
Valid-Until: sometime next week
";
        let release = Release::parse(body).unwrap();
        assert!(
            release
                .check("trixie", "amd64", &["main".to_string()], true)
                .is_err()
        );
    }
}
