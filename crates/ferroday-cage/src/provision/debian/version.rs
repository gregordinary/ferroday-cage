//! Debian package version comparison.
//!
//! Implements dpkg's algorithm (Debian Policy 5.6.12, `lib/dpkg/version.c`):
//! a version is `[epoch:]upstream[-revision]`, compared field by field, with
//! each field compared in alternating non-digit and digit runs. The one
//! subtlety worth stating is the character ordering: `~` sorts before
//! everything, including the end of a string, so `1.0~rc1` precedes `1.0`.
//!
//! Only comparison is needed, and only to keep the highest version when the
//! same package name appears more than once across an index.

use std::cmp::Ordering;

/// Compares two Debian version strings.
pub(crate) fn compare(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = split(a);
    let (eb, ub, rb) = split(b);
    ea.cmp(&eb)
        .then_with(|| verrevcmp(ua, ub))
        .then_with(|| verrevcmp(ra, rb))
}

/// Splits a version into `(epoch, upstream, revision)`.
///
/// A missing epoch is 0; a missing revision is empty. The upstream/revision
/// boundary is the last hyphen.
fn split(version: &str) -> (u64, &str, &str) {
    let (epoch, rest) = match version.find(':') {
        Some(colon) if colon > 0 && version[..colon].bytes().all(|b| b.is_ascii_digit()) => {
            // The field is all digits, so a parse failure is an overflow of a
            // pathologically large epoch. Saturate to the maximum: such an
            // epoch sorts above every real one, the correct direction, where
            // mapping it to 0 would wrongly sort it below.
            (
                version[..colon].parse().unwrap_or(u64::MAX),
                &version[colon + 1..],
            )
        }
        _ => (0, version),
    };
    match rest.rfind('-') {
        Some(hyphen) => (epoch, &rest[..hyphen], &rest[hyphen + 1..]),
        None => (epoch, rest, ""),
    }
}

/// Compares one version field (upstream or revision) by dpkg's rule.
fn verrevcmp(a: &str, b: &str) -> Ordering {
    let a = a.as_bytes();
    let b = b.as_bytes();
    // A byte past the end reads as 0, dpkg's NUL terminator, which `order`
    // weights the same as a digit position and below every real character
    // except `~`.
    let at = |i: usize| a.get(i).copied().unwrap_or(0);
    let bt = |j: usize| b.get(j).copied().unwrap_or(0);
    let (mut i, mut j) = (0, 0);

    while i < a.len() || j < b.len() {
        // Compare the leading non-digit run character by character.
        while (at(i) != 0 && !at(i).is_ascii_digit()) || (bt(j) != 0 && !bt(j).is_ascii_digit()) {
            let ac = order(at(i));
            let bc = order(bt(j));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }

        // Then the leading digit run, numerically, ignoring leading zeros.
        while at(i) == b'0' {
            i += 1;
        }
        while bt(j) == b'0' {
            j += 1;
        }
        let mut first_diff: i32 = 0;
        while at(i).is_ascii_digit() && bt(j).is_ascii_digit() {
            if first_diff == 0 {
                first_diff = i32::from(at(i)) - i32::from(bt(j));
            }
            i += 1;
            j += 1;
        }
        // The longer run of digits is the larger number.
        if at(i).is_ascii_digit() {
            return Ordering::Greater;
        }
        if bt(j).is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }
    Ordering::Equal
}

/// The sort weight of a version character: `~` below everything (including
/// the end of a string, weight 0), digits at 0, letters at their code, and
/// every other character above the letters.
fn order(c: u8) -> i32 {
    if c.is_ascii_digit() {
        0
    } else if c.is_ascii_alphabetic() {
        i32::from(c)
    } else if c == b'~' {
        -1
    } else if c != 0 {
        i32::from(c) + 256
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lt(a: &str, b: &str) {
        assert_eq!(compare(a, b), Ordering::Less, "{a} < {b}");
        assert_eq!(compare(b, a), Ordering::Greater, "{b} > {a}");
    }

    fn eq(a: &str, b: &str) {
        assert_eq!(compare(a, b), Ordering::Equal, "{a} == {b}");
    }

    #[test]
    fn equal_versions() {
        eq("1.0", "1.0");
        eq("2.41-5", "2.41-5");
        // Leading zeros are numerically insignificant.
        eq("0", "00");
        eq("1.0-00", "1.00-0");
    }

    #[test]
    fn epoch_dominates() {
        lt("1:0", "2:0");
        // A larger epoch beats a larger upstream.
        lt("1:9.9", "2:1.0");
        eq("0:1.0", "1.0");
    }

    #[test]
    fn an_overflowing_epoch_saturates_high() {
        // An all-digit epoch too large for u64 saturates to the maximum, so it
        // sorts above a normal epoch rather than below it (as mapping to 0
        // would have).
        let huge = "99999999999999999999999999:1.0";
        lt("9:1.0", huge);
        lt("1.0", huge);
    }

    #[test]
    fn tilde_sorts_before_everything() {
        lt("1.0~rc1", "1.0");
        lt("1.0~~", "1.0~");
        lt("1.0~rc1", "1.0~rc2");
        lt("1.0~beta", "1.0");
    }

    #[test]
    fn numeric_and_lexical_runs() {
        lt("1.0.0", "1.0.1");
        lt("1.0", "1.0.0");
        lt("1.9", "1.10");
        lt("a", "b");
        // Letters sort before non-letter punctuation like `.` and `+`.
        lt("1.0a", "1.0.");
    }

    #[test]
    fn real_archive_versions() {
        lt("2.41-4", "2.41-5");
        lt("1.22.21", "1.22.22");
        lt("5.2.37-2+b9", "5.2.37-2+b10");
        lt("9.7-3", "9.7-3+deb13u1");
    }
}
