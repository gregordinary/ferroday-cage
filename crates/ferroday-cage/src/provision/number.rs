//! A number as a file format or an archive spells one: a run of ASCII digits
//! and nothing else.
//!
//! Rust's integer parsers also accept a leading `+`, and a `-` for a signed
//! type, which none of the formats this crate reads spells a number with: a
//! tar header's pax records, an HTTP response's framing, an index's sizes, a
//! version's numeric components, an account's id. A reader more lenient than
//! the format is one that reads the same bytes differently from the tools that
//! wrote them, and where the number is framing, deciding where the next record
//! or the body ends, two readers that disagree read two different documents.
//! So a number is read here, and not through `str::parse` directly.

use std::str::FromStr;

/// Whether `text` is a non-empty run of ASCII digits.
pub(crate) fn is_digits(text: impl AsRef<[u8]>) -> bool {
    let text = text.as_ref();
    !text.is_empty() && text.iter().all(u8::is_ascii_digit)
}

/// `text` as a decimal number of type `T`, where it is a non-empty run of
/// ASCII digits and nothing else; `None` otherwise, a value past `T`'s range
/// included.
pub(crate) fn digits<T: FromStr>(text: impl AsRef<[u8]>) -> Option<T> {
    let text = text.as_ref();
    if !is_digits(text) {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// `text` as a number in `radix`, where it is a non-empty run of that radix's
/// digits, either case for a letter one, and nothing else.
///
/// For HTTP's framing, whose chunk size is hexadecimal (`1*HEXDIG`); every
/// other number this crate reads is decimal, and [`digits`] reads it.
#[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
pub(crate) fn digits_in(text: &str, radix: u32) -> Option<u64> {
    if text.is_empty() || !text.chars().all(|digit| digit.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(text, radix).ok()
}

/// Orders two runs of ASCII digits by the numbers they spell, without parsing
/// either.
///
/// Leading zeros are insignificant, so they are dropped and the longer run
/// wins; runs of equal length compare lexically, which for digits is the same
/// as numerically. A run of any length orders, where an integer parse would
/// overflow, which is what a version's numeric component needs: nothing bounds
/// its length but the mirror that wrote it.
#[cfg(any(feature = "alpine", feature = "gentoo"))]
pub(crate) fn compare_digit_runs(a: &str, b: &str) -> std::cmp::Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_is_digits_and_nothing_else() {
        assert_eq!(digits::<u64>("0"), Some(0));
        assert_eq!(digits::<u64>(b"0042"), Some(42));
        assert_eq!(digits::<u32>("4294967295"), Some(u32::MAX));
        // What Rust's parser accepts and no format spells.
        for refused in ["", "+5", "-5", " 5", "5 ", "5_0", "0x5", "\u{661}"] {
            assert_eq!(digits::<i64>(refused), None, "{refused:?}");
            assert!(!is_digits(refused), "{refused:?}");
        }
        // Past the type's range.
        assert_eq!(digits::<u32>("4294967296"), None);
        assert!(is_digits("4294967296"));
    }

    #[test]
    #[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
    fn a_number_in_a_radix_is_that_radixs_digits() {
        assert_eq!(digits_in("1a", 16), Some(26));
        assert_eq!(digits_in("1A", 16), Some(26));
        assert_eq!(digits_in("10", 10), Some(10));
        for refused in ["", "+1a", "1a", "-1"] {
            assert_eq!(digits_in(refused, 10), None, "{refused:?}");
        }
        assert_eq!(digits_in("+1a", 16), None);
    }

    #[test]
    #[cfg(any(feature = "alpine", feature = "gentoo"))]
    fn digit_runs_order_by_value_at_any_length() {
        assert_eq!(compare_digit_runs("10", "9"), std::cmp::Ordering::Greater);
        assert_eq!(compare_digit_runs("007", "7"), std::cmp::Ordering::Equal);
        assert_eq!(compare_digit_runs("0", ""), std::cmp::Ordering::Equal);
        let long = "9".repeat(40);
        assert_eq!(
            compare_digit_runs(&long, &format!("1{long}")),
            std::cmp::Ordering::Less
        );
    }
}
