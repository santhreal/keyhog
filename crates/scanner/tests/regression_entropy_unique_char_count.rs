//! Migrated from the inline `tests` module in `entropy/plausibility.rs` (removed
//! to satisfy `entropy_plausibility_no_inline_tests`). Pins the distinct-scalar
//! counting contract through the `crate::testing` facade.

use keyhog_scanner::testing::{
    entropy_unique_byte_count_for_test as unique_byte_count,
    entropy_unique_char_count_for_test as unique_char_count,
};

/// The ASCII fast path delegates to the single canonical distinct-byte primitive
/// (`entropy::unique_byte_count`); for ASCII input the two must agree exactly
/// (distinct bytes == distinct chars), and both report the real distinct count,
/// not merely non-emptiness.
#[test]
fn unique_char_count_ascii_matches_canonical_byte_count() {
    assert_eq!(unique_char_count("aabbc"), 3);
    assert_eq!(unique_char_count("AaAaAa"), 2);
    assert_eq!(unique_char_count(""), 0);
    for probe in ["aabbc", "AaAaAa", "0123456789abcdef0123", ""] {
        assert_eq!(
            unique_char_count(probe),
            unique_byte_count(probe.as_bytes()),
            "ASCII unique_char_count must equal the canonical distinct-byte count for {probe:?}",
        );
    }
}

/// The non-ASCII branch counts scalar values, not bytes: `é` is two UTF-8 bytes
/// but one char, so a byte-based count would over-report. `café` has four
/// distinct chars (five bytes) and `ééé` collapses to one.
#[test]
fn unique_char_count_non_ascii_counts_chars_not_bytes() {
    assert_eq!(unique_char_count("café"), 4);
    assert_eq!("café".len(), 5); // five UTF-8 bytes, so a byte count would give 5
    assert_eq!(unique_char_count("ééé"), 1);
}
