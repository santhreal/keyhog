//! Gap test: the fragment-name prefix extractor (`extract_prefix`).
//!
//! When a credential is split across assignment fragments (`api_key_part1`,
//! `api_key_part2`, ...) the structural resolver collapses each fragment name
//! to a shared base prefix so the pieces group together. `extract_prefix` does
//! that collapse: it drops `_`/`-` separators and `part` segments, lowercases,
//! and trims a trailing numeric run. Pin the exact outputs across those three
//! transforms so a regression in any one is caught.
//!
//! The seam lives in the multiline test module, so this is feature-gated.
#![cfg(feature = "multiline")]

use keyhog_scanner::testing::multiline::extract_prefix_for_test as extract_prefix;

#[test]
fn underscore_separator_is_dropped() {
    // `_` is a separator: `api_key` collapses to a contiguous lowercase base.
    assert_eq!(extract_prefix("api_key"), "apikey");
}

#[test]
fn part_segment_and_trailing_digits_are_stripped() {
    // `token_part1` drops the `_`, skips the `part` segment, then the trailing
    // `1` is trimmed — leaving the shared base that groups the fragments.
    assert_eq!(extract_prefix("token_part1"), "token");
}

#[test]
fn hyphen_separator_is_dropped_and_value_lowercased() {
    // `-` is a separator like `_`, and mixed case folds to lowercase.
    assert_eq!(extract_prefix("Auth-Token"), "authtoken");
}
