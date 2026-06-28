//! Gap test: the reverse decoder's string reversal and admission gate.
//!
//! `reverse_str` reverses by Unicode scalar (not byte), and `looks_reversible`
//! admits a candidate for reverse-decoding only when BOTH gates pass:
//!   1. a contiguous ASCII-alphanumeric run of at least `MIN_REVERSE_ALNUM_RUN`
//!      (12) scanned in the reversed direction, AND
//!   2. the candidate contains the reverse of a known provider prefix (so a
//!      plain monotonic alphabet, which reverses to nothing meaningful, is
//!      rejected).
//!
//! Pin the exact reversal, the 11-vs-12 run boundary, and the known-prefix
//! requirement (`AKIA` reversed is `AIKA`).
//!
//! The reverse decoder lives behind the `decode` feature.
#![cfg(feature = "decode")]

use keyhog_scanner::testing::looks_reversible_for_test as looks_reversible;
use keyhog_scanner::testing::reverse_str_for_test as reverse_str;

#[test]
fn reverses_ascii_exactly() {
    assert_eq!(reverse_str("ABCDEF"), "FEDCBA");
}

#[test]
fn reverses_by_unicode_scalar_not_byte() {
    // `é` is two UTF-8 bytes; a byte reversal would corrupt it. Char reversal
    // keeps it intact: "héllo" -> "olléh".
    assert_eq!(reverse_str("héllo"), "olléh");
}

#[test]
fn requires_a_twelve_long_alnum_run() {
    // Both strings contain `AIKA` (the reverse of the known `AKIA` prefix), so
    // only the alnum-run gate differs. 12 contiguous alnum chars admit; 11 do
    // not — pinning the exact MIN_REVERSE_ALNUM_RUN boundary.
    assert!(looks_reversible("AIKAABCDEFGH")); // 12-char run
    assert!(!looks_reversible("AIKAABCDEFG")); // 11-char run
}

#[test]
fn long_run_without_a_reversed_known_prefix_is_rejected() {
    // 26 contiguous alnum chars clear the run gate, but a monotonic A–Z string
    // contains no reversed provider prefix, so it is not admitted.
    assert!(!looks_reversible("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
}
