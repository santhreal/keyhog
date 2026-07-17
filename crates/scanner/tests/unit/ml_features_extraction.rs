//! ML feature-extraction internals (`ml_scorer/ml_features.rs`), reached via the
//! `keyhog_scanner::testing` facade. Migrated from an inline `#[cfg(test)]` block
//! to satisfy the `ml_features_no_inline_tests` gate.

use keyhog_scanner::testing::unique_bigram_stats_for_test as unique_bigram_stats;

/// `unique_bigram_stats` counts DISTINCT byte bigrams and total bigram windows.
/// Pinned to exact values, and called repeatedly to prove the reused thread-local
/// scratch is fully cleared between calls (a leaked bit would inflate a later
/// distinct count).
#[test]
fn unique_bigram_stats_counts_distinct_bigrams_and_reuses_scratch() {
    // "abcabc": windows ab,bc,ca,ab,bc -> distinct {ab,bc,ca}=3, total=5.
    assert_eq!(unique_bigram_stats(b"abcabc"), (3, 5));
    // "aaaa": windows aa,aa,aa -> distinct {aa}=1, total=3.
    assert_eq!(unique_bigram_stats(b"aaaa"), (1, 3));
    // Re-run the first input: identical result proves no cross-call leak.
    assert_eq!(unique_bigram_stats(b"abcabc"), (3, 5));
    assert_eq!(unique_bigram_stats(b"a"), (0, 0));
    assert_eq!(unique_bigram_stats(b""), (0, 0));
}
