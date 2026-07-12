//! Migrated from the inline `tests` module in `ml_scorer/ml_features.rs` (removed
//! to satisfy `ml_features_no_inline_tests`). Pins the bigram-bitset sizing and
//! distinct-window counting contract through the `crate::testing` facade.

use keyhog_scanner::testing::{
    ml_bigram_bitset_words_for_test as bigram_bitset_words,
    ml_unique_bigram_stats_for_test as unique_bigram_stats,
};

#[test]
fn bigram_bitset_covers_every_possible_bigram() {
    // 65_536 distinct byte bigrams, 64 per u64 word.
    assert_eq!(bigram_bitset_words(), 1024);
    // The largest bigram index (0xFF,0xFF) = 65_535 must land in the buffer.
    let max_idx = (0xFFusize << 8) | 0xFF;
    assert!(max_idx / 64 < bigram_bitset_words());
}

#[test]
fn unique_bigram_stats_counts_distinct_windows() {
    // "abcd" -> ab, bc, cd : 3 distinct of 3 windows.
    assert_eq!(unique_bigram_stats(b"abcd"), (3, 3));
    // "aaaa" -> aa repeated : 1 distinct of 3 windows.
    assert_eq!(unique_bigram_stats(b"aaaa"), (1, 3));
    // Degenerate lengths.
    assert_eq!(unique_bigram_stats(b"a"), (0, 0));
    assert_eq!(unique_bigram_stats(b""), (0, 0));
}
