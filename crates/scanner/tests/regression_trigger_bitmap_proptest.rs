//! Property invariants for the trigger bitmap (`engine::trigger_bitmap`), the
//! per-pattern set the confirmed-pass hot path walks to decide which detectors
//! to extract (`backend_triggered.rs`: `for_each_set_bit(&expanded_patterns, …)`).
//!
//! A bug in this bit walk is silent and severe: a MISSED bit drops a detector
//! trigger (a real credential is never confirmed), a DUPLICATE double-fires the
//! confirmed extraction, and a stray bit past `n_patterns` would index a
//! nonexistent detector. `words_for` has an example lock
//! (`regression_prefilter_trigger_union::trigger_bitmap_words_for_exact_div_ceil_64`);
//! this adds the property dimension for the walk itself over thousands of random
//! bit sets. The module is pure, so the invariants are exact, not statistical.

use keyhog_scanner::testing::{
    for_each_set_bit_collect_for_test as collect, new_trigger_bitmap_for_test as new_bitmap,
    trigger_bitmap_words_for_test as words_for,
};
use proptest::prelude::*;
use std::collections::BTreeSet;

const MAX_PATTERNS: usize = 4096;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Round-trip: for any set of pattern indices in `[0, n)`, marking them in a
    /// fresh `n`-pattern bitmap and walking it recovers EXACTLY those indices —
    /// no miss, no duplicate, strictly ascending (the confirmed pass relies on
    /// each triggered pattern being visited once).
    #[test]
    fn for_each_set_bit_recovers_exactly_the_marked_bits(
        n in 0usize..MAX_PATTERNS,
        raw in prop::collection::btree_set(0usize..MAX_PATTERNS, 0..80),
    ) {
        // Only bits that fit in the n-pattern bitmap can be marked.
        let expected: BTreeSet<usize> = raw.into_iter().filter(|&b| b < n).collect();

        let mut words = new_bitmap(n);
        prop_assert_eq!(words.len(), words_for(n), "bitmap word count must equal words_for(n)");
        for &b in &expected {
            words[b / 64] |= 1u64 << (b % 64);
        }

        let got = collect(&words);

        // No duplicates.
        prop_assert_eq!(got.len(), expected.len(), "walk reported a wrong count (miss or duplicate)");
        // Strictly ascending (word-major, low-bit-first).
        prop_assert!(got.windows(2).all(|w| w[0] < w[1]), "walk must report ascending, got {:?}", got);
        // Exact set recovery.
        prop_assert_eq!(got.into_iter().collect::<BTreeSet<_>>(), expected);
    }

    /// A freshly allocated bitmap has NO set bits (the walk yields nothing), so a
    /// no-trigger chunk never enters the confirmed extraction.
    #[test]
    fn fresh_bitmap_walks_empty(n in 0usize..MAX_PATTERNS) {
        let words = new_bitmap(n);
        prop_assert!(collect(&words).is_empty(), "a fresh bitmap must have no set bits");
    }

    /// Marking EVERY in-range bit recovers the full `[0, n)` range exactly — the
    /// dense case, catching a high-word tail-bit miss that a sparse set hides.
    #[test]
    fn all_bits_set_recovers_full_range(n in 0usize..1024) {
        let mut words = new_bitmap(n);
        for b in 0..n {
            words[b / 64] |= 1u64 << (b % 64);
        }
        let got = collect(&words);
        prop_assert_eq!(got, (0..n).collect::<Vec<_>>());
    }
}
