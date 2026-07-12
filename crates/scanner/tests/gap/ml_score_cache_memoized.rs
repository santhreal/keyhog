//! ml_scorer::score_with_config's per-thread score cache was migrated from a
//! hand-rolled get/compute/clear-at-256/insert to the shared
//! util_hash::memoize_by_hash idiom (completing the migration util_hash.rs's
//! doc already claimed). The migration must be observably byte-identical: the
//! same (text, context) returns the SAME score on a cache hit, after cap-256
//! eviction, and the empty-text guard still short-circuits to 0.0.

use keyhog_scanner::testing::ml_score;

#[test]
fn ml_score_is_deterministic_across_cache_hits_and_evictions() {
    // Empty-text guard short-circuits before the cache (returns 0.0).
    assert_eq!(ml_score("", ""), 0.0);
    assert_eq!(ml_score("", "api_key = "), 0.0);

    let text = "AKIAIOSFODNN7EXAMPLE";
    let context = "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"";

    let first = ml_score(text, context);
    assert!(
        (0.0..=1.0).contains(&first),
        "score must be a sigmoid output in [0,1], got {first}"
    );

    // Immediate repeat hits the memoized entry and must equal the first call.
    assert_eq!(
        ml_score(text, context),
        first,
        "cache hit must be identical"
    );

    // Drive >256 distinct keys to force the cap-256 wholesale eviction inside
    // memoize_by_hash, then re-score the original input: it recomputes from
    // scratch and must still produce the identical score (no drift, no panic).
    for i in 0..300u32 {
        let t = format!("candidate-token-value-{i:04}");
        let s = ml_score(&t, context);
        assert!((0.0..=1.0).contains(&s));
    }
    assert_eq!(
        ml_score(text, context),
        first,
        "score after cap-256 eviction + recompute must equal the original"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed test pins determinism/bounds at a couple of inputs + drives eviction;
// this SWEEPS the two observable contracts of `ml_score` over arbitrary printable
// inputs: every score is a sigmoid output in [0,1] AND the scorer is deterministic
// (an immediate repeat hits the per-thread memo and must be bit-identical), and the
// empty-text guard short-circuits to exactly 0.0 for any context. Traced against
// `ml_scorer::score_with_config`. No proptest before.

use proptest::prelude::*;

proptest! {
    // Each case runs real model inference; keep the count modest.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Every score is in [0,1] and a repeat call (cache hit) is bit-identical.
    #[test]
    fn score_is_bounded_and_deterministic(
        text in "[ -~]{0,40}",
        context in "[ -~]{0,60}",
    ) {
        let first = ml_score(&text, &context);
        prop_assert!((0.0..=1.0).contains(&first), "score {first} outside [0,1]");
        prop_assert_eq!(ml_score(&text, &context), first, "cache hit must be identical");
    }

    /// Empty text short-circuits to exactly 0.0 regardless of context.
    #[test]
    fn empty_text_scores_zero(context in "[ -~]{0,60}") {
        prop_assert_eq!(ml_score("", &context), 0.0);
    }
}
