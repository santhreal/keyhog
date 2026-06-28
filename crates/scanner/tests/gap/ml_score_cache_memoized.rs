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
    assert_eq!(ml_score(text, context), first, "cache hit must be identical");

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
