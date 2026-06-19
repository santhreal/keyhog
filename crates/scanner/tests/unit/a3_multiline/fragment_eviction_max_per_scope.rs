//! Fragment eviction respects MAX_FRAGMENTS_PER_SCOPE (8). When cluster size
//! exceeds 8, the oldest fragment is dropped (LRU). Contract: cluster never
//! exceeds 8 fragments despite multiple record calls, and eviction doesn't
//! affect join semantics of remaining fragments.

use keyhog_scanner::testing::fragment_cache::{FragmentCache, SecretFragment};
use std::sync::Arc;
use zeroize::Zeroizing;

fn frag(prefix: &str, var: &str, value: &str, path: &str, line: usize) -> SecretFragment {
    SecretFragment {
        prefix: prefix.to_string(),
        var_name: var.to_string(),
        value: Zeroizing::new(value.to_string()),
        line,
        path: Some(Arc::from(path)),
    }
}

#[test]
fn ninth_fragment_evicts_oldest_in_cluster() {
    let cache = FragmentCache::new(1024);

    // Record 9 unique fragments in the same file, each with a unique line and value
    for i in 0..9 {
        let line = (i * 5) as usize + 1; // Lines: 1, 6, 11, 16, 21, 26, 31, 36, 41
        let value = format!("fragment_{:02}", i);
        cache.record_and_reassemble(frag(
            "cred", // same prefix for all
            &format!("VAR_{}", i),
            &value,
            "/app/config.yaml",
            line,
        ));
    }

    // After 9 records, the cluster should only have 8 fragments (the oldest was evicted)
    // The last record (fragment_08 at line 41) should be in the cluster,
    // but fragment_00 (at line 1, recorded first) should have been evicted.

    // Verify by recording a 10th fragment: we should get joins with all 8 remaining
    // (but NOT with fragment_00 since it was evicted). With 8 fragments, we expect
    // 8*2 = 16 pairwise joins (each existing fragment pairs with the new one bidirectionally).
    let candidates = cache.record_and_reassemble(frag(
        "cred",
        "VAR_NEW",
        "final_fragment",
        "/app/config.yaml",
        45,
    ));

    // `record_and_reassemble` joins EVERY ordered pair (i != j) of the cluster,
    // not just pairs involving the newest fragment. Eviction holds the cluster
    // at MAX_FRAGMENTS_PER_SCOPE (8), so the join count is 8 * 7 = 56. Had
    // eviction not fired (9 fragments retained) it would be 9 * 8 = 72 - so 56
    // is exactly the signal that the cap is enforced.
    assert_eq!(
        candidates.len(),
        56,
        "expected 56 joins (8 capped fragments, all ordered pairs = 8*7) after eviction, got {}",
        candidates.len()
    );

    // Verify the joins don't include the evicted fragment's value
    let joined: Vec<String> = candidates.iter().map(|c| c.as_str().to_string()).collect();
    for cand in &joined {
        assert!(
            !cand.contains("fragment_00"),
            "evicted fragment should not appear in joins, but got: {}",
            cand
        );
    }
}
