//! Duplicate fragment (same path, line, value) is not added to cluster twice.
//! Contract: when recording fragment f at (path, line, value), if an
//! identical fragment already exists in the cluster, the cluster size
//! must not increment (checked against MAX_FRAGMENTS_PER_SCOPE eviction).

use keyhog_scanner::fragment_cache::{FragmentCache, SecretFragment};
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
fn identical_fragment_recorded_only_once() {
    let cache = FragmentCache::new(1024);

    // Record the same fragment 3 times: same prefix, path, line, value
    let f = frag(
        "github_token",
        "GITHUB_PAT",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "/config/creds.env",
        15,
    );

    cache.record_and_reassemble(f.clone());
    cache.record_and_reassemble(f.clone());
    let candidates = cache.record_and_reassemble(f.clone());

    // No candidates should be generated since we only have 1 effective fragment
    // (the duplicates were rejected by the dedup check)
    assert_eq!(
        candidates.len(),
        0,
        "no joins expected for single effective fragment despite 3 record calls"
    );
}

#[test]
fn similar_fragment_with_different_value_creates_new_entry() {
    let cache = FragmentCache::new(1024);

    // Record f1 with one value
    cache.record_and_reassemble(frag(
        "api_key",
        "PREFIX",
        "sk_live_",
        "/secrets/.env.prod",
        10,
    ));

    // Record f2 with same path/line but DIFFERENT value - this should create a new cluster entry
    let candidates = cache.record_and_reassemble(frag(
        "api_key",
        "DIFFERENT_VAR",
        "sk_test_", // different value from f1's "sk_live_"
        "/secrets/.env.prod",
        10,
    ));

    // We should now have 2 fragments in cluster and thus 2 join candidates
    assert_eq!(
        candidates.len(),
        2,
        "expected 2 joins for 2 different fragments at same line, got {}",
        candidates.len()
    );
}
