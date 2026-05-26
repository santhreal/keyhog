//! LR1-A8 replacement gate: `lib.rs` dedup on empty input.

use keyhog_core::DedupScope;
use keyhog_verifier::dedup_matches;

#[test]
fn dedup_empty_matches_returns_empty_vec() {
    let out = dedup_matches(vec![], &DedupScope::Credential);
    assert!(out.is_empty());
}
