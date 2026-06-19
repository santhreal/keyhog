//! LR1-A8 replacement gate: `cache.rs` zero TTL still starts empty.

use keyhog_verifier::testing::{TestVerificationCache as VerificationCache, VerifierTestCache};
use std::time::Duration;

#[test]
fn cache_zero_ttl_has_no_entries() {
    let cache = VerificationCache::new(Duration::from_secs(0));
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}
