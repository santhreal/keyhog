//! Fragment pair at exactly 99-line distance (just under 100-line boundary) joins.
//! Contract: same-path fragments with |f1.line - f2.line| == 99 must reassemble
//! since the contract is (f1.line as isize - f2.line as isize).abs() < 100.

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
fn line_distance_99_at_boundary_joins() {
    let cache = FragmentCache::new(1024);
    cache.record_and_reassemble(frag("api_key", "PREFIX", "sk_live_", "/env/.env.prod", 1));
    let candidates = cache.record_and_reassemble(frag(
        "api_key",
        "SUFFIX",
        "51a1c58f93f47e35f25a7ac9b8c2d77e",
        "/env/.env.prod",
        100, // line 1 → line 100: distance is 99, strictly less than 100
    ));

    assert_eq!(
        candidates.len(),
        2,
        "expected 2 joins (f1+f2 and f2+f1) for 99-line distance, got {}",
        candidates.len()
    );

    let joined: Vec<String> = candidates.iter().map(|c| c.as_str().to_string()).collect();
    assert!(
        joined.contains(&"sk_live_51a1c58f93f47e35f25a7ac9b8c2d77e".to_string()),
        "expected prefix+suffix join at 99-line boundary, got {:?}",
        joined
    );
}
