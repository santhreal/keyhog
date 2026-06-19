//! Fragment pair at exactly 100-line distance (at or exceeding boundary) does NOT join.
//! Contract: same-path fragments with |f1.line - f2.line| >= 100 must NOT reassemble
//! since the contract is (f1.line as isize - f2.line as isize).abs() < 100 (strict less-than).

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
fn line_distance_100_at_boundary_no_join() {
    let cache = FragmentCache::new(1024);
    cache.record_and_reassemble(frag("api_key", "PREFIX", "sk_test_", "/app/config.toml", 1));
    let candidates = cache.record_and_reassemble(frag(
        "api_key",
        "SUFFIX",
        "4eC39HqLyjWDarhtT1zgNVqH7FHhRnDe",
        "/app/config.toml",
        101, // line 1 → line 101: distance is 100, NOT strictly less than 100
    ));

    assert_eq!(
        candidates.len(),
        0,
        "expected 0 joins for 100-line distance (boundary exclusive), got {}",
        candidates.len()
    );
}

#[test]
fn line_distance_200_no_join() {
    let cache = FragmentCache::new(1024);
    cache.record_and_reassemble(frag(
        "secret_key",
        "PART_A",
        "AWSsecretaccesskey",
        "/infra/secrets.yml",
        50,
    ));
    let candidates = cache.record_and_reassemble(frag(
        "secret_key",
        "PART_B",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEX",
        "/infra/secrets.yml",
        250, // distance is 200, far exceeds 100-line limit
    ));

    assert_eq!(
        candidates.len(),
        0,
        "expected 0 joins for 200-line distance, got {}",
        candidates.len()
    );
}
