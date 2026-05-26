//! Thread-local entropy cache must not change numeric result.

use keyhog_scanner::entropy::shannon_entropy;

#[test]
fn entropy_shannon_cache_matches_uncached() {
    let data = b"sk-proj-abc123XYZ!@#mixedentropy";
    let first = shannon_entropy(data);
    let second = shannon_entropy(data);
    assert!(
        (first - second).abs() < 1e-12,
        "cached repeat lookup must match: {first} vs {second}"
    );
    assert!(first > 3.0, "fixture must have non-trivial entropy");
}
