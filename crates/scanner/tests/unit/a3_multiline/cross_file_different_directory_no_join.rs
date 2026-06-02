//! Cross-file fragments in DIFFERENT directories must not join.
//! Intentional design: prevent cross-directory secret glue (e.g., AKIA in
//! ./config/ + sk_ in ./vendor/) from synthesizing false reassembled findings.
//! Contract: fragments from /repo/config/a.py and /repo/lib/b.py scoped by
//! their full paths (not parent directory) must never cluster together.

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
fn cross_directory_fragments_never_join() {
    let cache = FragmentCache::new(1024);

    // Fragment 1: AWS prefix in /repo/config/secrets.yaml
    cache.record_and_reassemble(frag(
        "aws_key",
        "AWS_ACCESS_KEY",
        "AKIA6CR0ANJCWS6ROMLZ",
        "/repo/config/secrets.yaml",
        10,
    ));

    // Fragment 2: Unrelated token in /repo/vendor/lib/auth.py (different directory tree)
    let candidates = cache.record_and_reassemble(frag(
        "aws_key",
        "AWS_SECRET",
        "Y2xpZW50X3NlY3JldF9zazo3ZmRkZGFkOWE4",
        "/repo/vendor/lib/auth.py",
        15,
    ));

    // Despite matching prefix and within 100-line distance, cross-directory
    // fragments are keyed by full path, so they never pool in the same cluster.
    assert_eq!(
        candidates.len(),
        0,
        "cross-directory fragments must not join, got {} candidates",
        candidates.len()
    );
}

#[test]
fn same_directory_same_file_joins_different_from_same_directory_different_file() {
    let cache = FragmentCache::new(1024);

    // Fragment 1: in /app/env/a.env
    cache.record_and_reassemble(frag("secret", "PART_A", "sk_test_", "/app/env/a.env", 1));

    // Fragment 2: in /app/env/b.env (same directory, different file)
    let candidates = cache.record_and_reassemble(frag(
        "secret",
        "PART_B",
        "4eC39HqLyjWDarhtT1zgNVqH7FHhRnDe",
        "/app/env/b.env",
        2,
    ));

    // Even though both are in /app/env/, the full path is different (/app/env/a.env != /app/env/b.env)
    // So they should NOT join (same-path requirement enforced by the near-guard)
    assert_eq!(
        candidates.len(),
        0,
        "same-directory but different-file fragments must not join"
    );
}
