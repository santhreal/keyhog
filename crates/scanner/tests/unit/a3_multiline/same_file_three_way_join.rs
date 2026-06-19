//! Three fragments in the same file within 100-line window all join pairwise.
//! Contract: cluster size 3 with same path and line distances < 100 produces
//! 6 ordered pairwise joins (A+B, B+A, A+C, C+A, B+C, C+B).

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
fn three_fragments_same_file_emit_all_pairwise_joins() {
    let cache = FragmentCache::new(1024);
    // All in same file /config/setup.py, line distances: 1→10 (9 lines), 10→50 (40 lines)
    cache.record_and_reassemble(frag(
        "secret_key",
        "AWS_PART1",
        "AKIA6CR0ANJC",
        "/config/setup.py",
        1,
    ));
    cache.record_and_reassemble(frag(
        "secret_key",
        "AWS_PART2",
        "WS6ROMLZ",
        "/config/setup.py",
        10,
    ));
    let candidates = cache.record_and_reassemble(frag(
        "secret_key",
        "AWS_PART3",
        "ABC123",
        "/config/setup.py",
        50,
    ));

    assert_eq!(
        candidates.len(),
        6,
        "expected 6 pairwise joins for 3 same-file fragments within 100-line window, got {}",
        candidates.len()
    );

    let joined: std::collections::BTreeSet<String> =
        candidates.iter().map(|c| c.as_str().to_string()).collect();

    // All 6 ordered pairs must be present
    for expected in [
        "AKIA6CR0ANJCWS6ROMLZ",
        "WS6ROMLZAKIA6CR0ANJC",
        "AKIA6CR0ANJCABC123",
        "ABC123AKIA6CR0ANJC",
        "WS6ROMLZABC123",
        "ABC123WS6ROMLZ",
    ] {
        assert!(
            joined.contains(expected),
            "expected join `{expected}` missing from {:?}",
            joined
        );
    }
}
