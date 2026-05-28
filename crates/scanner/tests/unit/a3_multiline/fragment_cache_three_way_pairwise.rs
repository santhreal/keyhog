//! Three-fragment cluster emits all six ordered pairwise joins.

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
fn three_fragments_emit_all_pairwise_joins() {
    let cache = FragmentCache::new(1024);
    cache.record_and_reassemble(frag("p", "A", "111", "/d/a.py", 1));
    cache.record_and_reassemble(frag("p", "B", "222", "/d/b.py", 2));
    let candidates = cache.record_and_reassemble(frag("p", "C", "333", "/d/c.py", 3));
    assert_eq!(
        candidates.len(),
        6,
        "expected 6 pairwise joins for cluster size 3, got {}",
        candidates.len()
    );
    let joined: std::collections::BTreeSet<String> =
        candidates.iter().map(|c| c.as_str().to_string()).collect();
    for expected in ["111222", "222111", "111333", "333111", "222333", "333222"] {
        assert!(
            joined.contains(expected),
            "missing join `{expected}` from {:?}",
            joined
        );
    }
}
