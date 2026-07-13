//! Cross-directory fragments must not reassemble even with matching prefix.

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
fn fragments_in_different_directories_do_not_join() {
    let cache = FragmentCache::new(1024);
    cache.record_and_reassemble(frag(
        "key",
        "PREFIX",
        "AKIAIOSFODNN7",
        "/repo/config/a.py",
        10,
    ));
    let candidates = cache.record_and_reassemble(frag(
        "key",
        "SUFFIX",
        "EXAMPLE",
        "/repo/vendor/some_lib/b.py",
        12,
    ));
    assert!(
        candidates.is_empty(),
        "cross-directory fragments must not join, got {:?}",
        candidates
            .iter()
            .map(|c| c.as_str().to_string())
            .collect::<Vec<_>>()
    );
}
