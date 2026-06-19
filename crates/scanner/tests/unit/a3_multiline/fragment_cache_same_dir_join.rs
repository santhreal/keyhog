//! Cross-file fragments in the same directory join into credential candidates.

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
fn two_fragments_same_dir_join() {
    let cache = FragmentCache::new(1024);
    let candidates = cache.record_and_reassemble(frag(
        "aws_key",
        "AWS_PREFIX",
        "AKIAIOSFODNN7",
        "/repo/config/a.py",
        10,
    ));
    assert!(
        candidates.is_empty(),
        "single fragment can't form a join candidate"
    );
    let candidates = cache.record_and_reassemble(frag(
        "aws_key",
        "AWS_SUFFIX",
        "EXAMPLE",
        "/repo/config/b.py",
        12,
    ));
    let joined: Vec<String> = candidates.iter().map(|c| c.as_str().to_string()).collect();
    assert!(
        joined.contains(&concat!("AK", "IAIOSFODNN7EXAMPLE").to_string()),
        "expected prefix+suffix join, got {:?}",
        joined
    );
}
