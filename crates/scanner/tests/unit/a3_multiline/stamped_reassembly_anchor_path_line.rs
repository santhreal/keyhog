//! Stamped reassembly returns exact provenance of the prefix (f1) fragment,
//! not f2. Contract: ReassembledCandidate.path and .line must match the
//! anchor (first) fragment's path and line, allowing downstream attribution
//! to the file that actually supplied the prefix part of the credential.

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
fn stamped_reassembly_uses_prefix_fragment_anchor() {
    let cache = FragmentCache::new(1024);
    cache.record_and_reassemble_stamped(frag(
        "stripe_key",
        "SK_PREFIX",
        "sk_live_",
        "/app/secrets.json",
        42,
    ));
    let candidates = cache.record_and_reassemble_stamped(frag(
        "stripe_key",
        "SK_SUFFIX",
        "51a1c58f93f47e35f25a7ac9b8c2d77e",
        "/app/secrets.json",
        60,
    ));

    assert_eq!(
        candidates.len(),
        2,
        "expected 2 stamped candidates (f1+f2 and f2+f1), got {}",
        candidates.len()
    );

    // Both candidates must include a join, one anchored by the f1 fragment (line 42, path /app/secrets.json)
    let mut found_anchor_f1 = false;
    let mut found_anchor_f2 = false;

    for candidate in &candidates {
        let path_str = candidate
            .path
            .as_deref()
            .map(|p| p.to_string())
            .unwrap_or_default();

        if candidate.line == 42 && path_str == "/app/secrets.json" {
            found_anchor_f1 = true;
            assert_eq!(
                candidate.value.as_str(),
                "sk_live_51a1c58f93f47e35f25a7ac9b8c2d77e",
                "expected f1+f2 join anchored at f1"
            );
        }
        if candidate.line == 60 && path_str == "/app/secrets.json" {
            found_anchor_f2 = true;
            assert_eq!(
                candidate.value.as_str(),
                "51a1c58f93f47e35f25a7ac9b8c2d77esk_live_",
                "expected f2+f1 join anchored at f2"
            );
        }
    }

    assert!(
        found_anchor_f1,
        "expected at least one candidate anchored at f1 (line 42), got {:?}",
        candidates
            .iter()
            .map(|c| (c.line, c.path.clone()))
            .collect::<Vec<_>>()
    );

    assert!(
        found_anchor_f2,
        "expected at least one candidate anchored at f2 (line 60), got {:?}",
        candidates
            .iter()
            .map(|c| (c.line, c.path.clone()))
            .collect::<Vec<_>>()
    );
}
