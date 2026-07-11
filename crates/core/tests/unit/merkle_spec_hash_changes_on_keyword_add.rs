//! Adding a keyword must change spec hash to invalidate incremental cache.

use keyhog_core::compute_spec_hash;
use keyhog_core::{DetectorSpec, PatternSpec, Severity};

#[test]
fn merkle_compute_spec_hash_changes_when_keywords_change() {
    let base = DetectorSpec {
        tests: Vec::new(),
        id: "test-detector".into(),
        name: "test".into(),
        service: "test".into(),
        severity: Severity::Medium,
        keywords: vec!["secret".into()],
        min_confidence: None,
        patterns: vec![PatternSpec {
            regex: "[A-Z0-9]{32}".into(),
            ..Default::default()
        }],
        companions: vec![],
        verify: None,
        ..Default::default()
    };
    let mut with_extra = base.clone();
    with_extra.keywords.push("api_key".into());
    assert_ne!(
        compute_spec_hash(&[base.clone()]),
        compute_spec_hash(&[with_extra])
    );
}
