//! Bumping detector severity changes the merkle spec hash.

use keyhog_core::{compute_spec_hash, DetectorSpec, PatternSpec, Severity};

#[test]
fn compute_spec_hash_changes_when_severity_changes() {
    let base = DetectorSpec {
        id: "sev-test".into(),
        name: "sev".into(),
        service: "sev".into(),
        severity: Severity::Medium,
        keywords: vec![],
        patterns: vec![PatternSpec {
            regex: "[A-Z]{40}".into(),
            description: None,
            group: None,
        }],
        companions: vec![],
        verify: None,
    };
    let mut bumped = base.clone();
    bumped.severity = Severity::Critical;
    assert_ne!(
        compute_spec_hash(&[base]),
        compute_spec_hash(&[bumped]),
        "bumping severity must invalidate the cache"
    );
}
