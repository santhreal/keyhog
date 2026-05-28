//! compute_spec_hash must be order-invariant across detector slice ordering.

use keyhog_core::merkle_index::compute_spec_hash;
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec, Severity};

fn make(id: &str) -> DetectorSpec {
    DetectorSpec {
        id: id.to_string(),
        name: id.to_string(),
        service: id.to_string(),
        severity: Severity::Medium,
        keywords: vec![],
        patterns: vec![PatternSpec { regex: format!("{id}-[A-Z]+"), ..Default::default() }],
        companions: vec![CompanionSpec { name: "k".into(), regex: "v=([A-Z]+)".into(), within_lines: 3, required: false }],
        verify: None,
    }
}

#[test]
fn merkle_compute_spec_hash_is_stable_under_reordering() {
    let a = compute_spec_hash(&[make("alpha"), make("beta")]);
    let b = compute_spec_hash(&[make("beta"), make("alpha")]);
    assert_eq!(a, b, "spec hash must be order-invariant");
    let c = compute_spec_hash(&[make("alpha"), make("gamma")]);
    assert_ne!(a, c);
}
