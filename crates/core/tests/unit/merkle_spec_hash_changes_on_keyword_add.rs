//! Adding a keyword must change spec hash to invalidate incremental cache.

use keyhog_core::compute_spec_hash;
use keyhog_core::{DetectorSpec, PatternSpec, Severity};

#[test]
fn merkle_compute_spec_hash_changes_when_keywords_change() {
    let base = DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
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

#[test]
fn merkle_compute_spec_hash_changes_when_semantic_policy_changes() {
    let base = DetectorSpec {
        id: "semantic-hash-detector".into(),
        name: "semantic hash".into(),
        service: "test".into(),
        severity: Severity::Medium,
        patterns: vec![PatternSpec {
            regex: "[A-Z0-9]{32}".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let baseline = compute_spec_hash(std::slice::from_ref(&base));

    let mut changed = base.clone();
    changed.capture_role = keyhog_core::CaptureSemanticRole::AssignmentValue;
    assert_ne!(baseline, compute_spec_hash(std::slice::from_ref(&changed)));

    changed = base.clone();
    changed.anchor_role = keyhog_core::AnchorSemanticRole::ExactKey;
    assert_ne!(baseline, compute_spec_hash(std::slice::from_ref(&changed)));

    changed = base.clone();
    changed.allowed_source_roles = vec![keyhog_core::SemanticSourceRole::StringLiteral];
    assert_ne!(baseline, compute_spec_hash(std::slice::from_ref(&changed)));

    changed = base.clone();
    changed.required_evidence = vec![keyhog_core::RequiredSemanticEvidence::StructuralGrammar];
    assert_ne!(baseline, compute_spec_hash(std::slice::from_ref(&changed)));

    let mut reordered = base.clone();
    reordered.allowed_source_roles = vec![
        keyhog_core::SemanticSourceRole::StringLiteral,
        keyhog_core::SemanticSourceRole::StructuredAssignmentValue,
    ];
    reordered.required_evidence = vec![
        keyhog_core::RequiredSemanticEvidence::StructuralGrammar,
        keyhog_core::RequiredSemanticEvidence::Checksum,
    ];
    let ordered = compute_spec_hash(std::slice::from_ref(&reordered));
    reordered.allowed_source_roles.reverse();
    reordered.required_evidence.reverse();
    assert_eq!(
        ordered,
        compute_spec_hash(std::slice::from_ref(&reordered)),
        "set-like semantic declarations must be order-independent"
    );
}
