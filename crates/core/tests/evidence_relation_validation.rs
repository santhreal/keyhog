//! Validation contracts for the closed typed evidence-relation schema.

use keyhog_core::{
    validate_detector, CompanionSpec, DetectorRelationKind, DetectorRelationSpec, DetectorSpec,
    EvidenceDirection, EvidenceRequirement, EvidenceScope, EvidenceValueRelation, PatternSpec,
    QualityIssue, Severity,
};

fn detector_with(companion: CompanionSpec) -> DetectorSpec {
    DetectorSpec {
        id: "evidence-validation".into(),
        name: "Evidence validation".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"REL_[A-Za-z0-9]{20}".into(),
            required_literals: vec!["REL_".into()],
            ..Default::default()
        }],
        companions: vec![companion],
        keywords: vec!["REL_".into()],
        ..Default::default()
    }
}

fn errors(detector: &DetectorSpec) -> Vec<String> {
    validate_detector(detector)
        .into_iter()
        .filter_map(|issue| match issue {
            QualityIssue::Error(message) => Some(message),
            QualityIssue::Warning(_) => None,
        })
        .collect()
}

fn base_companion() -> CompanionSpec {
    CompanionSpec {
        name: "account".into(),
        regex: r"account=([A-Za-z0-9_-]+)".into(),
        within_lines: 2,
        capture_group: Some(1),
        ..Default::default()
    }
}

/// Same-line scope with a nonzero line radius is contradictory and must fail detector loading.
#[test]
fn same_line_scope_rejects_nonzero_line_radius() {
    let detector = detector_with(CompanionSpec {
        scope: EvidenceScope::SameLine,
        ..base_companion()
    });

    assert!(errors(&detector)
        .iter()
        .any(|message| message.contains("scope=same-line requires within_lines=0")));
}

/// Byte distance zero cannot describe a useful gap and must fail instead of becoming an implicit default.
#[test]
fn zero_byte_distance_is_rejected() {
    let detector = detector_with(CompanionSpec {
        within_bytes: Some(0),
        ..base_companion()
    });

    assert!(errors(&detector)
        .iter()
        .any(|message| message.contains("within_bytes=0 must be in 1..=1048576")));
}

/// Byte bounds above the one-megabyte work cap must be rejected to keep relation scans bounded.
#[test]
fn oversized_byte_distance_is_rejected() {
    let detector = detector_with(CompanionSpec {
        within_bytes: Some(1_048_577),
        ..base_companion()
    });

    assert!(errors(&detector)
        .iter()
        .any(|message| message.contains("within_bytes=1048577 must be in 1..=1048576")));
}

/// An explicit capture group must exist in the compiled regex rather than silently falling back to group one.
#[test]
fn nonexistent_capture_group_is_rejected() {
    let detector = detector_with(CompanionSpec {
        capture_group: Some(2),
        ..base_companion()
    });

    assert!(errors(&detector)
        .iter()
        .any(|message| message.contains("capture_group=2 does not exist")));
}

/// A schema-v2 required boolean cannot be mixed with a conflicting typed requirement.
#[test]
fn legacy_required_and_typed_forbidden_are_rejected() {
    let detector = detector_with(CompanionSpec {
        required: true,
        requirement: EvidenceRequirement::Forbidden,
        ..base_companion()
    });

    assert!(errors(&detector)
        .iter()
        .any(|message| message.contains("mixes schema-v2 required=true")));
}

/// The schema-v2 required boolean must still resolve to typed required semantics for compatible corpora.
#[test]
fn legacy_required_resolves_to_typed_required() {
    let companion = CompanionSpec {
        required: true,
        ..base_companion()
    };

    assert_eq!(
        companion.effective_requirement(),
        EvidenceRequirement::Required
    );
}

/// Unknown scope names must fail TOML decoding because the relation language is closed, not extensible scripting.
#[test]
fn unknown_scope_name_fails_closed() {
    let error = toml::from_str::<CompanionSpec>(
        r#"
name = "account"
regex = "account=([A-Za-z0-9_-]+)"
within_lines = 2
scope = "nearby-ish"
"#,
    )
    .expect_err("unknown evidence scope must fail TOML parsing");

    assert!(error.to_string().contains("unknown variant `nearby-ish`"));
}

/// Equality and inequality are distinct typed contracts and must survive TOML round trips exactly.
#[test]
fn value_relation_round_trip_preserves_variant() {
    let companion = CompanionSpec {
        value_relation: EvidenceValueRelation::DiffersFromPrimary,
        ..base_companion()
    };
    let encoded = toml::to_string(&companion).expect("typed relation serializes");
    let decoded: CompanionSpec = toml::from_str(&encoded).expect("typed relation deserializes");

    assert_eq!(
        decoded.value_relation,
        EvidenceValueRelation::DiffersFromPrimary
    );
    assert_eq!(decoded.capture_group, Some(1));
}

fn requires(target: &str) -> DetectorRelationSpec {
    DetectorRelationSpec {
        detector_id: target.into(),
        kind: DetectorRelationKind::Requires,
        within_lines: 2,
        within_bytes: Some(64),
        direction: EvidenceDirection::Either,
    }
}

/// A detector relation cannot target its owner because self-evidence is not an independent proof.
#[test]
fn detector_relation_rejects_self_target() {
    let mut detector = detector_with(base_companion());
    detector.detector_relations = vec![requires("evidence-validation")];

    assert!(errors(&detector)
        .iter()
        .any(|message| message.contains("cannot target its owning detector")));
}

/// Multiple operations for one detector pair are contradictory and must fail validation.
#[test]
fn detector_relation_rejects_multiple_operations_for_target() {
    let mut detector = detector_with(base_companion());
    detector.detector_relations = vec![
        requires("target-detector"),
        DetectorRelationSpec {
            detector_id: "target-detector".into(),
            kind: DetectorRelationKind::Conflicts,
            within_lines: 2,
            within_bytes: Some(64),
            direction: EvidenceDirection::Either,
        },
    ];

    assert!(errors(&detector)
        .iter()
        .any(|message| message.contains("contradicts relation 0")));
}

/// Detector relations must share the same bounded byte-distance limits as context relations.
#[test]
fn detector_relation_rejects_unbounded_work_radius() {
    let mut detector = detector_with(base_companion());
    detector.detector_relations = vec![DetectorRelationSpec {
        within_bytes: Some(1_048_577),
        ..requires("target-detector")
    }];

    assert!(errors(&detector)
        .iter()
        .any(|message| message.contains("within_bytes=1048577 must be in 0..=1048576")));
}

/// A zero-byte relation radius must remain available for exact overlapping detector spans.
#[test]
fn detector_relation_accepts_zero_byte_gap() {
    let mut detector = detector_with(base_companion());
    detector.detector_relations = vec![DetectorRelationSpec {
        within_bytes: Some(0),
        ..requires("target-detector")
    }];

    assert!(!errors(&detector)
        .iter()
        .any(|message| message.contains("detector relation 0 within_bytes")));
}
