use keyhog_core::{
    EvidenceReasonCode, EvidenceTier, EvidenceVerdict, FindingCandidateChannel, FindingProvenance,
    SemanticSourceRole,
};

fn unattributed_provenance() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "detector_digest": null,
        "pattern_index": null,
        "candidate_channel": "unattributed",
        "source_role": "unknown",
        "context_class": "unattributed"
    })
}

#[test]
fn finding_provenance_stays_compact() {
    assert_eq!(std::mem::size_of::<FindingProvenance>(), 16);
}

#[test]
fn every_reason_has_one_canonical_tier_and_wire_spelling() {
    let cases = [
        (
            EvidenceReasonCode::Unattributed,
            EvidenceTier::Review,
            "unattributed",
        ),
        (
            EvidenceReasonCode::UnsupportedContext,
            EvidenceTier::Review,
            "unsupported-context",
        ),
        (
            EvidenceReasonCode::RequiredEvidenceMissing,
            EvidenceTier::Review,
            "required-evidence-missing",
        ),
        (
            EvidenceReasonCode::WeakAnchor,
            EvidenceTier::Review,
            "weak-anchor",
        ),
        (
            EvidenceReasonCode::GenericDetector,
            EvidenceTier::Review,
            "generic-detector",
        ),
        (
            EvidenceReasonCode::GenericAssignment,
            EvidenceTier::Review,
            "generic-assignment",
        ),
        (
            EvidenceReasonCode::EntropyOnly,
            EvidenceTier::Review,
            "entropy-only",
        ),
        (
            EvidenceReasonCode::TestFixture,
            EvidenceTier::Review,
            "test-fixture",
        ),
        (
            EvidenceReasonCode::Documentation,
            EvidenceTier::Review,
            "documentation",
        ),
        (
            EvidenceReasonCode::RuleDefinition,
            EvidenceTier::Review,
            "rule-definition",
        ),
        (
            EvidenceReasonCode::Identifier,
            EvidenceTier::Review,
            "identifier",
        ),
        (
            EvidenceReasonCode::OptionDeclaration,
            EvidenceTier::Review,
            "option-declaration",
        ),
        (
            EvidenceReasonCode::GeneratedMaterial,
            EvidenceTier::Review,
            "generated-material",
        ),
        (
            EvidenceReasonCode::SourceRoleMismatch,
            EvidenceTier::Review,
            "source-role-mismatch",
        ),
        (
            EvidenceReasonCode::VendorPattern,
            EvidenceTier::Likely,
            "vendor-pattern",
        ),
        (
            EvidenceReasonCode::StructuralGrammar,
            EvidenceTier::Confirmed,
            "structural-grammar",
        ),
        (
            EvidenceReasonCode::RequiredCompanion,
            EvidenceTier::Confirmed,
            "required-companion",
        ),
        (
            EvidenceReasonCode::ChecksumValid,
            EvidenceTier::Confirmed,
            "checksum-valid",
        ),
        (
            EvidenceReasonCode::LiveVerification,
            EvidenceTier::Confirmed,
            "live-verification",
        ),
    ];

    for (reason, tier, spelling) in cases {
        let verdict = EvidenceVerdict::from_reason(reason);
        assert_eq!(verdict.tier(), tier, "{reason:?}");
        assert_eq!(reason.as_str(), spelling, "{reason:?}");
        let value = serde_json::to_value(verdict).expect("serialize verdict");
        assert_eq!(value["tier"], tier.as_str());
        assert_eq!(value["reason_code"], spelling);
        assert_eq!(value["provenance"], unattributed_provenance());
        assert_eq!(
            serde_json::from_value::<EvidenceVerdict>(value).expect("round trip"),
            verdict
        );
    }
}

#[test]
fn mismatched_or_extended_verdict_wire_fails_closed() {
    let mismatch = serde_json::json!({
        "tier": "confirmed",
        "reason_code": "documentation",
        "provenance": unattributed_provenance()
    });
    let error = serde_json::from_value::<EvidenceVerdict>(mismatch)
        .expect_err("tier/reason mismatch must fail");
    assert!(error.to_string().contains("does not match reason code"));

    let missing_provenance = serde_json::json!({
        "tier": "review",
        "reason_code": "documentation"
    });
    let error = serde_json::from_value::<EvidenceVerdict>(missing_provenance)
        .expect_err("missing provenance must fail");
    assert!(error.to_string().contains("provenance"));

    let extended = serde_json::json!({
        "tier": "review",
        "reason_code": "documentation",
        "provenance": unattributed_provenance(),
        "legacy_confidence": 0.9
    });
    let error = serde_json::from_value::<EvidenceVerdict>(extended)
        .expect_err("unknown verdict fields must fail");
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn exact_pattern_provenance_round_trips_and_malformed_identity_fails_closed() {
    let provenance = FindingProvenance::pattern(
        0x0123_4567_89ab_cdef,
        17,
        SemanticSourceRole::EnvironmentAssignmentValue,
        EvidenceReasonCode::VendorPattern,
    );
    let verdict =
        EvidenceVerdict::from_reason(EvidenceReasonCode::VendorPattern).with_provenance(provenance);
    let value = serde_json::to_value(verdict).expect("serialize exact provenance");
    assert_eq!(value["provenance"]["schema_version"], 1);
    assert_eq!(value["provenance"]["detector_digest"], "0123456789abcdef");
    assert_eq!(value["provenance"]["pattern_index"], 17);
    assert_eq!(value["provenance"]["candidate_channel"], "pattern");
    assert_eq!(
        serde_json::from_value::<EvidenceVerdict>(value.clone()).expect("round trip"),
        verdict
    );

    for (field, replacement) in [
        ("schema_version", serde_json::json!(2)),
        ("detector_digest", serde_json::json!("ABCDEF")),
        ("pattern_index", serde_json::Value::Null),
        (
            "candidate_channel",
            serde_json::json!(FindingCandidateChannel::GenericAssignment),
        ),
        (
            "context_class",
            serde_json::json!(EvidenceReasonCode::LiveVerification),
        ),
    ] {
        let mut malformed = value.clone();
        malformed["provenance"][field] = replacement;
        assert!(
            serde_json::from_value::<EvidenceVerdict>(malformed).is_err(),
            "{field} mutation must fail closed"
        );
    }

    for context_class in [
        EvidenceReasonCode::Unattributed,
        EvidenceReasonCode::LiveVerification,
    ] {
        let invalid = verdict.with_provenance(FindingProvenance::pattern(
            0x0123_4567_89ab_cdef,
            17,
            SemanticSourceRole::EnvironmentAssignmentValue,
            context_class,
        ));
        assert!(
            serde_json::to_value(invalid).is_err(),
            "scanner-owned provenance must not serialize with {context_class:?} context"
        );
    }

    for field in [
        "schema_version",
        "detector_digest",
        "pattern_index",
        "candidate_channel",
        "source_role",
        "context_class",
    ] {
        let mut missing = value.clone();
        missing["provenance"]
            .as_object_mut()
            .expect("provenance object")
            .remove(field);
        assert!(
            serde_json::from_value::<EvidenceVerdict>(missing).is_err(),
            "missing {field} must fail closed"
        );
    }

    for provenance in [
        FindingProvenance::unattributed(),
        FindingProvenance::generic_assignment(
            0x0123_4567_89ab_cdef,
            SemanticSourceRole::EnvironmentAssignmentValue,
            EvidenceReasonCode::GenericAssignment,
        ),
    ] {
        let mut missing_null = serde_json::to_value(verdict.with_provenance(provenance))
            .expect("serialize provenance");
        missing_null["provenance"]
            .as_object_mut()
            .expect("provenance object")
            .remove("pattern_index");
        assert!(
            serde_json::from_value::<EvidenceVerdict>(missing_null).is_err(),
            "nullable pattern_index remains a required wire field"
        );
    }

    let mut missing_null =
        serde_json::to_value(verdict.with_provenance(FindingProvenance::unattributed()))
            .expect("serialize unattributed provenance");
    missing_null["provenance"]
        .as_object_mut()
        .expect("provenance object")
        .remove("detector_digest");
    assert!(
        serde_json::from_value::<EvidenceVerdict>(missing_null).is_err(),
        "nullable detector_digest remains a required wire field"
    );
}

#[test]
fn stronger_is_order_independent_and_never_downgrades() {
    let review = EvidenceVerdict::from_reason(EvidenceReasonCode::Documentation);
    let likely = EvidenceVerdict::from_reason(EvidenceReasonCode::VendorPattern);
    let structural = EvidenceVerdict::from_reason(EvidenceReasonCode::StructuralGrammar);
    let checksum = EvidenceVerdict::from_reason(EvidenceReasonCode::ChecksumValid);

    for (weaker, stronger) in [
        (review, likely),
        (likely, structural),
        (structural, checksum),
    ] {
        assert_eq!(weaker.stronger(stronger), stronger);
        assert_eq!(stronger.stronger(weaker), stronger);
    }

    let attributed_review = review.with_provenance(FindingProvenance::pattern(
        0,
        0,
        SemanticSourceRole::Unknown,
        EvidenceReasonCode::Documentation,
    ));
    assert_eq!(review.stronger(attributed_review), attributed_review);
    assert_eq!(attributed_review.stronger(review), attributed_review);
}
