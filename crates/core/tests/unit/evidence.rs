use keyhog_core::{EvidenceReasonCode, EvidenceTier, EvidenceVerdict};

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
        "reason_code": "documentation"
    });
    let error = serde_json::from_value::<EvidenceVerdict>(mismatch)
        .expect_err("tier/reason mismatch must fail");
    assert!(error.to_string().contains("does not match reason code"));

    let extended = serde_json::json!({
        "tier": "review",
        "reason_code": "documentation",
        "legacy_confidence": 0.9
    });
    let error = serde_json::from_value::<EvidenceVerdict>(extended)
        .expect_err("unknown verdict fields must fail");
    assert!(error.to_string().contains("unknown field"));
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
}
