use keyhog_profile::{DetectorIdentityInput, DetectorIdentityV2, Evidence, EvidenceGap};

/// Exact corpus and plan digests must survive capture without normalization or truncation.
#[test]
fn capture_preserves_exact_detector_and_plan_identities() {
    let identity = DetectorIdentityV2::capture(DetectorIdentityInput {
        corpus_digest: "corpus-sha256",
        compiled_plan_digest: Some("plan-blake3"),
        enabled_detector_digest: Some("enabled-blake3"),
        backend_database_digest: Some("database-sha256"),
        external_provenance_digest: Some("provenance-sha256"),
    });

    assert_eq!(identity.version, 1);
    assert_eq!(identity.corpus_digest, "corpus-sha256");
    assert_eq!(
        identity.compiled_plan_digest,
        Evidence::recorded("plan-blake3".to_owned())
    );
    assert_eq!(
        identity.enabled_detector_digest,
        Evidence::recorded("enabled-blake3".to_owned())
    );
    assert_eq!(
        identity.backend_database_digest,
        Evidence::recorded("database-sha256".to_owned())
    );
    assert_eq!(
        identity.external_provenance_digest,
        Evidence::recorded("provenance-sha256".to_owned())
    );
}

/// Missing optional detector evidence must remain distinguishable from an empty measured digest.
#[test]
fn capture_reports_unavailable_optional_detector_evidence() {
    let identity = DetectorIdentityV2::capture(DetectorIdentityInput {
        corpus_digest: "corpus-sha256",
        compiled_plan_digest: None,
        enabled_detector_digest: None,
        backend_database_digest: None,
        external_provenance_digest: None,
    });
    let unavailable = Evidence::Unavailable {
        reason: EvidenceGap::Unavailable,
    };

    assert_eq!(identity.compiled_plan_digest, unavailable);
    assert_eq!(identity.enabled_detector_digest, unavailable);
    assert_eq!(identity.backend_database_digest, unavailable);
    assert_eq!(identity.external_provenance_digest, unavailable);
}

/// Empty optional values must not masquerade as recorded identities in persisted evidence.
#[test]
fn capture_rejects_empty_optional_detector_identities_as_unavailable() {
    let identity = DetectorIdentityV2::capture(DetectorIdentityInput {
        corpus_digest: "corpus-sha256",
        compiled_plan_digest: Some(""),
        enabled_detector_digest: Some(""),
        backend_database_digest: Some(""),
        external_provenance_digest: Some(""),
    });

    assert!(matches!(
        identity.compiled_plan_digest,
        Evidence::Unavailable {
            reason: EvidenceGap::Unavailable
        }
    ));
    assert!(matches!(
        identity.external_provenance_digest,
        Evidence::Unavailable {
            reason: EvidenceGap::Unavailable
        }
    ));
}

/// Detector identities must round-trip exactly because profile comparison keys consume them.
#[test]
fn detector_identity_json_round_trip_preserves_every_digest() {
    let identity = DetectorIdentityV2::capture(DetectorIdentityInput {
        corpus_digest: &"a".repeat(64),
        compiled_plan_digest: Some(&"b".repeat(64)),
        enabled_detector_digest: Some(&"c".repeat(64)),
        backend_database_digest: None,
        external_provenance_digest: Some(&"d".repeat(64)),
    });
    let json = serde_json::to_vec(&identity).expect("serialize detector identity");
    let decoded: DetectorIdentityV2 =
        serde_json::from_slice(&json).expect("deserialize detector identity");

    assert_eq!(decoded, identity);
}
