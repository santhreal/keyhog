use keyhog_profile::{Evidence, EvidenceGap, SourceIdentityInput, SourceIdentityV2};

/// Adapter names and safe target digests must survive capture as exact comparison evidence.
#[test]
fn capture_preserves_source_target_identity_and_normalizes_adapters() {
    let identity = SourceIdentityV2::capture(SourceIdentityInput {
        adapters: vec![
            "stdin".to_owned(),
            "filesystem".to_owned(),
            "stdin".to_owned(),
        ],
        target_digest: Some("target-sha256"),
        partition_digest: Some("partition-sha256"),
    });

    assert_eq!(identity.version, 1);
    assert_eq!(identity.adapters, ["filesystem", "stdin"]);
    assert_eq!(
        identity.target_digest,
        Evidence::recorded("target-sha256".to_owned())
    );
    assert_eq!(
        identity.partition_digest,
        Evidence::recorded("partition-sha256".to_owned())
    );
}

/// Missing target evidence must remain distinguishable from a measured empty target set.
#[test]
fn capture_reports_unavailable_source_target_evidence() {
    let identity = SourceIdentityV2::capture(SourceIdentityInput {
        adapters: vec!["stdin".to_owned()],
        target_digest: None,
        partition_digest: None,
    });
    let unavailable = Evidence::Unavailable {
        reason: EvidenceGap::Unavailable,
    };

    assert_eq!(identity.target_digest, unavailable);
    assert_eq!(identity.partition_digest, unavailable);
}

/// Empty digest strings must not masquerade as recorded source identities.
#[test]
fn capture_treats_empty_source_digests_as_unavailable() {
    let identity = SourceIdentityV2::capture(SourceIdentityInput {
        adapters: vec!["filesystem".to_owned()],
        target_digest: Some(""),
        partition_digest: Some(""),
    });

    assert!(matches!(
        identity.target_digest,
        Evidence::Unavailable {
            reason: EvidenceGap::Unavailable
        }
    ));
    assert!(matches!(
        identity.partition_digest,
        Evidence::Unavailable {
            reason: EvidenceGap::Unavailable
        }
    ));
}

/// Source identity JSON must round-trip without exposing any raw target values.
#[test]
fn source_identity_json_round_trip_contains_only_adapters_and_digests() {
    let target = "a".repeat(64);
    let partition = "b".repeat(64);
    let identity = SourceIdentityV2::capture(SourceIdentityInput {
        adapters: vec!["web".to_owned()],
        target_digest: Some(&target),
        partition_digest: Some(&partition),
    });
    let json = serde_json::to_string(&identity).expect("serialize source identity");
    let decoded: SourceIdentityV2 =
        serde_json::from_str(&json).expect("deserialize source identity");

    assert_eq!(decoded, identity);
    assert_eq!(json.matches(&target).count(), 1);
    assert_eq!(json.matches(&partition).count(), 1);
}
