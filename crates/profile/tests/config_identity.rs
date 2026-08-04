use keyhog_profile::{ConfigIdentityInput, ConfigIdentityV2, Evidence, EvidenceGap};

/// Resolved configuration and policy digests must remain exact comparison keys.
#[test]
fn capture_preserves_resolved_configuration_identity() {
    let identity = ConfigIdentityV2::capture(ConfigIdentityInput {
        resolved_config_digest: "resolved-blake3",
        policy_digest: Some("policy-blake3"),
        preset: Some("precision"),
        protection_state: Some("lockdown-applied"),
    });

    assert_eq!(identity.version, 1);
    assert_eq!(identity.resolved_config_digest, "resolved-blake3");
    assert_eq!(
        identity.policy_digest,
        Evidence::recorded("policy-blake3".to_owned())
    );
    assert_eq!(identity.preset, Evidence::recorded("precision".to_owned()));
    assert_eq!(
        identity.protection_state,
        Evidence::recorded("lockdown-applied".to_owned())
    );
}

/// Missing optional policy evidence must be explicit rather than an empty digest or label.
#[test]
fn capture_reports_unavailable_optional_configuration_evidence() {
    let identity = ConfigIdentityV2::capture(ConfigIdentityInput {
        resolved_config_digest: "resolved-blake3",
        policy_digest: None,
        preset: None,
        protection_state: None,
    });
    let unavailable = Evidence::Unavailable {
        reason: EvidenceGap::Unavailable,
    };

    assert_eq!(identity.policy_digest, unavailable);
    assert_eq!(identity.preset, unavailable);
    assert_eq!(identity.protection_state, unavailable);
}

/// Empty labels and digests must not masquerade as recorded configuration evidence.
#[test]
fn capture_treats_empty_optional_configuration_values_as_unavailable() {
    let identity = ConfigIdentityV2::capture(ConfigIdentityInput {
        resolved_config_digest: "resolved-blake3",
        policy_digest: Some(""),
        preset: Some(""),
        protection_state: Some(""),
    });

    assert!(matches!(
        identity.policy_digest,
        Evidence::Unavailable {
            reason: EvidenceGap::Unavailable
        }
    ));
    assert!(matches!(
        identity.protection_state,
        Evidence::Unavailable {
            reason: EvidenceGap::Unavailable
        }
    ));
}

/// Configuration identity JSON must round-trip because persisted profiles compare these fields.
#[test]
fn configuration_identity_json_round_trip_preserves_every_field() {
    let resolved = "a".repeat(64);
    let policy = "b".repeat(64);
    let identity = ConfigIdentityV2::capture(ConfigIdentityInput {
        resolved_config_digest: &resolved,
        policy_digest: Some(&policy),
        preset: Some("deep"),
        protection_state: Some("default-applied"),
    });
    let json = serde_json::to_vec(&identity).expect("serialize config identity");
    let decoded: ConfigIdentityV2 =
        serde_json::from_slice(&json).expect("deserialize config identity");

    assert_eq!(decoded, identity);
}
