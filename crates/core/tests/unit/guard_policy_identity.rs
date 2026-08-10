//! Policy identity and receipt conservation tests for the guard state.

use keyhog_core::guard_state::{
    GitCleanAttestation, GitHashAlgorithm, GuardPolicyIdentity, GuardReceipt, GuardRootState,
    GUARD_SCHEMA_VERSION,
};

fn sample_identity() -> GuardPolicyIdentity {
    GuardPolicyIdentity {
        build_identity: "abc123".to_string(),
        detector_digest: "deadbeef".to_string(),
        suppression_digest: "cafef00d".to_string(),
        keyhogignore_digest: String::new(),
        config_digest: "feedface".to_string(),
        decode_policy_version: 1,
        source_policy_digest: "baadf00d".to_string(),
        guard_schema_version: GUARD_SCHEMA_VERSION,
        report_semantics_version: 1,
    }
}

#[test]
fn identical_identities_are_compatible() {
    let a = sample_identity();
    let b = sample_identity();
    assert!(a.is_compatible_with(&b));
}

#[test]
fn detector_digest_change_breaks_compatibility() {
    let mut a = sample_identity();
    let mut b = sample_identity();
    b.detector_digest = "changed".to_string();
    assert!(!a.is_compatible_with(&b));
    a.detector_digest = "changed".to_string();
    assert!(a.is_compatible_with(&b));
}

#[test]
fn build_identity_change_breaks_compatibility() {
    let a = sample_identity();
    let mut b = sample_identity();
    b.build_identity = "different".to_string();
    assert!(!a.is_compatible_with(&b));
}

#[test]
fn suppression_digest_change_breaks_compatibility() {
    let a = sample_identity();
    let mut b = sample_identity();
    b.suppression_digest = "changed".to_string();
    assert!(!a.is_compatible_with(&b));
}

#[test]
fn config_digest_change_breaks_compatibility() {
    let a = sample_identity();
    let mut b = sample_identity();
    b.config_digest = "changed".to_string();
    assert!(!a.is_compatible_with(&b));
}

#[test]
fn decode_policy_version_change_breaks_compatibility() {
    let a = sample_identity();
    let mut b = sample_identity();
    b.decode_policy_version = 2;
    assert!(!a.is_compatible_with(&b));
}

#[test]
fn source_policy_digest_change_breaks_compatibility() {
    let a = sample_identity();
    let mut b = sample_identity();
    b.source_policy_digest = "changed".to_string();
    assert!(!a.is_compatible_with(&b));
}

#[test]
fn guard_schema_version_change_breaks_compatibility() {
    let a = sample_identity();
    let mut b = sample_identity();
    b.guard_schema_version = 2;
    assert!(!a.is_compatible_with(&b));
}

#[test]
fn keyhogignore_digest_change_breaks_compatibility() {
    let a = sample_identity();
    let mut b = sample_identity();
    b.keyhogignore_digest = "changed".to_string();
    assert!(!a.is_compatible_with(&b));
}

#[test]
fn report_semantics_version_change_breaks_compatibility() {
    let a = sample_identity();
    let mut b = sample_identity();
    b.report_semantics_version = 2;
    assert!(!a.is_compatible_with(&b));
}

#[test]
fn short_digest_is_12_hex_chars() {
    let id = sample_identity();
    let short = id.short_digest().unwrap();
    assert_eq!(short.len(), 12);
    assert!(short.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn short_digest_is_deterministic() {
    let id = sample_identity();
    let a = id.short_digest().unwrap();
    let b = id.short_digest().unwrap();
    assert_eq!(a, b);
}

#[test]
fn short_digest_differs_on_field_change() {
    let id = sample_identity();
    let a = id.short_digest().unwrap();
    let mut id2 = id;
    id2.detector_digest = "different".to_string();
    let b = id2.short_digest().unwrap();
    assert_ne!(a, b);
}

#[test]
fn receipt_conservation_valid_when_balanced() {
    let receipt = GuardReceipt {
        objects_requested: 10,
        objects_hit: 3,
        objects_scanned: 5,
        objects_skipped: 2,
        bytes_requested: 1000,
        bytes_hit: 300,
        bytes_scanned: 700,
        findings_count: 0,
        coverage_gaps: 0,
        terminal_state: GuardRootState::Current,
        policy_identity: sample_identity(),
        terminal_sequence: 42,
    };
    assert!(receipt.validate_conservation().is_ok());
}

#[test]
fn receipt_object_mismatch_detected() {
    let receipt = GuardReceipt {
        objects_requested: 10,
        objects_hit: 3,
        objects_scanned: 5,
        objects_skipped: 1, // 3+5+1=9 != 10
        bytes_requested: 1000,
        bytes_hit: 300,
        bytes_scanned: 700,
        findings_count: 0,
        coverage_gaps: 0,
        terminal_state: GuardRootState::Current,
        policy_identity: sample_identity(),
        terminal_sequence: 42,
    };
    assert!(receipt.validate_conservation().is_err());
}

#[test]
fn receipt_byte_mismatch_detected() {
    let receipt = GuardReceipt {
        objects_requested: 10,
        objects_hit: 3,
        objects_scanned: 5,
        objects_skipped: 2,
        bytes_requested: 1000,
        bytes_hit: 300,
        bytes_scanned: 600, // 300+600=900 != 1000
        findings_count: 0,
        coverage_gaps: 0,
        terminal_state: GuardRootState::Current,
        policy_identity: sample_identity(),
        terminal_sequence: 42,
    };
    assert!(receipt.validate_conservation().is_err());
}

#[test]
fn receipt_with_skipped_only_conserves() {
    let receipt = GuardReceipt {
        objects_requested: 3,
        objects_hit: 0,
        objects_scanned: 0,
        objects_skipped: 3,
        bytes_requested: 0,
        bytes_hit: 0,
        bytes_scanned: 0,
        findings_count: 0,
        coverage_gaps: 0,
        terminal_state: GuardRootState::Current,
        policy_identity: sample_identity(),
        terminal_sequence: 1,
    };
    assert!(receipt.validate_conservation().is_ok());
}

#[test]
fn clean_attestation_serializes_without_secrets() {
    let att = GitCleanAttestation {
        hash_algorithm: GitHashAlgorithm::Sha1,
        blob_oid: "abc123def456".to_string(),
        object_size: 1024,
        policy_identity: sample_identity(),
        last_seen_sequence: 7,
    };
    let json = serde_json::to_string(&att).unwrap();
    // The JSON should not contain any credential-like fields.
    // It should contain the OID and size but no payload bytes.
    assert!(json.contains("abc123def456"));
    assert!(!json.contains("password"));
    assert!(!json.contains("secret"));
    assert!(!json.contains("token"));

    // Round-trip
    let back: GitCleanAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(att, back);
}

#[test]
fn policy_identity_serializes_with_all_fields() {
    let id = sample_identity();
    let json = serde_json::to_string(&id).unwrap();
    let back: GuardPolicyIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn guard_schema_version_is_one() {
    assert_eq!(GUARD_SCHEMA_VERSION, 1);
}
