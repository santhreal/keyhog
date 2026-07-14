//! Regression: `RawMatch` / `MatchLocation` / `RedactedFinding` /
//! `VerifiedFinding` / `Severity` serde contract.
//!
//! Pins the EXACT on-wire JSON shape of keyhog's core finding types, read off
//! the real implementation in `crates/core/src/finding.rs` and the `Severity`
//! enum in `crates/core/src/spec.rs`:
//!
//!   * `RawMatch` derives `Serialize`/`Deserialize`; its `Arc<str>` fields use
//!     `serde_arc_str` (plain string), `credential` is a `SensitiveString`
//!     (serialized as the plaintext string on this internal wire type),
//!     `credential_hash` is a `CredentialHash` (`serde(transparent)` +
//!     `serde_hash_hex` → 64-char lower-case hex), and `entropy`/`confidence`
//!     are `Option<f64>` with `skip_serializing_if = "Option::is_none"`.
//!   * `Severity` is `serde(rename_all = "kebab-case")` with a `client_safe`
//!     alias on the `ClientSafe` variant.
//!   * `credential_hash` deserialization fails closed on any string that is not
//!     exactly 64 hex chars.
//!   * `VerifiedFinding` has a hand-written `Serialize` that adds a
//!     `remediation` field and emits `metadata` in sorted-key order.
//!
//! Every assertion is a concrete expected value. `is_empty()` / `is_some()` are
//! never used as the sole assertion of a test.

use std::collections::HashMap;

use keyhog_core::{
    hex_encode, sha256_hash, MatchLocation, RawMatch, Severity, VerificationResult, VerifiedFinding,
};

/// SHA-256("AKIAIOSFODNN7EXAMPLE"), lower-case hex. Computed independently via
/// `printf 'AKIAIOSFODNN7EXAMPLE' | sha256sum`.
const AKIA_HASH_HEX: &str = "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3";
const AKIA_PLAINTEXT: &str = "AKIAIOSFODNN7EXAMPLE";

/// Canonical, fully-populated `RawMatch` used across the round-trip tests.
fn make_raw() -> RawMatch {
    RawMatch {
        detector_id: "aws-access-key-id".into(),
        detector_name: "AWS Access Key ID".into(),
        service: "aws".into(),
        severity: Severity::Critical,
        credential: AKIA_PLAINTEXT.into(),
        credential_hash: sha256_hash(AKIA_PLAINTEXT),
        companions: HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("config/prod.env".into()),
            line: Some(42),
            offset: 100,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.5),
        confidence: Some(0.9),
    }
}

#[test]
fn raw_match_serializes_exact_field_names_and_values() {
    let raw = make_raw();
    let value = serde_json::to_value(&raw).expect("serialize RawMatch");

    assert_eq!(value["detector_id"].as_str(), Some("aws-access-key-id"));
    assert_eq!(value["detector_name"].as_str(), Some("AWS Access Key ID"));
    assert_eq!(value["service"].as_str(), Some("aws"));
    assert_eq!(value["severity"].as_str(), Some("critical"));
    // Internal wire type: credential is the plaintext string.
    assert_eq!(value["credential"].as_str(), Some(AKIA_PLAINTEXT));
    assert_eq!(value["credential_hash"].as_str(), Some(AKIA_HASH_HEX));
    assert_eq!(value["location"]["source"].as_str(), Some("filesystem"));
    assert_eq!(
        value["location"]["file_path"].as_str(),
        Some("config/prod.env")
    );
    assert_eq!(value["location"]["line"].as_u64(), Some(42));
    assert_eq!(value["location"]["offset"].as_u64(), Some(100));
    assert_eq!(value["entropy"].as_f64(), Some(4.5));
    assert_eq!(value["confidence"].as_f64(), Some(0.9));
}

#[test]
fn raw_match_roundtrips_equal_via_partial_eq() {
    let raw = make_raw();
    let json = serde_json::to_string(&raw).expect("serialize RawMatch");
    let back: RawMatch = serde_json::from_str(&json).expect("deserialize RawMatch");

    // RawMatch's manual PartialEq compares every field including the hash and
    // the total-ordered floats.
    assert_eq!(raw, back);
    // And spot-check the load-bearing fields survive individually.
    assert_eq!(&*back.detector_id, "aws-access-key-id");
    assert_eq!(&*back.service, "aws");
    assert_eq!(back.severity, Severity::Critical);
    assert_eq!(&*back.credential, AKIA_PLAINTEXT);
    assert_eq!(back.location.line, Some(42));
    assert_eq!(back.credential_hash, sha256_hash(AKIA_PLAINTEXT));
}

#[test]
fn raw_match_credential_hash_is_exact_64_char_lowercase_hex() {
    let raw = make_raw();
    let value = serde_json::to_value(&raw).expect("serialize RawMatch");
    let hash = value["credential_hash"].as_str().expect("hash is a string");

    assert_eq!(hash.len(), 64);
    assert_eq!(hash, AKIA_HASH_HEX);
    assert!(hash
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    // The serde form matches the documented hex_encode(sha256_hash(..)) pipeline.
    assert_eq!(hash, hex_encode(sha256_hash(AKIA_PLAINTEXT)));
}

#[test]
fn raw_match_unknown_field_is_ignored_on_deserialize() {
    let raw = make_raw();
    let mut value = serde_json::to_value(&raw).expect("serialize RawMatch");
    value.as_object_mut().expect("object").insert(
        "field_from_a_future_version".to_string(),
        serde_json::json!(123),
    );

    let back: RawMatch = serde_json::from_value(value).expect("unknown field must be ignored");
    assert_eq!(raw, back);
}

#[test]
fn raw_match_missing_optional_floats_default_to_none() {
    let raw = make_raw();
    let mut value = serde_json::to_value(&raw).expect("serialize RawMatch");
    let obj = value.as_object_mut().expect("object");
    obj.remove("entropy");
    obj.remove("confidence");

    let back: RawMatch = serde_json::from_value(value).expect("optional floats default None");
    assert_eq!(back.entropy, None);
    assert_eq!(back.confidence, None);
    // Everything else still preserved.
    assert_eq!(&*back.detector_id, "aws-access-key-id");
    assert_eq!(back.severity, Severity::Critical);
}

#[test]
fn raw_match_none_floats_are_omitted_from_output() {
    let mut raw = make_raw();
    raw.entropy = None;
    raw.confidence = None;
    let value = serde_json::to_value(&raw).expect("serialize RawMatch");
    let obj = value.as_object().expect("object");

    assert!(!obj.contains_key("entropy"));
    assert!(!obj.contains_key("confidence"));
    // Required fields are still present.
    assert_eq!(
        obj.get("credential_hash").and_then(|v| v.as_str()),
        Some(AKIA_HASH_HEX)
    );
    assert_eq!(
        obj.get("severity").and_then(|v| v.as_str()),
        Some("critical")
    );
}

#[test]
fn severity_serializes_exact_kebab_case_strings() {
    let cases = [
        (Severity::Info, "info"),
        (Severity::ClientSafe, "client-safe"),
        (Severity::Low, "low"),
        (Severity::Medium, "medium"),
        (Severity::High, "high"),
        (Severity::Critical, "critical"),
    ];
    for (severity, expected) in cases {
        let value = serde_json::to_value(severity).expect("serialize Severity");
        assert_eq!(value.as_str(), Some(expected), "variant {severity:?}");
    }
}

#[test]
fn severity_deserializes_canonical_and_alias_forms() {
    let canonical: Severity =
        serde_json::from_str("\"client-safe\"").expect("kebab-case client-safe");
    assert_eq!(canonical, Severity::ClientSafe);

    let alias: Severity = serde_json::from_str("\"client_safe\"").expect("snake_case alias");
    assert_eq!(alias, Severity::ClientSafe);

    let critical: Severity = serde_json::from_str("\"critical\"").expect("critical");
    assert_eq!(critical, Severity::Critical);
}

#[test]
fn severity_rejects_unknown_label() {
    let result = serde_json::from_str::<Severity>("\"catastrophic\"");
    let err = result.expect_err("unknown severity label must fail");
    assert!(
        err.to_string().contains("catastrophic") || err.to_string().contains("unknown variant"),
        "unexpected error message: {err}"
    );
}

#[test]
fn credential_hash_rejects_wrong_length_string() {
    // 63 hex chars (one short) must fail closed.
    let short_hex = "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb"; // 63 chars
    assert_eq!(short_hex.len(), 63);
    let mut value = serde_json::to_value(make_raw()).expect("serialize");
    value.as_object_mut().unwrap().insert(
        "credential_hash".to_string(),
        serde_json::Value::String(short_hex.to_string()),
    );

    let result = serde_json::from_value::<RawMatch>(value);
    let err = result.expect_err("short hash must fail");
    assert!(
        err.to_string().contains("64-char hex SHA-256 digest"),
        "unexpected error message: {err}"
    );
}

#[test]
fn credential_hash_rejects_non_hex_64_char_string() {
    // 64 chars but 'z' is not a hex digit.
    let bad_hex: String = std::iter::repeat('z').take(64).collect();
    assert_eq!(bad_hex.len(), 64);
    let mut value = serde_json::to_value(make_raw()).expect("serialize");
    value.as_object_mut().unwrap().insert(
        "credential_hash".to_string(),
        serde_json::Value::String(bad_hex),
    );

    let result = serde_json::from_value::<RawMatch>(value);
    let err = result.expect_err("non-hex hash must fail");
    // hex::decode_to_slice surfaces an "Invalid character" style error.
    let msg = err.to_string();
    assert!(
        msg.to_ascii_lowercase().contains("invalid")
            || msg.to_ascii_lowercase().contains("character"),
        "unexpected error message: {msg}"
    );
}

#[test]
fn match_location_serializes_absent_fields_as_null() {
    let location = MatchLocation {
        source: "git".into(),
        file_path: None,
        line: None,
        offset: 7,
        commit: Some("deadbeef".into()),
        author: None,
        date: None,
    };
    let value = serde_json::to_value(&location).expect("serialize MatchLocation");

    assert_eq!(value["source"].as_str(), Some("git"));
    assert_eq!(value["file_path"], serde_json::Value::Null);
    assert_eq!(value["line"], serde_json::Value::Null);
    assert_eq!(value["offset"].as_u64(), Some(7));
    assert_eq!(value["commit"].as_str(), Some("deadbeef"));
    assert_eq!(value["author"], serde_json::Value::Null);
    assert_eq!(value["date"], serde_json::Value::Null);

    // Round-trip preserves the exact structure via derived PartialEq.
    let back: MatchLocation = serde_json::from_value(value).expect("deserialize MatchLocation");
    assert_eq!(location, back);
}

#[test]
fn redacted_finding_serializes_without_plaintext_and_roundtrips() {
    let raw = make_raw();
    let redacted = raw.to_redacted();
    let value = serde_json::to_value(&redacted).expect("serialize RedactedFinding");
    let obj = value.as_object().expect("object");

    // The plaintext credential never appears; only the redacted preview + hash.
    assert!(!obj.contains_key("credential"));
    assert!(obj.contains_key("credential_redacted"));
    let preview = value["credential_redacted"]
        .as_str()
        .expect("preview string");
    assert_ne!(preview, AKIA_PLAINTEXT);
    assert_eq!(value["credential_hash"].as_str(), Some(AKIA_HASH_HEX));
    assert_eq!(value["detector_id"].as_str(), Some("aws-access-key-id"));
    assert_eq!(value["severity"].as_str(), Some("critical"));

    // Round-trip: the redacted preview + hash + location survive intact.
    // Clone so earlier `&str` borrows into `value` (e.g. `preview`) stay valid.
    let back: keyhog_core::RedactedFinding =
        serde_json::from_value(value.clone()).expect("deserialize RedactedFinding");
    assert_eq!(&*back.detector_id, "aws-access-key-id");
    assert_eq!(&*back.credential_redacted, preview);
    assert_eq!(back.credential_hash, sha256_hash(AKIA_PLAINTEXT));
    assert_eq!(back.location.line, Some(42));
}

#[test]
fn verified_finding_serialize_adds_remediation_and_sorts_metadata() {
    let mut metadata = HashMap::new();
    metadata.insert("zeta_key".to_string(), "z".to_string());
    metadata.insert("alpha_key".to_string(), "a".to_string());
    let companions_redacted = HashMap::from([
        ("zeta_context".to_string(), "z...9".to_string()),
        ("alpha_context".to_string(), "a...1".to_string()),
    ]);

    let finding = VerifiedFinding {
        detector_id: "aws-access-key-id".into(),
        detector_name: "AWS Access Key ID".into(),
        service: "aws".into(),
        severity: Severity::Critical,
        credential_redacted: "AK****LE".into(),
        credential_hash: sha256_hash(AKIA_PLAINTEXT),
        companions_redacted,
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("config/prod.env".into()),
            line: Some(42),
            offset: 100,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata,
        additional_locations: Vec::new(),
        entropy: None,
        confidence: Some(0.9),
    };

    let text = serde_json::to_string(&finding).expect("serialize VerifiedFinding");
    let value: serde_json::Value = serde_json::from_str(&text).expect("reparse");
    let obj = value.as_object().expect("object");

    // Custom Serialize adds `companions_redacted` and `remediation`.
    assert_eq!(obj.len(), 13);
    assert!(obj.contains_key("remediation"));
    assert!(value["remediation"]["action"].is_string());

    // snake_case verification tag.
    assert_eq!(value["verification"].as_str(), Some("unverifiable"));
    assert_eq!(value["credential_hash"].as_str(), Some(AKIA_HASH_HEX));
    assert_eq!(value["credential_redacted"].as_str(), Some("AK****LE"));
    assert_eq!(value["confidence"].as_f64(), Some(0.9));
    assert_eq!(value["additional_locations"], serde_json::json!([]));
    assert_eq!(
        value["companions_redacted"],
        serde_json::json!({"alpha_context": "a...1", "zeta_context": "z...9"})
    );

    // metadata is emitted in sorted-key order: "alpha_key" precedes "zeta_key"
    // in the raw serialized byte stream regardless of HashMap iteration order.
    let alpha_at = text.find("alpha_key").expect("alpha_key present");
    let zeta_at = text.find("zeta_key").expect("zeta_key present");
    assert!(alpha_at < zeta_at, "metadata keys must be sorted: {text}");
}

#[test]
fn verified_finding_error_verification_serializes_as_tagged_object() {
    let finding = VerifiedFinding {
        detector_id: "aws-access-key-id".into(),
        detector_name: "AWS Access Key ID".into(),
        service: "aws".into(),
        severity: Severity::High,
        credential_redacted: "AK****LE".into(),
        credential_hash: sha256_hash(AKIA_PLAINTEXT),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Error("connection timed out".to_string()),
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        entropy: None,
        confidence: None,
    };

    let value = serde_json::to_value(&finding).expect("serialize VerifiedFinding");
    // Externally-tagged snake_case: Error(String) => {"error": "..."}.
    assert_eq!(
        value["verification"]["error"].as_str(),
        Some("connection timed out")
    );
    // confidence is None => omitted; field_count == 12.
    let obj = value.as_object().expect("object");
    assert!(!obj.contains_key("confidence"));
    assert_eq!(obj.len(), 12);
    assert_eq!(value["severity"].as_str(), Some("high"));
}
