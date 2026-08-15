//! Regression coverage for fail-closed `SensitiveString` serialization.
//!
//! Source chunks and raw matches can contain plaintext credentials. Their
//! derived serializers must not turn an accidental logging, network, or disk
//! boundary into a secret exfiltration path. A caller that intentionally owns a
//! protected private channel must expose the string explicitly with `as_str()`.

use std::collections::HashMap;

use keyhog_core::{
    sha256_hash, Chunk, ChunkMetadata, MatchLocation, RawMatch, SensitiveString, Severity,
};

const SECRET: &str = "kh_live_serialization_boundary_secret";

fn raw_match() -> RawMatch {
    RawMatch {
        detector_id: "serialization-boundary".into(),
        detector_name: "Serialization Boundary".into(),
        service: "keyhog-test".into(),
        severity: Severity::Critical,
        credential: SECRET.into(),
        credential_hash: sha256_hash(SECRET),
        companions: HashMap::new(),
        location: MatchLocation {
            source: "memory".into(),
            file_path: Some("fixture.env".into()),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.25),
        confidence: Some(0.99),
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    }
}

/// Locks out direct serde exfiltration of a standalone secret wrapper.
#[test]
fn standalone_sensitive_string_refuses_implicit_serialization() {
    let secret = SensitiveString::from(SECRET);
    let error = serde_json::to_string(&secret)
        .expect_err("implicit SensitiveString serialization must fail closed")
        .to_string();

    assert_eq!(
        error,
        "SensitiveString refuses implicit plaintext serialization; call as_str() explicitly only for a protected private channel"
    );
    assert!(!error.contains(SECRET));
}

/// Locks out plaintext leakage through the public raw-match serde surface.
#[test]
fn raw_match_serialization_fails_without_emitting_the_credential() {
    let mut output = Vec::new();
    let error = serde_json::to_writer(&mut output, &raw_match())
        .expect_err("RawMatch must not serialize its plaintext credential")
        .to_string();

    assert!(!String::from_utf8_lossy(&output).contains(SECRET));
    assert!(!error.contains(SECRET));
    assert!(error.contains("SensitiveString refuses implicit plaintext serialization"));
}

/// Locks out plaintext leakage when a complete source chunk is serialized.
#[test]
fn source_chunk_serialization_fails_without_emitting_source_text() {
    let chunk = Chunk {
        data: SECRET.into(),
        metadata: ChunkMetadata {
            source_type: "memory".into(),
            path: Some("fixture.env".into()),
            ..ChunkMetadata::default()
        },
    };
    let mut output = Vec::new();
    let error = serde_json::to_writer(&mut output, &chunk)
        .expect_err("Chunk must not serialize its sensitive source bytes")
        .to_string();

    assert!(!String::from_utf8_lossy(&output).contains(SECRET));
    assert!(!error.contains(SECRET));
    assert!(error.contains("SensitiveString refuses implicit plaintext serialization"));
}

/// Locks out container-based bypasses that previously serialized every secret.
#[test]
fn nested_sensitive_strings_fail_closed_before_plaintext_is_written() {
    let secrets = vec![
        SensitiveString::from(SECRET),
        SensitiveString::from("second-secret"),
    ];
    let mut output = Vec::new();
    let error = serde_json::to_writer(&mut output, &secrets)
        .expect_err("nested SensitiveString values must retain the same fail-closed boundary")
        .to_string();

    let partial = String::from_utf8_lossy(&output);
    assert!(!partial.contains(SECRET));
    assert!(!partial.contains("second-secret"));
    assert!(error.contains("SensitiveString refuses implicit plaintext serialization"));
}

/// Proves plaintext serialization remains possible only after an explicit reveal.
#[test]
fn explicit_as_str_serialization_preserves_exact_private_channel_bytes() {
    let secret = SensitiveString::from(SECRET);
    let encoded = serde_json::to_string(secret.as_str())
        .expect("an explicit as_str reveal is an intentional serialization boundary");

    assert_eq!(encoded, format!("\"{SECRET}\""));
}

/// Preserves compatibility for explicitly supplied historical plaintext input.
#[test]
fn sensitive_string_deserialization_still_accepts_exact_private_wire_text() {
    let encoded = format!("\"{SECRET}\"");
    let decoded: SensitiveString =
        serde_json::from_str(&encoded).expect("historical private wire text must remain readable");

    assert_eq!(decoded.as_str(), SECRET);
}
