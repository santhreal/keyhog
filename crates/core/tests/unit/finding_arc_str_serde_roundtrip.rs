//! Migrated from `src/finding.rs` `arc_from_cow_tests` (KH-GAP-004).
//!
//! `arc_from_cow` is the private deserialize helper behind `serde_arc_str`,
//! which backs `RawMatch`'s `Arc<str>` fields (`detector_id`, `detector_name`,
//! and `service`). The exact byte-preservation guarantee is exercised through
//! the public historical `RawMatch` deserialize path. RawMatch output is
//! intentionally fail closed because it contains a `SensitiveString`; safe
//! output uses `RawMatch::to_redacted()`.

use keyhog_core::RawMatch;

/// Deserialize a historical protected-wire `RawMatch` with the supplied string fields.
fn deserialize(detector_id: &str, detector_name: &str, service: &str) -> RawMatch {
    serde_json::from_value(serde_json::json!({
        "detector_id": detector_id,
        "detector_name": detector_name,
        "service": service,
        "severity": "low",
        "credential": "key-value",
        "credential_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "companions": {},
        "location": {
            "source": "fs",
            "file_path": null,
            "line": null,
            "offset": 0,
            "commit": null,
            "author": null,
            "date": null
        },
        "confidence": 0.5,
        "evidence": {
            "tier": "review",
            "reason_code": "unattributed",
            "provenance": {
                "schema_version": 1,
                "detector_digest": null,
                "pattern_index": null,
                "candidate_channel": "unattributed",
                "source_role": "unknown",
                "context_class": "unattributed"
            }
        }
    }))
    .expect("historical RawMatch input deserializes")
}

#[test]
fn deserialized_arc_str_preserves_borrowed_token() {
    let back = deserialize("ghp_borrowed_token", "GitHub PAT", "github");
    assert_eq!(back.detector_id.as_ref(), "ghp_borrowed_token");
    assert_eq!(back.detector_id.len(), 18);
}

#[test]
fn deserialized_arc_str_preserves_owned_value() {
    let back = deserialize("id", "owned-secret-42", "svc");
    assert_eq!(back.detector_name.as_ref(), "owned-secret-42");
    assert_eq!(back.detector_name.len(), 15);
}

#[test]
fn deserialized_empty_arc_str_stays_empty() {
    let back = deserialize("id", "name", "");
    assert_eq!(back.service.as_ref(), "");
    assert_eq!(back.service.len(), 0);
    assert!(back.service.is_empty());
}

#[test]
fn deserialized_arc_str_preserves_multibyte_bytes() {
    // Adversarial: non-ASCII, mixed-width. Precomposed é (U+00E9, 2 bytes) and
    // a 4-byte emoji key, so 9 chars = 13 UTF-8 bytes. Every byte must survive.
    let value = "caf\u{e9}-\u{1f511}key";
    let back = deserialize(value, "name", "svc");
    assert_eq!(back.detector_id.as_ref(), "caf\u{e9}-\u{1f511}key");
    assert_eq!(back.detector_id.len(), 13);
    assert_eq!(back.detector_id.chars().count(), 9);
}
