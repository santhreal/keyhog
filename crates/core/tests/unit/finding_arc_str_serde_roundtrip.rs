//! Migrated from `src/finding.rs` `arc_from_cow_tests` (KH-GAP-004).
//!
//! `arc_from_cow` is the private deserialize helper behind `serde_arc_str`,
//! which backs `RawMatch`'s `Arc<str>` fields (`detector_id`, `detector_name`,
//! `service`). The inline tests poked the helper directly; here the SAME
//! "Cow -> Arc<str> preserves the exact bytes" guarantee is exercised
//! end-to-end through the public `RawMatch` serde round-trip, covering the
//! borrowed, owned, empty, and multibyte cases.

use keyhog_core::{MatchLocation, RawMatch, Severity};
use std::collections::HashMap;

/// Build a `RawMatch` with the given `Arc<str>` field values, then round-trip it
/// through serde so the returned value came out of the `serde_arc_str`
/// deserialize path (`arc_from_cow`).
fn roundtrip(detector_id: &str, detector_name: &str, service: &str) -> RawMatch {
    let original = RawMatch {
        detector_id: detector_id.into(),
        detector_name: detector_name.into(),
        service: service.into(),
        severity: Severity::Low,
        credential: "key-value".into(),
        credential_hash: [0; 32].into(),
        companions: HashMap::new(),
        location: MatchLocation {
            source: "fs".into(),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.5),
    };
    let json = serde_json::to_string(&original).expect("RawMatch serializes");
    serde_json::from_str(&json).expect("RawMatch deserializes")
}

#[test]
fn deserialized_arc_str_preserves_borrowed_token() {
    let back = roundtrip("ghp_borrowed_token", "GitHub PAT", "github");
    assert_eq!(back.detector_id.as_ref(), "ghp_borrowed_token");
    assert_eq!(back.detector_id.len(), 18);
}

#[test]
fn deserialized_arc_str_preserves_owned_value() {
    let back = roundtrip("id", "owned-secret-42", "svc");
    assert_eq!(back.detector_name.as_ref(), "owned-secret-42");
    assert_eq!(back.detector_name.len(), 15);
}

#[test]
fn deserialized_empty_arc_str_stays_empty() {
    let back = roundtrip("id", "name", "");
    assert_eq!(back.service.as_ref(), "");
    assert_eq!(back.service.len(), 0);
    assert!(back.service.is_empty());
}

#[test]
fn deserialized_arc_str_preserves_multibyte_bytes() {
    // Adversarial: non-ASCII, mixed-width. Precomposed é (U+00E9, 2 bytes) and
    // a 4-byte emoji key, so 9 chars = 13 UTF-8 bytes. Every byte must survive.
    let value = "caf\u{e9}-\u{1f511}key";
    let back = roundtrip(value, "name", "svc");
    assert_eq!(back.detector_id.as_ref(), "caf\u{e9}-\u{1f511}key");
    assert_eq!(back.detector_id.len(), 13);
    assert_eq!(back.detector_id.chars().count(), 9);
}
