//! Regression: the `confidence` FIELD on the core finding types
//! (`RawMatch`, `VerifiedFinding`, `RedactedFinding`).
//!
//! This pins the serde + ordering contract of the `confidence: Option<f64>`
//! field specifically, read off `crates/core/src/finding.rs`:
//!
//!   * `RawMatch.confidence` / `RedactedFinding.confidence` are
//!     `Option<f64>` with `#[serde(skip_serializing_if = "Option::is_none")]`,
//!     so `None` is OMITTED but `Some(0.0)` is PRESENT.
//!   * `VerifiedFinding` has a hand-written `Serialize` that bumps its field
//!     count from 11 to 12 iff `confidence.is_some()` (so `Some(0.0)` => 12,
//!     `None` => 11), emitting `confidence` as a bare JSON number.
//!   * `RawMatch::Ord` sorts HIGHER confidence first, treating a `None`
//!     confidence as `0.0` (lowest) for ordering only (LAW10 recall-safe).
//!   * `to_redacted()` copies `confidence` through byte-for-byte.
//!
//! Distinct from `regression_confidence_scoring.rs` (the scanner scoring math)
//! and the scanner `min_confidence` gate tests: this file is ONLY the core
//! `Finding` field's serde shape, bounds, and ordering use.
//!
//! Every assertion is a concrete expected value; no bare `is_empty()` /
//! `is_some()` sole assertions.

use std::collections::HashMap;

use keyhog_core::{
    dedup_matches, sha256_hash, DedupScope, MatchLocation, RawMatch, RedactedFinding, Severity,
    VerificationResult, VerifiedFinding,
};

const AKIA_PLAINTEXT: &str = "AKIAIOSFODNN7EXAMPLE";

/// Canonical `RawMatch` with a supplied confidence.
fn make_raw(confidence: Option<f64>) -> RawMatch {
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
        confidence,
    }
}

fn make_verified(confidence: Option<f64>) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "aws-access-key-id".into(),
        detector_name: "AWS Access Key ID".into(),
        service: "aws".into(),
        severity: Severity::Critical,
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
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        entropy: None,
        confidence,
    }
}

#[test]
fn measured_entropy_survives_redaction_dedup_and_verified_serialization() {
    let raw = make_raw(Some(0.91));
    let redacted = raw.to_redacted();
    assert_eq!(redacted.entropy, Some(4.5));

    let group = dedup_matches(vec![raw], &DedupScope::Credential)
        .into_iter()
        .next()
        .expect("one raw match produces one group");
    assert_eq!(group.entropy, Some(4.5));

    let finding = VerifiedFinding::from_deduped(
        group,
        Severity::Critical,
        VerificationResult::Skipped,
        HashMap::new(),
    );
    assert_eq!(finding.entropy, Some(4.5));
    let value = serde_json::to_value(&finding).expect("verified finding serializes");
    assert_eq!(value["entropy"].as_f64(), Some(4.5));
}

// ---------------------------------------------------------------------------
// RawMatch.confidence serde
// ---------------------------------------------------------------------------

#[test]
fn raw_match_confidence_some_serializes_exact_number() {
    let raw = make_raw(Some(0.4));
    let value = serde_json::to_value(&raw).expect("serialize RawMatch");
    // Present as a bare JSON number equal to 0.4.
    assert_eq!(value["confidence"].as_f64(), Some(0.4));
    assert!(value["confidence"].is_number());
    assert!(!value["confidence"].is_string());
}

#[test]
fn raw_match_confidence_none_is_omitted_from_object() {
    let raw = make_raw(None);
    let value = serde_json::to_value(&raw).expect("serialize RawMatch");
    let obj = value.as_object().expect("object");
    // skip_serializing_if drops the key entirely.
    assert!(!obj.contains_key("confidence"));
    // But entropy (Some) is still present, proving only confidence was dropped.
    assert_eq!(obj.get("entropy").and_then(|v| v.as_f64()), Some(4.5));
}

#[test]
fn raw_match_confidence_zero_boundary_is_present_not_omitted() {
    // BOUNDARY: 0.0 is `Some(0.0)`, NOT `None`, so it must be serialized.
    let raw = make_raw(Some(0.0));
    let value = serde_json::to_value(&raw).expect("serialize RawMatch");
    let obj = value.as_object().expect("object");
    assert!(obj.contains_key("confidence"));
    assert_eq!(value["confidence"].as_f64(), Some(0.0));
}

#[test]
fn raw_match_confidence_one_boundary_serializes_one() {
    // BOUNDARY: top of the documented [0.0, 1.0] closed interval.
    let raw = make_raw(Some(1.0));
    let value = serde_json::to_value(&raw).expect("serialize RawMatch");
    assert_eq!(value["confidence"].as_f64(), Some(1.0));
}

#[test]
fn raw_match_confidence_roundtrips_exact() {
    let raw = make_raw(Some(0.9));
    let json = serde_json::to_string(&raw).expect("serialize");
    let back: RawMatch = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.confidence, Some(0.9));
    // Full-value equality (manual PartialEq uses total_cmp on the float).
    assert_eq!(raw, back);
}

#[test]
fn raw_match_confidence_preserves_full_f64_precision() {
    // A value that needs many significant digits: serde_json uses a
    // round-trippable shortest repr, so the exact bits must survive.
    let precise = 0.123_456_789_012_345_67_f64;
    let raw = make_raw(Some(precise));
    let json = serde_json::to_string(&raw).expect("serialize");
    let back: RawMatch = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.confidence, Some(precise));
    // And within eps for good measure.
    let got = back.confidence.expect("some");
    assert!((got - precise).abs() < 1e-15, "got {got}");
}

#[test]
fn raw_match_confidence_deserializes_from_explicit_field() {
    // Deserialize a hand-authored JSON object; confidence must land verbatim.
    let json = r#"{
        "detector_id":"aws-access-key-id",
        "detector_name":"AWS Access Key ID",
        "service":"aws",
        "severity":"critical",
        "credential":"AKIAIOSFODNN7EXAMPLE",
        "credential_hash":"1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3",
        "companions":{},
        "location":{"source":"filesystem","file_path":null,"line":null,"offset":0,"commit":null,"author":null,"date":null},
        "confidence":0.72
    }"#;
    let raw: RawMatch = serde_json::from_str(json).expect("deserialize hand JSON");
    assert_eq!(raw.confidence, Some(0.72));
    // entropy field was absent -> None (independent optional float).
    assert_eq!(raw.entropy, None);
}

// ---------------------------------------------------------------------------
// VerifiedFinding.confidence serde (hand-written Serialize, field_count)
// ---------------------------------------------------------------------------

#[test]
fn verified_finding_confidence_some_included_and_field_count_is_13() {
    let finding = make_verified(Some(0.9));
    let value = serde_json::to_value(&finding).expect("serialize VerifiedFinding");
    let obj = value.as_object().expect("object");
    // 12 base fields + confidence => 13.
    assert_eq!(obj.len(), 13);
    assert!(obj.contains_key("confidence"));
    assert_eq!(value["confidence"].as_f64(), Some(0.9));
}

#[test]
fn verified_finding_confidence_none_omitted_and_field_count_is_12() {
    let finding = make_verified(None);
    let value = serde_json::to_value(&finding).expect("serialize VerifiedFinding");
    let obj = value.as_object().expect("object");
    assert_eq!(obj.len(), 12);
    assert!(!obj.contains_key("confidence"));
    // remediation is always injected by the custom Serialize regardless.
    assert!(obj.contains_key("remediation"));
}

#[test]
fn verified_finding_confidence_zero_is_present_field_count_13() {
    // BOUNDARY on the custom Serialize: `Some(0.0)` bumps the count to 13
    // because the branch keys on `is_some()`, not truthiness.
    let finding = make_verified(Some(0.0));
    let value = serde_json::to_value(&finding).expect("serialize VerifiedFinding");
    let obj = value.as_object().expect("object");
    assert_eq!(obj.len(), 13);
    assert_eq!(value["confidence"].as_f64(), Some(0.0));
}

// ---------------------------------------------------------------------------
// RedactedFinding.confidence via to_redacted()
// ---------------------------------------------------------------------------

#[test]
fn redacted_finding_confidence_propagates_from_raw_match() {
    let raw = make_raw(Some(0.55));
    let redacted: RedactedFinding = raw.to_redacted();
    // Field copied byte-for-byte.
    assert_eq!(redacted.confidence, Some(0.55));
    let value = serde_json::to_value(&redacted).expect("serialize RedactedFinding");
    assert_eq!(value["confidence"].as_f64(), Some(0.55));
}

#[test]
fn redacted_finding_confidence_none_is_omitted() {
    let raw = make_raw(None);
    let redacted = raw.to_redacted();
    assert_eq!(redacted.confidence, None);
    let value = serde_json::to_value(&redacted).expect("serialize RedactedFinding");
    let obj = value.as_object().expect("object");
    assert!(!obj.contains_key("confidence"));
}

#[test]
fn redacted_finding_confidence_roundtrips_exact() {
    let raw = make_raw(Some(0.33));
    let redacted = raw.to_redacted();
    let json = serde_json::to_string(&redacted).expect("serialize");
    let back: RedactedFinding = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.confidence, Some(0.33));
}

// ---------------------------------------------------------------------------
// RawMatch::Ord uses confidence (higher first; None == 0.0 lowest)
// ---------------------------------------------------------------------------

#[test]
fn raw_match_ord_sorts_higher_confidence_first() {
    let low = make_raw(Some(0.30));
    let high = make_raw(Some(0.90));
    // Everything else identical, so confidence is the sole discriminator.
    let mut v = vec![low, high];
    v.sort();
    assert_eq!(v[0].confidence, Some(0.90));
    assert_eq!(v[1].confidence, Some(0.30));
    // Direct comparator check too.
    let a = make_raw(Some(0.90));
    let b = make_raw(Some(0.30));
    assert_eq!(a.cmp(&b), std::cmp::Ordering::Less); // higher conf => "less" => first
}

#[test]
fn raw_match_ord_none_confidence_sorts_below_some() {
    // None is treated as 0.0 for ordering only; Some(0.5) must come first.
    let none_conf = make_raw(None);
    let some_conf = make_raw(Some(0.5));
    let mut v = vec![none_conf, some_conf];
    v.sort();
    assert_eq!(v[0].confidence, Some(0.5));
    assert_eq!(v[1].confidence, None);
}

#[test]
fn raw_match_ord_some_zero_and_none_have_distinct_identity_order() {
    // Some(0.0) and None both map to 0.0 for the confidence sort key, so they
    // tie on the priority confidence key, but the final identity tiebreaker
    // keeps them distinct so `cmp == Equal` remains equivalent to `Eq`.
    let some_zero = make_raw(Some(0.0));
    let none_conf = make_raw(None);
    assert_ne!(some_zero.cmp(&none_conf), std::cmp::Ordering::Equal);
    assert_ne!(some_zero, none_conf);
}
