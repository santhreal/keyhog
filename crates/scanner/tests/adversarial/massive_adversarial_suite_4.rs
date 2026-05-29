//! Part 4 of massive, handwritten, deep adversarial integration test suite.
//!
//! Exclusively validates deduplication logic, scope rules, cross-detector
//! folding, confidence aggregation, companion merging, and location equivalence.

use std::collections::HashMap;
use std::sync::Arc;
use keyhog_core::{
    dedup_cross_detector, dedup_matches, redact, DedupScope, DedupedMatch, MatchLocation,
    RawMatch, Severity,
};

// Helper to build a RawMatch
fn make_raw_match(
    detector_id: &str,
    credential: &str,
    file_path: &str,
    line: usize,
    offset: usize,
    severity: Severity,
    confidence: Option<f64>,
    companions: HashMap<String, String>,
) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(format!("Name-{detector_id}")),
        service: Arc::from(format!("Service-{detector_id}")),
        severity,
        credential: Arc::from(credential),
        credential_hash: format!("{:x}", md5::compute(credential)),
        companions,
        location: MatchLocation {
            source: Arc::from("test"),
            file_path: Some(Arc::from(file_path)),
            line: Some(line),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.0),
        confidence,
    }
}

// =========================================================================
// 1. DEDUPLICATION SCOPE NONE TESTS
// =========================================================================

#[test]
fn adv4_dedup_scope_none_keeps_all_distinct() {
    let m1 = make_raw_match("aws", "AKIA1", "a.txt", 1, 10, Severity::High, Some(0.8), HashMap::new());
    let m2 = make_raw_match("aws", "AKIA1", "a.txt", 2, 20, Severity::High, Some(0.8), HashMap::new());
    let res = dedup_matches(vec![m1, m2], &DedupScope::None);
    assert_eq!(res.len(), 2);
}

// =========================================================================
// 2. DEDUPLICATION SCOPE FILE TESTS
// =========================================================================

#[test]
fn adv4_dedup_scope_file_groups_same_file() {
    let m1 = make_raw_match("aws", "AKIA1", "a.txt", 1, 10, Severity::High, Some(0.8), HashMap::new());
    let m2 = make_raw_match("aws", "AKIA1", "a.txt", 2, 20, Severity::High, Some(0.8), HashMap::new());
    let res = dedup_matches(vec![m1, m2], &DedupScope::File);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].additional_locations.len(), 1);
}

#[test]
fn adv4_dedup_scope_file_separates_different_files() {
    let m1 = make_raw_match("aws", "AKIA1", "a.txt", 1, 10, Severity::High, Some(0.8), HashMap::new());
    let m2 = make_raw_match("aws", "AKIA1", "b.txt", 1, 10, Severity::High, Some(0.8), HashMap::new());
    let res = dedup_matches(vec![m1, m2], &DedupScope::File);
    assert_eq!(res.len(), 2);
}

// =========================================================================
// 3. DEDUPLICATION SCOPE CREDENTIAL TESTS
// =========================================================================

#[test]
fn adv4_dedup_scope_credential_groups_across_files() {
    let m1 = make_raw_match("aws", "AKIA1", "a.txt", 1, 10, Severity::High, Some(0.8), HashMap::new());
    let m2 = make_raw_match("aws", "AKIA1", "b.txt", 1, 10, Severity::High, Some(0.8), HashMap::new());
    let res = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].additional_locations.len(), 1);
}

// =========================================================================
// 4. CROSS DETECTOR GROUPING AND PRIORITY RULES
// =========================================================================

#[test]
fn adv4_cross_detector_priority_highest_confidence_wins() {
    let m1 = make_raw_match("aws-low-conf", "SECRET123", "a.txt", 1, 10, Severity::High, Some(0.4), HashMap::new());
    let m2 = make_raw_match("aws-high-conf", "SECRET123", "a.txt", 1, 10, Severity::High, Some(0.9), HashMap::new());
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    let res = dedup_cross_detector(deduped);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].detector_id.as_ref(), "aws-high-conf");
}

#[test]
fn adv4_cross_detector_priority_highest_severity_wins_on_equal_confidence() {
    let m1 = make_raw_match("aws-med-sev", "SECRET123", "a.txt", 1, 10, Severity::Medium, Some(0.8), HashMap::new());
    let m2 = make_raw_match("aws-critical-sev", "SECRET123", "a.txt", 1, 10, Severity::Critical, Some(0.8), HashMap::new());
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    let res = dedup_cross_detector(deduped);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].detector_id.as_ref(), "aws-critical-sev");
}

#[test]
fn adv4_cross_detector_priority_lexicographic_tiebreak() {
    let m1 = make_raw_match("aws-b-detector", "SECRET123", "a.txt", 1, 10, Severity::High, Some(0.8), HashMap::new());
    let m2 = make_raw_match("aws-a-detector", "SECRET123", "a.txt", 1, 10, Severity::High, Some(0.8), HashMap::new());
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    let res = dedup_cross_detector(deduped);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].detector_id.as_ref(), "aws-a-detector");
}

// =========================================================================
// 5. COMPANION MERGING AND ALPHABETICAL DELIMITING
// =========================================================================

#[test]
fn adv4_companion_merging_keeps_distinct_values_delimited() {
    let mut c1 = HashMap::new();
    c1.insert("org".to_string(), "org-1".to_string());
    let mut c2 = HashMap::new();
    c2.insert("org".to_string(), "org-2".to_string());

    let m1 = make_raw_match("aws", "AKIA1", "a.txt", 1, 10, Severity::High, Some(0.8), c1);
    let m2 = make_raw_match("aws", "AKIA1", "a.txt", 2, 20, Severity::High, Some(0.8), c2);

    let res = dedup_matches(vec![m1, m2], &DedupScope::File);
    assert_eq!(res.len(), 1);
    let org_val = res[0].companions.get("org").unwrap();
    assert!(org_val.contains("org-1"));
    assert!(org_val.contains("org-2"));
    assert!(org_val.contains(" | "));
}

// =========================================================================
// 6. REDACTION UTILITY ADVERSARIAL CASES
// =========================================================================

#[test]
fn adv4_redact_short_credential_produces_four_asterisks() {
    assert_eq!(redact("123"), "****");
    assert_eq!(redact("12345678"), "****");
}

#[test]
fn adv4_redact_long_ascii_credential_preserves_first_and_last_four() {
    assert_eq!(redact("123456789"), "1234...6789");
}

#[test]
fn adv4_redact_utf8_long_credential_preserves_first_and_last_four_chars() {
    // UTF-8 path: 9 characters
    let credential = "🦀🦀🦀🦀🔥🦖🦖🦖🦖";
    assert_eq!(redact(credential), "🦀🦀🦀🦀...🦖🦖🦖🦖");
}

#[test]
fn adv4_redact_utf8_short_credential_produces_four_asterisks() {
    assert_eq!(redact("🦀🦀🦀"), "****");
}
