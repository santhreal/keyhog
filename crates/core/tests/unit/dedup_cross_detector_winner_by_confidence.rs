//! Proving test: cross_detector dedup winner selection by confidence, severity, and ID.
//! Contract: When multiple detectors report the same credential,
//! the HIGHEST confidence wins; ties broken by HIGHEST severity;
//! final tiebreak is LEXICOGRAPHIC detector_id.

use keyhog_core::{DedupedMatch, MatchLocation, Severity, dedup_cross_detector};
use std::collections::HashMap;
use std::sync::Arc;

fn make_deduped(detector: &str, conf: Option<f64>, severity: Severity) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from("test"),
        severity,
        credential: keyhog_core::SensitiveString::from("SAME_CREDENTIAL_VALUE_FOR_ALL"),
        credential_hash: [42; 32].into(),
        companions: HashMap::new(),
        primary_location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from("test.env")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: Vec::new(),
        confidence: conf,
    }
}

#[test]
fn cross_detector_dedup_wins_by_highest_confidence() {
    // Three detectors, same credential, different confidence.
    // Winner should be the one with 0.95 confidence.
    let input = vec![
        make_deduped("detector-a", Some(0.7), Severity::High),
        make_deduped("detector-b", Some(0.95), Severity::High),
        make_deduped("detector-c", Some(0.8), Severity::High),
    ];

    let result = dedup_cross_detector(input);

    assert_eq!(result.len(), 1, "three same-cred detectors → 1 finding");
    assert_eq!(result[0].detector_id.as_ref(), "detector-b");
    assert_eq!(result[0].confidence, Some(0.95));

    // Losers should appear in companions.
    assert!(
        result[0].companions.contains_key("cross_detector.0"),
        "loser 0 should be in companions"
    );
    assert!(
        result[0].companions.contains_key("cross_detector.1"),
        "loser 1 should be in companions"
    );
}

#[test]
fn cross_detector_dedup_severity_tiebreak_when_confidence_equal() {
    // Two detectors with same confidence, different severity.
    // Winner should be the Critical one (higher severity).
    let input = vec![
        make_deduped("detector-low-sev", Some(0.9), Severity::Low),
        make_deduped("detector-critical", Some(0.9), Severity::Critical),
    ];

    let result = dedup_cross_detector(input);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].detector_id.as_ref(), "detector-critical");
    assert_eq!(result[0].severity, Severity::Critical);
}

#[test]
fn cross_detector_dedup_lexicographic_id_tiebreak() {
    // Two detectors with same confidence and severity.
    // Winner should be lexicographically first.
    let input = vec![
        make_deduped("zebra-detector", Some(0.8), Severity::High),
        make_deduped("alpha-detector", Some(0.8), Severity::High),
    ];

    let result = dedup_cross_detector(input);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].detector_id.as_ref(), "alpha-detector");
}

#[test]
fn cross_detector_dedup_none_confidence_loses_to_some() {
    // One detector with None confidence, one with Some(0.7).
    // The one with Some(0.7) should win (even if lower).
    let input = vec![
        make_deduped("detector-no-conf", None, Severity::High),
        make_deduped("detector-with-conf", Some(0.7), Severity::High),
    ];

    let result = dedup_cross_detector(input);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].detector_id.as_ref(), "detector-with-conf");
}

#[test]
fn cross_detector_dedup_both_none_confidence_falls_back_to_severity() {
    // Both have None confidence; severity decides.
    let input = vec![
        make_deduped("detector-low", None, Severity::Low),
        make_deduped("detector-critical", None, Severity::Critical),
    ];

    let result = dedup_cross_detector(input);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].detector_id.as_ref(), "detector-critical");
}

#[test]
fn cross_detector_dedup_loser_appears_in_companions_with_formatted_string() {
    // Verify the loser's metadata appears in companions under cross_detector.0
    // with format: "service (detector_name) [confidence]"
    let input = vec![
        make_deduped("winner-det", Some(0.95), Severity::High),
        make_deduped("loser-det", Some(0.6), Severity::Medium),
    ];

    let result = dedup_cross_detector(input);

    assert_eq!(result.len(), 1);
    let companion_value = result[0].companions.get("cross_detector.0").unwrap();

    // Format should be "test (loser-det) [0.60]"
    assert!(
        companion_value.contains("test"),
        "should contain service name"
    );
    assert!(
        companion_value.contains("loser-det"),
        "should contain detector name"
    );
    assert!(
        companion_value.contains("0.60"),
        "should contain confidence"
    );
}
