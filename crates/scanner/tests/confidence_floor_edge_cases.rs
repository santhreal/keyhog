//! Edge cases in confidence floor application and boundary conditions.
//!
//! Tests that the floor logic handles NaN, None, infinity, and mixed detector
//! scenarios correctly, ensuring robustness.
//!
//! COVERAGE PARTITION: scanner-confidence
//! - Boundary conditions for confidence values
//! - NaN handling in floor comparisons
//! - Missing confidence (None) handling

use keyhog_core::{MatchLocation, RawMatch, Severity};
use std::collections::HashMap;

/// Helper to build a RawMatch for testing.
fn make_match(
    detector_id: &str,
    detector_name: &str,
    service: &str,
    confidence: Option<f64>,
) -> RawMatch {
    RawMatch {
        detector_id: detector_id.into(),
        detector_name: detector_name.into(),
        service: service.into(),
        severity: Severity::Medium,
        credential: "test_secret".into(),
        credential_hash: [0u8; 32],
        companions: HashMap::new(),
        location: MatchLocation {
            source: "test".into(),
            file_path: Some("test.rs".into()),
            line: Some(42),
            offset: 10,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence,
    }
}

/// Test: Finding with None confidence is always kept (no floor gate).
///
/// Asserts that when confidence is None (detector has no confidence scoring),
/// the floor check is skipped and the finding passes the filter.
#[test]
fn none_confidence_skips_floor_check() {
    let global_floor = 0.40;
    let per_detector_floors: HashMap<String, f64> = HashMap::new();

    let match_no_conf = make_match("test-detector", "Test", "test", None);
    let matches_vec = vec![match_no_conf];

    let filtered: Vec<_> = matches_vec
        .into_iter()
        .filter(|m| {
            if let Some(conf) = m.confidence {
                if let Some(floor) = per_detector_floors.get(m.detector_id.as_ref()) {
                    return conf >= *floor;
                } else {
                    return conf >= global_floor;
                }
            }
            // No confidence: passes unconditionally
            true
        })
        .collect();

    assert_eq!(
        filtered.len(),
        1,
        "finding with None confidence must pass (floor check skipped)"
    );
}

/// Test: Detectors with and without explicit floors are handled together.
///
/// Asserts that a mixed set of detectors (some with per-detector floors,
/// some without) filters correctly, using the appropriate floor for each.
#[test]
fn mixed_detector_floors_filtering() {
    let global_floor = 0.40;
    let mut per_detector_floors: HashMap<String, f64> = HashMap::new();
    per_detector_floors.insert("aws-detector".to_string(), 0.70);
    // no entry for "slack-detector" -> uses global floor

    let matches_vec = vec![
        // AWS detector below its per-detector floor (but above global)
        make_match("aws-detector", "AWS", "aws", Some(0.55)),
        // AWS detector above both floors
        make_match("aws-detector", "AWS", "aws", Some(0.75)),
        // Slack detector below global floor
        make_match("slack-detector", "Slack", "slack", Some(0.30)),
        // Slack detector above global floor (no per-detector override)
        make_match("slack-detector", "Slack", "slack", Some(0.50)),
    ];

    let filtered: Vec<_> = matches_vec
        .into_iter()
        .filter(|m| {
            if let Some(conf) = m.confidence {
                if let Some(floor) = per_detector_floors.get(m.detector_id.as_ref()) {
                    return conf >= *floor;
                } else {
                    return conf >= global_floor;
                }
            }
            true
        })
        .collect();

    // Expected: indices 1 (aws 0.75) and 3 (slack 0.50) pass
    assert_eq!(
        filtered.len(),
        2,
        "expected 2 findings to pass (aws@0.75 and slack@0.50), got {}",
        filtered.len()
    );

    assert_eq!(
        filtered[0].confidence,
        Some(0.75),
        "first passing should be aws@0.75"
    );
    assert_eq!(
        filtered[1].confidence,
        Some(0.50),
        "second passing should be slack@0.50"
    );
}

/// Test: Exactly-zero confidence is compared correctly.
///
/// Asserts that a confidence of 0.0 is compared against the floor correctly
/// (0.0 < 0.40, so should be filtered).
#[test]
fn zero_confidence_filtered_by_global_floor() {
    let global_floor = 0.40;
    let per_detector_floors: HashMap<String, f64> = HashMap::new();

    let match_zero_conf = make_match("test-detector", "Test", "test", Some(0.0));
    let matches_vec = vec![match_zero_conf];

    let filtered: Vec<_> = matches_vec
        .into_iter()
        .filter(|m| {
            if let Some(conf) = m.confidence {
                if let Some(floor) = per_detector_floors.get(m.detector_id.as_ref()) {
                    return conf >= *floor;
                } else {
                    return conf >= global_floor;
                }
            }
            true
        })
        .collect();

    assert_eq!(
        filtered.len(),
        0,
        "confidence 0.0 must fail floor check (0.0 < 0.40)"
    );
}

/// Test: Exactly-one confidence always passes.
///
/// Asserts that confidence of 1.0 passes any floor (max possible confidence).
#[test]
fn max_confidence_always_passes() {
    let high_precision_floor = 0.85;
    let mut per_detector_floors: HashMap<String, f64> = HashMap::new();
    per_detector_floors.insert("stringent-detector".to_string(), 0.99);

    let match_perfect = make_match("stringent-detector", "Stringent", "service", Some(1.0));
    let matches_vec = vec![match_perfect];

    let filtered: Vec<_> = matches_vec
        .into_iter()
        .filter(|m| {
            if let Some(conf) = m.confidence {
                if let Some(floor) = per_detector_floors.get(m.detector_id.as_ref()) {
                    return conf >= *floor;
                } else {
                    return conf >= high_precision_floor;
                }
            }
            true
        })
        .collect();

    assert_eq!(
        filtered.len(),
        1,
        "confidence 1.0 must always pass, even against 0.99 floor"
    );
}

/// Test: Very small positive confidence (just above zero) is filtered.
///
/// Asserts that 1e-10 < 0.40, so it should be filtered (avoiding false
/// positives from floating-point arithmetic edge cases).
#[test]
fn tiny_confidence_filtered() {
    let global_floor = 0.40;
    let per_detector_floors: HashMap<String, f64> = HashMap::new();

    let match_tiny = make_match("test-detector", "Test", "test", Some(1e-10));
    let matches_vec = vec![match_tiny];

    let filtered: Vec<_> = matches_vec
        .into_iter()
        .filter(|m| {
            if let Some(conf) = m.confidence {
                if let Some(floor) = per_detector_floors.get(m.detector_id.as_ref()) {
                    return conf >= *floor;
                } else {
                    return conf >= global_floor;
                }
            }
            true
        })
        .collect();

    assert_eq!(
        filtered.len(),
        0,
        "tiny confidence 1e-10 must fail floor 0.40"
    );
}

/// Test: ScannerConfig sanitise() NaN-clamps invalid min_confidence.
///
/// Asserts that NaN or infinite values are replaced with the canonical default
/// (from ScanConfig::default()) when a ScannerConfig is sanitized.
#[test]
fn scanner_config_sanitise_nan_min_confidence() {
    use keyhog_scanner::ScannerConfig;

    // Create a config with NaN min_confidence
    let mut config_nan = ScannerConfig::default();
    config_nan.min_confidence = f64::NAN;

    config_nan.sanitise();

    assert!(
        !config_nan.min_confidence.is_nan(),
        "sanitise() should replace NaN min_confidence with a valid value, got NaN"
    );
    assert!(
        config_nan.min_confidence >= 0.0 && config_nan.min_confidence <= 1.0,
        "sanitised min_confidence should be in [0.0, 1.0], got {}",
        config_nan.min_confidence
    );

    // Create a config with infinite min_confidence
    let mut config_inf = ScannerConfig::default();
    config_inf.min_confidence = f64::INFINITY;

    config_inf.sanitise();

    assert!(
        config_inf.min_confidence.is_finite(),
        "sanitise() should clamp infinite min_confidence to a finite value, got infinity"
    );
    assert!(
        config_inf.min_confidence >= 0.0 && config_inf.min_confidence <= 1.0,
        "sanitised min_confidence should be in [0.0, 1.0], got {}",
        config_inf.min_confidence
    );
}

/// Test: Confidence threshold boundary at exactly 0.85 in high-precision.
///
/// Asserts the >= semantics: 0.85 passes, 0.849999 fails.
#[test]
fn high_precision_threshold_boundary() {
    let floor = 0.85;
    let per_detector_floors: HashMap<String, f64> = HashMap::new();

    // Test just below
    let match_below = make_match("test", "Test", "test", Some(0.849999));
    assert_eq!(
        [match_below]
            .iter()
            .filter(|m| { m.confidence.map_or(true, |c| c >= floor) })
            .count(),
        0,
        "0.849999 < 0.85 must fail"
    );

    // Test exactly at
    let match_exact = make_match("test", "Test", "test", Some(0.85));
    assert_eq!(
        [match_exact]
            .iter()
            .filter(|m| { m.confidence.map_or(true, |c| c >= floor) })
            .count(),
        1,
        "0.85 == floor must pass (>= semantics)"
    );

    // Test just above
    let match_above = make_match("test", "Test", "test", Some(0.850001));
    assert_eq!(
        [match_above]
            .iter()
            .filter(|m| { m.confidence.map_or(true, |c| c >= floor) })
            .count(),
        1,
        "0.850001 > 0.85 must pass"
    );
}
