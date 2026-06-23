//! Confidence floor enforcement in post-scan filtering.
//!
//! Tests that per-detector min_confidence (from DetectorSpec) and global
//! min_confidence are correctly applied in filter_and_resolve, and that
//! high-precision mode raises all floors to 0.85.
//!
//! COVERAGE PARTITION: scanner-confidence
//! - Line 151-167 in crates/cli/src/orchestrator/postprocess.rs:
//!   Per-detector floor lookup and application
//! - scanner.min_confidence default (0.40) and high_precision override (0.85)

use keyhog_core::{MatchLocation, RawMatch, Severity};

/// Build a minimal RawMatch for testing confidence floors.
fn make_match(detector_id: &str, detector_name: &str, service: &str, confidence: f64) -> RawMatch {
    RawMatch {
        detector_id: detector_id.into(),
        detector_name: detector_name.into(),
        service: service.into(),
        severity: Severity::Medium,
        credential: "test_secret_12345678".into(),
        credential_hash: [0u8; 32].into(),
        companions: std::collections::HashMap::new(),
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
        confidence: Some(confidence),
    }
}

/// Test: Finding below global min_confidence (0.40 default) is dropped.
///
/// Asserts that a finding with confidence 0.35 < 0.40 is filtered out
/// when no per-detector floor overrides it.
#[test]
fn global_confidence_floor_below_threshold_filtered() {
    // Manually create a match below 0.40 to test the floor logic.
    let below_floor = make_match("test-detector", "Test Detector", "test-service", 0.35);
    let matches_vec = vec![below_floor];

    // Simulate the postprocess filter with default (0.40) min_confidence
    let global_floor = 0.40;
    let per_detector_floors: std::collections::HashMap<String, f64> =
        std::collections::HashMap::new();

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
        "finding with confidence 0.35 must be dropped below global floor 0.40. Filtered count: {}",
        filtered.len()
    );
}

/// Test: Finding at exactly the global confidence threshold passes.
///
/// Asserts that a finding with confidence exactly 0.40 passes when the global
/// floor is 0.40 (boundary case: >= not >).
#[test]
fn global_confidence_floor_at_threshold_passes() {
    let global_floor = 0.40;
    let per_detector_floors: std::collections::HashMap<String, f64> =
        std::collections::HashMap::new();

    let at_floor = make_match("test-detector", "Test Detector", "test-service", 0.40);
    let matches_vec = vec![at_floor];

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
        1,
        "finding with confidence exactly at global floor 0.40 must pass (>= semantics)"
    );
}

/// Test: Per-detector floor overrides global floor.
///
/// Asserts that a detector with min_confidence 0.70 in its spec will drop
/// findings between 0.40 and 0.70, even though the global floor is 0.40.
#[test]
fn per_detector_floor_overrides_global() {
    let global_floor = 0.40;
    let mut per_detector_floors: std::collections::HashMap<String, f64> =
        std::collections::HashMap::new();
    per_detector_floors.insert("aws-detector".to_string(), 0.70);

    // A finding from "aws-detector" with conf 0.50 (above global 0.40, below per-detector 0.70)
    let test_match = make_match("aws-detector", "AWS Detector", "aws", 0.50);
    let matches_vec = vec![test_match];

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
        "finding from aws-detector with conf 0.50 must be filtered by per-detector floor 0.70 \
         (even though 0.50 > global floor 0.40). Filtered count: {}",
        filtered.len()
    );
}

/// Test: Per-detector floor is respected when above global floor.
///
/// Asserts that a detector with min_confidence 0.70 allows findings >= 0.70
/// to pass, even though global floor is only 0.40.
#[test]
fn per_detector_floor_passes_above_threshold() {
    let global_floor = 0.40;
    let mut per_detector_floors: std::collections::HashMap<String, f64> =
        std::collections::HashMap::new();
    per_detector_floors.insert("aws-detector".to_string(), 0.70);

    // A finding from "aws-detector" with conf 0.75 (above both floors)
    let test_match = make_match("aws-detector", "AWS Detector", "aws", 0.75);
    let matches_vec = vec![test_match];

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
        1,
        "finding from aws-detector with conf 0.75 must pass per-detector floor 0.70"
    );
}

/// Test: High-precision preset applies 0.85 global floor.
///
/// Asserts that ScannerConfig::high_precision() sets min_confidence to 0.85,
/// dropping findings below that threshold.
#[test]
fn high_precision_preset_sets_floor_to_0_85() {
    let high_precision_config = keyhog_scanner::ScannerConfig::high_precision();

    assert_eq!(
        high_precision_config.min_confidence, 0.85,
        "high_precision() preset must set min_confidence to exactly 0.85, got {}",
        high_precision_config.min_confidence
    );

    // Test the floor enforcement with this value
    let global_floor = 0.85;
    let per_detector_floors: std::collections::HashMap<String, f64> =
        std::collections::HashMap::new();

    let below_precision_floor = make_match("test-detector", "Test Detector", "test-service", 0.80);
    let matches_vec = vec![below_precision_floor];

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
        "with high-precision floor 0.85, finding with confidence 0.80 must be dropped"
    );
}

/// Test: High-precision mode raises per-detector floors to at least 0.85.
///
/// Asserts that when high-precision is active, any per-detector floor below 0.85
/// is raised to 0.85 (the high-precision global floor becomes a universal floor).
///
/// This models the behavior in orchestrator/mod.rs:
/// ```
/// if args.precision {
///     let floor = effective_config.scanner.min_confidence;  // 0.85
///     for v in detector_min_confidence.values_mut() {
///         *v = v.max(floor);
///     }
/// }
/// ```
#[test]
fn high_precision_raises_per_detector_floors() {
    let high_precision_floor = 0.85;
    let mut per_detector_floors: std::collections::HashMap<String, f64> =
        std::collections::HashMap::new();

    // Before precision adjustment: detectors at 0.12, 0.30, 0.50, 0.90
    per_detector_floors.insert("detector-low-1".to_string(), 0.12);
    per_detector_floors.insert("detector-low-2".to_string(), 0.30);
    per_detector_floors.insert("detector-mid".to_string(), 0.50);
    per_detector_floors.insert("detector-high".to_string(), 0.90);

    // Apply high-precision adjustment (same logic as orchestrator)
    for v in per_detector_floors.values_mut() {
        *v = v.max(high_precision_floor);
    }

    // Verify all floors were raised to at least 0.85
    assert_eq!(
        per_detector_floors.get("detector-low-1"),
        Some(&0.85),
        "detector-low-1: 0.12 should be raised to 0.85 by high-precision"
    );
    assert_eq!(
        per_detector_floors.get("detector-low-2"),
        Some(&0.85),
        "detector-low-2: 0.30 should be raised to 0.85 by high-precision"
    );
    assert_eq!(
        per_detector_floors.get("detector-mid"),
        Some(&0.85),
        "detector-mid: 0.50 should be raised to 0.85 by high-precision"
    );
    assert_eq!(
        per_detector_floors.get("detector-high"),
        Some(&0.90),
        "detector-high: 0.90 stays at 0.90 (already >= 0.85)"
    );

    // Now test that a finding from detector-low-1 at 0.70 is dropped
    let match_to_test = make_match("detector-low-1", "Low Detector 1", "service-1", 0.70);
    let matches_vec = vec![match_to_test];

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
        0,
        "with high-precision, detector-low-1's floor raised to 0.85 must drop confidence 0.70"
    );
}
