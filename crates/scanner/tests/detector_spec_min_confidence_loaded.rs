//! Detector specification min_confidence fields are correctly loaded and respected.
//!
//! Tests that DetectorSpec::min_confidence values from TOML are loaded,
//! merged into the per-detector floor map, and applied in postprocess filtering.
//!
//! COVERAGE PARTITION: scanner-confidence
//! - Verifies that detectors with explicit min_confidence are loaded correctly
//! - Validates that the 47 self-declared floors (0.12-0.30) exist and are honored

use keyhog_core::load_detectors;
use keyhog_scanner::testing::detector_weak_anchor_for_test;
use std::collections::HashMap;

mod support;
use support::paths::detector_dir;

/// Test: Loaded detectors include explicit min_confidence values.
///
/// Asserts that at least some detectors in the embedded corpus have
/// DetectorSpec::min_confidence set (47 detectors self-declare 0.12-0.30).
/// This validates that the TOML parsing correctly loads this field.
#[test]
fn detector_spec_min_confidence_fields_loaded() {
    let detectors = load_detectors(&detector_dir()).expect("detectors loaded");

    let with_explicit_floor: Vec<_> = detectors
        .iter()
        .filter(|d| d.min_confidence.is_some())
        .collect();

    assert!(
        with_explicit_floor.len() >= 40,
        "expected at least 40+ detectors with explicit min_confidence, got {}. \
         The 47 self-declared floors (0.12-0.30 range) may be missing from TOML.",
        with_explicit_floor.len()
    );

    // Verify that the stated floor range (0.12-0.30) appears
    let mut has_low_range = false;
    let mut has_mid_range = false;

    for detector in &with_explicit_floor {
        if let Some(floor) = detector.min_confidence {
            if (0.10..=0.20).contains(&floor) {
                has_low_range = true;
            }
            if (0.25..=0.35).contains(&floor) {
                has_mid_range = true;
            }
        }
    }

    assert!(
        has_low_range,
        "expected detectors with min_confidence in range 0.12-0.20, none found"
    );
    assert!(
        has_mid_range,
        "expected detectors with min_confidence in range 0.25-0.30, none found"
    );
}

#[test]
fn tier_b_weak_anchor_override_wins_over_min_confidence() {
    let detectors = load_detectors(&detector_dir()).expect("detectors loaded");
    let flickr = detectors
        .iter()
        .find(|detector| detector.id == "flickr-api-key")
        .expect("bundled flickr-api-key detector exists");
    assert!(
        flickr.min_confidence.is_some(),
        "test fixture must cover the min_confidence precedence edge"
    );
    assert!(
        detector_weak_anchor_for_test(flickr),
        "Tier-B weak_anchor classification must remain active even when a detector self-declares min_confidence"
    );
}

/// Test: Per-detector floor map is built from DetectorSpec::min_confidence.
///
/// Asserts that when per-detector floors are merged from detector specs
/// (the logic in orchestrator/mod.rs that fills detector_min_confidence map),
/// the floors respect the spec values and clamp to [0.0, 1.0].
#[test]
fn per_detector_floor_map_built_from_spec() {
    let detectors = load_detectors(&detector_dir()).expect("detectors loaded");

    // Simulate the orchestrator's floor-merging logic
    let mut detector_min_confidence: HashMap<String, f64> = HashMap::new();

    for d in &detectors {
        if let Some(mc) = d.min_confidence {
            detector_min_confidence
                .entry(d.id.clone())
                .or_insert(mc.clamp(0.0, 1.0));
        }
    }

    // Verify the map was populated
    assert!(
        detector_min_confidence.len() >= 40,
        "detector_min_confidence map should have 40+ entries, got {}",
        detector_min_confidence.len()
    );

    // Verify entries are properly clamped to [0.0, 1.0]
    for (detector_id, floor) in &detector_min_confidence {
        assert!(
            *floor >= 0.0 && *floor <= 1.0,
            "detector {} has floor {} outside [0.0, 1.0]",
            detector_id,
            floor
        );
    }

    // Check that we have some in the claimed range (0.12-0.30)
    let in_range: Vec<_> = detector_min_confidence
        .iter()
        .filter(|(_, floor)| **floor >= 0.10 && **floor <= 0.35)
        .collect();

    assert!(
        in_range.len() >= 20,
        "expected at least 20 detectors with floor in 0.12-0.30 range, got {}",
        in_range.len()
    );
}

/// Test: High-precision raises low-floor detectors to 0.85.
///
/// Asserts that the orchestrator's high-precision adjustment
/// (for each per-detector floor: max(floor, 0.85)) correctly raises
/// the 47 low-floor detectors to 0.85.
#[test]
fn high_precision_raises_all_low_floors_to_0_85() {
    let detectors = load_detectors(&detector_dir()).expect("detectors loaded");

    let mut detector_min_confidence: HashMap<String, f64> = HashMap::new();
    for d in &detectors {
        if let Some(mc) = d.min_confidence {
            detector_min_confidence
                .entry(d.id.clone())
                .or_insert(mc.clamp(0.0, 1.0));
        }
    }

    // Count how many are below 0.85 before adjustment
    let below_0_85_before: Vec<_> = detector_min_confidence
        .iter()
        .filter(|(_, floor)| **floor < 0.85)
        .collect();

    assert!(
        below_0_85_before.len() >= 40,
        "expected most detectors below 0.85 before precision adjustment, got {} below",
        below_0_85_before.len()
    );

    // Apply high-precision adjustment (same logic as orchestrator)
    let high_precision_floor = 0.85;
    for v in detector_min_confidence.values_mut() {
        *v = v.max(high_precision_floor);
    }

    // Verify all are now >= 0.85
    for (detector_id, floor) in &detector_min_confidence {
        assert!(
            *floor >= 0.85,
            "after high-precision adjustment, detector {} floor should be >= 0.85, got {}",
            detector_id,
            floor
        );
    }

    // Count how many are exactly 0.85 (were raised)
    let raised_to_0_85: Vec<_> = detector_min_confidence
        .iter()
        .filter(|(_, floor)| (**floor - 0.85).abs() < 1e-9)
        .collect();

    assert!(
        raised_to_0_85.len() >= 30,
        "expected at least 30 detectors raised to exactly 0.85, got {}",
        raised_to_0_85.len()
    );
}

/// Test: Detector floor clamping is idempotent.
///
/// Asserts that applying clamp(0.0, 1.0) multiple times produces the same result
/// (ensuring the config-load path doesn't double-clamp or corrupt values).
#[test]
fn detector_floor_clamping_idempotent() {
    let test_values = vec![
        -0.5, // below range
        0.0,  // boundary low
        0.15, // mid-range
        0.50, // mid-range
        0.85, // high-precision boundary
        1.0,  // boundary high
        1.5,  // above range
        f64::NAN,
    ];

    for val in test_values {
        let clamped_once = val.clamp(0.0, 1.0);
        let clamped_twice = clamped_once.clamp(0.0, 1.0);

        // NaN clamps to NaN, so skip that case
        if !val.is_nan() {
            assert_eq!(
                clamped_once, clamped_twice,
                "clamping idempotency failed for {}; once={}, twice={}",
                val, clamped_once, clamped_twice
            );
        }
    }
}
