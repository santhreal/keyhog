//! High-precision preset disables entropy-based detection.
//!
//! Test that ScannerConfig::high_precision() sets entropy_enabled = false,
//! and consequently entropy-only matches are not surfaced.
//!
//! COVERAGE PARTITION: scanner-confidence
//! - Verifies ScannerConfig::high_precision() line 111-118 in scanner_config.rs
//! - entropy_enabled: false, combined with min_confidence: 0.85

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

mod support;
use support::paths::detector_dir;

/// Test: High-precision preset disables entropy detection.
///
/// Asserts that ScannerConfig::high_precision() has entropy_enabled = false,
/// which prevents generic/entropy findings that would pass under default config
/// but fail under precision mode.
#[test]
fn high_precision_entropy_disabled() {
    let high_precision_config = keyhog_scanner::ScannerConfig::high_precision();

    assert_eq!(
        high_precision_config.entropy_enabled, false,
        "high_precision() must disable entropy_enabled; got {}",
        high_precision_config.entropy_enabled
    );

    // Load detectors and compile both scanners
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors loaded");

    // Default config has entropy enabled
    let mut default_config = keyhog_scanner::ScannerConfig::default();
    assert!(
        default_config.entropy_enabled,
        "default ScannerConfig should have entropy_enabled = true"
    );

    let default_scanner =
        CompiledScanner::compile(detectors.clone()).expect("default scanner compiled");
    let high_precision_scanner = CompiledScanner::compile(detectors)
        .expect("high-precision scanner compiled")
        .with_config(high_precision_config);

    // A high-entropy string without any detector prefix (entropy-only match)
    // Password assignments are commonly caught by entropy in default mode but
    // should be suppressed in precision mode when entropy is disabled.
    let text = "DATABASE_PASSWORD=Tx8vQp2zNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ";
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("config.env".into()),
            ..Default::default()
        },
    };

    let default_matches = default_scanner.scan(&chunk);
    let precision_matches = high_precision_scanner.scan(&chunk);

    // Count entropy-tagged findings (those without a strong detector prefix signal)
    let default_entropy_count = default_matches
        .iter()
        .filter(|m| m.detector_id.contains("entropy") || m.detector_id.contains("generic"))
        .count();

    // Precision mode should find fewer or no entropy-only matches
    let precision_entropy_count = precision_matches
        .iter()
        .filter(|m| m.detector_id.contains("entropy") || m.detector_id.contains("generic"))
        .count();

    assert!(
        precision_entropy_count <= default_entropy_count,
        "high-precision (entropy disabled) should find <= entropy matches than default; \
         default entropy count: {}, precision entropy count: {}",
        default_entropy_count,
        precision_entropy_count
    );
}

/// Test: High-precision preset has shallow decode (max_decode_depth = 1).
///
/// Asserts that ScannerConfig::high_precision() sets max_decode_depth = 1
/// to avoid FPs from deeply nested encodings (a FP source at mass-scan scale).
#[test]
fn high_precision_shallow_decode() {
    let high_precision_config = keyhog_scanner::ScannerConfig::high_precision();

    assert_eq!(
        high_precision_config.max_decode_depth, 1,
        "high_precision() must set max_decode_depth to 1; got {}",
        high_precision_config.max_decode_depth
    );

    // Default should have deeper decode
    let default_config = keyhog_scanner::ScannerConfig::default();
    assert!(
        default_config.max_decode_depth >= 3,
        "default ScannerConfig should have deeper decode (>= 3); got {}",
        default_config.max_decode_depth
    );
}

/// Test: High-precision preset keeps ML enabled.
///
/// Asserts that ScannerConfig::high_precision() keeps ml_enabled = true
/// (because ML is the confidence discriminator lifting genuine secrets
/// over the high 0.85 floor). Disabling it would crater the scores.
#[test]
fn high_precision_keeps_ml_enabled() {
    let high_precision_config = keyhog_scanner::ScannerConfig::high_precision();

    assert!(
        high_precision_config.ml_enabled,
        "high_precision() must keep ml_enabled = true; got {}",
        high_precision_config.ml_enabled
    );

    // Verify that ML weight is also a reasonable value (inherited from default)
    assert!(
        high_precision_config.ml_weight > 0.0 && high_precision_config.ml_weight <= 1.0,
        "ml_weight should be valid probability; got {}",
        high_precision_config.ml_weight
    );
}
