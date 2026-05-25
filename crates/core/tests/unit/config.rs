use keyhog_core::{ScanConfig, MAX_DECODE_DEPTH_LIMIT};

#[test]
fn default_config_valid() {
    let config = ScanConfig::default();
    assert!(config.validate().is_ok());
    // Pin the default ScanConfig field values that downstream consumers
    // (CLI, integrations, scanner orchestrator) silently depend on.
    // Without these assertions the test would still pass if Default
    // for ScanConfig started returning ml_enabled = false or
    // unicode_normalization = false, both of which would silently
    // halve recall on a swath of real corpora. Pre-2026-05-24 the
    // assertion was just `validate().is_ok()`, which the empty
    // default config also satisfies.
    assert!(
        config.min_confidence >= 0.4 && config.min_confidence <= 0.6,
        "default min_confidence should be ~0.5 (was 0.3 historically); got {}",
        config.min_confidence
    );
    assert!(config.max_decode_depth >= 4, "default decode depth too shallow: {}", config.max_decode_depth);
    assert!(config.entropy_enabled, "entropy must default to on");
    assert!(config.unicode_normalization, "unicode normalization must default to on");
    assert!(
        config.max_file_size >= 1024 * 1024,
        "default max_file_size too small: {}",
        config.max_file_size
    );
    assert!(
        config.max_matches_per_chunk >= 100,
        "default max_matches_per_chunk too low: {}",
        config.max_matches_per_chunk
    );
}

#[test]
fn fast_config_valid() {
    let config = ScanConfig::fast();
    assert!(config.validate().is_ok());
    assert_eq!(config.max_decode_depth, 2);
    assert!(!config.entropy_enabled);
}

#[test]
fn thorough_config_valid() {
    let config = ScanConfig::thorough();
    assert!(config.validate().is_ok());
    assert_eq!(config.max_decode_depth, 8);
    assert!(config.entropy_in_source_files);
}

#[test]
fn paranoid_config_valid() {
    let config = ScanConfig::paranoid();
    assert!(config.validate().is_ok());
    assert_eq!(config.max_decode_depth, MAX_DECODE_DEPTH_LIMIT);
}

#[test]
fn invalid_depth_rejected() {
    let config = ScanConfig {
        max_decode_depth: 100,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn invalid_confidence_rejected() {
    let config = ScanConfig {
        min_confidence: 1.5,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}
