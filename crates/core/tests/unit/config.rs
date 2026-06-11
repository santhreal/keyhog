use keyhog_core::ScanConfig;

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
    // Pin the canonical bench-tuned floor EXACTLY (SecretBench-mirror
    // grid-sweep: 0.40 maximises F1). Changing the shipped default without
    // re-tuning + updating this assertion breaks tuned == benched == shipped,
    // so the pin is intentionally tight, not a loose range.
    assert!(
        (config.min_confidence - 0.40).abs() < 1e-9,
        "default min_confidence must be the canonical tuned 0.40; got {}",
        config.min_confidence
    );
    assert_eq!(
        config.max_decode_depth, 10,
        "default max_decode_depth must be the canonical 10 (decode-through depth); got {}",
        config.max_decode_depth
    );
    assert!(config.entropy_enabled, "entropy must default to on");
    assert!(
        config.unicode_normalization,
        "unicode normalization must default to on"
    );
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
