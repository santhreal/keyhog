use super::*;

#[test]
fn tuning_effective_resolves_compiled_defaults_when_unset() {
    let cfg = ScannerTuningConfig::default();
    assert!(cfg.fallback_hs_effective());
    assert_eq!(
        cfg.hs_prefilter_max_len_effective(),
        ScannerTuningConfig::HS_PREFILTER_MAX_LEN_DEFAULT
    );
    assert_eq!(
        cfg.hs_shard_target_effective(),
        ScannerTuningConfig::HS_SHARD_TARGET_DEFAULT
    );
    assert!(cfg.fallback_anchor_effective());
    assert!(!cfg.fallback_reverse_effective()); // FALLBACK_REVERSE_DEFAULT = false
    assert_eq!(
        cfg.gpu_moe_timeout_ms_effective(),
        ScannerTuningConfig::GPU_MOE_TIMEOUT_MS_DEFAULT
    );
}

#[test]
fn tuning_effective_honors_explicit_overrides() {
    let cfg = ScannerTuningConfig {
        phase2_hs: Some(false),
        hs_shard_target: Some(999),
        fallback_reverse: Some(true),
        gpu_moe_timeout_ms: Some(1_500),
        ..ScannerTuningConfig::default()
    };
    assert!(!cfg.fallback_hs_effective());
    assert_eq!(cfg.hs_shard_target_effective(), 999);
    assert!(cfg.fallback_reverse_effective());
    assert_eq!(cfg.gpu_moe_timeout_ms_effective(), 1_500);
}

#[test]
fn sanitise_scrubs_nan_probabilities_to_canonical_defaults() {
    let canon = keyhog_core::ScanConfig::default();
    let mut cfg = ScannerConfig::default();
    cfg.ml_weight = f64::NAN;
    cfg.min_confidence = f64::NAN;
    cfg.sanitise();
    assert_eq!(cfg.ml_weight, canon.ml_weight);
    assert_eq!(cfg.min_confidence, canon.min_confidence);
}

#[test]
fn sanitise_clamps_out_of_range_probabilities() {
    let mut cfg = ScannerConfig::default();
    cfg.ml_weight = 5.0;
    cfg.min_confidence = -2.0;
    cfg.sanitise();
    assert_eq!(cfg.ml_weight, 1.0);
    assert_eq!(cfg.min_confidence, 0.0);
}

#[test]
fn sanitise_bounds_entropy_threshold() {
    let canon = keyhog_core::ScanConfig::default();
    // NaN and negative both scrub to the canonical shipped floor.
    let mut nanned = ScannerConfig::default();
    nanned.entropy_threshold = f64::NAN;
    nanned.sanitise();
    assert_eq!(nanned.entropy_threshold, canon.entropy_threshold);
    let mut negative = ScannerConfig::default();
    negative.entropy_threshold = -1.0;
    negative.sanitise();
    assert_eq!(negative.entropy_threshold, canon.entropy_threshold);
    // Above the 8-bit byte-entropy ceiling clamps to exactly 8.0.
    let mut high = ScannerConfig::default();
    high.entropy_threshold = 99.0;
    high.sanitise();
    assert_eq!(high.entropy_threshold, 8.0);
}

#[test]
fn sanitise_scrubs_bpe_bound_nan_and_nonpositive_but_keeps_high() {
    let canon = keyhog_core::ScanConfig::default();
    // NaN would silently break the `cpt > bound` gate (all comparisons false
    // → nothing ever suppressed); it must scrub to the canonical 2.2.
    let mut nanned = ScannerConfig::default();
    nanned.entropy_bpe_max_bytes_per_token = f64::NAN;
    nanned.sanitise();
    assert_eq!(
        nanned.entropy_bpe_max_bytes_per_token,
        canon.entropy_bpe_max_bytes_per_token
    );
    // A negative bound would suppress EVERY candidate (cpt is always ≥ ~0.5 >
    // any negative); it scrubs to the canonical default, not left as a footgun.
    let mut negative = ScannerConfig::default();
    negative.entropy_bpe_max_bytes_per_token = -1.0;
    negative.sanitise();
    assert_eq!(
        negative.entropy_bpe_max_bytes_per_token,
        canon.entropy_bpe_max_bytes_per_token
    );
    let mut zero = ScannerConfig::default();
    zero.entropy_bpe_max_bytes_per_token = 0.0;
    zero.sanitise();
    assert_eq!(
        zero.entropy_bpe_max_bytes_per_token,
        canon.entropy_bpe_max_bytes_per_token
    );
    // A deliberately HIGH bound is the documented way to disable the gate
    // (trade precision for recall) and must be preserved, NOT clamped.
    let mut high = ScannerConfig::default();
    high.entropy_bpe_max_bytes_per_token = 99.0;
    high.sanitise();
    assert_eq!(high.entropy_bpe_max_bytes_per_token, 99.0);
}

#[test]
fn scan_config_conversion_preserves_explicit_bpe_precedence() {
    let default = ScannerConfig::default();
    assert_eq!(default.entropy_bpe_max_bytes_per_token_override, None);

    let mut scan = ScanConfig::default();
    scan.entropy_bpe_max_bytes_per_token = 3.4;
    let explicit = ScannerConfig::from(scan);
    assert_eq!(explicit.entropy_bpe_max_bytes_per_token_override, Some(3.4));

    let explicit_default = ScannerConfig::default()
        .with_entropy_bpe_max_bytes_per_token_override(2.2)
        .expect("the compiled default is a valid explicit override");
    assert_eq!(
        explicit_default.entropy_bpe_max_bytes_per_token_override,
        Some(2.2),
        "library callers must be able to preserve an explicit default-valued override"
    );

    let rejected = ScannerConfig::default()
        .with_entropy_bpe_max_bytes_per_token_override(0.0)
        .expect_err("a zero BPE ceiling must fail closed");
    assert!(matches!(
        rejected,
        keyhog_core::ConfigError::InvalidBpeBound(bound) if bound == 0.0
    ));

    let mut invalid = ScannerConfig::default();
    invalid.entropy_bpe_max_bytes_per_token_override = Some(f64::NAN);
    invalid.sanitise();
    assert_eq!(
        invalid.entropy_bpe_max_bytes_per_token_override, None,
        "an invalid programmatic override must restore detector-local policy"
    );
}

#[test]
fn detector_ml_weight_remains_authoritative_until_override_is_explicit() {
    let default = ScannerConfig::default();
    assert_eq!(default.ml_weight_override, None);

    let explicit = ScannerConfig::default()
        .with_ml_weight_override(0.75)
        .expect("a unit-interval model weight is valid");
    assert_eq!(explicit.ml_weight_override, Some(0.75));

    let invalid = ScannerConfig::default().with_ml_weight_override(1.5);
    assert!(invalid.is_err());
}
