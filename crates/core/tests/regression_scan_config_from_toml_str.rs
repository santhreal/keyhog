//! The public, fail-closed `ScanConfig` loader + the completeness of `validate()`.
//!
//! `keyhog-core` is a published library: `ScanConfig` is `pub`, derives
//! `Deserialize`, and is documented as the canonical config surface. Before this
//! contract the only validator (`validate`) was `pub(crate)` and was NEVER called
//! on any production path, and it checked only TWO of the config's range-bearing
//! fields (`min_confidence`, `max_decode_depth`). A library consumer who
//! deserialized a config with `ml_weight = 2.0` (over-weights the model, silently
//! distorting every confidence) or `entropy_bpe_max_bytes_per_token = 0.0`
//! (treats every candidate as word-like → total recall wipeout) or
//! `entropy_threshold = nan` (`entropy >= NaN` is always false → nothing surfaces)
//! got a silently-broken scan with no error.
//!
//! [`ScanConfig::from_toml_str`] composes deserialize + the now-complete
//! [`ScanConfig::validate`] into ONE fail-closed load, and every assertion here
//! pins the EXACT [`ConfigError`] variant (and its offending value), never a bare
//! boolean — the deserialize step SUCCEEDS on these (the values are valid f64s),
//! so it is the validation step that must reject them.

use keyhog_core::{ConfigError, ScanConfig};

/// Serialize the shipped default to TOML, then replace exactly one `key = value`
/// scalar line. This keeps the tests robust to future field additions instead of
/// hand-maintaining a full ~20-field TOML that `#[serde(deny_unknown_fields)]`
/// plus all-required-fields would make brittle.
fn default_toml_with(field: &str, value: &str) -> String {
    let base = toml::to_string(&ScanConfig::default()).expect("default ScanConfig serializes");
    let needle = format!("{field} = ");
    let mut replaced = false;
    let out: Vec<String> = base
        .lines()
        .map(|line| {
            if line.starts_with(&needle) {
                replaced = true;
                format!("{field} = {value}")
            } else {
                line.to_string()
            }
        })
        .collect();
    assert!(
        replaced,
        "field `{field}` not found as a scalar line in the serialized default TOML"
    );
    out.join("\n")
}

/// The shipped default TOML with one extra (unknown) key appended.
fn default_toml_plus(extra_line: &str) -> String {
    let base = toml::to_string(&ScanConfig::default()).expect("default ScanConfig serializes");
    format!("{base}\n{extra_line}\n")
}

// --- happy path: valid configs load and round-trip -------------------------

#[test]
fn shipped_default_round_trips_through_from_toml_str() {
    let base = toml::to_string(&ScanConfig::default()).expect("default serializes");
    let cfg = ScanConfig::from_toml_str(&base).expect("the shipped default must load validated");
    // The defaults are themselves a validity contract, and survive a full
    // serialize → deserialize → validate round-trip byte-for-value.
    assert!((cfg.min_confidence - 0.40).abs() < 1e-9);
    assert!((cfg.ml_weight - 0.5).abs() < 1e-9);
    assert_eq!(cfg.max_decode_depth, 10);
}

#[test]
fn in_range_overrides_load() {
    let cfg = ScanConfig::from_toml_str(&default_toml_with("min_confidence", "0.85"))
        .expect("an in-range min_confidence must load");
    assert!((cfg.min_confidence - 0.85).abs() < 1e-9);

    let cfg = ScanConfig::from_toml_str(&default_toml_with("ml_weight", "1.0"))
        .expect("ml_weight at the inclusive upper boundary must load");
    assert!((cfg.ml_weight - 1.0).abs() < 1e-9);
}

#[test]
fn very_large_finite_bpe_bound_is_accepted() {
    // The field docs say a very large value "effectively disables the gate": a
    // large FINITE bound is legal and must NOT be rejected by the > 0 check.
    let cfg = ScanConfig::from_toml_str(&default_toml_with(
        "entropy_bpe_max_bytes_per_token",
        "1000000.0",
    ))
    .expect("a large finite bpe bound is a valid (gate-disabling) config");
    assert!(cfg.entropy_bpe_max_bytes_per_token >= 1_000_000.0);
}

#[test]
fn finite_negative_entropy_threshold_is_rejected_not_silently_normalized() {
    let err = ScanConfig::from_toml_str(&default_toml_with("entropy_threshold", "-1.0"))
        .expect_err("a negative entropy threshold is outside the byte-entropy domain");
    assert!(matches!(
        err,
        ConfigError::InvalidEntropyThreshold(value) if value == -1.0
    ));
}

// --- range validation: deserialize succeeds, validate rejects --------------

#[test]
fn over_range_min_confidence_is_rejected() {
    let err = ScanConfig::from_toml_str(&default_toml_with("min_confidence", "5.0"))
        .expect_err("min_confidence = 5.0 must be rejected");
    assert!(
        matches!(err, ConfigError::InvalidConfidence(v) if v == 5.0),
        "expected InvalidConfidence(5.0), got {err:?}"
    );
}

#[test]
fn negative_min_confidence_is_rejected() {
    let err = ScanConfig::from_toml_str(&default_toml_with("min_confidence", "-0.5"))
        .expect_err("negative min_confidence must be rejected");
    assert!(
        matches!(err, ConfigError::InvalidConfidence(v) if v == -0.5),
        "expected InvalidConfidence(-0.5), got {err:?}"
    );
}

#[test]
fn over_range_ml_weight_is_rejected() {
    let err = ScanConfig::from_toml_str(&default_toml_with("ml_weight", "2.0"))
        .expect_err("ml_weight = 2.0 must be rejected");
    assert!(
        matches!(err, ConfigError::InvalidMlWeight(v) if v == 2.0),
        "expected InvalidMlWeight(2.0), got {err:?}"
    );
}

#[test]
fn negative_ml_weight_is_rejected() {
    let err = ScanConfig::from_toml_str(&default_toml_with("ml_weight", "-0.25"))
        .expect_err("negative ml_weight must be rejected");
    assert!(
        matches!(err, ConfigError::InvalidMlWeight(v) if v == -0.25),
        "expected InvalidMlWeight(-0.25), got {err:?}"
    );
}

#[test]
fn zero_bpe_bound_is_rejected_as_recall_wipeout() {
    let err =
        ScanConfig::from_toml_str(&default_toml_with("entropy_bpe_max_bytes_per_token", "0.0"))
            .expect_err(
                "a 0.0 bpe bound suppresses the whole entropy surface and must be rejected",
            );
    assert!(
        matches!(err, ConfigError::InvalidBpeBound(v) if v == 0.0),
        "expected InvalidBpeBound(0.0), got {err:?}"
    );
}

#[test]
fn negative_bpe_bound_is_rejected() {
    let err = ScanConfig::from_toml_str(&default_toml_with(
        "entropy_bpe_max_bytes_per_token",
        "-3.0",
    ))
    .expect_err("a negative bpe bound must be rejected");
    assert!(
        matches!(err, ConfigError::InvalidBpeBound(v) if v == -3.0),
        "expected InvalidBpeBound(-3.0), got {err:?}"
    );
}

#[test]
fn infinite_bpe_bound_is_rejected() {
    // TOML 1.0 has an `inf` float literal; an infinite bound is non-finite and
    // rejected (a large FINITE value is the supported way to disable the gate).
    let err =
        ScanConfig::from_toml_str(&default_toml_with("entropy_bpe_max_bytes_per_token", "inf"))
            .expect_err("an infinite bpe bound must be rejected");
    assert!(
        matches!(err, ConfigError::InvalidBpeBound(v) if v.is_infinite()),
        "expected InvalidBpeBound(inf), got {err:?}"
    );
}

#[test]
fn nan_entropy_threshold_is_rejected() {
    // `entropy_threshold = nan` deserializes to f64::NAN, which would make every
    // `entropy >= threshold` comparison false — a silent whole-surface wipeout.
    let err = ScanConfig::from_toml_str(&default_toml_with("entropy_threshold", "nan"))
        .expect_err("a NaN entropy_threshold must be rejected");
    assert!(
        matches!(err, ConfigError::NonFiniteEntropyThreshold(v) if v.is_nan()),
        "expected NonFiniteEntropyThreshold(NaN), got {err:?}"
    );
}

#[test]
fn entropy_threshold_outside_byte_entropy_range_is_rejected() {
    for (raw, expected) in [("-0.1", -0.1), ("8.1", 8.1)] {
        let err = ScanConfig::from_toml_str(&default_toml_with("entropy_threshold", raw))
            .expect_err("entropy threshold outside [0,8] must be rejected");
        assert!(
            matches!(err, ConfigError::InvalidEntropyThreshold(value) if value == expected),
            "expected InvalidEntropyThreshold({expected}), got {err:?}"
        );
    }
}

#[test]
fn over_limit_decode_depth_is_rejected() {
    let err = ScanConfig::from_toml_str(&default_toml_with("max_decode_depth", "999"))
        .expect_err("max_decode_depth past the safety ceiling must be rejected");
    assert!(
        matches!(err, ConfigError::DepthTooHigh(v) if v == 999),
        "expected DepthTooHigh(999), got {err:?}"
    );
}

// --- parse failures fail closed as Parse, not a panic ----------------------

#[test]
fn malformed_toml_is_a_parse_error() {
    let err = ScanConfig::from_toml_str("this is not = valid toml @@@")
        .expect_err("syntactically invalid TOML must be a Parse error, not a panic");
    assert!(
        matches!(err, ConfigError::Parse(_)),
        "expected Parse(_), got {err:?}"
    );
}

#[test]
fn unknown_field_is_a_parse_error() {
    // `ScanConfig` is `#[serde(deny_unknown_fields)]`: a stray key in an otherwise
    // complete, valid config fails closed at deserialize (a typo'd knob is not
    // silently ignored).
    let err = ScanConfig::from_toml_str(&default_toml_plus("mystery_knob = 3"))
        .expect_err("an unknown field must be rejected by deny_unknown_fields");
    match err {
        ConfigError::Parse(msg) => assert!(
            msg.contains("mystery_knob") || msg.contains("unknown field"),
            "parse error should name the unknown field, got: {msg}"
        ),
        other => panic!("expected Parse(_), got {other:?}"),
    }
}

#[test]
fn empty_toml_is_a_parse_error_for_missing_required_fields() {
    // Most fields are required (no serde default); an empty document cannot
    // deserialize and must fail closed rather than silently synthesize a config.
    let err = ScanConfig::from_toml_str("")
        .expect_err("an empty TOML is missing required fields and must fail");
    assert!(
        matches!(err, ConfigError::Parse(_)),
        "expected Parse(_), got {err:?}"
    );
}

// --- validate() called directly on a hand-built ScanConfig -----------------

#[test]
fn validate_on_shipped_default_is_ok() {
    assert!(ScanConfig::default().validate().is_ok());
}

#[test]
fn validate_rejects_each_out_of_range_field_directly() {
    // The hand-built (non-TOML) path: a consumer who mutates a default and calls
    // validate() gets the same fail-closed guarantees as from_toml_str.
    let mut cfg = ScanConfig::default();
    cfg.min_confidence = 1.5;
    assert!(matches!(
        cfg.validate(),
        Err(ConfigError::InvalidConfidence(_))
    ));

    let mut cfg = ScanConfig::default();
    cfg.ml_weight = f64::NAN;
    assert!(
        matches!(cfg.validate(), Err(ConfigError::InvalidMlWeight(_))),
        "a NaN ml_weight must be rejected (RangeInclusive::contains is false for NaN)"
    );

    let mut cfg = ScanConfig::default();
    cfg.entropy_bpe_max_bytes_per_token = f64::NAN;
    assert!(matches!(
        cfg.validate(),
        Err(ConfigError::InvalidBpeBound(_))
    ));

    let mut cfg = ScanConfig::default();
    cfg.entropy_threshold = f64::INFINITY;
    assert!(matches!(
        cfg.validate(),
        Err(ConfigError::NonFiniteEntropyThreshold(_))
    ));

    let mut cfg = ScanConfig::default();
    cfg.entropy_threshold = 8.01;
    assert!(matches!(
        cfg.validate(),
        Err(ConfigError::InvalidEntropyThreshold(_))
    ));
}

#[test]
fn validate_accepts_unit_interval_boundaries() {
    let mut cfg = ScanConfig::default();
    for &boundary in &[0.0, 1.0] {
        cfg.min_confidence = boundary;
        cfg.ml_weight = boundary;
        assert!(
            cfg.validate().is_ok(),
            "min_confidence/ml_weight = {boundary} (inclusive boundary) must validate"
        );
    }
}
