//! Regression coverage for `ScanConfig` field validation and fail-closed
//! deserialization, focused on the ADVERSARIAL and TWO-STAGE surfaces that the
//! merge test (`regression_config_toml_merge.rs`) does not exercise:
//!
//!   * non-finite / signed-zero `min_confidence` floats (NaN, +inf, -inf, -0.0),
//!   * `max_decode_depth` at the `usize::MAX` extreme,
//!   * the deserialize-accepts-then-`validate`-rejects layering (an
//!     out-of-range value is a VALID TOML value but an INVALID config), and
//!   * the check ORDER inside `validate` (confidence is checked before depth).
//!
//! The public config surface is `keyhog_core::{ScanConfig, DedupScope,
//! DEFAULT_MAX_FILE_SIZE_BYTES, max_decode_depth_limit}`. `validate` and its
//! crate-private `ConfigError` are reached through the doc(hidden) testing
//! facade `keyhog_core::testing::{TestApi, CoreTestApi}::scan_config_validate`,
//! which surfaces the error as its exact `Display` string. Every assertion pins
//! a concrete expected value (exact bool / f64 / string / `Result`), never a
//! shape check.

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{max_decode_depth_limit, ScanConfig};

const F64_EPS: f64 = 1e-12;

/// A complete, valid TOML supplying every REQUIRED (non-serde-default) field.
/// Callers `.replace(...)` a single value to build an out-of-range-but-parseable
/// document, proving deserialization accepts what `validate` later rejects.
const BASE_TOML: &str = r#"
min_confidence = 0.5
max_decode_depth = 4
entropy_enabled = true
entropy_in_source_files = false
entropy_threshold = 4.0
min_secret_len = 20
max_file_size = 1000
dedup = "Credential"
ml_enabled = true
ml_weight = 0.5
unicode_normalization = true
validate_decode = true
max_decode_bytes = 4096
max_matches_per_chunk = 100
known_prefixes = []
secret_keywords = []
test_keywords = []
placeholder_keywords = []
"#;

/// Parse a TOML expected to deserialize into a `ScanConfig` (validation is a
/// SEPARATE later step and is NOT performed here).
fn parse(toml_text: &str) -> ScanConfig {
    toml::from_str::<ScanConfig>(toml_text)
        .unwrap_or_else(|e| panic!("expected TOML to deserialize into ScanConfig, got: {e}"))
}

/// The shipped default config must pass validation unchanged, the defaults are
/// themselves a validity contract, not merely a starting point to be edited.
#[test]
fn default_config_passes_validation() {
    let cfg = ScanConfig::default();
    assert_eq!(TestApi.scan_config_validate(&cfg), Ok(()));
    // Guard the two load-bearing fields the validator gates on, so a future
    // default change that would break validation is caught here too.
    assert!((cfg.min_confidence - 0.40).abs() < F64_EPS);
    assert_eq!(cfg.max_decode_depth, 10);
}

/// Both ends of the closed unit interval `[0.0, 1.0]` are accepted.
#[test]
fn min_confidence_zero_and_one_boundaries_accepted() {
    let mut cfg = ScanConfig::default();
    cfg.min_confidence = 0.0;
    assert_eq!(TestApi.scan_config_validate(&cfg), Ok(()));
    cfg.min_confidence = 1.0;
    assert_eq!(TestApi.scan_config_validate(&cfg), Ok(()));
}

/// Adversarial float: `-0.0` compares equal to `0.0`, so it is INSIDE the
/// closed interval and must be accepted (not spuriously rejected as "negative").
#[test]
fn min_confidence_negative_zero_accepted() {
    let mut cfg = ScanConfig::default();
    cfg.min_confidence = -0.0;
    assert_eq!(TestApi.scan_config_validate(&cfg), Ok(()));
}

/// A value just above `1.0` is rejected with the exact ceiling message.
#[test]
fn min_confidence_above_one_rejected_exact_error() {
    let mut cfg = ScanConfig::default();
    cfg.min_confidence = 1.5;
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("min_confidence must be between 0.0 and 1.0, found 1.5".to_string())
    );
}

/// Negative twin: a value below `0.0` is rejected and the message echoes the
/// exact offending (negative) value.
#[test]
fn min_confidence_negative_rejected_exact_error() {
    let mut cfg = ScanConfig::default();
    cfg.min_confidence = -0.25;
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("min_confidence must be between 0.0 and 1.0, found -0.25".to_string())
    );
}

/// Adversarial non-finite: `NaN` is not contained in any range (all NaN
/// comparisons are false), so it must fail closed with `found NaN`.
#[test]
fn min_confidence_nan_rejected_exact_error() {
    let mut cfg = ScanConfig::default();
    cfg.min_confidence = f64::NAN;
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("min_confidence must be between 0.0 and 1.0, found NaN".to_string())
    );
}

/// Adversarial non-finite: `+inf` is above the ceiling and rejected as `inf`.
#[test]
fn min_confidence_positive_infinity_rejected_exact_error() {
    let mut cfg = ScanConfig::default();
    cfg.min_confidence = f64::INFINITY;
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("min_confidence must be between 0.0 and 1.0, found inf".to_string())
    );
}

/// Adversarial non-finite: `-inf` is below the floor and rejected as `-inf`.
#[test]
fn min_confidence_negative_infinity_rejected_exact_error() {
    let mut cfg = ScanConfig::default();
    cfg.min_confidence = f64::NEG_INFINITY;
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("min_confidence must be between 0.0 and 1.0, found -inf".to_string())
    );
}

/// `max_decode_depth` of `0` (no recursion) and exactly the ceiling are both
/// accepted; the ceiling is sourced from the public `max_decode_depth_limit()`.
#[test]
fn max_decode_depth_zero_and_limit_accepted() {
    assert_eq!(max_decode_depth_limit(), 10);
    let mut cfg = ScanConfig::default();
    cfg.max_decode_depth = 0;
    assert_eq!(TestApi.scan_config_validate(&cfg), Ok(()));
    cfg.max_decode_depth = max_decode_depth_limit();
    assert_eq!(TestApi.scan_config_validate(&cfg), Ok(()));
}

/// A depth well above the ceiling is rejected with the exact message echoing the
/// limit (10) and the offending value.
#[test]
fn max_decode_depth_above_limit_rejected_exact_error() {
    let mut cfg = ScanConfig::default();
    cfg.max_decode_depth = 20;
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("max_decode_depth exceeds limit of 10, found 20".to_string())
    );
}

/// Boundary extreme: `usize::MAX` is rejected, and the message renders the full
/// integer (no overflow / truncation in the error path).
#[test]
fn max_decode_depth_usize_max_rejected_exact_error() {
    let mut cfg = ScanConfig::default();
    cfg.max_decode_depth = usize::MAX;
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("max_decode_depth exceeds limit of 10, found 18446744073709551615".to_string())
    );
}

/// Order contract: when BOTH `min_confidence` and `max_decode_depth` are out of
/// range, `validate` reports the confidence error FIRST (it is checked before
/// depth), so the depth violation is not what surfaces.
#[test]
fn validate_reports_confidence_error_before_depth_error() {
    let mut cfg = ScanConfig::default();
    cfg.min_confidence = 1.5; // invalid
    cfg.max_decode_depth = 99; // also invalid
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("min_confidence must be between 0.0 and 1.0, found 1.5".to_string())
    );
}

/// Two-stage layering: an out-of-range `min_confidence` is a perfectly VALID
/// TOML float, so deserialization SUCCEEDS; the config is caught only by the
/// later `validate` step. Proves the two responsibilities are distinct.
#[test]
fn toml_out_of_range_confidence_parses_then_validate_rejects() {
    let doc = BASE_TOML.replace("min_confidence = 0.5", "min_confidence = 1.5");
    let cfg = parse(&doc); // deserialization accepts it
    assert!((cfg.min_confidence - 1.5).abs() < F64_EPS);
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("min_confidence must be between 0.0 and 1.0, found 1.5".to_string())
    );
}

/// Two-stage layering for depth: `max_decode_depth = 25` deserializes fine (it
/// is a valid `usize`) but fails `validate` against the ceiling.
#[test]
fn toml_out_of_range_depth_parses_then_validate_rejects() {
    let doc = BASE_TOML.replace("max_decode_depth = 4", "max_decode_depth = 25");
    let cfg = parse(&doc);
    assert_eq!(cfg.max_decode_depth, 25); // deserialization accepted it
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("max_decode_depth exceeds limit of 10, found 25".to_string())
    );
}

/// `#[serde(deny_unknown_fields)]`: an operator typo must fail closed at
/// deserialization, naming the offending key rather than being silently dropped.
#[test]
fn unknown_field_fails_closed_naming_field() {
    let doc = format!("{BASE_TOML}\nmax_decode_dept = 3\n"); // typo: missing 'h'
    let err = toml::from_str::<ScanConfig>(&doc)
        .expect_err("unknown field must fail closed")
        .to_string();
    assert!(
        err.contains("unknown field `max_decode_dept`"),
        "expected 'unknown field `max_decode_dept`' in error, got: {err}"
    );
}

/// A wrong-typed value for a required field is rejected at deserialization, and
/// the rendered error both names the offending key and states the type mismatch.
#[test]
fn wrong_type_min_confidence_field_rejected() {
    let doc = BASE_TOML.replace("min_confidence = 0.5", "min_confidence = \"high\"");
    let err = toml::from_str::<ScanConfig>(&doc)
        .expect_err("string for a float field must be rejected")
        .to_string();
    assert!(
        err.contains("min_confidence"),
        "error must name the offending key, got: {err}"
    );
    assert!(
        err.contains("invalid type"),
        "error must state the type mismatch, got: {err}"
    );
}
