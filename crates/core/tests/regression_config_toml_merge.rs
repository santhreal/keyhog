//! Regression coverage for the core `ScanConfig` TOML surface:
//! deserialize/merge/override precedence and fail-closed validation.
//!
//! Every assertion pins a concrete expected value (exact bool/int/f64/string/
//! enum variant/error message). The public config surface is
//! `keyhog_core::{ScanConfig, DedupScope, DEFAULT_MAX_FILE_SIZE_BYTES,
//! max_decode_depth_limit}` (re-exported via `api::* -> config::*` and
//! `dedup::*`); validation is exercised through the doc(hidden) testing facade
//! `keyhog_core::testing::{TestApi, CoreTestApi}::scan_config_validate`, which
//! surfaces the crate-private `ConfigError` as its exact `Display` string.

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{max_decode_depth_limit, DedupScope, ScanConfig, DEFAULT_MAX_FILE_SIZE_BYTES};

const F64_EPS: f64 = 1e-12;

/// A complete, valid TOML that supplies every REQUIRED field but deliberately
/// OMITS the three `#[serde(default = ...)]` fields
/// (`entropy_ml_authoritative`, `generic_keyword_low_entropy`,
/// `scan_comments`) so tests can assert their shipped serde defaults fill in.
const REQUIRED_ONLY_TOML: &str = r#"
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

/// A complete TOML whose every value DIFFERS from `ScanConfig::default()`, so a
/// passing parse proves the bytes were read (not that defaults leaked through).
const FULL_NONDEFAULT_TOML: &str = r#"
min_confidence = 0.65
max_decode_depth = 7
entropy_enabled = false
entropy_in_source_files = true
entropy_ml_authoritative = false
generic_keyword_low_entropy = false
entropy_threshold = 3.75
entropy_bpe_max_bytes_per_token = 3.0
min_secret_len = 24
max_file_size = 2048
dedup = "File"
ml_enabled = false
ml_weight = 0.25
unicode_normalization = false
validate_decode = false
max_decode_bytes = 65536
max_matches_per_chunk = 250
scan_comments = true
known_prefixes = ["AKIA", "xoxb-"]
secret_keywords = ["password", "token"]
test_keywords = ["mock"]
placeholder_keywords = ["changeme"]
"#;

fn parse(toml_text: &str) -> ScanConfig {
    toml::from_str::<ScanConfig>(toml_text)
        .unwrap_or_else(|e| panic!("expected valid ScanConfig TOML, got error: {e}"))
}

#[test]
fn default_config_has_exact_shipped_values() {
    let d = ScanConfig::default();
    assert!((d.min_confidence - 0.40).abs() < F64_EPS, "min_confidence");
    assert_eq!(d.max_decode_depth, 10);
    assert!(d.entropy_enabled);
    assert!(!d.entropy_in_source_files);
    assert!(d.entropy_ml_authoritative);
    assert!(d.generic_keyword_low_entropy);
    assert!(
        (d.entropy_threshold - 4.5).abs() < F64_EPS,
        "entropy_threshold"
    );
    assert!(
        (d.entropy_bpe_max_bytes_per_token - 2.2).abs() < F64_EPS,
        "entropy_bpe_max_bytes_per_token"
    );
    assert_eq!(d.min_secret_len, 16);
    assert_eq!(d.max_file_size, 100 * 1024 * 1024);
    assert_eq!(d.dedup, DedupScope::Credential);
    assert!(d.ml_enabled);
    assert!((d.ml_weight - 0.5).abs() < F64_EPS, "ml_weight");
    assert!(d.unicode_normalization);
    assert!(d.validate_decode);
    assert_eq!(d.max_decode_bytes, 512 * 1024);
    assert_eq!(d.max_matches_per_chunk, 1000);
    assert!(!d.scan_comments);
    assert_eq!(
        d.known_prefixes,
        vec![
            "AKIA".to_string(),
            "ASIA".to_string(),
            "ghp_".to_string(),
            "sk_".to_string()
        ]
    );
    assert_eq!(d.secret_keywords.len(), 20);
    assert_eq!(d.secret_keywords[0], "password");
    assert_eq!(d.test_keywords.len(), 9);
    assert_eq!(d.placeholder_keywords.len(), 10);
    assert_eq!(d.placeholder_keywords[0], "change_me");
}

#[test]
fn shipped_constants_match_default_and_expected() {
    assert_eq!(DEFAULT_MAX_FILE_SIZE_BYTES, 104_857_600);
    assert_eq!(
        ScanConfig::default().max_file_size,
        DEFAULT_MAX_FILE_SIZE_BYTES
    );
    assert_eq!(max_decode_depth_limit(), 10);
    // The default depth sits exactly on the accepted ceiling.
    assert_eq!(
        ScanConfig::default().max_decode_depth,
        max_decode_depth_limit()
    );
}

#[test]
fn full_toml_parses_every_field_to_exact_value() {
    let c = parse(FULL_NONDEFAULT_TOML);
    assert!((c.min_confidence - 0.65).abs() < F64_EPS);
    assert_eq!(c.max_decode_depth, 7);
    assert!(!c.entropy_enabled);
    assert!(c.entropy_in_source_files);
    assert!(!c.entropy_ml_authoritative);
    assert!(!c.generic_keyword_low_entropy);
    assert!((c.entropy_threshold - 3.75).abs() < F64_EPS);
    assert!((c.entropy_bpe_max_bytes_per_token - 3.0).abs() < F64_EPS);
    assert_eq!(c.min_secret_len, 24);
    assert_eq!(c.max_file_size, 2048);
    assert_eq!(c.dedup, DedupScope::File);
    assert!(!c.ml_enabled);
    assert!((c.ml_weight - 0.25).abs() < F64_EPS);
    assert!(!c.unicode_normalization);
    assert!(!c.validate_decode);
    assert_eq!(c.max_decode_bytes, 65_536);
    assert_eq!(c.max_matches_per_chunk, 250);
    assert!(c.scan_comments);
    assert_eq!(
        c.known_prefixes,
        vec!["AKIA".to_string(), "xoxb-".to_string()]
    );
    assert_eq!(
        c.secret_keywords,
        vec!["password".to_string(), "token".to_string()]
    );
    assert_eq!(c.test_keywords, vec!["mock".to_string()]);
    assert_eq!(c.placeholder_keywords, vec!["changeme".to_string()]);
}

#[test]
fn dedup_scope_all_three_variants_parse() {
    let none = parse(&REQUIRED_ONLY_TOML.replace("dedup = \"Credential\"", "dedup = \"None\""));
    assert_eq!(none.dedup, DedupScope::None);
    let file = parse(&REQUIRED_ONLY_TOML.replace("dedup = \"Credential\"", "dedup = \"File\""));
    assert_eq!(file.dedup, DedupScope::File);
    let cred = parse(REQUIRED_ONLY_TOML);
    assert_eq!(cred.dedup, DedupScope::Credential);
    // Adversarial: an unknown enum variant must be rejected, not silently mapped.
    let bad = toml::from_str::<ScanConfig>(
        &REQUIRED_ONLY_TOML.replace("dedup = \"Credential\"", "dedup = \"Everything\""),
    );
    assert!(
        bad.is_err(),
        "unknown DedupScope variant must fail to parse"
    );
}

#[test]
fn cli_override_beats_toml_beats_default_min_confidence() {
    // default layer
    assert!((ScanConfig::default().min_confidence - 0.40).abs() < F64_EPS);
    // TOML layer overrides default
    let mut cfg = parse(FULL_NONDEFAULT_TOML);
    assert!((cfg.min_confidence - 0.65).abs() < F64_EPS);
    // CLI layer (mutating the parsed struct, as build_scanner_config does) wins
    cfg.min_confidence = 0.90;
    assert!((cfg.min_confidence - 0.90).abs() < F64_EPS);
}

#[test]
fn cli_override_beats_toml_beats_default_max_decode_depth() {
    assert_eq!(ScanConfig::default().max_decode_depth, 10);
    let mut cfg = parse(FULL_NONDEFAULT_TOML);
    assert_eq!(cfg.max_decode_depth, 7); // TOML beats default
    cfg.max_decode_depth = 3; // CLI beats TOML
    assert_eq!(cfg.max_decode_depth, 3);
}

#[test]
fn omitted_optional_fields_take_shipped_defaults() {
    // REQUIRED_ONLY_TOML omits the four serde-default fields: an older config
    // must inherit the shipped defaults, never bool's `false` / f64's `0.0`.
    let c = parse(REQUIRED_ONLY_TOML);
    assert!(
        c.entropy_ml_authoritative,
        "entropy_ml_authoritative default"
    );
    assert!(
        c.generic_keyword_low_entropy,
        "generic_keyword_low_entropy default"
    );
    assert!(!c.scan_comments, "scan_comments default is false");
    // The BPE bound's serde default is LOAD-BEARING for recall: `f64`'s `0.0`
    // would treat every non-empty candidate as word-like (bytes-per-token is
    // always > 0) and suppress the entire entropy/generic surface. An old config
    // that predates the field must inherit the shipped 2.2, never 0.0.
    assert!(
        (c.entropy_bpe_max_bytes_per_token - 2.2).abs() < F64_EPS,
        "entropy_bpe_max_bytes_per_token must default to the shipped 2.2, not 0.0"
    );
    // Sanity: the required fields still parsed to their TOML values.
    assert!((c.min_confidence - 0.5).abs() < F64_EPS);
    assert_eq!(c.max_decode_depth, 4);
}

#[test]
fn explicit_entropy_bpe_max_bytes_per_token_overrides_default() {
    let toml_text = format!("{REQUIRED_ONLY_TOML}\nentropy_bpe_max_bytes_per_token = 3.4\n");
    let c = parse(&toml_text);
    assert!((c.entropy_bpe_max_bytes_per_token - 3.4).abs() < F64_EPS);
    // The other optionals still take their shipped defaults.
    assert!(c.entropy_ml_authoritative);
    assert!(c.generic_keyword_low_entropy);
}

#[test]
fn explicit_entropy_ml_authoritative_false_overrides_default() {
    let toml_text = format!("{REQUIRED_ONLY_TOML}\nentropy_ml_authoritative = false\n");
    let c = parse(&toml_text);
    assert!(!c.entropy_ml_authoritative);
    // The other two optionals still default on/off respectively.
    assert!(c.generic_keyword_low_entropy);
    assert!(!c.scan_comments);
}

#[test]
fn explicit_generic_keyword_low_entropy_false_overrides_default() {
    let toml_text = format!("{REQUIRED_ONLY_TOML}\ngeneric_keyword_low_entropy = false\n");
    let c = parse(&toml_text);
    assert!(!c.generic_keyword_low_entropy);
    assert!(c.entropy_ml_authoritative);
}

#[test]
fn explicit_scan_comments_true_overrides_default() {
    let toml_text = format!("{REQUIRED_ONLY_TOML}\nscan_comments = true\n");
    let c = parse(&toml_text);
    assert!(c.scan_comments);
}

#[test]
fn unknown_key_fails_closed_with_exact_error() {
    // deny_unknown_fields: an operator typo must fail loudly, never be ignored.
    let toml_text = format!("{REQUIRED_ONLY_TOML}\nbogus_key = 42\n");
    let err = toml::from_str::<ScanConfig>(&toml_text)
        .expect_err("unknown field must fail closed")
        .to_string();
    assert!(
        err.contains("unknown field `bogus_key`"),
        "expected 'unknown field `bogus_key`' in error, got: {err}"
    );
}

#[test]
fn missing_required_field_fails_with_exact_error() {
    // Drop a required (non-serde-default) field; deserialization must reject it.
    let toml_text = REQUIRED_ONLY_TOML.replace("min_confidence = 0.5\n", "");
    let err = toml::from_str::<ScanConfig>(&toml_text)
        .expect_err("missing required field must fail")
        .to_string();
    assert!(
        err.contains("missing field `min_confidence`"),
        "expected 'missing field `min_confidence`' in error, got: {err}"
    );
}

#[test]
fn out_of_range_min_confidence_rejected_exact_error() {
    let mut cfg = ScanConfig::default();
    cfg.min_confidence = 1.5;
    let err = TestApi
        .scan_config_validate(&cfg)
        .expect_err("min_confidence 1.5 must be rejected");
    assert_eq!(err, "min_confidence must be between 0.0 and 1.0, found 1.5");

    // Negative twin below the interval, exact message with the negative value.
    cfg.min_confidence = -0.25;
    let err = TestApi
        .scan_config_validate(&cfg)
        .expect_err("negative min_confidence must be rejected");
    assert_eq!(
        err,
        "min_confidence must be between 0.0 and 1.0, found -0.25"
    );
}

#[test]
fn out_of_range_max_decode_depth_rejected_exact_error() {
    let mut cfg = ScanConfig::default();
    cfg.max_decode_depth = 11; // one past the ceiling of 10
    let err = TestApi
        .scan_config_validate(&cfg)
        .expect_err("max_decode_depth 11 must be rejected");
    assert_eq!(err, "max_decode_depth exceeds limit of 10, found 11");
}

#[test]
fn min_confidence_closed_interval_boundaries() {
    let mut cfg = ScanConfig::default();
    // Boundaries are inclusive: 0.0 and 1.0 are both valid.
    cfg.min_confidence = 0.0;
    assert_eq!(TestApi.scan_config_validate(&cfg), Ok(()));
    cfg.min_confidence = 1.0;
    assert_eq!(TestApi.scan_config_validate(&cfg), Ok(()));
    // Just outside on the high side is rejected.
    cfg.min_confidence = 1.0000001;
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("min_confidence must be between 0.0 and 1.0, found 1.0000001".to_string())
    );
}

#[test]
fn max_decode_depth_boundary_valid_at_limit_invalid_above() {
    let mut cfg = ScanConfig::default();
    // Exactly at the limit (10) is accepted.
    cfg.max_decode_depth = max_decode_depth_limit();
    assert_eq!(TestApi.scan_config_validate(&cfg), Ok(()));
    // Zero (no recursion) is accepted.
    cfg.max_decode_depth = 0;
    assert_eq!(TestApi.scan_config_validate(&cfg), Ok(()));
    // One past the limit is rejected.
    cfg.max_decode_depth = max_decode_depth_limit() + 1;
    assert_eq!(
        TestApi.scan_config_validate(&cfg),
        Err("max_decode_depth exceeds limit of 10, found 11".to_string())
    );
}

#[test]
fn toml_roundtrip_default_is_identity() {
    let original = ScanConfig::default();
    let serialized = toml::to_string(&original).expect("serialize default ScanConfig");
    let reparsed = parse(&serialized);
    assert!((reparsed.min_confidence - 0.40).abs() < F64_EPS);
    assert_eq!(reparsed.max_decode_depth, 10);
    assert_eq!(reparsed.dedup, DedupScope::Credential);
    assert_eq!(reparsed.max_file_size, DEFAULT_MAX_FILE_SIZE_BYTES);
    assert_eq!(reparsed.max_decode_bytes, 512 * 1024);
    assert_eq!(reparsed.known_prefixes, original.known_prefixes);
    assert_eq!(reparsed.secret_keywords, original.secret_keywords);
    assert!(reparsed.entropy_ml_authoritative);
    assert!(reparsed.generic_keyword_low_entropy);
    assert!(!reparsed.scan_comments);
    // The round-tripped config must still validate.
    assert_eq!(TestApi.scan_config_validate(&reparsed), Ok(()));
}
