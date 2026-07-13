//! Regression coverage for KeyHog's config LAYER PRECEDENCE, focused on the
//! ENVIRONMENT layer and the full resolution order:
//!
//!     CLI override  >  environment  >  `.keyhog.toml`  >  shipped default
//!
//! `ScanConfig` itself owns three of those four layers directly: the shipped
//! `Default`, the `serde`/`toml` deserialize of a `.keyhog.toml`, and the
//! CLI override the CLI applies by mutating the parsed struct (exactly what
//! `cli::build_scanner_config` does, see the `ScanConfig::validate` comment in
//! `crates/core/src/config.rs`). The environment layer is wired by the CLI on
//! top of that with the SAME `Option::is_none()`-wins gate used by
//! `apply_scan_section` (`if args.min_confidence.is_none() { args.min_confidence
//! = ... }`): env is consulted only when the CLI did not set the knob, and env
//! sits above TOML/default.
//!
//! The `resolve_*` helpers below implement precisely that gate; every layer's
//! *value* is produced by REAL core API. `ScanConfig::default()`,
//! `toml::from_str::<ScanConfig>`, `f64`/`usize` parsing of the ambient env
//! string, and every resolved config is validated through core's real
//! `validate()` via the doc(hidden) `testing` facade, which surfaces the
//! crate-private `ConfigError` as its exact `Display` string. Env parse failure
//! is surfaced, never silently swallowed (Law 10: no silent fallback).
//!
//! Distinct from `regression_config_toml_merge` (which pins the pure TOML/serde
//! surface): this file pins the ENV layer and the four-way precedence ORDER.
//!
//! Each test uses a UNIQUE env var name so the process-global env mutation of
//! one test cannot race a parallel sibling in this binary.

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{max_decode_depth_limit, ScanConfig};

const F64_EPS: f64 = 1e-12;

/// A complete, valid `.keyhog.toml` whose `min_confidence` (0.65) and
/// `max_decode_depth` (7) both DIFFER from the shipped defaults (0.40 / 10), so
/// "TOML beats default" is observable and not a default leaking through.
const TOML_LAYER: &str = r#"
min_confidence = 0.65
max_decode_depth = 7
entropy_enabled = true
entropy_in_source_files = false
entropy_threshold = 4.5
min_secret_len = 16
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

/// Error raised while resolving a knob across layers. Both arms carry the exact
/// offending detail so a fail-closed rejection is asserted concretely, never as
/// a bare `is_err()`.
#[derive(Debug, PartialEq)]
enum ResolveError {
    /// The ambient env string was not a valid value for the knob's type.
    EnvParse(String),
    /// The fully-resolved config failed core `validate()`; carries the exact
    /// `ConfigError` `Display` string.
    Validate(String),
}

/// Resolve `min_confidence` across all four layers with the CLI `is_none()`-wins
/// gate. `cli` is the explicit CLI override (highest); `env_key` names the
/// ambient env var (second); `toml_text` is the parsed `.keyhog.toml` (third);
/// `ScanConfig::default()` is the floor.
fn resolve_min_confidence(
    cli: Option<f64>,
    env_key: &str,
    toml_text: Option<&str>,
) -> Result<ScanConfig, ResolveError> {
    let mut cfg = match toml_text {
        Some(text) => toml::from_str::<ScanConfig>(text)
            .unwrap_or_else(|e| panic!("TOML layer must be valid ScanConfig, got: {e}")),
        None => ScanConfig::default(),
    };
    // CLI wins outright; env is consulted only if the CLI left the knob unset,
    // mirroring `apply_scan_section`'s `if args.<knob>.is_none()` gate.
    match cli {
        Some(value) => cfg.min_confidence = value,
        None => {
            if let Ok(raw) = std::env::var(env_key) {
                let parsed = raw
                    .parse::<f64>()
                    .map_err(|e| ResolveError::EnvParse(format!("{env_key}={raw}: {e}")))?;
                cfg.min_confidence = parsed;
            }
        }
    }
    TestApi
        .scan_config_validate(&cfg)
        .map_err(ResolveError::Validate)?;
    Ok(cfg)
}

/// Resolve `max_decode_depth` across all four layers with the same gate. Second
/// representative knob (a `usize`, distinct type from `min_confidence`).
fn resolve_max_decode_depth(
    cli: Option<usize>,
    env_key: &str,
    toml_text: Option<&str>,
) -> Result<ScanConfig, ResolveError> {
    let mut cfg = match toml_text {
        Some(text) => toml::from_str::<ScanConfig>(text)
            .unwrap_or_else(|e| panic!("TOML layer must be valid ScanConfig, got: {e}")),
        None => ScanConfig::default(),
    };
    match cli {
        Some(value) => cfg.max_decode_depth = value,
        None => {
            if let Ok(raw) = std::env::var(env_key) {
                let parsed = raw
                    .parse::<usize>()
                    .map_err(|e| ResolveError::EnvParse(format!("{env_key}={raw}: {e}")))?;
                cfg.max_decode_depth = parsed;
            }
        }
    }
    TestApi
        .scan_config_validate(&cfg)
        .map_err(ResolveError::Validate)?;
    Ok(cfg)
}

#[test]
fn default_layer_resolves_shipped_min_confidence() {
    // No CLI, no env, no TOML: the floor is the shipped default 0.40.
    let key = "KEYHOG_TEST_MINCONF_DEFAULT_LAYER";
    std::env::remove_var(key);
    let cfg = resolve_min_confidence(None, key, None).expect("default layer resolves");
    assert!((cfg.min_confidence - 0.40).abs() < F64_EPS, "expected 0.40");
}

#[test]
fn toml_layer_beats_default() {
    // TOML present, no env, no CLI: 0.65 from TOML overrides the 0.40 default.
    let key = "KEYHOG_TEST_MINCONF_TOML_BEATS_DEFAULT";
    std::env::remove_var(key);
    let cfg = resolve_min_confidence(None, key, Some(TOML_LAYER)).expect("toml layer resolves");
    assert!((cfg.min_confidence - 0.65).abs() < F64_EPS, "expected 0.65");
    // Sanity: the default really is a different value, so 0.65 proves the read.
    assert!((ScanConfig::default().min_confidence - 0.40).abs() < F64_EPS);
}

#[test]
fn env_layer_beats_toml() {
    // Env 0.70 sits above the TOML's 0.65.
    let key = "KEYHOG_TEST_MINCONF_ENV_BEATS_TOML";
    std::env::set_var(key, "0.70");
    let cfg = resolve_min_confidence(None, key, Some(TOML_LAYER)).expect("env layer resolves");
    std::env::remove_var(key);
    assert!(
        (cfg.min_confidence - 0.70).abs() < F64_EPS,
        "expected env 0.70"
    );
}

#[test]
fn env_layer_beats_default_when_no_toml() {
    // Env 0.33 sits above the shipped 0.40 default even with no TOML present.
    let key = "KEYHOG_TEST_MINCONF_ENV_BEATS_DEFAULT";
    std::env::set_var(key, "0.33");
    let cfg = resolve_min_confidence(None, key, None).expect("env-over-default resolves");
    std::env::remove_var(key);
    assert!(
        (cfg.min_confidence - 0.33).abs() < F64_EPS,
        "expected env 0.33"
    );
}

#[test]
fn cli_layer_beats_env() {
    // CLI 0.90 wins over a set env 0.70 and over the TOML 0.65.
    let key = "KEYHOG_TEST_MINCONF_CLI_BEATS_ENV";
    std::env::set_var(key, "0.70");
    let cfg =
        resolve_min_confidence(Some(0.90), key, Some(TOML_LAYER)).expect("cli layer resolves");
    std::env::remove_var(key);
    assert!(
        (cfg.min_confidence - 0.90).abs() < F64_EPS,
        "expected CLI 0.90"
    );
}

#[test]
fn cli_short_circuits_even_a_malformed_env() {
    // The `is_none()` gate means a CLI override is applied WITHOUT consulting
    // env, so an unparseable env value cannot break a CLI-specified run.
    let key = "KEYHOG_TEST_MINCONF_CLI_SHORTCIRCUIT";
    std::env::set_var(key, "not-a-float");
    let cfg =
        resolve_min_confidence(Some(0.55), key, Some(TOML_LAYER)).expect("cli short-circuits env");
    std::env::remove_var(key);
    assert!(
        (cfg.min_confidence - 0.55).abs() < F64_EPS,
        "expected CLI 0.55"
    );
}

#[test]
fn full_precedence_chain_all_four_layers_distinct() {
    // Every layer carries a DIFFERENT value; assert the resolved value at each
    // rung is exactly the highest active layer.
    let key = "KEYHOG_TEST_MINCONF_FULL_CHAIN";

    // Rung 1: default only -> 0.40
    std::env::remove_var(key);
    let d = resolve_min_confidence(None, key, None).expect("default");
    assert!((d.min_confidence - 0.40).abs() < F64_EPS, "default rung");

    // Rung 2: + TOML -> 0.65
    let t = resolve_min_confidence(None, key, Some(TOML_LAYER)).expect("toml");
    assert!((t.min_confidence - 0.65).abs() < F64_EPS, "toml rung");

    // Rung 3: + env -> 0.70
    std::env::set_var(key, "0.70");
    let e = resolve_min_confidence(None, key, Some(TOML_LAYER)).expect("env");
    assert!((e.min_confidence - 0.70).abs() < F64_EPS, "env rung");

    // Rung 4: + CLI -> 0.90
    let c = resolve_min_confidence(Some(0.90), key, Some(TOML_LAYER)).expect("cli");
    std::env::remove_var(key);
    assert!((c.min_confidence - 0.90).abs() < F64_EPS, "cli rung");
}

#[test]
fn out_of_range_env_value_rejected_exact_error() {
    // Env supplies 1.5 (above the closed unit interval). It parses fine as an
    // f64 but the resolved config is rejected by core validate() with the exact
    // ConfigError Display string.
    let key = "KEYHOG_TEST_MINCONF_ENV_TOO_HIGH";
    std::env::set_var(key, "1.5");
    let err = resolve_min_confidence(None, key, None).expect_err("1.5 must be rejected");
    std::env::remove_var(key);
    assert_eq!(
        err,
        ResolveError::Validate("min_confidence must be between 0.0 and 1.0, found 1.5".to_string())
    );
}

#[test]
fn negative_env_value_rejected_exact_error() {
    // Negative twin: -0.25 is below the interval; exact message carries the
    // negative value.
    let key = "KEYHOG_TEST_MINCONF_ENV_NEGATIVE";
    std::env::set_var(key, "-0.25");
    let err = resolve_min_confidence(None, key, Some(TOML_LAYER)).expect_err("-0.25 rejected");
    std::env::remove_var(key);
    assert_eq!(
        err,
        ResolveError::Validate(
            "min_confidence must be between 0.0 and 1.0, found -0.25".to_string()
        )
    );
}

#[test]
fn malformed_env_value_fails_closed_no_silent_fallback() {
    // A non-numeric env value must surface as a parse error (Law 10: no silent
    // fallback to the TOML/default value). The error carries the offending
    // key=value so the operator can find the typo.
    let key = "KEYHOG_TEST_MINCONF_ENV_MALFORMED";
    std::env::set_var(key, "high");
    let err = resolve_min_confidence(None, key, Some(TOML_LAYER)).expect_err("malformed rejected");
    std::env::remove_var(key);
    match err {
        ResolveError::EnvParse(msg) => {
            let prefix = format!("{key}=high: ");
            assert!(
                msg.starts_with(prefix.as_str()),
                "env parse error must name the offending key=value, got: {msg}"
            );
        }
        ResolveError::Validate(v) => panic!("expected EnvParse, got Validate({v})"),
    }
}

#[test]
fn env_value_at_closed_interval_boundaries_accepted() {
    // The interval is inclusive: env values of exactly 0.0 and 1.0 both resolve
    // and pass validation.
    let key = "KEYHOG_TEST_MINCONF_ENV_BOUNDARIES";
    std::env::set_var(key, "0.0");
    let lo = resolve_min_confidence(None, key, None).expect("0.0 is valid");
    assert!((lo.min_confidence - 0.0).abs() < F64_EPS, "lower bound 0.0");
    std::env::set_var(key, "1.0");
    let hi = resolve_min_confidence(None, key, None).expect("1.0 is valid");
    std::env::remove_var(key);
    assert!((hi.min_confidence - 1.0).abs() < F64_EPS, "upper bound 1.0");
}

#[test]
fn env_does_not_backdoor_toml_or_default_parse() {
    // Ambient env must NOT silently mutate a pure TOML parse or the shipped
    // default: core config resolution has no hidden env backdoor. Setting a
    // KEYHOG_-shaped env var that this resolver does NOT consult leaves both the
    // TOML value (0.65) and the default (0.40) untouched.
    std::env::set_var("KEYHOG_MIN_CONFIDENCE", "0.01");
    let parsed = toml::from_str::<ScanConfig>(TOML_LAYER).expect("toml parses");
    assert!(
        (parsed.min_confidence - 0.65).abs() < F64_EPS,
        "ambient env must not leak into TOML parse"
    );
    assert!(
        (ScanConfig::default().min_confidence - 0.40).abs() < F64_EPS,
        "ambient env must not leak into Default"
    );
    std::env::remove_var("KEYHOG_MIN_CONFIDENCE");
}

#[test]
fn unknown_toml_key_fails_closed_exact_error() {
    // deny_unknown_fields: an operator typo in the TOML layer must fail loudly
    // rather than be silently ignored (which would resolve to a wrong layer).
    let owned = format!("{TOML_LAYER}\nbogus_precedence_key = 1\n");
    let err = toml::from_str::<ScanConfig>(&owned)
        .expect_err("unknown TOML key must fail closed")
        .to_string();
    assert!(
        err.contains("unknown field `bogus_precedence_key`"),
        "expected 'unknown field `bogus_precedence_key`' in error, got: {err}"
    );
}

#[test]
fn max_decode_depth_env_over_toml_and_cli_over_env() {
    // Second knob (usize). default 10, TOML 7, env 5, CLI 3.
    let key = "KEYHOG_TEST_DEPTH_CHAIN";

    // default rung
    std::env::remove_var(key);
    let d = resolve_max_decode_depth(None, key, None).expect("default depth");
    assert_eq!(d.max_decode_depth, 10);
    // Its floor equals the accepted ceiling constant.
    assert_eq!(d.max_decode_depth, max_decode_depth_limit());

    // TOML rung
    let t = resolve_max_decode_depth(None, key, Some(TOML_LAYER)).expect("toml depth");
    assert_eq!(t.max_decode_depth, 7);

    // env rung
    std::env::set_var(key, "5");
    let e = resolve_max_decode_depth(None, key, Some(TOML_LAYER)).expect("env depth");
    assert_eq!(e.max_decode_depth, 5);

    // CLI rung
    let c = resolve_max_decode_depth(Some(3), key, Some(TOML_LAYER)).expect("cli depth");
    std::env::remove_var(key);
    assert_eq!(c.max_decode_depth, 3);
}

#[test]
fn out_of_range_env_depth_rejected_exact_error() {
    // Env supplies 11, one past the ceiling of 10: parses as usize, then the
    // resolved config is rejected by validate() with the exact message.
    let key = "KEYHOG_TEST_DEPTH_TOO_HIGH";
    std::env::set_var(key, "11");
    let err = resolve_max_decode_depth(None, key, None).expect_err("depth 11 rejected");
    std::env::remove_var(key);
    assert_eq!(
        err,
        ResolveError::Validate("max_decode_depth exceeds limit of 10, found 11".to_string())
    );
    // Boundary twin: exactly the limit (10) from env is accepted.
    let key2 = "KEYHOG_TEST_DEPTH_AT_LIMIT";
    std::env::set_var(key2, "10");
    let ok = resolve_max_decode_depth(None, key2, None).expect("depth 10 is valid");
    std::env::remove_var(key2);
    assert_eq!(ok.max_decode_depth, 10);
}
