//! `ScanConfig` carries two fields the scanner never reads: `max_file_size`,
//! whose effective cap belongs to the source walker, and `dedup`, whose
//! effective scope belongs to report grouping. They existed as documented
//! no-ops, so a library caller who set either one got exactly the scan they
//! would have got by leaving it alone, with nothing to tell them.
//!
//! Validation now refuses a non-default value and names the surface that owns
//! the behaviour. These tests pin both halves of that: setting the field fails
//! with a message a caller can act on, and leaving it alone still validates.

use keyhog_core::{ConfigError, DedupScope, ScanConfig, DEFAULT_MAX_FILE_SIZE_BYTES};

/// The default configuration must keep validating. A no-effect check that
/// rejected the default would break every caller of `ScanConfig::default()`.
#[test]
fn the_default_configuration_still_validates() {
    ScanConfig::default()
        .validate()
        .expect("the default configuration must validate");
}

/// Setting a size cap on `ScanConfig` looks like it bounds the scan and does
/// not. The error names `max_file_size` and points at the source walker.
#[test]
fn a_non_default_max_file_size_is_refused_and_names_its_owner() {
    let mut config = ScanConfig::default();
    config.max_file_size = 4096;
    let error = config
        .validate()
        .expect_err("a size cap the scanner ignores must not validate");
    assert!(
        matches!(
            error,
            ConfigError::NoEffectField {
                field: "max_file_size",
                ..
            }
        ),
        "expected a no-effect field error for max_file_size, got {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("max_file_size") && message.contains("FilesystemSource"),
        "the message must name both the ignored field and its real owner: {message}"
    );
}

/// Every non-default dedup scope is refused, not just one. `None` and `File`
/// are the two values a caller would reach for, and both are dropped.
#[test]
fn every_non_default_dedup_scope_is_refused() {
    for scope in [DedupScope::None, DedupScope::File] {
        let mut config = ScanConfig::default();
        config.dedup = scope;
        assert!(
            matches!(
                config.validate(),
                Err(ConfigError::NoEffectField { field: "dedup", .. })
            ),
            "dedup scope {scope:?} is not honoured and must not validate"
        );
    }
}

/// The exact boundary: the default size cap validates and one byte off does
/// not. An off-by-one in the check would let the common case through while
/// still rejecting an equivalent explicit value.
#[test]
fn the_size_cap_boundary_is_exact() {
    let mut at_default = ScanConfig::default();
    at_default.max_file_size = DEFAULT_MAX_FILE_SIZE_BYTES;
    at_default
        .validate()
        .expect("the documented default must validate");

    for off_by_one in [
        DEFAULT_MAX_FILE_SIZE_BYTES - 1,
        DEFAULT_MAX_FILE_SIZE_BYTES + 1,
    ] {
        let mut config = ScanConfig::default();
        config.max_file_size = off_by_one;
        assert!(
            config.validate().is_err(),
            "{off_by_one} differs from the default and must be refused"
        );
    }
}

/// A no-effect value must be refused even when every other field is valid, so
/// the check cannot be masked by an earlier range error.
#[test]
fn a_no_effect_field_is_refused_alongside_otherwise_valid_values() {
    let mut config = ScanConfig::default();
    config.min_confidence = 0.9;
    config.ml_weight = 0.25;
    config.entropy_threshold = 4.5;
    config.dedup = DedupScope::File;
    assert!(
        matches!(
            config.validate(),
            Err(ConfigError::NoEffectField { field: "dedup", .. })
        ),
        "a valid range must not hide a field the scanner cannot honour"
    );
}

/// A range error still wins over a no-effect error, because an out-of-range
/// value is the more severe defect and its message is the more actionable one.
#[test]
fn a_range_error_is_reported_before_a_no_effect_field() {
    let mut config = ScanConfig::default();
    config.min_confidence = 5.0;
    config.dedup = DedupScope::None;
    assert!(
        matches!(config.validate(), Err(ConfigError::InvalidConfidence(_))),
        "an out-of-range confidence must be reported ahead of a no-effect field"
    );
}

/// The validated TOML loader shares the check, so a config file that sets a
/// no-effect key is refused exactly like a hand-built config. The fixture is a
/// full serialized default with one key changed, because `ScanConfig` requires
/// every field and a fragment would fail on parse instead.
#[test]
fn the_toml_loader_refuses_a_no_effect_key() {
    let mut config = ScanConfig::default();
    config.dedup = DedupScope::File;
    let raw = toml::to_string(&config).expect("a default config serializes");
    let error =
        ScanConfig::from_toml_str(&raw).expect_err("a config that sets a no-effect key must fail");
    assert!(
        matches!(error, ConfigError::NoEffectField { field: "dedup", .. }),
        "expected a no-effect field error, got {error:?}"
    );

    // The same document with the default scope loads, so the refusal is about
    // the value and not about the serialized shape.
    let baseline = toml::to_string(&ScanConfig::default()).expect("a default config serializes");
    ScanConfig::from_toml_str(&baseline)
        .expect("a serialized default must round-trip and validate");
}
