use keyhog::value_parsers::{
    parse_byte_size, parse_decode_depth, parse_min_confidence, parse_ml_threshold,
    parse_verify_rate,
};

#[test]
fn parse_min_confidence_accepts_valid_fraction() {
    assert_eq!(parse_min_confidence("0.75").unwrap(), 0.75);
}

#[test]
fn parse_min_confidence_rejects_out_of_range() {
    assert!(parse_min_confidence("1.5").is_err());
}

#[test]
fn parse_verify_rate_rejects_non_positive() {
    assert!(parse_verify_rate("0").is_err());
}

#[test]
fn parse_ml_threshold_rejects_nan() {
    assert!(parse_ml_threshold("NaN").is_err());
}

#[test]
fn parse_decode_depth_accepts_positive_integer() {
    assert_eq!(parse_decode_depth("3").unwrap(), 3);
}

#[test]
fn parse_byte_size_parses_suffixes() {
    assert_eq!(parse_byte_size("1M").unwrap(), 1024 * 1024);
}

#[test]
fn verify_rate_accepts_typical_values() {
    assert_eq!(parse_verify_rate("5").unwrap(), 5.0);
    assert_eq!(parse_verify_rate("0.5").unwrap(), 0.5);
    assert_eq!(parse_verify_rate("100").unwrap(), 100.0);
    assert_eq!(parse_verify_rate("9999.9").unwrap(), 9999.9);
}

#[test]
fn verify_rate_rejects_garbage() {
    assert!(parse_verify_rate("abc").is_err());
    assert!(parse_verify_rate("").is_err());
    assert!(parse_verify_rate("--").is_err());
}

#[test]
fn verify_rate_rejects_non_positive_extended() {
    assert!(parse_verify_rate("0").is_err());
    assert!(parse_verify_rate("0.0").is_err());
    assert!(parse_verify_rate("-1").is_err());
    assert!(parse_verify_rate("-0.5").is_err());
}

#[test]
fn verify_rate_rejects_non_finite() {
    assert!(parse_verify_rate("nan").is_err());
    assert!(parse_verify_rate("NaN").is_err());
    assert!(parse_verify_rate("inf").is_err());
    assert!(parse_verify_rate("Infinity").is_err());
    assert!(parse_verify_rate("-inf").is_err());
}

#[test]
fn verify_rate_rejects_above_sanity_cap() {
    assert!(parse_verify_rate("10001").is_err());
    assert!(parse_verify_rate("1e6").is_err());
    assert!(parse_verify_rate("1e300").is_err());
}

#[test]
fn ml_threshold_accepts_in_range() {
    assert_eq!(parse_ml_threshold("0").unwrap(), 0.0);
    assert_eq!(parse_ml_threshold("0.5").unwrap(), 0.5);
    assert_eq!(parse_ml_threshold("1").unwrap(), 1.0);
}

#[test]
fn ml_threshold_rejects_out_of_range() {
    assert!(parse_ml_threshold("-0.001").is_err());
    assert!(parse_ml_threshold("1.001").is_err());
    assert!(parse_ml_threshold("2").is_err());
    assert!(parse_ml_threshold("-1").is_err());
}

#[test]
fn ml_threshold_rejects_non_finite() {
    assert!(parse_ml_threshold("nan").is_err());
    assert!(parse_ml_threshold("inf").is_err());
    assert!(parse_ml_threshold("-inf").is_err());
}

#[test]
fn ml_threshold_rejects_garbage() {
    assert!(parse_ml_threshold("").is_err());
    assert!(parse_ml_threshold("half").is_err());
}
