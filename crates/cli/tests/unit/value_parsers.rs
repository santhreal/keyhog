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
