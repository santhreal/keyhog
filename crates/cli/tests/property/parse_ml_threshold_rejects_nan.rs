//! Property: parse_ml_threshold rejects NaN.

use keyhog::value_parsers::parse_ml_threshold;

#[test]
fn parse_ml_threshold_rejects_nan() {
    assert!(parse_ml_threshold("NaN").is_err());
    assert!(parse_ml_threshold("-NaN").is_err());
}
