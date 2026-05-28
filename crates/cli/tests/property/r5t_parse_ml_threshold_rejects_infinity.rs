//! R5-T property: parse_ml_threshold rejects infinity.

use keyhog::value_parsers::parse_ml_threshold;

#[test]
fn r5t_parse_ml_threshold_rejects_infinity() {
    assert!(parse_ml_threshold("inf").is_err());
}
