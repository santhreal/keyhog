//! Property: parse_min_confidence rejects NaN/Inf.

use keyhog::value_parsers::parse_min_confidence;

#[test]
fn parse_min_confidence_rejects_nan() {
    for bad in ["NaN", "-NaN", "inf", "-inf", "Infinity"] {
        assert!(parse_min_confidence(bad).is_err(), "must reject {bad}");
    }
}
