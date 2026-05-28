//! R5-T property: parse_min_confidence rejects infinity.

use keyhog::value_parsers::parse_min_confidence;

#[test]
fn r5t_parse_min_confidence_rejects_infinity() {
    assert!(parse_min_confidence("inf").is_err());
}
