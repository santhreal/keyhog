//! R5-T property: parse_verify_rate rejects infinity.

use keyhog::value_parsers::parse_verify_rate;

#[test]
fn r5t_parse_verify_rate_rejects_infinity() {
    assert!(parse_verify_rate("inf").is_err());
    assert!(parse_verify_rate("Infinity").is_err());
}
