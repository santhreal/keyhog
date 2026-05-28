//! R5-T property: parse_verify_rate rejects NaN.

use keyhog::value_parsers::parse_verify_rate;

#[test]
fn r5t_parse_verify_rate_rejects_nan() {
    assert!(parse_verify_rate("NaN").is_err());
}
