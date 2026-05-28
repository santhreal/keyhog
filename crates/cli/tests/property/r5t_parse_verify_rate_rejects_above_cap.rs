//! R5-T property: parse_verify_rate rejects above 10000 rps.

use keyhog::value_parsers::parse_verify_rate;

#[test]
fn r5t_parse_verify_rate_rejects_above_cap() {
    assert!(parse_verify_rate("10001").is_err());
}
