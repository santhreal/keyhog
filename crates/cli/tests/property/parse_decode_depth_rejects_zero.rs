//! Property: parse_decode_depth rejects 0.

use keyhog::value_parsers::parse_decode_depth;

#[test]
fn parse_decode_depth_rejects_zero() {
    assert!(parse_decode_depth("0").is_err());
}
