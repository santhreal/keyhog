//! R5-T property: parse_decode_depth rejects depth 11.

use keyhog::value_parsers::parse_decode_depth;

#[test]
fn r5t_parse_decode_depth_rejects_eleven() {
    assert!(parse_decode_depth("11").is_err());
}
