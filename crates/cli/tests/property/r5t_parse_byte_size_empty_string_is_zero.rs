//! R5-T property: parse_byte_size empty string is zero.

use keyhog::value_parsers::parse_byte_size;

#[test]
fn r5t_parse_byte_size_empty_string_is_zero() {
    assert_eq!(parse_byte_size("").expect("empty"), 0);
    assert_eq!(parse_byte_size("   ").expect("whitespace"), 0);
}
