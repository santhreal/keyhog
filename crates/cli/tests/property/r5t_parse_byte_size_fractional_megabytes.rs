//! R5-T property: parse_byte_size accepts fractional megabytes.

use keyhog::value_parsers::parse_byte_size;

#[test]
fn r5t_parse_byte_size_fractional_megabytes() {
    let parsed = parse_byte_size("1.5M").expect("1.5M");
    assert_eq!(parsed, (1.5 * 1024.0 * 1024.0) as usize);
}
