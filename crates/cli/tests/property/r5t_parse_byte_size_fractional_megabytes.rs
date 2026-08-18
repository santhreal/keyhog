//! R5-T property: parse_byte_size accepts fractional megabytes across all doors (Row 112).

use keyhog::testing::ByteSizeParserDoor;

#[test]
fn r5t_parse_byte_size_fractional_megabytes() {
    let expected = (1.5 * 1024.0 * 1024.0) as usize;
    for door in ByteSizeParserDoor::ALL {
        let parsed = door.parse("1.5M").expect("1.5M");
        assert_eq!(parsed, expected, "door {:?}", door);
    }
}
