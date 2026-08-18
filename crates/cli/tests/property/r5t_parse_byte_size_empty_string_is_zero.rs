//! R5-T property: parse_byte_size empty string is zero across all doors (Row 112).

use keyhog::testing::ByteSizeParserDoor;

#[test]
fn r5t_parse_byte_size_empty_string_is_zero() {
    for door in ByteSizeParserDoor::ALL {
        assert_eq!(door.parse("").expect("empty"), 0, "door {:?}", door);
        assert_eq!(door.parse("   ").expect("whitespace"), 0, "door {:?}", door);
    }
}
