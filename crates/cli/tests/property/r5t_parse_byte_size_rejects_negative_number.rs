//! R5-T property: parse_byte_size rejects negative values across all doors (Row 112).

use keyhog::testing::ByteSizeParserDoor;

#[test]
fn r5t_parse_byte_size_rejects_negative_number() {
    for door in ByteSizeParserDoor::ALL {
        assert!(door.parse("-1K").is_err(), "door {:?}", door);
    }
}
