//! Property: parse_byte_size rejects bare numbers without unit across every entry door (Row 112).

use keyhog::testing::ByteSizeParserDoor;
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_byte_size_rejects_bare_number(n in 1u64..=999_999u64) {
        let s = n.to_string();
        for door in ByteSizeParserDoor::ALL {
            prop_assert!(door.parse(&s).is_err(), "door {:?} must reject bare number '{}'", door, s);
        }
    }
}
