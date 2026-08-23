//! Property: parse_byte_size rejects unknown suffixes across every entry door (Row 112).

use keyhog::testing::ByteSizeParserDoor;
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_byte_size_rejects_unknown_suffix(n in 1u64..=100u64, sfx in "[XYZQWERT]{2,4}") {
        let s = format!("{n}{sfx}");
        for door in ByteSizeParserDoor::ALL {
            prop_assert!(door.parse(&s).is_err(), "door {:?} must reject unknown suffix '{}'", door, s);
        }
    }
}
