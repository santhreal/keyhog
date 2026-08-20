//! Property: parse_byte_size round-trips integer KB/MB/GB across every entry door (Row 112).

use keyhog::testing::ByteSizeParserDoor;
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_byte_size_valid_suffix_roundtrip(n in 1u64..=1024u64) {
        for (suffix, mult) in [("K", 1024usize), ("M", 1024 * 1024), ("G", 1024 * 1024 * 1024)] {
            let s = format!("{n}{suffix}");
            let expected = (n as usize).saturating_mul(mult);
            for door in ByteSizeParserDoor::ALL {
                let parsed = door.parse(&s).expect("valid size");
                prop_assert_eq!(parsed, expected, "door {:?} parsed mismatch for '{}'", door, s);
            }
        }
    }
}
