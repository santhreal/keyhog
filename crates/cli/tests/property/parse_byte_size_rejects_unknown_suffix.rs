//! Property: parse_byte_size rejects unknown suffixes.

use keyhog::value_parsers::parse_byte_size;
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_byte_size_rejects_unknown_suffix(n in 1u64..=100u64, sfx in "[XYZQWERT]{2,4}") {
        let s = format!("{n}{sfx}");
        prop_assert!(parse_byte_size(&s).is_err());
    }
}
