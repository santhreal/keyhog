//! Property: parse_byte_size rejects bare numbers without unit.

use keyhog::value_parsers::parse_byte_size;
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_byte_size_rejects_bare_number(n in 1u64..=999_999u64) {
        let s = n.to_string();
        prop_assert!(parse_byte_size(&s).is_err());
    }
}
