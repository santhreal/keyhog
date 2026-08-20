//! Property: parse_byte_size rejects unknown suffixes.

use keyhog::testing::{CliTestApi as _, API};
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_byte_size_rejects_unknown_suffix(n in 1u64..=100u64, sfx in "[XYZQWERT]{2,4}") {
        let s = format!("{n}{sfx}");
        prop_assert!(API.parse_byte_size(&s).is_err());
    }
}
