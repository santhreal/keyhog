//! Property: parse_byte_size round-trips integer KB/MB/GB.

use keyhog::testing::{CliTestApi as _, API};
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_byte_size_valid_suffix_roundtrip(n in 1u64..=1024u64) {
        for (suffix, mult) in [("K", 1024usize), ("M", 1024 * 1024), ("G", 1024 * 1024 * 1024)] {
            let s = format!("{n}{suffix}");
            let parsed = API.parse_byte_size(&s).expect("valid size");
            prop_assert_eq!(parsed, (n as usize).saturating_mul(mult));
        }
    }
}
