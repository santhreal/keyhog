//! Property: parse_decode_depth accepts the shared core decode-depth range.

use keyhog::testing::{CliTestApi as _, API};
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_decode_depth_valid_range(
        d in 1usize..=keyhog_core::max_decode_depth_limit()
    ) {
        let s = d.to_string();
        prop_assert_eq!(API.parse_decode_depth(&s).expect("valid depth"), d);
    }
}
