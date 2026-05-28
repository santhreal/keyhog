//! Property: parse_decode_depth accepts 1..=10.

use keyhog::value_parsers::parse_decode_depth;
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_decode_depth_valid_range(d in 1usize..=10usize) {
        let s = d.to_string();
        prop_assert_eq!(parse_decode_depth(&s).expect("valid depth"), d);
    }
}
