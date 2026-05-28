//! Property: parse_verify_rate rejects non-positive rates.

use keyhog::value_parsers::parse_verify_rate;
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_verify_rate_rejects_nonpositive(r in -1000.0f64..=0.0) {
        let s = format!("{r}");
        prop_assert!(parse_verify_rate(&s).is_err());
    }
}
