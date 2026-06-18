//! Property: parse_verify_rate rejects non-positive rates.

use keyhog::testing::{CliTestApi as _, API};
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_verify_rate_rejects_nonpositive(r in -1000.0f64..=0.0) {
        let s = format!("{r}");
        prop_assert!(API.parse_verify_rate(&s).is_err());
    }
}
