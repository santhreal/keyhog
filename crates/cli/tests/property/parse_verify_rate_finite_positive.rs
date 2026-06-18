//! Property: parse_verify_rate accepts finite (0, 10_000].

use keyhog::testing::{CliTestApi as _, API};
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_verify_rate_finite_positive(r in 0.001f64..=10_000.0) {
        let s = format!("{r}");
        let parsed = API.parse_verify_rate(&s).expect("valid rate must parse");
        prop_assert!((parsed - r).abs() < f64::EPSILON);
    }
}
