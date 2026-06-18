//! Property: parse_ml_threshold accepts finite [0,1].

use keyhog::testing::{CliTestApi as _, API};
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_ml_threshold_finite_unit_interval(t in 0.0f64..=1.0) {
        let s = format!("{t}");
        let parsed = API.parse_ml_threshold(&s).expect("valid threshold must parse");
        prop_assert!((parsed - t).abs() < f64::EPSILON);
    }
}
