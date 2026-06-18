//! `parse_min_confidence` accepts only finite values in [0, 1].

use keyhog::testing::{CliTestApi as _, API};
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_min_confidence_finite_unit_interval(f in 0.0f64..=1.0) {
        let s = format!("{f}");
        let parsed = API.parse_min_confidence(&s).expect("valid fraction must parse");
        prop_assert!((parsed - f).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_min_confidence_rejects_out_of_range(f in prop_oneof![-100.0..=-0.001, 1.001..=100.0]) {
        let s = format!("{f}");
        prop_assert!(API.parse_min_confidence(&s).is_err());
    }
}
