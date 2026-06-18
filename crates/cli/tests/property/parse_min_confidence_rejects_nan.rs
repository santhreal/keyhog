//! Property: parse_min_confidence rejects NaN/Inf.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn parse_min_confidence_rejects_nan() {
    for bad in ["NaN", "-NaN", "inf", "-inf", "Infinity"] {
        assert!(API.parse_min_confidence(bad).is_err(), "must reject {bad}");
    }
}
