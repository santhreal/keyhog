//! Property: parse_ml_threshold rejects NaN.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn parse_ml_threshold_rejects_nan() {
    assert!(API.parse_ml_threshold("NaN").is_err());
    assert!(API.parse_ml_threshold("-NaN").is_err());
}
