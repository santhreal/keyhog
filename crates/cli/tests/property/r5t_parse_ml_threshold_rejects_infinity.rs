//! R5-T property: parse_ml_threshold rejects infinity.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn r5t_parse_ml_threshold_rejects_infinity() {
    assert!(API.parse_ml_threshold("inf").is_err());
}
