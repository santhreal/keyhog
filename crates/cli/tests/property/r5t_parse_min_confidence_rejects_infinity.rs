//! R5-T property: parse_min_confidence rejects infinity.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn r5t_parse_min_confidence_rejects_infinity() {
    assert!(API.parse_min_confidence("inf").is_err());
}
