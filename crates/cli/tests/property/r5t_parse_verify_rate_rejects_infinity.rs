//! R5-T property: parse_verify_rate rejects infinity.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn r5t_parse_verify_rate_rejects_infinity() {
    assert!(API.parse_verify_rate("inf").is_err());
    assert!(API.parse_verify_rate("Infinity").is_err());
}
