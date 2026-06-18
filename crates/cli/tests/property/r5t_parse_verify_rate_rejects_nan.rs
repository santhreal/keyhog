//! R5-T property: parse_verify_rate rejects NaN.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn r5t_parse_verify_rate_rejects_nan() {
    assert!(API.parse_verify_rate("NaN").is_err());
}
