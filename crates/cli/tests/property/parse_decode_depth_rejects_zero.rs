//! Property: parse_decode_depth rejects 0.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn parse_decode_depth_rejects_zero() {
    assert!(API.parse_decode_depth("0").is_err());
}
