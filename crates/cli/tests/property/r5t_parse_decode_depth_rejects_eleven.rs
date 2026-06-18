//! R5-T property: parse_decode_depth rejects depth above the shared core limit.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn r5t_parse_decode_depth_rejects_eleven() {
    let invalid = keyhog_core::max_decode_depth_limit() + 1;
    assert!(API.parse_decode_depth(&invalid.to_string()).is_err());
}
