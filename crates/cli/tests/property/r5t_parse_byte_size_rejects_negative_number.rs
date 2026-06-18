//! R5-T property: parse_byte_size rejects negative values.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn r5t_parse_byte_size_rejects_negative_number() {
    assert!(API.parse_byte_size("-1K").is_err());
}
