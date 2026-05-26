//! LR1-A8 replacement gate: `decode/util.rs` / hex decoder bytes.

use keyhog_scanner::decode::hex_decode;

#[test]
fn hex_decode_deadbeef_yields_expected_bytes() {
    let bytes = hex_decode("deadbeef").expect("valid hex must decode");
    assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
}
