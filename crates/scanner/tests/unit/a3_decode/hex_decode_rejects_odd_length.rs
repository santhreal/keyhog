//! Odd-length hex input is rejected.

use keyhog_scanner::decode::hex_decode;

#[test]
fn odd_length_hex_rejected() {
    assert!(hex_decode("abc").is_err());
}
