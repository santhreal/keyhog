//! Z85 input length must be a multiple of five.

use keyhog_scanner::decode::z85_decode;

#[test]
fn z85_non_multiple_of_five_rejected() {
    assert!(z85_decode("0000").is_err());
}
