//! Z85 "00000" encodes four null bytes.

use keyhog_scanner::decode::z85_decode;

#[test]
fn z85_zero_block_decodes_to_four_nulls() {
    assert_eq!(z85_decode("00000").unwrap(), vec![0, 0, 0, 0]);
}
