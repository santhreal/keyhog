//! Underscore separators in hex literals are stripped before decode.

use keyhog_scanner::decode::hex_decode;

#[test]
fn underscored_hex_decodes_same_as_plain() {
    let plain = hex_decode("736b2d70726f6a").unwrap();
    let underscored = hex_decode("736b_2d70_726f6a").unwrap();
    assert_eq!(plain, underscored);
}
