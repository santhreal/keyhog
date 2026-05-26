//! Lowercase hex decodes to ASCII bytes.

use keyhog_scanner::decode::hex_decode;

#[test]
fn lowercase_hex_decodes_sk_prefix() {
    let decoded = hex_decode("736b2d70726f6a").expect("valid hex");
    assert_eq!(String::from_utf8(decoded).unwrap(), "sk-proj");
}
