//! URL-safe base64 without padding decodes correctly.

use keyhog_scanner::decode::base64_decode;

#[test]
fn urlsafe_nopad_base64_decodes() {
    let decoded = base64_decode("c2stcHJvai1hYmMxMjM").expect("valid urlsafe nopad");
    assert_eq!(String::from_utf8(decoded).unwrap(), "sk-proj-abc123");
}
