//! Mixed standard and URL-safe alphabet chars are rejected.

use keyhog_scanner::decode::base64_decode;

#[test]
fn mixed_standard_and_urlsafe_alphabet_rejected() {
    assert!(base64_decode("c2stcHJvai1hYmMxMjM+/").is_err());
}
