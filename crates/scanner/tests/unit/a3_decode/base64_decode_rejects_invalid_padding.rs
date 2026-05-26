//! Invalid padding placement rejects decode.

use keyhog_scanner::decode::base64_decode;

#[test]
fn padding_in_middle_rejected() {
    assert!(base64_decode("YWI=YWQ=").is_err());
}
