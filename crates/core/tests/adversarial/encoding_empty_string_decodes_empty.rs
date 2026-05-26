//! Adversarial: empty base64 input decodes to empty bytes (not an error).

use keyhog_core::encoding::decode_standard_base64;

#[test]
fn encoding_empty_string_decodes_to_empty_bytes() {
    assert_eq!(decode_standard_base64("").expect("empty ok"), b"".as_slice());
}
