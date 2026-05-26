//! Oracle: RFC 4648 padded base64 for "Hello" decodes to known bytes.

use keyhog_core::encoding::decode_standard_base64;

#[test]
fn encoding_decodes_standard_padded_base64() {
    assert_eq!(
        decode_standard_base64("SGVsbG8=").expect("valid base64"),
        b"Hello".as_slice()
    );
}
