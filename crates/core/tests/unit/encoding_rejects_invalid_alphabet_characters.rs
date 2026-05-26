//! Invalid alphabet characters must be rejected with a descriptive error.

use keyhog_core::encoding::decode_standard_base64;

#[test]
fn encoding_rejects_invalid_alphabet_characters() {
    let err = decode_standard_base64("SGVsbG8!")
        .expect_err("bang is outside base64 alphabet");
    assert!(
        err.contains("invalid base64 char"),
        "expected alphabet error, got: {err}"
    );
}
