//! Encoding module must reject inputs above the documented byte cap.

use keyhog_core::encoding::{decode_standard_base64, MAX_STANDARD_BASE64_INPUT_BYTES};

/// Inputs longer than [`MAX_STANDARD_BASE64_INPUT_BYTES`] must fail with a cap oracle.
#[test]
fn encoding_rejects_oversized_input() {
    let oversized = "A".repeat(MAX_STANDARD_BASE64_INPUT_BYTES + 1);

    let err = decode_standard_base64(&oversized).unwrap_err();

    assert_eq!(
        err,
        format!(
            "base64 input exceeds {} bytes",
            MAX_STANDARD_BASE64_INPUT_BYTES
        ),
        "oversized input must fail with the documented cap message, got: {err}"
    );
}
