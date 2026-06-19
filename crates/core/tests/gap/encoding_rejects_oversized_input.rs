//! Encoding module must reject inputs above the documented byte cap.

use keyhog_core::decode_standard_base64;

/// Inputs longer than [`MAX_STANDARD_BASE64_INPUT_BYTES`] must fail with a cap oracle.
#[test]
fn encoding_rejects_oversized_input() {
    let cap = keyhog_core::testing::CoreTestApi::max_standard_base64_input_bytes(
        &keyhog_core::testing::TestApi,
    );
    let oversized = "A".repeat(cap + 1);

    let err = decode_standard_base64(&oversized).unwrap_err();

    assert_eq!(
        err,
        format!("base64 input exceeds {} bytes", cap),
        "oversized input must fail with the documented cap message, got: {err}"
    );
}
