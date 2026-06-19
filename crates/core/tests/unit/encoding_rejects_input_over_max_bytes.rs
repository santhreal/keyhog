//! Inputs exceeding MAX_STANDARD_BASE64_INPUT_BYTES must be rejected.

use keyhog_core::decode_standard_base64;

#[test]
fn encoding_rejects_input_over_max_bytes() {
    let cap = keyhog_core::testing::CoreTestApi::max_standard_base64_input_bytes(
        &keyhog_core::testing::TestApi,
    );
    let oversized = "A".repeat(cap + 1);
    let err = decode_standard_base64(&oversized).expect_err("oversized input");
    assert!(
        err.contains("exceeds"),
        "expected size cap error, got: {err}"
    );
}
