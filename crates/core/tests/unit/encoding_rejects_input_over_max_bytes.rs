//! Inputs exceeding MAX_STANDARD_BASE64_INPUT_BYTES must be rejected.

use keyhog_core::encoding::{decode_standard_base64, MAX_STANDARD_BASE64_INPUT_BYTES};

#[test]
fn encoding_rejects_input_over_max_bytes() {
    let oversized = "A".repeat(MAX_STANDARD_BASE64_INPUT_BYTES + 1);
    let err = decode_standard_base64(&oversized).expect_err("oversized input");
    assert!(err.contains("exceeds"), "expected size cap error, got: {err}");
}
