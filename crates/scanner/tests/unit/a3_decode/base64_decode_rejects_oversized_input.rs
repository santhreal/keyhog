//! Oversized base64 input hits MAX_BASE64_INPUT_LEN guard.

use keyhog_scanner::decode::base64_decode;

#[test]
fn oversized_base64_input_rejected() {
    let huge = "A".repeat(17 * 1024 * 1024);
    assert!(base64_decode(&huge).is_err());
}
