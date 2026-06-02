//! Z85 decoder must validate length BEFORE processing to avoid panic on chunks_exact.

use keyhog_scanner::decode::z85_decode;

#[test]
fn z85_rejects_non_multiple_of_5_length() {
    // Z85 MUST be a multiple of 5 bytes. Any other length is invalid.
    let inputs = vec!["1", "12", "123", "1234", "123456", "1234567"];
    for input in inputs {
        let result = z85_decode(input);
        assert!(
            result.is_err(),
            "z85_decode must reject length {}: {}",
            input.len(),
            input
        );
    }
}

#[test]
fn z85_accepts_multiple_of_5_length() {
    // Valid lengths: 5, 10, 15, 20, ...
    // Use valid Z85 characters to avoid decode errors from invalid alphabet.
    let valid = "00000"; // 5 bytes of Z85 zero
    assert!(z85_decode(valid).is_ok(), "z85 length 5 must succeed");

    let valid_10 = "0000000000"; // 10 bytes
    assert!(z85_decode(valid_10).is_ok(), "z85 length 10 must succeed");
}

#[test]
fn z85_length_zero_is_valid() {
    // Empty string is technically a multiple of 5.
    let result = z85_decode("");
    assert_eq!(
        result,
        Ok(vec![]),
        "empty Z85 input must decode to empty vec"
    );
}

#[test]
fn z85_oversized_input_rejected() {
    // MAX_Z85_INPUT_LEN guards against OOM.
    // Default is 16 MB. This test verifies the guard exists without allocating 16 MB.
    // A known-large input that exceeds the limit by a safe margin for testing.
    let oversized = "0".repeat(16 * 1024 * 1024 + 5);
    let result = z85_decode(&oversized);
    assert!(
        result.is_err(),
        "z85_decode must reject input exceeding MAX_Z85_INPUT_LEN"
    );
}
