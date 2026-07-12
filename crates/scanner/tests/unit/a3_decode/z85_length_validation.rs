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
    // Z85 decodes each 5-character group into exactly 4 bytes. Assert the DECODED
    // bytes, not merely that decoding returned Ok. "HelloWorld" is the canonical
    // Z85 test vector from the ZMQ RFC (https://rfc.zeromq.org/spec/32): it is the
    // Z85 encoding of these 8 bytes, so any correct decoder must reproduce them.
    assert_eq!(
        z85_decode("HelloWorld"),
        Ok(vec![0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B]),
        "canonical Z85 vector `HelloWorld` must decode to its 8 spec bytes"
    );
    // The all-zero group: five Z85 '0' chars (alphabet value 0) encode the 32-bit
    // value 0, so a length-5 input decodes to exactly four zero bytes.
    assert_eq!(
        z85_decode("00000"),
        Ok(vec![0u8, 0, 0, 0]),
        "length-5 all-zero Z85 must decode to exactly four zero bytes"
    );
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
