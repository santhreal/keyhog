//! Regression: `decode_standard_base64` must NOT silently truncate at an
//! embedded `=`.
//!
//! The previous implementation used `take_while(|c| c != b'=')`, which stopped
//! at the FIRST `=` and silently dropped everything after it. That made
//! `"QUJ=Q0Q="` decode to just `"AB"` (the bytes after the embedded `=` were
//! thrown away with no error) — a silent-accept that corrupts a credential
//! round-trip through `Credential`'s serde. These tests pin the corrected,
//! fail-closed behavior with EXACT byte oracles, and pin that the legitimate
//! trailing-padding forms still succeed unchanged.

use keyhog_core::decode_standard_base64;

#[test]
fn data_after_embedded_padding_is_rejected_not_truncated() {
    // "QUI" + "=" + "Q0Q=" : an `=` in the middle followed by more data.
    // Old behavior: silently decoded only "QUI"-worth and dropped the tail.
    let err = decode_standard_base64("QUI=Q0Q=")
        .expect_err("embedded '=' followed by data must be rejected");
    assert_eq!(
        err, "invalid base64: data after padding '=' (padding may only appear at the end)",
        "embedded-padding rejection message regressed"
    );
}

#[test]
fn leading_padding_is_rejected() {
    let err = decode_standard_base64("=QUJD").expect_err("leading '=' must be rejected");
    assert_eq!(
        err,
        "invalid base64: data after padding '=' (padding may only appear at the end)"
    );
}

#[test]
fn padding_in_the_middle_of_a_quad_is_rejected() {
    // "AB=C" : a single `=` with data after it inside one quad.
    let err = decode_standard_base64("AB=C").expect_err("mid-quad '=' before data must reject");
    assert_eq!(
        err,
        "invalid base64: data after padding '=' (padding may only appear at the end)"
    );
}

#[test]
fn rem1_padding_is_rejected_as_unalignable() {
    // 5 data chars then padding: idx % 4 == 1, which no valid base64 encoding
    // produces (1 leftover char carries < 6 bits of a byte).
    let err = decode_standard_base64("QUJDQ=").expect_err("rem-1 + padding is unalignable");
    assert!(
        err.starts_with("invalid base64: 1 padding char(s) do not align"),
        "unexpected message for unalignable padding: {err}"
    );
}

#[test]
fn three_padding_chars_after_a_full_quad_is_rejected() {
    let err = decode_standard_base64("QUJD===").expect_err("3 trailing '=' is malformed");
    assert!(
        err.starts_with("invalid base64: 3 padding char(s) do not align"),
        "unexpected message for over-long padding: {err}"
    );
}

#[test]
fn legitimate_trailing_padding_still_decodes_exact_bytes() {
    // One-byte payload, two pads.
    assert_eq!(decode_standard_base64("QQ==").expect("QQ=="), b"A");
    // Two-byte payload, one pad.
    assert_eq!(decode_standard_base64("QUI=").expect("QUI="), b"AB");
    // Three-byte payload, no pad.
    assert_eq!(decode_standard_base64("QUJD").expect("QUJD"), b"ABC");
    // Trailing padding after a whole quad (lenient, must still succeed).
    assert_eq!(decode_standard_base64("QUJD==").expect("QUJD=="), b"ABC");
    // Unpadded "Hello".
    assert_eq!(
        decode_standard_base64("SGVsbG8").expect("SGVsbG8"),
        b"Hello"
    );
    // Padded "Hello".
    assert_eq!(
        decode_standard_base64("SGVsbG8=").expect("SGVsbG8="),
        b"Hello"
    );
    // Empty stays empty.
    assert_eq!(decode_standard_base64("").expect("empty"), b"");
}

#[test]
fn credential_b64_roundtrip_is_not_silently_corrupted() {
    // The motivating case: a credential whose base64 happens to contain an
    // interior `=` must error on decode rather than round-trip to a TRUNCATED,
    // wrong value. "QUI=Q0Q=" is exactly such a string.
    assert!(
        decode_standard_base64("QUI=Q0Q=").is_err(),
        "interior '=' must fail closed, never decode to a truncated credential"
    );
}
