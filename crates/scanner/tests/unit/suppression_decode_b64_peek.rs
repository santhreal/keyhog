//! Direct unit coverage for the suppression base64 decode-peek helper
//! (`suppression::decode::try_decode_b64_to_utf8`). It was previously exercised
//! only transitively through the end-to-end suppression truth table; these pin
//! its own contract: the suppression-specific `len < 8` floor, the two
//! recall-preserving `None` paths (undecodable / non-UTF-8), and the successful
//! standard + url-safe decode paths.
//!
//! Every base64 input is GENERATED at runtime from benign plaintext by a local
//! RFC-4648 encoder, so no base64 literal (which the repo's own dogfood
//! self-scan would inspect) ever appears in this source.

use keyhog_scanner::suppression::decode::try_decode_b64_to_utf8;

/// Minimal standard-alphabet (RFC 4648) base64 encoder with `=` padding, the
/// inverse of the standard variant `try_decode_b64_to_utf8` accepts. Kept local
/// so test inputs are produced from plaintext, never pasted as encoded blobs.
fn b64_std(input: &[u8]) -> String {
    const AL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(AL[((n >> 18) & 63) as usize] as char);
        out.push(AL[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            AL[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            AL[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// url-safe (RFC 4648 §5) variant: `+`→`-`, `/`→`_`. The helper doc promises it
/// decodes url-safe input too, so it must round-trip an encoding that uses the
/// substituted glyphs.
fn b64_url(input: &[u8]) -> String {
    b64_std(input).replace('+', "-").replace('/', "_")
}

#[test]
fn decodes_standard_base64_of_utf8_payload() {
    // 17-byte plaintext -> 24 base64 chars (>= the len-8 floor).
    let encoded = b64_std(b"placeholder-value");
    assert_eq!(
        try_decode_b64_to_utf8(&encoded).as_deref(),
        Some("placeholder-value"),
        "standard base64 of a UTF-8 payload must decode back to the plaintext"
    );
}

#[test]
fn decodes_url_safe_base64_of_utf8_payload() {
    // "hello?" -> standard base64 "aGVsbG8/": the trailing '?' (0x3F) makes the
    // final 6-bit group 0b111111 = index 63 = '/', which the url-safe form
    // rewrites to '_'. So this input genuinely exercises the url-safe alphabet,
    // and 6 bytes -> 8 base64 chars clears the len-8 floor.
    let plaintext = "hello?";
    let encoded = b64_url(plaintext.as_bytes());
    assert!(
        encoded.contains('-') || encoded.contains('_'),
        "fixture must actually exercise the url-safe glyphs, got {encoded}"
    );
    assert_eq!(
        try_decode_b64_to_utf8(&encoded).as_deref(),
        Some(plaintext),
        "url-safe base64 of a UTF-8 payload must decode back to the plaintext"
    );
}

#[test]
fn below_length_floor_is_rejected_without_decoding() {
    // "ab" -> "YWI=" (4 chars) < 8: the suppression floor returns None BEFORE
    // consulting base64_decode, even though the input is perfectly valid base64.
    let encoded = b64_std(b"ab");
    assert!(
        encoded.len() < 8,
        "fixture must sit below the floor, got {} chars",
        encoded.len()
    );
    assert_eq!(
        try_decode_b64_to_utf8(&encoded),
        None,
        "inputs shorter than the len-8 floor must be rejected outright"
    );
}

#[test]
fn non_base64_input_returns_none() {
    // `#` is in neither the standard nor the url-safe alphabet; a >=8-char run of
    // it clears the floor but fails the decode -> recall-preserving None.
    let junk = "########"; // 8 chars, not a secret shape
    assert!(junk.len() >= 8);
    assert_eq!(
        try_decode_b64_to_utf8(junk),
        None,
        "undecodable base64 must return None (candidate stays unsuppressed)"
    );
}

#[test]
fn non_utf8_decoded_payload_returns_none() {
    // Six 0xFF bytes -> 8 base64 chars (clears the floor) but decode yields bytes
    // that are not valid UTF-8, so no plaintext fixture marker can be inspected.
    let encoded = b64_std(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(
        encoded.len(),
        8,
        "6 bytes must encode to exactly 8 base64 chars, got {}",
        encoded.len()
    );
    assert_eq!(
        try_decode_b64_to_utf8(&encoded),
        None,
        "a non-UTF-8 decoded payload must return None, not a lossy string"
    );
}
