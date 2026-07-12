//! Adversarial totality + roundtrip proptest for
//! `suppression::decode::try_decode_b64_to_utf8` — the base64 decode-and-recheck
//! peek the suppression decision tree uses to look inside base64-wrapped
//! fixtures. `suppression_decode_b64_peek` pins deterministic cases; this sweeps
//! thousands of inputs and asserts the four contracts:
//!
//!   1. TOTALITY: never panics for ANY `&str`. It is a decode path fed
//!      attacker-controlled candidate text — a crafted input must not crash the
//!      scanner ([[decode-structured-hotpath-dos-audit]]). The DoS ceiling itself
//!      is owned by `decode::base64_decode`; here we only prove no panic escapes.
//!   2. LENGTH FLOOR: any input shorter than 8 BYTES returns `None` (the
//!      suppression-specific floor at decode.rs:22), regardless of content.
//!   3. ROUNDTRIP SOUNDNESS (Law 6, not shape): the standard base64 of a valid
//!      UTF-8 string, once it clears the floor, decodes back to EXACTLY that
//!      string — proving the peek actually decodes, not merely "returns something".
//!   4. NON-UTF-8 ⟹ None: base64 of bytes that are not valid UTF-8 (any run
//!      containing `0xFF`) returns `None` — the recall-preserving path that keeps
//!      a binary blob from being mis-read as a plaintext fixture marker.

use keyhog_scanner::suppression::decode::try_decode_b64_to_utf8;
use proptest::prelude::*;

/// Standard RFC-4648 base64 with `=` padding. Local + self-contained so this test
/// file carries no external base64 dependency and no literal credential shape.
/// Verified compatible with `decode::base64_decode` by the deterministic
/// `suppression_decode_b64_peek` suite (its `decodes_standard` case is green).
fn b64_std(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHA[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHA[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Arbitrary candidate text: no panic, and the byte-length floor holds.
    #[test]
    fn try_decode_b64_to_utf8_is_total_and_respects_the_floor(
        s in ".{0,64}",
    ) {
        let result = try_decode_b64_to_utf8(&s);
        // 2. LENGTH FLOOR — sub-8-byte inputs never decode.
        if s.len() < 8 {
            prop_assert!(
                result.is_none(),
                "input {s:?} is {} bytes (< 8) but decoded to {result:?}",
                s.len()
            );
        }
        // 1. TOTALITY is proven by reaching here without a panic.
    }

    /// Valid UTF-8 → standard base64 → decode roundtrips to the original once the
    /// encoding clears the 8-byte floor.
    #[test]
    fn standard_base64_of_utf8_roundtrips_above_the_floor(
        plaintext in ".{4,48}",
    ) {
        let encoded = b64_std(plaintext.as_bytes());
        prop_assume!(encoded.len() >= 8);
        prop_assert_eq!(
            try_decode_b64_to_utf8(&encoded),
            Some(plaintext)
        );
    }

    /// Base64 of a byte run containing `0xFF` (never valid UTF-8) decodes to bytes
    /// but fails the UTF-8 gate, so the peek returns `None`.
    #[test]
    fn base64_of_non_utf8_bytes_returns_none(
        mut bytes in prop::collection::vec(any::<u8>(), 4..24usize),
    ) {
        bytes.push(0xFF); // guarantees the decoded payload is not valid UTF-8
        let encoded = b64_std(&bytes);
        prop_assume!(encoded.len() >= 8);
        prop_assert_eq!(
            try_decode_b64_to_utf8(&encoded),
            None,
            "non-UTF-8 payload must not decode to a string"
        );
    }
}
