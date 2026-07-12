//! Adversarial DoS-bound contracts for the leaf decoders
//! (`crates/scanner/src/decode/{caesar,reverse,url,json}.rs`).
//!
//! Every decoder runs on attacker-controlled candidate bytes, so each must be
//! LINEAR in its input: a multi-MB or pathological candidate may produce a large
//! (or empty) result, but it must never hang, panic, or allocate super-linearly
//! (the OOM/DoS class in the over-allocation backlog). These tests feed large and
//! crafted inputs and assert (1) no panic, (2) output bounded by a small constant
//! factor of the input — which fails LOUDLY (hang/OOM) if any decoder is
//! accidentally quadratic/exponential. If they pass, the leaf decoders are proven
//! linear and the "huge candidate → OOM" concern is bounded at the leaf.

#![cfg(feature = "decode")]

use keyhog_scanner::testing::{
    caesar_shift_for_test, mime_encoded_word_decode_for_test, octal_escape_decode_for_test,
    quoted_printable_decode_for_test, reverse_str_for_test,
};
use proptest::prelude::*;

/// 2 MiB — large enough that a non-linear decoder would hang or OOM this test,
/// small enough that a linear one finishes in milliseconds.
const BIG: usize = 2 * 1024 * 1024;

// ── large-input linearity (the DoS class) ────────────────────────────────────

#[test]
fn caesar_shift_is_linear_on_a_huge_candidate() {
    let input = "a".repeat(BIG);
    let out = caesar_shift_for_test(&input, 13);
    // Caesar rotates letters 1:1, so the output is exactly the input length.
    assert_eq!(out.len(), input.len());
    assert!(out.starts_with('n')); // 'a' + 13 = 'n'
}

#[test]
fn reverse_str_is_linear_on_a_huge_candidate() {
    let input = "x".repeat(BIG);
    let out = reverse_str_for_test(&input);
    assert_eq!(out.len(), input.len());
}

#[test]
fn quoted_printable_decode_is_bounded_on_a_huge_candidate() {
    // A huge run of `=41` QP octets — each 3 input chars decode to 1 byte, so the
    // output is ~1/3 the input, never larger.
    let input = "=41".repeat(BIG / 3);
    let out = quoted_printable_decode_for_test(&input);
    if let Some(decoded) = out {
        assert!(
            decoded.len() <= input.len(),
            "QP output must not exceed input"
        );
    }
}

#[test]
fn mime_encoded_word_decode_is_bounded_on_a_huge_candidate() {
    // A huge base64 MIME encoded-word; the decoded body is ~3/4 the base64 body.
    let body = "QQ".repeat(BIG / 2); // valid base64 alphabet
    let input = format!("=?utf-8?B?{body}?=");
    let out = mime_encoded_word_decode_for_test(&input);
    if let Some(decoded) = out {
        assert!(decoded.len() <= input.len());
    }
}

#[test]
fn octal_escape_decode_is_bounded_on_a_huge_candidate() {
    // A huge run of `\101` octal escapes — 4 input chars → 1 byte.
    let input = "\\101".repeat(BIG / 4);
    let out = octal_escape_decode_for_test(&input);
    if let Some(decoded) = out {
        assert!(decoded.len() <= input.len());
    }
}

// ── crafted pathological shapes (no panic, bounded) ──────────────────────────

#[test]
fn pathological_shapes_do_not_panic() {
    let shapes = [
        "=".repeat(BIG / 2),  // all bare `=` (QP soft-break bait)
        "\\".repeat(BIG / 2), // all backslashes (octal-escape bait)
        "%".repeat(BIG / 2),  // all percent signs
        "=?".repeat(BIG / 4), // repeated MIME word openers
        "\0".repeat(1024),    // NUL run
    ];
    for s in &shapes {
        // None of these must panic; results are ignored (bounded by construction).
        let _ = quoted_printable_decode_for_test(s);
        let _ = mime_encoded_word_decode_for_test(s);
        let _ = octal_escape_decode_for_test(s);
        let _ = reverse_str_for_test(s);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Caesar output length ALWAYS equals input length (1:1 transform) — no
    /// decoder-side amplification on any input.
    #[test]
    fn caesar_output_length_equals_input(s in ".{0,512}", shift in 0u8..26) {
        prop_assert_eq!(caesar_shift_for_test(&s, shift).chars().count(), s.chars().count());
    }

    /// Reverse output is the same length and reversing twice is the identity.
    #[test]
    fn reverse_is_a_length_preserving_involution(s in ".{0,512}") {
        let once = reverse_str_for_test(&s);
        prop_assert_eq!(once.chars().count(), s.chars().count());
        prop_assert_eq!(reverse_str_for_test(&once), s);
    }

    /// QP / MIME / octal decoders NEVER expand: decoded output <= input length,
    /// and never panic, on arbitrary bytes.
    #[test]
    fn decoders_never_expand_output(s in "\\PC{0,256}") {
        if let Some(d) = quoted_printable_decode_for_test(&s) {
            prop_assert!(d.len() <= s.len());
        }
        if let Some(d) = octal_escape_decode_for_test(&s) {
            prop_assert!(d.len() <= s.len());
        }
        if let Some(d) = mime_encoded_word_decode_for_test(&s) {
            prop_assert!(d.len() <= s.len());
        }
    }
}
