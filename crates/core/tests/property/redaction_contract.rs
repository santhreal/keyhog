//! Property tier for `keyhog_core::redact`: the display-redaction leak guard.
//! Fixed-vector coverage exists (`unit/redact_*`, `regression_redaction_mask`,
//! `regression_redaction_policy`); this file pins the SECURITY contract over
//! arbitrary inputs (proptest, 10k cases). `redact` is the last line before a
//! credential reaches a terminal / log / report, so its guarantees must hold
//! for EVERY input, not a handful of examples:
//!
//!   * a short secret (≤ 8 chars/graphemes) is FULLY masked to `****`: zero
//!     bytes revealed;
//!   * a long secret reveals at most a tiny bounded edge (≤ 4 chars each side),
//!     so the redacted form is length-bounded (≤ 11 chars) regardless of how
//!     long the secret is, and its MIDDLE never appears;
//!   * arbitrary UTF-8 never panics (char-boundary safe, the impl has an ASCII
//!     byte-slice fast path AND a `chars()` path, and the boundary between them
//!     is exactly where a slicing bug would live).
//!
//! Goes through the STABLE PUBLIC `redact` fn only.

use keyhog_core::redact;
use proptest::prelude::*;

/// The documented edge-length contract, mirroring the crate-private
/// `redaction_edge_len` (`lib.rs`): reveal `char_count / 8` chars per side,
/// clamped to `[1, 4]`. Kept here as the contract-of-record, a DELIBERATE
/// change to the redaction shape must update this line and the tests that use
/// it, which is the point (it can't drift silently).
fn documented_edge_len(char_count: usize) -> usize {
    (char_count / 8).clamp(1, 4)
}

const FULL_MASK: &str = "****";

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Any secret of 8 or fewer chars is fully masked, the redacted form is
    /// EXACTLY `****`, revealing nothing (not even the length beyond "≤ 8").
    #[test]
    fn prop_short_secret_is_fully_masked(s in "\\PC{0,8}") {
        // "\\PC{0,8}" = up to 8 non-control chars → char_count ≤ 8.
        prop_assume!(s.chars().count() <= 8);
        prop_assert_eq!(redact(&s), FULL_MASK);
    }

    /// The redacted form is LENGTH-BOUNDED regardless of secret size: a secret
    /// of any length redacts to at most 11 chars (2·4 edge + 3 for "..."). This
    /// is the core leak bound, a 10 000-char key cannot leak more than a
    /// bounded sliver. Also ties the exact output length to the documented edge.
    #[test]
    fn prop_long_secret_output_is_bounded(s in "\\PC{9,400}") {
        let cc = s.chars().count();
        prop_assume!(cc > 8);
        let out = redact(&s);
        let out_cc = out.chars().count();
        prop_assert!(out_cc <= 11, "redacted output {out_cc} chars exceeds the 11-char ceiling");
        let edge = documented_edge_len(cc);
        prop_assert_eq!(out_cc, edge * 2 + 3);
    }

    /// The MIDDLE of a long secret NEVER appears in the redacted form. Build a
    /// secret whose middle is a sentinel flanked by `k ≥ 4` filler chars each
    /// side; since the revealed edge is ≤ 4 ≤ k, the sentinel is always elided.
    /// Formula-independent, the strongest statement of "the secret body is
    /// hidden".
    #[test]
    fn prop_secret_middle_never_leaks(k in 4usize..120) {
        let secret = format!("{}SENTINEL_MIDDLE{}", "a".repeat(k), "b".repeat(k));
        let out = redact(&secret);
        prop_assert!(
            !out.contains("SENTINEL"),
            "redacted form leaked the secret middle: {out}"
        );
        prop_assert!(!out.contains("MIDDLE"));
    }

    /// For ASCII secrets over 8 bytes, the output is EXACTLY the documented
    /// `prefix + "..." + suffix` reconstruction. Exercises the ASCII byte-slice
    /// fast path; robust even when the secret itself contains literal `.`.
    #[test]
    fn prop_ascii_long_exact_reconstruction(s in "[ -~]{9,300}") {
        prop_assume!(s.is_ascii());
        let len = s.len();
        prop_assume!(len > 8);
        let edge = documented_edge_len(len);
        let expected = format!("{}...{}", &s[..edge], &s[len - edge..]);
        prop_assert_eq!(redact(&s), expected);
    }

    /// Arbitrary UTF-8, including multi-byte graphemes, combining marks, and
    /// content straddling the ASCII/non-ASCII decision, never panics, and a
    /// long secret's redacted form still begins with the secret's first char
    /// (proving the non-ASCII `chars()` path slices on grapheme boundaries, not
    /// bytes).
    #[test]
    fn prop_arbitrary_utf8_no_panic_and_char_boundary_safe(s in any::<String>()) {
        let out = redact(&s); // must not panic on any UTF-8
        if s.chars().count() > 8 {
            let first = s.chars().next().unwrap();
            prop_assert!(
                out.starts_with(first),
                "redacted form did not begin with the secret's first char (byte-slice mojibake?)"
            );
            prop_assert!(out.contains("..."));
        }
    }

    /// `redact` is pure: the same input always yields the same output.
    #[test]
    fn prop_redact_is_deterministic(s in any::<String>()) {
        prop_assert_eq!(redact(&s), redact(&s));
    }
}

// ---------------------------------------------------------------------------
// Explicit boundary examples (the edge cases the proptest ranges bracket but
// don't guarantee hitting): the 8/9-char mask boundary, the edge-length clamp
// steps, empty input, and a non-ASCII short secret.
// ---------------------------------------------------------------------------

#[test]
fn redact_boundary_cases() {
    assert_eq!(redact(""), "****"); // empty → masked, never "" (which would leak "length 0")
    assert_eq!(redact("12345678"), "****"); // exactly 8 → masked
                                            // 9 chars, ASCII: edge = 9/8 = 1 → first + "..." + last.
    assert_eq!(redact("123456789"), "1...9");
    // 16 chars: edge = 2.
    assert_eq!(redact("abcdefghijklmnop"), "ab...op");
    // 32 chars: edge = 4 (the clamp ceiling).
    assert_eq!(redact("abcdefghijklmnopqrstuvwxyzABCDEF"), "abcd...CDEF");
    // 40 chars: edge = 40/8 = 5, clamped down to 4 (never grows past 4).
    assert_eq!(
        redact("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"),
        "abcd...KLMN"
    );
    // Non-ASCII short (4 graphemes) → masked via the char-count path, no panic.
    assert_eq!(redact("café"), "****");
    // Non-ASCII long: 9 graphemes, edge = 1 → first + "..." + last grapheme.
    let s = "café☕mañana"; // c a f é ☕ m a ñ a n a = 11 chars
    let out = redact(s);
    assert!(out.starts_with('c') && out.ends_with('a') && out.contains("..."));
}
