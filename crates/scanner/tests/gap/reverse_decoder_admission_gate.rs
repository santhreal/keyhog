//! Gap test: the reverse decoder's string reversal and admission gate.
//!
//! `reverse_str` reverses by Unicode scalar (not byte), and `looks_reversible`
//! admits a candidate for reverse-decoding only when BOTH gates pass:
//!   1. a contiguous ASCII-alphanumeric run of at least `MIN_REVERSE_ALNUM_RUN`
//!      (12) scanned in the reversed direction, AND
//!   2. the candidate contains the reverse of a known provider prefix (so a
//!      plain monotonic alphabet, which reverses to nothing meaningful, is
//!      rejected).
//!
//! Pin the exact reversal, the 11-vs-12 run boundary, and the known-prefix
//! requirement (`AKIA` reversed is `AIKA`).
//!
//! The reverse decoder lives behind the `decode` feature.
#![cfg(feature = "decode")]

use keyhog_scanner::testing::looks_reversible_for_test as looks_reversible;
use keyhog_scanner::testing::reverse_str_for_test as reverse_str;

#[test]
fn reverses_ascii_exactly() {
    assert_eq!(reverse_str("ABCDEF"), "FEDCBA");
}

#[test]
fn reverses_by_unicode_scalar_not_byte() {
    // `é` is two UTF-8 bytes; a byte reversal would corrupt it. Char reversal
    // keeps it intact: "héllo" -> "olléh".
    assert_eq!(reverse_str("héllo"), "olléh");
}

#[test]
fn requires_a_twelve_long_alnum_run() {
    // Both strings contain `AIKA` (the reverse of the known `AKIA` prefix), so
    // only the alnum-run gate differs. 12 contiguous alnum chars admit; 11 do
    // not — pinning the exact MIN_REVERSE_ALNUM_RUN boundary.
    assert!(looks_reversible("AIKAABCDEFGH")); // 12-char run
    assert!(!looks_reversible("AIKAABCDEFG")); // 11-char run
}

#[test]
fn long_run_without_a_reversed_known_prefix_is_rejected() {
    // 26 contiguous alnum chars clear the run gate, but a monotonic A–Z string
    // contains no reversed provider prefix, so it is not admitted.
    assert!(!looks_reversible("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example each; these SWEEP them. `reverse_str` is a
// char-level reversal, so it is an INVOLUTION and equals `chars().rev()` — pinned
// over arbitrary Unicode. `looks_reversible` needs BOTH gates: a ≥12 contiguous
// ASCII-alnum run AND a reversed known provider prefix — swept so each gate is
// isolated (the run boundary with the `AIKA` prefix present; a long run of a
// repeated char with no reversed prefix). Traced against reverse_str +
// looks_reversible. No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// `reverse_str` is an INVOLUTION: reversing twice yields the original, for any
    /// Unicode (char-level, so combining sequences round-trip too).
    #[test]
    fn reverse_str_is_an_involution(s in "(?s).{0,40}") {
        let once = reverse_str(&s);
        prop_assert_eq!(reverse_str(&once), s);
    }

    /// `reverse_str` equals a char-wise reversal exactly.
    #[test]
    fn reverse_str_equals_char_reversal(s in "(?s).{0,40}") {
        let expected: String = s.chars().rev().collect();
        prop_assert_eq!(reverse_str(&s), expected);
    }

    /// A ≥12 contiguous alnum run that contains a reversed known prefix (`AIKA`)
    /// is admitted.
    #[test]
    fn twelve_alnum_run_with_reversed_prefix_admits(tail in "[A-Za-z0-9]{8,30}") {
        let candidate = format!("AIKA{tail}"); // run = 4 + (8..30) >= 12, contains AIKA
        prop_assert!(looks_reversible(&candidate));
    }

    /// A sub-12 alnum run is rejected even WITH the reversed prefix present — the
    /// run gate is independent.
    #[test]
    fn sub_twelve_run_is_rejected(tail in "[A-Za-z0-9]{0,7}") {
        let candidate = format!("AIKA{tail}"); // run = 4 + (0..7) <= 11 < 12
        prop_assert!(!looks_reversible(&candidate));
    }

    /// A long alnum run WITHOUT any reversed known prefix (a repeated single char)
    /// is rejected — the prefix gate is independent.
    #[test]
    fn long_run_without_reversed_prefix_is_rejected(n in 12usize..40) {
        let candidate = "1".repeat(n); // >= 12 run, no reversed provider prefix
        prop_assert!(!looks_reversible(&candidate));
    }
}
