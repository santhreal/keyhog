//! Gap test: the Caesar/ROT-N letter rotation produces exact rotated strings.
//!
//! `caesar_shift` rotates each ASCII letter forward by `shift` positions modulo
//! the alphabet length (`ALPHABET_LEN = 26`), wrapping `Z`→`A`, and leaves
//! digits and punctuation byte-for-byte unchanged. The decoder's whole
//! soundness argument (the rotated-prefix Aho-Corasick gate, the
//! shift-invariant precondition) rests on this being an exact position-wise
//! bijection, so pin the rotation, the wraparound, the digit/punct identity,
//! the ROT13 self-inverse, and the `BLJB`+25 → `AKIA` example the module's
//! soundness proof cites.
//!
//! The Caesar decoder lives behind the `decode` feature.
#![cfg(feature = "decode")]

use keyhog_scanner::testing::caesar_shift_for_test as shift;

#[test]
fn forward_shift_by_one() {
    assert_eq!(shift("ABC", 1), "BCD");
}

#[test]
fn wraps_past_z_back_to_a() {
    // X/Y/Z + 3 wrap to A/B/C.
    assert_eq!(shift("XYZ", 3), "ABC");
}

#[test]
fn rot13_leaves_digits_and_punctuation_identical() {
    // Only letters rotate; ", ", "! ", and "123" pass through unchanged.
    assert_eq!(shift("Hello, World! 123", 13), "Uryyb, Jbeyq! 123");
}

#[test]
fn rot13_is_its_own_inverse() {
    assert_eq!(shift(&shift("hello", 13), 13), "hello");
}

#[test]
fn shift_25_rotates_bljb_into_akia() {
    // The bijection example from the rotated-prefix soundness proof:
    // a candidate `BLJB` shifted +25 yields the `AKIA` known prefix.
    assert_eq!(shift("BLJB", 25), "AKIA");
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin representative rotations; these SWEEP the algebraic
// contract the decoder's rotated-prefix soundness proof relies on. `caesar_shift`
// must be an exact position-wise rotation that composes additively mod 26 — if it
// were not a clean bijection, the AC rotated-prefix gate could admit or drop
// candidates unsoundly. No proptest covered it before.
//
// SHIFT BOUND: shifts are kept within the non-overflowing range. `caesar_shift`
// computes `(ch - base + shift) % 26` as u8, so a letter at offset 25 (`z`/`Z`)
// with `shift >= 231` overflows the add BEFORE the mod (25 + 231 = 256) — a
// latent debug-panic on the public facade (filed in BACKLOG; production callers
// only ever pass 1..=25, so this is not production-reachable). By mod-26, the
// 0..26 range covers every semantically distinct rotation regardless.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// GROUP LAW: rotations compose additively mod 26 —
    /// `shift(shift(s, a), b) == shift(s, (a + b) % 26)`. This single invariant
    /// subsumes ROT13 self-inverse (a=b=13 ⇒ 0 ⇒ identity), the forward and
    /// wrap-past-Z cases, and every round-trip. Over arbitrary Unicode `s`
    /// (letters rotate, everything else is carried through both sides identically).
    #[test]
    fn caesar_shift_composition_is_additive_mod_26(
        s in "(?s).{0,40}",
        a in 0u8..26,
        b in 0u8..26,
    ) {
        let lhs = shift(&shift(&s, a), b);
        let rhs = shift(&s, (a + b) % 26);
        prop_assert_eq!(lhs, rhs);
    }

    /// The shift is taken MODULO 26: `shift(s, k) == shift(s, k % 26)` across the
    /// full non-overflowing shift range (0..=230), explicitly exercising the
    /// `% ALPHABET_LEN` wrap for `k >= 26` (e.g. shift 30 behaves as shift 4).
    #[test]
    fn caesar_shift_is_reduced_modulo_alphabet_len(
        s in "(?s).{0,40}",
        k in 0u8..=230,
    ) {
        prop_assert_eq!(shift(&s, k), shift(&s, k % 26));
    }

    /// Position-wise shape: the output has the SAME byte length as the input
    /// (ASCII letters stay 1-byte letters; every other char is byte-identical),
    /// and each non-ASCII-alphabetic char is unchanged with letter CASE preserved.
    /// Locks that ONLY `[A-Za-z]` rotate and nothing else moves.
    #[test]
    fn caesar_shift_preserves_length_case_and_non_letters(
        s in "(?s).{0,40}",
        k in 0u8..26,
    ) {
        let out = shift(&s, k);
        prop_assert_eq!(out.len(), s.len());
        for (inc, outc) in s.chars().zip(out.chars()) {
            if inc.is_ascii_alphabetic() {
                prop_assert!(outc.is_ascii_alphabetic(), "letter rotated to non-letter");
                prop_assert_eq!(inc.is_ascii_uppercase(), outc.is_ascii_uppercase());
            } else {
                prop_assert_eq!(inc, outc);
            }
        }
    }
}
