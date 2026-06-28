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
