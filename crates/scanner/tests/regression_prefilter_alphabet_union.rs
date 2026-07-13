//! Regression coverage for the MULTI-DETECTOR alphabet-union screen of the
//! "Layer 0" prefilter (`crates/scanner/src/alphabet_filter.rs`), exercised
//! through the public `keyhog_scanner::testing` facade.
//!
//! Distinct from `regression_ac_literal_prefilter` and the single-target
//! `regression_alphabet_filter_prefilter`: this file pins the UNION property.
//! `AlphabetScreen::new` folds the target byte set of ALL supplied detector
//! literals into ONE 256-bit presence mask, so the screen admits a chunk that
//! carries any one detector's distinctive byte and rejects a chunk disjoint
//! from every detector. The recall-load-bearing invariants are:
//!   * union WIDENS admission, a chunk a narrower detector set rejects becomes
//!     admitted once the owning detector is unioned in (monotone, never shrinks),
//!   * a chunk disjoint from ALL detectors is rejected,
//!   * target-set ORDER does not change the verdict (union is commutative),
//!   * scalar == AVX2 backend parity on the union (via the facade helper).
//!
//! Ground-truth target set (three synthetic detector-like literals with
//! deliberately disjoint distinctive bytes):
//!   det A "AKIA"   -> letters A K I, case-folded to {A a K k I i}
//!   det B "ghp_"   -> letters g h p folded to {G g H h P p}; '_' (0x5F) EXACT
//!                     (non-letter, so its 0x20-flip 0x7F is NOT set)
//!   det C "123456" -> digits {1 2 3 4 5 6} EXACT (non-letters, no fold)
//! Full union alphabet U = {A a K k I i, G g H h P p, _, 1 2 3 4 5 6}.
//! Bytes deliberately OUTSIDE U (used as filler / reject corpora):
//!   'z' 0x7A, 'q' 0x71, 'w' 0x77, 'v' 0x76, 'm' 0x6D, digits 7 8 9 0,
//!   'B' 'L' 'O', and DEL 0x7F.

use keyhog_scanner::testing::{
    assert_alphabet_prefilter_backend_parity, AlphabetMask, AlphabetScreen,
};

// ---- fixtures ---------------------------------------------------------------

/// det A only.
fn det_a() -> Vec<String> {
    vec!["AKIA".to_string()]
}

/// det A + det B.
fn det_ab() -> Vec<String> {
    vec!["AKIA".to_string(), "ghp_".to_string()]
}

/// det A + det B + det C (the full three-detector union).
fn det_abc() -> Vec<String> {
    vec!["AKIA".to_string(), "ghp_".to_string(), "123456".to_string()]
}

// ---- union admission: one byte from ANY detector admits ---------------------

#[test]
fn union_admits_a_chunk_carrying_any_single_detector_byte() {
    let screen = AlphabetScreen::new(&det_abc());
    // A distinctive byte from det A (uppercase 'K' 0x4B, verbatim literal byte).
    assert_eq!(screen.screen(b"zzzKzzz"), true);
    // A distinctive byte from det B (underscore 0x5F, non-letter exact).
    assert_eq!(screen.screen(b"zqwvm_zqwvm"), true);
    // A distinctive byte from det C (digit '5' 0x35).
    assert_eq!(screen.screen(b"qwv5qwv"), true);
}

#[test]
fn union_rejects_chunk_disjoint_from_all_detectors() {
    let screen = AlphabetScreen::new(&det_abc());
    // z q w v m (none in U).
    assert_eq!(screen.screen(b"zqwvm"), false);
    // Digits 7 8 9 0 are outside U (only 1..6 are targeted) plus '?'.
    assert_eq!(screen.screen(b"7890?7890"), false);
    // Uppercase near-misses B L O (not in U).
    assert_eq!(screen.screen(b"BLOB"), false);
}

// ---- union WIDENS admission (the core union property) -----------------------

#[test]
fn adding_detector_b_widens_admission_for_underscore_chunk() {
    // "____" carries only 0x5F, which belongs to det B ("ghp_") alone.
    let underscores = b"____";
    // det A alone ({A a K k I i}) does NOT contain 0x5F -> reject.
    assert_eq!(AlphabetScreen::new(&det_a()).screen(underscores), false);
    // Unioning det B in admits the same chunk -> union widened the alphabet.
    assert_eq!(AlphabetScreen::new(&det_ab()).screen(underscores), true);
    // Full union still admits it (monotone, never shrinks).
    assert_eq!(AlphabetScreen::new(&det_abc()).screen(underscores), true);
}

#[test]
fn adding_detector_c_widens_admission_for_digit_chunk() {
    // "42" carries digits 4 and 2, owned by det C ("123456") alone.
    let digits = b"42";
    // Neither det A nor det A+B covers plain digits -> both reject.
    assert_eq!(AlphabetScreen::new(&det_a()).screen(digits), false);
    assert_eq!(AlphabetScreen::new(&det_ab()).screen(digits), false);
    // Adding det C admits it.
    assert_eq!(AlphabetScreen::new(&det_abc()).screen(digits), true);
}

#[test]
fn union_is_monotone_admission_never_lost_when_widening() {
    // Any chunk admitted by the narrow det-A screen MUST stay admitted by the
    // wider det-A+B+C screen (union only adds bits, never removes).
    let narrow = AlphabetScreen::new(&det_a());
    let wide = AlphabetScreen::new(&det_abc());
    for chunk in [&b"A"[..], &b"contains i"[..], &b"KEY"[..]] {
        assert_eq!(narrow.screen(chunk), true);
        assert_eq!(wide.screen(chunk), true);
    }
}

// ---- order independence (union is commutative) ------------------------------

#[test]
fn union_verdict_is_order_independent() {
    let forward = AlphabetScreen::new(&det_abc());
    let reversed =
        AlphabetScreen::new(&["123456".to_string(), "ghp_".to_string(), "AKIA".to_string()]);
    // Admit case (det-B underscore) (identical verdict regardless of order).
    assert_eq!(forward.screen(b"__"), true);
    assert_eq!(reversed.screen(b"__"), true);
    // Reject case (disjoint) (identical verdict regardless of order).
    assert_eq!(forward.screen(b"zqwvm"), false);
    assert_eq!(reversed.screen(b"zqwvm"), false);
    // Admit case (det-C digit) (identical verdict regardless of order).
    assert_eq!(forward.screen(b"6"), true);
    assert_eq!(reversed.screen(b"6"), true);
}

// ---- case folding interacts with the union ----------------------------------

#[test]
fn union_case_folds_letters_from_each_uppercase_detector() {
    // Literals are uppercase/exact; the screen folds ASCII LETTERS only, so a
    // lowercase twin of any detector letter is admitted under the union.
    let screen = AlphabetScreen::new(&det_abc());
    // 'a' is the fold-twin of det A's 'A'.
    assert_eq!(screen.screen(b"value=a"), true);
    // 'p' is the fold-twin of det B's 'P' (from "ghp_", already lowercase; its
    // uppercase twin 'P' is therefore also admitted).
    assert_eq!(screen.screen(b"contains P here"), true);
}

#[test]
fn union_does_not_case_fold_non_letter_detector_bytes() {
    // '_' (det B) and digits (det C) are non-letters: only their exact byte is
    // set, never a 0x20-flip. DEL 0x7F (== '_' ^ 0x20) must stay rejected, and
    // '1' ^ 0x20 == 0x11 must stay rejected, proving folding is letter-only
    // even across a multi-detector union.
    let screen = AlphabetScreen::new(&det_abc());
    assert_eq!(screen.screen(&[0x7Fu8]), false); // DEL, would-be flip of '_'
    assert_eq!(screen.screen(&[0x11u8]), false); // would-be flip of '1'
                                                 // Sanity: the exact non-letter bytes ARE admitted.
    assert_eq!(screen.screen(&[0x5Fu8]), true); // '_'
    assert_eq!(screen.screen(&[b'1']), true); // 0x31
}

// ---- boundary: AVX2 block / remainder paths on the union --------------------

#[test]
fn union_admits_detector_c_byte_in_avx2_remainder_tail() {
    // 40-byte chunk: AVX2 consumes one 32-byte block, then a scalar 8-byte
    // remainder. Place det C's only distinctive byte at index 35 (remainder).
    let screen = AlphabetScreen::new(&det_abc());
    let mut data = vec![b'z'; 40]; // 'z' (0x7A) is outside U
    data[35] = b'3'; // det C digit in the tail
    assert_eq!(screen.screen(&data), true);
    // Identical length, no U-byte anywhere -> reject.
    assert_eq!(screen.screen(&vec![b'z'; 40]), false);
}

#[test]
fn union_admits_detector_b_byte_at_exact_32_byte_block_end() {
    // Exactly one AVX2 block (no remainder); det B underscore at final index.
    let screen = AlphabetScreen::new(&det_abc());
    let mut hit = vec![b'z'; 32];
    assert_eq!(hit.len(), 32);
    hit[31] = b'_';
    assert_eq!(screen.screen(&hit), true);
    // Same block, all filler -> reject.
    assert_eq!(screen.screen(&vec![b'z'; 32]), false);
}

// ---- empty union / empty chunk edge cases -----------------------------------

#[test]
fn empty_detector_set_rejects_every_chunk() {
    // A union of NO detectors is the empty mask: nothing is ever admitted.
    let screen = AlphabetScreen::new(&[]);
    assert_eq!(screen.screen(b"AKIA ghp_ 123456"), false);
    assert_eq!(screen.screen(&[0x00u8]), false);
    assert_eq!(screen.screen(b""), false);
}

#[test]
fn empty_chunk_rejected_under_populated_union() {
    let screen = AlphabetScreen::new(&det_abc());
    assert_eq!(screen.screen(b""), false);
    assert_eq!(screen.screen(&[]), false);
}

// ---- AlphabetMask union primitive backs the screen --------------------------

#[test]
fn mask_union_of_three_detectors_matches_membership() {
    // Build the union alphabet the same way the screen does its byte set, but
    // via the exact-byte AlphabetMask::union primitive (no case folding here).
    let mut u = AlphabetMask::from_text("AKIA");
    u.union(&AlphabetMask::from_text("ghp_"));
    u.union(&AlphabetMask::from_text("123456"));
    // One representative exact byte from each detector is present.
    assert_eq!(u.intersects(&AlphabetMask::from_bytes(b"K")), true); // det A
    assert_eq!(u.intersects(&AlphabetMask::from_bytes(&[0x5F])), true); // det B '_'
    assert_eq!(u.intersects(&AlphabetMask::from_bytes(b"4")), true); // det C
                                                                     // A byte in NONE of the three literals is absent (mask is exact, no fold:
                                                                     // lowercase 'a' differs from 'A').
    assert_eq!(u.intersects(&AlphabetMask::from_bytes(b"a")), false);
    assert_eq!(u.intersects(&AlphabetMask::from_bytes(b"z")), false);
    assert_eq!(u.intersects(&AlphabetMask::from_bytes(&[0x7F])), false);
    // Union is idempotent: unioning a detector already folded in changes nothing.
    let before = u;
    u.union(&AlphabetMask::from_text("ghp_"));
    assert_eq!(u, before);
}

// ---- scalar == AVX2 backend parity on the union -----------------------------

#[test]
fn union_scalar_avx2_backend_parity_admit_and_reject() {
    let targets = det_abc();
    // Admit: chunk carries det B's underscore.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&targets, b"log_line with underscore"),
        true
    );
    // Admit: chunk carries det C digit only ('z' filler is outside U).
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&targets, b"zzz6zzz"),
        true
    );
    // Reject: disjoint from every detector.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&targets, b"zqwvm zqwvm zqwvm"),
        false
    );
    // Empty chunk -> false, backends agree.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&targets, b""),
        false
    );
}
