//! Regression coverage for the "Layer 0" alphabet-bitmask prefilter
//! (`crates/scanner/src/alphabet_filter.rs`), exercised through the public
//! `keyhog_scanner::testing` facade.
//!
//! The prefilter's contract is exact and recall-load-bearing: `AlphabetScreen`
//! must ADMIT (return `true` for) any chunk containing at least one byte in the
//! union of the detector target alphabet, and REJECT (return `false` for) any
//! chunk containing none. A silent false-negative here drops a whole chunk from
//! deeper scanning, so every assertion below pins a concrete `bool` / count.
//!
//! Ground truth for the target set `["AKIA", "ghp_"]` (see `AlphabetScreen::new`,
//! which case-folds ASCII *letters* by also setting `b ^ 0x20`, but leaves
//! non-letters like `_` exact):
//!   letters (case-insensitive): A a K k I i G g H h P p
//!   non-letter exact:           _  (0x5F), its flip 0x7F is NOT set
//! Filler byte `x` (0x78) is deliberately outside this set.

use keyhog_scanner::testing::{
    assert_alphabet_prefilter_backend_parity, AlphabetMask, AlphabetScreen,
};

/// Canonical detector-like target set reused across the screen tests.
fn akia_ghp_targets() -> Vec<String> {
    vec!["AKIA".to_string(), "ghp_".to_string()]
}

#[test]
fn screen_empty_chunk_is_false() {
    let screen = AlphabetScreen::new(&akia_ghp_targets());
    // An empty chunk short-circuits to `false` (nothing to admit).
    assert_eq!(screen.screen(b""), false);
    assert_eq!(screen.screen(&[]), false);
}

#[test]
fn screen_admits_chunk_containing_target_byte() {
    let screen = AlphabetScreen::new(&akia_ghp_targets());
    // 'K' (0x4B) is a literal target byte -> admit.
    assert_eq!(screen.screen(b"zzzzzKzzzzz"), true);
    // '_' (0x5F) from "ghp_" is a non-letter target byte -> admit.
    assert_eq!(screen.screen(b"log_line"), true);
    // A full literal appearing verbatim -> admit.
    assert_eq!(screen.screen(b"prefix AKIA suffix"), true);
}

#[test]
fn screen_rejects_chunk_with_no_target_bytes() {
    let screen = AlphabetScreen::new(&akia_ghp_targets());
    // Bytes b,e,l,o,w,? (none is in {A a K k I i G g H h P p _}).
    assert_eq!(screen.screen(b"below?"), false);
    // Uppercase near-miss B,L,O,B (still none in the set).
    assert_eq!(screen.screen(b"BLOB"), false);
    // Pure digits and symbols, no alphabet overlap.
    assert_eq!(screen.screen(b"1234567890!@#$%^&*()"), false);
}

#[test]
fn screen_all_whitespace_chunk_rejected() {
    let screen = AlphabetScreen::new(&akia_ghp_targets());
    // Space 0x20, tab 0x09, LF 0x0A, CR 0x0D, VT 0x0B, FF 0x0C (none targeted).
    assert_eq!(screen.screen(b"   \t\n\r \x0b\x0c  "), false);
    assert_eq!(screen.screen(b"                "), false);
}

#[test]
fn screen_is_case_insensitive_for_letters() {
    // Targets are UPPERCASE "AKIA"; the screen folds ASCII letters, so the
    // lowercase twin of a target letter must still be admitted.
    let screen = AlphabetScreen::new(&["AKIA".to_string()]);
    assert_eq!(screen.screen(b"contains i letter"), true); // 'i' is flip of 'I'
    assert_eq!(screen.screen(b"contains a letter"), true); // 'a' is flip of 'A'
                                                           // A lowercase-only target admits the uppercase twin too (folding is symmetric).
    let screen_lower = AlphabetScreen::new(&["akia".to_string()]);
    assert_eq!(screen_lower.screen(b"KEY"), true); // 'K' is flip of 'k'
}

#[test]
fn screen_underscore_membership_exact_not_case_folded() {
    // '_' (0x5F) is a non-letter, so ONLY 0x5F is set, its 0x20-flip 0x7F (DEL)
    // must NOT be admitted. This guards against accidentally folding non-letters.
    let screen = AlphabetScreen::new(&["ghp_".to_string()]);
    assert_eq!(screen.screen(b"_"), true); // exact underscore -> admit
    assert_eq!(screen.screen(&[0x7Fu8]), false); // DEL (would-be flip) -> reject
}

#[test]
fn screen_matches_target_at_first_and_last_byte() {
    let screen = AlphabetScreen::new(&akia_ghp_targets());
    // Target byte at the very first position (early-exit path).
    assert_eq!(screen.screen(b"Axxxxxxxxxxx"), true);
    // Target byte at the very last position (tail/remainder path).
    assert_eq!(screen.screen(b"xxxxxxxxxxxK"), true);
}

#[test]
fn screen_target_in_avx2_remainder_tail() {
    // 40-byte chunk: the AVX2 path consumes one 32-byte block then handles an
    // 8-byte remainder scalar-side. Placing the only target byte at index 35
    // forces the remainder branch to admit it.
    let screen = AlphabetScreen::new(&akia_ghp_targets());
    let mut data = vec![b'x'; 40]; // 'x' (0x78) is outside the target set
    data[35] = b'K';
    assert_eq!(screen.screen(&data), true);
    // Same length, no target byte anywhere -> reject.
    let clean = vec![b'x'; 40];
    assert_eq!(screen.screen(&clean), false);
}

#[test]
fn screen_boundary_exactly_32_bytes() {
    // Exactly one AVX2 block, no remainder.
    let screen = AlphabetScreen::new(&akia_ghp_targets());
    let clean = vec![b'x'; 32];
    assert_eq!(clean.len(), 32);
    assert_eq!(screen.screen(&clean), false);
    // Target byte at the final index of the 32-byte block -> admit.
    let mut hit = vec![b'x'; 32];
    hit[31] = b'A';
    assert_eq!(screen.screen(&hit), true);
}

#[test]
fn screen_digit_targets_no_case_fold() {
    // Digits are non-letters: only their own bit is set, no 0x20-flip.
    let screen = AlphabetScreen::new(&["123".to_string()]);
    assert_eq!(screen.screen(b"value=1"), true); // '1' present -> admit
    assert_eq!(screen.screen(b"letters only"), false); // no 1/2/3 -> reject
    assert_eq!(screen.screen(&[0x11u8]), false); // '1'^0x20 == 0x11 not folded in
}

#[test]
fn mask_membership_exact_for_representative_bytes() {
    // `AlphabetMask::from_text` does NOT case-fold (folding lives only in
    // `AlphabetScreen::new`). Membership is tested via `intersects` with a
    // single-byte mask.
    let alpha = AlphabetMask::from_text("AKIA");
    // Present, exact case.
    assert_eq!(alpha.intersects(&AlphabetMask::from_bytes(b"A")), true);
    assert_eq!(alpha.intersects(&AlphabetMask::from_bytes(b"K")), true);
    assert_eq!(alpha.intersects(&AlphabetMask::from_bytes(b"I")), true);
    // Absent representatives.
    assert_eq!(alpha.intersects(&AlphabetMask::from_bytes(b"B")), false);
    assert_eq!(alpha.intersects(&AlphabetMask::from_bytes(b"Z")), false);
    assert_eq!(
        alpha.intersects(&AlphabetMask::from_bytes(&[0x00u8])),
        false
    );
    assert_eq!(
        alpha.intersects(&AlphabetMask::from_bytes(&[0xFFu8])),
        false
    );
}

#[test]
fn mask_from_text_is_not_case_folded() {
    // The raw mask sets exactly the bytes present, lowercase 'a' is a DIFFERENT
    // byte than 'A' and must be absent from a mask built from "AKIA".
    let alpha = AlphabetMask::from_text("AKIA");
    assert_eq!(alpha.intersects(&AlphabetMask::from_bytes(b"a")), false);
    assert_eq!(alpha.intersects(&AlphabetMask::from_bytes(b"k")), false);
    assert_eq!(alpha.intersects(&AlphabetMask::from_bytes(b"i")), false);
}

#[test]
fn mask_intersects_symmetric_and_exact() {
    let abc = AlphabetMask::from_text("abc");
    let cde = AlphabetMask::from_text("cde");
    let xyz = AlphabetMask::from_text("xyz");
    // Shared 'c' -> intersect, in both orders.
    assert_eq!(abc.intersects(&cde), true);
    assert_eq!(cde.intersects(&abc), true);
    // Disjoint alphabets -> no intersect, in both orders.
    assert_eq!(abc.intersects(&xyz), false);
    assert_eq!(xyz.intersects(&abc), false);
}

#[test]
fn mask_union_combines_membership() {
    let mut m = AlphabetMask::from_text("abc");
    m.union(&AlphabetMask::from_text("xyz"));
    // Both original and unioned bytes are now present.
    assert_eq!(m.intersects(&AlphabetMask::from_bytes(b"a")), true);
    assert_eq!(m.intersects(&AlphabetMask::from_bytes(b"y")), true);
    // A byte in neither source is still absent.
    assert_eq!(m.intersects(&AlphabetMask::from_bytes(b"q")), false);
    // Union with an empty mask leaves membership unchanged.
    let before = m;
    m.union(&AlphabetMask::default());
    assert_eq!(m, before);
}

#[test]
fn mask_default_is_empty() {
    // A default (all-zero) mask intersects nothing, including a populated mask
    // and itself.
    let empty = AlphabetMask::default();
    assert_eq!(empty.intersects(&AlphabetMask::from_text("abc")), false);
    assert_eq!(
        empty.intersects(&AlphabetMask::from_bytes(&[0x00u8])),
        false
    );
    assert_eq!(empty.intersects(&empty), false);
    // `from_text("")` produces the same empty mask.
    assert_eq!(AlphabetMask::from_text(""), empty);
}

#[test]
fn parity_helper_returns_screen_result_matching_scalar_and_simd() {
    // The facade helper cross-checks every compiled backend (scalar / AVX2 /
    // SSE2 / NEON) against the scalar fallback and returns the screen verdict.
    let targets = akia_ghp_targets();
    // Admitting corpus -> true.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&targets, b"line with AKIA token"),
        true
    );
    // Rejecting corpus ('z','q','w','v','m' none in target set) -> false.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&targets, b"zqwvm zqwvm"),
        false
    );
    // Empty corpus -> false.
    assert_eq!(
        assert_alphabet_prefilter_backend_parity(&targets, b""),
        false
    );
}
