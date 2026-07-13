//! Standalone unit coverage for `keyhog_scanner::alphabet_filter`.
//!
//! `AlphabetMask` is a 256-bit byte-presence histogram; `AlphabetScreen` is the
//! Layer-0 chunk-skip prefilter. These tests assert exact presence/intersection
//! semantics, the SIMD-vs-scalar mask equality contract, the case-folding
//! screen, and the empty-data reject (never `is_empty` decoration).

use keyhog_scanner::testing::{
    assert_alphabet_prefilter_backend_parity, AlphabetMask, AlphabetScreen,
};

// ---------------------------------------------------------------------------
// AlphabetMask, presence + intersection
// ---------------------------------------------------------------------------

#[test]
fn mask_from_text_intersects_on_shared_byte() {
    let a = AlphabetMask::from_text("ghp_");
    let b = AlphabetMask::from_text("xyzp"); // shares 'p'
    assert!(a.intersects(&b));
}

#[test]
fn mask_disjoint_alphabets_do_not_intersect() {
    let a = AlphabetMask::from_text("abc");
    let b = AlphabetMask::from_text("xyz");
    assert!(!a.intersects(&b));
}

#[test]
fn empty_mask_intersects_nothing() {
    let empty = AlphabetMask::default();
    let full = AlphabetMask::from_text("anything");
    assert!(!empty.intersects(&full));
    assert!(!full.intersects(&empty));
}

#[test]
fn union_merges_alphabets() {
    let mut a = AlphabetMask::from_text("abc");
    let b = AlphabetMask::from_text("xyz");
    a.union(&b);
    // After union, `a` must intersect a probe drawn from EITHER source.
    assert!(a.intersects(&AlphabetMask::from_text("a")));
    assert!(a.intersects(&AlphabetMask::from_text("z")));
}

#[test]
fn mask_equality_is_byte_set_based() {
    // Same byte set in different order / multiplicity -> equal masks.
    assert_eq!(
        AlphabetMask::from_bytes(b"abcabc"),
        AlphabetMask::from_bytes(b"cba")
    );
    assert_ne!(
        AlphabetMask::from_bytes(b"abc"),
        AlphabetMask::from_bytes(b"abcd")
    );
}

#[test]
fn high_bytes_set_in_upper_lanes() {
    // Bytes >= 192 land in the 4th u64 lane; ensure they are tracked, not lost.
    let a = AlphabetMask::from_bytes(&[0xC0, 0xFF]);
    let b = AlphabetMask::from_bytes(&[0xFF]);
    assert!(a.intersects(&b));
    // And a low-byte probe does NOT intersect a purely-high-byte mask.
    assert!(!a.intersects(&AlphabetMask::from_bytes(b"a")));
}

// ---------------------------------------------------------------------------
// SIMD body parity (scalar reference), the documented robustness contract
// ---------------------------------------------------------------------------

#[test]
fn scalar_path_matches_from_bytes_entry() {
    // `from_bytes` dispatches to the scalar body; assert they are identical for
    // a representative byte mix spanning all four lanes.
    let data: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
    assert_alphabet_prefilter_backend_parity(&[], &data);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn avx2_body_matches_scalar_when_available() {
    if !is_x86_feature_detected!("avx2") {
        return; // host-gated; nothing to compare on a non-AVX2 box
    }
    let data: Vec<u8> = b"ghp_AKIA sk_live_ xoxb- 0123456789 \xC0\xFF\x80"
        .iter()
        .copied()
        .collect();
    assert_alphabet_prefilter_backend_parity(&["ghp_".to_string(), "AKIA".to_string()], &data);
}

// ---------------------------------------------------------------------------
// AlphabetScreen, case-folding chunk skip
// ---------------------------------------------------------------------------

#[test]
fn screen_true_when_chunk_shares_target_byte() {
    let screen = AlphabetScreen::new(&["ghp_".into()]);
    assert!(screen.screen(b"some text with g in it"));
}

#[test]
fn screen_false_when_no_target_byte_present() {
    // Target alphabet is {x, y, z}; a chunk made only of {0-9, space} shares none.
    let screen = AlphabetScreen::new(&["xyz".into()]);
    assert!(!screen.screen(b"0123456789 4455"));
}

#[test]
fn screen_folds_ascii_case() {
    // Target "ABC" must also match lowercase 'a' (case is folded into the mask).
    let screen = AlphabetScreen::new(&["ABC".into()]);
    assert!(screen.screen(b"---a---")); // lowercase 'a' present
    assert!(screen.screen(b"---C---")); // uppercase 'C' present
}

#[test]
fn screen_empty_chunk_is_false() {
    let screen = AlphabetScreen::new(&["ghp_".into()]);
    assert!(!screen.screen(b""));
}

#[test]
fn screen_long_no_match_chunk_rejected() {
    // 1KB of a single byte not in the target alphabet -> screened out.
    let screen = AlphabetScreen::new(&["Q".into()]);
    let data = vec![b'a'; 1024];
    assert!(!screen.screen(&data));
}

#[test]
fn screen_long_with_match_at_tail_accepted() {
    // Match in the AVX2 remainder tail must still be found.
    let screen = AlphabetScreen::new(&["Q".into()]);
    let mut data = vec![b'a'; 1000];
    data.push(b'Q'); // a 'Q' at the very end (tail of the chunked scan)
    assert!(screen.screen(&data));
}
