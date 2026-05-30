//! Round 1 regression contract: AlphabetScreen case-fold optimization
//! must remain bit-for-bit equivalent to the legacy
//! `union(to_lowercase) + union(to_uppercase)` String-allocating path.
//!
//! Round 1 cleaned up AlphabetScreen::new to fold ASCII case into the
//! bitmask without allocating intermediate `String`s (the prior code
//! union'd target_mask with `target.to_lowercase()` and
//! `target.to_uppercase()`). The new code XORs ASCII alphabetic bytes
//! with 0x20 to set both case bits in one pass.
//!
//! Adversarial style: PROPTEST 1k iterations. Property: for every random
//! ASCII string `t`, the new AlphabetScreen built from `[t]` screens
//! `data` identically to a hand-rolled mask that explicitly unions
//! `from_text(t)`, `from_text(t.to_lowercase())`, `from_text(t.to_uppercase())`.
//! If the new path silently drops a case-related bit, this test fails on
//! the first input where the screen disagrees.

use keyhog_scanner::alphabet_filter::{AlphabetMask, AlphabetScreen};
use proptest::prelude::*;

fn legacy_screen(target: &str) -> AlphabetMask {
    let mut mask = AlphabetMask::default();
    mask.union(&AlphabetMask::from_text(target));
    mask.union(&AlphabetMask::from_text(&target.to_lowercase()));
    mask.union(&AlphabetMask::from_text(&target.to_uppercase()));
    mask
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1_000, .. ProptestConfig::default() })]

    /// Property: the new and legacy paths produce screens that agree on
    /// EVERY input across a 256-byte universe of inputs (single-byte
    /// chunks). This is a complete-coverage cross-check: if any byte's
    /// inclusion differs, this property fails.
    #[test]
    fn new_path_matches_legacy_path_on_single_byte_inputs(
        target in "[\\x20-\\x7e]{1,32}",
    ) {
        let new_screen = AlphabetScreen::new(&[target.clone()]);
        let legacy_mask = legacy_screen(&target);
        for byte in 0u8..=255 {
            let chunk = [byte];
            let chunk_mask = AlphabetMask::from_bytes(&chunk);
            let new_says = new_screen.screen(&chunk);
            let legacy_says = legacy_mask.intersects(&chunk_mask);
            prop_assert_eq!(
                new_says, legacy_says,
                "screen mismatch for byte 0x{:02x} against target={:?}: new={} legacy={}",
                byte, target, new_says, legacy_says
            );
        }
    }

    /// Property: ASCII case folding is symmetric in the new path - a
    /// screen built from a lowercase target accepts every uppercase
    /// equivalent ASCII byte, and vice versa. This is the load-bearing
    /// invariant the legacy code provided via the two union calls.
    #[test]
    fn screen_is_ascii_case_insensitive(
        target in "[a-zA-Z]{1,16}",
    ) {
        let screen = AlphabetScreen::new(&[target.clone()]);
        for b in target.bytes() {
            // The flipped-case byte must also be admitted.
            let flipped = b ^ 0x20;
            let chunk = [flipped];
            prop_assert!(
                screen.screen(&chunk),
                "screen for target={:?} must admit the case-flipped byte 0x{:02x} (from 0x{:02x})",
                target, flipped, b
            );
        }
    }
}
