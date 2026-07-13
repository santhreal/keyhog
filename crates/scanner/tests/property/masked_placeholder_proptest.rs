//! Masked-placeholder suppression contracts
//! (`crates/scanner/src/suppression/shape/canonical.rs`).
//!
//! Docs, UI prompts, and redacted config snippets carry values that LOOK like
//! secrets but are placeholders (`ghp_1a2b3c4...`, `xxxx1234567890`,
//! `abcabcabc…`). Two gates recognise them:
//!   • `looks_like_prefixed_masked_sequence`: a trailing `...`/`…` ellipsis, or an
//!     `xxx`/`***` mask prefix followed by a sequential digit / `abcdefgh` run.
//!   • `has_repeated_block_mask`: three+ long (>=4) identical-char runs, or a
//!     short block that tiles the whole string.
//! Suppressing a placeholder is safe (real secrets don't have these shapes); the
//! danger is a too-broad gate, so the accept/reject boundary is pinned exactly.

use keyhog_scanner::testing::{
    has_repeated_block_mask_for_test, looks_like_prefixed_masked_sequence_for_test,
};
use proptest::prelude::*;

// ── prefixed / trailing masked sequences ─────────────────────────────────────

#[test]
fn trailing_ellipsis_is_always_masked() {
    assert!(looks_like_prefixed_masked_sequence_for_test(
        "ghp_1a2b3c4..."
    ));
    assert!(looks_like_prefixed_masked_sequence_for_test(
        "sk_live_abcd1234…"
    )); // unicode …
}

#[test]
fn xxx_or_star_prefix_with_sequence_is_masked() {
    assert!(looks_like_prefixed_masked_sequence_for_test(
        "xxxxxxxx1234567890"
    ));
    assert!(looks_like_prefixed_masked_sequence_for_test(
        "***0123456789"
    ));
    assert!(looks_like_prefixed_masked_sequence_for_test("XXXabcdefgh")); // case-insensitive
}

#[test]
fn unmasked_values_are_not_flagged() {
    assert!(!looks_like_prefixed_masked_sequence_for_test(
        "realtokenvalue"
    ));
    assert!(!looks_like_prefixed_masked_sequence_for_test(
        "xxxnosequencehere"
    )); // prefix but no run
    assert!(!looks_like_prefixed_masked_sequence_for_test(
        "1234567890nomaskprefix"
    )); // run but no prefix
    assert!(!looks_like_prefixed_masked_sequence_for_test(""));
}

// ── repeated-block masks ─────────────────────────────────────────────────────

#[test]
fn three_long_runs_or_a_tiling_block_is_a_mask() {
    assert!(has_repeated_block_mask_for_test("aaaabbbbcccc")); // 3 runs of >=4
    assert!(has_repeated_block_mask_for_test("abcabcabcabcabcabcabcabc")); // block "abc" ×8, len 24
    assert!(has_repeated_block_mask_for_test("12ab12ab12ab12ab12ab12ab")); // block "12ab" ×6
}

#[test]
fn ordinary_values_are_not_repeated_block_masks() {
    assert!(!has_repeated_block_mask_for_test("abcdefghij")); // no long run, no tiling
    assert!(!has_repeated_block_mask_for_test("aabbccddee")); // runs of 2 only
    assert!(!has_repeated_block_mask_for_test("short"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// ANY value ending in `...` is masked, whatever precedes it.
    #[test]
    fn trailing_triple_dot_is_always_masked(prefix in "[a-zA-Z0-9_]{0,32}") {
        let value = format!("{prefix}...");
        prop_assert!(looks_like_prefixed_masked_sequence_for_test(&value));
    }

    /// A masked-sequence match IMPLIES a trailing ellipsis OR an `xxx`/`***` prefix
    ///: the gate never fires on a value with neither signal.
    #[test]
    fn masked_match_implies_ellipsis_or_mask_prefix(value in "[a-zA-Z0-9*.]{0,40}") {
        if looks_like_prefixed_masked_sequence_for_test(&value) {
            let lower = value.to_ascii_lowercase();
            let has_signal = value.ends_with("...")
                || value.ends_with('…')
                || lower.starts_with("xxx")
                || value.starts_with("***");
            prop_assert!(has_signal, "no mask signal in {value:?}");
        }
    }

    /// A single short block repeated enough times to reach the 24-byte tiling
    /// floor is ALWAYS a repeated-block mask via the tiling detector. `reps` is
    /// lifted to guarantee `len >= 24` by construction (no rejection), keeping the
    /// value a pure whole-block tiling.
    #[test]
    fn tiled_block_is_always_a_mask(
        block in "[a-z]{3,8}",
        reps in 3usize..12,
    ) {
        let min_reps = 24_usize.div_ceil(block.len());
        let value = block.repeat(reps.max(min_reps));
        prop_assert!(value.len() >= 24);
        prop_assert!(has_repeated_block_mask_for_test(&value));
    }

    /// A value with NO run of 4+ identical bytes and length < 24 is NEVER a
    /// repeated-block mask (neither the run branch nor the tiling branch can fire).
    #[test]
    fn short_no_long_run_is_never_a_block_mask(value in "[a-z]{0,20}") {
        // Reject any input that happens to contain a 4-run so the premise holds.
        let has_4run = value.as_bytes().windows(4).any(|w| w.iter().all(|&b| b == w[0]));
        prop_assume!(!has_4run && value.len() < 24);
        prop_assert!(!has_repeated_block_mask_for_test(&value));
    }
}
