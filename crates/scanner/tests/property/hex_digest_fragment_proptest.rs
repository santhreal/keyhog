//! Hash-fragment FP-suppression contract (`crates/scanner/src/adjudicate/mod.rs`
//! `is_hex_digest_fragment`).
//!
//! When a detector matches a run of hex that is actually a SUBSTRING of a longer
//! contiguous hex digest (a SHA-1 = 40 hex, SHA-256 = 64 hex split across the
//! match boundary), that match is a false positive, the bytes are a hash, not a
//! credential. This gate suppresses it, but ONLY when every precondition holds,
//! so it can never swallow a real standalone token. The exact truth table is
//! pinned here (an unknown detector id → default `min_len` 16, deterministic
//! without the registry); the proptest tiers sweep the two decisive invariants.

use keyhog_scanner::testing::is_hex_digest_fragment_for_test;
use proptest::prelude::*;

const FAKE_ID: &str = "definitely-not-a-real-detector-id-xyz"; // → default min_len 16

// ── the suppression truth table ──────────────────────────────────────────────

#[test]
fn partial_match_inside_a_long_hash_is_suppressed() {
    // A 64-char SHA-256 run; the detector matched a 20-char slice in the middle.
    // Hex context on BOTH sides + total run 64 >= 40 → it is a fragment.
    let data = "a".repeat(64);
    assert!(is_hex_digest_fragment_for_test(
        FAKE_ID,
        &data,
        22,
        42,
        &"a".repeat(20)
    ));
}

#[test]
fn one_sided_hex_context_still_suppresses() {
    // Match at the very START of a 50-char hex run: no hex before, 30 hex after.
    // "not both zero" is satisfied and total 50 >= 40 → fragment.
    let data = "e".repeat(50);
    assert!(is_hex_digest_fragment_for_test(
        FAKE_ID,
        &data,
        0,
        20,
        &"e".repeat(20)
    ));
}

#[test]
fn standalone_hash_with_no_context_is_not_suppressed() {
    // A complete 40-char hex with NOTHING around it: before==0 && after==0 → not a
    // fragment (a standalone value is judged by the other gates, never dropped here).
    let data = "b".repeat(40);
    assert!(!is_hex_digest_fragment_for_test(
        FAKE_ID,
        &data,
        0,
        40,
        &"b".repeat(40)
    ));
}

#[test]
fn short_credential_below_min_len_is_not_a_fragment() {
    // 10 hex chars < the default min_len of 16 → never a fragment regardless of run.
    let data = "c".repeat(64);
    assert!(!is_hex_digest_fragment_for_test(
        FAKE_ID,
        &data,
        10,
        20,
        &"c".repeat(10)
    ));
}

#[test]
fn non_hex_credential_is_not_a_fragment() {
    // The matched value contains non-hex bytes → cannot be part of a hex digest.
    let data = "z".repeat(64);
    assert!(!is_hex_digest_fragment_for_test(
        FAKE_ID,
        &data,
        22,
        42,
        &"z".repeat(20)
    ));
}

#[test]
fn total_run_below_forty_is_not_a_fragment() {
    // Whole surrounding run is only 30 hex chars (< 40 = SHA-1 width) → not a digest.
    let data = "d".repeat(30);
    assert!(!is_hex_digest_fragment_for_test(
        FAKE_ID,
        &data,
        5,
        25,
        &"d".repeat(20)
    ));
}

#[test]
fn out_of_range_offsets_fail_closed_to_not_a_fragment() {
    // start > end, and end past the buffer: both bounds violations return false
    // (never index out of range).
    assert!(!is_hex_digest_fragment_for_test(
        FAKE_ID,
        &"a".repeat(64),
        30,
        10,
        &"a".repeat(20)
    ));
    assert!(!is_hex_digest_fragment_for_test(
        FAKE_ID,
        "aaaa",
        0,
        100,
        &"a".repeat(20)
    ));
}

#[test]
fn hex_run_stops_at_first_non_hex_neighbor() {
    // 20-hex match, then "xyz" (non-hex), then more: the `after` count stops at 'x',
    // so the run is only 20 < 40 with no leading context → not a fragment.
    let data = format!("{}xyz{}", "f".repeat(20), "f".repeat(20));
    assert!(!is_hex_digest_fragment_for_test(
        FAKE_ID,
        &data,
        0,
        20,
        &"f".repeat(20)
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// INVARIANT (suppress): a credential of >= 16 hex chars taken as a strict
    /// interior slice of a hex run of length >= 40 is ALWAYS a fragment, it has
    /// hex context on at least one side and the whole run clears 40.
    #[test]
    fn interior_slice_of_long_hex_run_is_always_a_fragment(
        run_len in 40usize..256,
        cred_len in 16usize..31,
    ) {
        // Keep the slice strictly shorter than the run so context exists somewhere.
        prop_assume!(cred_len < run_len);
        let data = "a".repeat(run_len);
        let start = (run_len - cred_len) / 2;
        let end = start + cred_len;
        prop_assert!(
            is_hex_digest_fragment_for_test(FAKE_ID, &data, start, end, &"a".repeat(cred_len)),
            "run {} cred {} [{},{}]", run_len, cred_len, start, end
        );
    }

    /// INVARIANT (never suppress): if the credential contains ANY non-hex byte it
    /// is never a fragment, whatever the surrounding bytes look like.
    #[test]
    fn non_hex_credential_never_suppressed(
        cred in "[g-zG-Z]{16,40}",
        pad in 0usize..40,
    ) {
        let data = format!("{}{}{}", "a".repeat(pad), cred, "a".repeat(pad));
        prop_assert!(
            !is_hex_digest_fragment_for_test(FAKE_ID, &data, pad, pad + cred.len(), &cred)
        );
    }
}
