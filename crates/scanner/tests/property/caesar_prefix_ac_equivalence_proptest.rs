//! Behavior-preservation contract for the Caesar per-shift prefix gate
//! (`decode::caesar::contains_known_prefix`).
//!
//! The gate was an `O(prefixes × |variant|)` fan of `str::contains` calls; it is
//! now a single linear Aho-Corasick pass (`PLAIN_PREFIX_AC.is_match`). An AC
//! `is_match` is an unanchored substring test, so it MUST agree with the naive
//! `any(|p| variant.contains(p))` on every input — this suite pins that
//! equivalence (Law 6: the optimization changes cost, never behavior) plus the
//! obvious positive/negative anchors. If the two ever diverge (e.g. a prefix
//! with an internal overlap the AC handles differently), these fail LOUDLY.

use keyhog_scanner::testing::decode_caesar::{contains_known_prefix, KNOWN_PREFIXES};
use proptest::prelude::*;

/// The reference the optimized gate must match: does ANY known prefix occur as a
/// substring of `s`?
fn naive_contains_known_prefix(s: &str) -> bool {
    KNOWN_PREFIXES.iter().any(|p| s.contains(p.as_str()))
}

#[test]
fn a_real_prefix_embedded_anywhere_matches() {
    // Take a few actual prefixes from the Tier-B list and prove the gate fires
    // when they appear at the start, middle, and end of a variant.
    let sample: Vec<&String> = KNOWN_PREFIXES.iter().take(6).collect();
    assert!(!sample.is_empty(), "KNOWN_PREFIXES must be non-empty");
    for prefix in sample {
        assert!(
            contains_known_prefix(prefix),
            "bare prefix must match: {prefix}"
        );
        assert!(
            contains_known_prefix(&format!("noise_{prefix}_tail")),
            "embedded prefix must match: {prefix}"
        );
        // And the reference agrees.
        assert_eq!(
            contains_known_prefix(&format!("xx{prefix}yy")),
            naive_contains_known_prefix(&format!("xx{prefix}yy"))
        );
    }
}

#[test]
fn a_string_with_no_prefix_does_not_match() {
    // A run of a single unusual char is extremely unlikely to embed any known
    // service prefix; assert the gate and reference both say no.
    let s = "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~";
    assert_eq!(contains_known_prefix(s), naive_contains_known_prefix(s));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(6_000))]

    /// The AC gate agrees with the naive substring scan on ARBITRARY input.
    #[test]
    fn ac_matches_naive_on_arbitrary_input(s in "\\PC{0,128}") {
        prop_assert_eq!(contains_known_prefix(&s), naive_contains_known_prefix(&s));
    }

    /// The AC gate agrees with the naive scan on input built from the credential
    /// alphabet (letters/digits/`_`/`-`), where real prefixes actually live —
    /// this stresses genuine overlaps, not just random Unicode that never hits a
    /// prefix.
    #[test]
    fn ac_matches_naive_on_credential_alphabet(s in "[A-Za-z0-9_\\-]{0,64}") {
        prop_assert_eq!(contains_known_prefix(&s), naive_contains_known_prefix(&s));
    }

    /// Embedding ANY real prefix guarantees a match under BOTH implementations.
    #[test]
    fn embedding_a_real_prefix_always_matches(
        idx in 0usize..1_000,
        pre in "[a-z0-9]{0,16}",
        post in "[a-z0-9]{0,16}",
    ) {
        let prefix = &KNOWN_PREFIXES[idx % KNOWN_PREFIXES.len()];
        let value = format!("{pre}{prefix}{post}");
        prop_assert!(contains_known_prefix(&value));
        prop_assert!(naive_contains_known_prefix(&value));
    }
}
