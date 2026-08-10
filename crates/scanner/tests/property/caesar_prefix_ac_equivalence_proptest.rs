//! Behavior-preservation contract for the Caesar per-shift prefix gate
//! (`decode::caesar::contains_known_prefix`).
//!
//! The gate was an `O(prefixes × |variant|)` fan of boundary-aware
//! `str::contains` calls; it is now one linear Aho-Corasick pass followed by
//! the same ASCII token-boundary check. A prefix at byte zero always matches.
//! A later prefix matches only when the preceding byte is not ASCII
//! alphanumeric or `_`, which prevents suffixes inside longer identifiers from
//! admitting a Caesar decode. This suite pins exact equivalence (Law 6: the
//! optimization changes cost, never behavior) plus positive and negative
//! boundary anchors.

use keyhog_scanner::testing::decode_caesar::{contains_known_prefix, KNOWN_PREFIXES};
use proptest::prelude::*;

/// Boundary-aware reference for the optimized gate.
fn naive_contains_known_prefix(s: &str) -> bool {
    KNOWN_PREFIXES.iter().any(|prefix| {
        s.match_indices(prefix.as_str()).any(|(start, _)| {
            start == 0
                || !matches!(
                    s.as_bytes()[start - 1],
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'
                )
        })
    })
}

#[test]
fn a_real_prefix_at_token_boundaries_matches() {
    // Take a few actual prefixes and prove the gate fires at byte zero and
    // after an ASCII delimiter.
    let sample: Vec<&String> = KNOWN_PREFIXES.iter().take(6).collect();
    assert!(!sample.is_empty(), "KNOWN_PREFIXES must be non-empty");
    for prefix in sample {
        assert!(
            contains_known_prefix(prefix),
            "bare prefix must match: {prefix}"
        );
        assert!(
            contains_known_prefix(&format!("noise-{prefix}-tail")),
            "boundary-delimited prefix must match: {prefix}"
        );
        // And the reference agrees.
        assert_eq!(
            contains_known_prefix(&format!("xx-{prefix}yy")),
            naive_contains_known_prefix(&format!("xx-{prefix}yy"))
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

    /// The AC gate agrees with the boundary-aware reference on arbitrary input.
    #[test]
    fn ac_matches_naive_on_arbitrary_input(s in "\\PC{0,128}") {
        prop_assert_eq!(contains_known_prefix(&s), naive_contains_known_prefix(&s));
    }

    /// Credential-alphabet input stresses prefixes embedded inside longer
    /// identifiers, where the preceding-byte boundary decides admission.
    #[test]
    fn ac_matches_naive_on_credential_alphabet(s in "[A-Za-z0-9_\\-]{0,64}") {
        prop_assert_eq!(contains_known_prefix(&s), naive_contains_known_prefix(&s));
    }

    /// Embedding any real prefix after a delimiter guarantees a match.
    #[test]
    fn embedding_a_real_prefix_at_a_boundary_always_matches(
        idx in 0usize..1_000,
        pre in "[a-z0-9]{0,16}-",
        post in "[a-z0-9]{0,16}",
    ) {
        let prefix = &KNOWN_PREFIXES[idx % KNOWN_PREFIXES.len()];
        let value = format!("{pre}{prefix}{post}");
        prop_assert!(contains_known_prefix(&value));
        prop_assert!(naive_contains_known_prefix(&value));
    }
}
