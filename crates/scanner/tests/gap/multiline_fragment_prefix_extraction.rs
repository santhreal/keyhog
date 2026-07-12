//! Gap test: the fragment-name prefix extractor (`extract_prefix`).
//!
//! When a credential is split across assignment fragments (`api_key_part1`,
//! `api_key_part2`, ...) the structural resolver collapses each fragment name
//! to a shared base prefix so the pieces group together. `extract_prefix` does
//! that collapse: it drops `_`/`-` separators and `part` segments, lowercases,
//! and trims a trailing numeric run. Pin the exact outputs across those three
//! transforms so a regression in any one is caught.
//!
//! The seam lives in the multiline test module, so this is feature-gated.
#![cfg(feature = "multiline")]

use keyhog_scanner::testing::multiline::extract_prefix_for_test as extract_prefix;

#[test]
fn underscore_separator_is_dropped() {
    // `_` is a separator: `api_key` collapses to a contiguous lowercase base.
    assert_eq!(extract_prefix("api_key"), "apikey");
}

#[test]
fn part_segment_and_trailing_digits_are_stripped() {
    // `token_part1` drops the `_`, skips the `part` segment, then the trailing
    // `1` is trimmed — leaving the shared base that groups the fragments.
    assert_eq!(extract_prefix("token_part1"), "token");
}

#[test]
fn hyphen_separator_is_dropped_and_value_lowercased() {
    // `-` is a separator like `_`, and mixed case folds to lowercase.
    assert_eq!(extract_prefix("Auth-Token"), "authtoken");
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example of each transform; these SWEEP them. Two
// kinds of property: (1) OUTPUT INVARIANTS that hold for EVERY input (no
// separator, no uppercase, no trailing digit, never longer) — these need no
// oracle and catch any transform regression; (2) CONSTRUCTIVE differentials that
// isolate each documented transform (separator-drop, `part`-strip, trailing-digit
// trim) by building an input whose prefix is a known clean base. All claims were
// traced against `string_extract.rs::extract_prefix`. No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// Invariants that hold for ANY input: the output never carries a separator
    /// (`_`/`-`), never an uppercase ASCII letter, never ends with an ASCII digit,
    /// and is never longer than the input (the extractor only drops/folds bytes).
    /// Arbitrary Unicode also locks that the byte-level `part`/separator scan never
    /// panics on a multibyte boundary.
    #[test]
    fn output_invariants_hold_for_all_inputs(var in "(?s).{0,40}") {
        let out = extract_prefix(&var);
        prop_assert!(!out.contains('_') && !out.contains('-'), "separators leaked: {:?}", out);
        prop_assert!(
            !out.bytes().any(|b| b.is_ascii_uppercase()),
            "uppercase leaked: {:?}",
            out
        );
        prop_assert!(
            !out.chars().last().is_some_and(|c| c.is_ascii_digit()),
            "trailing digit: {:?}",
            out
        );
        prop_assert!(out.len() <= var.len(), "output grew: {:?} -> {:?}", var, out);
    }

    /// On a clean lowercase-alpha base (no separators, no digits, no `part`
    /// substring anywhere), the extractor is the IDENTITY.
    #[test]
    fn identity_on_clean_lowercase_base(base in "[a-z]{1,12}") {
        prop_assume!(!base.contains("part"));
        prop_assert_eq!(extract_prefix(&base), base.clone());
    }

    /// Separators (`_`/`-`) are transparent: weaving them between the base
    /// characters yields the same prefix as the clean base.
    #[test]
    fn separators_are_transparent(base in "[a-z]{1,10}", seps in "[_-]{0,6}") {
        prop_assume!(!base.contains("part"));
        let sep_chars: Vec<char> = seps.chars().collect();
        let mut woven = String::new();
        for (idx, c) in base.chars().enumerate() {
            woven.push(c);
            if let Some(s) = sep_chars.get(idx) {
                woven.push(*s);
            }
        }
        prop_assert_eq!(extract_prefix(&woven), base.clone());
    }

    /// A trailing ASCII-digit run is trimmed back to the clean base.
    #[test]
    fn trailing_digits_are_trimmed(base in "[a-z]{1,10}", digits in "[0-9]{1,6}") {
        prop_assume!(!base.contains("part"));
        let with_digits = format!("{base}{digits}");
        prop_assert_eq!(extract_prefix(&with_digits), base.clone());
    }

    /// A `_part<n>` fragment suffix is stripped (segment skip + trailing-digit
    /// trim), collapsing every fragment of a base to that shared base.
    #[test]
    fn part_fragment_suffix_collapses_to_base(base in "[a-z]{1,10}", n in 0u32..99) {
        prop_assume!(!base.contains("part"));
        let fragment = format!("{base}_part{n}");
        prop_assert_eq!(extract_prefix(&fragment), base.clone());
    }
}
