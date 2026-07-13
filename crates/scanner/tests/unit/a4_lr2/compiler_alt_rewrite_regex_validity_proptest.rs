//! Property invariant for the alternation-prefix rewriter
//! (`compiler_build::rewrite_alternation_prefix`, the fn whose leading-group
//! close-finder was hardened for escaped and char-class parens): given a VALID
//! base regex, the rewrite must NEVER emit a MALFORMED one, it either declines
//! (`None`) or returns a regex that still compiles.
//!
//! This is the exact failure the naive paren scanner produced: `(?:a|b\)c)x`
//! with prefix `a` spliced the unbalanced `[a]c)x`. The deterministic cases in
//! `compiler_alt_escaped_class` pin specific inputs; this proptest sweeps
//! thousands of adversarial interleavings of escaped parens (`\(` `\)`), char
//! classes containing parens (`[()]`), ranges (`[a-z]`), and benign filler
//! between the matched prefix and the group close, proving the corrected
//! escape/class-aware scanner keeps every rewrite well-formed.

use proptest::prelude::*;

/// Valid regex FRAGMENTS (each compiles standalone and stays balanced), chosen
/// to stress exactly the escape / char-class handling the close-finder depends
/// on. Concatenating any sequence yields a valid regex body, so the assembled
/// `(?:gh<filler>|other)tail` base is always compilable, isolating the rewrite
/// as the only thing that could introduce malformation.
const FRAGMENTS: &[&str] = &[
    "a", "b", "0", "\\)", "\\(", "[()]", "[a-z]", "-", "_", "\\|",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    /// A valid base regex whose leading `(?:…)` alternation has a branch starting
    /// with the known prefix `gh` must rewrite to a regex that STILL compiles (or
    /// to `None`), for every adversarial filler between the prefix and the group
    /// close. A `Some` carrying a regex that fails to compile is precisely the
    /// defect the escape/class-aware close-finder fixed.
    #[test]
    fn rewrite_alternation_prefix_never_emits_a_malformed_regex(
        pieces in prop::collection::vec(
            (0usize..FRAGMENTS.len()).prop_map(|i| FRAGMENTS[i]),
            0..14usize,
        ),
    ) {
        let filler: String = pieces.concat();
        let base = format!("(?:gh{filler}|other)tail");

        // Assembled bodies are balanced by construction; assume-compile keeps the
        // invariant exact even at edge concatenations.
        prop_assume!(regex::Regex::new(&base).is_ok());

        if let Some(rewritten) =
            keyhog_scanner::testing::rewrite_alternation_prefix(&base, "gh", "[gG]h")
        {
            prop_assert!(
                regex::Regex::new(&rewritten).is_ok(),
                "rewriter emitted a regex that does not compile from a valid input: \
                 {base:?} -> {rewritten:?}"
            );
        }
    }
}
