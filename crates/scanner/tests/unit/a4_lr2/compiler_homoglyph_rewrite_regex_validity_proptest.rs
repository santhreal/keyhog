//! Companion to `compiler_alt_rewrite_regex_validity_proptest`, one level up:
//! the PRODUCTION rewrite entry `compiler_build::rewrite_homoglyph_literal_prefix`
//! (what the compiler actually calls) must also never turn a VALID base regex
//! into a malformed one. It routes through TWO paths, the literal-head form
//! (`{prefix}…` via `strip_literal_prefix_source` / `rewrite_homoglyph_body_prefix`)
//! and, failing that, the alternation fallback (`rewrite_alternation_prefix`,
//! whose close-finder was hardened for escaped/class parens). This proptest
//! exercises BOTH shapes with adversarial escape/class filler and asserts the
//! output always compiles (or is declined).

use proptest::prelude::*;

/// Valid, standalone-compilable regex fragments that stress escape / char-class
/// handling; concatenating any sequence stays a valid regex body.
const FRAGMENTS: &[&str] = &[
    "a", "b", "0", "\\)", "\\(", "[()]", "[a-z]", "-", "_", "\\|",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    /// For both a literal-head base (`gh<filler>[a-z]*`) and an alternation-head
    /// base (`(?:gh<filler>|other)tail`), a valid input must rewrite to a regex
    /// that still compiles, or to `None`: never to a `Some` that fails to
    /// compile.
    #[test]
    fn rewrite_homoglyph_literal_prefix_never_emits_a_malformed_regex(
        pieces in prop::collection::vec(
            (0usize..FRAGMENTS.len()).prop_map(|i| FRAGMENTS[i]),
            0..14usize,
        ),
        use_alternation in any::<bool>(),
    ) {
        let filler: String = pieces.concat();
        let base = if use_alternation {
            format!("(?:gh{filler}|other)tail")
        } else {
            format!("gh{filler}[a-z]*")
        };

        prop_assume!(regex::Regex::new(&base).is_ok());

        if let Some(rewritten) =
            keyhog_scanner::testing::rewrite_homoglyph_literal_prefix(&base, "gh", "[gG]h")
        {
            prop_assert!(
                regex::Regex::new(&rewritten).is_ok(),
                "production rewrite entry emitted a non-compiling regex from a valid input: \
                 {base:?} -> {rewritten:?}"
            );
        }
    }
}
