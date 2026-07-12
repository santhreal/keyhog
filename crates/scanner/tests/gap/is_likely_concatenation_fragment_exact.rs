//! Gap test: `is_likely_concatenation_fragment` (entropy/keywords.rs).
//!
//! Load-bearing in `extract_candidates_internal`: a true verdict drops the line
//! from entropy candidate extraction as a `ConcatenationFragmentLine`. We pin
//! both branches with exact bool verdicts hand-traced against the source.

use keyhog_scanner::testing::is_likely_concatenation_fragment_for_test as is_fragment;

#[test]
fn quoted_run_with_concat_glue_is_fragment() {
    // opens `"`, exactly two `"`, suffix after last quote = "+" -> fragment.
    assert!(is_fragment("\"foo\" +"));
    // suffix starts with '+'.
    assert!(is_fragment("\"foo\" + bar"));
    // suffix `)` (closing call arg).
    assert!(is_fragment("\"foo\")"));
    // single-quoted run, trailing comma.
    assert!(is_fragment("'bar',"));
}

#[test]
fn bare_balanced_quoted_run_empty_suffix_is_fragment() {
    // exactly two `"`, nothing after the closing quote -> empty suffix -> true.
    assert!(is_fragment("\"complete value\""));
}

#[test]
fn quoted_run_with_real_trailing_text_is_not_fragment() {
    // suffix after last `"` is "= something" -> not glue, not empty -> false,
    // and line does not end with `\"` or `-\`.
    assert!(!is_fragment("\"key\" = something"));
}

#[test]
fn line_suffix_branch_dash_backslash_is_fragment() {
    // does not open with a quote; ends with `-\` -> fragment.
    assert!(is_fragment("abc-\\"));
    // ends with backslash-quote `\"`.
    assert!(is_fragment("literal\\\""));
}

#[test]
fn plain_assignment_is_not_fragment() {
    // opens with `x`, line ends with `"` (not `\"`), no `-\` -> false.
    assert!(!is_fragment("x = \"abc\""));
    // four quotes: neither the dq==2 nor sq==2 balanced branch fires.
    assert!(!is_fragment("\"a\" \"b\""));
    assert!(!is_fragment(""));
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin both branches on hand-picked lines; these SWEEP the two
// directional guarantees. A TRUE verdict DROPS the line from entropy candidate
// extraction, so a false positive is a silent recall loss — property (1) is the
// recall guard, (2) the detection guard. Confirmed against the source (a leading
// `"`/`'` gates the quoted-run branch; the final `ends_with("\\\"")||("-\\")`
// catches line-continuation glue). No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// RECALL: a plain line with no quote-run and no line-continuation glue is
    /// NEVER a fragment, so an ordinary entropy-candidate line is not dropped.
    /// (No `"`/`'` ⇒ the quoted-run branch is skipped; no trailing `\"`/`-\` ⇒ the
    /// suffix branch is false.)
    #[test]
    fn plain_text_is_never_a_concatenation_fragment(s in "[a-z0-9 =]{1,20}") {
        prop_assert!(!is_fragment(&s));
    }

    /// A line whose trimmed form ends with the `-\` line-continuation glue is
    /// ALWAYS a fragment — the final suffix branch catches it regardless of prefix.
    #[test]
    fn dash_backslash_continuation_is_always_a_fragment(s in "[a-z0-9 ]{0,15}") {
        let line = format!("{s}-\\");
        prop_assert!(is_fragment(&line));
    }

    /// The classifier must never panic on arbitrary Unicode input.
    #[test]
    fn is_fragment_never_panics(s in "(?s).{0,60}") {
        let _ = is_fragment(&s);
    }
}
