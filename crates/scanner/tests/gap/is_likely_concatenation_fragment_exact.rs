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
