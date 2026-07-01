//! Recall lock: the `+`/`.` string-concatenation extractors stripped a
//! `name = value` assignment prefix with a quote-UNAWARE `str::find('=')`. On a
//! bare continuation fragment whose first quoted literal ends in base64 padding
//! (`"aGVsbG8=" + "d29ybGQ="`) that `find('=')` matched the padding `=` INSIDE
//! the literal, discarded the leading fragment, and corrupted the operator split
//! so the whole concatenation was dropped — a silent recall loss on any secret
//! whose reassembly crosses a padded base64 fragment. The fix finds the
//! assignment `=` only OUTSIDE quoted spans (one shared `strip_assignment_prefix`
//! for both extractors, replacing two copies of the buggy scan).
//!
//! Source under test:
//!   * `crates/scanner/src/multiline/string_extract.rs`
//!         (`find_unquoted_assignment_eq`, `strip_assignment_prefix`,
//!          `extract_plus_concatenation`, `extract_dot_concatenation`)
//!   * `crates/scanner/src/multiline/preprocessor.rs` (continuation join)
//!
//! Unit tests drive the extractors directly through the `testing` facade and
//! assert the exact reassembled value; integration tests drive the real
//! `preprocess_multiline` join path.

use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{
    extract_dot_concatenation_for_test, extract_plus_concatenation_for_test, preprocess_multiline,
    MultilineConfig, PreprocessedText,
};

fn plus(line: &str) -> Option<(String, bool)> {
    extract_plus_concatenation_for_test(line)
}

fn dot(line: &str) -> Option<(String, bool)> {
    extract_dot_concatenation_for_test(line)
}

fn some(value: &str, continues: bool) -> Option<(String, bool)> {
    Some((value.to_string(), continues))
}

fn pre(text: &str) -> PreprocessedText<'_> {
    preprocess_multiline(
        std::borrow::Cow::Borrowed(text),
        &MultilineConfig::default(),
        &FragmentCache::new(100),
    )
}

// ── `+` concat: the bug — base64 padding in a bare continuation fragment ──────

#[test]
fn plus_bare_fragment_base64_padding_first_literal_preserved() {
    // Before the fix: `find('=')` split at the padding inside `"aGVsbG8="`,
    // dropping the leading fragment and the second literal entirely.
    assert_eq!(
        plus(r#""aGVsbG8=" + "d29ybGQ=""#),
        some("aGVsbG8=d29ybGQ=", false)
    );
}

#[test]
fn plus_bare_fragment_double_padding_preserved() {
    assert_eq!(plus(r#""YQ==" + "Ymo=""#), some("YQ==Ymo=", false));
}

#[test]
fn plus_bare_fragment_padding_three_literals() {
    assert_eq!(
        plus(r#""YWE=" + "YmI=" + "Y2M=""#),
        some("YWE=YmI=Y2M=", false)
    );
}

#[test]
fn plus_bare_fragment_padding_then_trailing_plus_continues() {
    // A single padded literal with a trailing join `+`: the fragment must be
    // kept whole AND the continuation flag set.
    assert_eq!(plus(r#""aGVsbG8=" +"#), some("aGVsbG8=", true));
}

#[test]
fn plus_bare_fragment_equals_inside_both_literals_preserved() {
    // Both `=` are inside quoted spans; the quote-aware scan finds NO assignment
    // and splits the whole line.
    assert_eq!(plus(r#""a=b" + "c=d""#), some("a=bc=d", false));
}

// ── `+` concat: regressions (assignment `=` precedes the value) ───────────────

#[test]
fn plus_assignment_padding_in_value_first_literal_still_joins() {
    // The `key =` assignment `=` is outside quotes and found first, so this WAS
    // correct before the fix — it must stay correct.
    assert_eq!(
        plus(r#"key = "aGVsbG8=" + "d29ybGQ=""#),
        some("aGVsbG8=d29ybGQ=", false)
    );
}

#[test]
fn plus_assignment_lhs_keyword_not_embedded_in_value() {
    let (value, _) = plus(r#"apiKey = "AKIA" + "IOSFODNN7EXAMPLE""#).expect("join");
    assert_eq!(value, "AKIAIOSFODNN7EXAMPLE");
    assert!(!value.contains("apiKey"), "LHS must be stripped: {value:?}");
}

#[test]
fn plus_assignment_value_with_unquoted_and_quoted_equals() {
    assert_eq!(plus(r#"x = "a=b" + "c=d""#), some("a=bc=d", false));
}

#[test]
fn plus_no_operator_returns_none() {
    assert_eq!(plus(r#""justoneliteral""#), None);
}

#[test]
fn plus_unquoted_expression_returns_none() {
    // No quoted literal anywhere: a bare `a + b` is arithmetic, not a join.
    assert_eq!(plus("a + b + c"), None);
}

#[test]
fn plus_single_literal_internal_plus_not_split() {
    // A lone base64 literal whose alphabet contains `+` is ONE value, not a
    // concatenation (regression for the in-quote `+` guard).
    assert_eq!(plus(r#"x = "aGVsbG8+more""#), None);
}

#[test]
fn plus_baseline_plain_two_literals_joined() {
    assert_eq!(
        plus(r#"a = "AKIA" + "IOSFODNN7EXAMPLE""#),
        some("AKIAIOSFODNN7EXAMPLE", false)
    );
}

// ── `.` concat (PHP/Perl): the bug + regressions ─────────────────────────────

#[test]
fn dot_bare_fragment_base64_padding_first_literal_preserved() {
    assert_eq!(dot(r#""YQ==" . "Ymo=""#), some("YQ==Ymo=", false));
}

#[test]
fn dot_bare_fragment_padding_three_literals() {
    assert_eq!(
        dot(r#""YWE=" . "YmI=" . "Y2M=""#),
        some("YWE=YmI=Y2M=", false)
    );
}

#[test]
fn dot_bare_fragment_padding_trailing_dot_continues() {
    assert_eq!(dot(r#""YQ==" ."#), some("YQ==", true));
}

#[test]
fn dot_assignment_padding_in_value_still_joins() {
    assert_eq!(dot(r#"$x = "YQ==" . "Ymo=""#), some("YQ==Ymo=", false));
}

#[test]
fn dot_member_access_not_joined() {
    assert_eq!(dot("obj.method().field"), None);
}

#[test]
fn dot_float_literal_not_joined() {
    assert_eq!(dot("x = 3.14"), None);
}

#[test]
fn dot_single_literal_internal_dots_not_joined() {
    // `"api.example.com"` is one value; the interior `.` are not joins.
    assert_eq!(dot(r#"$host = "api.example.com""#), None);
}

// ── Full-path integration through the real `preprocess_multiline` join ────────

#[test]
fn full_path_plus_padded_continuation_reassembles_whole_secret() {
    // line0 anchors + continues; line1 is a padded-fragment continuation whose
    // first literal ends in base64 padding — the exact bug shape.
    let text = "key = \"start\" +\n\"aGVsbG8=\" + \"d29ybGQ=\"\n";
    let p = pre(text);
    assert!(
        p.text.contains("startaGVsbG8=d29ybGQ="),
        "expected whole reassembled secret in {:?}",
        p.text
    );
}

#[test]
fn full_path_plus_baseline_still_reassembles() {
    let text = "key = \"AKIA\" +\n\"IOSFODNN7\"\n";
    let p = pre(text);
    assert!(p.text.contains("AKIAIOSFODNN7"), "{:?}", p.text);
}

#[test]
fn full_path_dot_padded_continuation_reassembles_whole_secret() {
    let text = "$k = \"YQ==\" .\n\"Ymo=\" . \"c3M=\"\n";
    let p = pre(text);
    assert!(
        p.text.contains("YQ==Ymo=c3M="),
        "expected whole dot-reassembled secret in {:?}",
        p.text
    );
}

#[test]
fn full_path_padded_fragment_preserves_original_prefix() {
    let text = "key = \"start\" +\n\"aGVsbG8=\" + \"d29ybGQ=\"\n";
    let p = pre(text);
    assert!(p.text.starts_with(text), "original bytes must be preserved");
    assert_eq!(p.original_end, text.len());
}
