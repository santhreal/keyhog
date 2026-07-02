//! Regression lock: multiline concatenation **JOIN** contracts.
//!
//! The multiline preprocessor (`crates/scanner/src/multiline/`) reassembles a
//! secret that a source file split across lines with an explicit string
//! concatenation operator (`+` in Java/JS/Python/C#, `.` in PHP/Perl) or a
//! trailing-operator continuation, so the scanner sees the whole credential as
//! one contiguous span. This file pins the JOIN behaviour end to end:
//!
//!   * POSITIVE — a `"AKIA" +` / `"ghp_" .` fragment continued on the next line
//!     reassembles into the EXACT credential bytes, appended after the untouched
//!     original body, with `original_end` always equal to the input length.
//!   * NEGATIVE TWIN — ordinary two-line prose, an unquoted arithmetic `+`, a
//!     `.` member access, and a base64 value whose alphabet contains `+`/`.`
//!     INSIDE a quoted literal are NOT falsely joined (no synthetic candidate).
//!   * BOUNDARY — `MultilineConfig::max_join_lines` is the join window: a chain
//!     that fits reassembles the whole key; one line past the window truncates
//!     the join; a window of 1 disables joining entirely.
//!
//! HOST-INDEPENDENCE: every function under test is a pure CPU string transform
//! (no Hyperscan / SIMD / GPU on this path), so these assertions hold
//! byte-identically on every host — there is no accelerator to be absent.
//!
//! Source under test:
//!   * crates/scanner/src/multiline/preprocessor.rs
//!       (`preprocess_multiline`, `process_line_chain` join walk, join window)
//!   * crates/scanner/src/multiline/string_extract.rs
//!       (`extract_plus_concatenation`, `extract_dot_concatenation`,
//!        `split_concatenation_operators`, `strip_assignment_prefix`)
//!   * crates/scanner/src/multiline/config.rs
//!       (`has_concatenation_indicators`, `MultilineConfig::max_join_lines`)

#![cfg(feature = "multiline")]

use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{
    extract_dot_concatenation_for_test, extract_plus_concatenation_for_test,
    has_concatenation_indicators_for_test, preprocess_multiline, preprocess_multiline_for_test,
    MultilineConfig,
};

// ── POSITIVE: `+`-split credential reassembled across two source lines ────────

/// The canonical join: `token = "ghp_" +` continued by `"abcdef…"` on line two
/// reassembles into the whole `ghp_…` token, appended after the untouched
/// original two-line body. `original_end` stays the exact input byte length.
#[test]
fn plus_split_two_lines_reassembles_exact_appended_bytes() {
    let text = "token = \"ghp_\" +\n\"abcdef0123456789abcdef01\"";
    let (joined, original_end) = preprocess_multiline_for_test(text);
    assert_eq!(
        joined,
        format!("{text}\nghp_abcdef0123456789abcdef01"),
        "the two `+`-joined fragments must reassemble into one appended candidate"
    );
    assert_eq!(
        original_end,
        text.len(),
        "original_end must equal the exact input byte length on the join path"
    );
    assert!(
        joined.starts_with(text),
        "the original bytes must be carried through verbatim before the append"
    );
}

/// The `+` extractor on the FIRST line of a split reports the leading literal
/// value AND `continues == true` (the trailing join `+`), which is what makes
/// the chain walker pull the next line.
#[test]
fn plus_extractor_reports_continuation_on_trailing_operator() {
    assert_eq!(
        extract_plus_concatenation_for_test("token = \"ghp_\" +"),
        Some(("ghp_".to_string(), true)),
        "a trailing join `+` yields the partial value and continues == true"
    );
}

/// Two quoted literals joined on ONE line with `+` reassemble to the whole key
/// with `continues == false` (no trailing operator, the chain ends here).
#[test]
fn plus_extractor_two_literal_join_single_line() {
    assert_eq!(
        extract_plus_concatenation_for_test("x = \"AKIA\" + \"IOSFODNN7EXAMPLE\""),
        Some(("AKIAIOSFODNN7EXAMPLE".to_string(), false)),
    );
}

// ── POSITIVE: PHP/Perl `.`-operator join ─────────────────────────────────────

/// PHP `.`-concatenation of two quoted literals reassembles to the whole value,
/// `continues == false`.
#[test]
fn dot_extractor_php_two_literal_join_single_line() {
    assert_eq!(
        extract_dot_concatenation_for_test("$t = \"ghp_\" . \"abcdef012345\""),
        Some(("ghp_abcdef012345".to_string(), false)),
    );
}

/// A trailing join `.` continuation (`$t = "ghp_" .` continued next line) yields
/// the partial literal and `continues == true`.
#[test]
fn dot_extractor_trailing_operator_continues() {
    assert_eq!(
        extract_dot_concatenation_for_test("$t = \"ghp_\" ."),
        Some(("ghp_".to_string(), true)),
    );
}

// ── NEGATIVE TWIN: shapes that must NOT be falsely joined ─────────────────────

/// Plain two-line prose trips NO concatenation indicator, so the preprocessor
/// passes it through byte-identically with nothing appended.
#[test]
fn plain_two_line_prose_is_not_falsely_joined() {
    let prose = "This is a normal paragraph\nwith no secret content here";
    assert!(
        !has_concatenation_indicators_for_test(prose),
        "prose must not register as a concatenation candidate"
    );
    let (joined, original_end) = preprocess_multiline_for_test(prose);
    assert_eq!(
        joined, prose,
        "prose must be carried through with no appended candidate"
    );
    assert_eq!(original_end, prose.len());
}

/// Adversarial: a base64 value whose alphabet contains `+` INSIDE a single
/// quoted literal (no join `+` outside quotes) must NOT be split — the `+` is
/// value bytes, not a join operator, so no candidate is synthesized.
#[test]
fn base64_plus_inside_quoted_literal_is_not_split() {
    assert_eq!(
        extract_plus_concatenation_for_test("x = \"aGVsbG8+d29ybGQ=\""),
        None,
        "a `+` inside a base64 literal is value bytes, not a join operator"
    );
}

/// Negative twin: an unquoted arithmetic `+` between two identifiers is not a
/// string-literal join (the structural resolver, not this extractor, owns
/// variable-reference joins), so the `+` extractor returns None.
#[test]
fn unquoted_arithmetic_plus_is_not_a_string_join() {
    assert_eq!(
        extract_plus_concatenation_for_test("total = count + amount"),
        None,
    );
}

/// Negative twin: a `.` that is member access (`arr["k"].length`) has a
/// non-quoted identifier on the right of the join, so no two quoted literals
/// contribute and the `.` extractor returns None.
#[test]
fn dot_member_access_is_not_a_string_join() {
    assert_eq!(
        extract_dot_concatenation_for_test("y = arr[\"k\"].length"),
        None,
    );
}

/// Negative twin: a single quoted value that merely CONTAINS `.` bytes
/// (`"api.example.com"`) is one literal, not a two-literal join, so it is never
/// reassembled into a synthetic candidate.
#[test]
fn dot_inside_single_quoted_literal_is_not_joined() {
    assert_eq!(
        extract_dot_concatenation_for_test("msg = \"api.example.com\""),
        None,
    );
}

// ── has_concatenation_indicators gate: positive + JSON negative ───────────────

/// The indicator gate is TRUE for a real `+`-split body and FALSE for a JSON
/// object body (its first non-space byte `{` short-circuits the scan), so a
/// JSON-embedded secret is never fed through the join reassembler.
#[test]
fn indicator_gate_true_for_plus_split_false_for_json() {
    assert!(has_concatenation_indicators_for_test(
        "api_key = \"AK\" +\n\"IAIOSFODNN7EXAMPLE\""
    ));
    assert!(!has_concatenation_indicators_for_test(
        "{\n  \"api_key\": \"AKIAIOSFODNN7EXAMPLE\"\n}"
    ));
}

// ── BOUNDARY: the `max_join_lines` join window ───────────────────────────────

/// Text used by the join-window boundary tests: three `+`-joined literals that,
/// fully reassembled, spell `AKIAIOSFODNN7EXAMPLE`. The assignment name `k` is
/// deliberately NOT credential-like, so the structural reassembler contributes
/// nothing and the join window is the only variable.
const WINDOW_TEXT: &str = "k = \"AKIA\" +\n\"IOSF\" +\n\"ODNN7EXAMPLE\"";

fn preprocess_with_window(text: &str, max_join_lines: usize) -> (String, usize) {
    let config = MultilineConfig {
        max_join_lines,
        ..MultilineConfig::default()
    };
    let cache = FragmentCache::new(64);
    let pre = preprocess_multiline(text, &config, &cache);
    let out: &str = &pre.text;
    (out.to_string(), pre.original_end)
}

/// Inside the window (limit 3 for a 3-fragment chain) the whole key reassembles:
/// the appended candidate is exactly `AKIAIOSFODNN7EXAMPLE`.
#[test]
fn join_window_within_limit_reassembles_full_key() {
    let (out, original_end) = preprocess_with_window(WINDOW_TEXT, 3);
    assert_eq!(
        out,
        format!("{WINDOW_TEXT}\nAKIAIOSFODNN7EXAMPLE"),
        "a chain that fits the window reassembles the whole key"
    );
    assert_eq!(original_end, WINDOW_TEXT.len());
    assert!(out.contains("AKIAIOSFODNN7EXAMPLE"));
}

/// One line past the window (limit 2 for a 3-fragment chain) the join stops at
/// the window edge: only `AKIAIOSF` is reassembled, and the full-key token
/// `AKIAIOSFODNN7EXAMPLE` NEVER appears.
#[test]
fn join_window_past_limit_truncates_the_join() {
    let (out, original_end) = preprocess_with_window(WINDOW_TEXT, 2);
    assert_eq!(
        original_end,
        WINDOW_TEXT.len(),
        "original_end is unaffected by where the join window cuts"
    );
    assert!(
        out.contains("AKIAIOSF"),
        "the two fragments inside the window still reassemble: {out:?}"
    );
    assert!(
        !out.contains("AKIAIOSFODNN7EXAMPLE"),
        "the third fragment is past the window and must not join: {out:?}"
    );
}

/// A window of 1 disables joining outright: a two-line `+`-split leaves the
/// leading fragment and its continuation on separate lines, so the combined
/// token `ghp_BODYBODYBODY01` is never synthesized.
#[test]
fn join_window_of_one_disables_joining() {
    let text = "token = \"ghp_\" +\n\"BODYBODYBODY01\"";
    let (out, original_end) = preprocess_with_window(text, 1);
    assert_eq!(original_end, text.len());
    assert!(
        !out.contains("ghp_BODYBODYBODY01"),
        "a join window of 1 must not reassemble across the continuation: {out:?}"
    );
    assert!(
        out.starts_with(text),
        "the original two-line body is still carried through verbatim"
    );
}
