//! Regression coverage for scanner per-match context-window extraction.
//!
//! Two public surfaces are pinned here, both reachable from an integration
//! test through the crate's own re-exports:
//!
//!   * the byte-window slicer `keyhog_scanner::testing::local_context_window`
//!     (the test seam over `pipeline::local_context_window`) plus its line-
//!     offset helper `compute_line_offsets`, and
//!   * the structural classifier `keyhog_scanner::context::infer_context` with
//!     the `CodeContext` enum it returns.
//!
//! Every assertion is a concrete expected value (exact byte slice, exact
//! offset vector, exact enum variant, exact multiplier) derived by hand from
//! the source in `crates/scanner/src/pipeline/context_window.rs` and
//! `crates/scanner/src/context/`. No `is_empty()` / `is_some()`-only checks.

use keyhog_scanner::context::{infer_context, CodeContext};
use keyhog_scanner::testing::{compute_line_offsets, local_context_window};

/// Canonical five-line buffer with a trailing newline. Each `lineN` token is
/// exactly five bytes, so line starts fall on 0, 6, 12, 18, 24 and the final
/// `\n` sits at byte 29 (total length 30).
const FIVE_LINES: &str = "line0\nline1\nline2\nline3\nline4\n";

fn approx(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < 1e-12,
        "expected {expected}, got {actual}"
    );
}

// ── local_context_window: before/after byte window around a known offset ─────

#[test]
fn local_context_window_radius1_midfile_exact_slice() {
    // 1-based line 3 ("line2") with radius 1 -> lines 2,3,4. The slicer starts
    // just past the newline at byte 5 (start = 6) and excludes the trailing
    // newline of the last window line (byte 23), yielding text[6..23].
    let w = local_context_window(FIVE_LINES, 3, 1);
    assert_eq!(w, "line1\nline2\nline3");
    assert_eq!(w.len(), 17);
}

#[test]
fn local_context_window_radius0_bare_line_no_newline() {
    // radius 0 returns exactly the single 1-based line with no terminator.
    let w = local_context_window(FIVE_LINES, 3, 0);
    assert_eq!(w, "line2");
    assert_eq!(w.len(), 5);
}

#[test]
fn local_context_window_clamps_to_file_start() {
    // Line 1 with radius 1 would begin before line 1; `lines_before`
    // saturates to 0, so the window clamps to byte 0 and spans lines 1..3.
    let w = local_context_window(FIVE_LINES, 1, 1);
    assert_eq!(w, "line0\nline1\nline2");
    assert_eq!(w.len(), 17);
}

#[test]
fn local_context_window_truncates_at_end_keeps_trailing_newline() {
    // Line 5 ("line4") with radius 1 asks for lines 4,5,6 but only 5 lines
    // exist. The final window iteration hits the byte cap (== text length)
    // and breaks BEFORE stripping a terminator, so the trailing newline at
    // byte 29 is retained: text[18..30].
    let w = local_context_window(FIVE_LINES, 5, 1);
    assert_eq!(w, "line3\nline4\n");
    assert_eq!(w.len(), 12);
}

#[test]
fn local_context_window_line_beyond_file_returns_empty() {
    // Requesting line 10 (radius 0) needs 9 preceding newlines; the buffer has
    // only 5. The forward walk runs out of newlines and returns "", the
    // documented "fewer lines than the window asks for" branch.
    let w = local_context_window(FIVE_LINES, 10, 0);
    assert_eq!(w, "");
    assert_eq!(w.len(), 0);
}

#[test]
fn local_context_window_byte_cap_truncates_long_line() {
    // A single 10 000-byte line with no newline. MAX_WINDOW_BYTES is 8 KiB, so
    // the window is capped at exactly 8192 bytes even though radius 0 would
    // otherwise take the whole line.
    let long_line = "a".repeat(10_000);
    let w = local_context_window(&long_line, 1, 0);
    assert_eq!(w.len(), 8192);
    assert!(w.bytes().all(|b| b == b'a'));
}

#[test]
fn local_context_window_snaps_down_to_char_boundary_under_cap() {
    // 2731 three-byte '€' characters (8193 bytes total, no newline). The 8192
    // byte cap lands inside the 2731st codepoint (bytes 8190..8192), so the
    // engine's `floor_char_boundary` snaps the end down to 8190 -> exactly
    // 2730 whole '€' characters. The result must stay valid UTF-8.
    let euros = "\u{20AC}".repeat(2731);
    assert_eq!(euros.len(), 8193);
    let w = local_context_window(&euros, 1, 0);
    assert_eq!(w.len(), 8190);
    assert_eq!(w.chars().count(), 2730);
    assert!(w.chars().all(|c| c == '\u{20AC}'));
}

// ── compute_line_offsets: exact per-line byte starts ─────────────────────────

#[test]
fn compute_line_offsets_trailing_newline_exact() {
    // Offset 0 is always pushed, then one entry per '\n' at (pos + 1).
    let offsets = compute_line_offsets(FIVE_LINES);
    assert_eq!(offsets, vec![0, 6, 12, 18, 24, 30]);
}

#[test]
fn compute_line_offsets_no_trailing_newline_and_empty() {
    // "a\nbb\nccc": newlines at bytes 1 and 4 -> starts 0, 2, 5.
    assert_eq!(compute_line_offsets("a\nbb\nccc"), vec![0, 2, 5]);
    // Empty input still yields the single leading zero offset.
    assert_eq!(compute_line_offsets(""), vec![0]);
}

// ── infer_context: structural classification of the match line ───────────────

#[test]
fn infer_context_assignment_exact() {
    // `KEY = "value"`: a bare assignment. The assignment check precedes the
    // string-literal fallback, so this is Assignment, not StringLiteral.
    let lines = ["API_KEY = \"abc\""];
    assert_eq!(infer_context(&lines, 0, None), CodeContext::Assignment);
}

#[test]
fn infer_context_comment_vs_commented_assignment() {
    // A prose comment classifies as Comment.
    let prose = ["# just a note"];
    assert_eq!(infer_context(&prose, 0, None), CodeContext::Comment);

    // A comment whose body is itself an assignment is reclassified as
    // Assignment (the commented-assignment check runs before the plain
    // comment check), a credential hidden in a commented-out `KEY = val`
    // must not get the softer comment multiplier.
    let commented_assign = ["# API_KEY = secret"];
    assert_eq!(
        infer_context(&commented_assign, 0, None),
        CodeContext::Assignment
    );
}

#[test]
fn infer_context_string_literal_and_unknown() {
    // Quote present, no assignment operator -> StringLiteral.
    let quoted = ["call(\"x\")"];
    assert_eq!(infer_context(&quoted, 0, None), CodeContext::StringLiteral);

    // No quote, no assignment, no comment -> Unknown.
    let plain = ["plain text here"];
    assert_eq!(infer_context(&plain, 0, None), CodeContext::Unknown);
}

#[test]
fn infer_context_out_of_bounds_is_unknown() {
    // line_idx >= lines.len() short-circuits to Unknown (no panic).
    let lines = ["a", "b"];
    assert_eq!(infer_context(&lines, 5, None), CodeContext::Unknown);
}

#[test]
fn infer_context_test_file_path_overrides_assignment() {
    // `_test.go` is a Tier-B test-path suffix. The file-path test-file check
    // runs first, so even an assignment line classifies as TestCode.
    let lines = ["password = hunter2"];
    assert_eq!(
        infer_context(&lines, 0, Some("auth_test.go")),
        CodeContext::TestCode
    );
}

#[test]
fn infer_context_encrypted_block() {
    // An `$ANSIBLE_VAULT` marker within the 10-line lookback puts following
    // lines in an Encrypted block.
    let lines = ["$ANSIBLE_VAULT;1.1;AES256;env", "3132333435"];
    assert_eq!(infer_context(&lines, 1, None), CodeContext::Encrypted);
}

#[test]
fn infer_context_markdown_fence_is_documentation() {
    // Inside a ``` fenced block the assignment line is Documentation: the
    // documentation-flag check precedes the assignment check.
    let lines = ["```", "api_key = SECRETVALUE", "```"];
    assert_eq!(infer_context(&lines, 1, None), CodeContext::Documentation);
}

#[test]
fn infer_context_rust_test_attribute_marks_body_testcode() {
    // A `#[test]` attribute above a `fn` with an arbitrary name puts the body
    // line in TestCode via the attribute-block walk above the signature.
    let lines = [
        "#[test]",
        "fn scenario() {",
        "    let k = \"AKIAIOSFODNN7EXAMPLE\";",
        "}",
    ];
    assert_eq!(infer_context(&lines, 2, None), CodeContext::TestCode);
}

// ── CodeContext: exact confidence multipliers and hard-suppression bounds ────

#[test]
fn code_context_confidence_multipliers_exact() {
    approx(CodeContext::Assignment.confidence_multiplier(), 1.0);
    approx(CodeContext::StringLiteral.confidence_multiplier(), 0.9);
    approx(CodeContext::Unknown.confidence_multiplier(), 0.8);
    approx(CodeContext::Comment.confidence_multiplier(), 0.4);
    approx(CodeContext::Documentation.confidence_multiplier(), 0.3);
    approx(CodeContext::TestCode.confidence_multiplier(), 0.3);
    approx(CodeContext::Encrypted.confidence_multiplier(), 0.05);
}

#[test]
fn code_context_should_hard_suppress_boundaries() {
    // Documentation/TestCode/Comment hard-suppress strictly below 0.5.
    assert!(CodeContext::Documentation.should_hard_suppress(0.49));
    assert!(!CodeContext::Documentation.should_hard_suppress(0.5));
    assert!(CodeContext::TestCode.should_hard_suppress(0.0));
    assert!(!CodeContext::Comment.should_hard_suppress(0.5));

    // Encrypted hard-suppresses strictly below 0.8.
    assert!(CodeContext::Encrypted.should_hard_suppress(0.79));
    assert!(!CodeContext::Encrypted.should_hard_suppress(0.8));

    // Assignment / StringLiteral / Unknown never hard-suppress.
    assert!(!CodeContext::Assignment.should_hard_suppress(0.0));
    assert!(!CodeContext::StringLiteral.should_hard_suppress(0.0));
    assert!(!CodeContext::Unknown.should_hard_suppress(0.0));
}
