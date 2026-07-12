//! Gap test: the per-finding context-window slicer (`local_context_window`).
//!
//! For each match the ML/keyword features need the few lines around it. This
//! slicer borrows that `[line - radius, line + radius]` window straight out of
//! the source buffer (1-based `line`) with a `memchr` newline walk — no
//! `Vec<&str>` collect, no `join`. Pin the exact byte slice across three
//! shapes: a centred window, a single bare line (radius 0), and a window whose
//! lower bound is clamped to the file start. The trailing newline of the last
//! window line is excluded; interior newlines are kept so neighbours stay
//! `\n`-joined.
//!
//! The slicer is portable (no feature gate), so neither is this test.

use keyhog_scanner::testing::local_context_window_for_test as window;

const FIVE_LINES: &str = "aaa\nbbb\nccc\nddd\neee";

#[test]
fn centred_window_radius_one_keeps_neighbours_newline_joined() {
    // Line 3 = "ccc"; radius 1 pulls lines 2..=4, the final newline excluded.
    assert_eq!(window(FIVE_LINES, 3, 1), "bbb\nccc\nddd");
}

#[test]
fn radius_zero_returns_the_bare_line_without_a_newline() {
    assert_eq!(window(FIVE_LINES, 3, 0), "ccc");
}

#[test]
fn window_lower_bound_clamps_to_the_file_start() {
    // Line 1 with radius 1 cannot go before line 1, so the window is lines 1..=3.
    assert_eq!(window(FIVE_LINES, 1, 1), "aaa\nbbb\nccc");
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin three window shapes; these SWEEP the slicer's safety and
// exactness. It feeds every match's ML/keyword features, so a panic crashes the
// scan and a wrong slice mis-scores a candidate. No proptest covered it before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// The slicer must never panic on ANY input. Its 8 KiB byte-cap path can land
    /// mid-codepoint and is snapped by `floor_char_boundary`; this locks that
    /// guard. Sweeps arbitrary Unicode text (incl. newlines), line indices (0
    /// included — the 1-based API saturates), and radii.
    #[test]
    fn local_context_window_never_panics(
        text in "(?s).{0,200}",
        line in 0usize..20,
        radius in 0usize..10,
    ) {
        let _ = window(&text, line, radius);
    }

    /// The window is always a genuine SUBSTRING of the source buffer (it borrows a
    /// byte slice, never fabricates), so a caller can trust it came from `text`.
    #[test]
    fn window_is_always_a_substring_of_source(
        text in "(?s).{0,200}",
        line in 0usize..20,
        radius in 0usize..10,
    ) {
        let w = window(&text, line, radius);
        prop_assert!(text.contains(w.as_str()));
    }

    /// RADIUS 0 extracts EXACTLY the 1-based indexed `\n`-delimited line (no
    /// surrounding newlines) for short multi-line text well under the 8 KiB cap.
    /// Differential against the input line vector the text was joined from.
    #[test]
    fn radius_zero_extracts_exactly_the_indexed_line(
        lines in prop::collection::vec("[a-z ]{0,20}", 1..8),
        pick in 0usize..8,
    ) {
        let text = lines.join("\n");
        let li = pick % lines.len();
        let expected = lines[li].clone();
        prop_assert_eq!(window(&text, li + 1, 0), expected);
    }
}
