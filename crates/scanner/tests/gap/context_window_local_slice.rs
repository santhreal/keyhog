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
