use keyhog_scanner::testing::local_context_window;

// Regression: a line with no `\n` for hundreds of KiB (a minified bundle, or
// a file that is one long run of credential-shaped tokens) must NOT return the
// whole line. An uncapped per-match context window made the per-candidate ML
// feature / FP keyword scan O(line_len), turning a many-match scan quadratic
// (a 164 KiB single-line file with 8 K matches took ~18 s before the cap).
// The window is byte-capped, so a match anywhere on a giant line yields at
// most ~8 KiB of context. (Short lines hit their newline first and are
// returned whole, covered by `local_context_window_single_line`.)
#[test]
fn long_no_newline_line_is_byte_capped() {
    let text = "x".repeat(512 * 1024); // 512 KiB, zero newlines
    let window = local_context_window(&text, 1, 1);
    assert!(
        window.len() <= 8 * 1024,
        "local_context_window must byte-cap a no-newline line to <= 8 KiB; got {}",
        window.len()
    );
}
