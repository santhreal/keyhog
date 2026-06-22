#[test]
fn multiline_join_window_uses_processed_line_count() {
    let config = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/multiline/config.rs"
    ))
    .expect("multiline config readable");
    let preprocessor = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/multiline/preprocessor.rs"
    ))
    .expect("multiline preprocessor readable");

    assert!(config.contains("const DEFAULT_MAX_JOIN_LINES: usize = 64;"));
    assert!(config.contains("max_join_lines: DEFAULT_MAX_JOIN_LINES"));
    assert!(preprocessor.contains("let mut lines_consumed = 0usize;"));
    assert!(preprocessor.contains("while current_idx < lines.len() && lines_consumed < join_limit"));
    assert!(
        !preprocessor.contains("let lines_consumed = (current_idx - start_idx) + 1;"),
        "join-window boundary must not count the next unprocessed line as consumed"
    );
}
