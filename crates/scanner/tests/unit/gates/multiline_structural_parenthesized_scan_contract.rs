#[test]
fn unclosed_parenthesized_implicit_blocks_advance_past_scanned_window() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/multiline/structural.rs"
    ))
    .expect("multiline structural source readable");

    let collector = source
        .split("fn collect_parenthesized_implicit_blocks")
        .nth(1)
        .expect("parenthesized implicit collector present")
        .split("fn quoted_literal_line")
        .next()
        .expect("collector boundary present");

    assert!(source.contains("const PARENTHESIZED_IMPLICIT_SCAN_LINES: usize = 16;"));
    assert!(collector.contains("let mut closed_at = None;"));
    assert!(collector.contains("index = close_index + 1;"));
    assert!(
        collector.contains("index = cursor.max(index + 1);"),
        "failed parenthesized candidates must advance to the already-scanned cursor, not rescan the window one line later"
    );
    assert!(
        !collector.contains("while cursor < lines.len() && cursor.saturating_sub(index) <= 16"),
        "scan window must be named, not buried as an inline threshold"
    );
    assert!(
        !collector.contains("} else {\n            index += 1;\n        }"),
        "unclosed or malformed parenthesized candidates must not advance by one after scanning a bounded window"
    );
}
