#[test]
fn backend_triggered_reuses_prepared_line_offsets_for_code_lines() {
    let backend_triggered = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/backend_triggered.rs"
    ))
    .expect("backend_triggered.rs readable");
    let backend_prepared = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/backend_prepared.rs"
    ))
    .expect("backend_prepared.rs readable");

    assert!(
        backend_triggered.matches("prepared.code_lines(line_offsets)").count() >= 2,
        "scan_prepared_with_triggered and debug_scan_phase2_only must reuse PreparedChunk line offsets for code-line splitting"
    );
    assert!(
        !backend_triggered.contains("prepared.chunk.data.lines().collect()"),
        "backend_triggered.rs must not rescan chunk data for code lines after line_offsets() already walked the same bytes"
    );
    assert!(
        backend_prepared.contains("fn code_lines_from_offsets")
            && backend_prepared.contains("line.as_bytes().last() == Some(&b'\\r')")
            && backend_prepared.contains("self.preprocessed.text.as_bytes() == self.chunk.data.as_bytes()"),
        "PreparedChunk must own the byte-identical fast path and preserve str::lines() CRLF semantics"
    );
}
