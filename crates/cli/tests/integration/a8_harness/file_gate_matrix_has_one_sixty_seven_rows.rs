//! LR2-A8 harness integration: matrix row count from LR1-A8

#[test]
fn file_gate_matrix_has_expected_rows() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let raw = std::fs::read_to_string(repo.join("tests/FILE_GATE_MATRIX.toml")).expect("matrix");
    let rows = raw.lines().filter(|l| l.starts_with("[[module]]")).count();
    assert!(rows >= 167, "expected >=167 module rows, got {rows}");
}
