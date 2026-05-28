//! LR2-A8 harness integration: matrix row count after R5-REV-STD split-module rows.

#[test]
fn file_gate_matrix_has_expected_rows() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let raw = std::fs::read_to_string(repo.join("tests/FILE_GATE_MATRIX.toml")).expect("matrix");
    let rows = raw.lines().filter(|l| l.starts_with("[[module]]")).count();
    assert_eq!(rows, 229, "expected 229 module rows after R5-REV-STD, got {rows}");
}
