//! FILE_GATE_MATRIX row-count contract for the current module inventory.

#[test]
fn file_gate_matrix_has_current_rows() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let raw = std::fs::read_to_string(repo.join("tests/FILE_GATE_MATRIX.toml")).expect("matrix");
    let rows = raw.lines().filter(|l| l.starts_with("[[module]]")).count();
    assert_eq!(rows, 336, "expected 336 module rows, got {rows}");
}
