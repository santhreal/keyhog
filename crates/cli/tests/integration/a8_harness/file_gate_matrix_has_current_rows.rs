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
    let paths = raw.lines().filter(|l| l.starts_with("path = ")).count();
    assert_eq!(
        rows, paths,
        "every FILE_GATE_MATRIX path row must be inside an explicit [[module]] table"
    );
    // 423 = 421 baseline + the docker `metadata.rs` / `oci.rs` module rows that
    // were added to FILE_GATE_MATRIX.toml without bumping this contract count.
    assert_eq!(rows, 423, "expected 423 module rows, got {rows}");
}
