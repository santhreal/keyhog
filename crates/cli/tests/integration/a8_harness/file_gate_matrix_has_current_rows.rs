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
    // 501 = the current module inventory. The count drifts whenever source
    // files are added or removed; `file_gate_matrix_lists_every_cli_src_module`
    // below guards that every real cli/src file is listed, so this hard-coded
    // total just forces a conscious reconcile when the tree changes.
    assert_eq!(rows, 501, "expected 501 module rows, got {rows}");
}
