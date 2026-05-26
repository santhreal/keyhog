//! LR2-A8 harness integration: FILE_GATE_MATRIX audit artifact

#[test]
fn file_gate_matrix_toml_exists() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let p = repo.join("tests/FILE_GATE_MATRIX.toml");
    assert!(p.is_file(), "FILE_GATE_MATRIX.toml must exist at repo root tests/");
}
