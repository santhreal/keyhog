//! KH-GAP-177: FILE_GATE_MATRIX must mark core error + adversarial coverage.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn file_gate_matrix_core_rows_mark_error_and_adversarial_coverage() {
    let raw = std::fs::read_to_string(repo_root().join("tests/FILE_GATE_MATRIX.toml"))
        .expect("FILE_GATE_MATRIX.toml");
    let mut current = None;
    let mut unmarked = Vec::new();
    for line in raw.lines() {
        if let Some(path) = line.strip_prefix("path = \"").and_then(|p| p.strip_suffix('"')) {
            current = Some(path.to_string());
        }
        if let Some(path) = &current {
            if !path.starts_with("crates/core/") {
                continue;
            }
            if line.trim() == "error = false" || line.trim() == "adversarial = false" {
                unmarked.push((path.clone(), line.trim().to_string()));
            }
        }
    }
    assert!(
        unmarked.is_empty(),
        "core matrix rows must mark error/adversarial=true when suites exist; unmarked={unmarked:?}"
    );
}
