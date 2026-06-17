//! KH-GAP-115: FILE_GATE_MATRIX must mark sources+verifier adversarial coverage.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn file_gate_matrix_sources_verifier_rows_mark_adversarial_coverage() {
    let raw = std::fs::read_to_string(repo_root().join("tests/FILE_GATE_MATRIX.toml"))
        .expect("FILE_GATE_MATRIX.toml");
    let mut current = None;
    let mut unmarked = Vec::new();
    for line in raw.lines() {
        if let Some(path) = line
            .strip_prefix("path = \"")
            .and_then(|p| p.strip_suffix('"'))
        {
            current = Some(path.to_string());
        }
        if line.trim() == "adversarial = false" {
            if let Some(path) = &current {
                if path.starts_with("crates/sources/") || path.starts_with("crates/verifier/") {
                    unmarked.push(path.clone());
                }
            }
        }
    }
    assert!(
        unmarked.is_empty(),
        "sources+verifier matrix rows must mark adversarial=true when suites exist; unmarked={unmarked:?}"
    );
}
