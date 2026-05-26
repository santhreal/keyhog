//! Validates GAP_FINDINGS.toml registry: every open finding has a test file on disk.

use std::path::PathBuf;

#[test]
fn gap_findings_registry_matches_test_files() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root");
    let registry = repo.join("GAP_FINDINGS.toml");
    let raw = std::fs::read_to_string(&registry).expect("GAP_FINDINGS.toml readable");

    let mut ids = Vec::new();
    let mut tests = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("id = ") {
            ids.push(rest.trim_matches('"').to_string());
        }
        if let Some(rest) = line.strip_prefix("test = ") {
            tests.push(rest.trim_matches('"').to_string());
        }
    }
    assert_eq!(
        ids.len(),
        tests.len(),
        "each finding must have id + test path"
    );

    for (id, test_path) in ids.iter().zip(tests.iter()) {
        let path = repo.join(test_path);
        assert!(
            path.is_file(),
            "{id}: registered test missing at {}",
            path.display()
        );
    }
}
