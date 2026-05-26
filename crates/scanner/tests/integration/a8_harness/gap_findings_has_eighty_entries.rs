//! LR2-A8 harness integration: deduplicated registry size

#[test]
fn gap_findings_registry_has_at_least_eighty_findings() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let raw = std::fs::read_to_string(repo.join("GAP_FINDINGS.toml")).expect("registry");
    let n = raw.matches("[[finding]]").count();
    assert!(
        n >= 80,
        "LR2-A8 registry must list >=80 deduplicated findings, got {n}"
    );
}
