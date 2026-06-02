//! KH-GAP-179: every WAIVED row in GAP_FINDINGS.toml must carry waiver_expires.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn waived_findings_registry_has_expiry_fields() {
    let raw = std::fs::read_to_string(repo_root().join("GAP_FINDINGS.toml")).expect("registry");
    let mut missing = Vec::new();
    for block in raw.split("[[finding]]").skip(1) {
        let Some(id_line) = block.lines().find(|l| l.starts_with("id = \"")) else {
            continue;
        };
        let id = id_line
            .trim()
            .trim_start_matches("id = \"")
            .trim_end_matches('"');
        if !block.contains("status = \"waived\"") {
            continue;
        }
        if !block.contains("waiver_expires = \"") {
            missing.push(id.to_string());
        }
    }
    assert!(
        missing.is_empty(),
        "WAIVED findings must declare waiver_expires in registry: {missing:?}"
    );
}
