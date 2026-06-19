//! The execution plan must include the issue hunt matrix that replaced the
//! old waived-findings registry.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn execution_plan_has_issue_hunt_inventory() {
    let raw = std::fs::read_to_string(repo_root().join("docs/EXECUTION_PLAN.md"))
        .expect("execution plan");
    assert!(
        raw.contains("## Current Issue Hunt Inventory"),
        "execution plan must carry the current issue hunt inventory"
    );
    for id in ["H1", "H2", "H3", "H4", "H5", "H6", "H7"] {
        assert!(raw.contains(&format!("### {id} -")), "missing hunt {id}");
    }
}
