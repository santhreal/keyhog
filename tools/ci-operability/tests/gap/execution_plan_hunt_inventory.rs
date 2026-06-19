//! The execution plan is the only internal issue inventory.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn execution_plan_carries_current_hunt_inventory() {
    let raw = std::fs::read_to_string(repo_root().join("docs/EXECUTION_PLAN.md"))
        .expect("execution plan");
    assert!(
        raw.contains("## Current Issue Hunt Inventory"),
        "execution plan must carry the current issue hunt inventory"
    );
    for id in ["H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8"] {
        assert!(raw.contains(&format!("### {id} -")), "missing hunt {id}");
    }
    assert!(
        raw.contains("GAP_FINDINGS.toml       -> delete"),
        "execution plan must document the retired gap registry contract"
    );
}
