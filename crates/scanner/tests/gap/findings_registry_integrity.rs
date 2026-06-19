//! Validates the single internal planning contract.

use std::path::PathBuf;

#[test]
fn only_execution_plan_is_the_internal_plan() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root");
    assert!(
        repo.join("docs/EXECUTION_PLAN.md").is_file(),
        "docs/EXECUTION_PLAN.md is the single internal plan"
    );
    for retired in [
        "GAP_FINDINGS.toml",
        "docs/legendary",
        "docs/ALL_VECTORS_GAPS.md",
        "docs/GPU_DETECTION_REWRITE.md",
        "docs/GPU_OOM_INNOVATION_CATALOG.md",
        "benchmarks/docs/RECALL_GAP.md",
    ] {
        assert!(
            !repo.join(retired).exists(),
            "retired planning artifact must stay absent: {retired}"
        );
    }
}
