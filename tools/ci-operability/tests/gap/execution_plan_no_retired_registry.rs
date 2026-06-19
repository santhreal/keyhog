//! Retired planning registries must stay absent from the standalone CI tool.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn retired_gap_registry_and_coordination_claims_stay_absent() {
    let root = repo_root();
    for retired in [
        "GAP_FINDINGS.toml",
        "coordination",
        "backlog",
        "audits",
        "docs/legendary",
        "docs/ALL_VECTORS_GAPS.md",
        "docs/GPU_DETECTION_REWRITE.md",
        "benchmarks/docs/RECALL_GAP.md",
    ] {
        assert!(
            !root.join(retired).exists(),
            "retired planning artifact must stay absent: {retired}"
        );
    }
}
