//! Retired planning registries must stay absent from the standalone CI tool.

use super::support::repo_root;
use std::process::Command;

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
        // The invariant is that retired planning registries never come back INTO
        // THE REPO, assert they are not git-TRACKED, not merely absent from the
        // working tree. A gitignored local scratch copy (e.g. an agent's
        // `coordination/` work log) is not a repo artifact and must not trip this.
        let out = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["ls-files", "--", retired])
            .output()
            .expect("git ls-files must run");
        assert!(
            out.stdout.is_empty(),
            "retired planning artifact must stay absent from the committed repo: {retired}"
        );
    }
}
