//! Governance guard: operator-internal planning artifacts must stay OUT of the
//! public repo.
//!
//! `docs/EXECUTION_PLAN.md` was the single internal planning doc. It leaked
//! operator machine paths across its history and was purged from the public
//! `santhsecurity/keyhog` repo (authorized governance action; the pre-push
//! audit hook refuses it). This guard fails loudly if it, or any other retired
//! planning artifact, is reintroduced by a stray `git add`, so the leak cannot
//! silently return. The plan's prose strategy lives only in the private Santh
//! monorepo backup; the behaviors it once tracked are covered by real
//! behavior/contract tests, not by asserting an internal doc's structure.

use std::path::PathBuf;

#[test]
fn internal_planning_artifacts_stay_out_of_public_repo() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root");
    for retired in [
        // Purged for the operator-machine-path leak; must never re-enter.
        "docs/EXECUTION_PLAN.md",
        "GAP_FINDINGS.toml",
        "docs/legendary",
        "docs/ALL_VECTORS_GAPS.md",
        "docs/GPU_DETECTION_REWRITE.md",
        "docs/GPU_OOM_INNOVATION_CATALOG.md",
        "benchmarks/docs/RECALL_GAP.md",
        "BACKLOG.md",
        "planning/vyre-acceleration",
    ] {
        assert!(
            !repo.join(retired).exists(),
            "operator-internal planning artifact must stay absent from the public repo: {retired}"
        );
    }
}
