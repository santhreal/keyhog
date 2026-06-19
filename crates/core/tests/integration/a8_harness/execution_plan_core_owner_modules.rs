//! LR2-A8 harness integration: single execution plan registered core hygiene.

#[test]
fn execution_plan_references_single_owner_modules() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let raw = std::fs::read_to_string(repo.join("docs/EXECUTION_PLAN.md")).expect("plan");
    assert!(raw.contains("Every module boundary has one owner"));
    assert!(raw.contains("Target core crate layout"));
}
