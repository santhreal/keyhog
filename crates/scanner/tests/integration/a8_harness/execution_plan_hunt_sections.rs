//! LR2-A8 harness integration: execution plan has concrete issue hunts.

#[test]
fn execution_plan_has_concrete_hunt_sections() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let raw = std::fs::read_to_string(repo.join("docs/EXECUTION_PLAN.md")).expect("plan");
    let n = raw.matches("\n### H").count();
    assert!(
        n >= 7,
        "execution plan must list the concrete issue hunt sections, got {n}"
    );
}
