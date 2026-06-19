//! LR2-A8 harness integration: no duplicate execution-plan hunt ids.

#[test]
fn execution_plan_hunt_ids_unique() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let raw = std::fs::read_to_string(repo.join("docs/EXECUTION_PLAN.md")).expect("plan");
    let mut ids = Vec::new();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("### H") {
            let id = rest
                .split_whitespace()
                .next()
                .expect("hunt id")
                .trim_end_matches(':');
            ids.push(format!("H{id}"));
        }
    }
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(ids.len(), sorted.len(), "duplicate execution-plan hunt ids");
}
