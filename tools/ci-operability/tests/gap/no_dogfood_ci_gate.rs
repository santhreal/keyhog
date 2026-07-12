//! KH-GAP-131: STANDARD dogfood requires real-product CI exercise.

use super::support::repo_root;

#[test]
fn ci_workflows_include_dogfood_scan_gate() {
    let workflows = repo_root().join(".github/workflows");
    let mut combined = String::new();
    for entry in std::fs::read_dir(&workflows).expect("workflows dir") {
        let entry = entry.expect("dir entry");
        if entry.path().extension().is_some_and(|e| e == "yml") {
            combined.push_str(&std::fs::read_to_string(entry.path()).expect("workflow"));
            combined.push('\n');
        }
    }
    assert!(
        combined.contains("--dogfood"),
        "STANDARD dogfood requires CI to run `keyhog scan --dogfood` (or equivalent persona gate)"
    );
}
