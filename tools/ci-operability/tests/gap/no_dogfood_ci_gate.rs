//! KH-GAP-131: STANDARD dogfood (§596) + TESTING_PROGRAM §4 require real-product CI exercise.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

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
