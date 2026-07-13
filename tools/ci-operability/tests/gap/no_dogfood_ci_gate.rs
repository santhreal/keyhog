//! KH-GAP-131: STANDARD dogfood requires real-product CI exercise.

use super::support::repo_root;

#[test]
fn ci_workflows_include_dogfood_scan_gate() {
    let root = repo_root();
    let workflows = root.join(".github/workflows");
    let mut combined = String::new();
    for entry in std::fs::read_dir(&workflows).expect("workflows dir") {
        let entry = entry.expect("dir entry");
        if entry.path().extension().is_some_and(|e| e == "yml") {
            combined.push_str(&std::fs::read_to_string(entry.path()).expect("workflow"));
            combined.push('\n');
        }
    }
    let direct = combined.contains("--dogfood");
    let harness_path = root.join("tests/dogfood/repository_scan.sh");
    let harness = std::fs::read_to_string(&harness_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", harness_path.display()));
    let delegated = combined.contains("tests/dogfood/repository_scan.sh")
        && harness.contains(" scan . ")
        && harness.contains("--dogfood");

    assert!(direct || delegated, "STANDARD dogfood requires CI to run `keyhog scan --dogfood` directly or through the owned repository-scan harness");
}
