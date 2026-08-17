//! Prevent `.github/workflows/ci.yml` from naming deleted CLI test binaries.

use super::support::{read_workflow, repo_root};

/// Regression: every target in the fail-closed CLI lane must map to a compiled integration-test file.
#[test]
fn fail_closed_cli_lane_references_existing_test_targets() {
    let workflow = read_workflow("ci.yml");
    let lane_after = workflow
        .split("- name: Fail-closed security regressions")
        .nth(1)
        .expect("ci.yml must retain the fail-closed security regression lane");
    // The step ends at the next step or next job definition
    let lane = lane_after
        .split("\n\n")
        .next()
        .expect("fail-closed step block");
    let targets = lane
        .lines()
        .filter_map(|line| line.trim().strip_prefix("--test "))
        .collect::<Vec<_>>();

    assert!(
        !targets.is_empty(),
        "fail-closed security regression lane must execute explicit CLI test targets"
    );
    let cli_tests = repo_root().join("crates/cli/tests");
    let missing = targets
        .iter()
        .copied()
        .filter(|target| !cli_tests.join(format!("{target}.rs")).is_file())
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "ci.yml references CLI test targets with no crates/cli/tests/<target>.rs binary: {missing:?}"
    );
}
