//! KH-GAP-078: PR gate must run all 14 strict runners.

use super::support::{read_workflow, STRICT_RUNNERS};

#[test]
fn pr_ci_runs_all_fourteen_strict_runners() {
    let ci = read_workflow("ci.yml");
    let strict_block = ci
        .split("strict-runners:")
        .nth(1)
        .and_then(|rest| rest.split("\n  test:").next())
        .expect("ci.yml must define strict-runners job before test job");

    let missing: Vec<&str> = STRICT_RUNNERS
        .iter()
        .copied()
        .filter(|runner| !strict_block.contains(&format!("--test {runner}")))
        .collect();

    assert!(
        missing.is_empty(),
        "ci.yml strict-runners must invoke all 14 runners on PR; missing: {missing:?}. \
         Nightly-only coverage leaves runners ungated on every push (KH-GAP-078)."
    );
}
