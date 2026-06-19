//! KH-GAP-078: PR gate must run all 14 strict runners (TESTING_PROGRAM §3.1).

use std::path::PathBuf;

const FOURTEEN_RUNNERS: [&str; 14] = [
    "contracts_runner",
    "adversarial_explosion_runner",
    "encoding_explosion_runner",
    "path_shape_runner",
    "noise_injection_runner",
    "unicode_confusable_runner",
    "whitespace_normalization_runner",
    "line_length_runner",
    "entropy_edge_runner",
    "compound_encoding_runner",
    "multi_secret_runner",
    "comment_embed_runner",
    "companion_contracts_runner",
    "cve_replay_runner",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn read_workflow(name: &str) -> String {
    std::fs::read_to_string(repo_root().join(".github/workflows").join(name))
        .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

#[test]
fn pr_ci_runs_all_fourteen_strict_runners() {
    let ci = read_workflow("ci.yml");
    let strict_block = ci
        .split("strict-runners:")
        .nth(1)
        .and_then(|rest| rest.split("\n  test:").next())
        .expect("ci.yml must define strict-runners job before test job");

    let missing: Vec<&str> = FOURTEEN_RUNNERS
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
