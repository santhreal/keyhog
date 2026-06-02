//! KH-GAP-077: runners-nightly.yml lists all 14 contract multipliers.

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

#[test]
fn runners_nightly_lists_fourteen_test_binaries() {
    let text = std::fs::read_to_string(repo_root().join(".github/workflows/runners-nightly.yml"))
        .expect("read runners-nightly.yml");

    let missing: Vec<&str> = FOURTEEN_RUNNERS
        .iter()
        .copied()
        .filter(|r| !text.contains(&format!("--test {r}")))
        .collect();

    assert!(
        missing.is_empty(),
        "runners-nightly.yml must list all 14 runners; missing: {missing:?}"
    );
}
