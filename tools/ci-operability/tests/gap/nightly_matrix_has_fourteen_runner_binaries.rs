//! KH-GAP-077: runners-nightly.yml lists all 14 contract multipliers.

use super::support::{read_workflow, STRICT_RUNNERS};

#[test]
fn runners_nightly_lists_fourteen_test_binaries() {
    let text = read_workflow("runners-nightly.yml");

    let missing: Vec<&str> = STRICT_RUNNERS
        .iter()
        .copied()
        .filter(|r| !text.contains(&format!("--test {r}")))
        .collect();

    assert!(
        missing.is_empty(),
        "runners-nightly.yml must list all 14 runners; missing: {missing:?}"
    );
}
