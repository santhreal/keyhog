//! Top-10 detector oracle: `github-classic-pat` true positive MUST fire.

use super::oracle_support::assert_detector_fires;

#[test]
fn top10_github_classic_pat_true_positive_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        r"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",
        "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",
    );
}
