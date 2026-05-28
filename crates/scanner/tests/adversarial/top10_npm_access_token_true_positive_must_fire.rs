//! Top-10 detector oracle: `npm-access-token` true positive MUST fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_fires;

#[test]
fn top10_npm_access_token_true_positive_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        r"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",
        "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",
    );
}
