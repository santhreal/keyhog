//! Top-10 detector oracle: `npm-access-token` true positive MUST fire.

use super::oracle_support::assert_detector_fires;

#[test]
fn top10_npm_access_token_true_positive_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        r"npm_000000000000000000000000000000000000",
        "npm_000000000000000000000000000000000000",
    );
}
