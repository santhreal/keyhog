//! Top-10 detector oracle: `npm-access-token` true positive MUST fire.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

#[test]
fn top10_npm_access_token_true_positive_evaded_must_stay_silent() {
    assert_detector_silent("npm-access-token", r"npm_000000000000000000000000000000000000");
}
