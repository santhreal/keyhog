//! Top-10 detector oracle: `sendgrid-api-key` true positive MUST fire.

use super::oracle_support::assert_detector_fires;

#[test]
fn top10_sendgrid_api_key_true_positive_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        r"SG.0000000000000000000000.0000000000000000000000000000000000000000000",
        "SG.0000000000000000000000.0000000000000000000000000000000000000000000",
    );
}
