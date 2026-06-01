//! Top-10 detector oracle: `aws-access-key` true positive MUST fire.

use super::oracle_support::assert_detector_fires;

#[test]
fn top10_aws_access_key_true_positive_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        r"AKIA0000000000000000",
        "AKIA0000000000000000",
    );
}
