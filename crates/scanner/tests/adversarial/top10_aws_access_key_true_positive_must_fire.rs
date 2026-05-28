//! Top-10 detector oracle: `aws-access-key` true positive MUST fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_fires;

#[test]
fn top10_aws_access_key_true_positive_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        r"AKIAQYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}
