//! Top-10 detector oracle: `aws-access-key` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top10_aws_access_key_near_miss_must_not_fire() {
    assert_detector_silent("aws-access-key", r"AKIA tag in a sentence with spaces");
}
