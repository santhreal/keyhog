//! R5-T-SCAN reversed near-miss must not fire.

#[path = "../oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn reverse_near_miss_reversed_stays_silent() {
    let reversed: String = "TROHSXXXXAIKA".chars().rev().collect();
    assert_detector_silent("aws-access-key", &format!("payload={reversed}"));
}
