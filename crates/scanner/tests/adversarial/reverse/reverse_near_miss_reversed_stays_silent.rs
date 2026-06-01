//! R5-T-SCAN reversed near-miss must not fire.

use crate::adversarial::oracle_support::assert_detector_silent;

#[test]
fn reverse_near_miss_reversed_stays_silent() {
    let reversed: String = "TROHSXXXXAIKA".chars().rev().collect();
    assert_detector_silent("aws-access-key", &format!("payload={reversed}"));
}
