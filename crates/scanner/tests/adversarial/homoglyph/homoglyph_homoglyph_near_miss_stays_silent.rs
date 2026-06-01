//! R5-T-SCAN homoglyph near-miss must not fire.

use crate::adversarial::oracle_support::assert_detector_silent;

#[test]
fn homoglyph_homoglyph_near_miss_stays_silent() {
    assert_detector_silent("aws-access-key", "export KEY=\"AKIAXXXXSHORT\"");
}
