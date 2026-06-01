//! KH-GAP-126 FP twin: repetitive-mask generic-password must not surface.

use super::oracle_support::assert_detector_silent;

#[test]
fn generic_password_repetitive_mask_suppressed_in_pipeline() {
    assert_detector_silent("generic-password", "password=xxxxxxxxxxxxxxxxxxxx");
}
