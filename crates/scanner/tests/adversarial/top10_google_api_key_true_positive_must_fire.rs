//! Top-10 detector oracle: `google-api-key` true positive MUST fire.

use super::oracle_support::assert_detector_fires;

#[test]
fn top10_google_api_key_true_positive_must_fire() {
    assert_detector_fires(
        "google-api-key",
        r"AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5P6q",
        "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5P6q",
    );
}
