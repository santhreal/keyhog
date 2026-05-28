//! Top-10 detector oracle: `google-api-key` true positive MUST fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_fires;

#[test]
fn top10_google_api_key_true_positive_must_fire() {
    assert_detector_fires(
        "google-api-key",
        r"AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}
