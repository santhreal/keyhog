//! Top-10 detector oracle: `sendgrid-api-key` true positive MUST fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_fires;

#[test]
fn top10_sendgrid_api_key_true_positive_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        r"SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aB",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aB",
    );
}
