//! Top-10 detector oracle: `openai-api-key` true positive MUST fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_fires;

#[test]
fn top10_openai_api_key_true_positive_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        r"sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}
