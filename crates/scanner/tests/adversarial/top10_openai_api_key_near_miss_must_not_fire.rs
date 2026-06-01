//! Top-10 detector oracle: `openai-api-key` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top10_openai_api_key_near_miss_must_not_fire() {
    assert_detector_silent("openai-api-key", r"sk-too-short");
}
