//! Top-10 detector oracle: `slack-bot-token` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top10_slack_bot_token_near_miss_must_not_fire() {
    assert_detector_silent("slack-bot-token", r"xoxb-12345");
}
