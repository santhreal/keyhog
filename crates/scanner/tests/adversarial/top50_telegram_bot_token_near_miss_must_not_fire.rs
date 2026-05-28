//! Top-50 detector oracle: `telegram-bot-token` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_telegram_bot_token_near_miss_must_not_fire() {
    assert_detector_silent("telegram-bot-token", "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
