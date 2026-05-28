//! Top-50 chunk-boundary oracle: `telegram-bot-token` near-miss must NOT fire when split across chunks.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_telegram_bot_token_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "telegram-bot-token",
        "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE",
    );
}
