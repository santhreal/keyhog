//! Top-10 detector oracle: `slack-bot-token` true positive MUST fire.

use super::oracle_support::assert_detector_fires;

#[test]
fn top10_slack_bot_token_true_positive_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        r"xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}
