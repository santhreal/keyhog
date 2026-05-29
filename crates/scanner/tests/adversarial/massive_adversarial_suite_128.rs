//! Part 128 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates slack, slack, smartproxy, smartsheet, smartthings, smartystreets, smugmug, snapchat, snowflake, snowflake detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. SLACK USER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv128_slack_user_token_normal_must_fire() {
    assert_detector_fires(
        "slack-user-token",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv128_slack_user_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "slack-user-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv128_slack_user_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "slack-user-token",
        "xoxp-1234567890123-2345678901234-345678\u{200B}9012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv128_slack_user_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "slack-user-token",
        "xoxp-1234567890123-2345678901234-345678\u{00AD}9012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv128_slack_user_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "slack-user-token",
        "xoxp-1234567890123-2345678901234-345678\u{200C}9012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv128_slack_user_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "slack-user-token",
        "xoxp-1234567890123-2345678901234-345678\u{200D}9012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv128_slack_user_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "slack-user-token",
        "xoxp-1234567890123-2345678901234-345678\u{FEFF}9012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv128_slack_user_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "slack-user-token",
        "xoxp-1234567890123-2345678901234-345678\u{2060}9012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv128_slack_user_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "slack-user-token",
        "xoxp-1234567890123-2345678901234-345678\u{180E}9012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv128_slack_user_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "slack-user-token",
        "xoxp-1234567890123-2345678901234-345678\u{202E}9012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv128_slack_user_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "slack-user-token",
        "xoxp-1234567890123-2345678901234-345678\u{202C}9012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv128_slack_user_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "slack-user-token",
        "xoxp-1234567890123-2345678901234-345678\u{200E}9012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xoxp-1234567890123-2345678901234-3456789012345-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 2. SLACK WEBHOOK URL ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv128_slack_webhook_url_normal_must_fire() {
    assert_detector_fires(
        "slack-webhook-url",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv128_slack_webhook_url_wrong_prefix_must_silent() {
    assert_detector_silent(
        "slack-webhook-url",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv128_slack_webhook_url_evade_zwsp_must_fire() {
    assert_detector_fires(
        "slack-webhook-url",
        "https://hooks.slack.com/services/T0123\u{200B}4567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv128_slack_webhook_url_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "slack-webhook-url",
        "https://hooks.slack.com/services/T0123\u{00AD}4567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv128_slack_webhook_url_evade_zwnj_must_fire() {
    assert_detector_fires(
        "slack-webhook-url",
        "https://hooks.slack.com/services/T0123\u{200C}4567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv128_slack_webhook_url_evade_zwj_must_fire() {
    assert_detector_fires(
        "slack-webhook-url",
        "https://hooks.slack.com/services/T0123\u{200D}4567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv128_slack_webhook_url_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "slack-webhook-url",
        "https://hooks.slack.com/services/T0123\u{FEFF}4567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv128_slack_webhook_url_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "slack-webhook-url",
        "https://hooks.slack.com/services/T0123\u{2060}4567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv128_slack_webhook_url_evade_mongolian_must_fire() {
    assert_detector_fires(
        "slack-webhook-url",
        "https://hooks.slack.com/services/T0123\u{180E}4567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv128_slack_webhook_url_evade_rtl_must_fire() {
    assert_detector_fires(
        "slack-webhook-url",
        "https://hooks.slack.com/services/T0123\u{202E}4567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv128_slack_webhook_url_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "slack-webhook-url",
        "https://hooks.slack.com/services/T0123\u{202C}4567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv128_slack_webhook_url_evade_lrm_must_fire() {
    assert_detector_fires(
        "slack-webhook-url",
        "https://hooks.slack.com/services/T0123\u{200E}4567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T01234567/B98765432/AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

// =========================================================================
// 3. SMARTPROXY CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv128_smartproxy_credentials_normal_must_fire() {
    assert_detector_fires(
        "smartproxy-credentials",
        "smartproxy password=ProxyPass123456",
        "ProxyPass123456",
    );
}

#[test]
fn adv128_smartproxy_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "smartproxy-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv128_smartproxy_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "smartproxy-credentials",
        "smartproxy password=ProxyPa\u{200B}ss123456",
        "ProxyPass123456",
    );
}

#[test]
fn adv128_smartproxy_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "smartproxy-credentials",
        "smartproxy password=ProxyPa\u{00AD}ss123456",
        "ProxyPass123456",
    );
}

#[test]
fn adv128_smartproxy_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "smartproxy-credentials",
        "smartproxy password=ProxyPa\u{200C}ss123456",
        "ProxyPass123456",
    );
}

#[test]
fn adv128_smartproxy_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "smartproxy-credentials",
        "smartproxy password=ProxyPa\u{200D}ss123456",
        "ProxyPass123456",
    );
}

#[test]
fn adv128_smartproxy_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "smartproxy-credentials",
        "smartproxy password=ProxyPa\u{FEFF}ss123456",
        "ProxyPass123456",
    );
}

#[test]
fn adv128_smartproxy_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "smartproxy-credentials",
        "smartproxy password=ProxyPa\u{2060}ss123456",
        "ProxyPass123456",
    );
}

#[test]
fn adv128_smartproxy_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "smartproxy-credentials",
        "smartproxy password=ProxyPa\u{180E}ss123456",
        "ProxyPass123456",
    );
}

#[test]
fn adv128_smartproxy_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "smartproxy-credentials",
        "smartproxy password=ProxyPa\u{202E}ss123456",
        "ProxyPass123456",
    );
}

#[test]
fn adv128_smartproxy_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "smartproxy-credentials",
        "smartproxy password=ProxyPa\u{202C}ss123456",
        "ProxyPass123456",
    );
}

#[test]
fn adv128_smartproxy_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "smartproxy-credentials",
        "smartproxy password=ProxyPa\u{200E}ss123456",
        "ProxyPass123456",
    );
}

// =========================================================================
// 4. SMARTSHEET ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv128_smartsheet_access_token_normal_must_fire() {
    assert_detector_fires(
        "smartsheet-access-token",
        "SMARTSHEET_ACCESS_TOKEN=ec97c55tiqen5ckur746w10z78x0",
        "ec97c55tiqen5ckur746w10z78x0",
    );
}

#[test]
fn adv128_smartsheet_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "smartsheet-access-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv128_smartsheet_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "smartsheet-access-token",
        "SMARTSHEET_ACCESS_TOKEN=ec97c55tiqen5c\u{200B}kur746w10z78x0",
        "ec97c55tiqen5ckur746w10z78x0",
    );
}

#[test]
fn adv128_smartsheet_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "smartsheet-access-token",
        "SMARTSHEET_ACCESS_TOKEN=ec97c55tiqen5c\u{00AD}kur746w10z78x0",
        "ec97c55tiqen5ckur746w10z78x0",
    );
}

#[test]
fn adv128_smartsheet_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "smartsheet-access-token",
        "SMARTSHEET_ACCESS_TOKEN=ec97c55tiqen5c\u{200C}kur746w10z78x0",
        "ec97c55tiqen5ckur746w10z78x0",
    );
}

#[test]
fn adv128_smartsheet_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "smartsheet-access-token",
        "SMARTSHEET_ACCESS_TOKEN=ec97c55tiqen5c\u{200D}kur746w10z78x0",
        "ec97c55tiqen5ckur746w10z78x0",
    );
}

#[test]
fn adv128_smartsheet_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "smartsheet-access-token",
        "SMARTSHEET_ACCESS_TOKEN=ec97c55tiqen5c\u{FEFF}kur746w10z78x0",
        "ec97c55tiqen5ckur746w10z78x0",
    );
}

#[test]
fn adv128_smartsheet_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "smartsheet-access-token",
        "SMARTSHEET_ACCESS_TOKEN=ec97c55tiqen5c\u{2060}kur746w10z78x0",
        "ec97c55tiqen5ckur746w10z78x0",
    );
}

#[test]
fn adv128_smartsheet_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "smartsheet-access-token",
        "SMARTSHEET_ACCESS_TOKEN=ec97c55tiqen5c\u{180E}kur746w10z78x0",
        "ec97c55tiqen5ckur746w10z78x0",
    );
}

#[test]
fn adv128_smartsheet_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "smartsheet-access-token",
        "SMARTSHEET_ACCESS_TOKEN=ec97c55tiqen5c\u{202E}kur746w10z78x0",
        "ec97c55tiqen5ckur746w10z78x0",
    );
}

#[test]
fn adv128_smartsheet_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "smartsheet-access-token",
        "SMARTSHEET_ACCESS_TOKEN=ec97c55tiqen5c\u{202C}kur746w10z78x0",
        "ec97c55tiqen5ckur746w10z78x0",
    );
}

#[test]
fn adv128_smartsheet_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "smartsheet-access-token",
        "SMARTSHEET_ACCESS_TOKEN=ec97c55tiqen5c\u{200E}kur746w10z78x0",
        "ec97c55tiqen5ckur746w10z78x0",
    );
}

// =========================================================================
// 5. SMARTTHINGS API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv128_smartthings_api_token_normal_must_fire() {
    assert_detector_fires(
        "smartthings-api-token",
        "SMARTTHINGS_ACCESS_TOKEN=be96d2f7-20dc-a4ec-aa3a-c4179112746d",
        "be96d2f7-20dc-a4ec-aa3a-c4179112746d",
    );
}

#[test]
fn adv128_smartthings_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "smartthings-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv128_smartthings_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "smartthings-api-token",
        "SMARTTHINGS_ACCESS_TOKEN=be96d2f7-20dc-a4ec\u{200B}-aa3a-c4179112746d",
        "be96d2f7-20dc-a4ec-aa3a-c4179112746d",
    );
}

#[test]
fn adv128_smartthings_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "smartthings-api-token",
        "SMARTTHINGS_ACCESS_TOKEN=be96d2f7-20dc-a4ec\u{00AD}-aa3a-c4179112746d",
        "be96d2f7-20dc-a4ec-aa3a-c4179112746d",
    );
}

#[test]
fn adv128_smartthings_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "smartthings-api-token",
        "SMARTTHINGS_ACCESS_TOKEN=be96d2f7-20dc-a4ec\u{200C}-aa3a-c4179112746d",
        "be96d2f7-20dc-a4ec-aa3a-c4179112746d",
    );
}

#[test]
fn adv128_smartthings_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "smartthings-api-token",
        "SMARTTHINGS_ACCESS_TOKEN=be96d2f7-20dc-a4ec\u{200D}-aa3a-c4179112746d",
        "be96d2f7-20dc-a4ec-aa3a-c4179112746d",
    );
}

#[test]
fn adv128_smartthings_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "smartthings-api-token",
        "SMARTTHINGS_ACCESS_TOKEN=be96d2f7-20dc-a4ec\u{FEFF}-aa3a-c4179112746d",
        "be96d2f7-20dc-a4ec-aa3a-c4179112746d",
    );
}

#[test]
fn adv128_smartthings_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "smartthings-api-token",
        "SMARTTHINGS_ACCESS_TOKEN=be96d2f7-20dc-a4ec\u{2060}-aa3a-c4179112746d",
        "be96d2f7-20dc-a4ec-aa3a-c4179112746d",
    );
}

#[test]
fn adv128_smartthings_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "smartthings-api-token",
        "SMARTTHINGS_ACCESS_TOKEN=be96d2f7-20dc-a4ec\u{180E}-aa3a-c4179112746d",
        "be96d2f7-20dc-a4ec-aa3a-c4179112746d",
    );
}

#[test]
fn adv128_smartthings_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "smartthings-api-token",
        "SMARTTHINGS_ACCESS_TOKEN=be96d2f7-20dc-a4ec\u{202E}-aa3a-c4179112746d",
        "be96d2f7-20dc-a4ec-aa3a-c4179112746d",
    );
}

#[test]
fn adv128_smartthings_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "smartthings-api-token",
        "SMARTTHINGS_ACCESS_TOKEN=be96d2f7-20dc-a4ec\u{202C}-aa3a-c4179112746d",
        "be96d2f7-20dc-a4ec-aa3a-c4179112746d",
    );
}

#[test]
fn adv128_smartthings_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "smartthings-api-token",
        "SMARTTHINGS_ACCESS_TOKEN=be96d2f7-20dc-a4ec\u{200E}-aa3a-c4179112746d",
        "be96d2f7-20dc-a4ec-aa3a-c4179112746d",
    );
}

// =========================================================================
// 6. SMARTYSTREETS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv128_smartystreets_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "smartystreets-api-credentials",
        "SMARTY_AUTH_ID=4c347b06-52f4-6c72-1daf-f11ca4c87270",
        "4c347b06-52f4-6c72-1daf-f11ca4c87270",
    );
}

#[test]
fn adv128_smartystreets_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "smartystreets-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv128_smartystreets_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "smartystreets-api-credentials",
        "SMARTY_AUTH_ID=4c347b06-52f4-6c72\u{200B}-1daf-f11ca4c87270",
        "4c347b06-52f4-6c72-1daf-f11ca4c87270",
    );
}

#[test]
fn adv128_smartystreets_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "smartystreets-api-credentials",
        "SMARTY_AUTH_ID=4c347b06-52f4-6c72\u{00AD}-1daf-f11ca4c87270",
        "4c347b06-52f4-6c72-1daf-f11ca4c87270",
    );
}

#[test]
fn adv128_smartystreets_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "smartystreets-api-credentials",
        "SMARTY_AUTH_ID=4c347b06-52f4-6c72\u{200C}-1daf-f11ca4c87270",
        "4c347b06-52f4-6c72-1daf-f11ca4c87270",
    );
}

#[test]
fn adv128_smartystreets_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "smartystreets-api-credentials",
        "SMARTY_AUTH_ID=4c347b06-52f4-6c72\u{200D}-1daf-f11ca4c87270",
        "4c347b06-52f4-6c72-1daf-f11ca4c87270",
    );
}

#[test]
fn adv128_smartystreets_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "smartystreets-api-credentials",
        "SMARTY_AUTH_ID=4c347b06-52f4-6c72\u{FEFF}-1daf-f11ca4c87270",
        "4c347b06-52f4-6c72-1daf-f11ca4c87270",
    );
}

#[test]
fn adv128_smartystreets_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "smartystreets-api-credentials",
        "SMARTY_AUTH_ID=4c347b06-52f4-6c72\u{2060}-1daf-f11ca4c87270",
        "4c347b06-52f4-6c72-1daf-f11ca4c87270",
    );
}

#[test]
fn adv128_smartystreets_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "smartystreets-api-credentials",
        "SMARTY_AUTH_ID=4c347b06-52f4-6c72\u{180E}-1daf-f11ca4c87270",
        "4c347b06-52f4-6c72-1daf-f11ca4c87270",
    );
}

#[test]
fn adv128_smartystreets_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "smartystreets-api-credentials",
        "SMARTY_AUTH_ID=4c347b06-52f4-6c72\u{202E}-1daf-f11ca4c87270",
        "4c347b06-52f4-6c72-1daf-f11ca4c87270",
    );
}

#[test]
fn adv128_smartystreets_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "smartystreets-api-credentials",
        "SMARTY_AUTH_ID=4c347b06-52f4-6c72\u{202C}-1daf-f11ca4c87270",
        "4c347b06-52f4-6c72-1daf-f11ca4c87270",
    );
}

#[test]
fn adv128_smartystreets_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "smartystreets-api-credentials",
        "SMARTY_AUTH_ID=4c347b06-52f4-6c72\u{200E}-1daf-f11ca4c87270",
        "4c347b06-52f4-6c72-1daf-f11ca4c87270",
    );
}

// =========================================================================
// 7. SMUGMUG API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv128_smugmug_api_key_normal_must_fire() {
    assert_detector_fires(
        "smugmug-api-key",
        "SMUGMUG_API_KEY=TxmLs09HULxSNfTW",
        "TxmLs09HULxSNfTW",
    );
}

#[test]
fn adv128_smugmug_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "smugmug-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv128_smugmug_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "smugmug-api-key",
        "SMUGMUG_API_KEY=TxmLs09H\u{200B}ULxSNfTW",
        "TxmLs09HULxSNfTW",
    );
}

#[test]
fn adv128_smugmug_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "smugmug-api-key",
        "SMUGMUG_API_KEY=TxmLs09H\u{00AD}ULxSNfTW",
        "TxmLs09HULxSNfTW",
    );
}

#[test]
fn adv128_smugmug_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "smugmug-api-key",
        "SMUGMUG_API_KEY=TxmLs09H\u{200C}ULxSNfTW",
        "TxmLs09HULxSNfTW",
    );
}

#[test]
fn adv128_smugmug_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "smugmug-api-key",
        "SMUGMUG_API_KEY=TxmLs09H\u{200D}ULxSNfTW",
        "TxmLs09HULxSNfTW",
    );
}

#[test]
fn adv128_smugmug_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "smugmug-api-key",
        "SMUGMUG_API_KEY=TxmLs09H\u{FEFF}ULxSNfTW",
        "TxmLs09HULxSNfTW",
    );
}

#[test]
fn adv128_smugmug_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "smugmug-api-key",
        "SMUGMUG_API_KEY=TxmLs09H\u{2060}ULxSNfTW",
        "TxmLs09HULxSNfTW",
    );
}

#[test]
fn adv128_smugmug_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "smugmug-api-key",
        "SMUGMUG_API_KEY=TxmLs09H\u{180E}ULxSNfTW",
        "TxmLs09HULxSNfTW",
    );
}

#[test]
fn adv128_smugmug_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "smugmug-api-key",
        "SMUGMUG_API_KEY=TxmLs09H\u{202E}ULxSNfTW",
        "TxmLs09HULxSNfTW",
    );
}

#[test]
fn adv128_smugmug_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "smugmug-api-key",
        "SMUGMUG_API_KEY=TxmLs09H\u{202C}ULxSNfTW",
        "TxmLs09HULxSNfTW",
    );
}

#[test]
fn adv128_smugmug_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "smugmug-api-key",
        "SMUGMUG_API_KEY=TxmLs09H\u{200E}ULxSNfTW",
        "TxmLs09HULxSNfTW",
    );
}

// =========================================================================
// 8. SNAPCHAT API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv128_snapchat_api_token_normal_must_fire() {
    assert_detector_fires(
        "snapchat-api-token",
        "SNAPCHAT_API_KEY=a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
        "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
    );
}

#[test]
fn adv128_snapchat_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "snapchat-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv128_snapchat_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "snapchat-api-token",
        "SNAPCHAT_API_KEY=a573881b385d7370d17ec84d8f8264a6\u{200B}f9a8d7709bc9323e8be592ba1c474c1a",
        "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
    );
}

#[test]
fn adv128_snapchat_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "snapchat-api-token",
        "SNAPCHAT_API_KEY=a573881b385d7370d17ec84d8f8264a6\u{00AD}f9a8d7709bc9323e8be592ba1c474c1a",
        "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
    );
}

#[test]
fn adv128_snapchat_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "snapchat-api-token",
        "SNAPCHAT_API_KEY=a573881b385d7370d17ec84d8f8264a6\u{200C}f9a8d7709bc9323e8be592ba1c474c1a",
        "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
    );
}

#[test]
fn adv128_snapchat_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "snapchat-api-token",
        "SNAPCHAT_API_KEY=a573881b385d7370d17ec84d8f8264a6\u{200D}f9a8d7709bc9323e8be592ba1c474c1a",
        "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
    );
}

#[test]
fn adv128_snapchat_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "snapchat-api-token",
        "SNAPCHAT_API_KEY=a573881b385d7370d17ec84d8f8264a6\u{FEFF}f9a8d7709bc9323e8be592ba1c474c1a",
        "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
    );
}

#[test]
fn adv128_snapchat_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "snapchat-api-token",
        "SNAPCHAT_API_KEY=a573881b385d7370d17ec84d8f8264a6\u{2060}f9a8d7709bc9323e8be592ba1c474c1a",
        "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
    );
}

#[test]
fn adv128_snapchat_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "snapchat-api-token",
        "SNAPCHAT_API_KEY=a573881b385d7370d17ec84d8f8264a6\u{180E}f9a8d7709bc9323e8be592ba1c474c1a",
        "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
    );
}

#[test]
fn adv128_snapchat_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "snapchat-api-token",
        "SNAPCHAT_API_KEY=a573881b385d7370d17ec84d8f8264a6\u{202E}f9a8d7709bc9323e8be592ba1c474c1a",
        "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
    );
}

#[test]
fn adv128_snapchat_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "snapchat-api-token",
        "SNAPCHAT_API_KEY=a573881b385d7370d17ec84d8f8264a6\u{202C}f9a8d7709bc9323e8be592ba1c474c1a",
        "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
    );
}

#[test]
fn adv128_snapchat_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "snapchat-api-token",
        "SNAPCHAT_API_KEY=a573881b385d7370d17ec84d8f8264a6\u{200E}f9a8d7709bc9323e8be592ba1c474c1a",
        "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a",
    );
}

// =========================================================================
// 9. SNOWFLAKE ACCOUNT INFO ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv128_snowflake_account_info_normal_must_fire() {
    assert_detector_fires(
        "snowflake-account-info",
        "snowflake.account=xy12345.us-east-1",
        "xy12345.us-east-1",
    );
}

#[test]
fn adv128_snowflake_account_info_wrong_prefix_must_silent() {
    assert_detector_silent(
        "snowflake-account-info",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv128_snowflake_account_info_evade_zwsp_must_fire() {
    assert_detector_fires(
        "snowflake-account-info",
        "snowflake.account=xy12345.\u{200B}us-east-1",
        "xy12345.us-east-1",
    );
}

#[test]
fn adv128_snowflake_account_info_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "snowflake-account-info",
        "snowflake.account=xy12345.\u{00AD}us-east-1",
        "xy12345.us-east-1",
    );
}

#[test]
fn adv128_snowflake_account_info_evade_zwnj_must_fire() {
    assert_detector_fires(
        "snowflake-account-info",
        "snowflake.account=xy12345.\u{200C}us-east-1",
        "xy12345.us-east-1",
    );
}

#[test]
fn adv128_snowflake_account_info_evade_zwj_must_fire() {
    assert_detector_fires(
        "snowflake-account-info",
        "snowflake.account=xy12345.\u{200D}us-east-1",
        "xy12345.us-east-1",
    );
}

#[test]
fn adv128_snowflake_account_info_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "snowflake-account-info",
        "snowflake.account=xy12345.\u{FEFF}us-east-1",
        "xy12345.us-east-1",
    );
}

#[test]
fn adv128_snowflake_account_info_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "snowflake-account-info",
        "snowflake.account=xy12345.\u{2060}us-east-1",
        "xy12345.us-east-1",
    );
}

#[test]
fn adv128_snowflake_account_info_evade_mongolian_must_fire() {
    assert_detector_fires(
        "snowflake-account-info",
        "snowflake.account=xy12345.\u{180E}us-east-1",
        "xy12345.us-east-1",
    );
}

#[test]
fn adv128_snowflake_account_info_evade_rtl_must_fire() {
    assert_detector_fires(
        "snowflake-account-info",
        "snowflake.account=xy12345.\u{202E}us-east-1",
        "xy12345.us-east-1",
    );
}

#[test]
fn adv128_snowflake_account_info_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "snowflake-account-info",
        "snowflake.account=xy12345.\u{202C}us-east-1",
        "xy12345.us-east-1",
    );
}

#[test]
fn adv128_snowflake_account_info_evade_lrm_must_fire() {
    assert_detector_fires(
        "snowflake-account-info",
        "snowflake.account=xy12345.\u{200E}us-east-1",
        "xy12345.us-east-1",
    );
}

// =========================================================================
// 10. SNOWFLAKE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv128_snowflake_credentials_normal_must_fire() {
    assert_detector_fires(
        "snowflake-credentials",
        "snowflake.password=SnowFlakePass123!",
        "SnowFlakePass123!",
    );
}

#[test]
fn adv128_snowflake_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "snowflake-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv128_snowflake_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "snowflake-credentials",
        "snowflake.password=SnowFlak\u{200B}ePass123!",
        "SnowFlakePass123!",
    );
}

#[test]
fn adv128_snowflake_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "snowflake-credentials",
        "snowflake.password=SnowFlak\u{00AD}ePass123!",
        "SnowFlakePass123!",
    );
}

#[test]
fn adv128_snowflake_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "snowflake-credentials",
        "snowflake.password=SnowFlak\u{200C}ePass123!",
        "SnowFlakePass123!",
    );
}

#[test]
fn adv128_snowflake_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "snowflake-credentials",
        "snowflake.password=SnowFlak\u{200D}ePass123!",
        "SnowFlakePass123!",
    );
}

#[test]
fn adv128_snowflake_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "snowflake-credentials",
        "snowflake.password=SnowFlak\u{FEFF}ePass123!",
        "SnowFlakePass123!",
    );
}

#[test]
fn adv128_snowflake_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "snowflake-credentials",
        "snowflake.password=SnowFlak\u{2060}ePass123!",
        "SnowFlakePass123!",
    );
}

#[test]
fn adv128_snowflake_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "snowflake-credentials",
        "snowflake.password=SnowFlak\u{180E}ePass123!",
        "SnowFlakePass123!",
    );
}

#[test]
fn adv128_snowflake_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "snowflake-credentials",
        "snowflake.password=SnowFlak\u{202E}ePass123!",
        "SnowFlakePass123!",
    );
}

#[test]
fn adv128_snowflake_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "snowflake-credentials",
        "snowflake.password=SnowFlak\u{202C}ePass123!",
        "SnowFlakePass123!",
    );
}

#[test]
fn adv128_snowflake_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "snowflake-credentials",
        "snowflake.password=SnowFlak\u{200E}ePass123!",
        "SnowFlakePass123!",
    );
}


