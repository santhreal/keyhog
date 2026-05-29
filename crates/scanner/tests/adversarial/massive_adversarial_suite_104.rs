//! Part 104 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates lunacy, magento, magento, mailchimp, mailgun, mailgun, mailjet, make, maltego, mandrill detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. LUNACY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv104_lunacy_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "lunacy-api-credentials",
        "LUNACY api_key=abcdefghijklmnopqrstuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv104_lunacy_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "lunacy-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv104_lunacy_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lunacy-api-credentials",
        "LUNACY api_key=abcdefghijklmnopqr\u{200B}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv104_lunacy_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lunacy-api-credentials",
        "LUNACY api_key=abcdefghijklmnopqr\u{00AD}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv104_lunacy_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lunacy-api-credentials",
        "LUNACY api_key=abcdefghijklmnopqr\u{200C}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv104_lunacy_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "lunacy-api-credentials",
        "LUNACY api_key=abcdefghijklmnopqr\u{200D}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv104_lunacy_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lunacy-api-credentials",
        "LUNACY api_key=abcdefghijklmnopqr\u{FEFF}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv104_lunacy_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lunacy-api-credentials",
        "LUNACY api_key=abcdefghijklmnopqr\u{2060}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv104_lunacy_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lunacy-api-credentials",
        "LUNACY api_key=abcdefghijklmnopqr\u{180E}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv104_lunacy_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "lunacy-api-credentials",
        "LUNACY api_key=abcdefghijklmnopqr\u{202E}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv104_lunacy_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lunacy-api-credentials",
        "LUNACY api_key=abcdefghijklmnopqr\u{202C}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv104_lunacy_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "lunacy-api-credentials",
        "LUNACY api_key=abcdefghijklmnopqr\u{200E}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

// =========================================================================
// 2. MAGENTO INTEGRATION TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv104_magento_integration_token_normal_must_fire() {
    assert_detector_fires(
        "magento-integration-token",
        "magento=e32420577b893886ed061724f6c4474e",
        "e32420577b893886ed061724f6c4474e",
    );
}

#[test]
fn adv104_magento_integration_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "magento-integration-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv104_magento_integration_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "magento-integration-token",
        "magento=e32420577b893886\u{200B}ed061724f6c4474e",
        "e32420577b893886ed061724f6c4474e",
    );
}

#[test]
fn adv104_magento_integration_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "magento-integration-token",
        "magento=e32420577b893886\u{00AD}ed061724f6c4474e",
        "e32420577b893886ed061724f6c4474e",
    );
}

#[test]
fn adv104_magento_integration_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "magento-integration-token",
        "magento=e32420577b893886\u{200C}ed061724f6c4474e",
        "e32420577b893886ed061724f6c4474e",
    );
}

#[test]
fn adv104_magento_integration_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "magento-integration-token",
        "magento=e32420577b893886\u{200D}ed061724f6c4474e",
        "e32420577b893886ed061724f6c4474e",
    );
}

#[test]
fn adv104_magento_integration_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "magento-integration-token",
        "magento=e32420577b893886\u{FEFF}ed061724f6c4474e",
        "e32420577b893886ed061724f6c4474e",
    );
}

#[test]
fn adv104_magento_integration_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "magento-integration-token",
        "magento=e32420577b893886\u{2060}ed061724f6c4474e",
        "e32420577b893886ed061724f6c4474e",
    );
}

#[test]
fn adv104_magento_integration_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "magento-integration-token",
        "magento=e32420577b893886\u{180E}ed061724f6c4474e",
        "e32420577b893886ed061724f6c4474e",
    );
}

#[test]
fn adv104_magento_integration_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "magento-integration-token",
        "magento=e32420577b893886\u{202E}ed061724f6c4474e",
        "e32420577b893886ed061724f6c4474e",
    );
}

#[test]
fn adv104_magento_integration_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "magento-integration-token",
        "magento=e32420577b893886\u{202C}ed061724f6c4474e",
        "e32420577b893886ed061724f6c4474e",
    );
}

#[test]
fn adv104_magento_integration_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "magento-integration-token",
        "magento=e32420577b893886\u{200E}ed061724f6c4474e",
        "e32420577b893886ed061724f6c4474e",
    );
}

// =========================================================================
// 3. MAGENTO REST API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv104_magento_rest_api_token_normal_must_fire() {
    assert_detector_fires(
        "magento-rest-api-token",
        "magento=293559c821020c9320063f6627da753a",
        "293559c821020c9320063f6627da753a",
    );
}

#[test]
fn adv104_magento_rest_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "magento-rest-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv104_magento_rest_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "magento-rest-api-token",
        "magento=293559c821020c93\u{200B}20063f6627da753a",
        "293559c821020c9320063f6627da753a",
    );
}

#[test]
fn adv104_magento_rest_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "magento-rest-api-token",
        "magento=293559c821020c93\u{00AD}20063f6627da753a",
        "293559c821020c9320063f6627da753a",
    );
}

#[test]
fn adv104_magento_rest_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "magento-rest-api-token",
        "magento=293559c821020c93\u{200C}20063f6627da753a",
        "293559c821020c9320063f6627da753a",
    );
}

#[test]
fn adv104_magento_rest_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "magento-rest-api-token",
        "magento=293559c821020c93\u{200D}20063f6627da753a",
        "293559c821020c9320063f6627da753a",
    );
}

#[test]
fn adv104_magento_rest_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "magento-rest-api-token",
        "magento=293559c821020c93\u{FEFF}20063f6627da753a",
        "293559c821020c9320063f6627da753a",
    );
}

#[test]
fn adv104_magento_rest_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "magento-rest-api-token",
        "magento=293559c821020c93\u{2060}20063f6627da753a",
        "293559c821020c9320063f6627da753a",
    );
}

#[test]
fn adv104_magento_rest_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "magento-rest-api-token",
        "magento=293559c821020c93\u{180E}20063f6627da753a",
        "293559c821020c9320063f6627da753a",
    );
}

#[test]
fn adv104_magento_rest_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "magento-rest-api-token",
        "magento=293559c821020c93\u{202E}20063f6627da753a",
        "293559c821020c9320063f6627da753a",
    );
}

#[test]
fn adv104_magento_rest_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "magento-rest-api-token",
        "magento=293559c821020c93\u{202C}20063f6627da753a",
        "293559c821020c9320063f6627da753a",
    );
}

#[test]
fn adv104_magento_rest_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "magento-rest-api-token",
        "magento=293559c821020c93\u{200E}20063f6627da753a",
        "293559c821020c9320063f6627da753a",
    );
}

// =========================================================================
// 4. MAILCHIMP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv104_mailchimp_api_key_normal_must_fire() {
    assert_detector_fires(
        "mailchimp-api-key",
        "MAILCHIMP_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
    );
}

#[test]
fn adv104_mailchimp_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mailchimp-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv104_mailchimp_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mailchimp-api-key",
        "MAILCHIMP_API_KEY=7b3e5d8c1a9f4e2b6c\u{200B}8d3a5e9f1b7c4d-us12",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
    );
}

#[test]
fn adv104_mailchimp_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mailchimp-api-key",
        "MAILCHIMP_API_KEY=7b3e5d8c1a9f4e2b6c\u{00AD}8d3a5e9f1b7c4d-us12",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
    );
}

#[test]
fn adv104_mailchimp_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mailchimp-api-key",
        "MAILCHIMP_API_KEY=7b3e5d8c1a9f4e2b6c\u{200C}8d3a5e9f1b7c4d-us12",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
    );
}

#[test]
fn adv104_mailchimp_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "mailchimp-api-key",
        "MAILCHIMP_API_KEY=7b3e5d8c1a9f4e2b6c\u{200D}8d3a5e9f1b7c4d-us12",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
    );
}

#[test]
fn adv104_mailchimp_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mailchimp-api-key",
        "MAILCHIMP_API_KEY=7b3e5d8c1a9f4e2b6c\u{FEFF}8d3a5e9f1b7c4d-us12",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
    );
}

#[test]
fn adv104_mailchimp_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mailchimp-api-key",
        "MAILCHIMP_API_KEY=7b3e5d8c1a9f4e2b6c\u{2060}8d3a5e9f1b7c4d-us12",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
    );
}

#[test]
fn adv104_mailchimp_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mailchimp-api-key",
        "MAILCHIMP_API_KEY=7b3e5d8c1a9f4e2b6c\u{180E}8d3a5e9f1b7c4d-us12",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
    );
}

#[test]
fn adv104_mailchimp_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "mailchimp-api-key",
        "MAILCHIMP_API_KEY=7b3e5d8c1a9f4e2b6c\u{202E}8d3a5e9f1b7c4d-us12",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
    );
}

#[test]
fn adv104_mailchimp_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mailchimp-api-key",
        "MAILCHIMP_API_KEY=7b3e5d8c1a9f4e2b6c\u{202C}8d3a5e9f1b7c4d-us12",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
    );
}

#[test]
fn adv104_mailchimp_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "mailchimp-api-key",
        "MAILCHIMP_API_KEY=7b3e5d8c1a9f4e2b6c\u{200E}8d3a5e9f1b7c4d-us12",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-us12",
    );
}

// =========================================================================
// 5. MAILGUN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv104_mailgun_api_key_normal_must_fire() {
    assert_detector_fires(
        "mailgun-api-key",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv104_mailgun_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mailgun-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv104_mailgun_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mailgun-api-key",
        "key-9a3b7c2e4d1f6a\u{200B}8b0c5d9e3f7a1b4c2d",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv104_mailgun_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mailgun-api-key",
        "key-9a3b7c2e4d1f6a\u{00AD}8b0c5d9e3f7a1b4c2d",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv104_mailgun_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mailgun-api-key",
        "key-9a3b7c2e4d1f6a\u{200C}8b0c5d9e3f7a1b4c2d",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv104_mailgun_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "mailgun-api-key",
        "key-9a3b7c2e4d1f6a\u{200D}8b0c5d9e3f7a1b4c2d",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv104_mailgun_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mailgun-api-key",
        "key-9a3b7c2e4d1f6a\u{FEFF}8b0c5d9e3f7a1b4c2d",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv104_mailgun_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mailgun-api-key",
        "key-9a3b7c2e4d1f6a\u{2060}8b0c5d9e3f7a1b4c2d",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv104_mailgun_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mailgun-api-key",
        "key-9a3b7c2e4d1f6a\u{180E}8b0c5d9e3f7a1b4c2d",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv104_mailgun_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "mailgun-api-key",
        "key-9a3b7c2e4d1f6a\u{202E}8b0c5d9e3f7a1b4c2d",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv104_mailgun_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mailgun-api-key",
        "key-9a3b7c2e4d1f6a\u{202C}8b0c5d9e3f7a1b4c2d",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv104_mailgun_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "mailgun-api-key",
        "key-9a3b7c2e4d1f6a\u{200E}8b0c5d9e3f7a1b4c2d",
        "key-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

// =========================================================================
// 6. MAILGUN WEBHOOK SIGNING KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv104_mailgun_webhook_signing_key_normal_must_fire() {
    assert_detector_fires(
        "mailgun-webhook-signing-key",
        "MAILGUNWEBHOOKSIGNING=7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
        "7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
    );
}

#[test]
fn adv104_mailgun_webhook_signing_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mailgun-webhook-signing-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv104_mailgun_webhook_signing_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mailgun-webhook-signing-key",
        "MAILGUNWEBHOOKSIGNING=7Mx3bxEAyReNbK3g\u{200B}qOQNcp7nWrfTFS6n",
        "7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
    );
}

#[test]
fn adv104_mailgun_webhook_signing_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mailgun-webhook-signing-key",
        "MAILGUNWEBHOOKSIGNING=7Mx3bxEAyReNbK3g\u{00AD}qOQNcp7nWrfTFS6n",
        "7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
    );
}

#[test]
fn adv104_mailgun_webhook_signing_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mailgun-webhook-signing-key",
        "MAILGUNWEBHOOKSIGNING=7Mx3bxEAyReNbK3g\u{200C}qOQNcp7nWrfTFS6n",
        "7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
    );
}

#[test]
fn adv104_mailgun_webhook_signing_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "mailgun-webhook-signing-key",
        "MAILGUNWEBHOOKSIGNING=7Mx3bxEAyReNbK3g\u{200D}qOQNcp7nWrfTFS6n",
        "7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
    );
}

#[test]
fn adv104_mailgun_webhook_signing_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mailgun-webhook-signing-key",
        "MAILGUNWEBHOOKSIGNING=7Mx3bxEAyReNbK3g\u{FEFF}qOQNcp7nWrfTFS6n",
        "7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
    );
}

#[test]
fn adv104_mailgun_webhook_signing_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mailgun-webhook-signing-key",
        "MAILGUNWEBHOOKSIGNING=7Mx3bxEAyReNbK3g\u{2060}qOQNcp7nWrfTFS6n",
        "7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
    );
}

#[test]
fn adv104_mailgun_webhook_signing_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mailgun-webhook-signing-key",
        "MAILGUNWEBHOOKSIGNING=7Mx3bxEAyReNbK3g\u{180E}qOQNcp7nWrfTFS6n",
        "7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
    );
}

#[test]
fn adv104_mailgun_webhook_signing_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "mailgun-webhook-signing-key",
        "MAILGUNWEBHOOKSIGNING=7Mx3bxEAyReNbK3g\u{202E}qOQNcp7nWrfTFS6n",
        "7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
    );
}

#[test]
fn adv104_mailgun_webhook_signing_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mailgun-webhook-signing-key",
        "MAILGUNWEBHOOKSIGNING=7Mx3bxEAyReNbK3g\u{202C}qOQNcp7nWrfTFS6n",
        "7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
    );
}

#[test]
fn adv104_mailgun_webhook_signing_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "mailgun-webhook-signing-key",
        "MAILGUNWEBHOOKSIGNING=7Mx3bxEAyReNbK3g\u{200E}qOQNcp7nWrfTFS6n",
        "7Mx3bxEAyReNbK3gqOQNcp7nWrfTFS6n",
    );
}

// =========================================================================
// 7. MAILJET API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv104_mailjet_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "mailjet-api-credentials",
        "MAILJETAPIKEYPUBLIC=2716b690eb062d28eee5f0b217fe9bfa",
        "2716b690eb062d28eee5f0b217fe9bfa",
    );
}

#[test]
fn adv104_mailjet_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mailjet-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv104_mailjet_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mailjet-api-credentials",
        "MAILJETAPIKEYPUBLIC=2716b690eb062d28\u{200B}eee5f0b217fe9bfa",
        "2716b690eb062d28eee5f0b217fe9bfa",
    );
}

#[test]
fn adv104_mailjet_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mailjet-api-credentials",
        "MAILJETAPIKEYPUBLIC=2716b690eb062d28\u{00AD}eee5f0b217fe9bfa",
        "2716b690eb062d28eee5f0b217fe9bfa",
    );
}

#[test]
fn adv104_mailjet_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mailjet-api-credentials",
        "MAILJETAPIKEYPUBLIC=2716b690eb062d28\u{200C}eee5f0b217fe9bfa",
        "2716b690eb062d28eee5f0b217fe9bfa",
    );
}

#[test]
fn adv104_mailjet_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "mailjet-api-credentials",
        "MAILJETAPIKEYPUBLIC=2716b690eb062d28\u{200D}eee5f0b217fe9bfa",
        "2716b690eb062d28eee5f0b217fe9bfa",
    );
}

#[test]
fn adv104_mailjet_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mailjet-api-credentials",
        "MAILJETAPIKEYPUBLIC=2716b690eb062d28\u{FEFF}eee5f0b217fe9bfa",
        "2716b690eb062d28eee5f0b217fe9bfa",
    );
}

#[test]
fn adv104_mailjet_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mailjet-api-credentials",
        "MAILJETAPIKEYPUBLIC=2716b690eb062d28\u{2060}eee5f0b217fe9bfa",
        "2716b690eb062d28eee5f0b217fe9bfa",
    );
}

#[test]
fn adv104_mailjet_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mailjet-api-credentials",
        "MAILJETAPIKEYPUBLIC=2716b690eb062d28\u{180E}eee5f0b217fe9bfa",
        "2716b690eb062d28eee5f0b217fe9bfa",
    );
}

#[test]
fn adv104_mailjet_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "mailjet-api-credentials",
        "MAILJETAPIKEYPUBLIC=2716b690eb062d28\u{202E}eee5f0b217fe9bfa",
        "2716b690eb062d28eee5f0b217fe9bfa",
    );
}

#[test]
fn adv104_mailjet_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mailjet-api-credentials",
        "MAILJETAPIKEYPUBLIC=2716b690eb062d28\u{202C}eee5f0b217fe9bfa",
        "2716b690eb062d28eee5f0b217fe9bfa",
    );
}

#[test]
fn adv104_mailjet_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "mailjet-api-credentials",
        "MAILJETAPIKEYPUBLIC=2716b690eb062d28\u{200E}eee5f0b217fe9bfa",
        "2716b690eb062d28eee5f0b217fe9bfa",
    );
}

// =========================================================================
// 8. MAKE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv104_make_api_token_normal_must_fire() {
    assert_detector_fires(
        "make-api-token",
        "MAKE_API_KEY=14609521-cd2f-544c-595f-3590c5bafa3e",
        "14609521-cd2f-544c-595f-3590c5bafa3e",
    );
}

#[test]
fn adv104_make_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "make-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv104_make_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "make-api-token",
        "MAKE_API_KEY=14609521-cd2f-544c\u{200B}-595f-3590c5bafa3e",
        "14609521-cd2f-544c-595f-3590c5bafa3e",
    );
}

#[test]
fn adv104_make_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "make-api-token",
        "MAKE_API_KEY=14609521-cd2f-544c\u{00AD}-595f-3590c5bafa3e",
        "14609521-cd2f-544c-595f-3590c5bafa3e",
    );
}

#[test]
fn adv104_make_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "make-api-token",
        "MAKE_API_KEY=14609521-cd2f-544c\u{200C}-595f-3590c5bafa3e",
        "14609521-cd2f-544c-595f-3590c5bafa3e",
    );
}

#[test]
fn adv104_make_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "make-api-token",
        "MAKE_API_KEY=14609521-cd2f-544c\u{200D}-595f-3590c5bafa3e",
        "14609521-cd2f-544c-595f-3590c5bafa3e",
    );
}

#[test]
fn adv104_make_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "make-api-token",
        "MAKE_API_KEY=14609521-cd2f-544c\u{FEFF}-595f-3590c5bafa3e",
        "14609521-cd2f-544c-595f-3590c5bafa3e",
    );
}

#[test]
fn adv104_make_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "make-api-token",
        "MAKE_API_KEY=14609521-cd2f-544c\u{2060}-595f-3590c5bafa3e",
        "14609521-cd2f-544c-595f-3590c5bafa3e",
    );
}

#[test]
fn adv104_make_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "make-api-token",
        "MAKE_API_KEY=14609521-cd2f-544c\u{180E}-595f-3590c5bafa3e",
        "14609521-cd2f-544c-595f-3590c5bafa3e",
    );
}

#[test]
fn adv104_make_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "make-api-token",
        "MAKE_API_KEY=14609521-cd2f-544c\u{202E}-595f-3590c5bafa3e",
        "14609521-cd2f-544c-595f-3590c5bafa3e",
    );
}

#[test]
fn adv104_make_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "make-api-token",
        "MAKE_API_KEY=14609521-cd2f-544c\u{202C}-595f-3590c5bafa3e",
        "14609521-cd2f-544c-595f-3590c5bafa3e",
    );
}

#[test]
fn adv104_make_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "make-api-token",
        "MAKE_API_KEY=14609521-cd2f-544c\u{200E}-595f-3590c5bafa3e",
        "14609521-cd2f-544c-595f-3590c5bafa3e",
    );
}

// =========================================================================
// 9. MALTEGO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv104_maltego_api_key_normal_must_fire() {
    assert_detector_fires(
        "maltego-api-key",
        "maltegokey=QaoH6LgKMjTTuEuU",
        "QaoH6LgKMjTTuEuU",
    );
}

#[test]
fn adv104_maltego_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "maltego-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv104_maltego_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "maltego-api-key",
        "maltegokey=QaoH6LgK\u{200B}MjTTuEuU",
        "QaoH6LgKMjTTuEuU",
    );
}

#[test]
fn adv104_maltego_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "maltego-api-key",
        "maltegokey=QaoH6LgK\u{00AD}MjTTuEuU",
        "QaoH6LgKMjTTuEuU",
    );
}

#[test]
fn adv104_maltego_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "maltego-api-key",
        "maltegokey=QaoH6LgK\u{200C}MjTTuEuU",
        "QaoH6LgKMjTTuEuU",
    );
}

#[test]
fn adv104_maltego_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "maltego-api-key",
        "maltegokey=QaoH6LgK\u{200D}MjTTuEuU",
        "QaoH6LgKMjTTuEuU",
    );
}

#[test]
fn adv104_maltego_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "maltego-api-key",
        "maltegokey=QaoH6LgK\u{FEFF}MjTTuEuU",
        "QaoH6LgKMjTTuEuU",
    );
}

#[test]
fn adv104_maltego_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "maltego-api-key",
        "maltegokey=QaoH6LgK\u{2060}MjTTuEuU",
        "QaoH6LgKMjTTuEuU",
    );
}

#[test]
fn adv104_maltego_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "maltego-api-key",
        "maltegokey=QaoH6LgK\u{180E}MjTTuEuU",
        "QaoH6LgKMjTTuEuU",
    );
}

#[test]
fn adv104_maltego_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "maltego-api-key",
        "maltegokey=QaoH6LgK\u{202E}MjTTuEuU",
        "QaoH6LgKMjTTuEuU",
    );
}

#[test]
fn adv104_maltego_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "maltego-api-key",
        "maltegokey=QaoH6LgK\u{202C}MjTTuEuU",
        "QaoH6LgKMjTTuEuU",
    );
}

#[test]
fn adv104_maltego_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "maltego-api-key",
        "maltegokey=QaoH6LgK\u{200E}MjTTuEuU",
        "QaoH6LgKMjTTuEuU",
    );
}

// =========================================================================
// 10. MANDRILL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv104_mandrill_api_key_normal_must_fire() {
    assert_detector_fires(
        "mandrill-api-key",
        "MANDRILL=SzsANQcSgpqa5WgOrklNRy",
        "SzsANQcSgpqa5WgOrklNRy",
    );
}

#[test]
fn adv104_mandrill_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mandrill-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv104_mandrill_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mandrill-api-key",
        "MANDRILL=SzsANQcSgpq\u{200B}a5WgOrklNRy",
        "SzsANQcSgpqa5WgOrklNRy",
    );
}

#[test]
fn adv104_mandrill_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mandrill-api-key",
        "MANDRILL=SzsANQcSgpq\u{00AD}a5WgOrklNRy",
        "SzsANQcSgpqa5WgOrklNRy",
    );
}

#[test]
fn adv104_mandrill_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mandrill-api-key",
        "MANDRILL=SzsANQcSgpq\u{200C}a5WgOrklNRy",
        "SzsANQcSgpqa5WgOrklNRy",
    );
}

#[test]
fn adv104_mandrill_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "mandrill-api-key",
        "MANDRILL=SzsANQcSgpq\u{200D}a5WgOrklNRy",
        "SzsANQcSgpqa5WgOrklNRy",
    );
}

#[test]
fn adv104_mandrill_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mandrill-api-key",
        "MANDRILL=SzsANQcSgpq\u{FEFF}a5WgOrklNRy",
        "SzsANQcSgpqa5WgOrklNRy",
    );
}

#[test]
fn adv104_mandrill_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mandrill-api-key",
        "MANDRILL=SzsANQcSgpq\u{2060}a5WgOrklNRy",
        "SzsANQcSgpqa5WgOrklNRy",
    );
}

#[test]
fn adv104_mandrill_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mandrill-api-key",
        "MANDRILL=SzsANQcSgpq\u{180E}a5WgOrklNRy",
        "SzsANQcSgpqa5WgOrklNRy",
    );
}

#[test]
fn adv104_mandrill_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "mandrill-api-key",
        "MANDRILL=SzsANQcSgpq\u{202E}a5WgOrklNRy",
        "SzsANQcSgpqa5WgOrklNRy",
    );
}

#[test]
fn adv104_mandrill_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mandrill-api-key",
        "MANDRILL=SzsANQcSgpq\u{202C}a5WgOrklNRy",
        "SzsANQcSgpqa5WgOrklNRy",
    );
}

#[test]
fn adv104_mandrill_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "mandrill-api-key",
        "MANDRILL=SzsANQcSgpq\u{200E}a5WgOrklNRy",
        "SzsANQcSgpqa5WgOrklNRy",
    );
}


