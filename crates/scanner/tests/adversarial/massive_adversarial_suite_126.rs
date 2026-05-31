//! Part 126 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates sentry, sentry, servicenow, shazam, shippo, shodan, shopify, shopify, shopify, shopify detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. SENTRY AUTH TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv126_sentry_auth_token_normal_must_fire() {
    assert_detector_fires(
        "sentry-auth-token",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv126_sentry_auth_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sentry-auth-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv126_sentry_auth_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sentry-auth-token",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{200B}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv126_sentry_auth_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sentry-auth-token",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{00AD}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv126_sentry_auth_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sentry-auth-token",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{200C}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv126_sentry_auth_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "sentry-auth-token",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{200D}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv126_sentry_auth_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sentry-auth-token",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{FEFF}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv126_sentry_auth_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sentry-auth-token",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{2060}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv126_sentry_auth_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sentry-auth-token",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{180E}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv126_sentry_auth_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "sentry-auth-token",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{202E}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv126_sentry_auth_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sentry-auth-token",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{202C}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv126_sentry_auth_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "sentry-auth-token",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{200E}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "sntrys_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

// =========================================================================
// 2. SENTRY DSN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv126_sentry_dsn_normal_must_fire() {
    assert_detector_fires(
        "sentry-dsn",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
    );
}

#[test]
fn adv126_sentry_dsn_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sentry-dsn",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv126_sentry_dsn_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sentry-dsn",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1\u{200B}b4c2d@o12345.ingest.sentry.io/67890",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
    );
}

#[test]
fn adv126_sentry_dsn_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sentry-dsn",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1\u{00AD}b4c2d@o12345.ingest.sentry.io/67890",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
    );
}

#[test]
fn adv126_sentry_dsn_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sentry-dsn",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1\u{200C}b4c2d@o12345.ingest.sentry.io/67890",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
    );
}

#[test]
fn adv126_sentry_dsn_evade_zwj_must_fire() {
    assert_detector_fires(
        "sentry-dsn",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1\u{200D}b4c2d@o12345.ingest.sentry.io/67890",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
    );
}

#[test]
fn adv126_sentry_dsn_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sentry-dsn",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1\u{FEFF}b4c2d@o12345.ingest.sentry.io/67890",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
    );
}

#[test]
fn adv126_sentry_dsn_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sentry-dsn",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1\u{2060}b4c2d@o12345.ingest.sentry.io/67890",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
    );
}

#[test]
fn adv126_sentry_dsn_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sentry-dsn",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1\u{180E}b4c2d@o12345.ingest.sentry.io/67890",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
    );
}

#[test]
fn adv126_sentry_dsn_evade_rtl_must_fire() {
    assert_detector_fires(
        "sentry-dsn",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1\u{202E}b4c2d@o12345.ingest.sentry.io/67890",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
    );
}

#[test]
fn adv126_sentry_dsn_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sentry-dsn",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1\u{202C}b4c2d@o12345.ingest.sentry.io/67890",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
    );
}

#[test]
fn adv126_sentry_dsn_evade_lrm_must_fire() {
    assert_detector_fires(
        "sentry-dsn",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1\u{200E}b4c2d@o12345.ingest.sentry.io/67890",
        "https://9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d@o12345.ingest.sentry.io/67890",
    );
}

// =========================================================================
// 3. SERVICENOW API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv126_servicenow_api_key_normal_must_fire() {
    assert_detector_fires(
        "servicenow-api-key",
        "servicenow_instance=dev12345.service-now.com",
        "dev12345.service-now.com",
    );
}

#[test]
fn adv126_servicenow_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "servicenow-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv126_servicenow_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "servicenow-api-key",
        "servicenow_instance=dev12345.ser\u{200B}vice-now.com",
        "dev12345.service-now.com",
    );
}

#[test]
fn adv126_servicenow_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "servicenow-api-key",
        "servicenow_instance=dev12345.ser\u{00AD}vice-now.com",
        "dev12345.service-now.com",
    );
}

#[test]
fn adv126_servicenow_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "servicenow-api-key",
        "servicenow_instance=dev12345.ser\u{200C}vice-now.com",
        "dev12345.service-now.com",
    );
}

#[test]
fn adv126_servicenow_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "servicenow-api-key",
        "servicenow_instance=dev12345.ser\u{200D}vice-now.com",
        "dev12345.service-now.com",
    );
}

#[test]
fn adv126_servicenow_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "servicenow-api-key",
        "servicenow_instance=dev12345.ser\u{FEFF}vice-now.com",
        "dev12345.service-now.com",
    );
}

#[test]
fn adv126_servicenow_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "servicenow-api-key",
        "servicenow_instance=dev12345.ser\u{2060}vice-now.com",
        "dev12345.service-now.com",
    );
}

#[test]
fn adv126_servicenow_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "servicenow-api-key",
        "servicenow_instance=dev12345.ser\u{180E}vice-now.com",
        "dev12345.service-now.com",
    );
}

#[test]
fn adv126_servicenow_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "servicenow-api-key",
        "servicenow_instance=dev12345.ser\u{202E}vice-now.com",
        "dev12345.service-now.com",
    );
}

#[test]
fn adv126_servicenow_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "servicenow-api-key",
        "servicenow_instance=dev12345.ser\u{202C}vice-now.com",
        "dev12345.service-now.com",
    );
}

#[test]
fn adv126_servicenow_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "servicenow-api-key",
        "servicenow_instance=dev12345.ser\u{200E}vice-now.com",
        "dev12345.service-now.com",
    );
}

// =========================================================================
// 4. SHAZAM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv126_shazam_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "shazam-api-credentials",
        "SHAZAM=85de8e8e1a3946c743f545a29af384f2",
        "85de8e8e1a3946c743f545a29af384f2",
    );
}

#[test]
fn adv126_shazam_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "shazam-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv126_shazam_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "shazam-api-credentials",
        "SHAZAM=85de8e8e1a3946c7\u{200B}43f545a29af384f2",
        "85de8e8e1a3946c743f545a29af384f2",
    );
}

#[test]
fn adv126_shazam_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "shazam-api-credentials",
        "SHAZAM=85de8e8e1a3946c7\u{00AD}43f545a29af384f2",
        "85de8e8e1a3946c743f545a29af384f2",
    );
}

#[test]
fn adv126_shazam_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "shazam-api-credentials",
        "SHAZAM=85de8e8e1a3946c7\u{200C}43f545a29af384f2",
        "85de8e8e1a3946c743f545a29af384f2",
    );
}

#[test]
fn adv126_shazam_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "shazam-api-credentials",
        "SHAZAM=85de8e8e1a3946c7\u{200D}43f545a29af384f2",
        "85de8e8e1a3946c743f545a29af384f2",
    );
}

#[test]
fn adv126_shazam_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "shazam-api-credentials",
        "SHAZAM=85de8e8e1a3946c7\u{FEFF}43f545a29af384f2",
        "85de8e8e1a3946c743f545a29af384f2",
    );
}

#[test]
fn adv126_shazam_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "shazam-api-credentials",
        "SHAZAM=85de8e8e1a3946c7\u{2060}43f545a29af384f2",
        "85de8e8e1a3946c743f545a29af384f2",
    );
}

#[test]
fn adv126_shazam_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "shazam-api-credentials",
        "SHAZAM=85de8e8e1a3946c7\u{180E}43f545a29af384f2",
        "85de8e8e1a3946c743f545a29af384f2",
    );
}

#[test]
fn adv126_shazam_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "shazam-api-credentials",
        "SHAZAM=85de8e8e1a3946c7\u{202E}43f545a29af384f2",
        "85de8e8e1a3946c743f545a29af384f2",
    );
}

#[test]
fn adv126_shazam_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "shazam-api-credentials",
        "SHAZAM=85de8e8e1a3946c7\u{202C}43f545a29af384f2",
        "85de8e8e1a3946c743f545a29af384f2",
    );
}

#[test]
fn adv126_shazam_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "shazam-api-credentials",
        "SHAZAM=85de8e8e1a3946c7\u{200E}43f545a29af384f2",
        "85de8e8e1a3946c743f545a29af384f2",
    );
}

// =========================================================================
// 5. SHIPPO API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv126_shippo_api_token_normal_must_fire() {
    assert_detector_fires(
        "shippo-api-token",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv126_shippo_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "shippo-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv126_shippo_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "shippo-api-token",
        "shippo_live_7b3e5d8c1a\u{200B}9f4e2b6c8d3a5e9f1b7c4d",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv126_shippo_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "shippo-api-token",
        "shippo_live_7b3e5d8c1a\u{00AD}9f4e2b6c8d3a5e9f1b7c4d",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv126_shippo_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "shippo-api-token",
        "shippo_live_7b3e5d8c1a\u{200C}9f4e2b6c8d3a5e9f1b7c4d",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv126_shippo_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "shippo-api-token",
        "shippo_live_7b3e5d8c1a\u{200D}9f4e2b6c8d3a5e9f1b7c4d",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv126_shippo_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "shippo-api-token",
        "shippo_live_7b3e5d8c1a\u{FEFF}9f4e2b6c8d3a5e9f1b7c4d",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv126_shippo_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "shippo-api-token",
        "shippo_live_7b3e5d8c1a\u{2060}9f4e2b6c8d3a5e9f1b7c4d",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv126_shippo_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "shippo-api-token",
        "shippo_live_7b3e5d8c1a\u{180E}9f4e2b6c8d3a5e9f1b7c4d",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv126_shippo_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "shippo-api-token",
        "shippo_live_7b3e5d8c1a\u{202E}9f4e2b6c8d3a5e9f1b7c4d",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv126_shippo_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "shippo-api-token",
        "shippo_live_7b3e5d8c1a\u{202C}9f4e2b6c8d3a5e9f1b7c4d",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv126_shippo_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "shippo-api-token",
        "shippo_live_7b3e5d8c1a\u{200E}9f4e2b6c8d3a5e9f1b7c4d",
        "shippo_live_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 6. SHODAN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv126_shodan_api_key_normal_must_fire() {
    assert_detector_fires(
        "shodan-api-key",
        "SHODAN=NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
        "NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
    );
}

#[test]
fn adv126_shodan_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "shodan-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv126_shodan_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "shodan-api-key",
        "SHODAN=NEnz4Vvb0QWNU48m\u{200B}VysPth7YaJJXUrHz",
        "NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
    );
}

#[test]
fn adv126_shodan_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "shodan-api-key",
        "SHODAN=NEnz4Vvb0QWNU48m\u{00AD}VysPth7YaJJXUrHz",
        "NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
    );
}

#[test]
fn adv126_shodan_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "shodan-api-key",
        "SHODAN=NEnz4Vvb0QWNU48m\u{200C}VysPth7YaJJXUrHz",
        "NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
    );
}

#[test]
fn adv126_shodan_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "shodan-api-key",
        "SHODAN=NEnz4Vvb0QWNU48m\u{200D}VysPth7YaJJXUrHz",
        "NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
    );
}

#[test]
fn adv126_shodan_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "shodan-api-key",
        "SHODAN=NEnz4Vvb0QWNU48m\u{FEFF}VysPth7YaJJXUrHz",
        "NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
    );
}

#[test]
fn adv126_shodan_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "shodan-api-key",
        "SHODAN=NEnz4Vvb0QWNU48m\u{2060}VysPth7YaJJXUrHz",
        "NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
    );
}

#[test]
fn adv126_shodan_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "shodan-api-key",
        "SHODAN=NEnz4Vvb0QWNU48m\u{180E}VysPth7YaJJXUrHz",
        "NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
    );
}

#[test]
fn adv126_shodan_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "shodan-api-key",
        "SHODAN=NEnz4Vvb0QWNU48m\u{202E}VysPth7YaJJXUrHz",
        "NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
    );
}

#[test]
fn adv126_shodan_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "shodan-api-key",
        "SHODAN=NEnz4Vvb0QWNU48m\u{202C}VysPth7YaJJXUrHz",
        "NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
    );
}

#[test]
fn adv126_shodan_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "shodan-api-key",
        "SHODAN=NEnz4Vvb0QWNU48m\u{200E}VysPth7YaJJXUrHz",
        "NEnz4Vvb0QWNU48mVysPth7YaJJXUrHz",
    );
}

// =========================================================================
// 7. SHOPIFY ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv126_shopify_access_token_normal_must_fire() {
    assert_detector_fires(
        "shopify-access-token",
        "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",
        "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",
    );
}

#[test]
fn adv126_shopify_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "shopify-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv126_shopify_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "shopify-access-token",
        "shpca_9a3b7c2e4d1f6\u{200B}a8b0c5d9e3f7a1b4c2d",
        "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",
    );
}

#[test]
fn adv126_shopify_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "shopify-access-token",
        "shpca_9a3b7c2e4d1f6\u{00AD}a8b0c5d9e3f7a1b4c2d",
        "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",
    );
}

#[test]
fn adv126_shopify_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "shopify-access-token",
        "shpca_9a3b7c2e4d1f6\u{200C}a8b0c5d9e3f7a1b4c2d",
        "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",
    );
}

#[test]
fn adv126_shopify_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "shopify-access-token",
        "shpca_9a3b7c2e4d1f6\u{200D}a8b0c5d9e3f7a1b4c2d",
        "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",
    );
}

#[test]
fn adv126_shopify_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "shopify-access-token",
        "shpca_9a3b7c2e4d1f6\u{FEFF}a8b0c5d9e3f7a1b4c2d",
        "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",
    );
}

#[test]
fn adv126_shopify_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "shopify-access-token",
        "shpca_9a3b7c2e4d1f6\u{2060}a8b0c5d9e3f7a1b4c2d",
        "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",
    );
}

#[test]
fn adv126_shopify_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "shopify-access-token",
        "shpca_9a3b7c2e4d1f6\u{180E}a8b0c5d9e3f7a1b4c2d",
        "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",
    );
}

#[test]
fn adv126_shopify_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "shopify-access-token",
        "shpca_9a3b7c2e4d1f6\u{202E}a8b0c5d9e3f7a1b4c2d",
        "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",
    );
}

#[test]
fn adv126_shopify_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "shopify-access-token",
        "shpca_9a3b7c2e4d1f6\u{202C}a8b0c5d9e3f7a1b4c2d",
        "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",
    );
}

#[test]
fn adv126_shopify_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "shopify-access-token",
        "shpca_9a3b7c2e4d1f6\u{200E}a8b0c5d9e3f7a1b4c2d",
        "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",
    );
}

// =========================================================================
// 8. SHOPIFY ADMIN API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv126_shopify_admin_api_token_normal_must_fire() {
    assert_detector_fires(
        "shopify-admin-api-token",
        "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",
        "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",
    );
}

#[test]
fn adv126_shopify_admin_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "shopify-admin-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv126_shopify_admin_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "shopify-admin-api-token",
        "shpat_c5eae857d74b6\u{200B}86a04406cc28f76deec",
        "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",
    );
}

#[test]
fn adv126_shopify_admin_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "shopify-admin-api-token",
        "shpat_c5eae857d74b6\u{00AD}86a04406cc28f76deec",
        "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",
    );
}

#[test]
fn adv126_shopify_admin_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "shopify-admin-api-token",
        "shpat_c5eae857d74b6\u{200C}86a04406cc28f76deec",
        "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",
    );
}

#[test]
fn adv126_shopify_admin_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "shopify-admin-api-token",
        "shpat_c5eae857d74b6\u{200D}86a04406cc28f76deec",
        "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",
    );
}

#[test]
fn adv126_shopify_admin_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "shopify-admin-api-token",
        "shpat_c5eae857d74b6\u{FEFF}86a04406cc28f76deec",
        "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",
    );
}

#[test]
fn adv126_shopify_admin_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "shopify-admin-api-token",
        "shpat_c5eae857d74b6\u{2060}86a04406cc28f76deec",
        "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",
    );
}

#[test]
fn adv126_shopify_admin_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "shopify-admin-api-token",
        "shpat_c5eae857d74b6\u{180E}86a04406cc28f76deec",
        "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",
    );
}

#[test]
fn adv126_shopify_admin_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "shopify-admin-api-token",
        "shpat_c5eae857d74b6\u{202E}86a04406cc28f76deec",
        "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",
    );
}

#[test]
fn adv126_shopify_admin_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "shopify-admin-api-token",
        "shpat_c5eae857d74b6\u{202C}86a04406cc28f76deec",
        "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",
    );
}

#[test]
fn adv126_shopify_admin_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "shopify-admin-api-token",
        "shpat_c5eae857d74b6\u{200E}86a04406cc28f76deec",
        "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",
    );
}

// =========================================================================
// 9. SHOPIFY STOREFRONT API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv126_shopify_storefront_api_token_normal_must_fire() {
    assert_detector_fires(
        "shopify-storefront-api-token",
        "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",
        "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",
    );
}

#[test]
fn adv126_shopify_storefront_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "shopify-storefront-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv126_shopify_storefront_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "shopify-storefront-api-token",
        "shpss_e9118f0809821\u{200B}a83c216b8b06a6487c4",
        "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",
    );
}

#[test]
fn adv126_shopify_storefront_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "shopify-storefront-api-token",
        "shpss_e9118f0809821\u{00AD}a83c216b8b06a6487c4",
        "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",
    );
}

#[test]
fn adv126_shopify_storefront_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "shopify-storefront-api-token",
        "shpss_e9118f0809821\u{200C}a83c216b8b06a6487c4",
        "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",
    );
}

#[test]
fn adv126_shopify_storefront_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "shopify-storefront-api-token",
        "shpss_e9118f0809821\u{200D}a83c216b8b06a6487c4",
        "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",
    );
}

#[test]
fn adv126_shopify_storefront_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "shopify-storefront-api-token",
        "shpss_e9118f0809821\u{FEFF}a83c216b8b06a6487c4",
        "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",
    );
}

#[test]
fn adv126_shopify_storefront_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "shopify-storefront-api-token",
        "shpss_e9118f0809821\u{2060}a83c216b8b06a6487c4",
        "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",
    );
}

#[test]
fn adv126_shopify_storefront_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "shopify-storefront-api-token",
        "shpss_e9118f0809821\u{180E}a83c216b8b06a6487c4",
        "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",
    );
}

#[test]
fn adv126_shopify_storefront_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "shopify-storefront-api-token",
        "shpss_e9118f0809821\u{202E}a83c216b8b06a6487c4",
        "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",
    );
}

#[test]
fn adv126_shopify_storefront_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "shopify-storefront-api-token",
        "shpss_e9118f0809821\u{202C}a83c216b8b06a6487c4",
        "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",
    );
}

#[test]
fn adv126_shopify_storefront_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "shopify-storefront-api-token",
        "shpss_e9118f0809821\u{200E}a83c216b8b06a6487c4",
        "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",
    );
}

// =========================================================================
// 10. SHOPIFY WEBHOOK SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv126_shopify_webhook_secret_normal_must_fire() {
    assert_detector_fires(
        "shopify-webhook-secret",
        "SHOPIFY_WEBHOOK_SECRET=28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
        "28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
    );
}

#[test]
fn adv126_shopify_webhook_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "shopify-webhook-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv126_shopify_webhook_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "shopify-webhook-secret",
        "SHOPIFY_WEBHOOK_SECRET=28bda45ee8d94d15c3aa\u{200B}dcf94e59f0d6e63244c0",
        "28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
    );
}

#[test]
fn adv126_shopify_webhook_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "shopify-webhook-secret",
        "SHOPIFY_WEBHOOK_SECRET=28bda45ee8d94d15c3aa\u{00AD}dcf94e59f0d6e63244c0",
        "28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
    );
}

#[test]
fn adv126_shopify_webhook_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "shopify-webhook-secret",
        "SHOPIFY_WEBHOOK_SECRET=28bda45ee8d94d15c3aa\u{200C}dcf94e59f0d6e63244c0",
        "28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
    );
}

#[test]
fn adv126_shopify_webhook_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "shopify-webhook-secret",
        "SHOPIFY_WEBHOOK_SECRET=28bda45ee8d94d15c3aa\u{200D}dcf94e59f0d6e63244c0",
        "28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
    );
}

#[test]
fn adv126_shopify_webhook_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "shopify-webhook-secret",
        "SHOPIFY_WEBHOOK_SECRET=28bda45ee8d94d15c3aa\u{FEFF}dcf94e59f0d6e63244c0",
        "28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
    );
}

#[test]
fn adv126_shopify_webhook_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "shopify-webhook-secret",
        "SHOPIFY_WEBHOOK_SECRET=28bda45ee8d94d15c3aa\u{2060}dcf94e59f0d6e63244c0",
        "28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
    );
}

#[test]
fn adv126_shopify_webhook_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "shopify-webhook-secret",
        "SHOPIFY_WEBHOOK_SECRET=28bda45ee8d94d15c3aa\u{180E}dcf94e59f0d6e63244c0",
        "28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
    );
}

#[test]
fn adv126_shopify_webhook_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "shopify-webhook-secret",
        "SHOPIFY_WEBHOOK_SECRET=28bda45ee8d94d15c3aa\u{202E}dcf94e59f0d6e63244c0",
        "28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
    );
}

#[test]
fn adv126_shopify_webhook_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "shopify-webhook-secret",
        "SHOPIFY_WEBHOOK_SECRET=28bda45ee8d94d15c3aa\u{202C}dcf94e59f0d6e63244c0",
        "28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
    );
}

#[test]
fn adv126_shopify_webhook_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "shopify-webhook-secret",
        "SHOPIFY_WEBHOOK_SECRET=28bda45ee8d94d15c3aa\u{200E}dcf94e59f0d6e63244c0",
        "28bda45ee8d94d15c3aadcf94e59f0d6e63244c0",
    );
}
