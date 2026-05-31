//! Part 41 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates home, homebrew, honeybadger, honeycomb, hotjar, huawei, hubitat, hubspot, hubspot, huggingface detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. HOME ASSISTANT API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv41_home_assistant_api_token_normal_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "long_lived_access_token = \"homeassistant_long_lived_access_token_high_entropy_12345\"",
        "homeassistant_long_lived_access_token_high_entropy_12345",
    );
}

#[test]
fn adv41_home_assistant_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "home-assistant-api-token",
        "tong_lived_access_token = \"homeassistant_long_lived_access_token_high_entropy_12345\"",
    );
}

#[test]
fn adv41_home_assistant_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "long_lived_access_token = \"homeassistant_long_lived_access_token_high\u{200B}_entropy_12345\"",
        "homeassistant_long_lived_access_token_high_entropy_12345",
    );
}

#[test]
fn adv41_home_assistant_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "long_lived_access_token = \"homeassistant_long_lived_access_token_high\u{00AD}_entropy_12345\"",
        "homeassistant_long_lived_access_token_high_entropy_12345",
    );
}

#[test]
fn adv41_home_assistant_api_token_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "h\u{043e}m\u{0435}_\u{0430}ss\u{0456}st\u{0430}nt_token = \"homeassistant_long_lived_access_token_high_entropy_12345\"",
        "homeassistant_long_lived_access_token_high_entropy_12345",
    );
}

// =========================================================================
// 2. HOMEBREW API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv41_homebrew_api_token_normal_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN = \"ghp_HomebrewGithubTokenHighEntropySecret123\"",
        "ghp_HomebrewGithubTokenHighEntropySecret123",
    );
}

#[test]
fn adv41_homebrew_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "homebrew-api-token",
        "TOMEBREW_GITHUB_API_TOKEN = \"ghp_HomebrewGithubTokenHighEntropySecret123\"",
    );
}

#[test]
fn adv41_homebrew_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN = \"ghp_HomebrewGithubTokenHigh\u{200B}EntropySecret123\"",
        "ghp_HomebrewGithubTokenHighEntropySecret123",
    );
}

#[test]
fn adv41_homebrew_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN = \"ghp_HomebrewGithubTokenHigh\u{00AD}EntropySecret123\"",
        "ghp_HomebrewGithubTokenHighEntropySecret123",
    );
}

#[test]
fn adv41_homebrew_api_token_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "h\u{043e}m\u{0435}br\u{0435}w_api_token = \"ghp_HomebrewGithubTokenHighEntropySecret123\"",
        "ghp_HomebrewGithubTokenHighEntropySecret123",
    );
}

// =========================================================================
// 3. HONEYBADGER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv41_honeybadger_api_key_normal_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "HONEYBADGER_API_KEY = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv41_honeybadger_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "honeybadger-api-key",
        "TONEYBADGER_TOKEN = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
    );
}

#[test]
fn adv41_honeybadger_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "HONEYBADGER_API_KEY = \"a1b2c3d4e5f6a1b2\u{200B}c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv41_honeybadger_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "HONEYBADGER_API_KEY = \"a1b2c3d4e5f6a1b2\u{00AD}c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv41_honeybadger_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "h\u{043e}n\u{0435}yb\u{0430}dg\u{0435}r_api_key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

// =========================================================================
// 4. HONEYCOMB API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv41_honeycomb_api_key_normal_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "honeycomb = hcai_1234567890123456789012",
        "hcai_1234567890123456789012",
    );
}

#[test]
fn adv41_honeycomb_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "honeycomb-api-key",
        "honeycomb = tcai_1234567890123456789012",
    );
}

#[test]
fn adv41_honeycomb_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "honeycomb = hcai_\u{200B}1234567890123456789012",
        "hcai_1234567890123456789012",
    );
}

#[test]
fn adv41_honeycomb_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "honeycomb = hcai_12345678901234567890\u{00AD}12",
        "hcai_1234567890123456789012",
    );
}

#[test]
fn adv41_honeycomb_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "h\u{043e}n\u{0435}yc\u{043e}mb = hcai_1234567890123456789012",
        "hcai_1234567890123456789012",
    );
}

// =========================================================================
// 5. HOTJAR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv41_hotjar_api_key_normal_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID = \"hotjar_client_id_high_entropy_secret_123\"\nHOTJAR_CLIENT_SECRET = \"hotjar_client_secret_high_entropy_secret_123\"",
        "hotjar_client_id_high_entropy_secret_123",
    );
}

#[test]
fn adv41_hotjar_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hotjar-api-key",
        "TOTJAR_CLIENT_ID = \"hotjar_client_id_high_entropy_secret_123\"\nHOTJAR_CLIENT_SECRET = \"hotjar_client_secret_high_entropy_secret_123\"",
    );
}

#[test]
fn adv41_hotjar_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID = \"hotjar_client_id_high\u{200B}_entropy_secret_123\"\nHOTJAR_CLIENT_SECRET = \"hotjar_client_secret_high_entropy_secret_123\"",
        "hotjar_client_id_high_entropy_secret_123",
    );
}

#[test]
fn adv41_hotjar_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID = \"hotjar_client_id_high\u{00AD}_entropy_secret_123\"\nHOTJAR_CLIENT_SECRET = \"hotjar_client_secret_high_entropy_secret_123\"",
        "hotjar_client_id_high_entropy_secret_123",
    );
}

#[test]
fn adv41_hotjar_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "h\u{043e}tj\u{0430}r_client_id = \"hotjar_client_id_high_entropy_secret_123\"\nHOTJAR_CLIENT_SECRET = \"hotjar_client_secret_high_entropy_secret_123\"",
        "hotjar_client_id_high_entropy_secret_123",
    );
}

// =========================================================================
// 6. HUAWEI CLOUD API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv41_huawei_cloud_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HW_ACCESS_KEY = \"HUAWEICLOUDACCESSKEY12345\"\nHW_SECRET_KEY = \"HuaweiCloudSecretKey1234567890abcdef\"",
        "HUAWEICLOUDACCESSKEY12345",
    );
}

#[test]
fn adv41_huawei_cloud_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "huawei-cloud-api-credentials",
        "TW_ACCESS_KEY = \"HUAWEICLOUDACCESSKEY12345\"\nTW_SECRET_KEY = \"HuaweiCloudSecretKey1234567890abcdef\"",
    );
}

#[test]
fn adv41_huawei_cloud_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HW_ACCESS_KEY = \"HUAWEICLOUDACCESS\u{200B}KEY12345\"\nHW_SECRET_KEY = \"HuaweiCloudSecretKey1234567890abcdef\"",
        "HUAWEICLOUDACCESSKEY12345",
    );
}

#[test]
fn adv41_huawei_cloud_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HW_ACCESS_KEY = \"HUAWEICLOUDACCESS\u{00AD}KEY12345\"\nHW_SECRET_KEY = \"HuaweiCloudSecretKey1234567890abcdef\"",
        "HUAWEICLOUDACCESSKEY12345",
    );
}

#[test]
fn adv41_huawei_cloud_api_credentials_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HW_\u{0430}cc\u{0435}ss_key = \"HUAWEICLOUDACCESSKEY12345\"\nHW_SECRET_KEY = \"HuaweiCloudSecretKey1234567890abcdef\"",
        "HUAWEICLOUDACCESSKEY12345",
    );
}

// =========================================================================
// 7. HUBITAT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv41_hubitat_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "access_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"\nhubitat_app_id = \"12345\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv41_hubitat_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hubitat-api-credentials",
        "tccess_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"\ntubitat_app_id = \"12345\"",
    );
}

#[test]
fn adv41_hubitat_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "access_token = \"a1b2c3d4e5f6a1b2\u{200B}c3d4e5f6a1b2c3d4\"\nhubitat_app_id = \"12345\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv41_hubitat_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "access_token = \"a1b2c3d4e5f6a1b2\u{00AD}c3d4e5f6a1b2c3d4\"\nhubitat_app_id = \"12345\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv41_hubitat_api_credentials_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "h\u{043e}b\u{0456}t\u{0430}t_access_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"\nhubitat_app_id = \"12345\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

// =========================================================================
// 8. HUBSPOT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv41_hubspot_api_key_normal_must_fire() {
    assert_detector_fires(
        "hubspot-api-key",
        "HUBSPOT_API_KEY = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-us1\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-us1",
    );
}

#[test]
fn adv41_hubspot_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hubspot-api-key",
        "TUBSPOT_API_KEY = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-us1\"",
    );
}

#[test]
fn adv41_hubspot_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hubspot-api-key",
        "HUBSPOT_API_KEY = \"a1b2c3d4e5f6a1b2\u{200B}c3d4e5f6a1b2c3d4-us1\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-us1",
    );
}

#[test]
fn adv41_hubspot_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hubspot-api-key",
        "HUBSPOT_API_KEY = \"a1b2c3d4e5f6a1b2\u{00AD}c3d4e5f6a1b2c3d4-us1\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-us1",
    );
}

#[test]
fn adv41_hubspot_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hubspot-api-key",
        "h\u{043e}bsp\u{043e}t_api_key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-us1\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-us1",
    );
}

// =========================================================================
// 9. HUBSPOT PRIVATE APP TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv41_hubspot_private_app_token_normal_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "hubspot = pat-na1-12345678-abcd-1234-abcd-1234567890ab",
        "pat-na1-12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv41_hubspot_private_app_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hubspot-private-app-token",
        "hubspot = tat-na1-12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv41_hubspot_private_app_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "hubspot = pat-na1-12345678-abcd-1234-abcd-1234\u{200B}567890ab",
        "pat-na1-12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv41_hubspot_private_app_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "hubspot = pat-na1-12345678-abcd-1234-abcd-123456\u{00AD}7890ab",
        "pat-na1-12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv41_hubspot_private_app_token_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "h\u{043e}bsp\u{043e}t = pat-na1-12345678-abcd-1234-abcd-1234567890ab",
        "pat-na1-12345678-abcd-1234-abcd-1234567890ab",
    );
}

// =========================================================================
// 10. HUGGINGFACE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv41_huggingface_api_key_normal_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "huggingface = hf_1234567890123456789012345678901234",
        "hf_1234567890123456789012345678901234",
    );
}

#[test]
fn adv41_huggingface_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "huggingface-api-key",
        "huggingface = tf_1234567890123456789012345678901234",
    );
}

#[test]
fn adv41_huggingface_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "huggingface = hf_12345678901234567890123456789\u{200B}01234",
        "hf_1234567890123456789012345678901234",
    );
}

#[test]
fn adv41_huggingface_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "huggingface = hf_123456789012345678901234567890\u{00AD}1234",
        "hf_1234567890123456789012345678901234",
    );
}

#[test]
fn adv41_huggingface_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hugg\u{0456}ngf\u{0430}c\u{0435} = hf_1234567890123456789012345678901234",
        "hf_1234567890123456789012345678901234",
    );
}
