//! Part 64 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates airtable, akamai, alchemy, alertmanager, algolia, algolia, algolia, alienvault, amadeus, amazon detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. AIRTABLE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv64_airtable_api_key_normal_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv64_airtable_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "airtable-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv64_airtable_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3\u{200B}f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv64_airtable_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3\u{00AD}f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv64_airtable_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3\u{200C}f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv64_airtable_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3\u{200D}f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv64_airtable_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3\u{FEFF}f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv64_airtable_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3\u{2060}f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv64_airtable_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3\u{180E}f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv64_airtable_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3\u{202E}f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv64_airtable_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3\u{202C}f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv64_airtable_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3\u{200E}f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

// =========================================================================
// 2. AKAMAI API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv64_akamai_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "akamai-api-credentials",
        "client_token=akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
        "akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv64_akamai_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "akamai-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv64_akamai_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "akamai-api-credentials",
        "client_token=akab-Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm2SnTb",
        "akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv64_akamai_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "akamai-api-credentials",
        "client_token=akab-Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm2SnTb",
        "akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv64_akamai_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "akamai-api-credentials",
        "client_token=akab-Kp4Qx7Rm2Sn5Tb\u{200C}8Vw3YzKp4Qx7Rm2SnTb",
        "akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv64_akamai_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "akamai-api-credentials",
        "client_token=akab-Kp4Qx7Rm2Sn5Tb\u{200D}8Vw3YzKp4Qx7Rm2SnTb",
        "akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv64_akamai_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "akamai-api-credentials",
        "client_token=akab-Kp4Qx7Rm2Sn5Tb\u{FEFF}8Vw3YzKp4Qx7Rm2SnTb",
        "akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv64_akamai_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "akamai-api-credentials",
        "client_token=akab-Kp4Qx7Rm2Sn5Tb\u{2060}8Vw3YzKp4Qx7Rm2SnTb",
        "akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv64_akamai_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "akamai-api-credentials",
        "client_token=akab-Kp4Qx7Rm2Sn5Tb\u{180E}8Vw3YzKp4Qx7Rm2SnTb",
        "akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv64_akamai_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "akamai-api-credentials",
        "client_token=akab-Kp4Qx7Rm2Sn5Tb\u{202E}8Vw3YzKp4Qx7Rm2SnTb",
        "akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv64_akamai_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "akamai-api-credentials",
        "client_token=akab-Kp4Qx7Rm2Sn5Tb\u{202C}8Vw3YzKp4Qx7Rm2SnTb",
        "akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv64_akamai_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "akamai-api-credentials",
        "client_token=akab-Kp4Qx7Rm2Sn5Tb\u{200E}8Vw3YzKp4Qx7Rm2SnTb",
        "akab-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

// =========================================================================
// 3. ALCHEMY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv64_alchemy_api_key_normal_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_alchemy_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "alchemy-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv64_alchemy_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_alchemy_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_alchemy_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_alchemy_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_alchemy_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_alchemy_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_alchemy_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_alchemy_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_alchemy_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_alchemy_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 4. ALERTMANAGER CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv64_alertmanager_credentials_normal_must_fire() {
    assert_detector_fires(
        "alertmanager-credentials",
        "ALERTMANAGER_USER=admin_user_kp4qx7rm2sn",
        "admin_user_kp4qx7rm2sn",
    );
}

#[test]
fn adv64_alertmanager_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "alertmanager-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv64_alertmanager_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "alertmanager-credentials",
        "ALERTMANAGER_USER=admin_user_\u{200B}kp4qx7rm2sn",
        "admin_user_kp4qx7rm2sn",
    );
}

#[test]
fn adv64_alertmanager_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "alertmanager-credentials",
        "ALERTMANAGER_USER=admin_user_\u{00AD}kp4qx7rm2sn",
        "admin_user_kp4qx7rm2sn",
    );
}

#[test]
fn adv64_alertmanager_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "alertmanager-credentials",
        "ALERTMANAGER_USER=admin_user_\u{200C}kp4qx7rm2sn",
        "admin_user_kp4qx7rm2sn",
    );
}

#[test]
fn adv64_alertmanager_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "alertmanager-credentials",
        "ALERTMANAGER_USER=admin_user_\u{200D}kp4qx7rm2sn",
        "admin_user_kp4qx7rm2sn",
    );
}

#[test]
fn adv64_alertmanager_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "alertmanager-credentials",
        "ALERTMANAGER_USER=admin_user_\u{FEFF}kp4qx7rm2sn",
        "admin_user_kp4qx7rm2sn",
    );
}

#[test]
fn adv64_alertmanager_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "alertmanager-credentials",
        "ALERTMANAGER_USER=admin_user_\u{2060}kp4qx7rm2sn",
        "admin_user_kp4qx7rm2sn",
    );
}

#[test]
fn adv64_alertmanager_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "alertmanager-credentials",
        "ALERTMANAGER_USER=admin_user_\u{180E}kp4qx7rm2sn",
        "admin_user_kp4qx7rm2sn",
    );
}

#[test]
fn adv64_alertmanager_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "alertmanager-credentials",
        "ALERTMANAGER_USER=admin_user_\u{202E}kp4qx7rm2sn",
        "admin_user_kp4qx7rm2sn",
    );
}

#[test]
fn adv64_alertmanager_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "alertmanager-credentials",
        "ALERTMANAGER_USER=admin_user_\u{202C}kp4qx7rm2sn",
        "admin_user_kp4qx7rm2sn",
    );
}

#[test]
fn adv64_alertmanager_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "alertmanager-credentials",
        "ALERTMANAGER_USER=admin_user_\u{200E}kp4qx7rm2sn",
        "admin_user_kp4qx7rm2sn",
    );
}

// =========================================================================
// 5. ALGOLIA ADMIN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv64_algolia_admin_api_key_normal_must_fire() {
    assert_detector_fires(
        "algolia-admin-api-key",
        "ALGOLIA_ADMIN_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_admin_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "algolia-admin-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv64_algolia_admin_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "algolia-admin-api-key",
        "ALGOLIA_ADMIN_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_admin_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "algolia-admin-api-key",
        "ALGOLIA_ADMIN_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_admin_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "algolia-admin-api-key",
        "ALGOLIA_ADMIN_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_admin_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "algolia-admin-api-key",
        "ALGOLIA_ADMIN_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_admin_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "algolia-admin-api-key",
        "ALGOLIA_ADMIN_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_admin_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "algolia-admin-api-key",
        "ALGOLIA_ADMIN_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_admin_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "algolia-admin-api-key",
        "ALGOLIA_ADMIN_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_admin_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "algolia-admin-api-key",
        "ALGOLIA_ADMIN_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_admin_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "algolia-admin-api-key",
        "ALGOLIA_ADMIN_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_admin_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "algolia-admin-api-key",
        "ALGOLIA_ADMIN_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 6. ALGOLIA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv64_algolia_api_key_normal_must_fire() {
    assert_detector_fires(
        "algolia-api-key",
        "ALGOLIA_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "algolia-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv64_algolia_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "algolia-api-key",
        "ALGOLIA_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "algolia-api-key",
        "ALGOLIA_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "algolia-api-key",
        "ALGOLIA_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "algolia-api-key",
        "ALGOLIA_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "algolia-api-key",
        "ALGOLIA_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "algolia-api-key",
        "ALGOLIA_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "algolia-api-key",
        "ALGOLIA_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "algolia-api-key",
        "ALGOLIA_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "algolia-api-key",
        "ALGOLIA_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "algolia-api-key",
        "ALGOLIA_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 7. ALGOLIA SEARCH KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv64_algolia_search_key_normal_must_fire() {
    assert_detector_fires(
        "algolia-search-key",
        "ALGOLIA_SEARCH_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_search_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "algolia-search-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv64_algolia_search_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "algolia-search-key",
        "ALGOLIA_SEARCH_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_search_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "algolia-search-key",
        "ALGOLIA_SEARCH_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_search_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "algolia-search-key",
        "ALGOLIA_SEARCH_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_search_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "algolia-search-key",
        "ALGOLIA_SEARCH_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_search_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "algolia-search-key",
        "ALGOLIA_SEARCH_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_search_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "algolia-search-key",
        "ALGOLIA_SEARCH_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_search_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "algolia-search-key",
        "ALGOLIA_SEARCH_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_search_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "algolia-search-key",
        "ALGOLIA_SEARCH_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_search_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "algolia-search-key",
        "ALGOLIA_SEARCH_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv64_algolia_search_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "algolia-search-key",
        "ALGOLIA_SEARCH_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 8. ALIENVAULT OTX API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv64_alienvault_otx_api_key_normal_must_fire() {
    assert_detector_fires(
        "alienvault-otx-api-key",
        "OTX_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
    );
}

#[test]
fn adv64_alienvault_otx_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "alienvault-otx-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv64_alienvault_otx_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "alienvault-otx-api-key",
        "OTX_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200B}8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
    );
}

#[test]
fn adv64_alienvault_otx_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "alienvault-otx-api-key",
        "OTX_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{00AD}8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
    );
}

#[test]
fn adv64_alienvault_otx_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "alienvault-otx-api-key",
        "OTX_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200C}8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
    );
}

#[test]
fn adv64_alienvault_otx_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "alienvault-otx-api-key",
        "OTX_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200D}8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
    );
}

#[test]
fn adv64_alienvault_otx_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "alienvault-otx-api-key",
        "OTX_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{FEFF}8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
    );
}

#[test]
fn adv64_alienvault_otx_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "alienvault-otx-api-key",
        "OTX_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{2060}8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
    );
}

#[test]
fn adv64_alienvault_otx_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "alienvault-otx-api-key",
        "OTX_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{180E}8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
    );
}

#[test]
fn adv64_alienvault_otx_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "alienvault-otx-api-key",
        "OTX_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202E}8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
    );
}

#[test]
fn adv64_alienvault_otx_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "alienvault-otx-api-key",
        "OTX_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202C}8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
    );
}

#[test]
fn adv64_alienvault_otx_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "alienvault-otx-api-key",
        "OTX_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200E}8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f0c3d7e1a5f8c2b9d6a3c4e1f",
    );
}

// =========================================================================
// 9. AMADEUS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv64_amadeus_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "amadeus-api-credentials",
        "AMADEUS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv64_amadeus_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "amadeus-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv64_amadeus_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "amadeus-api-credentials",
        "AMADEUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv64_amadeus_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "amadeus-api-credentials",
        "AMADEUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv64_amadeus_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "amadeus-api-credentials",
        "AMADEUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv64_amadeus_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "amadeus-api-credentials",
        "AMADEUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv64_amadeus_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "amadeus-api-credentials",
        "AMADEUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv64_amadeus_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "amadeus-api-credentials",
        "AMADEUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv64_amadeus_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "amadeus-api-credentials",
        "AMADEUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv64_amadeus_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "amadeus-api-credentials",
        "AMADEUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv64_amadeus_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "amadeus-api-credentials",
        "AMADEUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv64_amadeus_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "amadeus-api-credentials",
        "AMADEUS_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 10. AMAZON ADVERTISING API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv64_amazon_advertising_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "amazon-advertising-api-credentials",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv64_amazon_advertising_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "amazon-advertising-api-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv64_amazon_advertising_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "amazon-advertising-api-credentials",
        "amzn1.application-oa2-cl\u{200B}ient.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv64_amazon_advertising_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "amazon-advertising-api-credentials",
        "amzn1.application-oa2-cl\u{00AD}ient.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv64_amazon_advertising_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "amazon-advertising-api-credentials",
        "amzn1.application-oa2-cl\u{200C}ient.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv64_amazon_advertising_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "amazon-advertising-api-credentials",
        "amzn1.application-oa2-cl\u{200D}ient.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv64_amazon_advertising_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "amazon-advertising-api-credentials",
        "amzn1.application-oa2-cl\u{FEFF}ient.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv64_amazon_advertising_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "amazon-advertising-api-credentials",
        "amzn1.application-oa2-cl\u{2060}ient.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv64_amazon_advertising_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "amazon-advertising-api-credentials",
        "amzn1.application-oa2-cl\u{180E}ient.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv64_amazon_advertising_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "amazon-advertising-api-credentials",
        "amzn1.application-oa2-cl\u{202E}ient.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv64_amazon_advertising_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "amazon-advertising-api-credentials",
        "amzn1.application-oa2-cl\u{202C}ient.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv64_amazon_advertising_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "amazon-advertising-api-credentials",
        "amzn1.application-oa2-cl\u{200E}ient.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "amzn1.application-oa2-client.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}
