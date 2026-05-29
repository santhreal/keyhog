//! Part 67 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates auth0, authentik, autoblocks, automate, avalanche, avaya, aweber, aws, aws, aws detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. AUTH0 SPA CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv67_auth0_spa_credentials_normal_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0 config client_id: 'Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn'",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv67_auth0_spa_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "auth0-spa-credentials",
        "dummy_prefix_0: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
    );
}

#[test]
fn adv67_auth0_spa_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0 config client_id: 'Kp4Qx7Rm2Sn5Tb8\u{200B}Vw3YzKp4Qx7Rm2Sn'",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv67_auth0_spa_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0 config client_id: 'Kp4Qx7Rm2Sn5Tb8\u{00AD}Vw3YzKp4Qx7Rm2Sn'",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv67_auth0_spa_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0 config client_id: 'Kp4Qx7Rm2Sn5Tb8\u{200C}Vw3YzKp4Qx7Rm2Sn'",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv67_auth0_spa_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0 config client_id: 'Kp4Qx7Rm2Sn5Tb8\u{200D}Vw3YzKp4Qx7Rm2Sn'",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv67_auth0_spa_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0 config client_id: 'Kp4Qx7Rm2Sn5Tb8\u{FEFF}Vw3YzKp4Qx7Rm2Sn'",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv67_auth0_spa_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0 config client_id: 'Kp4Qx7Rm2Sn5Tb8\u{2060}Vw3YzKp4Qx7Rm2Sn'",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv67_auth0_spa_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0 config client_id: 'Kp4Qx7Rm2Sn5Tb8\u{180E}Vw3YzKp4Qx7Rm2Sn'",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv67_auth0_spa_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0 config client_id: 'Kp4Qx7Rm2Sn5Tb8\u{202E}Vw3YzKp4Qx7Rm2Sn'",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv67_auth0_spa_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0 config client_id: 'Kp4Qx7Rm2Sn5Tb8\u{202C}Vw3YzKp4Qx7Rm2Sn'",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv67_auth0_spa_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0 config client_id: 'Kp4Qx7Rm2Sn5Tb8\u{200E}Vw3YzKp4Qx7Rm2Sn'",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

// =========================================================================
// 2. AUTHENTIK TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv67_authentik_token_normal_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_authentik_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "authentik-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv67_authentik_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_authentik_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_authentik_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_authentik_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_authentik_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_authentik_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_authentik_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_authentik_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_authentik_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_authentik_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 3. AUTOBLOCKS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv67_autoblocks_api_key_normal_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_autoblocks_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "autoblocks-api-key",
        "dummyxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv67_autoblocks_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-Kp4Qx7Rm\u{200B}2Sn5Tb8Vw3Yz",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_autoblocks_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-Kp4Qx7Rm\u{00AD}2Sn5Tb8Vw3Yz",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_autoblocks_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-Kp4Qx7Rm\u{200C}2Sn5Tb8Vw3Yz",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_autoblocks_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-Kp4Qx7Rm\u{200D}2Sn5Tb8Vw3Yz",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_autoblocks_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-Kp4Qx7Rm\u{FEFF}2Sn5Tb8Vw3Yz",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_autoblocks_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-Kp4Qx7Rm\u{2060}2Sn5Tb8Vw3Yz",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_autoblocks_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-Kp4Qx7Rm\u{180E}2Sn5Tb8Vw3Yz",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_autoblocks_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-Kp4Qx7Rm\u{202E}2Sn5Tb8Vw3Yz",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_autoblocks_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-Kp4Qx7Rm\u{202C}2Sn5Tb8Vw3Yz",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_autoblocks_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-Kp4Qx7Rm\u{200E}2Sn5Tb8Vw3Yz",
        "AB-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 4. AUTOMATE IO CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv67_automate_io_credentials_normal_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_automate_io_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "automate-io-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv67_automate_io_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_automate_io_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_automate_io_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_automate_io_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_automate_io_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_automate_io_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_automate_io_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_automate_io_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_automate_io_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_automate_io_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 5. AVALANCHE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv67_avalanche_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche_rpc_url=https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_avalanche_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "avalanche-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv67_avalanche_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche_rpc_url=https://api.avax.netwo\u{200B}rk/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_avalanche_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche_rpc_url=https://api.avax.netwo\u{00AD}rk/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_avalanche_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche_rpc_url=https://api.avax.netwo\u{200C}rk/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_avalanche_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche_rpc_url=https://api.avax.netwo\u{200D}rk/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_avalanche_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche_rpc_url=https://api.avax.netwo\u{FEFF}rk/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_avalanche_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche_rpc_url=https://api.avax.netwo\u{2060}rk/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_avalanche_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche_rpc_url=https://api.avax.netwo\u{180E}rk/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_avalanche_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche_rpc_url=https://api.avax.netwo\u{202E}rk/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_avalanche_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche_rpc_url=https://api.avax.netwo\u{202C}rk/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_avalanche_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche_rpc_url=https://api.avax.netwo\u{200E}rk/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 6. AVAYA API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv67_avaya_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "AVAYA_CLOUD_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_avaya_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "avaya-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv67_avaya_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "AVAYA_CLOUD_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_avaya_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "AVAYA_CLOUD_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_avaya_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "AVAYA_CLOUD_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_avaya_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "AVAYA_CLOUD_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_avaya_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "AVAYA_CLOUD_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_avaya_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "AVAYA_CLOUD_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_avaya_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "AVAYA_CLOUD_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_avaya_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "AVAYA_CLOUD_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_avaya_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "AVAYA_CLOUD_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv67_avaya_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "AVAYA_CLOUD_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 7. AWEBER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv67_aweber_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "AWEBER_CLIENT_ID Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv67_aweber_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aweber-api-credentials",
        "dummyER_CLIENT_ID xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv67_aweber_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "AWEBER_CLIENT_ID Kp4Qx7Rm2Sn5\u{200B}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv67_aweber_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "AWEBER_CLIENT_ID Kp4Qx7Rm2Sn5\u{00AD}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv67_aweber_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "AWEBER_CLIENT_ID Kp4Qx7Rm2Sn5\u{200C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv67_aweber_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "AWEBER_CLIENT_ID Kp4Qx7Rm2Sn5\u{200D}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv67_aweber_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "AWEBER_CLIENT_ID Kp4Qx7Rm2Sn5\u{FEFF}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv67_aweber_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "AWEBER_CLIENT_ID Kp4Qx7Rm2Sn5\u{2060}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv67_aweber_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "AWEBER_CLIENT_ID Kp4Qx7Rm2Sn5\u{180E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv67_aweber_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "AWEBER_CLIENT_ID Kp4Qx7Rm2Sn5\u{202E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv67_aweber_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "AWEBER_CLIENT_ID Kp4Qx7Rm2Sn5\u{202C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv67_aweber_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "AWEBER_CLIENT_ID Kp4Qx7Rm2Sn5\u{200E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

// =========================================================================
// 8. AWS ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv67_aws_access_key_normal_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv67_aws_access_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-access-key",
        "dummyxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv67_aws_access_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN\u{200B}5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv67_aws_access_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN\u{00AD}5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv67_aws_access_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN\u{200C}5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv67_aws_access_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN\u{200D}5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv67_aws_access_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN\u{FEFF}5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv67_aws_access_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN\u{2060}5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv67_aws_access_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN\u{180E}5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv67_aws_access_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN\u{202E}5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv67_aws_access_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN\u{202C}5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv67_aws_access_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN\u{200E}5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

// =========================================================================
// 9. AWS CODECOMMIT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv67_aws_codecommit_credentials_normal_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit_username=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv67_aws_codecommit_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-codecommit-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv67_aws_codecommit_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit_username=Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv67_aws_codecommit_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit_username=Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv67_aws_codecommit_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit_username=Kp4Qx7Rm2Sn5Tb\u{200C}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv67_aws_codecommit_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit_username=Kp4Qx7Rm2Sn5Tb\u{200D}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv67_aws_codecommit_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit_username=Kp4Qx7Rm2Sn5Tb\u{FEFF}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv67_aws_codecommit_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit_username=Kp4Qx7Rm2Sn5Tb\u{2060}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv67_aws_codecommit_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit_username=Kp4Qx7Rm2Sn5Tb\u{180E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv67_aws_codecommit_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit_username=Kp4Qx7Rm2Sn5Tb\u{202E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv67_aws_codecommit_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit_username=Kp4Qx7Rm2Sn5Tb\u{202C}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv67_aws_codecommit_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit_username=Kp4Qx7Rm2Sn5Tb\u{200E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

// =========================================================================
// 10. AWS COGNITO CLIENT SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv67_aws_cognito_client_secret_normal_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_aws_cognito_client_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-cognito-client-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv67_aws_cognito_client_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_aws_cognito_client_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_aws_cognito_client_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_aws_cognito_client_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_aws_cognito_client_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_aws_cognito_client_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_aws_cognito_client_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_aws_cognito_client_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_aws_cognito_client_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv67_aws_cognito_client_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}


