//! Part 111 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates npm, ns1, ntfy, nuvei, octopus, okta, okta, olark, omnisend, onedrive detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. NPM ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv111_npm_access_token_normal_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "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",
        "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",
    );
}

#[test]
fn adv111_npm_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "npm-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv111_npm_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{200B}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

#[test]
fn adv111_npm_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{00AD}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

#[test]
fn adv111_npm_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{200C}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

#[test]
fn adv111_npm_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{200D}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

#[test]
fn adv111_npm_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{FEFF}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

#[test]
fn adv111_npm_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{2060}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

#[test]
fn adv111_npm_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{180E}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

#[test]
fn adv111_npm_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{202E}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

#[test]
fn adv111_npm_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{202C}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

#[test]
fn adv111_npm_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{200E}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

// =========================================================================
// 2. NS1 API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv111_ns1_api_key_normal_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv111_ns1_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ns1-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv111_ns1_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{200B}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv111_ns1_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{00AD}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv111_ns1_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{200C}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv111_ns1_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{200D}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv111_ns1_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{FEFF}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv111_ns1_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{2060}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv111_ns1_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{180E}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv111_ns1_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{202E}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv111_ns1_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{202C}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv111_ns1_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{200E}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

// =========================================================================
// 3. NTFY CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv111_ntfy_credentials_normal_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv111_ntfy_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("ntfy-credentials", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv111_ntfy_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{200B}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv111_ntfy_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{00AD}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv111_ntfy_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{200C}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv111_ntfy_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{200D}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv111_ntfy_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{FEFF}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv111_ntfy_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{2060}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv111_ntfy_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{180E}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv111_ntfy_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{202E}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv111_ntfy_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{202C}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv111_ntfy_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{200E}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

// =========================================================================
// 4. NUVEI API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv111_nuvei_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6afa7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv111_nuvei_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("nuvei-api-credentials", "dummy_prefix_0 =xxxxxxxxxxxxxxxx");
}

#[test]
fn adv111_nuvei_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{200B}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv111_nuvei_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{00AD}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv111_nuvei_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{200C}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv111_nuvei_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{200D}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv111_nuvei_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{FEFF}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv111_nuvei_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{2060}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv111_nuvei_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{180E}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv111_nuvei_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{202E}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv111_nuvei_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{202C}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv111_nuvei_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{200E}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

// =========================================================================
// 5. OCTOPUS DEPLOY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv111_octopus_deploy_api_key_normal_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S9206QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv111_octopus_deploy_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("octopus-deploy-api-key", "dummyxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv111_octopus_deploy_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{200B}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv111_octopus_deploy_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{00AD}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv111_octopus_deploy_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{200C}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv111_octopus_deploy_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{200D}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv111_octopus_deploy_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{FEFF}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv111_octopus_deploy_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{2060}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv111_octopus_deploy_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{180E}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv111_octopus_deploy_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{202E}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv111_octopus_deploy_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{202C}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv111_octopus_deploy_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{200E}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

// =========================================================================
// 6. OKTA OIDC CLIENT SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv111_okta_oidc_client_secret_normal_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv111_okta_oidc_client_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "okta-oidc-client-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv111_okta_oidc_client_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{200B}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv111_okta_oidc_client_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{00AD}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv111_okta_oidc_client_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{200C}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv111_okta_oidc_client_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{200D}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv111_okta_oidc_client_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{FEFF}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv111_okta_oidc_client_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{2060}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv111_okta_oidc_client_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{180E}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv111_okta_oidc_client_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{202E}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv111_okta_oidc_client_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{202C}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv111_okta_oidc_client_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{200E}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

// =========================================================================
// 7. OKTA SUPPORT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv111_okta_support_token_normal_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv111_okta_support_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "okta-support-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv111_okta_support_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{200B}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv111_okta_support_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{00AD}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv111_okta_support_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{200C}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv111_okta_support_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{200D}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv111_okta_support_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{FEFF}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv111_okta_support_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{2060}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv111_okta_support_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{180E}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv111_okta_support_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{202E}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv111_okta_support_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{202C}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv111_okta_support_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{200E}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

// =========================================================================
// 8. OLARK API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv111_olark_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv111_olark_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "olark-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv111_olark_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{200B}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv111_olark_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{00AD}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv111_olark_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{200C}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv111_olark_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{200D}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv111_olark_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{FEFF}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv111_olark_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{2060}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv111_olark_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{180E}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv111_olark_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{202E}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv111_olark_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{202C}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv111_olark_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{200E}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

// =========================================================================
// 9. OMNISEND API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv111_omnisend_api_key_normal_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626eedd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv111_omnisend_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "omnisend-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv111_omnisend_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{200B}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv111_omnisend_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{00AD}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv111_omnisend_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{200C}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv111_omnisend_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{200D}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv111_omnisend_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{FEFF}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv111_omnisend_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{2060}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv111_omnisend_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{180E}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv111_omnisend_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{202E}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv111_omnisend_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{202C}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv111_omnisend_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{200E}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

// =========================================================================
// 10. ONEDRIVE ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv111_onedrive_access_token_normal_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv111_onedrive_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "onedrive-access-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv111_onedrive_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{200B}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv111_onedrive_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{00AD}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv111_onedrive_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{200C}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv111_onedrive_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{200D}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv111_onedrive_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{FEFF}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv111_onedrive_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{2060}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv111_onedrive_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{180E}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv111_onedrive_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{202E}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv111_onedrive_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{202C}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv111_onedrive_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{200E}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}
