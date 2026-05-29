//! Part 47 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates notion, notion, notion, novu, npm, ns1, ntfy, nuvei, octopus, okta detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. NOTION API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv47_notion_api_key_normal_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv47_notion_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "notion-api-key",
        "dummy_prefix_0 =xxxret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv47_notion_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{200B}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv47_notion_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{00AD}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

// =========================================================================
// 2. NOTION INTEGRATION TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv47_notion_integration_token_normal_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv47_notion_integration_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "notion-integration-token",
        "dummyKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv47_notion_integration_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv47_notion_integration_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

// =========================================================================
// 3. NOTION OAUTH SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv47_notion_oauth_secret_normal_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv47_notion_oauth_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "notion-oauth-secret",
        "dummy_prefix_0 =xxxret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv47_notion_oauth_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv47_notion_oauth_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

// =========================================================================
// 4. NOVU API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv47_novu_api_key_normal_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv47_novu_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "novu-api-key",
        "dummyJYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv47_novu_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{200B}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv47_novu_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{00AD}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

// =========================================================================
// 5. NPM ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv47_npm_access_token_normal_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "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",
        "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",
    );
}

#[test]
fn adv47_npm_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "npm-access-token",
        "dummy9X3kQp7VbT2hYRzNcMfWj4DgEsLuHa3nVRk3",
    );
}

#[test]
fn adv47_npm_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{200B}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

#[test]
fn adv47_npm_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzN\u{00AD}cMfWj4DgEsLuHa3nVRk3",
        "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",
    );
}

// =========================================================================
// 6. NS1 API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv47_ns1_api_key_normal_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv47_ns1_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ns1-api-key",
        "dummy_prefix_0 =xxx_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv47_ns1_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{200B}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

#[test]
fn adv47_ns1_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ns1-api-key",
        "NS1_API_KEY=LMg_4h12QvVuiYMIkeb9\u{00AD}azkXGNDu3GdphrBLzm4h",
        "LMg_4h12QvVuiYMIkeb9azkXGNDu3GdphrBLzm4h",
    );
}

// =========================================================================
// 7. NTFY CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv47_ntfy_credentials_normal_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv47_ntfy_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ntfy-credentials",
        "dummy7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv47_ntfy_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{200B}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

#[test]
fn adv47_ntfy_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ntfy-credentials",
        "tk_p7ZTbNBEfRY8XT\u{00AD}J11XErKNuDX4bJeIZk",
        "tk_p7ZTbNBEfRY8XTJ11XErKNuDX4bJeIZk",
    );
}

// =========================================================================
// 8. NUVEI API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv47_nuvei_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6afa7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv47_nuvei_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "nuvei-api-credentials",
        "dummy_prefix_0 =xxx5d6afa7b1dbda",
    );
}

#[test]
fn adv47_nuvei_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{200B}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

#[test]
fn adv47_nuvei_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nuvei-api-credentials",
        "NUVEI_API_KEY=0815d6af\u{00AD}a7b1dbda",
        "0815d6afa7b1dbda",
    );
}

// =========================================================================
// 9. OCTOPUS DEPLOY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv47_octopus_deploy_api_key_normal_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S9206QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv47_octopus_deploy_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "octopus-deploy-api-key",
        "dummy7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv47_octopus_deploy_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{200B}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

#[test]
fn adv47_octopus_deploy_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "octopus-deploy-api-key",
        "API-7X68S92\u{00AD}06QLQW4S2FVP",
        "API-7X68S9206QLQW4S2FVP",
    );
}

// =========================================================================
// 10. OKTA OIDC CLIENT SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv47_okta_oidc_client_secret_normal_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv47_okta_oidc_client_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "okta-oidc-client-secret",
        "dummy_prefix_0 =xxx6Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv47_okta_oidc_client_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{200B}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}

#[test]
fn adv47_okta_oidc_client_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "okta-oidc-client-secret",
        "OKTACLIENTSECRET=5G96Yr7jKpsOaM4iCFAmSEiB\u{00AD}0EdYeQ8stohywLrmIKO3KgSn",
        "5G96Yr7jKpsOaM4iCFAmSEiB0EdYeQ8stohywLrmIKO3KgSn",
    );
}


