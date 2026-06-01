//! Part 76 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates clerk, clever, clickatell, clickhouse, clickup, clio, cloudflare, cloudflare, cloudflare, cloudflare detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. CLERK FRONTEND API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv76_clerk_frontend_api_key_normal_must_fire() {
    assert_detector_fires(
        "clerk-frontend-api-key",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clerk_frontend_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "clerk-frontend-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv76_clerk_frontend_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "clerk-frontend-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{200B}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clerk_frontend_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "clerk-frontend-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{00AD}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clerk_frontend_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "clerk-frontend-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{200C}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clerk_frontend_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "clerk-frontend-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{200D}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clerk_frontend_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "clerk-frontend-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{FEFF}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clerk_frontend_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "clerk-frontend-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{2060}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clerk_frontend_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "clerk-frontend-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{180E}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clerk_frontend_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "clerk-frontend-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{202E}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clerk_frontend_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "clerk-frontend-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{202C}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clerk_frontend_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "clerk-frontend-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{200E}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 2. CLEVER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv76_clever_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "clever-api-credentials",
        "clever_client_id=7b3e5d8c1a9f4e2b6c8d3a5e",
        "7b3e5d8c1a9f4e2b6c8d3a5e",
    );
}

#[test]
fn adv76_clever_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "clever-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv76_clever_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "clever-api-credentials",
        "clever_client_id=7b3e5d8c1a9f\u{200B}4e2b6c8d3a5e",
        "7b3e5d8c1a9f4e2b6c8d3a5e",
    );
}

#[test]
fn adv76_clever_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "clever-api-credentials",
        "clever_client_id=7b3e5d8c1a9f\u{00AD}4e2b6c8d3a5e",
        "7b3e5d8c1a9f4e2b6c8d3a5e",
    );
}

#[test]
fn adv76_clever_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "clever-api-credentials",
        "clever_client_id=7b3e5d8c1a9f\u{200C}4e2b6c8d3a5e",
        "7b3e5d8c1a9f4e2b6c8d3a5e",
    );
}

#[test]
fn adv76_clever_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "clever-api-credentials",
        "clever_client_id=7b3e5d8c1a9f\u{200D}4e2b6c8d3a5e",
        "7b3e5d8c1a9f4e2b6c8d3a5e",
    );
}

#[test]
fn adv76_clever_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "clever-api-credentials",
        "clever_client_id=7b3e5d8c1a9f\u{FEFF}4e2b6c8d3a5e",
        "7b3e5d8c1a9f4e2b6c8d3a5e",
    );
}

#[test]
fn adv76_clever_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "clever-api-credentials",
        "clever_client_id=7b3e5d8c1a9f\u{2060}4e2b6c8d3a5e",
        "7b3e5d8c1a9f4e2b6c8d3a5e",
    );
}

#[test]
fn adv76_clever_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "clever-api-credentials",
        "clever_client_id=7b3e5d8c1a9f\u{180E}4e2b6c8d3a5e",
        "7b3e5d8c1a9f4e2b6c8d3a5e",
    );
}

#[test]
fn adv76_clever_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "clever-api-credentials",
        "clever_client_id=7b3e5d8c1a9f\u{202E}4e2b6c8d3a5e",
        "7b3e5d8c1a9f4e2b6c8d3a5e",
    );
}

#[test]
fn adv76_clever_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "clever-api-credentials",
        "clever_client_id=7b3e5d8c1a9f\u{202C}4e2b6c8d3a5e",
        "7b3e5d8c1a9f4e2b6c8d3a5e",
    );
}

#[test]
fn adv76_clever_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "clever-api-credentials",
        "clever_client_id=7b3e5d8c1a9f\u{200E}4e2b6c8d3a5e",
        "7b3e5d8c1a9f4e2b6c8d3a5e",
    );
}

// =========================================================================
// 3. CLICKATELL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv76_clickatell_api_key_normal_must_fire() {
    assert_detector_fires(
        "clickatell-api-key",
        "CLICKATELL_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv76_clickatell_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("clickatell-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv76_clickatell_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "clickatell-api-key",
        "CLICKATELL_API_KEY=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv76_clickatell_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "clickatell-api-key",
        "CLICKATELL_API_KEY=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv76_clickatell_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "clickatell-api-key",
        "CLICKATELL_API_KEY=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv76_clickatell_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "clickatell-api-key",
        "CLICKATELL_API_KEY=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv76_clickatell_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "clickatell-api-key",
        "CLICKATELL_API_KEY=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv76_clickatell_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "clickatell-api-key",
        "CLICKATELL_API_KEY=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv76_clickatell_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "clickatell-api-key",
        "CLICKATELL_API_KEY=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv76_clickatell_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "clickatell-api-key",
        "CLICKATELL_API_KEY=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv76_clickatell_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "clickatell-api-key",
        "CLICKATELL_API_KEY=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv76_clickatell_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "clickatell-api-key",
        "CLICKATELL_API_KEY=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 4. CLICKHOUSE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv76_clickhouse_credentials_normal_must_fire() {
    assert_detector_fires(
        "clickhouse-credentials",
        "CLICKHOUSE_URL=clickhouse://default:Kp4Qx7Rm2Sn5Tb8V@clickhouse.local",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv76_clickhouse_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "clickhouse-credentials",
        "dummy_prefix_0 =clickhouse://default:xxxxxxxxxxxxxxxx@clickhouse.local",
    );
}

#[test]
fn adv76_clickhouse_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "clickhouse-credentials",
        "CLICKHOUSE_URL=clickhouse://default:Kp4Qx7Rm\u{200B}2Sn5Tb8V@clickhouse.local",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv76_clickhouse_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "clickhouse-credentials",
        "CLICKHOUSE_URL=clickhouse://default:Kp4Qx7Rm\u{00AD}2Sn5Tb8V@clickhouse.local",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv76_clickhouse_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "clickhouse-credentials",
        "CLICKHOUSE_URL=clickhouse://default:Kp4Qx7Rm\u{200C}2Sn5Tb8V@clickhouse.local",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv76_clickhouse_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "clickhouse-credentials",
        "CLICKHOUSE_URL=clickhouse://default:Kp4Qx7Rm\u{200D}2Sn5Tb8V@clickhouse.local",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv76_clickhouse_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "clickhouse-credentials",
        "CLICKHOUSE_URL=clickhouse://default:Kp4Qx7Rm\u{FEFF}2Sn5Tb8V@clickhouse.local",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv76_clickhouse_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "clickhouse-credentials",
        "CLICKHOUSE_URL=clickhouse://default:Kp4Qx7Rm\u{2060}2Sn5Tb8V@clickhouse.local",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv76_clickhouse_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "clickhouse-credentials",
        "CLICKHOUSE_URL=clickhouse://default:Kp4Qx7Rm\u{180E}2Sn5Tb8V@clickhouse.local",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv76_clickhouse_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "clickhouse-credentials",
        "CLICKHOUSE_URL=clickhouse://default:Kp4Qx7Rm\u{202E}2Sn5Tb8V@clickhouse.local",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv76_clickhouse_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "clickhouse-credentials",
        "CLICKHOUSE_URL=clickhouse://default:Kp4Qx7Rm\u{202C}2Sn5Tb8V@clickhouse.local",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv76_clickhouse_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "clickhouse-credentials",
        "CLICKHOUSE_URL=clickhouse://default:Kp4Qx7Rm\u{200E}2Sn5Tb8V@clickhouse.local",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

// =========================================================================
// 5. CLICKUP API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv76_clickup_api_token_normal_must_fire() {
    assert_detector_fires(
        "clickup-api-token",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clickup_api_token_wrong_prefix_must_silent() {
    assert_detector_silent("clickup-api-token", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv76_clickup_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "clickup-api-token",
        "pk_Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm2Sn5",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clickup_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "clickup-api-token",
        "pk_Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm2Sn5",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clickup_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "clickup-api-token",
        "pk_Kp4Qx7Rm2Sn5Tb\u{200C}8Vw3YzKp4Qx7Rm2Sn5",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clickup_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "clickup-api-token",
        "pk_Kp4Qx7Rm2Sn5Tb\u{200D}8Vw3YzKp4Qx7Rm2Sn5",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clickup_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "clickup-api-token",
        "pk_Kp4Qx7Rm2Sn5Tb\u{FEFF}8Vw3YzKp4Qx7Rm2Sn5",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clickup_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "clickup-api-token",
        "pk_Kp4Qx7Rm2Sn5Tb\u{2060}8Vw3YzKp4Qx7Rm2Sn5",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clickup_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "clickup-api-token",
        "pk_Kp4Qx7Rm2Sn5Tb\u{180E}8Vw3YzKp4Qx7Rm2Sn5",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clickup_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "clickup-api-token",
        "pk_Kp4Qx7Rm2Sn5Tb\u{202E}8Vw3YzKp4Qx7Rm2Sn5",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clickup_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "clickup-api-token",
        "pk_Kp4Qx7Rm2Sn5Tb\u{202C}8Vw3YzKp4Qx7Rm2Sn5",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv76_clickup_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "clickup-api-token",
        "pk_Kp4Qx7Rm2Sn5Tb\u{200E}8Vw3YzKp4Qx7Rm2Sn5",
        "pk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 6. CLIO API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv76_clio_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_clio_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "clio-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv76_clio_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_clio_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_clio_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_clio_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_clio_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_clio_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_clio_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_clio_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_clio_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_clio_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 7. CLOUDFLARE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv76_cloudflare_api_token_normal_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cloudflare-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv76_cloudflare_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200B}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{00AD}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200C}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200D}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{FEFF}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{2060}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{180E}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{202E}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{202C}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200E}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

// =========================================================================
// 8. CLOUDFLARE D1 CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv76_cloudflare_d1_credentials_normal_must_fire() {
    assert_detector_fires(
        "cloudflare-d1-credentials",
        "CF_D1_API_TOKEN=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_d1_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cloudflare-d1-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv76_cloudflare_d1_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudflare-d1-credentials",
        "CF_D1_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200B}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_d1_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudflare-d1-credentials",
        "CF_D1_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{00AD}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_d1_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cloudflare-d1-credentials",
        "CF_D1_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200C}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_d1_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "cloudflare-d1-credentials",
        "CF_D1_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200D}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_d1_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cloudflare-d1-credentials",
        "CF_D1_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{FEFF}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_d1_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cloudflare-d1-credentials",
        "CF_D1_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{2060}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_d1_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cloudflare-d1-credentials",
        "CF_D1_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{180E}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_d1_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "cloudflare-d1-credentials",
        "CF_D1_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{202E}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_d1_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cloudflare-d1-credentials",
        "CF_D1_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{202C}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv76_cloudflare_d1_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "cloudflare-d1-credentials",
        "CF_D1_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200E}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

// =========================================================================
// 9. CLOUDFLARE GLOBAL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv76_cloudflare_global_api_key_normal_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
    );
}

#[test]
fn adv76_cloudflare_global_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cloudflare-global-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv76_cloudflare_global_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY=7b3e5d8c1a9f4e2b6c\u{200B}8d3a5e9f1b7c4d3a5e9",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
    );
}

#[test]
fn adv76_cloudflare_global_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY=7b3e5d8c1a9f4e2b6c\u{00AD}8d3a5e9f1b7c4d3a5e9",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
    );
}

#[test]
fn adv76_cloudflare_global_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY=7b3e5d8c1a9f4e2b6c\u{200C}8d3a5e9f1b7c4d3a5e9",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
    );
}

#[test]
fn adv76_cloudflare_global_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY=7b3e5d8c1a9f4e2b6c\u{200D}8d3a5e9f1b7c4d3a5e9",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
    );
}

#[test]
fn adv76_cloudflare_global_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY=7b3e5d8c1a9f4e2b6c\u{FEFF}8d3a5e9f1b7c4d3a5e9",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
    );
}

#[test]
fn adv76_cloudflare_global_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY=7b3e5d8c1a9f4e2b6c\u{2060}8d3a5e9f1b7c4d3a5e9",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
    );
}

#[test]
fn adv76_cloudflare_global_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY=7b3e5d8c1a9f4e2b6c\u{180E}8d3a5e9f1b7c4d3a5e9",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
    );
}

#[test]
fn adv76_cloudflare_global_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY=7b3e5d8c1a9f4e2b6c\u{202E}8d3a5e9f1b7c4d3a5e9",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
    );
}

#[test]
fn adv76_cloudflare_global_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY=7b3e5d8c1a9f4e2b6c\u{202C}8d3a5e9f1b7c4d3a5e9",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
    );
}

#[test]
fn adv76_cloudflare_global_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY=7b3e5d8c1a9f4e2b6c\u{200E}8d3a5e9f1b7c4d3a5e9",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9",
    );
}

// =========================================================================
// 10. CLOUDFLARE KV CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv76_cloudflare_kv_credentials_normal_must_fire() {
    assert_detector_fires(
        "cloudflare-kv-credentials",
        "CF_ACCOUNT_ID=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_cloudflare_kv_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cloudflare-kv-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv76_cloudflare_kv_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudflare-kv-credentials",
        "CF_ACCOUNT_ID=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_cloudflare_kv_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudflare-kv-credentials",
        "CF_ACCOUNT_ID=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_cloudflare_kv_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cloudflare-kv-credentials",
        "CF_ACCOUNT_ID=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_cloudflare_kv_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "cloudflare-kv-credentials",
        "CF_ACCOUNT_ID=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_cloudflare_kv_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cloudflare-kv-credentials",
        "CF_ACCOUNT_ID=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_cloudflare_kv_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cloudflare-kv-credentials",
        "CF_ACCOUNT_ID=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_cloudflare_kv_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cloudflare-kv-credentials",
        "CF_ACCOUNT_ID=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_cloudflare_kv_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "cloudflare-kv-credentials",
        "CF_ACCOUNT_ID=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_cloudflare_kv_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cloudflare-kv-credentials",
        "CF_ACCOUNT_ID=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv76_cloudflare_kv_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "cloudflare-kv-credentials",
        "CF_ACCOUNT_ID=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}
