//! Part 63 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates adobe, adp, aerisweather, africastalking, agenta, agora, ai21, airbrake, airbyte, airplane detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. ADOBE STOCK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv63_adobe_stock_api_key_normal_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ADOBE_STOCK_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adobe_stock_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "adobe-stock-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv63_adobe_stock_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ADOBE_STOCK_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adobe_stock_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ADOBE_STOCK_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adobe_stock_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ADOBE_STOCK_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adobe_stock_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ADOBE_STOCK_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adobe_stock_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ADOBE_STOCK_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adobe_stock_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ADOBE_STOCK_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adobe_stock_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ADOBE_STOCK_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adobe_stock_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ADOBE_STOCK_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adobe_stock_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ADOBE_STOCK_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adobe_stock_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ADOBE_STOCK_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 2. ADP API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv63_adp_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adp_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "adp-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv63_adp_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adp_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adp_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adp_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adp_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adp_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adp_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adp_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adp_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_adp_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 3. AERISWEATHER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv63_aerisweather_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "AERIS_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv63_aerisweather_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aerisweather-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv63_aerisweather_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "AERIS_CLIENT_ID=Kp4Qx7Rm\u{200B}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv63_aerisweather_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "AERIS_CLIENT_ID=Kp4Qx7Rm\u{00AD}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv63_aerisweather_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "AERIS_CLIENT_ID=Kp4Qx7Rm\u{200C}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv63_aerisweather_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "AERIS_CLIENT_ID=Kp4Qx7Rm\u{200D}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv63_aerisweather_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "AERIS_CLIENT_ID=Kp4Qx7Rm\u{FEFF}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv63_aerisweather_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "AERIS_CLIENT_ID=Kp4Qx7Rm\u{2060}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv63_aerisweather_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "AERIS_CLIENT_ID=Kp4Qx7Rm\u{180E}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv63_aerisweather_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "AERIS_CLIENT_ID=Kp4Qx7Rm\u{202E}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv63_aerisweather_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "AERIS_CLIENT_ID=Kp4Qx7Rm\u{202C}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv63_aerisweather_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "AERIS_CLIENT_ID=Kp4Qx7Rm\u{200E}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

// =========================================================================
// 4. AFRICASTALKING API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv63_africastalking_api_key_normal_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_africastalking_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "africastalking-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv63_africastalking_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_africastalking_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_africastalking_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_africastalking_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_africastalking_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_africastalking_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_africastalking_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_africastalking_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_africastalking_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_africastalking_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 5. AGENTA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv63_agenta_api_key_normal_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_agenta_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "agenta-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv63_agenta_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_agenta_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_agenta_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_agenta_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_agenta_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_agenta_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_agenta_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_agenta_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_agenta_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_agenta_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 6. AGORA APP CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv63_agora_app_credentials_normal_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID=39bd4eecd4534c9808f4df2988459df7",
        "39bd4eecd4534c9808f4df2988459df7",
    );
}

#[test]
fn adv63_agora_app_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "agora-app-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv63_agora_app_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID=39bd4eecd4534c98\u{200B}08f4df2988459df7",
        "39bd4eecd4534c9808f4df2988459df7",
    );
}

#[test]
fn adv63_agora_app_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID=39bd4eecd4534c98\u{00AD}08f4df2988459df7",
        "39bd4eecd4534c9808f4df2988459df7",
    );
}

#[test]
fn adv63_agora_app_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID=39bd4eecd4534c98\u{200C}08f4df2988459df7",
        "39bd4eecd4534c9808f4df2988459df7",
    );
}

#[test]
fn adv63_agora_app_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID=39bd4eecd4534c98\u{200D}08f4df2988459df7",
        "39bd4eecd4534c9808f4df2988459df7",
    );
}

#[test]
fn adv63_agora_app_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID=39bd4eecd4534c98\u{FEFF}08f4df2988459df7",
        "39bd4eecd4534c9808f4df2988459df7",
    );
}

#[test]
fn adv63_agora_app_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID=39bd4eecd4534c98\u{2060}08f4df2988459df7",
        "39bd4eecd4534c9808f4df2988459df7",
    );
}

#[test]
fn adv63_agora_app_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID=39bd4eecd4534c98\u{180E}08f4df2988459df7",
        "39bd4eecd4534c9808f4df2988459df7",
    );
}

#[test]
fn adv63_agora_app_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID=39bd4eecd4534c98\u{202E}08f4df2988459df7",
        "39bd4eecd4534c9808f4df2988459df7",
    );
}

#[test]
fn adv63_agora_app_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID=39bd4eecd4534c98\u{202C}08f4df2988459df7",
        "39bd4eecd4534c9808f4df2988459df7",
    );
}

#[test]
fn adv63_agora_app_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID=39bd4eecd4534c98\u{200E}08f4df2988459df7",
        "39bd4eecd4534c9808f4df2988459df7",
    );
}

// =========================================================================
// 7. AI21 API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv63_ai21_api_key_normal_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_ai21_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ai21-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv63_ai21_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_ai21_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_ai21_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_ai21_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_ai21_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_ai21_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_ai21_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_ai21_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_ai21_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_ai21_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 8. AIRBRAKE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv63_airbrake_api_key_normal_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "AIRBRAKE_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_airbrake_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "airbrake-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv63_airbrake_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "AIRBRAKE_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_airbrake_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "AIRBRAKE_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_airbrake_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "AIRBRAKE_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_airbrake_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "AIRBRAKE_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_airbrake_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "AIRBRAKE_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_airbrake_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "AIRBRAKE_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_airbrake_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "AIRBRAKE_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_airbrake_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "AIRBRAKE_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_airbrake_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "AIRBRAKE_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv63_airbrake_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "AIRBRAKE_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 9. AIRBYTE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv63_airbyte_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_airbyte_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "airbyte-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv63_airbyte_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_airbyte_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_airbyte_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_airbyte_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_airbyte_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_airbyte_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_airbyte_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_airbyte_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_airbyte_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv63_airbyte_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 10. AIRPLANE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv63_airplane_api_key_normal_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv63_airplane_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "airplane-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv63_airplane_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm2SnTb",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv63_airplane_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm2SnTb",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv63_airplane_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_Kp4Qx7Rm2Sn5Tb\u{200C}8Vw3YzKp4Qx7Rm2SnTb",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv63_airplane_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_Kp4Qx7Rm2Sn5Tb\u{200D}8Vw3YzKp4Qx7Rm2SnTb",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv63_airplane_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_Kp4Qx7Rm2Sn5Tb\u{FEFF}8Vw3YzKp4Qx7Rm2SnTb",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv63_airplane_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_Kp4Qx7Rm2Sn5Tb\u{2060}8Vw3YzKp4Qx7Rm2SnTb",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv63_airplane_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_Kp4Qx7Rm2Sn5Tb\u{180E}8Vw3YzKp4Qx7Rm2SnTb",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv63_airplane_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_Kp4Qx7Rm2Sn5Tb\u{202E}8Vw3YzKp4Qx7Rm2SnTb",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv63_airplane_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_Kp4Qx7Rm2Sn5Tb\u{202C}8Vw3YzKp4Qx7Rm2SnTb",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}

#[test]
fn adv63_airplane_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_Kp4Qx7Rm2Sn5Tb\u{200E}8Vw3YzKp4Qx7Rm2SnTb",
        "aptk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTb",
    );
}


