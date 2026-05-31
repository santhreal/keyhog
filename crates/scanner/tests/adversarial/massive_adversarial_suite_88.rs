//! Part 88 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates flutterwave, flyio, flyio, footprint, formstack, fortinet, framer, freshdesk, front, fullstory detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. FLUTTERWAVE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv88_flutterwave_api_key_normal_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
    );
}

#[test]
fn adv88_flutterwave_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "flutterwave-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv88_flutterwave_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-7b3e5d8c1a\u{200B}9f4e2b6c8d3a5e9f1b7c4d-X",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
    );
}

#[test]
fn adv88_flutterwave_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-7b3e5d8c1a\u{00AD}9f4e2b6c8d3a5e9f1b7c4d-X",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
    );
}

#[test]
fn adv88_flutterwave_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-7b3e5d8c1a\u{200C}9f4e2b6c8d3a5e9f1b7c4d-X",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
    );
}

#[test]
fn adv88_flutterwave_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-7b3e5d8c1a\u{200D}9f4e2b6c8d3a5e9f1b7c4d-X",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
    );
}

#[test]
fn adv88_flutterwave_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-7b3e5d8c1a\u{FEFF}9f4e2b6c8d3a5e9f1b7c4d-X",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
    );
}

#[test]
fn adv88_flutterwave_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-7b3e5d8c1a\u{2060}9f4e2b6c8d3a5e9f1b7c4d-X",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
    );
}

#[test]
fn adv88_flutterwave_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-7b3e5d8c1a\u{180E}9f4e2b6c8d3a5e9f1b7c4d-X",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
    );
}

#[test]
fn adv88_flutterwave_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-7b3e5d8c1a\u{202E}9f4e2b6c8d3a5e9f1b7c4d-X",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
    );
}

#[test]
fn adv88_flutterwave_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-7b3e5d8c1a\u{202C}9f4e2b6c8d3a5e9f1b7c4d-X",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
    );
}

#[test]
fn adv88_flutterwave_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-7b3e5d8c1a\u{200E}9f4e2b6c8d3a5e9f1b7c4d-X",
        "FLWSECK_TEST-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d-X",
    );
}

// =========================================================================
// 2. FLYIO ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv88_flyio_access_token_normal_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv88_flyio_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "flyio-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv88_flyio_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_9X3kQp7VbT2hYRzNcMf\u{200B}Wj4DgEsLuHaIoBnVkPxKqRtY",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv88_flyio_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_9X3kQp7VbT2hYRzNcMf\u{00AD}Wj4DgEsLuHaIoBnVkPxKqRtY",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv88_flyio_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_9X3kQp7VbT2hYRzNcMf\u{200C}Wj4DgEsLuHaIoBnVkPxKqRtY",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv88_flyio_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_9X3kQp7VbT2hYRzNcMf\u{200D}Wj4DgEsLuHaIoBnVkPxKqRtY",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv88_flyio_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_9X3kQp7VbT2hYRzNcMf\u{FEFF}Wj4DgEsLuHaIoBnVkPxKqRtY",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv88_flyio_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_9X3kQp7VbT2hYRzNcMf\u{2060}Wj4DgEsLuHaIoBnVkPxKqRtY",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv88_flyio_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_9X3kQp7VbT2hYRzNcMf\u{180E}Wj4DgEsLuHaIoBnVkPxKqRtY",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv88_flyio_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_9X3kQp7VbT2hYRzNcMf\u{202E}Wj4DgEsLuHaIoBnVkPxKqRtY",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv88_flyio_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_9X3kQp7VbT2hYRzNcMf\u{202C}Wj4DgEsLuHaIoBnVkPxKqRtY",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv88_flyio_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_9X3kQp7VbT2hYRzNcMf\u{200E}Wj4DgEsLuHaIoBnVkPxKqRtY",
        "fm2_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

// =========================================================================
// 3. FLYIO DEPLOY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv88_flyio_deploy_token_normal_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv88_flyio_deploy_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "flyio-deploy-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv88_flyio_deploy_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv88_flyio_deploy_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv88_flyio_deploy_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv88_flyio_deploy_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv88_flyio_deploy_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv88_flyio_deploy_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv88_flyio_deploy_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv88_flyio_deploy_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv88_flyio_deploy_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv88_flyio_deploy_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "fo1_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

// =========================================================================
// 4. FOOTPRINT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv88_footprint_api_key_normal_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
    );
}

#[test]
fn adv88_footprint_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "footprint-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv88_footprint_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2S5T",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
    );
}

#[test]
fn adv88_footprint_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_api_key=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2S5T",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
    );
}

#[test]
fn adv88_footprint_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2S5T",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
    );
}

#[test]
fn adv88_footprint_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2S5T",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
    );
}

#[test]
fn adv88_footprint_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_api_key=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2S5T",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
    );
}

#[test]
fn adv88_footprint_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_api_key=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2S5T",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
    );
}

#[test]
fn adv88_footprint_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_api_key=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2S5T",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
    );
}

#[test]
fn adv88_footprint_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_api_key=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2S5T",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
    );
}

#[test]
fn adv88_footprint_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_api_key=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2S5T",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
    );
}

#[test]
fn adv88_footprint_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2S5T",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S5T",
    );
}

// =========================================================================
// 5. FORMSTACK API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv88_formstack_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack access_token \"7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d\"",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d",
    );
}

#[test]
fn adv88_formstack_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "formstack-api-credentials",
        "dummystack access_token \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"",
    );
}

#[test]
fn adv88_formstack_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack access_token \"7b3e5d8c1a9f4e2b6c8d3a\u{200B}5e9f1b7c4d3a5e9f1b7c4d\"",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d",
    );
}

#[test]
fn adv88_formstack_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack access_token \"7b3e5d8c1a9f4e2b6c8d3a\u{00AD}5e9f1b7c4d3a5e9f1b7c4d\"",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d",
    );
}

#[test]
fn adv88_formstack_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack access_token \"7b3e5d8c1a9f4e2b6c8d3a\u{200C}5e9f1b7c4d3a5e9f1b7c4d\"",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d",
    );
}

#[test]
fn adv88_formstack_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack access_token \"7b3e5d8c1a9f4e2b6c8d3a\u{200D}5e9f1b7c4d3a5e9f1b7c4d\"",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d",
    );
}

#[test]
fn adv88_formstack_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack access_token \"7b3e5d8c1a9f4e2b6c8d3a\u{FEFF}5e9f1b7c4d3a5e9f1b7c4d\"",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d",
    );
}

#[test]
fn adv88_formstack_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack access_token \"7b3e5d8c1a9f4e2b6c8d3a\u{2060}5e9f1b7c4d3a5e9f1b7c4d\"",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d",
    );
}

#[test]
fn adv88_formstack_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack access_token \"7b3e5d8c1a9f4e2b6c8d3a\u{180E}5e9f1b7c4d3a5e9f1b7c4d\"",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d",
    );
}

#[test]
fn adv88_formstack_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack access_token \"7b3e5d8c1a9f4e2b6c8d3a\u{202E}5e9f1b7c4d3a5e9f1b7c4d\"",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d",
    );
}

#[test]
fn adv88_formstack_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack access_token \"7b3e5d8c1a9f4e2b6c8d3a\u{202C}5e9f1b7c4d3a5e9f1b7c4d\"",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d",
    );
}

#[test]
fn adv88_formstack_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack access_token \"7b3e5d8c1a9f4e2b6c8d3a\u{200E}5e9f1b7c4d3a5e9f1b7c4d\"",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 6. FORTINET FORTIGATE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv88_fortinet_fortigate_token_normal_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "FORTINET_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_fortinet_fortigate_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fortinet-fortigate-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv88_fortinet_fortigate_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "FORTINET_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_fortinet_fortigate_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "FORTINET_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_fortinet_fortigate_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "FORTINET_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_fortinet_fortigate_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "FORTINET_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_fortinet_fortigate_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "FORTINET_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_fortinet_fortigate_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "FORTINET_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_fortinet_fortigate_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "FORTINET_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_fortinet_fortigate_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "FORTINET_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_fortinet_fortigate_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "FORTINET_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_fortinet_fortigate_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "FORTINET_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 7. FRAMER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv88_framer_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "FRAMER_API_KEY=H_ZM9TBrKrmGsNmjQ8mT",
        "H_ZM9TBrKrmGsNmjQ8mT",
    );
}

#[test]
fn adv88_framer_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "framer-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv88_framer_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "FRAMER_API_KEY=H_ZM9TBrKr\u{200B}mGsNmjQ8mT",
        "H_ZM9TBrKrmGsNmjQ8mT",
    );
}

#[test]
fn adv88_framer_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "FRAMER_API_KEY=H_ZM9TBrKr\u{00AD}mGsNmjQ8mT",
        "H_ZM9TBrKrmGsNmjQ8mT",
    );
}

#[test]
fn adv88_framer_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "FRAMER_API_KEY=H_ZM9TBrKr\u{200C}mGsNmjQ8mT",
        "H_ZM9TBrKrmGsNmjQ8mT",
    );
}

#[test]
fn adv88_framer_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "FRAMER_API_KEY=H_ZM9TBrKr\u{200D}mGsNmjQ8mT",
        "H_ZM9TBrKrmGsNmjQ8mT",
    );
}

#[test]
fn adv88_framer_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "FRAMER_API_KEY=H_ZM9TBrKr\u{FEFF}mGsNmjQ8mT",
        "H_ZM9TBrKrmGsNmjQ8mT",
    );
}

#[test]
fn adv88_framer_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "FRAMER_API_KEY=H_ZM9TBrKr\u{2060}mGsNmjQ8mT",
        "H_ZM9TBrKrmGsNmjQ8mT",
    );
}

#[test]
fn adv88_framer_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "FRAMER_API_KEY=H_ZM9TBrKr\u{180E}mGsNmjQ8mT",
        "H_ZM9TBrKrmGsNmjQ8mT",
    );
}

#[test]
fn adv88_framer_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "FRAMER_API_KEY=H_ZM9TBrKr\u{202E}mGsNmjQ8mT",
        "H_ZM9TBrKrmGsNmjQ8mT",
    );
}

#[test]
fn adv88_framer_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "FRAMER_API_KEY=H_ZM9TBrKr\u{202C}mGsNmjQ8mT",
        "H_ZM9TBrKrmGsNmjQ8mT",
    );
}

#[test]
fn adv88_framer_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "FRAMER_API_KEY=H_ZM9TBrKr\u{200E}mGsNmjQ8mT",
        "H_ZM9TBrKrmGsNmjQ8mT",
    );
}

// =========================================================================
// 8. FRESHDESK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv88_freshdesk_api_key_normal_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "FRESHDESK_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_freshdesk_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("freshdesk-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv88_freshdesk_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "FRESHDESK_API_KEY=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_freshdesk_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "FRESHDESK_API_KEY=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_freshdesk_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "FRESHDESK_API_KEY=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_freshdesk_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "FRESHDESK_API_KEY=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_freshdesk_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "FRESHDESK_API_KEY=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_freshdesk_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "FRESHDESK_API_KEY=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_freshdesk_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "FRESHDESK_API_KEY=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_freshdesk_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "FRESHDESK_API_KEY=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_freshdesk_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "FRESHDESK_API_KEY=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv88_freshdesk_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "FRESHDESK_API_KEY=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 9. FRONT API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv88_front_api_token_normal_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
    );
}

#[test]
fn adv88_front_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "front-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv88_front_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_HjJD61TscR_QHUxJKp\u{200B}NEzF2eY6S1P6ObM-U__68h",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
    );
}

#[test]
fn adv88_front_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_HjJD61TscR_QHUxJKp\u{00AD}NEzF2eY6S1P6ObM-U__68h",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
    );
}

#[test]
fn adv88_front_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_HjJD61TscR_QHUxJKp\u{200C}NEzF2eY6S1P6ObM-U__68h",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
    );
}

#[test]
fn adv88_front_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_HjJD61TscR_QHUxJKp\u{200D}NEzF2eY6S1P6ObM-U__68h",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
    );
}

#[test]
fn adv88_front_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_HjJD61TscR_QHUxJKp\u{FEFF}NEzF2eY6S1P6ObM-U__68h",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
    );
}

#[test]
fn adv88_front_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_HjJD61TscR_QHUxJKp\u{2060}NEzF2eY6S1P6ObM-U__68h",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
    );
}

#[test]
fn adv88_front_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_HjJD61TscR_QHUxJKp\u{180E}NEzF2eY6S1P6ObM-U__68h",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
    );
}

#[test]
fn adv88_front_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_HjJD61TscR_QHUxJKp\u{202E}NEzF2eY6S1P6ObM-U__68h",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
    );
}

#[test]
fn adv88_front_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_HjJD61TscR_QHUxJKp\u{202C}NEzF2eY6S1P6ObM-U__68h",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
    );
}

#[test]
fn adv88_front_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_HjJD61TscR_QHUxJKp\u{200E}NEzF2eY6S1P6ObM-U__68h",
        "fpt_HjJD61TscR_QHUxJKpNEzF2eY6S1P6ObM-U__68h",
    );
}

// =========================================================================
// 10. FULLSTORY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv88_fullstory_api_key_normal_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "FULLSTORY_API_KEY=na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
        "na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
    );
}

#[test]
fn adv88_fullstory_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fullstory-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv88_fullstory_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "FULLSTORY_API_KEY=na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuU\u{200B}ORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
        "na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
    );
}

#[test]
fn adv88_fullstory_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "FULLSTORY_API_KEY=na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuU\u{00AD}ORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
        "na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
    );
}

#[test]
fn adv88_fullstory_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "FULLSTORY_API_KEY=na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuU\u{200C}ORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
        "na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
    );
}

#[test]
fn adv88_fullstory_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "FULLSTORY_API_KEY=na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuU\u{200D}ORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
        "na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
    );
}

#[test]
fn adv88_fullstory_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "FULLSTORY_API_KEY=na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuU\u{FEFF}ORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
        "na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
    );
}

#[test]
fn adv88_fullstory_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "FULLSTORY_API_KEY=na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuU\u{2060}ORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
        "na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
    );
}

#[test]
fn adv88_fullstory_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "FULLSTORY_API_KEY=na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuU\u{180E}ORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
        "na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
    );
}

#[test]
fn adv88_fullstory_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "FULLSTORY_API_KEY=na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuU\u{202E}ORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
        "na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
    );
}

#[test]
fn adv88_fullstory_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "FULLSTORY_API_KEY=na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuU\u{202C}ORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
        "na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
    );
}

#[test]
fn adv88_fullstory_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "FULLSTORY_API_KEY=na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuU\u{200E}ORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
        "na1.ylPfzLN_HDUWbwrKqwThoQUtlcBtscgCtYvQG04QvayuUORdk1v1QdsZZWUOoHw5jFS52CijRBH1MSO6dcQ9NmJQG2ae4hn",
    );
}
