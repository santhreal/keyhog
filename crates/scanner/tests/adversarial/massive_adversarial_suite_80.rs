//! Part 80 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates databricks, datadog, datadog, datocms, deel, deepgram, deepl, deepnote, deepseek, deezer detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DATABRICKS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv80_databricks_token_normal_must_fire() {
    assert_detector_fires(
        "databricks-token",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv80_databricks_token_wrong_prefix_must_silent() {
    assert_detector_silent("databricks-token", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv80_databricks_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "databricks-token",
        "dapi9a3b7c2e4d1f6a\u{200B}8b0c5d9e3f7a1b4c2d",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv80_databricks_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "databricks-token",
        "dapi9a3b7c2e4d1f6a\u{00AD}8b0c5d9e3f7a1b4c2d",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv80_databricks_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "databricks-token",
        "dapi9a3b7c2e4d1f6a\u{200C}8b0c5d9e3f7a1b4c2d",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv80_databricks_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "databricks-token",
        "dapi9a3b7c2e4d1f6a\u{200D}8b0c5d9e3f7a1b4c2d",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv80_databricks_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "databricks-token",
        "dapi9a3b7c2e4d1f6a\u{FEFF}8b0c5d9e3f7a1b4c2d",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv80_databricks_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "databricks-token",
        "dapi9a3b7c2e4d1f6a\u{2060}8b0c5d9e3f7a1b4c2d",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv80_databricks_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "databricks-token",
        "dapi9a3b7c2e4d1f6a\u{180E}8b0c5d9e3f7a1b4c2d",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv80_databricks_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "databricks-token",
        "dapi9a3b7c2e4d1f6a\u{202E}8b0c5d9e3f7a1b4c2d",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv80_databricks_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "databricks-token",
        "dapi9a3b7c2e4d1f6a\u{202C}8b0c5d9e3f7a1b4c2d",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

#[test]
fn adv80_databricks_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "databricks-token",
        "dapi9a3b7c2e4d1f6a\u{200E}8b0c5d9e3f7a1b4c2d",
        "dapi9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d",
    );
}

// =========================================================================
// 2. DATADOG API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv80_datadog_api_key_normal_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_datadog_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "datadog-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv80_datadog_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_datadog_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_datadog_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_datadog_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_datadog_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_datadog_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_datadog_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_datadog_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_datadog_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_datadog_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 3. DATADOG APPLICATION KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv80_datadog_application_key_normal_must_fire() {
    assert_detector_fires(
        "datadog-application-key",
        "DATADOG_APP_KEY=3b70df2c347b7e02b642198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv80_datadog_application_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "datadog-application-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv80_datadog_application_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "datadog-application-key",
        "DATADOG_APP_KEY=3b70df2c347b7e02b642\u{200B}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv80_datadog_application_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "datadog-application-key",
        "DATADOG_APP_KEY=3b70df2c347b7e02b642\u{00AD}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv80_datadog_application_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "datadog-application-key",
        "DATADOG_APP_KEY=3b70df2c347b7e02b642\u{200C}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv80_datadog_application_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "datadog-application-key",
        "DATADOG_APP_KEY=3b70df2c347b7e02b642\u{200D}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv80_datadog_application_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "datadog-application-key",
        "DATADOG_APP_KEY=3b70df2c347b7e02b642\u{FEFF}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv80_datadog_application_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "datadog-application-key",
        "DATADOG_APP_KEY=3b70df2c347b7e02b642\u{2060}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv80_datadog_application_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "datadog-application-key",
        "DATADOG_APP_KEY=3b70df2c347b7e02b642\u{180E}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv80_datadog_application_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "datadog-application-key",
        "DATADOG_APP_KEY=3b70df2c347b7e02b642\u{202E}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv80_datadog_application_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "datadog-application-key",
        "DATADOG_APP_KEY=3b70df2c347b7e02b642\u{202C}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv80_datadog_application_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "datadog-application-key",
        "DATADOG_APP_KEY=3b70df2c347b7e02b642\u{200E}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

// =========================================================================
// 4. DATOCMS API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv80_datocms_api_token_normal_must_fire() {
    assert_detector_fires(
        "datocms-api-token",
        "DATOCMS_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_datocms_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "datocms-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv80_datocms_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "datocms-api-token",
        "DATOCMS_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_datocms_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "datocms-api-token",
        "DATOCMS_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_datocms_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "datocms-api-token",
        "DATOCMS_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_datocms_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "datocms-api-token",
        "DATOCMS_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_datocms_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "datocms-api-token",
        "DATOCMS_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_datocms_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "datocms-api-token",
        "DATOCMS_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_datocms_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "datocms-api-token",
        "DATOCMS_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_datocms_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "datocms-api-token",
        "DATOCMS_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_datocms_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "datocms-api-token",
        "DATOCMS_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_datocms_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "datocms-api-token",
        "DATOCMS_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 5. DEEL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv80_deel_api_key_normal_must_fire() {
    assert_detector_fires(
        "deel-api-key",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deel_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "deel-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv80_deel_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "deel-api-key",
        "organization_Kp4Qx7Rm2Sn5T\u{200B}b8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deel_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "deel-api-key",
        "organization_Kp4Qx7Rm2Sn5T\u{00AD}b8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deel_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "deel-api-key",
        "organization_Kp4Qx7Rm2Sn5T\u{200C}b8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deel_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "deel-api-key",
        "organization_Kp4Qx7Rm2Sn5T\u{200D}b8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deel_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "deel-api-key",
        "organization_Kp4Qx7Rm2Sn5T\u{FEFF}b8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deel_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "deel-api-key",
        "organization_Kp4Qx7Rm2Sn5T\u{2060}b8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deel_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "deel-api-key",
        "organization_Kp4Qx7Rm2Sn5T\u{180E}b8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deel_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "deel-api-key",
        "organization_Kp4Qx7Rm2Sn5T\u{202E}b8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deel_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "deel-api-key",
        "organization_Kp4Qx7Rm2Sn5T\u{202C}b8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deel_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "deel-api-key",
        "organization_Kp4Qx7Rm2Sn5T\u{200E}b8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "organization_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 6. DEEPGRAM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv80_deepgram_api_key_normal_must_fire() {
    assert_detector_fires(
        "deepgram-api-key",
        "DEEPGRAM_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv80_deepgram_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "deepgram-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv80_deepgram_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "deepgram-api-key",
        "DEEPGRAM_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{200B}3a5e9f1b7c4d7b3ea9e2",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv80_deepgram_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "deepgram-api-key",
        "DEEPGRAM_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{00AD}3a5e9f1b7c4d7b3ea9e2",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv80_deepgram_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "deepgram-api-key",
        "DEEPGRAM_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{200C}3a5e9f1b7c4d7b3ea9e2",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv80_deepgram_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "deepgram-api-key",
        "DEEPGRAM_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{200D}3a5e9f1b7c4d7b3ea9e2",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv80_deepgram_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "deepgram-api-key",
        "DEEPGRAM_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{FEFF}3a5e9f1b7c4d7b3ea9e2",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv80_deepgram_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "deepgram-api-key",
        "DEEPGRAM_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{2060}3a5e9f1b7c4d7b3ea9e2",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv80_deepgram_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "deepgram-api-key",
        "DEEPGRAM_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{180E}3a5e9f1b7c4d7b3ea9e2",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv80_deepgram_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "deepgram-api-key",
        "DEEPGRAM_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{202E}3a5e9f1b7c4d7b3ea9e2",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv80_deepgram_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "deepgram-api-key",
        "DEEPGRAM_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{202C}3a5e9f1b7c4d7b3ea9e2",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv80_deepgram_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "deepgram-api-key",
        "DEEPGRAM_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{200E}3a5e9f1b7c4d7b3ea9e2",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

// =========================================================================
// 7. DEEPL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv80_deepl_api_key_normal_must_fire() {
    assert_detector_fires(
        "deepl-api-key",
        "DEEPL_API_KEY=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
    );
}

#[test]
fn adv80_deepl_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "deepl-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv80_deepl_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "deepl-api-key",
        "DEEPL_API_KEY=7b3e5d8c-1a9f-4e2b-\u{200B}6c8d-3a5e9f1b7c4d:fx",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
    );
}

#[test]
fn adv80_deepl_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "deepl-api-key",
        "DEEPL_API_KEY=7b3e5d8c-1a9f-4e2b-\u{00AD}6c8d-3a5e9f1b7c4d:fx",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
    );
}

#[test]
fn adv80_deepl_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "deepl-api-key",
        "DEEPL_API_KEY=7b3e5d8c-1a9f-4e2b-\u{200C}6c8d-3a5e9f1b7c4d:fx",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
    );
}

#[test]
fn adv80_deepl_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "deepl-api-key",
        "DEEPL_API_KEY=7b3e5d8c-1a9f-4e2b-\u{200D}6c8d-3a5e9f1b7c4d:fx",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
    );
}

#[test]
fn adv80_deepl_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "deepl-api-key",
        "DEEPL_API_KEY=7b3e5d8c-1a9f-4e2b-\u{FEFF}6c8d-3a5e9f1b7c4d:fx",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
    );
}

#[test]
fn adv80_deepl_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "deepl-api-key",
        "DEEPL_API_KEY=7b3e5d8c-1a9f-4e2b-\u{2060}6c8d-3a5e9f1b7c4d:fx",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
    );
}

#[test]
fn adv80_deepl_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "deepl-api-key",
        "DEEPL_API_KEY=7b3e5d8c-1a9f-4e2b-\u{180E}6c8d-3a5e9f1b7c4d:fx",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
    );
}

#[test]
fn adv80_deepl_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "deepl-api-key",
        "DEEPL_API_KEY=7b3e5d8c-1a9f-4e2b-\u{202E}6c8d-3a5e9f1b7c4d:fx",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
    );
}

#[test]
fn adv80_deepl_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "deepl-api-key",
        "DEEPL_API_KEY=7b3e5d8c-1a9f-4e2b-\u{202C}6c8d-3a5e9f1b7c4d:fx",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
    );
}

#[test]
fn adv80_deepl_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "deepl-api-key",
        "DEEPL_API_KEY=7b3e5d8c-1a9f-4e2b-\u{200E}6c8d-3a5e9f1b7c4d:fx",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx",
    );
}

// =========================================================================
// 8. DEEPNOTE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv80_deepnote_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "deepnote-api-credentials",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deepnote_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "deepnote-api-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv80_deepnote_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "deepnote-api-credentials",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deepnote_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "deepnote-api-credentials",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deepnote_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "deepnote-api-credentials",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3\u{200C}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deepnote_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "deepnote-api-credentials",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3\u{200D}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deepnote_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "deepnote-api-credentials",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3\u{FEFF}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deepnote_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "deepnote-api-credentials",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3\u{2060}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deepnote_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "deepnote-api-credentials",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3\u{180E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deepnote_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "deepnote-api-credentials",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3\u{202E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deepnote_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "deepnote-api-credentials",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3\u{202C}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv80_deepnote_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "deepnote-api-credentials",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3\u{200E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 9. DEEPSEEK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv80_deepseek_api_key_normal_must_fire() {
    assert_detector_fires(
        "deepseek-api-key",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deepseek_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("deepseek-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv80_deepseek_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "deepseek-api-key",
        "sk-7b3e5d8c1a9f4e\u{200B}2b6c8d3a5e9f1b7c4d",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deepseek_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "deepseek-api-key",
        "sk-7b3e5d8c1a9f4e\u{00AD}2b6c8d3a5e9f1b7c4d",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deepseek_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "deepseek-api-key",
        "sk-7b3e5d8c1a9f4e\u{200C}2b6c8d3a5e9f1b7c4d",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deepseek_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "deepseek-api-key",
        "sk-7b3e5d8c1a9f4e\u{200D}2b6c8d3a5e9f1b7c4d",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deepseek_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "deepseek-api-key",
        "sk-7b3e5d8c1a9f4e\u{FEFF}2b6c8d3a5e9f1b7c4d",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deepseek_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "deepseek-api-key",
        "sk-7b3e5d8c1a9f4e\u{2060}2b6c8d3a5e9f1b7c4d",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deepseek_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "deepseek-api-key",
        "sk-7b3e5d8c1a9f4e\u{180E}2b6c8d3a5e9f1b7c4d",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deepseek_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "deepseek-api-key",
        "sk-7b3e5d8c1a9f4e\u{202E}2b6c8d3a5e9f1b7c4d",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deepseek_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "deepseek-api-key",
        "sk-7b3e5d8c1a9f4e\u{202C}2b6c8d3a5e9f1b7c4d",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deepseek_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "deepseek-api-key",
        "sk-7b3e5d8c1a9f4e\u{200E}2b6c8d3a5e9f1b7c4d",
        "sk-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 10. DEEZER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv80_deezer_api_key_normal_must_fire() {
    assert_detector_fires(
        "deezer-api-key",
        "DEEZER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deezer_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "deezer-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv80_deezer_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "deezer-api-key",
        "DEEZER_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deezer_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "deezer-api-key",
        "DEEZER_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deezer_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "deezer-api-key",
        "DEEZER_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deezer_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "deezer-api-key",
        "DEEZER_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deezer_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "deezer-api-key",
        "DEEZER_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deezer_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "deezer-api-key",
        "DEEZER_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deezer_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "deezer-api-key",
        "DEEZER_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deezer_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "deezer-api-key",
        "DEEZER_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deezer_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "deezer-api-key",
        "DEEZER_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv80_deezer_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "deezer-api-key",
        "DEEZER_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}
