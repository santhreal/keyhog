//! Part 96 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates hotjar, huawei, hubitat, hubspot, huggingface, huggingface, huggingface, humanloop, ibm, ibm detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. HOTJAR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv96_hotjar_api_key_normal_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID=zsJWFf-VUjCAnz7_l4YP",
        "zsJWFf-VUjCAnz7_l4YP",
    );
}

#[test]
fn adv96_hotjar_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("hotjar-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv96_hotjar_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID=zsJWFf-VUj\u{200B}CAnz7_l4YP",
        "zsJWFf-VUjCAnz7_l4YP",
    );
}

#[test]
fn adv96_hotjar_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID=zsJWFf-VUj\u{00AD}CAnz7_l4YP",
        "zsJWFf-VUjCAnz7_l4YP",
    );
}

#[test]
fn adv96_hotjar_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID=zsJWFf-VUj\u{200C}CAnz7_l4YP",
        "zsJWFf-VUjCAnz7_l4YP",
    );
}

#[test]
fn adv96_hotjar_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID=zsJWFf-VUj\u{200D}CAnz7_l4YP",
        "zsJWFf-VUjCAnz7_l4YP",
    );
}

#[test]
fn adv96_hotjar_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID=zsJWFf-VUj\u{FEFF}CAnz7_l4YP",
        "zsJWFf-VUjCAnz7_l4YP",
    );
}

#[test]
fn adv96_hotjar_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID=zsJWFf-VUj\u{2060}CAnz7_l4YP",
        "zsJWFf-VUjCAnz7_l4YP",
    );
}

#[test]
fn adv96_hotjar_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID=zsJWFf-VUj\u{180E}CAnz7_l4YP",
        "zsJWFf-VUjCAnz7_l4YP",
    );
}

#[test]
fn adv96_hotjar_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID=zsJWFf-VUj\u{202E}CAnz7_l4YP",
        "zsJWFf-VUjCAnz7_l4YP",
    );
}

#[test]
fn adv96_hotjar_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID=zsJWFf-VUj\u{202C}CAnz7_l4YP",
        "zsJWFf-VUjCAnz7_l4YP",
    );
}

#[test]
fn adv96_hotjar_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "hotjar-api-key",
        "HOTJAR_CLIENT_ID=zsJWFf-VUj\u{200E}CAnz7_l4YP",
        "zsJWFf-VUjCAnz7_l4YP",
    );
}

// =========================================================================
// 2. HUAWEI CLOUD API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv96_huawei_cloud_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HUAWEICLOUDAK=GR6FV9QT0XGHN4KNOALV",
        "GR6FV9QT0XGHN4KNOALV",
    );
}

#[test]
fn adv96_huawei_cloud_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "huawei-cloud-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv96_huawei_cloud_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HUAWEICLOUDAK=GR6FV9QT0X\u{200B}GHN4KNOALV",
        "GR6FV9QT0XGHN4KNOALV",
    );
}

#[test]
fn adv96_huawei_cloud_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HUAWEICLOUDAK=GR6FV9QT0X\u{00AD}GHN4KNOALV",
        "GR6FV9QT0XGHN4KNOALV",
    );
}

#[test]
fn adv96_huawei_cloud_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HUAWEICLOUDAK=GR6FV9QT0X\u{200C}GHN4KNOALV",
        "GR6FV9QT0XGHN4KNOALV",
    );
}

#[test]
fn adv96_huawei_cloud_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HUAWEICLOUDAK=GR6FV9QT0X\u{200D}GHN4KNOALV",
        "GR6FV9QT0XGHN4KNOALV",
    );
}

#[test]
fn adv96_huawei_cloud_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HUAWEICLOUDAK=GR6FV9QT0X\u{FEFF}GHN4KNOALV",
        "GR6FV9QT0XGHN4KNOALV",
    );
}

#[test]
fn adv96_huawei_cloud_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HUAWEICLOUDAK=GR6FV9QT0X\u{2060}GHN4KNOALV",
        "GR6FV9QT0XGHN4KNOALV",
    );
}

#[test]
fn adv96_huawei_cloud_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HUAWEICLOUDAK=GR6FV9QT0X\u{180E}GHN4KNOALV",
        "GR6FV9QT0XGHN4KNOALV",
    );
}

#[test]
fn adv96_huawei_cloud_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HUAWEICLOUDAK=GR6FV9QT0X\u{202E}GHN4KNOALV",
        "GR6FV9QT0XGHN4KNOALV",
    );
}

#[test]
fn adv96_huawei_cloud_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HUAWEICLOUDAK=GR6FV9QT0X\u{202C}GHN4KNOALV",
        "GR6FV9QT0XGHN4KNOALV",
    );
}

#[test]
fn adv96_huawei_cloud_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "huawei-cloud-api-credentials",
        "HUAWEICLOUDAK=GR6FV9QT0X\u{200E}GHN4KNOALV",
        "GR6FV9QT0XGHN4KNOALV",
    );
}

// =========================================================================
// 3. HUBITAT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv96_hubitat_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953e93a0df6213963265ab6",
        "83872b81e8e47b73d953e93a0df6213963265ab6",
    );
}

#[test]
fn adv96_hubitat_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hubitat-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv96_hubitat_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953\u{200B}e93a0df6213963265ab6",
        "83872b81e8e47b73d953e93a0df6213963265ab6",
    );
}

#[test]
fn adv96_hubitat_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953\u{00AD}e93a0df6213963265ab6",
        "83872b81e8e47b73d953e93a0df6213963265ab6",
    );
}

#[test]
fn adv96_hubitat_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953\u{200C}e93a0df6213963265ab6",
        "83872b81e8e47b73d953e93a0df6213963265ab6",
    );
}

#[test]
fn adv96_hubitat_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953\u{200D}e93a0df6213963265ab6",
        "83872b81e8e47b73d953e93a0df6213963265ab6",
    );
}

#[test]
fn adv96_hubitat_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953\u{FEFF}e93a0df6213963265ab6",
        "83872b81e8e47b73d953e93a0df6213963265ab6",
    );
}

#[test]
fn adv96_hubitat_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953\u{2060}e93a0df6213963265ab6",
        "83872b81e8e47b73d953e93a0df6213963265ab6",
    );
}

#[test]
fn adv96_hubitat_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953\u{180E}e93a0df6213963265ab6",
        "83872b81e8e47b73d953e93a0df6213963265ab6",
    );
}

#[test]
fn adv96_hubitat_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953\u{202E}e93a0df6213963265ab6",
        "83872b81e8e47b73d953e93a0df6213963265ab6",
    );
}

#[test]
fn adv96_hubitat_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953\u{202C}e93a0df6213963265ab6",
        "83872b81e8e47b73d953e93a0df6213963265ab6",
    );
}

#[test]
fn adv96_hubitat_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "hubitat-api-credentials",
        "HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953\u{200E}e93a0df6213963265ab6",
        "83872b81e8e47b73d953e93a0df6213963265ab6",
    );
}

// =========================================================================
// 4. HUBSPOT PRIVATE APP TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv96_hubspot_private_app_token_normal_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv96_hubspot_private_app_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hubspot-private-app-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv96_hubspot_private_app_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "pat-na1-a1b2c3d4-e5f6-\u{200B}7890-abcd-ef1234567890",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv96_hubspot_private_app_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "pat-na1-a1b2c3d4-e5f6-\u{00AD}7890-abcd-ef1234567890",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv96_hubspot_private_app_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "pat-na1-a1b2c3d4-e5f6-\u{200C}7890-abcd-ef1234567890",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv96_hubspot_private_app_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "pat-na1-a1b2c3d4-e5f6-\u{200D}7890-abcd-ef1234567890",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv96_hubspot_private_app_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "pat-na1-a1b2c3d4-e5f6-\u{FEFF}7890-abcd-ef1234567890",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv96_hubspot_private_app_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "pat-na1-a1b2c3d4-e5f6-\u{2060}7890-abcd-ef1234567890",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv96_hubspot_private_app_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "pat-na1-a1b2c3d4-e5f6-\u{180E}7890-abcd-ef1234567890",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv96_hubspot_private_app_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "pat-na1-a1b2c3d4-e5f6-\u{202E}7890-abcd-ef1234567890",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv96_hubspot_private_app_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "pat-na1-a1b2c3d4-e5f6-\u{202C}7890-abcd-ef1234567890",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv96_hubspot_private_app_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "hubspot-private-app-token",
        "pat-na1-a1b2c3d4-e5f6-\u{200E}7890-abcd-ef1234567890",
        "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    );
}

// =========================================================================
// 5. HUGGINGFACE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv96_huggingface_api_key_normal_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
    );
}

#[test]
fn adv96_huggingface_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "huggingface-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv96_huggingface_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hf_9X3kQp7VbT2hYRz\u{200B}NcMfWj4DgEsLuHaIoBn",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
    );
}

#[test]
fn adv96_huggingface_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hf_9X3kQp7VbT2hYRz\u{00AD}NcMfWj4DgEsLuHaIoBn",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
    );
}

#[test]
fn adv96_huggingface_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hf_9X3kQp7VbT2hYRz\u{200C}NcMfWj4DgEsLuHaIoBn",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
    );
}

#[test]
fn adv96_huggingface_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hf_9X3kQp7VbT2hYRz\u{200D}NcMfWj4DgEsLuHaIoBn",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
    );
}

#[test]
fn adv96_huggingface_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hf_9X3kQp7VbT2hYRz\u{FEFF}NcMfWj4DgEsLuHaIoBn",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
    );
}

#[test]
fn adv96_huggingface_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hf_9X3kQp7VbT2hYRz\u{2060}NcMfWj4DgEsLuHaIoBn",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
    );
}

#[test]
fn adv96_huggingface_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hf_9X3kQp7VbT2hYRz\u{180E}NcMfWj4DgEsLuHaIoBn",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
    );
}

#[test]
fn adv96_huggingface_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hf_9X3kQp7VbT2hYRz\u{202E}NcMfWj4DgEsLuHaIoBn",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
    );
}

#[test]
fn adv96_huggingface_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hf_9X3kQp7VbT2hYRz\u{202C}NcMfWj4DgEsLuHaIoBn",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
    );
}

#[test]
fn adv96_huggingface_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "huggingface-api-key",
        "hf_9X3kQp7VbT2hYRz\u{200E}NcMfWj4DgEsLuHaIoBn",
        "hf_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBn",
    );
}

// =========================================================================
// 6. HUGGINGFACE ORG TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv96_huggingface_org_token_normal_must_fire() {
    assert_detector_fires(
        "huggingface-org-token",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_org_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "huggingface-org-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv96_huggingface_org_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "huggingface-org-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{200B}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_org_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "huggingface-org-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{00AD}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_org_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "huggingface-org-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{200C}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_org_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "huggingface-org-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{200D}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_org_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "huggingface-org-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{FEFF}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_org_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "huggingface-org-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{2060}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_org_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "huggingface-org-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{180E}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_org_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "huggingface-org-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{202E}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_org_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "huggingface-org-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{202C}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_org_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "huggingface-org-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{200E}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

// =========================================================================
// 7. HUGGINGFACE USER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv96_huggingface_user_token_normal_must_fire() {
    assert_detector_fires(
        "huggingface-user-token",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_user_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "huggingface-user-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv96_huggingface_user_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "huggingface-user-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{200B}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_user_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "huggingface-user-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{00AD}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_user_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "huggingface-user-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{200C}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_user_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "huggingface-user-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{200D}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_user_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "huggingface-user-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{FEFF}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_user_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "huggingface-user-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{2060}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_user_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "huggingface-user-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{180E}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_user_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "huggingface-user-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{202E}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_user_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "huggingface-user-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{202C}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv96_huggingface_user_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "huggingface-user-token",
        "hf_Kp4Qx7Rm2Sn5Tb8\u{200E}Vw3YzKp4Qx7Rm2Sn5Tb",
        "hf_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

// =========================================================================
// 8. HUMANLOOP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv96_humanloop_api_key_normal_must_fire() {
    assert_detector_fires(
        "humanloop-api-key",
        "HUMANLOOP_API_KEY=24ed7c1290d4ed5e45bd69c30994238c",
        "24ed7c1290d4ed5e45bd69c30994238c",
    );
}

#[test]
fn adv96_humanloop_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "humanloop-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv96_humanloop_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "humanloop-api-key",
        "HUMANLOOP_API_KEY=24ed7c1290d4ed5e\u{200B}45bd69c30994238c",
        "24ed7c1290d4ed5e45bd69c30994238c",
    );
}

#[test]
fn adv96_humanloop_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "humanloop-api-key",
        "HUMANLOOP_API_KEY=24ed7c1290d4ed5e\u{00AD}45bd69c30994238c",
        "24ed7c1290d4ed5e45bd69c30994238c",
    );
}

#[test]
fn adv96_humanloop_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "humanloop-api-key",
        "HUMANLOOP_API_KEY=24ed7c1290d4ed5e\u{200C}45bd69c30994238c",
        "24ed7c1290d4ed5e45bd69c30994238c",
    );
}

#[test]
fn adv96_humanloop_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "humanloop-api-key",
        "HUMANLOOP_API_KEY=24ed7c1290d4ed5e\u{200D}45bd69c30994238c",
        "24ed7c1290d4ed5e45bd69c30994238c",
    );
}

#[test]
fn adv96_humanloop_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "humanloop-api-key",
        "HUMANLOOP_API_KEY=24ed7c1290d4ed5e\u{FEFF}45bd69c30994238c",
        "24ed7c1290d4ed5e45bd69c30994238c",
    );
}

#[test]
fn adv96_humanloop_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "humanloop-api-key",
        "HUMANLOOP_API_KEY=24ed7c1290d4ed5e\u{2060}45bd69c30994238c",
        "24ed7c1290d4ed5e45bd69c30994238c",
    );
}

#[test]
fn adv96_humanloop_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "humanloop-api-key",
        "HUMANLOOP_API_KEY=24ed7c1290d4ed5e\u{180E}45bd69c30994238c",
        "24ed7c1290d4ed5e45bd69c30994238c",
    );
}

#[test]
fn adv96_humanloop_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "humanloop-api-key",
        "HUMANLOOP_API_KEY=24ed7c1290d4ed5e\u{202E}45bd69c30994238c",
        "24ed7c1290d4ed5e45bd69c30994238c",
    );
}

#[test]
fn adv96_humanloop_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "humanloop-api-key",
        "HUMANLOOP_API_KEY=24ed7c1290d4ed5e\u{202C}45bd69c30994238c",
        "24ed7c1290d4ed5e45bd69c30994238c",
    );
}

#[test]
fn adv96_humanloop_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "humanloop-api-key",
        "HUMANLOOP_API_KEY=24ed7c1290d4ed5e\u{200E}45bd69c30994238c",
        "24ed7c1290d4ed5e45bd69c30994238c",
    );
}

// =========================================================================
// 9. IBM WATSON IOT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv96_ibm_watson_iot_credentials_normal_must_fire() {
    assert_detector_fires(
        "ibm-watson-iot-credentials",
        "INTERNETOFTHINGS.ibmcloud.com",
        "INTERNETOFTHINGS.ibmcloud.com",
    );
}

#[test]
fn adv96_ibm_watson_iot_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ibm-watson-iot-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv96_ibm_watson_iot_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ibm-watson-iot-credentials",
        "INTERNETOFTHIN\u{200B}GS.ibmcloud.com",
        "INTERNETOFTHINGS.ibmcloud.com",
    );
}

#[test]
fn adv96_ibm_watson_iot_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ibm-watson-iot-credentials",
        "INTERNETOFTHIN\u{00AD}GS.ibmcloud.com",
        "INTERNETOFTHINGS.ibmcloud.com",
    );
}

#[test]
fn adv96_ibm_watson_iot_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ibm-watson-iot-credentials",
        "INTERNETOFTHIN\u{200C}GS.ibmcloud.com",
        "INTERNETOFTHINGS.ibmcloud.com",
    );
}

#[test]
fn adv96_ibm_watson_iot_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "ibm-watson-iot-credentials",
        "INTERNETOFTHIN\u{200D}GS.ibmcloud.com",
        "INTERNETOFTHINGS.ibmcloud.com",
    );
}

#[test]
fn adv96_ibm_watson_iot_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ibm-watson-iot-credentials",
        "INTERNETOFTHIN\u{FEFF}GS.ibmcloud.com",
        "INTERNETOFTHINGS.ibmcloud.com",
    );
}

#[test]
fn adv96_ibm_watson_iot_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ibm-watson-iot-credentials",
        "INTERNETOFTHIN\u{2060}GS.ibmcloud.com",
        "INTERNETOFTHINGS.ibmcloud.com",
    );
}

#[test]
fn adv96_ibm_watson_iot_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ibm-watson-iot-credentials",
        "INTERNETOFTHIN\u{180E}GS.ibmcloud.com",
        "INTERNETOFTHINGS.ibmcloud.com",
    );
}

#[test]
fn adv96_ibm_watson_iot_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "ibm-watson-iot-credentials",
        "INTERNETOFTHIN\u{202E}GS.ibmcloud.com",
        "INTERNETOFTHINGS.ibmcloud.com",
    );
}

#[test]
fn adv96_ibm_watson_iot_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ibm-watson-iot-credentials",
        "INTERNETOFTHIN\u{202C}GS.ibmcloud.com",
        "INTERNETOFTHINGS.ibmcloud.com",
    );
}

#[test]
fn adv96_ibm_watson_iot_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "ibm-watson-iot-credentials",
        "INTERNETOFTHIN\u{200E}GS.ibmcloud.com",
        "INTERNETOFTHINGS.ibmcloud.com",
    );
}

// =========================================================================
// 10. IBM WATSON TRANSLATOR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv96_ibm_watson_translator_api_key_normal_must_fire() {
    assert_detector_fires(
        "ibm-watson-translator-api-key",
        "IBM_WATSON=9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
        "9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
    );
}

#[test]
fn adv96_ibm_watson_translator_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ibm-watson-translator-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv96_ibm_watson_translator_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ibm-watson-translator-api-key",
        "IBM_WATSON=9L9h4aeLVfr2jH1\u{200B}xPSxwKcksZMTREx",
        "9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
    );
}

#[test]
fn adv96_ibm_watson_translator_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ibm-watson-translator-api-key",
        "IBM_WATSON=9L9h4aeLVfr2jH1\u{00AD}xPSxwKcksZMTREx",
        "9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
    );
}

#[test]
fn adv96_ibm_watson_translator_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ibm-watson-translator-api-key",
        "IBM_WATSON=9L9h4aeLVfr2jH1\u{200C}xPSxwKcksZMTREx",
        "9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
    );
}

#[test]
fn adv96_ibm_watson_translator_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "ibm-watson-translator-api-key",
        "IBM_WATSON=9L9h4aeLVfr2jH1\u{200D}xPSxwKcksZMTREx",
        "9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
    );
}

#[test]
fn adv96_ibm_watson_translator_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ibm-watson-translator-api-key",
        "IBM_WATSON=9L9h4aeLVfr2jH1\u{FEFF}xPSxwKcksZMTREx",
        "9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
    );
}

#[test]
fn adv96_ibm_watson_translator_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ibm-watson-translator-api-key",
        "IBM_WATSON=9L9h4aeLVfr2jH1\u{2060}xPSxwKcksZMTREx",
        "9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
    );
}

#[test]
fn adv96_ibm_watson_translator_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ibm-watson-translator-api-key",
        "IBM_WATSON=9L9h4aeLVfr2jH1\u{180E}xPSxwKcksZMTREx",
        "9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
    );
}

#[test]
fn adv96_ibm_watson_translator_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "ibm-watson-translator-api-key",
        "IBM_WATSON=9L9h4aeLVfr2jH1\u{202E}xPSxwKcksZMTREx",
        "9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
    );
}

#[test]
fn adv96_ibm_watson_translator_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ibm-watson-translator-api-key",
        "IBM_WATSON=9L9h4aeLVfr2jH1\u{202C}xPSxwKcksZMTREx",
        "9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
    );
}

#[test]
fn adv96_ibm_watson_translator_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "ibm-watson-translator-api-key",
        "IBM_WATSON=9L9h4aeLVfr2jH1\u{200E}xPSxwKcksZMTREx",
        "9L9h4aeLVfr2jH1xPSxwKcksZMTREx",
    );
}
