//! Part 70 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates bamboohr, bandwidth, base, basecamp, baseten, betterstack, bigcommerce, bigcommerce, bing, bitbucket detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. BAMBOOHR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv70_bamboohr_api_key_normal_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "BAMBOOHR_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv70_bamboohr_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bamboohr-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv70_bamboohr_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "BAMBOOHR_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{200B}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv70_bamboohr_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "BAMBOOHR_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{00AD}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv70_bamboohr_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "BAMBOOHR_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{200C}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv70_bamboohr_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "BAMBOOHR_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{200D}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv70_bamboohr_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "BAMBOOHR_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{FEFF}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv70_bamboohr_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "BAMBOOHR_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{2060}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv70_bamboohr_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "BAMBOOHR_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{180E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv70_bamboohr_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "BAMBOOHR_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{202E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv70_bamboohr_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "BAMBOOHR_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{202C}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv70_bamboohr_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "bamboohr-api-key",
        "BAMBOOHR_API_KEY=7b3e5d8c1a9f4e2b6c8d\u{200E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

// =========================================================================
// 2. BANDWIDTH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv70_bandwidth_api_key_normal_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "BANDWIDTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv70_bandwidth_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bandwidth-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv70_bandwidth_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "BANDWIDTH_TOKEN=Kp4Qx7Rm2Sn5\u{200B}Tb8Vw3YzKp4Qx",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv70_bandwidth_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "BANDWIDTH_TOKEN=Kp4Qx7Rm2Sn5\u{00AD}Tb8Vw3YzKp4Qx",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv70_bandwidth_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "BANDWIDTH_TOKEN=Kp4Qx7Rm2Sn5\u{200C}Tb8Vw3YzKp4Qx",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv70_bandwidth_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "BANDWIDTH_TOKEN=Kp4Qx7Rm2Sn5\u{200D}Tb8Vw3YzKp4Qx",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv70_bandwidth_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "BANDWIDTH_TOKEN=Kp4Qx7Rm2Sn5\u{FEFF}Tb8Vw3YzKp4Qx",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv70_bandwidth_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "BANDWIDTH_TOKEN=Kp4Qx7Rm2Sn5\u{2060}Tb8Vw3YzKp4Qx",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv70_bandwidth_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "BANDWIDTH_TOKEN=Kp4Qx7Rm2Sn5\u{180E}Tb8Vw3YzKp4Qx",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv70_bandwidth_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "BANDWIDTH_TOKEN=Kp4Qx7Rm2Sn5\u{202E}Tb8Vw3YzKp4Qx",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv70_bandwidth_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "BANDWIDTH_TOKEN=Kp4Qx7Rm2Sn5\u{202C}Tb8Vw3YzKp4Qx",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv70_bandwidth_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "bandwidth-api-key",
        "BANDWIDTH_TOKEN=Kp4Qx7Rm2Sn5\u{200E}Tb8Vw3YzKp4Qx",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

// =========================================================================
// 3. BASE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv70_base_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv70_base_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "base-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv70_base_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base_api_key=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv70_base_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base_api_key=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv70_base_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base_api_key=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv70_base_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base_api_key=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv70_base_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base_api_key=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv70_base_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base_api_key=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv70_base_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base_api_key=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv70_base_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base_api_key=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv70_base_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base_api_key=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv70_base_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "base-api-credentials",
        "base_api_key=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 4. BASECAMP ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv70_basecamp_access_token_normal_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_ACCESS_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
    );
}

#[test]
fn adv70_basecamp_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "basecamp-access-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv70_basecamp_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_ACCESS_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200B}4Qx7Rm2Sn5Tb8Vw3YzKpKp",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
    );
}

#[test]
fn adv70_basecamp_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_ACCESS_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{00AD}4Qx7Rm2Sn5Tb8Vw3YzKpKp",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
    );
}

#[test]
fn adv70_basecamp_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_ACCESS_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200C}4Qx7Rm2Sn5Tb8Vw3YzKpKp",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
    );
}

#[test]
fn adv70_basecamp_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_ACCESS_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200D}4Qx7Rm2Sn5Tb8Vw3YzKpKp",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
    );
}

#[test]
fn adv70_basecamp_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_ACCESS_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{FEFF}4Qx7Rm2Sn5Tb8Vw3YzKpKp",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
    );
}

#[test]
fn adv70_basecamp_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_ACCESS_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{2060}4Qx7Rm2Sn5Tb8Vw3YzKpKp",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
    );
}

#[test]
fn adv70_basecamp_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_ACCESS_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{180E}4Qx7Rm2Sn5Tb8Vw3YzKpKp",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
    );
}

#[test]
fn adv70_basecamp_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_ACCESS_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{202E}4Qx7Rm2Sn5Tb8Vw3YzKpKp",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
    );
}

#[test]
fn adv70_basecamp_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_ACCESS_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{202C}4Qx7Rm2Sn5Tb8Vw3YzKpKp",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
    );
}

#[test]
fn adv70_basecamp_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "basecamp-access-token",
        "BASECAMP_ACCESS_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200E}4Qx7Rm2Sn5Tb8Vw3YzKpKp",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpKp",
    );
}

// =========================================================================
// 5. BASETEN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv70_baseten_api_key_normal_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv70_baseten_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "baseten-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv70_baseten_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200B}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv70_baseten_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{00AD}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv70_baseten_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200C}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv70_baseten_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200D}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv70_baseten_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{FEFF}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv70_baseten_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{2060}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv70_baseten_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{180E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv70_baseten_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{202E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv70_baseten_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{202C}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv70_baseten_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "baseten-api-key",
        "BASETEN_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

// =========================================================================
// 6. BETTERSTACK SOURCE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv70_betterstack_source_token_normal_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_source_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_betterstack_source_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "betterstack-source-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv70_betterstack_source_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_source_token=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_betterstack_source_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_source_token=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_betterstack_source_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_source_token=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_betterstack_source_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_source_token=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_betterstack_source_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_source_token=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_betterstack_source_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_source_token=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_betterstack_source_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_source_token=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_betterstack_source_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_source_token=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_betterstack_source_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_source_token=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_betterstack_source_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "betterstack-source-token",
        "betterstack_source_token=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 7. BIGCOMMERCE ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv70_bigcommerce_access_token_normal_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
    );
}

#[test]
fn adv70_bigcommerce_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bigcommerce-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv70_bigcommerce_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz012\u{200B}3456789AbCdEfGhIjKlMnOpQrStUvWxYz",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
    );
}

#[test]
fn adv70_bigcommerce_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz012\u{00AD}3456789AbCdEfGhIjKlMnOpQrStUvWxYz",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
    );
}

#[test]
fn adv70_bigcommerce_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz012\u{200C}3456789AbCdEfGhIjKlMnOpQrStUvWxYz",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
    );
}

#[test]
fn adv70_bigcommerce_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz012\u{200D}3456789AbCdEfGhIjKlMnOpQrStUvWxYz",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
    );
}

#[test]
fn adv70_bigcommerce_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz012\u{FEFF}3456789AbCdEfGhIjKlMnOpQrStUvWxYz",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
    );
}

#[test]
fn adv70_bigcommerce_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz012\u{2060}3456789AbCdEfGhIjKlMnOpQrStUvWxYz",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
    );
}

#[test]
fn adv70_bigcommerce_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz012\u{180E}3456789AbCdEfGhIjKlMnOpQrStUvWxYz",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
    );
}

#[test]
fn adv70_bigcommerce_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz012\u{202E}3456789AbCdEfGhIjKlMnOpQrStUvWxYz",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
    );
}

#[test]
fn adv70_bigcommerce_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz012\u{202C}3456789AbCdEfGhIjKlMnOpQrStUvWxYz",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
    );
}

#[test]
fn adv70_bigcommerce_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "bigcommerce-access-token",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz012\u{200E}3456789AbCdEfGhIjKlMnOpQrStUvWxYz",
        "bbc_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
    );
}

// =========================================================================
// 8. BIGCOMMERCE STORE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv70_bigcommerce_store_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
    );
}

#[test]
fn adv70_bigcommerce_store_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bigcommerce-store-api-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv70_bigcommerce_store_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{200B}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
    );
}

#[test]
fn adv70_bigcommerce_store_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{00AD}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
    );
}

#[test]
fn adv70_bigcommerce_store_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{200C}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
    );
}

#[test]
fn adv70_bigcommerce_store_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{200D}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
    );
}

#[test]
fn adv70_bigcommerce_store_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{FEFF}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
    );
}

#[test]
fn adv70_bigcommerce_store_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{2060}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
    );
}

#[test]
fn adv70_bigcommerce_store_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{180E}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
    );
}

#[test]
fn adv70_bigcommerce_store_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{202E}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
    );
}

#[test]
fn adv70_bigcommerce_store_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{202C}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
    );
}

#[test]
fn adv70_bigcommerce_store_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "bigcommerce-store-api-credentials",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{200E}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
        "bbc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbVwYz",
    );
}

// =========================================================================
// 9. BING MAPS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv70_bing_maps_api_key_normal_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv70_bing_maps_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bing-maps-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv70_bing_maps_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw\u{200B}3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv70_bing_maps_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw\u{00AD}3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv70_bing_maps_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw\u{200C}3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv70_bing_maps_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw\u{200D}3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv70_bing_maps_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw\u{FEFF}3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv70_bing_maps_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw\u{2060}3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv70_bing_maps_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw\u{180E}3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv70_bing_maps_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw\u{202E}3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv70_bing_maps_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw\u{202C}3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv70_bing_maps_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "bing-maps-api-key",
        "BING_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw\u{200E}3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

// =========================================================================
// 10. BITBUCKET APP PASSWORD ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv70_bitbucket_app_password_normal_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_bitbucket_app_password_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bitbucket-app-password",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv70_bitbucket_app_password_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_bitbucket_app_password_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_bitbucket_app_password_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_bitbucket_app_password_evade_zwj_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_bitbucket_app_password_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_bitbucket_app_password_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_bitbucket_app_password_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_bitbucket_app_password_evade_rtl_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_bitbucket_app_password_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv70_bitbucket_app_password_evade_lrm_must_fire() {
    assert_detector_fires(
        "bitbucket-app-password",
        "bitbucket_app_password=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}


