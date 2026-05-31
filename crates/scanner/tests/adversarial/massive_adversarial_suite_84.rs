//! Part 84 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates dynatrace, easypost, ebay, elastic, elasticsearch, elasticsearch, elevenlabs, eloqua, env0, epa detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DYNATRACE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv84_dynatrace_api_token_normal_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
    );
}

#[test]
fn adv84_dynatrace_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dynatrace-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv84_dynatrace_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9\u{200B}B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
    );
}

#[test]
fn adv84_dynatrace_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9\u{00AD}B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
    );
}

#[test]
fn adv84_dynatrace_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9\u{200C}B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
    );
}

#[test]
fn adv84_dynatrace_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9\u{200D}B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
    );
}

#[test]
fn adv84_dynatrace_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9\u{FEFF}B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
    );
}

#[test]
fn adv84_dynatrace_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9\u{2060}B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
    );
}

#[test]
fn adv84_dynatrace_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9\u{180E}B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
    );
}

#[test]
fn adv84_dynatrace_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9\u{202E}B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
    );
}

#[test]
fn adv84_dynatrace_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9\u{202C}B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
    );
}

#[test]
fn adv84_dynatrace_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9\u{200E}B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
        "dt0c01.A9C7E3F1B5D2H8K4N6P0Q8R2.Z3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1R7T0P3X8N7Y2V6W1H4G9B5D3F8K2L4M6Q1",
    );
}

// =========================================================================
// 2. EASYPOST API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv84_easypost_api_key_normal_must_fire() {
    assert_detector_fires(
        "easypost-api-key",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_easypost_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "easypost-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv84_easypost_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "easypost-api-key",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200B}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_easypost_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "easypost-api-key",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{00AD}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_easypost_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "easypost-api-key",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200C}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_easypost_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "easypost-api-key",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200D}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_easypost_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "easypost-api-key",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{FEFF}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_easypost_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "easypost-api-key",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{2060}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_easypost_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "easypost-api-key",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{180E}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_easypost_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "easypost-api-key",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{202E}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_easypost_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "easypost-api-key",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{202C}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_easypost_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "easypost-api-key",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200E}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "EZAKKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 3. EBAY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv84_ebay_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "EBAY_APP_ID=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv84_ebay_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ebay-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv84_ebay_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "EBAY_APP_ID=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv84_ebay_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "EBAY_APP_ID=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv84_ebay_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "EBAY_APP_ID=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv84_ebay_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "EBAY_APP_ID=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv84_ebay_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "EBAY_APP_ID=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv84_ebay_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "EBAY_APP_ID=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv84_ebay_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "EBAY_APP_ID=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv84_ebay_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "EBAY_APP_ID=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv84_ebay_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "EBAY_APP_ID=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv84_ebay_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "EBAY_APP_ID=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 4. ELASTIC CLOUD API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv84_elastic_cloud_api_key_normal_must_fire() {
    assert_detector_fires(
        "elastic-cloud-api-key",
        "ELASTIC_CLOUD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elastic_cloud_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "elastic-cloud-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv84_elastic_cloud_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "elastic-cloud-api-key",
        "ELASTIC_CLOUD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200B}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elastic_cloud_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "elastic-cloud-api-key",
        "ELASTIC_CLOUD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{00AD}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elastic_cloud_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "elastic-cloud-api-key",
        "ELASTIC_CLOUD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200C}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elastic_cloud_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "elastic-cloud-api-key",
        "ELASTIC_CLOUD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200D}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elastic_cloud_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "elastic-cloud-api-key",
        "ELASTIC_CLOUD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{FEFF}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elastic_cloud_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "elastic-cloud-api-key",
        "ELASTIC_CLOUD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{2060}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elastic_cloud_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "elastic-cloud-api-key",
        "ELASTIC_CLOUD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{180E}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elastic_cloud_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "elastic-cloud-api-key",
        "ELASTIC_CLOUD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{202E}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elastic_cloud_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "elastic-cloud-api-key",
        "ELASTIC_CLOUD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{202C}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elastic_cloud_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "elastic-cloud-api-key",
        "ELASTIC_CLOUD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200E}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

// =========================================================================
// 5. ELASTICSEARCH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv84_elasticsearch_api_key_normal_must_fire() {
    assert_detector_fires(
        "elasticsearch-api-key",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elasticsearch_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "elasticsearch-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv84_elasticsearch_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "elasticsearch-api-key",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200B}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elasticsearch_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "elasticsearch-api-key",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{00AD}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elasticsearch_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "elasticsearch-api-key",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200C}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elasticsearch_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "elasticsearch-api-key",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200D}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elasticsearch_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "elasticsearch-api-key",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{FEFF}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elasticsearch_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "elasticsearch-api-key",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{2060}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elasticsearch_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "elasticsearch-api-key",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{180E}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elasticsearch_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "elasticsearch-api-key",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{202E}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elasticsearch_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "elasticsearch-api-key",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{202C}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_elasticsearch_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "elasticsearch-api-key",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200E}2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V",
    );
}

// =========================================================================
// 6. ELASTICSEARCH BASIC AUTH ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv84_elasticsearch_basic_auth_normal_must_fire() {
    assert_detector_fires(
        "elasticsearch-basic-auth",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_elasticsearch_basic_auth_wrong_prefix_must_silent() {
    assert_detector_silent(
        "elasticsearch-basic-auth",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv84_elasticsearch_basic_auth_evade_zwsp_must_fire() {
    assert_detector_fires(
        "elasticsearch-basic-auth",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_elasticsearch_basic_auth_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "elasticsearch-basic-auth",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_elasticsearch_basic_auth_evade_zwnj_must_fire() {
    assert_detector_fires(
        "elasticsearch-basic-auth",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_elasticsearch_basic_auth_evade_zwj_must_fire() {
    assert_detector_fires(
        "elasticsearch-basic-auth",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_elasticsearch_basic_auth_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "elasticsearch-basic-auth",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_elasticsearch_basic_auth_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "elasticsearch-basic-auth",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_elasticsearch_basic_auth_evade_mongolian_must_fire() {
    assert_detector_fires(
        "elasticsearch-basic-auth",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_elasticsearch_basic_auth_evade_rtl_must_fire() {
    assert_detector_fires(
        "elasticsearch-basic-auth",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_elasticsearch_basic_auth_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "elasticsearch-basic-auth",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_elasticsearch_basic_auth_evade_lrm_must_fire() {
    assert_detector_fires(
        "elasticsearch-basic-auth",
        "ELASTICSEARCH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 7. ELEVENLABS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv84_elevenlabs_api_key_normal_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv84_elevenlabs_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("elevenlabs-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv84_elevenlabs_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "sk_7b3e5d8c1a9f4e\u{200B}2b6c8d3a5e9f1b7c4d",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv84_elevenlabs_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "sk_7b3e5d8c1a9f4e\u{00AD}2b6c8d3a5e9f1b7c4d",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv84_elevenlabs_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "sk_7b3e5d8c1a9f4e\u{200C}2b6c8d3a5e9f1b7c4d",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv84_elevenlabs_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "sk_7b3e5d8c1a9f4e\u{200D}2b6c8d3a5e9f1b7c4d",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv84_elevenlabs_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "sk_7b3e5d8c1a9f4e\u{FEFF}2b6c8d3a5e9f1b7c4d",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv84_elevenlabs_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "sk_7b3e5d8c1a9f4e\u{2060}2b6c8d3a5e9f1b7c4d",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv84_elevenlabs_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "sk_7b3e5d8c1a9f4e\u{180E}2b6c8d3a5e9f1b7c4d",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv84_elevenlabs_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "sk_7b3e5d8c1a9f4e\u{202E}2b6c8d3a5e9f1b7c4d",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv84_elevenlabs_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "sk_7b3e5d8c1a9f4e\u{202C}2b6c8d3a5e9f1b7c4d",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv84_elevenlabs_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "sk_7b3e5d8c1a9f4e\u{200E}2b6c8d3a5e9f1b7c4d",
        "sk_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 8. ELOQUA API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv84_eloqua_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "eloqua-api-credentials",
        "ELOQUA_SITE_NAME=Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_eloqua_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("eloqua-api-credentials", "dummy_prefix_0 =xxxxxxxxxxxxxxxx");
}

#[test]
fn adv84_eloqua_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "eloqua-api-credentials",
        "ELOQUA_SITE_NAME=Kp4Qx7Rm\u{200B}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_eloqua_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "eloqua-api-credentials",
        "ELOQUA_SITE_NAME=Kp4Qx7Rm\u{00AD}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_eloqua_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "eloqua-api-credentials",
        "ELOQUA_SITE_NAME=Kp4Qx7Rm\u{200C}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_eloqua_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "eloqua-api-credentials",
        "ELOQUA_SITE_NAME=Kp4Qx7Rm\u{200D}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_eloqua_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "eloqua-api-credentials",
        "ELOQUA_SITE_NAME=Kp4Qx7Rm\u{FEFF}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_eloqua_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "eloqua-api-credentials",
        "ELOQUA_SITE_NAME=Kp4Qx7Rm\u{2060}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_eloqua_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "eloqua-api-credentials",
        "ELOQUA_SITE_NAME=Kp4Qx7Rm\u{180E}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_eloqua_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "eloqua-api-credentials",
        "ELOQUA_SITE_NAME=Kp4Qx7Rm\u{202E}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_eloqua_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "eloqua-api-credentials",
        "ELOQUA_SITE_NAME=Kp4Qx7Rm\u{202C}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv84_eloqua_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "eloqua-api-credentials",
        "ELOQUA_SITE_NAME=Kp4Qx7Rm\u{200E}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

// =========================================================================
// 9. ENV0 API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv84_env0_api_key_normal_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "ENV0_API_KEY=a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    );
}

#[test]
fn adv84_env0_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "env0-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv84_env0_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "ENV0_API_KEY=a1b2c3d4-e5f6-4a7b\u{200B}-8c9d-0e1f2a3b4c5d",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    );
}

#[test]
fn adv84_env0_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "ENV0_API_KEY=a1b2c3d4-e5f6-4a7b\u{00AD}-8c9d-0e1f2a3b4c5d",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    );
}

#[test]
fn adv84_env0_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "ENV0_API_KEY=a1b2c3d4-e5f6-4a7b\u{200C}-8c9d-0e1f2a3b4c5d",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    );
}

#[test]
fn adv84_env0_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "ENV0_API_KEY=a1b2c3d4-e5f6-4a7b\u{200D}-8c9d-0e1f2a3b4c5d",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    );
}

#[test]
fn adv84_env0_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "ENV0_API_KEY=a1b2c3d4-e5f6-4a7b\u{FEFF}-8c9d-0e1f2a3b4c5d",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    );
}

#[test]
fn adv84_env0_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "ENV0_API_KEY=a1b2c3d4-e5f6-4a7b\u{2060}-8c9d-0e1f2a3b4c5d",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    );
}

#[test]
fn adv84_env0_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "ENV0_API_KEY=a1b2c3d4-e5f6-4a7b\u{180E}-8c9d-0e1f2a3b4c5d",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    );
}

#[test]
fn adv84_env0_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "ENV0_API_KEY=a1b2c3d4-e5f6-4a7b\u{202E}-8c9d-0e1f2a3b4c5d",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    );
}

#[test]
fn adv84_env0_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "ENV0_API_KEY=a1b2c3d4-e5f6-4a7b\u{202C}-8c9d-0e1f2a3b4c5d",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    );
}

#[test]
fn adv84_env0_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "ENV0_API_KEY=a1b2c3d4-e5f6-4a7b\u{200E}-8c9d-0e1f2a3b4c5d",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    );
}

// =========================================================================
// 10. EPA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv84_epa_api_key_normal_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "EPA_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_epa_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "epa-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv84_epa_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "EPA_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzK\u{200B}p4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_epa_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "EPA_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzK\u{00AD}p4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_epa_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "EPA_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzK\u{200C}p4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_epa_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "EPA_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzK\u{200D}p4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_epa_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "EPA_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzK\u{FEFF}p4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_epa_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "EPA_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzK\u{2060}p4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_epa_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "EPA_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzK\u{180E}p4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_epa_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "EPA_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzK\u{202E}p4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_epa_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "EPA_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzK\u{202C}p4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv84_epa_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "EPA_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzK\u{200E}p4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}
