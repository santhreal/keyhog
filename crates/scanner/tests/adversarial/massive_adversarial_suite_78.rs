//! Part 78 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates comet, confluent, constant, contentful, convertkit, convex, cortex, countly, courier, covalent detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. COMET ML API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv78_comet_ml_api_key_normal_must_fire() {
    assert_detector_fires(
        "comet-ml-api-key",
        "COMET_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_comet_ml_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "comet-ml-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv78_comet_ml_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "comet-ml-api-key",
        "COMET_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_comet_ml_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "comet-ml-api-key",
        "COMET_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_comet_ml_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "comet-ml-api-key",
        "COMET_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_comet_ml_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "comet-ml-api-key",
        "COMET_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_comet_ml_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "comet-ml-api-key",
        "COMET_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_comet_ml_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "comet-ml-api-key",
        "COMET_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_comet_ml_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "comet-ml-api-key",
        "COMET_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_comet_ml_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "comet-ml-api-key",
        "COMET_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_comet_ml_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "comet-ml-api-key",
        "COMET_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_comet_ml_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "comet-ml-api-key",
        "COMET_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 2. CONFLUENT CLOUD API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv78_confluent_cloud_api_key_normal_must_fire() {
    assert_detector_fires(
        "confluent-cloud-api-key",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_confluent_cloud_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "confluent-cloud-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv78_confluent_cloud_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "confluent-cloud-api-key",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200B}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_confluent_cloud_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "confluent-cloud-api-key",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{00AD}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_confluent_cloud_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "confluent-cloud-api-key",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200C}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_confluent_cloud_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "confluent-cloud-api-key",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200D}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_confluent_cloud_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "confluent-cloud-api-key",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{FEFF}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_confluent_cloud_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "confluent-cloud-api-key",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{2060}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_confluent_cloud_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "confluent-cloud-api-key",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{180E}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_confluent_cloud_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "confluent-cloud-api-key",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{202E}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_confluent_cloud_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "confluent-cloud-api-key",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{202C}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_confluent_cloud_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "confluent-cloud-api-key",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200E}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "cfltKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 3. CONSTANT CONTACT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv78_constant_contact_api_key_normal_must_fire() {
    assert_detector_fires(
        "constant-contact-api-key",
        "CONSTANT_CONTACT_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv78_constant_contact_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "constant-contact-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv78_constant_contact_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "constant-contact-api-key",
        "CONSTANT_CONTACT_API_KEY=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv78_constant_contact_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "constant-contact-api-key",
        "CONSTANT_CONTACT_API_KEY=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv78_constant_contact_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "constant-contact-api-key",
        "CONSTANT_CONTACT_API_KEY=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv78_constant_contact_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "constant-contact-api-key",
        "CONSTANT_CONTACT_API_KEY=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv78_constant_contact_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "constant-contact-api-key",
        "CONSTANT_CONTACT_API_KEY=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv78_constant_contact_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "constant-contact-api-key",
        "CONSTANT_CONTACT_API_KEY=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv78_constant_contact_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "constant-contact-api-key",
        "CONSTANT_CONTACT_API_KEY=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv78_constant_contact_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "constant-contact-api-key",
        "CONSTANT_CONTACT_API_KEY=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv78_constant_contact_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "constant-contact-api-key",
        "CONSTANT_CONTACT_API_KEY=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv78_constant_contact_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "constant-contact-api-key",
        "CONSTANT_CONTACT_API_KEY=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

// =========================================================================
// 4. CONTENTFUL MANAGEMENT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv78_contentful_management_token_normal_must_fire() {
    assert_detector_fires(
        "contentful-management-token",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv78_contentful_management_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "contentful-management-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv78_contentful_management_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "contentful-management-token",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv78_contentful_management_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "contentful-management-token",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv78_contentful_management_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "contentful-management-token",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3\u{200C}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv78_contentful_management_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "contentful-management-token",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3\u{200D}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv78_contentful_management_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "contentful-management-token",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3\u{FEFF}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv78_contentful_management_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "contentful-management-token",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3\u{2060}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv78_contentful_management_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "contentful-management-token",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3\u{180E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv78_contentful_management_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "contentful-management-token",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3\u{202E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv78_contentful_management_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "contentful-management-token",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3\u{202C}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv78_contentful_management_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "contentful-management-token",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3\u{200E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "CFPAT-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

// =========================================================================
// 5. CONVERTKIT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv78_convertkit_api_key_normal_must_fire() {
    assert_detector_fires(
        "convertkit-api-key",
        "CONVERTKIT_API_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_convertkit_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "convertkit-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv78_convertkit_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "convertkit-api-key",
        "CONVERTKIT_API_SECRET=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_convertkit_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "convertkit-api-key",
        "CONVERTKIT_API_SECRET=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_convertkit_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "convertkit-api-key",
        "CONVERTKIT_API_SECRET=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_convertkit_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "convertkit-api-key",
        "CONVERTKIT_API_SECRET=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_convertkit_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "convertkit-api-key",
        "CONVERTKIT_API_SECRET=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_convertkit_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "convertkit-api-key",
        "CONVERTKIT_API_SECRET=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_convertkit_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "convertkit-api-key",
        "CONVERTKIT_API_SECRET=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_convertkit_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "convertkit-api-key",
        "CONVERTKIT_API_SECRET=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_convertkit_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "convertkit-api-key",
        "CONVERTKIT_API_SECRET=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_convertkit_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "convertkit-api-key",
        "CONVERTKIT_API_SECRET=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 6. CONVEX DEPLOYMENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv78_convex_deployment_credentials_normal_must_fire() {
    assert_detector_fires(
        "convex-deployment-credentials",
        "CONVEX_DEPLOY_KEY=prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_convex_deployment_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "convex-deployment-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv78_convex_deployment_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "convex-deployment-credentials",
        "CONVEX_DEPLOY_KEY=prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_convex_deployment_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "convex-deployment-credentials",
        "CONVEX_DEPLOY_KEY=prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_convex_deployment_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "convex-deployment-credentials",
        "CONVEX_DEPLOY_KEY=prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3\u{200C}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_convex_deployment_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "convex-deployment-credentials",
        "CONVEX_DEPLOY_KEY=prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3\u{200D}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_convex_deployment_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "convex-deployment-credentials",
        "CONVEX_DEPLOY_KEY=prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3\u{FEFF}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_convex_deployment_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "convex-deployment-credentials",
        "CONVEX_DEPLOY_KEY=prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3\u{2060}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_convex_deployment_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "convex-deployment-credentials",
        "CONVEX_DEPLOY_KEY=prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3\u{180E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_convex_deployment_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "convex-deployment-credentials",
        "CONVEX_DEPLOY_KEY=prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3\u{202E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_convex_deployment_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "convex-deployment-credentials",
        "CONVEX_DEPLOY_KEY=prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3\u{202C}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_convex_deployment_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "convex-deployment-credentials",
        "CONVEX_DEPLOY_KEY=prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3\u{200E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "prod:my-project|Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 7. CORTEX API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv78_cortex_api_key_normal_must_fire() {
    assert_detector_fires(
        "cortex-api-key",
        "CORTEX_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_cortex_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cortex-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv78_cortex_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cortex-api-key",
        "CORTEX_API_KEY=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_cortex_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cortex-api-key",
        "CORTEX_API_KEY=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_cortex_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cortex-api-key",
        "CORTEX_API_KEY=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_cortex_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cortex-api-key",
        "CORTEX_API_KEY=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_cortex_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cortex-api-key",
        "CORTEX_API_KEY=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_cortex_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cortex-api-key",
        "CORTEX_API_KEY=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_cortex_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cortex-api-key",
        "CORTEX_API_KEY=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_cortex_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cortex-api-key",
        "CORTEX_API_KEY=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_cortex_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cortex-api-key",
        "CORTEX_API_KEY=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_cortex_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cortex-api-key",
        "CORTEX_API_KEY=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 8. COUNTLY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv78_countly_api_key_normal_must_fire() {
    assert_detector_fires(
        "countly-api-key",
        "COUNTLY_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv78_countly_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "countly-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv78_countly_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "countly-api-key",
        "COUNTLY_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv78_countly_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "countly-api-key",
        "COUNTLY_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv78_countly_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "countly-api-key",
        "COUNTLY_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv78_countly_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "countly-api-key",
        "COUNTLY_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv78_countly_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "countly-api-key",
        "COUNTLY_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv78_countly_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "countly-api-key",
        "COUNTLY_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv78_countly_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "countly-api-key",
        "COUNTLY_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv78_countly_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "countly-api-key",
        "COUNTLY_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv78_countly_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "countly-api-key",
        "COUNTLY_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv78_countly_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "countly-api-key",
        "COUNTLY_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 9. COURIER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv78_courier_api_key_normal_must_fire() {
    assert_detector_fires(
        "courier-api-key",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_courier_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "courier-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv78_courier_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "courier-api-key",
        "pk_prod_Kp4Qx7\u{200B}Rm2Sn5Tb8Vw3Yz",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_courier_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "courier-api-key",
        "pk_prod_Kp4Qx7\u{00AD}Rm2Sn5Tb8Vw3Yz",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_courier_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "courier-api-key",
        "pk_prod_Kp4Qx7\u{200C}Rm2Sn5Tb8Vw3Yz",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_courier_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "courier-api-key",
        "pk_prod_Kp4Qx7\u{200D}Rm2Sn5Tb8Vw3Yz",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_courier_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "courier-api-key",
        "pk_prod_Kp4Qx7\u{FEFF}Rm2Sn5Tb8Vw3Yz",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_courier_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "courier-api-key",
        "pk_prod_Kp4Qx7\u{2060}Rm2Sn5Tb8Vw3Yz",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_courier_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "courier-api-key",
        "pk_prod_Kp4Qx7\u{180E}Rm2Sn5Tb8Vw3Yz",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_courier_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "courier-api-key",
        "pk_prod_Kp4Qx7\u{202E}Rm2Sn5Tb8Vw3Yz",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_courier_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "courier-api-key",
        "pk_prod_Kp4Qx7\u{202C}Rm2Sn5Tb8Vw3Yz",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv78_courier_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "courier-api-key",
        "pk_prod_Kp4Qx7\u{200E}Rm2Sn5Tb8Vw3Yz",
        "pk_prod_Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 10. COVALENT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv78_covalent_api_key_normal_must_fire() {
    assert_detector_fires(
        "covalent-api-key",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_covalent_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "covalent-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv78_covalent_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "covalent-api-key",
        "cqt_Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm2Sn5",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_covalent_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "covalent-api-key",
        "cqt_Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm2Sn5",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_covalent_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "covalent-api-key",
        "cqt_Kp4Qx7Rm2Sn5Tb\u{200C}8Vw3YzKp4Qx7Rm2Sn5",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_covalent_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "covalent-api-key",
        "cqt_Kp4Qx7Rm2Sn5Tb\u{200D}8Vw3YzKp4Qx7Rm2Sn5",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_covalent_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "covalent-api-key",
        "cqt_Kp4Qx7Rm2Sn5Tb\u{FEFF}8Vw3YzKp4Qx7Rm2Sn5",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_covalent_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "covalent-api-key",
        "cqt_Kp4Qx7Rm2Sn5Tb\u{2060}8Vw3YzKp4Qx7Rm2Sn5",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_covalent_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "covalent-api-key",
        "cqt_Kp4Qx7Rm2Sn5Tb\u{180E}8Vw3YzKp4Qx7Rm2Sn5",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_covalent_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "covalent-api-key",
        "cqt_Kp4Qx7Rm2Sn5Tb\u{202E}8Vw3YzKp4Qx7Rm2Sn5",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_covalent_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "covalent-api-key",
        "cqt_Kp4Qx7Rm2Sn5Tb\u{202C}8Vw3YzKp4Qx7Rm2Sn5",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv78_covalent_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "covalent-api-key",
        "cqt_Kp4Qx7Rm2Sn5Tb\u{200E}8Vw3YzKp4Qx7Rm2Sn5",
        "cqt_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}


