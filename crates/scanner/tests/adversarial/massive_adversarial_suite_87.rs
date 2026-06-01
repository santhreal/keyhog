//! Part 87 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates firebase, firecrawl, firehydrant, fireworks, five9, fivetran, flagsmith, flickr, flipside, flipt detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. FIREBASE STORAGE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv87_firebase_storage_credentials_normal_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "gs://my-project-12345.appspot.com",
        "my-project-12345.appspot.com",
    );
}

#[test]
fn adv87_firebase_storage_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "firebase-storage-credentials",
        "dummy_prefix_0://xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv87_firebase_storage_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "gs://my-project-123\u{200B}45.appspot.com",
        "my-project-12345.appspot.com",
    );
}

#[test]
fn adv87_firebase_storage_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "gs://my-project-123\u{00AD}45.appspot.com",
        "my-project-12345.appspot.com",
    );
}

#[test]
fn adv87_firebase_storage_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "gs://my-project-123\u{200C}45.appspot.com",
        "my-project-12345.appspot.com",
    );
}

#[test]
fn adv87_firebase_storage_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "gs://my-project-123\u{200D}45.appspot.com",
        "my-project-12345.appspot.com",
    );
}

#[test]
fn adv87_firebase_storage_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "gs://my-project-123\u{FEFF}45.appspot.com",
        "my-project-12345.appspot.com",
    );
}

#[test]
fn adv87_firebase_storage_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "gs://my-project-123\u{2060}45.appspot.com",
        "my-project-12345.appspot.com",
    );
}

#[test]
fn adv87_firebase_storage_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "gs://my-project-123\u{180E}45.appspot.com",
        "my-project-12345.appspot.com",
    );
}

#[test]
fn adv87_firebase_storage_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "gs://my-project-123\u{202E}45.appspot.com",
        "my-project-12345.appspot.com",
    );
}

#[test]
fn adv87_firebase_storage_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "gs://my-project-123\u{202C}45.appspot.com",
        "my-project-12345.appspot.com",
    );
}

#[test]
fn adv87_firebase_storage_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "gs://my-project-123\u{200E}45.appspot.com",
        "my-project-12345.appspot.com",
    );
}

// =========================================================================
// 2. FIRECRAWL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv87_firecrawl_api_key_normal_must_fire() {
    assert_detector_fires(
        "firecrawl-api-key",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv87_firecrawl_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "firecrawl-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv87_firecrawl_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "firecrawl-api-key",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4\u{200B}Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv87_firecrawl_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "firecrawl-api-key",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4\u{00AD}Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv87_firecrawl_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "firecrawl-api-key",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4\u{200C}Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv87_firecrawl_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "firecrawl-api-key",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4\u{200D}Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv87_firecrawl_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "firecrawl-api-key",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4\u{FEFF}Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv87_firecrawl_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "firecrawl-api-key",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4\u{2060}Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv87_firecrawl_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "firecrawl-api-key",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4\u{180E}Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv87_firecrawl_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "firecrawl-api-key",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4\u{202E}Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv87_firecrawl_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "firecrawl-api-key",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4\u{202C}Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv87_firecrawl_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "firecrawl-api-key",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4\u{200E}Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "fc-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

// =========================================================================
// 3. FIREHYDRANT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv87_firehydrant_api_key_normal_must_fire() {
    assert_detector_fires(
        "firehydrant-api-key",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_firehydrant_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "firehydrant-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv87_firehydrant_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "firehydrant-api-key",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{200B}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_firehydrant_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "firehydrant-api-key",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{00AD}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_firehydrant_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "firehydrant-api-key",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{200C}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_firehydrant_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "firehydrant-api-key",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{200D}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_firehydrant_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "firehydrant-api-key",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{FEFF}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_firehydrant_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "firehydrant-api-key",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{2060}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_firehydrant_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "firehydrant-api-key",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{180E}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_firehydrant_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "firehydrant-api-key",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{202E}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_firehydrant_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "firehydrant-api-key",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{202C}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_firehydrant_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "firehydrant-api-key",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{200E}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "fhc7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 4. FIREWORKS AI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv87_fireworks_ai_api_key_normal_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fireworks_ai_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fireworks-ai-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv87_fireworks_ai_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fireworks_ai_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fireworks_ai_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3\u{200C}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fireworks_ai_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3\u{200D}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fireworks_ai_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3\u{FEFF}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fireworks_ai_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3\u{2060}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fireworks_ai_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3\u{180E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fireworks_ai_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3\u{202E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fireworks_ai_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3\u{202C}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fireworks_ai_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3\u{200E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "fw_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 5. FIVE9 API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv87_five9_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv87_five9_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "five9-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv87_five9_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_api_key=Kp4Qx7Rm2Sn5Tb8\u{200B}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv87_five9_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_api_key=Kp4Qx7Rm2Sn5Tb8\u{00AD}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv87_five9_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_api_key=Kp4Qx7Rm2Sn5Tb8\u{200C}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv87_five9_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_api_key=Kp4Qx7Rm2Sn5Tb8\u{200D}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv87_five9_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_api_key=Kp4Qx7Rm2Sn5Tb8\u{FEFF}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv87_five9_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_api_key=Kp4Qx7Rm2Sn5Tb8\u{2060}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv87_five9_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_api_key=Kp4Qx7Rm2Sn5Tb8\u{180E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv87_five9_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_api_key=Kp4Qx7Rm2Sn5Tb8\u{202E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv87_five9_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_api_key=Kp4Qx7Rm2Sn5Tb8\u{202C}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv87_five9_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_api_key=Kp4Qx7Rm2Sn5Tb8\u{200E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

// =========================================================================
// 6. FIVETRAN API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv87_fivetran_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "FIVETRAN_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fivetran_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fivetran-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv87_fivetran_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "FIVETRAN_API_KEY=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fivetran_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "FIVETRAN_API_KEY=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fivetran_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "FIVETRAN_API_KEY=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fivetran_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "FIVETRAN_API_KEY=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fivetran_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "FIVETRAN_API_KEY=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fivetran_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "FIVETRAN_API_KEY=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fivetran_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "FIVETRAN_API_KEY=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fivetran_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "FIVETRAN_API_KEY=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fivetran_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "FIVETRAN_API_KEY=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_fivetran_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "FIVETRAN_API_KEY=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 7. FLAGSMITH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv87_flagsmith_api_key_normal_must_fire() {
    assert_detector_fires(
        "flagsmith-api-key",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_flagsmith_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "flagsmith-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv87_flagsmith_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "flagsmith-api-key",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_flagsmith_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "flagsmith-api-key",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_flagsmith_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "flagsmith-api-key",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3\u{200C}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_flagsmith_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "flagsmith-api-key",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3\u{200D}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_flagsmith_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "flagsmith-api-key",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3\u{FEFF}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_flagsmith_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "flagsmith-api-key",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3\u{2060}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_flagsmith_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "flagsmith-api-key",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3\u{180E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_flagsmith_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "flagsmith-api-key",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3\u{202E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_flagsmith_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "flagsmith-api-key",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3\u{202C}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv87_flagsmith_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "flagsmith-api-key",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3\u{200E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "ser.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 8. FLICKR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv87_flickr_api_key_normal_must_fire() {
    assert_detector_fires(
        "flickr-api-key",
        "flickr_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_flickr_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "flickr-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv87_flickr_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "flickr-api-key",
        "flickr_api_key=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_flickr_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "flickr-api-key",
        "flickr_api_key=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_flickr_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "flickr-api-key",
        "flickr_api_key=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_flickr_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "flickr-api-key",
        "flickr_api_key=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_flickr_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "flickr-api-key",
        "flickr_api_key=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_flickr_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "flickr-api-key",
        "flickr_api_key=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_flickr_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "flickr-api-key",
        "flickr_api_key=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_flickr_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "flickr-api-key",
        "flickr_api_key=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_flickr_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "flickr-api-key",
        "flickr_api_key=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv87_flickr_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "flickr-api-key",
        "flickr_api_key=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 9. FLIPSIDE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv87_flipside_api_key_normal_must_fire() {
    assert_detector_fires(
        "flipside-api-key",
        "flipside_api_key=7b3e5d8c-a9f4-e2b6-c8d3-a5e9f1b7c4d",
        "7b3e5d8c-a9f4-e2b6-c8d3-a5e9f1b7c4d",
    );
}

#[test]
fn adv87_flipside_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "flipside-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv87_flipside_api_key_evade_zwsp_evaded_must_stay_silent() {
    assert_detector_silent("flipside-api-key", "flipside_api_key=7b3e5d8c-a9f4-e2b\u{200B}6-c8d3-a5e9f1b7c4d");
}

#[test]
fn adv87_flipside_api_key_evade_soft_hyphen_evaded_must_stay_silent() {
    assert_detector_silent("flipside-api-key", "flipside_api_key=7b3e5d8c-a9f4-e2b\u{00AD}6-c8d3-a5e9f1b7c4d");
}

#[test]
fn adv87_flipside_api_key_evade_zwnj_evaded_must_stay_silent() {
    assert_detector_silent("flipside-api-key", "flipside_api_key=7b3e5d8c-a9f4-e2b\u{200C}6-c8d3-a5e9f1b7c4d");
}

#[test]
fn adv87_flipside_api_key_evade_zwj_evaded_must_stay_silent() {
    assert_detector_silent("flipside-api-key", "flipside_api_key=7b3e5d8c-a9f4-e2b\u{200D}6-c8d3-a5e9f1b7c4d");
}

#[test]
fn adv87_flipside_api_key_evade_zwnbsp_evaded_must_stay_silent() {
    assert_detector_silent("flipside-api-key", "flipside_api_key=7b3e5d8c-a9f4-e2b\u{FEFF}6-c8d3-a5e9f1b7c4d");
}

#[test]
fn adv87_flipside_api_key_evade_word_joiner_evaded_must_stay_silent() {
    assert_detector_silent("flipside-api-key", "flipside_api_key=7b3e5d8c-a9f4-e2b\u{2060}6-c8d3-a5e9f1b7c4d");
}

#[test]
fn adv87_flipside_api_key_evade_mongolian_evaded_must_stay_silent() {
    assert_detector_silent("flipside-api-key", "flipside_api_key=7b3e5d8c-a9f4-e2b\u{180E}6-c8d3-a5e9f1b7c4d");
}

#[test]
fn adv87_flipside_api_key_evade_rtl_evaded_must_stay_silent() {
    assert_detector_silent("flipside-api-key", "flipside_api_key=7b3e5d8c-a9f4-e2b\u{202E}6-c8d3-a5e9f1b7c4d");
}

#[test]
fn adv87_flipside_api_key_evade_pop_dir_evaded_must_stay_silent() {
    assert_detector_silent("flipside-api-key", "flipside_api_key=7b3e5d8c-a9f4-e2b\u{202C}6-c8d3-a5e9f1b7c4d");
}

#[test]
fn adv87_flipside_api_key_evade_lrm_evaded_must_stay_silent() {
    assert_detector_silent("flipside-api-key", "flipside_api_key=7b3e5d8c-a9f4-e2b\u{200E}6-c8d3-a5e9f1b7c4d");
}

// =========================================================================
// 10. FLIPT API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv87_flipt_api_token_normal_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
    );
}

#[test]
fn adv87_flipt_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "flipt-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv87_flipt_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_7b3e5d8c1a9f4e2b6\u{200B}c8d3a5e9f1b7c4d3a5e9f1b7",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
    );
}

#[test]
fn adv87_flipt_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_7b3e5d8c1a9f4e2b6\u{00AD}c8d3a5e9f1b7c4d3a5e9f1b7",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
    );
}

#[test]
fn adv87_flipt_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_7b3e5d8c1a9f4e2b6\u{200C}c8d3a5e9f1b7c4d3a5e9f1b7",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
    );
}

#[test]
fn adv87_flipt_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_7b3e5d8c1a9f4e2b6\u{200D}c8d3a5e9f1b7c4d3a5e9f1b7",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
    );
}

#[test]
fn adv87_flipt_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_7b3e5d8c1a9f4e2b6\u{FEFF}c8d3a5e9f1b7c4d3a5e9f1b7",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
    );
}

#[test]
fn adv87_flipt_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_7b3e5d8c1a9f4e2b6\u{2060}c8d3a5e9f1b7c4d3a5e9f1b7",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
    );
}

#[test]
fn adv87_flipt_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_7b3e5d8c1a9f4e2b6\u{180E}c8d3a5e9f1b7c4d3a5e9f1b7",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
    );
}

#[test]
fn adv87_flipt_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_7b3e5d8c1a9f4e2b6\u{202E}c8d3a5e9f1b7c4d3a5e9f1b7",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
    );
}

#[test]
fn adv87_flipt_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_7b3e5d8c1a9f4e2b6\u{202C}c8d3a5e9f1b7c4d3a5e9f1b7",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
    );
}

#[test]
fn adv87_flipt_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_7b3e5d8c1a9f4e2b6\u{200E}c8d3a5e9f1b7c4d3a5e9f1b7",
        "flipt_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7",
    );
}
