//! Part 86 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates fastspring, fathom, fauna, fda, fedex, figma, figma, figma, filebase, finicity detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. FASTSPRING API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv86_fastspring_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "fastspring-api-credentials",
        "FASTSPRING_API_USERNAME=Kp4Qx7Rm",
        "Kp4Qx7Rm",
    );
}

#[test]
fn adv86_fastspring_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("fastspring-api-credentials", "dummy_prefix_0 =xxxxxxxx");
}

#[test]
fn adv86_fastspring_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fastspring-api-credentials",
        "FASTSPRING_API_USERNAME=Kp4Q\u{200B}x7Rm",
        "Kp4Qx7Rm",
    );
}

#[test]
fn adv86_fastspring_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fastspring-api-credentials",
        "FASTSPRING_API_USERNAME=Kp4Q\u{00AD}x7Rm",
        "Kp4Qx7Rm",
    );
}

#[test]
fn adv86_fastspring_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fastspring-api-credentials",
        "FASTSPRING_API_USERNAME=Kp4Q\u{200C}x7Rm",
        "Kp4Qx7Rm",
    );
}

#[test]
fn adv86_fastspring_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "fastspring-api-credentials",
        "FASTSPRING_API_USERNAME=Kp4Q\u{200D}x7Rm",
        "Kp4Qx7Rm",
    );
}

#[test]
fn adv86_fastspring_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fastspring-api-credentials",
        "FASTSPRING_API_USERNAME=Kp4Q\u{FEFF}x7Rm",
        "Kp4Qx7Rm",
    );
}

#[test]
fn adv86_fastspring_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fastspring-api-credentials",
        "FASTSPRING_API_USERNAME=Kp4Q\u{2060}x7Rm",
        "Kp4Qx7Rm",
    );
}

#[test]
fn adv86_fastspring_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fastspring-api-credentials",
        "FASTSPRING_API_USERNAME=Kp4Q\u{180E}x7Rm",
        "Kp4Qx7Rm",
    );
}

#[test]
fn adv86_fastspring_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "fastspring-api-credentials",
        "FASTSPRING_API_USERNAME=Kp4Q\u{202E}x7Rm",
        "Kp4Qx7Rm",
    );
}

#[test]
fn adv86_fastspring_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fastspring-api-credentials",
        "FASTSPRING_API_USERNAME=Kp4Q\u{202C}x7Rm",
        "Kp4Qx7Rm",
    );
}

#[test]
fn adv86_fastspring_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "fastspring-api-credentials",
        "FASTSPRING_API_USERNAME=Kp4Q\u{200E}x7Rm",
        "Kp4Qx7Rm",
    );
}

// =========================================================================
// 2. FATHOM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv86_fathom_api_key_normal_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fathom_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fathom-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv86_fathom_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fathom_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_api_key=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fathom_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fathom_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fathom_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_api_key=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fathom_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_api_key=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fathom_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_api_key=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fathom_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_api_key=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fathom_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_api_key=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fathom_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 3. FAUNA SECRET KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv86_fauna_secret_key_normal_must_fire() {
    assert_detector_fires(
        "fauna-secret-key",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv86_fauna_secret_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fauna-secret-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv86_fauna_secret_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fauna-secret-key",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200B}2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv86_fauna_secret_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fauna-secret-key",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{00AD}2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv86_fauna_secret_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fauna-secret-key",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200C}2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv86_fauna_secret_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "fauna-secret-key",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200D}2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv86_fauna_secret_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fauna-secret-key",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{FEFF}2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv86_fauna_secret_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fauna-secret-key",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{2060}2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv86_fauna_secret_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fauna-secret-key",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{180E}2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv86_fauna_secret_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "fauna-secret-key",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{202E}2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv86_fauna_secret_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fauna-secret-key",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{202C}2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv86_fauna_secret_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "fauna-secret-key",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm\u{200E}2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
        "fnAEKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Q_x7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 4. FDA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv86_fda_api_key_normal_must_fire() {
    assert_detector_fires(
        "fda-api-key",
        "FDA_API_KEY=P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
        "P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
    );
}

#[test]
fn adv86_fda_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fda-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv86_fda_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fda-api-key",
        "FDA_API_KEY=P9Zu9Et3gR9l0wzCFBMX\u{200B}TtYj4rssu8aHN3ahXjJd",
        "P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
    );
}

#[test]
fn adv86_fda_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fda-api-key",
        "FDA_API_KEY=P9Zu9Et3gR9l0wzCFBMX\u{00AD}TtYj4rssu8aHN3ahXjJd",
        "P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
    );
}

#[test]
fn adv86_fda_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fda-api-key",
        "FDA_API_KEY=P9Zu9Et3gR9l0wzCFBMX\u{200C}TtYj4rssu8aHN3ahXjJd",
        "P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
    );
}

#[test]
fn adv86_fda_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "fda-api-key",
        "FDA_API_KEY=P9Zu9Et3gR9l0wzCFBMX\u{200D}TtYj4rssu8aHN3ahXjJd",
        "P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
    );
}

#[test]
fn adv86_fda_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fda-api-key",
        "FDA_API_KEY=P9Zu9Et3gR9l0wzCFBMX\u{FEFF}TtYj4rssu8aHN3ahXjJd",
        "P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
    );
}

#[test]
fn adv86_fda_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fda-api-key",
        "FDA_API_KEY=P9Zu9Et3gR9l0wzCFBMX\u{2060}TtYj4rssu8aHN3ahXjJd",
        "P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
    );
}

#[test]
fn adv86_fda_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fda-api-key",
        "FDA_API_KEY=P9Zu9Et3gR9l0wzCFBMX\u{180E}TtYj4rssu8aHN3ahXjJd",
        "P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
    );
}

#[test]
fn adv86_fda_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "fda-api-key",
        "FDA_API_KEY=P9Zu9Et3gR9l0wzCFBMX\u{202E}TtYj4rssu8aHN3ahXjJd",
        "P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
    );
}

#[test]
fn adv86_fda_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fda-api-key",
        "FDA_API_KEY=P9Zu9Et3gR9l0wzCFBMX\u{202C}TtYj4rssu8aHN3ahXjJd",
        "P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
    );
}

#[test]
fn adv86_fda_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "fda-api-key",
        "FDA_API_KEY=P9Zu9Et3gR9l0wzCFBMX\u{200E}TtYj4rssu8aHN3ahXjJd",
        "P9Zu9Et3gR9l0wzCFBMXTtYj4rssu8aHN3ahXjJd",
    );
}

// =========================================================================
// 5. FEDEX API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv86_fedex_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "FEDEX_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fedex_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fedex-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv86_fedex_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "FEDEX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fedex_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "FEDEX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fedex_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "FEDEX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fedex_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "FEDEX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fedex_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "FEDEX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fedex_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "FEDEX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fedex_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "FEDEX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fedex_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "FEDEX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fedex_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "FEDEX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv86_fedex_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "FEDEX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 6. FIGMA API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv86_figma_api_token_normal_must_fire() {
    assert_detector_fires(
        "figma-api-token",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv86_figma_api_token_wrong_prefix_must_silent() {
    assert_detector_silent("figma-api-token", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv86_figma_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "figma-api-token",
        "figd_Kp4Qx7Rm2Sn5T\u{200B}b8Vw3YzKp4Qx7Rm2Sn",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv86_figma_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "figma-api-token",
        "figd_Kp4Qx7Rm2Sn5T\u{00AD}b8Vw3YzKp4Qx7Rm2Sn",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv86_figma_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "figma-api-token",
        "figd_Kp4Qx7Rm2Sn5T\u{200C}b8Vw3YzKp4Qx7Rm2Sn",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv86_figma_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "figma-api-token",
        "figd_Kp4Qx7Rm2Sn5T\u{200D}b8Vw3YzKp4Qx7Rm2Sn",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv86_figma_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "figma-api-token",
        "figd_Kp4Qx7Rm2Sn5T\u{FEFF}b8Vw3YzKp4Qx7Rm2Sn",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv86_figma_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "figma-api-token",
        "figd_Kp4Qx7Rm2Sn5T\u{2060}b8Vw3YzKp4Qx7Rm2Sn",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv86_figma_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "figma-api-token",
        "figd_Kp4Qx7Rm2Sn5T\u{180E}b8Vw3YzKp4Qx7Rm2Sn",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv86_figma_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "figma-api-token",
        "figd_Kp4Qx7Rm2Sn5T\u{202E}b8Vw3YzKp4Qx7Rm2Sn",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv86_figma_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "figma-api-token",
        "figd_Kp4Qx7Rm2Sn5T\u{202C}b8Vw3YzKp4Qx7Rm2Sn",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv86_figma_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "figma-api-token",
        "figd_Kp4Qx7Rm2Sn5T\u{200E}b8Vw3YzKp4Qx7Rm2Sn",
        "figd_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

// =========================================================================
// 7. FIGMA OAUTH SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv86_figma_oauth_secret_normal_must_fire() {
    assert_detector_fires(
        "figma-oauth-secret",
        "FIGMA_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv86_figma_oauth_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "figma-oauth-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv86_figma_oauth_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "figma-oauth-secret",
        "FIGMA_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv86_figma_oauth_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "figma-oauth-secret",
        "FIGMA_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv86_figma_oauth_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "figma-oauth-secret",
        "FIGMA_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb\u{200C}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv86_figma_oauth_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "figma-oauth-secret",
        "FIGMA_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb\u{200D}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv86_figma_oauth_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "figma-oauth-secret",
        "FIGMA_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb\u{FEFF}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv86_figma_oauth_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "figma-oauth-secret",
        "FIGMA_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb\u{2060}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv86_figma_oauth_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "figma-oauth-secret",
        "FIGMA_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb\u{180E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv86_figma_oauth_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "figma-oauth-secret",
        "FIGMA_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb\u{202E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv86_figma_oauth_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "figma-oauth-secret",
        "FIGMA_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb\u{202C}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv86_figma_oauth_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "figma-oauth-secret",
        "FIGMA_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb\u{200E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

// =========================================================================
// 8. FIGMA PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv86_figma_pat_normal_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figd_9X3kQp7VbT2hYRzNcMfW",
        "figd_9X3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv86_figma_pat_wrong_prefix_must_silent() {
    assert_detector_silent("figma-pat", "dummyxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv86_figma_pat_evade_zwsp_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figd_9X3kQp7\u{200B}VbT2hYRzNcMfW",
        "figd_9X3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv86_figma_pat_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figd_9X3kQp7\u{00AD}VbT2hYRzNcMfW",
        "figd_9X3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv86_figma_pat_evade_zwnj_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figd_9X3kQp7\u{200C}VbT2hYRzNcMfW",
        "figd_9X3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv86_figma_pat_evade_zwj_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figd_9X3kQp7\u{200D}VbT2hYRzNcMfW",
        "figd_9X3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv86_figma_pat_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figd_9X3kQp7\u{FEFF}VbT2hYRzNcMfW",
        "figd_9X3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv86_figma_pat_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figd_9X3kQp7\u{2060}VbT2hYRzNcMfW",
        "figd_9X3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv86_figma_pat_evade_mongolian_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figd_9X3kQp7\u{180E}VbT2hYRzNcMfW",
        "figd_9X3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv86_figma_pat_evade_rtl_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figd_9X3kQp7\u{202E}VbT2hYRzNcMfW",
        "figd_9X3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv86_figma_pat_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figd_9X3kQp7\u{202C}VbT2hYRzNcMfW",
        "figd_9X3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv86_figma_pat_evade_lrm_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figd_9X3kQp7\u{200E}VbT2hYRzNcMfW",
        "figd_9X3kQp7VbT2hYRzNcMfW",
    );
}

// =========================================================================
// 9. FILEBASE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv86_filebase_api_key_normal_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "FILEBASE_ACCESS_KEY=K4Q7R2S5T8V3Y6Z9B1N2",
        "K4Q7R2S5T8V3Y6Z9B1N2",
    );
}

#[test]
fn adv86_filebase_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("filebase-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv86_filebase_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "FILEBASE_ACCESS_KEY=K4Q7R2S5T8\u{200B}V3Y6Z9B1N2",
        "K4Q7R2S5T8V3Y6Z9B1N2",
    );
}

#[test]
fn adv86_filebase_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "FILEBASE_ACCESS_KEY=K4Q7R2S5T8\u{00AD}V3Y6Z9B1N2",
        "K4Q7R2S5T8V3Y6Z9B1N2",
    );
}

#[test]
fn adv86_filebase_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "FILEBASE_ACCESS_KEY=K4Q7R2S5T8\u{200C}V3Y6Z9B1N2",
        "K4Q7R2S5T8V3Y6Z9B1N2",
    );
}

#[test]
fn adv86_filebase_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "FILEBASE_ACCESS_KEY=K4Q7R2S5T8\u{200D}V3Y6Z9B1N2",
        "K4Q7R2S5T8V3Y6Z9B1N2",
    );
}

#[test]
fn adv86_filebase_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "FILEBASE_ACCESS_KEY=K4Q7R2S5T8\u{FEFF}V3Y6Z9B1N2",
        "K4Q7R2S5T8V3Y6Z9B1N2",
    );
}

#[test]
fn adv86_filebase_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "FILEBASE_ACCESS_KEY=K4Q7R2S5T8\u{2060}V3Y6Z9B1N2",
        "K4Q7R2S5T8V3Y6Z9B1N2",
    );
}

#[test]
fn adv86_filebase_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "FILEBASE_ACCESS_KEY=K4Q7R2S5T8\u{180E}V3Y6Z9B1N2",
        "K4Q7R2S5T8V3Y6Z9B1N2",
    );
}

#[test]
fn adv86_filebase_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "FILEBASE_ACCESS_KEY=K4Q7R2S5T8\u{202E}V3Y6Z9B1N2",
        "K4Q7R2S5T8V3Y6Z9B1N2",
    );
}

#[test]
fn adv86_filebase_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "FILEBASE_ACCESS_KEY=K4Q7R2S5T8\u{202C}V3Y6Z9B1N2",
        "K4Q7R2S5T8V3Y6Z9B1N2",
    );
}

#[test]
fn adv86_filebase_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "FILEBASE_ACCESS_KEY=K4Q7R2S5T8\u{200E}V3Y6Z9B1N2",
        "K4Q7R2S5T8V3Y6Z9B1N2",
    );
}

// =========================================================================
// 10. FINICITY PARTNER CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv86_finicity_partner_credentials_normal_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "FINICITY_PARTNER_ID=1234567",
        "1234567",
    );
}

#[test]
fn adv86_finicity_partner_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("finicity-partner-credentials", "dummy_prefix_0 =xxxxxxx");
}

#[test]
fn adv86_finicity_partner_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "FINICITY_PARTNER_ID=123\u{200B}4567",
        "1234567",
    );
}

#[test]
fn adv86_finicity_partner_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "FINICITY_PARTNER_ID=123\u{00AD}4567",
        "1234567",
    );
}

#[test]
fn adv86_finicity_partner_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "FINICITY_PARTNER_ID=123\u{200C}4567",
        "1234567",
    );
}

#[test]
fn adv86_finicity_partner_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "FINICITY_PARTNER_ID=123\u{200D}4567",
        "1234567",
    );
}

#[test]
fn adv86_finicity_partner_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "FINICITY_PARTNER_ID=123\u{FEFF}4567",
        "1234567",
    );
}

#[test]
fn adv86_finicity_partner_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "FINICITY_PARTNER_ID=123\u{2060}4567",
        "1234567",
    );
}

#[test]
fn adv86_finicity_partner_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "FINICITY_PARTNER_ID=123\u{180E}4567",
        "1234567",
    );
}

#[test]
fn adv86_finicity_partner_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "FINICITY_PARTNER_ID=123\u{202E}4567",
        "1234567",
    );
}

#[test]
fn adv86_finicity_partner_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "FINICITY_PARTNER_ID=123\u{202C}4567",
        "1234567",
    );
}

#[test]
fn adv86_finicity_partner_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "FINICITY_PARTNER_ID=123\u{200E}4567",
        "1234567",
    );
}
