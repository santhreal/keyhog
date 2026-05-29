//! Part 62 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates 123formbuilder, 500px, 8x8, abstract, abtasty, abuseipdb, accuweather, activecampaign, activepieces, adobe detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. 123FORMBUILDER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv62_123formbuilder_api_key_normal_must_fire() {
    assert_detector_fires(
        "123formbuilder-api-key",
        "123formbuilder api_key Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv62_123formbuilder_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "123formbuilder-api-key",
        "dummyormbuilder api_key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv62_123formbuilder_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "123formbuilder-api-key",
        "123formbuilder api_key Kp4Qx7-Rm2Sn5Tb8\u{200B}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv62_123formbuilder_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "123formbuilder-api-key",
        "123formbuilder api_key Kp4Qx7-Rm2Sn5Tb8\u{00AD}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv62_123formbuilder_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "123formbuilder-api-key",
        "123formbuilder api_key Kp4Qx7-Rm2Sn5Tb8\u{200C}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv62_123formbuilder_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "123formbuilder-api-key",
        "123formbuilder api_key Kp4Qx7-Rm2Sn5Tb8\u{200D}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv62_123formbuilder_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "123formbuilder-api-key",
        "123formbuilder api_key Kp4Qx7-Rm2Sn5Tb8\u{FEFF}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv62_123formbuilder_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "123formbuilder-api-key",
        "123formbuilder api_key Kp4Qx7-Rm2Sn5Tb8\u{2060}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv62_123formbuilder_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "123formbuilder-api-key",
        "123formbuilder api_key Kp4Qx7-Rm2Sn5Tb8\u{180E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv62_123formbuilder_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "123formbuilder-api-key",
        "123formbuilder api_key Kp4Qx7-Rm2Sn5Tb8\u{202E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv62_123formbuilder_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "123formbuilder-api-key",
        "123formbuilder api_key Kp4Qx7-Rm2Sn5Tb8\u{202C}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv62_123formbuilder_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "123formbuilder-api-key",
        "123formbuilder api_key Kp4Qx7-Rm2Sn5Tb8\u{200E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

// =========================================================================
// 2. 500PX API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv62_500px_api_key_normal_must_fire() {
    assert_detector_fires(
        "500px-api-key",
        "500PX_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_500px_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "500px-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv62_500px_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "500px-api-key",
        "500PX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_500px_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "500px-api-key",
        "500PX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_500px_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "500px-api-key",
        "500PX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_500px_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "500px-api-key",
        "500PX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_500px_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "500px-api-key",
        "500PX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_500px_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "500px-api-key",
        "500PX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_500px_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "500px-api-key",
        "500PX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_500px_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "500px-api-key",
        "500PX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_500px_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "500px-api-key",
        "500PX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_500px_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "500px-api-key",
        "500PX_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 3. 8X8 API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv62_8x8_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "8x8-api-credentials",
        "8x8_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_8x8_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "8x8-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv62_8x8_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "8x8-api-credentials",
        "8x8_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_8x8_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "8x8-api-credentials",
        "8x8_api_key=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_8x8_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "8x8-api-credentials",
        "8x8_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_8x8_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "8x8-api-credentials",
        "8x8_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_8x8_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "8x8-api-credentials",
        "8x8_api_key=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_8x8_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "8x8-api-credentials",
        "8x8_api_key=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_8x8_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "8x8-api-credentials",
        "8x8_api_key=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_8x8_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "8x8-api-credentials",
        "8x8_api_key=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_8x8_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "8x8-api-credentials",
        "8x8_api_key=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_8x8_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "8x8-api-credentials",
        "8x8_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 4. ABSTRACT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv62_abstract_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "abstract-api-credentials",
        "ABSTRACT_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv62_abstract_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "abstract-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv62_abstract_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "abstract-api-credentials",
        "ABSTRACT_API_KEY=Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv62_abstract_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "abstract-api-credentials",
        "ABSTRACT_API_KEY=Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv62_abstract_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "abstract-api-credentials",
        "ABSTRACT_API_KEY=Kp4Qx7Rm2Sn5Tb\u{200C}8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv62_abstract_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "abstract-api-credentials",
        "ABSTRACT_API_KEY=Kp4Qx7Rm2Sn5Tb\u{200D}8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv62_abstract_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "abstract-api-credentials",
        "ABSTRACT_API_KEY=Kp4Qx7Rm2Sn5Tb\u{FEFF}8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv62_abstract_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "abstract-api-credentials",
        "ABSTRACT_API_KEY=Kp4Qx7Rm2Sn5Tb\u{2060}8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv62_abstract_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "abstract-api-credentials",
        "ABSTRACT_API_KEY=Kp4Qx7Rm2Sn5Tb\u{180E}8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv62_abstract_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "abstract-api-credentials",
        "ABSTRACT_API_KEY=Kp4Qx7Rm2Sn5Tb\u{202E}8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv62_abstract_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "abstract-api-credentials",
        "ABSTRACT_API_KEY=Kp4Qx7Rm2Sn5Tb\u{202C}8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv62_abstract_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "abstract-api-credentials",
        "ABSTRACT_API_KEY=Kp4Qx7Rm2Sn5Tb\u{200E}8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

// =========================================================================
// 5. ABTASTY CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv62_abtasty_credentials_normal_must_fire() {
    assert_detector_fires(
        "abtasty-credentials",
        "ABTASTY:API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv62_abtasty_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "abtasty-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv62_abtasty_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "abtasty-credentials",
        "ABTASTY:API_KEY=Kp4Qx7Rm2Sn5\u{200B}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv62_abtasty_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "abtasty-credentials",
        "ABTASTY:API_KEY=Kp4Qx7Rm2Sn5\u{00AD}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv62_abtasty_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "abtasty-credentials",
        "ABTASTY:API_KEY=Kp4Qx7Rm2Sn5\u{200C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv62_abtasty_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "abtasty-credentials",
        "ABTASTY:API_KEY=Kp4Qx7Rm2Sn5\u{200D}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv62_abtasty_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "abtasty-credentials",
        "ABTASTY:API_KEY=Kp4Qx7Rm2Sn5\u{FEFF}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv62_abtasty_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "abtasty-credentials",
        "ABTASTY:API_KEY=Kp4Qx7Rm2Sn5\u{2060}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv62_abtasty_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "abtasty-credentials",
        "ABTASTY:API_KEY=Kp4Qx7Rm2Sn5\u{180E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv62_abtasty_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "abtasty-credentials",
        "ABTASTY:API_KEY=Kp4Qx7Rm2Sn5\u{202E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv62_abtasty_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "abtasty-credentials",
        "ABTASTY:API_KEY=Kp4Qx7Rm2Sn5\u{202C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv62_abtasty_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "abtasty-credentials",
        "ABTASTY:API_KEY=Kp4Qx7Rm2Sn5\u{200E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

// =========================================================================
// 6. ABUSEIPDB API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv62_abuseipdb_api_key_normal_must_fire() {
    assert_detector_fires(
        "abuseipdb-api-key",
        "ABUSEIPDB_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv62_abuseipdb_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "abuseipdb-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv62_abuseipdb_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "abuseipdb-api-key",
        "ABUSEIPDB_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv62_abuseipdb_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "abuseipdb-api-key",
        "ABUSEIPDB_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv62_abuseipdb_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "abuseipdb-api-key",
        "ABUSEIPDB_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv62_abuseipdb_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "abuseipdb-api-key",
        "ABUSEIPDB_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv62_abuseipdb_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "abuseipdb-api-key",
        "ABUSEIPDB_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv62_abuseipdb_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "abuseipdb-api-key",
        "ABUSEIPDB_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv62_abuseipdb_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "abuseipdb-api-key",
        "ABUSEIPDB_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv62_abuseipdb_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "abuseipdb-api-key",
        "ABUSEIPDB_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv62_abuseipdb_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "abuseipdb-api-key",
        "ABUSEIPDB_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv62_abuseipdb_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "abuseipdb-api-key",
        "ABUSEIPDB_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 7. ACCUWEATHER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv62_accuweather_api_key_normal_must_fire() {
    assert_detector_fires(
        "accuweather-api-key",
        "ACCUWEATHER_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv62_accuweather_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "accuweather-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv62_accuweather_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "accuweather-api-key",
        "ACCUWEATHER_API_KEY=Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv62_accuweather_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "accuweather-api-key",
        "ACCUWEATHER_API_KEY=Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv62_accuweather_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "accuweather-api-key",
        "ACCUWEATHER_API_KEY=Kp4Qx7Rm2Sn5Tb\u{200C}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv62_accuweather_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "accuweather-api-key",
        "ACCUWEATHER_API_KEY=Kp4Qx7Rm2Sn5Tb\u{200D}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv62_accuweather_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "accuweather-api-key",
        "ACCUWEATHER_API_KEY=Kp4Qx7Rm2Sn5Tb\u{FEFF}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv62_accuweather_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "accuweather-api-key",
        "ACCUWEATHER_API_KEY=Kp4Qx7Rm2Sn5Tb\u{2060}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv62_accuweather_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "accuweather-api-key",
        "ACCUWEATHER_API_KEY=Kp4Qx7Rm2Sn5Tb\u{180E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv62_accuweather_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "accuweather-api-key",
        "ACCUWEATHER_API_KEY=Kp4Qx7Rm2Sn5Tb\u{202E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv62_accuweather_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "accuweather-api-key",
        "ACCUWEATHER_API_KEY=Kp4Qx7Rm2Sn5Tb\u{202C}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv62_accuweather_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "accuweather-api-key",
        "ACCUWEATHER_API_KEY=Kp4Qx7Rm2Sn5Tb\u{200E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

// =========================================================================
// 8. ACTIVECAMPAIGN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv62_activecampaign_api_key_normal_must_fire() {
    assert_detector_fires(
        "activecampaign-api-key",
        "ACTIVECAMPAIGN_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_activecampaign_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "activecampaign-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv62_activecampaign_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "activecampaign-api-key",
        "ACTIVECAMPAIGN_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_activecampaign_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "activecampaign-api-key",
        "ACTIVECAMPAIGN_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_activecampaign_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "activecampaign-api-key",
        "ACTIVECAMPAIGN_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_activecampaign_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "activecampaign-api-key",
        "ACTIVECAMPAIGN_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_activecampaign_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "activecampaign-api-key",
        "ACTIVECAMPAIGN_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_activecampaign_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "activecampaign-api-key",
        "ACTIVECAMPAIGN_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_activecampaign_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "activecampaign-api-key",
        "ACTIVECAMPAIGN_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_activecampaign_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "activecampaign-api-key",
        "ACTIVECAMPAIGN_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_activecampaign_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "activecampaign-api-key",
        "ACTIVECAMPAIGN_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv62_activecampaign_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "activecampaign-api-key",
        "ACTIVECAMPAIGN_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 9. ACTIVEPIECES API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv62_activepieces_api_key_normal_must_fire() {
    assert_detector_fires(
        "activepieces-api-key",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_activepieces_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "activepieces-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv62_activepieces_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "activepieces-api-key",
        "ap_7b3e5d8c1a9f4e\u{200B}2b6c8d3a5e9f1b7c4d",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_activepieces_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "activepieces-api-key",
        "ap_7b3e5d8c1a9f4e\u{00AD}2b6c8d3a5e9f1b7c4d",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_activepieces_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "activepieces-api-key",
        "ap_7b3e5d8c1a9f4e\u{200C}2b6c8d3a5e9f1b7c4d",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_activepieces_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "activepieces-api-key",
        "ap_7b3e5d8c1a9f4e\u{200D}2b6c8d3a5e9f1b7c4d",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_activepieces_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "activepieces-api-key",
        "ap_7b3e5d8c1a9f4e\u{FEFF}2b6c8d3a5e9f1b7c4d",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_activepieces_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "activepieces-api-key",
        "ap_7b3e5d8c1a9f4e\u{2060}2b6c8d3a5e9f1b7c4d",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_activepieces_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "activepieces-api-key",
        "ap_7b3e5d8c1a9f4e\u{180E}2b6c8d3a5e9f1b7c4d",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_activepieces_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "activepieces-api-key",
        "ap_7b3e5d8c1a9f4e\u{202E}2b6c8d3a5e9f1b7c4d",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_activepieces_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "activepieces-api-key",
        "ap_7b3e5d8c1a9f4e\u{202C}2b6c8d3a5e9f1b7c4d",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_activepieces_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "activepieces-api-key",
        "ap_7b3e5d8c1a9f4e\u{200E}2b6c8d3a5e9f1b7c4d",
        "ap_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 10. ADOBE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv62_adobe_api_key_normal_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_adobe_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "adobe-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv62_adobe_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_adobe_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_adobe_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_adobe_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_adobe_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_adobe_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_adobe_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_adobe_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_adobe_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv62_adobe_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}


