//! Part 127 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates shutterstock, sigfox, signnow, simpleanalytics, sinch, singapore, sketch, skyscanner, slack, slack detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. SHUTTERSTOCK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv127_shutterstock_api_key_normal_must_fire() {
    assert_detector_fires(
        "shutterstock-api-key",
        "SHUTTERSTOCK_API_KEY=dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
        "dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
    );
}

#[test]
fn adv127_shutterstock_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "shutterstock-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv127_shutterstock_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "shutterstock-api-key",
        "SHUTTERSTOCK_API_KEY=dc14-049UaGtL0Ks\u{200B}rlVLnuwXuAU5wooM",
        "dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
    );
}

#[test]
fn adv127_shutterstock_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "shutterstock-api-key",
        "SHUTTERSTOCK_API_KEY=dc14-049UaGtL0Ks\u{00AD}rlVLnuwXuAU5wooM",
        "dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
    );
}

#[test]
fn adv127_shutterstock_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "shutterstock-api-key",
        "SHUTTERSTOCK_API_KEY=dc14-049UaGtL0Ks\u{200C}rlVLnuwXuAU5wooM",
        "dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
    );
}

#[test]
fn adv127_shutterstock_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "shutterstock-api-key",
        "SHUTTERSTOCK_API_KEY=dc14-049UaGtL0Ks\u{200D}rlVLnuwXuAU5wooM",
        "dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
    );
}

#[test]
fn adv127_shutterstock_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "shutterstock-api-key",
        "SHUTTERSTOCK_API_KEY=dc14-049UaGtL0Ks\u{FEFF}rlVLnuwXuAU5wooM",
        "dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
    );
}

#[test]
fn adv127_shutterstock_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "shutterstock-api-key",
        "SHUTTERSTOCK_API_KEY=dc14-049UaGtL0Ks\u{2060}rlVLnuwXuAU5wooM",
        "dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
    );
}

#[test]
fn adv127_shutterstock_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "shutterstock-api-key",
        "SHUTTERSTOCK_API_KEY=dc14-049UaGtL0Ks\u{180E}rlVLnuwXuAU5wooM",
        "dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
    );
}

#[test]
fn adv127_shutterstock_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "shutterstock-api-key",
        "SHUTTERSTOCK_API_KEY=dc14-049UaGtL0Ks\u{202E}rlVLnuwXuAU5wooM",
        "dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
    );
}

#[test]
fn adv127_shutterstock_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "shutterstock-api-key",
        "SHUTTERSTOCK_API_KEY=dc14-049UaGtL0Ks\u{202C}rlVLnuwXuAU5wooM",
        "dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
    );
}

#[test]
fn adv127_shutterstock_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "shutterstock-api-key",
        "SHUTTERSTOCK_API_KEY=dc14-049UaGtL0Ks\u{200E}rlVLnuwXuAU5wooM",
        "dc14-049UaGtL0KsrlVLnuwXuAU5wooM",
    );
}

// =========================================================================
// 2. SIGFOX API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv127_sigfox_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "sigfox-api-credentials",
        "SIGFOXAPILOGIN=ux6ujzpc",
        "ux6ujzpc",
    );
}

#[test]
fn adv127_sigfox_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("sigfox-api-credentials", "dummy_prefix_0 =xxxxxxxx");
}

#[test]
fn adv127_sigfox_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sigfox-api-credentials",
        "SIGFOXAPILOGIN=ux6u\u{200B}jzpc",
        "ux6ujzpc",
    );
}

#[test]
fn adv127_sigfox_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sigfox-api-credentials",
        "SIGFOXAPILOGIN=ux6u\u{00AD}jzpc",
        "ux6ujzpc",
    );
}

#[test]
fn adv127_sigfox_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sigfox-api-credentials",
        "SIGFOXAPILOGIN=ux6u\u{200C}jzpc",
        "ux6ujzpc",
    );
}

#[test]
fn adv127_sigfox_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "sigfox-api-credentials",
        "SIGFOXAPILOGIN=ux6u\u{200D}jzpc",
        "ux6ujzpc",
    );
}

#[test]
fn adv127_sigfox_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sigfox-api-credentials",
        "SIGFOXAPILOGIN=ux6u\u{FEFF}jzpc",
        "ux6ujzpc",
    );
}

#[test]
fn adv127_sigfox_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sigfox-api-credentials",
        "SIGFOXAPILOGIN=ux6u\u{2060}jzpc",
        "ux6ujzpc",
    );
}

#[test]
fn adv127_sigfox_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sigfox-api-credentials",
        "SIGFOXAPILOGIN=ux6u\u{180E}jzpc",
        "ux6ujzpc",
    );
}

#[test]
fn adv127_sigfox_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "sigfox-api-credentials",
        "SIGFOXAPILOGIN=ux6u\u{202E}jzpc",
        "ux6ujzpc",
    );
}

#[test]
fn adv127_sigfox_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sigfox-api-credentials",
        "SIGFOXAPILOGIN=ux6u\u{202C}jzpc",
        "ux6ujzpc",
    );
}

#[test]
fn adv127_sigfox_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "sigfox-api-credentials",
        "SIGFOXAPILOGIN=ux6u\u{200E}jzpc",
        "ux6ujzpc",
    );
}

// =========================================================================
// 3. SIGNNOW API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv127_signnow_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "signnow-api-credentials",
        "SIGNNOW_CLIENT_ID=hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
        "hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
    );
}

#[test]
fn adv127_signnow_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "signnow-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv127_signnow_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "signnow-api-credentials",
        "SIGNNOW_CLIENT_ID=hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65\u{200B}Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
        "hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
    );
}

#[test]
fn adv127_signnow_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "signnow-api-credentials",
        "SIGNNOW_CLIENT_ID=hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65\u{00AD}Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
        "hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
    );
}

#[test]
fn adv127_signnow_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "signnow-api-credentials",
        "SIGNNOW_CLIENT_ID=hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65\u{200C}Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
        "hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
    );
}

#[test]
fn adv127_signnow_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "signnow-api-credentials",
        "SIGNNOW_CLIENT_ID=hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65\u{200D}Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
        "hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
    );
}

#[test]
fn adv127_signnow_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "signnow-api-credentials",
        "SIGNNOW_CLIENT_ID=hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65\u{FEFF}Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
        "hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
    );
}

#[test]
fn adv127_signnow_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "signnow-api-credentials",
        "SIGNNOW_CLIENT_ID=hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65\u{2060}Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
        "hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
    );
}

#[test]
fn adv127_signnow_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "signnow-api-credentials",
        "SIGNNOW_CLIENT_ID=hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65\u{180E}Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
        "hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
    );
}

#[test]
fn adv127_signnow_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "signnow-api-credentials",
        "SIGNNOW_CLIENT_ID=hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65\u{202E}Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
        "hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
    );
}

#[test]
fn adv127_signnow_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "signnow-api-credentials",
        "SIGNNOW_CLIENT_ID=hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65\u{202C}Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
        "hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
    );
}

#[test]
fn adv127_signnow_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "signnow-api-credentials",
        "SIGNNOW_CLIENT_ID=hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65\u{200E}Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
        "hrAgZuZhha7xRnRRIC809j5u4Ocs4iM1xNNnmRA4fK65Zg6A08fKGNoYEMPvO_6K2nNU9n2KRp4MPC2FnjhEgjeOQ",
    );
}

// =========================================================================
// 4. SIMPLEANALYTICS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv127_simpleanalytics_api_key_normal_must_fire() {
    assert_detector_fires(
        "simpleanalytics-api-key",
        "SA_API_KEY=8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
        "8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
    );
}

#[test]
fn adv127_simpleanalytics_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "simpleanalytics-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv127_simpleanalytics_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "simpleanalytics-api-key",
        "SA_API_KEY=8c88efc1-6389-f9c8\u{200B}-aa10-49a8b9341dc3",
        "8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
    );
}

#[test]
fn adv127_simpleanalytics_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "simpleanalytics-api-key",
        "SA_API_KEY=8c88efc1-6389-f9c8\u{00AD}-aa10-49a8b9341dc3",
        "8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
    );
}

#[test]
fn adv127_simpleanalytics_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "simpleanalytics-api-key",
        "SA_API_KEY=8c88efc1-6389-f9c8\u{200C}-aa10-49a8b9341dc3",
        "8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
    );
}

#[test]
fn adv127_simpleanalytics_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "simpleanalytics-api-key",
        "SA_API_KEY=8c88efc1-6389-f9c8\u{200D}-aa10-49a8b9341dc3",
        "8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
    );
}

#[test]
fn adv127_simpleanalytics_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "simpleanalytics-api-key",
        "SA_API_KEY=8c88efc1-6389-f9c8\u{FEFF}-aa10-49a8b9341dc3",
        "8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
    );
}

#[test]
fn adv127_simpleanalytics_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "simpleanalytics-api-key",
        "SA_API_KEY=8c88efc1-6389-f9c8\u{2060}-aa10-49a8b9341dc3",
        "8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
    );
}

#[test]
fn adv127_simpleanalytics_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "simpleanalytics-api-key",
        "SA_API_KEY=8c88efc1-6389-f9c8\u{180E}-aa10-49a8b9341dc3",
        "8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
    );
}

#[test]
fn adv127_simpleanalytics_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "simpleanalytics-api-key",
        "SA_API_KEY=8c88efc1-6389-f9c8\u{202E}-aa10-49a8b9341dc3",
        "8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
    );
}

#[test]
fn adv127_simpleanalytics_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "simpleanalytics-api-key",
        "SA_API_KEY=8c88efc1-6389-f9c8\u{202C}-aa10-49a8b9341dc3",
        "8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
    );
}

#[test]
fn adv127_simpleanalytics_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "simpleanalytics-api-key",
        "SA_API_KEY=8c88efc1-6389-f9c8\u{200E}-aa10-49a8b9341dc3",
        "8c88efc1-6389-f9c8-aa10-49a8b9341dc3",
    );
}

// =========================================================================
// 5. SINCH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv127_sinch_api_key_normal_must_fire() {
    assert_detector_fires(
        "sinch-api-key",
        "sinchproject=6fea9b0996bEa7A40e325382d2eEc4CE",
        "6fea9b0996bEa7A40e325382d2eEc4CE",
    );
}

#[test]
fn adv127_sinch_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sinch-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv127_sinch_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sinch-api-key",
        "sinchproject=6fea9b0996bEa7A4\u{200B}0e325382d2eEc4CE",
        "6fea9b0996bEa7A40e325382d2eEc4CE",
    );
}

#[test]
fn adv127_sinch_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sinch-api-key",
        "sinchproject=6fea9b0996bEa7A4\u{00AD}0e325382d2eEc4CE",
        "6fea9b0996bEa7A40e325382d2eEc4CE",
    );
}

#[test]
fn adv127_sinch_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sinch-api-key",
        "sinchproject=6fea9b0996bEa7A4\u{200C}0e325382d2eEc4CE",
        "6fea9b0996bEa7A40e325382d2eEc4CE",
    );
}

#[test]
fn adv127_sinch_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "sinch-api-key",
        "sinchproject=6fea9b0996bEa7A4\u{200D}0e325382d2eEc4CE",
        "6fea9b0996bEa7A40e325382d2eEc4CE",
    );
}

#[test]
fn adv127_sinch_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sinch-api-key",
        "sinchproject=6fea9b0996bEa7A4\u{FEFF}0e325382d2eEc4CE",
        "6fea9b0996bEa7A40e325382d2eEc4CE",
    );
}

#[test]
fn adv127_sinch_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sinch-api-key",
        "sinchproject=6fea9b0996bEa7A4\u{2060}0e325382d2eEc4CE",
        "6fea9b0996bEa7A40e325382d2eEc4CE",
    );
}

#[test]
fn adv127_sinch_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sinch-api-key",
        "sinchproject=6fea9b0996bEa7A4\u{180E}0e325382d2eEc4CE",
        "6fea9b0996bEa7A40e325382d2eEc4CE",
    );
}

#[test]
fn adv127_sinch_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "sinch-api-key",
        "sinchproject=6fea9b0996bEa7A4\u{202E}0e325382d2eEc4CE",
        "6fea9b0996bEa7A40e325382d2eEc4CE",
    );
}

#[test]
fn adv127_sinch_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sinch-api-key",
        "sinchproject=6fea9b0996bEa7A4\u{202C}0e325382d2eEc4CE",
        "6fea9b0996bEa7A40e325382d2eEc4CE",
    );
}

#[test]
fn adv127_sinch_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "sinch-api-key",
        "sinchproject=6fea9b0996bEa7A4\u{200E}0e325382d2eEc4CE",
        "6fea9b0996bEa7A40e325382d2eEc4CE",
    );
}

// =========================================================================
// 6. SINGAPORE GOVTECH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv127_singapore_govtech_api_key_normal_must_fire() {
    assert_detector_fires(
        "singapore-govtech-api-key",
        "SINGAPORE_GOVTECH_API_KEY=PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
        "PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
    );
}

#[test]
fn adv127_singapore_govtech_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "singapore-govtech-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv127_singapore_govtech_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "singapore-govtech-api-key",
        "SINGAPORE_GOVTECH_API_KEY=PDsuJtQ1j69J6nI4deWg\u{200B}xnRlCTHmcYgbmcRfsLA4",
        "PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
    );
}

#[test]
fn adv127_singapore_govtech_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "singapore-govtech-api-key",
        "SINGAPORE_GOVTECH_API_KEY=PDsuJtQ1j69J6nI4deWg\u{00AD}xnRlCTHmcYgbmcRfsLA4",
        "PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
    );
}

#[test]
fn adv127_singapore_govtech_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "singapore-govtech-api-key",
        "SINGAPORE_GOVTECH_API_KEY=PDsuJtQ1j69J6nI4deWg\u{200C}xnRlCTHmcYgbmcRfsLA4",
        "PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
    );
}

#[test]
fn adv127_singapore_govtech_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "singapore-govtech-api-key",
        "SINGAPORE_GOVTECH_API_KEY=PDsuJtQ1j69J6nI4deWg\u{200D}xnRlCTHmcYgbmcRfsLA4",
        "PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
    );
}

#[test]
fn adv127_singapore_govtech_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "singapore-govtech-api-key",
        "SINGAPORE_GOVTECH_API_KEY=PDsuJtQ1j69J6nI4deWg\u{FEFF}xnRlCTHmcYgbmcRfsLA4",
        "PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
    );
}

#[test]
fn adv127_singapore_govtech_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "singapore-govtech-api-key",
        "SINGAPORE_GOVTECH_API_KEY=PDsuJtQ1j69J6nI4deWg\u{2060}xnRlCTHmcYgbmcRfsLA4",
        "PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
    );
}

#[test]
fn adv127_singapore_govtech_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "singapore-govtech-api-key",
        "SINGAPORE_GOVTECH_API_KEY=PDsuJtQ1j69J6nI4deWg\u{180E}xnRlCTHmcYgbmcRfsLA4",
        "PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
    );
}

#[test]
fn adv127_singapore_govtech_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "singapore-govtech-api-key",
        "SINGAPORE_GOVTECH_API_KEY=PDsuJtQ1j69J6nI4deWg\u{202E}xnRlCTHmcYgbmcRfsLA4",
        "PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
    );
}

#[test]
fn adv127_singapore_govtech_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "singapore-govtech-api-key",
        "SINGAPORE_GOVTECH_API_KEY=PDsuJtQ1j69J6nI4deWg\u{202C}xnRlCTHmcYgbmcRfsLA4",
        "PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
    );
}

#[test]
fn adv127_singapore_govtech_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "singapore-govtech-api-key",
        "SINGAPORE_GOVTECH_API_KEY=PDsuJtQ1j69J6nI4deWg\u{200E}xnRlCTHmcYgbmcRfsLA4",
        "PDsuJtQ1j69J6nI4deWgxnRlCTHmcYgbmcRfsLA4",
    );
}

// =========================================================================
// 7. SKETCH CLOUD API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv127_sketch_cloud_api_key_normal_must_fire() {
    assert_detector_fires(
        "sketch-cloud-api-key",
        "sketch_api_key=abcdefghijklmnopqrstuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv127_sketch_cloud_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sketch-cloud-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv127_sketch_cloud_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sketch-cloud-api-key",
        "sketch_api_key=abcdefghijklmnopqr\u{200B}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv127_sketch_cloud_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sketch-cloud-api-key",
        "sketch_api_key=abcdefghijklmnopqr\u{00AD}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv127_sketch_cloud_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sketch-cloud-api-key",
        "sketch_api_key=abcdefghijklmnopqr\u{200C}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv127_sketch_cloud_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "sketch-cloud-api-key",
        "sketch_api_key=abcdefghijklmnopqr\u{200D}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv127_sketch_cloud_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sketch-cloud-api-key",
        "sketch_api_key=abcdefghijklmnopqr\u{FEFF}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv127_sketch_cloud_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sketch-cloud-api-key",
        "sketch_api_key=abcdefghijklmnopqr\u{2060}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv127_sketch_cloud_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sketch-cloud-api-key",
        "sketch_api_key=abcdefghijklmnopqr\u{180E}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv127_sketch_cloud_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "sketch-cloud-api-key",
        "sketch_api_key=abcdefghijklmnopqr\u{202E}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv127_sketch_cloud_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sketch-cloud-api-key",
        "sketch_api_key=abcdefghijklmnopqr\u{202C}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

#[test]
fn adv127_sketch_cloud_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "sketch-cloud-api-key",
        "sketch_api_key=abcdefghijklmnopqr\u{200E}stuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    );
}

// =========================================================================
// 8. SKYSCANNER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv127_skyscanner_api_key_normal_must_fire() {
    assert_detector_fires(
        "skyscanner-api-key",
        "SKYSCANNER_API_KEY=JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
        "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
    );
}

#[test]
fn adv127_skyscanner_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "skyscanner-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv127_skyscanner_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "skyscanner-api-key",
        "SKYSCANNER_API_KEY=JEA8DfgFxzo9YbHh99eK\u{200B}uvHZUH62tIOeNPCQWBgg",
        "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
    );
}

#[test]
fn adv127_skyscanner_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "skyscanner-api-key",
        "SKYSCANNER_API_KEY=JEA8DfgFxzo9YbHh99eK\u{00AD}uvHZUH62tIOeNPCQWBgg",
        "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
    );
}

#[test]
fn adv127_skyscanner_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "skyscanner-api-key",
        "SKYSCANNER_API_KEY=JEA8DfgFxzo9YbHh99eK\u{200C}uvHZUH62tIOeNPCQWBgg",
        "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
    );
}

#[test]
fn adv127_skyscanner_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "skyscanner-api-key",
        "SKYSCANNER_API_KEY=JEA8DfgFxzo9YbHh99eK\u{200D}uvHZUH62tIOeNPCQWBgg",
        "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
    );
}

#[test]
fn adv127_skyscanner_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "skyscanner-api-key",
        "SKYSCANNER_API_KEY=JEA8DfgFxzo9YbHh99eK\u{FEFF}uvHZUH62tIOeNPCQWBgg",
        "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
    );
}

#[test]
fn adv127_skyscanner_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "skyscanner-api-key",
        "SKYSCANNER_API_KEY=JEA8DfgFxzo9YbHh99eK\u{2060}uvHZUH62tIOeNPCQWBgg",
        "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
    );
}

#[test]
fn adv127_skyscanner_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "skyscanner-api-key",
        "SKYSCANNER_API_KEY=JEA8DfgFxzo9YbHh99eK\u{180E}uvHZUH62tIOeNPCQWBgg",
        "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
    );
}

#[test]
fn adv127_skyscanner_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "skyscanner-api-key",
        "SKYSCANNER_API_KEY=JEA8DfgFxzo9YbHh99eK\u{202E}uvHZUH62tIOeNPCQWBgg",
        "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
    );
}

#[test]
fn adv127_skyscanner_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "skyscanner-api-key",
        "SKYSCANNER_API_KEY=JEA8DfgFxzo9YbHh99eK\u{202C}uvHZUH62tIOeNPCQWBgg",
        "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
    );
}

#[test]
fn adv127_skyscanner_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "skyscanner-api-key",
        "SKYSCANNER_API_KEY=JEA8DfgFxzo9YbHh99eK\u{200E}uvHZUH62tIOeNPCQWBgg",
        "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
    );
}

// =========================================================================
// 9. SLACK BOT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv127_slack_bot_token_normal_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv127_slack_bot_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "slack-bot-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv127_slack_bot_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-1234567890-123456789\u{200B}0-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv127_slack_bot_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-1234567890-123456789\u{00AD}0-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv127_slack_bot_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-1234567890-123456789\u{200C}0-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv127_slack_bot_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-1234567890-123456789\u{200D}0-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv127_slack_bot_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-1234567890-123456789\u{FEFF}0-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv127_slack_bot_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-1234567890-123456789\u{2060}0-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv127_slack_bot_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-1234567890-123456789\u{180E}0-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv127_slack_bot_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-1234567890-123456789\u{202E}0-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv127_slack_bot_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-1234567890-123456789\u{202C}0-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn adv127_slack_bot_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-1234567890-123456789\u{200E}0-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

// =========================================================================
// 10. SLACK OAUTH SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv127_slack_oauth_secret_normal_must_fire() {
    assert_detector_fires(
        "slack-oauth-secret",
        "SLACK_OAUTH_SECRET=5dc021e5826e61d6f10397f40939ef3b33a169fa",
        "5dc021e5826e61d6f10397f40939ef3b33a169fa",
    );
}

#[test]
fn adv127_slack_oauth_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "slack-oauth-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv127_slack_oauth_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "slack-oauth-secret",
        "SLACK_OAUTH_SECRET=5dc021e5826e61d6f103\u{200B}97f40939ef3b33a169fa",
        "5dc021e5826e61d6f10397f40939ef3b33a169fa",
    );
}

#[test]
fn adv127_slack_oauth_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "slack-oauth-secret",
        "SLACK_OAUTH_SECRET=5dc021e5826e61d6f103\u{00AD}97f40939ef3b33a169fa",
        "5dc021e5826e61d6f10397f40939ef3b33a169fa",
    );
}

#[test]
fn adv127_slack_oauth_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "slack-oauth-secret",
        "SLACK_OAUTH_SECRET=5dc021e5826e61d6f103\u{200C}97f40939ef3b33a169fa",
        "5dc021e5826e61d6f10397f40939ef3b33a169fa",
    );
}

#[test]
fn adv127_slack_oauth_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "slack-oauth-secret",
        "SLACK_OAUTH_SECRET=5dc021e5826e61d6f103\u{200D}97f40939ef3b33a169fa",
        "5dc021e5826e61d6f10397f40939ef3b33a169fa",
    );
}

#[test]
fn adv127_slack_oauth_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "slack-oauth-secret",
        "SLACK_OAUTH_SECRET=5dc021e5826e61d6f103\u{FEFF}97f40939ef3b33a169fa",
        "5dc021e5826e61d6f10397f40939ef3b33a169fa",
    );
}

#[test]
fn adv127_slack_oauth_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "slack-oauth-secret",
        "SLACK_OAUTH_SECRET=5dc021e5826e61d6f103\u{2060}97f40939ef3b33a169fa",
        "5dc021e5826e61d6f10397f40939ef3b33a169fa",
    );
}

#[test]
fn adv127_slack_oauth_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "slack-oauth-secret",
        "SLACK_OAUTH_SECRET=5dc021e5826e61d6f103\u{180E}97f40939ef3b33a169fa",
        "5dc021e5826e61d6f10397f40939ef3b33a169fa",
    );
}

#[test]
fn adv127_slack_oauth_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "slack-oauth-secret",
        "SLACK_OAUTH_SECRET=5dc021e5826e61d6f103\u{202E}97f40939ef3b33a169fa",
        "5dc021e5826e61d6f10397f40939ef3b33a169fa",
    );
}

#[test]
fn adv127_slack_oauth_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "slack-oauth-secret",
        "SLACK_OAUTH_SECRET=5dc021e5826e61d6f103\u{202C}97f40939ef3b33a169fa",
        "5dc021e5826e61d6f10397f40939ef3b33a169fa",
    );
}

#[test]
fn adv127_slack_oauth_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "slack-oauth-secret",
        "SLACK_OAUTH_SECRET=5dc021e5826e61d6f103\u{200E}97f40939ef3b33a169fa",
        "5dc021e5826e61d6f10397f40939ef3b33a169fa",
    );
}
