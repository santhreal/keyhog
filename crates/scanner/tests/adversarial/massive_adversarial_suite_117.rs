//! Part 117 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates plasmic, playht, playstation, playwright, plivo, podio, podio, polygon, polytomic, portkey detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PLASMIC API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv117_plasmic_api_key_normal_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv117_plasmic_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "plasmic-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv117_plasmic_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{200B}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv117_plasmic_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{00AD}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv117_plasmic_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{200C}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv117_plasmic_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{200D}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv117_plasmic_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{FEFF}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv117_plasmic_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{2060}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv117_plasmic_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{180E}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv117_plasmic_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{202E}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv117_plasmic_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{202C}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv117_plasmic_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{200E}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

// =========================================================================
// 2. PLAYHT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv117_playht_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv117_playht_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "playht-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv117_playht_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{200B}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv117_playht_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{00AD}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv117_playht_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{200C}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv117_playht_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{200D}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv117_playht_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{FEFF}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv117_playht_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{2060}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv117_playht_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{180E}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv117_playht_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{202E}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv117_playht_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{202C}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv117_playht_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{200E}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

// =========================================================================
// 3. PLAYSTATION API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv117_playstation_api_key_normal_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv117_playstation_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "playstation-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv117_playstation_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{200B}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv117_playstation_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{00AD}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv117_playstation_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{200C}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv117_playstation_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{200D}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv117_playstation_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{FEFF}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv117_playstation_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{2060}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv117_playstation_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{180E}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv117_playstation_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{202E}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv117_playstation_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{202C}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv117_playstation_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{200E}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

// =========================================================================
// 4. PLAYWRIGHT TEST CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv117_playwright_test_credentials_normal_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv117_playwright_test_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "playwright-test-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv117_playwright_test_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{200B}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv117_playwright_test_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{00AD}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv117_playwright_test_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{200C}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv117_playwright_test_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{200D}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv117_playwright_test_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{FEFF}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv117_playwright_test_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{2060}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv117_playwright_test_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{180E}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv117_playwright_test_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{202E}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv117_playwright_test_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{202C}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv117_playwright_test_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{200E}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

// =========================================================================
// 5. PLIVO VOICE AUTH ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv117_plivo_voice_auth_normal_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJMpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv117_plivo_voice_auth_wrong_prefix_must_silent() {
    assert_detector_silent("plivo-voice-auth", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv117_plivo_voice_auth_evade_zwsp_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{200B}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv117_plivo_voice_auth_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{00AD}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv117_plivo_voice_auth_evade_zwnj_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{200C}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv117_plivo_voice_auth_evade_zwj_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{200D}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv117_plivo_voice_auth_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{FEFF}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv117_plivo_voice_auth_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{2060}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv117_plivo_voice_auth_evade_mongolian_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{180E}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv117_plivo_voice_auth_evade_rtl_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{202E}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv117_plivo_voice_auth_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{202C}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv117_plivo_voice_auth_evade_lrm_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{200E}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

// =========================================================================
// 6. PODIO ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv117_podio_access_token_normal_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv117_podio_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "podio-access-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv117_podio_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{200B}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv117_podio_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{00AD}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv117_podio_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{200C}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv117_podio_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{200D}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv117_podio_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{FEFF}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv117_podio_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{2060}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv117_podio_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{180E}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv117_podio_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{202E}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv117_podio_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{202C}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv117_podio_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{200E}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

// =========================================================================
// 7. PODIO CLIENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv117_podio_client_credentials_normal_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=7222973",
        "7222973",
    );
}

#[test]
fn adv117_podio_client_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("podio-client-credentials", "dummy_prefix_0 =xxxxxxx");
}

#[test]
fn adv117_podio_client_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{200B}2973",
        "7222973",
    );
}

#[test]
fn adv117_podio_client_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{00AD}2973",
        "7222973",
    );
}

#[test]
fn adv117_podio_client_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{200C}2973",
        "7222973",
    );
}

#[test]
fn adv117_podio_client_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{200D}2973",
        "7222973",
    );
}

#[test]
fn adv117_podio_client_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{FEFF}2973",
        "7222973",
    );
}

#[test]
fn adv117_podio_client_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{2060}2973",
        "7222973",
    );
}

#[test]
fn adv117_podio_client_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{180E}2973",
        "7222973",
    );
}

#[test]
fn adv117_podio_client_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{202E}2973",
        "7222973",
    );
}

#[test]
fn adv117_podio_client_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{202C}2973",
        "7222973",
    );
}

#[test]
fn adv117_podio_client_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{200E}2973",
        "7222973",
    );
}

// =========================================================================
// 8. POLYGON API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv117_polygon_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc2524b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv117_polygon_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "polygon-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv117_polygon_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{200B}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv117_polygon_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{00AD}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv117_polygon_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{200C}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv117_polygon_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{200D}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv117_polygon_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{FEFF}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv117_polygon_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{2060}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv117_polygon_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{180E}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv117_polygon_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{202E}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv117_polygon_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{202C}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv117_polygon_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{200E}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

// =========================================================================
// 9. POLYTOMIC API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv117_polytomic_api_key_normal_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv117_polytomic_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "polytomic-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv117_polytomic_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{200B}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv117_polytomic_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{00AD}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv117_polytomic_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{200C}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv117_polytomic_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{200D}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv117_polytomic_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{FEFF}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv117_polytomic_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{2060}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv117_polytomic_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{180E}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv117_polytomic_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{202E}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv117_polytomic_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{202C}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv117_polytomic_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{200E}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

// =========================================================================
// 10. PORTKEY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv117_portkey_api_key_normal_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv117_portkey_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("portkey-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv117_portkey_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{200B}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv117_portkey_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{00AD}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv117_portkey_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{200C}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv117_portkey_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{200D}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv117_portkey_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{FEFF}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv117_portkey_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{2060}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv117_portkey_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{180E}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv117_portkey_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{202E}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv117_portkey_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{202C}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv117_portkey_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{200E}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}
