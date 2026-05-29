//! Part 53 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates plaid, planetscale, planetscale, plasmic, playht, playstation, playwright, plivo, podio, podio detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PLAID SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv53_plaid_secret_normal_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv53_plaid_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "plaid-secret",
        "dummy_prefix_0 =xxxe5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv53_plaid_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv53_plaid_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 2. PLANETSCALE API TOKEN V2 ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv53_planetscale_api_token_v2_normal_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv53_planetscale_api_token_v2_wrong_prefix_must_silent() {
    assert_detector_silent(
        "planetscale-api-token-v2",
        "dummyle_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv53_planetscale_api_token_v2_evade_zwsp_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{200B}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv53_planetscale_api_token_v2_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{00AD}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

// =========================================================================
// 3. PLANETSCALE SERVICE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv53_planetscale_service_token_normal_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv53_planetscale_service_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "planetscale-service-token",
        "dummyle_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv53_planetscale_service_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{200B}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv53_planetscale_service_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{00AD}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

// =========================================================================
// 4. PLASMIC API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv53_plasmic_api_key_normal_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv53_plasmic_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "plasmic-api-key",
        "dummy_prefix_0 =xxxeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv53_plasmic_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{200B}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

#[test]
fn adv53_plasmic_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "plasmic-api-key",
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1K\u{00AD}YlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    );
}

// =========================================================================
// 5. PLAYHT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv53_playht_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv53_playht_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "playht-api-credentials",
        "dummy_prefix_0 =xxx85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv53_playht_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{200B}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

#[test]
fn adv53_playht_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "playht-api-credentials",
        "PLAYHT=d5a85de4e8dcf26d\u{00AD}36132c4540d12c85",
        "d5a85de4e8dcf26d36132c4540d12c85",
    );
}

// =========================================================================
// 6. PLAYSTATION API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv53_playstation_api_key_normal_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv53_playstation_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "playstation-api-key",
        "dummy_prefix_0 =xxxf7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv53_playstation_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{200B}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

#[test]
fn adv53_playstation_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "playstation-api-key",
        "PSN_API_KEY=39ff7f8437d8ac46e79536bc00e27c0a\u{00AD}367fbb9357961603fddf2b5706196f97",
        "39ff7f8437d8ac46e79536bc00e27c0a367fbb9357961603fddf2b5706196f97",
    );
}

// =========================================================================
// 7. PLAYWRIGHT TEST CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv53_playwright_test_credentials_normal_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv53_playwright_test_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "playwright-test-credentials",
        "dummy_prefix_0 =xxxenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv53_playwright_test_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{200B}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

#[test]
fn adv53_playwright_test_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "playwright-test-credentials",
        "TESTOMATIO=K5PenZeiZ_\u{00AD}96EL2sMNKu",
        "K5PenZeiZ_96EL2sMNKu",
    );
}

// =========================================================================
// 8. PLIVO VOICE AUTH ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv53_plivo_voice_auth_normal_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJMpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv53_plivo_voice_auth_wrong_prefix_must_silent() {
    assert_detector_silent(
        "plivo-voice-auth",
        "dummy_prefix_0 =xxxdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv53_plivo_voice_auth_evade_zwsp_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{200B}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

#[test]
fn adv53_plivo_voice_auth_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "plivo-voice-auth",
        "PLIVO_AUTH_ID=XFhdBgXfaJ\u{00AD}MpNGaxRRsX",
        "XFhdBgXfaJMpNGaxRRsX",
    );
}

// =========================================================================
// 9. PODIO ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv53_podio_access_token_normal_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv53_podio_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "podio-access-token",
        "dummy_prefix_0 =xxxHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv53_podio_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{200B}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

#[test]
fn adv53_podio_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "podio-access-token",
        "PODIO_ACCESS_TOKEN=FzJHRZOsYwWCxU45KXdMIyV5\u{00AD}CZSTY1DU5bnigGf4UskM4BeF",
        "FzJHRZOsYwWCxU45KXdMIyV5CZSTY1DU5bnigGf4UskM4BeF",
    );
}

// =========================================================================
// 10. PODIO CLIENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv53_podio_client_credentials_normal_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=7222973",
        "7222973",
    );
}

#[test]
fn adv53_podio_client_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "podio-client-credentials",
        "dummy_prefix_0 =xxx2973",
    );
}

#[test]
fn adv53_podio_client_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{200B}2973",
        "7222973",
    );
}

#[test]
fn adv53_podio_client_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "podio-client-credentials",
        "PODIO_CLIENT_ID=722\u{00AD}2973",
        "7222973",
    );
}


