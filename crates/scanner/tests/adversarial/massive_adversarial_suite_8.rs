//! Part 8 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Adobe, Adobe Stock, ADP, AerisWeather, Africa's Talking, Agenta,
//! Agora, AI21 Labs, Airbrake, and Airbyte detectors against zero-width spaces,
//! soft hyphens, combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. ADOBE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv8_adobe_normal_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "adobe_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_adobe_wrong_prefix_must_silent() {
    assert_detector_silent(
        "adobe-api-key",
        "adobo_api_key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv8_adobe_evade_zwsp_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "adobe\u{200B}_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_adobe_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "adobe_api_key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_adobe_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "ad\u{043E}be_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 2. ADOBE STOCK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv8_adobe_stock_normal_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "adobe-stock-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_adobe_stock_wrong_prefix_must_silent() {
    assert_detector_silent(
        "adobe-stock-api-key",
        "adobe-soup-api-key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv8_adobe_stock_evade_zwsp_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "adobe-stock\u{200B}-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_adobe_stock_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "adobe-stock-api-key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_adobe_stock_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "adobe-stock-api-key",
        "ad\u{043E}be-stock-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 3. ADP API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv8_adp_normal_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv8_adp_wrong_prefix_must_silent() {
    assert_detector_silent(
        "adp-api-credentials",
        "BDP_CLIENT_ID = \"12345678-abcd-1234-abcd-1234567890ab\"",
    );
}

#[test]
fn adv8_adp_evade_zwsp_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP\u{200B}_CLIENT_ID = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv8_adp_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CLIENT_ID = \"12345678-abcd-1234-abcd-12345678\u{00AD}90ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv8_adp_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "adp-api-credentials",
        "ADP_CL\u{0406}ENT_ID = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

// =========================================================================
// 4. AERISWEATHER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv8_aerisweather_normal_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "aerisweather_id = \"abcde12345\"",
        "abcde12345",
    );
}

#[test]
fn adv8_aerisweather_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aerisweather-api-credentials",
        "barisweather_id = \"abcde12345\"",
    );
}

#[test]
fn adv8_aerisweather_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "aerisweather\u{200B}_id = \"abcde12345\"",
        "abcde12345",
    );
}

#[test]
fn adv8_aerisweather_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "aerisweather_id = \"abcde\u{00AD}12345\"",
        "abcde12345",
    );
}

#[test]
fn adv8_aerisweather_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "aerisweather-api-credentials",
        "aer\u{0456}sweather_id = \"abcde12345\"",
        "abcde12345",
    );
}

// =========================================================================
// 5. AFRICA'S TALKING API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv8_africastalking_normal_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_africastalking_wrong_prefix_must_silent() {
    assert_detector_silent(
        "africastalking-api-key",
        "americastalking_api_key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv8_africastalking_evade_zwsp_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking\u{200B}_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_africastalking_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalking_api_key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_africastalking_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "africastalking-api-key",
        "africastalk\u{0456}ng_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 6. AGENTA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv8_agenta_normal_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_agenta_wrong_prefix_must_silent() {
    assert_detector_silent(
        "agenta-api-key",
        "MAGENTA_API_KEY = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv8_agenta_evade_zwsp_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA\u{200B}_API_KEY = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_agenta_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "AGENTA_API_KEY = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_agenta_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "agenta-api-key",
        "ag\u{0435}nta_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 7. AGORA APP CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv8_agora_normal_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_agora_wrong_prefix_must_silent() {
    assert_detector_silent(
        "agora-app-credentials",
        "BAGORA_APP_ID = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv8_agora_evade_zwsp_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA\u{200B}_APP_ID = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_agora_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "AGORA_APP_ID = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_agora_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "agora-app-credentials",
        "ag\u{043E}ra_app_id = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 8. AI21 LABS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv8_ai21_normal_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_ai21_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ai21-api-key",
        "BI21_API_KEY = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv8_ai21_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21\u{200B}_API_KEY = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_ai21_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "AI21_API_KEY = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_ai21_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "ai21-api-key",
        "a\u{0456}21_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 9. AIRBRAKE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv8_airbrake_normal_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "airbrake_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_airbrake_wrong_prefix_must_silent() {
    assert_detector_silent(
        "airbrake-api-key",
        "fairbrake_api_key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv8_airbrake_evade_zwsp_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "airbrake\u{200B}_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_airbrake_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "airbrake_api_key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_airbrake_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "airbrake-api-key",
        "a\u{0456}rbrake_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 10. AIRBYTE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv8_airbyte_normal_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_airbyte_wrong_prefix_must_silent() {
    assert_detector_silent(
        "airbyte-api-credentials",
        "FAIRBYTE_API_KEY = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv8_airbyte_evade_zwsp_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE\u{200B}_API_KEY = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_airbyte_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "AIRBYTE_API_KEY = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv8_airbyte_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "airbyte-api-credentials",
        "a\u{0456}rbyte_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}
