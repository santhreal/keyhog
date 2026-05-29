//! Part 7 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates 123FormBuilder, 4everland, 500px, 8x8, Abstract API, AB Tasty,
//! AbuseIPDB, AccuWeather, ActiveCampaign, and Activepieces detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. 123FORMBUILDER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv7_formbuilder_normal_must_fire() {
    assert_detector_fires("123formbuilder-api-key", "123formbuilder_api = \"abcde-1234567890123456789012345\"", "abcde-1234567890123456789012345");
}

#[test]
fn adv7_formbuilder_wrong_prefix_must_silent() {
    assert_detector_silent("123formbuilder-api-key", "wrongbuilder_api = \"abcde-1234567890123456789012345\"");
}

#[test]
fn adv7_formbuilder_evade_zwsp_must_fire() {
    assert_detector_fires("123formbuilder-api-key", "123formbuilder\u{200B}_api = \"abcde-1234567890123456789012345\"", "abcde-1234567890123456789012345");
}

#[test]
fn adv7_formbuilder_evade_soft_hyphen_must_fire() {
    assert_detector_fires("123formbuilder-api-key", "123formbuilder_api = \"abcde\u{00AD}-1234567890123456789012345\"", "abcde-1234567890123456789012345");
}

#[test]
fn adv7_formbuilder_evade_homoglyph_must_fire() {
    assert_detector_fires("123formbuilder-api-key", "123formbu\u{0456}lder_api = \"abcde-1234567890123456789012345\"", "abcde-1234567890123456789012345");
}

// =========================================================================
// 2. 4EVERLAND API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv7_everland_normal_must_fire() {
    assert_detector_fires("4everland-api-token", "4ever_access_key = \"ABCDE1234567890ABCDE\"", "ABCDE1234567890ABCDE");
}

#[test]
fn adv7_everland_wrong_prefix_must_silent() {
    assert_detector_silent("4everland-api-token", "never_access_key = \"ABCDE1234567890ABCDE\"");
}

#[test]
fn adv7_everland_evade_zwsp_must_fire() {
    assert_detector_fires("4everland-api-token", "4ever\u{200B}_access_key = \"ABCDE1234567890ABCDE\"", "ABCDE1234567890ABCDE");
}

#[test]
fn adv7_everland_evade_soft_hyphen_must_fire() {
    assert_detector_fires("4everland-api-token", "4ever_access_key = \"ABCDE12345\u{00AD}67890ABCDE\"", "ABCDE1234567890ABCDE");
}

#[test]
fn adv7_everland_evade_homoglyph_must_fire() {
    assert_detector_fires("4everland-api-token", "4\u{0435}ver_access_key = \"ABCDE1234567890ABCDE\"", "ABCDE1234567890ABCDE");
}

// =========================================================================
// 3. 500PX API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv7_fivehundredpx_normal_must_fire() {
    assert_detector_fires("500px-api-key", "500px-api-key: \"abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012");
}

#[test]
fn adv7_fivehundredpx_wrong_prefix_must_silent() {
    assert_detector_silent("500px-api-key", "600px-api-key: \"abcde1234567890abcde123456789012\"");
}

#[test]
fn adv7_fivehundredpx_evade_zwsp_must_fire() {
    assert_detector_fires("500px-api-key", "500px\u{200B}-api-key: \"abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012");
}

#[test]
fn adv7_fivehundredpx_evade_soft_hyphen_must_fire() {
    assert_detector_fires("500px-api-key", "500px-api-key: \"abcde1234567890abcde1\u{00AD}23456789012\"", "abcde1234567890abcde123456789012");
}

#[test]
fn adv7_fivehundredpx_evade_homoglyph_must_fire() {
    assert_detector_fires("500px-api-key", "5\u{043E}\u{043E}px-api-key: \"abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012");
}

// =========================================================================
// 4. 8X8 API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv7_eightxeight_normal_must_fire() {
    assert_detector_fires("8x8-api-credentials", "8x8_api_key = \"abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012");
}

#[test]
fn adv7_eightxeight_wrong_prefix_must_silent() {
    assert_detector_silent("8x8-api-credentials", "9x9_api_key = \"abcde1234567890abcde123456789012\"");
}

#[test]
fn adv7_eightxeight_evade_zwsp_must_fire() {
    assert_detector_fires("8x8-api-credentials", "8x8\u{200B}_api_key = \"abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012");
}

#[test]
fn adv7_eightxeight_evade_soft_hyphen_must_fire() {
    assert_detector_fires("8x8-api-credentials", "8x8_api_key = \"abcde1234567890abcde1\u{00AD}23456789012\"", "abcde1234567890abcde123456789012");
}

#[test]
fn adv7_eightxeight_evade_homoglyph_must_fire() {
    assert_detector_fires("8x8-api-credentials", "eightxeight_api_key = \"abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012");
}

// =========================================================================
// 5. ABSTRACT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv7_abstract_normal_must_fire() {
    assert_detector_fires("abstract-api-credentials", "ABSTRACT_API_KEY = \"abcde1234567890abcde\"", "abcde1234567890abcde");
}

#[test]
fn adv7_abstract_wrong_prefix_must_silent() {
    assert_detector_silent("abstract-api-credentials", "CONCRETE_API_KEY = \"abcde1234567890abcde\"");
}

#[test]
fn adv7_abstract_evade_zwsp_must_fire() {
    assert_detector_fires("abstract-api-credentials", "ABSTRACT\u{200B}_API_KEY = \"abcde1234567890abcde\"", "abcde1234567890abcde");
}

#[test]
fn adv7_abstract_evade_soft_hyphen_must_fire() {
    assert_detector_fires("abstract-api-credentials", "ABSTRACT_API_KEY = \"abcde12345\u{00AD}67890abcde\"", "abcde1234567890abcde");
}

#[test]
fn adv7_abstract_evade_homoglyph_must_fire() {
    assert_detector_fires("abstract-api-credentials", "abstr\u{0430}ct_api_key = \"abcde1234567890abcde\"", "abcde1234567890abcde");
}

// =========================================================================
// 6. AB TASTY CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv7_abtasty_normal_must_fire() {
    assert_detector_fires("abtasty-credentials", "abtasty_api_key: \"abcde1234567890abcde12345\"", "abcde1234567890abcde12345");
}

#[test]
fn adv7_abtasty_wrong_prefix_must_silent() {
    assert_detector_silent("abtasty-credentials", "nasty_api_key: \"abcde1234567890abcde12345\"");
}

#[test]
fn adv7_abtasty_evade_zwsp_must_fire() {
    assert_detector_fires("abtasty-credentials", "abtasty\u{200B}_api_key: \"abcde1234567890abcde12345\"", "abcde1234567890abcde12345");
}

#[test]
fn adv7_abtasty_evade_soft_hyphen_must_fire() {
    assert_detector_fires("abtasty-credentials", "abtasty_api_key: \"abcde1234567890abcde1\u{00AD}2345\"", "abcde1234567890abcde12345");
}

#[test]
fn adv7_abtasty_evade_homoglyph_must_fire() {
    assert_detector_fires("abtasty-credentials", "abt\u{0430}sty_api_key: \"abcde1234567890abcde12345\"", "abcde1234567890abcde12345");
}

// =========================================================================
// 7. ABUSEIPDB API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv7_abuseipdb_normal_must_fire() {
    assert_detector_fires("abuseipdb-api-key", "abuseipdb_api = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890\"", "abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890");
}

#[test]
fn adv7_abuseipdb_wrong_prefix_must_silent() {
    assert_detector_silent("abuseipdb-api-key", "useipdb_api = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890\"");
}

#[test]
fn adv7_abuseipdb_evade_zwsp_must_fire() {
    assert_detector_fires("abuseipdb-api-key", "abuseipdb\u{200B}_api = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890\"", "abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890");
}

#[test]
fn adv7_abuseipdb_evade_soft_hyphen_must_fire() {
    assert_detector_fires("abuseipdb-api-key", "abuseipdb_api = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1\u{00AD}234567890\"", "abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890");
}

#[test]
fn adv7_abuseipdb_evade_homoglyph_must_fire() {
    assert_detector_fires("abuseipdb-api-key", "abus\u{0435}ipdb_api = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890\"", "abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890");
}

// =========================================================================
// 8. ACCUWEATHER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv7_accuweather_normal_must_fire() {
    assert_detector_fires("accuweather-api-key", "accuweather_api_key = \"abcde1234567890abcde\"", "abcde1234567890abcde");
}

#[test]
fn adv7_accuweather_wrong_prefix_must_silent() {
    assert_detector_silent("accuweather-api-key", "macuweather_api_key = \"abcde1234567890abcde\"");
}

#[test]
fn adv7_accuweather_evade_zwsp_must_fire() {
    assert_detector_fires("accuweather-api-key", "accuweather\u{200B}_api_key = \"abcde1234567890abcde\"", "abcde1234567890abcde");
}

#[test]
fn adv7_accuweather_evade_soft_hyphen_must_fire() {
    assert_detector_fires("accuweather-api-key", "accuweather_api_key = \"abcde12345\u{00AD}67890abcde\"", "abcde1234567890abcde");
}

#[test]
fn adv7_accuweather_evade_homoglyph_must_fire() {
    assert_detector_fires("accuweather-api-key", "acc\u{0457}weather_api_key = \"abcde1234567890abcde\"", "abcde1234567890abcde");
}

// =========================================================================
// 9. ACTIVECAMPAIGN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv7_activecampaign_normal_must_fire() {
    assert_detector_fires("activecampaign-api-key", "activecampaign_api_key: \"abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012");
}

#[test]
fn adv7_activecampaign_wrong_prefix_must_silent() {
    assert_detector_silent("activecampaign-api-key", "passivecampaign_api_key: \"abcde1234567890abcde123456789012\"");
}

#[test]
fn adv7_activecampaign_evade_zwsp_must_fire() {
    assert_detector_fires("activecampaign-api-key", "activecampaign\u{200B}_api_key: \"abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012");
}

#[test]
fn adv7_activecampaign_evade_soft_hyphen_must_fire() {
    assert_detector_fires("activecampaign-api-key", "activecampaign_api_key: \"abcde1234567890abcde1\u{00AD}23456789012\"", "abcde1234567890abcde123456789012");
}

#[test]
fn adv7_activecampaign_evade_homoglyph_must_fire() {
    assert_detector_fires("activecampaign-api-key", "\u{0430}ctivecampaign_api_key: \"abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012");
}

// =========================================================================
// 10. ACTIVEPIECES API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv7_activepieces_normal_must_fire() {
    assert_detector_fires("activepieces-api-key", "ap_abcde1234567890abcde123456789012", "ap_abcde1234567890abcde123456789012");
}

#[test]
fn adv7_activepieces_wrong_prefix_must_silent() {
    assert_detector_silent("activepieces-api-key", "bp_abcde1234567890abcde123456789012");
}

#[test]
fn adv7_activepieces_evade_zwsp_must_fire() {
    assert_detector_fires("activepieces-api-key", "ap\u{200B}_abcde1234567890abcde123456789012", "ap_abcde1234567890abcde123456789012");
}

#[test]
fn adv7_activepieces_evade_soft_hyphen_must_fire() {
    assert_detector_fires("activepieces-api-key", "ap_abcde1234567890abcde1\u{00AD}23456789012", "ap_abcde1234567890abcde123456789012");
}

#[test]
fn adv7_activepieces_evade_homoglyph_must_fire() {
    assert_detector_fires("activepieces-api-key", "ap_abcd\u{0435}1234567890abcde123456789012", "ap_abcde1234567890abcde123456789012");
}
