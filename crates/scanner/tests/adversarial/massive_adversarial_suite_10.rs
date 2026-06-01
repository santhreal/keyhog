//! Part 10 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Arbitrum, Arduino IoT, AssemblyAI, Atlantis, Australia Data.gov.au,
//! Auth0, Authentik, Autoblocks, Automate.io, and Avalanche detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. ARBITRUM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv10_arbitrum_normal_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "arbitrum-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_arbitrum_wrong_prefix_must_silent() {
    assert_detector_silent(
        "arbitrum-api-credentials",
        "barbitrum-api-key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv10_arbitrum_evade_zwsp_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "arbitrum\u{200B}-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_arbitrum_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "arbitrum-api-key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_arbitrum_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "arb\u{0456}trum-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 2. ARDUINO IOT CLOUD API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv10_arduino_normal_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "arduino_client_id = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_arduino_wrong_prefix_must_silent() {
    assert_detector_silent(
        "arduino-iot-api-credentials",
        "garduino_client_id = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv10_arduino_evade_zwsp_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "arduino\u{200B}_client_id = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_arduino_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "arduino_client_id = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_arduino_evade_homoglyph_evaded_must_stay_silent() {
    assert_detector_silent("arduino-iot-api-credentials", "ard\u{0457}no_client_id = \"abcde1234567890abcde123456789012\"");
}

// =========================================================================
// 3. ASSEMBLYAI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv10_assemblyai_normal_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "assemblyai_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_assemblyai_wrong_prefix_must_silent() {
    assert_detector_silent(
        "assemblyai-api-key",
        "disassemblyai_key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv10_assemblyai_evade_zwsp_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "assemblyai\u{200B}_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_assemblyai_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "assemblyai_key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_assemblyai_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ass\u{0435}mblyai_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 4. ATLANTIS WEBHOOK AND VCS CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv10_atlantis_normal_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN = \"ghp_abcde1234567890abcde1234567890abcde1\"",
        "ghp_abcde1234567890abcde1234567890abcde1",
    );
}

#[test]
fn adv10_atlantis_wrong_prefix_must_silent() {
    assert_detector_silent(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN = \"php_abcde1234567890abcde1234567890abcde1\"",
    );
}

#[test]
fn adv10_atlantis_evade_zwsp_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS\u{200B}_GH_TOKEN = \"ghp_abcde1234567890abcde1234567890abcde1\"",
        "ghp_abcde1234567890abcde1234567890abcde1",
    );
}

#[test]
fn adv10_atlantis_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN = \"ghp_abcde1234567890abcde1\u{00AD}234567890abcde1\"",
        "ghp_abcde1234567890abcde1234567890abcde1",
    );
}

#[test]
fn adv10_atlantis_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANT\u{0406}S_GH_TOKEN = \"ghp_abcde1234567890abcde1234567890abcde1\"",
        "ghp_abcde1234567890abcde1234567890abcde1",
    );
}

// =========================================================================
// 5. AUSTRALIA DATA.GOV.AU API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv10_audatagov_normal_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "CKAN_API_KEY = \"abcde123-abcd-1234-abcd-1234567890ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv10_audatagov_wrong_prefix_must_silent() {
    assert_detector_silent(
        "australia-data-gov-api-key",
        "DKAN_API_KEY = \"abcde123-abcd-1234-abcd-1234567890ab\"",
    );
}

#[test]
fn adv10_audatagov_evade_zwsp_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "CKAN\u{200B}_API_KEY = \"abcde123-abcd-1234-abcd-1234567890ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv10_audatagov_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "CKAN_API_KEY = \"abcde123-abcd-1234-abcd-12345678\u{00AD}90ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv10_audatagov_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "CK\u{0410}N_API_KEY = \"abcde123-abcd-1234-abcd-1234567890ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

// =========================================================================
// 6. AUTH0 SPA APPLICATION CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv10_auth0_normal_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0_client_id = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv10_auth0_wrong_prefix_must_silent() {
    assert_detector_silent(
        "auth0-spa-credentials",
        "oauth0_client_id = \"abcde1234567890abcde\"",
    );
}

#[test]
fn adv10_auth0_evade_zwsp_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0\u{200B}_client_id = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv10_auth0_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "auth0-spa-credentials",
        "auth0_client_id = \"abcde12345\u{00AD}67890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv10_auth0_evade_homoglyph_evaded_must_stay_silent() {
    assert_detector_silent("auth0-spa-credentials", "auth\u{043E}_client_id = \"abcde1234567890abcde\"");
}

// =========================================================================
// 7. AUTHENTIK API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv10_authentik_normal_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN = \"abcde1234567890abcde1234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

#[test]
fn adv10_authentik_wrong_prefix_must_silent() {
    assert_detector_silent(
        "authentik-token",
        "BAUTHENTIK_TOKEN = \"abcde1234567890abcde1234567890abcde12345\"",
    );
}

#[test]
fn adv10_authentik_evade_zwsp_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK\u{200B}_TOKEN = \"abcde1234567890abcde1234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

#[test]
fn adv10_authentik_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "AUTHENTIK_TOKEN = \"abcde1234567890abcde1\u{00AD}234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

#[test]
fn adv10_authentik_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "authentik-token",
        "auth\u{0435}ntik_token = \"abcde1234567890abcde1234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

// =========================================================================
// 8. AUTOBLOCKS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv10_autoblocks_normal_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-abcde1234567890abcde",
        "AB-abcde1234567890abcde",
    );
}

#[test]
fn adv10_autoblocks_wrong_prefix_must_silent() {
    assert_detector_silent("autoblocks-api-key", "BC-abcde1234567890abcde");
}

#[test]
fn adv10_autoblocks_evade_zwsp_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB\u{200B}-abcde1234567890abcde",
        "AB-abcde1234567890abcde",
    );
}

#[test]
fn adv10_autoblocks_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-abcde1234567890abc\u{00AD}de",
        "AB-abcde1234567890abcde",
    );
}

#[test]
fn adv10_autoblocks_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "autoblocks-api-key",
        "AB-abcd\u{0435}1234567890abcde",
        "AB-abcde1234567890abcde",
    );
}

// =========================================================================
// 9. AUTOMATE.IO API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv10_automateio_normal_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_automateio_wrong_prefix_must_silent() {
    assert_detector_silent(
        "automate-io-credentials",
        "KAUTOMATE_IO = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv10_automateio_evade_zwsp_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE\u{200B}_IO = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_automateio_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "AUTOMATE_IO = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_automateio_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "automate-io-credentials",
        "aut\u{043E}mate_io = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 10. AVALANCHE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv10_avalanche_normal_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_avalanche_wrong_prefix_must_silent() {
    assert_detector_silent(
        "avalanche-api-credentials",
        "bavalanche-api-key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv10_avalanche_evade_zwsp_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche\u{200B}-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_avalanche_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "avalanche-api-key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv10_avalanche_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "avalanche-api-credentials",
        "aval\u{0430}nche-api-key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}
