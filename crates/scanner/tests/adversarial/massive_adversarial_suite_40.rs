//! Part 40 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates hellosign, helpscout, here, heroku, hetzner, hevo, hexpm, hibp, hightouch, hologram detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. HELLOSIGN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv40_hellosign_api_key_normal_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv40_hellosign_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hellosign-api-key",
        "TELLOSIGN_API_KEY = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
    );
}

#[test]
fn adv40_hellosign_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\u{200B}e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv40_hellosign_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\u{00AD}e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv40_hellosign_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "h\u{0435}ll\u{043e}s\u{0456}gn_api_key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

// =========================================================================
// 2. HELPSCOUT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv40_helpscout_api_key_normal_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY = \"a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv40_helpscout_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "helpscout-api-key",
        "TELPSCOUT_API_KEY = \"a1b2c3d4e5f6a1b2c3d4\"",
    );
}

#[test]
fn adv40_helpscout_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY = \"a1b2c3d4e5f6a1b2\u{200B}c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv40_helpscout_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY = \"a1b2c3d4e5f6a1b2\u{00AD}c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv40_helpscout_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "h\u{0435}lpsc\u{043e}ut_api_key = \"a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4",
    );
}

// =========================================================================
// 3. HERE MAPS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv40_here_maps_api_key_normal_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY = \"hereMapsApiKeyHighEntropySecretMatch40chars\"",
        "hereMapsApiKeyHighEntropySecretMatch40chars",
    );
}

#[test]
fn adv40_here_maps_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "here-maps-api-key",
        "TERE_API_KEY = \"hereMapsApiKeyHighEntropySecretMatch40chars\"",
    );
}

#[test]
fn adv40_here_maps_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY = \"hereMapsApiKeyHigh\u{200B}EntropySecretMatch40chars\"",
        "hereMapsApiKeyHighEntropySecretMatch40chars",
    );
}

#[test]
fn adv40_here_maps_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY = \"hereMapsApiKeyHigh\u{00AD}EntropySecretMatch40chars\"",
        "hereMapsApiKeyHighEntropySecretMatch40chars",
    );
}

#[test]
fn adv40_here_maps_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "h\u{0435}r\u{0435}_api_key = \"hereMapsApiKeyHighEntropySecretMatch40chars\"",
        "hereMapsApiKeyHighEntropySecretMatch40chars",
    );
}

// =========================================================================
// 4. HEROKU API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv40_heroku_api_key_normal_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv40_heroku_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "heroku-api-key",
        "TEROKU_API_KEY = \"12345678-abcd-1234-abcd-1234567890ab\"",
    );
}

#[test]
fn adv40_heroku_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY = \"12345678-abcd-1234-abcd-1234\u{200B}567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv40_heroku_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY = \"12345678-abcd-1234-abcd-123456\u{00AD}7890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv40_heroku_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "h\u{0435}r\u{043e}ku_api_key = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

// =========================================================================
// 5. HETZNER API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv40_hetzner_api_token_normal_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv40_hetzner_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hetzner-api-token",
        "TCLOUD_TOKEN = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
    );
}

#[test]
fn adv40_hetzner_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\u{200B}e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv40_hetzner_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\u{00AD}e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv40_hetzner_api_token_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "h\u{0435}tzn\u{0435}r = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

// =========================================================================
// 6. HEVO DATA CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv40_hevo_data_credentials_normal_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY = \"hevoApiKeyHighEntropy\"",
        "hevoApiKeyHighEntropy",
    );
}

#[test]
fn adv40_hevo_data_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hevo-data-credentials",
        "TEVO_API_KEY = \"hevoApiKeyHighEntropy\"",
    );
}

#[test]
fn adv40_hevo_data_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY = \"hevoApiKeyHi\u{200B}ghEntropy\"",
        "hevoApiKeyHighEntropy",
    );
}

#[test]
fn adv40_hevo_data_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY = \"hevoApiKeyHi\u{00AD}ghEntropy\"",
        "hevoApiKeyHighEntropy",
    );
}

#[test]
fn adv40_hevo_data_credentials_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "h\u{0435}v\u{043e}_api_key = \"hevoApiKeyHighEntropy\"",
        "hevoApiKeyHighEntropy",
    );
}

// =========================================================================
// 7. HEX.PM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv40_hexpm_api_key_normal_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "HEX_API_KEY = \"hexpm_highEntropyBase64EncodedSecretForHexPm123\"",
        "hexpm_highEntropyBase64EncodedSecretForHexPm123",
    );
}

#[test]
fn adv40_hexpm_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hexpm-api-key",
        "HEX_API_KEY = \"texpm_highEntropyBase64EncodedSecretForHexPm123\"",
    );
}

#[test]
fn adv40_hexpm_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "HEX_API_KEY = \"hexpm_highEntropy\u{200B}Base64EncodedSecretForHexPm123\"",
        "hexpm_highEntropyBase64EncodedSecretForHexPm123",
    );
}

#[test]
fn adv40_hexpm_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "HEX_API_KEY = \"hexpm_highEntropy\u{00AD}Base64EncodedSecretForHexPm123\"",
        "hexpm_highEntropyBase64EncodedSecretForHexPm123",
    );
}

#[test]
fn adv40_hexpm_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "h\u{0435}x_api_key = \"hexpm_highEntropyBase64EncodedSecretForHexPm123\"",
        "hexpm_highEntropyBase64EncodedSecretForHexPm123",
    );
}

// =========================================================================
// 8. HIBP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv40_hibp_api_key_normal_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv40_hibp_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hibp-api-key",
        "tibp-api-key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
    );
}

#[test]
fn adv40_hibp_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key = \"a1b2c3d4e5f6a1b2\u{200B}c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv40_hibp_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key = \"a1b2c3d4e5f6a1b2\u{00AD}c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv40_hibp_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "h\u{0456}bp-ap\u{0456}-k\u{0435}y = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

// =========================================================================
// 9. HIGHTOUCH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv40_hightouch_api_key_normal_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY = \"hightouchApiKeyHighEntropySecret40\"",
        "hightouchApiKeyHighEntropySecret40",
    );
}

#[test]
fn adv40_hightouch_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hightouch-api-key",
        "TIGHTOUCH_API_KEY = \"hightouchApiKeyHighEntropySecret40\"",
    );
}

#[test]
fn adv40_hightouch_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY = \"hightouchApiKeyHigh\u{200B}EntropySecret40\"",
        "hightouchApiKeyHighEntropySecret40",
    );
}

#[test]
fn adv40_hightouch_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY = \"hightouchApiKeyHigh\u{00AD}EntropySecret40\"",
        "hightouchApiKeyHighEntropySecret40",
    );
}

#[test]
fn adv40_hightouch_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "h\u{0456}ght\u{043e}uch_api_key = \"hightouchApiKeyHighEntropySecret40\"",
        "hightouchApiKeyHighEntropySecret40",
    );
}

// =========================================================================
// 10. HOLOGRAM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv40_hologram_api_key_normal_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY = \"hologramApiKeyHighEntropySecret40\"",
        "hologramApiKeyHighEntropySecret40",
    );
}

#[test]
fn adv40_hologram_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hologram-api-key",
        "TOLOGRAM_API_KEY = \"hologramApiKeyHighEntropySecret40\"",
    );
}

#[test]
fn adv40_hologram_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY = \"hologramApiKeyHigh\u{200B}EntropySecret40\"",
        "hologramApiKeyHighEntropySecret40",
    );
}

#[test]
fn adv40_hologram_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY = \"hologramApiKeyHigh\u{00AD}EntropySecret40\"",
        "hologramApiKeyHighEntropySecret40",
    );
}

#[test]
fn adv40_hologram_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "h\u{043e}l\u{043e}gr\u{0430}m_api_key = \"hologramApiKeyHighEntropySecret40\"",
        "hologramApiKeyHighEntropySecret40",
    );
}
