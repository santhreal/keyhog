//! Part 105 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates mangopay, mapbox, mapquest, marker, marketo, marvel, mastodon, matomo, maxmind, medium detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. MANGOPAY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv105_mangopay_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "mangopay-api-credentials",
        "MANGOPAY_CLIENT_ID=PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
        "PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
    );
}

#[test]
fn adv105_mangopay_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mangopay-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv105_mangopay_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mangopay-api-credentials",
        "MANGOPAY_CLIENT_ID=PQgFHmZoKVL1TM\u{200B}4ym7pGMCqTy-Opq",
        "PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
    );
}

#[test]
fn adv105_mangopay_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mangopay-api-credentials",
        "MANGOPAY_CLIENT_ID=PQgFHmZoKVL1TM\u{00AD}4ym7pGMCqTy-Opq",
        "PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
    );
}

#[test]
fn adv105_mangopay_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mangopay-api-credentials",
        "MANGOPAY_CLIENT_ID=PQgFHmZoKVL1TM\u{200C}4ym7pGMCqTy-Opq",
        "PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
    );
}

#[test]
fn adv105_mangopay_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "mangopay-api-credentials",
        "MANGOPAY_CLIENT_ID=PQgFHmZoKVL1TM\u{200D}4ym7pGMCqTy-Opq",
        "PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
    );
}

#[test]
fn adv105_mangopay_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mangopay-api-credentials",
        "MANGOPAY_CLIENT_ID=PQgFHmZoKVL1TM\u{FEFF}4ym7pGMCqTy-Opq",
        "PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
    );
}

#[test]
fn adv105_mangopay_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mangopay-api-credentials",
        "MANGOPAY_CLIENT_ID=PQgFHmZoKVL1TM\u{2060}4ym7pGMCqTy-Opq",
        "PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
    );
}

#[test]
fn adv105_mangopay_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mangopay-api-credentials",
        "MANGOPAY_CLIENT_ID=PQgFHmZoKVL1TM\u{180E}4ym7pGMCqTy-Opq",
        "PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
    );
}

#[test]
fn adv105_mangopay_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "mangopay-api-credentials",
        "MANGOPAY_CLIENT_ID=PQgFHmZoKVL1TM\u{202E}4ym7pGMCqTy-Opq",
        "PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
    );
}

#[test]
fn adv105_mangopay_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mangopay-api-credentials",
        "MANGOPAY_CLIENT_ID=PQgFHmZoKVL1TM\u{202C}4ym7pGMCqTy-Opq",
        "PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
    );
}

#[test]
fn adv105_mangopay_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "mangopay-api-credentials",
        "MANGOPAY_CLIENT_ID=PQgFHmZoKVL1TM\u{200E}4ym7pGMCqTy-Opq",
        "PQgFHmZoKVL1TM4ym7pGMCqTy-Opq",
    );
}

// =========================================================================
// 2. MAPBOX ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv105_mapbox_access_token_normal_must_fire() {
    assert_detector_fires(
        "mapbox-access-token",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
    );
}

#[test]
fn adv105_mapbox_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mapbox-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv105_mapbox_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mapbox-access-token",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPP\u{200B}NyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
    );
}

#[test]
fn adv105_mapbox_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mapbox-access-token",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPP\u{00AD}NyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
    );
}

#[test]
fn adv105_mapbox_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mapbox-access-token",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPP\u{200C}NyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
    );
}

#[test]
fn adv105_mapbox_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "mapbox-access-token",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPP\u{200D}NyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
    );
}

#[test]
fn adv105_mapbox_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mapbox-access-token",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPP\u{FEFF}NyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
    );
}

#[test]
fn adv105_mapbox_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mapbox-access-token",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPP\u{2060}NyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
    );
}

#[test]
fn adv105_mapbox_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mapbox-access-token",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPP\u{180E}NyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
    );
}

#[test]
fn adv105_mapbox_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "mapbox-access-token",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPP\u{202E}NyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
    );
}

#[test]
fn adv105_mapbox_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mapbox-access-token",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPP\u{202C}NyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
    );
}

#[test]
fn adv105_mapbox_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "mapbox-access-token",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPP\u{200E}NyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
        "pk.eyJA5HA_hbDTF1ehFQcw04n1IbyKHrAsL0Ii98UNshdQVdyf43_duDPPNyWFZzVb06zdZNhAI8KWT_MieYZ.2VSbx2uM9jl7Sw75lvz9IFDKTSCPhLMo",
    );
}

// =========================================================================
// 3. MAPQUEST API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv105_mapquest_api_key_normal_must_fire() {
    assert_detector_fires(
        "mapquest-api-key",
        "MAPQUEST_API_KEY=dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
        "dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
    );
}

#[test]
fn adv105_mapquest_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mapquest-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv105_mapquest_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mapquest-api-key",
        "MAPQUEST_API_KEY=dVwxYfM2hWRAGmgp\u{200B}CyRcAZUJGrlt7uU4",
        "dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
    );
}

#[test]
fn adv105_mapquest_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mapquest-api-key",
        "MAPQUEST_API_KEY=dVwxYfM2hWRAGmgp\u{00AD}CyRcAZUJGrlt7uU4",
        "dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
    );
}

#[test]
fn adv105_mapquest_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mapquest-api-key",
        "MAPQUEST_API_KEY=dVwxYfM2hWRAGmgp\u{200C}CyRcAZUJGrlt7uU4",
        "dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
    );
}

#[test]
fn adv105_mapquest_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "mapquest-api-key",
        "MAPQUEST_API_KEY=dVwxYfM2hWRAGmgp\u{200D}CyRcAZUJGrlt7uU4",
        "dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
    );
}

#[test]
fn adv105_mapquest_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mapquest-api-key",
        "MAPQUEST_API_KEY=dVwxYfM2hWRAGmgp\u{FEFF}CyRcAZUJGrlt7uU4",
        "dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
    );
}

#[test]
fn adv105_mapquest_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mapquest-api-key",
        "MAPQUEST_API_KEY=dVwxYfM2hWRAGmgp\u{2060}CyRcAZUJGrlt7uU4",
        "dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
    );
}

#[test]
fn adv105_mapquest_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mapquest-api-key",
        "MAPQUEST_API_KEY=dVwxYfM2hWRAGmgp\u{180E}CyRcAZUJGrlt7uU4",
        "dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
    );
}

#[test]
fn adv105_mapquest_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "mapquest-api-key",
        "MAPQUEST_API_KEY=dVwxYfM2hWRAGmgp\u{202E}CyRcAZUJGrlt7uU4",
        "dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
    );
}

#[test]
fn adv105_mapquest_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mapquest-api-key",
        "MAPQUEST_API_KEY=dVwxYfM2hWRAGmgp\u{202C}CyRcAZUJGrlt7uU4",
        "dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
    );
}

#[test]
fn adv105_mapquest_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "mapquest-api-key",
        "MAPQUEST_API_KEY=dVwxYfM2hWRAGmgp\u{200E}CyRcAZUJGrlt7uU4",
        "dVwxYfM2hWRAGmgpCyRcAZUJGrlt7uU4",
    );
}

// =========================================================================
// 4. MARKER IO CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv105_marker_io_credentials_normal_must_fire() {
    assert_detector_fires(
        "marker-io-credentials",
        "MARKERIO=dtxQEDX8Y5R6RgO9aPrm",
        "dtxQEDX8Y5R6RgO9aPrm",
    );
}

#[test]
fn adv105_marker_io_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "marker-io-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv105_marker_io_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "marker-io-credentials",
        "MARKERIO=dtxQEDX8Y5\u{200B}R6RgO9aPrm",
        "dtxQEDX8Y5R6RgO9aPrm",
    );
}

#[test]
fn adv105_marker_io_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "marker-io-credentials",
        "MARKERIO=dtxQEDX8Y5\u{00AD}R6RgO9aPrm",
        "dtxQEDX8Y5R6RgO9aPrm",
    );
}

#[test]
fn adv105_marker_io_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "marker-io-credentials",
        "MARKERIO=dtxQEDX8Y5\u{200C}R6RgO9aPrm",
        "dtxQEDX8Y5R6RgO9aPrm",
    );
}

#[test]
fn adv105_marker_io_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "marker-io-credentials",
        "MARKERIO=dtxQEDX8Y5\u{200D}R6RgO9aPrm",
        "dtxQEDX8Y5R6RgO9aPrm",
    );
}

#[test]
fn adv105_marker_io_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "marker-io-credentials",
        "MARKERIO=dtxQEDX8Y5\u{FEFF}R6RgO9aPrm",
        "dtxQEDX8Y5R6RgO9aPrm",
    );
}

#[test]
fn adv105_marker_io_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "marker-io-credentials",
        "MARKERIO=dtxQEDX8Y5\u{2060}R6RgO9aPrm",
        "dtxQEDX8Y5R6RgO9aPrm",
    );
}

#[test]
fn adv105_marker_io_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "marker-io-credentials",
        "MARKERIO=dtxQEDX8Y5\u{180E}R6RgO9aPrm",
        "dtxQEDX8Y5R6RgO9aPrm",
    );
}

#[test]
fn adv105_marker_io_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "marker-io-credentials",
        "MARKERIO=dtxQEDX8Y5\u{202E}R6RgO9aPrm",
        "dtxQEDX8Y5R6RgO9aPrm",
    );
}

#[test]
fn adv105_marker_io_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "marker-io-credentials",
        "MARKERIO=dtxQEDX8Y5\u{202C}R6RgO9aPrm",
        "dtxQEDX8Y5R6RgO9aPrm",
    );
}

#[test]
fn adv105_marker_io_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "marker-io-credentials",
        "MARKERIO=dtxQEDX8Y5\u{200E}R6RgO9aPrm",
        "dtxQEDX8Y5R6RgO9aPrm",
    );
}

// =========================================================================
// 5. MARKETO API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv105_marketo_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=abcdefghijklmnopqrstuvwx12",
        "abcdefghijklmnopqrstuvwx12",
    );
}

#[test]
fn adv105_marketo_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "marketo-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv105_marketo_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=abcdefghijklm\u{200B}nopqrstuvwx12",
        "abcdefghijklmnopqrstuvwx12",
    );
}

#[test]
fn adv105_marketo_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=abcdefghijklm\u{00AD}nopqrstuvwx12",
        "abcdefghijklmnopqrstuvwx12",
    );
}

#[test]
fn adv105_marketo_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=abcdefghijklm\u{200C}nopqrstuvwx12",
        "abcdefghijklmnopqrstuvwx12",
    );
}

#[test]
fn adv105_marketo_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=abcdefghijklm\u{200D}nopqrstuvwx12",
        "abcdefghijklmnopqrstuvwx12",
    );
}

#[test]
fn adv105_marketo_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=abcdefghijklm\u{FEFF}nopqrstuvwx12",
        "abcdefghijklmnopqrstuvwx12",
    );
}

#[test]
fn adv105_marketo_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=abcdefghijklm\u{2060}nopqrstuvwx12",
        "abcdefghijklmnopqrstuvwx12",
    );
}

#[test]
fn adv105_marketo_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=abcdefghijklm\u{180E}nopqrstuvwx12",
        "abcdefghijklmnopqrstuvwx12",
    );
}

#[test]
fn adv105_marketo_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=abcdefghijklm\u{202E}nopqrstuvwx12",
        "abcdefghijklmnopqrstuvwx12",
    );
}

#[test]
fn adv105_marketo_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=abcdefghijklm\u{202C}nopqrstuvwx12",
        "abcdefghijklmnopqrstuvwx12",
    );
}

#[test]
fn adv105_marketo_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=abcdefghijklm\u{200E}nopqrstuvwx12",
        "abcdefghijklmnopqrstuvwx12",
    );
}

// =========================================================================
// 6. MARVEL API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv105_marvel_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "marvel-api-credentials",
        "MARVEL private_api_key=c5817e17200d3496738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    );
}

#[test]
fn adv105_marvel_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "marvel-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv105_marvel_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "marvel-api-credentials",
        "MARVEL private_api_key=c5817e17200d3496\u{200B}738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    );
}

#[test]
fn adv105_marvel_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "marvel-api-credentials",
        "MARVEL private_api_key=c5817e17200d3496\u{00AD}738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    );
}

#[test]
fn adv105_marvel_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "marvel-api-credentials",
        "MARVEL private_api_key=c5817e17200d3496\u{200C}738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    );
}

#[test]
fn adv105_marvel_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "marvel-api-credentials",
        "MARVEL private_api_key=c5817e17200d3496\u{200D}738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    );
}

#[test]
fn adv105_marvel_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "marvel-api-credentials",
        "MARVEL private_api_key=c5817e17200d3496\u{FEFF}738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    );
}

#[test]
fn adv105_marvel_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "marvel-api-credentials",
        "MARVEL private_api_key=c5817e17200d3496\u{2060}738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    );
}

#[test]
fn adv105_marvel_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "marvel-api-credentials",
        "MARVEL private_api_key=c5817e17200d3496\u{180E}738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    );
}

#[test]
fn adv105_marvel_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "marvel-api-credentials",
        "MARVEL private_api_key=c5817e17200d3496\u{202E}738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    );
}

#[test]
fn adv105_marvel_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "marvel-api-credentials",
        "MARVEL private_api_key=c5817e17200d3496\u{202C}738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    );
}

#[test]
fn adv105_marvel_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "marvel-api-credentials",
        "MARVEL private_api_key=c5817e17200d3496\u{200E}738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    );
}

// =========================================================================
// 7. MASTODON API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv105_mastodon_api_token_normal_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv105_mastodon_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mastodon-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv105_mastodon_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{200B}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv105_mastodon_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{00AD}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv105_mastodon_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{200C}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv105_mastodon_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{200D}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv105_mastodon_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{FEFF}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv105_mastodon_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{2060}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv105_mastodon_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{180E}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv105_mastodon_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{202E}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv105_mastodon_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{202C}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv105_mastodon_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{200E}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

// =========================================================================
// 8. MATOMO API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv105_matomo_api_token_normal_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f00d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv105_matomo_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "matomo-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv105_matomo_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{200B}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv105_matomo_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{00AD}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv105_matomo_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{200C}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv105_matomo_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{200D}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv105_matomo_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{FEFF}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv105_matomo_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{2060}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv105_matomo_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{180E}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv105_matomo_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{202E}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv105_matomo_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{202C}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv105_matomo_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{200E}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

// =========================================================================
// 9. MAXMIND GEOIP LICENSE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv105_maxmind_geoip_license_key_normal_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZWSvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv105_maxmind_geoip_license_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "maxmind-geoip-license-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv105_maxmind_geoip_license_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{200B}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv105_maxmind_geoip_license_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{00AD}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv105_maxmind_geoip_license_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{200C}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv105_maxmind_geoip_license_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{200D}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv105_maxmind_geoip_license_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{FEFF}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv105_maxmind_geoip_license_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{2060}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv105_maxmind_geoip_license_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{180E}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv105_maxmind_geoip_license_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{202E}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv105_maxmind_geoip_license_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{202C}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv105_maxmind_geoip_license_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{200E}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

// =========================================================================
// 10. MEDIUM API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv105_medium_api_token_normal_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9ef6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv105_medium_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "medium-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv105_medium_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{200B}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv105_medium_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{00AD}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv105_medium_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{200C}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv105_medium_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{200D}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv105_medium_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{FEFF}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv105_medium_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{2060}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv105_medium_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{180E}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv105_medium_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{202E}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv105_medium_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{202C}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv105_medium_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{200E}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}


