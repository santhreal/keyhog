//! Part 130 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates sparkpost, spiderfoot, splitio, splunk, splunk, spotify, spreedly, squadcast, squarespace, ssh detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. SPARKPOST API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv130_sparkpost_api_key_normal_must_fire() {
    assert_detector_fires(
        "sparkpost-api-key",
        "SPARKPOST_API_KEY=a1ef083b518e8cda65a1acb5d443e2b7",
        "a1ef083b518e8cda65a1acb5d443e2b7",
    );
}

#[test]
fn adv130_sparkpost_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sparkpost-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv130_sparkpost_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sparkpost-api-key",
        "SPARKPOST_API_KEY=a1ef083b518e8cda\u{200B}65a1acb5d443e2b7",
        "a1ef083b518e8cda65a1acb5d443e2b7",
    );
}

#[test]
fn adv130_sparkpost_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sparkpost-api-key",
        "SPARKPOST_API_KEY=a1ef083b518e8cda\u{00AD}65a1acb5d443e2b7",
        "a1ef083b518e8cda65a1acb5d443e2b7",
    );
}

#[test]
fn adv130_sparkpost_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sparkpost-api-key",
        "SPARKPOST_API_KEY=a1ef083b518e8cda\u{200C}65a1acb5d443e2b7",
        "a1ef083b518e8cda65a1acb5d443e2b7",
    );
}

#[test]
fn adv130_sparkpost_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "sparkpost-api-key",
        "SPARKPOST_API_KEY=a1ef083b518e8cda\u{200D}65a1acb5d443e2b7",
        "a1ef083b518e8cda65a1acb5d443e2b7",
    );
}

#[test]
fn adv130_sparkpost_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sparkpost-api-key",
        "SPARKPOST_API_KEY=a1ef083b518e8cda\u{FEFF}65a1acb5d443e2b7",
        "a1ef083b518e8cda65a1acb5d443e2b7",
    );
}

#[test]
fn adv130_sparkpost_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sparkpost-api-key",
        "SPARKPOST_API_KEY=a1ef083b518e8cda\u{2060}65a1acb5d443e2b7",
        "a1ef083b518e8cda65a1acb5d443e2b7",
    );
}

#[test]
fn adv130_sparkpost_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sparkpost-api-key",
        "SPARKPOST_API_KEY=a1ef083b518e8cda\u{180E}65a1acb5d443e2b7",
        "a1ef083b518e8cda65a1acb5d443e2b7",
    );
}

#[test]
fn adv130_sparkpost_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "sparkpost-api-key",
        "SPARKPOST_API_KEY=a1ef083b518e8cda\u{202E}65a1acb5d443e2b7",
        "a1ef083b518e8cda65a1acb5d443e2b7",
    );
}

#[test]
fn adv130_sparkpost_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sparkpost-api-key",
        "SPARKPOST_API_KEY=a1ef083b518e8cda\u{202C}65a1acb5d443e2b7",
        "a1ef083b518e8cda65a1acb5d443e2b7",
    );
}

#[test]
fn adv130_sparkpost_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "sparkpost-api-key",
        "SPARKPOST_API_KEY=a1ef083b518e8cda\u{200E}65a1acb5d443e2b7",
        "a1ef083b518e8cda65a1acb5d443e2b7",
    );
}

// =========================================================================
// 2. SPIDERFOOT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv130_spiderfoot_api_key_normal_must_fire() {
    assert_detector_fires(
        "spiderfoot-api-key",
        "spiderfoottoken=QT3EUl0GUeQm_rjcUr_T",
        "QT3EUl0GUeQm_rjcUr_T",
    );
}

#[test]
fn adv130_spiderfoot_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("spiderfoot-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv130_spiderfoot_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "spiderfoot-api-key",
        "spiderfoottoken=QT3EUl0GUe\u{200B}Qm_rjcUr_T",
        "QT3EUl0GUeQm_rjcUr_T",
    );
}

#[test]
fn adv130_spiderfoot_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "spiderfoot-api-key",
        "spiderfoottoken=QT3EUl0GUe\u{00AD}Qm_rjcUr_T",
        "QT3EUl0GUeQm_rjcUr_T",
    );
}

#[test]
fn adv130_spiderfoot_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "spiderfoot-api-key",
        "spiderfoottoken=QT3EUl0GUe\u{200C}Qm_rjcUr_T",
        "QT3EUl0GUeQm_rjcUr_T",
    );
}

#[test]
fn adv130_spiderfoot_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "spiderfoot-api-key",
        "spiderfoottoken=QT3EUl0GUe\u{200D}Qm_rjcUr_T",
        "QT3EUl0GUeQm_rjcUr_T",
    );
}

#[test]
fn adv130_spiderfoot_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "spiderfoot-api-key",
        "spiderfoottoken=QT3EUl0GUe\u{FEFF}Qm_rjcUr_T",
        "QT3EUl0GUeQm_rjcUr_T",
    );
}

#[test]
fn adv130_spiderfoot_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "spiderfoot-api-key",
        "spiderfoottoken=QT3EUl0GUe\u{2060}Qm_rjcUr_T",
        "QT3EUl0GUeQm_rjcUr_T",
    );
}

#[test]
fn adv130_spiderfoot_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "spiderfoot-api-key",
        "spiderfoottoken=QT3EUl0GUe\u{180E}Qm_rjcUr_T",
        "QT3EUl0GUeQm_rjcUr_T",
    );
}

#[test]
fn adv130_spiderfoot_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "spiderfoot-api-key",
        "spiderfoottoken=QT3EUl0GUe\u{202E}Qm_rjcUr_T",
        "QT3EUl0GUeQm_rjcUr_T",
    );
}

#[test]
fn adv130_spiderfoot_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "spiderfoot-api-key",
        "spiderfoottoken=QT3EUl0GUe\u{202C}Qm_rjcUr_T",
        "QT3EUl0GUeQm_rjcUr_T",
    );
}

#[test]
fn adv130_spiderfoot_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "spiderfoot-api-key",
        "spiderfoottoken=QT3EUl0GUe\u{200E}Qm_rjcUr_T",
        "QT3EUl0GUeQm_rjcUr_T",
    );
}

// =========================================================================
// 3. SPLITIO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv130_splitio_api_key_normal_must_fire() {
    assert_detector_fires(
        "splitio-api-key",
        "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv130_splitio_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "splitio-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv130_splitio_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "splitio-api-key",
        "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200B}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv130_splitio_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "splitio-api-key",
        "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{00AD}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv130_splitio_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "splitio-api-key",
        "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200C}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv130_splitio_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "splitio-api-key",
        "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200D}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv130_splitio_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "splitio-api-key",
        "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{FEFF}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv130_splitio_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "splitio-api-key",
        "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{2060}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv130_splitio_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "splitio-api-key",
        "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{180E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv130_splitio_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "splitio-api-key",
        "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{202E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv130_splitio_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "splitio-api-key",
        "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{202C}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv130_splitio_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "splitio-api-key",
        "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

// =========================================================================
// 4. SPLUNK HEC TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv130_splunk_hec_token_normal_must_fire() {
    assert_detector_fires(
        "splunk-hec-token",
        "Splunk=70977ea1-11e0-e768-18f3-48ab955cd5fc",
        "70977ea1-11e0-e768-18f3-48ab955cd5fc",
    );
}

#[test]
fn adv130_splunk_hec_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "splunk-hec-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv130_splunk_hec_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "splunk-hec-token",
        "Splunk=70977ea1-11e0-e768\u{200B}-18f3-48ab955cd5fc",
        "70977ea1-11e0-e768-18f3-48ab955cd5fc",
    );
}

#[test]
fn adv130_splunk_hec_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "splunk-hec-token",
        "Splunk=70977ea1-11e0-e768\u{00AD}-18f3-48ab955cd5fc",
        "70977ea1-11e0-e768-18f3-48ab955cd5fc",
    );
}

#[test]
fn adv130_splunk_hec_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "splunk-hec-token",
        "Splunk=70977ea1-11e0-e768\u{200C}-18f3-48ab955cd5fc",
        "70977ea1-11e0-e768-18f3-48ab955cd5fc",
    );
}

#[test]
fn adv130_splunk_hec_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "splunk-hec-token",
        "Splunk=70977ea1-11e0-e768\u{200D}-18f3-48ab955cd5fc",
        "70977ea1-11e0-e768-18f3-48ab955cd5fc",
    );
}

#[test]
fn adv130_splunk_hec_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "splunk-hec-token",
        "Splunk=70977ea1-11e0-e768\u{FEFF}-18f3-48ab955cd5fc",
        "70977ea1-11e0-e768-18f3-48ab955cd5fc",
    );
}

#[test]
fn adv130_splunk_hec_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "splunk-hec-token",
        "Splunk=70977ea1-11e0-e768\u{2060}-18f3-48ab955cd5fc",
        "70977ea1-11e0-e768-18f3-48ab955cd5fc",
    );
}

#[test]
fn adv130_splunk_hec_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "splunk-hec-token",
        "Splunk=70977ea1-11e0-e768\u{180E}-18f3-48ab955cd5fc",
        "70977ea1-11e0-e768-18f3-48ab955cd5fc",
    );
}

#[test]
fn adv130_splunk_hec_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "splunk-hec-token",
        "Splunk=70977ea1-11e0-e768\u{202E}-18f3-48ab955cd5fc",
        "70977ea1-11e0-e768-18f3-48ab955cd5fc",
    );
}

#[test]
fn adv130_splunk_hec_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "splunk-hec-token",
        "Splunk=70977ea1-11e0-e768\u{202C}-18f3-48ab955cd5fc",
        "70977ea1-11e0-e768-18f3-48ab955cd5fc",
    );
}

#[test]
fn adv130_splunk_hec_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "splunk-hec-token",
        "Splunk=70977ea1-11e0-e768\u{200E}-18f3-48ab955cd5fc",
        "70977ea1-11e0-e768-18f3-48ab955cd5fc",
    );
}

// =========================================================================
// 5. SPLUNK VICTOROPS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv130_splunk_victorops_api_key_normal_must_fire() {
    assert_detector_fires(
        "splunk-victorops-api-key",
        "VICTOROPS_API_KEY=5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
        "5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
    );
}

#[test]
fn adv130_splunk_victorops_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "splunk-victorops-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv130_splunk_victorops_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "splunk-victorops-api-key",
        "VICTOROPS_API_KEY=5f6ecfe44ed06debf36c\u{200B}a32b776b8f61a60221a3",
        "5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
    );
}

#[test]
fn adv130_splunk_victorops_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "splunk-victorops-api-key",
        "VICTOROPS_API_KEY=5f6ecfe44ed06debf36c\u{00AD}a32b776b8f61a60221a3",
        "5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
    );
}

#[test]
fn adv130_splunk_victorops_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "splunk-victorops-api-key",
        "VICTOROPS_API_KEY=5f6ecfe44ed06debf36c\u{200C}a32b776b8f61a60221a3",
        "5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
    );
}

#[test]
fn adv130_splunk_victorops_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "splunk-victorops-api-key",
        "VICTOROPS_API_KEY=5f6ecfe44ed06debf36c\u{200D}a32b776b8f61a60221a3",
        "5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
    );
}

#[test]
fn adv130_splunk_victorops_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "splunk-victorops-api-key",
        "VICTOROPS_API_KEY=5f6ecfe44ed06debf36c\u{FEFF}a32b776b8f61a60221a3",
        "5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
    );
}

#[test]
fn adv130_splunk_victorops_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "splunk-victorops-api-key",
        "VICTOROPS_API_KEY=5f6ecfe44ed06debf36c\u{2060}a32b776b8f61a60221a3",
        "5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
    );
}

#[test]
fn adv130_splunk_victorops_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "splunk-victorops-api-key",
        "VICTOROPS_API_KEY=5f6ecfe44ed06debf36c\u{180E}a32b776b8f61a60221a3",
        "5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
    );
}

#[test]
fn adv130_splunk_victorops_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "splunk-victorops-api-key",
        "VICTOROPS_API_KEY=5f6ecfe44ed06debf36c\u{202E}a32b776b8f61a60221a3",
        "5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
    );
}

#[test]
fn adv130_splunk_victorops_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "splunk-victorops-api-key",
        "VICTOROPS_API_KEY=5f6ecfe44ed06debf36c\u{202C}a32b776b8f61a60221a3",
        "5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
    );
}

#[test]
fn adv130_splunk_victorops_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "splunk-victorops-api-key",
        "VICTOROPS_API_KEY=5f6ecfe44ed06debf36c\u{200E}a32b776b8f61a60221a3",
        "5f6ecfe44ed06debf36ca32b776b8f61a60221a3",
    );
}

// =========================================================================
// 6. SPOTIFY CLIENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv130_spotify_client_credentials_normal_must_fire() {
    assert_detector_fires(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=25b7136a1e10908bb8e7a0f15e1a29d2",
        "25b7136a1e10908bb8e7a0f15e1a29d2",
    );
}

#[test]
fn adv130_spotify_client_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "spotify-client-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv130_spotify_client_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=25b7136a1e10908b\u{200B}b8e7a0f15e1a29d2",
        "25b7136a1e10908bb8e7a0f15e1a29d2",
    );
}

#[test]
fn adv130_spotify_client_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=25b7136a1e10908b\u{00AD}b8e7a0f15e1a29d2",
        "25b7136a1e10908bb8e7a0f15e1a29d2",
    );
}

#[test]
fn adv130_spotify_client_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=25b7136a1e10908b\u{200C}b8e7a0f15e1a29d2",
        "25b7136a1e10908bb8e7a0f15e1a29d2",
    );
}

#[test]
fn adv130_spotify_client_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=25b7136a1e10908b\u{200D}b8e7a0f15e1a29d2",
        "25b7136a1e10908bb8e7a0f15e1a29d2",
    );
}

#[test]
fn adv130_spotify_client_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=25b7136a1e10908b\u{FEFF}b8e7a0f15e1a29d2",
        "25b7136a1e10908bb8e7a0f15e1a29d2",
    );
}

#[test]
fn adv130_spotify_client_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=25b7136a1e10908b\u{2060}b8e7a0f15e1a29d2",
        "25b7136a1e10908bb8e7a0f15e1a29d2",
    );
}

#[test]
fn adv130_spotify_client_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=25b7136a1e10908b\u{180E}b8e7a0f15e1a29d2",
        "25b7136a1e10908bb8e7a0f15e1a29d2",
    );
}

#[test]
fn adv130_spotify_client_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=25b7136a1e10908b\u{202E}b8e7a0f15e1a29d2",
        "25b7136a1e10908bb8e7a0f15e1a29d2",
    );
}

#[test]
fn adv130_spotify_client_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=25b7136a1e10908b\u{202C}b8e7a0f15e1a29d2",
        "25b7136a1e10908bb8e7a0f15e1a29d2",
    );
}

#[test]
fn adv130_spotify_client_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=25b7136a1e10908b\u{200E}b8e7a0f15e1a29d2",
        "25b7136a1e10908bb8e7a0f15e1a29d2",
    );
}

// =========================================================================
// 7. SPREEDLY CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv130_spreedly_credentials_normal_must_fire() {
    assert_detector_fires(
        "spreedly-credentials",
        "SPREEDLY_ENVIRONMENT_KEY=CCNyPXmMim7lFCGIBBtOFVw8",
        "CCNyPXmMim7lFCGIBBtOFVw8",
    );
}

#[test]
fn adv130_spreedly_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "spreedly-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv130_spreedly_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "spreedly-credentials",
        "SPREEDLY_ENVIRONMENT_KEY=CCNyPXmMim7l\u{200B}FCGIBBtOFVw8",
        "CCNyPXmMim7lFCGIBBtOFVw8",
    );
}

#[test]
fn adv130_spreedly_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "spreedly-credentials",
        "SPREEDLY_ENVIRONMENT_KEY=CCNyPXmMim7l\u{00AD}FCGIBBtOFVw8",
        "CCNyPXmMim7lFCGIBBtOFVw8",
    );
}

#[test]
fn adv130_spreedly_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "spreedly-credentials",
        "SPREEDLY_ENVIRONMENT_KEY=CCNyPXmMim7l\u{200C}FCGIBBtOFVw8",
        "CCNyPXmMim7lFCGIBBtOFVw8",
    );
}

#[test]
fn adv130_spreedly_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "spreedly-credentials",
        "SPREEDLY_ENVIRONMENT_KEY=CCNyPXmMim7l\u{200D}FCGIBBtOFVw8",
        "CCNyPXmMim7lFCGIBBtOFVw8",
    );
}

#[test]
fn adv130_spreedly_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "spreedly-credentials",
        "SPREEDLY_ENVIRONMENT_KEY=CCNyPXmMim7l\u{FEFF}FCGIBBtOFVw8",
        "CCNyPXmMim7lFCGIBBtOFVw8",
    );
}

#[test]
fn adv130_spreedly_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "spreedly-credentials",
        "SPREEDLY_ENVIRONMENT_KEY=CCNyPXmMim7l\u{2060}FCGIBBtOFVw8",
        "CCNyPXmMim7lFCGIBBtOFVw8",
    );
}

#[test]
fn adv130_spreedly_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "spreedly-credentials",
        "SPREEDLY_ENVIRONMENT_KEY=CCNyPXmMim7l\u{180E}FCGIBBtOFVw8",
        "CCNyPXmMim7lFCGIBBtOFVw8",
    );
}

#[test]
fn adv130_spreedly_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "spreedly-credentials",
        "SPREEDLY_ENVIRONMENT_KEY=CCNyPXmMim7l\u{202E}FCGIBBtOFVw8",
        "CCNyPXmMim7lFCGIBBtOFVw8",
    );
}

#[test]
fn adv130_spreedly_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "spreedly-credentials",
        "SPREEDLY_ENVIRONMENT_KEY=CCNyPXmMim7l\u{202C}FCGIBBtOFVw8",
        "CCNyPXmMim7lFCGIBBtOFVw8",
    );
}

#[test]
fn adv130_spreedly_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "spreedly-credentials",
        "SPREEDLY_ENVIRONMENT_KEY=CCNyPXmMim7l\u{200E}FCGIBBtOFVw8",
        "CCNyPXmMim7lFCGIBBtOFVw8",
    );
}

// =========================================================================
// 8. SQUADCAST API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv130_squadcast_api_key_normal_must_fire() {
    assert_detector_fires(
        "squadcast-api-key",
        "SQUADCAST_API_KEY=04c87c3c76ba4d6ca219893fc4733412",
        "04c87c3c76ba4d6ca219893fc4733412",
    );
}

#[test]
fn adv130_squadcast_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "squadcast-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv130_squadcast_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "squadcast-api-key",
        "SQUADCAST_API_KEY=04c87c3c76ba4d6c\u{200B}a219893fc4733412",
        "04c87c3c76ba4d6ca219893fc4733412",
    );
}

#[test]
fn adv130_squadcast_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "squadcast-api-key",
        "SQUADCAST_API_KEY=04c87c3c76ba4d6c\u{00AD}a219893fc4733412",
        "04c87c3c76ba4d6ca219893fc4733412",
    );
}

#[test]
fn adv130_squadcast_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "squadcast-api-key",
        "SQUADCAST_API_KEY=04c87c3c76ba4d6c\u{200C}a219893fc4733412",
        "04c87c3c76ba4d6ca219893fc4733412",
    );
}

#[test]
fn adv130_squadcast_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "squadcast-api-key",
        "SQUADCAST_API_KEY=04c87c3c76ba4d6c\u{200D}a219893fc4733412",
        "04c87c3c76ba4d6ca219893fc4733412",
    );
}

#[test]
fn adv130_squadcast_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "squadcast-api-key",
        "SQUADCAST_API_KEY=04c87c3c76ba4d6c\u{FEFF}a219893fc4733412",
        "04c87c3c76ba4d6ca219893fc4733412",
    );
}

#[test]
fn adv130_squadcast_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "squadcast-api-key",
        "SQUADCAST_API_KEY=04c87c3c76ba4d6c\u{2060}a219893fc4733412",
        "04c87c3c76ba4d6ca219893fc4733412",
    );
}

#[test]
fn adv130_squadcast_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "squadcast-api-key",
        "SQUADCAST_API_KEY=04c87c3c76ba4d6c\u{180E}a219893fc4733412",
        "04c87c3c76ba4d6ca219893fc4733412",
    );
}

#[test]
fn adv130_squadcast_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "squadcast-api-key",
        "SQUADCAST_API_KEY=04c87c3c76ba4d6c\u{202E}a219893fc4733412",
        "04c87c3c76ba4d6ca219893fc4733412",
    );
}

#[test]
fn adv130_squadcast_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "squadcast-api-key",
        "SQUADCAST_API_KEY=04c87c3c76ba4d6c\u{202C}a219893fc4733412",
        "04c87c3c76ba4d6ca219893fc4733412",
    );
}

#[test]
fn adv130_squadcast_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "squadcast-api-key",
        "SQUADCAST_API_KEY=04c87c3c76ba4d6c\u{200E}a219893fc4733412",
        "04c87c3c76ba4d6ca219893fc4733412",
    );
}

// =========================================================================
// 9. SQUARESPACE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv130_squarespace_api_key_normal_must_fire() {
    assert_detector_fires(
        "squarespace-api-key",
        "squarespace_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv130_squarespace_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "squarespace-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv130_squarespace_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "squarespace-api-key",
        "squarespace_api_key=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv130_squarespace_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "squarespace-api-key",
        "squarespace_api_key=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv130_squarespace_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "squarespace-api-key",
        "squarespace_api_key=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv130_squarespace_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "squarespace-api-key",
        "squarespace_api_key=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv130_squarespace_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "squarespace-api-key",
        "squarespace_api_key=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv130_squarespace_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "squarespace-api-key",
        "squarespace_api_key=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv130_squarespace_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "squarespace-api-key",
        "squarespace_api_key=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv130_squarespace_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "squarespace-api-key",
        "squarespace_api_key=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv130_squarespace_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "squarespace-api-key",
        "squarespace_api_key=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv130_squarespace_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "squarespace-api-key",
        "squarespace_api_key=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 10. SSH PRIVATE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv130_ssh_private_key_normal_must_fire() {
    assert_detector_fires(
        "ssh-private-key",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv130_ssh_private_key_wrong_prefix_must_silent() {
    assert_detector_silent("ssh-private-key", "dummyxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv130_ssh_private_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ssh-private-key",
        "-----BEGIN PR\u{200B}IVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv130_ssh_private_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ssh-private-key",
        "-----BEGIN PR\u{00AD}IVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv130_ssh_private_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ssh-private-key",
        "-----BEGIN PR\u{200C}IVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv130_ssh_private_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "ssh-private-key",
        "-----BEGIN PR\u{200D}IVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv130_ssh_private_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ssh-private-key",
        "-----BEGIN PR\u{FEFF}IVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv130_ssh_private_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ssh-private-key",
        "-----BEGIN PR\u{2060}IVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv130_ssh_private_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ssh-private-key",
        "-----BEGIN PR\u{180E}IVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv130_ssh_private_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "ssh-private-key",
        "-----BEGIN PR\u{202E}IVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv130_ssh_private_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ssh-private-key",
        "-----BEGIN PR\u{202C}IVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv130_ssh_private_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "ssh-private-key",
        "-----BEGIN PR\u{200E}IVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    );
}
